import 'dart:convert';
import 'dart:math';

import 'package:crypto/crypto.dart';
import 'package:flutter/foundation.dart';
import 'package:google_sign_in/google_sign_in.dart';
import 'package:http/http.dart' as http;
import 'package:sign_in_with_apple/sign_in_with_apple.dart';

import '../modules/logto_storage_strategy.dart';
import 'eventus_auth_config.dart';
import 'eventus_auth_exception.dart';
import 'eventus_auth_models.dart';
import 'eventus_session_storage.dart';

/// Native Eventus authentication client backed by Eventus auth sessions.
class EventusAuthClient {
  /// Creates an Eventus authentication client.
  EventusAuthClient({
    required this.config,
    LogtoStorageStrategy? storageProvider,
    http.Client? httpClient,
  })  : _httpClient = httpClient ?? http.Client(),
        _ownsHttpClient = httpClient == null,
        _storage = EventusSessionStorage(storageProvider);

  /// SDK configuration.
  final EventusAuthConfig config;

  final http.Client _httpClient;
  final bool _ownsHttpClient;
  final EventusSessionStorage _storage;

  EventusAuthResult? _currentAuthResult;
  Future<EventusAuthResult>? _refreshOperation;

  /// Most recent authentication result loaded by this client.
  EventusAuthResult? get currentAuthResult => _currentAuthResult;

  /// Most recent Eventus app session loaded by this client.
  EventusAuthSession? get currentSession => _currentAuthResult?.session;

  /// Whether a stored Eventus session is available.
  Future<bool> get isAuthenticated async => await restoreSession() != null;

  /// Restores a persisted Eventus session, when available.
  Future<EventusAuthResult?> restoreSession() async {
    _currentAuthResult ??= await _storage.load();
    return _currentAuthResult;
  }

  /// Signs in with an email and password handled by Eventus auth.
  Future<EventusAuthResult> signInWithEmailPassword({
    required String email,
    required String password,
  }) async {
    final response = await _httpClient.post(
      _uri('/api/auth/email-password'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({
        'email': email.trim(),
        'password': password,
      }),
    );
    return _saveAuthResult(EventusAuthResult.fromJson(_decode(response)));
  }

  /// Signs in with native Google and exchanges the provider ID token.
  Future<EventusAuthResult> signInWithGoogle() async {
    final googleSignIn = GoogleSignIn(
      clientId: kIsWeb ? null : config.googleIosClientId,
      serverClientId: config.googleServerClientId,
      scopes: config.googleScopes,
    );

    final googleUser = await googleSignIn.signIn();
    if (googleUser == null) {
      throw const EventusAuthCancelledException('Google sign-in canceled.');
    }

    final googleAuth = await googleUser.authentication;
    final idToken = googleAuth.idToken;
    if (idToken == null) {
      throw const EventusAuthException('Google did not return an ID token.');
    }

    return exchangeNativeIdToken(
      provider: EventusNativeIdentityProvider.google,
      idToken: idToken,
      accessToken: googleAuth.accessToken,
    );
  }

  /// Signs in with native Apple and exchanges the provider ID token.
  Future<EventusAuthResult> signInWithApple() async {
    final isAvailable = await SignInWithApple.isAvailable();
    if (!isAvailable) {
      throw const EventusAuthException(
        'Sign in with Apple is not available on this device.',
      );
    }

    try {
      final rawNonce = _randomNonce();
      final hashedNonce = sha256.convert(utf8.encode(rawNonce)).toString();
      final credential = await SignInWithApple.getAppleIDCredential(
        scopes: [
          AppleIDAuthorizationScopes.email,
          AppleIDAuthorizationScopes.fullName,
        ],
        nonce: hashedNonce,
      );

      final idToken = credential.identityToken;
      if (idToken == null) {
        throw const EventusAuthException('Apple did not return an ID token.');
      }

      return exchangeNativeIdToken(
        provider: EventusNativeIdentityProvider.apple,
        idToken: idToken,
        nonce: rawNonce,
      );
    } on SignInWithAppleAuthorizationException catch (error) {
      if (error.code == AuthorizationErrorCode.canceled) {
        throw const EventusAuthCancelledException('Apple sign-in canceled.');
      }

      rethrow;
    }
  }

  /// Exchanges a native provider ID token with the Eventus auth service.
  Future<EventusAuthResult> exchangeNativeIdToken({
    required EventusNativeIdentityProvider provider,
    required String idToken,
    String? accessToken,
    String? nonce,
  }) async {
    final response = await _httpClient.post(
      _uri('/api/auth/native-id-token'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({
        'provider': provider.value,
        'idToken': idToken,
        if (accessToken != null) 'accessToken': accessToken,
        if (nonce != null) 'nonce': nonce,
      }),
    );
    return _saveAuthResult(EventusAuthResult.fromJson(_decode(response)));
  }

  /// Returns a valid access token, refreshing it when needed.
  Future<String> getValidAccessToken() async {
    final authResult = await restoreSession();
    final session = authResult?.session;
    if (session == null || session.accessToken.isEmpty) {
      throw const EventusAuthException('No Eventus session is available.');
    }

    if (!session.shouldRefresh(config.refreshLeeway)) {
      return session.accessToken;
    }

    return (await refreshSession()).session.accessToken;
  }

  /// Refreshes the Eventus app session using the stored refresh token.
  Future<EventusAuthResult> refreshSession() {
    final pending = _refreshOperation;
    if (pending != null) {
      return pending;
    }

    final operation = _refreshSessionImpl();
    _refreshOperation = operation;
    return operation.whenComplete(() {
      if (identical(_refreshOperation, operation)) {
        _refreshOperation = null;
      }
    });
  }

  /// Clears local SDK state and signs out of Google when available.
  Future<void> signOut() async {
    _currentAuthResult = null;
    _refreshOperation = null;
    await _storage.clear();
    try {
      await GoogleSignIn().signOut();
    } catch (_) {
      // Platform sign-out is best effort; local Eventus tokens are already gone.
    }
  }

  /// Releases resources owned by this client.
  void close() {
    if (_ownsHttpClient) {
      _httpClient.close();
    }
  }

  Future<EventusAuthResult> _refreshSessionImpl() async {
    final authResult = await restoreSession();
    final refreshToken = authResult?.session.refreshToken;
    if (refreshToken == null || refreshToken.isEmpty) {
      await signOut();
      throw const EventusAuthSessionExpiredException(
          'No Eventus refresh token is available.');
    }

    final response = await _httpClient.post(
      _uri('/api/auth/session/refresh'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({'refreshToken': refreshToken}),
    );

    try {
      return _saveAuthResult(
        EventusAuthResult.fromJson(
          _decode(response),
          fallbackIdentity: authResult?.identity,
        ),
      );
    } on EventusAuthException catch (error) {
      if (error.statusCode != 401) {
        rethrow;
      }

      await _clearStoredSession();
      throw EventusAuthSessionExpiredException(
        error.message,
        statusCode: error.statusCode,
      );
    }
  }

  Future<EventusAuthResult> _saveAuthResult(
      EventusAuthResult authResult) async {
    _currentAuthResult = authResult;
    await _storage.save(authResult);
    return authResult;
  }

  Uri _uri(String path) {
    final base = Uri.parse(config.authBaseUrl);
    final basePath = base.path.endsWith('/')
        ? base.path.substring(0, base.path.length - 1)
        : base.path;
    final normalizedPath = path.startsWith('/') ? path : '/$path';
    final prefix = basePath == '/' ? '' : basePath;
    return base.replace(path: '$prefix$normalizedPath');
  }

  Map<String, dynamic> _decode(http.Response response) {
    final body = response.body.trim();
    final Object? decoded;
    try {
      decoded = body.isEmpty ? null : jsonDecode(body);
    } on FormatException {
      if (response.statusCode < 200 || response.statusCode >= 300) {
        throw EventusAuthException(body, statusCode: response.statusCode);
      }

      throw const EventusAuthException(
        'Unexpected response from Eventus auth.',
      );
    }

    if (response.statusCode < 200 || response.statusCode >= 300) {
      throw EventusAuthException(
        decoded is String ? decoded : 'Request failed: ${response.statusCode}',
        statusCode: response.statusCode,
      );
    }

    if (decoded is Map<String, dynamic>) {
      return decoded;
    }

    throw const EventusAuthException(
      'Unexpected response from Eventus auth.',
    );
  }

  Future<void> _clearStoredSession() async {
    await _storage.clear();
    _currentAuthResult = null;
  }

  String _randomNonce([int length = 32]) {
    const charset =
        '0123456789ABCDEFGHIJKLMNOPQRSTUVXYZabcdefghijklmnopqrstuvwxyz-._';
    final random = Random.secure();
    return List.generate(
      length,
      (_) => charset[random.nextInt(charset.length)],
    ).join();
  }
}
