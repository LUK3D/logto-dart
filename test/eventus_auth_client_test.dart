import 'dart:async';
import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:logto_dart_sdk/logto_dart_sdk.dart';

import 'mocks/mock_storage.dart';

void main() {
  const config = EventusAuthConfig(
    authBaseUrl: 'https://auth.eventus.test',
    googleIosClientId: 'ios-client',
    googleServerClientId: 'server-client',
  );

  test('restores a persisted session from storage', () async {
    final storage = MockStorageStrategy();
    final storedResult = _authResult(accessToken: 'stored-access');
    await EventusSessionStorage(storage).save(storedResult);
    final client = EventusAuthClient(
      config: config,
      storageProvider: storage,
      httpClient: MockClient((_) async => http.Response('', 500)),
    );

    final restored = await client.restoreSession();

    expect(restored?.session.accessToken, 'stored-access');
    expect(await client.isAuthenticated, isTrue);
  });

  test('refreshes an expired session before returning an access token',
      () async {
    final storage = MockStorageStrategy();
    await EventusSessionStorage(storage).save(
      _authResult(accessToken: 'expired-access', expiresAt: _past()),
    );
    final client = EventusAuthClient(
      config: config,
      storageProvider: storage,
      httpClient: MockClient((request) async {
        expect(request.url.path, '/api/auth/session/refresh');
        expect(jsonDecode(request.body), {'refreshToken': 'refresh-token'});
        return http.Response(
          jsonEncode(_refreshResponse(accessToken: 'fresh-access')),
          200,
        );
      }),
    );

    final accessToken = await client.getValidAccessToken();

    expect(accessToken, 'fresh-access');
    expect(client.currentSession?.accessToken, 'fresh-access');
  });

  test('clears the stored session when refresh is rejected', () async {
    final storage = MockStorageStrategy();
    await EventusSessionStorage(storage).save(
      _authResult(accessToken: 'expired-access', expiresAt: _past()),
    );
    final client = EventusAuthClient(
      config: config,
      storageProvider: storage,
      httpClient: MockClient((_) async => http.Response('Rejected', 401)),
    );

    await expectLater(
      client.getValidAccessToken(),
      throwsA(isA<EventusAuthSessionExpiredException>()),
    );

    expect(await EventusSessionStorage(storage).load(), isNull);
    expect(client.currentAuthResult, isNull);
  });

  test('keeps the stored session when refresh has a server error', () async {
    final storage = MockStorageStrategy();
    await EventusSessionStorage(storage).save(
      _authResult(accessToken: 'expired-access', expiresAt: _past()),
    );
    final client = EventusAuthClient(
      config: config,
      storageProvider: storage,
      httpClient: MockClient(
        (_) async => http.Response('Service unavailable', 503),
      ),
    );

    await expectLater(
      client.getValidAccessToken(),
      throwsA(
        isA<EventusAuthException>()
            .having((error) => error.statusCode, 'statusCode', 503),
      ),
    );

    expect(
      (await EventusSessionStorage(storage).load())?.session.refreshToken,
      'refresh-token',
    );
    expect(client.currentAuthResult?.session.refreshToken, 'refresh-token');
  });

  test('shares a single in-flight refresh operation', () async {
    final storage = MockStorageStrategy();
    await EventusSessionStorage(storage).save(
      _authResult(accessToken: 'expired-access', expiresAt: _past()),
    );
    final completer = Completer<http.Response>();
    var requestCount = 0;
    final client = EventusAuthClient(
      config: config,
      storageProvider: storage,
      httpClient: MockClient((_) {
        requestCount++;
        return completer.future;
      }),
    );

    final first = client.getValidAccessToken();
    final second = client.getValidAccessToken();
    await Future<void>.delayed(Duration.zero);
    completer.complete(
      http.Response(jsonEncode(_refreshResponse(accessToken: 'fresh')), 200),
    );

    expect(await Future.wait([first, second]), ['fresh', 'fresh']);
    expect(requestCount, 1);
  });

  test('signOut clears persisted tokens', () async {
    final storage = MockStorageStrategy();
    await EventusSessionStorage(storage).save(_authResult());
    final client = EventusAuthClient(
      config: config,
      storageProvider: storage,
      httpClient: MockClient((_) async => http.Response('', 500)),
    );

    await client.restoreSession();
    await client.signOut();

    expect(await EventusSessionStorage(storage).load(), isNull);
    expect(client.currentAuthResult, isNull);
  });
}

EventusAuthResult _authResult({
  String accessToken = 'access-token',
  DateTime? expiresAt,
}) {
  return EventusAuthResult.fromJson({
    'user': _userJson(),
    'identity': {
      'provider': 'google',
      'providerUserId': 'provider-user',
      'email': 'test@example.com',
      'emailVerified': true,
      'name': 'Test User',
      'avatar': null,
      'providerPayload': <String, dynamic>{},
    },
    'session': {
      'accessToken': accessToken,
      'refreshToken': 'refresh-token',
      'tokenType': 'Bearer',
      'expiresIn': 900,
      if (expiresAt != null) 'expiresAt': expiresAt.toIso8601String(),
    },
  });
}

Map<String, dynamic> _refreshResponse({required String accessToken}) => {
      'user': _userJson(),
      'session': {
        'accessToken': accessToken,
        'refreshToken': 'new-refresh-token',
        'tokenType': 'Bearer',
        'expiresIn': 900,
      },
    };

Map<String, dynamic> _userJson() => {
      'id': 'user-1',
      'username': 'test_user',
      'primaryEmail': 'test@example.com',
      'name': 'Test User',
      'avatar': null,
    };

DateTime _past() => DateTime.now().toUtc().subtract(const Duration(minutes: 1));
