import 'dart:convert';

import '../modules/logto_storage_strategy.dart';
import 'eventus_auth_models.dart';

class _EventusSessionStorageKeys {
  static const authResult = 'eventus_auth_result';
}

/// Persists Eventus app sessions through the configured storage strategy.
class EventusSessionStorage {
  /// Creates an Eventus session storage wrapper.
  EventusSessionStorage(LogtoStorageStrategy? storageStrategy)
      : _storage = storageStrategy ?? SecureStorageStrategy();

  final LogtoStorageStrategy _storage;
  EventusAuthResult? _cachedAuthResult;

  /// Loads the persisted authentication result, when present.
  Future<EventusAuthResult?> load() async {
    if (_cachedAuthResult != null) {
      return _cachedAuthResult;
    }

    final encoded = await _storage.read(
      key: _EventusSessionStorageKeys.authResult,
    );
    if (encoded == null || encoded.isEmpty) {
      return null;
    }

    final decoded = jsonDecode(encoded);
    if (decoded is! Map<String, dynamic>) {
      return null;
    }

    _cachedAuthResult = EventusAuthResult.fromJson(decoded);
    return _cachedAuthResult;
  }

  /// Saves the current authentication result.
  Future<void> save(EventusAuthResult authResult) async {
    _cachedAuthResult = authResult;
    await _storage.write(
      key: _EventusSessionStorageKeys.authResult,
      value: jsonEncode(authResult.toJson()),
    );
  }

  /// Clears the current authentication result.
  Future<void> clear() async {
    _cachedAuthResult = null;
    await _storage.delete(key: _EventusSessionStorageKeys.authResult);
  }
}
