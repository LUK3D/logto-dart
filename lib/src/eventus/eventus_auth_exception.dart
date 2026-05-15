/// Exception thrown by the Eventus authentication client.
class EventusAuthException implements Exception {
  /// Creates an authentication exception.
  const EventusAuthException(this.message, {this.statusCode});

  /// Human-readable error message.
  final String message;

  /// HTTP status code returned by the auth service, when available.
  final int? statusCode;

  @override
  String toString() => message;
}

/// Exception thrown when the stored Eventus session is no longer valid.
class EventusAuthSessionExpiredException extends EventusAuthException {
  /// Creates a session-expired exception.
  const EventusAuthSessionExpiredException(super.message, {super.statusCode});
}

/// Exception thrown when the user cancels a native sign-in flow.
class EventusAuthCancelledException extends EventusAuthException {
  /// Creates a native sign-in cancellation exception.
  const EventusAuthCancelledException(super.message);
}
