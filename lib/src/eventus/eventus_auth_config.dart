/// Configuration for Eventus native authentication.
class EventusAuthConfig {
  /// Creates the Eventus native authentication configuration.
  const EventusAuthConfig({
    required this.authBaseUrl,
    required this.googleIosClientId,
    required this.googleServerClientId,
    this.googleScopes = const ['email', 'profile'],
    this.refreshLeeway = const Duration(minutes: 2),
  });

  /// Base URL for the Eventus auth service.
  final String authBaseUrl;

  /// iOS client ID from Google Cloud Console.
  final String googleIosClientId;

  /// Web/server client ID used to request Google ID tokens.
  final String googleServerClientId;

  /// Google OAuth scopes requested by the native sign-in flow.
  final List<String> googleScopes;

  /// Time before expiry when an access token should be refreshed.
  final Duration refreshLeeway;
}
