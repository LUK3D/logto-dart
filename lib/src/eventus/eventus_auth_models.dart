/// Supported native identity providers.
enum EventusNativeIdentityProvider {
  /// Google native sign-in.
  google('google'),

  /// Apple native sign-in.
  apple('apple');

  const EventusNativeIdentityProvider(this.value);

  /// Wire value accepted by the Eventus auth service.
  final String value;
}

/// User record returned by the Eventus auth service.
class EventusUser {
  /// Creates an Eventus user model.
  const EventusUser({
    required this.id,
    this.username,
    this.primaryEmail,
    this.name,
    this.avatar,
  });

  /// Creates a user model from JSON.
  factory EventusUser.fromJson(Map<String, dynamic> json) => EventusUser(
        id: json['id'] as String? ?? '',
        username: json['username'] as String?,
        primaryEmail: json['primaryEmail'] as String?,
        name: json['name'] as String?,
        avatar: json['avatar'] as String?,
      );

  /// Eventus account user ID.
  final String id;

  /// Account username, when set.
  final String? username;

  /// Primary email, when set.
  final String? primaryEmail;

  /// Display name, when set.
  final String? name;

  /// Avatar URL, when set.
  final String? avatar;

  /// Converts this user to JSON.
  Map<String, dynamic> toJson() => {
        'id': id,
        'username': username,
        'primaryEmail': primaryEmail,
        'name': name,
        'avatar': avatar,
      };
}

/// Native provider identity returned by the Eventus auth service.
class EventusNativeIdentity {
  /// Creates a native identity model.
  const EventusNativeIdentity({
    required this.provider,
    required this.providerUserId,
    required this.emailVerified,
    this.providerPayload = const <String, dynamic>{},
    this.email,
    this.name,
    this.avatar,
  });

  /// Creates a native identity from JSON.
  factory EventusNativeIdentity.fromJson(Map<String, dynamic> json) {
    return EventusNativeIdentity(
      provider: json['provider'] as String? ?? '',
      providerUserId: json['providerUserId'] as String? ?? '',
      email: json['email'] as String?,
      emailVerified: json['emailVerified'] as bool? ?? false,
      name: json['name'] as String?,
      avatar: json['avatar'] as String?,
      providerPayload: (json['providerPayload'] as Map<String, dynamic>?) ??
          const <String, dynamic>{},
    );
  }

  /// Provider wire value, e.g. `google` or `apple`.
  final String provider;

  /// Provider-specific stable subject.
  final String providerUserId;

  /// Provider email claim, when available.
  final String? email;

  /// Whether the provider reports the email as verified.
  final bool emailVerified;

  /// Provider display name, when available.
  final String? name;

  /// Provider avatar URL, when available.
  final String? avatar;

  /// Verified provider token claims returned by the auth service.
  final Map<String, dynamic> providerPayload;

  /// Converts this identity to JSON.
  Map<String, dynamic> toJson() => {
        'provider': provider,
        'providerUserId': providerUserId,
        'email': email,
        'emailVerified': emailVerified,
        'name': name,
        'avatar': avatar,
        'providerPayload': providerPayload,
      };
}

/// App session minted by the Eventus auth service.
class EventusAuthSession {
  /// Creates an Eventus app session model.
  const EventusAuthSession({
    required this.accessToken,
    required this.refreshToken,
    required this.tokenType,
    required this.expiresIn,
    required this.expiresAt,
  });

  /// Creates a session from a service response.
  factory EventusAuthSession.fromJson(
    Map<String, dynamic> json, {
    DateTime? issuedAt,
  }) {
    final expiresIn = _readInt(json['expiresIn']);
    final expiresAtValue = json['expiresAt'] as String?;

    return EventusAuthSession(
      accessToken: json['accessToken'] as String? ?? '',
      refreshToken: json['refreshToken'] as String? ?? '',
      tokenType: json['tokenType'] as String? ?? 'Bearer',
      expiresIn: expiresIn,
      expiresAt: expiresAtValue == null
          ? (issuedAt ?? DateTime.now()).toUtc().add(
                Duration(seconds: expiresIn),
              )
          : DateTime.parse(expiresAtValue).toUtc(),
    );
  }

  /// Short-lived app access token.
  final String accessToken;

  /// Long-lived app refresh token.
  final String refreshToken;

  /// Token type, usually `Bearer`.
  final String tokenType;

  /// Access-token lifetime in seconds.
  final int expiresIn;

  /// Client-side access-token expiry timestamp.
  final DateTime expiresAt;

  /// Whether the access token should be refreshed now.
  bool shouldRefresh(Duration leeway) {
    return DateTime.now().toUtc().add(leeway).isAfter(expiresAt);
  }

  /// Converts this session to JSON.
  Map<String, dynamic> toJson() => {
        'accessToken': accessToken,
        'refreshToken': refreshToken,
        'tokenType': tokenType,
        'expiresIn': expiresIn,
        'expiresAt': expiresAt.toIso8601String(),
      };
}

/// Authentication result returned by native sign-in or refresh.
class EventusAuthResult {
  /// Creates an authentication result.
  const EventusAuthResult({
    required this.user,
    required this.session,
    required this.raw,
    this.identity,
  });

  /// Creates an authentication result from JSON.
  factory EventusAuthResult.fromJson(
    Map<String, dynamic> json, {
    EventusNativeIdentity? fallbackIdentity,
  }) {
    final identityJson = json['identity'];

    return EventusAuthResult(
      user: EventusUser.fromJson(
        (json['user'] as Map<String, dynamic>?) ?? const {},
      ),
      identity: identityJson is Map<String, dynamic>
          ? EventusNativeIdentity.fromJson(identityJson)
          : fallbackIdentity,
      session: EventusAuthSession.fromJson(
        (json['session'] as Map<String, dynamic>?) ?? const {},
      ),
      raw: json,
    );
  }

  /// User created or resolved by the backend.
  final EventusUser user;

  /// Native provider identity, available after provider sign-in.
  final EventusNativeIdentity? identity;

  /// App session minted by the backend.
  final EventusAuthSession session;

  /// Raw backend payload, preserved for debugging.
  final Map<String, dynamic> raw;

  /// Converts this result to JSON.
  Map<String, dynamic> toJson() => {
        'user': user.toJson(),
        if (identity != null) 'identity': identity!.toJson(),
        'session': session.toJson(),
      };
}

int _readInt(Object? value) {
  if (value is int) {
    return value;
  }

  if (value is num) {
    return value.toInt();
  }

  return 0;
}
