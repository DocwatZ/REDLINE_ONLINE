# frozen_string_literal: true

class OauthService
  # Find or create a user from an OAuth callback.
  # SECURITY: Never auto-links accounts based on email to prevent account takeover.
  # Only allows linking if user is already authenticated (current_user present).
  def self.find_or_create_from_oauth(auth_hash, current_user: nil)
    provider = auth_hash["provider"]
    uid = auth_hash["uid"]

    identity = Identity.find_by(provider: provider, uid: uid)

    if identity
      # Existing identity — sign in the associated user
      AuditService.log(
        action: "oauth.login",
        user: identity.user,
        metadata: { provider: provider }
      )
      return identity.user
    end

    if current_user
      # Link new provider to existing signed-in user (safe: user is authenticated)
      create_identity(current_user, auth_hash)
      AuditService.log(
        action: "oauth.linked",
        user: current_user,
        metadata: { provider: provider }
      )
      return current_user
    end

    # SECURITY: Do NOT look up existing users by email from OAuth.
    # Always create a fresh user to prevent account takeover via email matching.
    user = create_user_from_oauth(auth_hash)
    create_identity(user, auth_hash)

    AuditService.log(
      action: "oauth.signup",
      user: user,
      metadata: { provider: provider }
    )

    user
  end

  def self.create_user_from_oauth(auth_hash)
    info = auth_hash.fetch("info", {})
    username = generate_unique_username(info["nickname"] || info["name"] || "user")
    display_name = info["name"] || username

    User.create!(
      username: username,
      display_name: display_name[0..31],
      password: Devise.friendly_token(32),
      role: "user"
    )
  end
  private_class_method :create_user_from_oauth

  def self.create_identity(user, auth_hash)
    credentials = auth_hash.fetch("credentials", {})
    user.identities.create!(
      provider: auth_hash["provider"],
      uid: auth_hash["uid"],
      access_token: credentials["token"],
      refresh_token: credentials["refresh_token"],
      expires_at: credentials["expires_at"] ? Time.at(credentials["expires_at"]) : nil
    )
  end
  private_class_method :create_identity

  def self.generate_unique_username(base)
    sanitized = base.to_s.gsub(/[^a-zA-Z0-9_\-]/, "")[0..23]
    sanitized = "user" if sanitized.blank?
    candidate = sanitized
    counter = 1
    while User.exists?(username: candidate)
      candidate = "#{sanitized}#{counter}"
      counter += 1
    end
    candidate
  end
  private_class_method :generate_unique_username
end
