# frozen_string_literal: true

class RecoveryCodeService
  # Generate recovery codes for a user
  def self.generate(user, count: 8)
    RecoveryCode.generate_for(user, count: count)
  end

  # Authenticate a user via recovery code.
  # Normalizes login input (downcase + strip) for consistent lookup.
  def self.authenticate(username_or_email, plaintext_code)
    normalized_login = username_or_email.to_s.downcase.strip
    user = User.find_for_database_authentication(login: normalized_login)
    return nil unless user

    recovery_code = RecoveryCode.verify(user, plaintext_code)
    return nil unless recovery_code

    AuditService.log(
      action: "recovery_code.used",
      user: user,
      metadata: { recovery_code_id: recovery_code.id }
    )

    user
  end
end
