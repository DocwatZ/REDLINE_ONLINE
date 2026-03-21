# frozen_string_literal: true

class RecoveryCode < ApplicationRecord
  belongs_to :user

  validates :code_digest, presence: true

  scope :unused, -> { where(used_at: nil) }

  def used?
    used_at.present?
  end

  def use!
    update!(used_at: Time.current)
  end

  # Verify a plaintext code against the stored digest using constant-time comparison.
  # Invalidation is atomic — wrapped in a transaction with row-level locking.
  def self.verify(user, plaintext_code)
    normalized = plaintext_code.to_s.strip.downcase.delete("-")

    transaction do
      user.recovery_codes.unused.lock("FOR UPDATE").find_each do |rc|
        hashed = BCrypt::Engine.hash_secret(normalized, BCrypt::Password.new(rc.code_digest).salt)
        if ActiveSupport::SecurityUtils.secure_compare(hashed, rc.code_digest)
          rc.use!
          return rc
        end
      end
      nil
    end
  end

  # Generate a set of recovery codes for a user
  def self.generate_for(user, count: 8)
    transaction do
      user.recovery_codes.destroy_all

      plaintext_codes = count.times.map do
        code = SecureRandom.hex(5) # 10 hex chars
        formatted = "#{code[0..4]}-#{code[5..9]}" # e.g. "a1b2c-d3e4f"
        digest = BCrypt::Password.create(code, cost: BCrypt::Engine.cost)
        user.recovery_codes.create!(code_digest: digest)
        formatted
      end

      plaintext_codes
    end
  end
end
