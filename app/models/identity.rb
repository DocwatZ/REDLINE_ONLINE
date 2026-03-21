# frozen_string_literal: true

class Identity < ApplicationRecord
  belongs_to :user

  validates :provider, presence: true
  validates :uid, presence: true
  validates :uid, uniqueness: { scope: :provider }

  # Token encryption via Rails encrypted attributes
  encrypts :access_token_ciphertext
  encrypts :refresh_token_ciphertext

  def token_expired?
    expires_at.present? && expires_at < Time.current
  end
end
