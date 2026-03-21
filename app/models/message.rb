# frozen_string_literal: true

class Message < ApplicationRecord
  belongs_to :room
  belongs_to :user
  belongs_to :parent, class_name: "Message", optional: true
  has_many :replies, class_name: "Message", foreign_key: :parent_id, dependent: :destroy

  MESSAGE_TYPES = %w[text system].freeze

  validates :body, length: { maximum: 4000 }, allow_blank: true
  validates :ciphertext, presence: true, if: :e2ee_message?
  validates :nonce, presence: true, if: -> { ciphertext.present? }
  validates :message_type, inclusion: { in: MESSAGE_TYPES }
  validate :require_body_or_ciphertext
  validate :no_plaintext_body_in_production

  before_validation :sanitize_body

  scope :recent, -> { order(created_at: :asc) }
  scope :visible, -> { where(deleted: false) }

  # Never expose plaintext body in serialized output; use display_body instead
  def display_body
    return "[message deleted]" if deleted?
    return "[encrypted]" if e2ee_message?
    body
  end

  def e2ee_message?
    ciphertext.present? || room&.e2ee_enabled?
  end

  def system?
    message_type == "system"
  end

  private

  def sanitize_body
    self.body = body.to_s.strip if body.present?
  end

  # Enforce that at least one content field is present
  def require_body_or_ciphertext
    if body.blank? && ciphertext.blank? && !deleted?
      errors.add(:base, "Message must have body or ciphertext")
    end
  end

  # In production, disallow plaintext body — all messages must be encrypted
  def no_plaintext_body_in_production
    if Rails.env.production? && body.present? && ciphertext.blank?
      errors.add(:body, "Plaintext messages are not allowed in production. Use encrypted messaging.")
    end
  end
end
