# frozen_string_literal: true

# Security and performance migration:
# - Add nonce column to messages for AEAD encryption
# - Add composite index on audit_logs(user_id, created_at) for query performance
# - Add case-insensitive functional index on users(username)
# - Add body column to filter from plaintext usage in production
class AddSecurityIndexesAndNonce < ActiveRecord::Migration[7.1]
  def change
    # Store unique nonce per encrypted message (AEAD requirement)
    add_column :messages, :nonce, :string

    # Composite index for audit log queries by user and time
    add_index :audit_logs, [:user_id, :created_at], name: "index_audit_logs_on_user_id_and_created_at"

    # Case-insensitive unique index on username for consistent lookups
    add_index :users, "LOWER(username)", unique: true, name: "index_users_on_lower_username"
  end
end
