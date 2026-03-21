# frozen_string_literal: true

# REDLINE Secure Cookie Configuration
# Enforces HttpOnly, SameSite=Lax, and Secure flags on session cookies.
Rails.application.config.session_store :cookie_store,
  key: "_redline_session",
  httponly: true,
  same_site: :lax,
  secure: Rails.env.production?
