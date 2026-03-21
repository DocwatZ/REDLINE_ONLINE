# frozen_string_literal: true

class Users::OmniauthCallbacksController < Devise::OmniauthCallbacksController
  skip_before_action :verify_authenticity_token, only: [:github, :steam]

  def github
    handle_oauth("GitHub")
  end

  def steam
    handle_oauth("Steam")
  end

  def failure
    AuditService.log(
      action: "oauth.failure",
      metadata: { provider: params[:strategy], message: failure_message }
    )
    redirect_to new_user_session_path, alert: "Authentication failed: #{failure_message}"
  end

  private

  def handle_oauth(provider_name)
    user = OauthService.find_or_create_from_oauth(
      request.env["omniauth.auth"],
      current_user: current_user
    )

    if user.persisted?
      sign_in_and_redirect user, event: :authentication
      set_flash_message(:notice, :success, kind: provider_name) if is_navigational_format?
    else
      redirect_to new_user_session_path, alert: "Could not authenticate via #{provider_name}."
    end
  rescue StandardError => e
    Rails.logger.error("OAuth error for #{provider_name}: #{e.message}")
    redirect_to new_user_session_path, alert: "Authentication error. Please try again."
  end
end
