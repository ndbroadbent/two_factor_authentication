class Devise::TwoFactorAuthenticationController < DeviseController
  prepend_before_filter :authenticate_scope!
  before_filter :prepare_and_validate, :handle_two_factor_authentication

  def show
  end

  def update
    render :show and return if params[:code].nil?
    md5 = Digest::MD5.hexdigest(params[:code])
    if md5.eql?(resource.second_factor_pass_code)
      warden.session(resource_name)[:need_two_factor_authentication] = false
      sign_in resource_name, resource, :bypass => true
      redirect_to stored_location_for(resource_name) || try(:after_two_factor_auth_path_for, resource) || :root
      resource.update_attribute(:second_factor_attempts_count, 0)

      if params[:trust_this_device] == '1'
        # Create new trusted device and store in cookie
        device = TrustedUserDevice.create :user => resource
        cookies.permanent.signed[:trusted_device_uid] = {:value => device.uid, :domain => :all}
      end
    else
      resource.second_factor_attempts_count += 1
      resource.save
      set_flash_message :notice, :attempt_failed
      if resource.max_login_attempts?
        sign_out(resource)
        render :template => 'devise/two_factor_authentication/max_login_attempts_reached' and return
      else
        render :show
      end
    end
  end

  private

    def authenticate_scope!
      self.resource = send("current_#{resource_name}")
    end

    def prepare_and_validate
      redirect_to :root and return if resource.nil?
      @limit = resource.class.max_login_attempts
      if resource.max_login_attempts?
        sign_out(resource)
        render :template => 'devise/two_factor_authentication/max_login_attempts_reached' and return
      end
    end
end
