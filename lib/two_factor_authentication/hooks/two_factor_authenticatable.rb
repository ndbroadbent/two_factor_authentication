Warden::Manager.after_authentication do |user, auth, options|
  if user.try(:need_two_factor_authentication?, auth.request)
    if uid = auth.cookies.signed[:trusted_device_uid]
      # Skip two-factor auth if logging in from trusted device
      next if TrustedUserDevice.where(:user_id => user.id, :uid => uid).exists?
    end

    auth.session(options[:scope])[:need_two_factor_authentication] = true
    user.two_factor_authentication!
  end
end
