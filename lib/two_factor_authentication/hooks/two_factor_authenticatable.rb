Warden::Manager.after_authentication do |user, auth, options|
  session = auth.session(options[:scope])

  if user.try(:need_two_factor_authentication?, auth.request)
    uid = auth.cookies.signed[:trusted_device_uid]
    if uid.present?
      next if TrustedUserDevice.where(:user_id => user.id, :uid => uid).exists?
    end

    auth.session(options[:scope])[:need_two_factor_authentication] = true
    user.two_factor_authentication!
  end
end
