Warden::Manager.after_authentication do |user, auth, options|
  session = auth.session(options[:scope])

  if user.try(:need_two_factor_authentication?, auth.request)
    uid = auth.cookies.signed[:trusted_device_uid]
    trusted_device = uid.present? && TrustedUserDevice.where(:user_id => user.id, :uid => uid).exists?

    auth.session(options[:scope])[:need_two_factor_authentication] = !trusted_device
    user.two_factor_authentication! unless trusted_device
  end
end
