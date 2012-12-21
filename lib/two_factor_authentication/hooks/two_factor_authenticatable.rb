Warden::Manager.after_authentication do |user, auth, options|
  session = auth.session(options[:scope])

  if auth.session(options[:scope])[:need_two_factor_authentication] = user.try(:need_two_factor_authentication?, auth.request)
    user.two_factor_authentication!
  end
end
