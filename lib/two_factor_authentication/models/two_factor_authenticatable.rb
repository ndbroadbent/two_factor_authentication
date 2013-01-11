require 'two_factor_authentication/hooks/two_factor_authenticatable'
module Devise
  module Models
    module TwoFactorAuthenticatable
      extend ActiveSupport::Concern

      module ClassMethods
        ::Devise::Models.config(self, :login_code_random_pattern, :max_login_attempts)
      end

      def two_factor_authentication!
        code = generate_two_factor_code
        self.second_factor_pass_code = Digest::MD5.hexdigest(code)
        save!
        send_two_factor_authentication_code(code)
      end

      def need_two_factor_authentication?(request)
        true
      end

      def generate_two_factor_code
        self.class.login_code_random_pattern.gen
      end

      def send_two_factor_authentication_code(code)
        p "Code is #{code}"
      end

      def confirm_two_factor_authentication!
        pending_mobile = self.second_factor_pending_mobile
        reset_two_factor_attributes

        self.second_factor_mobile = pending_mobile
        self.second_factor_active = true
        save!
      end

      def remove_two_factor_authentication!
        reset_two_factor_attributes
        save!
      end

      def max_login_attempts?
        second_factor_attempts_count >= self.class.max_login_attempts
      end

      private

      def reset_two_factor_attributes
        self.second_factor_mobile = self.second_factor_pending_mobile = nil
        self.second_factor_active = false
        self.second_factor_pending = false
        self.second_factor_pass_code = nil
        self.second_factor_attempts_count = 0
      end
    end
  end
end
