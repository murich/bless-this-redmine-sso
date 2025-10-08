module BlessThisRedmineSso
  module Patches
    module UserPatch
      def is_oauth_user?
        # OAuth users are identified by:
        # 1. Having passwd_changed_on set (we set this during OAuth login)
        # 2. Not having must_change_passwd flag (we clear this for OAuth users)
        # 3. Having a very recent passwd_changed_on (within reasonable time since creation)

        return false if passwd_changed_on.nil?
        return false if must_change_passwd

        # If password was "changed" very recently after creation (within 5 minutes)
        # This indicates it was set by OAuth, not by the user
        if created_on && passwd_changed_on
          time_diff = (passwd_changed_on - created_on).abs
          return time_diff < 300 # 5 minutes in seconds
        end

        false
      end
    end
  end
end

# Apply the patch
Rails.application.config.after_initialize do
  unless User.included_modules.include?(BlessThisRedmineSso::Patches::UserPatch)
    User.prepend BlessThisRedmineSso::Patches::UserPatch
  end
end
