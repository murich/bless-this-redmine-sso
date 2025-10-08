module BlessThisRedmineSso
  module Patches
    module UserPatch
      def is_oauth_user?
        # Check if user has the oauth_user custom field set to true
        # This is more reliable than time-based checks
        custom_value = self.custom_field_values.find { |cv| cv.custom_field.name == 'OAuth User' }
        return custom_value && custom_value.value == '1' if custom_value

        # Fallback to time-based check for backward compatibility
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

      def mark_as_oauth_user!
        # Set custom field to mark this user as OAuth user
        cf = CustomField.find_by(name: 'OAuth User', type: 'UserCustomField')
        unless cf
          # Create the custom field if it doesn't exist
          cf = UserCustomField.create!(
            name: 'OAuth User',
            field_format: 'bool',
            is_required: false,
            is_filter: true,
            searchable: false,
            visible: false, # Hidden from UI
            editable: false
          )
        end

        # Set the value - use custom_values (ActiveRecord relation) not custom_field_values (array)
        cv = self.custom_values.find_or_initialize_by(custom_field_id: cf.id)
        cv.value = '1'
        cv.save!

        # Reload to refresh custom_field_values cache
        self.reload
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
