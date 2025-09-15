# Changelog

## 2.0.0 - 2025-09-13 (by Jan Catrysse)
- OAuth endpoints accessible without prior Redmine login or login disabled (authorize/callback skip `check_if_login_required`).
- Reactivated CSRF protection.
- Localized UI and flash messages; new locales (en, nl, fr, de, es, it, pt).
- Configurable user mapping (login/email/first/last), presets (generic/microsoft/google), and mapping to User Custom Fields.
- Provisioning options: toggles for auto-create and update-existing; default group assignment for new users.
- MFA bypass option for SSO logins.
- Configurable login or email vs. login only matching.
- Full OAuth `validate_flow` rake task to inspect code→token→userinfo and resolved mappings.
- Expanded rake suite: `enable|disable`, `enable_sso_only|disable_sso_only`, `enable_bypass_twofa|disable_bypass_twofa`,
  `configure`, `status`, `test`, `help`; consistent boolean parsing (`1/true`).
- User provisioning now maps User Custom Fields via per-field key lists.
- Provider logout support via configurable Logout URL.
- Email matching/updates now case-insensitive via `EmailAddress`.
- SSO-only: login redirect can include `prompt=login` when needed.
- Logout flow: optional redirect to provider logout URL; otherwise next authorize forces re-auth.
- Added RSpec tests and GitHub Actions workflows for Redmine 5.1 and 6.0.
- Add timeouts and error handling for HTTP requests
