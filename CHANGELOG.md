# Changelog

Notable changes to `reflex-magic-link-auth`.

New entries are added by [towncrier](https://towncrier.readthedocs.io/) from the
news fragments under `news/` — see [Releasing](README.md#releasing). Everything
below `v0.2.0.post1` was reconstructed from the git history after the fact, so
it summarizes each release rather than reproducing entries that were never
written; alpha releases are omitted.

<!-- towncrier release notes start -->

## v0.2.1.post1 (2026-08-14)

### Miscellaneous

No significant changes (published for demo)

## v0.2.1 (2026-08-13)

### Bug Fixes

- Depend on `reflex[db]`. This component imports `sqlmodel` directly, and Reflex made it an optional extra, so installing against a recent Reflex left the import unsatisfied. ([#6](https://github.com/masenf/reflex-magic-link-auth/issues/6))

### Miscellaneous

- Releases are now changelog-driven. Entries accumulate as news fragments under `news/`, the Dispatch release workflow materializes them into `CHANGELOG.md` at the next version, and merging that pull request is what publishes — behind a required human approval on the `pypi` environment. Tags and GitHub releases are created only after a successful upload, so a failed release is retried by pushing a fix rather than by deleting a tag. ([#6](https://github.com/masenf/reflex-magic-link-auth/issues/6))


## v0.2.0.post1 (2025-09-05)

### Miscellaneous

- Require `reflex>=0.8.4`. Packaging-only release; the code is identical to v0.2.0.

## v0.2.0 (2025-09-05)

### Breaking Changes

- Require `reflex>=0.8.1`.

### Bug Fixes

- Read the magic link's query parameters from `router.url.query_parameters` instead of the removed `router.page.params`, so the auth route works again on Reflex 0.8. ([#5](https://github.com/masenf/reflex-magic-link-auth/issues/5))

## v0.1.2.post0 (2025-07-08)

### Miscellaneous

- Build and upload the distribution with `uv` in the publish workflow. Packaging-only release; the code is identical to v0.1.2.

## v0.1.2 (2025-07-08)

### Bug Fixes

- Resolve the client IP from the raw `x-forwarded-for` header, taking the first address of a comma-separated chain, so per-IP rate limiting sees real clients instead of the proxy when the app runs behind one. ([#4](https://github.com/masenf/reflex-magic-link-auth/issues/4))

## v0.1.1 (2025-02-12)

### Miscellaneous

- Demo app: only install the bundled test reCAPTCHA keys when none are configured in the environment, so the deployed demo can use real ones. No changes to the released library. ([#3](https://github.com/masenf/reflex-magic-link-auth/issues/3))

## v0.1.0 (2025-02-11)

### Breaking Changes

- Require `reflex>=0.7.0`. ([#2](https://github.com/masenf/reflex-magic-link-auth/issues/2))
- Require Python 3.10 or newer, up from 3.8.

### Features

- Derive the package version from git tags with `setuptools-scm` instead of hard-coding it in `pyproject.toml`.

### Bug Fixes

- Expiring outstanding OTPs, deleting a user's OTPs and logging out now persist: the bulk `update()`/`delete()` statements they issued were replaced with per-row updates that are committed through the session. ([#2](https://github.com/masenf/reflex-magic-link-auth/issues/2))
- Declare event handlers with `@rx.event` and computed vars with an explicit `cache=`, as Reflex 0.7 requires. ([#2](https://github.com/masenf/reflex-magic-link-auth/issues/2))

### Miscellaneous

- Run ruff, codespell and pyright from pre-commit, and check them on every pull request. ([#2](https://github.com/masenf/reflex-magic-link-auth/issues/2))

## v0.0.4 (2024-09-19)

### Breaking Changes

- Require `reflex>=0.5.0`. ([#1](https://github.com/masenf/reflex-magic-link-auth/issues/1))

### Bug Fixes

- Replace `rx.cached_var`, deprecated in Reflex 0.6.0, with `rx.var(cache=True)`. ([#1](https://github.com/masenf/reflex-magic-link-auth/issues/1))

### Miscellaneous

- Demo app: check production mode on the backend only, and migrate the database on app load so it runs on hosting with a temporary sqlite database. ([#1](https://github.com/masenf/reflex-magic-link-auth/issues/1))

## v0.0.3 (2024-04-10)

First tagged release.

### Features

- Passwordless email login for Reflex apps: `MagicLinkAuthState` issues a one-time password, mails a magic link for it, and validates the link on the `/magic-link-auth` route provided by `magic_link_auth_page`.
- `send_magic_link_mailgun` sends the links through the Mailgun API.
- Authenticated sessions are backed by `MagicLinkAuthSession`, with the session token kept in sync across browser tabs.
- One-time passwords are rate limited per email address and per client IP, and only one OTP is valid for an address at a time.
- Expirations and rate limits are configurable through `constants`.
- A demo app under `magic_link_auth_demo/` shows the flow end to end, including an optional Google reCAPTCHA challenge in production mode.
