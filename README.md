# reflex-magic-link-auth

Generate and verify "magic link" one time passwords for user authentication without
complex registration flows.

## Installation

```bash
pip install reflex-magic-link-auth
```

## Usage

See
[`magic_link_auth_demo/magic_link_auth_demo.py`](magic_link_auth_demo/magic_link_auth_demo.py)
for a complete example.

### 1. Collect the User email

You can use a simple form with a single input field and button, like the
example, or present a form prompting for more information, such as a name,
address, zip code, etc. Any additional data should be associated with the
provided email as the main key for the account.

### 2. Substate from MagicLinkAuthState

The substate which handles the authentication form submission should be
a substate of `reflex_magic_link_auth.MagicLinkAuthState` (alternatively, it
may get an instance of this state via `.get_state` API).

### 3. Generate the OTP

When the user submits the form, generate a one time password by calling
`._generate_otp` and providing the email address.

This function returns a 2-tuple:

* The latest record associated with the email address
* The one time password in plaintext

If the record is None, then the email address was invalid, or some other problem
occurred (ensure database migration has been applied).

If the record is returned, but the OTP is None, then the user has exceeded the
configured rate limit and cannot receive a new token for a while.

### 4. Send the Magic Link

Either on page `on_load` or some component `on_mount` should trigger
`reflex_magic_link_auth.MagicLinkAuthState.get_base_url` to ensure the state
knows the correct frontend URL when formatting the magic links.

Pass the `record` and `otp` to
`reflex_magic_link_auth.MagicLinkAuthState._get_magic_link` to get a URL that,
when accessed will log the user in to the app.

While this component contains an example mailgun provider, generally it is
up to you to actually email the link to the user.

### 5. User Accesses the Magic Link

The user clicks the link in their email, and the page mounted at
`reflex_magic_link_auth.constants.AUTH_ROUTE` will validate the token and
redirect to the URL specified in the query param `redir`.

### 6. Verifying Access

Any event handlers which depend on user session validity should check the computed var
`reflex_magic_link_auth.MagicLinkAuthState.session_is_valid` to determine if the user is
logged in and the session has not expired.

A persistent external identifier hashed over the email address is provided at
`reflex_magic_link_auth.MagicLinkAuthState.auth_session.persistent_id`. When interoperating
with other user information systems, this ID can be used to uniquely identify a user
originating from reflex-magic-link-auth.

### 7. Logout

To log the user out, trigger the event handler
`reflex_magic_link_auth.MagicLinkAuthState.logout`.

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

## Contributing

Every pull request that changes `custom_components/` needs a news fragment — a
short markdown file under `news/`, named `<pr-number>.<type>.md`, written for
someone reading release notes:

```bash
uvx --from "reflex-release @ git+https://github.com/reflex-dev/reflex@6d1f46663b4d5a9d193798689e8aa683d50e5172#subdirectory=packages/reflex-release" \
  reflex-release create 123.bugfix.md
```

The types are `breaking`, `deprecation`, `feature`, `bugfix`, `performance`,
`docs` and `misc`. Before the PR number is known, name the file
`+something.bugfix.md` and rename it later. The `skip-changelog` label waives
the requirement for changes that are not user-facing.

Do not edit `CHANGELOG.md` by hand: a new version heading on `main` is what
triggers a publish, so CI rejects headings that were not written by the release
workflow.

## Releasing

Releases are changelog-driven, via
[reflex-release](https://github.com/reflex-dev/reflex/tree/main/packages/reflex-release).

1. Run **Dispatch release** from the Actions tab and pick an action
   (`release-patch`/`-minor`/`-major`, `release-post`, or one of the
   prerelease actions). It runs towncrier over `news/`, writes the new
   `CHANGELOG.md` section, and opens a pull request.
2. Merge that pull request. The push to `main` is what publishes: **Release
   from changelog** finds the changelog version that has no git tag, builds it,
   and waits for approval on the `pypi` environment before uploading.
3. After a successful upload the tag and GitHub release are created, and
   **Deploy demo app** redeploys `magic_link_auth_demo` against the new version.

Because tags are only created after a successful upload, a failed release is
retried by pushing a fix on top of the changelog bump — there is nothing to
clean up.

Upgrading the release tooling is a `cli-command` bump in `pyproject.toml`
followed by `reflex-release sync`; the pull-request check fails while the
generated workflows are out of date.