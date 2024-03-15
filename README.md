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
occured (ensure database migration has been applied).

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
with other user information systems, this ID can be used to uniquely identifer a user
originating from reflex-magic-link-auth.

### 7. Logout

To log the user out, trigger the event handler
`reflex_magic_link_auth.MagicLinkAuthState.logout`.