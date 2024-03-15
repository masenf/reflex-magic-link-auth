"""Page for handling magic link authentication."""

import reflex as rx

from .constants import AUTH_ROUTE
from .state import MagicLinkAuthState


class HandleMagicLinkState(MagicLinkAuthState):
    """Validate email and OTP from query params, then redirect."""

    token_valid: bool = False

    def on_load(self):
        params = self.router.page.params
        email = params.get("email")
        otp = params.get("otp")
        redir = params.get("redir")
        if email is None or otp is None:
            return
        self.token_valid = self._validate_otp(email, otp)
        if self.token_valid and redir is not None:
            return rx.redirect(redir)


@rx.page(AUTH_ROUTE, on_load=HandleMagicLinkState.on_load)
def magic_link_auth_page():
    """Simple page component for handling magic link authentication in query params."""
    return rx.vstack(
        rx.cond(
            HandleMagicLinkState.is_hydrated,
            rx.cond(
                HandleMagicLinkState.token_valid,
                rx.heading("Login successful!"),
                rx.heading("Login failed!"),
            ),
            rx.heading("Validating Token..."),
        ),
    )
