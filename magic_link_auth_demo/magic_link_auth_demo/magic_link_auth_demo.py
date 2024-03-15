import reflex as rx

from reflex_magic_link_auth import MagicLinkAuthState


class State(MagicLinkAuthState):
    login_error: str = ""

    def handle_submit_login(self, form_data):
        self.login_error = ""
        record, otp = self._generate_otp(form_data["email"])
        if otp is None:
            if record is not None:
                self.login_error = "Too many attempts. Please try again later."
            else:
                self.login_error = "Invalid email."
            return
        print(self._get_magic_link(record, otp))
        return rx.redirect("/check-your-email")


def index() -> rx.Component:
    return rx.cond(
        State.is_hydrated & MagicLinkAuthState.session_is_valid,
        rx.vstack(
            rx.heading("Welcome back!", size="9"),
            rx.text(f"You are logged in as {MagicLinkAuthState.auth_session.email}."),
            rx.button("Logout", on_click=MagicLinkAuthState.logout),
            align="center",
            spacing="7",
        ),
        rx.vstack(
            rx.heading("Enter your email to log in", size="9"),
            rx.cond(
                State.login_error,
                rx.callout.root(
                    rx.callout.text(State.login_error, color="red"),
                ),
            ),
            rx.form(
                rx.input(name="email"),
                rx.button("Send Magic Link"),
                on_submit=State.handle_submit_login,
                on_mount=MagicLinkAuthState.get_base_url,
            ),
        ),
    )


@rx.page()
def check_your_email() -> rx.Component:
    return rx.vstack(
        rx.heading("Check your email for a magic link!", size="9"),
        rx.text("You may close this tab."),
        align="center",
        spacing="7",
    )


# Add state and page to the app.
app = rx.App()
app.add_page(index)
