import reflex as rx

config = rx.Config(
    app_name="magic_link_auth_demo",
    db_url="sqlite:///reflex.db",
    plugins=[
        # Enabled by default, but Reflex warns until it is named explicitly.
        rx.plugins.SitemapPlugin(),
        # The login form is built from Radix components; declaring the plugin
        # opts in to the Radix stylesheet instead of having it pulled in
        # implicitly, which Reflex deprecated in 0.9.0.
        rx.plugins.RadixThemesPlugin(),
    ],
)
