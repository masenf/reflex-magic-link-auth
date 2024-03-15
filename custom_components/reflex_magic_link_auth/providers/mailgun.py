import os
import urllib

import httpx

import reflex as rx

config = rx.config.get_config()


APP_NAME = " ".join(w.capitalize() for w in config.app_name.split("_"))
API_URL = os.environ.get("MAILGUN_API_URL", "https://api.mailgun.net")
DOMAIN_NAME = os.environ.get("MAILGUN_DOMAIN_NAME")
API_KEY = os.environ.get("MAILGUN_API_KEY")
DEFAULT_SUBJECT = "Magic Login Link"
DEFAULT_HTML = "Click this link to log in: <a href='{magic_link}'>{magic_link}</a>"


def messages_endpoint():
    if DOMAIN_NAME is None:
        raise ValueError("MAILGUN_DOMAIN_NAME is required to send magic link emails.")
    return urllib.parse.urljoin(API_URL, f"/v3/{DOMAIN_NAME}/messages")


def default_from():
    return f"{APP_NAME} <{config.app_name}@{DOMAIN_NAME}>"


def email_from():
    return os.environ.get("MAGIC_LINK_EMAIL_FROM") or default_from()


def email_subject():
    return os.environ.get("MAGIC_LINK_EMAIL_SUBJECT", DEFAULT_SUBJECT)


def email_html():
    return os.environ.get("MAGIC_LINK_EMAIL_HTML", DEFAULT_HTML)


def send_magic_link_mailgun(email: str, magic_link: str) -> httpx.Response:
    """Send magic link email to user."""
    if API_KEY is None:
        raise ValueError("MAILGUN_API_KEY is required to send magic link emails.")
    data = {
        "from": email_from(),
        "to": email,
        "subject": email_subject(),
        "html": email_html().format(magic_link=magic_link),
    }
    response = httpx.post(messages_endpoint(), data=data, auth=("api", API_KEY))
    response.raise_for_status()
    return response
