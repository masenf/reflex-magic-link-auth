"""MagicAuthLinkState generates OTPs and validates login sessions."""

from __future__ import annotations

import datetime
import secrets
import urllib

from sqlmodel import delete, func, update, Session

import reflex as rx

from .constants import AUTH_ROUTE, DEFAULT_OTP_EXPIRATION_DELTA, DEFAULT_OTP_RATE_LIMIT
from .models import MagicLinkAuthRecord, MagicLinkAuthSession


class MagicLinkBaseState(rx.State):
    """State for handling dynamic retrieval of the frontend URL."""

    auth_url: str

    def get_base_url(self):
        """EventHandler triggers a request for the frontend URL."""
        return rx.call_script(
            "window.location.origin", callback=type(self).get_auth_url_cb
        )

    def get_auth_url_cb(self, base_url):
        """Callback that accepts and stores the frontend URL for validating OTP."""
        self.auth_url = urllib.parse.urljoin(base_url, AUTH_ROUTE)

    def _get_magic_link(self, record: MagicLinkAuthRecord, otp: str):
        """Helper function to format the magic link URL."""
        url_parts = urllib.parse.urlparse(self.auth_url)
        return urllib.parse.urlunparse(
            url_parts._replace(
                query=urllib.parse.urlencode(
                    {"email": record.email, "otp": otp, "redir": "/"},
                ),
            ),
        )


class MagicLinkAuthState(MagicLinkBaseState):
    """State for handling generation and validation of OTP."""

    session_token: str = rx.LocalStorage()

    def _get_current_record(
        self, session: Session, email: str
    ) -> MagicLinkAuthRecord | None:
        return session.exec(
            MagicLinkAuthRecord.select()
            .where(
                MagicLinkAuthRecord.email == email,
                MagicLinkAuthRecord.expiration >= func.now(),
            )
            .order_by(MagicLinkAuthRecord.created.desc())
            .limit(1),
        ).one_or_none()

    def _expire_outstanding_otps(self, session: Session, email: str):
        # Kill unexpired OTPs for this email (only one active at a time).
        session.exec(
            update(MagicLinkAuthRecord)
            .where(
                MagicLinkAuthRecord.email == email,
                MagicLinkAuthRecord.expiration >= func.now(),
            )
            .values(
                expiration=datetime.datetime.now(datetime.timezone.utc),
            ),
        )

    def _delete_all_otps(self, session: Session, email: str):
        session.exec(
            delete(MagicLinkAuthRecord).where(MagicLinkAuthRecord.email == email)
        )

    def _generate_otp(
        self,
        email: str,
        expiration_delta: datetime.timedelta = DEFAULT_OTP_EXPIRATION_DELTA,
        rate_limit: int = DEFAULT_OTP_RATE_LIMIT,
    ) -> tuple[MagicLinkAuthRecord | None, str | None]:
        if not email:
            return None, None
        if "@" not in email[1:]:
            return None, None
        otp = secrets.token_hex(4)
        recent_attempts = 0
        with rx.session() as session:
            record = self._get_current_record(session, email)
            if record is not None:
                record.update_recent_attempts(session, expiration_delta)
                if record.recent_attempts >= rate_limit:
                    return record, None
                recent_attempts = record.recent_attempts
                self._expire_outstanding_otps(session, email)
            record = MagicLinkAuthRecord(  # type: ignore
                email=email,
                otp_hash=MagicLinkAuthRecord.hash_token(otp),
                expiration=datetime.datetime.now(datetime.timezone.utc)
                + expiration_delta,
                recent_attempts=recent_attempts + 1,
            )
            session.add(record)
            session.commit()
            session.refresh(record)
        return record, otp

    def _validate_otp(self, email: str, otp: str) -> bool:
        with rx.session() as session:
            record = self._get_current_record(session, email)
            if record and record.verify(otp):
                # Do not allow OTP reuse for this user.
                self._delete_all_otps(session, email)
                # Establish the session.
                auth_session = MagicLinkAuthSession.from_record(record)
                self.session_token = auth_session.session_token
                session.add(auth_session)
                session.commit()
                return True
        return False

    @rx.cached_var
    def auth_session(self) -> MagicLinkAuthSession | None:
        with rx.session() as session:
            auth_session_row = session.exec(
                MagicLinkAuthSession.select()
                .where(
                    MagicLinkAuthSession.session_token == self.session_token,
                    MagicLinkAuthSession.expiration >= func.now(),
                )
                .limit(1),
            ).one_or_none()
            if auth_session_row is not None:
                # Convert to UTC datetime, if necessary (sqlite does not respect timezone=True).
                if auth_session_row.expiration.tzinfo is None:
                    auth_session_row.expiration = auth_session_row.expiration.replace(
                        tzinfo=datetime.timezone.utc
                    )
                if auth_session_row.created.tzinfo is None:
                    auth_session_row.created = auth_session_row.created.replace(
                        tzinfo=datetime.timezone.utc
                    )
                return auth_session_row

    @rx.var
    def session_is_valid(self) -> bool:
        return (
            self.auth_session is not None
            and self.auth_session.expiration
            >= datetime.datetime.now(datetime.timezone.utc)
        )

    def logout(self):
        with rx.session() as session:
            session.exec(
                update(MagicLinkAuthSession)
                .where(
                    MagicLinkAuthSession.session_token == self.session_token,
                )
                .values(
                    expiration=datetime.datetime.now(datetime.timezone.utc),
                ),
            )
            session.commit()
        self.session_token = ""
