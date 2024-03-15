"""Reflex custom component MagicLinkAuth."""
from __future__ import annotations

import datetime
import secrets
import urllib

import bcrypt
from sqlmodel import Column, DateTime, Field, delete, func, update, Session, select

import reflex as rx


AUTH_ROUTE = "/magic-link-auth"
DEFAULT_OTP_EXPIRATION_DELTA = datetime.timedelta(minutes=30)
DEFAULT_OTP_RATE_LIMIT = 5
DEFAULT_AUTH_SESSION_EXPIRATION_DELTA = datetime.timedelta(days=7)


class MagicLinkAuthRecord(rx.Model, table=True):
    """Stores the generated OTP to authenticate the user."""
    email: str
    otp_hash: bytes
    created: datetime.datetime = Field(
        sa_column=Column(
            DateTime(timezone=True), server_default=func.now(), nullable=False,
        ),
    )
    expiration: datetime.datetime = Field(
        sa_column=Column(
            DateTime(timezone=True), server_default=func.now(), nullable=False
        ),
    )
    # How many times have we regenerated the OTP for this email in the last DEFAULT_OTP_EXPIRATION_DELTA?
    recent_attempts: int = Field(default=0)

    @staticmethod
    def hash_token(token: str) -> bytes:
        """Hash the token using bcrypt.

        Args:
            token: The password to hash.

        Returns:
            The hashed token.
        """
        return bcrypt.hashpw(
            password=token.encode("utf-8"),
            salt=bcrypt.gensalt(),
        )

    def verify(self, token: str) -> bool:
        """Validate the otp_hash.

        Args:
            token: The password to check.

        Returns:
            True if the hashed token matches this user's otp_hash.
        """
        return bcrypt.checkpw(
            password=token.encode("utf-8"),
            hashed_password=self.otp_hash,
        )

    def persistent_id(self) -> str:
        """Return a unique identifier for the user."""
        return self.hash_token(self.email).decode("utf-8")

    def update_recent_attempts(self, session: Session, delta: datetime.timedelta):
        """Update the recent_attempts count for this email."""
        self.recent_attempts = session.exec(
            select(func.count()).where(
                MagicLinkAuthRecord.email == self.email,
                MagicLinkAuthRecord.created >= datetime.datetime.now(datetime.timezone.utc) - delta,
            ),
        ).one()


class MagicLinkAuthSession(rx.Model, table=True):
    """Correlate a session_token with an arbitrary email."""
    email: str = Field(index=True, nullable=False)
    persistent_id: str = Field(index=True, nullable=False)
    session_token: str = Field(unique=True, index=True, nullable=False)
    created: datetime.datetime = Field(
        sa_column=Column(
            DateTime(timezone=True), server_default=func.now(), nullable=False,
        ),
    )
    expiration: datetime.datetime = Field(
        sa_column=Column(
            DateTime(timezone=True), server_default=func.now(), nullable=False,
        ),
    )

    @classmethod
    def from_record(
        cls,
        record: MagicLinkAuthRecord,
        expiration_delta: datetime.timedelta = DEFAULT_AUTH_SESSION_EXPIRATION_DELTA,
    ) -> MagicLinkAuthSession:
        return cls(
            email=record.email,
            persistent_id=record.persistent_id(),
            session_token=secrets.token_hex(32),
            expiration=datetime.datetime.now(datetime.timezone.utc) + expiration_delta,
        )


class MagicLinkBaseState(rx.State):
    auth_url: str

    def get_auth_url_cb(self, base_url):
        self.auth_url = urllib.parse.urljoin(base_url, AUTH_ROUTE)

    def get_base_url(self):
        return rx.call_script("window.location.origin", callback=type(self).get_auth_url_cb)

    def _get_magic_link(self, record: MagicLinkAuthRecord, otp: str):
        url_parts = urllib.parse.urlparse(self.auth_url)
        return urllib.parse.urlunparse(
            url_parts._replace(
                query=urllib.parse.urlencode({"email": record.email, "otp": otp, "redir": "/"})
            )
        )


class MagicLinkAuthState(MagicLinkBaseState):
    """MagicLinkAuth state."""
    session_token: str = rx.LocalStorage()

    def _expire_outstanding_otps(self, session: Session, email: str):
        # Kill unexpired OTPs for this email (only one active at a time).
        session.exec(
            update(MagicLinkAuthRecord).where(
                MagicLinkAuthRecord.email == email,
                MagicLinkAuthRecord.expiration >= func.now(),
            ).values(
                expiration=datetime.datetime.now(datetime.timezone.utc),
            ),
        )

    def _delete_all_otps(self, session: Session, email: str):
        session.exec(delete(MagicLinkAuthRecord).where(MagicLinkAuthRecord.email == email))

    def _get_current_record(self, session: Session, email: str) -> MagicLinkAuthRecord | None:
        return session.exec(
            MagicLinkAuthRecord.select().where(
                MagicLinkAuthRecord.email == email,
                MagicLinkAuthRecord.expiration >= func.now(),
            ).order_by(MagicLinkAuthRecord.created.desc()).limit(1),
        ).one_or_none()

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
                expiration=datetime.datetime.now(datetime.timezone.utc) + expiration_delta,
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
                MagicLinkAuthSession.select().where(
                    MagicLinkAuthSession.session_token == self.session_token,
                    MagicLinkAuthSession.expiration >= func.now(),
                ).limit(1),
            ).one_or_none()
            if auth_session_row is not None:
                # Convert to UTC datetime, if necessary (sqlite does not respect timezone=True).
                if auth_session_row.expiration.tzinfo is None:
                    auth_session_row.expiration = auth_session_row.expiration.replace(tzinfo=datetime.timezone.utc)
                if auth_session_row.created.tzinfo is None:
                    auth_session_row.created = auth_session_row.created.replace(tzinfo=datetime.timezone.utc)
                return auth_session_row

    @rx.var
    def session_is_valid(self) -> bool:
        return self.auth_session is not None and self.auth_session.expiration >= datetime.datetime.now(datetime.timezone.utc)

    def logout(self):
        with rx.session() as session:
            session.exec(
                update(MagicLinkAuthSession).where(
                    MagicLinkAuthSession.session_token == self.session_token,
                ).values(
                    expiration=datetime.datetime.now(datetime.timezone.utc),
                ),
            )
            session.commit()
        self.session_token = ""


class HandleMagicLinkState(MagicLinkAuthState):
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
