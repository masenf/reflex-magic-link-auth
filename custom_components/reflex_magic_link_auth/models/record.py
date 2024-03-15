"""The MagicLinkAuthRecord temporarily stores the generated OTP for an email."""

from __future__ import annotations

import datetime

import bcrypt
from sqlmodel import Column, DateTime, Field, func, Session, select

import reflex as rx


class MagicLinkAuthRecord(rx.Model, table=True):
    email: str
    otp_hash: bytes
    created: datetime.datetime = Field(
        sa_column=Column(
            DateTime(timezone=True),
            server_default=func.now(),
            nullable=False,
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
                MagicLinkAuthRecord.created
                >= datetime.datetime.now(datetime.timezone.utc) - delta,
            ),
        ).one()
