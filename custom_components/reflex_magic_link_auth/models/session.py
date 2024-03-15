"""The MagicLinkAuthSession model maps an email to a session_token."""

from __future__ import annotations

import datetime
import secrets

from sqlmodel import Column, DateTime, Field, func

import reflex as rx

from ..constants import DEFAULT_AUTH_SESSION_EXPIRATION_DELTA
from .record import MagicLinkAuthRecord


class MagicLinkAuthSession(rx.Model, table=True):
    email: str = Field(index=True, nullable=False)
    persistent_id: str = Field(index=True, nullable=False)
    session_token: str = Field(unique=True, index=True, nullable=False)
    created: datetime.datetime = Field(
        sa_column=Column(
            DateTime(timezone=True),
            server_default=func.now(),
            nullable=False,
        ),
    )
    expiration: datetime.datetime = Field(
        sa_column=Column(
            DateTime(timezone=True),
            server_default=func.now(),
            nullable=False,
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
