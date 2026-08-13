"""Declarative base shared by this component's tables."""

from __future__ import annotations

from sqlmodel import Field, SQLModel, select


class MagicLinkAuthModel(SQLModel):
    """Base class for the tables defined by this component.

    Stands in for `rx.Model`, which Reflex deprecated in 0.9.2 in favor of
    using the ORM layer directly. It reproduces the parts of `rx.Model` these
    tables were relying on -- the `id` primary key, the model config, and the
    `select()` helper -- so both the schema and the public API are unchanged:
    SQLModel derives `__tablename__` from the class name either way.

    The tables land in `SQLModel.metadata`, which is what `reflex db` migrates,
    so there is nothing to register with `rx.ModelRegistry`. Registering this
    base there would in fact make `ModelRegistry.get_metadata()` copy every
    table twice -- once for this base and once for the still-registered
    `rx.Model` -- and warn about it.
    """

    id: int | None = Field(default=None, primary_key=True)

    # Carried over verbatim from `rx.Model` so that constructing or subclassing
    # these tables behaves exactly as it did before.
    model_config = {
        "arbitrary_types_allowed": True,
        "use_enum_values": True,
        "extra": "allow",
    }

    @classmethod
    def select(cls):
        """Select rows from the table.

        Returns:
            The select statement.
        """
        return select(cls)
