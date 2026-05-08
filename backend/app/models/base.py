"""SQLAlchemy declarative base + shared mixins."""
from __future__ import annotations

import enum as _enum
from datetime import datetime, timezone
from typing import Type, TypeVar
from uuid import UUID, uuid4

from sqlalchemy import DateTime, Enum, MetaData
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

E = TypeVar("E", bound=_enum.Enum)


def pg_enum(enum_cls: Type[E], *, name: str, create_type: bool = False) -> Enum:
    """SQLAlchemy Enum type that sends enum *values* to Postgres, not member names.

    Required because Postgres enum labels are lowercase (`admin`, not `ADMIN`),
    while default SQLAlchemy behavior sends `member.name`.
    """
    return Enum(
        enum_cls,
        name=name,
        create_type=create_type,
        values_callable=lambda c: [m.value for m in c],
    )

NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class UuidPkMixin:
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )
