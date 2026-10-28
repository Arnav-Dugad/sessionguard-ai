"""Request bodies (responses are plain dicts built by the serialisers in each module)."""
from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, Field, field_validator


class RegisterIn(BaseModel):
    username: str = Field(min_length=3, max_length=32)
    email: str = Field(min_length=5, max_length=255)
    password: str = Field(min_length=10, max_length=128)
    display_name: str = Field(default="", max_length=64)

    @field_validator("username")
    @classmethod
    def _username(cls, v: str) -> str:
        if not re.fullmatch(r"[a-zA-Z0-9_.-]+", v):
            raise ValueError("letters, digits, '.', '_' and '-' only")
        return v.lower()

    @field_validator("email")
    @classmethod
    def _email(cls, v: str) -> str:
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", v):
            raise ValueError("invalid email address")
        return v.lower()

    @field_validator("password")
    @classmethod
    def _password(cls, v: str) -> str:
        classes = sum(bool(re.search(p, v)) for p in (r"[a-z]", r"[A-Z]", r"\d", r"[^a-zA-Z0-9]"))
        if classes < 3:
            raise ValueError("use at least three of: lowercase, uppercase, digits, symbols")
        return v


class LoginIn(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=128)


class ReauthIn(BaseModel):
    password: str = Field(min_length=1, max_length=128)


class TransferIn(BaseModel):
    recipient: str = Field(min_length=2, max_length=64)
    amount: float = Field(gt=0, le=100000)
    memo: str = Field(default="", max_length=140)


class ChangeEmailIn(BaseModel):
    email: str = Field(min_length=5, max_length=255)

    @field_validator("email")
    @classmethod
    def _email(cls, v: str) -> str:
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", v):
            raise ValueError("invalid email address")
        return v.lower()


class SimulationStartIn(BaseModel):
    scenario: str
    mode: Literal["sessionguard", "traditional"] = "sessionguard"


class SimulationStepIn(BaseModel):
    run_id: int


class SimulationResetIn(BaseModel):
    wipe_history: bool = False


class ActiveModelIn(BaseModel):
    model: Literal["rules", "logreg", "xgboost", "aexgb"]
