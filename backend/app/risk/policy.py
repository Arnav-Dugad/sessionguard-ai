"""Zero-Trust policy configuration (persisted in ``policy_configs``)."""
from __future__ import annotations

import copy
from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator
from sqlalchemy.orm import Session

from app.models import PolicyConfig


class Weights(BaseModel):
    ml: float = Field(60, ge=0, le=100)
    device: float = Field(35, ge=0, le=100)
    network: float = Field(30, ge=0, le=100)
    concurrency: float = Field(45, ge=0, le=100)
    behavior: float = Field(30, ge=0, le=100)
    auth: float = Field(25, ge=0, le=100)
    sensitive: float = Field(20, ge=0, le=100)
    synthetic: float = Field(40, ge=0, le=100)


class Thresholds(BaseModel):
    elevated: float = Field(25, ge=1, le=98)
    high: float = Field(50, ge=2, le=99)
    critical: float = Field(75, ge=3, le=100)

    @model_validator(mode="after")
    def ordered(self) -> "Thresholds":
        if not (self.elevated < self.high < self.critical):
            raise ValueError("thresholds must satisfy elevated < high < critical")
        return self


class Policy(BaseModel):
    weights: Weights = Weights()
    thresholds: Thresholds = Thresholds()
    decay_per_request: float = Field(0.9, ge=0.5, le=1.0)
    half_life_s: float = Field(300, ge=10, le=86400)
    # Operating point for the ML signal: probabilities below the floor are treated as no
    # evidence (removes the model's benign baseline offset); above it, strength scales to 1.
    # This is a calibration/operating-point choice, documented in docs/ARCHITECTURE.md.
    ml_floor: float = Field(0.45, ge=0.0, le=0.9)
    critical_action: Literal["revoke", "deny_sensitive"] = "revoke"
    step_up_on_context_change: bool = True
    context_change_threshold: float = Field(0.5, ge=0.05, le=1.0)
    enforcement: Literal["enforce", "monitor"] = "enforce"
    ml_enabled: bool = True


DEFAULT_POLICY = Policy()


def load_policy(db: Session) -> Policy:
    row = db.query(PolicyConfig).filter_by(name="active").one_or_none()
    if row is None:
        return copy.deepcopy(DEFAULT_POLICY)
    try:
        return Policy.model_validate(row.config)
    except ValueError:
        return copy.deepcopy(DEFAULT_POLICY)


def save_policy(db: Session, policy: Policy, updated_by: str | None) -> Policy:
    row = db.query(PolicyConfig).filter_by(name="active").one_or_none()
    data: dict[str, Any] = policy.model_dump()
    if row is None:
        row = PolicyConfig(name="active", config=data, updated_by=updated_by)
        db.add(row)
    else:
        row.config = data
        row.updated_by = updated_by
    db.commit()
    return policy
