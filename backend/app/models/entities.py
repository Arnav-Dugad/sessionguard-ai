"""Relational schema for SessionGuard AI."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base, utcnow


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(128), default="")
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(16), default="user")  # user | admin
    is_demo: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    sessions: Mapped[list[UserSession]] = relationship(back_populates="user", cascade="all, delete-orphan")


class UserSession(Base):
    __tablename__ = "sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    public_id: Mapped[str] = mapped_column(String(24), unique=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_activity: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    revoked_reason: Mapped[str | None] = mapped_column(String(255), nullable=True)

    device_profile: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)  # latest observed
    network_context: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)  # latest observed
    baseline_device: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    baseline_network: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    peak_risk: Mapped[float] = mapped_column(Float, default=0.0)
    status: Mapped[str] = mapped_column(String(24), default="active")  # active|step_up|revoked|expired|logged_out|rotated
    protection_mode: Mapped[str] = mapped_column(String(16), default="sessionguard")  # sessionguard | traditional
    is_lab: Mapped[bool] = mapped_column(Boolean, default=False)
    step_up_until: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    rotated_from_id: Mapped[int | None] = mapped_column(ForeignKey("sessions.id"), nullable=True)
    csrf_secret: Mapped[str] = mapped_column(String(64))
    request_count: Mapped[int] = mapped_column(Integer, default=0)
    baseline_ts: Mapped[float] = mapped_column(Float, default=0.0)  # epoch of creation / last step-up
    last_ts: Mapped[float] = mapped_column(Float, default=0.0)  # epoch of last request (virtual for lab)
    alert_state: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)  # de-duplicates repeated alerts

    user: Mapped[User] = relationship(back_populates="sessions")
    events: Mapped[list[SecurityEvent]] = relationship(back_populates="session")

    __table_args__ = (Index("ix_sessions_status_lab", "status", "is_lab"),)


class RequestLog(Base):
    """Stage-1 telemetry: one row per protected request."""

    __tablename__ = "request_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    session_id: Mapped[int] = mapped_column(ForeignKey("sessions.id", ondelete="CASCADE"))
    ts: Mapped[float] = mapped_column(Float)  # epoch seconds (virtual clock for harness traffic)
    method: Mapped[str] = mapped_column(String(8))
    path: Mapped[str] = mapped_column(String(255))
    category: Mapped[str] = mapped_column(String(16))
    status_code: Mapped[int] = mapped_column(Integer, default=200)
    ua_hash: Mapped[str] = mapped_column(String(16))
    device: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    network: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    synthetic: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    features: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    conventional_decision: Mapped[str] = mapped_column(String(16), default="accept")
    sessionguard_decision: Mapped[str] = mapped_column(String(24), default="allow")
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    processing_ms: Mapped[float] = mapped_column(Float, default=0.0)
    client_label: Mapped[str | None] = mapped_column(String(32), nullable=True)  # harness client name

    __table_args__ = (Index("ix_request_logs_session_ts", "session_id", "ts"),)


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    event_uid: Mapped[str] = mapped_column(String(20), unique=True, index=True)
    session_id: Mapped[int | None] = mapped_column(ForeignKey("sessions.id", ondelete="SET NULL"), index=True, nullable=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), index=True, nullable=True)
    event_type: Mapped[str] = mapped_column(String(48), index=True)
    category: Mapped[str] = mapped_column(String(32), default="session")
    severity: Mapped[str] = mapped_column(String(16), default="info")  # info|low|medium|high|critical
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    explanation: Mapped[str] = mapped_column(Text, default="")
    detection_method: Mapped[str] = mapped_column(String(48), default="none")
    action_taken: Mapped[str] = mapped_column(String(48), default="none")
    risk_before: Mapped[float] = mapped_column(Float, default=0.0)
    risk_after: Mapped[float] = mapped_column(Float, default=0.0)
    synthetic: Mapped[bool] = mapped_column(Boolean, default=False)
    is_lab: Mapped[bool] = mapped_column(Boolean, default=False)
    simulation_run_id: Mapped[int | None] = mapped_column(ForeignKey("simulation_runs.id", ondelete="SET NULL"), nullable=True, index=True)
    event_metadata: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict)

    session: Mapped[UserSession | None] = relationship(back_populates="events")


class RiskAssessment(Base):
    __tablename__ = "risk_assessments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    session_id: Mapped[int] = mapped_column(ForeignKey("sessions.id", ondelete="CASCADE"), index=True)
    request_log_id: Mapped[int | None] = mapped_column(ForeignKey("request_logs.id", ondelete="SET NULL"), nullable=True)
    model_version: Mapped[str] = mapped_column(String(48))
    anomaly_probability: Mapped[float | None] = mapped_column(Float, nullable=True)
    instant_risk: Mapped[float] = mapped_column(Float, default=0.0)
    final_risk_score: Mapped[float] = mapped_column(Float)
    feature_contributions: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    signals: Mapped[list[Any]] = mapped_column(JSON, default=list)
    decision: Mapped[str] = mapped_column(String(24))
    band: Mapped[str] = mapped_column(String(16))
    inference_ms: Mapped[float] = mapped_column(Float, default=0.0)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)


class AuthAttempt(Base):
    __tablename__ = "auth_attempts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), index=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    success: Mapped[bool] = mapped_column(Boolean)
    ip: Mapped[str] = mapped_column(String(64))
    ts: Mapped[float] = mapped_column(Float, index=True)
    kind: Mapped[str] = mapped_column(String(16), default="login")  # login | step_up
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)


class SimulationRun(Base):
    __tablename__ = "simulation_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scenario_name: Mapped[str] = mapped_column(String(48), index=True)
    protection_mode: Mapped[str] = mapped_column(String(16), default="sessionguard")
    experiment_id: Mapped[str | None] = mapped_column(String(24), nullable=True, index=True)
    started_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="running")  # running|completed|failed|reset
    outcome: Mapped[str | None] = mapped_column(String(64), nullable=True)
    detection_latency: Mapped[float | None] = mapped_column(Float, nullable=True)  # simulated seconds
    containment_latency: Mapped[float | None] = mapped_column(Float, nullable=True)  # simulated seconds
    detection_latency_ms: Mapped[float | None] = mapped_column(Float, nullable=True)  # wall-clock pipeline time
    summary: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    steps: Mapped[list[SimulationStep]] = relationship(back_populates="run", cascade="all, delete-orphan", order_by="SimulationStep.index")


class SimulationStep(Base):
    __tablename__ = "simulation_steps"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("simulation_runs.id", ondelete="CASCADE"), index=True)
    index: Mapped[int] = mapped_column(Integer)
    title: Mapped[str] = mapped_column(String(128))
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    run: Mapped[SimulationRun] = relationship(back_populates="steps")


class ModelEvaluation(Base):
    __tablename__ = "model_evaluations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    model_name: Mapped[str] = mapped_column(String(48), index=True)
    dataset_version: Mapped[str] = mapped_column(String(48))
    split: Mapped[str] = mapped_column(String(32), default="test")
    accuracy: Mapped[float] = mapped_column(Float)
    precision: Mapped[float] = mapped_column(Float)
    recall: Mapped[float] = mapped_column(Float)
    f1: Mapped[float] = mapped_column(Float)
    roc_auc: Mapped[float | None] = mapped_column(Float, nullable=True)
    false_positive_rate: Mapped[float] = mapped_column(Float)
    inference_ms_median: Mapped[float | None] = mapped_column(Float, nullable=True)
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    evaluation_timestamp: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class PolicyConfig(Base):
    __tablename__ = "policy_configs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(32), unique=True, default="active")
    config: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)
    updated_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
