import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, Boolean, Integer, Text, Float
from sqlalchemy.sql import func
from backend.database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    username = Column(String(50), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    display_name = Column(String(100), nullable=True)
    subscription_tier = Column(String(20), default="free")
    preferred_protocol = Column(String(30), default="WireGuard")
    kill_switch_default = Column(Boolean, default=True)
    auto_connect = Column(Boolean, default=False)
    fingerprint_shield_default = Column(Boolean, default=False)
    favorite_servers = Column(Text, default="[]")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    last_login = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True)
    total_data_transferred_bytes = Column(Integer, default=0)
    total_sessions = Column(Integer, default=0)


class ServerLog(Base):
    __tablename__ = "server_logs"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    event_type = Column(String(50), nullable=False, index=True)
    server_id = Column(String(50), nullable=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    duration_seconds = Column(Integer, nullable=True)
    bytes_transferred = Column(Integer, nullable=True)
    protocol = Column(String(30), nullable=True)
    anonymized_region = Column(String(10), nullable=True)
    purge_after = Column(DateTime, nullable=False)
    is_purged = Column(Boolean, default=False)
    no_logs_compliant = Column(Boolean, default=True)
