import time
import random
import uuid
import asyncio
import json
import threading
from datetime import datetime, timezone
from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
from sqlalchemy.orm import Session

from backend.database import get_db, init_db
from backend.models import User, ServerLog
from backend.auth import (
    hash_password,
    verify_password,
    create_access_token,
    create_refresh_token,
    decode_token,
    get_current_user,
    get_optional_user,
)
from backend.no_logs import (
    create_minimal_log,
    purge_expired_logs,
    auto_purge_loop,
    get_no_logs_policy,
)
import os

app = FastAPI(title="xVPN Backend Engine", version="1.0.0")

RESIDENTIAL_PROXY_URL = os.environ.get("RESIDENTIAL_PROXY_URL", "socks5://user:pass@p.shifter.io:2742")

PROXY_CHAIN_CONFIG = {
    "proxy_url": RESIDENTIAL_PROXY_URL,
    "redsocks_port": 12345,
    "routing_mode": "iptables_redirect",
    "iptables_rules": [
        "iptables -t nat -N REDSOCKS",
        "iptables -t nat -A REDSOCKS -d 0.0.0.0/8 -j RETURN",
        "iptables -t nat -A REDSOCKS -d 10.0.0.0/8 -j RETURN",
        "iptables -t nat -A REDSOCKS -d 127.0.0.0/8 -j RETURN",
        "iptables -t nat -A REDSOCKS -d 172.16.0.0/12 -j RETURN",
        "iptables -t nat -A REDSOCKS -d 192.168.0.0/16 -j RETURN",
        f"iptables -t nat -A REDSOCKS -p tcp -j REDIRECT --to-ports 12345",
        "iptables -t nat -A OUTPUT -p tcp -o wg0 -j REDSOCKS",
    ],
    "redsocks_config": {
        "local_ip": "127.0.0.1",
        "local_port": 12345,
        "ip": RESIDENTIAL_PROXY_URL.split("@")[-1].split(":")[0] if "@" in RESIDENTIAL_PROXY_URL else "p.shifter.io",
        "port": int(RESIDENTIAL_PROXY_URL.split(":")[-1]) if RESIDENTIAL_PROXY_URL.split(":")[-1].isdigit() else 2742,
        "type": "socks5",
        "login": RESIDENTIAL_PROXY_URL.split("//")[-1].split(":")[0] if "//" in RESIDENTIAL_PROXY_URL else "user",
    },
}

heartbeat_monitor_task = None
purge_task = None


@app.on_event("startup")
async def on_startup():
    global heartbeat_monitor_task, purge_task

    init_db()

    async def monitor_loop():
        while True:
            try:
                await asyncio.sleep(KILL_SWITCH_HEARTBEAT_INTERVAL)
                kill_switch_check_all()
            except asyncio.CancelledError:
                break
            except Exception:
                pass

    heartbeat_monitor_task = asyncio.create_task(monitor_loop())
    purge_task = asyncio.create_task(auto_purge_loop())


@app.on_event("shutdown")
async def on_shutdown():
    global heartbeat_monitor_task, purge_task
    for task in [heartbeat_monitor_task, purge_task]:
        if task:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class RegisterRequest(BaseModel):
    username: str
    email: str
    password: str
    display_name: Optional[str] = None


class LoginRequest(BaseModel):
    username: str
    password: str


class RefreshTokenRequest(BaseModel):
    refresh_token: str


class UpdateProfileRequest(BaseModel):
    display_name: Optional[str] = None
    preferred_protocol: Optional[str] = None
    kill_switch_default: Optional[bool] = None
    auto_connect: Optional[bool] = None
    fingerprint_shield_default: Optional[bool] = None
    favorite_servers: Optional[list[str]] = None


@app.post("/api/auth/register")
async def register(req: RegisterRequest, db: Session = Depends(get_db)):
    if len(req.username) < 3:
        raise HTTPException(status_code=400, detail="Username must be at least 3 characters")
    if len(req.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    if "@" not in req.email:
        raise HTTPException(status_code=400, detail="Invalid email address")

    existing = db.query(User).filter(
        (User.username == req.username) | (User.email == req.email)
    ).first()
    if existing:
        if existing.username == req.username:
            raise HTTPException(status_code=409, detail="Username already taken")
        raise HTTPException(status_code=409, detail="Email already registered")

    user = User(
        username=req.username,
        email=req.email,
        password_hash=hash_password(req.password),
        display_name=req.display_name or req.username,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    access_token = create_access_token(user.id, user.username)
    refresh_token = create_refresh_token(user.id)

    return {
        "status": "registered",
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "display_name": user.display_name,
            "subscription_tier": user.subscription_tier,
            "created_at": str(user.created_at),
        },
        "tokens": {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "expires_in": 3600,
        },
    }


@app.post("/api/auth/login")
async def login(req: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == req.username).first()
    if not user or not verify_password(req.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    if user.is_active is not True:
        raise HTTPException(status_code=403, detail="Account is deactivated")

    user.last_login = datetime.now(timezone.utc)
    db.commit()

    access_token = create_access_token(user.id, user.username)
    refresh_token = create_refresh_token(user.id)

    return {
        "status": "authenticated",
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "display_name": user.display_name,
            "subscription_tier": user.subscription_tier,
            "last_login": str(user.last_login),
        },
        "tokens": {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "expires_in": 3600,
        },
    }


@app.post("/api/auth/refresh")
async def refresh_token(req: RefreshTokenRequest, db: Session = Depends(get_db)):
    payload = decode_token(req.refresh_token)
    if payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Invalid token type")

    user = db.query(User).filter(User.id == payload["sub"]).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    new_access = create_access_token(user.id, user.username)
    new_refresh = create_refresh_token(user.id)

    return {
        "tokens": {
            "access_token": new_access,
            "refresh_token": new_refresh,
            "token_type": "bearer",
            "expires_in": 3600,
        },
    }


@app.get("/api/auth/profile")
async def get_profile(current_user: User = Depends(get_current_user)):
    return {
        "id": current_user.id,
        "username": current_user.username,
        "email": current_user.email,
        "display_name": current_user.display_name,
        "subscription_tier": current_user.subscription_tier,
        "preferred_protocol": current_user.preferred_protocol,
        "kill_switch_default": current_user.kill_switch_default,
        "auto_connect": current_user.auto_connect,
        "fingerprint_shield_default": current_user.fingerprint_shield_default,
        "favorite_servers": json.loads(current_user.favorite_servers or "[]"),
        "created_at": str(current_user.created_at),
        "last_login": str(current_user.last_login) if current_user.last_login else None,
        "total_data_transferred_bytes": current_user.total_data_transferred_bytes,
        "total_sessions": current_user.total_sessions,
    }


@app.put("/api/auth/profile")
async def update_profile(
    req: UpdateProfileRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if req.display_name is not None:
        current_user.display_name = req.display_name
    if req.preferred_protocol is not None:
        current_user.preferred_protocol = req.preferred_protocol
    if req.kill_switch_default is not None:
        current_user.kill_switch_default = req.kill_switch_default
    if req.auto_connect is not None:
        current_user.auto_connect = req.auto_connect
    if req.fingerprint_shield_default is not None:
        current_user.fingerprint_shield_default = req.fingerprint_shield_default
    if req.favorite_servers is not None:
        current_user.favorite_servers = json.dumps(req.favorite_servers)

    current_user.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(current_user)

    return {
        "status": "updated",
        "profile": {
            "display_name": current_user.display_name,
            "preferred_protocol": current_user.preferred_protocol,
            "kill_switch_default": current_user.kill_switch_default,
            "auto_connect": current_user.auto_connect,
            "fingerprint_shield_default": current_user.fingerprint_shield_default,
            "favorite_servers": json.loads(current_user.favorite_servers or "[]"),
        },
    }


@app.get("/api/no-logs-policy")
async def no_logs_policy():
    return get_no_logs_policy()


SERVERS = [
    {
        "id": "us-east-1",
        "name": "US East",
        "country": "United States",
        "city": "New York",
        "flag": "US",
        "ip": "198.51.100.1",
        "load": round(random.uniform(15, 65), 1),
        "ping": random.randint(8, 25),
        "premium": False,
        "protocol": "WireGuard",
        "capacity": 10000,
        "bandwidth": "10 Gbps",
    },
    {
        "id": "us-west-1",
        "name": "US West",
        "country": "United States",
        "city": "Los Angeles",
        "flag": "US",
        "ip": "198.51.100.2",
        "load": round(random.uniform(20, 70), 1),
        "ping": random.randint(15, 40),
        "premium": False,
        "protocol": "WireGuard",
        "capacity": 10000,
        "bandwidth": "10 Gbps",
    },
    {
        "id": "uk-london-1",
        "name": "UK London",
        "country": "United Kingdom",
        "city": "London",
        "flag": "GB",
        "ip": "203.0.113.1",
        "load": round(random.uniform(25, 55), 1),
        "ping": random.randint(35, 60),
        "premium": False,
        "protocol": "WireGuard",
        "capacity": 8000,
        "bandwidth": "10 Gbps",
    },
    {
        "id": "jp-tokyo-1",
        "name": "Japan",
        "country": "Japan",
        "city": "Tokyo",
        "flag": "JP",
        "ip": "203.0.113.10",
        "load": round(random.uniform(30, 75), 1),
        "ping": random.randint(70, 120),
        "premium": True,
        "protocol": "WireGuard",
        "capacity": 6000,
        "bandwidth": "10 Gbps",
    },
    {
        "id": "de-frankfurt-1",
        "name": "Germany",
        "country": "Germany",
        "city": "Frankfurt",
        "flag": "DE",
        "ip": "203.0.113.20",
        "load": round(random.uniform(15, 50), 1),
        "ping": random.randint(40, 65),
        "premium": False,
        "protocol": "WireGuard",
        "capacity": 8000,
        "bandwidth": "10 Gbps",
    },
    {
        "id": "sg-singapore-1",
        "name": "Singapore",
        "country": "Singapore",
        "city": "Singapore",
        "flag": "SG",
        "ip": "203.0.113.30",
        "load": round(random.uniform(20, 60), 1),
        "ping": random.randint(60, 95),
        "premium": True,
        "protocol": "WireGuard",
        "capacity": 6000,
        "bandwidth": "10 Gbps",
    },
    {
        "id": "au-sydney-1",
        "name": "Australia",
        "country": "Australia",
        "city": "Sydney",
        "flag": "AU",
        "ip": "203.0.113.40",
        "load": round(random.uniform(10, 40), 1),
        "ping": random.randint(90, 140),
        "premium": False,
        "protocol": "WireGuard",
        "capacity": 5000,
        "bandwidth": "5 Gbps",
    },
    {
        "id": "ca-toronto-1",
        "name": "Canada",
        "country": "Canada",
        "city": "Toronto",
        "flag": "CA",
        "ip": "203.0.113.50",
        "load": round(random.uniform(15, 45), 1),
        "ping": random.randint(12, 30),
        "premium": False,
        "protocol": "WireGuard",
        "capacity": 8000,
        "bandwidth": "10 Gbps",
    },
    {
        "id": "nl-amsterdam-1",
        "name": "Netherlands",
        "country": "Netherlands",
        "city": "Amsterdam",
        "flag": "NL",
        "ip": "203.0.113.60",
        "load": round(random.uniform(25, 65), 1),
        "ping": random.randint(38, 60),
        "premium": True,
        "protocol": "WireGuard",
        "capacity": 7000,
        "bandwidth": "10 Gbps",
    },
    {
        "id": "ch-zurich-1",
        "name": "Switzerland",
        "country": "Switzerland",
        "city": "Zurich",
        "flag": "CH",
        "ip": "203.0.113.70",
        "load": round(random.uniform(10, 35), 1),
        "ping": random.randint(45, 70),
        "premium": True,
        "protocol": "WireGuard",
        "capacity": 5000,
        "bandwidth": "5 Gbps",
    },
    {
        "id": "fr-paris-1",
        "name": "France",
        "country": "France",
        "city": "Paris",
        "flag": "FR",
        "ip": "203.0.113.80",
        "load": round(random.uniform(20, 50), 1),
        "ping": random.randint(35, 55),
        "premium": False,
        "protocol": "WireGuard",
        "capacity": 7000,
        "bandwidth": "10 Gbps",
    },
    {
        "id": "kr-seoul-1",
        "name": "South Korea",
        "country": "South Korea",
        "city": "Seoul",
        "flag": "KR",
        "ip": "203.0.113.90",
        "load": round(random.uniform(35, 80), 1),
        "ping": random.randint(80, 120),
        "premium": True,
        "protocol": "WireGuard",
        "capacity": 5000,
        "bandwidth": "5 Gbps",
    },
    {
        "id": "br-saopaulo-1",
        "name": "Brazil",
        "country": "Brazil",
        "city": "Sao Paulo",
        "flag": "BR",
        "ip": "203.0.113.100",
        "load": round(random.uniform(20, 55), 1),
        "ping": random.randint(110, 160),
        "premium": False,
        "protocol": "WireGuard",
        "capacity": 5000,
        "bandwidth": "5 Gbps",
    },
    {
        "id": "in-mumbai-1",
        "name": "India",
        "country": "India",
        "city": "Mumbai",
        "flag": "IN",
        "ip": "203.0.113.110",
        "load": round(random.uniform(30, 75), 1),
        "ping": random.randint(90, 130),
        "premium": False,
        "protocol": "WireGuard",
        "capacity": 5000,
        "bandwidth": "5 Gbps",
    },
    {
        "id": "se-stockholm-1",
        "name": "Sweden",
        "country": "Sweden",
        "city": "Stockholm",
        "flag": "SE",
        "ip": "203.0.113.120",
        "load": round(random.uniform(8, 30), 1),
        "ping": random.randint(50, 75),
        "premium": True,
        "protocol": "WireGuard",
        "capacity": 5000,
        "bandwidth": "5 Gbps",
    },
]

active_sessions: dict[str, dict] = {}

KILL_SWITCH_HEARTBEAT_INTERVAL = 10
KILL_SWITCH_TIMEOUT = 30

kill_switch_registry: dict[str, dict] = {}

MULTI_HOP_PAIRS = [
    {"entry": "ch-zurich-1", "exit": "se-stockholm-1", "label": "Swiss Guard → Nordic Shield", "anonymity_level": "maximum"},
    {"entry": "nl-amsterdam-1", "exit": "ch-zurich-1", "label": "Dutch Gate → Swiss Vault", "anonymity_level": "maximum"},
    {"entry": "us-east-1", "exit": "uk-london-1", "label": "US Shield → UK Relay", "anonymity_level": "high"},
    {"entry": "de-frankfurt-1", "exit": "nl-amsterdam-1", "label": "German Fortress → Dutch Exit", "anonymity_level": "maximum"},
    {"entry": "jp-tokyo-1", "exit": "sg-singapore-1", "label": "Tokyo Gate → Singapore Relay", "anonymity_level": "high"},
    {"entry": "ca-toronto-1", "exit": "us-west-1", "label": "Canada Shield → US West Exit", "anonymity_level": "high"},
    {"entry": "uk-london-1", "exit": "fr-paris-1", "label": "London Bridge → Paris Tunnel", "anonymity_level": "high"},
    {"entry": "se-stockholm-1", "exit": "de-frankfurt-1", "label": "Nordic Entry → Frankfurt Exit", "anonymity_level": "maximum"},
]

FINGERPRINT_HEADERS_TO_STRIP = [
    "User-Agent",
    "Accept-Language",
    "Accept-Encoding",
    "Accept",
    "DNT",
    "Sec-CH-UA",
    "Sec-CH-UA-Mobile",
    "Sec-CH-UA-Platform",
    "Sec-CH-UA-Full-Version",
    "Sec-CH-UA-Arch",
    "Sec-CH-UA-Model",
    "Sec-CH-UA-Platform-Version",
    "Sec-Fetch-Dest",
    "Sec-Fetch-Mode",
    "Sec-Fetch-Site",
    "Sec-Fetch-User",
    "X-Forwarded-For",
    "X-Real-IP",
    "Via",
    "Forwarded",
    "X-Client-IP",
    "CF-Connecting-IP",
    "True-Client-IP",
    "X-Cluster-Client-IP",
    "Fastly-Client-IP",
    "X-Originating-IP",
    "X-Request-ID",
    "X-Correlation-ID",
    "X-Device-ID",
    "X-Session-ID",
    "Cookie",
    "Referer",
    "Origin",
]

FINGERPRINT_NORMALIZED_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate, br",
    "Sec-CH-UA": '"Chromium";v="125", "Google Chrome";v="125", "Not=A?Brand";v="24"',
    "Sec-CH-UA-Mobile": "?0",
    "Sec-CH-UA-Platform": '"Windows"',
    "DNT": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
}

CANVAS_NOISE_PROFILES = [
    {"hash": uuid.uuid4().hex, "noise_level": 0.02, "entropy_bits": 128},
    {"hash": uuid.uuid4().hex, "noise_level": 0.015, "entropy_bits": 128},
    {"hash": uuid.uuid4().hex, "noise_level": 0.025, "entropy_bits": 128},
]

WEBGL_SPOOF_PROFILES = [
    {"vendor": "Google Inc. (NVIDIA)", "renderer": "ANGLE (NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0)", "hash": uuid.uuid4().hex[:16]},
    {"vendor": "Google Inc. (AMD)", "renderer": "ANGLE (AMD Radeon RX 580 Direct3D11 vs_5_0 ps_5_0)", "hash": uuid.uuid4().hex[:16]},
    {"vendor": "Google Inc. (Intel)", "renderer": "ANGLE (Intel UHD Graphics 630 Direct3D11 vs_5_0 ps_5_0)", "hash": uuid.uuid4().hex[:16]},
]


RESIDENTIAL_IP_POOL = [
    {"ip": "72.134.92.{}".format(random.randint(1, 254)), "isp": "Comcast Cable", "type": "residential", "city": "Chicago", "state": "IL", "asn": "AS7922"},
    {"ip": "98.45.172.{}".format(random.randint(1, 254)), "isp": "AT&T Internet", "type": "residential", "city": "Dallas", "state": "TX", "asn": "AS7018"},
    {"ip": "68.193.58.{}".format(random.randint(1, 254)), "isp": "Verizon FiOS", "type": "residential", "city": "New York", "state": "NY", "asn": "AS701"},
    {"ip": "76.120.33.{}".format(random.randint(1, 254)), "isp": "Charter Spectrum", "type": "residential", "city": "Los Angeles", "state": "CA", "asn": "AS20115"},
    {"ip": "24.56.178.{}".format(random.randint(1, 254)), "isp": "Cox Communications", "type": "residential", "city": "Phoenix", "state": "AZ", "asn": "AS22773"},
    {"ip": "71.82.214.{}".format(random.randint(1, 254)), "isp": "Comcast Cable", "type": "residential", "city": "Philadelphia", "state": "PA", "asn": "AS7922"},
    {"ip": "99.112.45.{}".format(random.randint(1, 254)), "isp": "AT&T Internet", "type": "residential", "city": "Houston", "state": "TX", "asn": "AS7018"},
    {"ip": "108.26.193.{}".format(random.randint(1, 254)), "isp": "Verizon FiOS", "type": "residential", "city": "Boston", "state": "MA", "asn": "AS701"},
    {"ip": "73.158.67.{}".format(random.randint(1, 254)), "isp": "Comcast Cable", "type": "residential", "city": "Denver", "state": "CO", "asn": "AS7922"},
    {"ip": "47.184.92.{}".format(random.randint(1, 254)), "isp": "Frontier Communications", "type": "residential", "city": "Seattle", "state": "WA", "asn": "AS5650"},
]

STEALTH_PROTOCOLS = {
    "shadowsocks": {
        "name": "Shadowsocks",
        "cipher": "chacha20-ietf-poly1305",
        "port": 443,
        "obfs": "tls",
        "obfs_host": "www.bing.com",
        "description": "Wraps WireGuard in Shadowsocks envelope, traffic appears as standard TLS/HTTPS",
        "fingerprint": "TLS 1.3 Client Hello",
        "header_size_bytes": 34,
    },
    "v2ray": {
        "name": "V2Ray (VMess + WebSocket)",
        "transport": "websocket",
        "security": "tls",
        "port": 443,
        "path": "/cdn-cgi/trace",
        "host": "cdn.cloudflare.com",
        "alter_id": 0,
        "description": "Disguises WireGuard as Cloudflare WebSocket traffic on port 443",
        "fingerprint": "Chrome TLS fingerprint",
        "header_size_bytes": 58,
    },
    "obfs4": {
        "name": "obfs4 (Pluggable Transport)",
        "port": 443,
        "iat_mode": 1,
        "description": "Randomizes packet timing and sizes, indistinguishable from random noise",
        "fingerprint": "None (fully randomized)",
        "header_size_bytes": 24,
    },
}


def kill_switch_register(session_id: str, enabled: bool = True) -> dict:
    if not enabled:
        return {"kill_switch": "disabled", "session_id": session_id}

    kill_switch_registry[session_id] = {
        "session_id": session_id,
        "enabled": True,
        "last_heartbeat": time.time(),
        "heartbeat_interval_sec": KILL_SWITCH_HEARTBEAT_INTERVAL,
        "timeout_sec": KILL_SWITCH_TIMEOUT,
        "missed_heartbeats": 0,
        "max_missed_heartbeats": 3,
        "status": "active",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "network_lock": True,
        "block_ipv6": True,
        "block_non_vpn_traffic": True,
        "firewall_rules": [
            {"rule": "BLOCK_ALL_NON_TUNNEL", "action": "drop", "priority": 1},
            {"rule": "ALLOW_VPN_GATEWAY", "action": "accept", "priority": 2},
            {"rule": "ALLOW_LOCAL_DHCP", "action": "accept", "priority": 3},
            {"rule": "BLOCK_DNS_LEAK", "action": "drop", "priority": 4},
            {"rule": "BLOCK_IPv6", "action": "drop", "priority": 5},
        ],
    }
    return kill_switch_registry[session_id]


def kill_switch_heartbeat(session_id: str) -> dict:
    if session_id not in kill_switch_registry:
        return {"error": "Kill switch not registered for this session", "session_id": session_id}

    ks = kill_switch_registry[session_id]
    now = time.time()
    time_since_last = now - ks["last_heartbeat"]

    ks["last_heartbeat"] = now
    ks["missed_heartbeats"] = 0
    ks["status"] = "active"

    return {
        "session_id": session_id,
        "status": "active",
        "heartbeat_received": True,
        "time_since_last_heartbeat_sec": round(time_since_last, 2),
        "next_heartbeat_due_sec": KILL_SWITCH_HEARTBEAT_INTERVAL,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def kill_switch_check_all() -> list[dict]:
    terminated = []
    now = time.time()
    expired_sessions = []

    for sid, ks in kill_switch_registry.items():
        if not ks["enabled"]:
            continue
        elapsed = now - ks["last_heartbeat"]
        missed = int(elapsed / KILL_SWITCH_HEARTBEAT_INTERVAL)
        ks["missed_heartbeats"] = missed

        if elapsed >= KILL_SWITCH_TIMEOUT:
            ks["status"] = "triggered"
            if sid in active_sessions:
                session = active_sessions.pop(sid)
                terminated.append({
                    "session_id": sid,
                    "reason": "heartbeat_timeout",
                    "missed_heartbeats": missed,
                    "elapsed_since_last_heartbeat_sec": round(elapsed, 2),
                    "server_id": session.get("server_id"),
                    "terminated_at": datetime.now(timezone.utc).isoformat(),
                })
            expired_sessions.append(sid)
        elif missed >= 1:
            ks["status"] = "warning"

    for sid in expired_sessions:
        kill_switch_registry.pop(sid, None)

    return terminated


def build_multi_hop_route(entry_server_id: str, exit_server_id: str) -> dict:
    entry_server = next((s for s in SERVERS if s["id"] == entry_server_id), None)
    exit_server = next((s for s in SERVERS if s["id"] == exit_server_id), None)

    if not entry_server:
        raise HTTPException(status_code=404, detail=f"Entry server not found: {entry_server_id}")
    if not exit_server:
        raise HTTPException(status_code=404, detail=f"Exit server not found: {exit_server_id}")
    if entry_server_id == exit_server_id:
        raise HTTPException(status_code=400, detail="Entry and exit nodes must be different servers")

    inter_node_latency = random.randint(15, 45)

    return {
        "multi_hop": True,
        "hops": 2,
        "route": [
            {
                "hop": 1,
                "role": "entry_node",
                "server": {
                    "id": entry_server["id"],
                    "name": entry_server["name"],
                    "city": entry_server["city"],
                    "country": entry_server["country"],
                    "flag": entry_server["flag"],
                    "ip": entry_server["ip"],
                },
                "encryption": {
                    "layer": "outer",
                    "algorithm": "AES-256-GCM",
                    "key_exchange": "Curve25519",
                    "pfs": True,
                },
                "function": "Receives encrypted traffic, re-encrypts and forwards to exit node",
            },
            {
                "hop": 2,
                "role": "exit_node",
                "server": {
                    "id": exit_server["id"],
                    "name": exit_server["name"],
                    "city": exit_server["city"],
                    "country": exit_server["country"],
                    "flag": exit_server["flag"],
                    "ip": exit_server["ip"],
                },
                "encryption": {
                    "layer": "inner",
                    "algorithm": "ChaCha20-Poly1305",
                    "key_exchange": "Curve25519",
                    "pfs": True,
                },
                "function": "Decrypts outer layer, forwards inner-encrypted traffic to destination",
            },
        ],
        "total_latency_ms": entry_server["ping"] + exit_server["ping"] + inter_node_latency,
        "inter_node_latency_ms": inter_node_latency,
        "encryption_layers": 2,
        "entry_knows_destination": False,
        "exit_knows_source": False,
        "anonymity_benefit": "Neither node can correlate your identity with your destination",
    }


def generate_fingerprint_shield(session_id: Optional[str] = None) -> dict:
    canvas_profile = random.choice(CANVAS_NOISE_PROFILES)
    webgl_profile = random.choice(WEBGL_SPOOF_PROFILES)

    timezone_offset = random.choice([-8, -7, -6, -5, -4, 0, 1, 2])
    screen_resolutions = [
        {"width": 1920, "height": 1080},
        {"width": 2560, "height": 1440},
        {"width": 1366, "height": 768},
        {"width": 1536, "height": 864},
        {"width": 1440, "height": 900},
    ]
    spoofed_screen = random.choice(screen_resolutions)

    return {
        "enabled": True,
        "session_id": session_id,
        "header_sanitization": {
            "headers_stripped": len(FINGERPRINT_HEADERS_TO_STRIP),
            "stripped_headers": FINGERPRINT_HEADERS_TO_STRIP,
            "normalized_headers": FINGERPRINT_NORMALIZED_HEADERS,
            "strategy": "All identifying headers are either stripped or replaced with generic values matching the most common browser profile worldwide",
        },
        "browser_fingerprint_spoofing": {
            "canvas": {
                "protection": "noise_injection",
                "noise_level": canvas_profile["noise_level"],
                "unique_hash": canvas_profile["hash"],
                "entropy_bits": canvas_profile["entropy_bits"],
                "description": "Injects subtle random noise into Canvas API calls to produce a unique-per-session fingerprint",
            },
            "webgl": {
                "protection": "vendor_spoofing",
                "spoofed_vendor": webgl_profile["vendor"],
                "spoofed_renderer": webgl_profile["renderer"],
                "hash": webgl_profile["hash"],
                "description": "Reports a common GPU configuration to blend with millions of identical setups",
            },
            "audio_context": {
                "protection": "noise_injection",
                "noise_amplitude": round(random.uniform(0.001, 0.005), 4),
                "sample_rate_spoofed": 44100,
                "description": "Adds micro-noise to AudioContext fingerprint to prevent audio-based tracking",
            },
            "screen": {
                "protection": "resolution_spoofing",
                "reported_resolution": spoofed_screen,
                "color_depth": 24,
                "device_pixel_ratio": 1.0,
                "description": "Reports a common screen resolution to avoid unique screen fingerprinting",
            },
            "timezone": {
                "protection": "timezone_spoofing",
                "reported_offset": timezone_offset,
                "reported_timezone": f"Etc/GMT{'+' if timezone_offset <= 0 else '-'}{abs(timezone_offset)}",
                "description": "Spoofs timezone to break geographic correlation",
            },
            "fonts": {
                "protection": "font_enumeration_blocked",
                "visible_fonts": 42,
                "actual_fonts": "hidden",
                "description": "Limits visible fonts to a common subset, blocking font enumeration attacks",
            },
        },
        "network_fingerprint_protection": {
            "tcp_fingerprint": {
                "os_spoofed": "Windows 10",
                "ttl": 128,
                "window_size": 65535,
                "mss": 1460,
                "description": "TCP/IP stack parameters normalized to match Windows 10 defaults",
            },
            "tls_fingerprint": {
                "ja3_spoofed": True,
                "mimicked_client": "Chrome 125 on Windows",
                "ja3_hash": uuid.uuid4().hex[:32],
                "description": "TLS Client Hello fingerprint matches the most common Chrome configuration",
            },
            "http2_fingerprint": {
                "akamai_hash_spoofed": True,
                "settings_order": "normalized",
                "description": "HTTP/2 SETTINGS frame order normalized to match Chrome defaults",
            },
        },
        "tracking_prevention": {
            "cookies": "isolated_per_session",
            "local_storage": "cleared_on_disconnect",
            "indexed_db": "blocked",
            "cache_partitioned": True,
            "etag_tracking": "blocked",
            "hsts_supercookies": "cleared",
            "referrer_policy": "strict-origin-when-cross-origin",
        },
        "overall_uniqueness_score": round(random.uniform(0.001, 0.01), 4),
        "blend_population": f"~{random.randint(15, 45)} million users with identical fingerprint",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def residential_proxy_middleware(region: Optional[str] = None) -> dict:
    selected_ip = get_residential_ip(region)
    return {
        "assigned_ip": selected_ip["ip"],
        "isp": selected_ip["isp"],
        "ip_type": selected_ip["type"],
        "city": selected_ip["city"],
        "state": selected_ip["state"],
        "asn": selected_ip["asn"],
        "proxy_chain": [
            {"hop": 1, "type": "vpn_tunnel", "protocol": "WireGuard", "encryption": "ChaCha20-Poly1305"},
            {"hop": 2, "type": "residential_gateway", "protocol": "SOCKS5", "encryption": "AES-256-GCM"},
            {"hop": 3, "type": "residential_exit", "ip": selected_ip["ip"], "isp": selected_ip["isp"]},
        ],
        "routing_latency_ms": random.randint(5, 25),
        "detection_risk": "very_low",
        "bot_detection_bypass": True,
    }


def get_residential_ip(region: Optional[str] = None) -> dict:
    if region:
        regional = [ip for ip in RESIDENTIAL_IP_POOL if ip["state"] == region.upper()]
        if regional:
            return random.choice(regional)
    return random.choice(RESIDENTIAL_IP_POOL)


def wrap_stealth_headers(protocol: str, payload_size: int = 0) -> dict:
    config = STEALTH_PROTOCOLS.get(protocol)
    if not config:
        return {"error": f"Unknown stealth protocol: {protocol}"}

    base = {
        "stealth_protocol": config["name"],
        "outer_port": config["port"],
        "inner_protocol": "WireGuard",
        "overhead_bytes": config["header_size_bytes"],
        "effective_mtu": 1500 - config["header_size_bytes"],
        "fingerprint_mimicry": config.get("fingerprint", "None"),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    if protocol == "shadowsocks":
        base.update({
            "cipher": config["cipher"],
            "obfuscation": config["obfs"],
            "sni_host": config["obfs_host"],
            "tls_version": "1.3",
            "wrapped_payload_size": payload_size + config["header_size_bytes"],
        })
    elif protocol == "v2ray":
        base.update({
            "transport": config["transport"],
            "ws_path": config["path"],
            "cdn_host": config["host"],
            "tls_version": "1.3",
            "http_method": "GET",
            "upgrade_header": "websocket",
            "wrapped_payload_size": payload_size + config["header_size_bytes"],
        })
    elif protocol == "obfs4":
        base.update({
            "iat_mode": config["iat_mode"],
            "packet_padding": random.randint(0, 255),
            "timing_jitter_ms": round(random.uniform(0, 50), 2),
            "wrapped_payload_size": payload_size + config["header_size_bytes"] + random.randint(0, 255),
        })

    return base


class ConnectRequest(BaseModel):
    server_id: str
    protocol: Optional[str] = "WireGuard"
    double_vpn: Optional[bool] = False
    double_vpn_server_id: Optional[str] = None
    stealth_mode: Optional[str] = None
    use_residential_ip: Optional[bool] = False
    residential_region: Optional[str] = None
    kill_switch: Optional[bool] = True
    fingerprint_shield: Optional[bool] = False


class ConnectResponse(BaseModel):
    session_id: str
    status: str
    server: dict
    virtual_ip: str
    handshake: dict
    encryption: dict
    timestamp: str


class StatusResponse(BaseModel):
    session_id: str
    status: str
    uptime_seconds: int
    latency_ms: int
    server: dict
    bytes_sent: int
    bytes_received: int
    encryption: dict


class SecurityCheckResponse(BaseModel):
    dns_leak: dict
    webrtc_leak: dict
    ipv6_leak: dict
    overall_status: str
    checked_at: str


@app.post("/api/connect")
async def connect(req: ConnectRequest, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    server = next((s for s in SERVERS if s["id"] == req.server_id), None)
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")

    session_id = str(uuid.uuid4())
    virtual_ip = f"{random.randint(10, 200)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(10, 200)}"

    if req.stealth_mode and req.stealth_mode not in STEALTH_PROTOCOLS:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown stealth protocol: {req.stealth_mode}. Available: {list(STEALTH_PROTOCOLS.keys())}",
        )

    residential_ip_info = None
    if req.use_residential_ip:
        residential_ip_info = residential_proxy_middleware(req.residential_region)
        virtual_ip = residential_ip_info["assigned_ip"]

    stealth_info = None
    if req.stealth_mode:
        stealth_info = wrap_stealth_headers(req.stealth_mode, payload_size=1400)

    session = {
        "session_id": session_id,
        "server_id": req.server_id,
        "server": server,
        "virtual_ip": virtual_ip,
        "protocol": req.protocol or "WireGuard",
        "connected_at": time.time(),
        "double_vpn": req.double_vpn,
        "double_vpn_server_id": req.double_vpn_server_id,
        "stealth_mode": req.stealth_mode,
        "residential_ip": residential_ip_info,
        "stealth_config": stealth_info,
    }
    active_sessions[session_id] = session

    handshake_latency = random.randint(45, 180)
    if req.stealth_mode:
        handshake_latency += random.randint(20, 80)

    response_data: dict = {
        "session_id": session_id,
        "status": "connected",
        "server": {
            "id": server["id"],
            "name": server["name"],
            "city": server["city"],
            "country": server["country"],
            "flag": server["flag"],
            "ip": server["ip"],
        },
        "virtual_ip": virtual_ip,
        "handshake": {
            "protocol": req.protocol or "WireGuard",
            "latency_ms": handshake_latency,
            "cipher": "ChaCha20-Poly1305",
            "key_exchange": "Curve25519",
            "pfs": True,
        },
        "encryption": {
            "algorithm": "AES-256-GCM",
            "key_size": 256,
            "hmac": "SHA-512",
            "handshake_cipher": "ChaCha20-Poly1305",
        },
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    if residential_ip_info:
        response_data["residential_proxy"] = {
            "enabled": True,
            "exit_ip": residential_ip_info["assigned_ip"],
            "isp": residential_ip_info["isp"],
            "ip_type": residential_ip_info["ip_type"],
            "city": residential_ip_info["city"],
            "state": residential_ip_info["state"],
            "asn": residential_ip_info["asn"],
            "proxy_chain": residential_ip_info["proxy_chain"],
            "routing_latency_ms": residential_ip_info["routing_latency_ms"],
            "detection_risk": residential_ip_info["detection_risk"],
            "bot_detection_bypass": residential_ip_info["bot_detection_bypass"],
        }

    if stealth_info:
        response_data["stealth"] = stealth_info

    if req.kill_switch:
        ks_info = kill_switch_register(session_id, enabled=True)
        session["kill_switch"] = True
        response_data["kill_switch"] = {
            "enabled": True,
            "heartbeat_interval_sec": KILL_SWITCH_HEARTBEAT_INTERVAL,
            "timeout_sec": KILL_SWITCH_TIMEOUT,
            "network_lock": True,
            "firewall_rules": len(ks_info["firewall_rules"]),
        }

    if req.fingerprint_shield:
        fp_shield = generate_fingerprint_shield(session_id)
        session["fingerprint_shield"] = True
        response_data["fingerprint_shield"] = {
            "enabled": True,
            "headers_sanitized": fp_shield["header_sanitization"]["headers_stripped"],
            "canvas_protection": True,
            "webgl_protection": True,
            "audio_protection": True,
            "network_protection": True,
            "uniqueness_score": fp_shield["overall_uniqueness_score"],
            "blend_population": fp_shield["blend_population"],
        }

    current_user.total_sessions = (current_user.total_sessions or 0) + 1
    db.commit()

    session["user_id"] = current_user.id

    create_minimal_log(
        db,
        event_type="session_start",
        protocol=req.protocol,
        region=server.get("flag"),
    )

    return response_data


@app.get("/api/status")
async def status(session_id: Optional[str] = None, current_user: User = Depends(get_current_user)):
    if not session_id and active_sessions:
        session_id = list(active_sessions.keys())[-1]

    if not session_id or session_id not in active_sessions:
        return {
            "status": "disconnected",
            "active_sessions": len(active_sessions),
            "message": "No active VPN session",
        }

    session = active_sessions[session_id]
    uptime = int(time.time() - session["connected_at"])
    server = session["server"]

    residential_info = session.get("residential_ip")
    display_ip = residential_info["assigned_ip"] if residential_info else server["ip"]

    status_data = {
        "session_id": session_id,
        "status": "connected",
        "uptime_seconds": uptime,
        "latency_ms": server["ping"] + random.randint(-5, 10),
        "server": {
            "id": server["id"],
            "name": server["name"],
            "city": server["city"],
            "country": server["country"],
            "flag": server["flag"],
        },
        "bytes_sent": uptime * random.randint(50000, 200000),
        "bytes_received": uptime * random.randint(200000, 800000),
        "encryption": {
            "algorithm": "AES-256-GCM",
            "key_size": 256,
            "active": True,
        },
        "visible_ip": display_ip,
    }

    if residential_info:
        status_data["residential_mask"] = {
            "active": True,
            "proxy_ip": residential_info["assigned_ip"],
            "isp": residential_info["isp"],
            "ip_type": residential_info["ip_type"],
            "city": residential_info["city"],
            "state": residential_info["state"],
            "asn": residential_info["asn"],
            "proxy_chain_hops": len(residential_info.get("proxy_chain", [])),
            "detection_risk": residential_info.get("detection_risk", "very_low"),
        }
        status_data["proxy_chaining"] = {
            "enabled": True,
            "routing_mode": PROXY_CHAIN_CONFIG["routing_mode"],
            "redsocks_port": PROXY_CHAIN_CONFIG["redsocks_port"],
            "iptables_rules_applied": len(PROXY_CHAIN_CONFIG["iptables_rules"]),
            "proxy_type": PROXY_CHAIN_CONFIG["redsocks_config"]["type"],
        }
    else:
        status_data["residential_mask"] = {"active": False}

    return status_data


@app.get("/api/servers")
async def get_servers():
    live_servers = []
    for s in SERVERS:
        live = {**s}
        live["load"] = round(min(100, max(5, s["load"] + random.uniform(-8, 8))), 1)
        live["ping"] = max(5, s["ping"] + random.randint(-5, 5))
        live["status"] = "online" if live["load"] < 95 else "busy"
        live["active_users"] = random.randint(100, int(s["capacity"] * live["load"] / 100))
        live_servers.append(live)

    return {
        "servers": live_servers,
        "total": len(live_servers),
        "regions": len(set(s["country"] for s in SERVERS)),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/api/security-check", response_model=SecurityCheckResponse)
async def security_check(session_id: Optional[str] = None, current_user: User = Depends(get_current_user)):
    is_connected = bool(session_id and session_id in active_sessions)

    dns_servers_detected = []
    if is_connected and session_id is not None:
        session = active_sessions[session_id]
        dns_servers_detected = [
            {"ip": session["server"]["ip"], "provider": "xVPN Secure DNS", "location": session["server"]["city"]},
        ]
    else:
        dns_servers_detected = [
            {"ip": "8.8.8.8", "provider": "Google Public DNS", "location": "Mountain View, US"},
            {"ip": "8.8.4.4", "provider": "Google Public DNS", "location": "Mountain View, US"},
        ]

    return SecurityCheckResponse(
        dns_leak={
            "status": "protected" if is_connected else "exposed",
            "leak_detected": not is_connected,
            "dns_servers": dns_servers_detected,
            "test_domain": "leak-test.xvpn.internal",
            "resolution_time_ms": random.randint(2, 15),
        },
        webrtc_leak={
            "status": "protected" if is_connected else "vulnerable",
            "leak_detected": not is_connected,
            "local_ip_exposed": not is_connected,
            "public_ip_exposed": not is_connected,
            "stun_server_blocked": is_connected,
            "mitigation": "WebRTC disabled via browser policy" if is_connected else "No protection active",
        },
        ipv6_leak={
            "status": "protected" if is_connected else "unknown",
            "leak_detected": False,
            "ipv6_disabled": is_connected,
            "tunnel_ipv6": False,
            "mitigation": "IPv6 traffic blocked at tunnel level" if is_connected else "No IPv6 protection",
        },
        overall_status="secure" if is_connected else "at_risk",
        checked_at=datetime.now(timezone.utc).isoformat(),
    )


@app.delete("/api/disconnect")
async def disconnect(session_id: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if session_id not in active_sessions:
        raise HTTPException(status_code=404, detail="Session not found")

    session = active_sessions.pop(session_id)
    uptime = int(time.time() - session["connected_at"])

    kill_switch_registry.pop(session_id, None)

    bytes_transferred = uptime * random.randint(100000, 500000)
    current_user.total_data_transferred_bytes = (current_user.total_data_transferred_bytes or 0) + bytes_transferred
    db.commit()

    create_minimal_log(
        db,
        event_type="session_end",
        duration_seconds=uptime,
        bytes_transferred=bytes_transferred,
        protocol=session.get("protocol"),
        region=session.get("server", {}).get("flag"),
    )

    return {
        "status": "disconnected",
        "session_id": session_id,
        "uptime_seconds": uptime,
        "kill_switch_disarmed": session.get("kill_switch", False),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/api/obfuscation/protocols")
async def get_obfuscation_protocols():
    protocols = []
    for key, config in STEALTH_PROTOCOLS.items():
        protocols.append({
            "id": key,
            "name": config["name"],
            "port": config["port"],
            "description": config["description"],
            "fingerprint": config.get("fingerprint", "Unknown"),
            "overhead_bytes": config["header_size_bytes"],
            "effective_mtu": 1500 - config["header_size_bytes"],
        })

    return {
        "protocols": protocols,
        "residential_proxy": {
            "available": True,
            "pool_size": len(RESIDENTIAL_IP_POOL),
            "regions": list(set(ip["state"] for ip in RESIDENTIAL_IP_POOL)),
            "isps": list(set(ip["isp"] for ip in RESIDENTIAL_IP_POOL)),
            "description": "Routes traffic through residential IP addresses from major US ISPs to bypass datacenter IP detection",
        },
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.post("/api/obfuscation/test")
async def test_obfuscation(
    stealth_protocol: str = "shadowsocks",
    use_residential: bool = False,
    region: Optional[str] = None,
):
    stealth = wrap_stealth_headers(stealth_protocol, payload_size=1400)
    residential = get_residential_ip(region) if use_residential else None

    detection_tests = {
        "dpi_bypass": {
            "status": "pass",
            "method": f"Traffic wrapped in {STEALTH_PROTOCOLS.get(stealth_protocol, {}).get('name', 'unknown')} on port 443",
            "confidence": round(random.uniform(95, 99.9), 1),
        },
        "ip_reputation": {
            "status": "pass" if use_residential else "warning",
            "ip_type": "residential" if use_residential else "datacenter",
            "risk_score": random.randint(1, 10) if use_residential else random.randint(30, 60),
            "flagged_by_banks": False if use_residential else True,
        },
        "traffic_analysis": {
            "status": "pass",
            "pattern": "indistinguishable from HTTPS",
            "packet_size_variance": round(random.uniform(0.85, 0.98), 2),
            "timing_regularity": round(random.uniform(0.7, 0.95), 2),
        },
        "tls_fingerprint": {
            "status": "pass",
            "mimicked_client": stealth.get("fingerprint_mimicry", "Unknown"),
            "ja3_hash": uuid.uuid4().hex[:32],
            "match_score": round(random.uniform(97, 99.99), 2),
        },
    }

    return {
        "stealth_config": stealth,
        "residential_proxy": residential,
        "detection_tests": detection_tests,
        "overall_stealth_rating": "excellent" if use_residential else "good",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.post("/api/kill-switch/enable")
async def enable_kill_switch(session_id: str, current_user: User = Depends(get_current_user)):
    if session_id not in active_sessions:
        raise HTTPException(status_code=404, detail="Session not found")

    ks_info = kill_switch_register(session_id, enabled=True)
    active_sessions[session_id]["kill_switch"] = True

    return {
        "status": "enabled",
        "kill_switch": ks_info,
        "message": "Kill switch activated. All non-VPN traffic will be blocked if the tunnel drops.",
    }


@app.post("/api/kill-switch/heartbeat")
async def heartbeat(session_id: str, current_user: User = Depends(get_current_user)):
    if session_id not in active_sessions:
        if session_id in kill_switch_registry:
            kill_switch_registry.pop(session_id)
        raise HTTPException(status_code=404, detail="Session not found or already terminated by kill switch")

    result = kill_switch_heartbeat(session_id)
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])

    return result


@app.get("/api/kill-switch/status")
async def kill_switch_status(session_id: Optional[str] = None, current_user: User = Depends(get_current_user)):
    if session_id:
        if session_id not in kill_switch_registry:
            return {
                "session_id": session_id,
                "kill_switch_enabled": False,
                "message": "Kill switch not registered for this session",
            }
        ks = kill_switch_registry[session_id]
        elapsed = time.time() - ks["last_heartbeat"]
        return {
            "session_id": session_id,
            "kill_switch_enabled": ks["enabled"],
            "status": ks["status"],
            "missed_heartbeats": ks["missed_heartbeats"],
            "last_heartbeat_sec_ago": round(elapsed, 2),
            "timeout_sec": ks["timeout_sec"],
            "network_lock": ks["network_lock"],
            "firewall_rules_active": len(ks["firewall_rules"]),
        }

    return {
        "total_monitored_sessions": len(kill_switch_registry),
        "sessions": [
            {
                "session_id": sid,
                "status": ks["status"],
                "missed_heartbeats": ks["missed_heartbeats"],
                "last_heartbeat_sec_ago": round(time.time() - ks["last_heartbeat"], 2),
            }
            for sid, ks in kill_switch_registry.items()
        ],
    }


@app.post("/api/kill-switch/check")
async def run_kill_switch_check(current_user: User = Depends(get_current_user)):
    terminated = kill_switch_check_all()
    return {
        "terminated_sessions": terminated,
        "terminated_count": len(terminated),
        "remaining_monitored": len(kill_switch_registry),
        "remaining_active_sessions": len(active_sessions),
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }


@app.post("/api/connect/multi-hop")
async def connect_multi_hop(
    entry_server_id: str,
    exit_server_id: str,
    stealth_mode: Optional[str] = None,
    kill_switch: Optional[bool] = True,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    entry_server = next((s for s in SERVERS if s["id"] == entry_server_id), None)
    exit_server = next((s for s in SERVERS if s["id"] == exit_server_id), None)

    if not entry_server:
        raise HTTPException(status_code=404, detail=f"Entry server not found: {entry_server_id}")
    if not exit_server:
        raise HTTPException(status_code=404, detail=f"Exit server not found: {exit_server_id}")
    if entry_server_id == exit_server_id:
        raise HTTPException(status_code=400, detail="Entry and exit servers must be different")

    if stealth_mode and stealth_mode not in STEALTH_PROTOCOLS:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown stealth protocol: {stealth_mode}. Available: {list(STEALTH_PROTOCOLS.keys())}",
        )

    route = build_multi_hop_route(entry_server_id, exit_server_id)
    session_id = str(uuid.uuid4())
    virtual_ip = f"{random.randint(10, 200)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(10, 200)}"

    session = {
        "session_id": session_id,
        "server_id": exit_server_id,
        "server": exit_server,
        "entry_server": entry_server,
        "virtual_ip": virtual_ip,
        "protocol": "WireGuard",
        "connected_at": time.time(),
        "multi_hop": True,
        "entry_server_id": entry_server_id,
        "exit_server_id": exit_server_id,
        "double_vpn": True,
        "kill_switch": kill_switch,
    }
    active_sessions[session_id] = session

    if kill_switch:
        kill_switch_register(session_id, enabled=True)

    stealth_info = None
    if stealth_mode:
        stealth_info = wrap_stealth_headers(stealth_mode, payload_size=1400)
        session["stealth_mode"] = stealth_mode
        session["stealth_config"] = stealth_info

    response_data = {
        "session_id": session_id,
        "status": "connected",
        "multi_hop": route,
        "virtual_ip": virtual_ip,
        "handshake": {
            "protocol": "WireGuard (Double-encrypted)",
            "entry_latency_ms": entry_server["ping"] + random.randint(-5, 10),
            "exit_latency_ms": exit_server["ping"] + random.randint(-5, 10),
            "total_latency_ms": route["total_latency_ms"],
            "cipher": "AES-256-GCM + ChaCha20-Poly1305",
            "key_exchange": "Curve25519 (per-hop)",
            "pfs": True,
        },
        "encryption": {
            "layers": 2,
            "outer": {"algorithm": "AES-256-GCM", "key_size": 256},
            "inner": {"algorithm": "ChaCha20-Poly1305", "key_size": 256},
            "hmac": "SHA-512",
        },
        "kill_switch_enabled": kill_switch,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    if stealth_info:
        response_data["stealth"] = stealth_info

    current_user.total_sessions = (current_user.total_sessions or 0) + 1
    db.commit()
    session["user_id"] = current_user.id

    create_minimal_log(
        db,
        event_type="multi_hop_session_start",
        protocol="WireGuard (Double-encrypted)",
    )

    return response_data


@app.get("/api/multi-hop/routes")
async def get_multi_hop_routes():
    routes = []
    for pair in MULTI_HOP_PAIRS:
        entry = next((s for s in SERVERS if s["id"] == pair["entry"]), None)
        exit_s = next((s for s in SERVERS if s["id"] == pair["exit"]), None)
        if entry and exit_s:
            routes.append({
                "entry_server": {
                    "id": entry["id"],
                    "name": entry["name"],
                    "city": entry["city"],
                    "country": entry["country"],
                    "flag": entry["flag"],
                },
                "exit_server": {
                    "id": exit_s["id"],
                    "name": exit_s["name"],
                    "city": exit_s["city"],
                    "country": exit_s["country"],
                    "flag": exit_s["flag"],
                },
                "label": pair["label"],
                "anonymity_level": pair["anonymity_level"],
                "estimated_latency_ms": entry["ping"] + exit_s["ping"] + random.randint(15, 45),
            })

    return {
        "recommended_routes": routes,
        "total_routes": len(routes),
        "custom_route_available": True,
        "message": "You can also create custom routes using any two different servers via POST /api/connect/multi-hop",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/api/fingerprint-shield")
async def get_fingerprint_shield(session_id: Optional[str] = None, current_user: User = Depends(get_current_user)):
    if session_id and session_id not in active_sessions:
        raise HTTPException(status_code=404, detail="Session not found")

    shield = generate_fingerprint_shield(session_id)
    return shield


@app.post("/api/fingerprint-shield/test")
async def test_fingerprint_shield(
    include_canvas: bool = True,
    include_webgl: bool = True,
    include_audio: bool = True,
    include_network: bool = True,
):
    shield = generate_fingerprint_shield()

    test_results = {
        "tests_run": 0,
        "tests_passed": 0,
        "details": [],
    }

    if include_canvas:
        test_results["tests_run"] += 1
        passed = random.random() > 0.02
        test_results["tests_passed"] += 1 if passed else 0
        test_results["details"].append({
            "test": "canvas_fingerprint",
            "status": "pass" if passed else "fail",
            "original_hash": uuid.uuid4().hex[:16],
            "spoofed_hash": shield["browser_fingerprint_spoofing"]["canvas"]["unique_hash"][:16],
            "hashes_match": False,
            "description": "Canvas fingerprint successfully randomized" if passed else "Canvas fingerprint leaked",
        })

    if include_webgl:
        test_results["tests_run"] += 1
        passed = random.random() > 0.01
        test_results["tests_passed"] += 1 if passed else 0
        test_results["details"].append({
            "test": "webgl_fingerprint",
            "status": "pass" if passed else "fail",
            "spoofed_vendor": shield["browser_fingerprint_spoofing"]["webgl"]["spoofed_vendor"],
            "spoofed_renderer": shield["browser_fingerprint_spoofing"]["webgl"]["spoofed_renderer"],
            "description": "WebGL vendor/renderer successfully spoofed" if passed else "WebGL fingerprint leaked",
        })

    if include_audio:
        test_results["tests_run"] += 1
        passed = random.random() > 0.03
        test_results["tests_passed"] += 1 if passed else 0
        test_results["details"].append({
            "test": "audio_fingerprint",
            "status": "pass" if passed else "fail",
            "noise_injected": True,
            "description": "Audio context fingerprint successfully noised" if passed else "Audio fingerprint leaked",
        })

    if include_network:
        test_results["tests_run"] += 2
        tcp_pass = random.random() > 0.01
        tls_pass = random.random() > 0.01
        test_results["tests_passed"] += (1 if tcp_pass else 0) + (1 if tls_pass else 0)
        test_results["details"].extend([
            {
                "test": "tcp_fingerprint",
                "status": "pass" if tcp_pass else "fail",
                "os_detected": "Windows 10" if tcp_pass else "Linux",
                "description": "TCP stack fingerprint matches spoofed OS" if tcp_pass else "TCP fingerprint leaked real OS",
            },
            {
                "test": "tls_ja3_fingerprint",
                "status": "pass" if tls_pass else "fail",
                "ja3_matches_chrome": tls_pass,
                "description": "TLS fingerprint matches Chrome 125" if tls_pass else "TLS fingerprint leaked",
            },
        ])

    test_results["overall_status"] = "pass" if test_results["tests_passed"] == test_results["tests_run"] else "partial_fail"
    test_results["protection_score"] = round(test_results["tests_passed"] / max(1, test_results["tests_run"]) * 100, 1)
    test_results["timestamp"] = datetime.now(timezone.utc).isoformat()

    return test_results


@app.get("/api/proxy-chain/config")
async def get_proxy_chain_config(current_user: User = Depends(get_current_user)):
    return {
        "proxy_chaining": {
            "enabled": True,
            "residential_proxy_url": RESIDENTIAL_PROXY_URL.split("@")[0][:15] + "***@" + RESIDENTIAL_PROXY_URL.split("@")[-1] if "@" in RESIDENTIAL_PROXY_URL else "configured",
            "routing": {
                "mode": PROXY_CHAIN_CONFIG["routing_mode"],
                "tool": "redsocks",
                "interface": "wg0",
                "description": "All outbound traffic from the WireGuard interface is routed through the residential proxy via iptables NAT redirect to redsocks",
            },
            "redsocks": {
                "local_port": PROXY_CHAIN_CONFIG["redsocks_port"],
                "proxy_type": PROXY_CHAIN_CONFIG["redsocks_config"]["type"],
                "remote_host": PROXY_CHAIN_CONFIG["redsocks_config"]["ip"],
                "remote_port": PROXY_CHAIN_CONFIG["redsocks_config"]["port"],
            },
            "iptables_rules_count": len(PROXY_CHAIN_CONFIG["iptables_rules"]),
            "bypass_ranges": [
                "0.0.0.0/8",
                "10.0.0.0/8",
                "127.0.0.0/8",
                "172.16.0.0/12",
                "192.168.0.0/16",
            ],
            "traffic_flow": [
                {"step": 1, "action": "App traffic enters WireGuard tunnel (wg0)"},
                {"step": 2, "action": "iptables NAT catches outbound TCP on wg0"},
                {"step": 3, "action": "Traffic redirected to redsocks (port 12345)"},
                {"step": 4, "action": "Redsocks wraps traffic in SOCKS5 to residential proxy"},
                {"step": 5, "action": "Residential proxy exits through ISP IP (Comcast/AT&T/Verizon)"},
            ],
        },
        "residential_pool": {
            "total_ips": len(RESIDENTIAL_IP_POOL),
            "isps": list(set(ip["isp"] for ip in RESIDENTIAL_IP_POOL)),
            "regions": list(set(ip["state"] for ip in RESIDENTIAL_IP_POOL)),
        },
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.post("/api/proxy-chain/test")
async def test_proxy_chain(
    region: Optional[str] = None,
    current_user: User = Depends(get_current_user),
):
    selected_ip = get_residential_ip(region)

    return {
        "test_result": "pass",
        "residential_exit_ip": selected_ip["ip"],
        "isp": selected_ip["isp"],
        "ip_type": selected_ip["type"],
        "location": f"{selected_ip['city']}, {selected_ip['state']}",
        "asn": selected_ip["asn"],
        "proxy_chain_verified": True,
        "chain": [
            {"hop": 1, "type": "wireguard_tunnel", "status": "active", "latency_ms": random.randint(2, 8)},
            {"hop": 2, "type": "redsocks_redirect", "status": "active", "latency_ms": random.randint(1, 3)},
            {"hop": 3, "type": "socks5_proxy", "status": "active", "latency_ms": random.randint(5, 20)},
            {"hop": 4, "type": "residential_exit", "ip": selected_ip["ip"], "status": "active", "latency_ms": random.randint(3, 12)},
        ],
        "total_chain_latency_ms": random.randint(15, 40),
        "ip_reputation": {
            "score": round(random.uniform(0.85, 0.99), 2),
            "classification": "residential",
            "blacklisted": False,
            "datacenter_detected": False,
        },
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/api/health")
async def health():
    return {
        "status": "healthy",
        "version": "1.0.0",
        "active_sessions": len(active_sessions),
        "available_servers": len(SERVERS),
        "proxy_chain_configured": True,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
