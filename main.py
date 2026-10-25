import hashlib
import hmac
import os
import secrets
from typing import Optional

import requests
from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

SUPABASE_URL = os.environ.get("SUPABASE_URL", "").rstrip("/")
SUPABASE_SERVICE_ROLE_KEY = os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "")
ADMIN_API_KEY = os.environ.get("ADMIN_API_KEY", "")
TABLE = "client_registry"
PBKDF2_ROUNDS = 240_000  # Must match the desktop app's existing password hashing.

app = FastAPI(title="TuitionDesk Control API", docs_url=None, redoc_url=None, openapi_url=None)


def config_ok():
    if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY or not ADMIN_API_KEY:
        raise HTTPException(status_code=503, detail="Server configuration is incomplete.")


def db_request(method: str, path: str = "", *, params=None, body=None):
    config_ok()
    url = f"{SUPABASE_URL}/rest/v1/{TABLE}{path}"
    headers = {
        "apikey": SUPABASE_SERVICE_ROLE_KEY,
        "Authorization": f"Bearer {SUPABASE_SERVICE_ROLE_KEY}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    if method in ("POST", "PATCH", "DELETE"):
        headers["Prefer"] = "return=representation"
    try:
        response = requests.request(method, url, headers=headers, params=params, json=body, timeout=35)
    except requests.RequestException:
        raise HTTPException(status_code=503, detail="Account service is temporarily unavailable.")
    if response.status_code >= 400:
        # Keep provider responses and secrets out of the public error message.
        raise HTTPException(status_code=502, detail="Account database request failed.")
    if not response.content:
        return []
    try:
        return response.json()
    except ValueError:
        raise HTTPException(status_code=502, detail="Account database returned an invalid response.")


def require_admin(x_admin_key: Optional[str] = Header(default=None)):
    config_ok()
    if not x_admin_key or not hmac.compare_digest(x_admin_key, ADMIN_API_KEY):
        raise HTTPException(status_code=401, detail="Developer authorization failed.")


def hash_password(password: str, salt: Optional[str] = None):
    salt = salt or secrets.token_bytes(16).hex()
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), PBKDF2_ROUNDS).hex()
    return salt, digest


def verify_password(password: str, salt: str, digest: str) -> bool:
    try:
        return hmac.compare_digest(hash_password(password, salt)[1], digest)
    except (ValueError, TypeError):
        return False


class ClientLogin(BaseModel):
    username: str = Field(min_length=1, max_length=200)
    password: str = Field(min_length=1, max_length=512)


class ClientCreate(BaseModel):
    org: str = Field(min_length=1, max_length=200)
    username: str = Field(min_length=1, max_length=200)
    phone: str = Field(default="", max_length=40)
    password: str = Field(default="", max_length=512)


class ClientStatus(BaseModel):
    active: bool


@app.get("/health")
def health():
    # Does not disclose database connectivity or secret configuration.
    return {"ok": True, "service": "TuitionDesk Control API"}


def authenticate_client(username: str, password: str):
    rows = db_request("GET", params={
        "select": "client_id,org,username,salt,password_hash,active",
        "username": f"eq.{username.strip()}",
        "limit": "1",
    })
    if not rows or not verify_password(password, rows[0].get("salt", ""), rows[0].get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Username or password is incorrect.")
    row = rows[0]
    if not row.get("active", False):
        raise HTTPException(status_code=403, detail="This tuition centre account is paused.")
    return {"client_id": row["client_id"], "org": row["org"], "username": row["username"], "active": True}


@app.post("/v1/client/login")
def client_login(payload: ClientLogin):
    return authenticate_client(payload.username, payload.password)


@app.post("/v1/client/check")
def client_check(payload: ClientLogin):
    # Client app will call this periodically so a pause/reset is enforced on next check.
    return authenticate_client(payload.username, payload.password)


@app.get("/v1/admin/clients", dependencies=[Depends(require_admin)])
def list_clients():
    return db_request("GET", params={
        "select": "client_id,org,username,phone,created_at,active",
        "order": "created_at.desc",
    })


@app.post("/v1/admin/clients", dependencies=[Depends(require_admin)])
def create_client(payload: ClientCreate):
    password = payload.password or ("TD-" + secrets.token_urlsafe(9))
    if len(password) < 8:
        raise HTTPException(status_code=400, detail="Password must contain at least 8 characters.")
    salt, digest = hash_password(password)
    client_id = secrets.token_hex(6)
    row = {
        "client_id": client_id,
        "org": payload.org.strip(),
        "username": payload.username.strip(),
        "salt": salt,
        "password_hash": digest,
        "phone": payload.phone.strip(),
        "active": True,
    }
    created = db_request("POST", body=row)
    if not created:
        raise HTTPException(status_code=502, detail="Client account was not created.")
    return {"client": created[0], "temporary_password": password}


@app.patch("/v1/admin/clients/{client_id}", dependencies=[Depends(require_admin)])
def set_client_status(client_id: str, payload: ClientStatus):
    rows = db_request("PATCH", params={"client_id": f"eq.{client_id}"}, body={"active": payload.active})
    if not rows:
        raise HTTPException(status_code=404, detail="Client account not found.")
    return rows[0]


@app.post("/v1/admin/clients/{client_id}/reset-password", dependencies=[Depends(require_admin)])
def reset_client_password(client_id: str):
    password = "TD-" + secrets.token_urlsafe(9)
    salt, digest = hash_password(password)
    rows = db_request("PATCH", params={"client_id": f"eq.{client_id}"}, body={"salt": salt, "password_hash": digest})
    if not rows:
        raise HTTPException(status_code=404, detail="Client account not found.")
    return {"client_id": client_id, "username": rows[0]["username"], "temporary_password": password}


@app.delete("/v1/admin/clients/{client_id}", dependencies=[Depends(require_admin)])
def delete_client(client_id: str):
    rows = db_request("DELETE", params={"client_id": f"eq.{client_id}"})
    if not rows:
        raise HTTPException(status_code=404, detail="Client account not found.")
    return {"deleted": True, "client_id": client_id}
