from fastapi import FastAPI, Request, Header, Response
import os, hmac, hashlib, base64, json, logging
from typing import Optional
import logging

class SkipHealthz(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        # Only hide uvicorn access-log lines for GET /healthz
        msg = record.getMessage()
        return ' "GET /healthz ' not in msg

logging.getLogger("uvicorn.access").addFilter(SkipHealthz())

# --- DB setup (async SQLAlchemy + asyncpg) ---
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy import text

app = FastAPI(title="ElectronConnect Webhook Receiver")

# Shared secret for signature checks (set in Render → Environment)
SECRET = os.getenv("ELECTRONCONNECT_WEBHOOK_SECRET", "")

# DATABASE_URL from Render (External Database URL); convert to async driver url
# DATABASE_URL from Render (External Database URL) → force asyncpg
def to_asyncpg_url(raw: str) -> str:
    # normalize old Heroku-style scheme
    if raw.startswith("postgres://"):
        raw = "postgresql://" + raw[len("postgres://"):]
    # force SQLAlchemy to use asyncpg
    if raw.startswith("postgresql://"):
        return "postgresql+asyncpg://" + raw[len("postgresql://"):]
    return raw

RAW_DB_URL = os.getenv("DATABASE_URL", "")
DB_URL = to_asyncpg_url(RAW_DB_URL) if RAW_DB_URL else None
engine = create_async_engine(DB_URL, future=True, echo=False) if DB_URL else None


# Create a single “log everything” table
DDL_TABLE = """
CREATE TABLE IF NOT EXISTS webhook_event (
  id               bigserial PRIMARY KEY,
  received_at      timestamptz NOT NULL DEFAULT now(),
  event_type       text,
  x_correlation_id text,
  x_signature      text,
  signature_valid  boolean,
  remote_addr      text,
  raw_body         text NOT NULL,
  parsed_body      jsonb
)
"""

DDL_INDEX = """
CREATE INDEX IF NOT EXISTS we_received_at_idx
ON webhook_event (received_at DESC)
"""

def compute_sig(raw: bytes) -> str:
    # Steps 1–4: UTF-8 secret → HMAC-SHA256(raw body) → Base64
    digest = hmac.new(SECRET.encode("utf-8"), raw, hashlib.sha256).digest()
    return base64.b64encode(digest).decode("ascii")

@app.on_event("startup")
async def startup():
    if engine:
        try:
            async with engine.begin() as conn:
                # run as two separate statements (asyncpg can't prepare multiple)
                await conn.execute(text(DDL_TABLE))
                await conn.execute(text(DDL_INDEX))
            logging.info("Database ready")
        except Exception as e:
            logging.error(f"Database connection failed at startup: {e}")

@app.get("/healthz")
def health():
    return {"status": "ok"}

@app.get("/debug/events")
async def debug_events(limit: int = 20):
    """Quick view of recent stored events (remove in prod if you prefer)."""
    if not engine:
        return []
    async with engine.begin() as conn:
        rows = (await conn.execute(text("""
            SELECT received_at, event_type, signature_valid, x_correlation_id
            FROM webhook_event
            ORDER BY received_at DESC
            LIMIT :limit
        """), {"limit": limit})).mappings().all()
    return [dict(r) for r in rows]

@app.post("/webhooks/electronconnect")
async def electronconnect_webhook(
    request: Request,
    x_signature: Optional[str] = Header(default=None),
    x_correlation_id: Optional[str] = Header(default=None),
):
    # 1) Exact raw bytes of the POST body (what you must HMAC)
    raw = await request.body()
    remote_addr = request.client.host if request.client else None

    # 2) Validate signature only if we have a secret configured
    sig_ok = True
    expected = None
    if SECRET:
        expected = compute_sig(raw)
        sig_ok = bool(x_signature) and hmac.compare_digest(expected, x_signature)

    # 3) Parse JSON *after* computing signature on raw bytes
    try:
        payload = json.loads(raw.decode("utf-8"))
        event_type = payload.get("event")
    except Exception:
        payload = {"_parse_error": True}
        event_type = None

    # 4) Store EVERY request (even invalid signatures) for audit/ops
    if engine:
        async with engine.begin() as conn:
            await conn.execute(text("""
                INSERT INTO webhook_event (
                  event_type, x_correlation_id, x_signature, signature_valid,
                  remote_addr, raw_body, parsed_body
                ) VALUES (
                  :event_type, :cid, :sig, :sig_ok,
                  :ip, :raw, CAST(:parsed AS jsonb)
                )
            """), {
                "event_type": event_type,
                "cid": x_correlation_id,
                "sig": x_signature,
                "sig_ok": sig_ok,
                "ip": remote_addr,
                "raw": raw.decode("utf-8", errors="replace"),
                "parsed": json.dumps(payload)
            })

    # 5) If secret is set and signature is bad → reject (but we've logged it)
    if SECRET and not sig_ok:
        logging.warning({
            "reason": "bad_signature",
            "x_correlation_id": x_correlation_id,
            "remote_addr": remote_addr
        })
        return Response(status_code=401)

    # 6) ACK immediately per spec
    logging.info({"received_event": event_type, "x_correlation_id": x_correlation_id})
    return Response(status_code=200)
