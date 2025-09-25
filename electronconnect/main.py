from fastapi import FastAPI, Request, Header, Response
from fastapi.responses import JSONResponse
import logging
import json

app = FastAPI(title="ElectronConnect Webhook Receiver")

# Basic health check
@app.get("/healthz")
def health():
    return {"status": "ok"}

@app.post("/webhooks/electronconnect")
async def electronconnect_webhook(
    request: Request,
    x_signature: str | None = Header(default=None),
    x_correlation_id: str | None = Header(default=None),
):
    # 1) Read and keep the raw bytes (for signature verification in Step 3)
    raw = await request.body()

    # 2) Log headers for tracing (mask signature length if you prefer)
    logging.info({
        "event_source": "electronconnect",
        "x_correlation_id": x_correlation_id,
        "x_signature_present": bool(x_signature),
        "raw_len": len(raw),
    })

    # 3) Parse JSON safely (don’t block the 200 if parsing fails)
    try:
        payload = json.loads(raw.decode("utf-8"))
    except Exception:
        payload = {"_parse_error": True}

    # (Optional) minimal sanity log of event type
    event = payload.get("event")
    logging.info({"received_event": event})

    # 4) ACK **immediately** per spec (do heavy work asynchronously later)
    #    DispatchInstruction MUST get 200 — we’ll implement signature + worker next steps.
    return Response(status_code=200)
