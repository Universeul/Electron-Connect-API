from fastapi import FastAPI, Request, Header, Response
import os, hmac, hashlib, base64, json, logging

app = FastAPI(title="ElectronConnect Webhook Receiver")
SECRET = os.getenv("ELECTRONCONNECT_WEBHOOK_SECRET", "")

def compute_sig(raw: bytes) -> str:
    digest = hmac.new(SECRET.encode("utf-8"), raw, hashlib.sha256).digest()   # steps 1–3
    return base64.b64encode(digest).decode("ascii")                           # step 4

@app.get("/healthz")
def health():
    return {"status": "ok"}

@app.post("/webhooks/electronconnect")
async def electronconnect_webhook(
    request: Request,
    x_signature: str | None = Header(default=None),
    x_correlation_id: str | None = Header(default=None),
):
    raw = await request.body()  # step 2

    # Only enforce validation once the secret has been issued by ElectronConnect
    if SECRET:
        expected = compute_sig(raw)
        if not x_signature or not hmac.compare_digest(expected, x_signature):  # step 5
            logging.warning({"reason": "bad_signature", "x_correlation_id": x_correlation_id})
            return Response(status_code=401)  # do not process invalid payloads

    # safe to parse/act (ack must be near-immediate)
    try:
        payload = json.loads(raw.decode("utf-8"))
    except Exception:
        payload = {"_parse_error": True}

    logging.info({"received_event": payload.get("event"), "x_correlation_id": x_correlation_id})
    return Response(status_code=200)
