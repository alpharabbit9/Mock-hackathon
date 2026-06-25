# QueueStorm Warmup — CRM Ticket Sorter

A small web service that reads one customer support ticket and returns a
structured classification: case type, severity, owning department, a one-line
agent summary, a human-review flag, and a confidence score.

Rules-based (no LLM, no GPU, no external API calls). Fast, deterministic, and
cheap to run on any free tier.

## Endpoints

| Method | Path           | Purpose                                  |
|--------|----------------|------------------------------------------|
| GET    | `/health`      | Health check, returns `{"status":"ok"}`  |
| POST   | `/sort-ticket` | Classify one ticket                      |

### Request (`POST /sort-ticket`)
```json
{
  "ticket_id": "T-001",
  "channel": "app",
  "locale": "en",
  "message": "I sent 5000 taka to a wrong number this morning, please help me get it back"
}
```
`ticket_id` and `message` are required. `channel` and `locale` are optional.

### Response
```json
{
  "ticket_id": "T-001",
  "case_type": "wrong_transfer",
  "severity": "high",
  "department": "dispute_resolution",
  "agent_summary": "Customer reports sending 5000 BDT to the wrong recipient and requests recovery.",
  "human_review_required": true,
  "confidence": 0.86
}
```

## How classification works

1. **case_type** is decided by keyword matching with a safety-first precedence:
   `phishing_or_social_engineering` > `wrong_transfer` > `payment_failed` >
   `refund_request` > `other`. Phishing is only triggered when a credential
   term (OTP/PIN/password/CVV) appears alongside an external-request context
   (someone called/asked/share/suspicious link), or on strong scam phrases.
   This avoids flagging a legitimate "I forgot my PIN" as fraud.
2. **severity** maps from case type (phishing→critical, wrong_transfer and
   payment_failed→high, refund→low, other→low). A *contested* refund
   (unauthorized / charged twice) is bumped to medium.
3. **department** follows the spec's routing table.
4. **agent_summary** is generated from safe templates and never instructs the
   customer to share a PIN, OTP, password, or card number. A final sanitizer
   enforces this rule as defense-in-depth.
5. **human_review_required** is true for any critical case or phishing.
6. **confidence** is a base score per case type, reduced slightly when wording
   is ambiguous (multiple money/refund signals fire at once).

Bengali and common transliterations are included in the keyword banks, so
`locale: "bn"` and `"mixed"` tickets are handled.

## Run locally

Requires Python 3.11+.

```bash
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000
```

Then:
```bash
curl http://localhost:8000/health

curl -X POST http://localhost:8000/sort-ticket \
  -H "Content-Type: application/json" \
  -d '{"ticket_id":"T-001","message":"I sent 3000 to wrong number"}'
```

Validate the public sample cases (no dependencies needed):
```bash
python test_local.py
```

## Run with Docker

```bash
docker build -t queuestorm .
docker run -p 8000:8000 queuestorm
# health: http://localhost:8000/health
```

## Deploy (pick one)

### Render (blueprint, easiest)
1. Push this repo to GitHub.
2. On Render: **New → Blueprint**, point it at the repo. `render.yaml` is
   detected automatically (Python runtime, health check on `/health`).
3. Deploy. Render gives you an HTTPS URL like
   `https://queuestorm-ticket-sorter.onrender.com`.

Manual alternative on Render (**New → Web Service**):
- Build command: `pip install -r requirements.txt`
- Start command: `uvicorn main:app --host 0.0.0.0 --port $PORT`
- Health check path: `/health`

### Railway / Fly
- Both detect the `Procfile`. Start command is
  `uvicorn main:app --host 0.0.0.0 --port $PORT`.
- Or deploy the included `Dockerfile` directly.

### Any VM (EC2 / Poridhi Lab)
```bash
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000
```
Put it behind a reverse proxy (Caddy / Nginx) for HTTPS, or use the platform's
managed TLS.

## Configuration

| Variable | Required | Notes                                                    |
|----------|----------|----------------------------------------------------------|
| `PORT`   | No       | Injected by the host. Defaults to 8000 locally / Docker. |

No secrets or API keys are used, so nothing sensitive lives in the repo.

## Project layout
```
classifier.py    # pure-Python rules engine (no deps, unit-testable)
main.py          # FastAPI app exposing /health and /sort-ticket
test_local.py    # offline check against the 5 public sample cases
requirements.txt
Procfile         # Railway / Fly / Heroku-style start command
render.yaml      # Render blueprint
runtime.txt      # pins Python 3.11.9
Dockerfile       # container build for any platform
```

## Known limitations
- Keyword-based, so adversarial or very indirect phrasing can be misrouted.
- Amount extraction is best-effort and used only for the summary text.
- English + a starter set of Bengali/transliterated terms; the Bengali bank
  can be expanded easily in `classifier.py`.
