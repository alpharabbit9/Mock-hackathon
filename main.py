"""
QueueStorm Warmup — CRM ticket sorter.

GET  /health        -> service health
POST /sort-ticket   -> structured classification of one ticket
"""

from fastapi import FastAPI
from pydantic import BaseModel
from typing import Optional

from classifier import classify

app = FastAPI(title="QueueStorm Ticket Sorter", version="1.0.0")


class Ticket(BaseModel):
    ticket_id: str
    message: str
    channel: Optional[str] = None
    locale: Optional[str] = None


class Classification(BaseModel):
    ticket_id: str
    case_type: str
    severity: str
    department: str
    agent_summary: str
    human_review_required: bool
    confidence: float


@app.get("/")
def root():
    return {"service": "QueueStorm Ticket Sorter", "endpoints": ["/health", "/sort-ticket"]}


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/sort-ticket", response_model=Classification)
def sort_ticket(ticket: Ticket):
    result = classify(ticket.message, ticket.locale)
    return Classification(ticket_id=ticket.ticket_id, **result)
