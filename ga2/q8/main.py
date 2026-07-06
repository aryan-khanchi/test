from fastapi import FastAPI, Header, HTTPException, Query, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List, Dict
from collections import defaultdict, deque
import time
import uuid

T = 58
RATE_LIMIT = 16
WINDOW_SECONDS = 10

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class OrderIn(BaseModel):
    item: Optional[str] = None
    quantity: Optional[int] = None

orders_catalog = [{"id": i, "name": f"order-{i}"} for i in range(1, T + 1)]

idempotency_store: Dict[str, Dict] = {}
client_requests = defaultdict(deque)

def check_rate_limit(client_id: str):
    now = time.time()
    bucket = client_requests[client_id]

    while bucket and now - bucket[0] >= WINDOW_SECONDS:
        bucket.popleft()

    if len(bucket) >= RATE_LIMIT:
        retry_after = max(1, int(WINDOW_SECONDS - (now - bucket[0]))) if bucket else WINDOW_SECONDS
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded",
            headers={"Retry-After": str(retry_after)},
        )

    bucket.append(now)

@app.post("/orders", status_code=201)
def create_order(
    order: OrderIn,
    response: Response,
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
    x_client_id: Optional[str] = Header(default="anonymous", alias="X-Client-Id"),
):
    check_rate_limit(x_client_id)

    if not idempotency_key:
        raise HTTPException(status_code=400, detail="Missing Idempotency-Key")

    if idempotency_key in idempotency_store:
        stored = idempotency_store[idempotency_key]
        response.status_code = 200
        return stored

    new_id = str(uuid.uuid4())
    stored = {"id": new_id, "item": order.item, "quantity": order.quantity}
    idempotency_store[idempotency_key] = stored
    return stored

@app.get("/orders")
def list_orders(
    limit: int = Query(default=10, ge=1, le=100),
    cursor: Optional[str] = None,
    x_client_id: Optional[str] = Header(default="anonymous", alias="X-Client-Id"),
):
    check_rate_limit(x_client_id)

    start_index = 0
    if cursor:
        try:
            start_index = int(cursor)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid cursor")

    page = orders_catalog[start_index:start_index + limit]
    next_cursor = None

    if start_index + limit < len(orders_catalog):
        next_cursor = str(start_index + limit)

    return {
        "items": page,
        "next_cursor": next_cursor,
    }

@app.get("/")
def root():
    return {"message": "orders api is running"}
