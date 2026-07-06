from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from uuid import uuid4
import time

app = FastAPI()

EMAIL = "24f1002157@ds.study.iitm.ac.in"
ALLOWED_ORIGINS = [
    "https://app-f7o01f.example.com",
    "https://exam.sanand.workers.dev"
]

RATE_LIMIT = 14
WINDOW_SECONDS = 10

client_buckets = {}


class RequestContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        request_id = request.headers.get("X-Request-ID") or str(uuid4())
        request.state.request_id = request_id

        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        client_id = request.headers.get("X-Client-Id", "anonymous")
        now = time.time()

        bucket = client_buckets.get(client_id, [])
        bucket = [ts for ts in bucket if now - ts < WINDOW_SECONDS]

        if len(bucket) >= RATE_LIMIT:
            return JSONResponse(
                status_code=429,
                content={"detail": "Too Many Requests"}
            )

        bucket.append(now)
        client_buckets[client_id] = bucket
        return await call_next(request)


app.add_middleware(RequestContextMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["X-Request-ID"],
)
app.add_middleware(RateLimitMiddleware)


@app.get("/ping")
async def ping(request: Request):
    return {
        "email": EMAIL,
        "request_id": request.state.request_id
    }
