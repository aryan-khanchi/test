from fastapi import FastAPI, HTTPException, Request, status
from pydantic import BaseModel
from jose import jwt, JWTError
import json

app = FastAPI()

PUBLIC_KEY_PEM = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2okOHspNjgA+2rTLbeuY
cxiP/hG8C6Sb9iwg3yiLAA4HCnpITcbWCSelbvbYGuc3EbNy4xFyf5Cbj5DHJMID
EkryOgyd2giIIIBOUBj8S63uGcnRpOBh9NFatfNwheKuzsPuVNldu6A9cNteNpXc
WyJjG2axVfmq7i6SuKr1JoWYG7xTTAvKPujSl4OtsQfO3h5NepzdfXpr28oNnzfW
ed+zclR6BcmNNo/WVfJ4xyCLSf0BCOgdTgW6PdaChd1l9VDetJZVEgC5tkyvXsfI
SI6iyrYbKR0NEBSqq4XkadEjsCs4F1RncsS4LlgniT7GlkL9Mce3b0wGLs9/7ZIX
dQIDAQAB
-----END PUBLIC KEY-----"""

EXPECTED_ISS = "https://idp.exam.local"
EXPECTED_AUD = "tds-u9szdr39.apps.exam.local"

class TokenBody(BaseModel):
    token: str

@app.post("/verify")
async def verify(body: TokenBody):
    token = body.token
    try:
# Decode and verify signature, audience, and issuer.
# options: do not skip expiration check; let jose handle exp automatically.
        claims = jwt.decode(
            token, PUBLIC_KEY_PEM,
            algorithms=["RS256"],
            audience=EXPECTED_AUD,
            issuer=EXPECTED_ISS,
            options={"require_exp": True, "require_iat": True},
        )
    except JWTError:
# Any error (signature, wrong aud/iss, expired) -> reject
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"valid": False})
# If we get here, token is valid. Extract requested claims.
    email = claims.get("email")
    sub = claims.get("sub")
    aud = claims.get("aud")
    return {"valid": True, "email": email, "sub": sub, "aud": aud}
