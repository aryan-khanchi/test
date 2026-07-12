import os
import base64
import binascii
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from openai import OpenAI

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

class AnswerRequest(BaseModel):
    image_base64: str
    question: str

def to_data_url(image_b64: str) -> str:
    s = image_b64.strip().replace("\n", "").replace(" ", "")
    if s.startswith("data:"):
        header, b64part = s.split(",", 1)
        base64.b64decode(b64part, validate=True)
        return s
    base64.b64decode(s, validate=True)
    return f"data:image/png;base64,{s}"

@app.post("/answer-image")
def answer_image(req: AnswerRequest):
    try:
        data_url = to_data_url(req.image_base64)

        response = client.responses.create(
            model="gpt-4.1",
            input=[
                {
                    "role": "user",
                    "content": [
                        {"type": "input_text", "text": req.question},
                        {"type": "input_image", "image_url": data_url},
                    ],
                }
            ],
        )

        answer = (response.output_text or "").strip()
        return {"answer": str(answer) if answer else "Unable to read the image"}

    except binascii.Error:
        raise HTTPException(status_code=400, detail="Invalid base64 image")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Model error: {str(e)}")
