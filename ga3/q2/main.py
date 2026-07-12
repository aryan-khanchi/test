import os
import base64
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

def make_data_url(image_b64: str) -> str:
    s = image_b64.strip()
    if s.startswith("data:"):
        return s
    return f"data:image/png;base64,{s}"

@app.post("/answer-image")
def answer_image(req: AnswerRequest):
    if not req.image_base64 or not req.question:
        raise HTTPException(status_code=400, detail="Missing image_base64 or question")

    data_url = make_data_url(req.image_base64)

    try:
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
        if not answer:
            answer = "Unable to read the image"

        return {"answer": str(answer)}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Model error: {str(e)}")
