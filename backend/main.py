from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI()

# Enable CORS so your secure React plugin frontend can communicate with localhost API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # In production, swap with your exact hosted React frontend URL
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class EmailPayload(BaseModel):
    text: str

@app.post("/api/analyze")
async def analyze_email(payload: EmailPayload):
    # Core Phase 1 placeholder logic.
    # Replace this section with your transformer model or API evaluation tool.
    sample_text = payload.text.lower()
    
    if "kindly" in sample_text or "urgent" in sample_text:
        ai_confidence = 88
    else:
        ai_confidence = 14

    return {
        "ai_confidence": ai_confidence,
        "status": "success"
    }