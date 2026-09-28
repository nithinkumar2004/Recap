from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1.releases import router as releases_router

app = FastAPI(
    title="Release Captain API",
    description="Autonomous Agentic Release Engineering Platform",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(releases_router)


@app.get("/health")
def health_check():
    return {"status": "healthy", "service": "Release Captain API"}
