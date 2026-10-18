"""HTTP API.  Run with:  uvicorn codeguard.api:app --port 8100 --reload"""

from __future__ import annotations

from fastapi import FastAPI, HTTPException
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, Field

from codeguard import __version__
from codeguard.scan import ScanInputError, scan_code
from codeguard.models import ScanResult

app = FastAPI(title="CodeGuard API", version=__version__)

# Hard cap on request size before line counting (about 2,000 long lines).
MAX_CODE_CHARS = 400_000


class HealthResponse(BaseModel):
    status: str
    version: str


class ScanRequest(BaseModel):
    code: str = Field(max_length=MAX_CODE_CHARS, description="Python source code to scan. It is never executed.")
    filename: str | None = Field(default=None, max_length=200, description="Optional file name, e.g. app.py")


@app.get("/api/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(status="ok", version=__version__)


@app.post("/api/scan", response_model=ScanResult)
async def scan(req: ScanRequest) -> ScanResult:
    try:
        # Scanners are slow subprocess calls; run them off the event loop.
        return await run_in_threadpool(scan_code, req.code, req.filename)
    except ScanInputError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
