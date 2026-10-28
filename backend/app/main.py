from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.api import auth, experiment, live, ml, policy, portal, security, sessions, simulation
from app.config import get_settings
from app.database import Base, SessionLocal, engine
from app.database.seed import seed
from app.detection.ml_detector import get_detector
from app.websocket.hub import hub

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("sessionguard")
settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        info = seed(db)
        log.info("seeded users: %s", info)
    finally:
        db.close()
    hub.bind_loop(asyncio.get_running_loop())
    status = get_detector().status()
    log.info("ML detector: active=%s loaded=%s version=%s", status["active_model"], status["loaded"], status["version"])
    if not status["loaded"]:
        log.warning("No trained model loaded - running rule-only. Run scripts/train_models.ps1 to enable ML scoring.")
    yield


app = FastAPI(
    title="SessionGuard AI",
    version="1.0.0",
    description="Intelligent session-hijacking detection, behavioral authentication and automated Zero-Trust defense. "
                "Detect. Analyze. Contain. Protect.",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["X-SG-Risk", "X-SG-Band", "X-SG-Decision", "X-SG-Request-Log"],
)


@app.exception_handler(StarletteHTTPException)
async def http_exc(request: Request, exc: StarletteHTTPException):
    detail = exc.detail
    body = detail if isinstance(detail, dict) else {"code": "error", "message": str(detail)}
    return JSONResponse(status_code=exc.status_code, content={"error": body}, headers=exc.headers)


@app.exception_handler(RequestValidationError)
async def validation_exc(request: Request, exc: RequestValidationError):
    first = exc.errors()[0] if exc.errors() else {}
    field = ".".join(str(p) for p in first.get("loc", [])[1:]) or "input"
    return JSONResponse(status_code=422, content={"error": {
        "code": "validation_error", "message": f"{field}: {first.get('msg', 'invalid value')}",
        "fields": [{"field": ".".join(str(p) for p in e.get("loc", [])[1:]), "message": e.get("msg")} for e in exc.errors()],
    }})


@app.get("/api/health", tags=["meta"])
def health():
    return {"status": "ok", "app": settings.app_name, "model": get_detector().status()}


@app.get("/api/meta", tags=["meta"])
def meta():
    from app.simulation.scenarios import SCENARIOS
    return {
        "app": settings.app_name, "version": app.version, "tagline": "Detect. Analyze. Contain. Protect.",
        "environment": settings.environment, "scenarios": len(SCENARIOS),
        "risk_bands": [{"band": "low", "range": "0-24"}, {"band": "elevated", "range": "25-49"},
                       {"band": "high", "range": "50-74"}, {"band": "critical", "range": "75-100"}],
        "demo_accounts": [{"username": "ada", "role": "user"}, {"username": "grace", "role": "user"},
                          {"username": "admin", "role": "admin"}],
    }


for r in (auth.router, sessions.router, portal.router, security.router, simulation.router, experiment.router,
          ml.router, policy.router, live.router):
    app.include_router(r)
