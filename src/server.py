from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.websockets import WebSocketState
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Dict, Any, Optional
from .router import route_request
from .services.audit_agent import get_audit_agent
from .services.repair_agent import get_repair_agent
from .services.edit_agent import get_edit_agent
from .models import RepairRequest, EditRequest, AuditRequest
import uvicorn
import os
import logging
import uuid

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("nexops.server")

app = FastAPI(title="NexOps MCP")

# Add CORS middleware
origins = [
    # ── NexOps Production Domains ──────────────────────────────────────────────
    "https://hub.nexops.cash",
    "https://app.nexops.cash",
    "https://wiz.nexops.cash",
    "https://docs.nexops.cash",
    # ── Legacy / Dev Origins ────────────────────────────────────────────────────
    "https://www.hexecutioners.club",
    "https://hexecutioners.club",       # without www
    "http://www.hexecutioners.club",    # http fallback
    "http://hexecutioners.club",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)

@app.middleware("http")
async def add_pna_header(request: Request, call_next):
    """
    Handle Chrome's Private Network Access (PNA) preflight and regular requests.
    Required when a public site (https://www.hexecutioners.club) calls a local address.
    """
    # 1. Capture the response first
    # For OPTIONS requests, CORSMiddleware might handle it, so we catch its response.
    response = await call_next(request)
    
    # 2. Add the PNA header if requested or for loopback access
    # Chrome sends 'Access-Control-Request-Private-Network: true' in preflight
    # We respond with 'Access-Control-Allow-Private-Network: true'
    if request.headers.get("access-control-request-private-network") == "true":
        response.headers["Access-Control-Allow-Private-Network"] = "true"
    
    # Also add it to any request from hexecutioners just to be safe with Chrome's aggressive PNA
    origin = request.headers.get("origin")
    if origin == "https://www.hexecutioners.club":
        response.headers["Access-Control-Allow-Private-Network"] = "true"
        
    return response

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    logger.error(f"Validation error: {exc.errors()}")
    logger.error(f"Body: {await request.body()}")
    return JSONResponse(
        status_code=422,
        content={"detail": exc.errors(), "body": str(await request.body())},
    )

@app.get("/")
async def health_check():
    return {"status": "ok", "service": "NexOps MCP", "version": "0.1.0"}

# ─── Phase AR (Audit & Repair) REST APIs ──────────────────────────────

@app.post("/api/audit")
async def audit_endpoint(req: AuditRequest):
    logger.info("Received /api/audit request")
    agent = get_audit_agent()
    api_key = req.context.get("api_key") if req.context else None
    provider = req.context.get("provider") if req.context else None
    groq_key = req.context.get("groq_key") if req.context else None
    openrouter_key = req.context.get("openrouter_key") if req.context else None
    report = await agent.audit(
        code=req.code, 
        intent=req.intent, 
        effective_mode=req.effective_mode,
        api_key=api_key,
        provider=provider,
        groq_key=groq_key,
        openrouter_key=openrouter_key
    )
    return report.model_dump()

@app.post("/api/repair")
async def repair_endpoint(req: RepairRequest):
    logger.info(f"Received /api/repair request for rule: {req.issue.rule_id}")
    agent = get_repair_agent()
    api_key = req.context.get("api_key") if req.context else None
    provider = req.context.get("provider") if req.context else None
    groq_key = req.context.get("groq_key") if req.context else None
    openrouter_key = req.context.get("openrouter_key") if req.context else None
    response = await agent.repair(
        req, 
        api_key=api_key, 
        provider=provider,
        groq_key=groq_key,
        openrouter_key=openrouter_key
    )
    return response.model_dump()

@app.post("/api/edit")
async def edit_endpoint(req: EditRequest):
    logger.info(f"Received /api/edit request: {req.instruction[:80]}")
    agent = get_edit_agent()
    response = await agent.edit(req)
    return response.model_dump()

# ─── Generation WebSocket API ─────────────────────────────────────────

@app.websocket("/ws/generate")
async def mcp_ws(ws: WebSocket):
    await ws.accept()
    logger.info("Client connected")
    
    # Callback to send updates back to the client
    async def send_update(update_msg: dict):
        try:
            if ws.client_state == WebSocketState.CONNECTED:
                await ws.send_json(update_msg)
        except Exception as e:
            logger.error(f"Failed to send update: {e}")

    try:
        while True:
            msg = await ws.receive_json()
            
            # Handle the new "intent" format from the external IDE
            if msg.get("type") == "intent":
                request_id = uuid.uuid4().hex[:8]
                logger.info(f"Received intent: {msg.get('prompt')} (ID: {request_id})")
                
                # BYOK Extraction from intent message
                context = msg.get("context", {})
                api_key = context.get("api_key")
                provider = context.get("provider")
                groq_key = context.get("groq_key")
                openrouter_key = context.get("openrouter_key")
                security_level = context.get("security_level", "high")

                # Transform to internal MCPRequest format
                internal_msg = {
                    "request_id": request_id,
                    "action": "generate",
                    "payload": {
                        "user_request": msg.get("prompt"),
                        "history": msg.get("history", [])
                    },
                    "context": {
                        "security_level": security_level,
                        "api_key": api_key,
                        "provider": provider,
                        "groq_key": groq_key,
                        "openrouter_key": openrouter_key
                    }
                }
                
                response = await route_request(internal_msg, on_update=send_update)
                await ws.send_json(response)
            else:
                # Traditional JSON-RPC style messages
                response = await route_request(msg, on_update=send_update)
                await ws.send_json(response)
                
    except WebSocketDisconnect:
        logger.info("Client disconnected")
    except Exception as e:
        logger.error(f"WebSocket fatal error: {e}")
        try:
            if ws.client_state == WebSocketState.CONNECTED:
                await ws.send_json({
                    "type": "error", 
                    "error": {"code": "FATAL", "message": str(e)}
                })
        except:
            pass

if __name__ == "__main__":
    port = int(os.getenv("PORT", 3000))
    # Note: Using string import for reload functionality
    uvicorn.run("src.server:app", host="0.0.0.0", port=port, reload=True)
