from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from starlette.websockets import WebSocketState
from fastapi.middleware.cors import CORSMiddleware
from .router import route_request
import uvicorn
import os
import logging
import uuid

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("nexops.server")

app = FastAPI(title="NexOps MCP")

# Add CORS middleware to prevent 403/Origin issues
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def health_check():
    return {"status": "ok", "service": "NexOps MCP", "version": "0.1.0"}

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
                request_id = str(uuid.uuid4())[:8]
                logger.info(f"Received intent: {msg.get('prompt')} (ID: {request_id})")
                
                # Transform to internal MCPRequest format
                internal_msg = {
                    "request_id": request_id,
                    "action": "generate",
                    "payload": {
                        "user_request": msg.get("prompt"),
                        "history": msg.get("history", [])
                    },
                    "context": {"security_level": "high"}
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
