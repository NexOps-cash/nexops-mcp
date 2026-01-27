from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from .router import route_request
import uvicorn
import os
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("nexops.server")

app = FastAPI(title="NexOps MCP")

@app.get("/")
async def health_check():
    return {"status": "ok", "service": "NexOps MCP", "version": "0.1.0"}

@app.websocket("/mcp")
async def mcp_ws(ws: WebSocket):
    await ws.accept()
    logger.info("Client connected")
    
    try:
        while True:
            msg = await ws.receive_json()
            response = await route_request(msg)
            await ws.send_json(response)
    except WebSocketDisconnect:
        logger.info("Client disconnected")
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        # Try to send error if connection is still open
        try:
            await ws.send_json({
                "type": "error", 
                "error": {"code": "FATAL", "message": str(e)}
            })
        except:
            pass

if __name__ == "__main__":
    port = int(os.getenv("PORT", 3000))
    uvicorn.run("src.server:app", host="0.0.0.0", port=port, reload=True)
