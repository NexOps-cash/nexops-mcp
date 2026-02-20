import asyncio
import websockets
import json
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("test_ws")

async def test_websocket():
    uri = "ws://localhost:3005/ws/generate"
    async with websockets.connect(uri) as websocket:
        logger.info("Connected to NexOps WebSocket")

        # 1. Send Intent
        intent_msg = {
            "type": "intent",
            "prompt": "Create a simple P2PKH contract with a timeout reclaiming to owner",
            "history": []
        }
        
        logger.info(f"Sending intent: {intent_msg['prompt']}")
        await websocket.send(json.dumps(intent_msg))

        # 2. Receive Updates and Result
        while True:
            try:
                response = await asyncio.wait_for(websocket.recv(), timeout=60)
                data = json.loads(response)
                
                msg_type = data.get("type")
                
                if msg_type == "update":
                    logger.info(f"[UPDATE] Stage: {data.get('stage')} | {data.get('message')}")
                elif msg_type == "success":
                    logger.info("[SUCCESS] Synthesis complete!")
                    logger.info(f"Contract Name: {data['data'].get('contract_name')}")
                    # logger.info(f"Code Preview: {data['data'].get('code')[:100]}...")
                    break
                elif msg_type == "error":
                    logger.error(f"[ERROR] {data.get('error')}")
                    break
                else:
                    logger.info(f"[MSG] {data}")
            except asyncio.TimeoutError:
                logger.error("Timed out waiting for response")
                break

if __name__ == "__main__":
    # Note: server.py must be running for this test to work.
    # We will attempt to run it in a subprocess if possible, or just ask user.
    asyncio.run(test_websocket())
