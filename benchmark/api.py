import sys
import io
import os
import json
import asyncio
import yaml
from fastapi import FastAPI, UploadFile, File, WebSocket, BackgroundTasks, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import List, Optional
from pathlib import Path

from benchmark.runner import BenchmarkRunner

app = FastAPI(title="NexOps Benchmark API")

# Enable CORS for frontend interaction
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

RESULTS_DIR = Path("benchmark/results")
SUITES_DIR = Path("benchmark/suites")

class BenchmarkRequest(BaseModel):
    yaml_content: str
    tags: Optional[List[str]] = None
    model: Optional[str] = None

active_websockets: List[WebSocket] = []

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    active_websockets.append(websocket)
    try:
        while True:
            await websocket.receive_text()
    except:
        active_websockets.remove(websocket)

async def broadcast_progress(data: dict):
    for ws in active_websockets:
        try:
            await ws.send_json(data)
        except:
            pass

@app.post("/run")
async def run_benchmark(request: BenchmarkRequest, background_tasks: BackgroundTasks):
    # Save temporary suite
    temp_suite_path = SUITES_DIR / f"temp_{os.urandom(4).hex()}.yaml"
    with open(temp_suite_path, "w", encoding="utf-8") as f:
        f.write(request.yaml_content)
    
    background_tasks.add_task(execute_benchmark, str(temp_suite_path), request.tags, request.model)
    return {"status": "started", "suite": temp_suite_path.name}

async def execute_benchmark(yaml_path: str, tags: List[str], model: str):
    try:
        runner = BenchmarkRunner(yaml_path, tags=tags)
        runner.load_suite()
        
        async def on_progress(data: dict):
            await broadcast_progress(data)
            
        await runner.run_all(model_override=model, on_progress=on_progress)
    except Exception as e:
        await broadcast_progress({"type": "error", "message": str(e)})
    finally:
        if "temp_" in yaml_path:
            try:
                os.remove(yaml_path)
            except:
                pass

@app.get("/results")
async def list_results():
    results = []
    for f in RESULTS_DIR.glob("*.json"):
        try:
            with open(f, "r", encoding="utf-8") as r:
                data = json.load(r)
                
                score = data.get("avg_final_score")
                if score is None:
                    # Legacy fallback
                    case_results = data.get("results", [])
                    if case_results:
                        score = sum(r.get("final_score", 0) for r in case_results) / len(case_results)
                    else:
                        score = 0
                
                results.append({
                    "id": data.get("run_id"),
                    "suite": f.name,
                    "timestamp": data.get("start_time"),
                    "score": score
                })
        except (json.JSONDecodeError, FileNotFoundError):
            continue
    return sorted(results, key=lambda x: x.get("timestamp", ""), reverse=True)

@app.get("/results/{run_id}")
async def get_result(run_id: str):
    # Search for file starting with run_id
    for f in RESULTS_DIR.glob(f"{run_id}*.json"):
        try:
            with open(f, "r", encoding="utf-8") as r:
                data = json.load(r)
                if "avg_final_score" not in data:
                    case_results = data.get("results", [])
                    if case_results:
                        data["avg_final_score"] = sum(r.get("final_score", 0) for r in case_results) / len(case_results)
                    else:
                        data["avg_final_score"] = 0.0
                return data
        except (json.JSONDecodeError, FileNotFoundError):
            continue
    raise HTTPException(status_code=404, detail="Result not found or invalid")

# Serve UI if exists
UI_DIR = Path("benchmark/ui")
if UI_DIR.exists():
    app.mount("/ui", StaticFiles(directory=str(UI_DIR), html=True), name="ui")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
