# NexOps MCP

The Model Context Protocol (MCP) server for NexOps. This server acts as the intelligence layer, moving AI reasoning out of the IDE.

## Features (Phase 1)
- **Architecture**: Python (FastAPI) + WebSockets.
- **Protocol**: JSON-based request/response over WebSockets.
- **Capability**: Phase 1 Skeleton Generation (Stub).

## Getting Started

### Prerequisites
- Python 3.11++

### Installation
1. Install dependencies:
   ```bash
   pip install -e .[test]
   ```
   Or using a virtual environment (recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -e .
   ```

2. Create a `.env` file (see provided `.env` template).

### Running the Server
```bash
uvicorn src.server:app --reload --port 3000
```

### Testing
```bash
pytest
```
