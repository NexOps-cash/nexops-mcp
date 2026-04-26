# Use a single base image that has both Python and Node.js (Node 20 — align with package.json engines)
FROM nikolaik/python-nodejs:python3.11-nodejs20

WORKDIR /app

# Install Node deps first (cashc at node_modules/.bin — must match compiler.get_cashc_path)
COPY package.json package-lock.json ./
# Fail the image build if Node is not 20.x or cashc is not at node_modules/.bin (compiler.get_cashc_path)
RUN set -e; \
  node -e "if (!String(process.version).startsWith('v20.')) { console.error('FATAL: expected Node 20.x, got', process.version); process.exit(1) }"; \
  npm ci; \
  if [ ! -f node_modules/.bin/cashc ]; then \
    echo "FATAL: expected node_modules/.bin/cashc after npm ci (src/services/compiler.py get_cashc_path)" >&2; \
    exit 1; \
  fi

# Install Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the source
COPY . .

CMD ["sh", "-c", "uvicorn src.server:app --host 0.0.0.0 --port $PORT"]
