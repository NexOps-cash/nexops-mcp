# Use a single base image that has both Python and Node.js
FROM nikolaik/python-nodejs:python3.11-nodejs22

WORKDIR /app

# Install Node deps first (cashc at node_modules/.bin — must match compiler.get_cashc_path)
COPY package.json package-lock.json ./
RUN npm ci

# Install Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the source
COPY . .

CMD ["sh", "-c", "uvicorn src.server:app --host 0.0.0.0 --port $PORT"]
