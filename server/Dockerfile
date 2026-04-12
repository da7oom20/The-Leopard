FROM node:20-slim AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev

FROM node:20-slim
WORKDIR /app
RUN apt-get update && apt-get install -y netcat-openbsd && rm -rf /var/lib/apt/lists/*
RUN groupadd -r appuser && useradd -r -g appuser appuser
COPY --from=builder /app/node_modules ./node_modules
COPY . .
RUN chown -R appuser:appuser /app
USER appuser
EXPOSE 4000
CMD ["node", "index.js"]
