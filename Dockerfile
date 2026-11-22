# SentinelML: Production Container Definition
FROM python:3.11-slim

# Install system utilities (libpcap for live packet capture)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    tcpdump \
    iptables \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project source and pre-trained models
COPY . .

# Expose Web Dashboard & REST API port
EXPOSE 5000

ENV PORT=5000 \
    HOST=0.0.0.0 \
    PYTHONUNBUFFERED=1

# Healthcheck endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:5000/api/stats || exit 1

CMD ["python", "flask_app/app.py"]
