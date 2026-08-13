# ForenSync - Containerized Digital Forensics Platform
FROM python:3.9-slim

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DEBIAN_FRONTEND=noninteractive

# Set working directory
WORKDIR /app

# Install system dependencies & common Linux forensic utilities
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    python3-dev \
    libmagic1 \
    foremost \
    scalpel \
    testdisk \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY . .

# Create persistent storage directories
RUN mkdir -p evidence reports instance

# Expose Flask web server port
EXPOSE 5000

# Start ForenSync platform via start.py
CMD ["python", "start.py"]
