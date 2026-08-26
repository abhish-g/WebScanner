FROM python:3.11-slim

WORKDIR /app

# System dependencies required by some ML packages
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Make application modules available
ENV PYTHONPATH=/app

# Render provides the PORT environment variable
ENV PORT=10000

# Start Flask application with Gunicorn
CMD ["sh", "-c", "gunicorn --bind 0.0.0.0:${PORT} ui.app:app"]