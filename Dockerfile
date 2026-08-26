FROM python:3.13-slim

# Hugging Face Spaces runs containers as a non-root user (uid 1000).
# Creating it explicitly avoids permission errors on the model cache.
RUN useradd -m -u 1000 user

ENV HOME=/home/user \
    PATH=/home/user/.local/bin:$PATH \
    PYTHONPATH=/home/user/app \
    PYTHONUNBUFFERED=1 \
    HF_HOME=/home/user/.cache/huggingface

USER user
WORKDIR /home/user/app

# Install dependencies first so this layer caches across code changes
COPY --chown=user requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Bake the embedding model into the image. Without this it downloads
# ~90MB on first request, which on a cold start pushes past gunicorn's
# timeout and puts the worker into a restart loop.
RUN python -c "from sentence_transformers import SentenceTransformer; \
    SentenceTransformer('all-MiniLM-L6-v2')"

COPY --chown=user . .

# HF Spaces expects 7860. Render injects its own PORT, which this
# respects, so the same image works on both.
ENV PORT=7860
EXPOSE 7860

# --workers 1 : each worker holds its own copy of the model and FAISS
#               index. Two workers on a small box means OOM.
# --threads 4 : concurrency without duplicating memory. Requests are
#               I/O-bound waiting on the LLM API, so threads fit well.
# --timeout 180 : the first request loads the model and builds the
#               index. The 30s default kills the worker mid-boot.
CMD ["sh", "-c", "gunicorn --bind 0.0.0.0:${PORT} --workers 1 --threads 4 --timeout 180 --access-logfile - ui.app:app"]