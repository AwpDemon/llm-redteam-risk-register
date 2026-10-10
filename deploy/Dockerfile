# Container for running the harness against any OpenAI-compatible endpoint (not a public demo:
# the target app is an attack surface by design and should never be exposed to the internet).
FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
COPY suite ./suite
COPY register ./register
COPY data ./data
RUN pip install --no-cache-dir .
ENV REDTEAM_BASE_URL=http://ollama:11434/v1 \
    REDTEAM_MODEL=qwen2.5:7b-instruct
ENTRYPOINT ["redteam"]
CMD ["--help"]
