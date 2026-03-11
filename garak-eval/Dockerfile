FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PIP_NO_CACHE_DIR=1
ENV OLLAMA_BASE_URL=http://host.docker.internal:11434

RUN pip install --no-cache-dir --index-url https://download.pytorch.org/whl/cpu torch==2.10.0
RUN pip install --no-cache-dir garak==0.14.0

WORKDIR /workspace

COPY run_garak.py /usr/local/bin/run_garak.py

ENTRYPOINT ["python", "/usr/local/bin/run_garak.py"]
