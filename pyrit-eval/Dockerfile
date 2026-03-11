FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir pyrit==0.11.0 httpx==0.28.1

COPY run_pyrit.py /usr/local/bin/run_pyrit.py

ENTRYPOINT ["python", "/usr/local/bin/run_pyrit.py"]
