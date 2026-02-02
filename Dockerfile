FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .

RUN apt-get update && apt-get install -y --no-install-recommends \
        python3-tk \
        x11-apps \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir -r requirements.txt

RUN mkdir -p secure_vault certs keystores trusted_certs

COPY securefile.py .

CMD ["python", "securefile.py"]
