FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 LINTEL_DATA=/data TZ=Pacific/Auckland
RUN apt-get update && apt-get install -y --no-install-recommends tzdata && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY lintel_server ./lintel_server
RUN useradd -r -u 1000 lintel && mkdir -p /data && chown lintel /data
USER lintel
VOLUME /data
EXPOSE 8080/tcp 47800/udp
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request,sys; urllib.request.urlopen(\"http://127.0.0.1:8080/api/openapi.json\")" || exit 1
CMD ["python", "-m", "lintel_server", "serve"]
