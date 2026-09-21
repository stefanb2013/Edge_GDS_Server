FROM python:3.12-slim

WORKDIR /app

# Install dependencies first so this layer is cached across code changes.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY gds/ ./gds/
COPY web/ ./web/
COPY nodesets/ ./nodesets/
COPY main.py ./

RUN useradd --create-home --uid 1000 gds \
    && mkdir -p /data \
    && chown -R gds:gds /app /data
USER gds

ENV GDS_DATA_DIR=/data \
    PYTHONUNBUFFERED=1

VOLUME ["/data"]

# OPC UA GDS endpoint and web admin UI, respectively (override via
# GDS_OPCUA_PORT/GDS_HTTP_PORT -- update the EXPOSE'd ports to match if you do).
EXPOSE 4840 8443

CMD ["python", "main.py"]
