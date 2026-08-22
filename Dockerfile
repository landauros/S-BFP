FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONUTF8=1 \
    S_BFP_HOST=0.0.0.0 \
    S_BFP_PORT=5001 \
    S_BFP_OPEN_BROWSER=0 \
    S_BFP_DATA_DIR=/data

WORKDIR /artifact

COPY requirements.txt ./
RUN python -m pip install --no-cache-dir -r requirements.txt

COPY . .
RUN mkdir -p /data

EXPOSE 5001
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5001/', timeout=2)" || exit 1

CMD ["python", "app.py"]

