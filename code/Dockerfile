FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

RUN apt-get update && apt-get install -y --no-install-recommends \
    p7zip-full \
    unar \
    ncompress \
    tesseract-ocr \
    tesseract-ocr-deu \
    tesseract-ocr-fra \
    tesseract-ocr-ita \
    libgl1 \
    libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt requirements.lock ./
RUN pip install --no-cache-dir -r requirements.lock && \
    python -c "from rapidocr import RapidOCR; RapidOCR()"

COPY machina_deid ./machina_deid
COPY pyproject.toml ./

ENTRYPOINT ["python", "-m", "machina_deid"]
CMD ["--help"]
