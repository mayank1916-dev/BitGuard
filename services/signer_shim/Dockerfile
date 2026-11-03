FROM python:3.12-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

COPY backend/requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt pydantic-settings

COPY . /app

EXPOSE 8001

CMD ["uvicorn", "services.signer_shim.main:app", "--host", "0.0.0.0", "--port", "8001"]
