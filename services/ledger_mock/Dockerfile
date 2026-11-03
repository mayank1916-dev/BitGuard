FROM python:3.12-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

COPY backend/requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt pydantic-settings

COPY . /app

EXPOSE 8002

CMD ["uvicorn", "services.ledger_mock.main:app", "--host", "0.0.0.0", "--port", "8002"]
