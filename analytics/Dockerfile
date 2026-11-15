FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN apt-get update && apt-get install -y --no-install-recommends default-jre-headless procps \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /srv
COPY analytics/requirements.txt analytics/requirements.txt
RUN pip install --no-cache-dir -r analytics/requirements.txt
COPY analytics ./analytics
COPY tests/test_analytics.py ./tests/test_analytics.py
ENTRYPOINT ["python", "-I", "analytics/pipeline.py"]
