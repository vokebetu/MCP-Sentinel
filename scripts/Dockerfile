FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /srv
COPY scripts/requirements.txt scripts/requirements.txt
RUN pip install --no-cache-dir -r scripts/requirements.txt
COPY database ./database
COPY scripts ./scripts
COPY tests/fixtures ./tests/fixtures
RUN useradd --create-home --uid 10001 sentinel
USER sentinel
ENTRYPOINT ["python", "-I", "scripts/load_data.py"]
CMD ["seed"]
