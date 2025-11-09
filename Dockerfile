FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Ensure the data directory exists inside the container.
RUN mkdir -p /etc/data

COPY file_displayer ./file_displayer
COPY README.md ./

EXPOSE 8888

ENV CODE=""

CMD ["python", "-m", "file_displayer"]
