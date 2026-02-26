FROM python:3.10-slim

WORKDIR /app

COPY src/ src/
COPY entrypoint.sh .
COPY pyproject.toml .

RUN apt-get update && apt-get install -y \
    libpcap-dev \
    gcc && \
    rm -rf /var/lib/apt/lists/*

RUN pip install poetry

RUN poetry config virtualenvs.in-project true && \
    poetry install

RUN chmod +x entrypoint.sh

CMD [ "./entrypoint.sh" ]
