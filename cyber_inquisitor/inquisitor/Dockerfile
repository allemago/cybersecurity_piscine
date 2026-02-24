FROM python:3.10-slim

WORKDIR /app

COPY src/ .
COPY tests/ .
COPY run.sh .
COPY pyproject.toml .

RUN pip install poetry

RUN poetry config virtualenvs.in-project true && \
    poetry install

RUN chmod +x run.sh

CMD [ "./run.sh" ]
