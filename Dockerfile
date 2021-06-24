FROM python:3.9

ENV PYTHONPATH /app
ENV PORT 8000

RUN groupadd --gid 10001 app && \
    useradd -g app --uid 10001 --shell /usr/sbin/nologin --create-home --home-dir /app app

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache -r requirements.txt

COPY . /app
RUN chown -R app:app /app

USER app
ENTRYPOINT ["python"]
CMD ["-m", "pulsebot"]