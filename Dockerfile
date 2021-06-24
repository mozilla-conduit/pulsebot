FROM python:2.7

ENV PYTHONPATH /app
ENV PORT 8000

RUN groupadd --gid 10001 app && \
    useradd -g app --uid 10001 --shell /usr/sbin/nologin --create-home --home-dir /app app

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache -r requirements.txt

COPY . /app

RUN pip install -e .

RUN chown -R app:app /app

RUN python -m pulsebot.config > pulsebot.cfg

USER app
ENTRYPOINT ["python"]
CMD ["-m pulsebot"]