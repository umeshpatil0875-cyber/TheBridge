# FIX 6: a non-root user, and a HEALTHCHECK.
FROM python:3.13-slim
WORKDIR /app
COPY . .
RUN pip install --no-cache-dir -r requirements.txt && useradd --uid 10001 --create-home app
USER 10001
HEALTHCHECK CMD python -c "import urllib.request as u; u.urlopen('http://127.0.0.1:5000/user')" || exit 1
CMD ["python", "app.py"]
