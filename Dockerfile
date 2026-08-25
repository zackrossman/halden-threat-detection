FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /srv

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY scripts ./scripts

RUN useradd --system --uid 10001 --create-home halden \
    && mkdir -p /var/lib/halden/artifacts \
    && chown -R halden:halden /srv /var/lib/halden

USER halden

# 8000 serves plaintext, 8443 serves TLS. Which one is live depends on whether
# HALDEN_TLS_CERT_FILE and HALDEN_TLS_KEY_FILE are set, so both are declared.
EXPOSE 8000 8443

# The listener is assembled from settings rather than from flags here, because
# the TLS arguments are conditional and a shell should not be deciding them.
CMD ["python", "-m", "app.serve"]
