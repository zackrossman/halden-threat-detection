"""Service entrypoint: builds the listener from configuration and runs it.

The Dockerfile used to hand uvicorn a fixed host and port on the command line.
Serving TLS needs the certificate paths, and whether to demand a client
certificate, to come from the same settings everything else reads — so the
listener is assembled here instead of in CMD, where a conditional flag would
have to be built by a shell.
"""

import logging
import ssl

import uvicorn

from app import audit
from app.config import Settings, get_settings


def uvicorn_options(settings: Settings) -> dict:
    """The uvicorn keyword arguments this configuration asks for.

    Separated from `run` so the mapping from settings to listener is testable
    without binding a socket.
    """
    options: dict = {
        "host": settings.listen_host,
        "port": settings.listen_port,
    }
    if not settings.tls_enabled:
        return options

    options["ssl_certfile"] = settings.tls_cert_file
    options["ssl_keyfile"] = settings.tls_key_file
    if settings.mutual_tls_enabled:
        # Refuse the handshake unless the caller presents a certificate this CA
        # signed. CERT_OPTIONAL would accept a caller that offers none, which
        # is the same as not asking.
        options["ssl_ca_certs"] = settings.tls_client_ca_file
        options["ssl_cert_reqs"] = ssl.CERT_REQUIRED
    return options


def run() -> None:
    audit.configure_audit_logging()
    settings = get_settings()
    options = uvicorn_options(settings)

    audit.record(
        "listener_configured",
        level=logging.INFO,
        port=settings.listen_port,
        tls=settings.tls_enabled,
        mutual_tls=settings.mutual_tls_enabled,
    )
    uvicorn.run("app.main:app", **options)


if __name__ == "__main__":
    run()
