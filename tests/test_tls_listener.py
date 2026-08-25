"""The service must actually serve TLS, not merely be configured for it.

Traffic to this service crosses the cluster network carrying bearer tokens in
the Authorization header. Asserting that settings map to uvicorn flags proves
nothing about the wire, so these tests stand the real application up on a real
socket and connect to it.
"""

import contextlib
import datetime
import socket
import ssl
import threading
import time

import httpx
import pytest
import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app.config import Settings
from app.serve import uvicorn_options

pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")


def issue_cert(tmp_path, common_name: str, prefix: str):
    """Write a self-signed cert and key, returning their paths."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(hours=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False
        )
        .sign(key, hashes.SHA256())
    )
    cert_path = tmp_path / f"{prefix}.crt"
    key_path = tmp_path / f"{prefix}.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


def free_port() -> int:
    with contextlib.closing(socket.socket()) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@contextlib.contextmanager
def serving(settings: Settings):
    """Run the real app under uvicorn with this configuration."""
    options = uvicorn_options(settings)
    options["host"] = "127.0.0.1"
    options["log_level"] = "warning"
    server = uvicorn.Server(uvicorn.Config("app.main:app", **options))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 20
        while not server.started and time.monotonic() < deadline:
            if not thread.is_alive():
                raise RuntimeError("server thread died during startup")
            time.sleep(0.05)
        if not server.started:
            raise RuntimeError("server did not start in time")
        yield options["port"]
    finally:
        server.should_exit = True
        thread.join(timeout=20)


def settings_for(tmp_path, **overrides) -> Settings:
    return Settings(
        internal_token_public_key="-----BEGIN PUBLIC KEY-----\nstub\n-----END PUBLIC KEY-----\n",
        database_url="sqlite+pysqlite:///:memory:",
        listen_port=free_port(),
        _env_file=None,
        **overrides,
    )


def test_the_listener_serves_tls_when_configured(tmp_path):
    cert, key = issue_cert(tmp_path, "localhost", "server")
    settings = settings_for(tmp_path, tls_cert_file=str(cert), tls_key_file=str(key))

    with serving(settings) as port:
        response = httpx.get(f"https://localhost:{port}/healthz", verify=str(cert))

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_plaintext_is_refused_once_tls_is_on(tmp_path):
    """The point of the control: an unencrypted request must not be served."""
    cert, key = issue_cert(tmp_path, "localhost", "server")
    settings = settings_for(tmp_path, tls_cert_file=str(cert), tls_key_file=str(key))

    with serving(settings) as port:
        with pytest.raises(httpx.HTTPError):
            httpx.get(f"http://localhost:{port}/healthz", timeout=5)


def test_an_untrusted_server_certificate_is_refused(tmp_path):
    """A caller that verifies must reject a certificate it does not trust."""
    cert, key = issue_cert(tmp_path, "localhost", "server")
    other_cert, _ = issue_cert(tmp_path, "localhost", "unrelated")
    settings = settings_for(tmp_path, tls_cert_file=str(cert), tls_key_file=str(key))

    with serving(settings) as port:
        with pytest.raises(httpx.HTTPError):
            httpx.get(f"https://localhost:{port}/healthz", verify=str(other_cert))


def test_mutual_tls_refuses_a_caller_with_no_certificate(tmp_path):
    cert, key = issue_cert(tmp_path, "localhost", "server")
    client_ca, _ = issue_cert(tmp_path, "halden-identity", "clientca")
    settings = settings_for(
        tmp_path,
        tls_cert_file=str(cert),
        tls_key_file=str(key),
        tls_client_ca_file=str(client_ca),
    )

    with serving(settings) as port:
        with pytest.raises(httpx.HTTPError):
            httpx.get(f"https://localhost:{port}/healthz", verify=str(cert), timeout=5)


def test_the_listener_stays_plaintext_when_no_certificate_is_set(tmp_path):
    """Deployable before certificates exist; nothing changes until they are."""
    settings = settings_for(tmp_path)

    with serving(settings) as port:
        response = httpx.get(f"http://localhost:{port}/healthz")

    assert response.status_code == 200


def test_mutual_tls_asks_for_a_certificate_rather_than_hoping(tmp_path):
    cert, key = issue_cert(tmp_path, "localhost", "server")
    client_ca, _ = issue_cert(tmp_path, "halden-identity", "clientca")
    settings = settings_for(
        tmp_path,
        tls_cert_file=str(cert),
        tls_key_file=str(key),
        tls_client_ca_file=str(client_ca),
    )

    options = uvicorn_options(settings)

    assert options["ssl_cert_reqs"] == ssl.CERT_REQUIRED
