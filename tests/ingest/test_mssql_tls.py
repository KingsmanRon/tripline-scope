"""SQL Server TLS: host-name verification and configuration rules (no server needed)."""

import datetime as dt
import ipaddress

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from OpenSSL import crypto

from tripline_scope.core.errors import ConfigError
from tripline_scope.ingest.mssql import _cert_matches_host, tls_kwargs


def _cert(cn: str, dns=(), ips=()):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    b = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
         .serial_number(1).not_valid_before(dt.datetime(2026, 1, 1)).not_valid_after(dt.datetime(2027, 1, 1)))
    alt = [x509.DNSName(d) for d in dns] + [x509.IPAddress(ipaddress.ip_address(i)) for i in ips]
    if alt:
        b = b.add_extension(x509.SubjectAlternativeName(alt), critical=False)
    return crypto.X509.from_cryptography(b.sign(key, hashes.SHA256()))


def test_dns_ip_and_wildcard_san():
    c = _cert("ignored-cn", dns=["sqlrestore.lab.local", "*.hosp.local"], ips=["10.20.0.15"])
    assert _cert_matches_host(c, b"sqlrestore.lab.local")
    assert _cert_matches_host(c, b"SQLRESTORE.LAB.LOCAL")
    assert _cert_matches_host(c, b"db1.hosp.local")
    assert not _cert_matches_host(c, b"a.db1.hosp.local")  # wildcard covers one label only
    assert _cert_matches_host(c, b"10.20.0.15")
    assert not _cert_matches_host(c, b"10.20.0.16")
    assert not _cert_matches_host(c, b"ignored-cn")  # CN is not used when SANs are present


def test_cn_only_when_no_san():
    c = _cert("legacy-sql")
    assert _cert_matches_host(c, b"legacy-sql")
    assert not _cert_matches_host(c, b"other")


def test_tls_options():
    assert tls_kwargs(False, None, False) == {}
    with pytest.raises(ConfigError):
        tls_kwargs(True, None, False)
    opts = tls_kwargs(True, "/etc/ca.pem", False)
    assert opts == {"cafile": "/etc/ca.pem", "validate_host": True, "enc_login_only": False}
    assert tls_kwargs(True, "/etc/ca.pem", True)["validate_host"] is False


def test_config_refuses_encryption_without_ca(tmp_path):
    from tripline_scope.ingest.config import mssql_target

    class H:
        config = {"restore_targets": {"mssql": {"host": "sql", "port": 1433, "login": "restore", "encryption": True,
                                                "backup_transfer": "shared_path", "server_backup_dir": "/in",
                                                "host_backup_dir": str(tmp_path)}}}

    with pytest.raises(ConfigError, match="tls_cafile"):
        mssql_target(H())
