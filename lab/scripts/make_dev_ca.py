"""Development Certificate Authority (CA) & Client Certificate Generator (Milestone S12).

Generates dev Root CA and mTLS client certificates with SPIFFE SAN identities
for local testing and custody client authentication.

Generated artifacts:
- lab/certs/ca.key & ca.crt: BitGuard Dev Root CA
- lab/certs/client.key & client.crt: Legitimate custody client with SAN:
    - URI: spiffe://exchange.internal/workload/custody
    - DNS: custody.exchange.internal
- lab/certs/rogue_ca.key & rogue_ca.crt: Rogue untrusted CA
- lab/certs/rogue_client.key & rogue_client.crt: Rogue client certificate (for negative tests)
"""

import argparse
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

# Custom OIDs for certificate-attested workload attributes (simulating SPIFFE/SPIRE extensions)
OID_IMAGE_DIGEST = x509.ObjectIdentifier("1.3.6.1.4.1.99999.1")
OID_DEPLOY_TIME = x509.ObjectIdentifier("1.3.6.1.4.1.99999.2")

DEFAULT_ATTESTED_IMAGE_DIGEST = "sha256:4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a"
DEFAULT_ATTESTED_DEPLOY_TIME = "2026-01-01T00:00:00Z"


def build_attested_client_cert(
    ca_cert: x509.Certificate,
    ca_key: rsa.RSAPrivateKey,
    common_name: str = "custody.exchange.internal",
    spiffe_id: str = "spiffe://exchange.internal/workload/custody",
    image_digest: str | None = DEFAULT_ATTESTED_IMAGE_DIGEST,
    deploy_time: str | None = DEFAULT_ATTESTED_DEPLOY_TIME,
    validity_days: int = 30,
) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    """Generates an attested client certificate with SPIFFE SANs and custom OID attributes."""
    client_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    client_name = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Exchange Custody Workload"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    now = datetime.now(UTC)
    expiry = now + timedelta(days=validity_days)

    san_entries: list[x509.GeneralName] = [
        x509.UniformResourceIdentifier(spiffe_id),
        x509.DNSName(common_name),
    ]

    # Embed SPIFFE SVID URI with query attributes
    if image_digest or deploy_time:
        query_parts = []
        if image_digest:
            query_parts.append(f"image_digest={image_digest}")
        if deploy_time:
            query_parts.append(f"deploy_time={deploy_time}")
        attested_uri = f"{spiffe_id}?{'&'.join(query_parts)}"
        san_entries.append(x509.UniformResourceIdentifier(attested_uri))

    builder = (
        x509.CertificateBuilder()
        .subject_name(client_name)
        .issuer_name(ca_cert.subject)
        .public_key(client_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(expiry)
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectAlternativeName(san_entries),
            critical=False,
        )
    )

    if image_digest:
        builder = builder.add_extension(
            x509.UnrecognizedExtension(OID_IMAGE_DIGEST, image_digest.encode("utf-8")),
            critical=False,
        )
    if deploy_time:
        builder = builder.add_extension(
            x509.UnrecognizedExtension(OID_DEPLOY_TIME, deploy_time.encode("utf-8")),
            critical=False,
        )

    cert = builder.sign(ca_key, hashes.SHA256())
    return client_key, cert


def generate_dev_pki(output_dir: Path) -> dict[str, str]:
    """Generates development CA and client certificates."""
    output_dir.mkdir(parents=True, exist_ok=True)
    now = datetime.now(UTC)
    expiry = now + timedelta(days=365)

    # -------------------------------------------------------------
    # 1. BitGuard Dev Root CA
    # -------------------------------------------------------------
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "BitGuard Lab Security"),
        x509.NameAttribute(NameOID.COMMON_NAME, "BitGuard Dev Root CA"),
    ])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(expiry)
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )

    ca_key_path = output_dir / "ca.key"
    ca_crt_path = output_dir / "ca.crt"
    ca_key_path.write_bytes(
        ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    ca_crt_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))

    # -------------------------------------------------------------
    # 2. Legitimate Custody Workload Client Certificate
    # -------------------------------------------------------------
    client_key, client_cert = build_attested_client_cert(
        ca_cert=ca_cert,
        ca_key=ca_key,
        common_name="custody.exchange.internal",
        spiffe_id="spiffe://exchange.internal/workload/custody",
    )

    client_key_path = output_dir / "client.key"
    client_crt_path = output_dir / "client.crt"
    client_key_path.write_bytes(
        client_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    client_crt_path.write_bytes(client_cert.public_bytes(serialization.Encoding.PEM))

    # -------------------------------------------------------------
    # 3. Untrusted Rogue CA and Client (for negative tests)
    # -------------------------------------------------------------
    rogue_ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rogue_ca_name = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Attacker Organization"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Rogue Untrusted CA"),
    ])
    rogue_ca_cert = (
        x509.CertificateBuilder()
        .subject_name(rogue_ca_name)
        .issuer_name(rogue_ca_name)
        .public_key(rogue_ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(expiry)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(rogue_ca_key, hashes.SHA256())
    )

    rogue_client_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rogue_client_name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "rogue-custody"),
    ])
    rogue_client_cert = (
        x509.CertificateBuilder()
        .subject_name(rogue_client_name)
        .issuer_name(rogue_ca_name)
        .public_key(rogue_client_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(expiry)
        .add_extension(
            x509.SubjectAlternativeName([
                x509.UniformResourceIdentifier("spiffe://exchange.internal/workload/custody"),
            ]),
            critical=False,
        )
        .sign(rogue_ca_key, hashes.SHA256())
    )

    (output_dir / "rogue_ca.crt").write_bytes(rogue_ca_cert.public_bytes(serialization.Encoding.PEM))
    (output_dir / "rogue_client.key").write_bytes(
        rogue_client_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    (output_dir / "rogue_client.crt").write_bytes(rogue_client_cert.public_bytes(serialization.Encoding.PEM))

    return {
        "ca_cert": str(ca_crt_path),
        "ca_key": str(ca_key_path),
        "client_cert": str(client_crt_path),
        "client_key": str(client_key_path),
        "rogue_cert": str(output_dir / "rogue_client.crt"),
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate Dev CA and mTLS client certificates")
    parser.add_argument(
        "--output-dir",
        default=str(Path(__file__).resolve().parent.parent / "certs"),
        help="Directory to store generated certificates",
    )
    args = parser.parse_args()
    paths = generate_dev_pki(Path(args.output_dir))
    print(f"Generated Dev PKI certificates in {args.output_dir}:")
    for k, v in paths.items():
        print(f"  {k}: {v}")
