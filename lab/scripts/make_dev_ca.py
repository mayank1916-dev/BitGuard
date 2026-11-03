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
    client_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    client_name = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Exchange Custody Workload"),
        x509.NameAttribute(NameOID.COMMON_NAME, "custody.exchange.internal"),
    ])
    client_cert = (
        x509.CertificateBuilder()
        .subject_name(client_name)
        .issuer_name(ca_name)
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
            x509.SubjectAlternativeName([
                x509.UniformResourceIdentifier("spiffe://exchange.internal/workload/custody"),
                x509.DNSName("custody.exchange.internal"),
            ]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
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
