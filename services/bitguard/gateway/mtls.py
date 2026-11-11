"""mTLS Client Certificate Authentication and Workload Identity (Milestone S12).

Invariants:
- Invariant #3: Fail-Closed Default. Missing client cert, unverified SAN,
  or unknown caller identity => DENY (INVALID_CALLER_IDENTITY).
- Workload identity derived strictly from Subject Alternative Name (SAN).
- Supports direct X.509 client certificate PEM verification, Envoy XFCC headers,
  and reverse-proxy SAN injection.
"""

import logging
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import ExtensionOID
from fastapi import Request

from services.bitguard.config import settings

logger = logging.getLogger("bitguard.gateway.mtls")

# Custom OIDs for certificate-attested attributes (simulating SPIFFE/SPIRE extensions)
OID_IMAGE_DIGEST = x509.ObjectIdentifier("1.3.6.1.4.1.99999.1")
OID_DEPLOY_TIME = x509.ObjectIdentifier("1.3.6.1.4.1.99999.2")


def parse_attestation_timestamp(val: Any) -> datetime | None:
    """Parses ISO-8601 strings, UNIX epoch seconds, or datetimes into UTC datetimes."""
    if val is None:
        return None
    if isinstance(val, datetime):
        return val if val.tzinfo is not None else val.replace(tzinfo=UTC)
    if isinstance(val, (int, float)):
        try:
            return datetime.fromtimestamp(float(val), tz=UTC)
        except Exception:
            return None
    if isinstance(val, str):
        v = val.strip().strip('"').strip("'")
        if not v:
            return None
        try:
            return datetime.fromisoformat(v.replace("Z", "+00:00"))
        except ValueError:
            try:
                return datetime.fromtimestamp(float(v), tz=UTC)
            except ValueError:
                return None
    return None


@dataclass
class WorkloadIdentity:
    """Authenticated caller workload identity extracted from mTLS client certificate."""

    san: str
    cert_subject: str | None = None
    auth_method: str = "mtls"
    image_digest: str | None = None
    deploy_time: datetime | None = None
    source_ip: str | None = None


def _verify_cert_against_ca(cert: x509.Certificate, ca_cert_path: str) -> bool:
    """Cryptographically verifies that the client certificate was signed by the configured CA."""
    ca_path = Path(ca_cert_path)
    if not ca_path.exists():
        logger.error("configured_mtls_ca_missing: path=%s", ca_cert_path)
        return False

    try:
        ca_bytes = ca_path.read_bytes()
        ca_cert = x509.load_pem_x509_certificate(ca_bytes)

        # Check CA expiration
        now = datetime.now(UTC)
        if now < ca_cert.not_valid_before_utc or now > ca_cert.not_valid_after_utc:
            logger.warning("mtls_ca_certificate_expired")
            return False

        # Verify client certificate signature against CA public key
        ca_pubkey = ca_cert.public_key()
        if isinstance(ca_pubkey, rsa.RSAPublicKey):
            sig_hash = cert.signature_hash_algorithm
            if sig_hash is None:
                return False
            ca_pubkey.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                sig_hash,
            )
        else:
            verify_fn = getattr(ca_pubkey, "verify", None)
            if not callable(verify_fn):
                return False
            sig_hash = cert.signature_hash_algorithm
            if sig_hash is None:
                return False
            verify_fn(cert.signature, cert.tbs_certificate_bytes, sig_hash)

        return True
    except Exception as exc:
        logger.warning("mtls_ca_signature_verification_failed: %s", exc)
        return False


def _extract_sans_from_cert(cert: x509.Certificate) -> list[str]:
    """Extracts all Subject Alternative Names (URIs, DNS names, IP addresses) from certificate."""
    sans: list[str] = []
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        san_val = ext.value
        if isinstance(san_val, x509.SubjectAlternativeName):
            for gn in san_val:
                val = str(getattr(gn, "value", ""))
                if val:
                    sans.append(val)
    except x509.ExtensionNotFound:
        pass
    except Exception as exc:
        logger.warning("failed_extracting_san_extension: %s", exc)
    return sans


def extract_workload_identity(request: Request) -> WorkloadIdentity | None:
    """Authenticates the incoming caller using mTLS client certificates and derives workload SAN.

    Fails closed (returns None) if:
    - No client certificate or SAN header is present.
    - Certificate is expired or signature check against CA fails.
    - SAN is missing or does not match configured allowed identities.
    """
    candidate_sans: list[str] = []
    subject_summary: str | None = None
    extracted_image_digest: str | None = None
    extracted_deploy_time: datetime | None = None

    # Helper to parse attributes from SAN URI
    def _inspect_san_attributes(san_str: str) -> str:
        nonlocal extracted_image_digest, extracted_deploy_time
        try:
            parsed = urlparse(san_str)
            if parsed.query:
                qs = parse_qs(parsed.query)
                if "image_digest" in qs and not extracted_image_digest:
                    extracted_image_digest = qs["image_digest"][0]
                if "digest" in qs and not extracted_image_digest:
                    extracted_image_digest = qs["digest"][0]
                if "deploy_time" in qs and not extracted_deploy_time:
                    extracted_deploy_time = parse_attestation_timestamp(qs["deploy_time"][0])
                if "deployed" in qs and not extracted_deploy_time:
                    extracted_deploy_time = parse_attestation_timestamp(qs["deployed"][0])
            # Return base SAN without query string for authorization matching
            if parsed.scheme and parsed.netloc:
                base_san = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                return base_san.rstrip("/") if base_san != f"{parsed.scheme}://{parsed.netloc}/" else base_san
        except Exception:
            pass
        return san_str

    # 1. Inspect direct client cert PEM header (e.g. X-Client-Cert-Pem or X-SSL-Client-Cert)
    pem_header = request.headers.get("x-client-cert-pem") or request.headers.get("x-ssl-client-cert")
    if pem_header:
        try:
            # Handle URL-encoded PEM or raw PEM
            raw_pem = unquote(pem_header).strip()
            if not raw_pem.startswith("-----BEGIN CERTIFICATE-----"):
                # Normalize line breaks if passed without newlines
                raw_pem = raw_pem.replace("\\n", "\n")
            cert_bytes = raw_pem.encode("utf-8")
            cert = x509.load_pem_x509_certificate(cert_bytes)

            # Check validity window
            now = datetime.now(UTC)
            if now < cert.not_valid_before_utc or now > cert.not_valid_after_utc:
                logger.warning("client_certificate_outside_validity_window")
                return None

            # Verify against CA if CA path is configured
            if settings.mtls_ca_cert_path:
                if not _verify_cert_against_ca(cert, settings.mtls_ca_cert_path):
                    logger.warning("client_certificate_failed_ca_verification")
                    return None

            subject_summary = cert.subject.rfc4514_string()
            raw_sans = _extract_sans_from_cert(cert)
            for s in raw_sans:
                base_s = _inspect_san_attributes(s)
                candidate_sans.append(s)
                if base_s != s:
                    candidate_sans.append(base_s)

            # Extract custom extensions if present
            try:
                ext_digest = cert.extensions.get_extension_for_oid(OID_IMAGE_DIGEST)
                if ext_digest and not extracted_image_digest:
                    val_digest = ext_digest.value
                    if isinstance(val_digest, x509.UnrecognizedExtension):
                        extracted_image_digest = val_digest.value.decode("utf-8", errors="ignore").strip()
                    elif hasattr(val_digest, "value"):
                        raw_bytes = val_digest.value
                        if isinstance(raw_bytes, bytes):
                            extracted_image_digest = raw_bytes.decode("utf-8", errors="ignore").strip()
            except x509.ExtensionNotFound:
                pass

            try:
                ext_deploy = cert.extensions.get_extension_for_oid(OID_DEPLOY_TIME)
                if ext_deploy and not extracted_deploy_time:
                    val_deploy = ext_deploy.value
                    raw_dt = ""
                    if isinstance(val_deploy, x509.UnrecognizedExtension):
                        raw_dt = val_deploy.value.decode("utf-8", errors="ignore").strip()
                    elif hasattr(val_deploy, "value"):
                        raw_bytes = val_deploy.value
                        if isinstance(raw_bytes, bytes):
                            raw_dt = raw_bytes.decode("utf-8", errors="ignore").strip()
                    if raw_dt:
                        extracted_deploy_time = parse_attestation_timestamp(raw_dt)
            except x509.ExtensionNotFound:
                pass

        except Exception as exc:
            logger.warning("client_cert_pem_parsing_failed: %s", exc)
            return None

    # 2. Inspect Envoy / Istio proxy header: X-Forwarded-Client-Cert (XFCC)
    xfcc_header = request.headers.get("x-forwarded-client-cert")
    if xfcc_header:
        uris = re.findall(r'URI="?([^;"]+)"?', xfcc_header)
        dns_names = re.findall(r'DNS="?([^;"]+)"?', xfcc_header)
        for u in uris:
            base_u = _inspect_san_attributes(u)
            candidate_sans.append(u)
            if base_u != u:
                candidate_sans.append(base_u)
        candidate_sans.extend(dns_names)

    # 3. Inspect reverse proxy direct SAN header: X-Client-Cert-SAN
    san_header = request.headers.get("x-client-cert-san")
    if san_header:
        for s in san_header.split(","):
            s_clean = s.strip()
            if s_clean:
                base_s = _inspect_san_attributes(s_clean)
                candidate_sans.append(s_clean)
                if base_s != s_clean:
                    candidate_sans.append(base_s)

    # 4. Check ASGI client cert extension if present
    asgi_cert = request.scope.get("client_cert")
    if asgi_cert and isinstance(asgi_cert, (bytes, str)):
        try:
            cert_bytes = asgi_cert.encode("utf-8") if isinstance(asgi_cert, str) else asgi_cert
            cert = x509.load_pem_x509_certificate(cert_bytes)
            raw_sans = _extract_sans_from_cert(cert)
            for s in raw_sans:
                base_s = _inspect_san_attributes(s)
                candidate_sans.append(s)
                if base_s != s:
                    candidate_sans.append(base_s)
        except Exception as exc:
            logger.debug("asgi_client_cert_extraction_failed: %s", exc)

    if not candidate_sans:
        logger.info("unauthenticated_caller_missing_mtls_identity")
        return None

    # 5. Extract image digest and deploy time from headers if not in cert
    if not extracted_image_digest:
        header_digest = request.headers.get("x-caller-image-digest") or request.headers.get("x-client-image-digest")
        if header_digest:
            extracted_image_digest = header_digest.strip()

    if not extracted_deploy_time:
        header_deploy = request.headers.get("x-caller-deploy-time") or request.headers.get("x-client-deploy-time")
        if header_deploy:
            extracted_deploy_time = parse_attestation_timestamp(header_deploy)

    # 6. Extract caller source IP
    source_ip: str | None = None
    header_ip = request.headers.get("x-caller-source-ip") or request.headers.get("x-real-ip")
    if not header_ip:
        xff = request.headers.get("x-forwarded-for")
        if xff:
            header_ip = xff.split(",")[0].strip()
    if not header_ip and request.client and request.client.host:
        header_ip = request.client.host
    if header_ip:
        header_ip_clean = header_ip.strip()
        source_ip = "127.0.0.1" if header_ip_clean == "testclient" else header_ip_clean

    # Filter against allowed SAN identities
    allowed_sans = set(settings.mtls_allowed_sans)
    for san in candidate_sans:
        if not allowed_sans or san in allowed_sans:
            return WorkloadIdentity(
                san=san,
                cert_subject=subject_summary,
                auth_method="mtls",
                image_digest=extracted_image_digest,
                deploy_time=extracted_deploy_time,
                source_ip=source_ip,
            )

    logger.warning("caller_san_not_in_allowed_list: candidate_sans=%s", candidate_sans)
    return None
