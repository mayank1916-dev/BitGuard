"""Abstract interface and exception definitions for blockchain raw transaction decoders."""

from abc import ABC, abstractmethod

from services.bitguard.models import DecodedTx


class DecodeError(Exception):
    """Raised when raw transaction bytes cannot be decoded, are malformed, or contain trailing garbage."""

    pass


class ChainDecoder(ABC):
    """Abstract interface defining transaction decoding strictly from raw bytes (Invariant #4)."""

    @abstractmethod
    def decode(self, raw_bytes: bytes | str) -> DecodedTx:
        """Decodes raw unsigned transaction bytes into canonical DecodedTx structure.

        Args:
            raw_bytes: Raw unsigned transaction bytes or hex-encoded string.

        Returns:
            DecodedTx: Canonical decoded transaction representation.

        Raises:
            DecodeError: If bytes are invalid, unknown type, malformed, or contain trailing data.
        """
        raise NotImplementedError
