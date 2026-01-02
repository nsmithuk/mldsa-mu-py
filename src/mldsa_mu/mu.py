import hashlib
from base64 import b64decode

from pyasn1.codec.der import decoder
from pyasn1_modules import rfc5280  # type: ignore[import-untyped]

TR_SIZE = 64
MU_SIZE = 64


def public_key_from_pkix(spki_der: bytes) -> bytes:
    """
    Extract the raw SubjectPublicKeyInfo.subjectPublicKey BIT STRING bytes
    from a DER-encoded PKIX SubjectPublicKeyInfo.
    """
    spki, rest = decoder.decode(spki_der, asn1Spec=rfc5280.SubjectPublicKeyInfo())
    if rest:
        raise ValueError("Trailing data after SubjectPublicKeyInfo")

    return spki["subjectPublicKey"].asOctets()


def public_key_from_pkix_b64(spki_b64: str | bytes) -> bytes:
    """
    Accepts base64 text (or bytes) of DER-encoded SubjectPublicKeyInfo.
    """
    if isinstance(spki_b64, str):
        spki_b64 = spki_b64.encode("ascii")
    return public_key_from_pkix(b64decode(spki_b64))


def generate(public_key: bytes, message: bytes, context: bytes = b"") -> bytes:
    """
    μ = SHAKE256( tr || M', MU_SIZE )

    where:
      tr = SHAKE256(public_key, TR_SIZE)
      M' = 0x00 || len(context) || context || message
    """
    if len(context) > 255:
        raise ValueError("context length must be less than or equal to 255")

    tr = hashlib.shake_256(public_key).digest(TR_SIZE)
    m_prime = b"\x00" + bytes([len(context)]) + context + message
    return hashlib.shake_256(tr + m_prime).digest(MU_SIZE)
