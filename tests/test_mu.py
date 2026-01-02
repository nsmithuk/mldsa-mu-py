import base64
import hashlib

import pytest
from pyasn1.codec.der import encoder
from pyasn1.type import univ
from pyasn1_modules import rfc5280  # type: ignore[import-untyped]

from mldsa_mu import (
    generate,
    public_key_from_pkix,
    public_key_from_pkix_b64,
)
from mldsa_mu.mu import MU_SIZE, TR_SIZE


def make_spki_der(subject_public_key_bytes: bytes, algorithm_oid: str = "1.2.3.4.5") -> bytes:
    """
    Build a minimal DER SubjectPublicKeyInfo for tests.

    NOTE: The algorithm OID here is dummy; your parser doesn't validate it,
    it only extracts the subjectPublicKey BIT STRING.
    """
    spki = rfc5280.SubjectPublicKeyInfo()
    spki["algorithm"] = rfc5280.AlgorithmIdentifier()
    spki["algorithm"]["algorithm"] = univ.ObjectIdentifier(algorithm_oid)

    # BIT STRING expects bits; we set it from octets. This yields 0 unused bits.
    spki["subjectPublicKey"] = univ.BitString.fromOctetString(subject_public_key_bytes)
    return encoder.encode(spki)


def ref_generate(public_key: bytes, message: bytes, context: bytes = b"") -> bytes:
    """
    Reference implementation matching the docstring:
      tr = SHAKE256(public_key, TR_SIZE)
      M' = 0x00 || len(context) || context || message
      μ = SHAKE256(tr || M', MU_SIZE)
    """
    if len(context) > 255:
        raise ValueError("context length must be less than or equal to 255")

    tr = hashlib.shake_256(public_key).digest(TR_SIZE)
    m_prime = b"\x00" + bytes([len(context)]) + context + message
    return hashlib.shake_256(tr + m_prime).digest(MU_SIZE)


class TestPublicKeyFromPKIX:
    def test_extracts_subject_public_key_bytes(self):
        raw_pk = b"\x01\x02\x03\x04\xff"
        der = make_spki_der(raw_pk)

        out = public_key_from_pkix(der)
        assert out == raw_pk

    def test_raises_on_trailing_data(self):
        raw_pk = b"\xaa\xbb\xcc"
        der = make_spki_der(raw_pk) + b"\x00\x01\x02"  # garbage trailing bytes

        with pytest.raises(ValueError, match="Trailing data"):
            public_key_from_pkix(der)

    @pytest.mark.parametrize(
        "bad_der",
        [
            b"",  # empty
            b"\x30\x03\x02\x01\x01",  # random DER that's not SPKI structure
            b"\x01\x02\x03",  # not valid DER at all
        ],
    )
    def test_bad_der_raises(self, bad_der):
        # pyasn1 may raise different exception types; just ensure it blows up
        with pytest.raises(Exception):
            public_key_from_pkix(bad_der)


class TestPublicKeyFromPKIXB64:
    def test_accepts_base64_str(self):
        raw_pk = b"raw-public-key"
        der = make_spki_der(raw_pk)
        b64 = base64.b64encode(der).decode("ascii")

        out = public_key_from_pkix_b64(b64)
        assert out == raw_pk

    def test_accepts_base64_bytes(self):
        raw_pk = b"\x00\x10\x20"
        der = make_spki_der(raw_pk)
        b64 = base64.b64encode(der)

        out = public_key_from_pkix_b64(b64)
        assert out == raw_pk

    def test_invalid_base64_raises(self):
        with pytest.raises(Exception):
            public_key_from_pkix_b64("%%% not base64 %%%")


class TestGenerateMu:
    def test_matches_reference_empty_context(self):
        public_key = b"\x11" * 32
        message = b"hello"

        got = generate(public_key, message, context=b"")
        exp = ref_generate(public_key, message, context=b"")
        assert got == exp
        assert isinstance(got, bytes)
        assert len(got) == MU_SIZE

    def test_matches_reference_non_empty_context(self):
        public_key = b"\x22" * 64
        message = b"message bytes"
        context = b"context"

        got = generate(public_key, message, context=context)
        exp = ref_generate(public_key, message, context=context)
        assert got == exp
        assert len(got) == MU_SIZE

    def test_context_length_255_ok(self):
        public_key = b"\x33" * 16
        message = b"m"
        context = b"\x00" * 255

        got = generate(public_key, message, context=context)
        exp = ref_generate(public_key, message, context=context)
        assert got == exp

    def test_context_length_256_raises(self):
        public_key = b"\x44" * 16
        message = b"m"
        context = b"\x00" * 256

        with pytest.raises(ValueError, match="context length must be less than or equal to 255"):
            generate(public_key, message, context=context)

    def test_domain_separator_byte_changes_output(self):
        """
        Sanity check: if someone removed the 0x00 prefix, this would likely fail.
        We compare against an alternate construction without the prefix.
        """
        public_key = b"\x55" * 32
        message = b"abc"
        context = b"ctx"

        got = generate(public_key, message, context=context)

        tr = hashlib.shake_256(public_key).digest(TR_SIZE)
        m_no_prefix = bytes([len(context)]) + context + message
        alt = hashlib.shake_256(tr + m_no_prefix).digest(MU_SIZE)

        assert got != alt

    def test_context_length_byte_matters(self):
        """
        Two different contexts with same suffix but different length must differ.
        """
        public_key = b"\x66" * 32
        message = b"abc"

        c1 = b"A"
        c2 = b"\x00A"  # ends with A but length differs

        mu1 = generate(public_key, message, context=c1)
        mu2 = generate(public_key, message, context=c2)

        assert mu1 != mu2
