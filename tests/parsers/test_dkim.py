"""Table-driven tests for the DKIM key record parser (RFC 6376, RFC 8463). No network.

RSA fixtures are SubjectPublicKeyInfo keys generated offline and deterministically: two
primes from ``random.Random(f"dkim-fixture-{bits}")`` (Miller-Rabin, 40 rounds), e=65537,
DER-encoded by hand and cross-checked with ``openssl pkey -pubin -text``. They are not real
customer keys. The ed25519 key is the sample from RFC 8463 Appendix A.2 (bare 32 bytes).
"""

from __future__ import annotations

import base64
import random
import time

import pytest

from app.parsers import dkim
from app.parsers.dkim import (
    MAX_DER_LENGTH,
    MAX_RECORD_LENGTH,
    MAX_TAGS,
    DkimKey,
    parse_dkim_key,
)
from app.parsers.spf import ParseIssue

RSA_512 = (
    "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAMYBmgYsv3YNV4JPv08KevmOS0wGACl6RtZrjQ9hF+pEm45EFHDYdeas"
    "I/FoFoPOcMsyZCphKcbCxYKG354H46cCAwEAAQ=="
)
RSA_1024 = (
    "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCnQuDGj8W5wGrQ3AnqSGkKEpAluYG4YICb2ypYdxNTN79cSITY"
    "QGeUMWAM5vYq5MlE3aMbNNEmLFy8u1gli8U5t6QcYREpvHR1XQcknNTCLDKfst3zumBFOqKzRcScWVnTkDmuR42D"
    "MZgsWQT9sEchBUkwp3BNwHBILvArihloJwIDAQAB"
)
RSA_2048 = (
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuCqbZdMOdM+yp+Aa4toQdfNClJZaIdO401CyksvcKtJP"
    "Ub2BP0TjjvTgRQ42wfj9BGEoxbCqJzCgmagvmHUI9wAp+5SPUc8a1jUVZ24X4v6Je+TJG1PFCDbhUzJseO45F1bX"
    "+qIejtygK0NMBuxhSuaN2uCbPYC9GgNtTrivV3eGkucKzorAfP+Bb/0lWepXJJiz4ZldE3Ho5YTRzn2QA0l28JQR"
    "MUbk8glggLHpFXgsBYPD6KkzJ3fA8MBttSHWeOJO7IPoDv5AQM20Eqjm2+w0bAVcv+84oXhHSNeLYTX2HkG+1hJk"
    "8XhV7bQwGKQpeGjCdtwpmU2RcS/AIv/ayQIDAQAB"
)
RSA_4096 = (
    "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAouv8l9yJekIY9QR1QIxn2D9DMKf+TerG/mPe2I8bwSqE"
    "n3SpuEjix+VVEufkHJbC1RQcrfe4hCd+yLEGM50QIrrVuAG4aArnONrzAbOncrFkssnlaw5TZyuu2i0pk41MIupp"
    "2fwe9olO1qyoxX+yhHXBcEk4G5CEUOQgy9BMVeBGeYUuBWxgFvr3VaoQyKdwx92BWPBcsiUbhkte4CsOaENQTWwJ"
    "ffbKQAKRHagRKuIINuLvAKdBJH4Ewq8PsHPUjGaQ+ke+fFOZXVs3+CBxJgTSF75HoOiDZNraPw46lbicbXtkiePZ"
    "HuFcNccTLdpbZYHGvGqm1oDQ9CJn1PlfMZb94GBvMupkqceLT8YXHBnjppi6h8Wf13u3PdrzO4p3hrsTMs1jWtGr"
    "x27ViZ12iKJCtPCL57dhE0AzK54EWfHwGBLEC3iUHB75gewwF6jlswnwR3Fvb3xbs+TP+oy7ZHdHB3byP43Eizd6"
    "hakTfvBWcvWkJLdTBLPE6r/nPz4+rTzOrSyRErlzzsGzIrlLISdNjQRx9rZtXTX2HvzOXCWI1ZOC24WpJg4IvFyr"
    "ttBGV6dKyOm0yrW8yWdJnV1la4oePgScH1CRSjeOURiS3MvEpoWGg51LX0tn5DP4+vM5d1F4PzgWD3Bgst4FnEIk"
    "2pFZLbejuBsWYYtYKb2p9WUCAwEAAQ=="
)
ED25519 = "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="


# --- DER helpers used to craft malformed keys from the fixtures ---------------------------


def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(content)) + content


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


_SPKI_2048 = base64.b64decode(RSA_2048)
_SPKI_1024 = base64.b64decode(RSA_1024)
# RSAPublicKey inside the 1024-bit SPKI: header(3) + alg(15) + bitstring header(3) + pad(1).
_RSAPK_1024 = _SPKI_1024[22:]
_RSA_OID = bytes.fromhex("2a864886f70d010101")


def _spki(oid: bytes, key: bytes, params: bytes = b"\x05\x00") -> bytes:
    alg = _tlv(0x30, _tlv(0x06, oid) + params)
    return _tlv(0x30, alg + _tlv(0x03, b"\x00" + key))


def _nested(depth: int) -> bytes:
    data = _tlv(0x02, b"\x01")
    for _ in range(depth):
        data = _tlv(0x30, data)
    return data


def _issue_codes(key: DkimKey) -> set[str]:
    return set(key.issue_codes())


# --- valid records --------------------------------------------------------------------

# (record, key_type, key_format, bits)
VALID_CASES: list[tuple[str, str, str, int]] = [
    (f"v=DKIM1; k=rsa; p={RSA_512}", "rsa", "spki", 512),
    (f"v=DKIM1; k=rsa; p={RSA_1024}", "rsa", "spki", 1024),
    (f"v=DKIM1; k=rsa; p={RSA_2048}", "rsa", "spki", 2048),
    (f"v=DKIM1; k=rsa; p={RSA_4096}", "rsa", "spki", 4096),
    (f"p={RSA_2048}", "rsa", "spki", 2048),  # v and k are optional, k defaults to rsa
    (f"v=DKIM1;p={RSA_1024};", "rsa", "spki", 1024),  # trailing ";"
    (f" v = DKIM1 ;\tk = rsa ;\r\n p = {RSA_1024} ", "rsa", "spki", 1024),  # FWS
    (
        f"v=DKIM1; k=rsa; p={RSA_2048[:100]} {RSA_2048[100:200]}\t{RSA_2048[200:]}",
        "rsa",
        "spki",
        2048,
    ),
    (f"v=DKIM1; p={RSA_2048[:120]}\r\n {RSA_2048[120:]}", "rsa", "spki", 2048),  # folded
    (f"v=DKIM1; k=rsa; p={_b64(_RSAPK_1024)}", "rsa", "rsa_public_key", 1024),
    (f"v=DKIM1; k=ed25519; p={ED25519}", "ed25519", "raw", 256),
    (f"v=DKIM1; k=rsa; h=sha256; s=email; t=s; n=main key; p={RSA_2048}", "rsa", "spki", 2048),
    (f"v=DKIM1; h=sha1:sha256; s=*; p={RSA_1024}", "rsa", "spki", 1024),
    (f"v=DKIM1; t=y; p={RSA_1024}", "rsa", "spki", 1024),
    (f"v=DKIM1; t=y:s; p={RSA_1024}", "rsa", "spki", 1024),
    (f"v=DKIM1; p={_b64(_spki(_RSA_OID, _RSAPK_1024, params=b''))}", "rsa", "spki", 1024),
]


@pytest.mark.parametrize(("text", "key_type", "key_format", "bits"), VALID_CASES)
def test_valid_records(text: str, key_type: str, key_format: str, bits: int) -> None:
    key = parse_dkim_key(text)
    assert key.issues == (), key.issues
    assert key.is_valid
    assert key.key_type == key_type
    assert key.key_format == key_format
    assert key.bits == bits
    assert not key.revoked
    assert key.public_key is not None and not any(c in " \t\r\n" for c in key.public_key)


def test_fields_and_flags() -> None:
    key = parse_dkim_key(f"v=DKIM1; k=rsa; h=sha256; s=email; t=y:s; n=rotated; p={RSA_2048}")
    assert key.version == "DKIM1"
    assert key.hash_algorithms == ("sha256",)
    assert key.service_types == ("email",)
    assert key.flags == ("y", "s")
    assert key.testing and key.strict_identity
    assert key.notes == "rotated"
    assert [t.name for t in key.tags] == ["v", "k", "h", "s", "t", "n", "p"]
    assert key.tags[1].position == key.raw.index("k=")


def test_defaults() -> None:
    key = parse_dkim_key(f"p={RSA_1024}")
    assert key.version is None
    assert key.key_type == "rsa"
    assert key.hash_algorithms is None
    assert key.service_types == ("*",)
    assert key.flags == ()
    assert not key.testing and not key.strict_identity
    assert key.notes is None


# --- revoked ---------------------------------------------------------------------------

REVOKED_CASES: list[str] = [
    "v=DKIM1; p=",
    "v=DKIM1; k=rsa; p=;",
    "v=DKIM1; p=   ",
    "v=DKIM1; k=ed25519; p=",
    "p=",
]


@pytest.mark.parametrize("text", REVOKED_CASES)
def test_revoked(text: str) -> None:
    key = parse_dkim_key(text)
    assert key.revoked
    assert key.bits is None
    assert key.public_key == ""
    assert key.is_valid, key.issues


# --- warnings (record still usable) ----------------------------------------------------

WARNING_CASES: list[tuple[str, str]] = [
    (f"v=DKIM1; x=1; p={RSA_1024}", "unknown_tag"),
    (f"v=DKIM1; P=abc; p={RSA_1024}", "unknown_tag"),  # tag names are case-sensitive
    (f"v=DKIM1; h=sha512:sha256; p={RSA_1024}", "unknown_hash_algorithm"),
    (f"v=DKIM1; s=email:smtp; p={RSA_1024}", "unknown_service_type"),
    (f"v=DKIM1; t=y:z; p={RSA_1024}", "unknown_flag"),
]


@pytest.mark.parametrize(("text", "code"), WARNING_CASES)
def test_warnings(text: str, code: str) -> None:
    key = parse_dkim_key(text)
    assert code in _issue_codes(key)
    assert all(i.severity == "warning" for i in key.issues), key.issues
    assert key.is_valid
    assert key.bits == 1024


def test_unknown_tags_kept() -> None:
    key = parse_dkim_key(f"v=DKIM1; x_1=a b; p={RSA_1024}")
    assert key.unknown_tags == ("x_1",)
    assert key.tags[1].value == "a b"


# --- malformed input -------------------------------------------------------------------

_TRUNCATED = _b64(_SPKI_2048[:-10])
_WRONG_OID = _b64(_spki(bytes.fromhex("2a864886f70d01010a"), _RSAPK_1024))  # RSASSA-PSS
_EC_OID = _b64(_spki(bytes.fromhex("2a8648ce3d0201"), _RSAPK_1024))  # id-ecPublicKey
_ED_SPKI = _b64(_spki(bytes.fromhex("2b6570"), base64.b64decode(ED25519), params=b""))
_BAD_PARAMS = _b64(_spki(_RSA_OID, _RSAPK_1024, params=b"\x02\x01\x00"))
_TRAILING = _b64(_SPKI_1024 + b"\x00")
_INDEFINITE = _b64(b"\x30\x80" + _SPKI_1024[3:] + b"\x00\x00")
_HUGE_LEN = _b64(b"\x30\x84\x7f\xff\xff\xff" + _SPKI_1024[3:])
_OVER_LEN = _b64(b"\x30\x82\x7f\xff" + _SPKI_1024[3:])
_NON_MINIMAL_LEN = _b64(b"\x30\x81\x06\x02\x01\x03\x02\x01\x03")
_HIGH_TAG = _b64(b"\x1f\x81\x00\x00")
_NEGATIVE_MODULUS = _b64(
    _tlv(0x30, _tlv(0x02, b"\x80" + b"\x01" * 63) + _tlv(0x02, b"\x01\x00\x01"))
)
_NON_MINIMAL_INT = _b64(_tlv(0x30, _tlv(0x02, b"\x00\x01" + b"\x01" * 63) + _tlv(0x02, b"\x03")))
_EVEN_MODULUS = _b64(_tlv(0x30, _tlv(0x02, b"\x41" + b"\x02" * 63) + _tlv(0x02, b"\x03")))
_NESTED = _b64(_nested(200))
_BAD_BITSTRING_PAD = _b64(
    _tlv(0x30, _tlv(0x30, _tlv(0x06, _RSA_OID) + b"\x05\x00") + _tlv(0x03, b"\x07" + _RSAPK_1024))
)
_TOO_LARGE = _b64(b"\x00" * (MAX_DER_LENGTH + 3))
_RAW_32 = _b64(bytes(range(32)))
_RAW_31 = _b64(bytes(range(31)))

# (record, expected issue code). Every case must be an error and leave bits=None.
MALFORMED_CASES: list[tuple[str, str]] = [
    ("", "empty_record"),
    ("   \t ", "empty_record"),
    ("v=DKIM1", "missing_key"),
    ("v=DKIM1; k=rsa", "missing_key"),
    ("v=DKIM1; p=!!!notbase64!!!", "bad_base64"),
    ("v=DKIM1; p=QUJD", "bad_der"),  # valid base64, not DER
    (f"v=DKIM1; p={RSA_1024[:-1]}", "bad_base64"),  # bad padding/length
    (f"v=DKIM1; p={RSA_1024}===", "bad_base64"),
    (f"v=DKIM1; p={RSA_1024[:10]}={RSA_1024[10:]}", "bad_base64"),  # "=" inside
    (f"v=DKIM1; p={RSA_1024[:10]}\x0b{RSA_1024[10:]}", "control_character"),
    (f"v=DKIM1; p={_TRUNCATED}", "bad_der"),
    (f"v=DKIM1; p={_WRONG_OID}", "wrong_key_algorithm"),
    (f"v=DKIM1; p={_EC_OID}", "wrong_key_algorithm"),
    (f"v=DKIM1; p={_BAD_PARAMS}", "wrong_key_algorithm"),
    (f"v=DKIM1; p={_TRAILING}", "bad_der"),
    (f"v=DKIM1; p={_INDEFINITE}", "bad_der"),
    (f"v=DKIM1; p={_HUGE_LEN}", "bad_der"),
    (f"v=DKIM1; p={_OVER_LEN}", "bad_der"),
    (f"v=DKIM1; p={_NON_MINIMAL_LEN}", "bad_der"),
    (f"v=DKIM1; p={_HIGH_TAG}", "bad_der"),
    (f"v=DKIM1; p={_NEGATIVE_MODULUS}", "bad_der"),
    (f"v=DKIM1; p={_NON_MINIMAL_INT}", "bad_der"),
    (f"v=DKIM1; p={_EVEN_MODULUS}", "bad_der"),
    (f"v=DKIM1; p={_NESTED}", "bad_der"),
    (f"v=DKIM1; p={_BAD_BITSTRING_PAD}", "bad_der"),
    (f"v=DKIM1; p={_TOO_LARGE}", "key_too_large"),
    (f"v=DKIM1; k=rsa; p={ED25519}", "key_type_mismatch"),
    (f"v=DKIM1; p={_RAW_32}", "key_type_mismatch"),
    (f"v=DKIM1; k=ed25519; p={RSA_2048}", "key_type_mismatch"),
    (f"v=DKIM1; k=ed25519; p={_ED_SPKI}", "bad_key_length"),
    (f"v=DKIM1; k=rsa; p={_ED_SPKI}", "key_type_mismatch"),
    (f"v=DKIM1; k=ed25519; p={_RAW_31}", "bad_key_length"),
    (f"v=DKIM1; k=dsa; p={RSA_1024}", "unknown_key_type"),
    (f"v=DKIM1; k=RSA; p={RSA_1024}", "unknown_key_type"),  # values are case-sensitive
    (f"v=DKIM1; k=; p={RSA_1024}", "unknown_key_type"),
    (f"v=DKIM1; p={RSA_1024}; p={RSA_2048}", "duplicate_tag"),
    (f"v=DKIM1; k=rsa; k=rsa; p={RSA_1024}", "duplicate_tag"),
    (f"v=DKIM2; p={RSA_1024}", "bad_version"),
    (f"v=DKIM1.0; p={RSA_1024}", "bad_version"),
    (f"v=dkim1; p={RSA_1024}", "bad_version"),
    (f"k=rsa; v=DKIM1; p={RSA_1024}", "version_not_first"),
    (f"v=DKIM1;; p={RSA_1024}", "empty_tag"),
    (f"; v=DKIM1; p={RSA_1024}", "empty_tag"),
    (f"v=DKIM1; garbage; p={RSA_1024}", "invalid_tag"),
    (f"v=DKIM1; 1x=a; p={RSA_1024}", "invalid_tag_name"),
    (f"v=DKIM1; x-y=a; p={RSA_1024}", "invalid_tag_name"),
    (f"v=DKIM1; =a; p={RSA_1024}", "invalid_tag_name"),
    (f"v=DKIM1; h=; p={RSA_1024}", "bad_tag_value"),
    (f"v=DKIM1; h=sha256:; p={RSA_1024}", "bad_tag_value"),
    (f"v=DKIM1; s=smtp; p={RSA_1024}", "service_excludes_email"),
    (f"v=DKIM1; n=café; p={RSA_1024}", "non_ascii"),
    (f"v=DKIM1; p={RSA_1024[:20]} {RSA_1024[20:]}", "non_ascii"),
    ("v=DKIM1; p=١٢٣٤", "non_ascii"),  # non-ASCII digits
    (f"v=DKIM1; p={RSA_1024}; " + "x" * MAX_RECORD_LENGTH, "record_too_long"),
    ("".join(f"x{i}=a;" for i in range(MAX_TAGS + 5)) + f"p={RSA_1024}", "too_many_tags"),
]


_KEY_CODES = {
    "missing_key",
    "bad_base64",
    "bad_der",
    "wrong_key_algorithm",
    "key_too_large",
    "key_type_mismatch",
    "bad_key_length",
    "unknown_key_type",
}


@pytest.mark.parametrize(("text", "code"), MALFORMED_CASES)
def test_malformed(text: str, code: str) -> None:
    key = parse_dkim_key(text)
    issue = next((i for i in key.issues if i.code == code), None)
    assert issue is not None, key.issues
    assert isinstance(issue, ParseIssue)
    assert issue.severity == "error"
    assert not key.is_valid
    if code in _KEY_CODES:
        assert key.bits is None


def test_malformed_case_count() -> None:
    assert len(MALFORMED_CASES) >= 25


def test_whitespace_in_p_still_rejects_control_and_nbsp_but_decodes() -> None:
    # Non-FWS whitespace is reported but does not break tokenisation.
    key = parse_dkim_key(f"v=DKIM1; p={RSA_1024[:20]} {RSA_1024[20:]}")
    assert "non_ascii" in _issue_codes(key)
    assert key.bits is None
    assert "bad_base64" in _issue_codes(key)


def test_oversized_record_is_cut() -> None:
    text = f"v=DKIM1; p={RSA_1024}; n=" + "a" * (MAX_RECORD_LENGTH * 50)
    start = time.perf_counter()
    key = parse_dkim_key(text)
    assert time.perf_counter() - start < 1.0
    assert key.truncated
    assert key.raw == text
    assert key.bits == 1024
    assert key.notes is not None and len(key.notes) < MAX_RECORD_LENGTH


def test_too_many_tags_is_truncated() -> None:
    key = parse_dkim_key("".join(f"x{i}=a;" for i in range(MAX_TAGS * 10)))
    assert key.truncated
    assert len(key.tags) == MAX_TAGS


def test_wrong_oid_reported_dotted() -> None:
    key = parse_dkim_key(f"p={_WRONG_OID}")
    issue = next(i for i in key.issues if i.code == "wrong_key_algorithm")
    assert issue.term == "1.2.840.113549.1.1.10"


@pytest.mark.parametrize("value", [None, 123, b"p=abc", ["p="]])
def test_non_string_input(value: object) -> None:
    key = parse_dkim_key(value)  # type: ignore[arg-type]
    assert key.issue_codes() == ("empty_record",)


# --- DER reader bounds -----------------------------------------------------------------

DER_ERROR_CASES: list[tuple[str, bytes]] = [
    ("empty", b""),
    ("single byte", b"\x30"),
    ("length beyond buffer", b"\x30\x05\x02\x01"),
    ("three length octets", b"\x30\x83\x00\x01\x00" + b"\x00" * 256),
    ("indefinite", b"\x30\x80\x00\x00"),
    ("non-minimal long form", b"\x30\x81\x03\x02\x01\x03"),
    ("leading zero length", b"\x30\x82\x00\x80" + b"\x00" * 128),
    ("high tag", b"\x3f\x01\x00\x00"),
    ("not a sequence", b"\x04\x03\x02\x01\x03"),
    ("deep nesting", _nested(50)),
    ("empty integer", b"\x30\x04\x02\x00\x02\x00"),
    ("sequence then junk", b"\x30\x00\x00"),
]


@pytest.mark.parametrize(("name", "data"), DER_ERROR_CASES)
def test_der_reader_rejects(name: str, data: bytes) -> None:
    with pytest.raises(dkim._DerError):
        dkim._read_public_key(data)


def test_der_depth_limit() -> None:
    with pytest.raises(dkim._DerError):
        dkim._read_tlv(b"\x30\x00", 0, 2, dkim.MAX_DER_DEPTH + 1)


def test_mutated_keys_never_raise() -> None:
    """Seeded mutation sweep over the fixtures: only ParseIssues, never exceptions."""
    rng = random.Random(6376)
    seeds = [
        base64.b64decode(k)
        for k in (RSA_512, RSA_1024, RSA_2048, base64.b64encode(_RSAPK_1024).decode())
    ]
    for _ in range(1500):
        data = bytearray(rng.choice(seeds))
        for _ in range(rng.randint(1, 4)):
            op = rng.randrange(3)
            idx = rng.randrange(len(data))
            if op == 0:
                data[idx] = rng.randrange(256)
            elif op == 1:
                del data[idx:]
            else:
                data.insert(idx, rng.randrange(256))
            if not data:
                break
        key = parse_dkim_key(f"v=DKIM1; k={rng.choice(['rsa', 'ed25519'])}; p={_b64(bytes(data))}")
        assert isinstance(key, DkimKey)
        assert key.bits is None or key.bits > 0
        if key.bits is None and not key.revoked:
            assert not key.is_valid
