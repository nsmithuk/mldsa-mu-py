# mldsa-mu

A small Python library for generating **external μ (mu)** values as specified by **ML-DSA (FIPS 204)**.

This library is intended for use in systems that need to compute μ outside of a full ML-DSA signing implementation (for example: KMS-style services, HSM adapters, or test tooling).

---

## What is μ?

In ML-DSA, the value **μ** is defined as:

```
μ = SHAKE256(tr || M', 64)
```

where:

- `tr = SHAKE256(public_key, 64)`
- `M' = 0x00 || len(context) || context || message`

This library implements exactly that construction.

---

## Features

- Deterministic μ generation per FIPS 204
- Supports optional domain-separation context
- Utilities for extracting raw public keys from (base64) PKIX / SPKI encodings

---

## Installation

```bash
pip install mldsa-mu
```

---

## Usage

### Example: generate μ from a raw public key
```python
from mldsa_mu import generate

public_key = b"\x01" * 64
message = b"hello world"

mu = generate(public_key, message)
print(mu)
```

### Example: generate μ with a domain-separation context
```python
from mldsa_mu import generate

public_key = b"\x02" * 64
message = b"important message"
context = b"my-protocol-v1"

mu = generate(public_key, message, context=context)
print(mu)
```

### Example: extract raw public key from DER-encoded PKIX (SPKI) and generate μ
```python
from mldsa_mu import generate, public_key_from_pkix

with open("public_key.spki.der", "rb") as f:
    spki_der = f.read()

public_key = public_key_from_pkix(spki_der)

mu = generate(public_key, b"hello world")
print(mu)
```

### Example: extract raw public key from base64-encoded PKIX (SPKI)
```python
from mldsa_mu import generate, public_key_from_pkix_b64

spki_b64 = (
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A..."
)

public_key = public_key_from_pkix_b64(spki_b64)

mu = generate(public_key, b"hello world")
print(mu)
```

---

## Development

Create (and remove if needed) the Hatch dev environment.
```bash
hatch env remove dev
hatch env create dev
```

Run tests: `hatch run dev:fmt`

Run code linting: `hatch run dev:pytest`

Run code type checking: `hatch run dev:typing`

## License

`mldsa-mu` is distributed under the terms of the [MIT](https://spdx.org/licenses/MIT.html) license.

---

*Python written by humans. English written by AI.*
