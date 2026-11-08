# Tests

## NIST ACVP Known Answer Tests

`TestNistAcvpVectors` in `test_mu.py` verifies `generate()` against frozen test vectors derived from the NIST ACVP-Server repository:

https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ML-DSA-sigGen-FIPS204

The fixture file `nist_acvp_vectors.json` contains 6 test cases extracted from the `internalProjection.json` file's external-interface, deterministic, pure (non-prehash) test groups:

| Parameter Set | tcId | Context |
|---------------|------|---------|
| ML-DSA-44     | 1    | 96 bytes |
| ML-DSA-44     | 5    | empty |
| ML-DSA-65     | 31   | 17 bytes |
| ML-DSA-65     | 44   | empty |
| ML-DSA-87     | 61   | 141 bytes |
| ML-DSA-87     | 63   | empty |

Each vector contains `pk`, `message`, and `context` fields taken directly from the NIST test data. The `expected_mu` field is the result of computing:

```
tr = SHAKE256(pk, 64)
M' = 0x00 || len(context) || context || message
mu = SHAKE256(tr || M', 64)
```

### Cross-implementation validation

The expected mu values were independently verified using the OpenSSL CLI (`openssl dgst -shake256 -xoflen 64`), which is a separate SHAKE256 implementation from Python's `hashlib`. Both the intermediate `tr` and final `mu` were confirmed to match byte-for-byte. For example, for ML-DSA-65 tcId=44:

```
$ openssl dgst -shake256 -xoflen 64 pk.bin
SHAKE-256(pk.bin)= d672568216be656dbcf6a468f661b7aa...

$ openssl dgst -shake256 -xoflen 64 tr_mprime.bin
SHAKE-256(tr_mprime.bin)= ad9ce0fd4991fa73dc0e28348360eb5e...
```

Both values matched the Python-computed results exactly.

### Reproducing the vectors

To regenerate or extend the fixture from the NIST source:

```bash
curl -sL "https://raw.githubusercontent.com/usnistgov/ACVP-Server/master/gen-val/json-files/ML-DSA-sigGen-FIPS204/internalProjection.json" -o internalProjection.json
```

Then extract vectors from the external/deterministic/pure test groups (tgId 1, 3, 5) and compute `expected_mu` using the formula above.
