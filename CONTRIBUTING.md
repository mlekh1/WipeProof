# Contributing to WipeProof

Thank you for your interest in contributing to WipeProof! We welcome security researchers, systems programmers, and storage engineers.

---

## 1. Principles of Honesty & Standards Grounding
WipeProof strictly enforces honest standards alignment:
1. **Never overclaim sanitization:** Overwriting an SSD is **Clear at best**, never **Purge**. All claims must map directly to executable code and verified tests.
2. **Safety Invariants:** Destructive test suites MUST execute only against `/dev/loopX` devices or virtual sparse image files. Never submit a test or PR that targets a raw disk node.
3. **Cryptographic Rigor:** All certificate changes must preserve deterministic RFC 8785 canonicalization and RFC 8032 Ed25519 signature round-trips.

---

## 2. Development Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/your-username/wipeproof.git
   cd wipeproof
   ```

2. **Install in editable mode with development tools:**
   ```bash
   pip install -e ".[dev]"
   ```

3. **Run the test suite:**
   ```bash
   pytest tests -v
   ```

4. **Run the end-to-end reproducible demo:**
   ```bash
   python demo.py
   ```

---

## 3. Pull Request Guidelines

Before submitting a pull request, ensure:
* All 37+ tests pass (`pytest tests`).
* Property-based tests pass (`hypothesis`).
* Code adheres to typing standards (`mypy wipeproof`).
* Negative tests cover any new failure modes (e.g. malformed inputs, tampered payloads).
