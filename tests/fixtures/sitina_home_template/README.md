# Disposable Sitina test-home template

This template contains no production data or credentials. `home_factory.py`
copies source-only runtime/config/schema/documentation material, generates
test-only provider profiles with `example.invalid` endpoints, creates empty
mutable roots, and seeds a separate legacy fixture database and JSONL file.
Every generated home carries a nonce marker required for safe cleanup.
