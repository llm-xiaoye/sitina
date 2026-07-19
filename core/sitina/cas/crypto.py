from __future__ import annotations

import hashlib
import os
import struct
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from sitina.journal.model import canonical_json_bytes, domain_hash, validate_identifier
from sitina.security.key_provider import InMemoryKeyProvider, KeyProviderError, KeyPurpose

from .model import CASError, EncryptedObject, ObjectEnvelope, ObjectRef


CRYPTO_PROFILE_ID = "SITINA_CRYPTO_V1"
WRAP_PROFILE_ID = "SITINA_AES256_GCM_DEK_WRAP_V1"
ZSTD_CORE_HEADER_SCHEMA = "SITINA_CAS_CORE_HEADER_V2"
ZSTD_CHUNK_SIZE = 1024 * 1024


def _envelope_aad_mapping(*, core_header_hash: str, object_id: str, key_id: str, purpose: str, version: int) -> dict[str, Any]:
    return {
        "schema": "SITINA_ENVELOPE_AAD_V1", "core_header_hash": core_header_hash, "object_id": object_id,
        "key_id": key_id, "purpose": purpose, "wrap_profile": WRAP_PROFILE_ID, "version": version,
    }


def _build_envelope(provider: InMemoryKeyProvider, dek: bytes, *, core_header_hash: str, object_id: str, purpose: str, version: int) -> ObjectEnvelope:
    descriptor = provider.current_descriptor(KeyPurpose.CAS_KEK)
    aad = canonical_json_bytes(_envelope_aad_mapping(core_header_hash=core_header_hash, object_id=object_id, key_id=descriptor.key_id, purpose=purpose, version=version))
    wrapped = provider.wrap_dek(dek, aad)
    core = {
        **_envelope_aad_mapping(core_header_hash=core_header_hash, object_id=object_id, key_id=wrapped["key_id"], purpose=purpose, version=version),
        "nonce_hex": wrapped["nonce"].hex(), "wrapped_dek_hex": wrapped["wrapped_dek"].hex(),
    }
    envelope_id = domain_hash("CAS_ENVELOPE", canonical_json_bytes(core))
    return ObjectEnvelope(envelope_id, object_id, core_header_hash, wrapped["key_id"], purpose, WRAP_PROFILE_ID, version, wrapped["nonce"].hex(), wrapped["wrapped_dek"].hex())


def _zstd_module():
    try:
        import zstandard  # type: ignore[import-not-found]
    except ImportError as error:
        raise CASError("zstandard Reader/Writer dependency is unavailable") from error
    return zstandard


def _compress_zstd(plaintext: bytes, *, level: int) -> tuple[bytes, dict[str, Any]]:
    if level != 3:
        raise CASError("Sitina CAS zstd profile requires level 3")
    zstandard = _zstd_module()
    compressor = zstandard.ZstdCompressor(level=level, write_content_size=True, write_checksum=True)
    if len(plaintext) <= ZSTD_CHUNK_SIZE:
        compressed = compressor.compress(plaintext)
        return compressed, {
            "compression": "zstd",
            "compression_level": level,
            "compression_mode": "single",
            "compressed_length": len(compressed),
        }
    frames: list[bytes] = []
    for offset in range(0, len(plaintext), ZSTD_CHUNK_SIZE):
        frame = compressor.compress(plaintext[offset : offset + ZSTD_CHUNK_SIZE])
        frames.append(struct.pack(">I", len(frame)) + frame)
    compressed = b"".join(frames)
    return compressed, {
        "compression": "zstd",
        "compression_level": level,
        "compression_mode": "chunked",
        "compression_chunk_size": ZSTD_CHUNK_SIZE,
        "compression_chunk_count": len(frames),
        "compressed_length": len(compressed),
    }


def _decompress_zstd(stored: bytes, header: dict[str, Any]) -> bytes:
    zstandard = _zstd_module()
    if header.get("compression_level") != 3 or header.get("compressed_length") != len(stored):
        raise CASError("CAS zstd compression metadata mismatch")
    decompressor = zstandard.ZstdDecompressor()
    mode = header.get("compression_mode")
    try:
        if mode == "single":
            return decompressor.decompress(stored, max_output_size=int(header["plaintext_length"]))
        if mode != "chunked" or header.get("compression_chunk_size") != ZSTD_CHUNK_SIZE:
            raise CASError("unknown CAS zstd compression mode")
        expected_chunks = int(header.get("compression_chunk_count", 0))
        chunks: list[bytes] = []
        offset = 0
        while offset < len(stored):
            if offset + 4 > len(stored):
                raise CASError("truncated CAS zstd chunk header")
            length = struct.unpack(">I", stored[offset : offset + 4])[0]
            offset += 4
            if length < 1 or offset + length > len(stored):
                raise CASError("truncated CAS zstd chunk frame")
            frame = stored[offset : offset + length]
            offset += length
            remaining = int(header["plaintext_length"]) - sum(len(item) for item in chunks)
            chunks.append(decompressor.decompress(frame, max_output_size=min(ZSTD_CHUNK_SIZE, remaining)))
        if len(chunks) != expected_chunks:
            raise CASError("CAS zstd chunk count mismatch")
        return b"".join(chunks)
    except zstandard.ZstdError as error:
        raise CASError("CAS zstd frame authentication/decompression failed") from error


def encrypt_object(
    plaintext: bytes,
    provider: InMemoryKeyProvider,
    *,
    tenant_id: str,
    purpose: str = "business-object",
    compression: str = "none",
    compression_level: int = 3,
) -> EncryptedObject:
    if not isinstance(plaintext, bytes):
        raise TypeError("CAS plaintext must be bytes")
    validate_identifier(tenant_id, field="tenant_id")
    validate_identifier(purpose, field="purpose")
    commitment_key_id, commitment = provider.commitment(tenant_id, plaintext)
    dek = AESGCM.generate_key(bit_length=256)
    object_nonce = os.urandom(12)
    if compression == "none":
        stored = plaintext
        compression_fields: dict[str, Any] = {"compression": "none"}
        header_schema = "SITINA_CAS_CORE_HEADER_V1"
    elif compression == "zstd":
        stored, compression_fields = _compress_zstd(plaintext, level=compression_level)
        header_schema = ZSTD_CORE_HEADER_SCHEMA
    else:
        raise CASError("unknown CAS compression profile")
    core_header = {
        "schema": header_schema, "profile": CRYPTO_PROFILE_ID, "tenant_id": tenant_id,
        "purpose": purpose, "object_nonce_hex": object_nonce.hex(), "plaintext_length": len(plaintext),
        "plaintext_commitment": commitment, "commitment_key_id": commitment_key_id, **compression_fields,
    }
    header_bytes = canonical_json_bytes(core_header)
    ciphertext = AESGCM(dek).encrypt(object_nonce, stored, header_bytes)
    object_bytes = len(header_bytes).to_bytes(4, "big") + header_bytes + ciphertext
    object_id = hashlib.sha256(object_bytes).hexdigest()
    reference = ObjectRef(object_id, tenant_id, commitment, commitment_key_id)
    core_header_hash = domain_hash("CAS_CORE_HEADER", header_bytes)
    envelope = _build_envelope(provider, dek, core_header_hash=core_header_hash, object_id=object_id, purpose=purpose, version=1)
    return EncryptedObject(reference, core_header, ciphertext, envelope)


def decrypt_object(encrypted: EncryptedObject, provider: InMemoryKeyProvider) -> bytes:
    object_bytes = encrypted.object_bytes()
    if hashlib.sha256(object_bytes).hexdigest() != encrypted.reference.object_id:
        raise CASError("CAS ciphertext identity mismatch")
    if encrypted.core_header_hash != encrypted.envelope.core_header_hash or encrypted.reference.object_id != encrypted.envelope.object_id:
        raise CASError("envelope does not bind object/header identity")
    header = dict(encrypted.core_header)
    schema = header.get("schema")
    compression = header.get("compression")
    if header.get("profile") != CRYPTO_PROFILE_ID:
        raise CASError("unknown CAS core header profile")
    if schema == "SITINA_CAS_CORE_HEADER_V1" and compression != "none":
        raise CASError("V1 CAS header cannot declare compression")
    if schema == ZSTD_CORE_HEADER_SCHEMA and compression != "zstd":
        raise CASError("V2 CAS compression header is invalid")
    if schema not in {"SITINA_CAS_CORE_HEADER_V1", ZSTD_CORE_HEADER_SCHEMA}:
        raise CASError("unknown CAS core header profile")
    aad = canonical_json_bytes(_envelope_aad_mapping(core_header_hash=encrypted.core_header_hash, object_id=encrypted.reference.object_id, key_id=encrypted.envelope.key_id, purpose=encrypted.envelope.purpose, version=encrypted.envelope.version))
    try:
        dek = provider.unwrap_dek(encrypted.envelope.key_id, bytes.fromhex(encrypted.envelope.nonce_hex), bytes.fromhex(encrypted.envelope.wrapped_dek_hex), aad)
        stored = AESGCM(dek).decrypt(bytes.fromhex(header["object_nonce_hex"]), encrypted.ciphertext, encrypted.core_header_bytes)
    except (KeyProviderError, Exception) as error:
        raise CASError("CAS authentication or key unwrap failed") from error
    plaintext = stored if compression == "none" else _decompress_zstd(stored, header)
    if len(plaintext) != header["plaintext_length"]:
        raise CASError("CAS plaintext length mismatch")
    if header["tenant_id"] != encrypted.reference.tenant_id or not provider.verify_commitment(header["commitment_key_id"], header["tenant_id"], plaintext, header["plaintext_commitment"]):
        raise CASError("CAS tenant plaintext commitment mismatch")
    return plaintext


def rewrap_object(encrypted: EncryptedObject, provider: InMemoryKeyProvider) -> EncryptedObject:
    old = encrypted.envelope
    old_aad = canonical_json_bytes(_envelope_aad_mapping(core_header_hash=old.core_header_hash, object_id=old.object_id, key_id=old.key_id, purpose=old.purpose, version=old.version))
    dek = provider.unwrap_dek(old.key_id, bytes.fromhex(old.nonce_hex), bytes.fromhex(old.wrapped_dek_hex), old_aad)
    envelope = _build_envelope(provider, dek, core_header_hash=old.core_header_hash, object_id=old.object_id, purpose=old.purpose, version=old.version + 1)
    return EncryptedObject(encrypted.reference, encrypted.core_header, encrypted.ciphertext, envelope)
