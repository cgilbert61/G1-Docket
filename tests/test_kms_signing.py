"""Tests for Cloud KMS / Hardware Security Module (HSM) DSSE envelope signing and verification."""

import base64
import json
import pytest
from unittest.mock import MagicMock

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, decode_dss_signature

from registry.schema_validator import SNAPSHOT_PREDICATE_TYPE
from registry.signing import (
    AWSKMSSigner,
    AzureKeyVaultSigner,
    GCPCloudKMSSigner,
    HashiCorpVaultTransitSigner,
    Keyring,
    MockKMSSigner,
    SignatureVerificationError,
    build_attestation_statement,
    compute_bytes_sha256,
    sign_statement,
    verify_dsse_envelope,
)
from registry.store import RegistryService
from snapshot.publisher import SnapshotPublisher


def _sample_attestation_statement() -> dict:
    return build_attestation_statement(
        locator="file:///pc_demo_folder/01_board_minutes.docx",
        content_sha256=compute_bytes_sha256(b"Board Minutes Confidential 2026"),
        tier="Confidential",
        steward="infosec-stewards@yourcompany.com",
        owner="board-secretary@yourcompany.com",
        org_unit="Executive Governance",
        jurisdiction="US",
        ttl_days=30,
    )


def test_mock_kms_signer_signing_and_verification(tmp_path):
    pub_dir = tmp_path / "pub"
    priv_dir = tmp_path / "priv"
    keyring = Keyring(public_key_dir=pub_dir, private_key_dir=priv_dir)

    signer = MockKMSSigner(
        algorithm="ECDSA_P256_SHA256",
        kms_uri="mockkms://us-east-1/cmk-finance-hsm-001",
    )
    meta = keyring.register_kms_signer(signer, activate=True)
    assert meta["is_kms"] is True
    assert meta["kms_uri"] == "mockkms://us-east-1/cmk-finance-hsm-001"
    assert meta["algorithm"] == "ECDSA_P256_SHA256"

    # Verify public key file exists, but NO private key file exists
    keyid = signer.keyid
    pub_file = pub_dir / f"{keyid}.pub.pem"
    assert pub_file.exists()
    assert not (priv_dir / f"{keyid}.priv.pem").exists()

    # Attempting to export/load private key must fail closed
    with pytest.raises(SignatureVerificationError) as exc_info:
        keyring.load_private_key(keyid)
    assert "hardware KMS/HSM key" in str(exc_info.value)
    assert "private keys cannot be exported" in str(exc_info.value)

    # Sign statement using KMS key
    stmt = _sample_attestation_statement()
    envelope = sign_statement(stmt, keyring)

    # Verify DSSE envelope structure and KMS metadata in Sigstore bundle
    assert envelope["signatures"][0]["keyid"] == keyid
    sigstore = envelope["sigstoreBundle"]["verificationMaterial"]["publicKey"]
    assert sigstore["hint"] == keyid
    assert sigstore["algorithm"] == "ECDSA_P256_SHA256"
    assert sigstore["kmsUri"] == "mockkms://us-east-1/cmk-finance-hsm-001"
    assert signer.sign_call_count == 1

    # In-boundary / offline verification with zero KMS calls
    verifier_keyring = Keyring(public_key_dir=pub_dir, verification_only=True)
    res = verify_dsse_envelope(envelope, verifier_keyring)
    assert res.verified is True
    assert res.keyid == keyid
    assert res.algorithm == "ECDSA_P256_SHA256"
    assert signer.sign_call_count == 1  # No additional calls to KMS during verification

    # Tampering with payload fails verification
    tampered_stmt = dict(stmt)
    tampered_stmt["predicate"]["classification"]["tier"] = "Public"
    tampered_payload_b64 = base64.b64encode(json.dumps(tampered_stmt).encode("utf-8")).decode("ascii")
    tampered_envelope = dict(envelope, payload=tampered_payload_b64)
    with pytest.raises(SignatureVerificationError) as exc_info:
        verify_dsse_envelope(tampered_envelope, verifier_keyring)
    assert "signature verification failed" in str(exc_info.value).lower()


def test_ed25519_mock_kms_signer(tmp_path):
    keyring = Keyring(public_key_dir=tmp_path / "pub", private_key_dir=tmp_path / "priv")
    signer = MockKMSSigner(
        algorithm="Ed25519",
        kms_uri="mockkms://eu-central-1/cmk-ed25519-hsm",
    )
    keyring.register_kms_signer(signer, activate=True)

    stmt = _sample_attestation_statement()
    envelope = sign_statement(stmt, keyring)
    assert envelope["sigstoreBundle"]["verificationMaterial"]["publicKey"]["algorithm"] == "Ed25519"

    res = verify_dsse_envelope(envelope, keyring)
    assert res.verified is True
    assert res.algorithm == "Ed25519"


def test_aws_kms_signer_interface_and_mock(tmp_path):
    # Setup a realistic EC P-256 key inside the simulated AWS KMS client
    hsm_key = ec.generate_private_key(ec.SECP256R1())
    der_pub = hsm_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    mock_client = MagicMock()
    mock_client.get_public_key.return_value = {"PublicKey": der_pub}

    def _aws_mock_sign(KeyId, Message, MessageType, SigningAlgorithm):
        assert MessageType == "RAW"
        assert SigningAlgorithm == "ECDSA_SHA_256"
        return {"Signature": hsm_key.sign(Message, ec.ECDSA(hashes.SHA256()))}

    mock_client.sign.side_effect = _aws_mock_sign

    arn = "arn:aws:kms:us-east-1:112233445566:key/abc-1234-hsm"
    aws_signer = AWSKMSSigner(key_arn=arn, kms_client=mock_client)

    keyring = Keyring(public_key_dir=tmp_path / "pub", private_key_dir=tmp_path / "priv")
    keyring.register_kms_signer(aws_signer, activate=True)

    stmt = _sample_attestation_statement()
    envelope = sign_statement(stmt, keyring)

    mock_client.sign.assert_called_once()
    assert envelope["sigstoreBundle"]["verificationMaterial"]["publicKey"]["kmsUri"] == f"awskms://{arn}"

    res = verify_dsse_envelope(envelope, keyring)
    assert res.verified is True


def test_azure_keyvault_signer_interface_and_mock(tmp_path):
    hsm_key = ec.generate_private_key(ec.SECP256R1())
    pub_pem = hsm_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    mock_crypto_client = MagicMock()

    def _azure_mock_sign(algorithm, digest):
        assert algorithm == "ES256"
        der_sig = hsm_key.sign(digest, ec.ECDSA(Prehashed(hashes.SHA256())))
        r, s = decode_dss_signature(der_sig)
        raw_64 = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        resp = MagicMock()
        resp.signature = raw_64
        return resp

    mock_crypto_client.sign.side_effect = _azure_mock_sign

    vault_url = "https://corp-governance-kv.vault.azure.net"
    az_signer = AzureKeyVaultSigner(
        vault_url=vault_url,
        key_name="docket-master-key",
        key_version="v1",
        crypto_client=mock_crypto_client,
        public_key_pem=pub_pem,
    )

    keyring = Keyring(public_key_dir=tmp_path / "pub", private_key_dir=tmp_path / "priv")
    keyring.register_kms_signer(az_signer, activate=True)

    stmt = _sample_attestation_statement()
    envelope = sign_statement(stmt, keyring)

    mock_crypto_client.sign.assert_called_once()
    assert envelope["sigstoreBundle"]["verificationMaterial"]["publicKey"]["kmsUri"] == f"azurekms://{vault_url}/keys/docket-master-key/v1"

    res = verify_dsse_envelope(envelope, keyring)
    assert res.verified is True


def test_gcp_cloud_kms_signer_interface_and_mock(tmp_path):
    hsm_key = ec.generate_private_key(ec.SECP256R1())
    pub_pem = hsm_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    mock_kms_client = MagicMock()
    mock_pub_resp = MagicMock()
    mock_pub_resp.pem = pub_pem
    mock_kms_client.get_public_key.return_value = mock_pub_resp

    def _gcp_mock_asymmetric_sign(request):
        digest = request["digest"]["sha256"]
        der_sig = hsm_key.sign(digest, ec.ECDSA(Prehashed(hashes.SHA256())))
        resp = MagicMock()
        resp.signature = der_sig
        return resp

    mock_kms_client.asymmetric_sign.side_effect = _gcp_mock_asymmetric_sign

    key_resource = "projects/my-governance-proj/locations/global/keyRings/g1-ring/cryptoKeys/docket-attestor/cryptoKeyVersions/1"
    gcp_signer = GCPCloudKMSSigner(
        key_name=key_resource,
        kms_client=mock_kms_client,
    )

    keyring = Keyring(public_key_dir=tmp_path / "pub", private_key_dir=tmp_path / "priv")
    keyring.register_kms_signer(gcp_signer, activate=True)

    stmt = _sample_attestation_statement()
    envelope = sign_statement(stmt, keyring)

    mock_kms_client.asymmetric_sign.assert_called_once()
    assert envelope["sigstoreBundle"]["verificationMaterial"]["publicKey"]["kmsUri"] == f"gcpkms://{key_resource}"

    res = verify_dsse_envelope(envelope, keyring)
    assert res.verified is True


def test_snapshot_publisher_with_kms_signing(tmp_path):
    key_pub = tmp_path / "keys_pub"
    key_priv = tmp_path / "keys_priv"
    keyring = Keyring(public_key_dir=key_pub, private_key_dir=key_priv)
    signer = MockKMSSigner(
        algorithm="ECDSA_P256_SHA256",
        kms_uri="mockkms://global/hsm-snapshot-publisher",
    )
    keyring.register_kms_signer(signer, activate=True, key_purpose=["snapshot", "attestation"])

    registry = RegistryService(
        db_url=f"sqlite:///{tmp_path.as_posix()}/reg.db",
        key_dir=key_pub,
    )
    registry.keyring = keyring

    snap_file = tmp_path / "snapshot.dsse.json"
    publisher = SnapshotPublisher(registry=registry, snapshot_output_path=snap_file)

    envelope = publisher.publish_snapshot()
    assert snap_file.exists()
    assert envelope["signatures"][0]["keyid"] == signer.keyid
    assert envelope["sigstoreBundle"]["verificationMaterial"]["publicKey"]["kmsUri"] == "mockkms://global/hsm-snapshot-publisher"

    verifier_keyring = Keyring(public_key_dir=key_pub, verification_only=True)
    res = verifier_keyring.verify_dsse(envelope)
    assert res.verified is True
    assert res.predicate_type == "https://schemas.proofofdata.dev/snapshot/v0.1"


def test_kms_key_rotation_and_revocation(tmp_path):
    keyring = Keyring(public_key_dir=tmp_path / "pub", private_key_dir=tmp_path / "priv")

    signer1 = MockKMSSigner(algorithm="ECDSA_P256_SHA256", kms_uri="mockkms://v1/key1")
    keyring.register_kms_signer(signer1, activate=True)
    key1_id = signer1.keyid

    stmt1 = _sample_attestation_statement()
    env1 = sign_statement(stmt1, keyring)
    assert env1["signatures"][0]["keyid"] == key1_id

    # Rotate to KMS signer 2
    signer2 = MockKMSSigner(algorithm="ECDSA_P256_SHA256", kms_uri="mockkms://v2/key2")
    keyring.register_kms_signer(signer2, activate=True)
    key2_id = signer2.keyid
    assert key2_id != key1_id

    # Active key is now key2
    meta_key1 = keyring.get_key_metadata(key1_id)
    assert meta_key1["status"] == "rotated"
    assert meta_key1["rotated_at"] is not None

    stmt2 = _sample_attestation_statement()
    stmt2["predicate"]["identity"]["locator"] = "file:///pc_demo_folder/02_quarterly_report.xlsx"
    stmt2["subject"][0]["name"] = stmt2["predicate"]["identity"]["locator"]
    env2 = sign_statement(stmt2, keyring)
    assert env2["signatures"][0]["keyid"] == key2_id

    # Both envelopes verify
    assert verify_dsse_envelope(env1, keyring).verified is True
    assert verify_dsse_envelope(env2, keyring).verified is True

    # Revoke key 1
    keyring.revoke_key(key1_id)
    with pytest.raises(SignatureVerificationError) as exc_info:
        verify_dsse_envelope(env1, keyring)
    assert "has been revoked" in str(exc_info.value)

    # Key 2 envelope still verifies
    assert verify_dsse_envelope(env2, keyring).verified is True


def test_hashicorp_vault_transit_signer_ecdsa(tmp_path):
    """Test HashiCorp Vault Transit Engine ECDSA P-256 signing and offline verification."""
    from cryptography.hazmat.primitives.asymmetric import ec

    vault_priv_key = ec.generate_private_key(ec.SECP256R1())
    vault_pub_pem = vault_priv_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    mock_vault_client = MagicMock()
    mock_vault_client.read_key.return_value = {
        "data": {
            "type": "ecdsa-p256",
            "keys": {
                "1": {"public_key": vault_pub_pem}
            },
        }
    }

    def _mock_sign_data(name, mount_point, prompt_input):
        raw_data = base64.b64decode(prompt_input)
        sig = vault_priv_key.sign(raw_data, ec.ECDSA(hashes.SHA256()))
        sig_b64 = base64.b64encode(sig).decode("ascii")
        return {"data": {"signature": f"vault:v1:{sig_b64}"}}

    mock_vault_client.sign_data.side_effect = _mock_sign_data

    keyring = Keyring(public_key_dir=tmp_path / "pub", private_key_dir=tmp_path / "priv")
    signer = HashiCorpVaultTransitSigner(
        key_name="docket-ecdsa-key",
        vault_addr="https://vault.corp.internal:8200",
        mount_path="transit",
        algorithm="ECDSA_P256_SHA256",
        vault_client=mock_vault_client,
    )

    meta = keyring.register_kms_signer(signer, activate=True)
    assert meta["is_kms"] is True
    assert meta["kms_uri"] == "vaultkms://vault.corp.internal:8200/transit/keys/docket-ecdsa-key"
    assert meta["algorithm"] == "ECDSA_P256_SHA256"

    # Sign statement using Vault Transit
    stmt = _sample_attestation_statement()
    envelope = sign_statement(stmt, keyring)

    # Verify DSSE envelope
    assert envelope["signatures"][0]["keyid"] == signer.keyid
    sigstore = envelope["sigstoreBundle"]["verificationMaterial"]["publicKey"]
    assert sigstore["kmsUri"] == "vaultkms://vault.corp.internal:8200/transit/keys/docket-ecdsa-key"

    # Offline verification with zero Vault calls
    res = verify_dsse_envelope(envelope, keyring)
    assert res.verified is True
    assert res.keyid == signer.keyid


def test_hashicorp_vault_transit_signer_ed25519(tmp_path):
    """Test HashiCorp Vault Transit Engine Ed25519 signing and offline verification."""
    from cryptography.hazmat.primitives.asymmetric import ed25519

    vault_priv_key = ed25519.Ed25519PrivateKey.generate()
    vault_pub_pem = vault_priv_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    mock_vault_client = MagicMock()
    mock_vault_client.read_key.return_value = {
        "data": {
            "type": "ed25519",
            "keys": {
                "1": {"public_key": vault_pub_pem}
            },
        }
    }

    def _mock_sign_data(name, mount_point, prompt_input):
        raw_data = base64.b64decode(prompt_input)
        sig = vault_priv_key.sign(raw_data)
        sig_b64 = base64.b64encode(sig).decode("ascii")
        return {"data": {"signature": f"vault:v1:{sig_b64}"}}

    mock_vault_client.sign_data.side_effect = _mock_sign_data

    keyring = Keyring(public_key_dir=tmp_path / "pub", private_key_dir=tmp_path / "priv")
    signer = HashiCorpVaultTransitSigner(
        key_name="docket-ed25519-key",
        vault_addr="http://127.0.0.1:8200",
        mount_path="transit",
        algorithm="Ed25519",
        vault_client=mock_vault_client,
    )

    meta = keyring.register_kms_signer(signer, activate=True)
    assert meta["is_kms"] is True
    assert meta["kms_uri"] == "vaultkms://127.0.0.1:8200/transit/keys/docket-ed25519-key"
    assert meta["algorithm"] == "Ed25519"

    stmt = _sample_attestation_statement()
    envelope = sign_statement(stmt, keyring)

    res = verify_dsse_envelope(envelope, keyring)
    assert res.verified is True
    assert res.algorithm == "Ed25519"


def test_re_sign_active_records_after_key_rotation(tmp_path):
    db_url = f"sqlite:///{(tmp_path / 'resign.db').as_posix()}"
    key_dir = tmp_path / "keys"
    key_dir.mkdir(parents=True, exist_ok=True)

    reg = RegistryService(db_url=db_url, key_dir=key_dir)

    # Issue initial record under key1
    key1_id = reg.keyring.ensure_active_key()["keyid"]
    res = reg.issue_or_queue_finding(
        locator="file:///data/confidential_report.pdf",
        content_sha256="a" * 64,
        tier="Confidential",
        steward="infosec@yourcompany.com",
        owner="finance@yourcompany.com",
    )
    rec = res["record"]
    sig1 = rec["dsse_envelope"]["signatures"][0]
    assert sig1["keyid"] == key1_id

    # Rotate to a new key
    new_meta = reg.keyring.rotate_key(algorithm="ECDSA_P256_SHA256")
    key2_id = new_meta["keyid"]
    assert reg.keyring.ensure_active_key()["keyid"] == key2_id

    # Re-sign active records
    re_signed = reg.re_sign_active_records()
    assert len(re_signed) == 1
    sig2 = re_signed[0]["dsse_envelope"]["signatures"][0]
    assert sig2["keyid"] == key2_id

    # Verify signature verifies with keyring
    env2 = re_signed[0]["dsse_envelope"]
    v = verify_dsse_envelope(env2, reg.keyring)
    assert v.verified is True
    assert v.keyid == key2_id

    reg.close()

