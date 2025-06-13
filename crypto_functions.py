import json, socket
from typing import Any, Dict, Tuple
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

# --- Helpers ---

def kdf(*shared_secrets: bytes) -> bytes:
    concatenated = b''.join(shared_secrets)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'session key derivation',
    )
    return hkdf.derive(concatenated)

def hash_md5(data: bytes) -> str:
    digest = hashes.Hash(hashes.MD5())
    digest.update(data)
    return digest.finalize().hex()

def serialize_public_key(key: X25519PublicKey | Ed25519PublicKey) -> bytes:
    return key.public_bytes(Encoding.Raw, PublicFormat.Raw)

def deserialize_x25519_public_key(data: bytes) -> X25519PublicKey:
    return X25519PublicKey.from_public_bytes(data)

def deserialize_ed25519_public_key(data: bytes) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(data)

# --- User key publication ---

# IMPORTANT: call this function as my_keys = generate_and_publish_keys(...)

def generate_and_publish_keys(sock: socket.socket, user_id: str) -> Dict[str, Any]:
    # IK: signature key pair
    IK_sign_priv = Ed25519PrivateKey.generate()
    IK_sign_pub = IK_sign_priv.public_key()

    # IK for DH
    IK_dh_priv = X25519PrivateKey.generate()
    IK_dh_pub = IK_dh_priv.public_key()

    # Pre-Key
    PK_priv = X25519PrivateKey.generate()
    PK_pub = PK_priv.public_key()

    # SPK = signature of PK_pub using IK_sign_priv
    pk_pub_bytes = serialize_public_key(PK_pub)
    signature = IK_sign_priv.sign(pk_pub_bytes)

    payload = {
        "type": "publish_keys",
        "user_id": user_id,
        "IK_sign_pub": IK_sign_pub.public_bytes(Encoding.Raw, PublicFormat.Raw).hex(),
        "IK_dh_pub": serialize_public_key(IK_dh_pub).hex(),
        "PK_pub": pk_pub_bytes.hex(),
        "SPK_sig": signature.hex()
    }

    sock.sendall(json.dumps(payload).encode())

    return {
        "IK_sign_priv": IK_sign_priv,
        "IK_sign_pub": IK_sign_pub,
        "IK_dh_priv": IK_dh_priv,
        "IK_dh_pub": IK_dh_pub,
        "PK_priv": PK_priv,
        "PK_pub": PK_pub,
        "user_id": user_id
    }

# --- Ephemeral key publication ---

def publish_ephemeral(sock: socket.socket, user_id: str, EK_pub: X25519PublicKey) -> None:
    payload = {
        "type": "publish_ephemeral",
        "user_id": user_id,
        "EK_pub": serialize_public_key(EK_pub).hex()
    }
    sock.sendall(json.dumps(payload).encode())

# --- Fetch ephemeral key from the other party ---

def fetch_ephemeral(sock: socket.socket, user_id: str) -> X25519PublicKey:
    request = {
        "type": "fetch_ephemeral",
        "user_id": user_id
    }
    sock.sendall(json.dumps(request).encode())
    response = sock.recv(4096)
    data = json.loads(response.decode())
    return deserialize_x25519_public_key(bytes.fromhex(data["EK_pub"]))

# --- Fetch recipient's keys from the server ---

# IMPORTANT: call as recipient_keys = fetch_recipient_keys(...)

def fetch_recipient_keys(sock: socket.socket, recipient_id: str) -> Dict[str, Any]:
    request = {
        "type": "fetch_keys",
        "user_id": recipient_id
    }
    sock.sendall(json.dumps(request).encode())
    response = sock.recv(4096)
    data = json.loads(response.decode())

    IK_sign_pub = deserialize_ed25519_public_key(bytes.fromhex(data["IK_sign_pub"]))
    IK_dh_pub = deserialize_x25519_public_key(bytes.fromhex(data["IK_dh_pub"]))
    PK_pub = deserialize_x25519_public_key(bytes.fromhex(data["PK_pub"]))
    SPK_sig = bytes.fromhex(data["SPK_sig"])

    # Verify SPK signature
    IK_sign_pub.verify(SPK_sig, serialize_public_key(PK_pub))

    return {
        "IK_sign_pub": IK_sign_pub,
        "IK_dh_pub": IK_dh_pub,
        "PK_pub": PK_pub
    }

# --- Initiator (A) ---

def establish_session_key_initiator(
    sock: socket.socket,
    my_keys: Dict[str, Any],
    recipient_id: str
) -> Tuple[bytes, str]:
    recipient_keys = fetch_recipient_keys(sock, recipient_id)

    # Generate EK
    EK_priv = X25519PrivateKey.generate()
    EK_pub = EK_priv.public_key()

    # DH exchanges
    DH1 = my_keys["IK_dh_priv"].exchange(recipient_keys["PK_pub"])
    DH2 = EK_priv.exchange(recipient_keys["IK_dh_pub"])
    DH3 = EK_priv.exchange(recipient_keys["PK_pub"])

    SK = kdf(DH1, DH2, DH3)
    md5_hash = hash_md5(SK)

    # Publish EK
    publish_ephemeral(sock, my_keys["user_id"], EK_pub)

    return SK, md5_hash

# --- Responder (B) ---

def establish_session_key_responder(
    sock: socket.socket,
    my_keys: Dict[str, Any],
    sender_id: str
) -> Tuple[bytes, str]:
    EK_pub = fetch_ephemeral(sock, sender_id)
    sender_keys = fetch_recipient_keys(sock, sender_id)

    # DH exchanges
    DH1 = sender_keys["IK_dh_pub"].exchange(my_keys["PK_priv"])
    DH2 = EK_pub.exchange(my_keys["IK_dh_priv"])
    DH3 = EK_pub.exchange(my_keys["PK_priv"])

    SK = kdf(DH1, DH2, DH3)
    md5_hash = hash_md5(SK)

    return SK, md5_hash

