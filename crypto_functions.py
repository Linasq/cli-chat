from typing import Any, Dict, Tuple
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

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


def hash_sha3(data: bytes):
    digest = hashes.Hash(hashes.SHA3_256())
    digest.update(data)
    return digest.finalize()


def x25519_pubkey_to_bytes(pubkey: X25519PublicKey) -> bytes:
    return pubkey.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )


def x25519_pubkey_from_bytes(data: bytes) -> X25519PublicKey:
    return X25519PublicKey.from_public_bytes(data)


def ed25519_pubkey_to_bytes(pubkey: Ed25519PublicKey) -> bytes:
    return pubkey.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

def ed25519_pubkey_from_bytes(data: bytes) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(data)

# --- User key publication ---

# IMPORTANT: call this function as my_keys = generate_and_publish_keys(...)

def generate_keys_to_send(user_id: str) -> Tuple[Dict[str, str], Dict[str, Any]]:
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
    signature = IK_sign_priv.sign(x25519_pubkey_to_bytes(PK_pub))

    payload = {
        "type": "publish_keys",
        "user_id": user_id,
        "IK_sign_pub": ed25519_pubkey_to_bytes(IK_sign_pub).hex(),
        "IK_dh_pub": x25519_pubkey_to_bytes(IK_dh_pub).hex(),
        "PK_pub": x25519_pubkey_to_bytes(PK_pub).hex(),
        "SPK_sig": signature.hex()
    }


    my_keys = {
        "IK_sign_priv": IK_sign_priv,
        "IK_sign_pub": IK_sign_pub,
        "IK_dh_priv": IK_dh_priv,
        "IK_dh_pub": IK_dh_pub,
        "PK_priv": PK_priv,
        "PK_pub": PK_pub,
        "user_id": user_id
    }

    return payload, my_keys


# --- Initiator (A) ---
#before calling this function you need to fetch recipient keys from the server and pass it as an argument for this function
def establish_session_key_initiator(user_id: str, my_keys: Dict[str, Any], recipient_keys: Dict[str, Any]):
    # Generate EK
    EK_priv = X25519PrivateKey.generate()
    EK_pub = EK_priv.public_key()

    IK_sign_pub = ed25519_pubkey_from_bytes(bytes.fromhex(recipient_keys["IK_sign_pub"]))
    IK_dh_pub = x25519_pubkey_from_bytes(bytes.fromhex(recipient_keys["IK_dh_pub"]))
    PK_pub = x25519_pubkey_from_bytes(bytes.fromhex(recipient_keys["PK_pub"]))
    SPK_sig = bytes.fromhex(recipient_keys["SPK_sig"])
    pk_pub_bytes = x25519_pubkey_to_bytes(PK_pub)

    try:
        IK_sign_pub.verify(SPK_sig, pk_pub_bytes)
    except InvalidSignature:
        return None, None, None

    # DH exchanges
    DH1 = my_keys["IK_dh_priv"].exchange(PK_pub)
    DH2 = EK_priv.exchange(IK_dh_pub)
    DH3 = EK_priv.exchange(PK_pub)

    SK = kdf(DH1, DH2, DH3)
    md5_hash = hash_md5(SK)

    # Publish EK
    ephemerals_to_send = {
            "type": "publish_ephemeral",
            "user_id": user_id,
            "responder_id": recipient_keys[user_id],
            "EK_pub": x25519_pubkey_to_bytes(EK_pub).hex()
            }

    return SK, md5_hash, ephemerals_to_send

# --- Responder (B) ---
#before calling this function you need to fech for sender keys and ephemearl public key and pass it as arguments for this function
def establish_session_key_responder(my_keys: Dict[str, Any], sender_keys: Dict[str, Any], ephemeral: Dict[str, Any]):
    
    IK_sign_pub = ed25519_pubkey_from_bytes(bytes.fromhex(sender_keys["IK_sign_pub"]))
    IK_dh_pub = x25519_pubkey_from_bytes(bytes.fromhex(sender_keys["IK_dh_pub"]))
    PK_pub = x25519_pubkey_from_bytes(bytes.fromhex(sender_keys["PK_pub"]))
    SPK_sig = bytes.fromhex(sender_keys["SPK_sig"])
    pk_pub_bytes = x25519_pubkey_to_bytes(PK_pub)

    try:
        IK_sign_pub.verify(SPK_sig, pk_pub_bytes)
    except InvalidSignature:
        return None, None 

    EK_pub = x25519_pubkey_from_bytes(bytes.fromhex(ephemeral["EK_pub"]))

    # DH exchanges

    DH1 = my_keys["PK_priv"].exchange(IK_dh_pub)
    DH2 = my_keys["IK_dh_priv"].exchange(EK_pub)
    DH3 = my_keys["PK_priv"].exchange(EK_pub)

    SK = kdf(DH1, DH2, DH3)
    md5_hash = hash_md5(SK)

    return SK, md5_hash


def encrypt_db(key: bytes, db_name: str):
    """
    Encrypts a db using AES-256 in ECB mode with PKCS7 padding.

    Args:
        key (bytes): 32-byte key (256 bits).
        db_name (str): path to db
    """
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes long (256 bits)")

    with open(db_name, 'rb') as f:
        msg = f.read()

    # Padding (PKCS7)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(msg) + padder.finalize()

    # Cipher AES-256 in ECB mode
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    with open(db_name, 'wb') as f:
        f.write(ciphertext)


def decrypt_db(key: bytes, db_name: str):
    """
    Dcrypts a db encrypted using AES-256 in ECB mode with PKCS7 padding.

    Args:
        key (bytes): 32-byte AES key (256 bits).
        db_name: str path to db

    Returns:
        bytes: Decrypted plaintext message.
    """
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes long (256 bits)")

    with open(db_name, 'rb') as f:
        ciphertext = f.read()

    # Cipher AES-256 in ECB mode
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Usunięcie paddingu (PKCS7)
    unpadder = padding.PKCS7(128).unpadder()
    msg = unpadder.update(padded_data) + unpadder.finalize()

    with open(db_name, 'wb') as f:
        f.write(msg)

# --- data to send/recive format ---
    # basic keys to send
    # payload = {
    #     "type": "publish_keys",
    #     "user_id": user_id,
    #     "IK_sign_pub": IK_sign_pub.public_bytes(Encoding.Raw, PublicFormat.Raw).hex(),
    #     "IK_dh_pub": serialize_public_key(IK_dh_pub).hex(),
    #     "PK_pub": pk_pub_bytes.hex(),
    #     "SPK_sig": signature.hex()
    # }
    # request for basic keys
    #    request = {
    #       "type": "fetch_keys",
    #       "user_id": recipient_id
    #       }
    # your keys returned in generate_keys_to_send
    # my_keys = {
    #     "IK_sign_priv": IK_sign_priv,
    #     "IK_sign_pub": IK_sign_pub,
    #     "IK_dh_priv": IK_dh_priv,
    #     "IK_dh_pub": IK_dh_pub,
    #     "PK_priv": PK_priv,
    #     "PK_pub": PK_pub,
    #     "user_id": user_id
    #     }
    # REMEMBER TO DESERIALISE SUCKERS YOU RECIVE FROM SERVER

