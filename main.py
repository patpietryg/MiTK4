from fastapi import FastAPI, HTTPException
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from typing import Optional
import base64
import uvicorn

app = FastAPI()

symmetric_key = None
asymmetric_public_key = None
asymmetric_private_key = None


def generate_symmetric_key():
    return Fernet.generate_key()


def generate_asymmetric_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key


def encrypt_message_symmetric(message: bytes, key: bytes):
    fernet = Fernet(key)
    encrypted_message = fernet.encrypt(message)
    return encrypted_message


def decrypt_message_symmetric(encrypted_message: bytes, key: bytes):
    fernet = Fernet(key)
    decrypted_message = fernet.decrypt(encrypted_message)
    return decrypted_message


def sign_message(message: bytes, private_key):
    signature = private_key.sign(
        message, padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature


def verify_signature(message: bytes, signature: bytes, public_key):
    try:
        public_key.verify(
            signature, message, padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


@app.get("/symmetric/key")
def get_symmetric_key():
    global symmetric_key
    symmetric_key = generate_symmetric_key()
    return {"key": symmetric_key.hex()}


@app.post("/symmetric/key")
def set_symmetric_key(key: str):
    global symmetric_key
    try:
        symmetric_key = bytes.fromhex(key)
        return {"message": "Symmetric key set successfully."}
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid symmetric key format.")


@app.post("/symmetric/encode")
def encode_symmetric(message: str):
    global symmetric_key
    if symmetric_key is None:
        raise HTTPException(status_code=400, detail="Symmetric key not set.")
    encrypted_message = encrypt_message_symmetric(message.encode(), symmetric_key)
    return {"encrypted_message": encrypted_message.decode()}


@app.post("/symmetric/decode")
def decode_symmetric(encrypted_message: str):
    global symmetric_key
    if symmetric_key is None:
        raise HTTPException(status_code=400, detail="Symmetric key not set.")
    decrypted_message = decrypt_message_symmetric(
        encrypted_message.encode(), symmetric_key
    )
    return {"decrypted_message": decrypted_message.decode()}


@app.get("/asymmetric/key")
def get_asymmetric_key():
    global asymmetric_private_key, asymmetric_public_key
    asymmetric_private_key, asymmetric_public_key = generate_asymmetric_keys()
    return {
        "private_key": asymmetric_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode(),
        "public_key": asymmetric_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
    }


@app.get("/asymmetric/key/ssh")
def get_asymmetric_key_ssh():
    global asymmetric_private_key, asymmetric_public_key
    if asymmetric_private_key is None or asymmetric_public_key is None:
        raise HTTPException(status_code=400, detail="Asymmetric keys not generated.")
    private_key_ssh = asymmetric_private_key.private_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()
    public_key_ssh = asymmetric_public_key.public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH
    ).decode()
    return {"private_key_ssh": private_key_ssh, "public_key_ssh": public_key_ssh}


@app.post("/asymmetric/key")
def set_asymmetric_key(keys: dict):
    global asymmetric_private_key, asymmetric_public_key
    try:
        private_bytes = keys["private_key"].encode()
        public_bytes = keys["public_key"].encode()
        asymmetric_private_key = serialization.load_pem_private_key(
            private_bytes, password=None
        )
        asymmetric_public_key = serialization.load_pem_public_key(public_bytes)
        return {"message": "Asymmetric keys set successfully."}
    except KeyError:
        raise HTTPException(status_code=400, detail="Private or public key missing.")
    except ValueError:
        raise HTTPException(
            status_code=400, detail="Invalid private or public key format."
        )


@app.post("/asymmetric/verify")
def verify_asymmetric(message: str, signature: str):
    global asymmetric_private_key
    if asymmetric_private_key is None:
        raise HTTPException(status_code=400, detail="Asymmetric key not set.")
    verified = verify_signature(
        message.encode(), base64.b64decode(signature), asymmetric_private_key
    )
    return {"verified": verified}


@app.post("/asymmetric/sign")
def sign_asymmetric(message: str):
    global asymmetric_public_key
    if asymmetric_public_key is None:
        raise HTTPException(status_code=400, detail="Asymmetric key not set.")
    signature = sign_message(message.encode(), asymmetric_public_key)
    return {"signature": base64.b64encode(signature).decode()}


@app.post("/asymmetric/encode")
def encode_asymmetric(message: str):
    global asymmetric_public_key
    if asymmetric_public_key is None:
        raise HTTPException(status_code=400, detail="Asymmetric key not set.")
    encrypted_message = asymmetric_public_key.encrypt(
        message.encode(), padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return {"encrypted_message": base64.b64encode(encrypted_message).decode()}


@app.post("/asymmetric/decode")
def decode_asymmetric(encrypted_message: str):
    global asymmetric_private_key
    if asymmetric_private_key is None:
        raise HTTPException(status_code=400, detail="Asymmetric key not set.")
    decrypted_message = asymmetric_private_key.decrypt(
        base64.b64decode(encrypted_message), padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return {"decrypted_message": decrypted_message.decode()}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
