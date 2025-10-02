from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

def load_private_key(path="keys/private.pem"):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def load_public_key(path="keys/public.pem"):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())

def sign_report_file(file_path, priv_key_path="keys/private.pem"):
    priv = load_private_key(priv_key_path)
    with open(file_path, "rb") as f:
        data = f.read()
    signature = priv.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    sig_path = file_path + ".sig"
    with open(sig_path, "wb") as s:
        s.write(signature)
    return sig_path

def verify_signature(pub_key_path, data_path, sig_path):
    pub = load_public_key(pub_key_path)
    with open(data_path, "rb") as f:
        data = f.read()
    with open(sig_path, "rb") as f:
        sig = f.read()
    try:
        pub.verify(sig, data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        return True
    except Exception:
        return False
