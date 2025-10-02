import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

os.makedirs("keys", exist_ok=True)

priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)

priv_bytes = priv.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

pub = priv.public_key()
pub_bytes = pub.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

with open("keys/private.pem", "wb") as f:
    f.write(priv_bytes)
with open("keys/public.pem", "wb") as f:
    f.write(pub_bytes)

print("✅ Generated keys/private.pem and keys/public.pem")
