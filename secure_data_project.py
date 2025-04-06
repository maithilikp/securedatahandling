from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import os


if os.path.exists("private_key.pem") and os.path.exists("public_key.pem"):
    # Load existing keys
    with open("private_key.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
    with open("public_key.pem", "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())
else:
    # Generate new keys
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    # Save the keys
    with open("private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open("public_key.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

user_message = input("Enter a message to encrypt: ")
message = user_message.encode()

signature = private_key.sign(
    message,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

ciphertext = public_key.encrypt(
    message,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

with open("encrypted_message.bin", "wb") as f:
    f.write(ciphertext)

with open("signature.bin", "wb") as f:
    f.write(signature)

print("Encrypted message and signature saved to files.")
with open("encrypted_message.bin", "rb") as f:
    loaded_ciphertext = f.read()

with open("signature.bin", "rb") as f:
    loaded_signature = f.read()
decrypted_message = private_key.decrypt(
    loaded_ciphertext,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

print("Message decrypted successfully!")
print("Decrypted message:", decrypted_message.decode())


try:
    public_key.verify(
        loaded_signature,
        decrypted_message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("Signature is valid!")
except Exception as e:
    print("Signature verification failed:", e)
