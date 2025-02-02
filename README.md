# fad
he4ayaho
import ecdsa
import hashlib
import binascii

def generate_keys():
    private_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    public_key = private_key.get_verifying_key()
    return private_key.to_string().hex(), public_key.to_string().hex()

def sha256_hash(data):
    return hashlib.sha256(data.encode()).hexdigest()

def main():
    priv_key, pub_key = generate_keys()
    print(f"Private Key: {priv_key}")
    print(f"Public Key: {pub_key}")
    
    message = "Hello, blockchain!"
    hashed_message = sha256_hash(message)
    print(f"Message: {message}")
    print(f"SHA-256 Hash: {hashed_message}")

if __name__ == "__main__":
    main()
