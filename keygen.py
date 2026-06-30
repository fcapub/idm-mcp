from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey 
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey 
from cryptography.exceptions import InvalidSignature

def generate_raw_keys():
    try:
        private_key = Ed25519PrivateKey.generate()
    
        raw_private_key = private_key.private_bytes_raw().hex()
    except Exception as e:
        print("Private key error:", e)
    
    try:
        public_key = private_key.public_key()
    
        raw_public_key = public_key.public_bytes_raw().hex()
    except Exception as e:
        print ("Public key error:", e)
    
    return raw_public_key, raw_private_key

def sign_rand(raw_secret_key_str: str, rand: int):
    sk_raw = bytes.fromhex(raw_secret_key_str)
    # Get secret key using raw secret key bytes
    secret_key = Ed25519PrivateKey.from_private_bytes(sk_raw)
    # encode rand
    encoded_rand = bytes(rand)
    # sign rand with secret key
    signed_rand = secret_key.sign(encoded_rand)
    
    return signed_rand

def sign_vc(raw_secret_key_str: str, vc: str):
    sk_raw = bytes.fromhex(raw_secret_key_str)
    # Get secret key using raw secret key bytes
    secret_key = Ed25519PrivateKey.from_private_bytes(sk_raw)
    # encode rand
    encoded_rand = bytes(vc, "utf-8")
    # sign rand with secret key
    signed_rand = secret_key.sign(encoded_rand)
    
    return signed_rand

def verify_rand(raw_public_key_str: str, rand: int, signed_rand: bytes):
    # get raw public key from public key string
    pk_raw = bytes.fromhex(raw_public_key_str)
    # Get public key using raw public key bytes
    public_key = Ed25519PublicKey.from_public_bytes(pk_raw)
    # encode rand
    encoded_rand = bytes(rand)
    # verify rand with signed rand
    try:
        public_key.verify(signed_rand, encoded_rand)
    except InvalidSignature:
        return False # invalid

    return True # valid

def verify_vc(raw_public_key_str: str, vc: str, signed_vc: bytes):
    # get raw public key from public key string
    pk_raw = bytes.fromhex(raw_public_key_str)
    # Get public key using raw public key bytes
    public_key = Ed25519PublicKey.from_public_bytes(pk_raw)
    # encode vc
    encoded_vc = bytes(vc, "utf-8")
    # verify vc with signed vc
    try:
        public_key.verify(signed_vc, encoded_vc)
    except InvalidSignature:
        return False # invalid

    return True # valid

if __name__ == '__main__':
  pk, sk = generate_raw_keys()
  print('Public Key:', pk)
  print('Secret Key:', sk)