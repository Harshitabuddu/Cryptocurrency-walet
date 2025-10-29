import os
import ecdsa
import hashlib
import base58

class SimpleCryptoWallet:
    def __init__(self):
        self.private_key = None
        self.public_key = None
        self.address = None

    def generate_keys(self):
        """Generate a new private key and derive public key & address."""
        self.private_key = os.urandom(32)  # 256-bit private key
        sk = ecdsa.SigningKey.from_string(self.private_key, curve=ecdsa.SECP256k1)
        vk = sk.get_verifying_key()
        self.public_key = b"\x04" + vk.to_string()  # Prefix for uncompressed key
        self.address = self.generate_address(self.public_key)

    def generate_address(self, public_key):
        """Generate a simple wallet address from a public key."""
        sha256_pubkey = hashlib.sha256(public_key).digest()
        ripemd160 = hashlib.new('ripemd160', sha256_pubkey).digest()
        versioned = b"\x00" + ripemd160  # Bitcoin mainnet prefix
        checksum = hashlib.sha256(hashlib.sha256(versioned).digest()).digest()[:4]
        return base58.b58encode(versioned + checksum).decode()

    def get_wallet_info(self):
        """Return wallet details."""
        return {
            "Private Key (hex)": self.private_key.hex(),
            "Public Key (hex)": self.public_key.hex(),
            "Address": self.address
        }

# Usage
wallet = SimpleCryptoWallet()
wallet.generate_keys()
wallet_info = wallet.get_wallet_info()

for key, value in wallet_info.items():
    print(f"{key}: {value}")
