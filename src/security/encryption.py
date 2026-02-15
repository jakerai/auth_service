from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from src.config.logger import Logger
from src.config.settings import JWT_MASTER_SECRET

log = Logger().get_logger()

class KeyEncryptionService:
    def __init__(self):
        # Equivalent to Java: this.secret = properties.get...
        self.secret = JWT_MASTER_SECRET
        
        # Java strict validation check
        if len(self.secret) not in [16, 24, 32]:
            raise ValueError("AES key must be 16, 24, or 32 bytes long")
            
        self.key_bytes = self.secret.encode("utf-8")
        log.info("[KeyEncryptionService] Loading encryption key...")

    def encrypt(self, data: bytes) -> bytes:
        try:
            # AES/ECB/PKCS7Padding
            cipher = AES.new(self.key_bytes, AES.MODE_ECB)
            # Use PyCryptodome's built-in padding for reliability
            padded_data = pad(data, AES.block_size) 
            return cipher.encrypt(padded_data)
        except Exception as e:
            log.error(f"Error during encryption: {e}")
            raise RuntimeError("Failed to encrypt data") from e

    def decrypt(self, data: bytes) -> bytes:
        try:
            cipher = AES.new(self.key_bytes, AES.MODE_ECB)
            decrypted_padded = cipher.decrypt(data)
            # Remove PKCS7 padding
            return unpad(decrypted_padded, AES.block_size)
        except Exception as e:
            log.error(f"Error during decryption: {e}")
            raise RuntimeError("Failed to decrypt data") from e