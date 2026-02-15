from cryptography.hazmat.primitives.asymmetric import rsa
from src.config.settings import JWT_RSA_KEY_SIZE
from src.config.logger import Logger

log = Logger().get_logger()

class RsaKeyGenerator:
    """
    Python equivalent of the Telemetry Engine Java RsaKeyGenerator.
    Generates a new RSA public/private key pair (KeyPair).
    """

    def __init__(self, key_size: int = None):
        # Default to settings, similar to @RequiredArgsConstructor + AppSecurityProperties
        self.key_size = key_size or JWT_RSA_KEY_SIZE

    def generate(self):
        """
        Generates a new RSA public/private key pair.
        Returns: (private_key, public_key)
        """
        log.info(f"[RsaKeyGenerator] Generating a new RSA key pair (size: {self.key_size})")
        try:
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=self.key_size
            )
            public_key = private_key.public_key()
            
            # Returning a tuple is the Python version of returning a KeyPair object
            return private_key, public_key
            
        except Exception as e:
            log.error("[RsaKeyGenerator] Error while generating a new RSA key pair")
            # In Python, we re-raise or raise a specific domain exception
            raise RuntimeError("Failed to generate RSA key") from e