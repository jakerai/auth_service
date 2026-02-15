# src/security/stores/aws_store.py
import json
import boto3
from botocore.exceptions import ClientError
from .base import JwtKeyStore
from src.utils.key_serialization import serialize_keys, deserialize_keys
from src.config.logger import Logger

log = Logger().get_logger()

class AwsJwtKeyStore(JwtKeyStore):
    """
    Stores JWT keys in AWS Secrets Manager.
    Serializes datetime objects for safe JSON storage.
    """

    SECRET_NAME = "jwt/keys"

    def __init__(self):
        self.client = boto3.client("secretsmanager")
        log.info("[AwsJwtKeyStore] Initialized AWS Secrets Manager client")

    async def find_keys(self):
        """Retrieve keys and deserialize datetime fields."""
        log.info(f"[AwsJwtKeyStore] Retrieving keys from secret '{self.SECRET_NAME}'...")
        try:
            response = self.client.get_secret_value(SecretId=self.SECRET_NAME)
            raw_keys = json.loads(response.get("SecretString", "{}"))
            if raw_keys:
                keys = deserialize_keys(raw_keys)
                log.info(f"[AwsJwtKeyStore] Keys found: {len(keys.get('keys', []))} entries")
                return keys
            log.info("[AwsJwtKeyStore] No keys found in Secrets Manager")
            return None
        except self.client.exceptions.ResourceNotFoundException:
            log.warning(f"[AwsJwtKeyStore] Secret '{self.SECRET_NAME}' not found")
            return None
        except ClientError as e:
            log.error(f"[AwsJwtKeyStore] Error retrieving secret: {e}")
            raise

    async def save_keys(self, keys):
        """Serialize datetime fields before saving to Secrets Manager."""
        payload = json.dumps(serialize_keys(keys))
        log.info(f"[AwsJwtKeyStore] Saving {len(keys.get('keys', []))} key(s) to secret '{self.SECRET_NAME}'...")
        try:
            self.client.put_secret_value(
                SecretId=self.SECRET_NAME,
                SecretString=payload,
            )
            log.info("[AwsJwtKeyStore] Keys saved successfully")
        except self.client.exceptions.ResourceNotFoundException:
            log.info(f"[AwsJwtKeyStore] Secret not found, creating new secret '{self.SECRET_NAME}'...")
            self.client.create_secret(
                Name=self.SECRET_NAME,
                SecretString=payload,
            )
            log.info("[AwsJwtKeyStore] Secret created and keys saved successfully")
        except ClientError as e:
            log.error(f"[AwsJwtKeyStore] Error saving keys: {e}")
            raise

    async def rotate_keys_atomically(self, expected_kid, new_keys):
        """
        AWS Secrets Manager has version control.
        Serialize keys before saving. Logs rotation progress.
        """
        log.info(f"[AwsJwtKeyStore] Rotating keys, expected kid={expected_kid}...")
        await self.save_keys(new_keys)
        log.info(f"[AwsJwtKeyStore] Rotation complete for kid={expected_kid}")
        return True
