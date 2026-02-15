import asyncio
import base64
import uuid
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from src.security.rsa_generator import RsaKeyGenerator
from src.security.encryption import KeyEncryptionService
from src.config.logger import Logger
from src.config.settings import (
    JWT_KEY_TTL_SECONDS,
    JWT_ROTATION_THRESHOLD_SECONDS,
    JWT_ROTATION_CHECK_INTERVAL_SECONDS
)

log = Logger().get_logger()


class JwtKeyManager:
    """Manages RSA keys for JWT signing/validation with rotation support."""

    _instance = None
    _lock = asyncio.Lock()
    rotation_interval = JWT_ROTATION_CHECK_INTERVAL_SECONDS

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self, store):
        if self._initialized:
            return

        self.store = store
        self.encryption = KeyEncryptionService()
        self.generator = RsaKeyGenerator()

        self.current_key_meta: Optional[dict] = None
        self.previous_key_meta: Optional[dict] = None

        self.cached_private_key: Optional[RSAPrivateKey] = None
        self.public_key_cache: Dict[str, RSAPublicKey] = {}

        self._initialized = True
        self._rotation_task: Optional[asyncio.Task] = None

    # -----------------------------------------
    # STARTUP
    # -----------------------------------------
    async def init(self):
        """Initialize keys and start background rotation task."""
        log.info("[JwtKeyManager] Initializing key manager...")
        await self.refresh_internal_state()

        # Immediate rotation check at startup
        #await self.rotate_if_needed()

        # Start background rotation loop
        self._start_rotation_task()

    # -----------------------------------------
    # LOAD / REFRESH FROM STORE
    # -----------------------------------------
    async def refresh_internal_state(self):
        async with self._lock:
            log.info("[JwtKeyManager] Refreshing keys from store")
            data = await self.store.find_keys() or {}
            keys = data.get("keys", [])

            self.current_key_meta = next(
                (k for k in keys if k["status"] == "CURRENT"), None
            )
            self.previous_key_meta = next(
                (k for k in keys if k["status"] == "PREVIOUS"), None
            )

            if not self.current_key_meta:
                log.info("[JwtKeyManager] No current key found → creating new one")
                self.current_key_meta = await self._create_new_key_and_save()

            self._rebuild_caches()

    # -----------------------------------------
    # CACHE
    # -----------------------------------------
    def _rebuild_caches(self):
        log.info("[JwtKeyManager] Building key cache")
        self.cached_private_key = self._decrypt_private_key(self.current_key_meta)

        self.public_key_cache = {
            self.current_key_meta["kid"]: self._build_public_key(
                self.current_key_meta["publicKey"]
            )
        }

        if self.previous_key_meta:
            self.public_key_cache[self.previous_key_meta["kid"]] = self._build_public_key(
                self.previous_key_meta["publicKey"]
            )

    # -----------------------------------------
    # PUBLIC ACCESS
    # -----------------------------------------
    async def get_public_key(self, kid: str) -> RSAPublicKey:
        key = self.public_key_cache.get(kid)
        if not key:
            await self.refresh_internal_state()
            key = self.public_key_cache.get(kid)
        if not key:
            raise ValueError(f"Unknown kid: {kid}")
        return key

    def get_private_key(self) -> RSAPrivateKey:
        return self.cached_private_key

    def get_current_kid(self) -> str:
        return self.current_key_meta["kid"]

    # -----------------------------------------
    # ROTATION
    # -----------------------------------------
    async def rotate_if_needed(self):
        """Rotate JWT keys if the current key is near expiry."""
        rotate_before = JWT_ROTATION_THRESHOLD_SECONDS
        now = datetime.now(timezone.utc)

        expires_at = self.current_key_meta.get("expiresAt")
        if isinstance(expires_at, str):
            expires_at = datetime.fromisoformat(expires_at)
        elif not isinstance(expires_at, datetime):
            expires_at = now + timedelta(seconds=JWT_KEY_TTL_SECONDS)

        # Check if rotation is required
        time_left = (expires_at - now).total_seconds()
        if time_left <= rotate_before:
            log.info(f"[JwtKeyManager] Rotation required: current key expires in {int(time_left)}s")
        else:
            log.info(f"[JwtKeyManager] Rotation skipped: current key still valid for {int(time_left)}s")
            return

        async with self._lock:
            log.info("[JwtKeyManager] Rotating keys")

            new_prev = self.current_key_meta.copy()
            new_prev["status"] = "PREVIOUS"

            new_current = self._create_new_key_dict()
            new_keys_array = {"keys": [new_prev, new_current]}

            try:
                success = await self.store.rotate_keys_atomically(
                    expected_current_kid=self.current_key_meta["kid"],
                    new_keys=new_keys_array,
                )
            except Exception as e:
                log.error(f"[JwtKeyManager] Error rotating keys: {e}")
                await self.refresh_internal_state()
                return

            if success:
                self.previous_key_meta = new_prev
                self.current_key_meta = new_current
                self._rebuild_caches()
                log.info("[JwtKeyManager] Key rotation successful")
            else:
                log.info("[JwtKeyManager] Rotation skipped or done by another instance")
                await self.refresh_internal_state()

    # -----------------------------------------
    # KEY CREATION
    # -----------------------------------------
    def _create_new_key_dict(self) -> dict:
        priv, pub = self.generator.generate()

        priv_bytes = priv.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        encrypted_priv = self.encryption.encrypt(priv_bytes)

        pub_bytes = pub.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        return {
            "kid": str(uuid.uuid4()),
            "publicKey": base64.b64encode(pub_bytes).decode(),
            "encryptedPrivateKey": base64.b64encode(encrypted_priv).decode(),
            "status": "CURRENT",
            "expiresAt": (datetime.now(timezone.utc) + timedelta(seconds=JWT_KEY_TTL_SECONDS)).isoformat(),
        }

    async def _create_new_key_and_save(self) -> dict:
        key = self._create_new_key_dict()
        self.current_key_meta = key
        await self._save_keys()
        return key

    # -----------------------------------------
    # BUILD / DECRYPT
    # -----------------------------------------
    def _decrypt_private_key(self, key_meta: dict) -> RSAPrivateKey:
        encrypted_bytes = base64.b64decode(key_meta["encryptedPrivateKey"])
        decrypted = self.encryption.decrypt(encrypted_bytes)
        return serialization.load_der_private_key(decrypted, password=None)

    def _build_public_key(self, b64: str) -> RSAPublicKey:
        return serialization.load_der_public_key(base64.b64decode(b64))

    # -----------------------------------------
    # SAVE
    # -----------------------------------------
    async def _save_keys(self):
        keys = [self.current_key_meta]
        if self.previous_key_meta:
            keys.append(self.previous_key_meta)
        await self.store.save_keys({"keys": keys})

    # -----------------------------------------
    # BACKGROUND ROTATION
    # -----------------------------------------
    def _start_rotation_task(self):
        if not self._rotation_task:
            log.info("[JwtKeyManager] Starting background key rotation task")
            self._rotation_task = asyncio.create_task(self._rotation_loop())

    async def _rotation_loop(self):
        """Run background rotation loop."""
        while True:
            try:
                await self.rotate_if_needed()
            except Exception as e:
                log.error(f"[JwtKeyManager] Error in background rotation: {e}")
            await asyncio.sleep(self.rotation_interval)
