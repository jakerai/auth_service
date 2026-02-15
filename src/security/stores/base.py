from abc import ABC, abstractmethod
from typing import Optional, Dict


class JwtKeyStore(ABC):

    @abstractmethod
    async def find_keys(self) -> Optional[Dict]:
        pass

    @abstractmethod
    async def save_keys(self, keys: Dict):
        pass

    @abstractmethod
    async def rotate_keys_atomically(self, expected_kid: str, new_keys: Dict) -> bool:
        pass
