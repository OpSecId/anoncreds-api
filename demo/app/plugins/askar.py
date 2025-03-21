"""Askar plugin for storing and verifying data."""

import hashlib
import json

from aries_askar import Store

from config import Config


class AskarStorage:
    """Askar storage plugin."""

    def __init__(self):
        """Initialize the Askar storage plugin."""
        self.db = Config.ASKAR_DB
        self.key = Store.generate_raw_key(
            hashlib.md5(Config.SECRET_KEY.encode()).hexdigest()
        )

    async def provision(self, recreate=False):
        """Provision the Askar storage."""
        await Store.provision(self.db, "raw", self.key, recreate=recreate)

    async def open(self):
        """Open the Askar storage."""
        return await Store.open(self.db, "raw", self.key)

    async def fetch(self, category, data_key):
        """Fetch data from the store."""
        store = await self.open()
        try:
            async with store.session() as session:
                data = await session.fetch(category, data_key)
            return json.loads(data.value)
        except Exception:
            return None

    async def store(self, category, data_key, data):
        """Store data in the store."""
        store = await self.open()
        try:
            async with store.session() as session:
                await session.insert(category, data_key, json.dumps(data))
        except Exception:
            return False

    async def update(self, category, data_key, data):
        """Update data in the store."""
        store = await self.open()
        try:
            async with store.session() as session:
                await session.replace(category, data_key, json.dumps(data))
        except Exception:
            return False
