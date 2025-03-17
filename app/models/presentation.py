import uuid
from typing import Any, Dict, List, Union

from pydantic import BaseModel, Field, field_validator
from config import settings


class Statement(BaseModel):
    type: str = Field()


class Commitment(BaseModel):
    claim: str = Field()
    messageGenerator: str = Field()
    blinderGenerator: str = Field()

class Revocation(BaseModel):
    accumulator: str = Field()

class VerifiableEncryption(BaseModel):
    claim: str = Field(example='revocationId')
    encryptionKey: str = Field(None, example=settings.TEST_VALUES.get('encryption_key'))


class Range(BaseModel):
    claim: str = Field()
    lower: int = Field(None)
    upper: int = Field(None)