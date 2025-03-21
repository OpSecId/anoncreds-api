import uuid
from typing import Any, Dict, List, Union

from pydantic import BaseModel, Field, field_validator
from config import settings


class Statement(BaseModel):
    type: str = Field()


class Signature(BaseModel):
    # type: str =Field("Signature")
    disclosed: List[str] = Field([])
    verificationMethod: str = Field(example="zQmb5W91ceoJoRD6DaDLfrRJLkm7H78EaTHCSJkHdHW8Kyh")


class Revocation(BaseModel):
    # type: str =Field("Revocation")
    # signatureIndex: int = Field(0)
    # claimRef: Union[str, int] = Field(0)
    accumulator: Union[str, None] = Field(None)


class Range(BaseModel):
    # type: str =Field("Range")
    # commitmentIndex: int = Field()
    # signatureIndex: int = Field(0)
    # claimRef: Union[str, int] = Field()
    lower: int = Field(None)
    upper: int = Field(None)


class Commitment(BaseModel):
    # type: str =Field("Commitment")
    # signatureIndex: int = Field(0)
    claimRef: str = Field(example="name")
    messageGenerator: str = Field()
    blinderGenerator: str = Field()
    range: Range = Field(None)


class Encryption(BaseModel):
    # type: str =Field("Encryption")
    # signatureIndex: int = Field(0)
    claimRef: str = Field(example="credentialId")
    domain: str = Field(example="example.com")
    encryptionKey: str = Field(None, example=settings.TEST_VALUES.get("encryption_key"))


class Membership(BaseModel):
    # type: str =Field("Membership")
    # signatureIndex: int = Field(0)
    claimRef: str = Field()
    accumulator: str = Field()
    verificationKey: str = Field(example="zQmb5W91ceoJoRD6DaDLfrRJLkm7H78EaTHCSJkHdHW8Kyh")


class EqualityClaim(BaseModel):
    claimRef: str = Field(example="name")
    signatureRef: int = Field(example=0)


class Equality(BaseModel):
    # type: str =Field("Equality")
    claims: List[EqualityClaim] = Field()


class ProofRequest(BaseModel):
    # type: str =Field("Equality")
    label: str = Field(example="Signature request 123")
    verificationMethod: str = Field(example="zQmb5W91ceoJoRD6DaDLfrRJLkm7H78EaTHCSJkHdHW8Kyh")
    disclosed: List[str] = Field([])
    revocation: bool = Field(True)
    commitment: List[Commitment] = Field()
    # membership: List[Membership]= Field()
    encryption: List[Encryption] = Field()


class SignatureQuery(BaseModel):
    type: str = Field("SignatureQuery")
    refId: str = Field(example="signature-request-for-some-credential")
    disclosed: List[str] = Field([])
    # revocation: bool = Field(True)
    commitment: List[Commitment] = Field()
    encryption: List[Encryption] = Field()
    verificationMethod: str = Field(example="zQmb5W91ceoJoRD6DaDLfrRJLkm7H78EaTHCSJkHdHW8Kyh")


class EqualityQuery(BaseModel):
    type: str = Field("EqualityQuery")
    refId: str = Field(example="are-names-equal")
    claims: List[EqualityClaim] = Field()
