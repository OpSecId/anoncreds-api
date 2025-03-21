"""Request body models."""

from typing import Any, Dict, List, Union

from pydantic import BaseModel, Field, field_validator
from .schema import JsonSchema
from .credential import Credential, CredentialRequest
from .presentation import (
    SignatureQuery,
    EqualityQuery,
    ProofRequest,
    Statement,
    Signature,
    Encryption,
    Revocation,
    Commitment,
    Range,
    Membership,
    Equality,
    EqualityClaim,
)
from config import settings


class BaseModel(BaseModel):
    """Base model for all models in the application."""

    def model_dump(self, **kwargs) -> Dict[str, Any]:
        """Dump the model to a dictionary."""
        return super().model_dump(by_alias=True, exclude_none=True, **kwargs)


class CredSchemaOptions(BaseModel):
    linkSecret: bool = Field(False)
    # setupIssuer: bool = Field(False)


class NewCredSchema(BaseModel):
    """NewCredSchema model."""

    # jsonSchemaUrl: str = Field(None, example="https://example.com")
    jsonSchema: JsonSchema = Field(None)
    options: CredSchemaOptions = Field(None)


class NewPresSchemaOptions(BaseModel):
    credDefId: str = Field()
    domain: str = Field(None, example="anoncreds.vc")
    disclosedClaims: List[str] = Field([], example=["name"])


class NewPresSchema(BaseModel):
    """NewPresSchema model."""

    query: List[Union[SignatureQuery, EqualityQuery]] = Field()
    # challenge: str = Field(None)
    # signatures: List[ProofRequest] = Field()
    # equalities: List[List[EqualityClaim]] = Field()


class SetupIssuerOptions(BaseModel):
    credSchemaId: str = Field(example=settings.TEST_VALUES.get("schema_id"))


class SetupIssuerRequest(BaseModel):
    """SetupIssuerRequest model."""

    credSchemaId: str = Field(example=settings.TEST_VALUES.get("schema_id"))
    # options: SetupIssuerOptions = Field()


class IssueCredentialOptions(BaseModel):
    credentialId: str = Field(None)
    verificationMethod: str = Field(example="zQmb5W91ceoJoRD6DaDLfrRJLkm7H78EaTHCSJkHdHW8Kyh")


class IssueCredentialRequest(BaseModel):
    """IssueCredentialRequest model."""

    credentialSubject: Dict[str, Union[str, int, float]] = Field(
        example={"name": "Alice"}
    )
    credentialRequest: dict = Field(None)
    options: IssueCredentialOptions = Field()


class BlindCredentialRequest(BaseModel):
    linkSecret: str = Field(
        None, example="5179bc1a7276e2d6dddca6915a57e7b8cd41326652f7760811d56de92a4fba86"
    )
    verificationMethod: str = Field(example="zQmb5W91ceoJoRD6DaDLfrRJLkm7H78EaTHCSJkHdHW8Kyh")


class MessageGeneratorRequest(BaseModel):
    """MessageGeneratorRequest model."""

    domain: str = Field(None)


class DecryptProofOption(BaseModel):
    """DecryptProofOption model."""

    decryptionKey: str = Field(example=settings.TEST_VALUES.get("decryption_key"))


class DecryptProofRequest(BaseModel):
    """DecryptProofRequest model."""

    proof: dict = Field()
    options: DecryptProofOption = Field()


class VerifyPresentationOption(BaseModel):
    """VerifyPresentationOption model."""

    challenge: str = Field()
    presSchemaId: str = Field()


class VerifyPresentationRequest(BaseModel):
    """VerifyPresentationRequest model."""

    presentation: dict = Field()
    options: VerifyPresentationOption = Field()


class CreatePresentationOption(BaseModel):
    """CreatePresentationOption model."""

    challenge: str = Field(None)
    presSchemaId: str = Field()


class CreatePresentationRequest(BaseModel):
    """CreatePresentationRequest model."""

    credential: dict = Field()
    options: CreatePresentationOption = Field()


class CredentialsIssueOptions(BaseModel):
    """CredentialsIssueRequest model."""

    credDefId: str = Field()
    credentialId: str = Field()


class CredentialsIssueRequest(BaseModel):
    """CreatePresentationRequest model."""

    credential: dict = Field()
    options: CredentialsIssueOptions = Field()


class CreateCommitmentRequest(BaseModel):
    """CreateCommitmentRequest model."""

    value: str = Field()
    domain: str = Field()
