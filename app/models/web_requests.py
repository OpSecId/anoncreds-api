"""This module defines the DataIntegrityProof model used for data integrity proofs."""

from typing import Any, Dict, List, Union

from pydantic import BaseModel, Field, field_validator
from .schema import JsonSchema
from .credential import Credential, CredentialRequest
from .presentation import Statement, VerifiableEncryption, Revocation
from config import settings


class BaseModel(BaseModel):
    """Base model for all models in the application."""

    def model_dump(self, **kwargs) -> Dict[str, Any]:
        """Dump the model to a dictionary."""
        return super().model_dump(by_alias=True, exclude_none=True, **kwargs)
    

class CreateSchemaOptions(BaseModel):
    linkSecret: bool = Field(False)
    

class CreateSchemaRequest(BaseModel):
    """CreateSchemaRequest model."""

    jsonSchema: JsonSchema = Field()
    options: CreateSchemaOptions = Field()
    

class SetupIssuerOptions(BaseModel):
    schemaId: str = Field(example=settings.TEST_VALUES.get('schema_id'))
    

class SetupIssuerRequest(BaseModel):
    """SetupIssuerRequest model."""
    
    options: SetupIssuerOptions = Field()
    
class IssueCredentialOptions(BaseModel):
    credDefId: str = Field()
    credentialId: str = Field(None)
    
class IssueCredentialRequest(BaseModel):
    """IssueCredentialRequest model."""

    credentialSubject: Dict[str, Union[str, int, float]] = Field(example={'name': 'Alice'})
    credentialRequest: dict = Field(None)
    options: IssueCredentialOptions = Field()

class BlindCredentialRequest(BaseModel):
    credDefId: str = Field()
    linkSecretId: str = Field()


class CreatePresReqOptions(BaseModel):
    credDefId: str = Field()
    domain: str = Field(None, example='anoncreds.vc')
    disclosedClaims: List[str] = Field([], example=['name'])
    

class CreatePresReqRequest(BaseModel):
    """CreatePresReqRequest model."""

    # statements: List[VerifiableEncryption] = Field()
    statements: Dict[str, Union[Revocation, VerifiableEncryption]] = Field(example={
        'revocation': {
            "accumulator": ""
        },
        'encryption': VerifiableEncryption(
            claim='revocationId', 
            domain='example.com', 
            encryptionKey=settings.TEST_VALUES.get('encryption_key')
        ),
    })
    options: CreatePresReqOptions = Field()
    

class MessageGeneratorRequest(BaseModel):
    """MessageGeneratorRequest model."""

    domain: str= Field(None)
    

class DecryptProofOption(BaseModel):
    """DecryptProofOption model."""
    decryptionKey: str = Field(example=settings.TEST_VALUES.get('decryption_key'))
    

class DecryptProofRequest(BaseModel):
    """DecryptProofRequest model."""
    proof: dict = Field()
    options: DecryptProofOption = Field()
    

class VerifyPresentationOption(BaseModel):
    """VerifyPresentationOption model."""
    nonce: str = Field()
    presReqId: str = Field()
    

class VerifyPresentationRequest(BaseModel):
    """VerifyPresentationRequest model."""
    presentation: dict = Field()
    options: VerifyPresentationOption = Field()
    

class CreatePresentationOption(BaseModel):
    """CreatePresentationOption model."""
    challenge: str = Field(None)
    presReqId: str = Field()
    

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
