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
    

class IssueCredentialRequest(BaseModel):
    """CreateSchemaRequest model."""

    credential: dict = Field()
    options: dict = Field()

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "credential": {
                        '@context': [
                            'https://www.w3.org/ns/credentials/v2',
                            'https://www.w3.org/ns/credentials/examples/v2'
                        ],
                        'type': ['VerifiableCredential', 'CreditCardCredential'],
                        'credentialSubject': {
                            'cardType': 'Visa',
                            'number': '4086 8176 1180 4614',
                            'holder': 'Jane Doe',
                            'cvv': '962',
                            'expires': '02/26'
                        }
                    },
                    'options': {
                        'credentialId': '43c1434e-05c9-4914-9345-0164fd592284',
                        'credDefId': 'zQmWjfaqVAb3NByVCxWMT96rHeqSwR26U8wXYoPuLTb67wy',
                    }
                }
            ]
        }
    }
    

class DeriveCredentialRequest(BaseModel):
    """CreateSchemaRequest model."""

    verifiableCredential: dict = Field()
    options: dict = Field()