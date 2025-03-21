from typing import Any, Dict, List

from pydantic import BaseModel, Field, field_validator
from .claims import ClaimSchema


class BaseModel(BaseModel):
    """Base model for all models in the application."""

    def model_dump(self, **kwargs) -> Dict[str, Any]:
        """Dump the model to a dictionary."""
        return super().model_dump(by_alias=True, exclude_none=True, **kwargs)


class Property(BaseModel):
    type: str = Field()
    enum: List[str] = Field(None)
    pattern: str = Field(None)
    minimum: int = Field(None)
    maximum: int = Field(None)
    minLength: int = Field(None)
    maxLength: int = Field(None)


class JsonSchema(BaseModel):
    """JsonSchema model."""

    type: str = Field("object")
    title: str = Field()
    description: str = Field()
    properties: Dict[str, Property] = Field()

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "type": "object",
                    "title": "Sample Credential",
                    "description": "A sample credential",
                    "properties": {"name": {"type": "string"}},
                }
            ]
        }
    }


class CredentialSchema(BaseModel):
    label: str = Field()
    description: str = Field()
    blind_claims: List[str] = Field()
    claim_indices: List[str] = Field()
    claims: List[ClaimSchema] = Field()
