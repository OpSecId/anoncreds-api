from typing import Any, Dict, List

from pydantic import BaseModel, Field, field_validator
from .claims import ClaimSchema


class BaseModel(BaseModel):
    """Base model for all models in the application."""

    def model_dump(self, **kwargs) -> Dict[str, Any]:
        """Dump the model to a dictionary."""
        return super().model_dump(by_alias=True, exclude_none=True, **kwargs)


class Issuer(BaseModel):
    pass


class IssuerPublic(BaseModel):
    pass
