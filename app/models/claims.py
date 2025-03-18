from pydantic import BaseModel, Field
from typing import List, Union, Literal


# Validators
class Length(BaseModel):
    min: int = Field(None)
    max: int = Field(None)


class LengthValidator(BaseModel):
    length: Length = Field(None, alias="Length")


class Range(BaseModel):
    min: int = Field(None)
    max: int = Field(None)


class RangeValidator(BaseModel):
    range: Length = Field(None, alias="Range")


class RegexValidator(BaseModel):
    pattern: str = Field(None)


class AnyOne(BaseModel):
    values: List[str] = Field(None)


# Claims
class ClaimSchema(BaseModel):
    claim_type: Literal["Enumeration", "Number", "Hashed", "Scalar", "Revocation"] = (
        Field()
    )
    label: str = Field()
    validators: List[Union[dict, LengthValidator,RangeValidator,RegexValidator,AnyOne]] = Field([])
    # validators: List[dict] = Field([])
    print_friendly: bool = Field(False)
