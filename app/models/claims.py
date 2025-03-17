from pydantic import BaseModel, Field
from typing import List, Union, Literal


# Validators
class Length(BaseModel):
    min: int = Field()
    max: int = Field()


class LengthValidator(BaseModel):
    length: Length = Field(alias="Length")


class Range(BaseModel):
    min: int = Field()
    max: int = Field()


class RangeValidator(BaseModel):
    range: Length = Field(alias="Range")


class RegexValidator(BaseModel):
    pattern: str = Field()


class AnyOne(BaseModel):
    values: List[str] = Field()


# Claims
class ClaimSchema(BaseModel):
    claim_type: Literal["Enumeration", "Number", "Hashed", "Scalar", "Revocation"] = (
        Field()
    )
    label: str = Field()
    validators: List[Union[LengthValidator,RangeValidator,RegexValidator,AnyOne]] = Field([])
    # validators: List[dict] = Field([])
    print_friendly: bool = Field(False)
