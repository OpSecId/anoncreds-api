from flask_wtf import FlaskForm
from wtforms import (
    IntegerRangeField,
    SubmitField,
    StringField,
    TextAreaField,
    BooleanField,
    IntegerField,
    SelectMultipleField,
)
from wtforms.validators import InputRequired


class CreateSchema(FlaskForm):

    name = StringField("Name", default="Demo Credential")
    description = TextAreaField(
        "Description", default="A demonstration of AnonCreds v2 claim statements."
    )

    hashed_claim = StringField("Hashed Claim", default="name")
    blind = BooleanField("Blindable")
    # minLength = IntegerRangeField("Min Length", default=2)
    maxLength = IntegerRangeField("Max Length (0-255)", default=255)
    pattern = StringField("Regex", default="/^[a-zA-Z\s]*$/")

    number_claim = StringField("Number Claim", default="age")
    minValue = IntegerField("Min", default=0)
    maxValue = IntegerField("Max", default=100)

    enumeration_claim = StringField("Enumeration Claim", default="province")
    enumeration_values = SelectMultipleField("Values")

    revocation = BooleanField("Revocation", default=True)
    pseudonym = BooleanField("Pseudonymity", default=False)

    submit = SubmitField("Create Schema")


class IssueCredential(FlaskForm):

    hashed_claim = StringField("Hashed Claim Value", [InputRequired()])
    number_claim = IntegerField("Number Claim Value", [InputRequired()])

    submit = SubmitField("Issue Credential")


class RequestPresentation(FlaskForm):

    minValue = IntegerField("Lower Range Limit", default=18)
    maxValue = IntegerField("Upper Range Limit")

    disclose = BooleanField("Disclose Hashed Claim", default=True)

    revocation = BooleanField("Include Revocation Statement", default=True)

    submit = SubmitField("Request Presentation")
