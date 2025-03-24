import pytest
from .fixtures import CRED_NAME, CRED_DESC
from app.plugins.anoncreds import AnonCredsV2

anoncreds = AnonCredsV2()


class TestWebvhRoutes:
    def __init__(self):
        pass

    @pytest.mark.asyncio
    async def test_claim_types(self):
        json_schema = {
            "type": "object",
            "title": CRED_NAME,
            "description": CRED_DESC,
            "properties": {"name": {"type": "string"}, "age": {"type": "number"}},
        }
        options = {"linkSecret": True}
        cred_schema = anoncreds.map_cred_schema(json_schema, options)

        assert cred_schema.get("label") == CRED_NAME
        assert cred_schema.get("description") == CRED_DESC
        assert isinstance(cred_schema.get("claims"), list)
        assert isinstance(cred_schema.get("claim_indices"), list)
        assert isinstance(cred_schema.get("blind_claims"), list)
        assert (
            len(cred_schema.get("claims")) == len(cred_schema.get("claim_indices")) == 4
        )
        assert "linkSecret" in cred_schema.get("blind_claims")

        claims = cred_schema.get("claims")
        assert next(
            (claim for claim in claims if claim["claim_type"] == "Revocation"), None
        )
        assert next(
            (claim for claim in claims if claim["claim_type"] == "Scalar"), None
        )
        assert next(
            (claim for claim in claims if claim["claim_type"] == "Hashed"), None
        )
        assert next(
            (claim for claim in claims if claim["claim_type"] == "Number"), None
        )

        assert next(
            (claim for claim in claims if claim["label"] == "credentialId"), None
        )
        assert next((claim for claim in claims if claim["label"] == "linkSecret"), None)

    @pytest.mark.asyncio
    async def test_claim_validators(self):
        json_schema = {
            "type": "object",
            "title": CRED_NAME,
            "description": CRED_DESC,
            "properties": {
                "province": {"enum": ["BC", "QC", "ON", "AB", "SK", "MB"]},
                "name": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 255,
                    "pattern": "[A-Za-z]",
                },
                "age": {"type": "number", "minimum": 1, "maximum": 255},
            },
        }
        options = {"linkSecret": True}
        cred_schema = anoncreds.map_cred_schema(json_schema, options)
        claims = cred_schema.get("claims")
