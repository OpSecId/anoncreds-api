import anoncreds_api
import json
import uuid
from app.models.claims import ClaimSchema  # , LengthValidator, RangeValidator
from app.models.schema import CredentialSchema
from app.utils import (
    digest_multibase,
    multibase_encode,
    public_key_multibase,
    to_encoded_cbor,
    from_encoded_cbor,
)
from config import settings
from bitstring import Array
from array import array


CLAIM_TYPES_MAPPING = {
    "string": "Hashed",
    "number": "Number",
}


class AnonCredsV2:
    """AnonCredsV2 plugin."""

    def __init__(self, issuer=None):
        self.issuer = issuer

    def _sanitize_input(self, value):
        return json.loads(value)

    def _generate_id(self, value):
        value.pop("id", None)
        return digest_multibase(value)

    def _get_sig_id(self, pres_req):
        for statement in pres_req.get("statements"):
            if pres_req.get("statements")[statement].get("Signature"):
                return pres_req.get("statements")[statement]["Signature"].get("id")
        return None

    def provision(self):
        pass

    def full_test(self):
        value_1 = anoncreds_api.check_domain_commitment()
        return self._sanitize_input(value_1)

    # def decode_nonce(self, nonce):
    #     return list(array('B', bytes.fromhex(nonce)))

    # def encode_nonce(self, nonce):
    #     return Array('uint8', nonce).data.hex

    # def create_nonce(self):
    #     nonce = anoncreds_api.create_nonce()
    #     nonce = self._sanitize_input(nonce)
    #     return self.encode_nonce(nonce)

    def create_scalar(self, value):
        scalar = (
            anoncreds_api.derive_scalar(json.dumps(value))
            if value
            else anoncreds_api.create_scalar()
        )
        scalar = self._sanitize_input(scalar)
        return scalar

    def create_keypair(self):
        encryption_key, decryption_key = anoncreds_api.new_keys()
        encryption_key, decryption_key = self._sanitize_input(
            encryption_key
        ), self._sanitize_input(decryption_key)
        return encryption_key, decryption_key

    def membership_registry(self):
        signing_key, verification_key, registry = anoncreds_api.membership_registry()
        signing_key, verification_key, registry = (
            self._sanitize_input(signing_key),
            self._sanitize_input(verification_key),
            self._sanitize_input(registry),
        )
        return signing_key, verification_key, registry

    def message_generator(self, domain=None):
        if domain:
            generator = anoncreds_api.domain_proof_generator(domain.encode())
        else:
            generator = anoncreds_api.msg_generator()
        generator = self._sanitize_input(generator)
        return generator

    def map_claims(self, cred_def, credential_subject, cred_id):
        schema = cred_def.get("schema")
        claims = schema.get("claims")
        claims_data = []
        for claim in claims:
            if claim.get("claim_type") == "Revocation":
                claims_data.append({"Revocation": {"value": cred_id}})
            elif claim.get("label") in credential_subject:
                value = credential_subject[claim.get("label")]
                if isinstance(value, str):
                    claims_data.append(
                        {
                            "Hashed": {
                                "value": value,
                                "print_friendly": claim.get("print_friendly"),
                            }
                        }
                    )
                elif isinstance(value, int) or isinstance(value, float):
                    claims_data.append(
                        {
                            "Number": {
                                "value": value,
                                "print_friendly": claim.get("print_friendly"),
                            }
                        }
                    )
        return claims_data

    def map_pres_schema(self, queries, challenge):
        statements = []
        for query in queries:
            if query.get("type") == "SignatureQuery":
                issuer = query.get("issuer")
                cred_schema = issuer.get("schema")
                indices = cred_schema.get("claim_indices")
                statements.append(
                    {
                        "Signature": {
                            "id": query.get("referenceId"),
                            "disclosed": query.get("disclosed", []),
                            "issuer": issuer,
                        }
                    }
                )
                statement = {
                    "claim": 0,
                    "reference_id": query.get("referenceId"),
                    "accumulator": issuer.get("revocation_registry"),
                    "verification_key": issuer.get("revocation_verifying_key"),
                }
                statements.append(
                    {"Revocation": statement | {"id": self._generate_id(statement)}}
                )
                for commitment in query.get("commitment", []):
                    statement = {
                        "claim": indices.index(commitment.get("claimRef")),
                        "reference_id": query.get("referenceId"),
                        "blinder_generator": commitment.get("blinderGenerator"),
                        "message_generator": commitment.get("messageGenerator"),
                    }
                    statements.append(
                        {"Commitment": statement | {"id": self._generate_id(statement)}}
                    )
                    if commitment.get("range"):
                        statement = {
                            "claim": indices.index(commitment.get("claimRef")),
                            "reference_id": statements[-1].get("Commitment").get("id"),
                            "signature_id": query.get("referenceId"),
                            "upper": commitment.get("range").get("upper"),
                            "lower": commitment.get("range").get("lower"),
                        }
                        statements.append(
                            {"Range": statement | {"id": self._generate_id(statement)}}
                        )

                for encryption in query.get("encryption", []):
                    statement = {
                        "claim": indices.index(encryption.get("claimRef")),
                        "reference_id": query.get("referenceId"),
                        "message_generator": self.domain_proof_generator(
                            encryption.get("domain")
                        ),
                        "encryption_key": encryption.get("encryptionKey"),
                    }
                    statements.append(
                        {
                            "VerifiableEncryption": statement
                            | {"id": self._generate_id(statement)}
                        }
                    )
        for query in queries:
            if query.get("type") == "EqualityQuery":
                statement = {}
                for claim in query.get("claims"):
                    signature_statement = next((
                        entry.get('Signature') for entry in statements if (
                            entry.get('Signature') 
                            and entry.get('Signature').get('id') == claim.get("signatureRef")
                        )
                    ), None)
                    signature_id = signature_statement.get('id')
                    claim_ref = signature_statement.get('issuer').get('schema').get('claim_indices').index(claim.get("claimRef"))
                    statement[signature_id] = claim_ref
                statements.append({
                    'Equality': {'ref_id_claim_index': statement} | {'id': self._generate_id(statement)}
                })

        return statements

    def map_cred_schema(self, json_schema, options):
        claims = []
        blind_claims = []
        claim_indices = []

        claim_indices.append("credentialId")
        claims.append(ClaimSchema(claim_type="Revocation", label="credentialId"))

        if options.get("linkSecret"):
            claim_indices.append("linkSecret")
            blind_claims.append("linkSecret")
            claims.append(ClaimSchema(claim_type="Scalar", label="linkSecret"))

        properties = json_schema.get("properties")
        for property in properties:

            claim_indices.append(property)

            validators = []
            if properties[property].get("minimum") or properties[property].get(
                "maximum"
            ):
                validator = {
                    "Range": {
                        "min": properties[property].get("minimum"),
                        "max": properties[property].get("maximum"),
                    }
                }
                validators.append(validator)
            if properties[property].get("minLength") or properties[property].get(
                "maxLength"
            ):
                validator = {
                    "Length": {
                        "min": properties[property].get("minLength"),
                        "max": properties[property].get("maxLength"),
                    }
                }
                validators.append(validator)
            if properties[property].get("pattern"):
                validator = {"Regex": properties[property].get("pattern")}
                validators.append(validator)
            if properties[property].get("enum"):
                values = properties[property].get("enum")
                for idx, value in enumerate(values):
                    value_type = "string" if isinstance(value, str) else "number"
                    values[idx] = {
                        CLAIM_TYPES_MAPPING[value_type]: {
                            "value": value,
                            "print_friendly": True,
                        }
                    }
                validator = {"AnyOne": values}
                validators.append(validator)

            claims.append(
                ClaimSchema(
                    claim_type=CLAIM_TYPES_MAPPING[properties[property].get("type")],
                    label=property,
                    validators=validators,
                    print_friendly=True,
                )
            )

        schema = CredentialSchema(
            label=json_schema.get("title"),
            description=json_schema.get("description"),
            blind_claims=blind_claims,
            claim_indices=claim_indices,
            claims=claims,
        ).model_dump()
        schema["id"] = digest_multibase(schema)

        return schema

    def create_cred_schema(self, schema):

        cred_schema = anoncreds_api.new_cred_schema(json.dumps(schema))
        cred_schema = self._sanitize_input(cred_schema)
        cred_schema["id"] = self._generate_id(cred_schema)

        return schema

    def create_pres_schema(self, statements):
        pres_schema = anoncreds_api.new_pres_schema(json.dumps(statements))
        pres_schema = self._sanitize_input(pres_schema)
        pres_schema["id"] = self._generate_id(pres_schema)
        return pres_schema

    def setup_issuer(self, schema):

        issuer_pub, issuer_priv = anoncreds_api.new_issuer(json.dumps(schema))
        issuer_pub, issuer_priv = self._sanitize_input(
            issuer_pub
        ), self._sanitize_input(issuer_priv)
        issuer_pub["id"] = issuer_priv["id"] = self._generate_id(issuer_pub)

        return issuer_pub, issuer_priv

    def link_secret(self):
        pass

    def create_key(self):
        pass

    def domain_proof_generator(self, domain):
        generator = anoncreds_api.domain_proof_generator(domain.encode("utf-8"))
        return self._sanitize_input(generator)

    def credential_request(self, cred_def, blind_claims):
        blind_claims, cred_request, blinder = anoncreds_api.new_cred_request(
            json.dumps(cred_def),
            json.dumps(blind_claims),
        )
        blind_claims, cred_request, blinder = (
            self._sanitize_input(blind_claims),
            self._sanitize_input(cred_request),
            self._sanitize_input(blinder),
        )
        return blind_claims, to_encoded_cbor(cred_request), blinder

    def cred_to_w3c(self, issuer, credential_input):
        schema = issuer.get("schema")
        verifying_key = public_key_multibase(
            issuer.get("verifying_key").get("w"), "bls"
        )
        schema_endpoint = "https://" + settings.DOMAIN + "/" + issuer.get("id")
        credential = {
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                "https://www.w3.org/ns/credentials/examples/v2",
            ],
            "type": ["VerifiableCredential", schema.get("label").replace(" ", "")],
            "name": schema.get("label"),
            "description": schema.get("description"),
            "issuer": {"id": f"did:key:{verifying_key}"},
            "credentialSchema": {"type": "AnonCredsDefinition", "id": schema_endpoint},
            "credentialStatus": {
                "credentialId": credential_input.get("claims")[0]["Revocation"][
                    "value"
                ],
                "revocationIndex": credential_input.get("revocation_index"),
                "revocationHandle": credential_input.get("revocation_handle"),
                "revocationRegistry": issuer.get("revocation_registry"),
            },
            "credentialSubject": {},
            "proof": {
                "type": "DataIntegrityProof",
                "cryptosuite": "anoncreds-bbs-2025",
                "proofPurpose": "assertionMethod",
                "proofValue": multibase_encode(credential_input.get("signature")),
                "verificationMethod": f"did:key:{verifying_key}#{verifying_key}",
            },
        }
        for idx, claim in enumerate(credential_input.get("claims")):
            if claim.get("Revocation"):
                continue
            elif claim.get("Scalar"):
                continue
            elif claim.get("Number"):
                credential["credentialSubject"][schema["claim_indices"][idx]] = (
                    claim.get("Number").get("value")
                )
            elif claim.get("Hashed"):
                credential["credentialSubject"][schema["claim_indices"][idx]] = (
                    claim.get("Hashed").get("value")
                )
        return credential

    def issue_credential(self, claims_data):
        response = anoncreds_api.issue_credential(
            json.dumps(self.issuer),
            json.dumps(claims_data),
        )
        response = self._sanitize_input(response)
        credential = response.get("credential")
        # credential = self.cred_to_w3c(response.get('issuer'), credential)
        return credential

    def issue_blind_credential(self, claims_map, request_proof):
        cred_request = from_encoded_cbor(request_proof)
        response = anoncreds_api.issue_blind_credential(
            json.dumps(self.issuer),
            json.dumps(claims_map),
            json.dumps(cred_request),
        )
        response = self._sanitize_input(response)
        credential = response.get("credential")
        # credential = self.cred_to_w3c(response.get('issuer'), credential)
        return credential

    def create_presentation(self, pres_req, credential, nonce):
        sig_id = self._get_sig_id(pres_req)
        # credential = {
        #     'issuer': pres_req['statements'][sig_id]['Signature']['issuer'],
        #     'credential': credential
        # }
        presentation = anoncreds_api.create_presentation(
            json.dumps(credential),
            json.dumps(pres_req),
            json.dumps(sig_id),
            nonce.encode(),
        )
        presentation = self._sanitize_input(presentation)
        return presentation

    def verify_presentation(self, pres_schema, presentation, nonce):
        try:
            verification = anoncreds_api.verify_presentation(
                json.dumps(pres_schema), json.dumps(presentation), nonce.encode()
            )
            verification = self._sanitize_input(verification)
            return True
        except:
            return False

    def decrypt_proof(self, proof, key):
        decrypted_proof = anoncreds_api.decrypt_proof(
            json.dumps(proof), json.dumps(key)
        )
        decrypted_proof = self._sanitize_input(decrypted_proof)
        return decrypted_proof

    def create_commitment(self, value, domain):
        commitment = anoncreds_api.create_commitment(
            json.dumps(value), json.dumps(domain).encode()
        )
        return self._sanitize_input(commitment)

    def unblind_credential(self, credential, cred_def, blinder=None):
        credential = anoncreds_api.reveal_blind_credential(
            json.dumps(credential), json.dumps(cred_def), json.dumps(blinder)
        )
        credential = self._sanitize_input(credential)
        return credential.get("credential")
