from config import Config
from app.plugins.askar import AskarStorage
from app.utils import zalgo_id
import requests
import json


class AnonCredsApi:
    def __init__(self):
        self.endpoint = Config.ANONCREDS_API

    async def provision(self):
        askar = AskarStorage()
        await askar.provision()
        if await askar.fetch("demo", "default"):
            return

        with open("app/static/demo/credentials/credit-card.json", "r") as f:
            cc_demo = json.loads(f.read())

        # Create commitments
        cc_commitments = self.create_commitments(
            cc_demo.get("registry"), cc_demo.get("issuer").get("domain")
        )

        # Create Schema
        cc_schema = self.create_cred_schema(cc_demo.get("schema")).get("schema")

        cc_issuer = self.setup_issuer(cc_schema.get("id"))
        cc_cred_def = cc_issuer.get("public")

        cc_cred_subject = cc_demo.get("credential").get("credentialSubject")
        cc_credential = self.issue_credential(cc_cred_def.get("id"), cc_cred_subject)

        with open("app/static/demo/credentials/rebates-card.json", "r") as f:
            rc_demo = json.loads(f.read())

        rc_schema = self.create_cred_schema(rc_demo.get("schema")).get("schema")
        rc_issuer = self.setup_issuer(rc_schema.get("id"))
        rc_cred_def = rc_issuer.get("public")

        rc_cred_subject = rc_demo.get("credential").get("credentialSubject")
        rc_cred_subject["clientNo"] = zalgo_id(64)
        rc_credential = self.issue_credential(rc_cred_def.get("id"), rc_cred_subject)

        cc_pres_statements = {
            # 'signature': {
            #     'disclosed': ['cvv']
            # },
            "revocation": {"accumulator": ""},
            "encryption": {
                "claim": "number",
                "domain": cc_demo.get("issuer").get("domain"),
                "encryptionKey": cc_cred_def.get("verifiable_encryption_key"),
            },
        }
        challenge = self.create_nonce().get("nonce")
        cc_pres_schema = self.create_pres_schema(
            cc_cred_def.get("id"), cc_pres_statements
        ).get("presReq")
        cc_presentation = self.create_presentation(
            cc_credential, cc_pres_schema.get("id"), challenge
        ).get("presentation")
        cc_verified = self.verify_presentation(
            cc_presentation, cc_pres_schema.get("id"), challenge
        )

        rc_pres_statements = {
            # 'signature': {
            #     'disclosed': ['anniversaryMonth']
            # },
            "revocation": {"accumulator": ""},
            "encryption": {
                "claim": "clientNo",
                "domain": cc_demo.get("issuer").get("domain"),
                "encryptionKey": cc_cred_def.get("verifiable_encryption_key"),
            },
        }
        challenge = self.create_nonce().get("nonce")
        rc_pres_schema = self.create_pres_schema(
            rc_cred_def.get("id"), rc_pres_statements
        ).get("presReq")
        rc_presentation = self.create_presentation(
            rc_credential, rc_pres_schema.get("id"), challenge
        ).get("presentation")
        rc_verified = self.verify_presentation(
            rc_presentation, rc_pres_schema.get("id"), challenge
        )
        print(rc_cred_subject)

        # # Decrypt Proof
        # proofs = presentation.get('proofs')
        # for proof_id in proofs:
        #     proof = proofs.get(proof_id)
        #     if proof.get('VerifiableEncryption'):
        #         ve_proof = proof.get('VerifiableEncryption')

        # decryption_key = issuer_private.get('verifiable_decryption_key')
        # decrypted_proof = self.decrypt_proof(ve_proof,decryption_key ).get('decrypted')
        # decrypted_proof

        demo = {
            "credentials": {
                "creditCard": {
                    "issuer": {
                        "name": "NeoVault",
                        "domain": "flux@neovault.bank.example",
                    },
                    "credentialSubject": cc_cred_subject,
                },
                "rebatesCard": {
                    "issuer": {
                        "name": "SynergiPay Consortium",
                        "domain": "rebates@synergipay.example",
                    },
                    "credentialSubject": rc_cred_subject,
                },
            }
        }

        await askar.store("demo", "default", demo)
        await askar.store("credential", "credit-card", cc_credential)
        await askar.store("credential", "rebates-card", rc_credential)
        await askar.store("presentation", "shoes-checkout", cc_presentation)
        await askar.store("presentation", "shorts-checkout", rc_presentation)

    def create_cred_schema(self, schema):
        r = requests.post(
            f"{self.endpoint}/create-cred-schema",
            json={"jsonSchema": schema, "options": {}},
        )
        return r.json()

    def setup_issuer(self, schema_id):
        r = requests.post(
            f"{self.endpoint}/setup-issuer", json={"options": {"schemaId": schema_id}}
        )
        return r.json()

    def issue_credential(self, cred_def_id, cred_subject):
        r = requests.post(
            f"{self.endpoint}/issue-credential",
            json={
                "credentialSubject": cred_subject,
                "options": {"credDefId": cred_def_id},
            },
        )
        return r.json()

    def create_pres_schema(self, cred_def_id, pres_statements):
        r = requests.post(
            f"{self.endpoint}/create-pres-schema",
            json={"statements": pres_statements, "options": {"credDefId": cred_def_id}},
        )
        return r.json()

    def create_nonce(self):
        r = requests.post(
            f"{self.endpoint}/utilities/challenge",
        )
        return r.json()

    def create_presentation(self, credential, pres_schema_id, challenge):
        r = requests.post(
            f"{self.endpoint}/create-presentation",
            json={
                "credential": credential,
                "options": {"challenge": challenge, "presReqId": pres_schema_id},
            },
        )
        return r.json()

    def decrypt_proof(self, proof, decryption_key):
        r = requests.post(
            f"{self.endpoint}/utilities/decrypt",
            json={"proof": proof, "options": {"decryptionKey": decryption_key}},
        )
        return r.json()

    def create_commitments(self, values, domain):
        commitments = {}
        for value in values:
            r = requests.post(
                f"{self.endpoint}/utilities/commitment",
                json={"value": value, "domain": domain},
            )
            commitments[value] = r.json().get("commitment")
        return commitments

    def verify_presentation(self, presentation, pres_schema_id, challenge):
        r = requests.post(
            f"{self.endpoint}/verify-presentation",
            json={
                "presentation": presentation,
                "options": {"challenge": challenge, "presReqId": pres_schema_id},
            },
        )
        return r.json()
