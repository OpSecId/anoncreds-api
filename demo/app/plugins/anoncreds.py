from config import Config
from app.plugins.askar import AskarStorage
from app.utils import zalgo_id
import requests
import uuid
import json


class AnonCredsApi:
    def __init__(self):
        self.endpoint = Config.ANONCREDS_API

    async def provision(self):
        askar = AskarStorage()
        await askar.provision(recreate=True)
        if await askar.fetch("demo", "default"):
            return

        with open("app/static/demo/holder.json", "r") as f:
            holder = json.loads(f.read())
        holder_id = holder.get("subjectId")

        with open("app/static/demo/credentials/credit-card.json", "r") as f:
            cc_demo = json.loads(f.read())

        # Create commitments
        cc_commitments = self.create_commitments(
            cc_demo.get("registry"), cc_demo.get("issuer").get("domain")
        )

        # Create Schema
        # cc_schema_id = self.create_cred_schema(cc_demo.get("schema")).get("credentialSchemaId")
        # cc_issuer = self.setup_issuer(cc_schema_id)
        # cc_cred_def = cc_issuer.get("public")

        cc_verification_method = cc_demo.get("issuer").get('verificationMethod')
        cc_cred_subject = cc_demo.get("credential").get("credentialSubject")
        cc_request_proof = self.request_credential(holder_id, cc_verification_method).get('requestProof')
        cc_credential = self.issue_credential(
            cred_id=str(uuid.uuid4()),
            rev_id=str(uuid.uuid4()),
            cred_subject=cc_cred_subject,
            request_proof=cc_request_proof,
            verification_method=cc_verification_method, 
        )
        
        with open("app/static/demo/credentials/rebates-card.json", "r") as f:
            rc_demo = json.loads(f.read())

        # rc_schema = self.create_cred_schema(rc_demo.get("schema")).get("schema")
        # rc_issuer = self.setup_issuer(rc_schema.get("id"))
        # rc_cred_def = rc_issuer.get("public")

        rc_verification_method = rc_demo.get("issuer").get('verificationMethod')
        rc_cred_subject = rc_demo.get("credential").get("credentialSubject")
        rc_cred_subject["clientNo"] = zalgo_id(64)
        rc_request_proof = self.request_credential(holder_id, rc_verification_method).get('requestProof')
        rc_credential = self.issue_credential(
            cred_id=str(uuid.uuid4()),
            rev_id=str(uuid.uuid4()),
            cred_subject=rc_cred_subject,
            request_proof=rc_request_proof,
            verification_method=rc_verification_method, 
        )

        with open("app/static/demo/presentations/shoes-purchase.json", "r") as f:
            shoes_demo = json.loads(f.read())

        shoes_pres_schema_id = self.create_pres_schema(shoes_demo.get('query'))

        with open("app/static/demo/presentations/shorts-purchase.json", "r") as f:
            shorts_demo = json.loads(f.read())

        shorts_pres_schema_id = self.create_pres_schema(shorts_demo.get('query'))
        # challenge = self.create_nonce().get("nonce")
        # cc_presentation = self.create_presentation(
        #     cc_credential, cc_pres_schema.get("id"), challenge
        # ).get("presentation")
        # cc_verified = self.verify_presentation(
        #     cc_presentation, cc_pres_schema.get("id"), challenge
        # )

        # rc_pres_statements = {
        #     # 'signature': {
        #     #     'disclosed': ['anniversaryMonth']
        #     # },
        #     "revocation": {"accumulator": ""},
        #     "encryption": {
        #         "claim": "clientNo",
        #         "domain": cc_demo.get("issuer").get("domain"),
        #         "encryptionKey": cc_cred_def.get("verifiable_encryption_key"),
        #     },
        # }
        # challenge = self.create_nonce().get("nonce")
        # rc_pres_schema = self.create_pres_schema(
        #     rc_cred_def.get("id"), rc_pres_statements
        # ).get("presReq")
        # rc_presentation = self.create_presentation(
        #     rc_credential, rc_pres_schema.get("id"), challenge
        # ).get("presentation")
        # rc_verified = self.verify_presentation(
        #     rc_presentation, rc_pres_schema.get("id"), challenge
        # )
        # print(rc_cred_subject)

        # # # Decrypt Proof
        # # proofs = presentation.get('proofs')
        # # for proof_id in proofs:
        # #     proof = proofs.get(proof_id)
        # #     if proof.get('VerifiableEncryption'):
        # #         ve_proof = proof.get('VerifiableEncryption')

        # # decryption_key = issuer_private.get('verifiable_decryption_key')
        # # decrypted_proof = self.decrypt_proof(ve_proof,decryption_key ).get('decrypted')
        # # decrypted_proof

        # demo = {
        #     "credentials": {
        #         "creditCard": {
        #             "issuer": {
        #                 "name": "NeoVault",
        #                 "domain": "flux@neovault.bank.example",
        #             },
        #             "credentialSubject": cc_cred_subject,
        #         },
        #         "rebatesCard": {
        #             "issuer": {
        #                 "name": "SynergiPay Consortium",
        #                 "domain": "rebates@synergipay.example",
        #             },
        #             "credentialSubject": rc_cred_subject,
        #         },
        #     }
        # }

        # await askar.store("demo", "default", demo)
        # await askar.store("credential", "credit-card", cc_credential)
        # await askar.store("credential", "rebates-card", rc_credential)
        # await askar.store("presentation", "shoes-checkout", cc_presentation)
        # await askar.store("presentation", "shorts-checkout", rc_presentation)

    def create_cred_schema(self, schema):
        r = requests.post(
            f"{self.endpoint}/resources/schemas/credentials",
            json={"jsonSchema": schema, "options": {}},
        )
        return r.json()

    def setup_issuer(self, issuer_name, schema_id):
        r = requests.post(
            f"{self.endpoint}/resources/issuers/{issuer_name}", json={"options": {"credSchemaId": schema_id}}
        )
        return r.json()

    def create_pres_schema(self, query):
        r = requests.post(
            f"{self.endpoint}/resources/schemas/presentations",
            json={"query": query},
        )
        return r.json()

    def request_credential(self, subject_id, verification_method):
        r = requests.post(
            f"{self.endpoint}/operations/credentials/request",
            json={
                "subjectId": subject_id,
                "verificationMethod": verification_method,
            },
        )
        return r.json()

    def issue_credential(self, cred_subject, cred_id, rev_id, verification_method, request_proof=None):
        r = requests.post(
            f"{self.endpoint}/operations/credentials/issuance",
            json={
                "credentialSubject": cred_subject,
                "options": {
                    "credentialId": cred_id,
                    "revocationId": rev_id,
                    "requestProof": request_proof,
                    "verificationMethod": verification_method
                },
            },
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

    def create_nonce(self):
        r = requests.post(
            f"{self.endpoint}/utilities/challenge",
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
