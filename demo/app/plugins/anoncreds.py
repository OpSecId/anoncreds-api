from config import Config
from app.plugins.askar import AskarStorage
import requests
import json


class AnonCredsApi:
    def __init__(self):
        self.endpoint = Config.ANONCREDS_API
        
    async def provision(self):
        with open('app/static/demo/credit-card.json', 'r') as f:
            demo = json.loads(f.read())

        # Create commitments
        for number in demo.get('registry'):
            r = requests.post(
                f'{self.endpoint}/utilities/create-commitment',
                json={
                    'value': number,
                    'domain': demo.get('issuer').get('domain')
                }
            )
            commitment = r.json()
            commitment
        
        # Create Schema
        r = requests.post(
            f'{self.endpoint}/create-schema',
            json={
                'jsonSchema': demo.get('schema'),
                'options': {}
            }
        )
        schema = r.json().get('schema')
        
        # Setup Issuer
        r = requests.post(
            f'{self.endpoint}/define-credential',
            json={
                'options': {'schemaId': schema.get('id')}
            }
        )
        issuer_public, issuer_private = r.json().get('public'), r.json().get('private')
        
        # Issue Credential
        r = requests.post(
            f'{self.endpoint}/issue-credential',
            json={
                'credentialSubject': demo.get('issuance').get('credentialSubject'),
                'options': {'credDefId': issuer_public.get('id')}
            }
        )
        credential = r.json()
        
        # Create Presentation Request
        r = requests.post(
            f'{self.endpoint}/request-presentation',
            json={
                'statements': {
                    'encryption': {
                        'claim': 'number',
                        'domain': demo.get('issuer').get('domain'),
                        'encryptionKey': issuer_public.get('verifiable_encryption_key')
                    }
                },
                'options': {'credDefId': issuer_public.get('id')}
            }
        )
        presentation_request = r.json().get('presReq')
        
        # Create Presentation
        r = requests.post(
            f'{self.endpoint}/utilities/nonce',
        )
        nonce = r.json().get('nonce')
        r = requests.post(
            f'{self.endpoint}/create-presentation',
            json={
                'credential': credential,
                'options': {
                    'nonce': nonce,
                    'presReqId': presentation_request.get('id')
                }
            }
        )
        presentation = r.json().get('presentation')
        
        # Decrypt Proof
        proofs = presentation.get('proofs')
        for proof_id in proofs:
            proof = proofs.get(proof_id)
            if proof.get('VerifiableEncryption'):
                ve_proof = proof.get('VerifiableEncryption')
                
        r = requests.post(
            f'{self.endpoint}/utilities/decrypt-proof',
            json={
                'proof': ve_proof,
                'options': {
                    'decryptionKey': issuer_private.get('verifiable_decryption_key')
                }
            }
        )
        decrypted_number = r.json().get('decrypted')
        decrypted_number
                
        demo = {
            'issuer': {
                'id': '',
                'name': '',
                'image': ''
            },
            'credential': demo.get('issuance')
        }
        askar = AskarStorage()
        await askar.provision()
        await askar.store('demo', 'default', demo)