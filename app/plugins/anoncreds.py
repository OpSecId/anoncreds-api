import anoncreds_api
import json
import uuid
from app.models.claims import ClaimSchema#, LengthValidator, RangeValidator
from app.models.schema import CredentialSchema
from app.utils import digest_multibase, multibase_encode, public_key_multibase
from config import settings


CLAIM_TYPES_MAPPING = {
    'string': 'Hashed',
    'number': 'Number',
}

class AnonCredsV2:
    """AnonCredsV2 plugin."""

    def __init__(self, issuer=None):
        self.issuer = issuer

    def _sanitize_input(self, value):
        return json.loads(value)

    def _generate_id(self, value):
        value.pop('id', None)
        return digest_multibase(value)

    def _get_sig_id(self, pres_req):
        for statement in pres_req.get('statements'):
            if pres_req.get('statements')[statement].get('Signature'):
                return pres_req.get('statements')[statement]['Signature'].get('id')
        return None

    def provision(self):
        pass

    def create_keypair(self):
        encryption_key, decryption_key = anoncreds_api.new_keys()
        encryption_key, decryption_key = self._sanitize_input(encryption_key), self._sanitize_input(decryption_key)
        return encryption_key, decryption_key

    def message_generator(self, domain=None):
        if domain:
            generator = anoncreds_api.domain_proof_generator(domain.encode())
        else:
            generator = anoncreds_api.msg_generator()
        generator = self._sanitize_input(generator)
        return generator

    def map_claims(self, cred_def, credential_subject, cred_id):
        schema = cred_def.get('schema')
        claims = schema.get('claims')
        claims_data = []
        for claim in claims:
            if claim.get('claim_type') == 'Revocation':
                claims_data.append({
                    'Revocation': {'value': cred_id}
                })
            elif claim.get('label') in credential_subject:
                value = credential_subject[claim.get('label')]
                if isinstance(value, str):
                    claims_data.append({
                        'Hashed': {
                            'value': value,
                            'print_friendly': claim.get('print_friendly')
                        }
                    })
                elif isinstance(value, int) or isinstance(value, float):
                    claims_data.append({
                        'Number': {
                            'value': value,
                            'print_friendly': claim.get('print_friendly')
                        }
                    })
        return claims_data
                    

    def map_statements(self, cred_def, statements_input, options):
        statements = []
        schema = cred_def.get('schema')
        indices = schema.get('claim_indices')
        
        statement = {
            'disclosed': options['disclosedClaims'],
            'issuer': cred_def
        }
        sig_id = self._generate_id(statement)
        statements.append({
            'Signature': statement | {'id': sig_id}
        })
        
        if statements_input.get('revocation'):
            statement = {
                'reference_id': sig_id,
                'accumulator': statements_input['revocation'].get('accumulator'),
                'verification_key': cred_def['revocation_verifying_key'],
                'claim': 0
            }
            statements.append({
                'Revocation': statement | {'id': self._generate_id(statement)}
            })
            
        if statements_input.get('encryption'):
            message_generator = (
                self._sanitize_input(anoncreds_api.domain_proof_generator(options.get('domain').encode('utf-8'))) 
                if options.get('domain') else self._sanitize_input(anoncreds_api.msg_generator())
            )
            encryption_key = (
                statements_input['encryption'].get('key') 
                if statements_input['encryption'].get('key') else cred_def.get('verifiable_encryption_key')
            )
            statement = {
                'reference_id': sig_id,
                'message_generator': message_generator,
                'encryption_key': encryption_key,
                'claim': indices.index(statements_input['encryption'].get('claim'))
            }
            statements.append({
                'VerifiableEncryption': statement | {'id': self._generate_id(statement)}
            })
            
        return statements

    def map_schema(self, json_schema, options):
        claims = []
        blind_claims = []
        claim_indices = []
        
        if options.get('revocation'):
            claim_indices.append('revocationId')
            claims.append(
                ClaimSchema(
                    claim_type='Revocation',
                    label='revocationId'
                )
            )
            
        if options.get('linkSecret'):
            claim_indices.append('linkSecret')
            blind_claims.append('linkSecret')
            claims.append(
                ClaimSchema(
                    claim_type='Scalar',
                    label='linkSecret'
                )
            )

        properties = json_schema.get('properties')
        for property in properties:
            
            claim_indices.append(property)
            
            validators = []
            if properties[property].get('minimum') or properties[property].get('maximum'):
                pass
            if properties[property].get('minLength') or properties[property].get('maxLength'):
                pass
            if properties[property].get('pattern'):
                pass
            if properties[property].get('enum'):
                pass
            
            claims.append(
                ClaimSchema(
                    claim_type=CLAIM_TYPES_MAPPING[properties[property].get('type')],
                    label=property,
                    validators=validators,
                    print_friendly=True
                )
            )
            
        schema = CredentialSchema(
            label=json_schema.get('title'),
            description=json_schema.get('description'),
            blind_claims=blind_claims,
            claim_indices=claim_indices,
            claims=claims
        ).model_dump()
        schema['id'] = digest_multibase(schema)
        
        return schema
    
    def create_schema(self, schema):
        
        schema = anoncreds_api.create_schema(json.dumps(schema))
        schema = self._sanitize_input(schema)
        schema['id'] = self._generate_id(schema)
        
        return schema
    
    def setup_issuer(self, schema):
        
        issuer_pub, issuer_priv = anoncreds_api.setup_issuer(json.dumps(schema))
        issuer_pub, issuer_priv = self._sanitize_input(issuer_pub), self._sanitize_input(issuer_priv)
        issuer_pub['id'] = issuer_priv['id'] = self._generate_id(issuer_pub)
        
        return issuer_pub, issuer_priv
    
    def link_secret(self):
        pass
    
    def create_key(self):
        pass
    
    def credential_request(self, cred_def, blind_claims):
        cred_request, blinder = anoncreds_api.request_credential(
            json.dumps(cred_def),
            json.dumps(blind_claims),
        )
        cred_request, blinder = self._sanitize_input(cred_request), self._sanitize_input(blinder)
        return cred_request, blinder
    
    def cred_to_w3c(self, issuer, credential_input):
        schema = issuer.get('schema')
        verifying_key = public_key_multibase(issuer.get('verifying_key').get('w'), 'bls')
        credential = {
            'issuer': {
                'id': f'did:key:{verifying_key}'    
            },
            'credentialStatus': {
                'revocationId': credential_input.get('claims')[0]['Revocation']['value'],
                'revocationIndex': credential_input.get('revocation_index'),
                'revocationHandle': credential_input.get('revocation_handle'),
                'revocationRegistry': issuer.get('revocation_registry'),
            },
            'credentialSubject': {},
            'proof': {
                'proofValue': multibase_encode(credential_input.get('signature')),
                'verificationMethod': f'did:key:{verifying_key}#{verifying_key}'
            }
        }
        for idx, claim in enumerate(credential_input.get('claims')):
            if claim.get('Revocation'):
                continue
            elif claim.get('Scalar'):
                continue
            elif claim.get('Number'):
                credential['credentialSubject'][schema['claim_indices'][idx]] = claim.get('Number').get('value')
            elif claim.get('Hashed'):
                credential['credentialSubject'][schema['claim_indices'][idx]] = claim.get('Hashed').get('value')
        return credential
    
    def issue_credential(self, claims_data):
        response = anoncreds_api.sign_credential(
            json.dumps(self.issuer),
            json.dumps(claims_data),
        )
        response = self._sanitize_input(response)
        credential = response.get('credential')
        # credential = self.cred_to_w3c(response.get('issuer'), credential)
        return credential
    
    def new_pres_req(self, statements):
        pres_req = anoncreds_api.new_presentation_request(
            json.dumps(statements)
        )
        pres_req = self._sanitize_input(pres_req)
        pres_req['id'] = self._generate_id(pres_req)
        return pres_req
    
    def create_presentation(self, pres_req, credential, nonce):
        sig_id = self._get_sig_id(pres_req)
        # credential = {
        #     'issuer': pres_req['statements'][sig_id]['Signature']['issuer'],
        #     'credential': credential
        # }
        presentation = anoncreds_api.create_presentation(
            json.dumps(credential), json.dumps(pres_req), json.dumps(sig_id)#, nonce.encode()
        )
        presentation = self._sanitize_input(presentation)
        return presentation