use pyo3::prelude::*;
use pyo3::PyResult;
use blsful::inner_types::*;
use blsful::*;
use std::collections::BTreeMap;
use rand::{thread_rng, RngCore};
use indexmap::{indexmap, IndexMap};
// use maplit::{btreemap, btreeset};
use ::credx::blind::BlindCredentialRequest;
use ::credx::claim::{Claim, ClaimData, HashedClaim};
// use ::credx::claim::{ClaimType, ClaimValidator, HashedClaim, RevocationClaim, NumberClaim, ScalarClaim};
use ::credx::{
    create_domain_proof_generator, generate_verifiable_encryption_keys
};
use ::credx::prelude::{PresentationCredential, MembershipRegistry, MembershipSigningKey, MembershipVerificationKey};
use ::credx::credential::{Credential, CredentialSchema};
use ::credx::presentation::{Presentation, PresentationSchema, PresentationProofs, VerifiableEncryptionProof};
use ::credx::statement::Statements;
use ::credx::knox::bbs::BbsScheme;
use ::credx::issuer::{IssuerPublic, Issuer};
mod demo;
use demo::full_demo;

#[pyfunction]
fn create_schema(schema: String) -> String {
    let cred_schema: CredentialSchema = serde_json::from_str(&schema).unwrap();
    format!("{}", serde_json::to_string(&cred_schema).unwrap())
}

#[pyfunction]
fn setup_issuer(schema: String) -> (String, String) {
    let cred_schema: CredentialSchema = serde_json::from_str(&schema).unwrap();
    let (isspub, iss) = Issuer::<BbsScheme>::new(&cred_schema);
    (
        format!("{}", serde_json::to_string(&isspub).unwrap()),
        format!("{}", serde_json::to_string(&iss).unwrap())
    )
}

#[pyfunction]
fn request_credential(issuer_public: String, blind_claims: String) -> (String, String) {
    let issuer_public: IssuerPublic<BbsScheme> = serde_json::from_str(&issuer_public).unwrap();
    let blind_claims: BTreeMap<String, ClaimData> = serde_json::from_str(&blind_claims).unwrap();
    let (request, blinder): (BlindCredentialRequest<BbsScheme>, Scalar) = BlindCredentialRequest::new(&issuer_public, &blind_claims).unwrap();
    (
        format!("{}", serde_json::to_string(&request).unwrap()),
        format!("{}", serde_json::to_string(&blinder).unwrap())
    )
}

#[pyfunction]
fn sign_credential(issuer: String, claims_data: String) -> String {
    let mut issuer: Issuer<BbsScheme> = serde_json::from_str(&issuer).unwrap();
    let claims_data: Vec<ClaimData> = serde_json::from_str(&claims_data).unwrap();
    let credential = issuer.sign_credential(&claims_data).unwrap();
    format!("{}", serde_json::to_string(&credential).unwrap())
}

#[pyfunction]
fn sign_blind_credential(issuer: String, claims_data: String, request: String) -> String {
    let mut issuer: Issuer<BbsScheme> = serde_json::from_str(&issuer).unwrap();
    let request: BlindCredentialRequest<BbsScheme> = serde_json::from_str(&request).unwrap();
    let claims_data: BTreeMap<String, ClaimData> = serde_json::from_str(&claims_data).unwrap();
    // let blind_bundle = issuer.blind_sign_credential(
    //     &request,
    //     &claims_data,
    // );
    format!("{}", serde_json::to_string(&request).unwrap())
}

#[pyfunction]
fn new_presentation_request(statements: String) -> String {
    let statements: Vec<Statements<BbsScheme>> = serde_json::from_str(&statements).unwrap();
    let presentation_schema: PresentationSchema<BbsScheme> = PresentationSchema::new(&statements);

    format!("{}", serde_json::to_string(&presentation_schema).unwrap())
}

#[pyfunction]
fn create_presentation(credential: String, presentation_schema: String, sig_id: String) -> String {

    let mut nonce = [0u8; 16];
    thread_rng().fill_bytes(&mut nonce);

    let sig_id: String = serde_json::from_str(&sig_id).unwrap();

    let credential: Credential<BbsScheme> = serde_json::from_str(&credential).unwrap();
    let presentation_schema: PresentationSchema<BbsScheme> = serde_json::from_str(&presentation_schema).unwrap();

    let credentials: IndexMap<String, PresentationCredential<BbsScheme>> = indexmap! { sig_id => credential.into() };
    // println!("{:?}", credentials);
    let presentation = Presentation::create(&credentials, &presentation_schema, &nonce).unwrap();

    format!("{}", serde_json::to_string(&presentation).unwrap())
}

#[pyfunction]
fn verify_presentation(schema: String, presentation: String, nonce: String) -> String {
    let schema: PresentationSchema<BbsScheme> = serde_json::from_str(&schema).unwrap();
    let presentation: Presentation<BbsScheme> = serde_json::from_str(&presentation).unwrap();
    let nonce: &[u8] = serde_json::from_str(&nonce).unwrap();
    let verification = presentation.verify(&schema, &nonce).unwrap();

    format!("{}", serde_json::to_string(&presentation).unwrap())
}

#[pyfunction]
fn decrypt_proof(proof: String, decryption_key: String) -> String {
    let proof: VerifiableEncryptionProof = serde_json::from_str(&proof).unwrap();
    let decryption_key: SecretKey<Bls12381G2Impl> = serde_json::from_str(&decryption_key).unwrap();
    let value = proof.decrypt(&decryption_key);
    format!("{}", serde_json::to_string(&value).unwrap())
}

#[pyfunction]
fn new_keys() -> (String, String) {
    let (verifier_domain_specific_encryption_key, verifier_domain_specific_decryption_key) =
        generate_verifiable_encryption_keys(thread_rng());
    (
        format!("{}", serde_json::to_string(&verifier_domain_specific_encryption_key).unwrap()),
        format!("{}", serde_json::to_string(&verifier_domain_specific_decryption_key).unwrap())
    )
}

#[pyfunction]
fn msg_generator() -> String {
    format!("{}", serde_json::to_string(&G1Projective::GENERATOR).unwrap())
}

#[pyfunction]
fn create_nonce() -> String {
    let mut nonce = [0u8; 16];
    thread_rng().fill_bytes(&mut nonce);
    format!("{}", serde_json::to_string(&nonce).unwrap())
}

#[pyfunction]
fn create_scalar() -> String {
    let scalar = Scalar::random(rand_core::OsRng);
    format!("{}", serde_json::to_string(&scalar).unwrap())
}

#[pyfunction]
fn membership_registry() -> (String, String, String) {
    let sk = MembershipSigningKey::new(None);
    let vk = MembershipVerificationKey::from(&sk);
    let registry = MembershipRegistry::random(thread_rng());
    (
        format!("{}", serde_json::to_string(&sk).unwrap()),
        format!("{}", serde_json::to_string(&vk).unwrap()),
        format!("{}", serde_json::to_string(&registry).unwrap())
    )
}

#[pyfunction]
fn domain_proof_generator(message: &[u8]) -> String {
    let generator: G1Projective = create_domain_proof_generator(message);
    format!("{}", serde_json::to_string(&generator).unwrap())
}

#[pyfunction]
fn create_commitment(value: String, domain: &[u8]) -> String {
    let value_hash: HashedClaim = HashedClaim::from(value);
    let value_scalar: Scalar = value_hash.to_scalar();
    let value_commitment: G1Projective = create_domain_proof_generator(domain) * value_scalar;
    format!("{}", serde_json::to_string(&value_commitment).unwrap())
}

#[pymodule]
fn anoncreds_api(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(create_schema, m)?)?;
    m.add_function(wrap_pyfunction!(setup_issuer, m)?)?;
    m.add_function(wrap_pyfunction!(request_credential, m)?)?;
    m.add_function(wrap_pyfunction!(sign_credential, m)?)?;
    m.add_function(wrap_pyfunction!(sign_blind_credential, m)?)?;
    m.add_function(wrap_pyfunction!(new_presentation_request, m)?)?;
    m.add_function(wrap_pyfunction!(create_presentation, m)?)?;
    m.add_function(wrap_pyfunction!(new_keys, m)?)?;
    m.add_function(wrap_pyfunction!(msg_generator, m)?)?;
    m.add_function(wrap_pyfunction!(decrypt_proof, m)?)?;
    m.add_function(wrap_pyfunction!(domain_proof_generator, m)?)?;
    m.add_function(wrap_pyfunction!(create_nonce, m)?)?;
    m.add_function(wrap_pyfunction!(create_scalar, m)?)?;
    m.add_function(wrap_pyfunction!(membership_registry, m)?)?;
    m.add_function(wrap_pyfunction!(create_commitment, m)?)?;
    m.add_function(wrap_pyfunction!(full_demo, m)?)?;

    Ok(())
}
