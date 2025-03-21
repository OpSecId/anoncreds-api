use pyo3::prelude::*;
use pyo3::PyResult;
use blsful::inner_types::*;
use blsful::*;
use std::collections::BTreeMap;
use rand::{thread_rng, RngCore};
use indexmap::{indexmap, IndexMap};
// use maplit::{btreemap, btreeset};
use ::credx::blind::BlindCredentialRequest;
use ::credx::claim::{Claim, ClaimData, ClaimType, ScalarClaim, NumberClaim, HashedClaim, RevocationClaim};
// use ::credx::claim::{ClaimType, ClaimValidator, HashedClaim, RevocationClaim, NumberClaim, ScalarClaim};
use ::credx::{
    create_domain_proof_generator, generate_verifiable_encryption_keys, random_string
};
use ::credx::prelude::{PresentationCredential, MembershipRegistry, MembershipSigningKey, MembershipVerificationKey};
use ::credx::credential::{Credential, CredentialSchema, ClaimSchema};
use ::credx::presentation::{Presentation, PresentationSchema, PresentationProofs, VerifiableEncryptionProof};
use ::credx::statement::{Statements, VerifiableEncryptionStatement, RevocationStatement, SignatureStatement};
use ::credx::knox::bbs::BbsScheme;
use ::credx::issuer::{IssuerPublic, Issuer};

use maplit::{btreemap, btreeset};

#[pyfunction]
// fn check_domain_commitment(value: String, domain: &[u8], proof: String, decryption_key: String) -> String {
pub fn check_domain_commitment() -> String {

    let CRED_NAME: &str = "Credential";
    let CRED_DESC: &str = "A credential";
    let CRED_ID: &str = "1dfc0443-d71f-4a72-8c9e-97a6e280ded2";
    let DOMAIN: &[u8] = b"example.com";
    let SUBJECT_NAME: &str = "Jane Doe";

    // Setup the credential schema and issuer
    let schema_claims = [
        ClaimSchema {
            claim_type: ClaimType::Revocation,
            label: "credentialId".to_string(),
            print_friendly: false,
            validators: vec![],
        },
        // ClaimSchema {
        //     claim_type: ClaimType::Scalar,
        //     label: "linkSecret".to_string(),
        //     print_friendly: false,
        //     validators: vec![],
        // },
        ClaimSchema {
            claim_type: ClaimType::Hashed,
            label: "name".to_string(),
            print_friendly: true,
            validators: vec![],
        },
        ClaimSchema {
            claim_type: ClaimType::Number,
            label: "age".to_string(),
            print_friendly: true,
            validators: vec![],
        },
    ];
    let cred_schema =
        CredentialSchema::new(Some(CRED_NAME), Some(CRED_DESC), &[], &schema_claims).unwrap();
    let (issuer_public, mut issuer) = Issuer::<BbsScheme>::new(&cred_schema);

    // Setup the presentation schema and verifier
    let (encryption_key, decryption_key) = generate_verifiable_encryption_keys(thread_rng());
    let sig_st = SignatureStatement {
        disclosed: btreeset! {},
        id: random_string(16, rand::thread_rng()),
        issuer: issuer_public.clone(),
    };
    let sig_id =  sig_st.id.clone();

    let verenc_st = VerifiableEncryptionStatement {
        message_generator: create_domain_proof_generator(DOMAIN),
        encryption_key: encryption_key,
        id: random_string(16, rand::thread_rng()),
        reference_id: sig_st.id.clone(),
        claim: 1,
    };
    let verenc_st_id = verenc_st.id.clone();

    let mut nonce = [0u8; 16];
    thread_rng().fill_bytes(&mut nonce);
    let presentation_schema = PresentationSchema::new(&[
        sig_st.into(),
        verenc_st.into(),
    ]);

    // Issue credential and create presentation
    // let blind_claims: BTreeMap<String, ClaimData> = btreemap! { "linkSecret".to_string() => ScalarClaim::from(Scalar::random(rand_core::OsRng)).into() };
    // let (request, blinder): (BlindCredentialRequest<BbsScheme>, Scalar) = BlindCredentialRequest::new(&issuer_public, &blind_claims).unwrap();
    // let blind_bundle = issuer.blind_sign_credential(
    //     &request,
    //     &btreemap! {
    //         "credentialId".to_string() => RevocationClaim::from(CRED_ID).into(),
    //         "name".to_string() => HashedClaim::from(SUBJECT_NAME).into(),
    //         "age".to_string() => NumberClaim::from(24).into(),
    //     },
    // );
    // println!("{}", serde_json::to_string(&blind_claims).unwrap());
    let credential = issuer
        .sign_credential(&[
            RevocationClaim::from(CRED_ID).into(),
            HashedClaim::from(SUBJECT_NAME).into(),
            NumberClaim::from(24).into(),
        ])
        .unwrap();
    let credentials = indexmap! { sig_id => credential.credential.into() };
    let presentation = Presentation::create(&credentials, &presentation_schema, &nonce).unwrap();
    presentation.verify(&presentation_schema, &nonce).unwrap();

    // Compare decrypted proof
    let proof: VerifiableEncryptionProof = 
    if let PresentationProofs::VerifiableEncryption(v) = &presentation.proofs[&verenc_st_id] {
        *v.clone()
    } else {
        panic!("Expected VerifiableEncryption proof");
    };
    let decrypted_proof = proof.decrypt(&decryption_key);

    let value_hash: HashedClaim = HashedClaim::from(SUBJECT_NAME);
    let value_scalar: Scalar = value_hash.to_scalar();
    let value_commitment: G1Projective = create_domain_proof_generator(DOMAIN) * value_scalar;

    println!("{}", serde_json::to_string(&decrypted_proof).unwrap());
    println!("{}", serde_json::to_string(&value_commitment).unwrap());

    format!("{}", serde_json::to_string(&value_commitment).unwrap())
}