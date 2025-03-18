use pyo3::prelude::*;
use rand::{thread_rng, RngCore};
use indexmap::indexmap;
use maplit::btreeset;
// use ::credx::blind::BlindCredentialRequest;
use ::credx::claim::{ClaimType, HashedClaim, RevocationClaim};
use ::credx::{
    create_domain_proof_generator, generate_verifiable_encryption_keys, random_string
};
use ::credx::prelude::PresentationProofs;
use ::credx::credential::{CredentialSchema, ClaimSchema};
use ::credx::presentation::{Presentation, PresentationSchema};
use ::credx::statement::{VerifiableEncryptionStatement, RevocationStatement, SignatureStatement};
use ::credx::knox::bbs::BbsScheme;
use ::credx::issuer::Issuer;

#[pyfunction]
pub fn full_demo() -> (String, String, String, String) {
    const LABEL: &str = "Test Schema";
    const DESCRIPTION: &str = "This is a test presentation schema";
    const CRED_ID: &str = "91742856-6eda-45fb-a709-d22ebb5ec8a5";
    let schema_claims = [
        ClaimSchema {
            claim_type: ClaimType::Revocation,
            label: "revocationId".to_string(),
            print_friendly: false,
            validators: vec![],
        },
        ClaimSchema {
            claim_type: ClaimType::Hashed,
            label: "name".to_string(),
            print_friendly: true,
            validators: vec![],
        },
    ];
    let cred_schema =
        CredentialSchema::new(Some(LABEL), Some(DESCRIPTION), &[], &schema_claims).unwrap();
    // println!("{}", serde_json::to_string(&cred_schema).unwrap());

    let (issuer_public, mut issuer) = Issuer::<BbsScheme>::new(&cred_schema);
    // println!("{}", serde_json::to_string(&issuer_public).unwrap());
    // println!("{}", serde_json::to_string(&issuer).unwrap());

    let credential = issuer
        .sign_credential(&[
            RevocationClaim::from(CRED_ID).into(),
            HashedClaim::from("John Doe").into(),
        ])
        .unwrap();
    // println!("{}", serde_json::to_string(&credential).unwrap());

    let (verifier_domain_specific_encryption_key, verifier_domain_specific_decryption_key) =
        generate_verifiable_encryption_keys(thread_rng());

    let sig_id = random_string(16, rand::thread_rng());
    let sig_st = SignatureStatement {
        disclosed: btreeset! {"name".to_string()},
        id: sig_id.clone(),
        issuer: issuer_public.clone(),
    };
    let acc_st = RevocationStatement {
        id: random_string(16, rand::thread_rng()),
        reference_id: sig_st.id.clone(),
        accumulator: issuer_public.revocation_registry,
        verification_key: issuer_public.revocation_verifying_key,
        claim: 0,
    };
    let verenc_st = VerifiableEncryptionStatement {
        message_generator: create_domain_proof_generator(b"verifier specific message generator"),
        encryption_key: verifier_domain_specific_encryption_key,
        id: random_string(16, rand::thread_rng()),
        reference_id: sig_st.id.clone(),
        claim: 0,
    };
    let verenc_st_id = verenc_st.id.clone();

    let mut nonce = [0u8; 16];
    thread_rng().fill_bytes(&mut nonce);

    println!("{}", serde_json::to_string(&credential).unwrap());
    let credentials = indexmap! { sig_id => credential.credential.into() };
    println!("{:?}", credentials);
    let presentation_schema = PresentationSchema::new(&[
        sig_st.into(),
        acc_st.into(),
        verenc_st.into(),
    ]);

    println!("{}", serde_json::to_string(&presentation_schema).unwrap());

    let presentation = Presentation::create(&credentials, &presentation_schema, &nonce).unwrap();
    presentation.verify(&presentation_schema, &nonce).unwrap();
    let proof1 =
        if let PresentationProofs::VerifiableEncryption(v) = &presentation.proofs[&verenc_st_id] {
            v.clone()
        } else {
            panic!("Expected VerifiableEncryption proof");
        };

    thread_rng().fill_bytes(&mut nonce);
    let presentation = Presentation::create(&credentials, &presentation_schema, &nonce).unwrap();
    presentation.verify(&presentation_schema, &nonce).unwrap();

    let proof2 =
        if let PresentationProofs::VerifiableEncryption(v) = &presentation.proofs[&verenc_st_id] {
            v.clone()
        } else {
            panic!("Expected VerifiableEncryption proof");
        };

    assert_ne!(proof1.blinder_proof, proof2.blinder_proof);
    assert_ne!(proof1.c1, proof2.c1);
    assert_ne!(proof1.c2, proof2.c2);
    let value1 = proof1.decrypt(&verifier_domain_specific_decryption_key);
    let value2 = proof2.decrypt(&verifier_domain_specific_decryption_key);
    assert_eq!(value1, value2);

    (
        format!("{}", serde_json::to_string(&proof1).unwrap()),
        format!("{}", serde_json::to_string(&proof2).unwrap()),
        format!("{}", serde_json::to_string(&verifier_domain_specific_decryption_key).unwrap()),
        format!("{}", serde_json::to_string(&value2).unwrap())
    )
}