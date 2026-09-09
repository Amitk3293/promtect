use serde_json::Value;

const RAW: &str = include_str!("../PRODUCT-CONTRACT.json");

fn contract() -> Value {
    serde_json::from_str(RAW).expect("PRODUCT-CONTRACT.json must be valid JSON")
}

#[test]
fn contract_locks_detector_count_and_publishes_core_only() {
    let contract = contract();

    assert_eq!(contract["schema_version"], 2);
    assert_eq!(contract["editions"]["core"]["detector_count"], 96);
    assert_eq!(
        contract["editions"]["core"]["detector_registry_entries"],
        99
    );

    // The Core repository is public. Schema 2 publishes no prices and no
    // commerce identifiers; those live outside this repository. Paid edition
    // names are locked out separately, by the exact-keys assertion in
    // `every_edition_and_capability_uses_a_public_status`.
    for marker in [
        "price_",
        "plink_",
        "prod_",
        "acct_",
        "buy.stripe.com",
        "pricing_usd",
    ] {
        assert!(
            !RAW.contains(marker),
            "PRODUCT-CONTRACT.json must not contain the commerce marker {marker}"
        );
    }
    // A bare `$` is legitimate inside prose; a price is `$` next to a digit.
    assert!(
        !RAW.chars()
            .zip(RAW.chars().skip(1))
            .any(|(a, b)| a == '$' && b.is_ascii_digit()),
        "PRODUCT-CONTRACT.json must not contain a price literal"
    );
}

#[test]
fn every_edition_and_capability_uses_a_public_status() {
    let contract = contract();
    let state_names: std::collections::BTreeSet<&str> = contract["states"]
        .as_object()
        .expect("states must be an object")
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        state_names,
        std::collections::BTreeSet::from(["available", "beta", "planned"])
    );

    let editions = contract["editions"]
        .as_object()
        .expect("editions must be an object");
    let edition_names: std::collections::BTreeSet<&str> =
        editions.keys().map(String::as_str).collect();
    assert_eq!(
        edition_names,
        std::collections::BTreeSet::from(["core"]),
        "the public contract must describe the Core edition and no other"
    );

    for (edition, value) in editions {
        assert_status(edition, &value["availability"]);
        let mut capability_ids = std::collections::HashSet::new();
        for capability in value["capabilities"]
            .as_array()
            .expect("capabilities must be an array")
        {
            let capability_id = capability["id"]
                .as_str()
                .expect("capability id must be a string");
            assert!(
                capability_ids.insert(capability_id),
                "{edition} repeats capability id {capability_id}"
            );
            assert_status(capability_id, &capability["state"]);
        }
    }
}

fn assert_status(subject: &str, value: &Value) {
    let status = value.as_str().expect("status must be a string");
    assert!(
        matches!(status, "available" | "beta" | "planned"),
        "{subject} has unsupported public status {status}"
    );
}
