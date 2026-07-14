use serde_json::Value;

fn contract() -> Value {
    serde_json::from_str(include_str!("../PRODUCT-CONTRACT.json"))
        .expect("PRODUCT-CONTRACT.json must be valid JSON")
}

#[test]
fn contract_locks_detector_count_and_prices() {
    let contract = contract();

    assert_eq!(contract["editions"]["core"]["detector_count"], 96);
    assert_eq!(
        contract["editions"]["core"]["detector_registry_entries"],
        99
    );
    assert_eq!(contract["pricing_usd"]["pro"]["monthly_per_developer"], 12);
    assert_eq!(contract["pricing_usd"]["pro"]["annual_per_developer"], 96);
    assert_eq!(contract["pricing_usd"]["team"]["monthly_per_developer"], 25);
    assert_eq!(contract["pricing_usd"]["team"]["annual_per_developer"], 240);
    assert_eq!(contract["pricing_usd"]["checkout_enabled"], false);

    let mut price_ids = std::collections::HashSet::new();
    for tier in ["pro", "team"] {
        for environment in ["live", "staging"] {
            for period in ["monthly", "annual"] {
                let price_id = contract["pricing_usd"][tier]["price_ids"][environment][period]
                    .as_str()
                    .expect("price id must be a string");
                assert!(price_id.starts_with("price_"));
                assert!(price_ids.insert(price_id), "duplicate price id {price_id}");
            }
        }
    }
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
        std::collections::BTreeSet::from(["core", "enterprise", "pro", "team"])
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
