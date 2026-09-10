//! The deployed CRD and this reader have to agree about field names.
//!
//! They did not. `deploy/crd.yaml` declared the budget in camelCase —
//! `wallClockSecs`, `maxCommands`, `maxMoneyCents`, `maxApiCalls` — and
//! the reader accepts only snake_case, because `Budget` comes from
//! lex-os and does not follow this CRD's convention.
//!
//! That is worse than a resource being rejected, and the failure runs the
//! wrong way round:
//!
//! - camelCase **survives** the API server, because the CRD declares it,
//!   and then the reader refuses it. Loud, and therefore safe.
//! - snake_case is what the reader **wants**, and the API server
//!   **prunes** it — the CRD is a structural schema with no
//!   `x-kubernetes-preserve-unknown-fields`, so anything undeclared is
//!   dropped before the webhook ever sees the object. The reader then
//!   applies `Budget::research_default()` for an absent budget.
//!
//! So the only spelling that worked was the one Kubernetes threw away,
//! and a namespace lead's declared budget would have been silently
//! replaced by a default. Nothing anywhere would have said so.
//!
//! Found by a cold-read participant (lex-os#89, pass 3), who reported
//! the mismatch and was explicit that pruning was the half they had not
//! tested. It is the half that mattered.

use lex_k8s::manifest::LexManifest;

/// The CRD's declared property names for `spec.budget`.
fn crd_budget_properties() -> Vec<String> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/deploy/crd.yaml");
    let text = std::fs::read_to_string(path).expect("deploy/crd.yaml");
    let doc: serde_yaml::Value = serde_yaml::from_str(&text).expect("crd.yaml is valid YAML");

    // Walk to whichever schema node carries `budget`, rather than
    // hardcoding a path that a CRD restructure would silently invalidate.
    fn find(v: &serde_yaml::Value) -> Option<Vec<String>> {
        if let serde_yaml::Value::Mapping(m) = v {
            if let Some(props) = m.get(serde_yaml::Value::from("properties")) {
                if let Some(budget) = props.get(serde_yaml::Value::from("budget")) {
                    if let Some(serde_yaml::Value::Mapping(bp)) =
                        budget.get(serde_yaml::Value::from("properties"))
                    {
                        let mut out: Vec<String> = bp
                            .keys()
                            .filter_map(|k| k.as_str().map(str::to_string))
                            .collect();
                        out.sort();
                        return Some(out);
                    }
                }
            }
            for (_, v) in m {
                if let Some(f) = find(v) {
                    return Some(f);
                }
            }
        }
        if let serde_yaml::Value::Sequence(s) = v {
            for v in s {
                if let Some(f) = find(v) {
                    return Some(f);
                }
            }
        }
        None
    }
    find(&doc).expect("the CRD must declare spec.budget properties")
}

#[test]
fn the_crd_declares_the_budget_keys_the_reader_accepts() {
    let declared = crd_budget_properties();

    // What the reader accepts, taken from the reader rather than
    // restated: serialise a real Budget and read its keys.
    let mut accepted: Vec<String> =
        serde_json::to_value(lex_os_manifest::Budget::research_default())
            .expect("serialisable")
            .as_object()
            .expect("an object")
            .keys()
            .cloned()
            .collect();
    accepted.sort();

    assert_eq!(
        declared, accepted,
        "the CRD and the reader disagree about budget field names — the spelling \
         the reader wants would be pruned by the API server and replaced by the \
         default budget, in silence"
    );
}

/// The round trip that matters: a manifest written the way the CRD
/// describes must be readable.
#[test]
fn a_manifest_written_against_the_crd_parses() {
    let keys = crd_budget_properties();
    let budget: String = keys
        .iter()
        .map(|k| format!("\"{k}\": 10"))
        .collect::<Vec<_>>()
        .join(",");

    let src = format!(
        r#"{{"apiVersion":"lex.dev/v1alpha1","kind":"LexManifest",
             "metadata":{{"name":"t","namespace":"n"}},
             "spec":{{"goal":"g","budget":{{{budget}}}}}}}"#
    );
    serde_json::from_str::<LexManifest>(&src)
        .unwrap_or_else(|e| panic!("a CRD-shaped manifest must parse: {e}"));
}

/// A field this reader does not recognise is refused rather than
/// ignored. `isolation_floor` for `isolationFloor` used to parse
/// happily and leave the floor unset — and the API server prunes the
/// same thing, so a mis-spelled declaration could disappear at both
/// layers with the manifest still admitted.
#[test]
fn a_misspelled_field_is_refused_not_ignored() {
    let src = r#"{"apiVersion":"lex.dev/v1alpha1","kind":"LexManifest",
                  "metadata":{"name":"t","namespace":"n"},
                  "spec":{"goal":"g","isolation_floor":"microvm"}}"#;
    let err = serde_json::from_str::<LexManifest>(src)
        .expect_err("snake_case `isolation_floor` is not this reader's spelling");
    assert!(
        err.to_string().contains("isolation_floor"),
        "the refusal must name the field: {err}"
    );
}

/// The control: the correct spelling still works, so the test above is
/// not passing because everything is refused.
#[test]
fn the_camel_case_spelling_still_parses() {
    let src = r#"{"apiVersion":"lex.dev/v1alpha1","kind":"LexManifest",
                  "metadata":{"name":"t","namespace":"n"},
                  "spec":{"goal":"g","isolationFloor":"microvm"}}"#;
    let m = serde_json::from_str::<LexManifest>(src).expect("camelCase is the wire spelling");
    assert_eq!(m.spec.isolation_floor.as_deref(), Some("microvm"));
}
