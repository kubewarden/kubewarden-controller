use anyhow::Result;
use memchr::memmem;
use policy_evaluator::host_capabilities::HostCapabilities;

#[derive(Debug, PartialEq)]
pub struct DetectedHostCapability {
    pub namespace: String,
    pub operation: String,
}

pub fn scan(module: &walrus::Module) -> Result<Vec<DetectedHostCapability>> {
    // Collect all data segment payloads, separated by 0xFF to avoid
    // cross-boundary false matches.
    let mut all_data: Vec<u8> = Vec::new();
    for segment in module.data.iter() {
        all_data.extend_from_slice(&segment.value);
        all_data.push(0xFF);
    }

    let operations = HostCapabilities::enumerate_operations();

    // Collect all operation strings so we can detect prefix collisions generically.
    // For each operation, find every other operation string it is a strict prefix of.
    let op_strings: Vec<&str> = operations.iter().map(|(_, op)| op.as_str()).collect();

    let mut capabilities = Vec::new();
    for (namespace, operation) in &operations {
        // Collect all other operation strings that start with `operation` and are longer.
        let longer_siblings: Vec<&str> = op_strings
            .iter()
            .copied()
            .filter(|&other| other != operation.as_str() && other.starts_with(operation.as_str()))
            .collect();

        if is_operation_present(&all_data, namespace, operation, &longer_siblings) {
            capabilities.push(DetectedHostCapability {
                namespace: namespace.clone(),
                operation: operation.clone(),
            });
        }
    }

    Ok(capabilities)
}

fn is_operation_present(
    data: &[u8],
    namespace: &str,
    operation: &str,
    longer_siblings: &[&str],
) -> bool {
    // The namespace string must be present (also passed to HostCall).
    if memmem::find(data, namespace.as_bytes()).is_none() {
        return false;
    }

    // If there are longer operation strings that share our string as a prefix,
    // we must confirm that `operation` appears at least once as a standalone
    // match (i.e. not solely as part of one of those longer strings).
    if longer_siblings.is_empty() {
        memmem::find(data, operation.as_bytes()).is_some()
    } else {
        longer_siblings
            .iter()
            .all(|longer| has_standalone_match(data, operation.as_bytes(), longer.as_bytes()))
    }
}

/// Returns true if `needle` appears in `data` at a position that is NOT the
/// start of any occurrence of `longer` (which must begin with `needle`).
fn has_standalone_match(data: &[u8], needle: &[u8], longer: &[u8]) -> bool {
    let mut offset = 0;
    while let Some(pos) = memmem::find(&data[offset..], needle) {
        let abs_pos = offset + pos;
        if !data[abs_pos..].starts_with(longer) {
            return true;
        }
        offset = abs_pos + 1;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    use wasm_encoder::{ConstExpr, DataSection, MemorySection, MemoryType, Module};

    fn build_wasm(strings: &[&str]) -> walrus::Module {
        let mut module = Module::new();

        let mut memories = MemorySection::new();
        memories.memory(MemoryType {
            minimum: 1,
            maximum: None,
            memory64: false,
            shared: false,
            page_size_log2: None,
        });
        module.section(&memories);

        let mut data = DataSection::new();
        let mut payload: Vec<u8> = Vec::new();
        for s in strings {
            payload.extend_from_slice(s.as_bytes());
            payload.push(0);
        }
        data.active(0, &ConstExpr::i32_const(0), payload);
        module.section(&data);

        walrus::Module::from_buffer(&module.finish()).unwrap()
    }

    #[test]
    fn no_capabilities_without_kubewarden_marker() {
        let module = build_wasm(&["hello", "world"]);
        let caps = scan(&module).unwrap();
        assert!(caps.is_empty());
    }

    #[test]
    fn kubewarden_policy_no_capabilities() {
        let module = build_wasm(&["kubewarden"]);
        let caps = scan(&module).unwrap();
        assert!(caps.is_empty());
    }

    #[test]
    fn detects_single_capability_crypto() {
        let module = build_wasm(&["kubewarden", "crypto", "v1/is_certificate_trusted"]);
        let caps = scan(&module).unwrap();
        assert_eq!(caps.len(), 1);
        assert_eq!(caps[0].operation, "v1/is_certificate_trusted");
    }

    #[test]
    fn detects_single_capability_net() {
        let module = build_wasm(&["kubewarden", "net", "v1/dns_lookup_host"]);
        let caps = scan(&module).unwrap();
        assert_eq!(caps.len(), 1);
        assert_eq!(caps[0].operation, "v1/dns_lookup_host");
    }

    #[test]
    fn detects_all_capabilities() {
        let all_ops = HostCapabilities::enumerate_operations();
        let mut strings: Vec<&str> = vec!["kubewarden"];
        for (ns, op) in &all_ops {
            strings.push(ns.as_str());
            strings.push(op.as_str());
        }
        let module = build_wasm(&strings);
        let caps = scan(&module).unwrap();
        assert_eq!(caps.len(), all_ops.len());
    }

    #[test]
    fn oci_manifest_config_only_does_not_trigger_oci_manifest() {
        let module = build_wasm(&["kubewarden", "oci", "v1/oci_manifest_config"]);
        let caps = scan(&module).unwrap();
        let ops: Vec<&str> = caps.iter().map(|c| c.operation.as_str()).collect();
        assert!(
            ops.contains(&"v1/oci_manifest_config"),
            "expected v1/oci_manifest_config"
        );
        assert!(
            !ops.contains(&"v1/oci_manifest"),
            "v1/oci_manifest must not be a false positive"
        );
    }

    #[test]
    fn oci_manifest_standalone_is_detected() {
        let module = build_wasm(&[
            "kubewarden",
            "oci",
            "v1/oci_manifest_config",
            "v1/oci_manifest",
        ]);
        let caps = scan(&module).unwrap();
        let ops: Vec<&str> = caps.iter().map(|c| c.operation.as_str()).collect();
        assert!(ops.contains(&"v1/oci_manifest_config"));
        assert!(ops.contains(&"v1/oci_manifest"));
    }

    #[test]
    fn namespace_required_for_short_ops() {
        let module = build_wasm(&["kubewarden", "can_i"]);
        let caps = scan(&module).unwrap();
        let ops: Vec<&str> = caps.iter().map(|c| c.operation.as_str()).collect();
        assert!(
            !ops.contains(&"can_i"),
            "can_i without namespace must not match"
        );
    }

    #[test]
    fn enumerate_operations_has_unique_entries() {
        let ops = HostCapabilities::enumerate_operations();
        let mut keys: Vec<(&str, &str)> = ops
            .iter()
            .map(|(ns, op)| (ns.as_str(), op.as_str()))
            .collect();
        let original_len = keys.len();
        keys.sort();
        keys.dedup();
        assert_eq!(
            keys.len(),
            original_len,
            "duplicate entries in enumerate_operations"
        );
    }

    #[test]
    fn invalid_wasm_returns_error() {
        assert!(walrus::Module::from_buffer(b"not a wasm binary").is_err());
    }
}
