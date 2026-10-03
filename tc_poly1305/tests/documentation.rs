//! Every public type and method, and every trait method `Poly1305` implements,
//! documents its timing.

/// Declaration prefixes whose doc comments must state their timing.
const DECLARATIONS: &[&str] = &[
    "pub struct ",
    "pub fn ",
    "pub const fn ",
    "fn default(",
    "fn init(",
    "fn fmt(",
    "fn mac_size(",
    "fn update(",
    "fn do_final(",
    "fn reset(",
    "fn drop(",
];

fn missing_timing_docs(source: &str) -> (usize, Vec<String>) {
    let mut docs = String::new();
    let mut attribute_depth = 0_i32;
    let mut checked = 0;
    let mut missing = Vec::new();
    for line in source.lines().map(str::trim) {
        // Helpers inside test modules are not part of the contract.
        if line == "#[cfg(test)]" {
            break;
        }
        if let Some(comment) = line.strip_prefix("///") {
            docs.push_str(comment);
            docs.push('\n');
            continue;
        }
        if line.starts_with("#[") || attribute_depth > 0 {
            attribute_depth += line.chars().filter(|&c| c == '[').count() as i32;
            attribute_depth -= line.chars().filter(|&c| c == ']').count() as i32;
            continue;
        }
        if line.is_empty() || line.starts_with("//") {
            continue;
        }
        if DECLARATIONS.iter().any(|prefix| line.starts_with(prefix)) {
            checked += 1;
            let docs = docs.to_ascii_lowercase();
            if docs.contains("constant time") == docs.contains("variable time") {
                missing.push(line.to_owned());
            }
        }
        docs.clear();
    }
    (checked, missing)
}

#[test]
fn the_scanner_requires_exactly_one_timing_classification_on_each_declaration() {
    let fixture = "\
/// Constant time.
pub struct Documented {}
pub struct Undocumented {}
/// VARIABLE TIME.
#[inline]
pub const fn accepted() {}
/// Constant time and variable time.
fn init() {}
fn do_final() {}
/// Constant time when the cipher's is.
fn update() {}
fn drop() {}
impl Trait for Type {
    fn clone() {}
}
#[cfg(test)]
mod tests {
    fn reset() {}
}
";
    let (checked, missing) = missing_timing_docs(fixture);
    assert_eq!(checked, 7);
    assert_eq!(
        missing,
        [
            "pub struct Undocumented {}",
            "fn init() {}",
            "fn do_final() {}",
            "fn drop() {}",
        ]
    );
}

#[test]
fn every_public_api_and_implemented_trait_method_has_an_unambiguous_timing_doc() {
    let (checked, missing) = missing_timing_docs(include_str!("../src/mac.rs"));
    assert!(checked > 0, "mac.rs: no declarations scanned");
    assert!(
        missing.is_empty(),
        "missing timing docs:\n{}",
        missing.join("\n")
    );
}
