use anyhow::{anyhow, Result};
use semver::Version;
use std::cmp::Ordering;

pub fn is_valid(args: &[serde_json::Value]) -> Result<serde_json::Value> {
    if args.len() != 1 {
        return Err(anyhow!("semver.is_valid: wrong number of arguments"));
    }

    let input = args[0]
        .as_str()
        .ok_or_else(|| anyhow!("semver.is_valid: 1st parameter is not a string"))?;

    let valid_version = Version::parse(input).map(|_| true).unwrap_or(false);

    serde_json::to_value(valid_version)
        .map_err(|e| anyhow!("semver.is_valid: cannot convert value into JSON: {:?}", e))
}

pub fn compare(args: &[serde_json::Value]) -> Result<serde_json::Value> {
    if args.len() != 2 {
        return Err(anyhow!("semver.compare: wrong number of arguments"));
    }

    let version_a = args[0]
        .as_str()
        .ok_or_else(|| anyhow!("semver.compare: 1st parameter is not a string"))?;

    let version_b = args[1]
        .as_str()
        .ok_or_else(|| anyhow!("semver.compare: 2nd parameter is not a string"))?;

    let version_a = Version::parse(version_a).map_err(|e| {
        anyhow!(
            "semver.compare: first argument is not a valid semantic version: {:?}",
            e
        )
    })?;

    let version_b = Version::parse(version_b).map_err(|e| {
        anyhow!(
            "semver.compare: second argument is not a valid semantic version: {:?}",
            e
        )
    })?;

    let res = match version_a.cmp(&version_b) {
        Ordering::Less => -1,
        Ordering::Equal => 0,
        Ordering::Greater => 1,
    };

    serde_json::to_value(res)
        .map_err(|e| anyhow!("semver.compare: cannot convert value into JSON: {:?}", e))
}

#[cfg(test)]
mod test {
    use super::*;

    use serde_json::json;

    #[test]
    fn is_valid() -> Result<()> {
        assert_eq!(super::is_valid(&[json!("1.0.0")])?, true);
        assert_eq!(super::is_valid(&[json!("1.0.0-rc1")])?, true);
        assert_eq!(super::is_valid(&[json!("invalidsemver-1.0.0")])?, false);

        Ok(())
    }

    #[test]
    fn compare() -> Result<()> {
        assert_eq!(super::compare(&[json!("0.0.1"), json!("0.1.0")])?, -1);
        assert_eq!(
            super::compare(&[json!("1.0.0-rc1"), json!("1.0.0-rc1")])?,
            0
        );
        assert_eq!(super::compare(&[json!("0.1.0"), json!("0.0.1")])?, 1);
        assert_eq!(
            super::compare(&[json!("1.0.0-beta1"), json!("1.0.0-alpha3")])?,
            1
        );
        assert_eq!(
            super::compare(&[json!("1.0.0-rc2"), json!("1.0.0-rc1")])?,
            1
        );
        assert!(super::compare(&[json!("invalidsemver-1.0.0"), json!("0.1.0")]).is_err());
        assert!(super::compare(&[json!("0.1.0"), json!("invalidsemver-1.0.0")]).is_err());

        Ok(())
    }
}
