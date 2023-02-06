use crate::errors::{BurregoError, Result};
use semver::Version;
use std::cmp::Ordering;

pub fn is_valid(args: &[serde_json::Value]) -> Result<serde_json::Value> {
    if args.len() != 1 {
        return Err(BurregoError::BuiltinError {
            name: "semver.is_valid".to_string(),
            message: "wrong number of arguments".to_string(),
        });
    }

    let input = args[0].as_str().ok_or_else(|| BurregoError::BuiltinError {
        name: "semver.is_valid".to_string(),
        message: "1st parameter is not a string".to_string(),
    })?;

    let valid_version = Version::parse(input).map(|_| true).unwrap_or(false);

    serde_json::to_value(valid_version).map_err(|e| BurregoError::BuiltinError {
        name: "semver.is_valid".to_string(),
        message: format!("cannot convert value into JSON: {e:?}"),
    })
}

pub fn compare(args: &[serde_json::Value]) -> Result<serde_json::Value> {
    if args.len() != 2 {
        return Err(BurregoError::BuiltinError {
            name: "semver.compare".to_string(),
            message: "wrong number of arguments".to_string(),
        });
    }

    let version_a = args[0].as_str().ok_or_else(|| BurregoError::BuiltinError {
        name: "semver.compare".to_string(),
        message: "1st parameter is not a string".to_string(),
    })?;

    let version_b = args[1].as_str().ok_or_else(|| BurregoError::BuiltinError {
        name: "semver.compare".to_string(),
        message: "2nd parameter is not a string".to_string(),
    })?;

    let version_a = Version::parse(version_a).map_err(|e| BurregoError::BuiltinError {
        name: "semver.compare".to_string(),
        message: format!("first argument is not a valid semantic version: {e:?}"),
    })?;

    let version_b = Version::parse(version_b).map_err(|e| BurregoError::BuiltinError {
        name: "semver.compare".to_string(),
        message: format!("second argument is not a valid semantic version: {e:?}"),
    })?;

    let res = match version_a.cmp(&version_b) {
        Ordering::Less => -1,
        Ordering::Equal => 0,
        Ordering::Greater => 1,
    };

    serde_json::to_value(res).map_err(|e| BurregoError::BuiltinError {
        name: "semver.compare".to_string(),
        message: format!("cannot convert value into JSON: {e:?}"),
    })
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
