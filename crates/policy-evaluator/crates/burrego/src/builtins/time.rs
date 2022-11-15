use std::str::FromStr;

use anyhow::{anyhow, Result};
use chrono::{self, DateTime, Datelike, Duration, Local};

pub fn now_ns(args: &[serde_json::Value]) -> Result<serde_json::Value> {
    if !args.is_empty() {
        return Err(anyhow!("time.now_ns: wrong number of arguments given"));
    }
    let now = Local::now();
    serde_json::to_value(now.timestamp_nanos())
        .map_err(|e| anyhow!("time.now_ns: cannot convert value into JSON: {:?}", e))
}

pub fn parse_rfc3339_ns(args: &[serde_json::Value]) -> Result<serde_json::Value> {
    if args.len() != 1 {
        return Err(anyhow!(
            "time.parse_rfc3339_ns: wrong number of arguments given"
        ));
    }

    let value = args[0]
        .as_str()
        .ok_or_else(|| anyhow!("time.parse_rfc3339_ns: 1st parameter is not a string"))?;

    let dt = DateTime::parse_from_rfc3339(value)
        .map_err(|e| anyhow!("time.parse_rfc3339_ns: cannot convert {}: {:?}", value, e))?;

    serde_json::to_value(dt.timestamp_nanos()).map_err(|e| {
        anyhow!(
            "time.parse_rfc3339_ns: cannot convert value into JSON: {:?}",
            e
        )
    })
}

pub fn date(args: &[serde_json::Value]) -> Result<serde_json::Value> {
    if args.len() != 1 {
        return Err(anyhow!("time.date: wrong number of arguments given"));
    }

    let nanoseconds: i64;
    let mut timezone: chrono_tz::Tz = chrono_tz::UTC;

    match args[0].clone() {
        serde_json::Value::Number(val) => {
            nanoseconds = val
                .as_i64()
                .ok_or_else(|| anyhow!("time.date: 1st parameter is not a number"))?;
        }
        serde_json::Value::Array(val) => {
            if val.len() != 2 {
                return Err(anyhow!(
                    "time.date: wrong number of items inside of input array"
                ));
            }
            nanoseconds = val[0]
                .as_i64()
                .ok_or_else(|| anyhow!("time.date: 1st array item is not a number"))?;
            let tz_name = val[1]
                .as_str()
                .ok_or_else(|| anyhow!("time.date: 2nd array item is not a string"))?;
            if tz_name == "Local" {
                return date_local(nanoseconds);
            } else {
                timezone = chrono_tz::Tz::from_str(tz_name).map_err(|e| {
                    anyhow!(
                        "time.date: cannot handle given timezone {}: {:?}",
                        tz_name,
                        e
                    )
                })?;
            }
        }
        _ => {
            return Err(anyhow!(
                "time.date: the 1st parameter is neither a number nor an array"
            ));
        }
    };

    let unix_epoch = DateTime::<chrono::Utc>::from_utc(
        chrono::NaiveDateTime::from_timestamp_opt(0, 0)
            .ok_or_else(|| anyhow!("cannot create timestamp"))?,
        chrono::Utc,
    );
    let dt = unix_epoch
        .checked_add_signed(Duration::nanoseconds(nanoseconds))
        .ok_or_else(|| anyhow!("time.date: overflow when building date"))?
        .with_timezone(&timezone);

    Ok(serde_json::json!([dt.year(), dt.month(), dt.day(),]))
}

pub fn date_local(ns: i64) -> Result<serde_json::Value> {
    let unix_epoch = DateTime::<chrono::Utc>::from_utc(
        chrono::NaiveDateTime::from_timestamp_opt(0, 0)
            .ok_or_else(|| anyhow!("cannot create timestamp"))?,
        chrono::Utc,
    );
    let dt = unix_epoch
        .checked_add_signed(Duration::nanoseconds(ns))
        .ok_or_else(|| anyhow!("time.date: overflow when building date"))?
        .with_timezone(&chrono::Local);

    Ok(serde_json::json!([dt.year(), dt.month(), dt.day(),]))
}
#[cfg(test)]
mod test {
    use super::*;
    use chrono::TimeZone;
    use serde_json::json;

    #[test]
    fn test_parse_rfc3339_ns() {
        let input_dt = Local::now();

        let args: Vec<serde_json::Value> = vec![json!(input_dt.to_rfc3339())];

        let actual = parse_rfc3339_ns(&args);
        assert!(actual.is_ok());
        assert_eq!(json!(input_dt.timestamp_nanos()), actual.unwrap());
    }

    #[test]
    fn date_with_no_tz() {
        let input_dt = Local::now().naive_utc();

        let args: Vec<serde_json::Value> = vec![json!(input_dt.timestamp_nanos())];

        let actual = date(&args);
        assert!(actual.is_ok());
        assert_eq!(
            json!([input_dt.year(), input_dt.month(), input_dt.day()]),
            actual.unwrap()
        );
    }

    #[test]
    fn date_with_tz() {
        let input_dt = chrono_tz::US::Pacific.ymd(1990, 5, 6).and_hms(12, 30, 45);

        let args: Vec<serde_json::Value> = vec![json!([input_dt.timestamp_nanos(), "US/Pacific"])];

        let actual = date(&args);
        assert!(actual.is_ok());
        assert_eq!(
            json!([input_dt.year(), input_dt.month(), input_dt.day()]),
            actual.unwrap()
        );
    }

    #[test]
    fn date_with_local_tz() {
        let input_dt = Local::now().naive_utc();

        let args: Vec<serde_json::Value> = vec![json!([input_dt.timestamp_nanos(), "Local"])];

        let actual = date(&args);
        assert!(actual.is_ok());
        assert_eq!(
            json!([input_dt.year(), input_dt.month(), input_dt.day()]),
            actual.unwrap()
        );
    }
}
