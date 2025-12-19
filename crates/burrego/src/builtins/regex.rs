use crate::errors::{BurregoError, Result};
use core::fmt::Display;
use regex::{escape as regex_escape, Regex};
use std::{fmt, str::FromStr};

pub fn split(args: &[serde_json::Value]) -> Result<serde_json::Value> {
    if args.len() != 2 {
        return Err(BurregoError::BuiltinError {
            name: "regex.split".to_string(),
            message: "Wrong number of arguments given".to_string(),
        });
    }

    let pattern_str = args[0].as_str().ok_or_else(|| BurregoError::BuiltinError {
        name: "regex.split".to_string(),
        message: "1st parameter is not a string".to_string(),
    })?;
    let string_str = args[1].as_str().ok_or_else(|| BurregoError::BuiltinError {
        name: "regex.split".to_string(),
        message: "2nd parameter is not a string".to_string(),
    })?;

    serde_json::to_value(
        Regex::new(pattern_str)
            .map_err(|e| BurregoError::BuiltinError {
                name: "regex.split".to_string(),
                message: format!(
                    "cannot build regex from the given pattern string '{pattern_str}': {e:?}"
                ),
            })?
            .split(string_str)
            .collect::<String>(),
    )
    .map_err(|e| BurregoError::BuiltinError {
        name: "regex.split".to_string(),
        message: format!("cannot convert result into JSON: {e:?}"),
    })
}

pub fn template_match(args: &[serde_json::Value]) -> Result<serde_json::Value> {
    if args.len() != 4 {
        return Err(BurregoError::BuiltinError {
            name: "regex.template_match".to_string(),
            message: "Wrong number of arguments given".to_string(),
        });
    }
    let pattern_str = args[0].as_str().ok_or_else(|| BurregoError::BuiltinError {
        name: "regex.template_match".to_string(),
        message: "1st parameter is not a string".to_string(),
    })?;
    let string_str = args[1].as_str().ok_or_else(|| BurregoError::BuiltinError {
        name: "regex.template_match".to_string(),
        message: "2nd parameter is not a string".to_string(),
    })?;
    let delimiter_start_str = args[2].as_str().ok_or_else(|| BurregoError::BuiltinError {
        name: "regex.template_match".to_string(),
        message: "3rd parameter is not a string".to_string(),
    })?;
    if delimiter_start_str.len() != 1 {
        return Err(BurregoError::BuiltinError {
            name: "regex.template_match".to_string(),
            message: "3rd parameter has to be exactly one character long".to_string(),
        });
    }
    let delimiter_end_str = args[3].as_str().ok_or_else(|| BurregoError::BuiltinError {
        name: "regex.template_match".to_string(),
        message: "4th parameter is not a string".to_string(),
    })?;
    if delimiter_end_str.len() != 1 {
        return Err(BurregoError::BuiltinError {
            name: "regex.template_match".to_string(),
            message: "4th parameter has to be exactly one character long".to_string(),
        });
    }
    let computed_regexp = TemplateMatch::regexp_from_template(
        pattern_str,
        // safe, since we have ensured that the length is 1
        delimiter_start_str.chars().next().unwrap(),
        // safe, since we have ensured that the length is 1
        delimiter_end_str.chars().next().unwrap(),
    )?;
    serde_json::to_value(computed_regexp.is_match(string_str)).map_err(|e| {
        BurregoError::BuiltinError {
            name: "regex.template_match".to_string(),
            message: format!("cannot convert value into JSON: {e:?}"),
        }
    })
}

pub fn find_n(args: &[serde_json::Value]) -> Result<serde_json::Value> {
    if args.len() != 3 {
        return Err(BurregoError::BuiltinError {
            name: "regex.find_n".to_string(),
            message: "Wrong number of arguments given to ".to_string(),
        });
    }
    let pattern_str = args[0].as_str().ok_or_else(|| BurregoError::BuiltinError {
        name: "regex.find_n".to_string(),
        message: "1st parameter is not a string".to_string(),
    })?;
    let string_str = args[1].as_str().ok_or_else(|| BurregoError::BuiltinError {
        name: "regex.find_n".to_string(),
        message: "2nd parameter is not a string".to_string(),
    })?;
    let take_number = args[2].as_i64().ok_or_else(|| BurregoError::BuiltinError {
        name: "regex.find_n".to_string(),
        message: "3rd parameter is not a number".to_string(),
    })?;

    let take_n = if take_number != -1 {
        take_number as usize
    } else {
        Regex::new(pattern_str)
            .map_err(|e| BurregoError::BuiltinError {
                name: "regex.find_n".to_string(),
                message: format!(
                    "cannot build regex from the given pattern string '{pattern_str}': {e:?}"
                ),
            })?
            .find_iter(string_str)
            .count()
    };

    let matches: Vec<String> = Regex::new(pattern_str)
        .map_err(|e| BurregoError::BuiltinError {
            name: "regex.find_n".to_string(),
            message: format!(
                "cannot build regex from the given pattern string '{pattern_str}': {e:?}"
            ),
        })?
        .find_iter(string_str)
        .take(take_n)
        .map(|match_| String::from(match_.as_str()))
        .collect();

    serde_json::to_value(matches).map_err(|e| BurregoError::BuiltinError {
        name: "regex.find_n".to_string(),
        message: format!("cannot convert value into JSON: {e:?}"),
    })
}

struct Expression {
    is_regexp: bool,
    expression: String,
}

impl Display for Expression {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_regexp {
            write!(f, "{}", &self.expression)
        } else {
            write!(f, "{}", &regex_escape(&self.expression))
        }
    }
}

struct ExpressionList(Vec<Expression>);

impl Display for ExpressionList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for expression in self.0.iter() {
            write!(f, "{expression}")?;
        }
        Ok(())
    }
}

struct TemplateMatch {}

impl TemplateMatch {
    fn regexp_from_template(
        template: &str,
        delimiter_start: char,
        delimiter_end: char,
    ) -> Result<Regex> {
        let mut expressions = ExpressionList(Vec::new());
        let mut current_expression = Expression {
            is_regexp: false,
            expression: String::new(),
        };
        let mut delimiters_open = 0;

        for c in template.chars() {
            if c == delimiter_start {
                delimiters_open += 1;
                if delimiters_open == 1 {
                    if !current_expression.expression.is_empty() {
                        expressions.0.push(current_expression);
                    }
                    current_expression = Expression {
                        is_regexp: true,
                        expression: String::new(),
                    }
                }
            } else if c == delimiter_end {
                delimiters_open -= 1;
                if delimiters_open == 0 {
                    if !current_expression.expression.is_empty() {
                        expressions.0.push(current_expression);
                    }
                    current_expression = Expression {
                        is_regexp: false,
                        expression: String::new(),
                    }
                }
            } else {
                current_expression.expression.push(c);
            }
        }

        if !current_expression.expression.is_empty() {
            expressions.0.push(current_expression);
        }

        Regex::from_str(&format!("{expressions}")).map_err(|e| BurregoError::BuiltinError {
            name: "regex".to_string(),
            message: format!("tried to initialize an invalid regular expression: {e:?}"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regex_from_template() -> Result<()> {
        assert!(
            TemplateMatch::regexp_from_template("urn:foo:bar:baz", '{', '}',)?
                .is_match("urn:foo:bar:baz"),
        );

        assert!(
            TemplateMatch::regexp_from_template("urn:foo:{.*}", '{', '}',)?
                .is_match("urn:foo:bar:baz"),
        );

        assert!(
            TemplateMatch::regexp_from_template("urn:foo:<.*>", '<', '>',)?
                .is_match("urn:foo:bar:baz"),
        );

        assert!(
            TemplateMatch::regexp_from_template("urn:foo:{.*}", '<', '>',)?
                .is_match("urn:foo:{.*}"),
        );

        assert!(TemplateMatch::regexp_from_template(
            "urn:foo:test:section-<[0-9]{2}>:alert-<[0-9]{4}>",
            '<',
            '>',
        )?
        .is_match("urn:foo:test:section-42:alert-1234"),);

        Ok(())
    }

    #[test]
    fn find_n() -> Result<()> {
        assert_eq!(
            super::find_n(&[
                serde_json::to_value("a.").unwrap(),
                serde_json::to_value("paranormal").unwrap(),
                serde_json::to_value(1).unwrap()
            ])?
            .as_array()
            .unwrap(),
            &vec!["ar",],
        );

        assert_eq!(
            super::find_n(&[
                serde_json::to_value("a.").unwrap(),
                serde_json::to_value("paranormal").unwrap(),
                serde_json::to_value(2).unwrap()
            ])?
            .as_array()
            .unwrap(),
            &vec!["ar", "an",],
        );

        assert_eq!(
            super::find_n(&[
                serde_json::to_value("a.").unwrap(),
                serde_json::to_value("paranormal").unwrap(),
                serde_json::to_value(10).unwrap()
            ])?
            .as_array()
            .unwrap(),
            &vec!["ar", "an", "al"],
        );

        assert_eq!(
            super::find_n(&[
                serde_json::to_value("a.").unwrap(),
                serde_json::to_value("paranormal").unwrap(),
                serde_json::to_value(-1).unwrap()
            ])?
            .as_array()
            .unwrap(),
            &vec!["ar", "an", "al"],
        );

        assert_eq!(
            super::find_n(&[
                serde_json::to_value("nomatch").unwrap(),
                serde_json::to_value("paranormal").unwrap(),
                serde_json::to_value(-1).unwrap()
            ])?
            .as_array()
            .unwrap(),
            &vec![] as &Vec<String>,
        );

        Ok(())
    }
}
