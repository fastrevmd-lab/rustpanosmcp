//! Bounded structural validation for untrusted PAN-OS XML responses.

use crate::{PanosMcpError, Result};
use quick_xml::{Reader, XmlVersion, events::Event};

/// Parser limits applied before semantic response processing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XmlLimits {
    /// Maximum raw response size in bytes.
    pub max_bytes: usize,
    /// Maximum nested element depth.
    pub max_depth: usize,
}

impl Default for XmlLimits {
    fn default() -> Self {
        Self {
            max_bytes: 5 * 1024 * 1024,
            max_depth: 64,
        }
    }
}

/// Minimal metadata from a validated PAN-OS `<response>` envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvelopeSummary {
    /// `status` attribute, when present.
    pub status: Option<String>,
    /// PAN-OS numeric `code` attribute, when present.
    pub code: Option<String>,
}

/// Validate XML structure and return top-level PAN-OS response attributes.
///
/// DTD declarations are rejected, raw input and depth are bounded, and the
/// root element must be `response`. Entity expansion is therefore never
/// enabled by this parser.
pub fn validate_panos_response(input: &[u8], limits: XmlLimits) -> Result<EnvelopeSummary> {
    if input.len() > limits.max_bytes {
        return Err(PanosMcpError::InputTooLarge {
            field: "panos_xml_response",
            limit: limits.max_bytes,
        });
    }

    let mut reader = Reader::from_reader(input);
    reader.config_mut().trim_text(true);
    reader.config_mut().check_end_names = true;

    let mut depth = 0usize;
    let mut saw_root = false;
    let mut root_closed = false;
    let mut summary = EnvelopeSummary {
        status: None,
        code: None,
    };

    loop {
        match reader.read_event() {
            Ok(Event::Start(element)) => {
                if root_closed {
                    return Err(PanosMcpError::Xml(
                        "response contains multiple root elements".to_owned(),
                    ));
                }
                depth = depth.saturating_add(1);
                if depth > limits.max_depth {
                    return Err(PanosMcpError::Xml(format!(
                        "element depth exceeds the {}-level limit",
                        limits.max_depth
                    )));
                }
                if !saw_root {
                    if element.name().as_ref() != b"response" {
                        return Err(PanosMcpError::Xml(
                            "root element must be 'response'".to_owned(),
                        ));
                    }
                    saw_root = true;
                    for attribute in element.attributes().with_checks(true) {
                        let attribute =
                            attribute.map_err(|error| PanosMcpError::Xml(error.to_string()))?;
                        let value = attribute
                            .decoded_and_normalized_value(XmlVersion::Implicit1_0, reader.decoder())
                            .map_err(|error| PanosMcpError::Xml(error.to_string()))?
                            .into_owned();
                        match attribute.key.as_ref() {
                            b"status" => summary.status = Some(value),
                            b"code" => summary.code = Some(value),
                            _ => {}
                        }
                    }
                }
            }
            Ok(Event::End(_)) => {
                if depth == 0 {
                    return Err(PanosMcpError::Xml(
                        "response contains an unexpected closing element".to_owned(),
                    ));
                }
                depth -= 1;
                if saw_root && depth == 0 {
                    root_closed = true;
                }
            }
            Ok(Event::Empty(element)) => {
                let empty_depth = depth.saturating_add(1);
                if empty_depth > limits.max_depth {
                    return Err(PanosMcpError::Xml(format!(
                        "element depth exceeds the {}-level limit",
                        limits.max_depth
                    )));
                }
                if !saw_root {
                    if element.name().as_ref() != b"response" {
                        return Err(PanosMcpError::Xml(
                            "root element must be 'response'".to_owned(),
                        ));
                    }
                    saw_root = true;
                    root_closed = true;
                    for attribute in element.attributes().with_checks(true) {
                        let attribute =
                            attribute.map_err(|error| PanosMcpError::Xml(error.to_string()))?;
                        let value = attribute
                            .decoded_and_normalized_value(XmlVersion::Implicit1_0, reader.decoder())
                            .map_err(|error| PanosMcpError::Xml(error.to_string()))?
                            .into_owned();
                        match attribute.key.as_ref() {
                            b"status" => summary.status = Some(value),
                            b"code" => summary.code = Some(value),
                            _ => {}
                        }
                    }
                } else if depth == 0 {
                    return Err(PanosMcpError::Xml(
                        "response contains multiple root elements".to_owned(),
                    ));
                }
            }
            Ok(Event::DocType(_)) => {
                return Err(PanosMcpError::Xml(
                    "DOCTYPE declarations are forbidden".to_owned(),
                ));
            }
            Ok(Event::Text(text))
                if depth == 0
                    && text
                        .as_ref()
                        .iter()
                        .any(|byte| !matches!(byte, b' ' | b'\t' | b'\n' | b'\r')) =>
            {
                return Err(PanosMcpError::Xml(
                    "non-whitespace text is forbidden outside the root element".to_owned(),
                ));
            }
            Ok(Event::CData(text)) if depth == 0 && !text.is_empty() => {
                return Err(PanosMcpError::Xml(
                    "CDATA is forbidden outside the root element".to_owned(),
                ));
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(error) => return Err(PanosMcpError::Xml(error.to_string())),
        }
    }

    if !saw_root {
        return Err(PanosMcpError::Xml(
            "response contains no root element".to_owned(),
        ));
    }
    if depth != 0 || !root_closed {
        return Err(PanosMcpError::Xml(
            "response ended with unclosed elements".to_owned(),
        ));
    }

    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_doctype_before_entity_processing() {
        let xml = br#"<!DOCTYPE response [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
                     <response status="success"><result>&xxe;</result></response>"#;
        let error = validate_panos_response(xml, XmlLimits::default())
            .expect_err("DOCTYPE input must be rejected");
        assert!(error.to_string().contains("DOCTYPE"));
    }

    #[test]
    fn rejects_excessive_depth() {
        let xml = b"<response><a><b/></a></response>";
        let error = validate_panos_response(
            xml,
            XmlLimits {
                max_bytes: 1024,
                max_depth: 2,
            },
        )
        .expect_err("depth three must exceed a limit of two");
        assert!(error.to_string().contains("depth"));
    }

    #[test]
    fn rejects_oversized_input_before_parsing() {
        let error = validate_panos_response(
            b"<response/>",
            XmlLimits {
                max_bytes: 4,
                max_depth: 64,
            },
        )
        .expect_err("input must be size-capped");
        assert!(matches!(error, PanosMcpError::InputTooLarge { .. }));
    }

    #[test]
    fn rejects_multiple_root_elements() {
        let error = validate_panos_response(
            b"<response status=\"success\"/><response status=\"success\"/>",
            XmlLimits::default(),
        )
        .expect_err("a second root element must be rejected");
        assert!(error.to_string().contains("multiple root"));
    }

    #[test]
    fn rejects_trailing_text() {
        let error = validate_panos_response(
            b"<response status=\"success\"/>trailing",
            XmlLimits::default(),
        )
        .expect_err("trailing text must be rejected");
        assert!(error.to_string().contains("outside the root"));
    }
}
