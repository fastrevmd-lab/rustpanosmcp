//! Bounded PAN-OS XML parsing and read-only input validation.

use crate::{PanosMcpError, Result};
use quick_xml::{Reader, XmlVersion, events::Event};
use schemars::JsonSchema;
use serde::Serialize;

/// Maximum accepted operational command body.
pub const MAX_OP_COMMAND_BYTES: usize = 64 * 1024;
/// Maximum accepted configuration XPath.
pub const MAX_XPATH_BYTES: usize = 4096;
const MAX_EXTRACTED_TEXT_BYTES: usize = 4096;
const MAX_ENVELOPE_ATTRIBUTE_BYTES: usize = 64;

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

/// Validated PAN-OS response and its stable envelope fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PanosResponse {
    /// PAN-OS status attribute.
    pub status: String,
    /// PAN-OS numeric response code, if supplied.
    pub code: Option<i32>,
    /// Bounded human-readable message extracted from `<msg>`.
    pub message: String,
    /// Complete, already size-bounded response XML.
    pub xml: String,
}

impl PanosResponse {
    /// Whether PAN-OS declared the request successful.
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.status.eq_ignore_ascii_case("success") && !matches!(self.code, Some(1..=18 | 21..))
    }

    /// Convert a PAN-OS error envelope to a stable typed error.
    pub fn ensure_success(self, device: &str) -> Result<Self> {
        if self.is_success() {
            return Ok(self);
        }
        let code = self.code.unwrap_or(-1);
        let message = if self.message.is_empty() {
            "PAN-OS returned an error without a message".to_owned()
        } else {
            self.message.clone()
        };
        Err(PanosMcpError::Api {
            device: device.to_owned(),
            code,
            name: panos_api_code_name(code),
            message,
        })
    }
}

/// Selected, stable fields returned by `show system info`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, JsonSchema)]
pub struct DeviceFacts {
    /// Configured hostname.
    pub hostname: Option<String>,
    /// Management IP address.
    pub management_ip: Option<String>,
    /// Hardware or VM model.
    pub model: Option<String>,
    /// Device serial number.
    pub serial: Option<String>,
    /// PAN-OS software version.
    pub software_version: Option<String>,
    /// Application content version.
    pub app_version: Option<String>,
    /// Threat content version.
    pub threat_version: Option<String>,
    /// Device uptime as reported by PAN-OS.
    pub uptime: Option<String>,
    /// Device family when supplied by the release.
    pub family: Option<String>,
}

/// Terminal and intermediate state from a PAN-OS asynchronous job.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JobStatus {
    /// PAN-OS job state, such as `PEND`, `ACT`, or `FIN`.
    pub status: Option<String>,
    /// Final result, such as `OK` or `FAIL`.
    pub result: Option<String>,
    /// Integer completion percentage when supplied.
    pub progress: Option<u8>,
    /// Bounded details from the job response.
    pub details: Option<String>,
}

impl JobStatus {
    /// Whether the job reached the documented terminal `FIN` state.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.status.as_deref() == Some("FIN")
    }

    /// Whether a terminal job reports success.
    #[must_use]
    pub fn succeeded(&self) -> bool {
        self.is_finished() && self.result.as_deref() == Some("OK")
    }
}

/// Validate XML structure and return top-level PAN-OS response attributes.
///
/// DTD declarations are rejected, raw input and depth are bounded, and the
/// root element must be `response`. Entity expansion is therefore never
/// enabled by this parser.
pub fn validate_panos_response(input: &[u8], limits: XmlLimits) -> Result<EnvelopeSummary> {
    validate_xml_root(input, limits, b"response", "panos_xml_response")
}

/// Parse a validated PAN-OS response envelope.
pub fn parse_panos_response(input: &[u8], limits: XmlLimits) -> Result<PanosResponse> {
    let summary = validate_panos_response(input, limits)?;
    let xml = std::str::from_utf8(input)
        .map_err(|_| PanosMcpError::Xml("response is not valid UTF-8".to_owned()))?
        .to_owned();
    let code = summary
        .code
        .as_deref()
        .map(str::parse::<i32>)
        .transpose()
        .map_err(|_| PanosMcpError::Xml("response code is not an integer".to_owned()))?;
    let message = collect_text_for_elements(input, &[b"msg", b"line"], 1024)?;
    Ok(PanosResponse {
        status: summary.status.unwrap_or_default(),
        code,
        message,
        xml,
    })
}

/// Validate a caller-supplied, read-only operational command.
///
/// Only a single `<show>...</show>` command is accepted. PAN-OS operational
/// mutations use other roots and are intentionally outside Phase 1.
pub fn validate_read_only_op_command(input: &str) -> Result<()> {
    validate_xml_root(
        input.as_bytes(),
        XmlLimits {
            max_bytes: MAX_OP_COMMAND_BYTES,
            max_depth: 32,
        },
        b"show",
        "command",
    )?;
    let mut reader = Reader::from_reader(input.as_bytes());
    loop {
        match reader.read_event() {
            Ok(Event::Start(element) | Event::Empty(element)) => {
                if element.attributes().next().is_some() {
                    return Err(PanosMcpError::Policy {
                        field: "command",
                        reason: "attributes on the show root are not permitted".to_owned(),
                    });
                }
                break;
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(error) => return Err(PanosMcpError::Xml(error.to_string())),
        }
    }
    Ok(())
}

/// Validate the deliberately small read-only XPath subset accepted in Phase 1.
pub fn validate_read_xpath(xpath: &str) -> Result<()> {
    if xpath.is_empty() {
        return Err(PanosMcpError::Policy {
            field: "xpath",
            reason: "value is empty".to_owned(),
        });
    }
    if xpath.len() > MAX_XPATH_BYTES {
        return Err(PanosMcpError::InputTooLarge {
            field: "xpath",
            limit: MAX_XPATH_BYTES,
        });
    }
    if xpath != "/config" && !xpath.starts_with("/config/") {
        return Err(PanosMcpError::Policy {
            field: "xpath",
            reason: "path must be rooted at /config".to_owned(),
        });
    }
    if xpath.contains("//") || xpath.contains("..") {
        return Err(PanosMcpError::Policy {
            field: "xpath",
            reason: "descendant and parent traversal are forbidden".to_owned(),
        });
    }
    if xpath.bytes().any(|byte| {
        !byte.is_ascii()
            || !(byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'/' | b'-' | b'_' | b'.' | b':' | b'[' | b']' | b'@' | b'=' | b'\'' | b'"'
                ))
    }) {
        return Err(PanosMcpError::Policy {
            field: "xpath",
            reason: "value contains unsupported XPath syntax".to_owned(),
        });
    }
    if xpath.matches('/').count() > 64 {
        return Err(PanosMcpError::Policy {
            field: "xpath",
            reason: "path exceeds the 64-segment limit".to_owned(),
        });
    }

    let mut brackets = 0_u8;
    let mut quote = None;
    for byte in xpath.bytes() {
        match (quote, byte) {
            (Some(open), current) if current == open => quote = None,
            (Some(_), _) => {}
            (None, b'\'' | b'"') => quote = Some(byte),
            (None, b'[') => {
                brackets = brackets
                    .checked_add(1)
                    .ok_or_else(|| PanosMcpError::Policy {
                        field: "xpath",
                        reason: "predicate nesting is invalid".to_owned(),
                    })?;
                if brackets > 1 {
                    return Err(PanosMcpError::Policy {
                        field: "xpath",
                        reason: "nested predicates are forbidden".to_owned(),
                    });
                }
            }
            (None, b']') => {
                brackets = brackets
                    .checked_sub(1)
                    .ok_or_else(|| PanosMcpError::Policy {
                        field: "xpath",
                        reason: "predicate brackets are unbalanced".to_owned(),
                    })?;
            }
            _ => {}
        }
    }
    if brackets != 0 || quote.is_some() {
        return Err(PanosMcpError::Policy {
            field: "xpath",
            reason: "quotes or predicate brackets are unbalanced".to_owned(),
        });
    }
    Ok(())
}

/// Extract common facts from a successful `show system info` response.
pub fn parse_device_facts(response: &PanosResponse) -> Result<DeviceFacts> {
    let input = response.xml.as_bytes();
    Ok(DeviceFacts {
        hostname: first_element_text(input, b"hostname")?,
        management_ip: first_element_text(input, b"ip-address")?,
        model: first_element_text(input, b"model")?,
        serial: first_element_text(input, b"serial")?,
        software_version: first_element_text(input, b"sw-version")?,
        app_version: first_element_text(input, b"app-version")?,
        threat_version: first_element_text(input, b"threat-version")?,
        uptime: first_element_text(input, b"uptime")?,
        family: first_element_text(input, b"family")?,
    })
}

/// Extract a PAN-OS job state from a successful job response.
pub fn parse_job_status(response: &PanosResponse) -> Result<JobStatus> {
    let input = response.xml.as_bytes();
    let progress = first_child_text(input, b"job", b"progress")?
        .map(|value| value.parse::<u8>())
        .transpose()
        .map_err(|_| PanosMcpError::Xml("job progress is not an integer".to_owned()))?;
    Ok(JobStatus {
        status: first_child_text(input, b"job", b"status")?,
        result: first_child_text(input, b"job", b"result")?,
        progress,
        details: first_child_text(input, b"job", b"details")?,
    })
}

/// Stable name for the documented PAN-OS XML API response code.
#[must_use]
pub const fn panos_api_code_name(code: i32) -> &'static str {
    match code {
        1 => "unknown-command",
        2..=5 | 11 | 21 => "internal-error",
        6 => "bad-xpath",
        7 => "object-not-present",
        8 => "object-not-unique",
        10 => "reference-count-not-zero",
        12 => "invalid-object",
        13 => "object-not-found",
        14 => "operation-not-possible",
        15 => "operation-denied",
        16 => "unauthorized",
        17 => "invalid-command",
        18 => "malformed-command",
        19 => "success",
        20 => "success-command-completed",
        22 => "session-timed-out",
        _ => "unknown",
    }
}

fn validate_xml_root(
    input: &[u8],
    limits: XmlLimits,
    expected_root: &[u8],
    input_field: &'static str,
) -> Result<EnvelopeSummary> {
    if input.len() > limits.max_bytes {
        return Err(PanosMcpError::InputTooLarge {
            field: input_field,
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
                        "input contains multiple root elements".to_owned(),
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
                    if element.name().as_ref() != expected_root {
                        return Err(PanosMcpError::Xml(format!(
                            "root element must be '{}'",
                            String::from_utf8_lossy(expected_root)
                        )));
                    }
                    saw_root = true;
                    read_envelope_attributes(&reader, &element, &mut summary)?;
                }
            }
            Ok(Event::End(_)) => {
                if depth == 0 {
                    return Err(PanosMcpError::Xml(
                        "input contains an unexpected closing element".to_owned(),
                    ));
                }
                depth -= 1;
                if saw_root && depth == 0 {
                    root_closed = true;
                }
            }
            Ok(Event::Empty(element)) => {
                if depth.saturating_add(1) > limits.max_depth {
                    return Err(PanosMcpError::Xml(format!(
                        "element depth exceeds the {}-level limit",
                        limits.max_depth
                    )));
                }
                if !saw_root {
                    if element.name().as_ref() != expected_root {
                        return Err(PanosMcpError::Xml(format!(
                            "root element must be '{}'",
                            String::from_utf8_lossy(expected_root)
                        )));
                    }
                    saw_root = true;
                    root_closed = true;
                    read_envelope_attributes(&reader, &element, &mut summary)?;
                } else if depth == 0 {
                    return Err(PanosMcpError::Xml(
                        "input contains multiple root elements".to_owned(),
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
            "input contains no root element".to_owned(),
        ));
    }
    if depth != 0 || !root_closed {
        return Err(PanosMcpError::Xml(
            "input ended with unclosed elements".to_owned(),
        ));
    }
    Ok(summary)
}

fn read_envelope_attributes(
    reader: &Reader<&[u8]>,
    element: &quick_xml::events::BytesStart<'_>,
    summary: &mut EnvelopeSummary,
) -> Result<()> {
    for attribute in element.attributes().with_checks(true) {
        let attribute = attribute.map_err(|error| PanosMcpError::Xml(error.to_string()))?;
        let value = attribute
            .decoded_and_normalized_value(XmlVersion::Implicit1_0, reader.decoder())
            .map_err(|error| PanosMcpError::Xml(error.to_string()))?
            .into_owned();
        if value.len() > MAX_ENVELOPE_ATTRIBUTE_BYTES {
            return Err(PanosMcpError::Xml(format!(
                "response envelope attribute exceeds {MAX_ENVELOPE_ATTRIBUTE_BYTES} bytes"
            )));
        }
        match attribute.key.as_ref() {
            b"status" => summary.status = Some(value),
            b"code" => summary.code = Some(value),
            _ => {}
        }
    }
    Ok(())
}

fn first_element_text(input: &[u8], wanted: &[u8]) -> Result<Option<String>> {
    let mut reader = Reader::from_reader(input);
    reader.config_mut().trim_text(true);
    let mut inside = false;
    loop {
        match reader.read_event() {
            Ok(Event::Start(element)) if element.name().as_ref() == wanted => inside = true,
            Ok(Event::Text(text)) if inside => {
                let value = text
                    .decode()
                    .map_err(|error| PanosMcpError::Xml(error.to_string()))?
                    .into_owned();
                return bounded_extracted_text(value).map(Some);
            }
            Ok(Event::CData(text)) if inside => {
                let value = text
                    .decode()
                    .map_err(|error| PanosMcpError::Xml(error.to_string()))?
                    .into_owned();
                return bounded_extracted_text(value).map(Some);
            }
            Ok(Event::End(element)) if element.name().as_ref() == wanted => return Ok(None),
            Ok(Event::DocType(_)) => {
                return Err(PanosMcpError::Xml(
                    "DOCTYPE declarations are forbidden".to_owned(),
                ));
            }
            Ok(Event::Eof) => return Ok(None),
            Ok(_) => {}
            Err(error) => return Err(PanosMcpError::Xml(error.to_string())),
        }
    }
}

fn first_child_text(input: &[u8], parent: &[u8], wanted: &[u8]) -> Result<Option<String>> {
    let mut reader = Reader::from_reader(input);
    reader.config_mut().trim_text(true);
    let mut parent_depth = None;
    let mut depth = 0_usize;
    let mut inside_wanted = false;
    loop {
        match reader.read_event() {
            Ok(Event::Start(element)) => {
                depth += 1;
                if parent_depth.is_none() && element.name().as_ref() == parent {
                    parent_depth = Some(depth);
                } else if parent_depth.is_some_and(|value| depth == value + 1)
                    && element.name().as_ref() == wanted
                {
                    inside_wanted = true;
                }
            }
            Ok(Event::Text(text)) if inside_wanted => {
                return text
                    .decode()
                    .map_err(|error| PanosMcpError::Xml(error.to_string()))
                    .and_then(|value| bounded_extracted_text(value.into_owned()).map(Some));
            }
            Ok(Event::CData(text)) if inside_wanted => {
                return text
                    .decode()
                    .map_err(|error| PanosMcpError::Xml(error.to_string()))
                    .and_then(|value| bounded_extracted_text(value.into_owned()).map(Some));
            }
            Ok(Event::End(element)) => {
                if inside_wanted && element.name().as_ref() == wanted {
                    return Ok(None);
                }
                if parent_depth == Some(depth) && element.name().as_ref() == parent {
                    return Ok(None);
                }
                depth = depth.saturating_sub(1);
            }
            Ok(Event::DocType(_)) => {
                return Err(PanosMcpError::Xml(
                    "DOCTYPE declarations are forbidden".to_owned(),
                ));
            }
            Ok(Event::Eof) => return Ok(None),
            Ok(_) => {}
            Err(error) => return Err(PanosMcpError::Xml(error.to_string())),
        }
    }
}

fn collect_text_for_elements(input: &[u8], wanted: &[&[u8]], max_bytes: usize) -> Result<String> {
    let mut reader = Reader::from_reader(input);
    reader.config_mut().trim_text(true);
    let mut matched_depth = 0_usize;
    let mut pieces = Vec::new();
    loop {
        match reader.read_event() {
            Ok(Event::Start(element)) => {
                if matched_depth > 0 || wanted.contains(&element.name().as_ref()) {
                    matched_depth += 1;
                }
            }
            Ok(Event::End(_)) if matched_depth > 0 => matched_depth -= 1,
            Ok(Event::Text(text)) if matched_depth > 0 => {
                let value = text
                    .decode()
                    .map_err(|error| PanosMcpError::Xml(error.to_string()))?;
                let value = value.trim();
                if !value.is_empty() {
                    pieces.push(value.to_owned());
                }
            }
            Ok(Event::DocType(_)) => {
                return Err(PanosMcpError::Xml(
                    "DOCTYPE declarations are forbidden".to_owned(),
                ));
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(error) => return Err(PanosMcpError::Xml(error.to_string())),
        }
    }
    let mut message = pieces.join("; ");
    if message.len() > max_bytes {
        let mut boundary = max_bytes;
        while !message.is_char_boundary(boundary) {
            boundary -= 1;
        }
        message.truncate(boundary);
    }
    Ok(message)
}

fn bounded_extracted_text(value: String) -> Result<String> {
    if value.len() > MAX_EXTRACTED_TEXT_BYTES {
        return Err(PanosMcpError::Xml(format!(
            "extracted element text exceeds {MAX_EXTRACTED_TEXT_BYTES} bytes"
        )));
    }
    Ok(value)
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
    fn rejects_excessive_depth_size_multiple_roots_and_trailing_text() {
        assert!(
            validate_panos_response(
                b"<response><a><b/></a></response>",
                XmlLimits {
                    max_bytes: 1024,
                    max_depth: 2
                }
            )
            .is_err()
        );
        assert!(matches!(
            validate_panos_response(
                b"<response/>",
                XmlLimits {
                    max_bytes: 4,
                    max_depth: 64
                }
            ),
            Err(PanosMcpError::InputTooLarge { .. })
        ));
        assert!(
            validate_panos_response(
                b"<response status=\"success\"/><response status=\"success\"/>",
                XmlLimits::default()
            )
            .is_err()
        );
        assert!(
            validate_panos_response(
                b"<response status=\"success\"/>trailing",
                XmlLimits::default()
            )
            .is_err()
        );
    }

    #[test]
    fn maps_error_response_and_extracts_message() {
        let response = parse_panos_response(
            br#"<response status="error" code="7"><msg><line>Object is not present</line></msg></response>"#,
            XmlLimits::default(),
        ).expect("valid response");
        assert_eq!(response.message, "Object is not present");
        let error = response.ensure_success("fw").expect_err("API error");
        assert!(matches!(
            error,
            PanosMcpError::Api {
                code: 7,
                name: "object-not-present",
                ..
            }
        ));
    }

    #[test]
    fn accepts_only_show_operational_commands() {
        validate_read_only_op_command("<show><system><info/></system></show>")
            .expect("read command");
        assert!(validate_read_only_op_command("<show mode=\"unsafe\"/>").is_err());
        assert!(
            validate_read_only_op_command("<request><restart><system/></restart></request>")
                .is_err()
        );
        assert!(validate_read_only_op_command("<show/><show/>").is_err());
        assert!(validate_read_only_op_command("<!DOCTYPE show><show/>").is_err());
    }

    #[test]
    fn validates_safe_config_xpath_subset() {
        validate_read_xpath(
            "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']",
        )
        .expect("normal PAN-OS XPath");
        assert!(validate_read_xpath("/config//entry").is_err());
        assert!(validate_read_xpath("/config/../mgt-config").is_err());
        assert!(validate_read_xpath("/op/commands").is_err());
        assert!(validate_read_xpath("/config/*").is_err());
    }

    #[test]
    fn extracts_facts_and_job_status() {
        let response = parse_panos_response(
            br#"<response status="success" code="19"><result><system><hostname>fw-1</hostname><sw-version>11.2.3</sw-version><serial>001</serial></system></result></response>"#,
            XmlLimits::default(),
        ).expect("facts response");
        let facts = parse_device_facts(&response).expect("facts");
        assert_eq!(facts.hostname.as_deref(), Some("fw-1"));
        assert_eq!(facts.software_version.as_deref(), Some("11.2.3"));

        let response = parse_panos_response(
            br#"<response status="success"><result><job><status>FIN</status><result>OK</result><progress>100</progress></job></result></response>"#,
            XmlLimits::default(),
        ).expect("job response");
        let job = parse_job_status(&response).expect("job");
        assert!(job.succeeded());
    }
}
