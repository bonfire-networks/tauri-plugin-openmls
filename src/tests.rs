use super::*;

#[test]
fn sanitize_strips_script_from_article() {
    let input = r#"{"type":"Article","content":"<script>window.__xss=1;</script>Legit text"}"#;
    let output = sanitize_message_content(input);
    let val: serde_json::Value = serde_json::from_str(&output).unwrap();
    let content = val["content"].as_str().unwrap();
    assert!(!content.contains("<script>"), "script tag must be stripped from Article");
    assert!(content.contains("Legit text"), "safe text must be preserved");
}

#[test]
fn sanitize_preserves_p_tag_in_article() {
    let input = r#"{"type":"Article","content":"<p>Block paragraph.</p>"}"#;
    let output = sanitize_message_content(input);
    let val: serde_json::Value = serde_json::from_str(&output).unwrap();
    let content = val["content"].as_str().unwrap();
    assert!(content.contains("Block paragraph."), "paragraph text must remain");
    assert!(content.contains("<p>"), "p tag must be preserved by ammonia defaults");
}

#[test]
fn sanitize_strips_script_from_note() {
    let input = r#"{"type":"Note","content":"<script>evil()</script>Safe text"}"#;
    let output = sanitize_message_content(input);
    let val: serde_json::Value = serde_json::from_str(&output).unwrap();
    let content = val["content"].as_str().unwrap();
    assert!(!content.contains("<script>"), "script tag must be stripped from Note");
    assert!(content.contains("Safe text"));
}

#[test]
fn sanitize_does_not_affect_image_type() {
    let input = r#"{"type":"Image","content":"<script>evil()</script>data"}"#;
    let output = sanitize_message_content(input);
    let val: serde_json::Value = serde_json::from_str(&output).unwrap();
    let content = val["content"].as_str().unwrap();
    assert!(content.contains("<script>"), "Image content must NOT be sanitized");
}

#[test]
fn sanitize_ignores_non_html_content() {
    let input = r#"{"type":"Note","content":"Hello world"}"#;
    let output = sanitize_message_content(input);
    let val: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert_eq!(val["content"].as_str().unwrap(), "Hello world");
}
