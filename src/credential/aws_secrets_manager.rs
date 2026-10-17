use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_config::{meta::region::RegionProviderChain, BehaviorVersion, Region};
use aws_sdk_secretsmanager::Client;
use serde_json::Value;
use tokio::sync::OnceCell;
use tracing::debug;

use super::CredentialProvider;

/// AWS Secrets Manager credential provider.
///
/// References use one of these forms:
/// - `secret-id` to return the full secret value
/// - `secret-id#field.path` to extract a field from a JSON secret string
pub struct AwsSecretsManagerProvider {
    region: Option<String>,
    profile: Option<String>,
    client: OnceCell<Client>,
}

impl AwsSecretsManagerProvider {
    pub fn new(region: Option<String>, profile: Option<String>) -> Self {
        Self {
            region,
            profile,
            client: OnceCell::new(),
        }
    }

    async fn client(&self) -> Result<&Client> {
        self.client
            .get_or_try_init(|| async {
                let region_provider = match &self.region {
                    Some(region) => RegionProviderChain::first_try(Region::new(region.clone())),
                    None => RegionProviderChain::default_provider(),
                };

                let mut loader = aws_config::defaults(BehaviorVersion::latest())
                    .region(region_provider);

                if let Some(profile) = &self.profile {
                    loader = loader.profile_name(profile);
                }

                let shared_config = loader.load().await;
                Ok(Client::new(&shared_config))
            })
            .await
    }
}

#[async_trait]
impl CredentialProvider for AwsSecretsManagerProvider {
    async fn resolve(&self, reference: &str) -> Result<String> {
        let (secret_id, field_path) = parse_reference(reference)?;

        debug!(reference, secret_id, "resolving AWS Secrets Manager credential");

        let response = self
            .client()
            .await?
            .get_secret_value()
            .secret_id(secret_id)
            .send()
            .await
            .with_context(|| format!("failed to fetch AWS Secrets Manager secret '{}'", secret_id))?;

        if let Some(secret_string) = response.secret_string() {
            return extract_secret_value(secret_string, field_path);
        }

        if let Some(secret_binary) = response.secret_binary() {
            if field_path.is_some() {
                anyhow::bail!(
                    "AWS Secrets Manager reference '{}' requested a JSON field, but the secret is binary",
                    reference
                );
            }

            let secret = String::from_utf8(secret_binary.as_ref().to_vec()).with_context(|| {
                format!(
                    "AWS Secrets Manager secret '{}' is binary and not valid UTF-8",
                    secret_id
                )
            })?;

            return Ok(secret);
        }

        anyhow::bail!(
            "AWS Secrets Manager secret '{}' had neither secret_string nor secret_binary",
            secret_id
        )
    }
}

fn parse_reference(reference: &str) -> Result<(&str, Option<&str>)> {
    let reference = reference.trim();
    if reference.is_empty() {
        anyhow::bail!("AWS Secrets Manager reference cannot be empty");
    }

    let (secret_id, field_path) = match reference.split_once('#') {
        Some((secret_id, field_path)) => {
            if field_path.is_empty() {
                anyhow::bail!(
                    "AWS Secrets Manager reference '{}' has an empty field selector",
                    reference
                );
            }
            (secret_id, Some(field_path))
        }
        None => (reference, None),
    };

    if secret_id.is_empty() {
        anyhow::bail!(
            "AWS Secrets Manager reference '{}' is missing the secret identifier",
            reference
        );
    }

    Ok((secret_id, field_path))
}

fn extract_secret_value(secret_string: &str, field_path: Option<&str>) -> Result<String> {
    let Some(field_path) = field_path else {
        return Ok(secret_string.to_string());
    };

    let secret_json: Value = serde_json::from_str(secret_string)
        .with_context(|| format!("failed to parse JSON secret while resolving field '{}'", field_path))?;

    let mut current = &secret_json;
    for field in field_path.split('.') {
        current = current.get(field).ok_or_else(|| {
            anyhow::anyhow!(
                "AWS Secrets Manager JSON secret does not contain field path '{}'",
                field_path
            )
        })?;
    }

    match current {
        Value::String(value) => Ok(value.clone()),
        value => serde_json::to_string(value)
            .context("failed to serialize non-string JSON secret field"),
    }
}

#[cfg(test)]
mod tests {
    use super::{extract_secret_value, parse_reference};

    #[test]
    fn parses_plain_reference() {
        let (secret_id, field_path) = parse_reference("service/api-key").unwrap();
        assert_eq!(secret_id, "service/api-key");
        assert_eq!(field_path, None);
    }

    #[test]
    fn parses_reference_with_field_path() {
        let (secret_id, field_path) = parse_reference("service/api-key#token.value").unwrap();
        assert_eq!(secret_id, "service/api-key");
        assert_eq!(field_path, Some("token.value"));
    }

    #[test]
    fn extracts_nested_json_field() {
        let secret = r#"{"token":{"value":"abc123"}}"#;
        let value = extract_secret_value(secret, Some("token.value")).unwrap();
        assert_eq!(value, "abc123");
    }

    #[test]
    fn serializes_non_string_json_field() {
        let secret = r#"{"token":{"ttl":3600}}"#;
        let value = extract_secret_value(secret, Some("token")).unwrap();
        assert_eq!(value, r#"{"ttl":3600}"#);
    }
}