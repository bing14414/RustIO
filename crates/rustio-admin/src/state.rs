use std::{
    collections::{HashMap, HashSet, VecDeque},
    fs::OpenOptions,
    io::Write,
    path::PathBuf,
    sync::atomic::{AtomicI64, AtomicU64, Ordering},
    sync::Arc,
};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use chrono::{DateTime, Duration, Utc};
use reqwest::Client;
use rustio_core::{
    AlertChannel, AlertEscalationPolicy, AlertHistoryEntry, AlertRule, AlertSilence, AuditEvent,
    BatchRunScope, BucketAclConfig, BucketCorsRule, BucketEncryptionConfig, BucketLegalHoldConfig,
    BucketLifecycleRule, BucketNotificationRule, BucketObjectLockConfig,
    BucketPublicAccessBlockConfig, BucketRetentionConfig, BucketSpec, BucketTag,
    ClusterConfigSnapshot, ClusterNode, ClusterQuota, ConsoleSession, DiagnosticReport, IamGroup,
    IamPolicy, IamUser, JobStatus, LoginResponse, RemoteTierConfig, ReplicationBacklogItem,
    ReplicationStatus, RuntimeEvent, S3ObjectEncryptionMeta, S3ObjectMeta, SecurityConfig,
    SiteReplicationStatus, StsSession, TenantSpec,
};
use rustls::{pki_types::ServerName, ClientConfig, RootCertStore};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader},
    net::TcpStream,
    sync::{broadcast, RwLock},
    time::timeout,
};
use tokio_rustls::{client::TlsStream, TlsConnector};
use tracing::info;
use uuid::Uuid;

use crate::routes::{
    expire_current_object_for_lifecycle, expire_noncurrent_object_version_for_lifecycle,
    process_storage_governance_heal_queue_once, process_storage_governance_scan_once,
    transition_current_object_for_lifecycle, transition_noncurrent_object_version_for_lifecycle,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AlertSmtpTransport {
    Plain,
    StartTls,
    Tls,
}

#[derive(Debug, Clone, Default)]
pub struct StorageGovernanceRuntimeState {
    pub last_scan_at: Option<DateTime<Utc>>,
    pub last_heal_at: Option<DateTime<Utc>>,
    pub last_rebalance_at: Option<DateTime<Utc>>,
    pub last_decommission_at: Option<DateTime<Utc>>,
    pub last_scan_duration_seconds: f64,
    pub last_heal_duration_seconds: f64,
    pub last_scan_result: String,
    pub scan_runs_total: u64,
    pub scan_failures_total: u64,
    pub heal_objects_total: u64,
    pub heal_failures_total: u64,
    pub rebalance_objects_total: u64,
    pub rebalance_failures_total: u64,
    pub decommission_objects_total: u64,
    pub decommission_failures_total: u64,
    pub scan_running: bool,
    pub heal_running: usize,
    pub disk_last_anomaly_at: HashMap<String, DateTime<Utc>>,
    pub draining_disks: HashSet<String>,
    pub decommissioned_disks: HashSet<String>,
}

#[derive(Debug, Clone)]
struct LifecycleJobDraft {
    kind: String,
    bucket: String,
    object_key: String,
    idempotency_key: String,
    payload: Value,
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        path::PathBuf,
        sync::{Mutex, OnceLock},
        time::{SystemTime, UNIX_EPOCH},
    };

    use chrono::{Duration, Utc};
    use rustio_core::{AlertChannel, AuditEvent, ConsoleSession, ReplicationBacklogItem};
    use serde_json::json;

    use super::{AlertSmtpTransport, AppState, LocalCredential};

    fn test_env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn unique_temp_dir(prefix: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{}-{nonce}", std::process::id()))
    }

    #[test]
    fn parse_smtp_endpoint_supports_starttls_scheme() {
        let (server, recipient, transport) = AppState::alert_delivery_parse_smtp_endpoint(
            "smtp+starttls://smtp.example.com:587/ops@example.com",
        )
        .expect("smtp endpoint should parse");
        assert_eq!(server, "smtp.example.com:587");
        assert_eq!(recipient, "ops@example.com");
        assert_eq!(transport, AlertSmtpTransport::StartTls);
    }

    #[test]
    fn audit_pruning_keeps_latest_entries() {
        let _guard = test_env_lock()
            .lock()
            .expect("env lock should be available");
        std::env::set_var("RUSTIO_AUDIT_MAX_EVENTS", "100");

        let mut audits = (0..105)
            .map(|index| AuditEvent {
                id: format!("audit-{index}"),
                actor: "admin".to_string(),
                action: "auth.refresh".to_string(),
                resource: "session".to_string(),
                outcome: "success".to_string(),
                reason: None,
                timestamp: Utc::now(),
                details: json!({ "index": index }),
            })
            .collect::<Vec<_>>();

        super::prune_audits_locked(&mut audits);

        let ids = audits.into_iter().map(|entry| entry.id).collect::<Vec<_>>();
        assert_eq!(ids.len(), 100);
        assert_eq!(ids.first().map(String::as_str), Some("audit-5"));
        assert_eq!(ids.last().map(String::as_str), Some("audit-104"));

        std::env::remove_var("RUSTIO_AUDIT_MAX_EVENTS");
    }

    #[test]
    fn memory_trim_idle_threshold_defaults_to_twelve_hours() {
        let _guard = test_env_lock()
            .lock()
            .expect("env lock should be available");
        std::env::remove_var("RUSTIO_MEMORY_TRIM_IDLE_SECONDS");

        assert_eq!(
            AppState::memory_trim_idle_threshold(),
            std::time::Duration::from_secs(43_200)
        );
    }

    #[test]
    fn memory_trim_triggers_after_idle_threshold() {
        assert!(AppState::should_trim_memory(
            100,
            0,
            1_100,
            std::time::Duration::from_secs(900)
        ));
    }

    #[test]
    fn memory_trim_skips_when_already_trimmed_since_last_request() {
        assert!(!AppState::should_trim_memory(
            100,
            150,
            1_100,
            std::time::Duration::from_secs(900)
        ));
    }

    #[test]
    fn memory_trim_force_triggers_when_rss_exceeds_threshold() {
        assert!(AppState::should_force_trim_memory(
            0,
            7_500,
            128 * 1024 * 1024,
            128 * 1024 * 1024,
            std::time::Duration::from_secs(7_200)
        ));
    }

    #[test]
    fn memory_trim_force_skips_when_interval_not_elapsed() {
        assert!(!AppState::should_force_trim_memory(
            5_000,
            7_500,
            256 * 1024 * 1024,
            128 * 1024 * 1024,
            std::time::Duration::from_secs(7_200)
        ));
    }

    #[test]
    fn expired_replication_lease_does_not_block_same_target_progress() {
        let now = Utc::now();
        let backlog = vec![
            ReplicationBacklogItem {
                id: "expired-in-progress".to_string(),
                source_bucket: "photos".to_string(),
                target_site: "dr-site-a".to_string(),
                object_key: "2026/03/a.jpg".to_string(),
                rule_id: None,
                priority: 100,
                operation: "put".to_string(),
                checkpoint: 10,
                idempotency_key: "expired-in-progress".to_string(),
                version_id: Some("v1".to_string()),
                attempts: 1,
                status: "in_progress".to_string(),
                last_error: String::new(),
                lease_owner: Some("worker-1".to_string()),
                lease_until: Some(now - Duration::seconds(1)),
                queued_at: now - Duration::minutes(2),
                last_attempt_at: now - Duration::minutes(1),
            },
            ReplicationBacklogItem {
                id: "pending-next".to_string(),
                source_bucket: "photos".to_string(),
                target_site: "dr-site-a".to_string(),
                object_key: "2026/03/a.jpg".to_string(),
                rule_id: None,
                priority: 100,
                operation: "put".to_string(),
                checkpoint: 11,
                idempotency_key: "pending-next".to_string(),
                version_id: Some("v2".to_string()),
                attempts: 0,
                status: "pending".to_string(),
                last_error: String::new(),
                lease_owner: None,
                lease_until: None,
                queued_at: now - Duration::minutes(1),
                last_attempt_at: now - Duration::minutes(1),
            },
        ];

        assert!(
            !AppState::replication_target_blocked(&backlog, 1, &now),
            "expired in-progress lease should not block newer task on same target"
        );
    }

    #[test]
    fn parse_smtp_server_auth_supports_inline_credentials() {
        let (server, username, password) =
            AppState::alert_delivery_parse_smtp_server_auth("alice:secret@smtp.example.com:465");
        assert_eq!(server, "smtp.example.com:465");
        assert_eq!(username.as_deref(), Some("alice"));
        assert_eq!(password.as_deref(), Some("secret"));
    }

    #[test]
    fn parse_nats_endpoint_supports_tls_scheme() {
        let (server, subject, tls) =
            AppState::alert_delivery_parse_nats_endpoint("natss://nats.example.com:4222/ops.alert")
                .expect("nats endpoint should parse");
        assert_eq!(server, "nats.example.com:4222");
        assert_eq!(subject.as_deref(), Some("ops.alert"));
        assert!(tls);
    }

    #[test]
    fn parse_nats_server_auth_supports_token() {
        let (server, username, password, token) =
            AppState::alert_delivery_parse_nats_server_auth("apitoken@nats.example.com:4222");
        assert_eq!(server, "nats.example.com:4222");
        assert!(username.is_none());
        assert!(password.is_none());
        assert_eq!(token.as_deref(), Some("apitoken"));
    }

    #[test]
    fn parse_nats_server_auth_supports_user_password() {
        let (server, username, password, token) =
            AppState::alert_delivery_parse_nats_server_auth("alice:secret@nats.example.com:4222");
        assert_eq!(server, "nats.example.com:4222");
        assert_eq!(username.as_deref(), Some("alice"));
        assert_eq!(password.as_deref(), Some("secret"));
        assert!(token.is_none());
    }

    #[test]
    fn parse_redis_endpoint_supports_tls_scheme() {
        let (server, channel, tls) = AppState::alert_delivery_parse_redis_endpoint(
            "rediss://cache.example.com:6380/rustio.alerts",
        )
        .expect("redis endpoint should parse");
        assert_eq!(server, "cache.example.com:6380");
        assert_eq!(channel.as_deref(), Some("rustio.alerts"));
        assert!(tls);
    }

    #[test]
    fn parse_redis_server_auth_supports_password_and_userpass() {
        let (server, username, password) =
            AppState::alert_delivery_parse_redis_server_auth(":secret@redis.example.com:6379");
        assert_eq!(server, "redis.example.com:6379");
        assert!(username.is_none());
        assert_eq!(password.as_deref(), Some("secret"));

        let (server, username, password) =
            AppState::alert_delivery_parse_redis_server_auth("alice:secret@redis.example.com:6379");
        assert_eq!(server, "redis.example.com:6379");
        assert_eq!(username.as_deref(), Some("alice"));
        assert_eq!(password.as_deref(), Some("secret"));
    }

    #[test]
    fn notification_target_kind_supports_redis_scheme() {
        assert_eq!(
            AppState::notification_target_kind("redis://127.0.0.1:6379/rustio.alerts").as_deref(),
            Some("redis")
        );
    }

    #[test]
    fn alert_delivery_template_renders_payload_fields() {
        let rendered = AppState::alert_delivery_render_template(
            r#"{"bucket":"{{bucket}}","version":"{{object.version_id}}"}"#,
            &json!({
                "bucket": "reports",
                "object": { "version_id": "v1" }
            }),
        )
        .expect("template should render");
        assert_eq!(rendered, r#"{"bucket":"reports","version":"v1"}"#);
    }

    #[test]
    fn alert_delivery_http_body_wraps_kafka_and_rabbitmq_payloads() {
        let kafka_channel = AlertChannel {
            id: "channel-kafka".to_string(),
            name: "Kafka".to_string(),
            kind: "kafka".to_string(),
            endpoint: "https://kafka.example.internal/topics/rustio".to_string(),
            headers: HashMap::new(),
            payload_template: Some(r#"{"bucket":"{{bucket}}"}"#.to_string()),
            header_template: HashMap::new(),
            enabled: true,
            status: "healthy".to_string(),
            last_checked_at: Utc::now(),
            error: None,
        };
        let (kafka_content_type, kafka_body) = AppState::alert_delivery_render_http_body(
            &kafka_channel,
            &json!({ "bucket": "archive" }),
        )
        .expect("kafka payload should render");
        assert_eq!(kafka_content_type, "application/vnd.kafka.json.v2+json");
        let kafka_json: serde_json::Value =
            serde_json::from_slice(&kafka_body).expect("kafka payload should be json");
        assert_eq!(
            kafka_json.pointer("/records/0/value/bucket"),
            Some(&json!("archive"))
        );

        let rabbitmq_channel = AlertChannel {
            id: "channel-rabbit".to_string(),
            name: "RabbitMQ".to_string(),
            kind: "rabbitmq".to_string(),
            endpoint: "https://rabbit.example.internal/api/exchanges/%2F/rustio/publish?routing_key=ops.alerts".to_string(),
            headers: HashMap::new(),
            payload_template: Some(r#"bucket={{bucket}}"#.to_string()),
            header_template: HashMap::new(),
            enabled: true,
            status: "healthy".to_string(),
            last_checked_at: Utc::now(),
            error: None,
        };
        let (_, rabbitmq_body) = AppState::alert_delivery_render_http_body(
            &rabbitmq_channel,
            &json!({ "bucket": "archive" }),
        )
        .expect("rabbitmq payload should render");
        let rabbitmq_json: serde_json::Value =
            serde_json::from_slice(&rabbitmq_body).expect("rabbitmq payload should be json");
        assert_eq!(rabbitmq_json.get("routing_key"), Some(&json!("ops.alerts")));
        assert_eq!(rabbitmq_json.get("payload"), Some(&json!("bucket=archive")));
    }

    #[tokio::test]
    async fn metadata_snapshot_replicates_security_config() {
        let _guard = test_env_lock()
            .lock()
            .expect("failed to lock state test env guard");
        let leader_dir = unique_temp_dir("rustio-state-leader");
        let follower_dir = unique_temp_dir("rustio-state-follower");
        std::fs::create_dir_all(&leader_dir).expect("failed to create leader temp dir");
        std::fs::create_dir_all(&follower_dir).expect("failed to create follower temp dir");

        std::env::set_var("RUSTIO_DATA_DIR", &leader_dir);
        let leader = AppState::bootstrap();
        {
            let mut security = leader.security.write().await;
            security.oidc_enabled = true;
            security.ldap_enabled = true;
            security.oidc_discovery_url =
                "https://id.example.internal/.well-known/openid-configuration".to_string();
            security.oidc_client_id = "rustio-console".to_string();
            security.ldap_url = "ldap://ldap.example.internal:389".to_string();
            security.ldap_default_role = "operator".to_string();
            security.kms_endpoint = "https://vault.example.internal".to_string();
            security.sse_mode = "SSE-KMS".to_string();
        }
        let request = leader
            .export_metadata_raft_sync_request("state-test-security")
            .await
            .expect("leader should export metadata snapshot");

        std::env::set_var("RUSTIO_DATA_DIR", &follower_dir);
        let follower = AppState::bootstrap();
        {
            let mut raft = follower.metadata_raft.write().await;
            raft.cluster_id = request.cluster_id.clone();
        }
        follower
            .apply_metadata_raft_snapshot_internal(request, true)
            .await
            .expect("follower should apply metadata snapshot");

        let follower_security = follower.security.read().await.clone();
        assert_eq!(
            follower_security.oidc_discovery_url,
            "https://id.example.internal/.well-known/openid-configuration"
        );
        assert_eq!(follower_security.oidc_client_id, "rustio-console");
        assert_eq!(
            follower_security.ldap_url,
            "ldap://ldap.example.internal:389"
        );
        assert_eq!(follower_security.ldap_default_role, "operator");
        assert_eq!(
            follower_security.kms_endpoint,
            "https://vault.example.internal"
        );

        let persisted_path = follower_dir
            .join(".rustio_meta")
            .join("security-config.json");
        let persisted = std::fs::read_to_string(&persisted_path)
            .expect("follower security config should persist to disk");
        assert!(
            persisted.contains("\"oidc_client_id\": \"rustio-console\""),
            "persisted security config should contain replicated oidc client id"
        );

        let _ = std::fs::remove_dir_all(&leader_dir);
        let _ = std::fs::remove_dir_all(&follower_dir);
    }

    #[tokio::test]
    async fn metadata_snapshot_replicates_console_sessions() {
        let _guard = test_env_lock()
            .lock()
            .expect("failed to lock state test env guard");
        let leader_dir = unique_temp_dir("rustio-state-session-leader");
        let follower_dir = unique_temp_dir("rustio-state-session-follower");
        std::fs::create_dir_all(&leader_dir).expect("failed to create leader temp dir");
        std::fs::create_dir_all(&follower_dir).expect("failed to create follower temp dir");

        std::env::set_var("RUSTIO_DATA_DIR", &leader_dir);
        let leader = AppState::bootstrap();
        let now = Utc::now();
        {
            let mut sessions = leader.admin_sessions.write().await;
            sessions.push(ConsoleSession {
                session_id: "console-session-001".to_string(),
                principal: "admin".to_string(),
                role: "admin".to_string(),
                permissions: vec!["cluster:read".to_string(), "cluster:write".to_string()],
                provider: "local".to_string(),
                status: "active".to_string(),
                issued_at: now,
                access_expires_at: now + Duration::hours(4),
                refresh_expires_at: now + Duration::days(7),
                last_refreshed_at: Some(now + Duration::minutes(5)),
                revoked_at: None,
                revoked_reason: None,
            });
        }
        let request = leader
            .export_metadata_raft_sync_request("state-test-console-session")
            .await
            .expect("leader should export metadata snapshot");

        std::env::set_var("RUSTIO_DATA_DIR", &follower_dir);
        let follower = AppState::bootstrap();
        {
            let mut raft = follower.metadata_raft.write().await;
            raft.cluster_id = request.cluster_id.clone();
        }
        follower
            .apply_metadata_raft_snapshot_internal(request, true)
            .await
            .expect("follower should apply metadata snapshot");

        let sessions = follower.admin_sessions.read().await;
        let session = sessions
            .iter()
            .find(|session| session.session_id == "console-session-001")
            .expect("console session should be replicated");
        assert_eq!(session.principal, "admin");
        assert_eq!(session.provider, "local");
        assert_eq!(session.status, "active");
        assert_eq!(session.last_refreshed_at, Some(now + Duration::minutes(5)));
        drop(sessions);

        let _ = std::fs::remove_dir_all(&leader_dir);
        let _ = std::fs::remove_dir_all(&follower_dir);
    }

    #[tokio::test]
    async fn metadata_snapshot_replicates_local_credentials() {
        let _guard = test_env_lock()
            .lock()
            .expect("failed to lock state test env guard");
        let leader_dir = unique_temp_dir("rustio-state-cred-leader");
        let follower_dir = unique_temp_dir("rustio-state-cred-follower");
        std::fs::create_dir_all(&leader_dir).expect("failed to create leader temp dir");
        std::fs::create_dir_all(&follower_dir).expect("failed to create follower temp dir");

        std::env::set_var("RUSTIO_DATA_DIR", &leader_dir);
        let leader = AppState::bootstrap();
        {
            let mut credentials = leader.credentials.write().await;
            credentials.insert(
                "auditor-1".to_string(),
                LocalCredential {
                    password: "auditor-password".to_string(),
                    role: "auditor".to_string(),
                },
            );
        }
        let request = leader
            .export_metadata_raft_sync_request("state-test-local-credentials")
            .await
            .expect("leader should export metadata snapshot");

        std::env::set_var("RUSTIO_DATA_DIR", &follower_dir);
        let follower = AppState::bootstrap();
        {
            let mut raft = follower.metadata_raft.write().await;
            raft.cluster_id = request.cluster_id.clone();
        }
        follower
            .apply_metadata_raft_snapshot_internal(request, true)
            .await
            .expect("follower should apply metadata snapshot");

        let credentials = follower.credentials.read().await;
        let credential = credentials
            .get("auditor-1")
            .expect("local credential should be replicated");
        assert_eq!(credential.password, "auditor-password");
        assert_eq!(credential.role, "auditor");
        drop(credentials);

        let _ = std::fs::remove_dir_all(&leader_dir);
        let _ = std::fs::remove_dir_all(&follower_dir);
    }

    #[tokio::test]
    async fn delete_console_session_runtime_persists_removal() {
        let _guard = test_env_lock()
            .lock()
            .expect("failed to lock state test env guard");
        let data_dir = unique_temp_dir("rustio-state-session-delete");
        std::fs::create_dir_all(&data_dir).expect("failed to create temp data dir");

        std::env::set_var("RUSTIO_DATA_DIR", &data_dir);
        let state = AppState::bootstrap();
        let now = Utc::now();
        state
            .upsert_console_session_runtime(ConsoleSession {
                session_id: "console-session-delete-001".to_string(),
                principal: "admin".to_string(),
                role: "admin".to_string(),
                permissions: vec!["cluster:read".to_string(), "cluster:write".to_string()],
                provider: "local".to_string(),
                status: "active".to_string(),
                issued_at: now,
                access_expires_at: now + Duration::hours(4),
                refresh_expires_at: now + Duration::days(7),
                last_refreshed_at: None,
                revoked_at: None,
                revoked_reason: None,
            })
            .await
            .expect("console session should be persisted");

        state
            .delete_console_session_runtime("console-session-delete-001")
            .await
            .expect("console session removal should be persisted");

        let sessions = state.admin_sessions.read().await;
        assert!(
            sessions
                .iter()
                .all(|session| session.session_id != "console-session-delete-001"),
            "runtime console session should be removed"
        );
        drop(sessions);

        let persisted_path = data_dir.join(".rustio_meta").join("console-sessions.json");
        let persisted = std::fs::read_to_string(&persisted_path)
            .expect("console sessions snapshot should exist");
        assert!(
            !persisted.contains("console-session-delete-001"),
            "persisted console sessions should not contain removed session"
        );

        let _ = std::fs::remove_dir_all(&data_dir);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalCredential {
    pub password: String,
    pub role: String,
}

#[derive(Debug, Clone)]
pub struct MultipartPart {
    pub part_number: u32,
    pub etag: String,
    pub size: u64,
    pub path: PathBuf,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct MultipartUpload {
    pub upload_id: String,
    pub bucket: String,
    pub key: String,
    pub initiated_at: DateTime<Utc>,
    pub parts: HashMap<u32, MultipartPart>,
    pub encryption: S3ObjectEncryptionMeta,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaneComponent {
    pub id: String,
    pub responsibility: String,
    pub owner: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaneTopology {
    pub id: String,
    pub name: String,
    pub responsibilities: Vec<String>,
    pub components: Vec<PlaneComponent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchitectureTopology {
    pub version: String,
    pub aligned_at: DateTime<Utc>,
    pub planes: Vec<PlaneTopology>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaneAlignmentStatus {
    pub plane_id: String,
    pub plane_name: String,
    pub status: String,
    pub component_total: usize,
    pub component_ready: usize,
    pub checks: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchitectureAlignmentReport {
    pub version: String,
    pub generated_at: DateTime<Utc>,
    pub overall_status: String,
    pub missing_planes: Vec<String>,
    pub planes: Vec<PlaneAlignmentStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataObjectEntry {
    pub bucket: String,
    pub key: String,
    pub meta: S3ObjectMeta,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataRaftSnapshot {
    pub generated_at: DateTime<Utc>,
    pub buckets: Vec<BucketSpec>,
    pub remote_tiers: Vec<(String, RemoteTierConfig)>,
    pub bucket_object_locks: Vec<(String, BucketObjectLockConfig)>,
    pub bucket_retentions: Vec<(String, BucketRetentionConfig)>,
    pub bucket_legal_holds: Vec<(String, BucketLegalHoldConfig)>,
    pub bucket_notifications: Vec<(String, Vec<BucketNotificationRule>)>,
    pub bucket_lifecycle_rules: Vec<(String, Vec<BucketLifecycleRule>)>,
    pub bucket_acls: Vec<(String, BucketAclConfig)>,
    pub bucket_public_access_blocks: Vec<(String, BucketPublicAccessBlockConfig)>,
    pub bucket_policies: Vec<(String, Value)>,
    pub bucket_cors_rules: Vec<(String, Vec<BucketCorsRule>)>,
    pub bucket_tags: Vec<(String, Vec<BucketTag>)>,
    pub bucket_encryptions: Vec<(String, BucketEncryptionConfig)>,
    pub objects: Vec<MetadataObjectEntry>,
    pub credentials: Vec<(String, LocalCredential)>,
    pub iam_users: Vec<IamUser>,
    pub iam_groups: Vec<IamGroup>,
    pub iam_policies: Vec<IamPolicy>,
    pub service_accounts: Vec<rustio_core::ServiceAccount>,
    pub admin_sessions: Vec<ConsoleSession>,
    pub sts_sessions: Vec<StsSession>,
    pub replications: Vec<ReplicationStatus>,
    pub site_replications: Vec<SiteReplicationStatus>,
    pub replication_backlog: Vec<ReplicationBacklogItem>,
    pub replication_checkpoints: Vec<(String, u64)>,
    pub cluster_config_history: Vec<ClusterConfigSnapshot>,
    pub security: SecurityConfig,
    pub jobs: Vec<JobStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataRaftLogEntry {
    pub index: u64,
    pub term: u64,
    pub reason: String,
    pub written_at: DateTime<Utc>,
    pub snapshot_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataRaftPeer {
    pub id: String,
    pub path: PathBuf,
    #[serde(default)]
    pub endpoint: Option<String>,
    pub online: bool,
    #[serde(default)]
    pub match_index: u64,
    #[serde(default = "metadata_peer_next_index_default")]
    pub next_index: u64,
    pub last_index: u64,
}

fn metadata_peer_next_index_default() -> u64 {
    1
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataRaftState {
    pub cluster_id: String,
    pub leader_id: String,
    pub term: u64,
    #[serde(default)]
    pub voted_for: Option<String>,
    pub commit_index: u64,
    #[serde(default)]
    pub last_commit_term: u64,
    #[serde(default)]
    pub last_heartbeat_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub last_election_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub last_quorum_at: Option<DateTime<Utc>>,
    #[serde(default = "metadata_membership_phase_default")]
    pub membership_phase: String,
    #[serde(default)]
    pub joint_old_members: Vec<String>,
    #[serde(default)]
    pub joint_new_members: Vec<String>,
    pub last_snapshot_hash: String,
    pub last_error: Option<String>,
    pub last_commit_at: Option<DateTime<Utc>>,
    pub peers: Vec<MetadataRaftPeer>,
}

fn metadata_membership_phase_default() -> String {
    "stable".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataRaftStatus {
    pub cluster_id: String,
    pub leader_id: String,
    pub term: u64,
    pub commit_index: u64,
    pub quorum: usize,
    pub online_peers: usize,
    pub last_error: Option<String>,
    pub last_commit_at: Option<DateTime<Utc>>,
    pub membership_phase: String,
    #[serde(default)]
    pub joint_old_members: Vec<String>,
    #[serde(default)]
    pub joint_new_members: Vec<String>,
    #[serde(default)]
    pub joint_elapsed_seconds: Option<u64>,
    pub joint_timeout_seconds: u64,
    pub peers: Vec<MetadataRaftPeer>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataRaftSyncRequest {
    pub cluster_id: String,
    pub peer_id: String,
    pub entry: MetadataRaftLogEntry,
    #[serde(default)]
    pub prev_log_index: u64,
    #[serde(default)]
    pub prev_log_term: u64,
    #[serde(default)]
    pub install_snapshot: bool,
    #[serde(default)]
    pub leader_commit: u64,
    pub snapshot: MetadataRaftSnapshot,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataRaftVoteRequest {
    pub cluster_id: String,
    pub candidate_id: String,
    pub term: u64,
    pub last_log_index: u64,
    #[serde(default)]
    pub last_log_term: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataRaftVoteResponse {
    pub term: u64,
    pub vote_granted: bool,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataRaftPreVoteRequest {
    pub cluster_id: String,
    pub candidate_id: String,
    pub term: u64,
    pub last_log_index: u64,
    #[serde(default)]
    pub last_log_term: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataRaftPreVoteResponse {
    pub term: u64,
    pub pre_vote_granted: bool,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataRaftReadIndexRequest {
    pub cluster_id: String,
    pub requester_id: String,
    #[serde(default)]
    pub request_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataRaftReadIndexResponse {
    pub term: u64,
    pub leader_id: String,
    pub read_index: u64,
    pub success: bool,
    #[serde(default)]
    pub request_id: String,
    #[serde(default)]
    pub members: Vec<String>,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataRaftSyncResponse {
    pub term: u64,
    pub success: bool,
    pub match_index: u64,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataRaftHeartbeatRequest {
    pub cluster_id: String,
    pub leader_id: String,
    pub term: u64,
    pub leader_commit: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataRaftHeartbeatResponse {
    pub term: u64,
    pub accepted: bool,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalReplicationApplyRequest {
    pub source_bucket: String,
    pub target_site: String,
    pub object_key: String,
    pub operation: String,
    pub checkpoint: u64,
    pub idempotency_key: String,
    #[serde(default)]
    pub version_id: Option<String>,
    #[serde(default)]
    pub payload_base64: Option<String>,
    #[serde(default)]
    pub object_meta: Option<S3ObjectMeta>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertDeliveryItem {
    pub id: String,
    pub history_id: String,
    pub rule_id: Option<String>,
    pub channel_id: String,
    pub channel_kind: String,
    pub endpoint: String,
    pub status: String,
    pub attempts: u32,
    pub last_error: String,
    pub lease_owner: Option<String>,
    pub lease_until: Option<DateTime<Utc>>,
    pub queued_at: DateTime<Utc>,
    pub last_attempt_at: Option<DateTime<Utc>>,
    pub next_attempt_at: DateTime<Utc>,
    pub payload: Value,
    pub idempotency_key: String,
}

pub struct AppState {
    pub jwt_secret: String,
    pub s3_access_key: String,
    pub s3_secret_key: String,
    pub data_dir: PathBuf,
    pub data_disks: Vec<PathBuf>,
    pub architecture: ArchitectureTopology,
    pub metadata_raft: RwLock<MetadataRaftState>,
    pub credentials: RwLock<HashMap<String, LocalCredential>>,
    pub nodes: RwLock<Vec<ClusterNode>>,
    pub quotas: RwLock<Vec<ClusterQuota>>,
    pub tenants: RwLock<Vec<TenantSpec>>,
    pub diagnostics: RwLock<Vec<DiagnosticReport>>,
    pub cluster_config_history: RwLock<Vec<ClusterConfigSnapshot>>,
    pub users: RwLock<Vec<IamUser>>,
    pub groups: RwLock<Vec<IamGroup>>,
    pub policies: RwLock<Vec<IamPolicy>>,
    pub service_accounts: RwLock<Vec<rustio_core::ServiceAccount>>,
    pub admin_sessions: RwLock<Vec<ConsoleSession>>,
    pub sts_sessions: RwLock<Vec<StsSession>>,
    pub buckets: RwLock<HashMap<String, BucketSpec>>,
    pub remote_tiers: RwLock<HashMap<String, RemoteTierConfig>>,
    pub bucket_object_locks: RwLock<HashMap<String, BucketObjectLockConfig>>,
    pub bucket_retentions: RwLock<HashMap<String, BucketRetentionConfig>>,
    pub bucket_legal_holds: RwLock<HashMap<String, BucketLegalHoldConfig>>,
    pub bucket_notifications: RwLock<HashMap<String, Vec<BucketNotificationRule>>>,
    pub bucket_lifecycle_rules: RwLock<HashMap<String, Vec<BucketLifecycleRule>>>,
    pub bucket_acls: RwLock<HashMap<String, BucketAclConfig>>,
    pub bucket_public_access_blocks: RwLock<HashMap<String, BucketPublicAccessBlockConfig>>,
    pub bucket_policies: RwLock<HashMap<String, Value>>,
    pub bucket_cors_rules: RwLock<HashMap<String, Vec<BucketCorsRule>>>,
    pub bucket_tags: RwLock<HashMap<String, Vec<BucketTag>>>,
    pub bucket_encryptions: RwLock<HashMap<String, BucketEncryptionConfig>>,
    pub replications: RwLock<Vec<ReplicationStatus>>,
    pub site_replications: RwLock<Vec<SiteReplicationStatus>>,
    pub replication_backlog: RwLock<Vec<ReplicationBacklogItem>>,
    pub replication_checkpoints: RwLock<HashMap<String, u64>>,
    pub replication_sequence: AtomicU64,
    pub alert_rules: RwLock<Vec<AlertRule>>,
    pub alert_channels: RwLock<Vec<AlertChannel>>,
    pub alert_silences: RwLock<Vec<AlertSilence>>,
    pub alert_escalations: RwLock<Vec<AlertEscalationPolicy>>,
    pub alert_history: RwLock<Vec<AlertHistoryEntry>>,
    pub alert_delivery_queue: RwLock<Vec<AlertDeliveryItem>>,
    pub security: RwLock<SecurityConfig>,
    pub oidc_auth_requests: RwLock<HashMap<String, PendingOidcAuthorization>>,
    pub oidc_completed_logins: RwLock<HashMap<String, CompletedOidcLogin>>,
    pub audits: RwLock<Vec<AuditEvent>>,
    pub jobs: RwLock<Vec<JobStatus>>,
    pub object_access_heat: RwLock<HashMap<(String, String), u64>>,
    pub storage_governance: RwLock<StorageGovernanceRuntimeState>,
    pub object_store: RwLock<HashMap<(String, String), Vec<u8>>>,
    pub object_meta: RwLock<HashMap<(String, String), S3ObjectMeta>>,
    pub multipart_uploads: RwLock<HashMap<String, MultipartUpload>>,
    pub last_request_activity_at: AtomicI64,
    pub last_memory_trim_at: AtomicI64,
    pub events: broadcast::Sender<RuntimeEvent>,
}

fn bilingual_runtime_error(zh: &str, en: impl AsRef<str>) -> String {
    let en = en.as_ref().trim();
    if en.contains(" / ") {
        return en.to_string();
    }
    if en.is_empty() {
        return format!("{zh} / runtime error");
    }
    format!("{zh} / {en}")
}

#[derive(Debug, Clone)]
pub struct PendingOidcAuthorization {
    pub code_verifier: String,
    pub nonce: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct CompletedOidcLogin {
    pub response: LoginResponse,
    pub created_at: DateTime<Utc>,
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

#[cfg(target_os = "linux")]
fn trim_process_memory() -> bool {
    unsafe { libc::malloc_trim(0) != 0 }
}

#[cfg(not(target_os = "linux"))]
fn trim_process_memory() -> bool {
    false
}

#[cfg(target_os = "linux")]
fn current_process_rss_bytes() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|line| line.starts_with("VmRSS:"))?;
    let value = line.split_whitespace().nth(1)?.parse::<u64>().ok()?;
    Some(value.saturating_mul(1024))
}

#[cfg(not(target_os = "linux"))]
fn current_process_rss_bytes() -> Option<u64> {
    None
}

fn audit_max_events() -> usize {
    std::env::var("RUSTIO_AUDIT_MAX_EVENTS")
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .unwrap_or(2_048)
        .clamp(100, 100_000)
}

fn prune_audits_locked(audits: &mut Vec<AuditEvent>) {
    let max_events = audit_max_events();
    if audits.len() <= max_events {
        return;
    }

    let overflow = audits.len().saturating_sub(max_events);
    audits.drain(0..overflow);
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct ReplicationRuntimeState {
    #[serde(default)]
    version: u32,
    #[serde(default)]
    sequence: u64,
    #[serde(default)]
    backlog: Vec<ReplicationBacklogItem>,
    #[serde(default)]
    checkpoints: HashMap<String, u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct MetadataRaftRuntimePeer {
    #[serde(default)]
    id: String,
    #[serde(default)]
    endpoint: Option<String>,
    #[serde(default = "metadata_runtime_peer_online_default")]
    online: bool,
    #[serde(default)]
    last_index: u64,
    #[serde(default)]
    match_index: u64,
    #[serde(default = "metadata_peer_next_index_default")]
    next_index: u64,
}

fn metadata_runtime_peer_online_default() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct MetadataRaftRuntimeState {
    #[serde(default)]
    version: u32,
    #[serde(default)]
    cluster_id: String,
    #[serde(default)]
    leader_id: String,
    #[serde(default)]
    term: u64,
    #[serde(default)]
    voted_for: Option<String>,
    #[serde(default)]
    commit_index: u64,
    #[serde(default)]
    last_commit_term: u64,
    #[serde(default)]
    last_snapshot_hash: String,
    #[serde(default)]
    last_error: Option<String>,
    #[serde(default)]
    last_commit_at: Option<DateTime<Utc>>,
    #[serde(default)]
    last_heartbeat_at: Option<DateTime<Utc>>,
    #[serde(default)]
    last_election_at: Option<DateTime<Utc>>,
    #[serde(default)]
    last_quorum_at: Option<DateTime<Utc>>,
    #[serde(default = "metadata_membership_phase_default")]
    membership_phase: String,
    #[serde(default)]
    joint_old_members: Vec<String>,
    #[serde(default)]
    joint_new_members: Vec<String>,
    #[serde(default)]
    peers: Vec<MetadataRaftRuntimePeer>,
}

fn default_security_config_from_env() -> SecurityConfig {
    SecurityConfig {
        oidc_enabled: std::env::var("RUSTIO_OIDC_ENABLED")
            .ok()
            .and_then(|value| value.parse::<bool>().ok())
            .unwrap_or(true),
        ldap_enabled: std::env::var("RUSTIO_LDAP_ENABLED")
            .ok()
            .and_then(|value| value.parse::<bool>().ok())
            .unwrap_or(true),
        oidc_discovery_url: std::env::var("RUSTIO_OIDC_DISCOVERY_URL").unwrap_or_default(),
        oidc_issuer: std::env::var("RUSTIO_OIDC_ISSUER").unwrap_or_default(),
        oidc_client_id: std::env::var("RUSTIO_OIDC_CLIENT_ID").unwrap_or_default(),
        oidc_jwks_url: std::env::var("RUSTIO_OIDC_JWKS_URL").unwrap_or_default(),
        oidc_allowed_algs: std::env::var("RUSTIO_OIDC_ALLOWED_ALGS").unwrap_or_default(),
        oidc_username_claim: std::env::var("RUSTIO_OIDC_USERNAME_CLAIM")
            .unwrap_or_else(|_| "preferred_username".to_string()),
        oidc_groups_claim: std::env::var("RUSTIO_OIDC_GROUPS_CLAIM")
            .unwrap_or_else(|_| "groups".to_string()),
        oidc_role_claim: std::env::var("RUSTIO_OIDC_ROLE_CLAIM")
            .unwrap_or_else(|_| "role".to_string()),
        oidc_default_role: std::env::var("RUSTIO_OIDC_DEFAULT_ROLE")
            .unwrap_or_else(|_| "viewer".to_string()),
        oidc_group_role_map: std::env::var("RUSTIO_OIDC_GROUP_ROLE_MAP").unwrap_or_default(),
        ldap_url: std::env::var("RUSTIO_LDAP_URL").unwrap_or_default(),
        ldap_bind_dn: std::env::var("RUSTIO_LDAP_BIND_DN").unwrap_or_default(),
        ldap_user_base_dn: std::env::var("RUSTIO_LDAP_USER_BASE_DN").unwrap_or_default(),
        ldap_user_filter: std::env::var("RUSTIO_LDAP_USER_FILTER")
            .unwrap_or_else(|_| "(uid={username})".to_string()),
        ldap_group_base_dn: std::env::var("RUSTIO_LDAP_GROUP_BASE_DN").unwrap_or_default(),
        ldap_group_filter: std::env::var("RUSTIO_LDAP_GROUP_FILTER")
            .unwrap_or_else(|_| "(member={user_dn})".to_string()),
        ldap_group_attribute: std::env::var("RUSTIO_LDAP_GROUP_ATTRIBUTE")
            .unwrap_or_else(|_| "memberOf".to_string()),
        ldap_group_name_attribute: std::env::var("RUSTIO_LDAP_GROUP_NAME_ATTRIBUTE")
            .unwrap_or_else(|_| "cn".to_string()),
        ldap_default_role: std::env::var("RUSTIO_LDAP_DEFAULT_ROLE")
            .unwrap_or_else(|_| "viewer".to_string()),
        ldap_group_role_map: std::env::var("RUSTIO_LDAP_GROUP_ROLE_MAP").unwrap_or_default(),
        kms_endpoint: std::env::var("RUSTIO_KMS_ENDPOINT")
            .unwrap_or_else(|_| "https://vault.example.internal".to_string()),
        kms_healthy: true,
        kms_last_error: None,
        kms_last_checked_at: None,
        kms_last_success_at: None,
        kms_last_recovered_at: None,
        kms_rotation_status: "idle".to_string(),
        kms_rotation_last_started_at: None,
        kms_rotation_last_completed_at: None,
        kms_rotation_last_success_at: None,
        kms_rotation_last_failure_reason: None,
        kms_rotation_scanned: 0,
        kms_rotation_rotated: 0,
        kms_rotation_skipped: 0,
        kms_rotation_failed: 0,
        kms_rotation_failed_objects: Vec::new(),
        sse_mode: std::env::var("RUSTIO_SSE_MODE").unwrap_or_else(|_| "SSE-KMS".to_string()),
    }
}

fn merge_security_config(mut base: SecurityConfig, persisted: SecurityConfig) -> SecurityConfig {
    base.oidc_enabled = persisted.oidc_enabled;
    base.ldap_enabled = persisted.ldap_enabled;

    if !persisted.oidc_discovery_url.trim().is_empty() {
        base.oidc_discovery_url = persisted.oidc_discovery_url;
    }
    if !persisted.oidc_issuer.trim().is_empty() {
        base.oidc_issuer = persisted.oidc_issuer;
    }
    if !persisted.oidc_client_id.trim().is_empty() {
        base.oidc_client_id = persisted.oidc_client_id;
    }
    if !persisted.oidc_jwks_url.trim().is_empty() {
        base.oidc_jwks_url = persisted.oidc_jwks_url;
    }
    if !persisted.oidc_allowed_algs.trim().is_empty() {
        base.oidc_allowed_algs = persisted.oidc_allowed_algs;
    }
    if !persisted.oidc_username_claim.trim().is_empty() {
        base.oidc_username_claim = persisted.oidc_username_claim;
    }
    if !persisted.oidc_groups_claim.trim().is_empty() {
        base.oidc_groups_claim = persisted.oidc_groups_claim;
    }
    if !persisted.oidc_role_claim.trim().is_empty() {
        base.oidc_role_claim = persisted.oidc_role_claim;
    }
    if !persisted.oidc_default_role.trim().is_empty() {
        base.oidc_default_role = persisted.oidc_default_role;
    }
    if !persisted.oidc_group_role_map.trim().is_empty() {
        base.oidc_group_role_map = persisted.oidc_group_role_map;
    }
    if !persisted.ldap_url.trim().is_empty() {
        base.ldap_url = persisted.ldap_url;
    }
    if !persisted.ldap_bind_dn.trim().is_empty() {
        base.ldap_bind_dn = persisted.ldap_bind_dn;
    }
    if !persisted.ldap_user_base_dn.trim().is_empty() {
        base.ldap_user_base_dn = persisted.ldap_user_base_dn;
    }
    if !persisted.ldap_user_filter.trim().is_empty() {
        base.ldap_user_filter = persisted.ldap_user_filter;
    }
    if !persisted.ldap_group_base_dn.trim().is_empty() {
        base.ldap_group_base_dn = persisted.ldap_group_base_dn;
    }
    if !persisted.ldap_group_filter.trim().is_empty() {
        base.ldap_group_filter = persisted.ldap_group_filter;
    }
    if !persisted.ldap_group_attribute.trim().is_empty() {
        base.ldap_group_attribute = persisted.ldap_group_attribute;
    }
    if !persisted.ldap_group_name_attribute.trim().is_empty() {
        base.ldap_group_name_attribute = persisted.ldap_group_name_attribute;
    }
    if !persisted.ldap_default_role.trim().is_empty() {
        base.ldap_default_role = persisted.ldap_default_role;
    }
    if !persisted.ldap_group_role_map.trim().is_empty() {
        base.ldap_group_role_map = persisted.ldap_group_role_map;
    }
    if !persisted.kms_endpoint.trim().is_empty() {
        base.kms_endpoint = persisted.kms_endpoint;
    }
    base.kms_healthy = persisted.kms_healthy;
    base.kms_last_error = persisted.kms_last_error;
    base.kms_last_checked_at = persisted.kms_last_checked_at;
    base.kms_last_success_at = persisted.kms_last_success_at;
    base.kms_last_recovered_at = persisted.kms_last_recovered_at;
    if !persisted.kms_rotation_status.trim().is_empty() {
        base.kms_rotation_status = persisted.kms_rotation_status;
    }
    base.kms_rotation_last_started_at = persisted.kms_rotation_last_started_at;
    base.kms_rotation_last_completed_at = persisted.kms_rotation_last_completed_at;
    base.kms_rotation_last_success_at = persisted.kms_rotation_last_success_at;
    base.kms_rotation_last_failure_reason = persisted.kms_rotation_last_failure_reason;
    base.kms_rotation_scanned = persisted.kms_rotation_scanned;
    base.kms_rotation_rotated = persisted.kms_rotation_rotated;
    base.kms_rotation_skipped = persisted.kms_rotation_skipped;
    base.kms_rotation_failed = persisted.kms_rotation_failed;
    base.kms_rotation_failed_objects = persisted.kms_rotation_failed_objects;
    if !persisted.sse_mode.trim().is_empty() {
        base.sse_mode = persisted.sse_mode;
    }

    base
}

fn default_cluster_config_payload(security: &SecurityConfig) -> Value {
    json!({
        "cluster": {
            "name": "rustio-cluster",
            "region": "cn-east-1",
            "domain": "localhost:9000"
        },
        "network": {
            "api": {
                "address": "0.0.0.0:9000"
            },
            "console": {
                "embedded": true,
                "address": "0.0.0.0:9000"
            }
        },
        "storage": {
            "erasure_set_size": 4,
            "bitrot": "highwayhash256"
        },
        "security": {
            "oidc_enabled": security.oidc_enabled,
            "ldap_enabled": security.ldap_enabled,
            "oidc_discovery_url": security.oidc_discovery_url,
            "oidc_issuer": security.oidc_issuer,
            "oidc_client_id": security.oidc_client_id,
            "oidc_jwks_url": security.oidc_jwks_url,
            "oidc_allowed_algs": security.oidc_allowed_algs,
            "oidc_username_claim": security.oidc_username_claim,
            "oidc_groups_claim": security.oidc_groups_claim,
            "oidc_role_claim": security.oidc_role_claim,
            "oidc_default_role": security.oidc_default_role,
            "oidc_group_role_map": security.oidc_group_role_map,
            "ldap_url": security.ldap_url,
            "ldap_bind_dn": security.ldap_bind_dn,
            "ldap_user_base_dn": security.ldap_user_base_dn,
            "ldap_user_filter": security.ldap_user_filter,
            "ldap_group_base_dn": security.ldap_group_base_dn,
            "ldap_group_filter": security.ldap_group_filter,
            "ldap_group_attribute": security.ldap_group_attribute,
            "ldap_group_name_attribute": security.ldap_group_name_attribute,
            "ldap_default_role": security.ldap_default_role,
            "ldap_group_role_map": security.ldap_group_role_map,
            "kms_endpoint": security.kms_endpoint,
            "sse_mode": security.sse_mode
        },
        "observability": {
            "audit_enabled": true,
            "metrics_enabled": true
        }
    })
}

impl AppState {
    fn cluster_config_history_path(data_dir: &PathBuf) -> PathBuf {
        data_dir
            .join(".rustio_meta")
            .join("cluster-config-history.json")
    }

    fn load_cluster_config_history(
        data_dir: &PathBuf,
        security: &SecurityConfig,
    ) -> Vec<ClusterConfigSnapshot> {
        let path = Self::cluster_config_history_path(data_dir);
        if let Ok(bytes) = std::fs::read(&path) {
            if let Ok(history) = serde_json::from_slice::<Vec<ClusterConfigSnapshot>>(&bytes) {
                if !history.is_empty() {
                    return history;
                }
            }
        }

        vec![ClusterConfigSnapshot {
            version: "cfg-bootstrap".to_string(),
            updated_at: Utc::now(),
            updated_by: "bootstrap".to_string(),
            source: "bootstrap".to_string(),
            reason: Some("initial cluster configuration".to_string()),
            etag: format!("cfg-{}", Uuid::new_v4().simple()),
            payload: default_cluster_config_payload(security),
        }]
    }

    pub(crate) fn persist_cluster_config_history_snapshot(
        data_dir: &PathBuf,
        history: &[ClusterConfigSnapshot],
    ) -> Result<(), String> {
        let path = Self::cluster_config_history_path(data_dir);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|err| err.to_string())?;
        }
        let bytes = serde_json::to_vec_pretty(history).map_err(|err| err.to_string())?;
        let temp_path = path.with_extension("json.tmp");
        std::fs::write(&temp_path, bytes).map_err(|err| err.to_string())?;
        std::fs::rename(&temp_path, &path).map_err(|err| err.to_string())
    }

    fn security_config_path(data_dir: &PathBuf) -> PathBuf {
        data_dir.join(".rustio_meta").join("security-config.json")
    }

    fn load_security_config(data_dir: &PathBuf) -> SecurityConfig {
        let defaults = default_security_config_from_env();
        let path = Self::security_config_path(data_dir);
        let persisted = std::fs::read(&path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<SecurityConfig>(&bytes).ok());
        persisted
            .map(|value| merge_security_config(defaults.clone(), value))
            .unwrap_or(defaults)
    }

    pub(crate) fn persist_security_config_snapshot(
        data_dir: &PathBuf,
        config: &SecurityConfig,
    ) -> Result<(), String> {
        let path = Self::security_config_path(data_dir);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|err| err.to_string())?;
        }
        let bytes = serde_json::to_vec_pretty(config).map_err(|err| err.to_string())?;
        let temp_path = path.with_extension("json.tmp");
        std::fs::write(&temp_path, bytes).map_err(|err| err.to_string())?;
        std::fs::rename(&temp_path, &path).map_err(|err| err.to_string())
    }

    fn console_sessions_path(data_dir: &PathBuf) -> PathBuf {
        data_dir.join(".rustio_meta").join("console-sessions.json")
    }

    fn load_console_sessions(data_dir: &PathBuf) -> Vec<ConsoleSession> {
        let path = Self::console_sessions_path(data_dir);
        std::fs::read(&path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Vec<ConsoleSession>>(&bytes).ok())
            .unwrap_or_default()
    }

    fn remote_tiers_path(data_dir: &PathBuf) -> PathBuf {
        data_dir.join(".rustio_system").join("remote-tiers.json")
    }

    fn load_remote_tiers(data_dir: &PathBuf) -> HashMap<String, RemoteTierConfig> {
        let path = Self::remote_tiers_path(data_dir);
        std::fs::read(&path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Vec<RemoteTierConfig>>(&bytes).ok())
            .unwrap_or_default()
            .into_iter()
            .map(|tier| (tier.name.clone(), tier))
            .collect()
    }

    pub(crate) fn persist_remote_tiers_snapshot(
        data_dir: &PathBuf,
        tiers: &HashMap<String, RemoteTierConfig>,
    ) -> Result<(), String> {
        let path = Self::remote_tiers_path(data_dir);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|err| err.to_string())?;
        }
        let mut payload = tiers.values().cloned().collect::<Vec<_>>();
        payload.sort_by(|left, right| left.name.cmp(&right.name));
        let bytes = serde_json::to_vec_pretty(&payload).map_err(|err| err.to_string())?;
        let temp_path = path.with_extension("json.tmp");
        std::fs::write(&temp_path, bytes).map_err(|err| err.to_string())?;
        std::fs::rename(&temp_path, &path).map_err(|err| err.to_string())
    }

    pub(crate) fn persist_console_sessions_snapshot(
        data_dir: &PathBuf,
        sessions: &[ConsoleSession],
    ) -> Result<(), String> {
        let path = Self::console_sessions_path(data_dir);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|err| err.to_string())?;
        }
        let bytes = serde_json::to_vec_pretty(sessions).map_err(|err| err.to_string())?;
        let temp_path = path.with_extension("json.tmp");
        std::fs::write(&temp_path, bytes).map_err(|err| err.to_string())?;
        std::fs::rename(&temp_path, &path).map_err(|err| err.to_string())
    }

    pub fn bootstrap() -> Arc<Self> {
        let (events, _) = broadcast::channel(512);
        let now = Utc::now();
        let data_dir = std::env::var("RUSTIO_DATA_DIR")
            .or_else(|_| std::env::var("MINIO_VOLUMES"))
            .map(|raw| {
                // Compatible volume env may contain multiple paths; v1 uses the first one.
                raw.split_whitespace()
                    .next()
                    .unwrap_or("./data")
                    .to_string()
            })
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("./data"));
        let _ = std::fs::create_dir_all(&data_dir);
        let data_disks = Self::resolve_data_disks(&data_dir);
        for disk in &data_disks {
            let _ = std::fs::create_dir_all(disk);
        }
        let metadata_raft = Self::bootstrap_metadata_raft(&data_dir);

        let s3_access_key = std::env::var("RUSTIO_ROOT_USER")
            .or_else(|_| std::env::var("MINIO_ROOT_USER"))
            .unwrap_or_else(|_| "rustioadmin".to_string());
        let s3_secret_key = std::env::var("RUSTIO_ROOT_PASSWORD")
            .or_else(|_| std::env::var("MINIO_ROOT_PASSWORD"))
            .unwrap_or_else(|_| "rustioadmin".to_string());

        let console_user =
            std::env::var("RUSTIO_CONSOLE_USER").unwrap_or_else(|_| "admin".to_string());
        let console_password =
            std::env::var("RUSTIO_CONSOLE_PASSWORD").unwrap_or_else(|_| "rustio-admin".to_string());

        let mut credentials = HashMap::new();
        credentials.insert(
            console_user.clone(),
            LocalCredential {
                password: console_password,
                role: "admin".to_string(),
            },
        );
        if console_user != "admin" {
            credentials.insert(
                "admin".to_string(),
                LocalCredential {
                    password: "rustio-admin".to_string(),
                    role: "admin".to_string(),
                },
            );
        }

        let remote_tiers = Self::load_remote_tiers(&data_dir);
        let mut buckets = HashMap::new();
        let mut bucket_object_locks = HashMap::new();
        let mut bucket_retentions = HashMap::new();
        let mut bucket_legal_holds = HashMap::new();
        let mut bucket_notifications = HashMap::new();
        let mut bucket_lifecycle_rules = HashMap::new();
        let mut bucket_acls = HashMap::new();
        let mut bucket_public_access_blocks = HashMap::new();
        let mut bucket_policies = HashMap::new();
        let mut bucket_cors_rules = HashMap::new();
        let mut bucket_tags = HashMap::new();
        let mut bucket_encryptions = HashMap::new();
        if let Ok(entries) = std::fs::read_dir(&data_dir) {
            for entry in entries.flatten() {
                if let Ok(file_type) = entry.file_type() {
                    if !file_type.is_dir() {
                        continue;
                    }
                } else {
                    continue;
                }

                let name = entry.file_name().to_string_lossy().to_string();
                if name.is_empty() || name.starts_with('.') {
                    continue;
                }

                let bucket = BucketSpec {
                    name: name.clone(),
                    tenant_id: "default".to_string(),
                    versioning: true,
                    object_lock: false,
                    ilm_policy: None,
                    replication_policy: None,
                };
                buckets.insert(name.clone(), bucket.clone());
                bucket_object_locks.insert(
                    name.clone(),
                    BucketObjectLockConfig {
                        enabled: bucket.object_lock,
                        mode: "GOVERNANCE".to_string(),
                        default_retention_days: 30,
                    },
                );
                bucket_retentions.insert(
                    name.clone(),
                    BucketRetentionConfig {
                        enabled: false,
                        mode: "GOVERNANCE".to_string(),
                        duration_days: 30,
                    },
                );
                bucket_legal_holds.insert(name.clone(), BucketLegalHoldConfig { enabled: false });
                bucket_notifications.insert(name.clone(), Vec::new());
                bucket_acls.insert(
                    name.clone(),
                    BucketAclConfig {
                        acl: "private".to_string(),
                    },
                );
                bucket_public_access_blocks.insert(
                    name.clone(),
                    BucketPublicAccessBlockConfig {
                        block_public_acls: false,
                        ignore_public_acls: false,
                        block_public_policy: false,
                        restrict_public_buckets: false,
                    },
                );

                let notifications_path = entry
                    .path()
                    .join(".rustio_meta")
                    .join("bucket-notifications.json");
                if let Ok(bytes) = std::fs::read(&notifications_path) {
                    if let Ok(rules) = serde_json::from_slice::<Vec<BucketNotificationRule>>(&bytes)
                    {
                        bucket_notifications.insert(name.clone(), rules);
                    }
                }

                let lifecycle_path = entry
                    .path()
                    .join(".rustio_meta")
                    .join("bucket-lifecycle.json");
                if let Ok(bytes) = std::fs::read(&lifecycle_path) {
                    if let Ok(rules) = serde_json::from_slice::<Vec<BucketLifecycleRule>>(&bytes) {
                        bucket_lifecycle_rules.insert(name.clone(), rules);
                    }
                }

                let acl_path = entry.path().join(".rustio_meta").join("bucket-acl.json");
                if let Ok(bytes) = std::fs::read(&acl_path) {
                    if let Ok(acl) = serde_json::from_slice::<BucketAclConfig>(&bytes) {
                        bucket_acls.insert(name.clone(), acl);
                    }
                }

                let pab_path = entry
                    .path()
                    .join(".rustio_meta")
                    .join("bucket-public-access-block.json");
                if let Ok(bytes) = std::fs::read(&pab_path) {
                    if let Ok(pab) = serde_json::from_slice::<BucketPublicAccessBlockConfig>(&bytes)
                    {
                        bucket_public_access_blocks.insert(name.clone(), pab);
                    }
                }

                let policy_path = entry.path().join(".rustio_meta").join("bucket-policy.json");
                if let Ok(bytes) = std::fs::read(&policy_path) {
                    if let Ok(policy) = serde_json::from_slice::<Value>(&bytes) {
                        bucket_policies.insert(name.clone(), policy);
                    }
                }

                let cors_path = entry.path().join(".rustio_meta").join("bucket-cors.json");
                if let Ok(bytes) = std::fs::read(&cors_path) {
                    if let Ok(cors_rules) = serde_json::from_slice::<Vec<BucketCorsRule>>(&bytes) {
                        bucket_cors_rules.insert(name.clone(), cors_rules);
                    }
                }

                let tags_path = entry.path().join(".rustio_meta").join("bucket-tags.json");
                if let Ok(bytes) = std::fs::read(&tags_path) {
                    if let Ok(tags) = serde_json::from_slice::<Vec<BucketTag>>(&bytes) {
                        bucket_tags.insert(name.clone(), tags);
                    }
                }

                let encryption_path = entry
                    .path()
                    .join(".rustio_meta")
                    .join("bucket-encryption.json");
                if let Ok(bytes) = std::fs::read(&encryption_path) {
                    if let Ok(encryption) = serde_json::from_slice::<BucketEncryptionConfig>(&bytes)
                    {
                        bucket_encryptions.insert(name, encryption);
                    }
                }
            }
        }

        let security = Self::load_security_config(&data_dir);
        let cluster_config_history = Self::load_cluster_config_history(&data_dir, &security);
        let console_sessions = Self::load_console_sessions(&data_dir);

        let state = Arc::new(Self {
            jwt_secret: std::env::var("RUSTIO_JWT_SECRET")
                .unwrap_or_else(|_| "rustio-dev-secret".to_string()),
            s3_access_key: s3_access_key.clone(),
            s3_secret_key: s3_secret_key.clone(),
            data_dir,
            data_disks,
            architecture: ArchitectureTopology {
                version: "m0-architecture-aligned".to_string(),
                aligned_at: now,
                planes: vec![
                    PlaneTopology {
                        id: "control-plane".to_string(),
                        name: "控制平面".to_string(),
                        responsibilities: vec![
                            "管理 API".to_string(),
                            "访问控制与会话".to_string(),
                            "审计与配置治理".to_string(),
                        ],
                        components: vec![
                            PlaneComponent {
                                id: "admin-api".to_string(),
                                responsibility: "承载 /api/v1/* 控制接口".to_string(),
                                owner: "rustio-admin".to_string(),
                            },
                            PlaneComponent {
                                id: "auth-service".to_string(),
                                responsibility: "本地账号登录、JWT 签发与校验".to_string(),
                                owner: "rustio-admin/auth".to_string(),
                            },
                            PlaneComponent {
                                id: "audit-service".to_string(),
                                responsibility: "审计事件记录与导出".to_string(),
                                owner: "rustio-admin/state".to_string(),
                            },
                        ],
                    },
                    PlaneTopology {
                        id: "metadata-plane".to_string(),
                        name: "元数据平面".to_string(),
                        responsibilities: vec![
                            "桶/IAM/策略元数据".to_string(),
                            "版本与对象治理元数据".to_string(),
                            "集群配置快照".to_string(),
                        ],
                        components: vec![
                            PlaneComponent {
                                id: "bucket-metadata-store".to_string(),
                                responsibility: "桶治理与对象治理元数据".to_string(),
                                owner: "rustio-admin/routes".to_string(),
                            },
                            PlaneComponent {
                                id: "iam-metadata-store".to_string(),
                                responsibility: "用户、组、策略、服务账号、STS 会话".to_string(),
                                owner: "rustio-admin/routes".to_string(),
                            },
                            PlaneComponent {
                                id: "cluster-config-history".to_string(),
                                responsibility: "配置验证、应用、回滚历史".to_string(),
                                owner: "rustio-admin/routes".to_string(),
                            },
                        ],
                    },
                    PlaneTopology {
                        id: "data-plane".to_string(),
                        name: "数据平面".to_string(),
                        responsibilities: vec![
                            "对象数据读写".to_string(),
                            "版本归档与分片上传".to_string(),
                            "S3 协议入口".to_string(),
                        ],
                        components: vec![
                            PlaneComponent {
                                id: "s3-gateway".to_string(),
                                responsibility: "根路径 S3 兼容接口与 SigV4 验签".to_string(),
                                owner: "rustio-admin/routes".to_string(),
                            },
                            PlaneComponent {
                                id: "object-store".to_string(),
                                responsibility: "本地文件对象存取与对象元数据缓存".to_string(),
                                owner: "rustio-admin/state".to_string(),
                            },
                            PlaneComponent {
                                id: "multipart-store".to_string(),
                                responsibility: "分片上传会话与分片清单维护".to_string(),
                                owner: "rustio-admin/state".to_string(),
                            },
                        ],
                    },
                    PlaneTopology {
                        id: "worker-plane".to_string(),
                        name: "任务平面".to_string(),
                        responsibilities: vec![
                            "复制状态与补偿队列".to_string(),
                            "后台任务编排".to_string(),
                            "告警规则触发与处理历史".to_string(),
                        ],
                        components: vec![
                            PlaneComponent {
                                id: "replication-worker".to_string(),
                                responsibility: "复制规则状态、站点切换、重试队列".to_string(),
                                owner: "rustio-admin/routes".to_string(),
                            },
                            PlaneComponent {
                                id: "job-orchestrator".to_string(),
                                responsibility: "heal/cancel 等后台任务状态机入口".to_string(),
                                owner: "rustio-admin/routes".to_string(),
                            },
                            PlaneComponent {
                                id: "alert-worker".to_string(),
                                responsibility: "告警规则评估触发与历史处理".to_string(),
                                owner: "rustio-admin/routes".to_string(),
                            },
                        ],
                    },
                ],
            },
            metadata_raft: RwLock::new(metadata_raft),
            credentials: RwLock::new(credentials),
            nodes: RwLock::new(vec![
                ClusterNode {
                    id: "node-a".to_string(),
                    hostname: "rustio-node-a".to_string(),
                    zone: "zone-1".to_string(),
                    online: true,
                    capacity_total_bytes: 10 * 1024 * 1024 * 1024 * 1024,
                    capacity_used_bytes: 3 * 1024 * 1024 * 1024 * 1024,
                    last_heartbeat: now,
                },
                ClusterNode {
                    id: "node-b".to_string(),
                    hostname: "rustio-node-b".to_string(),
                    zone: "zone-1".to_string(),
                    online: true,
                    capacity_total_bytes: 10 * 1024 * 1024 * 1024 * 1024,
                    capacity_used_bytes: 4 * 1024 * 1024 * 1024 * 1024,
                    last_heartbeat: now,
                },
                ClusterNode {
                    id: "node-c".to_string(),
                    hostname: "rustio-node-c".to_string(),
                    zone: "zone-2".to_string(),
                    online: true,
                    capacity_total_bytes: 10 * 1024 * 1024 * 1024 * 1024,
                    capacity_used_bytes: 2 * 1024 * 1024 * 1024 * 1024,
                    last_heartbeat: now,
                },
            ]),
            quotas: RwLock::new(vec![
                ClusterQuota {
                    tenant: "default".to_string(),
                    hard_limit_bytes: 20 * 1024 * 1024 * 1024 * 1024,
                    used_bytes: 7 * 1024 * 1024 * 1024 * 1024,
                },
                ClusterQuota {
                    tenant: "analytics".to_string(),
                    hard_limit_bytes: 8 * 1024 * 1024 * 1024 * 1024,
                    used_bytes: 2 * 1024 * 1024 * 1024 * 1024,
                },
            ]),
            tenants: RwLock::new(vec![
                TenantSpec {
                    id: "default".to_string(),
                    display_name: "默认租户".to_string(),
                    owner_group: "platform-admins".to_string(),
                    project_id: Some("default".to_string()),
                    project_name: Some("默认租户".to_string()),
                    domain_id: Some("default".to_string()),
                    domain_name: Some("Default".to_string()),
                    enabled: true,
                    status: "active".to_string(),
                    hard_limit_bytes: 20 * 1024 * 1024 * 1024 * 1024,
                    used_bytes: 7 * 1024 * 1024 * 1024 * 1024,
                    created_at: now,
                    updated_at: now,
                    labels: HashMap::from([
                        ("env".to_string(), "prod".to_string()),
                        ("tier".to_string(), "gold".to_string()),
                    ]),
                },
                TenantSpec {
                    id: "analytics".to_string(),
                    display_name: "分析租户".to_string(),
                    owner_group: "platform-admins".to_string(),
                    project_id: Some("analytics".to_string()),
                    project_name: Some("分析租户".to_string()),
                    domain_id: Some("default".to_string()),
                    domain_name: Some("Default".to_string()),
                    enabled: true,
                    status: "active".to_string(),
                    hard_limit_bytes: 8 * 1024 * 1024 * 1024 * 1024,
                    used_bytes: 2 * 1024 * 1024 * 1024 * 1024,
                    created_at: now,
                    updated_at: now,
                    labels: HashMap::from([
                        ("env".to_string(), "prod".to_string()),
                        ("tier".to_string(), "silver".to_string()),
                    ]),
                },
            ]),
            diagnostics: RwLock::new(vec![]),
            cluster_config_history: RwLock::new(cluster_config_history),
            users: RwLock::new({
                let mut users = vec![IamUser {
                    username: console_user.clone(),
                    display_name: "RustIO Admin".to_string(),
                    role: "admin".to_string(),
                    enabled: true,
                    created_at: now,
                }];
                if console_user != "admin" {
                    users.push(IamUser {
                        username: "admin".to_string(),
                        display_name: "RustIO Legacy Admin".to_string(),
                        role: "admin".to_string(),
                        enabled: true,
                        created_at: now,
                    });
                }
                users
            }),
            groups: RwLock::new(vec![IamGroup {
                name: "platform-admins".to_string(),
                members: {
                    let mut members = vec![console_user.clone()];
                    if console_user != "admin" {
                        members.push("admin".to_string());
                    }
                    members
                },
            }]),
            policies: RwLock::new(vec![IamPolicy {
                name: "cluster-admin".to_string(),
                document: json!({
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Effect": "Allow",
                        "Action": ["*"],
                        "Resource": ["*"]
                    }]
                }),
                attached_to: {
                    let mut attached = vec![console_user.clone()];
                    if console_user != "admin" {
                        attached.push("admin".to_string());
                    }
                    attached
                },
            }]),
            service_accounts: RwLock::new(vec![rustio_core::ServiceAccount {
                access_key: "sa-bootstrap".to_string(),
                secret_key: "sa-bootstrap-secret".to_string(),
                owner: "admin".to_string(),
                created_at: now,
                status: "enabled".to_string(),
            }]),
            admin_sessions: RwLock::new(console_sessions),
            sts_sessions: RwLock::new(vec![StsSession {
                session_id: Uuid::new_v4().to_string(),
                principal: "admin".to_string(),
                access_key: "sts-bootstrap-ak".to_string(),
                secret_key: "sts-bootstrap-sk".to_string(),
                session_token: Uuid::new_v4().to_string(),
                provider: "manual".to_string(),
                role_arn: None,
                session_name: Some("bootstrap".to_string()),
                session_policy: None,
                subject: None,
                audience: None,
                status: "active".to_string(),
                issued_at: now,
                expires_at: now + Duration::hours(1),
            }]),
            buckets: RwLock::new(buckets),
            remote_tiers: RwLock::new(remote_tiers),
            bucket_object_locks: RwLock::new(bucket_object_locks),
            bucket_retentions: RwLock::new(bucket_retentions),
            bucket_legal_holds: RwLock::new(bucket_legal_holds),
            bucket_notifications: RwLock::new(bucket_notifications),
            bucket_lifecycle_rules: RwLock::new(bucket_lifecycle_rules),
            bucket_acls: RwLock::new(bucket_acls),
            bucket_public_access_blocks: RwLock::new(bucket_public_access_blocks),
            bucket_policies: RwLock::new(bucket_policies),
            bucket_cors_rules: RwLock::new(bucket_cors_rules),
            bucket_tags: RwLock::new(bucket_tags),
            bucket_encryptions: RwLock::new(bucket_encryptions),
            replications: RwLock::new(vec![]),
            site_replications: RwLock::new(vec![
                SiteReplicationStatus {
                    site_id: "dr-site-a".to_string(),
                    endpoint: "https://dr-site-a.example.internal".to_string(),
                    role: "primary".to_string(),
                    preferred_primary: true,
                    state: "healthy".to_string(),
                    lag_seconds: 0,
                    managed_buckets: 3,
                    last_sync_at: now,
                    bootstrap_state: "ready".to_string(),
                    joined_at: Some(now),
                    last_resync_at: Some(now),
                    last_reconcile_at: Some(now),
                    pending_resync_items: 0,
                    drifted_buckets: 0,
                    topology_version: 1,
                    last_error: None,
                },
                SiteReplicationStatus {
                    site_id: "dr-site-b".to_string(),
                    endpoint: "https://dr-site-b.example.internal".to_string(),
                    role: "secondary".to_string(),
                    preferred_primary: false,
                    state: "healthy".to_string(),
                    lag_seconds: 12,
                    managed_buckets: 3,
                    last_sync_at: now - Duration::seconds(12),
                    bootstrap_state: "ready".to_string(),
                    joined_at: Some(now),
                    last_resync_at: Some(now - Duration::seconds(12)),
                    last_reconcile_at: Some(now - Duration::seconds(12)),
                    pending_resync_items: 0,
                    drifted_buckets: 0,
                    topology_version: 1,
                    last_error: None,
                },
            ]),
            replication_backlog: RwLock::new(vec![]),
            replication_checkpoints: RwLock::new(HashMap::new()),
            replication_sequence: AtomicU64::new(1),
            alert_rules: RwLock::new(vec![
                AlertRule {
                    id: "rule-capacity-high".to_string(),
                    name: "容量使用率过高".to_string(),
                    metric: "cluster.capacity.used_ratio".to_string(),
                    condition: ">=".to_string(),
                    threshold: 0.85,
                    window_minutes: 5,
                    severity: "critical".to_string(),
                    enabled: true,
                    channels: vec!["channel-webhook-main".to_string()],
                    last_triggered_at: None,
                },
                AlertRule {
                    id: "rule-repl-lag".to_string(),
                    name: "复制延迟超阈值".to_string(),
                    metric: "replication.lag.seconds".to_string(),
                    condition: ">=".to_string(),
                    threshold: 300.0,
                    window_minutes: 10,
                    severity: "warning".to_string(),
                    enabled: true,
                    channels: vec!["channel-email-ops".to_string()],
                    last_triggered_at: None,
                },
            ]),
            alert_channels: RwLock::new(vec![
                AlertChannel {
                    id: "channel-webhook-main".to_string(),
                    name: "主 webhook".to_string(),
                    kind: "webhook".to_string(),
                    endpoint: "https://hooks.example.internal/rustio/alerts".to_string(),
                    headers: HashMap::new(),
                    payload_template: None,
                    header_template: HashMap::new(),
                    enabled: true,
                    status: "healthy".to_string(),
                    last_checked_at: now,
                    error: None,
                },
                AlertChannel {
                    id: "channel-email-ops".to_string(),
                    name: "运维邮件组".to_string(),
                    kind: "email".to_string(),
                    endpoint: "ops@example.internal".to_string(),
                    headers: HashMap::new(),
                    payload_template: None,
                    header_template: HashMap::new(),
                    enabled: true,
                    status: "healthy".to_string(),
                    last_checked_at: now,
                    error: None,
                },
            ]),
            alert_silences: RwLock::new(vec![]),
            alert_escalations: RwLock::new(vec![
                AlertEscalationPolicy {
                    id: "escalation-critical".to_string(),
                    name: "严重告警 5 分钟升级".to_string(),
                    severity: "critical".to_string(),
                    wait_minutes: 5,
                    channels: vec![
                        "channel-webhook-main".to_string(),
                        "channel-email-ops".to_string(),
                    ],
                    enabled: true,
                },
                AlertEscalationPolicy {
                    id: "escalation-warning".to_string(),
                    name: "警告告警 15 分钟升级".to_string(),
                    severity: "warning".to_string(),
                    wait_minutes: 15,
                    channels: vec!["channel-email-ops".to_string()],
                    enabled: true,
                },
            ]),
            alert_history: RwLock::new(vec![
                AlertHistoryEntry {
                    id: "history-boot-1".to_string(),
                    rule_id: Some("rule-capacity-high".to_string()),
                    rule_name: Some("容量使用率过高".to_string()),
                    severity: "critical".to_string(),
                    status: "resolved".to_string(),
                    message: "节点容量瞬时峰值已回落至阈值以下".to_string(),
                    triggered_at: now - Duration::minutes(30),
                    source: "rule-engine".to_string(),
                    assignee: Some("admin".to_string()),
                    claimed_at: Some(now - Duration::minutes(29)),
                    acknowledged_by: Some("admin".to_string()),
                    acknowledged_at: Some(now - Duration::minutes(28)),
                    resolved_by: Some("admin".to_string()),
                    resolved_at: Some(now - Duration::minutes(26)),
                    details: json!({
                        "value": 0.91,
                        "threshold": 0.85
                    }),
                },
                AlertHistoryEntry {
                    id: "history-boot-2".to_string(),
                    rule_id: Some("rule-repl-lag".to_string()),
                    rule_name: Some("复制延迟超阈值".to_string()),
                    severity: "warning".to_string(),
                    status: "firing".to_string(),
                    message: "跨站复制延迟持续超过 300 秒".to_string(),
                    triggered_at: now - Duration::minutes(8),
                    source: "rule-engine".to_string(),
                    assignee: None,
                    claimed_at: None,
                    acknowledged_by: None,
                    acknowledged_at: None,
                    resolved_by: None,
                    resolved_at: None,
                    details: json!({
                        "value": 420,
                        "threshold": 300
                    }),
                },
            ]),
            alert_delivery_queue: RwLock::new(vec![]),
            security: RwLock::new(security),
            oidc_auth_requests: RwLock::new(HashMap::new()),
            oidc_completed_logins: RwLock::new(HashMap::new()),
            audits: RwLock::new(vec![]),
            jobs: RwLock::new(vec![JobStatus {
                id: "job-heal-001".to_string(),
                kind: "heal".to_string(),
                status: "idle".to_string(),
                priority: 3,
                bucket: None,
                object_key: None,
                site_id: None,
                idempotency_key: String::new(),
                attempt: 0,
                lease_owner: None,
                lease_until: None,
                checkpoint: None,
                last_error: None,
                payload: json!({}),
                progress: 0.0,
                created_at: now,
                updated_at: now,
                key: None,
                version_id: None,
                target: Some("cluster".to_string()),
                affected_disks: vec![],
                missing_shards: 0,
                corrupted_shards: 0,
                started_at: None,
                finished_at: None,
                attempts: 0,
                max_attempts: 0,
                next_attempt_at: None,
                error: None,
                dedupe_key: None,
                source: Some("bootstrap".to_string()),
                details: Value::Null,
            }]),
            object_access_heat: RwLock::new(HashMap::new()),
            storage_governance: RwLock::new(StorageGovernanceRuntimeState::default()),
            object_store: RwLock::new(HashMap::new()),
            object_meta: RwLock::new(HashMap::new()),
            multipart_uploads: RwLock::new(HashMap::new()),
            last_request_activity_at: AtomicI64::new(Utc::now().timestamp()),
            last_memory_trim_at: AtomicI64::new(0),
            events,
        });
        state.restore_replication_runtime_state();
        state.start_background_workers();
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let state_clone = Arc::clone(&state);
            handle.spawn(async move {
                let _ = state_clone.restore_metadata_raft_on_startup().await;
                let _ = state_clone.sync_metadata_raft("bootstrap").await;
            });
        }
        state
    }

    pub async fn push_event(&self, topic: &str, source: &str, payload: serde_json::Value) {
        let _ = self.events.send(RuntimeEvent {
            topic: topic.to_string(),
            source: source.to_string(),
            timestamp: Utc::now(),
            payload,
        });
    }

    pub fn record_request_activity(&self) {
        self.last_request_activity_at
            .store(Utc::now().timestamp(), Ordering::Relaxed);
    }

    fn maybe_trim_memory(&self) {
        if !Self::memory_trim_enabled() {
            return;
        }

        let now_ts = Utc::now().timestamp();
        let last_request_at = self.last_request_activity_at.load(Ordering::Relaxed);
        let last_trim_at = self.last_memory_trim_at.load(Ordering::Relaxed);
        let current_rss_bytes = current_process_rss_bytes();

        if Self::should_trim_memory(
            last_request_at,
            last_trim_at,
            now_ts,
            Self::memory_trim_idle_threshold(),
        ) && self.trim_memory("idle", current_rss_bytes, now_ts)
        {
            return;
        }

        let Some(rss_bytes) = current_rss_bytes else {
            return;
        };
        let threshold_bytes = Self::memory_trim_rss_threshold_bytes();
        if Self::should_force_trim_memory(
            last_trim_at,
            now_ts,
            rss_bytes,
            threshold_bytes,
            Self::memory_trim_force_interval(),
        ) {
            let _ = self.trim_memory("pressure", Some(rss_bytes), now_ts);
        }
    }

    fn trim_memory(&self, reason: &str, rss_bytes: Option<u64>, now_ts: i64) -> bool {
        let trimmed = trim_process_memory();
        if trimmed {
            self.last_memory_trim_at.store(now_ts, Ordering::Relaxed);
            let rss_after_bytes = current_process_rss_bytes();
            info!(
                reason,
                rss_bytes = rss_bytes.or(rss_after_bytes).unwrap_or_default(),
                rss_before_bytes = rss_bytes.unwrap_or_default(),
                rss_after_bytes = rss_after_bytes.unwrap_or_default(),
                threshold_bytes = Self::memory_trim_rss_threshold_bytes(),
                "RustIO 已执行内存回收 / RustIO memory trim executed"
            );
        }
        trimmed
    }

    async fn append_audit_with_sync(
        &self,
        actor: &str,
        action: &str,
        resource: &str,
        outcome: &str,
        reason: Option<String>,
        details: serde_json::Value,
        sync_metadata: bool,
    ) {
        let event = AuditEvent {
            id: Uuid::new_v4().to_string(),
            actor: actor.to_string(),
            action: action.to_string(),
            resource: resource.to_string(),
            outcome: outcome.to_string(),
            reason,
            timestamp: Utc::now(),
            details,
        };
        {
            let mut audits = self.audits.write().await;
            audits.push(event.clone());
            prune_audits_locked(&mut audits);
        }
        self.push_event(
            "audit.appended",
            "audit-service",
            json!({
                "action": event.action,
                "resource": event.resource,
                "outcome": event.outcome,
                "timestamp": event.timestamp,
            }),
        )
        .await;
        if sync_metadata {
            let _ = self.sync_metadata_raft("audit").await;
        }
    }

    pub async fn append_audit(
        &self,
        actor: &str,
        action: &str,
        resource: &str,
        outcome: &str,
        reason: Option<String>,
        details: serde_json::Value,
    ) {
        self.append_audit_with_sync(actor, action, resource, outcome, reason, details, true)
            .await;
    }

    pub async fn append_runtime_audit(
        &self,
        actor: &str,
        action: &str,
        resource: &str,
        outcome: &str,
        reason: Option<String>,
        details: serde_json::Value,
    ) {
        self.append_audit_with_sync(actor, action, resource, outcome, reason, details, false)
            .await;
    }

    fn resolve_data_disks(data_dir: &PathBuf) -> Vec<PathBuf> {
        let from_env = std::env::var("RUSTIO_DATA_DISKS")
            .or_else(|_| std::env::var("RUSTIO_EC_DISKS"))
            .unwrap_or_default();
        let mut disks = from_env
            .split(|ch: char| ch == ',' || ch == ';' || ch.is_ascii_whitespace())
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .map(PathBuf::from)
            .collect::<Vec<_>>();
        if disks.len() < 5 {
            disks = (0..5)
                .map(|idx| data_dir.join(".rustio_disks").join(format!("disk-{idx}")))
                .collect();
        }
        disks
    }

    fn metadata_network_enabled() -> bool {
        std::env::var("RUSTIO_METADATA_RAFT_NETWORK_ENABLED")
            .map(|value| value.eq_ignore_ascii_case("true") || value == "1")
            .unwrap_or(false)
    }

    fn metadata_network_strict_enabled() -> bool {
        std::env::var("RUSTIO_METADATA_RAFT_NETWORK_STRICT")
            .map(|value| value.eq_ignore_ascii_case("true") || value == "1")
            .unwrap_or(false)
    }

    fn metadata_heartbeat_interval() -> std::time::Duration {
        let ms = std::env::var("RUSTIO_METADATA_RAFT_HEARTBEAT_MS")
            .ok()
            .and_then(|raw| raw.parse::<u64>().ok())
            .unwrap_or(800)
            .clamp(200, 5_000);
        std::time::Duration::from_millis(ms)
    }

    fn metadata_election_timeout() -> std::time::Duration {
        let ms = std::env::var("RUSTIO_METADATA_RAFT_ELECTION_TIMEOUT_MS")
            .ok()
            .and_then(|raw| raw.parse::<u64>().ok())
            .unwrap_or(3_500)
            .clamp(800, 20_000);
        std::time::Duration::from_millis(ms)
    }

    fn metadata_election_cooldown() -> std::time::Duration {
        let ms = std::env::var("RUSTIO_METADATA_RAFT_ELECTION_COOLDOWN_MS")
            .ok()
            .and_then(|raw| raw.parse::<u64>().ok())
            .unwrap_or(1_500)
            .clamp(300, 10_000);
        std::time::Duration::from_millis(ms)
    }

    fn metadata_membership_change_timeout() -> std::time::Duration {
        let ms = std::env::var("RUSTIO_METADATA_RAFT_MEMBERSHIP_CHANGE_TIMEOUT_MS")
            .ok()
            .and_then(|raw| raw.parse::<u64>().ok())
            .unwrap_or(15_000)
            .clamp(2_000, 600_000);
        std::time::Duration::from_millis(ms)
    }

    fn metadata_wal_retain_entries() -> usize {
        std::env::var("RUSTIO_METADATA_RAFT_WAL_RETAIN_ENTRIES")
            .ok()
            .and_then(|raw| raw.parse::<usize>().ok())
            .unwrap_or(256)
            .clamp(32, 20_000)
    }

    fn metadata_local_peer_id() -> String {
        std::env::var("RUSTIO_METADATA_RAFT_NODE_ID").unwrap_or_else(|_| "meta-1".to_string())
    }

    fn replication_remote_enabled() -> bool {
        std::env::var("RUSTIO_REPLICATION_REMOTE_ENABLED")
            .map(|value| value.eq_ignore_ascii_case("true") || value == "1")
            .unwrap_or(false)
    }

    fn replication_worker_interval() -> std::time::Duration {
        let ms = std::env::var("RUSTIO_REPLICATION_WORKER_INTERVAL_MS")
            .ok()
            .and_then(|raw| raw.parse::<u64>().ok())
            .unwrap_or(250)
            .clamp(50, 5_000);
        std::time::Duration::from_millis(ms)
    }

    fn replication_lease_interval() -> std::time::Duration {
        let ms = std::env::var("RUSTIO_REPLICATION_LEASE_MS")
            .ok()
            .and_then(|raw| raw.parse::<u64>().ok())
            .unwrap_or_else(|| {
                let base = Self::replication_worker_interval().as_millis() as u64;
                base.saturating_mul(12).clamp(500, 60_000)
            })
            .clamp(100, 300_000);
        std::time::Duration::from_millis(ms)
    }

    fn replication_worker_concurrency() -> usize {
        std::env::var("RUSTIO_REPLICATION_WORKER_CONCURRENCY")
            .ok()
            .and_then(|raw| raw.parse::<usize>().ok())
            .unwrap_or(1)
            .clamp(1, 32)
    }

    fn alert_rule_eval_interval() -> std::time::Duration {
        let ms = std::env::var("RUSTIO_ALERT_RULE_EVAL_INTERVAL_MS")
            .ok()
            .and_then(|raw| raw.parse::<u64>().ok())
            .unwrap_or(15_000)
            .clamp(500, 600_000);
        std::time::Duration::from_millis(ms)
    }

    fn alert_delivery_interval() -> std::time::Duration {
        let ms = std::env::var("RUSTIO_ALERT_DELIVERY_INTERVAL_MS")
            .ok()
            .and_then(|raw| raw.parse::<u64>().ok())
            .unwrap_or(500)
            .clamp(100, 10_000);
        std::time::Duration::from_millis(ms)
    }

    fn alert_delivery_lease_interval() -> std::time::Duration {
        let ms = std::env::var("RUSTIO_ALERT_DELIVERY_LEASE_MS")
            .ok()
            .and_then(|raw| raw.parse::<u64>().ok())
            .unwrap_or_else(|| {
                let base = Self::alert_delivery_interval().as_millis() as u64;
                base.saturating_mul(8).clamp(500, 60_000)
            })
            .clamp(100, 300_000);
        std::time::Duration::from_millis(ms)
    }

    fn alert_delivery_max_attempts() -> u32 {
        std::env::var("RUSTIO_ALERT_DELIVERY_MAX_ATTEMPTS")
            .ok()
            .and_then(|raw| raw.parse::<u32>().ok())
            .unwrap_or(5)
            .clamp(1, 20)
    }

    fn alert_delivery_retry_base_interval() -> std::time::Duration {
        let ms = std::env::var("RUSTIO_ALERT_DELIVERY_RETRY_BASE_MS")
            .ok()
            .and_then(|raw| raw.parse::<u64>().ok())
            .unwrap_or(500)
            .clamp(100, 60_000);
        std::time::Duration::from_millis(ms)
    }

    fn alert_delivery_retry_max_interval() -> std::time::Duration {
        let ms = std::env::var("RUSTIO_ALERT_DELIVERY_RETRY_MAX_MS")
            .ok()
            .and_then(|raw| raw.parse::<u64>().ok())
            .unwrap_or(30_000)
            .clamp(500, 300_000);
        std::time::Duration::from_millis(ms)
    }

    fn alert_delivery_http_timeout() -> std::time::Duration {
        let ms = std::env::var("RUSTIO_ALERT_DELIVERY_HTTP_TIMEOUT_MS")
            .ok()
            .and_then(|raw| raw.parse::<u64>().ok())
            .unwrap_or(5_000)
            .clamp(500, 60_000);
        std::time::Duration::from_millis(ms)
    }

    fn alert_delivery_smtp_server() -> Option<String> {
        std::env::var("RUSTIO_ALERT_SMTP_SERVER")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
    }

    fn alert_delivery_smtp_from() -> String {
        std::env::var("RUSTIO_ALERT_SMTP_FROM")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "rustio-alert@localhost".to_string())
    }

    fn alert_delivery_smtp_username() -> Option<String> {
        std::env::var("RUSTIO_ALERT_SMTP_USERNAME")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
    }

    fn alert_delivery_smtp_password() -> Option<String> {
        std::env::var("RUSTIO_ALERT_SMTP_PASSWORD")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
    }

    fn alert_delivery_smtp_starttls_default() -> bool {
        std::env::var("RUSTIO_ALERT_SMTP_STARTTLS")
            .ok()
            .map(|value| value.eq_ignore_ascii_case("true") || value == "1")
            .unwrap_or(false)
    }

    fn alert_delivery_smtp_tls_default() -> bool {
        std::env::var("RUSTIO_ALERT_SMTP_TLS")
            .ok()
            .map(|value| value.eq_ignore_ascii_case("true") || value == "1")
            .unwrap_or(false)
    }

    fn alert_delivery_nats_default_subject() -> String {
        std::env::var("RUSTIO_ALERT_NATS_SUBJECT")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "rustio.alerts".to_string())
    }

    fn alert_delivery_nats_username() -> Option<String> {
        std::env::var("RUSTIO_ALERT_NATS_USERNAME")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
    }

    fn alert_delivery_nats_password() -> Option<String> {
        std::env::var("RUSTIO_ALERT_NATS_PASSWORD")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
    }

    fn alert_delivery_nats_token() -> Option<String> {
        std::env::var("RUSTIO_ALERT_NATS_TOKEN")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
    }

    fn alert_delivery_nats_tls_default() -> bool {
        std::env::var("RUSTIO_ALERT_NATS_TLS")
            .ok()
            .map(|value| value.eq_ignore_ascii_case("true") || value == "1")
            .unwrap_or(false)
    }

    fn alert_delivery_redis_default_channel() -> String {
        std::env::var("RUSTIO_ALERT_REDIS_CHANNEL")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "rustio.alerts".to_string())
    }

    fn alert_delivery_redis_username() -> Option<String> {
        std::env::var("RUSTIO_ALERT_REDIS_USERNAME")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
    }

    fn alert_delivery_redis_password() -> Option<String> {
        std::env::var("RUSTIO_ALERT_REDIS_PASSWORD")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
    }

    fn alert_delivery_redis_tls_default() -> bool {
        std::env::var("RUSTIO_ALERT_REDIS_TLS")
            .ok()
            .map(|value| value.eq_ignore_ascii_case("true") || value == "1")
            .unwrap_or(false)
    }

    fn alert_delivery_tls_ca_file() -> Option<String> {
        std::env::var("RUSTIO_ALERT_TLS_CA_FILE")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
    }

    fn replication_backlog_alert_interval() -> std::time::Duration {
        let ms = std::env::var("RUSTIO_REPLICATION_BACKLOG_ALERT_INTERVAL_MS")
            .ok()
            .and_then(|raw| raw.parse::<u64>().ok())
            .unwrap_or(1_000)
            .clamp(200, 10_000);
        std::time::Duration::from_millis(ms)
    }

    fn replication_backlog_alert_suppress_interval() -> std::time::Duration {
        let secs = std::env::var("RUSTIO_REPLICATION_BACKLOG_ALERT_SUPPRESS_SECONDS")
            .ok()
            .and_then(|raw| raw.parse::<u64>().ok())
            .unwrap_or(60)
            .clamp(1, 86_400);
        std::time::Duration::from_secs(secs)
    }

    fn replication_backlog_alert_failed_threshold() -> usize {
        std::env::var("RUSTIO_REPLICATION_BACKLOG_ALERT_FAILED_THRESHOLD")
            .ok()
            .and_then(|raw| raw.parse::<usize>().ok())
            .unwrap_or(50)
            .clamp(0, 1_000_000)
    }

    fn replication_backlog_alert_dead_letter_threshold() -> usize {
        std::env::var("RUSTIO_REPLICATION_BACKLOG_ALERT_DEAD_LETTER_THRESHOLD")
            .ok()
            .and_then(|raw| raw.parse::<usize>().ok())
            .unwrap_or(5)
            .clamp(0, 1_000_000)
    }

    fn replication_backlog_alert_pending_age_threshold() -> std::time::Duration {
        let secs = std::env::var("RUSTIO_REPLICATION_BACKLOG_ALERT_PENDING_AGE_SECONDS")
            .ok()
            .and_then(|raw| raw.parse::<u64>().ok())
            .unwrap_or(900)
            .clamp(0, 604_800);
        std::time::Duration::from_secs(secs)
    }

    pub fn replication_backlog_alert_threshold_snapshot() -> (usize, usize, u64) {
        (
            Self::replication_backlog_alert_failed_threshold(),
            Self::replication_backlog_alert_dead_letter_threshold(),
            Self::replication_backlog_alert_pending_age_threshold().as_secs(),
        )
    }

    fn replication_retry_base_interval() -> std::time::Duration {
        let ms = std::env::var("RUSTIO_REPLICATION_RETRY_BASE_MS")
            .ok()
            .and_then(|raw| raw.parse::<u64>().ok())
            .unwrap_or(500)
            .clamp(100, 60_000);
        std::time::Duration::from_millis(ms)
    }

    fn replication_retry_max_interval() -> std::time::Duration {
        let ms = std::env::var("RUSTIO_REPLICATION_RETRY_MAX_MS")
            .ok()
            .and_then(|raw| raw.parse::<u64>().ok())
            .unwrap_or(30_000)
            .clamp(500, 600_000);
        std::time::Duration::from_millis(ms)
    }

    fn replication_retry_delay(attempts: u32) -> std::time::Duration {
        let base_ms = Self::replication_retry_base_interval().as_millis() as u64;
        let max_ms = Self::replication_retry_max_interval().as_millis() as u64;
        let exp = attempts.saturating_sub(1).min(31);
        let factor = 1u64.checked_shl(exp).unwrap_or(u64::MAX);
        let delay_ms = base_ms.saturating_mul(factor).min(max_ms);
        std::time::Duration::from_millis(delay_ms)
    }

    fn replication_max_attempts() -> u32 {
        std::env::var("RUSTIO_REPLICATION_MAX_ATTEMPTS")
            .ok()
            .and_then(|raw| raw.parse::<u32>().ok())
            .unwrap_or(8)
            .clamp(1, 100)
    }

    fn storage_scan_interval() -> std::time::Duration {
        let ms = std::env::var("RUSTIO_STORAGE_SCAN_INTERVAL_MS")
            .ok()
            .and_then(|raw| raw.parse::<u64>().ok())
            .unwrap_or(300_000)
            .clamp(500, 3_600_000);
        std::time::Duration::from_millis(ms)
    }

    fn storage_heal_worker_interval() -> std::time::Duration {
        let ms = std::env::var("RUSTIO_STORAGE_HEAL_INTERVAL_MS")
            .ok()
            .and_then(|raw| raw.parse::<u64>().ok())
            .unwrap_or(1_000)
            .clamp(100, 60_000);
        std::time::Duration::from_millis(ms)
    }

    fn memory_trim_enabled() -> bool {
        std::env::var("RUSTIO_MEMORY_TRIM_ENABLED")
            .map(|value| !(value.eq_ignore_ascii_case("false") || value == "0"))
            .unwrap_or(true)
    }

    fn memory_trim_interval() -> std::time::Duration {
        let secs = std::env::var("RUSTIO_MEMORY_TRIM_INTERVAL_SECONDS")
            .ok()
            .and_then(|raw| raw.parse::<u64>().ok())
            .unwrap_or(300)
            .clamp(30, 86_400);
        std::time::Duration::from_secs(secs)
    }

    fn memory_trim_idle_threshold() -> std::time::Duration {
        let secs = std::env::var("RUSTIO_MEMORY_TRIM_IDLE_SECONDS")
            .ok()
            .and_then(|raw| raw.parse::<u64>().ok())
            .unwrap_or(43_200)
            .clamp(30, 604_800);
        std::time::Duration::from_secs(secs)
    }

    fn memory_trim_force_interval() -> std::time::Duration {
        let secs = std::env::var("RUSTIO_MEMORY_TRIM_FORCE_INTERVAL_SECONDS")
            .ok()
            .and_then(|raw| raw.parse::<u64>().ok())
            .unwrap_or(7_200)
            .clamp(300, 604_800);
        std::time::Duration::from_secs(secs)
    }

    fn memory_trim_rss_threshold_bytes() -> u64 {
        let mb = std::env::var("RUSTIO_MEMORY_TRIM_RSS_THRESHOLD_MB")
            .ok()
            .and_then(|raw| raw.parse::<u64>().ok())
            .unwrap_or(128)
            .clamp(32, 65_536);
        mb.saturating_mul(1024 * 1024)
    }

    fn should_trim_memory(
        last_request_at: i64,
        last_trim_at: i64,
        now_ts: i64,
        idle_threshold: std::time::Duration,
    ) -> bool {
        let idle_secs = idle_threshold.as_secs().min(i64::MAX as u64) as i64;
        now_ts.saturating_sub(last_request_at) >= idle_secs && last_trim_at < last_request_at
    }

    fn should_force_trim_memory(
        last_trim_at: i64,
        now_ts: i64,
        rss_bytes: u64,
        threshold_bytes: u64,
        min_interval: std::time::Duration,
    ) -> bool {
        let interval_secs = min_interval.as_secs().min(i64::MAX as u64) as i64;
        rss_bytes >= threshold_bytes && now_ts.saturating_sub(last_trim_at) >= interval_secs
    }

    const REPLICATION_NON_RETRYABLE_PREFIX: &'static str = "__RUSTIO_NON_RETRYABLE__:";

    fn replication_mark_non_retryable(message: String) -> String {
        format!("{}{}", Self::REPLICATION_NON_RETRYABLE_PREFIX, message)
    }

    fn replication_error_is_non_retryable(err: &str) -> bool {
        err.starts_with(Self::REPLICATION_NON_RETRYABLE_PREFIX)
    }

    fn replication_error_message(err: &str) -> String {
        err.strip_prefix(Self::REPLICATION_NON_RETRYABLE_PREFIX)
            .unwrap_or(err)
            .to_string()
    }

    fn replication_dead_letter_error(attempts: u32, max_attempts: u32, err: &str) -> String {
        let err = err.replace(" / ", " | ");
        format!(
            "复制任务超过最大重试次数（{attempts}/{max_attempts}），已进入死信队列：{err} / replication item exceeded max retry attempts ({attempts}/{max_attempts}) and moved to dead-letter queue: {err}"
        )
    }

    fn replication_dead_letter_non_retryable_error(err: &str) -> String {
        let err = err.replace(" / ", " | ");
        format!(
            "复制任务遇到不可重试错误，已进入死信队列：{err} / replication item hit a non-retryable error and moved to dead-letter queue: {err}"
        )
    }

    fn replication_retry_ready(item: &ReplicationBacklogItem, now: &DateTime<Utc>) -> bool {
        if item.status != "failed" {
            return false;
        }
        let delay = Self::replication_retry_delay(item.attempts.max(1));
        let Ok(retry_after) = Duration::from_std(delay) else {
            return true;
        };
        now.signed_duration_since(item.last_attempt_at) >= retry_after
    }

    pub fn internal_control_token() -> String {
        std::env::var("RUSTIO_INTERNAL_TOKEN")
            .unwrap_or_else(|_| "rustio-internal-token".to_string())
    }

    pub async fn upsert_console_session_runtime(
        &self,
        session: ConsoleSession,
    ) -> Result<(), String> {
        let snapshot = {
            let mut sessions = self.admin_sessions.write().await;
            sessions.retain(|item| item.session_id != session.session_id);
            sessions.push(session);
            sessions.clone()
        };
        Self::persist_console_sessions_snapshot(&self.data_dir, &snapshot)
    }

    pub async fn delete_console_session_runtime(&self, session_id: &str) -> Result<(), String> {
        let snapshot = {
            let mut sessions = self.admin_sessions.write().await;
            sessions.retain(|item| item.session_id != session_id);
            sessions.clone()
        };
        Self::persist_console_sessions_snapshot(&self.data_dir, &snapshot)
    }

    pub async fn broadcast_console_session_runtime(&self, session: &ConsoleSession) {
        if !Self::metadata_network_enabled() {
            return;
        }

        let endpoints = Self::metadata_peer_endpoints();
        if endpoints.is_empty() {
            return;
        }

        let local_peer_id = Self::metadata_local_peer_id();
        let internal_token = Self::internal_control_token();
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(3))
            .build()
            .unwrap_or_else(|_| Client::new());

        for (peer_id, endpoint) in endpoints {
            if peer_id == local_peer_id {
                continue;
            }

            let url = format!("{endpoint}/api/v1/internal/auth/sessions/sync");
            let _ = client
                .post(url)
                .header("x-rustio-internal-token", &internal_token)
                .json(session)
                .send()
                .await;
        }
    }

    pub async fn broadcast_console_session_delete_runtime(&self, session_id: &str) {
        if !Self::metadata_network_enabled() {
            return;
        }

        let endpoints = Self::metadata_peer_endpoints();
        if endpoints.is_empty() {
            return;
        }

        let local_peer_id = Self::metadata_local_peer_id();
        let internal_token = Self::internal_control_token();
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(3))
            .build()
            .unwrap_or_else(|_| Client::new());

        for (peer_id, endpoint) in endpoints {
            if peer_id == local_peer_id {
                continue;
            }

            let url = format!(
                "{endpoint}/api/v1/internal/auth/sessions/sync/{}",
                session_id
            );
            let _ = client
                .delete(url)
                .header("x-rustio-internal-token", &internal_token)
                .send()
                .await;
        }
    }

    fn metadata_peer_endpoints() -> HashMap<String, String> {
        let mut endpoints = HashMap::new();
        let raw = std::env::var("RUSTIO_METADATA_RAFT_PEERS").unwrap_or_default();
        for item in raw.split(',') {
            let token = item.trim();
            if token.is_empty() {
                continue;
            }
            let mut pair = token.splitn(2, '=');
            let Some(peer_id) = pair.next().map(str::trim).filter(|value| !value.is_empty()) else {
                continue;
            };
            let Some(endpoint) = pair.next().map(str::trim).filter(|value| !value.is_empty())
            else {
                continue;
            };
            endpoints.insert(peer_id.to_string(), endpoint.to_string());
        }
        endpoints
    }

    fn metadata_raft_root_dir(data_dir: &PathBuf) -> PathBuf {
        data_dir.join(".rustio_meta_raft")
    }

    fn metadata_raft_state_path(data_dir: &PathBuf) -> PathBuf {
        Self::metadata_raft_root_dir(data_dir).join("state.json")
    }

    fn load_metadata_raft_runtime_state(data_dir: &PathBuf) -> Option<MetadataRaftRuntimeState> {
        let bytes = std::fs::read(Self::metadata_raft_state_path(data_dir)).ok()?;
        serde_json::from_slice::<MetadataRaftRuntimeState>(&bytes).ok()
    }

    fn metadata_raft_runtime_from_state(raft: &MetadataRaftState) -> MetadataRaftRuntimeState {
        MetadataRaftRuntimeState {
            version: 1,
            cluster_id: raft.cluster_id.clone(),
            leader_id: raft.leader_id.clone(),
            term: raft.term,
            voted_for: raft.voted_for.clone(),
            commit_index: raft.commit_index,
            last_commit_term: raft.last_commit_term,
            last_snapshot_hash: raft.last_snapshot_hash.clone(),
            last_error: raft.last_error.clone(),
            last_commit_at: raft.last_commit_at,
            last_heartbeat_at: raft.last_heartbeat_at,
            last_election_at: raft.last_election_at,
            last_quorum_at: raft.last_quorum_at,
            membership_phase: raft.membership_phase.clone(),
            joint_old_members: raft.joint_old_members.clone(),
            joint_new_members: raft.joint_new_members.clone(),
            peers: raft
                .peers
                .iter()
                .map(|peer| MetadataRaftRuntimePeer {
                    id: peer.id.clone(),
                    endpoint: peer.endpoint.clone(),
                    online: peer.online,
                    last_index: peer.last_index,
                    match_index: peer.match_index,
                    next_index: peer.next_index,
                })
                .collect(),
        }
    }

    fn persist_metadata_raft_state_inner(&self, raft: &MetadataRaftState) -> Result<(), String> {
        let runtime = Self::metadata_raft_runtime_from_state(raft);
        let path = Self::metadata_raft_state_path(&self.data_dir);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|err| err.to_string())?;
        }
        let bytes = serde_json::to_vec_pretty(&runtime).map_err(|err| err.to_string())?;
        let temp_path = path.with_extension("tmp");
        std::fs::write(&temp_path, bytes).map_err(|err| err.to_string())?;
        std::fs::rename(temp_path, path).map_err(|err| err.to_string())?;
        Ok(())
    }

    pub async fn persist_metadata_raft_state(&self) -> Result<(), String> {
        let raft = self.metadata_raft.read().await.clone();
        self.persist_metadata_raft_state_inner(&raft)
    }

    fn bootstrap_metadata_raft(data_dir: &PathBuf) -> MetadataRaftState {
        let raft_root = Self::metadata_raft_root_dir(data_dir);
        let _ = std::fs::create_dir_all(&raft_root);
        let peer_endpoints = Self::metadata_peer_endpoints();
        let peers = (1..=3)
            .map(|idx| {
                let peer_id = format!("meta-{idx}");
                let peer_dir = raft_root.join(&peer_id);
                let _ = std::fs::create_dir_all(&peer_dir);
                MetadataRaftPeer {
                    endpoint: peer_endpoints.get(&peer_id).cloned(),
                    id: peer_id,
                    path: peer_dir,
                    online: true,
                    match_index: 0,
                    next_index: 1,
                    last_index: 0,
                }
            })
            .collect::<Vec<_>>();
        let mut state = MetadataRaftState {
            cluster_id: "raft-meta-cluster".to_string(),
            leader_id: "meta-1".to_string(),
            term: 1,
            voted_for: None,
            commit_index: 0,
            last_commit_term: 0,
            last_heartbeat_at: Some(Utc::now()),
            last_election_at: None,
            last_quorum_at: Some(Utc::now()),
            membership_phase: "stable".to_string(),
            joint_old_members: Vec::new(),
            joint_new_members: Vec::new(),
            last_snapshot_hash: String::new(),
            last_error: None,
            last_commit_at: None,
            peers,
        };

        if let Some(runtime) = Self::load_metadata_raft_runtime_state(data_dir) {
            if !runtime.cluster_id.trim().is_empty() {
                state.cluster_id = runtime.cluster_id;
            }
            if runtime.term > 0 {
                state.term = runtime.term;
            }
            state.voted_for = runtime.voted_for;
            state.commit_index = runtime.commit_index;
            state.last_commit_term = if runtime.last_commit_term == 0 && runtime.commit_index > 0 {
                state.term
            } else {
                runtime.last_commit_term
            };
            state.last_snapshot_hash = runtime.last_snapshot_hash;
            state.last_error = runtime.last_error;
            state.last_commit_at = runtime.last_commit_at;
            state.last_heartbeat_at = runtime.last_heartbeat_at.or(state.last_commit_at);
            state.last_election_at = runtime.last_election_at;
            state.last_quorum_at = runtime.last_quorum_at.or(state.last_heartbeat_at);
            if runtime.membership_phase == "joint" {
                state.membership_phase = "joint".to_string();
                state.joint_old_members = runtime.joint_old_members;
                state.joint_new_members = runtime.joint_new_members;
            }

            let mut merged = state
                .peers
                .iter()
                .map(|peer| (peer.id.clone(), peer.clone()))
                .collect::<HashMap<_, _>>();
            for peer in runtime.peers {
                if peer.id.trim().is_empty() {
                    continue;
                }
                let peer_id = peer.id.trim().to_string();
                let peer_dir = raft_root.join(&peer_id);
                let _ = std::fs::create_dir_all(&peer_dir);
                merged
                    .entry(peer_id.clone())
                    .and_modify(|item| {
                        item.online = peer.online;
                        item.last_index = peer.last_index;
                        item.match_index = peer.match_index.max(peer.last_index);
                        item.next_index = if peer.next_index == 0 {
                            item.match_index.saturating_add(1)
                        } else {
                            peer.next_index
                        };
                        if peer.endpoint.is_some() {
                            item.endpoint = peer.endpoint.clone();
                        }
                    })
                    .or_insert(MetadataRaftPeer {
                        id: peer_id,
                        path: peer_dir,
                        endpoint: peer.endpoint,
                        online: peer.online,
                        match_index: peer.match_index.max(peer.last_index),
                        next_index: if peer.next_index == 0 {
                            peer.last_index.saturating_add(1)
                        } else {
                            peer.next_index
                        },
                        last_index: peer.last_index,
                    });
            }
            state.peers = merged.into_values().collect::<Vec<_>>();
            state.peers.sort_by(|left, right| left.id.cmp(&right.id));
            if !runtime.leader_id.trim().is_empty()
                && state.peers.iter().any(|peer| peer.id == runtime.leader_id)
            {
                state.leader_id = runtime.leader_id;
            }
        }

        for peer in &mut state.peers {
            if let Some(endpoint) = peer_endpoints.get(&peer.id) {
                peer.endpoint = Some(endpoint.clone());
            }
            peer.match_index = peer.match_index.max(peer.last_index);
            if peer.next_index == 0 {
                peer.next_index = peer.match_index.saturating_add(1);
            }
        }
        if !state
            .peers
            .iter()
            .any(|peer| peer.id == state.leader_id && peer.online)
        {
            if let Some(leader) = state.peers.iter().find(|peer| peer.online) {
                state.leader_id = leader.id.clone();
            }
        }
        state.last_heartbeat_at = Some(Utc::now());
        state.last_quorum_at = state.last_quorum_at.or(state.last_heartbeat_at);
        if state.membership_phase != "joint" {
            state.membership_phase = "stable".to_string();
            state.joint_old_members.clear();
            state.joint_new_members.clear();
        } else if state.joint_old_members.is_empty() || state.joint_new_members.is_empty() {
            state.membership_phase = "stable".to_string();
            state.joint_old_members.clear();
            state.joint_new_members.clear();
        }
        state
    }

    fn hash_json(value: &impl Serialize) -> Result<String, String> {
        let bytes = serde_json::to_vec(value).map_err(|err| err.to_string())?;
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        Ok(hex::encode(hasher.finalize()))
    }

    fn metadata_snapshot_hash(snapshot: &MetadataRaftSnapshot) -> Result<String, String> {
        let mut canonical = snapshot.clone();
        canonical.generated_at = DateTime::<Utc>::from(std::time::SystemTime::UNIX_EPOCH);
        Self::hash_json(&canonical)
    }

    fn raft_last_commit_term(raft: &MetadataRaftState) -> u64 {
        if raft.last_commit_term == 0 && raft.commit_index > 0 {
            raft.term
        } else {
            raft.last_commit_term
        }
    }

    async fn send_metadata_raft_sync_request(
        client: &Client,
        url: &str,
        internal_token: &str,
        request: &MetadataRaftSyncRequest,
    ) -> Result<MetadataRaftSyncResponse, String> {
        let response = client
            .post(url)
            .header("x-rustio-internal-token", internal_token)
            .json(request)
            .send()
            .await
            .map_err(|err| err.to_string())?;
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(format!("sync status: {status}, body: {}", body.trim()));
        }
        response
            .json::<MetadataRaftSyncResponse>()
            .await
            .map_err(|err| format!("decode sync response failed: {err}"))
    }

    async fn send_metadata_raft_pre_vote_request(
        client: &Client,
        url: &str,
        internal_token: &str,
        request: &MetadataRaftPreVoteRequest,
    ) -> Result<MetadataRaftPreVoteResponse, String> {
        let response = client
            .post(url)
            .header("x-rustio-internal-token", internal_token)
            .json(request)
            .send()
            .await
            .map_err(|err| err.to_string())?;
        if !response.status().is_success() {
            return Err(format!("pre-vote status: {}", response.status()));
        }
        response
            .json::<MetadataRaftPreVoteResponse>()
            .await
            .map_err(|err| format!("decode pre-vote response failed: {err}"))
    }

    async fn send_metadata_raft_read_index_request(
        client: &Client,
        url: &str,
        internal_token: &str,
        request: &MetadataRaftReadIndexRequest,
    ) -> Result<MetadataRaftReadIndexResponse, String> {
        let response = client
            .post(url)
            .header("x-rustio-internal-token", internal_token)
            .json(request)
            .send()
            .await
            .map_err(|err| err.to_string())?;
        if !response.status().is_success() {
            return Err(format!("read-index status: {}", response.status()));
        }
        response
            .json::<MetadataRaftReadIndexResponse>()
            .await
            .map_err(|err| format!("decode read-index response failed: {err}"))
    }

    async fn send_metadata_raft_heartbeat_request(
        client: &Client,
        url: &str,
        internal_token: &str,
        request: &MetadataRaftHeartbeatRequest,
    ) -> Result<MetadataRaftHeartbeatResponse, String> {
        let response = client
            .post(url)
            .header("x-rustio-internal-token", internal_token)
            .json(request)
            .send()
            .await
            .map_err(|err| err.to_string())?;
        if !response.status().is_success() {
            return Err(format!("heartbeat status: {}", response.status()));
        }
        response
            .json::<MetadataRaftHeartbeatResponse>()
            .await
            .map_err(|err| format!("decode heartbeat response failed: {err}"))
    }

    fn persist_metadata_log_to_peer(
        peer_path: &PathBuf,
        entry: &MetadataRaftLogEntry,
        snapshot_bytes: &[u8],
    ) -> Result<(), String> {
        std::fs::create_dir_all(peer_path).map_err(|err| err.to_string())?;
        let wal_path = peer_path.join("wal.jsonl");
        let line = format!(
            "{}\n",
            serde_json::to_string(entry).map_err(|err| err.to_string())?
        );
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(&wal_path)
            .and_then(|mut file| file.write_all(line.as_bytes()))
            .map_err(|err| err.to_string())?;

        let snapshot_path = peer_path.join("snapshot.json");
        std::fs::write(&snapshot_path, snapshot_bytes).map_err(|err| err.to_string())?;

        let snapshots_dir = peer_path.join("snapshots");
        std::fs::create_dir_all(&snapshots_dir).map_err(|err| err.to_string())?;
        let index_snapshot = snapshots_dir.join(format!("{}.json", entry.index));
        std::fs::write(index_snapshot, snapshot_bytes).map_err(|err| err.to_string())?;
        let retain_entries = Self::metadata_wal_retain_entries();
        let _ = Self::compact_metadata_wal_for_peer(peer_path, retain_entries);
        Ok(())
    }

    fn compact_metadata_wal_for_peer(
        peer_path: &PathBuf,
        retain_entries: usize,
    ) -> Result<(), String> {
        let wal_path = peer_path.join("wal.jsonl");
        let content = match std::fs::read_to_string(&wal_path) {
            Ok(value) => value,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(err) => return Err(err.to_string()),
        };
        let mut entries = content
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(|line| {
                serde_json::from_str::<MetadataRaftLogEntry>(line).map_err(|err| err.to_string())
            })
            .collect::<Result<Vec<_>, _>>()?;
        if entries.len() <= retain_entries {
            return Ok(());
        }
        entries.sort_by(|left, right| left.index.cmp(&right.index));
        let keep_from = entries.len().saturating_sub(retain_entries);
        let kept_entries = entries.split_off(keep_from);
        let min_kept_index = kept_entries.first().map(|entry| entry.index).unwrap_or(0);
        let wal_bytes = kept_entries
            .iter()
            .map(|item| serde_json::to_string(item).map(|line| format!("{line}\n")))
            .collect::<Result<Vec<_>, _>>()
            .map(|lines| lines.concat())
            .map_err(|err| err.to_string())?;
        let temp_wal = wal_path.with_extension("jsonl.tmp");
        std::fs::write(&temp_wal, wal_bytes).map_err(|err| err.to_string())?;
        std::fs::rename(&temp_wal, &wal_path).map_err(|err| err.to_string())?;

        let snapshots_dir = peer_path.join("snapshots");
        if !snapshots_dir.exists() {
            return Ok(());
        }
        for item in std::fs::read_dir(&snapshots_dir).map_err(|err| err.to_string())? {
            let entry = match item {
                Ok(value) => value,
                Err(_) => continue,
            };
            let path = entry.path();
            let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
                continue;
            };
            if !file_name.ends_with(".json") {
                continue;
            }
            let Some(stem) = file_name.strip_suffix(".json") else {
                continue;
            };
            let Ok(index) = stem.parse::<u64>() else {
                continue;
            };
            if index < min_kept_index {
                let _ = std::fs::remove_file(path);
            }
        }
        Ok(())
    }

    fn metadata_log_term_from_peer(peer_path: &PathBuf, index: u64, fallback: u64) -> u64 {
        if index == 0 {
            return 0;
        }
        let wal_path = peer_path.join("wal.jsonl");
        let Ok(content) = std::fs::read_to_string(wal_path) else {
            return fallback;
        };
        let mut term = None::<u64>;
        for line in content.lines() {
            if let Ok(entry) = serde_json::from_str::<MetadataRaftLogEntry>(line) {
                if entry.index == index {
                    term = Some(entry.term);
                }
            }
        }
        term.unwrap_or(fallback)
    }

    fn sorted_map_entries<T: Clone>(map: &HashMap<String, T>) -> Vec<(String, T)> {
        let mut entries = map
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect::<Vec<_>>();
        entries.sort_by(|left, right| left.0.cmp(&right.0));
        entries
    }

    async fn build_metadata_snapshot(&self) -> MetadataRaftSnapshot {
        let mut buckets = self
            .buckets
            .read()
            .await
            .values()
            .cloned()
            .collect::<Vec<_>>();
        buckets.sort_by(|left, right| left.name.cmp(&right.name));
        let remote_tiers = Self::sorted_map_entries(&self.remote_tiers.read().await.clone());
        let bucket_object_locks =
            Self::sorted_map_entries(&self.bucket_object_locks.read().await.clone());
        let bucket_retentions =
            Self::sorted_map_entries(&self.bucket_retentions.read().await.clone());
        let bucket_legal_holds =
            Self::sorted_map_entries(&self.bucket_legal_holds.read().await.clone());
        let bucket_notifications =
            Self::sorted_map_entries(&self.bucket_notifications.read().await.clone());
        let bucket_lifecycle_rules =
            Self::sorted_map_entries(&self.bucket_lifecycle_rules.read().await.clone());
        let bucket_acls = Self::sorted_map_entries(&self.bucket_acls.read().await.clone());
        let bucket_public_access_blocks =
            Self::sorted_map_entries(&self.bucket_public_access_blocks.read().await.clone());
        let bucket_policies = Self::sorted_map_entries(&self.bucket_policies.read().await.clone());
        let bucket_cors_rules =
            Self::sorted_map_entries(&self.bucket_cors_rules.read().await.clone());
        let bucket_tags = Self::sorted_map_entries(&self.bucket_tags.read().await.clone());
        let bucket_encryptions =
            Self::sorted_map_entries(&self.bucket_encryptions.read().await.clone());

        let mut objects = self
            .object_meta
            .read()
            .await
            .iter()
            .map(|((bucket, key), meta)| MetadataObjectEntry {
                bucket: bucket.clone(),
                key: key.clone(),
                meta: meta.clone(),
            })
            .collect::<Vec<_>>();
        objects.sort_by(|left, right| {
            left.bucket
                .cmp(&right.bucket)
                .then_with(|| left.key.cmp(&right.key))
        });

        let mut iam_users = self.users.read().await.clone();
        iam_users.sort_by(|left, right| left.username.cmp(&right.username));
        let credentials = Self::sorted_map_entries(&self.credentials.read().await.clone());
        let mut iam_groups = self.groups.read().await.clone();
        iam_groups.sort_by(|left, right| left.name.cmp(&right.name));
        let mut iam_policies = self.policies.read().await.clone();
        iam_policies.sort_by(|left, right| left.name.cmp(&right.name));
        let mut service_accounts = self.service_accounts.read().await.clone();
        service_accounts.sort_by(|left, right| left.access_key.cmp(&right.access_key));
        let mut admin_sessions = self.admin_sessions.read().await.clone();
        admin_sessions.sort_by(|left, right| left.session_id.cmp(&right.session_id));
        let mut sts_sessions = self.sts_sessions.read().await.clone();
        sts_sessions.sort_by(|left, right| left.session_id.cmp(&right.session_id));
        let mut replications = self.replications.read().await.clone();
        replications.sort_by(|left, right| {
            left.source_bucket
                .cmp(&right.source_bucket)
                .then_with(|| left.target_site.cmp(&right.target_site))
                .then_with(|| left.rule_id.cmp(&right.rule_id))
        });
        let mut site_replications = self.site_replications.read().await.clone();
        site_replications.sort_by(|left, right| left.site_id.cmp(&right.site_id));
        let mut replication_backlog = self.replication_backlog.read().await.clone();
        replication_backlog.sort_by(|left, right| left.id.cmp(&right.id));
        let replication_checkpoints =
            Self::sorted_map_entries(&self.replication_checkpoints.read().await.clone());
        let cluster_config_history = self.cluster_config_history.read().await.clone();
        let security = self.security.read().await.clone();
        let mut jobs = self.jobs.read().await.clone();
        jobs.sort_by(|left, right| left.id.cmp(&right.id));

        MetadataRaftSnapshot {
            generated_at: Utc::now(),
            buckets,
            remote_tiers,
            bucket_object_locks,
            bucket_retentions,
            bucket_legal_holds,
            bucket_notifications,
            bucket_lifecycle_rules,
            bucket_acls,
            bucket_public_access_blocks,
            bucket_policies,
            bucket_cors_rules,
            bucket_tags,
            bucket_encryptions,
            objects,
            credentials,
            iam_users,
            iam_groups,
            iam_policies,
            service_accounts,
            admin_sessions,
            sts_sessions,
            replications,
            site_replications,
            replication_backlog,
            replication_checkpoints,
            cluster_config_history,
            security,
            jobs,
        }
    }

    pub async fn export_metadata_raft_sync_request(
        &self,
        reason: &str,
    ) -> Result<MetadataRaftSyncRequest, String> {
        let snapshot = self.build_metadata_snapshot().await;
        let raft = self.metadata_raft.read().await;
        let snapshot_hash = if raft.last_snapshot_hash.is_empty() {
            Self::metadata_snapshot_hash(&snapshot)?
        } else {
            raft.last_snapshot_hash.clone()
        };
        let last_commit_term = Self::raft_last_commit_term(&raft);
        let entry = MetadataRaftLogEntry {
            index: raft.commit_index,
            term: if raft.commit_index > 0 {
                last_commit_term
            } else {
                raft.term
            },
            reason: reason.to_string(),
            written_at: raft.last_commit_at.unwrap_or_else(Utc::now),
            snapshot_hash,
        };
        Ok(MetadataRaftSyncRequest {
            cluster_id: raft.cluster_id.clone(),
            peer_id: Self::metadata_local_peer_id(),
            entry,
            prev_log_index: 0,
            prev_log_term: 0,
            install_snapshot: true,
            leader_commit: raft.commit_index,
            snapshot,
        })
    }

    fn replication_state_path(&self) -> PathBuf {
        self.replication_root_dir().join("runtime-state.json")
    }

    fn restore_replication_runtime_state(&self) {
        let state_path = self.replication_state_path();
        let bytes = match std::fs::read(&state_path) {
            Ok(bytes) => bytes,
            Err(_) => return,
        };
        let runtime = match serde_json::from_slice::<ReplicationRuntimeState>(&bytes) {
            Ok(value) => value,
            Err(_) => return,
        };
        if let Ok(mut backlog) = self.replication_backlog.try_write() {
            *backlog = runtime.backlog;
        }
        if let Ok(mut checkpoints) = self.replication_checkpoints.try_write() {
            *checkpoints = runtime.checkpoints;
        }
        let mut next_sequence = runtime.sequence.max(1);
        if let Ok(backlog) = self.replication_backlog.try_read() {
            for item in backlog.iter() {
                next_sequence = next_sequence.max(item.checkpoint.saturating_add(1));
            }
        }
        if let Ok(checkpoints) = self.replication_checkpoints.try_read() {
            for checkpoint in checkpoints.values() {
                next_sequence = next_sequence.max(checkpoint.saturating_add(1));
            }
        }
        self.replication_sequence
            .store(next_sequence.max(1), Ordering::SeqCst);
    }

    pub async fn persist_replication_runtime_state(&self) {
        let runtime = ReplicationRuntimeState {
            version: 1,
            sequence: self.replication_sequence.load(Ordering::SeqCst),
            backlog: self.replication_backlog.read().await.clone(),
            checkpoints: self.replication_checkpoints.read().await.clone(),
        };
        let path = self.replication_state_path();
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(bytes) = serde_json::to_vec_pretty(&runtime) {
            let temp_path = path.with_extension("tmp");
            if std::fs::write(&temp_path, bytes).is_ok() {
                let _ = std::fs::rename(temp_path, path);
            }
        }
    }

    pub async fn sync_metadata_raft(&self, reason: &str) -> Result<(), String> {
        let network_enabled = Self::metadata_network_enabled();
        let local_peer_id = Self::metadata_local_peer_id();
        let force_sync = reason.contains("joint") || reason.starts_with("peer-");
        if network_enabled {
            let raft = self.metadata_raft.read().await;
            if !Self::local_peer_in_membership(&raft, &local_peer_id) {
                return Err(bilingual_runtime_error(
                    "当前节点不在元数据 Raft 成员集合中",
                    "local peer is not in metadata raft membership",
                ));
            }
            if raft.leader_id != local_peer_id {
                return Err(bilingual_runtime_error(
                    "仅 Raft leader 可提交元数据",
                    format!(
                        "metadata raft write must be issued on leader {}, local peer is {}",
                        raft.leader_id, local_peer_id
                    ),
                ));
            }
        }

        let snapshot = self.build_metadata_snapshot().await;
        let snapshot_hash = Self::metadata_snapshot_hash(&snapshot)?;
        let snapshot_bytes = serde_json::to_vec_pretty(&snapshot).map_err(|err| err.to_string())?;
        let now = Utc::now();

        let mut raft = self.metadata_raft.write().await;
        if snapshot_hash == raft.last_snapshot_hash && !force_sync {
            return Ok(());
        }

        let next_index = raft.commit_index + 1;
        let entry = MetadataRaftLogEntry {
            index: next_index,
            term: raft.term,
            reason: reason.to_string(),
            written_at: now,
            snapshot_hash: snapshot_hash.clone(),
        };

        let quorum = Self::metadata_membership_quorum(raft.peers.len());
        let mut last_error = None::<String>;
        let mut max_term_seen = raft.term;
        let network_strict = network_enabled && Self::metadata_network_strict_enabled();
        let internal_token = Self::internal_control_token();
        let cluster_id = raft.cluster_id.clone();
        let local_last_term = Self::raft_last_commit_term(&raft);
        let local_peer_path = raft
            .peers
            .iter()
            .find(|peer| peer.id == local_peer_id)
            .map(|peer| peer.path.clone());
        let http_client = if network_enabled {
            Some(
                Client::builder()
                    .timeout(std::time::Duration::from_secs(5))
                    .build()
                    .map_err(|err| err.to_string())?,
            )
        } else {
            None
        };
        for peer in raft.peers.iter_mut() {
            if !peer.online {
                continue;
            }
            let mut replicated = false;
            if peer.id == local_peer_id {
                match Self::persist_metadata_log_to_peer(&peer.path, &entry, &snapshot_bytes) {
                    Ok(_) => {
                        replicated = true;
                    }
                    Err(err) => {
                        last_error = Some(bilingual_runtime_error(
                            "元数据 Raft 本地节点写入失败",
                            format!("peer {} write failed: {err}", peer.id),
                        ));
                    }
                }
            }
            if replicated {
                peer.last_index = next_index;
                peer.match_index = next_index;
                peer.next_index = next_index.saturating_add(1);
                continue;
            }
            let endpoint = peer
                .endpoint
                .as_ref()
                .map(|value| value.trim())
                .filter(|value| !value.is_empty())
                .map(ToString::to_string);
            if network_enabled && network_strict && endpoint.is_none() {
                last_error = Some(bilingual_runtime_error(
                    "元数据 Raft 网络同步配置缺失",
                    format!("peer {} missing endpoint in strict mode", peer.id),
                ));
                continue;
            }
            if let (Some(client), Some(endpoint)) = (http_client.as_ref(), endpoint.as_ref()) {
                if !endpoint.starts_with("http://") && !endpoint.starts_with("https://") {
                    last_error = Some(bilingual_runtime_error(
                        "元数据 Raft 网络同步配置错误",
                        format!("peer {} endpoint is invalid", peer.id),
                    ));
                    if network_strict {
                        continue;
                    }
                }
                let endpoint = endpoint.trim_end_matches('/');
                let url = format!("{endpoint}/api/v1/internal/metadata-raft/sync");
                let local_path = local_peer_path.as_ref();
                let mut probe_prev_index = peer
                    .next_index
                    .saturating_sub(1)
                    .min(next_index.saturating_sub(1))
                    .max(peer.match_index.min(next_index.saturating_sub(1)));
                let mut append_success = false;
                for _ in 0..5 {
                    let prev_log_term = if let Some(path) = local_path {
                        Self::metadata_log_term_from_peer(path, probe_prev_index, local_last_term)
                    } else if probe_prev_index == 0 {
                        0
                    } else {
                        local_last_term
                    };
                    let request = MetadataRaftSyncRequest {
                        cluster_id: cluster_id.clone(),
                        peer_id: peer.id.clone(),
                        entry: entry.clone(),
                        prev_log_index: probe_prev_index,
                        prev_log_term,
                        install_snapshot: false,
                        leader_commit: next_index,
                        snapshot: snapshot.clone(),
                    };
                    match Self::send_metadata_raft_sync_request(
                        client,
                        &url,
                        &internal_token,
                        &request,
                    )
                    .await
                    {
                        Ok(payload) if payload.success => {
                            max_term_seen = max_term_seen.max(payload.term);
                            peer.match_index = peer.match_index.max(payload.match_index);
                            peer.last_index = peer.last_index.max(peer.match_index);
                            peer.next_index = peer.match_index.saturating_add(1);
                            replicated = true;
                            append_success = true;
                            break;
                        }
                        Ok(payload) => {
                            max_term_seen = max_term_seen.max(payload.term);
                            let reason = payload
                                .reason
                                .unwrap_or_else(|| "append rejected".to_string());
                            if payload.term > entry.term {
                                last_error = Some(bilingual_runtime_error(
                                    "元数据 Raft 网络同步失败",
                                    format!("peer {} has higher term {}", peer.id, payload.term),
                                ));
                                break;
                            }
                            let next_probe = if payload.match_index < probe_prev_index {
                                payload.match_index
                            } else {
                                probe_prev_index.saturating_sub(1)
                            };
                            peer.next_index = next_probe.saturating_add(1);
                            if next_probe == probe_prev_index {
                                last_error = Some(bilingual_runtime_error(
                                    "元数据 Raft 网络同步失败",
                                    format!("peer {} rejected append: {reason}", peer.id),
                                ));
                                break;
                            }
                            probe_prev_index = next_probe;
                            last_error = Some(bilingual_runtime_error(
                                "元数据 Raft 网络同步重试中",
                                format!(
                                    "peer {} append retry with prev_log_index {}: {}",
                                    peer.id, probe_prev_index, reason
                                ),
                            ));
                        }
                        Err(err) => {
                            last_error = Some(bilingual_runtime_error(
                                "元数据 Raft 网络同步失败",
                                format!("peer {} sync request failed: {err}", peer.id),
                            ));
                            break;
                        }
                    }
                }

                if !append_success {
                    let install_snapshot_request = MetadataRaftSyncRequest {
                        cluster_id: cluster_id.clone(),
                        peer_id: peer.id.clone(),
                        entry: entry.clone(),
                        prev_log_index: 0,
                        prev_log_term: 0,
                        install_snapshot: true,
                        leader_commit: next_index,
                        snapshot: snapshot.clone(),
                    };
                    match Self::send_metadata_raft_sync_request(
                        client,
                        &url,
                        &internal_token,
                        &install_snapshot_request,
                    )
                    .await
                    {
                        Ok(payload) if payload.success => {
                            max_term_seen = max_term_seen.max(payload.term);
                            peer.match_index = peer.match_index.max(payload.match_index);
                            peer.last_index = peer.last_index.max(peer.match_index);
                            peer.next_index = peer.match_index.saturating_add(1);
                            replicated = true;
                        }
                        Ok(payload) => {
                            max_term_seen = max_term_seen.max(payload.term);
                            last_error = Some(bilingual_runtime_error(
                                "元数据 Raft 网络同步失败",
                                format!(
                                    "peer {} install-snapshot rejected: {}",
                                    peer.id,
                                    payload
                                        .reason
                                        .unwrap_or_else(|| "snapshot rejected".to_string())
                                ),
                            ));
                        }
                        Err(err) => {
                            last_error = Some(bilingual_runtime_error(
                                "元数据 Raft 网络同步失败",
                                format!("peer {} snapshot sync request failed: {err}", peer.id),
                            ));
                        }
                    }
                }
            }
            if !replicated && network_strict && network_enabled && endpoint.is_some() {
                continue;
            }
            if !replicated {
                match Self::persist_metadata_log_to_peer(&peer.path, &entry, &snapshot_bytes) {
                    Ok(_) => {
                        replicated = true;
                    }
                    Err(err) => {
                        last_error = Some(bilingual_runtime_error(
                            "元数据 Raft 节点写入失败",
                            format!("peer {} write failed: {err}", peer.id),
                        ));
                    }
                }
            }
            if replicated {
                peer.last_index = peer.last_index.max(next_index);
                peer.match_index = peer.match_index.max(peer.last_index);
                peer.next_index = peer.match_index.saturating_add(1);
            }
        }
        raft.term = raft.term.max(max_term_seen);
        if max_term_seen > entry.term {
            raft.voted_for = None;
            if raft.leader_id == local_peer_id {
                raft.leader_id.clear();
            }
            raft.last_error = Some(bilingual_runtime_error(
                "元数据 Raft leader 任期已过期",
                format!(
                    "leader term {} is stale, observed higher term {}",
                    entry.term, max_term_seen
                ),
            ));
            let error_message = raft.last_error.clone().unwrap_or_else(|| {
                bilingual_runtime_error("元数据 Raft 提交失败", "raft leader term is stale")
            });
            let raft_snapshot = raft.clone();
            drop(raft);
            let _ = self.persist_metadata_raft_state_inner(&raft_snapshot);
            return Err(error_message);
        }

        let (quorum_commit_index, quorum_error) = if let Some((old_members, new_members)) =
            Self::effective_joint_members(&raft)
        {
            let old_quorum = Self::metadata_membership_quorum(old_members.len());
            let new_quorum = Self::metadata_membership_quorum(new_members.len());
            let old_online = Self::online_member_count(&raft, &old_members);
            let new_online = Self::online_member_count(&raft, &new_members);
            let old_commit_index = Self::quorum_commit_index_for_members(&raft, &old_members);
            let new_commit_index = Self::quorum_commit_index_for_members(&raft, &new_members);
            let joint_commit_index = old_commit_index.min(new_commit_index);
            if old_online < old_quorum
                || new_online < new_quorum
                || old_commit_index < next_index
                || new_commit_index < next_index
            {
                (
                        joint_commit_index,
                        Some(bilingual_runtime_error(
                            "元数据 Raft joint-consensus 未达到法定票数",
                            format!(
                                "joint quorum not reached: old {old_online}/{old_quorum} commit={old_commit_index}, new {new_online}/{new_quorum} commit={new_commit_index}, expected={next_index}"
                            ),
                        )),
                    )
            } else {
                (joint_commit_index, None)
            }
        } else {
            let mut online_match_indexes = raft
                .peers
                .iter()
                .filter(|peer| peer.online)
                .map(|peer| peer.match_index)
                .collect::<Vec<_>>();
            online_match_indexes.sort_unstable_by(|left, right| right.cmp(left));
            let stable_commit_index = online_match_indexes
                .get(quorum.saturating_sub(1))
                .copied()
                .unwrap_or(0);
            let replicated_peers = raft
                .peers
                .iter()
                .filter(|peer| peer.online && peer.match_index >= next_index)
                .count();
            if stable_commit_index < next_index {
                (
                        stable_commit_index,
                        Some(bilingual_runtime_error(
                            "元数据 Raft 未达到法定票数",
                            format!(
                                "raft quorum not reached: replicated peers {replicated_peers}/{quorum}, quorum_commit_index={stable_commit_index}, expected={next_index}"
                            ),
                        )),
                    )
            } else {
                (stable_commit_index, None)
            }
        };

        if let Some(quorum_error) = quorum_error {
            raft.last_error = Some(last_error.unwrap_or(quorum_error));
            let error_message = raft.last_error.clone().unwrap_or_else(|| {
                bilingual_runtime_error("元数据 Raft 提交失败", "raft commit failed")
            });
            let raft_snapshot = raft.clone();
            drop(raft);
            let _ = self.persist_metadata_raft_state_inner(&raft_snapshot);
            return Err(error_message);
        }

        raft.commit_index = raft.commit_index.max(quorum_commit_index);
        if raft.commit_index >= next_index {
            raft.last_commit_term = entry.term;
        }
        raft.last_snapshot_hash = snapshot_hash;
        raft.last_commit_at = Some(now);
        raft.last_quorum_at = Some(now);
        raft.last_error = None;
        let raft_snapshot = raft.clone();
        drop(raft);
        self.persist_metadata_raft_state_inner(&raft_snapshot)?;
        Ok(())
    }

    async fn restore_metadata_raft_on_startup(&self) -> Result<(), String> {
        self.restore_metadata_raft_from_local_snapshot().await?;
        if !Self::metadata_network_enabled() {
            return Ok(());
        }

        let mut last_error = None::<String>;
        for _ in 0..8 {
            match self.catchup_metadata_raft_from_remote_peers().await {
                Ok(_) => return Ok(()),
                Err(err) => {
                    last_error = Some(err);
                    tokio::time::sleep(std::time::Duration::from_millis(400)).await;
                }
            }
        }
        if let Some(err) = last_error {
            return Err(err);
        }
        Ok(())
    }

    async fn restore_metadata_raft_from_local_snapshot(&self) -> Result<(), String> {
        let local_peer_id = Self::metadata_local_peer_id();
        let peer_root = self.data_dir.join(".rustio_meta_raft").join(&local_peer_id);
        let wal_entries = std::fs::read_to_string(peer_root.join("wal.jsonl"))
            .ok()
            .map(|content| {
                content
                    .lines()
                    .filter_map(|line| serde_json::from_str::<MetadataRaftLogEntry>(line).ok())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let mut wal_entries = wal_entries;
        wal_entries.sort_by(|left, right| left.index.cmp(&right.index));

        let cluster_id = self.metadata_raft.read().await.cluster_id.clone();
        let mut applied = false;
        let snapshots_dir = peer_root.join("snapshots");

        for entry in wal_entries.iter() {
            let candidate_path = snapshots_dir.join(format!("{}.json", entry.index));
            if !candidate_path.exists() {
                continue;
            }
            let snapshot_bytes = match std::fs::read(&candidate_path) {
                Ok(bytes) => bytes,
                Err(_) => continue,
            };
            let snapshot = match serde_json::from_slice::<MetadataRaftSnapshot>(&snapshot_bytes) {
                Ok(snapshot) => snapshot,
                Err(_) => continue,
            };
            let mut entry = entry.clone();
            if entry.snapshot_hash.is_empty() {
                entry.snapshot_hash = Self::metadata_snapshot_hash(&snapshot)?;
            }
            let leader_commit = entry.index;
            let request = MetadataRaftSyncRequest {
                cluster_id: cluster_id.clone(),
                peer_id: local_peer_id.clone(),
                entry,
                prev_log_index: 0,
                prev_log_term: 0,
                install_snapshot: true,
                leader_commit,
                snapshot,
            };
            let response = self
                .apply_metadata_raft_snapshot_internal(request, false)
                .await?;
            if !response.success {
                return Err(bilingual_runtime_error(
                    "本地元数据 Raft 重放失败",
                    response
                        .reason
                        .unwrap_or_else(|| "local metadata raft replay rejected".to_string()),
                ));
            }
            applied = true;
        }

        if applied {
            return Ok(());
        }

        let snapshot_path = peer_root.join("snapshot.json");
        if !snapshot_path.exists() {
            return Ok(());
        }
        let snapshot_bytes = std::fs::read(&snapshot_path).map_err(|err| {
            bilingual_runtime_error(
                "读取元数据快照失败",
                format!("failed to read metadata raft snapshot: {err}"),
            )
        })?;
        let snapshot =
            serde_json::from_slice::<MetadataRaftSnapshot>(&snapshot_bytes).map_err(|err| {
                bilingual_runtime_error(
                    "解析元数据快照失败",
                    format!("failed to decode metadata raft snapshot: {err}"),
                )
            })?;
        let mut entry = wal_entries.last().cloned().unwrap_or(MetadataRaftLogEntry {
            index: 0,
            term: 1,
            reason: "startup-restore".to_string(),
            written_at: Utc::now(),
            snapshot_hash: String::new(),
        });
        if entry.snapshot_hash.is_empty() {
            entry.snapshot_hash = Self::metadata_snapshot_hash(&snapshot)?;
        }
        let leader_commit = entry.index;
        let request = MetadataRaftSyncRequest {
            cluster_id,
            peer_id: local_peer_id,
            entry,
            prev_log_index: 0,
            prev_log_term: 0,
            install_snapshot: true,
            leader_commit,
            snapshot,
        };
        let response = self
            .apply_metadata_raft_snapshot_internal(request, false)
            .await?;
        if response.success {
            Ok(())
        } else {
            Err(bilingual_runtime_error(
                "本地元数据 Raft 恢复失败",
                response
                    .reason
                    .unwrap_or_else(|| "local metadata raft restore rejected".to_string()),
            ))
        }
    }

    async fn catchup_metadata_raft_from_remote_peers(&self) -> Result<(), String> {
        if !Self::metadata_network_enabled() {
            return Ok(());
        }

        let endpoints = Self::metadata_peer_endpoints();
        let local_peer_id = Self::metadata_local_peer_id();
        let internal_token = Self::internal_control_token();
        let current_index = self.metadata_raft.read().await.commit_index;
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .map_err(|err| err.to_string())?;

        let mut best_remote = None::<MetadataRaftSyncRequest>;
        let mut last_error = None::<String>;
        let mut attempted = 0usize;

        for (peer_id, endpoint_raw) in endpoints {
            if peer_id == local_peer_id {
                continue;
            }
            let endpoint = endpoint_raw.trim().trim_end_matches('/');
            if !(endpoint.starts_with("http://") || endpoint.starts_with("https://")) {
                continue;
            }
            attempted += 1;
            let url = format!("{endpoint}/api/v1/internal/metadata-raft/export");
            match client
                .get(url)
                .header("x-rustio-internal-token", &internal_token)
                .send()
                .await
            {
                Ok(response) if response.status().is_success() => {
                    match response.json::<MetadataRaftSyncRequest>().await {
                        Ok(mut payload) => {
                            payload.peer_id = local_peer_id.clone();
                            payload.install_snapshot = true;
                            payload.prev_log_index = 0;
                            payload.prev_log_term = 0;
                            if payload.leader_commit == 0 {
                                payload.leader_commit = payload.entry.index;
                            }
                            if payload.entry.index <= current_index {
                                continue;
                            }
                            let replace = best_remote
                                .as_ref()
                                .map(|item| payload.entry.index > item.entry.index)
                                .unwrap_or(true);
                            if replace {
                                best_remote = Some(payload);
                            }
                        }
                        Err(err) => {
                            last_error = Some(bilingual_runtime_error(
                                "元数据 Raft 追平失败",
                                format!("decode remote raft snapshot failed: {err}"),
                            ));
                        }
                    }
                }
                Ok(response) => {
                    last_error = Some(bilingual_runtime_error(
                        "元数据 Raft 追平失败",
                        format!("remote raft export status: {}", response.status()),
                    ));
                }
                Err(err) => {
                    last_error = Some(bilingual_runtime_error(
                        "元数据 Raft 追平失败",
                        format!("remote raft export request failed: {err}"),
                    ));
                }
            }
        }

        if let Some(request) = best_remote {
            let response = self
                .apply_metadata_raft_snapshot_internal(request, true)
                .await?;
            if response.success {
                return Ok(());
            }
            return Err(bilingual_runtime_error(
                "元数据 Raft 追平被拒绝",
                response
                    .reason
                    .unwrap_or_else(|| "metadata raft catch-up rejected".to_string()),
            ));
        }

        if attempted == 0 {
            return Ok(());
        }
        if let Some(err) = last_error {
            return Err(err);
        }
        Ok(())
    }

    async fn process_metadata_raft_heartbeat_once(&self) -> Result<(), String> {
        if !Self::metadata_network_enabled() {
            return Ok(());
        }

        let local_peer_id = Self::metadata_local_peer_id();
        let (
            cluster_id,
            leader_id,
            term,
            commit_index,
            peers,
            last_heartbeat_at,
            last_election_at,
            last_quorum_at,
            local_online,
        ) = {
            let raft = self.metadata_raft.read().await;
            (
                raft.cluster_id.clone(),
                raft.leader_id.clone(),
                raft.term,
                raft.commit_index,
                raft.peers.clone(),
                raft.last_heartbeat_at,
                raft.last_election_at,
                raft.last_quorum_at,
                raft.peers
                    .iter()
                    .any(|peer| peer.id == local_peer_id && peer.online),
            )
        };

        if !local_online {
            return Ok(());
        }

        if leader_id == local_peer_id {
            let internal_token = Self::internal_control_token();
            let client = Client::builder()
                .timeout(std::time::Duration::from_secs(3))
                .build()
                .map_err(|err| err.to_string())?;
            let request = MetadataRaftHeartbeatRequest {
                cluster_id,
                leader_id: local_peer_id.clone(),
                term,
                leader_commit: commit_index,
            };

            let quorum = peers.len() / 2 + 1;
            let mut heartbeat_acks = 1usize;
            let mut max_term_seen = term;
            let mut last_error = None::<String>;
            for peer in peers {
                if !peer.online || peer.id == local_peer_id {
                    continue;
                }
                let Some(endpoint) = peer
                    .endpoint
                    .as_ref()
                    .map(|value| value.trim().to_string())
                    .filter(|value| !value.is_empty())
                else {
                    last_error = Some(bilingual_runtime_error(
                        "元数据 Raft 心跳失败",
                        format!("peer {} missing endpoint", peer.id),
                    ));
                    continue;
                };
                if !Self::metadata_peer_endpoint_valid(&endpoint) {
                    last_error = Some(bilingual_runtime_error(
                        "元数据 Raft 心跳失败",
                        format!("peer {} endpoint is invalid", peer.id),
                    ));
                    continue;
                }
                let url = format!(
                    "{}/api/v1/internal/metadata-raft/heartbeat",
                    endpoint.trim_end_matches('/')
                );
                match Self::send_metadata_raft_heartbeat_request(
                    &client,
                    &url,
                    &internal_token,
                    &request,
                )
                .await
                {
                    Ok(payload) => {
                        max_term_seen = max_term_seen.max(payload.term);
                        if payload.accepted {
                            heartbeat_acks += 1;
                        } else {
                            let reason = payload
                                .reason
                                .unwrap_or_else(|| "heartbeat rejected".to_string());
                            last_error = Some(bilingual_runtime_error(
                                "元数据 Raft 心跳失败",
                                format!("peer {} rejected heartbeat: {reason}", peer.id),
                            ));
                        }
                    }
                    Err(err) => {
                        last_error = Some(bilingual_runtime_error(
                            "元数据 Raft 心跳失败",
                            format!("peer {} heartbeat request failed: {err}", peer.id),
                        ));
                    }
                }
            }

            let mut raft = self.metadata_raft.write().await;
            if max_term_seen > raft.term {
                raft.term = max_term_seen;
                raft.voted_for = None;
                if raft.leader_id == local_peer_id {
                    raft.leader_id.clear();
                }
                raft.last_error = Some(bilingual_runtime_error(
                    "元数据 Raft leader 任期已过期",
                    format!(
                        "leader term {} is stale, observed higher term {}",
                        term, max_term_seen
                    ),
                ));
            } else {
                let now = Utc::now();
                let previous_quorum_at = raft.last_quorum_at.or(last_quorum_at).unwrap_or(now);
                raft.last_heartbeat_at = Some(now);
                if heartbeat_acks >= quorum {
                    raft.last_quorum_at = Some(now);
                    raft.last_error = None;
                } else {
                    let quorum_lost_for = now
                        .signed_duration_since(previous_quorum_at)
                        .to_std()
                        .unwrap_or_default();
                    if quorum_lost_for >= Self::metadata_election_timeout() {
                        if raft.leader_id == local_peer_id {
                            raft.leader_id.clear();
                            raft.voted_for = None;
                        }
                        raft.last_election_at = Some(now);
                        raft.last_error = Some(bilingual_runtime_error(
                            "元数据 Raft leader 丢失法定票数",
                            format!(
                                "metadata raft leader lost quorum: heartbeat acknowledgements {heartbeat_acks}/{quorum}"
                            ),
                        ));
                    } else {
                        raft.last_error = Some(last_error.unwrap_or_else(|| {
                            bilingual_runtime_error(
                                "元数据 Raft 心跳未达到法定票数",
                                format!(
                                    "heartbeat acknowledgements below quorum: {heartbeat_acks}/{quorum}"
                                ),
                            )
                        }));
                    }
                }
            }
            let raft_snapshot = raft.clone();
            drop(raft);
            self.persist_metadata_raft_state_inner(&raft_snapshot)?;
            return Ok(());
        }

        let now = Utc::now();
        let heartbeat_timed_out = last_heartbeat_at
            .and_then(|ts| now.signed_duration_since(ts).to_std().ok())
            .map(|elapsed| elapsed >= Self::metadata_election_timeout())
            .unwrap_or(true);
        let in_cooldown = last_election_at
            .and_then(|ts| now.signed_duration_since(ts).to_std().ok())
            .map(|elapsed| elapsed < Self::metadata_election_cooldown())
            .unwrap_or(false);
        if !heartbeat_timed_out || in_cooldown {
            return Ok(());
        }

        match self.elect_metadata_leader(&local_peer_id).await {
            Ok(_) => Ok(()),
            Err(err) => {
                let mut raft = self.metadata_raft.write().await;
                raft.last_error = Some(err.clone());
                let raft_snapshot = raft.clone();
                drop(raft);
                self.persist_metadata_raft_state_inner(&raft_snapshot)?;
                Err(err)
            }
        }
    }

    fn metadata_joint_elapsed_seconds(raft: &MetadataRaftState, now: DateTime<Utc>) -> Option<u64> {
        if raft.membership_phase != "joint" {
            return None;
        }
        let anchor = raft
            .last_commit_at
            .or(raft.last_heartbeat_at)
            .or(raft.last_election_at)?;
        let elapsed = now
            .signed_duration_since(anchor)
            .to_std()
            .unwrap_or_default()
            .as_secs();
        Some(elapsed)
    }

    fn metadata_raft_status_from_state(raft: &MetadataRaftState) -> MetadataRaftStatus {
        let now = Utc::now();
        let quorum = Self::metadata_membership_quorum(raft.peers.len());
        let online_peers = raft.peers.iter().filter(|peer| peer.online).count();
        MetadataRaftStatus {
            cluster_id: raft.cluster_id.clone(),
            leader_id: raft.leader_id.clone(),
            term: raft.term,
            commit_index: raft.commit_index,
            quorum,
            online_peers,
            last_error: raft.last_error.clone(),
            last_commit_at: raft.last_commit_at,
            membership_phase: raft.membership_phase.clone(),
            joint_old_members: Self::canonical_member_ids(raft.joint_old_members.clone()),
            joint_new_members: Self::canonical_member_ids(raft.joint_new_members.clone()),
            joint_elapsed_seconds: Self::metadata_joint_elapsed_seconds(raft, now),
            joint_timeout_seconds: Self::metadata_membership_change_timeout().as_secs(),
            peers: raft.peers.clone(),
        }
    }

    async fn process_metadata_membership_watchdog_once(&self) -> Result<(), String> {
        let now = Utc::now();
        let timeout = Self::metadata_membership_change_timeout();
        let timeout_secs = timeout.as_secs();
        let timeout_prefix = "元数据 Raft 成员变更超时，请执行 finalize 或 abort";
        let (joint_elapsed_secs, timeout_triggered) = {
            let mut raft = self.metadata_raft.write().await;
            let Some(elapsed_secs) = Self::metadata_joint_elapsed_seconds(&raft, now) else {
                if raft
                    .last_error
                    .as_deref()
                    .map(|message| message.contains(timeout_prefix))
                    .unwrap_or(false)
                {
                    raft.last_error = None;
                    let raft_snapshot = raft.clone();
                    drop(raft);
                    self.persist_metadata_raft_state_inner(&raft_snapshot)?;
                }
                return Self::resolve_membership_watchdog_alerts(&self.alert_history, now).await;
            };
            let elapsed = std::time::Duration::from_secs(elapsed_secs);
            if elapsed < timeout {
                (Some(elapsed_secs), false)
            } else {
                let timeout_error = bilingual_runtime_error(
                    timeout_prefix,
                    format!(
                        "metadata raft membership change timed out: joint elapsed {}s exceeds timeout {}s, please finalize or abort",
                        elapsed_secs, timeout_secs
                    ),
                );
                if raft.last_error.as_deref() != Some(timeout_error.as_str()) {
                    raft.last_error = Some(timeout_error);
                    let raft_snapshot = raft.clone();
                    drop(raft);
                    self.persist_metadata_raft_state_inner(&raft_snapshot)?;
                }
                (Some(elapsed_secs), true)
            }
        };
        if !timeout_triggered {
            return Ok(());
        }

        let mut history = self.alert_history.write().await;
        let already_firing = history.iter().any(|entry| {
            entry.source == "metadata-raft-membership-watchdog"
                && entry.status == "firing"
                && entry.resolved_at.is_none()
        });
        if already_firing {
            return Ok(());
        }
        history.push(AlertHistoryEntry {
            id: format!("history-{}", Uuid::new_v4().simple()),
            rule_id: None,
            rule_name: Some("元数据 Raft 成员变更超时".to_string()),
            severity: "warning".to_string(),
            status: "firing".to_string(),
            message: bilingual_runtime_error(
                "元数据 Raft 成员变更长时间处于 joint 阶段",
                "metadata raft membership change is stuck in joint phase",
            ),
            triggered_at: now,
            source: "metadata-raft-membership-watchdog".to_string(),
            assignee: None,
            claimed_at: None,
            acknowledged_by: None,
            acknowledged_at: None,
            resolved_by: None,
            resolved_at: None,
            details: json!({
                "membership_phase": "joint",
                "joint_elapsed_seconds": joint_elapsed_secs,
                "joint_timeout_seconds": timeout_secs,
            }),
        });
        Ok(())
    }

    async fn resolve_membership_watchdog_alerts(
        alert_history: &RwLock<Vec<AlertHistoryEntry>>,
        now: DateTime<Utc>,
    ) -> Result<(), String> {
        let mut history = alert_history.write().await;
        let mut changed = false;
        for entry in history.iter_mut() {
            if entry.source == "metadata-raft-membership-watchdog"
                && entry.status == "firing"
                && entry.resolved_at.is_none()
            {
                entry.status = "resolved".to_string();
                entry.resolved_by = Some("system".to_string());
                entry.resolved_at = Some(now);
                entry.message = bilingual_runtime_error(
                    "元数据 Raft 成员变更已恢复",
                    "metadata raft membership change recovered",
                );
                changed = true;
            }
        }
        if !changed {
            return Ok(());
        }
        Ok(())
    }

    pub async fn metadata_raft_status(&self) -> MetadataRaftStatus {
        let raft = self.metadata_raft.read().await;
        Self::metadata_raft_status_from_state(&raft)
    }

    fn verify_membership_quorum_available(raft: &MetadataRaftState) -> Result<(), String> {
        if let Some((old_members, new_members)) = Self::effective_joint_members(raft) {
            let old_quorum = Self::metadata_membership_quorum(old_members.len());
            let new_quorum = Self::metadata_membership_quorum(new_members.len());
            let old_online = Self::online_member_count(raft, &old_members);
            let new_online = Self::online_member_count(raft, &new_members);
            if old_online < old_quorum || new_online < new_quorum {
                return Err(format!(
                    "joint quorum unavailable: old {old_online}/{old_quorum}, new {new_online}/{new_quorum}"
                ));
            }
            return Ok(());
        }
        let quorum = Self::metadata_membership_quorum(raft.peers.len());
        let online = raft.peers.iter().filter(|peer| peer.online).count();
        if online < quorum {
            return Err(format!("quorum unavailable: {online}/{quorum}"));
        }
        Ok(())
    }

    pub async fn handle_metadata_read_index_request(
        &self,
        request: MetadataRaftReadIndexRequest,
    ) -> Result<MetadataRaftReadIndexResponse, String> {
        let request_id = request.request_id.trim().to_string();
        if !Self::metadata_read_index_request_id_valid(&request_id) {
            return Err(bilingual_runtime_error(
                "元数据 Raft 读索引请求 ID 无效",
                "invalid metadata raft read-index request id",
            ));
        }
        let local_peer_id = Self::metadata_local_peer_id();
        let mut raft = self.metadata_raft.write().await;
        if raft.cluster_id != request.cluster_id {
            return Err(bilingual_runtime_error(
                "元数据 Raft 集群标识不匹配",
                format!(
                    "metadata raft cluster mismatch: expected {}, got {}",
                    raft.cluster_id, request.cluster_id
                ),
            ));
        }
        if !Self::local_peer_in_membership(&raft, &local_peer_id) {
            return Ok(MetadataRaftReadIndexResponse {
                term: raft.term,
                leader_id: raft.leader_id.clone(),
                read_index: raft.commit_index,
                success: false,
                request_id,
                members: Self::canonical_member_ids(
                    raft.peers.iter().map(|peer| peer.id.clone()).collect(),
                ),
                reason: Some("local peer not in membership".to_string()),
            });
        }

        if raft.leader_id != local_peer_id {
            return Ok(MetadataRaftReadIndexResponse {
                term: raft.term,
                leader_id: raft.leader_id.clone(),
                read_index: raft.commit_index,
                success: false,
                request_id,
                members: Self::canonical_member_ids(
                    raft.peers.iter().map(|peer| peer.id.clone()).collect(),
                ),
                reason: Some("not leader".to_string()),
            });
        }

        if let Err(reason) = Self::verify_membership_quorum_available(&raft) {
            raft.last_error = Some(bilingual_runtime_error(
                "元数据 Raft 读索引失败",
                format!("metadata raft read-index quorum unavailable: {reason}"),
            ));
            let response = MetadataRaftReadIndexResponse {
                term: raft.term,
                leader_id: raft.leader_id.clone(),
                read_index: raft.commit_index,
                success: false,
                request_id,
                members: Self::canonical_member_ids(
                    raft.peers.iter().map(|peer| peer.id.clone()).collect(),
                ),
                reason: Some(reason),
            };
            let raft_snapshot = raft.clone();
            drop(raft);
            self.persist_metadata_raft_state_inner(&raft_snapshot)?;
            return Ok(response);
        }

        let now = Utc::now();
        let quorum_fresh = raft
            .last_quorum_at
            .and_then(|ts| now.signed_duration_since(ts).to_std().ok())
            .map(|elapsed| elapsed < Self::metadata_election_timeout())
            .unwrap_or(false);
        if !quorum_fresh {
            let reason = "quorum heartbeat is stale".to_string();
            raft.last_error = Some(bilingual_runtime_error(
                "元数据 Raft 读索引失败",
                format!("metadata raft read-index rejected: {reason}"),
            ));
            let response = MetadataRaftReadIndexResponse {
                term: raft.term,
                leader_id: raft.leader_id.clone(),
                read_index: raft.commit_index,
                success: false,
                request_id,
                members: Self::canonical_member_ids(
                    raft.peers.iter().map(|peer| peer.id.clone()).collect(),
                ),
                reason: Some(reason),
            };
            let raft_snapshot = raft.clone();
            drop(raft);
            self.persist_metadata_raft_state_inner(&raft_snapshot)?;
            return Ok(response);
        }

        raft.last_quorum_at = Some(now);
        raft.last_heartbeat_at = Some(now);
        raft.last_error = None;
        let response = MetadataRaftReadIndexResponse {
            term: raft.term,
            leader_id: raft.leader_id.clone(),
            read_index: raft.commit_index,
            success: true,
            request_id,
            members: Self::canonical_member_ids(
                raft.peers.iter().map(|peer| peer.id.clone()).collect(),
            ),
            reason: None,
        };
        let raft_snapshot = raft.clone();
        drop(raft);
        self.persist_metadata_raft_state_inner(&raft_snapshot)?;
        Ok(response)
    }

    pub async fn metadata_read_index(&self) -> Result<MetadataRaftReadIndexResponse, String> {
        let request_id = format!("readidx-{}", Uuid::new_v4().simple());
        if !Self::metadata_network_enabled() {
            let raft = self.metadata_raft.read().await;
            return Ok(MetadataRaftReadIndexResponse {
                term: raft.term,
                leader_id: raft.leader_id.clone(),
                read_index: raft.commit_index,
                success: true,
                request_id,
                members: Self::canonical_member_ids(
                    raft.peers.iter().map(|peer| peer.id.clone()).collect(),
                ),
                reason: None,
            });
        }

        let local_peer_id = Self::metadata_local_peer_id();
        let (cluster_id, leader_id, term, leader_endpoint, probe_targets, local_member) = {
            let raft = self.metadata_raft.read().await;
            let mut targets = Vec::new();
            for peer in raft.peers.iter().filter(|peer| peer.id != local_peer_id) {
                if let Some(endpoint) = Self::metadata_peer_endpoint_from_raft(&raft, &peer.id) {
                    targets.push((peer.id.clone(), endpoint));
                }
            }
            (
                raft.cluster_id.clone(),
                raft.leader_id.clone(),
                raft.term,
                if raft.leader_id == local_peer_id {
                    None
                } else {
                    Self::metadata_peer_endpoint_from_raft(&raft, &raft.leader_id)
                },
                targets,
                raft.peers.iter().any(|peer| peer.id == local_peer_id),
            )
        };

        if !local_member {
            return Err(bilingual_runtime_error(
                "当前节点不在元数据 Raft 成员集合中",
                "local peer is not in metadata raft membership",
            ));
        }

        if leader_id == local_peer_id {
            let payload = self
                .handle_metadata_read_index_request(MetadataRaftReadIndexRequest {
                    cluster_id,
                    requester_id: local_peer_id,
                    request_id,
                })
                .await?;
            if payload.success {
                return Ok(payload);
            }
            return Err(bilingual_runtime_error(
                "元数据 Raft 读索引失败",
                payload
                    .reason
                    .unwrap_or_else(|| "metadata raft read-index rejected".to_string()),
            ));
        }

        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(4))
            .build()
            .map_err(|err| err.to_string())?;
        let request = MetadataRaftReadIndexRequest {
            cluster_id,
            requester_id: local_peer_id.clone(),
            request_id,
        };
        let mut last_probe_error = None::<String>;

        if !leader_id.trim().is_empty() {
            if let Some(endpoint) = leader_endpoint.map(|value| value.trim().to_string()) {
                match self
                    .request_metadata_read_index_from_endpoint(
                        &client, &request, &leader_id, &endpoint, term,
                    )
                    .await
                {
                    Ok(payload) => return Ok(payload),
                    Err(err) => last_probe_error = Some(err),
                }
            } else {
                last_probe_error = Some(bilingual_runtime_error(
                    "元数据 Raft leader endpoint 缺失",
                    format!("metadata raft leader {} endpoint is missing", leader_id),
                ));
            }
        }

        for (peer_id, endpoint) in probe_targets {
            match self
                .request_metadata_read_index_from_endpoint(
                    &client, &request, &peer_id, &endpoint, term,
                )
                .await
            {
                Ok(payload) => return Ok(payload),
                Err(err) => last_probe_error = Some(err),
            }
        }

        Err(bilingual_runtime_error(
            "当前无可用元数据 Raft leader",
            last_probe_error.unwrap_or_else(|| "metadata raft leader unavailable".to_string()),
        ))
    }

    async fn request_metadata_read_index_from_endpoint(
        &self,
        client: &Client,
        request: &MetadataRaftReadIndexRequest,
        leader_id_hint: &str,
        endpoint: &str,
        local_term: u64,
    ) -> Result<MetadataRaftReadIndexResponse, String> {
        if !Self::metadata_peer_endpoint_valid(endpoint) {
            return Err(bilingual_runtime_error(
                "元数据 Raft leader endpoint 无效",
                format!(
                    "metadata raft leader {} endpoint is invalid",
                    leader_id_hint
                ),
            ));
        }
        let url = format!(
            "{}/api/v1/internal/metadata-raft/read-index",
            endpoint.trim_end_matches('/')
        );
        let payload = Self::send_metadata_raft_read_index_request(
            client,
            &url,
            &Self::internal_control_token(),
            request,
        )
        .await
        .map_err(|err| {
            bilingual_runtime_error(
                "元数据 Raft 读索引失败",
                format!("read-index request failed: {err}"),
            )
        })?;
        if !payload.success {
            return Err(bilingual_runtime_error(
                "元数据 Raft 读索引失败",
                payload
                    .reason
                    .clone()
                    .unwrap_or_else(|| "metadata raft read-index rejected".to_string()),
            ));
        }
        if payload.request_id != request.request_id {
            return Err(bilingual_runtime_error(
                "元数据 Raft 读索引响应 ID 不匹配",
                format!(
                    "read-index response request id mismatch: expected {}, got {}",
                    request.request_id, payload.request_id
                ),
            ));
        }
        if !payload.members.is_empty()
            && !payload
                .members
                .iter()
                .any(|member_id| member_id == &request.requester_id)
        {
            let _ = self
                .mark_local_peer_removed_from_membership(
                    &payload.leader_id,
                    payload.term,
                    &payload.members,
                )
                .await;
            return Err(bilingual_runtime_error(
                "当前节点不在元数据 Raft 成员集合中",
                format!(
                    "local peer {} is not in leader membership set",
                    request.requester_id
                ),
            ));
        }
        if payload.term < local_term {
            return Err(bilingual_runtime_error(
                "元数据 Raft 读索引失败",
                format!(
                    "read-index leader term is stale: local={}, remote={}",
                    local_term, payload.term
                ),
            ));
        }
        self.catchup_metadata_to_read_index(payload.read_index)
            .await?;
        Ok(payload)
    }

    async fn catchup_metadata_to_read_index(&self, required_read_index: u64) -> Result<(), String> {
        let local_commit = self.metadata_raft.read().await.commit_index;
        if local_commit >= required_read_index {
            return Ok(());
        }
        for _ in 0..6 {
            let _ = self.catchup_metadata_raft_from_remote_peers().await;
            let current_commit = self.metadata_raft.read().await.commit_index;
            if current_commit >= required_read_index {
                return Ok(());
            }
            tokio::time::sleep(std::time::Duration::from_millis(120)).await;
        }
        Err(bilingual_runtime_error(
            "元数据 Raft 读索引追平失败",
            format!(
                "metadata read-index catch-up not reached: local_commit={}, required={}",
                self.metadata_raft.read().await.commit_index,
                required_read_index
            ),
        ))
    }

    async fn mark_local_peer_removed_from_membership(
        &self,
        leader_id: &str,
        leader_term: u64,
        members: &[String],
    ) -> Result<(), String> {
        let local_peer_id = Self::metadata_local_peer_id();
        if members.iter().any(|member| member == &local_peer_id) {
            return Ok(());
        }

        let raft_snapshot = {
            let mut raft = self.metadata_raft.write().await;
            let mut changed = false;
            let original_len = raft.peers.len();
            raft.peers.retain(|peer| peer.id != local_peer_id);
            if raft.peers.len() != original_len {
                changed = true;
            }
            let leader_id = leader_id.trim();
            if !leader_id.is_empty() && raft.leader_id != leader_id {
                raft.leader_id = leader_id.to_string();
                changed = true;
            }
            if leader_term > raft.term {
                raft.term = leader_term;
                raft.voted_for = None;
                changed = true;
            }
            if raft.voted_for.as_deref() == Some(local_peer_id.as_str()) {
                raft.voted_for = None;
                changed = true;
            }
            if raft.membership_phase != "stable" {
                raft.membership_phase = "stable".to_string();
                raft.joint_old_members.clear();
                raft.joint_new_members.clear();
                changed = true;
            }
            let local_removed_error = bilingual_runtime_error(
                "当前节点已被移出元数据 Raft 成员集合",
                "local peer has been removed from metadata raft membership",
            );
            if raft.last_error.as_deref() != Some(local_removed_error.as_str()) {
                raft.last_error = Some(local_removed_error);
                changed = true;
            }
            changed.then(|| raft.clone())
        };
        if let Some(raft_snapshot) = raft_snapshot {
            self.persist_metadata_raft_state_inner(&raft_snapshot)?;
        }
        Ok(())
    }

    fn metadata_peer_id_valid(peer_id: &str) -> bool {
        !peer_id.is_empty()
            && peer_id
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
    }

    fn metadata_read_index_request_id_valid(request_id: &str) -> bool {
        !request_id.is_empty()
            && request_id.len() <= 96
            && request_id
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
    }

    fn metadata_peer_endpoint_valid(endpoint: &str) -> bool {
        let value = endpoint.trim();
        value.starts_with("http://") || value.starts_with("https://")
    }

    fn metadata_peer_endpoint_from_raft(raft: &MetadataRaftState, peer_id: &str) -> Option<String> {
        let endpoint_from_state = raft
            .peers
            .iter()
            .find(|peer| peer.id == peer_id)
            .and_then(|peer| peer.endpoint.clone())
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
        if endpoint_from_state.is_some() {
            return endpoint_from_state;
        }
        Self::metadata_peer_endpoints().get(peer_id).cloned()
    }

    fn canonical_member_ids(ids: Vec<String>) -> Vec<String> {
        let mut seen = HashSet::new();
        let mut members = ids
            .into_iter()
            .filter(|id| !id.trim().is_empty())
            .filter(|id| seen.insert(id.clone()))
            .collect::<Vec<_>>();
        members.sort();
        members
    }

    fn local_peer_in_membership(raft: &MetadataRaftState, local_peer_id: &str) -> bool {
        raft.peers.iter().any(|peer| peer.id == local_peer_id)
    }

    fn metadata_membership_quorum(member_count: usize) -> usize {
        member_count / 2 + 1
    }

    fn effective_joint_members(raft: &MetadataRaftState) -> Option<(Vec<String>, Vec<String>)> {
        if raft.membership_phase != "joint" {
            return None;
        }
        let old_members = Self::canonical_member_ids(raft.joint_old_members.clone());
        let new_members = Self::canonical_member_ids(raft.joint_new_members.clone());
        if old_members.is_empty() || new_members.is_empty() {
            return None;
        }
        Some((old_members, new_members))
    }

    fn online_member_count(raft: &MetadataRaftState, members: &[String]) -> usize {
        let member_set = members.iter().collect::<HashSet<_>>();
        raft.peers
            .iter()
            .filter(|peer| peer.online && member_set.contains(&peer.id))
            .count()
    }

    fn quorum_commit_index_for_members(raft: &MetadataRaftState, members: &[String]) -> u64 {
        let member_set = members.iter().collect::<HashSet<_>>();
        let mut indexes = raft
            .peers
            .iter()
            .filter(|peer| peer.online && member_set.contains(&peer.id))
            .map(|peer| peer.match_index)
            .collect::<Vec<_>>();
        indexes.sort_unstable_by(|left, right| right.cmp(left));
        let quorum = Self::metadata_membership_quorum(members.len());
        indexes.get(quorum.saturating_sub(1)).copied().unwrap_or(0)
    }

    fn elect_metadata_raft_leader_if_needed(raft: &mut MetadataRaftState) {
        let leader_online = raft
            .peers
            .iter()
            .any(|peer| peer.id == raft.leader_id && peer.online);
        if leader_online {
            return;
        }
        let mut candidates = raft
            .peers
            .iter()
            .filter(|peer| peer.online)
            .collect::<Vec<_>>();
        candidates.sort_by(|left, right| {
            right
                .last_index
                .cmp(&left.last_index)
                .then_with(|| left.id.cmp(&right.id))
        });
        if let Some(candidate) = candidates.first() {
            if raft.leader_id != candidate.id {
                raft.leader_id = candidate.id.clone();
                raft.term = raft.term.saturating_add(1);
                raft.voted_for = None;
            }
        }
    }

    pub async fn set_metadata_peer_state(
        &self,
        peer_id: &str,
        online: bool,
    ) -> Result<MetadataRaftStatus, String> {
        let mut raft = self.metadata_raft.write().await;
        let Some(peer) = raft.peers.iter_mut().find(|item| item.id == peer_id) else {
            return Err(bilingual_runtime_error(
                "未找到元数据 Raft 节点",
                "metadata raft peer not found",
            ));
        };
        peer.online = online;
        Self::elect_metadata_raft_leader_if_needed(&mut raft);
        let status = Self::metadata_raft_status_from_state(&raft);
        let raft_snapshot = raft.clone();
        drop(raft);
        self.persist_metadata_raft_state_inner(&raft_snapshot)?;
        Ok(status)
    }

    pub async fn abort_metadata_membership_change(&self) -> Result<MetadataRaftStatus, String> {
        let local_peer_id = Self::metadata_local_peer_id();
        let network_enabled = Self::metadata_network_enabled();
        let (abort_snapshot, rollback_snapshot) = {
            let mut raft = self.metadata_raft.write().await;
            if raft.membership_phase != "joint" {
                return Err(bilingual_runtime_error(
                    "当前无进行中的元数据 Raft joint-consensus 变更",
                    "no metadata raft joint-consensus change in progress",
                ));
            }
            if !Self::local_peer_in_membership(&raft, &local_peer_id) {
                return Err(bilingual_runtime_error(
                    "当前节点不在元数据 Raft 成员集合中",
                    "local peer is not in metadata raft membership",
                ));
            }
            if network_enabled && raft.leader_id != local_peer_id {
                return Err(bilingual_runtime_error(
                    "仅 Raft leader 可中止成员变更",
                    format!(
                        "metadata raft membership abort must be issued on leader {}, local peer is {}",
                        raft.leader_id, local_peer_id
                    ),
                ));
            }

            let old_members = Self::canonical_member_ids(raft.joint_old_members.clone());
            if old_members.is_empty() {
                return Err(bilingual_runtime_error(
                    "joint-consensus 旧成员集合为空，无法中止",
                    "joint-consensus old membership set is empty and cannot be aborted",
                ));
            }

            let rollback_snapshot = raft.clone();
            let mut merged_peers = old_members
                .iter()
                .map(|member_id| {
                    if let Some(existing) = raft.peers.iter().find(|peer| &peer.id == member_id) {
                        return existing.clone();
                    }
                    let peer_path = Self::metadata_raft_root_dir(&self.data_dir).join(member_id);
                    let _ = std::fs::create_dir_all(&peer_path);
                    MetadataRaftPeer {
                        id: member_id.clone(),
                        path: peer_path,
                        endpoint: Self::metadata_peer_endpoints().get(member_id).cloned(),
                        online: false,
                        match_index: raft.commit_index,
                        next_index: raft.commit_index.saturating_add(1),
                        last_index: raft.commit_index,
                    }
                })
                .collect::<Vec<_>>();
            merged_peers.sort_by(|left, right| left.id.cmp(&right.id));

            raft.peers = merged_peers;
            raft.membership_phase = "stable".to_string();
            raft.joint_old_members.clear();
            raft.joint_new_members.clear();
            Self::elect_metadata_raft_leader_if_needed(&mut raft);
            raft.last_error = None;
            (raft.clone(), rollback_snapshot)
        };
        self.persist_metadata_raft_state_inner(&abort_snapshot)?;

        if let Err(err) = self.sync_metadata_raft("peer-joint-abort").await {
            let rollback_snapshot = {
                let mut raft = self.metadata_raft.write().await;
                *raft = rollback_snapshot.clone();
                raft.last_error = Some(bilingual_runtime_error(
                    "元数据 Raft 成员变更中止失败",
                    format!("metadata raft membership abort failed: {err}"),
                ));
                raft.clone()
            };
            let _ = self.persist_metadata_raft_state_inner(&rollback_snapshot);
            return Err(bilingual_runtime_error(
                "元数据 Raft 成员变更中止失败",
                format!("metadata raft membership abort failed: {err}"),
            ));
        }

        Ok(self.metadata_raft_status().await)
    }

    pub async fn finalize_metadata_membership_change(&self) -> Result<MetadataRaftStatus, String> {
        let local_peer_id = Self::metadata_local_peer_id();
        let network_enabled = Self::metadata_network_enabled();
        let (finalize_snapshot, rollback_snapshot) = {
            let mut raft = self.metadata_raft.write().await;
            if raft.membership_phase != "joint" {
                return Err(bilingual_runtime_error(
                    "当前无进行中的元数据 Raft joint-consensus 变更",
                    "no metadata raft joint-consensus change in progress",
                ));
            }
            if !Self::local_peer_in_membership(&raft, &local_peer_id) {
                return Err(bilingual_runtime_error(
                    "当前节点不在元数据 Raft 成员集合中",
                    "local peer is not in metadata raft membership",
                ));
            }
            if network_enabled && raft.leader_id != local_peer_id {
                return Err(bilingual_runtime_error(
                    "仅 Raft leader 可完成成员变更",
                    format!(
                        "metadata raft membership finalize must be issued on leader {}, local peer is {}",
                        raft.leader_id, local_peer_id
                    ),
                ));
            }

            let new_members = Self::canonical_member_ids(raft.joint_new_members.clone());
            if new_members.is_empty() {
                return Err(bilingual_runtime_error(
                    "joint-consensus 新成员集合为空，无法完成",
                    "joint-consensus new membership set is empty and cannot be finalized",
                ));
            }

            let rollback_snapshot = raft.clone();
            let mut merged_peers = new_members
                .iter()
                .map(|member_id| {
                    if let Some(existing) = raft.peers.iter().find(|peer| &peer.id == member_id) {
                        return existing.clone();
                    }
                    let peer_path = Self::metadata_raft_root_dir(&self.data_dir).join(member_id);
                    let _ = std::fs::create_dir_all(&peer_path);
                    MetadataRaftPeer {
                        id: member_id.clone(),
                        path: peer_path,
                        endpoint: Self::metadata_peer_endpoints().get(member_id).cloned(),
                        online: false,
                        match_index: raft.commit_index,
                        next_index: raft.commit_index.saturating_add(1),
                        last_index: raft.commit_index,
                    }
                })
                .collect::<Vec<_>>();
            merged_peers.sort_by(|left, right| left.id.cmp(&right.id));

            raft.peers = merged_peers;
            raft.membership_phase = "stable".to_string();
            raft.joint_old_members.clear();
            raft.joint_new_members.clear();
            Self::elect_metadata_raft_leader_if_needed(&mut raft);
            raft.last_error = None;
            (raft.clone(), rollback_snapshot)
        };
        self.persist_metadata_raft_state_inner(&finalize_snapshot)?;

        if let Err(err) = self.sync_metadata_raft("peer-joint-manual-finalize").await {
            let rollback_snapshot = {
                let mut raft = self.metadata_raft.write().await;
                *raft = rollback_snapshot.clone();
                raft.last_error = Some(bilingual_runtime_error(
                    "元数据 Raft 成员变更完成失败",
                    format!("metadata raft membership finalize failed: {err}"),
                ));
                raft.clone()
            };
            let _ = self.persist_metadata_raft_state_inner(&rollback_snapshot);
            return Err(bilingual_runtime_error(
                "元数据 Raft 成员变更完成失败",
                format!("metadata raft membership finalize failed: {err}"),
            ));
        }

        Ok(self.metadata_raft_status().await)
    }

    pub async fn add_metadata_peer(
        &self,
        peer_id: &str,
        endpoint: Option<String>,
        online: bool,
        auto_finalize: bool,
    ) -> Result<MetadataRaftStatus, String> {
        let id = peer_id.trim();
        if !Self::metadata_peer_id_valid(id) {
            return Err(bilingual_runtime_error(
                "元数据 Raft 节点 ID 无效",
                "invalid metadata raft peer id",
            ));
        }
        let endpoint = endpoint
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
        if let Some(value) = endpoint.as_ref() {
            if !Self::metadata_peer_endpoint_valid(value) {
                return Err(bilingual_runtime_error(
                    "元数据 Raft 节点 endpoint 无效",
                    "invalid metadata raft peer endpoint",
                ));
            }
        }
        let start_snapshot = {
            let mut raft = self.metadata_raft.write().await;
            if raft.membership_phase == "joint" {
                return Err(bilingual_runtime_error(
                    "已有元数据 Raft 成员变更进行中",
                    "metadata raft joint-consensus change already in progress",
                ));
            }
            if raft.peers.iter().any(|peer| peer.id == id) {
                return Err(bilingual_runtime_error(
                    "元数据 Raft 节点已存在",
                    "metadata raft peer already exists",
                ));
            }

            let old_members = Self::canonical_member_ids(
                raft.peers
                    .iter()
                    .map(|peer| peer.id.clone())
                    .collect::<Vec<_>>(),
            );
            let peer_path = Self::metadata_raft_root_dir(&self.data_dir).join(id);
            std::fs::create_dir_all(&peer_path).map_err(|err| err.to_string())?;
            let commit_index = raft.commit_index;
            raft.peers.push(MetadataRaftPeer {
                id: id.to_string(),
                path: peer_path,
                endpoint,
                online,
                match_index: commit_index,
                next_index: commit_index.saturating_add(1),
                last_index: commit_index,
            });
            raft.peers.sort_by(|left, right| left.id.cmp(&right.id));
            let new_members = Self::canonical_member_ids(
                raft.peers
                    .iter()
                    .map(|peer| peer.id.clone())
                    .collect::<Vec<_>>(),
            );

            let old_quorum = Self::metadata_membership_quorum(old_members.len());
            let new_quorum = Self::metadata_membership_quorum(new_members.len());
            let old_online = Self::online_member_count(&raft, &old_members);
            let new_online = Self::online_member_count(&raft, &new_members);
            if old_online < old_quorum || new_online < new_quorum {
                raft.peers.retain(|peer| peer.id != id);
                return Err(bilingual_runtime_error(
                    "新增后无法满足 joint-consensus 法定票数",
                    format!(
                        "joint membership quorum would be invalid after add: old {old_online}/{old_quorum}, new {new_online}/{new_quorum}"
                    ),
                ));
            }

            raft.membership_phase = "joint".to_string();
            raft.joint_old_members = old_members;
            raft.joint_new_members = new_members;
            raft.last_error = None;
            raft.clone()
        };
        self.persist_metadata_raft_state_inner(&start_snapshot)?;

        if let Err(err) = self.sync_metadata_raft("peer-add-joint-start").await {
            let rollback_snapshot = {
                let mut raft = self.metadata_raft.write().await;
                raft.peers.retain(|peer| peer.id != id);
                raft.membership_phase = "stable".to_string();
                raft.joint_old_members.clear();
                raft.joint_new_members.clear();
                raft.last_error = Some(err.clone());
                raft.clone()
            };
            let _ = self.persist_metadata_raft_state_inner(&rollback_snapshot);
            return Err(err);
        }
        if !auto_finalize {
            return Ok(self.metadata_raft_status().await);
        }

        let (finalize_snapshot, rollback_joint_snapshot) = {
            let mut raft = self.metadata_raft.write().await;
            if !raft.peers.iter().any(|peer| peer.id == id) {
                return Err(bilingual_runtime_error(
                    "元数据 Raft 节点不存在",
                    "metadata raft peer not found when finalizing add",
                ));
            }
            let rollback_snapshot = raft.clone();
            raft.membership_phase = "stable".to_string();
            raft.joint_old_members.clear();
            raft.joint_new_members.clear();
            Self::elect_metadata_raft_leader_if_needed(&mut raft);
            raft.last_error = None;
            (raft.clone(), rollback_snapshot)
        };
        self.persist_metadata_raft_state_inner(&finalize_snapshot)?;

        if let Err(err) = self.sync_metadata_raft("peer-add-joint-finalize").await {
            let rollback_snapshot = {
                let mut raft = self.metadata_raft.write().await;
                *raft = rollback_joint_snapshot.clone();
                raft.last_error = Some(bilingual_runtime_error(
                    "元数据 Raft 成员变更 finalize 失败，已回滚到 joint 阶段",
                    format!("peer-add finalize failed and rolled back to joint phase: {err}"),
                ));
                raft.clone()
            };
            let _ = self.persist_metadata_raft_state_inner(&rollback_snapshot);
            let _ = self.sync_metadata_raft("peer-add-joint-rollback").await;
            return Err(bilingual_runtime_error(
                "元数据 Raft 成员变更 finalize 失败",
                format!("peer-add joint-finalize failed: {err}"),
            ));
        }

        Ok(self.metadata_raft_status().await)
    }

    pub async fn remove_metadata_peer(
        &self,
        peer_id: &str,
        auto_finalize: bool,
    ) -> Result<MetadataRaftStatus, String> {
        let id = peer_id.trim();
        if id.is_empty() {
            return Err(bilingual_runtime_error(
                "元数据 Raft 节点 ID 不能为空",
                "metadata raft peer id cannot be empty",
            ));
        }
        let local_peer = Self::metadata_local_peer_id();
        if id == local_peer {
            return Err(bilingual_runtime_error(
                "不允许移除本地元数据 Raft 节点",
                "cannot remove local metadata raft peer",
            ));
        }
        let start_snapshot = {
            let mut raft = self.metadata_raft.write().await;
            if raft.membership_phase == "joint" {
                return Err(bilingual_runtime_error(
                    "已有元数据 Raft 成员变更进行中",
                    "metadata raft joint-consensus change already in progress",
                ));
            }
            if raft.peers.len() <= 1 {
                return Err(bilingual_runtime_error(
                    "至少保留一个元数据 Raft 节点",
                    "at least one metadata raft peer is required",
                ));
            }
            if !raft.peers.iter().any(|peer| peer.id == id) {
                return Err(bilingual_runtime_error(
                    "未找到元数据 Raft 节点",
                    "metadata raft peer not found",
                ));
            }

            let old_members = Self::canonical_member_ids(
                raft.peers
                    .iter()
                    .map(|peer| peer.id.clone())
                    .collect::<Vec<_>>(),
            );
            let new_members = Self::canonical_member_ids(
                raft.peers
                    .iter()
                    .filter(|peer| peer.id != id)
                    .map(|peer| peer.id.clone())
                    .collect::<Vec<_>>(),
            );
            if new_members.is_empty() {
                return Err(bilingual_runtime_error(
                    "至少保留一个元数据 Raft 节点",
                    "at least one metadata raft peer is required",
                ));
            }

            let old_quorum = Self::metadata_membership_quorum(old_members.len());
            let new_quorum = Self::metadata_membership_quorum(new_members.len());
            let old_online = Self::online_member_count(&raft, &old_members);
            let new_online = Self::online_member_count(&raft, &new_members);
            if old_online < old_quorum || new_online < new_quorum {
                return Err(bilingual_runtime_error(
                    "移除后无法满足 joint-consensus 法定票数",
                    format!(
                        "joint membership quorum would be invalid after remove: old {old_online}/{old_quorum}, new {new_online}/{new_quorum}"
                    ),
                ));
            }

            raft.membership_phase = "joint".to_string();
            raft.joint_old_members = old_members;
            raft.joint_new_members = new_members;
            raft.last_error = None;
            raft.clone()
        };
        self.persist_metadata_raft_state_inner(&start_snapshot)?;

        if let Err(err) = self.sync_metadata_raft("peer-remove-joint-start").await {
            let rollback_snapshot = {
                let mut raft = self.metadata_raft.write().await;
                raft.membership_phase = "stable".to_string();
                raft.joint_old_members.clear();
                raft.joint_new_members.clear();
                raft.last_error = Some(err.clone());
                raft.clone()
            };
            let _ = self.persist_metadata_raft_state_inner(&rollback_snapshot);
            return Err(err);
        }
        if !auto_finalize {
            return Ok(self.metadata_raft_status().await);
        }

        let (finalize_snapshot, rollback_joint_snapshot) = {
            let mut raft = self.metadata_raft.write().await;
            let Some(index) = raft.peers.iter().position(|peer| peer.id == id) else {
                return Err(bilingual_runtime_error(
                    "未找到元数据 Raft 节点",
                    "metadata raft peer not found",
                ));
            };
            let rollback_snapshot = raft.clone();
            raft.peers.remove(index);
            raft.membership_phase = "stable".to_string();
            raft.joint_old_members.clear();
            raft.joint_new_members.clear();
            Self::elect_metadata_raft_leader_if_needed(&mut raft);
            raft.last_error = None;
            (raft.clone(), rollback_snapshot)
        };
        self.persist_metadata_raft_state_inner(&finalize_snapshot)?;

        if let Err(err) = self.sync_metadata_raft("peer-remove-joint-finalize").await {
            let rollback_snapshot = {
                let mut raft = self.metadata_raft.write().await;
                *raft = rollback_joint_snapshot.clone();
                raft.last_error = Some(bilingual_runtime_error(
                    "元数据 Raft 成员变更 finalize 失败，已回滚到 joint 阶段",
                    format!("peer-remove finalize failed and rolled back to joint phase: {err}"),
                ));
                raft.clone()
            };
            let _ = self.persist_metadata_raft_state_inner(&rollback_snapshot);
            let _ = self.sync_metadata_raft("peer-remove-joint-rollback").await;
            return Err(bilingual_runtime_error(
                "元数据 Raft 成员变更 finalize 失败",
                format!("peer-remove joint-finalize failed: {err}"),
            ));
        }

        Ok(self.metadata_raft_status().await)
    }

    pub async fn elect_metadata_leader(
        &self,
        candidate_id: &str,
    ) -> Result<MetadataRaftStatus, String> {
        let candidate = candidate_id.trim();
        if candidate.is_empty() {
            return Err(bilingual_runtime_error(
                "候选节点不能为空",
                "raft election candidate cannot be empty",
            ));
        }
        let local_peer = Self::metadata_local_peer_id();
        let network_enabled = Self::metadata_network_enabled();
        if network_enabled && candidate != local_peer {
            return Err(bilingual_runtime_error(
                "请在候选节点本机发起选主",
                "in network mode election must be requested on candidate node",
            ));
        }

        let (cluster_id, term, quorum, candidate_last_index, candidate_last_term, peers) = {
            let raft = self.metadata_raft.read().await;
            let Some(candidate_peer) = raft.peers.iter().find(|peer| peer.id == candidate) else {
                return Err(bilingual_runtime_error(
                    "未找到候选元数据 Raft 节点",
                    "candidate metadata raft peer not found",
                ));
            };
            if !candidate_peer.online {
                return Err(bilingual_runtime_error(
                    "候选元数据 Raft 节点不在线",
                    "candidate metadata raft peer is offline",
                ));
            }
            let quorum = raft.peers.len() / 2 + 1;
            let online_peers = raft.peers.iter().filter(|item| item.online).count();
            if online_peers < quorum {
                return Err(bilingual_runtime_error(
                    "当前在线节点不足法定票数",
                    format!("online peers below quorum: {online_peers}/{quorum}"),
                ));
            }
            let max_online_index = raft
                .peers
                .iter()
                .filter(|peer| peer.online)
                .map(|peer| peer.last_index)
                .max()
                .unwrap_or(0);
            if candidate_peer.last_index < max_online_index {
                return Err(bilingual_runtime_error(
                    "候选节点日志落后，拒绝选主",
                    format!(
                        "candidate peer log is stale: {} < {}",
                        candidate_peer.last_index, max_online_index
                    ),
                ));
            }
            let last_commit_term = if raft.last_commit_term == 0 && raft.commit_index > 0 {
                raft.term
            } else {
                raft.last_commit_term
            };
            (
                raft.cluster_id.clone(),
                raft.term,
                quorum,
                raft.commit_index.max(candidate_peer.last_index),
                last_commit_term,
                raft.peers.clone(),
            )
        };

        if !network_enabled {
            let mut raft = self.metadata_raft.write().await;
            let now = Utc::now();
            if raft.leader_id != candidate {
                raft.leader_id = candidate.to_string();
                raft.term = raft.term.saturating_add(1);
                raft.voted_for = Some(candidate.to_string());
                raft.last_commit_at = Some(now);
                raft.last_error = None;
            }
            raft.last_election_at = Some(now);
            if candidate == local_peer {
                raft.last_heartbeat_at = Some(now);
            }
            raft.last_quorum_at = Some(now);
            let status = Self::metadata_raft_status_from_state(&raft);
            let raft_snapshot = raft.clone();
            drop(raft);
            self.persist_metadata_raft_state_inner(&raft_snapshot)?;
            return Ok(status);
        }

        let pre_vote_term = term.saturating_add(1);
        let mut pre_votes = 1usize;
        let mut max_term_seen = term;
        let mut last_error = None::<String>;
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .map_err(|err| err.to_string())?;
        let internal_token = Self::internal_control_token();
        let pre_vote_request = MetadataRaftPreVoteRequest {
            cluster_id: cluster_id.clone(),
            candidate_id: candidate.to_string(),
            term: pre_vote_term,
            last_log_index: candidate_last_index,
            last_log_term: candidate_last_term,
        };
        for peer in peers.iter() {
            if !peer.online || peer.id == candidate {
                continue;
            }
            let Some(endpoint) = peer
                .endpoint
                .as_ref()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
            else {
                last_error = Some(bilingual_runtime_error(
                    "元数据 Raft 预投票失败",
                    format!("peer {} missing endpoint for pre-vote", peer.id),
                ));
                continue;
            };
            if !Self::metadata_peer_endpoint_valid(&endpoint) {
                last_error = Some(bilingual_runtime_error(
                    "元数据 Raft 预投票失败",
                    format!("peer {} endpoint is invalid", peer.id),
                ));
                continue;
            }
            let url = format!(
                "{}/api/v1/internal/metadata-raft/pre-vote",
                endpoint.trim_end_matches('/')
            );
            match Self::send_metadata_raft_pre_vote_request(
                &client,
                &url,
                &internal_token,
                &pre_vote_request,
            )
            .await
            {
                Ok(payload) => {
                    max_term_seen = max_term_seen.max(payload.term);
                    if payload.pre_vote_granted {
                        pre_votes += 1;
                    } else if let Some(reason) = payload.reason {
                        last_error =
                            Some(bilingual_runtime_error("元数据 Raft 预投票失败", reason));
                    }
                }
                Err(err) => {
                    last_error = Some(bilingual_runtime_error(
                        "元数据 Raft 预投票失败",
                        format!("pre-vote request failed: {err}"),
                    ));
                }
            }
        }

        if pre_votes < quorum {
            let mut raft = self.metadata_raft.write().await;
            raft.term = raft.term.max(max_term_seen);
            raft.voted_for = None;
            raft.last_election_at = Some(Utc::now());
            raft.last_error = Some(last_error.unwrap_or_else(|| {
                bilingual_runtime_error(
                    "元数据 Raft 预投票未达到法定票数",
                    format!("pre-votes below quorum: {pre_votes}/{quorum}"),
                )
            }));
            let err = raft.last_error.clone().unwrap_or_else(|| {
                bilingual_runtime_error("元数据 Raft 预投票失败", "metadata raft pre-vote failed")
            });
            let raft_snapshot = raft.clone();
            drop(raft);
            self.persist_metadata_raft_state_inner(&raft_snapshot)?;
            return Err(err);
        }

        let election_term = pre_vote_term;
        let mut votes = 1usize;
        let vote_request = MetadataRaftVoteRequest {
            cluster_id: cluster_id.clone(),
            candidate_id: candidate.to_string(),
            term: election_term,
            last_log_index: candidate_last_index,
            last_log_term: candidate_last_term,
        };
        for peer in peers {
            if !peer.online || peer.id == candidate {
                continue;
            }
            let Some(endpoint) = peer
                .endpoint
                .as_ref()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
            else {
                last_error = Some(bilingual_runtime_error(
                    "元数据 Raft 选举失败",
                    format!("peer {} missing endpoint for vote", peer.id),
                ));
                continue;
            };
            if !Self::metadata_peer_endpoint_valid(&endpoint) {
                last_error = Some(bilingual_runtime_error(
                    "元数据 Raft 选举失败",
                    format!("peer {} endpoint is invalid", peer.id),
                ));
                continue;
            }
            let url = format!(
                "{}/api/v1/internal/metadata-raft/request-vote",
                endpoint.trim_end_matches('/')
            );
            match client
                .post(url)
                .header("x-rustio-internal-token", &internal_token)
                .json(&vote_request)
                .send()
                .await
            {
                Ok(response) if response.status().is_success() => {
                    match response.json::<MetadataRaftVoteResponse>().await {
                        Ok(payload) => {
                            max_term_seen = max_term_seen.max(payload.term);
                            if payload.vote_granted {
                                votes += 1;
                            } else if let Some(reason) = payload.reason {
                                last_error =
                                    Some(bilingual_runtime_error("元数据 Raft 选举失败", reason));
                            }
                        }
                        Err(err) => {
                            last_error = Some(bilingual_runtime_error(
                                "元数据 Raft 选举失败",
                                format!("decode vote response failed: {err}"),
                            ));
                        }
                    }
                }
                Ok(response) => {
                    last_error = Some(bilingual_runtime_error(
                        "元数据 Raft 选举失败",
                        format!("vote request status: {}", response.status()),
                    ));
                }
                Err(err) => {
                    last_error = Some(bilingual_runtime_error(
                        "元数据 Raft 选举失败",
                        format!("vote request failed: {err}"),
                    ));
                }
            }
        }

        if votes < quorum {
            let mut raft = self.metadata_raft.write().await;
            raft.term = raft.term.max(max_term_seen);
            raft.voted_for = None;
            raft.last_election_at = Some(Utc::now());
            raft.last_error = Some(last_error.unwrap_or_else(|| {
                bilingual_runtime_error(
                    "元数据 Raft 选举失败",
                    format!("votes below quorum: {votes}/{quorum}"),
                )
            }));
            let err = raft.last_error.clone().unwrap_or_else(|| {
                bilingual_runtime_error("元数据 Raft 选举失败", "raft election failed")
            });
            let raft_snapshot = raft.clone();
            drop(raft);
            self.persist_metadata_raft_state_inner(&raft_snapshot)?;
            return Err(err);
        }

        let mut raft = self.metadata_raft.write().await;
        let now = Utc::now();
        raft.term = raft.term.max(election_term);
        raft.leader_id = candidate.to_string();
        raft.voted_for = Some(candidate.to_string());
        raft.last_commit_at = Some(now);
        raft.last_election_at = Some(now);
        if candidate == local_peer {
            raft.last_heartbeat_at = Some(now);
        }
        raft.last_quorum_at = Some(now);
        raft.last_error = None;
        let status = Self::metadata_raft_status_from_state(&raft);
        let raft_snapshot = raft.clone();
        drop(raft);
        self.persist_metadata_raft_state_inner(&raft_snapshot)?;
        Ok(status)
    }

    pub async fn handle_metadata_pre_vote_request(
        &self,
        request: MetadataRaftPreVoteRequest,
    ) -> Result<MetadataRaftPreVoteResponse, String> {
        let local_peer_id = Self::metadata_local_peer_id();
        let raft = self.metadata_raft.read().await;
        if raft.cluster_id != request.cluster_id {
            return Err(bilingual_runtime_error(
                "元数据 Raft 集群标识不匹配",
                format!(
                    "metadata raft cluster mismatch: expected {}, got {}",
                    raft.cluster_id, request.cluster_id
                ),
            ));
        }
        if !Self::local_peer_in_membership(&raft, &local_peer_id) {
            return Ok(MetadataRaftPreVoteResponse {
                term: raft.term,
                pre_vote_granted: false,
                reason: Some("local peer not in membership".to_string()),
            });
        }

        if request.term < raft.term {
            return Ok(MetadataRaftPreVoteResponse {
                term: raft.term,
                pre_vote_granted: false,
                reason: Some("candidate term is stale".to_string()),
            });
        }

        let candidate_peer = raft
            .peers
            .iter()
            .find(|peer| peer.id == request.candidate_id);
        let Some(candidate_peer) = candidate_peer else {
            return Ok(MetadataRaftPreVoteResponse {
                term: raft.term,
                pre_vote_granted: false,
                reason: Some("candidate peer not found".to_string()),
            });
        };
        if !candidate_peer.online {
            return Ok(MetadataRaftPreVoteResponse {
                term: raft.term,
                pre_vote_granted: false,
                reason: Some("candidate peer is offline".to_string()),
            });
        }

        let local_last_term = if raft.last_commit_term == 0 && raft.commit_index > 0 {
            raft.term
        } else {
            raft.last_commit_term
        };
        let local_last_index = raft.commit_index;
        if request.last_log_term < local_last_term {
            return Ok(MetadataRaftPreVoteResponse {
                term: raft.term,
                pre_vote_granted: false,
                reason: Some("candidate log term is stale".to_string()),
            });
        }
        if request.last_log_term == local_last_term && request.last_log_index < local_last_index {
            return Ok(MetadataRaftPreVoteResponse {
                term: raft.term,
                pre_vote_granted: false,
                reason: Some("candidate log index is stale".to_string()),
            });
        }

        Ok(MetadataRaftPreVoteResponse {
            term: raft.term,
            pre_vote_granted: true,
            reason: None,
        })
    }

    pub async fn handle_metadata_vote_request(
        &self,
        request: MetadataRaftVoteRequest,
    ) -> Result<MetadataRaftVoteResponse, String> {
        let local_peer_id = Self::metadata_local_peer_id();
        let mut raft = self.metadata_raft.write().await;
        if raft.cluster_id != request.cluster_id {
            return Err(bilingual_runtime_error(
                "元数据 Raft 集群标识不匹配",
                format!(
                    "metadata raft cluster mismatch: expected {}, got {}",
                    raft.cluster_id, request.cluster_id
                ),
            ));
        }
        if !Self::local_peer_in_membership(&raft, &local_peer_id) {
            return Ok(MetadataRaftVoteResponse {
                term: raft.term,
                vote_granted: false,
                reason: Some("local peer not in membership".to_string()),
            });
        }

        let mut changed = false;
        let response = if request.term < raft.term {
            MetadataRaftVoteResponse {
                term: raft.term,
                vote_granted: false,
                reason: Some("candidate term is stale".to_string()),
            }
        } else {
            if request.term > raft.term {
                raft.term = request.term;
                raft.leader_id.clear();
                raft.voted_for = None;
                changed = true;
            }

            let candidate_peer = raft
                .peers
                .iter()
                .find(|peer| peer.id == request.candidate_id);
            if candidate_peer.is_none() {
                MetadataRaftVoteResponse {
                    term: raft.term,
                    vote_granted: false,
                    reason: Some("candidate peer not found".to_string()),
                }
            } else if !candidate_peer.map(|peer| peer.online).unwrap_or(false) {
                MetadataRaftVoteResponse {
                    term: raft.term,
                    vote_granted: false,
                    reason: Some("candidate peer is offline".to_string()),
                }
            } else {
                let local_last_term = if raft.last_commit_term == 0 && raft.commit_index > 0 {
                    raft.term
                } else {
                    raft.last_commit_term
                };
                let local_last_index = raft.commit_index;
                if request.last_log_term < local_last_term {
                    MetadataRaftVoteResponse {
                        term: raft.term,
                        vote_granted: false,
                        reason: Some("candidate log term is stale".to_string()),
                    }
                } else if request.last_log_term == local_last_term
                    && request.last_log_index < local_last_index
                {
                    MetadataRaftVoteResponse {
                        term: raft.term,
                        vote_granted: false,
                        reason: Some("candidate log index is stale".to_string()),
                    }
                } else if let Some(voted_for) = raft.voted_for.as_ref() {
                    if voted_for != &request.candidate_id {
                        MetadataRaftVoteResponse {
                            term: raft.term,
                            vote_granted: false,
                            reason: Some("already voted for another candidate".to_string()),
                        }
                    } else {
                        raft.last_error = None;
                        MetadataRaftVoteResponse {
                            term: raft.term,
                            vote_granted: true,
                            reason: None,
                        }
                    }
                } else {
                    raft.voted_for = Some(request.candidate_id);
                    raft.last_error = None;
                    changed = true;
                    MetadataRaftVoteResponse {
                        term: raft.term,
                        vote_granted: true,
                        reason: None,
                    }
                }
            }
        };
        let raft_snapshot = changed.then(|| raft.clone());
        drop(raft);
        if let Some(raft_snapshot) = raft_snapshot {
            self.persist_metadata_raft_state_inner(&raft_snapshot)?;
        }
        Ok(response)
    }

    pub async fn handle_metadata_heartbeat_request(
        &self,
        request: MetadataRaftHeartbeatRequest,
    ) -> Result<MetadataRaftHeartbeatResponse, String> {
        let local_peer_id = Self::metadata_local_peer_id();
        let mut raft = self.metadata_raft.write().await;
        if raft.cluster_id != request.cluster_id {
            return Err(bilingual_runtime_error(
                "元数据 Raft 集群标识不匹配",
                format!(
                    "metadata raft cluster mismatch: expected {}, got {}",
                    raft.cluster_id, request.cluster_id
                ),
            ));
        }
        if !Self::local_peer_in_membership(&raft, &local_peer_id) {
            return Ok(MetadataRaftHeartbeatResponse {
                term: raft.term,
                accepted: false,
                reason: Some("local peer not in membership".to_string()),
            });
        }

        let mut changed = false;
        let response = if request.term < raft.term {
            MetadataRaftHeartbeatResponse {
                term: raft.term,
                accepted: false,
                reason: Some("leader term is stale".to_string()),
            }
        } else if request.leader_id.trim().is_empty() {
            MetadataRaftHeartbeatResponse {
                term: raft.term,
                accepted: false,
                reason: Some("leader id is empty".to_string()),
            }
        } else if let Some(leader_index) = raft
            .peers
            .iter()
            .position(|peer| peer.id == request.leader_id)
        {
            let local_last_index = raft
                .peers
                .iter()
                .find(|peer| peer.id == local_peer_id)
                .map(|peer| peer.last_index)
                .unwrap_or(raft.commit_index);

            if request.term > raft.term {
                raft.term = request.term;
                raft.voted_for = None;
            }
            if raft.leader_id != request.leader_id {
                raft.leader_id = request.leader_id.clone();
            }
            let leader_peer = &mut raft.peers[leader_index];
            if !leader_peer.online {
                leader_peer.online = true;
            }

            let target_commit = request
                .leader_commit
                .min(local_last_index.max(raft.commit_index));
            if target_commit > raft.commit_index {
                raft.commit_index = target_commit;
                if request.term >= raft.last_commit_term {
                    raft.last_commit_term = request.term;
                }
            }
            if request.term >= raft.last_commit_term {
                raft.last_commit_term = request.term;
            }
            raft.last_heartbeat_at = Some(Utc::now());
            raft.last_error = None;
            changed = true;

            MetadataRaftHeartbeatResponse {
                term: raft.term,
                accepted: true,
                reason: None,
            }
        } else {
            MetadataRaftHeartbeatResponse {
                term: raft.term,
                accepted: false,
                reason: Some("leader peer not found".to_string()),
            }
        };

        let raft_snapshot = changed.then(|| raft.clone());
        drop(raft);
        if let Some(raft_snapshot) = raft_snapshot {
            self.persist_metadata_raft_state_inner(&raft_snapshot)?;
        }
        Ok(response)
    }

    async fn apply_metadata_raft_snapshot_internal(
        &self,
        request: MetadataRaftSyncRequest,
        persist_to_disk: bool,
    ) -> Result<MetadataRaftSyncResponse, String> {
        let applied_match_index = request.entry.index;
        let leader_commit = if request.leader_commit == 0 {
            request.entry.index
        } else {
            request.leader_commit.min(request.entry.index)
        };
        let raft_snapshot = {
            let mut raft = self.metadata_raft.write().await;
            if raft.cluster_id != request.cluster_id {
                return Err(bilingual_runtime_error(
                    "元数据 Raft 集群标识不匹配",
                    format!(
                        "metadata raft cluster mismatch: expected {}, got {}",
                        raft.cluster_id, request.cluster_id
                    ),
                ));
            }

            let local_commit_index = raft.commit_index;
            let local_commit_term = Self::raft_last_commit_term(&raft);
            if request.entry.term < raft.term && persist_to_disk {
                return Ok(MetadataRaftSyncResponse {
                    term: raft.term,
                    success: false,
                    match_index: local_commit_index,
                    reason: Some("stale leader term".to_string()),
                });
            }
            if !request.install_snapshot {
                if request.prev_log_index > local_commit_index {
                    return Ok(MetadataRaftSyncResponse {
                        term: raft.term,
                        success: false,
                        match_index: local_commit_index,
                        reason: Some("missing previous log entry".to_string()),
                    });
                }
                if request.prev_log_index == local_commit_index
                    && request.prev_log_index > 0
                    && request.prev_log_term != local_commit_term
                {
                    return Ok(MetadataRaftSyncResponse {
                        term: raft.term,
                        success: false,
                        match_index: local_commit_index,
                        reason: Some("prev log term mismatch".to_string()),
                    });
                }
            }
            if request.entry.index < local_commit_index {
                return Ok(MetadataRaftSyncResponse {
                    term: raft.term,
                    success: true,
                    match_index: local_commit_index,
                    reason: Some("already up-to-date".to_string()),
                });
            }
            if request.entry.index == local_commit_index {
                if persist_to_disk && request.entry.term < local_commit_term {
                    return Ok(MetadataRaftSyncResponse {
                        term: raft.term,
                        success: false,
                        match_index: local_commit_index,
                        reason: Some("incoming entry term is stale".to_string()),
                    });
                }
                if !request.install_snapshot
                    && !raft.last_snapshot_hash.is_empty()
                    && !request.entry.snapshot_hash.is_empty()
                    && request.entry.snapshot_hash != raft.last_snapshot_hash
                {
                    return Ok(MetadataRaftSyncResponse {
                        term: raft.term,
                        success: false,
                        match_index: local_commit_index,
                        reason: Some("conflicting snapshot at same index".to_string()),
                    });
                }
            }

            let target_path = if let Some(peer) = raft
                .peers
                .iter_mut()
                .find(|peer| peer.id == request.peer_id)
            {
                peer.last_index = peer.last_index.max(request.entry.index);
                peer.match_index = peer.match_index.max(peer.last_index);
                peer.next_index = peer.match_index.saturating_add(1);
                peer.path.clone()
            } else {
                let peer_dir = self
                    .data_dir
                    .join(".rustio_meta_raft")
                    .join(request.peer_id.clone());
                let _ = std::fs::create_dir_all(&peer_dir);
                raft.peers.push(MetadataRaftPeer {
                    id: request.peer_id.clone(),
                    path: peer_dir.clone(),
                    endpoint: None,
                    online: true,
                    match_index: request.entry.index,
                    next_index: request.entry.index.saturating_add(1),
                    last_index: request.entry.index,
                });
                peer_dir
            };

            if persist_to_disk {
                let snapshot_bytes =
                    serde_json::to_vec_pretty(&request.snapshot).map_err(|err| err.to_string())?;
                Self::persist_metadata_log_to_peer(&target_path, &request.entry, &snapshot_bytes)?;
            }

            if request.entry.term > raft.term {
                raft.voted_for = None;
            }
            let incoming_term = request.entry.term;
            if leader_commit > raft.commit_index
                || (leader_commit == raft.commit_index && incoming_term > raft.last_commit_term)
            {
                raft.last_commit_term = incoming_term;
            }
            raft.term = raft.term.max(incoming_term);
            raft.commit_index = raft.commit_index.max(leader_commit);
            raft.last_snapshot_hash = request.entry.snapshot_hash.clone();
            raft.last_commit_at = Some(request.entry.written_at);
            raft.last_error = None;
            raft.clone()
        };
        self.persist_metadata_raft_state_inner(&raft_snapshot)?;

        let snapshot = request.snapshot;
        {
            let mut buckets = HashMap::new();
            for bucket in snapshot.buckets {
                buckets.insert(bucket.name.clone(), bucket);
            }
            *self.buckets.write().await = buckets;
        }
        *self.remote_tiers.write().await =
            snapshot.remote_tiers.into_iter().collect::<HashMap<_, _>>();
        *self.bucket_object_locks.write().await = snapshot
            .bucket_object_locks
            .into_iter()
            .collect::<HashMap<_, _>>();
        *self.bucket_retentions.write().await = snapshot
            .bucket_retentions
            .into_iter()
            .collect::<HashMap<_, _>>();
        *self.bucket_legal_holds.write().await = snapshot
            .bucket_legal_holds
            .into_iter()
            .collect::<HashMap<_, _>>();
        *self.bucket_notifications.write().await = snapshot
            .bucket_notifications
            .into_iter()
            .collect::<HashMap<_, _>>();
        *self.bucket_lifecycle_rules.write().await = snapshot
            .bucket_lifecycle_rules
            .into_iter()
            .collect::<HashMap<_, _>>();
        *self.bucket_acls.write().await =
            snapshot.bucket_acls.into_iter().collect::<HashMap<_, _>>();
        *self.bucket_public_access_blocks.write().await = snapshot
            .bucket_public_access_blocks
            .into_iter()
            .collect::<HashMap<_, _>>();
        *self.bucket_policies.write().await = snapshot
            .bucket_policies
            .into_iter()
            .collect::<HashMap<_, _>>();
        *self.bucket_cors_rules.write().await = snapshot
            .bucket_cors_rules
            .into_iter()
            .collect::<HashMap<_, _>>();
        *self.bucket_tags.write().await =
            snapshot.bucket_tags.into_iter().collect::<HashMap<_, _>>();
        *self.bucket_encryptions.write().await = snapshot
            .bucket_encryptions
            .into_iter()
            .collect::<HashMap<_, _>>();
        *self.object_meta.write().await = snapshot
            .objects
            .into_iter()
            .map(|entry| ((entry.bucket, entry.key), entry.meta))
            .collect::<HashMap<_, _>>();
        *self.credentials.write().await =
            snapshot.credentials.into_iter().collect::<HashMap<_, _>>();
        *self.users.write().await = snapshot.iam_users;
        *self.groups.write().await = snapshot.iam_groups;
        *self.policies.write().await = snapshot.iam_policies;
        *self.service_accounts.write().await = snapshot.service_accounts;
        *self.admin_sessions.write().await = snapshot.admin_sessions.clone();
        Self::persist_console_sessions_snapshot(&self.data_dir, &snapshot.admin_sessions)?;
        *self.sts_sessions.write().await = snapshot.sts_sessions;
        *self.replications.write().await = snapshot.replications;
        *self.site_replications.write().await = snapshot.site_replications;
        *self.replication_backlog.write().await = snapshot.replication_backlog;
        *self.replication_checkpoints.write().await = snapshot
            .replication_checkpoints
            .into_iter()
            .collect::<HashMap<_, _>>();
        *self.cluster_config_history.write().await = snapshot.cluster_config_history.clone();
        Self::persist_cluster_config_history_snapshot(
            &self.data_dir,
            &snapshot.cluster_config_history,
        )?;
        *self.security.write().await = snapshot.security.clone();
        Self::persist_security_config_snapshot(&self.data_dir, &snapshot.security)?;
        *self.jobs.write().await = snapshot.jobs;
        self.persist_replication_runtime_state().await;
        Ok(MetadataRaftSyncResponse {
            term: raft_snapshot.term,
            success: true,
            match_index: applied_match_index,
            reason: None,
        })
    }

    pub async fn apply_remote_metadata_raft_sync(
        &self,
        request: MetadataRaftSyncRequest,
    ) -> Result<MetadataRaftSyncResponse, String> {
        self.apply_metadata_raft_snapshot_internal(request, true)
            .await
    }

    fn replication_root_dir(&self) -> PathBuf {
        self.data_dir.join(".rustio_replication")
    }

    fn replication_object_space_root(&self, site_id: &str, bucket: &str) -> PathBuf {
        self.data_dir
            .join(".rustio_sites")
            .join(site_id)
            .join("data")
            .join(bucket)
    }

    pub fn next_replication_checkpoint(&self) -> u64 {
        self.replication_sequence.fetch_add(1, Ordering::SeqCst)
    }

    fn replication_item_supersedable(status: &str) -> bool {
        matches!(status, "pending" | "failed" | "dead_letter")
    }

    fn replication_operation_priority(operation: &str) -> u8 {
        if operation.eq_ignore_ascii_case("delete") {
            0
        } else {
            1
        }
    }

    fn replication_backlog_alert_source(site: &str) -> String {
        format!("replication-backlog-sla-watchdog:{site}")
    }

    fn replication_backlog_alert_site(source: &str) -> Option<&str> {
        source.strip_prefix("replication-backlog-sla-watchdog:")
    }

    fn replication_backlog_alert_breach_hash(details: &Value) -> Option<&str> {
        details.get("breach_hash").and_then(Value::as_str)
    }

    fn alert_rule_condition_matches(
        value: f64,
        condition: &str,
        threshold: f64,
    ) -> Result<bool, String> {
        if !value.is_finite() {
            return Err(bilingual_runtime_error(
                "告警指标值无效",
                "alert metric value is not finite",
            ));
        }
        if !threshold.is_finite() {
            return Err(bilingual_runtime_error(
                "告警阈值无效",
                "alert threshold is not finite",
            ));
        }
        match condition {
            ">" => Ok(value > threshold),
            ">=" => Ok(value >= threshold),
            "<" => Ok(value < threshold),
            "<=" => Ok(value <= threshold),
            "=" => Ok((value - threshold).abs() <= f64::EPSILON),
            "!=" => Ok((value - threshold).abs() > f64::EPSILON),
            _ => Err(bilingual_runtime_error(
                "告警条件不支持",
                format!("alert condition is unsupported: {condition}"),
            )),
        }
    }

    async fn alert_rule_metric_value(&self, metric: &str) -> Result<f64, String> {
        match metric {
            "cluster.capacity.used_ratio" => {
                let nodes = self.nodes.read().await;
                let total = nodes
                    .iter()
                    .map(|node| node.capacity_total_bytes)
                    .sum::<u64>();
                let used = nodes
                    .iter()
                    .map(|node| node.capacity_used_bytes.min(node.capacity_total_bytes))
                    .sum::<u64>();
                if total == 0 {
                    return Err(bilingual_runtime_error(
                        "集群容量总量为 0，无法计算使用率",
                        "cluster capacity total is 0, cannot compute used ratio",
                    ));
                }
                Ok(used as f64 / total as f64)
            }
            "replication.lag.seconds" => {
                let sites = self.site_replications.read().await;
                Ok(sites
                    .iter()
                    .map(|site| site.lag_seconds)
                    .max()
                    .unwrap_or_default() as f64)
            }
            _ => Err(bilingual_runtime_error(
                "告警指标不支持",
                format!("alert metric unsupported: {metric}"),
            )),
        }
    }

    async fn evaluate_alert_rule_once(
        &self,
        rule: AlertRule,
        now: DateTime<Utc>,
        record_stable_state: bool,
        evaluated_by: &str,
    ) -> Result<Option<AlertHistoryEntry>, String> {
        let value = self.alert_rule_metric_value(&rule.metric).await?;
        let matched = Self::alert_rule_condition_matches(value, &rule.condition, rule.threshold)?;
        let silence = self
            .alert_silences
            .read()
            .await
            .iter()
            .find(|silence| {
                silence.enabled
                    && silence.rule_ids.iter().any(|rule_id| rule_id == &rule.id)
                    && now >= silence.starts_at
                    && now <= silence.ends_at
            })
            .cloned();
        let is_silenced = silence.is_some();
        if matched {
            let mut rules = self.alert_rules.write().await;
            if let Some(existing) = rules.iter_mut().find(|item| item.id == rule.id) {
                existing.last_triggered_at = Some(now);
            }
            drop(rules);
        }

        let firing_message = bilingual_runtime_error(
            &format!(
                "规则 {} 触发：指标 {} 当前值 {:.6} {} 阈值 {:.6}",
                rule.name, rule.metric, value, rule.condition, rule.threshold
            ),
            format!(
                "rule {} fired: metric {} value {:.6} {} threshold {:.6}",
                rule.name, rule.metric, value, rule.condition, rule.threshold
            ),
        );
        let recovered_message = bilingual_runtime_error(
            &format!(
                "规则 {} 已恢复：指标 {} 当前值 {:.6} 未命中条件 {} {:.6}",
                rule.name, rule.metric, value, rule.condition, rule.threshold
            ),
            format!(
                "rule {} recovered: metric {} value {:.6} no longer matches {} {:.6}",
                rule.name, rule.metric, value, rule.condition, rule.threshold
            ),
        );
        let stable_message = bilingual_runtime_error(
            &format!(
                "规则 {} 当前健康：指标 {} 当前值 {:.6} 未命中条件 {} {:.6}",
                rule.name, rule.metric, value, rule.condition, rule.threshold
            ),
            format!(
                "rule {} is healthy: metric {} value {:.6} does not match {} {:.6}",
                rule.name, rule.metric, value, rule.condition, rule.threshold
            ),
        );
        let suppressed_message = bilingual_runtime_error(
            &format!(
                "规则 {} 命中但处于静默窗口：指标 {} 当前值 {:.6} {} 阈值 {:.6}",
                rule.name, rule.metric, value, rule.condition, rule.threshold
            ),
            format!(
                "rule {} matched but is silenced: metric {} value {:.6} {} threshold {:.6}",
                rule.name, rule.metric, value, rule.condition, rule.threshold
            ),
        );
        let source = "rule-engine".to_string();
        let mut history = self.alert_history.write().await;
        let active_firing = history
            .iter()
            .enumerate()
            .filter(|(_, entry)| {
                entry.rule_id.as_deref() == Some(rule.id.as_str())
                    && entry.status == "firing"
                    && entry.resolved_at.is_none()
            })
            .map(|(index, entry)| (index, entry.triggered_at))
            .max_by_key(|(_, triggered_at)| *triggered_at)
            .map(|(index, _)| index);

        if matched && !is_silenced {
            let details = json!({
                "metric": rule.metric,
                "condition": rule.condition,
                "threshold": rule.threshold,
                "window_minutes": rule.window_minutes,
                "value": value,
                "matched": true,
                "silenced": false,
                "evaluator": evaluated_by,
            });
            if let Some(index) = active_firing {
                if let Some(entry) = history.get_mut(index) {
                    entry.rule_name = Some(rule.name.clone());
                    entry.severity = rule.severity.clone();
                    entry.message = firing_message;
                    entry.details = details;
                    return Ok(Some(entry.clone()));
                }
            }
            let entry = AlertHistoryEntry {
                id: format!("history-{}", Uuid::new_v4().simple()),
                rule_id: Some(rule.id.clone()),
                rule_name: Some(rule.name.clone()),
                severity: rule.severity.clone(),
                status: "firing".to_string(),
                message: firing_message,
                triggered_at: now,
                source,
                assignee: None,
                claimed_at: None,
                acknowledged_by: None,
                acknowledged_at: None,
                resolved_by: None,
                resolved_at: None,
                details,
            };
            history.push(entry.clone());
            return Ok(Some(entry));
        }

        if matched && is_silenced {
            let suppress_window = Duration::minutes(rule.window_minutes.max(1) as i64);
            let suppressed_recent = history
                .iter()
                .filter(|entry| {
                    entry.rule_id.as_deref() == Some(rule.id.as_str())
                        && entry.status == "suppressed"
                })
                .map(|entry| entry.triggered_at)
                .max()
                .map(|last| now.signed_duration_since(last) < suppress_window)
                .unwrap_or(false);
            if suppressed_recent {
                return Ok(None);
            }
            let entry = AlertHistoryEntry {
                id: format!("history-{}", Uuid::new_v4().simple()),
                rule_id: Some(rule.id.clone()),
                rule_name: Some(rule.name.clone()),
                severity: rule.severity.clone(),
                status: "suppressed".to_string(),
                message: suppressed_message,
                triggered_at: now,
                source,
                assignee: None,
                claimed_at: None,
                acknowledged_by: None,
                acknowledged_at: None,
                resolved_by: Some("system".to_string()),
                resolved_at: Some(now),
                details: json!({
                    "metric": rule.metric,
                    "condition": rule.condition,
                    "threshold": rule.threshold,
                    "window_minutes": rule.window_minutes,
                    "value": value,
                    "matched": true,
                    "silenced": true,
                    "silence_id": silence.as_ref().map(|item| item.id.clone()),
                    "silence_name": silence.as_ref().map(|item| item.name.clone()),
                    "evaluator": evaluated_by,
                }),
            };
            history.push(entry.clone());
            return Ok(Some(entry));
        }

        let mut resolved = None::<AlertHistoryEntry>;
        for entry in history.iter_mut().filter(|entry| {
            entry.rule_id.as_deref() == Some(rule.id.as_str())
                && entry.status == "firing"
                && entry.resolved_at.is_none()
        }) {
            entry.status = "resolved".to_string();
            entry.resolved_by = Some("system".to_string());
            entry.resolved_at = Some(now);
            entry.message = recovered_message.clone();
            entry.details = json!({
                "metric": rule.metric,
                "condition": rule.condition,
                "threshold": rule.threshold,
                "window_minutes": rule.window_minutes,
                "value": value,
                "matched": false,
                "silenced": false,
                "evaluator": evaluated_by,
            });
            if resolved
                .as_ref()
                .map(|current| entry.triggered_at > current.triggered_at)
                .unwrap_or(true)
            {
                resolved = Some(entry.clone());
            }
        }
        if resolved.is_some() {
            return Ok(resolved);
        }
        if !record_stable_state {
            return Ok(None);
        }

        let entry = AlertHistoryEntry {
            id: format!("history-{}", Uuid::new_v4().simple()),
            rule_id: Some(rule.id.clone()),
            rule_name: Some(rule.name.clone()),
            severity: rule.severity,
            status: "resolved".to_string(),
            message: stable_message,
            triggered_at: now,
            source,
            assignee: None,
            claimed_at: None,
            acknowledged_by: None,
            acknowledged_at: None,
            resolved_by: Some(evaluated_by.to_string()),
            resolved_at: Some(now),
            details: json!({
                "metric": rule.metric,
                "condition": rule.condition,
                "threshold": rule.threshold,
                "window_minutes": rule.window_minutes,
                "value": value,
                "matched": false,
                "silenced": false,
                "evaluator": evaluated_by,
                "stable_snapshot": true,
            }),
        };
        history.push(entry.clone());
        Ok(Some(entry))
    }

    pub async fn evaluate_alert_rule_now(
        &self,
        rule_id: &str,
        evaluated_by: &str,
    ) -> Result<AlertHistoryEntry, String> {
        let now = Utc::now();
        let rule = self
            .alert_rules
            .read()
            .await
            .iter()
            .find(|rule| rule.id == rule_id)
            .cloned()
            .ok_or_else(|| bilingual_runtime_error("告警规则不存在", "alert rule not found"))?;
        if !rule.enabled {
            return Err(bilingual_runtime_error(
                "告警规则已禁用",
                "alert rule is disabled",
            ));
        }
        self.evaluate_alert_rule_once(rule, now, true, evaluated_by)
            .await?
            .ok_or_else(|| {
                bilingual_runtime_error(
                    "告警规则评估未产生状态变更",
                    "alert rule evaluation produced no transition",
                )
            })
    }

    async fn process_alert_rules_once(&self) -> Result<usize, String> {
        let now = Utc::now();
        let rules = self
            .alert_rules
            .read()
            .await
            .iter()
            .filter(|rule| rule.enabled)
            .cloned()
            .collect::<Vec<_>>();
        let mut transitions = 0usize;
        let mut first_error = None::<String>;
        for rule in rules {
            match self
                .evaluate_alert_rule_once(rule, now, false, "system")
                .await
            {
                Ok(Some(entry)) => {
                    transitions += 1;
                    if let Err(err) = self.enqueue_alert_deliveries(&entry).await {
                        if first_error.is_none() {
                            first_error = Some(err);
                        }
                    }
                    self.push_event(
                        "alerts.rule.evaluated",
                        "alerts-service",
                        json!({
                            "rule_id": entry.rule_id,
                            "status": entry.status,
                            "severity": entry.severity,
                        }),
                    )
                    .await;
                }
                Ok(None) => {}
                Err(err) => {
                    if first_error.is_none() {
                        first_error = Some(err);
                    }
                }
            }
        }
        if transitions == 0 {
            if let Some(err) = first_error {
                return Err(err);
            }
        }
        Ok(transitions)
    }

    fn alert_delivery_retry_delay(attempts: u32) -> std::time::Duration {
        let base = Self::alert_delivery_retry_base_interval();
        let max = Self::alert_delivery_retry_max_interval();
        let exponent = attempts.saturating_sub(1).min(10);
        let factor = 1u64 << exponent;
        let delay_ms = (base.as_millis() as u64).saturating_mul(factor);
        std::time::Duration::from_millis(delay_ms.min(max.as_millis() as u64))
    }

    fn alert_delivery_spool_path(&self, kind: &str) -> PathBuf {
        self.data_dir
            .join(".rustio_alerts")
            .join(format!("{kind}.ndjson"))
    }

    fn alert_delivery_write_spool(&self, kind: &str, payload: &Value) -> Result<(), String> {
        let path = self.alert_delivery_spool_path(kind);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|err| {
                bilingual_runtime_error(
                    "创建告警投递落盘目录失败",
                    format!("create alert spool dir failed: {err}"),
                )
            })?;
        }
        let line = serde_json::to_string(payload).map_err(|err| {
            bilingual_runtime_error(
                "序列化告警投递内容失败",
                format!("serialize alert delivery payload failed: {err}"),
            )
        })?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|err| {
                bilingual_runtime_error(
                    "打开告警投递落盘文件失败",
                    format!("open alert spool file failed: {err}"),
                )
            })?;
        file.write_all(format!("{line}\n").as_bytes())
            .map_err(|err| {
                bilingual_runtime_error(
                    "写入告警投递落盘文件失败",
                    format!("write alert spool file failed: {err}"),
                )
            })?;
        Ok(())
    }

    fn alert_delivery_sanitize_header(value: &str) -> String {
        value
            .chars()
            .filter(|ch| *ch != '\r' && *ch != '\n')
            .collect::<String>()
            .trim()
            .to_string()
    }

    fn alert_delivery_parse_smtp_endpoint(
        endpoint: &str,
    ) -> Option<(String, String, AlertSmtpTransport)> {
        let (raw, transport) = if let Some(raw) = endpoint.strip_prefix("smtp+starttls://") {
            (raw, AlertSmtpTransport::StartTls)
        } else if let Some(raw) = endpoint.strip_prefix("smtps://") {
            (raw, AlertSmtpTransport::Tls)
        } else if let Some(raw) = endpoint.strip_prefix("smtp://") {
            let transport = if Self::alert_delivery_smtp_tls_default() {
                AlertSmtpTransport::Tls
            } else if Self::alert_delivery_smtp_starttls_default() {
                AlertSmtpTransport::StartTls
            } else {
                AlertSmtpTransport::Plain
            };
            (raw, transport)
        } else {
            return None;
        };
        let (server, recipient) = raw.split_once('/')?;
        let server = server.trim();
        let recipient = recipient.trim().trim_start_matches('/');
        if server.is_empty() || recipient.is_empty() {
            return None;
        }
        Some((server.to_string(), recipient.to_string(), transport))
    }

    fn alert_delivery_parse_smtp_server_transport(raw: &str) -> (String, AlertSmtpTransport) {
        if let Some(server) = raw.strip_prefix("smtp+starttls://") {
            return (server.trim().to_string(), AlertSmtpTransport::StartTls);
        }
        if let Some(server) = raw.strip_prefix("smtps://") {
            return (server.trim().to_string(), AlertSmtpTransport::Tls);
        }
        if let Some(server) = raw.strip_prefix("smtp://") {
            let transport = if Self::alert_delivery_smtp_tls_default() {
                AlertSmtpTransport::Tls
            } else if Self::alert_delivery_smtp_starttls_default() {
                AlertSmtpTransport::StartTls
            } else {
                AlertSmtpTransport::Plain
            };
            return (server.trim().to_string(), transport);
        }
        if Self::alert_delivery_smtp_tls_default() {
            (raw.trim().to_string(), AlertSmtpTransport::Tls)
        } else if Self::alert_delivery_smtp_starttls_default() {
            (raw.trim().to_string(), AlertSmtpTransport::StartTls)
        } else {
            (raw.trim().to_string(), AlertSmtpTransport::Plain)
        }
    }

    fn alert_delivery_parse_smtp_server_auth(
        server: &str,
    ) -> (String, Option<String>, Option<String>) {
        let Some((auth, host)) = server.rsplit_once('@') else {
            return (server.trim().to_string(), None, None);
        };
        let host = host.trim().to_string();
        if host.is_empty() {
            return (server.trim().to_string(), None, None);
        }
        let Some((username, password)) = auth.split_once(':') else {
            return (host, Some(auth.trim().to_string()), None);
        };
        let username = username.trim().to_string();
        let password = password.trim().to_string();
        (
            host,
            if username.is_empty() {
                None
            } else {
                Some(username)
            },
            if password.is_empty() {
                None
            } else {
                Some(password)
            },
        )
    }

    fn alert_delivery_parse_nats_endpoint(
        endpoint: &str,
    ) -> Option<(String, Option<String>, bool)> {
        let (raw, tls) = if let Some(raw) = endpoint.strip_prefix("natss://") {
            (raw, true)
        } else if let Some(raw) = endpoint.strip_prefix("nats://") {
            (raw, Self::alert_delivery_nats_tls_default())
        } else {
            return None;
        };
        let (server, subject) = if let Some((server, subject)) = raw.split_once('/') {
            (server.trim(), Some(subject.trim().trim_start_matches('/')))
        } else {
            (raw.trim(), None)
        };
        if server.is_empty() {
            return None;
        }
        let subject = subject.and_then(|value| {
            if value.is_empty() {
                None
            } else {
                Some(value.to_string())
            }
        });
        Some((server.to_string(), subject, tls))
    }

    fn alert_delivery_parse_nats_server_auth(
        server: &str,
    ) -> (String, Option<String>, Option<String>, Option<String>) {
        let Some((auth, host)) = server.rsplit_once('@') else {
            return (server.trim().to_string(), None, None, None);
        };
        let host = host.trim().to_string();
        if host.is_empty() {
            return (server.trim().to_string(), None, None, None);
        }
        if let Some((username, password)) = auth.split_once(':') {
            let username = username.trim().to_string();
            let password = password.trim().to_string();
            return (
                host,
                if username.is_empty() {
                    None
                } else {
                    Some(username)
                },
                if password.is_empty() {
                    None
                } else {
                    Some(password)
                },
                None,
            );
        }
        let token = auth.trim().to_string();
        (
            host,
            None,
            None,
            if token.is_empty() { None } else { Some(token) },
        )
    }

    fn alert_delivery_parse_redis_endpoint(
        endpoint: &str,
    ) -> Option<(String, Option<String>, bool)> {
        let (raw, tls) = if let Some(raw) = endpoint.strip_prefix("rediss://") {
            (raw, true)
        } else if let Some(raw) = endpoint.strip_prefix("redis://") {
            (raw, Self::alert_delivery_redis_tls_default())
        } else {
            return None;
        };
        let (server, channel) = if let Some((server, channel)) = raw.split_once('/') {
            (server.trim(), Some(channel.trim().trim_start_matches('/')))
        } else {
            (raw.trim(), None)
        };
        if server.is_empty() {
            return None;
        }
        let channel = channel.and_then(|value| {
            if value.is_empty() {
                None
            } else {
                Some(value.to_string())
            }
        });
        Some((server.to_string(), channel, tls))
    }

    fn alert_delivery_parse_redis_server_auth(
        server: &str,
    ) -> (String, Option<String>, Option<String>) {
        let Some((auth, host)) = server.rsplit_once('@') else {
            return (server.trim().to_string(), None, None);
        };
        let host = host.trim().to_string();
        if host.is_empty() {
            return (server.trim().to_string(), None, None);
        }
        if let Some((username, password)) = auth.split_once(':') {
            let username = username.trim().to_string();
            let password = password.trim().to_string();
            return (
                host,
                if username.is_empty() {
                    None
                } else {
                    Some(username)
                },
                if password.is_empty() {
                    None
                } else {
                    Some(password)
                },
            );
        }
        let password = auth.trim().to_string();
        (
            host,
            None,
            if password.is_empty() {
                None
            } else {
                Some(password)
            },
        )
    }

    fn alert_delivery_server_name(server: &str) -> Option<String> {
        let host = if server.starts_with('[') {
            let end = server.find(']')?;
            server[1..end].to_string()
        } else {
            server
                .split(':')
                .next()
                .unwrap_or_default()
                .trim()
                .to_string()
        };
        if host.is_empty() {
            None
        } else {
            Some(host)
        }
    }

    fn alert_delivery_tls_connector() -> Result<TlsConnector, String> {
        static TLS_PROVIDER_INIT: std::sync::OnceLock<()> = std::sync::OnceLock::new();
        TLS_PROVIDER_INIT.get_or_init(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
        let mut root_store = RootCertStore::empty();
        let native = rustls_native_certs::load_native_certs();
        for cert in native.certs {
            let _ = root_store.add(cert);
        }
        if let Some(path) = Self::alert_delivery_tls_ca_file() {
            let pem = std::fs::read(&path).map_err(|err| {
                bilingual_runtime_error(
                    "读取告警 TLS CA 证书文件失败",
                    format!("read alert tls ca certificate file failed: {err}"),
                )
            })?;
            let mut reader = std::io::Cursor::new(pem);
            let mut loaded = 0usize;
            for cert in rustls_pemfile::certs(&mut reader) {
                let cert = cert.map_err(|err| {
                    bilingual_runtime_error(
                        "解析告警 TLS CA 证书失败",
                        format!("parse alert tls ca certificate failed: {err}"),
                    )
                })?;
                root_store.add(cert).map_err(|err| {
                    bilingual_runtime_error(
                        "加载告警 TLS CA 证书失败",
                        format!("load alert tls ca certificate failed: {err}"),
                    )
                })?;
                loaded += 1;
            }
            if loaded == 0 {
                return Err(bilingual_runtime_error(
                    "告警 TLS CA 证书文件中没有可用证书",
                    format!(
                        "alert tls ca certificate file does not contain usable certificates: {path}"
                    ),
                ));
            }
        }
        if native.errors.iter().any(|_| true) && root_store.is_empty() {
            return Err(bilingual_runtime_error(
                "加载系统根证书失败",
                "load system root certificates failed",
            ));
        }
        if root_store.is_empty() {
            return Err(bilingual_runtime_error(
                "系统根证书为空",
                "system root certificates are empty",
            ));
        }
        let config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        Ok(TlsConnector::from(Arc::new(config)))
    }

    async fn alert_delivery_tls_wrap(
        server: &str,
        stream: TcpStream,
    ) -> Result<TlsStream<TcpStream>, String> {
        let connector = Self::alert_delivery_tls_connector()?;
        let server_name_raw = Self::alert_delivery_server_name(server).ok_or_else(|| {
            bilingual_runtime_error(
                "TLS 服务器名无效",
                format!("invalid tls server name: {server}"),
            )
        })?;
        let server_name: ServerName<'static> = ServerName::try_from(server_name_raw.clone())
            .map_err(|_| {
                bilingual_runtime_error(
                    "TLS 服务器名无效",
                    format!("invalid tls server name: {server_name_raw}"),
                )
            })?;
        timeout(
            Self::alert_delivery_http_timeout(),
            connector.connect(server_name, stream),
        )
        .await
        .map_err(|_| bilingual_runtime_error("TLS 握手超时", "tls handshake timed out"))?
        .map_err(|err| {
            bilingual_runtime_error("TLS 握手失败", format!("tls handshake failed: {err}"))
        })
    }

    async fn alert_delivery_smtp_read_response<T>(
        reader: &mut BufReader<T>,
    ) -> Result<(u16, String), String>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        let timeout_duration = Self::alert_delivery_http_timeout();
        let mut merged = String::new();
        let code = loop {
            let mut line = String::new();
            let size = timeout(timeout_duration, reader.read_line(&mut line))
                .await
                .map_err(|_| {
                    bilingual_runtime_error("读取 SMTP 响应超时", "read smtp response timed out")
                })?
                .map_err(|err| {
                    bilingual_runtime_error(
                        "读取 SMTP 响应失败",
                        format!("read smtp response failed: {err}"),
                    )
                })?;
            if size == 0 {
                return Err(bilingual_runtime_error(
                    "SMTP 连接提前关闭",
                    "smtp connection closed unexpectedly",
                ));
            }
            let trimmed = line.trim_end_matches(['\r', '\n']);
            if !merged.is_empty() {
                merged.push('\n');
            }
            merged.push_str(trimmed);
            let bytes = trimmed.as_bytes();
            if bytes.len() < 3
                || !bytes[0].is_ascii_digit()
                || !bytes[1].is_ascii_digit()
                || !bytes[2].is_ascii_digit()
            {
                return Err(bilingual_runtime_error(
                    "SMTP 响应格式错误",
                    format!("smtp response malformed: {trimmed}"),
                ));
            }
            let parsed = std::str::from_utf8(&bytes[0..3])
                .ok()
                .and_then(|value| value.parse::<u16>().ok())
                .ok_or_else(|| {
                    bilingual_runtime_error(
                        "SMTP 响应码解析失败",
                        format!("smtp response code parse failed: {trimmed}"),
                    )
                })?;
            let continued = bytes.get(3) == Some(&b'-');
            if !continued {
                break parsed;
            }
        };
        Ok((code, merged))
    }

    async fn alert_delivery_smtp_command<T>(
        reader: &mut BufReader<T>,
        command: &str,
        expected_codes: &[u16],
    ) -> Result<String, String>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        let timeout_duration = Self::alert_delivery_http_timeout();
        timeout(
            timeout_duration,
            reader.get_mut().write_all(command.as_bytes()),
        )
        .await
        .map_err(|_| {
            bilingual_runtime_error(
                "写入 SMTP 命令超时",
                format!("write smtp command timed out: {}", command.trim()),
            )
        })?
        .map_err(|err| {
            bilingual_runtime_error(
                "写入 SMTP 命令失败",
                format!("write smtp command failed: {err}"),
            )
        })?;
        timeout(timeout_duration, reader.get_mut().flush())
            .await
            .map_err(|_| {
                bilingual_runtime_error("刷新 SMTP 命令超时", "flush smtp command timed out")
            })?
            .map_err(|err| {
                bilingual_runtime_error(
                    "刷新 SMTP 命令失败",
                    format!("flush smtp command failed: {err}"),
                )
            })?;
        let (code, response) = Self::alert_delivery_smtp_read_response(reader).await?;
        if expected_codes.iter().any(|expected| *expected == code) {
            Ok(response)
        } else {
            Err(bilingual_runtime_error(
                "SMTP 返回错误状态码",
                format!(
                    "smtp command {} failed with code {} response={}",
                    command.trim(),
                    code,
                    response
                ),
            ))
        }
    }

    async fn alert_delivery_smtp_auth_and_send<T>(
        reader: &mut BufReader<T>,
        ehlo_response: &str,
        from: &str,
        to: &str,
        payload: &Value,
        username: Option<&str>,
        password: Option<&str>,
    ) -> Result<(), String>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        if let (Some(username), Some(password)) = (username, password) {
            let username_clean = Self::alert_delivery_sanitize_header(username);
            let password_clean = Self::alert_delivery_sanitize_header(password);
            if username_clean.is_empty() || password_clean.is_empty() {
                return Err(bilingual_runtime_error(
                    "SMTP 认证信息无效",
                    "smtp auth username/password is empty",
                ));
            }
            let auth_plain = BASE64.encode(format!("\0{username_clean}\0{password_clean}"));
            let plain_command = format!("AUTH PLAIN {auth_plain}\r\n");
            let plain_result =
                Self::alert_delivery_smtp_command(reader, &plain_command, &[235, 250]).await;
            if plain_result.is_err() {
                if !ehlo_response.to_ascii_uppercase().contains("AUTH") {
                    return Err(bilingual_runtime_error(
                        "SMTP 服务端不支持认证",
                        "smtp server does not advertise auth capability",
                    ));
                }
                let _ = Self::alert_delivery_smtp_command(reader, "AUTH LOGIN\r\n", &[334]).await?;
                let user_line = format!("{}\r\n", BASE64.encode(username_clean));
                let _ = Self::alert_delivery_smtp_command(reader, &user_line, &[334]).await?;
                let pass_line = format!("{}\r\n", BASE64.encode(password_clean));
                let _ = Self::alert_delivery_smtp_command(reader, &pass_line, &[235]).await?;
            }
        }
        let from_clean = Self::alert_delivery_sanitize_header(from);
        let to_clean = Self::alert_delivery_sanitize_header(to);
        let _ = Self::alert_delivery_smtp_command(
            reader,
            &format!("MAIL FROM:<{from_clean}>\r\n"),
            &[250],
        )
        .await?;
        let _ = Self::alert_delivery_smtp_command(
            reader,
            &format!("RCPT TO:<{to_clean}>\r\n"),
            &[250, 251],
        )
        .await?;
        let _ = Self::alert_delivery_smtp_command(reader, "DATA\r\n", &[354]).await?;
        let subject = Self::alert_delivery_sanitize_header(&format!(
            "RustIO alert {}",
            payload
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or("event")
        ));
        let body = serde_json::to_string_pretty(payload).map_err(|err| {
            bilingual_runtime_error(
                "序列化 SMTP 告警消息失败",
                format!("serialize smtp payload failed: {err}"),
            )
        })?;
        let message = format!(
            "From: <{from_clean}>\r\nTo: <{to_clean}>\r\nSubject: {subject}\r\nContent-Type: application/json; charset=utf-8\r\n\r\n{body}\r\n.\r\n"
        );
        timeout(
            Self::alert_delivery_http_timeout(),
            reader.get_mut().write_all(message.as_bytes()),
        )
        .await
        .map_err(|_| bilingual_runtime_error("写入 SMTP 消息超时", "write smtp message timed out"))?
        .map_err(|err| {
            bilingual_runtime_error(
                "写入 SMTP 消息失败",
                format!("write smtp message failed: {err}"),
            )
        })?;
        timeout(
            Self::alert_delivery_http_timeout(),
            reader.get_mut().flush(),
        )
        .await
        .map_err(|_| bilingual_runtime_error("刷新 SMTP 消息超时", "flush smtp message timed out"))?
        .map_err(|err| {
            bilingual_runtime_error(
                "刷新 SMTP 消息失败",
                format!("flush smtp message failed: {err}"),
            )
        })?;
        let (data_code, data_response) = Self::alert_delivery_smtp_read_response(reader).await?;
        if data_code != 250 {
            return Err(bilingual_runtime_error(
                "SMTP DATA 提交失败",
                format!(
                    "smtp data commit expected 250 got {} response={data_response}",
                    data_code
                ),
            ));
        }
        let _ = Self::alert_delivery_smtp_command(reader, "QUIT\r\n", &[221]).await;
        Ok(())
    }

    async fn alert_delivery_send_smtp(
        server: &str,
        from: &str,
        to: &str,
        payload: &Value,
        username: Option<&str>,
        password: Option<&str>,
        transport: AlertSmtpTransport,
    ) -> Result<(), String> {
        let timeout_duration = Self::alert_delivery_http_timeout();
        let stream = timeout(timeout_duration, TcpStream::connect(server))
            .await
            .map_err(|_| {
                bilingual_runtime_error(
                    "连接 SMTP 服务器超时",
                    format!("connect smtp server timed out: {server}"),
                )
            })?
            .map_err(|err| {
                bilingual_runtime_error(
                    "连接 SMTP 服务器失败",
                    format!("connect smtp server failed: {err}"),
                )
            })?;

        if transport == AlertSmtpTransport::Tls {
            let tls = Self::alert_delivery_tls_wrap(server, stream).await?;
            let mut reader = BufReader::new(tls);
            let (greet_code, greet) = Self::alert_delivery_smtp_read_response(&mut reader).await?;
            if greet_code != 220 {
                return Err(bilingual_runtime_error(
                    "SMTP 欢迎响应异常",
                    format!(
                        "smtp greeting expected 220 got {} response={greet}",
                        greet_code
                    ),
                ));
            }
            let ehlo_response =
                Self::alert_delivery_smtp_command(&mut reader, "EHLO rustio.local\r\n", &[250])
                    .await?;
            return Self::alert_delivery_smtp_auth_and_send(
                &mut reader,
                &ehlo_response,
                from,
                to,
                payload,
                username,
                password,
            )
            .await;
        }

        let mut reader = BufReader::new(stream);
        let (greet_code, greet) = Self::alert_delivery_smtp_read_response(&mut reader).await?;
        if greet_code != 220 {
            return Err(bilingual_runtime_error(
                "SMTP 欢迎响应异常",
                format!(
                    "smtp greeting expected 220 got {} response={greet}",
                    greet_code
                ),
            ));
        }
        let mut ehlo_response =
            Self::alert_delivery_smtp_command(&mut reader, "EHLO rustio.local\r\n", &[250]).await?;
        if transport == AlertSmtpTransport::StartTls {
            if !ehlo_response.to_ascii_uppercase().contains("STARTTLS") {
                return Err(bilingual_runtime_error(
                    "SMTP 服务端不支持 STARTTLS",
                    "smtp server does not advertise STARTTLS",
                ));
            }
            let _ = Self::alert_delivery_smtp_command(&mut reader, "STARTTLS\r\n", &[220]).await?;
            let stream = reader.into_inner();
            let tls = Self::alert_delivery_tls_wrap(server, stream).await?;
            let mut tls_reader = BufReader::new(tls);
            ehlo_response =
                Self::alert_delivery_smtp_command(&mut tls_reader, "EHLO rustio.local\r\n", &[250])
                    .await?;
            return Self::alert_delivery_smtp_auth_and_send(
                &mut tls_reader,
                &ehlo_response,
                from,
                to,
                payload,
                username,
                password,
            )
            .await;
        }
        Self::alert_delivery_smtp_auth_and_send(
            &mut reader,
            &ehlo_response,
            from,
            to,
            payload,
            username,
            password,
        )
        .await
    }

    async fn alert_delivery_nats_publish<T>(
        reader: &mut BufReader<T>,
        subject: &str,
        payload: &Value,
        username: Option<&str>,
        password: Option<&str>,
        token: Option<&str>,
        tls: bool,
    ) -> Result<(), String>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        let timeout_duration = Self::alert_delivery_http_timeout();
        let mut info = String::new();
        let _ = timeout(timeout_duration, reader.read_line(&mut info)).await;

        let payload_raw = serde_json::to_string(payload).map_err(|err| {
            bilingual_runtime_error(
                "序列化 NATS 告警消息失败",
                format!("serialize nats payload failed: {err}"),
            )
        })?;
        let mut connect_payload = json!({
            "verbose": false,
            "pedantic": false,
            "tls_required": tls,
        });
        if let Some(token) = token {
            let token = token.trim();
            if token.is_empty() {
                return Err(bilingual_runtime_error(
                    "NATS token 为空",
                    "nats token is empty",
                ));
            }
            connect_payload["auth_token"] = Value::String(token.to_string());
        } else if let (Some(username), Some(password)) = (username, password) {
            let username = username.trim();
            let password = password.trim();
            if username.is_empty() || password.is_empty() {
                return Err(bilingual_runtime_error(
                    "NATS 用户名或密码为空",
                    "nats username or password is empty",
                ));
            }
            connect_payload["user"] = Value::String(username.to_string());
            connect_payload["pass"] = Value::String(password.to_string());
        }
        let connect_raw = serde_json::to_string(&connect_payload).map_err(|err| {
            bilingual_runtime_error(
                "序列化 NATS CONNECT 载荷失败",
                format!("serialize nats connect payload failed: {err}"),
            )
        })?;
        let connect_line = format!("CONNECT {connect_raw}\r\n");
        let publish_line = format!(
            "PUB {} {}\r\n{}\r\nPING\r\n",
            subject,
            payload_raw.as_bytes().len(),
            payload_raw
        );
        timeout(
            timeout_duration,
            reader
                .get_mut()
                .write_all(format!("{connect_line}{publish_line}").as_bytes()),
        )
        .await
        .map_err(|_| bilingual_runtime_error("写入 NATS 消息超时", "write nats message timed out"))?
        .map_err(|err| {
            bilingual_runtime_error(
                "写入 NATS 消息失败",
                format!("write nats message failed: {err}"),
            )
        })?;
        timeout(timeout_duration, reader.get_mut().flush())
            .await
            .map_err(|_| {
                bilingual_runtime_error("刷新 NATS 消息超时", "flush nats message timed out")
            })?
            .map_err(|err| {
                bilingual_runtime_error(
                    "刷新 NATS 消息失败",
                    format!("flush nats message failed: {err}"),
                )
            })?;

        for _ in 0..4 {
            let mut line = String::new();
            let size = timeout(timeout_duration, reader.read_line(&mut line))
                .await
                .map_err(|_| {
                    bilingual_runtime_error("读取 NATS 响应超时", "read nats response timed out")
                })?
                .map_err(|err| {
                    bilingual_runtime_error(
                        "读取 NATS 响应失败",
                        format!("read nats response failed: {err}"),
                    )
                })?;
            if size == 0 {
                break;
            }
            let trimmed = line.trim();
            if trimmed.eq_ignore_ascii_case("PONG") {
                return Ok(());
            }
            if trimmed.starts_with("-ERR") {
                return Err(bilingual_runtime_error(
                    "NATS 返回错误响应",
                    format!("nats responded with error: {trimmed}"),
                ));
            }
        }
        Err(bilingual_runtime_error(
            "NATS 未返回确认响应",
            "nats did not return acknowledge response",
        ))
    }

    async fn alert_delivery_send_nats(
        server: &str,
        subject: &str,
        payload: &Value,
        username: Option<&str>,
        password: Option<&str>,
        token: Option<&str>,
        tls: bool,
    ) -> Result<(), String> {
        let timeout_duration = Self::alert_delivery_http_timeout();
        let stream = timeout(timeout_duration, TcpStream::connect(server))
            .await
            .map_err(|_| {
                bilingual_runtime_error(
                    "连接 NATS 服务器超时",
                    format!("connect nats server timed out: {server}"),
                )
            })?
            .map_err(|err| {
                bilingual_runtime_error(
                    "连接 NATS 服务器失败",
                    format!("connect nats server failed: {err}"),
                )
            })?;
        if tls {
            let tls_stream = Self::alert_delivery_tls_wrap(server, stream).await?;
            let mut reader = BufReader::new(tls_stream);
            return Self::alert_delivery_nats_publish(
                &mut reader,
                subject,
                payload,
                username,
                password,
                token,
                true,
            )
            .await;
        }
        let mut reader = BufReader::new(stream);
        Self::alert_delivery_nats_publish(
            &mut reader,
            subject,
            payload,
            username,
            password,
            token,
            false,
        )
        .await
    }

    fn alert_delivery_redis_command(parts: &[&str]) -> Vec<u8> {
        let mut output = Vec::new();
        output.extend_from_slice(format!("*{}\r\n", parts.len()).as_bytes());
        for part in parts {
            output.extend_from_slice(format!("${}\r\n", part.as_bytes().len()).as_bytes());
            output.extend_from_slice(part.as_bytes());
            output.extend_from_slice(b"\r\n");
        }
        output
    }

    async fn alert_delivery_redis_run_command<T>(
        reader: &mut BufReader<T>,
        command: &[&str],
        error_prefix_zh: &str,
        error_prefix_en: &str,
    ) -> Result<String, String>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        let timeout_duration = Self::alert_delivery_http_timeout();
        let payload = Self::alert_delivery_redis_command(command);
        timeout(timeout_duration, reader.get_mut().write_all(&payload))
            .await
            .map_err(|_| {
                bilingual_runtime_error(
                    error_prefix_zh,
                    format!("{error_prefix_en}: write timed out"),
                )
            })?
            .map_err(|err| {
                bilingual_runtime_error(
                    error_prefix_zh,
                    format!("{error_prefix_en}: write failed: {err}"),
                )
            })?;
        timeout(timeout_duration, reader.get_mut().flush())
            .await
            .map_err(|_| {
                bilingual_runtime_error(
                    error_prefix_zh,
                    format!("{error_prefix_en}: flush timed out"),
                )
            })?
            .map_err(|err| {
                bilingual_runtime_error(
                    error_prefix_zh,
                    format!("{error_prefix_en}: flush failed: {err}"),
                )
            })?;

        let mut line = String::new();
        let size = timeout(timeout_duration, reader.read_line(&mut line))
            .await
            .map_err(|_| {
                bilingual_runtime_error(
                    error_prefix_zh,
                    format!("{error_prefix_en}: read timed out"),
                )
            })?
            .map_err(|err| {
                bilingual_runtime_error(
                    error_prefix_zh,
                    format!("{error_prefix_en}: read failed: {err}"),
                )
            })?;
        if size == 0 {
            return Err(bilingual_runtime_error(
                error_prefix_zh,
                format!("{error_prefix_en}: empty response"),
            ));
        }
        let trimmed = line.trim();
        if trimmed.starts_with('-') {
            return Err(bilingual_runtime_error(
                error_prefix_zh,
                format!("{error_prefix_en}: {trimmed}"),
            ));
        }
        Ok(trimmed.to_string())
    }

    async fn alert_delivery_redis_publish<T>(
        reader: &mut BufReader<T>,
        channel: &str,
        payload: &Value,
        username: Option<&str>,
        password: Option<&str>,
    ) -> Result<(), String>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        if username.is_some() && password.is_none() {
            return Err(bilingual_runtime_error(
                "Redis 认证配置不完整",
                "redis auth requires both username and password when username is specified",
            ));
        }

        if let Some(password) = password {
            let password = password.trim();
            if password.is_empty() {
                return Err(bilingual_runtime_error(
                    "Redis 密码为空",
                    "redis password is empty",
                ));
            }
            if let Some(username) = username {
                let username = username.trim();
                if username.is_empty() {
                    return Err(bilingual_runtime_error(
                        "Redis 用户名为空",
                        "redis username is empty",
                    ));
                }
                let response = Self::alert_delivery_redis_run_command(
                    reader,
                    &["AUTH", username, password],
                    "Redis 认证失败",
                    "redis auth failed",
                )
                .await?;
                if response != "+OK" {
                    return Err(bilingual_runtime_error(
                        "Redis 认证返回异常",
                        format!("redis auth returned unexpected response: {response}"),
                    ));
                }
            } else {
                let response = Self::alert_delivery_redis_run_command(
                    reader,
                    &["AUTH", password],
                    "Redis 认证失败",
                    "redis auth failed",
                )
                .await?;
                if response != "+OK" {
                    return Err(bilingual_runtime_error(
                        "Redis 认证返回异常",
                        format!("redis auth returned unexpected response: {response}"),
                    ));
                }
            }
        }

        let payload_raw = serde_json::to_string(payload).map_err(|err| {
            bilingual_runtime_error(
                "序列化 Redis 通知载荷失败",
                format!("serialize redis payload failed: {err}"),
            )
        })?;
        let response = Self::alert_delivery_redis_run_command(
            reader,
            &["PUBLISH", channel, &payload_raw],
            "Redis 发布失败",
            "redis publish failed",
        )
        .await?;
        if !response.starts_with(':') {
            return Err(bilingual_runtime_error(
                "Redis 发布返回异常",
                format!("redis publish returned unexpected response: {response}"),
            ));
        }
        Ok(())
    }

    async fn alert_delivery_send_redis(
        server: &str,
        channel: &str,
        payload: &Value,
        username: Option<&str>,
        password: Option<&str>,
        tls: bool,
    ) -> Result<(), String> {
        let timeout_duration = Self::alert_delivery_http_timeout();
        let stream = timeout(timeout_duration, TcpStream::connect(server))
            .await
            .map_err(|_| {
                bilingual_runtime_error(
                    "连接 Redis 服务器超时",
                    format!("connect redis server timed out: {server}"),
                )
            })?
            .map_err(|err| {
                bilingual_runtime_error(
                    "连接 Redis 服务器失败",
                    format!("connect redis server failed: {err}"),
                )
            })?;
        if tls {
            let tls_stream = Self::alert_delivery_tls_wrap(server, stream).await?;
            let mut reader = BufReader::new(tls_stream);
            return Self::alert_delivery_redis_publish(
                &mut reader,
                channel,
                payload,
                username,
                password,
            )
            .await;
        }
        let mut reader = BufReader::new(stream);
        Self::alert_delivery_redis_publish(&mut reader, channel, payload, username, password).await
    }

    fn alert_delivery_template_value(payload: &Value, expression: &str) -> Option<String> {
        let expression = expression
            .trim()
            .trim_start_matches("payload.")
            .trim_start_matches("$.")
            .trim_start_matches('.');
        if expression.is_empty() {
            return Some(String::new());
        }
        let mut current = payload;
        for segment in expression.split('.') {
            let segment = segment.trim();
            if segment.is_empty() {
                continue;
            }
            current = match current {
                Value::Object(map) => map.get(segment)?,
                _ => return None,
            };
        }
        match current {
            Value::Null => Some(String::new()),
            Value::String(value) => Some(value.clone()),
            Value::Bool(value) => Some(value.to_string()),
            Value::Number(value) => Some(value.to_string()),
            Value::Array(_) | Value::Object(_) => serde_json::to_string(current).ok(),
        }
    }

    fn alert_delivery_render_template(template: &str, payload: &Value) -> Result<String, String> {
        let mut rendered = String::new();
        let mut remaining = template;
        while let Some(start) = remaining.find("{{") {
            rendered.push_str(&remaining[..start]);
            let placeholder = &remaining[start + 2..];
            let Some(end) = placeholder.find("}}") else {
                return Err(bilingual_runtime_error(
                    "通知模板占位符未闭合",
                    "alert template contains an unclosed placeholder",
                ));
            };
            let expression = placeholder[..end].trim();
            let value =
                Self::alert_delivery_template_value(payload, expression).unwrap_or_default();
            rendered.push_str(&value);
            remaining = &placeholder[end + 2..];
        }
        rendered.push_str(remaining);
        Ok(rendered)
    }

    fn alert_delivery_render_headers(
        channel: &AlertChannel,
        payload: &Value,
    ) -> Result<Vec<(String, String)>, String> {
        let mut headers = channel
            .headers
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect::<Vec<_>>();
        for (key, template) in &channel.header_template {
            headers.push((
                key.clone(),
                Self::alert_delivery_render_template(template, payload)?,
            ));
        }
        Ok(headers)
    }

    fn alert_delivery_render_http_body(
        channel: &AlertChannel,
        payload: &Value,
    ) -> Result<(String, Vec<u8>), String> {
        let kind = channel.kind.trim().to_ascii_lowercase();
        let rendered_template = match channel.payload_template.as_deref() {
            Some(template) => Some(Self::alert_delivery_render_template(template, payload)?),
            None => None,
        };
        match kind.as_str() {
            "kafka" => {
                let value = match rendered_template {
                    Some(rendered) => serde_json::from_str::<Value>(&rendered)
                        .unwrap_or_else(|_| Value::String(rendered)),
                    None => payload.clone(),
                };
                let body = serde_json::to_vec(&json!({ "records": [{ "value": value }] }))
                    .map_err(|err| {
                        bilingual_runtime_error(
                            "序列化 Kafka 通知载荷失败",
                            format!("serialize kafka payload failed: {err}"),
                        )
                    })?;
                Ok(("application/vnd.kafka.json.v2+json".to_string(), body))
            }
            "rabbitmq" => {
                let routing_key = reqwest::Url::parse(channel.endpoint.trim())
                    .ok()
                    .and_then(|url| {
                        url.query_pairs()
                            .find(|(key, _)| key == "routing_key")
                            .map(|(_, value)| value.to_string())
                    })
                    .unwrap_or_else(|| "rustio.alerts".to_string());
                let payload_string = match rendered_template {
                    Some(rendered) => rendered,
                    None => serde_json::to_string(payload).map_err(|err| {
                        bilingual_runtime_error(
                            "序列化 RabbitMQ 通知载荷失败",
                            format!("serialize rabbitmq payload failed: {err}"),
                        )
                    })?,
                };
                let body = serde_json::to_vec(&json!({
                    "properties": {},
                    "routing_key": routing_key,
                    "payload": payload_string,
                    "payload_encoding": "string",
                }))
                .map_err(|err| {
                    bilingual_runtime_error(
                        "序列化 RabbitMQ 发布载荷失败",
                        format!("serialize rabbitmq publish payload failed: {err}"),
                    )
                })?;
                Ok(("application/json".to_string(), body))
            }
            _ => {
                if let Some(rendered) = rendered_template {
                    let content_type = if serde_json::from_str::<Value>(&rendered).is_ok() {
                        "application/json".to_string()
                    } else {
                        "text/plain; charset=utf-8".to_string()
                    };
                    return Ok((content_type, rendered.into_bytes()));
                }
                let body = serde_json::to_vec(payload).map_err(|err| {
                    bilingual_runtime_error(
                        "序列化 HTTP 通知载荷失败",
                        format!("serialize http payload failed: {err}"),
                    )
                })?;
                Ok(("application/json".to_string(), body))
            }
        }
    }

    pub async fn dispatch_alert_channel_message(
        &self,
        channel: &AlertChannel,
        payload: &Value,
    ) -> Result<(), String> {
        if !channel.enabled {
            return Err(bilingual_runtime_error(
                "通知渠道已禁用",
                format!("alert channel {} is disabled", channel.id),
            ));
        }
        let endpoint = channel.endpoint.trim();
        if endpoint.is_empty() {
            return Err(bilingual_runtime_error(
                "通知渠道地址为空",
                format!("alert channel {} endpoint is empty", channel.id),
            ));
        }
        let kind = channel.kind.trim().to_ascii_lowercase();
        if endpoint.starts_with("http://") || endpoint.starts_with("https://") {
            let client = Client::builder()
                .timeout(Self::alert_delivery_http_timeout())
                .build()
                .map_err(|err| {
                    bilingual_runtime_error(
                        "创建告警投递客户端失败",
                        format!("build alert delivery client failed: {err}"),
                    )
                })?;
            let (content_type, body) = Self::alert_delivery_render_http_body(channel, payload)?;
            let mut request = client.post(endpoint).body(body);
            let mut content_type_present = false;
            for (key, value) in Self::alert_delivery_render_headers(channel, payload)? {
                if key.eq_ignore_ascii_case("content-type") {
                    content_type_present = true;
                }
                request = request.header(&key, value);
            }
            if !content_type_present {
                request = request.header("content-type", content_type);
            }
            let response = request.send().await.map_err(|err| {
                bilingual_runtime_error(
                    "发送告警通知失败",
                    format!("alert channel {} request failed: {err}", channel.id),
                )
            })?;
            if !response.status().is_success() {
                let status = response.status();
                let body = response.text().await.unwrap_or_default();
                let summary = Self::replication_remote_response_summary(&body);
                return Err(bilingual_runtime_error(
                    "告警通道返回非成功状态",
                    format!(
                        "alert channel {} responded {} body={summary}",
                        channel.id, status
                    ),
                ));
            }
            return Ok(());
        }

        match kind.as_str() {
            "email" => {
                if let Some((server, recipient, transport)) =
                    Self::alert_delivery_parse_smtp_endpoint(endpoint)
                {
                    let from = Self::alert_delivery_smtp_from();
                    let (server, endpoint_username, endpoint_password) =
                        Self::alert_delivery_parse_smtp_server_auth(&server);
                    let username = endpoint_username.or_else(Self::alert_delivery_smtp_username);
                    let password = endpoint_password.or_else(Self::alert_delivery_smtp_password);
                    if username.is_some() ^ password.is_some() {
                        return Err(bilingual_runtime_error(
                            "SMTP 认证配置不完整",
                            "smtp auth requires both username and password",
                        ));
                    }
                    return Self::alert_delivery_send_smtp(
                        &server,
                        &from,
                        &recipient,
                        payload,
                        username.as_deref(),
                        password.as_deref(),
                        transport,
                    )
                    .await;
                }
                if endpoint.contains('@') {
                    if let Some(server) = Self::alert_delivery_smtp_server() {
                        let from = Self::alert_delivery_smtp_from();
                        let (server_with_auth, transport) =
                            Self::alert_delivery_parse_smtp_server_transport(&server);
                        let (server, endpoint_username, endpoint_password) =
                            Self::alert_delivery_parse_smtp_server_auth(&server_with_auth);
                        let username =
                            endpoint_username.or_else(Self::alert_delivery_smtp_username);
                        let password =
                            endpoint_password.or_else(Self::alert_delivery_smtp_password);
                        if username.is_some() ^ password.is_some() {
                            return Err(bilingual_runtime_error(
                                "SMTP 认证配置不完整",
                                "smtp auth requires both username and password",
                            ));
                        }
                        return Self::alert_delivery_send_smtp(
                            &server,
                            &from,
                            endpoint,
                            payload,
                            username.as_deref(),
                            password.as_deref(),
                            transport,
                        )
                        .await;
                    }
                    return self.alert_delivery_write_spool("email", payload);
                }
                Err(bilingual_runtime_error(
                    "邮件通知地址无效",
                    format!("email endpoint is invalid: {}", channel.endpoint),
                ))
            }
            "nats" => {
                let Some((server, subject_opt, tls)) =
                    Self::alert_delivery_parse_nats_endpoint(endpoint)
                else {
                    return Err(bilingual_runtime_error(
                        "NATS 通知地址无效",
                        format!("nats endpoint is invalid: {}", channel.endpoint),
                    ));
                };
                let subject = subject_opt.unwrap_or_else(Self::alert_delivery_nats_default_subject);
                let (server, endpoint_username, endpoint_password, endpoint_token) =
                    Self::alert_delivery_parse_nats_server_auth(&server);
                let token = endpoint_token.or_else(Self::alert_delivery_nats_token);
                let username = endpoint_username.or_else(Self::alert_delivery_nats_username);
                let password = endpoint_password.or_else(Self::alert_delivery_nats_password);
                if token.is_some() && (username.is_some() || password.is_some()) {
                    return Err(bilingual_runtime_error(
                        "NATS 认证配置冲突",
                        "nats auth cannot use token and username/password together",
                    ));
                }
                if username.is_some() ^ password.is_some() {
                    return Err(bilingual_runtime_error(
                        "NATS 认证配置不完整",
                        "nats auth requires both username and password",
                    ));
                }
                Self::alert_delivery_send_nats(
                    &server,
                    &subject,
                    payload,
                    username.as_deref(),
                    password.as_deref(),
                    token.as_deref(),
                    tls,
                )
                .await
            }
            "redis" => {
                let Some((server, channel_opt, tls)) =
                    Self::alert_delivery_parse_redis_endpoint(endpoint)
                else {
                    return Err(bilingual_runtime_error(
                        "Redis 通知地址无效",
                        format!("redis endpoint is invalid: {}", channel.endpoint),
                    ));
                };
                let channel_name =
                    channel_opt.unwrap_or_else(Self::alert_delivery_redis_default_channel);
                let (server, endpoint_username, endpoint_password) =
                    Self::alert_delivery_parse_redis_server_auth(&server);
                let username = endpoint_username.or_else(Self::alert_delivery_redis_username);
                let password = endpoint_password.or_else(Self::alert_delivery_redis_password);
                if username.is_some() && password.is_none() {
                    return Err(bilingual_runtime_error(
                        "Redis 认证配置不完整",
                        "redis auth requires password when username is specified",
                    ));
                }
                Self::alert_delivery_send_redis(
                    &server,
                    &channel_name,
                    payload,
                    username.as_deref(),
                    password.as_deref(),
                    tls,
                )
                .await
            }
            "webhook" | "slack" | "elasticsearch" | "kafka" | "rabbitmq" => {
                Err(bilingual_runtime_error(
                    "通知渠道地址协议无效",
                    format!(
                        "channel {} kind {} requires http(s) endpoint",
                        channel.id, kind
                    ),
                ))
            }
            _ => Err(bilingual_runtime_error(
                "通知渠道类型不支持",
                format!("unsupported alert channel kind: {}", channel.kind),
            )),
        }
    }

    fn notification_event_matches(rule_event: &str, event_name: &str) -> bool {
        let rule_event = rule_event.trim();
        if rule_event.is_empty() {
            return false;
        }
        if rule_event.eq_ignore_ascii_case(event_name) {
            return true;
        }
        if let Some(prefix) = rule_event.strip_suffix('*') {
            return event_name.starts_with(prefix);
        }
        false
    }

    fn notification_key_matches(rule: &BucketNotificationRule, key: &str) -> bool {
        let prefix_matches = rule
            .prefix
            .as_deref()
            .map(|prefix| key.starts_with(prefix))
            .unwrap_or(true);
        let suffix_matches = rule
            .suffix
            .as_deref()
            .map(|suffix| key.ends_with(suffix))
            .unwrap_or(true);
        prefix_matches && suffix_matches
    }

    fn notification_target_channel_id(target: &str) -> Option<String> {
        target
            .strip_prefix("arn:rustio:alert-channel:")
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
    }

    fn notification_target_kind(target: &str) -> Option<String> {
        let normalized = target.trim();
        if normalized.starts_with("http://") || normalized.starts_with("https://") {
            return Some("webhook".to_string());
        }
        if normalized.starts_with("redis://") || normalized.starts_with("rediss://") {
            return Some("redis".to_string());
        }
        if normalized.starts_with("nats://") || normalized.starts_with("natss://") {
            return Some("nats".to_string());
        }
        if normalized.starts_with("smtp://")
            || normalized.starts_with("smtp+starttls://")
            || normalized.starts_with("smtps://")
            || normalized.contains('@')
        {
            return Some("email".to_string());
        }
        None
    }

    async fn enqueue_bucket_notification_deliveries(
        &self,
        bucket: &str,
        key: &str,
        event_name: &str,
        object_meta: Option<&S3ObjectMeta>,
        origin: &str,
    ) -> Result<usize, String> {
        let rules = self
            .bucket_notifications
            .read()
            .await
            .get(bucket)
            .cloned()
            .unwrap_or_default();
        if rules.is_empty() {
            return Ok(0);
        }

        let channels = self.alert_channels.read().await.clone();
        let now = Utc::now();
        let mut queue = self.alert_delivery_queue.write().await;
        let mut enqueued = 0usize;

        for rule in rules.into_iter().filter(|rule| {
            rule.enabled
                && Self::notification_event_matches(&rule.event, event_name)
                && Self::notification_key_matches(rule, key)
        }) {
            let target = rule.target.trim();
            if target.is_empty() {
                continue;
            }

            let resolved_channel = if let Some(channel) = channels
                .iter()
                .find(|channel| channel.id == target)
                .cloned()
            {
                channel
            } else if let Some(channel_id) = Self::notification_target_channel_id(target) {
                let Some(channel) = channels
                    .iter()
                    .find(|channel| channel.id == channel_id)
                    .cloned()
                else {
                    return Err(bilingual_runtime_error(
                        "桶通知目标渠道不存在",
                        format!("bucket notification target channel not found: {target}"),
                    ));
                };
                channel
            } else {
                let kind = Self::notification_target_kind(target).ok_or_else(|| {
                    bilingual_runtime_error(
                        "桶通知目标不支持",
                        format!("bucket notification target is unsupported: {target}"),
                    )
                })?;
                AlertChannel {
                    id: format!("bucket-notification-{}", sha256_hex(target.as_bytes())),
                    name: format!("bucket-notification:{bucket}:{}", rule.id),
                    kind,
                    endpoint: target.to_string(),
                    headers: HashMap::new(),
                    payload_template: None,
                    header_template: HashMap::new(),
                    enabled: true,
                    status: "unknown".to_string(),
                    last_checked_at: now,
                    error: None,
                }
            };

            let idempotency_key = format!(
                "bucket-notification:{}:{}:{}:{}:{}",
                bucket, key, event_name, rule.id, resolved_channel.id
            );
            if queue.iter().any(|item| {
                item.idempotency_key == idempotency_key
                    && matches!(item.status.as_str(), "pending" | "in_progress" | "done")
            }) {
                continue;
            }

            let payload = json!({
                "kind": "bucket-notification",
                "bucket": bucket,
                "key": key,
                "event": event_name,
                "origin": origin,
                "rule_id": rule.id,
                "rule_event": rule.event,
                "target": rule.target,
                "triggered_at": now,
                "object": object_meta.map(|meta| json!({
                    "version_id": meta.version_id,
                    "size": meta.size,
                    "etag": meta.etag,
                    "delete_marker": meta.delete_marker,
                    "created_at": meta.created_at,
                })),
            });

            queue.push(AlertDeliveryItem {
                id: format!("alert-delivery-{}", Uuid::new_v4().simple()),
                history_id: format!("bucket-notification-{}", Uuid::new_v4().simple()),
                rule_id: None,
                channel_id: resolved_channel.id,
                channel_kind: resolved_channel.kind,
                endpoint: resolved_channel.endpoint,
                status: "pending".to_string(),
                attempts: 0,
                last_error: String::new(),
                lease_owner: None,
                lease_until: None,
                queued_at: now,
                last_attempt_at: None,
                next_attempt_at: now,
                payload,
                idempotency_key,
            });
            enqueued += 1;
        }

        Ok(enqueued)
    }

    pub async fn emit_bucket_object_event(
        &self,
        bucket: &str,
        key: &str,
        event_name: &str,
        object_meta: Option<&S3ObjectMeta>,
        origin: &str,
    ) -> Result<usize, String> {
        let enqueued = self
            .enqueue_bucket_notification_deliveries(bucket, key, event_name, object_meta, origin)
            .await?;
        self.push_event(
            "bucket.notification.enqueued",
            "bucket-notification-worker",
            json!({
                "bucket": bucket,
                "key": key,
                "event": event_name,
                "origin": origin,
                "enqueued": enqueued,
            }),
        )
        .await;
        Ok(enqueued)
    }

    async fn mark_alert_channel_delivery_result(
        &self,
        channel_id: &str,
        success: bool,
        last_error: Option<String>,
    ) {
        let mut channels = self.alert_channels.write().await;
        let Some(channel) = channels.iter_mut().find(|channel| channel.id == channel_id) else {
            return;
        };
        channel.last_checked_at = Utc::now();
        if !channel.enabled {
            channel.status = "paused".to_string();
            channel.error = Some(bilingual_runtime_error(
                "通知渠道已禁用",
                format!("alert channel {} is disabled", channel.id),
            ));
            return;
        }
        if success {
            channel.status = "healthy".to_string();
            channel.error = None;
        } else {
            channel.status = "degraded".to_string();
            channel.error = Some(last_error.unwrap_or_else(|| {
                bilingual_runtime_error("告警投递失败", "alert delivery failed")
            }));
        }
    }

    pub async fn enqueue_alert_deliveries(
        &self,
        entry: &AlertHistoryEntry,
    ) -> Result<usize, String> {
        if !matches!(entry.status.as_str(), "firing" | "resolved") {
            return Ok(0);
        }
        let Some(rule_id) = entry.rule_id.as_ref() else {
            return Ok(0);
        };
        let rules = self.alert_rules.read().await;
        let Some(rule) = rules.iter().find(|rule| rule.id == *rule_id).cloned() else {
            return Ok(0);
        };
        drop(rules);
        let escalations = self.alert_escalations.read().await.clone();
        let channels = self.alert_channels.read().await.clone();

        let mut channel_ids = Vec::<String>::new();
        for channel_id in &rule.channels {
            if !channel_ids.iter().any(|item| item == channel_id) {
                channel_ids.push(channel_id.clone());
            }
        }
        for escalation in escalations.iter().filter(|escalation| {
            escalation.enabled && escalation.severity.eq_ignore_ascii_case(&entry.severity)
        }) {
            for channel_id in &escalation.channels {
                if !channel_ids.iter().any(|item| item == channel_id) {
                    channel_ids.push(channel_id.clone());
                }
            }
        }
        if channel_ids.is_empty() {
            return Ok(0);
        }

        let now = Utc::now();
        let mut queue = self.alert_delivery_queue.write().await;
        let mut enqueued = 0usize;
        for channel_id in channel_ids {
            let Some(channel) = channels.iter().find(|channel| channel.id == channel_id) else {
                continue;
            };
            let idempotency_key = format!("{}:{}", entry.id, channel.id);
            if queue.iter().any(|item| {
                item.idempotency_key == idempotency_key
                    && matches!(item.status.as_str(), "pending" | "in_progress" | "done")
            }) {
                continue;
            }
            if let Some(existing) = queue
                .iter_mut()
                .find(|item| item.idempotency_key == idempotency_key)
            {
                existing.status = "pending".to_string();
                existing.attempts = 0;
                existing.last_error.clear();
                existing.lease_owner = None;
                existing.lease_until = None;
                existing.last_attempt_at = None;
                existing.next_attempt_at = now;
                existing.payload = json!({
                    "history_id": entry.id,
                    "rule_id": entry.rule_id,
                    "rule_name": entry.rule_name,
                    "severity": entry.severity,
                    "status": entry.status,
                    "message": entry.message,
                    "triggered_at": entry.triggered_at,
                    "details": entry.details,
                    "channel_id": channel.id,
                    "channel_kind": channel.kind,
                });
                enqueued += 1;
                continue;
            }
            queue.push(AlertDeliveryItem {
                id: format!("alert-delivery-{}", Uuid::new_v4().simple()),
                history_id: entry.id.clone(),
                rule_id: entry.rule_id.clone(),
                channel_id: channel.id.clone(),
                channel_kind: channel.kind.clone(),
                endpoint: channel.endpoint.clone(),
                status: "pending".to_string(),
                attempts: 0,
                last_error: String::new(),
                lease_owner: None,
                lease_until: None,
                queued_at: now,
                last_attempt_at: None,
                next_attempt_at: now,
                payload: json!({
                    "history_id": entry.id,
                    "rule_id": entry.rule_id,
                    "rule_name": entry.rule_name,
                    "severity": entry.severity,
                    "status": entry.status,
                    "message": entry.message,
                    "triggered_at": entry.triggered_at,
                    "details": entry.details,
                    "channel_id": channel.id,
                    "channel_kind": channel.kind,
                }),
                idempotency_key,
            });
            enqueued += 1;
        }
        Ok(enqueued)
    }

    async fn process_alert_delivery_item(&self, item: &AlertDeliveryItem) -> Result<(), String> {
        let channels = self.alert_channels.read().await;
        let channel = channels
            .iter()
            .find(|channel| channel.id == item.channel_id)
            .cloned()
            .ok_or_else(|| {
                bilingual_runtime_error(
                    "通知渠道不存在",
                    format!("alert channel {} not found", item.channel_id),
                )
            })?;
        drop(channels);
        self.dispatch_alert_channel_message(&channel, &item.payload)
            .await
    }

    async fn process_alert_delivery_queue_once(&self, worker_id: &str) -> usize {
        let now = Utc::now();
        let lease_until = now
            + Duration::from_std(Self::alert_delivery_lease_interval())
                .unwrap_or_else(|_| Duration::seconds(1));
        let picked_item = {
            let mut queue = self.alert_delivery_queue.write().await;
            let mut picked_index = None::<usize>;
            let mut picked_time = None::<DateTime<Utc>>;
            for (index, item) in queue.iter().enumerate() {
                let lease_expired = item.lease_until.map(|value| value <= now).unwrap_or(true);
                let ready = matches!(item.status.as_str(), "pending" | "failed")
                    || (item.status == "in_progress" && lease_expired);
                if !ready {
                    continue;
                }
                if item.next_attempt_at > now {
                    continue;
                }
                if picked_time
                    .map(|value| item.next_attempt_at < value)
                    .unwrap_or(true)
                {
                    picked_index = Some(index);
                    picked_time = Some(item.next_attempt_at);
                }
            }
            let Some(index) = picked_index else {
                return 0;
            };
            let Some(entry) = queue.get_mut(index) else {
                return 0;
            };
            entry.status = "in_progress".to_string();
            entry.attempts += 1;
            entry.last_attempt_at = Some(now);
            entry.lease_owner = Some(worker_id.to_string());
            entry.lease_until = Some(lease_until);
            entry.clone()
        };

        let result = self.process_alert_delivery_item(&picked_item).await;
        let max_attempts = Self::alert_delivery_max_attempts();
        let mut channel_success = false;
        let mut channel_error = None::<String>;
        {
            let mut queue = self.alert_delivery_queue.write().await;
            if let Some(entry) = queue.iter_mut().find(|entry| entry.id == picked_item.id) {
                match result {
                    Ok(_) => {
                        entry.status = "done".to_string();
                        entry.last_error.clear();
                        entry.lease_owner = None;
                        entry.lease_until = None;
                        entry.next_attempt_at = now;
                        channel_success = true;
                    }
                    Err(err) => {
                        let error = bilingual_runtime_error(
                            "告警投递失败",
                            format!(
                                "alert delivery to channel {} failed: {err}",
                                entry.channel_id
                            ),
                        );
                        channel_error = Some(error.clone());
                        if entry.attempts >= max_attempts {
                            entry.status = "dead_letter".to_string();
                            entry.lease_owner = None;
                            entry.lease_until = None;
                            entry.last_error = bilingual_runtime_error(
                                "告警投递达到最大重试次数，进入死信队列",
                                format!(
                                    "alert delivery reached max attempts {} and moved to dead-letter: {}",
                                    max_attempts, error
                                ),
                            );
                        } else {
                            entry.status = "failed".to_string();
                            entry.lease_owner = None;
                            entry.lease_until = None;
                            entry.last_error = error.clone();
                            let retry_delay = Self::alert_delivery_retry_delay(entry.attempts);
                            entry.next_attempt_at = now
                                + Duration::from_std(retry_delay)
                                    .unwrap_or_else(|_| Duration::seconds(1));
                        }
                    }
                }
            } else {
                return 0;
            }
        }
        self.mark_alert_channel_delivery_result(
            &picked_item.channel_id,
            channel_success,
            channel_error,
        )
        .await;
        1
    }

    fn managed_async_job_worker_interval() -> std::time::Duration {
        let millis = std::env::var("RUSTIO_ASYNC_JOB_WORKER_INTERVAL_MS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(200);
        std::time::Duration::from_millis(millis)
    }

    fn managed_async_job_lease_interval() -> std::time::Duration {
        let millis = std::env::var("RUSTIO_ASYNC_JOB_LEASE_MS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(5_000);
        std::time::Duration::from_millis(millis)
    }

    fn managed_async_job_max_attempts() -> u32 {
        std::env::var("RUSTIO_ASYNC_JOB_MAX_ATTEMPTS")
            .ok()
            .and_then(|value| value.parse::<u32>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(3)
    }

    fn managed_async_job_kind(kind: &str) -> Option<&'static str> {
        let normalized = kind.trim().to_ascii_lowercase();
        if normalized.starts_with("batch:") {
            None
        } else if normalized.contains("lifecycle") {
            Some("lifecycle")
        } else if normalized.contains("site-bootstrap") || normalized.contains("bootstrap") {
            Some("site-bootstrap")
        } else if normalized.contains("site-join") || normalized.contains("join") {
            Some("site-join")
        } else if normalized.contains("site-resync") || normalized.contains("resync") {
            Some("site-resync")
        } else if normalized.contains("site-reconcile") || normalized.contains("reconcile") {
            Some("site-reconcile")
        } else if normalized.contains("failover") {
            Some("failover")
        } else if normalized.contains("failback") {
            Some("failback")
        } else {
            None
        }
    }

    fn managed_async_job_dedupe_key(job: &JobStatus) -> String {
        job.payload
            .get("dedupe_key")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .map(|value| value.to_string())
            .unwrap_or_else(|| job.idempotency_key.clone())
    }

    fn build_managed_async_job(
        &self,
        kind: &str,
        priority: u8,
        bucket: Option<String>,
        object_key: Option<String>,
        site_id: Option<String>,
        idempotency_key: String,
        checkpoint: Option<u64>,
        payload: Value,
    ) -> JobStatus {
        let now = Utc::now();
        let mut payload_map = payload.as_object().cloned().unwrap_or_default();
        payload_map
            .entry("dedupe_key".to_string())
            .or_insert_with(|| Value::String(idempotency_key.clone()));
        JobStatus {
            id: format!("job-{}-{}", kind.replace(':', "-"), Uuid::new_v4().simple()),
            kind: kind.to_string(),
            status: "pending".to_string(),
            priority: i32::from(priority),
            bucket,
            object_key,
            site_id,
            idempotency_key,
            attempt: 0,
            lease_owner: None,
            lease_until: None,
            checkpoint,
            last_error: None,
            payload: Value::Object(payload_map),
            progress: 0.0,
            created_at: now,
            updated_at: now,
            key: None,
            version_id: None,
            target: None,
            affected_disks: vec![],
            missing_shards: 0,
            corrupted_shards: 0,
            started_at: None,
            finished_at: None,
            attempts: 0,
            max_attempts: 0,
            next_attempt_at: None,
            error: None,
            dedupe_key: None,
            source: None,
            details: Value::Null,
        }
    }

    async fn mutate_job<F>(&self, job_id: &str, mutator: F) -> Option<JobStatus>
    where
        F: FnOnce(&mut JobStatus),
    {
        let mut jobs = self.jobs.write().await;
        let job = jobs.iter_mut().find(|job| job.id == job_id)?;
        mutator(job);
        Some(job.clone())
    }

    async fn enqueue_lifecycle_job_if_absent(&self, job: JobStatus) -> bool {
        let dedupe_key = Self::managed_async_job_dedupe_key(&job);
        let mut blocked = false;
        let mut jobs = self.jobs.write().await;
        jobs.retain(|existing| {
            if Self::managed_async_job_kind(&existing.kind) != Some("lifecycle")
                || Self::managed_async_job_dedupe_key(existing) != dedupe_key
            {
                return true;
            }
            match existing.status.as_str() {
                "pending" => false,
                "in_progress" | "running" | "failed" | "dead_letter" => {
                    blocked = true;
                    true
                }
                _ => true,
            }
        });
        if blocked {
            return false;
        }
        jobs.push(job);
        true
    }

    fn lifecycle_job_matches_existing_filters(
        existing_jobs: &[JobStatus],
        dedupe_key: &str,
        statuses: Option<&HashSet<String>>,
        retry_only_failed: bool,
    ) -> bool {
        if statuses.is_none() && !retry_only_failed {
            return true;
        }
        existing_jobs.iter().any(|job| {
            if Self::managed_async_job_kind(&job.kind) != Some("lifecycle") {
                return false;
            }
            if Self::managed_async_job_dedupe_key(job) != dedupe_key {
                return false;
            }
            let normalized_status = job.status.trim().to_ascii_lowercase();
            if retry_only_failed && !matches!(normalized_status.as_str(), "failed" | "dead_letter")
            {
                return false;
            }
            statuses
                .map(|filter| filter.contains(&normalized_status))
                .unwrap_or(true)
        })
    }

    fn lifecycle_current_job_draft(
        &self,
        bucket: &str,
        meta: &S3ObjectMeta,
        active_rules: &[BucketLifecycleRule],
        remote_tiers: &HashMap<String, RemoteTierConfig>,
        now: DateTime<Utc>,
    ) -> Option<LifecycleJobDraft> {
        let transition_tier = active_rules.iter().find_map(|rule| {
            if !Self::lifecycle_rule_matches(rule, &meta.key) {
                return None;
            }
            let tier = Self::lifecycle_current_transition_target(rule, meta, now)?;
            remote_tiers
                .get(&tier)
                .filter(|config| config.enabled)
                .map(|_| tier)
        });
        if let Some(tier) = transition_tier {
            let idempotency_key = format!(
                "lifecycle:transition-current:{}:{}:{}:{}",
                bucket, meta.key, meta.version_id, tier
            );
            return Some(LifecycleJobDraft {
                kind: "lifecycle:transition-current".to_string(),
                bucket: bucket.to_string(),
                object_key: meta.key.clone(),
                idempotency_key: idempotency_key.clone(),
                payload: json!({
                    "mode": "transition-current",
                    "version_id": meta.version_id,
                    "tier": tier,
                    "dedupe_key": idempotency_key,
                }),
            });
        }

        let should_expire = active_rules.iter().any(|rule| {
            Self::lifecycle_rule_matches(rule, &meta.key)
                && rule
                    .expiration_days
                    .map(|days| {
                        now.signed_duration_since(meta.created_at) >= Duration::days(days as i64)
                    })
                    .unwrap_or(false)
        });
        if !should_expire {
            return None;
        }

        let idempotency_key = format!(
            "lifecycle:current:{}:{}:{}",
            bucket, meta.key, meta.version_id
        );
        Some(LifecycleJobDraft {
            kind: "lifecycle:current".to_string(),
            bucket: bucket.to_string(),
            object_key: meta.key.clone(),
            idempotency_key: idempotency_key.clone(),
            payload: json!({
                "mode": "current",
                "version_id": meta.version_id,
                "dedupe_key": idempotency_key,
            }),
        })
    }

    fn lifecycle_noncurrent_job_draft(
        &self,
        bucket: &str,
        meta: &S3ObjectMeta,
        active_rules: &[BucketLifecycleRule],
        remote_tiers: &HashMap<String, RemoteTierConfig>,
        now: DateTime<Utc>,
    ) -> Option<LifecycleJobDraft> {
        let transition_tier = active_rules.iter().find_map(|rule| {
            if !Self::lifecycle_rule_matches(rule, &meta.key) {
                return None;
            }
            let tier = Self::lifecycle_noncurrent_transition_target(rule, meta, now)?;
            remote_tiers
                .get(&tier)
                .filter(|config| config.enabled)
                .map(|_| tier)
        });
        if let Some(tier) = transition_tier {
            let idempotency_key = format!(
                "lifecycle:transition-noncurrent:{}:{}:{}:{}",
                bucket, meta.key, meta.version_id, tier
            );
            return Some(LifecycleJobDraft {
                kind: "lifecycle:transition-noncurrent".to_string(),
                bucket: bucket.to_string(),
                object_key: meta.key.clone(),
                idempotency_key: idempotency_key.clone(),
                payload: json!({
                    "mode": "transition-noncurrent",
                    "version_id": meta.version_id,
                    "tier": tier,
                    "dedupe_key": idempotency_key,
                }),
            });
        }

        let should_expire = active_rules.iter().any(|rule| {
            Self::lifecycle_rule_matches(rule, &meta.key)
                && rule
                    .noncurrent_expiration_days
                    .map(|days| {
                        now.signed_duration_since(meta.created_at) >= Duration::days(days as i64)
                    })
                    .unwrap_or(false)
        });
        if !should_expire {
            return None;
        }

        let idempotency_key = format!(
            "lifecycle:noncurrent:{}:{}:{}",
            bucket, meta.key, meta.version_id
        );
        Some(LifecycleJobDraft {
            kind: "lifecycle:noncurrent".to_string(),
            bucket: bucket.to_string(),
            object_key: meta.key.clone(),
            idempotency_key: idempotency_key.clone(),
            payload: json!({
                "mode": "noncurrent",
                "version_id": meta.version_id,
                "dedupe_key": idempotency_key,
            }),
        })
    }

    fn build_lifecycle_job_from_draft(&self, draft: &LifecycleJobDraft) -> JobStatus {
        let checkpoint = self.next_replication_checkpoint();
        self.build_managed_async_job(
            &draft.kind,
            1,
            Some(draft.bucket.clone()),
            Some(draft.object_key.clone()),
            None,
            draft.idempotency_key.clone(),
            Some(checkpoint),
            draft.payload.clone(),
        )
    }

    async fn enqueue_lifecycle_batch_job(&self, draft: &LifecycleJobDraft) -> bool {
        let job = self.build_lifecycle_job_from_draft(draft);
        let dedupe_key = Self::managed_async_job_dedupe_key(&job);
        let mut blocked = false;
        let mut jobs = self.jobs.write().await;
        jobs.retain(|existing| {
            if Self::managed_async_job_kind(&existing.kind) != Some("lifecycle")
                || Self::managed_async_job_dedupe_key(existing) != dedupe_key
            {
                return true;
            }
            if matches!(existing.status.as_str(), "in_progress" | "running") {
                blocked = true;
                return true;
            }
            false
        });
        if blocked {
            return false;
        }
        jobs.push(job);
        true
    }

    pub async fn enqueue_lifecycle_batch_run(
        &self,
        scope: &BatchRunScope,
    ) -> Result<(usize, usize, usize), String> {
        let bucket = scope.source_bucket.as_deref().ok_or_else(|| {
            bilingual_runtime_error(
                "生命周期批处理必须提供源桶",
                "lifecycle batch run requires source bucket",
            )
        })?;
        let rules = self
            .bucket_lifecycle_rules
            .read()
            .await
            .get(bucket)
            .cloned()
            .unwrap_or_default();
        let active_rules = rules
            .into_iter()
            .filter(|rule| {
                rule.status.eq_ignore_ascii_case("enabled")
                    && scope
                        .rule_id
                        .as_deref()
                        .map(|rule_id| rule.id == rule_id)
                        .unwrap_or(true)
            })
            .collect::<Vec<_>>();
        if active_rules.is_empty() {
            return Err(bilingual_runtime_error(
                "未找到匹配的启用生命周期规则",
                "no enabled lifecycle rule matched this batch run",
            ));
        }

        let remote_tiers = self.remote_tiers.read().await.clone();
        let existing_jobs = self.jobs.read().await.clone();
        let status_filter = (!scope.statuses.is_empty())
            .then(|| scope.statuses.iter().cloned().collect::<HashSet<String>>());
        let now = Utc::now();
        let bucket_root = self.lifecycle_bucket_root(bucket).await;
        let current_meta_root = bucket_root.join(".rustio_meta");
        let archived_meta_root = bucket_root.join(".rustio_versions");
        let current_metas = Self::lifecycle_scan_object_metas(&current_meta_root, bucket);
        let archived_metas = Self::lifecycle_scan_object_metas(&archived_meta_root, bucket);
        let mut candidates = Vec::<LifecycleJobDraft>::new();

        if !scope.noncurrent_only {
            for meta in current_metas {
                if meta.delete_marker {
                    continue;
                }
                if scope
                    .object_prefix
                    .as_deref()
                    .map(|prefix| !meta.key.starts_with(prefix))
                    .unwrap_or(false)
                {
                    continue;
                }
                let Some(draft) = self.lifecycle_current_job_draft(
                    bucket,
                    &meta,
                    &active_rules,
                    &remote_tiers,
                    now,
                ) else {
                    continue;
                };
                if !Self::lifecycle_job_matches_existing_filters(
                    &existing_jobs,
                    &draft.idempotency_key,
                    status_filter.as_ref(),
                    scope.retry_only_failed,
                ) {
                    continue;
                }
                candidates.push(draft);
            }
        }

        if !scope.current_only {
            for meta in archived_metas {
                if scope
                    .object_prefix
                    .as_deref()
                    .map(|prefix| !meta.key.starts_with(prefix))
                    .unwrap_or(false)
                {
                    continue;
                }
                let Some(draft) = self.lifecycle_noncurrent_job_draft(
                    bucket,
                    &meta,
                    &active_rules,
                    &remote_tiers,
                    now,
                ) else {
                    continue;
                };
                if !Self::lifecycle_job_matches_existing_filters(
                    &existing_jobs,
                    &draft.idempotency_key,
                    status_filter.as_ref(),
                    scope.retry_only_failed,
                ) {
                    continue;
                }
                candidates.push(draft);
            }
        }

        candidates.sort_by(|left, right| {
            left.kind
                .cmp(&right.kind)
                .then_with(|| left.object_key.cmp(&right.object_key))
                .then_with(|| left.idempotency_key.cmp(&right.idempotency_key))
        });

        let matched = candidates.len();
        let selected = scope.limit.unwrap_or(matched).min(matched);
        let mut enqueued = 0usize;
        for draft in candidates.into_iter().take(selected) {
            if self.enqueue_lifecycle_batch_job(&draft).await {
                enqueued += 1;
            }
        }

        Ok((matched, enqueued, matched.saturating_sub(enqueued)))
    }

    pub async fn enqueue_switch_job(&self, job: JobStatus) -> Result<JobStatus, String> {
        let dedupe_key = Self::managed_async_job_dedupe_key(&job);
        let kind = Self::managed_async_job_kind(&job.kind).unwrap_or("switch");
        let mut jobs = self.jobs.write().await;
        if jobs.iter().any(|existing| {
            Self::managed_async_job_kind(&existing.kind) == Some(kind)
                && Self::managed_async_job_dedupe_key(existing) == dedupe_key
                && matches!(
                    existing.status.as_str(),
                    "pending" | "in_progress" | "running"
                )
        }) {
            return Err(bilingual_runtime_error(
                "切换任务已存在",
                format!("{kind} task is already pending or running"),
            ));
        }
        jobs.retain(|existing| {
            !(Self::managed_async_job_kind(&existing.kind) == Some(kind)
                && Self::managed_async_job_dedupe_key(existing) == dedupe_key
                && matches!(
                    existing.status.as_str(),
                    "failed" | "dead_letter" | "skipped"
                ))
        });
        jobs.push(job.clone());
        Ok(job)
    }

    fn lifecycle_interval() -> std::time::Duration {
        let millis = std::env::var("RUSTIO_LIFECYCLE_INTERVAL_MS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(60_000);
        std::time::Duration::from_millis(millis)
    }

    async fn lifecycle_bucket_root(&self, bucket: &str) -> PathBuf {
        let sites = self.site_replications.read().await.clone();
        if let Some(active_site) = sites
            .iter()
            .find(|site| site.role == "primary" && !site.preferred_primary)
            .map(|site| site.site_id.clone())
        {
            let rules = self.replications.read().await.clone();
            if rules.iter().any(|rule| {
                rule.source_bucket == bucket
                    && rule.target_site == active_site
                    && rule.status != "paused"
            }) {
                return self
                    .data_dir
                    .join(".rustio_sites")
                    .join(active_site)
                    .join("data")
                    .join(bucket);
            }
        }
        self.data_dir.join(bucket)
    }

    fn lifecycle_collect_json_files(root: &std::path::Path, output: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(root) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_dir() {
                Self::lifecycle_collect_json_files(&path, output);
                continue;
            }
            if file_type.is_file()
                && path.extension().and_then(|value| value.to_str()) == Some("json")
            {
                output.push(path);
            }
        }
    }

    fn lifecycle_scan_object_metas(root: &std::path::Path, bucket: &str) -> Vec<S3ObjectMeta> {
        let mut files = Vec::new();
        Self::lifecycle_collect_json_files(root, &mut files);
        let mut metas = Vec::new();
        let mut seen = HashSet::new();
        for path in files {
            let Ok(bytes) = std::fs::read(&path) else {
                continue;
            };
            let Ok(meta) = serde_json::from_slice::<S3ObjectMeta>(&bytes) else {
                continue;
            };
            if meta.bucket != bucket || meta.key.is_empty() {
                continue;
            }
            let dedupe_key = format!("{}:{}", meta.key, meta.version_id);
            if seen.insert(dedupe_key) {
                metas.push(meta);
            }
        }
        metas
    }

    fn lifecycle_rule_matches(rule: &BucketLifecycleRule, key: &str) -> bool {
        rule.status.eq_ignore_ascii_case("enabled")
            && rule
                .prefix
                .as_deref()
                .map(|prefix| key.starts_with(prefix))
                .unwrap_or(true)
    }

    fn lifecycle_current_transition_target(
        rule: &BucketLifecycleRule,
        meta: &S3ObjectMeta,
        now: DateTime<Utc>,
    ) -> Option<String> {
        let tier = rule.transition_tier.as_deref()?.trim();
        if tier.is_empty() || meta.delete_marker || meta.remote_tier.is_some() {
            return None;
        }
        let days = rule.transition_days?;
        (now.signed_duration_since(meta.created_at) >= Duration::days(days as i64))
            .then(|| tier.to_string())
    }

    fn lifecycle_noncurrent_transition_target(
        rule: &BucketLifecycleRule,
        meta: &S3ObjectMeta,
        now: DateTime<Utc>,
    ) -> Option<String> {
        let tier = rule.noncurrent_transition_tier.as_deref()?.trim();
        if tier.is_empty() || meta.remote_tier.is_some() {
            return None;
        }
        let days = rule.noncurrent_transition_days?;
        (now.signed_duration_since(meta.created_at) >= Duration::days(days as i64))
            .then(|| tier.to_string())
    }

    async fn process_bucket_lifecycle_once(&self) -> Result<usize, String> {
        let buckets = self.bucket_lifecycle_rules.read().await.clone();
        let remote_tiers = self.remote_tiers.read().await.clone();
        let mut enqueued = 0usize;
        let now = Utc::now();

        for (bucket, rules) in buckets {
            let active_rules = rules
                .into_iter()
                .filter(|rule| rule.status.eq_ignore_ascii_case("enabled"))
                .collect::<Vec<_>>();
            if active_rules.is_empty() {
                continue;
            }

            let bucket_root = self.lifecycle_bucket_root(&bucket).await;
            let current_meta_root = bucket_root.join(".rustio_meta");
            let archived_meta_root = bucket_root.join(".rustio_versions");
            let current_metas = Self::lifecycle_scan_object_metas(&current_meta_root, &bucket);
            let archived_metas = Self::lifecycle_scan_object_metas(&archived_meta_root, &bucket);

            for meta in current_metas {
                if meta.delete_marker {
                    continue;
                }
                let transition_tier = active_rules.iter().find_map(|rule| {
                    if !Self::lifecycle_rule_matches(rule, &meta.key) {
                        return None;
                    }
                    let tier = Self::lifecycle_current_transition_target(rule, &meta, now)?;
                    remote_tiers
                        .get(&tier)
                        .filter(|config| config.enabled)
                        .map(|_| tier)
                });
                if let Some(tier) = transition_tier {
                    let checkpoint = self.next_replication_checkpoint();
                    let idempotency_key = format!(
                        "lifecycle:transition-current:{}:{}:{}:{}",
                        bucket, meta.key, meta.version_id, tier
                    );
                    let job = self.build_managed_async_job(
                        "lifecycle:transition-current",
                        1,
                        Some(bucket.clone()),
                        Some(meta.key.clone()),
                        None,
                        idempotency_key.clone(),
                        Some(checkpoint),
                        json!({
                            "mode": "transition-current",
                            "version_id": meta.version_id,
                            "tier": tier,
                            "dedupe_key": idempotency_key,
                        }),
                    );
                    if self.enqueue_lifecycle_job_if_absent(job).await {
                        enqueued += 1;
                    }
                    continue;
                }
                let should_expire = active_rules.iter().any(|rule| {
                    Self::lifecycle_rule_matches(rule, &meta.key)
                        && rule
                            .expiration_days
                            .map(|days| {
                                now.signed_duration_since(meta.created_at)
                                    >= Duration::days(days as i64)
                            })
                            .unwrap_or(false)
                });
                if !should_expire {
                    continue;
                }
                let checkpoint = self.next_replication_checkpoint();
                let idempotency_key = format!(
                    "lifecycle:current:{}:{}:{}",
                    bucket, meta.key, meta.version_id
                );
                let job = self.build_managed_async_job(
                    "lifecycle:current",
                    1,
                    Some(bucket.clone()),
                    Some(meta.key.clone()),
                    None,
                    idempotency_key.clone(),
                    Some(checkpoint),
                    json!({
                        "mode": "current",
                        "version_id": meta.version_id,
                        "dedupe_key": idempotency_key,
                    }),
                );
                if self.enqueue_lifecycle_job_if_absent(job).await {
                    enqueued += 1;
                }
            }

            for meta in archived_metas {
                let transition_tier = active_rules.iter().find_map(|rule| {
                    if !Self::lifecycle_rule_matches(rule, &meta.key) {
                        return None;
                    }
                    let tier = Self::lifecycle_noncurrent_transition_target(rule, &meta, now)?;
                    remote_tiers
                        .get(&tier)
                        .filter(|config| config.enabled)
                        .map(|_| tier)
                });
                if let Some(tier) = transition_tier {
                    let checkpoint = self.next_replication_checkpoint();
                    let idempotency_key = format!(
                        "lifecycle:transition-noncurrent:{}:{}:{}:{}",
                        bucket, meta.key, meta.version_id, tier
                    );
                    let job = self.build_managed_async_job(
                        "lifecycle:transition-noncurrent",
                        1,
                        Some(bucket.clone()),
                        Some(meta.key.clone()),
                        None,
                        idempotency_key.clone(),
                        Some(checkpoint),
                        json!({
                            "mode": "transition-noncurrent",
                            "version_id": meta.version_id,
                            "tier": tier,
                            "dedupe_key": idempotency_key,
                        }),
                    );
                    if self.enqueue_lifecycle_job_if_absent(job).await {
                        enqueued += 1;
                    }
                    continue;
                }
                let should_expire = active_rules.iter().any(|rule| {
                    Self::lifecycle_rule_matches(rule, &meta.key)
                        && rule
                            .noncurrent_expiration_days
                            .map(|days| {
                                now.signed_duration_since(meta.created_at)
                                    >= Duration::days(days as i64)
                            })
                            .unwrap_or(false)
                });
                if !should_expire {
                    continue;
                }
                let checkpoint = self.next_replication_checkpoint();
                let idempotency_key = format!(
                    "lifecycle:noncurrent:{}:{}:{}",
                    bucket, meta.key, meta.version_id
                );
                let job = self.build_managed_async_job(
                    "lifecycle:noncurrent",
                    1,
                    Some(bucket.clone()),
                    Some(meta.key.clone()),
                    None,
                    idempotency_key.clone(),
                    Some(checkpoint),
                    json!({
                        "mode": "noncurrent",
                        "version_id": meta.version_id,
                        "dedupe_key": idempotency_key,
                    }),
                );
                if self.enqueue_lifecycle_job_if_absent(job).await {
                    enqueued += 1;
                }
            }
        }

        Ok(enqueued)
    }

    async fn ensure_site_bucket_roots(&self, site_id: &str) {
        let buckets = self
            .replications
            .read()
            .await
            .iter()
            .filter(|rule| rule.target_site == site_id)
            .map(|rule| rule.source_bucket.clone())
            .collect::<HashSet<_>>();
        for bucket in buckets {
            let path = self
                .data_dir
                .join(".rustio_sites")
                .join(site_id)
                .join("data")
                .join(bucket);
            let _ = tokio::fs::create_dir_all(path).await;
        }
    }

    fn site_bucket_root_path(&self, site_id: &str, bucket: &str) -> PathBuf {
        self.data_dir
            .join(".rustio_sites")
            .join(site_id)
            .join("data")
            .join(bucket)
    }

    async fn site_managed_buckets(&self, site_id: &str) -> HashSet<String> {
        self.replications
            .read()
            .await
            .iter()
            .filter(|rule| rule.target_site == site_id)
            .map(|rule| rule.source_bucket.clone())
            .collect::<HashSet<_>>()
    }

    async fn count_site_bucket_root_drift(&self, site_id: &str) -> u32 {
        let buckets = self.site_managed_buckets(site_id).await;
        let mut missing = 0u32;
        for bucket in buckets {
            if !tokio::fs::try_exists(self.site_bucket_root_path(site_id, &bucket))
                .await
                .unwrap_or(false)
            {
                missing += 1;
            }
        }
        missing
    }

    async fn copy_directory_tree(
        &self,
        source_root: &std::path::Path,
        target_root: &std::path::Path,
    ) -> Result<u64, String> {
        let mut queue = VecDeque::new();
        let mut copied_files = 0u64;
        queue.push_back((source_root.to_path_buf(), target_root.to_path_buf()));

        while let Some((source_dir, target_dir)) = queue.pop_front() {
            let mut entries = tokio::fs::read_dir(&source_dir).await.map_err(|err| {
                bilingual_runtime_error(
                    "读取回迁目录失败",
                    format!("failed to read recovery directory: {err}"),
                )
            })?;
            tokio::fs::create_dir_all(&target_dir)
                .await
                .map_err(|err| {
                    bilingual_runtime_error(
                        "创建回迁目录失败",
                        format!("failed to create recovery directory: {err}"),
                    )
                })?;

            while let Some(entry) = entries.next_entry().await.map_err(|err| {
                bilingual_runtime_error(
                    "遍历回迁目录失败",
                    format!("failed to iterate recovery directory: {err}"),
                )
            })? {
                let source_path = entry.path();
                let target_path = target_dir.join(entry.file_name());
                let file_type = entry.file_type().await.map_err(|err| {
                    bilingual_runtime_error(
                        "读取文件类型失败",
                        format!("failed to read file type: {err}"),
                    )
                })?;
                if file_type.is_dir() {
                    queue.push_back((source_path, target_path));
                    continue;
                }
                if !file_type.is_file() {
                    continue;
                }
                if let Some(parent) = target_path.parent() {
                    tokio::fs::create_dir_all(parent).await.map_err(|err| {
                        bilingual_runtime_error(
                            "创建目标目录失败",
                            format!("failed to create target directory: {err}"),
                        )
                    })?;
                }
                tokio::fs::copy(&source_path, &target_path)
                    .await
                    .map_err(|err| {
                        bilingual_runtime_error(
                            "复制文件失败",
                            format!("failed to copy file during recovery: {err}"),
                        )
                    })?;
                copied_files += 1;
            }
        }

        Ok(copied_files)
    }

    async fn recover_failback_object_space(&self, source_site_id: &str) -> Result<u64, String> {
        if source_site_id.trim().is_empty() || source_site_id == "unknown" {
            return Ok(0);
        }

        let buckets = self
            .replications
            .read()
            .await
            .iter()
            .filter(|rule| rule.target_site == source_site_id)
            .map(|rule| rule.source_bucket.clone())
            .collect::<HashSet<_>>();
        let mut recovered_files = 0u64;
        for bucket in buckets {
            let source_root = self
                .data_dir
                .join(".rustio_sites")
                .join(source_site_id)
                .join("data")
                .join(&bucket);
            if !tokio::fs::try_exists(&source_root).await.unwrap_or(false) {
                continue;
            }
            let target_root = self.data_dir.join(&bucket);
            tokio::fs::create_dir_all(&target_root)
                .await
                .map_err(|err| {
                    bilingual_runtime_error(
                        "创建主站存储桶目录失败",
                        format!("failed to create primary bucket directory: {err}"),
                    )
                })?;
            recovered_files += self.copy_directory_tree(&source_root, &target_root).await?;
        }
        Ok(recovered_files)
    }

    async fn execute_lifecycle_job(&self, job: &JobStatus) -> Result<(), String> {
        let bucket = job.bucket.as_ref().cloned().ok_or_else(|| {
            bilingual_runtime_error("生命周期任务缺少桶名", "lifecycle job missing bucket")
        })?;
        let object_key = job.object_key.as_ref().cloned().ok_or_else(|| {
            bilingual_runtime_error("生命周期任务缺少对象键", "lifecycle job missing object key")
        })?;
        let mode = job
            .payload
            .get("mode")
            .and_then(Value::as_str)
            .unwrap_or("current");

        match mode {
            "current" => {
                if let Some(result_meta) =
                    expire_current_object_for_lifecycle(self, &bucket, &object_key).await?
                {
                    if let Err(err) = self
                        .emit_bucket_object_event(
                            &bucket,
                            &object_key,
                            "s3:ObjectRemoved:Delete",
                            Some(&result_meta),
                            "lifecycle-expiration",
                        )
                        .await
                    {
                        self.push_event(
                            "bucket.notification.failed",
                            "bucket-notification-worker",
                            json!({
                                "bucket": bucket,
                                "key": object_key,
                                "event": "s3:ObjectRemoved:Delete",
                                "origin": "lifecycle-expiration",
                                "error": err,
                            }),
                        )
                        .await;
                    }
                    self.append_audit(
                        "system",
                        "bucket.lifecycle.expire.current",
                        &format!("bucket/{bucket}/{object_key}"),
                        "success",
                        Some("生命周期到期自动删除 / lifecycle automatic expiration".to_string()),
                        json!({
                            "bucket": bucket,
                            "key": object_key,
                            "version_id": result_meta.version_id,
                            "job_id": job.id,
                        }),
                    )
                    .await;
                }
            }
            "noncurrent" => {
                let version_id = job
                    .payload
                    .get("version_id")
                    .and_then(Value::as_str)
                    .filter(|value| !value.trim().is_empty())
                    .ok_or_else(|| {
                        bilingual_runtime_error(
                            "生命周期任务缺少版本号",
                            "lifecycle noncurrent job missing version id",
                        )
                    })?
                    .to_string();
                if expire_noncurrent_object_version_for_lifecycle(
                    self,
                    &bucket,
                    &object_key,
                    &version_id,
                )
                .await?
                {
                    self.append_audit(
                        "system",
                        "bucket.lifecycle.expire.noncurrent",
                        &format!("bucket/{bucket}/{object_key}?versionId={version_id}"),
                        "success",
                        Some(
                            "生命周期到期自动删除非当前版本 / lifecycle automatic noncurrent expiration"
                                .to_string(),
                        ),
                        json!({
                            "bucket": bucket,
                            "key": object_key,
                            "version_id": version_id,
                            "job_id": job.id,
                        }),
                    )
                    .await;
                }
            }
            "transition-current" => {
                let tier = job
                    .payload
                    .get("tier")
                    .and_then(Value::as_str)
                    .filter(|value| !value.trim().is_empty())
                    .ok_or_else(|| {
                        bilingual_runtime_error(
                            "生命周期转层任务缺少目标层",
                            "lifecycle transition job missing target tier",
                        )
                    })?
                    .to_string();
                if let Some(result_meta) =
                    transition_current_object_for_lifecycle(self, &bucket, &object_key, &tier)
                        .await?
                {
                    self.append_audit(
                        "system",
                        "bucket.lifecycle.transition.current",
                        &format!("bucket/{bucket}/{object_key}"),
                        "success",
                        Some(
                            "生命周期转层当前版本 / lifecycle transition current object"
                                .to_string(),
                        ),
                        json!({
                            "bucket": bucket,
                            "key": object_key,
                            "version_id": result_meta.version_id,
                            "tier": tier,
                            "job_id": job.id,
                        }),
                    )
                    .await;
                }
            }
            "transition-noncurrent" => {
                let version_id = job
                    .payload
                    .get("version_id")
                    .and_then(Value::as_str)
                    .filter(|value| !value.trim().is_empty())
                    .ok_or_else(|| {
                        bilingual_runtime_error(
                            "生命周期转层任务缺少版本号",
                            "lifecycle transition noncurrent job missing version id",
                        )
                    })?
                    .to_string();
                let tier = job
                    .payload
                    .get("tier")
                    .and_then(Value::as_str)
                    .filter(|value| !value.trim().is_empty())
                    .ok_or_else(|| {
                        bilingual_runtime_error(
                            "生命周期转层任务缺少目标层",
                            "lifecycle transition job missing target tier",
                        )
                    })?
                    .to_string();
                if transition_noncurrent_object_version_for_lifecycle(
                    self,
                    &bucket,
                    &object_key,
                    &version_id,
                    &tier,
                )
                .await?
                {
                    self.append_audit(
                        "system",
                        "bucket.lifecycle.transition.noncurrent",
                        &format!("bucket/{bucket}/{object_key}?versionId={version_id}"),
                        "success",
                        Some(
                            "生命周期转层非当前版本 / lifecycle transition noncurrent object"
                                .to_string(),
                        ),
                        json!({
                            "bucket": bucket,
                            "key": object_key,
                            "version_id": version_id,
                            "tier": tier,
                            "job_id": job.id,
                        }),
                    )
                    .await;
                }
            }
            _ => {
                return Err(bilingual_runtime_error(
                    "生命周期任务模式无效",
                    format!("unsupported lifecycle job mode: {mode}"),
                ));
            }
        }
        Ok(())
    }

    async fn execute_site_bootstrap_job(&self, job: &JobStatus) -> Result<(), String> {
        let site_id = job.site_id.as_ref().cloned().ok_or_else(|| {
            bilingual_runtime_error(
                "Bootstrap 任务缺少站点 ID",
                "site bootstrap job missing site id",
            )
        })?;
        let operator = job
            .payload
            .get("operator")
            .and_then(Value::as_str)
            .unwrap_or("system");
        let reason = job
            .payload
            .get("reason")
            .and_then(Value::as_str)
            .map(|value| value.to_string());
        let endpoint = job
            .payload
            .get("endpoint")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                bilingual_runtime_error(
                    "Bootstrap 任务缺少 endpoint",
                    "site bootstrap job missing endpoint",
                )
            })?
            .to_string();
        let preferred_primary = job
            .payload
            .get("preferred_primary")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let _ = self
            .mutate_job(&job.id, |entry| {
                entry.progress = entry.progress.max(0.25);
                entry.updated_at = Utc::now();
            })
            .await;

        let managed_buckets = self.site_managed_buckets(&site_id).await.len() as u32;
        self.ensure_site_bucket_roots(&site_id).await;
        let now = Utc::now();
        let role = {
            let mut sites = self.site_replications.write().await;
            if sites.iter().any(|site| site.site_id == site_id) {
                return Err(bilingual_runtime_error(
                    "复制站点已存在",
                    format!("replication site {site_id} already exists"),
                ));
            }
            let has_primary = sites.iter().any(|site| site.role == "primary");
            let role = if preferred_primary && !has_primary {
                "primary".to_string()
            } else {
                "secondary".to_string()
            };
            sites.push(SiteReplicationStatus {
                site_id: site_id.clone(),
                endpoint: endpoint.clone(),
                role: role.clone(),
                preferred_primary,
                state: "healthy".to_string(),
                lag_seconds: 0,
                managed_buckets,
                last_sync_at: now,
                bootstrap_state: "bootstrapped".to_string(),
                joined_at: Some(now),
                last_resync_at: Some(now),
                last_reconcile_at: Some(now),
                pending_resync_items: 0,
                drifted_buckets: 0,
                topology_version: 1,
                last_error: None,
            });
            role
        };
        let _ = self
            .mutate_job(&job.id, |entry| {
                entry.progress = entry.progress.max(0.8);
                entry.updated_at = Utc::now();
            })
            .await;
        self.append_audit(
            operator,
            "replication.site.bootstrap",
            &format!("replication/site/{site_id}"),
            "success",
            reason.clone(),
            json!({
                "site_id": site_id,
                "endpoint": endpoint,
                "role": role,
                "preferred_primary": preferred_primary,
                "job_id": job.id,
            }),
        )
        .await;
        self.push_event(
            "replication.site.bootstrap",
            "replication-site-manager",
            json!({
                "site_id": site_id,
                "endpoint": endpoint,
                "operator": operator,
                "job_id": job.id,
            }),
        )
        .await;
        Ok(())
    }

    async fn execute_site_join_job(&self, job: &JobStatus) -> Result<(), String> {
        let site_id = job.site_id.as_ref().cloned().ok_or_else(|| {
            bilingual_runtime_error("Join 任务缺少站点 ID", "site join job missing site id")
        })?;
        let operator = job
            .payload
            .get("operator")
            .and_then(Value::as_str)
            .unwrap_or("system");
        let reason = job
            .payload
            .get("reason")
            .and_then(Value::as_str)
            .map(|value| value.to_string());
        let endpoint = job
            .payload
            .get("endpoint")
            .and_then(Value::as_str)
            .map(|value| value.to_string());
        let _ = self
            .mutate_job(&job.id, |entry| {
                entry.progress = entry.progress.max(0.25);
                entry.updated_at = Utc::now();
            })
            .await;

        let managed_buckets = self.site_managed_buckets(&site_id).await.len() as u32;
        self.ensure_site_bucket_roots(&site_id).await;
        let now = Utc::now();
        let (created, effective_endpoint) = {
            let mut sites = self.site_replications.write().await;
            if let Some(site) = sites.iter_mut().find(|site| site.site_id == site_id) {
                if let Some(endpoint) = endpoint.clone() {
                    site.endpoint = endpoint;
                }
                site.state = "healthy".to_string();
                site.bootstrap_state = "joined".to_string();
                site.joined_at.get_or_insert(now);
                site.last_sync_at = now;
                site.last_error = None;
                site.managed_buckets = managed_buckets;
                site.topology_version += 1;
                (false, site.endpoint.clone())
            } else {
                let effective_endpoint =
                    endpoint.unwrap_or_else(|| format!("https://{site_id}.example.internal"));
                sites.push(SiteReplicationStatus {
                    site_id: site_id.clone(),
                    endpoint: effective_endpoint.clone(),
                    role: "secondary".to_string(),
                    preferred_primary: false,
                    state: "healthy".to_string(),
                    lag_seconds: 0,
                    managed_buckets,
                    last_sync_at: now,
                    bootstrap_state: "joined".to_string(),
                    joined_at: Some(now),
                    last_resync_at: None,
                    last_reconcile_at: None,
                    pending_resync_items: 0,
                    drifted_buckets: 0,
                    topology_version: 1,
                    last_error: None,
                });
                (true, effective_endpoint)
            }
        };
        let _ = self
            .mutate_job(&job.id, |entry| {
                entry.progress = entry.progress.max(0.8);
                entry.updated_at = Utc::now();
            })
            .await;
        self.append_audit(
            operator,
            "replication.site.join",
            &format!("replication/site/{site_id}"),
            "success",
            reason.clone(),
            json!({
                "site_id": site_id,
                "endpoint": effective_endpoint,
                "created": created,
                "job_id": job.id,
            }),
        )
        .await;
        self.push_event(
            "replication.site.join",
            "replication-site-manager",
            json!({
                "site_id": site_id,
                "endpoint": effective_endpoint,
                "created": created,
                "operator": operator,
                "job_id": job.id,
            }),
        )
        .await;
        Ok(())
    }

    async fn execute_site_resync_job(&self, job: &JobStatus) -> Result<(), String> {
        let site_id = job.site_id.as_ref().cloned().ok_or_else(|| {
            bilingual_runtime_error("Resync 任务缺少站点 ID", "site resync job missing site id")
        })?;
        let operator = job
            .payload
            .get("operator")
            .and_then(Value::as_str)
            .unwrap_or("system");
        let reason = job
            .payload
            .get("reason")
            .and_then(Value::as_str)
            .map(|value| value.to_string());
        let _ = self
            .mutate_job(&job.id, |entry| {
                entry.progress = entry.progress.max(0.25);
                entry.updated_at = Utc::now();
            })
            .await;

        let pending_items = self
            .replication_backlog
            .read()
            .await
            .iter()
            .filter(|item| {
                item.target_site == site_id && item.status != "done" && item.status != "completed"
            })
            .count() as u64;
        let checkpoint = self
            .replication_checkpoints
            .read()
            .await
            .get(&site_id)
            .copied();
        if let Some(value) = checkpoint {
            self.write_replication_checkpoint(&site_id, value).await;
        }
        self.ensure_site_bucket_roots(&site_id).await;
        let now = Utc::now();
        {
            let mut sites = self.site_replications.write().await;
            let site = sites
                .iter_mut()
                .find(|site| site.site_id == site_id)
                .ok_or_else(|| {
                    bilingual_runtime_error(
                        "复制站点不存在",
                        format!("replication site {site_id} not found"),
                    )
                })?;
            site.last_resync_at = Some(now);
            site.pending_resync_items = pending_items;
            site.state = if pending_items > 0 {
                "resyncing".to_string()
            } else {
                "healthy".to_string()
            };
            if pending_items == 0 {
                site.lag_seconds = 0;
                site.last_sync_at = now;
                site.last_error = None;
            }
        }
        let _ = self
            .mutate_job(&job.id, |entry| {
                entry.progress = entry.progress.max(0.8);
                entry.updated_at = Utc::now();
                entry.checkpoint = checkpoint;
            })
            .await;
        self.append_audit(
            operator,
            "replication.site.resync",
            &format!("replication/site/{site_id}"),
            "success",
            reason.clone(),
            json!({
                "site_id": site_id,
                "pending_resync_items": pending_items,
                "job_id": job.id,
                "checkpoint": checkpoint,
            }),
        )
        .await;
        self.push_event(
            "replication.site.resync",
            "replication-site-manager",
            json!({
                "site_id": site_id,
                "pending_resync_items": pending_items,
                "operator": operator,
                "job_id": job.id,
                "checkpoint": checkpoint,
            }),
        )
        .await;
        Ok(())
    }

    async fn execute_site_reconcile_job(&self, job: &JobStatus) -> Result<(), String> {
        let site_id = job.site_id.as_ref().cloned().ok_or_else(|| {
            bilingual_runtime_error(
                "Reconcile 任务缺少站点 ID",
                "site reconcile job missing site id",
            )
        })?;
        let operator = job
            .payload
            .get("operator")
            .and_then(Value::as_str)
            .unwrap_or("system");
        let reason = job
            .payload
            .get("reason")
            .and_then(Value::as_str)
            .map(|value| value.to_string());
        let _ = self
            .mutate_job(&job.id, |entry| {
                entry.progress = entry.progress.max(0.25);
                entry.updated_at = Utc::now();
            })
            .await;

        let drifted_before = self.count_site_bucket_root_drift(&site_id).await;
        self.ensure_site_bucket_roots(&site_id).await;
        let drifted_after = self.count_site_bucket_root_drift(&site_id).await;
        let managed_buckets = self.site_managed_buckets(&site_id).await.len() as u32;
        let now = Utc::now();
        {
            let mut sites = self.site_replications.write().await;
            let site = sites
                .iter_mut()
                .find(|site| site.site_id == site_id)
                .ok_or_else(|| {
                    bilingual_runtime_error(
                        "复制站点不存在",
                        format!("replication site {site_id} not found"),
                    )
                })?;
            site.managed_buckets = managed_buckets;
            site.drifted_buckets = drifted_after;
            site.last_reconcile_at = Some(now);
            if drifted_after == 0 {
                site.last_error = None;
                if site.state != "offline" {
                    site.state = if site.pending_resync_items > 0 {
                        "resyncing".to_string()
                    } else {
                        "healthy".to_string()
                    };
                }
            } else {
                site.state = "degraded".to_string();
            }
            site.topology_version += 1;
        }
        let _ = self
            .mutate_job(&job.id, |entry| {
                entry.progress = entry.progress.max(0.8);
                entry.updated_at = Utc::now();
            })
            .await;
        self.append_audit(
            operator,
            "replication.site.reconcile",
            &format!("replication/site/{site_id}"),
            "success",
            reason.clone(),
            json!({
                "site_id": site_id,
                "managed_buckets": managed_buckets,
                "drifted_before": drifted_before,
                "drifted_after": drifted_after,
                "job_id": job.id,
            }),
        )
        .await;
        self.push_event(
            "replication.site.reconcile",
            "replication-site-manager",
            json!({
                "site_id": site_id,
                "managed_buckets": managed_buckets,
                "drifted_before": drifted_before,
                "drifted_after": drifted_after,
                "operator": operator,
                "job_id": job.id,
            }),
        )
        .await;
        Ok(())
    }

    async fn execute_failover_job(&self, job: &JobStatus) -> Result<(), String> {
        let site_id = job.site_id.as_ref().cloned().ok_or_else(|| {
            bilingual_runtime_error("Failover 任务缺少站点 ID", "failover job missing site id")
        })?;
        let operator = job
            .payload
            .get("operator")
            .and_then(Value::as_str)
            .unwrap_or("system");
        let reason = job
            .payload
            .get("reason")
            .and_then(Value::as_str)
            .map(|value| value.to_string());
        let _ = self
            .mutate_job(&job.id, |entry| {
                entry.progress = entry.progress.max(0.35);
                entry.updated_at = Utc::now();
            })
            .await;

        let now = Utc::now();
        let previous_primary = {
            let mut sites = self.site_replications.write().await;
            let target_exists = sites.iter().any(|site| site.site_id == site_id);
            if !target_exists {
                return Err(bilingual_runtime_error(
                    "复制站点不存在",
                    format!("replication site {site_id} not found"),
                ));
            }
            let previous_primary = sites
                .iter()
                .find(|site| site.role == "primary")
                .map(|site| site.site_id.clone())
                .unwrap_or_else(|| "unknown".to_string());
            if previous_primary == site_id {
                return Err(bilingual_runtime_error(
                    "目标站点已是主站",
                    "selected site is already primary",
                ));
            }
            for site in sites.iter_mut() {
                if site.site_id == site_id {
                    site.role = "primary".to_string();
                    site.state = "healthy".to_string();
                    site.lag_seconds = 0;
                    site.last_sync_at = now;
                    site.last_error = None;
                } else {
                    site.role = "secondary".to_string();
                    if site.state != "offline" {
                        site.state = "healthy".to_string();
                    }
                    site.last_sync_at = now;
                }
            }
            previous_primary
        };
        let checkpoint = self
            .replication_checkpoints
            .read()
            .await
            .get(&site_id)
            .copied();
        if let Some(value) = checkpoint {
            self.write_replication_checkpoint(&site_id, value).await;
        }
        let _ = self
            .mutate_job(&job.id, |entry| {
                entry.progress = entry.progress.max(0.8);
                entry.updated_at = Utc::now();
                entry.checkpoint = checkpoint;
            })
            .await;
        self.ensure_site_bucket_roots(&site_id).await;
        self.append_audit(
            operator,
            "replication.site.failover",
            &format!("replication/site/{site_id}"),
            "success",
            reason.clone(),
            json!({
                "from": previous_primary,
                "to": site_id,
                "job_id": job.id,
                "checkpoint": checkpoint,
            }),
        )
        .await;
        self.push_event(
            "replication.site.failover",
            "replication-site-manager",
            json!({
                "from": previous_primary,
                "to": site_id,
                "operator": operator,
                "job_id": job.id,
                "checkpoint": checkpoint,
            }),
        )
        .await;
        Ok(())
    }

    async fn execute_failback_job(&self, job: &JobStatus) -> Result<(), String> {
        let site_id = job.site_id.as_ref().cloned().ok_or_else(|| {
            bilingual_runtime_error("Failback 任务缺少站点 ID", "failback job missing site id")
        })?;
        let operator = job
            .payload
            .get("operator")
            .and_then(Value::as_str)
            .unwrap_or("system");
        let reason = job
            .payload
            .get("reason")
            .and_then(Value::as_str)
            .map(|value| value.to_string());
        let previous_primary = {
            let sites = self.site_replications.read().await;
            let target = sites
                .iter()
                .find(|site| site.site_id == site_id)
                .cloned()
                .ok_or_else(|| {
                    bilingual_runtime_error(
                        "复制站点不存在",
                        format!("replication site {site_id} not found"),
                    )
                })?;
            if !target.preferred_primary {
                return Err(bilingual_runtime_error(
                    "Failback 目标必须是首选主站",
                    "failback target must be preferred primary site",
                ));
            }
            let previous_primary = sites
                .iter()
                .find(|site| site.role == "primary")
                .map(|site| site.site_id.clone())
                .unwrap_or_else(|| "unknown".to_string());
            if previous_primary == site_id {
                return Err(bilingual_runtime_error(
                    "目标站点已是主站",
                    "selected site is already primary",
                ));
            }
            previous_primary
        };
        let _ = self
            .mutate_job(&job.id, |entry| {
                entry.progress = entry.progress.max(0.35);
                entry.updated_at = Utc::now();
            })
            .await;
        let recovered_files = self
            .recover_failback_object_space(&previous_primary)
            .await?;
        let _ = self
            .mutate_job(&job.id, |entry| {
                entry.progress = entry.progress.max(0.7);
                entry.updated_at = Utc::now();
            })
            .await;

        let now = Utc::now();
        {
            let mut sites = self.site_replications.write().await;
            for site in sites.iter_mut() {
                if site.site_id == site_id {
                    site.role = "primary".to_string();
                    site.state = "healthy".to_string();
                    site.lag_seconds = 0;
                    site.last_sync_at = now;
                    site.last_error = None;
                } else {
                    site.role = "secondary".to_string();
                    if site.state != "offline" {
                        site.state = "healthy".to_string();
                    }
                    site.last_sync_at = now;
                }
            }
        }
        let checkpoint = self
            .replication_checkpoints
            .read()
            .await
            .get(&site_id)
            .copied();
        if let Some(value) = checkpoint {
            self.write_replication_checkpoint(&site_id, value).await;
        }
        self.ensure_site_bucket_roots(&site_id).await;
        self.append_audit(
            operator,
            "replication.site.failback",
            &format!("replication/site/{site_id}"),
            "success",
            reason.clone(),
            json!({
                "from": previous_primary,
                "to": site_id,
                "recovered_files": recovered_files,
                "job_id": job.id,
                "checkpoint": checkpoint,
            }),
        )
        .await;
        self.push_event(
            "replication.site.failback",
            "replication-site-manager",
            json!({
                "from": previous_primary,
                "to": site_id,
                "recovered_files": recovered_files,
                "operator": operator,
                "job_id": job.id,
                "checkpoint": checkpoint,
            }),
        )
        .await;
        Ok(())
    }

    async fn execute_managed_async_job(&self, job: &JobStatus) -> Result<(), String> {
        match Self::managed_async_job_kind(&job.kind) {
            Some("lifecycle") => self.execute_lifecycle_job(job).await,
            Some("site-bootstrap") => self.execute_site_bootstrap_job(job).await,
            Some("site-join") => self.execute_site_join_job(job).await,
            Some("site-resync") => self.execute_site_resync_job(job).await,
            Some("site-reconcile") => self.execute_site_reconcile_job(job).await,
            Some("failover") => self.execute_failover_job(job).await,
            Some("failback") => self.execute_failback_job(job).await,
            _ => Err(bilingual_runtime_error(
                "不支持的统一任务类型",
                format!("unsupported managed async job kind: {}", job.kind),
            )),
        }
    }

    pub async fn process_managed_async_jobs_once(&self, worker_id: &str) -> usize {
        let now = Utc::now();
        let lease_until = now
            + Duration::from_std(Self::managed_async_job_lease_interval())
                .unwrap_or_else(|_| Duration::seconds(5));
        let next_job = {
            let mut jobs = self.jobs.write().await;
            let mut picked_index = None::<usize>;
            let mut picked_priority = i32::MAX;
            let mut picked_checkpoint = u64::MAX;
            let mut picked_created_at = i64::MAX;

            for (index, job) in jobs.iter().enumerate() {
                if Self::managed_async_job_kind(&job.kind).is_none() {
                    continue;
                }
                let lease_expired = job.lease_until.map(|value| value <= now).unwrap_or(true);
                let ready =
                    job.status == "pending" || (job.status == "in_progress" && lease_expired);
                if !ready {
                    continue;
                }
                let checkpoint = job.checkpoint.unwrap_or(u64::MAX);
                let created_at = job.created_at.timestamp_millis();
                if job.priority < picked_priority
                    || (job.priority == picked_priority && checkpoint < picked_checkpoint)
                    || (job.priority == picked_priority
                        && checkpoint == picked_checkpoint
                        && created_at < picked_created_at)
                {
                    picked_index = Some(index);
                    picked_priority = job.priority;
                    picked_checkpoint = checkpoint;
                    picked_created_at = created_at;
                }
            }

            let Some(index) = picked_index else {
                return 0;
            };
            let Some(job) = jobs.get_mut(index) else {
                return 0;
            };
            job.status = "in_progress".to_string();
            job.attempt += 1;
            job.lease_owner = Some(worker_id.to_string());
            job.lease_until = Some(lease_until);
            job.progress = job.progress.max(0.1);
            job.updated_at = now;
            job.clone()
        };

        let result = self.execute_managed_async_job(&next_job).await;
        let max_attempts = Self::managed_async_job_max_attempts();
        let completed_at = Utc::now();
        match result {
            Ok(()) => {
                let _ = self
                    .mutate_job(&next_job.id, |job| {
                        job.status = "completed".to_string();
                        job.progress = 1.0;
                        job.last_error = None;
                        job.lease_owner = None;
                        job.lease_until = None;
                        job.updated_at = completed_at;
                    })
                    .await;
            }
            Err(err) => {
                let decorated_error = format!(
                    "{err}；可通过统一任务重试并检查回滚提示 / retry via unified async jobs and review rollback guidance"
                );
                let _ = self
                    .mutate_job(&next_job.id, |job| {
                        job.last_error = Some(decorated_error.clone());
                        job.lease_owner = None;
                        job.lease_until = None;
                        job.updated_at = completed_at;
                        if job.attempt >= max_attempts {
                            job.status = "dead_letter".to_string();
                            job.progress = job.progress.max(0.95);
                        } else {
                            job.status = "failed".to_string();
                            job.progress = job.progress.max(0.4);
                        }
                    })
                    .await;
            }
        }
        1
    }

    fn replication_item_matches_target(
        item: &ReplicationBacklogItem,
        source_bucket: &str,
        target_site: &str,
        object_key: &str,
    ) -> bool {
        item.source_bucket == source_bucket
            && item.target_site == target_site
            && item.object_key == object_key
    }

    fn replication_items_same_target(
        left: &ReplicationBacklogItem,
        right: &ReplicationBacklogItem,
    ) -> bool {
        Self::replication_item_matches_target(
            left,
            &right.source_bucket,
            &right.target_site,
            &right.object_key,
        )
    }

    fn replication_target_blocked(
        backlog: &[ReplicationBacklogItem],
        candidate_index: usize,
        now: &DateTime<Utc>,
    ) -> bool {
        let Some(candidate) = backlog.get(candidate_index) else {
            return true;
        };
        backlog.iter().enumerate().any(|(index, item)| {
            if index == candidate_index || !Self::replication_items_same_target(item, candidate) {
                return false;
            }
            let lease_active = item.lease_until.map(|value| value > *now).unwrap_or(false);
            if item.status == "in_progress" && lease_active {
                return true;
            }
            Self::replication_item_supersedable(&item.status)
                && item.checkpoint < candidate.checkpoint
        })
    }

    fn replication_remote_response_summary(body: &str) -> String {
        let normalized = body.split_whitespace().collect::<Vec<_>>().join(" ");
        if normalized.len() <= 240 {
            normalized
        } else {
            format!("{}...", &normalized[..240])
        }
    }

    fn replication_remote_failure_retryable(status: reqwest::StatusCode) -> bool {
        status.is_server_error()
            || status == reqwest::StatusCode::TOO_MANY_REQUESTS
            || status == reqwest::StatusCode::REQUEST_TIMEOUT
    }

    pub async fn enqueue_replication_task(
        &self,
        source_bucket: &str,
        target_site: &str,
        object_key: &str,
        rule_id: Option<String>,
        priority: i32,
        operation: &str,
        version_id: Option<String>,
    ) -> ReplicationBacklogItem {
        let now = Utc::now();
        let checkpoint = self.next_replication_checkpoint();
        let idempotency_key = format!(
            "{}:{}:{}:{}",
            source_bucket, target_site, object_key, checkpoint
        );
        let item = ReplicationBacklogItem {
            id: Uuid::new_v4().to_string(),
            source_bucket: source_bucket.to_string(),
            target_site: target_site.to_string(),
            object_key: object_key.to_string(),
            rule_id,
            priority,
            operation: operation.to_string(),
            checkpoint,
            idempotency_key,
            version_id,
            attempts: 0,
            status: "pending".to_string(),
            last_error: String::new(),
            lease_owner: None,
            lease_until: None,
            queued_at: now,
            last_attempt_at: now,
        };
        {
            let mut backlog = self.replication_backlog.write().await;
            backlog.retain(|entry| {
                if !Self::replication_item_matches_target(
                    entry,
                    source_bucket,
                    target_site,
                    object_key,
                ) {
                    return true;
                }
                !Self::replication_item_supersedable(&entry.status)
            });
            backlog.push(item.clone());
        }
        self.persist_replication_runtime_state().await;
        item
    }

    fn safe_object_path(bucket_root: &std::path::Path, key: &str) -> Option<PathBuf> {
        if key.is_empty() {
            return None;
        }
        let key_path = std::path::Path::new(key);
        for component in key_path.components() {
            match component {
                std::path::Component::Normal(_) => {}
                _ => return None,
            }
        }
        Some(bucket_root.join(key_path))
    }

    fn valid_replication_version_id(version_id: &str) -> bool {
        !version_id.is_empty()
            && version_id.len() <= 128
            && version_id.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_' || byte == b'.'
            })
    }

    fn object_meta_file_path(bucket_root: &std::path::Path, key: &str) -> Option<PathBuf> {
        let mut meta_key = key.to_string();
        meta_key.push_str(".json");
        Self::safe_object_path(&bucket_root.join(".rustio_meta"), &meta_key)
    }

    fn object_versions_dir(bucket_root: &std::path::Path, key: &str) -> PathBuf {
        bucket_root
            .join(".rustio_versions")
            .join(sha256_hex(key.as_bytes()))
    }

    fn object_version_meta_file_path(
        bucket_root: &std::path::Path,
        key: &str,
        version_id: &str,
    ) -> Option<PathBuf> {
        if !Self::valid_replication_version_id(version_id) {
            return None;
        }
        Some(Self::object_versions_dir(bucket_root, key).join(format!("{version_id}.json")))
    }

    fn object_version_payload_file_path(
        bucket_root: &std::path::Path,
        key: &str,
        version_id: &str,
    ) -> Option<PathBuf> {
        if !Self::valid_replication_version_id(version_id) {
            return None;
        }
        Some(Self::object_versions_dir(bucket_root, key).join(format!("{version_id}.bin")))
    }

    fn write_pretty_json_file(path: &std::path::Path, value: &S3ObjectMeta) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|err| {
                bilingual_runtime_error(
                    "创建复制元数据目录失败",
                    format!("create replication metadata directory failed: {err}"),
                )
            })?;
        }
        let bytes = serde_json::to_vec_pretty(value).map_err(|err| {
            bilingual_runtime_error(
                "序列化复制元数据失败",
                format!("serialize replication metadata failed: {err}"),
            )
        })?;
        std::fs::write(path, bytes).map_err(|err| {
            bilingual_runtime_error(
                "写入复制元数据失败",
                format!("write replication metadata failed: {err}"),
            )
        })?;
        Ok(())
    }

    fn persist_replication_snapshot(
        site_root: &std::path::Path,
        key: &str,
        payload: Option<&[u8]>,
        object_meta: Option<&S3ObjectMeta>,
    ) -> Result<(), String> {
        if let Some(meta) = object_meta {
            if let Some(current_meta_path) = Self::object_meta_file_path(site_root, key) {
                Self::write_pretty_json_file(&current_meta_path, meta)?;
            }
            if let Some(version_path) =
                Self::object_version_meta_file_path(site_root, key, &meta.version_id)
            {
                Self::write_pretty_json_file(&version_path, meta)?;
            }
            if !meta.delete_marker {
                if let (Some(payload), Some(payload_path)) = (
                    payload,
                    Self::object_version_payload_file_path(site_root, key, &meta.version_id),
                ) {
                    if let Some(parent) = payload_path.parent() {
                        std::fs::create_dir_all(parent).map_err(|err| {
                            bilingual_runtime_error(
                                "创建复制版本目录失败",
                                format!("create replication version directory failed: {err}"),
                            )
                        })?;
                    }
                    std::fs::write(payload_path, payload).map_err(|err| {
                        bilingual_runtime_error(
                            "写入复制版本对象失败",
                            format!("write replication version payload failed: {err}"),
                        )
                    })?;
                }
            }
        }
        Ok(())
    }

    fn write_replication_object_payload(
        root: &std::path::Path,
        key: &str,
        payload: &[u8],
    ) -> Result<(), String> {
        let target_path = Self::safe_object_path(root, key).ok_or_else(|| {
            bilingual_runtime_error("目标对象路径无效", "invalid target object key")
        })?;
        if let Some(parent) = target_path.parent() {
            std::fs::create_dir_all(parent).map_err(|err| {
                bilingual_runtime_error(
                    "创建目标目录失败",
                    format!("create target directory failed: {err}"),
                )
            })?;
        }
        std::fs::write(&target_path, payload).map_err(|err| {
            bilingual_runtime_error(
                "写入目标对象失败",
                format!("write target object failed: {err}"),
            )
        })?;
        Ok(())
    }

    fn delete_replication_object_payload(root: &std::path::Path, key: &str) -> Result<(), String> {
        let target_path = Self::safe_object_path(root, key).ok_or_else(|| {
            bilingual_runtime_error("复制对象路径无效", "invalid replication object key")
        })?;
        let _ = std::fs::remove_file(target_path);
        Ok(())
    }

    fn load_replication_payload(
        &self,
        item: &ReplicationBacklogItem,
    ) -> Result<Option<Vec<u8>>, String> {
        if item.operation == "delete" {
            return Ok(None);
        }
        let source_bucket_root = self.data_dir.join(&item.source_bucket);
        if let Some(version_id) = item.version_id.as_deref() {
            if let Some(version_payload_path) = Self::object_version_payload_file_path(
                &source_bucket_root,
                &item.object_key,
                version_id,
            ) {
                match std::fs::read(&version_payload_path) {
                    Ok(bytes) => return Ok(Some(bytes)),
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                    Err(err) => {
                        return Err(bilingual_runtime_error(
                            "读取源版本对象失败",
                            format!("read source version payload failed: {err}"),
                        ));
                    }
                }
            }
        }

        let source_path = Self::safe_object_path(&source_bucket_root, &item.object_key)
            .ok_or_else(|| {
                bilingual_runtime_error("源对象路径无效", "invalid source object key")
            })?;
        let payload = std::fs::read(&source_path).map_err(|err| {
            bilingual_runtime_error(
                "读取源对象失败",
                format!("read source object failed: {err}"),
            )
        })?;
        Ok(Some(payload))
    }

    async fn load_replication_object_meta(
        &self,
        item: &ReplicationBacklogItem,
    ) -> Result<Option<S3ObjectMeta>, String> {
        let cached = self
            .object_meta
            .read()
            .await
            .get(&(item.source_bucket.clone(), item.object_key.clone()))
            .cloned();
        if let Some(version_id) = item.version_id.as_deref() {
            if let Some(meta) = cached.clone() {
                if meta.version_id == version_id {
                    return Ok(Some(meta));
                }
            }

            let source_bucket_root = self.data_dir.join(&item.source_bucket);
            if let Some(version_meta_path) = Self::object_version_meta_file_path(
                &source_bucket_root,
                &item.object_key,
                version_id,
            ) {
                match std::fs::read(&version_meta_path) {
                    Ok(bytes) => {
                        let meta =
                            serde_json::from_slice::<S3ObjectMeta>(&bytes).map_err(|err| {
                                bilingual_runtime_error(
                                    "解析源版本元数据失败",
                                    format!("decode source version metadata failed: {err}"),
                                )
                            })?;
                        return Ok(Some(meta));
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                    Err(err) => {
                        return Err(bilingual_runtime_error(
                            "读取源版本元数据失败",
                            format!("read source version metadata failed: {err}"),
                        ));
                    }
                }
            }
            if let Some(meta_path) =
                Self::object_meta_file_path(&source_bucket_root, &item.object_key)
            {
                match std::fs::read(&meta_path) {
                    Ok(bytes) => {
                        let meta =
                            serde_json::from_slice::<S3ObjectMeta>(&bytes).map_err(|err| {
                                bilingual_runtime_error(
                                    "解析源对象元数据失败",
                                    format!("decode source object metadata failed: {err}"),
                                )
                            })?;
                        if meta.version_id == version_id {
                            return Ok(Some(meta));
                        }
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                    Err(err) => {
                        return Err(bilingual_runtime_error(
                            "读取源对象元数据失败",
                            format!("read source object metadata failed: {err}"),
                        ));
                    }
                }
            }
            return Ok(None);
        }

        if cached.is_some() {
            return Ok(cached);
        }

        let source_bucket_root = self.data_dir.join(&item.source_bucket);
        let Some(meta_path) = Self::object_meta_file_path(&source_bucket_root, &item.object_key)
        else {
            return Ok(None);
        };
        match std::fs::read(meta_path) {
            Ok(bytes) => {
                let meta = serde_json::from_slice::<S3ObjectMeta>(&bytes).map_err(|err| {
                    bilingual_runtime_error(
                        "解析源对象元数据失败",
                        format!("decode source object metadata failed: {err}"),
                    )
                })?;
                Ok(Some(meta))
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(bilingual_runtime_error(
                "读取源对象元数据失败",
                format!("read source object metadata failed: {err}"),
            )),
        }
    }

    async fn write_replication_checkpoint(&self, site_id: &str, checkpoint: u64) {
        {
            let mut checkpoints = self.replication_checkpoints.write().await;
            checkpoints
                .entry(site_id.to_string())
                .and_modify(|current| *current = (*current).max(checkpoint))
                .or_insert(checkpoint);
        }

        let checkpoint_path = self
            .replication_root_dir()
            .join("checkpoints")
            .join(format!("{site_id}.json"));
        if let Some(parent) = checkpoint_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let value = json!({
            "site_id": site_id,
            "checkpoint": checkpoint,
            "updated_at": Utc::now(),
        });
        let _ = std::fs::write(
            checkpoint_path,
            serde_json::to_vec_pretty(&value).unwrap_or_default(),
        );
        self.persist_replication_runtime_state().await;
    }

    async fn replication_site_endpoint(&self, site_id: &str) -> Option<String> {
        self.site_replications
            .read()
            .await
            .iter()
            .find(|site| site.site_id == site_id)
            .map(|site| site.endpoint.clone())
    }

    async fn apply_replication_item_remote(
        &self,
        item: &ReplicationBacklogItem,
        payload_base64: Option<String>,
        object_meta: Option<S3ObjectMeta>,
    ) -> Result<bool, String> {
        if !Self::replication_remote_enabled() {
            return Ok(false);
        }
        let Some(endpoint) = self.replication_site_endpoint(&item.target_site).await else {
            return Ok(false);
        };
        let endpoint = endpoint.trim().trim_end_matches('/');
        if !(endpoint.starts_with("http://") || endpoint.starts_with("https://")) {
            return Ok(false);
        }

        let request = InternalReplicationApplyRequest {
            source_bucket: item.source_bucket.clone(),
            target_site: item.target_site.clone(),
            object_key: item.object_key.clone(),
            operation: item.operation.clone(),
            checkpoint: item.checkpoint,
            idempotency_key: item.idempotency_key.clone(),
            version_id: item.version_id.clone(),
            payload_base64,
            object_meta,
        };

        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|err| err.to_string())?;
        let response = client
            .post(format!("{endpoint}/api/v1/internal/replication/apply"))
            .header("x-rustio-internal-token", Self::internal_control_token())
            .json(&request)
            .send()
            .await
            .map_err(|err| {
                bilingual_runtime_error(
                    "远端复制请求失败",
                    format!("remote replication request failed: {err}"),
                )
            })?;
        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            let body_summary = Self::replication_remote_response_summary(&body);
            let detail = if body_summary.is_empty() {
                format!("remote replication status: {}", status)
            } else {
                format!(
                    "remote replication status: {}, body: {}",
                    status, body_summary
                )
            };
            let err = bilingual_runtime_error("远端复制请求失败", detail);
            if Self::replication_remote_failure_retryable(status) {
                return Err(err);
            }
            return Err(Self::replication_mark_non_retryable(err));
        }
        Ok(true)
    }

    async fn apply_replication_item(&self, item: &ReplicationBacklogItem) -> Result<(), String> {
        let site_root = self
            .replication_root_dir()
            .join("sites")
            .join(&item.target_site)
            .join(&item.source_bucket);
        let object_space_root =
            self.replication_object_space_root(&item.target_site, &item.source_bucket);
        let marker_path = site_root
            .join(".applied")
            .join(format!("{}.done", item.idempotency_key));

        if marker_path.exists() {
            self.write_replication_checkpoint(&item.target_site, item.checkpoint)
                .await;
            return Ok(());
        }

        let object_meta = self.load_replication_object_meta(item).await?;
        let payload = self.load_replication_payload(item)?;
        let payload_base64 = payload.as_ref().map(|bytes| BASE64.encode(bytes));

        if self
            .apply_replication_item_remote(item, payload_base64, object_meta.clone())
            .await?
        {
            if let Some(parent) = marker_path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            std::fs::write(&marker_path, item.checkpoint.to_string()).map_err(|err| {
                bilingual_runtime_error(
                    "写入复制幂等标记失败",
                    format!("write replication marker failed: {err}"),
                )
            })?;
            self.write_replication_checkpoint(&item.target_site, item.checkpoint)
                .await;
            return Ok(());
        }

        if item.operation == "delete" {
            if let Some(meta_path) = Self::object_meta_file_path(&site_root, &item.object_key) {
                let _ = std::fs::remove_file(meta_path);
            }
            if let Some(version_id) = item.version_id.as_deref() {
                if let Some(version_meta_path) =
                    Self::object_version_meta_file_path(&site_root, &item.object_key, version_id)
                {
                    let _ = std::fs::remove_file(version_meta_path);
                }
                if let Some(version_payload_path) =
                    Self::object_version_payload_file_path(&site_root, &item.object_key, version_id)
                {
                    let _ = std::fs::remove_file(version_payload_path);
                }
            }
            Self::delete_replication_object_payload(&site_root, &item.object_key)?;
            Self::delete_replication_object_payload(&object_space_root, &item.object_key)?;
            if object_meta
                .as_ref()
                .map(|meta| meta.delete_marker)
                .unwrap_or(false)
            {
                Self::persist_replication_snapshot(
                    &site_root,
                    &item.object_key,
                    None,
                    object_meta.as_ref(),
                )?;
                Self::persist_replication_snapshot(
                    &object_space_root,
                    &item.object_key,
                    None,
                    object_meta.as_ref(),
                )?;
            }
        } else {
            let payload = payload.as_deref().ok_or_else(|| {
                bilingual_runtime_error("源对象内容缺失", "replication source payload missing")
            })?;
            Self::write_replication_object_payload(&site_root, &item.object_key, payload)?;
            Self::write_replication_object_payload(&object_space_root, &item.object_key, payload)?;
            Self::persist_replication_snapshot(
                &site_root,
                &item.object_key,
                Some(payload),
                object_meta.as_ref(),
            )?;
            Self::persist_replication_snapshot(
                &object_space_root,
                &item.object_key,
                Some(payload),
                object_meta.as_ref(),
            )?;
        }

        if let Some(parent) = marker_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        std::fs::write(&marker_path, item.checkpoint.to_string()).map_err(|err| {
            bilingual_runtime_error(
                "写入复制幂等标记失败",
                format!("write replication marker failed: {err}"),
            )
        })?;
        self.write_replication_checkpoint(&item.target_site, item.checkpoint)
            .await;
        Ok(())
    }

    async fn process_replication_backlog_sla_watchdog_once(&self) -> Result<(), String> {
        #[derive(Default)]
        struct SiteStats {
            total: usize,
            failed: usize,
            dead_letter: usize,
            stale_pending: usize,
            max_pending_age_seconds: u64,
        }

        let now = Utc::now();
        let (failed_threshold, dead_letter_threshold, pending_age_threshold_secs) =
            Self::replication_backlog_alert_threshold_snapshot();
        let suppress_interval = Self::replication_backlog_alert_suppress_interval();
        let suppress_interval_chrono =
            Duration::from_std(suppress_interval).unwrap_or_else(|_| Duration::seconds(0));

        let backlog = self.replication_backlog.read().await.clone();
        let mut per_site = HashMap::<String, SiteStats>::new();
        for item in &backlog {
            let stats = per_site.entry(item.target_site.clone()).or_default();
            stats.total += 1;
            match item.status.as_str() {
                "failed" => stats.failed += 1,
                "dead_letter" => stats.dead_letter += 1,
                "pending" => {
                    let age = now
                        .signed_duration_since(item.queued_at)
                        .num_seconds()
                        .max(0) as u64;
                    stats.max_pending_age_seconds = stats.max_pending_age_seconds.max(age);
                    if pending_age_threshold_secs > 0 && age >= pending_age_threshold_secs {
                        stats.stale_pending += 1;
                    }
                }
                _ => {}
            }
        }

        let mut breached_sites = HashMap::<String, (String, String, Value, String)>::new();
        for (site, stats) in &per_site {
            let mut reasons_zh = Vec::new();
            let mut reasons_en = Vec::new();
            let mut breach_kinds = Vec::new();
            if failed_threshold > 0 && stats.failed >= failed_threshold {
                reasons_zh.push(format!(
                    "失败任务 {} >= 阈值 {}",
                    stats.failed, failed_threshold
                ));
                reasons_en.push(format!(
                    "failed backlog {} >= threshold {}",
                    stats.failed, failed_threshold
                ));
                breach_kinds.push("failed".to_string());
            }
            if dead_letter_threshold > 0 && stats.dead_letter >= dead_letter_threshold {
                reasons_zh.push(format!(
                    "死信任务 {} >= 阈值 {}",
                    stats.dead_letter, dead_letter_threshold
                ));
                reasons_en.push(format!(
                    "dead-letter backlog {} >= threshold {}",
                    stats.dead_letter, dead_letter_threshold
                ));
                breach_kinds.push("dead_letter".to_string());
            }
            if pending_age_threshold_secs > 0
                && stats.stale_pending > 0
                && stats.max_pending_age_seconds >= pending_age_threshold_secs
            {
                reasons_zh.push(format!(
                    "超时 pending 任务 {} 个（最老 {}s >= 阈值 {}s）",
                    stats.stale_pending, stats.max_pending_age_seconds, pending_age_threshold_secs
                ));
                reasons_en.push(format!(
                    "stale pending items {} (oldest {}s >= threshold {}s)",
                    stats.stale_pending, stats.max_pending_age_seconds, pending_age_threshold_secs
                ));
                breach_kinds.push("pending_age".to_string());
            }
            if reasons_zh.is_empty() {
                continue;
            }
            let message_zh = format!(
                "站点 {site} 复制 backlog SLA 超阈值：{}",
                reasons_zh.join("；")
            );
            let message_en = format!(
                "replication backlog SLA breached on site {site}: {}",
                reasons_en.join("; ")
            );
            let fingerprint = json!({
                "site_id": site,
                "breaches": breach_kinds,
                "failed_threshold": failed_threshold,
                "dead_letter_threshold": dead_letter_threshold,
                "pending_age_threshold_seconds": pending_age_threshold_secs,
            });
            let breach_hash = Self::hash_json(&fingerprint).unwrap_or_else(|_| {
                format!(
                    "{site}:{failed_threshold}:{dead_letter_threshold}:{pending_age_threshold_secs}"
                )
            });
            let details = json!({
                "site_id": site,
                "failed": stats.failed,
                "dead_letter": stats.dead_letter,
                "stale_pending": stats.stale_pending,
                "max_pending_age_seconds": stats.max_pending_age_seconds,
                "failed_threshold": failed_threshold,
                "dead_letter_threshold": dead_letter_threshold,
                "pending_age_threshold_seconds": pending_age_threshold_secs,
                "breaches": fingerprint["breaches"].clone(),
                "breach_hash": breach_hash.clone(),
                "total": stats.total,
            });
            breached_sites.insert(site.clone(), (message_zh, message_en, details, breach_hash));
        }

        let mut history = self.alert_history.write().await;

        for entry in history.iter_mut() {
            let Some(site) = Self::replication_backlog_alert_site(&entry.source) else {
                continue;
            };
            if entry.status != "firing" || entry.resolved_at.is_some() {
                continue;
            }
            if breached_sites.contains_key(site) {
                continue;
            }
            entry.status = "resolved".to_string();
            entry.resolved_by = Some("system".to_string());
            entry.resolved_at = Some(now);
            entry.message = bilingual_runtime_error(
                &format!("站点 {site} 复制 backlog SLA 已恢复"),
                format!("replication backlog SLA recovered on site {site}"),
            );
        }

        for (site, (message_zh, message_en, details, breach_hash)) in breached_sites {
            let source = Self::replication_backlog_alert_source(&site);
            let already_firing = history.iter().any(|entry| {
                entry.source == source && entry.status == "firing" && entry.resolved_at.is_none()
            });
            if already_firing {
                continue;
            }
            let last_same_hash_triggered = history
                .iter()
                .filter(|entry| {
                    entry.source == source
                        && Self::replication_backlog_alert_breach_hash(&entry.details)
                            == Some(breach_hash.as_str())
                })
                .map(|entry| entry.triggered_at)
                .max();
            if let Some(last) = last_same_hash_triggered {
                if now.signed_duration_since(last) < suppress_interval_chrono {
                    continue;
                }
            }
            let last_triggered = history
                .iter()
                .filter(|entry| entry.source == source)
                .map(|entry| entry.triggered_at)
                .max();
            if let Some(last) = last_triggered {
                if now.signed_duration_since(last) < suppress_interval_chrono {
                    continue;
                }
            }
            history.push(AlertHistoryEntry {
                id: format!("history-{}", Uuid::new_v4().simple()),
                rule_id: None,
                rule_name: Some("复制 backlog SLA 超阈值".to_string()),
                severity: "warning".to_string(),
                status: "firing".to_string(),
                message: bilingual_runtime_error(&message_zh, message_en),
                triggered_at: now,
                source,
                assignee: None,
                claimed_at: None,
                acknowledged_by: None,
                acknowledged_at: None,
                resolved_by: None,
                resolved_at: None,
                details,
            });
        }
        Ok(())
    }

    pub async fn process_replication_queue_once(&self, worker_id: &str) -> usize {
        let now = Utc::now();
        let max_attempts = Self::replication_max_attempts();
        let lease_until = now
            + Duration::from_std(Self::replication_lease_interval())
                .unwrap_or_else(|_| Duration::seconds(1));
        let next_item = {
            let mut backlog = self.replication_backlog.write().await;
            let mut picked = None::<ReplicationBacklogItem>;
            let mut picked_index = None::<usize>;
            let mut picked_priority = i32::MAX;
            let mut picked_operation_priority = u8::MAX;
            let mut picked_checkpoint = u64::MAX;
            for (index, entry) in backlog.iter().enumerate() {
                let retry_ready = Self::replication_retry_ready(entry, &now);
                let lease_expired = entry.lease_until.map(|value| value <= now).unwrap_or(true);
                let ready = entry.status == "pending"
                    || retry_ready
                    || (entry.status == "in_progress" && lease_expired);
                if !ready {
                    continue;
                }
                if Self::replication_target_blocked(&backlog, index, &now) {
                    continue;
                }
                let operation_priority = Self::replication_operation_priority(&entry.operation);
                if entry.priority < picked_priority
                    || (entry.priority == picked_priority
                        && operation_priority < picked_operation_priority)
                    || (entry.priority == picked_priority
                        && operation_priority == picked_operation_priority
                        && entry.checkpoint < picked_checkpoint)
                {
                    picked_index = Some(index);
                    picked_priority = entry.priority;
                    picked_operation_priority = operation_priority;
                    picked_checkpoint = entry.checkpoint;
                }
            }
            if let Some(index) = picked_index {
                if let Some(entry) = backlog.get_mut(index) {
                    entry.status = "in_progress".to_string();
                    entry.attempts += 1;
                    entry.last_attempt_at = now;
                    entry.lease_owner = Some(worker_id.to_string());
                    entry.lease_until = Some(lease_until);
                    picked = Some(entry.clone());
                }
            }
            picked
        };
        let Some(item) = next_item else {
            return 0;
        };

        let result = self.apply_replication_item(&item).await;
        let mut backlog = self.replication_backlog.write().await;
        if let Some(entry) = backlog.iter_mut().find(|entry| entry.id == item.id) {
            match result {
                Ok(_) => {
                    entry.status = "done".to_string();
                    entry.last_error.clear();
                    entry.lease_owner = None;
                    entry.lease_until = None;
                }
                Err(err) => {
                    let non_retryable = Self::replication_error_is_non_retryable(&err);
                    let err = Self::replication_error_message(&err);
                    if non_retryable {
                        entry.status = "dead_letter".to_string();
                        entry.lease_owner = None;
                        entry.lease_until = None;
                        entry.last_error = Self::replication_dead_letter_non_retryable_error(&err);
                    } else if entry.attempts >= max_attempts {
                        entry.status = "dead_letter".to_string();
                        entry.lease_owner = None;
                        entry.lease_until = None;
                        entry.last_error =
                            Self::replication_dead_letter_error(entry.attempts, max_attempts, &err);
                    } else {
                        entry.status = "failed".to_string();
                        entry.lease_owner = None;
                        entry.lease_until = None;
                        entry.last_error = err;
                    }
                }
            }
        }
        backlog.retain(|entry| {
            if entry.id == item.id {
                return true;
            }
            if !Self::replication_items_same_target(entry, &item) {
                return true;
            }
            if !Self::replication_item_supersedable(&entry.status) {
                return true;
            }
            entry.checkpoint > item.checkpoint
        });
        drop(backlog);
        self.persist_replication_runtime_state().await;
        1
    }

    fn start_background_workers(self: &Arc<Self>) {
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        for _ in 0..Self::replication_worker_concurrency() {
            let state = Arc::clone(self);
            let worker_id = format!("replication-worker-{}", Uuid::new_v4().simple());
            handle.spawn(async move {
                loop {
                    let _ = state.process_replication_queue_once(&worker_id).await;
                    tokio::time::sleep(Self::replication_worker_interval()).await;
                }
            });
        }
        let replication_alert_state = Arc::clone(self);
        handle.spawn(async move {
            loop {
                let _ = replication_alert_state
                    .process_replication_backlog_sla_watchdog_once()
                    .await;
                tokio::time::sleep(Self::replication_backlog_alert_interval()).await;
            }
        });
        let alert_rule_state = Arc::clone(self);
        handle.spawn(async move {
            loop {
                let _ = alert_rule_state.process_alert_rules_once().await;
                tokio::time::sleep(Self::alert_rule_eval_interval()).await;
            }
        });
        let alert_delivery_state = Arc::clone(self);
        let alert_delivery_worker_id = format!("alert-worker-{}", Uuid::new_v4().simple());
        handle.spawn(async move {
            loop {
                let _ = alert_delivery_state
                    .process_alert_delivery_queue_once(&alert_delivery_worker_id)
                    .await;
                tokio::time::sleep(Self::alert_delivery_interval()).await;
            }
        });
        let lifecycle_state = Arc::clone(self);
        handle.spawn(async move {
            loop {
                let _ = lifecycle_state.process_bucket_lifecycle_once().await;
                tokio::time::sleep(Self::lifecycle_interval()).await;
            }
        });
        let storage_scan_state = Arc::clone(self);
        handle.spawn(async move {
            loop {
                let _ = process_storage_governance_scan_once(&storage_scan_state).await;
                tokio::time::sleep(Self::storage_scan_interval()).await;
            }
        });
        let storage_heal_state = Arc::clone(self);
        handle.spawn(async move {
            loop {
                let _ = process_storage_governance_heal_queue_once(&storage_heal_state).await;
                tokio::time::sleep(Self::storage_heal_worker_interval()).await;
            }
        });
        let managed_async_state = Arc::clone(self);
        let managed_async_worker_id = format!("async-worker-{}", Uuid::new_v4().simple());
        handle.spawn(async move {
            loop {
                let _ = managed_async_state
                    .process_managed_async_jobs_once(&managed_async_worker_id)
                    .await;
                tokio::time::sleep(Self::managed_async_job_worker_interval()).await;
            }
        });
        let metadata_state = Arc::clone(self);
        handle.spawn(async move {
            loop {
                let _ = metadata_state.process_metadata_raft_heartbeat_once().await;
                let _ = metadata_state
                    .process_metadata_membership_watchdog_once()
                    .await;
                tokio::time::sleep(Self::metadata_heartbeat_interval()).await;
            }
        });
        let memory_trim_state = Arc::clone(self);
        handle.spawn(async move {
            loop {
                tokio::time::sleep(Self::memory_trim_interval()).await;
                memory_trim_state.maybe_trim_memory();
            }
        });
    }

    pub async fn architecture_alignment_report(&self) -> ArchitectureAlignmentReport {
        let required_planes = [
            "control-plane",
            "metadata-plane",
            "data-plane",
            "worker-plane",
        ];
        let topology = self.architecture.clone();
        let plane_ids: HashSet<&str> = topology
            .planes
            .iter()
            .map(|plane| plane.id.as_str())
            .collect();
        let missing_planes: Vec<String> = required_planes
            .iter()
            .filter(|plane| !plane_ids.contains(*plane))
            .map(|plane| plane.to_string())
            .collect();

        let credential_count = self.credentials.read().await.len();
        let user_count = self.users.read().await.len();
        let group_count = self.groups.read().await.len();
        let policy_count = self.policies.read().await.len();
        let cluster_config_count = self.cluster_config_history.read().await.len();
        let bucket_count = self.buckets.read().await.len();
        let bucket_object_lock_count = self.bucket_object_locks.read().await.len();
        let site_replication_count = self.site_replications.read().await.len();
        let job_count = self.jobs.read().await.len();
        let alert_rule_count = self.alert_rules.read().await.len();
        let alert_channel_count = self.alert_channels.read().await.len();
        let replication_checkpoint_count = self.replication_checkpoints.read().await.len();
        let raft_status = self.metadata_raft_status().await;
        let data_disk_ready = self.data_disks.iter().filter(|path| path.exists()).count();
        let data_dir_ready = self.data_dir.exists();
        let s3_credential_ready = !self.s3_access_key.is_empty() && !self.s3_secret_key.is_empty();
        let jwt_ready = !self.jwt_secret.is_empty();

        let planes: Vec<PlaneAlignmentStatus> = topology
            .planes
            .iter()
            .map(|plane| {
                let mut checks = Vec::new();
                let mut component_ready = 0usize;

                for component in &plane.components {
                    let ready = match component.id.as_str() {
                        "admin-api" => cluster_config_count > 0,
                        "auth-service" => jwt_ready && credential_count > 0 && user_count > 0,
                        "audit-service" => user_count > 0,
                        "bucket-metadata-store" => {
                            bucket_object_lock_count >= bucket_count
                                && raft_status.online_peers >= raft_status.quorum
                        }
                        "iam-metadata-store" => {
                            user_count > 0
                                && group_count > 0
                                && policy_count > 0
                                && raft_status.online_peers >= raft_status.quorum
                        }
                        "cluster-config-history" => {
                            cluster_config_count > 0 && raft_status.commit_index > 0
                        }
                        "s3-gateway" => s3_credential_ready && data_disk_ready >= 3,
                        "object-store" => data_dir_ready && data_disk_ready >= 3,
                        "multipart-store" => data_dir_ready && data_disk_ready >= 3,
                        "replication-worker" => {
                            site_replication_count > 0
                                && replication_checkpoint_count <= site_replication_count
                        }
                        "job-orchestrator" => job_count > 0,
                        "alert-worker" => alert_rule_count > 0 && alert_channel_count > 0,
                        _ => false,
                    };
                    if ready {
                        component_ready += 1;
                    }
                    checks.push(format!(
                        "{}={}",
                        component.id,
                        if ready { "ready" } else { "missing" }
                    ));
                }

                let status = if component_ready == plane.components.len() {
                    "aligned"
                } else {
                    "degraded"
                };

                PlaneAlignmentStatus {
                    plane_id: plane.id.clone(),
                    plane_name: plane.name.clone(),
                    status: status.to_string(),
                    component_total: plane.components.len(),
                    component_ready,
                    checks,
                }
            })
            .collect();

        let all_planes_aligned = planes.iter().all(|plane| plane.status == "aligned");
        let overall_status = if missing_planes.is_empty() && all_planes_aligned {
            "aligned"
        } else {
            "degraded"
        };

        ArchitectureAlignmentReport {
            version: topology.version,
            generated_at: Utc::now(),
            overall_status: overall_status.to_string(),
            missing_planes,
            planes,
        }
    }
}
