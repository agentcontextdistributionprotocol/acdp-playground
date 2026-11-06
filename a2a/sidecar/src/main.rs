//! `acdp-a2a-sidecar`: a JSON-lines bridge from a Python A2A agent to
//! acdp-rs's `acdp-a2a` producer (RFC-ACDP-0022, profile `acdp-producer-a2a`).
//!
//! The published `acdp` Python wheel exposes no A2A surface, so the Python
//! agent drives the Rust crate through this process instead of growing a
//! third implementation. All RFC-0022 logic stays in `acdp_a2a`: assembly,
//! the salted record, signing, publish-before-the-final-chunk, the
//! Idempotency-Key, the link and fail-open. This file only moves JSON
//! between stdin/stdout and `Agent` / `TaskSession`.
//!
//! Wire format: one JSON object per line each way. A request is
//! `{"id": <n>, "op": <name>, ...}` and its reply is
//! `{"id": <n>, "ok": true, "result": ...}` or
//! `{"id": <n>, "ok": false, "error": "<message>"}`. Requests are served in
//! order, one at a time.
//!
//! Ops:
//! - `init` `{seed_hex, registry_url, registry, a2a_protocol_version,
//!   body_type, visibility?, domain?, tags?, allow_local_http?}` →
//!   `{agent_id, key_id, card_extension}`
//! - `begin` `{task_id, context_id}`: open a `TaskSession`
//! - `message` `{task_id, message}`: `observe_client_message` (§7)
//! - `verified_inputs` `{task_id, ids}`: `mark_inputs_verified` (§7 step 3)
//! - `chunk` `{task_id, chunk}` → `{emit}` | `{withhold: {artifact_id, failure}}`
//! - `task` `{task_id, task}` → `{task, withheld}`
//! - `end` `{task_id}`: drop the session

use std::collections::HashMap;

use acdp::{
    client::RegistryClient,
    crypto::SigningKey,
    producer::Producer,
    safe_http::SsrfPolicy,
    types::{
        primitives::{AgentDid, ContextType, Visibility},
        CtxId,
    },
};
use acdp_a2a::{
    card::{card_extension, CardParams},
    Agent, ArtifactPolicy, BodyTemplate, ChunkOutput, TaskSession,
};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

type OpResult = Result<Value, String>;

struct Bridge {
    agent: Option<Agent>,
    sessions: HashMap<String, TaskSession>,
}

fn str_field<'a>(req: &'a Value, name: &str) -> Result<&'a str, String> {
    req.get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing string field `{name}`"))
}

impl Bridge {
    fn agent(&self) -> Result<&Agent, String> {
        self.agent.as_ref().ok_or_else(|| "not initialised".into())
    }

    fn session(&mut self, req: &Value) -> Result<&mut TaskSession, String> {
        let id = str_field(req, "task_id")?;
        self.sessions
            .get_mut(id)
            .ok_or_else(|| format!("no session for task {id}"))
    }

    async fn init(&mut self, req: &Value) -> OpResult {
        let seed = hex::decode(str_field(req, "seed_hex")?).map_err(|e| e.to_string())?;
        let seed: [u8; 32] = seed
            .try_into()
            .map_err(|_| "seed_hex is not 32 bytes".to_string())?;
        let producer = Producer::new_did_key(SigningKey::from_bytes(&seed));
        let key_id = producer.key_id().to_owned();
        // A did:key producer's key_id is `<did>#<fragment>`.
        let agent_id = key_id
            .split_once('#')
            .map(|(did, _)| did.to_owned())
            .ok_or("did:key key_id has no fragment")?;

        let registry_url = str_field(req, "registry_url")?;
        let registry = str_field(req, "registry")?.to_owned();
        let client = if req["allow_local_http"].as_bool() == Some(true) {
            // Local demo stack only: the registry is plain http on loopback.
            // Every production fetch keeps the default HTTPS-only,
            // no-loopback posture (RFC-ACDP-0008 §4.8).
            RegistryClient::builder(registry_url)
                .ssrf_policy(SsrfPolicy {
                    reject_ip_literals: false,
                    allow_http: true,
                    allow_loopback_resolved: true,
                })
                .build()
                .await
        } else {
            RegistryClient::new(registry_url)
        }
        .map_err(|e| e.to_string())?;

        let body_type: ContextType =
            serde_json::from_value(req["body_type"].clone()).map_err(|e| e.to_string())?;
        let mut template = BodyTemplate::new(body_type);
        if let Some(v) = req.get("visibility").filter(|v| !v.is_null()) {
            template.visibility =
                serde_json::from_value::<Visibility>(v.clone()).map_err(|e| e.to_string())?;
        }
        template.domain = req["domain"].as_str().map(str::to_owned);
        if let Some(tags) = req["tags"].as_array() {
            template.tags = tags
                .iter()
                .filter_map(|t| t.as_str().map(str::to_owned))
                .collect();
        }

        let version = str_field(req, "a2a_protocol_version")?;
        self.agent = Some(Agent::new(
            producer,
            client,
            version,
            ArtifactPolicy::new(template),
        ));
        let params = CardParams {
            registry,
            agent_id: AgentDid::parse(&agent_id).map_err(|e| e.to_string())?,
        };
        Ok(json!({
            "agent_id": agent_id,
            "key_id": key_id,
            "card_extension": card_extension(
                &params,
                Some("Completed artifacts are published as signed ACDP bodies (RFC-ACDP-0022)."),
            ),
        }))
    }

    async fn handle(&mut self, req: &Value) -> OpResult {
        match str_field(req, "op")? {
            "init" => self.init(req).await,
            "begin" => {
                let task_id = str_field(req, "task_id")?.to_owned();
                let context_id = str_field(req, "context_id")?;
                self.sessions
                    .entry(task_id.clone())
                    .or_insert_with(|| TaskSession::new(task_id, context_id));
                Ok(Value::Null)
            }
            "message" => {
                let message = req["message"].clone();
                self.session(req)?.observe_client_message(&message);
                let cited: Vec<String> = self
                    .session(req)?
                    .cited_inputs()
                    .iter()
                    .map(ToString::to_string)
                    .collect();
                Ok(json!({ "cited": cited }))
            }
            "verified_inputs" => {
                let ids = req["ids"]
                    .as_array()
                    .ok_or("missing array field `ids`")?
                    .iter()
                    .map(|v| {
                        CtxId::parse(v.as_str().unwrap_or_default()).map_err(|e| e.to_string())
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                self.session(req)?.mark_inputs_verified(ids);
                Ok(Value::Null)
            }
            "chunk" => {
                let chunk = req["chunk"].clone();
                let id = str_field(req, "task_id")?.to_owned();
                let session = self
                    .sessions
                    .get_mut(&id)
                    .ok_or_else(|| format!("no session for task {id}"))?;
                let agent = self.agent.as_ref().ok_or("not initialised")?;
                match agent.on_chunk(session, chunk).await.map_err(|e| e.0)? {
                    ChunkOutput::Emit(c) => Ok(json!({ "emit": c })),
                    ChunkOutput::Withhold {
                        artifact_id,
                        failure,
                    } => Ok(json!({
                        "withhold": { "artifact_id": artifact_id, "failure": failure }
                    })),
                }
            }
            "task" => {
                let task = req["task"].clone();
                let id = str_field(req, "task_id")?.to_owned();
                let session = self
                    .sessions
                    .get_mut(&id)
                    .ok_or_else(|| format!("no session for task {id}"))?;
                let agent = self.agent.as_ref().ok_or("not initialised")?;
                let out = agent.on_task(session, task).await.map_err(|e| e.0)?;
                let withheld: Vec<Value> = out
                    .withheld
                    .into_iter()
                    .map(|(a, f)| json!({ "artifact_id": a, "failure": f }))
                    .collect();
                Ok(json!({ "task": out.task, "withheld": withheld }))
            }
            "end" => {
                self.agent()?;
                self.sessions.remove(str_field(req, "task_id")?);
                Ok(Value::Null)
            }
            other => Err(format!("unknown op `{other}`")),
        }
    }
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let mut bridge = Bridge {
        agent: None,
        sessions: HashMap::new(),
    };
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    let mut out = tokio::io::stdout();
    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let reply = match serde_json::from_str::<Value>(&line) {
            Ok(req) => {
                let id = req.get("id").cloned().unwrap_or(Value::Null);
                match bridge.handle(&req).await {
                    Ok(result) => json!({ "id": id, "ok": true, "result": result }),
                    Err(error) => json!({ "id": id, "ok": false, "error": error }),
                }
            }
            Err(e) => json!({ "id": null, "ok": false, "error": format!("bad request: {e}") }),
        };
        let mut bytes = serde_json::to_vec(&reply)?;
        bytes.push(b'\n');
        out.write_all(&bytes).await?;
        out.flush().await?;
    }
    Ok(())
}
