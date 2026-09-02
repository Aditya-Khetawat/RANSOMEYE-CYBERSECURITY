/**
 * Types for the RansomEye FastAPI backend (backend/app/ransomeye/*).
 * Mirror the shapes the backend actually returns, captured from live
 * responses — not an OpenAPI generation. The backend is the source of
 * truth; nothing here should drive a backend change.
 */

export type RiskLevel = "low" | "medium" | "high" | "critical";

export interface Endpoint {
  id: string;
  hostname: string;
  ip: string;
  os: string;
  user: string;
  department: string;
}

export interface FileEvent {
  type: "file";
  op: "modify" | "create" | "rename" | "delete";
  path: string;
  new_path?: string;
  ext: string;
  new_ext?: string;
  size_bytes: number;
  entropy: number;
  ts: string;
}

export interface ProcessEvent {
  type: "process";
  action: "spawn";
  pid: number;
  ppid: number;
  image: string;
  parent_image: string;
  cmdline: string;
  suspicious_indicators: string[];
  ts: string;
}

export interface NetworkEvent {
  type: "network";
  direction: "outbound";
  dest_ip: string;
  dest_port: number;
  is_external: boolean;
  reputation: "clean" | "unknown" | "malicious";
  bytes_out: number;
  ts: string;
}

export interface PrivilegeEvent {
  type: "privilege";
  action: string;
  detail: string;
  ts: string;
}

export type TelemetryEvent = FileEvent | ProcessEvent | NetworkEvent | PrivilegeEvent;

export interface Features {
  file_mod_rate: number;
  file_rename_rate: number;
  file_delete_rate: number;
  unique_extensions_touched: number;
  files_touched: number;
  new_ext_convergence: number;
  entropy_flip_rate: number;
  process_spawn_rate: number;
  suspicious_process_rate: number;
  privilege_event_rate: number;
  network_conn_rate: number;
  malicious_conn_rate: number;
  external_conn_ratio: number;
  evidence: string[];
  raw_events_in_window: number;
}

export interface RiskFactors {
  encryption_pattern: number;
  process_behavior: number;
  privilege_escalation: number;
  network_abnormality: number;
}

export interface ContributingFactor {
  factor: string;
  key: string;
  value: number;
  baseline: number;
  deviation: number;
}

export interface Risk {
  score: number;
  level: RiskLevel;
  factors: RiskFactors;
  weighted_contribution_pct: RiskFactors;
  ml_anomaly_score: number | null;
  evidence: string[];
  top_contributing_factors: ContributingFactor[];
}

export interface EndpointState {
  feat: Features;
  risk: Risk;
}

export interface EarlyWarningAlert {
  id: string;
  endpoint_id: string;
  hostname: string;
  user: string;
  severity: "high" | "critical";
  risk_score: number;
  risk_level: RiskLevel;
  fired_at_tick: number;
  timestamp: string;
  title: string;
  primary_signal: string;
  contributing_behaviors: string[];
  affected_process: string | null;
  recommended_action: string;
}

export interface Tick {
  tick: number;
  ts: string;
  events_by_endpoint: Record<string, TelemetryEvent[]>;
  endpoint_states: Record<string, EndpointState>;
  alerts: EarlyWarningAlert[];
}

export type ScenarioName = "NORMAL_ACTIVITY" | "SUSPICIOUS_ACTIVITY" | "RANSOMWARE_ATTACK";

export interface ScenarioRun {
  scenario: ScenarioName;
  run_id: string;
  endpoints: Endpoint[];
  target_endpoint_id: string | null;
  ticks: Tick[];
  alerts: EarlyWarningAlert[];
  summary: {
    total_ticks: number;
    total_alerts: number;
    peak_risk_endpoint: string | null;
    peak_risk_score: number;
    final_status: "NORMAL" | "ANOMALY_OBSERVED_NO_ALERT" | "CONTAINED_ALERT_FIRED";
  };
}

export interface ForecastStep {
  minutes: number;
  risk: number;
  estimated_files_encrypted: number;
  confidence: number;
}

export interface EndpointForecast {
  endpoint_id: string;
  currentRisk: number;
  confidence: number;
  recommendedImmediateAction: string;
  forecast: ForecastStep[];
  reasoning: string[];
}

export interface ContainmentAction {
  id: string;
  action_type: string;
  title: string;
  description: string;
  destructive: boolean;
  requires_approval: boolean;
  status: "executed" | "pending_approval";
}

export interface ContainmentPlan {
  endpoint_id: string;
  actions: ContainmentAction[];
}

export interface CopilotMessage {
  role: "user" | "assistant";
  content: string;
}

export interface CopilotResponse {
  status: string;
  provider: string;
  model?: string;
  answer: string;
  note?: string;
}

/** GET /ransomeye/evaluation */
export interface KillChainVariantResult {
  seeds_tested: number;
  alerts_fired: number;
  detection_rate_pct: number;
  mean_lead_seconds: number | null;
}

export interface PerScenarioEvaluation {
  seeds_tested: number;
  alerts_fired: number;
  expected_to_fire: boolean;
  fire_rate_pct: number;
  mean_peak_risk: number;
  min_peak_risk: number;
  max_peak_risk: number;
  full_kill_chain?: KillChainVariantResult;
  smash_and_grab?: KillChainVariantResult;
}

export interface ConfusionMatrix {
  tp: number;
  fp: number;
  fn: number;
  tn: number;
}

export interface EvaluationResult {
  seeds_tested: number[];
  per_scenario: Record<ScenarioName, PerScenarioEvaluation>;
  confusion_matrix: ConfusionMatrix;
  precision: number | null;
  recall: number | null;
  f1: number | null;
  false_positive_rate: number | null;
  detection_lead_seconds: {
    n: number;
    mean: number | null;
    min: number | null;
    max: number | null;
  };
}
