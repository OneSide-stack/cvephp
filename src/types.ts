export type ViewId = "attacker" | "target" | "network" | "lab" | "guide";
export type MachineId = "attacker" | "target";
export type LabStatus =
  | "not-started"
  | "loading-emulator"
  | "booting-attacker"
  | "booting-target"
  | "initializing-network"
  | "ready"
  | "testing"
  | "completed"
  | "failed"
  | "resetting";

export type MachineStatus = "offline" | "loading" | "booting" | "ready" | "degraded" | "stopped" | "failed";
export type CheckStatus = "pending" | "running" | "passed" | "failed";
export type ResourceMode = "standard" | "low";

export interface AssetDescription {
  path: string;
  available: boolean;
  required: boolean;
  bytes?: number;
  sha256?: string;
}

export interface TargetAsset {
  id: string;
  operatingSystem: string;
  architecture: string;
  phpVersion: string;
  phpSource: string;
  executionMode: string;
  buildRole: "vulnerable" | "patched";
  networkAddress: string;
  memory: { standardMiB: number; lowMiB: number };
  required: boolean;
  image: AssetDescription;
}

export interface AssetManifest {
  schemaVersion: number;
  generatedAt: string;
  v86: {
    package: string;
    version: string;
    upstream: string;
    license: string;
    wasm: AssetDescription;
    fallbackWasm: AssetDescription;
    bios: AssetDescription;
    vgaBios: AssetDescription;
  };
  attacker: {
    id: string;
    operatingSystem: string;
    architecture: string;
    networkAddress: string;
    memory: { standardMiB: number; lowMiB: number };
    image: AssetDescription;
  };
  targets: TargetAsset[];
}

export interface MachineState {
  id: MachineId;
  status: MachineStatus;
  title: string;
  guestOs?: string;
  architecture?: string;
  address?: string;
  detail: string;
  error?: string;
  ramMiB?: number;
  serial: string;
  lastBootAt?: string;
}

export interface Verification {
  id: string;
  label: string;
  description: string;
  status: CheckStatus;
  detail: string;
  source: string;
  observedAt?: string;
}

export interface Telemetry {
  timestamp: number;
  guest_mem_total_kib: number;
  guest_mem_available_kib: number;
  guest_mem_used_kib: number;
  apache_worker_count: number;
  apache_modphp_rss_kib: number;
  apache_state: string;
  php_version: string;
  php_sapi: string;
  php_memory_limit: string;
  php_memory_limit_bytes: number;
  php_binary_sha256: string;
}

export interface TargetHealth {
  service: string;
  application: string;
  wordpress: boolean;
  php_version: string;
  php_sapi: string;
  memory_limit: string;
  post_max_size: string;
  upload_max_filesize: string;
  max_file_uploads: number;
  upload_progress: boolean;
  apache: string | null;
  worker_pid: number;
  time: string;
}

export interface EvidenceRecord {
  id: string;
  timestamp: string;
  category: "network" | "http" | "proxy" | "telemetry" | "log" | "rce-proof" | "system";
  title: string;
  source: string;
  machine: MachineId;
  data: string;
  genuine: true;
}

export interface LogLine {
  id: string;
  timestamp: string;
  level: "info" | "success" | "warning" | "error";
  message: string;
}

export interface SessionInfo {
  id: string;
  networkId: string;
  startedAt: string;
  targetBuild: string;
  phpVersion: string;
  flagSha256: string;
  challenge: string;
  flagSubmittedAt?: string;
  proof?: {
    observedAt: string;
    owner: string;
    path: string;
    data: string;
  };
}

export type ExerciseStepId =
  | "reconnaissance"
  | "baseline"
  | "request-analysis"
  | "investigation"
  | "reproduction"
  | "target-verification"
  | "remediation"
  | "completion";

export type ExerciseStepStatus = "locked" | "available" | "passed" | "limited" | "failed";

export interface ExerciseStep {
  id: ExerciseStepId;
  number: string;
  title: string;
  objective: string;
  requirement: string;
  status: ExerciseStepStatus;
  detail: string;
}

export interface BuildObservation {
  /** Values observed inside the guest, never taken from the manifest. */
  phpVersion: string;
  sapi: string;
  memoryLimit: string;
  postMaxSize: string;
  uploadMaxFilesize: string;
  uploadProgress: boolean;
  hardLimitDirective: string | null;
  libphpSha256: string;
  workerCount: number;
  buildInfo: string;
  flagMode: string;
  observedAt: string;
  raw: string;
}

export type BuildClassification = "vulnerable-build" | "patched-build" | "unknown";

export interface BuildAssessment {
  observation: BuildObservation;
  classification: BuildClassification;
  basis: string;
  conditions: ExerciseCondition[];
}

export interface ExerciseCondition {
  id: string;
  label: string;
  observed: string;
  requirement: string;
  met: boolean;
  note: string;
}

export interface ProbeObservation {
  id: string;
  marker: string;
  mib: number;
  startedAt: string;
  finishedAt: string;
  httpStatus: string;
  responsePreview: string;
  targetPhpLog: string;
  targetErrorLog: string;
  targetAccessLog: string;
  workersBefore: number;
  workersAfter: number;
  workersBeforePids: string;
  workersAfterPids: string;
  attackerEvidence: string;
  oomObserved: boolean;
  parserCapObserved: boolean;
  outcome: "oom-observed" | "parser-cap-observed" | "no-target-effect" | "transport-error";
  interpretation: string;
}

export interface RemediationObservation {
  observedAt: string;
  runningBuild: string;
  patchMarkerPresent: boolean;
  patchedImageAvailable: boolean;
  comparison: string;
  advisoryGuidance: string[];
  limitation: string;
}

export interface SimulationAnswer {
  questionId: string;
  choice: string;
  correct: boolean;
  observedValue: string;
}

export interface SimulationState {
  answers: SimulationAnswer[];
  passed: boolean;
  completedAt?: string;
  note: string;
}

export interface ExerciseFacts {
  build: BuildAssessment | null;
  baseline: {
    markers: string[];
    corroborated: string[];
    requests: { method: string; path: string; status: string; marker: string }[];
    observedAt: string;
  } | null;
  proxyAnalysis: {
    marker: string;
    modifiedMarker: string;
    proxySequence: number | null;
    targetLines: string[];
    modifiedAccepted: boolean;
    observedAt: string;
  } | null;
  probe: ProbeObservation | null;
  targetVerification: {
    observedAt: string;
    workers: string;
    phpLogTail: string;
    proofCheck: string;
    genuineProof: boolean;
    summary: string;
  } | null;
  remediation: RemediationObservation | null;
  simulation: SimulationState | null;
  failures: Partial<Record<ExerciseStepId, string>>;
}

export interface SnapshotMeta {
  id: string;
  createdAt: string;
  sessionId: string;
  phpVersion: string;
  attackerBytes: number;
  targetBytes: number;
  v86Version: string;
}

export type ProxyAcceptanceGateId = "process" | "browser-routing" | "interception" | "editing" | "target-log" | "disabled" | "repeater" | "errors";
export type ProxyAcceptanceGateStatus = "PENDING" | "RUNNING" | "PASS" | "FAIL" | "BLOCKED";

export interface ProxyAcceptanceGate {
  id: ProxyAcceptanceGateId;
  label: string;
  status: ProxyAcceptanceGateStatus;
  detail: string;
}

export interface ProxyAcceptanceReport {
  schema: 1;
  runId: string;
  startedAt: string;
  finishedAt: string | null;
  status: "RUNNING" | "PASS" | "FAIL";
  gates: ProxyAcceptanceGate[];
  markers: Record<string, string>;
  artifacts: Record<string, string>;
  error: string | null;
}

export interface LabState {
  view: ViewId;
  status: LabStatus;
  operation: string | null;
  error: string | null;
  notice: string | null;
  manifest: AssetManifest | null;
  assetProgress: { label: string; loaded: number; total: number } | null;
  resourceMode: ResourceMode;
  selectedTarget: string;
  machines: Record<MachineId, MachineState>;
  checks: Verification[];
  telemetry: Telemetry | null;
  health: TargetHealth | null;
  buildInfo: string;
  logs: Record<"access" | "error" | "php", string>;
  evidence: EvidenceRecord[];
  activity: LogLine[];
  session: SessionInfo | null;
  snapshots: SnapshotMeta[];
  hasUnsavedProgress: boolean;
  completedAs: "genuine-rce" | "simulated-exercise" | null;
  activeSerialMachine: MachineId;
  attackerTools: string[];
  proxyStatus: "unknown" | "running" | "failed";
  proxyAcceptance: ProxyAcceptanceReport | null;
  exercise: ExerciseFacts;
  recovery: { attempts: number; lastAt?: string; detail: string } | null;
}

export const STATUS_LABELS: Record<LabStatus, string> = {
  "not-started": "Not started",
  "loading-emulator": "Loading emulator",
  "booting-attacker": "Booting attacker",
  "booting-target": "Booting target",
  "initializing-network": "Initializing virtual network",
  ready: "Ready",
  testing: "Testing",
  completed: "Completed",
  failed: "Failed",
  resetting: "Resetting",
};
