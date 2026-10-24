import type {
  BuildAssessment,
  BuildObservation,
  ExerciseCondition,
  ExerciseFacts,
  ExerciseStep,
  ExerciseStepId,
  ExerciseStepStatus,
  LabState,
  ProbeObservation,
  SimulationAnswer,
} from "../types";
import { PATCH_INI_MARKER, classifyObservedBuild, isModPhp, parsePhpVersion } from "./cve";

export const EXERCISE_STEPS: Omit<ExerciseStep, "status" | "detail">[] = [
  {
    id: "reconnaissance",
    number: "01",
    title: "Reconnaissance",
    objective: "Identify the running services, execution mode and PHP request limits from the target itself.",
    requirement: "Real target configuration read over the isolated network: SAPI, PHP build, memory and multipart limits, flag mode.",
  },
  {
    id: "baseline",
    number: "02",
    title: "Baseline testing",
    objective: "Send ordinary requests from the attacker guest and inspect the genuine responses.",
    requirement: "At least three real HTTP exchanges, each with a unique marker corroborated by the target's access log.",
  },
  {
    id: "request-analysis",
    number: "03",
    title: "Request analysis",
    objective: "Route a request through the real RangeProxy and observe it being modified before forwarding.",
    requirement: "A proxied request and a modified POST, both visible in the guest proxy record and in the target log.",
  },
  {
    id: "investigation",
    number: "04",
    title: "Vulnerability investigation",
    objective: "Decide whether this exact build and configuration match the advisory's vulnerable conditions.",
    requirement: "Build classified from observed version plus patch marker, and each applicable condition recorded with its observed value.",
  },
  {
    id: "reproduction",
    number: "05",
    title: "Controlled reproduction",
    objective: "Send one bounded request-processing probe to the isolated target and record what actually happens.",
    requirement: "A real chunked multipart probe with its response, target logs and worker state captured. OOM is not code execution.",
  },
  {
    id: "target-verification",
    number: "06",
    title: "Target-side verification",
    objective: "Corroborate the probe against the target's own files, processes and logs, and check for genuine execution evidence.",
    requirement: "Target-side log tails, process state, and an honest verdict on whether any Apache-owned execution proof exists.",
  },
  {
    id: "remediation",
    number: "07",
    title: "Remediation",
    objective: "Compare the running vulnerable build with the verified patched release and the advisory's configuration mitigations.",
    requirement: "Patch-marker comparison against pinned upstream sources, plus the advisory's mitigation limits stated explicitly.",
  },
  {
    id: "completion",
    number: "08",
    title: "Completion",
    objective: "Award the CTF objective only on genuinely verified target-side execution, and keep simulation separate.",
    requirement: "An Apache-owned challenge proof created after provisioning, plus the matching session flag read through that context.",
  },
];

export function emptyExercise(): ExerciseFacts {
  return {
    build: null,
    baseline: null,
    proxyAnalysis: null,
    probe: null,
    targetVerification: null,
    remediation: null,
    simulation: null,
    failures: {},
  };
}

/** The patch marker plus the observed PHP limits, described without inventing behaviour. */
export function assessBuild(observation: BuildObservation): BuildAssessment {
  const { classification, basis } = classifyObservedBuild({
    phpVersion: observation.phpVersion,
    sapi: observation.sapi,
    hardLimitDirective: observation.hardLimitDirective,
  });
  const memoryLimitBytes = parseIniBytes(observation.memoryLimit);
  const postMaxBytes = parseIniBytes(observation.postMaxSize);
  const conditions: ExerciseCondition[] = [
    {
      id: "sapi",
      label: "SAPI runs request startup automatically",
      observed: observation.sapi || "not reported",
      requirement: "apache2handler (Apache mod_php)",
      met: isModPhp(observation.sapi),
      note: isModPhp(observation.sapi)
        ? "mod_php runs request shutdown even when request startup failed, which is the condition the advisory calls highest risk."
        : "Without mod_php, the advisory's application-independent shutdown path does not apply to this SAPI.",
    },
    {
      id: "memory-limit",
      label: "Finite per-request memory limit",
      observed: observation.memoryLimit || "not reported",
      requirement: "a finite memory_limit (the advisory's mitigation is -1)",
      met: memoryLimitBytes !== null && memoryLimitBytes > 0,
      note: memoryLimitBytes !== null && memoryLimitBytes > 0
        ? "A predictable ceiling exists, so a parsing strategy can aim at it."
        : "With memory_limit=-1 the advisory's primary configuration mitigation is in place.",
    },
    {
      id: "multipart",
      label: "Multipart parsing enabled",
      observed: `post_max_size=${observation.postMaxSize}, upload_max_filesize=${observation.uploadMaxFilesize}`,
      requirement: "multipart bodies are accepted and parsed before application code",
      met: postMaxBytes !== null && postMaxBytes > 0,
      note: "The advisory lists multipart framing and part headers as the request-startup OOM strategy, so this surface decides what is reachable.",
    },
    {
      id: "upload-progress",
      label: "Upload progress session handler",
      observed: observation.uploadProgress ? "enabled" : "disabled",
      requirement: "relevant to the companion advisory GHSA-6wmf-4rv5-p3rp",
      met: observation.uploadProgress,
      note: observation.uploadProgress
        ? "Upload progress is enabled; the companion advisory's session path is present in this configuration."
        : "Upload progress is disabled, removing the companion advisory's session path from this configuration.",
    },
    {
      id: "workers",
      label: "Multiple prefork workers",
      observed: `${observation.workerCount} httpd process(es)`,
      requirement: "more than one worker so the process survives individual request failures",
      met: observation.workerCount > 1,
      note: "Worker count is measured from the guest process table, not assumed.",
    },
    {
      id: "patch-marker",
      label: "Allocator patch marker",
      observed: observation.hardLimitDirective === null ? `${PATCH_INI_MARKER} absent` : `${PATCH_INI_MARKER}=${observation.hardLimitDirective}`,
      requirement: "patched builds expose the delayed-OOM hard-limit directive",
      met: observation.hardLimitDirective !== null,
      note: observation.hardLimitDirective !== null
        ? "The fixed allocator is compiled in: OOM is deferred to a VM safe point instead of an immediate longjmp()."
        : "The build has no hard-limit directive, consistent with the pre-8.2.35 immediate longjmp() OOM path from the source diff.",
    },
  ];
  if (memoryLimitBytes !== null && postMaxBytes !== null && postMaxBytes < memoryLimitBytes) {
    conditions.push({
      id: "parser-cap",
      label: "Declared parser cap versus memory limit",
      observed: `post_max_size=${observation.postMaxSize} < memory_limit=${observation.memoryLimit}`,
      requirement: "does not by itself prevent OOM during parsing",
      met: false,
      note: "The advisory records that a multipart request without a usable declared content length can pass the initial post_max_size check, so this cap does not by itself prevent OOM during parsing. Only the probe measures the real behaviour.",
    });
  }
  return { observation, classification, basis, conditions };
}

export function parseIniBytes(value: string): number | null {
  const match = /^\s*(-?\d+)\s*([kmg]?)\s*$/i.exec(value ?? "");
  if (!match) return null;
  let bytes = Number(match[1]);
  if (!Number.isFinite(bytes)) return null;
  const suffix = (match[2] ?? "").toUpperCase();
  if (suffix === "K") bytes *= 1024;
  else if (suffix === "M") bytes *= 1024 ** 2;
  else if (suffix === "G") bytes *= 1024 ** 3;
  return bytes;
}

export function classifyProbeOutcome(input: {
  response: string;
  phpLog: string;
  errorLog: string;
  accessLog: string;
  workersBefore: number;
  workersAfter: number;
  transportError: string | null;
  marker: string;
}): Pick<ProbeObservation, "httpStatus" | "oomObserved" | "parserCapObserved" | "outcome" | "interpretation"> {
  const statusLine = /HTTP\/1\.[01]\s+(\d{3}[^\r\n]*)/.exec(input.response)?.[1]?.trim() ?? "no HTTP response";
  const combined = `${input.response}\n${input.phpLog}\n${input.errorLog}\n${input.accessLog}`;
  const oomObserved = /Allowed memory size of \d+ bytes exhausted/i.test(combined);
  const parserCapObserved = /exceeds the limit of \d+ bytes|Request Entity Too Large|Content-Length of \d+ bytes/i.test(combined);
  if (!input.response && input.transportError) {
    return {
      httpStatus: "no HTTP response",
      oomObserved,
      parserCapObserved,
      outcome: "transport-error",
      interpretation: `The raw socket exchange failed before a response was read (${input.transportError}). A transport failure is not an exploit result.`,
    };
  }
  if (oomObserved) {
    return {
      httpStatus: statusLine,
      oomObserved,
      parserCapObserved,
      outcome: "oom-observed",
      interpretation: "The target recorded a PHP memory-limit exhaustion. That is the OOM primitive the advisory describes, and it is still not code execution: no proof file or flag read followed from it.",
    };
  }
  if (parserCapObserved) {
    return {
      httpStatus: statusLine,
      oomObserved,
      parserCapObserved,
      outcome: "parser-cap-observed",
      interpretation: "PHP's multipart/post-size limit rejected or stopped the body before the memory limit was reached. Recorded as an observed limit, not as a vulnerability or a fix.",
    };
  }
  return {
    httpStatus: statusLine,
    oomObserved,
    parserCapObserved,
    outcome: "no-target-effect",
    interpretation: "The target answered without a memory-limit or size-limit record. The probe did not produce the advisory's condition on this attempt.",
  };
}

function passed(detail: string): { status: ExerciseStepStatus; detail: string } {
  return { status: "passed", detail };
}

function available(detail: string): { status: ExerciseStepStatus; detail: string } {
  return { status: "available", detail };
}

function locked(detail: string): { status: ExerciseStepStatus; detail: string } {
  return { status: "locked", detail };
}

/**
 * Derive every step status from recorded facts. Steps unlock only when the
 * previous step's real requirement is satisfied; nothing is stored as "done"
 * because a button was pressed.
 */
export function evaluateExercise(state: Pick<LabState, "exercise" | "status" | "session" | "completedAs" | "checks">): {
  steps: ExerciseStep[];
  genuineCompletion: boolean;
  simulationAvailable: boolean;
  blockers: string[];
} {
  const facts = state.exercise;
  const results: Record<ExerciseStepId, { status: ExerciseStepStatus; detail: string }> = {} as never;
  const blockers: string[] = [];

  const networkReady = state.checks.length > 0 && state.checks.every((check) => check.status === "passed");
  const labRunning = ["ready", "testing", "completed"].includes(state.status);
  const build = facts.build;
  const reconOk = Boolean(build) && networkReady;

  results.reconnaissance = !labRunning
    ? locked("Start the lab so the real target is running; nothing is inspected before that.")
    : facts.failures.reconnaissance
      ? { status: "failed", detail: facts.failures.reconnaissance }
      : reconOk && build
        ? passed(`${build.classification} · ${build.observation.sapi} · PHP ${build.observation.phpVersion} · ${build.observation.memoryLimit}/${build.observation.postMaxSize}`)
        : available(networkReady ? "Target not inspected yet. Run the inspection to read its real configuration." : "Waiting for the isolated network checks to pass on the running guests.");

  const baseline = facts.baseline;
  results.baseline = !reconOk
    ? locked("Requires completed reconnaissance.")
    : facts.failures.baseline
      ? { status: "failed", detail: facts.failures.baseline }
      : baseline && baseline.corroborated.length >= 3
        ? passed(`${baseline.requests.length} exchanges, all corroborated in the target access log: ${baseline.corroborated.sort().join(", ")}`)
        : available("Send ordinary GET and POST requests and require the target's own access log to show each marker.");

  const analysis = facts.proxyAnalysis;
  results["request-analysis"] = results.baseline.status !== "passed"
    ? locked("Requires completed baseline testing.")
    : facts.failures["request-analysis"]
      ? { status: "failed", detail: facts.failures["request-analysis"] }
      : analysis && analysis.targetLines.length >= 2
        ? passed(`Proxy sequence ${analysis.proxySequence ?? "n/a"} forwarded ${analysis.marker}; modified POST ${analysis.modifiedMarker} was accepted by the target${analysis.modifiedAccepted ? "" : " (credentials rejected)"}.`)
        : available("Route one request and one modified POST through RangeProxy and corroborate both in the target log.");

  const investigation = facts.build;
  results.investigation = results["request-analysis"].status !== "passed"
    ? locked("Requires completed request analysis.")
    : facts.failures.investigation
      ? { status: "failed", detail: facts.failures.investigation }
      : investigation && investigation.classification !== "unknown"
        ? passed(`${investigation.classification}. ${investigation.basis}`)
        : available("Classify the running build from its observed version and patch marker.");

  const probe = facts.probe;
  results.reproduction = results.investigation.status !== "passed"
    ? locked("Requires a classified build.")
    : facts.failures.reproduction
      ? { status: "failed", detail: facts.failures.reproduction }
      : probe
        ? passed(`${probe.mib} MiB probe (${probe.outcome}) · ${probe.httpStatus} · workers ${probe.workersBefore}→${probe.workersAfter}. ${probe.interpretation}`)
        : available("Run one bounded probe and record the real target behaviour.");

  const verification = facts.targetVerification;
  results["target-verification"] = results.reproduction.status !== "passed"
    ? locked("Requires a completed reproduction attempt.")
    : facts.failures["target-verification"]
      ? { status: "failed", detail: facts.failures["target-verification"] }
      : verification
        ? passed(`${verification.summary}${verification.genuineProof ? " Genuine execution proof present." : " No genuine execution proof exists for this session."}`)
        : available("Read the target's own logs and process state and look for Apache-owned proof.");

  const remediation = facts.remediation;
  results.remediation = results["target-verification"].status !== "passed"
    ? locked("Requires target-side verification.")
    : facts.failures.remediation
      ? { status: "failed", detail: facts.failures.remediation }
      : remediation
        ? passed(`${remediation.runningBuild}; patch marker ${remediation.patchMarkerPresent ? "present" : "absent"}; patched comparison image ${remediation.patchedImageAvailable ? "available" : "not provisioned"}. ${remediation.limitation}`)
        : available("Compare the running build with the patched release and the advisory's mitigations.");

  const genuine = Boolean(state.session?.proof && state.session.flagSubmittedAt && state.completedAs === "genuine-rce");
  results.completion = genuine
    ? passed("Genuine target-side execution proof and the matching session flag are both verified.")
    : results.remediation.status === "passed"
      ? {
        status: "limited",
        detail: facts.targetVerification?.genuineProof
          ? "Genuine proof exists but the matching session flag has not been submitted yet."
          : "No genuine exploitation path was verified for this build, so the genuine CTF objective stays unavailable. The simulation is recorded separately and never changes this status.",
      }
      : locked("Requires completed remediation comparison.");

  if (results.completion.status === "limited") {
    blockers.push("Genuine RCE completion is unavailable: no target-side execution proof has been produced for this session.");
  }
  if (build?.classification === "unknown") {
    blockers.push(`Build classification is unresolved: ${build.basis}`);
  }
  if (facts.probe && facts.probe.outcome === "oom-observed" && !genuine) {
    blockers.push("An OOM was observed, but OOM alone is not code execution and is not accepted as completion evidence.");
  }

  const steps: ExerciseStep[] = EXERCISE_STEPS.map((definition) => ({
    ...definition,
    status: results[definition.id].status,
    detail: results[definition.id].detail,
  }));

  return {
    steps,
    genuineCompletion: genuine,
    simulationAvailable: results.remediation.status === "passed" && !genuine,
    blockers,
  };
}


/**
 * Cross-checks performed on the raw reconnaissance readings before they become
 * exercise facts. Returns the concrete problems; an empty array means the
 * target is configured as the lab requires.
 */
export function validateReconFacts(input: {
  httpStatus: string;
  httpFlagStatus: string;
  flagMode: string;
  listeners: string;
  sapi: string;
  phpCli: string;
}): string[] {
  const problems: string[] = [];
  if (!/200/.test(input.httpStatus)) problems.push(`/health.php returned "${input.httpStatus}" instead of HTTP 200`);
  if (!isModPhp(input.sapi)) problems.push(`the target reported SAPI "${input.sapi}", not Apache mod_php`);
  if (input.httpFlagStatus !== "403") problems.push(`/flag.txt returned ${input.httpFlagStatus || "no status"} to the attacker; the target must deny it (expected 403)`);
  if (!/^root\s+apache\s+640\s/.test(input.flagMode)) problems.push(`flag permissions are "${input.flagMode}", expected root:apache 0640`);
  if (!/:80\s/.test(input.listeners)) problems.push("no TCP :80 listener was observed in the target socket table");
  if (!/version=8\./.test(input.phpCli)) problems.push(`the target PHP CLI did not report a version: ${input.phpCli.slice(-200)}`);
  return problems;
}

/** A probe outcome can never by itself be genuine code execution. */
export function probeAwardsExecution(probe: Pick<ProbeObservation, "outcome"> | null): boolean {
  return false && Boolean(probe);
}

export interface SimulationQuestion {
  id: string;
  prompt: string;
  correct: (build: BuildAssessment) => string;
  choices: string[];
  because: string;
}

/**
 * A knowledge check answered from the *observed* build. It never produces a
 * target-side effect, never shows a fabricated prompt, and is stored apart from
 * genuine exploitation status.
 */
export const SIMULATION_QUESTIONS: SimulationQuestion[] = [
  {
    id: "sapi",
    prompt: "Which request-handling mode did the target actually report?",
    correct: (build) => build.observation.sapi,
    choices: ["apache2handler", "fpm-fcgi", "cli-server", "cgi-fcgi"],
    because: "The advisory singles out mod_php because it runs request shutdown even after a failed startup.",
  },
  {
    id: "limit",
    prompt: "Which observed setting creates the predictable per-request ceiling the advisory's mitigation removes?",
    correct: (build) => build.observation.memoryLimit,
    choices: (() => ["128M", "-1", "unlimited", "0"]) as unknown as string[],
    because: "memory_limit is the ceiling; the advisory's configuration mitigation is to enforce -1 administratively.",
  },
  {
    id: "marker",
    prompt: "Which allocator patch marker is absent from this build?",
    correct: () => PATCH_INI_MARKER,
    choices: [PATCH_INI_MARKER, "post_max_size", "max_input_vars", "opcache.enable"],
    because: "The 8.2.35 source diff adds memory_hard_limit_percent alongside the delayed-OOM allocator change.",
  },
];

/** Choices are static; the limit question is rewritten from the observation at call time. */
export function simulationChoices(question: SimulationQuestion, build: BuildAssessment): string[] {
  if (question.id === "limit") {
    const seen = build.observation.memoryLimit || "not reported";
    return [seen, "-1", "unlimited", "0"];
  }
  return question.choices;
}

export function validateSimulationAnswer(
  question: SimulationQuestion,
  choice: string,
  build: BuildAssessment,
): SimulationAnswer {
  const expected = question.correct(build);
  return {
    questionId: question.id,
    choice,
    correct: choice === expected,
    observedValue: expected,
  };
}

/** Genuine completion requires every independently checked property. */
export function validateGenuineCompletion(state: Pick<LabState, "session" | "completedAs">): { ok: boolean; reason: string } {
  const session = state.session;
  if (!session) return { ok: false, reason: "No active session." };
  if (!session.proof) return { ok: false, reason: "No target-side execution proof was observed." };
  if (!session.flagSubmittedAt) return { ok: false, reason: "The session flag has not been submitted." };
  if (session.proof.owner !== "apache") return { ok: false, reason: `The proof file owner is ${session.proof.owner}, not apache.` };
  if (state.completedAs !== "genuine-rce") return { ok: false, reason: "Completion was not recorded as genuine exploitation." };
  return { ok: true, reason: "Apache-owned proof and matching session flag verified." };
}

/** Used by the flag validator and by tests: version-independent digest compare. */
export function flagDigestMatches(expectedDigest: string, submittedDigest: string): boolean {
  return expectedDigest.length === 64 && expectedDigest === submittedDigest;
}

export function isFlagShaped(value: string): boolean {
  return /^RANGE\{[0-9a-f]{48}\}$/.test(value.trim());
}

export function describeExerciseProgress(steps: ExerciseStep[]): string {
  const done = steps.filter((step) => step.status === "passed").length;
  return `${done}/${steps.length} steps verified`;
}

export function stepById(steps: ExerciseStep[], id: ExerciseStepId): ExerciseStep | undefined {
  return steps.find((step) => step.id === id);
}

export function phpPatchLevel(version: string): string {
  const parsed = parsePhpVersion(version);
  return parsed ? `${parsed.major}.${parsed.minor}.${parsed.patch}` : "unknown";
}
