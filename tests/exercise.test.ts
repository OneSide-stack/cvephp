import { readFile, readdir } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import type { BuildAssessment, ExerciseFacts, LabState, Verification } from "../src/types";
import {
  SIMULATION_QUESTIONS,
  assessBuild,
  classifyProbeOutcome,
  emptyExercise,
  evaluateExercise,
  flagDigestMatches,
  isFlagShaped,
  parseIniBytes,
  simulationChoices,
  validateGenuineCompletion,
  validateReconFacts,
  validateSimulationAnswer,
} from "../src/lib/exercise";
import { ADVISORY, PATCH_INI_MARKER, PATCHED_RELEASES, classifyObservedBuild } from "../src/lib/cve";

const OBSERVED_VULNERABLE = {
  phpVersion: "8.2.34",
  sapi: "apache2handler",
  memoryLimit: "128M",
  postMaxSize: "16M",
  uploadMaxFilesize: "8M",
  uploadProgress: true,
  hardLimitDirective: null,
  libphpSha256: "a".repeat(64),
  workerCount: 3,
  buildInfo: "schema=1\nphp_source_version=8.2.34\ncve_reproduction_status=unverified-for-this-32-bit-build",
  flagMode: "root apache 640 57 /var/www/html/flag.txt · HTTP 403",
  observedAt: "2026-10-24T10:00:00.000Z",
  raw: "observed",
};

const OBSERVED_PATCHED = {
  ...OBSERVED_VULNERABLE,
  phpVersion: "8.2.35",
  hardLimitDirective: "-1",
  buildInfo: "schema=1\nphp_source_version=8.2.35\ncve_reproduction_status=unverified-for-this-32-bit-build",
};

const passedChecks: Verification[] = ["a", "b"].map((id) => ({
  id,
  label: id,
  description: id,
  status: "passed",
  detail: "observed",
  source: "guest",
}));

function assessment(overrides: Partial<typeof OBSERVED_VULNERABLE> = {}): BuildAssessment {
  return assessBuild({ ...OBSERVED_VULNERABLE, ...overrides });
}

function facts(overrides: Partial<ExerciseFacts> = {}): ExerciseFacts {
  const build = assessment();
  return {
    ...emptyExercise(),
    build,
    baseline: {
      markers: ["m1", "m2", "m3"],
      corroborated: ["m1", "m2", "m3"],
      requests: [
        { method: "GET", path: "/?evidence=m1", status: "200", marker: "m1" },
        { method: "GET", path: "/wp-login.php?evidence=m2", status: "200", marker: "m2" },
        { method: "POST", path: "/wp-login.php?evidence=m3", status: "200", marker: "m3" },
      ],
      observedAt: "2026-10-24T10:01:00.000Z",
    },
    proxyAnalysis: {
      marker: "analysis-1",
      modifiedMarker: "repeater-1",
      proxySequence: 7,
      targetLines: ["line-analysis", "line-repeater"],
      modifiedAccepted: true,
      observedAt: "2026-10-24T10:02:00.000Z",
    },
    probe: {
      id: "probe-1",
      marker: "probe-1",
      mib: 8,
      startedAt: "2026-10-24T10:03:00.000Z",
      finishedAt: "2026-10-24T10:04:00.000Z",
      httpStatus: "500 Internal Server Error",
      responsePreview: "",
      targetPhpLog: "PHP Fatal error: Allowed memory size of 134217728 bytes exhausted (tried to allocate 20480 bytes)",
      targetErrorLog: "",
      targetAccessLog: "",
      workersBefore: 3,
      workersAfter: 2,
      workersBeforePids: "1 2 3",
      workersAfterPids: "1 3",
      attackerEvidence: "/home/tc/lab-evidence/probe-oom-1.json",
      oomObserved: true,
      parserCapObserved: false,
      outcome: "oom-observed",
      interpretation: "OOM observed; not RCE.",
    },
    targetVerification: {
      observedAt: "2026-10-24T10:05:00.000Z",
      workers: "1 3",
      phpLogTail: "Allowed memory size exhausted",
      proofCheck: "rce-proof.txt absent",
      genuineProof: false,
      summary: "No Apache-owned challenge proof exists for this session.",
    },
    remediation: {
      observedAt: "2026-10-24T10:06:00.000Z",
      runningBuild: "vulnerable-build (PHP 8.2.34, apache2handler)",
      patchMarkerPresent: false,
      patchedImageAvailable: false,
      comparison: "advisory comparison",
      advisoryGuidance: ["update"],
      limitation: "Comparison image not provisioned.",
    },
    ...overrides,
  };
}

function labState(overrides: Partial<LabState> = {}): LabState {
  return {
    checks: passedChecks,
    status: "ready",
    session: { id: "session-a", networkId: "0", startedAt: "2026-10-24T09:59:00.000Z", targetBuild: "alpine-php-8.2.34", phpVersion: "8.2.34", flagSha256: "f".repeat(64), challenge: "challenge-a" },
    completedAs: null,
    exercise: facts(),
    ...overrides,
  } as unknown as LabState;
}

describe("verified advisory facts", () => {
  it("matches the published advisory table", () => {
    expect(ADVISORY.advisory).toBe("GHSA-w8hw-w9fx-j79w");
    expect(ADVISORY.affected).toContain("< 8.2.35");
    expect(ADVISORY.patched).toContain("8.2.35");
    expect(PATCHED_RELEASES["8.2"]).toBe(35);
    expect(PATCHED_RELEASES["8.5"]).toBe(12);
    expect(PATCH_INI_MARKER).toBe("memory_hard_limit_percent");
  });
});

describe("build classification from observed guest facts", () => {
  it("identifies the vulnerable build from version and absent patch marker", () => {
    const result = classifyObservedBuild({ phpVersion: "8.2.34", sapi: "apache2handler", hardLimitDirective: null });
    expect(result.classification).toBe("vulnerable-build");
    expect(result.basis).toContain("below the first fixed release 8.2.35");
    expect(result.basis).toContain("memory_hard_limit_percent directive is absent");
  });

  it("identifies the patched build from both independent signals", () => {
    const result = classifyObservedBuild({ phpVersion: "8.2.35", sapi: "apache2handler", hardLimitDirective: "-1" });
    expect(result.classification).toBe("patched-build");
  });

  it("refuses to guess when a distribution backport disagrees with the banner", () => {
    const result = classifyObservedBuild({ phpVersion: "8.2.34", sapi: "apache2handler", hardLimitDirective: "200" });
    expect(result.classification).toBe("unknown");
    expect(result.basis).toContain("Conflicting evidence");
  });

  it("refuses to classify unsupported or malformed versions", () => {
    expect(classifyObservedBuild({ phpVersion: "7.4.33", sapi: "apache2handler", hardLimitDirective: null }).classification).toBe("unknown");
    expect(classifyObservedBuild({ phpVersion: "not-a-version", sapi: "apache2handler", hardLimitDirective: null }).classification).toBe("unknown");
    expect(classifyObservedBuild({ phpVersion: "8.3.35", sapi: "apache2handler", hardLimitDirective: null }).classification).toBe("vulnerable-build");
    expect(classifyObservedBuild({ phpVersion: "8.4.27", sapi: "apache2handler", hardLimitDirective: "-1" }).classification).toBe("patched-build");
  });
});

describe("target configuration verification", () => {
  it("accepts the lab's intended target state", () => {
    expect(validateReconFacts({
      httpStatus: "200",
      httpFlagStatus: "403",
      flagMode: "root apache 640 57 /var/www/html/flag.txt",
      listeners: "LISTEN 0 128 0.0.0.0:80 0.0.0.0:*",
      sapi: "apache2handler",
      phpCli: "version=8.2.34\n",
    })).toEqual([]);
  });

  it.each([
    ["target served the flag over HTTP", { httpFlagStatus: "200" }, /must deny it/],
    ["flag readable by others", { flagMode: "root apache 644 57 /var/www/html/flag.txt" }, /expected root:apache 0640/],
    ["no Apache listener", { listeners: "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*" }, /no TCP :80 listener/],
    ["wrong SAPI", { sapi: "fpm-fcgi" }, /not Apache mod_php/],
    ["no PHP CLI version", { phpCli: "sh: php: not found" }, /did not report a version/],
    ["health failure", { httpStatus: "500" }, /instead of HTTP 200/],
  ])("rejects a target where %s", (_label, override, expected) => {
    const problems = validateReconFacts({
      httpStatus: "200",
      httpFlagStatus: "403",
      flagMode: "root apache 640 57 /var/www/html/flag.txt",
      listeners: "LISTEN 0 128 0.0.0.0:80 0.0.0.0:*",
      sapi: "apache2handler",
      phpCli: "version=8.2.34\n",
      ...override,
    });
    expect(problems.join(" ")).toMatch(expected);
  });

  it("records each applicable condition with its observed value", () => {
    const result = assessment();
    const byId = Object.fromEntries(result.conditions.map((condition) => [condition.id, condition]));
    expect(byId.sapi?.met).toBe(true);
    expect(byId["memory-limit"]?.observed).toBe("128M");
    expect(byId["memory-limit"]?.met).toBe(true);
    expect(byId.multipart?.met).toBe(true);
    expect(byId["upload-progress"]?.met).toBe(true);
    expect(byId.workers?.observed).toBe("3 httpd process(es)");
    expect(byId["patch-marker"]?.met).toBe(false);
    expect(byId["parser-cap"]?.note).toContain("does not by itself prevent OOM");
  });

  it("recognises the patched configuration without changing the advisory facts", () => {
    const patched = assessBuild({ ...OBSERVED_PATCHED });
    expect(patched.classification).toBe("patched-build");
    expect(patched.conditions.find((condition) => condition.id === "patch-marker")?.met).toBe(true);
  });

  it("parses PHP ini quantities the way PHP does", () => {
    expect(parseIniBytes("128M")).toBe(134217728);
    expect(parseIniBytes("16M")).toBe(16777216);
    expect(parseIniBytes("8K")).toBe(8192);
    expect(parseIniBytes("1024")).toBe(1024);
    expect(parseIniBytes("-1")).toBe(-1);
    expect(parseIniBytes("garbage")).toBeNull();
  });
});

describe("probe interpretation", () => {
  const base = {
    response: "HTTP/1.1 500 Internal Server Error\r\n\r\n",
    phpLog: "",
    errorLog: "",
    accessLog: "",
    workersBefore: 3,
    workersAfter: 3,
    transportError: null,
    marker: "probe-1",
  };

  it("reports an observed OOM without promoting it to execution", () => {
    const outcome = classifyProbeOutcome({ ...base, phpLog: "PHP Fatal error: Allowed memory size of 134217728 bytes exhausted (tried to allocate 4096 bytes)" });
    expect(outcome.outcome).toBe("oom-observed");
    expect(outcome.oomObserved).toBe(true);
    expect(outcome.interpretation).toContain("still not code execution");
  });

  it("reports the parser cap when PHP stops the body", () => {
    const outcome = classifyProbeOutcome({ ...base, response: "HTTP/1.1 200 OK\r\n\r\n", phpLog: "PHP Warning:  POST Content-Length of 20971520 bytes exceeds the limit of 16777216 bytes" });
    expect(outcome.outcome).toBe("parser-cap-observed");
    expect(outcome.parserCapObserved).toBe(true);
  });

  it("reports an uneventful probe and a transport error distinctly", () => {
    expect(classifyProbeOutcome({ ...base, response: "HTTP/1.1 200 OK\r\n\r\n" }).outcome).toBe("no-target-effect");
    const transported = classifyProbeOutcome({ ...base, response: "", transportError: "timed out" });
    expect(transported.outcome).toBe("transport-error");
    expect(transported.httpStatus).toBe("no HTTP response");
  });
});

describe("step gating from real facts", () => {
  it("unlocks only the first step before anything is observed", () => {
    const progress = evaluateExercise({ ...labState(), exercise: emptyExercise() });
    expect(progress.steps[0]?.status).toBe("available");
    expect(progress.steps.slice(1).every((step) => step.status === "locked")).toBe(true);
    expect(progress.genuineCompletion).toBe(false);
  });

  it("keeps every step locked while no guests are running", () => {
    const idle = evaluateExercise({ ...labState({ status: "not-started" }), exercise: emptyExercise() });
    expect(idle.steps.every((step) => step.status === "locked")).toBe(true);
    expect(idle.steps[0]?.detail).toContain("Start the lab");
    expect(idle.simulationAvailable).toBe(false);
  });

  it("keeps baseline locked while the network checks are incomplete", () => {
    const checks = passedChecks.map((check, index) => index === 0 ? { ...check, status: "failed" as const } : check);
    const progress = evaluateExercise({ ...labState({ checks }), exercise: emptyExercise() });
    expect(progress.steps[0]?.status).toBe("available");
    expect(progress.steps[1]?.status).toBe("locked");
  });

  it("awards each completed step from its recorded evidence", () => {
    const progress = evaluateExercise(labState());
    expect(progress.steps.map((step) => step.id)).toEqual([
      "reconnaissance", "baseline", "request-analysis", "investigation", "reproduction", "target-verification", "remediation", "completion",
    ]);
    expect(progress.steps.slice(0, 7).every((step) => step.status === "passed")).toBe(true);
    expect(progress.steps[7]?.status).toBe("limited");
    expect(progress.genuineCompletion).toBe(false);
    expect(progress.blockers.join(" ")).toContain("Genuine RCE completion is unavailable");
  });

  it("does not accept an OOM as code execution", () => {
    const progress = evaluateExercise(labState());
    const reproduction = progress.steps.find((step) => step.id === "reproduction");
    expect(reproduction?.detail).toContain("oom-observed");
    expect(progress.blockers.join(" ")).toContain("OOM alone is not code execution");
    expect(progress.steps[7]?.status).not.toBe("passed");
  });

  it("unlocks completion only for genuine proof plus the matching flag", () => {
    const state = labState();
    state.session = {
      ...state.session!,
      proof: { observedAt: "2026-10-24T10:07:00.000Z", owner: "apache", path: "/var/www/html/rce-proof.txt", data: "{}" },
      flagSubmittedAt: "2026-10-24T10:08:00.000Z",
    };
    state.completedAs = "genuine-rce";
    const progress = evaluateExercise(state);
    expect(progress.steps[7]?.status).toBe("passed");
    expect(progress.genuineCompletion).toBe(true);
    expect(progress.blockers).toEqual([]);
  });

  it("surfaces step failures instead of silently staying available", () => {
    const exercise = { ...facts(), failures: { investigation: "Conflicting evidence: version and patch marker disagree" } };
    const progress = evaluateExercise(labState({ exercise }));
    const investigation = progress.steps.find((step) => step.id === "investigation");
    expect(investigation?.status).toBe("failed");
    expect(investigation?.detail).toContain("Conflicting evidence");
    expect(progress.steps.find((step) => step.id === "reproduction")?.status).toBe("locked");
  });
});

describe("genuine completion validation", () => {
  const genuineSession = {
    id: "s1",
    networkId: "0",
    startedAt: "2026-10-24T09:59:00.000Z",
    targetBuild: "alpine-php-8.2.34",
    phpVersion: "8.2.34",
    flagSha256: "f".repeat(64),
    challenge: "challenge-a",
    proof: { observedAt: "2026-10-24T10:07:00.000Z", owner: "apache", path: "/var/www/html/rce-proof.txt", data: "{}" },
    flagSubmittedAt: "2026-10-24T10:08:00.000Z",
  };

  it("accepts only Apache-owned proof with a submitted flag", () => {
    expect(validateGenuineCompletion({ session: genuineSession, completedAs: "genuine-rce" }).ok).toBe(true);
    expect(validateGenuineCompletion({ session: genuineSession, completedAs: "simulated-exercise" }).ok).toBe(false);
    expect(validateGenuineCompletion({ session: { ...genuineSession, proof: undefined }, completedAs: "genuine-rce" }).ok).toBe(false);
    expect(validateGenuineCompletion({ session: { ...genuineSession, flagSubmittedAt: undefined }, completedAs: "genuine-rce" }).ok).toBe(false);
    expect(validateGenuineCompletion({ session: { ...genuineSession, proof: { ...genuineSession.proof, owner: "lab" } }, completedAs: "genuine-rce" }).reason).toContain("not apache");
  });

  it("treats another session's proof as absent", () => {
    const other = labState({ completedAs: "genuine-rce" });
    other.session = { ...other.session!, id: "session-b", challenge: "challenge-b", flagSha256: "e".repeat(64) };
    const progress = evaluateExercise(other);
    expect(progress.genuineCompletion).toBe(false);
    expect(validateGenuineCompletion(other).ok).toBe(false);
  });
});

describe("flag handling", () => {
  it("compares only full 64-character digests", () => {
    expect(flagDigestMatches("a".repeat(64), "a".repeat(64))).toBe(true);
    expect(flagDigestMatches("a".repeat(64), "b".repeat(64))).toBe(false);
    expect(flagDigestMatches("", "")).toBe(false);
    expect(flagDigestMatches("a".repeat(64), "a".repeat(63))).toBe(false);
  });

  it("recognises the shape of a target-generated flag", () => {
    expect(isFlagShaped(`RANGE{${"0123456789abcdef".repeat(3)}}`)).toBe(true);
    expect(isFlagShaped("RANGE{UNPROVISIONED}")).toBe(false);
    expect(isFlagShaped("RANGE{deadbeef}")).toBe(false);
  });

  it("never hardcodes a flag in frontend source", async () => {
    const root = new URL("../src/", import.meta.url).pathname;
    const offenders: string[] = [];
    const walk = async (directory: string): Promise<void> => {
      for (const entry of await readdir(directory, { withFileTypes: true })) {
        const path = join(directory, entry.name);
        if (entry.isDirectory()) await walk(path);
        else if (/\.(ts|tsx)$/.test(entry.name)) {
          const content = await readFile(path, "utf8");
          if (/RANGE\{[0-9a-zA-Z]{8,}\}/.test(content)) offenders.push(path);
        }
      }
    };
    await walk(root);
    expect(offenders).toEqual([]);
  });
});

describe("simulation separation", () => {
  const build = assessment();

  it("answers from the observed build, not from a static key", () => {
    const sapi = SIMULATION_QUESTIONS.find((question) => question.id === "sapi")!;
    expect(validateSimulationAnswer(sapi, "apache2handler", build).correct).toBe(true);
    expect(validateSimulationAnswer(sapi, "fpm-fcgi", build).correct).toBe(false);
    const marker = SIMULATION_QUESTIONS.find((question) => question.id === "marker")!;
    expect(validateSimulationAnswer(marker, PATCH_INI_MARKER, build).observedValue).toBe(PATCH_INI_MARKER);
    const limit = SIMULATION_QUESTIONS.find((question) => question.id === "limit")!;
    expect(simulationChoices(limit, build)[0]).toBe("128M");
    expect(validateSimulationAnswer(limit, "128M", build).correct).toBe(true);
  });

  it("never grants genuine completion from simulation", () => {
    const state = labState({
      completedAs: "simulated-exercise",
      exercise: {
        ...facts(),
        simulation: {
          answers: [{ questionId: "sapi", choice: "apache2handler", correct: true, observedValue: "apache2handler" }],
          passed: true,
          completedAt: "2026-10-24T10:09:00.000Z",
          note: "Training simulation.",
        },
      },
    });
    const progress = evaluateExercise(state);
    expect(progress.genuineCompletion).toBe(false);
    expect(progress.steps[7]?.status).toBe("limited");
    expect(progress.simulationAvailable).toBe(true);
  });
});

describe("reset semantics", () => {
  it("clears every derived step and completion marker", () => {
    const reset = { ...labState({ completedAs: "genuine-rce" }), exercise: emptyExercise(), completedAs: null };
    const progress = evaluateExercise(reset);
    expect(progress.steps[0]?.status).toBe("available");
    expect(progress.genuineCompletion).toBe(false);
    expect(progress.steps[7]?.status).toBe("locked");
    expect(reset.exercise.build).toBeNull();
    expect(reset.exercise.probe).toBeNull();
  });
});
