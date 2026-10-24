import { useMemo, useState, type FormEvent } from "react";
import {
  AlertOctagon,
  ArrowRight,
  Award,
  Check,
  CheckCircle2,
  ChevronRight,
  CircleSlash2,
  ExternalLink,
  FileClock,
  Flag,
  FlaskConical,
  Info,
  KeyRound,
  ListChecks,
  LockKeyhole,
  Play,
  RefreshCw,
  RotateCcw,
  ScrollText,
  ShieldAlert,
  ShieldCheck,
  TerminalSquare,
  TriangleAlert,
  XCircle,
} from "lucide-react";
import { useLab } from "../lib/LabContext";
import { EmptyState, KeyValue, PageHeading, Panel, StatusPill } from "../components/ui";
import type { ExerciseStep } from "../types";
import { ADVISORY, LAB_REPRODUCTION_STATEMENT, PATCH_INI_MARKER } from "../lib/cve";
import { SIMULATION_QUESTIONS, describeExerciseProgress, simulationChoices, type SimulationQuestion } from "../lib/exercise";
import { formatDateTime, shortHash } from "../lib/utils";

const probeSizes = [4, 8, 16, 32];

function stepBadge(step: ExerciseStep) {
  if (step.status === "passed") return <StatusPill status="completed" label="Verified" />;
  if (step.status === "limited") return <StatusPill status="warning" label="Genuine path unavailable" />;
  if (step.status === "failed") return <StatusPill status="failed" label="Failed" />;
  if (step.status === "available") return <StatusPill status="testing" label="Ready to run" />;
  return <StatusPill status="not-started" label="Locked" />;
}

function conditionIcon(met: boolean) {
  return met ? <Check size={14} className="text-success" /> : <XCircle size={14} className="text-warning" />;
}

export function LabView() {
  const { controller, state } = useLab();
  const [flag, setFlag] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [probeMib, setProbeMib] = useState(8);
  const [probeWarning, setProbeWarning] = useState(false);
  const progress = useMemo(() => controller.exerciseSummary(), [controller, state]);
  const exercise = state.exercise;
  const busy = Boolean(state.operation);
  const running = ["ready", "testing", "completed"].includes(state.status);
  const genuine = state.completedAs === "genuine-rce";
  const simulated = state.completedAs === "simulated-exercise";
  const simulation = exercise.simulation;
  const build = exercise.build;

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setSubmitting(true);
    const accepted = await controller.submitFlag(flag);
    if (accepted) setFlag("");
    setSubmitting(false);
  };

  const stepAction = (step: ExerciseStep): { label: string; run: () => void; disabled: boolean } | null => {
    const locked = step.status === "locked" || busy || !running;
    switch (step.id) {
      case "reconnaissance":
        return { label: "Inspect the target", run: () => void controller.runRecon(), disabled: locked };
      case "baseline":
        return { label: "Send baseline requests", run: () => void controller.runBaselineSuite(), disabled: locked };
      case "request-analysis":
        return { label: "Analyse through RangeProxy", run: () => void controller.analyzeProxiedRequests(), disabled: locked };
      case "investigation":
        return { label: "Classify this build", run: () => void controller.investigateVulnerability(), disabled: locked };
      case "reproduction":
        return {
          label: `Send ${probeMib} MiB probe`,
          run: () => {
            if (probeMib > 16 && !probeWarning) {
              setProbeWarning(true);
              return;
            }
            setProbeWarning(false);
            void controller.runControlledProbe(probeMib, true);
          },
          disabled: locked,
        };
      case "target-verification":
        return { label: "Verify target-side state", run: () => void controller.verifyTargetSide(), disabled: locked };
      case "remediation":
        return { label: "Compare builds", run: () => void controller.compareRemediation(), disabled: locked };
      case "completion":
        return null;
    }
  };

  return <div className="view lab-view">
    <PageHeading
      index="04"
      eyebrow="VULNERABILITY LAB"
      title="CVE-2026-109618 · practical exercise"
      description="Eight gated steps against the real isolated target. Each step unlocks only when its own requirement was verified from guest output."
      actions={<>
        <StatusPill status="real" label={describeExerciseProgress(progress.steps)} />
        <span className="address-chip"><TerminalSquare size={14} />192.168.10.55</span>
      </>}
    />

    <div className="truth-banner">
      <ShieldAlert size={22} />
      <div>
        <strong>Verified advisory, honest reproduction status</strong>
        <p>{LAB_REPRODUCTION_STATEMENT}</p>
        <div className="banner-links">
          <a className="inline-link" href={ADVISORY.advisoryUrl} target="_blank" rel="noreferrer">{ADVISORY.advisory} · {ADVISORY.title}<ExternalLink size={12} /></a>
          <span>Affected {ADVISORY.affected.join(" · ")} → patched {ADVISORY.patched.join(" · ")}</span>
        </div>
      </div>
    </div>

    {progress.blockers.length > 0 && <div className="blocker-strip">
      <TriangleAlertRow />
      <div>{progress.blockers.map((blocker) => <span key={blocker}>{blocker}</span>)}</div>
    </div>}

    <div className="lab-layout">
      <Panel eyebrow="EXERCISE RUNBOOK" title="Steps and verified requirements" className="lab-steps-panel">
        <div className="lab-steps">
          {progress.steps.map((step) => {
            const action = stepAction(step);
            return <article className={`lab-step ${step.status}`} key={step.id}>
              <div className="lab-step-index">{step.number}</div>
              <div className="lab-step-body">
                <header>
                  <h3>{step.title}</h3>
                  {stepBadge(step)}
                </header>
                <p>{step.objective}</p>
                <div className="lab-step-detail">
                  <strong>{step.status === "passed" ? "Observed" : "Requirement"}</strong>
                  <span>{step.detail || step.requirement}</span>
                </div>
                {exercise.failures[step.id] && <div className="lab-step-failure"><AlertOctagon size={13} />{exercise.failures[step.id]}</div>}
                {step.id === "reproduction" && action && !action.disabled && <div className="probe-controls">
                  {probeSizes.map((size) => <button key={size} className={`chip-button ${probeMib === size ? "active" : ""}`} onClick={() => setProbeMib(size)}>{size} MiB</button>)}
                  {probeMib > 16 && <span className="probe-warning"><TriangleAlert size={13} />{probeWarning ? "Press again to confirm: workers may terminate." : "Requires a second confirmation."}</span>}
                </div>}
                {action && <button className={`button ${step.status === "passed" ? "secondary" : "primary"} small-button`} onClick={action.run} disabled={action.disabled}>
                  {step.status === "passed" ? <RefreshCw size={13} /> : <Play size={13} />}{step.status === "passed" ? `Re-run: ${action.label}` : action.label}
                </button>}
                {step.id === "completion" && !genuine && <p className="step-note">This step is driven by target-side proof and flag validation below, not by a button. Simulation results never unlock it.</p>}
              </div>
            </article>;
          })}
        </div>
      </Panel>

      <div className="lab-side">
        <Panel eyebrow="VERIFIED BUILD" title="What the target actually reports" action={<ShieldCheck size={17} />}>
          {build ? <>
            <KeyValue label="Classification" value={<span className={build.classification === "patched-build" ? "text-success" : "text-warning"}>{build.classification}</span>} />
            <KeyValue label="PHP version" value={build.observation.phpVersion} mono />
            <KeyValue label="SAPI" value={build.observation.sapi} mono />
            <KeyValue label="memory_limit" value={build.observation.memoryLimit} mono />
            <KeyValue label="post_max_size" value={build.observation.postMaxSize} mono />
            <KeyValue label="upload_max_filesize" value={build.observation.uploadMaxFilesize} mono />
            <KeyValue label="upload progress" value={build.observation.uploadProgress ? "enabled" : "disabled"} />
            <KeyValue label={PATCH_INI_MARKER} value={build.observation.hardLimitDirective ?? "absent"} mono />
            <KeyValue label="libphp.so SHA-256" value={shortHash(build.observation.libphpSha256, 18)} mono title={build.observation.libphpSha256} />
            <KeyValue label="httpd workers" value={String(build.observation.workerCount)} />
            <KeyValue label="flag mode" value={build.observation.flagMode} mono />
            <p className="panel-footnote">{build.basis}</p>
          </> : <EmptyState icon={<ListChecks size={24} />} title="Target not inspected">Run step 1 to read the real SAPI, PHP build, limits and patch marker.</EmptyState>}
        </Panel>

        <Panel eyebrow="SESSION & RECOVERY" title="Flag, challenge and guest state">
          {state.session ? <>
            <KeyValue label="Session" value={state.session.id} mono />
            <KeyValue label="Challenge" value={<code>{state.session.challenge}</code>} />
            <KeyValue label="Flag SHA-256" value={shortHash(state.session.flagSha256, 22)} mono title={state.session.flagSha256 || "not provisioned"} />
            <KeyValue label="Target proof" value={state.session.proof ? `apache · ${formatDateTime(state.session.proof.observedAt)}` : "not observed"} />
            <KeyValue label="Completion" value={genuine ? "Genuine exploitation" : simulated ? "Simulation only" : "Not awarded"} />
          </> : <EmptyState icon={<KeyRound size={22} />} title="No active session">Start the lab to allocate a challenge and a target-generated flag.</EmptyState>}
          <div className="recovery-actions">
            <button className="button secondary small-button" onClick={() => void controller.recoverGuests()} disabled={busy || !state.session}><RefreshCw size={13} />Check guest responsiveness</button>
            <button className="button ghost small-button" onClick={() => { if (window.confirm("Reset the exercise? This cold-boots the target, generates a new session flag and challenge inside the guest, removes the previous proof, and clears exercise completion.")) void controller.resetExercise(); }} disabled={busy || !state.session || !running}><RotateCcw size={13} />Reset exercise</button>
          </div>
          <p className="panel-footnote">Reset is a real v86 cold boot of the target followed by target-side provisioning; it is not a parent-side variable change. The attacker guest keeps running.</p>
          {state.recovery && <p className="panel-footnote">Recovery attempts: {state.recovery.attempts} · {state.recovery.detail}</p>}
        </Panel>
      </div>
    </div>

    <div className="lab-detail-grid">
      <Panel eyebrow="CONDITIONS" title="Applied to this target" action={<ListChecks size={17} />}>
        {build ? <div className="condition-list">
          {build.conditions.map((condition) => <div className={`condition-row ${condition.met ? "met" : "unmet"}`} key={condition.id}>
            <span>{conditionIcon(condition.met)}</span>
            <div><strong>{condition.label}</strong><span>{condition.note}</span></div>
            <div className="condition-values"><code>{condition.observed}</code><small>{condition.requirement}</small></div>
          </div>)}
        </div> : <EmptyState title="No conditions assessed">Step 1 and step 4 produce this comparison from observed values.</EmptyState>}
      </Panel>

      <Panel eyebrow="PROBE OBSERVATION" title="What the target did" action={<FlaskConical size={17} />}>
        {exercise.probe ? <div className="probe-summary">
          <div className={`probe-outcome ${exercise.probe.outcome}`}>
            <span><ScrollText size={16} />{exercise.probe.outcome}</span>
            <strong>{exercise.probe.httpStatus}</strong>
            <small>{exercise.probe.mib} MiB · {formatDateTime(exercise.probe.finishedAt)}</small>
          </div>
          <KeyValue label="Workers before → after" value={`${exercise.probe.workersBefore} → ${exercise.probe.workersAfter}`} />
          <KeyValue label="PHP OOM recorded" value={exercise.probe.oomObserved ? "yes" : "no"} />
          <KeyValue label="Size-limit record" value={exercise.probe.parserCapObserved ? "yes" : "no"} />
          <KeyValue label="Guest evidence file" value={<code>{exercise.probe.attackerEvidence}</code>} />
          <p className="panel-footnote">{exercise.probe.interpretation}</p>
          <details className="probe-details"><summary><FileClock size={13} />Response preview</summary><pre>{exercise.probe.responsePreview || "(no response bytes)"}</pre></details>
          <details className="probe-details"><summary><ScrollText size={13} />Target PHP/Apache log tails</summary><pre>{exercise.probe.targetPhpLog || "(empty)"}</pre><pre>{exercise.probe.targetErrorLog || "(empty)"}</pre></details>
        </div> : <EmptyState icon={<FlaskConical size={24} />} title="No probe yet">Step 5 sends one bounded multipart probe from the attacker guest. Its outcome is recorded even when nothing interesting happens.</EmptyState>}
      </Panel>
    </div>

    {exercise.targetVerification && <Panel eyebrow="TARGET-SIDE VERIFICATION" title="Independent guest state" action={<ShieldCheck size={17} />}>
      <div className="verification-grid">
        <div><strong>Verdict</strong><p>{exercise.targetVerification.summary}</p><small>{formatDateTime(exercise.targetVerification.observedAt)}</small></div>
        <div><strong>Genuine execution proof</strong><p>{exercise.targetVerification.genuineProof ? <span className="text-success">present and Apache-owned</span> : <span className="text-warning">absent</span>}</p><small>Checked with target-side file metadata and the session challenge.</small></div>
      </div>
      <details className="probe-details"><summary><ScrollText size={13} />Process state and proof check</summary><pre>{exercise.targetVerification.workers}</pre><pre>{exercise.targetVerification.proofCheck}</pre></details>
    </Panel>}

    {exercise.remediation && <Panel eyebrow="REMEDIATION" title="Vulnerable versus patched" action={<CheckCircle2 size={17} />}>
      <p className="remediation-lead">{exercise.remediation.comparison}</p>
      <div className="remediation-grid">
        <div><strong>Advisory mitigations <small>(not a fix)</small></strong><ul>{exercise.remediation.advisoryGuidance.map((item) => <li key={item}>{item}</li>)}</ul></div>
        <div><strong>Comparison status</strong><p>{exercise.remediation.limitation}</p><KeyValue label="Patched image available" value={exercise.remediation.patchedImageAvailable ? "yes" : "no"} /><KeyValue label="Patch marker on running build" value={exercise.remediation.patchMarkerPresent ? "present" : "absent"} /></div>
      </div>
    </Panel>}

    <div className="lab-completion-grid">
      <Panel eyebrow="CTF" title="Genuine completion" className="flag-panel">
        {genuine ? <div className="completion-card"><span className="completion-seal"><Award size={30} /></span><div><h3>Genuine target-side completion verified</h3><p>An Apache-owned challenge proof and the matching session flag were both independently verified.</p><span>{formatDateTime(state.session?.flagSubmittedAt)}</span></div></div> : <>
          <p>The flag lives inside the target guest and is only readable through an execution context running as the Apache worker. Submitting it here also requires the fresh, target-owned proof from step 6 and every earlier step.</p>
          <form className="flag-form" onSubmit={(event) => void submit(event)}>
            <label htmlFor="lab-flag">Session flag</label>
            <div>
              <Flag size={17} />
              <input id="lab-flag" value={flag} onChange={(event) => setFlag(event.target.value)} placeholder="RANGE{…}" autoComplete="off" spellCheck={false} />
              <button className="button primary" disabled={!flag.trim() || submitting || !state.session} type="submit">{submitting ? "Checking…" : "Validate flag"}<ChevronRight size={15} /></button>
            </div>
          </form>
          <div className="completion-checklist">
            <div className={state.session?.proof ? "done" : ""}>{state.session?.proof ? <Check size={14} /> : <XCircle size={14} />}Apache-owned challenge proof</div>
            <div className={state.session?.flagSubmittedAt ? "done" : ""}>{state.session?.flagSubmittedAt ? <Check size={14} /> : <LockKeyhole size={14} />}Matching session flag</div>
          </div>
        </>}
        <div className="ctf-limitation"><Info size={14} /><span>This token is a training objective, not an authorization secret. No shell prompt is ever fabricated by this interface.</span></div>
      </Panel>

      <Panel eyebrow="SIMULATION · NOT EXPLOITATION" title="Check your reading of the evidence" className="simulation-panel">
        <div className="simulation-banner"><CircleSlash2 size={16} /><span>This is a knowledge check answered from the observed guest configuration. It performs no target-side effect, awards no genuine completion, and is stored separately.</span></div>
        {!progress.simulationAvailable && !simulated && <p className="panel-footnote">Available once the remediation step is verified. It never substitutes for a missing exploit.</p>}
        {simulation?.answers.length ? <div className="simulation-answers">{simulation.answers.map((answer) => <div key={answer.questionId} className={answer.correct ? "correct" : "wrong"}>{answer.correct ? <Check size={13} /> : <XCircle size={13} />}<span>{answer.questionId}: <code>{answer.choice}</code>{answer.correct ? "" : ` · observed ${answer.observedValue}`}</span></div>)}</div> : null}
        {simulated && <div className="simulation-complete"><CheckCircle2 size={16} /><span>Completed {formatDateTime(simulation?.completedAt)} as <strong>simulation only</strong>.</span></div>}
        <div className="simulation-questions">
          {(SIMULATION_QUESTIONS as SimulationQuestion[]).map((question) => <div className="simulation-question" key={question.id}>
            <strong>{question.prompt}</strong>
            <div>{build ? simulationChoices(question, build).map((choice) => {
              const answered = simulation?.answers.find((answer) => answer.questionId === question.id)?.choice === choice;
              return <button key={choice} className={`chip-button ${answered ? "active" : ""}`} onClick={() => controller.answerSimulation(question.id, choice)} disabled={!build || !progress.simulationAvailable || busy || genuine}>{choice}</button>;
            }) : <span className="panel-footnote">Needs step 1.</span>}</div>
          </div>)}
        </div>
      </Panel>
    </div>

    <div className="lab-footer">
      <ArrowRight size={14} />
      <span>Every step above re-runs against the live guests. Use the attacker workstation and target views to inspect raw output yourself; this view never invents it.</span>
    </div>
  </div>;
}

function TriangleAlertRow() {
  return <span className="blocker-icon"><TriangleAlert size={16} /></span>;
}
