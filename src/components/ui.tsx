import type { ReactNode } from "react";
import { AlertTriangle, Check, CircleDot, LoaderCircle, X } from "lucide-react";
import type { CheckStatus, LabStatus, MachineStatus } from "../types";
import { STATUS_LABELS } from "../types";

export function StatusPill({ status, label }: { status: LabStatus | MachineStatus | CheckStatus | "real" | "warning"; label?: string }) {
  const text = label ?? (status in STATUS_LABELS ? STATUS_LABELS[status as LabStatus] : status.replace("-", " "));
  const spinning = ["loading-emulator", "booting-attacker", "booting-target", "initializing-network", "resetting", "loading", "booting", "running"].includes(status);
  return <span className={`status-pill status-${status}`}><span className="status-dot">{spinning ? <LoaderCircle size={12} className="spin" /> : null}</span>{text}</span>;
}

export function CheckIcon({ status }: { status: CheckStatus }) {
  if (status === "passed") return <span className="check-icon passed"><Check size={15} /></span>;
  if (status === "failed") return <span className="check-icon failed"><X size={15} /></span>;
  if (status === "running") return <span className="check-icon running"><LoaderCircle size={15} className="spin" /></span>;
  return <span className="check-icon pending"><CircleDot size={15} /></span>;
}

export function Panel({ title, eyebrow, action, children, className = "" }: { title?: string; eyebrow?: string; action?: ReactNode; children: ReactNode; className?: string }) {
  return <section className={`panel ${className}`}>
    {(title || eyebrow || action) && <header className="panel-header"><div>{eyebrow && <span className="eyebrow">{eyebrow}</span>}{title && <h2>{title}</h2>}</div>{action}</header>}
    <div className="panel-content">{children}</div>
  </section>;
}

export function PageHeading({ index, eyebrow, title, description, actions }: { index: string; eyebrow: string; title: string; description: string; actions?: ReactNode }) {
  return <div className="page-heading"><div><div className="page-kicker"><span>{index}</span>{eyebrow}</div><h1>{title}</h1><p>{description}</p></div>{actions && <div className="page-actions">{actions}</div>}</div>;
}

export function KeyValue({ label, value, mono = false, title }: { label: string; value: ReactNode; mono?: boolean; title?: string }) {
  return <div className="key-value" title={title}><span>{label}</span><strong className={mono ? "mono" : ""}>{value}</strong></div>;
}

export function EmptyState({ icon, title, children }: { icon?: ReactNode; title: string; children: ReactNode }) {
  return <div className="empty-state">{icon}<h3>{title}</h3><p>{children}</p></div>;
}

export function InlineMessage({ type, children, onClose }: { type: "error" | "warning" | "info"; children: ReactNode; onClose?: () => void }) {
  return <div className={`inline-message ${type}`} role={type === "error" ? "alert" : "status"}><AlertTriangle size={17} /><div>{children}</div>{onClose && <button className="icon-button" onClick={onClose} aria-label="Dismiss message"><X size={15} /></button>}</div>;
}

export function Meter({ value, maximum, tone = "teal" }: { value: number; maximum: number; tone?: "teal" | "amber" | "blue" }) {
  const percentage = maximum > 0 ? Math.min(100, Math.max(0, value / maximum * 100)) : 0;
  return <div className={`meter ${tone}`} role="meter" aria-valuenow={Math.round(percentage)} aria-valuemin={0} aria-valuemax={100}><span style={{ width: `${percentage}%` }} /></div>;
}
