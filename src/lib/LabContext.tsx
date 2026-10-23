import { createContext, useContext, useRef, useSyncExternalStore, type ReactNode } from "react";
import { LabController } from "./LabController";
import type { LabState } from "../types";

interface LabContextValue {
  controller: LabController;
  state: LabState;
}

const LabContext = createContext<LabContextValue | null>(null);

export function LabProvider({ children }: { children: ReactNode }) {
  const reference = useRef<LabController | null>(null);
  if (!reference.current) reference.current = new LabController();
  const controller = reference.current;
  const state = useSyncExternalStore(controller.subscribe, controller.getState, controller.getState);
  return <LabContext.Provider value={{ controller, state }}>{children}</LabContext.Provider>;
}

export function useLab(): LabContextValue {
  const value = useContext(LabContext);
  if (!value) throw new Error("useLab must be used inside LabProvider");
  return value;
}
