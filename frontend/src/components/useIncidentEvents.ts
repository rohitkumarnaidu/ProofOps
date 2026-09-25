import { useEffect, useRef, useState } from "react";
import { apiBase, auditApi } from "../api";
import {
  streamEventId,
  subscribeStream,
  type StreamConnectionState,
  type StreamItem,
} from "../sse";

export const INCIDENT_EVENT_TYPES = [
  "transition",
  "policy.decision",
  "verification.verdict",
] as const;

export const INCIDENT_EVENT_PREFIXES = [
  "approval.",
  "execution.",
  "rollback.",
  "rca.",
] as const;

export type IncidentEventType =
  | (typeof INCIDENT_EVENT_TYPES)[number]
  | `${(typeof INCIDENT_EVENT_PREFIXES)[number]}${string}`;

export interface IncidentEvent extends StreamItem {
  type?: string;
  event_type?: string;
}

export type IncidentEventConnectionState =
  | StreamConnectionState
  | "idle";

export interface UseIncidentEventsOptions {
  incidentId: string | undefined;
  enabled?: boolean;
  onRefresh: () => void;
  debounceMs?: number;
}

export interface IncidentEventsState {
  connectionState: IncidentEventConnectionState;
  lastEventId: string | null;
  lastEvent: IncidentEvent | null;
  lastEventType: IncidentEventType | null;
  lastByType: Partial<Record<string, IncidentEvent>>;
  error: string;
}

// Must mirror the canonical FSM's TERMINAL set (backend/app/services/fsm.py:44).
// Treating RESOLVED/ESCALATED as terminal is wrong: the FSM still routes
// RESOLVED|ESCALATED -> RCA_PENDING -> RCA_PUBLISHED -> AUDITED, so an earlier
// version of this list stopped the stream three states before the RCA/audit
// evidence the operator actually needs to watch appear. tests/
// test_frontend_m19c.py reads the Python constant and fails on any drift.
const TERMINAL_INCIDENT_STATES = new Set(["BLOCKED", "AUDITED"]);

export function isTerminalIncidentState(state: string | null | undefined): boolean {
  return state !== null && state !== undefined && TERMINAL_INCIDENT_STATES.has(state);
}

function eventTypeOf(event: IncidentEvent): IncidentEventType | null {
  const value = event.event_type ?? event.type;
  if (typeof value !== "string") return null;
  if (INCIDENT_EVENT_TYPES.some((candidate) => candidate === value)) {
    return value as IncidentEventType;
  }
  if (INCIDENT_EVENT_PREFIXES.some((prefix) => value.startsWith(prefix))) {
    return value as IncidentEventType;
  }
  return null;
}

export function useIncidentEvents({
  incidentId,
  enabled = true,
  onRefresh,
  debounceMs = 150,
}: UseIncidentEventsOptions): IncidentEventsState {
  const refreshRef = useRef(onRefresh);
  const cursorRef = useRef<string | null>(null);
  const activeIncidentRef = useRef<string | undefined>(undefined);
  const refreshTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const [connectionState, setConnectionState] =
    useState<IncidentEventConnectionState>("idle");
  const [lastEventId, setLastEventId] = useState<string | null>(null);
  const [lastEvent, setLastEvent] = useState<IncidentEvent | null>(null);
  const [lastEventType, setLastEventType] =
    useState<IncidentEventType | null>(null);
  const [lastByType, setLastByType] = useState<
    Partial<Record<string, IncidentEvent>>
  >({});
  const [error, setError] = useState("");

  refreshRef.current = onRefresh;

  useEffect(() => {
    if (activeIncidentRef.current !== incidentId) {
      activeIncidentRef.current = incidentId;
      cursorRef.current = null;
      setLastEventId(null);
      setLastEvent(null);
      setLastEventType(null);
      setLastByType({});
      setError("");
    }
    if (incidentId === undefined || incidentId === "" || !enabled) {
      setConnectionState("idle");
      return;
    }

    const streamUrl = `${apiBase()}/stream/incidents/${encodeURIComponent(incidentId)}`;
    const pollUrl = auditApi.pollUrl(incidentId);
    const unsubscribe = subscribeStream(streamUrl, pollUrl, cursorRef.current, {
      onItem: (item) => {
        const event = item as IncidentEvent;
        const eventId = streamEventId(event);
        if (eventId !== null) {
          cursorRef.current = eventId;
          setLastEventId(eventId);
        }
        const eventType = eventTypeOf(event);
        if (eventType === null) return;
        setLastEvent(event);
        setLastEventType(eventType);
        setLastByType((current) => ({ ...current, [eventType]: event }));
        if (refreshTimerRef.current !== null) {
          clearTimeout(refreshTimerRef.current);
        }
        refreshTimerRef.current = setTimeout(() => {
          refreshTimerRef.current = null;
          refreshRef.current();
        }, Math.max(0, debounceMs));
      },
      onMode: () => undefined,
      onState: (state) => {
        setConnectionState(state);
        if (state === "stream" || state === "polling") setError("");
      },
      onError: (streamError) => setError(streamError.message),
      onCursorReset: () => {
        cursorRef.current = null;
        setLastEventId(null);
      },
    });

    return () => {
      unsubscribe();
      if (refreshTimerRef.current !== null) {
        clearTimeout(refreshTimerRef.current);
        refreshTimerRef.current = null;
      }
    };
  }, [debounceMs, enabled, incidentId]);

  return {
    connectionState,
    lastEventId,
    lastEvent,
    lastEventType,
    lastByType,
    error,
  };
}
