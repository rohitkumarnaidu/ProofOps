export interface StreamItem {
  audit_event_id?: string;
  event_id?: string;
  [key: string]: unknown;
}

export type StreamConnectionState =
  | "connecting"
  | "stream"
  /** Replay finished normally: the backlog was delivered and the server closed. */
  | "replay"
  | "polling"
  | "offline";

/** Named sentinel the server emits after the last replayed frame. Must match
    `REPLAY_COMPLETE_EVENT` in backend/app/routers/stream.py; kept as a literal
    because the frontend must not import backend modules. */
const REPLAY_COMPLETE_EVENT = "replay-complete";

export interface StreamHandlers {
  onItem: (item: StreamItem) => void;
  onMode: (mode: "LIVE" | "OFFLINE") => void;
  onState?: (state: StreamConnectionState) => void;
  onError?: (error: Error) => void;
  onCursorReset?: () => void;
}

const POLL_FALLBACK_MS = 3000;
const MAX_BACKOFF_MS = 30000;

function statusOf(error: unknown): number | null {
  if (typeof error !== "object" || error === null || !("status" in error)) {
    return null;
  }
  const status = (error as { status?: unknown }).status;
  return typeof status === "number" ? status : null;
}

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export function streamEventId(item: StreamItem): string | null {
  if (typeof item.audit_event_id === "string" && item.audit_event_id !== "") {
    return item.audit_event_id;
  }
  if (typeof item.event_id === "string" && item.event_id !== "") return item.event_id;
  return null;
}

export function subscribeStream(
  url: string,
  pollUrl: string,
  sinceId: string | null,
  handlers: StreamHandlers,
  deps?: {
    eventSource?: typeof EventSource | undefined;
    fetchJson?: (url: string) => Promise<{ events?: StreamItem[]; items?: StreamItem[] }>;
    setTimeoutFn?: typeof setTimeout;
    clearTimeoutFn?: typeof clearTimeout;
  },
): () => void {
  const ES =
    deps?.eventSource ??
    (typeof globalThis.EventSource === "undefined" ? undefined : globalThis.EventSource);
  const setT = deps?.setTimeoutFn ?? setTimeout;
  const clearT = deps?.clearTimeoutFn ?? clearTimeout;
  let stopped = false;
  let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  let pollTimer: ReturnType<typeof setTimeout> | null = null;
  let backoff = 1000;
  let source: EventSource | null = null;
  let cursor = sinceId;
  let replayedCursor: string | null = null;
  let polling = false;
  // Set when the server's `replay-complete` sentinel arrives, so the
  // EventSource close that follows is recognised as normal termination.
  let replayCompleted = false;

  const clearReconnect = () => {
    if (reconnectTimer !== null) clearT(reconnectTimer);
    reconnectTimer = null;
  };

  const clearPoll = () => {
    if (pollTimer !== null) clearT(pollTimer);
    pollTimer = null;
  };

  const resetCursorOnce = (failed: string | null): boolean => {
    if (failed === null || replayedCursor === failed) return false;
    replayedCursor = failed;
    cursor = null;
    handlers.onCursorReset?.();
    return true;
  };

  const stopPolling = () => {
    polling = false;
    clearPoll();
  };

  const schedulePoll = (delay = POLL_FALLBACK_MS) => {
    if (stopped || !polling || pollTimer !== null) return;
    pollTimer = setT(() => {
      pollTimer = null;
      void pollOnce();
    }, delay);
  };

  const startPolling = () => {
    if (stopped || polling) return;
    polling = true;
    schedulePoll();
  };

  const defaultFetch = async (target: string) => {
    const response = await fetch(target, { cache: "no-store" });
    if (!response.ok) {
      const error = new Error(`polling failed (${response.status})`) as Error & {
        status: number;
      };
      error.status = response.status;
      throw error;
    }
    return (await response.json()) as { events?: StreamItem[]; items?: StreamItem[] };
  };

  async function pollOnce(): Promise<void> {
    if (stopped || !polling) return;
    let replayImmediately = false;
    try {
      const fetchJson = deps?.fetchJson ?? defaultFetch;
      const data = await fetchJson(pollUrl);
      if (stopped || !polling) return;
      const pollCursor = cursor;
      let reachedCursor = pollCursor === null;
      // The poll fallback is the audit chain endpoint, which returns `events`.
      // `items` is accepted only as a tolerated alias so a custom fetchJson
      // injected by a caller or test cannot silently break the cursor.
      const raw = Array.isArray(data.events) ? data.events : data.items;
      const items = Array.isArray(raw) ? raw : [];
      for (const item of items) {
        const eventId = streamEventId(item) ?? "";
        if (!reachedCursor) {
          if (eventId === pollCursor) reachedCursor = true;
          continue;
        }
        if (eventId !== "") cursor = eventId;
        handlers.onItem(item);
      }
      if (pollCursor !== null && !reachedCursor) {
        replayImmediately = resetCursorOnce(pollCursor);
        if (!replayImmediately) {
          throw new Error("polling cursor is no longer present in the audit");
        }
      } else {
        handlers.onState?.("polling");
        handlers.onMode("LIVE");
        backoff = 1000;
      }
    } catch (error) {
      const status = statusOf(error);
      if (resetCursorOnce(cursor)) {
        replayImmediately = true;
      } else {
        if (status === 400 || status === 404 || status === 410) {
          handlers.onError?.(
            new Error(`stream replay failed (${status ?? "unknown"})`),
          );
        } else {
          handlers.onError?.(
            new Error(`polling fallback failed: ${messageOf(error)}`),
          );
        }
        handlers.onState?.("offline");
        handlers.onMode("OFFLINE");
      }
    } finally {
      if (polling && !stopped) schedulePoll(replayImmediately ? 0 : POLL_FALLBACK_MS);
    }
  }

  if (ES === undefined) {
    handlers.onState?.("connecting");
    handlers.onMode("OFFLINE");
    startPolling();
  } else {
    const ESCtor: typeof EventSource = ES;

    const scheduleReconnect = (delay: number) => {
      if (stopped || reconnectTimer !== null) return;
      reconnectTimer = setT(() => {
        reconnectTimer = null;
        connect();
      }, delay);
    };

    function connect(): void {
      if (stopped) return;
      clearReconnect();
      const target =
        cursor === null ? url : `${url}?since=${encodeURIComponent(cursor)}`;
      let opened = false;
      handlers.onState?.("connecting");
      try {
        source = new ESCtor(target);
      } catch (error) {
        handlers.onState?.("offline");
        handlers.onMode("OFFLINE");
        handlers.onError?.(
          new Error(`event stream unavailable: ${messageOf(error)}`),
        );
        startPolling();
        backoff = Math.min(backoff * 2, MAX_BACKOFF_MS);
        scheduleReconnect(backoff);
        return;
      }
      source.onopen = () => {
        opened = true;
        replayCompleted = false;
        stopPolling();
        backoff = 1000;
        handlers.onState?.("stream");
        handlers.onMode("LIVE");
      };
      // The stream is replay-only: the server sends the backlog, emits a named
      // `replay-complete` sentinel, then closes. EventSource surfaces that
      // close through onerror, which is indistinguishable from a real drop, so
      // the sentinel is what lets us report the normal case as normal.
      source.addEventListener(REPLAY_COMPLETE_EVENT, () => {
        replayCompleted = true;
        handlers.onState?.("replay");
      });
      source.onmessage = (message: MessageEvent) => {
        try {
          const item = JSON.parse(message.data as string) as StreamItem;
          const eventId = streamEventId(item);
          if (eventId !== null) cursor = eventId;
          handlers.onItem(item);
        } catch (error) {
          handlers.onError?.(
            new Error(`malformed event frame: ${messageOf(error)}`),
          );
        }
      };
      source.onerror = () => {
        source?.close();
        source = null;
        if (!opened && resetCursorOnce(cursor)) {
          handlers.onState?.("connecting");
          scheduleReconnect(0);
          return;
        }
        if (replayCompleted) {
          // Normal termination, not a failure. Do NOT raise an error and do NOT
          // report OFFLINE: the backend answered and delivered the whole
          // backlog. Polling plus a backed-off reconnect still run, because new
          // audit events may appear after the replay window.
          handlers.onState?.("replay");
          startPolling();
          backoff = Math.min(backoff * 2, MAX_BACKOFF_MS);
          scheduleReconnect(backoff);
          return;
        }
        handlers.onState?.("offline");
        handlers.onMode("OFFLINE");
        handlers.onError?.(new Error("incident event stream disconnected"));
        startPolling();
        backoff = Math.min(backoff * 2, MAX_BACKOFF_MS);
        scheduleReconnect(backoff);
      };
    }

    connect();
  }

  const unsubscribe = () => {
    stopped = true;
    source?.close();
    stopPolling();
    clearReconnect();
  };
  return unsubscribe;
}
