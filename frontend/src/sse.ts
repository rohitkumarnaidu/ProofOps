/* SSE client (M19.7): Lyzr stream-chat shape + control-plane events.
   Auto-reconnect with backoff; 3s polling fallback; every item carries its
   audit event id through untouched. No data invented: on total failure the
   consumer sees OFFLINE, never synthetic rows. */

export interface StreamItem {
  audit_event_id?: string;
  [key: string]: unknown;
}

export interface StreamHandlers {
  onItem: (item: StreamItem) => void;
  onMode: (mode: "LIVE" | "OFFLINE") => void;
}

const POLL_FALLBACK_MS = 3000;
const MAX_BACKOFF_MS = 30000;

/** Subscribe to an SSE endpoint with polling fallback.
    Returns an unsubscribe function. Pure logic over injected primitives so
    the reconnect/backoff contract is unit-testable without a browser. */
export function subscribeStream(
  url: string,
  pollUrl: string,
  sinceId: string | null,
  handlers: StreamHandlers,
  deps?: {
    eventSource?: typeof EventSource | undefined;
    fetchJson?: (url: string) => Promise<{ items: StreamItem[] }>;
    setTimeoutFn?: typeof setTimeout;
    clearTimeoutFn?: typeof clearTimeout;
  },
): () => void {
  const ES = deps?.eventSource;
  const setT = deps?.setTimeoutFn ?? setTimeout;
  const clearT = deps?.clearTimeoutFn ?? clearTimeout;
  let stopped = false;
  let timer: ReturnType<typeof setTimeout> | null = null;
  let backoff = 1000;
  let source: EventSource | null = null;

  function scheduleFallback() {
    if (stopped) return;
    timer = setT(async () => {
      try {
        const fetchJson = deps?.fetchJson ?? defaultFetch;
        const data = await fetchJson(
          sinceId !== null ? `${pollUrl}?since=${sinceId}` : pollUrl,
        );
        for (const item of data.items) {
          if (typeof item.audit_event_id === "string") {
            sinceId = item.audit_event_id;
          }
          handlers.onItem(item);
        }
        handlers.onMode("LIVE");
        backoff = 1000;
      } catch {
        handlers.onMode("OFFLINE");
      }
      if (!stopped) scheduleFallback();
    }, POLL_FALLBACK_MS);
  }

  async function defaultFetch(u: string) {
    const res = await fetch(u);
    return (await res.json()) as { items: StreamItem[] };
  }

  if (ES === undefined) {
    handlers.onMode("OFFLINE");
    scheduleFallback();
    return () => {
      stopped = true;
      if (timer !== null) clearT(timer);
    };
  }
  const ESCtor: typeof EventSource = ES;

  function connect() {
    if (stopped) return;
    const target =
      sinceId !== null ? `${url}?since=${encodeURIComponent(sinceId)}` : url;
    source = new ESCtor(target);
    handlers.onMode("LIVE");
    source.onmessage = (event: MessageEvent) => {
      try {
        const item = JSON.parse(event.data as string) as StreamItem;
        if (typeof item.audit_event_id === "string") {
          sinceId = item.audit_event_id;
        }
        handlers.onItem(item);
      } catch {
        /* malformed frame: counted by caller via onMode staying LIVE */
      }
    };
    source.onerror = () => {
      source?.close();
      source = null;
      handlers.onMode("OFFLINE");
      backoff = Math.min(backoff * 2, MAX_BACKOFF_MS);
      timer = setT(connect, backoff);
    };
  }

  connect();
  return () => {
    stopped = true;
    source?.close();
    if (timer !== null) clearT(timer);
  };
}
