import { useCallback, useEffect, useRef, useState } from "react";
import { ApiError } from "../api";

/**
 * One loader's state, with the two failure modes every view had.
 *
 * `error` is the message and `status` the HTTP code, so a view can distinguish
 * "not found" from "permission denied" from "backend unreachable" instead of
 * collapsing all three into one string.
 */
export interface AsyncState<T> {
  data: T | null;
  error: string;
  status: number | null;
  loading: boolean;
}

export interface AsyncResource<T> extends AsyncState<T> {
  /** Re-run the loader. `showLoading` false keeps the current data on screen. */
  reload: (showLoading?: boolean) => Promise<void>;
  /** Replace the data locally, e.g. after a mutation returned fresh state. */
  set: (value: T | null) => void;
}

export interface AsyncOptions {
  /** Skip fetching entirely (e.g. no incident selected yet). */
  enabled?: boolean;
}

/**
 * Run an async loader with cancellation and out-of-order protection.
 *
 * Every view here had the same two defects and no shared place to fix them:
 *
 *  1. **No unmount guard.** A slow response landing after the operator
 *     navigated away called `setState` on an unmounted component. React 18
 *     tolerates the warning, but the state write is still a bug, and in dev it
 *     forces a re-render pass over a tree that no longer exists.
 *
 *  2. **No request sequencing.** Two loads could be in flight at once -- a
 *     manual refresh while an event-stream refresh was already pending. If the
 *     slower one resolved last, it overwrote fresher data with stale data, and
 *     the operator saw an incident revert to an earlier state with no way to
 *     tell why. A monotonic sequence token discards any response that is not
 *     the newest request.
 *
 * The sequence token is used rather than AbortController alone because a
 * cancelled request is not guaranteed to have stopped: a response already in
 * flight can still resolve, and the ordering guarantee must not depend on the
 * abort landing first.
 */
export function useAsyncData<T>(
  loader: () => Promise<T>,
  deps: ReadonlyArray<unknown>,
  options: AsyncOptions = {},
): AsyncResource<T> {
  const enabled = options.enabled ?? true;
  const [state, setState] = useState<AsyncState<T>>({
    data: null,
    error: "",
    status: null,
    loading: enabled,
  });

  const mounted = useRef(true);
  // Monotonic per-loader request id. Only the newest may write.
  const sequence = useRef(0);
  const loaderRef = useRef(loader);
  loaderRef.current = loader;
  // Identity of the current dependency set, so a change (a different incident
  // in the route) clears the previous subject's data instead of leaving it on
  // screen while the new one loads. Without this, navigating from incident A
  // to incident B briefly shows A's audit chain and postmortem against B's
  // heading -- which reads as one incident contradicting itself.
  const signature = JSON.stringify([enabled, ...deps.map((d) => d ?? null)]);
  const lastSignature = useRef<string | null>(null);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  const reload = useCallback(async (showLoading: boolean = true) => {
    if (!enabled) return;
    sequence.current += 1;
    const ticket = sequence.current;
    if (showLoading) {
      setState((current) => ({ ...current, loading: true }));
    }
    try {
      const value = await loaderRef.current();
      // Drop a response that is not the newest, and drop it entirely once the
      // component is gone.
      if (!mounted.current || ticket !== sequence.current) return;
      setState({ data: value, error: "", status: null, loading: false });
    } catch (caught) {
      if (!mounted.current || ticket !== sequence.current) return;
      setState({
        data: null,
        error: caught instanceof ApiError ? caught.message : String(caught),
        status: caught instanceof ApiError ? caught.status : 0,
        loading: false,
      });
    }
  }, [enabled]);

  useEffect(() => {
    if (!enabled) {
      setState({ data: null, error: "", status: null, loading: false });
      lastSignature.current = signature;
      return;
    }
    const changedSubject = lastSignature.current !== signature;
    lastSignature.current = signature;
    // Invalidate anything in flight for the previous subject before clearing,
    // so its response cannot land after the reset and repopulate stale data.
    sequence.current += 1;
    if (changedSubject) {
      setState({ data: null, error: "", status: null, loading: true });
    }
    void reload(true);
    // `reload` is stable for a given `enabled`; the caller's deps drive the
    // re-fetch, which is the intent (re-run when the incident changes).
  }, [enabled, reload, signature]);

  const set = useCallback((value: T | null) => {
    if (!mounted.current) return;
    // Invalidate any in-flight response so it cannot overwrite local state.
    sequence.current += 1;
    setState({ data: value, error: "", status: null, loading: false });
  }, []);

  return { ...state, reload, set };
}
