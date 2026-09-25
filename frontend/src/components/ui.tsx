import { useId } from "react";
import type {
  ButtonHTMLAttributes,
  InputHTMLAttributes,
  ReactNode,
  SelectHTMLAttributes,
  TextareaHTMLAttributes,
} from "react";

/* ==========================================================================
   UI primitives (M19 design system)

   The views were each hand-rolling the same seven things: a bordered panel, a
   button, a labelled field, a table, and the loading/empty/error triple. That
   duplication is why the app could not be themed consistently and why an
   a11y fix had to be applied in five places at once.

   These are the canonical versions. Each one carries the accessibility
   structure that is easy to forget and tedious to repeat:

     Button    -> defaults to type="button"; a <button> inside a form must not
                  submit by accident, and the default type is "submit".
     Field     -> owns the label/control/description wiring via useId, so
                  aria-describedby and htmlFor cannot drift from the markup.
     DataTable -> <caption>, column-header scope, and a real <th> per column.

   Colour comes only from the token layer in index.css -- no raw palette values
   in this file, so re-theming is one edit and contrast is auditable in one place.
   ========================================================================== */

/** Merge conditional class names without pulling in a dependency. */
function cx(...parts: Array<string | false | null | undefined>): string {
  return parts.filter(Boolean).join(" ");
}

/* -------------------------------------------------------------------------- */
/* Button                                                                     */
/* -------------------------------------------------------------------------- */

export type ButtonTone = "primary" | "secondary" | "danger" | "ghost";
export type ButtonSize = "sm" | "md";

const BUTTON_TONE: Record<ButtonTone, string> = {
  primary: "bg-accent text-accent-fg hover:bg-accent-strong border border-accent",
  secondary: "bg-surface-raised text-fg hover:bg-line border border-line",
  danger: "bg-danger text-danger-fg hover:brightness-110 border border-danger",
  ghost: "bg-transparent text-fg-muted hover:text-fg hover:bg-surface-raised border border-transparent",
};

const BUTTON_SIZE: Record<ButtonSize, string> = {
  sm: "min-h-8 px-2.5 py-1 text-xs",
  md: "min-h-10 px-3.5 py-2 text-sm",
};

export function Button({
  tone = "secondary",
  size = "md",
  className,
  type,
  children,
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & {
  tone?: ButtonTone;
  size?: ButtonSize;
}) {
  return (
    <button
      {...rest}
      // An unspecified type inside a <form> submits it. Every button in this
      // app is either an explicit submit or, far more often, a plain action, so
      // the default has to be stated rather than inherited from HTML.
      type={type ?? "button"}
      className={cx(
        "inline-flex items-center justify-center gap-1.5 rounded font-medium",
        "transition-colors disabled:cursor-not-allowed disabled:opacity-50",
        BUTTON_TONE[tone],
        BUTTON_SIZE[size],
        className,
      )}
    >
      {children}
    </button>
  );
}

/* -------------------------------------------------------------------------- */
/* StatusPill                                                                 */
/* -------------------------------------------------------------------------- */

export type StatusTone = "ok" | "warn" | "danger" | "info" | "neutral";

const TONE_CLASS: Record<StatusTone, string> = {
  ok: "bg-ok text-ok-fg border-ok",
  warn: "bg-warn text-warn-fg border-warn",
  danger: "bg-danger text-danger-fg border-danger",
  info: "bg-info text-info-fg border-info",
  neutral: "bg-neutral text-neutral-fg border-neutral",
};

export function StatusPill({
  tone,
  children,
  className,
  title,
}: {
  tone: StatusTone;
  children: ReactNode;
  className?: string;
  title?: string;
}) {
  return (
    <span
      title={title}
      className={cx(
        "inline-flex items-center gap-1 rounded border px-2 py-0.5",
        "text-xs font-bold uppercase tracking-wide",
        TONE_CLASS[tone],
        className,
      )}
    >
      {children}
    </span>
  );
}

/* -------------------------------------------------------------------------- */
/* Panel                                                                      */
/* -------------------------------------------------------------------------- */

export function Panel({
  title,
  description,
  actions,
  children,
  className,
  bodyClassName,
  headingLevel = 2,
}: {
  title?: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
  bodyClassName?: string;
  /** Keep heading order correct when a panel is nested inside another panel. */
  headingLevel?: 2 | 3 | 4;
}) {
  const Heading = `h${headingLevel}` as "h2" | "h3" | "h4";
  const hasHeader = Boolean(title || actions);
  // A <section> without an accessible name is not exposed as a region at all,
  // so every Panel labels itself from its own heading. The views used to do
  // this by hand with aria-labelledby + a hand-written id per section, which
  // is exactly the wiring that rots when a heading is reworded.
  const headingId = useId();
  return (
    <section
      aria-labelledby={title ? headingId : undefined}
      className={cx(
        "rounded-lg border border-line bg-surface",
        className,
      )}
    >
      {hasHeader ? (
        <header className="flex flex-wrap items-start justify-between gap-2 border-b border-line px-4 py-3">
          <div className="min-w-0">
            {title ? (
              <Heading id={headingId} className="text-sm font-bold tracking-wide text-fg">
                {title}
              </Heading>
            ) : null}
            {description ? (
              <p className="mt-1 text-xs text-fg-subtle">{description}</p>
            ) : null}
          </div>
          {actions ? <div className="flex shrink-0 flex-wrap gap-2">{actions}</div> : null}
        </header>
      ) : null}
      <div className={cx("px-4 py-3", bodyClassName)}>{children}</div>
    </section>
  );
}

/* -------------------------------------------------------------------------- */
/* Field                                                                      */
/* -------------------------------------------------------------------------- */

type FieldShellProps = {
  label: ReactNode;
  hint?: ReactNode;
  error?: string | null;
  required?: boolean;
  className?: string;
  /**
   * Stable id override. The generated useId is correct for label/control wiring
   * but unstable across renders, which makes a field impossible to target from
   * an automated check. Passing an explicit id wires htmlFor to the same value,
   * so the a11y relationship survives the override.
   */
  id?: string;
  children: (ids: { id: string; describedBy: string | undefined }) => ReactNode;
};

/**
 * Owns the label/control/description relationship.
 *
 * The views previously hand-wrote `id`/`htmlFor`/`aria-describedby` on every
 * input, which is exactly the kind of wiring that rots: add a hint and forget
 * the aria attribute and the hint becomes invisible to a screen reader while
 * still being visible on screen. Here the control cannot exist without its id.
 */
function FieldShell({
  label,
  hint,
  error,
  required,
  className,
  id: idOverride,
  children,
}: FieldShellProps) {
  const generated = useId();
  const id = idOverride ?? generated;
  const hintId = hint ? `${id}-hint` : undefined;
  const errorId = error ? `${id}-error` : undefined;
  const describedBy = [hintId, errorId].filter(Boolean).join(" ") || undefined;

  return (
    <div className={cx("flex flex-col gap-1", className)}>
      <label htmlFor={id} className="text-xs font-semibold text-fg-muted">
        {label}
        {required ? <span className="ml-0.5 text-danger">*</span> : null}
      </label>
      {children({ id, describedBy })}
      {hint ? (
        <p id={hintId} className="text-xs text-fg-subtle">
          {hint}
        </p>
      ) : null}
      {error ? (
        <p id={errorId} role="alert" className="text-xs font-semibold text-danger">
          {error}
        </p>
      ) : null}
    </div>
  );
}

/*
 * `line-control`, not `line`: a control's border is what identifies the
 * control, so it carries the SC 1.4.11 3:1 requirement that decorative
 * separators are exempt from. `line` at 1.3:1 is correct for a row rule and
 * wrong here.
 */
const CONTROL =
  "w-full rounded border border-line-control bg-surface-sunken px-2.5 py-1.5 text-sm text-fg " +
  "placeholder:text-fg-subtle disabled:opacity-60";

export function TextField({
  label,
  hint,
  error,
  id,
  className,
  ...rest
}: {
  label: ReactNode;
  hint?: ReactNode;
  error?: string | null;
  id?: string;
} & Omit<InputHTMLAttributes<HTMLInputElement>, "id">) {
  return (
    <FieldShell label={label} hint={hint} error={error} id={id}>
      {({ id: controlId, describedBy }) => (
        <input
          // rest is spread FIRST so a caller's className or aria-* can never
          // clobber the wiring this primitive exists to guarantee. Spreading it
          // last is how the control silently lost its border and background:
          // the view's className replaced CONTROL outright.
          {...rest}
          id={controlId}
          aria-describedby={describedBy}
          aria-invalid={error ? true : undefined}
          className={cx(CONTROL, error && "border-danger", className)}
        />
      )}
    </FieldShell>
  );
}

export function TextAreaField({
  label,
  hint,
  error,
  id,
  className,
  ...rest
}: {
  label: ReactNode;
  hint?: ReactNode;
  error?: string | null;
  id?: string;
} & Omit<TextareaHTMLAttributes<HTMLTextAreaElement>, "id">) {
  return (
    <FieldShell label={label} hint={hint} error={error} id={id}>
      {({ id: controlId, describedBy }) => (
        <textarea
          {...rest}
          id={controlId}
          aria-describedby={describedBy}
          aria-invalid={error ? true : undefined}
          className={cx(CONTROL, "min-h-24 resize-y break-all font-mono", error && "border-danger", className)}
        />
      )}
    </FieldShell>
  );
}

export function SelectField({
  label,
  hint,
  error,
  id,
  className,
  children,
  ...rest
}: {
  label: ReactNode;
  hint?: ReactNode;
  error?: string | null;
  id?: string;
} & Omit<SelectHTMLAttributes<HTMLSelectElement>, "id">) {
  return (
    <FieldShell label={label} hint={hint} error={error} id={id}>
      {({ id: controlId, describedBy }) => (
        <select
          {...rest}
          id={controlId}
          aria-describedby={describedBy}
          aria-invalid={error ? true : undefined}
          className={cx(CONTROL, error && "border-danger", className)}
        >
          {children}
        </select>
      )}
    </FieldShell>
  );
}

/* -------------------------------------------------------------------------- */
/* DataTable                                                                  */
/* -------------------------------------------------------------------------- */

export type Column<T> = {
  key: string;
  header: ReactNode;
  /** Right-align numeric columns so digits line up for scanning. */
  numeric?: boolean;
  render: (row: T) => ReactNode;
};

export function DataTable<T>({
  caption,
  columns,
  rows,
  rowKey,
  empty,
  testId,
}: {
  caption: ReactNode;
  columns: Array<Column<T>>;
  rows: readonly T[];
  rowKey: (row: T) => string;
  empty: ReactNode;
  testId?: string;
}) {
  return (
    <div className="overflow-x-auto">
      <table data-testid={testId} className="w-full border-collapse text-sm">
        <caption className="sr-only">{caption}</caption>
        <thead>
          <tr className="border-b border-line bg-surface-raised text-left">
            {columns.map((col) => (
              <th
                key={col.key}
                scope="col"
                className={cx(
                  "px-2.5 py-2 text-xs font-bold uppercase tracking-wide text-fg-muted",
                  col.numeric && "text-right",
                )}
              >
                {col.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.length === 0 ? (
            <tr>
              <td colSpan={columns.length} className="px-2.5 py-4 text-fg-subtle">
                {empty}
              </td>
            </tr>
          ) : (
            rows.map((row) => (
              <tr
                key={rowKey(row)}
                className="border-b border-line last:border-b-0 hover:bg-surface-raised"
              >
                {columns.map((col) => (
                  <td
                    key={col.key}
                    className={cx(
                      "px-2.5 py-2 align-top",
                      col.numeric ? "text-right tabular-nums" : "text-fg",
                    )}
                  >
                    {col.render(row)}
                  </td>
                ))}
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/* State displays                                                             */
/* -------------------------------------------------------------------------- */

/**
 * The three states a view can be in that are not content.
 *
 * They existed as ad-hoc markup in four different shapes, and in two cases the
 * error state was not announced at all -- an inline <p> with no role, so a
 * screen reader user learned about a failed request only by hunting for it.
 */
export function LoadingState({ label = "Loading" }: { label?: string }) {
  return (
    <p role="status" aria-live="polite" className="py-4 text-sm text-fg-muted">
      {label}…
    </p>
  );
}

export function EmptyState({
  title,
  hint,
  action,
}: {
  title: ReactNode;
  hint?: ReactNode;
  action?: ReactNode;
}) {
  return (
    <div className="flex flex-col items-start gap-2 rounded border border-dashed border-line px-4 py-6">
      <p className="text-sm font-semibold text-fg-muted">{title}</p>
      {hint ? <p className="text-xs text-fg-subtle">{hint}</p> : null}
      {action}
    </div>
  );
}

export function ErrorState({
  title = "Request failed",
  detail,
  onRetry,
  retryLabel = "Retry",
  testId,
}: {
  title?: ReactNode;
  detail?: ReactNode;
  onRetry?: () => void;
  retryLabel?: string;
  testId?: string;
}) {
  return (
    <div
      role="alert"
      data-testid={testId}
      className="flex flex-wrap items-start justify-between gap-3 rounded border border-danger bg-surface px-4 py-3"
    >
      <div className="min-w-0">
        <p className="text-sm font-bold text-danger">{title}</p>
        {detail ? <p className="mt-1 text-xs text-fg-muted">{detail}</p> : null}
      </div>
      {onRetry ? (
        <Button tone="secondary" size="sm" onClick={onRetry}>
          {retryLabel}
        </Button>
      ) : null}
    </div>
  );
}

/**
 * An inline, non-blocking message: a caveat, a degraded-mode notice, a
 * condition the operator must know about before acting.
 *
 * Distinct from ErrorState (something failed, here is a retry) and from
 * EmptyState (there is nothing here). The Safety Gate alone had eight of these
 * hand-written as bare <p> elements, four of which were not announced at all --
 * a screen reader user would have no idea a separation-of-duties warning was on
 * screen. `live` opts into assertive announcement for the ones that change what
 * an operator may safely do.
 */
export function Notice({
  tone = "info",
  title,
  children,
  testId,
  live = false,
  polite = false,
  className,
}: {
  tone?: StatusTone;
  title?: ReactNode;
  children?: ReactNode;
  testId?: string;
  /** Assertive: something an operator must notice before acting. */
  live?: boolean;
  /** Polite status region: informational, announced without interrupting. */
  polite?: boolean;
  className?: string;
}) {
  const edge: Record<StatusTone, string> = {
    ok: "border-ok",
    warn: "border-warn",
    danger: "border-danger",
    info: "border-info",
    neutral: "border-line-strong",
  };
  const heading: Record<StatusTone, string> = {
    ok: "text-ok",
    warn: "text-warn",
    danger: "text-danger",
    info: "text-info",
    neutral: "text-fg-muted",
  };
  return (
    <div
      data-testid={testId}
      role={live ? "alert" : polite ? "status" : undefined}
      aria-live={live ? "assertive" : polite ? "polite" : undefined}
      className={cx(
        "rounded border bg-surface px-3 py-2 text-xs leading-relaxed",
        edge[tone],
        className,
      )}
    >
      {title ? <p className={cx("font-bold", heading[tone])}>{title}</p> : null}
      {children ? (
        <div className={cx(Boolean(title) && "mt-1", "text-fg-muted")}>{children}</div>
      ) : null}
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/* Small layout helpers                                                       */
/* -------------------------------------------------------------------------- */

export function KeyValue({ items }: { items: Array<[ReactNode, ReactNode]> }) {
  return (
    <dl className="grid grid-cols-[minmax(6rem,auto)_1fr] gap-x-3 gap-y-1.5 text-sm">
      {items.map(([term, value], i) => (
        <div key={i} className="contents">
          <dt className="text-xs uppercase tracking-wide text-fg-subtle">{term}</dt>
          <dd className="min-w-0 break-words text-fg">{value}</dd>
        </div>
      ))}
    </dl>
  );
}

export function Well({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <pre
      className={cx(
        "overflow-x-auto rounded border border-line bg-surface-sunken p-3",
        "font-mono text-xs leading-relaxed text-fg-muted",
        className,
      )}
    >
      {children}
    </pre>
  );
}
