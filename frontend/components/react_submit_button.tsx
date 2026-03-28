/**
 * @title React Submit Button States
 * @notice Typed submit button state model with secure label handling and reliability guards.
 * @dev The component intentionally prefers safe defaults to reduce accidental double submits.
 */
import React, { useMemo, useState } from "react";

export type SubmitButtonState = "idle" | "submitting" | "success" | "error" | "disabled";

/**
 * @title Submit Button Labels
 * @notice Optional override labels for each supported state.
 */
export interface SubmitButtonLabels {
  idle?: string;
  submitting?: string;
  success?: string;
  error?: string;
  disabled?: string;
}

/**
 * @title React Submit Button Props
 * @notice Contract for state, label overrides, and interaction behavior.
 */
export interface ReactSubmitButtonProps {
  state: SubmitButtonState;
  previousState?: SubmitButtonState;
  strictTransitions?: boolean;
  labels?: SubmitButtonLabels;
  onClick?: (event: React.MouseEvent<HTMLButtonElement>) => void | Promise<void>;
  className?: string;
  id?: string;
  type?: "button" | "submit";
  disabled?: boolean;
}

const DEFAULT_LABELS: Required<SubmitButtonLabels> = {
  idle: "Submit",
  submitting: "Submitting...",
  success: "Submitted",
  error: "Try Again",
  disabled: "Submit Disabled",
};

const MAX_LABEL_LENGTH = 80;
const CONTROL_CHARACTER_REGEX = /[\u0000-\u001F\u007F]/g;

const ALLOWED_STATE_TRANSITIONS: Record<SubmitButtonState, SubmitButtonState[]> = {
  idle: ["submitting", "disabled"],
  submitting: ["success", "error", "disabled"],
  success: ["idle", "disabled"],
  error: ["idle", "submitting", "disabled"],
  disabled: ["idle"],
};

/**
 * @title Label Normalizer
 * @notice Enforces string-only, bounded, and readable labels.
 */
export function normalizeSubmitButtonLabel(candidate: unknown, fallback: string): string {
  if (typeof candidate !== "string") {
    return fallback;
  }
  const withoutControlCharacters = candidate.replace(CONTROL_CHARACTER_REGEX, " ");
  const normalized = withoutControlCharacters.replace(/\s+/g, " ").trim();
  if (!normalized) {
    return fallback;
  }
  if (normalized.length <= MAX_LABEL_LENGTH) {
    return normalized;
  }
  return `${normalized.slice(0, MAX_LABEL_LENGTH - 3)}...`;
}

/**
 * @title Label Resolver
 * @notice Returns a safe, non-empty label for the current state.
 */
export function resolveSubmitButtonLabel(
  state: SubmitButtonState,
  labels?: SubmitButtonLabels,
): string {
  return normalizeSubmitButtonLabel(labels?.[state], DEFAULT_LABELS[state]);
}

/**
 * @title State Transition Validator
 */
export function isValidSubmitButtonStateTransition(
  previousState: SubmitButtonState,
  nextState: SubmitButtonState,
): boolean {
  if (previousState === nextState) {
    return true;
  }
  return ALLOWED_STATE_TRANSITIONS[previousState].includes(nextState);
}

/**
 * @title Safe State Resolver
 */
export function resolveSafeSubmitButtonState(
  state: SubmitButtonState,
  previousState?: SubmitButtonState,
  strictTransitions = true,
): SubmitButtonState {
  if (!strictTransitions || !previousState) {
    return state;
  }
  return isValidSubmitButtonStateTransition(previousState, state) ? state : previousState;
}

/**
 * @title Interaction Block Guard
 */
export function isSubmitButtonInteractionBlocked(
  state: SubmitButtonState,
  disabled = false,
  isLocallySubmitting = false,
): boolean {
  return Boolean(disabled) || state === "disabled" || state === "submitting" || isLocallySubmitting;
}

/**
 * @title Busy State Guard
 */
export function isSubmitButtonBusy(
  state: SubmitButtonState,
  isLocallySubmitting = false,
): boolean {
  return state === "submitting" || isLocallySubmitting;
}

/**
 * @title Disabled Guard
 */
export function isSubmitButtonDisabled(state: SubmitButtonState, disabled?: boolean): boolean {
  return Boolean(disabled) || state === "disabled" || state === "submitting";
}

const BASE_STYLE: React.CSSProperties = {
  minHeight: "44px",
  minWidth: "120px",
  borderRadius: "8px",
  border: "1px solid #4f46e5",
  padding: "0.5rem 1rem",
  color: "#ffffff",
  fontWeight: 600,
  cursor: "pointer",
  transition: "opacity 0.2s ease",
  backgroundColor: "#4f46e5",
};

const STATE_STYLE_MAP: Record<SubmitButtonState, React.CSSProperties> = {
  idle: { backgroundColor: "#4f46e5" },
  submitting: { backgroundColor: "#6366f1" },
  success: { backgroundColor: "#16a34a", borderColor: "#15803d" },
  error: { backgroundColor: "#dc2626", borderColor: "#b91c1c" },
  disabled: { backgroundColor: "#9ca3af", borderColor: "#9ca3af", cursor: "not-allowed", opacity: 0.9 },
};

/**
 * @title React Submit Button
 * @notice Reusable submit button with secure labels and transition-aware state handling.
 */
const ReactSubmitButton = ({
  state,
  previousState,
  strictTransitions = true,
  labels,
  onClick,
  className,
  id,
  type = "button",
  disabled,
}: ReactSubmitButtonProps) => {
  const [isLocallySubmitting, setIsLocallySubmitting] = useState(false);

  const resolvedState = useMemo(
    () => resolveSafeSubmitButtonState(state, previousState, strictTransitions),
    [state, previousState, strictTransitions],
  );

  const label = resolveSubmitButtonLabel(resolvedState, labels);
  const computedDisabled = isSubmitButtonInteractionBlocked(resolvedState, disabled, isLocallySubmitting);
  const ariaBusy = isSubmitButtonBusy(resolvedState, isLocallySubmitting);

  const handleClick = async (event: React.MouseEvent<HTMLButtonElement>) => {
    if (computedDisabled || !onClick) {
      return;
    }
    setIsLocallySubmitting(true);
    try {
      await Promise.resolve(onClick(event));
    } finally {
      setIsLocallySubmitting(false);
    }
  };

  return (
    <button
      id={id}
      type={type}
      className={className}
      disabled={computedDisabled}
      aria-busy={ariaBusy}
      aria-live="polite"
      aria-label={label}
      onClick={computedDisabled ? undefined : handleClick}
      style={{
        ...BASE_STYLE,
        ...STATE_STYLE_MAP[resolvedState],
      }}
    >
      {label}
    </button>
  );
};

export default ReactSubmitButton;
