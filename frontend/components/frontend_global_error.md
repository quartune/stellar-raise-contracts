# frontend_global_error — Global Error Boundary Component

Technical reference for the React global error boundary component built for the Stellar Raise frontend application.

---

## Overview

`FrontendGlobalErrorBoundary` catches synchronous render-phase errors anywhere in the wrapped component tree, classifies them (generic vs. smart-contract), logs a structured report, and renders an appropriate fallback UI with a capped "Try Again" recovery path.

```
Error thrown → getDerivedStateFromError → componentDidCatch → fallback UI → recovery
```

---

## Gas-Efficiency Improvements (v2)

This version introduces several changes that reduce redundant computation and prevent resource-wasting retry loops:

| Improvement | Detail |
| :--- | :--- |
| **Classification cache** | `isSmartContractError` results are stored in a `WeakMap` keyed on the Error instance. Repeated renders with the same error object skip the string-scan entirely. |
| **`onError` called once** | The reporting callback is invoked in `componentDidCatch` (once per caught error), not in `render` (which may run many times). Prevents duplicate events to paid observability services. |
| **Retry cap (`MAX_RETRIES`)** | Retries are capped at `MAX_RETRIES = 3`. After exhaustion the "Try Again" button is hidden and a status message is shown, preventing infinite re-render loops on unrecoverable errors. |
| **Non-Error normalisation** | Thrown strings, numbers, and `null` are normalised to `Error` in `getDerivedStateFromError` so downstream code never needs to guard against non-Error values. |

---

## Component API

### `FrontendGlobalErrorBoundary`

```tsx
interface FrontendGlobalErrorBoundaryProps {
  children?: ReactNode;
  fallback?: ReactNode;
  onError?: (report: ErrorReport) => void;
}
```

| Prop | Description |
| :--- | :--- |
| `children` | Component tree to protect. |
| `fallback` | Optional custom fallback UI — replaces the built-in fallback entirely. |
| `onError` | Callback invoked once per caught error with a sanitised `ErrorReport`. |

### `ErrorReport`

```tsx
interface ErrorReport {
  message: string;
  stack: string | undefined;          // undefined in production
  componentStack: string | null | undefined; // undefined in production
  timestamp: string;                  // ISO 8601
  isSmartContractError: boolean;
  errorName: string;
}
```

### `MAX_RETRIES`

Exported constant (`number`). Controls how many times the user can click "Try Again" before the button is hidden. Default: `3`.

---

## Custom Error Classes

```tsx
class ContractError extends Error  // smart contract / Soroban invocation failures
class NetworkError  extends Error  // Horizon API / RPC connectivity issues
class TransactionError extends Error  // tx submission, signing, confirmation failures
```

Throwing one of these classes guarantees the boundary shows the "Smart Contract Error" fallback regardless of the message content.

---

## Error Classification

The boundary classifies an error as a smart-contract error when:

1. It is an instance of `ContractError`, `NetworkError`, or `TransactionError`, **or**
2. Its `name` or `message` contains one of: `contract`, `stellar`, `soroban`, `transaction`, `blockchain`, `ledger`, `horizon`, `xdr`, `invoke`, `wallet`.

The result is cached per Error instance (WeakMap) so repeated renders do not re-scan the string.

---

## Fallback UI Variants

### Smart Contract Error

- 🔗 icon
- Title: "Smart Contract Error"
- Guidance: wallet balance / connection check
- Buttons: "Try Again" (hidden after `MAX_RETRIES`), "Go Home"

### Generic Error

- ⚠️ icon
- Title: "Documentation Loading Error"
- Buttons: "Try Again" (hidden after `MAX_RETRIES`), "Go Home"

Both variants show a `role="status"` message once retries are exhausted.

In development (`NODE_ENV !== 'production'`) a collapsible `<details>` block shows the raw error message.

---

## Security Considerations

- Stack traces and component stacks are **omitted in production** to prevent information disclosure.
- Fallback UI uses only static strings — no raw error data is injected into `innerHTML`, preventing XSS from crafted error messages.
- The `onError` callback receives a sanitised report; callers must not log `error.stack` in production.
- `ContractError` / `TransactionError` messages must never contain XDR blobs, signing keys, or raw contract state.

---

## Lifecycle

```
Error thrown in child
  └─ getDerivedStateFromError(error)   ← pure, sync; normalises non-Error values
       └─ componentDidCatch(error, info) ← side-effects: console.error + onError (once)
            └─ render()                  ← shows fallback; retry button visible if retryCount < MAX_RETRIES
```

---

## Limitations

- Does **not** catch errors in async event handlers, `setTimeout`, Promises, or SSR.
- Does **not** catch errors thrown inside the boundary's own `render` method.
- Nested boundaries can be used for more granular isolation.

---

## Usage Examples

### Basic

```tsx
import FrontendGlobalErrorBoundary from '../components/frontend_global_error';

function App() {
  return (
    <FrontendGlobalErrorBoundary>
      <MainApplication />
    </FrontendGlobalErrorBoundary>
  );
}
```

### With error reporting

```tsx
import FrontendGlobalErrorBoundary, { ErrorReport } from '../components/frontend_global_error';

function App() {
  const handleError = (report: ErrorReport) => {
    // report.stack is undefined in production — safe to forward
    Sentry.captureMessage(report.message, { extra: report });
  };
  return (
    <FrontendGlobalErrorBoundary onError={handleError}>
      <MainApplication />
    </FrontendGlobalErrorBoundary>
  );
}
```

### Throwing typed errors in contract code

```tsx
import { ContractError } from '../components/frontend_global_error';

async function contribute(amount: number) {
  try {
    await contract.invoke('contribute', { amount });
  } catch (err) {
    throw new ContractError('Contribution failed — check wallet balance');
  }
}
```

### Next.js `_app.tsx`

```tsx
import FrontendGlobalErrorBoundary from '../components/frontend_global_error';

function MyApp({ Component, pageProps }) {
  return (
    <FrontendGlobalErrorBoundary>
      <Component {...pageProps} />
    </FrontendGlobalErrorBoundary>
  );
}
export default MyApp;
```

---

## Test Coverage

| Category | Tests |
| :--- | :--- |
| Custom error classes | 3 |
| Normal rendering | 2 |
| Generic error fallback | 5 |
| Smart contract fallback | 12 |
| Custom fallback prop | 3 |
| Recovery via Try Again | 3 |
| Retry cap (gas efficiency) | 5 |
| Classification caching | 1 |
| Non-Error thrown values | 3 |
| onError callback | 5 |
| Accessibility | 5 |
| Error classification edge cases | 6 |

Target: ≥ 95 % statement coverage, 100 % function coverage.
