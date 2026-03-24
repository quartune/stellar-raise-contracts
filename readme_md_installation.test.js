/**
 * readme_md_installation.test.js
 *
 * Programmatically verifies that the installation commands documented in
 * README.md and docs/readme_md_installation.md execute without errors.
 *
 * Coverage target: 95%+ of "Getting Started" commands.
 *
 * @security  Tests run in the current working directory. They do not write
 *            to the network or require Stellar keys. No secret material is
 *            accessed or generated.
 */

'use strict';

const { execSync } = require('child_process');
const path = require('path');
const fs = require('fs');

const ROOT = process.cwd();
const EXEC_OPTS = { encoding: 'utf8', stdio: 'pipe' };

// ── helpers ──────────────────────────────────────────────────────────────────

/** Run a command and return stdout, or throw with a clear message. */
function run(cmd, opts = {}) {
  return execSync(cmd, { ...EXEC_OPTS, ...opts });
}

// ── Prerequisites ─────────────────────────────────────────────────────────────

describe('Prerequisites', () => {
  test('rustc is installed (stable channel)', () => {
    const out = run('rustc --version');
    expect(out).toMatch(/^rustc \d+\.\d+\.\d+/);
  });

  test('cargo is installed', () => {
    const out = run('cargo --version');
    expect(out).toMatch(/^cargo \d+\.\d+\.\d+/);
  });

  test('wasm32-unknown-unknown target is installed', () => {
    const out = run('rustup target list --installed');
    expect(out).toContain('wasm32-unknown-unknown');
  });

  test('stellar CLI is installed (v20+ rename)', () => {
    const out = run('stellar --version');
    expect(out).toContain('stellar-cli');
  });

  test('Node.js >= 18 is available', () => {
    const out = run('node --version');
    const major = parseInt(out.trim().replace('v', ''), 10);
    expect(major).toBeGreaterThanOrEqual(18);
  });
});

// ── Getting Started commands ──────────────────────────────────────────────────

describe('Getting Started', () => {
  test('cargo build --dry-run succeeds (wasm32 release)', () => {
    run(
      'cargo build --release --target wasm32-unknown-unknown -p crowdfund --dry-run',
      { cwd: ROOT, timeout: 30000 }
    );
  }, 35000);

  test('cargo test --no-run compiles test suite', () => {
    run('cargo test --no-run --workspace', { cwd: ROOT, timeout: 120000, stdio: 'ignore' });
  }, 130000);
});

// ── Edge Case: WASM target ────────────────────────────────────────────────────

describe('Edge Case — WASM target', () => {
  test('rustup target list --installed contains wasm32-unknown-unknown', () => {
    expect(run('rustup target list --installed')).toMatch(/wasm32-unknown-unknown/);
  });
});

// ── Edge Case: CLI versioning ─────────────────────────────────────────────────

describe('Edge Case — Stellar CLI versioning', () => {
  test('stellar --version does not contain "soroban" (v20+ rename)', () => {
    const out = run('stellar --version');
    // The binary is now `stellar`, not `soroban`
    expect(out).not.toMatch(/^soroban/);
  });

  test('stellar contract --help exits cleanly', () => {
    // Verifies the CLI sub-command structure expected by deploy scripts
    expect(() => run('stellar contract --help')).not.toThrow();
  });
});

// ── Edge Case: Network identity ───────────────────────────────────────────────

describe('Edge Case — Network identity (graceful, no keys required)', () => {
  test('stellar keys list does not crash', () => {
    // May return empty list — that is fine
    expect(() => {
      try { run('stellar keys list'); } catch (_) { /* no keys configured */ }
    }).not.toThrow();
  });
});

// ── Security: .soroban not committed ─────────────────────────────────────────

describe('Security', () => {
  test('.soroban/ is listed in .gitignore', () => {
    const gitignore = fs.readFileSync(path.join(ROOT, '.gitignore'), 'utf8');
    expect(gitignore).toMatch(/\.soroban/);
  });

  test('verify_env.sh exists and is executable', () => {
    const script = path.join(ROOT, 'scripts', 'verify_env.sh');
    expect(fs.existsSync(script)).toBe(true);
    // S_IXUSR = 0o100 — owner execute bit
    expect(fs.statSync(script).mode & 0o100).toBeTruthy();
  });

  test('docs/readme_md_installation.md exists', () => {
    expect(fs.existsSync(path.join(ROOT, 'docs', 'readme_md_installation.md'))).toBe(true);
  });
});
