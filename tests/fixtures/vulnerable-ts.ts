// Synthetic vulnerable TypeScript file — used by run-tests.sh.
// DO NOT CONNECT TO A REAL SYSTEM.

// Hardcoded OpenAI key — should hard-block.
const OPENAI_KEY = "sk-proj-FAKEKEYabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJ";

// Stripe live key — should hard-block.
const STRIPE_KEY = "sk_live_FAKEKEY0123456789abcdefABCDEF";

// GitHub PAT — should hard-block.
const GH_TOKEN = "ghp_FAKEKEYabcdefghijklmnopqrstuvwxyz0123456";

export function evaluate(expr: string): unknown {
  // eval on user input — should advisory.
  return eval(expr);
}

export function buildQuery(userId: string): string {
  // SQL string concat — should advisory.
  return `SELECT * FROM users WHERE id = '${userId}'`;
}

export function generateToken(): string {
  // Math.random() in token context — should advisory (weak crypto).
  const token = Math.random().toString(36);
  return token;
}

export function executeShell(cmd: string) {
  // child_process.exec with user input — should advisory.
  const cp = require("child_process");
  return cp.exec(cmd);
}
