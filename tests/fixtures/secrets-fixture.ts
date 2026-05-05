// File path contains "fixture" → VulnPatternHook should DOWNGRADE to advisory,
// not hard-block. This is the test-path override semantics.

export const FIXTURE_ANTHROPIC_KEY = "sk-ant-api03-FAKEKEY1234567890123456789012345678901234567890aB";
export const FIXTURE_OPENAI_KEY = "sk-proj-FAKEKEYabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJ";

// These should produce advisory-level findings only.
