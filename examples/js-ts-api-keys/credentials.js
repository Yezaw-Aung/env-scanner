// Sample project #2 — JavaScript file with hardcoded AWS and Stripe secrets.
// Intentionally contains beginner mistakes for scanner testing.

// Bug: AWS credentials hardcoded
const AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE";
const AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

// Bug: Stripe live secret key hardcoded
const STRIPE_SECRET_KEY = "sk_live_51Mza2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t1u2v3w4x5y6z";

// This is fine — just a regular greeting string (low entropy, not a secret name)
const greeting = "Hello, welcome to our service!";

module.exports = {
  AWS_ACCESS_KEY_ID,
  AWS_SECRET_ACCESS_KEY,
  STRIPE_SECRET_KEY,
};
