// Sample project #2 — TypeScript with frontend API keys (beginner mistake).
// These keys get shipped to every user's browser — anyone can read them.

// Bug: Google Maps API key hardcoded in frontend bundle
export const GOOGLE_MAPS_API_KEY = "AIzaSyDemo_99887766aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890";

// Bug: Stripe publishable key hardcoded
export const STRIPE_PUBLISHABLE_KEY = "pk_live_51Mza2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t1u2v3w4x5y6z";

// Bug: Firebase API key hardcoded
export const FIREBASE_API_KEY = "AIzaSyFirebase_99887766_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234";

// This is fine — Tailwind CSS classes, not a secret
export const buttonClasses = "flex items-center gap-2 rounded-md bg-blue-500 px-4 py-2 text-sm font-medium text-white hover:bg-blue-600";
