// This interface might not be needed anymore if we only check cookie status
// interface User {
//   id: string;
//   email: string;
//   verified_email: boolean;
//   name: string;
//   picture: string;
// }

interface AuthCheckResult {
  isLoggedIn: boolean;
  loading: boolean;
}

// We no longer store user details globally in this script
// let user: User | null = null;
// let loading = true; // Loading state handled within the function now

/**
 * Checks if the user is logged in by looking for the 'auth_status' cookie.
 */
export function checkAuth(): AuthCheckResult {
  // Access cookies (works only in browser context)
  const cookies = typeof document !== "undefined" ? document.cookie : "";

  // Check if the specific cookie exists and has the expected value
  const isLoggedIn = cookies
    .split(";")
    .some((item) => item.trim().startsWith("auth_status=loggedin"));

  // Since this check is synchronous and client-side, loading is always false
  return { isLoggedIn: isLoggedIn, loading: false };
}

// Removed logout function - handled by backend redirect via link click

// Removed getUser function - state not managed here anymore

// Removed setUser function - state not managed here anymore
