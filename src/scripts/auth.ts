// src/scripts/auth.ts

// Define the structure of the user profile we expect from the backend
export interface UserProfile {
  id: string;
  email: string;
  name: string;
  provider: string;
  // picture?: string; // Optional
}

// Result structure for our auth check function
export interface AuthCheckResult {
  user: UserProfile | null;
  loading: boolean; // Indicates if the check is in progress
  error?: string;    // Optional error message
}

/**
 * Checks authentication status by fetching user data from the backend API.
 * Relies on the browser sending the session cookie automatically.
 * @returns Promise<AuthCheckResult>
 */
export async function checkCurrentUser(): Promise<AuthCheckResult> {
  try {
    const response = await fetch('http://localhost:5000/api/user', {
      method: 'GET',
      // Crucial: Include credentials (cookies) in the request
      credentials: 'include',
      headers: {
        'Accept': 'application/json',
      },
    });

    if (response.ok) {
      const user = await response.json() as UserProfile;
      return { user, loading: false };
    } else if (response.status === 401) {
      // 401 Unauthorized means the user is not logged in (session invalid or missing)
      return { user: null, loading: false };
    } else {
      // Handle other unexpected errors (e.g., 500 Internal Server Error)
      const errorText = await response.text();
      console.error(`Auth check failed with status ${response.status}: ${errorText}`);
      return { user: null, loading: false, error: `Server error (${response.status})` };
    }
  } catch (error) {
    // Handle network errors or other fetch issues
    console.error("Network or fetch error during auth check:", error);
    // Check if error is an instance of Error to access message safely
    const message = error instanceof Error ? error.message : 'Unknown fetch error';
    return { user: null, loading: false, error: message };
  }
}