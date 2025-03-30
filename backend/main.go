package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url" // Import net/url
	"os"
	"sort"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/gorilla/sessions" // Ensure v1.3.0 or later is in go.mod
	"github.com/joho/godotenv"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/markbates/goth/providers/auth0" // Import Auth0 provider
	"github.com/markbates/goth/providers/google"
)

// --- STRUCT DEFINITIONS ---

// BookRequest represents the request body for book generation.
type BookRequest struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Chapters    int    `json:"chapters"`
	ApiKey      string `json:"api_key,omitempty"` // API key is optional in the request.
}

// QwenMessage represents a message in the Qwen API request.
type QwenMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// QwenAPIRequest represents the request body for the Qwen API.
type QwenAPIRequest struct {
	Model string `json:"model"`
	Input struct {
		Messages []QwenMessage `json:"messages"`
	} `json:"input"`
	ResultFormat string `json:"result_format"`
}

// QwenResponse represents the response from the Qwen API.
type QwenResponse struct {
	Output struct {
		FinishReason string `json:"finish_reason"`
		Text         string `json:"text"`
	} `json:"output"`
	// Add Usage if needed based on actual API response
	// Usage struct { ... } `json:"usage"`
	// RequestID string `json:"request_id"`
}

// UserProfile struct to store relevant info in session
type UserProfile struct {
	UserID   string `json:"id"`
	Email    string `json:"email"`
	Name     string `json:"name"`
	Provider string `json:"provider"`
	// Add other fields like Picture if needed
	// Picture   string `json:"picture"`
}

// --- END STRUCT DEFINITIONS ---


// --- CONSTANTS & GLOBALS ---

// Use a more descriptive session name
const sessionName = "lekhok-session"

// Key for storing user info in session
const userSessionKey = "userProfile"

// Store setup (consider a more persistent store for production)
var store *sessions.CookieStore

// --- END CONSTANTS & GLOBALS ---


// --- INITIALIZATION ---

func init() {
	// Load .env file early for session secret
	err := godotenv.Load()
	if err != nil {
		// Don't log fatal here, maybe .env is not in this specific directory when run
		log.Printf("Warning: Error loading .env file: %v. Ensure it's in the working directory or accessible.", err)
	}

	sessionSecret := os.Getenv("SESSION_SECRET")
	if sessionSecret == "" {
		log.Fatal("FATAL: SESSION_SECRET environment variable is required")
		// In development, you could generate one, but it's better to set it.
		// sessionSecret = string(securecookie.GenerateRandomKey(32))
		// log.Println("Warning: SESSION_SECRET not set, using a temporary one. Set it in your .env file.")
	}
	store = sessions.NewCookieStore([]byte(sessionSecret))

	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 7, // 7 days
		HttpOnly: true,
		Secure:   false, // Set to true if using HTTPS in production
		SameSite: http.SameSiteLaxMode,
	}
	// IMPORTANT: Assign the configured store to gothic
	gothic.Store = store

	// --- Provider Configuration ---
	googleClientID := os.Getenv("GOOGLE_CLIENT_ID")
	googleClientSecret := os.Getenv("GOOGLE_CLIENT_SECRET")
	auth0Domain := os.Getenv("AUTH0_DOMAIN")
	auth0ClientID := os.Getenv("AUTH0_CLIENT_ID")
	auth0ClientSecret := os.Getenv("AUTH0_CLIENT_SECRET")

	// Check for Google credentials (optional)
	if googleClientID != "" && googleClientSecret != "" {
		log.Println("Configuring Google OAuth provider...")
		goth.UseProviders(
			google.New(googleClientID, googleClientSecret, "http://localhost:5000/auth/google/callback"),
		)
	} else {
		log.Println("Warning: Google OAuth credentials (GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET) not set. Google login disabled.")
	}

	// Check for Auth0 credentials (required)
	if auth0Domain == "" || auth0ClientID == "" || auth0ClientSecret == "" {
		log.Fatal("FATAL: Auth0 credentials (AUTH0_DOMAIN, AUTH0_CLIENT_ID, AUTH0_CLIENT_SECRET) are required. Set them in your .env file.")
	} else {
		log.Println("Configuring Auth0 provider...")
		goth.UseProviders(
			auth0.New(
				auth0ClientID,     // Client ID
				auth0ClientSecret, // Client Secret
				"http://localhost:5000/auth/auth0/callback", // Callback URL MUST match Auth0 settings
				auth0Domain,       // Auth0 Domain
				// Add scopes necessary to get profile info
				"openid", "profile", "email"), // Standard OIDC scopes
		)
	}


	// Optional: Provider Map (Example - not strictly needed by goth itself)
	m := map[string]string{
		"auth0":  "Auth0",
		"google": "Google",
		// ... add other providers if you configure them
	}
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	log.Println("Initialized providers:", keys)
	// --- End Provider Configuration ---
}

// --- END INITIALIZATION ---


// --- MAIN FUNCTION ---

func main() {
	r := chi.NewRouter()

	// Middleware Setup
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger) // Log requests
	r.Use(middleware.Recoverer) // Recover from panics
	r.Use(middleware.Timeout(60 * time.Second)) // Set a reasonable request timeout

	// CORS Configuration
	r.Use(cors.Handler(cors.Options{
		// IMPORTANT: For sessions/cookies to work, AllowedOrigins cannot be "*" when AllowCredentials is true.
		AllowedOrigins:   []string{"http://localhost:4321"}, // Your Frontend URL
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token", "Cookie"}, // Allow Cookie header
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true, // Crucial for cookies/sessions
		MaxAge:           300, // How long to cache preflight results
	}))

	// --- Public Routes ---
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"message": "Hello There! API is running."})
	})

	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]string{
			"status":    "healthy",
			"timestamp": time.Now().Format(time.RFC3339),
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	// --- Authentication Routes ---
	// Initiates the login flow for a specific provider
	r.Get("/auth/{provider}", func(res http.ResponseWriter, req *http.Request) {
		provider := chi.URLParam(req, "provider")
		log.Printf("Attempting to initiate auth flow for provider: %s", provider)

		// Check if user is already logged in via our session BEFORE starting flow
		session, _ := store.Get(req, sessionName) // Ignore error, just check value
		if profileData := session.Values[userSessionKey]; profileData != nil {
			log.Println("User already authenticated based on session, redirecting to dashboard.")
			http.Redirect(res, req, "http://localhost:4321", http.StatusFound) // Redirect home
			return
		}

		// If not logged in, begin the auth flow. Gothic needs the provider in the context.
		ctx := context.WithValue(req.Context(), "provider", provider)
		req = req.WithContext(ctx)
		gothic.BeginAuthHandler(res, req)
	})

	// Handles the callback from the identity provider
	r.Get("/auth/{provider}/callback", func(res http.ResponseWriter, req *http.Request) {
		provider := chi.URLParam(req, "provider") // Get provider from URL again
		log.Printf("Received callback for provider: %s", provider)

		// Gothic needs provider in context for callback too
		ctx := context.WithValue(req.Context(), "provider", provider)
		req = req.WithContext(ctx)


		// Complete the authentication process
		user, err := gothic.CompleteUserAuth(res, req)
		if err != nil {
			log.Printf("Error completing auth for provider %s: %v", provider, err)
			http.Error(res, fmt.Sprintf("Error completing authentication: %v", err), http.StatusInternalServerError)
			// Consider redirecting to login with an error parameter:
			// http.Redirect(res, req, "http://localhost:4321/login?error=auth_failed", http.StatusSeeOther)
			return
		}

		log.Printf("User successfully authenticated via %s: %+v", provider, user)

		// Get or create a session
		session, err := store.Get(req, sessionName)
		if err != nil {
			log.Printf("Error getting session after auth: %v", err)
			http.Error(res, fmt.Sprintf("Session error: %v", err), http.StatusInternalServerError)
			return
		}

		// Create UserProfile from goth.User and store it securely
		profile := UserProfile{
			UserID:   user.UserID, // Provider's unique ID for the user
			Email:    user.Email,
			Name:     user.Name, // Use Name, fallback to NickName or FirstName if Name is empty
			Provider: user.Provider,
			// Picture: user.AvatarURL, // Uncomment if needed and available
		}
		if profile.Name == "" {
			profile.Name = user.NickName
		}
		if profile.Name == "" {
			profile.Name = user.FirstName
		}


		profileBytes, err := json.Marshal(profile)
		if err != nil {
			log.Printf("Error marshalling user profile to JSON: %v", err)
			http.Error(res, "Failed to process user profile", http.StatusInternalServerError)
			return
		}

		// Store the JSON bytes in the session
		session.Values[userSessionKey] = profileBytes
		session.Options.MaxAge = store.Options.MaxAge // Ensure max age is copied

		// Save the session
		if err := session.Save(req, res); err != nil {
			log.Printf("Error saving session after auth: %v", err)
			http.Error(res, fmt.Sprintf("Failed to save session: %v", err), http.StatusInternalServerError)
			return
		}

		log.Printf("Session saved successfully for user %s (%s)", profile.Email, profile.UserID)
		// Redirect to the frontend application's main page/dashboard
		http.Redirect(res, req, "http://localhost:4321", http.StatusFound)
	})

	// Handles logout
	r.Get("/logout/{provider}", func(res http.ResponseWriter, req *http.Request) {
		provider := chi.URLParam(req, "provider")
		log.Printf("Attempting to log out user from provider: %s", provider)

		// 1. Clear the local application session
		session, err := store.Get(req, sessionName)
		if err == nil {
			// Delete user profile from session data
			delete(session.Values, userSessionKey)
			// Set MaxAge to -1 to effectively delete the session cookie
			session.Options.MaxAge = -1
			err = session.Save(req, res)
			if err != nil {
				log.Printf("Error saving cleared session during logout: %v", err)
				// Continue with logout anyway, but log the error
			} else {
				log.Println("Local session cleared successfully.")
			}
		} else {
			log.Printf("Error getting session during logout (might already be expired): %v", err)
		}

		// 2. Clear the provider's session via Gothic (may not always be necessary/effective depending on provider)
		// Gothic needs provider in context here too
		ctx := context.WithValue(req.Context(), "provider", provider)
		req = req.WithContext(ctx)
		gothicErr := gothic.Logout(res, req) // This primarily clears gothic's internal state if any
		if gothicErr != nil {
			log.Printf("Error calling gothic.Logout for %s: %v", provider, gothicErr)
			// This usually isn't critical, proceed with redirect
		}

		// 3. Redirect to Auth0 logout endpoint if provider is Auth0 (Recommended)
		if provider == "auth0" {
			auth0Domain := os.Getenv("AUTH0_DOMAIN")
			auth0ClientID := os.Getenv("AUTH0_CLIENT_ID")
			// URL where Auth0 should redirect the user *after* they logout from Auth0
			frontendLoginURL := "http://localhost:4321/login" 

			logoutUrl, parseErr := url.Parse("https://" + auth0Domain + "/v2/logout")
			if parseErr != nil {
				log.Printf("Error parsing Auth0 logout URL: %v", parseErr)
				// Fallback to simple redirect if URL parsing fails
				http.Redirect(res, req, frontendLoginURL, http.StatusTemporaryRedirect)
				return
			}

			parameters := url.Values{}
			// returnTo parameter tells Auth0 where to send the user after logout
			parameters.Add("returnTo", frontendLoginURL)
			// client_id is required by Auth0 logout endpoint
			parameters.Add("client_id", auth0ClientID)
			logoutUrl.RawQuery = parameters.Encode()

			log.Printf("Redirecting user to Auth0 logout endpoint: %s", logoutUrl.String())
			http.Redirect(res, req, logoutUrl.String(), http.StatusTemporaryRedirect)
			return // IMPORTANT: Stop execution here after redirecting to Auth0
		}

		// 4. Fallback/Default: Redirect directly to frontend login page for other providers or if Auth0 redirect fails
		log.Printf("Provider is not Auth0 or Auth0 redirect failed, redirecting directly to frontend login.")
		http.Redirect(res, req, "http://localhost:4321/login", http.StatusFound)
	})

	// --- Authenticated API Routes ---
	r.Route("/api", func(r chi.Router) {
		// Apply the authentication middleware to all routes within this group
		r.Use(authRequiredMiddleware)

		// Get current user's profile (useful for frontend)
		r.Get("/user", func(w http.ResponseWriter, r *http.Request) {
			// The user profile is added to the context by the authRequiredMiddleware
			userProfile, ok := r.Context().Value(userSessionKey).(UserProfile)
			if !ok {
				log.Println("Error: User profile not found in context after auth middleware")
				http.Error(w, "Internal Server Error: Could not retrieve user profile", http.StatusInternalServerError)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(userProfile)
		})

		// Example protected route (moved generate-book here)
		r.Post("/generate-book", generateBook)

		// Add other authenticated API endpoints here...
		//r.Get("/protected-data", getProtectedDataHandler)

	}) // End of /api protected group


	// --- Server Start ---
	port := os.Getenv("PORT")
	if port == "" {
		port = "5000" // Default port
	}

	log.Printf("Server starting on port %s...", port)
	log.Printf("Frontend expected at http://localhost:4321")
	log.Printf("Auth Callback URL for Google (if enabled): http://localhost:5000/auth/google/callback")
	log.Printf("Auth Callback URL for Auth0: http://localhost:5000/auth/auth0/callback")

	// Start the HTTP server
	server := &http.Server{
		Addr:    ":" + port,
		Handler: r,
		// Add timeouts for production hardening
		// ReadTimeout:  5 * time.Second,
		// WriteTimeout: 10 * time.Second,
		// IdleTimeout:  120 * time.Second,
	}
	log.Fatal(server.ListenAndServe())
}

// --- END MAIN FUNCTION ---


// --- MIDDLEWARE ---

// authRequiredMiddleware checks if a user is authenticated via session.
// If authenticated, it adds the UserProfile to the request context.
func authRequiredMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, err := store.Get(r, sessionName)
		if err != nil {
			log.Printf("Auth middleware: Session error: %v", err)
			http.Error(w, "Unauthorized: Session error", http.StatusUnauthorized)
			return
		}

		profileData := session.Values[userSessionKey]
		if profileData == nil {
			log.Println("Auth middleware: No user session found (user not logged in)")
			http.Error(w, "Unauthorized: Please log in", http.StatusUnauthorized)
			return
		}

		// Assuming profileData is stored as JSON bytes
		profileBytes, ok := profileData.([]byte)
		if !ok {
			log.Println("Auth middleware: Error - Session data format is invalid (not []byte)")
			// Clear potentially corrupt session data
			delete(session.Values, userSessionKey)
			session.Options.MaxAge = -1 // Expire session/cookie
			session.Save(r, w)
			http.Error(w, "Internal Server Error: Invalid session state", http.StatusInternalServerError)
			return
		}

		var userProfile UserProfile
		if err := json.Unmarshal(profileBytes, &userProfile); err != nil {
			log.Printf("Auth middleware: Error unmarshalling user profile from session: %v", err)
			// Clear potentially corrupt session data
			delete(session.Values, userSessionKey)
			session.Options.MaxAge = -1
			session.Save(r, w)
			http.Error(w, "Internal Server Error: Cannot read session data", http.StatusInternalServerError)
			return
		}

		// User is authenticated, add profile to context for downstream handlers
		// Use a dedicated type for context key for safety
		// type contextKey string
		// const userProfileKey contextKey = userSessionKey
		// ctx := context.WithValue(r.Context(), userProfileKey, userProfile)

		// Using the const string directly (less safe but simpler for this example)
		ctx := context.WithValue(r.Context(), userSessionKey, userProfile)

		// Proceed to the next handler with the updated context
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}


// --- API HANDLERS (Example: generateBook) ---

// generateBook handles the request to generate book content.
// It now expects to be called AFTER the authRequiredMiddleware.
func generateBook(w http.ResponseWriter, r *http.Request) {
	// Example: Retrieve user from context if needed for logging or logic
	userProfile, ok := r.Context().Value(userSessionKey).(UserProfile)
	if !ok {
		// This shouldn't happen if middleware is correctly applied, but good to check
		log.Println("Error in generateBook: User profile missing from context")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	log.Printf("generateBook called by user: %s (%s)", userProfile.Email, userProfile.UserID)


	// Parse the request body
	var req BookRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	defer r.Body.Close() // Ensure body is closed

	// Validate the request.
	if req.Title == "" || req.Description == "" || req.Chapters <= 0 {
		errResp := map[string]string{"error": "Title, description, and a positive number of chapters are required"}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errResp)
		return
	}

	// Get the API key from the request or the environment variable.
	apiKey := req.ApiKey // Allow user-specific key override if provided

	if apiKey == "" {
		apiKey = os.Getenv("QWEN_API_KEY")
		print("API Key from request:", apiKey)
		fmt.Sprintf("API Key from env: %s", apiKey)
		if apiKey == "" {
			errResp := map[string]string{"error": "Qwen API key is missing. Configure QWEN_API_KEY on the server or provide api_key in the request."}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest) // Or 500 if server config error
			json.NewEncoder(w).Encode(errResp)
			return
		}
	}

	// Create the system prompt.
	systemPrompt := fmt.Sprintf(`You are a professional book writer.
Generate a complete book with the following details:
- Title: %s
- Description: %s
- Number of chapters: %d

The book should have a coherent narrative that follows the description.
Each chapter should have a title (e.g., using '## Chapter Title') and substantial content.
Format the output using standard Markdown.
Create a compelling opening and satisfying conclusion. Ensure the full book text is generated.`, req.Title, req.Description, req.Chapters)

	// Create the Qwen API request payload.
	qwenReq := QwenAPIRequest{
		Model:        "qwen-plus", // Or other appropriate model
		ResultFormat: "message",   // Expect message format in response
		Input: struct {
			Messages []QwenMessage `json:"messages"`
		}{
			Messages: []QwenMessage{
				{
					Role:    "system",
					Content: systemPrompt,
				},
				{
					Role:    "user",
					Content: fmt.Sprintf("Please generate the complete book titled '%s' with %d chapters based on the provided description.", req.Title, req.Chapters),
				},
			},
		},
	}

	// Call the Qwen API.
	bookContent, err := callQwenAPI(qwenReq, apiKey)
	if err != nil {
		log.Printf("Error calling Qwen API: %v", err)
		errResp := map[string]string{"error": "Failed to generate book content: " + err.Error()}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(errResp)
		return
	}

	// Return the generated book.
	resp := map[string]string{"book": bookContent}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK) // OK status
	json.NewEncoder(w).Encode(resp)
}

// --- HELPER FUNCTIONS ---

// callQwenAPI makes the actual HTTP call to the Qwen API.
func callQwenAPI(req QwenAPIRequest, apiKey string) (string, error) {
	// Marshal the request payload into JSON.
	jsonData, err := json.Marshal(req)
	if err != nil {
		return "", fmt.Errorf("failed to marshal Qwen request: %w", err)
	}

	// Define the Qwen API endpoint URL.
	// Ensure this is the correct endpoint for your chosen model and region.
	url := "https://dashscope-intl.aliyuncs.com/api/v1/services/aigc/text-generation/generation"

	// Create the HTTP request object.
	httpReq, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("failed to create HTTP request for Qwen API: %w", err)
	}

	// Create a context with a timeout (e.g., 5 minutes).
	// Adjust timeout based on expected generation time.
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
	defer cancel() // Ensure the context cancel function is called
	httpReq = httpReq.WithContext(ctx)

	// Set the required headers for the Qwen API.
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+apiKey)
	// Add any other required headers, e.g., X-DashScope-SSE: enable for streaming (if used)

	authHeader := httpReq.Header.Get("Authorization")
log.Printf("DEBUG: callQwenAPI - Sending Authorization Header: %s (Length: %d)", authHeader, len(authHeader))
if len(authHeader) > 15 { // Bearer + space + key
   log.Printf("DEBUG: callQwenAPI - Key part starts: '%s'", authHeader[7:11]) // Log first few chars of key part
}
	// Create an HTTP client with a timeout matching the context.
	client := &http.Client{Timeout: 300 * time.Second}

	// Send the request.
	log.Printf("Calling Qwen API at %s with model %s", url, req.Model)
	resp, err := client.Do(httpReq)
	if err != nil {
		// Check for context deadline exceeded
		if ctx.Err() == context.DeadlineExceeded {
			return "", fmt.Errorf("Qwen API request timed out after 300 seconds")
		}
		return "", fmt.Errorf("failed to send request to Qwen API: %w", err)
	}
	defer resp.Body.Close() // Ensure the response body is closed

	// Read the response body.
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read Qwen API response body: %w", err)
	}

	// Check the HTTP status code.
	if resp.StatusCode != http.StatusOK {
		log.Printf("Qwen API returned non-OK status: %d. Response body: %s", resp.StatusCode, string(body))
		return "", fmt.Errorf("Qwen API returned status %d: %s", resp.StatusCode, string(body))
	}

	// Parse the JSON response.
	var qwenResp QwenResponse
	if err := json.Unmarshal(body, &qwenResp); err != nil {
		log.Printf("Failed to parse Qwen API JSON response. Body: %s", string(body))
		return "", fmt.Errorf("failed to parse Qwen API JSON response: %w", err)
	}

	// Check if the response text is empty or indicates an error within the JSON.
	if qwenResp.Output.Text == "" {
		log.Printf("Qwen API returned an empty text response or unexpected format: %+v", qwenResp)
		// You might want to check for specific error codes or messages in the qwenResp structure if the API provides them
		return "", fmt.Errorf("Qwen API returned empty content (FinishReason: %s)", qwenResp.Output.FinishReason)
	}

	log.Printf("Successfully received response from Qwen API (FinishReason: %s)", qwenResp.Output.FinishReason)
	return qwenResp.Output.Text, nil
}

// --- END HELPER FUNCTIONS ---