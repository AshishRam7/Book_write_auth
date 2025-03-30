package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/gorilla/sessions"

	//"github.com/gorilla/pat"
	"github.com/joho/godotenv"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/markbates/goth/providers/google"
)

// Define a session store
// NOTE: Use a secure key and consider a persistent store (like RedisStore or FilesystemStore) for production.
var store = sessions.NewCookieStore([]byte(os.Getenv("SESSION_SECRET")))

const sessionName = "auth-session"
const cookieAuthStatus = "auth_status"

func init() {
	// Set session options
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 7, // 7 days
		HttpOnly: true,
		Secure:   false, // Set to true if using HTTPS
	}
	// Gothic uses the default store provided by gorilla/sessions
	// We replace gothic's default store initializer
	gothic.Store = store
}

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
}

func main() {
	// Load environment variables from .env file.

	goth.UseProviders(
		google.New(os.Getenv("GOOGLE_CLIENT_ID"), os.Getenv("GOOGLE_CLIENT_SECRET"), "http://localhost:5000/auth/google/callback"),
	)

	m := map[string]string{
		"amazon":          "Amazon",
		"apple":           "Apple",
		"auth0":           "Auth0",
		"azuread":         "Azure AD",
		"battlenet":       "Battle.net",
		"bitbucket":       "Bitbucket",
		"box":             "Box",
		"dailymotion":     "Dailymotion",
		"deezer":          "Deezer",
		"digitalocean":    "Digital Ocean",
		"discord":         "Discord",
		"dropbox":         "Dropbox",
		"eveonline":       "Eve Online",
		"facebook":        "Facebook",
		"fitbit":          "Fitbit",
		"gitea":           "Gitea",
		"github":          "Github",
		"gitlab":          "Gitlab",
		"google":          "Google",
		"gplus":           "Google Plus",
		"heroku":          "Heroku",
		"instagram":       "Instagram",
		"intercom":        "Intercom",
		"kakao":           "Kakao",
		"lastfm":          "Last FM",
		"line":            "LINE",
		"linkedin":        "LinkedIn",
		"mastodon":        "Mastodon",
		"meetup":          "Meetup.com",
		"microsoftonline": "Microsoft Online",
		"naver":           "Naver",
		"nextcloud":       "NextCloud",
		"okta":            "Okta",
		"onedrive":        "Onedrive",
		"openid-connect":  "OpenID Connect",
		"patreon":         "Patreon",
		"paypal":          "Paypal",
		"salesforce":      "Salesforce",
		"seatalk":         "SeaTalk",
		"shopify":         "Shopify",
		"slack":           "Slack",
		"soundcloud":      "SoundCloud",
		"spotify":         "Spotify",
		"steam":           "Steam",
		"strava":          "Strava",
		"stripe":          "Stripe",
		"tiktok":          "TikTok",
		"twitch":          "Twitch",
		"twitter":         "Twitter",
		"twitterv2":       "Twitter",
		"typetalk":        "Typetalk",
		"uber":            "Uber",
		"vk":              "VK",
		"wecom":           "WeCom",
		"wepay":           "Wepay",
		"xero":            "Xero",
		"yahoo":           "Yahoo",
		"yammer":          "Yammer",
		"yandex":          "Yandex",
		"zoom":            "Zoom",
	}
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if err := godotenv.Load(); err != nil {

		log.Println("Warning: Error loading .env file:", err)
	}

	r := chi.NewRouter()

	// Middleware
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: false,
		MaxAge:           300,
	}))

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello There!"))
	})

	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]string{
			"status":    "healthy",
			"timestamp": time.Now().Format(time.RFC3339),
		}

		jsonResp, err := json.Marshal(resp)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write(jsonResp)
	})

	r.Post("/generate-book", generateBook)
	r.Get("/auth/{provider}/callback", func(res http.ResponseWriter, req *http.Request) {
		provider := chi.URLParam(req, "provider")
		req = req.WithContext(context.WithValue(context.Background(), "provider", provider))

		user, err := gothic.CompleteUserAuth(res, req)
		if err != nil {
			fmt.Fprintln(res, err)
			return
		}
		fmt.Println(user)

		// Set a simple cookie to indicate login status
		cookie := http.Cookie{
			Name:     cookieAuthStatus,
			Value:    "loggedin",
			Path:     "/",
			Expires:  time.Now().Add(7 * 24 * time.Hour), // Matches session max age
			HttpOnly: true,
			Secure:   false, // Set to true if using HTTPS
			SameSite: http.SameSiteLaxMode,
		}
		http.SetCookie(res, &cookie)

		http.Redirect(res, req, "http://localhost:4321", http.StatusFound)
	})

	r.Get("/logout/{provider}", func(res http.ResponseWriter, req *http.Request) {
		provider := chi.URLParam(req, "provider")
		req = req.WithContext(context.WithValue(context.Background(), "provider", provider))

		gothic.Logout(res, req) // This should clear the gothic session cookie

		// Clear our custom auth status cookie
		cookie := http.Cookie{
			Name:     cookieAuthStatus,
			Value:    "",
			Path:     "/",
			MaxAge:   -1, // Tells the browser to delete the cookie
			HttpOnly: true,
			Secure:   false, // Set to true if using HTTPS
			SameSite: http.SameSiteLaxMode,
		}
		http.SetCookie(res, &cookie)

		res.Header().Set("Location", "/")             // Keep this? Or redirect to login?
		res.WriteHeader(http.StatusTemporaryRedirect) // This might conflict with http.Redirect

		// Redirect to the login page after logout
		http.Redirect(res, req, "http://localhost:4321/login", http.StatusFound)
	})

	// Add a route to initiate auth
	r.Get("/auth/{provider}", func(res http.ResponseWriter, req *http.Request) {
		provider := chi.URLParam(req, "provider")
		req = req.WithContext(context.WithValue(context.Background(), "provider", provider))

		// try to get the user without re-authenticating
		if gothUser, err := gothic.CompleteUserAuth(res, req); err == nil {
			// User is already authenticated, perhaps redirect them home?
			fmt.Println("User already authenticated:", gothUser.Email)
			http.Redirect(res, req, "http://localhost:4321", http.StatusFound) // Redirect home if already logged in
		} else {
			// User is not authenticated, begin the auth flow
			gothic.BeginAuthHandler(res, req)
		}
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "5000"
	}

	log.Printf("Server starting on port %s\n", port)
	log.Fatal(http.ListenAndServe(":"+port, r))
}

func generateBook(w http.ResponseWriter, r *http.Request) {
	// Parse the request body
	var req BookRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate the request.
	if req.Title == "" || req.Description == "" || req.Chapters <= 0 {
		jsonError := map[string]string{"error": "Title, description, and chapters are required"}
		jsonResp, _ := json.Marshal(jsonError)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write(jsonResp)
		return
	}

	// Get the API key from the request or the environment variable.
	apiKey := req.ApiKey
	if apiKey == "" {
		apiKey = os.Getenv("QWEN_API_KEY")
		if apiKey == "" {
			jsonError := map[string]string{"error": "API key is required either in request or environment variable"}
			jsonResp, _ := json.Marshal(jsonError)

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			w.Write(jsonResp)
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
Each chapter should have a title and substantial content.
Format the book with proper Markdown, including headings for chapters.
Create a compelling opening and satisfying conclusion.`, req.Title, req.Description, req.Chapters)

	// Create the Qwen API request payload.
	var qwenReq QwenAPIRequest
	qwenReq.Model = "qwen-plus"
	qwenReq.ResultFormat = "message"
	qwenReq.Input.Messages = []QwenMessage{
		{
			Role:    "system",
			Content: systemPrompt,
		},
		{
			Role:    "user",
			Content: fmt.Sprintf("Please generate a complete book titled '%s' with %d chapters based on this description: %s", req.Title, req.Chapters, req.Description),
		},
	}

	// Call the Qwen API.
	bookContent, err := callQwenAPI(qwenReq, apiKey)
	if err != nil {
		jsonError := map[string]string{"error": "Failed to generate book: " + err.Error()}
		jsonResp, _ := json.Marshal(jsonError)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write(jsonResp)
		return
	}

	// Return the generated book.
	resp := map[string]string{"book": bookContent}
	jsonResp, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonResp)
}

func callQwenAPI(req QwenAPIRequest, apiKey string) (string, error) {
	// Marshal the request payload into JSON.
	jsonData, err := json.Marshal(req)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	// Create the HTTP request with the proper Qwen API endpoint.
	url := "https://dashscope-intl.aliyuncs.com/api/v1/services/aigc/text-generation/generation"
	httpReq, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("failed to create HTTP request: %w", err)
	}

	// Create a context with a 5-minute timeout and attach it to the request.
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
	defer cancel()
	httpReq = httpReq.WithContext(ctx)

	// Set the required headers.
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+apiKey)

	client := &http.Client{Timeout: 300 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// Read the response.
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
	}

	// Parse the JSON response.
	var qwenResp QwenResponse
	if err := json.Unmarshal(body, &qwenResp); err != nil {
		return "", fmt.Errorf("failed to parse JSON response: %w, response body: %s", err, string(body))
	}

	if qwenResp.Output.Text == "" {
		return "", fmt.Errorf("API returned an empty or invalid response: %+v", qwenResp)
	}

	return qwenResp.Output.Text, nil
}
