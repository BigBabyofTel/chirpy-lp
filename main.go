package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/BigBabyofTel/chirpy-lp/internal/auth"
	"github.com/BigBabyofTel/chirpy-lp/internal/database"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	DB             *database.Queries
	DBConn         *sql.DB
	JWTSecret      string
	PolkaKey       string
}

// UserResponse DTOs to ensure snake_case JSON keys
type UserResponse struct {
	ID          uuid.UUID `json:"id"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	Email       string    `json:"email"`
	IsChirpyRed bool      `json:"is_chirpy_red"`
}

type ChirpResponse struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Body      string    `json:"body"`
	UserID    uuid.UUID `json:"user_id"`
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)

		next.ServeHTTP(w, r)
	})
}

func (cfg *apiConfig) handlerMetrics(w http.ResponseWriter, _ *http.Request) {
	hits := cfg.fileserverHits.Load()

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	_, err := fmt.Fprintf(w, `
<html>
<body>
    <h1>Welcome, Chirpy Admin</h1>
    <p>Chirpy has been visited %d times!</p>
</body>
</html>`, hits)
	if err != nil {
		return
	}
}

func (cfg *apiConfig) reset(w http.ResponseWriter, r *http.Request) {
	cfg.fileserverHits.Swap(0)

	ctx := r.Context()

	// Delete from child tables first to avoid foreign key constraint violations
	_, err := cfg.DBConn.ExecContext(ctx, "DELETE FROM refresh_tokens")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("Failed to reset refresh_tokens: " + err.Error()))
		return
	}

	_, err = cfg.DBConn.ExecContext(ctx, "DELETE FROM chirps")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("Failed to reset chirps: " + err.Error()))
		return
	}

	_, err = cfg.DBConn.ExecContext(ctx, "DELETE FROM users")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("Failed to reset users: " + err.Error()))
		return
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("Hits reset to 0 and database reset to initial state."))
}

func getCleanedBody(body string, badWords map[string]struct{}) string {
	words := strings.Split(body, " ")
	for i, word := range words {
		loweredWord := strings.ToLower(word)
		if _, ok := badWords[loweredWord]; ok {
			words[i] = "****"
		}
	}
	cleaned := strings.Join(words, " ")
	return cleaned
}

func validateChirp(body string) (string, error) {
	const maxChirpLength = 140
	if len(body) > maxChirpLength {
		return "", errors.New("chirp is too long")
	}

	badWords := map[string]struct{}{
		"kerfuffle": {},
		"sharbert":  {},
		"fornax":    {},
	}
	cleaned := getCleanedBody(body, badWords)
	return cleaned, nil
}

func (cfg *apiConfig) handlerChirpsCreate(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Body string `json:"body"`
	}

	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	if err := decoder.Decode(&params); err != nil {
		respondWithError(w, http.StatusBadRequest, "Couldn't decode parameters", err)
		return
	}

	bearer, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "invalid or missing token", nil)
		return
	}
	userID, err := auth.ValidateJWT(bearer, cfg.JWTSecret)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "invalid or expired token", nil)
		return
	}

	cleaned, err := validateChirp(params.Body)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, err.Error(), err)
		return
	}

	chirp, err := cfg.DB.CreateChirp(r.Context(), database.CreateChirpParams{
		Body:   cleaned,
		UserID: userID,
	})
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't create chirp", err)
		return
	}

	respondWithJSON(w, http.StatusCreated, ChirpResponse{
		ID:        chirp.ID,
		CreatedAt: chirp.CreatedAt,
		UpdatedAt: chirp.UpdatedAt,
		Body:      chirp.Body,
		UserID:    chirp.UserID,
	})
}

func (cfg *apiConfig) handlerCreateUser(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "failed to decode request body", nil)
		return
	}
	//do something with params body (create new user)
	ctx := r.Context()

	//hash the password
	newPassword, err := auth.HashPassword(params.Password)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "failed to hash password", err)
	}
	//createUserParams
	userParams := database.CreateUserParams{
		Email:        params.Email,
		PasswordHash: newPassword,
	}
	user, err := cfg.DB.CreateUser(ctx, userParams)
	if err != nil {
		respondWithError(w, http.StatusForbidden, "request timeout", nil)
		return
	}
	respondWithJSON(w, http.StatusCreated, UserResponse{
		ID:          user.ID,
		CreatedAt:   user.CreatedAt,
		UpdatedAt:   user.UpdatedAt,
		Email:       user.Email,
		IsChirpyRed: user.IsChirpyRed.Bool,
	})
}

func (cfg *apiConfig) handlerUpdateUser(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	if err := decoder.Decode(&params); err != nil {
		respondWithError(w, http.StatusBadRequest, "failed to decode request body", nil)
		return
	}

	// Both email and password are required for this endpoint
	if strings.TrimSpace(params.Email) == "" || strings.TrimSpace(params.Password) == "" {
		respondWithError(w, http.StatusBadRequest, "email and password are required", nil)
		return
	}

	// Extract and validate bearer token
	bearer, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "missing or invalid Authorization header", nil)
		return
	}

	userID, err := auth.ValidateJWT(bearer, cfg.JWTSecret)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "invalid or expired token", nil)
		return
	}

	// Hash the new password
	hashed, err := auth.HashPassword(params.Password)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "failed to hash password", err)
		return
	}

	// Update the user's email and password_hash, returning the updated row (without password)
	ctx := r.Context()
	row := cfg.DBConn.QueryRowContext(ctx, `
		UPDATE users
		SET email = $1, password_hash = $2, updated_at = NOW()
		WHERE id = $3
		RETURNING id, created_at, updated_at, email, is_chirpy_red
	`, params.Email, hashed, userID)

	var u UserResponse
	if err := row.Scan(&u.ID, &u.CreatedAt, &u.UpdatedAt, &u.Email, &u.IsChirpyRed); err != nil {
		if err == sql.ErrNoRows {
			respondWithError(w, http.StatusNotFound, "user not found", nil)
			return
		}
		respondWithError(w, http.StatusInternalServerError, "could not update user", err)
		return
	}

	respondWithJSON(w, http.StatusOK, u)
}

func (cfg *apiConfig) getAllChirps(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Check for author_id query parameter
	authorIDStr := r.URL.Query().Get("author_id")

	// Check for sort query parameter (default to "asc")
	sortParam := r.URL.Query().Get("sort")
	if sortParam == "" {
		sortParam = "asc"
	}

	// Validate sort parameter
	if sortParam != "asc" && sortParam != "desc" {
		respondWithError(w, http.StatusBadRequest, "sort parameter must be 'asc' or 'desc'", nil)
		return
	}

	var chirps []database.Chirp
	var err error

	if authorIDStr != "" {
		// Parse author_id as UUID
		authorID, parseErr := uuid.Parse(authorIDStr)
		if parseErr != nil {
			respondWithError(w, http.StatusBadRequest, "invalid author_id format", parseErr)
			return
		}

		// Get chirps for specific author using direct SQL query (without ORDER BY since we'll sort in-memory)
		rows, queryErr := cfg.DBConn.QueryContext(ctx, `
			SELECT id, created_at, updated_at, body, user_id 
			FROM chirps 
			WHERE user_id = $1
		`, authorID)
		if queryErr != nil {
			respondWithError(w, http.StatusInternalServerError, "could not get chirps", queryErr)
			return
		}
		defer rows.Close()

		for rows.Next() {
			var chirp database.Chirp
			if scanErr := rows.Scan(&chirp.ID, &chirp.CreatedAt, &chirp.UpdatedAt, &chirp.Body, &chirp.UserID); scanErr != nil {
				respondWithError(w, http.StatusInternalServerError, "could not scan chirp", scanErr)
				return
			}
			chirps = append(chirps, chirp)
		}

		if rowsErr := rows.Err(); rowsErr != nil {
			respondWithError(w, http.StatusInternalServerError, "error reading chirps", rowsErr)
			return
		}
	} else {
		// Get all chirps using existing method
		chirps, err = cfg.DB.GetAllChirps(ctx)
		if err != nil {
			respondWithError(w, http.StatusForbidden, "could not get chirps", nil)
			return
		}
	}

	// Sort chirps in-memory based on sort parameter
	sort.Slice(chirps, func(i, j int) bool {
		if sortParam == "desc" {
			return chirps[i].CreatedAt.After(chirps[j].CreatedAt)
		}
		// Default to ascending order
		return chirps[i].CreatedAt.Before(chirps[j].CreatedAt)
	})

	// Map DB chirps to response DTOs for snake_case JSON
	resp := make([]ChirpResponse, 0, len(chirps))
	for _, c := range chirps {
		resp = append(resp, ChirpResponse{
			ID:        c.ID,
			CreatedAt: c.CreatedAt,
			UpdatedAt: c.UpdatedAt,
			Body:      c.Body,
			UserID:    c.UserID,
		})
	}
	respondWithJSON(w, http.StatusOK, resp)
}

func (cfg *apiConfig) getChirpById(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	chirpIDStr := r.PathValue("chirpID")
	if chirpIDStr == "" {
		respondWithError(w, http.StatusBadRequest, "missing chirp ID", nil)
		return
	}
	chirpID, err := uuid.Parse(chirpIDStr)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "invalid chirp ID", err)
		return
	}

	chirp, err := cfg.DB.GetChirpByID(ctx, chirpID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			respondWithError(w, http.StatusNotFound, "chirp not found", nil)
		} else {
			respondWithError(w, http.StatusInternalServerError, "could not get chirp", err)
		}
		return
	}

	respondWithJSON(w, http.StatusOK, ChirpResponse{
		chirp.ID,
		chirp.CreatedAt,
		chirp.UpdatedAt,
		chirp.Body,
		chirp.UserID,
	})
}

func (cfg *apiConfig) handlerDeleteChirp(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Extract and validate bearer token
	bearer, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "missing or invalid Authorization header", nil)
		return
	}

	userID, err := auth.ValidateJWT(bearer, cfg.JWTSecret)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "invalid or expired token", nil)
		return
	}

	// Get chirp ID from URL path
	chirpIDStr := r.PathValue("chirpID")
	if chirpIDStr == "" {
		respondWithError(w, http.StatusBadRequest, "missing chirp ID", nil)
		return
	}
	chirpID, err := uuid.Parse(chirpIDStr)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "invalid chirp ID", err)
		return
	}

	// Get the chirp to verify ownership
	chirp, err := cfg.DB.GetChirpByID(ctx, chirpID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			respondWithError(w, http.StatusNotFound, "chirp not found", nil)
		} else {
			respondWithError(w, http.StatusInternalServerError, "could not get chirp", err)
		}
		return
	}

	// Check if the user is the author of the chirp
	if chirp.UserID != userID {
		respondWithError(w, http.StatusForbidden, "you can only delete your own chirps", nil)
		return
	}

	// Delete the chirp
	_, err = cfg.DBConn.ExecContext(ctx, "DELETE FROM chirps WHERE id = $1", chirpID)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "could not delete chirp", err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (cfg *apiConfig) handleLogin(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Email            string `json:"email"`
		Password         string `json:"password"`
		ExpiresInSeconds int    `json:"expires_in_seconds"`
	}

	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "failed to decode request body", nil)
		return
	}
	ctx := r.Context()

	user, err := cfg.DB.GetUser(ctx, params.Email)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "could not get user", err)
	}

	ok, err := auth.VerifyPassword(params.Password, user.PasswordHash)
	if err != nil || !ok {
		respondWithError(w, http.StatusUnauthorized, "could not get user", err)
		return
	}

	expires := time.Hour
	if params.ExpiresInSeconds > 0 {
		expires = time.Duration(params.ExpiresInSeconds) * time.Second
	}

	token, err := auth.MakeJWT(user.ID, cfg.JWTSecret, expires)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "could not create token", err)
		return
	}

	// add refresh token
	refreshToken, err := auth.MakeRefreshToken()
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "could not create refresh token", err)
	}

	rTokenParams := database.AddRefreshTokenParams{
		Token:  refreshToken,
		UserID: user.ID,
	}

	cfg.DB.AddRefreshToken(ctx, rTokenParams)
	// Respond with user info and the token
	type loginResponse struct {
		ID           uuid.UUID `json:"id"`
		CreatedAt    time.Time `json:"created_at"`
		UpdatedAt    time.Time `json:"updated_at"`
		Email        string    `json:"email"`
		Token        string    `json:"token"`
		RefreshToken string    `json:"refresh_token"`
		IsChirpyRed  bool      `json:"is_chirpy_red"`
	}

	respondWithJSON(w, http.StatusOK, loginResponse{
		ID:           user.ID,
		CreatedAt:    user.CreatedAt,
		UpdatedAt:    user.UpdatedAt,
		Email:        user.Email,
		Token:        token,
		RefreshToken: refreshToken,
		IsChirpyRed:  user.IsChirpyRed.Bool,
	})
}

func (cfg *apiConfig) refreshToken(w http.ResponseWriter, r *http.Request) {

	bearer, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "missing or invalid Authorization header", nil)
		return
	}

	ctx := r.Context()

	token, err := cfg.DB.GetRefreshToken(ctx, bearer)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "could not get refresh token", err)
	}
	if token.ExpiresAt.Before(time.Now()) {
		respondWithError(w, http.StatusUnauthorized, "refresh token expired", nil)
		return
	}

	newToken, err := auth.MakeJWT(token.UserID, cfg.JWTSecret, time.Hour)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "could not create token", err)
		return
	}

	respondWithJSON(w, http.StatusOK, map[string]string{"token": newToken})
}

func (cfg *apiConfig) handleRevoke(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	bearer, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "missing or invalid Authorization header", nil)
		return
	}

	if err := cfg.DB.RevokeRefreshToken(ctx, bearer); err != nil {
		if err == sql.ErrNoRows {
			respondWithError(w, http.StatusNotFound, "refresh token not found", nil)
			return
		}
		respondWithError(w, http.StatusInternalServerError, "could not revoke refresh token", err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (cfg *apiConfig) handlePolkaWebhook(w http.ResponseWriter, r *http.Request) {
	// Validate API key first
	apiKey, err := auth.GetAPIKey(r.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "missing or invalid authorization header", nil)
		return
	}

	if apiKey != cfg.PolkaKey {
		respondWithError(w, http.StatusUnauthorized, "invalid api key", nil)
		return
	}

	type webhookData struct {
		UserID uuid.UUID `json:"user_id"`
	}

	type webhookRequest struct {
		Event string      `json:"event"`
		Data  webhookData `json:"data"`
	}

	decoder := json.NewDecoder(r.Body)
	params := webhookRequest{}
	if err := decoder.Decode(&params); err != nil {
		respondWithError(w, http.StatusBadRequest, "failed to decode request body", nil)
		return
	}

	// If event is not user.upgraded, respond with 204 and ignore
	if params.Event != "user.upgraded" {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// Update user to chirpy red status
	ctx := r.Context()
	err = cfg.DB.UpgradeUserToChirpyRed(ctx, params.Data.UserID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			respondWithError(w, http.StatusNotFound, "user not found", nil)
		} else {
			respondWithError(w, http.StatusInternalServerError, "could not upgrade user", err)
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("something went wrong, error: %s", err)
	}

	dbURL := os.Getenv("DB_URL")
	if dbURL == "" {
		log.Fatal("DB_URL environment variable is required")
	}

	jwtSecret := os.Getenv("TOKEN_SECRET")
	if jwtSecret == "" {
		log.Fatal("JWT_SECRET environment variable is required")
	}

	polkaKey := os.Getenv("POLKA_KEY")
	if polkaKey == "" {
		log.Fatal("POLKA_KEY environment variable is required")
	}
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatalf("Error opening database: %v", err)
	}

	err = db.Ping()
	if err != nil {
		log.Fatalf("Error connecting to database: %v", err)
	}

	dbQueries := database.New(db)

	// Create a new ServeMux
	mux := http.NewServeMux()
	cfg := apiConfig{
		DB:        dbQueries,
		DBConn:    db,
		JWTSecret: jwtSecret,
		PolkaKey:  polkaKey,
	}

	// Create a new http.Server struct
	server := &http.Server{
		Addr:    ":8080", // Set the address
		Handler: mux,     // Use the new ServeMux as the server's handler
	}

	mux.HandleFunc("GET /admin/metrics", cfg.handlerMetrics)
	mux.HandleFunc("POST /admin/reset", cfg.reset)
	mux.HandleFunc("GET /api/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")

		w.WriteHeader(http.StatusOK)

		_, err2 := w.Write([]byte("OK"))
		if err2 != nil {
			return
		}
	})

	appFs := http.FileServer(http.Dir("./app"))
	mux.Handle("/app/", cfg.middlewareMetricsInc(http.StripPrefix("/app/", appFs)))

	assetsFs := http.FileServer(http.Dir("./app/assets"))
	mux.Handle("/assets/", http.StripPrefix("/assets/", assetsFs))

	mux.HandleFunc("POST /api/users", cfg.handlerCreateUser)
	mux.HandleFunc("PUT /api/users", cfg.handlerUpdateUser)
	mux.HandleFunc("POST /api/chirps", cfg.handlerChirpsCreate)
	mux.HandleFunc("GET /api/chirps", cfg.getAllChirps)
	mux.HandleFunc("GET /api/chirps/{chirpID}", cfg.getChirpById)
	mux.HandleFunc("DELETE /api/chirps/{chirpID}", cfg.handlerDeleteChirp)
	mux.HandleFunc("POST /api/login", cfg.handleLogin)
	mux.HandleFunc("POST /api/refresh", cfg.refreshToken)
	mux.HandleFunc("POST /api/revoke", cfg.handleRevoke)
	mux.HandleFunc("POST /api/polka/webhooks", cfg.handlePolkaWebhook)

	// Use the server's ListenAndServe method to start the server
	fmt.Println("Server starting on http://localhost:8080")
	if err := server.ListenAndServe(); err != nil {
		fmt.Printf("Error starting server: %s\n", err)
	}

}
