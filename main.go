package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
)

type apiConfig struct {
	fileserverHits atomic.Int32
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)

		next.ServeHTTP(w, r)
	})
}

func (cfg *apiConfig) handlerMetrics(w http.ResponseWriter, r *http.Request) {
	hits := cfg.fileserverHits.Load()

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	fmt.Fprintf(w, `
<html>
<body>
    <h1>Welcome, Chirpy Admin</h1>
    <p>Chirpy has been visited %d times!</p>
</body>
</html>`, hits)
}

func (cfg *apiConfig) reset(w http.ResponseWriter, r *http.Request) {
	cfg.fileserverHits.Swap(0)
}

func cleanChirp(body string) string {
	profaneWords := map[string]bool{
		"kerfuffle": true,
		"sharbert":  true,
		"fornax":    true,
	}

	words := strings.Split(body, " ")

	for i, word := range words {
		lowerWord := strings.ToLower(word)
		if profaneWords[lowerWord] {
			words[i] = "****"
		}
	}

	return strings.Join(words, " ")
}

func handlerChirpsValidate(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Body string `json:"body"`
	}
	type returnVals struct {
		CleanedBody string `json:"cleaned_body"`
	}

	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Something went wrong", nil)
		return
	}

	const maxChirpLength = 140
	if len(params.Body) > maxChirpLength {
		respondWithError(w, http.StatusBadRequest, "Chirp is too long", nil)
		return
	}

	// Clean the chirp body by replacing profane words
	cleanedBody := cleanChirp(params.Body)

	// Return cleaned version in JSON
	respondWithJSON(w, http.StatusOK, returnVals{
		CleanedBody: cleanedBody,
	})
}

func main() {
	// Create a new ServeMux
	mux := http.NewServeMux()
	cfg := apiConfig{}

	// Create a new http.Server struct
	server := &http.Server{
		Addr:    ":8080", // Set the address
		Handler: mux,     // Use the new ServeMux as the server's handler
	}

	mux.HandleFunc("GET /admin/metrics", cfg.handlerMetrics)
	mux.HandleFunc("POST /admin/reset", cfg.reset)
	mux.HandleFunc("GET /api/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")

		w.WriteHeader(http.StatusOK)

		w.Write([]byte("OK"))
	})

	appFs := http.FileServer(http.Dir("./app"))
	mux.Handle("/app/", cfg.middlewareMetricsInc(http.StripPrefix("/app/", appFs)))

	assetsFs := http.FileServer(http.Dir("./app/assets"))
	mux.Handle("/assets/", http.StripPrefix("/assets/", assetsFs))

	mux.HandleFunc("POST /api/validate_chirp", handlerChirpsValidate)

	// Use the server's ListenAndServe method to start the server
	fmt.Println("Server starting on http://localhost:8080")
	if err := server.ListenAndServe(); err != nil {
		fmt.Printf("Error starting server: %s\n", err)
	}

}

/*
Assignment
We need to update the /api/validate_chirp endpoint to replace all "profane" words with 4 asterisks: ****.

Assuming the length validation passed, replace any of the following words in the Chirp with the static 4-character string ****:

kerfuffle
sharbert
fornax
Be sure to match against uppercase versions of the words as well, but not punctuation. "Sharbert!" does not need to be replaced, we'll consider it a different word due to the exclamation point. Finally, instead of the valid boolean, your handler should return the cleaned version of the text in a JSON response:

Example Input
{
  "body": "This is a kerfuffle opinion I need to share with the world"
}

Example Output
{
  "cleaned_body": "This is a **** opinion I need to share with the world"
}

Run and submit the CLI tests.

Tips
Use an HTTP client to test your POST requests.

I'd recommend creating two helper functions:

respondWithError(w http.ResponseWriter, code int, msg string)
respondWithJSON(w http.ResponseWriter, code int, payload interface{})
These helpers are not required but might help DRY up your code when we add more endpoints in the future.

I'd also recommend breaking the bad word replacement into a separate function. You can even write some unit tests for it!

Here are some useful standard library functions:

strings.ToLower
strings.Split
strings.Join


*/
