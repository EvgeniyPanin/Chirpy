package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync/atomic"

	"github.com/EvgeniyPanin/Chirpy/internal/database"
	_ "github.com/lib/pq"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	dbQueries      *database.Queries
}

func (this *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		this.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

func (this *apiConfig) handleMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "<html><body><h1>Welcome, Chirpy Admin</h1><p>Chirpy has been visited %d times!</p></body></html>", this.fileserverHits.Load())
}

func (this *apiConfig) resetMetrics(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	this.fileserverHits.Store(0)
}

func main() {
	dbURL := os.Getenv("DB_URL")
	db, _ := sql.Open("postgres", dbURL)
	dbQueries := database.New(db)

	config := apiConfig{dbQueries: dbQueries}

	mux := http.NewServeMux()
	fs := http.FileServer(http.Dir("."))

	mux.Handle("/app/", http.StripPrefix("/app/", config.middlewareMetricsInc(fs)))

	mux.HandleFunc("GET /api/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	mux.HandleFunc("POST /api/validate_chirp", func(w http.ResponseWriter, r *http.Request) {
		type payload struct {
			Body string `json:"body"`
		}

		d := json.NewDecoder(r.Body)
		params := payload{}
		err := d.Decode(&params)

		if err != nil {
			respondWithError(w, http.StatusInternalServerError, "Something went wrong")
			return
		}

		if len(params.Body) > 140 {
			respondWithError(w, http.StatusBadRequest, "Chirp is too long")
			return
		}

		respondWithJSON(w, http.StatusOK, map[string]string{"cleaned_body": cleanPhrase(params.Body)})
	})

	mux.Handle("GET /admin/metrics", http.HandlerFunc(config.handleMetrics))
	mux.Handle("POST /admin/reset", http.HandlerFunc(config.resetMetrics))

	http.ListenAndServe(":8080", mux)
}

func respondWithError(w http.ResponseWriter, code int, msg string) error {
	return respondWithJSON(w, code, map[string]string{"error": msg})
}

func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) error {
	response, err := json.Marshal(payload)

	if err != nil {
		return err
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(response)

	return nil
}

func cleanPhrase(s string) string {
	badWords := []string{"kerfuffle", "sharbert", "fornax"}
	res := []string{}

	for _, str := range strings.Split(s, " ") {
		if slices.Contains(badWords, strings.ToLower(str)) {
			res = append(res, "****")
		} else {
			res = append(res, str)
		}
	}

	return strings.Join(res, " ")
}
