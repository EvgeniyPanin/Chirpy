package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/EvgeniyPanin/Chirpy/internal/database"
	"github.com/EvgeniyPanin/Chirpy/internal/database/auth"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

type User struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Email     string    `json:"email"`
	Token     string    `json:"token,omitempty"`
}

type Chirp struct {
	ID        uuid.UUID     `json:"id"`
	CreatedAt time.Time     `json:"created_at"`
	UpdatedAt time.Time     `json:"updated_at"`
	Body      string        `json:"body"`
	UserID    uuid.NullUUID `json:"user_id"`
}

type apiConfig struct {
	fileserverHits atomic.Int32
	dbQueries      *database.Queries
	platform       string
	jwtSecret      string
}

const DEFAULT_JWT_EXPIRATION_TIME = 3600

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

func (this *apiConfig) reset(w http.ResponseWriter, r *http.Request) {
	if this.platform != "dev" {
		respondWithError(w, http.StatusForbidden, fmt.Sprintf("Frobidden on the plstform %s", this.platform))
	}
	w.WriteHeader(http.StatusOK)
	this.fileserverHits.Store(0)
	err := this.dbQueries.DeleteUsers(r.Context())

	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Something went wrong")
	}
}

func (this *apiConfig) createUser(w http.ResponseWriter, r *http.Request) {
	type payload struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	d := json.NewDecoder(r.Body)
	params := payload{}
	err := d.Decode(&params)

	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Something went wrong")
		return
	}

	hashedPassword, err := auth.HashPassword(params.Password)

	if err != nil {
		http.Error(w, "Something went wrong", http.StatusBadRequest)
	}

	dbUser, err := this.dbQueries.CreateUser(
		r.Context(),
		database.CreateUserParams{Email: params.Email, HashedPassword: hashedPassword},
	)

	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't create user")
		return
	}

	respondWithJSON(w, http.StatusCreated, dbUserToUser(dbUser, ""))
}
func (this *apiConfig) login(w http.ResponseWriter, r *http.Request) {
	type payload struct {
		Email            string `json:"email"`
		Password         string `json:"password"`
		ExpiresInSeconds int    `json:"expires_in_seconds"`
	}

	d := json.NewDecoder(r.Body)
	params := payload{}
	err := d.Decode(&params)

	if err != nil {
		http.Error(w, "Incorrect email or password", http.StatusUnauthorized)
		return
	}

	if params.ExpiresInSeconds == 0 || params.ExpiresInSeconds > DEFAULT_JWT_EXPIRATION_TIME {
		params.ExpiresInSeconds = DEFAULT_JWT_EXPIRATION_TIME
	}

	dbUser, err := this.dbQueries.GetUser(r.Context(), params.Email)

	if err != nil {
		http.Error(w, "Incorrect email or password", http.StatusUnauthorized)
		return
	}

	ok, err := auth.CheckPasswordHash(params.Password, dbUser.HashedPassword)

	if err != nil || !ok {
		http.Error(w, "Incorrect email or password", http.StatusUnauthorized)
		return
	}

	token, err := auth.MakeJWT(dbUser.ID, this.jwtSecret, time.Duration(params.ExpiresInSeconds*int(time.Second)))

	if err != nil {
		http.Error(w, "Incorrect email or password", http.StatusUnauthorized)
		return
	}

	respondWithJSON(w, http.StatusOK, dbUserToUser(dbUser, token))
}

func (this *apiConfig) postChirp(w http.ResponseWriter, r *http.Request) {
	token, err := auth.GetBearerToken(r.Header)

	if err != nil {
		respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	userID, err := auth.ValidateJWT(token, this.jwtSecret)

	if err != nil {
		respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	type payload struct {
		Body string `json:"body"`
	}

	d := json.NewDecoder(r.Body)
	params := payload{}
	err = d.Decode(&params)

	if err != nil {
		respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	if len(params.Body) > 140 {
		respondWithError(w, http.StatusBadRequest, "Chirp is too long")
		return
	}

	dbChirp, err := this.dbQueries.CreateChirp(r.Context(), database.CreateChirpParams{Body: cleanPhrase(params.Body), UserID: uuid.NullUUID{UUID: userID, Valid: true}})

	if err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	respondWithJSON(w, http.StatusCreated, dbChirpToChirp(dbChirp))
}

func (this *apiConfig) listChirps(w http.ResponseWriter, r *http.Request) {
	dbChirps, err := this.dbQueries.ListChirps(r.Context())

	if err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	res := []Chirp{}

	for _, dbChirp := range dbChirps {
		res = append(res, dbChirpToChirp(dbChirp))
	}

	respondWithJSON(w, http.StatusOK, res)
}

func (this *apiConfig) getChirp(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("chirpID"))

	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	dbChirp, err := this.dbQueries.GetChirp(r.Context(), id)

	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	respondWithJSON(w, http.StatusOK, dbChirpToChirp(dbChirp))
}

func main() {
	godotenv.Load()

	dbURL := os.Getenv("DB_URL")
	db, err := sql.Open("postgres", dbURL)

	if err != nil {
		log.Fatal("Couldn't connect to database", err)
	}

	dbQueries := database.New(db)

	config := apiConfig{dbQueries: dbQueries, platform: os.Getenv("PLATFORM"), jwtSecret: os.Getenv("JWT_SECRET")}

	mux := http.NewServeMux()
	fs := http.FileServer(http.Dir("."))

	mux.Handle("/app/", http.StripPrefix("/app/", config.middlewareMetricsInc(fs)))

	mux.HandleFunc("GET /api/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	mux.HandleFunc("POST /api/users", http.HandlerFunc(config.createUser))
	mux.HandleFunc("POST /api/login", http.HandlerFunc(config.login))

	mux.HandleFunc("POST /api/chirps", http.HandlerFunc(config.postChirp))
	mux.HandleFunc("GET /api/chirps", http.HandlerFunc(config.listChirps))
	mux.HandleFunc("GET /api/chirps/{chirpID}", http.HandlerFunc(config.getChirp))

	mux.Handle("GET /admin/metrics", http.HandlerFunc(config.handleMetrics))
	mux.Handle("POST /admin/reset", http.HandlerFunc(config.reset))

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

func dbUserToUser(dbUser database.User, token string) User {
	return User{
		ID:        dbUser.ID,
		CreatedAt: dbUser.CreatedAt,
		UpdatedAt: dbUser.UpdatedAt,
		Email:     dbUser.Email,
		Token:     token,
	}
}

func dbChirpToChirp(dbChirp database.Chirp) Chirp {
	return Chirp{
		ID:        dbChirp.ID,
		CreatedAt: dbChirp.CreatedAt,
		UpdatedAt: dbChirp.UpdatedAt,
		Body:      dbChirp.Body,
		UserID:    dbChirp.UserID,
	}
}
