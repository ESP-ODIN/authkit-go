package authkit_test

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	authkit "github.com/ESP-ODIN/authkit-go"
	"github.com/google/uuid"
)

type createPostRequest struct {
	Content string `json:"content"`
}

type postService struct{}

func (postService) CreatePost(ctx context.Context, authorID uuid.UUID, request createPostRequest) error {
	// Connect the business service here: POST.author_id = authorID.
	return ctx.Err()
}

func Example() {
	authenticator, err := authkit.New(authkit.Config{
		JWKSURL:  os.Getenv("AUTH_JWKS_URL"),
		Issuer:   os.Getenv("AUTH_ISSUER"),
		Audience: os.Getenv("AUTH_AUDIENCE"),
	})
	if err != nil {
		log.Fatal(err)
	}
	posts := postService{}
	postHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity, ok := authkit.IdentityFromContext(r.Context())
		if !ok {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		var request createPostRequest
		if err := decoder.Decode(&request); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}
		if err := decoder.Decode(new(any)); err != io.EOF || request.Content == "" {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}
		if err := posts.CreatePost(r.Context(), identity.ID, request); err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusCreated)
	})
	mux := http.NewServeMux()
	mux.Handle("POST /api/v1/posts", authenticator.RequireAuth(postHandler))
	server := &http.Server{
		Addr: ":8080", Handler: mux, ReadHeaderTimeout: 5 * time.Second,
	}
	log.Fatal(server.ListenAndServe())
}
