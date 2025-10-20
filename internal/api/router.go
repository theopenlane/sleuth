package api

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	httpSwagger "github.com/swaggo/http-swagger"

	"github.com/theopenlane/sleuth/internal/intel"
	"github.com/theopenlane/sleuth/internal/scanner"

	// Import generated docs
	_ "github.com/theopenlane/sleuth/docs"
)

// NewRouter creates a new chi router with all endpoints and middleware.
func NewRouter(s scanner.ScannerInterface, intelManager *intel.Manager, maxBodySize int64, scanTimeout time.Duration) http.Handler {
	h := &Handler{
		scanner:     s,
		intel:       intelManager,
		maxBodySize: maxBodySize,
		scanTimeout: scanTimeout,
	}

	r := chi.NewRouter()

	// Middleware
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Compress(5))
	r.Use(middleware.Timeout(scanTimeout + 10*time.Second)) // scan timeout + buffer
	r.Use(middleware.Heartbeat("/ping"))

	// CORS for browser access to Swagger UI
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Accept, Authorization, Content-Type, X-CSRF-Token")

			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusOK)
				return
			}

			next.ServeHTTP(w, r)
		})
	})

	// API routes
	r.Route("/api", func(r chi.Router) {
		r.Get("/health", h.handleHealth)
		r.Post("/scan", h.handleScan)

		r.Route("/intel", func(r chi.Router) {
			r.Post("/hydrate", h.handleIntelHydrate)
			r.Post("/check", h.handleIntelCheck)
		})
	})

	// UI routes
	r.Get("/ui", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "ui/index.html")
	})
	r.Handle("/ui/*", http.StripPrefix("/ui/", http.FileServer(http.Dir("ui"))))

	// Swagger documentation
	r.Get("/swagger/*", httpSwagger.Handler(
		httpSwagger.URL("/swagger/doc.json"),
	))

	// Redirect root to UI
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/ui", http.StatusFound)
	})

	return r
}
