package api

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	httpSwagger "github.com/swaggo/http-swagger"

	"github.com/theopenlane/sleuth/internal/cloudflare"
	"github.com/theopenlane/sleuth/internal/intel"
	"github.com/theopenlane/sleuth/internal/scanner"
	"github.com/theopenlane/sleuth/internal/slack"

	// Import generated specs
	_ "github.com/theopenlane/sleuth/specs"
)

// compressLevel controls the gzip compression level for responses
const compressLevel = 5

// RouterConfig holds the dependencies for creating a new API router.
type RouterConfig struct {
	// Scanner performs domain security analysis.
	Scanner scanner.Interface
	// IntelManager provides threat intelligence scoring.
	IntelManager *intel.Manager
	// Enricher provides domain enrichment via Cloudflare.
	Enricher *cloudflare.Client
	// Notifier sends notifications to Slack.
	Notifier *slack.Client
	// MaxBodySize limits the size of incoming request bodies.
	MaxBodySize int64
	// ScanTimeout is the maximum duration for a scan operation.
	ScanTimeout time.Duration
}

// NewRouter creates a new chi router with all endpoints and middleware
func NewRouter(cfg RouterConfig) http.Handler {
	h := &Handler{
		scanner:     cfg.Scanner,
		intel:       cfg.IntelManager,
		enricher:    cfg.Enricher,
		notifier:    cfg.Notifier,
		maxBodySize: cfg.MaxBodySize,
		scanTimeout: cfg.ScanTimeout,
	}

	r := chi.NewRouter()

	// Middleware
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Compress(compressLevel))
	r.Use(middleware.Timeout(cfg.ScanTimeout + 10*time.Second)) // scan timeout + buffer
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
		r.Post("/enrich", h.handleEnrich)

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

	// OpenAPI spec files
	r.Get("/api-docs/swagger.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		http.ServeFile(w, r, "specs/swagger.json")
	})
	r.Get("/api-docs/swagger.yaml", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-yaml")
		http.ServeFile(w, r, "specs/swagger.yaml")
	})

	// Redirect root to UI
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/ui", http.StatusFound)
	})

	return r
}
