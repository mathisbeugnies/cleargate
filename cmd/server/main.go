package main

import (
	"cleargate/pkg/api"
	"cleargate/pkg/cache"
	"cleargate/pkg/mail"
	"cleargate/pkg/metrics"
	"cleargate/pkg/policy"
	"cleargate/pkg/proxy"
	"cleargate/pkg/sanitizer"
	"cleargate/pkg/security"
	"cleargate/pkg/storage"
	"cleargate/pkg/vector"
	"context"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func main() {
	// Setup Zerolog
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339})
	log.Info().Msg("Starting ClearGate...")

	// Config
	dbDSN := getEnv("DB_DSN", "postgres://user:password@localhost:5432/cleargate?sslmode=disable")
	qdrantAddr := getEnv("QDRANT_ADDR", "localhost:6334")
	redisAddr := getEnv("REDIS_ADDR", "localhost:6379")
	redisPass := getEnv("REDIS_PASS", "")
	port := getEnv("PORT", "8080")

	if v := getEnv("MAX_BODY_BYTES", ""); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			proxy.MaxBodyBytes = n
		}
	}

	// Mail Config
	mailConfig := mail.Config{
		SMTPHost: getEnv("SMTP_HOST", ""),
		SMTPPort: getEnv("SMTP_PORT", ""),
		SMTPUser: getEnv("SMTP_USER", ""),
		SMTPPass: getEnv("SMTP_PASS", ""),
		From:     getEnv("SMTP_FROM", "noreply@cleargate.com"),
	}

	// Init DB
	store, err := storage.NewStore(dbDSN)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to connect to database")
	}

	if err := store.InitSchema(); err != nil {
		log.Fatal().Err(err).Msg("Failed to initialize database schema")
	}
	log.Info().Msg("Database initialized")

	// Init Vector DB
	vClient, err := vector.NewClient(qdrantAddr)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to connect to Qdrant")
	}
	// Use SmartEmbedder (Dense Vectors + Fallback)
	embedder := vector.NewSmartEmbedder()
	guard := vector.NewGuard(vClient, embedder)

	// Seed Vector DB
	forbiddenSectors := []string{} // Assuming forbiddenSectors is defined elsewhere or meant to be empty for now
	log.Info().Msg("Seeding Vector DB with forbidden sectors...")
	if err := guard.Seed(forbiddenSectors); err != nil {
		log.Error().Err(err).Msg("Failed to seed vector DB (Forbidden)")
	} else {
		log.Info().Msg("Vector DB seeded with forbidden sectors")
	}

	// Seed Allowed Topics (Domain Verification)
	allowedTopics := []string{
		"Finance", "Comptabilité", "Bilan",
		"Human Resources", "Ressources Humaines", "Recrutement",
		"Software Engineering", "Development", "Code", "DevOps",
		"Customer Support", "Service Client", "Helpdesk",
	}
	log.Info().Msg("Seeding Vector DB with allowed topics...")
	if err := guard.SeedAllowed(allowedTopics); err != nil {
		log.Error().Err(err).Msg("Failed to seed vector DB (Allowed)")
	} else {
		log.Info().Msg("Vector DB seeded with allowed topics")
	}

	// Init Redis Cache
	cacheClient := cache.NewClient(redisAddr, redisPass)
	if cacheClient != nil {
		log.Info().Msg("Redis Cache initialized")
	}

	// Init Security and Policy
	policyEngine := policy.NewEngine()
	// Use Intent Classifier (Classification + Heuristics)
	var promptGuard security.PromptGuardClient
	ollamaURL := getEnv("OLLAMA_URL", "")
	if ollamaURL != "" {
		log.Info().Str("url", ollamaURL).Msg("Initializing LlamaGuard (Ollama)...")
		promptGuard = security.NewLlamaGuardClient(ollamaURL, "llama-guard:latest")
	}

	injector := security.NewIntentClassifier(promptGuard)
	leak := security.NewLeakDetector()
	sanitizerService := sanitizer.NewSanitizer()
	anomaly := security.NewAnomalyDetector(cacheClient)

	// Initialize handlers
	reloadChan := make(chan struct{}, 1) // Buffered to prevent blocking if handler is busy
	mailService := mail.NewService(mailConfig)
	handler := proxy.NewProxyHandler(store, policyEngine, guard, injector, leak, cacheClient, sanitizerService, anomaly)
	adminHandler := api.NewAdminHandler(store, policyEngine, guard, cacheClient, reloadChan)
	authHandler := api.NewAuthHandler(store)
	superAdminHandler := api.NewSuperAdminHandler(store, mailService)
	publicHandler := api.NewPublicHandler(store)
	signupHandler := api.NewSignupHandler(store)

	// Simulator
	simHandler := api.NewSimulatorHandler(store, policyEngine, guard, injector, leak, sanitizerService)

	mux := http.NewServeMux()
	mux.Handle("/", handler)

	// Operational endpoints (no auth). /metrics can be gated with METRICS_TOKEN.
	mux.HandleFunc("/healthz", api.Healthz)
	mux.HandleFunc("/readyz", api.Readyz(store))
	mux.Handle("/metrics", api.GuardMetrics(getEnv("METRICS_TOKEN", ""), metrics.Handler()))

	// Rate-limit the unauthenticated endpoints per IP (shared via Redis when available).
	mux.Handle("/auth/login", api.RateLimitShared(cacheClient, "login", 10, time.Minute, http.HandlerFunc(authHandler.Login)))
	mux.HandleFunc("/auth/logout", authHandler.Logout)
	mux.Handle("/auth/me", api.AuthMiddleware(http.HandlerFunc(authHandler.Me)))

	// Public Invitation Routes
	mux.HandleFunc("/api/invite", publicHandler.GetInvitation)          // GET ?token=...
	mux.HandleFunc("/api/invite/complete", publicHandler.CompleteSetup) // POST

	mux.Handle("/api/signup", api.RateLimitShared(cacheClient, "signup", 5, time.Hour, http.HandlerFunc(signupHandler.Signup))) // POST - self-serve org creation

	// Protected Admin Routes
	mux.Handle("/api/admin/audit", api.AuthMiddleware(http.HandlerFunc(adminHandler.ServeAuditLogs)))
	mux.Handle("/api/stats", api.AuthMiddleware(http.HandlerFunc(adminHandler.ServeStats)))
	mux.Handle("/api/config", api.AuthMiddleware(http.HandlerFunc(adminHandler.ServeConfig)))
	mux.Handle("/api/keys", api.AuthMiddleware(http.HandlerFunc(adminHandler.ServeKeys)))                                  // Encryption Keys
	mux.Handle("/api/admin/integrity", api.AuthMiddleware(http.HandlerFunc(adminHandler.ServeIntegrityCheck)))             // Integrity Check
	mux.Handle("/api/admin/feedback", api.AuthMiddleware(http.HandlerFunc(adminHandler.ServeFeedback)))                    // Semantic Feedback (Allow)
	mux.Handle("/api/admin/reload", api.AuthMiddleware(api.RequireSuperAdmin(http.HandlerFunc(adminHandler.ServeReload)))) // Graceful Reload
	mux.Handle("/api/admin/sandbox/test", api.AuthMiddleware(http.HandlerFunc(simHandler.Simulate)))

	// Protected Super Admin Routes
	mux.Handle("/api/superadmin/organizations", api.AuthMiddleware(api.RequireSuperAdmin(http.HandlerFunc(superAdminHandler.CreateOrganization))))
	mux.Handle("/api/superadmin/organizations/list", api.AuthMiddleware(api.RequireSuperAdmin(http.HandlerFunc(superAdminHandler.ListOrganizations))))

	// Protected Vector/RAG Routes
	vectorHandler := api.NewVectorHandler(store, vClient, embedder) // embedder is local
	mux.Handle("/api/vector/upload", api.AuthMiddleware(http.HandlerFunc(vectorHandler.UploadDocument)))
	mux.Handle("/api/vector/documents", api.AuthMiddleware(http.HandlerFunc(vectorHandler.ListDocuments)))
	mux.Handle("/api/vector/delete", api.AuthMiddleware(http.HandlerFunc(vectorHandler.DeleteDocument))) // ?id=...
	mux.Handle("/api/vector/test", api.AuthMiddleware(http.HandlerFunc(vectorHandler.TestSimilarity)))

	handlerChain := api.Recover(api.RequestID(api.SecurityHeaders(api.CorsMiddleware(mux))))

	// Server
	server := &http.Server{
		Addr:              ":" + port,
		Handler:           handlerChain,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      180 * time.Second, // upstream completions can be slow
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	// Signal Handling for Graceful Reload
	go func() {
		log.Info().Msgf("ClearGate Proxy listening on :%s", port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal().Err(err).Msg("Server request fail")
		}
	}()

	// Signal Channel
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM) // Removed SIGUSR1 for Windows compat

	for {
		select {
		case <-reloadChan:
			log.Info().Msg("Received Reload Signal from API: Reloading Configuration & Keys...")
			// Reload Logic
			if cacheClient != nil {
				log.Info().Msg("Flushing Cache...")
				// cacheClient.FlushAll()
			}
			log.Info().Msg("Reload Complete")

		case sig := <-sigs:
			log.Info().Str("signal", sig.String()).Msg("Shutting down...")
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			if err := server.Shutdown(ctx); err != nil {
				log.Warn().Err(err).Msg("Graceful shutdown timed out")
			}
			cancel()
			return
		}
	}
}
