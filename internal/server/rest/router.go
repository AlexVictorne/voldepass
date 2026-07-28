package rest

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/rs/zerolog"
	httpSwagger "github.com/swaggo/http-swagger/v2"

	_ "github.com/alexvictorne/voldepass/api/openapi" // регистрирует сгенерированную swagger-спецификацию
	"github.com/alexvictorne/voldepass/internal/server/service"
)

// NewRouter собирает chi-роутер со всеми маршрутами Voldepass API.
// jwt используется для AuthMiddleware на защищённых маршрутах.
// corsAllowedOrigins — разрешённые Origin для CORS (см. config.Config.CORSAllowedOrigins);
// пустой список отключает CORS-заголовки (браузерные клиенты не смогут делать запросы
// с других origin — нормально для CLI/TUI-клиентов, не затрагивающих браузер).
// log используется RequestLogger для структурного логирования каждого запроса.
// loginAttempts используется LoginRateLimit-middleware на /login, чтобы отклонять
// превысившие лимит запросы транспортным слоем, не доходя до AuthService.Login.
func NewRouter(auth *AuthHandlers, vault *VaultHandlers, sync *SyncHandlers, jwt jwtParser, corsAllowedOrigins []string, log zerolog.Logger, loginAttempts service.LoginAttemptTracker) http.Handler {
	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.Recoverer)
	r.Use(RequestLogger(log))
	if len(corsAllowedOrigins) > 0 {
		r.Use(cors.Handler(cors.Options{
			AllowedOrigins:   corsAllowedOrigins,
			AllowedMethods:   []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete},
			AllowedHeaders:   []string{"Content-Type", "Authorization", "Idempotency-Key", "X-API-Version"},
			AllowCredentials: false,
			MaxAge:           300,
		}))
	}
	r.Use(CheckAPIVersion)

	// Swagger UI: смотреть контракт API на GET /swagger/index.html.
	r.Get("/swagger/*", httpSwagger.WrapHandler)

	r.Route("/api/v1", func(r chi.Router) {
		// Публичные маршруты (не требуют access-токена).
		r.Post("/register", auth.Register)
		r.Post("/login/challenge", auth.Challenge)
		r.With(LoginRateLimit(loginAttempts, log)).Post("/login", auth.Login)
		r.Post("/refresh", auth.Refresh)

		// Защищённые маршруты.
		r.Group(func(r chi.Router) {
			r.Use(AuthMiddleware(jwt, log))

			r.Route("/records", func(r chi.Router) {
				r.Post("/", vault.Create)
				r.Get("/", vault.List)
				r.Get("/{id}", vault.Get)
				r.Put("/{id}", vault.Update)
				r.Delete("/{id}", vault.Delete)
			})

			r.Route("/sync", func(r chi.Router) {
				r.Get("/", sync.Pull)
				r.Post("/", sync.Push)
			})
		})
	})

	return r
}
