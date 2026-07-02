package rest

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	httpSwagger "github.com/swaggo/http-swagger/v2"

	_ "github.com/alexvictorne/voldepass/api/openapi" // регистрирует сгенерированную swagger-спецификацию
)

// NewRouter собирает chi-роутер со всеми маршрутами Voldepass API.
// jwt используется для AuthMiddleware на защищённых маршрутах.
func NewRouter(auth *AuthHandlers, vault *VaultHandlers, sync *SyncHandlers, jwt jwtParser) http.Handler {
	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.Recoverer)
	r.Use(CheckAPIVersion)

	// Swagger UI: смотреть контракт API на GET /swagger/index.html.
	r.Get("/swagger/*", httpSwagger.WrapHandler)

	r.Route("/api/v1", func(r chi.Router) {
		// Публичные маршруты (не требуют access-токена).
		r.Post("/register", auth.Register)
		r.Post("/login/challenge", auth.Challenge)
		r.Post("/login", auth.Login)
		r.Post("/refresh", auth.Refresh)

		// Защищённые маршруты.
		r.Group(func(r chi.Router) {
			r.Use(AuthMiddleware(jwt))

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
