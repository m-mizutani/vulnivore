package server

import (
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/m-mizutani/vulnivore/pkg/domain/interfaces"
	"github.com/m-mizutani/vulnivore/pkg/domain/model"
	"github.com/m-mizutani/vulnivore/pkg/utils"
)

type Server struct {
	mux *chi.Mux
}

type apiResponse struct {
	data any
}

type apiHandler func(ctx *model.Context, uc interfaces.UseCase, req *http.Request) (*apiResponse, error)

func New(uc interfaces.UseCase) *Server {
	api := func(hdlr apiHandler) http.HandlerFunc {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := toVulnivoreContext(r.Context())

			resp, err := hdlr(ctx, uc, r)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				utils.SafeMarshal(w, err)
				ctx.Logger().Error("handler error", slog.Any("err", err))
				return
			}

			w.WriteHeader(http.StatusOK)
			utils.SafeMarshal(w, resp.data)
		})
	}

	route := chi.NewRouter()
	route.Use(accessLogger)
	route.Route("/health", func(r chi.Router) {
		r.Get("/hello", api(hello))
	})

	route.Route("/webhook", func(r chi.Router) {
		r.Route("/github", func(r chi.Router) {
			r.Route("/action", func(r chi.Router) {
				r.Use(authGitHubAction(validateGitHubIDToken))
				r.Post("/sarif", api(recvGitHubActionSARIF))
				r.Post("/trivy", api(recvGitHubActionTrivy))
			})
			r.Route("/app", func(r chi.Router) {
				r.Post("/event", api(recvGitHubAppEvent))
			})
		})
	})

	return &Server{
		mux: route,
	}
}

func (x *Server) Handler() http.Handler {
	return x.mux
}
