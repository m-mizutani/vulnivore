package server

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/m-mizutani/vulsink/pkg/domain/interfaces"
	"github.com/m-mizutani/vulsink/pkg/utils"
)

type Server struct {
	mux *chi.Mux
}

type apiResponse struct {
	data any
}

type apiHandler func(uc interfaces.UseCase, req *http.Request) (*apiResponse, error)

func New(uc interfaces.UseCase) *Server {
	api := func(hdlr apiHandler) http.HandlerFunc {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			resp, err := hdlr(uc, r)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				utils.SafeMarshal(w, err)
			}

			w.WriteHeader(http.StatusOK)
			utils.SafeMarshal(w, resp)
		})
	}

	route := chi.NewRouter()
	route.Use(accessLogger)
	route.Route("/health", func(r chi.Router) {
		r.Get("/hello", api(hello))
	})

	return &Server{
		mux: route,
	}
}

func (x *Server) Handler() http.Handler {
	return x.mux
}
