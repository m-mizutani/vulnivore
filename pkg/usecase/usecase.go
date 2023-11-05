package usecase

import (
	_ "embed"
	"text/template"

	"github.com/m-mizutani/vulnivore/pkg/domain/interfaces"
	"github.com/m-mizutani/vulnivore/pkg/infra"
)

type useCase struct {
	clients              *infra.Clients
	sarifTemplate        *template.Template
	trivyOSPkgTemplate   *template.Template
	trivyLangPkgTemplate *template.Template
}

func New(clients *infra.Clients, options ...Option) interfaces.UseCase {
	uc := &useCase{
		clients:              clients,
		sarifTemplate:        defaultSarifTemplate,
		trivyOSPkgTemplate:   defaultTrivyOSPkgTemplate,
		trivyLangPkgTemplate: defaultTrivyLangPkgTemplate,
	}

	for _, opt := range options {
		opt(uc)
	}

	return uc
}

type Option func(*useCase)

//go:embed templates/sarif_github_issue_body.md
var sarifTemplate string

//go:embed templates/trivy_ospkg_body.md
var trivyOSPkgTemplate string

//go:embed templates/trivy_langpkg_body.md
var trivyLangPkgTemplate string

var (
	defaultSarifTemplate        *template.Template
	defaultTrivyOSPkgTemplate   *template.Template
	defaultTrivyLangPkgTemplate *template.Template
)

func init() {
	defaultSarifTemplate = template.Must(template.New("issue").Parse(sarifTemplate))
	defaultTrivyOSPkgTemplate = template.Must(template.New("issue").Parse(trivyOSPkgTemplate))
	defaultTrivyLangPkgTemplate = template.Must(template.New("issue").Parse(trivyLangPkgTemplate))
}

func WithSarifTemplate(tmpl *template.Template) Option {
	return func(c *useCase) {
		c.sarifTemplate = tmpl
	}
}

func WithTrivyOSPkgTemplate(tmpl *template.Template) Option {
	return func(c *useCase) {
		c.trivyOSPkgTemplate = tmpl
	}
}

func WithTrivyLangPkgTemplate(tmpl *template.Template) Option {
	return func(c *useCase) {
		c.trivyLangPkgTemplate = tmpl
	}
}
