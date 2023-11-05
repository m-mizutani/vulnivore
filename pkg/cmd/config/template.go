package config

import (
	"text/template"

	"github.com/m-mizutani/goerr"
	"github.com/m-mizutani/vulnivore/pkg/usecase"
	"github.com/urfave/cli/v2"
)

type TemplateConfig struct {
	sarifPath        string
	trivyOSPkgPath   string
	trivyLangPkgPath string
}

func (x *TemplateConfig) Flags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:        "sarif-template",
			Category:    "Template",
			Usage:       "Path to SARIF file",
			EnvVars:     []string{"VULNIVORE_SARIF_TEMPLATE"},
			Destination: &x.sarifPath,
		},
		&cli.StringFlag{
			Name:        "trivy-ospkg-path",
			Category:    "Template",
			Usage:       "Path to Trivy OS package file",
			EnvVars:     []string{"VULNIVORE_TRIVY_OSPKG_TEMPLATE"},
			Destination: &x.trivyOSPkgPath,
		},
		&cli.StringFlag{
			Name:        "trivy-langpkg-path",
			Category:    "Template",
			Usage:       "Path to Trivy language package file",
			EnvVars:     []string{"VULNIVORE_TRIVY_LANGPKG_TEMPLATE"},
			Destination: &x.trivyLangPkgPath,
		},
	}
}

func (x *TemplateConfig) New() ([]usecase.Option, error) {
	var resp []usecase.Option
	if x.sarifPath != "" {
		tmpl, err := template.ParseFiles(x.sarifPath)
		if err != nil {
			return nil, goerr.Wrap(err, "Failed to load SARIF template")
		}
		resp = append(resp, usecase.WithSarifTemplate(tmpl))
	}

	if x.trivyOSPkgPath != "" {
		tmpl, err := template.ParseFiles(x.trivyOSPkgPath)
		if err != nil {
			return nil, goerr.Wrap(err, "Failed to load Trivy OS package template")
		}
		resp = append(resp, usecase.WithTrivyOSPkgTemplate(tmpl))
	}

	if x.trivyLangPkgPath != "" {
		tmpl, err := template.ParseFiles(x.trivyLangPkgPath)
		if err != nil {
			return nil, goerr.Wrap(err, "Failed to load Trivy language package template")
		}
		resp = append(resp, usecase.WithTrivyLangPkgTemplate(tmpl))
	}

	return resp, nil
}
