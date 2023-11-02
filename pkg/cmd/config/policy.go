package config

import (
	"github.com/m-mizutani/vulnivore/pkg/domain/interfaces"
	"github.com/m-mizutani/vulnivore/pkg/infra/policy"
	"github.com/urfave/cli/v2"
)

type Policy struct {
	dir string
}

func (x *Policy) Flags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:        "policy-dir",
			Aliases:     []string{"p"},
			Value:       "./policy",
			Usage:       "Policy directory",
			EnvVars:     []string{"VULNIVORE_POLICY_DIR"},
			Destination: &x.dir,
		},
	}
}

func (x *Policy) NewPolicy() (interfaces.Policy, error) {
	return policy.New(policy.WithDir(x.dir))
}
