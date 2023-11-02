package policy

import (
	"encoding/json"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/m-mizutani/goerr"
	"github.com/m-mizutani/vulnivore/pkg/domain/model"
	"github.com/m-mizutani/vulnivore/pkg/utils"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/topdown/print"
)

// Client is a policy engine client
type Client struct {
	dirs     []string
	files    []string
	policies map[string]string

	readFile readFile

	compiler *ast.Compiler
	query    string
	printer  RegoPrint
}

type RegoPrint func(ctx *model.Context, file string, row int, msg string) error
type readFile func(string) ([]byte, error)

// Option is a functional option for Client
type Option func(x *Client)

// WithDir specifies directory path of .rego policy. Import policy files recursively.
func WithDir(dirPath string) Option {
	return func(x *Client) {
		x.dirs = append(x.dirs, filepath.Clean(dirPath))
	}
}

// WithFile specifies file path of .rego policy. Import policy files recursively.
func WithFile(filePath string) Option {
	return func(x *Client) {
		x.files = append(x.files, filepath.Clean(filePath))
	}
}

// WithReadFile specifies file path of .rego policy. Import policy files recursively.
func WithReadFile(fn func(string) ([]byte, error)) Option {
	return func(x *Client) {
		x.readFile = fn
	}
}

// WithPolicyData specifies raw policy data with name. If the `name` conflicts with file path loaded by WithFile or WithDir, the policy overwrites data loaded by WithFile or WithDir.
func WithPolicyData(name, policy string) Option {
	return func(x *Client) {
		x.policies[name] = policy
	}
}

// WithPackage specifies using package name. e.g. "example.my_policy"
func WithPackage(pkg string) Option {
	return func(x *Client) {
		x.query = "data." + pkg
	}
}

// WithPrinter specifies callback function to print statement in policy. This is useful for debugging.
func WithPrinter(fn RegoPrint) Option {
	return func(x *Client) {
		x.printer = fn
	}
}

type regoPrintHook struct {
	callback func(ctx print.Context, msg string) error
	printer  RegoPrint
}

func (x *regoPrintHook) Print(ctx print.Context, msg string) error {
	return x.callback(ctx, msg)
}

// New creates a new Local client. It requires one or more WithFile, WithDir or WithPolicyData.
func New(options ...Option) (*Client, error) {
	client := &Client{
		query:    "data",
		policies: make(map[string]string),
		printer: func(ctx *model.Context, file string, row int, msg string) error {
			ctx.Logger().Info("[PRINT] "+msg, slog.Any("file", file), slog.Any("row", row))
			return nil
		},
	}
	for _, opt := range options {
		opt(client)
	}

	policies := make(map[string]string)
	var targetFiles []string

	for _, dirPath := range client.dirs {
		err := filepath.WalkDir(dirPath, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return goerr.Wrap(err, "Failed to walk directory").With("path", path)
			}
			if d.IsDir() {
				return nil
			}
			if filepath.Ext(path) != ".rego" {
				return nil
			}

			targetFiles = append(targetFiles, path)

			return nil
		})
		if err != nil {
			return nil, goerr.Wrap(err)
		}
	}
	targetFiles = append(targetFiles, client.files...)

	for _, filePath := range targetFiles {
		utils.Logger().Info("Loading policy file", "path", filePath)

		raw, err := os.ReadFile(filepath.Clean(filePath))
		if err != nil {
			return nil, goerr.Wrap(err, "Failed to read policy file").With("path", filePath)
		}

		policies[filePath] = string(raw)
	}

	for k, v := range client.policies {
		policies[k] = v
	}

	if len(policies) == 0 {
		return client, nil
	}

	compiler, err := ast.CompileModulesWithOpt(policies, ast.CompileOpts{
		EnablePrintStatements: true,
	})
	if err != nil {
		return nil, goerr.Wrap(err)
	}
	client.compiler = compiler

	return client, nil
}

// Query evaluates policy with `input` data. The result will be written to `out`. `out` must be pointer of instance.
func (x *Client) Query(ctx *model.Context, query string, input any, output any) error {
	if x.compiler == nil {
		return nil // No policy
	}

	regoOpt := []func(r *rego.Rego){
		rego.Query(strings.Join([]string{x.query, query}, ".")),
		rego.Compiler(x.compiler),
		rego.Input(input),
		rego.PrintHook(&regoPrintHook{
			callback: func(regoCtx print.Context, msg string) error {
				return x.printer(ctx, regoCtx.Location.File, regoCtx.Location.Row, msg)
			},
			printer: x.printer,
		}),
	}

	rs, err := rego.New(regoOpt...).Eval(ctx)
	if err != nil {
		return goerr.Wrap(err, "fail to eval local policy").With("input", input)
	}
	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return goerr.Wrap(model.ErrNoPolicyResult)
	}

	raw, err := json.Marshal(rs[0].Expressions[0].Value)
	if err != nil {
		return goerr.Wrap(err, "fail to marshal a result of rego.Eval").With("rs", rs)
	}
	if err := json.Unmarshal(raw, output); err != nil {
		return goerr.Wrap(err, "fail to unmarshal a result of rego.Eval to out").With("rs", rs)
	}

	return nil
}
