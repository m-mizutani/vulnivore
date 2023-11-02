package model

import "github.com/m-mizutani/goerr"

var (
	// setup error
	ErrInvalidConfig = goerr.New("invalid config")

	// runtime error
	ErrInvalidGitHubIDToken = goerr.New("invalid GitHub ID token")
	ErrInvalidContext       = goerr.New("invalid context")

	ErrNoPolicyResult = goerr.New("no policy result")
)
