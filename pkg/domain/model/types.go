package model

import "fmt"

// GitHub
type (
	GitHubRepoID       int64
	GitHubAppID        int64
	GitHubAppInstallID int64
	GitHubPrivateKey   string
	GitHubSecret       string
)

func (x GitHubRepoID) String() string     { return fmt.Sprintf("%d", x) }
func (x GitHubAppID) Int64() int64        { return int64(x) }
func (x GitHubAppInstallID) Int64() int64 { return int64(x) }
func (x GitHubPrivateKey) Byte() []byte   { return []byte(x) }
