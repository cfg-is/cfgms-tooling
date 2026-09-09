// Planted-vulnerability fixture for the security-review scanner profiles
// (Issue #3982). Its own module so `go build ./...` from the repository root
// never compiles it (a dot-directory is not a package of the main module)
// while the Go profile can still run gosec/staticcheck from this module root.
module cfgms-scan-fixture

go 1.24
