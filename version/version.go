package version

import "runtime/debug"

// Version is the threatcl build version.
//
// Release builds are stamped by GoReleaser at link time via
//
//	-ldflags "-X github.com/threatcl/threatcl/version.Version=<tag>"
//
// so this "dev" default only applies to un-stamped builds (e.g. a plain
// `go build`). It must be a var (not a const) for -X to take effect.
var Version = "dev"

// GetVersion returns the build version. It prefers the link-time value injected
// by GoReleaser, then falls back to the module version embedded by the Go
// toolchain for `go install github.com/threatcl/threatcl/cmd/threatcl@vX.Y.Z`
// builds, and finally to the "dev" default.
func GetVersion() string {
	if Version != "dev" {
		return Version
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		if v := info.Main.Version; v != "" && v != "(devel)" {
			return v
		}
	}
	return Version
}
