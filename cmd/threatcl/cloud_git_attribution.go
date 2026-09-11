package main

import (
	"errors"
	"flag"
	"fmt"
	"net/mail"
	"regexp"
	"strings"
)

// Git-author attribution on an upload is billing metadata: paid Threatcl
// Cloud plans count contributors (distinct identities that pushed a change),
// and without these fields the server attributes a push to the token's
// owner. An entire team pushing through one CI token then counts as a single
// contributor. The CLI therefore lets a push name the human who actually
// authored the change.
//
// The values are only ever taken from an explicit flag or environment
// variable - never read out of the local git repo behind the user's back,
// because attribution decides who is billed.

// Environment variables the attribution fields fall back to when the
// matching flag is not given.
const (
	envGitAuthorName  = "THREATCL_GIT_AUTHOR_NAME"
	envGitAuthorEmail = "THREATCL_GIT_AUTHOR_EMAIL"
	envGitCommitSHA   = "THREATCL_GIT_COMMIT_SHA"
)

// Server-side field bounds, mirrored here so a bad value fails locally with
// a clear message instead of a 400 invalid_git_attribution from the API.
const (
	maxGitAuthorNameLen  = 255
	maxGitAuthorEmailLen = 254
)

// gitCommitSHAPattern accepts an abbreviated or full hex commit id.
var gitCommitSHAPattern = regexp.MustCompile(`^[0-9a-fA-F]{7,64}$`)

// gitAttribution is the optional attribution sent with an upload: who
// authored the change, as opposed to whose credential pushed it. A zero
// value sends nothing.
type gitAttribution struct {
	Name      string
	Email     string
	CommitSHA string
}

// Supplied reports whether any attribution field is set.
func (g gitAttribution) Supplied() bool {
	return g.Name != "" || g.Email != "" || g.CommitSHA != ""
}

// gitAttributionFlags holds the raw flag values a command collects; resolve
// merges them with the environment and validates the result. Commands that
// hit the upload endpoint embed one and register its flags.
type gitAttributionFlags struct {
	name  string
	email string
	sha   string
}

// addFlags registers the attribution flags on a command's flag set.
func (f *gitAttributionFlags) addFlags(flagSet *flag.FlagSet) {
	flagSet.StringVar(&f.name, "git-author-name", "", "Git author name to attribute this change to")
	flagSet.StringVar(&f.email, "git-author-email", "", "Git author email to attribute this change to")
	flagSet.StringVar(&f.sha, "git-commit-sha", "", "Git commit SHA this change corresponds to")
}

// resolve builds the attribution to send: each flag wins over its
// environment variable, then the whole is normalized and validated. A
// resolved attribution with nothing supplied is the zero value.
func (f *gitAttributionFlags) resolve(fsSvc FileSystemService) (gitAttribution, error) {
	pick := func(flagValue, envKey string) string {
		if flagValue != "" {
			return flagValue
		}
		return fsSvc.Getenv(envKey)
	}
	return normalizeGitAttribution(gitAttribution{
		Name:      pick(f.name, envGitAuthorName),
		Email:     pick(f.email, envGitAuthorEmail),
		CommitSHA: pick(f.sha, envGitCommitSHA),
	})
}

// normalizeGitAttribution trims the fields, reduces the email to a bare
// address and applies the server's validation rules, so the user gets a
// clear local error rather than a 400.
//
// The server only accepts a bare address (`jane@example.com`), but the
// display-name form (`Jane <jane@example.com>`) is what `git log --format=%an
// <%ae>` and most CI contexts hand out, so it is accepted here and stripped:
// the address is sent as the email, and its display name fills the author
// name when no name was given separately. No-reply and forge privacy
// addresses (e.g. users.noreply.github.com) are ordinary valid addresses and
// pass through untouched.
func normalizeGitAttribution(g gitAttribution) (gitAttribution, error) {
	g.Name = strings.TrimSpace(g.Name)
	g.Email = strings.TrimSpace(g.Email)
	g.CommitSHA = strings.TrimSpace(g.CommitSHA)

	if !g.Supplied() {
		return gitAttribution{}, nil
	}
	if g.Email == "" {
		return gitAttribution{}, fmt.Errorf("-git-author-email (or %s) is required when git author attribution is supplied", envGitAuthorEmail)
	}

	addr, err := mail.ParseAddress(g.Email)
	if err != nil {
		return gitAttribution{}, fmt.Errorf("invalid git author email %q: expected an address such as jane@example.com", g.Email)
	}
	g.Email = addr.Address
	if g.Name == "" {
		g.Name = strings.TrimSpace(addr.Name)
	}

	if len(g.Email) > maxGitAuthorEmailLen {
		return gitAttribution{}, fmt.Errorf("git author email is too long (max %d characters)", maxGitAuthorEmailLen)
	}
	if len(g.Name) > maxGitAuthorNameLen {
		return gitAttribution{}, fmt.Errorf("git author name is too long (max %d characters)", maxGitAuthorNameLen)
	}
	if g.CommitSHA != "" && !gitCommitSHAPattern.MatchString(g.CommitSHA) {
		return gitAttribution{}, errors.New("invalid git commit SHA: must be 7 to 64 hexadecimal characters")
	}
	return g, nil
}

// cloudGitAttributionOptionsHelp is the "Options" text for the attribution
// flags, shared by the commands that upload a spec file. The caller places it
// inside its Options section.
func cloudGitAttributionOptionsHelp() string {
	return ` -git-author-email=<email>
   Attribute this change to the given git author rather than to the owner
   of the API token. Paid plans bill per contributor, so a team pushing
   through one shared CI token should set this (typically from the CI
   event's commit author) so each author is counted rather than the token
   owner. Required if any of the -git-* flags is given. A display-name form
   such as 'Jane <jane@example.com>' is accepted; the bare address is sent.
   Defaults to ` + envGitAuthorEmail + `.

 -git-author-name=<name>
   Git author name to record alongside -git-author-email. Defaults to
   ` + envGitAuthorName + `, then to the display name in -git-author-email.

 -git-commit-sha=<sha>
   Git commit SHA (7 to 64 hex characters) this change corresponds to.
   Defaults to ` + envGitCommitSHA + `.

   Attribution is never read from the local git repository: it is sent only
   when given explicitly by flag or environment variable.
`
}

// cloudGitAttributionEnvHelp is the "Environment Variables" text for the
// attribution fallbacks, appended after the standard cloud env var help.
func cloudGitAttributionEnvHelp() string {
	return `
 ` + envGitAuthorEmail + `, ` + envGitAuthorName + `, ` + envGitCommitSHA + `
   Defaults for -git-author-email, -git-author-name and -git-commit-sha.
   Convenient for CI, where the commit author is known from the event.
`
}
