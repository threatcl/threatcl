# How to contribute

Hi! I'm really happy you want to help out with `threatcl`. At this early stage, the best way to get started is to [Submit an Issue](https://github.com/threatcl/threatcl/issues) or [Submit a PR](https://github.com/threatcl/threatcl/pulls).

I've been doing most of the work in the [dev](https://github.com/threatcl/threatcl/tree/dev) branch, and this is probably the best place to start looking at making changes.

## Testing

There are a bunch of `_test.go` files. To run the test suite:

```
$ make test
```

Alternatively, if you want to run `go vet` in addition to the `go test` run:

```
$ make testvet
```

To check test coverage, the `make testcover` will open up the generated coverage output in your browser.

## Submitting changes

Please send a [GitHub Pull Request to threatcl](https://github.com/threatcl/threatcl/pulls) with a clear list of what you've done (read more about [pull requests](http://help.github.com/pull-requests/)). When you send a pull request, we will love you forever if you include tests as well. We can always use more test coverage. Please follow our coding conventions (below) and make sure all of your commits are atomic (one feature per commit).

Always write a clear log message for your commits. One-line messages are fine for small changes, but bigger changes should look like this:

    $ git commit -m "fix: A brief summary of the commit
    > 
    > A paragraph describing what changed and its impact."

## Automatic Releases

Git commit messages will be auto-converted into Release change log text based on these prefixes:

```
feat = 'Features',
fix = 'Bug Fixes',
docs = 'Documentation',
style = 'Styles',
refactor = 'Code Refactoring',
perf = 'Performance Improvements',
test = 'Tests',
build = 'Builds',
ci = 'Continuous Integration',
chore = 'Chores',
revert = 'Reverts',
```

From https://github.com/marvinpinto/actions/blob/f2f409029c432b82229a4eacb8a313bc09abf48e/packages/automatic-releases/src/utils.ts#L38-L50

## Coding conventions

All Go code should be formatted according to https://pkg.go.dev/golang.org/x/tools/cmd/goimports. This can be validated by running:

```
$ make fmt
```

If it complains about missing `goimports`, run:

```
$ make bootstrap
```

## Releasing

All changes merged into the "main" branch will auto create a "Pre-release" https://github.com/threatcl/threatcl/releases

To release a new version:
* Update all the references to the version number to the new version, particularly the [version](version/version.go) file.
* Update the [CHANGELOG](CHANGELOG.md)
* Once the main branch has been merged and updated and all the [actions](https://github.com/threatcl/threatcl/actions) are complete - this is basically setup to release "dev" release (without docker)
* Once that's complete and you're ready to do the primary release, you tag
* `git tag -a vN.N.N -m 'vN.N.N'`
* `git tag -f latest`
* `git push --tags`
* This should then run a "threatcl release" action to release a new version, including amd64/arm64 docker images to ghcr.io
* Then don't forget to update https://github.com/threatcl/homebrew-repo
* And also https://github.com/threatcl/threatcl-action and https://github.com/threatcl/threatcl-action-example

Thanks,
Christian @xntrik Frichot
