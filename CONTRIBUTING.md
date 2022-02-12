# How to contribute

Hi! I'm really happy you want to help out with `hcltm`. At this early stage, the best way to get started is to [Submit an Issue](https://github.com/xntrik/hcltm/issues) or [Submit a PR](https://github.com/xntrik/hcltm/pulls).

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

Please send a [GitHub Pull Request to hcltm](https://github.com/xntrik/hcltm/pulls) with a clear list of what you've done (read more about [pull requests](http://help.github.com/pull-requests/)). When you send a pull request, we will love you forever if you include tests as well. We can always use more test coverage. Please follow our coding conventions (below) and make sure all of your commits are atomic (one feature per commit).

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

Thanks,
Christian @xntrik Frichot
