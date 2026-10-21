# Contributing

Contributions are welcome: bug reports, fixes, tests and documentation.

## Developer Certificate of Origin

Every commit must be signed off under the
[Developer Certificate of Origin](https://developercertificate.org/), which
certifies that you wrote the change or otherwise have the right to submit it
under this project's licence. Sign off with:

```bash
git commit -s
```

This adds a line to the commit message:

```
Signed-off-by: Your Name <you@example.com>
```

The name and email must match the commit author. Pull requests with unsigned
commits cannot be merged. To sign off commits you have already made, use
`git rebase --signoff <base>`.

## Making a change

1. Open an issue first for anything beyond a small fix, so the approach can be
   agreed before you build it.
2. Keep each pull request to one change that could be reverted on its own.
3. Run `go build ./... && go vet ./... && go test ./...` and make sure it passes.
4. Add a test that would have failed before your change.

Changes to what the service verifies, stores or signs need particular care,
because other people's security rests on this service's receipts. Explain in
the pull request what the change guarantees and what it does not.

Report security issues privately, as described in [SECURITY.md](SECURITY.md),
not in a pull request.

## Licence

By contributing you agree that your contribution is licensed under the
[Apache License 2.0](LICENSE).
