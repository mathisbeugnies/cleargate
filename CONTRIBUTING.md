# Contributing

Bug reports, detection-rule improvements, tests, and docs are all welcome.

## Development setup

Backend (Go 1.26+):

```bash
go build ./...
go vet ./...
go test ./...
go run ./cmd/server
```

Dashboard (Node 18+):

```bash
cd dashboard
npm install
npm run dev      # http://localhost:5173
npm run build
```

Full stack:

```bash
docker compose up -d   # proxy on :8080, plus Postgres, Redis, Qdrant
```

## Pull requests

- Branch off `main`, one change per PR.
- Run `go build ./...`, `go vet ./...`, and `npm run build` before pushing.
- Match the surrounding code style.
- For a new detection heuristic, include an example prompt it catches and one
  it should not flag.

## Security issues

Please don't open a public issue for a vulnerability. See [SECURITY.md](./SECURITY.md).

## CLA and sign-off

Every pull request needs a Developer Certificate of Origin sign-off on each
commit (`git commit -s`) and, on your first PR, a one-line comment accepting the
[CLA](./CLA.md). CI checks the sign-off automatically.

## License

The project is under the [Business Source License 1.1](./LICENSE) (converts to
Apache 2.0 on the Change Date). By contributing you agree your work is licensed
under those terms per the [CLA](./CLA.md).
