# Contributing

Thanks for the interest. The project is small and the bar for contributions is concrete: it should make the toolkit work for one more real situation.

## Setup

```sh
git clone <your-fork>
cd dbsc-toolkit
npm install
npm run build
npm test
```

Requirements: Node.js 20 or 22.

## Working on the protocol

Most changes start in `src/core`. The core has no framework dependency — it operates on plain request/response shapes. Add or change behaviour there first, then surface it through the adapters.

When you change a header name, cookie name, or anything on the wire, update:
1. `src/core/protocol/headers.ts`
2. Every adapter in `src/express`, `src/fastify`, `src/hono`, `src/nextjs`
3. The example in `examples/express/src/server.js`
4. README and CHANGELOG

## Verifying against a Chromium browser

Unit tests cover the protocol logic in isolation. They do not exercise a real browser. Before merging anything that touches the wire format, run the demo against any Chromium 145+ browser (Chrome, Edge, Brave, Opera):

1. Deploy `examples/express` somewhere with HTTPS (Railway works).
2. Click Login, wait a few seconds, click Check Session. `tier` must read `"dbsc"`.
3. Inspect Network. The `/dbsc/registration` POST must carry `Secure-Session-Response` header with a non-empty JWS.

## Tests

```sh
npm test
```

Add a unit test for any new behaviour in `core`. Adapters are thin enough that a real-browser smoke test is more useful than a mocked one — but if you can fake a known JWS and add an integration test for an adapter, that is welcome.

## Pull requests

- One change per PR.
- Update CHANGELOG.md under a new entry.
- Update the README only if user-visible API or setup changed.
- If your change adds a new wire format detail, link the spec section.

## Reporting bugs

Open an issue with:
- Chrome version
- OS
- The exact response headers your server sends on the registration trigger
- The exact request Chrome sends back (or "Chrome made no request")

Without those four, a DBSC bug is almost impossible to reproduce.

## Security

Do not file public issues for security problems. See [SECURITY.md](./SECURITY.md).

## License

By contributing you agree that your contribution is licensed under Apache 2.0, the project's license.
