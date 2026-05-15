---
name: Bug report
about: A wire-format problem, a verification failure, or an adapter bug
title: ""
labels: bug
---

## Environment
- Chrome version:
- OS:
- Adapter (express / nextjs / fastify / hono):
- Storage (memory / redis / postgres):
- Behind proxy / CDN? If yes, which:

## What you did
A short description of the request flow that breaks.

## Server-side response headers on the trigger response
Paste the full response headers your server sent on the request that should have triggered DBSC registration (usually `/login`).

```
Secure-Session-Registration: ...
Set-Cookie: ...
```

## Chrome-side request headers and body on the registration POST
Open DevTools → Network. Find the POST to `/dbsc/registration` (Chrome-initiated). Paste its request headers. Note whether the body is empty.

```
POST /dbsc/registration
Secure-Session-Response: ...
```

If Chrome made no such request at all, say so explicitly.

## Server logs
Anything the middleware logged for that request, especially `verification_failure` events.

## Expected behaviour
What should have happened.
