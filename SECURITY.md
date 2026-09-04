# Security Policy

## Reporting a vulnerability

Please report security issues privately rather than in a public issue.

- Use GitHub's private vulnerability reporting ("Report a vulnerability" on the
  Security tab), or
- Email the maintainer (address on the GitHub profile).

Include a description, reproduction steps, and the impact you expect. You'll get
an acknowledgement within a few days.

## Scope

Known limitations are listed in the README (heuristic prompt-injection
detection, regex/NER-based PII detection, thin test coverage, bearer tokens in
`localStorage`, invitation email sent via opportunistic STARTTLS). Issues beyond
those are especially useful: auth bypass, tenant isolation breaks, audit-log
tampering that defeats the hash chain, secret leakage.

## Supported versions

Until there is a tagged release, only the latest `main` is supported.
