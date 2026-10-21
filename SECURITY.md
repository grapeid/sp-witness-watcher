# Security Policy

## Reporting a vulnerability

Please do not report security vulnerabilities through public GitHub issues,
discussions, or pull requests.

Email **security@antispamguy.org** with:

- a description of the issue and its potential impact
- steps to reproduce it
- the affected commit or version
- any suggested mitigation, if known

Reports may be anonymous. If you prefer encrypted email, ask for our PGP key in
your first message.

We aim to acknowledge a report within 48 hours and to give an initial
assessment within 7 days. We follow coordinated disclosure: we agree a timeline
with you, and credit you if you wish.

## Especially in scope

A witness is only useful if its receipts mean what they claim. Of particular
interest:

- anything that makes the service store or receipt an event its controller did
  not sign
- anything that lets one identity's events alter the digest reported for another
- disclosure or substitution of the service's own signing key
- ways to reset or rewrite when the service first observed an identity

## Operators

If you run your own instance and believe its signing key has been exposed, treat
that instance's identity as compromised: stop it, and tell the controllers it
witnesses so they can rotate it out of their witness sets.
