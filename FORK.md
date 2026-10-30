# MaxRink/bichon fork

This fork exists for one reason: native OpenID Connect login (Authelia) for
the homelab Bichon instance. Upstream closed the third-party OIDC PR
(rustmailer/bichon#328), so the patches stay here.

## Branch scheme

- `main` = latest upstream **release tag** + the fork patches, as a linear
  series on top of the tag. It is force-pushed on every forward; never merge
  upstream into it.
- `upstream` remote = https://github.com/rustmailer/bichon (tags `X.Y.Z`).
- Backups of replaced `main` lines: tag `archive/main-pre-<release>-<yyyymmdd>`.
- Topic branches (`codex/*`, `claude/*`, `forward-port/*`) are history only.

## Fork patches (on top of 2.2.0)

1. `feat(oidc)`: OpenID Connect SSO (ported from rustmailer/bichon#328), JWKS
   verification of RS/PS/ES/EdDSA ID tokens, PKCE + nonce
2. `fix(oidc)`: bind the verified admin to the existing local account
3. `security`: exact OIDC subject required for the native admin link
4. refuse ambiguous OIDC email linking
5. + 6. default admin password reminder compatibility with 2.2
7. style fix
8. this file

## Upstream sync (forward to a new release)

```sh
git fetch upstream --tags
git tag archive/main-pre-<NEW>-$(date +%Y%m%d) main
git rebase --onto <NEW> <OLD> main      # e.g. --onto 2.3.0 2.2.0
cargo test -p bichon-core users::tests::oidc_ --lib
cargo test -p bichon-core --lib account
git push --force-with-lease origin main archive/main-pre-<NEW>-<yyyymmdd>
```

Then build and deploy per truenas-homelab-ops `docs/apps/bichon/README.md`
(source tarball from `git archive`, image `local/bichon:<ver>-oidc-<sha>-amd64`).
