# Releases

The package is published to npm as `@agenthooksprotocol/adapter-openclaw`. Merging
a release PR on `main` publishes it through npm trusted publishing, with provenance:
no npm token is stored anywhere.

## One-time setup

1. Create the npm organization `agenthooksprotocol` if it does not exist.
2. npm configures trusted publishing on a package that already exists, so publish
   the first version by hand with your own login:

   ```sh
   npm login
   git checkout main && git pull
   npm ci
   npm publish
   ```

3. In npm, open **@agenthooksprotocol/adapter-openclaw → Settings → Trusted
   Publisher**, select GitHub Actions and enter these exact, case-sensitive values:
   - Organization or user: `agenthooksprotocol`
   - Repository: `adapter-openclaw`
   - Workflow filename: `release.yml`
   - Environment: `release`
4. In **Settings → Publishing access**, require two-factor authentication and
   disallow tokens.
5. The **Agent Hooks Protocol Bot** GitHub App is installed on all of the organization's
   repositories, and `release.yml` reads its credentials from the organization's
   `AHP_BOT_APP_ID` and `AHP_BOT_APP_PRIVATE_KEY` secrets. Check that this repository
   has access to both.
6. In the GitHub environment **release**, restrict deployments to `main` and add
   required reviewers as appropriate.

## Releasing

Conventional commits on `main` make release-please open a release PR. Merging it tags
the version, creates the GitHub release and runs the `publish` job in `release.yml`.
