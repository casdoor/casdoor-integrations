# casdoor-integrations

Official integrations for the [Casdoor Marketplace](https://www.casdoor.com/integrations): app integrations, provider templates, themes and actions that Casdoor admins can install from the Marketplace page of the Casdoor admin console.

## Layout

```
integrations/<type>/<id>/
  integration.json   manifest, see schema/integration.schema.json
  ...                content files for the type
schema/              JSON Schemas for the manifest and content files
scripts/build.mjs    validates everything and writes dist/
```

`<type>` is one of `app`, `provider`, `theme`, `action`. `<id>` is unique across all types and becomes the page address `/integrations/<id>`.

## App integrations

Single sign-on for an app people run, such as Grafana or GitLab.

| File | Contents |
|---|---|
| `integration.json` | Name, description, logo, categories, and the variables the installer asks for (usually `appUrl`) |
| `application.json` | The Casdoor application to create: redirect URLs, token group format ([schema](schema/app/application.schema.json)) |
| `guide.json` | Setup guide for the app's side: steps with code or form fields, tips, FAQs, and the app documentation the settings come from ([schema](schema/guide.schema.json)) |
| `logo.svg` | Optional |

The first step of every guide, registering the app in Casdoor, is generated from `application.json`, so `guide.json` starts with the app's own settings.

## Provider templates

An identity provider people already have accounts with, set up as a sign-in provider in Casdoor, such as Keycloak or authentik.

| File | Contents |
|---|---|
| `integration.json` | Name, description, logo, and the variables for the other side's address (e.g. `keycloakUrl`, `realm`) |
| `provider.json` | The Casdoor provider to create: type `OIDC` (or `Custom` for plain OAuth 2.0), issuer, endpoints, scopes, PKCE, user mapping ([schema](schema/provider/provider.schema.json)) |
| `guide.json` | The steps on the other side: registering Casdoor as a client, with redirect URI `{{casdoorUrl}}/callback` |
| `logo.svg` | Optional |

The last two steps of every guide, adding the provider in Casdoor and putting it on an application, are generated from `provider.json`.

- Casdoor's sign-in page builds the authorization request from `customAuthUrl` even for OIDC, so list the endpoints rather than relying on discovery. Always set `customUserInfoUrl`: several providers (Authelia, authentik, ZITADEL) keep profile claims out of the ID token.
- Casdoor sends the client secret with HTTP Basic first (Go's oauth2 auto-detection), so the other side can keep `client_secret_basic`.
- Casdoor links users of every OIDC-type provider in an organization through one user field (`oidc`), so an organization should have only one; a second one should be `Custom Flexible`, which links accounts per provider. The generated Casdoor step says so.

## Themes

A look for the sign-in pages of a Casdoor application.

| File | Contents |
|---|---|
| `integration.json` | Name, description, at least one screenshot, and variables such as an accent color |
| `theme.json` | Application fields in the shape of Casdoor's **Export JSON**: `themeData`, `formOffset`, `formCss`, `formCssMobile`, `formSideHtml`, `footerHtml` ([schema](schema/theme/theme.schema.json)) |
| `screenshot.png` | 1280×800 screenshot of the sign-in page, taken from a real Casdoor with the variables at their examples |

- CSS hooks: `.login-background`, `.login-content`, `.login-panel`, `.login-form`, `.login-logo-box`, `.side-image`. Without `formCssMobile`, phones get no custom CSS at all.
- Casdoor drops form CSS containing `url(`, `@import`, `@font-face`, image functions, backslashes or HTML when an organization admin saves it; the build rejects those. Use gradients instead of background images.
- `formSideHtml` and `footerHtml` can only be saved by a global admin, so a theme that sets them is marked `requiresGlobalAdmin` in the index and on its page.
- The public page builds the JSON for Casdoor's **Import JSON** button, so a theme can be applied by hand before the Marketplace installer exists.

## Variables

Content files write values that differ per installation as `{{name}}`:

| Variable | Public page shows | Filled in by |
|---|---|---|
| `casdoorUrl` | `https://auth.example.com` | Casdoor |
| `clientId` | `<client ID>` | App integrations: Casdoor, from the new application. Provider templates: the admin, from the other side |
| `clientSecret` | `<client secret>` | Same as `clientId` |
| anything in `variables` | its `example` | the admin, in the install form |

Variable types are `string`, `url` (no trailing slash) and `color` (`#rrggbb`). The installer must HTML-escape values it puts into HTML fields, and check colors.

The installer should also set a provider's `customLogo` to the integration's logo, since templates leave it empty and Casdoor otherwise shows a generic icon on the sign-in button.

## Writing a guide

- Take every setting of the other side from its own documentation and list it in `sources`. Check Casdoor's side against the Casdoor source code.
- For app integrations: Casdoor's default JWT ID token has the username in `name`, the display name in `displayName`, and `email`, `email_verified` and `groups`; it has no `preferred_username`. `/api/userinfo` returns the standard `preferred_username`, `name`, `email` and `groups`. JWT-Standard tokens carry no groups.
- Text may use `` `code` `` and `**bold**`.
- Bump `version` in `integration.json` whenever any file of the integration changes.

## Actions

Their content schema is not defined yet.

## Build

```bash
npm ci
npm run check   # validate only
npm run build   # validate and write dist/
```

`dist/index.json` lists every integration; each version is in `dist/integrations/<id>/<version>/bundle.json` (manifest plus content files) with its logo and screenshots. Paths in `index.json` are relative to it.

Logos are from [Simple Icons](https://simpleicons.org) (CC0); the names and marks belong to their owners.
