<div align="center">
  <a href="https://marketplace.casdoor.com">
    <img src="https://cdn.casbin.org/img/casdoor-logo_1185x256.png" alt="Casdoor" width="400">
  </a>

  <h3>Casdoor Integrations</h3>

  <p>
    The official content of the <a href="https://marketplace.casdoor.com">Casdoor Marketplace</a>: app integrations, identity provider templates,<br>
    sign-in themes and actions that Casdoor admins can install from the Marketplace page of the Casdoor admin console.
  </p>

  <p>
    <a href="https://marketplace.casdoor.com"><strong>Marketplace</strong></a> &middot;
    <a href="https://github.com/casdoor/casdoor-marketplace"><strong>Marketplace website</strong></a> &middot;
    <a href="https://github.com/casdoor/casdoor"><strong>Casdoor</strong></a> &middot;
    <a href="https://casdoor.ai/docs/overview"><strong>Casdoor docs</strong></a> &middot;
    <a href="https://discord.gg/5rPsrAzK7S"><strong>Discord</strong></a>
  </p>

  <p>
    <a href="https://github.com/casdoor/casdoor-integrations/actions/workflows/build.yml">
      <img src="https://img.shields.io/github/actions/workflow/status/casdoor/casdoor-integrations/build.yml?branch=master&style=flat-square&label=build" alt="Build Status">
    </a>
    <a href="https://marketplace.casdoor.com">
      <img src="https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fraw.githubusercontent.com%2Fcasdoor%2Fcasdoor-integrations%2Fdist%2Findex.json&query=%24.integrations.length&label=integrations&style=flat-square&color=blue" alt="Integrations">
    </a>
    <a href="https://github.com/casdoor/casdoor-integrations/commits/master">
      <img src="https://img.shields.io/github/last-commit/casdoor/casdoor-integrations?style=flat-square" alt="Last commit">
    </a>
    <a href="LICENSE">
      <img src="https://img.shields.io/github/license/casdoor/casdoor-integrations?style=flat-square" alt="License">
    </a>
    <a href="https://discord.gg/5rPsrAzK7S">
      <img src="https://img.shields.io/discord/1022748306096537660?style=flat-square&logo=discord&label=Discord&color=5865F2" alt="Discord">
    </a>
  </p>
</div>

## Contributing

- **Add an integration**: copy a similar one under `integrations/<type>/`, follow the sections below, run `npm run check`, and open a pull request. CI validates every manifest against the schemas in `schema/`.
- **Request an integration**: [open an issue](https://github.com/casdoor/casdoor-integrations/issues/new) with the app or identity provider you need.
- Once merged, an integration shows up on the [Marketplace](https://marketplace.casdoor.com) at its next build, and on Casdoor's Marketplace page once jsDelivr refreshes its cache of the `dist` branch (up to 12 hours).

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
- For a `Custom` provider whose requests don't follow OAuth 2.0, such as `appid` and `secret` instead of `client_id` and `client_secret`, or a userinfo endpoint that takes the token's fields in its query, write the URLs with `{name}` placeholders (single braces, filled in at sign-in, unlike `{{variables}}`). `customAuthUrl` gets `clientId`, `redirectUri`, `scope`, `state` and `codeChallenge`; `customTokenUrl` gets `clientId`, `clientSecret`, `code`, `redirectUri`, `codeVerifier` and `state`, and its query is posted as the form body; `customUserInfoUrl` gets `clientId`, `state` and any field of the token response, and is requested without an `Authorization` header. See [chaoxing](integrations/provider/chaoxing/provider.json).
- Casdoor links users of every OIDC-type provider in an organization through one user field (`oidc`), so an organization should have only one; a second one should be `Custom Flexible`, which links accounts per provider. The generated Casdoor step says so.

## The Chinese Marketplace

`"region": "cn"` in `integration.json` lists an integration only in Chinese: on the Chinese pages of the store, and in Casdoor for admins using it in Chinese. It is for platforms only used in China, such as Chaoxing; their name, description and guide are written in Chinese, under `en`. Everything else is listed in both.

## Themes

A look for the sign-in pages of a Casdoor application.

| File | Contents |
|---|---|
| `integration.json` | Name, description, at least one screenshot, and variables such as an accent color |
| `theme.json` | Application fields in the shape of Casdoor's **Export JSON**: `themeData`, `formOffset`, `formCss`, `formCssMobile`, `formSideHtml`, `footerHtml`, `formBackgroundUrl`, `formBackgroundUrlMobile` ([schema](schema/theme/theme.schema.json)) |
| `screenshot.png` | 1280×800 screenshot of the sign-in page, taken from a real Casdoor with the variables at their examples |

- CSS hooks: `.login-background`, `.login-topbar` (Casdoor 4.20.0 and later; `.login-background > div:first-of-type` before that), `.login-content`, `.login-panel`, `.login-form`, `.login-logo-box`, `.side-image`, `#footer`. Without `formCssMobile`, phones get no custom CSS at all.
- Form CSS may load fonts and images, with `url()`, `@font-face` and `@import`, from places an organization admin cannot read the access logs of: relative URLs on the Casdoor itself, `data:` URIs, Google Fonts, Fontsource on jsDelivr, `cdn.jsdelivr.net/gh/casdoor/` and Casdoor's own CDNs. `@import` is limited to Google Fonts and Fontsource stylesheets. Anything else, image functions other than `url()`, backslashes and HTML make Casdoor keep the old CSS when an organization admin saves it, and the build rejects them. A theme that loads files needs `casdoorVersion` `>=4.20.0`: earlier versions reject every `url()`.
- A picture behind the whole page goes in `formBackgroundUrl` and `formBackgroundUrlMobile`, usually as a variable of type `url`; any address works there. Keep a default picture next to `theme.json` and point the variable's example at it on jsDelivr (`https://cdn.jsdelivr.net/gh/casdoor/casdoor-integrations@master/integrations/theme/<id>/<file>`).
- `formSideHtml` and `footerHtml` are for layout and branding. From Casdoor 4.20.0 an organization admin can save them as long as they hold only text, links, pictures, inline SVG and styles: no scripts, event handlers, forms, fields, buttons, frames or comments, and pictures and styles follow the same rule as form CSS about where files come from. Before 4.20.0 only a global admin can save them, so a theme that sets them is still marked `requiresGlobalAdmin` in the index, which those versions go by.
- The public page builds the JSON for Casdoor's **Import JSON** button, so a theme can also be applied by hand, without the Marketplace installer.

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

On every push to master, CI publishes `dist/` to the `dist` branch. Casdoor instances read it from `https://cdn.jsdelivr.net/gh/casdoor/casdoor-integrations@dist` by default (`marketplaceUrl` in Casdoor's `conf/app.conf` points them to a mirror), and [casdoor-marketplace](https://github.com/casdoor/casdoor-marketplace) builds the public pages from it.

Logos are from [Simple Icons](https://simpleicons.org) (CC0); the names and marks belong to their owners.
