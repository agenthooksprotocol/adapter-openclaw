// A backend's OAuth settings: its registration `authentication` preset, and the
// `oauth` object beside it in hooks.json. hooks.json is shared by every harness's
// adapter, so these names and meanings are the same in all of them. AHP receivers
// ignore unknown registration fields: the SDK passes `oauth` by, and this reads it.
//
//   "oauth": {
//     "issuer": "https://auth.example.com",   // the one issuer trusted for this backend
//     "trustAdvertisedIssuer": false,         // or, for a public browser sign-in only, the one it advertises
//     "flow": "authorization_code_pkce",      // or "client_credentials"
//     "scopes": ["hooks"],
//     "clientId": "openclaw",                 // a pre-registered client, or:
//     "clientSecretRef": "example-secret",    // a key in the plugin config's `secrets`
//     "clientMetadataDocument": { "url": "https://…/client.json", "redirectUris": ["http://127.0.0.1:18789/ahp/oauth/callback"] },
//     "registration": true,                   // or { "clientName", "scopes", "initialAccessTokenRef" }: DCR at `issuer`
//     "redirectPort": 33418,                  // other harnesses' own listener; not OpenClaw's, whose callback is the Gateway's
//     "loginLifetimeMinutes": 10,
//     "allowPrivateNetwork": false
//   }

export type Flow = "authorization_code_pkce" | "client_credentials";

export interface BackendSettings {
  issuer?: string;
  trustAdvertisedIssuer: boolean;
  flow?: Flow;
  scopes?: string[];
  clientId?: string;
  clientSecretRef?: string;
  clientMetadataDocument?: { url: string; redirectUris: string[] };
  registration?: { clientName?: string; scopes?: string[]; initialAccessTokenRef?: string };
  loginLifetimeMs: number;
  allowPrivateNetwork: boolean;
  /** An `oauth` object was given: the operator expects OAuth here. */
  configured: boolean;
}

const MAX_LIFETIME_MS = 600_000;

function object(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function strings(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === "string" && item.length > 0);
}

/** Read one backend's `oauth`; problems name settings that were ignored. */
export function backendSettings(backend: Record<string, unknown>): { settings: BackendSettings; problems: string[] } {
  const id = String(backend.id);
  const problems: string[] = [];
  const raw = backend.oauth;
  const settings: BackendSettings = { trustAdvertisedIssuer: false, loginLifetimeMs: MAX_LIFETIME_MS, allowPrivateNetwork: false, configured: object(raw) };
  const ignore = (name: string, why: string) => problems.push(`${id}: oauth.${name} ${why}; ignored`);
  if (raw !== undefined && !object(raw)) problems.push(`${id}: oauth is not an object; ignored`);
  const given = object(raw) ? raw : {};
  if (given.issuer !== undefined) {
    if (typeof given.issuer === "string" && given.issuer.startsWith("https://")) settings.issuer = given.issuer;
    else ignore("issuer", "is not an https URL");
  }
  if (given.flow !== undefined) {
    if (given.flow === "authorization_code_pkce" || given.flow === "client_credentials") settings.flow = given.flow;
    else ignore("flow", 'is not "authorization_code_pkce" or "client_credentials"');
  }
  for (const name of ["clientId", "clientSecretRef"] as const) {
    if (given[name] === undefined) continue;
    if (typeof given[name] === "string" && given[name]) settings[name] = given[name] as string;
    else ignore(name, "is not a string");
  }
  if (given.scopes !== undefined) {
    if (strings(given.scopes)) settings.scopes = given.scopes;
    else ignore("scopes", "is not a list of strings");
  }
  const document = given.clientMetadataDocument;
  if (document !== undefined) {
    if (object(document) && typeof document.url === "string" && strings(document.redirectUris)) settings.clientMetadataDocument = { url: document.url, redirectUris: document.redirectUris };
    else ignore("clientMetadataDocument", "needs url and redirectUris");
  }
  const registration = given.registration;
  if (registration !== undefined && registration !== false) {
    if (registration === true) settings.registration = {};
    else if (object(registration)) {
      settings.registration = {
        ...(typeof registration.clientName === "string" ? { clientName: registration.clientName } : {}),
        ...(strings(registration.scopes) ? { scopes: registration.scopes } : {}),
        ...(typeof registration.initialAccessTokenRef === "string" ? { initialAccessTokenRef: registration.initialAccessTokenRef } : {}),
      };
    } else ignore("registration", "is not true or an object");
    // Permission to register is for one issuer, named here.
    if (settings.registration && !settings.issuer) {
      delete settings.registration;
      ignore("registration", "needs oauth.issuer");
    }
  }
  // `redirectPort` is for adapters with a listener of their own. OpenClaw's callback
  // is the Gateway's route, on the Gateway's port.
  if (given.loginLifetimeMinutes !== undefined) {
    const minutes = given.loginLifetimeMinutes;
    if (typeof minutes === "number" && minutes > 0 && minutes <= 10) settings.loginLifetimeMs = Math.round(minutes * 60_000);
    else ignore("loginLifetimeMinutes", "is not more than 0 and at most 10");
  }
  if (given.trustAdvertisedIssuer !== undefined) {
    if (typeof given.trustAdvertisedIssuer === "boolean") settings.trustAdvertisedIssuer = given.trustAdvertisedIssuer;
    else ignore("trustAdvertisedIssuer", "is not a boolean");
  }
  if (given.allowPrivateNetwork !== undefined) {
    if (typeof given.allowPrivateNetwork === "boolean") settings.allowPrivateNetwork = given.allowPrivateNetwork;
    else ignore("allowPrivateNetwork", "is not a boolean");
  }
  return { settings, problems };
}

/** The issuer to trust: the configured one (the `oauth` object's, else the preset's),
 * if the backend advertises it; or, by explicit opt-in, the one issuer it advertises,
 * for a public browser sign-in only. An advertisement alone never chooses an issuer
 * that a client secret is sent to. */
export function trustedIssuer(options: { configured: string | undefined; trustAdvertised: boolean; flow: Flow; confidential: boolean; advertised: readonly string[] }): string | undefined {
  const { configured, trustAdvertised, flow, confidential, advertised } = options;
  if (configured !== undefined) return advertised.includes(configured) ? configured : undefined;
  if (!trustAdvertised || flow !== "authorization_code_pkce" || confidential || advertised.length !== 1) return undefined;
  return advertised[0];
}
