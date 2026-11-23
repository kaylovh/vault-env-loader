export interface Options {
  /** Vault address. Default: VAULT_ADDR. */
  addr?: string;
  /** Token. Default: VAULT_TOKEN, else the contents of tokenFile / VAULT_TOKEN_FILE. */
  token?: string;
  tokenFile?: string;
  /**
   * AppRole, used only when there is no token: log in with roleId (+ secretId),
   * read, then revoke the session. Default: VAULT_ROLE_ID / VAULT_ROLE_ID_FILE,
   * VAULT_SECRET_ID / VAULT_SECRET_ID_FILE.
   */
  roleId?: string;
  roleIdFile?: string;
  secretId?: string;
  secretIdFile?: string;
  /** AppRole auth mount. Default: VAULT_ENV_APPROLE_MOUNT, else "approle". */
  approleMount?: string;
  /**
   * Certificate login, used when there is no token and no secret ID: with roleId, sign a
   * short-lived JWT with the private key and log in at auth/<jwtMount>/login. One PEM file
   * with the key and the certificate. Default: VAULT_CLIENT_CERTIFICATE_PATH.
   */
  clientCertificatePath?: string;
  /** The private key, when it is in a file of its own. Default: VAULT_CLIENT_KEY_PATH. */
  clientKeyPath?: string;
  /** Password of an encrypted key. Default: VAULT_CLIENT_CERTIFICATE_PASSWORD, else the contents of ..._PASSWORD_FILE. */
  clientCertificatePassword?: string;
  clientCertificatePasswordFile?: string;
  /** JWT auth mount for certificate login. Default: VAULT_ENV_JWT_MOUNT, else "jwt". */
  jwtMount?: string;
  /** Imports, e.g. ["vault://secret/app/prod/db", "redis?prefix=REDIS_"]. Default: VAULT_ENV_IMPORT. */
  imports?: string[] | string;
  /** Base path for relative imports. Default: VAULT_ENV_BASE, else token metadata application/environment. */
  base?: string;
  namespace?: string;
  /** Extra CA certificate file (PEM). Default: VAULT_CACERT. */
  cacert?: string;
  capath?: string;
  /** Replace variables that are already set. Default: VAULT_ENV_OVERRIDE, false. */
  override?: boolean;
  /** Leave VAULT_TOKEN (or the AppRole / certificate variables) in the environment after loading. Default: false. */
  keepToken?: boolean;
  /** Seconds per request. Default 10. */
  timeout?: number;
  /** Retries for transient failures. Default 3. */
  retries?: number;
  /** Allow plain http to a non-loopback host. Default: VAULT_ENV_ALLOW_HTTP. */
  allowHttp?: boolean;
  /** Environment to read configuration from and write into. Default: process.env. */
  env?: NodeJS.ProcessEnv;
}

/** Load secrets into the environment. Resolves with the names that were set. */
export function load(options?: Options): Promise<string[]>;
/** Same as load(), synchronously (the HTTP work runs in a child process). */
export function loadSync(options?: Options): string[];
/** Read secrets and return { NAME: value } without touching the environment. */
export function fetch(options?: Options): Promise<Record<string, string>>;

export interface ClientAssertionOptions {
  /** The role: iss and sub of the assertion. */
  roleId: string;
  /** PEM file with the certificate and, unless keyPath is given, the private key. */
  certificatePath: string;
  keyPath?: string;
  /** Password of an encrypted private key. */
  password?: string;
  /** The Vault address the assertion is for (its aud is <vaultAddr>/v1/auth/<mount>/login). */
  vaultAddr: string;
  /** JWT auth mount. Default "jwt". */
  mount?: string;
}

/**
 * A client assertion (a JWT signed with the certificate's private key, valid 120 s, with a
 * new jti) for POST auth/<mount>/login { role, jwt }, e.g. node-vault's jwtLogin().
 * Synchronous; throws VaultEnvError (code "config") for an unreadable or unsuitable file.
 */
export function clientAssertion(options: ClientAssertionOptions): string;

export class VaultEnvError extends Error {
  name: 'VaultEnvError';
  /** config | auth | not_found | resolve | collision | value | unavailable | error */
  code: string;
}

export const VERSION: string;
