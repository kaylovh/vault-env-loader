export interface Options {
  /** Vault address. Default: VAULT_ADDR. */
  addr?: string;
  /** Token. Default: VAULT_TOKEN, else the contents of tokenFile / VAULT_TOKEN_FILE. */
  token?: string;
  tokenFile?: string;
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
  /** Leave VAULT_TOKEN in the environment after loading. Default: false. */
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

export class VaultEnvError extends Error {
  name: 'VaultEnvError';
  /** config | auth | not_found | resolve | collision | value | unavailable | error */
  code: string;
}

export const VERSION: string;
