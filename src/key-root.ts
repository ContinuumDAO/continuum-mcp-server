import os from "os"
import path from "path"

/**
 * Resolves KEY_ROOT for local key material. Never uses a literal "~" segment:
 * `~` and `~/.mpa` expand via os.homedir(). Default is $HOME/.mpa (no tilde in path).
 */
export function resolveKeyRoot(envValue: string | undefined): string {
  const raw = envValue?.trim()
  if (!raw) {
    return path.join(os.homedir(), ".mpa")
  }
  if (raw === "~") {
    return path.join(os.homedir(), ".mpa")
  }
  const tildePrefix = raw.startsWith("~/") || raw.startsWith("~\\")
  if (tildePrefix) {
    let rest = raw.slice(2).replace(/^[\\/]+/, "")
    if (!rest) {
      return path.join(os.homedir(), ".mpa")
    }
    return path.join(os.homedir(), rest)
  }
  return path.resolve(raw)
}
