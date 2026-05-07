const fs = require("node:fs/promises")
const path = require("node:path")
const os = require("node:os")

const KEY_ROOT = process.env.KEY_ROOT || path.join(os.homedir(), ".mpa")
const KEY_DIR = path.join(KEY_ROOT, "management_keys")

function detectPrivateKeyFormat(content) {
  const firstLine = content.split(/\r?\n/).find((line) => line.trim().length > 0) || ""
  if (firstLine.includes("OPENSSH")) {
    return "PEM (OPENSSH)"
  }
  if (/-----BEGIN [A-Z0-9 \s-]*PRIVATE KEY-----/i.test(content)) {
    return "PEM"
  }
  if (/^(?:0x)?[a-fA-F0-9]+$/.test(content.trim())) {
    return "DER (hex)"
  }
  return "Unknown"
}

async function main() {
  console.log(`KEY_ROOT=${KEY_ROOT}`)
  console.log(`Scanning: ${KEY_DIR}`)

  let entries
  try {
    entries = await fs.readdir(KEY_DIR)
  } catch (error) {
    console.error(`Cannot read key directory: ${KEY_DIR}`)
    console.error(error instanceof Error ? error.message : String(error))
    process.exit(1)
  }

  const pubFiles = entries.filter((name) => name.endsWith(".pub")).sort()
  if (pubFiles.length === 0) {
    console.log("No .pub files found.")
    return
  }

  for (const pubFile of pubFiles) {
    const pubPath = path.join(KEY_DIR, pubFile)
    const privPath = path.join(KEY_DIR, pubFile.slice(0, -4))

    let publicKeyPreview = ""
    try {
      const pub = (await fs.readFile(pubPath, "utf8")).trim()
      publicKeyPreview = pub.slice(0, 80)
    } catch {
      publicKeyPreview = "<unreadable .pub file>"
    }

    const privateExists = await fs.access(privPath).then(() => true).catch(() => false)
    let privateFormat = "MISSING"
    let privateKeyMaterial = ""
    if (privateExists) {
      try {
        const priv = await fs.readFile(privPath, "utf8")
        privateFormat = detectPrivateKeyFormat(priv)
        privateKeyMaterial = priv.trim()
      } catch {
        privateFormat = "UNREADABLE"
        privateKeyMaterial = "<unreadable private key file>"
      }
    } else {
      privateKeyMaterial = "<missing>"
    }

    console.log("")
    console.log(`public:  ${pubPath}`)
    console.log(`private: ${privPath}`)
    console.log(`hasPrivate: ${privateExists ? "yes" : "no"}`)
    console.log(`privateFormat: ${privateFormat}`)
    console.log(`publicKey: ${publicKeyPreview}${publicKeyPreview.length === 80 ? "..." : ""}`)
    console.log("privateKey:")
    console.log(privateKeyMaterial)
  }
}

main().catch((error) => {
  console.error(error)
  process.exit(1)
})
