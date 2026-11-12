// ChronoLock
// Developed by Kevin Roper for NueM8.
// Version 1.1.0
// Free to use and test.
// https://chronolock.nuem8.com/
// Licensed under GPL-3.0-only. See LICENSE.

const MAX_BYTES = 8192
const PUBLIC_KEY_BYTES = 65
const KEY_STORE = "chronolock.key"
const KEY_INFO = new TextEncoder().encode("chronolock-recipient")
const KEY_SALT = new TextEncoder().encode("chronolock")

const root = document.querySelector("#app")
const path = location.pathname.split("/").filter(Boolean)

if (!crypto.subtle) {
  renderSecureContext()
} else if (path[0] === "s" && path[1]) {
  renderReveal(path[1])
} else if (path[0] === "key") {
  renderKey()
} else {
  renderCreate()
}

function renderSecureContext() {
  root.innerHTML = `
    <p class="lede">Open this page over HTTPS, or on localhost. This browser will not encrypt a secret on an insecure page.</p>
  `
}

function renderCreate() {
  const identity = readIdentity()
  root.innerHTML = `
    <form class="card" id="create">
      <label for="secret">Secret</label>
      <textarea id="secret" name="secret" autocomplete="off" spellcheck="false" required></textarea>
      <p class="limit" id="limit" aria-live="polite">0 bytes of 8KB.</p>
      <label for="ttl">Lifetime</label>
      <select id="ttl" name="ttl">
        <option value="300">5 minutes</option>
        <option value="3600" selected>1 hour</option>
        <option value="86400">1 day</option>
        <option value="604800">7 days</option>
      </select>
      <label class="choice"><input id="burn" type="checkbox" checked> Delete after one reveal</label>
      <div class="toggle-row">
        <label class="choice"><input id="use-key" type="checkbox" aria-controls="key-panel"${identity ? " checked" : ""}> User key pair</label>
        <a class="button quiet" id="view-keys" href="/key" hidden>View keys</a>
      </div>
      <div id="key-panel"${identity ? "" : " hidden"}>
        <label for="recipient">Recipient public key</label>
        <div class="key-row">
          <input id="recipient" type="text" autocomplete="off" spellcheck="false">
          <a class="button quiet" id="your-key" href="/key">Your key</a>
        </div>
        <p class="note" id="key-note"></p>
      </div>
      <p class="note">ChronoLock is provided as is. You use it at your own risk. <a href="https://nuem8.com/disclaimer" target="_blank" rel="noreferrer noopener">Disclaimer</a></p>
      <button type="submit">Create link</button>
      <p class="status" id="status" role="status"></p>
    </form>
  `
  const secret = document.querySelector("#secret")
  const useKey = document.querySelector("#use-key")
  const keyPanel = document.querySelector("#key-panel")
  const recipient = document.querySelector("#recipient")
  const yourKey = document.querySelector("#your-key")
  const syncKeyLink = () => {
    const on = useKey.checked
    keyPanel.hidden = !on
    useKey.setAttribute("aria-expanded", on ? "true" : "false")
    const value = recipient.value.trim()
    const stored = readIdentity()
    yourKey.hidden = !on || value.length > 0 || Boolean(stored)
    document.querySelector("#view-keys").hidden = !stored
    document.querySelector("#key-note").textContent = stored && value === stored.publicKey
      ? "This is the public key in this browser. Replace it to lock to a different key. ChronoLock never receives the private key."
      : "Paste a public key. Only the private key that matches it can open the secret. ChronoLock never receives the private key."
  }
  if (identity) recipient.value = identity.publicKey
  secret.addEventListener("input", refreshLimit)
  useKey.addEventListener("change", syncKeyLink)
  recipient.addEventListener("input", syncKeyLink)
  document.querySelector("#create").addEventListener("submit", onCreate)
  refreshLimit()
  syncKeyLink()
}

async function onCreate(event) {
  event.preventDefault()
  const status = document.querySelector("#status")
  const secret = document.querySelector("#secret").value
  const bytes = new TextEncoder().encode(secret).length
  if (!secret.trim()) {
    status.textContent = "Write a secret first."
    return
  }
  if (bytes > MAX_BYTES) {
    status.textContent = limitMessage(bytes)
    return
  }
  const useKey = document.querySelector("#use-key").checked
  const recipient = useKey ? document.querySelector("#recipient").value.trim() : ""
  if (useKey && !recipient) {
    status.textContent = "Paste the recipient's public key."
    return
  }
  status.textContent = "Encrypting…"
  let packed
  try {
    packed = recipient ? await encryptToRecipient(secret, recipient) : await encrypt(secret)
  } catch {
    status.textContent = "That public key is not valid."
    return
  }
  const response = await fetch("/api/secrets", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      ciphertext: packed.ciphertext,
      ttl_seconds: Number(document.querySelector("#ttl").value),
      burn: document.querySelector("#burn").checked,
      locked: Boolean(recipient),
    }),
    credentials: "omit",
    cache: "no-store",
    referrerPolicy: "no-referrer",
  })
  const payload = await response.json().catch(() => ({}))
  if (!response.ok) {
    status.textContent = payload.error || (response.status === 413
      ? "That secret is larger than 8KB."
      : "The link was not created.")
    return
  }
  const link = new URL("/s/" + payload.id, location.origin)
  if (!recipient) link.hash = packed.key
  renderLink(link.toString(), payload.expires_at, document.querySelector("#burn").checked, Boolean(recipient))
}

function renderLink(link, expiresAt, burn, locked) {
  const when = new Date(expiresAt * 1000).toLocaleString()
  const end = locked && burn
    ? "The secret is deleted after the recipient's private key opens it."
    : burn
      ? "The secret is deleted the first time someone reveals it."
      : "The secret can be revealed until " + when + "."
  const lead = locked
    ? "Send this link. Only the private key that matches the public key can open it. That private key is not in the link, and ChronoLock never receives it."
    : "Send this link. The part after # is the key. ChronoLock never receives it and cannot read the secret."
  root.innerHTML = `
    <div class="card">
      <p>${lead}</p>
      <label for="link">Secret link</label>
      <input id="link" type="text" readonly value="">
      <button type="button" id="copy">Copy link</button>
      <a class="button quiet" href="/">New secret</a>
      <p class="note">${escapeText(end)} It also dies at ${escapeText(when)}.</p>
      <p class="status" id="status" role="status"></p>
    </div>
  `
  document.querySelector("#link").value = link
  document.querySelector("#copy").addEventListener("click", () => copyValue(link, "Link copied."))
}

function renderReveal(id) {
  const key = location.hash.replace(/^#/, "")
  const mode = document.querySelector('meta[name="chronolock"]')?.content || ""
  if (mode === "gone") {
    root.innerHTML = `
      <div class="card">
        <p class="lede">This secret is gone.</p>
      </div>
    `
    return
  }
  const locked = mode === "recipient"
  const held = locked ? readIdentity() : null
  const lead = locked
    ? (held
      ? "A secret is waiting. This browser holds a private key. ChronoLock never receives it."
      : "A secret is waiting. Paste the private key that matches the public key used to send it.")
    : "A secret is waiting. Revealing it asks the server for the ciphertext, then decrypts it here."
  const privateField = locked
    ? `<div class="toggle-row">
         <label class="choice"><input id="use-key" type="checkbox" aria-controls="key-panel"${held ? "" : " checked"}> User key pair</label>
         <a class="button quiet" id="view-keys" href="/key"${held ? "" : " hidden"}>View keys</a>
       </div>
       <div id="key-panel" hidden>
         <label for="private-key">Private key</label>
         <div class="key-row">
           <input id="private-key" type="password" autocomplete="off" spellcheck="false" placeholder="${held ? "Leave blank to use the key in this browser" : ""}">
           <button type="button" class="button quiet" id="load-key">Load key</button>
           <a class="button quiet" id="your-key" href="/key">Your key</a>
           <button type="button" class="button quiet" id="clear-key" hidden>Clear</button>
         </div>
         <button type="button" class="button quiet" id="load-file">Load key file</button>
         <input id="key-file" type="file" accept=".pem,.txt,.key,text/plain" hidden>
         <p class="note">Load the key in this browser, paste a private key, or load a private key file. Clear removes it from this box. ChronoLock never receives the private key.</p>
       </div>`
    : ""
  root.innerHTML = `
    <div class="card">
      <p class="lede" id="lead">${lead}</p>
      ${privateField}
      <button type="button" id="reveal">Reveal secret</button>
      <p class="status" id="status" role="status"></p>
      <div id="opened" hidden>
        <label for="plain">Secret</label>
        <textarea id="plain" class="secret" readonly></textarea>
        <button type="button" id="copy">Copy secret</button>
        <p class="note" id="after"></p>
      </div>
    </div>
  `
  if (!locked && !key) {
    document.querySelector("#lead").textContent = "This link has no key. The part after # is missing, so the secret cannot be opened."
    document.querySelector("#reveal").disabled = true
    return
  }
  const open = () => openSecret(id, locked ? null : key)
  document.querySelector("#reveal").addEventListener("click", open)
  const privateKey = document.querySelector("#private-key")
  if (privateKey) {
    const useKey = document.querySelector("#use-key")
    const keyPanel = document.querySelector("#key-panel")
    const loadKey = document.querySelector("#load-key")
    const clearKey = document.querySelector("#clear-key")
    const yourKey = document.querySelector("#your-key")
    const syncKey = () => {
      const on = useKey.checked
      keyPanel.hidden = !on
      useKey.setAttribute("aria-expanded", on ? "true" : "false")
      const filled = privateKey.value.trim().length > 0
      const hasKey = Boolean(readIdentity())
      loadKey.hidden = !on || filled || !hasKey
      yourKey.hidden = !on || filled || hasKey
      clearKey.hidden = !on || !filled
    }
    useKey.addEventListener("change", () => {
      if (!useKey.checked) privateKey.value = ""
      syncKey()
    })
    loadKey.addEventListener("click", () => {
      const identity = readIdentity()
      if (!identity) {
        document.querySelector("#status").textContent = "This browser does not hold a private key."
        return
      }
      privateKey.value = identity.privateKey
      document.querySelector("#status").textContent = ""
      syncKey()
    })
    clearKey.addEventListener("click", () => {
      privateKey.value = ""
      document.querySelector("#status").textContent = ""
      syncKey()
    })
    const keyFile = document.querySelector("#key-file")
    document.querySelector("#load-file").addEventListener("click", () => keyFile.click())
    keyFile.addEventListener("change", async () => {
      const file = keyFile.files && keyFile.files[0]
      keyFile.value = ""
      if (!file) return
      const status = document.querySelector("#status")
      try {
        const privateKeyText = privateMaterialFromText(await file.text())
        await importPrivateKey(privateKeyText)
        privateKey.value = privateKeyText
        status.textContent = ""
        syncKey()
      } catch (error) {
        status.textContent = keyFileMessage(error)
      }
    })
    privateKey.addEventListener("input", syncKey)
    privateKey.addEventListener("keydown", (event) => {
      if (event.key === "Enter") {
        event.preventDefault()
        open()
      }
    })
    syncKey()
  }
}

async function openSecret(id, key) {
  const status = document.querySelector("#status")
  const button = document.querySelector("#reveal")
  const typed = document.querySelector("#private-key")
  const pasted = typed ? typed.value.trim() : ""
  const held = readIdentity()
  let privateKey = ""
  try {
    privateKey = pasted ? privateMaterialFromText(pasted) : (held ? held.privateKey : "")
  } catch (error) {
    status.textContent = keyFileMessage(error)
    return
  }
  if (typed && !privateKey) {
    status.textContent = "This browser does not hold the private key."
    return
  }
  button.disabled = true
  status.textContent = "Opening…"
  const response = await fetch("/api/secrets/" + encodeURIComponent(id) + "/reveal", {
    method: "POST",
    credentials: "omit",
    cache: "no-store",
    referrerPolicy: "no-referrer",
  })
  const payload = await response.json().catch(() => ({}))
  if (!response.ok) {
    status.textContent = payload.error || "This secret is gone."
    return
  }
  try {
    const plain = payload.locked
      ? await decryptWithRecipient(payload.ciphertext, privateKey)
      : await decrypt(payload.ciphertext, key)
    if (typed) typed.value = ""
    let deleted = !payload.locked
    if (payload.locked && payload.burn) {
      const done = await fetch("/api/secrets/" + encodeURIComponent(id) + "/finish", {
        method: "POST",
        credentials: "omit",
        cache: "no-store",
        referrerPolicy: "no-referrer",
      })
      deleted = done.ok
    }
    document.querySelector("#opened").hidden = false
    document.querySelector("#plain").value = plain
    document.querySelector("#copy").addEventListener("click", () => copyValue(plain, "Secret copied."))
    document.querySelector("#lead").textContent = "Opened in this browser."
    document.querySelector("#after").textContent = payload.burn
      ? (deleted
        ? "This secret has been deleted."
        : "Opened in this browser. It could not be deleted yet.")
      : "This secret remains until " + new Date(payload.expires_at * 1000).toLocaleString() + "."
    status.textContent = ""
    button.hidden = true
  } catch {
    if (payload.locked) {
      status.textContent = "That private key does not open this secret."
      button.disabled = false
      return
    }
    status.textContent = payload.burn
      ? "The secret was deleted, and the key does not open it."
      : "The key does not open this secret."
    if (!payload.burn) button.disabled = false
  }
}

async function encrypt(plain) {
  const raw = crypto.getRandomValues(new Uint8Array(32))
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const key = await crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt"])
  const cipher = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    new TextEncoder().encode(plain),
  ))
  const payload = new Uint8Array(iv.length + cipher.length)
  payload.set(iv, 0)
  payload.set(cipher, iv.length)
  return { ciphertext: b64url(payload), key: b64url(raw) }
}

async function encryptToRecipient(plain, publicKeyText) {
  const recipient = await importPublicKey(publicKeyText)
  const ephemeral = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"],
  )
  const ephRaw = new Uint8Array(await crypto.subtle.exportKey("raw", ephemeral.publicKey))
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const key = await sharedKey(ephemeral.privateKey, recipient, ["encrypt"])
  const cipher = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    new TextEncoder().encode(plain),
  ))
  const payload = new Uint8Array(ephRaw.length + iv.length + cipher.length)
  payload.set(ephRaw, 0)
  payload.set(iv, ephRaw.length)
  payload.set(cipher, ephRaw.length + iv.length)
  return { ciphertext: b64url(payload) }
}

async function decryptWithRecipient(ciphertext, privateKeyText) {
  const payload = fromB64url(ciphertext)
  if (payload.length < PUBLIC_KEY_BYTES + 12 + 16 || payload[0] !== 4) throw new Error("short")
  const ephRaw = payload.slice(0, PUBLIC_KEY_BYTES)
  const iv = payload.slice(PUBLIC_KEY_BYTES, PUBLIC_KEY_BYTES + 12)
  const cipher = payload.slice(PUBLIC_KEY_BYTES + 12)
  const privateKey = await importPrivateKey(privateKeyText)
  const ephemeral = await crypto.subtle.importKey(
    "raw",
    ephRaw,
    { name: "ECDH", namedCurve: "P-256" },
    false,
    [],
  )
  const key = await sharedKey(privateKey, ephemeral, ["decrypt"])
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, cipher)
  return new TextDecoder().decode(plain)
}

async function sharedKey(privateKey, publicKey, usages) {
  const bits = await crypto.subtle.deriveBits(
    { name: "ECDH", public: publicKey },
    privateKey,
    256,
  )
  const base = await crypto.subtle.importKey("raw", bits, "HKDF", false, ["deriveKey"])
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: KEY_SALT, info: KEY_INFO },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    usages,
  )
}

async function importPublicKey(text) {
  const raw = fromB64url(text.trim())
  if (raw.length !== PUBLIC_KEY_BYTES || raw[0] !== 4) throw new Error("key")
  return crypto.subtle.importKey(
    "raw",
    raw,
    { name: "ECDH", namedCurve: "P-256" },
    false,
    [],
  )
}

async function importPrivateKey(text) {
  return crypto.subtle.importKey(
    "pkcs8",
    fromB64url(text.trim()),
    { name: "ECDH", namedCurve: "P-256" },
    false,
    ["deriveBits"],
  )
}

async function decrypt(ciphertext, keyText) {
  const payload = fromB64url(ciphertext)
  const iv = payload.slice(0, 12)
  const cipher = payload.slice(12)
  const key = await crypto.subtle.importKey("raw", fromB64url(keyText), "AES-GCM", false, ["decrypt"])
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, cipher)
  return new TextDecoder().decode(plain)
}

function renderKey() {
  const identity = readIdentity()
  if (!identity) {
    root.innerHTML = `
      <form class="card" id="hold">
        <a class="button quiet back" href="/">Back</a>
        <p>The public key locks a secret. The private key is the only key that opens it. It stays in this browser. ChronoLock never receives it. If you lose the private key, the secret cannot be opened.</p>
        <button type="button" id="create-key">Generate new key pair</button>
        <button type="button" class="text-action" id="show-import">Import an existing key</button>
        <div id="import-panel" hidden>
          <label for="backup">Private key</label>
          <textarea id="backup" class="keytext" autocomplete="off" spellcheck="false"></textarea>
          <button type="submit">Import existing key</button>
        </div>
        <p class="status" id="status" role="status"></p>
      </form>
    `
    document.querySelector("#show-import").addEventListener("click", () => {
      const panel = document.querySelector("#import-panel")
      panel.hidden = false
      document.querySelector("#backup").focus()
    })
    document.querySelector("#create-key").addEventListener("click", async () => {
      const button = document.querySelector("#create-key")
      const status = document.querySelector("#status")
      button.disabled = true
      button.textContent = "Creating…"
      try {
        renderBackup(await generateIdentity())
      } catch {
        button.disabled = false
        button.textContent = "Generate new key pair"
        status.textContent = "This browser could not create a key."
      }
    })
    document.querySelector("#hold").addEventListener("submit", async (event) => {
      event.preventDefault()
      const status = document.querySelector("#status")
      const backup = document.querySelector("#backup").value
      if (!backup.trim()) {
        status.textContent = "Paste a private key first."
        return
      }
      try {
        await holdBackup(backup)
        renderKey()
      } catch (error) {
        status.textContent = error.message === "same"
          ? "The private key has to be different from the public key."
          : "That private key is not valid."
      }
    })
    return
  }

  root.innerHTML = `
    <div class="card">
      <a class="button quiet back" href="/">Back</a>
      <p>This browser holds the private key. Give the public key to the person who will send the secret. ChronoLock never receives the private key.</p>
      <label for="public-key">Public key <span class="badge">Safe to share</span></label>
      <div class="key-row">
        <input id="public-key" class="keytext" type="text" readonly>
        <button type="button" id="copy-public">Copy public key</button>
      </div>
      <div class="warn" role="note">If you lose this private key, a secret locked with the public key cannot be opened. ChronoLock cannot recover it.</div>
      <button type="button" id="show-private">Reveal private key</button>
      <div id="private-panel" hidden>
        <label for="private-key">Private key</label>
        <textarea id="private-key" class="keytext" readonly></textarea>
        <div class="actions">
          <button type="button" id="download-private">Download private key</button>
          <button type="button" class="button quiet" id="copy-private">Copy private key</button>
          <button type="button" class="button quiet" id="hide-private">Hide private key</button>
        </div>
      </div>
      <button type="button" class="button quiet" id="remove-key">Delete local keys</button>
      <p class="status" id="status" role="status"></p>
    </div>
  `
  document.querySelector("#public-key").value = identity.publicKey
  document.querySelector("#copy-public").addEventListener("click", () => copyValue(identity.publicKey, "Public key copied."))
  document.querySelector("#show-private").addEventListener("click", () => {
    const panel = document.querySelector("#private-panel")
    document.querySelector("#private-key").value = identity.privateKey
    panel.hidden = false
    document.querySelector("#show-private").hidden = true
  })
  document.querySelector("#hide-private").addEventListener("click", () => {
    document.querySelector("#private-key").value = ""
    document.querySelector("#private-panel").hidden = true
    document.querySelector("#show-private").hidden = false
  })
  document.querySelector("#download-private").addEventListener("click", () => downloadPrivateKey(identity.privateKey))
  document.querySelector("#copy-private").addEventListener("click", () => copyValue(identity.privateKey, "Private key copied."))
  const remove = document.querySelector("#remove-key")
  remove.addEventListener("click", () => {
    if (remove.dataset.armed !== "yes") {
      remove.dataset.armed = "yes"
      remove.textContent = "Delete the key"
      return
    }
    localStorage.removeItem(KEY_STORE)
    renderKey()
  })
}

function renderBackup(identity) {
  root.innerHTML = `
    <div class="card">
      <button type="button" class="button quiet back" id="cancel-key">Back</button>
      <p>Save the private key before this browser keeps it. Nothing is stored until you confirm.</p>
      <label for="public-key">Public key <span class="badge">Safe to share</span></label>
      <div class="key-row">
        <input id="public-key" class="keytext" type="text" readonly>
        <button type="button" id="copy-public">Copy public key</button>
      </div>
      <label for="private-key">Private key</label>
      <textarea id="private-key" class="keytext" readonly></textarea>
      <div class="actions">
        <button type="button" id="download-private">Download private key</button>
        <button type="button" class="button quiet" id="copy-private">Copy private key</button>
      </div>
      <div class="warn" role="note">If you lose this private key, a secret locked with the public key cannot be opened. ChronoLock cannot recover it.</div>
      <label class="choice" for="saved-key"><input id="saved-key" type="checkbox"> I have saved my private key</label>
      <button type="button" id="confirm-key" disabled>Confirm and continue</button>
      <p class="status" id="status" role="status"></p>
    </div>
  `
  document.querySelector("#public-key").value = identity.publicKey
  document.querySelector("#private-key").value = identity.privateKey
  document.querySelector("#copy-public").addEventListener("click", () => copyValue(identity.publicKey, "Public key copied."))
  document.querySelector("#copy-private").addEventListener("click", () => copyValue(identity.privateKey, "Private key copied."))
  document.querySelector("#download-private").addEventListener("click", () => downloadPrivateKey(identity.privateKey))
  document.querySelector("#saved-key").addEventListener("change", (event) => {
    document.querySelector("#confirm-key").disabled = !event.target.checked
  })
  document.querySelector("#confirm-key").addEventListener("click", () => {
    assertDifferent(identity.publicKey, identity.privateKey)
    writeIdentity(identity)
    renderKey()
  })
  document.querySelector("#cancel-key").addEventListener("click", () => renderKey())
}

async function generateIdentity() {
  const pair = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"],
  )
  const identity = {
    publicKey: b64url(new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey))),
    privateKey: b64url(new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey))),
  }
  assertDifferent(identity.publicKey, identity.privateKey)
  return identity
}

function downloadPrivateKey(privateKey) {
  const file = new Blob([privateKey + "\n"], { type: "text/plain" })
  const url = URL.createObjectURL(file)
  const link = document.createElement("a")
  link.href = url
  link.download = "chronolock-private-key.txt"
  document.body.appendChild(link)
  link.click()
  link.remove()
  URL.revokeObjectURL(url)
}

async function holdBackup(text) {
  const trimmed = text.trim()
  let privateKey = trimmed
  let statedPublic = ""
  if (trimmed.includes(".")) {
    const parsed = parseBackup(trimmed)
    assertDifferent(parsed.publicKey, parsed.privateKey)
    statedPublic = parsed.publicKey
    privateKey = parsed.privateKey
  }
  const identity = await identityFromPrivate(privateKey)
  if (statedPublic && statedPublic !== identity.publicKey) throw new Error("key")
  writeIdentity(identity)
}

async function identityFromPrivate(privateKeyText) {
  const key = await crypto.subtle.importKey(
    "pkcs8",
    fromB64url(privateKeyText),
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"],
  )
  const jwk = await crypto.subtle.exportKey("jwk", key)
  if (!jwk.x || !jwk.y) throw new Error("key")
  const raw = new Uint8Array(65)
  raw[0] = 4
  raw.set(fixed32(fromB64url(jwk.x)), 1)
  raw.set(fixed32(fromB64url(jwk.y)), 33)
  const publicKey = b64url(raw)
  assertDifferent(publicKey, privateKeyText)
  await importPublicKey(publicKey)
  return { publicKey, privateKey: privateKeyText }
}

function fixed32(bytes) {
  if (bytes.length > 32) throw new Error("key")
  const out = new Uint8Array(32)
  out.set(bytes, 32 - bytes.length)
  return out
}

function assertDifferent(publicKey, privateKey) {
  if (!publicKey || !privateKey || publicKey === privateKey) throw new Error("same")
}

function normalizeIdentity(identity) {
  let privateKey = identity.privateKey
  const prefix = identity.publicKey + "."
  if (privateKey.startsWith(prefix)) privateKey = privateKey.slice(prefix.length)
  assertDifferent(identity.publicKey, privateKey)
  return { publicKey: identity.publicKey, privateKey }
}

function parseBackup(text) {
  const parts = text.trim().split(".")
  if (parts.length !== 2 || !parts[0] || !parts[1]) throw new Error("key")
  assertDifferent(parts[0], parts[1])
  return { publicKey: parts[0], privateKey: parts[1] }
}

function privateMaterial(text) {
  const trimmed = text.trim()
  if (!trimmed.includes(".")) return trimmed
  return parseBackup(trimmed).privateKey
}

function privateMaterialFromText(text) {
  const trimmed = text.trim().replace(/^\uFEFF/, "")
  const match = trimmed.match(/-----BEGIN ([A-Z0-9 ]+)-----([A-Za-z0-9+/=\s]+)-----END \1-----/)
  if (!match) return privateMaterial(trimmed)
  if (match[1] === "PUBLIC KEY" || match[1] === "EC PUBLIC KEY") throw new Error("public")
  if (match[1] === "ENCRYPTED PRIVATE KEY") throw new Error("encrypted")
  const der = fromB64url(match[2].replace(/\s/g, ""))
  if (match[1] === "PRIVATE KEY") return b64url(der)
  if (match[1] === "EC PRIVATE KEY") return b64url(pkcs8FromSec1(der))
  throw new Error("key")
}

function pkcs8FromSec1(sec1) {
  const version = Uint8Array.of(0x02, 0x01, 0x00)
  const ecOid = Uint8Array.of(0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01)
  const p256 = Uint8Array.of(0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07)
  return der(0x30, joinBytes([version, der(0x30, joinBytes([ecOid, p256])), der(0x04, sec1)]))
}

function der(tag, content) {
  const length = derLen(content.length)
  const out = new Uint8Array(1 + length.length + content.length)
  out[0] = tag
  out.set(length, 1)
  out.set(content, 1 + length.length)
  return out
}

function derLen(length) {
  if (length < 0x80) return Uint8Array.of(length)
  const bytes = []
  let rest = length
  while (rest > 0) {
    bytes.unshift(rest & 0xff)
    rest = Math.floor(rest / 256)
  }
  return Uint8Array.of(0x80 | bytes.length, ...bytes)
}

function joinBytes(parts) {
  const size = parts.reduce((sum, part) => sum + part.length, 0)
  const out = new Uint8Array(size)
  let offset = 0
  parts.forEach((part) => {
    out.set(part, offset)
    offset += part.length
  })
  return out
}

function keyFileMessage(error) {
  if (error.message === "same") return "The private key has to be different from the public key."
  if (error.message === "public") return "That file is a public key. Load the private key."
  if (error.message === "encrypted") return "That key file is encrypted. ChronoLock needs an unencrypted private key."
  return "That private key is not valid."
}

function readIdentity() {
  try {
    const saved = JSON.parse(localStorage.getItem(KEY_STORE) || "")
    if (!saved || typeof saved.publicKey !== "string" || typeof saved.privateKey !== "string") return null
    const identity = normalizeIdentity(saved)
    if (saved.privateKey !== identity.privateKey) writeIdentity(identity)
    return identity
  } catch {
    return null
  }
}

function writeIdentity(identity) {
  localStorage.setItem(KEY_STORE, JSON.stringify({
    publicKey: identity.publicKey,
    privateKey: identity.privateKey,
  }))
}

function b64url(bytes) {
  let bin = ""
  bytes.forEach((byte) => {
    bin += String.fromCharCode(byte)
  })
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "")
}

function fromB64url(text) {
  const pad = text.length % 4 === 0 ? "" : "=".repeat(4 - (text.length % 4))
  const bin = atob(text.replace(/-/g, "+").replace(/_/g, "/") + pad)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i)
  return out
}

async function copyValue(value, message) {
  try {
    await navigator.clipboard.writeText(value)
    toast(message || "Copied.")
  } catch {
    const status = document.querySelector("#status")
    if (status) status.textContent = "Select the text and copy it."
  }
}

let toastTimer = 0
function toast(message) {
  let node = document.querySelector("#toast")
  if (!node) {
    node = document.createElement("p")
    node.id = "toast"
    node.className = "toast"
    node.setAttribute("role", "status")
    document.body.appendChild(node)
  }
  node.hidden = false
  node.textContent = message
  clearTimeout(toastTimer)
  toastTimer = setTimeout(() => {
    node.hidden = true
  }, 2000)
}

function refreshLimit() {
  const field = document.querySelector("#secret")
  const note = document.querySelector("#limit")
  const button = document.querySelector("#create button")
  const bytes = new TextEncoder().encode(field.value).length
  const over = bytes > MAX_BYTES
  note.textContent = over ? limitMessage(bytes) : formatSize(bytes) + " of 8KB."
  note.classList.toggle("over", over)
  field.setAttribute("aria-invalid", over ? "true" : "false")
  button.disabled = over
}

function limitMessage(bytes) {
  return "That secret is " + bytes + " bytes. The limit is 8KB."
}

function formatSize(bytes) {
  if (bytes < 1024) return bytes + (bytes === 1 ? " byte" : " bytes")
  const kb = bytes / 1024
  return (Number.isInteger(kb) ? String(kb) : kb.toFixed(1)) + "KB"
}

function escapeText(value) {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
}
