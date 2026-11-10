const MAX_BYTES = 65536

const root = document.querySelector("#app")
const path = location.pathname.split("/").filter(Boolean)

if (!crypto.subtle) {
  renderSecureContext()
} else if (path[0] === "s" && path[1]) {
  renderReveal(path[1])
} else {
  renderCreate()
}

function renderSecureContext() {
  root.innerHTML = `
    <h1>NueM8 ChronoLock</h1>
    <p class="lede">Open this page over HTTPS, or on localhost. This browser will not encrypt a secret on an insecure page.</p>
  `
}

function renderCreate() {
  root.innerHTML = `
    <h1>NueM8 ChronoLock</h1>
    <p class="lede">A secret link that dies. The secret is encrypted in this browser before it is stored. ChronoLock keeps the ciphertext only. It has no accounts and it does not phone home.</p>
    <form class="card" id="create">
      <label for="secret">Secret</label>
      <textarea id="secret" name="secret" autocomplete="off" spellcheck="false" required></textarea>
      <label for="ttl">Lifetime</label>
      <select id="ttl" name="ttl">
        <option value="300">5 minutes</option>
        <option value="3600" selected>1 hour</option>
        <option value="86400">1 day</option>
        <option value="604800">7 days</option>
      </select>
      <label class="choice"><input id="burn" type="checkbox" checked> Delete after one reveal</label>
      <button type="submit">Create link</button>
      <p class="status" id="status" role="status"></p>
    </form>
  `
  document.querySelector("#create").addEventListener("submit", onCreate)
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
    status.textContent = "That secret is too long."
    return
  }
  status.textContent = "Encrypting…"
  const packed = await encrypt(secret)
  const response = await fetch("/api/secrets", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      ciphertext: packed.ciphertext,
      ttl_seconds: Number(document.querySelector("#ttl").value),
      burn: document.querySelector("#burn").checked,
    }),
    credentials: "omit",
    cache: "no-store",
    referrerPolicy: "no-referrer",
  })
  const payload = await response.json().catch(() => ({}))
  if (!response.ok) {
    status.textContent = payload.error || "The link was not created."
    return
  }
  const link = new URL("/s/" + payload.id, location.origin)
  link.hash = packed.key
  renderLink(link.toString(), payload.expires_at, document.querySelector("#burn").checked)
}

function renderLink(link, expiresAt, burn) {
  const when = new Date(expiresAt * 1000).toLocaleString()
  const end = burn
    ? "The secret is deleted the first time someone reveals it."
    : "The secret can be revealed until " + when + "."
  root.innerHTML = `
    <h1>NueM8 ChronoLock</h1>
    <div class="card">
      <p>Send this link. The part after # is the key. ChronoLock never receives it and cannot read the secret.</p>
      <label for="link">Secret link</label>
      <input id="link" type="text" readonly value="">
      <button type="button" id="copy">Copy link</button>
      <a class="button quiet" href="/">New secret</a>
      <p class="note">${escapeText(end)} It also dies at ${escapeText(when)}.</p>
      <p class="status" id="status" role="status"></p>
    </div>
  `
  document.querySelector("#link").value = link
  document.querySelector("#copy").addEventListener("click", () => copyValue(link))
}

function renderReveal(id) {
  const key = location.hash.replace(/^#/, "")
  root.innerHTML = `
    <h1>NueM8 ChronoLock</h1>
    <div class="card">
      <p class="lede" id="lead">A secret is waiting. Revealing it asks the server for the ciphertext, then decrypts it here.</p>
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
  if (!key) {
    document.querySelector("#lead").textContent = "This link has no key. The part after # is missing, so the secret cannot be opened."
    document.querySelector("#reveal").disabled = true
    return
  }
  document.querySelector("#reveal").addEventListener("click", () => openSecret(id, key))
}

async function openSecret(id, key) {
  const status = document.querySelector("#status")
  const button = document.querySelector("#reveal")
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
    const plain = await decrypt(payload.ciphertext, key)
    document.querySelector("#opened").hidden = false
    document.querySelector("#plain").value = plain
    document.querySelector("#copy").addEventListener("click", () => copyValue(plain))
    document.querySelector("#lead").textContent = "Opened in this browser."
    document.querySelector("#after").textContent = payload.burn
      ? "This secret has been deleted."
      : "This secret remains until " + new Date(payload.expires_at * 1000).toLocaleString() + "."
    status.textContent = ""
    button.hidden = true
  } catch {
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

async function decrypt(ciphertext, keyText) {
  const payload = fromB64url(ciphertext)
  const iv = payload.slice(0, 12)
  const cipher = payload.slice(12)
  const key = await crypto.subtle.importKey("raw", fromB64url(keyText), "AES-GCM", false, ["decrypt"])
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, cipher)
  return new TextDecoder().decode(plain)
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

async function copyValue(value) {
  const status = document.querySelector("#status")
  try {
    await navigator.clipboard.writeText(value)
    status.textContent = "Copied."
  } catch {
    status.textContent = "Select the text and copy it."
  }
}

function escapeText(value) {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
}
