"use strict";

const TOPIC_PATTERN = /^[a-z0-9-]{40,64}$/;
const REQUEST_PATTERN = /^[a-f0-9]{24}$/;
const PROFILE_PATTERN = /^[a-f0-9]{32}$/;
const VERIFIER_TEXT = "ticketflow-remote-unlock-ok-v1";
const VERIFIER_AAD_PREFIX = "ticketflow-remote-unlock-verifier-v1|";

const statusPanel = document.getElementById("status-panel");
const statusTitle = document.getElementById("status-title");
const statusMessage = document.getElementById("status-message");
const unlockForm = document.getElementById("unlock-form");
const passwordInput = document.getElementById("profile-password");
const visibilityButton = document.getElementById("visibility-button");
const unlockButton = document.getElementById("unlock-button");
const successBody = document.getElementById("success-body");

let payload;
let state = "loading";

function fromBase64Url(value) {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error("잘못된 보안 데이터입니다.");
  }
  const padded = value.replace(/-/g, "+").replace(/_/g, "/")
    + "=".repeat((4 - (value.length % 4)) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function toBase64Url(value) {
  let binary = "";
  for (let index = 0; index < value.length; index += 1) {
    binary += String.fromCharCode(value[index]);
  }
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function decodePayload() {
  const hash = window.location.hash.replace(/^#/, "");
  const parameters = new URLSearchParams(hash);
  const encoded = parameters.get("p");
  if (!encoded) {
    throw new Error(
      "잠금 해제 요청 정보가 없습니다. ntfy 알림에서 ‘잠금번호 입력’을 다시 눌러주세요.",
    );
  }

  const decoded = new TextDecoder().decode(fromBase64Url(encoded));
  const candidate = JSON.parse(decoded);
  if (
    candidate.v !== 1
    || !REQUEST_PATTERN.test(candidate.requestId ?? "")
    || !PROFILE_PATTERN.test(candidate.profileId ?? "")
    || typeof candidate.profileName !== "string"
    || candidate.profileName.length < 1
    || candidate.profileName.length > 30
    || typeof candidate.expiresAt !== "number"
    || !Number.isSafeInteger(candidate.expiresAt)
    || typeof candidate.serverUrl !== "string"
    || !TOPIC_PATTERN.test(candidate.responseTopic ?? "")
    || typeof candidate.publicKey !== "string"
    || typeof candidate.salt !== "string"
    || typeof candidate.iterations !== "number"
    || candidate.iterations < 100_000
    || candidate.iterations > 2_000_000
    || typeof candidate.verifierNonce !== "string"
    || typeof candidate.verifierCiphertext !== "string"
    || typeof candidate.verifierTag !== "string"
  ) {
    throw new Error("잠금 해제 요청의 형식이 올바르지 않습니다.");
  }

  const server = new URL(candidate.serverUrl);
  if (server.protocol !== "https:" || server.username || server.password) {
    throw new Error("안전하지 않은 알림 서버 주소입니다.");
  }
  if (candidate.expiresAt <= Math.floor(Date.now() / 1000)) {
    throw new Error(
      "잠금 해제 요청 시간이 만료됐습니다. PC 프로그램에서 새 요청을 보내주세요.",
    );
  }
  return candidate;
}

function setState(kind, message, title) {
  state = kind;
  statusPanel.className = `status-panel status-${kind}`;
  statusTitle.textContent = title;
  statusMessage.textContent = message;

  const readyForInput = Boolean(payload)
    && kind !== "working"
    && kind !== "success";
  passwordInput.disabled = !readyForInput;
  visibilityButton.disabled = !readyForInput;
  unlockButton.disabled = !readyForInput || passwordInput.value.length < 8;
  unlockButton.textContent = kind === "working"
    ? "처리 중…"
    : "이 PC 프로그램 잠금 해제";

  const succeeded = kind === "success";
  successBody.hidden = !succeeded;
  unlockForm.hidden = succeeded;
}

async function deriveAndVerifyKey(password, request) {
  const passwordBytes = new TextEncoder().encode(password);
  const salt = fromBase64Url(request.salt);
  let rawKey;
  try {
    const keyMaterial = await crypto.subtle.importKey(
      "raw",
      passwordBytes,
      "PBKDF2",
      false,
      ["deriveBits"],
    );
    const bits = await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        salt,
        iterations: request.iterations,
        hash: "SHA-256",
      },
      keyMaterial,
      256,
    );
    rawKey = new Uint8Array(bits);
    const aesKey = await crypto.subtle.importKey(
      "raw",
      rawKey,
      { name: "AES-GCM" },
      false,
      ["decrypt"],
    );
    const ciphertext = fromBase64Url(request.verifierCiphertext);
    const tag = fromBase64Url(request.verifierTag);
    const combined = new Uint8Array(ciphertext.length + tag.length);
    combined.set(ciphertext);
    combined.set(tag, ciphertext.length);
    const plaintext = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: fromBase64Url(request.verifierNonce),
        additionalData: new TextEncoder().encode(
          `${VERIFIER_AAD_PREFIX}${request.profileId}`,
        ),
        tagLength: 128,
      },
      aesKey,
      combined,
    );
    if (new TextDecoder().decode(plaintext) !== VERIFIER_TEXT) {
      throw new Error("잠금번호가 올바르지 않습니다.");
    }
    return rawKey;
  } catch (error) {
    rawKey?.fill(0);
    if (error instanceof Error && error.message.includes("잠금번호")) {
      throw error;
    }
    throw new Error("잠금번호가 올바르지 않습니다.");
  } finally {
    passwordBytes.fill(0);
    salt.fill(0);
  }
}

async function encryptKey(rawKey, publicKey) {
  const key = await crypto.subtle.importKey(
    "spki",
    fromBase64Url(publicKey),
    { name: "RSA-OAEP", hash: "SHA-256" },
    false,
    ["encrypt"],
  );
  const encrypted = await crypto.subtle.encrypt(
    { name: "RSA-OAEP" },
    key,
    rawKey,
  );
  return toBase64Url(new Uint8Array(encrypted));
}

passwordInput.addEventListener("input", () => {
  unlockButton.disabled = state === "working"
    || state === "success"
    || !payload
    || passwordInput.value.length < 8;
});

visibilityButton.addEventListener("click", () => {
  const show = passwordInput.type === "password";
  passwordInput.type = show ? "text" : "password";
  visibilityButton.textContent = show ? "숨김" : "표시";
  visibilityButton.setAttribute(
    "aria-label",
    show ? "잠금번호 숨기기" : "잠금번호 표시",
  );
  passwordInput.focus();
});

unlockForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!payload || state === "working") return;
  if (passwordInput.value.length < 8 || passwordInput.value.length > 64) {
    setState(
      "error",
      "프로필 잠금번호를 8~64자로 입력해주세요.",
      "확인이 필요합니다",
    );
    passwordInput.focus();
    return;
  }

  let rawKey;
  try {
    setState(
      "working",
      "휴대폰 안에서 잠금번호를 확인하고 있습니다.",
      "안전하게 처리 중",
    );
    rawKey = await deriveAndVerifyKey(passwordInput.value, payload);
    passwordInput.value = "";
    setState(
      "working",
      "일회용 암호화 응답을 PC로 보내고 있습니다.",
      "안전하게 처리 중",
    );
    const encryptedKey = await encryptKey(rawKey, payload.publicKey);
    const responseUrl = new URL(
      `/${encodeURIComponent(payload.responseTopic)}`,
      payload.serverUrl,
    );
    responseUrl.searchParams.set("cache", "no");
    const response = await fetch(responseUrl, {
      method: "POST",
      headers: { "Content-Type": "text/plain;charset=UTF-8" },
      body: JSON.stringify({
        kind: "remote_unlock",
        requestId: payload.requestId,
        encryptedKey,
        expiresAt: payload.expiresAt,
      }),
      cache: "no-store",
      referrerPolicy: "no-referrer",
    });
    if (!response.ok) {
      throw new Error("응답 서버에 연결하지 못했습니다. 잠시 후 다시 시도해주세요.");
    }
    history.replaceState(null, "", `${location.pathname}${location.search}`);
    setState(
      "success",
      `${payload.profileName} 프로필이 실행 중인 PC에서 잠금 해제됩니다.`,
      "잠금 해제 요청 전송 완료",
    );
  } catch (error) {
    setState(
      "error",
      error instanceof Error
        ? error.message
        : "잠금 해제 응답을 보내지 못했습니다.",
      "확인이 필요합니다",
    );
    window.setTimeout(() => passwordInput.focus(), 0);
  } finally {
    rawKey?.fill(0);
  }
});

try {
  payload = decodePayload();
  setState(
    "ready",
    "PC에서 만든 잠금번호를 입력하면 이 실행 중인 프로그램만 잠금 해제됩니다.",
    `${payload.profileName} 프로필`,
  );
  window.setTimeout(() => passwordInput.focus(), 0);
} catch (error) {
  setState(
    "error",
    error instanceof Error
      ? error.message
      : "잠금 해제 요청을 읽지 못했습니다.",
    "확인이 필요합니다",
  );
}
