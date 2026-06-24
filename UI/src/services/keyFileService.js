/**
 * keyFileService.js — Browser file I/O for .medledger key bundles
 * ──────────────────────────────────────────────────────────────────
 * Pure DOM operations. No crypto. No Worker communication.
 * Responsible only for getting bytes in and out of the browser.
 *
 * Called by useKeySession — never by components directly.
 */

const FILE_EXTENSION = ".medledger";
const FILE_MIME = "application/octet-stream";

// ─────────────────────────────────────────────────────────────────
// Download
// ─────────────────────────────────────────────────────────────────

/**
 * Trigger a browser download of the encrypted keypair bundle.
 * Called immediately after createUser() — the user saves this file locally.
 *
 * @param {string} bundleB64   — base64url bytes from keyWorker.createUser()
 * @param {string} username    — used to name the file
 */
export function downloadKeyFile(bundleB64, username) {
  // Decode base64url to raw bytes
  const padded = bundleB64.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  const blob = new Blob([bytes], { type: FILE_MIME });
  const url = URL.createObjectURL(blob);

  const filename = `${sanitizeFilename(username)}${FILE_EXTENSION}`;

  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.style.display = "none";
  document.body.appendChild(anchor);
  anchor.click();

  // Clean up after a tick — revoking too soon aborts the download
  setTimeout(() => {
    URL.revokeObjectURL(url);
    document.body.removeChild(anchor);
  }, 1000);
}

// ─────────────────────────────────────────────────────────────────
// Upload / read
// ─────────────────────────────────────────────────────────────────

/**
 * Open a file picker filtered to .medledger files.
 * Reads the selected file and returns its bytes as a base64url string,
 * ready to pass directly to keyWorker.loadAndUnlock().
 *
 * @returns {Promise<{ bundleB64: string, filename: string }>}
 * @throws {Error} if user cancels or file read fails
 */
export function pickAndReadKeyFile() {
  return new Promise((resolve, reject) => {
    const input = document.createElement("input");
    input.type = "file";
    input.accept = FILE_EXTENSION;
    input.style.display = "none";
    document.body.appendChild(input);

    let settled = false;

    input.onchange = () => {
      if (settled) return;
      const file = input.files?.[0];
      if (!file) {
        settled = true;
        document.body.removeChild(input);
        reject(new Error("No file selected"));
        return;
      }

      const reader = new FileReader();
      reader.onload = () => {
        settled = true;
        document.body.removeChild(input);
        const arrayBuffer = reader.result;
        const bytes = new Uint8Array(arrayBuffer);
        const bundleB64 = uint8ToBase64Url(bytes);
        resolve({ bundleB64, filename: file.name });
      };
      reader.onerror = () => {
        settled = true;
        document.body.removeChild(input);
        reject(new Error(`Failed to read file: ${reader.error?.message ?? "unknown error"}`));
      };
      reader.readAsArrayBuffer(file);
    };

    // Handle cancel — focus returns to window after picker closes
    // We give the browser a moment to fire onchange first
    window.addEventListener(
      "focus",
      () => {
        setTimeout(() => {
          if (!settled) {
            settled = true;
            if (document.body.contains(input)) document.body.removeChild(input);
            reject(new Error("File picker cancelled"));
          }
        }, 500);
      },
      { once: true },
    );

    input.click();
  });
}

// ─────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────

function uint8ToBase64Url(bytes) {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function sanitizeFilename(str) {
  // Keep alphanumeric, dash, underscore — strip everything else
  return str.replace(/[^a-zA-Z0-9_-]/g, "_").slice(0, 64) || "medledger_key";
}
