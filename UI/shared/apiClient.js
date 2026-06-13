// shared/apiClient.js
/**
 * MedLedger API Client
 * 
 * Thin wrapper around fetch() with:
 *   - JSON body serialization
 *   - Automatic error handling (throws on non-2xx)
 *   - CSRF token header injection
 *   - Base URL prefixing
 *   - Request/response logging in dev mode
 */

const BASE_URL = "";
// Set this to your API origin if different from the frontend, e.g.:
// const BASE_URL = import.meta.env.VITE_API_URL || "";

/**
 * Get CSRF token from meta tag or cookie
 */
function getCsrfToken() {
  const meta = document.querySelector('meta[name="csrf-token"]');
  if (meta) return meta.content;
  // Fallback: parse from cookie
  const match = document.cookie.match(/csrf_token=([^;]+)/);
  return match ? decodeURIComponent(match[1]) : null;
}

/**
 * Core request handler
 */
async function request(method, path, body = null, extraHeaders = {}) {
  const url = `${BASE_URL}${path}`;
  const headers = {
    "Accept": "application/json",
    "Content-Type": "application/json",
    ...extraHeaders,
  };

  const csrf = getCsrfToken();
  if (csrf) {
    headers["X-CSRF-Token"] = csrf;
  }

  const opts = {
    method,
    headers,
    credentials: "same-origin",
  };

  if (body !== null) {
    opts.body = JSON.stringify(body);
  }

  if (process.env.NODE_ENV === "development") {
    console.log(`[API] ${method} ${url}`, body);
  }

  const response = await fetch(url, opts);

  // Parse JSON or text depending on Content-Type
  let data;
  const contentType = response.headers.get("content-type") || "";
  if (contentType.includes("application/json")) {
    data = await response.json();
  } else {
    data = await response.text();
  }

  if (!response.ok) {
    const error = new Error(
      data?.message || data || `HTTP ${response.status}: ${response.statusText}`
    );
    error.status = response.status;
    error.data = data;
    error.path = path;
    throw error;
  }

  return data;
}

/**
 * Exported API client methods
 */
export const apiClient = {
  /**
   * GET request
   * @param {string} path - API path (e.g. "/api/me")
   * @param {object} [params] - Query parameters (auto-serialized)
   * @returns {Promise<any>}
   */
  get(path, params = null) {
    let url = path;
    if (params) {
      const qs = new URLSearchParams(params).toString();
      url += `?${qs}`;
    }
    return request("GET", url, null);
  },

  /**
   * POST request
   * @param {string} path - API path
   * @param {object} body - JSON body
   * @returns {Promise<any>}
   */
  post(path, body) {
    return request("POST", path, body);
  },

  /**
   * PUT request
   * @param {string} path - API path
   * @param {object} body - JSON body
   * @returns {Promise<any>}
   */
  put(path, body) {
    return request("PUT", path, body);
  },

  /**
   * DELETE request
   * @param {string} path - API path
   * @returns {Promise<any>}
   */
  delete(path) {
    return request("DELETE", path, null);
  },

  /**
   * Upload a file with multipart/form-data
   * @param {string} path - API path
   * @param {FormData} formData - FormData instance
   * @returns {Promise<any>}
   */
  upload(path, formData) {
    const url = `${BASE_URL}${path}`;
    const headers = {};
    const csrf = getCsrfToken();
    if (csrf) headers["X-CSRF-Token"] = csrf;

    return fetch(url, {
      method: "POST",
      headers,
      body: formData,
      credentials: "same-origin",
    }).then(async (res) => {
      let data;
      const ct = res.headers.get("content-type") || "";
      if (ct.includes("application/json")) {
        data = await res.json();
      } else {
        data = await res.text();
      }
      if (!res.ok) {
        const err = new Error(data?.message || data || `HTTP ${res.status}`);
        err.status = res.status;
        err.data = data;
        throw err;
      }
      return data;
    });
  },
};

export default apiClient;
