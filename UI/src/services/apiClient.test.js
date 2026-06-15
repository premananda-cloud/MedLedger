/**
 * apiClient.test.js
 *
 * Unit tests for apiClient.js.
 * fetch is mocked globally — no real network calls are made.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'

// ─── Helpers ─────────────────────────────────────────────────────────────────

/** Build a mock Response that fetch() resolves to */
function mockResponse(body, { status = 200, ok = true } = {}) {
  return {
    ok,
    status,
    json: vi.fn().mockResolvedValue(body),
  }
}

// ─── Module-level fetch mock ──────────────────────────────────────────────────

// We replace the global fetch before importing so apiClient captures the mock.
const fetchMock = vi.fn()
global.fetch = fetchMock

// Import AFTER setting up the global mock
const { setToken, clearToken, hasToken, ApiError, api, authApi } =
  await import('./apiClient.js')

// ─── Reset between tests ──────────────────────────────────────────────────────

beforeEach(() => {
  fetchMock.mockReset()
  clearToken()
})

// ─────────────────────────────────────────────────────────────────────────────
// Token store
// ─────────────────────────────────────────────────────────────────────────────

describe('setToken / clearToken / hasToken', () => {
  it('starts with no token', () => {
    expect(hasToken()).toBe(false)
  })

  it('setToken stores a token and hasToken returns true', () => {
    setToken('my-jwt')
    expect(hasToken()).toBe(true)
  })

  it('clearToken removes the token', () => {
    setToken('my-jwt')
    clearToken()
    expect(hasToken()).toBe(false)
  })

  it('setToken throws on empty string', () => {
    expect(() => setToken('')).toThrow('non-empty string')
  })

  it('setToken throws on non-string values', () => {
    expect(() => setToken(null)).toThrow()
    expect(() => setToken(42)).toThrow()
    expect(() => setToken(undefined)).toThrow()
  })
})

// ─────────────────────────────────────────────────────────────────────────────
// ApiError
// ─────────────────────────────────────────────────────────────────────────────

describe('ApiError', () => {
  it('is an instance of Error', () => {
    const err = new ApiError('oops', 404, 'NOT_FOUND')
    expect(err).toBeInstanceOf(Error)
  })

  it('exposes .message, .status, .code, and .name', () => {
    const err = new ApiError('not found', 404, 'NOT_FOUND')
    expect(err.message).toBe('not found')
    expect(err.status).toBe(404)
    expect(err.code).toBe('NOT_FOUND')
    expect(err.name).toBe('ApiError')
  })

  it('defaults code to null when omitted', () => {
    const err = new ApiError('server error', 500)
    expect(err.code).toBeNull()
  })
})

// ─────────────────────────────────────────────────────────────────────────────
// api.get / api.post  (core request helper)
// ─────────────────────────────────────────────────────────────────────────────

describe('api — successful requests', () => {
  it('GET returns data from envelope', async () => {
    fetchMock.mockResolvedValue(mockResponse({ data: { id: 1 } }))
    const result = await api.get('/things/1')
    expect(result).toEqual({ id: 1 })
  })

  it('POST sends the body as JSON and returns data', async () => {
    fetchMock.mockResolvedValue(mockResponse({ data: { created: true } }))
    const result = await api.post('/things', { name: 'test' })

    expect(result).toEqual({ created: true })

    const [url, opts] = fetchMock.mock.calls[0]
    expect(opts.method).toBe('POST')
    expect(JSON.parse(opts.body)).toEqual({ name: 'test' })
  })

  it('falls back to the whole envelope when data field is absent', async () => {
    fetchMock.mockResolvedValue(mockResponse({ userId: '123' }))
    const result = await api.get('/me')
    expect(result).toEqual({ userId: '123' })
  })

  it('attaches Authorization header when a token is set', async () => {
    setToken('secret-jwt')
    fetchMock.mockResolvedValue(mockResponse({ data: null }))
    await api.get('/protected')

    const [, opts] = fetchMock.mock.calls[0]
    expect(opts.headers['Authorization']).toBe('Bearer secret-jwt')
  })

  it('omits Authorization header when no token is set', async () => {
    fetchMock.mockResolvedValue(mockResponse({ data: null }))
    await api.get('/public')

    const [, opts] = fetchMock.mock.calls[0]
    expect(opts.headers['Authorization']).toBeUndefined()
  })

  it('GET does not include a body', async () => {
    fetchMock.mockResolvedValue(mockResponse({ data: [] }))
    await api.get('/list')

    const [, opts] = fetchMock.mock.calls[0]
    expect(opts.body).toBeUndefined()
  })
})

describe('api — error handling', () => {
  it('throws ApiError with NETWORK_ERROR on fetch failure', async () => {
    fetchMock.mockRejectedValue(new Error('DNS lookup failed'))

    await expect(api.get('/anything')).rejects.toMatchObject({
      name: 'ApiError',
      code: 'NETWORK_ERROR',
      status: 0,
    })
  })

  it('throws ApiError with PARSE_ERROR when response is not JSON', async () => {
    fetchMock.mockResolvedValue({
      ok: false,
      status: 502,
      json: vi.fn().mockRejectedValue(new SyntaxError('bad json')),
    })

    await expect(api.get('/bad')).rejects.toMatchObject({
      name: 'ApiError',
      code: 'PARSE_ERROR',
      status: 502,
    })
  })

  it('throws ApiError on 4xx with server error message', async () => {
    fetchMock.mockResolvedValue(
      mockResponse(
        { error: { message: 'Invalid signature', code: 'INVALID_SIGNATURE' } },
        { status: 401, ok: false }
      )
    )

    await expect(api.post('/auth/login', {})).rejects.toMatchObject({
      name: 'ApiError',
      message: 'Invalid signature',
      status: 401,
      code: 'INVALID_SIGNATURE',
    })
  })

  it('falls back to HTTP status as message when error envelope is missing', async () => {
    fetchMock.mockResolvedValue(
      mockResponse({}, { status: 500, ok: false })
    )

    const err = await api.get('/boom').catch((e) => e)
    expect(err.message).toBe('HTTP 500')
    expect(err.status).toBe(500)
  })

  // ─── NEW: envelope ok === false tests ─────────────────────────────────────

  it('throws ApiError when HTTP 200 but envelope ok is false', async () => {
    fetchMock.mockResolvedValue(
      mockResponse(
        { ok: false, error: { message: 'Rate limited', code: 'RATE_LIMIT' } },
        { status: 200, ok: true }
      )
    )

    const err = await api.get('/limited').catch((e) => e)
    expect(err).toBeInstanceOf(ApiError)
    expect(err.message).toBe('Rate limited')
    expect(err.code).toBe('RATE_LIMIT')
    expect(err.status).toBe(200)
  })

  it('throws ApiError with ok: false even when error object is minimal', async () => {
    fetchMock.mockResolvedValue(
      mockResponse(
        { ok: false, detail: 'Something went wrong' },
        { status: 200, ok: true }
      )
    )

    const err = await api.post('/submit', {}).catch((e) => e)
    expect(err.message).toBe('Something went wrong')
    expect(err.status).toBe(200)
    expect(err.code).toBeNull()
  })

  it('does not throw when ok is true and response is HTTP 200', async () => {
    fetchMock.mockResolvedValue(
      mockResponse(
        { ok: true, data: { success: true } },
        { status: 200, ok: true }
      )
    )

    const result = await api.get('/success')
    expect(result).toEqual({ success: true })
  })

  it('does not throw when ok field is absent (legacy envelope)', async () => {
    fetchMock.mockResolvedValue(
      mockResponse({ data: { legacy: true } }, { status: 200, ok: true })
    )

    const result = await api.get('/legacy')
    expect(result).toEqual({ legacy: true })
  })
})

// ─────────────────────────────────────────────────────────────────────────────
// authApi thin wrappers
// ─────────────────────────────────────────────────────────────────────────────

describe('authApi', () => {
  it('initPoW calls GET /auth/pow/init', async () => {
    fetchMock.mockResolvedValue(
      mockResponse({ data: { challenge_id: 'c1', challenge: 'abc', difficulty: 4 } })
    )
    await authApi.initPoW()
    expect(fetchMock.mock.calls[0][0]).toMatch('/auth/pow/init')
    expect(fetchMock.mock.calls[0][1].method).toBe('GET')
  })

  it('verifyPoW POSTs challenge_id and nonce', async () => {
    fetchMock.mockResolvedValue(mockResponse({ data: { sessionToken: 'tok' } }))
    await authApi.verifyPoW('c1', '99')
    const body = JSON.parse(fetchMock.mock.calls[0][1].body)
    expect(body).toEqual({ challenge_id: 'c1', nonce: '99' })
  })

  it('login POSTs payloadCanon, signature, and username', async () => {
    fetchMock.mockResolvedValue(mockResponse({ data: { token: 'jwt' } }))
    await authApi.login('CANON', 'SIG', 'alice')
    const body = JSON.parse(fetchMock.mock.calls[0][1].body)
    expect(body).toEqual({ payload_canon: 'CANON', signature: 'SIG', username: 'alice' })
  })

  it('getUserKeys calls GET /users/:username/keys', async () => {
    fetchMock.mockResolvedValue(mockResponse({ data: { keys: [] } }))
    await authApi.getUserKeys('bob')
    expect(fetchMock.mock.calls[0][0]).toMatch('/users/bob/keys')
  })
})
