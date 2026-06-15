/**
 * loginBridge.test.js
 *
 * Unit tests for loginBridge.js.
 *
 * All external dependencies are mocked:
 *   - ./apiClient   (setToken, clearToken, authApi)
 *   - ../key_manager/key_manager  (KeysetManager, KeysetError, ERRORS)
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'

// ─── Mock dependencies ────────────────────────────────────────────────────────

const mockSetToken = vi.fn()
const mockClearToken = vi.fn()
const mockAuthApi = {
  login: vi.fn(),
  logout: vi.fn(),
}

vi.mock('./apiClient.js', () => ({
  setToken: mockSetToken,
  clearToken: mockClearToken,
  authApi: mockAuthApi,
}))

const mockPublicKeys = {
  signingPublicKey: 'sig-pub',
  exchangePublicKey: 'exch-pub',
  userIdHex: 'abc123',
  username: 'alice',
}

const KeysetManager = {
  init: vi.fn().mockResolvedValue(undefined),
  loginUser: vi.fn().mockResolvedValue(mockPublicKeys),
  signPayload: vi.fn().mockReturnValue({
    payloadCanon: 'CANON_JSON',
    signature: 'SIG',
  }),
  verifySignature: vi.fn().mockReturnValue(true),
  logoutUser: vi.fn(),
  isLocked: vi.fn().mockReturnValue(false),
  getPublicKeys: vi.fn().mockReturnValue(mockPublicKeys),
}

class KeysetError extends Error {
  constructor(message, code) {
    super(message)
    this.code = code
  }
}

const ERRORS = { BAD_KEY_FORMAT: 'BAD_KEY_FORMAT', SESSION_LOCKED: 'SESSION_LOCKED' }

vi.mock('../key_manager/key_manager.js', () => ({
  KeysetManager,
  KeysetError,
  ERRORS,
}))

// ─── Import SUT after mocks ───────────────────────────────────────────────────

const { login, logout, isSessionActive, getSessionPublicKeys } =
  await import('./loginBridge.js')

// ─── Reset between tests ──────────────────────────────────────────────────────

beforeEach(() => {
  vi.clearAllMocks()
  KeysetManager.init.mockResolvedValue(undefined)
  KeysetManager.loginUser.mockResolvedValue(mockPublicKeys)
  KeysetManager.signPayload.mockReturnValue({ payloadCanon: 'CANON_JSON', signature: 'SIG' })
  KeysetManager.verifySignature.mockReturnValue(true)
  KeysetManager.isLocked.mockReturnValue(false)
  KeysetManager.getPublicKeys.mockReturnValue(mockPublicKeys)
  mockAuthApi.login.mockResolvedValue({ token: 'jwt-token' })
  mockAuthApi.logout.mockResolvedValue(undefined)
})

// ─────────────────────────────────────────────────────────────────────────────
// login()
// ─────────────────────────────────────────────────────────────────────────────

describe('login()', () => {
  const keypair = {
    signing: { publicKey: new Uint8Array(32), privateKey: new Uint8Array(64) },
    exchange: { publicKey: new Uint8Array(32), privateKey: new Uint8Array(32) },
  }

  it('initializes libsodium via KeysetManager.init()', async () => {
    await login('alice', keypair)
    expect(KeysetManager.init).toHaveBeenCalledOnce()
  })

  it('calls loginUser with username and keypair', async () => {
    await login('alice', keypair)
    expect(KeysetManager.loginUser).toHaveBeenCalledWith('alice', keypair)
  })

  it('signs a payload containing action, username, and issuedAt', async () => {
    await login('alice', keypair)
    const [payload] = KeysetManager.signPayload.mock.calls[0]
    expect(payload.action).toBe('login')
    expect(payload.username).toBe('alice')
    expect(typeof payload.issuedAt).toBe('string')
  })

  it('self-verifies the signature before sending', async () => {
    await login('alice', keypair)
    expect(KeysetManager.verifySignature).toHaveBeenCalledWith(
      'CANON_JSON',
      'SIG',
      mockPublicKeys.signingPublicKey
    )
  })

  it('POSTs to authApi.login with canonical payload, signature, and username', async () => {
    await login('alice', keypair)
    expect(mockAuthApi.login).toHaveBeenCalledWith('CANON_JSON', 'SIG', 'alice')
  })

  it('stores the returned token via setToken()', async () => {
    await login('alice', keypair)
    expect(mockSetToken).toHaveBeenCalledWith('jwt-token')
  })

  it('returns the public keys', async () => {
    const result = await login('alice', keypair)
    expect(result).toEqual({ publicKeys: mockPublicKeys })
  })

  it('wipes session and clears token if signing fails', async () => {
    KeysetManager.signPayload.mockImplementation(() => {
      throw new Error('signing exploded')
    })

    await expect(login('alice', keypair)).rejects.toThrow('signing exploded')
    expect(KeysetManager.logoutUser).toHaveBeenCalledOnce()
    expect(mockClearToken).toHaveBeenCalledOnce()
  })

  it('wipes session if self-verification fails', async () => {
    KeysetManager.verifySignature.mockReturnValue(false)

    await expect(login('alice', keypair)).rejects.toThrow('self-verification')
    expect(KeysetManager.logoutUser).toHaveBeenCalledOnce()
    expect(mockClearToken).toHaveBeenCalledOnce()
  })
})

// ─────────────────────────────────────────────────────────────────────────────
// logout()
// ─────────────────────────────────────────────────────────────────────────────

describe('logout()', () => {
  it('wipes private keys via logoutUser() and clears the token', async () => {
    await logout()
    expect(KeysetManager.logoutUser).toHaveBeenCalledOnce()
    expect(mockClearToken).toHaveBeenCalledOnce()
  })

  it('calls authApi.logout to invalidate the server session', async () => {
    await logout()
    expect(mockAuthApi.logout).toHaveBeenCalledOnce()
  })

  it('still clears the local session even if the server call fails', async () => {
    mockAuthApi.logout.mockRejectedValue(new Error('network down'))
    await logout() // must NOT throw
    expect(KeysetManager.logoutUser).toHaveBeenCalledOnce()
    expect(mockClearToken).toHaveBeenCalledOnce()
  })
})

// ─────────────────────────────────────────────────────────────────────────────
// isSessionActive() / getSessionPublicKeys()
// ─────────────────────────────────────────────────────────────────────────────

describe('isSessionActive()', () => {
  it('returns true when KeysetManager is unlocked', () => {
    KeysetManager.isLocked.mockReturnValue(false)
    expect(isSessionActive()).toBe(true)
  })

  it('returns false when KeysetManager is locked', () => {
    KeysetManager.isLocked.mockReturnValue(true)
    expect(isSessionActive()).toBe(false)
  })
})

describe('getSessionPublicKeys()', () => {
  it('returns public keys when session is active', () => {
    KeysetManager.isLocked.mockReturnValue(false)
    expect(getSessionPublicKeys()).toEqual(mockPublicKeys)
  })

  it('returns null when session is locked', () => {
    KeysetManager.isLocked.mockReturnValue(true)
    expect(getSessionPublicKeys()).toBeNull()
  })

  it('returns null if getPublicKeys() throws', () => {
    KeysetManager.isLocked.mockReturnValue(false)
    KeysetManager.getPublicKeys.mockImplementation(() => { throw new Error('oops') })
    expect(getSessionPublicKeys()).toBeNull()
  })
})
