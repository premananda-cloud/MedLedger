/**
 * registerBridge.test.js
 *
 * Unit tests for RegisterBridge (registerBridge.js).
 *
 * Mocks:
 *   - ./apiClient   (authApi, setToken)
 *   - ../key_manager/key_manager  (KeysetManager)
 *   - Web Crypto (crypto.subtle.digest) for the PoW solver
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'

// ─── Mock dependencies ────────────────────────────────────────────────────────

const mockSetToken = vi.fn()
const mockAuthApi = {
  initPoW: vi.fn(),
  verifyPoW: vi.fn(),
  submitEmail: vi.fn(),
  verifyEmailCode: vi.fn(),
  verifyTOTP: vi.fn(),
  createAccount: vi.fn(),
}

vi.mock('./apiClient.js', () => ({
  setToken: mockSetToken,
  authApi: mockAuthApi,
}))

// Mock keyset manager
// exchangePublicKey must be valid base64 — registerBridge calls atob() on it
const VALID_B64_32 = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='
const mockKeypairResult = {
  signingPublicKey: VALID_B64_32,
  exchangePublicKey: VALID_B64_32,
  userIdHex: 'deadbeef',
  signingPrivateKey: new Uint8Array(64),   // Ed25519 private = 64 bytes
  exchangePrivateKey: new Uint8Array(32),
}

const KeysetManager = {
  init: vi.fn().mockResolvedValue(undefined),
  createUser: vi.fn().mockResolvedValue(mockKeypairResult),
}

vi.mock('../key_manager/key_manager.js', () => ({
  KeysetManager,
  KeysetError: class KeysetError extends Error {},
  ERRORS: {},
}))

// ─── Mock crypto.subtle so PoW resolves instantly ─────────────────────────────
//
// 32 zero bytes → "0000..." hex, so any difficulty ≤ 64 resolves at nonce=0.
// crypto is a getter-only global in Node 18+, so we use vi.stubGlobal.

const zeroHashBuffer = new Uint8Array(32).buffer
vi.stubGlobal('crypto', {
  subtle: {
    digest: vi.fn().mockResolvedValue(zeroHashBuffer),
  },
})

// ─── Import SUT after mocks ───────────────────────────────────────────────────

const { RegisterBridge } = await import('./registerBridge.js')

// ─── Shared fixtures ──────────────────────────────────────────────────────────

const SESSION_TOKEN = 'sess-abc'

function freshBridge() {
  const bridge = new RegisterBridge()
  return bridge
}

async function bridgeAfterPoW() {
  const bridge = freshBridge()
  mockAuthApi.initPoW.mockResolvedValue({ challenge_id: 'c1', challenge: 'ch', difficulty: 4 })
  mockAuthApi.verifyPoW.mockResolvedValue({ sessionToken: SESSION_TOKEN })
  await bridge.startPoW()
  return bridge
}

// ─── Reset ────────────────────────────────────────────────────────────────────

beforeEach(() => {
  vi.clearAllMocks()
  KeysetManager.init.mockResolvedValue(undefined)
  KeysetManager.createUser.mockResolvedValue(mockKeypairResult)
})

// ─────────────────────────────────────────────────────────────────────────────
// _assertSession guard
// ─────────────────────────────────────────────────────────────────────────────

describe('_assertSession guard', () => {
  it('throws if startPoW() has not been called', async () => {
    const bridge = freshBridge()
    await expect(bridge.submitEmail('a@b.com')).rejects.toThrow('startPoW')
  })
})

// ─────────────────────────────────────────────────────────────────────────────
// startPoW()
// ─────────────────────────────────────────────────────────────────────────────

describe('startPoW()', () => {
  it('fetches a PoW challenge from authApi.initPoW()', async () => {
    mockAuthApi.initPoW.mockResolvedValue({ challenge_id: 'c1', challenge: 'ch', difficulty: 4 })
    mockAuthApi.verifyPoW.mockResolvedValue({ sessionToken: 'tok' })
    await freshBridge().startPoW()
    expect(mockAuthApi.initPoW).toHaveBeenCalledOnce()
  })

  it('submits the solved nonce to authApi.verifyPoW()', async () => {
    mockAuthApi.initPoW.mockResolvedValue({ challenge_id: 'c1', challenge: 'ch', difficulty: 4 })
    mockAuthApi.verifyPoW.mockResolvedValue({ sessionToken: 'tok' })
    await freshBridge().startPoW()
    expect(mockAuthApi.verifyPoW).toHaveBeenCalledWith('c1', expect.any(String))
  })

  it('returns the session token', async () => {
    mockAuthApi.initPoW.mockResolvedValue({ challenge_id: 'c1', challenge: 'ch', difficulty: 4 })
    mockAuthApi.verifyPoW.mockResolvedValue({ sessionToken: 'tok-xyz' })
    const result = await freshBridge().startPoW()
    expect(result).toEqual({ sessionToken: 'tok-xyz' })
  })

  it('defaults difficulty to 4 when not provided by server', async () => {
    mockAuthApi.initPoW.mockResolvedValue({ challenge_id: 'c1', challenge: 'ch' })
    mockAuthApi.verifyPoW.mockResolvedValue({ sessionToken: 'tok' })
    // Should not throw — difficulty defaults to 4
    await expect(freshBridge().startPoW()).resolves.toBeDefined()
  })
})

// ─────────────────────────────────────────────────────────────────────────────
// submitEmail()
// ─────────────────────────────────────────────────────────────────────────────

describe('submitEmail()', () => {
  it('calls authApi.submitEmail with the session token and email', async () => {
    const bridge = await bridgeAfterPoW()
    mockAuthApi.submitEmail.mockResolvedValue({ message: 'Code sent', expiresIn: 300, email: 'a@b.com' })
    await bridge.submitEmail('a@b.com')
    expect(mockAuthApi.submitEmail).toHaveBeenCalledWith(SESSION_TOKEN, 'a@b.com')
  })

  it('returns the result from authApi.submitEmail', async () => {
    const bridge = await bridgeAfterPoW()
    const payload = { message: 'Code sent', expiresIn: 300, email: 'a@b.com' }
    mockAuthApi.submitEmail.mockResolvedValue(payload)
    const result = await bridge.submitEmail('a@b.com')
    expect(result).toEqual(payload)
  })
})

// ─────────────────────────────────────────────────────────────────────────────
// verifyEmailCode()
// ─────────────────────────────────────────────────────────────────────────────

describe('verifyEmailCode()', () => {
  it('calls authApi.verifyEmailCode with session token and code', async () => {
    const bridge = await bridgeAfterPoW()
    mockAuthApi.verifyEmailCode.mockResolvedValue({ totp: { qrCodeUri: 'qr', manualKey: 'key' } })
    await bridge.verifyEmailCode('483920')
    expect(mockAuthApi.verifyEmailCode).toHaveBeenCalledWith(SESSION_TOKEN, '483920')
  })

  it('caches totpInfo when server returns it', async () => {
    const bridge = await bridgeAfterPoW()
    mockAuthApi.verifyEmailCode.mockResolvedValue({
      totp: { qrCodeUri: 'otpauth://...', manualKey: 'ABCD1234' },
    })
    await bridge.verifyEmailCode('483920')
    expect(bridge.getTotpInfo()).toEqual({ qrCodeUri: 'otpauth://...', manualKey: 'ABCD1234' })
  })

  it('leaves totpInfo null when server omits it', async () => {
    const bridge = await bridgeAfterPoW()
    mockAuthApi.verifyEmailCode.mockResolvedValue({ message: 'ok' })
    await bridge.verifyEmailCode('000000')
    expect(bridge.getTotpInfo()).toBeNull()
  })
})

// ─────────────────────────────────────────────────────────────────────────────
// verifyTOTP()
// ─────────────────────────────────────────────────────────────────────────────

describe('verifyTOTP()', () => {
  it('calls authApi.verifyTOTP with session token and TOTP token', async () => {
    const bridge = await bridgeAfterPoW()
    mockAuthApi.verifyTOTP.mockResolvedValue({ message: 'ok' })
    await bridge.verifyTOTP('123456')
    expect(mockAuthApi.verifyTOTP).toHaveBeenCalledWith(SESSION_TOKEN, '123456')
  })
})

// ─────────────────────────────────────────────────────────────────────────────
// createAccount()
// ─────────────────────────────────────────────────────────────────────────────

describe('createAccount()', () => {
  it('initialises libsodium via KeysetManager.init()', async () => {
    const bridge = await bridgeAfterPoW()
    mockAuthApi.createAccount.mockResolvedValue({ userId: 'u1' })
    await bridge.createAccount('alice', 'P@ss!')
    expect(KeysetManager.init).toHaveBeenCalledOnce()
  })

  it('generates a keypair via KeysetManager.createUser()', async () => {
    const bridge = await bridgeAfterPoW()
    mockAuthApi.createAccount.mockResolvedValue({ userId: 'u1' })
    await bridge.createAccount('alice', 'P@ss!')
    expect(KeysetManager.createUser).toHaveBeenCalledWith('alice')
  })

  it('sends public keys + credentials to authApi.createAccount()', async () => {
    const bridge = await bridgeAfterPoW()
    mockAuthApi.createAccount.mockResolvedValue({ userId: 'u1' })
    await bridge.createAccount('alice', 'P@ss!')

    expect(mockAuthApi.createAccount).toHaveBeenCalledWith(
      SESSION_TOKEN,
      'alice',
      'P@ss!',
      expect.objectContaining({
        signingPublicKey: mockKeypairResult.signingPublicKey,
        exchangePublicKey: mockKeypairResult.exchangePublicKey,
        userIdHex: mockKeypairResult.userIdHex,
      })
    )
  })

  it('returns keypair, publicKeys, and userId', async () => {
    const bridge = await bridgeAfterPoW()
    mockAuthApi.createAccount.mockResolvedValue({ userId: 'u-999' })
    const result = await bridge.createAccount('alice', 'P@ss!')

    expect(result.userId).toBe('u-999')
    expect(result.keypair).toBeDefined()
    expect(result.publicKeys).toMatchObject({
      signingPublicKey: mockKeypairResult.signingPublicKey,
      exchangePublicKey: mockKeypairResult.exchangePublicKey,
      userIdHex: mockKeypairResult.userIdHex,
      username: 'alice',
    })
  })

  it('keypair contains both signing and exchange keys', async () => {
    const bridge = await bridgeAfterPoW()
    mockAuthApi.createAccount.mockResolvedValue({ userId: 'u1' })
    const { keypair } = await bridge.createAccount('alice', 'P@ss!')

    expect(keypair.signing).toHaveProperty('publicKey')
    expect(keypair.signing).toHaveProperty('privateKey')
    expect(keypair.exchange).toHaveProperty('publicKey')
    expect(keypair.exchange).toHaveProperty('privateKey')
  })
})

// ─────────────────────────────────────────────────────────────────────────────
// clearKeypair() / reset()
// ─────────────────────────────────────────────────────────────────────────────

describe('clearKeypair()', () => {
  it('releases the internal keypair reference', async () => {
    const bridge = await bridgeAfterPoW()
    mockAuthApi.createAccount.mockResolvedValue({ userId: 'u1' })
    await bridge.createAccount('alice', 'P@ss!')
    bridge.clearKeypair()
    expect(bridge._keypair).toBeNull()
  })
})

describe('reset()', () => {
  it('clears session, totpInfo, and keypair', async () => {
    const bridge = await bridgeAfterPoW()
    mockAuthApi.verifyEmailCode.mockResolvedValue({ totp: { qrCodeUri: 'x', manualKey: 'y' } })
    mockAuthApi.createAccount.mockResolvedValue({ userId: 'u1' })
    await bridge.verifyEmailCode('111111')
    await bridge.createAccount('alice', 'P@ss!')

    bridge.reset()

    expect(bridge._sessionToken).toBeNull()
    expect(bridge._totpInfo).toBeNull()
    expect(bridge._keypair).toBeNull()
  })

  it('after reset, calling submitEmail throws "startPoW" error', async () => {
    const bridge = await bridgeAfterPoW()
    bridge.reset()
    await expect(bridge.submitEmail('x@x.com')).rejects.toThrow('startPoW')
  })
})
