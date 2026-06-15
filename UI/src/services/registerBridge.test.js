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

// ─── Hoisted mocks (required because vi.mock factories are hoisted) ───────────

const { mockSetToken, mockAuthApi } = vi.hoisted(() => ({
  mockSetToken: vi.fn(),
  mockAuthApi: {
    initPoW: vi.fn(),
    verifyPoW: vi.fn(),
    submitEmail: vi.fn(),
    verifyEmailCode: vi.fn(),
    verifyTOTP: vi.fn(),
    createAccount: vi.fn(),
  },
}))

vi.mock('./apiClient.js', () => ({
  setToken: mockSetToken,
  authApi: mockAuthApi,
}))

// Mock keyset manager
// exchangePublicKey must be valid base64 — registerBridge may decode it
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

// ─── Mock crypto.subtle so PoW resolves instantly ───────────────────────────
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
const VALID_PASSWORD = 'P@ssw0rd!'  // ≥ 8 chars to satisfy patched validation

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

  it('rejects difficulty > 6 to prevent main-thread DoS', async () => {
    mockAuthApi.initPoW.mockResolvedValue({ challenge_id: 'c1', challenge: 'ch', difficulty: 7 })
    await expect(freshBridge().startPoW()).rejects.toThrow('exceeds max')
  })

  it('respects AbortSignal to cancel PoW solving', async () => {
    mockAuthApi.initPoW.mockResolvedValue({ challenge_id: 'c1', challenge: 'ch', difficulty: 4 })
    const controller = new AbortController()
    controller.abort()
    await expect(freshBridge().startPoW({ signal: controller.signal })).rejects.toThrow('aborted')
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

  it('throws on invalid email format', async () => {
    const bridge = await bridgeAfterPoW()
    await expect(bridge.submitEmail('not-an-email')).rejects.toThrow('email format')
  })

  it('throws on empty email', async () => {
    const bridge = await bridgeAfterPoW()
    await expect(bridge.submitEmail('')).rejects.toThrow('email must be a non-empty string')
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

  it('throws on non-6-digit code', async () => {
    const bridge = await bridgeAfterPoW()
    await expect(bridge.verifyEmailCode('12345')).rejects.toThrow('exactly 6 digits')
    await expect(bridge.verifyEmailCode('1234567')).rejects.toThrow('exactly 6 digits')
    await expect(bridge.verifyEmailCode('abcdef')).rejects.toThrow('exactly 6 digits')
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

  it('throws on non-6-digit TOTP token', async () => {
    const bridge = await bridgeAfterPoW()
    await expect(bridge.verifyTOTP('12345')).rejects.toThrow('exactly 6 digits')
    await expect(bridge.verifyTOTP('1234567')).rejects.toThrow('exactly 6 digits')
    await expect(bridge.verifyTOTP('abcdef')).rejects.toThrow('exactly 6 digits')
  })
})

// ─────────────────────────────────────────────────────────────────────────────
// createAccount()
// ─────────────────────────────────────────────────────────────────────────────

describe('createAccount()', () => {
  it('initialises libsodium via KeysetManager.init()', async () => {
    const bridge = await bridgeAfterPoW()
    mockAuthApi.createAccount.mockResolvedValue({ userId: 'u1' })
    await bridge.createAccount('alice', VALID_PASSWORD)
    expect(KeysetManager.init).toHaveBeenCalledOnce()
  })

  it('generates a keypair via KeysetManager.createUser()', async () => {
    const bridge = await bridgeAfterPoW()
    mockAuthApi.createAccount.mockResolvedValue({ userId: 'u1' })
    await bridge.createAccount('alice', VALID_PASSWORD)
    expect(KeysetManager.createUser).toHaveBeenCalledWith('alice')
  })

  it('sends public keys + credentials to authApi.createAccount()', async () => {
    const bridge = await bridgeAfterPoW()
    mockAuthApi.createAccount.mockResolvedValue({ userId: 'u1' })
    await bridge.createAccount('alice', VALID_PASSWORD)

    expect(mockAuthApi.createAccount).toHaveBeenCalledWith(
      SESSION_TOKEN,
      'alice',
      VALID_PASSWORD,
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
    const result = await bridge.createAccount('alice', VALID_PASSWORD)

    expect(result.userId).toBe('u-999')
    expect(result.keypair).toBeDefined()
    expect(result.publicKeys).toMatchObject({
      signingPublicKey: expect.any(Uint8Array),
      exchangePublicKey: expect.any(Uint8Array),
      userIdHex: mockKeypairResult.userIdHex,
      username: 'alice',
    })
  })

  it('keypair contains both signing and exchange keys as Uint8Arrays', async () => {
    const bridge = await bridgeAfterPoW()
    mockAuthApi.createAccount.mockResolvedValue({ userId: 'u1' })
    const { keypair } = await bridge.createAccount('alice', VALID_PASSWORD)

    expect(keypair.signing.publicKey).toBeInstanceOf(Uint8Array)
    expect(keypair.signing.privateKey).toBeInstanceOf(Uint8Array)
    expect(keypair.exchange.publicKey).toBeInstanceOf(Uint8Array)
    expect(keypair.exchange.privateKey).toBeInstanceOf(Uint8Array)
  })

  it('stores JWT token when server returns one', async () => {
    const bridge = await bridgeAfterPoW()
    mockAuthApi.createAccount.mockResolvedValue({ userId: 'u1', token: 'jwt-123' })
    await bridge.createAccount('alice', VALID_PASSWORD)
    expect(mockSetToken).toHaveBeenCalledWith('jwt-123')
  })

  it('does not call setToken when server omits token', async () => {
    const bridge = await bridgeAfterPoW()
    mockAuthApi.createAccount.mockResolvedValue({ userId: 'u1' })
    await bridge.createAccount('alice', VALID_PASSWORD)
    expect(mockSetToken).not.toHaveBeenCalled()
  })

  it('clears session token after successful creation', async () => {
    const bridge = await bridgeAfterPoW()
    mockAuthApi.createAccount.mockResolvedValue({ userId: 'u1' })
    await bridge.createAccount('alice', VALID_PASSWORD)
    // After reset, submitEmail should throw because session is gone
    await expect(bridge.submitEmail('x@x.com')).rejects.toThrow('startPoW')
  })

  it('throws on password < 8 characters', async () => {
    const bridge = await bridgeAfterPoW()
    await expect(bridge.createAccount('alice', 'short')).rejects.toThrow('at least 8 characters')
  })

  it('throws on username < 2 characters', async () => {
    const bridge = await bridgeAfterPoW()
    await expect(bridge.createAccount('a', VALID_PASSWORD)).rejects.toThrow('at least 2 characters')
  })
})

// ─────────────────────────────────────────────────────────────────────────────
// clearKeypair() / reset()
// ─────────────────────────────────────────────────────────────────────────────

describe('clearKeypair()', () => {
  it('releases the internal keypair reference', async () => {
    const bridge = await bridgeAfterPoW()
    mockAuthApi.createAccount.mockResolvedValue({ userId: 'u1' })
    await bridge.createAccount('alice', VALID_PASSWORD)
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
    await bridge.createAccount('alice', VALID_PASSWORD)

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
