// useRegister.test.js
import React from "react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { renderHook, act, waitFor } from "@testing-library/react";
import { useRegister } from "./useRegister.js";

// Mock RegisterBridge
const mockRegisterBridge = {
  startPoW: vi.fn(),
  submitEmail: vi.fn(),
  verifyEmailCode: vi.fn(),
  getTotpInfo: vi.fn(),
  verifyTOTP: vi.fn(),
  createAccount: vi.fn(),
  clearKeypair: vi.fn(),
};

vi.mock("../services/registerBridge.js", () => ({
  RegisterBridge: vi.fn(() => mockRegisterBridge),
}));

describe("useRegister", () => {
  const mockSessionToken = "session_token_123";
  const mockTotpInfo = {
    qrCodeUri: "otpauth://...",
    manualKey: "ABCDEF123456",
  };

  beforeEach(() => {
    vi.clearAllMocks();
    mockRegisterBridge.startPoW.mockReset();
    mockRegisterBridge.submitEmail.mockReset();
    mockRegisterBridge.verifyEmailCode.mockReset();
    mockRegisterBridge.getTotpInfo.mockReset();
    mockRegisterBridge.verifyTOTP.mockReset();
    mockRegisterBridge.createAccount.mockReset();
    mockRegisterBridge.clearKeypair.mockReset();
  });

  describe("initial state", () => {
    it("should initialize with IDLE step", () => {
      const { result } = renderHook(() => useRegister());

      expect(result.current.step).toBe("idle");
      expect(result.current.loading).toBe(false);
      expect(result.current.error).toBe(null);
      expect(result.current.totpInfo).toBe(null);
      expect(result.current.keypair).toBe(null);
      expect(result.current.publicKeys).toBe(null);
    });
  });

  describe("startPoW", () => {
    it("should successfully start PoW and move to POW step", async () => {
      mockRegisterBridge.startPoW.mockResolvedValue({
        sessionToken: mockSessionToken,
      });

      const { result } = renderHook(() => useRegister());

      let powResult;
      await act(async () => {
        powResult = await result.current.startPoW();
      });

      expect(powResult).toEqual({ sessionToken: mockSessionToken });
      expect(result.current.step).toBe("pow");
      expect(result.current.loading).toBe(false);
      expect(mockRegisterBridge.startPoW).toHaveBeenCalledWith({
        signal: expect.any(AbortSignal),
      });
    });

    it("should handle PoW failure", async () => {
      const error = new Error("Server error (500).");
      error.name = "ApiError";
      error.status = 500;
      mockRegisterBridge.startPoW.mockRejectedValue(error);

      const { result } = renderHook(() => useRegister());

      let powResult;
      await act(async () => {
        powResult = await result.current.startPoW();
      });

      expect(powResult).toBe(null);
      expect(result.current.step).toBe("idle");
      expect(result.current.error).toBe("Server error (500).");
    });

    it("should cancel previous PoW when starting new one", async () => {
      const abortMock = vi.fn();
      const mockController = { abort: abortMock };

      const originalAbortController = global.AbortController;
      global.AbortController = vi.fn(() => mockController);

      mockRegisterBridge.startPoW
        .mockRejectedValueOnce(new Error("Aborted"))
        .mockResolvedValueOnce({ sessionToken: mockSessionToken });

      const { result } = renderHook(() => useRegister());

      act(() => {
        result.current.startPoW();
      });

      await act(async () => {
        await result.current.startPoW();
      });

      expect(abortMock).toHaveBeenCalled();

      global.AbortController = originalAbortController;
    });
  });

  describe("cancelPoW", () => {
    it("should cancel in-progress PoW and reset to IDLE", async () => {
      let resolvePromise;
      const promise = new Promise((resolve) => {
        resolvePromise = resolve;
      });
      mockRegisterBridge.startPoW.mockImplementation(() => promise);

      const { result } = renderHook(() => useRegister());

      // Start PoW
      act(() => {
        result.current.startPoW();
      });

      // Wait for loading to become true
      await waitFor(() => {
        expect(result.current.loading).toBe(true);
      });

      // Step should still be "idle" while PoW is solving
      expect(result.current.step).toBe("idle");

      // Cancel PoW
      act(() => {
        result.current.cancelPoW();
      });

      // Wait for loading to become false
      await waitFor(() => {
        expect(result.current.loading).toBe(false);
      });

      // After cancellation, step should be "idle"
      expect(result.current.step).toBe("idle");

      // Resolve the promise to clean up
      resolvePromise();
    });
  });

  describe("submitEmail", () => {
    it("should submit email and move to EMAIL_VERIFY step", async () => {
      const emailResponse = {
        message: "Code sent",
        expiresIn: 300,
        email: "test@example.com",
      };
      mockRegisterBridge.submitEmail.mockResolvedValue(emailResponse);

      const { result } = renderHook(() => useRegister());

      mockRegisterBridge.startPoW.mockResolvedValue({
        sessionToken: mockSessionToken,
      });
      await act(async () => {
        await result.current.startPoW();
      });

      let response;
      await act(async () => {
        response = await result.current.submitEmail("test@example.com");
      });

      expect(response).toEqual(emailResponse);
      expect(result.current.step).toBe("emailVerify");
      expect(mockRegisterBridge.submitEmail).toHaveBeenCalledWith(
        "test@example.com",
      );
    });
  });

  describe("verifyEmailCode", () => {
    it("should verify email code and move to TOTP step with TOTP info", async () => {
      const verifyResponse = { success: true };
      mockRegisterBridge.verifyEmailCode.mockResolvedValue(verifyResponse);
      mockRegisterBridge.getTotpInfo.mockReturnValue(mockTotpInfo);

      const { result } = renderHook(() => useRegister());

      mockRegisterBridge.startPoW.mockResolvedValue({
        sessionToken: mockSessionToken,
      });
      await act(async () => {
        await result.current.startPoW();
      });
      mockRegisterBridge.submitEmail.mockResolvedValue({});
      await act(async () => {
        await result.current.submitEmail("test@example.com");
      });

      let response;
      await act(async () => {
        response = await result.current.verifyEmailCode("123456");
      });

      expect(response).toEqual(verifyResponse);
      expect(result.current.step).toBe("totp");
      expect(result.current.totpInfo).toEqual(mockTotpInfo);
      expect(mockRegisterBridge.verifyEmailCode).toHaveBeenCalledWith("123456");
    });
  });

  describe("verifyTOTP", () => {
    it("should verify TOTP and move to CREATE_ACCOUNT step", async () => {
      const totpResponse = { success: true };
      mockRegisterBridge.verifyTOTP.mockResolvedValue(totpResponse);

      const { result } = renderHook(() => useRegister());

      mockRegisterBridge.startPoW.mockResolvedValue({
        sessionToken: mockSessionToken,
      });
      await act(async () => {
        await result.current.startPoW();
      });
      mockRegisterBridge.submitEmail.mockResolvedValue({});
      await act(async () => {
        await result.current.submitEmail("test@example.com");
      });
      mockRegisterBridge.verifyEmailCode.mockResolvedValue({});
      mockRegisterBridge.getTotpInfo.mockReturnValue(mockTotpInfo);
      await act(async () => {
        await result.current.verifyEmailCode("123456");
      });

      let response;
      await act(async () => {
        response = await result.current.verifyTOTP("654321");
      });

      expect(response).toEqual(totpResponse);
      expect(result.current.step).toBe("createAccount");
      expect(mockRegisterBridge.verifyTOTP).toHaveBeenCalledWith("654321");
    });
  });

  describe("createAccount", () => {
    const mockKeypairResult = {
      keypair: {
        signing: {
          publicKey: new Uint8Array([1, 2, 3]),
          privateKey: new Uint8Array([4, 5, 6]),
        },
        exchange: {
          publicKey: new Uint8Array([7, 8, 9]),
          privateKey: new Uint8Array([10, 11, 12]),
        },
      },
      publicKeys: {
        signingPublicKey: "signingPub",
        exchangePublicKey: "exchangePub",
        userIdHex: "user123",
        username: "testuser",
      },
      userId: "user123",
    };

    it("should create account and move to KEYPAIR_READY step", async () => {
      mockRegisterBridge.createAccount.mockResolvedValue(mockKeypairResult);

      const { result } = renderHook(() => useRegister());

      mockRegisterBridge.startPoW.mockResolvedValue({
        sessionToken: mockSessionToken,
      });
      await act(async () => {
        await result.current.startPoW();
      });
      mockRegisterBridge.submitEmail.mockResolvedValue({});
      await act(async () => {
        await result.current.submitEmail("test@example.com");
      });
      mockRegisterBridge.verifyEmailCode.mockResolvedValue({});
      mockRegisterBridge.getTotpInfo.mockReturnValue(mockTotpInfo);
      await act(async () => {
        await result.current.verifyEmailCode("123456");
      });
      mockRegisterBridge.verifyTOTP.mockResolvedValue({});
      await act(async () => {
        await result.current.verifyTOTP("654321");
      });

      let response;
      await act(async () => {
        response = await result.current.createAccount(
          "testuser",
          "password123",
        );
      });

      expect(response).toEqual(mockKeypairResult);
      expect(result.current.step).toBe("keypairReady");
      expect(result.current.keypair).toEqual(mockKeypairResult.keypair);
      expect(result.current.publicKeys).toEqual(mockKeypairResult.publicKeys);
      expect(mockRegisterBridge.createAccount).toHaveBeenCalledWith(
        "testuser",
        "password123",
      );
    });
  });

  describe("clearKeypair", () => {
    it("should clear keypair from hook state and bridge", async () => {
      const mockKeypairResult = {
        keypair: { signing: {}, exchange: {} },
        publicKeys: {},
        userId: "user123",
      };
      mockRegisterBridge.createAccount.mockResolvedValue(mockKeypairResult);

      const { result } = renderHook(() => useRegister());

      mockRegisterBridge.startPoW.mockResolvedValue({
        sessionToken: mockSessionToken,
      });
      await act(async () => {
        await result.current.startPoW();
      });
      mockRegisterBridge.submitEmail.mockResolvedValue({});
      await act(async () => {
        await result.current.submitEmail("test@example.com");
      });
      mockRegisterBridge.verifyEmailCode.mockResolvedValue({});
      mockRegisterBridge.getTotpInfo.mockReturnValue(mockTotpInfo);
      await act(async () => {
        await result.current.verifyEmailCode("123456");
      });
      mockRegisterBridge.verifyTOTP.mockResolvedValue({});
      await act(async () => {
        await result.current.verifyTOTP("654321");
      });
      await act(async () => {
        await result.current.createAccount("testuser", "password123");
      });

      expect(result.current.keypair).toBeTruthy();

      act(() => {
        result.current.clearKeypair();
      });

      expect(result.current.keypair).toBe(null);
      expect(mockRegisterBridge.clearKeypair).toHaveBeenCalled();
    });
  });

  describe("reset", () => {
    it("should reset all state to initial values", async () => {
      const { result } = renderHook(() => useRegister());

      mockRegisterBridge.startPoW.mockResolvedValue({
        sessionToken: mockSessionToken,
      });
      await act(async () => {
        await result.current.startPoW();
      });
      mockRegisterBridge.submitEmail.mockResolvedValue({});
      await act(async () => {
        await result.current.submitEmail("test@example.com");
      });

      expect(result.current.step).not.toBe("idle");

      act(() => {
        result.current.reset();
      });

      expect(result.current.step).toBe("idle");
      expect(result.current.loading).toBe(false);
      expect(result.current.error).toBe(null);
      expect(result.current.totpInfo).toBe(null);
      expect(result.current.keypair).toBe(null);
      expect(result.current.publicKeys).toBe(null);
    });

    it("should cancel in-progress PoW on reset", async () => {
      const abortMock = vi.fn();
      const mockController = { abort: abortMock };
      const originalAbortController = global.AbortController;
      global.AbortController = vi.fn(() => mockController);

      mockRegisterBridge.startPoW.mockImplementation(
        () => new Promise(() => {}),
      );

      const { result } = renderHook(() => useRegister());

      act(() => {
        result.current.startPoW();
      });

      act(() => {
        result.current.reset();
      });

      expect(abortMock).toHaveBeenCalled();
      expect(result.current.step).toBe("idle");

      global.AbortController = originalAbortController;
    });
  });

  describe("error handling", () => {
    it("should format network errors correctly", async () => {
      const error = new Error("Network error");
      error.name = "ApiError";
      error.status = 0;
      mockRegisterBridge.startPoW.mockRejectedValue(error);

      const { result } = renderHook(() => useRegister());

      await act(async () => {
        await result.current.startPoW();
      });

      expect(result.current.error).toBe(
        "Network error — check your connection.",
      );
    });

    it("should format KeysetError correctly", async () => {
      const error = new Error("Bad key");
      error.name = "KeysetError";
      error.code = "BAD_KEY_FORMAT";
      mockRegisterBridge.createAccount.mockRejectedValue(error);

      const { result } = renderHook(() => useRegister());

      mockRegisterBridge.startPoW.mockResolvedValue({
        sessionToken: mockSessionToken,
      });
      await act(async () => {
        await result.current.startPoW();
      });
      mockRegisterBridge.submitEmail.mockResolvedValue({});
      await act(async () => {
        await result.current.submitEmail("test@example.com");
      });
      mockRegisterBridge.verifyEmailCode.mockResolvedValue({});
      mockRegisterBridge.getTotpInfo.mockReturnValue(mockTotpInfo);
      await act(async () => {
        await result.current.verifyEmailCode("123456");
      });
      mockRegisterBridge.verifyTOTP.mockResolvedValue({});
      await act(async () => {
        await result.current.verifyTOTP("654321");
      });

      await act(async () => {
        await result.current.createAccount("testuser", "password123");
      });

      expect(result.current.error).toBe(
        "Invalid key format — re-upload your keypair.",
      );
    });
  });
});
