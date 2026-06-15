// useAuth.test.js
import { renderHook, act, waitFor } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { useAuth } from "./useAuth";
import * as loginBridge from "../services/loginBridge.js";

// Mock the loginBridge module
vi.mock("../services/loginBridge.js", () => ({
  login: vi.fn(),
  logout: vi.fn(),
  isSessionActive: vi.fn(),
  getSessionPublicKeys: vi.fn(),
}));

describe("useAuth", () => {
  const mockKeypair = {
    signing: {
      publicKey: new Uint8Array([1, 2, 3]),
      privateKey: new Uint8Array([4, 5, 6]),
    },
    exchange: {
      publicKey: new Uint8Array([7, 8, 9]),
      privateKey: new Uint8Array([10, 11, 12]),
    },
  };

  const mockPublicKeys = {
    signingPublicKey: "base64signingkey",
    exchangePublicKey: "base64exchangekey",
    userIdHex: "abc123",
    username: "testuser",
  };

  beforeEach(() => {
    vi.clearAllMocks();
    vi.spyOn(console, "error").mockImplementation(() => {});
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe("initial state", () => {
    it("should initialize with inactive session when bridge reports no active session", () => {
      vi.mocked(loginBridge.isSessionActive).mockReturnValue(false);
      vi.mocked(loginBridge.getSessionPublicKeys).mockReturnValue(null);

      const { result } = renderHook(() => useAuth());

      expect(result.current.isAuthenticated).toBe(false);
      expect(result.current.publicKeys).toBe(null);
      expect(result.current.loading).toBe(false);
      expect(result.current.error).toBe(null);
    });

    it("should initialize with active session when bridge reports active session", () => {
      vi.mocked(loginBridge.isSessionActive).mockReturnValue(true);
      vi.mocked(loginBridge.getSessionPublicKeys).mockReturnValue(
        mockPublicKeys,
      );

      const { result } = renderHook(() => useAuth());

      expect(result.current.isAuthenticated).toBe(true);
      expect(result.current.publicKeys).toEqual(mockPublicKeys);
      expect(result.current.loading).toBe(false);
    });
  });

  describe("login", () => {
    it("should successfully login with valid credentials", async () => {
      vi.mocked(loginBridge.isSessionActive).mockReturnValue(false);
      vi.mocked(loginBridge.login).mockResolvedValue({
        publicKeys: mockPublicKeys,
      });

      const { result } = renderHook(() => useAuth());

      let success;
      await act(async () => {
        success = await result.current.login("testuser", mockKeypair);
      });

      expect(success).toBe(true);
      expect(result.current.isAuthenticated).toBe(true);
      expect(result.current.publicKeys).toEqual(mockPublicKeys);
      expect(result.current.loading).toBe(false);
      expect(result.current.error).toBe(null);
      expect(loginBridge.login).toHaveBeenCalledWith("testuser", mockKeypair);
    });

    it("should handle login failure", async () => {
      const error = new Error("Login failed");
      error.name = "ApiError";
      error.status = 401;
      error.code = "INVALID_SIGNATURE";

      vi.mocked(loginBridge.login).mockRejectedValue(error);

      const { result } = renderHook(() => useAuth());

      let success;
      await act(async () => {
        success = await result.current.login("testuser", mockKeypair);
      });

      expect(success).toBe(false);
      expect(result.current.isAuthenticated).toBe(false);
      expect(result.current.publicKeys).toBe(null);
      expect(result.current.error).toBe(
        "Login failed — keypair does not match this account.",
      );
    });

    it("should handle network error during login", async () => {
      const error = new Error("Network error");
      error.name = "ApiError";
      error.status = 0;

      vi.mocked(loginBridge.login).mockRejectedValue(error);

      const { result } = renderHook(() => useAuth());

      await act(async () => {
        await result.current.login("testuser", mockKeypair);
      });

      expect(result.current.error).toBe(
        "Network error — check your connection.",
      );
    });

    it("should handle KeysetError during login", async () => {
      const error = new Error("Bad key format");
      error.name = "KeysetError";
      error.code = "BAD_KEY_FORMAT";

      vi.mocked(loginBridge.login).mockRejectedValue(error);

      const { result } = renderHook(() => useAuth());

      await act(async () => {
        await result.current.login("testuser", mockKeypair);
      });

      expect(result.current.error).toBe(
        "Invalid keypair file — check the file and try again.",
      );
    });
  });

  describe("logout", () => {
    it("should successfully logout", async () => {
      vi.mocked(loginBridge.isSessionActive).mockReturnValue(true);
      vi.mocked(loginBridge.getSessionPublicKeys).mockReturnValue(
        mockPublicKeys,
      );
      vi.mocked(loginBridge.logout).mockResolvedValue(undefined);

      const { result } = renderHook(() => useAuth());

      await act(async () => {
        await result.current.logout();
      });

      expect(result.current.isAuthenticated).toBe(false);
      expect(result.current.publicKeys).toBe(null);
      expect(result.current.loading).toBe(false);
      expect(loginBridge.logout).toHaveBeenCalled();
    });

    it("should handle logout errors gracefully and still clear state", async () => {
      vi.mocked(loginBridge.isSessionActive).mockReturnValue(true);
      vi.mocked(loginBridge.logout).mockRejectedValue(
        new Error("Network error"),
      );

      const { result } = renderHook(() => useAuth());

      await act(async () => {
        await result.current.logout();
      });

      // State should still be cleared despite error
      expect(result.current.isAuthenticated).toBe(false);
      expect(result.current.publicKeys).toBe(null);
    });
  });

  describe("clearError", () => {
    it("should clear error state", async () => {
      vi.mocked(loginBridge.login).mockRejectedValue(new Error("Test error"));

      const { result } = renderHook(() => useAuth());

      await act(async () => {
        await result.current.login("testuser", mockKeypair);
      });

      expect(result.current.error).toBeTruthy();

      act(() => {
        result.current.clearError();
      });

      expect(result.current.error).toBe(null);
    });
  });
});
