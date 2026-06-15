// useKeyset.test.js
import React from "react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { renderHook, act, waitFor } from "@testing-library/react";
import { useKeyset } from "./useKeyset.js";

// Mock the authKeyBridge
const mockBridge = {
  init: vi.fn().mockResolvedValue(undefined),
  isCryptoLocked: vi.fn(),
  unlockCryptoSession: vi.fn(),
  logout: vi.fn(),
  getPublicKeys: vi.fn(),
  encryptRecord: vi.fn(),
  decryptShare: vi.fn(),
  signPayload: vi.fn(),
  verifySignature: vi.fn(),
};

vi.mock("../services/authKeyBridge.js", () => ({
  getAuthKeyBridge: () => mockBridge,
}));

describe("useKeyset", () => {
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
  };

  beforeEach(() => {
    vi.clearAllMocks();
    mockBridge.init.mockResolvedValue(undefined);
  });

  describe("initialization", () => {
    it("should initialize with UNINITIALIZED status", () => {
      mockBridge.isCryptoLocked.mockImplementation(() => {
        throw new Error("Not initialized");
      });

      const { result } = renderHook(() => useKeyset());

      expect(result.current.vaultStatus).toBe("uninitialized");
      expect(result.current.isLocked).toBe(true);
      expect(result.current.initialized).toBe(false);
      expect(result.current.publicKeys).toBe(null);
    });

    it("should detect LOCKED status after init", async () => {
      mockBridge.isCryptoLocked.mockReturnValue(true);
      mockBridge.getPublicKeys.mockImplementation(() => {
        throw new Error("Locked");
      });

      const { result } = renderHook(() => useKeyset());

      await waitFor(() => {
        expect(result.current.initialized).toBe(true);
      });

      expect(result.current.vaultStatus).toBe("locked");
      expect(result.current.isLocked).toBe(true);
      expect(result.current.publicKeys).toBe(null);
    });

    it("should detect UNLOCKED status after init", async () => {
      mockBridge.isCryptoLocked.mockReturnValue(false);
      mockBridge.getPublicKeys.mockReturnValue(mockPublicKeys);

      const { result } = renderHook(() => useKeyset());

      await waitFor(() => {
        expect(result.current.initialized).toBe(true);
      });

      expect(result.current.vaultStatus).toBe("unlocked");
      expect(result.current.isLocked).toBe(false);
      expect(result.current.isUnlocked).toBe(true);
      expect(result.current.publicKeys).toEqual(mockPublicKeys);
    });

    it("should handle initialization error", async () => {
      mockBridge.init.mockRejectedValue(new Error("Init failed"));

      const { result } = renderHook(() => useKeyset());

      await waitFor(() => {
        expect(result.current.error).toBe("Failed to initialize crypto layer.");
      });
    });
  });

  describe("unlockSession", () => {
    it("should successfully unlock session", async () => {
      mockBridge.isCryptoLocked.mockReturnValue(true);
      mockBridge.unlockCryptoSession.mockResolvedValue(undefined);

      const { result } = renderHook(() => useKeyset());

      await waitFor(() => {
        expect(result.current.initialized).toBe(true);
      });

      mockBridge.isCryptoLocked.mockReturnValue(false);
      mockBridge.getPublicKeys.mockReturnValue(mockPublicKeys);

      let success;
      await act(async () => {
        success = await result.current.unlockSession("testuser", mockKeypair);
      });

      expect(success).toBe(true);
      expect(result.current.vaultStatus).toBe("unlocked");
      expect(result.current.publicKeys).toEqual(mockPublicKeys);
      expect(mockBridge.unlockCryptoSession).toHaveBeenCalledWith(
        "testuser",
        mockKeypair,
      );
    });

    it("should handle unlock failure", async () => {
      mockBridge.isCryptoLocked.mockReturnValue(true);
      const error = new Error("Invalid keypair");
      error.name = "KeysetError";
      error.code = "BAD_KEY_FORMAT";
      mockBridge.unlockCryptoSession.mockRejectedValue(error);

      const { result } = renderHook(() => useKeyset());

      await waitFor(() => {
        expect(result.current.initialized).toBe(true);
      });

      let success;
      await act(async () => {
        success = await result.current.unlockSession("testuser", mockKeypair);
      });

      expect(success).toBe(false);
      expect(result.current.error).toBe(
        "Invalid keypair — check your saved keys and try again.",
      );
      expect(result.current.vaultStatus).toBe("locked");
    });
  });

  describe("lockSession", () => {
    it("should lock session and clear keys", async () => {
      mockBridge.isCryptoLocked.mockReturnValue(false);
      mockBridge.getPublicKeys.mockReturnValue(mockPublicKeys);

      const { result } = renderHook(() => useKeyset());

      await waitFor(() => {
        expect(result.current.initialized).toBe(true);
      });

      act(() => {
        result.current.lockSession();
      });

      expect(mockBridge.logout).toHaveBeenCalled();
      expect(result.current.vaultStatus).toBe("locked");
      expect(result.current.publicKeys).toBe(null);
    });

    it("should handle logout error gracefully", async () => {
      mockBridge.logout.mockImplementation(() => {
        throw new Error("Logout failed");
      });

      const { result } = renderHook(() => useKeyset());

      await waitFor(() => {
        expect(result.current.initialized).toBe(true);
      });

      act(() => {
        result.current.lockSession();
      });

      expect(result.current.vaultStatus).toBe("locked");
      expect(result.current.publicKeys).toBe(null);
    });
  });

  describe("encryptRecord", () => {
    it("should encrypt record successfully", async () => {
      const fileBytes = new Uint8Array([1, 2, 3]);
      const recipientKey = "recipientPublicKey";
      const encryptedResult = {
        ciphertext: new Uint8Array([4, 5, 6]),
        nonce: new Uint8Array([7, 8, 9]),
      };

      mockBridge.encryptRecord.mockReturnValue(encryptedResult);

      const { result } = renderHook(() => useKeyset());

      let encrypted;
      await act(async () => {
        encrypted = await result.current.encryptRecord(fileBytes, recipientKey);
      });

      expect(encrypted).toEqual(encryptedResult);
      expect(mockBridge.encryptRecord).toHaveBeenCalledWith(
        fileBytes,
        recipientKey,
      );
    });

    it("should handle encryption error", async () => {
      mockBridge.encryptRecord.mockImplementation(() => {
        throw new Error("Encryption failed");
      });

      const { result } = renderHook(() => useKeyset());

      let encrypted;
      await act(async () => {
        encrypted = await result.current.encryptRecord(new Uint8Array(), "key");
      });

      expect(encrypted).toBe(null);
      expect(result.current.error).toBe("Encryption failed");
    });
  });

  describe("decryptShare", () => {
    it("should decrypt share successfully", async () => {
      const encryptedRecord = new Uint8Array([1, 2, 3]);
      const nonce = new Uint8Array([4, 5, 6]);
      const dekBundle = { key: new Uint8Array([7, 8, 9]) };
      const plaintext = new Uint8Array([10, 11, 12]);

      mockBridge.decryptShare.mockReturnValue(plaintext);

      const { result } = renderHook(() => useKeyset());

      let decrypted;
      await act(async () => {
        decrypted = await result.current.decryptShare(
          encryptedRecord,
          nonce,
          dekBundle,
        );
      });

      expect(decrypted).toEqual(plaintext);
      expect(mockBridge.decryptShare).toHaveBeenCalledWith(
        encryptedRecord,
        nonce,
        dekBundle,
      );
    });
  });

  describe("signPayload", () => {
    it("should sign payload successfully", async () => {
      const payload = { data: "test" };
      const signature = { payloadCanon: "canonical", signature: "sig123" };

      mockBridge.signPayload.mockReturnValue(signature);

      const { result } = renderHook(() => useKeyset());

      let signed;
      await act(async () => {
        signed = await result.current.signPayload(payload);
      });

      expect(signed).toEqual(signature);
      expect(mockBridge.signPayload).toHaveBeenCalledWith(payload);
    });
  });

  describe("verifySignature", () => {
    it("should verify signature successfully", () => {
      const payload = { data: "test" };
      const signature = "sig123";
      const publicKey = "pubkey456";

      mockBridge.verifySignature.mockReturnValue(true);

      const { result } = renderHook(() => useKeyset());

      const isValid = result.current.verifySignature(
        payload,
        signature,
        publicKey,
      );

      expect(isValid).toBe(true);
      expect(mockBridge.verifySignature).toHaveBeenCalledWith(
        payload,
        signature,
        publicKey,
      );
    });

    it("should return false for invalid signature", () => {
      mockBridge.verifySignature.mockImplementation(() => {
        throw new Error("Invalid signature");
      });

      const { result } = renderHook(() => useKeyset());

      const isValid = result.current.verifySignature({}, "sig", "key");

      expect(isValid).toBe(false);
    });
  });

  describe("clearError", () => {
    it("should clear error state", async () => {
      mockBridge.encryptRecord.mockImplementation(() => {
        throw new Error("Test error");
      });

      const { result } = renderHook(() => useKeyset());

      await act(async () => {
        await result.current.encryptRecord(new Uint8Array(), "key");
      });

      expect(result.current.error).toBeTruthy();

      act(() => {
        result.current.clearError();
      });

      expect(result.current.error).toBe(null);
    });
  });
});
