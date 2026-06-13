// hooks/useKeyset.js
import { useState, useEffect } from "react";
import { KeysetManager } from "../key_manager/key_manager.js";
import {
  unlockVault,
  lockVault,
  isVaultUnlocked,
} from "../shared/loginBridge.js";

export function useKeyset() {
  const [locked, setLocked] = useState(true);
  const [publicKeys, setPublicKeys] = useState(null);

  useEffect(() => {
    const init = async () => {
      await KeysetManager.init();
      setLocked(KeysetManager.isLocked());
      if (!KeysetManager.isLocked()) {
        // Get session info if unlocked
        // This would require a getSession() method in KeysetManager
        setPublicKeys({
          signing: KeysetManager.signingPublicKey,
          exchange: KeysetManager.exchangePublicKey,
        });
      }
    };
    init();
  }, []);

  const login = async (username, keypairFile, serverPublicKeys) => {
    const result = await unlockVault(username, keypairFile, serverPublicKeys);
    setLocked(false);
    setPublicKeys(result.publicKeys);
    return result;
  };

  const logout = () => {
    lockVault();
    setLocked(true);
    setPublicKeys(null);
  };

  const checkLocked = () => {
    return KeysetManager.isLocked();
  };

  return {
    locked,
    publicKeys,
    login,
    logout,
    checkLocked,
  };
}
