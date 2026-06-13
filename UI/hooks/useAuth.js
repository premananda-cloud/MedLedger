// hooks/useAuth.js
import { useState, useEffect } from "react";
import { apiClient } from "../shared/apiClient.js";

export function useAuth() {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Check if user is already logged in
    checkAuth();
  }, []);

  const checkAuth = async () => {
    try {
      const userData = await apiClient.get("/api/me");
      setUser(userData);
    } catch (error) {
      setUser(null);
    } finally {
      setLoading(false);
    }
  };

  const login = async (username, password) => {
    const result = await apiClient.post("/api/login", { username, password });
    setUser({
      username: result.username,
      userIdHex: result.userIdHex,
      publicKeys: result.publicKeys,
    });
    return result;
  };

  const logout = async () => {
    await apiClient.post("/api/logout", {});
    setUser(null);
  };

  return {
    user,
    loading,
    login,
    logout,
    checkAuth,
  };
}
