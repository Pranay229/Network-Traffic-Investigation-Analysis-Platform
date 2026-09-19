/**
 * Open Access Authentication Context Provider
 * Provides a default active SOC Analyst context without requiring registration, login, or credentials.
 */
import React, { createContext, useContext, useMemo } from 'react';
import type { User, UserRole } from '../types';

interface AuthContextType {
  user: User | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (email: string, password: string, rememberMe?: boolean) => Promise<void>;
  register: (fullName: string, email: string, password: string, confirmPassword: string) => Promise<{ requires_verification: boolean; message: string }>;
  logout: () => Promise<void>;
  logoutAll: () => Promise<void>;
  refreshProfile: () => Promise<void>;
  hasRole: (roles: UserRole | UserRole[]) => boolean;
}

const DEFAULT_USER: User = {
  id: 1,
  email: 'analyst@novacyberspark.local',
  full_name: 'SOC Analyst',
  role: 'ADMIN',
  is_active: true,
  is_email_verified: true,
  created_at: '2026-01-01T00:00:00Z',
  last_login_at: null,
};

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const value = useMemo<AuthContextType>(
    () => ({
      user: DEFAULT_USER,
      isAuthenticated: true,
      isLoading: false,
      login: async () => {},
      register: async () => ({ requires_verification: false, message: 'Open access active' }),
      logout: async () => {},
      logoutAll: async () => {},
      refreshProfile: async () => {},
      hasRole: () => true,
    }),
    []
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

export default AuthProvider;
