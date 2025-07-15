import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react'
import { loginUser as apiLogin, register as apiRegister, getCurrentUser, logout as apiLogout } from '@/api/auth'

interface User {
  id: string
  email: string
  role: string
  createdAt: string
}

interface AuthContextType {
  user: User | null
  login: (email: string, password: string) => Promise<void>
  register: (email: string, password: string, role?: string) => Promise<void>
  logout: () => void
  loading: boolean
  isAdmin: boolean
  isAuthenticated: boolean
}

const AuthContext = createContext<AuthContextType | undefined>(undefined)

export const useAuth = () => {
  const context = useContext(AuthContext)
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider')
  }
  return context
}

interface AuthProviderProps {
  children: ReactNode
}

export const AuthProvider: React.FC<AuthProviderProps> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null)
  const [loading, setLoading] = useState(true)
  const [isAuthenticated, setIsAuthenticated] = useState(false)

  useEffect(() => {
    console.log('AuthContext: Component mounted, checking auth status')
    checkAuthStatus()
  }, [])

  const checkAuthStatus = async () => {
    console.log('AuthContext: Checking auth status')
    const token = localStorage.getItem('accessToken')
    console.log('AuthContext: Token from localStorage:', token ? 'EXISTS' : 'NOT_FOUND')
    
    if (token) {
      try {
        console.log('AuthContext: Fetching current user with existing token')
        const response = await getCurrentUser()
        console.log('AuthContext: Current user response:', response)
        
        // Fix: The API returns user data directly, not wrapped in a user property
        const userData = response.user || response // Handle both cases
        console.log('AuthContext: Extracted user data:', userData)
        
        // Convert _id to id for consistency
        const normalizedUser = {
          id: userData._id || userData.id,
          email: userData.email,
          role: userData.role,
          createdAt: userData.createdAt
        }

        setUser(normalizedUser)
        setIsAuthenticated(true)
        console.log('AuthContext: User restored from token:', normalizedUser)
      } catch (error) {
        console.error('AuthContext: Error fetching current user:', error)
        localStorage.removeItem('accessToken')
        localStorage.removeItem('refreshToken')
        setUser(null)
        setIsAuthenticated(false)
      }
    } else {
      console.log('AuthContext: No token found, user not authenticated')
      setUser(null)
      setIsAuthenticated(false)
    }
    setLoading(false)
  }

  const login = async (email: string, password: string) => {
    console.log('AuthContext: Starting login process for:', email);
    try {
      const response = await apiLogin({ email, password });
      console.log('AuthContext: Login API response:', response);
      
      if (response.accessToken) {
        localStorage.setItem('accessToken', response.accessToken);
        localStorage.setItem('refreshToken', response.refreshToken);
        console.log('AuthContext: Tokens stored in localStorage');
        
        // Fetch user info after successful login
        console.log('AuthContext: Fetching user info after login');
        const userResponse = await getCurrentUser();
        console.log('AuthContext: User info response:', userResponse);
        
        // Fix: Handle the user data structure properly
        const userData = userResponse.user || userResponse
        const normalizedUser = {
          id: userData._id || userData.id,
          email: userData.email,
          role: userData.role,
          createdAt: userData.createdAt
        }

        setUser(normalizedUser);
        setIsAuthenticated(true);
        console.log('AuthContext: User set in context:', normalizedUser);
        console.log('AuthContext: Authentication state set to true');
      }
    } catch (error) {
      console.error('AuthContext: Login error:', error);
      throw error;
    }
  }

  const register = async (email: string, password: string, role: string = 'user') => {
    try {
      console.log('Auth: Attempting registration for:', email, 'with role:', role)
      const response = await apiRegister({ email, password, role })
      
      localStorage.setItem('accessToken', response.accessToken)
      
      // Fix: Handle the user data structure properly
      const userData = response.user || response
      const normalizedUser = {
        id: userData._id || userData.id,
        email: userData.email,
        role: userData.role,
        createdAt: userData.createdAt
      }
      
      setUser(normalizedUser)
      setIsAuthenticated(true)
      console.log('Auth: Registration successful for user:', normalizedUser)
    } catch (error) {
      console.error('Auth: Registration failed:', error)
      throw error
    }
  }

  const logout = () => {
    console.log('Auth: Logging out user')
    localStorage.removeItem('accessToken')
    localStorage.removeItem('refreshToken')
    setUser(null)
    setIsAuthenticated(false)

    // Call API logout if needed
    apiLogout().catch(error => {
      console.error('Auth: API logout failed:', error)
    })
  }

  const isAdmin = user?.role === 'admin'

  const value: AuthContextType = {
    user,
    login,
    register,
    logout,
    loading,
    isAdmin,
    isAuthenticated
  }

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  )
}