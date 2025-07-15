import api from './api';

// Description: User login
// Endpoint: POST /api/auth/login
// Request: { email: string, password: string }
// Response: { user: { id: string, email: string, role: string, createdAt: string }, accessToken: string, refreshToken: string }
export const loginUser = async (data: { email: string; password: string }) => {
  console.log('API: Attempting login with data:', { email: data.email, password: '[HIDDEN]' });
  try {
    const response = await api.post('/api/auth/login', data);
    console.log('API: Login response received:', response.data);
    return response.data;
  } catch (error: any) {
    console.error('API: Login error:', error?.response?.data || error.message);
    throw new Error(error?.response?.data?.error || error.message);
  }
};

// Description: User registration
// Endpoint: POST /api/auth/register
// Request: { email: string, password: string, role?: string }
// Response: { user: { id: string, email: string, role: string, createdAt: string }, accessToken: string }
export const register = async (data: { email: string; password: string; role?: string }) => {
  try {
    const response = await api.post('/api/auth/register', data);
    return response.data;
  } catch (error: any) {
    throw new Error(error?.response?.data?.message || error?.response?.data?.error || error.message);
  }
};

// Description: Get current user information
// Endpoint: GET /api/auth/me
// Request: {}
// Response: { user: { id: string, email: string, role: string, createdAt: string } }
export const getCurrentUser = async () => {
  console.log('API: Fetching current user');
  try {
    const response = await api.get('/api/auth/me');
    console.log('API: Current user response:', response.data);
    return response.data;
  } catch (error: any) {
    console.error('API: Get current user error:', error?.response?.data || error.message);
    throw new Error(error?.response?.data?.error || error.message);
  }
};

// Description: User logout
// Endpoint: POST /api/auth/logout
// Request: {}
// Response: { message: string }
export const logout = async () => {
  try {
    const response = await api.post('/api/auth/logout');
    return response.data;
  } catch (error: any) {
    throw new Error(error?.response?.data?.message || error?.response?.data?.error || error.message);
  }
};