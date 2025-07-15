import { Navigate, useLocation } from "react-router-dom";
import { useAuth } from "@/contexts/AuthContext";

export function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated, user, loading } = useAuth();
  const location = useLocation();

  console.log('ProtectedRoute: Checking protection for path:', location.pathname);
  console.log('ProtectedRoute: isAuthenticated:', isAuthenticated);
  console.log('ProtectedRoute: user:', user);
  console.log('ProtectedRoute: loading:', loading);

  if (loading) {
    console.log('ProtectedRoute: Still loading, showing loading state');
    return <div>Loading...</div>;
  }

  if (!isAuthenticated) {
    console.log('ProtectedRoute: Not authenticated, redirecting to login');
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  console.log('ProtectedRoute: Authenticated, rendering children');
  return <>{children}</>;
}