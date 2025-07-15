import { useState, useEffect } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts'
import { MessageSquare, TrendingUp, Users, MapPin, Clock, CheckCircle, AlertCircle } from 'lucide-react'
import { getDashboardAnalytics } from '@/api/reports'
import { getMessageHistory } from '@/api/sms'
import { useAuth } from '@/contexts/AuthContext'
import { SMSDiagnosticsTool } from '@/components/SMSDiagnosticsTool'
import { useToast } from '@/hooks/useToast'

interface DashboardData {
  totalRequests: number
  successRate: number
  totalCities: number
  totalTechnicians: number
  requestsByCity: Array<{ name: string; count: number }>
  requestsByTechnician: Array<{ name: string; count: number }>
  recentActivity: Array<{
    id: string
    cityName: string
    technicianName: string
    customerName: string
    status: string
    sentAt: string
  }>
}

interface MessageHistoryItem {
  id: string
  cityName: string
  technicianName: string
  customerName: string
  customerPhone: string
  status: string
  sentAt: string
}

const COLORS = ['#0088FE', '#00C49F', '#FFBB28', '#FF8042', '#8884D8']

export function Dashboard() {
  const [data, setData] = useState<DashboardData | null>(null)
  const [recentMessages, setRecentMessages] = useState<MessageHistoryItem[]>([])
  const [loading, setLoading] = useState(true)
  const { user } = useAuth()
  const { toast } = useToast()

  useEffect(() => {
    loadDashboardData()
  }, [])

  const loadDashboardData = async () => {
    try {
      setLoading(true)
      const [analyticsResponse, messagesResponse] = await Promise.all([
        getDashboardAnalytics(),
        getMessageHistory({ page: 1, limit: 5 })
      ])

      console.log('Dashboard: Analytics response:', analyticsResponse)
      console.log('Dashboard: Messages response:', messagesResponse)

      setData(analyticsResponse)
      setRecentMessages(messagesResponse.messages || [])
    } catch (error) {
      console.error('Dashboard: Error loading data:', error)
      toast({
        title: "Error",
        description: error instanceof Error ? error.message : "Failed to load dashboard data",
        variant: "destructive",
      })
    } finally {
      setLoading(false)
    }
  }

  if (loading) {
    return (
      <div className="space-y-6">
        <div className="animate-pulse">
          <div className="h-8 bg-gray-200 rounded w-48 mb-2"></div>
          <div className="h-4 bg-gray-200 rounded w-64"></div>
        </div>
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          {[...Array(4)].map((_, i) => (
            <Card key={i} className="animate-pulse">
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <div className="h-4 bg-gray-200 rounded w-24"></div>
                <div className="h-4 w-4 bg-gray-200 rounded"></div>
              </CardHeader>
              <CardContent>
                <div className="h-8 bg-gray-200 rounded w-16 mb-2"></div>
                <div className="h-3 bg-gray-200 rounded w-32"></div>
              </CardContent>
            </Card>
          ))}
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight bg-gradient-to-r from-blue-600 to-indigo-600 bg-clip-text text-transparent">
          Dashboard
        </h1>
        <p className="text-muted-foreground">
          Overview of SMS review request activity and performance metrics
        </p>
      </div>

      {/* Key Metrics */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card className="bg-white/60 dark:bg-gray-900/60 backdrop-blur-lg border-0 shadow-lg">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Requests</CardTitle>
            <MessageSquare className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{data?.totalRequests || 0}</div>
            <p className="text-xs text-muted-foreground">
              SMS review requests sent
            </p>
          </CardContent>
        </Card>

        <Card className="bg-white/60 dark:bg-gray-900/60 backdrop-blur-lg border-0 shadow-lg">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Success Rate</CardTitle>
            <TrendingUp className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{data?.successRate || 0}%</div>
            <p className="text-xs text-muted-foreground">
              Successfully delivered
            </p>
          </CardContent>
        </Card>

        <Card className="bg-white/60 dark:bg-gray-900/60 backdrop-blur-lg border-0 shadow-lg">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Active Cities</CardTitle>
            <MapPin className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{data?.totalCities || 0}</div>
            <p className="text-xs text-muted-foreground">
              Service locations
            </p>
          </CardContent>
        </Card>

        <Card className="bg-white/60 dark:bg-gray-900/60 backdrop-blur-lg border-0 shadow-lg">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Technicians</CardTitle>
            <Users className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{data?.totalTechnicians || 0}</div>
            <p className="text-xs text-muted-foreground">
              Active team members
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Admin-only SMS Diagnostics Tool */}
      {user?.role === 'admin' && (
        <SMSDiagnosticsTool />
      )}

      {/* Charts */}
      <div className="grid gap-6 md:grid-cols-2">
        <Card className="bg-white/60 dark:bg-gray-900/60 backdrop-blur-lg border-0 shadow-lg">
          <CardHeader>
            <CardTitle>Requests by City</CardTitle>
            <CardDescription>SMS requests sent per service location</CardDescription>
          </CardHeader>
          <CardContent>
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={data?.requestsByCity || []}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="name" />
                <YAxis />
                <Tooltip />
                <Bar dataKey="count" fill="#3B82F6" />
              </BarChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>

        <Card className="bg-white/60 dark:bg-gray-900/60 backdrop-blur-lg border-0 shadow-lg">
          <CardHeader>
            <CardTitle>Requests by Technician</CardTitle>
            <CardDescription>Distribution of SMS requests by team member</CardDescription>
          </CardHeader>
          <CardContent>
            <ResponsiveContainer width="100%" height={300}>
              <PieChart>
                <Pie
                  data={data?.requestsByTechnician || []}
                  cx="50%"
                  cy="50%"
                  labelLine={false}
                  label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                  outerRadius={80}
                  fill="#8884d8"
                  dataKey="count"
                >
                  {(data?.requestsByTechnician || []).map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>
      </div>

      {/* Recent Activity */}
      <Card className="bg-white/60 dark:bg-gray-900/60 backdrop-blur-lg border-0 shadow-lg">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Clock className="h-5 w-5 text-blue-600" />
            Recent Activity
          </CardTitle>
          <CardDescription>Latest SMS review requests</CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Customer</TableHead>
                <TableHead>City</TableHead>
                <TableHead>Technician</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Sent At</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {recentMessages.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={5} className="text-center text-muted-foreground">
                    No recent activity
                  </TableCell>
                </TableRow>
              ) : (
                recentMessages.map((message) => (
                  <TableRow key={message.id}>
                    <TableCell className="font-medium">{message.customerName}</TableCell>
                    <TableCell>{message.cityName}</TableCell>
                    <TableCell>{message.technicianName}</TableCell>
                    <TableCell>
                      <Badge
                        variant={
                          message.status === 'Sent' ? 'default' :
                          message.status === 'Failed' ? 'destructive' : 'secondary'
                        }
                        className="flex items-center gap-1 w-fit"
                      >
                        {message.status === 'Sent' ? (
                          <CheckCircle className="h-3 w-3" />
                        ) : message.status === 'Failed' ? (
                          <AlertCircle className="h-3 w-3" />
                        ) : (
                          <Clock className="h-3 w-3" />
                        )}
                        {message.status}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      {new Date(message.sentAt).toLocaleString()}
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  )
}