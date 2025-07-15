import { useState, useEffect } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Badge } from '@/components/ui/badge'
import { Separator } from '@/components/ui/separator'
import { AlertCircle, CheckCircle, Clock, Loader2, TestTube } from 'lucide-react'
import { getCities, getTechnicians, sendSMSRequest } from '@/api/sms'
import { useToast } from '@/hooks/useToast'

interface City {
  id: string
  name: string
  googleReviewLink: string
}

interface Technician {
  id: string
  name: string
  email: string
  phone: string
}

interface ApiResponse {
  success: boolean
  message: string
  messageId?: string
  error?: string
}

export function SMSDiagnosticsTool() {
  const [cities, setCities] = useState<City[]>([])
  const [technicians, setTechnicians] = useState<Technician[]>([])
  const [loading, setLoading] = useState(false)
  const [response, setResponse] = useState<ApiResponse | null>(null)
  const [startTime, setStartTime] = useState<number | null>(null)
  const [duration, setDuration] = useState<number | null>(null)
  const { toast } = useToast()

  const [formData, setFormData] = useState({
    cityId: '',
    technicianId: '',
    customerName: '',
    customerPhone: ''
  })

  useEffect(() => {
    loadData()
  }, [])

  const loadData = async () => {
    try {
      const [citiesResponse, techniciansResponse] = await Promise.all([
        getCities(),
        getTechnicians()
      ])

      console.log('SMSDiagnostics: Cities loaded:', citiesResponse)
      console.log('SMSDiagnostics: Technicians loaded:', techniciansResponse)

      setCities(citiesResponse.cities || [])
      setTechnicians(techniciansResponse.technicians || [])
    } catch (error) {
      console.error('SMSDiagnostics: Error loading data:', error)
      toast({
        title: "Error",
        description: "Failed to load cities and technicians",
        variant: "destructive",
      })
    }
  }

  const formatPhoneNumber = (value: string) => {
    const cleaned = value.replace(/\D/g, '')
    const match = cleaned.match(/^(\d{3})(\d{3})(\d{4})$/)
    if (match) {
      return `${match[1]}-${match[2]}-${match[3]}`
    }
    return value
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()

    if (!formData.cityId || !formData.technicianId || !formData.customerName || !formData.customerPhone) {
      toast({
        title: "Validation Error",
        description: "Please fill in all fields",
        variant: "destructive",
      })
      return
    }

    // Validate phone number format
    const phoneRegex = /^\d{3}-\d{3}-\d{4}$/
    if (!phoneRegex.test(formData.customerPhone)) {
      toast({
        title: "Validation Error",
        description: "Please enter a valid phone number in XXX-XXX-XXXX format",
        variant: "destructive",
      })
      return
    }

    setLoading(true)
    setResponse(null)
    setStartTime(Date.now())
    setDuration(null)

    console.log('=== SMS DIAGNOSTICS TOOL DEBUG START ===')
    console.log('SMSDiagnostics: Form submission started')
    console.log('SMSDiagnostics: Form data being sent:', {
      cityId: formData.cityId,
      technicianId: formData.technicianId,
      customerName: formData.customerName,
      customerPhone: formData.customerPhone
    })

    try {
      console.log('SMSDiagnostics: Calling sendSMSRequest API function...')
      const result = await sendSMSRequest(formData)
      const endTime = Date.now()
      const requestDuration = startTime ? endTime - startTime : 0

      console.log('SMSDiagnostics: API call completed successfully')
      console.log('SMSDiagnostics: Full API response received:', result)
      console.log('SMSDiagnostics: Request duration:', requestDuration, 'ms')

      setResponse(result)
      setDuration(requestDuration)

      if (result.success) {
        console.log('SMSDiagnostics: SMS marked as successful in response')
        toast({
          title: "Success",
          description: "SMS sent successfully",
        })
      } else {
        console.log('SMSDiagnostics: SMS marked as failed in response')
      }
    } catch (error) {
      const endTime = Date.now()
      const requestDuration = startTime ? endTime - startTime : 0

      console.error('SMSDiagnostics: API call failed with error:', error)
      console.error('SMSDiagnostics: Error type:', typeof error)
      console.error('SMSDiagnostics: Error message:', error instanceof Error ? error.message : 'Unknown error')

      setResponse({
        success: false,
        message: error instanceof Error ? error.message : 'Unknown error occurred',
        error: error instanceof Error ? error.message : 'Unknown error occurred'
      })
      setDuration(requestDuration)

      toast({
        title: "Error",
        description: error instanceof Error ? error.message : "Failed to send SMS",
        variant: "destructive",
      })
    } finally {
      setLoading(false)
      console.log('SMSDiagnostics: Form submission completed')
      console.log('=== SMS DIAGNOSTICS TOOL DEBUG END ===')
    }
  }

  const handleInputChange = (field: string, value: string) => {
    if (field === 'customerPhone') {
      const formatted = formatPhoneNumber(value)
      setFormData(prev => ({
        ...prev,
        [field]: formatted
      }))
    } else {
      setFormData(prev => ({
        ...prev,
        [field]: value
      }))
    }
  }

  return (
    <Card className="bg-white/60 dark:bg-gray-900/60 backdrop-blur-lg border-0 shadow-lg">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <TestTube className="h-5 w-5 text-blue-600" />
          SMS Diagnostics Tool
        </CardTitle>
        <CardDescription>
          Test the SMS sending functionality with live API calls
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label htmlFor="city">City</Label>
              <Select value={formData.cityId} onValueChange={(value) => handleInputChange('cityId', value)}>
                <SelectTrigger>
                  <SelectValue placeholder="Select a city" />
                </SelectTrigger>
                <SelectContent>
                  {cities.map((city) => (
                    <SelectItem key={city.id} value={city.id}>
                      {city.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-2">
              <Label htmlFor="technician">Technician</Label>
              <Select value={formData.technicianId} onValueChange={(value) => handleInputChange('technicianId', value)}>
                <SelectTrigger>
                  <SelectValue placeholder="Select a technician" />
                </SelectTrigger>
                <SelectContent>
                  {technicians.map((technician) => (
                    <SelectItem key={technician.id} value={technician.id}>
                      {technician.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-2">
              <Label htmlFor="customerName">Customer Name</Label>
              <Input
                id="customerName"
                type="text"
                placeholder="John Doe"
                value={formData.customerName}
                onChange={(e) => handleInputChange('customerName', e.target.value)}
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="customerPhone">Customer Phone</Label>
              <Input
                id="customerPhone"
                type="tel"
                placeholder="123-456-7890"
                value={formData.customerPhone}
                onChange={(e) => handleInputChange('customerPhone', e.target.value)}
              />
            </div>
          </div>

          <Button type="submit" disabled={loading} className="w-full">
            {loading ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                Testing SMS Send...
              </>
            ) : (
              <>
                <TestTube className="mr-2 h-4 w-4" />
                Test SMS Send
              </>
            )}
          </Button>
        </form>

        {response && (
          <>
            <Separator />
            <div className="space-y-4">
              <div className="flex items-center gap-2">
                <h3 className="text-lg font-semibold">API Response</h3>
                {response.success ? (
                  <CheckCircle className="h-5 w-5 text-green-600" />
                ) : (
                  <AlertCircle className="h-5 w-5 text-red-600" />
                )}
                {response.isMockMode && (
                  <Badge variant="secondary" className="ml-2">
                    Mock Mode
                  </Badge>
                )}
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="space-y-1">
                  <Label className="text-sm font-medium">Status</Label>
                  <Badge variant={response.success ? "default" : "destructive"}>
                    {response.success ? "Success" : "Failed"}
                  </Badge>
                </div>

                {duration !== null && (
                  <div className="space-y-1">
                    <Label className="text-sm font-medium">Duration</Label>
                    <div className="flex items-center gap-1">
                      <Clock className="h-4 w-4 text-muted-foreground" />
                      <span className="text-sm">{duration}ms</span>
                    </div>
                  </div>
                )}

                <div className="space-y-1">
                  <Label className="text-sm font-medium">Timestamp</Label>
                  <span className="text-sm text-muted-foreground">
                    {new Date().toLocaleTimeString()}
                  </span>
                </div>
              </div>

              {response.isMockMode && (
                <div className="p-4 bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-md">
                  <div className="flex items-start gap-2">
                    <AlertCircle className="h-5 w-5 text-yellow-600 mt-0.5" />
                    <div>
                      <h4 className="text-sm font-medium text-yellow-800 dark:text-yellow-200">
                        Development Mode Active
                      </h4>
                      <p className="text-sm text-yellow-700 dark:text-yellow-300 mt-1">
                        No actual SMS was sent. This is a simulated response for development purposes.
                        To enable real SMS sending in production, ensure proper environment configuration.
                      </p>
                    </div>
                  </div>
                </div>
              )}

              <div className="space-y-2">
                <Label className="text-sm font-medium">Message</Label>
                <div className="p-3 bg-muted rounded-md">
                  <p className="text-sm">{response.message}</p>
                </div>
              </div>

              {response.messageId && (
                <div className="space-y-2">
                  <Label className="text-sm font-medium">Message ID</Label>
                  <div className="p-3 bg-muted rounded-md">
                    <code className="text-sm font-mono">{response.messageId}</code>
                  </div>
                </div>
              )}

              <div className="space-y-2">
                <Label className="text-sm font-medium">Full API Response</Label>
                <div className="p-3 bg-muted rounded-md max-h-40 overflow-y-auto">
                  <pre className="text-xs font-mono whitespace-pre-wrap">
                    {JSON.stringify(response, null, 2)}
                  </pre>
                </div>
              </div>
            </div>
          </>
        )}
      </CardContent>
    </Card>
  )
}