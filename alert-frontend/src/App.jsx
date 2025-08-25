import { useState, useEffect, useRef } from 'react'
import 'bootstrap/dist/css/bootstrap.min.css'
import 'bootstrap-icons/font/bootstrap-icons.css'
import './App.css'
import Navbar from './components/Navbar'
import { useDarkMode } from './contexts/DarkModeContext'
import { 
  SeverityChart, 
  AlertTrendChart, 
  ResponseRateChart, 
  ClassificationMethodChart 
} from './components/Charts'
import React from 'react'
import { BrowserRouter, Routes, Route } from 'react-router-dom'
import ReportGenerator from './components/Reports/ReportGenerator'
import SimpleReportGenerator from './components/Reports/SimpleReportGenerator'
import ThreatIntelligenceDashboard from './components/ThreatIntelligenceDashboard'
import LiveAlertMonitor from './components/LiveAlertMonitor';
import { ErrorBoundary } from 'react-error-boundary'

// Add error fallback component
const ErrorFallback = ({ error }) => (
  <div className="alert alert-danger m-3" role="alert">
    <h4 className="alert-heading">Error Loading Alerts</h4>
    <p>{error.message}</p>
    <hr />
    <button 
      className="btn btn-outline-danger"
      onClick={() => window.location.reload()}
    >
      Retry
    </button>
  </div>
);

function App() {
  // Define all state variables
  const [alerts, setAlerts] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [message, setMessage] = useState('')
  const [submissionResult, setSubmissionResult] = useState(null)
  const [showResult, setShowResult] = useState(false)
  const [classificationMethod, setClassificationMethod] = useState('model')
  const [activeTab, setActiveTab] = useState('create')
  const { isDarkMode } = useDarkMode()
  const [showFloatingButton, setShowFloatingButton] = useState(false)
  
  // Stats counters
  const [alertStats, setAlertStats] = useState({
    total: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    ticketed: 0
  })
  
  // Reference for alert form section for quick navigation
  const createAlertRef = useRef(null)

  // Show/hide floating action button based on scroll position
  useEffect(() => {
    const handleScroll = () => {
      if (window.scrollY > 300) {
        setShowFloatingButton(true)
      } else {
        setShowFloatingButton(false)
      }
    }
    
    window.addEventListener('scroll', handleScroll)
    return () => window.removeEventListener('scroll', handleScroll)
  }, [])
  
  // Load alerts when component mounts
  useEffect(() => {
    fetchAlerts()
  }, [])
  
  // Calculate stats whenever alerts change
  useEffect(() => {
    if (alerts.length) {
      setAlertStats({
        total: alerts.length,
        critical: alerts.filter(a => a.severity === 'Critical').length,
        high: alerts.filter(a => a.severity === 'High').length,
        medium: alerts.filter(a => a.severity === 'Medium').length,
        low: alerts.filter(a => a.severity === 'Low').length,
        ticketed: alerts.filter(a => a.jira_ticket_id).length
      })
    }
  }, [alerts])

  const fetchAlerts = async () => {
    try {
      setLoading(true);
      console.log('Fetching alerts from API...');
      
      const response = await fetch('http://localhost:5000/get_alerts', {
        method: 'GET',
        headers: {
          'Accept': 'application/json',
          'Content-Type': 'application/json'
        },
        mode: 'cors'  // Add this line
      });
      
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || `HTTP error! status: ${response.status}`);
      }
      
      const data = await response.json();
      console.log('Received alerts:', data);
      
      if (Array.isArray(data)) {
        setAlerts(data);
        setError(null);
      } else {
        throw new Error('Invalid response format: expected an array');
      }
    } catch (err) {
      console.error('Error fetching alerts:', err);
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const fetchAlertsBySeverity = async (severity) => {
    try {
      setLoading(true)
      const response = await fetch(`http://localhost:5000/get_alerts?severity=${severity}`)
      
      if (!response.ok) {
        throw new Error(`Server responded with ${response.status}`)
      }
      
      const data = await response.json()
      setAlerts(data)
      setError(null)
    } catch (err) {
      console.error('Error fetching alerts by severity:', err)
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  const deleteAllAlerts = async () => {
    if (!window.confirm('Are you sure you want to delete ALL alerts? This cannot be undone.')) {
      return
    }
    
    try {
      const response = await fetch('http://localhost:5000/delete_alerts', {
        method: 'DELETE'
      })
      
      if (!response.ok) {
        throw new Error(`Server responded with ${response.status}`)
      }
      
      fetchAlerts()
      setError(null)
    } catch (err) {
      console.error('Error deleting alerts:', err)
      setError(err.message)
    }
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    if (!message.trim()) return
    
    try {
      console.log('Submitting alert:', message)
      console.log('Using classification method:', classificationMethod)
      setLoading(true)
      
      const response = await fetch('http://localhost:5000/process_alert', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ 
          message, 
          classification_method: classificationMethod 
        })
      })
      
      const result = await response.json()
      console.log('Full API response:', result)
      
      if (response.ok) {
        // Store the result for display
        setSubmissionResult(result)
        setShowResult(true)
        setMessage('')
        fetchAlerts()
        setError(null)
        // Auto-scroll to the result
        setTimeout(() => {
          document.getElementById('result-section')?.scrollIntoView({ behavior: 'smooth' })
        }, 100)
      } else {
        setError(result.error || 'Error processing alert')
        setSubmissionResult(null)
        setShowResult(false)
      }
    } catch (err) {
      console.error('Error submitting alert:', err)
      setError(err.message)
      setSubmissionResult(null)
      setShowResult(false)
    } finally {
      setLoading(false)
    }
  }

  // Function to close the result modal
  const handleCreateNewAlert = () => {
    setActiveTab('create')
    setShowResult(false)
    setSubmissionResult(null)
    
    // Scroll to form on mobile
    if (window.innerWidth < 992) {
      setTimeout(() => {
        createAlertRef.current?.scrollIntoView({ behavior: 'smooth' })
      }, 100)
    }
  }
  
  // Function to close the result modal
  const closeResultModal = () => {
    setShowResult(false)
    setSubmissionResult(null)
  }
  
  // Function to format date
  const formatDate = (dateString) => {
    const options = { 
      year: 'numeric', 
      month: 'short', 
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    }
    return new Date(dateString).toLocaleString(undefined, options)
  }
  
  // Function to get severity icon
  const getSeverityIcon = (severity) => {
    switch(severity) {
      case 'Critical': return <i className="bi bi-exclamation-triangle-fill"></i>
      case 'High': return <i className="bi bi-exclamation-circle-fill"></i>
      case 'Medium': return <i className="bi bi-exclamation"></i>
      case 'Low': return <i className="bi bi-info-circle-fill"></i>
      default: return <i className="bi bi-question-circle-fill"></i>
    }
  }
  
  // Color scheme by severity 
  const getSeverityColor = (severity) => {
    switch(severity) {
      case 'Critical': return '#ef4444'
      case 'High': return '#f59e0b'  
      case 'Medium': return '#3b82f6'
      case 'Low': return '#10b981'
      default: return '#6b7280'
    }
  }

  // Render loading spinner function
  const renderLoading = () => (
    <div className="loading-spinner-container">
      <div className="loading-spinner"></div>
      <p className="mt-3 text-muted">Loading...</p>
    </div>
  )

  return (
    <ErrorBoundary FallbackComponent={ErrorFallback}>
      <BrowserRouter>
        <Routes>
          <Route path="/" element={
            <div className={`app-container ${isDarkMode ? 'dark-mode' : ''}`}>
              {/* Modern Navigation Bar */}
              <Navbar 
                activeTab={activeTab} 
                setActiveTab={setActiveTab} 
                alertCount={alerts.length}
              />
              
              <div className="container-fluid px-4 py-3">
                {/* Header Section */}
                <div className="app-header mb-4">
                  <div className="d-flex justify-content-between align-items-center">
                    <div>
                      <h1>
                        <i className="bi bi-shield-lock security-logo me-2"></i>
                        Security Alert System
                      </h1>
                      <p className="lead">Enterprise-grade security monitoring and response platform</p>
                    </div>
                    <div className="d-none d-md-flex align-items-center">
                      <div className="me-4">
                        <div className="d-flex align-items-center">
                          <span className="status-indicator status-active"></span>
                          <span className="text-light">System Active</span>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
                
                {/* Error Message */}
                {error && (
                  <div className="alert alert-danger d-flex align-items-center mb-4">
                    <i className="bi bi-exclamation-triangle-fill me-2 fs-5"></i>
                    <div>{error}</div>
                    <button type="button" className="btn-close ms-auto" onClick={() => setError(null)}></button>
                  </div>
                )}
                
                {/* Create Alert Content */}
                {activeTab === 'create' && (
                  <div className="row" ref={createAlertRef}>
                    <div className="col-lg-7 order-lg-1 order-2">
                      <div className="card card-3d">
                        <div className="card-header bg-primary text-white d-flex align-items-center">
                          <i className="bi bi-bell-fill fs-4 me-2"></i>
                          <h3 className="mb-0">Create New Security Alert</h3>
                        </div>
                        <div className="card-body">
                          <form onSubmit={handleSubmit}>
                            <div className="mb-4">
                              <label htmlFor="message" className="form-label">
                                <i className="bi bi-chat-text me-2"></i>Alert Description
                              </label>
                              <textarea 
                                className="form-control shadow-sm"
                                style={{ minHeight: "150px" }} 
                                id="message" 
                                rows="5"
                                placeholder="Describe the security incident or alert in detail..."
                                value={message}
                                onChange={(e) => setMessage(e.target.value)}
                                required
                              ></textarea>
                              <div className="form-text">
                                Enter all relevant details about the security event to ensure accurate classification.
                              </div>
                            </div>
                            
                            <div className="mb-4">
                              <label className="form-label d-flex align-items-center">
                                <i className="bi bi-gear-fill me-2"></i>Classification Method
                              </label>
                              <div className="d-flex flex-wrap gap-3">
                                <div className="form-check card p-3" style={{minWidth: "200px", cursor: "pointer"}}>
                                  <input
                                    className="form-check-input"
                                    type="radio"
                                    name="classificationMethod"
                                    id="modelMethod"
                                    value="model"
                                    checked={classificationMethod === 'model'}
                                    onChange={(e) => setClassificationMethod(e.target.value)}
                                  />
                                  <label className="form-check-label w-100" htmlFor="modelMethod" style={{cursor: "pointer"}}>
                                    <div className="d-flex align-items-center mb-2">
                                      <i className="bi bi-cpu me-2 text-primary fs-3"></i>
                                      <span className="fw-bold">Local ML Model</span>
                                    </div>
                                    <p className="text-muted mb-0 small">
                                      Uses a trained machine learning model to classify alerts based on historical data.
                                    </p>
                                  </label>
                                </div>
                                <div className="form-check card p-3" style={{minWidth: "200px", cursor: "pointer"}}>
                                  <input
                                    className="form-check-input"
                                    type="radio"
                                    name="classificationMethod"
                                    id="geminiMethod"
                                    value="gemini"
                                    checked={classificationMethod === 'gemini'}
                                    onChange={(e) => setClassificationMethod(e.target.value)}
                                  />
                                  <label className="form-check-label w-100" htmlFor="geminiMethod" style={{cursor: "pointer"}}>
                                    <div className="d-flex align-items-center mb-2">
                                      <i className="bi bi-stars me-2 text-warning fs-3"></i>
                                      <span className="fw-bold">Gemini AI</span>
                                    </div>
                                    <p className="text-muted mb-0 small">
                                      Uses Google's advanced AI to provide intelligent analysis with impact assessment.
                                    </p>
                                  </label>
                                </div>
                              </div>
                            </div>
                            
                            <div className="mb-3 d-grid">
                              <button type="submit" className="btn btn-primary btn-lg py-3" disabled={loading}>
                                {loading ? (
                                  <>
                                    <span className="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span>
                                    Processing...
                                  </>
                                ) : (
                                  <>
                                    <i className="bi bi-send me-2"></i>Submit Security Alert
                                  </>
                                )}
                              </button>
                            </div>
                          </form>
                        </div>
                      </div>
                    </div>

                    {/* Processing Status */}
                    <div className="col-lg-5 order-lg-2 order-1 mb-4 mb-lg-0">
                      <div className="card glass-card h-100">
                        <div className="card-header bg-dark text-white d-flex align-items-center">
                          <i className="bi bi-activity fs-4 me-2"></i>
                          <h3 className="mb-0">System Status</h3>
                        </div>
                        <div className="card-body d-flex flex-column justify-content-center">
                          <div className="text-center mb-4">
                            <span className="d-inline-block p-3 bg-light rounded-circle mb-3">
                              <i className="bi bi-shield-check text-success fs-1"></i>
                            </span>
                            <h4>Security Monitoring Active</h4>
                            <p className="text-muted">
                              The system is actively monitoring for security threats and incidents
                            </p>
                          </div>
                          
                          <div className="row row-cols-2 g-3 mb-4">
                            <div className="col">
                              <div className="stats-box h-100">
                                <div className="d-flex flex-column align-items-start">
                                  <div className="bg-light p-2 rounded mb-2">
                                    <i className="bi bi-shield-exclamation fs-4 text-primary"></i>
                                  </div>
                                  <div className="stats-value">{alertStats.total}</div>
                                  <div className="stats-label">Total Alerts</div>
                                </div>
                              </div>
                            </div>
                            <div className="col">
                              <div className="stats-box h-100">
                                <div className="d-flex flex-column align-items-start">
                                  <div className="bg-light p-2 rounded mb-2">
                                    <i className="bi bi-kanban fs-4 text-success"></i>
                                  </div>
                                  <div className="stats-value">{alertStats.ticketed}</div>
                                  <div className="stats-label">Tickets Created</div>
                                </div>
                              </div>
                            </div>
                            <div className="col">
                              <div className="stats-box h-100">
                                <div className="d-flex flex-column align-items-start">
                                  <div className="bg-light p-2 rounded mb-2">
                                    <i className="bi bi-exclamation-triangle fs-4 text-danger"></i>
                                  </div>
                                  <div className="stats-value">{alertStats.critical + alertStats.high}</div>
                                  <div className="stats-label">High/Critical</div>
                                </div>
                              </div>
                            </div>
                            <div className="col">
                              <div className="stats-box h-100">
                                <div className="d-flex flex-column align-items-start">
                                  <div className="bg-light p-2 rounded mb-2">
                                    <i className="bi bi-info-circle fs-4 text-info"></i>
                                  </div>
                                  <div className="stats-value">{alertStats.medium + alertStats.low}</div>
                                  <div className="stats-label">Medium/Low</div>
                                </div>
                              </div>
                            </div>
                          </div>

                          <div className="d-grid">
                            <button className="btn btn-outline-primary" onClick={() => setActiveTab('alerts')}>
                              <i className="bi bi-list-ul me-2"></i>
                              View All Alerts
                            </button>
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                )}
                
                {/* Result Section */}
                {showResult && submissionResult && (
                  <div className="row mb-4" id="result-section">
                    <div className="col">
                      <div className="card result-card">
                        <div className="card-header bg-success text-white d-flex justify-content-between align-items-center">
                          <div className="d-flex align-items-center">
                            <i className="bi bi-check-circle-fill fs-4 me-2"></i>
                            <h3 className="mb-0">Alert Processed Successfully</h3>
                          </div>
                          <button 
                            type="button" 
                            className="btn-close btn-close-white" 
                            onClick={closeResultModal}
                          ></button>
                        </div>
                        <div className="card-body">
                          <div className="alert" style={{
                            backgroundColor: `${getSeverityColor(submissionResult.severity)}15`,
                            borderLeft: `4px solid ${getSeverityColor(submissionResult.severity)}`
                          }}>
                            <div className="d-flex justify-content-between align-items-center flex-wrap">
                              <h4 className="mb-0 d-flex align-items-center">
                                <span className="me-2">Alert Severity:</span>
                                <span className="badge p-2" style={{
                                  backgroundColor: getSeverityColor(submissionResult.severity),
                                  color: 'white'
                                }}>
                                  {getSeverityIcon(submissionResult.severity)}
                                  <span className="ms-1">{submissionResult.severity}</span>
                                </span>
                              </h4>
                              <span className="badge bg-secondary d-flex align-items-center p-2 mt-2 mt-sm-0">
                                <i className="bi bi-clock me-1"></i>
                                {formatDate(submissionResult.timestamp)}
                              </span>
                            </div>
                            
                            {/* Display classification method */}
                            <div className="mt-3 d-flex align-items-center">
                              <strong className="me-2">Classification by:</strong> 
                              {submissionResult.classification_method === 'gemini' ? (
                                <span className="badge bg-warning text-dark d-flex align-items-center p-2">
                                  <i className="bi bi-stars me-1"></i>Gemini AI
                                </span>
                              ) : (
                                <span className="badge bg-primary d-flex align-items-center p-2">
                                  <i className="bi bi-cpu me-1"></i>Local ML Model
                                </span>
                              )}
                            </div>
                          </div>
                          
                          {/* Show Impact Analysis (for Gemini) */}
                          {submissionResult.impact && (
                            <div className="impact-analysis my-4">
                              <h5 className="d-flex align-items-center mb-3">
                                <i className="bi bi-graph-up-arrow me-2 text-primary"></i>Impact Analysis
                              </h5>
                              <p className="mb-3 lead">{submissionResult.impact}</p>
                              
                              {submissionResult.reasoning && (
                                <div className="mt-3 pt-3 border-top">
                                  <strong className="d-flex align-items-center">
                                    <i className="bi bi-lightbulb me-2 text-warning"></i>Reasoning:
                                  </strong> 
                                  <p className="mb-0 mt-2">{submissionResult.reasoning}</p>
                                </div>
                              )}
                            </div>
                          )}
                          
                          <div className="row mt-4 g-4">
                            {/* Jira Ticket Info */}
                            <div className="col-md-6">
                              <div className="card card-3d h-100">
                                <div className="card-header d-flex align-items-center">
                                  <span className="jira-icon"></span>
                                  <h5 className="mb-0">Jira Ticket Status</h5>
                                </div>
                                <div className="card-body">
                                  {submissionResult.jira_ticket ? (
                                    <div className="text-center">
                                      <span className="d-inline-block p-3 bg-success bg-opacity-10 rounded-circle mb-3">
                                        <i className="bi bi-check-circle-fill text-success fs-1"></i>
                                      </span>
                                      <h5 className="mb-3">Ticket Successfully Created</h5>
                                      <div className="d-flex align-items-center justify-content-center mb-3">
                                        <span className="badge bg-primary p-2 fs-6">
                                          {submissionResult.jira_ticket}
                                        </span>
                                      </div>
                                      <a 
                                        href={`https://subhashsrinivas36.atlassian.net/browse/${submissionResult.jira_ticket}`} 
                                        target="_blank" 
                                        rel="noopener noreferrer" 
                                        className="btn btn-outline-primary"
                                      >
                                        <i className="bi bi-box-arrow-up-right me-2"></i>View in Jira
                                      </a>
                                    </div>
                                  ) : (
                                    <div className="text-center">
                                      <span className="d-inline-block p-3 bg-warning bg-opacity-10 rounded-circle mb-3">
                                        <i className="bi bi-exclamation-circle-fill text-warning fs-1"></i>
                                      </span>
                                      <h5>No Ticket Created</h5>
                                      <p className="text-muted">
                                        The system couldn't create a Jira ticket for this alert. Please check your Jira configuration.
                                      </p>
                                    </div>
                                  )}
                                </div>
                              </div>
                            </div>
                            
                            {/* Slack Notification Info */}
                            <div className="col-md-6">
                              <div className="card card-3d h-100">
                                <div className="card-header d-flex align-items-center">
                                  <span className="slack-icon"></span>
                                  <h5 className="mb-0">Slack Notification Status</h5>
                                </div>
                                <div className="card-body">
                                  {submissionResult.slack_notification_sent === true ? (
                                    <div className="text-center">
                                      <span className="d-inline-block p-3 bg-success bg-opacity-10 rounded-circle mb-3">
                                        <i className="bi bi-check-circle-fill text-success fs-1"></i>
                                      </span>
                                      <h5 className="mb-3">Notification Sent</h5>
                                      <p>The security team has been notified via Slack</p>
                                      <div className="alert alert-info">
                                        <div className="d-flex align-items-center">
                                          <i className="bi bi-info-circle-fill me-2"></i>
                                          <small>A detailed notification with recommendations was sent to the security channel</small>
                                        </div>
                                      </div>
                                    </div>
                                  ) : (
                                    <div className="text-center">
                                      <span className="d-inline-block p-3 bg-warning bg-opacity-10 rounded-circle mb-3">
                                        <i className="bi bi-exclamation-circle-fill text-warning fs-1"></i>
                                      </span>
                                      <h5>Notification Not Sent</h5>
                                      <p className="text-muted">
                                        Slack notification could not be sent. This could be due to configuration issues.
                                      </p>
                                    </div>
                                  )}
                                </div>
                              </div>
                            </div>
                          </div>
                          
                          {/* Recommendations */}
                          {submissionResult.recommendations && (
                            <div className="mt-4">
                              <h5 className="d-flex align-items-center mb-3">
                                <i className="bi bi-list-check fs-4 me-2 text-primary"></i>Recommended Actions:
                              </h5>
                              <div className="row g-4">
                                <div className="col-md-6">
                                  <div className="card glass-card h-100">
                                    <div className="card-header bg-primary text-white d-flex align-items-center">
                                      <i className="bi bi-lightning-fill me-2"></i>
                                      <h6 className="mb-0">Immediate Actions</h6>
                                    </div>
                                    <div className="card-body p-0">
                                      <ul className="list-group list-group-flush">
                                        {submissionResult.recommendations.immediate.map((rec, index) => (
                                          <li key={index} className="list-group-item d-flex py-3">
                                            <div className="d-flex">
                                              <span className="rounded-circle me-3 mt-1 d-flex align-items-center justify-content-center" 
                                                    style={{minWidth: "24px", height: "24px", background: "#e6f0ff", color: "#0066ff"}}>
                                                <small>{index + 1}</small>
                                              </span>
                                            </div>
                                            <span>{rec}</span>
                                          </li>
                                        ))}
                                      </ul>
                                    </div>
                                  </div>
                                </div>
                                
                                {submissionResult.recommendations.long_term && 
                                  submissionResult.recommendations.long_term.length > 0 && (
                                  <div className="col-md-6">
                                    <div className="card glass-card h-100">
                                      <div className="card-header bg-secondary text-white d-flex align-items-center">
                                        <i className="bi bi-clock-history me-2"></i>
                                        <h6 className="mb-0">Long-term Actions</h6>
                                      </div>
                                      <div className="card-body p-0">
                                        <ul className="list-group list-group-flush">
                                          {submissionResult.recommendations.long_term.map((rec, index) => (
                                            <li key={index} className="list-group-item d-flex py-3">
                                              <div className="d-flex">
                                                <span className="rounded-circle me-3 mt-1 d-flex align-items-center justify-content-center" 
                                                      style={{minWidth: "24px", height: "24px", background: "#e6e6e6", color: "#666666"}}>
                                                  <small>{index + 1}</small>
                                                </span>
                                              </div>
                                              <span>{rec}</span>
                                            </li>
                                          ))}
                                        </ul>
                                      </div>
                                    </div>
                                  </div>
                                )}
                              </div>
                            </div>
                          )}
                          
                          {/* Response Details - Collapsible */}
                          <div className="mt-4 pt-3 border-top">
                            <button 
                              className="btn btn-outline-secondary d-flex align-items-center"
                              type="button"
                              data-bs-toggle="collapse"
                              data-bs-target="#responseDetails"
                              aria-expanded="false"
                              aria-controls="responseDetails"
                            >
                              <i className="bi bi-code-slash me-2"></i>
                              Technical Details
                              <i className="bi bi-chevron-down ms-2"></i>
                            </button>
                            <div className="collapse mt-3" id="responseDetails">
                              <div className="card card-body bg-light">
                                <pre className="mb-0" style={{ fontSize: '0.85rem', whiteSpace: 'pre-wrap' }}>
                                  {JSON.stringify(submissionResult, null, 2)}
                                </pre>
                              </div>
                            </div>
                          </div>
                          
                          {/* Action Buttons */}
                          <div className="d-flex justify-content-between mt-4 pt-3 border-top">
                            <button className="btn btn-outline-primary" onClick={() => setActiveTab('alerts')}>
                              <i className="bi bi-list me-2"></i>View All Alerts
                            </button>
                            <button className="btn btn-primary" onClick={handleCreateNewAlert}>
                              <i className="bi bi-plus-circle me-2"></i>Create New Alert
                            </button>
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                )}
                
                {/* Alerts Tab Content */}
                {activeTab === 'alerts' && (
                  <div className="row">
                    <div className="col-12">
                      <div className="card shadow">
                        <div className="card-header bg-dark text-white d-flex justify-content-between align-items-center">
                          <h3 className="mb-0 d-flex align-items-center">
                            <i className="bi bi-shield-exclamation fs-4 me-2"></i>Security Alerts
                          </h3>
                          <div className="btn-group">
                            <button onClick={fetchAlerts} className="btn btn-outline-light">
                              <i className="bi bi-arrow-clockwise me-1"></i>Refresh
                            </button>
                            <button onClick={deleteAllAlerts} className="btn btn-outline-danger">
                              <i className="bi bi-trash me-1"></i>Delete All
                            </button>
                          </div>
                        </div>
                        
                        <div className="card-body">
                          <div className="mb-4">
                            <div className="d-flex justify-content-between align-items-center flex-wrap gap-3 mb-3">
                              <div className="btn-group shadow-sm" role="group">
                                <button 
                                  type="button" 
                                  className="btn btn-outline-secondary"
                                  onClick={() => fetchAlerts()}
                                >
                                  All Alerts
                                </button>
                                <button 
                                  type="button" 
                                  className="btn btn-outline-success"
                                  onClick={() => fetchAlertsBySeverity('Low')}
                                >
                                  <span className="status-indicator" style={{ backgroundColor: "#10b981" }}></span>
                                  Low
                                </button>
                                <button 
                                  type="button" 
                                  className="btn btn-outline-primary"
                                  onClick={() => fetchAlertsBySeverity('Medium')}
                                >
                                  <span className="status-indicator" style={{ backgroundColor: "#3b82f6" }}></span>
                                  Medium
                                </button>
                                <button 
                                  type="button" 
                                  className="btn btn-outline-warning"
                                  onClick={() => fetchAlertsBySeverity('High')}
                                >
                                  <span className="status-indicator" style={{ backgroundColor: "#f59e0b" }}></span>
                                  High
                                </button>
                                <button 
                                  type="button" 
                                  className="btn btn-outline-danger"
                                  onClick={() => fetchAlertsBySeverity('Critical')}
                                >
                                  <span className="status-indicator" style={{ backgroundColor: "#ef4444" }}></span>
                                  Critical
                                </button>
                              </div>
                              <div className="d-flex align-items-center">
                                <span className="badge bg-dark me-2">
                                  {alerts.length} {alerts.length === 1 ? 'Alert' : 'Alerts'}
                                </span>
                              </div>
                            </div>
                          </div>
                          
                          {loading ? (
                            renderLoading()
                          ) : alerts.length === 0 ? (
                            <div className="text-center p-5">
                              <div className="mb-4">
                                <i className="bi bi-shield-check text-muted" style={{fontSize: '4rem'}}></i>
                              </div>
                              <h4>No Alerts Found</h4>
                              <p className="text-muted">No security alerts have been recorded yet</p>
                              <button 
                                className="btn btn-primary mt-2"
                                onClick={() => setActiveTab('create')}
                              >
                                <i className="bi bi-plus-circle me-2"></i>
                                Create New Alert
                              </button>
                            </div>
                          ) : (
                            <div className="table-responsive">
                              <table className="table align-middle">
                                <thead>
                                  <tr>
                                    <th>Time</th>
                                    <th>Message</th>
                                    <th>Severity</th>
                                    <th>Ticket</th>
                                    <th>Notification</th>
                                    <th>Actions</th>
                                  </tr>
                                </thead>
                                <tbody>
                                  {alerts.map(alert => (
                                    <tr 
                                      key={alert.id} 
                                      className={`${alert.id === submissionResult?.alert_id ? 'highlight-new' : ''}`}
                                    >
                                      <td width="160">{formatDate(alert.timestamp)}</td>
                                      <td>
                                        <div style={{maxWidth: "400px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap"}}>
                                          {alert.message}
                                        </div>
                                      </td>
                                      <td>
                                        <span className="badge p-2" style={{
                                          backgroundColor: getSeverityColor(alert.severity),
                                          color: 'white'
                                        }}>
                                          {getSeverityIcon(alert.severity)}
                                          <span className="ms-1">{alert.severity}</span>
                                        </span>
                                      </td>
                                      <td>
                                        {alert.jira_ticket_id ? (
                                          <a 
                                            href={`https://subhashsrinivas36.atlassian.net/browse/${alert.jira_ticket_id}`}
                                            target="_blank" 
                                            rel="noopener noreferrer"
                                            className="badge bg-primary text-decoration-none p-2"
                                          >
                                            <i className="bi bi-link-45deg me-1"></i>
                                            {alert.jira_ticket_id}
                                          </a>
                                        ) : (
                                          <span className="badge bg-secondary p-2">None</span>
                                        )}
                                      </td>
                                      <td>
                                        {alert.slack_notification_sent ? (
                                          <span className="badge bg-success p-2">
                                            <i className="bi bi-check-circle me-1"></i>Sent
                                          </span>
                                        ) : (
                                          <span className="badge bg-secondary p-2">Not sent</span>
                                        )}
                                      </td>
                                      <td>
                                        <button 
                                          className="btn btn-sm btn-primary"
                                          onClick={() => {
                                            setSubmissionResult({
                                              severity: alert.severity,
                                              recommendations: alert.recommendations,
                                              message: alert.message,
                                              jira_ticket: alert.jira_ticket_id,
                                              slack_notification_sent: Boolean(alert.slack_notification_sent),
                                              alert_id: alert.id,
                                              timestamp: alert.timestamp,
                                              impact: alert.additional_data?.impact,
                                              reasoning: alert.additional_data?.reasoning,
                                              classification_method: alert.additional_data?.classification_method || 'model'
                                            });
                                            setShowResult(true);
                                            // Auto-scroll to the result
                                            setTimeout(() => {
                                              document.getElementById('result-section')?.scrollIntoView({ behavior: 'smooth' })
                                            }, 100);
                                          }}
                                        >
                                          <i className="bi bi-eye me-1"></i>View Details
                                        </button>
                                      </td>
                                    </tr>
                                  ))}
                                </tbody>
                              </table>
                            </div>
                          )}
                        </div>
                      </div>
                    </div>
                  </div>
                )}
                
                {/* Dashboard Tab Content */}
                {activeTab === 'dashboard' && (
                  <>
                    <div className="row g-4">
                      <div className="col-xl-3 col-md-6">
                        <div className="dashboard-widget text-center">
                          <div className="widget-header">
                            <h5 className="widget-title">Total Alerts</h5>
                          </div>
                          <div className="widget-content">
                            <div className="display-1 fw-bold text-primary my-3">{alertStats.total}</div>
                            <div className="text-muted">Security alerts recorded</div>
                            <div className="mt-auto">
                              <button className="btn btn-sm btn-outline-primary mt-3" onClick={() => setActiveTab('alerts')}>
                                View All Alerts
                              </button>
                            </div>
                          </div>
                        </div>
                      </div>
                      
                      <div className="col-xl-3 col-md-6">
                        <div className="dashboard-widget">
                          <div className="widget-header">
                            <h5 className="widget-title">Alerts by Severity</h5>
                          </div>
                          <div className="widget-content">
                            {alerts.length > 0 ? (
                              <SeverityChart data={alertStats} />
                            ) : (
                              <div className="text-center p-3">
                                <i className="bi bi-pie-chart text-muted fs-1"></i>
                                <p className="text-muted mt-2">No alert data available</p>
                              </div>
                            )}
                          </div>
                        </div>
                      </div>
                      
                      <div className="col-xl-3 col-md-6">
                        <div className="dashboard-widget">
                          <div className="widget-header">
                            <h5 className="widget-title">Response Success Rate</h5>
                          </div>
                          <div className="widget-content">
                            {alerts.length > 0 ? (
                              <ResponseRateChart data={alerts} />
                            ) : (
                              <div className="text-center p-3">
                                <i className="bi bi-bar-chart text-muted fs-1"></i>
                                <p className="text-muted mt-2">No alert data available</p>
                              </div>
                            )}
                          </div>
                        </div>
                      </div>
                      
                      <div className="col-xl-3 col-md-6">
                        <div className="dashboard-widget">
                          <div className="widget-header">
                            <h5 className="widget-title">Classification Methods</h5>
                          </div>
                          <div className="widget-content">
                            {alerts.length > 0 ? (
                              <ClassificationMethodChart data={alerts} />
                            ) : (
                              <div className="text-center p-3">
                                <i className="bi bi-diagram-3 text-muted fs-1"></i>
                                <p className="text-muted mt-2">No alert data available</p>
                              </div>
                            )}
                          </div>
                        </div>
                      </div>
                    </div>
                    
                    <div className="row mt-4">
                      <div className="col-12">
                        <div className="card card-3d">
                          <div className="card-header bg-primary text-white">
                            <h5 className="mb-0">Alert Trend (Last 7 Days)</h5>
                          </div>
                          <div className="card-body" style={{ height: "350px" }}>
                            {alerts.length > 0 ? (
                              <AlertTrendChart data={alerts} />
                            ) : (
                              <div className="text-center p-5">
                                <i className="bi bi-graph-up text-muted fs-1"></i>
                                <p className="text-muted mt-2">No trend data available</p>
                              </div>
                            )}
                          </div>
                        </div>
                      </div>
                    </div>
                    
                    <div className="row mt-4 g-4">
                      <div className="col-md-6">
                        <div className="card card-3d">
                          <div className="card-header">
                            <h5 className="mb-0">Critical & High Alerts</h5>
                          </div>
                          <div className="card-body p-0">
                            {loading ? (
                              renderLoading()
                            ) : (
                              <div className="table-responsive">
                                <table className="table mb-0">
                                  <thead>
                                    <tr>
                                      <th>Time</th>
                                      <th>Message</th>
                                      <th>Severity</th>
                                      <th>Status</th>
                                    </tr>
                                  </thead>
                                  <tbody>
                                    {alerts
                                      .filter(a => a.severity === 'Critical' || a.severity === 'High')
                                      .slice(0, 5)
                                      .map(alert => (
                                        <tr key={alert.id}>
                                          <td>{formatDate(alert.timestamp)}</td>
                                          <td style={{maxWidth: "200px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap"}}>
                                            {alert.message}
                                          </td>
                                          <td>
                                            <span className="badge p-2" style={{
                                              backgroundColor: getSeverityColor(alert.severity),
                                              color: 'white'
                                            }}>
                                              {getSeverityIcon(alert.severity)}
                                              <span className="ms-1">{alert.severity}</span>
                                            </span>
                                          </td>
                                          <td>
                                            {alert.jira_ticket_id ? 
                                              <span className="badge bg-success p-2">Ticketed</span> : 
                                              <span className="badge bg-warning text-dark p-2">Pending</span>
                                            }
                                          </td>
                                        </tr>
                                      ))
                                    }
                                    {alerts.filter(a => a.severity === 'Critical' || a.severity === 'High').length === 0 && (
                                      <tr>
                                        <td colSpan="4" className="text-center py-4">
                                          <p className="text-muted mb-0">No critical or high alerts found</p>
                                        </td>
                                      </tr>
                                    )}
                                  </tbody>
                                </table>
                              </div>
                            )}
                          </div>
                          {alerts.filter(a => a.severity === 'Critical' || a.severity === 'High').length > 5 && (
                            <div className="card-footer text-center">
                              <button className="btn btn-sm btn-outline-primary" onClick={() => setActiveTab('alerts')}>
                                View All High Priority Alerts
                              </button>
                            </div>
                          )}
                        </div>
                      </div>
                      
                      <div className="col-md-6">
                        <div className="card card-3d">
                          <div className="card-header">
                            <h5 className="mb-0">System Status</h5>
                          </div>
                          <div className="card-body">
                            <div className="row g-3">
                              <div className="col-sm-6">
                                <div className="p-3 border rounded bg-light">
                                  <div className="d-flex justify-content-between align-items-center mb-2">
                                    <h6 className="mb-0">API Status</h6>
                                    <span className="status-indicator status-active"></span>
                                  </div>
                                  <p className="text-success mb-0">Operational</p>
                                </div>
                              </div>
                              <div className="col-sm-6">
                                <div className="p-3 border rounded bg-light">
                                  <div className="d-flex justify-content-between align-items-center mb-2">
                                    <h6 className="mb-0">ML Model</h6>
                                    <span className="status-indicator status-active"></span>
                                  </div>
                                  <p className="text-success mb-0">Active</p>
                                </div>
                              </div>
                              <div className="col-sm-6">
                                <div className="p-3 border rounded bg-light">
                                  <div className="d-flex justify-content-between align-items-center mb-2">
                                    <h6 className="mb-0">Jira Integration</h6>
                                    <span className={`status-indicator ${alertStats.ticketed > 0 ? 'status-active' : ''}`}
                                          style={{ backgroundColor: alertStats.ticketed > 0 ? '#10b981' : '#f43f5e' }}></span>
                                  </div>
                                  <p className={`${alertStats.ticketed > 0 ? 'text-success' : 'text-danger'} mb-0`}>
                                    {alertStats.ticketed > 0 ? 'Connected' : 'Error'}
                                  </p>
                                </div>
                              </div>
                              <div className="col-sm-6">
                                <div className="p-3 border rounded bg-light">
                                  <div className="d-flex justify-content-between align-items-center mb-2">
                                    <h6 className="mb-0">Slack Integration</h6>
                                    <span className={`status-indicator ${alerts.some(a => a.slack_notification_sent) ? 'status-active' : ''}`}
                                          style={{ backgroundColor: alerts.some(a => a.slack_notification_sent) ? '#10b981' : '#f43f5e' }}></span>
                                  </div>
                                  <p className={`${alerts.some(a => a.slack_notification_sent) ? 'text-success' : 'text-danger'} mb-0`}>
                                    {alerts.some(a => a.slack_notification_sent) ? 'Connected' : 'Error'}
                                  </p>
                                </div>
                              </div>
                            </div>
                            
                            {/* Last Update Timestamp */}
                            <div className="text-center mt-4">
                              <small className="text-muted">
                                Last updated: {new Date().toLocaleString()}
                                <button 
                                  className="btn btn-sm btn-link p-0 ms-2 align-baseline" 
                                  onClick={fetchAlerts}
                                >
                                  <i className="bi bi-arrow-repeat"></i> Refresh
                                </button>
                              </small>
                            </div>
                          </div>
                        </div>
                      </div>
                    </div>
                  </>
                )}
                
                {activeTab === 'monitor' && (
                  <LiveAlertMonitor />
                )}
                {/* Footer */}
                <footer className="mt-5 pt-4 border-top text-center text-muted">
                  <p>Security Alert System | Enterprise Edition | &copy; 2025</p>
                </footer>
              </div>
              
              {/* Floating action button */}
              {showFloatingButton && (
                <div className="fab" onClick={handleCreateNewAlert}>
                  <i className="bi bi-plus-lg"></i>
                </div>
              )}
            </div>
          } />
          <Route path="/reports" element={<SimpleReportGenerator />} />
          <Route path="/threat-intelligence" element={<ThreatIntelligenceDashboard />} />
          
        </Routes>
      </BrowserRouter>
    </ErrorBoundary>
  )
}

export default App
