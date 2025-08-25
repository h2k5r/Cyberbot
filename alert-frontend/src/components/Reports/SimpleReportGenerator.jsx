import React, { useState } from 'react';
import axios from 'axios';
import { saveAs } from 'file-saver';
import { jsPDF } from 'jspdf';
import autoTable from 'jspdf-autotable';
import * as XLSX from 'xlsx';
import { Link } from 'react-router-dom';
import { useDarkMode } from '../../contexts/DarkModeContext';
import Chart from 'chart.js/auto';
import html2canvas from 'html2canvas';

const SimpleReportGenerator = () => {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [success, setSuccess] = useState(null);
  const { isDarkMode } = useDarkMode();
  const [filters, setFilters] = useState({
    startDate: '',
    endDate: '',
    priority: ''
  });

  const handleFilterChange = (e) => {
    const { name, value } = e.target;
    setFilters({
      ...filters,
      [name]: value
    });
  };

  const clearFilters = () => {
    setFilters({
      startDate: '',
      endDate: '',
      priority: ''
    });
  };

  const generatePDFReport = async () => {
    setLoading(true);
    setError(null);
    setSuccess(null);
    
    try {
      console.log('Starting PDF report generation...');
      
      const queryParams = new URLSearchParams();
      if (filters.startDate) queryParams.append('startDate', filters.startDate);
      if (filters.endDate) queryParams.append('endDate', filters.endDate);
      if (filters.priority) queryParams.append('severity', filters.priority);
      
      console.log('Fetching data from API...');
      const url = `http://localhost:5000/get_alerts${queryParams.toString() ? `?${queryParams.toString()}` : ''}`;
      const response = await axios.get(url);
      const data = response.data;
      
      if (!data || data.length === 0) {
        throw new Error('No alert data available for the selected filters');
      }

      // Create new PDF document
      const doc = new jsPDF();
      
      // Add report title and metadata
      doc.setFontSize(24);
      doc.setTextColor(59, 130, 246);
      doc.text('Security Alert Analytics Report', 14, 20);
      
      doc.setFontSize(10);
      doc.setTextColor(75, 85, 99);
      doc.text(`Generated: ${new Date().toLocaleString()}`, 14, 30);
      
      // Add executive summary
      let yPos = 40;
      doc.setFontSize(14);
      doc.setTextColor(31, 41, 55);
      doc.text('Executive Summary', 14, yPos);
      yPos += 10;
      
      // Add summary statistics
      doc.setFontSize(10);
      doc.setTextColor(75, 85, 99);
      const summary = [
        `Total Alerts: ${data.length}`,
        `Critical Alerts: ${data.filter(a => a.severity === 'Critical').length}`,
        `High Alerts: ${data.filter(a => a.severity === 'High').length}`,
        `Ticketed Alerts: ${data.filter(a => a.jira_ticket_id).length}`,
        `Response Rate: ${((data.filter(a => a.jira_ticket_id).length / data.length) * 100).toFixed(1)}%`
      ];
      
      summary.forEach(line => {
        doc.text(line, 14, yPos);
        yPos += 6;
      });

      // Create and mount temporary chart containers
      const chartContainer = document.createElement('div');
      chartContainer.style.position = 'absolute';
      chartContainer.style.left = '-9999px';
      document.body.appendChild(chartContainer);

      // Create severity chart container
      const severityCanvas = document.createElement('canvas');
      severityCanvas.width = 400;
      severityCanvas.height = 200;
      chartContainer.appendChild(severityCanvas);

      // Create severity chart
      const severityCounts = {
        Critical: data.filter(a => a.severity === 'Critical').length,
        High: data.filter(a => a.severity === 'High').length,
        Medium: data.filter(a => a.severity === 'Medium').length,
        Low: data.filter(a => a.severity === 'Low').length
      };

      const severityChart = new Chart(severityCanvas.getContext('2d'), {
        type: 'pie',
        data: {
          labels: Object.keys(severityCounts),
          datasets: [{
            data: Object.values(severityCounts),
            backgroundColor: ['#ef4444', '#f59e0b', '#3b82f6', '#10b981']
          }]
        },
        options: {
          responsive: false,
          animation: false,
          plugins: {
            legend: {
              position: 'right',
              labels: {
                color: '#000000'
              }
            }
          }
        }
      });

      // Wait for chart render and convert to image
      await new Promise(resolve => setTimeout(resolve, 100));
      yPos += 10;
      const severityChartImage = await html2canvas(severityCanvas, {
        logging: false,
        backgroundColor: null
      });
      doc.addImage(severityChartImage, 'PNG', 14, yPos, 180, 90);
      yPos += 100;

      // Create trend chart
      const trendCanvas = document.createElement('canvas');
      trendCanvas.width = 400;
      trendCanvas.height = 200;
      chartContainer.appendChild(trendCanvas);

      // Group alerts by date
      const alertsByDate = data.reduce((acc, alert) => {
        const date = new Date(alert.timestamp).toLocaleDateString();
        acc[date] = (acc[date] || 0) + 1;
        return acc;
      }, {});

      const trendChart = new Chart(trendCanvas.getContext('2d'), {
        type: 'line',
        data: {
          labels: Object.keys(alertsByDate),
          datasets: [{
            label: 'Number of Alerts',
            data: Object.values(alertsByDate),
            borderColor: '#3b82f6',
            tension: 0.4
          }]
        },
        options: {
          responsive: false,
          animation: false,
          plugins: {
            legend: {
              display: false
            }
          },
          scales: {
            y: {
              beginAtZero: true,
              ticks: {
                color: '#000000'
              }
            },
            x: {
              ticks: {
                color: '#000000'
              }
            }
          }
        }
      });

      // Wait for chart render and convert to image
      await new Promise(resolve => setTimeout(resolve, 100));
      const trendChartImage = await html2canvas(trendCanvas, {
        logging: false,
        backgroundColor: null
      });
      doc.addImage(trendChartImage, 'PNG', 14, yPos, 180, 90);

      // Clean up chart containers
      document.body.removeChild(chartContainer);
      severityChart.destroy();
      trendChart.destroy();

      // Add detailed alerts table
      doc.addPage();
      doc.setFontSize(14);
      doc.setTextColor(31, 41, 55);
      doc.text('Detailed Alert Log', 14, 20);

      // Define table columns and data
      const columns = [
        { header: 'Date', dataKey: 'timestamp' },
        { header: 'Severity', dataKey: 'severity' },
        { header: 'Message', dataKey: 'message' },
        { header: 'Status', dataKey: 'status' }
      ];

      const tableData = data.map(alert => ({
        timestamp: new Date(alert.timestamp).toLocaleString(),
        severity: alert.severity,
        message: alert.message.substring(0, 60) + (alert.message.length > 60 ? '...' : ''),
        status: alert.jira_ticket_id ? 'Ticketed' : 'Pending'
      }));

      // Add table to document
      autoTable(doc, {
        startY: 30,
        head: [columns.map(col => col.header)],
        body: tableData.map(row => columns.map(col => row[col.dataKey])),
        theme: 'striped',
        headStyles: { 
          fillColor: [59, 130, 246],
          textColor: 255,
          fontSize: 10
        },
        styles: {
          fontSize: 8,
          cellPadding: 3
        },
        columnStyles: {
          0: { cellWidth: 40 },
          1: { cellWidth: 30 },
          2: { cellWidth: 85 },
          3: { cellWidth: 25 }
        }
      });

      // Save the PDF
      doc.save('security-alert-analytics-report.pdf');
      setSuccess('PDF report has been generated and downloaded successfully.');
      
    } catch (err) {
      console.error('Error generating PDF report:', err);
      if (err.response) {
        setError(`Server error: ${err.response.status} - ${err.response.data}`);
      } else if (err.request) {
        setError('Network error: Could not connect to the server');
      } else {
        setError(err.message || 'Failed to generate report');
      }
    } finally {
      setLoading(false);
    }
  };

  const generateExcelReport = async () => {
    setLoading(true);
    setError(null);
    setSuccess(null);
    
    try {
      // Fetch alerts data from the backend
      const queryParams = new URLSearchParams();
      if (filters.startDate) queryParams.append('startDate', filters.startDate);
      if (filters.endDate) queryParams.append('endDate', filters.endDate);
      if (filters.priority) queryParams.append('severity', filters.priority);
      
      const url = `http://localhost:5000/get_alerts${queryParams.toString() ? `?${queryParams.toString()}` : ''}`;
      const response = await axios.get(url);
      const data = response.data;
      
      // Create a new workbook
      const workbook = XLSX.utils.book_new();
      
      // Format data for the worksheet
      const worksheetData = data.map(alert => ({
        ID: alert.id,
        Severity: alert.severity,
        Date: new Date(alert.timestamp).toLocaleString(),
        Message: alert.message,
        'Jira Ticket': alert.jira_ticket_id || 'None',
        'Slack Notification': alert.slack_notification_sent ? 'Sent' : 'Not Sent',
        Classification: alert.additional_data?.classification_method || 'Model'
      }));
      
      // Create worksheet from data
      const worksheet = XLSX.utils.json_to_sheet(worksheetData);
      
      // Set column widths
      const columnWidths = [
        { wch: 8 },  // ID
        { wch: 10 }, // Severity
        { wch: 20 }, // Date
        { wch: 50 }, // Message
        { wch: 15 }, // Jira Ticket
        { wch: 18 }, // Slack Notification
        { wch: 15 }  // Classification
      ];
      
      worksheet['!cols'] = columnWidths;
      
      // Add the worksheet to the workbook
      XLSX.utils.book_append_sheet(workbook, worksheet, 'Security Alerts');
      
      // Add a summary sheet
      const summaryData = [
        ['Security Alert Report Summary'],
        ['Generated', new Date().toLocaleString()],
        [],
        ['Filters Applied'],
        ['Start Date', filters.startDate || 'None'],
        ['End Date', filters.endDate || 'None'],
        ['Severity', filters.priority || 'All'],
        [],
        ['Total Alerts', data.length],
        []
      ];
      
      // Count alerts by severity
      const severityCounts = data.reduce((acc, alert) => {
        acc[alert.severity] = (acc[alert.severity] || 0) + 1;
        return acc;
      }, {});
      
      Object.entries(severityCounts).forEach(([severity, count]) => {
        summaryData.push([severity, count]);
      });
      
      const summarySheet = XLSX.utils.aoa_to_sheet(summaryData);
      XLSX.utils.book_append_sheet(workbook, summarySheet, 'Summary');
      
      // Convert workbook to binary
      const excelBuffer = XLSX.write(workbook, { bookType: 'xlsx', type: 'array' });
      
      // Create Blob and save
      const blob = new Blob([excelBuffer], { type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' });
      saveAs(blob, 'security-alert-report.xlsx');
      
      setSuccess('Excel report has been generated and downloaded successfully.');
    } catch (err) {
      console.error('Error generating Excel report:', err);
      setError(err.message || 'Failed to generate report');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className={`app-container ${isDarkMode ? 'dark-mode' : ''}`}>
      <div className="container-fluid px-4 py-3">
        <div className="d-flex justify-content-between align-items-center mb-4">
          <div>
            <h1>
              <i className="bi bi-file-earmark-text me-2"></i>
              Security Alert Reports
            </h1>
            <p className="lead">Generate and download security alert reports</p>
          </div>
          <div>
            <Link to="/" className="btn btn-outline-primary">
              <i className="bi bi-arrow-left me-2"></i>
              Back to Dashboard
            </Link>
          </div>
        </div>

        {error && (
          <div className="alert alert-danger d-flex align-items-center mb-4">
            <i className="bi bi-exclamation-triangle-fill me-2 fs-5"></i>
            <div>{error}</div>
            <button type="button" className="btn-close ms-auto" onClick={() => setError(null)}></button>
          </div>
        )}

        {success && (
          <div className="alert alert-success d-flex align-items-center mb-4">
            <i className="bi bi-check-circle-fill me-2 fs-5"></i>
            <div>{success}</div>
            <button type="button" className="btn-close ms-auto" onClick={() => setSuccess(null)}></button>
          </div>
        )}

        <div className="row">
          <div className="col-lg-8">
            <div className="card shadow mb-4">
              <div className="card-header bg-primary text-white">
                <h3 className="mb-0 d-flex align-items-center">
                  <i className="bi bi-funnel fs-5 me-2"></i>Report Filters
                </h3>
              </div>
              <div className="card-body">
                <form>
                  <div className="row mb-3">
                    <div className="col-md-6">
                      <div className="mb-3">
                        <label htmlFor="startDate" className="form-label">
                          <i className="bi bi-calendar3 me-2"></i>Start Date
                        </label>
                        <input 
                          type="date" 
                          className="form-control"
                          id="startDate"
                          name="startDate"
                          value={filters.startDate}
                          onChange={handleFilterChange}
                        />
                      </div>
                    </div>
                    <div className="col-md-6">
                      <div className="mb-3">
                        <label htmlFor="endDate" className="form-label">
                          <i className="bi bi-calendar3 me-2"></i>End Date
                        </label>
                        <input 
                          type="date" 
                          className="form-control"
                          id="endDate"
                          name="endDate"
                          value={filters.endDate}
                          onChange={handleFilterChange}
                        />
                      </div>
                    </div>
                  </div>

                  <div className="row mb-3">
                    <div className="col-md-6">
                      <div className="mb-3">
                        <label htmlFor="priority" className="form-label">
                          <i className="bi bi-exclamation-circle me-2"></i>Severity
                        </label>
                        <select 
                          className="form-select"
                          id="priority"
                          name="priority"
                          value={filters.priority}
                          onChange={handleFilterChange}
                        >
                          <option value="">All Severities</option>
                          <option value="Critical">Critical</option>
                          <option value="High">High</option>
                          <option value="Medium">Medium</option>
                          <option value="Low">Low</option>
                        </select>
                      </div>
                    </div>
                  </div>

                  <div className="d-flex justify-content-between">
                    <button 
                      type="button" 
                      className="btn btn-outline-secondary"
                      onClick={clearFilters}
                    >
                      <i className="bi bi-x-circle me-2"></i>
                      Clear Filters
                    </button>
                  </div>
                </form>
              </div>
            </div>
          </div>

          <div className="col-lg-4">
            <div className="card shadow">
              <div className="card-header bg-dark text-white">
                <h3 className="mb-0 d-flex align-items-center">
                  <i className="bi bi-download fs-5 me-2"></i>Download Reports
                </h3>
              </div>
              <div className="card-body">
                <p className="text-muted mb-4">
                  Select your desired report format below. Reports will be generated based on the filters you've set.
                </p>
                
                <div className="d-grid gap-3">
                  <button
                    className="btn btn-primary btn-lg py-3 d-flex align-items-center justify-content-center"
                    onClick={generatePDFReport}
                    disabled={loading}
                  >
                    {loading ? (
                      <>
                        <span className="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span>
                        Generating PDF...
                      </>
                    ) : (
                      <>
                        <i className="bi bi-file-earmark-pdf fs-4 me-2"></i>
                        <span>Download as PDF</span>
                      </>
                    )}
                  </button>
                  
                  <button
                    className="btn btn-success btn-lg py-3 d-flex align-items-center justify-content-center"
                    onClick={generateExcelReport}
                    disabled={loading}
                  >
                    {loading ? (
                      <>
                        <span className="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span>
                        Generating Excel...
                      </>
                    ) : (
                      <>
                        <i className="bi bi-file-earmark-excel fs-4 me-2"></i>
                        <span>Download as Excel</span>
                      </>
                    )}
                  </button>
                </div>
              </div>
            </div>

            <div className="card shadow mt-4">
              <div className="card-header bg-info text-white">
                <h3 className="mb-0 d-flex align-items-center">
                  <i className="bi bi-info-circle fs-5 me-2"></i>About Reports
                </h3>
              </div>
              <div className="card-body">
                <div className="mb-3">
                  <h5><i className="bi bi-file-earmark-pdf me-2 text-danger"></i>PDF Reports</h5>
                  <p className="text-muted">PDF reports include formatted tables, severity charts and basic statistics. Best for printing or sharing formally.</p>
                </div>
                
                <div>
                  <h5><i className="bi bi-file-earmark-excel me-2 text-success"></i>Excel Reports</h5>
                  <p className="text-muted">Excel reports include detailed data in spreadsheet format with multiple sheets. Best for further data analysis.</p>
                </div>
              </div>
            </div>
          </div>
        </div>

        <footer className="mt-5 pt-4 border-top text-center text-muted">
          <p>Security Alert System | Enterprise Edition | &copy; 2025</p>
        </footer>
      </div>
    </div>
  );
};

export default SimpleReportGenerator;