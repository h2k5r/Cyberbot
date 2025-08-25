import axios from 'axios';
import { saveAs } from 'file-saver';
import { jsPDF } from 'jspdf';
import 'jspdf-autotable';
import * as XLSX from 'xlsx';

const API_URL = 'http://localhost:5000';  // Changed to match your backend API URL

class ReportService {
  /**
   * Fetches alert data from the API with optional filters
   * @param {Object} filters - Filter criteria for the alerts
   * @returns {Promise<Array>} - Promise resolving to array of alert data
   */
  async getAlertData(filters = {}) {
    try {
      // Convert filters object to query parameters
      const queryParams = new URLSearchParams();
      
      if (filters.startDate) queryParams.append('startDate', filters.startDate);
      if (filters.endDate) queryParams.append('endDate', filters.endDate);
      if (filters.priority) queryParams.append('severity', filters.priority);
      
      const queryString = queryParams.toString();
      const url = `${API_URL}/get_alerts${queryString ? `?${queryString}` : ''}`;
      
      const response = await axios.get(url);
      return response.data;
    } catch (error) {
      console.error('Error fetching alert data:', error);
      throw new Error(error.response?.data?.message || 'Failed to fetch alert data');
    }
  }

  /**
   * Generates a PDF report from alert data
   * @param {Array} data - Alert data to include in the report
   * @param {Object} filters - Filters applied to the data
   * @returns {jsPDF} - PDF document object
   */
  generatePDFReport(data, filters = {}) {
    // Create new PDF document
    const doc = new jsPDF();
    
    // Add report title
    doc.setFontSize(18);
    doc.text('Security Alert Report', 14, 22);
    
    // Add report metadata
    doc.setFontSize(10);
    doc.text(`Generated: ${new Date().toLocaleString()}`, 14, 30);
    
    // Add filter information if any filters were applied
    let yPos = 36;
    if (Object.values(filters).some(v => v)) {
      doc.setFontSize(12);
      doc.text('Filters Applied:', 14, yPos);
      yPos += 6;
      
      if (filters.startDate) {
        doc.text(`Start Date: ${filters.startDate}`, 20, yPos);
        yPos += 5;
      }
      
      if (filters.endDate) {
        doc.text(`End Date: ${filters.endDate}`, 20, yPos);
        yPos += 5;
      }
      
      if (filters.priority) {
        doc.text(`Severity: ${filters.priority}`, 20, yPos);
        yPos += 5;
      }
      
      yPos += 5;
    }
    
    // Define table columns
    const columns = [
      { header: 'ID', dataKey: 'id' },
      { header: 'Severity', dataKey: 'severity' },
      { header: 'Date', dataKey: 'timestamp' },
      { header: 'Message', dataKey: 'message' },
      { header: 'Status', dataKey: 'status' }
    ];
    
    // Format data for the table
    const tableData = data.map(alert => ({
      id: alert.id,
      severity: alert.severity,
      timestamp: new Date(alert.timestamp).toLocaleString(),
      message: alert.message.substring(0, 60) + (alert.message.length > 60 ? '...' : ''),
      status: alert.jira_ticket_id ? 'Ticketed' : 'Pending'
    }));
    
    // Add table to the document
    doc.autoTable({
      startY: yPos,
      head: [columns.map(col => col.header)],
      body: tableData.map(row => columns.map(col => row[col.dataKey])),
      theme: 'striped',
      headStyles: { fillColor: [59, 130, 246], textColor: 255 },
      margin: { top: 15 }
    });
    
    // Add summary information
    const finalY = doc.lastAutoTable.finalY + 10;
    doc.setFontSize(12);
    doc.text(`Total Alerts: ${data.length}`, 14, finalY);
    
    // Count alerts by severity
    const severityCounts = data.reduce((acc, alert) => {
      acc[alert.severity] = (acc[alert.severity] || 0) + 1;
      return acc;
    }, {});
    
    let summaryY = finalY + 6;
    Object.entries(severityCounts).forEach(([severity, count]) => {
      doc.text(`${severity}: ${count}`, 20, summaryY);
      summaryY += 5;
    });
    
    return doc;
  }

  /**
   * Generates an Excel report from alert data
   * @param {Array} data - Alert data to include in the report
   * @param {Object} filters - Filters applied to the data
   * @returns {Blob} - Excel file as a Blob
   */
  generateExcelReport(data, filters = {}) {
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
    
    // Create Blob from binary
    return new Blob([excelBuffer], { type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' });
  }

  /**
   * Downloads a report in the specified format
   * @param {String} format - The format of the report (pdf or excel)
   * @param {Object} filters - Filters to apply to the data
   */
  async downloadReport(format, filters = {}) {
    try {
      const data = await this.getAlertData(filters);
      
      if (format === 'pdf') {
        const doc = this.generatePDFReport(data, filters);
        doc.save('security-alert-report.pdf');
      } else if (format === 'excel') {
        const excelBlob = this.generateExcelReport(data, filters);
        saveAs(excelBlob, 'security-alert-report.xlsx');
      } else {
        throw new Error(`Unsupported format: ${format}`);
      }
    } catch (error) {
      console.error('Error downloading report:', error);
      throw error;
    }
  }
}

export default new ReportService();