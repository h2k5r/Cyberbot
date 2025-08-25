import React, { useState, useEffect } from 'react';
import ReportService from '../../services/ReportService';
import { useDarkMode } from '../../contexts/DarkModeContext';
import { Link } from 'react-router-dom';

const ReportGenerator = () => {
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

  const generateReport = async (format) => {
    setLoading(true);
    setError(null);
    setSuccess(null);
    
    try {
      await ReportService.downloadReport(format, filters);
      setSuccess(`${format.toUpperCase()} report has been generated and downloaded successfully.`);
    } catch (err) {
      setError(err.message || 'Failed to generate report');
    } finally {
      setLoading(false);
    }
  };

  const clearFilters = () => {
    setFilters({
      startDate: '',
      endDate: '',
      priority: ''
    });
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
                          <option value="critical">Critical</option>
                          <option value="high">High</option>
                          <option value="medium">Medium</option>
                          <option value="low">Low</option>
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
                    onClick={() => generateReport('pdf')}
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
                    onClick={() => generateReport('excel')}
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

export default ReportGenerator;