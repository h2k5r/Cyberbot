import { useState, useEffect } from 'react';
import { useDarkMode } from '../contexts/DarkModeContext';
import { Link } from 'react-router-dom';

const Navbar = ({ activeTab, setActiveTab, alertCount }) => {
  const { isDarkMode, toggleDarkMode } = useDarkMode();
  const [scrolled, setScrolled] = useState(false);
  const [dropdownOpen, setDropdownOpen] = useState(false);
  
  // Handle scroll event for navbar appearance
  useEffect(() => {
    const handleScroll = () => {
      const isScrolled = window.scrollY > 10;
      if (isScrolled !== scrolled) {
        setScrolled(isScrolled);
      }
    };
    
    window.addEventListener('scroll', handleScroll);
    return () => window.removeEventListener('scroll', handleScroll);
  }, [scrolled]);
  
  return (
    <nav className={`top-navbar d-flex justify-content-between align-items-center ${scrolled ? 'scrolled' : ''}`}>
      {/* Brand Logo */}
      <a href="/" className="navbar-brand">
        <i className="bi bi-shield-lock fs-4 me-2 security-logo"></i>
        Security Alert System
      </a>
      
      {/* Main Navigation */}
      <div className="d-none d-md-flex align-items-center">
        <button 
          className={`nav-link me-2 ${activeTab === 'create' ? 'active' : ''}`}
          onClick={() => setActiveTab('create')}
        >
          <i className="bi bi-plus-circle me-2"></i>Create
        </button>
        
        <button 
          className={`nav-link me-2 position-relative ${activeTab === 'alerts' ? 'active' : ''}`}
          onClick={() => setActiveTab('alerts')}
        >
          <i className="bi bi-shield-exclamation me-2"></i>Alerts
          {alertCount > 0 && (
            <span className="badge-notification">{alertCount > 99 ? '99+' : alertCount}</span>
          )}
        </button>

        {/* NEW: Log Monitor Tab */}
        <button 
          className={`nav-link me-2 ${activeTab === 'monitor' ? 'active' : ''}`}
          onClick={() => setActiveTab('monitor')}
          title="Live Suricata Log Monitor"
        >
          <i className="bi bi-activity me-2"></i>Log Monitor
        </button>
        
        <button 
          className={`nav-link me-2 ${activeTab === 'dashboard' ? 'active' : ''}`}
          onClick={() => setActiveTab('dashboard')}
        >
          <i className="bi bi-graph-up me-2"></i>Dashboard
        </button>
        
        <Link 
          to="/threat-intelligence" 
          className="nav-link me-2"
        >
          <i className="bi bi-shield-shaded me-2"></i>Threat Intel
        </Link>
        
        <Link        
          to="/reports" 
          className="nav-link me-2"
        >
          <i className="bi bi-file-earmark-text me-2"></i>Reports
        </Link>
      </div>
      
      {/* Mobile Navigation Toggle (for smaller screens) */}
      <div className="d-md-none">
        <button 
          className="btn btn-outline-light btn-sm"
          type="button"
          data-bs-toggle="offcanvas"
          data-bs-target="#mobileNav"
          aria-controls="mobileNav"
        >
          <i className="bi bi-list"></i>
        </button>
      </div>

      {/* Mobile Offcanvas Navigation */}
      <div className="offcanvas offcanvas-end" tabIndex="-1" id="mobileNav" aria-labelledby="mobileNavLabel">
        <div className="offcanvas-header">
          <h5 className="offcanvas-title" id="mobileNavLabel">Navigation</h5>
          <button type="button" className="btn-close" data-bs-dismiss="offcanvas" aria-label="Close"></button>
        </div>
        <div className="offcanvas-body">
          <div className="d-flex flex-column">
            <button 
              className={`nav-link mobile-nav-link ${activeTab === 'create' ? 'active' : ''}`}
              onClick={() => {
                setActiveTab('create');
                // Close offcanvas
                const offcanvas = document.getElementById('mobileNav');
                const bsOffcanvas = window.bootstrap?.Offcanvas?.getInstance(offcanvas);
                bsOffcanvas?.hide();
              }}
            >
              <i className="bi bi-plus-circle me-2"></i>Create Alert
            </button>
            
            <button 
              className={`nav-link mobile-nav-link position-relative ${activeTab === 'alerts' ? 'active' : ''}`}
              onClick={() => {
                setActiveTab('alerts');
                const offcanvas = document.getElementById('mobileNav');
                const bsOffcanvas = window.bootstrap?.Offcanvas?.getInstance(offcanvas);
                bsOffcanvas?.hide();
              }}
            >
              <i className="bi bi-shield-exclamation me-2"></i>View Alerts
              {alertCount > 0 && (
                <span className="badge-notification">{alertCount > 99 ? '99+' : alertCount}</span>
              )}
            </button>

            {/* Mobile Log Monitor */}
            <button 
              className={`nav-link mobile-nav-link ${activeTab === 'monitor' ? 'active' : ''}`}
              onClick={() => {
                setActiveTab('monitor');
                const offcanvas = document.getElementById('mobileNav');
                const bsOffcanvas = window.bootstrap?.Offcanvas?.getInstance(offcanvas);
                bsOffcanvas?.hide();
              }}
            >
              <i className="bi bi-activity me-2"></i>Log Monitor
            </button>
            
            <button 
              className={`nav-link mobile-nav-link ${activeTab === 'dashboard' ? 'active' : ''}`}
              onClick={() => {
                setActiveTab('dashboard');
                const offcanvas = document.getElementById('mobileNav');
                const bsOffcanvas = window.bootstrap?.Offcanvas?.getInstance(offcanvas);
                bsOffcanvas?.hide();
              }}
            >
              <i className="bi bi-graph-up me-2"></i>Dashboard
            </button>
            
            <Link 
              to="/threat-intelligence" 
              className="nav-link mobile-nav-link"
              data-bs-dismiss="offcanvas"
            >
              <i className="bi bi-shield-shaded me-2"></i>Threat Intelligence
            </Link>
            
            <Link        
              to="/reports" 
              className="nav-link mobile-nav-link"
              data-bs-dismiss="offcanvas"
            >
              <i className="bi bi-file-earmark-text me-2"></i>Reports
            </Link>
          </div>
        </div>
      </div>
      
      {/* Right Controls */}
      <div className="d-flex align-items-center">
        {/* Dark Mode Toggle */}
        <div 
          className={`dark-mode-toggle me-3 ${isDarkMode ? 'active' : ''}`}
          onClick={toggleDarkMode}
          role="button"
          aria-label="Toggle dark mode"
        >
          <div className="toggle-handle">
            <i className={`bi ${isDarkMode ? 'bi-moon-stars-fill' : 'bi-sun-fill'}`}></i>
          </div>
        </div>
        
        {/* User Dropdown */}
        <div className="user-dropdown">
          <img 
            src="https://ui-avatars.com/api/?name=Security+Admin&background=0D8ABC&color=fff"
            alt="User" 
            className="user-avatar"
            onClick={() => setDropdownOpen(!dropdownOpen)}
          />
          
          {dropdownOpen && (
            <div className="dropdown-menu">
              <div className="p-3 mb-2 border-bottom">
                <div className="fw-bold">Security Admin</div>
                <small className="text-muted">admin@example.com</small>
              </div>
              
              <a href="#settings" className="dropdown-item">
                <i className="bi bi-gear"></i>Settings
              </a>
              
              <a href="#profile" className="dropdown-item">
                <i className="bi bi-person"></i>Profile
              </a>
              
              <div className="dropdown-divider"></div>
              
              <a href="#documentation" className="dropdown-item">
                <i className="bi bi-file-text"></i>Documentation
              </a>
              
              <a href="#help" className="dropdown-item">
                <i className="bi bi-question-circle"></i>Help & Support
              </a>
              
              <div className="dropdown-divider"></div>
              
              <a href="#logout" className="dropdown-item text-danger">
                <i className="bi bi-box-arrow-right"></i>Sign Out
              </a>
            </div>
          )}
        </div>
      </div>
    </nav>
  );
};

export default Navbar;
