import React, { useEffect, useState, useRef } from 'react';
import io from 'socket.io-client';
import './LiveAlertMonitor.css';

const SuricataLogMonitor = () => {
    const [alerts, setAlerts] = useState([]);
    const [isConnected, setIsConnected] = useState(false);
    const [alertStats, setAlertStats] = useState({
        total: 0,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0
    });
    const [autoScroll, setAutoScroll] = useState(true);
    const [filter, setFilter] = useState('all');
    const terminalRef = useRef(null);

    useEffect(() => {
        // Add initial welcome messages
        addWelcomeMessages();
        
        // Fetch initial logs
        fetchInitialLogs();

        // Connect to WebSocket for real-time updates
        const socket = io('http://localhost:5000');

        socket.on('connect', () => {
            setIsConnected(true);
            console.log('Connected to Suricata alert stream');
            addSystemMessage('Connected to Suricata IDS monitoring system');
        });

        socket.on('disconnect', () => {
            setIsConnected(false);
            console.log('Disconnected from Suricata alert stream');
            addSystemMessage('Disconnected from monitoring system');
        });

        socket.on('suricata_alert', (alert) => {
            setAlerts(prev => {
                const newAlerts = [alert, ...prev].slice(0, 1000); // Keep last 1000 alerts
                updateStats(newAlerts);
                return newAlerts;
            });
        });

        return () => {
            socket.disconnect();
        };
    }, []);

    // Auto-scroll to bottom when new alerts arrive
    useEffect(() => {
        if (autoScroll && terminalRef.current) {
            terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
        }
    }, [alerts, autoScroll]);

    const addWelcomeMessages = () => {
        const welcomeMessages = [
            {
                timestamp: new Date().toISOString(),
                severity: 'System',
                signature: '========================================',
                source_ip: 'System',
                dest_ip: '-',
                source_port: '-',
                dest_port: '-',
                protocol: '-',
                category: 'System',
                rule_file: 'system.log'
            },
            {
                timestamp: new Date().toISOString(),
                severity: 'System',
                signature: '    SURICATA LOG MONITOR v2.0',
                source_ip: 'System',
                dest_ip: '-',
                source_port: '-',
                dest_port: '-',
                protocol: '-',
                category: 'System',
                rule_file: 'system.log'
            },
            {
                timestamp: new Date().toISOString(),
                severity: 'System',
                signature: '    Real-time IDS Alert Monitoring',
                source_ip: 'System',
                dest_ip: '-',
                source_port: '-',
                dest_port: '-',
                protocol: '-',
                category: 'System',
                rule_file: 'system.log'
            },
            {
                timestamp: new Date().toISOString(),
                severity: 'System',
                signature: '========================================',
                source_ip: 'System',
                dest_ip: '-',
                source_port: '-',
                dest_port: '-',
                protocol: '-',
                category: 'System',
                rule_file: 'system.log'
            }
        ];
        setAlerts(welcomeMessages);
    };

    const addSystemMessage = (message) => {
        const systemAlert = {
            timestamp: new Date().toISOString(),
            severity: 'System',
            signature: message,
            source_ip: 'System',
            dest_ip: '-',
            source_port: '-',
            dest_port: '-',
            protocol: '-',
            category: 'System',
            rule_file: 'system.log'
        };
        setAlerts(prev => [systemAlert, ...prev]);
    };

    const fetchInitialLogs = async () => {
        try {
            addSystemMessage('Initializing Suricata log monitor...');
            const response = await fetch('http://localhost:5000/api/suricata/logs');
            const data = await response.json();
            if (data.status === 'success') {
                // Keep welcome messages at the top, add real logs after
                setAlerts(prev => [...prev, ...data.logs]);
                updateStats(data.logs);
                addSystemMessage(`Loaded ${data.logs.length} historical alerts`);
            }
        } catch (error) {
            console.error('Failed to fetch initial logs:', error);
            addSystemMessage('Error: Failed to fetch initial logs');
        }
    };

    const updateStats = (alertList) => {
        const stats = {
            total: alertList.filter(a => a.severity !== 'System').length,
            critical: alertList.filter(a => a.severity === 'Critical').length,
            high: alertList.filter(a => a.severity === 'High').length,
            medium: alertList.filter(a => a.severity === 'Medium').length,
            low: alertList.filter(a => a.severity === 'Low').length
        };
        setAlertStats(stats);
    };

    const getSeverityColor = (severity) => {
        switch(severity) {
            case 'Critical': return '#ff4444';
            case 'High': return '#ff8c00';
            case 'Medium': return '#ffd700';
            case 'Low': return '#00ff00';
            case 'System': return '#00bfff';
            default: return '#ffffff';
        }
    };

    const getSeverityPrefix = (severity) => {
        switch(severity) {
            case 'Critical': return '[CRIT]';
            case 'High': return '[HIGH]';
            case 'Medium': return '[MED ]';
            case 'Low': return '[LOW ]';
            case 'System': return '[SYS ]';
            default: return '[INFO]';
        }
    };

    const formatTimestamp = (timestamp) => {
        return new Date(timestamp).toLocaleString('en-US', {
            hour12: false,
            year: 'numeric',
            month: '2-digit',
            day: '2-digit',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit'
        });
    };

    const formatLogEntry = (alert) => {
        if (alert.severity === 'System') {
            // For welcome messages and system messages, display them specially
            if (alert.signature.includes('SURICATA LOG MONITOR') || 
                alert.signature.includes('Real-time IDS') ||
                alert.signature.includes('====')) {
                return alert.signature;
            }
            return `${formatTimestamp(alert.timestamp)} ${getSeverityPrefix(alert.severity)} ${alert.signature}`;
        }
        
        return `${formatTimestamp(alert.timestamp)} ${getSeverityPrefix(alert.severity)} [${alert.protocol}] ${alert.source_ip}:${alert.source_port} -> ${alert.dest_ip}:${alert.dest_port} | ${alert.signature} | Category: ${alert.category}`;
    };

    const filteredAlerts = alerts.filter(alert => {
        if (filter === 'all') return true;
        if (filter === 'system') return alert.severity === 'System';
        return alert.severity.toLowerCase() === filter.toLowerCase();
    });

    const clearTerminal = () => {
        addWelcomeMessages();
        addSystemMessage('Terminal cleared');
    };

    return (
        <div className="terminal-wrapper">
            <div className="terminal-container">
                {/* Terminal Header */}
                <div className="terminal-header">
                    <div className="terminal-title">
                        <div className="terminal-controls">
                            <span className="terminal-button close"></span>
                            <span className="terminal-button minimize"></span>
                            <span className="terminal-button maximize"></span>
                        </div>
                        <span className="terminal-title-text">
                            <i className="bi bi-terminal me-2"></i>
                            Suricata IDS Monitor - Real-time Log Viewer
                        </span>
                        <div className="terminal-status">
                            <span className={`connection-indicator ${isConnected ? 'connected' : 'disconnected'}`}>
                                <i className={`bi ${isConnected ? 'bi-circle-fill' : 'bi-circle'}`}></i>
                                {isConnected ? 'ONLINE' : 'OFFLINE'}
                            </span>
                        </div>
                    </div>
                    
                    {/* Terminal Controls */}
                    <div className="terminal-controls-bar">
                        <div className="stats-bar">
                            <span className="stat-item">Total: {alertStats.total}</span>
                            <span className="stat-item critical">Critical: {alertStats.critical}</span>
                            <span className="stat-item high">High: {alertStats.high}</span>
                            <span className="stat-item medium">Medium: {alertStats.medium}</span>
                            <span className="stat-item low">Low: {alertStats.low}</span>
                        </div>
                        
                        <div className="terminal-actions">
                            <select 
                                className="terminal-filter"
                                value={filter}
                                onChange={(e) => setFilter(e.target.value)}
                            >
                                <option value="all">All Logs</option>
                                <option value="system">System</option>
                                <option value="critical">Critical</option>
                                <option value="high">High</option>
                                <option value="medium">Medium</option>
                                <option value="low">Low</option>
                            </select>
                            
                            <button 
                                className="terminal-btn"
                                onClick={() => setAutoScroll(!autoScroll)}
                                title={autoScroll ? 'Disable auto-scroll' : 'Enable auto-scroll'}
                            >
                                <i className={`bi ${autoScroll ? 'bi-pause-fill' : 'bi-play-fill'}`}></i>
                            </button>
                            
                            <button 
                                className="terminal-btn"
                                onClick={clearTerminal}
                                title="Clear terminal"
                            >
                                <i className="bi bi-trash"></i>
                            </button>
                            
                            <button 
                                className="terminal-btn"
                                onClick={fetchInitialLogs}
                                title="Refresh logs"
                            >
                                <i className="bi bi-arrow-clockwise"></i>
                            </button>
                        </div>
                    </div>
                </div>

                {/* Terminal Body */}
                <div className="terminal-body" ref={terminalRef}>
                    {filteredAlerts.length === 0 ? (
                        <div className="terminal-empty">
                            <div className="terminal-line system">
                                ========================================
                            </div>
                            <div className="terminal-line system">
                                    SURICATA LOG MONITOR v2.0
                            </div>
                            <div className="terminal-line system">
                                    Real-time IDS Alert Monitoring
                            </div>
                            <div className="terminal-line system">
                                ========================================
                            </div>
                            <div className="terminal-line system">
                                {formatTimestamp(new Date().toISOString())} [SYS ] Suricata IDS Monitor initialized
                            </div>
                            <div className="terminal-line system">
                                {formatTimestamp(new Date().toISOString())} [SYS ] Waiting for security alerts...
                            </div>
                            <div className="terminal-cursor">█</div>
                        </div>
                    ) : (
                        <>
                            {filteredAlerts.slice().reverse().map((alert, index) => (
                                <div 
                                    key={index} 
                                    className={`terminal-line ${alert.severity.toLowerCase()}`}
                                    style={{ color: getSeverityColor(alert.severity) }}
                                >
                                    {formatLogEntry(alert)}
                                </div>
                            ))}
                            {autoScroll && <div className="terminal-cursor">█</div>}
                        </>
                    )}
                </div>
            </div>
        </div>
    );
};

export default SuricataLogMonitor;
