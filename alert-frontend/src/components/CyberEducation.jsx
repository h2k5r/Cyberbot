import React, { useState } from 'react';

const CyberEducation = () => {
    const [selectedAttack, setSelectedAttack] = useState(null);

    const attacks = {
        "Ransomware": {
            icon: "🔒", desc: "Encrypts files, demands payment", 
            damage: "$4.6M avg", prevention: "Backups, patches, training"
        },
        "Phishing": {
            icon: "🎣", desc: "Fake emails steal credentials", 
            damage: "$4.9M avg", prevention: "MFA, email filters, training"
        },
        "DDoS": {
            icon: "🌊", desc: "Floods servers with traffic", 
            damage: "$2.5M avg", prevention: "CDN, rate limiting, monitoring"
        },
        "Malware": {
            icon: "🦠", desc: "Malicious software infection", 
            damage: "$3.2M avg", prevention: "Antivirus, sandboxing, updates"
        },
        "SQL Injection": {
            icon: "💉", desc: "Database attacks via input fields", 
            damage: "$3.5M avg", prevention: "Input validation, parameterized queries"
        },
        "XSS": {
            icon: "🔗", desc: "Malicious scripts in web pages", 
            damage: "$1.8M avg", prevention: "Input sanitization, CSP headers"
        }
    };

    return (
        <div className="mt-4">
            <div className="card">
                <div className="card-header">
                    <h5 className="mb-0">
                        <i className="fas fa-graduation-cap me-2"></i>
                        Cyber Attack Education
                    </h5>
                </div>
                <div className="card-body">
                    <div className="row">
                        {Object.entries(attacks).map(([name, info]) => (
                            <div key={name} className="col-md-4 mb-3">
                                <div 
                                    className={`card h-100 cursor-pointer ${selectedAttack === name ? 'border-primary' : ''}`}
                                    onClick={() => setSelectedAttack(selectedAttack === name ? null : name)}
                                >
                                    <div className="card-body text-center">
                                        <div className="fs-1 mb-2">{info.icon}</div>
                                        <h6 className="card-title">{name}</h6>
                                        <p className="card-text small">{info.desc}</p>
                                        <div className="text-muted small">
                                            <div>💰 {info.damage}</div>
                                            <div>🛡️ {info.prevention}</div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        ))}
                    </div>
                    
                    {selectedAttack && (
                        <div className="alert alert-info mt-3">
                            <h6>{attacks[selectedAttack].icon} {selectedAttack} Attack</h6>
                            <p><strong>What it is:</strong> {attacks[selectedAttack].desc}</p>
                            <p><strong>Avg Damage:</strong> {attacks[selectedAttack].damage}</p>
                            <p><strong>Prevention:</strong> {attacks[selectedAttack].prevention}</p>
                        </div>
                    )}
                </div>
            </div>
            
            <style jsx>{`
                .cursor-pointer { cursor: pointer; }
                .card:hover { transform: translateY(-2px); transition: 0.2s; }
            `}</style>
        </div>
    );
};

export default CyberEducation;
