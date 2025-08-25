import React from 'react';
import {
  Chart as ChartJS,
  ArcElement,
  Tooltip,
  Legend,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  Title
} from 'chart.js';
import { Pie, Line, Bar } from 'react-chartjs-2';

// Register ChartJS components
ChartJS.register(
  ArcElement, 
  Tooltip, 
  Legend,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  Title
);

// Severity distribution chart (Pie)
export const SeverityChart = ({ data }) => {
  const chartData = {
    labels: ['Critical', 'High', 'Medium', 'Low'],
    datasets: [
      {
        data: [
          data.critical || 0,
          data.high || 0,
          data.medium || 0,
          data.low || 0
        ],
        backgroundColor: [
          '#ef4444',  // Critical - Red
          '#f59e0b',  // High - Orange
          '#3b82f6',  // Medium - Blue
          '#10b981',  // Low - Green
        ],
        borderColor: [
          '#fef2f2',
          '#fffbeb',
          '#eff6ff',
          '#ecfdf5',
        ],
        borderWidth: 2,
      },
    ],
  };

  const options = {
    responsive: true,
    plugins: {
      legend: {
        position: 'bottom',
      },
      title: {
        display: false,
      },
      tooltip: {
        callbacks: {
          label: (context) => {
            const label = context.label || '';
            const value = context.raw || 0;
            const total = context.chart.data.datasets[0].data.reduce((a, b) => a + b, 0);
            const percentage = total > 0 ? Math.round((value / total) * 100) : 0;
            return `${label}: ${value} (${percentage}%)`;
          }
        }
      }
    },
  };

  return (
    <div className="chart-container">
      <Pie data={chartData} options={options} />
    </div>
  );
};

// Alert trend chart (Line)
export const AlertTrendChart = ({ data }) => {
  // Sort data by timestamp
  const sortedAlerts = [...data].sort((a, b) => 
    new Date(a.timestamp) - new Date(b.timestamp)
  );

  // Group by date (last 7 days)
  const sevenDaysAgo = new Date();
  sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
  
  const dateLabels = [];
  for (let i = 6; i >= 0; i--) {
    const date = new Date();
    date.setDate(date.getDate() - i);
    dateLabels.push(date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }));
  }

  // Count alerts per day
  const alertCounts = Array(7).fill(0);
  
  sortedAlerts.forEach(alert => {
    const alertDate = new Date(alert.timestamp);
    if (alertDate >= sevenDaysAgo) {
      const daysAgo = Math.floor((new Date() - alertDate) / (1000 * 60 * 60 * 24));
      if (daysAgo >= 0 && daysAgo < 7) {
        alertCounts[6 - daysAgo]++;
      }
    }
  });

  const chartData = {
    labels: dateLabels,
    datasets: [
      {
        label: 'Alerts',
        data: alertCounts,
        fill: true,
        backgroundColor: 'rgba(59, 130, 246, 0.2)',
        borderColor: 'rgba(59, 130, 246, 1)',
        tension: 0.4,
        pointBackgroundColor: 'rgba(59, 130, 246, 1)',
        pointBorderColor: '#fff',
        pointBorderWidth: 2,
        pointRadius: 4,
      },
    ],
  };

  const options = {
    responsive: true,
    maintainAspectRatio: false,
    scales: {
      y: {
        beginAtZero: true,
        ticks: {
          stepSize: 1,
        },
      },
    },
    plugins: {
      legend: {
        display: false,
      },
      title: {
        display: true,
        text: 'Alert Trend (Last 7 Days)',
      },
    },
  };

  return (
    <div className="chart-container">
      <Line data={chartData} options={options} />
    </div>
  );
};

// Response success rate (Bar)
export const ResponseRateChart = ({ data }) => {
  const jiraSuccess = data.filter(a => a.jira_ticket_id).length;
  const slackSuccess = data.filter(a => a.slack_notification_sent).length;
  const total = data.length;
  
  const jiraRate = total > 0 ? (jiraSuccess / total * 100) : 0;
  const slackRate = total > 0 ? (slackSuccess / total * 100) : 0;

  const chartData = {
    labels: ['Jira Tickets', 'Slack Notifications'],
    datasets: [
      {
        label: 'Success Rate %',
        data: [jiraRate, slackRate],
        backgroundColor: [
          'rgba(0, 82, 204, 0.8)',  // Jira blue
          'rgba(74, 21, 75, 0.8)',  // Slack purple
        ],
        borderColor: [
          'rgba(0, 82, 204, 1)',
          'rgba(74, 21, 75, 1)',
        ],
        borderWidth: 1,
      },
    ],
  };

  const options = {
    responsive: true,
    maintainAspectRatio: false,
    scales: {
      y: {
        beginAtZero: true,
        max: 100,
        ticks: {
          callback: function(value) {
            return value + '%';
          }
        }
      },
    },
    plugins: {
      legend: {
        display: false,
      },
      tooltip: {
        callbacks: {
          label: function(context) {
            return `Success Rate: ${Math.round(context.raw)}%`;
          }
        }
      }
    },
  };

  return (
    <div className="chart-container">
      <Bar data={chartData} options={options} />
    </div>
  );
};

// Classification Method Chart (Doughnut)
export const ClassificationMethodChart = ({ data }) => {
  const geminiAlerts = data.filter(a => 
    a.additional_data?.classification_method === 'gemini'
  ).length;
  const modelAlerts = data.length - geminiAlerts;
  
  const chartData = {
    labels: ['Gemini AI', 'ML Model'],
    datasets: [
      {
        data: [geminiAlerts, modelAlerts],
        backgroundColor: [
          '#f59e0b',  // Gemini - amber
          '#3b82f6',  // ML Model - blue
        ],
        borderColor: [
          '#fffbeb',
          '#eff6ff',
        ],
        borderWidth: 2,
        hoverOffset: 4,
      },
    ],
  };

  const options = {
    responsive: true,
    cutout: '65%',
    plugins: {
      legend: {
        position: 'bottom',
      },
      tooltip: {
        callbacks: {
          label: (context) => {
            const label = context.label || '';
            const value = context.raw || 0;
            const total = context.chart.data.datasets[0].data.reduce((a, b) => a + b, 0);
            const percentage = total > 0 ? Math.round((value / total) * 100) : 0;
            return `${label}: ${value} (${percentage}%)`;
          }
        }
      }
    },
  };

  return (
    <div className="chart-container">
      <Pie data={chartData} options={options} />
    </div>
  );
};