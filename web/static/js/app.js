/**
 * VulnScanner Web UI JavaScript
 */

document.addEventListener('DOMContentLoaded', function() {
    // Auto-refresh for running scans
    initScanPolling();

    // Initialize tooltips
    initTooltips();
});

/**
 * Poll scan status for running scans
 */
function initScanPolling() {
    const runningBadges = document.querySelectorAll('.badge.bg-primary');

    runningBadges.forEach(function(badge) {
        const row = badge.closest('tr');
        if (row) {
            const scanIdText = row.querySelector('td:first-child')?.textContent;
            // Extract numeric ID (remove # prefix if present)
            const scanId = scanIdText?.replace(/[^0-9]/g, '');
            if (scanId) {
                pollScanStatus(scanId, row);
            }
        }
    });
}

/**
 * Poll a single scan's status
 */
function pollScanStatus(scanId, row) {
    const interval = setInterval(function() {
        fetch(`/api/scans/${scanId}/status`)
            .then(response => response.json())
            .then(data => {
                if (data.status === 'completed' || data.status === 'failed') {
                    clearInterval(interval);
                    // Reload to show updated status
                    location.reload();
                }
            })
            .catch(error => {
                console.error('Error polling scan status:', error);
            });
    }, 5000); // Poll every 5 seconds
}

/**
 * Initialize Bootstrap tooltips
 */
function initTooltips() {
    const tooltipTriggerList = document.querySelectorAll('[data-bs-toggle="tooltip"]');
    tooltipTriggerList.forEach(function(tooltipTriggerEl) {
        new bootstrap.Tooltip(tooltipTriggerEl);
    });
}

/**
 * Start a new scan via API
 */
function startScan(target, method, ports) {
    return fetch('/api/scans', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            target: target,
            method: method || 'icmp',
            ports: ports || '1-1024'
        })
    })
    .then(response => response.json());
}

/**
 * Format date for display
 */
function formatDate(dateString) {
    if (!dateString) return '-';
    const date = new Date(dateString);
    return date.toLocaleString();
}

/**
 * Get risk level color class
 */
function getRiskLevelClass(level) {
    const classes = {
        'Critical': 'danger',
        'High': 'warning',
        'Medium': 'info',
        'Low': 'primary',
        'Info': 'secondary'
    };
    return classes[level] || 'secondary';
}
