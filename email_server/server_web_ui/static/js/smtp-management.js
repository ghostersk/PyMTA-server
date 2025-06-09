/* Custom JavaScript for SMTP Management Frontend */

// Global utilities
const SMTPManagement = {
    // Copy text to clipboard
    copyToClipboard: function(text, button) {
        navigator.clipboard.writeText(text).then(() => {
            this.showCopySuccess(button);
        }).catch(err => {
            console.error('Failed to copy: ', err);
            this.showCopyError(button);
        });
    },

    // Show copy success feedback
    showCopySuccess: function(button) {
        const originalText = button.innerHTML;
        button.innerHTML = '<i class="fas fa-check me-1"></i>Copied!';
        button.classList.remove('btn-outline-light');
        button.classList.add('btn-success');
        
        setTimeout(() => {
            button.innerHTML = originalText;
            button.classList.remove('btn-success');
            button.classList.add('btn-outline-light');
        }, 2000);
    },

    // Show copy error feedback
    showCopyError: function(button) {
        const originalText = button.innerHTML;
        button.innerHTML = '<i class="fas fa-times me-1"></i>Failed!';
        button.classList.remove('btn-outline-light');
        button.classList.add('btn-danger');
        
        setTimeout(() => {
            button.innerHTML = originalText;
            button.classList.remove('btn-danger');
            button.classList.add('btn-outline-light');
        }, 2000);
    },

    // Format timestamps
    formatTimestamp: function(timestamp) {
        const date = new Date(timestamp);
        return date.toLocaleString();
    },

    // Validate email address
    validateEmail: function(email) {
        const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return re.test(email);
    },

    // Validate IP address
    validateIP: function(ip) {
        const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
        const ipv6Regex = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
        return ipv4Regex.test(ip) || ipv6Regex.test(ip);
    },

    // Show loading state
    showLoading: function(element) {
        element.classList.add('loading');
        const spinner = element.querySelector('.spinner-border');
        if (spinner) {
            spinner.style.display = 'inline-block';
        }
    },

    // Hide loading state
    hideLoading: function(element) {
        element.classList.remove('loading');
        const spinner = element.querySelector('.spinner-border');
        if (spinner) {
            spinner.style.display = 'none';
        }
    },

    // Show toast notification
    showToast: function(message, type = 'info') {
        const toastContainer = document.getElementById('toast-container') || this.createToastContainer();
        const toast = this.createToast(message, type);
        toastContainer.appendChild(toast);
        
        // Auto-remove after 5 seconds
        setTimeout(() => {
            toast.remove();
        }, 5000);
    },

    // Create toast container
    createToastContainer: function() {
        const container = document.createElement('div');
        container.id = 'toast-container';
        container.className = 'position-fixed top-0 end-0 p-3';
        container.style.zIndex = '1056';
        document.body.appendChild(container);
        return container;
    },

    // Create toast element
    createToast: function(message, type) {
        const toast = document.createElement('div');
        toast.className = `toast align-items-center text-white bg-${type} border-0`;
        toast.setAttribute('role', 'alert');
        toast.innerHTML = `
            <div class="d-flex">
                <div class="toast-body">${message}</div>
                <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
            </div>
        `;
        
        // Initialize Bootstrap toast
        const bsToast = new bootstrap.Toast(toast);
        bsToast.show();
        
        return toast;
    },

    // Auto-refresh functionality
    autoRefresh: function(url, interval = 30000) {
        setInterval(() => {
            fetch(url, {
                method: 'GET',
                headers: {
                    'X-Requested-With': 'XMLHttpRequest'
                }
            })
            .then(response => response.text())
            .then(html => {
                const parser = new DOMParser();
                const doc = parser.parseFromString(html, 'text/html');
                const newContent = doc.querySelector('#refresh-content');
                const currentContent = document.querySelector('#refresh-content');
                
                if (newContent && currentContent) {
                    currentContent.innerHTML = newContent.innerHTML;
                }
            })
            .catch(error => {
                console.error('Auto-refresh failed:', error);
            });
        }, interval);
    }
};

// DNS verification functionality
const DNSVerification = {
    // Check DNS record
    checkDNSRecord: function(domain, recordType, expectedValue) {
        return fetch('/email/check-dns', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Requested-With': 'XMLHttpRequest'
            },
            body: JSON.stringify({
                domain: domain,
                record_type: recordType,
                expected_value: expectedValue
            })
        })
        .then(response => response.json());
    },

    // Update DNS status indicator
    updateDNSStatus: function(element, status, message) {
        const statusIcon = element.querySelector('.dns-status-icon');
        const statusText = element.querySelector('.dns-status-text');
        
        if (statusIcon && statusText) {
            statusIcon.className = `dns-status-icon fas ${status === 'valid' ? 'fa-check-circle text-success' : 'fa-times-circle text-danger'}`;
            statusText.textContent = message;
        }
    }
};

// Form validation
const FormValidation = {
    // Real-time email validation
    validateEmailField: function(input) {
        const isValid = SMTPManagement.validateEmail(input.value);
        this.updateFieldStatus(input, isValid, 'Please enter a valid email address');
        return isValid;
    },

    // Real-time IP validation
    validateIPField: function(input) {
        const isValid = SMTPManagement.validateIP(input.value);
        this.updateFieldStatus(input, isValid, 'Please enter a valid IP address');
        return isValid;
    },

    // Update field validation status
    updateFieldStatus: function(input, isValid, errorMessage) {
        const feedback = input.parentNode.querySelector('.invalid-feedback');
        
        if (isValid) {
            input.classList.remove('is-invalid');
            input.classList.add('is-valid');
            if (feedback) feedback.textContent = '';
        } else {
            input.classList.remove('is-valid');
            input.classList.add('is-invalid');
            if (feedback) feedback.textContent = errorMessage;
        }
    }
};

// Initialize on DOM load
document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function(tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    // Initialize form validation
    const emailInputs = document.querySelectorAll('input[type="email"]');
    emailInputs.forEach(input => {
        input.addEventListener('blur', () => FormValidation.validateEmailField(input));
    });

    const ipInputs = document.querySelectorAll('input[data-validate="ip"]');
    ipInputs.forEach(input => {
        input.addEventListener('blur', () => FormValidation.validateIPField(input));
    });

    // Initialize auto-refresh for logs page
    if (document.querySelector('#logs-page')) {
        SMTPManagement.autoRefresh(window.location.href, 30000);
    }

    // Initialize current IP detection
    const currentIPSpan = document.querySelector('#current-ip');
    if (currentIPSpan) {
        fetch('https://api.ipify.org?format=json')
            .then(response => response.json())
            .then(data => {
                currentIPSpan.textContent = data.ip;
            })
            .catch(() => {
                currentIPSpan.textContent = 'Unable to detect';
            });
    }

    // Initialize copy buttons
    const copyButtons = document.querySelectorAll('.copy-btn');
    copyButtons.forEach(button => {
        button.addEventListener('click', function() {
            const textToCopy = this.getAttribute('data-copy') || this.nextElementSibling.textContent;
            SMTPManagement.copyToClipboard(textToCopy, this);
        });
    });

    // Initialize DNS check buttons
    const dnsCheckButtons = document.querySelectorAll('.dns-check-btn');
    dnsCheckButtons.forEach(button => {
        button.addEventListener('click', function() {
            const domain = this.getAttribute('data-domain');
            const recordType = this.getAttribute('data-record-type');
            const expectedValue = this.getAttribute('data-expected-value');
            const statusElement = this.closest('.dns-record').querySelector('.dns-status');
            
            SMTPManagement.showLoading(this);
            
            DNSVerification.checkDNSRecord(domain, recordType, expectedValue)
                .then(result => {
                    DNSVerification.updateDNSStatus(statusElement, result.status, result.message);
                    SMTPManagement.hideLoading(this);
                })
                .catch(error => {
                    console.error('DNS check failed:', error);
                    DNSVerification.updateDNSStatus(statusElement, 'error', 'DNS check failed');
                    SMTPManagement.hideLoading(this);
                });
        });
    });
});

// Export for use in other scripts
window.SMTPManagement = SMTPManagement;
window.DNSVerification = DNSVerification;
window.FormValidation = FormValidation;
