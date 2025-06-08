// DKIM Management functionality
const DKIMManagement = {
    // Check DNS records for a domain
    checkDomainDNS: async function(domain, selector, checkDkimUrl, checkSpfUrl) {
        const dkimStatus = document.getElementById(`dkim-status-${domain.replace('.', '-')}`);
        const spfStatus = document.getElementById(`spf-status-${domain.replace('.', '-')}`);
        
        // Show loading state
        dkimStatus.innerHTML = '<span class="status-indicator status-warning"></span><small class="text-muted">Checking...</small>';
        spfStatus.innerHTML = '<span class="status-indicator status-warning"></span><small class="text-muted">Checking...</small>';
        
        try {
            // Check DKIM DNS
            const dkimResponse = await fetch(checkDkimUrl, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                body: new URLSearchParams({
                    domain: domain,
                    selector: selector
                })
            });
            const dkimResult = await dkimResponse.json();
            
            // Check SPF DNS
            const spfResponse = await fetch(checkSpfUrl, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                body: new URLSearchParams({
                    domain: domain
                })
            });
            const spfResult = await spfResponse.json();
            
            // Get DKIM key status from the card class
            const domainCard = document.getElementById(`domain-${domain.replace('.', '-')}`);
            const isActive = domainCard && domainCard.classList.contains('dkim-active');
            
            // Update DKIM status based on active state and DNS visibility
            if (isActive) {
                if (dkimResult.success) {
                    dkimStatus.innerHTML = '<span class="status-indicator status-success"></span><small class="text-success">✓ Active & Configured</small>';
                } else {
                    dkimStatus.innerHTML = '<span class="status-indicator" style="background-color: #fd7e14;"></span><small class="text-warning">Active but DNS not found</small>';
                }
            } else {
                dkimStatus.innerHTML = '<span class="status-indicator" style="background-color: #6c757d;"></span><small class="text-muted">Disabled</small>';
            }
            
            // Update SPF status
            if (spfResult.success) {
                spfStatus.innerHTML = '<span class="status-indicator status-success"></span><small class="text-success">✓ Found</small>';
            } else {
                spfStatus.innerHTML = '<span class="status-indicator status-danger"></span><small class="text-danger">✗ Not found</small>';
            }
            
            // Show detailed results in modal
            this.showDNSResults(domain, dkimResult, spfResult);
            
        } catch (error) {
            console.error('DNS check error:', error);
            dkimStatus.innerHTML = '<span class="status-indicator status-danger"></span><small class="text-danger">Error</small>';
            spfStatus.innerHTML = '<span class="status-indicator status-danger"></span><small class="text-danger">Error</small>';
        }
    },

    // Show DNS check results in modal
    showDNSResults: function(domain, dkimResult, spfResult) {
        // Clean up record strings by removing extra quotes and normalizing whitespace
        function cleanRecordDisplay(record) {
            if (!record) return '';
            return record
                .replace(/^["']|["']$/g, '')  // Remove outer quotes
                .replace(/\\n/g, '')          // Remove newlines
                .replace(/\s+/g, ' ')         // Normalize whitespace
                .trim();                      // Remove leading/trailing space
        }

        const dkimRecordsHtml = dkimResult.records ? 
            dkimResult.records.map(record => 
                `<div class="record-value" style="word-break: break-all; font-family: monospace; background: #f8f9fa; padding: 8px; border-radius: 4px;">
                    ${cleanRecordDisplay(record)}
                </div>`
            ).join('') : '';

        const spfRecordHtml = spfResult.spf_record ? 
            `<div class="record-value mt-2" style="word-break: break-all; font-family: monospace; background: #f8f9fa; padding: 8px; border-radius: 4px;">
                ${cleanRecordDisplay(spfResult.spf_record)}
            </div>` : '';

        const resultsHtml = `
            <h6>DNS Check Results for ${domain}</h6>
            
            <div class="mb-3">
                <h6 class="text-primary">DKIM Record</h6>
                <div class="alert ${dkimResult.success ? 'alert-success' : 'alert-danger'}">
                    <strong>Status:</strong> ${dkimResult.success ? 'Found' : 'Not Found'}<br>
                    <strong>Message:</strong> ${dkimResult.message}
                    ${dkimResult.records ? `
                        <br><strong>Records:</strong>
                        <div class="records-container mt-2">
                            ${dkimRecordsHtml}
                        </div>
                    ` : ''}
                </div>
            </div>
            
            <div class="mb-3">
                <h6 class="text-primary">SPF Record</h6>
                <div class="alert ${spfResult.success ? 'alert-success' : 'alert-danger'}">
                    <strong>Status:</strong> ${spfResult.success ? 'Found' : 'Not Found'}<br>
                    <strong>Message:</strong> ${spfResult.message}
                    ${spfResult.spf_record ? `
                        <br><strong>Current SPF:</strong>
                        ${spfRecordHtml}
                    ` : ''}
                </div>
            </div>
        `;
        
        document.getElementById('dnsResults').innerHTML = resultsHtml;
        new bootstrap.Modal(document.getElementById('dnsResultModal')).show();
    },

    // Check all domains' DNS records
    checkAllDNS: async function(checkDkimUrl, checkSpfUrl) {
        const domains = document.querySelectorAll('[id^="domain-"]');
        const results = [];
        
        // Show a progress indicator
        showToast('Checking DNS records for all domains...', 'info');
        
        for (const domainCard of domains) {
            try {
                const domainId = domainCard.id.split('-')[1];
                // Extract domain name from the card header
                const domainHeaderText = domainCard.querySelector('h5').textContent.trim();
                const domainName = domainHeaderText.split('\n')[0].trim().replace(/^\s*\S+\s+/, ''); // Remove icon
                const selectorElement = domainCard.querySelector('code');
                
                if (selectorElement) {
                    const selector = selectorElement.textContent;
                    
                    // Check DKIM DNS
                    const dkimResponse = await fetch(checkDkimUrl, {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/x-www-form-urlencoded',
                        },
                        body: `domain=${encodeURIComponent(domainName)}&selector=${encodeURIComponent(selector)}`
                    });
                    const dkimResult = await dkimResponse.json();
                    
                    // Check SPF DNS
                    const spfResponse = await fetch(checkSpfUrl, {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/x-www-form-urlencoded',
                        },
                        body: `domain=${encodeURIComponent(domainName)}`
                    });
                    const spfResult = await spfResponse.json();
                    
                    results.push({
                        domain: domainName,
                        dkim: dkimResult,
                        spf: spfResult
                    });
                    
                    // Update individual status indicators
                    const dkimStatus = document.getElementById(`dkim-status-${domainName.replace('.', '-')}`);
                    const spfStatus = document.getElementById(`spf-status-${domainName.replace('.', '-')}`);
                    
                    if (dkimStatus) {
                        if (dkimResult.success) {
                            dkimStatus.innerHTML = '<span class="status-indicator status-success"></span><small class="text-success">✓ Configured</small>';
                        } else {
                            dkimStatus.innerHTML = '<span class="status-indicator status-danger"></span><small class="text-danger">✗ Not found</small>';
                        }
                    }
                    
                    if (spfStatus) {
                        if (spfResult.success) {
                            spfStatus.innerHTML = '<span class="status-indicator status-success"></span><small class="text-success">✓ Found</small>';
                        } else {
                            spfStatus.innerHTML = '<span class="status-indicator status-danger"></span><small class="text-danger">✗ Not found</small>';
                        }
                    }
                    
                    // Small delay between checks to avoid overwhelming the DNS server
                    await new Promise(resolve => setTimeout(resolve, 300));
                }
            } catch (error) {
                console.error('Error checking DNS for domain:', error);
            }
        }
        
        // Show combined results in modal
        this.showAllDNSResults(results);
    },

    // Show combined DNS check results
    showAllDNSResults: function(results) {
        let tableRows = '';
        
        results.forEach(result => {
            const dkimIcon = result.dkim.success ? '<i class="bi bi-check-circle-fill text-success"></i>' : '<i class="bi bi-x-circle-fill text-danger"></i>';
            const spfIcon = result.spf.success ? '<i class="bi bi-check-circle-fill text-success"></i>' : '<i class="bi bi-x-circle-fill text-danger"></i>';
            
            tableRows += `
                <tr>
                    <td><strong>${result.domain}</strong></td>
                    <td class="text-center">
                        ${dkimIcon}
                        <small class="d-block">${result.dkim.success ? 'Configured' : 'Not Found'}</small>
                    </td>
                    <td class="text-center">
                        ${spfIcon}
                        <small class="d-block">${result.spf.success ? 'Found' : 'Not Found'}</small>
                    </td>
                    <td>
                        <small class="text-muted">
                            DKIM: ${result.dkim.message}<br>
                            SPF: ${result.spf.message}
                        </small>
                    </td>
                </tr>
            `;
        });
        
        const resultsHtml = `
            <h6>DNS Check Results for All Domains</h6>
            <div class="table-responsive">
                <table class="table table-striped">
                    <thead>
                        <tr>
                            <th>Domain</th>
                            <th class="text-center">DKIM Status</th>
                            <th class="text-center">SPF Status</th>
                            <th>Details</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${tableRows}
                    </tbody>
                </table>
            </div>
            <div class="mt-3">
                <div class="alert alert-info">
                    <small>
                        <i class="bi bi-info-circle me-1"></i>
                        <strong>DKIM:</strong> Verifies email signatures for authenticity<br>
                        <i class="bi bi-info-circle me-1"></i>
                        <strong>SPF:</strong> Authorizes servers that can send email for your domain
                    </small>
                </div>
            </div>
        `;
        
        document.getElementById('dnsResults').innerHTML = resultsHtml;
        new bootstrap.Modal(document.getElementById('dnsResultModal')).show();
    }
}; 