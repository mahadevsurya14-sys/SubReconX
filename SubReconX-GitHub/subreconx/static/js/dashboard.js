/**
 * SubReconX — Primary Dashboard Application Logic
 */

class SubReconXApp {
  constructor() {
    this.currentScanId = null;
    this.pollInterval = null;
    this.currentPage = 1;
    this.perPage = 50;
    this.searchTerm = '';
    this.sortBy = 'hostname';
    this.sortDesc = false;

    this.initElements();
    this.attachEventListeners();
    this.loadHistory();
    this.checkHealth();
  }

  initElements() {
    this.domainInput = document.getElementById('target-domain');
    this.chkDns = document.getElementById('chk-dns');
    this.chkHttp = document.getElementById('chk-http');
    this.chkSubfinder = document.getElementById('chk-subfinder');
    this.chkAmass = document.getElementById('chk-amass');
    this.btnStart = document.getElementById('btn-start-scan');
    this.btnCancel = document.getElementById('btn-cancel-scan');
    this.scopePreview = document.getElementById('scope-text');

    this.progressCard = document.getElementById('progress-card');
    this.progressPhase = document.getElementById('progress-phase');
    this.progressBar = document.getElementById('progress-bar');
    this.elapsedTime = document.getElementById('elapsed-time');

    this.statTotal = document.getElementById('stat-total');
    this.statResolved = document.getElementById('stat-resolved');
    this.statHttp = document.getElementById('stat-http');
    this.statWarnings = document.getElementById('stat-warnings');

    this.tableBody = document.getElementById('results-tbody');
    this.searchInput = document.getElementById('search-input');
    this.paginationInfo = document.getElementById('pagination-info');
    this.btnPrev = document.getElementById('btn-prev');
    this.btnNext = document.getElementById('btn-next');

    this.historyList = document.getElementById('history-list');
    this.toast = document.getElementById('toast');

    this.btnExportCsv = document.getElementById('export-csv');
    this.btnExportJson = document.getElementById('export-json');
    this.btnExportHtml = document.getElementById('export-html');
  }

  attachEventListeners() {
    this.domainInput.addEventListener('input', () => this.updateScopePreview());
    this.btnStart.addEventListener('click', () => this.startScan());
    this.btnCancel.addEventListener('click', () => this.cancelScan());

    let searchTimeout = null;
    this.searchInput.addEventListener('input', (e) => {
      clearTimeout(searchTimeout);
      searchTimeout = setTimeout(() => {
        this.searchTerm = e.target.value;
        this.currentPage = 1;
        this.loadResults();
      }, 300);
    });

    this.btnPrev.addEventListener('click', () => {
      if (this.currentPage > 1) {
        this.currentPage--;
        this.loadResults();
      }
    });

    this.btnNext.addEventListener('click', () => {
      this.currentPage++;
      this.loadResults();
    });

    document.querySelectorAll('.data-table th.sortable').forEach(th => {
      th.addEventListener('click', () => {
        const field = th.dataset.sort;
        if (this.sortBy === field) {
          this.sortDesc = !this.sortDesc;
        } else {
          this.sortBy = field;
          this.sortDesc = false;
        }
        this.loadResults();
      });
    });
  }

  showToast(message, isError = false) {
    if (!this.toast) return;
    this.toast.textContent = message;
    this.toast.style.borderColor = isError ? 'var(--accent-red)' : 'var(--accent-green)';
    this.toast.style.display = 'block';
    setTimeout(() => {
      this.toast.style.display = 'none';
    }, 4000);
  }

  updateScopePreview() {
    const raw = this.domainInput.value.trim();
    if (!raw) {
      this.scopePreview.innerHTML = 'Enter target domain to preview scope authorization.';
      return;
    }
    const clean = raw.toLowerCase().replace(/^(https?:\/\/)?/, '').split('/')[0];
    this.scopePreview.innerHTML = `<strong>Authorized Scope Boundary:</strong><br>• *.${clean}<br>• ${clean}`;
  }

  async checkHealth() {
    try {
      const res = await fetch('/api/health');
      if (res.ok) {
        const data = await res.json();
        const sfInstalled = data.tools.subfinder.installed;
        const amassInstalled = data.tools.amass.installed;
        if (!sfInstalled && this.chkSubfinder) {
          this.chkSubfinder.disabled = true;
          this.chkSubfinder.checked = false;
          this.chkSubfinder.parentElement.title = 'Subfinder not detected in PATH';
        }
        if (!amassInstalled && this.chkAmass) {
          this.chkAmass.disabled = true;
          this.chkAmass.checked = false;
          this.chkAmass.parentElement.title = 'Amass not detected in PATH';
        }
      }
    } catch (err) {
      console.warn('Health check failed', err);
    }
  }

  async startScan() {
    const domain = this.domainInput.value.trim();
    if (!domain) {
      this.showToast('Please specify a target domain', true);
      return;
    }

    const payload = {
      domain: domain,
      enable_dns: this.chkDns.checked,
      enable_http: this.chkHttp.checked,
      use_subfinder: this.chkSubfinder.checked,
      use_amass: this.chkAmass.checked
    };

    this.btnStart.disabled = true;
    this.btnCancel.style.display = 'block';
    this.progressCard.style.display = 'block';
    this.progressPhase.textContent = 'Initiating assessment pipeline...';

    try {
      const res = await fetch('/api/scans', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || 'Failed to start scan');
      }

      const data = await res.json();
      this.currentScanId = data.scan_id;
      this.updateExportLinks(this.currentScanId);
      this.showToast(`Scan ${this.currentScanId} started for ${domain}`);

      this.startPolling();
    } catch (err) {
      this.showToast(err.message, true);
      this.btnStart.disabled = false;
      this.btnCancel.style.display = 'none';
      this.progressCard.style.display = 'none';
    }
  }

  startPolling() {
    if (this.pollInterval) clearInterval(this.pollInterval);
    const startTime = Date.now();

    this.pollInterval = setInterval(async () => {
      if (!this.currentScanId) return;

      const elapsedSec = Math.floor((Date.now() - startTime) / 1000);
      this.elapsedTime.textContent = `${elapsedSec}s`;

      try {
        const res = await fetch(`/api/scans/${this.currentScanId}`);
        if (!res.ok) return;

        const scan = await res.json();
        this.updateStatusUI(scan);

        if (scan.status === 'completed' || scan.status === 'failed' || scan.status === 'cancelled') {
          clearInterval(this.pollInterval);
          this.btnStart.disabled = false;
          this.btnCancel.style.display = 'none';
          this.loadHistory();
          this.loadResults();

          if (scan.status === 'completed') {
            this.showToast('Assessment completed successfully!');
          } else {
            this.showToast(`Scan ended with status: ${scan.status}`, true);
          }
        }
      } catch (err) {
        console.error('Polling error', err);
      }
    }, 1500);
  }

  updateStatusUI(scan) {
    if (scan.status === 'running') {
      this.progressPhase.textContent = 'Enumerating subdomains and probing assets...';
      this.progressBar.classList.add('progress-bar-indeterminate');
    } else {
      this.progressPhase.textContent = `Status: ${scan.status.toUpperCase()}`;
      this.progressBar.classList.remove('progress-bar-indeterminate');
      this.progressBar.style.width = '100%';
    }

    if (scan.summary) {
      this.statTotal.textContent = scan.summary.total_subdomains || 0;
      this.statResolved.textContent = scan.summary.dns_resolved || 0;
      this.statHttp.textContent = (scan.summary.http_live || 0) + (scan.summary.https_live || 0);
      this.statWarnings.textContent = (scan.summary.warnings || []).length;
    }
  }

  async cancelScan() {
    if (!this.currentScanId) return;
    try {
      await fetch(`/api/scans/${this.currentScanId}/cancel`, { method: 'POST' });
      this.showToast('Cancellation requested...');
    } catch (err) {
      this.showToast('Could not cancel scan', true);
    }
  }

  updateExportLinks(scanId) {
    if (!scanId) {
      this.btnExportCsv.href = '#';
      this.btnExportJson.href = '#';
      this.btnExportHtml.href = '#';
      return;
    }
    this.btnExportCsv.href = `/api/reports/${scanId}/csv`;
    this.btnExportJson.href = `/api/reports/${scanId}/json`;
    this.btnExportHtml.href = `/api/reports/${scanId}/html`;
  }

  async loadResults() {
    if (!this.currentScanId) return;

    const params = new URLSearchParams({
      page: this.currentPage,
      per_page: this.perPage,
      sort_by: this.sortBy,
      sort_desc: this.sortDesc
    });
    if (this.searchTerm) params.set('search', this.searchTerm);

    try {
      const res = await fetch(`/api/scans/${this.currentScanId}/results?${params}`);
      if (!res.ok) return;

      const data = await res.json();
      this.renderTable(data.results);
      this.renderPagination(data);
    } catch (err) {
      console.error('Failed to load results', err);
    }
  }

  renderTable(rows) {
    if (!rows || rows.length === 0) {
      this.tableBody.innerHTML = `
        <tr>
          <td colspan="6" style="text-align: center; color: var(--text-muted); padding: 2rem;">
            No asset records found matching criteria.
          </td>
        </tr>`;
      return;
    }

    this.tableBody.innerHTML = rows.map(r => {
      const dnsBadge = r.dns_resolved
        ? '<span class="badge badge-resolved">RESOLVED</span>'
        : '<span class="badge badge-unresolved">UNRESOLVED</span>';

      const dnsRecordsText = r.dns_records && r.dns_records.length > 0
        ? r.dns_records.map(d => `${d.type}: ${d.value}`).join('<br>')
        : (r.dns_error || '—');

      const httpBadge = this.getHttpBadge(r.http);
      const httpsBadge = this.getHttpBadge(r.https);

      return `
        <tr>
          <td class="cell-host">${r.hostname}</td>
          <td><span class="badge badge-source">${r.source}</span></td>
          <td>${dnsBadge}</td>
          <td style="font-family: var(--font-mono); font-size: 0.78rem;">${dnsRecordsText}</td>
          <td>${httpBadge}</td>
          <td>${httpsBadge}</td>
        </tr>`;
    }).join('');
  }

  getHttpBadge(probe) {
    if (!probe) return '<span class="badge badge-http-err">—</span>';
    if (probe.error) return `<span class="badge badge-http-err" title="${probe.error}">ERR</span>`;
    const code = probe.status_code;
    if (code >= 200 && code < 300) return `<span class="badge badge-http-2xx">${code}</span>`;
    if (code >= 300 && code < 400) return `<span class="badge badge-http-3xx">${code}</span>`;
    if (code >= 400 && code < 500) return `<span class="badge badge-http-4xx">${code}</span>`;
    return `<span class="badge badge-http-5xx">${code}</span>`;
  }

  renderPagination(data) {
    const total = data.total;
    const start = total === 0 ? 0 : (data.page - 1) * data.per_page + 1;
    const end = Math.min(data.page * data.per_page, total);

    this.paginationInfo.textContent = `Showing ${start}-${end} of ${total} entries`;
    this.btnPrev.disabled = data.page <= 1;
    this.btnNext.disabled = data.page >= data.total_pages;
  }

  async loadHistory() {
    try {
      const res = await fetch('/api/scans?limit=15');
      if (!res.ok) return;

      const scans = await res.json();
      if (!scans || scans.length === 0) {
        this.historyList.innerHTML = '<div style="color: var(--text-muted); font-size: 0.8rem;">No past scans.</div>';
        return;
      }

      this.historyList.innerHTML = scans.map(s => `
        <div class="history-item" onclick="app.selectHistoryScan('${s.scan_id}')">
          <div>
            <div class="history-domain">${s.domain}</div>
            <div class="history-date">${s.started_at ? s.started_at.split('T')[0] : '—'} • ${s.status}</div>
          </div>
          <div class="history-count">${s.total_subdomains !== undefined ? s.total_subdomains : '—'} subs</div>
        </div>
      `).join('');
    } catch (err) {
      console.warn('Failed to load history', err);
    }
  }

  async selectHistoryScan(scanId) {
    this.currentScanId = scanId;
    this.updateExportLinks(scanId);
    this.currentPage = 1;

    try {
      const res = await fetch(`/api/scans/${scanId}`);
      if (res.ok) {
        const scan = await res.json();
        this.domainInput.value = scan.domain;
        this.updateScopePreview();
        this.updateStatusUI(scan);
      }
      this.loadResults();
      this.showToast(`Loaded scan ${scanId}`);
    } catch (err) {
      console.error(err);
    }
  }
}

// Global initialization
let app = null;
window.addEventListener('DOMContentLoaded', () => {
  app = new SubReconXApp();
});
