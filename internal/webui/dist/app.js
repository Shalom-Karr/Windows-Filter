// skfilter dashboard SPA — drives index.html via /api/rules.
// Vanilla JS, fetch + async/await, no framework.

const banner = document.getElementById('banner');
const tbody = document.getElementById('rules-body');
const filterInput = document.getElementById('filter');

let cachedRules = [];

function escapeHTML(s) {
    return String(s ?? '').replace(/[&<>"']/g, c => ({
        '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'
    }[c]));
}

function showError(msg) {
    banner.textContent = msg;
    banner.classList.remove('hidden');
    banner.classList.remove('banner-info');
}

function showInfo(msg) {
    banner.textContent = msg;
    banner.classList.remove('hidden');
    banner.classList.add('banner-info');
}

function clearBanner() {
    banner.classList.add('hidden');
    banner.classList.remove('banner-info');
}

function fmtTime(s) {
    if (!s) return '—';
    try {
        const d = new Date(s);
        if (isNaN(d.getTime())) return s;
        return d.toLocaleString();
    } catch (_) { return s; }
}

function renderTable() {
    const q = (filterInput.value || '').trim().toLowerCase();
    const rules = q ? cachedRules.filter(r => (r.domain || '').toLowerCase().includes(q)) : cachedRules;

    if (!rules.length) {
        tbody.innerHTML = `<tr><td colspan="5" class="muted" style="text-align:center; padding:24px">${cachedRules.length ? 'No matches.' : 'No allowed sites yet — add one above.'}</td></tr>`;
        return;
    }

    tbody.innerHTML = rules.map(r => {
        const ipsArr = Array.isArray(r.ips) ? r.ips : [];
        const ipsHTML = ipsArr.length
            ? `<div class="ip-list">${ipsArr.map(escapeHTML).join('<br>')}</div>`
            : '<span class="muted">resolving…</span>';
        const enabledBadge = r.enabled
            ? '<span class="badge badge-on">enabled</span>'
            : '<span class="badge badge-off">disabled</span>';
        return `<tr data-id="${r.id}">
            <td><strong>${escapeHTML(r.domain)}</strong></td>
            <td>${ipsHTML}</td>
            <td class="muted">${escapeHTML(fmtTime(r.last_resolved_at))}</td>
            <td>${enabledBadge}</td>
            <td>
                <div class="row-actions" style="justify-content:flex-end">
                    <button class="btn-secondary btn-sm" data-action="refresh" data-id="${r.id}">Refresh</button>
                    <button class="btn-danger btn-sm" data-action="delete-arm" data-id="${r.id}">Remove</button>
                </div>
            </td>
        </tr>`;
    }).join('');
}

async function loadRules() {
    try {
        const res = await fetch('/api/rules');
        if (!res.ok) {
            if (res.status === 401) { window.location = '/login'; return; }
            throw new Error('HTTP ' + res.status);
        }
        cachedRules = await res.json();
        renderTable();
        clearBanner();
    } catch (e) {
        showError('Failed to load rules: ' + e.message);
    }
}

async function addDomain(domain) {
    domain = (domain || '').trim().toLowerCase();
    if (!domain) { showError('Enter a domain'); return; }
    try {
        const res = await fetch('/api/rules', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({domain})
        });
        if (!res.ok) {
            if (res.status === 401) { window.location = '/login'; return; }
            const j = await res.json().catch(() => ({}));
            throw new Error(j.error || ('HTTP ' + res.status));
        }
        document.getElementById('add-domain').value = '';
        await loadRules();
        showInfo('Added ' + domain);
    } catch (e) {
        showError('Failed to add: ' + e.message);
    }
}

async function refreshRule(id) {
    try {
        const res = await fetch(`/api/rules/${id}/refresh`, {method: 'POST'});
        if (!res.ok) {
            if (res.status === 401) { window.location = '/login'; return; }
            const j = await res.json().catch(() => ({}));
            throw new Error(j.error || ('HTTP ' + res.status));
        }
        await loadRules();
        showInfo('Refreshed');
    } catch (e) {
        showError('Refresh failed: ' + e.message);
    }
}

async function deleteRule(id) {
    try {
        const res = await fetch(`/api/rules/${id}`, {method: 'DELETE'});
        if (!res.ok && res.status !== 204) {
            if (res.status === 401) { window.location = '/login'; return; }
            const j = await res.json().catch(() => ({}));
            throw new Error(j.error || ('HTTP ' + res.status));
        }
        await loadRules();
        showInfo('Removed');
    } catch (e) {
        showError('Delete failed: ' + e.message);
    }
}

// 10-second confirm countdown for delete.
function armDelete(btn, id) {
    if (btn.dataset.armed === '1') return;
    btn.dataset.armed = '1';
    btn.disabled = true;
    let left = 10;
    btn.textContent = `Confirm in ${left}s…`;
    const tick = setInterval(() => {
        left -= 1;
        if (left > 0) {
            btn.textContent = `Confirm in ${left}s…`;
        } else {
            clearInterval(tick);
            btn.disabled = false;
            btn.textContent = 'Confirm remove';
            btn.dataset.action = 'delete-confirm';
            // Auto-disarm after 15s of armed-but-unconfirmed.
            setTimeout(() => {
                if (btn.dataset.armed === '1' && btn.dataset.action === 'delete-confirm') {
                    btn.dataset.armed = '';
                    btn.dataset.action = 'delete-arm';
                    btn.textContent = 'Remove';
                }
            }, 15000);
        }
    }, 1000);
}

// Event delegation for table buttons.
tbody.addEventListener('click', async (e) => {
    const btn = e.target.closest('button[data-action]');
    if (!btn) return;
    const id = btn.dataset.id;
    const action = btn.dataset.action;
    if (action === 'refresh') {
        btn.disabled = true;
        btn.textContent = 'Refreshing…';
        await refreshRule(id);
    } else if (action === 'delete-arm') {
        armDelete(btn, id);
    } else if (action === 'delete-confirm') {
        await deleteRule(id);
    }
});

document.getElementById('add-btn').addEventListener('click', () => {
    addDomain(document.getElementById('add-domain').value);
});
document.getElementById('add-domain').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') addDomain(e.target.value);
});
document.getElementById('reload-btn').addEventListener('click', loadRules);
filterInput.addEventListener('input', renderTable);

loadRules();
