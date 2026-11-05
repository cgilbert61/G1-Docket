/**
 * G1 Docket & Combine Governance Dashboard JavaScript
 * Handles SSE live event stream, Four-Eyes dual-key approval, WORM verification, and SIEM management.
 */

let currentQuarantineId = null;
let currentQuarantineItem = null;
let currentConfigDestId = null;

function switchTab(tabId) {
  const tabs = ['quarantine', 'worm', 'siem', 'live'];
  tabs.forEach(t => {
    document.getElementById('tab-' + t).classList.add('hidden');
    const btn = document.getElementById('tab-btn-' + t);
    btn.className = 'pb-2.5 text-[#475569] hover:text-[#0F172A] border-b-2 border-transparent cursor-pointer';
  });

  document.getElementById('tab-' + tabId).classList.remove('hidden');
  const activeBtn = document.getElementById('tab-btn-' + tabId);
  activeBtn.className = 'pb-2.5 text-[#0F172A] border-b-2 border-[#1E293B] cursor-pointer';
}

async function refreshQuarantine() {
  const res = await fetch('/api/quarantine');
  const items = await res.json();
  const tbody = document.getElementById('quarantine-tbody');
  if (items.length === 0) {
    tbody.innerHTML = '<tr><td colspan="8" class="p-6 text-center text-[#475569]">No quarantined objects pending review.</td></tr>';
    return;
  }
  tbody.innerHTML = items.map(item => `
    <tr class="hover:bg-[#F8FAFC]">
      <td class="p-3 font-semibold text-[#0F172A]">${item.quarantine_id}</td>
      <td class="p-3"><span class="badge ${item.status === 'RELEASED' ? 'badge-success' : (item.status === 'AWAITING_SECOND_KEY' ? 'badge-neutral' : 'badge-warning')}">${item.status}</span></td>
      <td class="p-3 text-[#475569]">${item.event_type}</td>
      <td class="p-3 text-[#0F172A] font-semibold">${item.reason_code}</td>
      <td class="p-3">${item.claimed_tier}</td>
      <td class="p-3 text-[#475569] truncate max-w-[200px]" title="${item.locator_uri}">${item.locator_uri}</td>
      <td class="p-3 text-[#475569]">${(item.created_at || '').substring(0, 19)}</td>
      <td class="p-3 text-right">
        <button onclick="openTriageModal('${item.quarantine_id}')" class="btn btn-secondary text-xs py-1 px-2.5">
          Inspect & Triage
        </button>
      </td>
    </tr>
  `).join('');
}

async function openTriageModal(qid) {
  currentQuarantineId = qid;
  const res = await fetch(`/api/quarantine/${qid}`);
  const item = await res.json();
  currentQuarantineItem = item;

  document.getElementById('m-id').textContent = item.quarantine_id;
  document.getElementById('m-status').textContent = item.status;
  document.getElementById('m-reason').textContent = item.reason_code;
  document.getElementById('m-tier').textContent = item.claimed_tier;
  document.getElementById('m-loc').textContent = item.locator_uri;
  document.getElementById('m-sha').textContent = item.payload_digest;
  document.getElementById('m-content').textContent = item.extracted_text || JSON.stringify(item.raw_payload, null, 2);
  document.getElementById('modal-subtitle').textContent = `Inspecting ${item.quarantine_id} [${item.reason_code}]`;

  // Workflow states
  const k1Btn = document.getElementById('btn-submit-key1');
  const k2Btn = document.getElementById('btn-submit-key2');
  const k1Op = document.getElementById('k1-operator');
  const k1Rat = document.getElementById('k1-rationale');
  const k2Op = document.getElementById('k2-operator');
  const k2Notes = document.getElementById('k2-notes');
  const replayBox = document.getElementById('replay-box');

  if (item.status === 'QUARANTINED') {
    k1Btn.disabled = false;
    k1Op.disabled = false;
    k1Rat.disabled = false;
    k1Op.value = '';
    k1Rat.value = '';
    document.getElementById('key1-badge').className = 'badge badge-warning';
    document.getElementById('key1-badge').textContent = 'Awaiting Key 1';
    const qk1 = document.getElementById('btn-quick-k1');
    if (qk1) qk1.classList.remove('hidden');

    k1Btn.disabled = false;
    k1Btn.className = 'btn btn-primary font-bold';
    k1Btn.textContent = '1. Stage Key 1 Override';
    k2Btn.disabled = true;
    k2Btn.style.pointerEvents = 'none';
    k2Btn.style.backgroundColor = '#F1F5F9';
    k2Btn.style.color = '#94A3B8';
    k2Btn.style.borderColor = '#CBD5E1';
    k2Btn.className = 'btn btn-secondary cursor-not-allowed';
    k2Btn.textContent = '🔒 Sign Key 2 & Execute Replay (Locked)';
    k2Btn.title = 'Locked: Complete Step 1 (Stage Key 1 Override) above first.';
    k2Op.disabled = true;
    k2Notes.disabled = true;
    document.getElementById('key2-badge').className = 'badge badge-neutral';
    document.getElementById('key2-badge').textContent = 'Locked';
    const s2Badge = document.getElementById('step2-badge-tag');
    if (s2Badge) {
      s2Badge.textContent = 'STEP 2 (LOCKED)';
      s2Badge.className = 'text-[10px] font-bold text-[#64748B] bg-[#F1F5F9] border border-[#E2E8F0] px-1.5 py-0.5 rounded';
    }
    const lockNotice = document.getElementById('key2-lock-notice');
    if (lockNotice) lockNotice.classList.remove('hidden');
    const qk2 = document.getElementById('btn-quick-k2');
    if (qk2) qk2.classList.add('hidden');
    replayBox.classList.add('hidden');
  } else if (item.status === 'AWAITING_SECOND_KEY') {
    k1Btn.disabled = true;
    k1Op.disabled = true;
    k1Rat.disabled = true;
    k1Op.value = (item.first_key || {}).operator || '';
    k1Rat.value = (item.first_key || {}).rationale || '';
    document.getElementById('key1-badge').className = 'badge badge-success';
    document.getElementById('key1-badge').textContent = `Signed by ${k1Op.value}`;
    const qk1 = document.getElementById('btn-quick-k1');
    if (qk1) qk1.classList.add('hidden');

    k1Btn.disabled = true;
    k1Btn.className = 'btn btn-secondary';
    k1Btn.textContent = '[OK] Step 1 Staged';
    k2Btn.disabled = false;
    k2Btn.style.pointerEvents = 'auto';
    k2Btn.style.backgroundColor = '';
    k2Btn.style.color = '';
    k2Btn.style.borderColor = '';
    k2Btn.className = 'btn btn-primary font-bold';
    k2Btn.textContent = '⚡ 2. Sign Key 2 & Execute Replay';
    k2Btn.title = 'Authorize emergency release and replay payload through :18082';
    k2Op.disabled = false;
    k2Notes.disabled = false;
    k2Op.value = '';
    k2Notes.value = '';
    document.getElementById('key2-badge').className = 'badge badge-warning';
    document.getElementById('key2-badge').textContent = 'Awaiting Distinct Key 2';
    const s2Badge = document.getElementById('step2-badge-tag');
    if (s2Badge) {
      s2Badge.textContent = 'STEP 2 (UNLOCKED)';
      s2Badge.className = 'text-[10px] font-bold text-[#166534] bg-[#F0FDF4] border border-[#BBF7D0] px-1.5 py-0.5 rounded';
    }
    const lockNotice = document.getElementById('key2-lock-notice');
    if (lockNotice) lockNotice.classList.add('hidden');
    const qk2 = document.getElementById('btn-quick-k2');
    if (qk2) qk2.classList.remove('hidden');
    replayBox.classList.add('hidden');
  } else if (item.status === 'RELEASED') {
    k1Btn.disabled = true;
    k1Op.disabled = true;
    k1Rat.disabled = true;
    k1Op.value = (item.first_key || {}).operator || '';
    k1Rat.value = (item.first_key || {}).rationale || '';
    const qk1 = document.getElementById('btn-quick-k1');
    if (qk1) qk1.classList.add('hidden');

    k2Btn.disabled = true;
    k2Btn.style.pointerEvents = 'none';
    k2Btn.title = 'Item already released via Ed25519 DSSE emergency ticket.';
    k2Op.disabled = true;
    k2Notes.disabled = true;
    k2Op.value = (item.second_key || {}).operator || '';
    k2Notes.value = (item.second_key || {}).notes || '';
    document.getElementById('key1-badge').className = 'badge badge-success';
    document.getElementById('key1-badge').textContent = `Signed by ${k1Op.value}`;
    document.getElementById('key2-badge').className = 'badge badge-success';
    document.getElementById('key2-badge').textContent = `Approved by ${k2Op.value}`;
    const s2Badge = document.getElementById('step2-badge-tag');
    if (s2Badge) {
      s2Badge.textContent = 'STEP 2 (COMPLETED)';
      s2Badge.className = 'text-[10px] font-bold text-[#166534] bg-[#F0FDF4] border border-[#BBF7D0] px-1.5 py-0.5 rounded';
    }
    const lockNotice = document.getElementById('key2-lock-notice');
    if (lockNotice) lockNotice.classList.add('hidden');
    const qk2 = document.getElementById('btn-quick-k2');
    if (qk2) qk2.classList.add('hidden');

    if (item.replay_response) {
      replayBox.classList.remove('hidden');
      document.getElementById('replay-output').textContent = JSON.stringify(item.replay_response, null, 2);
    }
  }

  document.getElementById('triage-modal').classList.remove('hidden');
}

function handleKey2Click(e) {
  const k2Btn = document.getElementById('btn-submit-key2');
  if (k2Btn && k2Btn.disabled) {
    if (e) e.stopPropagation();
    const k1Box = document.getElementById('step-1-container');
    if (k1Box) {
      k1Box.style.backgroundColor = '#FEF3C7';
      setTimeout(() => { k1Box.style.backgroundColor = ''; }, 1200);
    }
    const k1Op = document.getElementById('k1-operator');
    if (k1Op && !k1Op.value) {
      quickFillDemoK1();
    }
    alert('⚠️ Step 1 Required First:\n\nPlease complete Step 1 (Key 1: Override Request) above first:\n\n1. Requester ID has been autofilled.\n2. Click "1. Stage Key 1 Override".\n\nOnce Key 1 is staged, Key 2 will automatically unlock for distinct approver signoff.\n\n(Tip: Or click "⚡ 1-Click Dual Signoff & Replay" above!)');
  }
}

async function fastTrackDualApproval() {
  if (!currentQuarantineId) return;
  const btn = document.getElementById('btn-fast-track');
  if (btn) {
    btn.disabled = true;
    btn.textContent = 'Processing Dual Signoff...';
  }
  try {
    const r1 = await fetch(`/api/quarantine/${currentQuarantineId}/stage-override`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        requester_id: 'secops-analyst-1',
        rationale: 'Emergency four-eyes authorization: fast-track demo override.'
      })
    });
    if (!r1.ok) {
      const err1 = await r1.json();
      alert('Failed to stage Key 1: ' + (err1.detail || r1.statusText));
      return;
    }
    const r2 = await fetch(`/api/quarantine/${currentQuarantineId}/approve-override`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        approver_id: 'ciso-officer-2',
        notes: 'Cryptographic Ed25519 DSSE emergency ticket minted; replayed through :18082.'
      })
    });
    const d2 = await r2.json();
    if (!r2.ok) {
      alert('Failed Key 2 signoff: ' + (d2.detail || r2.statusText));
      return;
    }
    await openTriageModal(currentQuarantineId);
    refreshQuarantine();
  } catch (err) {
    alert('Dual signoff error: ' + err.message);
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.textContent = '⚡ 1-Click Dual Signoff & Replay (Demo)';
    }
  }
}

function quickFillDemoK1() {
  const k1Op = document.getElementById('k1-operator');
  const k1Rat = document.getElementById('k1-rationale');
  if (k1Op && !k1Op.disabled) {
    k1Op.value = 'secops-analyst-1';
    k1Rat.value = 'Operational triage test: mission-critical incident justification.';
  }
}

function quickFillDemoK2() {
  const k2Op = document.getElementById('k2-operator');
  const k2Notes = document.getElementById('k2-notes');
  if (k2Op && !k2Op.disabled) {
    k2Op.value = 'ciso-officer-2';
    k2Notes.value = 'Four-eyes verification confirmed: authorized emergency DSSE ticket emit.';
  }
}

function closeTriageModal() {
  document.getElementById('triage-modal').classList.add('hidden');
}

async function submitKey1() {
  const op = document.getElementById('k1-operator').value.trim();
  const rat = document.getElementById('k1-rationale').value.trim();
  if (!op || !rat) {
    alert('Please enter both Requester ID and business rationale.');
    return;
  }
  const res = await fetch(`/api/quarantine/${currentQuarantineId}/stage-override`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ requester_id: op, rationale: rat })
  });
  if (!res.ok) {
    const err = await res.json();
    alert('Error staging Key 1: ' + (err.detail || res.statusText));
    return;
  }
  await openTriageModal(currentQuarantineId);
  refreshQuarantine();
}

async function submitKey2() {
  const op = document.getElementById('k2-operator').value.trim();
  const notes = document.getElementById('k2-notes').value.trim();
  if (!op) {
    alert('Please enter Approver ID.');
    return;
  }
  const res = await fetch(`/api/quarantine/${currentQuarantineId}/approve-override`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ approver_id: op, notes: notes })
  });
  const data = await res.json();
  if (!res.ok) {
    alert('Dual-Key Approval Failed: ' + (data.detail || res.statusText));
    return;
  }
  alert(`Emergency Admission Granted! DSSE Ticket Minted.\nWORM Hash: ${data.worm_hash.substring(0, 16)}...`);
  await openTriageModal(currentQuarantineId);
  refreshQuarantine();
}

async function rejectCurrentItem() {
  const reason = prompt('Enter rejection reason:');
  if (!reason) return;
  const res = await fetch(`/api/quarantine/${currentQuarantineId}/reject`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ reviewer_id: 'secops-lead', reason: reason })
  });
  if (res.ok) {
    closeTriageModal();
    refreshQuarantine();
  }
}

async function verifyWORM() {
  const banner = document.getElementById('worm-verify-banner');
  banner.className = 'border rounded p-4 text-xs font-mono-tabular bg-[#F8FAFC] text-[#0F172A] block';
  banner.textContent = 'Auditing Merkle hash-chain from genesis block to tip...';

  const res = await fetch('/api/worm/verify');
  const data = await res.json();

  if (data.valid) {
    banner.className = 'border border-[#BBF7D0] rounded p-4 text-xs font-mono-tabular bg-[#F0FDF4] text-[#166534] block';
    banner.innerHTML = `
      <div class="font-bold uppercase tracking-wide">Cryptographic Chain Valid (100% Intact)</div>
      <div class="mt-1">Records Validated: <strong>${data.total_entries}</strong> | Genesis: <code>${data.genesis_hash.substring(0, 16)}...</code> | Tip: <code>${data.tip_hash.substring(0, 16)}...</code></div>
      <div class="mt-1 text-[11px]">${data.message}</div>
    `;
  } else {
    banner.className = 'border border-[#FECACA] rounded p-4 text-xs font-mono-tabular bg-[#FEF2F2] text-[#991B1B] block';
    banner.innerHTML = `
      <div class="font-bold uppercase tracking-wide">WORM Chain Tamper Detected!</div>
      <div class="mt-1">Error: <strong>${data.error_type}</strong> on line <strong>${data.line_number}</strong></div>
      <div class="mt-1">${data.message}</div>
    `;
  }
}

async function testSIEM(destId) {
  const resElem = document.getElementById('siem-ping-result-' + destId);
  if (resElem) {
    resElem.textContent = 'Pinging...';
    resElem.className = 'text-[11px] font-mono-tabular text-[#475569]';
  }
  try {
    const res = await fetch(`/api/siem/${destId}/test`, { method: 'POST' });
    const data = await res.json();
    if (resElem) {
      if (data.success) {
        resElem.textContent = 'Delivered (200 OK)';
        resElem.className = 'text-[11px] font-mono-tabular text-[#166534] font-bold';
      } else {
        resElem.textContent = 'Buffered: ' + (data.error || 'offline');
        resElem.className = 'text-[11px] font-mono-tabular text-[#991B1B]';
      }
    }
    refreshSIEM();
  } catch (err) {
    if (resElem) {
      resElem.textContent = 'Failed: ' + err.message;
      resElem.className = 'text-[11px] font-mono-tabular text-[#991B1B]';
    }
  }
}

function togglePasswordVisibility(fieldId) {
  const input = document.getElementById(fieldId);
  if (input.type === 'password') {
    input.type = 'text';
  } else {
    input.type = 'password';
  }
}

async function openConfigModal(destId) {
  currentConfigDestId = destId;
  const banner = document.getElementById('cfg-save-banner');
  banner.className = 'hidden';
  banner.textContent = '';

  try {
    const res = await fetch(`/api/siem/${destId}/config`);
    if (!res.ok) throw new Error('Failed to load configuration');
    const data = await res.json();

    document.getElementById('cfg-dest-name').textContent = data.name;
    document.getElementById('cfg-dest-type').textContent = data.type;
    document.getElementById('cfg-enabled').checked = !!data.enabled;

    // Show/hide syslog vs http fields
    const isSyslog = data.type === 'syslog';
    document.getElementById('cfg-syslog-fields').classList.toggle('hidden', !isSyslog);
    document.getElementById('cfg-http-fields').classList.toggle('hidden', isSyslog);

    if (isSyslog) {
      document.getElementById('cfg-syslog-host').value = data.syslog_host || '';
      document.getElementById('cfg-syslog-port').value = data.syslog_port || 514;
      document.getElementById('cfg-syslog-tls').checked = !!data.syslog_use_tls;
    } else {
      document.getElementById('cfg-endpoint-url').value = data.endpoint_url || '';
      document.getElementById('cfg-api-key').value = data.api_key || '';
      document.getElementById('cfg-auth-header').value = data.auth_header || '';
      document.getElementById('cfg-index-sourcetype').value = data.index_or_sourcetype || '';
      document.getElementById('cfg-workspace-loggroup').value = data.workspace_id || data.log_group_name || '';
    }

    document.getElementById('siem-config-modal').classList.remove('hidden');
  } catch (err) {
    alert('Failed to load destination config: ' + err.message);
  }
}

function closeConfigModal() {
  document.getElementById('siem-config-modal').classList.add('hidden');
}

async function saveConfigModal() {
  if (!currentConfigDestId) return;

  const isSyslog = !document.getElementById('cfg-syslog-fields').classList.contains('hidden');
  const banner = document.getElementById('cfg-save-banner');
  banner.className = 'border rounded p-3 font-mono-tabular text-xs bg-[#F8FAFC] text-[#0F172A] block';
  banner.textContent = 'Saving configuration live to memory and config.yaml...';

  const payload = {
    enabled: document.getElementById('cfg-enabled').checked,
    endpoint_url: document.getElementById('cfg-endpoint-url').value.trim(),
    api_key: document.getElementById('cfg-api-key').value.trim() || null,
    auth_header: document.getElementById('cfg-auth-header').value.trim() || null,
    index_or_sourcetype: document.getElementById('cfg-index-sourcetype').value.trim() || null,
    workspace_id: document.getElementById('cfg-workspace-loggroup').value.trim() || null,
    log_group_name: document.getElementById('cfg-workspace-loggroup').value.trim() || null,
    syslog_host: document.getElementById('cfg-syslog-host').value.trim() || null,
    syslog_port: parseInt(document.getElementById('cfg-syslog-port').value, 10) || null,
    syslog_use_tls: document.getElementById('cfg-syslog-tls').checked
  };

  try {
    const res = await fetch(`/api/siem/${currentConfigDestId}/config`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || res.statusText);

    banner.className = 'border border-[#BBF7D0] rounded p-3 font-mono-tabular text-xs bg-[#F0FDF4] text-[#166534] block';
    banner.textContent = 'Configuration updated and applied live! (Saved to config.yaml)';

    const epElem = document.getElementById(`endpoint-siem-${currentConfigDestId}`);
    if (epElem) {
      epElem.textContent = isSyslog 
        ? `Endpoint: ${payload.syslog_host}:${payload.syslog_port}` 
        : `Endpoint: ${payload.endpoint_url}`;
      epElem.title = epElem.textContent;
    }

    refreshSIEM();
  } catch (err) {
    banner.className = 'border border-[#FECACA] rounded p-3 font-mono-tabular text-xs bg-[#FEF2F2] text-[#991B1B] block';
    banner.textContent = 'Error saving config: ' + err.message;
  }
}

async function testConfigModalPing() {
  if (!currentConfigDestId) return;
  const banner = document.getElementById('cfg-save-banner');
  banner.className = 'border rounded p-3 font-mono-tabular text-xs bg-[#F8FAFC] text-[#0F172A] block';
  banner.textContent = 'Sending real-time probe to destination...';

  try {
    const res = await fetch(`/api/siem/${currentConfigDestId}/test`, { method: 'POST' });
    const data = await res.json();
    if (data.success) {
      banner.className = 'border border-[#BBF7D0] rounded p-3 font-mono-tabular text-xs bg-[#F0FDF4] text-[#166534] block';
      banner.textContent = `Ping Succeeded: ${data.message}`;
    } else {
      banner.className = 'border border-[#FECACA] rounded p-3 font-mono-tabular text-xs bg-[#FEF2F2] text-[#991B1B] block';
      banner.textContent = `Ping Failed: ${data.error || data.message}`;
    }
    const resElem = document.getElementById('siem-ping-result-' + currentConfigDestId);
    if (resElem) {
      resElem.textContent = data.success ? 'Delivered (200 OK)' : 'Buffered: ' + (data.error || 'offline');
      resElem.className = data.success ? 'text-[11px] font-mono-tabular text-[#166534] font-bold' : 'text-[11px] font-mono-tabular text-[#991B1B]';
    }
  } catch (err) {
    banner.className = 'border border-[#FECACA] rounded p-3 font-mono-tabular text-xs bg-[#FEF2F2] text-[#991B1B] block';
    banner.textContent = 'Network probe error: ' + err.message;
  }
}

async function toggleMockReceivers() {
  try {
    const res = await fetch('/api/siem/mock-receivers/toggle', { method: 'POST' });
    const data = await res.json();
    updateMockUI(data.running);
  } catch (err) {
    alert('Failed to toggle mock sinks: ' + err.message);
  }
}

function updateMockUI(isRunning) {
  const dot = document.getElementById('mock-status-dot');
  const txt = document.getElementById('mock-status-text');
  if (isRunning) {
    dot.className = 'w-2.5 h-2.5 rounded-full bg-[#16A34A] inline-block';
    txt.textContent = 'Local Mock Sinks: Active';
  } else {
    dot.className = 'w-2.5 h-2.5 rounded-full bg-[#94A3B8] inline-block';
    txt.textContent = 'Local Mock Sinks: Stopped';
  }
}

async function checkMockReceiversStatus() {
  try {
    const res = await fetch('/api/siem/mock-receivers');
    const data = await res.json();
    updateMockUI(data.running);
  } catch (e) {
    // ignore
  }
}

async function refreshSIEM() {
  try {
    const res = await fetch('/api/siem/status');
    const list = await res.json();
    list.forEach(d => {
      const qElem = document.getElementById(`queue-siem-${d.id}`);
      const delElem = document.getElementById(`delivered-siem-${d.id}`);
      const bElem = document.getElementById(`badge-siem-${d.id}`);
      if (qElem) qElem.textContent = d.pending_queue_count;
      if (delElem) delElem.textContent = d.delivered_count;
      if (bElem) {
        if (d.health === 'HEALTHY') {
          bElem.className = 'badge badge-success';
          bElem.textContent = 'HEALTHY';
        } else if (d.health === 'DEGRADED') {
          bElem.className = 'badge badge-danger';
          bElem.textContent = 'DEGRADED';
        } else {
          bElem.className = 'badge badge-neutral';
          bElem.textContent = 'STANDBY';
        }
      }
    });
  } catch (e) {
    // ignore
  }
}

function clearLiveLog() {
  document.getElementById('live-event-container').innerHTML = '<div class="text-[#475569]">// Log cleared. Waiting for events...</div>';
}

// Live SSE Stream Listener
const evtSource = new EventSource('/events/stream');
evtSource.onmessage = function(e) {
  const data = JSON.parse(e.data);
  const container = document.getElementById('live-event-container');
  const row = document.createElement('div');
  row.className = 'border-b border-[#E2E8F0] py-1.5 flex items-start gap-2 text-xs font-mono-tabular';

  const timeStr = new Date().toISOString().substring(11, 19);
  let badgeClass = 'text-[#16A34A] font-bold';
  if (data.event_type === 'DOCKET_DENIAL' || data.event_type === 'COMBINE_THREAT_BLOCKED') {
    badgeClass = 'text-[#DC2626] font-bold';
  } else if (data.event_type === 'COMBINE_PII_REDACTED') {
    badgeClass = 'text-[#D97706] font-bold';
  } else if (data.event_type === 'CONNECTED') {
    badgeClass = 'text-[#2563EB] font-bold';
  }

  let detail = '';
  if (data.reason_code) {
    detail = `[${data.reason_code}] loc: ${data.locator_uri || 'urn:prompt'} | tier: ${data.claimed_tier || 'n/a'}`;
    if (data.quarantine_id) {
      detail += ` | Quarantine: ${data.quarantine_id}`;
    }
  } else if (data.message) {
    detail = data.message;
  } else {
    detail = JSON.stringify(data);
  }

  row.innerHTML = `<span class="text-[#64748B]">[${timeStr}]</span> <span class="${badgeClass}">${data.event_type}</span> <span class="text-[#0F172A]">${detail}</span>`;
  container.prepend(row);

  // Dynamically increment stats counters
  if (data.event_type !== 'CONNECTED') {
    const wormCountElem = document.getElementById('stat-worm-count');
    if (wormCountElem) {
      wormCountElem.textContent = parseInt(wormCountElem.textContent || '0', 10) + 1;
    }
    if (data.quarantine_id) {
      const qCountElem = document.getElementById('stat-quarantined');
      if (qCountElem) {
        qCountElem.textContent = parseInt(qCountElem.textContent || '0', 10) + 1;
      }
      refreshQuarantine();
    }
  }
};

window.addEventListener('DOMContentLoaded', () => {
  checkMockReceiversStatus();
});
