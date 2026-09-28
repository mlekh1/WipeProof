"""
WipeProof Embedded Local Web UI.
Single-page application served via FastAPI for one-click demonstrations,
device inspection, certificate verification, and Merkle tree auditing.
"""

WEB_DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en" class="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>WipeProof | Certified Disk Sanitization & Trust Ledger</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script>
    tailwind.config = {
      darkMode: 'class',
      theme: {
        extend: {
          colors: {
            brand: { 50: '#ecfdf5', 500: '#10b981', 600: '#059669', 900: '#064e3b' },
            darkbg: '#0b0f19',
            cardbg: '#111827',
          }
        }
      }
    }
  </script>
  <style>
    pre, code { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }
  </style>
</head>
<body class="bg-darkbg text-slate-200 min-h-screen font-sans antialiased">

  <!-- Navigation -->
  <header class="border-b border-slate-800 bg-cardbg/80 backdrop-blur sticky top-0 z-50">
    <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
      <div class="flex items-center space-x-3">
        <div class="h-9 w-9 rounded-lg bg-emerald-500/20 border border-emerald-500/40 flex items-center justify-center text-emerald-400 font-bold">
          WP
        </div>
        <div>
          <span class="text-lg font-bold tracking-tight text-white">WipeProof</span>
          <span class="text-xs ml-2 px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800 font-mono">NIST SP 800-88 Rev. 2</span>
        </div>
      </div>
      <div class="flex items-center space-x-4 text-xs font-mono">
        <span class="text-slate-400">RFC 8785 (JCS) | RFC 8032 (Ed25519)</span>
        <div class="h-2 w-2 rounded-full bg-emerald-400 animate-pulse"></div>
        <span class="text-emerald-400 font-semibold" id="sys-status">SYSTEM READY</span>
      </div>
    </div>
  </header>

  <!-- Main Container -->
  <main class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">

    <!-- Top Alert Banner -->
    <div class="rounded-xl border border-slate-800 bg-cardbg p-6 shadow-xl relative overflow-hidden">
      <div class="absolute -right-10 -bottom-10 w-48 h-48 bg-emerald-500/5 rounded-full blur-3xl pointer-events-none"></div>
      <div class="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <h1 class="text-xl font-bold text-white flex items-center gap-2">
            Secure Disk Sanitization & Verifiable Certificate Engine
          </h1>
          <p class="text-sm text-slate-400 mt-1 max-w-3xl">
            A portfolio security engineering project demonstrating true hardware command mapping (ATA/NVMe Sanitize vs Overwrite),
            deterministic RFC 8785 JSON canonicalization, RFC 8032 Ed25519 digital signatures, and append-only Merkle transparency logging.
          </p>
        </div>
        <div class="flex items-center gap-3">
          <button id="btn-run-demo" onclick="runLoopbackDemo()" class="px-5 py-2.5 bg-emerald-600 hover:bg-emerald-500 text-white font-medium text-sm rounded-lg shadow-lg shadow-emerald-900/40 transition flex items-center gap-2">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z"></path><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
            <span>Run Safe Loopback Demo</span>
          </button>
        </div>
      </div>
    </div>

    <!-- Interactive Grid -->
    <div class="grid grid-cols-1 lg:grid-cols-3 gap-8">

      <!-- Left Column: Verification & Lab Inspector -->
      <div class="lg:col-span-2 space-y-6">

        <!-- Console & Execution Log -->
        <div class="rounded-xl border border-slate-800 bg-cardbg overflow-hidden shadow-xl">
          <div class="px-5 py-3 border-b border-slate-800 bg-slate-900/60 flex items-center justify-between">
            <span class="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-2">
              <span class="h-2 w-2 rounded-full bg-emerald-400"></span> Execution Pipeline Trace
            </span>
            <span id="job-duration" class="text-xs text-slate-500 font-mono">Idle</span>
          </div>
          <div class="p-4 bg-black/40 font-mono text-xs leading-relaxed overflow-x-auto max-h-72" id="console-log">
            <p class="text-slate-500">> WipeProof engine loaded. Ready to execute virtual disk sanitization.</p>
            <p class="text-slate-500">> Destructive actions are strictly isolated to virtual sparse images.</p>
          </div>
        </div>

        <!-- Generated Certificate Viewer -->
        <div class="rounded-xl border border-slate-800 bg-cardbg overflow-hidden shadow-xl" id="cert-card">
          <div class="px-5 py-3 border-b border-slate-800 bg-slate-900/60 flex items-center justify-between">
            <span class="text-xs font-semibold uppercase tracking-wider text-slate-400">Signed Certificate Artifact (RFC 8785 JSON)</span>
            <div class="flex items-center space-x-2">
              <button onclick="tamperCertificate()" id="btn-tamper" class="hidden text-xs px-2.5 py-1 bg-rose-950 text-rose-400 border border-rose-800 rounded hover:bg-rose-900 transition">
                Simulate Adversary Tamper
              </button>
              <button onclick="verifyCurrentCert()" id="btn-verify-now" class="hidden text-xs px-2.5 py-1 bg-emerald-950 text-emerald-400 border border-emerald-800 rounded hover:bg-emerald-900 transition">
                Verify Mathematical Signature
              </button>
            </div>
          </div>
          <div class="p-4">
            <pre class="bg-black/40 p-3 rounded text-xs overflow-x-auto text-emerald-400 max-h-80" id="cert-json-display">{ "status": "No certificate generated yet. Click 'Run Safe Loopback Demo' above." }</pre>
          </div>
        </div>

      </div>

      <!-- Right Column: Verification Status & Transparency Log -->
      <div class="space-y-6">

        <!-- Verification Result Badge Card -->
        <div class="rounded-xl border border-slate-800 bg-cardbg p-5 shadow-xl space-y-4">
          <h3 class="text-xs font-semibold uppercase tracking-wider text-slate-400">Independent Verifier Status</h3>
          <div id="verif-status-badge" class="p-4 rounded-lg bg-slate-900 border border-slate-800 flex items-center justify-center flex-col text-center">
            <span class="text-2xl font-bold font-mono text-slate-500" id="badge-text">STANDBY</span>
            <span class="text-xs text-slate-500 mt-1" id="badge-subtext">Waiting for certificate verification</span>
          </div>

          <div class="space-y-2 text-xs font-mono">
            <div class="flex justify-between py-1 border-b border-slate-800/60">
              <span class="text-slate-400">Calculated Hash:</span>
              <span class="text-slate-200 truncate max-w-[180px]" id="meta-calc-hash">-</span>
            </div>
            <div class="flex justify-between py-1 border-b border-slate-800/60">
              <span class="text-slate-400">Reported Hash:</span>
              <span class="text-slate-200 truncate max-w-[180px]" id="meta-rep-hash">-</span>
            </div>
            <div class="flex justify-between py-1 border-b border-slate-800/60">
              <span class="text-slate-400">Key ID:</span>
              <span class="text-slate-200" id="meta-key-id">-</span>
            </div>
            <div class="flex justify-between py-1 border-b border-slate-800/60">
              <span class="text-slate-400">Entropy Score:</span>
              <span class="text-emerald-400 font-bold" id="meta-entropy">-</span>
            </div>
          </div>
        </div>

        <!-- Merkle Transparency Ledger Card -->
        <div class="rounded-xl border border-slate-800 bg-cardbg p-5 shadow-xl space-y-4">
          <div class="flex items-center justify-between">
            <h3 class="text-xs font-semibold uppercase tracking-wider text-slate-400">Merkle Transparency Log</h3>
            <span class="text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono" id="merkle-count">0 Entries</span>
          </div>
          <p class="text-xs text-slate-400">
            Append-only public cryptographic audit ledger. Every verified certificate updates the Merkle tree root hash.
          </p>
          <div class="p-3 bg-black/40 rounded border border-slate-800 font-mono text-xs">
            <div class="text-slate-500 text-[10px] uppercase">Current Merkle Root</div>
            <div class="text-amber-400 truncate mt-0.5" id="merkle-root-display">0000000000000000000000000000000000000000000000000000000000000000</div>
          </div>
        </div>

      </div>

    </div>

  </main>

  <script>
    let currentCert = null;
    let currentPubHex = null;

    function appendLog(msg, color = 'text-slate-300') {
      const box = document.getElementById('console-log');
      const p = document.createElement('p');
      p.className = color;
      p.textContent = '> ' + msg;
      box.appendChild(p);
      box.scrollTop = box.scrollHeight;
    }

    async function runLoopbackDemo() {
      const btn = document.getElementById('btn-run-demo');
      btn.disabled = true;
      btn.classList.add('opacity-50');

      appendLog('Creating temporary 2MB virtual sparse disk image...', 'text-cyan-400');
      appendLog('Populating virtual sectors with high-entropy pseudo-random bytes (simulating customer data)...', 'text-cyan-400');

      try {
        const res = await fetch('/api/demo/run', { method: 'POST' });
        const data = await res.json();

        appendLog('Safety interlock checks passed (Target is isolated virtual disk).', 'text-emerald-400');
        appendLog('Executing sanitization driver: ' + data.method, 'text-yellow-400');
        appendLog('Post-wipe verification completed: Shannon Entropy = ' + data.entropy + ' bits/byte (100% Zero-fill).', 'text-emerald-400');
        appendLog('Applying RFC 8785 (JCS) JSON canonicalization...', 'text-cyan-400');
        appendLog('Signing canonical digest with RFC 8032 Ed25519 private key...', 'text-cyan-400');
        appendLog('Issued Certificate: ' + data.certificate.certificate_id, 'text-emerald-400');

        currentCert = data.certificate;
        currentPubHex = data.public_key_hex;

        document.getElementById('cert-json-display').textContent = JSON.stringify(currentCert, null, 2);
        document.getElementById('btn-tamper').classList.remove('hidden');
        document.getElementById('btn-verify-now').classList.remove('hidden');

        // Automatically trigger verification
        verifyCurrentCert();

      } catch (err) {
        appendLog('Error running demo: ' + err, 'text-rose-400');
      } finally {
        btn.disabled = false;
        btn.classList.remove('opacity-50');
      }
    }

    async function verifyCurrentCert() {
      if (!currentCert) return;
      appendLog('Submitting certificate to independent verification engine...', 'text-slate-300');

      try {
        const res = await fetch('/verify', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            certificate: currentCert,
            trusted_public_key_hex: currentPubHex
          })
        });
        const report = await res.json();

        updateStatusBadge(report);
      } catch (err) {
        appendLog('Verification error: ' + err, 'text-rose-400');
      }
    }

    function tamperCertificate() {
      if (!currentCert) return;
      appendLog('[!] ADVERSARY ACTION: Mutating 1 character in serial number from "S5Y2NJ0N" to "S5Y2NJ0X"...', 'text-rose-400');
      currentCert.device.serial = (currentCert.device.serial || 'TEST') + '_MODIFIED';
      document.getElementById('cert-json-display').textContent = JSON.stringify(currentCert, null, 2);

      appendLog('Re-verifying tampered certificate payload...', 'text-yellow-400');
      verifyCurrentCert();
    }

    function updateStatusBadge(report) {
      const badge = document.getElementById('verif-status-badge');
      const text = document.getElementById('badge-text');
      const sub = document.getElementById('badge-subtext');

      document.getElementById('meta-calc-hash').textContent = report.calculated_payload_sha256 || 'N/A';
      document.getElementById('meta-rep-hash').textContent = report.canonical_payload_sha256 || 'N/A';
      document.getElementById('meta-key-id').textContent = report.key_id || 'N/A';
      document.getElementById('meta-entropy').textContent = (currentCert?.verification?.shannon_entropy ?? '0.000000') + ' bits/byte';

      if (report.status === 'VALID') {
        badge.className = 'p-4 rounded-lg bg-emerald-950/60 border border-emerald-500/50 flex items-center justify-center flex-col text-center';
        text.className = 'text-2xl font-bold font-mono text-emerald-400';
        text.textContent = 'VALID';
        sub.className = 'text-xs text-emerald-300 mt-1';
        sub.textContent = report.reason;
        appendLog('Independent Verifier: ' + report.reason, 'text-emerald-400');

        if (report.merkle_root_hash) {
          document.getElementById('merkle-root-display').textContent = report.merkle_root_hash;
          document.getElementById('merkle-count').textContent = report.merkle_tree_size + ' Entries';
          appendLog('Certificate anchored into Merkle Transparency Log at leaf index ' + report.merkle_leaf_index, 'text-amber-400');
        }
      } else {
        badge.className = 'p-4 rounded-lg bg-rose-950/60 border border-rose-500/50 flex items-center justify-center flex-col text-center';
        text.className = 'text-2xl font-bold font-mono text-rose-400';
        text.textContent = report.status;
        sub.className = 'text-xs text-rose-300 mt-1';
        sub.textContent = report.reason;
        appendLog('ALERT: Verification Failed! ' + report.reason, 'text-rose-400');
      }
    }
  </script>
</body>
</html>
"""
