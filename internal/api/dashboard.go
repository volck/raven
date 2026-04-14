package api

import (
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"strings"
	"time"

	"github.com/volck/raven/internal/config"
	"github.com/volck/raven/internal/gitops"
)

type dashboardData struct {
	Engine       string
	DestEnv      string
	VaultURL     string
	Secrets      []secretInfo
	Events       []SyncEvent
	GeneratedAt  string
	SecretCount  int
	LastSync     string
	NextSync     string
	NextSyncISO  string
	SyncInterval string
	SyncOverdue  bool
}

type secretInfo struct {
	Name       string
	SecretName string
	Modified   string
}

var dashboardTmpl = template.Must(template.New("dashboard").Funcs(template.FuncMap{
	"inc": func(i int) int { return i + 1 },
}).Parse(dashboardHTML))

// DashboardHandler returns an HTTP handler that renders the Raven dashboard.
func DashboardHandler(cfg config.Config, events *SecretEventHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}

		var secrets []secretInfo
		files, err := gitops.GetBaseListOfFiles(cfg)
		if err == nil {
			secrets = filesToSecretInfo(files)
		}

		syncStatus := events.GetSyncStatus()
		var lastSync, nextSync, nextSyncISO, syncInterval string
		var syncOverdue bool
		if !syncStatus.LastSync.IsZero() {
			lastSync = syncStatus.LastSync.Format("2006-01-02 15:04:05 MST")
			nextSync = syncStatus.NextSync.Format("15:04:05 MST")
			nextSyncISO = syncStatus.NextSync.UTC().Format(time.RFC3339)
			syncInterval = fmt.Sprintf("%dm", syncStatus.SleepSeconds/60)
			syncOverdue = time.Now().After(syncStatus.NextSync)
		} else {
			lastSync = "not yet"
			nextSync = "pending"
			syncInterval = "—"
		}

		data := dashboardData{
			Engine:       cfg.SecretEngine,
			DestEnv:      cfg.DestEnv,
			VaultURL:     cfg.VaultEndpoint,
			Secrets:      secrets,
			Events:       events.RecentEvents(),
			GeneratedAt:  time.Now().Format("2006-01-02 15:04:05 MST"),
			SecretCount:  len(secrets),
			LastSync:     lastSync,
			NextSync:     nextSync,
			NextSyncISO:  nextSyncISO,
			SyncInterval: syncInterval,
			SyncOverdue:  syncOverdue,
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := dashboardTmpl.Execute(w, data); err != nil {
			jsonLogger.Error("dashboard template error", "error", err)
		}
	}
}

func filesToSecretInfo(files []fs.FileInfo) []secretInfo {
	out := make([]secretInfo, 0, len(files))
	for _, f := range files {
		name := f.Name()
		secretName := strings.TrimSuffix(name, ".yaml")
		out = append(out, secretInfo{
			Name:       name,
			SecretName: secretName,
			Modified:   f.ModTime().Format("2006-01-02 15:04:05"),
		})
	}
	return out
}

const dashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Raven Dashboard</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0d1117; color: #c9d1d9; padding: 24px; max-width: 1200px; margin: 0 auto; }
  h1 { color: #58a6ff; margin-bottom: 4px; font-size: 1.8em; }
  .subtitle { color: #8b949e; margin-bottom: 24px; font-size: 0.95em; }
  .cards { display: flex; gap: 16px; margin-bottom: 24px; flex-wrap: wrap; }
  .card { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 16px 20px; min-width: 180px; }
  .card .label { color: #8b949e; font-size: 0.8em; text-transform: uppercase; letter-spacing: 0.05em; }
  .card .value { color: #f0f6fc; font-size: 1.4em; font-weight: 600; margin-top: 4px; }
  .info-bar { display: flex; gap: 6px; margin-bottom: 12px; flex-wrap: wrap; align-items: center; }
  .info-pill { display: inline-flex; align-items: center; gap: 4px; background: #161b22; border: 1px solid #30363d; border-radius: 12px; padding: 2px 10px; font-size: 0.72em; }
  .info-pill .pill-label { color: #8b949e; }
  .info-pill .pill-value { color: #f0f6fc; font-weight: 600; }
  .info-pill .pill-value.overdue { color: #f85149; }
  h2 { color: #c9d1d9; font-size: 1.2em; margin-bottom: 12px; }
  table { width: 100%; border-collapse: collapse; background: #161b22; border: 1px solid #30363d; border-radius: 6px; overflow: hidden; margin-bottom: 32px; }
  th { background: #21262d; color: #8b949e; font-weight: 600; font-size: 0.8em; text-transform: uppercase; letter-spacing: 0.04em; text-align: left; padding: 10px 14px; }
  td { padding: 10px 14px; border-top: 1px solid #21262d; font-size: 0.9em; }
  tr:hover td { background: #1c2129; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 0.75em; font-weight: 600; }
  .badge-ok { background: #238636; color: #fff; }
  .badge-error { background: #da3633; color: #fff; }
  .badge-skipped { background: #d29922; color: #000; }
  .badge-create { background: #1f6feb; color: #fff; }
  .badge-update { background: #8957e5; color: #fff; }
  .badge-delete { background: #da3633; color: #fff; }
  .badge-k8s-added { background: #0d419d; color: #58a6ff; border: 1px solid #1f6feb; }
  .badge-k8s-modified { background: #341a5e; color: #d2a8ff; border: 1px solid #8957e5; }
  .badge-k8s-deleted { background: #490202; color: #f85149; border: 1px solid #da3633; }
  .badge-k8s-rollout { background: #0c2d14; color: #3fb950; border: 1px solid #238636; }
  .empty { color: #484f58; text-align: center; padding: 24px; }
  .footer { color: #484f58; font-size: 0.8em; margin-top: 16px; }
  .sync-row { display: flex; gap: 16px; margin-bottom: 24px; flex-wrap: wrap; }
  .sync-card { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 12px 16px; min-width: 200px; }
  .sync-card .label { color: #8b949e; font-size: 0.75em; text-transform: uppercase; letter-spacing: 0.05em; }
  .sync-card .value { color: #f0f6fc; font-size: 1.1em; font-weight: 500; margin-top: 2px; }
  .sync-card .value.overdue { color: #f85149; }
  .btn-refresh { background: linear-gradient(135deg, #1f6feb 0%, #388bfd 100%); color: #fff; border: none; border-radius: 8px; padding: 6px 16px; cursor: pointer; font-size: 0.8em; font-weight: 600; letter-spacing: 0.03em; transition: all 0.25s cubic-bezier(.4,0,.2,1); box-shadow: 0 2px 8px rgba(31,111,235,0.35); }
  .btn-refresh:hover { background: linear-gradient(135deg, #388bfd 0%, #58a6ff 100%); box-shadow: 0 4px 16px rgba(56,139,253,0.4); transform: translateY(-1px); }
  .btn-refresh:active { transform: translateY(0); box-shadow: 0 1px 4px rgba(31,111,235,0.3); }
  .btn-refresh:disabled { opacity: 0.4; cursor: not-allowed; transform: none; box-shadow: none; }
  .btn-refresh.success { background: linear-gradient(135deg, #238636 0%, #2ea043 100%); box-shadow: 0 2px 8px rgba(46,160,67,0.3); }
  .btn-refresh.error { background: linear-gradient(135deg, #da3633 0%, #f85149 100%); box-shadow: 0 2px 8px rgba(248,81,73,0.3); }
  .toast { position: fixed; bottom: 24px; right: 24px; background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 12px 20px; color: #c9d1d9; font-size: 0.9em; display: none; z-index: 100; max-width: 400px; border-left: 4px solid #30363d; }
  .toast.show { display: block; }
  .toast.toast-ok { border-left-color: #238636; }
  .toast.toast-error { border-left-color: #da3633; }
  .search-bar { display: flex; align-items: center; gap: 12px; margin-bottom: 12px; flex-wrap: wrap; }
  .search-bar input { background: #0d1117; border: 1px solid #30363d; border-radius: 6px; color: #c9d1d9; padding: 8px 12px; font-size: 0.9em; width: 300px; outline: none; }
  .search-bar input:focus { border-color: #58a6ff; }
  .search-bar .count { color: #8b949e; font-size: 0.85em; }
  .page-controls { display: flex; align-items: center; gap: 8px; margin-top: 8px; margin-bottom: 24px; }
  .page-controls button { background: linear-gradient(135deg, #21262d 0%, #2d333b 100%); color: #c9d1d9; border: 1px solid #444c56; border-radius: 8px; padding: 6px 14px; cursor: pointer; font-size: 0.8em; font-weight: 500; transition: all 0.25s cubic-bezier(.4,0,.2,1); box-shadow: 0 1px 3px rgba(0,0,0,0.2); }
  .page-controls button:hover { background: linear-gradient(135deg, #2d333b 0%, #3d444d 100%); border-color: #58a6ff; color: #f0f6fc; transform: translateY(-1px); box-shadow: 0 2px 6px rgba(88,166,255,0.12); }
  .page-controls button:active { transform: translateY(0); }
  .page-controls button:disabled { opacity: 0.35; cursor: not-allowed; transform: none; box-shadow: none; }
  .page-controls span { color: #8b949e; font-size: 0.85em; }
  .tabs { display: flex; gap: 0; border-bottom: 1px solid #30363d; margin-bottom: 20px; }
  .tab { padding: 10px 20px; cursor: pointer; color: #8b949e; font-size: 0.95em; font-weight: 500; border-bottom: 2px solid transparent; transition: color 0.15s, border-color 0.15s; }
  .tab:hover { color: #c9d1d9; }
  .tab.active { color: #58a6ff; border-bottom-color: #58a6ff; }
  .tab-badge { background: #30363d; color: #c9d1d9; font-size: 0.75em; padding: 1px 7px; border-radius: 10px; margin-left: 6px; }
  .tab-panel { display: none; }
  .tab-panel.active { display: block; }
  .collapsible-header { display: flex; align-items: center; cursor: pointer; user-select: none; gap: 8px; margin-bottom: 12px; }
  .collapsible-header h2 { margin-bottom: 0; }
  .collapse-icon { color: #8b949e; font-size: 0.8em; transition: transform 0.2s; display: inline-block; }
  .collapse-icon.collapsed { transform: rotate(-90deg); }
  .collapsible-body { overflow: hidden; transition: max-height 0.3s ease; }
  .collapsible-body.collapsed { max-height: 0 !important; overflow: hidden; }
  .manual-refresh { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px 20px; margin-bottom: 20px; overflow: visible; }
  .manual-refresh-title { color: #58a6ff; font-size: 0.85em; font-weight: 600; text-transform: uppercase; letter-spacing: 0.04em; margin-bottom: 10px; display: flex; align-items: center; gap: 6px; }
  .manual-refresh-row { display: flex; gap: 8px; align-items: flex-start; }
  .ac-wrap { position: relative; width: 320px; }
  .manual-refresh input { background: #0d1117; border: 1px solid #30363d; border-radius: 6px; color: #c9d1d9; padding: 8px 12px; font-size: 0.9em; width: 100%; outline: none; }
  .manual-refresh input:focus { border-color: #58a6ff; box-shadow: 0 0 0 2px rgba(88,166,255,0.15); }
  .ac-dropdown { position: absolute; top: 100%; left: 0; width: 100%; max-height: 200px; overflow-y: auto; background: #1c2129; border: 1px solid #30363d; border-radius: 6px; margin-top: 4px; z-index: 999; display: none; }
  .ac-dropdown.show { display: block; }
  .ac-item { padding: 7px 12px; color: #c9d1d9; font-size: 0.88em; cursor: pointer; }
  .ac-item:hover, .ac-item.active { background: #30363d; color: #f0f6fc; }
  .ac-item .ac-match { color: #58a6ff; font-weight: 600; }
  .manual-refresh .hint { color: #8b949e; font-size: 0.8em; margin-top: 8px; }
  .btn-sync { background: linear-gradient(135deg, #1f6feb 0%, #388bfd 100%); color: #fff; border: none; border-radius: 8px; padding: 9px 22px; cursor: pointer; font-size: 0.85em; font-weight: 600; letter-spacing: 0.03em; transition: all 0.25s cubic-bezier(.4,0,.2,1); box-shadow: 0 2px 8px rgba(31,111,235,0.35); }
  .btn-sync:hover { background: linear-gradient(135deg, #388bfd 0%, #58a6ff 100%); box-shadow: 0 4px 16px rgba(56,139,253,0.4); transform: translateY(-1px); }
  .btn-sync:active { transform: translateY(0); box-shadow: 0 1px 4px rgba(31,111,235,0.3); }
  .btn-sync:disabled { opacity: 0.4; cursor: not-allowed; transform: none; box-shadow: none; }
  .btn-sync.success { background: linear-gradient(135deg, #238636 0%, #2ea043 100%); box-shadow: 0 2px 8px rgba(46,160,67,0.35); }
  .btn-sync.error { background: linear-gradient(135deg, #da3633 0%, #f85149 100%); box-shadow: 0 2px 8px rgba(248,81,73,0.35); }
  .ws-status { display: inline-flex; align-items: center; gap: 6px; font-size: 0.45em; font-weight: 400; vertical-align: middle; margin-left: 12px; }
  .ws-dot { width: 8px; height: 8px; border-radius: 50%; display: inline-block; }
  .ws-dot.connected { background: #238636; }
  .ws-dot.disconnected { background: #da3633; }
  .ws-dot.connecting { background: #d29922; }
  .k8s-flags { display: flex; gap: 10px; margin-bottom: 16px; flex-wrap: wrap; }
  .k8s-flag { display: inline-flex; align-items: center; gap: 6px; background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 6px 12px; font-size: 0.82em; }
  .k8s-flag .flag-dot { width: 8px; height: 8px; border-radius: 50%; display: inline-block; }
  .k8s-flag .flag-dot.on { background: #238636; }
  .k8s-flag .flag-dot.off { background: #484f58; }
  .k8s-flag .flag-label { color: #8b949e; }
  .k8s-flag .flag-value { color: #f0f6fc; font-weight: 600; }
  .k8s-workloads { display: flex; gap: 4px; flex-wrap: wrap; }
  .k8s-workload { display: inline-flex; align-items: center; gap: 4px; background: #1c2129; border: 1px solid #30363d; border-radius: 4px; padding: 2px 8px; font-size: 0.8em; color: #c9d1d9; }
  .k8s-workload .wl-icon { font-size: 0.9em; }
  .k8s-workload.dep .wl-icon { color: #58a6ff; }
  .k8s-workload.sts .wl-icon { color: #d2a8ff; }
  .k8s-none { color: #484f58; font-size: 0.82em; font-style: italic; }
  .k8s-badge { display: inline-flex; align-items: center; gap: 4px; padding: 2px 8px; border-radius: 12px; font-size: 0.75em; font-weight: 600; letter-spacing: 0.03em; white-space: nowrap; }
  .k8s-badge.in-cluster { background: rgba(35,134,54,0.15); color: #3fb950; border: 1px solid rgba(35,134,54,0.3); }
  .k8s-badge.not-in-cluster { background: rgba(72,79,88,0.15); color: #484f58; border: 1px solid rgba(72,79,88,0.3); }
  .k8s-badge .badge-dot { width: 6px; height: 6px; border-radius: 50%; display: inline-block; }
  .k8s-badge.in-cluster .badge-dot { background: #238636; }
  .k8s-badge.not-in-cluster .badge-dot { background: #484f58; }
  .pipeline-stages { display: flex; align-items: flex-start; gap: 0; flex-wrap: nowrap; justify-content: center; padding: 20px 0 8px; }
  .pipeline-stage { display: flex; flex-direction: column; align-items: center; min-width: 72px; flex-shrink: 1; }
  .pipeline-node { width: 34px; height: 34px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 15px; border: 2px solid #30363d; position: relative; z-index: 1; }
  .pipeline-node.done { background: #0d419d; border-color: #1f6feb; color: #58a6ff; }
  .pipeline-node.pending { background: #21262d; border-color: #30363d; color: #484f58; }
  .pipeline-label { font-size: 0.7em; color: #8b949e; margin-top: 6px; text-align: center; white-space: nowrap; }
  .pipeline-time { font-size: 0.65em; color: #58a6ff; margin-top: 2px; }
  .pipeline-connector { width: 28px; height: 2px; background: #30363d; margin-top: 16px; flex-shrink: 0; }
  .pipeline-connector.done { background: #1f6feb; }
  .pipeline-detail { font-size: 0.62em; color: #6e7681; margin-top: 2px; max-width: 80px; text-align: center; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .modal-overlay { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.7); z-index: 1000; justify-content: center; align-items: center; }
  .modal-overlay.show { display: flex; }
  .modal-content { background: #161b22; border: 1px solid #30363d; border-radius: 12px; padding: 28px 32px; max-width: 680px; width: 90%; max-height: 80vh; overflow-y: auto; position: relative; box-shadow: 0 8px 32px rgba(0,0,0,0.5); }
  .modal-close { position: absolute; top: 12px; right: 16px; background: none; border: none; color: #8b949e; font-size: 1.4em; cursor: pointer; padding: 4px 8px; border-radius: 4px; }
  .modal-close:hover { color: #f0f6fc; background: #21262d; }
  .modal-title { font-size: 1.2em; font-weight: 600; color: #f0f6fc; margin-bottom: 4px; }
  .modal-subtitle { font-size: 0.8em; color: #8b949e; margin-bottom: 16px; }
  .secret-link { color: #58a6ff; cursor: pointer; text-decoration: none; }
  .secret-link:hover { text-decoration: underline; }
  .meta-grid { display: grid; grid-template-columns: auto 1fr; gap: 3px 12px; font-size: 0.82em; }
  .meta-label { color: #8b949e; white-space: nowrap; }
  .meta-value { color: #c9d1d9; word-break: break-all; }
  .meta-value .tag { display: inline-block; background: #21262d; border: 1px solid #30363d; border-radius: 4px; padding: 1px 6px; margin: 1px 4px 1px 0; font-size: 0.9em; color: #8b949e; }
  .meta-value .workload { color: #58a6ff; }
  .modal-section { background: #0d1117; border: 1px solid #21262d; border-radius: 8px; padding: 12px 14px; margin-bottom: 10px; }
  .modal-section:last-child { margin-bottom: 0; }
  .section-header { font-size: 0.75em; font-weight: 600; color: #8b949e; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 8px; display: flex; align-items: center; gap: 6px; }
  .section-icon { font-size: 1.1em; }
</style>
</head>
<body>

<h1>&#x1F426; Raven <span class="ws-status"><span class="ws-dot connecting" id="wsDot"></span><span id="wsLabel">Connecting...</span></span></h1>
<p class="subtitle">Sealed Secrets Sync Dashboard</p>

<div class="info-bar">
  <span class="info-pill"><span class="pill-label">Engine:</span> <span class="pill-value">{{.Engine}}</span></span>
  <span class="info-pill"><span class="pill-label">Namespace:</span> <span class="pill-value">{{.DestEnv}}</span></span>
  <span class="info-pill"><span class="pill-label">Vault:</span> <span class="pill-value">{{.VaultURL}}</span></span>
  <span class="info-pill"><span class="pill-label">Secrets:</span> <span class="pill-value">{{.SecretCount}}</span></span>
  <span class="info-pill"><span class="pill-label">Last Sync:</span> <span class="pill-value" id="pillLastSync">{{.LastSync}}</span></span>
  <span class="info-pill"><span class="pill-label">Next Sync:</span> <span class="pill-value{{if .SyncOverdue}} overdue{{end}}" id="pillNextSync" data-iso="{{.NextSyncISO}}">{{.NextSync}}</span></span>
  <span class="info-pill"><span class="pill-label">Interval:</span> <span class="pill-value" id="pillInterval">{{.SyncInterval}}</span></span>
</div>

<div class="tabs">
  <div class="tab active" onclick="switchTab('secrets')">Secrets <span class="tab-badge">{{.SecretCount}}</span></div>
  <div class="tab" onclick="switchTab('events')">Events <span class="tab-badge" id="eventBadge">{{len .Events}}</span></div>
  <div class="tab" onclick="switchTab('k8s')">Kubernetes <span class="tab-badge" id="k8sBadge">&hellip;</span></div>
</div>

<div class="tab-panel active" id="tab-secrets">
<div class="manual-refresh">
  <div class="manual-refresh-title">Sync Secret from Vault</div>
  <div class="manual-refresh-row">
    <div class="ac-wrap">
      <input type="text" id="manualSecretPath" placeholder="Enter secret name..." autocomplete="off" oninput="acFilter()" onkeydown="acKeydown(event)" onfocus="acFilter()">
      <div class="ac-dropdown" id="acDropdown"></div>
    </div>
    <button class="btn-sync" onclick="manualRefresh()" id="btnManualRefresh">&#x21BB; Sync</button>
  </div>
  <div class="hint">Fetch and seal a secret from Vault &mdash; works even if it&rsquo;s not tracked yet</div>
</div>

<div class="collapsible-header" onclick="toggleCollapse('secretsList')">
  <span class="collapse-icon" id="secretsList-icon">&#9660;</span>
  <h2>Synced Sealed Secrets</h2>
</div>
<div class="collapsible-body" id="secretsList" style="max-height:none">
{{if .Secrets}}
<div class="search-bar">
  <input type="text" id="secretSearch" placeholder="Search secrets..." oninput="filterSecrets()">
  <span class="count" id="secretCount">Showing {{.SecretCount}} of {{.SecretCount}}</span>
</div>
<table id="secretsTable">
  <thead><tr><th>#</th><th>Secret Name</th><th>File</th><th>Last Modified</th><th>K8s</th><th>Action</th></tr></thead>
  <tbody>
  {{range $i, $s := .Secrets}}
    <tr data-name="{{$s.SecretName}}">
      <td class="row-num">{{inc $i}}</td>
      <td><a class="secret-link" onclick="showPipeline('{{$s.SecretName}}')"><strong>{{$s.SecretName}}</strong></a></td>
      <td style="color:#8b949e">{{$s.Name}}</td>
      <td>{{$s.Modified}}</td>
      <td class="k8s-cell" data-secret="{{$s.SecretName}}"><span class="k8s-badge not-in-cluster"><span class="badge-dot"></span> —</span></td>
      <td><button class="btn-refresh" onclick="refreshSecret('{{$s.SecretName}}', this)">Refresh</button></td>
    </tr>
  {{end}}
  </tbody>
</table>
<div class="page-controls" id="pageControls">
  <button onclick="changePage(-1)" id="btnPrev" disabled>&laquo; Prev</button>
  <span id="pageInfo"></span>
  <button onclick="changePage(1)" id="btnNext">&raquo; Next</button>
  <span style="margin-left:8px">Per page:</span>
  <select id="perPageSelect" onchange="changePerPage()" style="background:#0d1117;color:#c9d1d9;border:1px solid #30363d;border-radius:4px;padding:2px 6px;font-size:0.8em;">
    <option value="50">50</option>
    <option value="100">100</option>
    <option value="250">250</option>
    <option value="0">All</option>
  </select>
</div>
{{else}}
<div class="empty">No sealed secrets found in worktree</div>
{{end}}
</div><!-- end collapsible-body -->
</div>

<div class="tab-panel" id="tab-events">
<h2>Recent Events</h2>
{{if .Events}}
<table>
  <thead><tr><th>Time</th><th>Operation</th><th>Path</th><th>Status</th><th>Message</th></tr></thead>
  <tbody>
  {{range .Events}}
    <tr>
      <td>{{.Time.Format "15:04:05"}}</td>
      <td><span class="badge badge-{{.Operation}}">{{.Operation}}</span></td>
      <td>{{.Engine}}/{{.Path}}</td>
      <td><span class="badge badge-{{.Status}}">{{.Status}}</span></td>
      <td>{{.Message}}</td>
    </tr>
  {{end}}
  </tbody>
</table>
{{else}}
<div class="empty">No events recorded yet.<br><span style="font-size:0.85em;color:#6e7681">Events appear when secrets are created, updated, or deleted via Vault.</span></div>
{{end}}
</div>

<div class="tab-panel" id="tab-k8s">
<div id="k8sContent"><div class="empty">Click the Kubernetes tab to load live namespace data.</div></div>
</div>

<div class="modal-overlay" id="pipelineModal" onclick="if(event.target===this)closePipeline()">
<div class="modal-content">
  <button class="modal-close" onclick="closePipeline()">&times;</button>
  <div id="pipelineModalBody"></div>
</div>
</div>

<div class="footer">
  Connected since <span id="connectedSince">{{.GeneratedAt}}</span>
</div>

<div class="toast" id="toast"></div>

<script>
function switchTab(name) {
  document.querySelectorAll('.tab-panel').forEach(function(p) { p.classList.remove('active'); });
  document.querySelectorAll('.tab').forEach(function(t) { t.classList.remove('active'); });
  document.getElementById('tab-' + name).classList.add('active');
  var tabs = document.querySelectorAll('.tab');
  for (var i = 0; i < tabs.length; i++) {
    if (tabs[i].getAttribute('onclick').indexOf(name) !== -1) { tabs[i].classList.add('active'); break; }
  }
  if (location.hash.replace('#','') !== name && !(location.hash.indexOf('#secret/') === 0)) {
    history.replaceState(null, '', '#' + name);
  }
}

var allRows = [];
var filteredRows = [];
var currentPage = 0;
var perPage = 50;
var totalSecrets = {{.SecretCount}};

(function init() {
  var tbody = document.querySelector('#secretsTable tbody');
  if (!tbody) return;
  allRows = Array.prototype.slice.call(tbody.querySelectorAll('tr'));
  filteredRows = allRows.slice();
  if (totalSecrets <= 50) {
    document.getElementById('pageControls').style.display = 'none';
  }
  renderPage();
  rebuildSuggestions();
  loadK8sSecretStatus();
})();

function loadK8sSecretStatus() {
  fetch('/api/v1/k8s-status').then(function(r){ return r.json(); }).then(function(data) {
    if (!data.enabled) return;
    var k8sNames = {};
    if (data.secrets) { data.secrets.forEach(function(s){ k8sNames[s.name] = true; }); }
    document.querySelectorAll('.k8s-cell').forEach(function(cell) {
      var name = cell.getAttribute('data-secret');
      if (k8sNames[name]) {
        cell.innerHTML = '<span class="k8s-badge in-cluster"><span class="badge-dot"></span> In cluster</span>';
      } else {
        cell.innerHTML = '<span class="k8s-badge not-in-cluster"><span class="badge-dot"></span> Missing</span>';
      }
    });
  }).catch(function(){ /* k8s endpoint unavailable, leave as-is */ });
}

function rebuildSuggestions() {
  acNames = allRows.map(function(tr){ return tr.getAttribute('data-name'); });
}

var acNames = [];
var acIdx = -1;
function acFilter() {
  var input = document.getElementById('manualSecretPath');
  var dd = document.getElementById('acDropdown');
  var q = input.value.toLowerCase();
  if (!q) { dd.classList.remove('show'); return; }
  var matches = acNames.filter(function(n){ return n.toLowerCase().indexOf(q) !== -1; });
  if (matches.length === 0) { dd.classList.remove('show'); return; }
  dd.innerHTML = '';
  acIdx = -1;
  matches.forEach(function(name) {
    var div = document.createElement('div');
    div.className = 'ac-item';
    var i = name.toLowerCase().indexOf(q);
    div.innerHTML = name.substring(0,i) + '<span class="ac-match">' + name.substring(i, i+q.length) + '</span>' + name.substring(i+q.length);
    div.onmousedown = function(e) { e.preventDefault(); input.value = name; dd.classList.remove('show'); };
    dd.appendChild(div);
  });
  dd.classList.add('show');
}
function acKeydown(e) {
  var dd = document.getElementById('acDropdown');
  var items = dd.querySelectorAll('.ac-item');
  if (e.key === 'ArrowDown') { e.preventDefault(); acIdx = Math.min(acIdx+1, items.length-1); acHighlight(items); }
  else if (e.key === 'ArrowUp') { e.preventDefault(); acIdx = Math.max(acIdx-1, 0); acHighlight(items); }
  else if (e.key === 'Enter') { if (acIdx >= 0 && items[acIdx]) { document.getElementById('manualSecretPath').value = items[acIdx].textContent; dd.classList.remove('show'); } else { manualRefresh(); } }
  else if (e.key === 'Escape') { dd.classList.remove('show'); }
}
function acHighlight(items) {
  items.forEach(function(el,i){ el.classList.toggle('active', i === acIdx); });
  if (items[acIdx]) items[acIdx].scrollIntoView({block:'nearest'});
}
document.addEventListener('click', function(e) {
  if (!e.target.closest('.ac-wrap')) document.getElementById('acDropdown').classList.remove('show');
});

function filterSecrets() {
  var q = document.getElementById('secretSearch').value.toLowerCase();
  filteredRows = allRows.filter(function(tr) {
    return tr.getAttribute('data-name').toLowerCase().indexOf(q) !== -1;
  });
  currentPage = 0;
  renderPage();
}

function renderPage() {
  var start = perPage > 0 ? currentPage * perPage : 0;
  var end = perPage > 0 ? start + perPage : filteredRows.length;
  var total = filteredRows.length;

  allRows.forEach(function(tr) { tr.style.display = 'none'; });
  for (var i = start; i < Math.min(end, total); i++) {
    filteredRows[i].style.display = '';
    filteredRows[i].querySelector('.row-num').textContent = i + 1;
  }

  document.getElementById('secretCount').textContent =
    'Showing ' + Math.min(end, total) + ' of ' + total + (total < totalSecrets ? ' (filtered from ' + totalSecrets + ')' : '');

  var pages = perPage > 0 ? Math.ceil(total / perPage) : 1;
  document.getElementById('pageInfo').textContent = 'Page ' + (pages > 0 ? currentPage + 1 : 0) + ' of ' + pages;
  document.getElementById('btnPrev').disabled = currentPage === 0;
  document.getElementById('btnNext').disabled = currentPage >= pages - 1;

  var pc = document.getElementById('pageControls');
  if (pc) pc.style.display = (total <= 50 && perPage <= 50) ? 'none' : 'flex';
}

function changePage(dir) {
  currentPage += dir;
  renderPage();
}

function changePerPage() {
  perPage = parseInt(document.getElementById('perPageSelect').value);
  currentPage = 0;
  renderPage();
}

function showToast(msg, ms, type) {
  var t = document.getElementById('toast');
  t.textContent = msg;
  t.className = 'toast show' + (type ? ' toast-' + type : '');
  setTimeout(function(){ t.className = 'toast'; }, ms || 3000);
}
function toggleCollapse(id) {
  var body = document.getElementById(id);
  var icon = document.getElementById(id + '-icon');
  if (body.classList.contains('collapsed')) {
    body.classList.remove('collapsed');
    body.style.maxHeight = body.scrollHeight + 'px';
    icon.classList.remove('collapsed');
    setTimeout(function(){ body.style.maxHeight = 'none'; }, 300);
  } else {
    body.style.maxHeight = body.scrollHeight + 'px';
    body.offsetHeight;
    body.classList.add('collapsed');
    icon.classList.add('collapsed');
  }
}
function manualRefresh() {
  var input = document.getElementById('manualSecretPath');
  var name = input.value.trim();
  if (!name) { showToast('Enter a secret path first', 2000); return; }
  var btn = document.getElementById('btnManualRefresh');
  btn.disabled = true;
  btn.textContent = '...';
  fetch('/api/v1/refresh-secret', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({secret_path: name})
  }).then(function(r){ return r.json().then(function(d){ return {ok: r.ok, data: d}; }); })
    .then(function(res){
      if (res.ok) {
        btn.textContent = 'Done';
        btn.classList.add('success');
        showToast('Refreshed ' + name + ': ' + (res.data.message || 'ok'), 3000, 'ok');
        input.value = '';
      } else {
        btn.textContent = 'Error';
        btn.classList.add('error');
        showToast('Failed: ' + (res.data.message || 'unknown error'), 5000, 'error');
      }
      setTimeout(function(){ btn.textContent='\u21BB Sync'; btn.disabled=false; btn.classList.remove('success','error'); }, 3000);
    }).catch(function(err){
      btn.textContent = 'Error';
      btn.classList.add('error');
      showToast('Network error: ' + err, 5000, 'error');
      setTimeout(function(){ btn.textContent='\u21BB Sync'; btn.disabled=false; btn.classList.remove('error'); }, 3000);
    });
}
function refreshSecret(name, btn) {
  btn.disabled = true;
  btn.textContent = '...';
  fetch('/api/v1/refresh-secret', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({secret_path: name})
  }).then(function(r){ return r.json().then(function(d){ return {ok: r.ok, data: d}; }); })
    .then(function(res){
      if (res.ok) {
        btn.textContent = 'Done';
        btn.classList.add('success');
        showToast('Refreshed ' + name + ': ' + (res.data.message || 'ok'), 3000, 'ok');
      } else {
        btn.textContent = 'Error';
        btn.classList.add('error');
        showToast('Failed: ' + (res.data.message || 'unknown error'), 5000, 'error');
      }
      setTimeout(function(){ btn.textContent='Refresh'; btn.disabled=false; btn.classList.remove('success','error'); }, 3000);
    }).catch(function(err){
      btn.textContent = 'Error';
      btn.classList.add('error');
      showToast('Network error: ' + err, 5000, 'error');
      setTimeout(function(){ btn.textContent='Refresh'; btn.disabled=false; btn.classList.remove('error'); }, 3000);
    });
}

// --- WebSocket live updates ---
var ws;
var wsReconnectDelay = 1000;
function connectWS() {
  var proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  ws = new WebSocket(proto + '//' + location.host + '/ws');
  var dot = document.getElementById('wsDot');
  var label = document.getElementById('wsLabel');

  ws.onopen = function() {
    dot.className = 'ws-dot connected';
    label.textContent = 'Live';
    wsReconnectDelay = 1000;
  };
  ws.onclose = function() {
    dot.className = 'ws-dot disconnected';
    label.textContent = 'Reconnecting...';
    setTimeout(connectWS, wsReconnectDelay);
    wsReconnectDelay = Math.min(wsReconnectDelay * 2, 30000);
  };
  ws.onerror = function() { ws.close(); };
  ws.onmessage = function(e) {
    try {
      var msg = JSON.parse(e.data);
      if (msg.type === 'event') handleWSEvent(msg.data);
      else if (msg.type === 'sync_status') handleWSSyncStatus(msg.data);
    } catch(err) { console.error('ws parse error', err); }
  };
}
function handleWSEvent(ev) {
  // Update events badge with authoritative count from server
  var badge = document.getElementById('eventBadge');
  if (ev.total !== undefined) {
    badge.textContent = ev.total;
  } else {
    badge.textContent = parseInt(badge.textContent) + 1;
  }

  // Prepend to events table
  var panel = document.getElementById('tab-events');
  var table = panel.querySelector('table');
  if (!table) {
    // First event — replace empty message with a table
    var empty = panel.querySelector('.empty');
    if (empty) empty.remove();
    table = document.createElement('table');
    table.innerHTML = '<thead><tr><th>Time</th><th>Operation</th><th>Path</th><th>Status</th><th>Message</th></tr></thead><tbody></tbody>';
    var h2 = panel.querySelector('h2');
    h2.insertAdjacentElement('afterend', table);
  }
  var tbody = table.querySelector('tbody');
  var tr = document.createElement('tr');
  var t = ev.time ? new Date(ev.time) : new Date();
  var timeStr = ('0'+t.getHours()).slice(-2)+':'+('0'+t.getMinutes()).slice(-2)+':'+('0'+t.getSeconds()).slice(-2);
  tr.innerHTML = '<td>'+timeStr+'</td>'+
    '<td><span class="badge badge-'+ev.operation+'">'+ev.operation+'</span></td>'+
    '<td>'+ev.engine+'/'+ev.path+'</td>'+
    '<td><span class="badge badge-'+ev.status+'">'+ev.status+'</span></td>'+
    '<td>'+ev.message+'</td>';
  tbody.insertBefore(tr, tbody.firstChild);

  // Toast
  showToast(ev.operation + ' ' + ev.path + ': ' + ev.status, 3000, ev.status);

  // Update K8s cell in secrets table for k8s lifecycle events
  if (ev.operation.indexOf('k8s-') === 0) {
    var cells = document.querySelectorAll('.k8s-cell[data-secret="'+ev.path+'"]');
    cells.forEach(function(cell) {
      if (ev.operation === 'k8s-deleted') {
        cell.innerHTML = '<span class="k8s-badge not-in-cluster"><span class="badge-dot"></span> Missing</span>';
      } else {
        cell.innerHTML = '<span class="k8s-badge in-cluster"><span class="badge-dot"></span> In cluster</span>';
      }
    });
  }

  // Update secrets table if create/update
  if ((ev.operation === 'create' || ev.operation === 'update') && ev.status === 'ok') {
    addOrUpdateSecretRow(ev.path);
  } else if (ev.operation === 'delete' && ev.status === 'ok') {
    removeSecretRow(ev.path);
  }
}
function addOrUpdateSecretRow(name) {
  var tbody = document.querySelector('#secretsTable tbody');
  if (!tbody) return;
  var existing = tbody.querySelector('tr[data-name="'+name+'"]');
  var now = new Date();
  var mod = now.getFullYear()+'-'+('0'+(now.getMonth()+1)).slice(-2)+'-'+('0'+now.getDate()).slice(-2)+' '+('0'+now.getHours()).slice(-2)+':'+('0'+now.getMinutes()).slice(-2)+':'+('0'+now.getSeconds()).slice(-2);
  if (existing) {
    existing.querySelectorAll('td')[3].textContent = mod;
    existing.style.background = '#1a2332';
    setTimeout(function(){ existing.style.background=''; }, 2000);
  } else {
    var tr = document.createElement('tr');
    tr.setAttribute('data-name', name);
    tr.innerHTML = '<td class="row-num"></td><td><a class="secret-link" onclick="showPipeline(\''+name+'\');"><strong>'+name+'</strong></a></td><td style="color:#8b949e">'+name+'.yaml</td><td>'+mod+'</td><td class="k8s-cell" data-secret="'+name+'"><span class="k8s-badge not-in-cluster"><span class="badge-dot"></span> \u2014</span></td><td><button class="btn-refresh" onclick="refreshSecret(\''+name+'\', this)">Refresh</button></td>';
    tbody.appendChild(tr);
    allRows.push(tr);
    filteredRows = allRows.slice();
    totalSecrets = allRows.length;
    tr.style.background = '#1a2332';
    setTimeout(function(){ tr.style.background=''; }, 2000);
  }
  // Update badge and count
  var tabBadges = document.querySelectorAll('.tab-badge');
  if (tabBadges.length > 1) tabBadges[0].textContent = totalSecrets;
  document.getElementById('secretCount').textContent = 'Showing ' + totalSecrets + ' of ' + totalSecrets;
  renderPage();
  rebuildSuggestions();
}
function removeSecretRow(name) {
  var tbody = document.querySelector('#secretsTable tbody');
  if (!tbody) return;
  var row = tbody.querySelector('tr[data-name="'+name+'"]');
  if (row) {
    row.remove();
    allRows = allRows.filter(function(tr){ return tr.getAttribute('data-name') !== name; });
    filteredRows = allRows.slice();
    totalSecrets = allRows.length;
    renderPage();
  }
  var tabBadges = document.querySelectorAll('.tab-badge');
  if (tabBadges.length > 1) tabBadges[0].textContent = totalSecrets;
}
function handleWSSyncStatus(s) {
  var ls = document.getElementById('pillLastSync');
  var ns = document.getElementById('pillNextSync');
  var iv = document.getElementById('pillInterval');
  if (ls) ls.textContent = s.last_sync || '';
  if (ns) {
    ns.setAttribute('data-iso', s.next_sync_iso || '');
    ns.classList.remove('overdue');
    if (s.overdue) ns.classList.add('overdue');
  }
  if (iv) iv.textContent = s.interval || '';
  startCountdown();
}

var countdownTimer;
function startCountdown() {
  if (countdownTimer) clearInterval(countdownTimer);
  updateCountdown();
  countdownTimer = setInterval(updateCountdown, 1000);
}
function updateCountdown() {
  var el = document.getElementById('pillNextSync');
  if (!el) return;
  var iso = el.getAttribute('data-iso');
  if (!iso) return;
  var target = new Date(iso).getTime();
  var now = Date.now();
  var diff = Math.floor((target - now) / 1000);
  if (diff <= 0) {
    el.textContent = 'now';
    el.classList.add('overdue');
    return;
  }
  el.classList.remove('overdue');
  var m = Math.floor(diff / 60);
  var s = diff % 60;
  var ts = new Date(target);
  var hh = ('0'+ts.getUTCHours()).slice(-2);
  var mm = ('0'+ts.getUTCMinutes()).slice(-2);
  var ss = ('0'+ts.getUTCSeconds()).slice(-2);
  el.textContent = m + 'm ' + ('0'+s).slice(-2) + 's';
}
startCountdown();
connectWS();

// --- Kubernetes tab ---
var k8sLoaded = false;
var origSwitchTab = switchTab;
switchTab = function(name) {
  origSwitchTab(name);
  if (name === 'k8s' && !k8sLoaded) { loadK8sStatus(); }
};
function loadK8sStatus() {
  var el = document.getElementById('k8sContent');
  el.innerHTML = '<div class="empty">Loading...</div>';
  fetch('/api/v1/k8s-status')
    .then(function(r){ return r.json(); })
    .then(function(data){ renderK8s(data); k8sLoaded = true; })
    .catch(function(err){ el.innerHTML = '<div class="empty">Failed to load: ' + err + '</div>'; });
}
function renderK8s(data) {
  var el = document.getElementById('k8sContent');
  var badge = document.getElementById('k8sBadge');
  var html = '';

  // Feature flags
  html += '<div class="k8s-flags">';
  html += k8sFlag('K8s Integration', data.enabled);
  html += k8sFlag('Auto Rollout', data.rollout_enabled);
  html += k8sFlag('Monitor', data.monitor_enabled);
  html += k8sFlag('Cleanup', data.cleanup_enabled);
  html += '<span class="info-pill"><span class="pill-label">Namespace:</span> <span class="pill-value">' + data.namespace + '</span></span>';
  html += '</div>';

  if (!data.enabled) {
    html += '<div class="empty">Kubernetes integration is not enabled.<br><span style="font-size:0.85em;color:#6e7681">Set KUBERNETESMONITOR=true, KUBERNETESREMOVE=true, or KUBERNETES_ROLLOUT=true to enable.</span></div>';
    badge.textContent = 'off';
    el.innerHTML = html;
    return;
  }

  var secrets = data.secrets || [];
  badge.textContent = secrets.length;

  if (secrets.length === 0) {
    html += '<div class="empty">No Raven-managed secrets found in namespace <strong>' + data.namespace + '</strong>.</div>';
    el.innerHTML = html;
    return;
  }

  html += '<table><thead><tr><th>#</th><th>Secret</th><th>Source</th><th>Created</th><th>Modified</th><th>Used By</th></tr></thead><tbody>';
  for (var i = 0; i < secrets.length; i++) {
    var s = secrets[i];
    var workloads = '';
    var deps = s.deployments || [];
    var stss = s.statefulsets || [];
    for (var d = 0; d < deps.length; d++) {
      workloads += '<span class="k8s-workload dep"><span class="wl-icon">&#9654;</span>' + deps[d] + '</span>';
    }
    for (var t = 0; t < stss.length; t++) {
      workloads += '<span class="k8s-workload sts"><span class="wl-icon">&#9670;</span>' + stss[t] + '</span>';
    }
    if (!workloads) workloads = '<span class="k8s-none">no workloads</span>';
    html += '<tr><td>' + (i+1) + '</td><td><strong>' + s.name + '</strong></td><td style="color:#8b949e">' + (s.source||'—') + '</td><td>' + s.created + '</td><td>' + s.modified + '</td><td><div class="k8s-workloads">' + workloads + '</div></td></tr>';
  }
  html += '</tbody></table>';
  html += '<div style="margin-top:12px"><button class="btn-refresh" onclick="k8sLoaded=false;loadK8sStatus()">&#x21BB; Reload</button></div>';
  el.innerHTML = html;
}
function k8sFlag(label, on) {
  return '<span class="k8s-flag"><span class="flag-dot ' + (on ? 'on' : 'off') + '"></span><span class="flag-label">' + label + ':</span> <span class="flag-value">' + (on ? 'on' : 'off') + '</span></span>';
}

// --- Pipeline modal ---
var stageIcons = {'Vault':'\u{1F512}','Sealed':'\u{1F4E6}','Git':'\u{1F4CB}','ArgoCD':'\u{1F500}','K8s Secret':'\u2638','Rollout':'\u{1F504}'};

function showPipeline(secretName) {
  var modal = document.getElementById('pipelineModal');
  var body = document.getElementById('pipelineModalBody');
  body.innerHTML = '<div class="modal-title">' + secretName + '</div><div class="modal-subtitle">Loading lifecycle...</div>';
  modal.classList.add('show');
  history.replaceState(null, '', '#secret/' + encodeURIComponent(secretName));
  fetch('/api/v1/pipeline')
    .then(function(r){ return r.json(); })
    .then(function(data) {
      var entry = null;
      for (var i = 0; i < data.length; i++) {
        if (data[i].secret === secretName) { entry = data[i]; break; }
      }
      if (!entry) {
        body.innerHTML = '<div class="modal-title">' + secretName + '</div><div class="empty">No pipeline data found for this secret.</div>';
        return;
      }
      var html = '<div class="modal-title">' + secretName + '</div>';
      html += '<div class="modal-subtitle">Secret lifecycle</div>';

      // Vault section
      html += '<div class="modal-section">';
      html += '<div class="section-header"><span class="section-icon">\u{1F512}</span> Vault</div>';
      html += '<div class="meta-grid">';
      html += '<div class="meta-label">Engine</div><div class="meta-value">' + (entry.engine || '\u2014') + '</div>';
      html += '<div class="meta-label">Source</div><div class="meta-value">' + (entry.source || '\u2014') + '</div>';
      if (entry.data_keys && entry.data_keys.length) {
        html += '<div class="meta-label">Data Keys</div><div class="meta-value">';
        for (var k = 0; k < entry.data_keys.length; k++) html += '<span class="tag">' + entry.data_keys[k] + '</span>';
        html += '</div>';
      }
      html += '</div></div>';

      // Kubernetes section
      html += '<div class="modal-section">';
      html += '<div class="section-header"><span class="section-icon">\u2638</span> Kubernetes</div>';
      html += '<div class="meta-grid">';
      html += '<div class="meta-label">Namespace</div><div class="meta-value">' + (entry.namespace || '\u2014') + '</div>';
      if (entry.k8s_created) {
        html += '<div class="meta-label">Created</div><div class="meta-value">' + entry.k8s_created + '</div>';
        html += '<div class="meta-label">Modified</div><div class="meta-value">' + entry.k8s_modified + '</div>';
      } else {
        html += '<div class="meta-label">Status</div><div class="meta-value" style="color:#484f58">Not in cluster</div>';
      }
      if (entry.deployments && entry.deployments.length) {
        html += '<div class="meta-label">Deployments</div><div class="meta-value">';
        for (var d = 0; d < entry.deployments.length; d++) html += '<span class="workload">' + entry.deployments[d] + '</span> ';
        html += '</div>';
      }
      if (entry.statefulsets && entry.statefulsets.length) {
        html += '<div class="meta-label">StatefulSets</div><div class="meta-value">';
        for (var ss = 0; ss < entry.statefulsets.length; ss++) html += '<span class="workload">' + entry.statefulsets[ss] + '</span> ';
        html += '</div>';
      }
      html += '</div></div>';

      // Pipeline section
      html += '<div class="modal-section">';
      html += '<div class="section-header"><span class="section-icon">\u{1F504}</span> Pipeline</div>';
      html += '<div class="pipeline-stages">';
      for (var j = 0; j < entry.stages.length; j++) {
        var s = entry.stages[j];
        if (j > 0) {
          var connClass = (entry.stages[j-1].status === 'done' && s.status === 'done') ? 'done' : '';
          html += '<div class="pipeline-connector ' + connClass + '"></div>';
        }
        var icon = stageIcons[s.name] || '\u25CF';
        html += '<div class="pipeline-stage">';
        html += '<div class="pipeline-node ' + s.status + '" title="' + s.name + (s.detail ? ': ' + s.detail : '') + '">' + icon + '</div>';
        html += '<div class="pipeline-label">' + s.name + '</div>';
        if (s.time) html += '<div class="pipeline-time">' + s.time + '</div>';
        if (s.detail) html += '<div class="pipeline-detail" title="' + s.detail + '">' + s.detail + '</div>';
        html += '</div>';
      }
      html += '</div>';
      html += '</div>';
      body.innerHTML = html;
    })
    .catch(function(err) {
      body.innerHTML = '<div class="modal-title">' + secretName + '</div><div class="empty">Failed to load: ' + err + '</div>';
    });
}

function closePipeline() {
  document.getElementById('pipelineModal').classList.remove('show');
  var tab = document.querySelector('.tab-panel.active');
  if (tab) history.replaceState(null, '', '#' + tab.id.replace('tab-', ''));
  else history.replaceState(null, '', '#secrets');
}

document.addEventListener('keydown', function(e) {
  if (e.key === 'Escape') closePipeline();
});

function routeFromHash() {
  var hash = location.hash.replace('#', '');
  if (!hash) return;
  if (hash.indexOf('secret/') === 0) {
    var name = decodeURIComponent(hash.substring(7));
    switchTab('secrets');
    showPipeline(name);
  } else if (['secrets','events','k8s'].indexOf(hash) !== -1) {
    switchTab(hash);
  }
}

window.addEventListener('hashchange', routeFromHash);
window.addEventListener('load', function() { if (location.hash) routeFromHash(); });
</script>
</body>
</html>`
