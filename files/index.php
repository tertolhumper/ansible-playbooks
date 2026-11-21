<?php
// SESSION AUTH
session_start();

// Handle login POST
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login_username'])) {
    $u = trim($_POST['login_username'] ?? '');
    $p = trim($_POST['login_password'] ?? '');

    // Fetch password from Vault
    $vault_token  = getenv('VAULT_TOKEN') ?: '';
    $vault_url    = 'http://vault.vault.svc.cluster.local:8200/v1/secret/data/sentinel-admin';
    $vault_resp   = @file_get_contents($vault_url, false, stream_context_create([
        'http' => [
            'header' => "X-Vault-Token: $vault_token\r\n",
            'timeout' => 3,
        ]
    ]));

    $admin_user = '';
    $admin_pass = '';

    if ($vault_resp) {
        $vdata = json_decode($vault_resp, true);
        $admin_pass = $vdata['data']['data']['password'] ?? '';
        $admin_user = $vdata['data']['data']['username'] ?? '';
    }

    if ($admin_user === '' || $admin_pass === '' || $u !== $admin_user || $p !== $admin_pass) {
        $_SESSION['login_error'] = true;
        header('Location: ?view=login');
        exit;
    }

    $_SESSION['authenticated'] = true;
    $_SESSION['user'] = $admin_user;
    header('Location: ?view=dashboard');
    exit;
}

// Handle logout
if (isset($_GET['logout'])) {
    session_destroy();
    header('Location: /');
    exit;
}

$is_auth      = $_SESSION['authenticated'] ?? false;
$login_error  = $_SESSION['login_error'] ?? false;
unset($_SESSION['login_error']);

$host = 'mariadb';
$db   = 'calmapps';
$user = 'calmapps';
$pass = getenv('MARIADB_PASSWORD') ?: '';

$pdo = null;
try {
    $pdo = new PDO("mysql:host=$host;dbname=$db;charset=utf8mb4", $user, $pass, [
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_TIMEOUT            => 3,
    ]);
} catch (PDOException $e) {}

// Handle email registration POST
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['email'])) {
    header('Content-Type: application/json');
    $email = filter_var(trim($_POST['email']), FILTER_VALIDATE_EMAIL);
    if (!$email) {
        echo json_encode(['success' => false, 'message' => 'Invalid email address.']);
        exit;
    }
    if ($pdo) {
        try {
            $stmt = $pdo->prepare('INSERT IGNORE INTO launch_notifications (email, ip_hash, user_agent) VALUES (?, ?, ?)');
            $stmt->execute([
                $email,
                hash('sha256', $_SERVER['REMOTE_ADDR'] ?? ''),
                substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 500),
            ]);
            echo json_encode(['success' => true, 'message' => 'Registered successfully.']);
        } catch (PDOException $e) {
            echo json_encode(['success' => false, 'message' => 'Registration failed.']);
        }
    } else {
        echo json_encode(['success' => false, 'message' => 'Database unavailable.']);
    }
    exit;
}

// Handle dashboard API
if ($_SERVER['REQUEST_URI'] === '/api/dashboard.php' || ($_GET['api'] ?? '') === 'dashboard') {
    header('Content-Type: application/json');
    $response = [
        'visits'             => 0,
        'registrations'      => 0,
        'status'             => [
            'application' => 'ONLINE',
            'php'         => 'PHP ' . phpversion(),
            'mariadb'     => $pdo ? 'ONLINE' : 'OFFLINE',
            'host'        => gethostname(),
        ],
        'telemetry'          => [],
        'registrations_list' => [],
    ];
    if ($pdo) {
        try {
            $response['visits']       = (int) $pdo->query('SELECT COUNT(*) FROM visitors')->fetchColumn();
            $response['registrations'] = (int) $pdo->query('SELECT COUNT(*) FROM launch_notifications')->fetchColumn();
            $response['telemetry']    = $pdo->query(
                'SELECT DATE_FORMAT(created_at,"%Y-%m-%d %H:%i:%s") AS timestamp, path, user_agent AS ua
                 FROM visitors ORDER BY created_at DESC LIMIT 20'
            )->fetchAll();
            $response['registrations_list'] = $pdo->query(
                'SELECT email, DATE_FORMAT(created_at,"%Y-%m-%d %H:%i:%s") AS created_at
                 FROM launch_notifications ORDER BY created_at DESC'
            )->fetchAll();
        } catch (PDOException $e) {}
    }
    echo json_encode($response);
    exit;
}

// Track visit
if ($pdo) {
    try {
        $stmt = $pdo->prepare('INSERT INTO visitors (ip_hash, path, user_agent) VALUES (?, ?, ?)');
        $stmt->execute([
            hash('sha256', $_SERVER['REMOTE_ADDR'] ?? ''),
            $_SERVER['REQUEST_URI'] ?? '/',
            substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 500),
        ]);
    } catch (PDOException $e) {}
}

$mariadb_status = $pdo ? 'ONLINE' : 'OFFLINE';
$php_version    = 'PHP ' . phpversion();
$hostname       = gethostname();
$app_status     = 'ONLINE';
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="theme-color" content="#050E1A">
<title>Sentinel NSM — Network Security Monitoring</title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --navy:#050E1A;--navy-mid:#0A1929;--navy-light:#0F2540;
  --teal:#00C2CB;--teal-dim:#00878E;--slate:#8A9BB0;--slate-light:#B8C8DC;
  --white:#FFFFFF;--red:#E53935;--amber:#F59E0B;--green:#10B981;
  --border:rgba(0,194,203,0.15);--border-subtle:rgba(138,155,176,0.12);
}
html,body{font-family:-apple-system,BlinkMacSystemFont,'Inter','Segoe UI',sans-serif;background:var(--navy);color:var(--white);min-height:100vh;overflow-x:hidden;font-size:15px;line-height:1.6;-webkit-text-size-adjust:100%}
.view{display:none;min-height:100vh}.view.active{display:block}
#login.active{display:flex}#dashboard.active{display:block}
.logo-mark{display:inline-flex;align-items:center;gap:10px;text-decoration:none;cursor:pointer}
.logo-wordmark{font-size:13px;font-weight:600;letter-spacing:0.08em;color:var(--white);line-height:1.2}
.logo-wordmark span{display:block;font-size:9px;font-weight:400;color:var(--slate);letter-spacing:0.12em}
nav{position:fixed;top:0;left:0;right:0;z-index:100;display:flex;align-items:center;justify-content:space-between;padding:16px 40px;background:rgba(5,14,26,0.92);backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);border-bottom:1px solid var(--border-subtle)}
.nav-right{display:flex;align-items:center;gap:20px}
.status-badge{display:flex;align-items:center;gap:6px;font-size:11px;font-weight:500;color:var(--slate);letter-spacing:0.06em}
.status-dot{width:6px;height:6px;border-radius:50%;background:var(--green);animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:0.4}}
.btn-nav{font-size:12px;font-weight:500;color:var(--teal);background:transparent;border:1px solid var(--teal-dim);padding:8px 18px;cursor:pointer;transition:all 0.2s;letter-spacing:0.04em;-webkit-tap-highlight-color:transparent;touch-action:manipulation}
.btn-nav:hover,.btn-nav:active{background:rgba(0,194,203,0.08);border-color:var(--teal)}
#landing{background:var(--navy)}
.hero{min-height:100vh;display:flex;flex-direction:column;justify-content:center;padding:110px 40px 80px;position:relative;overflow:hidden}
.hero-grid{position:absolute;inset:0;background-image:linear-gradient(rgba(0,194,203,0.04) 1px,transparent 1px),linear-gradient(90deg,rgba(0,194,203,0.04) 1px,transparent 1px);background-size:60px 60px;mask-image:radial-gradient(ellipse 80% 80% at 50% 50%,black 30%,transparent 100%);-webkit-mask-image:radial-gradient(ellipse 80% 80% at 50% 50%,black 30%,transparent 100%)}
.hero-glow{position:absolute;top:20%;right:5%;width:500px;height:500px;background:radial-gradient(ellipse,rgba(0,194,203,0.06) 0%,transparent 70%);pointer-events:none}
.hero-content{position:relative;max-width:660px}
h1{font-size:clamp(32px,5vw,60px);font-weight:700;line-height:1.08;letter-spacing:-0.02em;margin-bottom:24px;color:var(--white)}
h1 .accent{color:var(--teal)}
.hero-desc{font-size:16px;color:var(--slate-light);line-height:1.7;max-width:540px;margin-bottom:36px;font-weight:300}
.hero-actions{display:flex;align-items:center;gap:14px;flex-wrap:wrap}
.btn-primary{background:var(--teal);color:var(--navy);font-size:13px;font-weight:600;padding:13px 28px;border:none;cursor:pointer;letter-spacing:0.04em;transition:all 0.2s;-webkit-tap-highlight-color:transparent;touch-action:manipulation}
.btn-primary:hover,.btn-primary:active{background:#00D6E0}
.btn-ghost{background:transparent;color:var(--slate-light);font-size:13px;padding:13px 28px;border:1px solid var(--border-subtle);cursor:pointer;transition:all 0.2s;-webkit-tap-highlight-color:transparent;touch-action:manipulation}
.btn-ghost:hover,.btn-ghost:active{border-color:var(--slate);color:var(--white)}
.stats-bar{display:flex;gap:40px;margin-top:60px;padding-top:36px;border-top:1px solid var(--border-subtle);flex-wrap:wrap}
.stat-value{font-size:26px;font-weight:700;color:var(--white);letter-spacing:-0.02em;line-height:1}
.stat-label{font-size:11px;color:var(--slate);margin-top:5px}
section{padding:80px 40px;max-width:1080px;margin:0 auto}
h2{font-size:clamp(22px,3vw,36px);font-weight:700;letter-spacing:-0.02em;line-height:1.15;margin-bottom:14px}
.section-desc{font-size:15px;color:var(--slate-light);max-width:520px;line-height:1.7;margin-bottom:48px;font-weight:300}
.stack-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:1px;background:var(--border-subtle);border:1px solid var(--border-subtle)}
.stack-item{background:var(--navy-mid);padding:28px 24px;transition:background 0.2s}
.stack-item:hover,.stack-item:active{background:var(--navy-light)}
.stack-icon{width:32px;height:32px;margin-bottom:16px;color:var(--teal)}
.stack-name{font-size:14px;font-weight:600;margin-bottom:8px;color:var(--white)}
.stack-desc{font-size:13px;color:var(--slate);line-height:1.6}
.threat-flow{background:var(--navy-mid);border:1px solid var(--border-subtle);padding:36px;margin-top:36px}
.threat-flow-title{font-size:11px;font-weight:500;color:var(--slate);letter-spacing:0.1em;margin-bottom:28px}
.flow-steps{display:flex;align-items:stretch}
.flow-step{flex:1;padding:18px 14px;background:var(--navy);border-right:1px solid var(--border-subtle)}
.flow-step:last-child{border-right:none}
.flow-step-num{font-size:10px;color:var(--teal);font-weight:600;letter-spacing:0.08em;margin-bottom:8px}
.flow-step-name{font-size:13px;font-weight:600;color:var(--white);margin-bottom:5px}
.flow-step-detail{font-size:11px;color:var(--slate);line-height:1.5}
.pricing-grid{display:grid;grid-template-columns:1fr 1fr;gap:1px;background:var(--border-subtle);border:1px solid var(--border-subtle)}
.pricing-card{background:var(--navy-mid);padding:36px 32px}
.pricing-card.featured{background:var(--navy-light)}
.pricing-tier{font-size:11px;font-weight:500;color:var(--teal);letter-spacing:0.1em;margin-bottom:18px}
.pricing-amount{font-size:34px;font-weight:700;color:var(--white);letter-spacing:-0.02em;margin-bottom:4px}
.pricing-period{font-size:12px;color:var(--slate);margin-bottom:24px}
.pricing-features{list-style:none;display:flex;flex-direction:column;gap:9px}
.pricing-features li{font-size:13px;color:var(--slate-light);display:flex;align-items:flex-start;gap:9px;line-height:1.5}
.pricing-features li::before{content:'';display:block;width:5px;height:5px;background:var(--teal);border-radius:50%;margin-top:7px;flex-shrink:0}
.notify-form{display:flex;gap:10px;margin-top:32px;flex-wrap:wrap}
.notify-input{flex:1;min-width:200px;background:var(--navy-mid);border:1px solid var(--border-subtle);color:var(--white);font-family:inherit;font-size:14px;padding:12px 16px;outline:none;transition:border-color 0.2s;-webkit-appearance:none;border-radius:0}
.notify-input:focus{border-color:var(--teal-dim)}
.notify-input::placeholder{color:var(--slate)}
.notify-msg{font-size:13px;margin-top:10px;display:none}
.notify-msg.ok{color:var(--green)}.notify-msg.err{color:var(--red)}
footer{border-top:1px solid var(--border-subtle);padding:36px 40px;text-align:center;display:flex;flex-direction:column;align-items:center;gap:14px}
footer p{font-size:12px;color:var(--slate)}
#login{min-height:100vh;background:var(--navy);align-items:center;justify-content:center;padding:20px}
.login-panel{width:100%;max-width:400px;padding:44px 36px;background:var(--navy-mid);border:1px solid var(--border-subtle)}
.login-logo{margin-bottom:36px}
.login-title{font-size:17px;font-weight:600;margin-bottom:5px;letter-spacing:-0.01em}
.login-sub{font-size:12px;color:var(--slate);margin-bottom:32px}
.form-group{margin-bottom:18px}
.form-label{font-size:11px;font-weight:500;color:var(--slate);letter-spacing:0.08em;display:block;margin-bottom:7px}
.form-input{width:100%;background:var(--navy);border:1px solid var(--border-subtle);color:var(--white);font-family:inherit;font-size:14px;padding:12px 14px;outline:none;transition:border-color 0.2s;-webkit-appearance:none;border-radius:0}
.form-input:focus{border-color:var(--teal-dim)}
.form-input::placeholder{color:var(--slate)}
.btn-login{width:100%;background:var(--teal);color:var(--navy);font-size:13px;font-weight:600;padding:13px;border:none;cursor:pointer;letter-spacing:0.04em;margin-top:6px;transition:background 0.2s;-webkit-tap-highlight-color:transparent;touch-action:manipulation;-webkit-appearance:none;border-radius:0}
.btn-login:hover,.btn-login:active{background:#00D6E0}
.login-error{font-size:12px;color:var(--red);margin-top:10px;display:none}
.login-footer{margin-top:28px;padding-top:20px;border-top:1px solid var(--border-subtle);font-size:11px;color:var(--slate);text-align:center}
.login-footer a{color:var(--slate);text-decoration:none;cursor:pointer}
#dashboard{min-height:100vh;background:var(--navy)}
.dash-nav{position:sticky;top:0;z-index:100;display:flex;align-items:center;justify-content:space-between;padding:14px 24px;background:var(--navy-mid);border-bottom:1px solid var(--border-subtle)}
.dash-nav-right{display:flex;align-items:center;gap:16px}
.dash-user{font-size:12px;color:var(--slate)}
.btn-logout{font-size:11px;font-weight:500;color:var(--slate);background:transparent;border:1px solid var(--border-subtle);padding:6px 14px;cursor:pointer;transition:all 0.2s;letter-spacing:0.04em;-webkit-tap-highlight-color:transparent}
.btn-logout:hover,.btn-logout:active{border-color:var(--red);color:var(--red)}
.dash-body{display:grid;grid-template-columns:200px 1fr;min-height:calc(100vh - 57px)}
.dash-sidebar{background:var(--navy-mid);border-right:1px solid var(--border-subtle);padding:24px 0}
.sidebar-section{padding:0 14px;margin-bottom:28px}
.sidebar-label{font-size:9px;font-weight:600;color:var(--slate);letter-spacing:0.14em;padding:0 8px;margin-bottom:8px}
.sidebar-item{display:flex;align-items:center;gap:9px;padding:9px 8px;font-size:13px;color:var(--slate-light);cursor:pointer;transition:all 0.15s;border:1px solid transparent;-webkit-tap-highlight-color:transparent;touch-action:manipulation}
.sidebar-item:hover,.sidebar-item:active{background:rgba(0,194,203,0.06);color:var(--white)}
.sidebar-item.active{background:rgba(0,194,203,0.08);color:var(--teal);border-color:rgba(0,194,203,0.15)}
.dash-main{padding:28px;overflow-y:auto}
.dash-title{font-size:19px;font-weight:600;letter-spacing:-0.01em;margin-bottom:4px}
.dash-subtitle{font-size:12px;color:var(--slate);margin-bottom:28px}
.kpi-row{display:grid;grid-template-columns:repeat(4,1fr);gap:1px;background:var(--border-subtle);border:1px solid var(--border-subtle);margin-bottom:20px}
.kpi-card{background:var(--navy-mid);padding:22px 18px}
.kpi-label{font-size:10px;font-weight:500;color:var(--slate);letter-spacing:0.1em;margin-bottom:10px}
.kpi-value{font-size:26px;font-weight:700;letter-spacing:-0.02em;color:var(--white);line-height:1;margin-bottom:5px}
.kpi-delta{font-size:11px;color:var(--green)}
.dash-grid{display:grid;grid-template-columns:1fr 340px;gap:14px;margin-bottom:14px}
.dash-panel{background:var(--navy-mid);border:1px solid var(--border-subtle);padding:22px}
.panel-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:18px}
.panel-title{font-size:13px;font-weight:600;color:var(--white)}
.panel-meta{font-size:11px;color:var(--slate)}
.tele-table{width:100%;border-collapse:collapse}
.tele-table th{font-size:10px;font-weight:500;color:var(--slate);letter-spacing:0.08em;text-align:left;padding:0 0 10px;border-bottom:1px solid var(--border-subtle)}
.tele-table td{font-size:12px;color:var(--slate-light);padding:9px 0;border-bottom:1px solid rgba(138,155,176,0.06);vertical-align:middle}
.tele-table td:first-child{color:var(--teal);font-family:monospace;font-size:11px}
.tele-table tr:last-child td{border-bottom:none}
.alert-feed{display:flex;flex-direction:column;gap:7px}
.alert-item{display:flex;gap:10px;align-items:flex-start;padding:11px;background:var(--navy);border-left:2px solid transparent}
.alert-item.high{border-left-color:var(--red)}.alert-item.med{border-left-color:var(--amber)}.alert-item.low{border-left-color:var(--teal)}
.alert-dot{width:5px;height:5px;border-radius:50%;margin-top:5px;flex-shrink:0}
.alert-item.high .alert-dot{background:var(--red)}.alert-item.med .alert-dot{background:var(--amber)}.alert-item.low .alert-dot{background:var(--teal)}
.alert-content{flex:1;min-width:0}
.alert-msg{font-size:12px;color:var(--white);line-height:1.4}
.alert-time{font-size:10px;color:var(--slate);margin-top:2px}
.sys-status-grid{display:flex;flex-direction:column;gap:7px}
.sys-item{display:flex;align-items:center;justify-content:space-between;padding:9px 12px;background:var(--navy)}
.sys-name{font-size:12px;color:var(--slate-light)}
.sys-badge{font-size:10px;font-weight:600;letter-spacing:0.06em;padding:3px 8px}
.sys-badge.online{background:rgba(16,185,129,0.12);color:var(--green)}
.sys-badge.ready{background:rgba(0,194,203,0.1);color:var(--teal)}
.sys-badge.offline{background:rgba(229,57,53,0.12);color:var(--red)}
.reg-empty{text-align:center;padding:36px 20px;color:var(--slate);font-size:13px}
@media(max-width:768px){
  nav{padding:12px 16px}.status-badge{display:none}
  .hero{padding:90px 16px 60px}.hero-glow{display:none}
  section{padding:56px 16px}
  .stack-grid{grid-template-columns:1fr}.pricing-grid{grid-template-columns:1fr}
  .stats-bar{gap:24px}
  .flow-steps{flex-direction:column}
  .flow-step{border-right:none;border-bottom:1px solid var(--border-subtle)}
  .flow-step:last-child{border-bottom:none}
  footer{padding:28px 16px}
  #login{padding:16px}.login-panel{padding:32px 24px}
  .dash-body{grid-template-columns:1fr}.dash-sidebar{display:none}
  .kpi-row{grid-template-columns:1fr 1fr}.dash-grid{grid-template-columns:1fr}
  .dash-main{padding:16px}.threat-flow{padding:20px}
}
@media(max-width:400px){
  h1{font-size:28px}.stats-bar{flex-direction:column;gap:20px}.kpi-row{grid-template-columns:1fr}
}
</style>
</head>
<body>

<svg style="display:none" xmlns="http://www.w3.org/2000/svg">
<symbol id="snsmlogo" viewBox="0 0 40 44">
  <path d="M20 1 L37 10.5 L37 29.5 L20 39 L3 29.5 L3 10.5 Z" fill="none" stroke="#00C2CB" stroke-width="1.5"/>
  <path d="M20 7 L32 13.5 L32 26.5 L20 33 L8 26.5 L8 13.5 Z" fill="rgba(0,194,203,0.06)" stroke="rgba(0,194,203,0.25)" stroke-width="0.75"/>
  <path d="M15 15 Q15 12 20 12 Q25 12 25 16 Q25 19 20 20 Q15 21 15 25 Q15 29 20 29 Q25 29 25 26" fill="none" stroke="#00C2CB" stroke-width="2.2" stroke-linecap="round"/>
  <circle cx="20" cy="1" r="1.5" fill="#00C2CB"/>
  <circle cx="37" cy="10.5" r="1" fill="rgba(0,194,203,0.5)"/>
  <circle cx="37" cy="29.5" r="1" fill="rgba(0,194,203,0.5)"/>
  <circle cx="20" cy="39" r="1.5" fill="#00C2CB"/>
  <circle cx="3" cy="29.5" r="1" fill="rgba(0,194,203,0.5)"/>
  <circle cx="3" cy="10.5" r="1" fill="rgba(0,194,203,0.5)"/>
</symbol>
</svg>

<!-- LANDING -->
<div id="landing" class="view active">
  <nav>
    <a class="logo-mark" onclick="showView('landing')">
      <svg width="30" height="33" viewBox="0 0 40 44"><use href="#snsmlogo"/></svg>
      <div class="logo-wordmark">SENTINEL NSM<span>Network Security Monitoring</span></div>
    </a>
    <div class="nav-right">
      <div class="status-badge"><div class="status-dot"></div>System in Development</div>
      <button class="btn-nav" onclick="showView('login')">Admin Access</button>
    </div>
  </nav>

  <div class="hero">
    <div class="hero-grid"></div>
    <div class="hero-glow"></div>
    <div class="hero-content">
      <h1>See the network.<br><span class="accent">Stop the threat.</span></h1>
      <p class="hero-desc">Sentinel NSM is a purpose-built 2U appliance combining Zeek, Suricata, and Wazuh with a local AI correlation layer, delivering enterprise-grade threat detection at a price accessible to Philippine SMEs.</p>
      <div class="hero-actions">
        <button class="btn-primary" onclick="goTo('about')">How it works</button>
        <button class="btn-ghost" onclick="goTo('pricing')">Pricing</button>
      </div>
      <div class="stats-bar">
        <div class="stat"><div class="stat-value">₱300K</div><div class="stat-label">Per appliance, turnkey</div></div>
        <div class="stat"><div class="stat-value">100%</div><div class="stat-label">On-premises processing</div></div>
        <div class="stat"><div class="stat-value">111K+</div><div class="stat-label">Detection rules</div></div>
        <div class="stat"><div class="stat-value">0ms</div><div class="stat-label">Network impact on failure</div></div>
      </div>
    </div>
  </div>

  <section id="about">
    <h2>Three engines.<br>One correlation layer.</h2>
    <p class="section-desc">Sentinel NSM integrates proven open-source security engines with a local AI layer that correlates events across all sources — catching coordinated attacks that evade individual rules.</p>
    <div class="stack-grid">
      <div class="stack-item">
        <svg class="stack-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M9 3H5a2 2 0 00-2 2v4m6-6h10a2 2 0 012 2v4M9 3v18m0 0h10a2 2 0 002-2V9M9 21H5a2 2 0 01-2-2V9m0 0h18"/></svg>
        <div class="stack-name">Zeek</div>
        <div class="stack-desc">Full network metadata — DNS queries, HTTP transactions, SSL certificates, file hashes, and complete connection records.</div>
      </div>
      <div class="stack-item">
        <svg class="stack-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
        <div class="stack-name">Suricata</div>
        <div class="stack-desc">Signature-based IDS/IPS with 111,000+ rules from Emerging Threats, Abuse.ch, and custom POS-specific rulesets.</div>
      </div>
      <div class="stack-item">
        <svg class="stack-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"/></svg>
        <div class="stack-name">Wazuh</div>
        <div class="stack-desc">SIEM and event correlation — log analysis, compliance monitoring, and active response integration.</div>
      </div>
      <div class="stack-item">
        <svg class="stack-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M13 10V3L4 14h7v7l9-11h-7z"/></svg>
        <div class="stack-name">AI Correlation Layer</div>
        <div class="stack-desc">Local quantized LLM analyzes structured event streams — identifies coordinated attack patterns that evade individual rules.</div>
      </div>
      <div class="stack-item">
        <svg class="stack-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg>
        <div class="stack-name">Policy Engine</div>
        <div class="stack-desc">Graduated response — observe, alert, temporary containment, permanent block. AI issues risk scores; enforcement requires admin approval.</div>
      </div>
      <div class="stack-item">
        <svg class="stack-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M3 10h18M7 15h1m4 0h1m-7 4h12a3 3 0 003-3V8a3 3 0 00-3-3H6a3 3 0 00-3 3v8a3 3 0 003 3z"/></svg>
        <div class="stack-name">POS-Aware Detection</div>
        <div class="stack-desc">Payment processor whitelist at the Suricata pass rule level. Legitimate card transactions are never interrupted.</div>
      </div>
    </div>
    <div class="threat-flow">
      <div class="threat-flow-title">Detection flow — POS network attack scenario</div>
      <div class="flow-steps">
        <div class="flow-step"><div class="flow-step-num">01</div><div class="flow-step-name">Traffic Mirror</div><div class="flow-step-detail">Managed switch SPAN port/TUN → eth0 (passive, zero network impact)</div></div>
        <div class="flow-step"><div class="flow-step-num">02</div><div class="flow-step-name">Zeek + Suricata</div><div class="flow-step-detail">Parallel analysis — metadata extraction and signature matching</div></div>
        <div class="flow-step"><div class="flow-step-num">03</div><div class="flow-step-name">Wazuh Pipeline</div><div class="flow-step-detail">Event aggregation, log normalization, compliance checks</div></div>
        <div class="flow-step"><div class="flow-step-num">04</div><div class="flow-step-name">AI Correlation</div><div class="flow-step-detail">Local LLM receives structured event stream — risk score and explanation</div></div>
        <div class="flow-step"><div class="flow-step-num">05</div><div class="flow-step-name">Policy Decision</div><div class="flow-step-detail">Deterministic engine applies graduated response — admin gates enforcement</div></div>
      </div>
    </div>
  </section>

  <section id="hardware" style="padding-top:0">
    <h2>Purpose-built hardware.</h2>
    <p class="section-desc">2U rackmount appliance designed for SME server rooms and data closets. Enhanced airflow for sustained 24/7 operation.</p>
    <div class="stack-grid" style="grid-template-columns:repeat(2,1fr)">
      <div class="stack-item"><div class="stack-name">Server-grade CPU</div><div class="stack-desc">High core count, large cache for sustained packet processing under full Zeek, Suricata, and Wazuh concurrent load.</div></div>
      <div class="stack-item"><div class="stack-name">32 GB DDR4 ECC RAM</div><div class="stack-desc">Error-correcting memory for 24/7 unattended operation. AI correlation layer, NSM engines, and SIEM run concurrently.</div></div>
      <div class="stack-item"><div class="stack-name">1 TB NVMe SSD</div><div class="stack-desc">High write throughput for continuous log ingestion from Zeek, Suricata, and Wazuh event pipelines.</div></div>
      <div class="stack-item"><div class="stack-name">Dual 10GbE NIC</div><div class="stack-desc">First NIC captures a silent copy of all network traffic via the switch SPAN port or TUN. Second NIC handles dashboard access and updates.</div></div>
      <div class="stack-item"><div class="stack-name">Dual Redundant PSU</div><div class="stack-desc">Hot-swappable redundant power supplies ensure continuous operation. Single PSU failure does not interrupt monitoring or detection.</div></div>
      <div class="stack-item"><div class="stack-name">2U Rackmount Chassis</div><div class="stack-desc">Enhanced airflow with optimized fan layout for sustained 24/7 operation in SME server rooms and data closets.</div></div>
    </div>
  </section>

  <section id="pricing">
    <h2>Enterprise security.<br>SME pricing.</h2>
    <p class="section-desc">Turnkey appliance deployment with optional recurring SaaS subscription for fleet management and rule updates.</p>
    <div class="pricing-grid">
      <div class="pricing-card featured">
        <div class="pricing-tier">Appliance</div>
        <div class="pricing-amount">₱300,000</div>
        <div class="pricing-period">One-time, turnkey deployment</div>
        <ul class="pricing-features">
          <li>2U Appliance, fully configured</li>
          <li>Zeek + Suricata + Wazuh + AI layer</li>
          <li>POS-aware detection baseline</li>
          <li>On-site installation and onboarding</li>
          <li>90-day support included</li>
          <li>All processing on-premises — data never leaves site</li>
        </ul>
      </div>
      <div class="pricing-card">
        <div class="pricing-tier">SaaS Subscription</div>
        <div class="pricing-amount">₱10–15K</div>
        <div class="pricing-period">Per month (optional)</div>
        <ul class="pricing-features">
          <li>Fleet management dashboard</li>
          <li>Automatic rule updates (111K+ rules)</li>
          <li>Remote health monitoring</li>
          <li>Remote support — no on-site required</li>
          <li>Priority incident response</li>
          <li>Appliance operates fully without subscription</li>
        </ul>
      </div>
    </div>

    <div style="margin-top:48px">
      <h2 style="font-size:22px;margin-bottom:10px">Stay informed.</h2>
      <p class="section-desc" style="margin-bottom:0">Get notified when Sentinel NSM is available for deployment.</p>
      <div class="notify-form">
        <input class="notify-input" type="email" id="notify-email" placeholder="your@email.com" autocomplete="email">
        <button class="btn-primary" onclick="doRegister()">Notify Me</button>
      </div>
      <div class="notify-msg" id="notify-msg"></div>
    </div>
  </section>

  <footer>
    <a class="logo-mark" onclick="showView('landing')">
      <svg width="24" height="26" viewBox="0 0 40 44"><use href="#snsmlogo"/></svg>
      <div class="logo-wordmark" style="font-size:11px">SENTINEL NSM<span>Network Security Monitoring</span></div>
    </a>
    <p>Copyright &reg; 2026 Sentinel NSM. All rights reserved.</p>
  </footer>
</div>

<!-- LOGIN -->
<div id="login" class="view">
  <div class="login-panel">
    <div class="login-logo">
      <a class="logo-mark" onclick="showView('landing')">
        <svg width="30" height="33" viewBox="0 0 40 44"><use href="#snsmlogo"/></svg>
        <div class="logo-wordmark">SENTINEL NSM<span>Network Security Monitoring</span></div>
      </a>
    </div>
    <div class="login-title">Admin Access</div>
    <div class="login-sub">Restricted — authorized personnel only</div>
    <form method="POST" action="/">
    <div class="form-group">
      <label class="form-label" for="username">Username</label>
      <input class="form-input" type="text" id="username" name="login_username" placeholder="admin" autocomplete="off" autocapitalize="none" autocorrect="off" spellcheck="false">
    </div>
    <div class="form-group">
      <label class="form-label" for="password">Password</label>
      <input class="form-input" type="password" id="password" name="login_password" placeholder="••••••••" autocomplete="current-password">
    </div>
    <button class="btn-login" type="submit">Authenticate</button>
    <?php if ($login_error): ?>
    <div class="login-error" style="display:block">Invalid credentials. Access denied.</div>
    <?php endif; ?>
    </form>
    <div class="login-footer"><a onclick="showView('landing')">← Back to sentinel-nsm.com</a></div>
  </div>
</div>

<!-- DASHBOARD -->
<div id="dashboard" class="view">
  <div class="dash-nav">
    <a class="logo-mark" onclick="showView('landing')">
      <svg width="26" height="29" viewBox="0 0 40 44"><use href="#snsmlogo"/></svg>
      <div class="logo-wordmark" style="font-size:12px">SENTINEL NSM<span>Admin Console</span></div>
    </a>
    <div class="dash-nav-right">
      <div class="dash-user">admin</div>
      <button class="btn-logout" onclick="window.location.href='?logout=1'">Sign out</button>
    </div>
  </div>
  <div class="dash-body">
    <div class="dash-sidebar">
      <div class="sidebar-section">
        <div class="sidebar-label">Overview</div>
        <div class="sidebar-item active">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/></svg>Dashboard
        </div>
        <div class="sidebar-item">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M13 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V9z"/><polyline points="13 2 13 9 20 9"/></svg>Telemetry
        </div>
        <div class="sidebar-item">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/><circle cx="9" cy="7" r="4"/></svg>Registrations
        </div>
      </div>
      <div class="sidebar-section">
        <div class="sidebar-label">System</div>
        <div class="sidebar-item">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg>System Status
        </div>
      </div>
    </div>
    <div class="dash-main">
      <div class="dash-title">Operations Overview</div>
      <div class="dash-subtitle" id="dash-time">—</div>
      <div class="kpi-row">
        <div class="kpi-card"><div class="kpi-label">Total Visits</div><div class="kpi-value" id="kpi-visits">—</div><div class="kpi-delta">Live from MariaDB</div></div>
        <div class="kpi-card"><div class="kpi-label">Registrations</div><div class="kpi-value" id="kpi-regs">—</div><div class="kpi-delta">Launch signups</div></div>
        <div class="kpi-card"><div class="kpi-label">Application</div><div class="kpi-value" id="kpi-status" style="font-size:15px;padding-top:6px">—</div><div class="kpi-delta" id="kpi-host">—</div></div>
        <div class="kpi-card"><div class="kpi-label">PHP Runtime</div><div class="kpi-value" id="kpi-php" style="font-size:16px;padding-top:5px">—</div><div class="kpi-delta">App server</div></div>
      </div>
      <div class="dash-grid">
        <div class="dash-panel">
          <div class="panel-header"><div class="panel-title">Recent Web Telemetry</div><div class="panel-meta" id="tele-count">—</div></div>
          <table class="tele-table">
            <thead><tr><th>Timestamp</th><th>Path</th><th>User Agent</th></tr></thead>
            <tbody id="tele-body"><tr><td colspan="3" style="color:var(--slate);padding:20px 0;font-size:12px">Loading...</td></tr></tbody>
          </table>
        </div>
        <div style="display:flex;flex-direction:column;gap:14px">
          <div class="dash-panel">
            <div class="panel-header"><div class="panel-title">System Health</div><div class="panel-meta">Live</div></div>
            <div class="sys-status-grid" id="sys-status"><div class="sys-item"><span class="sys-name">Loading...</span></div></div>
          </div>
          <div class="dash-panel">
            <div class="panel-header"><div class="panel-title">Security Events</div><div class="panel-meta">Simulated</div></div>
            <div class="alert-feed">
              <div class="alert-item med"><div class="alert-dot"></div><div class="alert-content"><div class="alert-msg">Unusual outbound DNS query pattern on POS-03</div><div class="alert-time">2026-09-03 07:41:22 — Zeek · MEDIUM</div></div></div>
              <div class="alert-item low"><div class="alert-dot"></div><div class="alert-content"><div class="alert-msg">New device fingerprint on management VLAN</div><div class="alert-time">2026-09-03 06:18:04 — Suricata · LOW</div></div></div>
              <div class="alert-item low"><div class="alert-dot"></div><div class="alert-content"><div class="alert-msg">SSL certificate change on payment gateway endpoint</div><div class="alert-time">2026-09-03 05:02:55 — Zeek · LOW</div></div></div>
            </div>
          </div>
        </div>
      </div>
      <div class="dash-panel">
        <div class="panel-header"><div class="panel-title">Launch Registrations</div><div class="panel-meta" id="reg-count">—</div></div>
        <div id="reg-body"><div class="reg-empty">Loading...</div></div>
      </div>
    </div>
  </div>
  <footer style="margin-top:0">
    <p>Copyright &reg; 2026 Sentinel NSM. All rights reserved.</p>
  </footer>
</div>

<script>
const ADMIN_USER='';
const ADMIN_PASS='';

function showView(id){
  document.querySelectorAll('.view').forEach(v=>v.classList.remove('active'));
  document.getElementById(id).classList.add('active');
  window.scrollTo(0,0);
}

function goTo(id){
  document.getElementById(id).scrollIntoView({behavior:'smooth'});
}

function doLogout(){
  window.location.href='?logout=1';
}

async function doRegister(){
  const email = document.getElementById('notify-email').value.trim();
  const msg = document.getElementById('notify-msg');
  if (!email) {
    msg.className = 'notify-msg err';
    msg.style.display = 'block';
    msg.textContent = 'Please enter a valid email address.';
    return;
  }
  try {
    const res = await fetch('/', {
      method: 'POST',
      headers: {'Content-Type': 'application/x-www-form-urlencoded'},
      body: 'email=' + encodeURIComponent(email)
    });
    const data = await res.json();
    msg.className = 'notify-msg ' + (data.success ? 'ok' : 'err');
    msg.style.display = 'block';
    msg.textContent = data.message;
    if (data.success) document.getElementById('notify-email').value = '';
  } catch(e) {
    msg.className = 'notify-msg err';
    msg.style.display = 'block';
    msg.textContent = 'Request failed. Please try again.';
  }
}

function updateClock(){
  const el=document.getElementById('dash-time');
  if(el) el.textContent=new Date().toLocaleString('en-PH',{weekday:'long',year:'numeric',month:'long',day:'numeric',hour:'2-digit',minute:'2-digit',second:'2-digit'});
}

async function loadDashboard(){
  updateClock();
  setInterval(updateClock,1000);
  try{
    const res=await fetch('?api=dashboard');
    if(!res.ok) throw new Error();
    const d=await res.json();
    renderDashboard(d);
  } catch(e){
    renderDashboard({
      visits:0,registrations:0,
      status:{application:'ONLINE',php:'<?= $php_version ?>',mariadb:'<?= $mariadb_status ?>',host:'<?= $hostname ?>'},
      telemetry:[],registrations_list:[]
    });
  }
}

function renderDashboard(d){
  document.getElementById('kpi-visits').textContent=d.visits??'—';
  document.getElementById('kpi-regs').textContent=d.registrations??'—';
  document.getElementById('kpi-status').textContent=d.status?.application??'—';
  document.getElementById('kpi-php').textContent=d.status?.php??'—';
  document.getElementById('kpi-host').textContent=d.status?.host??'—';
  const mdb=d.status?.mariadb??'—';
  document.getElementById('sys-status').innerHTML=`
    <div class="sys-item"><span class="sys-name">Application</span><span class="sys-badge online">${d.status?.application??'—'}</span></div>
    <div class="sys-item"><span class="sys-name">PHP Runtime</span><span class="sys-badge ready">${d.status?.php??'—'}</span></div>
    <div class="sys-item"><span class="sys-name">MariaDB</span><span class="sys-badge ${mdb==='ONLINE'?'online':'offline'}">${mdb}</span></div>
    <div class="sys-item"><span class="sys-name">Host Pod</span><span class="sys-badge ready">${d.status?.host??'—'}</span></div>
  `;
  const tele=d.telemetry??[];
  document.getElementById('tele-count').textContent=tele.length+' entries';
  document.getElementById('tele-body').innerHTML=tele.length===0
    ?'<tr><td colspan="3" style="color:var(--slate);padding:20px 0;font-size:12px">No telemetry recorded</td></tr>'
    :tele.map(t=>`<tr><td>${t.timestamp}</td><td style="color:var(--white)">${t.path}</td><td style="max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${t.ua}</td></tr>`).join('');
  const regs=d.registrations_list??[];
  document.getElementById('reg-count').textContent=regs.length+' total';
  document.getElementById('reg-body').innerHTML=regs.length===0
    ?'<div class="reg-empty">No registrations yet.</div>'
    :`<table class="tele-table"><thead><tr><th>Email</th><th>Registered</th></tr></thead><tbody>${regs.map(r=>`<tr><td>${r.email}</td><td style="color:var(--slate-light)">${r.created_at}</td></tr>`).join('')}</tbody></table>`;
}

// Init — show correct view based on PHP session state
<?php if ($is_auth): ?>
document.addEventListener('DOMContentLoaded',()=>{ showView('dashboard'); loadDashboard(); });
<?php elseif (isset($_GET['view']) && $_GET['view']==='login'): ?>
document.addEventListener('DOMContentLoaded',()=>{ showView('login'); });
<?php else: ?>
document.addEventListener('DOMContentLoaded',()=>{ showView('landing'); });
<?php endif; ?>
</script>
</body>
</html>
