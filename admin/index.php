<?php
/**
 * Ahpu website admin: manage the client logos shown on the home page.
 *
 * Data:    /data/clients.json        (public, read by the home page)
 * Logos:   /uploads/clients/*.webp   (public, scripts blocked by .htaccess)
 * Secrets: /private/*.php            (denied by .htaccess; PHP files so they never print even if served)
 */
declare(strict_types=1);

$ROOT   = dirname(__DIR__);
$PRIV   = $ROOT . '/private';
$DATA   = $ROOT . '/data/clients.json';
$UPDIR  = $ROOT . '/uploads/clients';
$AUTH   = $PRIV . '/auth.php';
$TRIES  = $PRIV . '/attempts.php';

$cfg = is_file($PRIV . '/config.php') ? (include $PRIV . '/config.php') : [];
$cfg += ['admin_email' => 'admin@ahpuapp.com', 'setup_key' => '', 'session_minutes' => 30, 'max_attempts' => 5, 'lock_minutes' => 15, 'max_upload_mb' => 5, 'logo_size' => 400];

/* ---------- transport & headers ---------- */
$host    = $_SERVER['HTTP_HOST'] ?? '';
$isHttps = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
        || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https')
        || (($_SERVER['SERVER_PORT'] ?? '') === '443');
$isLocal = (bool)preg_match('/^(localhost|127\.0\.0\.1|\[::1\])(:\d+)?$|\.(test|localhost)(:\d+)?$/i', $host);
if (!$isHttps && !$isLocal) {
    header('Location: https://' . $host . ($_SERVER['REQUEST_URI'] ?? '/admin/'), true, 301);
    exit;
}
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
header('X-Robots-Tag: noindex, nofollow');
header('Cache-Control: no-store, max-age=0');
header("Content-Security-Policy: default-src 'self'; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; script-src 'self' 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
if ($isHttps) header('Strict-Transport-Security: max-age=31536000');

/* ---------- session ---------- */
session_name('ahpu_admin');
session_set_cookie_params(['lifetime' => 0, 'path' => '/admin', 'secure' => $isHttps, 'httponly' => true, 'samesite' => 'Strict']);
ini_set('session.use_strict_mode', '1');
session_start();
$now = time();
if (!empty($_SESSION['ok'])) {
    $ua = hash('sha256', $_SERVER['HTTP_USER_AGENT'] ?? '');
    if (($now - ($_SESSION['last'] ?? 0)) > $cfg['session_minutes'] * 60 || ($_SESSION['ua'] ?? '') !== $ua) {
        $_SESSION = [];
        session_regenerate_id(true);
        flash('Signed out after inactivity. Please sign in again.', 'warn');
    } else {
        $_SESSION['last'] = $now;
    }
}
$_SESSION['csrf'] ??= bin2hex(random_bytes(32));

/* ---------- small helpers ---------- */
function e(string $s): string { return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }
function flash(string $msg, string $type = 'ok'): void { $_SESSION['flash'] = [$msg, $type]; }
const HOME_LIMIT = 20; // how many clients the home page shows (the first N in the list)
const TABS = ['clients' => 'Clients', 'add' => 'Add client', 'password' => 'Change password'];
$GLOBALS['back_tab'] = null;
function back(): never {
    $t = $GLOBALS['back_tab'] ?? null;
    header('Location: ./' . ($t && isset(TABS[$t]) && $t !== 'clients' ? '?tab=' . $t : ''), true, 303);
    exit;
}
function load_php(string $f): array { if (!is_file($f)) return []; $v = include $f; return is_array($v) ? $v : []; }
function save_php(string $f, array $data): void {
    $tmp = $f . '.' . bin2hex(random_bytes(4)) . '.tmp';
    if (file_put_contents($tmp, "<?php\nreturn " . var_export($data, true) . ";\n", LOCK_EX) === false) throw new RuntimeException('Cannot write to the private folder. Check its permissions.');
    rename($tmp, $f);
    if (function_exists('opcache_invalidate')) @opcache_invalidate($f, true);
}
function client_ip(): string { return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0'; }
function slugify(string $s): string {
    $s = strtolower(trim(preg_replace('/[^A-Za-z0-9]+/', '-', $s) ?? '', '-'));
    return substr($s, 0, 40) ?: 'client';
}

/* ---------- brute-force protection ---------- */
function attempts_state(string $file, array $cfg): array {
    $all = load_php($file); $now = time(); $win = $cfg['lock_minutes'] * 60;
    foreach ($all as $k => $v) if (($v['t'] ?? 0) + $win < $now && ($v['lock'] ?? 0) < $now) unset($all[$k]);
    return $all;
}
function locked_for(string $file, array $cfg): int {
    $all = attempts_state($file, $cfg); $now = time(); $ip = client_ip();
    $lock = max($all[$ip]['lock'] ?? 0, $all['*']['lock'] ?? 0);
    return $lock > $now ? $lock - $now : 0;
}
function record_fail(string $file, array $cfg): void {
    $all = attempts_state($file, $cfg); $now = time(); $ip = client_ip();
    foreach ([$ip => $cfg['max_attempts'], '*' => $cfg['max_attempts'] * 6] as $k => $max) {
        $r = $all[$k] ?? ['n' => 0, 't' => $now, 'lock' => 0];
        $r['n']++;
        if ($r['n'] >= $max) { $r['lock'] = $now + $cfg['lock_minutes'] * 60; $r['n'] = 0; $r['t'] = $now; }
        $all[$k] = $r;
    }
    save_php($file, $all);
    usleep(random_int(400000, 900000));
}
function clear_fails(string $file, array $cfg): void { $all = attempts_state($file, $cfg); unset($all[client_ip()]); save_php($file, $all); }

/* ---------- clients data ---------- */
function load_clients(string $f): array {
    if (!is_file($f)) return [];
    $j = json_decode((string)file_get_contents($f), true);
    return is_array($j['clients'] ?? null) ? array_values($j['clients']) : [];
}
function save_clients(string $f, array $clients): void {
    $json = json_encode(['updated' => gmdate('c'), 'clients' => array_values($clients)], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    $tmp = $f . '.' . bin2hex(random_bytes(4)) . '.tmp';
    if (file_put_contents($tmp, $json . "\n", LOCK_EX) === false) throw new RuntimeException('Cannot write data/clients.json. Check folder permissions.');
    rename($tmp, $f);
}
function find_index(array $clients, string $id): int {
    foreach ($clients as $i => $c) if (($c['id'] ?? '') === $id) return $i;
    throw new RuntimeException('That client no longer exists.');
}
function clean_name(string $n): string {
    $n = trim(preg_replace('/\s+/u', ' ', strip_tags($n)) ?? '');
    if ($n === '' || mb_strlen($n) > 60) throw new RuntimeException('Name must be 1 to 60 characters.');
    return $n;
}
function delete_logo(string $root, string $rel): void {
    if (preg_match('#^uploads/clients/[a-z0-9-]+\.webp$#', $rel) && is_file($root . '/' . $rel)) @unlink($root . '/' . $rel);
}
/** Validate any uploaded image, re-encode it as WebP (strips anything hidden inside), return its public path. */
function save_logo(array $f, string $name, string $updir, array $cfg): string {
    if (($f['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK) {
        throw new RuntimeException(($f['error'] ?? 0) === UPLOAD_ERR_INI_SIZE || ($f['error'] ?? 0) === UPLOAD_ERR_FORM_SIZE ? 'That file is too big.' : 'Please choose a logo image.');
    }
    if (!is_uploaded_file($f['tmp_name'])) throw new RuntimeException('Upload failed. Please try again.');
    if ($f['size'] > $cfg['max_upload_mb'] * 1024 * 1024) throw new RuntimeException('Logo must be under ' . $cfg['max_upload_mb'] . ' MB.');
    $info = @getimagesize($f['tmp_name']);
    $types = ['image/jpeg' => 'imagecreatefromjpeg', 'image/png' => 'imagecreatefrompng', 'image/webp' => 'imagecreatefromwebp', 'image/gif' => 'imagecreatefromgif'];
    if (!$info || !isset($types[$info['mime']])) throw new RuntimeException('Logo must be a JPG, PNG, WebP or GIF image.');
    [$w, $h] = $info;
    if ($w < 32 || $h < 32 || $w > 6000 || $h > 6000) throw new RuntimeException('Logo size must be between 32 and 6000 pixels.');
    if (!function_exists('imagewebp')) throw new RuntimeException('This server\'s PHP has no WebP support (GD). Ask hosting to enable it.');
    $src = @$types[$info['mime']]($f['tmp_name']);
    if (!$src) throw new RuntimeException('Could not read that image.');
    $max = (int)$cfg['logo_size'];
    $r = min(1, $max / $w, $max / $h);
    $nw = max(1, (int)round($w * $r)); $nh = max(1, (int)round($h * $r));
    $dst = imagecreatetruecolor($nw, $nh);
    imagealphablending($dst, false); imagesavealpha($dst, true);
    imagefill($dst, 0, 0, imagecolorallocatealpha($dst, 0, 0, 0, 127));
    imagecopyresampled($dst, $src, 0, 0, 0, 0, $nw, $nh, $w, $h);
    if (!is_dir($updir) && !mkdir($updir, 0755, true)) throw new RuntimeException('Cannot create uploads/clients folder.');
    $file = slugify($name) . '-' . bin2hex(random_bytes(3)) . '.webp';
    if (!imagewebp($dst, $updir . '/' . $file, 85)) throw new RuntimeException('Could not save the logo.');
    return 'uploads/clients/' . $file;
}

/* ---------- actions (POST only, CSRF checked) ---------- */
$auth = load_php($AUTH);
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!hash_equals($_SESSION['csrf'], (string)($_POST['csrf'] ?? ''))) { flash('Your session expired. Please try again.', 'err'); back(); }
    $act = (string)($_POST['act'] ?? '');
    try {
        if ($act === 'setup') {
            if (!empty($auth['hash'])) back();
            if ($wait = locked_for($TRIES, $cfg)) throw new RuntimeException('Too many attempts. Try again in ' . ceil($wait / 60) . ' min.');
            $key = (string)$cfg['setup_key'];
            if (strlen($key) < 24 || str_starts_with($key, 'PUT-')) throw new RuntimeException('Setup key is not configured in private/config.php.');
            if (!hash_equals($key, (string)($_POST['key'] ?? ''))) { record_fail($TRIES, $cfg); throw new RuntimeException('Wrong setup key.'); }
            $p = (string)($_POST['pw'] ?? '');
            if (strlen($p) < 10) throw new RuntimeException('Password must be at least 10 characters.');
            if ($p !== (string)($_POST['pw2'] ?? '')) throw new RuntimeException('Passwords do not match.');
            save_php($AUTH, ['hash' => password_hash($p, PASSWORD_DEFAULT), 'set' => gmdate('c')]);
            session_regenerate_id(true);
            $_SESSION['ok'] = 1; $_SESSION['last'] = $now; $_SESSION['ua'] = hash('sha256', $_SERVER['HTTP_USER_AGENT'] ?? '');
            $_SESSION['csrf'] = bin2hex(random_bytes(32));
            flash('Password created. You are signed in.');
        } elseif ($act === 'login') {
            if ($wait = locked_for($TRIES, $cfg)) throw new RuntimeException('Too many wrong passwords. Try again in ' . ceil($wait / 60) . ' min.');
            $emailOk = hash_equals(strtolower(trim((string)$cfg['admin_email'])), strtolower(trim((string)($_POST['email'] ?? ''))));
            $pwOk = !empty($auth['hash']) && password_verify((string)($_POST['pw'] ?? ''), $auth['hash']);
            if (!$emailOk || !$pwOk) { record_fail($TRIES, $cfg); throw new RuntimeException('Wrong email or password.'); }
            clear_fails($TRIES, $cfg);
            if (password_needs_rehash($auth['hash'], PASSWORD_DEFAULT)) save_php($AUTH, ['hash' => password_hash((string)$_POST['pw'], PASSWORD_DEFAULT), 'set' => gmdate('c')]);
            session_regenerate_id(true);
            $_SESSION['ok'] = 1; $_SESSION['last'] = $now; $_SESSION['ua'] = hash('sha256', $_SERVER['HTTP_USER_AGENT'] ?? '');
            $_SESSION['csrf'] = bin2hex(random_bytes(32));
        } else {
            if (empty($_SESSION['ok'])) back();
            $clients = load_clients($DATA);
            switch ($act) {
                case 'logout':
                    $_SESSION = []; session_regenerate_id(true); back();
                case 'add':
                    $GLOBALS['back_tab'] = 'add';
                    $name = clean_name((string)($_POST['name'] ?? ''));
                    if (count($clients) >= 200) throw new RuntimeException('Client limit reached (200).');
                    $logo = save_logo($_FILES['logo'] ?? [], $name, $UPDIR, $cfg);
                    array_unshift($clients, ['id' => slugify($name) . '-' . bin2hex(random_bytes(2)), 'name' => $name, 'logo' => $logo]); // newest first
                    save_clients($DATA, $clients);
                    $GLOBALS['back_tab'] = 'clients';
                    flash('"' . $name . '" added.');
                    break;
                case 'edit':
                    $i = find_index($clients, (string)($_POST['id'] ?? ''));
                    $clients[$i]['name'] = clean_name((string)($_POST['name'] ?? ''));
                    if (($_FILES['logo']['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_NO_FILE) {
                        $new = save_logo($_FILES['logo'], $clients[$i]['name'], $UPDIR, $cfg);
                        delete_logo($ROOT, (string)$clients[$i]['logo']);
                        $clients[$i]['logo'] = $new;
                    }
                    save_clients($DATA, $clients);
                    flash('"' . $clients[$i]['name'] . '" saved.');
                    break;
                case 'delete':
                    $i = find_index($clients, (string)($_POST['id'] ?? ''));
                    $gone = $clients[$i];
                    array_splice($clients, $i, 1);
                    save_clients($DATA, $clients);
                    delete_logo($ROOT, (string)$gone['logo']);
                    flash('"' . $gone['name'] . '" removed.');
                    break;
                case 'reorder':
                    $ids = array_values(array_filter(explode(',', (string)($_POST['order'] ?? ''))));
                    $byId = array_column($clients, null, 'id');
                    if (count($ids) !== count($byId) || array_diff($ids, array_keys($byId))) throw new RuntimeException('The list changed meanwhile. Reload and try again.');
                    save_clients($DATA, array_map(fn($id) => $byId[$id], $ids));
                    flash('Order saved.');
                    break;
                case 'password':
                    $GLOBALS['back_tab'] = 'password';
                    if (!password_verify((string)($_POST['cur'] ?? ''), $auth['hash'] ?? '')) throw new RuntimeException('Current password is wrong.');
                    $p = (string)($_POST['pw'] ?? '');
                    if (strlen($p) < 10) throw new RuntimeException('New password must be at least 10 characters.');
                    if ($p !== (string)($_POST['pw2'] ?? '')) throw new RuntimeException('New passwords do not match.');
                    save_php($AUTH, ['hash' => password_hash($p, PASSWORD_DEFAULT), 'set' => gmdate('c')]);
                    session_regenerate_id(true);
                    flash('Password changed.');
                    break;
                default:
                    throw new RuntimeException('Unknown action.');
            }
        }
    } catch (Throwable $ex) {
        flash($ex instanceof RuntimeException ? $ex->getMessage() : 'Something went wrong. Please try again.', 'err');
    }
    back();
}

/* ---------- view ---------- */
$flash = $_SESSION['flash'] ?? null; unset($_SESSION['flash']);
$mode = empty($auth['hash']) ? 'setup' : (empty($_SESSION['ok']) ? 'login' : 'app');
$clients = $mode === 'app' ? load_clients($DATA) : [];
$csrf = e($_SESSION['csrf']);
$tab = (string)($_GET['tab'] ?? 'clients');
if (!isset(TABS[$tab])) $tab = 'clients';
$maxBytes = $cfg['max_upload_mb'] * 1024 * 1024;
?><!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="robots" content="noindex, nofollow">
<title>Ahpu Admin</title>
<link rel="icon" href="../img/favicon.ico?v=2" sizes="48x48">
<link rel="icon" type="image/png" sizes="32x32" href="../img/favicon-32.png?v=2">
<link rel="icon" type="image/png" sizes="192x192" href="../img/icon-192.png?v=2">
<link rel="apple-touch-icon" href="../img/apple-touch-icon.png?v=2">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=Sora:wght@600;700&display=swap" rel="stylesheet">
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#070a14;--card:#0f1528;--line:rgba(255,255,255,.08);--line2:rgba(255,255,255,.14);--text:#e8ecf6;--muted:#9aa4bd;--dim:#6b7590;--green:#34d399;--red:#f87171;--amber:#fbbf24;--grad:linear-gradient(110deg,#22c3ee 0%,#6d8cff 40%,#a46bf5 70%,#d946ef 100%)}
body{font-family:'Inter',system-ui,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;-webkit-font-smoothing:antialiased;background-image:radial-gradient(700px 400px at 10% -10%,rgba(29,111,224,.25),transparent 60%),radial-gradient(700px 400px at 100% 0%,rgba(124,58,237,.22),transparent 60%)}
a{color:inherit}
h1,h2{font-family:'Sora',sans-serif;letter-spacing:-.02em;color:#fff}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:.4rem;padding:.65rem 1.05rem;border-radius:11px;font:inherit;font-weight:600;font-size:.9rem;border:1px solid var(--line2);background:rgba(255,255,255,.05);color:var(--text);cursor:pointer;text-decoration:none;transition:background .2s,transform .15s}
.btn:hover{background:rgba(255,255,255,.1)}
.btn:active{transform:scale(.97)}
.btn-main{background:var(--grad);border:0;color:#fff}
.btn-danger{color:var(--red);border-color:rgba(248,113,113,.3);background:rgba(248,113,113,.06)}
.btn-danger:hover{background:rgba(248,113,113,.15)}
.btn-sm{padding:.45rem .7rem;font-size:.8rem;border-radius:9px}
input[type=text],input[type=password],input[type=email]{width:100%;font:inherit;font-size:.95rem;color:#fff;background:rgba(255,255,255,.04);border:1px solid var(--line2);border-radius:11px;padding:.7rem .85rem;outline:none;transition:border-color .2s,box-shadow .2s}
input:focus{border-color:#8b5cf6;box-shadow:0 0 0 3px rgba(139,92,246,.25)}
label{display:block;font-size:.8rem;color:var(--muted);margin:0 0 .35rem}
.field{margin-bottom:14px}
.card{background:rgba(15,21,40,.85);border:1px solid var(--line2);border-radius:20px;padding:24px;backdrop-filter:blur(10px)}
.flash{padding:.8rem 1rem;border-radius:12px;margin-bottom:16px;font-size:.9rem;border:1px solid}
.flash.ok{background:rgba(52,211,153,.1);border-color:rgba(52,211,153,.35);color:#a7f3d0}
.flash.err{background:rgba(248,113,113,.1);border-color:rgba(248,113,113,.35);color:#fecaca}
.flash.warn{background:rgba(251,191,36,.1);border-color:rgba(251,191,36,.35);color:#fde68a}
.auth{min-height:100vh;display:grid;place-items:center;padding:24px}
.auth .card{width:100%;max-width:400px}
.auth img{height:40px;margin-bottom:18px}
.auth h1{font-size:1.4rem;margin-bottom:.3rem}
.auth p{color:var(--muted);font-size:.88rem;margin-bottom:18px}
.auth .btn{width:100%;margin-top:4px;padding:.8rem}
.head{display:flex;justify-content:space-between;align-items:flex-end;gap:12px;margin:10px 0 16px;flex-wrap:wrap}
.head h1{font-size:1.6rem}
.head p{color:var(--muted);font-size:.9rem}
.drop{width:150px;height:150px;border-radius:16px;border:1.5px dashed var(--line2);display:grid;place-items:center;text-align:center;font-size:.72rem;color:var(--dim);cursor:pointer;overflow:hidden;background:#fff0;position:relative;transition:border-color .2s}
.drop:hover{border-color:#8b5cf6}
.drop img{position:absolute;inset:0;width:100%;height:100%;object-fit:contain;background:#fff}
.drop input{position:absolute;inset:0;opacity:0;cursor:pointer}
.list{display:grid;gap:8px}
.row{display:grid;grid-template-columns:28px 64px 1fr auto;gap:12px;align-items:center;background:rgba(255,255,255,.03);border:1px solid var(--line);border-radius:14px;padding:10px 12px;transition:background .2s,border-color .2s,opacity .2s}
.row.dragging{opacity:.4}
.row.over{border-color:#8b5cf6;background:rgba(139,92,246,.08)}
.handle{cursor:grab;color:var(--dim);font-size:1.1rem;text-align:center;user-select:none;line-height:1}
.thumb{width:64px;height:64px;border-radius:12px;object-fit:contain;background:#fff;border:1px solid var(--line)}
.name{font-weight:600;color:#fff;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.pos{font-size:.75rem;color:var(--dim);display:flex;align-items:center;gap:8px}
.pos .home{font-style:normal;font-size:.68rem;font-weight:600;color:#a7f3d0;background:rgba(52,211,153,.1);border:1px solid rgba(52,211,153,.3);border-radius:999px;padding:.05rem .5rem}
.pos .home[hidden]{display:none}
.head p a{color:#c4b5fd}
.acts{display:flex;gap:6px;align-items:center;flex-wrap:wrap;justify-content:flex-end}
.mv{display:flex;flex-direction:column;gap:2px}
.mv button{background:none;border:1px solid var(--line);color:var(--muted);border-radius:6px;width:26px;height:20px;cursor:pointer;font-size:.65rem}
.mv button:hover{color:#fff;border-color:var(--line2)}
.edit{grid-column:2/-1;display:none;grid-template-columns:1fr auto auto;gap:8px;align-items:center;padding-top:6px}
.row.editing .edit{display:grid}
.file-btn{position:relative;overflow:hidden}
.file-btn input{position:absolute;inset:0;opacity:0;cursor:pointer}
.savebar{position:sticky;bottom:16px;margin-top:16px;display:none;justify-content:space-between;align-items:center;gap:12px;padding:12px 16px;border-radius:14px;background:rgba(15,21,40,.95);border:1px solid rgba(139,92,246,.5);box-shadow:0 20px 40px -10px rgba(0,0,0,.6)}
.savebar.show{display:flex}
.empty{text-align:center;color:var(--dim);padding:40px;border:1px dashed var(--line2);border-radius:16px}
.shell{display:grid;grid-template-columns:240px minmax(0,1fr);min-height:100vh}
.side{position:sticky;top:0;height:100vh;display:flex;flex-direction:column;gap:22px;padding:22px 14px;border-right:1px solid var(--line);background:rgba(7,10,20,.6);backdrop-filter:blur(10px)}
.brand{display:flex;align-items:center;gap:10px;text-decoration:none;padding:0 8px}
.brand img{height:30px;width:auto;display:block}
.brand span{font-family:'Sora',sans-serif;font-size:.78rem;font-weight:600;color:var(--muted);border:1px solid var(--line2);border-radius:999px;padding:.15rem .55rem}
.nav{display:flex;flex-direction:column;gap:4px}
.nav a{display:flex;align-items:center;gap:11px;padding:.68rem .8rem;border-radius:11px;color:var(--muted);text-decoration:none;font-weight:500;font-size:.92rem;border:1px solid transparent;transition:background .2s,color .2s}
.nav a:hover{background:rgba(255,255,255,.05);color:#fff}
.nav a.on{background:rgba(139,92,246,.14);border-color:rgba(139,92,246,.35);color:#fff}
.nav svg{width:18px;height:18px;flex:none;fill:none;stroke:currentColor;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}
.nav a.on svg{stroke:#c4b5fd}
.nav i{font-style:normal}
.nav .cnt{margin-left:auto;font-size:.72rem;font-weight:600;background:rgba(255,255,255,.08);border-radius:999px;padding:.1rem .5rem;color:var(--text)}
.side-foot{margin-top:auto;display:flex;flex-direction:column;gap:8px}
.side-foot .btn,.side-foot form{width:100%}
.main{padding:30px clamp(18px,4vw,44px) 60px;max-width:1000px;width:100%}
.add{display:grid;grid-template-columns:150px minmax(0,1fr);gap:22px;align-items:start;max-width:640px}
.add-f{display:flex;flex-direction:column;gap:12px}
.add-f .field{margin:0}
.add-f .btn{align-self:flex-start}
.narrow{max-width:440px}
.empty a{color:#c4b5fd}
.hint{font-size:.78rem;color:var(--dim);margin-top:6px}
@media(max-width:860px){
  .shell{grid-template-columns:minmax(0,1fr)}
  .side{min-width:0}
  .side{position:sticky;top:0;z-index:5;height:auto;flex-direction:row;flex-wrap:wrap;align-items:center;gap:10px;padding:12px 14px;border-right:0;border-bottom:1px solid var(--line);background:rgba(7,10,20,.92)}
  .nav{order:3;flex-direction:row;width:100%;overflow-x:auto;gap:6px;scrollbar-width:none}
  .nav a{white-space:nowrap;padding:.5rem .6rem;gap:7px;font-size:.84rem}
  .nav svg{width:16px;height:16px}
  .nav .lg-only{display:none}
  .nav a span::first-letter{text-transform:uppercase}
  .side-foot{margin:0 0 0 auto;flex-direction:row}
  .side-foot .btn,.side-foot form{width:auto}
  .main{padding-top:22px}
}
@media(max-width:640px){
  .add{grid-template-columns:1fr}.add-f .btn{align-self:stretch}
  .drop{width:120px;height:120px}
  .row{grid-template-columns:26px 52px 1fr}
  .thumb{width:52px;height:52px}
  .acts{grid-column:1/-1;justify-content:flex-start}
  .edit{grid-column:1/-1;grid-template-columns:1fr}
}
</style>
</head>
<body>
<?php if ($mode !== 'app'): ?>
<div class="auth">
  <div class="card">
    <img src="../img/ahpu-logo-mark.png" alt="Ahpu" width="86" height="40">
    <?php if ($flash): ?><div class="flash <?= e($flash[1]) ?>"><?= e($flash[0]) ?></div><?php endif; ?>
    <?php if ($mode === 'setup'): ?>
      <h1>Create admin password</h1>
      <p>First-time setup. Enter the setup key from <b>private/config.php</b> and choose a password.</p>
      <form method="post" autocomplete="off">
        <input type="hidden" name="csrf" value="<?= $csrf ?>"><input type="hidden" name="act" value="setup">
        <input type="email" name="username" value="<?= e((string)$cfg['admin_email']) ?>" autocomplete="username" readonly hidden>
        <div class="field"><label for="key">Setup key</label><input type="password" id="key" name="key" required></div>
        <div class="field"><label for="pw">New password (10+ characters)</label><input type="password" id="pw" name="pw" minlength="10" required autocomplete="new-password"></div>
        <div class="field"><label for="pw2">Repeat password</label><input type="password" id="pw2" name="pw2" minlength="10" required autocomplete="new-password"></div>
        <button class="btn btn-main">Create password</button>
      </form>
    <?php else: ?>
      <h1>Sign in</h1>
      <p>Website admin · client logos</p>
      <form method="post">
        <input type="hidden" name="csrf" value="<?= $csrf ?>"><input type="hidden" name="act" value="login">
        <div class="field"><label for="email">Email</label><input type="email" id="email" name="email" value="<?= e((string)$cfg['admin_email']) ?>" required autocomplete="username" spellcheck="false" autocapitalize="off"></div>
        <div class="field"><label for="pw">Password</label><input type="password" id="pw" name="pw" required autofocus autocomplete="current-password"></div>
        <button class="btn btn-main">Sign in</button>
      </form>
    <?php endif; ?>
  </div>
</div>
<?php else: ?>
<div class="shell">
  <aside class="side">
    <a class="brand" href="./"><img src="../img/ahpu-logo-mark.png" alt="Ahpu" width="74" height="34"><span>Admin</span></a>
    <nav class="nav" aria-label="Admin sections">
      <a href="./" class="<?= $tab === 'clients' ? 'on' : '' ?>"<?= $tab === 'clients' ? ' aria-current="page"' : '' ?>>
        <svg viewBox="0 0 24 24"><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/></svg>
        <span>Clients</span><b class="cnt"><?= count($clients) ?></b></a>
      <a href="?tab=add" class="<?= $tab === 'add' ? 'on' : '' ?>"<?= $tab === 'add' ? ' aria-current="page"' : '' ?>>
        <svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 8v8M8 12h8"/></svg>
        <span>Add client</span></a>
      <a href="?tab=password" class="<?= $tab === 'password' ? 'on' : '' ?>"<?= $tab === 'password' ? ' aria-current="page"' : '' ?>>
        <svg viewBox="0 0 24 24"><rect x="4" y="10" width="16" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/></svg>
        <span><i class="lg-only">Change </i>password</span></a>
    </nav>
    <div class="side-foot">
      <a class="btn btn-sm" href="../#clients" target="_blank" rel="noopener">View website ↗</a>
      <form method="post"><input type="hidden" name="csrf" value="<?= $csrf ?>"><input type="hidden" name="act" value="logout"><button class="btn btn-sm">Sign out</button></form>
    </div>
  </aside>

  <main class="main">
  <?php if ($flash): ?><div class="flash <?= e($flash[1]) ?>"><?= e($flash[0]) ?></div><?php endif; ?>

  <?php if ($tab === 'clients'): ?>
  <div class="head">
    <div><h1>Clients</h1><p><?= count($clients) ?> restaurants. The top <?= HOME_LIMIT ?> show on the home page; all of them show on <a href="../clients/" target="_blank" rel="noopener">Our clients</a>. Drag to change the order.</p></div>
    <a class="btn btn-main" href="?tab=add">+ Add client</a>
  </div>

  <?php if (!$clients): ?>
    <div class="empty">No clients yet. <a href="?tab=add">Add the first one</a>.</div>
  <?php else: ?>
  <div class="list" id="list">
    <?php foreach ($clients as $i => $c): $id = e((string)$c['id']); ?>
    <div class="row" draggable="true" data-id="<?= $id ?>">
      <div class="handle" title="Drag to reorder">⋮⋮</div>
      <img class="thumb" src="../<?= e((string)$c['logo']) ?>" alt="" loading="lazy">
      <div><div class="name"><?= e((string)$c['name']) ?></div><div class="pos"><span>#<span class="n"><?= $i + 1 ?></span></span> <em class="home"<?= $i < HOME_LIMIT ? '' : ' hidden' ?>>On home page</em></div></div>
      <div class="acts">
        <div class="mv"><button type="button" data-mv="-1" aria-label="Move up">▲</button><button type="button" data-mv="1" aria-label="Move down">▼</button></div>
        <button type="button" class="btn btn-sm" data-edit>Edit</button>
        <form method="post" data-confirm="Remove <?= e((string)$c['name']) ?> from the website?">
          <input type="hidden" name="csrf" value="<?= $csrf ?>"><input type="hidden" name="act" value="delete"><input type="hidden" name="id" value="<?= $id ?>">
          <button class="btn btn-sm btn-danger">Delete</button>
        </form>
      </div>
      <form class="edit" method="post" enctype="multipart/form-data">
        <input type="hidden" name="csrf" value="<?= $csrf ?>"><input type="hidden" name="act" value="edit"><input type="hidden" name="id" value="<?= $id ?>">
        <input type="hidden" name="MAX_FILE_SIZE" value="<?= $maxBytes ?>">
        <input type="text" name="name" value="<?= e((string)$c['name']) ?>" maxlength="60" required aria-label="Name">
        <label class="btn btn-sm file-btn">Replace logo<input type="file" name="logo" accept="image/jpeg,image/png,image/webp,image/gif"></label>
        <button class="btn btn-sm btn-main">Save</button>
      </form>
    </div>
    <?php endforeach; ?>
  </div>
  <form method="post" class="savebar" id="savebar">
    <input type="hidden" name="csrf" value="<?= $csrf ?>"><input type="hidden" name="act" value="reorder"><input type="hidden" name="order" id="order">
    <span>Order changed</span>
    <span style="display:flex;gap:8px"><a href="./" class="btn btn-sm">Undo</a><button class="btn btn-sm btn-main">Save order</button></span>
  </form>
  <?php endif; ?>

  <?php elseif ($tab === 'add'): ?>
  <div class="head"><div><h1>Add client</h1><p>New restaurants go to the top of the list, so they show on the home page straight away. You can reorder them in Clients.</p></div></div>
  <form class="card add" method="post" enctype="multipart/form-data">
    <input type="hidden" name="csrf" value="<?= $csrf ?>"><input type="hidden" name="act" value="add">
    <input type="hidden" name="MAX_FILE_SIZE" value="<?= $maxBytes ?>">
    <label class="drop" title="Choose logo"><span>+ Logo<br>JPG · PNG · WebP</span><input type="file" name="logo" accept="image/jpeg,image/png,image/webp,image/gif" required data-preview></label>
    <div class="add-f">
      <div class="field"><label for="newname">Restaurant name</label><input type="text" id="newname" name="name" maxlength="60" required placeholder="e.g. Himalayan Java" autofocus></div>
      <div class="hint">Square logos look best. Max <?= (int)$cfg['max_upload_mb'] ?> MB. Images are resized to <?= (int)$cfg['logo_size'] ?>px and saved as WebP.</div>
      <button class="btn btn-main">Add client</button>
    </div>
  </form>

  <?php else: ?>
  <div class="head"><div><h1>Change password</h1><p>Use at least 10 characters. You stay signed in on this device.</p></div></div>
  <form class="card narrow" method="post" autocomplete="off">
    <input type="hidden" name="csrf" value="<?= $csrf ?>"><input type="hidden" name="act" value="password">
    <input type="email" name="username" value="<?= e((string)$cfg['admin_email']) ?>" autocomplete="username" readonly hidden>
    <div class="field"><label for="cur">Current password</label><input type="password" id="cur" name="cur" required autocomplete="current-password"></div>
    <div class="field"><label for="npw">New password (10+ characters)</label><input type="password" id="npw" name="pw" minlength="10" required autocomplete="new-password"></div>
    <div class="field"><label for="npw2">Repeat new password</label><input type="password" id="npw2" name="pw2" minlength="10" required autocomplete="new-password"></div>
    <button class="btn btn-main">Change password</button>
  </form>
  <?php endif; ?>
  </main>
</div>
<script>
(function(){
  var list=document.getElementById('list'), bar=document.getElementById('savebar'), order=document.getElementById('order');
  // preview new logo
  document.querySelectorAll('[data-preview]').forEach(function(inp){inp.addEventListener('change',function(){var f=inp.files[0],box=inp.parentNode,old=box.querySelector('img');if(old)old.remove();if(!f)return;var im=new Image();im.src=URL.createObjectURL(f);box.appendChild(im)})});
  // confirm delete
  document.querySelectorAll('form[data-confirm]').forEach(function(f){f.addEventListener('submit',function(e){if(!confirm(f.dataset.confirm))e.preventDefault()})});
  // edit toggle
  document.querySelectorAll('[data-edit]').forEach(function(b){b.addEventListener('click',function(){var r=b.closest('.row');r.classList.toggle('editing');b.textContent=r.classList.contains('editing')?'Close':'Edit'})});
  document.querySelectorAll('.edit input[type=file]').forEach(function(inp){inp.addEventListener('change',function(){var l=inp.parentNode;l.firstChild.textContent=inp.files[0]?'✓ '+inp.files[0].name.slice(0,18):'Replace logo'})});
  if(!list)return;
  function changed(){var ids=[].map.call(list.children,function(r,i){r.querySelector('.n').textContent=i+1;r.querySelector('.home').hidden=i>=<?= HOME_LIMIT ?>;return r.dataset.id});order.value=ids.join(',');bar.classList.add('show')}
  // drag and drop (mouse)
  var drag=null;
  list.addEventListener('dragstart',function(e){drag=e.target.closest('.row');if(!drag)return;drag.classList.add('dragging');e.dataTransfer.effectAllowed='move';e.dataTransfer.setData('text/plain',drag.dataset.id)});
  list.addEventListener('dragend',function(){if(drag)drag.classList.remove('dragging');list.querySelectorAll('.over').forEach(function(x){x.classList.remove('over')});drag=null});
  list.addEventListener('dragover',function(e){var r=e.target.closest('.row');if(!drag||!r||r===drag)return;e.preventDefault();var box=r.getBoundingClientRect(),after=e.clientY>box.top+box.height/2;list.insertBefore(drag,after?r.nextSibling:r);changed()});
  list.addEventListener('drop',function(e){e.preventDefault()});
  // up/down buttons (touch friendly)
  list.addEventListener('click',function(e){var b=e.target.closest('[data-mv]');if(!b)return;var r=b.closest('.row');if(b.dataset.mv==='-1'&&r.previousElementSibling)list.insertBefore(r,r.previousElementSibling);else if(b.dataset.mv==='1'&&r.nextElementSibling)list.insertBefore(r.nextElementSibling,r);changed()});
  // stop text inputs inside rows from starting a drag
  list.querySelectorAll('input,button,label').forEach(function(x){x.addEventListener('mousedown',function(){x.closest('.row').draggable=false});x.addEventListener('mouseup',function(){x.closest('.row').draggable=true})});
})();
</script>
<?php endif; ?>
</body>
</html>
