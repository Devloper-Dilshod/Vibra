<?php
// backend/index.php

header("Content-Type: application/json");
date_default_timezone_set('Asia/Tashkent');

// Allow CORS from specific origins
$allowed_origins = [
    "http://localhost:5173",
    "https://vibra-uz.vercel.app",
    "https://vibra.uz",
    "http://vibra.uz"
];

$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
if (in_array($origin, $allowed_origins)) {
    header("Access-Control-Allow-Origin: $origin");
} else {
    // Default to allow for local dev if origin is missing (rare for fetch)
    header("Access-Control-Allow-Origin: *");
}

header("Access-Control-Allow-Methods: POST, GET, OPTIONS, DELETE, PUT");
header("Access-Control-Allow-Headers: Content-Type, Authorization");

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    exit(0);
}

// 1. Database Initialization (Self-Healing)
$db_file = __DIR__ . '/vibra.sqlite';
try {
    $pdo = new PDO("sqlite:$db_file");
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);

    // Initial Schema
    $pdo->exec("CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'user',
        is_blocked INTEGER NOT NULL DEFAULT 0,
        muted_until DATETIME,
        last_ip TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        device_id TEXT
    )");

    $pdo->exec("CREATE TABLE IF NOT EXISTS blocked_ips (
        ip TEXT PRIMARY KEY,
        blocked_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )");

    $pdo->exec("CREATE TABLE IF NOT EXISTS blocked_devices (
        device_id TEXT PRIMARY KEY,
        blocked_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )");

    $pdo->exec("CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        message TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        is_edited INTEGER NOT NULL DEFAULT 0,
        is_seen INTEGER NOT NULL DEFAULT 0,
        reply_to INTEGER DEFAULT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (reply_to) REFERENCES messages(id) ON DELETE SET NULL
    )");
} catch (PDOException $e) {
    echo json_encode(['error' => 'Baza bilan bog\'lanishda xatolik: ' . $e->getMessage()]);
    exit;
}

// 1. Core Logic
$client_ip = getClientIP();
$device_id = getDeviceID();
$route = $_GET['route'] ?? null;

// Parse route from URL if not in GET
if (!$route) {
    if (isset($_SERVER['PATH_INFO'])) {
        $route = $_SERVER['PATH_INFO'];
    } else {
        $path = parse_url($_SERVER['REQUEST_URI'] ?? '', PHP_URL_PATH);
        if (strpos($path, 'index.php') !== false) {
            $route = substr($path, strpos($path, 'index.php') + 9);
        }
    }
}
$route = trim($route ?? '', '/');
if (empty($route)) $route = 'ping';

$is_auth_route = strpos($route, 'auth/') !== false;

// 2. Response Helper
function respond($data, $status = 200) {
    http_response_code($status);
    echo json_encode($data);
    exit;
}

// 3. Global Security Check (Device Level)
if ($device_id !== 'no-device-id' && !$is_auth_route && $route !== 'ping') {
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM blocked_devices WHERE device_id = ?");
    $stmt->execute([$device_id]);
    if ($stmt->fetchColumn() > 0) {
        // Admin Immunity: Hardcoded 'dilshod' bypass
        $user_id_param = $_GET['user_id'] ?? $input['user_id'] ?? $_GET['admin_id'] ?? $input['admin_id'] ?? null;
        $is_admin = false;
        
        if ($user_id_param) {
            $stmt_a = $pdo->prepare("SELECT username, role FROM users WHERE id = ?");
            $stmt_a->execute([$user_id_param]);
            $u_check = $stmt_a->fetch();
            if ($u_check && ($u_check['role'] === 'admin' || strtolower($u_check['username']) === 'dilshod')) {
                $is_admin = true;
            }
        }

        if (!$is_admin) {
            respond(['error' => 'Sizning qurilmangiz bloklangan'], 403);
        }
    }
}

// ROUTING LOGIC
try {
    switch ($route) {
        case 'ping':
            respond(['pong' => true, 'ip' => $client_ip, 'date' => date('Y-m-d H:i:s')]);
            break;

        case 'auth/register':
        if ($method !== 'POST') respond(['error' => 'Method not allowed'], 405);
        $username = trim($input['username'] ?? '');
        $password = $input['password'] ?? '';
        if (!$username || !$password) respond(['error' => 'Missing fields'], 400);

        if (!preg_match('/^[a-zA-Z0-9_]+$/', $username)) {
            respond(['error' => "Username faqat harf, raqam va '_' dan iborat bo'lishi kerak"], 400);
        }

        // Reserve 'dilshod'
        if (strtolower($username) !== 'dilshod' && strpos(strtolower($username), 'dilshod') !== false) {
            respond(['error' => "Ushbu username taqiqlangan!"], 400);
        }

        // Rate Limit: 3 accounts per hour from same IP
        $stmt = $pdo->prepare("SELECT COUNT(*) FROM users WHERE last_ip = ? AND created_at > datetime('now', '-1 hour')");
        $stmt->execute([$client_ip]);
        $reg_count = $stmt->fetchColumn();

        $mute_until = null;
        if ($reg_count >= 3) {
            $mute_until = date('Y-m-d H:i:s', time() + 86400); // 24 hours
        }
        
        $role = (strtolower($username) === 'dilshod') ? 'admin' : 'user';
        $hashed_password = password_hash($password, PASSWORD_DEFAULT);
        
        try {
            $stmt = $pdo->prepare("INSERT INTO users (username, password, role, last_ip, muted_until, device_id) VALUES (?, ?, ?, ?, ?, ?)");
            $stmt->execute([$username, $hashed_password, $role, $client_ip, $mute_until, $device_id]);
            
            // Get the new user
            $new_user_id = $pdo->lastInsertId();
            $stmt = $pdo->prepare("SELECT id, username, role, is_blocked, muted_until, device_id FROM users WHERE id = ?");
            $stmt->execute([$new_user_id]);
            $user = $stmt->fetch();
            
            // Ensure is_blocked is 0 for new users
            $user['is_blocked'] = 0; 
            $user['is_verified'] = (strtolower($user['username']) === 'dilshod') ? 1 : 0;

            respond(['success' => true, 'user' => $user, 'muted_until' => $mute_until]);
        } catch (PDOException $e) {
            respond(['error' => 'Bu foydalanuvchi nomi band'], 400);
        }
        break;

    case 'auth/login':
        if ($method !== 'POST') respond(['error' => 'Method not allowed'], 405);
        $username = $input['username'] ?? '';
        $password = $input['password'] ?? '';
        
        $stmt = $pdo->prepare("SELECT * FROM users WHERE username = ?");
        $stmt->execute([$username]);
        $user = $stmt->fetch();
        
        if ($user && password_verify($password, $user['password'])) {
            // Update last IP and Device ID
            $stmt = $pdo->prepare("UPDATE users SET last_ip = ?, device_id = ? WHERE id = ?");
            $stmt->execute([$client_ip, $device_id, $user['id']]);

            unset($user['password']);
            $user['is_verified'] = (strtolower($user['username']) === 'dilshod') ? 1 : 0;
            
            // Admin is never blocked
            if ($user['role'] === 'admin') $user['is_blocked'] = 0;
            
            respond(['success' => true, 'user' => $user, 'muted_until' => $user['muted_until']]);
        } else {
            respond(['error' => 'Invalid credentials'], 401);
        }
        break;

    case 'chat/messages':
        if ($method !== 'GET') respond(['error' => 'Method not allowed'], 405);
        $curr_user_id = $_GET['user_id'] ?? null;
        
        // Mark as seen if requester is not the sender
        if ($curr_user_id) {
            $stmt = $pdo->prepare("UPDATE messages SET is_seen = 1 WHERE user_id != ? AND is_seen = 0");
            $stmt->execute([$curr_user_id]);
        }

        $stmt = $pdo->prepare("
            SELECT m.*, u.username, u.role,
                   p.message as parent_message, p.username as parent_username
            FROM messages m
            JOIN users u ON m.user_id = u.id
            LEFT JOIN (SELECT m1.id, m1.message, u1.username FROM messages m1 JOIN users u1 ON m1.user_id = u1.id) p ON m.reply_to = p.id
            ORDER BY m.created_at ASC
        ");
        $stmt->execute();
        $msgs = $stmt->fetchAll() ?: [];
        foreach ($msgs as &$m) {
            $m['is_verified'] = (isset($m['username']) && strtolower($m['username']) === 'dilshod') ? 1 : 0;
            $m['id'] = (int)$m['id'];
            $m['user_id'] = (int)$m['user_id'];
            $m['is_edited'] = (int)$m['is_edited'];
            $m['is_seen'] = (int)$m['is_seen'];
        }

        // Return current user status if requested
        $is_blocked = 0;
        $muted_until = null;
        if ($curr_user_id) {
            $stmt = $pdo->prepare("SELECT is_blocked, muted_until FROM users WHERE id = ?");
            $stmt->execute([$curr_user_id]);
            $row = $stmt->fetch();
            if ($row) {
                // Return 0 for is_blocked if user is admin
                $stmt_role = $pdo->prepare("SELECT role FROM users WHERE id = ?");
                $stmt_role->execute([$curr_user_id]);
                $user_role = $stmt_role->fetchColumn();
                
                $is_blocked = ($user_role === 'admin') ? 0 : (int)$row['is_blocked'];
                $muted_until = $row['muted_until'];
            }
        }

        respond(['messages' => $msgs, 'is_blocked' => $is_blocked, 'muted_until' => $muted_until]);
        break;

    case 'chat/send':
        if ($method !== 'POST') respond(['error' => 'Method not allowed'], 405);
        $user_id = $input['user_id'] ?? null;
        $message = $input['message'] ?? '';
        $reply_to = $input['reply_to'] ?? null;
        if (!$user_id || !$message) respond(['error' => 'Missing fields'], 400);
        
        // Fetch user info
        $stmt = $pdo->prepare("SELECT role, is_blocked, muted_until FROM users WHERE id = ?");
        $stmt->execute([$user_id]);
        $u = $stmt->fetch();
        if ($u['is_blocked']) respond(['error' => 'Blocked'], 403);

        // Check Mute
        if ($u['muted_until'] && strtotime($u['muted_until']) > time()) {
            respond(['error' => 'Siz mute qilingansiz', 'muted_until' => $u['muted_until']], 403);
        }

        // Anti-Flood Logic (Ignore Admin)
        if ($u['role'] !== 'admin') {
            // Rule 1: 30+ messages in 10s
            $stmt = $pdo->prepare("SELECT COUNT(*) FROM messages WHERE user_id = ? AND created_at > datetime('now', '-10 seconds')");
            $stmt->execute([$user_id]);
            $count10s = $stmt->fetchColumn();

            // Rule 2: 6+ messages in 5s
            $stmt = $pdo->prepare("SELECT COUNT(*) FROM messages WHERE user_id = ? AND created_at > datetime('now', '-5 seconds')");
            $stmt->execute([$user_id]);
            $count5s = $stmt->fetchColumn();

            if ($count10s >= 30 || $count5s >= 6) {
                $mute_time = date('Y-m-d H:i:s', time() + 300); // 5 mins
                $stmt = $pdo->prepare("UPDATE users SET muted_until = ? WHERE id = ?");
                $stmt->execute([$mute_time, $user_id]);

                // Delete flood messages
                $window = ($count10s >= 30) ? '10 seconds' : '5 seconds';
                $stmt = $pdo->prepare("DELETE FROM messages WHERE user_id = ? AND created_at > datetime('now', '-$window')");
                $stmt->execute([$user_id]);

                respond(['error' => 'Anti-Flood: 5 minutga mute qilindingiz', 'muted_until' => $mute_time], 403);
            }
        }

        $stmt = $pdo->prepare("INSERT INTO messages (user_id, message, created_at, reply_to) VALUES (?, ?, ?, ?)");
        $stmt->execute([$user_id, $message, date('Y-m-d H:i:s'), $reply_to]);
        respond(['success' => true]);
        break;

    case 'chat/edit':
        if ($method !== 'POST') respond(['error' => 'Method not allowed'], 405);
        $id = $input['id'] ?? null;
        $user_id = $input['user_id'] ?? null;
        $message = $input['message'] ?? '';
        if (!$id || !$user_id || !$message) respond(['error' => 'Missing fields'], 400);

        $stmt = $pdo->prepare("UPDATE messages SET message = ?, is_edited = 1 WHERE id = ? AND user_id = ?");
        $stmt->execute([$message, $id, $user_id]);
        respond(['success' => true]);
        break;

    case 'chat/delete':
        if ($method !== 'POST') respond(['error' => 'Method not allowed'], 405);
        $id = $input['id'] ?? null;
        $user_id = $input['user_id'] ?? null; // ID of the person trying to delete
        
        if (!$id || !$user_id) respond(['error' => 'Missing fields'], 400);

        // Fetch the message to check ownership
        $stmt = $pdo->prepare("SELECT user_id FROM messages WHERE id = ?");
        $stmt->execute([$id]);
        $owner_id = $stmt->fetchColumn();

        if (!$owner_id) respond(['error' => 'Xabar topilmadi'], 404);

        // Check if requester is admin
        $stmt = $pdo->prepare("SELECT role FROM users WHERE id = ?");
        $stmt->execute([$user_id]);
        $role = $stmt->fetchColumn();

        if ($role === 'admin' || (int)$owner_id === (int)$user_id) {
            $stmt = $pdo->prepare("DELETE FROM messages WHERE id = ?");
            $stmt->execute([$id]);
            respond(['success' => true]);
        } else {
            respond(['error' => 'Ruxsat berilmagan'], 403);
        }
        break;

    case 'admin/block':
        if ($method !== 'POST') respond(['error' => 'Method not allowed'], 405);
        $target_user_id = $input['user_id'] ?? null;
        $admin_id = $input['admin_id'] ?? null;

        // Verify admin
        $stmt = $pdo->prepare("SELECT role FROM users WHERE id = ?");
        $stmt->execute([$admin_id]);
        if ($stmt->fetchColumn() !== 'admin') respond(['error' => 'Unauthorized'], 403);

        // Admin can't be blocked
        $stmt = $pdo->prepare("SELECT role, last_ip FROM users WHERE id = ?");
        $stmt->execute([$target_user_id]);
        $target_user = $stmt->fetch();
        
        if (!$target_user) respond(['error' => 'Foydalanuvchi topilmadi'], 404);
        if ($target_user['role'] === 'admin') respond(['error' => 'Adminni bloklay olmaysiz!'], 400);
        if ((int)$target_user_id === (int)$admin_id) respond(['error' => 'O\'zingizni bloklay olmaysiz!'], 400);

        $ip_to_block = $target_user['last_ip'];
        $device_to_block = $target_user['device_id'];

        // Block User
        $stmt = $pdo->prepare("UPDATE users SET is_blocked = 1 WHERE id = ?");
        $stmt->execute([$target_user_id]);

        // Add Device to blocked list (Precision Block)
        if ($device_to_block && $device_to_block !== 'no-device-id') {
            $stmt = $pdo->prepare("INSERT OR IGNORE INTO blocked_devices (device_id) VALUES (?)");
            $stmt->execute([$device_to_block]);
        }

        // Add IP to blocked list (Shared IP Protection)
        if ($ip_to_block && !in_array($ip_to_block, ['', '::1', '127.0.0.1', 'unknown', '0.0.0.0'])) {
            // Check if this is a shared IP (e.g. more than 5 users)
            $stmt = $pdo->prepare("SELECT COUNT(*) FROM users WHERE last_ip = ?");
            $stmt->execute([$ip_to_block]);
            $ip_user_count = $stmt->fetchColumn();

            if ($ip_user_count <= 5) {
                $stmt = $pdo->prepare("INSERT OR IGNORE INTO blocked_ips (ip) VALUES (?)");
                $stmt->execute([$ip_to_block]);
            }
        }

        respond(['success' => true]);
        break;

    case 'admin/unblock':
        if ($method !== 'POST') respond(['error' => 'Method not allowed'], 405);
        $target_user_id = $input['user_id'] ?? null;
        $admin_id = $input['admin_id'] ?? null;

        // Verify admin
        $stmt = $pdo->prepare("SELECT role FROM users WHERE id = ?");
        $stmt->execute([$admin_id]);
        if ($stmt->fetchColumn() !== 'admin') respond(['error' => 'Unauthorized'], 403);

        // Get user IP and Device before unblocking
        $stmt = $pdo->prepare("SELECT last_ip, device_id FROM users WHERE id = ?");
        $stmt->execute([$target_user_id]);
        $row = $stmt->fetch();
        $ip_to_unblock = $row['last_ip'] ?? null;
        $device_to_unblock = $row['device_id'] ?? null;

        // Unblock User
        $stmt = $pdo->prepare("UPDATE users SET is_blocked = 0 WHERE id = ?");
        $stmt->execute([$target_user_id]);

        // Remove Device from blocked list
        if ($device_to_unblock) {
            $stmt = $pdo->prepare("DELETE FROM blocked_devices WHERE device_id = ?");
            $stmt->execute([$device_to_unblock]);
        }

        // Remove IP from blocked list
        if ($ip_to_unblock) {
            $stmt = $pdo->prepare("DELETE FROM blocked_ips WHERE ip = ?");
            $stmt->execute([$ip_to_unblock]);
        }
        respond(['success' => true]);
        break;

    case 'admin/reset_blocks':
        if ($method !== 'POST') respond(['error' => 'Method not allowed'], 405);
        $admin_id = $input['admin_id'] ?? null;
        
        $stmt = $pdo->prepare("SELECT role FROM users WHERE id = ?");
        $stmt->execute([$admin_id]);
        if ($stmt->fetchColumn() !== 'admin') respond(['error' => 'Unauthorized'], 403);
        
        $pdo->exec("DELETE FROM blocked_ips");
        $pdo->exec("DELETE FROM blocked_devices");
        $pdo->exec("UPDATE users SET is_blocked = 0");
        respond(['success' => true]);
        break;

    case 'admin/users':
        if ($method !== 'GET') respond(['error' => 'Method not allowed'], 405);
        $admin_id = $_GET['admin_id'] ?? null;

        // Verify admin
        $stmt = $pdo->prepare("SELECT role FROM users WHERE id = ?");
        $stmt->execute([$admin_id]);
        if ($stmt->fetchColumn() !== 'admin') respond(['error' => 'Unauthorized'], 403);

        $stmt = $pdo->query("SELECT id, username, role, is_blocked, last_ip, device_id FROM users ORDER BY id DESC");
        $all_users = $stmt->fetchAll();
        foreach ($all_users as &$u) {
            if ($u['role'] === 'admin') $u['is_blocked'] = 0;
            $u['is_blocked'] = (int)$u['is_blocked'];
        }
        respond($all_users);
        break;

        case 'admin/delete_user':
            if ($method !== 'POST') respond(['error' => 'Method not allowed'], 405);
            $target_user_id = $input['user_id'] ?? null;
            $admin_id = $input['admin_id'] ?? null;

            // Verify admin
            $stmt = $pdo->prepare("SELECT role FROM users WHERE id = ?");
            $stmt->execute([$admin_id]);
            if ($stmt->fetchColumn() !== 'admin') respond(['error' => 'Unauthorized'], 403);

            // Admin can't be deleted via this endpoint (safety)
            $stmt = $pdo->prepare("SELECT role FROM users WHERE id = ?");
            $stmt->execute([$target_user_id]);
            if ($stmt->fetchColumn() === 'admin') respond(['error' => 'Adminni o\'chirib bo\'lmaydi'], 400);

            // Delete User (Messages will cascade delete due to FK)
            $stmt = $pdo->prepare("DELETE FROM users WHERE id = ?");
            $stmt->execute([$target_user_id]);

            respond(['success' => true]);
            break;

        default:
            respond(['error' => 'Endpoint not found: ' . $route], 404);
            break;
    }
} catch (Exception $e) {
    respond(['error' => 'System Error: ' . $e->getMessage()], 500);
}
?>
