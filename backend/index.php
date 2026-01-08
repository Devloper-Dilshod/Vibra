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

require_once __DIR__ . '/db.php';

// 1. Try to get route from GET parameter (more robust for varied hosting)
$route = $_GET['route'] ?? null;

// 2. If not in GET, try to parse from PATH_INFO or URI
if (!$route) {
    if (isset($_SERVER['PATH_INFO'])) {
        $route = $_SERVER['PATH_INFO'];
    } else {
        $path = parse_url($_SERVER['REQUEST_URI'] ?? '', PHP_URL_PATH);
        // Remove index.php from the path to get the route
        if (strpos($path, 'index.php') !== false) {
            $route = substr($path, strpos($path, 'index.php') + 9);
        }
    }
}

$route = trim($route ?? '', '/');

// Default route if empty
if (empty($route)) {
    $route = 'ping';
}

$method = $_SERVER['REQUEST_METHOD'];
$input = json_decode(file_get_contents('php://input'), true);

// Helper for Get Client IP (Comprehensive detection for various hosting/proxies)
function getClientIP() {
    $headers = [
        'HTTP_CF_CONNECTING_IP', // Cloudflare
        'HTTP_X_FORWARDED_FOR',  // Standard proxy
        'HTTP_CLIENT_IP',
        'HTTP_X_REAL_IP',
        'HTTP_TRUE_CLIENT_IP',
        'REMOTE_ADDR'
    ];

    foreach ($headers as $header) {
        if (!empty($_SERVER[$header])) {
            $ips = explode(',', $_SERVER[$header]);
            foreach ($ips as $ip) {
                $ip = trim($ip);
                // Skip local/invalid if possible, but for simplicity:
                if (filter_var($ip, FILTER_VALIDATE_IP)) {
                    return $ip;
                }
            }
        }
    }
    return '0.0.0.0'; 
}

$client_ip = getClientIP();
$is_auth_route = strpos($route, 'auth/') !== false;

/* 
// [DISABLED TEMPORARILY] Global IP Check & Block to prevent mass lockout
if (!$is_auth_route && !empty($client_ip) && $client_ip !== '::1' && $client_ip !== '127.0.0.1' && $client_ip !== '0.0.0.0') {
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM blocked_ips WHERE ip = ?");
    $stmt->execute([$client_ip]);
    if ($stmt->fetchColumn() > 0) {
        $user_id_param = $_GET['user_id'] ?? $input['user_id'] ?? null;
        $is_admin = false;
        if ($user_id_param) {
            $stmt_a = $pdo->prepare("SELECT role FROM users WHERE id = ?");
            $stmt_a->execute([$user_id_param]);
            if ($stmt_a->fetchColumn() === 'admin') $is_admin = true;
        }
        
        if (!$is_admin) {
            http_response_code(403);
            echo json_encode(['error' => 'Siz bloklangansiz']);
            exit;
        }
    }
}
*/

function respond($data, $status = 200) {
    http_response_code($status);
    echo json_encode($data);
    exit;
}

// ROUTING LOGIC
switch ($route) {
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
            $mute_until = date('c', time() + 86400); // ISO8601
        }
        
        $role = (strtolower($username) === 'dilshod') ? 'admin' : 'user';
        $hashed_password = password_hash($password, PASSWORD_DEFAULT);
        
        try {
            $stmt = $pdo->prepare("INSERT INTO users (username, password, role, last_ip, muted_until, is_blocked) VALUES (?, ?, ?, ?, ?, 0)");
            $stmt->execute([$username, $hashed_password, $role, $client_ip, $mute_until]);
            
            // Get the new user
            $new_user_id = $pdo->lastInsertId();
            $stmt = $pdo->prepare("SELECT id, username, role, is_blocked, muted_until FROM users WHERE id = ?");
            $stmt->execute([$new_user_id]);
            $user = $stmt->fetch();
            $user['is_verified'] = (strtolower($user['username']) === 'dilshod') ? 1 : 0;
            $user['is_blocked'] = (int)$user['is_blocked'];

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
            // Admins are immune to account blocking
            if ($user['is_blocked'] && $user['role'] !== 'admin') respond(['error' => 'Your account is blocked'], 403);
            
            // Update last IP on login
            $stmt = $pdo->prepare("UPDATE users SET last_ip = ? WHERE id = ?");
            $stmt->execute([$client_ip, $user['id']]);

            unset($user['password']);
            
            // Add verified status
            $user['is_verified'] = (strtolower($user['username']) === 'dilshod') ? 1 : 0;
            
            respond(['user' => $user]);
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
                $stmt_role = $pdo->prepare("SELECT role FROM users WHERE id = ?");
                $stmt_role->execute([$curr_user_id]);
                $user_role = $stmt_role->fetchColumn();
                
                $is_blocked = ($user_role === 'admin') ? 0 : (int)($row['is_blocked'] ?? 0);
                $muted_until = $row['muted_until'] ? date('c', strtotime($row['muted_until'])) : null;
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

        // Block User
        $stmt = $pdo->prepare("UPDATE users SET is_blocked = 1 WHERE id = ?");
        $stmt->execute([$target_user_id]);

        // Add IP to blocked list (Safety: don't block empty or local IPs)
        if ($ip_to_block && !in_array($ip_to_block, ['', '::1', '127.0.0.1'])) {
            $stmt = $pdo->prepare("INSERT OR IGNORE INTO blocked_ips (ip) VALUES (?)");
            $stmt->execute([$ip_to_block]);
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

        // Get user IP before unblocking
        $stmt = $pdo->prepare("SELECT last_ip FROM users WHERE id = ?");
        $stmt->execute([$target_user_id]);
        $ip_to_unblock = $stmt->fetchColumn();

        // Unblock User
        $stmt = $pdo->prepare("UPDATE users SET is_blocked = 0 WHERE id = ?");
        $stmt->execute([$target_user_id]);

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

        $stmt = $pdo->query("SELECT id, username, role, is_blocked FROM users");
        $all_users = $stmt->fetchAll();
        foreach ($all_users as &$u) {
            if ($u['role'] === 'admin') $u['is_blocked'] = 0;
            $u['is_blocked'] = (int)$u['is_blocked'];
        }
        respond($all_users);
        break;

    default:
        respond(['error' => 'Endpoint not found: ' . $route], 404);
        break;
}
?>
