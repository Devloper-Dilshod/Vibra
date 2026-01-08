<?php
// backend/index.php

header("Content-Type: application/json");
date_default_timezone_set('Asia/Tashkent');

// Allow CORS from specific origins
$allowed_origins = [
    "http://localhost:5173",
    "https://vibra-uz.vercel.app",
    "https://vibra.uz"
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

$request_uri = $_SERVER['REQUEST_URI'] ?? '';
$path = parse_url($request_uri, PHP_URL_PATH);
// Base path adjustment if running in a subdirectory
$base_path = '/VIbra/backend/index.php';
$route = str_replace($base_path, '', $path);
$route = trim($route, '/');

// For f0069.5fh.ru/vibra style hosting, we might need more flexible routing
// If the above doesn't work perfectly, we'll use a simpler 'action' param if needed
// but let's try clean routes first.

$method = $_SERVER['REQUEST_METHOD'];
$input = json_decode(file_get_contents('php://input'), true);

// Global IP Check & Block
$client_ip = $_SERVER['REMOTE_ADDR'] ?? '';
$stmt = $pdo->prepare("SELECT COUNT(*) FROM blocked_ips WHERE ip = ?");
$stmt->execute([$client_ip]);
if ($stmt->fetchColumn() > 0) {
    http_response_code(403);
    echo json_encode(['error' => 'Siz  bloklangansiz']);
    exit;
}

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
        
        $role = (strtolower($username) === 'dilshod') ? 'admin' : 'user';
        $hashed_password = password_hash($password, PASSWORD_DEFAULT);
        
        try {
            $stmt = $pdo->prepare("INSERT INTO users (username, password, role, last_ip) VALUES (?, ?, ?, ?)");
            $stmt->execute([$username, $hashed_password, $role, $client_ip]);
            
            // Get the new user
            $new_user_id = $pdo->lastInsertId();
            $stmt = $pdo->prepare("SELECT id, username, role, is_blocked FROM users WHERE id = ?");
            $stmt->execute([$new_user_id]);
            $user = $stmt->fetch();
            $user['is_verified'] = (strtolower($user['username']) === 'dilshod') ? 1 : 0;

            respond(['success' => true, 'user' => $user]);
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
            if ($user['is_blocked']) respond(['error' => 'Your account is blocked'], 403);
            
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
                $is_blocked = (int)$row['is_blocked'];
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

        // Get user IP before blocking
        $stmt = $pdo->prepare("SELECT last_ip FROM users WHERE id = ?");
        $stmt->execute([$target_user_id]);
        $ip_to_block = $stmt->fetchColumn();

        // Block User
        $stmt = $pdo->prepare("UPDATE users SET is_blocked = 1 WHERE id = ?");
        $stmt->execute([$target_user_id]);

        // Add IP to blocked list
        if ($ip_to_block) {
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

        $stmt = $pdo->prepare("UPDATE users SET is_blocked = 0 WHERE id = ?");
        $stmt->execute([$target_user_id]);
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
        respond($stmt->fetchAll());
        break;

    default:
        respond(['error' => 'Endpoint not found: ' . $route], 404);
        break;
}
?>
