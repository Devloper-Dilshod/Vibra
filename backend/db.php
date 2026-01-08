<?php
// backend/db.php

$db_file = __DIR__ . '/vibra.sqlite';

try {
    $pdo = new PDO("sqlite:$db_file");
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);

    // Create users table
    $pdo->exec("CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'user',
        is_blocked INTEGER NOT NULL DEFAULT 0,
        muted_until DATETIME,
        last_ip TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )");

    // Create blocked_ips table
    $pdo->exec("CREATE TABLE IF NOT EXISTS blocked_ips (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT UNIQUE NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )");

    // Create login_attempts table
    $pdo->exec("CREATE TABLE IF NOT EXISTS login_attempts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT NOT NULL,
        username TEXT,
        attempted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        is_success INTEGER DEFAULT 0
    )");

    // Create messages table
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
    die("Database connection failed: " . $e->getMessage());
}
?>
