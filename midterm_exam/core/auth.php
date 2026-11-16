<?php
if (session_status() === PHP_SESSION_NONE) {
	session_set_cookie_params([
		'lifetime' => 0,
		'path'     => '/',
		'httponly' => true,
		'samesite' => 'Strict'
	]);
	session_start();
}

header("Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'none'");

function baseUrl() {
	$root = str_replace('\\', '/', rtrim($_SERVER['DOCUMENT_ROOT'], '/\\'));
	$dir  = str_replace('\\', '/', dirname(__DIR__));
	return str_replace($root, '', $dir);
}

function isLoggedIn() {
	return isset($_SESSION['user_id']);
}

function requireLogin() {
	if (!isLoggedIn()) {
		header("Location: " . baseUrl() . "/login.php");
		exit;
	}
}

function currentUserId() {
	return $_SESSION['user_id'] ?? null;
}

function getUserByUsername($pdo, $username) {
	$stmt = $pdo->prepare("SELECT * FROM users WHERE username = ?");
	$stmt->execute([$username]);
	return $stmt->fetch();
}

function getUserByEmail($pdo, $email) {
	$stmt = $pdo->prepare("SELECT * FROM users WHERE email = ?");
	$stmt->execute([$email]);
	return $stmt->fetch();
}

function registerUser($pdo, $d) {
	$sql = "INSERT INTO users (username, password_hash, first_name, last_name, email,
			contact_number, address, age, date_of_birth, gender)
			VALUES (?,?,?,?,?,?,?,?,?,?)";
	$stmt = $pdo->prepare($sql);
	return $stmt->execute([
		$d['username'], password_hash($d['password'], PASSWORD_DEFAULT),
		$d['first_name'], $d['last_name'], $d['email'], $d['contact_number'],
		$d['address'], $d['age'] !== '' ? $d['age'] : null,
		$d['date_of_birth'] !== '' ? $d['date_of_birth'] : null, $d['gender']
	]);
}

function loginUser($pdo, $username, $password) {
	$user = getUserByUsername($pdo, $username);
	if ($user && password_verify($password, $user['password_hash'])) {
		session_regenerate_id(true);
		$_SESSION['user_id'] = $user['user_id'];
		$_SESSION['username'] = $user['username'];
		$_SESSION['full_name'] = $user['first_name'] . ' ' . $user['last_name'];
		return true;
	}
	return false;
}

function logoutUser() {
	$_SESSION = [];
	if (ini_get("session.use_cookies")) {
		$p = session_get_cookie_params();
		setcookie(session_name(), '', time() - 42000, $p['path'], $p['domain'], $p['secure'], $p['httponly']);
	}
	session_destroy();
}

function isStrongPassword($password) {
	return strlen($password) >= 8
		&& preg_match('/[A-Z]/', $password)
		&& preg_match('/[a-z]/', $password)
		&& preg_match('/[0-9]/', $password);
}

function e($value) {
	return $value;
}
?>
