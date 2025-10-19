<?php
session_start();
require_once '../config.php';
require_once '../classes/Auth.php';

$auth = new Auth($pdo);

// Если уже авторизован, перенаправляем на панель курьера
if ($auth->isCourierLoggedIn()) {
    header('Location: dashboard.php');
    exit;
}

$error = '';

// Обрабатываем форму входа
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Проверка CSRF токена
    if (!isset($_POST['csrf_token']) || !$auth->verifyCsrfToken($_POST['csrf_token'])) {
        $error = 'Ошибка безопасности. Пожалуйста, попробуйте еще раз.';
    } else {
        $username = trim($_POST['username'] ?? '');
        $password = $_POST['password'] ?? '';
        
        if (empty($username) || empty($password)) {
            $error = 'Пожалуйста, введите логин и пароль.';
        } else {
            if ($auth->loginCourier($username, $password)) {
                header('Location: dashboard.php');
                exit;
            } else {
                $error = 'Неверный логин или пароль.';
            }
        }
    }
}
