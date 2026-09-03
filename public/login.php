<?php
// Iniciar sesion - Guardar datos del usuario en $_SESSION
session_start();
require_once '../config/database.php';
$error = '';
$success = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {

$email = trim($_POST['email']);
$password = $_POST['password'];


if (empty($email) || empty($password)) {

$error = 'Todos los campos son requeridos';
} elseif (strlen($password) < 6) {
$error = 'La contraseña debe tener un largo mínimo de 6 caracteres';
} elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
$error = 'Formato de correo electronico invalido';
} else {
// APLICAR HASH - Bcrypt con Salt automatica
$stmt = $pdo->prepare("SELECT id, username, password FROM users WHERE email = ?");
        $stmt->execute([$email]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);





if ($user && password_verify($password , $user['password'])) {
$_SESSION['user_id'] = $user['id'];
$_SESSION['username'] = $user['username'];
$_SESSION['login_time'] = date('Y-m-d H:i:s');
header('Location: dashboard.php');
exit;
}
}
}
/**
* Página de inicio de sesión
* Verifica credenciales usando password_verify() para comparación segura
*/
// password_verify() compara la contraseña ingresada con el hash almacenado
// Es seguro contra ataques de timing
?>
<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Inicio de sesion </title>
<link rel="stylesheet" href="style.css">
</head>
<body>
<div class="container">
<div class="card">
<h2>Inicio de sesion </h2>
<?php if ($error): ?>
<div class="alert alert-error"><?php echo $error; ?></div>
<?php endif; ?>
<?php if ($success): ?>
<div class="alert alert-success"><?php echo $success; ?></div>
<?php endif; ?>
<form method="POST">
<div class="form-group">
<label for="email">Email </label>
<input type="email" id="email" name="email" required>
</div>
<div class="form-group">
<label for="password">Password </label>
<input type="password" id="password" name="password"
required>
</div>
<button type="submit" class="btn btn-primary">Inicia sesion </button>

</form>
<p class="link">¿No estas registrado? <a href="register.php">Registrate </a></p>
</div>
</div>
</body>
</html>