<?php
// Тестовый PHP-код с подозрительными конструкциями

// Подозрительный system
system("whoami");

// Подозрительный shell_exec
$output = shell_exec("ls -la");

// Подозрительный eval
eval('echo "Malicious PHP code";');

// Обфусцированный код
$obfuscated = base64_decode("ZWNobyAiSGVsbG8iOw==");
eval($obfuscated);
?>