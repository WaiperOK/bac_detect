<?php
// Test PHP code with suspicious constructs

// Suspicious system
system("whoami");

// Suspicious shell_exec
$output = shell_exec("ls -la");

// Suspicious eval
eval('echo "Malicious PHP code";');

// Obfuscated code
$obfuscated = base64_decode("ZWNobyAiSGVsbG8iOw==");
eval($obfuscated);
?>