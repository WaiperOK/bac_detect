
// Тестовый JavaScript-код с подозрительными конструкциями
function maliciousFunction() {
    // Подозрительный eval
    eval("alert('Hacked!')");

    // Обфусцированный код
    var encoded = unescape("%61%6c%65%72%74%28%27%48%61%63%6b%65%64%27%29");
    eval(encoded);

    // Сетевой вызов
    fetch("http://malicious-site.example.com");
}
