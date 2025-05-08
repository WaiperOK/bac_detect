// Test JavaScript code with suspicious constructs
function maliciousFunction() {
    // Suspicious eval
    eval("alert('Hacked!')");

    // Obfuscated code
    var encoded = unescape("%61%6c%65%72%74%28%27%48%61%63%6b%65%64%27%29");
    eval(encoded);

    // Network call
    fetch("http://malicious-site.example.com");
}
