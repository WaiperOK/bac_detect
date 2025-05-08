# Test Python code with suspicious constructs
import urllib.request
import base64

def malicious_function():
    # Suspicious eval
    user_input = input("Enter some code: ")
    eval(user_input)

    # Suspicious exec
    exec("print('Malicious code executed')")

    # Network call
    urllib.request.urlopen("http://malicious-site.example.com")

    # Obfuscated code
    obfuscated = base64.b64decode("cHJpbnQoIkhlbGxvIik=").decode()
    exec(obfuscated)