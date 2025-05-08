# Тестовый Python-код с подозрительными конструкциями
import urllib.request
import base64

def malicious_function():
    # Подозрительный eval
    user_input = input("Enter some code: ")
    eval(user_input)

    # Подозрительный exec
    exec("print('Malicious code executed')")

    # Сетевой вызов
    urllib.request.urlopen("http://malicious-site.example.com")

    # Обфусцированный код
    obfuscated = base64.b64decode("cHJpbnQoIkhlbGxvIik=").decode()
    exec(obfuscated)