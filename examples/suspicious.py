# Suspicious Python code
def bad_function():
    eval(input('Enter code: '))  # Dangerous eval
    exec('print(123)')  # Dangerous exec
    import urllib.request
    urllib.request.urlopen('http://example.com')  # Network call
