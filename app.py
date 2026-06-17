def add(a,b):
    return a+b

def get_user(id):
    query = f"SELECT * FROM users WHERE id = {id}"   # SQL Injection 취약점
    return execute(query)

def execute(query):
    print("executing:", query)
    return []
