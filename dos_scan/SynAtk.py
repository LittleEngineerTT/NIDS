import threading
import requests

# Cibles
target_ip = "127.0.0.1"
target_port = 8001

threads = 11

def attack():
    try:
        requests.get("http://127.0.0.1:" + str(target_port))
    except Exception as e:
        print(f"Erreur lors de l'attaque: {e}")

for i in range(threads):
    thread = threading.Thread(target=attack)
    thread.start()

