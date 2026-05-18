import requests
import time

SERVER = "http://127.0.0.1:5000/api/report"

while True:

    attack_detected = True

    if attack_detected:

        data = {
 
            "threat_type":"DoS Attack",
            "location":"h2",
            "severity":"High",
            "description":"Flood Attack Automatically Detected"

        }

        requests.post(SERVER, json=data)

        print("Threat Automatically Reported")

    time.sleep(15)