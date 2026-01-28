import requests
import json

def send_to_n8n(payload: dict, webhook_url: str) -> bool:
    try:
        response = requests.post(
            webhook_url,
            json=payload,
            timeout=10,
            headers={"Content-Type": "application/json"},
        )

        if response.status_code in (200, 201):
            return True

        print(f"[!] n8n webhook failed: {response.status_code} - {response.text}")
        return False

    except Exception as e:
        print(f"[!] Error sending to n8n: {e}")
        return False
