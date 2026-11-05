import json
import requests
import os

API_URL = "https://mb-api.abuse.ch/api/v1/"
# Grabs the secret we passed in from the YAML file
AUTH_KEY = os.environ.get("MB_AUTH_KEY")

def get_android_hashes(limit=1000):
    # Attaches your API key to the request headers
    headers = {"Auth-Key": AUTH_KEY} if AUTH_KEY else {}
    
    data = {
        "query": "get_taginfo",
        "tag": "android",
        "limit": limit
    }
    
    print("Connecting to MalwareBazaar API...")
    resp = requests.post(API_URL, headers=headers, data=data, timeout=30)
    resp.raise_for_status()
    
    result = resp.json()
    status = result.get("query_status")
    
    if status != "ok":
        raise RuntimeError(f"API Error: {status}")

    threats = []
    for item in result.get("data", [])[:limit]:
        sig = item.get("signature")
        name = sig if sig else "Android.Malware.Generic"
        
        # Formatted exactly for Guardian's Room database
        threats.append({
            "hash": item.get("sha256_hash"),
            "name": name
        })
        
    return threats

if __name__ == "__main__":
    try:
        threats = get_android_hashes(1000)
        with open("threats.json", "w") as f:
            json.dump(threats, f, indent=2)
        print(f"Success! Saved {len(threats)} Android threat hashes to threats.json")
    except Exception as e:
        print(f"Critical Script Error: {e}")
