import requests
import json

url = "https://mb-api.abuse.ch/api/v1/"
data = {
    "query": "get_taginfo",
    "tag": "apk",
    "limit": 1000
}

try:
    response = requests.post(url, data=data)
    result = response.json()
    
    threats = []
    if result.get("query_status") == "ok":
        for entry in result.get("data", []):
            sig = entry.get("signature")
            name = sig if sig else "Android.Malware.Generic"
            threats.append({
                "hash": entry.get("sha256_hash"),
                "name": name
            })
            
    with open("threats.json", "w") as f:
        json.dump(threats, f, indent=2)
    print(f"Saved {len(threats)} Android malware hashes.")
except Exception as e:
    print(f"Error: {e}")
