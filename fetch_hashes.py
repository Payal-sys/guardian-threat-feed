import json
import requests

API = "https://mb-api.abuse.ch/api/v1/"

def get_android_hashes(limit=200):
    resp = requests.post(API, data={
        "query": "get_taginfo",
        "tag": "apk",
        "limit": limit
    }, timeout=30)
    
    resp.raise_for_status()
    data = resp.json()
    
    if data.get("query_status") != "ok":
        raise RuntimeError(f"API Error: {data.get('query_status')}")

    threats = []
    for item in data.get("data", [])[:limit]:
        threats.append({
            "hash": item["sha256_hash"],
            "name": item.get("signature", "Android.Malware.Generic")
        })
    return threats

if __name__ == "__main__":
    threats = get_android_hashes(200)
    with open("threats.json", "w") as f:
        json.dump(threats, f, indent=2)
    print(f"Saved {len(threats)} Android threat hashes to threats.json")
