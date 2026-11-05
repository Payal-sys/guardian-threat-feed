import requests
import json

url = "https://mb-api.abuse.ch/api/v1/"

# Use get_recent with time selector to guarantee recent malware samples
data = {
    "query": "get_recent",
    "selector": "time"
}

try:
    response = requests.post(url, data=data)
    result = response.json()
    
    threats = []
    status = result.get("query_status")
    
    if status == "ok":
        for entry in result.get("data", []):
            # Fallback to Generic if signature name is missing
            sig = entry.get("signature")
            name = sig if sig else "Unknown.Malware"
            threats.append({
                "hash": entry.get("sha256_hash"),
                "name": name
            })
        print(f"Successfully grabbed {len(threats)} recent threats.")
    else:
        print(f"API Error Status: {status}")
            
    with open("threats.json", "w") as f:
        json.dump(threats, f, indent=2)
        
except Exception as e:
    print(f"Critical Script Error: {e}")
