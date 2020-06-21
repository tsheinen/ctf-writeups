import requests
import json
url = "https://oo5apsmnc8.execute-api.eu-west-1.amazonaws.com/stag/wm02"
for i in range(100):
	r = requests.post(url, data = json.dumps({"id": i}))
	print(r.text)