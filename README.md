# Empire: Breakout — VulnHub Writeup

**Machine:** Empire: Breakout
**Platform:** [VulnHub](https://www.vulnhub.com/entry/empire-breakout,751/)
**Difficulty:** Easy/Intermediate
**Author of box:** Icex64 & Empire Cybersecurity
**Attacker machine:** Kali Linux (VMware Workstation)

## Summary

Empire: Breakout is a boot2root VulnHub machine that combines web enumeration,
classic esoteric-encoding puzzle solving, SMB enumeration, abuse of an
admin web panel (Webmin/Usermin), and Linux file capabilities abuse for
privilege escalation. This writeup documents the full path from initial
recon to root.

---

## 1. Reconnaissance

### 1.1 Host Discovery

Both the Kali attack box and the target VM were placed on the same VMware
network. The target's IP was identified with:

```bash
sudo netdiscover -r 192.168.142.0/24
```

### 1.2 Port Scanning

A full TCP port scan was run:

```bash
sudo nmap -p- --min-rate=1000 -T4 -Pn -n 192.168.142.129
```

> **Note:** Initial scans stalled indefinitely at the "ARP Ping Scan" /
> "Parallel DNS resolution" stage. Adding `-n` (disable DNS resolution)
> resolved the issue — a reminder that `nmap` can hang on DNS lookups in
> certain lab network configurations.

Followed by a version/service scan on discovered ports:

```bash
sudo nmap -p80,139,445,10000,20000 -sC -sV -A -n 192.168.142.129
```

**Open ports found:**

| Port  | Service              | Version                       |
|-------|-----------------------|--------------------------------|
| 80    | HTTP (Apache)          | Apache 2.4.51 (Debian)        |
| 139   | NetBIOS-SSN (Samba)    | Samba 4                       |
| 445   | NetBIOS-SSN (Samba)    | Samba 4                       |
| 10000 | HTTP (Webmin)          | MiniServ 1.981                |
| 20000 | HTTP (Usermin)         | MiniServ 1.830                |

---

## 2. Web Enumeration

The default Apache "It works!" page was inspected. A directory brute-force
with `gobuster` found nothing of interest beyond the default page and
`/manual`:

```bash
gobuster dir -u http://192.168.142.129/ -w /usr/share/wordlists/dirb/common.txt -x txt,php,html
```

However, viewing the **page source** (`Ctrl+U`) revealed a hidden HTML
comment at the very bottom of the page containing a message encoded in
**Brainfuck**:

```
don't worry no one will get here, it's safe to share with you my access. Its encrypted :)

++++++++++[>+>+++>+++++++>++++++++++<<<<-]>>++++++++++++++++.++++.>>+++++++++++++++++.----.<++++++++++.-----------.>-----------.++++.<<+.>-.--------.++++++++++++++++++++.<------------.>>---------.<<++++++.++++++.
```

### Decoding Brainfuck

Decoded with a small custom Python interpreter:

```python
def brainfuck(code):
    code = ''.join(filter(lambda x: x in '><+-.,[]', code))
    tape = [0] * 30000
    ptr = 0
    output = ''
    i = 0
    loop_stack = []
    while i < len(code):
        c = code[i]
        if c == '>': ptr += 1
        elif c == '<': ptr -= 1
        elif c == '+': tape[ptr] = (tape[ptr] + 1) % 256
        elif c == '-': tape[ptr] = (tape[ptr] - 1) % 256
        elif c == '.': output += chr(tape[ptr])
        elif c == '[':
            if tape[ptr] == 0:
                depth = 1
                while depth > 0:
                    i += 1
                    if code[i] == '[': depth += 1
                    elif code[i] == ']': depth -= 1
            else:
                loop_stack.append(i)
        elif c == ']':
            if tape[ptr] != 0:
                i = loop_stack[-1]
            else:
                loop_stack.pop()
        i += 1
    return output
```

**Result (candidate password):**

```
.2uqPEfj3D<P'a-3
```

---

## 3. SMB Enumeration

Null-session SMB enumeration was attempted:

```bash
smbclient -L //192.168.142.129/ -N
enum4linux -a 192.168.142.129
```

No readable shares were available, but RID cycling in `enum4linux`
revealed a local Unix user:

```
S-1-22-1-1000 Unix User\cyber (Local User)
```

This gave us a credential pair to try: **`cyber` : `.2uqPEfj3D<P'a-3`**

---

## 4. Initial Access — Usermin (port 20000)

The credentials did not work against Webmin (port 10000), but succeeded
against **Usermin** on port 20000:

```
https://192.168.142.129:20000
Username: cyber
Password: .2uqPEfj3D<P'a-3
```

Using the **Applications → Upload and Download** module (and later
**Tools → Command Shell**), the home directory of `cyber` was inspected,
revealing two files:

- `user.txt` → contained the first flag
- `tar` → a suspicious binary copy of `tar` sitting in the user's home directory

**User flag:**

```
3mp!r3{You_Manage_To_Break_To_My_Secure_Access}
```

> Attempting to upload a PHP reverse shell to `/var/www/html` via the
> Usermin "Upload to server" module failed with a permission error — the
> `cyber` user does not own that directory. Command execution was instead
> achieved directly through the built-in **Command Shell** module under
> **Tools**, which executes one command at a time against the target
> system (not an interactive shell).

---

## 5. Privilege Escalation — Abusing `tar` Capabilities

Running `getcap` on the suspicious `tar` binary revealed it had been
granted a special Linux **capability**:

```bash
getcap /home/cyber/tar
```
```
tar cap_dac_read_search=ep
```

`cap_dac_read_search` allows a binary to **bypass file read/directory
search permission checks** — effectively letting it read any file on the
filesystem regardless of ownership or permissions, without being fully
SUID root.

This was abused to read a root-owned backup file that the `cyber` user
could not access directly:

```bash
/home/cyber/tar -cvf /tmp/pass.tar /var/backups/.old_pass.bak
tar -xvf /tmp/pass.tar -C /tmp
cat /tmp/var/backups/.old_pass.bak
```

**Recovered root password:**

```
Ts&4&YurgtRX(=~h
```

---

## 6. Root

Logged back into Usermin (port 20000) with:

```
Username: root
Password: Ts&4&YurgtRX(=~h
```

Using the Command Shell module again:

```bash
cat /root/root.txt
```

(The exact flag filename turned out to be case-sensitive: `rOOt.txt`.)

**Root flag:**

```
3mp!r3{You_Manage_To_BreakOut_From_My_System_Congratulation}
```

---

## 7. Lessons Learned / Key Takeaways

1. **DNS resolution can silently hang `nmap` scans** — use `-n` in lab
   environments with no reverse DNS.
2. **Always inspect page source**, not just the rendered page — hidden
   comments are a common CTF technique.
3. **Esoteric encodings (Brainfuck, Base-family, etc.)** are a common
   obfuscation layer for credentials in CTFs; always worth decoding
   suspicious strings found in comments.
4. **Null-session SMB / RID cycling** can enumerate valid usernames even
   without share access.
5. **Linux Capabilities** (`getcap`/`setcap`) are a powerful and often
   overlooked privilege escalation vector — a binary doesn't need to be
   SUID root to be dangerous; a single capability like
   `cap_dac_read_search` is enough to leak sensitive files.
6. **Admin web panels (Webmin/Usermin)** are high-value targets once
   valid credentials are found — their built-in file managers and shell
   modules can provide code execution without needing a traditional
   reverse shell.

---

## Tools Used

- `nmap` — port scanning & service enumeration
- `netdiscover` — host discovery
- `gobuster` — web content discovery
- `smbclient` / `enum4linux` — SMB enumeration
- Custom Python Brainfuck interpreter
- Usermin web panel (built-in Command Shell / File Manager)
- `tar` + Linux Capabilities abuse

---

*This writeup is for educational purposes only, documenting a deliberately
vulnerable machine from [VulnHub](https://www.vulnhub.com/).*
