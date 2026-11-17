# 🔍 retool
 
> My first reverse-engineering tool, written in **bash**! 🐚
> Give it a file and it tells you what's inside, without running it. 🛡️
 
![bash](https://img.shields.io/badge/made%20with-bash-4EAA25?logo=gnubash&logoColor=white)
![status](https://img.shields.io/badge/status-learning%20project-blue)
![license](https://img.shields.io/badge/license-MIT-green)
 
---
 
## 🤔 What is this?
 
**Reverse engineering (RE)** means taking a finished program and figuring out what it does
without having the source code. Before diving deep, analysts do a quick **static triage**:
a first look at the file *without running it* (running unknown files can be dangerous! ⚠️).
 
`retool` automates that first look. I built it to **learn how executable files work**
(PE for Windows, ELF for Linux) and to practice bash scripting. 📚
 
## ✨ What it can do
 
| Command | What it does | |
|---------|--------------|---|
| `info`    | File type, size, hashes (MD5/SHA1/SHA256), entropy, PE/ELF header info | 🧾 |
| `strings` | Pulls readable text out of a binary and flags the interesting bits | 🔤 |
| `hex`     | Shows raw bytes in a hexdump | 🔢 |
| `all`     | `info` + interesting strings together | 🚀 |
 
### 🚩 What gets flagged in strings?
 
- 🌐 URLs and IP addresses
- 📧 Email addresses
- 📁 File paths and Windows registry keys
- ⚙️ Suspicious function names (like `VirtualAlloc`, `execve`, `strcpy`)
- 🔑 Things that look like passwords or API keys
## 🛠️ Install
 
```bash
git clone https://github.com/<your-username>/retool.git
cd retool
chmod +x retool.sh
./retool.sh help
```
 
**You need:** bash 4+, coreutils, `strings` (binutils), `awk`, and `xxd`.
On Kali/Ubuntu: `sudo apt install binutils xxd` 📦
 
> 🐍 There is also a Python version (`retool.py`) with the same features if you prefer Python.
 
## 🎮 How to use it
 
```bash
./retool.sh info sample.exe                  # quick overview
./retool.sh strings sample.bin -n 6 -i       # strings of 6+ chars, only flagged ones
./retool.sh hex sample.elf -o 0x400 -l 128   # 128 bytes starting at offset 0x400
./retool.sh all suspicious.bin               # everything at once
```
 
### 📸 Example output
 
```
$ ./retool.sh info /bin/ls
File     : /bin/ls
Type     : ELF executable
SHA256   : 2726eb35...
Entropy  : 5.93 / 8.00  (normal)
class    : 64-bit
type     : DYN (PIE/so)
machine  : x86-64
entry    : 0x6d30
```
 
## 🧠 Beginner cheat sheet
 
**What is entropy?** 🎲
A number from 0 to 8 that measures how random the bytes are.
Normal programs sit around 5-6. If it's **above ~7.2**, the file is probably **packed or encrypted**
(malware authors do this to hide code). 🕵️
 
**What are PE and ELF?** 📦
The "container formats" for programs. **PE** = Windows (`.exe`, `.dll`), **ELF** = Linux.
`retool` recognises them by their first bytes (the "magic bytes": `MZ` for PE, `7f 45 4c 46` for ELF).
 
**What are sections?** 🧩
Programs are split into parts like `.text` (code) and `.data` (variables).
A section with very high entropy can mean hidden or packed code.
 
**Why are some flags false alarms?** 🤷
The tags are just pattern matching. The word "system" in a help message isn't dangerous.
Treat flags as *"look here"*, not *"this is malware"*.
 
## 📖 What I learned building this
 
- How the PE and ELF headers are laid out (reading bytes at fixed offsets with `od`) 🔬
- How Shannon entropy works and how to compute it with `awk` 🧮
- Handling endianness (little vs big endian) 🔄
- Writing a bash script with subcommands and option parsing 🐚
## ⚠️ Limitations (it's v0.1!)
 
- 🐢 Slow on very big files (entropy is calculated in `awk`)
- 🔎 String flags are guesses, not real import table analysis
- 🪟 Only PE and ELF headers are parsed (no Mach-O yet)
- 🧪 Tested on a few files only, so bugs are possible. Please open an issue! 🐛
## 🗺️ Roadmap
 
- [ ] Parse the PE import table and ELF symbols (real API detection)
- [ ] Disassembly support (Capstone / objdump)
- [ ] JSON output
- [ ] Mach-O support
- [ ] Colored output 🌈
## 🙏 Disclaimer
 
For **learning, CTFs and defensive analysis** of files you're allowed to examine.
Never run unknown files on your real machine, use a VM. 🖥️
 
## 🤝 Contributing
 
I'm still learning, so tips, bug reports and pull requests are very welcome! 💙
 
## 📄 License
 
MIT. Do whatever you want, just keep the license notice.
 
---
 
⭐ If this helped you learn something, drop a star!
 
