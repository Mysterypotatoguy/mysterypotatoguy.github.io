---
layout: post
categories: writeup
author: Mysterypotatoguy
tags: [reverse-engineering, angr]
---
Crack The Password was one of the reverse engineering challenges for Deloitte's 2022 Hacky Holidays CTF. This was a fairly simple reversing challenge with just some byte manipulation standing between myself and the flag, however, I chose to take a slightly different approach.

> The AI has taken control of the authentication system and we no longer have access to our important files! Can you help us find a way in by reversing the binary and cracking the password?

We are given a binary with debugging symbols and upon initial analysis we can see just how simple this challenge should be, in `main`, a password is read in from stdin and then passed to the `validatePassword` function. From here the return value determines whether "Access granted!" or "Access denied!" is printed.

![The main function](/images/crackthepassword-main.png)

In `validatePassword`, we see the password is being checked for a variety of conditions, and we can assume that the flag satisfies all of these checks.

![The validatePassword function](/images/crackthepassword-validatepassword.png)

Instead of reversing each of these manually, or creating a script to invert the checks, I decided to get some practice with a tool that had been discussed within LUHack sessions, angr.

Angr is a tool developed by Shellphish, a team well known for competing in the annual DEFCON CTF. It is at it's core a program analysis tool, containing modules for disassembly & decompilation, automatic exploit building, ROP chain building, just to name a few. With this challenge we will be leveraging its symbolic execution engine and constraint solving.

With a simple script this challenge can be solved automagically. All we need to do is provide angr an address to try and find a path to, and one to avoid. I chose two instructions that were part of printing the `Access granted/denied!` strings.

```python
import angr

FIND_ADDR = 0x401659 # mov dword [esp], str.Congrats_ ; [0x8048654:4]=0x676e6f43 LEA str.Congrats_ ; "Congrats!" @ 0x8048654
AVOID_ADDR = 0x40166a # mov dword [esp], str.Wrong_ ; [0x804865e:4]=0x6e6f7257 LEA str.Wrong_ ; "Wrong!" @ 0x804865e


def main():
	proj = angr.Project('CrackThePassword', load_options={"auto_load_libs": False})
	sm = proj.factory.simulation_manager()
	sm.explore(find=FIND_ADDR, avoid=AVOID_ADDR)
	return sm.found[0].posix.dumps(0).split(b'\0')[0] # stdin

if __name__ == '__main__':
	print(main())
```

And the flag is given to us!

`CTF{7a0QfB8dr1cF293Oy5a9fk9dA01c}`
