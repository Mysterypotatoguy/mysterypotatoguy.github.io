---
layout: post
categories: writeup
author: Alex Butler
tags: [reverse-engineering, pwn]
---
coffee_invocation was one of the reversing challenges for the HTB x UNI 2020 CTF, with its twist being that rather than just a standard C or C++ program, it utilises the [Java Native Interface](https://en.wikipedia.org/wiki/Java_Native_Interface) to execute most of the program logic
As far as I can tell no team solved this during the event, likely due to perceived time investment for learning about JNI, but it is surprisingly simple once you can wrap your head around some of the obstacles.

There were no debugging symbols present on this binary so any function names, apart from the JNI provided ones, have been provided by myself from deducing what they do. 

---
## main

Decompiling `main` immediately gives away the JNI twist for this challenge, the first function call is to `JNI_CreateJavaVM`, with some arguments that consist of some unknown numbers and strings.
I imported [this JNI header definition](https://gist.github.com/jcalabres/bf8d530b3f18c30ca6f66388357b1d91) into Ghidra to define the JNI specific types and allow me to view which fields and functions were being accessed, from here we can make a little more sense of things.

After this, the arguments to `JNI_CreateJavaVM` make a bit more sense. The function arguments are a pointer to a `JavaVM` struct, a pointer to a `JNIEnv` struct, and a `JavaVMInitArgs` struct -
The `JVMInitArgs` don't tell us much, the struct only takes a `version`, `nOptions` and `options` from which we can determine the Java version is 1.8.
The `jvm` and `env` pointers are then populated with the respective structs, these are the structs with which the program will interface with the Java process, the `JavaVM` struct being a function table and an interface to the running VM, providing the ability to attach threads or destroy it. 
The `JNIEnv` struct is far more useful in this challenge, providing a function table giving access to call methods, edit fields, and create objects.

![main](/images/coffee_main.png)

### get_option

The next call is to a function I have renamed to `get_option`, it is a fairly simple function which prints some ASCII art and asks for a selection from a menu, on picking anything but `[REDACTED]` the Java VM is destroyed and the program terminates. On picking `[REDACTED]` the function returns back to `main`

![get_option](/images/coffee_get_option.png)

Next, `main` checks `argc` is greater than 2 (One argument supplied via the command line since `argv[0]` is the command with which the program was invoked). If there is no argument present a message is printed via the renamed `print` function

### print

Printing to standard out is usually pretty simple in C, but the challenge authors decided to rewrite this functionality with JNI. Using the JNI definitions and some basic Java knowledge, it's pretty clear that this function just finds the `PrintStream` of `System.out`, then calls `println(String)` on it, providing the `char*` passed in the original C function.

![print](/images/coffee_print.png)

This `print` (and later `print_str` which seems to be identical) function is used for all further printing within the program.

### get_flag

Focussing back on `main`, if the `argc < 2` check does not pass, the next call is to a function I renamed to `get_flag`, passing the `JNIEnv` and `argv[1]` as arguments.
This function calls `verify1` and `verify2`, checks if they both return `0` and if so, prints out some ASCII art and gives us the flag.

![get_flag](/images/coffee_get_flag.png)

## verify1

Here begins the most complex parts of this challenge, `verify1` first calls a function I have renamed `hook_shutdown`, which essentially overrides Java's `static native void halt0(int status)` function and replaces it with a function `shutdown_hook_param_save`, this either saves the status code in a global variable, or if it is already set, compares the status code with the currently stored value and replaces it if it is less than. This will be used later for some program logic.

![verify1](/images/coffee_verify1.png)

![shutdown](/images/coffee_shutdown.png)

### get_remappings / Remapping Type caches

`get_remappings` is a function which takes an integer and depending on that integer, returns a pointer to a different byte array. These arrays all contain values from hex 0x00 to hex 0xFF, but have some variation on their order. For example `plus_3D` begins at 0x3D and increments at each index, wrapping around to 0x00 after 0xFF.

![remappings](/images/coffee_remappings.png)

In a few places this challenge will play around with the caches of some of Java's boxed types such as `Byte`, `Short`, `Character` and `Boolean`. These caches hold all of the 256 possible values for `Byte` and a variable number for `Character` or `Short`. By overwriting these, any operations performed within the upcoming Java code will use these new mappings, so we must be aware of this going forth.

![remap_bytes](/images/coffee_remap_bytes.png)
![remap_shorts](/images/coffee_remap_shorts.png)

For `verify1`, `Byte` and `Short` are remapped to new byte orders, `plus_3D` (Hex 00 to FF but offset by +3D)  and `00_CD_9A_67_34` (this is the pattern of 5 bytes which are all incremented to form the pattern) respectively.

---

Two compiled Java class files are contained within this binary, `get_verify_source` selects which one to access and then provides a pointer to it as well as its length in bytes. 
`verify1` accesses the first and makes a JNI call to `DefineClass` to load the class into the JVM. Then, still using JNI, creates an empty `String`, a length 2 `String[]` array of these empty `String`s. Our input string which is taken from `argv[1]` is substringed to length 30, placed in index 0 of the 2-element `String[]` array, and is then accompanied by a seemingly random `String` of characters placed in slot 1.
The `verify1` class now has its main method called via `CallStaticVoidMethod` with the 2-element `String[]` as its `String[] args` argument.

Extracting the `verify1` source and decompiling it (with some re-arranging of code for readability) we find a fairly simple functionality. Both `String`s from the 2-element array are checked to be present, non-null and of the same length. Providing this is true, each character in the `String` is compared to its corresponding character in the other `String` and if all match, the `main` method can exit with status 0, else it will return with a non-zero value depending on which condition was not met.

![verify1_java](/images/coffee_verify1_java.png)

However, remembering that both the `Byte` and `Short` caches have been tampered with, we must do some scripting to match values in both arrays to their remappings, and reverse this to find how we can match our input to the remapped second `String`.

```
remap1 = "3d 3e 3f 40 41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f 50 51 52 53 54 55 56 57 58 59 5a 5b 5c 5d 5e 5f 60 61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f 70 71 72 73 74 75 76 77 78 79 7a 7b 7c 7d 7e 7f 80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f 90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f a0 a1 a2 a3 a4 a5 a6 a7 a8 a9 aa ab ac ad ae af b0 b1 b2 b3 b4 b5 b6 b7 b8 b9 ba bb bc bd be bf c0 c1 c2 c3 c4 c5 c6 c7 c8 c9 ca cb cc cd ce cf d0 d1 d2 d3 d4 d5 d6 d7 d8 d9 da db dc dd de df e0 e1 e2 e3 e4 e5 e6 e7 e8 e9 ea eb ec ed ee ef f0 f1 f2 f3 f4 f5 f6 f7 f8 f9 fa fb fc fd fe ff 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f 30 31 32 33 34 35 36 37 38 39 3a 3b 3c"
remap2 = "00 cd 9a 67 34 01 ce 9b 68 35 02 cf 9c 69 36 03 d0 9d 6a 37 04 d1 9e 6b 38 05 d2 9f 6c 39 06 d3 a0 6d 3a 07 d4 a1 6e 3b 08 d5 a2 6f 3c 09 d6 a3 70 3d 0a d7 a4 71 3e 0b d8 a5 72 3f 0c d9 a6 73 40 0d da a7 74 41 0e db a8 75 42 0f dc a9 76 43 10 dd aa 77 44 11 de ab 78 45 12 df ac 79 46 13 e0 ad 7a 47 14 e1 ae 7b 48 15 e2 af 7c 49 16 e3 b0 7d 4a 17 e4 b1 7e 4b 18 e5 b2 7f 4c 19 e6 b3 80 4d 1a e7 b4 81 4e 1b e8 b5 82 4f 1c e9 b6 83 50 1d ea b7 84 51 1e eb b8 85 52 1f ec b9 86 53 20 ed ba 87 54 21 ee bb 88 55 22 ef bc 89 56 23 f0 bd 8a 57 24 f1 be 8b 58 25 f2 bf 8c 59 26 f3 c0 8d 5a 27 f4 c1 8e 5b 28 f5 c2 8f 5c 29 f6 c3 90 5d 2a f7 c4 91 5e 2b f8 c5 92 5f 2c f9 c6 93 60 2d fa c7 94 61 2e fb c8 95 62 2f fc c9 96 63 30 fd ca 97 64 31 fe cb 98 65 32 ff cc 99 66 33"

remap_bytes = [int(i, 16) for i in remap1.split(' ')]
remap_shorts = [int(i, 16) for i in remap2.split(' ')]

known_string = "u90\fp0 k0u0\fk0 &a0\f&p\f+0\f9!zk:"
input_str = ""

for char in known_string:
    input_str = input_str + chr(remap_bytes.index(remap_shorts[ord(char)]))

print(input_str)
```

And this gives us: 
```
th3_s3cr3t3_r3c1p3_1s_23_h0ur5
```

Running this through `verify1` as a standalone Java program exits successfully with a zero exit code, verifying that this is the correct string!

## verify2

`verify2` follows much of the same story as `verify1`, another Java class file is embedded in the binary, and caches are remapped. However, this one will be slightly more tricky.

![verify2](/images/coffee_verify2.png)

The first difference we see is that the `hook_shutdown` function is now called with a different replacement function. I have named this `remap_character_set` since it appears to remap the `char` array to one of 15 different remappings, depending on the exit code received. There also appears to be a global variable modified each time which eventually is returned as the result of `verify2`.

![remap_chars](/images/coffee_remap_chars.png)

There is another new function which I have named `invert_booleans`, the purpose of which is to swap the `true` and `false` definitions within the `Boolean` class's fields. This means we will need to take care when reading the Java source for the `verify2` class, as any booleans boxed into a `Boolean` will be inverted.
This time the second 30-char half of our input string from `argv` is passed to the Java `main` method.

![invert_bools](/images/coffee_invert_bools.png)

The first part of the `main` method is much of the same checks, the `args` array must be non-null and of length 1, and the length of our input string must be an even number.
From there it iterates over the input string, splitting it into 2 character chunks, then calling `complexSort(chars, true)`. `complexSort` boxes the input `String` into an array of `Char`s, which remaps them onto the mappings set earlier, then if the second boolean argument is `true` (or in our inverted case, `false`) then the `Char`s are sorted by the standard library `Arrays.sort` function, combined back into a `String` and returned.
`complexSort` is called again, this time with a hard-coded string `Cr1KD5mk0_uUzQYifaGVqlN2B3wvpgPtSx6Odo{8hjJLHy9IXb4RnWZ}TAFEsMce7` and `false`. This means the string will be remapped and *will* be sorted into its natural ordering.
Both 2-character chunks are then compared to each other. If they match, `System.exit(i+3)` is called, this is intercepted by the shutdown hook set earlier and switches the char remapping to the next mapping set.

![verify2_java](/images/coffee_verify2_java.png)

This requires another script to try to reverse - 
```
mappings = [
		"00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f 55 43 78 7b 4b 47 69 56 67 41 3a 3b 3c 3d 3e 3f 40 76 52 34 38 79 61 35 54 6f 53 6d 63 4f 49 4e 5f 32 7d 7a 71 50 75 33 42 45 66 5b 5c 5d 5e 30 60 57 48 58 6c 51 65 39 4d 5a 4a 62 64 6e 73 72 74 6b 77 31 44 37 68 36 59 46 70 4c 7c 6a 7e 7f 80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f 90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f a0 a1 a2 a3 a4 a5 a6 a7 a8 a9 aa ab ac ad ae af b0 b1 b2 b3 b4 b5 b6 b7 b8 b9 ba bb bc bd be bf c0 c1 c2 c3 c4 c5 c6 c7 c8 c9 ca cb cc cd ce cf d0 d1 d2 d3 d4 d5 d6 d7 d8 d9 da db dc dd de df e0 e1 e2 e3 e4 e5 e6 e7 e8 e9 ea eb ec ed ee ef f0 f1 f2 f3 f4 f5 f6 f7 f8 f9 fa fb fc fd fe ff 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
		"00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f 6b 41 63 31 51 43 72 76 4d 48 3a 3b 3c 3d 3e 3f 40 68 45 56 73 4f 57 70 37 46 55 44 74 42 30 6e 61 5f 62 36 58 6c 65 52 53 4c 34 5b 5c 5d 5e 71 60 4b 54 77 47 49 59 6f 7b 38 4a 67 79 78 6a 7d 7a 35 33 6d 32 64 69 39 75 4e 5a 66 7c 50 7e 7f 80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f 90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f a0 a1 a2 a3 a4 a5 a6 a7 a8 a9 aa ab ac ad ae af b0 b1 b2 b3 b4 b5 b6 b7 b8 b9 ba bb bc bd be bf c0 c1 c2 c3 c4 c5 c6 c7 c8 c9 ca cb cc cd ce cf d0 d1 d2 d3 d4 d5 d6 d7 d8 d9 da db dc dd de df e0 e1 e2 e3 e4 e5 e6 e7 e8 e9 ea eb ec ed ee ef f0 f1 f2 f3 f4 f5 f6 f7 f8 f9 fa fb fc fd fe ff 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
		"00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f 6d 35 56 38 34 59 49 71 54 77 3a 3b 3c 3d 3e 3f 40 41 74 58 33 63 57 47 61 4e 6b 76 67 4c 39 44 4a 7b 5f 70 64 37 65 32 30 52 62 5b 5c 5d 5e 6a 60 36 68 69 53 51 73 45 6f 4f 6c 7d 31 48 43 72 66 42 75 50 46 4b 7a 5a 79 55 6e 78 7c 4d 7e 7f 80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f 90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f a0 a1 a2 a3 a4 a5 a6 a7 a8 a9 aa ab ac ad ae af b0 b1 b2 b3 b4 b5 b6 b7 b8 b9 ba bb bc bd be bf c0 c1 c2 c3 c4 c5 c6 c7 c8 c9 ca cb cc cd ce cf d0 d1 d2 d3 d4 d5 d6 d7 d8 d9 da db dc dd de df e0 e1 e2 e3 e4 e5 e6 e7 e8 e9 ea eb ec ed ee ef f0 f1 f2 f3 f4 f5 f6 f7 f8 f9 fa fb fc fd fe ff 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
		"00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f 68 64 59 52 49 45 51 31 74 34 3a 3b 3c 3d 3e 3f 40 71 47 55 4d 66 35 61 65 6d 43 50 7d 63 67 41 6e 6f 78 58 6a 46 4c 54 77 30 39 5b 5c 5d 5e 62 60 7b 32 57 69 6b 72 36 37 38 70 4e 76 48 4a 5a 56 75 42 44 4f 79 4b 73 53 33 5f 7a 7c 6c 7e 7f 80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f 90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f a0 a1 a2 a3 a4 a5 a6 a7 a8 a9 aa ab ac ad ae af b0 b1 b2 b3 b4 b5 b6 b7 b8 b9 ba bb bc bd be bf c0 c1 c2 c3 c4 c5 c6 c7 c8 c9 ca cb cc cd ce cf d0 d1 d2 d3 d4 d5 d6 d7 d8 d9 da db dc dd de df e0 e1 e2 e3 e4 e5 e6 e7 e8 e9 ea eb ec ed ee ef f0 f1 f2 f3 f4 f5 f6 f7 f8 f9 fa fb fc fd fe ff 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
		"00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f 71 33 7b 42 31 61 55 7a 52 6a 3a 3b 3c 3d 3e 3f 40 64 5a 53 6b 58 34 44 79 78 69 4d 6f 76 4f 6c 77 74 54 63 75 68 70 30 41 7d 6d 5b 5c 5d 5e 39 60 48 36 56 32 67 37 45 62 50 51 43 4e 59 72 4a 49 66 4b 35 38 5f 57 47 46 73 6e 4c 7c 65 7e 7f 80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f 90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f a0 a1 a2 a3 a4 a5 a6 a7 a8 a9 aa ab ac ad ae af b0 b1 b2 b3 b4 b5 b6 b7 b8 b9 ba bb bc bd be bf c0 c1 c2 c3 c4 c5 c6 c7 c8 c9 ca cb cc cd ce cf d0 d1 d2 d3 d4 d5 d6 d7 d8 d9 da db dc dd de df e0 e1 e2 e3 e4 e5 e6 e7 e8 e9 ea eb ec ed ee ef f0 f1 f2 f3 f4 f5 f6 f7 f8 f9 fa fb fc fd fe ff 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
		"00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f 41 4f 7a 30 6a 67 5a 7b 5f 54 3a 3b 3c 3d 3e 3f 40 47 33 72 69 6b 64 32 6c 62 77 49 57 53 38 66 7d 46 4d 70 4b 4e 76 36 55 65 74 5b 5c 5d 5e 4a 60 45 59 78 31 58 42 43 51 61 39 73 79 6e 52 44 63 4c 37 34 6d 48 50 71 35 6f 68 75 7c 56 7e 7f 80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f 90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f a0 a1 a2 a3 a4 a5 a6 a7 a8 a9 aa ab ac ad ae af b0 b1 b2 b3 b4 b5 b6 b7 b8 b9 ba bb bc bd be bf c0 c1 c2 c3 c4 c5 c6 c7 c8 c9 ca cb cc cd ce cf d0 d1 d2 d3 d4 d5 d6 d7 d8 d9 da db dc dd de df e0 e1 e2 e3 e4 e5 e6 e7 e8 e9 ea eb ec ed ee ef f0 f1 f2 f3 f4 f5 f6 f7 f8 f9 fa fb fc fd fe ff 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
		"00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f 55 75 30 32 6e 7d 41 56 34 4c 3a 3b 3c 3d 3e 3f 40 59 68 58 37 36 71 53 39 50 48 6d 7a 5f 6c 4f 51 45 6a 77 31 65 46 38 64 70 74 5b 5c 5d 5e 43 60 4a 76 5a 4d 73 4b 79 6f 57 52 62 33 67 69 35 72 78 44 54 49 4e 61 6b 7b 66 63 47 7c 42 7e 7f 80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f 90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f a0 a1 a2 a3 a4 a5 a6 a7 a8 a9 aa ab ac ad ae af b0 b1 b2 b3 b4 b5 b6 b7 b8 b9 ba bb bc bd be bf c0 c1 c2 c3 c4 c5 c6 c7 c8 c9 ca cb cc cd ce cf d0 d1 d2 d3 d4 d5 d6 d7 d8 d9 da db dc dd de df e0 e1 e2 e3 e4 e5 e6 e7 e8 e9 ea eb ec ed ee ef f0 f1 f2 f3 f4 f5 f6 f7 f8 f9 fa fb fc fd fe ff 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
		"00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f 30 58 6d 45 46 6e 38 4a 4d 36 3a 3b 3c 3d 3e 3f 40 61 63 34 62 59 31 53 6c 55 54 4b 78 7b 5a 73 37 50 70 41 69 39 52 4c 5f 48 67 5b 5c 5d 5e 65 60 56 47 71 6a 32 6b 4e 33 72 42 49 74 44 6f 7d 75 77 57 35 64 7a 79 51 4f 43 68 76 7c 66 7e 7f 80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f 90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f a0 a1 a2 a3 a4 a5 a6 a7 a8 a9 aa ab ac ad ae af b0 b1 b2 b3 b4 b5 b6 b7 b8 b9 ba bb bc bd be bf c0 c1 c2 c3 c4 c5 c6 c7 c8 c9 ca cb cc cd ce cf d0 d1 d2 d3 d4 d5 d6 d7 d8 d9 da db dc dd de df e0 e1 e2 e3 e4 e5 e6 e7 e8 e9 ea eb ec ed ee ef f0 f1 f2 f3 f4 f5 f6 f7 f8 f9 fa fb fc fd fe ff 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
		"00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f 31 48 7b 76 70 7d 71 73 6d 6e 3a 3b 3c 3d 3e 3f 40 33 50 45 75 6b 57 56 5a 79 62 7a 4d 30 39 69 52 6f 49 67 72 6c 63 44 58 4a 53 5b 5c 5d 5e 74 60 61 65 37 47 66 51 55 6a 5f 64 34 4c 38 35 68 4e 4f 43 36 42 4b 54 59 46 78 77 41 7c 32 7e 7f 80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f 90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f a0 a1 a2 a3 a4 a5 a6 a7 a8 a9 aa ab ac ad ae af b0 b1 b2 b3 b4 b5 b6 b7 b8 b9 ba bb bc bd be bf c0 c1 c2 c3 c4 c5 c6 c7 c8 c9 ca cb cc cd ce cf d0 d1 d2 d3 d4 d5 d6 d7 d8 d9 da db dc dd de df e0 e1 e2 e3 e4 e5 e6 e7 e8 e9 ea eb ec ed ee ef f0 f1 f2 f3 f4 f5 f6 f7 f8 f9 fa fb fc fd fe ff 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
		"00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f 45 4c 6c 70 75 6a 52 76 6d 73 3a 3b 3c 3d 3e 3f 40 48 32 47 54 66 56 7d 50 68 5f 46 39 55 51 78 74 71 42 7a 63 35 4f 61 33 62 34 5b 5c 5d 5e 6e 60 44 57 58 64 43 37 4a 4b 67 31 53 36 30 49 77 6f 72 4d 59 7b 65 38 79 5a 41 6b 4e 7c 69 7e 7f 80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f 90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f a0 a1 a2 a3 a4 a5 a6 a7 a8 a9 aa ab ac ad ae af b0 b1 b2 b3 b4 b5 b6 b7 b8 b9 ba bb bc bd be bf c0 c1 c2 c3 c4 c5 c6 c7 c8 c9 ca cb cc cd ce cf d0 d1 d2 d3 d4 d5 d6 d7 d8 d9 da db dc dd de df e0 e1 e2 e3 e4 e5 e6 e7 e8 e9 ea eb ec ed ee ef f0 f1 f2 f3 f4 f5 f6 f7 f8 f9 fa fb fc fd fe ff 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
		"00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f 6c 72 39 4d 74 4e 4f 75 49 68 3a 3b 3c 3d 3e 3f 40 37 35 32 64 7b 59 61 62 48 4c 63 77 36 69 30 44 6a 54 7d 6e 73 79 70 41 71 6f 5b 5c 5d 5e 4b 60 5a 46 33 34 55 42 6b 4a 47 65 5f 67 51 6d 57 53 66 78 52 76 38 56 45 43 50 7a 31 7c 58 7e 7f 80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f 90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f a0 a1 a2 a3 a4 a5 a6 a7 a8 a9 aa ab ac ad ae af b0 b1 b2 b3 b4 b5 b6 b7 b8 b9 ba bb bc bd be bf c0 c1 c2 c3 c4 c5 c6 c7 c8 c9 ca cb cc cd ce cf d0 d1 d2 d3 d4 d5 d6 d7 d8 d9 da db dc dd de df e0 e1 e2 e3 e4 e5 e6 e7 e8 e9 ea eb ec ed ee ef f0 f1 f2 f3 f4 f5 f6 f7 f8 f9 fa fb fc fd fe ff 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
		"00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f 66 38 58 61 4d 59 6c 36 45 53 3a 3b 3c 3d 3e 3f 40 39 52 77 33 63 30 32 57 31 41 78 46 43 6d 56 67 47 37 6f 7d 4f 65 75 34 76 69 5b 5c 5d 5e 74 60 5f 6a 42 4c 7b 64 79 68 70 7a 50 49 6e 35 48 5a 4b 6b 44 55 54 4e 73 51 71 72 4a 7c 62 7e 7f 80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f 90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f a0 a1 a2 a3 a4 a5 a6 a7 a8 a9 aa ab ac ad ae af b0 b1 b2 b3 b4 b5 b6 b7 b8 b9 ba bb bc bd be bf c0 c1 c2 c3 c4 c5 c6 c7 c8 c9 ca cb cc cd ce cf d0 d1 d2 d3 d4 d5 d6 d7 d8 d9 da db dc dd de df e0 e1 e2 e3 e4 e5 e6 e7 e8 e9 ea eb ec ed ee ef f0 f1 f2 f3 f4 f5 f6 f7 f8 f9 fa fb fc fd fe ff 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
		"00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f 4d 4b 42 79 4f 6c 68 69 63 75 3a 3b 3c 3d 3e 3f 40 56 7a 6d 64 70 6a 62 5f 38 30 4e 55 6f 4c 7b 31 36 53 7d 77 51 59 6b 46 32 43 5b 5c 5d 5e 50 60 61 67 6e 49 33 5a 41 58 4a 54 39 45 78 35 52 44 65 48 76 66 57 47 74 72 73 37 71 7c 34 7e 7f 80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f 90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f a0 a1 a2 a3 a4 a5 a6 a7 a8 a9 aa ab ac ad ae af b0 b1 b2 b3 b4 b5 b6 b7 b8 b9 ba bb bc bd be bf c0 c1 c2 c3 c4 c5 c6 c7 c8 c9 ca cb cc cd ce cf d0 d1 d2 d3 d4 d5 d6 d7 d8 d9 da db dc dd de df e0 e1 e2 e3 e4 e5 e6 e7 e8 e9 ea eb ec ed ee ef f0 f1 f2 f3 f4 f5 f6 f7 f8 f9 fa fb fc fd fe ff 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
		"00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f 52 48 67 4b 6a 55 71 54 79 57 3a 3b 3c 3d 3e 3f 40 59 36 6e 4c 53 7b 44 30 63 49 70 46 35 37 6d 7a 75 69 4f 61 42 74 6c 77 6f 7d 5b 5c 5d 5e 31 60 56 72 66 51 65 41 6b 43 47 39 68 33 45 76 4a 58 34 50 5a 64 4d 62 78 73 38 32 4e 7c 5f 7e 7f 80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f 90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f a0 a1 a2 a3 a4 a5 a6 a7 a8 a9 aa ab ac ad ae af b0 b1 b2 b3 b4 b5 b6 b7 b8 b9 ba bb bc bd be bf c0 c1 c2 c3 c4 c5 c6 c7 c8 c9 ca cb cc cd ce cf d0 d1 d2 d3 d4 d5 d6 d7 d8 d9 da db dc dd de df e0 e1 e2 e3 e4 e5 e6 e7 e8 e9 ea eb ec ed ee ef f0 f1 f2 f3 f4 f5 f6 f7 f8 f9 fa fb fc fd fe ff 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
		"00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f 79 7d 31 68 36 4d 62 67 32 4b 3a 3b 3c 3d 3e 3f 40 6d 44 47 42 78 51 35 74 72 56 57 4f 65 6b 59 6c 37 45 69 38 6f 4e 7b 4a 48 33 5b 5c 5d 5e 52 60 64 58 53 71 63 49 73 76 43 6a 30 66 5a 70 5f 46 55 6e 54 4c 50 77 34 41 75 61 39 7c 7a 7e 7f 80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f 90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f a0 a1 a2 a3 a4 a5 a6 a7 a8 a9 aa ab ac ad ae af b0 b1 b2 b3 b4 b5 b6 b7 b8 b9 ba bb bc bd be bf c0 c1 c2 c3 c4 c5 c6 c7 c8 c9 ca cb cc cd ce cf d0 d1 d2 d3 d4 d5 d6 d7 d8 d9 da db dc dd de df e0 e1 e2 e3 e4 e5 e6 e7 e8 e9 ea eb ec ed ee ef f0 f1 f2 f3 f4 f5 f6 f7 f8 f9 fa fb fc fd fe ff 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
]

for i in range(len(mappings)):
    mappings[i] = [chr(int(j, 16)) for j in mappings[i].split(' ')]

current_mapping = 0

ascii_range = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz{}"
input_str = ""
    
for i in range(0, 30, 2):
    chars = ascii_range[i:i+2]
    
    for char in chars:
        input_str += chr(mappings[current_mapping].index(char))
    current_mapping += 1
    
print(input_str)
```

Since we know `complexSort` will always sort the compared string into its natural ascii ordering (same string, true passed which is mapped to false so no `sort` call) we can sort it ourselves and skip a step, from there we just chunk the string into 2-character pairs and reverse the mapping, resulting with the output of the 2nd half of our flag:
```
_str41ght_0f_r34d1ng_J4v4_d0cs
```

## Success

From here we can combine the two halves to create the string `th3_s3cr3t3_r3c1p3_1s_23_h0ur5_str41ght_0f_r34d1ng_J4v4_d0cs`, which we can feed to the `[REDACTED]` option and...

![flag](/images/coffee_flag.png)

Our final flag is output - `HTB{th3_s3cr3t3_r3c1p3_1s_23_h0ur5_str41ght_0f_r34d1ng_J4v4_d0cs}` !

## Conclusions

This was a super fun challenge to solve after the actual competition and time pressures that come along with it, I got to combine my developing reverse engineering skills with my existing Java knowledge, along with some learning about how JNI works.
It can bend your brain a little thinking about all of the remappings, especially when true becomes false and vice-versa, but some simple scripting can help immensely.