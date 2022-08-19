# Auto-updating Memory check crippler-inator
Cripples the integrity check built-in, so it allows you to edit memory without any issues.
UD*

# What is memory integrity check?
The memory integrity check is a set of functions that prevent you from editing memory in different regions. The regions that are scanned are ``.text``, ``.rdata``, ``.vmp1``, and ``.vmpx``. (``.vmp0`` is not scanned)

The memory that is scanned is then hashed and then send to the server for verification. If the hashes do not match you get kicked, this simply spoofs the hashes to make it always return the correct hashes the server is looking for.

# How to use
Simply import the files within the repository (utilities and integrity_check), include the integrity_check.hpp into your dllmain. Afterwards declare a variable (an example is located in dllmain.cpp) and call initialize_bypass()

# What if I don't want to make a new project
We have compiled it for you and put it into Releases section! So that you'll only have to inject it.

# Credits
* [RexiRexii](https://github.com/RexiRexii)
* [ModulusAtScriptWare](https://github.com/ModulusAtScriptWare)
* Pixleus

# Documentation Disclaimer
All the addresses and screenshots are from version ``version-dd069f433d43402d`` which was pushed to users on ``August 17, 2022``.

# How it Works
The memory integrity check works by having a main hasher that always runs and then (currently) 16 secondary hashers of which only 1 runs per server you connect to and is the same for everone who is connected to said server.

The reason the secondary hashers exist (and why only 1 runs per server you connect to) is to make it so the main hasher cannot be disabled by itself and to make finding all the "silent" checkers more difficult in an attempt to make a full bypass harder.

The bypass works by hooking the main hasher and spoofing the addresses read with a cloned region of memory while each of the secondary hashers are hooked and their scan results are saved and returned on lookup. (This was done because caching the results of the main hasher was more work than just spoofing the address directly)

## The Main Hasher
The main hasher is hooked at the entryoint of the loop for simplicity.
The image below is of the main hasher, with the highlighted address (0xDA8B0) where we hook.
The main info here is that ``ebx`` holds the address that is to be read from and hashed and then ``ecx`` holds the memory to scan to. The other values are not of use to us for this bypass.

![alt text](https://github.com/RexiRexii/memory-check-bypass/blob/main/images/MainHasher.png?raw=true)

## Secondary Hashers
A name that has been seen time and time again is silent checkers as only 1 of the (currently) 16 run per server while the others remain dormant.

The way these are bypassed are by running each one and saving the results of the hash. There are currently 30 regions that are scanned and saved. In a lazy attempt, instead of scanning for the math operation used with each hasher we simply just brute force the math operation by sending the hasher different keys and trying the result.

The image below is of one of the secondary hashers with the arguments renamed to what they are, with an unused 3rd argument which is just zero. As for argument 4 being the random key that they pass to the hasher to give each result a unique hash, which can easily be determined by passing a random number a couple times to brute force the operation without a second thought.

![alt text](https://github.com/RexiRexii/memory-check-bypass/blob/main/images/ASecondaryHasher.png?raw=true)

As for how the regions are determined, the regions and their sizes are stored in their own array that is stored in ``.vmpx`` memory and the resulting values are encrypted with the decyption showed when the memory is obtained. At the bottom of the image shows ``v11`` which is the current active secondary hasher. The arguments passed are shown in the image of a secondary hasher.

![alt text](https://github.com/RexiRexii/memory-check-bypass/blob/main/images/SecondaryHasherInvoker.png?raw=true)

If one so wanted, they could get the active secondary hasher by reading an offset off of ``ClientReplicator`` and decrypting it with the same sytem used for the hasher regions. The key for the active hasher is passed as argument 2. The address off of ``ClientReplicator`` can easily be found by looking at the only xref to this function, and looking at argument 2 which is shown in the image below. (The current offset writing this is ``0x2F24`` (or ``12068`` in decimal))

![alt text](https://github.com/RexiRexii/memory-check-bypass/blob/main/images/SecondaryHasherInvokerXref.png?raw=true)
