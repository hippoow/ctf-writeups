# Chrono II writeup

## Introduction and Chrono I

Chrono I displays a simple message:
	2026/09/21/14:35:07 - "As always, The Time is always the key to unlock it"
	Ciphertext:
		ESUITO{gwfvb_xejqnf_nimgt_b_whhrlv}

		Flag Format: CSSCTF{...}

As we can see, we have multiple clues:
- first, the time displayed isn't the actual time and isn't changing through time,
- then the sentence "As always, The Time is always the key to unlock it"
- finally the encoded flag and the format it's supposed to be in once decoded.

If we look closely at the encoded flag, we can see two major things:
the header of the flag is the same length as "CSSCTF" and the "{}" are still here.
This makes us think about some simple substitution-based encoding.
After a quick lookup on the internet, it looks like a variant of Vigenère encoding, which substitutes each letter
with another. As a hint we also have the time, which could possibly be the key to decode this flag,
since it is oddly displayed for us to see it.
This guides us toward the Gronsfeld cipher, which is a variant of Vigenère but, instead of using a keyword,
uses a sequence of numbers as a key.
We then go to a website like dCode.com to decode the flag, trying the time as the key and...
bingo! We have our first flag.

This first challenge introduces us to Gronsfeld, which will be useful in Chrono II.

## Chrono II

This time the challenge looks a bit more complex. We have a website displaying multiple things:
- first we can see a clock in the top right corner of the website,
- we can also see a sentence "Gears are beautiful. A few turning together can tell the time"
- we can also see, with the same format as in Chrono I but a bit more complex and long,
rows of what seem like encrypted flags rolling across the bottom part of the website
- just on top of the displayed rolling flags we have some info: 1Hz, 60s capture window,
channel 002 and the same flag format as used in Chrono I
- on the left of those flags there is a download button, a json file recording the last 60s log
- those encrypted flags have special characters like "{}" and "_" that seem not to be moving; these are probably ignored by the key like in the first challenge

Seeing the flag change each second tells us one thing: something in the key changes every second.
It is surely not the same type of key as in the Chrono I challenge, since every part of the flag changes
each second. If only the second changed in the key, it would only change the end of the flag, not the whole.

We then proceed to build a script to tell us the distance in the alphabet between two letters,
then between each two letters of two strings.


```python
import json
import datetime


def cryptozer(clear, cypher):
    l2 = 0
    l1 = 0
    if clear == cypher:
        return 0
    l1 = ord(clear) - 64
    l2 = ord(cypher) - 64
    if l1 < 0 or l1 > 26:
        return 0
    i = l2 - l1
    # print(l1, l2, i)

    if i < 0:
        return i % 26
    return i


def decy_str(a, b):
    decy = []
    for x, y in zip(a, b):
        decy.append(cryptozer(x, y))
    return decy
```

With that script we first try to notice a pattern with the CSSCTF header of the flag,
but nothing seems to highlight until we download another log file and something seems familiar...

A similar pattern seems to highlight, every X encrypted flags,
repeating way after the first one we saw.
This was also visible without decrypting the key, just by doing a ctrl+f on an older log file, but this is the way I saw these patterns.

This guides us towards a rotating key mechanism:
we just have to extract each part of the key from those patterns to rebuild the entire key.

We just have to list every similar pattern and see, for two patterns, how many flags separate them
and most importantly how many seconds separate them.
We notice each similar pattern comes up on the same spot exactly 77s apart, so in another log file.

We then recall the hint sentence on the website quoting gears.
So in order to understand the mechanism we have to understand WHY 77 seconds.
We then notice 77 is the obvious product of two prime numbers, 7 and 11. The gears are surely 7 and 11, which tells us multiple things:
- firstly, two gears of 11 and 7 teeth meet the exact same position every 77 seconds,
- secondly, the key might in fact be a keystream, way longer than the flag, probably 77 numbers long, moving across the flag and encrypting it periodically.

This guides us towards the first thing we've done: comparing each line in the log file with the header of the flag, "CSSCTF",
which will return the correct first 6 numbers of the keystream for each line in the log file.

But we still have a value to determine: how many cases do we jump in the flag each second?
It can't be 1-5 since we don't see any overlap from line to line, and neither can it be 71-76 for the same reason.
So we then proceed to create a script that will brute-force this unknown value:


```python
data = json.load(open("chrono-ii-capture.json"))

def stream(s):
    r = {}
    for entries in data:
        ts = entries["timestamp"]
        c = entries["ciphertext"]
        dt = datetime.datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")
        dt = dt.replace(tzinfo=datetime.timezone.utc)
        t = int(dt.timestamp())
        cle = decy_str("CSSCTF", c)
        for i in range(6):
            pos = (s * t + i) % 77
            if pos in r and r[pos] != cle[i]:
                return None
            r[pos] = cle[i]
    return r

for j in range(77):
    r = stream(j)
    if r is not None:
        print(j, "=", len(r), "cases")
```


This script will display the only jumps without any discrepancy and the number of cases they fill, which will obviously be 77 cases.
We then proceed to rebuild the keystream with the same function "stream()" but with 43 this time.

And we finally create a function to decypher this flag using the keystream:


```python
def decypher(s, r):
    for i in data:
        ts = i["timestamp"]
        c = i["ciphertext"]
        dt = datetime.datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")
        dt = dt.replace(tzinfo=datetime.timezone.utc)
        t = int(dt.timestamp())
        out = ""
        j = 0
        for n in c:
            if n.isalpha():
                k = r[(s * t + j) % 77]
                if ord(n) > 64 and ord(n) < 91:
                    out += chr((ord(n) - 64 - k) % 26 + 64)
                elif ord(n) > 96 and ord(n) < 122:
                    out += chr((ord(n) - 96 - k) % 26 + 96)
                j += 1
            elif n.isdigit():
                k = r[(s * t + j) % 77]
                out += str((int(n) - k) % 10)
                j += 1
            else:
                out += n
        print(out)
```


By calling the two functions like this, decypher(43, stream(43)), we get multiple similar flags.
In order to determine the right one, since a lot of them seem to be truncated,
we look at the flag that comes up the most times and that is the most coherent out of all these outputs.

And... we have our flag!

## Flag:

CSSCTF{th3_cl0ck_r3m3mb3rs_3very_s3c0nd}

## Takeaway:

In this challenge I lost most of my time trying to reproduce the same logic as in Chrono I,
trying to compare the ciphers with the Time instead of comparing them with each other.
And the part where I lost most of my time is in fact one of the shortest paragraphs in this writeup...
But this gave me a lesson:
I should eliminate possible paths the fastest way possible instead of digging one until I feel like this isn't the right way.
