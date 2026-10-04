#run this script from the chrono-ii-scripts/ folder
import json
import datetime


def cryptozer(clear, cypher):
    l2 = 0
    l1 = 0
    if clear == cypher :
        return 0
    l1 = ord(clear)-64
    l2 = ord(cypher)-64
    if l1 < 0 or l1 > 26:
        return 0
    i = l2 - l1
    #print(l1, l2, i)

    if i < 0:
        return i%26
    return i


def deca_str(a, b):
    deca = []
    for x, y in zip(a,b):
        deca.append(cryptozer(x,y))
    return deca

data = json.load(open("chrono-ii-capture.json"))

def stream(s):
    r = {}
    for entries in data:
        ts = entries["timestamp"]
        c = entries["ciphertext"]
        dt = datetime.datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")
        dt = dt.replace(tzinfo=datetime.timezone.utc)
        t = int(dt.timestamp())
        cle = deca_str("CSSCTF", c)
        for i in range (6):
            pos = (s * t + i) % 77
            if pos in r and r[pos] != cle[i]:
                return None
            r[pos] = cle[i]
    return r

for j in range(77):
    r = stream(j)
    if r is not None:
        print(j, "=", len(r), "cases")
        




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
                k = r[(s * t + j)%77]
                if ord(n) > 64 and ord(n) < 91:
                    out += chr((ord(n) - 64 - k)%26+64)
                elif ord(n) > 96 and ord(n) < 122:
                    out += chr((ord(n)-96-k)%26+96)
                j += 1
            elif n.isdigit():
                k = r[(s * t + j)%77]
                out += str((int(n) - k)%10)
                j += 1
            else:
                out += n
        print(out)

decypher(43, stream(43))
