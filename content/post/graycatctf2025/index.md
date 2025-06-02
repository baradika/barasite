---
title: "GreyCTF 2025 Qualifiers"
date: "2025-06-01"
categories: [
    "Write-up"
]
tags : [
    "International",
    "TCP1P"
]
image: logo.png
---
>`GreyCTF 2025 Qualifiers` is a CTF (Capture The Flag) event hosted by an information security student group from the National University of Singapore.

On Saturday, May 31, 2025, I participated in GreyCTF 2025 with TCP1P, and I managed to solve 3 Crypto, 1 Forensic, and 1 Reverse Engineering challenges.

## Cryptography
### Tung Tung Tung Sahur

![](tungtungtungsahur.png)

After unzipping the zip file, we got 2 files, `tung_tung_tung_sahur.py` and `output.txt`

`tung_tung_tung_sahur.py`:
```py
from Crypto.Util.number import getPrime, bytes_to_long

flag = "grey{flag_here}"

e = 3
p, q = getPrime(512), getPrime(512)
N = p * q
m = bytes_to_long(flag.encode())
C = pow(m,e)

assert C < N
while (C < N):
    C *= 2
    print("Tung!")

# now C >= N

while (C >= N):
    C -= N
    print("Sahur!")


print(f"{e = }")
print(f"{N = }")
print(f"{C = }")
```
`output.txt`:
```
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Tung!
Sahur!
e = 3
N = 140435453730354645791411355194663476189925572822633969369789174462118371271596760636019139860253031574578527741964265651042308868891445943157297334529542262978581980510561588647737777257782808189452048059686839526183098369088517967034275028064545393619471943508597642789736561111876518966375338087811587061841
C = 49352042282005059128581014505726171900605591297613623345867441621895112187636996726631442703018174634451487011943207283077132380966236199654225908444639768747819586037837300977718224328851698492514071424157020166404634418443047079321427635477610768472595631700807761956649004094995037741924081602353532946351
```
#### Summary
##### 1. Understanding the Initial Encryption Process
The `tung_tung_tung_sahur.py` performs a slightly modified RSA encryption.

* The flag is converted into an integer `m`: `m = bytes_to_long(flag.encode())`

* The initial ciphertext is calculated as `C_initial = pow(m, e)`, with `e = 3`

* The script then `asserts assert C_initial < N`. This is crucial because it indicates that `m^e` (before the standard RSA modulo `N` operation) is indeed smaller than `N`. The variable `C` in the script is initialized with this `C_initial`

##### 2. Analyzing the "Tung!" Loop
```py
assert C < N
while (C < N):
    C *= 2
    print("Tung!")
```
This loop takes `C` (which was initially `m^e`) and repeatedly multiplies it by 2 until `C >= N`

If "Tung!" is printed `k` times(from `output.txt`, we know `k = 140`), then the value of `C` after this loop is:
$
C aftertung​=(me)⋅2k
$

##### 3. Analyzing the "Sahur!" Loop
```py
# now C >= N
while (C >= N):
    C -= N
    print("Sahur!")
print(f"{C = }") # This is C_final from output.txt
```
This loop essentially performs a modulo operation. `C` is repeatedly reduced by `N` until `C < N`. The value of `C` printed at the end of the script (`C_final` in our solver) is the result of $Caftertung​(mod N)$.

If "Sahur!" is printed `S` times (from `output.txt`, we know `s = 1`), this implies that $Caftertung​$ was in range [$s⋅N,(s+1)⋅N−1$] relative $Cfinal$. More precisely: \
$Caftertung = Cfinal + s⋅N$ \
Since `s = 1` (there's only one "Sahur!"), then:\
$Caftertung = Cfinal + N$

By combining the result from both loops, we get:\
$(m^e)⋅2^k = Cfinal+s⋅N$

##### Solve
To find `m`, Let's isolate $m^e$:\
$m^e=\frac{Cfinal​+s⋅N} {2^k}​$ \
Since all values on the right-hand side are int, and $m^e$ must also be an int, this division is an int divison (floor division)

After obtaining the value of $m^e$:

1. Use the values `e = 3`, `N`, and `C_final` provided in `output.txt`.

2. Determine `k = 140` (number of "Tung!" prints) and `s = 1` (number of "Sahur!" prints) from output.txt.

3. Calculate $m^e=(Cfinal​+1⋅N)//(2^{140})$.
    
4. Take the `e`-th root (i.e., cube root) of the resulting $m^e$ to get `m`. The function `gmpy2.iroot(value, root_degree)` is ideal for this as it finds integer roots.
    
5. Convert the integer `m` back into bytes using `long_to_bytes()` to reveal the flag.

`Solver.py`:
```py
from Crypto.Util.number import long_to_bytes
import gmpy2 

e = 3
N = 140435453730354645791411355194663476189925572822633969369789174462118371271596760636019139860253031574578527741964265651042308868891445943157297334529542262978581980510561588647737777257782808189452048059686839526183098369088517967034275028064545393619471943508597642789736561111876518966375338087811587061841
C_final = 49352042282005059128581014505726171900605591297613623345867441621895112187636996726631442703018174634451487011943207283077132380966236199654225908444639768747819586037837300977718224328851698492514071424157020166404634418443047079321427635477610768472595631700807761956649004094995037741924081602353532946351

num_tung = 140
num_sahur = 1
C_after_tung = C_final + num_sahur * N
m_pow_e = C_after_tung // (2**num_tung)
m, is_perfect_root = gmpy2.iroot(m_pow_e, e)
assert is_perfect_root root

flag = long_to_bytes(int(m)) 
print(flag.decode())
```
Flag: `grey{tUn9_t00nG_t0ONg_x7_th3n_s4hUr}`

### UWUSIGNATURES

![](uwusignature.png)

We got a zip file and 2 netcat server addres, after unzipping the zip file, we got a file named `uwusignatures.py` 

`uwusignatures.py`:
```py
❯ cat uwusignatures.py
from Crypto.Util.number import *
import json
import hashlib

KEY_LENGTH = 2048
FLAG = "grey{fakeflagfornow}"

class Uwu:
    def __init__(self, keylen):
        self.p = getPrime(keylen)
        self.g = getRandomRange(1, self.p)
        self.x = getRandomRange(2, self.p) # x is private key
        self.y = pow(self.g, self.x, self.p) # y is public key
        self.k = getRandomRange(1, self.p)
        while GCD(self.k, self.p - 1) != 1:
            self.k = getRandomRange(1, self.p)
        print(f"{self.p :} {self.g :} {self.y :}")
        print(f"k: {self.k}")
    def hash_m(self, m):
        sha = hashlib.sha256()
        sha.update(long_to_bytes(m))
        return bytes_to_long(sha.digest())
    def sign(self, m):
        assert m > 0
        assert m < self.p
        h = self.hash_m(m)
        r = pow(self.g, self.k, self.p)
        s = ((h - self.x * r) * pow(self.k, -1, self.p - 1)) % (self.p - 1)
        return (r, s)
    def verify(self, m, signature):
        r, s = signature
        assert r >= 1
        assert r < self.p
        h = self.hash_m(m)
        lhs = pow(self.g, h, self.p)
        rhs = (pow(self.y, r, self.p) * pow(r, s, self.p)) % self.p
        return lhs == rhs

def main():
    print("Welcome to my super uwu secure digital signature scheme!")
    uwu = Uwu(KEY_LENGTH)
    sign_count = 0
    while True:
        print("1. Show me some of your cutesy patootie signatures!")
        print("2. Get some of my uwu signatures (max 2)")
        choice = int(input("> "))
        if choice == 1:
            data = json.loads(input("Send me a message and a signature: "))
            m, r, s = data["m"], data["r"], data["s"]
            if m == bytes_to_long(b"gib flag pls uwu"):
                if uwu.verify(m, (r, s)):
                    print("Very cutesy, very mindful, very demure!")
                    print(FLAG)
                    exit()
                else:
                    print("Very cutesy, but not very mindful")
                    exit()
            else:
                print("Not very cutesy")
                exit()
        elif choice == 2:
            if sign_count >= 2:
                print("Y-Y-You'd steal from poor me? U_U")
                exit()
            data = json.loads(input("Send me a message: "))
            m = data["m"]
            if type(m) is not int or m == bytes_to_long(b"gib flag pls uwu"):
                print("Y-Y-You'd trick poor me? U_U")
                exit()
            r, s = uwu.sign(m)
            print(f"Here's your uwu signature! {s :}")
            sign_count += 1
        else:
            print("Not very smart of you OmO")
            exit()

if __name__ == "__main__":
    main()%           cat 
```
#### Summary
This challenge, `"UwuSignatures"` involved exploiting a flaw in a custom ElGamal-like digital signature scheme to forge a signature for a specific message and retrieve the flag.

The server implements a signature scheme with the following characteristics:

* Parameters & Keys:
    * `p`: A 2048-bit prime.
    * `g`: A random generator modulo `p`.
    * `x`: The private key, chosen randomly.
    * `y`: The public key, $y≡g^x(modp)$.

* Nonce `k`:
    * A nonce `k` is generated once per Uwu class instance
    * It's chosen such that `GCD(k, p - 1) = 1`, meaning $k−1(modp−1)$ exists

* Signing Process:
    * `h = SHA256(m)` (converted to an integer)
    * `r = pow(g, k, p)`
    * $s = ((h - x \cdot r) \cdot \text{pow}(k, -1, p - 1)) \pmod{p - 1}$

* Verification Process: A signature `(r, s)` for a message `m`(with hash `h`) is valid if $g^h = y^r ⋅ r^s (mod p) $. This is a standard verification equation for ElGamal signatures

#### Solve
First, we need receive the public parameters `p`, `g`, `y` and leaked nonce `k`

2. Obtain One Signature on a Chosen Message:
    * Choose an arbitary message `m_0` that isnt the forbidden one(e.g., `m_0 = 42`)
    * Use Option 2 to ask the server to sign `m_0`, the server returns `s_0`
    * Calculate $r_0 = \text{pow}(g, k, p)$ since `k`(and `g`, `p`) are known, we can compute `r_0`. This `r_0` will be the same for any signature generated during this session because `k` is fixed.
    * Calculate the hash $h_0 = \text{SHA256}(m_0)$

3. Recover the Private Key `x`:
    * We have the equation: $s_0​≡(h_0​−x⋅r_0​)k^{−1}(modp−1)$
    * To solve for `x`: $s_0​⋅k≡h_0​−x⋅r_0​(modp−1) x⋅r_0​≡h_0​−s_0​⋅k(modp−1) x ≡(h_0​−s_0​⋅k)⋅r_0^−1​(modp−1)$
    * All values on the right(`h_0`, `s_0`, `k`, `r_0`, `p-1`) are known. Compute $r_0^-1(mod p-1$ and then `x`

4. Forge the Signature for the Target Message:
    * The target message is $m_1 = \text{b"gib flag pls uwu"}$
    * Calculate its hash $h_1 = \text{SHA256}(m_1)$
    * The `r` component for this forged signature (`r_1`) will be the same as `r_0` cus `k` is reused $r_1 = r_0$
    * Using the recovered private key `x`, calculate the corresponding `s_1`: $s_1 \equiv (h_1 - x \cdot r_1)k^{-1} \pmod{p-1}$

5. Submit and win

`Solver.py`:
```py
from pwn import remote
import hashlib
import json

def bytes_to_long(b: bytes) -> int:
    return int.from_bytes(b, byteorder='big')

def modinv(a: int, m: int) -> int:
    return pow(a, -1, m)

def read_until_three_ints(io):
    while True:
        line = io.recvline(timeout=5).decode('utf-8', errors='ignore').strip()
        parts = line.split()
        if len(parts) == 3 and all(p.isdigit() for p in parts):
            return list(map(int, parts))

def read_until_nonce_k(io):
    while True:
        line = io.recvline(timeout=5).decode('utf-8', errors='ignore').strip()
        if line.startswith("k:"):
            try:
                return int(line.split("k:")[1].strip())
            except ValueError:
                continue.

def read_until_menu(io):
    while True:
        line = io.recvline(timeout=5).decode('utf-8', errors='ignore')      
        if line.startswith("2."):
            return

def main():
    io = remote('challs2.nusgreyhats.org', 33301)
    p, g, y = read_until_three_ints(io)
    k = read_until_nonce_k(io)
    read_until_menu(io)
    io.sendline(b'2')
    io.recvuntil(b"Send me a message:", timeout=5)
    m0 = 42
    io.sendline(json.dumps({ "m": m0 }).encode())
    line = io.recvline(timeout=5).decode().strip()
    try:
        s0 = int(line.split()[-1])
    except Exception:
        print("Failed to parse s0 from:", repr(line))
        return
    r = pow(g, k, p)
    h0 = int.from_bytes(
        hashlib.sha256(
            m0.to_bytes((m0.bit_length() + 7)//8, 'big')
        ).digest(),
        'big'
    )

    lhs = (s0 * k) % (p - 1)
    inv_r = modinv(r, p - 1)
    x = ((h0 - lhs) * inv_r) % (p - 1)
    forbidden = b"gib flag pls uwu"
    m1 = bytes_to_long(forbidden)
    h1 = int.from_bytes(hashlib.sha256(forbidden).digest(), 'big')

    inv_k = modinv(k, p - 1)
    s1 = ((h1 - x * r) * inv_k) % (p - 1)

    read_until_menu(io)

    io.sendline(b'1')
    io.recvuntil(b"Send me a message and a signature:", timeout=5)

    sig_payload = { "m": m1, "r": r, "s": s1 }
    io.sendline(json.dumps(sig_payload).encode())
    print(io.recvall(timeout=5).decode('utf-8', errors='ignore'))

if __name__ == '__main__':
    main()
```
Flag: `grey{h_h_H_h0wd_y0u_Do_tH4T_OMO}`

### Shaker
![](shaker.png)

We got a netcat server address and a zip file, extract the zip and i got python code named `shaker.py`


`Shaker.py`:
```py
import random
import hashlib 

class Shaker:

    def __init__(self, state):
        self.state = state
        self.x = random.randbytes(64)
        self.p = [i for i in range(64)]
        random.shuffle(self.p)

    def permute(self):
        self.state = [self.state[_] for _ in self.p]

    def xor(self):
        self.state = [a^b for a,b in zip(self.state, self.x)]

    def shake(self):
        self.xor()
        self.permute()

    def reset(self):
        random.shuffle(self.p)
        self.shake()

    def open(self):
        self.xor()
        return self.state

with open("flag.txt", "r") as f:
    flag = f.read().encode()

assert(len(flag) == 64)
assert(hashlib.md5(flag).hexdigest() == "4839d730994228d53f64f0dca6488f8d")
s = Shaker(flag)

ct = 0
MAX_SHAKES = 200
MENU = """Choose an option:
1. Shake the shaker
2. See inside
3. Exit
> """

while True:
    choice = input(MENU)
    if choice == '1':
        if (ct >= MAX_SHAKES):
            print("The shaker broke...")
            exit(0)
        s.shake()
        ct += 1
        print(f"You have shaken {ct} times.")

    if choice == '2':
        ret = s.open()
        s.reset()
        print(f"Result: {bytes(ret).hex()}")

    if choice == '3':
        exit(0)
```
#### Summary 
The `shaker.py` defines a `Shaker` class with the following key components and operations:
* Initialization (`__init__`):
    * The shaker is initialized with the `flag` (64 bytes) as its initial `state`
    * A secret 64-byte random key `self.x` is generated once and remains constant
    * A permutation `self.p` (an array of indices from 0 to 63) is randomly shuffled

* Core Operations:
    * `xor()`: The current `state` is XORed byte-wise with `self.x`. $S_{new}[i] ⊕ x[i]$
    * `permute()`: The current `state` is permuted according to `self.p`. If $P$ is the permutation array, then $S_{new}[i] = S_{current}[P[i]]$

* Main Shaker Actions:
    * `shake()`: Performs an `xor()` followed by a `permute()` on the current state.\
    $S\xrightarrow{xor}S ⊕ x \xrightarrow{permute} (S ⊕ x)_P$
    * `open()`: This is how we get output. It first performs `xor()` on the current state and returns the result. $S_{current} ⊕ x$. The internal state `self.state` is updated to this `output` value
    * `reset()`: This function is called after `open()` when we request to see inside (option 2). It first re-shuffles `self.p`(generating a new permutation $P_{new}$), and then calls `shake()`

* Interaction Loop:\
The server provides two main options:

1. Shake the shaker: Calls `s.shake()`. This modifies the internal state
2. See inside:
    * Calls `s.open()`, which computes $Output = S_{beforeopen} ⊕ x$. This `output` is sent to us. The shaker's internal state `s.state` becomes $S_{beforeopen} ⊕ x$
    * Then, `s.reset()` is called:
        * A new permutation $P_{new}$ is created for `s.p`
        * `s.shake()` is called. The state it operates on is $S_{beforeopen} ⊕ x$
            * `xor` step: $(S_{beforeopen}⊕ x) ⊕ x = S_{beforeopen}$
            * `permute()` step: The state becomes $(S_{beforeopen})P_{new}$. So, after each "See inside" operation, we receive $S_{k-1}  ⊕x$ (where $S_{k-1}$ was the state before this `open` call), and the shaker's internal state for next round becomes $S_k = (S_{k-1})P_{new}$

#### Solve 
The first, we must connect to the server and use option 2 (See inside) multiple times (e.g., `NUM_SAMPLES = 100`) to collect a set of outputs $O_1, O_2, ..., O_{100}$. Each $O_i$ is 64 bytes long. Then,

* Recover the XOR Key `x`:
    * For each byte position `j` from 0 to 63 (the length of `x`):
        * Iterate through all 256 possible byte values for `guess_x_byte`(out candidate for $x[j]$)
        * For the current `guess_x_byte`, check its validity: For every collected sample $O_i$ (from $i = 1$ to $100$): Calculate $candidate_flag_byte = O_i[j]$ ⊕ `guess_x_byte`. If `candidate_flag_byte` is __not__ within a predefined set of plausible flag char (e.g., `string.ascii_letters + string.digits + "{}_")`, then `guess_x_byte` is no the correct $x[j]$. Break and try the next `guess_x_byte`
        * If `guess_x_byte` satisfies the condition for all 100 samples (i.e., $O_i[j]$ ⊕ `guess_x_byte`is always a plausible flag char), then its a strong candidate for the true $x[j]$. The script stores the first such candidates found.
    * After iterating through all positions `j`, we will have recovered the full 64 byte key `x`.

* Recover the Flag:
    * Take the first output collected, $O_1$. We know $O_1 = F ⊕ x$
    * Therefore, the original flag $F$ can be recovered by computing $F = O_1 ⊕ x$, using the `recovered_X` from the previous step.

* Verify:
    * Calculate the MD5 hash of the recovered flag
    * Compare it against the target MD5 hash \
    ("4839d730994228d53f64f0dca6488f8d") 

`Solver.py`:
```py
import hashlib
from pwn import remote, log
import string

HOST = "challs.nusgreyhats.org"
PORT = 33302
NUM_SAMPLES = 100
FLAG_LEN = 64
TARGET_MD5 = "4839d730994228d53f64f0dca6488f8d"
PLAUSIBLE_FLAG_CHARS = set(map(ord, string.ascii_letters + string.digits + "{}_-!@#$%^&*()."))

def get_one_output(r):
    """Sends command to get one encrypted output and returns it as bytes."""
    r.sendlineafter(b"> ", b"2")
    r.recvuntil(b"Result: ")
    hex_output = r.recvline().strip().decode()
    return bytes.fromhex(hex_output)

def solve():
    """Connects to the server, recovers the XOR key and flag, then verifies MD5."""
    r = remote(HOST, PORT)
    log.info(f"Connected to {HOST}:{PORT}")

    observed_outputs = []
    log.info(f"Collecting {NUM_SAMPLES} samples...")
    for i in range(NUM_SAMPLES):
        try:
            output = get_one_output(r)
            if len(output) != FLAG_LEN:
                log.error(f"Output {i+1} has incorrect length: {len(output)}. Stopping.")
                r.close()
                return
            observed_outputs.append(output)
            if (i + 1) % 10 == 0 or (i + 1) == NUM_SAMPLES:
                log.info(f"Collected sample {i+1}/{NUM_SAMPLES}")
        except EOFError:
            log.error("Connection lost while collecting samples.")
            r.close()
            return
        except Exception as e:
            log.error(f"Error collecting sample {i+1}: {e}")
            r.close()
            return

        log.error("No samples were collected.")
        r.close()
        return

    recovered_X = bytearray(FLAG_LEN)
    any_ambiguity_in_key = False
    log.info("Recovering XOR key (self.x)...")

    for j in range(FLAG_LEN):
        possible_key_bytes_for_pos_j = [
            guess_x_byte for guess_x_byte in range(256)
            if all((sample[j] ^ guess_x_byte) in PLAUSIBLE_FLAG_CHARS for sample in observed_outputs)
        ]

        if not possible_key_bytes_for_pos_j:
            log.error(f"No plausible key byte found for position {j}. Consider revising PLAUSIBLE_FLAG_CHARS.")
            r.close()
            return

        if len(possible_key_bytes_for_pos_j) > 1:
            log.warning(f"Position {j} has {len(possible_key_bytes_for_pos_j)} possible key bytes: {possible_key_bytes_for_pos_j}. Using the first.")
            any_ambiguity_in_key = True
        
        recovered_X[j] = possible_key_bytes_for_pos_j[0]

        if (j + 1) % 8 == 0 or j == FLAG_LEN - 1:
             log.info(f"Recovered key byte {j+1}/{FLAG_LEN} (chosen: {recovered_X[j]}, candidates: {len(possible_key_bytes_for_pos_j)})")
    
    log.success(f"XOR key (self.x) recovered: {recovered_X.hex()}")

    recovered_flag = bytes(o_byte ^ x_byte for o_byte, x_byte in zip(observed_outputs[0], recovered_X))

    log.success(f"Recovered flag (bytes): {recovered_flag!r}")
    
    flag_str_decoded = None
    try:
        flag_str_decoded = recovered_flag.decode('utf-8')
        log.success(f"Recovered flag (UTF-8 string): {flag_str_decoded}")
    except UnicodeDecodeError:
        try:
            flag_str_decoded = recovered_flag.decode('latin-1')
            log.warning(f"Flag not UTF-8, decoded as Latin-1: {flag_str_decoded}")
        except UnicodeDecodeError:
            log.error(f"Flag is not valid UTF-8 or Latin-1. Raw hex: {recovered_flag.hex()}")

    md5_hash = hashlib.md5(recovered_flag).hexdigest()
    log.info(f"MD5 of recovered flag: {md5_hash}")

    if md5_hash == TARGET_MD5:
        log.success("MD5 MATCHES! Flag is correct.")
    else:
        log.error(f"MD5 MISMATCH. Target: {TARGET_MD5}, Got: {md5_hash}")
        if any_ambiguity_in_key:
            log.info("Ambiguity was encountered during key recovery. This might be the cause if the flag is incorrect. Review warnings for key byte choices.")
            
    r.close()

if __name__ == "__main__":
    solve()
```

Flag: `grey{kinda_long_flag_but_whatever_65k2n427c61ww064ac3vhzigae2qg}`


## Forensic
### Connection Issues

![](connectionissues.png)

So we got the zip files, and i got pcap file after extracted it. \
I started with check the strings, and i figure out some base64

![](stringsforen.png)

then i tried to decode it, and this is the result

![](base64.png)

just fix it, and u will get the flag

Flag: `grey{d1d_1_jus7_ge7_p01son3d}`

## Reverse Engineering
### reversing101

![](reversing101.png)

So we get zip file and netcat server address, when u get into the netcat, it will ask u some question and we must ask it all to get the flag

![](question1.png)

To answer the first question, we can just check it with gdb

![](infofunctions.png)

![](question2.png)

To answer this, we just need to decompile it,
```c

long a(char *param_1)

{
  long lVar1;
  char *local_10;
  
  local_10 = param_1;
  if (*param_1 == '\0') {
    lVar1 = 0;
  }
  else {
    do {
      local_10 = local_10 + 1;
    } while (*local_10 != '\0');
    lVar1 = (long)local_10 - (long)param_1;
  }
  return lVar1;
}
```

the `a` function is basically same as `strlen` from libc,

![](question3.png)

To answer this, we can checked by decompile `main` function
```C
undefined8 main(void)

{
  int iVar1;
  size_t sVar2;
  long in_FS_OFFSET;
  char local_118 [264];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_118[0] = '\0';
  local_118[1] = '\0';
  local_118[2] = '\0';
  local_118[3] = '\0';
  local_118[4] = '\0';
  local_118[5] = '\0';
  local_118[6] = '\0';
  local_118[7] = '\0';
  local_118[8] = '\0';
  local_118[9] = '\0';
  local_118[10] = '\0';
  local_118[0xb] = '\0';
  local_118[0xc] = '\0';
  local_118[0xd] = '\0';
  local_118[0xe] = '\0';
  local_118[0xf] = '\0';
  local_118[0x10] = '\0';
  local_118[0x11] = '\0';
  local_118[0x12] = '\0';
  local_118[0x13] = '\0';
  local_118[0x14] = '\0';
  local_118[0x15] = '\0';
  local_118[0x16] = '\0';
  local_118[0x17] = '\0';
  local_118[0x18] = '\0';
  local_118[0x19] = '\0';
  local_118[0x1a] = '\0';
  local_118[0x1b] = '\0';
  local_118[0x1c] = '\0';
  local_118[0x1d] = '\0';
  local_118[0x1e] = '\0';
  local_118[0x1f] = '\0';
  local_118[0x20] = '\0';
  local_118[0x21] = '\0';
  local_118[0x22] = '\0';
  local_118[0x23] = '\0';
  local_118[0x24] = '\0';
  local_118[0x25] = '\0';
  local_118[0x26] = '\0';
  local_118[0x27] = '\0';
  local_118[0x28] = '\0';
  local_118[0x29] = '\0';
  local_118[0x2a] = '\0';
  local_118[0x2b] = '\0';
  local_118[0x2c] = '\0';
  local_118[0x2d] = '\0';
  local_118[0x2e] = '\0';
  local_118[0x2f] = '\0';
  local_118[0x30] = '\0';
  local_118[0x31] = '\0';
  local_118[0x32] = '\0';
  local_118[0x33] = '\0';
  local_118[0x34] = '\0';
  local_118[0x35] = '\0';
  local_118[0x36] = '\0';
  local_118[0x37] = '\0';
  local_118[0x38] = '\0';
  local_118[0x39] = '\0';
  local_118[0x3a] = '\0';
  local_118[0x3b] = '\0';
  local_118[0x3c] = '\0';
  local_118[0x3d] = '\0';
  local_118[0x3e] = '\0';
  local_118[0x3f] = '\0';
  local_118[0x40] = '\0';
  local_118[0x41] = '\0';
  local_118[0x42] = '\0';
  local_118[0x43] = '\0';
  local_118[0x44] = '\0';
  local_118[0x45] = '\0';
  local_118[0x46] = '\0';
  local_118[0x47] = '\0';
  local_118[0x48] = '\0';
  local_118[0x49] = '\0';
  local_118[0x4a] = '\0';
  local_118[0x4b] = '\0';
  local_118[0x4c] = '\0';
  local_118[0x4d] = '\0';
  local_118[0x4e] = '\0';
  local_118[0x4f] = '\0';
  local_118[0x50] = '\0';
  local_118[0x51] = '\0';
  local_118[0x52] = '\0';
  local_118[0x53] = '\0';
  local_118[0x54] = '\0';
  local_118[0x55] = '\0';
  local_118[0x56] = '\0';
  local_118[0x57] = '\0';
  local_118[0x58] = '\0';
  local_118[0x59] = '\0';
  local_118[0x5a] = '\0';
  local_118[0x5b] = '\0';
  local_118[0x5c] = '\0';
  local_118[0x5d] = '\0';
  local_118[0x5e] = '\0';
  local_118[0x5f] = '\0';
  local_118[0x60] = '\0';
  local_118[0x61] = '\0';
  local_118[0x62] = '\0';
  local_118[99] = '\0';
  local_118[100] = '\0';
  local_118[0x65] = '\0';
  local_118[0x66] = '\0';
  local_118[0x67] = '\0';
  local_118[0x68] = '\0';
  local_118[0x69] = '\0';
  local_118[0x6a] = '\0';
  local_118[0x6b] = '\0';
  local_118[0x6c] = '\0';
  local_118[0x6d] = '\0';
  local_118[0x6e] = '\0';
  local_118[0x6f] = '\0';
  local_118[0x70] = '\0';
  local_118[0x71] = '\0';
  local_118[0x72] = '\0';
  local_118[0x73] = '\0';
  local_118[0x74] = '\0';
  local_118[0x75] = '\0';
  local_118[0x76] = '\0';
  local_118[0x77] = '\0';
  local_118[0x78] = '\0';
  local_118[0x79] = '\0';
  local_118[0x7a] = '\0';
  local_118[0x7b] = '\0';
  local_118[0x7c] = '\0';
  local_118[0x7d] = '\0';
  local_118[0x7e] = '\0';
  local_118[0x7f] = '\0';
  local_118[0x80] = '\0';
  local_118[0x81] = '\0';
  local_118[0x82] = '\0';
  local_118[0x83] = '\0';
  local_118[0x84] = '\0';
  local_118[0x85] = '\0';
  local_118[0x86] = '\0';
  local_118[0x87] = '\0';
  local_118[0x88] = '\0';
  local_118[0x89] = '\0';
  local_118[0x8a] = '\0';
  local_118[0x8b] = '\0';
  local_118[0x8c] = '\0';
  local_118[0x8d] = '\0';
  local_118[0x8e] = '\0';
  local_118[0x8f] = '\0';
  local_118[0x90] = '\0';
  local_118[0x91] = '\0';
  local_118[0x92] = '\0';
  local_118[0x93] = '\0';
  local_118[0x94] = '\0';
  local_118[0x95] = '\0';
  local_118[0x96] = '\0';
  local_118[0x97] = '\0';
  local_118[0x98] = '\0';
  local_118[0x99] = '\0';
  local_118[0x9a] = '\0';
  local_118[0x9b] = '\0';
  local_118[0x9c] = '\0';
  local_118[0x9d] = '\0';
  local_118[0x9e] = '\0';
  local_118[0x9f] = '\0';
  local_118[0xa0] = '\0';
  local_118[0xa1] = '\0';
  local_118[0xa2] = '\0';
  local_118[0xa3] = '\0';
  local_118[0xa4] = '\0';
  local_118[0xa5] = '\0';
  local_118[0xa6] = '\0';
  local_118[0xa7] = '\0';
  local_118[0xa8] = '\0';
  local_118[0xa9] = '\0';
  local_118[0xaa] = '\0';
  local_118[0xab] = '\0';
  local_118[0xac] = '\0';
  local_118[0xad] = '\0';
  local_118[0xae] = '\0';
  local_118[0xaf] = '\0';
  local_118[0xb0] = '\0';
  local_118[0xb1] = '\0';
  local_118[0xb2] = '\0';
  local_118[0xb3] = '\0';
  local_118[0xb4] = '\0';
  local_118[0xb5] = '\0';
  local_118[0xb6] = '\0';
  local_118[0xb7] = '\0';
  local_118[0xb8] = '\0';
  local_118[0xb9] = '\0';
  local_118[0xba] = '\0';
  local_118[0xbb] = '\0';
  local_118[0xbc] = '\0';
  local_118[0xbd] = '\0';
  local_118[0xbe] = '\0';
  local_118[0xbf] = '\0';
  local_118[0xc0] = '\0';
  local_118[0xc1] = '\0';
  local_118[0xc2] = '\0';
  local_118[0xc3] = '\0';
  local_118[0xc4] = '\0';
  local_118[0xc5] = '\0';
  local_118[0xc6] = '\0';
  local_118[199] = '\0';
  local_118[200] = '\0';
  local_118[0xc9] = '\0';
  local_118[0xca] = '\0';
  local_118[0xcb] = '\0';
  local_118[0xcc] = '\0';
  local_118[0xcd] = '\0';
  local_118[0xce] = '\0';
  local_118[0xcf] = '\0';
  local_118[0xd0] = '\0';
  local_118[0xd1] = '\0';
  local_118[0xd2] = '\0';
  local_118[0xd3] = '\0';
  local_118[0xd4] = '\0';
  local_118[0xd5] = '\0';
  local_118[0xd6] = '\0';
  local_118[0xd7] = '\0';
  local_118[0xd8] = '\0';
  local_118[0xd9] = '\0';
  local_118[0xda] = '\0';
  local_118[0xdb] = '\0';
  local_118[0xdc] = '\0';
  local_118[0xdd] = '\0';
  local_118[0xde] = '\0';
  local_118[0xdf] = '\0';
  local_118[0xe0] = '\0';
  local_118[0xe1] = '\0';
  local_118[0xe2] = '\0';
  local_118[0xe3] = '\0';
  local_118[0xe4] = '\0';
  local_118[0xe5] = '\0';
  local_118[0xe6] = '\0';
  local_118[0xe7] = '\0';
  local_118[0xe8] = '\0';
  local_118[0xe9] = '\0';
  local_118[0xea] = '\0';
  local_118[0xeb] = '\0';
  local_118[0xec] = '\0';
  local_118[0xed] = '\0';
  local_118[0xee] = '\0';
  local_118[0xef] = '\0';
  local_118[0xf0] = '\0';
  local_118[0xf1] = '\0';
  local_118[0xf2] = '\0';
  local_118[0xf3] = '\0';
  local_118[0xf4] = '\0';
  local_118[0xf5] = '\0';
  local_118[0xf6] = '\0';
  local_118[0xf7] = '\0';
  local_118[0xf8] = '\0';
  local_118[0xf9] = '\0';
  local_118[0xfa] = '\0';
  local_118[0xfb] = '\0';
  local_118[0xfc] = '\0';
  local_118[0xfd] = '\0';
  local_118[0xfe] = '\0';
  local_118[0xff] = '\0';
  printf("please input the correct password: ");
  FUN_004010e0("%255s",local_118);
  sVar2 = strcspn(local_118,"\n");
  local_118[sVar2] = '\0';
  iVar1 = a(local_118);
  if (iVar1 == 0xf) {
    b();
    c(local_118,(void *)0xf);
    iVar1 = memcmp(local_118,enc,0xf);
    if (iVar1 == 0) {
      puts("correct password! answer the quiz to get the flag.");
      goto LAB_00402fde;
    }
  }
  puts("incorrect password. try again.");
LAB_00402fde:
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

as we can see,
```C
  printf("please input the correct password: ");
  FUN_004010e0("%255s",local_118);
  sVar2 = strcspn(local_118,"\n");
  local_118[sVar2] = '\0';
  iVar1 = a(local_118);
  if (iVar1 == 0xf) {
    b();
    c(local_118,(void *)0xf);
    iVar1 = memcmp(local_118,enc,0xf);
    if (iVar1 == 0) {
      puts("correct password! answer the quiz to get the flag.");
      goto LAB_00402fde;
    }
  }
```
the input limit is 255 chars, but validated length for correctness is 15 chars, so the answer is `15`

![](question4.png)

to solve this, we can do dynamic analysis with gdb (or other tools)\
breakpoint at `main` and dissas `main`, revealed that function `b` is called only if a proceding length check passes, 

![](disassmain.png)

to ensure function `b` gets called regardless of the actual input length, we set a breakpoint just after call to function `a` (at `0x402f6c`, which is the `cmp $0xf,%eax`)

![](question42.png)

When this breakpoint was hit (after providing "a" as input, making eax=1), we manually changed the value of `eax` to `0xf` using the GDB command: `set $eax = 0xf`. This tricks the program into thinking the input length was `15`

![](question43.png)

`0xc1de1494171d9e2f` convert it to decimal = `13969625720425389615`

![](question5.png)

to answer the question, we need to decompile the `c` function
```c
int c(void *param_1,void *param_2)

{
  byte bVar1;
  undefined8 in_RDX;
  long in_FS_OFFSET;
  int local_130;
  int local_12c;
  void *local_128;
  byte local_120 [4];
  undefined1 local_11c;
  undefined1 local_11b;
  undefined1 local_11a;
  undefined1 local_119;
  byte abStack_118 [264];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_12c = 0;
  local_120[0] = (byte)in_RDX;
  local_120[1] = (char)((ulong)in_RDX >> 8);
  local_120[2] = (char)((ulong)in_RDX >> 0x10);
  local_120[3] = (char)((ulong)in_RDX >> 0x18);
  local_11c = (char)((ulong)in_RDX >> 0x20);
  local_11b = (char)((ulong)in_RDX >> 0x28);
  local_11a = (char)((ulong)in_RDX >> 0x30);
  local_119 = (char)((ulong)in_RDX >> 0x38);
  for (local_130 = 0; local_130 < 0x100; local_130 = local_130 + 1) {
    abStack_118[local_130] = (byte)local_130;
  }
  for (local_130 = 0; local_130 < 0x100; local_130 = local_130 + 1) {
    local_12c = (int)((uint)local_120[local_130 % 8] + (uint)abStack_118[local_130] + local_12c)  %
                0x100;
    bVar1 = abStack_118[local_130];
    abStack_118[local_130] = abStack_118[local_12c];
    abStack_118[local_12c] = bVar1;
  }
  local_130 = 0;
  local_12c = 0;
  for (local_128 = (void *)0x0; local_128 < param_2; local_128 = (void *)((long)local_128 + 1)) {
    local_130 = (local_130 + 1) % 0x100;
    local_12c = (int)(local_12c + (uint)abStack_118[local_130]) % 0x100;
    bVar1 = abStack_118[local_130];
    abStack_118[local_130] = abStack_118[local_12c];
    abStack_118[local_12c] = bVar1;
    *(byte *)((long)local_128 + (long)param_1) =
         *(byte *)((long)local_128 + (long)param_1) ^
         abStack_118[(int)(uint)(byte)(abStack_118[local_12c] + abStack_118[local_130])];
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```
as the hints says, so we just gonna ask AI tho

![](answer5.png)

so the answer is `RC4`

![](question6.png)

this is kinda easy, cus we alr get the key by doin this

![](question43.png)

and we know the encryption algorithm, so all we need it now is just dump the `enc`,

![](enc.png)

and this is the solver:
```py
def rc4(key: bytes, data: bytes) -> bytes:
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]

    out = bytearray(len(data))
    i = 0
    j = 0
    for idx in range(len(data)):
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) & 0xFF]
        out[idx] = data[idx] ^ K
    return bytes(out)


if __name__ == "__main__":
    key_from_b_return_value = 0xc1de1494171d9e2f 
    key = key_from_b_return_value.to_bytes(8, byteorder='little') 
    enc_bytes = bytes([
        0xD1, 0x58, 0x15, 0x8A, 0xEE,
        0xB5, 0xBB, 0x52, 0x0C, 0x6B,
        0xA4, 0xAB, 0x6D, 0x7D, 0xB7
    ])

    password = rc4(key, enc_bytes)
    print(password)
```
output:
`b'honk-mimimimimi'`

![](revflag.png)

Flag: `grey{solv3d_m1_f1r5t_r3v_ch4lleng3_heh3}`