# MicroPython .mpy Bytecode Reversing — Cinderbound Example

## Challenge Overview

**Scenario:** "Cinderbound" — The Ash-Vault keeps vows pressed into stone (cracked stones can be forged). The priesthood sealed one vow in a "foreign engine" (MicroPython `.mpy` file) instead.

**File:** `cinderbound.mpy` (221 bytes, MPY v6)

## Initial Recon

```
$ xxd cinderbound.mpy
00000000: 4d06 001f 0801 186a 7564 6765 5f73 7263  M......judge_src
00000010: 2e70 7900 0f0a 6a75 6467 6500 7910 7379  .py...judge.y.sy
00000020: 6c6c 6162 6c65 0081 5781 6f81 590a 1007  llable..W.o.Y...
```

- Magic: `4d 06` (MPY v6)
- Flag: `00 1f` (little-endian 0x1f00)
- Strings visible: `judge_src.py`, `judge`, `y`, `syllable`
- Object table: `[(57, 129, 154, 31, 199, 192, 73, 243, 43, 176, 255, 173, 54, 203, 67, 15)]` (16-element tuple — the encrypted target)

## Disassembly Output

```
source_file: judge_src.py
qstr_table[8]:
    judge_src.py, <module>, judge, append, syllable, len, ord, list
obj_table: [(57, 129, 154, 31, 199, 192, 73, 243, 43, 176, 255, 173, 54, 203, 67, 15)]

simple_name: <module>
  MAKE_FUNCTION 0
  STORE_NAME judge
  RETURN_VALUE

simple_name: judge
  args: ['syllable']
  23:00       LOAD_CONST_OBJ (target tuple)
  c1          STORE_FAST 1          # v1 = target_tuple
  22:80:5a    LOAD_CONST_SMALL_INT 90
  c2          STORE_FAST 2          # v2 = 90 (seed)
  2b:00       BUILD_LIST 0
  c3          STORE_FAST 3          # v3 = [] (output list)
  12:05       LOAD_GLOBAL len
  b0          LOAD_FAST 0           # syllable
  34:01       CALL_FUNCTION 1       # len(syllable)
  80          LOAD_CONST_SMALL_INT 0
  42:6b       JUMP 43               # jump to loop test

  # Loop body:
  57          DUP_TOP
  c4          STORE_FAST 4          # i = counter
  12:06       LOAD_GLOBAL ord
  b0          LOAD_FAST 0           # syllable
  b4          LOAD_FAST 4           # i
  55          LOAD_SUBSCR
  34:01       CALL_FUNCTION 1       # ord(syllable[i])
  b2          LOAD_FAST 2           # seed
  ee          BINARY_OP 23 __xor__  # ord(c) ^ seed
  b4          LOAD_FAST 4           # i
  8d          LOAD_CONST_SMALL_INT 13
  f4          BINARY_OP 29 __mul__  # i * 13
  22:81:7f    LOAD_CONST_SMALL_INT 255
  ef          BINARY_OP 24 __and__  # (i*13) & 255
  ee          BINARY_OP 23 __xor__  # (ord(c)^seed) ^ ((i*13)&255)
  c5          STORE_FAST 5          # v5 = encrypted char
  b2          LOAD_FAST 2           # seed
  12:06       LOAD_GLOBAL ord
  ...same subscript pattern...
  34:01       CALL_FUNCTION 1       # ord(syllable[i])
  f2          BINARY_OP 27 __add__  # seed + ord(c)
  22:81:7f    LOAD_CONST_SMALL_INT 255
  ef          BINARY_OP 24 __and__  # (seed+ord(c)) & 255
  c2          STORE_FAST 2          # seed = (seed + ord(c)) & 255

  b3          LOAD_FAST 3           # output list
  14:03       LOAD_METHOD append
  b5          LOAD_FAST 5           # encrypted char
  36:01       CALL_METHOD 1         # output.append(v5)
  59          POP_TOP
  81          LOAD_CONST_SMALL_INT 1
  e5          BINARY_OP 14 __iadd__ # i += 1
  58          DUP_TOP_TWO
  5a          ROT_TWO
  d7          BINARY_OP 0 __lt__    # i < len(syllable)?
  43:10       POP_JUMP_IF_TRUE -48 # loop back
  59          POP_TOP
  59          POP_TOP

  b3          LOAD_FAST 3           # output
  12:07       LOAD_GLOBAL list
  b1          LOAD_FAST 1           # target tuple
  34:01       CALL_FUNCTION 1       # list(target)
  d9          BINARY_OP 2 __eq__    # output == list(target)?
  63          RETURN_VALUE
```

## Reconstructed Algorithm

```python
def judge(syllable):
    target = (57, 129, 154, 31, 199, 192, 73, 243, 43, 176, 255, 173, 54, 203, 67, 15)
    seed = 90
    output = []
    for i in range(len(syllable)):
        encrypted = (ord(syllable[i]) ^ seed) ^ ((i * 13) & 255)
        seed = (seed + ord(syllable[i])) & 255
        output.append(encrypted)
    return output == list(target)
```

## Reverse (Get Flag)

```python
target = [57, 129, 154, 31, 199, 192, 73, 243, 43, 176, 255, 173, 54, 203, 67, 15]
seed = 90
flag = []
for i, t in enumerate(target):
    c_val = t ^ seed ^ ((i * 13) & 255)
    flag.append(chr(c_val))
    seed = (seed + c_val) & 255
print(''.join(flag))  # c1nd3rbound_v0w5
```

## Key Bytecode Mnemonics Reference

| Bytecode | Python | Encoding |
|----------|--------|----------|
| `80` | `0` (small int) | LOAD_CONST_SMALL_INT |
| `81` | `1` | +1 from 80 |
| `22:81:7f` | `255` | Extended small int (2's complement: 0xff - 256 = -1, but positive) |
| `b0` | `v0` | LOAD_FAST 0 |
| `b4` | `v4` | LOAD_FAST 4 |
| `c1` | `v1 = ...` | STORE_FAST 1 |
| `55` | `a[b]` | LOAD_SUBSCR |
| `34:01` | `fn(1 arg)` | CALL_FUNCTION 1 |
| `36:01` | `.method(1 arg)` | CALL_METHOD 1 |
| `14:03` | `.append` | LOAD_METHOD (qstr index 3) |
| `12:05` | `len` | LOAD_GLOBAL (qstr index 5) |
| `12:06` | `ord` | LOAD_GLOBAL (qstr index 6) |
| `12:07` | `list` | LOAD_GLOBAL (qstr index 7) |
| `2b:00` | `[]` | BUILD_LIST 0 |
| `42:6b` | `JUMP 43` | Forward jump, offset 43 |
| `43:10` | `POP_JUMP_IF_TRUE -48` | Backward jump (-48 = 0xffd0 signed) |
| `63` | `return` | RETURN_VALUE |
| `59` | (pop) | POP_TOP |
| `58` | (dup first two) | DUP_TOP_TWO |
| `5a` | (swap top two) | ROT_TWO |
