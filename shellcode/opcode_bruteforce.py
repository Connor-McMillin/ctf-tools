#!/usr/bin/env python3

import argparse
import binascii
from capstone import *
from pwn import *
from itertools import product # Cartesian Product

parser = argparse.ArgumentParser()

# TODO: Riscv and friends
arch_choices = ["aarch64", "alpha",     "amd64", "arm",   "avr",     "cris",
                "i386",    "ia64",      "m68k",  "mips",  "mips64",  "msp430",
                "powerpc", "powerpc64", "s390",  "sparc", "sparc64", "thumb",
                "vax"]

parser.add_argument("-a", "--arch", required=True, choices=arch_choices,
                    help="Architecture which will be used when assembling opcodes")
parser.add_argument("-o", "--opcodes", help="String of opcodes (hex encoded) with an X placed at every NIBBLE that should be brute forced")
args = parser.parse_args()

context.arch = args.arch
opcodes = args.opcodes.lower().encode("utf-8")

# TODO: Allow for bit level specifications instead of just nibbles
brute_count = opcodes.count("x".encode("utf-8"))
for x in product(range(16), repeat=brute_count):
    temp_opcodes = opcodes
    for y in x:
        temp_opcodes = temp_opcodes.replace("x".encode("utf-8"), hex(y)[2:].encode("utf-8"), 1)

    temp_opcodes = binascii.unhexlify(temp_opcodes)

    print(temp_opcodes)
    result = disasm(temp_opcodes[::-1])
    if "undefined" not in result:
        print(result)
