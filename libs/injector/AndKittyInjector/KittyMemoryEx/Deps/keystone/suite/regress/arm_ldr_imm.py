#!/usr/bin/python
# Ingmar Steen, 2016

# This tests the LDR Rd, =imm pseudo-instruction on ARM.

# Github issue: #28
# Author: Ingmar Steen

from keystone import *

import regress

class TestARM(regress.RegressTest):
    def runTest(self):
        # Initialize Keystone engine
        ks = Ks(KS_ARCH_ARM, KS_MODE_ARM)
        # Assemble to get back insn encoding & statement count
        encoding, count = ks.asm(b"ldr r0, =0x11223344")
        # Assert the result
        self.assertEqual(encoding, [ 0x04, 0x00, 0x1f, 0xe5, 0x44, 0x33, 0x22, 0x11 ])

if __name__ == '__main__':
    regress.main()
