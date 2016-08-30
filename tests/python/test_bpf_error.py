#!/usr/bin/env python
# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

from bcc import BPF
from builtins import input
from simulation import Simulation
import sys
import os
from unittest import main, TestCase


arg1 = sys.argv.pop(1)
output = os.path.join(os.getcwd(), 'output.txt')
sys.stderr = open(output, 'wb')
error_msg = "R7 invalid mem access 'map_value_or_null'\n"

class TestBPFProgLoad(TestCase):
    def test_jumps(self):
        b = BPF(src_file=arg1, debug=2)
        try:
            ingress = b.load_func("bridge_port",BPF.SCHED_CLS)
        except Exception:
            sys.stderr.flush()
            with open(output, 'rb') as f:
                lines = f.readlines()
                os.remove(output)
                self.assertEqual(error_msg in lines, True)

if __name__ == "__main__":
    main()


