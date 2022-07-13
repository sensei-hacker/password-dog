#!/usr/bin/env python3

import sys
from bloom_filter2 import BloomFilter


bloom = BloomFilter( max_elements=(600 * 1000 * 1000), error_rate=0.0001, filename=('bloom554M.bin', (128 * 1024 * 1024) ) )


# for line in sys.stdin:
line =" "
while (line):
    try:
        line = sys.stdin.readline()
        bloom.add(line.rstrip("\n"))
    except EOFError:
        print("EOF")
        break
    except Exception as inst:
        sys.stderr.write("Error after reading line '{}', on {}, {}".format(lastline, line, inst))
        line=lastline
        continue
    lastline = line
bloom.close

