#!/usr/bin/env python3

# Tests a given password to see if it would be cracked by a given set of rules and dictionary.

import sys
from optparse import OptionParser, OptionGroup
import cProfile
import string
from pwchecker import pwchecker


def checkpasswords(options):
    checker = pwchecker(options.rulelist, options.wordlist, options.masklist, options.debug)
    for line in sys.stdin:
        password = line.rstrip("\n")
        (attack, score) = checker.allchecks(password)
        print( "{}\t{}\t{}".format(score, attack, password) )


if __name__ == "__main__":


    parser = OptionParser("%prog [options] passwords.txt")
    parser.add_option("-w", "--wordlist", help="Use a custom wordlist for rule analysis.", metavar="wiki.dict")
    parser.add_option("-s", "--simplewords", help="Do not tweak input to better match words", action="store_true", default=False)
    debug = OptionGroup(parser, "Debugging options:")
    debug.add_option("-v", "--verbose", help="Show verbose information.", action="store_true", default=False)
    debug.add_option("-d", "--debug", help="Debug rules.", action="store_true", default=False)
    debug.add_option("--password", help="Process the last argument as a password not a file.", action="store_true",
                     default=False)
    parser.add_option_group(debug)

    checkpw = OptionGroup(parser, "Options specific to checkpw")
    checkpw.add_option("--rulelist", help="List of rules to check against", metavar="rules.txt")
    checkpw.add_option("-m", "--masklist", help="mask list", metavar="rockyou.masks")
    parser.add_option_group(checkpw)
    
    (options, args) = parser.parse_args()
    if not options.rulelist:
        parser.error('--rulelist required')
    if not options.wordlist:
        parser.error('--wordlist required')
    if not options.masklist:
        parser.error('--masklist required')

checkpasswords(options)
# cProfile.run('checkpasswords(rules)')

# TODO: Handle capitalization, because the spelling engine may hide that for all caps, all lower, or initial caps
# TODO: Trim trailing or leading punctuation before hybrid. Combine this with digits, perhaps, to handle \d\W and \W\d

