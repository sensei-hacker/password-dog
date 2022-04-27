#!/usr/bin/env python3

# Tests a given password to see if it would be cracked by a given set of rules and dictionary.

import sys
from optparse import OptionParser, OptionGroup
import multiprocessing
from rulegen import RuleGen
import re
import math
import cProfile
import pprint
import string
import os
from bloom_filter2 import BloomFilter

class rulechecker:
    def __init__(self, rulelist, dictfile):
        self.rules = set( line.strip() for line in open(rulelist) )
        self.rulegen = RuleGen(language="en")
        self.dictfile = dictfile
        self.dictsize = 0
        self.rulegen.load_custom_wordlist(dictfile)
        # self.dict = set()

# [   {   'best_rule_length': 9999,
#        'distance': 4,
#        'hashcat_rules': [['$2', '$0', '$0', '$0']],
#        'password': 'christy2000',
#        'pre_rule': [],
#        'suggestion': 'christy'}]

    def findrule(self, words):
        rules = set()
        for word in words:
            if (options.verbose or options.debug):
                print("suggestion: {}".format(word["suggestion"]))
            pre = ''.join(word["pre_rule"])
            for rule in word["hashcat_rules"]:
                if len(rule) > 0:
                    rules.add(pre + ''.join(rule))
        for rule in rules:
            # print(rule)
            if rule in self.rules:
                if (options.debug or options.verbose):
                    print( "found with rule {}".format(rule) )
                return(rule)
            else:
                if (options.debug):
                    print( "rule not in list: {}".format(rule) )
        return None

    def getdictsize(self):
        return( round(os.path.getsize(self.dictfile) / 9) )

    def checkdict(self, password):
        if ( self.rulegen.enchant.check(password) ):
            return( round(math.log10( self.getdictsize() ) ) )
        else:
            return(100)

    def checkrules(self, password):
        # print( "checking rules for {}".format(password) )
        # self.rulegen.analyze_password(password, rules_queue, words_queue)
        words = self.analyze_password(password)
        if (not words):
            return 100
        rule_found = self.findrule(words)
        if rule_found == None:
            return 100
        else:
            # 102401 is approximately the size of /usr/share/dict/words, which is also used
            keyspace = len(self.rules) * (102401 + self.getdictsize() )
            # print(  "rulescore: {}".format( round(math.log10(keyspace)) )  )
            return( round(math.log10(keyspace)) ) 

    def analyze_password(self, password):
        """ Analyze a single password. """

        words = []

        # Short-cut words in the dictionary
        if self.checkdict(password) < 100:
            word = dict()
            word["password"] = password
            word["suggestion"] = password
            word["hashcat_rules"] = [[], ]
            word["pre_rule"] = []
            word["best_rule_length"] = 1
            words.append(word)

        # Generate rules for words not in the dictionary
        else:

            # Generate source words list
            words = self.rulegen.generate_words(password)

            # Generate levenshtein reverse paths for each suggestion
            for word in words:
                # Generate a collection of hashcat_rules lists
                word["hashcat_rules"] = self.rulegen.generate_hashcat_rules(word["suggestion"], word["password"])
        return(words)
        # pp = pprint.PrettyPrinter(indent=4)
        # pp.pprint(words)



def mask2score(masknum):
    # score = 0 - (0.000000011 * math.pow(masknum, 2) ) + (0.000449824 * masknum) + 11.148066427
    # This math determined via quadratic regression of the actual number of candidates generated
    score = (0.00067481 * masknum) + 38.69001341 - ( 0.0000000035 * math.pow(masknum, 2))
    score = score * math.log( 2, 10)
    if ( options.debug ) :
            print( "in mask2score, masknum {}, score {}".format(masknum, score) )
    return round(score)


def checkmask_known(password):
    score = 0.0
    lower = digit = upper = special = 0
    advancedmask_string = ''
    for char in password:
        if char in string.digits:
            digit += 1
            advancedmask_string += "?d"
            score += 1.0

        elif char in string.ascii_lowercase:
            lower += 1
            advancedmask_string += "?l"
            score +- 1.4

        elif char in string.ascii_uppercase:
            upper += 1.4
            advancedmask_string += "?u"

        else:
            special += 1
            advancedmask_string += "?s"
            score += 1.5
    return advancedmask_string
        
def checkmask(password, masklist):
    mask = checkmask_known(password)
    i=0
    list = open(masklist, 'r')
    for line in list:
        # print(line)
        if(line.rstrip("\n") == mask):
            if (options.debug):
                print("line {} == mask {}".format(line.rstrip("\n"), mask))
            list.close()
            score = mask2score(i)
            if score == -1:
                score = 100
            return(score)
        i += 1
    list.close()
    return 100


def checkbrute(password):
    # logb ( m^k) = k * logb(M)
    # log10 ( 95^len(password)) = len(password) * log10(95)
    return( round(len(password) * math.log10(95)) )


def trimpunc(password):
    # TODO - trim punctuation, mixed with numbers? for hybrid attack
    leading = re.compile("^(" + re.escape(string.punctuation) + ")(.*)")
    trailing = re.compile("(.*?)(" + re.escape(string.punctuation + ")$"))


def checkdigits(password):
    if not password.isdigit():
        return(100)

    if str(password) in '01234567890' or str(password) in '09876543210':
        return 2
    years = set()
    i = 1940
    while i < 2030:
        years.add(str(i))
        i += 1
    if str(password) in years:
      return 2

    return(len(password))


def checkhybrid(password, rules):
    score = 0
    base = password

    trailingdigits = re.compile('(.+?)(\d+)$')
    leadingdigits = re.compile('^(\d+)(.+)')
    
    leading = leadingdigits.search(password)
    if (leading):
        base = leading.group(2)
        score = checkdigits( leading.group(1) )

    trailing = trailingdigits.search(base)
    if (trailing):
        base = trailing.group(1)
        score += checkdigits( trailing.group(2) )
    
# TODO RAY DEBUG
    dictscore = rules.checkdict(base)
    # print("dictscore: {}".format(dictscore))
    # Because both scores are already log10, addition of the logs = multiplication of the raw
    return dictscore + score

    # TODO passwords that are mostly digits, but not all digits, after removing leading and trailing


def checkbloom(password):
    if password in bloom:
        return 9
    else:
        return 100

def allchecks(password, rules):

    digitscore = 100
    if password.isdigit():
        digitscore = checkdigits(password)
        if digitscore < 8:
            return('digits', digitscore)


    brutescore = checkbrute(password)
    if brutescore < 8:
        return('brute', brutescore)


    maskscore = checkmask(password, options.masklist)
    if (maskscore < 8):
        return('mask', maskscore)

    bloomscore = checkbloom(password)
    if (bloomscore < 10):
        return('bloom', bloomscore)

    # print("checking hybrid for {}".format(password))
    hybridscore = checkhybrid(password, rules)
    if (hybridscore < 8):
        return('hybrid', hybridscore)

    rulescore = rules.checkrules(password)

    totalscore = min(hybridscore, rulescore, brutescore, maskscore, digitscore, bloomscore)
    if (totalscore == hybridscore):
        return('hybrid', hybridscore)
    if(totalscore == maskscore):
        return('mask', maskscore)
    if(totalscore == brutescore):
        return('brute', brutescore)
    if(totalscore == digitscore):
        return('digits', digitscore)
    if(totalscore == bloomscore):
        return('bloom', bloomscore)
    else:
        return('rules', rulescore)


def checkpasswords(rules):
    for line in sys.stdin:
        password = line.rstrip("\n")
        (attack, score) = allchecks(password, rules)
        # print( "time: 10^{}\tattack: {}\t password: {}".format(score, attack, password) )
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

    rules = rulechecker(options.rulelist, options.wordlist)
    # bloom = BloomFilter(max_elements=1.5 * (10**8), error_rate=0.0001, filename=('bloom182M.bin', 400000000))
    bloom = BloomFilter( max_elements=(600 * 1000 * 1000), error_rate=0.0001, filename=('bloom554M.bin', (128 * 1024 * 1024) ) )


checkpasswords(rules)
# cProfile.run('checkpasswords(rules)')

# TODO: Handle capitalization, because the spelling engine may hide that for all caps, all lower, or initial caps
# TODO: Trim trailing or leading punctuation before hybrid. Combine this with digits, perhaps, to handle \d\W and \W\d
