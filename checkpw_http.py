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
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
import pprint
import json

class rulechecker:
    def __init__(self, rulelist, dictfile):
        self.rules = set( line.strip() for line in open(rulelist) )
        self.rulegen = RuleGen(language="en")
        self.dictfile = dictfile
        self.dictsize = 0
        self.rulegen.load_custom_wordlist(dictfile)

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

            words = self.rulegen.generate_words(password)
            for word in words:
                word["hashcat_rules"] = self.rulegen.generate_hashcat_rules(word["suggestion"], word["password"])
        return(words)


def mask2score(masknum):
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


masks = {}
def read_mask_file(masklist):
    i = 0
    list = open(masklist, 'r')
    for line in list:
        masks[line.rstrip("\n")] = i
        i += 1
    list.close()
    return masks


def checkmask(password):
    mask = checkmask_known(password)
    if mask in masks:
        score = mask2score(masks[mask])
        if score == -1:
            score = 100
        return(score)
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
        return 8
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
        print( "{}\t{}\t{}".format(score, attack, password) )

class PwServer(BaseHTTPRequestHandler):
    def do_GET(self):
        # TODO: send headers
        args = parse_qs( urlparse(self.path).query )
        # pprint.pprint(args)
        # pprint.pprint(args['newpassword'][0])

        password = args['newpassword'][0]
        (attack, score) = allchecks(password, rules)

        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.send_header("Access-Control-Allow-Origin", "*")
        res = json.dumps( { 'score': score, 'attack': attack} )
        # self.send_header( "Content-Length", len(res.encode('utf-8')) )

        self.end_headers()

        self.wfile.write( bytes(res, "utf-8") )

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
    bloom = BloomFilter(max_elements=1.5 * (10**8), error_rate=0.0001, filename=('bloom182M.bin', 400000000))

    # checkpasswords(rules)
    webserver = HTTPServer(("localhost", 8080), PwServer)

    print("server started")
    try:
        webserver.serve_forever()
    except KeyboardInterrupt:
        pass
    webserver.server_close()
    print("server stopped")

# cProfile.run('checkpasswords(rules)')

# TODO: Handle capitalization, because the spelling engine may hide that for all caps, all lower, or initial caps
# TODO: Trim trailing or leading punctuation before hybrid. Combine this with digits, perhaps, to handle \d\W and \W\d
