
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
from datetime import datetime
from rulechecker import rulechecker

class pwchecker:
    def __init__(self, rulelist, wordlist, masklist, debug):
        self.rules = rulechecker(rulelist, wordlist, debug)
        # self.bloom = BloomFilter(max_elements=1.5 * (10**8), error_rate=0.0001, filename=('bloom182M.bin', 400000000))
        # TODO: Make max_elements a function of filesize mod 10 million
        self.bloom = BloomFilter( max_elements=(600 * 1000 * 1000),
            error_rate=0.0001,
            filename=('bloom554M.bin', (128 * 1024 * 1024) )
            )
        self.masks = self.read_mask_file(masklist)
        self.debug = debug

    def mask2score(self, masknum):
        # This math determined via quadratic regression of the actual number of candidates generated
        score = (0.00067481 * masknum) + 38.69001341 - ( 0.0000000035 * math.pow(masknum, 2))
        score = score * math.log( 2, 10)
        if (self.debug):
            print( "in mask2score, masknum {}, score {}".format(masknum, score) )
        return round(score)
    
    @staticmethod
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
                score += 1.4
    
            elif char in string.ascii_uppercase:
                upper += 1.4
                advancedmask_string += "?u"
    
            else:
                special += 1
                advancedmask_string += "?s"
                score += 1.5
        return advancedmask_string
    
    
    @staticmethod
    def read_mask_file(masklist):
        masks = {}
        i = 0
        listfile = open(masklist, 'r')
        for line in listfile:
            masks[line.rstrip("\n")] = i
            i += 1
        listfile.close()
        return masks
    
    
    def checkmask(self, password):
        mask = self.checkmask_known(password)
        if mask in self.masks:
            score = self.mask2score(self.masks[mask])
            if score == -1:
                score = 100
            return(score)
        return 100
    
    
    
    @staticmethod
    def checkbrute(password):
        # logb ( m^k) = k * logb(M)
        # log10 ( 95^len(password)) = len(password) * log10(95)
        return( round(len(password) * math.log10(95)) )
    
    @staticmethod
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
    
    
    def checkhybrid(self, password):
        score = 0
        base = password
    
        trailingdigits = re.compile('(.+?)(\d+)$')
        leadingdigits = re.compile('^(\d+)(.+)')

        # anypunc =  '|'.join(  map( lambda x: '\\' + x, list(string.punctuation) )  )
        # trailingpunc = re.compile( "(.*?)(" + anypunc  + ")$" )
        # Ending password with !, ., or ? is worth only 1 point (x10)
        trailingpunc = re.compile( "(.*?)([!\?\.]*)$" )
        trailing = trailingpunc.search(base)
        if (trailing):
            base = trailing.group(1)
            score = len( trailing.group(2) )

        leading = leadingdigits.search(base)
        if (leading):
            base = leading.group(2)
            score = self.checkdigits( leading.group(1) )
    
        trailing = trailingdigits.search(base)
        if (trailing):
            base = trailing.group(1)
            score += self.checkdigits( trailing.group(2) )
        
    # TODO RAY DEBUG
        dictscore = self.rules.checkdict(base)
        # print("dictscore: {}".format(dictscore))
        # Because both scores are already log10, addition of the logs = multiplication of the raw
        return dictscore + score
    
        # TODO passwords that are mostly digits, but not all digits, after removing leading and trailing
    
    
    def checkbloom(self, password):
        if password in self.bloom:
            return 8
        else:
            return 100
    
    def allchecks(self,password):
    
        digitscore = 100
        if password.isdigit():
            digitscore = self.checkdigits(password)
            if digitscore < 8:
                return('digits', digitscore)
    
    
        brutescore = self.checkbrute(password)
        if brutescore < 8:
            return('brute', brutescore)
    
    
        maskscore = self.checkmask(password)
        if (maskscore < 8):
            return('mask', maskscore)
    
        bloomscore = self.checkbloom(password)
        if (bloomscore < 10):
            return('bloom', bloomscore)
    
        hybridscore = self.checkhybrid(password)
        if (hybridscore < 8):
            return('hybrid', hybridscore)
    
        rulescore = self.rules.checkrules(password)
    
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
    
    
