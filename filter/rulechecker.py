from rulegen import RuleGen
import os
import math

class rulechecker:
    def __init__(sellf):
        return self

    def __init__(self, rulelist, dictfile, debug):
        self.rules = set( line.strip() for line in open(rulelist) )
        self.rulegen = RuleGen(language="en")
        self.dictfile = dictfile
        self.dictsize = 0
        self.rulegen.load_custom_wordlist(dictfile)
        self.debug = debug

    def findrule(self, words):
        rules = set()
        for word in words:
            if (self.debug):
                print("suggestion: {}".format(word["suggestion"]))
            pre = ''.join(word["pre_rule"])
            for rule in word["hashcat_rules"]:
                if len(rule) > 0:
                    rules.add(pre + ''.join(rule))
        for rule in rules:
            # print(rule)
            if rule in self.rules:
                if (self.debug):
                    print( "found with rule {}".format(rule) )
                return(rule)
            else:
                if (self.debug):
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


