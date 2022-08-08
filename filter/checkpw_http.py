#!/usr/bin/env python3

# Tests a given password to see if it would be cracked by a given set of rules and dictionary.

import sys
from optparse import OptionParser, OptionGroup
import multiprocessing
import re
import math
import cProfile
import pprint
import string
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
import pprint
import json
from datetime import datetime
from pwchecker import pwchecker


class PwServer(HTTPServer):
    def __init__(self, server_address, handler, local_data):
        HTTPServer.__init__(self, server_address, handler)
        self.local_data = local_data


class PwHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        checker = self.server.local_data
        args = parse_qs( urlparse(self.path).query )
        if (options.debug):
            pprint.pprint(args)
            date_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            with open("/tmp/pd.log", 'a') as out:
                out.write(date_time + ' ' + args['newpassword'][0] + '\n')


        password = args['newpassword'][0]
        (attack, score) = checker.allchecks(password)

        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.send_header("Access-Control-Allow-Origin", "*")
        res = json.dumps( { 'score': score, 'attack': attack} ) + "\n\n";

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

    checker = pwchecker(options.rulelist, options.wordlist, options.masklist, options.debug)
    webserver = PwServer(("localhost", 8080), PwHandler, checker)

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
