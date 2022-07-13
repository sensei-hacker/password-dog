
echo 'let wordlist = new Array (' > clean_30k.js
sed "s@\(.*\)@'\1',@" <clean_30k.txt | tr -d "\n" >>clean_30k.js
echo ');' >> clean_30k.js



