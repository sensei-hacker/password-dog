#/bin/bash
# #!/usr/bin/env -S bash -euET -o pipefail -O inherit_errexit

die ()
{
    echo "Assertion failed:  \"$1\"" >2
    echo "File \"$0\", line $2" >2
    exit 99
} 

./checkpw_http.py --rulelist rules.txt --wordlist ignis-1M.txt --masklist rockyou_masks_10tothe20.masks 




