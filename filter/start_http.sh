#/bin/bash
# #!/usr/bin/env -S bash -euET -o pipefail -O inherit_errexit

die ()
{
    echo "Assertion failed:  \"$1\"" >2
    echo "File \"$0\", line $2" >2
    exit 99
} 

DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
$DIR/checkpw_http.py --rulelist $DIR/rules.txt --wordlist $DIR/ignis-1M.txt --masklist $DIR/rockyou_masks_10tothe20.masks # --debug

