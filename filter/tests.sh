#/bin/bash
# #!/usr/bin/env -S bash -euET -o pipefail -O inherit_errexit

die ()
{
    echo "Assertion failed:  \"$1\"" >2
    echo "File \"$0\", line $2" >2
    exit 99
} 

./checkpw_cli.py --rulelist rules.txt --wordlist ignis-1M.txt --masklist rockyou_masks_10tothe20.masks << EOF
kd0
123
123456789
947302829
0382902137138510883541490834469292392423908231
Portable744
123Portable
Portable123
Portable!
portABLE!
ab8350
EOF



wget -q -O - 'http://localhost:8080/?newpassword=kd0'
wget -q -O - 'http://localhost:8080/?newpassword=123'
wget -q -O - 'http://localhost:8080/?newpassword=123'
wget -q -O - 'http://localhost:8080/?newpassword=123456789'
wget -q -O - 'http://localhost:8080/?newpassword=Portable744'
wget -q -O - 'http://localhost:8080/?newpassword=Portable744'
wget -q -O - 'http://localhost:8080/?newpassword=123Portable'
wget -q -O - 'http://localhost:8080/?newpassword=Portable123'
wget -q -O - 'http://localhost:8080/?newpassword=Portable!'
wget -q -O - 'http://localhost:8080/?newpassword=portABLE!'
wget -q -O - 'http://localhost:8080/?newpassword=ab8350'
