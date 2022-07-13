#!/bin/sh

yum install python3
yum install enchant
pip3 install pyenchant
pip3 install bloom_filter2

mkdir -p  /usr/local/lib/systemd/system
cp -a password-dog.service /usr/local/lib/systemd/system/password-dog.service
systemctl daemon-reload
systemctl enable password-dog
systemctl start password-dog
