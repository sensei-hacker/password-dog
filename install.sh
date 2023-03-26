#!/bin/sh


BINDIR=/opt/password-dog
DOCROOT=/var/www/html/password-dog
CGIBIN=/usr/lib/cgi-bin/password-dog

cp -a cgi-bin $CGIBIN
chmod 755 cgi-bin/*.cgi
cp -a html $DOCROOT
if [ -e /usr/lib/cgi-bin ]
then
    ln -s $CGIBIN /usr/lib/cgi-bin/password-dog
fi



cpan LWP::UserAgent

( yum install python3 || apt install python3 )
( yum install enchant || apt install enchant-2 )
( apt install python3-enchant )
apt install python3-pip

thisdir=`pwd`
mkdir -p $BINDIR
cp -a filter $BINDIR
wget -O $BINDIR/filter/bloom554M.bin https://passworddog.s3.amazonaws.com/bloom554M.bin
cd $BINDIR

python3 -m venv pd_python
source ./pd_python/bin/activate

pip3 install bloom_filter2


mkdir -p  /usr/local/lib/systemd/system
sed "s@BINDIR@$BINDIR@g" $BINDIR/filter/password-dog.service > /usr/local/lib/systemd/system/password-dog.service
systemctl daemon-reload
systemctl enable password-dog
systemctl start password-dog

cd $thisdir



