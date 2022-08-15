# Password Dog, an advanced password meter and filter


## What is Password Dog?

Password Dog is an advanced password meter / filter 
that will more *accurately* determine whether a candidate 
password is likely to be cracked by attackers.
Password Dog is based on simulating the actual attacks
that real password crackers use, and seeing how long
it would take a real attacker to crack a candidate
password, and which type of attack they would actually use.
THis gives much more accurate results.

## Why is another filter needed?

Other meters and filters look at things like whether
the password has a capital letter. Unfortunately, 
capitalizing your password does NOT stop attackers.
Adding an exclamation point at the end also does 
not make it strong - password crackers are smart
enough to try those things.

For this reason, other password meters don't work
much better than just random chance, just flipping 
a coin and calling a password "strong" if the coin
happens to come up heads.

![graph of password meter effectivness](/docs/total_accuracy.png)

While other meters are only about as good as flipping
a coin, Password Dog is over 90% accurate at distinguishing
passwords that will be cracked from those that won't.

More information about this, including testing methodology,
can be found int he docs/ folder.

## Installation

Password Dog is developed on Linux, on Ubuntu and CentOS.
It is Python, so it may also run on Windows, but the 
installation script is written for Linux. Also included
is a script for updating passwords on a Windows domain
controller (Active Directory), so it can be used successfully
in a Windows-centeric environment, if a Linux VM is used
to run Password Dog.

Download the zip file from Github or use "git clone" to 
retrieve the files. Unzip and look at install.sh. Some
changes may be needed for your environment. If you're not
sure, try running it with the defaults. It will do no harm.

Run install.sh as follows:
sh install.sh

Note the installation script will download a 1.3GB dictionary
file from Amazon S3.

## Using Password Dog

Installation will provide two applications. A server running on
localhost:8080, and a cli application.

It will take a couple of minutes to start the server,
which by default runs on http://localhost:8080 will accept
requests of the form:
wget -q -O - http://localhost:8080/?newpassword=Password

Also you can pipe a list of candidates to checkpw_cli.py:
./checkpw_cli.py \<posible\_passwords.txt

Note it takes a minute for the application to start up.

Note the installation script will download a 1.3GB dictionary
file from Amazon S3.

A sample html file in /var/www/html/password-dog/index.html
shows how to update a password meter using AJAX with Password Dog.



