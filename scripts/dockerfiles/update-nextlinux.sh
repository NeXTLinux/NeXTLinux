#!/bin/bash

nextlinux system status

if [ -d "/root/nextlinux_modules/" ]; then
    for p in `ls -1 /root/nextlinux_modules/nextlinux-modules*.rpm 2>/dev/null`
    do
	echo "installing extra nextlinux modules $p"
	yum -y install $p
	done
fi


while(true)
do
    nextlinux feeds sync
    nextlinux feeds sub vulnerabilities
    nextlinux feeds sync
    sleep 3600
done
