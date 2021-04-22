#! /bin/bash

function naive() {
	sleep 1800
	sudo killall -9 deauth
}

while true ; do
	naive &
	sudo ./build/deauth horse0mon configuration.yaml
done
