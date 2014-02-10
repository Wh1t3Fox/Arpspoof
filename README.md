Arpspoof
=========

A simple arpspoofing program written in python

<br>
<br>
#Usage
```sh
python arpspoof.py -t <target_ip> -p <proxy_server> -p <ports>
```
<br>
* If no target is specified a list of live IP's will be displayed.
* If no proxy_server is specifed it will simply act as MITM
* Default port is 80
<br>
<br>

#### Dependencies
* python 2.7
* scapy
* signal


####NOTE:
This is for educational purposes only. I am not responsible for what is done with the script.