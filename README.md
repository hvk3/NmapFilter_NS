# NmapFilter_NS
Second assignment for Network Security course.
  
This assignment was aimed at constructing a netfilter kernel module which would filter TCP packets according to the flags set, and log them to /var/log/kern.log.  
Credits:  
http://www.paulkiddie.com/2009/10/creating-a-simple-hello-world-netfilter-module/  
http://ttcplinux.sourceforge.net/documents/one/structure/tcphdr.html  
http://stackoverflow.com/  
  
Steps to setup module:  
make (Gives a warning of incompatible pointer cast, but that doesn't seem to affect the build.)  
sudo insmod filter.ko  
  
Steps to remove module:  
sudo rmmod filter  

TCP scans supported:  
a) Xmas scan (Checking if only FIN, PSH and URG flags are set in the TCP header.)  
b) TCP Maimon scan (Checking if only the FIN and ACK flags are set in the TCP header.)  
c) FIN scan (Checking if only the FIN flag is set in the TCP header.)  
d) Null scan (Checking if none of the flags are set in the TCP header.)  
  
Testing the module:  
cat /var/log/kern.log | grep filter.c  
The above command wil show all packets logged by filter.c, which is the source code of the kernel module. To test the various scans, use the following:  
a) sudo nmap -sX localhost  
b) sudo nmap -sM localhost  
c) sudo nmap -sF localhost  
  
Null scans are detected with the above three.  
  
Assumptions:  
Used kernel version 4.4.0-36-generic, so this may not work on older kernel versions.  
