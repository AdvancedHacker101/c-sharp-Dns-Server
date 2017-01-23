.exe:
Please only start this file with permission from the computer's owner.
The file is NOT a virus it will not harm your and/or other's computer.
it will open port udp/53 since every DNS server uses that.
if a firewall prompt come's up please accept it otherwise the program will not work.

.xml:

here you can configure the MITM functions

to work as a normal dns server use:
START of file
<dns></dns>
END of file

To redirect a hostname to an IP Address use:
START of file
<dns>
<redirect from="exaple.com" to="1.3.3.7"/>
</dns>
END of file

in the file you can use multiple redirects so you can redirect example.com and example2.com too!

To block a hostname use:
START of file
<dns>
<drop hostname="example.com"/>
</dns>
END of file

you can also block example.com and example2.com both!

you can use thevariation of these to create the optimal config for yourself:
for example:

<dns>
<redirect from="wrongsite.com" to="safesite.com"/>
<drop hostname="malware.com"/>
<redirect from="facebook.com" to="restricted-page-alert.com"/>
</dns>
