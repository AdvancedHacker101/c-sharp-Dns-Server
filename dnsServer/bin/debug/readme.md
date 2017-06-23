# Configuration Examples
## File Information
### dnsServer.exe:
Please only start this file with permission from the computer's owner.  
The file is NOT a virus it will not harm your and/or other's computer.  
It will open port udp/53 since every DNS server uses that.  
If a firewall prompt come's up please accept it otherwise the program will not work.  

### test.xml:
Here you can configure the MITM functions  
## Configuration
All of the example goes into the **test.xml** file  
#### To work as a normal dns server use:
`<dns></dns>`

#### To redirect a hostname to an IP Address use:
```
<dns>
<redirect from="exaple.com" to="1.3.3.7"/>
</dns>
```
In the file you can use **multiple** redirects so you can redirect example.com and example2.com too!  

#### To block a hostname use:
```
<dns>
<drop hostname="example.com"/>
</dns>
```
You can also block example.com and example2.com **both**!  
You can use the **variation** of these to create the optimal config for yourself!  
For example:  
```
<dns>
<redirect from="wrongsite.com" to="safesite.com"/>
<drop hostname="malware.com"/>
<redirect from="facebook.com" to="restricted-page-alert.com"/>
</dns>
```
