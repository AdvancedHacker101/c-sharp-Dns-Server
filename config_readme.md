# Configuration Examples
## File Information
### test.xml:
Here you can configure the MITM functions  
After building the project you need to place this file under the bin/Debug folder  
This way the dnsServer can read your configuration
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
