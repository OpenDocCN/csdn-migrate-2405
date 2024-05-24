# 精通 Linux 安全和加固（四）

> 原文：[`zh.annas-archive.org/md5/FE09B081B50264BD581CF4C8AD742097`](https://zh.annas-archive.org/md5/FE09B081B50264BD581CF4C8AD742097)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：扫描、审计和加固

一个常见的误解是 Linux 用户永远不需要担心恶意软件。是的，Linux 比 Windows 更抵抗病毒。但是，病毒只是恶意软件的一种类型，其他类型的恶意软件也可以植入 Linux 机器。而且，如果您运行的服务器将与 Windows 用户共享文件，您将希望确保不与他们共享任何感染病毒的文件。

虽然 Linux 系统日志文件很好，但它们并不总是能清楚地反映谁做了什么或者谁访问了什么。可能是入侵者或内部人员试图访问未经授权的数据。我们真正想要的是一个良好的审计系统，可以在人们做了不应该做的事情时向我们发出警报。

然后，还有合规性的问题。您的组织可能必须与一个或多个规制机构打交道，这些机构规定了您如何加固服务器以防止攻击。如果您不符合规定，可能会被罚款或被迫停业。

幸运的是，我们有办法解决所有这些问题，而且它们并不那么复杂。

在本章中，我们将涵盖以下主题：

+   安装和更新 ClamAV 和 maldet

+   使用 ClamAV 和 maldet 进行扫描

+   SELinux 考虑

+   使用 Rootkit Hunter 扫描 rootkits

+   控制 auditd 守护程序

+   创建审计规则

+   使用`ausearch`和`aureport`实用程序搜索审计日志中的问题

+   `oscap`，命令行实用程序，用于管理和应用 OpenSCAP 策略

+   OpenSCAP Workbench，用于管理和应用 OpenSCAP 策略的 GUI 实用程序

+   OpenSCAP 策略文件及其各自旨在满足的合规标准

+   在操作系统安装期间应用策略

# 安装和更新 ClamAV 和 maldet

尽管我们不必过多担心病毒感染我们的 Linux 机器，但我们确实需要担心与 Windows 用户共享感染文件的问题。ClamAV 是一个可以作为独立程序运行或集成到邮件服务器守护程序（如 Postfix）中的**自由开源软件**（**FOSS**）防病毒解决方案。它是一个传统的防病毒扫描程序，工作方式基本与典型的 Windows 工作站上的防病毒程序相同。包含的`freshclam`实用程序允许您更新病毒签名。

*Linux Malware Detect*，通常缩写为**LMD**或**maldet**，是另一个可以与 ClamAV 一起工作的 FOSS 防病毒程序。（为了节省输入，我现在只会称它为 LMD。）据我所知，它并不在任何 Linux 发行版的存储库中，但安装和配置起来仍然很简单。其特点之一是当它在网络的边缘入侵检测系统上看到恶意软件时，它会自动生成恶意软件检测签名。最终用户也可以提交自己的恶意软件样本。安装后，您将获得一个已启用的 systemd 服务和一个定期更新恶意软件签名和程序本身的 cron 作业。它利用 Linux 内核的 inotify 功能自动监视目录中已更改的文件。安装它的过程对于任何基于 systemd 的 Linux 发行版来说基本相同。

您可以在以下网址获取有关 Linux Malware Detect 的所有细节：

[`www.rfxn.com/projects/linux-malware-detect/.`](https://www.rfxn.com/projects/linux-malware-detect/)

我们安装 ClamAV 和 LMD 的原因是，正如 LMD 的开发人员自由承认的那样，ClamAV 扫描引擎在扫描大文件集时性能更好。而且，通过将它们放在一起，ClamAV 可以使用 LMD 恶意软件签名以及自己的恶意软件签名。

# 安装 ClamAV 和 maldet

我们将从安装 ClamAV 开始。（它在 Ubuntu 的正常软件库中，但不在 CentOS 中。对于 CentOS，您需要安装 EPEL 软件库，就像我在第一章中所示的那样，*在虚拟环境中运行 Linux*。）我们还将安装 Wget，我们将用它来下载 LMD。

以下命令将帮助您在 Ubuntu 上安装 ClamAV 和 Wget：

```
donnie@ubuntu3:~$ sudo apt install clamav wget
```

以下命令将帮助您在 CentOS 上安装 ClamAV 和 Wget：

```
[donnie@localhost ~]$ sudo yum install clamav clamav-update wget
```

对于 Ubuntu，`clamav`软件包包含您所需的一切。对于 CentOS，您还需要安装`clamav-update`以获取病毒更新。

其余步骤对于任何虚拟机都是相同的。

接下来，您将下载并安装 LMD。在这里，您将要做一件我很少告诉人们要做的事情。也就是说，您将要登录到根用户 shell。原因是，尽管 LMD 安装程序可以使用 sudo 正常工作，但您最终会发现程序文件的所有者是执行安装的用户，而不是根用户。从根用户的 shell 中执行安装可以避免我们跟踪这些文件并更改所有权的麻烦。因此，按照以下方式下载文件：

```
sudo su -
wget http://www.rfxn.com/downloads/maldetect-current.tar.gz
```

现在，您将在根用户的主目录中找到该文件。现在，解压缩存档，进入生成的目录，并运行安装程序。安装程序完成后，将`README`文件复制到您自己的主目录，以便随时参考。（此`README`文件是 LMD 的文档。）然后，从根用户的 shell 退出到您自己的 shell：

```
tar xzvf maldetect-current.tar.gz
cd maldetect-1.6.2/

root@ubuntu3:~/maldetect-1.6.2# ./install.sh
Created symlink from /etc/systemd/system/multi-user.target.wants/maldet.service to /usr/lib/systemd/system/maldet.service.
update-rc.d: error: initscript does not exist: /etc/init.d/maldet
Linux Malware Detect v1.6
 (C) 2002-2017, R-fx Networks <proj@r-fx.org>
 (C) 2017, Ryan MacDonald <ryan@r-fx.org>
This program may be freely redistributed under the terms of the GNU GPL

installation completed to /usr/local/maldetect
config file: /usr/local/maldetect/conf.maldet
exec file: /usr/local/maldetect/maldet
exec link: /usr/local/sbin/maldet
exec link: /usr/local/sbin/lmd
cron.daily: /etc/cron.daily/maldet
maldet(22138): {sigup} performing signature update check...
maldet(22138): {sigup} local signature set is version 2017070716978
maldet(22138): {sigup} new signature set (201708255569) available
maldet(22138): {sigup} downloading https://cdn.rfxn.com/downloads/maldet-sigpack.tgz
maldet(22138): {sigup} downloading https://cdn.rfxn.com/downloads/maldet-cleanv2.tgz
maldet(22138): {sigup} verified md5sum of maldet-sigpack.tgz
maldet(22138): {sigup} unpacked and installed maldet-sigpack.tgz
maldet(22138): {sigup} verified md5sum of maldet-clean.tgz
maldet(22138): {sigup} unpacked and installed maldet-clean.tgz
maldet(22138): {sigup} signature set update completed
maldet(22138): {sigup} 15218 signatures (12485 MD5 | 1954 HEX | 779 YARA | 0 USER)

root@ubuntu3:~/maldetect-1.6.2# cp README /home/donnie

root@ubuntu3:~/maldetect-1.6.2# exit
logout
donnie@ubuntu3:~$

```

正如您所看到的，安装程序会自动创建符号链接以启用 maldet 服务，并且还会自动下载并安装最新的恶意软件签名。

# 配置 maldet

如果您在此时尝试启动 maldet 服务，它将失败。要使其工作，您需要配置要自动监视和扫描的目录。为此，您将把这些目录添加到`/usr/local/maldetect/monitor_paths`文件中。目前，我只想监视`/home`和`/root`目录，所以我的`monitor_paths`文件看起来是这样的：

```
/home
/root
```

保存文件后，您就可以启动 maldet 守护程序了：

```
sudo systemctl start maldet
```

您可以随时向`monitor_paths`文件添加更多目录，但请记住每次这样做时都要重新启动 maldet 守护程序，以便读取新添加的内容。

LMD 的配置文件是`/usr/local/maldetect/conf.maldet`。它有非常完善的文档和对每个配置项都有良好的注释，因此您不应该有任何困难来弄清楚它。目前，我们只会做一些配置更改。

在文件顶部，启用电子邮件警报并将您的用户名设置为电子邮件地址。现在，这两行应该看起来像这样：

```
email_alert="1"
email_addr="donnie"
```

LMD 尚未配置为将可疑文件移动到隔离文件夹中，我们希望它这样做。打开您的文本编辑器中的`conf.maldet`文件，并查找以下行：

```
quarantine_hits="0"
```

将上一行更改为以下行：

```
quarantine_hits="1"
```

您将看到一些其他可以配置的隔离操作，但目前这就是我们需要的全部。保存文件后，重新启动 maldet：

```
sudo systemctl restart maldet
```

新更改现在将生效。

# 更新 ClamAV 和 maldet

对于忙碌的管理员来说，好消息是您不必做任何事情来保持这两个程序的更新。它们都通过自动创建的 cron 作业运行，并为我们进行更新。为了证明 ClamAV 正在更新，我们可以查看系统日志文件：

```
Dec 8 20:02:09 localhost freshclam[22326]: ClamAV update process started at Fri Dec 8 20:02:09 2017
Dec 8 20:02:29 localhost freshclam[22326]: Can't query current.cvd.clamav.net
Dec 8 20:02:29 localhost freshclam[22326]: Invalid DNS reply. Falling back to HTTP mode.
Dec 8 20:02:29 localhost freshclam[22326]: Reading CVD header (main.cvd):
Dec 8 20:02:35 localhost freshclam[22326]: OK
Dec 8 20:02:47 localhost freshclam[22326]: Downloading main-58.cdiff [100%]
Dec 8 20:03:19 localhost freshclam[22326]: main.cld updated (version: 58, sigs: 4566249, f-level: 60, builder: sigmgr)
. . .
. . .
Dec 8 20:04:45 localhost freshclam[22326]: Downloading daily.cvd [100%]
Dec 8 20:04:53 localhost freshclam[22326]: daily.cvd updated (version: 24111, sigs: 1799769, f-level: 63, builder: neo)
Dec 8 20:04:53 localhost freshclam[22326]: Reading CVD header (bytecode.cvd):
Dec 8 20:04:54 localhost freshclam[22326]: OK
Dec 8 20:04:54 localhost freshclam[22326]: Downloading bytecode-279.cdiff [100%]
Dec 8 20:04:55 localhost freshclam[22326]: Downloading bytecode-280.cdiff [100%]
Dec 8 20:04:55 localhost freshclam[22326]: Downloading bytecode-281.cdiff [100%]
Dec 8 20:04:56 localhost freshclam[22326]: Downloading bytecode-282.cdiff [100%]
. . .
. . .
```

您将在 Ubuntu 日志或 CentOS 日志中看到相同的条目。但是，自动运行更新的方式有所不同。

在您的 Ubuntu 机器的`/etc/clamav/freshclam.conf`文件中，您会在末尾看到以下行：

```
# Check for new database 24 times a day
Checks 24
DatabaseMirror db.local.clamav.net
DatabaseMirror database.clamav.net
```

因此，基本上这意味着在 Ubuntu 上，ClamAV 将每小时检查更新。

在您的 CentOS 机器上，您将在`/etc/cron.d`目录中看到一个`clamav-update` cron 作业，如下所示：

```
## Adjust this line...
MAILTO=root

## It is ok to execute it as root; freshclam drops privileges and becomes
## user 'clamupdate' as soon as possible
0  */3 * * * root /usr/share/clamav/freshclam-sleep
```

左侧第二列中的`*/3`表示 ClamAV 将每 3 小时检查更新。如果您愿意，可以更改该设置，但您还需要更改`/etc/sysconfig/freshclam`文件中的设置。假设您希望 CentOS 每小时检查一次 ClamAV 更新。在 cron 作业文件中，将`*/3`更改为`*`。（您不需要执行`*/1`，因为该位置上的星号已经表示作业将每小时运行一次。）然后，在`/etc/sysconfig/freshclam`文件中查找以下行：

```
# FRESHCLAM_MOD=
```

取消注释该行，并添加您希望更新之间的分钟数。要设置为 1 小时，以匹配 cron 作业，它将如下所示：

```
FRESHCLAM_MOD=60
```

为了证明 maldet 正在更新，您可以查看`/usr/local/maldetect/logs/`目录中的其自己的日志文件。在`event_log`文件中，您将看到以下代码：

```
Dec 06 22:06:14 localhost maldet(3728): {sigup} performing signature update check...
Dec 06 22:06:14 localhost maldet(3728): {sigup} local signature set is version 2017070716978
Dec 06 22:07:13 localhost maldet(3728): {sigup} downloaded https://cdn.rfxn.com/downloads/maldet.sigs.ver
Dec 06 22:07:13 localhost maldet(3728): {sigup} new signature set (201708255569) available
Dec 06 22:07:13 localhost maldet(3728): {sigup} downloading https://cdn.rfxn.com/downloads/maldet-sigpack.tgz
. . .
. . .
Dec 06 22:07:43 localhost maldet(3728): {sigup} unpacked and installed maldet-clean.tgz
Dec 06 22:07:43 localhost maldet(3728): {sigup} signature set update completed
Dec 06 22:07:43 localhost maldet(3728): {sigup} 15218 signatures (12485 MD5 | 1954 HEX | 779 YARA | 0 USER)
Dec 06 22:14:55 localhost maldet(4070): {scan} signatures loaded: 15218 (12485 MD5 | 1954 HEX | 779 YARA | 0 USER)

```

在`/usr/local/maldetect/conf.maldet`文件中，您将看到以下两行，但它们之间有一些注释：

```
autoupdate_signatures="1"

autoupdate_version="1"
```

LMD 不仅会自动更新其恶意软件签名，还会确保您拥有 LMD 本身的最新版本。

# 使用 ClamAV 和 maldet 进行扫描

LMD 的 maldet 守护程序会不断监视您在`/usr/local/maldetect/monitor_paths`文件中指定的目录。当它发现可能是恶意软件的文件时，它会自动执行您在`conf.maldet`文件中指定的操作。为了演示其工作原理，我将在我的主目录中创建一个模拟恶意软件文件。幸运的是，这比听起来要容易，因为我们有一个网站可以帮助我们。

**EICAR**，以前以其全名**European Institute for Computer Antivirus Research**而闻名，提供了一个病毒签名，您可以将其包含在一个纯文本文件中。您可以在以下网址获取：[`www.eicar.org/86-0-Intended-use.html`](http://www.eicar.org/86-0-Intended-use.html)。

要创建模拟病毒文件，请转到我在前面链接中列出的页面。

向下滚动页面，直到在文本框中看到以下文本行：

```
X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
```

复制该文本行并将其插入到一个文本文件中，然后将其保存到任一虚拟机的主目录中。（您可以随意命名，但我会将其命名为`testing.txt`。）等待片刻，您会看到文件消失。然后，查看`/usr/local/maldetect/logs/event_log`文件，以验证 LMD 是否将文件移至隔离区：

```
Dec 09 19:03:43 localhost maldet(7192): {quar} malware quarantined from '/home/donnie/testing.txt' to '/usr/local/maldetect/quarantine/testing.txt.89513558'
```

LMD 还有更多内容，这里无法全部展示。但是，您可以在随附的`README`文件中了解所有内容。

# SELinux 注意事项

以前，在 Red Hat 类型的系统上进行杀毒扫描会触发 SELinux 警报。但是，在校对本章的过程中，扫描都按照预期进行，SELinux 从未打扰过我。因此，这个问题似乎已经解决了。

如果您在病毒扫描中生成任何 SELinux 警报，只需更改一个布尔值即可解决问题：

```
[donnie@localhost ~]$ getsebool -a | grep 'virus'
antivirus_can_scan_system --> off
antivirus_use_jit --> off
[donnie@localhost ~]$
```

我们感兴趣的是`antivirus_can_scan_system`布尔值，默认情况下是关闭的。要打开以启用病毒扫描，请按照以下步骤：

```
[donnie@localhost ~]$ sudo setsebool -P antivirus_can_scan_system on
[sudo] password for donnie:

[donnie@localhost ~]$ getsebool antivirus_can_scan_system
antivirus_can_scan_system --> on
[donnie@localhost ~]$
```

这应该解决您可能遇到的与 SELinux 相关的扫描问题。但是，就目前情况而言，您可能不需要担心它。

# 使用 Rootkit Hunter 扫描 rootkits

rootkit 是极其恶毒的恶意软件，绝对会毁了你的一天。它们可以监听来自他们主人的命令，窃取敏感数据并将其发送给他们的主人，或者为他们的主人提供一个易于访问的后门。它们被设计为隐秘的，具有隐藏自己的能力。有时，它们会用自己的特洛伊木马版本替换诸如`ls`或`ps`之类的实用程序，这些实用程序将显示系统上的所有文件或进程，但不包括与 rootkit 相关的文件。Rootkit 可以感染任何操作系统，甚至是我们心爱的 Linux。

为了植入 rootkit，攻击者必须已经在系统上获得了管理员权限。这是我总是在看到人们都在 root 用户的 shell 中完成所有工作时感到不安的许多原因之一，也是我坚决主张尽可能使用 sudo 的原因。我是说，真的，我们为什么要让坏人轻而易举地得逞呢？

几年前，在 Windows XP 的黑暗时期，索尼音乐因为有人发现他们在音乐 CD 上植入了 rootkit 而陷入了一些麻烦。他们并不是有意要做任何恶意的事情，只是想阻止人们使用他们的计算机制作非法副本。当然，大多数人都以管理员帐户运行 Windows XP，这使得 rootkit 很容易感染他们的计算机。Windows 用户仍然大多以管理员帐户运行，但至少现在有用户访问控制来帮助缓解这些问题。

有几个不同的程序可以扫描 rootkit，两者使用方式基本相同。我们现在要看的是一个名为 Rootkit Hunter 的程序。

# 安装和更新 Rootkit Hunter

对于 Ubuntu，Rootkit Hunter 在正常的存储库中。对于 CentOS，您需要安装 EPEL 存储库，就像我在第一章中所示的那样，*在虚拟环境中运行 Linux*。对于这两个 Linux 发行版，软件包名称是`rkhunter`。

对于 Ubuntu：

```
sudo apt install rkhunter
```

对于 CentOS：

```
sudo yum install rkhunter
```

安装后，您可以使用以下命令查看其选项：

```
man rkhunter
```

简单，对吧？

接下来，您需要使用`--update`选项更新 rootkit 签名：

```
[donnie@localhost ~]$ sudo rkhunter --update
[ Rootkit Hunter version 1.4.4 ]

Checking rkhunter data files...
 Checking file mirrors.dat [ Updated ]
 Checking file programs_bad.dat [ Updated ]
 Checking file backdoorports.dat [ No update ]
 Checking file suspscan.dat [ Updated ]
 Checking file i18n/cn [ No update ]
 Checking file i18n/de [ Updated ]
 Checking file i18n/en [ Updated ]
 Checking file i18n/tr [ Updated ]
 Checking file i18n/tr.utf8 [ Updated ]
 Checking file i18n/zh [ Updated ]
 Checking file i18n/zh.utf8 [ Updated ]
 Checking file i18n/ja [ Updated ]
[donnie@localhost ~]$
```

现在，我们准备好扫描了。

# 扫描 rootkit

要运行扫描，请使用`-c`选项。（这是用于检查的`-c`。）请耐心等待，因为这需要一段时间：

```
sudo rkhunter -c
```

当您以这种方式运行扫描时，Rootkit Hunter 将定期停止并要求您按*Enter*键继续。扫描完成后，您会在`/var/log`目录中找到一个`rkhunter.log`文件。

要让 Rootkit Hunter 自动作为 cron 作业运行，您需要使用`--cronjob`选项，这将导致程序一直运行下去，而不会提示您不断按*Enter*键。您可能还想使用`--rwo`选项，这将导致程序仅报告警告，而不是报告所有良好的内容。从命令行，命令看起来是这样的：

```
sudo rkhunter -c --cronjob --rwo
```

要创建一个自动每晚运行 Rootkit Hunter 的 cron 作业，请打开 root 用户的 crontab 编辑器：

```
sudo crontab -e -u root
```

假设您想在每天晚上 10 点 20 分运行 Rootkit Hunter。将其输入到 crontab 编辑器中：

```
20 22 * * * /usr/bin/rkhunter -c --cronjob --rwo
```

由于 cron 只能使用 24 小时制时间，因此您必须将晚上 10:00 表示为 22。 （只需将您习惯使用的 P.M.时钟时间加 12 即可。）这三个星号分别表示该作业将在每个月的每一天，每个月和每周的每一天运行。您需要列出命令的完整路径，否则 cron 将无法找到它。

您可以在`rkhunter`手册页中找到更多可能对您感兴趣的选项，但这应该足以让您开始使用它。

# 控制 auditd 守护程序

因此，您有一个充满了只有极少数人需要看到的绝密文件的目录，并且您想知道未经授权的人何时尝试查看它们。或者，也许您想知道某个文件何时被更改。或者，也许您想知道人们何时登录系统以及他们登录后在做什么。对于所有这些以及更多内容，您都有 auditd 系统。这是一个非常酷的系统，我相信您会喜欢它。

auditd 的美妙之一是它在 Linux 内核级别工作，而不是在用户模式级别。这使得攻击者更难以颠覆。

在红帽类型的系统上，auditd 默认已安装并启用。因此，您会在 CentOS 机器上找到它。在 Ubuntu 上，它尚未安装，因此您需要自己安装：

```
sudo apt install auditd
```

在 Ubuntu 上，您可以使用正常的`systemctl`命令控制 auditd 守护程序。因此，如果需要重新启动 auditd 以读取新的配置，可以使用以下命令：

```
sudo systemctl restart auditd
```

在 CentOS 7 上，由于某种我不理解的原因，正常的`systemctl`命令无法与 auditd 一起使用。（对于所有其他守护程序，它们可以。）因此，在您的 CentOS 7 机器上，您将使用老式的`service`命令重新启动 auditd 守护程序，如下所示：

```
sudo service auditd restart
```

除了这个小的不同之外，我告诉你的关于 auditd 的一切都适用于 Ubuntu 和 CentOS。

# 创建审计规则

好的，让我们从简单的开始，逐步提升到令人惊叹的东西。首先，让我们检查是否有任何审计规则生效：

```
[donnie@localhost ~]$ sudo auditctl -l
[sudo] password for donnie:
No rules
[donnie@localhost ~]$
```

正如您所看到的，`auditctl`命令是我们用来管理审计规则的命令。`-l`选项列出规则。

# 审计文件的更改

现在，假设我们想要查看当有人更改`/etc/passwd`文件时。 （我们将使用的命令看起来有点吓人，但我保证一旦我们分解它，它就会讲得通。）看看以下代码：

```
[donnie@localhost ~]$ sudo auditctl -w /etc/passwd -p wa -k passwd_changes
[sudo] password for donnie:

[donnie@localhost ~]$ sudo auditctl -l
-w /etc/passwd -p wa -k passwd_changes
[donnie@localhost ~]$
```

这是细节：

+   `-w`：这代表着“在哪里”，并且指向我们想要监视的对象。在这种情况下，它是`/etc/passwd`。

+   `-p`：这表示我们要监视的对象的权限。在这种情况下，我们正在监视任何人尝试（w）写入文件或尝试进行（a）属性更改的情况。（我们可以审计的另外两个权限是（r）读取和 e(x)ecute。）

+   `-k`：`k`代表 key，这只是 auditd 分配规则名称的方式。因此，`passwd_changes`是我们正在创建的规则的键或名称。

`auditctl -l`命令向我们显示规则确实存在。

现在，这个规则的一个小问题是它只是临时的，当我们重新启动机器时就会消失。要使其永久，我们需要在`/etc/audit/rules.d/`目录中创建一个自定义规则文件。然后，当您重新启动 auditd 守护程序时，自定义规则将被插入到`/etc/audit/audit.rules`文件中。因为`/etc/audit/`目录只能被具有 root 权限的人访问，所以我将通过列出文件的完整路径来打开文件，而不是尝试进入目录：

```
sudo less /etc/audit/audit.rules
```

这个默认文件中没有太多内容：

```
## This file is automatically generated from /etc/audit/rules.d
-D
-b 8192
-f 1

```

这个文件的细节如下：

+   `-D`：这将导致当前生效的所有规则和监视被删除，以便我们可以从干净的状态开始。因此，如果我现在重新启动 auditd 守护程序，它将读取这个`audit.rules`文件，这将删除我刚刚创建的规则。

+   `-b 8192`：这设置了我们可以同时拥有的未决审计缓冲区的数量。如果所有缓冲区都满了，系统将无法生成更多的审计消息。

+   `-f 1`：这设置了关键错误的失败模式，值可以是 0、1 或 2。`-f 0`会将模式设置为静默，这意味着 auditd 不会对关键错误采取任何措施。如我们在这里看到的`-f 1`，告诉 auditd 只报告关键错误，`-f 2`会导致 Linux 内核进入紧急模式。根据`auditctl`手册页面，高安全环境中的任何人可能都想将其更改为`-f 2`。但对于我们的目的，`-f1`就可以了。

您可以使用文本编辑器在`/etc/audit/rules.d/`目录中创建一个新的规则文件。或者，您可以将`auditctl -l`输出重定向到一个新文件，就像这样：

```
[donnie@localhost ~]$ sudo sh -c "auditctl -l > /etc/audit/rules.d/custom.rules"
[donnie@localhost ~]$ sudo service auditd restart
```

由于 Bash shell 不允许我直接将信息重定向到`/etc`目录中的文件，即使使用 sudo，我也必须使用`sudo sh -c`命令来执行`auditctl`命令。重新启动 auditd 守护程序后，我们的`audit.rules`文件现在如下所示：

```
## This file is automatically generated from /etc/audit/rules.d
-D
-b 8192
-f 1

-w /etc/passwd -p wa -k passwd_changes
```

现在，规则将在每次机器重新启动时生效，以及每次手动重新启动 auditd 守护程序时生效。

# 审计目录

我的固体灰色小猫维基和灰白色虎斑小猫克利奥帕特拉有一些非常敏感的秘密需要保护。因此，我创建了`secretcats`组并将它们添加到其中。然后，我创建了`secretcats`共享目录，并按照我在第六章中向您展示的方式设置了它的访问控制列表：

```
[donnie@localhost ~]$ sudo groupadd secretcats
[sudo] password for donnie:

[donnie@localhost ~]$ sudo usermod -a -G secretcats vicky
[donnie@localhost ~]$ sudo usermod -a -G secretcats cleopatra

[donnie@localhost ~]$ sudo mkdir /secretcats
[donnie@localhost ~]$ sudo chown nobody:secretcats /secretcats/
[donnie@localhost ~]$ sudo chmod 3770 /secretcats/

[donnie@localhost ~]$ ls -ld /secretcats/
drwxrws--T. 2 nobody secretcats 6 Dec 11 14:47 /secretcats/
[donnie@localhost ~]$
```

维基和克利奥帕特拉希望绝对确定没有人能进入他们的东西，因此他们要求我为他们的目录设置审计规则：

```
[donnie@localhost ~]$ sudo auditctl -w /secretcats/ -k secretcats_watch
[sudo] password for donnie:

[donnie@localhost ~]$ sudo auditctl -l
-w /etc/passwd -p wa -k passwd_changes
-w /secretcats -p rwxa -k secretcats_watch
[donnie@localhost ~]$
```

与以前一样，`-w`表示我们要监视的内容，`-k`表示审计规则的名称。这次，我省略了`-p`选项，因为我想监视每种类型的访问。换句话说，我想监视任何读取、写入、属性更改或执行操作。（因为这是一个目录，当有人尝试`cd`到目录时，执行操作会发生。）您可以在`auditctl -l`输出中看到，通过省略`-p`，我们现在将监视一切。但是，假设我只想监视有人尝试`cd`到这个目录的情况。相反，我可以使规则看起来像这样：

```
sudo auditctl -w /secretcats/ -p x -k secretcats_watch
```

到目前为止还算简单，对吧？现在让我们看看更复杂的东西。

# 审计系统调用

创建监视某个动作的规则并不难，但命令语法比我们到目前为止看到的要复杂一些。使用这个规则，我们将在查理尝试打开文件或尝试创建文件时收到警报：

```
[donnie@localhost ~]$ sudo auditctl -a always,exit -F arch=b64 -S openat -F auid=1006
[sudo] password for donnie:

[donnie@localhost ~]$ sudo auditctl -l
-w /etc/passwd -p wa -k passwd_changes
-w /secretcats -p rwxa -k secretcats_watch
-a always,exit -F arch=b64 -S openat -F auid=1006
[donnie@localhost ~]$
```

这是分解：

+   `-a always,exit`：这里有动作和列表。`exit`部分表示此规则将被添加到系统调用退出列表中。每当操作系统从系统调用退出时，将使用退出列表来确定是否需要生成审计事件。`always`部分是动作，表示每次从指定系统调用退出时都会创建此规则的审计记录。请注意，动作和列表参数必须用逗号分隔。

+   `-F arch=b64`：`-F`选项用于构建规则字段，在此命令中我们看到两个规则字段。第一个规则字段指定了机器的 CPU 架构。`b64`表示计算机正在使用 x86_64 CPU。（无论是英特尔还是 AMD 都无关紧要。）考虑到 32 位机器正在消失，Sun SPARC 和 PowerPC 机器并不常见，现在大多数情况下会看到`b64`。

+   `-S openat`：`-S`选项指定我们要监视的系统调用。`openat`是打开或创建文件的系统调用。

+   `-F auid=1006`：这第二个审计字段指定了我们要监视的用户的用户 ID 号码。（查理的用户 ID 号码是`1006`。）

关于系统调用或 syscalls 的完整解释对我们当前的目的来说有点太深奥了。现在，暂且可以说，每当用户发出请求 Linux 内核提供服务的命令时，就会发生系统调用。如果你有兴趣，可以在这里阅读更多关于 syscalls 的内容：[`blog.packagecloud.io/eng/2016/04/05/the-definitive-guide-to-linux-system-calls/`](https://blog.packagecloud.io/eng/2016/04/05/the-definitive-guide-to-linux-system-calls/)。

我在这里呈现的只是你可以使用审计规则做的许多事情中的一小部分。要查看更多示例，请查看`auditctl`手册页：

```
man auditctl
```

所以，现在你在想，“*既然我有了这些规则，我怎么知道有人试图违反它们呢？*”像往常一样，我很高兴你问了。

# 使用 ausearch 和 aureport

auditd 守护程序将事件记录到`/var/log/audit/audit.log`文件中。虽然你可以直接使用`less`之类的工具读取文件，但你真的不想这样做。`ausearch`和`aureport`实用程序将帮助你将文件转换为一种有些意义的语言。

# 搜索文件更改警报

让我们首先看一下我们创建的规则，该规则将在对`/etc/passwd`文件进行更改时警报我们：

```
sudo auditctl -w /etc/passwd -p wa -k passwd_changes
```

现在，让我们对文件进行更改并查找警报消息。我不想再添加另一个用户，因为我已经用完了可以使用的猫的名字，所以我将使用`chfn`实用程序来将联系信息添加到 Cleopatra 条目的注释字段中：

```
[donnie@localhost etc]$ sudo chfn cleopatra
Changing finger information for cleopatra.
Name []: Cleopatra Tabby Cat
Office []: Donnie's back yard
Office Phone []: 555-5555
Home Phone []: 555-5556

Finger information changed.
[donnie@localhost etc]
```

我现在将使用`ausearch`查找此事件可能生成的任何审计消息：

```
[donnie@localhost ~]$ sudo ausearch -i -k passwd_changes
----
type=CONFIG_CHANGE msg=audit(12/11/2017 13:06:20.665:11393) : auid=donnie ses=842 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 op=add_rule key=passwd_changes li
st=exit res=yes
----
type=CONFIG_CHANGE msg=audit(12/11/2017 13:49:15.262:11511) : auid=donnie ses=842 op=updated_rules path=/etc/passwd key=passwd_changes list=exit res=yes
[donnie@localhost ~]$
```

这是分解：

+   `-i`：这将接受任何数字数据，并在可能的情况下将其转换为文本。在这种情况下，它接受用户 ID 号并将其转换为实际的用户名，显示为`auid=donnie`。如果我不加`-i`，用户信息将显示为`auid=1000`，这是我的用户 ID 号。

+   `-k passwd_changes`：这指定了我们想要查看审计消息的审计规则的键或名称。

你可以看到这个输出有两部分。第一部分只是显示我创建审计规则的时间，所以我们对此不感兴趣。在第二部分中，你可以看到我触发规则的时间，但它没有显示我如何触发它。所以，让我们使用`aureport`来看看它是否会给我们更多线索：

```
[donnie@localhost ~]$ sudo aureport -i -k | grep 'passwd_changes'
1\. 12/11/2017 13:06:20 passwd_changes yes ? donnie 11393
2\. 12/11/2017 13:49:15 passwd_changes yes ? donnie 11511
3\. 12/11/2017 13:49:15 passwd_changes yes /usr/bin/chfn donnie 11512
4\. 12/11/2017 14:54:11 passwd_changes yes /usr/sbin/usermod donnie 11728
5\. 12/11/2017 14:54:25 passwd_changes yes /usr/sbin/usermod donnie 11736
[donnie@localhost ~]$
```

有趣的是，使用`ausearch`时，你必须在`-k`选项之后指定你感兴趣的审计规则的名称或键。而对于`aureport`，`-k`选项表示你想查看与所有审计规则键有关的所有日志条目。要查看特定键的日志条目，只需将输出导入 grep。`-i`选项对`ausearch`的作用与对`aureport`的作用相同。

正如你所看到的，`aureport`将`audit.log`文件的隐晦语言解析为更容易理解的普通语言。我不确定我做了什么来生成事件 1 和 2，所以我查看了`/var/log/secure`文件以查找答案。我在那些时间看到了这两个条目：

```
Dec 11 13:06:20 localhost sudo: donnie : TTY=pts/1 ; PWD=/home/donnie ; USER=root ; COMMAND=/sbin/auditctl -w /etc/passwd -p wa -k passwd_changes
. . .
. . .
Dec 11 13:49:24 localhost sudo: donnie : TTY=pts/1 ; PWD=/home/donnie ; USER=root ; COMMAND=/sbin/ausearch -i -k passwd_changes

```

所以，事件 1 是我最初创建审计规则时发生的，事件 2 发生在我执行`ausearch`操作时。

我必须承认，第 4 行和第 5 行的事件有点神秘。当我调用`usermod`命令时，都会创建这两个事件，并且它们都与我将 Vicky 和 Cleopatra 添加到`secretcats`组的安全日志条目相关：

```
Dec 11 14:54:11 localhost sudo:  donnie : TTY=pts/1 ; PWD=/home/donnie ; USER=root ; COMMAND=/sbin/usermod -a -G secretcats vicky
Dec 11 14:54:11 localhost usermod[14865]: add 'vicky' to group 'secretcats'
Dec 11 14:54:11 localhost usermod[14865]: add 'vicky' to shadow group 'secretcats'
Dec 11 14:54:25 localhost sudo:  donnie : TTY=pts/1 ; PWD=/home/donnie ; USER=root ; COMMAND=/sbin/usermod -a -G secretcats cleopatra
Dec 11 14:54:25 localhost usermod[14871]: add 'cleopatra' to group 'secretcats'
Dec 11 14:54:25 localhost usermod[14871]: add 'cleopatra' to shadow group 'secretcats'
```

奇怪的是，将用户添加到辅助组不会修改`passwd`文件。所以，我真的不知道为什么规则会触发创建第 4 行和第 5 行的事件。

这让我们留下了第 3 行的事件，那是我使用`chfn`实际修改`passwd`文件的地方。这是关于那个的`secure`日志条目：

```
Dec 11 13:48:49 localhost sudo:  donnie : TTY=pts/1 ; PWD=/etc ; USER=root ; COMMAND=/bin/chfn cleopatra
```

所以，在所有这些事件中，只有第 3 行的事件是实际修改了`/etc/passwd`文件的。

我一直在这里提到的`/var/log/secure`文件是在 Red Hat 类型的操作系统上，比如 CentOS。在你的 Ubuntu 机器上，你会看到`/var/log/auth.log`文件。

# 搜索目录访问规则违规

在我们的下一个场景中，我们为 Vicky 和 Cleopatra 创建了一个共享目录，并为它创建了一个审计规则，看起来像这样：

```
sudo auditctl -w /secretcats/ -k secretcats_watch
```

因此，对这个目录的所有访问或尝试访问都应该触发警报。首先，让 Vicky 进入`/secretcats`目录并运行`ls -l`命令：

```
[vicky@localhost ~]$ cd /secretcats
[vicky@localhost secretcats]$ ls -l
total 4
-rw-rw-r--. 1 cleopatra secretcats 31 Dec 12 11:49 cleopatrafile.txt
[vicky@localhost secretcats]$
```

我们看到 Cleopatra 已经在那里并创建了一个文件。（我们稍后再回来讨论这个问题。）当事件触发 auditd 规则时，通常会在`/var/log/audit/audit.log`文件中创建多条记录。如果你研究每个事件的每条记录，你会发现每条记录都涵盖了该事件的不同方面。当我执行`ausearch`命令时，我看到了来自那个`ls -l`操作的总共五条记录。为了节省空间，我只列出第一条和最后一条：

```
sudo ausearch -i -k secretcats_watch | less

type=PROCTITLE msg=audit(12/12/2017 12:15:35.447:14077) : proctitle=ls --color=auto -l
type=PATH msg=audit(12/12/2017 12:15:35.447:14077) : item=0 name=. inode=33583041 dev=fd:01 mode=dir,sgid,sticky,770 ouid=nobody ogid=secretcats rdev=00:00 obj=unconfined_u:object_r:default_t:s0 objtype=NORMAL
type=CWD msg=audit(12/12/2017 12:15:35.447:14077) :  cwd=/secretcats
type=SYSCALL msg=audit(12/12/2017 12:15:35.447:14077) : arch=x86_64 syscall=openat success=yes exit=3 a0=0xffffffffffffff9c a1=0x2300330 a2=O_RDONLY|O_NONBLOCK|O_DIRECTORY|O_CLOEXEC a3=0x0 items=1 ppid=10805 pid=10952 auid=vicky uid=vicky gid=vicky euid=vicky suid=vicky fsuid=vicky egid=vicky sgid=vicky fsgid=vicky tty=pts0 ses=1789 comm=ls exe=/usr/bin/ls subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=secretcats_watch
. . .
. . .
type=PROCTITLE msg=audit(12/12/2017 12:15:35.447:14081) : proctitle=ls --color=auto -l
type=PATH msg=audit(12/12/2017 12:15:35.447:14081) : item=0 name=cleopatrafile.txt inode=33583071 dev=fd:01 mode=file,664 ouid=cleopatra ogid=secretcats rdev=00:00 obj=unconfined_u:object_r:default_t:s0 objtype=NORMAL
type=CWD msg=audit(12/12/2017 12:15:35.447:14081) :  cwd=/secretcats
type=SYSCALL msg=audit(12/12/2017 12:15:35.447:14081) : arch=x86_64 syscall=getxattr success=no exit=ENODATA(No data available) a0=0x7fff7c266e60 a1=0x7f0a61cb9db0 a2=0x0 a3=0x0 items=1 ppid=10805 pid=10952 auid=vicky uid=vicky gid=vicky euid=vicky suid=vicky fsuid=vicky egid=vicky sgid=vicky fsgid=vicky tty=pts0 ses=1789 comm=ls exe=/usr/bin/ls subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=secretcats_watch
```

在这两条记录中，你可以看到所采取的行动（`ls -l`），以及采取行动的人或者在这种情况下是猫的信息。由于这是一个 CentOS 机器，你还可以看到 SELinux 上下文信息。在第二条记录中，你还可以看到 Vicky 在执行`ls`命令时看到的文件名。

接下来，让我们假设那个狡猾的查理登录并尝试进入`/secretcats`目录：

```
[charlie@localhost ~]$ cd /secretcats
-bash: cd: /secretcats: Permission denied
[charlie@localhost ~]$ ls -l /secretcats
ls: cannot open directory /secretcats: Permission denied
[charlie@localhost ~]$
```

查理不是`secretcats`组的成员，也没有权限进入`secretcats`目录。因此，他应该触发一个警报消息。实际上，他触发了一个包含四条记录的警报，我再次只列出第一条和最后一条：

```
sudo ausearch -i -k secretcats_watch | less

type=PROCTITLE msg=audit(12/12/2017 12:32:04.341:14152) : proctitle=ls --color=auto -l /secretcats
type=PATH msg=audit(12/12/2017 12:32:04.341:14152) : item=0 name=/secretcats inode=33583041 dev=fd:01 mode=dir,sgid,sticky,770 ouid=nobody ogid=secretcats rdev=00:00 obj=unconfined_u:object_r:default_t:s0 objtype=NORMAL
type=CWD msg=audit(12/12/2017 12:32:04.341:14152) :  cwd=/home/charlie
type=SYSCALL msg=audit(12/12/2017 12:32:04.341:14152) : arch=x86_64 syscall=lgetxattr success=yes exit=35 a0=0x7ffd8d18f7dd a1=0x7f2496858f8a a2=0x12bca30 a3=0xff items=1 ppid=11637 pid=11663 auid=charlie uid=charlie gid=charlie euid=charlie suid=charlie fsuid=charlie egid=charlie sgid=charlie fsgid=charlie tty=pts0 ses=1794 comm=ls exe=/usr/bin/ls subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=secretcats_watch
. . .
. . .
type=PROCTITLE msg=audit(12/12/2017 12:32:04.341:14155) : proctitle=ls --color=auto -l /secretcats
type=PATH msg=audit(12/12/2017 12:32:04.341:14155) : item=0 name=/secretcats inode=33583041 dev=fd:01 mode=dir,sgid,sticky,770 ouid=nobody ogid=secretcats rdev=00:00 obj=unconfined_u:object_r:default_t:s0 objtype=NORMAL
type=CWD msg=audit(12/12/2017 12:32:04.341:14155) :  cwd=/home/charlie
type=SYSCALL msg=audit(12/12/2017 12:32:04.341:14155) : arch=x86_64 syscall=openat success=no exit=EACCES(Permission denied) a0=0xffffffffffffff9c a1=0x12be300 a2=O_RDONLY|O_NONBLOCK|O_DIRECTORY|O_CLOEXEC a3=0x0 items=1 ppid=11637 pid=11663 auid=charlie uid=charlie gid=charlie euid=charlie suid=charlie fsuid=charlie egid=charlie sgid=charlie fsgid=charlie tty=pts0 ses=1794 comm=ls exe=/usr/bin/ls subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=secretcats_watch
```

这里有两件事需要注意。首先，仅尝试`cd`进入目录不会触发警报。然而，使用`ls`尝试读取目录的内容会触发警报。其次，注意第二条记录中出现的`Permission denied`消息。

我们将要查看的最后一组警报是在 Cleopatra 创建她的`cleopatrafile.txt`文件时创建的。这个事件触发了一个包含 30 条记录的警报。以下是其中的两条：

```
. . .
. . .
type=PROCTITLE msg=audit(12/12/2017 11:49:37.536:13856) : proctitle=vim cleopatrafile.txt
type=PATH msg=audit(12/12/2017 11:49:37.536:13856) : item=0 name=. inode=33583041 dev=fd:01 mode=dir,sgid,sticky,770 ouid=nobody ogid=secretcats rdev=00:00 obj=unconfined_u:o
bject_r:default_t:s0 objtype=NORMAL
type=CWD msg=audit(12/12/2017 11:49:37.536:13856) :  cwd=/secretcats
type=SYSCALL msg=audit(12/12/2017 11:49:37.536:13856) : arch=x86_64 syscall=open success=yes exit=4 a0=0x5ab983 a1=O_RDONLY a2=0x0 a3=0x63 items=1 ppid=9572 pid=9593 auid=cle
opatra uid=cleopatra gid=cleopatra euid=cleopatra suid=cleopatra fsuid=cleopatra egid=cleopatra sgid=cleopatra fsgid=cleopatra tty=pts0 ses=1779 comm=vim exe=/usr/bin/vim sub
j=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=secretcats_watch
----
type=PROCTITLE msg=audit(12/12/2017 11:49:56.001:13858) : proctitle=vim cleopatrafile.txt
type=PATH msg=audit(12/12/2017 11:49:56.001:13858) : item=1 name=/secretcats/.cleopatrafile.txt.swp inode=33583065 dev=fd:01 mode=file,600 ouid=cleopatra ogid=secretcats rdev
=00:00 obj=unconfined_u:object_r:default_t:s0 objtype=DELETE
type=PATH msg=audit(12/12/2017 11:49:56.001:13858) : item=0 name=/secretcats/ inode=33583041 dev=fd:01 mode=dir,sgid,sticky,770 ouid=nobody ogid=secretcats rdev=00:00 obj=unc
onfined_u:object_r:default_t:s0 objtype=PARENT
type=CWD msg=audit(12/12/2017 11:49:56.001:13858) :  cwd=/secretcats
type=SYSCALL msg=audit(12/12/2017 11:49:56.001:13858) : arch=x86_64 syscall=unlink success=yes exit=0 a0=0x15ee7a0 a1=0x1 a2=0x1 a3=0x7ffc2c82e6b0 items=2 ppid=9572 pid=9593
auid=cleopatra uid=cleopatra gid=cleopatra euid=cleopatra suid=cleopatra fsuid=cleopatra egid=cleopatra sgid=cleopatra fsgid=cleopatra tty=pts0 ses=1779 comm=vim exe=/usr/bin
/vim subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=secretcats_watch
. . .
. . .
```

你可以看出这两条消息中的第一条是 Cleopatra 保存文件并退出 vim 时发生的，因为第二条消息显示了`objtype=DELETE`，她的临时 vim 交换文件被删除了。

好的，这都很好，但如果这些信息太多怎么办？如果你只想要一个快速而简洁的安全事件列表，那么我们将使用`aureport`。我们将像之前一样使用它。

首先，让我们将`aureport`的输出导入`less`而不是`grep`，这样我们就可以看到列标题：

```
[donnie@localhost ~]$ sudo aureport -i -k | less

Key Report
===============================================
# date time key success exe auid event
===============================================
1\. 12/11/2017 13:06:20 passwd_changes yes ? donnie 11393
2\. 12/11/2017 13:49:15 passwd_changes yes ? donnie 11511
3\. 12/11/2017 13:49:15 passwd_changes yes /usr/bin/chfn donnie 11512
4\. 12/11/2017 14:54:11 passwd_changes yes /usr/sbin/usermod donnie 11728
5\. 12/11/2017 14:54:25 passwd_changes yes /usr/sbin/usermod donnie 11736
. . .
. . .
```

`success`列中的状态将是`yes`或`no`，取决于用户是否能够成功执行违反规则的操作。或者，如果事件不是触发规则的结果，它可能是一个问号。

对于查理，我们在第 48 行看到了一个`yes`事件，而在第 49 到 51 行的事件中都有一个`no`状态。我们还看到所有这些条目都是由查理使用`ls`命令触发的：

```
sudo aureport -i -k | grep 'secretcats_watch'

[donnie@localhost ~]$ sudo aureport -i -k | grep 'secretcats_watch'
6\. 12/11/2017 15:01:25 secretcats_watch yes ? donnie 11772
8\. 12/12/2017 11:49:29 secretcats_watch yes /usr/bin/ls cleopatra 13828
9\. 12/12/2017 11:49:37 secretcats_watch yes /usr/bin/vim cleopatra 13830
10\. 12/12/2017 11:49:37 secretcats_watch yes /usr/bin/vim cleopatra 13829
. . .
. . .
48\. 12/12/2017 12:32:04 secretcats_watch yes /usr/bin/ls charlie 14152
49\. 12/12/2017 12:32:04 secretcats_watch no /usr/bin/ls charlie 14153
50\. 12/12/2017 12:32:04 secretcats_watch no /usr/bin/ls charlie 14154
51\. 12/12/2017 12:32:04 secretcats_watch no /usr/bin/ls charlie 14155
[donnie@localhost ~]$
```

你可能会认为第 48 行的`yes`事件表明查理成功读取了`secretcats`目录的内容。要进一步分析，请查看每行末尾的事件编号，并将其与我们之前的`ausearch`命令的输出进行对照。你会发现事件编号 14152 到 14155 属于具有相同时间戳的记录。我们可以在每条记录的第一行看到这一点：

```
[donnie@localhost ~]$ sudo ausearch -i -k secretcats_watch | less

type=PROCTITLE msg=audit(12/12/2017 12:32:04.341:14152) : proctitle=ls --color=auto -l /secretcats

type=PROCTITLE msg=audit(12/12/2017 12:32:04.341:14153) : proctitle=ls --color=auto -l /secretcats

type=PROCTITLE msg=audit(12/12/2017 12:32:04.341:14154) : proctitle=ls --color=auto -l /secretcats

type=PROCTITLE msg=audit(12/12/2017 12:32:04.341:14155) : proctitle=ls --color=auto -l /secretcats
```

正如我们之前指出的，这个系列的最后一条记录显示了查理的`Permission denied`，这才是真正重要的。

空间不允许我对审计日志记录中的每个项目进行全面解释。但是，您可以在官方的 Red Hat 文档中阅读有关此处的内容：[`access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/security_guide/sec-understanding_audit_log_files`](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/security_guide/sec-understanding_audit_log_files)。

# 搜索系统调用规则违规

我们创建的第三条规则是监视这个狡猾的查尔斯。这条规则将在查尔斯尝试打开或创建文件时向我们发出警报。（正如我们之前指出的，`1006`是查尔斯的用户 ID 号。）

```
sudo auditctl -a always,exit -F arch=b64 -S openat -F auid=1006
```

尽管查尔斯在这个系统上并没有做太多事情，但这条规则给我们带来了比我们预期的更多的日志条目。我们只看其中的一些条目：

```
time->Tue Dec 12 11:49:29 2017
type=PROCTITLE msg=audit(1513097369.952:13828): proctitle=6C73002D2D636F6C6F723D6175746F
type=PATH msg=audit(1513097369.952:13828): item=0 name="." inode=33583041 dev=fd:01 mode=043770 ouid=99 ogid=1009 rdev=00:00 obj=unconfined_u:object_r:default_t:s0 objtype=NO
RMAL
type=CWD msg=audit(1513097369.952:13828):  cwd="/secretcats"
type=SYSCALL msg=audit(1513097369.952:13828): arch=c000003e syscall=257 success=yes exit=3 a0=ffffffffffffff9c a1=10d1560 a2=90800 a3=0 items=1 ppid=9572 pid=9592 auid=1004 u
id=1004 gid=1006 euid=1004 suid=1004 fsuid=1004 egid=1006 sgid=1006 fsgid=1006 tty=pts0 ses=1779 comm="ls" exe="/usr/bin/ls" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0
:c0.c1023 key="secretcats_watch"
```

这条记录是在查尔斯试图访问`/secretcats/`目录时生成的。所以，我们可以期待看到这个。但是，我们没有预料到的是查尔斯通过安全外壳登录系统时间接访问的文件记录的数量之多。这里只是其中的一部分：

```
time->Tue Dec 12 11:50:28 2017
type=PROCTITLE msg=audit(1513097428.662:13898): proctitle=737368643A20636861726C6965407074732F30
type=PATH msg=audit(1513097428.662:13898): item=0 name="/proc/9726/fd" inode=1308504 dev=00:03 mode=040500 ouid=0 ogid=0 rdev=00:00 obj=unconfined_u:unconfined_r:unconfined_t
:s0-s0:c0.c1023 objtype=NORMAL
type=CWD msg=audit(1513097428.662:13898):  cwd="/home/charlie"
type=SYSCALL msg=audit(1513097428.662:13898): arch=c000003e syscall=257 success=yes exit=3 a0=ffffffffffffff9c a1=7ffc7ca1d840 a2=90800 a3=0 items=1 ppid=9725 pid=9726 auid=1
006 uid=1006 gid=1008 euid=1006 suid=1006 fsuid=1006 egid=1008 sgid=1008 fsgid=1008 tty=pts0 ses=1781 comm="sshd" exe="/usr/sbin/sshd" subj=unconfined_u:unconfined_r:unconfin
ed_t:s0-s0:c0.c1023 key=(null)
----
time->Tue Dec 12 11:50:28 2017
type=PROCTITLE msg=audit(1513097428.713:13900): proctitle=737368643A20636861726C6965407074732F30
type=PATH msg=audit(1513097428.713:13900): item=0 name="/etc/profile.d/" inode=33593031 dev=fd:01 mode=040755 ouid=0 ogid=0 rdev=00:00 obj=system_u:object_r:bin_t:s0 objtype=
NORMAL
type=CWD msg=audit(1513097428.713:13900):  cwd="/home/charlie"
type=SYSCALL msg=audit(1513097428.713:13900): arch=c000003e syscall=257 success=yes exit=3 a0=ffffffffffffff9c a1=1b27930 a2=90800 a3=0 items=1 ppid=9725 pid=9726 auid=1006 u
id=1006 gid=1008 euid=1006 suid=1006 fsuid=1006 egid=1008 sgid=1008 fsgid=1008 tty=pts0 ses=1781 comm="bash" exe="/usr/bin/bash" subj=unconfined_u:unconfined_r:unconfined_t:s
0-s0:c0.c1023 key=(null)
```

在第一条记录中，我们看到查尔斯访问了`/usr/sbin/sshd`文件。在第二条记录中，我们看到他访问了`/usr/bin/bash`文件。并不是查尔斯选择访问这些文件。操作系统在正常的登录事件中为他访问了这些文件。因此，正如您所看到的，当您创建审计规则时，您必须小心您的愿望，因为有明显的危险，愿望可能会实现。如果您真的需要监视某人，您将需要创建一个不会给您太多信息的规则。

在此期间，我们也可以看看`aureport`的输出是什么样的：

```
[donnie@localhost ~]$ sudo aureport -s -i | grep 'openat'
[sudo] password for donnie:
1068\. 12/12/2017 11:49:29 openat 9592 ls cleopatra 13828
1099\. 12/12/2017 11:50:28 openat 9665 sshd charlie 13887
1100\. 12/12/2017 11:50:28 openat 9665 sshd charlie 13889
1101\. 12/12/2017 11:50:28 openat 9665 sshd charlie 13890
1102\. 12/12/2017 11:50:28 openat 9726 sshd charlie 13898
1103\. 12/12/2017 11:50:28 openat 9726 bash charlie 13900
1104\. 12/12/2017 11:50:28 openat 9736 grep charlie 13901
1105\. 12/12/2017 11:50:28 openat 9742 grep charlie 13902
1108\. 12/12/2017 11:50:51 openat 9766 ls charlie 13906
1110\. 12/12/2017 12:15:35 openat 10952 ls vicky 14077
1115\. 12/12/2017 12:30:54 openat 11632 sshd charlie 14129
1116\. 12/12/2017 12:30:54 openat 11632 sshd charlie 14131
1117\. 12/12/2017 12:30:54 openat 11632 sshd charlie 14132
1118\. 12/12/2017 12:30:54 openat 11637 sshd charlie 14140
1119\. 12/12/2017 12:30:54 openat 11637 bash charlie 14142
1120\. 12/12/2017 12:30:54 openat 11647 grep charlie 14143
1121\. 12/12/2017 12:30:54 openat 11653 grep charlie 14144
1125\. 12/12/2017 12:32:04 openat 11663 ls charlie 14155
[donnie@localhost ~]$
```

除了查尔斯所做的事情，我们还可以看到维基和克利奥帕特拉所做的事情。这是因为我们为`/secretcats/`目录设置的规则在维基和克利奥帕特拉访问、查看或创建该目录中的文件时生成了`openat`事件。

# 生成认证报告

您可以生成用户认证报告，而无需定义任何审计规则。只需使用`aureport`加上`-au`选项开关即可。（记住`au`，认证的前两个字母。）

```
[donnie@localhost ~]$ sudo aureport -au
[sudo] password for donnie:

Authentication Report
============================================
# date time acct host term exe success event
============================================
1\. 10/28/2017 13:38:52 donnie localhost.localdomain tty1 /usr/bin/login yes 94
2\. 10/28/2017 13:39:03 donnie localhost.localdomain /dev/tty1 /usr/bin/sudo yes 102
3\. 10/28/2017 14:04:51 donnie localhost.localdomain /dev/tty1 /usr/bin/sudo yes 147
. . .
. . .
239\. 12/12/2017 11:50:20 charlie 192.168.0.222 ssh /usr/sbin/sshd no 13880
244\. 12/12/2017 12:10:06 cleopatra 192.168.0.222 ssh /usr/sbin/sshd no 13992
247\. 12/12/2017 12:14:28 vicky 192.168.0.222 ssh /usr/sbin/sshd no 14049
250\. 12/12/2017 12:30:49 charlie 192.168.0.222 ssh /usr/sbin/sshd no 14122
265\. 12/12/2017 19:06:20 charlie 192.168.0.222 ssh /usr/sbin/sshd no 725
269\. 12/12/2017 19:23:45 donnie ? /dev/pts/0 /usr/bin/sudo no 779
[donnie@localhost ~]$
```

对于登录事件，这告诉我们用户是在本地终端登录还是通过安全外壳远程登录。要查看任何事件的详细信息，请使用`ausearch`加上`-a`选项，然后跟上您在行末看到的事件编号。（奇怪的是，`-a`选项代表一个事件。）让我们看看查尔斯的事件编号 14122：

```
[donnie@localhost ~]$ sudo ausearch -a 14122
----
time->Tue Dec 12 12:30:49 2017
type=USER_AUTH msg=audit(1513099849.322:14122): pid=11632 uid=0 auid=4294967295 ses=4294967295 subj=system_u:system_r:sshd_t:s0-s0:c0.c1023 msg='op=pubkey acct="charlie" exe="/usr/sbin/sshd" hostname=? addr=192.168.0.222 terminal=ssh res=failed'
```

问题在于这真的毫无意义。我是为查尔斯做的登录记录，我可以确定查尔斯从未有过任何登录失败。事实上，我们可以将其与`/var/log/secure`文件中的匹配条目进行关联：

```
Dec 12 12:30:53 localhost sshd[11632]: Accepted password for charlie from 192.168.0.222 port 34980 ssh2
Dec 12 12:30:54 localhost sshd[11632]: pam_unix(sshd:session): session opened for user charlie by (uid=0)
```

这两个条目的时间戳比`ausearch`输出的时间戳晚了几秒，但没关系。这个日志文件中没有任何迹象表明查尔斯曾经有过登录失败，这两个条目清楚地显示了查尔斯的登录确实成功了。这里的教训是，当您在`ausearch`或`aureport`输出中看到一些奇怪的东西时，一定要将其与适当的认证日志文件中的匹配条目进行关联，以更好地了解发生了什么。（通过*认证日志文件*，我指的是 Red Hat 类型系统的`/var/log/secure`和 Ubuntu 系统的`/var/log/auth.log`。其他 Linux 发行版的名称可能有所不同。）

# 使用预定义的规则集

在你的 CentOS 机器的`/usr/share/doc/audit-version_number/`目录中，你会看到一些预先制定的不同场景的规则集。一旦你在 Ubuntu 上安装了 auditd，你也会有适用于它的审计规则，但对于 Ubuntu 16.04 和 Ubuntu 17.10，位置是不同的。在 Ubuntu 16.04 上，规则位于`/usr/share/doc/auditd/examples/`目录中。在 Ubuntu 17.10 上，它们位于`/usr/share/doc/auditd/examples/rules/`目录中。无论如何，这三个发行版中有一些规则集是共通的。让我们看看 CentOS 机器上有什么：

```
[donnie@localhost rules]$ pwd
/usr/share/doc/audit-2.7.6/rules
[donnie@localhost rules]$ ls -l
total 96
-rw-r--r--. 1 root root  163 Aug  4 17:29 10-base-config.rules
-rw-r--r--. 1 root root  284 Apr 19  2017 10-no-audit.rules
-rw-r--r--. 1 root root   93 Apr 19  2017 11-loginuid.rules
-rw-r--r--. 1 root root  329 Apr 19  2017 12-cont-fail.rules
-rw-r--r--. 1 root root  323 Apr 19  2017 12-ignore-error.rules
-rw-r--r--. 1 root root  516 Apr 19  2017 20-dont-audit.rules
-rw-r--r--. 1 root root  273 Apr 19  2017 21-no32bit.rules
-rw-r--r--. 1 root root  252 Apr 19  2017 22-ignore-chrony.rules
-rw-r--r--. 1 root root 4915 Apr 19  2017 30-nispom.rules
-rw-r--r--. 1 root root 5952 Apr 19  2017 30-pci-dss-v31.rules
-rw-r--r--. 1 root root 6663 Apr 19  2017 30-stig.rules
-rw-r--r--. 1 root root 1498 Apr 19  2017 31-privileged.rules
-rw-r--r--. 1 root root  218 Apr 19  2017 32-power-abuse.rules
-rw-r--r--. 1 root root  156 Apr 19  2017 40-local.rules
-rw-r--r--. 1 root root  439 Apr 19  2017 41-containers.rules
-rw-r--r--. 1 root root  672 Apr 19  2017 42-injection.rules
-rw-r--r--. 1 root root  424 Apr 19  2017 43-module-load.rules
-rw-r--r--. 1 root root  326 Apr 19  2017 70-einval.rules
-rw-r--r--. 1 root root  151 Apr 19  2017 71-networking.rules
-rw-r--r--. 1 root root   86 Apr 19  2017 99-finalize.rules
-rw-r--r--. 1 root root 1202 Apr 19  2017 README-rules
[donnie@localhost rules]$
```

我想重点关注的三个文件是`nispom`、`pci-dss`和`stig`文件。这三个规则集分别设计用于满足特定认证机构的审计标准。依次来看，这些规则集是：

+   `nispom`：国家工业安全计划——你会看到这个规则集在美国国防部或其承包商处使用

+   `pci-dss`：支付卡行业数据安全标准——如果你在银行或金融行业工作，或者你只是经营一个接受信用卡的在线业务，你可能会对这个非常熟悉

+   `stig`：安全技术实施指南——如果你在美国政府工作，或者可能是其他政府，你将会处理这个

要使用这些规则集中的一个，将相应的文件复制到`/etc/audit/rules.d/`目录中：

```
[donnie@localhost rules]$ sudo cp 30-pci-dss-v31.rules /etc/audit/rules.d
[donnie@localhost rules]$
```

然后，重新启动 auditd 守护程序以读取新规则。

对于 Red Hat 或 CentOS：

```
sudo service auditd restart
```

对于 Ubuntu：

```
sudo systemctl restart auditd
```

当然，总会有可能某个规则集中的特定规则对你不起作用，或者你可能需要启用当前禁用的规则。如果是这样，只需在文本编辑器中打开规则文件，注释掉不起作用的部分，或取消注释你需要启用的部分。

尽管 auditd 非常酷，但请记住它只会警告你可能存在的安全漏洞。它不会采取任何措施来加固系统。

这基本上就是我们对 auditd 系统的讨论。试一试，看看你的想法如何。

# 使用 oscap 应用 OpenSCAP 策略

SCAP，即**安全内容自动化协议**（**SCAP**），是由美国国家标准与技术研究所创建的。它包括用于设置安全系统的加固指南、加固模板和基线配置指南。OpenSCAP 是一套免费开源软件工具，可用于实施 SCAP。它包括以下内容：

+   可以应用于系统的安全配置文件。有不同的配置文件，满足几个不同认证机构的要求。

+   安全指南，帮助你进行系统的初始设置。

+   `oscap`命令行实用程序用于应用安全模板。

+   在具有桌面界面的 Red Hat 类型系统上，你可以使用 SCAP Workbench，这是一种图形界面实用程序。

你可以在 Red Hat 或 Ubuntu 发行版上安装 OpenSCAP，但在 Red Hat 发行版上实现得更好。首先，Red Hat 世界拥有非常酷的 SCAP Workbench，而 Ubuntu 世界没有。当你安装 Red Hat 类型的操作系统时，可以选择在安装过程中应用 SCAP 配置文件。在 Ubuntu 上无法这样做。最后，Red Hat 发行版配备了一套相当完整的可供使用的配置文件。耐人寻味的是，Ubuntu 只配备了用于较旧版本的 Fedora 和 Red Hat 的配置文件，这些配置文件在 Ubuntu 系统上无法使用。如果你想要 Ubuntu 可用的配置文件，你需要从 OpenSCAP 网站下载并手动安装它们。（我们将在本章的最后一节中介绍这一点。）话虽如此，让我们看看如何安装 OpenSCAP 以及如何使用两种发行版都通用的命令行实用程序。由于 CentOS 具有更完整的实现，我将在演示中使用它。

# 安装 OpenSCAP

在你的 CentOS 机器上，假设你在操作系统安装过程中没有安装 OpenSCAP，按照以下步骤进行：

```
sudo yum install openscap-scanner scap-security-guide
```

在 Ubuntu 机器上，执行以下操作：

```
sudo apt install python-openscap
```

# 查看配置文件

在 CentOS 机器上，你会在`/usr/share/xml/scap/ssg/content/`目录中看到配置文件。在 Ubuntu 机器上，你会在`/usr/share/openscap/`目录中看到少量的配置文件。配置文件是`.xml`格式的，每个文件包含一个或多个可以应用到系统上的配置文件：

```
[donnie@localhost content]$ pwd
/usr/share/xml/scap/ssg/content
[donnie@localhost content]$ ls -l
total 50596
-rw-r--r--. 1 root root  6734643 Oct 19 19:40 ssg-centos6-ds.xml
-rw-r--r--. 1 root root  1596043 Oct 19 19:40 ssg-centos6-xccdf.xml
-rw-r--r--. 1 root root 11839886 Oct 19 19:41 ssg-centos7-ds.xml
-rw-r--r--. 1 root root  2636971 Oct 19 19:40 ssg-centos7-xccdf.xml
-rw-r--r--. 1 root root      642 Oct 19 19:40 ssg-firefox-cpe-dictionary.xml
. . .
. . .
-rw-r--r--. 1 root root 11961196 Oct 19 19:41 ssg-rhel7-ds.xml
-rw-r--r--. 1 root root   851069 Oct 19 19:40 ssg-rhel7-ocil.xml
-rw-r--r--. 1 root root  2096046 Oct 19 19:40 ssg-rhel7-oval.xml
-rw-r--r--. 1 root root  2863621 Oct 19 19:40 ssg-rhel7-xccdf.xml
[donnie@localhost content]$
```

用于处理 OpenSCAP 的命令行实用程序是`oscap`。我们可以使用`info`开关来查看任何配置文件的信息。让我们看看`ssg-centos7-xccdf.xml`文件：

```
[donnie@localhost content]$ sudo oscap info ssg-centos7-xccdf.xml
Document type: XCCDF Checklist
Checklist version: 1.1
Imported: 2017-10-19T19:40:43
Status: draft
Generated: 2017-10-19
Resolved: true
Profiles:
 standard
 pci-dss
 C2S
 rht-ccp
 common
 stig-rhel7-disa
 stig-rhevh-upstream
 ospp-rhel7
 cjis-rhel7-server
 docker-host
 nist-800-171-cui
Referenced check files:
 ssg-rhel7-oval.xml
 system: http://oval.mitre.org/XMLSchema/oval-definitions-5
 ssg-rhel7-ocil.xml
 system: http://scap.nist.gov/schema/ocil/2
 https://www.redhat.com/security/data/oval/com.redhat.rhsa-RHEL7.xml.bz2
 system: http://oval.mitre.org/XMLSchema/oval-definitions-5
[donnie@localhost content]$
```

我们可以看到这个文件包含了 11 个不同的配置文件，我们可以应用到系统上。其中，你可以看到`stig`和`pci-dss`的配置文件，就像我们为审计规则所做的那样。而且，如果你正在运行 Docker 容器，`docker-host`配置文件将非常方便。

# 扫描系统

现在，假设我们需要确保我们的系统符合支付卡行业标准。我们首先要扫描 CentOS 机器，看看需要什么样的补救措施。（请注意，以下命令非常长，在打印页面上换行了。）

```
sudo oscap xccdf eval --profile pci-dss --results scan-xccdf-results.xml /usr/share/xml/scap/ssg/content/ssg-centos7-xccdf.xml
```

正如我们一直喜欢做的那样，让我们来分解一下：

+   `xccdf eval`：可扩展配置清单描述是我们可以编写安全配置规则的语言之一。我们将使用这种语言编写的配置文件来对系统进行评估。

+   `--profile pci-dss`：在这里，我指定我要使用支付卡行业数据安全标准配置文件来评估系统。

+   `--results scan-xccdf-results.xml`：我将把扫描结果保存到这个`.xml`格式的文件中。扫描完成后，我将从这个文件中创建报告。

+   `/usr/share/xml/scap/ssg/content/ssg-centos7-xccdf.xml`：这个文件包含了`pci-dss`配置文件。

随着扫描的进行，输出将发送到屏幕以及指定的输出文件。这是一个很长的列表，所以我只会给你展示其中的一些：

```
    Ensure Red Hat GPG Key Installed
    ensure_redhat_gpgkey_installed
    pass

    Ensure gpgcheck Enabled In Main Yum Configuration
    ensure_gpgcheck_globally_activated
    pass

    Ensure gpgcheck Enabled For All Yum Package Repositories
    ensure_gpgcheck_never_disabled
    pass

    Ensure Software Patches Installed
    security_patches_up_to_date
    notchecked

   . . .
   . . .

    Install AIDE
    package_aide_installed
    fail

    Build and Test AIDE Database
    aide_build_database
    fail
. . .
. . .
```

所以，我们安装了 GPG 加密，这很好。但是，我们没有安装 AIDE 入侵检测系统，这是一个坏事。

现在我已经运行了扫描并创建了一个包含结果的输出文件，我可以制作我的报告了：

```
sudo oscap xccdf generate report scan-xccdf-results.xml > scan-xccdf-results.html
```

这会从`.xml`格式文件中提取信息，这些文件不是为人类阅读而设计的，并将其转移到一个`.html`文件中，你可以在 Web 浏览器中打开。（记录上，报告显示有 20 个问题需要解决。）

# 系统的补救措施

所以，我们有 20 个问题需要解决，才能使我们的系统符合支付卡行业标准。让我们看看`oscap`能为我们解决多少个问题：

```
sudo oscap xccdf eval --remediate --profile pci-dss --results scan-xccdf-remediate-results.xml /usr/share/xml/scap/ssg/content/ssg-centos7-xccdf.xml
```

这是我用来执行初始扫描的相同命令，只是我添加了`--remediate`选项，并将结果保存到不同的文件中。当你运行这个命令时，你需要有点耐心，因为修复一些问题涉及下载和安装软件包。事实上，就在我打字的时候，`oscap`正在忙着下载和安装缺失的 AIDE 入侵检测系统包。

好的，补救措施仍在进行中，但我仍然可以向你展示一些已经修复的问题：

```
    Disable Prelinking
    disable_prelink
    error

    Install AIDE
    package_aide_installed
    fixed

    Build and Test AIDE Database
    aide_build_database
    fixed

    Configure Periodic Execution of AIDE
    aide_periodic_cron_checking
    fixed

    Verify and Correct File Permissions with RPM
    rpm_verify_permissions
    error

    Prevent Log In to Accounts With Empty Password
    no_empty_passwords
    fixed
. . .
. . .
```

由于`oscap`无法修复的一些问题，会出现一些错误，但这是正常的。至少你知道了这些问题，这样你就可以尝试自己修复它们。

还有，看看这个。你还记得在第二章中，*保护用户账户*，我让你跳过一些步骤，以确保用户拥有定期过期的强密码吗？通过应用这个 OpenSCAP 配置文件，所有这些问题都会自动解决：

```
    Set Password Maximum Age
    accounts_maximum_age_login_defs
    fixed

    Set Account Expiration Following Inactivity
    account_disable_post_pw_expiration
    fixed

    Set Password Strength Minimum Digit Characters
    accounts_password_pam_dcredit
    fixed

    Set Password Minimum Length
    accounts_password_pam_minlen
    fixed

    Set Password Strength Minimum Uppercase Characters
    accounts_password_pam_ucredit
    fixed

    Set Password Strength Minimum Lowercase Characters
    accounts_password_pam_lcredit
    fixed

    Set Deny For Failed Password Attempts
    accounts_passwords_pam_faillock_deny
    fixed

    Set Lockout Time For Failed Password Attempts
    accounts_passwords_pam_faillock_unlock_time
    fixed

    Limit Password Reuse
    accounts_password_pam_unix_remember
    fixed
```

所以，OpenSCAP 非常酷，即使命令行工具也不难使用。

# 使用 SCAP Workbench

对于安装了桌面环境的 Red Hat 和 CentOS 机器，我们有 SCAP Workbench。然而，如果你上次使用 SCAP Workbench 是在 Red Hat/CentOS 7.0 或 Red Hat/CentOS 7.1 上，你可能会感到非常失望。事实上，早期版本的 Workbench 是如此糟糕，以至于根本无法使用。幸运的是，随着 Red Hat 7.2 和 CentOS 7.2 的推出，情况得到了很大改善。现在，Workbench 是一个非常好用的小工具。

要在你的 CentOS 机器上安装它，只需使用以下代码：

```
sudo yum install scap-workbench
```

是的，包名只是`scap-workbench`，而不是`openscap-workbench`。我不知道为什么，但我知道如果你搜索`openscap`包，你永远也找不到它。

安装完成后，你会在“系统工具”菜单下看到它的菜单项。

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sec-hdn/img/26aaca25-75db-4280-974f-2a44a9db0dca.png)

当你第一次打开程序时，你可能会认为系统会要求你输入 root 或 sudo 密码。但是，它没有。我们马上就会看到这是否会影响我们。

在打开屏幕上你会看到一个下拉列表，让你选择要加载的内容类型。我会选择 CentOS7，然后点击“加载内容”按钮：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sec-hdn/img/3459006f-dc60-4e4b-b27c-ba2e94233104.png)

接下来，你会在顶部面板看到可以选择所需配置文件的地方。你还可以选择自定义配置文件，以及是否要在本地机器上或远程机器上运行扫描。在底部面板上，你会看到该配置文件的规则列表。你可以展开每个规则项以获取该规则的描述：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sec-hdn/img/abfefe14-1610-4ffe-b02a-9167e174e0a5.png)

现在，让我们点击“扫描”按钮看看会发生什么：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sec-hdn/img/24d3c1d1-303e-481e-a3f0-ab80761c44ff.png)

很好。正如我所希望的那样，它会提示你输入 sudo 密码。除此之外，我会让你自己去尝试。这只是另一个 GUI 工具，所以剩下的应该很容易弄清楚。

# 关于 OpenSCAP 配置文件的更多信息

所以现在你可能会说，“好吧，这都很好，但我怎么找出这些配置文件中有什么，我需要哪一个呢？”好吧，有几种方法。

第一种方法，我刚刚向你展示的，是在安装了桌面界面的机器上安装 SCAP Workbench，并阅读每个配置文件的所有规则的描述。

第二种方法可能更容易一些，就是去 OpenSCAP 网站查看他们那里的文档。

你可以在[`www.open-scap.org/security-policies/choosing-policy/`](https://www.open-scap.org/security-policies/choosing-policy/)找到有关可用 OpenSCAP 配置文件的信息。

就选择哪个配置文件而言，有几件事情需要考虑：

+   如果你在金融领域工作，或者在从事在线金融交易的企业工作，那么选择`pci-dss`配置文件。

+   如果你在政府机构工作，尤其是美国政府，那么根据特定机构的要求，选择`stig`配置文件或`nispom`配置文件。

+   如果这两种情况都不适用于你的情况，那么你只需要进行一些研究和规划，以找出真正需要被锁定的内容。浏览每个配置文件中的规则，并阅读 OpenSCAP 网站上的文档，以帮助决定你需要什么。

你接下来会想，“那 Ubuntu 呢？我们已经知道 Ubuntu 附带的配置文件是无用的，因为它们是为 RHEL 和 Fedora 设计的。”这是真的，但你会在 OpenSCAP 网站上找到各种不同发行版的配置文件，包括 Ubuntu 的长期支持版本：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sec-hdn/img/eb3ec2e6-131d-444a-aea6-1924176405a7.png)

# 在系统安装过程中应用 OpenSCAP 配置文件

我喜欢 Red Hat 的人的一点是，他们完全懂得这个安全问题。是的，我们可以锁定其他发行版并使它们更安全，就像我们已经看到的那样。但是，对于 Red Hat 发行版来说，这要容易一些。对于很多事情，Red Hat 类型的发行版的维护者已经设置了安全的默认选项，而其他发行版上并没有被安全设置。（例如，Red Hat 发行版是唯一默认锁定用户家目录的发行版。）对于其他事情，Red Hat 类型的发行版提供了工具和安装选项，帮助那些忙碌、注重安全的管理员更轻松地工作。

当你安装 Red Hat 7 类型的发行版时，在操作系统安装过程中，你将有机会应用 OpenSCAP 配置文件。在这个 CentOS 7 安装程序屏幕上，你可以在右下角看到选择安全配置文件的选项：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sec-hdn/img/4ef9ba2c-943b-4540-bc12-8be66cddc9b3.png)

你所需要做的就是点击那个，然后选择你的配置文件：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sec-hdn/img/e4ccb457-c84a-4702-acd2-93e90b799d51.png)

好的，我们关于 OpenSCAP 的讨论基本上就到这里了。唯一剩下的要补充的是，尽管 OpenSCAP 很棒，但它并不能做到一切。例如，一些安全标准要求你必须有特定的目录，比如`/home/`或`/var/`，在它们自己独立的分区上。OpenSCAP 扫描会提醒你如果情况不是这样，但它不能改变你现有的分区方案。所以对于这样的事情，你需要从规定你安全要求的管理机构那里得到一个清单，并在甚至触及 OpenSCAP 之前做一些高级工作。

# 摘要

在本章中，我们涵盖了很多内容，看到了一些非常酷的东西。我们首先看了一些防病毒扫描器，这样我们就可以防止任何访问我们的 Linux 服务器的 Windows 机器感染。在 Rootkit Hunter 部分，我们看到了如何扫描这些讨厌的 rootkit。了解如何审计系统非常重要，特别是在高安全环境中，我们看到了如何做到这一点。最后，我们讨论了如何使用 OpenSCAP 加固我们的系统。

在下一章中，我们将看一下漏洞扫描和入侵检测。到时候见。


# 第九章：漏洞扫描和入侵检测

有很多威胁存在，其中一些甚至可能渗入您的网络。您会想知道发生了什么，因此您需要一个良好的**网络入侵检测系统**（**NIDS**）。我们将看看 Snort，这可能是最著名的一个。然后我会向您展示一种快速设置 Snort 系统的方法。

我们已经看到了如何通过在要扫描的机器上安装扫描工具来扫描病毒和 rootkit。但是，还有很多漏洞可以进行扫描，我会向您展示一些很酷的工具可以用于此。

本章涵盖以下主题：

+   介绍 Snort 和 Security Onion

+   使用 Lynis 进行扫描和加固

+   使用 OpenVAS 查找漏洞

+   使用 Nikto 进行 Web 服务器扫描

# 查看 Snort 和 Security Onion

Snort 是一个 NIDS，是作为免费开源软件产品提供的。程序本身是免费的，但如果您想拥有完整的、最新的威胁检测规则集，就需要付费。Snort 最初是一个单人项目，但现在由思科公司拥有。但要明白，这不是您要保护的机器上安装的东西。相反，您至少需要一个专用的 Snort 机器在网络的某个地方，只是监视所有网络流量，观察异常情况。当它看到不应该出现的流量时——例如表明存在机器人的流量——它可以向管理员发送警报消息，甚至可以根据规则的配置阻止异常流量。对于小型网络，您可以只有一个 Snort 机器，既作为控制台又作为传感器。对于大型网络，您可以设置一个 Snort 机器作为控制台，并让它接收其他作为传感器设置的 Snort 机器的报告。

Snort 并不难处理，但是从头开始设置完整的 Snort 解决方案可能有点繁琐。在我们了解了 Snort 的基本用法之后，我将向您展示如何通过设置预构建的 Snort 设备大大简化事情。

空间不允许我提供有关 Snort 的全面教程。相反，我将提供一个高层次的概述，然后向您提供其他学习 Snort 的资源。

# 获取和安装 Snort

Snort 不在任何 Linux 发行版的官方软件库中，因此您需要从 Snort 网站获取。在他们的下载页面上，您将看到 Fedora 和 CentOS 的`.rpm`格式的安装程序文件，以及 Windows 的`.exe`安装程序文件。但是，您在 Ubuntu 上看不到任何`.deb`安装程序文件。没关系，因为他们还提供源代码文件，您可以在各种不同的 Linux 发行版上编译。为了简化事情，让我们只谈谈在 CentOS 7 上安装 Snort 与预构建的`.rpm`软件包。

您可以从官方 Snort 网站获取 Snort 和 Snort 培训：[`www.snort.org`](https://www.snort.org)。

在 Snort 主页上，只需向下滚动一点，你就会看到如何下载和安装 Snort 的指南。点击 Centos 选项卡并按照步骤操作。第 1 步中的命令将下载并安装 Snort，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sec-hdn/img/825be8a6-1bc3-417e-a31d-defb1636a75b.png)

第 2 步和第 3 步涉及注册 Oinkcode，以便您可以下载官方的 Snort 检测规则，然后安装 PulledPork，以便您可以自动更新规则，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sec-hdn/img/9fcc95e1-cce7-43fc-b61f-b394926a815a.png)

请记住，Snort 提供的免费检测规则大约比付费订阅者获得的规则晚一个月。但是，就学习目的而言，它们就是您所需要的一切。此外，如果您选择不获取 Oinkcode，您可以使用社区规则，这是官方 Snort 规则的一个子集。

第 4 步只是阅读文档：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sec-hdn/img/34f8d630-e4e3-48ad-aa40-e1ce33afa131.png)

就是这样。您现在拥有一个可用的 Snort 副本。唯一的问题是，到目前为止，您只有命令行界面，这可能不是您想要的。

# Snort 的图形界面

普通的、未装饰的 Snort 将做您需要它做的事情，并将其发现保存到其自己的一组日志文件中。但是，阅读日志文件以辨别网络流量趋势可能会有点乏味，因此您需要一些工具来帮助您。最好的工具是图形工具，它们可以为您提供对网络情况的良好可视化。

一个例子是**基本分析和安全引擎**（**BASE**），如下截图所示：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sec-hdn/img/a1273047-f170-4c8e-9822-259d9a0dcc7e.png)

还有几个，但我会在我们到达* Security Onion *部分时向您展示它们。

您可以从作者的* Professionally Evil *网站了解有关 BASE 的更多信息：[`professionallyevil.com/`](https://professionallyevil.com/)

# 获取预构建的 Snort 设备

设置 Snort 本身并不是太难。但是，如果您一切都是手动操作，那么在设置控制台、传感器和您选择的图形前端之后，可能会有点乏味。因此——想象一下，当我戴着墨镜凝视着您说这些话时——如果我告诉您，您可以将 Snort 设置为即插即用设备的一部分呢？如果我告诉您，设置这样的设备绝对是轻而易举的呢？我想您可能会说，“那就给我看看吧！”

如果您因使 Snort 部署变得如此简单而感到内疚，那么实际上没有必要。一位 Snort 官方代表曾经告诉我，大多数人都以这种方式部署 Snort。

由于 Snort 是一个**自由开源软件**（**FOSS**）项目，因此人们将其构建到自己的 FOSS 应用程序中是完全合法的。此外，如果您回想一下我们在第三章中对防火墙的讨论，*使用防火墙保护服务器*，我完全忽略了创建**网络地址转换**（**NAT**）规则的讨论，这是您设置边缘或网关类型防火墙所需的。这是因为有几个 Linux 发行版专门为此目的而创建。如果我告诉您，其中一些还包括 Snort 的完整实现呢？

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sec-hdn/img/470e2fe5-231d-49e4-81b3-1982a6cbc381.png)

IPFire 完全免费，只需几分钟即可设置。您可以将其安装在至少具有两个网络接口适配器的计算机上，并将其配置为与您的网络配置相匹配。这是一种代理类型的防火墙，这意味着除了进行正常的防火墙类型的数据包检查外，它还包括缓存、内容过滤和 NAT 功能。您可以以多种不同的配置设置 IPFire：

+   在具有两个网络接口适配器的计算机上，您可以将一个连接到互联网，另一个连接到内部局域网。

+   使用三个网络适配器，您可以将一个连接到互联网，一个连接到内部局域网，一个连接到**非军事区**（**DMZ**），在那里您有面向互联网的服务器。

+   通过第四个网络适配器，您可以拥有上述所有内容，以及对无线网络的保护。

安装 IPFire 后，您需要使用普通工作站的 Web 浏览器导航到 IPFire 仪表板。在 Services 菜单下，您会看到入侵检测的条目。单击该条目即可进入此屏幕，您可以在此屏幕上下载并启用 Snort 检测规则：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sec-hdn/img/deb79b23-a4a1-43b1-83b1-b622c99c61be.png)

实际上，您可能只需要从命令行进行一点微调。也就是说，您可能需要进入规则目录，并确保您要启用的规则已启用。在我的演示机器上，我安装了社区规则和新兴威胁规则：

```
[root@ipfire rules]# ls -l
total 19336
-rw-r--r-- 1 nobody nobody    1656 Dec 19 06:01 BSD-License.txt
-rw-r--r-- 1 nobody nobody    2638 Dec 19 06:01 classification.config
-rw-r--r-- 1 nobody nobody 1478085 Dec 19 06:01 community.rules
-rw-r--r-- 1 nobody nobody   15700 Dec 19 06:01 compromised-ips.txt
-rw-r--r-- 1 nobody nobody  378690 Dec 19 06:01 emerging-activex.rules
-rw-r--r-- 1 nobody nobody   79832 Dec 19 06:01 emerging-attack_response.rules
-rw-r--r-- 1 nobody nobody   82862 Dec 19 06:01 emerging-botcc.portgrouped.rules
-rw-r--r-- 1 nobody nobody  249176 Dec 19 06:01 emerging-botcc.rules
-rw-r--r-- 1 nobody nobody   34658 Dec 19 06:01 emerging-chat.rules
. . .
. . .
-rw-r--r-- 1 nobody nobody    1375 Dec 19 06:01 reference.config
-rw-r--r-- 1 nobody nobody 3691529 Dec 19 06:01 sid-msg.map
-rw-r--r-- 1 nobody nobody       0 Dec 19 06:01 snort-2.9.0-enhanced-open.txt
-rw-r--r-- 1 nobody nobody   53709 Dec 19 06:01 unicode.map
-rw-r--r-- 1 nobody nobody   21078 Dec 19 04:46 VRT-License.txt
[root@ipfire rules]#
```

当您首次安装 IPFire 时，它设置的唯一用户帐户是 root 用户。但是，有工具可以创建普通用户帐户并赋予其`sudo`权限。我还没有在这台机器上做这个操作，因为我想向您展示默认配置。但是，在生产机器上我肯定会这样做。然后我会禁用 root 帐户。

当您打开这些规则文件时，您会发现其中许多规则是禁用的，而相对较少的是启用的。禁用的规则前面有一个`#`号，就像`community.rules`文件中的这两个规则一样：

```
#alert tcp $HOME_NET 2589 -> $EXTERNAL_NET any (msg:"MALWARE-BACKDOOR - Dagger_1.4.0"; flow:to_client,established; content:"2|00 00 00 06 00 00 00|Drives|24 00|"; depth:16; metadata:ruleset community; classtype:misc-activity; sid:105; rev:14;)
#alert tcp $EXTERNAL_NET any -> $HOME_NET 7597 (msg:"MALWARE-BACKDOOR QAZ Worm Client Login access"; flow:to_server,established; content:"qazwsx.hsq"; metadata:ruleset community; reference:mcafee,98775; classtype:misc-activity; sid:108; rev:11;)
```

您可能还注意到每个规则都以关键字`alert`开头。您可以使用`grep`快速检查文件中启用的规则：

```
[root@ipfire rules]# grep ^alert community.rules | less
[root@ipfire rules]#
```

`^`字符表示我正在`community.rules`文件中搜索以单词`alert`开头的每一行，而不带前面的`#`号。将输出导入`less`是可选的，但它可以帮助您更好地查看所有输出数据。您还可以使用通配符一次搜索所有文件：

```
[root@ipfire rules]# grep ^alert *.rules | less
[root@ipfire rules]#
```

您需要查看规则以确定您需要哪些规则，哪些规则不需要。通过删除规则前面的`#`号来启用所需的规则，并通过在规则前面放置`#`号来禁用不需要的规则。

不幸的是，IPFire 不包括用于可视化 Snort 数据的图形前端，但它确实带有 IDS 日志查看器：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sec-hdn/img/17a98e3e-7965-4498-ba9b-73dfe68fe310.png)

IPFire 还有许多其他很酷的功能，我还没有提到。这些功能包括内置的**虚拟专用网络**（**VPN**）功能，内置的 DHCP 服务器，内置的动态 DNS 服务器和服务质量控制。最好的部分是它是完全免费的，除非您想购买订阅以始终获得最新的 Snort 规则。

您可以从他们的网站下载 IPFire：[`www.ipfire.org/.`](https://www.ipfire.org/)

# 使用 Security Onion

好吧，也许带有内置 Snort 的防火墙设备现在不是您需要的。也许您需要的是一个完整的 NIDS。但是，您是一个忙碌的人，需要快速简便的东西，而且您的老板对您的预算要求相当严格。那么，您该怎么办呢？

Security Onion 是一个免费的专业 Linux 发行版，构建在 Xubuntu **长期支持**（**LTS**）发行版之上。它包括完整的 Snort 实现，几乎包括您可以想象的所有图形功能，以帮助您可视化网络上发生的情况。如果您可以安装 Linux 发行版并在安装后进行一些点对点的配置，那么您就可以安装 Security Onion。

请注意，Security Onion 所基于的 Xubuntu LTS 版本始终至少落后于当前 Xubuntu LTS 版本。在撰写本文时，当前的 Xubuntu LTS 版本是版本 16.04，而 Security Onion 仍然基于 Xubuntu 14.04。但是，这可能会在您阅读本书时发生变化。

此外，如果您想尝试 Security Onion，您可以在 VirtualBox 虚拟机中设置它。创建虚拟机时，将其设置为两个网络适配器，都处于*Bridged*模式。为了获得最佳性能，至少分配 3GB 内存。

安装完操作系统后，配置只是简单地双击设置图标，然后按照对话框进行操作：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sec-hdn/img/bd8cdbf0-8157-4d55-ae8f-cbc2add30f1b.jpg)

要设置具有传感器功能的机器，您需要一台具有两个接口卡的机器。一个接口将分配 IP 地址，将成为管理接口：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sec-hdn/img/61604ee1-7bbd-49a6-988f-df84287ec385.jpg)

您可以将管理界面设置为通过 DHCP 自动获取 IP 地址，但最好分配一个静态 IP 地址：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sec-hdn/img/ec1ad2ee-0f10-4ee3-9aed-cad2f089aa00.jpg)

您将使用另一个网络适配器作为嗅探接口。您不会为其分配 IP 地址，因为您希望该接口对坏人不可见：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sec-hdn/img/793d112c-1fbc-4e40-9d48-4f99d4ead81a.jpg)

确认您选择的网络配置后，重新启动机器：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sec-hdn/img/896c92b3-90aa-4dd4-bc84-d47f13d78311.jpg)

机器重新启动后，再次双击设置图标，但这次选择跳过网络配置。对于第一次使用 Security Onion 的用户来说，评估模式非常有帮助，因为它会自动选择大多数东西的最正确选项。

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sec-hdn/img/f669c960-bbe3-4221-9f3d-ec3984739106.jpg)

从现在开始，只需确认哪个网络接口将成为嗅探接口，并填写不同图形界面的登录凭据。然后，在等待设置实用程序下载 Snort 规则并执行最后的配置步骤后，您将拥有自己的操作 NIDS。现在我问，还有什么比这更容易的呢？

Security Onion 配备了几种不同的图形界面。我最喜欢的是 Squert，如图所示。即使只有默认的检测规则，我已经看到了一些有趣的东西。以下截图显示了 Squert：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sec-hdn/img/80bc54f7-f1df-40c7-ad84-de2f28b8c732.jpg)

首先，我看到网络上有人在挖掘一些 Monero 加密货币。好吧，实际上，我就是在挖，所以没关系。但是，能够检测到这一点是件好事，因为众所周知，坏人曾经在企业服务器上种植 Monero 挖矿软件以谋取私利。Monero 加密货币挖矿会给服务器的 CPU 带来很大负载，所以这不是你想要的服务器上的东西。此外，一些狡猾的网站运营商在其网页上放置了 JavaScript 代码，导致任何访问它们的计算机都开始挖掘 Monero。因此，这条规则也有助于保护桌面系统。

我还看到 Dropbox 客户端正在广播，这也没关系，因为我是 Dropbox 用户。但是，这也是您可能不希望在企业网络上拥有的东西。

要查看与特定项目相关联的 Snort 规则，只需单击该项目：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sec-hdn/img/aa806acb-0fd3-4099-bf35-8feaed3a9b83.jpg)

这只是一个已经为我们设置好的标准 Snort 规则。

想要挖掘 Monero 而不付费的坏人已经建立了被感染其挖矿软件的机器的僵尸网络。在一些攻击中，只有 Windows 服务器被感染。但是，这里有一个情况，Windows 和 Linux 服务器都被感染了：

[`www.v3.co.uk/v3-uk/news/3023348/cyber-crooks-conducting-sophisticated-malware-campaign-to-mine-monero`](https://www.v3.co.uk/v3-uk/news/3023348/cyber-crooks-conducting-sophisticated-malware-campaign-to-mine-monero)

单击 Squert 的“视图”选项卡，您将看到您的机器建立的连接的图形表示：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sec-hdn/img/54090a04-67d2-403b-a088-26bd25236c1e.jpg)

关于 Security Onion 和 Snort，我还可以向您展示更多，但是，空间不允许。我已经给了您要领，现在去尝试一下吧。

我知道我让 Snort/Security Onion 看起来相当简单，但实际上比我能向您展示的要复杂得多。在大型网络上，您可能会看到很多看起来毫无意义的流量，除非您知道如何解释 Snort 向您呈现的信息。您可能还需要微调您的 Snort 规则，以便看到您想要看到的异常情况，而不会产生错误的警报。或者，您甚至可能需要编写自己的自定义 Snort 规则来处理异常情况。幸运的是，Security Onion 团队提供培训，包括现场和在线培训。您可以在以下网站了解更多信息：

[`securityonionsolutions.com/.`](https://securityonionsolutions.com/)

# 使用 Lynis 进行扫描和加固

Lynis 是另一个可以用来扫描系统漏洞和不良安全配置的自由开源软件工具。它是一个便携式 shell 脚本，不仅可以在 Linux 上使用，还可以在各种不同的 Unix 系统和类 Unix 系统上使用。它是一个多用途工具，您可以用它进行合规性审计、漏洞扫描或加固。与大多数漏洞扫描工具不同，您需要在要扫描的系统上安装和运行 Lynis。根据 Lynis 的创建者，这样可以进行更深入的扫描。

Lynis 扫描工具有免费版本，但其扫描能力有限。如果您需要 Lynis 提供的所有功能，您需要购买企业许可证。

# 在 Red Hat/CentOS 上安装 Lynis

Red Hat/CentOS 用户将在 EPEL 存储库中找到最新版本的 Lynis。因此，如果您已安装了 EPEL，就像我在第一章中向您展示的那样，*在虚拟环境上运行 Linux*，安装只是一个简单的事情：

```
sudo yum install lynis
```

# 在 Ubuntu 上安装 Lynis

Ubuntu 在其自己的存储库中有 Lynis，但您获得的版本取决于您使用的 Ubuntu 版本。Ubuntu 16.04 LTS 存储库中的版本相对较旧。Ubuntu 17.10 存储库中的版本更新一些，但仍不完全是最新的。在任何情况下，安装 Lynis 的命令是：

```
sudo apt install lynis
```

如果您想要 Ubuntu 的最新版本，或者想要在没有 Lynis 的存储库中使用 Lynis 的操作系统上使用它，您可以从作者的网站上下载。

您可以从[`cisofy.com/downloads/lynis/.`](https://cisofy.com/downloads/lynis/)下载 Lynis。这个很酷的地方是，一旦您下载了它，您可以在任何 Linux、Unix 或类 Unix 操作系统上使用它。（这甚至包括 MacOS，我刚刚通过在运行 macOS High Sierra 的旧 Mac Pro 上运行它来确认。）[](https://cisofy.com/downloads/lynis/)

由于可执行文件只是一个普通的 shell 脚本，因此无需执行实际安装。您只需要解压缩存档文件，`cd`进入生成的目录，并从那里运行 Lynis：

```
tar xzvf lynis-2.5.7.tar.gz
cd lynis
sudo ./lynis -h
```

`lynis -h`命令显示帮助屏幕，其中包含您需要了解的所有 Lynis 命令。

# 使用 Lynis 进行扫描

无论您要扫描哪个操作系统，Lynis 命令都是相同的。唯一的区别是，如果您从网站下载的存档文件中运行它，您将`cd`进入`lynis`目录，并在`lynis`命令之前加上`./`。（这是因为出于安全原因，您自己的主目录不在允许 shell 自动查找可执行文件的路径设置中。）

要扫描已安装 Lynis 的系统，请按照以下步骤进行：

```
sudo lynis audit system
```

要扫描刚刚下载存档文件的系统，请按照以下步骤进行：

```
cd lynis
sudo ./lynis audit system
```

从您的主目录中的 shell 脚本运行 Lynis 会显示以下消息：

```
donnie@ubuntu:~/lynis$ sudo ./lynis audit system
[sudo] password for donnie:

[!] Change ownership of /home/donnie/lynis/include/functions to 'root' or similar (found: donnie with UID 1000).

 Command:
 # chown 0:0 /home/donnie/lynis/include/functions

[X] Security check failed

 Why do I see this error?
 -------------------------------
 This is a protection mechanism to prevent the root user from executing user created files. The files may be altered, or including malicious pieces of script.

 What can I do?
 ---------------------
 Option 1) Check if a trusted user created the files (e.g. due to using Git, Homebrew or similar).
 If you trust these files, you can decide to continue this run by pressing ENTER.

 Option 2) Change ownership of the related files (or full directory).

 Commands (full directory):
 # cd ..
 # chown -R 0:0 lynis
 # cd lynis
 # ./lynis audit system

[ Press ENTER to continue, or CTRL+C to cancel ]
```

这不会造成任何损害，所以你可以按*Enter*继续。或者，如果看到这条消息真的让你烦恼，你可以按照消息告诉你的那样，将 Lynis 文件的所有权更改为 root 用户。现在，我只是按下*Enter*。

以这种方式运行 Lynis 扫描类似于运行 OpenSCAP 扫描以符合通用安全配置文件。主要区别在于 OpenSCAP 具有自动修复功能，而 Lynis 没有。Lynis 告诉你它发现了什么，并建议如何修复它认为是问题的东西，但它不会为你修复任何东西。

空间不允许我展示整个扫描输出，但我可以给你展示一些示例片段：

```
[+] Boot and services
------------------------------------
 - Service Manager                                           [ systemd ]
 - Checking UEFI boot                                        [ DISABLED ]
 - Checking presence GRUB                                    [ OK ]
 - Checking presence GRUB2                                   [ FOUND ]
 - Checking for password protection                        [ WARNING ]
 - Check running services (systemctl)                        [ DONE ]
 Result: found 21 running services
 - Check enabled services at boot (systemctl)                [ DONE ]
 Result: found 28 enabled services
 - Check startup files (permissions)                         [ OK ]

```

警告消息显示我没有为我的`GRUB2`引导加载程序设置密码保护。这可能很重要，也可能不重要，因为有人可以利用这一点来获得对机器的物理访问权限。如果这是一个被锁在只有少数信任人员可以访问的房间里的服务器，那么我不会担心，除非适用的监管机构的规定要求我这样做。如果这是一个放在开放式隔间里的台式机，那么我肯定会修复这个问题。（我们将在第十章中看到 GRUB 密码保护，*忙碌蜜蜂的安全提示和技巧*。）

在“文件系统”部分，我们看到一些带有“建议”标志的项目。

```
[+] File systems
------------------------------------
 - Checking mount points
 - Checking /home mount point                              [ SUGGESTION ]
 - Checking /tmp mount point                               [ SUGGESTION ]
 - Checking /var mount point                               [ SUGGESTION ]
 - Query swap partitions (fstab)                             [ OK ]
 - Testing swap partitions                                   [ OK ]
 - Testing /proc mount (hidepid)                             [ SUGGESTION ]
 - Checking for old files in /tmp                            [ OK ]
 - Checking /tmp sticky bit                                  [ OK ]
 - ACL support root file system                              [ ENABLED ]
 - Mount options of /                                        [ NON DEFAULT ]
 - Checking Locate database                                  [ FOUND ]
 - Disable kernel support of some filesystems
 - Discovered kernel modules: cramfs freevxfs hfs hfsplus jffs2 udf
```

正是 Lynis 建议的内容出现在输出的最后：

```
. . .
. . .

 * To decrease the impact of a full /home file system, place /home on a separated partition [FILE-6310]
 https://cisofy.com/controls/FILE-6310/

 * To decrease the impact of a full /tmp file system, place /tmp on a separated partition [FILE-6310]
 https://cisofy.com/controls/FILE-6310/

 * To decrease the impact of a full /var file system, place /var on a separated partition [FILE-6310]
 https://cisofy.com/controls/FILE-6310/
. . .
. . .
```

我们将看看输出的最后一个部分，即扫描详细信息部分：

```
 Lynis security scan details:

 Hardening index : 67 [#############       ]
 Tests performed : 218
 Plugins enabled : 0

 Components:
 - Firewall               [V]
 - Malware scanner        [X]

 Lynis Modules:
 - Compliance Status      [?]
 - Security Audit         [V]
 - Vulnerability Scan     [V]

 Files:
 - Test and debug information      : /var/log/lynis.log
 - Report data                     : /var/log/lynis-report.dat
```

对于“组件”，“恶意软件扫描器”旁边有一个红色的`X`。这是因为我没有在这台机器上安装 ClamAV 或`maldet`，所以 Lynis 无法进行病毒扫描。

对于“Lynis 模块”，我们看到“合规状态”旁边有一个问号。这是因为这个功能是为 Lynis 企业版保留的，需要付费订阅。正如我们在上一章中看到的，你可以使用 OpenSCAP 配置文件使系统符合几种不同的安全标准，而且这不需要花费任何费用。使用 Lynis，你必须为合规配置文件付费，但你可以选择更广泛的范围。除了 OpenSCAP 提供的合规配置文件外，Lynis 还提供了 HIPAA 和萨班斯-奥克斯合规配置文件。

如果你在美国，你肯定知道 HIPAA 和萨班斯-奥克斯是什么，以及它们是否适用于你。如果你不在美国，那么你可能不需要担心它们。

话虽如此，如果你在医疗行业工作，即使你不在美国，HIPAA 配置文件也可以为你提供如何保护患者的私人数据的指导。

关于 Lynis，我想说的最后一件事是关于企业版。在他们网站上的这张截图中，你可以看到当前的定价和不同订阅计划之间的区别：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sec-hdn/img/56958b7d-ddee-4df7-b56b-ad6cfb4b44ee.png)

正如你所看到的，你有选择。

在这个网站上你会找到有关定价的信息：

[`cisofy.com/pricing/.`](https://cisofy.com/pricing/)

这基本上就是我们对 Lynis 的讨论。接下来，让我们看看一个*外部*漏洞扫描器。

# 使用 OpenVAS 查找漏洞

**开放漏洞评估扫描器**（**OpenVAS**）是你用来执行远程漏洞扫描的工具。你可以扫描单台机器、一组相似的机器或整个网络。它不包含在主要 Linux 发行版的软件仓库中，所以最好的方法是安装专门的安全发行版之一来获取它。

三大安全发行版是 Kali Linux、Parrot Linux 和 Black Arch。它们面向安全研究人员和渗透测试人员，但它们包含的工具也适用于 Linux 或 Windows 的普通安全管理员。OpenVAS 就是其中之一。这三个安全发行版都有各自独特的优势和劣势，但由于 Kali 最受欢迎，我们将用它进行演示。

您可以从[`www.kali.org/downloads/.`](https://www.kali.org/downloads/)下载 Kali Linux

当您转到 Kali 下载页面时，您会看到很多选择。如果您像我一样不喜欢默认的 Gnome 3 桌面环境，您可以选择其他内容。我个人是 LXDE 的粉丝，所以我会选择它：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sec-hdn/img/d8022e70-a058-4517-b4b3-8fd1a9c3399f.png)

Kali 是基于 Debian Linux 构建的，因此安装它与安装 Debian 几乎相同。唯一的例外是 Kali 安装程序允许您为 root 用户创建密码，但不允许您创建普通的非 root 用户帐户。这是因为您在 Kali 中几乎所有操作都需要以 root 用户身份登录。我知道这与我一直告诉您的不要以`root`身份登录以及使用`sudo`而不是普通用户帐户登录的建议相悖。但是，您在 Kali 中需要做的大部分工作都无法使用`sudo`完成。此外，Kali 并不是用作通用发行版，只要您按照其预期使用，以 root 身份登录就可以。

OpenVAS 是一个占用内存较多的程序，因此如果您在虚拟机中安装 Kali，请确保至少分配 3GB 的内存。

安装 Kali 后，您需要做的第一件事是更新它，这与更新任何 Debian/Ubuntu 类型的发行版的方式相同。然后，按照以下方式安装 OpenVAS：

```
apt update
apt dist-upgrade
apt install openvas
```

OpenVAS 安装完成后，您需要运行一个脚本，该脚本将创建安全证书并下载漏洞数据库：

```
openvas-setup
```

这将需要很长时间，所以在运行时您可以去拿一个三明治和一杯咖啡。最终完成后，您将看到用于登录 OpenVAS 的密码。记下来并保存在安全的地方：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sec-hdn/img/876e41e9-8657-4e9c-82b4-c2aa404e2281.png)

您可以从应用程序菜单控制和更新 OpenVAS：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sec-hdn/img/94e3fd1a-6ecb-46ef-b233-246cbfe67655.png)

在菜单中，单击 openvas start。然后，打开 Firefox 并导航到`https://localhost:9392`。您会收到一个安全警告，因为 OpenVAS 使用自签名的安全证书，但没关系。只需单击“高级”按钮，然后单击“添加异常”：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sec-hdn/img/c92c5951-0845-4196-b747-e9801c6c1f45.png)

在登录页面，输入`admin`作为用户，然后输入由`openvas-setup`脚本生成的密码。

现在，OpenVAS 有各种花哨的功能，但现在我们只看如何进行基本的漏洞扫描。首先，从 OpenVAS 仪表板的扫描菜单中选择“任务”：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sec-hdn/img/e9e44e34-d33e-4018-b7fd-8144c6ab1dd2.png)

这将弹出对话框，告诉您使用向导。（没错，我们要去见向导。）：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sec-hdn/img/4f032242-2fd2-48b1-be96-38459018f05c.png)

关闭对话框后，您会看到紫色的向导图标出现在左上角。现在，我们只需选择“任务向导”选项，它将为我们选择所有默认的扫描设置：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sec-hdn/img/f10eb08c-d992-4ba7-ba21-c23023f02f14.png)

您需要做的唯一事情是输入要扫描的机器的 IP 地址，然后开始扫描：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sec-hdn/img/010d859c-f0cc-4125-aa11-1790c54a812d.png)

扫描需要一些时间，所以在运行时您可以去拿一个三明治和一杯咖啡。

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sec-hdn/img/fe476525-6d56-4b2d-9d63-a253e287d4d2.png)

你正在进行的扫描类型被称为全面和快速，这不是最全面的扫描类型。要选择另一种扫描类型并配置其他扫描选项，请使用高级任务向导，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sec-hdn/img/7035b467-e60d-4787-9e85-ec9b1d8d3843.png)

在这里，你可以看到不同扫描选项的下拉列表：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sec-hdn/img/fdc8c84f-c9f5-4f31-a1c2-623a0a6b5d1d.png)

当我使用默认的全面和快速选项进行第一次扫描时，我没有发现太多问题。我发现了一个中等严重性和 18 个低严重性的问题，就这些。由于我扫描的机器的年龄，我知道肯定会有更多问题，所以我尝试了全面和快速终极选项。这一次，我发现了更多问题，包括一些高严重性的问题：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sec-hdn/img/90b5493d-aa82-4d16-91fb-e42f1d21bf04.png)

报告显示，我的机器正在使用弱加密算法进行 Secure Shell，这被分类为中等严重性。它还有一个被分类为高严重性问题的打印服务器漏洞。

你还需要注意那些没有标记为漏洞的项目。例如，VNC 安全类型项显示端口`5900`是开放的。这意味着**虚拟网络计算**（VNC）守护程序正在运行，允许用户远程登录到这台机器的桌面。如果这台机器是一个面向互联网的机器，那将是一个真正的问题，因为 VNC 没有像 Secure Shell 那样的真正安全性。

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sec-hdn/img/c4a7abda-7d02-41fb-9170-002fceb1b0a9.png)

点击打印服务器项目，我可以看到对这个漏洞的解释。

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sec-hdn/img/133d19f1-c93a-4aa6-b1eb-9a7970a25ab8.png)

请记住，目标机器在这种情况下是一台台式机。如果它是一台服务器，很可能会出现更多问题。

这基本上就是 OpenVAS 的全部内容了。正如我之前所说，你可以用它做很多很棒的事情。但是，我在这里向你展示的应该足够让你入门了。尝试使用不同的扫描选项来玩耍，看看结果的差异。

如果你想了解更多关于 Kali Linux 的信息，你可以在 Packt Publishing 网站上找到很多关于它的书籍。

# 使用 Nikto 进行 Web 服务器扫描

我们刚刚看到的 OpenVAS 是一个通用的漏洞扫描器。它可以找到任何操作系统或服务器守护程序的漏洞。然而，正如我们刚刚看到的，OpenVAS 扫描可能需要一段时间才能运行，并且可能超出你的需求。

Nikto 是一个专用工具，只有一个目的。也就是说，它的目的是扫描 Web 服务器，只有 Web 服务器。它易于安装，易于使用，并且能够相当快速地对 Web 服务器进行全面扫描。虽然它包含在 Kali Linux 中，但你不需要 Kali Linux 来运行它。

# Kali Linux 中的 Nikto

如果你已经有 Kali Linux，你会发现 nikto 已经安装在漏洞分析菜单下：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sec-hdn/img/2a672fb6-b8ca-4630-8a4e-0b8f75378588.png)

当你点击菜单项时，你会打开一个带有 Nikto 帮助屏幕显示的命令行终端：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sec-hdn/img/df7af3ce-9d87-4c84-b649-d2edaa72ac91.png)

# 在 Linux 上安装和更新 Nikto

Nikto 在 Red Hat/CentOS 的 EPEL 仓库中，而在 Ubuntu 的正常仓库中。除了 Nikto 软件包本身，你还需要安装一个允许 Nikto 扫描设置了 SSL/TLS 加密的 Web 服务器的软件包。

在 Red Hat/CentOS 上安装：

```
sudo yum install nikto perl-Net-SSLeay
```

在 Ubuntu 上安装：

```
sudo apt install nikto libnet-ssleay-perl
```

接下来你需要做的是更新漏洞签名数据库。但是，在撰写本文时，Red Hat/CentOS 实现中存在一个轻微的错误。由于某种原因，`docs`目录丢失，这意味着更新功能将无法下载`CHANGES.txt`文件，以向您展示新数据库更新的变化。要在您的 CentOS 虚拟机上修复这个问题，请使用以下命令：

```
sudo mkdir /usr/share/nikto/docs
```

不过请记住，到你读到这篇文章的时候，这些问题可能已经被修复了。

从现在开始，无论你的虚拟机是哪一个，事情都会一样。要更新漏洞数据库，请使用以下命令：

```
sudo nikto -update
```

Nikto 本身不需要`sudo`权限，但更新它需要，因为它需要写入普通用户无法写入的目录。

# 使用 Nikto 扫描 Web 服务器

从现在开始，你不再需要`sudo`权限。所以，你可以暂时不用输入密码了。

要进行简单的扫描，使用`-h`选项指定目标主机：

```
nikto -h 192.168.0.9
nikto -h www.example.com
```

让我们来看一些示例输出：

```
+ Allowed HTTP Methods: POST, OPTIONS, GET, HEAD
+ OSVDB-396: /_vti_bin/shtml.exe: Attackers may be able to crash FrontPage by requesting a DOS device, like shtml.exe/aux.htm -- a DoS was not attempted.
+ /cgi-bin/guestbook.pl: May allow attackers to execute commands as the web daemon.
+ /cgi-bin/wwwadmin.pl: Administration CGI?
+ /cgi-bin/Count.cgi: This may allow attackers to execute arbitrary commands on the server
+ OSVDB-28260: /_vti_bin/shtml.exe/_vti_rpc?method=server+version%3a4%2e0%2e2%2e2611: Gives info about server settings.
+ OSVDB-3092: /_vti_bin/_vti_aut/author.exe?method=list+documents%3a3%2e0%2e2%2e1706&service%5fname=&listHiddenDocs=true&listExplorerDocs=true&listRecurse=false&listFiles=true&listFolders=true&listLinkInfo=true&listIncludeParent=true&listDerivedT=false&listBorders=fals: We seem to have authoring access to the FrontPage web.
+ OSVDB-250: /wwwboard/passwd.txt: The wwwboard password file is browsable. Change wwwboard to store this file elsewhere, or upgrade to the latest version.
+ OSVDB-3092: /stats/: This might be interesting...
+ OSVDB-3092: /test.html: This might be interesting...
+ OSVDB-3092: /webstats/: This might be interesting...
+ OSVDB-3092: /cgi-bin/wwwboard.pl: This might be interesting...
+ OSVDB-3233: /_vti_bin/shtml.exe/_vti_rpc: FrontPage may be installed.
+ 6545 items checked: 0 error(s) and 15 item(s) reported on remote host
+ End Time:           2017-12-24 10:54:21 (GMT-5) (678 seconds)
```

在顶部，我们看到`vti_bin`目录中有一个`shtml.exe`文件，据说是用于 FrontPage Web 编写程序的。我不知道为什么会有这个文件，考虑到这是一个 Linux 服务器，那是一个 Windows 可执行文件。Nikto 告诉我，通过拥有那个文件，某人可能会对我进行**拒绝服务**（**DOS**）攻击。

接下来，我们看到`/cgi-bin`目录中有各种脚本。你可以从解释性消息中看出这不是一件好事，因为这可能允许攻击者在我的服务器上执行命令。

在这之后，我们看到`vti_bin`目录中有一个`author.exe`文件，这理论上可能允许某人拥有作者权限。

最后一个有趣的项目是`wwwboard`目录中的`passwd.txt`文件。显然，这个密码文件是可浏览的，这绝对不是一件好事。

现在，在你指责我捏造这些问题之前，我要透露这是对一个真实托管服务上的真实生产网站的扫描。（是的，我有扫描的许可。）所以，这些问题是真实存在的，需要修复。

以下是我从扫描运行 WordPress 的 Web 服务器中得到的另外两个示例消息：

```
HTTP TRACK method is active, suggesting the host is vulnerable to XST
Cookie wordpress_test_cookie created without the httponly flag
```

长话短说，这两个问题都有可能允许攻击者窃取用户凭据。在这种情况下，解决方法是查看 WordPress 团队是否发布了任何可以解决问题的更新。

那么，我们如何保护 Web 服务器免受这些漏洞的影响呢？

+   正如我们在第一个示例中看到的，你希望确保你的 Web 服务器上没有任何风险的可执行文件。在这种情况下，我们发现了两个`.exe`文件，可能不会对我们的 Linux 服务器造成任何伤害，因为 Windows 可执行文件无法在 Linux 上运行。然而，另一方面，它可能是一个伪装成 Windows 可执行文件的 Linux 可执行文件。我们还发现了一些`perl`脚本，这些脚本肯定会在 Linux 上运行，并可能会造成问题。

+   如果有人在你的 Web 服务器上植入了一些恶意脚本，你会希望有某种强制访问控制，比如 SELinux 或 AppArmor，可以阻止恶意脚本运行。（有关详细信息，请参阅第七章，*使用 SELinux 和 AppArmor 实施强制访问控制*。）

+   你可能还考虑安装 Web 应用防火墙，比如*ModSecurity*。空间不允许我详细介绍 ModSecurity 的细节，但你可以在 Packt Publishing 网站找到一本介绍它的书。

+   保持系统更新，特别是如果你正在运行基于 PHP 的内容管理系统，比如 WordPress。（如果你关注 IT 安全新闻，你会发现关于 WordPress 漏洞的报道比你想象的要频繁。）

还有其他的扫描选项，你可以在命令行中输入`nikto`来查看。不过，现在这些已经足够让你开始进行基本的 Web 服务器扫描了。

# 总结

我们已经在我们的旅程中达到了又一个里程碑，并且看到了一些很酷的东西。我们从讨论设置 Snort 作为 NIDS 的基础知识开始。然后我向你展示了如何通过部署已经设置好并准备就绪的专业 Linux 发行版来严重作弊。

接下来，我向你介绍了 Lynis 以及如何使用它来扫描系统中的各种漏洞和合规性问题。最后，我们通过 OpenVAS 和 Nikto 的实际演示结束了这一切。

在下一章中，我们将以一些忙碌管理员的快速提示来结束整个旅程。我会在那里见到你。


# 第十章：对于繁忙的用户的安全提示和技巧

在我们的最后一章中，我想对之前章节中不一定适合的一些快速提示和技巧进行总结。把这些提示看作是繁忙管理员的时间节省者。

我们将涵盖以下主题：

+   快速审计系统服务的方法

+   对 GRUB2 配置进行密码保护

+   安全配置然后对 UEFI/BIOS 进行密码保护

+   在设置系统时使用安全检查表

# 审计系统服务

服务器管理的一个基本原则，无论我们谈论哪个操作系统，都是在服务器上永远不要安装任何你绝对不需要的东西。特别是你不希望任何不必要的网络服务在运行，因为这会给坏人额外的进入系统的途径。而且，总是有可能一些邪恶的黑客可能已经植入了一些充当网络服务的东西，你肯定想知道这件事。在本章中，我们将看一些审计系统的不同方法，以确保系统上没有不必要的网络服务在运行。

# 使用 systemctl 审计系统服务

在带有 systemd 的 Linux 系统中，`systemctl`命令几乎是一个为您执行许多操作的通用命令。除了控制系统的服务，它还可以显示这些服务的状态。我们有以下代码：

```
donnie@linux-0ro8:~> sudo systemctl -t service --state=active
```

以下是前述命令的分解：

+   `-t service`：我们想要查看关于系统上服务或者以前称为**守护进程**的信息

+   `--state=active`：这指定我们想要查看实际正在运行的所有系统服务的信息

这个命令的部分输出看起来像这样：

```
UNIT                                                  LOAD   ACTIVE SUB     DESCRIPTION
accounts-daemon.service                               loaded active running Accounts Service
after-local.service                                   loaded active exited  /etc/init.d/after.local Compatibility
alsa-restore.service                                  loaded active exited  Save/Restore Sound Card State
apparmor.service                                      loaded active exited  Load AppArmor profiles
auditd.service                                        loaded active running Security Auditing Service
avahi-daemon.service                                  loaded active running Avahi mDNS/DNS-SD Stack
cron.service                                          loaded active running Command Scheduler
. . .
. . .
systemd-sysctl.service                                loaded active exited  Apply Kernel Variables
systemd-tmpfiles-setup-dev.service                    loaded active exited  Create Static Device Nodes in /dev
systemd-tmpfiles-setup.service                        loaded active exited  Create Volatile Files and Directories
systemd-udev-root-symlink.service                     loaded active exited  Rule generator for /dev/root symlink
systemd-udev-trigger.service                          loaded active exited  udev Coldplug all Devices
systemd-udevd.service                                 loaded active running udev Kernel Device Manager
systemd-update-utmp.service                           loaded active exited  Update UTMP about System Boot/Shutdown

```

通常你不会想看到这么多信息，尽管有时可能会需要。这个命令显示了系统上运行的每个服务的状态。现在真正让我们感兴趣的是可以允许某人连接到你的系统的网络服务。所以，让我们看看如何缩小范围。

# 使用 netstat 审计网络服务

以下是你想要跟踪系统上正在运行的网络服务的两个原因：

+   确保没有不需要的合法网络服务正在运行

+   确保你没有任何恶意软件在监听来自其主机的网络连接

`netstat`命令对于这些情况既方便又易于使用。首先，假设你想要查看正在监听并等待有人连接的网络服务列表：

```
donnie@linux-0ro8:~> netstat -lp -A inet

(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address       Foreign Address   State       PID/Program name
tcp        0      0 *:ideafarm-door     *:*               LISTEN      -
tcp        0      0 localhost:40432     *:*               LISTEN      3296/SpiderOakONE
tcp        0      0 *:ssh               *:*               LISTEN      -
tcp        0      0 localhost:ipp       *:*               LISTEN      -
tcp        0      0 localhost:smtp      *:*               LISTEN      -
tcp        0      0 *:db-lsp            *:*               LISTEN      3246/dropbox
tcp        0      0 *:37468             *:*               LISTEN      3296/SpiderOakONE
tcp        0      0 localhost:17600     *:*               LISTEN      3246/dropbox
tcp        0      0 localhost:17603     *:*               LISTEN      3246/dropbox
udp        0      0 *:57228             *:*                           3376/plugin-contain
udp        0      0 192.168.204.1:ntp   *:*                           -
udp        0      0 172.16.249.1:ntp    *:*                           -
udp        0      0 linux-0ro8:ntp      *:*                           -
udp        0      0 localhost:ntp       *:*                           -
udp        0      0 *:ntp               *:*                           -
udp        0      0 *:58102             *:*                           5598/chromium --pas
udp        0      0 *:db-lsp-disc       *:*                           3246/dropbox
udp        0      0 *:43782             *:*                           5598/chromium --pas
udp        0      0 *:36764             *:*                           -
udp        0      0 *:21327             *:*                           3296/SpiderOakONE
udp        0      0 *:mdns              *:*                           5598/chromium --pas
udp        0      0 *:mdns              *:*                           5598/chromium --pas
udp        0      0 *:mdns              *:*                           5598/chromium --pas
udp        0      0 *:mdns              *:*                           -
raw        0      0 *:icmp              *:*               7           -
donnie@linux-0ro8:~>
```

分解如下：

+   `-lp`：`l`表示我们想要查看哪些网络端口正在监听。换句话说，我们想要查看哪些网络端口正在等待连接。`p`表示我们想要查看每个端口上正在监听的程序或服务的名称和进程 ID 号。

+   `-A inet`：这意味着我们只想要查看属于`inet`系列的网络协议的信息。换句话说，我们想要查看关于`raw`、`tcp`和`udp`网络套接字的信息，但我们不想看到任何关于仅处理操作系统内部进程通信的 Unix 套接字的信息。

由于这个输出来自我目前正在使用的 OpenSUSE 工作站，你在这里看不到通常的服务器类型服务。但是，你会看到一些你可能不想在你的服务器上看到的东西。例如，让我们看看第一项：

```
Proto Recv-Q Send-Q Local Address      Foreign Address         State       PID/Program name
tcp        0      0 *:ideafarm-door    *:*                     LISTEN      -
```

`本地地址`列指定了这个监听套接字的本地地址和端口。星号表示这个套接字在本地网络上，`ideafarm-door`是正在监听的网络端口的名称。（默认情况下，`netstat`会尽可能地显示端口的名称，通过从`/etc/services`文件中提取端口信息。）

现在，因为我不知道`ideafarm-door`服务是什么，我使用了我最喜欢的搜索引擎来找出答案。通过将术语`ideafarm-door`输入 DuckDuckGo，我找到了答案：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sec-hdn/img/c01aa891-62dd-4b2c-8758-2883e24819a9.png)

顶部搜索结果将我带到了一个名为*WhatPortIs*的网站。根据这个网站，`ideafarm-door`实际上是端口`902`，属于 VMware Server Console。好的，这很合理，因为我确实在这台机器上安装了 VMware Player。所以，一切都很好。

您可以在*WhatPortIs*网站上查看：[`whatportis.com/`](http://whatportis.com/)。

接下来是：

```
tcp        0      0 localhost:40432    *:*       LISTEN      3296/SpiderOakONE
```

此项目显示本地地址为`localhost`，监听端口为端口`40432`。这次，`PID/Program Name`列实际上告诉了我们这是什么。*SpiderOak ONE*是一个基于云的备份服务，您可能希望在服务器上运行它，也可能不希望。

现在，让我们再看几个项目：

```
tcp 0      0 *:db-lsp                   *:*      LISTEN      3246/dropbox
tcp 0      0 *:37468                    *:*      LISTEN      3296/SpiderOakONE
tcp 0      0 localhost:17600            *:*      LISTEN      3246/dropbox
tcp 0      0 localhost:17603            *:*      LISTEN      3246/dropbox
```

在这里，我们看到 Dropbox 和 SpiderOak ONE 都在本地地址上带有星号。因此，它们都在使用本地网络地址。Dropbox 的端口名称是`db-lsp`，代表*Dropbox LAN Sync Protocol*。SpiderOak ONE 端口没有官方名称，所以只列为端口`37468`。最后两行显示 Dropbox 还使用本地机器的地址，端口为`17600`和`17603`。

到目前为止，我们只看了 TCP 网络套接字。让我们看看它们与 UDP 套接字有何不同：

```
udp        0      0 192.168.204.1:ntp       *:*                                 -
udp        0      0 172.16.249.1:ntp        *:*                                 -
udp        0      0 linux-0ro8:ntp          *:*                                 -
```

首先要注意的是`State`列下面没有任何内容。这是因为在 UDP 中，没有状态。它们实际上是在等待数据包进来，并准备发送数据包出去。但由于这几乎是 UDP 套接字所能做的全部，所以没有必要为它们定义不同的状态。

在前两行中，我们看到一些奇怪的本地地址。这是因为我在这台工作站上安装了 VMware Player 和 VirtualBox。这两个套接字的本地地址是 VMware 和 VirtualBox 虚拟网络适配器的地址。最后一行显示了我的 OpenSUSE 工作站的主机名作为本地地址。在这三种情况下，端口都是用于时间同步的网络时间协议端口。

现在让我们看一下最后一组 UDP 项目：

```
udp        0      0 *:58102         *:*                                 5598/chromium --pas
udp        0      0 *:db-lsp-disc   *:*                                 3246/dropbox
udp        0      0 *:43782         *:*                                 5598/chromium --pas
udp        0      0 *:36764         *:*                                 -
udp        0      0 *:21327         *:*                                 3296/SpiderOakONE
udp        0      0 *:mdns          *:*                                 5598/chromium --pas
```

在这里，我们看到我的 Chromium 网络浏览器已准备好在几个不同的端口上接受网络数据包。我们还看到 Dropbox 使用 UDP 来接受其他安装了 Dropbox 的本地机器的发现请求。我猜端口`21327`对 SpiderOak ONE 执行相同的功能。

当然，由于这台机器是我的主力工作站，Dropbox 和 SpiderOak ONE 对我来说几乎是必不可少的。我自己安装了它们，所以我一直知道它们在那里。但是，如果您在服务器上看到类似的情况，您将希望调查一下服务器管理员是否知道这些程序已安装，然后找出它们为什么安装。可能它们正在执行合法的功能，也可能它们没有。

Dropbox 和 SpiderOak ONE 之间的一个区别是，使用 Dropbox 时，您的文件直到上传到 Dropbox 服务器后才会被加密。因此，Dropbox 的人员拥有您文件的加密密钥。另一方面，SpiderOak ONE 在本地机器上对文件进行加密，加密密钥永远不会离开您的手中。因此，如果您确实需要云备份服务并且正在处理敏感文件，像 SpiderOak ONE 这样的服务肯定比 Dropbox 更好。 （不，SpiderOak ONE 的人员并没有付我来说这些话。）

如果您想查看端口号和 IP 地址而不是网络名称，请添加`n`选项。我们有以下代码：

```
donnie@linux-0ro8:~> netstat -lpn -A inet

(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address      Foreign Address     State       PID/Program name
tcp        0      0 0.0.0.0:902        0.0.0.0:*           LISTEN      -
tcp        0      0 127.0.0.1:40432    0.0.0.0:*           LISTEN      3296/SpiderOakONE
tcp        0      0 0.0.0.0:22         0.0.0.0:*           LISTEN      -
tcp        0      0 127.0.0.1:631      0.0.0.0:*           LISTEN      -
tcp        0      0 127.0.0.1:25       0.0.0.0:*           LISTEN      -
tcp        0      0 0.0.0.0:17500      0.0.0.0:*           LISTEN      3246/dropbox
tcp        0      0 0.0.0.0:37468      0.0.0.0:*           LISTEN      3296/SpiderOakONE
tcp        0      0 127.0.0.1:17600    0.0.0.0:*           LISTEN      3246/dropbox
tcp        0      0 127.0.0.1:17603    0.0.0.0:*           LISTEN      3246/dropbox
udp        0      0 192.168.204.1:123  0.0.0.0:*                       -
udp        0      0 172.16.249.1:123   0.0.0.0:*                       -
udp        0      0 192.168.0.222:123  0.0.0.0:*                       -
udp        0      0 127.0.0.1:123      0.0.0.0:*                       -
udp        0      0 0.0.0.0:123        0.0.0.0:*                       -
udp        0      0 0.0.0.0:17500      0.0.0.0:*                       3246/dropbox
udp        0      0 0.0.0.0:50857      0.0.0.0:*                       5598/chromium --pas
udp        0      0 0.0.0.0:43782      0.0.0.0:*                       5598/chromium --pas
udp        0      0 0.0.0.0:44023      0.0.0.0:*                       10212/plugin-contai
udp        0      0 0.0.0.0:36764      0.0.0.0:*                       -
udp        0      0 0.0.0.0:21327      0.0.0.0:*                       3296/SpiderOakONE
udp        0      0 0.0.0.0:5353       0.0.0.0:*                       5598/chromium --pas
udp        0      0 0.0.0.0:5353       0.0.0.0:*                       5598/chromium --pas
udp        0      0 0.0.0.0:5353       0.0.0.0:*                       5598/chromium --pas
udp        0      0 0.0.0.0:5353       0.0.0.0:*                       -
raw        0      0 0.0.0.0:1          0.0.0.0:*           7           -
donnie@linux-0ro8:~>
```

只需省略`l`选项即可查看已建立的 TCP 连接。在我的工作站上，这会生成一个非常长的列表，所以我只会显示一些项目：

```
donnie@linux-0ro8:~> netstat -p -A inet
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (w/o servers)
Proto Recv-Q Send-Q Local Address      Foreign Address         State       PID/Program name
tcp        1      0 linux-0ro8:41670   ec2-54-88-208-223:https CLOSE_WAIT  3246/dropbox
tcp        0      0 linux-0ro8:59810   74-126-144-106.wa:https ESTABLISHED 3296/SpiderOakONE
tcp        0      0 linux-0ro8:58712   74-126-144-105.wa:https ESTABLISHED 3296/SpiderOakONE
tcp        0      0 linux-0ro8:caerpc  atl14s78-in-f2.1e:https ESTABLISHED 10098/firefox
. . .
. . .
```

`Foreign Address`列显示了连接远程端的机器的地址和端口号。第一项显示与 Dropbox 服务器的连接处于`CLOSE_WAIT`状态。这意味着 Dropbox 服务器已关闭连接，现在我们正在等待本地机器关闭套接字。

因为那些外国地址的名称没有太多意义，让我们添加`n`选项以查看 IP 地址：

```
donnie@linux-0ro8:~> netstat -np -A inet
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (w/o servers)
Proto Recv-Q Send-Q Local Address         Foreign Address      State        PID/Program name
tcp        0      1 192.168.0.222:59594   37.187.24.170:443    SYN_SENT     10098/firefox
tcp        0      0 192.168.0.222:59810   74.126.144.106:443   ESTABLISHED  3296/SpiderOakONE
tcp        0      0 192.168.0.222:58712   74.126.144.105:443   ESTABLISHED  3296/SpiderOakONE
tcp        0      0 192.168.0.222:38606   34.240.121.144:443   ESTABLISHED  10098/firefox
. . .
. . .
```

这次我们看到了一些新的东西。第一项显示了 Firefox 连接的`SYN_SENT`状态。这意味着本地机器正在尝试与外国 IP 地址建立连接。此外，在`Local Address`下，我们看到了我 OpenSUSE 工作站的静态 IP 地址。

如果我有空间在这里显示整个`netstat`输出，您将看到`Proto`列下只有`tcp`。这是因为 UDP 协议不像 TCP 协议那样建立连接。

需要记住的一点是，rootkit 可以用它们自己的木马版本替换合法的 Linux 实用程序。例如，rootkit 可以有自己的`netstat`的木马版本，它将显示除与 rootkit 相关的所有网络进程之外的所有网络进程。这就是为什么您需要像 Rootkit Hunter 这样的工具。

如果您需要有关`netstat`的更多信息，请参阅`netstat`手册页。

# 使用 Nmap 审计网络服务

`netstat`工具非常好，可以为您提供有关网络服务情况的大量信息。稍微不足的是，您必须登录到网络上的每个主机才能使用它。

如果您想远程审计您的网络，查看每台计算机上运行的服务，而无需登录到每台计算机，那么您需要像 Nmap 这样的工具。它适用于所有主要操作系统，因此即使您被迫在工作站上使用 Windows，您也很幸运。如果您使用的是 Kali Linux，则内置了最新版本。它还在每个主要 Linux 发行版的存储库中，但通常存储库中的版本非常旧。因此，如果您使用的不是 Kali，最好的选择就是从创建者的网站下载 Nmap。

您可以从[`nmap.org/download.html`](https://nmap.org/download.html)下载所有主要操作系统的 Nmap。

在所有情况下，您还会找到安装说明。

您将在所有操作系统上以相同的方式使用 Nmap，只有一个例外。在 Linux 和 Mac 机器上，您将在某些 Nmap 命令之前加上 sudo，在 Windows 机器上则不需要。由于我碰巧正在使用我值得信赖的 OpenSUSE 工作站，我将向您展示在 Linux 上的工作原理。让我们首先进行 SYN 数据包扫描：

```
donnie@linux-0ro8:~> sudo nmap -sS 192.168.0.37

Starting Nmap 6.47 ( http://nmap.org ) at 2017-12-24 19:32 EST
Nmap scan report for 192.168.0.37
Host is up (0.00016s latency).
Not shown: 996 closed ports
PORT STATE SERVICE
22/tcp open ssh
515/tcp open printer
631/tcp open ipp
5900/tcp open vnc
MAC Address: 00:0A:95:8B:E0:C0 (Apple)

Nmap done: 1 IP address (1 host up) scanned in 57.41 seconds
donnie@linux-0ro8:~>
```

以下是详细信息：

+   `-sS`：小写`s`表示我们要执行的扫描类型。大写`S`表示我们正在进行 SYN 数据包扫描。（稍后详细介绍。）

+   `192.168.0.37`：在这种情况下，我只扫描了一台机器。但是，我也可以扫描一组机器或整个网络。

+   `Not shown: 996 closed ports`：显示所有这些关闭的端口而不是`filtered`端口的事实告诉我这台机器上没有防火墙。（稍后详细介绍。）

接下来，我们看到了一系列打开的端口。（稍后详细介绍。）

这台机器的 MAC 地址表明它是某种苹果产品。稍后，我将向您展示如何获取有关它可能是什么类型的苹果产品的更多详细信息。

现在让我们更详细地看一下。

# 端口状态

Nmap 扫描将显示目标机器的端口处于三种状态之一：

+   `filtered`：这意味着该端口被防火墙阻止

+   `open`：这意味着该端口未被防火墙阻止，并且与该端口关联的服务正在运行

+   `closed`：这意味着该端口没有被防火墙阻塞，并且与该端口相关的服务未运行

因此，在我们对苹果机器的扫描中，我们看到 Secure Shell 服务准备在端口`22`上接受连接，打印服务准备在端口`515`和`631`上接受连接，以及**虚拟网络计算**（**VNC**）服务准备在端口`5900`上接受连接。所有这些端口对于注重安全的管理员来说都是感兴趣的。如果 Secure Shell 正在运行，了解它是否配置安全是很有趣的。打印服务正在运行意味着这台机器设置为使用**Internet Printing Protocol**（**IPP**）。了解为什么我们使用 IPP 而不是普通的网络打印是很有趣的，也很有趣的是了解这个版本的 IPP 是否存在任何安全问题。当然，我们已经知道 VNC 不是一个安全的协议，所以我们想知道为什么它会运行。我们还看到没有端口被列为`filtered`，所以我们也想知道为什么这台机器上没有防火墙。

有一个小秘密，我终于要揭露了，就是这台机器和我用来进行 OpenVAS 扫描演示的是同一台。所以，我们已经有了一些所需的信息。OpenVAS 扫描告诉我们，这台机器上的 Secure Shell 使用了弱加密算法，并且打印服务存在安全漏洞。马上，我会向你展示如何使用 Nmap 获取一些信息。

# 扫描类型

有很多不同的扫描选项，每个选项都有自己的目的。我们在这里使用的 SYN 数据包扫描被认为是一种隐秘的扫描类型，因为它产生的网络流量和系统日志条目比某些其他类型的扫描要少。使用这种类型的扫描，Nmap 向目标机器的一个端口发送一个 SYN 数据包，就好像它试图创建一个 TCP 连接到该机器。如果目标机器用一个 SYN/ACK 数据包回应，这意味着该端口处于`open`状态，准备好创建 TCP 连接。如果目标机器用一个 RST 数据包回应，这意味着该端口处于`closed`状态。如果根本没有响应，这意味着该端口是`filtered`，被防火墙阻塞。作为一个普通的 Linux 管理员，这是你大部分时间会做的扫描类型之一。

`-sS`扫描显示 TCP 端口的状态，但不显示 UDP 端口的状态。要查看 UDP 端口，使用`-sU`选项：

```
donnie@linux-0ro8:~> sudo nmap -sU 192.168.0.37

Starting Nmap 6.47 ( http://nmap.org ) at 2017-12-28 12:41 EST
Nmap scan report for 192.168.0.37
Host is up (0.00018s latency).
Not shown: 996 closed ports
PORT     STATE         SERVICE
123/udp  open          ntp
631/udp  open|filtered ipp
3283/udp open|filtered netassistant
5353/udp open          zeroconf
MAC Address: 00:0A:95:8B:E0:C0 (Apple)

Nmap done: 1 IP address (1 host up) scanned in 119.91 seconds
donnie@linux-0ro8:~>
```

在这里，你看到了一些不同的东西。你看到两个端口被列为`open|filtered`。这是因为由于 UDP 端口对 Nmap 扫描的响应方式，Nmap 并不能总是确定 UDP 端口是`open`还是`filtered`。在这种情况下，我们知道这两个端口可能是打开的，因为我们已经看到它们对应的 TCP 端口是打开的。

ACK 数据包扫描也可能是有用的，但不是为了查看目标机器的网络服务状态。相反，它是一个很好的选项，当你需要查看是否有防火墙阻挡你和目标机器之间的通路时。ACK 扫描命令看起来像这样：

```
sudo nmap -sA 192.168.0.37
```

你不仅限于一次只扫描一台机器。你可以一次扫描一组机器或整个子网：

```
sudo nmap -sS 192.168.0.1-128
sudo nmap -sS 192.168.0.0/24
```

第一个命令只扫描了这个网络段上的前 128 个主机。第二个命令扫描了使用 24 位子网掩码的子网上的所有 254 个主机。

发现扫描对于只想看看网络上有哪些设备是有用的：

```
sudo nmap -sn 192.168.0.0/24
```

使用`-sn`选项，Nmap 将首先检测您是在扫描本地子网还是远程子网。如果子网是本地的，Nmap 将发送一个**地址解析协议**（**ARP**）广播，请求子网上每个设备的 IPv4 地址。这是一种可靠的发现设备的方式，因为 ARP 不会被设备的防火墙阻止。然而，ARP 广播无法跨越路由器，这意味着您无法使用 ARP 来发现远程子网上的主机。因此，如果 Nmap 检测到您正在对远程子网进行发现扫描，它将发送 ping 数据包而不是 ARP 广播。使用 ping 数据包进行发现不像使用 ARP 那样可靠，因为一些网络设备可以配置为忽略 ping 数据包。无论如何，这是我自己家庭网络的一个例子：

```
donnie@linux-0ro8:~> sudo nmap -sn 192.168.0.0/24

Starting Nmap 6.47 ( http://nmap.org ) at 2017-12-25 14:48 EST
Nmap scan report for 192.168.0.1
Host is up (0.00043s latency).
MAC Address: 00:18:01:02:3A:57 (Actiontec Electronics)
Nmap scan report for 192.168.0.3
Host is up (0.0044s latency).
MAC Address: 44:E4:D9:34:34:80 (Cisco Systems)
Nmap scan report for 192.168.0.5
Host is up (0.00026s latency).
MAC Address: 1C:1B:0D:0A:2A:76 (Unknown)
Nmap scan report for 192.168.0.6
Host is up (0.00013s latency).
MAC Address: 90:B1:1C:A3:DF:5D (Dell)
. . .
. . .
```

我们在这段代码中看到了四个主机，每个主机有三行输出。第一行显示 IP 地址，第二行显示主机是否在线，第三行显示主机网络适配器的 MAC 地址。每个 MAC 地址的前三对字符表示该网络适配器的制造商。（记录上，未知的网络适配器是最近型号的技嘉主板上的。我不知道为什么它不在 Nmap 数据库中。）

我们将要看的最后一个扫描为我们做了四件事：

+   它识别`open`、`closed`和`filtered`的 TCP 端口

+   它识别正在运行的服务的版本

+   它运行一组随 Nmap 提供的漏洞扫描脚本

+   它试图识别目标主机的操作系统

执行所有这些操作的扫描命令如下：

```
sudo nmap -A 192.168.0.37
```

我猜您可以将`-A`选项看作是*all*选项，因为它确实做了所有的事情。（嗯，几乎所有，因为它不扫描 UDP 端口。）这是我针对目标进行的扫描的结果：

```
donnie@linux-0ro8:~> sudo nmap -A 192.168.0.37

Starting Nmap 6.47 ( http://nmap.org ) at 2017-12-24 19:33 EST
Nmap scan report for 192.168.0.37
Host is up (0.00016s latency).
Not shown: 996 closed ports
PORT STATE SERVICE VERSION
22/tcp open ssh OpenSSH 5.1 (protocol 1.99)
|_ssh-hostkey: ERROR: Script execution failed (use -d to debug)
|_sshv1: Server supports SSHv1
515/tcp open printer?
631/tcp open ipp CUPS 1.1
| http-methods: Potentially risky methods: PUT
|_See http://nmap.org/nsedoc/scripts/http-methods.html
| http-robots.txt: 1 disallowed entry
|_/
|_http-title: Common UNIX Printing System
5900/tcp open vnc Apple remote desktop vnc
| vnc-info:
| Protocol version: 3.889
| Security types:
|_ Mac OS X security type (30)
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at http://www.insecure.org/cgi-bin/servicefp-submit.cgi :
SF-Port515-TCP:V=6.47%I=7%D=12/24%Time=5A40479E%P=x86_64-suse-linux-gnu%r(
SF:GetRequest,1,"\x01");
MAC Address: 00:0A:95:8B:E0:C0 (Apple)
Device type: general purpose
Running: Apple Mac OS X 10.4.X
OS CPE: cpe:/o:apple:mac_os_x:10.4.10
OS details: Apple Mac OS X 10.4.10 - 10.4.11 (Tiger) (Darwin 8.10.0 - 8.11.1)
Network Distance: 1 hop
Service Info: OS: Mac OS X; CPE: cpe:/o:apple:mac_os_x

TRACEROUTE
HOP RTT ADDRESS
1 0.16 ms 192.168.0.37

OS and Service detection performed. Please report any incorrect results at http://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 213.92 seconds
donnie@linux-0ro8:~>
```

这里有几件有趣的事情。首先是安全外壳信息：

```
22/tcp open ssh OpenSSH 5.1 (protocol 1.99)
|_ssh-hostkey: ERROR: Script execution failed (use -d to debug)
|_sshv1: Server supports SSHv1
```

版本 5.1 是一个非常古老的 OpenSSH 版本。（在撰写本文时，当前版本是 7.6。）更糟糕的是，这个 OpenSSH 服务器支持安全外壳协议的第一个版本。第一个版本存在严重缺陷，很容易被利用，所以您绝不希望在您的网络上看到这个。

接下来，我们对使用 OpenVAS 扫描发现的打印服务漏洞进行了详细说明：

```
515/tcp  open  printer?
631/tcp  open  ipp      CUPS 1.1
| http-methods: Potentially risky methods: PUT
|_See http://nmap.org/nsedoc/scripts/http-methods.html
| http-robots.txt: 1 disallowed entry
|_/
|_http-title: Common UNIX Printing System
```

在`631/tcp`行中，我们看到相关服务是`ipp`，代表**Internet Printing Protocol**。这个协议基于我们用来查看网页的**超文本传输协议**（**HTTP**）。HTTP 用于从客户端向服务器发送数据的两种方法是**POST**和**PUT**。我们真正希望的是每个 HTTP 服务器都使用 POST 方法，因为 PUT 方法使得有人通过操纵 URL 很容易就能破坏服务器。因此，如果您扫描一个服务器并发现它允许使用 PUT 方法进行任何类型的 HTTP 通信，那么您就有了一个潜在的问题。在这种情况下，解决方案将是更新操作系统，并希望更新修复问题。如果这是一个 Web 服务器，您会想与 Web 服务器管理员交谈，让他们知道您发现了什么。

最后，让我们看看 Nmap 发现的目标机器的操作系统信息：

```
Running: Apple Mac OS X 10.4.X
OS CPE: cpe:/o:apple:mac_os_x:10.4.10
OS details: Apple Mac OS X 10.4.10 - 10.4.11 (Tiger) (Darwin 8.10.0 - 8.11.1)
Network Distance: 1 hop
Service Info: OS: Mac OS X; CPE: cpe:/o:apple:mac_os_x
```

等等，什么？Mac OS X 10.4？那不是非常古老吗？是的，确实如此。在过去的几章中我一直保密的秘密是，我 OpenVAS 和 Nmap 扫描演示的目标机器是我 2003 年的古老的、收藏价值的苹果 eMac。我想扫描它会给我们一些有趣的结果看，看来我是对的。（是的，是 eMac，不是 iMac。）

# 保护 GRUB 2 引导加载程序的密码

有时人们会忘记密码，即使他们是管理员。有时，人们购买了二手电脑，但忘记询问卖家密码是什么。（是的，我曾经这样做过。）不过，这没关系，因为所有主要操作系统都有办法让您重置或恢复丢失的管理员密码。这很方便，但是当有人可以物理访问机器时，登录密码的整个概念似乎就没有什么意义了。假设您的笔记本电脑刚刚被盗。如果您没有加密硬盘，窃贼只需要几分钟就可以重置密码并窃取您的数据。如果您已经加密了硬盘，保护级别将取决于您使用的操作系统。使用标准的 Windows 文件夹加密，窃贼可以通过重置密码来访问加密文件夹。在 Linux 机器上使用 LUKS 整盘加密，窃贼将无法绕过输入加密密码的步骤。

在 Linux 中，我们有一种方法来防止未经授权的密码重置，即使我们没有使用整盘加密。我们所要做的就是对**Grand Unified Bootloader** (**GRUB**)进行密码保护，这将阻止窃贼进入紧急模式进行密码重置。

无论您是否需要本节中的建议取决于您组织的物理安全设置。这是因为将 Linux 机器引导到紧急模式需要物理访问该机器。这不是您可以远程执行的操作。在具有适当物理安全措施的组织中，服务器，尤其是保存敏感数据的服务器，都被锁在一个房间里，而这个房间又被锁在另一个房间里。只有极少数信任的人被允许进入，并且他们必须在两个访问点出示自己的凭据。因此，在这些服务器的引导加载程序上设置密码将是毫无意义的，除非您正在处理一个规定不同的监管机构。

另一方面，对于摆放在公开场所的工作站和笔记本电脑的引导加载程序进行密码保护可能非常有用。但是，仅仅这样做并不能保护您的数据。某人仍然可以从活动光盘或 USB 存储设备引导机器，挂载机器的硬盘，并获取敏感数据。这就是为什么您还需要加密您的敏感数据，就像我在第四章中向您展示的那样，*加密和 SSH 加固*。

要重置密码，您所要做的就是在引导菜单出现时中断引导过程，并更改一些内核参数。然而，重置密码并不是您可以从引导菜单中做的唯一事情。如果您的机器安装了多个操作系统，例如一个分区上安装了 Windows，另一个分区上安装了 Linux，引导菜单允许您选择要引导的操作系统。使用旧式的传统 GRUB，您可以防止人们编辑内核参数，但无法阻止他们选择多重引导机器上的另一个操作系统。在较新版本的 Linux 中使用的新 GRUB 2 中，您可以选择您希望能够从任何特定操作系统引导的用户。

现在，为了让您知道我所说的您可以从 GRUB 2 引导菜单中编辑内核参数，让我向您展示如何执行密码重置。

# 重置 Red Hat/CentOS 的密码

当引导菜单出现时，按下箭头键一次中断引导过程。然后，按上箭头键一次选择默认的引导选项：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sec-hdn/img/25af8418-ee03-4da1-a179-07d01dfb4b3c.png)

按下*E*键编辑内核参数。当 GRUB 2 配置出现时，光标下移，直到看到这一行：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sec-hdn/img/eba3931e-5e0d-43b9-b3a0-4abfeeb1a274.png)

从此行中删除`rhgb quiet`，然后在行末添加`rd.break enforcing=0`。以下是这两个新选项为您做的事情：

+   `rd.break`：这将导致机器进入紧急模式，从而使您无需输入 root 用户密码即可获得 root 用户特权。即使 root 用户密码尚未设置，这仍然有效。

+   `enforcing=0`：在启用 SELinux 的系统上重置密码时，`/etc/shadow`文件的安全上下文将更改为错误类型。如果系统在执行模式下执行此操作，SELinux 将阻止您登录，直到`shadow`文件重新标记。但是，在引导过程中重新标记可能需要很长时间，特别是对于大容量驱动器。通过将 SELinux 设置为宽松模式，您可以等到重启后再恢复`shadow`文件的正确安全上下文。

编辑内核参数后，按下*Ctrl* + *X*继续引导过程。这将带您到带有`switch_root`命令提示符的紧急模式：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sec-hdn/img/b50df375-e63a-45f5-a4ba-8ad2752188ea.png)

在紧急模式下，文件系统以只读方式挂载。您需要将其重新挂载为读写模式，并在重置密码之前进入`chroot`模式：

```
mount -o remount,rw /sysroot
chroot /sysroot
```

输入这两个命令后，命令提示符将更改为普通的 bash shell：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sec-hdn/img/7d25c842-5b18-4c02-adc8-bc8f080c9539.png)

现在您已经到达这个阶段，终于可以重置密码了。

如果要重置 root 用户密码，甚至是在以前不存在密码的情况下创建 root 密码，只需输入：

```
passwd
```

然后，输入新的所需密码。

如果系统从未设置过 root 用户密码，而您仍然不希望设置密码，您可以重置具有完整 sudo 特权的帐户的密码。例如，在我的系统上，命令如下：

```
passwd donnie
```

接下来，将文件系统重新挂载为只读。然后，输入两次`exit`以恢复重启：

```
mount -o remount,ro /
exit
exit
```

重启后，您需要做的第一件事是恢复`/etc/shadow`文件的正确 SELinux 安全上下文。然后，将 SELinux 恢复为强制模式：

```
sudo restorecon /etc/shadow
sudo setenforce 1
```

这是我`shadow`文件上下文设置的之前和之后的屏幕截图：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sec-hdn/img/e161c85f-8bc6-4d57-a845-fc94e93e9825.png)

您可以看到重置密码将文件类型更改为`unlabeled_t`。运行`restorecon`命令将类型更改回`shadow_t`。

# 在 Ubuntu 上重置密码

在 Ubuntu 系统上重置密码的过程有很大不同，也更简单。首先，按下向下箭头键一次以中断引导过程，然后按一次向上箭头键以选择默认引导选项。按下*E*键编辑内核参数：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sec-hdn/img/6a52090c-1f47-44be-9d94-7372ed34d00e.png)

当 GRUB 2 配置出现时，光标下移，直到看到`linux`行：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sec-hdn/img/0d9a3652-b616-489f-b92e-c44db5d8ea70.png)

将`ro`更改为`rw`并添加`init=/bin/bash`：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sec-hdn/img/2bf6dabd-d488-44fd-a727-d3c76a4a8c38.png)

按下*Ctrl* + *X*继续引导。这将带您到一个 root shell：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sec-hdn/img/09c55698-6c2d-4062-b025-0d8815aa790f.png)

由于 Ubuntu 通常不会为 root 用户分配密码，因此您很可能只会重置具有完整 sudo 特权的用户的密码。请参阅以下示例：

```
passwd donnie
```

在此模式下，常规的重启命令将无效。因此，在完成密码重置操作后，输入以下命令进行重启：

```
exec /sbin/init
```

机器现在将正常启动。

# 在 Red Hat/CentOS 上防止内核参数编辑

自从引入 Red Hat/CentOS 7.2 以来，设置 GRUB 2 密码以防止内核参数编辑变得很容易。您只需运行一个命令并选择一个密码：

```
[donnie@localhost ~]$ sudo grub2-setpassword

[sudo] password for donnie:
Enter password:
Confirm password:
[donnie@localhost ~]$
```

就是这样。密码哈希将存储在`/boot/grub2/user.cfg`文件中。

现在，当您重新启动机器并尝试编辑内核参数时，您将被提示输入用户名和密码：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sec-hdn/img/818bcdff-425e-4676-8e2e-671022bed7b3.png)

请注意，即使系统上尚未设置 root 用户的密码，您也将输入`root`作为用户名。在这种情况下，`root`用户只是 GRUB 2 的超级用户。

# 防止在 Ubuntu 上编辑内核参数

Ubuntu 没有 Red Hat 和 CentOS 拥有的那种很酷的实用程序，因此您必须手动编辑配置文件来设置 GRUB 2 密码。

在`/etc/grub.d/`目录中，您将看到组成 GRUB 2 配置的文件：

```
donnie@ubuntu3:/etc/grub.d$ ls -l
total 76
-rwxr-xr-x 1 root root  9791 Oct 12 16:48 00_header
-rwxr-xr-x 1 root root  6258 Mar 15  2016 05_debian_theme
-rwxr-xr-x 1 root root 12512 Oct 12 16:48 10_linux
-rwxr-xr-x 1 root root 11082 Oct 12 16:48 20_linux_xen
-rwxr-xr-x 1 root root 11692 Oct 12 16:48 30_os-prober
-rwxr-xr-x 1 root root  1418 Oct 12 16:48 30_uefi-firmware
-rwxr-xr-x 1 root root   214 Oct 12 16:48 40_custom
-rwxr-xr-x 1 root root   216 Oct 12 16:48 41_custom
-rw-r--r-- 1 root root   483 Oct 12 16:48 README
donnie@ubuntu3:/etc/grub.d$
```

您要编辑的文件是`40_custom`文件。但是，在编辑文件之前，您需要使用`grub-mkpasswd-pbkdf2`实用程序创建密码哈希。：

```
donnie@ubuntu3:/etc/grub.d$ grub-mkpasswd-pbkdf2
Enter password:
Reenter password:
PBKDF2 hash of your password is grub.pbkdf2.sha512.10000.F1BA16B2799CBF6A6DFBA537D43222A0D5006124ECFEB29F5C81C9769C6C3A66BF53C2B3AB71BEA784D4386E86C991F7B5D33CB6C29EB6AA12C8D11E0FFA0D40.371648A84CC4131C3CFFB53604ECCBA46DA75AF196E970C98483385B0BE026590C63A1BAC23691517BC4A5D3EDF89D026B599A0D3C49F2FB666F9C12B56DB35D
donnie@ubuntu3:/etc/grub.d$
```

在您喜欢的编辑器中打开`40_custom`文件，并添加一行来定义超级用户是谁。再添加一行密码哈希。在我的情况下，文件现在看起来像这样：

```
#!/bin/sh
exec tail -n +3 $0
# This file provides an easy way to add custom menu entries. Simply type the
# menu entries you want to add after this comment. Be careful not to change
# the 'exec tail' line above.

set superusers="donnie"

password_pbkdf2 donnie grub.pbkdf2.sha512.10000.F1BA16B2799CBF6A6DFBA537D43222A0D5006124ECFEB29F5C81C9769C6C3A66BF53C2B3AB71BEA784D4386E86C991F7B5D33CB6C29EB6AA12C8D11E0FFA0D40.371648A84CC4131C3CFFB53604ECCBA46DA75AF196E970C98483385B0BE026590C63A1BAC23691517BC4A5D3EDF89D026B599A0D3C49F2FB666F9C12B56DB35D

```

以`password_pbkdf2`开头的文本字符串是一页上环绕的一行。

保存文件后，最后一步是生成新的`grub.cfg`文件：

```
donnie@ubuntu3:/etc/grub.d$ sudo update-grub

Generating grub configuration file ...
Found linux image: /boot/vmlinuz-4.4.0-104-generic
Found initrd image: /boot/initrd.img-4.4.0-104-generic
Found linux image: /boot/vmlinuz-4.4.0-101-generic
Found initrd image: /boot/initrd.img-4.4.0-101-generic
Found linux image: /boot/vmlinuz-4.4.0-98-generic
Found initrd image: /boot/initrd.img-4.4.0-98-generic
done
donnie@ubuntu3:/etc/grub.d$
```

现在，当我重新启动这台机器时，我必须输入密码才能编辑内核参数：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sec-hdn/img/cf540a8a-3608-481f-9b0d-2dcb2f783b2f.png)

这只有一个问题。这不仅阻止除超级用户之外的任何人编辑内核参数，还阻止除超级用户之外的任何人正常启动。是的，没错。即使是正常启动，Ubuntu 现在也需要您输入授权超级用户的用户名和密码。修复很容易，尽管一点也不优雅。

修复需要在`/boot/grub/grub.cfg`文件中插入一个单词。很容易，对吧？但是，这不是一个优雅的解决方案，因为您实际上不应该手动编辑`grub.cfg`文件。在文件顶部，我们看到这样的内容：

```
# DO NOT EDIT THIS FILE
#
# It is automatically generated by grub-mkconfig using templates
# from /etc/grub.d and settings from /etc/default/grub
#
```

这意味着每当我们做一些会更新`grub.cfg`文件的操作时，我们对文件所做的手动编辑都将丢失。这包括当我们进行安装新内核的系统更新，或者当我们运行`sudo apt autoremove`删除不再需要的旧内核时。然而，最讽刺的是，官方的 GRUB 2 文档告诉我们手动编辑`grub.cfg`文件来处理这些问题。

无论如何，为了修复这个问题，使您不再需要输入密码来正常启动，请在您喜欢的文本编辑器中打开`/boot/grub/grub.cfg`文件。查找以`menuentry`开头的第一行，应该看起来像这样：

```
menuentry 'Ubuntu' --class ubuntu --class gnu-linux --class gnu --class os $menuentry_id_option 'gnulinux-simple-f0f002e8-16b2-45a1-bebc-41e518ab9497' {
```

在该行的末尾的左花括号之前，添加文本字符串`--unrestricted`。现在`menuentry`应该看起来像这样：

```
menuentry 'Ubuntu' --class ubuntu --class gnu-linux --class gnu --class os $menuentry_id_option 'gnulinux-simple-f0f002e8-16b2-45a1-bebc-41e518ab9497' --unrestricted {
```

保存文件并通过重新启动机器进行测试。您应该看到机器现在会正常启动默认的启动选项。但是，您还会看到访问 Ubuntu 高级选项子菜单仍然需要密码。我们稍后会解决这个问题。

# 保护密码启动选项

对于任何给定的 Linux 系统，您至少会有两个启动选项。您将有正常启动和恢复模式启动的选项。红帽类型和 Ubuntu 类型的操作系统是独特的，因为当您进行操作系统更新时，它们不会覆盖旧内核。相反，它们会安装新内核以及旧内核，并且所有安装的内核都有自己的启动菜单条目。在红帽类型的系统上，您永远不会安装超过五个内核，因为一旦安装了五个内核，下次系统更新时最旧的内核将自动被删除。对于 Ubuntu 类型的系统，您需要通过运行`sudo apt autoremove`手动删除旧内核。

你可能还有一个双重引导或多重引导配置，并且你可能只希望某些用户使用某些引导选项。假设你的系统上安装了 Windows 和 Linux，并且你希望阻止某些用户引导到其中一个。你可以通过配置 GRUB 2 来做到这一点，但你可能不会。我的意思是，无论如何登录操作系统都需要密码和用户帐户，那么为什么要麻烦呢？

我能想到的最现实的情景是，如果你在一个公共可访问的信息亭上设置了一台计算机。你肯定不希望普通公众将机器引导到恢复模式，这种技术将有助于防止这种情况发生。

这种技术在红帽类型和 Ubuntu 类型的发行版上基本相同，只有少数例外。最主要的例外是我们需要在 Ubuntu 机器上禁用子菜单。

# 禁用 Ubuntu 的子菜单

理论上，你可以通过将`GRUB_DISABLE_SUBMENU=true`放入`/etc/default/grub`文件中，然后运行`sudo update-grub`来禁用 Ubuntu 子菜单。然而，我无法让它起作用，根据我的 DuckDuckGo 搜索结果，其他人也无法。因此，我们将手动编辑`/boot/grub/grub.cfg`文件来修复它。

查找出现在第一个`menuentry`项后面的`submenu`行。它应该看起来像这样：

```
submenu 'Advanced options for Ubuntu' $menuentry_id_option 'gnulinux-advanced-f0f002e8-16b2-45a1-bebc-41e518ab9497' {
```

将该行注释掉，使其看起来像这样：

```
# submenu 'Advanced options for Ubuntu' $menuentry_id_option 'gnulinux-advanced-f0f002e8-16b2-45a1-bebc-41e518ab9497' {
```

向下滚动，直到你看到这行：

```
### END /etc/grub.d/10_linux ###
```

就在这行上面，你会看到子菜单段的闭合大括号。注释掉这个大括号，使其看起来像这样：

```
# }
```

现在当你重新启动机器时，你将看到整个引导选项列表，而不仅仅是默认的引导选项和一个子菜单。然而，按目前的情况，只有指定的超级用户才能引导到除默认选项以外的任何东西。

# 保护引导选项的步骤，适用于 Ubuntu 和 Red Hat。

从这里开始，对于 CentOS 和 Ubuntu 虚拟机，步骤都是一样的，除了以下几点：

+   在你的 Ubuntu 机器上，`grub.cfg`文件在`/boot/grub/`目录中。在你的 CentOS 机器上，它在`/boot/grub2/`目录中。

+   在 Ubuntu 上，`/boot/grub/`和`/etc/grub.d/`目录是可读的。因此，你可以像普通用户一样进入它们。

+   在 CentOS 上，`/boot/grub2/`和`/etc/grub.d/`目录只对 root 用户有限制。因此，要进入这些目录，你需要登录到 root 用户的 shell。或者，你可以在你的普通用户 shell 中使用`sudo ls -l`列出内容，并使用`sudo vim /boot/grub2/grub.cfg`或`sudo vim /etc/grub.d/40_custom`编辑你需要编辑的文件。（用你喜欢的编辑器替换 vim。）

+   在 Ubuntu 上，创建密码哈希的命令是`grub-mkpasswd-pbkdf2`。在 CentOS 上，命令是`grub2-mkpasswd-pbkdf2`。

考虑到这些细微差别，让我们开始吧。

如果你正在使用只有文本模式界面的服务器，你肯定会想从具有图形界面的工作站远程登录。如果你的工作站正在运行 Windows，你可以使用 Cygwin，就像我在第一章中向你展示的那样，*在虚拟环境中运行 Linux*。

这是因为你需要一种方法来复制和粘贴密码哈希到你需要编辑的两个文件中。

你要做的第一件事是为你的新用户创建一个密码哈希：

+   在 Ubuntu 上：

```
 grub-mkpasswd-pbkdf2
```

+   在 CentOS 上：

```
 grub2-mkpasswd-pbkdf2
```

接下来，打开你的文本编辑器中的`/etc/grub.d/40_custom`文件，并为你的新用户添加一行，以及你刚刚创建的密码哈希。该行应该看起来像这样：

```
password_pbkdf2 goldie grub.pbkdf2.sha512.10000.225205CBA2584240624D077ACB84E86C70349BBC00DF40A219F88E5691FB222DD6E2F7765E96C63C4A8FA3B41BDBF62DA1F3B07C700D78BC5DE524DCAD9DD88B.9655985015C3BEF29A7B8E0A6EA42599B1152580251FF99AA61FE68C1C1209ACDCBBBDAA7A97D4FC4DA6984504923E1449253024619A82A57CECB1DCDEE53C06
```

请注意，这是一页上环绕的一行。

接下来您应该运行一个实用程序，该实用程序将读取`/etc/grub.d/`目录中的所有文件以及`/etc/default/grub`文件，然后重新构建`grub.cfg`文件。但是，在 CentOS 上，该实用程序无法正常工作。在 Ubuntu 上，它可以正常工作，但它将覆盖您可能已经对`grub.cfg`文件进行的任何更改。因此，我们将采取欺骗手段。

在文本编辑器中打开`grub.cfg`文件：

+   在 Ubuntu 上：

```
 sudo vim /boot/grub/grub.cfg
```

+   在 CentOS 上：

```
        sudo vim /boot/grub2/grub.cfg
```

向下滚动直到看到`### BEGIN /etc/grub.d/40_custom ###`部分。在此部分，复制并粘贴刚刚添加到`40_custom`文件的行。此部分现在应该看起来像这样：

```
### BEGIN /etc/grub.d/40_custom ###
# This file provides an easy way to add custom menu entries.  Simply type the
# menu entries you want to add after this comment.  Be careful not to change
# the 'exec tail' line above.
password_pbkdf2 "goldie" grub.pbkdf2.sha512.10000.225205CBA2584240624D077ACB84E86C70349BBC00DF40A219F88E5691FB222DD6E2F7765E96C63C4A8FA3B41BDBF62DA1F3B07C700D78BC5DE524DCAD9DD88B.9655985015C3BEF29A7B8E0A6EA42599B1152580251FF99AA61FE68C1C1209ACDCBBBDAA7A97D4FC4DA6984504923E1449253024619A82A57CECB1DCDEE53C06
### END /etc/grub.d/40_custom ###
```

最后，您已经准备好为各个菜单项添加密码保护。在这里，我发现 Ubuntu 和 CentOS 之间又有一个不同之处。

在 CentOS 的所有菜单项中，您将看到`--unrestricted`选项已经存在于所有菜单项中。这意味着默认情况下，所有用户都被允许启动每个菜单选项，即使您设置了超级用户密码：

```
menuentry 'CentOS Linux (3.10.0-693.11.1.el7.x86_64) 7 (Core)' --class centos --class gnu-linux --class gnu --class os --unrestricted $menuentry_id_option 'gnulinux-3.10.0-693.el7.x86_64-advanced-f338b70d-ff57-404e-a349-6fd84ad1b692' {
```

因此，在 CentOS 上，如果您希望所有用户都能够使用所有可用的引导选项，则无需进行任何操作。

现在，假设您有一个`menuentry`，您希望所有人都能访问。在 CentOS 上，就像我刚指出的那样，您无需做任何事情。在 Ubuntu 上，添加`--unrestricted`到`menuentry`，就像您之前所做的那样：

```
menuentry 'Ubuntu' --class ubuntu --class gnu-linux --class gnu --class os $menuentry_id_option 'gnulinux-simple-f0f002e8-16b2-45a1-bebc-41e518ab9497' --unrestricted {
```

如果您希望除超级用户之外没有其他用户能够从特定选项启动，请添加`--users ""`。（在 CentOS 上，请务必首先删除`--unrestricted`选项。）

```
menuentry 'Ubuntu, with Linux 4.4.0-98-generic (recovery mode)' --class ubuntu --class gnu-linux --class gnu --class os $menuentry_id_option 'gnulinux-4.4.0-98-generic-recovery-f0f002e8-16b2-45a1-bebc-41e518ab9497' --users "" {
```

如果您只希望超级用户和其他特定用户能够从某个选项启动，请添加`--users`，后跟用户名。（同样，在 CentOS 上，首先删除`--unrestricted`选项。）：

```
menuentry 'Ubuntu, with Linux 4.4.0-97-generic' --class ubuntu --class gnu-linux --class gnu --class os $menuentry_id_option 'gnulinux-4.4.0-97-generic-advanced-f0f002e8-16b2-45a1-bebc-41e518ab9497' --users goldie {
```

如果您有多个用户希望访问引导选项，请在`### BEGIN /etc/grub.d/40_custom ###`部分为新用户添加条目。然后，将新用户添加到您希望其访问的`menuentry`中。使用逗号分隔用户名：

```
menuentry 'Ubuntu, with Linux 4.4.0-97-generic' --class ubuntu --class gnu-linux --class gnu --class os $menuentry_id_option 'gnulinux-4.4.0-97-generic-advanced-f0f002e8-16b2-45a1-bebc-41e518ab9497' --users goldie,frank {
```

保存文件并重新启动以尝试不同的选项。

既然我们已经做了这么多工作，我需要再次提醒您，您对`grub.cfg`文件所做的任何手动编辑都将在生成新的`grub.cfg`时丢失。因此，每当您进行包括安装或删除内核的系统更新时，您都需要手动编辑此文件，以重新添加密码保护。（事实上，我让您将用户及其密码添加到`/etc/grub.d/40_custom`文件的唯一真正原因是，这样您将始终可以将该信息复制并粘贴到`grub.cfg`中。）我希望有一种更加优雅的方法来做到这一点，但根据官方 GRUB 2 文档，这是不可能的。

您将在官方 GRUB 2 文档的安全部分找到[`www.gnu.org/software/grub/manual/grub/grub.html#Security`](http://www.gnu.org/software/grub/manual/grub/grub.html#Security)。

在我们离开这个话题之前，我想分享一下我对 GRUB 2 的个人看法。

由于旧的传统版本无法与新的基于 UEFI 的主板配合使用，因此有必要创建一个新版本的 GRUB。但是，GRUB 2 也有一些令人失望的地方。

首先，与传统的 GRUB 不同，GRUB 2 在所有 Linux 发行版上的实现并不一致。事实上，我们在演示中刚刚看到，当我们从 CentOS 切换到 Ubuntu 时，我们必须以不同的方式进行操作。

接下来是 GRUB 2 开发人员给我们提供了一些良好的安全选项，但他们并没有给我们提供一种优雅的实现方式。我是说，真的。通过手动编辑一个在每次操作系统更新时都会被覆盖的文件来实现安全功能的整个想法似乎并不正确。

最后，还有 GRUB 2 文档的可悲状态。我并不是要自吹自擂，因为我知道那是不合适的。然而，我认为可以肯定地说，这是你在任何地方找到的唯一全面的 GRUB 2 密码保护功能的写作。

# 安全配置 BIOS/UEFI

这个主题与我们迄今为止看到的任何内容都不同，因为它与操作系统无关。相反，我们现在要谈论的是计算机硬件。

每个计算机主板都有一个 BIOS 或 UEFI 芯片，它存储了计算机的硬件配置和启动引导指令，这些指令在打开电源后启动引导过程所需。UEFI 已经取代了较新主板上的老式 BIOS，并且它比老式 BIOS 具有更多的安全功能。

关于 BIOS/UEFI 设置，我无法给你任何具体的信息，因为每个主板型号的操作方式都不同。我可以给你一些更一般化的信息。

当你考虑 BIOS/UEFI 安全时，你可能会考虑禁用从除了正常系统驱动器以外的任何引导设备引导的能力。在下面的截图中，你可以看到我已经禁用了除了连接系统驱动器的 SATA 驱动器端口之外的所有 SATA 驱动器端口：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sec-hdn/img/bc13e849-eebf-4750-8694-d50766666987.png)

当计算机放在公众可以轻易物理接触的地方时，这可能需要考虑。对于被锁在安全房间并且访问受限的服务器，除非某个监管机构的安全要求另有规定，否则没有真正的理由担心。对于放在公开场所的机器，整个磁盘加密可以防止有人在从光盘或 USB 设备引导后窃取数据。然而，你可能仍有其他原因阻止任何人从这些备用引导设备引导机器。

另一个考虑因素可能是，如果你在处理超敏感数据的安全环境中工作。如果你担心未经授权的敏感数据外泄，你可能考虑禁用写入 USB 设备的能力。这也将阻止人们从 USB 设备引导机器：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sec-hdn/img/6c8bdae5-cfa5-4774-9fef-d42a672537e1.png)

然而，BIOS/UEFI 安全不仅仅是这些。今天的现代服务器 CPU 配备了各种安全功能，以帮助防止数据泄露。例如，让我们看一下实现在 Intel Xeon CPU 中的安全功能清单：

+   身份保护技术

+   高级加密标准新指令

+   可信执行技术

+   硬件辅助虚拟化技术

AMD，在 CPU 市场上的勇敢的小角色，他们在他们的新一代 EPYC 服务器 CPU 中有自己的新安全功能。这些功能包括：

+   安全内存加密

+   安全加密虚拟化

无论如何，你都会在服务器的 UEFI 设置实用程序中配置这些 CPU 安全选项。

你可以在[`www.intel.com/content/www/us/en/data-security/security-overview-general-technology.html`](https://www.intel.com/content/www/us/en/data-security/security-overview-general-technology.html)上阅读关于 Intel Xeon 安全功能的信息。

而且，你可以在[`semiaccurate.com/2017/06/22/amds-epyc-major-advance-security/`](https://semiaccurate.com/2017/06/22/amds-epyc-major-advance-security/)上阅读关于 AMD EPYC 安全功能的信息。

当然，对于任何放在公开场所的机器，密码保护 BIOS 或 UEFI 是个好主意：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sec-hdn/img/0f6702b0-cb20-4bf5-9d15-e62a624adaff.png)

即使没有其他原因，也要这样做以防止人们对你的设置进行篡改。

# 使用系统设置的安全检查表

我之前告诉过您 OpenSCAP，这是一个非常有用的工具，可以通过最少的努力来锁定您的系统。OpenSCAP 带有各种配置文件，您可以应用这些配置文件来帮助使您的系统符合不同监管机构的标准。但是，OpenSCAP 无法为您做某些事情。例如，某些监管机构要求您的服务器硬盘以特定方式分区，将某些目录分隔到自己的分区中。如果您已经将服务器设置为一个大分区下的所有内容，您无法通过使用 OpenSCAP 的修复程序来解决这个问题。确保服务器符合任何适用安全法规的程序必须在安装操作系统之前开始。为此，您需要适当的清单。

如果您只需要通用安全清单，有几个地方可以获取。德克萨斯大学奥斯汀分校发布了适用于 Red Hat Enterprise 7 的通用清单，您可以根据需要将其调整为适用于 CentOS 7、Oracle Linux 7 或 Scientific Linux 7。您可能会发现某些清单项目不适用于您的情况，您可以根据需要进行调整：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sec-hdn/img/b39cd887-9904-46c2-837e-3112238c1106.png)

对于特定的业务领域，您需要从适用的监管机构获取清单。如果您在金融领域工作或与接受信用卡支付的企业合作，您将需要来自支付卡行业安全标准委员会的清单：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sec-hdn/img/a43c0b90-2003-4f78-9896-4ad1c464a50a.png)

而对于美国的医疗保健机构，有其要求的 HIPAA。对于美国的上市公司，有其要求的萨班斯-奥克斯利法：

您可以在以下网址获取德克萨斯大学的清单：[`wikis.utexas.edu/display/ISO/Operating+System+Hardening+Checklists`](https://wikis.utexas.edu/display/ISO/Operating+System+Hardening+Checklists)。

您可以在以下网址获取 PCI-DSS 清单：[`www.pcisecuritystandards.org/`](https://www.pcisecuritystandards.org/).

您可以在以下网址获取 HIPAA 清单：[`www.hipaainstitute.com/security-checklist.`](https://www.hipaainstitute.com/security-checklist)

而且，您可以在以下网址获取萨班斯-奥克斯利清单：[`www.sarbanes-oxley-101.com/sarbanes-oxley-checklist.htm`](http://www.sarbanes-oxley-101.com/sarbanes-oxley-checklist.htm)。

其他监管机构可能也有他们自己的清单。如果您知道您必须处理其中任何一个，请务必获取适当的清单。

# 摘要

再次，我们已经结束了另一个章节，并涵盖了许多有趣的话题。我们首先看了一些审计系统上运行的各种服务的方法，并看到了一些您可能不想看到的示例。然后，我们看到了如何使用 GRUB 2 的密码保护功能，以及在使用这些功能时我们必须处理的一些小问题。接下来，我们通过正确设置系统的 BIOS/UEFI 来改变步调，进一步锁定系统。最后，我们看了为什么我们需要通过获取和遵循适当的清单来正确开始准备建立一个强化系统。

这不仅结束了另一个章节，也结束了这本书。但是，这并不意味着您在*掌握 Linux 安全和强化*的旅程结束了。当您继续这个旅程时，您会发现还有更多需要学习的内容，还有更多内容无法适应 300 页书的范围。您未来的方向主要取决于您所在的 IT 管理领域。不同类型的 Linux 服务器，无论是 Web 服务器、DNS 服务器还是其他类型，都有自己特殊的安全要求，您将希望按照最适合您需求的学习路径。

我很享受能够陪伴你一起走过的旅程。希望你和我一样享受这段旅程。
