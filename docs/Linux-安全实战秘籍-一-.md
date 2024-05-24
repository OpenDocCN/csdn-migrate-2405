# Linux 安全实战秘籍（一）

> 原文：[`zh.annas-archive.org/md5/9B7E99EE96EAD6CC77971D4699E9954A`](https://zh.annas-archive.org/md5/9B7E99EE96EAD6CC77971D4699E9954A)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

在设置 Linux 系统时，安全性应该是所有阶段的重要组成部分。对 Linux 基础知识的良好了解对于在机器上实施良好的安全策略至关重要。

Linux 作为发行的时候并不完全安全，管理员有责任配置机器，使其更加安全。

《实用 Linux 安全食谱》将作为管理员的实用指南，并帮助他们配置更安全的机器。

如果您想了解内核配置、文件系统安全、安全身份验证、网络安全以及 Linux 的各种安全工具，那么这本书适合您。

Linux 安全是一个庞大的主题，并不是一本书就能涵盖所有内容。不过，《实用 Linux 安全食谱》将为您提供许多保护您机器的方法。

# 本书涵盖内容

第一章，Linux 安全问题，涵盖了与 Linux 相关的各种漏洞和利用。它还讨论了可以针对这些漏洞实施的安全类型。主题包括为密码保护和服务器安全准备安全策略和安全控制，以及执行 Linux 系统的漏洞评估。它还涵盖了 sudo 访问的配置。

第二章，配置安全和优化内核，侧重于配置和构建 Linux 内核及其测试的过程。涵盖的主题包括构建内核的要求、配置内核、内核安装、定制和内核调试。本章还讨论了使用 Netconsole 配置控制台。

第三章，本地文件系统安全，探讨了 Linux 文件结构和权限。它涵盖了查看文件和目录详细信息、使用 chmod 处理文件和文件权限以及实施访问控制列表等主题。本章还向读者介绍了 LDAP 的配置。

第四章，Linux 本地身份验证，探讨了在本地系统上进行用户身份验证并保持安全性。本章涵盖的主题包括用户身份验证日志记录、限制用户登录能力、监视用户活动、身份验证控制定义，以及如何使用 PAM。

第五章，远程身份验证，讨论了在 Linux 系统上远程对用户进行身份验证。本章涵盖的主题包括使用 SSH 进行远程服务器访问、禁用和启用 root 登录、在使用 SSH 时限制远程访问、通过 SSH 远程复制文件以及设置 Kerberos。

第六章，网络安全，提供有关网络攻击和安全的信息。它涵盖了管理 TCP/IP 网络、使用 Iptables 配置防火墙、阻止欺骗地址和不需要的传入流量。本章还向读者介绍了配置和使用 TCP Wrapper。

第七章，安全工具，针对可以用于 Linux 系统安全的各种安全工具或软件。本章涵盖的工具包括 sXID、PortSentry、Squid 代理、OpenSSL 服务器、Tripwire 和 Shorewall。

第八章，Linux 安全发行版，向读者介绍了一些与安全和渗透测试相关的著名 Linux/Unix 发行版。本章涵盖的发行版包括 Kali Linux、pfSense、DEFT、NST 和 Helix。

第九章，*补丁 Bash 漏洞*，探讨了 Bash shell 最著名的漏洞，即 Shellshock。它使读者了解了 Shellshock 漏洞以及其存在可能引发的安全问题。该章还告诉读者如何使用 Linux 补丁管理系统来保护他们的机器，并使他们了解在 Linux 系统中如何应用补丁。

第十章，*安全监控和日志记录*，提供了有关在 Linux 上监控日志的信息，包括本地系统和网络。本章讨论的主题包括使用 Logcheck 监控日志，使用 Nmap 进行网络监控，使用 Glances 进行系统监控，以及使用 MultiTail 监控日志。还讨论了一些其他工具，包括 Whowatch、stat、lsof、strace 和 Lynis。

# 您需要为这本书做好准备

为了充分利用本书，读者应该对 Linux 文件系统和管理有基本的了解。他们应该熟悉 Linux 的基本命令，并且了解信息安全将是一个额外的优势。

本书将包括使用 Linux 内置工具以及其他可用的开源工具进行 Linux 安全的实际示例。根据配方，读者将需要安装这些工具，如果它们尚未安装在 Linux 中。

# 这本书适合谁

*实用 Linux 安全食谱*适用于所有那些已经了解 Linux 文件系统和管理的 Linux 用户。您应该熟悉基本的 Linux 命令。了解信息安全及其对 Linux 系统的风险也有助于更容易地理解配方。

然而，即使您对信息安全不熟悉，也能轻松地跟随和理解所讨论的配方。

由于*实用 Linux 安全食谱*采用了实用的方法，按照步骤非常容易。

# 章节

在本书中，您会经常看到几个标题（准备好、如何做、工作原理、还有更多、另请参阅）。

为了清晰地说明如何完成一个配方，我们使用以下部分：

## 准备好

本节告诉您在配方中可以期待什么，并描述如何设置配方所需的任何软件或任何预备设置。

## 如何做...

本节包含了跟随配方所需的步骤。

## 工作原理...

本节通常包括对前一节发生的事情的详细解释。

## 还有更多...

本节包含了有关配方的额外信息，以便使读者对配方更加了解。

## 另请参阅

本节提供了有关配方的其他有用信息的链接。

# 约定

在本书中，您会发现许多区分不同类型信息的文本样式。以下是这些样式的一些示例及其含义的解释。

文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下：“`md5sum`命令然后会在一行中打印出计算出的哈希值。”

任何命令行输入或输出都以以下形式书写：

```
telinit 1

```

**新术语**和**重要单词**以粗体显示。例如，屏幕上看到的菜单或对话框中的单词会以这种形式出现在文本中：“导航到**主菜单** | **回溯** | **利用工具** | **网络利用工具** | **Metasploit 框架** | **Msfconsole**。”

### 注意

警告或重要提示会以这样的方式出现在一个框中。

### 提示

提示和技巧会以这种形式出现。


# 第一章：Linux 安全问题

在本章中，我们将讨论以下内容：

+   Linux 的安全策略

+   配置密码保护

+   配置服务器安全性

+   使用校验和对安装介质进行完整性检查

+   使用 LUKS 磁盘加密

+   使用 sudoers – 配置 sudo 访问

+   使用 Nmap 扫描主机

+   在易受攻击的 Linux 系统上获取 root 权限

# 介绍

Linux 机器的安全性取决于管理员的配置。一旦我们完成了 Linux 操作系统的安装，并在安装完成后删除了不必要的软件包，我们可以开始处理软件的安全性以及 Linux 机器提供的服务方面。

# Linux 的安全策略

安全策略是定义了组织中设置计算机网络安全的规则和实践。安全策略还定义了组织应该如何管理、保护和分发敏感数据。

## 制定安全策略

在制定安全策略时，我们应该牢记它应该对所有用户简单易懂。政策的目标应该是在保护数据的同时保持用户的隐私。

它应该围绕这些要点展开：

+   对系统的可访问性

+   系统上的软件安装权限

+   数据权限

+   从故障中恢复

在制定安全策略时，用户应该只使用已获得许可的服务。不允许的任何事物都应该在政策中受到限制。

# 配置密码保护

在任何系统中，密码在安全方面起着非常重要的作用。弱密码可能导致组织资源被 compromise。密码保护政策应该被组织中的每个人遵守，从用户到管理员级别。

## 如何做到…

在选择或保护密码时，请遵循给定的规则。

对于创建策略，请遵循以下规则：

+   用户不应该在组织中的所有账户上使用相同的密码。

+   所有与访问相关的密码都不应该相同

+   任何系统级别的账户的密码都应该与同一用户拥有的其他账户不同

对于保护策略，请遵循以下规则：

+   密码是需要被视为敏感和机密信息的东西。因此，不应该与任何人分享。

+   密码不应该通过电子通信（如电子邮件）分享。

+   永远不要在电话或问卷调查中透露密码。

+   不要使用可能为攻击者提供线索的密码提示。

+   永远不要与任何人分享公司密码，包括管理人员、经理、同事，甚至家人。

+   不要在办公室的任何地方以书面形式存储密码。如果在移动设备上存储密码，始终使用加密。

+   不要使用应用程序的“记住密码”功能。

+   如果怀疑密码被 compromise，立即报告事件并尽快更改密码。

对于更改策略，请遵循以下规则：

+   所有用户和管理员必须定期更改密码，或者至少每季度更改一次

+   组织的安全审计团队必须进行随机检查，以检查任何用户的密码是否可以被猜测或破解。

## 它是如何运作的…

通过前述要点的帮助，确保密码在创建或更改时不容易被猜测或破解。

# 配置服务器安全性

对 Linux 服务器进行恶意攻击的一个主要原因是安全性实施不当或现有的漏洞。在配置服务器时，安全策略需要得到适当的实施，并且需要承担责任以便正确定制服务器。

## 如何做到…

一般政策：

+   组织内所有内部服务器的管理是专门团队的责任，该团队还应该密切关注任何合规性。如果发生任何合规性，团队应相应地实施或审查安全策略。

+   在配置内部服务器时，必须以这样的方式注册服务器，以便可以根据以下信息识别服务器：

+   服务器的位置

+   操作系统版本及其硬件配置

+   正在运行的服务和应用程序

+   组织管理系统中的任何信息都必须始终保持最新。

配置策略：

+   服务器上的操作系统应按照 InfoSec 批准的指南进行配置。

+   尽可能禁用未使用的任何服务或应用程序。

+   对服务器上的所有服务和应用程序的所有访问都应进行监控和记录。它们还应通过访问控制方法进行保护。这方面的示例将在第三章中进行介绍，*本地文件系统安全*。

+   系统应保持更新，并且应尽快安装任何最近的安全补丁（如果有的话）。

+   尽量避免使用 root 帐户。最好使用需要最少访问权限来执行功能的安全原则。

+   任何特权访问必须尽可能通过安全通道连接（SSH）进行。

+   应在受控环境中访问服务器。

监控策略：

+   服务器系统上的所有与安全相关的操作必须记录，并且审计报告应保存如下：

+   所有与安全相关的日志应在线保存 1 个月

+   在 1 个月的时间内，应保留每日备份以及每周备份

+   至少保留 2 年的完整月度备份

+   任何与安全有关的事件应报告给 InfoSec 团队。然后他们将审查日志并向 IT 部门报告事件。

+   一些与安全相关的事件的示例如下：

+   与端口扫描相关的攻击

+   未经授权访问特权帐户

+   由于主机上存在特定应用程序而导致的异常事件

## 工作原理…

遵循前述政策有助于对组织拥有或运营的内部服务器进行基本配置。有效实施该政策将最大程度地减少对敏感和专有信息的未经授权访问。

## 还有更多内容…

在谈论 Linux 安全时，还有一些其他要发现的事情。

# 安全控制

当我们谈论保护 Linux 机器时，应始终从遵循清单开始，以帮助加固系统。清单应该是这样的，遵循它将确认适当的安全控制的实施。

# 使用校验和对安装介质进行完整性检查

每当我们下载任何 Linux 发行版的镜像文件时，都应始终检查其正确性和安全性。可以通过将下载的镜像的 MD5 校验和与正确镜像的 MD5 值进行比较来实现这一点。

这有助于检查下载文件的完整性。通过 MD5 哈希比较可以检测到文件的任何更改。

每当下载文件发生更改时，MD5 哈希比较可以检测到。文件越大，文件更改的可能性就越高。建议对诸如光盘上的操作系统安装文件之类的文件进行 MD5 哈希比较。

## 准备工作

大多数 Linux 发行版通常已安装了 MD5 校验和，因此不需要安装。

## 操作步骤…

1.  首先打开 Linux 终端，然后使用`ubuntu@ubuntu-desktop:~$ cd Downloads`命令将目录更改为包含下载的 ISO 文件的文件夹。

### 注意

Linux 区分大小写，请为文件夹名称输入正确的拼写。在 Linux 中，*Downloads*与*downloads*不同。

1.  切换到`Downloads`目录后，键入以下命令：

```
md5sum ubuntu-filename.iso

```

1.  然后，`md5sum`命令将以单行打印计算出的哈希，如下所示：

```
8044d756b7f00b695ab8dce07dce43e5 ubuntu-filename.iso

```

现在，我们可以将前面命令计算的哈希与 UbuntuHashes 页面上的哈希进行比较（[`help.ubuntu.com/community/UbuntuHashes`](https://help.ubuntu.com/community/UbuntuHashes)）。打开 UbuntuHashes 页面后，我们只需要在浏览器的*查找*框中复制前面计算的哈希（按下*Ctrl* + *F*）。

## 工作原理…

如果计算出的哈希与 UbuntuHashes 页面上的哈希匹配，则下载的文件没有损坏。如果哈希不匹配，则可能是下载的文件或下载的服务器出了问题。尝试重新下载文件。如果问题仍然存在，建议您向服务器管理员报告问题。

## 另请参阅

如果您想要额外的东西，可以尝试一下 Ubuntu 可用的 GUI 校验和计算器

有时，使用终端执行校验和真的很不方便。您需要知道已下载文件的正确目录以及确切的文件名。这使得很难记住确切的命令。

作为解决方案，有一个名为**GtkHash**的非常小型和简单的软件。

您可以从[`gtkhash.sourceforge.net/`](http://gtkhash.sourceforge.net/)下载该工具，并使用此命令进行安装：

```
sudo apt-get install gtkhash

```

# 使用 LUKS 磁盘加密

在小型企业和政府办公室等企业中，用户可能需要保护其系统以保护其私人数据，包括客户详细信息、重要文件、联系方式等。为此，Linux 提供了大量的加密技术，可用于保护硬盘或可移动介质上的数据。其中一种加密技术使用**Linux 统一密钥设置**-磁盘格式（**LUKS**）。该技术允许对 Linux 分区进行加密。

LUKS 具有以下功能：

+   可以使用 LUKS 对整个块设备进行加密。它非常适合保护可移动存储介质或笔记本电脑硬盘驱动器上的数据。

+   一旦加密，加密块设备的内容就是随机的，因此对于加密交换设备非常有用。

+   LUKS 使用现有的设备映射器内核子系统。

+   它还提供了一个口令强化器，有助于防范字典攻击。

## 准备就绪

为了使以下过程工作，需要在安装 Linux 时在单独的分区上创建`/home`。

### 提示

**警告**

使用给定的步骤配置 LUKS 将删除正在加密的分区上的所有数据。因此，在开始使用 LUKS 的过程之前，请务必将数据备份到外部来源。

## 如何操作…

要手动加密目录，请按照以下步骤进行：

1.  切换到运行级别 1。在 shell 提示符或终端中键入以下命令：

```
telinit 1

```

1.  现在，使用此命令卸载当前的`/home`分区：

```
umount /home

```

1.  如果有任何控制`/home`的进程，前面的命令可能会失败。使用`fuser`命令找到并终止任何此类进程：

```
fuser -mvk /home

```

1.  检查确认`/home`分区现在未挂载：

```
grep home /proc/mounts

```

1.  现在，将一些随机数据放入分区：

```
shred -v --iterations=1 /dev/MYDisk/home

```

1.  前面的命令可能需要一些时间才能完成，所以请耐心等待。所花费的时间取决于您设备的写入速度。

1.  一旦前面的命令完成，初始化分区：

```
cryptsetup --verbose --verify-passphrase luksFormat /dev/MYDisk/home

```

1.  打开新创建的加密设备：

```
cryptsetup luksOpen /dev/MYDisk/home 

```

1.  检查确认设备是否存在：

```
ls -l /dev/mapper | grep home

```

1.  现在创建文件系统：

```
mkfs.ext3 /dev/mapper/home

```

1.  然后，挂载新的文件系统：

```
mount /dev/mapper/home /home

```

1.  确认文件系统仍然可见：

```
df -h | grep home

```

1.  在`/etc/crypttab`文件中输入以下行：

```
home /dev/MYDisk/home none

```

1.  在`/etc/fstab`文件中进行更改，删除`/home`的条目并添加以下行：

```
/dev/mapper/home /home ext3 defaults 1 2

```

1.  完成后，运行此命令以恢复默认的 SELinux 安全设置：

```
/sbin/restorecon -v -R /home

```

1.  重新启动机器：

```
shutdown -r now

```

1.  重启后，系统将在启动时提示我们输入 LUKS 密码。您现在可以以 root 身份登录并恢复您的备份。

恭喜！您已成功创建了一个加密分区。现在，即使计算机关闭，您也可以保持所有数据的安全。

## 工作原理…

我们首先进入运行级别 1 并卸载`/home`分区。卸载后，在`/home`分区中填充一些随机数据。然后，我们使用`cryptsetup`命令对分区进行初始化并加密。

加密完成后，我们再次挂载文件系统，然后在`/etc/crypttab`文件中添加分区的条目。此外，编辑`/etc/fstab`文件以添加前面加密的分区的条目。

完成所有步骤后，我们已恢复了 SELinux 的默认设置。

这样做，系统将始终在启动时要求输入 LUKS 密码。

# 利用 sudoers – 配置 sudo 访问权限

每当系统管理员希望为受信任的用户提供对系统的管理访问权限，而不共享 root 用户的密码时，他们可以使用`sudo`机制来实现。

一旦用户使用`sudo`机制获得访问权限，他们可以通过在命令前加上`sudo`来执行任何管理命令。然后，用户将被要求输入他们自己的密码。之后，管理命令将以与 root 用户相同的方式执行。

## 准备工作

由于配置文件是预定义的，使用的命令是内置的，在开始这些步骤之前不需要额外配置。

## 操作步骤…

1.  我们将首先创建一个普通帐户，然后给予它`sudo`访问权限。完成后，我们将能够从新帐户使用`sudo`命令，然后执行管理命令。按照给定的步骤配置`sudo`访问权限。首先，使用 root 帐户登录系统。然后，使用`useradd`命令创建用户帐户，如下图所示：![操作步骤…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_01_01.jpg)

在前面的命令中，用任何您选择的名称替换`USERNAME`。

1.  现在，使用`passwd`命令为新用户帐户设置密码。![操作步骤…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_01_02.jpg)

1.  通过运行`visudo`编辑`/etc/sudoers`文件。使用`sudo`命令时应用的策略由`/etc/sudoers`文件定义。![操作步骤…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_01_03.jpg)

1.  一旦文件在编辑器中打开，搜索以下允许`test`组中的用户使用`sudo`访问的行：![操作步骤…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_01_04.jpg)

1.  我们可以通过删除第二行开头的注释字符(`#`)来启用给定的配置。一旦更改完成，保存文件并退出编辑器。现在，使用`usermod`命令，将先前创建的用户添加到`test`组。![操作步骤…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_01_05.jpg)

1.  我们需要检查前面截图中显示的配置是否允许新用户帐户使用`sudo`运行命令。

1.  使用`su`选项切换到新创建的用户帐户。![操作步骤…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_01_06.jpg)

1.  现在，使用`groups`命令确认`test`组中存在用户帐户。![操作步骤…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_01_07.jpg)

最后，使用新帐户从`sudo`运行`whoami`命令。由于我们是第一次使用新用户帐户执行使用`sudo`的命令，`sudo`命令将显示默认的横幅消息。屏幕还会要求输入用户帐户密码。

![操作步骤…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_01_08.jpg)

1.  前面输出的最后一行是`whoami`命令返回的用户名。如果`sudo`配置正确，这个值将是`root`。

您已成功配置了一个具有`sudo`访问权限的用户。您现在可以登录到这个用户帐户，并使用`sudo`来运行命令，就像您从根用户那里一样。

## 它是如何工作的…

当我们创建一个新帐户时，它没有权限运行管理员命令。但是，在编辑`/etc/sudoers`文件并对新用户帐户授予`sudo`访问的适当条目后，我们可以开始使用新用户帐户运行所有管理员命令。

## 还有更多…

以下是您可以采取的额外措施，以确保总体安全。

### 漏洞评估

漏洞评估是通过审计我们的网络和系统安全性来了解我们网络的机密性、完整性和可用性的过程。漏洞评估的第一阶段是侦察，这进一步导致了系统准备阶段，我们主要检查目标中所有已知的漏洞。下一个阶段是报告，我们将所有发现的漏洞分为低、中和高风险的类别。

# 使用 Nmap 扫描主机

Nmap 是 Linux 中包含的最流行的工具之一，可用于扫描网络。它已经存在多年，迄今为止，它是收集有关网络信息的最可取的工具之一。

Nmap 可以被管理员用于他们的网络上找到任何开放的端口和主机系统。

在进行漏洞评估时，Nmap 无疑是一个不可或缺的工具。

## 准备就绪

大多数 Linux 版本都安装了 Nmap。第一步是使用以下命令检查您是否已经拥有它：

```
nmap –version

```

如果 Nmap 存在，你应该看到类似于这里显示的输出：

![准备就绪](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_01_17.jpg)

如果尚未安装 Nmap，可以从[`nmap.org/download.html`](https://nmap.org/download.html)下载并安装它

## 如何做…

按照以下步骤使用 Nmap 扫描主机：

1.  Nmap 最常见的用途是找到给定 IP 范围内的所有在线主机。用于执行此操作的默认命令需要一些时间来扫描完整的网络，这取决于网络中存在的主机数量。但是，我们可以优化这个过程，以便更快地扫描范围。

以下截图向您展示了一个例子：

![如何做…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_01_09.jpg)

1.  在前面的例子中，扫描完成所用的时间为 6.67 秒，扫描了 100 个主机。如果要扫描特定网络的整个 IP 范围，将需要更多的时间。

1.  现在，让我们试着加快这个过程。`n`开关告诉 Nmap 不执行 IP 地址的 DNS 解析，从而使过程更快。`T`开关告诉 Nmap 以什么速度运行。在这里，`T1`是最慢的，`T5`是最快的。`max-rtt-timeout`选项指定等待响应的最长时间。

现在，相同的命令在这个例子中显示如下：

![如何做…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_01_10.jpg)

这一次，Nmap 在 1.97 秒内扫描了完整的 IP 范围。相当不错，对吧？

1.  使用 Nmap 进行端口扫描有助于我们发现在线的服务，比如找到 FTP 服务器。要做到这一点，使用以下命令：![如何做…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_01_11.jpg)

Nmap 的前面的命令将列出所有开放端口 21 的 IP 地址。

1.  不仅 FTP，其他服务也可以通过匹配它们运行的端口号来发现。例如，MySQL 运行在端口 3306 上。命令现在将如下所示：![如何做…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_01_12.jpg)

## 它是如何工作的…

Nmap 通过测试最常见的网络通信端口来检查正在监听的服务。这些信息有助于网络管理员关闭任何不需要或未使用的服务。前面的例子向您展示了如何使用端口扫描和 Nmap 作为研究我们周围网络的强大工具。

## 另请参阅

Nmap 还具有脚本功能，可以编写自定义脚本。这些脚本可以与 Nmap 一起使用，自动化和扩展其扫描能力。您可以在其官方主页[`nmap.org/`](https://nmap.org/)上找到有关 Nmap 的更多信息。

# 在易受攻击的 Linux 系统上获得 root 权限

学习如何扫描和利用 Linux 机器时，我们遇到的一个主要问题是在哪里学习。为此，Metasploit 团队开发并发布了一个名为**Metasploitable**的 VMware 机器。这台机器被故意制作成易受攻击，并且有许多未打补丁的服务在运行。因此，它成为了一个练习或开发渗透测试技能的绝佳平台。在本节中，您将学习如何扫描 Linux 系统，然后使用扫描结果找到一个有漏洞的服务。利用这个有漏洞的服务，我们将获得对系统的 root 访问权限。

## 准备工作

本节将使用 Backtrack 5R2 和 Metasploitable VMware 系统。Metasploitable 的镜像文件可以从[`sourceforge.net/projects/metasploitable/files/Metasploitable2/`](http://sourceforge.net/projects/metasploitable/files/Metasploitable2/)下载。

## 操作步骤…

按照以下步骤获得对易受攻击的 Linux 系统的 root 访问权限：

1.  首先，通过以下菜单在 backtrack 系统上打开 Metasploit 控制台：导航到**Main Menu** | **Backtrack** | **Exploitation Tools** | **Network Exploitation Tools** | **Metasploit Framework** | **Msfconsole**。

1.  接下来，我们需要使用 Nmap 扫描目标（在本例中是`192.168.0.1`）：

这张图片显示了执行的命令的输出：

![如何操作…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_01_13.jpg)

在上述命令中，`-Ss`选项允许我们执行隐蔽扫描，`-A`选项尝试发现操作系统和服务的版本信息。

此外，在上述命令中，我们可以看到许多服务在不同的端口上运行。其中包括运行在端口 139 和 445 上的 Samba。

### 注意

请注意，Samba 是一个为 Windows 系统提供 SMB 文件和打印服务的服务。

1.  一旦我们能够找到 Samba 服务，我们现在将专注于它。从上述输出中，我们可以看到 Samba 运行的是 3.x 版本。现在，我们将尝试获取有关服务的更具体信息。为此，我们将使用 Metasploit 的任何辅助模块，比如扫描器部分，并寻找 SMB 协议。![如何操作…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_01_14.jpg)

1.  我们可以看到扫描器部分有一个 SMB 版本检测器。现在，我们将使用 SMB 检测程序获得 Samba 的确切版本。如果我们在线搜索特定版本的 Samba 的所有漏洞，我们将找到用户名 map script。

1.  我们现在可以在 Metasploit 提供的漏洞列表中搜索`map script`用户名是否存在漏洞，使用`search samba`命令。![如何操作…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_01_15.jpg)

1.  我们已经找到了 map script 用户名的一个漏洞利用，并且它的评分非常优秀，这意味着我们可以使用这个漏洞利用。

1.  现在，使用 map script 用户名在系统中获得 root 级别的 shell。![如何操作…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_01_16.jpg)

现在，我们将使用上述漏洞利用获得对系统的 root 级别访问权限。一旦我们选择了漏洞利用并配置了目标 IP 地址（在本例中是`192.168.0.1`），我们将执行一个命令来运行漏洞利用。这将在目标系统上创建并给我们一个远程会话，并打开一个命令 shell。现在，在远程 shell 中运行`id`命令。这将给出一个结果—`uid=0(root)gid=0(root)`。这证实我们已经对目标系统具有远程 root 访问权限。

## 它是如何工作的

我们首先执行了 Nmap 扫描，以检查运行的服务和开放的端口，并发现 Samba 服务正在运行。然后，我们尝试找到 SMB 服务的版本。一旦获得这些信息，我们就搜索了 Samba 的任何利用。使用利用漏洞，我们试图攻击目标系统，并在其中获得了 root shell。

## 还有更多…

让我们了解一些特有于 Linux 的更多利用和攻击。

在本节中，我们将介绍 Linux 容易受到的一些常见利用和攻击。但是，在本节中，我们不会涵盖任何处理攻击的方法。本节只是让您了解 Linux 中常用的利用。

### 空密码或默认密码

通常，管理员使用供应商提供给他们的默认密码，或者甚至将管理密码留空。这主要发生在配置设备（如路由器）和 BIOS 时。甚至一些在 Linux 上运行的服务可能包含默认的管理员密码。建议您始终更改默认密码，并设置一个只有管理员知道的新密码。

### IP 欺骗

攻击者可以在我们的系统和服务器上找到漏洞，并利用这些漏洞安装后台程序或攻击网络。如果攻击者以一种使其看起来像是本地网络中的一个节点的方式连接他的系统到我们的网络，就可以实现这一点。在执行 IP 欺骗时，有各种工具可用于帮助黑客。

### 窃听

攻击者可以通过窃听来收集在网络上进行通信的两个活动节点之间传递的数据。这种类型的攻击主要适用于 Telnet、FTP 和 HTTP 等协议。这种攻击可以在远程攻击者已经可以访问网络上的任何系统时进行。这可以通过其他攻击，如中间人攻击来实现。

#### 服务漏洞

如果攻击者能够发现网络系统上运行的任何服务的缺陷或漏洞，他们可以 compromise 整个系统及其数据以及网络上的其他系统。

管理员应该及时了解网络系统上运行的任何服务或应用程序的可用补丁或更新。

#### 拒绝服务（DoS）攻击

当攻击者向目标系统发送未经授权的数据包（可以是服务器、路由器或工作站），并且数量很大时，会导致资源对合法用户不可用。

攻击者发送的数据包通常是伪造的，这使得调查过程变得困难。


# 第二章：配置安全和优化内核

在本章中，我们将讨论以下内容：

+   构建和使用内核的要求

+   创建 USB 引导介质

+   检索内核源代码

+   配置和构建内核

+   安装和引导内核

+   测试和调试内核

+   使用 Netconsole 配置控制台进行调试

+   引导时调试内核

# 介绍

对于包括 Ubuntu、CentOS 和 Fedora 在内的所有 Linux 发行版，内核都是至关重要的。在大多数 Linux 版本安装操作系统时，默认安装内核，因此我们通常不必编译内核。即使需要安装内核的关键更新，也可以在 Linux 系统上使用`apt-get`或`yum`来完成。

但是，可能会有一些情况需要我们自己从源代码编译内核。以下是其中的一些情况：

+   启用内核中的实验性功能

+   启用新的硬件支持

+   调试内核

+   探索内核源代码

# 构建和使用内核的要求

在我们开始构建 Linux 内核之前，我们必须确保 Linux 系统存在工作的引导介质。如果引导加载程序未正确配置，可以用它来引导进入 Linux 系统。您将学习如何创建 USB 引导介质，检索内核源代码，配置和构建内核，并执行内核的安装和引导。

# 创建 USB 引导介质

可以在格式为 ext2、ext3 或 VFAT 的任何 USB 存储介质上创建 USB 引导介质。还要确保设备上有足够的可用空间，从传输发行版 DVD 映像需要 4GB，传输发行版 CD 映像需要 700MB，或者只需 10MB 来传输最小的引导介质映像。

## 做好准备

在执行这些步骤之前，我们需要有 Linux 安装光盘的映像文件，我们可以将其命名为`boot.iso`，以及一个 USB 存储设备，如前所述。

## 如何做…

要创建 USB 引导介质，我们需要以 root 身份执行这些命令：

1.  首先，我们需要通过在 USB 存储设备上执行以下命令来安装`syslinux`引导加载程序：

```
syslinux /dev/sdb1

```

1.  现在，通过执行以下命令为`boot.iso`文件和 USB 存储设备创建挂载点：

```
mkdir /mnt/isoboot /mnt/diskboot

```

1.  接下来，将`boot.iso`文件挂载到为其创建的挂载点上：

```
mount –o loop boot.iso /mnt/isoboot

```

在上述命令中，使用`-o loop`选项创建一个伪设备，它充当基于块的设备。它将文件视为块设备。

1.  接下来，我们将挂载为其创建的挂载点上的 USB 存储设备：

```
mount /dev/sdb1 /mnt/diskboot

```

1.  一旦`boot.iso`和 USB 存储设备都被挂载，我们将从`boot.iso`复制`isolinux`文件到 USB 存储设备：

```
cp /mnt/isoboot/isolinux/* /mnt/diskboot

```

1.  接下来，运行命令，使用`boot.iso`中的`isolinux.cfg`文件作为 USB 存储设备的`syslinux.cfg`文件：

```
grep –v local /mnt/isoboot/isolinux/isolinux.cfg > /mnt/diskboot/syslinux.cfg

```

1.  完成上一个命令后，卸载`boot.iso`和 USB 存储设备：

```
unmount /mnt/isoboot /mnt/diskboot

```

1.  现在，重新启动系统，然后尝试使用 USB 引导介质引导系统，以验证我们能够使用它引导。

## 它是如何工作的…

当我们从`boot.iso`文件复制所需的文件到 USB 存储介质，并使用 USB 存储介质中的`isolinux.cfg`文件作为`syslinux.cfg`文件时，它将 USB 存储介质转换为可引导的介质设备，可用于引导 Linux 系统。

# 检索内核源代码

大多数 Linux 发行版都包含内核源代码。但是，这些源代码可能会有点过时。因此，在构建或自定义内核时，我们可能需要获取最新的源代码。

## 做好准备

大多数 Linux 内核开发社区使用**Git**工具来管理源代码。即使 Ubuntu 也已经集成了 Git 用于其自己的 Linux 内核源代码，因此使内核开发人员能够更好地与社区互动。

我们可以使用以下命令安装`git`软件包：

```
sudo apt-get install git

```

## 如何做…

Linux 内核源代码可以从各种来源下载，我们将讨论从这些来源下载的方法：

+   我们可以在 Linux 内核的官方网页[`www.kernel.org`](http://www.kernel.org)上找到完整的 tarball 形式的 Linux 源代码，也可以找到增量补丁形式的源代码。

+   除非有特定原因要使用旧版本，否则建议使用最新版本。

+   Ubuntu 的内核源代码可以在 Git 下找到。内核的每个发行代码都在自己的 Git 存储库中单独维护，位于[kernel.ubuntu.com](http://kernel.ubuntu.com)上：

`git://kernel.ubuntu.com/ubuntu/ubuntu-<release>.git`或[`kernel.ubuntu.com/git-repos/ubuntu/`](http://kernel.ubuntu.com/git-repos/ubuntu/)

+   我们可以使用 Git 克隆存储库以获得本地副本。命令将根据我们感兴趣的 Ubuntu 版本进行修改。

+   要获取精确的树，请执行以下截图中显示的命令：![如何做…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_02_01.jpg)

+   使用前面图像中的命令将下载精确的树。要下载任何其他树，命令的语法将是：git clone `git://kernel.ubuntu.com/ubuntu/ubuntu-<release>`。

+   下载的文件可能是 GNU zip（`.gzip`）格式或`.bzip2`格式。下载源文件后，我们需要解压缩它。如果 tarball 是`.bzip2`格式，使用以下命令：

```
tar xvjf linux-x.y.z.tar.bz2

```

如果它是以压缩的 GNU `.gz`格式，使用以下命令：

```
tar xvzf linux-x.y.z.tar.gz

```

## 工作原理…

使用前面部分提到的不同方法，我们能够下载 Linux 内核的源代码。使用任何选项取决于用户的选择和偏好。

# 配置和构建内核

由于许多原因可能需要配置内核。我们可能希望调整内核以仅运行必要的服务，或者可能需要对其进行补丁以支持内核先前不支持的新硬件。这对于任何系统管理员来说可能是一项艰巨的任务，在本节中，我们将看看如何配置和构建内核。

## 准备工作

在任何系统的引导分区中，建议为内核留有充足的空间。我们可以选择整个磁盘安装选项，或者为引导分区留出至少 3GB 的磁盘空间。

在安装 Linux 发行版并在系统上配置开发包后，还需要为我们的用户帐户启用 root 帐户以及 sudo。

现在，在我们开始安装任何软件包之前，运行以下命令来更新系统：

```
sudo apt-get update && sudo apt-get upgrade

```

之后，检查`build-essential`软件包是否已安装。如果没有安装，可以使用以下命令进行安装：

```
sudo apt-get install build-essential

```

这个软件包用于在 x86_64 系统上构建 Linux 内核。

我们还需要一些其他要求来编译内核：

+   使用以下命令安装最新版本的`gcc`：

```
sudo apt-get install gcc

```

+   使用以下命令安装`ncurses`开发包：

```
sudo apt-get install libncurses5-dev

```

+   还可能需要一些其他软件包来交叉编译 Linux 内核：

```
sudo apt-get install binutils-multiarch
sudo apt-get install alien

```

+   接下来，安装`ncurses-dev`，这是运行 make `menuconfig`所需的：

```
sudo apt-get install ncurses-dev

```

## 如何做…

完成*准备工作*部分的步骤后，我们可以继续进行配置和构建内核的过程。这个过程会花费很多时间，所以要有所准备：

1.  通过访问[`www.kernel.org`](http://www.kernel.org)下载 Linux 内核，如下图所示：![如何做…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_02_02.jpg)

1.  也可以使用以下命令进行下载：

```
wget https://www.kernel.org/pub/linux/kernel/v4.x/linux-4.1.5.tar.xz

```

![如何做…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_02_03.jpg)

1.  下载完成后，转到下载保存的目录。

1.  如果下载的文件已保存在`Downloads`文件夹中，则应执行以下命令：![如何做…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_02_04.jpg)

1.  现在，使用以下命令将下载的`.tar`文件提取到`/usr/src/`位置：![如何操作…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_02_05.jpg)

1.  接下来，切换到使用以下命令进行提取的目录：![如何操作…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_02_06.jpg)

1.  现在，运行命令配置 Linux 内核，以便可以在系统上进行编译和安装。![如何操作…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_02_07.jpg)

1.  如果您的帐户没有管理员权限，执行上述命令之前可能需要使用`sudo`。

1.  执行上述命令后，将会弹出一个窗口，其中包含一个菜单列表。选择新配置的项目。![如何操作…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_02_08.jpg)

1.  您需要检查**文件系统**菜单。![如何操作…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_02_09.jpg)

1.  在其中，检查是否选择了`ext4`，如下截图所示。如果没有选择，现在需要选择它。![如何操作…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_02_10.jpg)

1.  然后，保存配置。![如何操作…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_02_11.jpg)

1.  现在，编译 Linux 内核。编译过程将需要大约 40 到 50 分钟的时间，具体取决于系统配置。运行如下命令：

```
make -j 5

```

![如何操作…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_02_12.jpg)

## 工作原理…

首先下载 Linux 内核源代码，然后在特定位置提取它，为编译过程配置内核。

# 安装和从内核引导

在花费了大量时间配置和编译内核之后，我们现在可以开始在本地系统上安装内核的过程。

## 准备工作

在开始安装内核之前，请确保在系统上备份所有重要数据。此外，将`/boot/`复制到以 FAT32 文件系统格式化的外部存储设备。如果安装过程因任何原因失败，这将有助于修复系统。

## 如何操作…

在内核编译完成后，我们可以开始遵循安装内核所需的命令。

1.  通过运行以下命令安装驱动程序：![如何操作…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_02_13.jpg)

上述命令将把模块复制到`/lib/`modules 的子目录中。

1.  现在，运行以下命令来安装实际的内核：

```
make install

```

![如何操作…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_02_14.jpg)

1.  此命令执行`/sbin/installkernel`。

1.  新内核将安装在`/boot/vmlinuz-{version}`中。

如果`/boot/vmlinuz`已经存在符号链接，它将通过将`/boot/vmlinuz`链接到新内核来刷新。

先前安装的内核将作为`/boot/vmlinuz.old`可用。`config`和`System.map`文件也将在相同位置可用。

1.  接下来，我们将通过运行此命令将内核复制到`/boot`目录中：

```
cp -v arch/x86/boot/bzImage /boot/vmlinuz-4.1.6

```

![如何操作…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_02_15.jpg)

1.  现在构建初始 RAM 磁盘。![如何操作…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_02_16.jpg)

1.  接下来，我们需要复制包含内核符号及其对应地址列表的`System.map`。为此，请运行以下命令，将内核的名称附加到目标文件。![如何操作…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_02_17.jpg)

1.  接下来，创建`symlink /boot/System.map`，它将指向`/boot/System.map-YourKernelName`，如果`/boot`位于支持符号链接的文件系统上。![如何操作…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_02_18.jpg)

1.  如果`/boot`位于不支持符号链接的文件系统上，只需运行此命令：

```
cp /boot/System.map-YourKernelName /boot/System.map

```

## 工作原理…

在内核配置和编译完成后，我们开始安装内核的过程。第一个命令将把模块复制到`/lib/`modules 的子目录中。

第二个命令执行`/sbin/installkernel`。同时，新内核将安装在`/boot/vmlinuz-{version}`中。在执行此操作时，如果`/boot/vmlinuz`已经存在符号链接，它将通过将`/boot/vmlinuz`链接到新内核来刷新。先前安装的内核将作为`/boot/vmlinuz.old`可用。相同的操作也适用于`config`和`System.map`文件。

一切都完成后，我们可以重新启动系统以从新内核引导。

# 测试和调试内核

任何开放或封闭的**软件开发周期**（**SDC**）的重要部分是测试和调试。这也适用于 Linux 内核。测试和调试的最终目标是确保内核在安装新的内核源代码后仍然像以前一样工作。

# 使用 Netconsole 配置用于调试的控制台

如果我们想捕获内核恐慌，一旦系统重新启动，就会变得困难，因为没有为此创建日志。为了解决这个问题，我们可以使用 Netconsole。

内核模块通过 UDP 记录内核打印消息，当登录到磁盘失败时，这对于调试问题非常有帮助。

## 准备就绪

在开始配置 Netconsole 之前，我们需要知道将发送 UDP 数据包的系统的 MAC 地址。这个系统被称为接收者，它可能在同一个子网中，也可能在不同的子网中。这两种情况在这里描述：

1.  第一种情况是接收者在同一个子网中。

1.  在本例中，接收者的 IP 地址是`192.168.1.4`。我们将向此 IP 地址发送 UDP 数据包。![准备就绪](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_02_19.jpg)

1.  现在，让我们通过执行此命令找到接收系统的 MAC 地址。在这种情况下，IP 地址是接收系统的。![准备就绪](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_02_20.jpg)

正如我们在上面的例子中看到的那样，`90:00:4e:2f:ac:ef`是我们需要的 MAC 地址。

1.  第二种情况是接收者不在同一个子网中。在这种情况下，我们需要首先找到默认网关。为此，我们运行此命令：![准备就绪](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_02_21.jpg)

1.  在这里，默认网关是`192.168.1.1`。

1.  我们需要找到默认网关的 MAC 地址。首先，以这种方式向默认网关发送一个数据包：![准备就绪](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_02_22.jpg)

1.  现在，让我们找到 MAC 地址。![准备就绪](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_02_23.jpg)

在这里，`c0:3f:0e:10:c6:be`是我们需要的默认网关的 MAC 地址。

现在我们有了接收者的 MAC 地址，我们可以开始配置 Netconsole 的过程。

## 如何做…

首先，我们需要在启动时更改内核选项。如果您使用 Grub 作为引导加载程序，默认情况下会使用`quiet splash`选项引导内核。但是，我们不希望这种情况发生。因此，我们需要更改内核选项。

1.  首先，使用以下屏幕截图中显示的命令在`/etc/default/grub`位置创建 Grub 的备份：![如何做…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_02_24.jpg)

1.  现在，打开您选择的任何编辑器以编辑`/etc/default/grub`。![如何做…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_02_25.jpg)

1.  找到`GRUB_CMDLINE_LINUX_DEFAULT="quiet splash"`一行，并将其替换为`GRUB_CMDLINE_LINUX_DEFAULT="debug ignore_loglevel"`。![如何做…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_02_26.jpg)

1.  现在，运行此命令相应地更新 Grub：![如何做…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_02_27.jpg)

1.  实施了上述命令后，我们需要在启动时初始化 Netconsole。为此，我们首先需要知道发送系统的 IP 地址和接口。可以使用以下屏幕截图中显示的命令来完成：![如何做…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_02_28.jpg)

1.  我们还需要接收系统的 IP 地址和 MAC 地址，这是我们在*准备就绪*部分中看到的。

1.  现在，让我们开始初始化 Netconsole。首先，让我们通过将模块添加到`/etc/`modules 中，使`netconsole`在启动时加载。![如何做…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_02_29.jpg)

1.  接下来，我们将确保它也配置了适当的选项。为此，我们将将模块选项添加到`/etc/modprobe.d/netconsole.conf`文件，并运行此屏幕截图中显示的命令：![如何做…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_02_30.jpg)

1.  在上述命令中，以 Netconsole 开头的部分具有以下语法：

```
netconsole=<LOCAL_PORT>@<SENDER_IP_ADDRESS>/<SENDER_INTERFACE>,<REMOTE_PORT>@<RECEIVER_IP_ADDRESS>/<STEP_1_MAC_ADDRESS>

```

我们已经为`<LOCAL_PORT>`和`<REMOTE_PORT>`都使用了`6666`。

1.  接下来，我们需要设置接收者。

根据用作接收方的 Linux 版本，用于设置它的命令可能会有所不同：

```
netcat -l -u 192.168.1.4 6666 | tee ~/netconsole.log

```

如果上述命令不起作用，尝试设置接收方而不使用 IP 地址：

```
netcat -l -u 6666 | tee ~/netconsole.log

```

1.  如果您使用的是具有不同版本 Netcat 的 Linux 变体，则在尝试使用上述命令时将打印以下错误消息：![如何操作…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_02_31.jpg)

1.  如果您收到上述错误消息，可以尝试执行此截图中显示的命令：![如何操作…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_02_32.jpg)

1.  现在，让上述命令继续运行。

1.  接下来，我们需要检查一切是否正常工作。重新启动发送系统，然后执行此截图中显示的命令：![如何操作…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_02_33.jpg)

1.  现在，您需要检查接收系统，看看内核消息是否已经接收到。

1.  一切都完成后，按下*Ctrl* + *C*。然后，您可以在`~/netconsole.log`中检查消息。

## 它是如何工作的

为了捕获内核恐慌消息，我们配置 Netconsole，通过网络记录消息。为此，我们需要在网络上再有一个作为接收方的系统。首先，我们尝试找到接收系统的 MAC 地址。然后，我们更改内核引导选项。更新 Grub 后，在我们要调试的发送系统上启动 Netconsole。最后，我们设置接收系统开始接收内核消息。

## 更多内容…

如果您正在使用 Windows 系统作为接收方，则可以使用 Windows 的**Netcat**，可在[`joncraton.org/files/nc111nt.zip`](http://joncraton.org/files/nc111nt.zip)下载。执行以下步骤设置 Windows 接收方：

1.  从给定链接下载文件，并将其解压缩到指定位置（即`C:\Users\Tajinder\Downloads\nc>`）。

1.  现在，打开命令提示符。然后，转到您提取 Netcat 的文件夹。![更多内容…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_02_34.jpg)

1.  接下来，运行此命令：![更多内容…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_02_35.jpg)

1.  这里的`192.168.1.3`与`<RECEIVER_IP_ADDRESS>`相同。

1.  让上述命令继续运行，并继续执行第 9 步中提到的命令。完成后，按下*Ctrl* + *C*。您将在`netconsole.txt`中找到消息。

# 在引导时调试内核

有时，您的系统可能无法在内核中引导更改。因此，在创建有关这些故障的报告时，包括有关调试的所有适当信息非常重要。这将对内核团队解决问题非常有用。

## 如何操作…

如果您尝试捕获引导过程中出现的错误消息，最好删除`quiet`和`splash`选项来引导内核。这有助于您查看屏幕上出现的消息（如果有）。

要编辑引导选项参数，请执行以下步骤：

1.  启动机器。

1.  在 BIOS 屏幕上，按下*Shift*键并按住。BIOS 加载后，您应该看到 Grub 菜单。![如何操作…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_02_36.jpg)

1.  导航到您想要启动的内核入口，然后按下*e*键。

1.  然后，删除`quiet`和`splash`关键字（这些可以在以 Linux 开头的行中找到）![如何操作…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_02_37.jpg)

1.  按下*Ctrl* + *x*进行启动。

您可以在屏幕上看到错误消息（如果有）。

根据您遇到的错误消息类型，您可以尝试其他引导选项。例如，如果注意到 ACPI 错误，请尝试使用`acpi=off`引导选项进行引导。


# 第三章：本地文件系统安全

在本章中，我们将讨论以下内容：

+   使用`ls`命令查看文件和目录详细信息

+   使用`chmod`命令更改文件权限

+   实施访问控制列表（ACL）

+   使用`mv`命令（移动和重命名）处理文件

+   在 Ubuntu 上安装和配置基本 LDAP 服务器

# 使用`ls`命令查看文件和目录详细信息

`ls`命令用于列出目录中的文件，类似于 DOS 中的`dir`命令。该命令可与各种参数一起使用，以提供不同的结果。

## 准备工作

由于`ls`命令是 Linux 的内置命令，因此我们无需安装其他任何内容即可使用它。

## 如何做…

现在，让我们看一下如何以不同方式使用`ls`来通过遵循这些给定步骤获得各种结果：

1.  要查看当前目录中文件的简单列表，请键入`ls：`![如何做…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_03_01.jpg)

1.  要获取有关使用`ls`命令列出的文件和目录的更多信息，请添加类型标识符，如下所示：![如何做…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_03_02.jpg)

当使用上述标识符时，可执行文件的名称末尾会有一个星号，而目录则有一个斜杠，依此类推。

1.  要查看文件的详细信息，例如创建日期、所有者和权限，请使用`l`标识符运行命令，如下所示：![如何做…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_03_03.jpg)

1.  要查找当前目录中所有隐藏文件的列表，请使用`a`标识符，如下所示：![如何做…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_03_04.jpg)

以句点开头的文件（也称为**点文件**）是隐藏文件，如果未使用`-a`选项，则不会显示这些文件。

1.  为了以可读的形式打印文件大小，例如 MB、GB、TB 等，而不是以字节打印，我们可以使用`-h`标识符以及`-l`标识符，如下所示：![如何做…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_03_05.jpg)

1.  如果您希望排除所有文件并仅显示它们的子目录，则可以使用`-d`选项，如下所示：![如何做…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_03_06.jpg)

1.  当与`-R`选项一起使用`ls`命令时，将显示子目录的内容：![如何做…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_03_07.jpg)

## 工作原理…

当我们使用`ls`命令的不同选项时，它会根据我们的要求给出不同的目录列表结果。我们可以根据需要使用任何选项。

建议您养成使用`ls -lah`的习惯，这样您就可以始终找到可读大小的列表。

# 使用`chmod`命令更改文件权限

**Change Mode**或**chmod**是 Linux 命令，用于修改文件和目录的访问权限。每个人都希望保护其数据并进行适当的组织。因此，Linux 有一个概念，将所有者和组与每个文件和目录相关联。这些所有者和组具有不同的权限来访问特定文件。

## 准备工作

在我们查看`chmod`命令的不同用法之前，我们需要了解不同类型的用户和使用的符号表示：

+   `u`用于用户/所有者

+   `g`用于组

+   `o`用于其他用户

现在，创建一个名为`testfile.txt`的文件，以尝试`chmod`的不同命令。

## 如何做…

现在，我们将看一下如何以不同方式使用`chmod`以设置不同的权限：

1.  如果我们想要更改用户（所有者、组或其他用户）的单个权限，我们使用`+`符号来添加权限，如下命令所示：

```
chmod u+x testfile.txt

```

上述命令将为文件所有者添加`执行`权限：

![如何做…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_03_17.jpg)

1.  如果我们想要添加多个权限，我们可以通过单个命令来实现。我们只需要使用逗号分隔不同的权限，如下所示：

```
chmod g+x, o+x testfile.txt

```

上述命令将为文件的组和其他用户添加`执行`权限：

![如何做…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_03_18.jpg)

1.  如果我们想要删除权限，我们只需使用`-`符号，而不是`+`，如下所示：

```
chmod o-x testfile.txt

```

这将删除特定文件的其他用户的`执行`权限：

![如何做…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_03_19.jpg)

1.  假设我们希望为所有用户（所有者、组和其他人）添加或删除权限；我们可以通过使用`a`选项来完成这个单一命令，该选项表示所有用户，如下所示：

要为所有用户添加`读`权限，请使用此命令：

```
chmod a+r testfile.txt

```

要删除所有用户的`读`权限，请使用此命令：

```
chmod a-r testfile.txt

```

这在下面的屏幕截图中显示：

![如何做…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_03_20.jpg)

1.  在这里，我们假设我们想要为目录中的所有文件添加特定权限。现在，我们可以使用`-R`选项，而不是单独为所有文件运行命令，该选项表示给定操作是递归的。因此，为了给其他用户和目录中的所有文件添加`执行`权限，命令将如下所示：

```
chmod o+x –R /example

```

看一下下面的屏幕截图

![如何做…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_03_21.jpg)

1.  要将特定文件的权限复制到另一个文件，我们可以使用`reference`选项：

```
chmod --reference=file1 file2

```

在这里，我们将`file1`的权限应用到另一个名为`file2`的文件。相同的命令也可以用于将一个目录的权限应用到另一个目录：

![如何做…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_03_22.jpg)

## 它是如何工作的…

当`chmod`与符号表示一起使用时，我们已经知道以下内容：

+   `u`用于用户/所有者

+   `g`用于组

+   `o`用于其他人

另外，不同的权限被称为如下：

+   `r`：读

+   `w`：写

+   `x`：执行

因此，使用上述命令，我们根据我们的要求更改用户、组或其他人的权限。

## 还有更多…

我们也可以使用数字来使用`chmod`设置权限，这被称为**八进制**表示。使用数字，我们可以同时编辑所有者、组和其他人的权限。命令的语法如下：

+   `chmod xxx 文件/目录`

这里，`xxx`指的是从`1`到`7`的三位数字。第一位数字表示所有者的权限，而组由第二位数字表示，第三位数字表示其他人的权限。

当我们使用八进制表示时，`r`、`w`和`x`权限具有特定的数字值，如下所述：

+   *r=4*

+   *w=2*

+   *x=1*

现在，`读`和`执行`权限表示如下：

+   *r-x = 4+0+1 = 5*

同样，`读`、`写`和`执行`权限的计算如下：

+   *rwx = 4+2+1 = 7*

如果我们只希望给予`读`权限，将如下所示：

+   *r-- = 4+0+0 = 4*

所以，现在如果我们运行以下命令，它会给出计算的权限：

```
chmod 754 testfile.txt

```

这是屏幕截图：

![还有更多…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_03_23.jpg)

# 实施访问控制列表（ACL）

使用`chmod`实现基本文件权限是不够的，因此我们可以使用 ACL。除了为特定文件的所有者和组提供权限外，我们还可以使用 ACL 为任何用户、用户组或不属于特定用户组的所有用户组设置权限。

## 准备工作

在开始使用 ACL 设置权限之前，我们需要确认 ACL 是否已启用。我们可以通过尝试查看任何文件的 ACL 来确认这一点，如本例所示：

```
getfacl<filename>

```

如果 ACL 已启用，上述命令将显示类似于以下内容的输出：

![准备工作](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_03_24.jpg)

## 如何做…

为了更好地理解 ACL，让我们执行以下步骤：

1.  首先，我们将创建三个用户并给他们命名—`user1`、`user2`和`user3`：![如何做…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_03_25.jpg)

上述命令用于更改密码信息，这是可选的。如果你愿意，你可以忽略它。但是，在这种情况下，您将需要根据需要使用特定用户的密码登录。

1.  接下来，创建一个名为`group1`的组。创建组后，我们将在此组中添加在上一步中创建的三个用户：![如何做…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_03_26.jpg)

1.  接下来，我们将创建`/example`目录并将其所有权更改为`user1`：![如何做…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_03_27.jpg)

1.  打开一个新的终端窗口并从`user1`登录。然后，切换到在上一个示例中创建的`/example`目录，并在其中创建一个任意名称的目录，比如`accounts`：![如何做…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_03_28.jpg)

1.  现在，假设`user1`想要仅在`accounts`目录中向`user2`授予`write`权限。为此，`user1`必须在组中设置`write`权限。但这样做将给`user3`也赋予写权限，我们不希望发生这种情况。因此，`user1`将使用 ACL 向`user2`授予写访问权限，如下所示：![如何做…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_03_29.jpg)

1.  现在，我们将检查`accounts`目录中的权限：![如何做…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_03_30.jpg)

我们可以看到在前面的图像中，只有`user1`和`user2`在目录中有`write`权限，其他人没有权限。

1.  打开一个新的终端并从`user2`登录。然后，切换到`/example`目录：![如何做…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_03_31.jpg)

1.  让我们尝试在`accounts`文件夹中创建一个目录。由于`user2`有`write`权限，这应该是成功的：![如何做…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_03_32.jpg)

1.  接下来，打开一个新的终端并从`user3`登录。然后，切换到`/example`目录：![如何做…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_03_33.jpg)

1.  尝试切换到`accounts`目录。由于`user3`对该目录没有任何权限，将被拒绝：![如何做…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_03_34.jpg)

## 更多信息…

我们可能希望仅为一组用户中的两个用户授予`execute`权限。如果我们使用`chmod`设置权限，所有组中的用户都将获得执行权限。然而，我们不希望这样。可以使用 ACL 来处理这种情况。

在前面的步骤中，我们为每个用户单独设置了文件的权限，从而避免了允许其他人也具有任何权限的机会。

每当处理文件权限时，如果您的文件很重要，最好备份权限。

在这里，我们假设有一个包含一些重要文件的`example`目录。然后，使用以下命令备份权限：

```
getfacl -R /example>permissions.acl

```

![更多信息…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_03_35.jpg)

前面的命令备份权限并将其存储在名为`permissions.acl`的文件中。

现在，如果我们想要恢复权限，可以使用以下命令：

```
setfacl -- restore=permission.acl

```

这在下面的截图中显示：

![更多信息…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_03_36.jpg)

这将恢复并备份所有权限到创建备份时的状态。

# 使用 mv 命令进行文件处理（移动和重命名）

当我们希望将文件从一个目录移动到另一个目录时，并且不希望在此过程中创建副本（这在使用`cp`命令时会发生），则使用**mv**或**move**命令。

## 准备就绪…

由于`mv`是 Linux 的内置命令，我们不需要配置其他内容来理解它的工作原理。

## 工作原理…

在每个 Linux 系统上，默认安装了这个命令。让我们看看如何使用`mv`命令，通过不同种类的例子：

1.  将`testfile1.txt`文件从当前目录移动到其他目录，比如`home/practical/example`，命令如下：

```
mv testfile1.txt /home/practical/example

```

只有当源文件的位置与目标不同时，前面的命令才能起作用。

使用前面的命令移动文件时，文件将从先前的位置中删除：

![工作原理…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_03_37.jpg)

1.  要使用单个命令移动多个文件，可以使用以下命令：

```
mv testfile2.txt testfile3.txt testfile4.txt /home/practical/example

```

在使用前面的命令时，我们要移动的所有文件都应该在同一个源位置：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_03_38.jpg)

1.  要移动目录，命令与移动文件的命令相同。假设我们在当前目录中有一个名为`directory1`的目录，希望将其移动到`/home/practical/example`位置，则命令如下：

```
mv directory1/ /home/practical/example

```

如下所示的截图：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_03_39.jpg)

1.  `mv`命令也用于重命名文件和目录。假设我们有一个名为`example_1.txt`的文件，希望将其重命名为`example_2.txt`，则执行此操作的命令如下：

```
mv example_1.txt example_2.txt

```

当目标位置与源位置相同时，前面的命令也适用：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_03_40.jpg)

1.  重命名目录的操作方式与重命名文件的操作方式相同。假设我们有一个名为`test_directory_1`的目录，我们想将其重命名为`test_directory_2`，那么命令将如下所示：

```
mv test_directory_1/ test_directory_2/

```

可以在以下截图中看到前面命令的执行情况：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_03_41.jpg)

1.  当我们使用`mv`命令移动或重命名大量文件或目录时，可以使用`-v`选项来检查命令是否成功执行。

1.  我们可能希望将当前目录中的所有文本文件移动到`/home/practical/example`文件夹，并对它们进行检查。要做到这一点，请使用以下命令：

```
mv -v *.txt /home/practical/example

```

可以在以下截图中看到前面命令的执行情况：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_03_42.jpg)

1.  这也适用于移动或重命名目录：![它是如何工作的...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_03_43.jpg)

1.  当我们使用`mv`命令将文件移动到另一个位置，并且目标位置已经存在同名文件时，默认命令会覆盖现有文件。但是，如果我们希望在覆盖文件之前显示弹出通知，则必须使用`-i`选项，如下所示：

```
mv -i testfile1.txt /home/practical/example

```

运行前面的命令时，它会通知我们目标位置已经存在同名文件。只有当我们按下*y*时，命令才会完成；否则，它将被取消：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_03_44.jpg)

1.  使用`mv`命令将文件移动到另一个位置时，如果目标位置已经存在同名文件，则使用`-u`选项将仅在源文件较新时才更新目标位置的文件。

我们在源位置有两个文件，`file_1.txt`和`file_2.txt`。首先，使用以下命令检查文件的详细信息：

```
ls –l *.txt

```

现在让我们检查一下目标位置的文件详细信息：

```
ls –l /home/practical/example/*.txt

```

现在，使用以下命令移动文件：

```
mv –uv *.txt /home/practical/example/

```

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_03_45.jpg)

我们看到`file1.txt`和`file2.txt`已经移动到目标位置，并且由于源文件的新时间戳，它们已经更新了之前的文件。

1.  假设我们移动多个文件，并且在目标位置已经存在与源文件同名的文件，而我们不希望更新这些文件。在这种情况下，我们可以使用`-n`选项，如下所示。

1.  我们在源位置有两个文件，`file_1.txt`和`file_2.txt`。首先，使用以下命令检查文件的详细信息：

```
ls –l *.txt

```

1.  现在，使用以下命令移动文件：

```
mv –nv *.txt /home/practical/example/

```

1.  让我们检查一下目标位置的文件详细信息：

```
ls –l /home/practical/example/*.txt

```

1.  同名文件并没有被移动，可以通过它们的时间戳进行验证：![它是如何工作的...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_03_46.jpg)

1.  在移动文件时，如果目标位置已经有同名文件，那么在新文件覆盖之前，我们还可以创建目标文件的备份。为此，我们使用`-b`选项：

```
mv -bv *.txt /home/practical/example

```

1.  现在，让我们检查一下目标位置的文件详细信息。在详细信息中，我们有名为`file1.txt~`和`file2.txt~`的文件。这些文件是备份文件，可以通过时间戳进行验证，时间戳比`file1.txt`和`file2.txt`的时间戳要早：![它是如何工作的...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_03_47.jpg)

## 还有更多...

您可以通过键入`man`、`mv`或`mv --help`来了解更多关于`mv`命令的信息。这将显示其手册页面，我们可以在其中探索有关该命令的更多细节。

# 在 Ubuntu 上安装和配置基本的 LDAP 服务器

轻量级目录访问协议（LDAP）是一种用于从某个集中位置管理对文件和目录层次结构的访问的协议。目录类似于数据库；但是，它可能包含更具表达力的基于属性的信息。LDAP 主要用于集中式身份验证。

LDAP 服务器有助于控制谁可以访问目录中的读取和更新信息。

## 准备工作

要安装和配置 LDAP，我们首先需要创建一个 Ubuntu 服务器。可以在[`www.ubuntu.com/download/server`](http://www.ubuntu.com/download/server)找到 Ubuntu 服务器安装媒体的当前版本。

下载完成后，按照提供的步骤安装 Ubuntu 服务器。

我们需要第二个安装了 Ubuntu 桌面版的系统。这将用于通过 Web 界面访问您的 LDAP 服务器。

完成后，我们可以继续安装 LDAP。

## 如何操作...

我们现在将开始在 Ubuntu 服务器上安装和配置 LDAP 的过程。安装 LDAP 需要`slapd`软件包，并且它存在于 Ubuntu 的默认存储库中：

1.  我们首先需要从 Ubuntu 的存储库中更新服务器上的软件包列表，以获取有关所有软件包及其依赖关系的最新版本的信息：

```
sudo apt-get update

```

1.  现在，运行命令以安装`slapd`软件包以安装 LDAP：

```
sudo apt-get install slapd

```

以下截图显示了此命令的输出：

![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_03_48.jpg)

1.  在安装过程中，您将被提示输入并确认管理员密码，该密码将用于 LDAP 的管理员帐户。配置您选择的任何密码并完成安装过程：![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_03_49.jpg)

1.  接下来，我们需要安装一些与 LDAP 一起使用的附加实用程序：

```
sudo apt-get install ldap-utils

```

该命令的输出如下截图所示：

![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_03_50.jpg)

1.  安装部分完成后，我们将根据我们的要求重新配置 LDAP 软件包。键入此命令以启动软件包配置工具：

```
sudodpkg-reconfigure slapd

```

1.  这将开始一系列关于软件配置的问题。我们需要根据我们的要求逐个选择选项。

1.  首先，您将被问到**省略 OpenLDAP 服务器配置？** 选择**否**并继续：![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_03_51.jpg)

1.  接下来，您需要输入域名。您可以在服务器上使用已经存在的域名或创建任何您喜欢的内容。我们在这里使用了`example.com`：![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_03_52.jpg)

1.  下一步将是要求输入**组织名称**，可以是您喜欢的任何内容：![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_03_53.jpg)

1.  您将被要求输入 LDAP 的管理员密码。我们在安装 LDAP 时已经配置了这个。在这一步中使用相同的密码，或者更改为其他密码：![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_03_54.jpg)

1.  接下来，我们需要在提示选择要使用的数据库后端时选择**HDB**：![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_03_55.jpg)

1.  当`slapd`被清除时，您将被问及是否希望删除数据库。在这里选择**否**：![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_03_56.jpg)

1.  在下一步中，选择**是**以移动旧数据库，并允许配置过程创建新数据库：![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_03_57.jpg)

1.  现在，在询问**允许 LDAPv2 协议？**时选择**否**。![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_03_58.jpg)

1.  配置过程完成后，我们将安装`phpldapadmin`软件包。这将帮助通过 Web 界面管理 LDAP：

```
sudo apt-get install phpldapadmin

```

此命令的执行结果如下截图所示：

![操作方法...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_03_59.jpg)

1.  安装完成后，打开 phpldapadmin 的配置文件以配置一些值：

```
sudo nano /etc/phpldapadmin/config.php

```

可以在以下截图中看到：

![操作方法...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_03_60.jpg)

1.  搜索给定部分，并修改以反映 Ubuntu 服务器的域名或 IP 地址：

```
$servers->setValue('server','host','domain_nam_or_IP_address');

```

可以在以下截图中看到：

![操作方法...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_03_61.jpg)

1.  接下来，编辑以下条目并插入我们在重新配置`slapd`时给出的域名：

```
$servers->setValue('server','base',array('dc=example,dc=com'));

```

在前一行的`dc`属性中以值的形式给出域名。由于我们的域名是`example.com`，因此前一行中的值将输入为`dc=example, dc=com`。

![操作方法...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_03_62.jpg)

1.  找到以下行，并再次输入域名作为`dc`属性。对于`cn`属性，值将仅为`admin`：

```
$servers->setValue('login','bind_id','cn=admin,dc=example,dc=com');

```

可以在以下截图中看到：

![操作方法...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_03_63.jpg)

1.  搜索类似于以下代码所示的部分，首先取消注释该行，然后将值设置为`true`：

```
$config->custom->appearance['hide_template_warning'] = true;

```

可以在以下截图中看到：

![操作方法...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_03_64.jpg)

1.  在进行所有更改后，保存并关闭文件。

1.  当`phpldapadmin`的配置完成后，在另一台安装了 Ubuntu 桌面版的系统中打开浏览器。在浏览器的地址栏中输入服务器的域名或 IP 地址，后面加上`/phpldapadmin`，如`domain_name_or_IP_address/phpldapadmin`：![操作方法...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_03_65.jpg)

1.  打开`phpldapadmin`页面后，在左侧找到**登录**链接。单击它，将会出现登录提示：![操作方法...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_03_66.jpg)

1.  如果`phpldapadmin`到目前为止已经正确配置，登录界面将显示正确的**登录 DN**详细信息。在我们的情况下是`cn=admin,dc=example,dc=com`。

1.  正确输入管理员密码后，将显示管理员界面：![操作方法...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_03_67.jpg)

1.  在左侧的管理员界面中，找到域组件(`dc=example,dc=co`)，点击其旁边的*加号*。它将显示正在使用的管理员登录：![操作方法...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_03_68.jpg)

我们的基本 LDAP 服务器现在已经启动运行。

## 工作原理...

首先创建一个 Ubuntu 服务器，然后在其上安装`slapd`软件包以安装 LDAP。一旦完全安装完成，我们安装所需的附加软件包。然后，根据我们的要求重新配置 LDAP。

重新配置完成后，我们安装`phpldapadmin`软件包，这将帮助我们通过浏览器的 Web 界面管理 LDAP 服务器。


# 第四章：Linux 中的本地认证

在本章中，我们将讨论以下主题：

+   用户认证和日志

+   限制用户的登录能力

+   使用 acct 监视用户活动

+   使用 USB 设备和 PAM 进行登录认证

+   定义用户授权控制

# 用户认证和日志记录

用户认证的一个主要方面是监视系统用户。有各种方法可以跟踪 Linux 中用户进行的所有成功和失败的登录尝试。

## 入门

Linux 系统维护着系统中不同账户的所有登录尝试的日志。这些日志都位于`/var/log/`目录下。

![入门](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_04_01.jpg)

## 如何做...

Linux 有许多方法可以帮助管理员查看日志，无论是通过图形界面还是命令行方法：

1.  如果我们想要检查特定用户（如 root）的错误登录尝试，可以使用以下命令：

```
lastb root

```

![如何做...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_04_02.jpg)

1.  要使用终端查看日志，我们使用`dmesg`命令。该命令显示存储在内存中的 Linux 内核消息缓冲区，如下所示：![如何做...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_04_03.jpg)

1.  如果我们希望过滤上述输出，只显示与 USB 设备相关的日志，我们可以使用`grep`来实现：![如何做...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_04_04.jpg)

1.  如果我们不想查看所有日志，而只想查看特定日志文件中最近的 10 条日志，命令如下：![如何做...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_04_05.jpg)

在上面的命令中，使用`-n`选项来指定要显示的行数。

1.  如果我们希望查看用户账户的最近登录尝试，可以使用`last`工具。![如何做...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_04_06.jpg)

`last`工具以格式化的方式显示`/etc/log/wtmp`文件。

1.  如果我们想要查看系统上任何用户最后一次登录的时间，我们可以使用`lastlog`命令：![如何做...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_04_07.jpg)

## 它是如何工作的...

Linux 有不同的文件用于记录不同类型的详细信息。使用上面显示的命令，我们能够查看这些日志并根据我们的要求查看详细信息。每个命令都会给我们不同类型的详细信息。

# 限制用户的登录能力

系统管理员的一个主要角色是配置和管理 Linux 系统上的用户和组。这也涉及检查所有用户的登录能力。

## 准备工作

以下所有步骤都在 Ubuntu 系统上尝试过；但是，您也可以在任何其他 Linux 发行版上进行这些操作。

## 如何做...

在这里，我们将讨论如何在 Linux 系统上限制用户的登录能力：

1.  我们可以通过将账户的登录 shell 更改为`/etc/passwd`文件中的特殊值来限制用户账户的访问。让我们以`sslh`账户为例，在`/etc/passwd`文件中检查账户的详细信息，如下所示：

```
cat /etc/passwd | grep sslh

```

![如何做...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_04_08.jpg)

1.  在上述详细信息中，`sslh`账户的最终值设置为`/bin/false`。如果我们现在尝试以 root 用户登录`sslh`用户，我们会发现我们无法这样做：

```
su sslh

```

1.  因此，现在，如果我们更改要限制的用户账户的 shell，我们可以这样做，如下所示：![如何做...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_04_09.jpg)

1.  限制用户访问的另一种方法是使用`/etc/shadow`文件。如果我们使用`cat`命令检查此文件的详细信息，我们会得到如下结果：![如何做...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_04_10.jpg)

1.  输出被截断，如下所示：![如何做...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_04_11.jpg)

1.  详细信息显示了`user1`账户的哈希密码（以`$6$2iumTg65`开头的密码）。我们还可以看到，系统账户的哈希密码被替换为星号`*`。

1.  现在，要锁定账户`user1`，命令如下：

```
passwd -l user1

```

![如何做...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_04_12.jpg)

1.  让我们再次检查`/etc/shadow`文件中`user1`帐户的详细信息。我们看到哈希密码已被加上`!`变为无效：

```
cat /etc/shadow | grep user1

```

![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_04_13.jpg)

1.  要再次解锁帐户，命令如下所示：

```
passwd -u user1

```

![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_04_14.jpg)

1.  如果我们希望检查帐户是否已被锁定，可以使用以下命令进行检查：![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_04_15.jpg)

如上面的输出所示，`user1`帐户已被锁定，第二字段中标有`L`。而`user2`没有被锁定，因为详细信息中显示为`P`。

1.  使用`usermod`命令也可以锁定或解锁帐户。要使用`usermod`锁定帐户，命令如下：

```
usermod -L user1

```

1.  并使用`usermod`解锁帐户，命令如下所示：

```
usermod -U user1

```

## 它是如何工作的...

对于 Linux 中的每个帐户，用户帐户详细信息存储在`/etc/passwd`和`/etc/shadow`文件中。这些详细信息指定用户帐户的行为。当我们能够更改这些文件中任何用户帐户的详细信息时，我们就能够更改用户帐户的行为。

在上面的部分中，我们已经看到如何修改这些文件来“锁定”或“解锁”用户帐户。

# 使用 acct 监控用户活动

**Acct**是一个开源应用程序，它帮助监控 Linux 系统上的用户活动。它在后台运行并跟踪用户的所有活动，还维护资源使用情况的记录。

## 入门

要使用`acct`的命令，我们首先需要通过以下命令在我们的 Linux 系统上安装该软件包：

```
apt-get install acct

```

![入门](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_04_16.jpg)

如果上述方法无法正常工作，我们可以通过访问链接[`packages.ubuntu.com/precise/admin/acct`](http://packages.ubuntu.com/precise/admin/acct)手动下载软件包。

1.  下载软件包后，我们需要将其解压缩到某个目录中，比如桌面。![入门](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_04_17.jpg)

1.  然后，将其移动到目录中。![入门](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_04_18.jpg)

1.  然后，运行脚本以配置软件包。![入门](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_04_19.jpg)

1.  安装完成后，接下来运行`make`命令：![入门](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_04_20.jpg)

1.  然后，运行`make install`命令：![入门](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_04_21.jpg)

1.  成功完成后，它将在您的 Linux 系统上安装该软件包。

## 如何操作？

`acct`包有不同的命令来监控进程活动：

1.  基于特定用户从`wtmp`文件中的登录和注销，如果我们希望检查总连接时间，可以使用`ac`命令：![如何操作？](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_04_22.jpg)

1.  如果我们希望打印一天的总登录时间，我们将使用`ac`命令的`-d`选项：![如何操作？](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_04_23.jpg)

1.  要打印用户的总登录时间，我们使用以下命令：![如何操作？](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_04_24.jpg)

1.  如果我们只想检查特定用户的登录时间，我们使用以下命令：![如何操作？](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_04_25.jpg)

1.  我们还可以使用`lastcomm`命令查看所有用户或特定用户以前执行的命令。![如何操作？](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_04_26.jpg)

## 它是如何工作的...

为了保持对系统的监控，我们首先在系统上安装`acct`包。对于其他一些 Linux 发行版，如果`acct`不兼容，可以使用`psacct`包。

工具安装并运行后，它开始维护系统上的活动日志。然后我们可以使用上面部分讨论的命令来查看这些日志。

# 使用 USB 设备和 PAM 进行登录验证

当 Linux 用户想要保护系统时，最常见的方法始终是使用登录密码。然而，我们知道这种方法并不是非常可靠，因为有许多方法可以破解传统密码。为了增加安全性，我们可以使用 USB 设备作为认证令牌，用于登录系统。

## 准备就绪

要按照给定的步骤，我们需要在 Linux 系统上下载一个 USB 存储设备和**可插拔认证模块**（**PAM**）。大多数 Linux 系统都以预编译包的形式提供，可以从相关存储库中访问。

## 如何操作...

通过使用任何类型的 USB 存储设备和 PAM，我们可以创建一个认证令牌。

1.  首先，我们需要安装 PAM USB 认证所需的软件包。为此，我们运行以下命令：

```
$ sudo apt-get install pamusb-tools libpam-usb

```

![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_04_27.jpg)

1.  安装软件包后，我们必须配置 USB 设备以与 PAM 认证一起使用。为此，我们可以使用命令，或者我们可以编辑`/etc/pamusb.conf`文件。

1.  使用命令方法时，首先连接 USB 设备，然后执行给定的命令：

```
$ sudo pamusb-conf --add-device usb-device

```

命令的输出如下所示：

![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_04_28.jpg)

在上述命令中，`usb-device`是我们正在使用的 USB 设备的名称。这个名称可以是您选择的任何内容。

当使用`pamusb-conf`命令时，它会自动发现 USB 设备，其中还包括多个分区。命令执行完成后，它会将一个 XML 代码块添加到`/etc/pamusb.conf`文件中，定义我们的 USB 设备。

![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_04_29.jpg)

1.  接下来，我们定义我们的 USB 设备：

```
$ sudo pamusb-conf --add-user user1

```

执行结果如下截图所示：

![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_04_30.jpg)

如果用户已经存在，它将被添加到 PAM 配置中。

上述命令将`pam_usb`用户的定义添加到`/etc/pamusb.conf`文件中。

![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_04_31.jpg)

1.  现在，我们将配置 PAM 以在系统认证过程中添加`pam_usb`模块。为此，我们将编辑`/etc/pam.d/common-auth`文件并添加以下行：![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_04_32.jpg)

这将使系统范围的 PAM 库意识到`pam_usb`模块。

`required`选项指定需要正确的密码，而`sufficient`选项表示这也可以对用户进行认证。在上述配置中，我们已经为`usb-device`认证使用了`sufficient`，同时对默认密码使用了`required`。

如果为`user1`定义的 USB 设备在系统中不存在，用户将需要输入正确的密码。为了强制用户在授予他们系统访问权限之前必须同时具备两种认证程序，将`sufficient`更改为`required`。

1.  现在我们将尝试切换到`user1`。![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_04_33.jpg)

当要求时，连接相关的`usb-device`。如果连接了正确的 USB 令牌设备，登录将如图所示完成；否则将出现错误。

1.  如果出现错误，如下所示，可能是 USB 设备的路径未正确添加。

```
Error: device /dev/sdb1 is not removable
* Mount failed

```

在这种情况下，将 USB 设备的完整路径添加到`/etc/pmount.allow`中。

1.  现在运行命令以检查 USB 设备分区在文件系统中的列表：

```
$ sudo fdisk –l

```

![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_04_34.jpg)

在我们的情况下，分区已列出为：`/dev/sdb1`

1.  现在在`/etc/pmount.allow`文件中添加一行以解决错误。

1.  到目前为止，在`/etc/pam.d/common-auth`中我们所做的配置意味着如果 USB 设备未连接，用户仍然可以使用正确的密码登录。如果我们希望强制用户在登录时也使用 USB 设备，则将`sufficient`更改为`required`，如下所示：![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_04_35.jpg)

1.  如果用户现在尝试登录，他们将不仅需要输入正确的密码，还需要插入 USB 设备。![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_04_36.jpg)

1.  现在拔掉 USB 设备，然后尝试使用正确的密码再次登录：![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_04_37.jpg)

## 工作原理...

安装所需的 PAM-USB 软件包后，我们编辑配置文件以添加我们想要用作身份验证令牌的 USB 设备。之后，我们添加要使用的用户账户，然后在`/etc/pam.d/common-auth`文件中完成更改，以指定 USB 身份验证的工作方式，无论在登录时是否始终需要。

## 还有更多...

到目前为止，我们已经看到如何使用 USB 设备对用户登录进行身份验证。除此之外，我们还可以使用 USB 设备在每次连接或断开连接到系统时触发一个事件。

让我们修改`/etc/pamusb.conf`中的 XML 代码，以添加用户定义的事件代码：

![还有更多...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_04_38.jpg)

由于上述修改，每当用户断开 USB 设备时，屏幕将被锁定。同样，当用户再次连接 USB 设备时，屏幕将被解锁。

# 定义用户授权控制

在计算机上定义用户授权主要涉及决定用户可能或不可能被允许执行的活动。这可能包括执行程序或读取文件等活动。

由于`root`账户拥有所有权限，授权控制主要涉及允许或禁止`root`访问用户账户。

## 入门...

要查看用户授权是如何工作的，我们需要一个用户账户来尝试这些命令。因此，我们创建了两个用户账户`user1`和`user2`来尝试这些命令。

## 如何操作...

在本节中，我们将介绍可以应用于用户账户的各种控制。

1.  假设我们有两个用户账户，`user1`和`user2`。我们从`user2`登录，然后尝试以`user1`身份运行`ps`命令。在正常情况下，我们会得到如下结果：![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_04_39.jpg)

1.  现在编辑`/etc/sudoers`文件并添加以下行：

```
User2 ALL = (user1) /bin/ps

```

1.  在`/etc/sudoers`中保存更改后，再次尝试从`user2`以`user1`身份运行`ps`命令。![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_04_40.jpg)

1.  现在，如果我们想要再次从`user2`以`user1`身份运行相同的命令，但不需要输入密码，我们可以通过编辑`/etc/sudoers`文件来实现：![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_04_41.jpg)

1.  现在，当我们从`user2`以`user1`身份运行`ps`命令时，我们会发现它不再要求输入密码：![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_04_42.jpg)

1.  现在我们已经看到如何在不需要输入密码的情况下运行命令，系统管理员的主要关注点将是`sudo`应始终提示输入密码。

1.  要使系统上的用户账户`user1`始终需要输入密码来使用`sudo`，请编辑文件`/etc/sudoers`并添加以下行：

```
Defaults:user1 timestamp_timeout = 0

```

![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_04_43.jpg)

1.  现在，如果`user1`尝试运行任何命令，将始终提示输入密码：![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_04_44.jpg)

1.  现在，假设我们想要给`user1`账户特权来更改`user2`和`user3`的密码。编辑`/etc/sudoers`文件并添加如下行：![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_04_45.jpg)

1.  现在从`user1`登录，让我们尝试更改`user2`和`user3`账户的密码：![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_04_46.jpg)

## 工作原理...

使用`sudo`命令和`/etc/sudoers`文件，我们进行必要的更改以执行所需的任务。

我们编辑文件以允许以另一个用户的身份执行程序。我们还添加了`NOPASSWD`选项，以便在不需要输入密码的情况下执行程序。然后，我们添加所需的行，以便`sudo`始终提示输入密码。

接下来，我们看看如何授权用户账户更改其他用户账户的密码。
