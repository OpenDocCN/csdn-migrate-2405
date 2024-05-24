# 精通 Ansible 中文第四版（二）

> 原文：[`zh.annas-archive.org/md5/F58519F0D978AE01B8EEFA01F4E150D0`](https://zh.annas-archive.org/md5/F58519F0D978AE01B8EEFA01F4E150D0)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：Ansible 和 Windows-不仅仅适用于 Linux

大量的工作都是在 Linux 操作系统上进行的；事实上，本书的前两版完全围绕在 Linux 中使用 Ansible 展开。然而，大多数环境并不是这样的，至少会有一些微软 Windows 服务器和桌面机器。自本书的第三版出版以来，Ansible 已经进行了大量工作，创建了一个真正强大的跨平台自动化工具，它在 Linux 数据中心和 Windows 数据中心同样得心应手。当然，Windows 和 Linux 主机的操作方式存在根本差异，因此并不奇怪，Ansible 在 Linux 上自动化任务的方式与在 Windows 上自动化任务的方式之间存在一些根本差异。

我们将在本章中介绍这些基础知识，以便为您提供一个坚实的基础，开始使用 Ansible 自动化您的 Windows 任务，具体涵盖以下领域：

+   在 Windows 上运行 Ansible

+   为 Ansible 控制设置 Windows 主机

+   处理 Windows 身份验证和加密

+   使用 Ansible 自动化 Windows 任务

# 技术要求

要按照本章介绍的示例，您需要一台运行 Ansible 4.3 或更新版本的 Linux 机器。几乎任何 Linux 的版本都可以；对于那些对细节感兴趣的人，本章中提供的所有代码都是在 Ubuntu Server 20.04 LTS 上测试的，除非另有说明，并且在 Ansible 4.3 上也进行了测试。

在本章中使用 Windows 时，示例代码是在 Windows Server 2019 的 1809 版本、构建 17763.1817 上进行测试和运行的。Windows Store 的屏幕截图是从 Windows 10 Pro 的 20H2 版本、构建 19042.906 中获取的。

本章附带的示例代码可以从 GitHub 的以下网址下载：[`github.com/PacktPublishing/Mastering-Ansible-Fourth-Edition/tree/main/Chapter04`](https://github.com/PacktPublishing/Mastering-Ansible-Fourth-Edition/tree/main/Chapter04)。

查看以下视频以查看代码的实际操作：[`bit.ly/3B2zmvL`](https://bit.ly/3B2zmvL)。

# 在 Windows 上运行 Ansible

如果您浏览 Ansible 的官方安装文档，您会发现针对大多数主流 Linux 变体、Solaris、macOS 和 FreeBSD 的各种说明。然而，您会注意到，没有提到 Windows。这是有充分理由的 - 对于那些对技术细节感兴趣的人来说，Ansible 在其操作中广泛使用 POSIX `fork()`系统调用，而 Windows 上并不存在这样的调用。POSIX 兼容项目，如备受尊敬的 Cygwin，曾试图在 Windows 上实现`fork()`，但即使在今天，有时这并不起作用。因此，尽管在 Windows 上有一个可行的 Python 实现，但没有这个重要的系统调用，Ansible 无法在此平台上本地运行。

好消息是，如果您正在运行最新版本的 Windows 10，或 Windows Server 2016 或 2019，由于**Windows 子系统**（**WSL**），安装和运行 Ansible 现在变得非常容易。现在有两个版本的这项技术，原始的 WSL 发布版（在本书的第三版中有介绍），以及更新的**WSL2**。**WSL2**目前只在 Windows 10 的 1903 版本（或更高版本）上，构建 18362（或更高版本）上可用。这两项技术允许 Windows 用户在 Windows 之上运行未经修改的 Linux 发行版，而无需虚拟机的复杂性或开销（尽管在幕后，您会发现**WSL2**是在 Hyper-V 之上运行的，尽管以一种无缝的方式）。因此，这些技术非常适合运行 Ansible，因为它可以轻松安装和运行，并且具有可靠的`fork()`系统调用的实现。

在我们继续之前，让我们暂停一下看两个重要的点。首先，只有在 Windows 上运行 Ansible 来控制其他机器（运行任何操作系统）时，才需要 WSL 或 WSL2-不需要使用它们来控制 Windows 机器。我们将在本章后面更多地了解这一点。其次，不要让 WSL2 没有 Windows Server 的官方版本阻碍您-如果您有 Windows 堡垒主机，并希望从中运行 Ansible，它在**WSL**上和**WSL2**上都可以。在撰写本文时，有关**WSL2**在 Windows Server 的最新预览版中可用的消息；但是，我预计大多数读者将寻找稳定的、可用于生产的解决方案，因此我们将在本章更多地关注**WSL**而不是**WSL2**。

官方的 Ansible 安装文档可以在[`docs.ansible.com/ansible/latest/installation_guide/intro_installation.html`](https://docs.ansible.com/ansible/latest/installation_guide/intro_installation.html)找到。

## 检查您的构建

WSL 仅在特定版本的 Windows 上可用，如下所示：

+   Windows 10-版本 1607（构建 14393）或更高版本：

+   请注意，如果要通过 Microsoft Store 安装 Linux，则需要构建 16215 或更高版本。

+   如果您想要使用 WSL2，则需要 Windows 10 的 1903 版本或更高版本（18362 版本或更高版本）。

+   仅支持 64 位英特尔和 ARM 版本的 Windows 10。

+   Windows Server 2016 版本 1803（构建 16215）或更高版本

+   Windows Server 2019 版本 1709（构建 16237）或更高版本

您可以通过在 PowerShell 中运行以下命令轻松检查您的构建和版本号：

```
systeminfo | Select-String "^OS Name","^OS Version"
```

如果您使用的是较早版本的 Windows，仍然可以通过虚拟机或通过 Cygwin 运行 Ansible。但是，这些方法超出了本书的范围。

## 启用 WSL

验证了您的构建后，启用 WSL 很容易。只需以管理员身份打开 PowerShell 并运行以下命令：

```
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux
```

安装完成后，您将能够选择并安装您喜欢的 Linux 发行版。有很多选择，但是为了运行 Ansible，选择官方 Ansible 安装说明中列出的发行版之一是有意义的，比如 Debian 或 Ubuntu。

## 在 WSL 下安装 Linux

如果您的 Windows 10 版本足够新，那么安装您喜欢的 Linux 就像打开 Microsoft Store 并搜索它一样简单。例如，搜索`Ubuntu`，您应该很容易找到。*图 4.1*显示了在 Windows 10 的 Microsoft Store 中可供下载的 Ubuntu 的最新 LTS 版本：

![图 4.1-在 Windows 10 的 Microsoft Store 应用程序中可用的 WSL 和 WSL2 的 Linux 发行版之一](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_04_01.jpg)

图 4.1-在 Windows 10 的 Microsoft Store 应用程序中可用的 WSL 和 WSL2 的 Linux 发行版之一

要在 WSL 下安装 Ubuntu，只需单击**获取**按钮，等待安装完成。

如果您使用的是 Windows 10，但是支持的构建早于 16215，或者确实是 Windows Server 2016/2019 的任何支持的构建，那么安装 Linux 就是一个稍微手动的过程。首先，从 Microsoft 下载您喜欢的 Linux 发行版，例如，可以使用以下 PowerShell 命令下载 Ubuntu 20.04：

```
Invoke-WebRequest -Uri https://aka.ms/wslubuntu2004 -OutFile Ubuntu.appx -UseBasicParsing
```

下载成功后，解压`Ubuntu.appx`文件-只要它在系统（引导）驱动器上，通常是`C:`上的任何位置即可。如果要保持 Linux 发行版的私密性，可以将其解压缩到个人资料目录中的某个位置，否则可以将文件解压缩到系统驱动器的任何位置。例如，以下 PowerShell 命令将解压缩存档到`C:\WSL\`：

```
Rename-Item Ubuntu.appx Ubuntu.zip 
Expand-Archive Ubuntu.zip C:\WSL\Ubuntu 
```

完成后，您可以使用以所选发行版命名的可执行文件启动新安装的 Linux 发行版。以我们的 Ubuntu 示例为例，您可以通过资源管理器（或您喜欢的方法）运行以下命令：

```
C:\WSL\Ubuntu\ubuntu2004.exe
```

第一次运行新安装的 Linux 发行版时，无论是通过 Microsoft Store 安装还是手动安装，它都会初始化自己。在此过程的一部分中，它将要求您创建一个新用户帐户。请注意，此帐户与您的 Windows 用户名和密码是独立的，因此请务必记住您在此设置的密码！每次通过`sudo`运行命令时都会需要它，尽管与任何 Linux 发行版一样，如果您愿意，可以通过`/etc/sudoers`自定义此行为。这在*图 4.2*中有所示：

![图 4.2-WSL Ubuntu 终端在首次运行时的输出](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_04_02.jpg)

图 4.2-WSL Ubuntu 终端在首次运行时的输出

恭喜！现在您在 WSL 下运行 Linux。从这里开始，您应该按照 Ansible 的标准安装过程进行操作，并且可以像在任何其他 Linux 系统上一样在 Linux 子系统上运行它。

# 使用 WinRM 为 Ansible 控制设置 Windows 主机

到目前为止，我们已经讨论了从 Windows 本身运行 Ansible。这对于企业环境尤其有帮助，尤其是在那些 Windows 终端用户系统是主流的情况下。但是，实际的自动化任务呢？好消息是，正如已经提到的，使用 Ansible 自动化 Windows 不需要 WSL。Ansible 的一个核心前提是无需代理，这对于 Windows 和 Linux 同样适用。可以合理地假设几乎任何现代 Linux 主机都将启用 SSH 访问，同样，大多数现代 Windows 主机都内置了一个远程管理协议，称为 WinRM。Windows 的狂热追随者将知道，微软在最近的版本中添加了 OpenSSH 客户端和服务器包，并且自本书上一版出版以来，已经为 Ansible 添加了对这些的实验性支持。出于安全原因，这两种技术默认情况下都是禁用的，因此，在本书的这一部分中，我们将介绍启用和保护 WinRM 以进行远程管理的过程。我们还将简要介绍在 Windows 上设置和使用 OpenSSH 服务器-然而，由于 Ansible 对此的支持目前是实验性的，并且在未来的版本中可能会有稳定性和向后不兼容的变化，大多数用户将希望使用 WinRM，尤其是在稳定的生产环境中。

有了这个想法，让我们开始看一下如何在本章的下一部分中使用 WinRM 自动化 Windows 主机上的任务。

## 使用 WinRM 进行 Ansible 自动化的系统要求

Ansible 使用 WinRM 意味着对新旧 Windows 版本有广泛的支持-在幕后，几乎任何支持以下内容的 Windows 版本都可以使用：

+   PowerShell 3.0

+   .NET 4.0

实际上，这意味着只要满足前面的要求，就可以支持以下 Windows 版本：

+   **桌面**：Windows 7 SP1，8.1 和 10

+   **服务器**：Windows Server 2008 SP2，2008 R2 SP1，2012，2012 R2，2016 和 2019

请注意，以前列出的旧操作系统（如 Windows 7 或 Server 2008）未附带.NET 4.0 或 PowerShell 3.0，并且在使用 Ansible 之前需要安装它们。正如您所期望的那样，支持更新版本的 PowerShell，并且对.NET 4.0 可能有安全补丁。只要满足这些最低要求，您就可以开始使用 Ansible 自动化 Windows 任务，即使在旧操作系统仍然占主导地位的商业环境中也是如此。

如果您使用的是较旧（但受支持的）PowerShell 版本，例如 3.0，请注意在 PowerShell 3.0 下存在一个 WinRM 错误，该错误限制了服务可用的内存，从而可能导致某些 Ansible 命令失败。这可以通过确保在运行 PowerShell 3.0 的所有主机上应用 KB2842230 来解决，因此，如果您正在通过 PowerShell 3.0 自动化 Windows 任务，请务必检查您的热修复和补丁。

## 启用 WinRM 监听器

一旦满足了先前详细介绍的所有系统要求，剩下的任务就是启用和保护 WinRM 监听器。完成这一步后，我们实际上可以对 Windows 主机本身运行 Ansible 任务！WinRM 可以在 HTTP 和 HTTPS 协议上运行，虽然通过纯 HTTP 快速且容易上手，但这会使您容易受到数据包嗅探器的攻击，并有可能在网络上泄露敏感数据。如果使用基本身份验证，情况尤其如此。默认情况下，也许并不奇怪，Windows 不允许使用 HTTP 或基本身份验证通过 WinRM 进行远程管理。

有时，基本身份验证就足够了（例如在开发环境中），如果要使用它，那么我们肯定希望启用 HTTPS 作为 WinRM 的传输！但是，在本章后面，我们将介绍 Kerberos 身份验证，这是更可取的，并且还可以使用域帐户。不过，为了演示将 Ansible 连接到具有一定安全性的 Windows 主机的过程，我们将使用自签名证书启用 WinRM 的 HTTPS，并启用基本身份验证，以便我们可以使用本地的`Administrator`帐户进行工作。

要使 WinRM 在 HTTPS 上运行，必须存在具有以下内容的证书：

+   与主机名匹配的`CN`值

+   在**增强密钥用途**字段中的`服务器身份验证（1.3.6.1.5.5.7.3.1）`

理想情况下，这应该由中央**证书颁发机构**（**CA**）生成，以防止中间人攻击等 - 更多内容稍后再讨论。但是，为了让所有读者都能够测试，我们将生成一个自签名证书作为示例。在 PowerShell 中运行以下命令以生成合适的证书：

```
New-SelfSignedCertificate -CertStoreLocation Cert:\LocalMachine\My -DnsName "$env:computername" -FriendlyName "WinRM HTTPS Certificate" -NotAfter (Get-Date).AddYears(5)
```

`New-SelfSignedCertificate`命令仅在较新版本的 Windows 上可用 - 如果您的系统上没有该命令，请考虑使用 Ansible 提供的自动化 PowerShell 脚本，网址为[`raw.githubusercontent.com/ansible/ansible/devel/examples/scripts/ConfigureRemotingForAnsible.ps1`](https://raw.githubusercontent.com/ansible/ansible/devel/examples/scripts/ConfigureRemotingForAnsible.ps1)。

这应该产生类似于*图 4.3*中显示的内容 - 请记下证书的指纹，稍后会用到：

![图 4.3 - 使用 PowerShell 为 WinRM HTTPS 监听器创建自签名证书](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_04_03.jpg)

图 4.3 - 使用 PowerShell 为 WinRM HTTPS 监听器创建自签名证书

有了证书，我们现在可以使用以下命令设置新的 WinRM 监听器：

```
New-Item -Path WSMan:\Localhost\Listener -Transport HTTPS -Address * -CertificateThumbprint <thumbprint of certificate>
```

成功后，该命令将在端口`5986`上设置一个带有我们之前生成的自签名证书的 WinRM HTTPS 监听器。为了使 Ansible 能够通过 WinRM 自动化此 Windows 主机，我们需要执行另外两个步骤 - 在防火墙上打开此端口，并启用基本身份验证，以便我们可以使用本地的`Administrator`帐户进行测试。使用以下两个命令可以实现这一点：

```
New-NetFirewallRule -DisplayName "WinRM HTTPS Management" -Profile Domain,Private -Direction Inbound -Action Allow -Protocol TCP -LocalPort 5986
Set-Item -Path "WSMan:\localhost\Service\Auth\Basic" -Value $true
```

您应该看到与*图 4.4*中显示的类似的先前命令的输出：

![图 4.4 - 在 PowerShell 中创建和启用对 WinRM HTTPS 监听器的访问](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_04_04.jpg)

图 4.4 - 在 PowerShell 中创建和启用对 WinRM HTTPS 监听器的访问

这些命令已被单独拆分，以便让您了解为 Ansible 连接设置 Windows 主机所涉及的过程。对于自动化部署和系统，如果`New-SelfSignedCertificate`不可用，可以考虑使用官方 Ansible GitHub 帐户上提供的`ConfigureRemotingForAnsible.ps1`脚本，我们在本节前面已经提到过。该脚本执行了我们之前完成的所有步骤（以及更多），可以按照以下方式下载并在 PowerShell 中运行：

```
$url = "https://raw.githubusercontent.com/ansible/ansible/devel/examples/scripts/ConfigureRemotingForAnsible.ps1"
$file = "$env:temp\ConfigureRemotingForAnsible.ps1"
(New-Object -TypeName System.Net.WebClient).DownloadFile($url, $file)
powershell.exe -ExecutionPolicy ByPass -File $file
```

还有许多其他方法可以为 Ansible 配置 WinRM 所需的配置，包括通过组策略，这在企业环境中几乎肯定更可取。本章节提供的信息现在应该已经为您提供了在您的环境中设置 WinRM 所需的所有基础知识，准备好启用 Ansible 管理您的 Windows 主机。

## 使用 WinRM 连接 Ansible 到 Windows

一旦配置了 WinRM，让 Ansible 与 Windows 通信就相当简单，只要记住两个注意事项——它期望使用 SSH 协议，如果您没有指定用户账户，它将尝试使用与 Ansible 运行的用户账户相同的用户账户进行连接。这几乎肯定不会与 Windows 用户名一起使用。

此外，请注意，Ansible 需要安装`winrm` Python 模块才能成功连接。这并不总是默认安装的，因此在开始使用 Windows 主机之前，值得在 Ansible 系统上测试一下。如果不存在，您将看到类似于*图 4.5*中显示的错误：

![图 4.5 - 在 Ubuntu Server 20.04 上测试 winrm Python 模块的存在](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_04_05.jpg)

图 4.5 - 在 Ubuntu Server 20.04 上测试 winrm Python 模块的存在

如果您看到此错误，您需要在继续之前安装该模块。您的操作系统可能有预打包版本可用，例如，在 Ubuntu Server 20.04 上，您可以使用以下命令安装它：

```
sudo apt install python3-winrm
```

如果没有预打包版本可用，可以使用以下命令直接从`pip`安装。请注意，在*第二章*中，我们讨论了使用 Python 虚拟环境安装 Ansible - 如果您已经这样做，您必须确保激活您的虚拟环境，然后在不使用`sudo`的情况下运行以下命令：

```
sudo pip3 install "pywinrm>=0.3.0"
```

完成后，我们可以测试之前的 WinRM 配置是否成功。对于基于 SSH 的连接，有一个名为`ansible.builtin.ping`的 Ansible 模块，它执行完整的端到端测试，以确保连接、成功的身份验证和远程系统上可用的 Python 环境。类似地，还有一个名为`win_ping`的模块（来自`ansible.windows`集合），它在 Windows 上执行类似的测试。

在我的测试环境中，我将准备一个清单，以连接到我新配置的 Windows 主机：

```
[windows]
10.50.0.101
[windows:vars]
ansible_user=Administrator
ansible_password="Password123"
ansible_port=5986
ansible_connection=winrm
ansible_winrm_server_cert_validation=ignore
```

请注意在 playbook 的`windows:vars`部分设置的`ansible_`开头的连接特定变量。在这个阶段，它们应该是相当容易理解的，因为它们在*第一章*中已经涵盖了 Ansible 的*系统架构和设计*，但特别要注意`ansible_winrm_server_cert_validation`变量，当使用自签名证书时需要设置为`ignore`。显然，在实际示例中，您不会将`ansible_password`参数以明文形式留下，它要么放在 Ansible vault 中，要么在启动时使用`--ask-pass`参数提示输入。

基于证书的身份验证也可以在 WinRM 上实现，它带来的好处和风险与基于 SSH 密钥的身份验证几乎相同。

使用先前的清单（根据您的环境进行适当更改，如主机名/IP 地址和身份验证详细信息），我们可以运行以下命令来测试连接：

```
ansible -i windows-hosts -m ansible.windows.win_ping all
```

如果一切顺利，您应该会看到类似于*图 4.6*中显示的输出：

![图 4.6 - 使用 Ansible 的 ansible.windows.win_ping 模块测试 WinRM 上的 Windows 主机连接](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_04_06.jpg)

图 4.6 - 使用 Ansible 的 ansible.windows.win_ping 模块测试 WinRM 上的 Windows 主机连接

这完成了将 Ansible 主机成功设置到 Windows 主机的端到端设置！通过这样的设置，您可以像在任何其他系统上一样编写和运行 playbooks，只是您必须使用专门支持 Windows 的 Ansible 模块。接下来，我们将致力于改进 Ansible 与 Windows 之间连接的安全性，最后转向一些 Windows playbook 的示例。

# 处理使用 WinRM 时的 Windows 认证和加密

现在我们已经建立了 Ansible 在 Windows 主机上使用 WinRM 执行任务所需的基本连接级别，让我们更深入地了解认证和加密方面的内容。在本章的前部分，我们使用了基本的认证机制与本地账户。虽然这在测试场景中是可以的，但在域环境中会发生什么呢？基本认证只支持本地账户，所以显然我们在这里需要其他东西。我们还选择不验证 SSL 证书（因为它是自签名的），这在测试目的上是可以的，但在生产环境中并不是最佳实践。在本节中，我们将探讨改进 Ansible 与 Windows 通信安全性的选项。

## 认证机制

事实上，当使用 WinRM 时，Ansible 支持五种不同的 Windows 认证机制，如下所示：

+   基本：仅支持本地账户

+   证书：仅支持本地账户，概念上类似于基于 SSH 密钥的认证

+   Kerberos：支持 AD 账户

+   NTLM：支持本地和 AD 账户

+   CredSSP：支持本地和 AD 账户

值得注意的是，Kerberos、NTLM 和 CredSSP 都提供了在 HTTP 上的消息加密，这提高了安全性。然而，我们已经看到了在 HTTPS 上设置 WinRM 有多么容易，而且 WinRM 管理在普通 HTTP 上默认情况下也是不启用的，所以我们将假设通信通道已经被加密。WinRM 是一个 SOAP 协议，意味着它必须在 HTTP 或 HTTPS 等传输层上运行。为了防止远程管理命令在网络上被拦截，最佳实践是确保 WinRM 在 HTTPS 协议上运行。

在这些认证方法中，最让我们感兴趣的是 Kerberos。Kerberos（在本章中）有效地取代了 NTLM，用于 Ansible 对 Active Directory 账户的认证。CredSSP 提供了另一种机制，但在部署之前最好了解与在目标主机上拦截明文登录相关的安全风险，事实上，它默认是禁用的。

在我们继续配置 Kerberos 之前，简要说明一下证书认证。虽然最初这可能看起来很吸引人，因为它实际上是无密码的，但是 Ansible 中的当前依赖关系意味着证书认证的私钥必须在 Ansible 自动化主机上是未加密的。在这方面，将基本或 Kerberos 认证会话的密码放在 Ansible vault 中实际上更安全（更明智）。我们已经介绍了基本认证，所以我们将把精力集中在 Kerberos 上。

由于 Kerberos 认证只支持 Active Directory 账户，因此假定要由 Ansible 控制的 Windows 主机已经加入了域。还假定 WinRM 在 HTTPS 上已经设置好，就像本章前面讨论的那样。

有了这些要求，我们首先要做的是在 Ansible 主机上安装一些与 Kerberos 相关的软件包。确切的软件包将取决于您选择的操作系统，但在 Red Hat Enterprise Linux/CentOS 8 上，它看起来会像这样：

```
sudo dnf -y install python3-devel krb5-devel krb5-libs krb5-workstation
```

在 Ubuntu 20.04 上，您需要安装以下软件包：

```
sudo apt-get install python3-dev libkrb5-dev krb5-user
```

信息

有关更广泛的操作系统的 Kerberos 支持的软件包要求，请参阅 Ansible 文档中有关 Windows 远程管理的部分：[`docs.ansible.com/ansible/latest/user_guide/windows_winrm.html`](https://docs.ansible.com/ansible/latest/user_guide/windows_winrm.html)。

除了这些软件包，我们还需要安装`pywinrm[kerberos]` Python 模块。可用性会有所不同——在 Red Hat Enterprise Linux/CentOS 8 上，它不作为 RPM 包提供，因此我们需要通过`pip`进行安装（同样，如果您使用了 Python 虚拟环境，请确保激活它，并且在没有`sudo`的情况下运行`pip3`命令）：

```
sudo dnf -y install gcc
sudo pip3 install pywinrm[kerberos]
```

请注意，`pip3`需要`gcc`来构建模块——如果不再需要，之后可以将其删除。

接下来，确保您的 Ansible 服务器可以解析您的 AD 相关的 DNS 条目。这个过程根据操作系统和网络架构会有所不同，但是至关重要的是，您的 Ansible 控制器必须能够解析您的域控制器的名称和其他相关条目，以便本过程的其余部分能够正常工作。

一旦您为 Ansible 控制主机配置了 DNS 设置，接下来，将您的域添加到`/etc/krb5.conf`。例如，我的测试域是`mastery.example.com`，我的域控制器是`DEMODEM-O5NVEP9.mastery.example.com`，所以我的`/etc/krb5.conf`文件底部看起来是这样的：

```
[realms]
MASTERY.EXAMPLE.COM = {
 kdc = DEMODEM-O5NVEP9.mastery.example.com
}
[domain_realm]
.mastery.example.com = MASTERY.EXAMPLE.COM
```

注意大写——这很重要！使用`kinit`命令测试您的 Kerberos 集成，使用已知的域用户帐户。例如，我将使用以下命令测试我的测试域的集成：

```
kinit Administrator@MASTERY.EXAMPLE.COM
klist
```

成功的测试结果应该像*图 4.7*中所示的那样：

![图 4.7 – 在 Ubuntu Ansible 控制主机和 Windows 域控制器之间测试 Kerberos 集成](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_04_07.jpg)

图 4.7 – 在 Ubuntu Ansible 控制主机和 Windows 域控制器之间测试 Kerberos 集成

最后，让我们创建一个 Windows 主机清单——请注意，它几乎与我们在基本身份验证示例中使用的清单相同；只是这一次，在用户名之后，我们指定了 Kerberos 域：

```
[windows]
10.0.50.103
[windows:vars]
ansible_user=administrator@MASTERY.EXAMPLE.COM
ansible_password="Password123"
ansible_port=5986
ansible_connection=winrm
ansible_winrm_server_cert_validation=ignore
```

现在，我们可以像以前一样测试连接：

![图 4.8 – 使用 ansible.windows.win_ping 模块进行 Ansible 连接测试和 Kerberos 身份验证](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_04_08.jpg)

图 4.8 – 使用 ansible.windows.win_ping 模块和 Kerberos 身份验证进行 Ansible 连接测试

成功！前面的结果显示了与 Windows 的成功端到端连接，包括使用 Kerberos 对域帐户进行成功认证，并访问 WinRM 子系统。

## 关于账户的说明

默认情况下，WinRM 配置为仅允许由给定 Windows 主机上的本地`Administrators`组的成员进行管理。这不一定是管理员帐户本身——我们在这里使用它仅用于演示目的。可以启用使用权限较低的帐户进行 WinRM 管理，但是它们的使用可能会受到限制，因为大多数 Ansible 命令需要一定程度的特权访问。如果您希望通过 WinRM 为 Ansible 提供一个权限较低的帐户，可以在主机上运行以下命令：

```
winrm configSDDL default
```

运行此命令会打开一个 Windows 对话框。使用它来添加并授予（至少）`Read`和`Execute`权限给您希望具有 WinRM 远程管理能力的任何用户或组。

## 通过 WinRM 进行证书验证

到目前为止，我们一直忽略了 WinRM 通信中使用的自签名 SSL 证书——显然，这不是理想的情况，如果 SSL 证书不是自签名的，让 Ansible 验证 SSL 证书是非常简单的。

如果您的 Windows 机器是域成员，最简单的方法是使用**Active Directory Certificate Services**（**ADCS**）- 但是，大多数企业将通过 ADCS 或其他第三方服务拥有自己的认证流程。假设为了继续本节，所涉及的 Windows 主机已生成了用于远程管理的证书，并且 CA 证书以 Base64 格式可用。

就像我们之前在 Windows 主机上所做的那样，您需要设置一个 HTTPS 监听器，但这次要使用您的 CA 签名的证书。您可以使用以下命令（如果尚未完成）来执行此操作：

```
Import-Certificate -FilePath .\certnew.cer -CertStoreLocation Cert:\LocalMachine\My
```

自然地，将`FilePath`证书替换为与您自己证书位置匹配的证书。如果需要，您可以使用以下命令删除以前创建的任何 HTTPS WinRM 监听器：

```
winrm delete winrm/config/Listener?Address=*+Transport=HTTPS
```

然后，使用导入证书的指纹创建一个新的监听器：

```
New-Item -Path WSMan:\Localhost\Listener -Transport HTTPS -Address * -CertificateThumbprint <thumbprint of certificate>
```

现在到 Ansible 控制器。首先要做的是将 WinRM 监听器的 CA 证书导入到操作系统的 CA 捆绑包中。这种方法和位置在不同的操作系统之间会有所不同，但是在 Ubuntu Server 20.04 上，您可以将 Base64 编码的 CA 证书放在`/usr/share/ca-certificates/`中。请注意，为了被识别，CA 文件必须具有`.crt`扩展名。

完成此操作后，运行以下命令：

```
sudo dpkg-reconfigure ca-certificates
```

在被问及是否要信任新证书颁发机构的证书时选择“是”，并确保在下一个屏幕上呈现的列表中选择您的新证书文件名。

最后，我们需要告诉 Ansible 在哪里找到证书。默认情况下，Ansible 使用 Python Certifi 模块，并且除非我们告诉它否则，否则将使用默认路径。上述过程更新了 CA 捆绑包，位于`/etc/ssl/certs/ca-certificates.crt`，幸运的是，我们可以在清单文件中告诉 Ansible 在哪里找到它。请注意清单文件中所示的两个进一步更改，首先，我们现在已经指定了 Windows 主机的完整主机名，而不是 IP 地址，因为清单主机名必须与证书上的`CN`值匹配，以进行完整验证。此外，我们已经删除了`ansible_winrm_server_cert_validation`行，这意味着现在所有 SSL 证书都会被隐式验证：

```
[windows]
DEMODEM-O5NVEP9.mastery.example.com
[windows:vars]
ansible_user=administrator@MASTERY.EXAMPLE.COM
ansible_password="Password123"
ansible_port=5986
ansible_connection=winrm
ansible_winrm_ca_trust_path=/etc/ssl/certs/ca-certificates.crt
```

如果我们再次运行 ping 测试，我们应该会看到`SUCCESS`，如*图 4.9*所示：

![图 4.9 - 使用 Kerberos 身份验证和 SSL 验证对 Windows 域控制器进行 Ansible ping 测试](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_04_09.jpg)

图 4.9 - 使用 Kerberos 身份验证和 SSL 验证对 Windows 域控制器进行 Ansible ping 测试

显然，我们可以改进我们的证书生成以消除`subjectAltName`警告，但目前，这演示了 Ansible 与 Windows 的连接，使用 Kerberos 身份验证连接到域帐户并进行完整的 SSL 验证。这完成了我们对设置 WinRM 的介绍，并应为您提供了在您的基础架构中为 Ansible 设置 Windows 主机所需的所有基础知识。

在本章的下一部分中，我们将看一下在 Windows 上设置新支持的 OpenSSH 服务器，以启用 Ansible 自动化。

# 使用 OpenSSH 设置 Windows 主机以进行 Ansible 控制

微软在支持和拥抱开源社区方面取得了巨大进展，并向其操作系统添加了许多流行的开源软件包。就 Ansible 自动化而言，最值得注意的是备受推崇和非常受欢迎的 OpenSSH 软件包，它有客户端和服务器两种版本。

在 Ansible 2.8 中添加了使用 SSH 而不是 WinRM 作为传输的 Windows 自动化任务的支持 - 但是，应该注意官方 Ansible 文档中对此支持有许多警告 - 支持被描述为实验性，并且用户被警告未来可能会以不向后兼容的方式进行更改。此外，开发人员预计在继续测试时会发现更多的错误。

出于这些原因，我们已经付出了很多努力来描述使用 WinRM 自动化 Windows 主机与 Ansible。尽管如此，本章没有涉及使用 OpenSSH 为 Windows 启用 Ansible 自动化的内容将不完整。

Windows 上的 OpenSSH 服务器支持 Windows 10 版本 1809 及更高版本，以及 Windows Server 2019。如果您正在运行较旧版本的 Windows，则有两种选择 - 要么继续使用 WinRM 作为通信协议（毕竟，它是内置的，并且一旦您知道如何配置，就很容易），要么手动安装 Win32-OpenSSH 软件包 - 此过程在此处有详细描述，并且应该支持从 Windows 7 开始的任何版本：[`github.com/PowerShell/Win32-OpenSSH/wiki/Install-Win32-OpenSSH`](https://github.com/PowerShell/Win32-OpenSSH/wiki/Install-Win32-OpenSSH)。鉴于该软件包的积极开发，读者被建议在想要在较旧版本的 Windows 上安装 OpenSSH 服务器时参考此文档，因为说明可能在书籍印刷时已经发生了变化。

但是，如果您正在运行较新版本的 Windows，则安装 OpenSSH 服务器就很简单。首先，使用具有管理员权限的 PowerShell 会话，首先使用以下命令查询可用的`OpenSSH`选项：

```
Get-WindowsCapability -Online | ? Name -like 'OpenSSH*'
```

此命令的输出应该与*图 4.10*中的内容类似：

![图 4.10 - 在 Windows Server 2019 上的 PowerShell 中显示可用的 OpenSSH 安装选项

]

图 4.10 - 在 Windows Server 2019 上的 PowerShell 中显示可用的 OpenSSH 安装选项

使用此输出，运行以下命令安装 OpenSSH 服务器：

```
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
```

接下来，运行以下命令以确保 SSH 服务器服务在启动时启动，已启动，并且存在适当的防火墙规则以允许 SSH 流量到服务器：

```
Start-Service sshd
Set-Service -Name sshd -StartupType 'Automatic'
Get-NetFirewallRule -Name *ssh*
```

如果不存在适当的防火墙规则，您可以使用以下命令添加一个：

```
New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
```

最后，Windows 的 OpenSSH 服务器默认为`cmd`。这对于交互式任务来说很好，但是大多数用于 Windows 的本机 Ansible 模块都是为了支持 PowerShell 而编写的 - 您可以通过在 PowerShell 中运行以下命令来更改 OpenSSH 服务器的默认 shell：

```
New-ItemProperty -Path 'HKLM:\SOFTWARE\OpenSSH' -Name 'DefaultShell' -Value 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
```

完成所有这些任务后，我们最终可以像以前一样测试我们的`ansible.windows.win_ping`模块。我们的清单文件将与 WinRM 的不同 - 以下内容应该作为您测试的一个合适的示例：

```
[windows]
DEMODEM-O5NVEP9.mastery.example.com
[windows:vars]
ansible_user=administrator@MASTERY.EXAMPLE.COM
ansible_password="Password123"
ansible_shell_type=powershell
```

请注意，我们不再关心证书验证或端口号，因为我们正在使用默认端口`22`上的 SSH。实际上，除了用户名和密码（您可以像我们在本书早期那样轻松地将其指定为`ansible`命令的命令行参数），唯一需要设置的清单变量是`ansible_shell_type`，除非我们另行告知，否则它将默认为 Bourne 兼容的 shell。

`win_ping`模块在测试连接时使用 PowerShell，使我们能够使用先前的临时命令来测试我们新的 SSH 连接到 Windows。只需运行此命令（现在应该看起来很熟悉！）：

```
ansible -i windows-hosts -m ansible.windows.win_ping all
```

即使我们现在使用了完全不同的通信协议，但是此命令的输出与之前完全相同，并且应该看起来像下面的*图 4.11*：

![图 4.11 - 使用 SSH 作为传输机制测试 Windows 上的 Ansible 集成](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_04_11.jpg)

图 4.11——使用 SSH 作为传输机制测试 Windows 与 Ansible 集成

因此，将 Ansible 与 Windows 主机集成起来真的非常简单——只需确保关注新版本的发布说明和迁移指南，以防某些不兼容的变化。然而，我认为您会同意，使用 OpenSSH 将 Ansible 与 Windows 集成起来也很简单。当然，您可以以类似的方式设置 SSH 密钥认证，就像在任何其他基于 SSH 的主机上一样，以确保您可以在无需用户交互的情况下运行 playbooks。

现在，在通过 WinRM 和 SSH 演示与 Ansible 的 Windows 集成的方面，我们只使用了 Ansible `ansible.windows.win_ping`模块来测试连接。让我们通过一些简单的示例 playbooks 结束本章，以帮助您开始创建自己的 Windows 自动化解决方案。

# 使用 Ansible 自动化 Windows 任务

Ansible 4.3 包含的 Windows 模块列表可在以下链接找到，需要注意的是，虽然您可以在 Windows 主机上使用所有熟悉的 Ansible 构造，如`vars`、`handlers`和`blocks`，但在定义任务时必须使用特定于 Windows 的模块。引入了集合意味着很容易找到它们，`ansible.windows`集合是一个很好的起点。其中包含了您在 Ansible 2.9 及更早版本中使用的所有特定于 Windows 的模块：https://docs.ansible.com/ansible/latest/collections/index_module.html#ansible-windows。

在本章的这一部分中，我们将运行一些简单的 Windows playbook 示例，以突出编写 Windows playbook 时需要了解的一些内容。

## 选择正确的模块

如果您要针对 Linux 服务器运行 Ansible，并且想要创建一个目录，然后将文件复制到其中，您将使用`ansible.builtin.file`和`ansible.builtin.copy` Ansible 模块，playbook 看起来类似于以下内容：

```
---
- name: Linux file example playbook
  hosts: all
  gather_facts: false
  tasks:
    - name: Create temporary directory
      ansible.builtin.file:
        path: /tmp/mastery
        state: directory
    - name: Copy across a test file
      ansible.builtin.copy:
        src: mastery.txt
        dest: /tmp/mastery/mastery.txt
```

然而，在 Windows 上，此 playbook 将无法运行，因为`ansible.builtin.file`和`ansible.builtin.copy`模块与 PowerShell 或 cmd 不兼容，无论您使用 WinRM 还是 SSH 作为与 Windows 机器通信的协议。因此，执行相同任务的等效 playbook 在 Windows 上将如下所示：

```
---
- name: Windows file example playbook
  hosts: all
  gather_facts: false
  tasks:
    - name: Create temporary directory
      ansible.windows.win_file:
        path: 'C:\Mastery Test'
        state: directory
    - name: Copy across a test file
      ansible.windows.win_copy:
        src: ~/src/mastery/mastery.txt
        dest: 'C:\Mastery Test\mastery.txt'
```

请注意以下两个 playbook 之间的区别：

+   `ansible.windows.win_file`和`ansible.windows.win_copy`用于替代`ansible.builtin.file`和`ansible.builtin.copy`模块。

+   在`ansible.windows.win_file`和`ansible.windows.win_copy`模块的文档中建议在处理远程（Windows 路径）时使用反斜杠（`\`）。

+   继续在 Linux 主机上使用正斜杠（`/`）。

+   使用单引号（而不是双引号）引用包含空格的路径。

始终重要的是查阅 playbooks 中使用的各个模块的文档。例如，查看`ansible.windows.win_copy`模块的文档，它建议在进行大文件传输时使用`ansible.windows.win_get_url`模块，因为 WinRM 传输机制效率不高。当然，如果您使用 OpenSSH 服务器代替 WinRM，则可能不适用——在撰写本文时，该模块的文档尚未更新以考虑这一点。

还要注意，如果文件名包含某些特殊字符（例如方括号），则需要使用 PowerShell 转义字符`` ` ``进行转义。例如，以下任务将安装`c:\temp\setupdownloader_[aaff].exe`文件：

```
  - name: Install package
    win_package:
      path: 'c:\temp\setupdownloader_`[aaff`].exe'
      product_id: {00000000-0000-0000-0000-000000000000}
      arguments: /silent /unattended
      state: present
```

许多其他 Windows 模块足以满足您的 Windows 剧本需求，结合这些技巧，您将能够快速轻松地获得所需的结果。

## 安装软件

大多数 Linux 系统（以及其他 Unix 变体）都有一个原生包管理器，使得安装各种软件变得容易。`chocolatey`包管理器使得 Windows 也能实现这一点，而 Ansible 的`chocolatey.chocolatey.win_chocolatey`模块使得以无人值守方式使用 Ansible 安装软件变得简单（注意，这不是我们迄今为止使用的`ansible.windows`集合的一部分，而是存在于其自己的集合中）。

您可以探索`chocolatey`仓库，并在[`chocolatey.org`](https://chocolatey.org)了解更多信息。

例如，如果您想在 Windows 机器群中部署 Adobe 的 Acrobat Reader，您可以使用`ansible.windows.win_copy`或`ansible.windows.win_get_url`模块分发安装程序，然后使用`ansible.windows.win_package`模块进行安装。然而，以下代码将以更少的代码执行相同的任务：

```
- name: Install Acrobat Reader
  chocolatey.chocolatey.win_chocolatey:
    name: adobereader
    state: present
```

使用`chocolatey.chocolatey.win_chocolatey`模块，您可以运行各种巧妙的安装例程——例如，您可以将软件包锁定到特定版本，安装特定架构，以及更多功能——该模块的文档包含了许多有用的示例。官方 Chocolatey 网站本身列出了所有可用的软件包——大多数您期望需要的常见软件包都可以在那里找到，因此它应该满足您将遇到的大多数安装场景。

## 超越模块

就像在任何平台上一样，可能会遇到所需的确切功能无法从模块获得的情况。虽然编写自定义模块（或修改现有模块）是解决此问题的可行方案，但有时需要更即时的解决方案。为此，`ansible.windows.win_command`和`ansible.windows.win_shell`模块派上了用场——这些模块可以在 Windows 上运行实际的 PowerShell 命令。官方 Ansible 文档中有许多示例，但以下代码，例如，将使用 PowerShell 创建`C:\Mastery`目录：

```
    - name: Create a directory using PowerShell
      ansible.windows.win_shell: New-Item -Path C:\Mastery -ItemType Directory
```

我们甚至可以为此任务回退到传统的`cmd` shell：

```
    - name: Create a directory using cmd.exe
      ansible.windows.win_shell: mkdir C:\MasteryCMD
      args:
        executable: cmd
```

有了这些提示，应该可以在几乎任何 Windows 环境中创建所需的功能。

通过以上内容，我们结束了对 Windows 自动化与 Ansible 的探讨——只要您记得使用正确的 Windows 原生模块，您就能像对待任何给定的 Linux 主机一样轻松地将本书其余部分应用于 Windows 主机。

# 总结

Ansible 处理 Windows 主机与 Linux（及其他 Unix）主机同样有效。本章我们介绍了如何从 Windows 主机运行 Ansible，以及如何将 Windows 主机与 Ansible 集成以实现自动化，包括认证机制、加密，甚至 Windows 特定 playbook 的基础知识。

你已经了解到，Ansible 可以在支持 WSL 的最新版 Windows 上运行，并学会了如何实现这一点。你还学会了如何为 Ansible 控制设置 Windows 主机，以及如何通过 Kerberos 认证和加密来确保安全。你也学会了如何设置和使用 Ansible 与 Windows 主机间的新实验性 SSH 通信支持。最后，你学习了编写 Windows playbook 的基础知识，包括找到适用于 Windows 主机的正确模块、转义特殊字符、为主机创建目录和复制文件、安装软件包，甚至使用 Ansible 在 Windows 主机上运行原始 shell 命令。这是一个坚实的基础，你可以在此基础上构建出管理自己 Windows 主机群所需的 Windows playbook。

下一章我们将介绍如何在企业中通过 AWX 有效管理 Ansible。

# 问题

1.  Ansible 可以通过以下方式与 Windows 主机通信：

    a) SSH

    b) WinRM

    c) 两者皆是

1.  Ansible 可以可靠地在 Windows 上运行：

    a) 原生地

    b) 使用 Python for Windows

    c) 通过 Cygwin

    d) 通过 WSL 或 WSL2

1.  `ansible.builtin.file`模块可用于在 Linux 和 Windows 主机上操作文件：

    a) True

    b) False

1.  Windows 机器无需初始设置即可运行 Ansible 自动化：

    a) True

    b) False

1.  Windows 的包管理器称为：

    a) Bournville

    b) Cadbury

    c) Chocolatey

    d) RPM

1.  Windows 的 Ansible 模块默认通过以下方式运行命令：

    a) PowerShell

    b) `cmd.exe`

    c) Bash for Windows

    d) WSL

    e) Cygwin

1.  即使没有所需功能的模块，你也可以直接运行 Windows 命令：

    a) True

    b) False

1.  在使用 Ansible 操作 Windows 上的文件和目录时，你应该：

    a) 使用`\`表示 Windows 路径引用，使用`/`表示 Linux 主机上的文件

    b) 对所有路径使用`/`

1.  Windows 文件名中的特殊字符应使用以下方式转义：

    a) `\`

    b) `` ` ``

c）`"`

d）`/`

1.  您的 Ansible 剧本必须根据您是使用 WinRM 还是 SSH 通信而进行更改：

a）真

b）假


# 第五章：使用 AWX 进行企业基础设施管理

可以明显看出，Ansible 是一个非常强大和多功能的自动化工具，非常适合管理整个服务器和网络设备。单调、重复的任务可以变得可重复和简单，节省大量时间！显然，在企业环境中，这是非常有益的。然而，这种力量是有代价的。如果每个人都在自己的机器上有自己的 Ansible 副本，那么你怎么知道谁运行了什么 playbook，以及何时运行的？如何确保所有 playbooks 都被正确存储和进行版本控制？此外，你如何防止超级用户级别的访问凭据在你的组织中泛滥，同时又能从 Ansible 的强大功能中受益？

这些问题的答案以 AWX 的形式呈现，它是一个用于 Ansible 的开源企业管理系统。AWX 是商业 Ansible Tower 软件的开源上游版本，可从 Red Hat 获得，它提供几乎相同的功能和好处，但没有 Red Hat 提供的支持或产品发布周期。AWX 是一个功能强大、功能丰富的产品，不仅包括 GUI，使非 Ansible 用户可以轻松运行 playbooks，还包括完整的 API，可集成到更大的工作流和 CI/CD 流水线中。

在本章中，我们将为您提供安装和使用 AWX 的坚实基础，具体涵盖以下主题：

+   启动和运行 AWX

+   将 AWX 与您的第一个 playbook 集成

+   超越基础知识

# 技术要求

要遵循本章中提出的示例，您需要一台运行 Ansible 4.3 或更新版本的 Linux 机器。几乎任何 Linux 版本都可以；对于那些对具体细节感兴趣的人，本章中提供的所有代码都是在 Ubuntu Server 20.04 LTS 上测试的，除非另有说明，并且在 Ansible 4.3 上测试。本章附带的示例代码可以从 GitHub 的以下网址下载：[`github.com/PacktPublishing/Mastering-Ansible-Fourth-Edition/tree/main/Chapter05`](https://github.com/PacktPublishing/Mastering-Ansible-Fourth-Edition/tree/main/Chapter05)。

查看以下视频，了解来自 Packt 的实际代码演示视频：[`bit.ly/3ndx73Q`](https://bit.ly/3ndx73Q)

# 启动和运行 AWX

在我们深入讨论安装 AWX 之前，值得简要探讨一下 AWX 是什么，以及它不是什么。AWX 是一个与 Ansible 并用的工具。它不以任何方式复制或复制 Ansible 的功能。事实上，当从 AWX 运行 Ansible playbooks 时，幕后实际上是调用了`ansible-playbook`可执行文件。AWX 应被视为一个补充工具，它增加了许多企业所依赖的以下好处：

+   丰富的基于角色的访问控制（RBAC）

+   与集中式登录服务（例如 LDAP 或 AD）集成

+   安全凭据管理

+   可审计性

+   问责制

+   降低新操作员的准入门槛

+   改进 playbook 版本控制的管理

+   完整的 API

大部分 AWX 代码在一组 Linux 容器中运行。然而，自上一版书以来，标准安装方法已经改变，现在更倾向于在 Kubernetes 上部署 AWX。如果您已经精通 Kubernetes，您可能希望尝试在自己的环境中部署，因为 AWX 应该可以在 Red Hat 的 OpenShift、开源 OKD 以及许多其他现有的 Kubernetes 版本上运行。

然而，如果您不精通 Kubernetes，或者正在寻找一些入门指南，那么我们将在本章的这一部分为您详细介绍如何从头开始完整安装 AWX。我们将基于出色的`microk8s`发行版进行，您可以在 Ubuntu Server 上只用一个命令即可在单个节点上启动和运行！

在开始之前，最后一点。尽管 Kubernetes 现在是首选的安装平台，但在撰写本文时，仍然有一个可用于 Docker 主机的安装方法。但是，AWX 项目的维护者指出，这仅针对开发和测试环境，并没有官方发布的版本。因此，我们在本章中不会涵盖这一点。但是，如果您想了解更多，可以阅读以下链接中的安装说明：[`github.com/ansible/awx/blob/devel/tools/docker-compose/README.md`](https://github.com/ansible/awx/blob/devel/tools/docker-compose/README.md)。

有了这个，让我们开始我们基于`microk8s`的部署。这里概述的安装过程假定您从未修改过的 Ubuntu Server 20.04 安装开始。

首先，让我们安装`microk8s`本身，使用 Ubuntu 提供的`snap`：

```
sudo snap install microk8s --classic
```

唯一需要的其他步骤是将您的用户帐户添加到`microk8s`组中，以便您可以在本节中运行剩余的命令而无需`sudo`权限：

```
sudo gpasswd -a $USER microk8s
```

您需要注销并重新登录，以使组成员身份的更改应用到您的帐户。一旦您这样做了，让我们开始准备`microk8s`进行 AWX 部署。我们需要`storage`、`dns`和`ingress`插件来进行我们的部署，因此让我们使用以下命令启用它们：

```
for i in storage dns ingress; do microk8s enable $i; done
```

现在我们准备安装 AWX Operator，这又用于管理其余的安装。安装这个就像运行以下命令一样简单：

```
microk8s kubectl apply -f https://raw.githubusercontent.com/ansible/awx-operator/devel/deploy/awx-operator.yaml
```

该命令将立即返回，而安装将在后台继续进行。您可以使用以下命令检查安装的状态：

```
microk8s kubectl get pods
```

`STATUS`字段应该在 AWX Operator 部署完成后显示`Running`。

重要提示

上一个命令将克隆 AWX Operator 的最新开发版本。如果您想克隆其中一个发布版，请浏览存储库的*Releases*部分，可在以下链接找到，并检出您想要的版本：[`github.com/ansible/awx-operator/releases`](https://github.com/ansible/awx-operator/releases)。

*图 5.1*中的屏幕截图显示了成功部署 AWX Operator 后的输出：

![图 5.1 - 成功部署 AWX Operator 后的 microk8s pod 状态](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_05_01.png)

图 5.1 - 成功部署 AWX Operator 后的 microk8s pod 状态

接下来，我们将为我们的 AWX 部署创建一个简单的自签名证书。如果您有自己的证书颁发机构，当然可以生成适合您环境的证书。如果您要使用以下命令生成自签名证书，请确保将`awx.example.org`替换为您为 AWX 服务器分配的主机名：

```
openssl req -x509 -nodes -days 3650 -newkey rsa:2048 -keyout awx.key -out awx.crt -subj "/CN=awx.example.org/O=mastery" -addext "subjectAltName = DNS:awx.example.org"
```

我们将在 Kubernetes 中创建一个包含我们新生成的证书的 secret（包含少量敏感数据的对象）：

```
microk8s kubectl create secret tls awx-secret-ssl --namespace default --key awx.key --cert awx.crt
```

完成后，现在是考虑存储的时候了。AWX 旨在从源代码存储库（如 Git）中获取其 playbooks，并且因此，默认安装不提供对本地 playbook 文件的简单访问。但是，为了在本书中创建一个每个人都可以遵循的工作示例，我们将创建一个持久卷来存储本地 playbooks。创建一个名为`my-awx-storage.yml`的 YAML 文件，其中包含以下内容：

```
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: awx-pvc
spec:
  accessModes:
    - ReadWriteMany
  storageClassName: microk8s-hostpath
  resources:
    requests:
      storage: 1Gi
```

运行以下命令，使用我们刚创建的 YAML 文件来创建这个存储：

```
microk8s kubectl create -f my-awx-storage.yml
```

现在是部署 AWX 本身的时候了。为此，我们必须创建另一个描述部署的 YAML 文件。我们将称其为`my-awx.yml`，对于我们的示例，它应该包含以下内容：

```
apiVersion: awx.ansible.com/v1beta1
kind: AWX
metadata:
  name: awx
spec:
  tower_ingress_type: Ingress
  tower_ingress_tls_secret: awx-secret-ssl
  tower_hostname: awx.example.org
  tower_projects_existing_claim: awx-pvc
  tower_projects_persistence: true
```

使用以下命令使用此文件部署 AWX：

```
microk8s kubectl apply -f my-awx.yml
```

部署将需要几分钟时间，特别是第一次运行时，因为容器映像必须在后台下载。您可以使用以下命令检查状态：

```
microk8s kubectl get pods
```

当部署完成时，所有 pod 的`STATUS`应显示为`Running`，如*图 5.2*所示：

![图 5.2-成功部署 AWX 后的 Kubernetes pod 状态](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_05_02.jpg)

图 5.2-成功部署 AWX 后的 Kubernetes pod 状态

当然，如果我们无法访问 AWX，部署 AWX 就只能有限的用途。我们将使用 Microk8s 的入口附加组件创建一个入口路由器，以便我们可以在我们选择的主机名（在本例中为`awx.example.org`）上访问我们的 AWX 部署，通过标准的 HTTPS 端口。创建另一个 YAML 文件，这次称为`my-awx-ingress.yml`。它应包含以下内容：

```
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: awx-ingress
  annotations:
    nginx.ingress.kubernetes.io/rewrite-target: /$1
spec:
  tls:
  - hosts:
    - awx.example.org
    secretName: awx-secret-ssl
  rules:
    - host: awx.example.org
      http:
        paths:
          - backend:
              service:
                name: awx-service
                port:
                  number: 80
            path: /
            pathType: Prefix
```

部署，然后使用以下命令检查此入口定义：

```
microk8s kubectl apply -f my-awx-ingress.yml
microk8s kubectl describe ingress
```

如果您没有看到`Reason`值设置为`CREATE`的事件，您可能需要删除然后重新部署入口定义，如下所示：

```
microk8s kubectl delete -f my-awx-ingress.yml
microk8s kubectl apply -f my-awx-ingress.yml
```

入口规则的成功部署应该看起来像下图所示：

![图 5.3-成功部署 AWX 的入口配置](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_05_03.jpg)

图 5.3-成功部署 AWX 的入口配置

登录到 AWX 的默认用户名是`admin`。但是，密码是随机生成的并存储在 Kubernetes 的一个秘密中。要检索这个密码以便您第一次登录，请运行以下命令：

```
microk8s kubectl get secret awx-admin-password -o jsonpath='{.data.password}' | base64 --decode
```

恭喜！您现在应该能够通过浏览器登录到您之前选择的主机名的 AWX 部署。在本例中，它将是[`awx.example.org`](https://awx.example.org)。

在第一次运行 AWX 时，许多操作（如构建数据库模式）都是在后台执行的。因此，最初看起来 GUI 没有响应。如果您的 pod 状态看起来健康，请耐心等待，几分钟后您将看到登录屏幕出现，如下图所示：

![图 5.4-部署 AWX 后访问登录屏幕](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_05_04.jpg)

图 5.4-部署 AWX 后访问登录屏幕

当您第一次登录到 AWX 时，您将看到一个仪表板屏幕和左侧的菜单栏。通过这个菜单栏，我们将探索 AWX 并进行我们的第一个配置工作。同样值得注意的是，当首次安装 AWX 时，会填充一些示例内容，以帮助您更快地上手。请随意探索演示内容，因为示例与本书中给出的示例不同。

在我们完成本节之前，考虑一下我们之前创建的用于存储本地 playbooks 的持久卷。我们如何访问它？当使用`microk8s`的简单单节点部署时，您可以执行一些命令来查询环境并找出文件应该放在哪里。

首先，检索您的`hostpath-provisioner` pod 的名称。它应该看起来有点像`hostpath-provisioner-5c65fbdb4f-jcq8b`，可以使用以下命令检索：

```
microk8s kubectl get pods -A | awk '/hostpath/ {print $2}'
```

确定了这个唯一的名称后，运行以下命令来发现文件被存储在您的 pod 的本地目录。确保用您系统中的唯一`hostpath-provisioner`名称替换它：

```
microk8s kubectl describe -n kube-system pod/hostpath-provisioner-5c65fbdb4f-jcq8b | awk '/PV_DIR/ {print $2}'
```

最后，使用以下命令检索您的 AWX playbooks 的持久卷索赔的唯一名称：

```
microk8s kubectl describe pvc/awx-pvc | awk '/Volume:/ {print $2}'
```

您的最终路径将是这些结果的综合，包括`namespace`（在本例中为`default`），以及您的 PVC 名称（在之前的`my-awx-storage.yml`文件中定义为`awx-pvc`）。因此，在我的演示系统上，我的本地 playbooks 应放在以下目录下：

```
/var/snap/microk8s/common/default-storage/default-awx-pvc-pvc-52ea2e69-f3c7-4dd0-abcb-2a1370ca3ac6/
```

我们将在本章后面将一些简单的示例操作手册放入此目录，因此现在找到它并做个笔记，以便您可以轻松地在以后的示例中访问它。

在 Microk8s 上运行 AWX 后，我们将在下一节中查看如何将我们的第一个操作手册集成并运行在 AWX 中。

# 将 AWX 与您的第一个操作手册集成

将操作手册集成到 AWX 中涉及基本的四个阶段过程。一旦您理解了这一点，就为更高级的用法和在企业环境中更完整的集成铺平了道路。在本章的这一部分，我们将掌握这四个阶段，以便达到我们可以运行我们的第一个简单操作手册的地步，这将为我们在 AWX 中自信地前进提供基础。这四个阶段如下：

1.  定义项目。

1.  定义清单。

1.  定义凭据。

1.  定义模板。

前三个阶段可以以任何顺序执行，但最后一个阶段提到的模板将三个先前创建的方面汇集在一起。因此，它必须最后定义。还要注意，这些项目之间不需要一对一的关系。可以从一个项目创建多个模板。清单和凭据也是如此。

在我们开始之前，我们需要一个简单的操作手册，可以在本章的示例中使用。在 AWX 主机上，找到本地 AWX 持久卷文件夹（如果您在 Microk8s 上运行 AWX，则在上一节中有描述）。我将在以下命令中展示我的演示系统的示例，但您的系统将有其自己的唯一 ID。确保您调整路径以适应您的系统-复制和粘贴我的路径几乎肯定不起作用！

每个本地托管的项目必须在持久卷中有自己的子目录，因此让我们在这里创建一个：

```
cd /var/snap/microk8s/common/default-storage/default-awx-pvc-pvc-64aee7f5-a65d-493d-bdc1-2c33f7da8a4e
mkdir /var/lib/awx/projects/mastery
```

现在将以下示例代码放入此文件夹中，作为`example.yaml`：

```
---
- name: AWX example playbook
  hosts: all
  gather_facts: false
  tasks:
    - name: Create temporary directory
      ansible.builtin.file:
        path: /tmp/mastery
        state: directory
    - name: Create a file with example text
      ansible.builtin.lineinfile:
        path: /tmp/mastery/mastery.txt
        line: 'Created with Ansible Mastery!'
        create: yes
```

完成后，我们可以继续定义项目。

## 定义项目。

在 AWX 术语中，项目只是一组组合在一起的 Ansible 操作手册。这些操作手册的集合通常来自**源代码管理**（SCM）系统。事实上，这是在企业中托管 Ansible 操作手册的推荐方式。使用 SCM 意味着每个人都在使用相同版本的代码，并且所有更改都得到跟踪。这些是企业环境中至关重要的元素。

关于操作手册的分组，没有组织项目的正确或错误方式，因此这很大程度上取决于涉及的团队。简单地说，一个项目链接到一个存储库，因此如果多个操作手册存放在一个存储库中是有意义的，它们将存放在 AWX 中的一个项目中。但这不是必需的-如果适合您的需求，您可以每个项目只有一个操作手册！

如前所述，还可以在本地存储 Ansible 操作手册。在测试或刚开始时，这很有用，我们将在这里的示例中利用这种能力，因为它确保了阅读本书的每个人都可以轻松完成示例。

使用`admin`帐户登录 AWX 界面，然后单击左侧菜单栏上的**项目**链接。然后单击窗口右上角附近的**添加**按钮。这为我们创建了一个新的空白项目。

目前，我们不需要担心所有字段（我们将在后面详细讨论这些）。但是，我们需要配置以下内容：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/Table_1.jpg)

最终结果应该看起来像下图所示：

![图 5.5-使用我们的本地操作手册目录在 AWX 中创建您的第一个项目](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_05_05.jpg)

图 5.5-使用我们的本地操作手册目录在 AWX 中创建您的第一个项目

单击**保存**按钮以保存您的编辑。就是这样-您已经在 AWX 中定义了您的第一个项目！从这里开始，我们可以定义清单。

## 定义库存

AWX 中的库存与我们在*第一章*中使用命令行引用的库存完全相同，*Ansible 的系统架构和设计*，它们可以是静态的或动态的，可以由组和/或单个主机组成，并且可以在全局每组或每个主机基础上定义变量-我们现在只是通过用户界面定义它们。

单击左侧菜单栏上的**库存**项。与项目一样，我们想要定义新的内容，因此单击窗口右上方附近的**添加**按钮。将出现一个下拉列表。从中选择**添加库存**。

当**创建新库存**屏幕出现时，输入库存的名称（例如`Mastery Demo`），然后单击**保存**按钮。

重要说明

在定义主机或组之前，您必须保存空白库存。

完成后，您应该看到一个类似于以下图所示的屏幕：

![图 5.6-AWX 中创建新的空库存](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_05_06.jpg)

图 5.6-AWX 中创建新的空库存

保存新库存后，请注意库存子窗格顶部的选项卡-**详情**、**访问**、**组**、**主机**、**来源**和**作业**。您几乎可以在 AWX 用户界面的每个窗格上找到这样的选项卡-我们在本章早些时候定义了第一个项目后也看到了它们（在那个阶段我们只是不需要使用它们）。

为了简化我们的示例，我们将在一个组中定义一个主机，以便运行我们的示例 playbook。单击**组**选项卡，然后单击**添加**按钮以添加新的库存组。给组命名并单击**保存**，如下图所示：

![图 5.7-在 AWX 中创建新的库存组](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_05_07.jpg)

图 5.7-在 AWX 中创建新的库存组

现在单击**主机**选项卡，然后单击**添加**按钮，并从下拉菜单中选择**添加新主机**。将您的 AWX 主机的 IP 地址输入到**名称**字段中（如果您已设置 DNS 解析，则输入 FQDN）。如果需要，您还可以向主机添加描述，然后单击**保存**。最终结果应该看起来像以下图所示：

![图 5.8-在 Mastery Demo 库存的 Mastery Group 组中创建新主机](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_05_08.jpg)

图 5.8-在 Mastery Demo 库存的 Mastery Group 组中创建新主机

重要说明

大多数库存屏幕上看到的**变量**框期望以 YAML 或 JSON 格式定义变量，而不是我们在命令行上使用的 INI 格式。在此之前，我们已经定义了变量，例如`ansible_ssh_user=james`，如果选择了 YAML 模式，我们现在将输入`ansible_ssh_user: james`。

干得好！您刚刚在 AWX 中创建了您的第一个库存。如果我们要在命令行上创建这个库存，它将如下所示：

```
[MasteryGroup]
10.0.50.25
```

这可能很简单，但它为我们运行第一个 playbook 铺平了道路。接下来，让我们看看 AWX 中凭据的概念。

## 定义凭据

AWX 适用于企业的一种方式是安全存储凭据。鉴于 Ansible 的性质和典型用例，通常以 SSH 密钥或具有 root 或其他管理级别特权的密码的形式提供*王国的钥匙*。即使在保险库中加密，运行 playbook 的用户也将拥有加密密码，因此可以获取凭据。显然，让许多人不受控制地访问管理员凭据可能是不可取的。幸运的是，AWX 解决了这个问题。

让我们举一个简单的例子。假设我的测试主机（我们之前为其定义了库存）的`root`密码是`Mastery123!`。我们如何安全地存储这个密码？

首先，导航到**凭据**菜单项，然后单击**添加**按钮（就像我们之前所做的那样）来创建新内容。为凭据命名（例如，`Mastery Login`），然后单击**凭据类型**下拉菜单以展开可用凭据类型的列表（如果您在此处找不到所需的凭据类型，甚至可以创建自己的凭据类型！）。

您会看到 AWX 可以存储许多不同的凭据类型。对于我们这样的机器登录，我们希望选择`Machine`类型。设置凭据类型后，您会看到屏幕发生变化，并出现了创建机器凭据所需的字段。我们可以基于 SSH 密钥和其他各种参数定义登录，但在我们的简单示例中，我们将简单地将用户名和密码设置为适当的值，如下图所示：

![图 5.9 - 在 AWX 中添加新的机器凭据](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_05_09.jpg)

图 5.9 - 在 AWX 中添加新的机器凭据

现在，保存凭据。如果您现在返回编辑凭据，您会注意到密码消失了，并被字符串`ENCRYPTED`替换。现在无法通过 AWX 用户界面直接检索密码（或 SSH 密钥或其他敏感数据）。您会注意到可以替换现有值（通过单击现在变灰的密码字段左侧的卷曲箭头），但无法看到它。获取凭据的唯一方法将是获得与后端数据库的连接以及安装时使用的数据库的加密密钥。这意味着即使执行对数据库本身的`SELECT`操作，也无法看到密钥，因为包含敏感数据的数据库行都是使用在安装时自动生成的密钥进行加密的。尽管这显然对组织有巨大的安全益处，但也必须指出，后端数据库的丢失或与之关联的加密密钥将导致 AWX 配置的完全丢失。因此，重要的是（与任何基础设施部署一样）备份您的 AWX 部署和相关机密，以防需要从潜在的灾难情况中恢复。

尽管如此，AWX 以一种与 Ansible Vault 并不完全不同的方式保护了您的敏感访问数据。当然，Ansible Vault 仍然是一个命令行工具，尽管在 AWX 中可以像在命令行上使用 Ansible 时一样使用 vault 数据，但 vault 的创建和修改仍然是一个仅限命令行的活动。有了我们的凭据，让我们继续进行运行我们的第一个来自 AWX 的 playbook 所需的最后一步 - 定义一个模板。

## 定义模板

作业模板 - 给它完整的名称 - 是一种将之前创建的所有配置项以及任何其他所需参数汇集在一起，以针对清单运行给定 playbook 的方式。可以将其视为定义如果在命令行上运行`ansible-playbook`时的方式。

让我们立即开始创建我们的模板，按照以下步骤进行：

1.  在左侧菜单中单击**模板**。

1.  单击**添加**按钮创建新模板。

1.  从下拉列表中选择**添加作业模板**。

1.  要运行我们的第一个作业，您需要在**创建新作业模板**屏幕上定义以下字段：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/Table_2.jpg)

这应该会导致一个屏幕，看起来与下图所示的屏幕有些相似：

![图 5.10 - 在 AWX 中创建新模板](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_05_10.jpg)

图 5.10 - 在 AWX 中创建新模板

在所有字段都填充完毕后，如前面的截图所示，点击**Save**按钮。恭喜！你现在已经准备好从 AWX 运行你的第一个 playbook。要这样做，返回到**templates**列表，点击我们新创建的模板右侧的小火箭图标。立即执行后，你将看到作业执行并将看到来自`ansible-playbook`的输出，这是我们从命令行熟悉的，如下图所示：

![图 5.11 - 我们在 AWX 中第一个 playbook 模板运行的输出](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_05_11.jpg)

图 5.11 - 我们在 AWX 中第一个 playbook 模板运行的输出

在这个屏幕上，你可以看到来自`ansible-playbook`的原始输出。你可以随时通过点击菜单栏上的**Jobs**菜单项，浏览所有已运行的作业。这对于审计 AWX 一直在协调的各种活动特别有用，尤其是在大型多用户环境中。

在**Jobs**屏幕的顶部，你可以看到**Details**选项卡，列出了我们之前定义的所有基本参数，比如**Project**和**Template**。还显示了有用的审计信息，比如有关作业启动和完成时间的信息。如下图所示：

![图 5.12 - 我们的 playbook 模板运行的 Details 选项卡](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_05_12.jpg)

图 5.12 - 我们的 playbook 模板运行的 Details 选项卡

虽然 AWX 能够做更多的事情，但这些基本阶段对于你想在 AWX 中执行的大多数任务来说是至关重要的。因此，了解它们的用法和顺序对于学习如何使用 AWX 是至关重要的。现在我们已经掌握了基础知识，在下一节中我们将看一下你可以用 AWX 做的一些更高级的事情。

# 超越基础知识

我们现在已经涵盖了从 AWX 运行你的第一个 playbook 所需的基础知识 - 这是在这个环境中大多数 Ansible 自动化所需的基础知识。当然，我们不可能在一个章节中涵盖 AWX 提供的所有高级功能。因此，在本节中，我们将重点介绍一些更高级的方面，如果你想了解更多关于 AWX 的内容，可以探索。

## 基于角色的访问控制（RBAC）

到目前为止，我们只从内置的`admin`用户的角度来看 AWX 的使用。当然，AWX 的企业级功能之一就是 RBAC。这是通过使用**用户**和**团队**来实现的。团队基本上是一组用户，用户可以是一个或多个团队的成员。

用户和团队都可以在 AWX 用户界面中手动创建，或通过与外部目录服务（如 LDAP 或 Active Directory）集成来创建。在目录集成的情况下，团队很可能会映射到目录中的组，尽管丰富的配置允许管理员定义这种行为的确切性质。

AWX 内的 RBAC 非常丰富。例如，给定用户可以在一个团队中被授予`Admin`角色，并在另一个团队中被授予`Member`或`Read`角色。

用户帐户本身可以设置为系统管理员、普通用户或系统审计员。

除此之外，当我们在本章的基本设置部分进行设置时，你会注意到 AWX 用户界面的几乎每个页面上都有选项卡。其中，几乎总会有一个名为**Permissions**的选项卡，它允许实现真正的细粒度访问控制。

例如，给定的**普通用户**类型的用户可以在其分配的团队中被赋予`Admin`角色。然而，他们可以在给定项目上被分配`READ`角色，这种更具体的特权将取代在**Team**级别设置的不太具体的`Admin`角色。因此，当他们登录时，他们可以看到相关的项目，但不能更改它或执行任何任务 - 例如，来自 SCM 的更新。

重要提示

一般来说，更具体的权限会覆盖不太具体的权限。因此，在项目级别的权限将优先于团队或用户级别的权限。请注意，对于没有通过用户或其团队指定权限的项目，当用户登录到用户界面时，该人甚至都看不到该项目。唯一的例外是系统管理员，他们可以看到一切并执行任何操作。请谨慎将此类型分配给用户账户！

在涉及 RBAC 时有很多可以探索的内容。一旦掌握了它，就可以轻松创建安全且严格锁定的 AWX 部署，每个人都具有适当的访问权限。

## 组织

AWX 包含一个名为**组织**的顶级配置项。这是一组清单、项目、作业模板和团队（这些又是用户的分组）。因此，如果企业的两个不同部分具有完全不同的需求，但仍需要使用 AWX，它们可以共享单个 AWX 实例，而无需在用户界面中重叠配置。

虽然系统管理员类型的用户可以访问所有组织，但普通用户只能看到他们关联的组织和配置。这是一种非常强大的方式，可以将企业部署的 AWX 的不同部分的访问权限进行分隔。

举例来说，当我们在本章的前面创建清单时，您可能已经注意到我们忽略了**组织**字段（这被设置为默认值 - 在新的 AWX 安装中存在的唯一组织）。如果我们要创建一个名为`Mastery`的新组织，那么不是该组织成员的任何人都无法看到此清单，无论他们拥有的权限或特权如何（唯一的例外是**系统管理员**用户类型，可以看到一切）。

## 调度

一些 AWX 配置项，例如项目（可能需要从 SCM 更新）或作业模板（执行特定任务），可能需要定期运行。拥有像 AWX 这样强大的工具，但又需要操作员定期登录执行常规任务，这是没有意义的。因此，AWX 具有内置的调度功能。

在任何项目或模板的定义页面上，只需查找**调度**选项卡，然后您就可以使用丰富的调度选项 - *图 5.13*显示了一个每天运行一次的日程安排示例，从 2021 年 5 月 7 日到 11 日在伦敦时区的下午 1 点。请注意，此日程安排是针对我们之前创建的`Mastery Template`作业模板创建的，因此将自动按照定义的日程安排运行此 playbook 模板：

![图 5.13 - 创建一个每日日程安排来运行之前创建的 Mastery Template 作业模板](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_05_13.jpg)

图 5.13 - 创建一个每日日程安排来运行之前创建的 Mastery Template 作业模板

请注意，您可以选择多种调度选项。为了帮助您确保日程安排符合您的要求，在保存新日程安排时会显示日程安排的详细信息。当您有多个用户登录到 AWX 等系统并运行无人值守的日程安排时，您可以维护对正在进行的操作的监督是至关重要的。幸运的是，AWX 具有丰富的功能，允许对发生的事件进行审计，我们将在下一节中介绍这些功能。

## 审计

在命令行上运行 Ansible 的一个风险是，一旦运行了特定任务，其输出将永远丢失。当然，可以为 Ansible 打开日志记录。但是，在企业中，这需要强制执行，对于许多操作员具有给定 Ansible 机器的 root 访问权限，无论是他们自己的笔记本电脑还是其他地方的服务器，这将是困难的。幸运的是，正如我们在之前的示例中看到的，AWX 不仅存储了谁运行了什么任务以及何时运行的详细信息，还存储了所有`ansible-playbook`运行的输出。通过这种方式，企业希望使用 Ansible 的合规性和可审计性得到了实现。

只需导航到**作业**菜单项，将显示所有先前运行的作业（用户有权限查看的）。甚至可以直接从此屏幕重复以前完成的作业，只需单击问题中的火箭图标。请注意，这将立即使用与上次启动时相同的参数启动作业，因此请确保单击是您想要执行的操作！

*图 5.14*显示了我们用于本书的演示 AWX 实例的作业历史：

![图 5.14-用于本书的 AWX 实例的作业历史窗格](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_05_14.jpg)

图 5.14-用于本书的 AWX 实例的作业历史窗格

单击**名称**列中的编号条目将带您到我们在*图 5.11*和*图 5.12*中看到的**输出**和**详细信息**选项卡窗格，但当然，与您单击的特定作业运行相关。虽然您可以清理作业历史记录，但作业仍然保留在那里供您检查，直到您删除它们。还请注意*图 5.14*顶部的两个灰色按钮。使用这些按钮，您可以取消运行作业（如果由于任何原因它们被卡住或失败），还可以从作业历史记录中删除多个条目。一旦完成审核，这对于清理非常有用。

当然，对于 playbooks，没有一种大小适合所有的解决方案，有时我们需要操作员能够在运行 playbooks 时输入唯一的数据。AWX 提供了一个名为调查的功能，专门用于此目的，我们将在下一节中看到。

## 调查

有时，在启动作业模板时，不可能（或不希望）预先定义所有信息。虽然在 AWX 用户界面中使用变量定义参数是完全可能的，但这并不总是理想的，或者用户友好的，因为变量必须以有效的 JSON 或 YAML 语法指定。此外，只被授予模板上的“读取”角色的用户将无法编辑该模板定义-这包括变量！然而，他们可能有正当的理由设置一个变量，即使他们不应该编辑模板本身。

调查提供了答案，对于您创建的任何作业模板，您将在顶部找到一个标记为**调查**的选项卡。调查本质上是由管理员定义的问卷调查（因此得名！），以用户友好的方式要求输入，并进行简单的用户输入验证。一旦验证，输入的值将被存储在 Ansible 变量中，就像它们如果以 YAML 或 JSON 格式定义一样。

例如，如果我们想要在运行作业模板时捕获`http_port`变量值，我们可以创建一个调查问题，如*图 5.15*所示：

![图 5.15-创建一个调查问题，以捕获有效的 HTTP 端口号到一个变量](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_05_15.jpg)

图 5.15-创建一个调查问题，以捕获有效的 HTTP 端口号到一个变量

创建所有问题后，请注意，您需要为作业模板打开调查，如*图 5.16*所示，否则在运行时问题将不会出现：

![图 5.16-为作业模板打开调查](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_05_16.jpg)

图 5.16 – 为作业模板启用调查

现在，当运行 playbook 时，用户将被提示输入一个值，并且 AWX 将确保它是指定范围内的整数。还定义了一个合理的默认值。现在让我们继续看一下在 AWX 中更高级使用作业模板的方法，称为工作流。

## 工作流模板

Playbook 运行，特别是来自 AWX，可能会很复杂。例如，可能希望首先从 SCM 系统更新项目和任何动态清单。然后我们可能会运行一个作业模板来部署一些更新的代码。然而，如果失败，几乎肯定希望回滚所做的任何更改（或采取其他补救措施）。当您单击现在熟悉的**添加**按钮以添加新模板时，您将在下拉菜单中看到两个选项 – **作业模板**（我们已经使用过）和**工作流模板**。

一旦为新的工作流模板填写了所有必填字段并保存了，您将自动进入**工作流可视化器**（要在将来返回到此处，只需通过常规方式在 GUI 中访问工作流模板，然后单击**可视化器**选项卡）。工作流可视化器从左到右构建了 AWX 执行的任务流程。例如，以下屏幕截图显示了一个工作流，其中我们的演示项目最初与其 SCM 同步。

如果该步骤成功（由指向下一个块的绿色链接表示），则运行演示作业模板。如果这反过来成功，则运行 Mastery 模板。如果前面的任何步骤失败，则工作流在那里停止（尽管可以在任何阶段定义**失败时**操作）。基于这个简单的构建块前提和在成功、失败或始终发生事件后执行后续操作的能力，将使您能够在 AWX 中构建大规模的运营流程。这将在不必构建庞大的单片剧本的情况下实现。*图 5.17*显示了我们在可视化器中的简单工作流：

![图 5.17 – AWX 中的工作流可视化器](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_05_17.jpg)

图 5.17 – AWX 中的工作流可视化器

使用这个工具，我们可以强大地构建多步工作流，在每个阶段之后采取智能行动，具体取决于它是否成功。

到目前为止，我们讨论的一切都很棒，如果您直接与 AWX GUI 交互。但是，如果您设置了无人值守的操作来运行，但希望收到其结果的通知（特别是如果它们失败了），会发生什么？同样，如果有人运行了可能影响服务的更改，您如何通知团队？您将在下一节中找到这些问题的答案。

## 通知

当您检查 AWX 用户界面时，您会注意到大多数屏幕都有一个名为**通知**的选项卡。AWX 有能力与许多流行的通信平台集成，例如 Slack、IRC、Pagerduty，甚至老式的电子邮件（此列表不是详尽的）。一旦通过用户界面定义了给定平台的配置，就可以在特定事件发生时发送通知。这些事件将根据您希望从中生成通知的项目而变化。例如，对于作业模板，您可以选择在作业开始时、成功时和/或失败时收到通知（以及这些事件的任何组合）。您可以为不同的事件生成不同的通知类型。例如，您可以通知 Slack 频道模板已启动，但如果模板未能自动生成票据以促进进一步调查，则通过电子邮件通知您的票务系统。

例如，*图 5.18*显示了我们之前配置的`Mastery Template`设置为在其执行失败时向给定的收件人列表发送电子邮件。在开始和成功时，不会收到通知（当然可以打开）：

![图 5.18 – 为 Mastery 模板设置失败运行的电子邮件通知](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_05_18.jpg)

图 5.18 - 设置 Mastery Template 失败运行的电子邮件通知

AWX 中定义的所有通知都显示在**通知**选项卡中。但是，一旦定义，它们就不必添加。用户只需决定是否为每个通知服务打开或关闭**启动**、**成功**和**失败**通知。

还有一种与 AWX 交互的方式，而不使用 GUI。当然，这是通过 API，我们将在本章的最后部分进行讨论。

## 使用 API

在本书的本章中，我们已经使用 GUI 查看了所有 AWX 操作，因为这可能是解释其功能和用法的最简单和最直观的方式。然而，对于任何企业来说，AWX 的一个关键特性是 API，这是一个完整的功能，使我们能够执行所有这里完成的操作（以及更多），而无需触及 UI。

这是一个非常强大的工具，特别是在集成到更大的工作流程中。例如，您可以使用 API 将 AWX 连接到您的 CI/CD 流水线中，在代码成功构建后，您可以触发 AWX 作业来部署一个测试环境来运行它（甚至将代码部署到该环境）。同样，您可以通过 API 自动创建作业模板、清单项和配置的所有其他方面。

API 本身是可浏览的，您可以通过在 AWX 服务器的 URL 中添加`/api`或`/api/v2`来访问它（分别用于 API 的版本 1 和版本 2）。

尽管通常您会将这些集成到更大的应用程序或工作流程中，但使用`curl`很容易演示 API 的用法。例如，假设我们想要检索在我们的 AWX 服务器中定义的清单列表，我们可以使用以下命令来执行：

```
curl -k -s --user admin:adminpassword -X GET https://awx.example.org/api/v2/inventories/ | python -m json.tool
```

当然，您需要将您的凭据替换到`--user`参数中，并将您的 AWX 服务器的正确 FQDN 替换到命令中的 URL 中。完成后，此命令将以 JSON 格式检索 AWX 中定义的所有清单的详细信息 - 您不需要通过 Python 的`json.tool`工具进行管道处理 - 它只是使输出对人类更可读！

同样，我们可以通过 API 启动我们的 Mastery 示例模板。AWX 的所有配置元素都有与之关联的唯一数字 ID，我们必须使用这些 ID 来访问它们。因此，例如，让我们使用 API 从 AWX 检索作业模板的列表：

```
curl -k -s --user admin:adminpassword -X GET https://awx.example.org/api/v2/job_templates/ | python -m json.tool
```

通过 JSON 输出，我可以看到在我的系统上，我们的`Mastery Template`具有`12`的`id`。另外，因为我在本章的早期示例中为这个模板设置了一个调查，JSON 输出告诉我在启动模板之前需要指定一些变量。在`GET`查询的输出中可能需要设置一些项目，因此在组合`API POST`之前仔细审查它们是值得的。*图 5.19*显示了从`API GET`调用中获取的输出，显示了在启动模板之前必须设置的变量：

![图 5.19 - 从作业模板 12 的 API GET 调用中获取的部分输出](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_05_19.jpg)

图 5.19 - 从作业模板 12 的 API GET 调用中获取的部分输出

可以使用 API 中的`extra_vars`数据字段来指定这些变量数据，因此我们可以组合一个类似以下的 API 调用来启动作业：

```
curl -k -s --user admin:adminpassword -X POST -H 'Content-Type:application/json' https://awx.example.org/api/v2/job_templates/12/launch/ --data '{"extra_vars": "{\"http_port\": 80}"}' | python -m json.tool
```

此命令的输出将包括作业 ID 等使用详细信息，以便我们可以查询作业运行（如果需要的话）。在我的示例中，作业 ID 返回为`10`，因此我可以使用以下命令查询此作业的状态（包括是否成功）：

```
curl -k -s --user admin:adminpassword -X GET https://awx.example.org/api/v2/jobs/10/ | python -m json.tool
```

甚至可以使用类似以下的 API 调用从作业运行中检索`ansible-playbook`命令的输出：

```
curl -k -s --user admin:adminpassword -X GET https://awx.example.org/api/v2/jobs/10/stdout/
```

尽管在生产环境中不太可能使用`curl`来驱动 API，但希望这些简单、可重复的示例能帮助你开始使用 API 集成 AWX 的旅程。

甚至可以通过 Python 的`pip`包装系统安装 AWX 的 CLI。这个 CLI 使用了与我们在本节讨论过的基于 HTTP 的 API 一致的命名和命令结构，鉴于相似性，因此这被留作可选练习。然而，为了帮助你入门，AWX CLI 的官方文档可以在这里找到：

[`docs.ansible.com/ansible-tower/latest/html/towercli/index.html`](https://docs.ansible.com/ansible-tower/latest/html/towercli/index.html)

尽管文档提到了 Ansible Tower，但在使用开源 AWX 软件时同样有效。

# 总结

这就结束了我们对 AWX 的快速介绍。在本章中，我们展示了一旦你了解了涉及的核心四个步骤过程，AWX 安装和配置起来是很简单的。我们还展示了如何通过调查、通知和工作流等功能来完善这个过程。

你学到了 AWX 安装简单（实际上，它是用 Ansible 安装的！），以及如何为其添加 SSL 加密。然后你了解了平台的工作原理，以及如何从新安装到构建项目、清单、凭据和模板来运行 Ansible 作业。你了解到有许多其他功能可以构建在此基础上。这些在本章的最后部分进行了介绍，以帮助你构建一个强大的企业管理系统来管理 Ansible。

在下一章中，我们将回到 Ansible 语言，看看 Jinja2 模板系统的好处。

# 问题

1.  AWX 可以在独立的 Docker 容器或 Kubernetes 中运行。

a) True

b) False

1.  AWX 为希望管理其自动化流程的企业提供了以下哪些内容？

a) web UI

b) 一个功能完整的 API

c) 源代码控制集成

d) 以上所有

1.  AWX 直接支持安全管理自动化的凭据。

a) True

b) False

1.  AWX 为创建和测试 Ansible playbook 提供了图形化的开发环境。

a) True

b) False

1.  AWX 可以安排无人值守的作业运行。

a) True

b) False

1.  在 AWX 中，预配置的`ansible-playbook`运行的参数集被称为什么？

a) 作业配置

b) Ansible 模板

c) 作业模板

d) Ansible 运行

1.  AWX 可以通过创建以下哪些内容将其配置分为业务的不同部分？

a) 团队

b) 组织

c) 部署第二个 AWX 服务器

d) 组

1.  在 AWX 中，可以告诉以下哪些内容？

a) playbook 运行的时间

b) 谁运行了 playbook

c) 传递给 playbook 的参数是什么

d) 以上所有

1.  AWX 中的用户友好的变量定义是通过哪个功能提供的？

a) 表单

b) e-Forms

c) 额外的变量

d) 调查

1.  AWX 中的项目由什么组成？

a) 用户的逻辑团队

b) playbook 的逻辑文件夹

c) 任务管理系统

d) 角色的逻辑集合


# 第二部分：编写和故障排除 Ansible Playbooks

在本节中，您将获得如何编写健壮、多功能 playbook 的扎实理解，适用于各种用例和环境。

本节包括以下章节：

+   *第六章*, *释放 Jinja2 模板的力量*

+   *第七章*, *控制任务条件*

+   *第八章*, *使用角色组合可重用的 Ansible 内容*

+   *第九章*, *故障排除 Ansible*

+   *第十章*, *扩展 Ansible*


# 第六章：解锁 Jinja2 模板的力量

手动操作配置文件是一项繁琐且容易出错的任务。同样，执行模式匹配以对现有文件进行更改是有风险的，并且确保模式可靠和准确可能是耗时的。无论您是使用 Ansible 来定义配置文件内容、在任务中执行变量替换、评估条件语句，还是其他操作，模板化几乎在每个 Ansible playbook 中都发挥作用。事实上，鉴于这项任务的重要性，可以说模板化是 Ansible 的命脉。

Ansible 使用的模板引擎是 Jinja2，这是一种现代且设计友好的 Python 模板语言。Jinja2 值得有一本专门的书；然而，在本章中，我们将介绍 Jinja2 模板在 Ansible 中的一些常见用法模式，以展示它可以为您的 playbook 带来的强大功能。在本章中，我们将涵盖以下主题：

+   控制结构

+   数据操作

+   比较值

# 技术要求

为了跟随本章中提供的示例，您需要一台运行 Ansible 4.3 或更新版本的 Linux 机器。几乎任何 Linux 版本都可以；对于那些对具体细节感兴趣的人，本章中提供的所有代码都是在 Ubuntu Server 20.04 LTS 上测试的，除非另有说明，并且在 Ansible 4.3 上测试。本章附带的示例代码可以从 GitHub 上下载：[`github.com/PacktPublishing/Mastering-Ansible-Fourth-Edition/tree/main/Chapter06`](https://github.com/PacktPublishing/Mastering-Ansible-Fourth-Edition/tree/main/Chapter06)。

查看以下视频以查看代码示例：[`bit.ly/3lZHTM1`](https://bit.ly/3lZHTM1)

# 控制结构

在 Jinja2 中，控制结构是指模板中控制引擎解析模板流程的语句。这些结构包括条件、循环和宏。在 Jinja2 中（假设使用默认值），控制结构将出现在`{% ... %}`块内。这些开放和关闭块会提醒 Jinja2 解析器，提供了一个控制语句，而不是一个普通的字符串或变量名。

## 条件语句

模板中的条件语句创建了一个决策路径。引擎将考虑条件，并从两个或更多潜在的代码块中进行选择。至少有两个：如果条件满足（评估为`true`）的路径，以及如果条件不满足（评估为`false`）的显式定义的`else`路径，或者另外一个隐含的`else`路径，其中包含一个空块。

条件语句是`if`语句。这个语句的工作方式与 Python 中的工作方式相同。`if`语句可以与一个或多个可选的`elif`语句和一个可选的最终`else`结合使用，并且，与 Python 不同，它需要一个显式的`endif`。下面的示例显示了一个配置文件模板片段，结合了常规变量替换和`if else`结构：

```
setting = {{ setting }} 
{% if feature.enabled %} 
feature = True 
{% else %} 
feature = False 
{% endif %} 
another_setting = {{ another_setting }} 
```

在这个示例中，我们检查`feature.enabled`变量是否存在，并且它没有被设置为`False`。如果是`True`，那么就使用`feature = True`文本；否则，使用`feature = False`文本。在这个控制块之外，解析器对大括号内的变量执行正常的变量替换。可以使用`elif`语句定义多个路径，这会给解析器提供另一个测试，如果前面的测试结果为`False`。

为了演示模板和变量替换的渲染，我们将把示例模板保存为`demo.j2`。然后，我们将创建一个名为`template-demo.yaml`的 playbook，定义要使用的变量，然后使用`template`查找作为`ansible.builtin.pause`任务的一部分来在屏幕上显示渲染后的模板：

```
--- 
- name: demo the template 
  hosts: localhost 
  gather_facts: false  
  vars: 
    setting: a_val 
    feature: 
      enabled: true 
    another_setting: b_val  
  tasks: 
    - name: pause with render 
      ansible.builtin.pause: 
        prompt: "{{ lookup('template', 'demo.j2') }}" 
```

执行此 playbook 将在屏幕上显示渲染的模板，并等待输入。您可以使用以下命令来执行它：

```
ansible-playbook -i mastery-hosts template-demo.yaml
```

只需按*Enter*运行 playbook，如*图 6.1*所示：

![图 6.1-使用 Ansible 渲染带条件的简单模板](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_06_01.jpg)

图 6.1-使用 Ansible 渲染简单的带条件模板

记住我们在*第一章*中讨论过的 Ansible 变量优先顺序，我们可以将`feature.enabled`的值覆盖为`False`。当运行 playbook 时，我们可以使用`--extra-vars`（或`-e`）参数来实现这一点；这是因为额外变量比 playbook 定义的变量具有更高的优先级。您可以通过再次运行 playbook 来实现这一点，但这次使用以下命令：

```
ansible-playbook -i mastery-hosts template-demo.yaml -e '{feature: {"enabled": false}}'
```

在这种情况下，输出应该略有不同，如*图 6.2*所示：

![图 6.2-使用 Ansible 渲染带条件的简单模板，同时覆盖变量值](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_06_02.jpg)

图 6.2-使用 Ansible 渲染带条件的简单模板，同时覆盖变量值

从这些简单的测试中可以看出，Jinja2 提供了一种非常简单但强大的方式来通过模板中的条件来定义数据。

### 内联条件

请注意，`if`语句可以在内联表达式中使用。在某些不希望有额外换行的情况下，这可能很有用。让我们构建一个场景，我们需要将 API 定义为`cinder`或`cinderv2`，如下所示：

```
API = cinder{{ 'v2' if api.v2 else '' }} 
```

这个例子假设`api.v2`被定义为布尔值`True`或`False`。内联`if`表达式遵循`<条件为真时做某事> if <条件为真> else <否则做某事>`的语法。在内联`if`表达式中，有一个隐含的`else`；然而，这个隐含的`else`意味着要被评估为未定义对象，这通常会创建一个错误。我们可以通过定义一个显式的`else`来保护它，它会渲染一个零长度的字符串。

让我们修改我们的 playbook 来演示内联条件。这次，我们将使用`debug`模块来渲染简单的模板，如下所示：

```
--- 
- name: demo the template 
  hosts: localhost 
  gather_facts: false 
  vars: 
    api: 
      v2: true  
  tasks: 
    - name: pause with render 
      ansible.builtin.debug: 
        msg: "API = cinder{{ 'v2' if api.v2 else '' }}" 
```

请注意，这次我们没有定义外部模板文件；模板实际上是与 Ansible 任务一起的。使用以下命令执行 playbook：

```
ansible-playbook -i mastery-hosts template-demo-v2.yaml
```

输出应该与*图 6.3*中显示的类似：

![图 6.3-使用内联模板运行 playbook](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_06_03.jpg)

图 6.3-使用内联模板运行 playbook

现在，就像我们在之前的例子中所做的那样，我们将使用 Ansible 的额外变量将`api.v2`的值更改为`false`，以查看这对内联模板渲染的影响。再次使用以下命令执行 playbook：

```
ansible-playbook -i mastery-hosts template-demo-v2.yaml -e '{api: {"v2": false}}'
```

这次，输出应该与*图 6.4*中显示的类似。注意渲染的字符串如何改变：

![图 6.4-使用内联模板运行 playbook，同时使用额外变量改变行为](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_06_04.jpg)

图 6.4-使用内联模板运行 playbook，同时使用额外变量改变行为

通过这种方式，我们可以创建非常简洁和强大的代码，根据 Ansible 变量定义值，就像我们在这里演示的那样。

## 循环

循环允许您在模板文件中构建动态创建的部分。当您知道需要以相同方式操作未知数量的项目时，这是很有用的。要启动循环控制结构，我们使用`for`语句。让我们演示一种简单的方法，循环遍历一个虚构服务可能找到数据的目录列表：

```
# data dirs 
{% for dir in data_dirs -%} 
data_dir = {{ dir }} 
{% endfor -%} 
```

提示

默认情况下，当模板被渲染时，`{% %}`块会打印一个空行。这可能在我们的输出中是不可取的，但幸运的是，我们可以通过在块的结尾使用`-%}`来修剪它。更多详情请参考官方的 Jinja2 文档[`jinja.palletsprojects.com/en/3.0.x/templates/#whitespace-control`](https://jinja.palletsprojects.com/en/3.0.x/templates/#whitespace-control)。

在这个例子中，我们将得到一个`data_dir =`行，每个`data_dirs`变量中的项目，假设`data_dirs`是一个至少有一个项目的列表。如果变量不是列表（或其他可迭代类型），或者未定义，将生成一个错误。如果变量是一个可迭代类型但是空的，那么将不会生成任何行。Jinja2 可以处理这种情况，并且还允许通过`else`语句在变量中找不到项目时替换一行。在下面的例子中，让我们假设`data_dirs`是一个空列表：

```
# data dirs 
{% for dir in data_dirs -%} 
data_dir = {{ dir }} 
{% else -%} 
# no data dirs found 
{% endfor -%} 
```

我们可以通过修改我们的 playbook 和模板文件来测试这一点。我们将创建一个名为`demo-for.j2`的模板文件，其中包含前面列出的模板内容。此外，我们将在我们第一个条件渲染模板并暂停用户输入的示例中创建一个 playbook 文件。应该命名为`template-demo-for.yaml`，并包含以下代码：

```
- name: demo the template
  hosts: localhost
  gather_facts: false
  vars:
    data_dirs: []
  tasks:
    - name: pause with render
      ansible.builtin.pause:
        prompt: "{{ lookup('template', 'demo-for.j2') }}"
```

创建这两个文件后，您可以使用以下命令运行 playbook：

```
ansible-playbook -i mastery-hosts template-demo-for.yaml
```

运行我们的 playbook 将渲染模板，并产生一个类似于*图 6.5*所示的输出：

![图 6.5 - 在 Ansible 中使用 for 循环渲染模板](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_06_05.jpg)

图 6.5 - 在 Ansible 中使用 for 循环渲染模板

正如你所看到的，在`for`循环中的`else`语句优雅地处理了空的`data_dirs`列表，这正是我们在 playbook 运行中想要的。

### 过滤循环项目

循环也可以与条件结合使用。在循环结构内部，可以使用`if`语句来检查当前循环项目作为条件的一部分。让我们扩展我们的例子，防止模板的用户意外使用`/`作为`data_dir`（对文件系统的根目录执行的任何操作都可能很危险，特别是如果它们是递归执行的）：

```
# data dirs 
{% for dir in data_dirs -%} 
{% if dir != "/" -%} 
data_dir = {{ dir }} 
{% endif -%} 
{% else -%} 
# no data dirs found 
{% endfor -%}
```

前面的例子成功地过滤掉了任何`data_dirs`中是`/`的项目，但这需要的输入比必要的要多得多。Jinja2 提供了一种方便的方法，允许你在`for`语句中轻松地过滤循环项目。让我们使用这种便利来重复前面的例子：

```
# data dirs 
{% for dir in data_dirs if dir != "/" -%} 
data_dir = {{ dir }} 
{% else -%} 
# no data dirs found 
{% endfor -%} 
```

因此，这种结构不仅需要输入更少，而且还正确计算了循环次数，我们将在下一节中学习。

### 循环索引

循环计数是免费提供的，可以得到当前循环迭代的索引。作为变量，它们可以以几种不同的方式访问。以下表格概述了它们可以被引用的方式：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/Table_01.jpg)

有关循环内部位置的信息可以帮助确定要渲染的内容。考虑到我们之前的例子，我们可以提供一个单行，其中包含逗号分隔的值，而不是渲染多行`data_dir`来表示每个数据目录。如果没有访问循环迭代数据，这将是困难的。然而，通过使用这些数据，可以变得简单。为了简单起见，本例假设允许在最后一项后面加上逗号，并且允许在项目之间有任何空格（换行符）：

```
# data dirs
{% for dir in data_dirs if dir != "/" -%}
{% if loop.first -%}
data_dir = {{ dir }},
           {% else -%}
           {{ dir }},
{% endif -%}
{% else -%}
# no data dirs found
{% endfor -%} 
```

前面的例子使用了`loop.first`变量来确定是否需要渲染`data_dir =`部分，或者是否只需要渲染适当间距的目录。通过在`for`语句中使用过滤器，我们可以得到`loop.first`的正确值，即使`data_dirs`中的第一项是不需要的`/`。

重要提示

看一下第一个`else`语句的缩进 - 为什么我们要这样做？答案与 Jinja2 中的空格控制有关。简单地说，如果您不缩进控制语句（例如`if`或`else`语句），那么您希望渲染的模板内容将会将左侧的所有空格修剪掉；因此，我们随后的目录条目将不会有任何缩进。在某些文件中（包括 YAML 和 Python），缩进非常重要，因此这是一个小但非常重要的细微差别。

为了测试这一点，我们将创建一个名为`demo-for.j2`的新模板文件，其中包含前面列出的内容。此外，我们将修改`template-demo-for.yaml`以定义一些`data_dirs`，包括一个`/`，应该被过滤掉：

```
--- 
- name: demo the template 
  hosts: localhost 
  gather_facts: false  
  vars: 
    data_dirs: ['/', '/foo', '/bar']  
  tasks: 
    - name: pause with render 
      ansible.builtin.pause: 
        prompt: "{{ lookup('template', 'demo-for.j2') }}"
```

现在，我们可以使用以下命令执行 playbook：

```
ansible-playbook -i mastery-hosts template-demo-for.yaml
```

当它运行时，我们应该看到我们渲染的内容，如*图 6.6*所示：

![图 6.6 - 在 Ansible 中使用 for 循环渲染模板，同时利用循环索引](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_06_06.jpg)

图 6.6 - 在 Ansible 中使用 for 循环渲染模板，同时利用循环索引

在前面的例子中，如果不允许有尾随逗号，我们可以利用内联`if`语句来确定我们是否已经完成循环并正确地渲染逗号。您可以在前面模板代码的以下增强版本中查看这一点：

```
# data dirs. 
{% for dir in data_dirs if dir != "/" -%} 
{% if loop.first -%} 
data_dir = {{ dir }}{{ ',' if not loop.last else '' }} 
           {% else -%} 
           {{ dir }}{{ ',' if not loop.last else '' }} 
{% endif -%} 
{% else -%} 
# no data dirs found 
{% endfor -%}
```

使用内联`if`语句允许我们构建一个模板，只有在循环中有更多项目通过我们的初始过滤时才会渲染逗号。再次，我们将使用前面的内容更新`demo-for.j2`并使用以下命令执行 playbook：

```
ansible-playbook -i mastery-hosts template-demo-for.yaml
```

渲染模板的输出应该与*图 6.7*中显示的类似：

![图 6.7 - 在 Ansible 中使用 for 循环渲染模板，扩展使用循环索引](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_06_07.jpg)

图 6.7 - 在 Ansible 中使用 for 循环渲染模板，扩展使用循环索引

输出基本上与以前一样。但是，这一次，我们的模板使用内联`if`语句评估是否在循环中的每个`dir`值后放置逗号，从而删除最终值末尾的多余逗号。

## 宏

敏锐的读者会注意到，在前面的例子中，我们有一些重复的代码。重复的代码是任何开发人员的敌人，幸运的是，Jinja2 有一种方法可以帮助！宏就像常规编程语言中的函数：它是定义可重用习语的一种方式。宏在`{% macro ... %} ... {% endmacro %}`块内定义。它有一个名称，可以接受零个或多个参数。宏内的代码不会继承调用宏的块的命名空间，因此所有参数必须显式传递。宏通过名称在花括号块内调用，并通过括号传递零个或多个参数。让我们创建一个名为`comma`的简单宏，以取代我们重复的代码：

```
{% macro comma(loop) -%} 
{{ ',' if not loop.last else '' }} 
{%- endmacro -%} 
# data dirs. 
{% for dir in data_dirs if dir != "/" -%} 
{% if loop.first -%} 
data_dir = {{ dir }}{{ comma(loop) }} 
           {% else -%} 
           {{ dir }}{{ comma(loop) }} 
{% endif -%} 
{% else -%} 
# no data dirs found 
{% endfor -%} 
```

调用`comma`并将循环对象传递给宏，允许宏检查循环并决定是否应省略逗号。

### 宏变量

宏在调用宏时可以访问传递的任何位置或关键字参数。位置参数是根据它们提供的顺序分配给变量的参数，而关键字参数是无序的，并明确地将数据分配给变量名。如果在调用宏时未定义关键字参数，关键字参数也可以具有默认值。还有三个额外的特殊变量可用：

+   `varargs`：这是一个额外的位置参数的占位符，这些参数将传递给宏。这些位置参数值将组成`varargs`列表。

+   `kwargs`：这与`varargs`相同；但是，它不是保存额外的位置参数值，而是保存额外关键字参数和它们的关联值的哈希。

+   `caller`：这可以用来回调到可能调用此宏的更高级宏（是的，宏可以调用其他宏）。

除了这三个特殊变量之外，还有许多变量可以公开有关宏本身的内部细节。这些有点复杂，但我们将逐一介绍它们的用法。首先，让我们简要介绍一下每个变量：

+   `name`：这是宏本身的名称。

+   `arguments`：这是宏接受的参数的名称元组。

+   `defaults`：这是默认值的元组。

+   `catch_kwargs`：这是一个布尔值，如果宏访问（因此接受）`kwargs`变量，则将其定义为`true`。

+   `catch_varargs`：这是一个布尔值，如果宏访问（因此接受）`varargs`变量，则将其定义为`true`。

+   `caller`：这是一个布尔值，如果宏访问（因此可以从另一个宏调用）`caller`变量，则将其定义为`true`。

与 Python 中的类类似，这些变量需要通过宏本身的名称引用。尝试在不加上名称的情况下访问这些宏将导致未定义的变量。现在，让我们逐一演示它们的用法。

#### 名称

`name`变量实际上非常简单。它只是提供了一种访问宏名称作为变量的方式，也许用于进一步操作或使用。以下模板包括一个引用宏名称的宏，以在输出中呈现它：

```
{% macro test() -%} 
{{ test.name }} 
{%- endmacro -%} 
{{ test() }} 
```

假设我们要创建`demo-macro.j2`，其中包含此模板和以下`template-demo-macro.yaml` playbook：

```
---
- name: demo the template
  hosts: localhost
  gather_facts: false
  vars:
    data_dirs: ['/', '/foo', '/bar']
  tasks:
    - name: pause with render
      ansible.builtin.pause:
        prompt: "{{ lookup('template', 'demo-macro.j2') }}"
```

我们将使用以下命令运行此 playbook：

```
ansible-playbook -i mastery-hosts template-demo-macro.yaml
```

当您运行 playbook 时，您的输出应该类似于*图 6.8*中显示的输出：

![图 6.8 - 使用名称宏变量呈现模板](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_06_08.jpg)

图 6.8 - 使用名称宏变量呈现模板

从这次测试运行中可以看出，我们的模板只是以宏名称呈现，没有其他内容，正如预期的那样。

#### 参数

`arguments`变量是宏接受的参数的元组。请注意，这些是明确定义的参数，而不是特殊的`kwargs`或`varargs`。我们之前的例子将呈现一个空元组`()`，所以让我们修改它以得到其他内容：

```
{% macro test(var_a='a string') -%} 
{{ test.arguments }} 
{%- endmacro -%} 
{{ test() }} 
```

像以前一样运行相同的 playbook，以相同的方式呈现此模板，应该产生*图 6.9*中显示的输出：

![图 6.9 - 运行一个 playbook 来呈现打印其宏参数的 Jinja2 模板](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_06_09.jpg)

图 6.9 - 运行一个 playbook 来呈现打印其宏参数的 Jinja2 模板

在这个例子中，我们可以清楚地看到我们的模板是使用宏接受的参数的名称（而不是它们的值）呈现的。

#### 默认值

`defaults`变量是宏显式接受的任何关键字参数的默认值的元组。尽管在 Jinja2 的文档中仍然存在（在撰写本文时，有一个问题正在解决文档错误），但此变量已从所有新于版本 2.8.1 的 Jinja2 版本中删除。如果您需要访问此变量，您需要将您的 Jinja2 Python 模块降级到 2.8.1。

对于使用较旧版本的 Jinja2 的人，我们可以如下演示此变量；让我们将我们的宏更改为显示默认值以及参数：

```
{% macro test(var_a='a string') -%} 
{{ test.arguments }} 
{{ test.defaults }} 
{%- endmacro -%} 
{{ test() }}
```

我们可以像以前一样运行我们现有的测试 playbook，但现在使用新更新的模板。如果您的 Jinja2 版本支持`defaults`变量，输出应该类似于*图 6.10*中显示的输出：

![图 6.10 - 使用默认值和名称宏变量呈现 Jinja2 模板](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_06_10.jpg)

图 6.10 - 使用默认值和名称宏变量呈现 Jinja2 模板

在这里，我们可以看到模板是使用宏接受的参数的名称和默认值进行渲染的。

#### catch_kwargs

只有当宏本身访问`kwargs`变量以捕获可能传递的任何额外关键字参数时，此变量才被定义。如果定义了，它将被设置为`true`。如果没有访问`kwargs`变量，在调用宏时传递的任何额外关键字参数都将在渲染模板时导致错误。同样，访问`catch_kwargs`而不访问`kwargs`将导致未定义错误。让我们再次修改我们的示例模板，以便我们可以传递额外的`kwargs`变量：

```
{% macro test() -%} 
{{ kwargs }} 
{{ test.catch_kwargs }} 
{%- endmacro -%} 
{{ test(unexpected='surprise') }}
```

我们可以再次使用与之前相同的命令将更新后的模板通过现有的渲染模板运行。这次，输出应该类似于*图 6.11*中显示的结果：

![图 6.11 - 渲染使用 catch_kwargs 变量的模板](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_06_11.jpg)

图 6.11 - 渲染使用 catch_kwargs 变量的模板

从这个输出中可以看出，当向模板传递意外变量时，模板不会产生错误，而是使我们能够访问传递的意外值。

#### catch_varargs

与`catch_kwargs`类似，只有当宏访问`varargs`变量时，此变量才存在（并且设置为`true`）。再次修改我们的示例，我们可以看到它的作用：

```
{% macro test() -%} 
{{ varargs }} 
{{ test.catch_varargs }} 
{%- endmacro -%} 
{{ test('surprise') }}
```

模板的渲染结果应该类似于*图 6.12*中显示的结果：

![图 6.12 - 渲染使用 varargs 和 catch_varargs 宏变量的模板](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_06_12.jpg)

图 6.12 - 渲染使用 varargs 和 catch_varargs 宏变量的模板

同样，我们可以看到我们能够捕获并渲染传递给宏的意外值，而不是在渲染时返回错误，如果我们没有使用`catch_varargs`，那么将会发生错误。

#### caller

`caller`变量需要更多的解释。宏可以调用另一个宏。如果模板的同一部分将被多次使用，但内部数据的一部分更改比作为宏参数轻松传递的更多，这将非常有用。`caller`变量并不是一个确切的变量；它更像是一个引用，用于获取调用该调用宏的内容。

让我们更新我们的模板来演示它的用法：

```
{% macro test() -%}
The text from the caller follows: {{ caller() }}
{%- endmacro -%}
{% call test() -%}
This is text inside the call 
{% endcall -%} 
```

渲染的结果应该类似于*图 6.13*中显示的结果：

![图 6.13 - 渲染使用 caller 变量的模板](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_06_13.jpg)

图 6.13 - 渲染使用 caller 变量的模板

调用宏仍然可以向该宏传递参数；可以传递任意组合的参数或关键字参数。如果宏使用`varargs`或`kwargs`，那么也可以传递更多的参数。此外，宏还可以将参数传递回给调用者！为了演示这一点，让我们创建一个更大的示例。这次，我们的示例将生成一个适用于 Ansible 清单的文件：

```
{% macro test(group, hosts) -%} 
[{{ group }}] 
{% for host in hosts -%} 
{{ host }} {{ caller(host) }} 
{%- endfor -%} 
{%- endmacro -%}  
{% call(host) test('web', ['host1', 'host2', 'host3']) -%} 
ssh_host_name={{ host }}.example.name ansible_sudo=true 
{% endcall -%}  
{% call(host) test('db', ['db1', 'db2']) -%} 
ssh_host_name={{ host }}.example.name 
{% endcall -%}
```

使用我们的测试 playbook 进行渲染后，结果应该如*图 6.14*中所示：

![图 6.14 - 使用 caller 变量渲染的模板的更高级示例](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_06_14.jpg)

图 6.14 - 使用 caller 变量渲染的模板的更高级示例

我们两次调用了`test`宏，每次为我们想要定义的每个组调用一次。每个组都有略有不同的`host`变量集合要应用，并且这些变量是在调用本身中定义的。通过让宏回调到调用者，传递当前循环中的`host`变量，我们节省了输入。

控制块在模板内提供了编程能力，允许模板作者使其模板更高效。效率不一定体现在模板的初始草稿中；相反，当需要对重复值进行小改动时，效率才真正发挥作用。现在我们已经详细地看了 Jinja2 中构建控制结构，接下来，我们将继续看看这种强大的模板语言如何帮助我们处理另一个常见的自动化需求：数据操作。

# 数据操作

虽然控制结构影响模板处理的流程，但还有另一种工具可以帮助您修改变量的内容。这个工具叫做过滤器。过滤器与小函数或方法相同，可以在变量上运行。一些过滤器不带参数，一些带可选参数，一些需要参数。过滤器也可以链接在一起，一个过滤器操作的结果被馈送到下一个过滤器，然后是下一个。Jinja2 带有许多内置过滤器，而 Ansible 通过许多自定义过滤器扩展了这些过滤器，当您在模板、任务或任何其他 Ansible 允许模板化的地方使用 Jinja2 时，这些过滤器都可以使用。

## 语法

通过管道符号|将过滤器应用于变量，然后是过滤器的名称，以及括号内的过滤器参数。变量名称和管道符号之间可以有空格，管道符号和过滤器名称之间也可以有空格。例如，如果我们想将 lower filter（使所有字符变为小写）应用于 my_word 变量，我们将使用以下语法：

```
{{ my_word | lower }} 
```

因为 lower filter 不需要任何参数，所以不需要给它附加一个空的括号集。然而，如果我们使用一个需要参数的不同 filter，情况就会改变。让我们使用 replace filter，它允许我们用另一个子字符串替换所有出现的子字符串。在这个例子中，我们想要在 answers 变量中用 yes 替换所有出现的 no 子字符串：

```
{{ answers | replace('no', 'yes') }} 
```

通过简单地添加更多的管道符号和更多的过滤器名称来实现应用多个过滤器。让我们结合 replace 和 lower 来演示语法-过滤器按照列出的顺序应用。在下面的例子中，首先，我们将所有的 no 子字符串替换为 yes，然后将整个结果字符串转换为小写：

```
{{ answers | replace('no', 'yes') | lower }} 
```

由于我们正在进行区分大小写的字符串替换，您可能选择先执行小写转换，这意味着您不会错过任何情况下的 no 单词-无论大小写如何-假设这是您想要的行为！后一个例子的代码将简单地如下所示：

```
 {{ answers | lower | replace('no', 'yes') }} 
```

我们可以通过一个简单的 play 来演示这一点，该 play 使用 debug 命令来渲染这一行：

```
- name: demo the template
  hosts: localhost
  gather_facts: false
  vars:
    answers: "no so YES no"
  tasks:
    - name: debug the template
      ansible.builtin.debug: 
        msg: "{{ answers | replace('no', 'yes') | lower }}" 
```

现在，我们可以使用以下命令执行 playbook：

```
ansible-playbook -i mastery-hosts template-demo-filters.yaml
```

在我们的 answers 变量中，代码中声明的所有单词 no 的实例都将被替换为单词 yes。此外，所有字符都将转换为小写。输出应该类似于*图 6.15*中显示的输出：

![图 6.15-演示在一个简单的 Ansible playbook 中使用链式过滤器](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_06_15.jpg)

图 6.15-演示在一个简单的 Ansible playbook 中使用链式过滤器

在这里，我们可以看到 playbook 按预期运行，并结合了两个过滤器来操作我们的测试字符串，就像我们要求的那样。当然，这只是可用的过滤器中的两个。在下一节中，让我们继续看一些 Jinja2 中包含的更有用的过滤器。

## 有用的内置过滤器

Jinja2 内置的过滤器的完整列表可以在 Jinja2 文档中找到。在撰写本书时，有 50 个内置过滤器。接下来，我们将看一些更常用的过滤器。

提示

如果您想查看所有可用过滤器的列表，可以在当前版本的 Jinja2 文档中找到（在撰写时可用）：[`jinja.palletsprojects.com/en/3.0.x/templates/#builtin-filters`](https://jinja.palletsprojects.com/en/3.0.x/templates/#builtin-filters)。

### default

`default` 过滤器是为了为一个未定义的变量提供默认值的一种方式，从而防止 Ansible 生成错误。它是一个复杂的`if`语句的简写，它在尝试使用`else`子句提供不同值之前检查变量是否已定义。让我们看两个渲染相同内容的例子。一个使用`if/else`结构，另一个使用`default`过滤器：

```
{% if some_variable is defined -%} 
{{ some_variable }} 
{% else -%} 
default_value 
{% endif -%}
{{ some_variable | default('default_value') }} 
```

这些例子的渲染结果是相同的；然而，使用`default`过滤器的例子写起来更快，阅读起来更容易。

虽然`default`非常有用，但如果您在多个位置使用相同的变量，请谨慎操作。更改默认值可能会变得麻烦，定义默认值可能更有效，可以在 play 或角色级别定义变量的默认值。

### length

`length` 过滤器将返回序列或哈希的长度。在本书的早期版本中，我们引用了一个名为`count`的变量，它是`length`的别名，完成了相同的功能。这个过滤器对于执行任何关于主机集大小的数学运算或任何其他需要知道某个集合计数的情况非常有用。让我们创建一个例子，其中我们将`max_threads`配置条目设置为与 play 中主机数量相匹配的计数：

```
max_threads: {{ play_hosts | count }} 
```

这为我们提供了一个简洁的方式来获取`play_hosts`变量中包含的主机数量，并将答案赋给`max_threads`变量。

### random

`random` 过滤器用于从序列中进行随机选择。让我们使用这个过滤器将一个任务委派给`db_servers`组中的随机选择：

```
name: backup the database 
  shell: mysqldump -u root nova > /data/nova.backup.sql 
  delegate_to: "{{ groups['db_servers'] | random }}" 
  run_once: true 
```

在这里，我们可以很容易地将这个任务委派给`db_servers`组中的一个成员，使用我们的过滤器随机选择。

### round

`round` 过滤器用于将数字四舍五入。如果您需要执行浮点数运算，然后将结果转换为四舍五入的整数，这可能很有用。`round` 过滤器接受可选参数来定义精度（默认为`0`）和舍入方法。可能的舍入方法有`common`（四舍五入，是默认值）、`ceil`（总是向上舍入）和`floor`（总是向下舍入）。在这个例子中，我们将两个过滤器链接在一起，将一个数学结果舍入到零精度，然后将其转换为整数：

```
{{ math_result | round | int }} 
```

因此，如果`math_result`变量设置为`3.4`，则前一个过滤器链的输出将为`3`。

## 有用的 Ansible 提供的自定义过滤器

虽然 Jinja2 提供了许多过滤器，但 Ansible 还包括一些额外的过滤器，playbook 作者可能会发现特别有用。我们将在下面重点介绍这些过滤器。

提示

Ansible 中的这些自定义过滤器在不同版本之间经常发生变化。它们值得审查，特别是如果您经常使用它们。自定义 Ansible 过滤器的完整列表可在[`docs.ansible.com/ansible/latest/user_guide/playbooks_filters.html`](https://docs.ansible.com/ansible/latest/user_guide/playbooks_filters.html)上找到。

### 与任务状态相关的过滤器

Ansible 为每个任务跟踪任务数据。这些数据用于确定任务是否失败、是否导致更改或是否完全跳过。Playbook 作者可以注册任务的结果，在先前版本的 playbook 中，他们将使用过滤器来检查任务的状态。从 Ansible 2.9 开始，这完全被移除了。因此，如果您有来自早期 Ansible 版本的遗留 playbook，您可能需要相应地进行更新。

在 Ansible 2.7 发布之前，您可能会使用一个带有过滤器的条件语句，如下所示：

```
when: derp | success
```

现在应该使用新的语法，如下片段所示。请注意，以下代码块中的代码执行相同的功能：

```
when: derp is success
```

让我们在以下代码中查看它的运行情况：

```
--- 
- name: demo the filters 
  hosts: localhost 
  gather_facts: false  
  tasks: 
    - name: fail a task 
      ansible.builtin.debug: 
        msg: "I am not a change" 
      register: derp  
    - name: only do this on change 
      ansible.builtin.debug: 
        msg: "You had a change" 
      when: derp is changed  
    - name: only do this on success 
      ansible.builtin.debug: 
        msg: "You had a success" 
      when: derp is success
```

您可以使用以下命令运行此 playbook：

```
ansible-playbook -i mastery-hosts template-demo-filters.yaml
```

输出显示在*图 6.16*中：

![图 6.16 – 根据任务状态运行 Ansible playbook 的条件](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_06_16.jpg)

图 6.16 – 根据任务状态运行 Ansible playbook 的条件

如您所见，`ansible.builtin.debug`语句导致`success`。因此，我们跳过了要在`change`上运行的任务，并执行了要在`success`上运行的任务。

### shuffle

与`random`过滤器类似，`shuffle`过滤器可用于生成随机结果。与从列表中选择一个随机选择的`random`过滤器不同，`shuffle`过滤器将对序列中的项目进行洗牌并返回完整的序列：

```
--- 
- name: demo the filters 
  hosts: localhost 
  gather_facts: false  
  tasks: 
    - name: shuffle the cards 
      ansible.builtin.debug: 
        msg: "{{ ['Ace', 'Queen', 'King', 'Deuce'] | shuffle }}" 
```

使用以下命令运行此 playbook：

```
ansible-playbook -i mastery-hosts template-demo-filters.yaml
```

输出显示在*图 6.17*中：

![图 6.17 – 运行使用 shuffle 过滤器的 playbook](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_06_17.jpg)

图 6.17 – 运行使用 shuffle 过滤器的 playbook

如预期的那样，整个列表返回但顺序被打乱了。如果重复运行 playbook，您将看到每次运行时返回列表的不同顺序。自己试试吧！

### 处理路径名的过滤器

配置管理和编排经常涉及路径名，但通常只需要路径的一部分。例如，我们可能需要文件的完整路径，但不需要文件名本身。或者，我们只需要从完整路径中提取文件名，忽略其前面的目录。Ansible 提供了一些过滤器来帮助处理这些任务，我们将在以下部分进行讨论。

#### basename

假设我们有一个要求，只需使用完整路径中的文件名。当然，我们可以执行一些复杂的模式匹配来做到这一点。但是，通常情况下，这会导致代码难以阅读并且难以维护。幸运的是，Ansible 提供了一个专门用于从完整路径中提取文件名的过滤器，我们将在下面进行演示。在这个例子中，我们将使用`basename`过滤器从完整路径中提取文件名：

```
---
- name: demo the filters
  hosts: localhost
  gather_facts: false
  tasks:
    - name: demo basename
      ansible.builtin.debug:
        msg: "{{ '/var/log/nova/nova-api.log' | basename }}"
```

使用以下命令运行此 playbook：

```
ansible-playbook -i mastery-hosts template-demo-filters.yaml
```

输出显示在*图 6.18*中：

![图 6.18 – 运行使用 basename 过滤器的 playbook](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_06_18.jpg)

图 6.18 – 运行使用 basename 过滤器的 playbook

在这里，您可以看到只返回了所需的完整路径的文件名。

#### dirname

`basename`的反义词是`dirname`。`dirname`不返回路径的最后部分，而是返回其他所有部分（除了文件名，文件名是完整路径的最后部分）。让我们更改之前的 play 以使用`dirname`，然后使用相同的命令重新运行它。输出现在应该与*图 6.19*中显示的类似：

![图 6.19 – 使用 dirname 过滤器运行 playbook](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_06_19.jpg)

图 6.19 – 使用 dirname 过滤器运行 playbook

现在，我们只有变量的路径，这在 playbook 的其他地方可能非常有用。

#### expanduser

通常，各种东西的路径都使用用户快捷方式提供，例如`~/.stackrc`。但是，某些任务可能需要文件的完整路径。`expanduser`过滤器提供了一种将路径扩展到完整定义的方法，而不是复杂的命令和注册调用。在此示例中，用户名是`jfreeman`：

```
---
- name: demo the filters
  hosts: localhost
  gather_facts: false
  tasks:
    - name: demo filter
      ansible.builtin.debug:
        msg: "{{ '~/.stackrc' | expanduser }}"
```

您可以使用与之前相同的命令运行此 playbook，输出应该与*图 6.20*中显示的类似：

![图 6.20 – 使用 expanduser 过滤器运行 playbook](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_06_20.jpg)

图 6.20 – 使用 expanduser 过滤器运行 playbook

在这里，我们成功地扩展了路径，这对于创建配置文件或执行其他可能需要绝对路径名而不是相对路径名的文件操作可能是有用的。

### Base64 编码

从远程主机读取内容时，例如使用`ansible.builtin.slurp`模块（用于将远程主机的文件内容读入变量中），内容将被 Base64 编码。为了解码这样的内容，Ansible 提供了一个`b64decode`过滤器。同样，如果运行一个需要 Base64 编码输入的任务，常规字符串可以使用`b64encode`过滤器进行编码。

让我们使用 Ansible 创建一个名为`/tmp/derp`的测试文件，其中将包含一个测试字符串。然后，我们将使用`ansible.builtin.slurp`模块获取文件内容，并使用上述过滤器对其进行解码：

```
--- 
- name: demo the filters 
  hosts: localhost 
  gather_facts: false  
  tasks: 
    - name: create a test file
      ansible.builtin.lineinfile:
        path: /tmp/derp
        line: "Ansible is great!"
        state: present
        create: yes
    - name: read file 
      ansible.builtin.slurp: 
        src: /tmp/derp 
      register: derp  
    - name: display file content (undecoded) 
      ansible.builtin.debug: 
        var: derp.content  
    - name: display file content (decoded) 
      ansible.builtin.debug: 
        var: derp.content | b64decode
```

如果您正在使用本书附带的示例代码，可以使用以下命令运行 playbook：

```
ansible-playbook -i mastery-hosts template-demo-filters.yaml
```

输出显示在*图 6.21*中：

![图 6.21 - 运行包含 b64decode 过滤器的 playbook](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_06_21.jpg)

图 6.21 - 运行包含 b64decode 过滤器的 playbook

在这里，我们成功地将创建的小文件读入一个变量中。此外，我们可以看到变量内容以 Base64 编码形式（请记住，这个编码是由`ansible.builtin.slurp`模块执行的）进行编码。然后，我们可以使用过滤器对其进行解码以查看原始文件内容。

### 搜索内容

在 Ansible 中，搜索字符串以查找子字符串是相对常见的。特别是，管理员常见的任务是运行命令并在输出中使用`grep`查找特定的关键数据片段，这在许多 playbook 中是一个常见的构造。虽然可以使用 shell 任务执行命令，将输出传递给`grep`，并使用`failed_when`的谨慎处理来捕获`grep`的退出代码，但更好的策略是使用命令任务`register`输出，然后在后续条件中使用 Ansible 提供的**正则表达式**（**regex**）过滤器。

让我们看两个例子：一个使用`ansible.builtin.shell`，管道和`grep`方法，另一个使用`search`测试：

```
- name: check database version 
  ansible.builtin.shell: neutron-manage current | grep juno 
  register: neutron_db_ver 
  failed_when: false  
- name: upgrade db 
  ansible.builtin.command: neutron-manage db_sync 
  when: neutron_db_ver is failed 
```

前面的例子通过强制 Ansible 始终将任务视为成功来工作，但假设如果 shell 的退出代码为非零，则`juno`字符串未在`neutron-manage`命令的输出中找到。这种构造是功能性的，但阅读起来复杂，并且可能掩盖了来自命令的真实错误。让我们再试一次，使用`search`测试。

正如我们之前提到的，关于任务状态，使用`search`在 Ansible 中搜索字符串被认为是一个测试，并且已被弃用。尽管可能读起来有点奇怪，但为了符合 Ansible 2.9 及更高版本，我们必须在这种情况下使用`is`关键字代替管道使用`search`：

```
- name: check database version 
  ansible.builtin.command: neutron-manage current 
  register: neutron_db_ver  
- name: upgrade db 
  ansible.builtin.command: neutron-manage db_sync 
  when: not neutron_db_ver.stdout is search('juno') 
```

在这里，我们请求在`neutron_db_ver.stdout`不包含`juno`字符串时运行名为`upgrade db`的任务。一旦你习惯了`when: not ... is`的概念，你会发现这个版本更容易理解，并且不会掩盖第一个任务的错误。

`search`过滤器搜索字符串，如果在输入字符串的任何位置找到子字符串，则返回`True`。但是，如果需要精确完整匹配，可以使用`match`过滤器。在`search`/`match`字符串内可以利用完整的 Python 正则表达式语法。

## 省略未定义的参数

`omit`变量需要一点解释。有时，在遍历数据哈希以构建任务参数时，可能只需要为哈希中的某些项目提供一些参数。即使 Jinja2 支持内联`if`语句来有条件地渲染一行的部分，但这在 Ansible 任务中效果不佳。传统上，playbook 作者会创建多个任务，每个任务针对传入的一组潜在参数，并使用条件语句在每个任务集之间对循环成员进行排序。最近添加的魔术变量`omit`与`default`过滤器一起使用时解决了这个问题。`omit`变量将完全删除使用该变量的参数。

为了说明这是如何工作的，让我们考虑一个场景，我们需要使用`ansible.builtin.pip`安装一组 Python 包。一些包有特定版本，而其他包没有。这些包在一个名为`pips`的哈希列表中。每个哈希都有一个`name`键，可能还有一个`ver`键。我们的第一个示例利用了两个不同的任务来完成安装：

```
- name: install pips with versions 
  ansible.builtin.pip: "name={{ item.name }} version={{ item.ver }}"
  loop: "{{ pips }}"
  when: item.ver is defined  
- name: install pips without versions 
  ansible.builtin.pip: "name={{ item.name }}" 
  loop: "{{ pips }}"
  when: item.ver is undefined 
```

这种构造方式可以工作，但是循环会被迭代两次，并且每个任务中的一些迭代将被跳过。下面的示例将两个任务合并为一个，并利用`omit`变量：

```
- name: install pips 
  ansible.builtin.pip: "name={{ item.name }} version={{ item.ver | default(omit) }}" 
  loop: "{{ pips }}" 
```

这个示例更短、更清晰，不会生成额外的跳过任务。

## Python 对象方法

Jinja2 是一个基于 Python 的模板引擎，因此 Python 对象方法在模板中是可用的。对象方法是直接由变量对象（通常是`string`、`list`、`int`或`float`）访问的方法或函数。一个好的思路是：如果你在写 Python 代码时可以写变量，然后是一个句点，然后是一个方法调用，那么你在 Jinja2 中也可以做同样的事情。在 Ansible 中，通常只使用返回修改后的内容或布尔值的方法。让我们探索一些在 Ansible 中可能有用的常见对象方法。

### 字符串方法

字符串方法可以用来返回新的字符串，返回一组以某种方式被修改的字符串，或者测试字符串的各种条件并返回一个布尔值。一些有用的方法如下：

+   `endswith`：确定字符串是否以一个子字符串结尾。

+   `startswith`：与`endswith`相同，但是从开头开始。

+   `split`：将字符串按字符（默认为空格）分割成一个子字符串列表。

+   `rsplit`：与`split`相同，但是从字符串的末尾开始向后工作。

+   `splitlines`：将字符串在换行符处分割成一个子字符串列表。

+   `upper`：返回字符串的大写副本。

+   `lower`：返回字符串的小写副本。

+   `capitalize`：返回字符串的副本，只有第一个字符是大写的。

我们可以创建一个简单的 playbook，在一个任务中利用这些方法：

```
--- 
- name: demo the filters 
  hosts: localhost 
  gather_facts: false 

  tasks: 
    - name: string methods 
      ansible.builtin.debug: 
        msg: "{{ 'foo bar baz'.upper().split() }}" 
```

如果您正在使用本书附带的示例代码，请使用以下命令运行此 playbook：

```
ansible-playbook -i mastery-hosts template-demo-objects.yaml
```

输出将类似于*图 6.22*所示的内容：

![图 6.22 - 运行使用 Python 字符串对象方法的 playbook](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_06_22.jpg)

图 6.22 - 运行使用 Python 字符串对象方法的 playbook

由于这些是对象方法，我们需要使用点符号访问它们，而不是通过`|`过滤器。

### 列表方法

大多数 Ansible 提供的与列表相关的方法都是对列表本身进行修改。然而，在处理列表时，特别是涉及循环时，有两个列表方法非常有用。这两个函数分别是`index`和`count`，它们的功能描述如下：

+   `index`：返回提供数值的第一个索引位置。

+   `count`：计算列表中的项目数。

当在循环中迭代列表时，这些函数可以非常有用，因为它允许执行位置逻辑，并在通过列表时采取适当的操作。这在其他编程语言中很常见，幸运的是，Ansible 也提供了这个功能。

### int 和 float 方法

大多数`int`和`float`方法对 Ansible 没有用。有时，我们的变量不完全符合我们想要的格式。但是，我们可以利用 Jinja2 过滤器在需要修改的各个地方执行操作，而不是定义更多的变量来轻微修改相同的内容。这使我们能够有效地定义数据，避免大量重复的变量和任务，这些变量和任务可能以后需要更改。

# 比较值

比较在 Ansible 中的许多地方都有用。任务条件是比较。 Jinja2 控制结构，如`if`/`elif`/`else`块，`for`循环和宏，通常使用比较；一些过滤器也使用比较。要掌握 Ansible 对 Jinja2 的使用，了解可用的比较是很重要的。

## 比较

与大多数语言一样，Jinja2 配备了您期望的标准比较表达式集，这些表达式将生成布尔值`true`或`false`。

Jinja2 中的表达式如下：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/Table_02.jpg)

如果您在几乎任何其他编程语言中编写了比较操作（通常以`if`语句的形式），这些操作应该都很熟悉。Jinja2 在模板中保持了这种功能，允许进行与任何良好的编程语言中条件逻辑相同的强大比较操作。

## 逻辑

有时，单独执行一个比较操作是不够的 - 也许我们希望在两个比较同时评估为`true`时执行一个操作。或者，我们可能只想在一个比较不为 true 时执行一个操作。Jinja2 中的逻辑帮助您将两个或多个比较组合在一起，从简单的比较中形成复杂条件。每个比较被称为一个操作数，将这些操作数组合成复杂条件的逻辑在以下列表中给出：

+   `and`: 如果左操作数和右操作数为 true，则返回`true`。

+   `or`: 如果左操作数或右操作数为 true，则返回`true`。

+   `not`: 这否定一个操作数。

+   `()`: 这将一组操作数包装在一起，形成一个更大的操作数。

为了进一步定义 Jinja2 中的逻辑条件，我们可以对某些变量条件进行测试，比如变量是否已定义或未定义。我们将在下一节中更详细地讨论这个问题。

## 测试

Jinja2 中的测试用于确定变量是否符合某些明确定义的标准，在本章的特定场景中我们已经遇到过这种情况。`is`运算符用于启动测试。测试用于需要布尔结果的任何地方，例如`if`表达式和任务条件。有许多内置测试，但我们将重点介绍一些特别有用的测试，如下所示：

+   `defined`: 如果变量已定义，则返回`true`。

+   `undefined`: 这是`defined`的相反。

+   `none`: 如果变量已定义但值为 none，则返回`true`。

+   `even`: 如果数字可以被`2`整除，则返回`true`。

+   `odd`: 如果数字不能被`2`整除，则返回`true`。

要测试一个值是否不是某个值，只需使用`is not`。

我们可以创建一个 playbook 来演示这些值的比较：

```
---
- name: demo the logic
  hosts: localhost
  gather_facts: false
  vars:
    num1: 10
    num3: 10
  tasks:
    - name: logic and comparison
      ansible.builtin.debug:
        msg: "Can you read me?"
      when: num1 >= num3 and num1 is even and num2 is not defined
```

如果您正在运行本书附带的代码，可以使用以下命令执行此示例 playbook：

```
ansible-playbook -i mastery-hosts template-demo-comparisons.yaml
```

输出显示在*图 6.23*中：

![图 6.23 - 执行包含复杂条件的 playbook](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-asb-4e/img/B17462_06_23.jpg)

图 6.23 - 执行包含复杂条件的 playbook

在这里，我们可以看到我们的复杂条件评估为`true`，因此执行了调试任务。

这就结束了我们对 Ansible 广泛的模板能力的探讨。我们希望本章为您提供了有效自动化基础设施的种子想法。 

# 摘要

Jinja2 是 Ansible 广泛使用的强大语言。它不仅用于生成文件内容，还用于使 playbook 的部分动态化。精通 Jinja2 对于创建和维护优雅高效的 playbook 和角色至关重要。

在本章中，我们学习了如何使用 Jinja2 构建简单模板，并从 Ansible playbook 中呈现它们。此外，我们还学习了如何有效地使用控制结构，如何操作数据，甚至如何对变量进行比较和测试，以控制 Ansible playbook 的流程（通过保持代码轻量和高效）并创建和操作数据，而无需重复定义或过多的变量。

在下一章中，我们将更深入地探讨 Ansible 的能力，以定义 play 中任务的变化或失败。

# 问题

1.  Jinja2 条件可以用于在 playbook 任务中内联渲染内容。

a）真

b）假

1.  以下哪个 Jinja2 结构将在每次评估时打印一个空行？

a）`{% if loop.first -%}`

b）`{% if loop.first %}`

c）`{%- if loop.first -%}`

d）`{%- if loop.first %}`

1.  Jinja2 宏可用于执行以下哪些操作？

a）定义需要自动化的一系列按键。

b）定义一个用于使用 Ansible 自动化电子表格的函数。

c）定义一个经常从模板中的其他位置调用的函数。

d）宏不在 Jinja2 中使用。

1.  以下哪个是将两个 Jinja2 过滤器链接在一起并对 Ansible 变量进行操作的有效表达式？

a）`{{ value.replace('A', 'B').lower }}`

b）`{{ value | replace('A', 'B') | lower }}`

c）`value.replace('A', 'B').lower`

d）`lower(replace('A', 'B',value))`

1.  Jinja2 过滤器始终具有强制参数。

a）真

b）假

1.  您将使用哪个 Ansible 自定义过滤器来从列表变量中检索随机条目？

a）`洗牌`

b）`随机`

c）`选择`

d）`rand`

1.  Ansible 可以使用哪个过滤器从完整路径中提取文件名？

a）`文件名`

b）`dirname`

c）`expanduser`

d）`basename`

1.  Ansible 提供了一个构造来跳过可选参数以防止未定义的变量错误。它叫什么？

a）`skip_var`

b）`跳过`

c）`省略`

d）`prevent_undefined`

1.  可以使用哪些运算符为 Ansible 任务构建复杂的条件？

a）`和`，`或`和`不`

b）`和`，`nand`，`或`，`nor`和`not`

c）`&&`，`||`和`！`

d）`＆`，`|`和`！`

1.  以下哪个任务执行条件将允许任务在前一个任务成功完成时运行？

a）`previoustask | success`

b）`previoustask = success`

c）`previoustask == success`

d）`previoustask 成功`
