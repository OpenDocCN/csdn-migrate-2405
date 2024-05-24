# Ansible 2 实战（一）

> 原文：[`zh.annas-archive.org/md5/B93AA180F347B680872C5A7851966C2F`](https://zh.annas-archive.org/md5/B93AA180F347B680872C5A7851966C2F)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

欢迎阅读*Practical Ansible 2*，本书将指导您从初学者变成熟练的 Ansible 自动化工程师。本书将为您提供执行第一个安装和自动化任务所需的知识和技能，并带您从执行单个任务的简单一行自动化命令，一直到编写自己的复杂自定义代码来扩展 Ansible 的功能，并自动化云和容器基础设施。本书将提供实际示例，让您不仅可以阅读有关 Ansible 自动化的内容，还可以自己尝试并理解代码的工作原理。然后，您将能够以可扩展、可重复和可靠的方式使用 Ansible 自动化您的基础设施。

# 这本书适合谁

本书适用于希望自动化 IT 任务的任何人，从日常琐事到基于复杂基础设施即代码的部署。它旨在吸引任何有 Linux 环境先前经验的人，他们希望快速掌握 Ansible 自动化，并吸引各种人群，从系统管理员到 DevOps 工程师，再到考虑整体自动化策略的架构师。它甚至可以为爱好者提供帮助。假设您具有 Linux 系统管理和维护任务的基本熟练程度；但不需要有先前的 Ansible 或自动化经验。

# 为了充分利用本书

本书的所有章节都假设您至少可以访问一台运行较新 Linux 发行版的 Linux 机器。本书中的所有示例都在 CentOS 7 和 Ubuntu Server 18.04 上进行了测试，但几乎可以在任何其他主流发行版上运行。您还需要在至少一台测试机器上安装 Ansible 2.9——安装步骤将在第一章中介绍。较新版本的 Ansible 也应该可以工作，尽管可能会有一些细微差异，您应该参考较新版本的 Ansible 的发布说明和移植指南。最后一章还将带您完成 AWX 的安装，但这需要一台安装了 Ansible 的 Linux 服务器。大多数示例演示了跨多个主机的自动化，如果您有更多的 Linux 主机可用，您将能够更好地利用这些示例；但是，它们可以根据您的需求进行扩展或缩减。拥有更多主机并非强制要求，但可以让您更好地利用本书。

| **书中涉及的软件/硬件** | **操作系统要求** |
| --- | --- |
| 至少一个 Linux 服务器（虚拟机或物理机） | CentOS 7 或 Ubuntu Server 18.04，尽管其他主流发行版（包括这些操作系统的更新版本）也应该可以工作。 |
| Ansible 2.9 | 如上所述 |
| AWX 发布 10.0.0 或更高版本 | 如上所述 |

**如果您使用的是本书的数字版本，我们建议您自己输入代码或通过 GitHub 存储库访问代码（链接在下一节中提供）。这样做将帮助您避免与复制和粘贴代码相关的潜在错误。**

# 下载示例代码文件

您可以从您的[www.packt.com](http://www.packt.com)账户下载本书的示例代码文件。如果您在其他地方购买了本书，您可以访问[www.packtpub.com/support](https://www.packtpub.com/support)注册，将文件直接发送到您的邮箱。

您可以按照以下步骤下载代码文件：

1.  登录或注册[www.packt.com](http://www.packt.com)。

1.  选择支持选项卡。

1.  点击代码下载。

1.  在搜索框中输入书名，按照屏幕上的指示操作。

下载文件后，请确保使用最新版本的解压缩软件解压缩文件夹：

+   WinRAR/7-Zip 适用于 Windows

+   Zipeg/iZip/UnRarX 适用于 Mac

+   7-Zip/PeaZip 适用于 Linux

该书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Practical-Ansible-2`](https://github.com/PacktPublishing/Practical-Ansible-2)。 如果代码有更新，将在现有的 GitHub 存储库上进行更新。

我们还提供了来自我们丰富书籍和视频目录的其他代码包，可在**[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)**上找到。 快去看看吧！

# 下载彩色图像

我们还提供了一份 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图像。 您可以在这里下载：`www.packtpub.com/sites/default/files/downloads/9781789807462_ColorImages.pdf`。

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词，数据库表名，文件夹名，文件名，文件扩展名，路径名，虚拟 URL，用户输入和 Twitter 句柄。 例如：“将下载的`WebStorm-10*.dmg`磁盘映像文件挂载为系统中的另一个磁盘。”

代码块设置如下：

```
html, body, #map {
 height: 100%; 
 margin: 0;
 padding: 0
}
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```
[default]
exten => s,1,Dial(Zap/1|30)
exten => s,2,Voicemail(u100)
exten => s,102,Voicemail(b100)
exten => i,1,Voicemail(s0)
```

任何命令行输入或输出都以以下形式编写：

```
$ mkdir css
$ cd css
```

**粗体**：表示新术语，重要单词或屏幕上看到的单词。 例如，菜单或对话框中的单词会在文本中显示为这样。 例如：“从管理面板中选择系统信息。”

警告或重要说明会以这种方式出现。提示和技巧会以这种方式出现。


# 第一部分：学习 Ansible 的基本原理

在本节中，我们将看一下 Ansible 的基本原理。我们将从安装 Ansible 的过程开始，然后我们将掌握基本原理，包括语言的基础知识和临时命令。然后我们将探索 Ansible 清单，然后看看如何编写我们的第一个 playbooks 和 roles 来完成多阶段自动化任务。

本节包括以下章节：

+   第一章，使用 Ansible 入门

+   第二章，理解 Ansible 的基本原理

+   第三章，定义您的清单

+   第四章，playbooks 和 roles


# 第一章：开始使用 Ansible

Ansible 使您能够使用诸如 SSH 和 WinRM 等本机通信协议轻松一致和可重复地部署应用程序和系统。也许最重要的是，Ansible 是无代理的，因此在受管系统上不需要安装任何东西（除了 Python，这些天大多数系统都有）。因此，它使您能够为您的环境构建一个简单而强大的自动化平台。

安装 Ansible 简单直接，并且适用于大多数现代系统。它的架构是无服务器和无代理的，因此占用空间很小。您可以选择从中央服务器或您自己的笔记本电脑上运行它——完全取决于您。您可以从一个 Ansible 控制机器管理单个主机到数十万个远程主机。所有远程机器都可以（通过编写足够的 playbooks）由 Ansible 管理，并且一切创建正确的话，您可能再也不需要单独登录这些机器了。

在本章中，我们将开始教授您实际技能，涵盖 Ansible 的基本原理，从如何在各种操作系统上安装 Ansible 开始。然后，我们将看看如何配置 Windows 主机以使其能够通过 Ansible 自动化进行管理，然后深入探讨 Ansible 如何连接到其目标主机的主题。然后我们将看看节点要求以及如何验证您的 Ansible 安装，最后看看如何获取和运行最新的 Ansible 源代码，如果您希望为其开发做出贡献或获得最新的功能。

在本章中，我们将涵盖以下主题：

+   安装和配置 Ansible

+   了解您的 Ansible 安装

+   从源代码运行与预构建的 RPM 包

# 技术要求

Ansible 有一组相当简单的系统要求——因此，您应该会发现，如果您有一台能够运行 Python 的机器（无论是笔记本电脑、服务器还是虚拟机），那么您就可以在上面运行 Ansible。在本章的后面，我们将演示在各种操作系统上安装 Ansible 的方法，因此您可以决定哪些操作系统适合您。

前述声明的唯一例外是 Microsoft Windows——尽管 Windows 有 Python 环境可用，但目前还没有 Windows 的原生构建。运行更高版本 Windows 的读者可以使用 Windows 子系统来安装 Ansible（以下简称 WSL），并按照后面为所选的 WSL 环境（例如，如果您在 WSL 上安装了 Ubuntu，则应该简单地按照本章中为 Ubuntu 安装 Ansible 的说明进行操作）的程序进行操作。

# 安装和配置 Ansible

Ansible 是用 Python 编写的，因此可以在各种系统上运行。这包括大多数流行的 Linux、FreeBSD 和 macOS 版本。唯一的例外是 Windows，尽管存在原生的 Python 发行版，但目前还没有原生的 Ansible 构建。因此，在撰写本文时，您最好的选择是在 WSL 下安装 Ansible，就像在本机 Linux 主机上运行一样。

一旦您确定了要运行 Ansible 的系统，安装过程通常是简单直接的。在接下来的章节中，我们将讨论如何在各种不同的系统上安装 Ansible，因此大多数读者应该能够在几分钟内开始使用 Ansible。

# 在 Linux 和 FreeBSD 上安装 Ansible

Ansible 的发布周期通常约为四个月，在这个短暂的发布周期内，通常会有许多变化，从较小的错误修复到较大的错误修复，到新功能，甚至有时对语言进行根本性的更改。不仅可以使用本地包来快速上手并保持最新状态，而且可以使用本地包来保持最新状态。

例如，如果你希望在诸如 CentOS、Fedora、Red Hat Enterprise Linux（RHEL）、Debian 和 Ubuntu 等 Linux 发行版上运行最新版本的 Ansible，我强烈建议你使用操作系统包管理器，如基于 Red Hat 的发行版上的`yum`或基于 Debian 的发行版上的`apt`。这样，每当你更新操作系统时，你也会同时更新 Ansible。

当然，可能是因为你需要保留特定版本的 Ansible 以用于特定目的——也许是因为你的 playbooks 已经经过了测试。在这种情况下，你几乎肯定会选择另一种安装方法，但这超出了本书的范围。此外，建议在可能的情况下，按照记录的最佳实践创建和维护你的 playbooks，这应该意味着它们能够在大多数 Ansible 升级中生存下来。

以下是一些示例，展示了如何在几种 Linux 发行版上安装 Ansible：

+   **在 Ubuntu 上安装 Ansible：**要在 Ubuntu 上安装最新版本的 Ansible 控制机，`apt`包装工具使用以下命令很容易：

```
$ sudo apt-get update 
$ sudo apt-get install software-properties-common 
$ sudo apt-add-repository --yes --update ppa:ansible/ansible 
$ sudo apt-get install ansible
```

如果你正在运行较旧版本的 Ubuntu，你可能需要用`python-software-properties`替换`software-properties-common`。

+   **在 Debian 上安装 Ansible：**你应该将以下行添加到你的`/etc/apt/sources.list`文件中：

```
deb http://ppa.launchpad.net/ansible/ansible/ubuntu trusty main
```

你会注意到在上述配置行中出现了`ubuntu`一词，以及`trusty`，这是一个 Ubuntu 版本。在撰写本文时，Debian 版本的 Ansible 是从 Ubuntu 的 Ansible 仓库中获取的，并且可以正常工作。你可能需要根据你的 Debian 版本更改上述配置中的版本字符串，但对于大多数常见用例，这里引用的行就足够了。

完成后，你可以按以下方式在 Debian 上安装 Ansible：

```
$ sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 93C4A3FD7BB9C367 
$ sudo apt-get update 
$ sudo apt-get install ansible
```

+   **在 Gentoo 上安装 Ansible：**要在 Gentoo 上安装最新版本的 Ansible 控制机，`portage`包管理器使用以下命令很容易：

```
$ echo 'app-admin/ansible' >> /etc/portage/package.accept_keywords
$ emerge -av app-admin/ansible
```

+   **在 FreeBSD 上安装 Ansible：**要在 FreeBSD 上安装最新版本的 Ansible 控制机，PKG 管理器使用以下命令很容易：

```
$ sudo pkg install py36-ansible
$ sudo make -C /usr/ports/sysutils/ansible install
```

+   **在 Fedora 上安装 Ansible：**要在 Fedora 上安装最新版本的 Ansible 控制机，`dnf`包管理器使用以下命令很容易：

```
$ sudo dnf -y install ansible
```

+   **在 CentOS 上安装 Ansible：**要在 CentOS 或 RHEL 上安装最新版本的 Ansible 控制机，`yum`包管理器使用以下命令很容易：

```
$ sudo yum install epel-release
$ sudo yum -y install ansible
```

如果你在 RHEL 上执行上述命令，你必须确保 Ansible 仓库已启用。如果没有，你需要使用以下命令启用相关仓库：

```
$ sudo subscription-manager repos --enable rhel-7-server-ansible-2.9-rpms
```

+   **在 Arch Linux 上安装 Ansible：**要在 Arch Linux 上安装最新版本的 Ansible 控制机，`pacman`包管理器使用以下命令很容易：

```
$ pacman -S ansible
```

一旦你在你使用的特定 Linux 发行版上安装了 Ansible，你就可以开始探索。让我们从一个简单的例子开始——当你运行`ansible`命令时，你会看到类似以下的输出：

```
$ ansible --version
ansible 2.9.6
 config file = /etc/ansible/ansible.cfg
 configured module search path = [u'/home/jamesf_local/.ansible/plugins/modules', u'/usr/share/ansible/plugins/modules']
 ansible python module location = /usr/lib/python2.7/dist-packages/ansible
 executable location = /usr/bin/ansible
 python version = 2.7.17 (default, Nov 7 2019, 10:07:09) [GCC 9.2.1 20191008]
```

那些希望测试来自 GitHub 最新版本的 Ansible 的人可能对构建 RPM 软件包以安装到控制机器感兴趣。当然，这种方法只适用于基于 Red Hat 的发行版，如 Fedora、CentOS 和 RHEL。为此，您需要从 GitHub 存储库克隆源代码，并按以下方式构建 RPM 软件包：

```
$ git clone https://github.com/ansible/ansible.git
$ cd ./ansible
$ make rpm
$ sudo rpm -Uvh ./rpm-build/ansible-*.noarch.rpm
```

现在您已经了解了如何在 Linux 上安装 Ansible，我们将简要介绍如何在 macOS 上安装 Ansible。

# 在 macOS 上安装 Ansible

在本节中，您将学习如何在 macOS 上安装 Ansible。最简单的安装方法是使用 Homebrew，但您也可以使用 Python 软件包管理器。让我们从安装 Homebrew 开始，这是 macOS 的快速便捷的软件包管理解决方案。

如果您在 macOS 上尚未安装 Homebrew，可以按照此处的详细说明轻松安装它：

+   安装 Homebrew：通常，这里显示的两个命令就足以在 macOS 上安装 Homebrew：

```
$ xcode-select --install
$ ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
```

如果您已经为其他目的安装了 Xcode 命令行工具，您可能会看到以下错误消息：

```
xcode-select: error: command line tools are already installed, use "Software Update" to update
```

您可能希望在 macOS 上打开 App Store 并检查是否需要更新 Xcode，但只要安装了命令行工具，您的 Homebrew 安装应该顺利进行。

如果您希望确认您的 Homebrew 安装成功，可以运行以下命令，它会警告您有关安装的任何潜在问题，例如，以下输出警告我们，尽管 Homebrew 已成功安装，但它不在我们的`PATH`中，因此我们可能无法运行任何可执行文件而不指定它们的绝对路径：

```
$ brew doctor
Please note that these warnings are just used to help the Homebrew maintainers
with debugging if you file an issue. If everything you use Homebrew for is
working fine: please don't worry or file an issue; just ignore this. Thanks!

Warning: Homebrew's sbin was not found in your PATH but you have installed
formulae that put executables in /usr/local/sbin.
Consider setting the PATH for example like so
 echo 'export PATH="/usr/local/sbin:$PATH"' >> ~/.bash_profile
```

+   安装 Python 软件包管理器（pip）：如果您不希望使用 Homebrew 安装 Ansible，您可以使用以下简单命令安装`pip`：

```
$ sudo easy_install pip
```

还要检查您的 Python 版本是否至少为 2.7，因为旧版本的 Ansible 无法运行（几乎所有现代 macOS 安装都应该是这种情况）：

```
$ python --version
Python 2.7.16
```

您可以使用 Homebrew 或 Python 软件包管理器在 macOS 上安装最新版本的 Ansible，方法如下：

+   通过 Homebrew 安装 Ansible：要通过 Homebrew 安装 Ansible，请运行以下命令：

```
$ brew install ansible
```

+   通过 Python 软件包管理器（pip）安装 Ansible：要通过`pip`安装 Ansible，请使用以下命令：

```
$ sudo pip install ansible
```

如果您有兴趣直接从 GitHub 运行最新的 Ansible 开发版本，那么您可以通过运行以下命令来实现：

```
$ pip install git+https://github.com/ansible/ansible.git@devel 
```

现在您已经使用您喜欢的方法安装了 Ansible，您可以像以前一样运行`ansible`命令，如果一切按计划进行，您将看到类似以下的输出：

```
$ ansible --version
ansible 2.9.6
  config file = None
  configured module search path = ['/Users/james/.ansible/plugins/modules', '/usr/share/ansible/plugins/modules']
  ansible python module location = /usr/local/Cellar/ansible/2.9.4_1/libexec/lib/python3.8/site-packages/ansible
  executable location = /usr/local/bin/ansible
  python version = 3.8.1 (default, Dec 27 2019, 18:05:45) [Clang 11.0.0 (clang-1100.0.33.16)]
```

如果您正在运行 macOS 10.9，使用`pip`安装 Ansible 可能会遇到问题。以下是一个解决此问题的解决方法：

```
$ sudo CFLAGS=-Qunused-arguments CPPFLAGS=-Qunused-arguments pip install ansible
```

如果您想更新您的 Ansible 版本，`pip`可以通过以下命令轻松实现：

```
$ sudo pip install ansible --upgrade
```

同样，如果您使用的是`brew`命令进行安装，也可以使用该命令进行升级：

```
$ brew upgrade ansible
```

现在您已经学会了在 macOS 上安装 Ansible 的步骤，让我们看看如何为 Ansible 配置 Windows 主机以进行自动化。

# 为 Ansible 配置 Windows 主机

正如前面讨论的，Windows 上没有直接的 Ansible 安装方法，建议在可用的情况下安装 WSL，并像在本章前面概述的过程中那样安装 Ansible，就像在 Linux 上本地运行一样。

尽管存在这种限制，但是 Ansible 并不仅限于管理 Linux 和基于 BSD 的系统，它能够使用本机 WinRM 协议对 Windows 主机进行无代理管理，使用 PowerShell 模块和原始命令，这在每个现代 Windows 安装中都可用。在本节中，您将学习如何配置 Windows 以启用 Ansible 的任务自动化。

让我们看看在自动化 Windows 主机时，Ansible 能做些什么：

+   收集远程主机的信息。

+   安装和卸载 Windows 功能。

+   管理和查询 Windows 服务。

+   管理用户账户和用户列表。

+   使用 Chocolatey（Windows 的软件存储库和配套管理工具）来管理软件包。

+   执行 Windows 更新。

+   从远程机器获取多个文件到 Windows 主机。

+   在目标主机上执行原始的 PowerShell 命令和脚本。

Ansible 允许你通过连接本地用户或域用户来自动化 Windows 机器上的任务。你可以像在 Linux 发行版上使用`sudo`命令一样，以管理员身份运行操作，使用 Windows 的`runas`支持。

另外，由于 Ansible 是开源软件，你可以通过创建自己的 PowerShell 模块或者发送原始的 PowerShell 命令来扩展其功能。例如，信息安全团队可以轻松地管理文件系统 ACL、配置 Windows 防火墙，并使用本地 Ansible 模块和必要时的原始命令来管理主机名和域成员资格。

Windows 主机必须满足以下要求，以便 Ansible 控制机器与之通信：

+   Ansible 尝试支持所有在 Microsoft 的当前或扩展支持下的 Windows 版本，包括桌面平台，如 Windows 7、8.1 和 10，以及服务器操作系统，包括 Windows Server 2008（和 R2）、2012（和 R2）、2016 和 2019。

+   你还需要在 Windows 主机上安装 PowerShell 3.0 或更高版本，以及至少.NET 4.0。

+   你需要创建和激活一个 WinRM 监听器，这将在后面详细描述。出于安全原因，这不是默认启用的。

让我们更详细地看一下如何准备 Windows 主机以便被 Ansible 自动化：

1.  关于先决条件，你必须确保 Windows 机器上安装了 PowerShell 3.0 和.NET Framework 4.0。如果你仍在使用旧版本的 PowerShell 或.NET Framework，你需要升级它们。你可以手动执行这个过程，或者以下的 PowerShell 脚本可以自动处理：

```
$url = "https://raw.githubusercontent.com/jborean93/ansible-windows/master/scripts/Upgrade-PowerShell.ps1" 
$file = "$env:temp\Upgrade-PowerShell.ps1" (New-Object -TypeName System.Net.WebClient).DownloadFile($url, $file) 

Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Force &$file -Verbose Set-ExecutionPolicy -ExecutionPolicy Restricted -Force
```

这个脚本通过检查需要安装的程序（如.NET Framework 4.5.2）和所需的 PowerShell 版本，如果需要的话重新启动，并设置用户名和密码参数。脚本将在重新启动时自动重新启动和登录，因此不需要更多的操作，脚本将一直持续，直到 PowerShell 版本与目标版本匹配。

如果用户名和密码参数没有设置，脚本将要求用户在必要时重新启动并手动登录，下次用户登录时，脚本将在中断的地方继续。这个过程会一直持续，直到主机满足 Ansible 自动化的要求。

1.  当 PowerShell 升级到至少 3.0 版本后，下一步将是配置 WinRM 服务，以便 Ansible 可以连接到它。WinRM 服务配置定义了 Ansible 如何与 Windows 主机进行交互，包括监听端口和协议。

如果以前从未设置过 WinRM 监听器，你有三种选项可以做到这一点：

+   首先，你可以使用`winrm quickconfig`来配置 HTTP，使用`winrm quickconfig -transport:https`来配置 HTTPS。这是在需要在域环境之外运行并创建一个简单监听器时使用的最简单的方法。这个过程的优势在于它会在 Windows 防火墙中打开所需的端口，并自动启动 WinRM 服务。

+   如果你在域环境中运行，我强烈建议使用**组策略对象**（**GPOs**），因为如果主机是域成员，那么配置会自动完成，无需用户输入。有许多可用的文档化程序可以做到这一点，由于这是一个非常 Windows 领域中心的任务，它超出了本书的范围。

+   最后，您可以通过运行以下 PowerShell 命令创建具有特定配置的监听器：

```
$selector_set = @{
    Address = "*"
    Transport = "HTTPS"
}
$value_set = @{
    CertificateThumbprint = "E6CDAA82EEAF2ECE8546E05DB7F3E01AA47D76CE"
}

New-WSManInstance -ResourceURI "winrm/config/Listener" -SelectorSet $selector_set -ValueSet $value_set
```

前面的`CertificateThumbprint`应该与您之前创建或导入到 Windows 证书存储中的有效 SSL 证书的指纹匹配。

如果您正在运行 PowerShell v3.0，您可能会遇到 WinRM 服务的问题，该问题限制了可用内存的数量。这是一个已知的错误，并且有一个热修复程序可用于解决它。这里提供了一个应用此热修复程序的示例过程（用 PowerShell 编写）：

```
$url = "https://raw.githubusercontent.com/jborean93/ansible-windows/master/scripts/Install-WMF3Hotfix.ps1" 
$file = "$env:temp\Install-WMF3Hotfix.ps1" 

(New-Object -TypeName System.Net.WebClient).DownloadFile($url, $file) powershell.exe -ExecutionPolicy ByPass -File $file -Verbose
```

配置 WinRM 监听器可能是一个复杂的任务，因此重要的是能够检查您的配置过程的结果。以下命令（可以从命令提示符中运行）将显示当前的 WinRM 监听器配置：

```
winrm enumerate winrm/config/Listener
```

如果一切顺利，您应该会得到类似于此的输出：

```
Listener
    Address = *
    Transport = HTTP
    Port = 5985
    Hostname
    Enabled = true
    URLPrefix = wsman
    CertificateThumbprint
    ListeningOn = 10.0.2.15, 127.0.0.1, 192.168.56.155, ::1, fe80::5efe:10.0.2.15%6, fe80::5efe:192.168.56.155%8, fe80::
ffff:ffff:fffe%2, fe80::203d:7d97:c2ed:ec78%3, fe80::e8ea:d765:2c69:7756%7

Listener
    Address = *
    Transport = HTTPS
    Port = 5986
    Hostname = SERVER2016
    Enabled = true
    URLPrefix = wsman
    CertificateThumbprint = E6CDAA82EEAF2ECE8546E05DB7F3E01AA47D76CE
    ListeningOn = 10.0.2.15, 127.0.0.1, 192.168.56.155, ::1, fe80::5efe:10.0.2.15%6, fe80::5efe:192.168.56.155%8, fe80::
ffff:ffff:fffe%2, fe80::203d:7d97:c2ed:ec78%3, fe80::e8ea:d765:2c69:7756%7
```

根据前面的输出，有两个活动的监听器——一个监听 HTTP 端口`5985`，另一个监听 HTTPS 端口`5986`，提供更高的安全性。另外，前面的输出还显示了以下参数的解释：

+   `传输`：这应该设置为 HTTPS 或 HTTPS，尽管强烈建议您使用 HTTPS 监听器，以确保您的自动化命令不会受到窥探或操纵。

+   `端口`：这是监听器操作的端口，默认情况下为`5985`（HTTP）或`5986`（HTTPS）。

+   `URL 前缀`：这是与之通信的 URL 前缀，默认情况下为`wsman`。如果更改它，您必须在 Ansible 控制主机上设置`ansible_winrm_path`主机为相同的值。

+   `CertificateThumbprint`：如果在 HTTPS 监听器上运行，这是连接使用的 Windows 证书存储的证书指纹。

如果您在设置 WinRM 监听器后需要调试任何连接问题，您可能会发现以下命令很有价值，因为它们在 Windows 主机之间执行基于 WinRM 的连接，而不使用 Ansible，因此您可以使用它们来区分您可能遇到的问题是与您的 Ansible 主机相关还是 WinRM 监听器本身存在问题：

```
# test out HTTP
winrs -r:http://<server address>:5985/wsman -u:Username -p:Password ipconfig 
# test out HTTPS (will fail if the cert is not verifiable)
winrs -r:https://<server address>:5986/wsman -u:Username -p:Password -ssl ipconfig 

# test out HTTPS, ignoring certificate verification
$username = "Username"
$password = ConvertTo-SecureString -String "Password" -AsPlainText -Force
$cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $username, $password

$session_option = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
Invoke-Command -ComputerName server -UseSSL -ScriptBlock { ipconfig } -Credential $cred -SessionOption $session_option
```

如果前面的命令中的任何一个失败，您应该在尝试设置或配置 Ansible 控制主机之前调查您的 WinRM 监听器设置。

在这个阶段，Windows 应该准备好通过 WinRM 接收来自 Ansible 的通信。要完成此过程，您还需要在 Ansible 控制主机上执行一些额外的配置。首先，您需要安装`winrm` Python 模块，这取决于您的控制主机的配置，可能已经安装或尚未安装。安装方法会因操作系统而异，但通常可以使用`pip`在大多数平台上安装如下：

```
$ pip install winrm
```

完成后，您需要为 Windows 主机定义一些额外的清单变量——现在不要太担心清单，因为我们将在本书的后面部分介绍这些。以下示例仅供参考：

```
[windows]
192.168.1.52

[windows:vars]
ansible_user=administrator
ansible_password=password
ansible_connection=winrm
ansible_winrm_server_cert_validation=ignore
```

最后，您应该能够运行 Ansible `ping`模块，执行类似以下命令的端到端连接性测试（根据您的清单进行调整）：

```
$ ansible -i inventory -m ping windows
192.168.1.52 | SUCCESS => {
 "changed": false,
 "ping": "pong"
}
```

现在您已经学会了为 Ansible 配置 Windows 主机所需的步骤，让我们在下一节中看看如何通过 Ansible 连接多个主机。

# 了解您的 Ansible 安装

在本章的这个阶段，无论你选择的操作系统是什么，你应该已经有一个可用的 Ansible 安装，可以开始探索自动化的世界。在本节中，我们将进行对 Ansible 基础知识的实际探索，以帮助你了解如何使用它。一旦掌握了这些基本技能，你就会有足够的知识来充分利用本书的其余部分。让我们从概述 Ansible 如何连接到非 Windows 主机开始。

# 理解 Ansible 如何连接到主机

除了 Windows 主机（如前一节末讨论的），Ansible 使用 SSH 协议与主机通信。Ansible 设计选择这种方式的原因有很多，其中最重要的是几乎每台 Linux/FreeBSD/macOS 主机都内置了它，许多网络设备（如交换机和路由器）也是如此。这个 SSH 服务通常与操作系统身份验证堆栈集成，使你能够利用诸如 Kerberos 等功能来提高身份验证安全性。此外，OpenSSH 的功能，如 `ControlPersist`，用于增加自动化任务的性能和用于网络隔离和安全的 SSH 跳转主机。

`ControlPersist` 在大多数现代 Linux 发行版中默认启用作为 OpenSSH 服务器安装的一部分。然而，在一些较旧的操作系统上，如 Red Hat Enterprise Linux 6（和 CentOS 6），它不受支持，因此你将无法使用它。Ansible 自动化仍然是完全可能的，但更长的 playbooks 可能会运行得更慢。

Ansible 使用与你已经熟悉的相同的身份验证方法，SSH 密钥通常是最简单的方法，因为它们消除了用户在每次运行 playbook 时输入身份验证密码的需要。然而，这绝不是强制性的，Ansible 通过使用 `--ask-pass` 开关支持密码身份验证。如果你连接到主机上的一个非特权帐户，并且需要执行 Ansible 等效的以 `sudo` 运行命令，你也可以在运行 playbook 时添加 `--ask-become-pass`，以允许在运行时指定这个。

自动化的目标是能够安全地运行任务，但最少的用户干预。因此，强烈建议你使用 SSH 密钥进行身份验证，如果你有多个密钥需要管理，那么一定要使用 `ssh-agent`。

每个 Ansible 任务，无论是单独运行还是作为复杂 playbook 的一部分运行，都是针对清单运行的。清单就是你希望运行自动化命令的主机列表。Ansible 支持各种清单格式，包括使用动态清单，它可以自动从编排提供程序中填充自己（例如，你可以动态生成一个 Ansible 清单，从你的 Amazon EC2 实例中，这意味着你不必跟上云基础设施中的所有变化）。

动态清单插件已经为大多数主要的云提供商（例如，Amazon EC2，Google Cloud Platform 和 Microsoft Azure），以及本地系统（如 OpenShift 和 OpenStack）编写。甚至还有 Docker 的插件。开源软件的美妙之处在于，对于大多数你能想到的主要用例，有人已经贡献了代码，所以你不需要自己去弄清楚或编写它。

Ansible 的无代理架构以及它不依赖于 SSL 的事实意味着你不需要担心 DNS 未设置或者由于 NTP 不工作而导致的时间偏移问题——事实上，这些都可以由 Ansible playbook 执行！事实上，Ansible 确实是设计用来从几乎空白的操作系统镜像中运行你的基础设施。

目前，让我们专注于 INI 格式的清单。下面是一个示例，其中有四台服务器，每台服务器分成两个组。可以对整个清单（即所有四台服务器）、一个或多个组（例如`webservers`）甚至单个服务器运行 Ansible 命令和 playbooks：

```
[webservers]
web1.example.com
web2.example.com

[apservers]
ap1.example.com
ap2.example.com
```

让我们使用这个清单文件以及 Ansible 的`ping`模块，用于测试 Ansible 是否能够成功在所讨论的清单主机上执行自动化任务。以下示例假设您已将清单安装在默认位置，通常为`/etc/ansible/hosts`。当您运行以下`ansible`命令时，您将看到类似于这样的输出：

```
$ ansible webservers -m ping 
web1.example.com | SUCCESS => {
 "changed": false, 
 "ping": "pong"
}
web2.example.com | SUCCESS => {
 "changed": false, 
 "ping": "pong"
}
$
```

请注意，`ping`模块仅在`webservers`组中的两台主机上运行，而不是整个清单——这是因为我们在命令行参数中指定了这一点。

`ping`模块是 Ansible 的成千上万个模块之一，所有这些模块都执行一组给定的任务（从在主机之间复制文件到文本替换，再到复杂的网络设备配置）。同样，由于 Ansible 是开源软件，有大量的编码人员在编写和贡献模块，这意味着如果您能想到一个任务，可能已经有一个 Ansible 模块。即使没有模块存在的情况下，Ansible 支持发送原始 shell 命令（或者对于 Windows 主机的 PowerShell 命令），因此即使在这种情况下，您也可以完成所需的任务，而无需离开 Ansible。

只要 Ansible 控制主机能够与清单中的主机通信，您就可以自动化您的任务。但是，值得考虑一下您放置控制主机的位置。例如，如果您专门使用一组 Amazon EC2 机器，您的 Ansible 控制机器最好是一个 EC2 实例——这样，您就不需要通过互联网发送所有自动化命令。这也意味着您不需要将 EC2 主机的 SSH 端口暴露给互联网，因此使它们更安全。

到目前为止，我们已经简要解释了 Ansible 如何与其目标主机通信，包括清单是什么以及对所有主机进行 SSH 通信的重要性，除了 Windows 主机。在下一节中，我们将通过更详细地查看如何验证您的 Ansible 安装来进一步了解这一点。

# 验证 Ansible 安装

在本节中，您将学习如何使用简单的临时命令验证您的 Ansible 安装。

正如之前讨论的，Ansible 可以通过多种方式对目标主机进行身份验证。在本节中，我们将假设您希望使用 SSH 密钥，并且您已经生成了公钥和私钥对，并将公钥应用于您将自动化任务的所有目标主机。

`ssh-copy-id`实用程序非常有用，可以在继续之前将您的公共 SSH 密钥分发到目标主机。例如命令可能是`ssh-copy-id -i ~/.ssh/id_rsa ansibleuser@web1.example.com`。

为了确保 Ansible 可以使用您的私钥进行身份验证，您可以使用`ssh-agent`——命令显示了如何启动`ssh-agent`并将您的私钥添加到其中的简单示例。当然，您应该将路径替换为您自己私钥的路径：

```
$ ssh-agent bash 
$ ssh-add ~/.ssh/id_rsa
```

正如我们在前一节中讨论的，我们还必须为 Ansible 定义一个清单。下面是另一个简单的示例：

```
[frontends]
frt01.example.com
frt02.example.com
```

我们在上一节中使用的`ansible`命令有两个重要的开关，您几乎总是会使用：`-m <MODULE_NAME>`在您指定的清单主机上运行一个模块，还可以使用`-a OPT_ARGS`开关传递模块参数。使用`ansible`二进制运行的命令称为临时命令。

以下是三个简单示例，演示了临时命令-它们也对验证您控制机器上的 Ansible 安装和目标主机的配置非常有价值，如果配置的任何部分存在问题，它们将返回错误：

+   **Ping 主机**：您可以使用以下命令对您的库存主机执行 Ansible“ping”：

```
$ ansible frontends -i hosts -m ping
```

+   显示收集的事实：您可以使用以下命令显示有关您的库存主机的收集事实：

```
$ ansible frontends -i hosts -m setup | less
```

+   **过滤收集的事实**：您可以使用以下命令过滤收集的事实：

```
$ ansible frontends -i hosts -m setup -a "filter=ansible_distribution*"
```

对于您运行的每个临时命令，您将以 JSON 格式获得响应-以下示例输出是成功运行`ping`模块的结果：

```
$ ansible frontends -m ping 
frontend01.example.com | SUCCESS => {
 "changed": false, 
 "ping": "pong"
}
frontend02.example.com | SUCCESS => {
 "changed": false, 
 "ping": "pong"
}
```

Ansible 还可以收集并返回有关目标主机的“事实”-事实是有关主机的各种有用信息，从 CPU 和内存配置到网络参数，再到磁盘几何。这些事实旨在使您能够编写智能的 playbook，执行条件操作-例如，您可能只想在具有 4GB 以上 RAM 的主机上安装特定软件包，或者仅在 macOS 主机上执行特定配置。以下是来自基于 macOS 的主机的过滤事实的示例：

```
$ ansible frontend01.example.com -m setup -a "filter=ansible_distribution*"
frontend01.example.com | SUCCESS => {
 ansible_facts": {
 "ansible_distribution": "macOS", 
 "ansible_distribution_major_version": "10", 
 "ansible_distribution_release": "18.5.0", 
 "ansible_distribution_version": "10.14.4"
 }, 
 "changed": false
```

临时命令非常强大，既可以用于验证您的 Ansible 安装，也可以用于学习 Ansible 以及如何使用模块，因为您不需要编写整个 playbook-您只需运行一个临时命令并学习它如何响应。以下是一些供您考虑的其他临时示例：

+   使用以下命令将文件从 Ansible 控制主机复制到“前端”组中的所有主机：

```
$ ansible frontends -m copy -a "src=/etc/yum.conf dest=/tmp/yum.conf"
```

+   在“前端”库存组中的所有主机上创建一个新目录，并使用特定的所有权和权限创建它：

```
$ ansible frontends -m file -a "dest=/path/user1/new mode=777 owner=user1 group=user1 state=directory" 
```

+   使用以下命令从“前端”组中的所有主机中删除特定目录：

```
$ ansible frontends -m file -a "dest=/path/user1/new state=absent"
```

+   使用`yum`安装`httpd`软件包，如果尚未安装-如果已安装，则不更新。同样，这适用于“前端”库存组中的所有主机：

```
$ ansible frontends -m yum -a "name=httpd state=present"
```

+   以下命令与上一个命令类似，只是将`state=present`更改为`state=latest`会导致 Ansible 安装（最新版本的）软件包（如果尚未安装），并将其更新到最新版本（如果已安装）：

```
$ ansible frontends -m yum -a "name=demo-tomcat-1 state=latest" 
```

+   显示有关库存中所有主机的所有事实（警告-这将产生大量的 JSON！）：

```
$ ansible all -m setup 
```

现在您已经了解了如何验证您的 Ansible 安装以及如何运行临时命令，让我们继续更详细地查看由 Ansible 管理的节点的要求。

# 受管节点要求

到目前为止，我们几乎完全专注于 Ansible 控制主机的要求，并假设（除了分发 SSH 密钥之外）目标主机将正常工作。当然，并非总是如此，例如，从 ISO 安装的现代 Linux 安装通常会正常工作，云操作系统映像通常会被剥离以保持其小巧，因此可能缺少重要的软件包，如 Python，没有 Python，Ansible 无法运行。

如果您的目标主机缺少 Python，通常可以通过操作系统的软件包管理系统轻松安装它。Ansible 要求您在 Ansible 控制机器（正如我们在本章前面所介绍的）和每个受管节点上安装 Python 版本 2.7 或 3.5（及以上）。再次强调，这里的例外是 Windows，它依赖于 PowerShell。

如果您使用缺少 Python 的操作系统映像，以下命令提供了快速安装 Python 的指南：

+   要使用`yum`安装 Python（在旧版本的 Fedora 和 CentOS/RHEL 7 及以下版本中），请使用以下命令：

```
$ sudo yum -y install python
```

+   在 RHEL 和 CentOS 8 及更新版本的 Fedora 上，您将使用`dnf`软件包管理器：

```
$ sudo dnf install python
```

您也可以选择安装特定版本以满足您的需求，就像这个例子一样：

```
$ sudo dnf install python37
```

+   在 Debian 和 Ubuntu 系统上，您将使用`apt`软件包管理器安装 Python，如果需要的话再指定一个版本（这里给出的示例是安装 Python 3.6，在 Ubuntu 18.04 上可以工作）：

```
$ sudo apt-get update
$ sudo apt-get install python3.6
```

我们在本章前面讨论的 Ansible 的`ping`模块不仅检查与受控主机的连接和身份验证，而且使用受控主机的 Python 环境执行一些基本主机检查。因此，它是一个很棒的端到端测试，可以让您确信您的受控主机已正确配置为主机，具有完美的连接和身份验证设置，但如果缺少 Python，它将返回一个`failed`结果。

当然，在这个阶段一个完美的问题是：如果您使用一个精简的基础镜像在云服务器上部署了 100 个节点，Ansible 如何帮助您？这是否意味着您必须手动检查所有 100 个节点并手动安装 Python 才能开始自动化？

幸运的是，即使在这种情况下，Ansible 也可以帮助您，这要归功于`raw`模块。这个模块用于向受控节点发送原始 shell 命令——它既适用于 SSH 管理的主机，也适用于 Windows PowerShell 管理的主机。因此，您可以使用 Ansible 在缺少 Python 的整套系统上安装 Python，甚至运行一个整个的 shell 脚本来引导一个受控节点。最重要的是，`raw`模块是为数不多的几个不需要在受控节点上安装 Python 的模块之一，因此它非常适合我们的用例，我们必须安装 Python 以启用进一步的自动化。

以下是 Ansible playbook 中的一些任务示例，您可以使用它们来引导受控节点并为其准备好 Ansible 管理：

```
- name: Bootstrap a host without python2 installed
  raw: dnf install -y python2 python2-dnf libselinux-python

- name: Run a command that uses non-posix shell-isms (in this example /bin/sh doesn't handle redirection and wildcards together but bash does)
  raw: cat < /tmp/*txt
  args:
    executable: /bin/bash

- name: safely use templated variables. Always use quote filter to avoid injection issues.
  raw: "{{package_mgr|quote}}  {{pkg_flags|quote}}  install  {{python|quote}}"
```

我们现在已经介绍了在控制主机和受控节点上设置 Ansible 的基础知识，并且为您提供了配置第一个连接的简要入门。在结束本章之前，我们将更详细地看一下如何从 GitHub 直接运行最新的 Ansible 开发版本。

# 从源代码运行与预构建的 RPM 包

Ansible 一直在快速发展，可能会有时候，无论是为了早期访问新功能（或模块），还是作为您自己的开发工作的一部分，您希望从 GitHub 运行最新的、最前沿的 Ansible 版本。在本节中，我们将看一下如何快速启动并运行源代码。本章概述的方法有一个优点，即与基于软件包管理器的安装不同，后者必须以 root 身份执行，最终结果是安装了一个可工作的 Ansible，而无需任何 root 权限。

让我们开始从 GitHub 检出最新版本的源代码：

1.  您必须首先从`git`存储库克隆源代码，然后切换到包含已检出代码的目录：

```
$ git clone https://github.com/ansible/ansible.git --recursive
$ cd ./ansible
```

1.  在进行任何开发工作之前，或者确保从源代码运行 Ansible，您必须设置您的 shell 环境。为此提供了几个脚本，每个脚本适用于不同的 shell 环境。例如，如果您使用古老的 Bash shell，您将使用以下命令设置您的环境：

```
$ source ./hacking/env-setup
```

相反，如果您使用 Fish shell，您将设置您的环境如下：

```
**$ source ./hacking/env-setup.fish**
```

1.  设置好环境后，您必须安装`pip` Python 软件包管理器，然后使用它来安装所有所需的 Python 软件包（注意：如果您的系统上已经有`pip`，则可以跳过第一个命令）：

```
$ sudo easy_install pip
$ sudo pip install -r ./requirements.txt
```

请注意，当您运行`env-setup`脚本时，您将从您的源代码检出运行，并且默认的清单文件将是`/etc/ansible/hosts`。您可以选择指定一个除`/etc/ansible/hosts`之外的清单文件。

1.  当您运行`env-setup`脚本时，Ansible 将从源代码检出运行，默认的清单文件是`/etc/ansible/hosts`；但是，您可以选择在您的机器上任何地方指定清单文件（有关更多详细信息，请参见*使用清单*，[`docs.ansible.com/ansible/latest/user_guide/intro_inventory.html#inventory`](https://docs.ansible.com/ansible/latest/user_guide/intro_inventory.html#inventory)）。以下命令提供了一个示例，说明您可能会这样做，但显然，您的文件名和内容几乎肯定会有所不同：

```
$ echo "ap1.example.com" > ~/my_ansible_inventory
$ export ANSIBLE_INVENTORY=~/my_ansible_inventory
```

`ANSIBLE_INVENTORY`适用于 Ansible 版本 1.9 及以上，并替换了已弃用的`ANSIBLE_HOSTS`环境变量。

完成这些步骤后，您可以像本章中讨论的那样运行 Ansible，唯一的例外是您必须指定它的绝对路径。例如，如果您像前面的代码中设置清单并将 Ansible 源克隆到您的主目录中，您可以运行我们现在熟悉的临时`ping`命令，如下所示：

```
$ ~/ansible/bin/ansible all -m ping
ap1.example.com | SUCCESS => {
 "changed": false, 
 "ping": "pong"
}
```

当然，Ansible 源树不断变化，您不太可能只想坚持您克隆的副本。当需要更新时，您不需要克隆新副本；您可以使用以下命令更新现有的工作副本（同样，假设您最初将源树克隆到您的主目录中）：

```
$ git pull --rebase
$ git submodule update --init --recursive
```

这就结束了我们对设置您的 Ansible 控制机和受管节点的介绍。希望您在本章中获得的知识将帮助您启动并为本书的其余部分奠定基础。

# 摘要

Ansible 是一个强大而多才多艺的简单自动化工具，其主要优势是其无代理架构和简单的安装过程。Ansible 旨在让您迅速实现从零到自动化，并以最小的努力，我们已经在本章中展示了您可以如何轻松地开始使用 Ansible。

在本章中，您学习了设置 Ansible 的基础知识——如何安装它来控制其他主机以及被 Ansible 管理的节点的要求。您了解了为 Ansible 自动化设置 SSH 和 WinRM 所需的基础知识，以及如何引导受管节点以确保它们适合于 Ansible 自动化。您还了解了临时命令及其好处。最后，您学会了如何直接从 GitHub 运行最新版本的代码，这既使您能够直接为 Ansible 的开发做出贡献，又使您能够在您的基础设施上使用最新的功能。

在下一章中，我们将学习 Ansible 语言基础知识，以便您编写您的第一个 playbook，并帮助您创建模板化配置，并开始构建复杂的自动化工作流程。

# 问题

1.  您可以在哪些操作系统上安装 Ansible？（多个正确答案）

A）Ubuntu

B）Fedora

C）Windows 2019 服务器

D）HP-UX

E）主机

1.  Ansible 使用哪种协议连接远程机器来运行任务？

A）HTTP

B）HTTPS

C）SSH

D）TCP

E）UDP

1.  要在 Ansible 临时命令行中执行特定模块，您需要使用`-m`选项。

A）正确

B）错误

# 进一步阅读

+   有关通过 Ansible Mailing Liston Google Groups 安装的任何问题，请参阅以下内容：

[`groups.google.com/forum/#!forum/ansible-project`](https://groups.google.com/forum/#!forum/ansible-project)

+   如何安装最新版本的`pip`可以在这里找到：

[`pip.pypa.io/en/stable/installing/#installation`](https://pip.pypa.io/en/stable/installing/#installation)

+   可以在此处找到使用 PowerShell 的特定 Windows 模块：

[`github.com/ansible/ansible-modules-core/tree/devel/windows`](https://github.com/ansible/ansible-modules-core/tree/devel/windows)

+   如果您有 GitHub 账户并想关注 GitHub 项目，您可以继续跟踪 Ansible 的问题、错误和想法：

[`github.com/ansible/ansible`](https://github.com/ansible/ansible)


# 第二章：理解 Ansible 的基础知识

在其核心，Ansible 是一个简单的框架，它将一个称为**Ansible 模块**的小程序推送到目标节点。模块是 Ansible 的核心，负责执行所有自动化的繁重工作。然而，Ansible 框架不仅限于此，还包括插件和动态清单管理，以及使用 playbooks 将所有这些内容与一起自动化基础设施的配置管理、应用部署、网络自动化等联系起来，如下所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/prac-asb/img/075a1fbf-b62c-4730-8456-c81515ebb75c.png)

Ansible 只需要安装在管理节点上；从那里，它通过网络传输层（通常是 SSH 或 WinRM）分发所需的模块来执行任务，并在任务完成后删除它们。通过这种方式，Ansible 保持了无代理的架构，并且不会用可能需要进行一次性自动化任务的代码来混淆目标节点。

在本章中，您将更多地了解 Ansible 框架的组成及其各个组件，以及如何在使用 YAML 语法编写的 playbooks 中将它们结合在一起。因此，您将学习如何为 IT 操作任务创建自动化代码，并学习如何使用临时任务和更复杂的 playbooks 应用它们。最后，您将学习 Jinja2 模板如何允许您使用变量和动态表达式重复构建动态配置文件。

在本章中，我们将涵盖以下主题：

+   熟悉 Ansible 框架

+   探索配置文件

+   命令行参数

+   定义变量

+   理解 Jinja2 过滤器

# 技术要求

本章假设您已成功将最新版本的 Ansible（在撰写本文时为 2.9）安装到 Linux 节点上，如第一章中所讨论的*开始使用 Ansible*。它还假设您至少有另一台 Linux 主机用于测试自动化代码；您拥有的主机越多，您就能够开发本章中的示例并了解 Ansible 的内容就越多。假定 Linux 主机之间存在 SSH 通信，并且对它们有一定的了解。

本章的代码包可在[`github.com/PacktPublishing/Ansible-2-Cookbook/tree/master/Chapter%202`](https://github.com/PacktPublishing/Ansible-2-Cookbook/tree/master/Chapter%202)获取。

# 熟悉 Ansible 框架

在本节中，您将了解 Ansible 框架如何适用于 IT 操作自动化。我们将解释如何首次启动 Ansible。一旦您了解了这个框架，您就准备好开始学习更高级的概念，比如创建和运行自己清单的 playbooks。

为了通过 SSH 连接从 Ansible 控制机器运行 Ansible 的临时命令到多个远程主机，您需要确保控制主机上安装了最新的 Ansible 版本。使用以下命令确认最新的 Ansible 版本：

```
$ ansible --version
ansible 2.9.6
 config file = /etc/ansible/ansible.cfg
 configured module search path = [u'/home/jamesf_local/.ansible/plugins/modules', u'/usr/share/ansible/plugins/modules']
 ansible python module location = /usr/lib/python2.7/dist-packages/ansible
 executable location = /usr/bin/ansible
 python version = 2.7.17 (default, Nov 7 2019, 10:07:09) [GCC 9.2.1 20191008]
```

您还需要确保与清单中定义的每个远程主机建立 SSH 连接。您可以在每个远程主机上使用简单的手动 SSH 连接来测试连接性，因为在所有远程基于 Linux 的自动化任务中，Ansible 将使用 SSH：

```
$ ssh <username>@frontend.example.com
The authenticity of host 'frontend.example.com (192.168.1.52)' can't be established.
ED25519 key fingerprint is SHA256:hU+saFERGFDERW453tasdFPAkpVws.
Are you sure you want to continue connecting (yes/no)? yes password:<Input_Your_Password>
```

在本节中，我们将带您了解 Ansible 的工作原理，从一些简单的连接测试开始。您可以通过以下简单步骤了解 Ansible 框架如何访问多个主机来执行您的任务：

1.  创建或编辑您的默认清单文件`/etc/ansible/hosts`（您也可以通过传递选项，如`--inventory=/path/inventory_file`来指定自己的清单文件的路径）。在清单中添加一些示例主机——这些必须是 Ansible 要测试的真实机器的 IP 地址或主机名。以下是我网络中的示例，但您需要用自己的设备替换这些。每行添加一个主机名（或 IP 地址）：

```
frontend.example.com
backend1.example.com
backend2.example.com 
```

所有主机都应该使用可解析的地址来指定——即**完全合格的域名**（**FQDN**）——如果您的主机有 DNS 条目（或者在您的 Ansible 控制节点上的`/etc/hosts`中）。如果您没有设置 DNS 或主机条目，这可以是 IP 地址。无论您选择哪种格式作为清单地址，您都应该能够成功地对每个主机进行 ping。以下输出是一个例子：

```
$ ping frontend.example.com
PING frontend.example.com (192.168.1.52): 56 data bytes
64 bytes from 192.168.1.52: icmp_seq=0 ttl=64 time=0.040 ms
64 bytes from 192.168.1.52: icmp_seq=1 ttl=64 time=0.115 ms
64 bytes from 192.168.1.52: icmp_seq=2 ttl=64 time=0.097 ms
64 bytes from 192.168.1.52: icmp_seq=3 ttl=64 time=0.130 ms 
```

1.  为了使自动化过程更加无缝，我们将生成一个 SSH 认证密钥对，这样我们就不必每次运行 playbook 时都输入密码。如果您还没有 SSH 密钥对，可以使用以下命令生成一个：

```
$ ssh-keygen 
```

当您运行`ssh-keygen`工具时，您将看到类似以下的输出。请注意，当提示时，您应该将`passphrase`变量留空；否则，您每次想运行 Ansible 任务时都需要输入一个密码，这将取消使用 SSH 密钥进行认证的便利性：

```
$ ssh-keygen 
Generating public/private rsa key pair.
Enter file in which to save the key (/Users/doh/.ssh/id_rsa): <Enter>
Enter passphrase (empty for no passphrase): <Press Enter>
Enter same passphrase again: <Press Enter>
Your identification has been saved in /Users/doh/.ssh/id_rsa.
Your public key has been saved in /Users/doh/.ssh/id_rsa.pub.
The key fingerprint is:
SHA256:1IF0KMMTVAMEQF62kTwcG59okGZLiMmi4Ae/BGBT+24 doh@danieloh.com
The key's randomart image is:
+---[RSA 2048]----+
|=*=*BB==+oo |
|B=*+*B=.o+ . |
|=+=o=.o+. . |
|...=. . |
| o .. S |
| .. |
| E |
| . |
| |
+----[SHA256]-----+
```

1.  虽然有条件可以自动选择您的 SSH 密钥，但建议您使用`ssh-agent`，因为这样可以加载多个密钥来对抗各种目标进行认证。即使现在用不上，将来这对您也会非常有用。启动`ssh-agent`并添加您的新认证密钥，如下（请注意，您需要为每个打开的 shell 执行此操作）：

```
$ ssh-agent bash
$ ssh-add ~/.ssh/id_rsa 
```

4. 在您可以对目标主机执行基于密钥的认证之前，您需要将刚刚生成的密钥对的公钥应用到每个主机上。您可以使用以下命令依次将密钥复制到每个主机：

```
$  ssh-copy-id -i ~/.ssh/id_rsa.pub frontend.example.com
/usr/bin/ssh-copy-id: INFO: Source of key(s) to be installed: "~/.ssh/id_rsa.pub"
/usr/bin/ssh-copy-id: INFO: attempting to log in with the new key(s), to filter out any that are already installed
/usr/bin/ssh-copy-id: INFO: 1 key(s) remain to be installed -- if you are prompted now it is to install the new keys
doh@frontend.example.com's password:

Number of key(s) added: 1

Now try logging into the machine, with: "ssh 'frontend.example.com'"
and check to make sure that only the key(s) you wanted were added.
```

5. 完成后，您现在应该能够对清单文件中放入的主机执行 Ansible 的`ping`命令。您会发现在任何时候都不需要输入密码，因为对清单中所有主机的 SSH 连接都使用您的 SSH 密钥对进行了认证。因此，您应该会看到类似以下的输出：

```
$ ansible all -i hosts -m ping
frontend.example.com | SUCCESS => {
 "changed": false, 
 "ping": "pong"
}
backend1.example.com | SUCCESS => {
 "changed": false, 
 "ping": "pong"
}
backend2.example.com | SUCCESS => {
 "changed": false, 
 "ping": "pong"
}
```

此示例输出是使用 Ansible 的默认详细级别生成的。如果在此过程中遇到问题，您可以通过在运行时向`ansible`命令传递一个或多个`-v`开关来增加 Ansible 的详细级别。对于大多数问题，建议您使用`-vvvv`，这会为您提供丰富的调试信息，包括原始 SSH 命令和来自它们的输出。例如，假设某个主机（例如`backend2.example.com`）无法连接，并且您收到类似以下的错误：

```
backend2.example.com | FAILED => SSH encountered an unknown error during the connection. We recommend you re-run the command using -vvvv, which will enable SSH debugging output to help diagnose the issue 
```

请注意，即使 Ansible 也建议使用`-vvvv`开关进行调试。这可能会产生大量输出，但会包括许多有用的细节，例如用于生成与清单中目标主机的连接的原始 SSH 命令，以及可能由此调用产生的任何错误消息。在调试连接或代码问题时，这可能非常有用，尽管一开始输出可能有点压倒性。但是，通过一些实践，您将很快学会如何解释它。

到目前为止，您应该已经对 Ansible 如何通过 SSH 与其客户端进行通信有了一个很好的了解。让我们继续进行下一部分，我们将更详细地了解组成 Ansible 的各个组件，因为这将帮助我们更好地理解如何使用它。

# 分解 Ansible 组件

Ansible 允许您在 playbooks 中定义策略、配置、任务序列和编排步骤，限制只在于您的想象力。可以同步或异步地在远程机器上执行 playbook 来管理任务，尽管大多数示例都是同步的。在本节中，您将了解 Ansible 的主要组件，并了解 Ansible 如何利用这些组件与远程主机通信。

为了了解各个组件，我们首先需要一个清单来进行工作。让我们创建一个示例清单，最好其中包含多个主机，这可能与您在上一节中创建的相同。如上一节所述，您应该使用主机名或 IP 地址填充清单，这些主机可以从控制主机本身访问到：

```
remote1.example.com
remote2.example.com
remote3.example.com
```

要真正了解 Ansible 以及其各个组件的工作原理，我们首先需要创建一个 Ansible playbook。尽管迄今为止我们尝试过的临时命令只是单个任务，但 playbooks 是组织良好的任务组，通常按顺序运行。可以应用条件逻辑，在任何其他编程语言中，它们都将被视为您的代码。在 playbook 的开头，您应该指定 play 的名称，尽管这不是强制性的，但将所有 play 和任务命名是一个良好的做法，没有这一点，其他人很难解释 playbook 的作用，即使您在一段时间后回来也是如此。让我们开始构建我们的第一个示例 playbook：

1.  在 playbook 的顶部指定 play 名称和清单主机以运行您的任务。还要注意使用`---`，它表示一个 YAML 文件的开始（用 YAML 编写的 Ansible playbook）：

```
---
- name: My first Ansible playbook
  hosts: all
```

1.  之后，我们将告诉 Ansible，我们希望将此 playbook 中的所有任务都作为超级用户（通常为`root`）执行。我们使用以下语句来实现这一点（为了帮助您记忆，将`become`视为`become superuser`的缩写）：

```
  become: yes
```

1.  在此标题之后，我们将指定一个任务块，其中将包含一个或多个要按顺序运行的任务。现在，我们将简单地创建一个任务，使用`yum`模块更新 Apache 的版本（因此，此 playbook 仅适用于针对基于 RHEL、CentOS 或 Fedora 的主机运行）。我们还将指定 play 的一个特殊元素，称为处理程序。处理程序将在第四章《Playbooks and Roles》中详细介绍，所以现在不要太担心它们。简而言之，处理程序是一种特殊类型的任务，仅在某些内容更改时才会调用。因此，在此示例中，它会重新启动 Web 服务器，但仅在更改时才会重新启动，如果多次运行 playbook 并且没有 Apache 的更新，则可以防止不必要的重新启动。以下代码完全执行了这些功能，并应成为您的第一个 playbook 的基础：

```
  tasks:
  - name: Update the latest of an Apache Web Server
    yum:
      name: httpd
      state: latest
    notify:
      - Restart an Apache Web Server

 handlers:
 - name: Restart an Apache Web Server
   service:
     name: httpd
     state: restarted
```

恭喜，您现在拥有了您的第一个 Ansible playbook！如果您现在运行此 playbook，您应该会看到它在清单中的所有主机上进行迭代，以及在 Apache 软件包的每次更新时，然后重新启动服务。您的输出应该如下所示：

```
$ PLAY [My first Ansible playbook] ***********************************************

TASK [Gathering Facts] *********************************************************
ok: [remote2.example.com]
ok: [remote1.example.com]
ok: [remote3.example.com]

TASK [Update the latest of an Apache Web Server] *******************************
changed: [remote2.example.com]
changed: [remote3.example.com]
changed: [remote1.example.com]

RUNNING HANDLER [Restart an Apache Web Server] *********************************
changed: [remote3.example.com]
changed: [remote1.example.com]
changed: [remote2.example.com]

PLAY RECAP *********************************************************************
remote1.example.com : ok=3 changed=2 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
remote2.example.com : ok=3 changed=2 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
remote3.example.com : ok=3 changed=2 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
```

如果您检查 playbook 的输出，您会发现不仅 play 的名称很重要，每个执行的任务也很重要，因为这使得解释运行的输出变得非常简单。您还会看到运行任务有多种可能的结果；在前面的示例中，我们可以看到两种结果——`ok`和`changed`。这些结果大多都很容易理解，`ok`表示任务成功运行，并且由于运行的结果没有发生任何变化。在前面的 playbook 中，`Gathering Facts`阶段就是一个只读任务，用于收集有关目标主机的信息。因此，它只能返回`ok`或失败的状态，比如如果主机宕机，则返回`unreachable`。它不应该返回`changed`。

然而，您可以在前面的输出中看到，所有三个主机都需要升级其 Apache 软件包，因此，“更新 Apache Web 服务器的最新版本”任务的结果对所有主机都是“更改”。这个“更改”结果意味着我们的“处理程序”变量被通知，Web 服务器服务被重新启动。

如果我们第二次运行 playbook，我们知道 Apache 软件包很可能不需要再次升级。请注意这次 playbook 输出的不同之处：

```
PLAY [My first Ansible playbook] ***********************************************

TASK [Gathering Facts] *********************************************************
ok: [remote1.example.com]
ok: [remote2.example.com]
ok: [remote3.example.com]

TASK [Update the latest of an Apache Web Server] *******************************
ok: [remote2.example.com]
ok: [remote3.example.com]
ok: [remote1.example.com]

PLAY RECAP *********************************************************************
remote1.example.com : ok=2 changed=0 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
remote2.example.com : ok=2 changed=0 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
remote3.example.com : ok=2 changed=0 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
```

您可以看到，这次“更新 Apache Web 服务器的最新版本”任务的输出对所有三个主机都是`ok`，这意味着没有应用任何更改（软件包未更新）。因此，我们的处理程序没有收到通知，也没有运行——您可以看到它甚至没有出现在前面的 playbook 输出中。这种区别很重要——Ansible playbook（以及支持 Ansible 的模块）的目标应该是只在需要时才进行更改。如果一切都是最新的，那么目标主机就不应该被更改。应该避免不必要地重新启动服务，也应该避免对文件进行不必要的更改。简而言之，Ansible playbook 被设计为高效实现目标机器状态。

这实际上是一个关于编写您的第一个 playbook 的速成课程，但希望它能让您对 Ansible 从单个临时命令到更复杂的 playbook 时可以做些什么有所了解。在我们进一步探索 Ansible 语言和组件之前，让我们更深入地了解一下 playbook 所写的 YAML 语言。

# 学习 YAML 语法

在本节中，您将学习如何以正确的语法编写 YAML 文件，并了解在多个远程机器上运行 playbook 的最佳实践和技巧。Ansible 使用 YAML 是因为它比其他常见的数据格式（如 XML 或 JSON）更容易阅读和编写。不需要担心逗号、花括号或标签，代码中强制的缩进确保了代码的整洁和易读。此外，大多数编程语言都有可用于处理 YAML 的库。

这反映了 Ansible 的核心目标之一——产生易于阅读（和编写）的代码，描述给定主机的目标状态。Ansible playbook（理想情况下）应该是自我记录的，因为在繁忙的技术环境中，文档通常是一个事后想法——那么，有什么比通过负责部署代码的自动化系统更好的记录方式呢？

在我们深入了解 YAML 结构之前，先说一下文件本身。以 YAML 编写的文件可以选择性地以`---`开头（如前一节中示例 playbook 中所见）并以`...`结尾。这适用于 YAML 中的所有文件，无论是由 Ansible 还是其他系统使用，都表示文件是使用 YAML 语言编写的。您会发现，大多数 Ansible playbook 的示例（以及角色和其他相关的 YAML 文件）都以`---`开头，但不以`...`结尾——标题足以清楚地表示文件使用 YAML 格式。

让我们通过前面部分创建的示例 playbook 来探索 YAML 语言：

1.  列表是 YAML 语言中的一个重要构造——实际上，尽管可能不太明显，playbook 的`tasks:`块实际上是一个 YAML 列表。YAML 中的列表将所有项目列在相同的缩进级别上，每行以`-`开头。例如，我们使用以下代码更新了前面 playbook 中的`httpd`软件包：

```
  - name: Update the latest of an Apache Web Server
    yum:
      name: httpd
      state: latest
```

然而，我们可以指定要升级的软件包列表如下：

```
  - name: Update the latest of an Apache Web Server
    yum:
      name:
        - httpd
        - mod_ssl
      state: latest
```

现在，我们不再将单个值传递给`name:`键，而是传递一个包含要更新的两个软件包名称的 YAML 格式列表。

1.  字典是 YAML 中的另一个重要概念——它们由`key: value`格式表示，正如我们已经广泛看到的那样，但字典中的所有项目都缩进了一个更高的级别。这最容易通过一个例子来解释，因此考虑我们示例 playbook 中的以下代码：

```
    service:
      name: httpd
      state: restarted
```

在这个例子中（来自`handler`），`service`定义实际上是一个字典，`name`和`state`键的缩进比`service`键多两个空格。这种更高级别的缩进意味着`name`和`state`键与`service`键相关联，因此，在这种情况下，告诉`service`模块要操作哪个服务（`httpd`）以及对其执行什么操作（重新启动）。

已经在这两个例子中观察到，通过混合列表和字典，您可以制作相当复杂的数据结构。

1.  随着您在 playbook 设计方面变得更加高级（我们将在本书的后面看到这方面的例子），您可能会开始制作相当复杂的变量结构，并将它们放入自己的单独文件中，以保持 playbook 代码的可读性。以下是一个提供公司两名员工详细信息的`variables`文件示例：

```
---
employees:
  - name: daniel
    fullname: Daniel Oh
    role: DevOps Evangelist
    level: Expert
    skills:
      - Kubernetes
      - Microservices
      - Ansible
      - Linux Container
  - name: michael
    fullname: Michael Smiths
    role: Enterprise Architect
    level: Advanced
    skills:
      - Cloud
      - Middleware
      - Windows
      - Storage
```

在这个例子中，您可以看到我们有一个包含每个员工详细信息的字典。员工本身是列表项（您可以通过行首的`-`来识别），同样，员工技能也被表示为列表项。您会注意到`fullname`、`role`、`level`和`skills`键与`name`处于相同的缩进级别，但它们之前没有`-`。这告诉您它们与列表项本身在同一个字典中，因此它们代表员工的详细信息。

1.  YAML 在解析语言时非常字面，每个新行始终代表着新的代码行。如果您确实需要添加一块文本（例如，到一个变量）怎么办？在这种情况下，您可以使用一个文字块标量`|`来写多行，YAML 将忠实地保留新行、回车和每行后面的所有空格（但请注意，每行开头的缩进是 YAML 语法的一部分）：

```
Specialty: |
  Agile methodology
  Cloud-native app development practices
  Advanced enterprise DevOps practices
```

因此，如果我们让 Ansible 将前面的内容打印到屏幕上，它将显示如下（请注意，前面的两个空格已经消失——它们被正确解释为 YAML 语言的一部分，而没有被打印出来）：

```
Agile methodology
Cloud-native app development practices
Advanced enterprise DevOps practices
```

与前面类似的是折叠块标量`>`，它与文字块标量相同，但不保留行结束。这对于您想要在单行上打印的非常长的字符串很有用，但又想要为了可读性的目的将其跨多行包装在代码中。考虑我们示例的以下变化：

```
Specialty: >
  Agile methodology
  Cloud-native app development practices
  Advanced enterprise DevOps practices
```

现在，如果我们要打印这个，我们会看到以下内容：

```
Agile methodologyCloud-native app development practicesAdvanced enterprise DevOps practices
```

我们可以在前面的示例中添加尾随空格，以防止单词之间相互重叠，但我在这里没有这样做，因为我想为您提供一个易于解释的例子。

当您审查 playbooks、变量文件等时，您会看到这些结构一次又一次地被使用。尽管定义简单，但它们非常重要——缩进级别的遗漏或列表项开头缺少`-`实例都会导致整个 playbook 无法运行。正如我们发现的，您可以将所有这些不同的结构组合在一起。以下代码块中提供了一个`variables`文件的额外示例供您考虑，其中显示了我们已经涵盖的各种示例：

```
---
servers:
  - frontend
  - backend
  - database
  - cache
employees:
  - name: daniel
    fullname: Daniel Oh
    role: DevOps Evangelist
    level: Expert
    skills:
      - Kubernetes
      - Microservices
      - Ansible
      - Linux Container
  - name: michael
    fullname: Michael Smiths
    role: Enterprise Architect
    level: Advanced
    skills:
      - Cloud
      - Middleware
      - Windows
      - Storage
    Speciality: |
      Agile methodology
      Cloud-native app development practices
      Advanced enterprise DevOps practices
```

您还可以用缩写形式表示字典和列表，称为**流集合**。以下示例显示了与我们原始的`employees`变量文件完全相同的数据结构：

```
--- employees: [{"fullname": "Daniel Oh","level": "Expert","name": "daniel","role": "DevOps Evangelist","skills": ["Kubernetes","Microservices","Ansible","Linux Container"]},{"fullname": "Michael Smiths","level": "Advanced","name": "michael","role": "Enterprise Architect","skills":["Cloud","Middleware","Windows","Storage"]}]
```

尽管这显示了完全相同的数据结构，但您可以看到肉眼很难阅读。在 YAML 中并不广泛使用流集合，我不建议您自己使用它们，但了解它们是很重要的。您还会注意到，尽管我们已经开始讨论 YAML 中的变量，但我们并没有表达任何变量类型。YAML 尝试根据它们包含的数据对变量类型进行假设，因此如果您想将`1.0`赋给一个变量，YAML 会假设它是一个浮点数。如果您需要将其表示为字符串（也许是因为它是一个版本号），您需要在其周围加上引号，这会导致 YAML 解析器将其解释为字符串，例如以下示例：

```
version: "2.0"
```

这完成了我们对 YAML 语言语法的介绍。现在完成了，在下一节中，让我们看看如何组织您的自动化代码以使其易于管理和整洁。

# 组织您的自动化代码

可以想象，如果您将所有所需的 Ansible 任务都写在一个庞大的 playbook 中，它将很快变得难以管理——也就是说，它将难以阅读，难以让其他人理解，并且——最重要的是——当出现问题时难以调试。Ansible 提供了许多将代码分割成可管理块的方法；其中最重要的可能是使用角色。角色（简单类比）就像传统高级编程语言中的库。我们将在第四章 *Playbooks and Roles*中更详细地讨论角色。

然而，Ansible 支持将代码分割成可管理的块的其他方法，我们将在本节简要探讨，作为本书后面更深入探讨角色的先导。

让我们举一个实际的例子。首先，我们知道我们需要为 Ansible 运行创建清单。在这种情况下，我们将创建四个虚构的服务器组，每个组包含两台服务器。我们的假设示例将包含一个前端服务器和位于两个不同地理位置的虚构应用程序的应用程序服务器。我们的清单文件将被称为`production-inventory`，示例内容如下：

```
[frontends_na_zone] 
frontend1-na.example.com 
frontend2-na.example.com [frontends_emea_zone]
frontend1-emea.example.com
frontend2-emea.example.com

[appservers_na_zone]
appserver1-na.example.com
appserver2-na.example.com

[appservers_emea_zone]
appserver1-emea.example.com
appserver2-emea.example.com
```

显然，我们可以编写一个庞大的 playbook 来处理这些不同主机上所需的任务，但正如我们已经讨论过的那样，这将是繁琐和低效的。让我们将自动化这些不同主机的任务分解成更小的 playbook：

1.  创建一个 playbook 来对特定主机组（例如`frontends_na_zone`）运行连接测试。将以下内容放入 playbook 中：

```
---
- hosts: frontends_na_zone
  remote_user: danieloh
  tasks:
    - name: simple connection test
      ping: 
```

1.  现在，尝试运行此 playbook 以针对主机（请注意，我们已配置它连接到名为`danieloh`的清单系统上的远程用户，因此您需要创建此用户并设置适当的 SSH 密钥，或者更改 playbook 中`remote_user`行中的用户）。在设置身份验证后运行 playbook 时，您应该会看到类似以下的输出：

```
$ ansible-playbook -i production-inventory frontends-na.yml

PLAY [frontends_na_zone] *******************************************************

TASK [Gathering Facts] *********************************************************
ok: [frontend1-na.example.com]
ok: [frontend2-na.example.com]

TASK [simple connection test] **************************************************
ok: [frontend1-na.example.com]
ok: [frontend2-na.example.com]

PLAY RECAP *********************************************************************
frontend1-na.example.com : ok=2 changed=0 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
frontend2-na.example.com : ok=2 changed=0 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0 
```

1.  现在，让我们通过创建一个只在应用服务器上运行的 playbook 来扩展我们的简单示例。同样，我们将使用 Ansible 的`ping`模块来执行连接测试，但在实际情况下，您可能会执行更复杂的任务，比如安装软件包或修改文件。指定此 playbook 针对`appservers_emea_zone`清单中的主机组运行。将以下内容添加到 playbook 中：

```
---
- hosts: appservers_emea_zone
  remote_user: danieloh
  tasks:
    - name: simple connection test
      ping: 
```

与以前一样，您需要确保可以访问这些服务器，因此要么创建`danieloh`用户并设置对该帐户的身份验证，要么更改示例 playbook 中的`remote_user`行。完成这些操作后，您应该能够运行 playbook，并且会看到类似以下的输出：

```
$ ansible-playbook -i production-inventory appservers-emea.yml

PLAY [appservers_emea_zone] ****************************************************

TASK [Gathering Facts] *********************************************************
ok: [appserver2-emea.example.com]
ok: [appserver1-emea.example.com]

TASK [simple connection test] **************************************************
ok: [appserver2-emea.example.com]
ok: [appserver1-emea.example.com]

PLAY RECAP *********************************************************************
appserver1-emea.example.com : ok=2 changed=0 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
appserver2-emea.example.com : ok=2 changed=0 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
```

1.  到目前为止，一切都很好。然而，现在我们有两个需要手动运行的 playbook，只涉及到我们清单中的两个主机组。如果我们想要处理所有四个组，我们需要创建总共四个 playbook，所有这些都需要手动运行。这几乎不符合最佳的自动化实践。如果有一种方法可以将这些单独的 playbook 合并在一个顶级 playbook 中一起运行呢？这将使我们能够分割我们的代码以保持可管理性，但在运行 playbook 时也可以防止大量的手动工作。幸运的是，我们可以通过利用`import_playbook`指令在一个名为`site.yml`的顶级 playbook 中实现这一点：

```
---
- import_playbook: frontend-na.yml
- import_playbook: appserver-emea.yml
```

现在，当您使用（现在已经熟悉的）`ansible-playbook`命令运行这个单个 playbook 时，您会发现效果与我们实际上连续运行两个 playbook 的效果相同。这样，即使在我们探索角色的概念之前，您也可以看到 Ansible 支持将您的代码分割成可管理的块，而无需手动运行每个块：

```
$ ansible-playbook -i production-inventory site.yml

PLAY [frontends_na_zone] *******************************************************

TASK [Gathering Facts] *********************************************************
ok: [frontend2-na.example.com]
ok: [frontend1-na.example.com]

TASK [simple connection test] **************************************************
ok: [frontend1-na.example.com]
ok: [frontend2-na.example.com]

PLAY [appservers_emea_zone] ****************************************************

TASK [Gathering Facts] *********************************************************
ok: [appserver2-emea.example.com]
ok: [appserver1-emea.example.com]

TASK [simple connection test] **************************************************
ok: [appserver2-emea.example.com]
ok: [appserver1-emea.example.com]

PLAY RECAP *********************************************************************
appserver1-emea.example.com : ok=2 changed=0 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
appserver2-emea.example.com : ok=2 changed=0 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
frontend1-na.example.com : ok=2 changed=0 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
frontend2-na.example.com : ok=2 changed=0 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
```

在地理多样化的环境中，您可以做的远不止我们这里的简单示例，因为我们甚至还没有涉及将变量放入清单中的事情（例如，将不同的参数与不同的环境关联）。我们将在第三章中更详细地探讨这个问题，*定义您的清单*。

然而，希望这已经为您提供了足够的知识，以便您可以开始对如何组织 playbooks 的代码做出明智的选择。随着您完成本书的进一步章节，您将能够确定您是否希望利用角色或`import_playbook`指令（或者甚至两者都使用）作为 playbook 组织的一部分。

让我们在下一节继续进行 Ansible 的速成课程，看看配置文件和一些您可能发现有价值的关键指令。

# 探索配置文件

Ansible 的行为在一定程度上由其配置文件定义。中央配置文件（影响系统上所有用户的 Ansible 行为）可以在`/etc/ansible/ansible.cfg`找到。然而，这并不是 Ansible 寻找其配置的唯一位置；事实上，它将从顶部到底部查找以下位置。

文件的第一个实例是它将使用的配置；所有其他实例都将被忽略，即使它们存在：

1.  `ANSIBLE_CONFIG`：由此环境变量的值指定的文件位置，如果设置

1.  `ansible.cfg`：在当前工作目录

1.  `~/.ansible.cfg`：在用户的主目录中

1.  `/etc/ansible/ansible.cfg`：我们之前提到的中央配置

如果您通过`yum`或`apt`等软件包管理器安装了 Ansible，您几乎总是会在`/etc/ansible`中找到名为`ansible.cfg`的默认配置文件。但是，如果您从源代码构建了 Ansible 或通过`pip`安装了它，则中央配置文件将不存在，您需要自己创建。一个很好的起点是参考包含在源代码中的示例 Ansible 配置文件，可以在 GitHub 上找到其副本，网址为[`raw.githubusercontent.com/ansible/ansible/devel/examples/ansible.cfg`](https://raw.githubusercontent.com/ansible/ansible/devel/examples/ansible.cfg)。

在本节中，我们将详细介绍如何定位 Ansible 的运行配置以及如何操作它。大多数通过软件包安装 Ansible 的人发现，在修改默认配置之前，他们可以在很多情况下使用 Ansible，因为它经过精心设计，可以在许多场景中工作。然而，重要的是要了解一些关于配置 Ansible 的知识，以防您在环境中遇到只能通过修改配置来更改的问题。

显然，如果您没有安装 Ansible，探索其配置就没有意义，因此让我们通过发出以下命令来检查您是否已安装并运行 Ansible（所示的输出是在撰写时安装在 macOS 上的最新版本的 Ansible 的输出）：

```
$ ansible 2.9.6
  config file = None
  configured module search path = ['/Users/james/.ansible/plugins/modules', '/usr/share/ansible/plugins/modules']
  ansible python module location = /usr/local/Cellar/ansible/2.9.6_1/libexec/lib/python3.8/site-packages/ansible
  executable location = /usr/local/bin/ansible
  python version = 3.8.2 (default, Mar 11 2020, 00:28:52) [Clang 11.0.0 (clang-1100.0.33.17)]
```

让我们开始探索 Ansible 提供的默认配置：

1.  以下代码块中的命令列出了 Ansible 支持的当前配置参数。这非常有用，因为它告诉您可以用来更改设置的环境变量（请参阅`env`字段），以及可以使用的配置文件参数和部分（请参阅`ini`字段）。其他有价值的信息，包括默认配置值和配置的描述，也会给出（请参阅`default`和`description`字段）。所有信息均来自`lib/constants.py`。运行以下命令来探索输出：

```
$ ansible-config list 
```

以下是您将看到的输出的示例。当然，它有很多页面，但这里只是一个片段示例：

```
$ ansible-config list
ACTION_WARNINGS:
  default: true
  description:
  - By default Ansible will issue a warning when received from a task action (module
    or action plugin)
  - These warnings can be silenced by adjusting this setting to False.
  env:
  - name: ANSIBLE_ACTION_WARNINGS
  ini:
  - key: action_warnings
    section: defaults
  name: Toggle action warnings
  type: boolean
  version_added: '2.5'
AGNOSTIC_BECOME_PROMPT:
  default: true
  description: Display an agnostic become prompt instead of displaying a prompt containing
    the command line supplied become method
  env:
  - name: ANSIBLE_AGNOSTIC_BECOME_PROMPT
  ini:
  - key: agnostic_become_prompt
    section: privilege_escalation
  name: Display an agnostic become prompt
  type: boolean
  version_added: '2.5'
  yaml:
    key: privilege_escalation.agnostic_become_prompt
.....
```

1.  如果您想看到所有可能的配置参数以及它们的当前值的简单显示（无论它们是从环境变量还是配置文件中的一个配置的），您可以运行以下命令：

```
$ ansible-config dump 
```

输出显示了所有配置参数（以环境变量格式），以及当前的设置。如果参数配置为其默认值，则会告诉您（请参阅每个参数名称后的`(default)`元素）：

```
$ ansible-config dump
ACTION_WARNINGS(default) = True
AGNOSTIC_BECOME_PROMPT(default) = True
ALLOW_WORLD_READABLE_TMPFILES(default) = False
ANSIBLE_CONNECTION_PATH(default) = None
ANSIBLE_COW_PATH(default) = None
ANSIBLE_COW_SELECTION(default) = default
ANSIBLE_COW_WHITELIST(default) = ['bud-frogs', 'bunny', 'cheese', 'daemon', 'default', 'dragon', 'elephant-in-snake', 'elephant', 'eyes', 'hellokitty', 'kitty', 'luke-koala', 'meow', 'milk', 'moofasa', 'moose', 'ren', 'sheep', 'small', 'stegosaurus', 'stimpy', 'supermilker', 'three-eyes', 'turkey', 'turtle', 'tux', 'udder', 'vader-koala', 'vader', 'www']
ANSIBLE_FORCE_COLOR(default) = False
ANSIBLE_NOCOLOR(default) = False
ANSIBLE_NOCOWS(default) = False
ANSIBLE_PIPELINING(default) = False
ANSIBLE_SSH_ARGS(default) = -C -o ControlMaster=auto -o ControlPersist=60s
ANSIBLE_SSH_CONTROL_PATH(default) = None
ANSIBLE_SSH_CONTROL_PATH_DIR(default) = ~/.ansible/cp
....
```

1.  通过编辑其中一个配置参数，让我们看看这个输出的影响。通过设置环境变量来实现这一点，如下所示（此命令已在`bash` shell 中进行了测试，但对于其他 shell 可能有所不同）：

```
$ export ANSIBLE_FORCE_COLOR=True 
```

现在，让我们重新运行`ansible-config`命令，但这次让它告诉我们只有从默认值更改的参数：

```
$ ansible-config dump --only-change
ANSIBLE_FORCE_COLOR(env: ANSIBLE_FORCE_COLOR) = True
```

在这里，您可以看到`ansible-config`告诉我们，我们只更改了`ANSIBLE_FORCE_COLOR`的默认值，它设置为`True`，并且我们通过`env`变量设置了它。这非常有价值，特别是如果您必须调试配置问题。

在处理 Ansible 配置文件本身时，您会注意到它是 INI 格式，意味着它有`[defaults]`等部分，格式为`key = value`的参数，以及以`#`或`;`开头的注释。您只需要在配置文件中放置您希望从默认值更改的参数，因此，如果您想要创建一个简单的配置来更改默认清单文件的位置，它可能如下所示：

```
# Set my configuration variables
[defaults]
inventory = /Users/danieloh/ansible/hosts ; Here is the path of the inventory file
```

正如前面讨论的那样，`ansible.cfg`配置文件的可能有效位置之一是您当前的工作目录。很可能这是在您的主目录中，因此在多用户系统上，我们强烈建议您将对 Ansible 配置文件的访问权限限制为仅限于您的用户帐户。在多用户系统上保护重要配置文件时，您应该采取所有通常的预防措施，特别是因为 Ansible 通常用于配置多个远程系统，因此如果配置文件被意外损坏，可能会造成很大的损害！

当然，Ansible 的行为不仅由配置文件和开关控制，您传递给各种 Ansible 可执行文件的命令行参数也非常重要。实际上，我们已经在先前的示例中使用了其中一个——在前面的示例中，我们向您展示了如何使用`ansible.cfg`中的`inventory`参数更改 Ansible 查找清单文件的位置。然而，在本书先前介绍的许多示例中，我们使用`-i`开关覆盖了这一点。因此，让我们继续下一节，看看在运行 Ansible 时使用命令行参数的用法。

# 命令行参数

在本节中，您将学习有关使用命令行参数执行 playbook 以及如何将一些常用的参数应用到您的优势中。我们已经非常熟悉其中一个参数，即`--version`开关，我们用它来确认 Ansible 是否已安装（以及安装的版本）：

```
$ ansible 2.9.6
  config file = None
  configured module search path = ['/Users/james/.ansible/plugins/modules', '/usr/share/ansible/plugins/modules']
  ansible python module location = /usr/local/Cellar/ansible/2.9.6_1/libexec/lib/python3.8/site-packages/ansible
  executable location = /usr/local/bin/ansible
  python version = 3.8.2 (default, Mar 11 2020, 00:28:52) [Clang 11.0.0 (clang-1100.0.33.17)]
```

就像我们能够直接通过 Ansible 了解各种配置参数一样，我们也可以了解命令行参数。几乎所有的 Ansible 可执行文件都有一个`--help`选项，您可以运行它来显示有效的命令行参数。现在让我们试一试：

1.  当您执行`ansible`命令行时，您可以查看所有选项和参数。使用以下命令：

```
$ ansible --help 
```

运行上述命令时，您将看到大量有用的输出；以下代码块显示了一个示例（您可能希望将其导入到分页器中，例如`less`，以便您可以轻松阅读所有内容）：

```
$ ansible --help
usage: ansible [-h] [--version] [-v] [-b] [--become-method BECOME_METHOD] [--become-user BECOME_USER] [-K] [-i INVENTORY] [--list-hosts] [-l SUBSET] [-P POLL_INTERVAL] [-B SECONDS] [-o] [-t TREE] [-k]
               [--private-key PRIVATE_KEY_FILE] [-u REMOTE_USER] [-c CONNECTION] [-T TIMEOUT] [--ssh-common-args SSH_COMMON_ARGS] [--sftp-extra-args SFTP_EXTRA_ARGS] [--scp-extra-args SCP_EXTRA_ARGS]
               [--ssh-extra-args SSH_EXTRA_ARGS] [-C] [--syntax-check] [-D] [-e EXTRA_VARS] [--vault-id VAULT_IDS] [--ask-vault-pass | --vault-password-file VAULT_PASSWORD_FILES] [-f FORKS]
               [-M MODULE_PATH] [--playbook-dir BASEDIR] [-a MODULE_ARGS] [-m MODULE_NAME]
               pattern

Define and run a single task 'playbook' against a set of hosts

positional arguments:
  pattern host pattern

optional arguments:
  --ask-vault-pass ask for vault password
  --list-hosts outputs a list of matching hosts; does not execute anything else
  --playbook-dir BASEDIR
                        Since this tool does not use playbooks, use this as a substitute playbook directory.This sets the relative path for many features including roles/ group_vars/ etc.
  --syntax-check perform a syntax check on the playbook, but do not execute it
  --vault-id VAULT_IDS the vault identity to use
  --vault-password-file VAULT_PASSWORD_FILES
                        vault password file
  --version show program's version number, config file location, configured module search path, module location, executable location and exit
  -B SECONDS, --background SECONDS
                        run asynchronously, failing after X seconds (default=N/A)
  -C, --check don't make any changes; instead, try to predict some of the changes that may occur
  -D, --diff when changing (small) files and templates, show the differences in those files; works great with --check
  -M MODULE_PATH, --module-path MODULE_PATH
                        prepend colon-separated path(s) to module library (default=~/.ansible/plugins/modules:/usr/share/ansible/plugins/modules)
  -P POLL_INTERVAL, --poll POLL_INTERVAL
                        set the poll interval if using -B (default=15)
  -a MODULE_ARGS, --args MODULE_ARGS
                        module arguments
  -e EXTRA_VARS, --extra-vars EXTRA_VARS
                        set additional variables as key=value or YAML/JSON, if filename prepend with @
```

1.  我们可以从前面的代码中选取一个示例来扩展我们之前对`ansible`的使用；到目前为止，我们几乎完全使用它来使用`-m`和`-a`参数运行临时任务。但是，`ansible`还可以执行有用的任务，例如告诉我们清单中组的主机。我们可以使用本章前面使用的`production-inventory`文件来探索这一点：

```
$ ansible -i production-inventory --list-host appservers_emea_zone 
```

运行此命令时，您应该会看到列出`appservers_emea_zone`清单组的成员。尽管这个例子可能有点牵强，但当您开始使用动态清单文件并且不能再简单地将清单文件传输到终端以查看内容时，这个例子是非常有价值的：

```
$ ansible -i production-inventory --list-host appservers_emea_zone
  hosts (2):
    appserver1-emea.example.com
    appserver2-emea.example.com
```

`ansible-playbook`可执行文件也是如此。我们已经在本书的先前示例中看到了其中一些，并且还有更多可以做的。例如，前面我们讨论了使用`ssh-agent`来管理多个 SSH 身份验证密钥。虽然这使运行 playbook 变得简单（因为您不必向 Ansible 传递任何身份验证参数），但这并不是唯一的方法。您可以使用`ansible-playbook`的命令行参数之一来指定私有 SSH 密钥文件，如下所示：

```
$ ansible-playbook -i production-inventory site.yml --private-key ~/keys/id_rsa
```

同样，在前一节中，我们在 playbook 中指定了`remote_user`变量以便 Ansible 连接。然而，命令行参数也可以为 playbook 设置此参数；因此，我们可以完全删除`remote_user`行，并改用以下命令行字符串运行它：

```
$ ansible-playbook -i production-inventory site.yml --user danieloh
```

Ansible 的最终目标是使您的生活更简单，并从您的清单中删除单调的日常任务。因此，没有正确或错误的方法来做到这一点——您可以使用命令行参数指定您的私有 SSH 密钥，也可以使用`ssh-agent`使其可用。同样，您可以在 playbook 中放置`remote_user`行，也可以在命令行上使用`--user`参数。最终，选择权在您手中，但重要的是要考虑，如果您将 playbook 分发给多个用户，并且他们都必须记住在命令行上指定远程用户，他们是否会真的记得这样做？如果他们不这样做会有什么后果？如果`remote_user`行存在于 playbook 中，是否会使他们的生活更轻松，并且更不容易出错，因为用户帐户已在 playbook 中设置？

与 Ansible 的配置一样，您将经常使用一小部分命令行参数，而您可能永远不会接触到许多命令行参数。重要的是您知道它们的存在以及如何了解它们，并且您可以对何时使用它们做出明智的决定。让我们继续到下一节，在那里我们将更详细地查看使用 Ansible 的临时命令。

# 理解临时命令

到目前为止，我们已经在本书中看到了一些临时命令，但是为了回顾，它们是您可以使用 Ansible 运行的单个命令，利用 Ansible 模块而无需创建或保存 playbook。它们非常有用，可以在许多远程机器上执行快速的一次性任务，也可以用于测试和了解您打算在 playbook 中使用的 Ansible 模块的行为。它们既是一个很好的学习工具，也是一个快速而肮脏（因为您从不使用 playbook 记录您的工作！）的自动化解决方案。

与每个 Ansible 示例一样，我们需要一个清单来运行。让我们重用之前的`production-inventory`文件：

```
[frontends_na_zone]
frontend1-na.example.com
frontend2-na.example.com

[frontends_emea_zone]
frontend1-emea.example.com
frontend2-emea.example.com

[appservers_na_zone]
appserver1-na.example.com
appserver2-na.example.com

[appservers_emea_zone]
appserver1-emea.example.com
appserver2-emea.example.com
```

现在，让我们从可能是最快最肮脏的临时命令开始——在一组远程机器上运行原始 shell 命令。假设您想要检查 EMEA 地区所有前端服务器的日期和时间是否同步——您可以使用监控工具或手动依次登录到每台服务器并检查日期和时间来执行此操作。但是，您也可以使用 Ansible 的临时命令：

1.  运行以下临时命令，从所有`frontends_emea_zone`服务器检索当前日期和时间：

```
$ ansible -i production-inventory frontends_emea_zone -a /usr/bin/date 
```

您将看到 Ansible 忠实地依次登录到每台机器并运行`date`命令，返回当前日期和时间。您的输出将如下所示：

```
$ ansible -i production-inventory frontends_emea_zone -a /usr/bin/date
frontend1-emea.example.com | CHANGED | rc=0 >>
Sun 5 Apr 18:55:30 BST 2020
frontend2-emea.example.com | CHANGED | rc=0 >>
Sun 5 Apr 18:55:30 BST 2020
```

1.  该命令是在您登录时运行的用户帐户中运行的。您可以使用命令行参数（在前一节中讨论）作为不同的用户运行：

```
$ ansible -i production-inventory frontends_emea_zone -a /usr/sbin/pvs -u danieloh

frontend2-emea.example.com | FAILED | rc=5 >>
  WARNING: Running as a non-root user. Functionality may be unavailable.
  /run/lvm/lvmetad.socket: access failed: Permission denied
  WARNING: Failed to connect to lvmetad. Falling back to device scanning.
  /run/lock/lvm/P_global:aux: open failed: Permission denied
  Unable to obtain global lock.non-zero return code
frontend1-emea.example.com | FAILED | rc=5 >>
  WARNING: Running as a non-root user. Functionality may be unavailable.
  /run/lvm/lvmetad.socket: access failed: Permission denied
  WARNING: Failed to connect to lvmetad. Falling back to device scanning.
  /run/lock/lvm/P_global:aux: open failed: Permission denied
  Unable to obtain global lock.non-zero return code
```

1.  在这里，我们可以看到`danieloh`用户帐户没有成功运行`pvs`命令所需的权限。但是，我们可以通过添加`--become`命令行参数来解决这个问题，该参数告诉 Ansible 在远程系统上成为`root`：

```
$ ansible -i production-inventory frontends_emea_zone -a /usr/sbin/pvs -u danieloh --become

frontend2-emea.example.com | FAILED | rc=-1 >>
Missing sudo password
frontend1-emea.example.com | FAILED | rc=-1 >>
Missing sudo password
```

1.  我们可以看到，该命令仍然失败，因为虽然`danieloh`在`/etc/sudoers`中，但是不允许以`root`身份运行命令而不输入`sudo`密码。幸运的是，有一个开关可以让 Ansible 在运行时提示我们，这意味着我们不需要编辑我们的`/etc/sudoers`文件：

```
$ ansible -i production-inventory frontends_emea_zone -a /usr/sbin/pvs -u danieloh --become --ask-become-pass
BECOME password:

frontend1-emea.example.com | CHANGED | rc=0 >>
 PV VG Fmt Attr PSize PFree
 /dev/sda2 centos lvm2 a-- <19.00g 0
frontend2-emea.example.com | CHANGED | rc=0 >>
 PV VG Fmt Attr PSize PFree
 /dev/sda2 centos lvm2 a-- <19.00g 0
```

1.  默认情况下，如果您不使用`-m`命令行参数指定模块，Ansible 会假定您想要使用`command`模块（参见[`docs.ansible.com/ansible/latest/modules/command_module.html`](https://docs.ansible.com/ansible/latest/modules/command_module.html)）。如果您希望使用特定模块，可以在命令行参数中添加`-m`开关，然后在`-a`开关下指定模块参数，如下例所示：

```
$ ansible -i production-inventory frontends_emea_zone -m copy -a "src=/etc/yum.conf dest=/tmp/yum.conf"
frontend1-emea.example.com | CHANGED => {
    "ansible_facts": {
        "discovered_interpreter_python": "/usr/bin/python"
    },
    "changed": true,
    "checksum": "e0637e631f4ab0aaebef1a6b8822a36f031f332e",
    "dest": "/tmp/yum.conf",
    "gid": 0,
    "group": "root",
    "md5sum": "a7dc0d7b8902e9c8c096c93eb431d19e",
    "mode": "0644",
    "owner": "root",
    "size": 970,
    "src": "/root/.ansible/tmp/ansible-tmp-1586110004.75-208447517347027/source",
    "state": "file",
    "uid": 0
}
frontend2-emea.example.com | CHANGED => {
    "ansible_facts": {
        "discovered_interpreter_python": "/usr/bin/python"
    },
    "changed": true,
    "checksum": "e0637e631f4ab0aaebef1a6b8822a36f031f332e",
    "dest": "/tmp/yum.conf",
    "gid": 0,
    "group": "root",
    "md5sum": "a7dc0d7b8902e9c8c096c93eb431d19e",
    "mode": "0644",
    "owner": "root",
    "size": 970,
    "src": "/root/.ansible/tmp/ansible-tmp-1586110004.75-208447517347027/source",
    "state": "file",
    "uid": 0
} 
```

前面的输出不仅显示了成功将复制到两个主机的操作，还显示了`copy`模块的所有输出值。这在以后开发 playbook 时非常有帮助，因为它使您能够准确了解模块的工作原理以及在需要进一步处理输出的情况下产生的输出。然而，这是一个更高级的话题，超出了本章的范围。

您还会注意到，传递给模块的所有参数都必须用引号括起来（`"`）。所有参数都被指定为`key=value`对，`key`和`value`之间不应添加空格（例如，`key = value`是不可接受的）。如果您需要在一个参数值周围放置引号，可以使用反斜杠字符进行转义（例如，`-a "src=/etc/yum.conf dest=\"/tmp/yum file.conf\""`）

到目前为止，我们执行的所有示例都非常快速，但这并不总是计算任务的情况。当您需要长时间运行操作时，比如超过两个小时，您应该考虑将其作为后台进程运行。在这种情况下，您可以异步运行命令，并稍后确认执行的结果。

例如，要在后台异步执行`sleep 2h`，并设置超时为 7,200 秒（`-B`），并且不进行轮询（`-P`），请使用以下命令：

```
$ ansible -i production-inventory frontends_emea_zone -B 7200 -P 0 -a "sleep 2h"
frontend1-emea.example.com | CHANGED => {
    "ansible_facts": {
        "discovered_interpreter_python": "/usr/bin/python"
    },
    "ansible_job_id": "537978889103.8857",
    "changed": true,
    "finished": 0,
    "results_file": "/root/.ansible_async/537978889103.8857",
    "started": 1
}
frontend2-emea.example.com | CHANGED => {
    "ansible_facts": {
        "discovered_interpreter_python": "/usr/bin/python"
    },
    "ansible_job_id": "651461662130.8858",
    "changed": true,
    "finished": 0,
    "results_file": "/root/.ansible_async/651461662130.8858",
    "started": 1
}
```

请注意，此命令的输出为每个主机上的每个任务提供了唯一的作业 ID。现在假设我们想要查看第二个前端服务器上的任务进展。只需从您的 Ansible 控制机发出以下命令：

```
$ ansible -i production-inventory frontend2-emea.example.com -m async_status -a "jid=651461662130.8858"
frontend2-emea.example.com | SUCCESS => {
    "ansible_facts": {
        "discovered_interpreter_python": "/usr/bin/python"
    },
    "ansible_job_id": "651461662130.8858",
    "changed": false,
    "finished": 0,
    "started": 1
} 
```

在这里，我们可以看到作业已经开始但尚未完成。如果我们现在终止我们发出的`sleep`命令并再次检查状态，我们可以看到以下内容：

```
$ ansible -i production-inventory frontend2-emea.example.com -m async_status -a "jid=651461662130.8858"
frontend2-emea.example.com | FAILED! => {
 "ansible_facts": {
 "discovered_interpreter_python": "/usr/bin/python"
 },
 "ansible_job_id": "651461662130.8858",
 "changed": true,
 "cmd": [
 "sleep",
 "2h"
 ],
 "delta": "0:03:16.534212",
 "end": "2020-04-05 19:18:08.431258",
 "finished": 1,
 "msg": "non-zero return code",
 "rc": -15,
 "start": "2020-04-05 19:14:51.897046",
 "stderr": "",
 "stderr_lines": [],
 "stdout": "",
 "stdout_lines": []
}
```

在这里，我们看到了一个`FAILED`状态的结果，因为`sleep`命令被终止；它没有干净地退出，并返回了一个`-15`的代码（请参阅`rc`参数）。当它被终止时，没有输出被发送到`stdout`或`stderr`，但如果有的话，Ansible 会捕获它并在前面的代码中显示它，这将有助于您调试失败。还包括了许多其他有用的信息，包括任务实际运行的时间、结束时间等。同样，当任务干净地退出时，也会返回有用的输出。

这就结束了我们对 Ansible 中的临时命令的介绍。到目前为止，您应该对 Ansible 的基本原理有了相当扎实的掌握，但还有一件重要的事情我们还没有看到，即使我们简要提到过——变量以及如何定义它们。我们将在下一节继续讨论这个问题。

# 定义变量

在本节中，我们将介绍变量的主题以及如何在 Ansible 中定义它们。您将逐步学习变量应该如何定义，并了解如何在 Ansible 中使用它们。

尽管自动化消除了以前手动任务中的大部分重复，但并非每个系统都是相同的。如果两个系统在某些细微的方式上不同，您可以编写两个独特的 playbook——一个用于每个系统。然而，这将是低效和浪费的，随着时间的推移也很难管理（例如，如果一个 playbook 中的代码发生了变化，您如何确保它在第二个变体中得到更新？）。

同样，您可能需要在一个系统中使用另一个系统的值——也许您需要获取数据库服务器的主机名并使其可用于另一个系统。所有这些问题都可以通过变量来解决，因为它们允许相同的自动化代码以参数变化的方式运行，以及将值从一个系统传递到另一个系统（尽管这必须小心处理）。

让我们开始实际看一下在 Ansible 中定义变量。

Ansible 中的变量应具有格式良好的名称，符合以下规则：

+   变量的名称只能包含字母、下划线和数字，不允许包含空格。

+   变量的名称只能以字母开头，可以包含数字，但不能以数字开头。

例如，以下是良好的变量名称：

+   `external_svc_port`

+   `internal_hostname_ap1`

然而，以下示例都是无效的，不能使用：

+   `appserver-zone-na`

+   `cache server ip`

+   `dbms.server.port`

+   `01appserver`

如在*学习 YAML 语法*部分中讨论的，变量可以以字典结构定义，例如以下方式。所有值都以键值对的形式声明：

```
region:
  east: app
  west: frontend
  central: cache
```

为了从前面的字典结构中检索特定字段，您可以使用以下任一表示法：

```
# bracket notation
region['east']

# dot notation
region.east
```

有一些例外情况；例如，如果变量名以两个下划线开头和结尾（例如`__variable__`），或包含已知的公共属性，您应该使用`括号表示法`：

+   `as_integer_ratio`

+   `symmetric_difference`

您可以在[`docs.ansible.com/ansible/latest/user_guide/playbooks_variables.html#creating-valid-variable-names`](https://docs.ansible.com/ansible/latest/user_guide/playbooks_variables.html#creating-valid-variable-names)找到更多信息。

当定义主机变量时，这种字典结构是有价值的；尽管在本章的早些时候，我们使用了一个定义为 Ansible `variables`文件的虚构员工记录集，但您可以使用它来指定一些`redis`服务器参数等内容：

```
---
redis:
  - server: cacheserver01.example.com
    port: 6379
    slaveof: cacheserver02.example.com

```

然后，这些可以通过您的 playbook 应用，并且一个通用的 playbook 可以用于所有`redis`服务器，而不管它们的配置如何，因为可变的参数，如`port`和`master`服务器都包含在变量中。

您还可以直接在 playbook 中传递设置变量，并将它们传递给您调用的角色。例如，以下 playbook 代码调用了四个假设的角色，并且每个角色为`username`变量分配了不同的值。这些角色可以用于在服务器上设置各种管理角色（或多个服务器），每个角色都传递一个不断变化的用户名列表，因为公司的人员来来去去：

```
roles:
  - role: dbms_admin
    vars:
      username: James
  - role: system_admin
    vars:
      username: John
  - role: security_amdin
    vars:
      username: Rock
  - role: app_admin
    vars:
      username: Daniel
```

要从 playbook 中访问变量，只需将变量名放在引号括号中。考虑以下示例 playbook（基于我们之前的`redis`示例）：

```
---
- name: Display redis variables
  hosts: all

  vars:
    redis:
      server: cacheserver01.example.com
      port: 6379
      slaveof: cacheserver02.example.com

  tasks:
    - name: Display the redis port
      debug:
        msg: "The redis port for {{ redis.server }} is {{ redis.port }}"
```

在这里，我们在 playbook 中定义了一个名为`redis`的变量。这个变量是一个字典，包含了一些对我们的服务器可能很重要的参数。为了访问这些变量的内容，我们使用花括号对它们进行配对（如前面所述），并且整个字符串被引号括起来，这意味着我们不必单独引用这些变量。如果您在本地机器上运行 playbook，您应该会看到以下输出：

```
$ ansible-playbook -i localhost, redis-playbook.yml

PLAY [Display redis variables] *************************************************

TASK [Gathering Facts] *********************************************************
ok: [localhost]

TASK [Display the redis port] **************************************************
ok: [localhost] => {
 "msg": "The redis port for cacheserver01.example.com is 6379"
}

PLAY RECAP *********************************************************************
localhost : ok=2 changed=0 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
```

尽管我们在这里访问这些变量以在调试消息中打印它们，但您可以使用相同的花括号表示法将它们分配给模块参数，或者用于 playbook 需要它们的任何其他目的。

与许多语言一样，Ansible 也有特殊保留的变量，在 playbooks 中具有特定含义。在 Ansible 中，这些被称为魔术变量，您可以在[`docs.ansible.com/ansible/latest/reference_appendices/special_variables.html`](https://docs.ansible.com/ansible/latest/reference_appendices/special_variables.html)找到完整的列表。不用说，您不应该尝试使用任何魔术变量名称作为您自己的变量。您可能会遇到的一些常见的魔术变量如下：

+   `inventory_hostname`：在播放中迭代的当前主机的主机名

+   `groups`：清单中主机组的字典，以及每个组的主机成员资格

+   `group_names`：当前主机（由`inventory_hostname`指定）所属的组的列表

+   `hostvars`：清单中所有主机和分配给它们的变量的字典

例如，可以在播放中的任何时候使用`hostvars`访问所有主机的主机变量，即使您只对一个特定主机进行操作。在 playbook 中，魔术变量非常有用，您将迅速开始发现自己在使用它们，因此了解它们的存在非常重要。

您还应该注意，您可以在多个位置指定 Ansible 变量。 Ansible 具有严格的变量优先级顺序，您可以利用这一点，在优先级较低的位置设置变量的默认值，然后在播放中稍后覆盖它们。这对于各种原因都很有用，特别是当未定义的变量可能在运行 playbook 时造成混乱（甚至当 playbook 由于此原因失败时）。我们尚未讨论变量可以存储的所有位置，因此此处未给出变量优先级顺序的完整列表。

此外，它可能会在 Ansible 版本之间发生变化，因此在处理和理解变量优先级时，重要的是参考文档——请访问[`docs.ansible.com/ansible/latest/user_guide/playbooks_variables.html#variable-precedence-where-should-i-put-a-variable`](https://docs.ansible.com/ansible/latest/user_guide/playbooks_variables.html#variable-precedence-where-should-i-put-a-variable)获取更多信息。

这就结束了我们对 Ansible 中变量的简要概述，尽管我们将在本书的后续示例中再次看到它们的使用。现在让我们通过查看 Jinja2 过滤器来结束本章，它为您的变量定义增添了无限的力量。

# 理解 Jinja2 过滤器

由于 Ansible 是用 Python 编写的，它继承了一个非常有用和强大的模板引擎，称为 Jinja2。我们将在本书的后面看到模板化的概念，因此现在我们将专注于 Jinja2 的一个特定方面，即过滤器。 Jinja2 过滤器提供了一个非常强大的框架，您可以使用它来操作和转换数据。也许您有一个需要转换为小写的字符串，例如-您可以应用 Jinja2 过滤器来实现这一点。您还可以使用它来执行模式匹配、搜索和替换操作等等。有数百种过滤器供您使用，在本节中，我们希望为您提供对 Jinja2 过滤器的基本理解以及如何应用它们的实际知识，并向您展示如何获取更多关于它们的信息，如果您希望进一步探索这个主题。

值得注意的是，Jinja2 操作是在 Ansible 控制主机上执行的，只有过滤器操作的结果被发送到远程主机。这是出于设计考虑，既为了一致性，也为了尽可能减少各个节点的工作量。

让我们通过一个实际的例子来探讨这个。假设我们有一个包含一些我们想要解析的数据的 YAML 文件。我们可以很容易地从机器文件系统中读取文件，并使用`register`关键字来捕获结果（`register`捕获任务的结果并将其存储在一个变量中——在运行`shell`模块的情况下，它会捕获命令的所有输出）。

我们的 YAML 数据文件可能如下所示：

```
tags:
  - key: job
    value: developer
  - key: language
    value: java
```

现在，我们可以创建一个 playbook 来读取这个文件并注册结果，但是我们如何将其实际转换为 Ansible 可以理解和使用的变量结构呢？让我们考虑下面的 playbook：

```
---
- name: Jinja2 filtering demo 1
  hosts: localhost

  tasks:
    - copy:
        src: multiple-document-strings.yaml
        dest: /tmp/multiple-document-strings.yaml
    - shell: cat /tmp/multiple-document-strings.yaml
      register: result
    - debug:
        msg: '{{ item }}'
      loop: '{{ result.stdout | from_yaml_all | list }}'
```

`shell`模块不一定是从 playbook 所在的目录运行的，所以我们不能保证它会找到我们的`multiple-document-strings.yaml`文件。然而，`copy`模块会从当前目录中获取文件，所以可以使用它将文件复制到一个已知的位置（比如`/tmp`），以便`shell`模块从中读取文件。然后在`loop`模块中运行`debug`模块。`loop`模块用于遍历`shell`命令的所有`stdout`行，因为我们使用了两个 Jinja2 过滤器——`from_yaml_all`和`list`。

`from_yaml_all`过滤器解析源文档行为 YAML，然后`list`过滤器将解析后的数据转换为有效的 Ansible 列表。如果我们运行 playbook，我们应该能够看到 Ansible 对原始文件中的数据结构的表示。

```
$ ansible-playbook -i localhost, jinja-filtering1.yml

PLAY [Jinja2 filtering demo 1] *************************************************

TASK [Gathering Facts] *********************************************************
ok: [localhost]

TASK [copy] ********************************************************************
ok: [localhost]

TASK [shell] *******************************************************************
changed: [localhost]

TASK [debug] *******************************************************************
ok: [localhost] => (item={'tags': [{'value': u'developer', 'key': u'job'}, {'value': u'java', 'key': u'language'}]}) => {
 "msg": {
 "tags": [
 {
 "key": "job",
 "value": "developer"
 },
 {
 "key": "language",
 "value": "java"
 }
 ]
 }
}

PLAY RECAP *********************************************************************
localhost : ok=4 changed=1 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
```

正如你所看到的，我们生成了一个包含`key-value`对的字典列表。

如果这个数据结构已经存储在我们的 playbook 中，我们可以再进一步使用`items2dict`过滤器将列表转换为真正的`key: value`对，从数据结构中移除`key`和`value`项。例如，考虑下面的第二个 playbook：

```
---
- name: Jinja2 filtering demo 2
  hosts: localhost
  vars:
    tags:
      - key: job
        value: developer
      - key: language
        value: java

  tasks:
    - debug:
        msg: '{{ tags | items2dict }}'
```

现在，如果我们运行这个，我们可以看到我们的数据被转换成了一组漂亮整洁的`key: value`对。

```
$ ansible-playbook -i localhost, jinja2-filtering2.yml
[WARNING]: Found variable using reserved name: tags

PLAY [Jinja2 filtering demo 2] *************************************************

TASK [Gathering Facts] *********************************************************
ok: [localhost]

TASK [debug] *******************************************************************
ok: [localhost] => {
 "msg": {
 "job": "developer",
---
 "language": "java"
 }
}

PLAY RECAP *********************************************************************
localhost : ok=2 changed=0 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
```

观察一下 playbook 顶部的警告。如果你尝试使用保留名称作为变量，Ansible 会显示警告，就像我们在这里做的一样。通常情况下，你不应该使用保留名称创建变量，但是这个例子展示了过滤器的工作原理，以及如果你做一些可能会引起问题的事情，Ansible 会尝试警告你。

在本节的早些时候，我们使用了`shell`模块来读取文件，并使用`register`将结果存储在一个变量中。这是完全可以的，虽然有点不够优雅。Jinja2 包含一系列`lookup`过滤器，其中包括读取给定文件内容的功能。让我们来看看下面的 playbook 的行为：

```
---
- name: Jinja2 filtering demo 3
  hosts: localhost
  vars:
    ping_value: "{{ lookup('file', '/etc/hosts') }}"
```

```
  tasks:
    - debug:
        msg: "ping value is {{ ping_value }}"
```

当我们运行这个时，我们可以看到 Ansible 已经为我们捕获了`/etc/hosts`文件的内容，而不需要我们像之前那样使用`copy`和`shell`模块。

```
$ ansible-playbook -i localhost, jinja2-filtering3.yml

PLAY [Jinja2 filtering demo 3] *************************************************

TASK [Gathering Facts] *********************************************************
ok: [localhost]

TASK [debug] *******************************************************************
ok: [localhost] => {
 "msg": "ping value is 127.0.0.1 localhost localhost.localdomain localhost4 localhost4.localdomain4\n::1 localhost localhost.localdomain localhost6 localhost6.localdomain6\n\n"
}

PLAY RECAP *********************************************************************
localhost : ok=2 changed=0 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
```

有许多其他过滤器可能会让你感兴趣，完整列表可以在官方的 Jinja2 文档中找到（[`jinja.palletsprojects.com/en/2.11.x/`](https://jinja.palletsprojects.com/en/2.11.x/)）。以下是一些其他示例，可以让你了解 Jinja2 过滤器可以为你实现的功能，从引用字符串到连接列表，再到获取文件的有用路径信息：

```
# Add some quotation in the shell - shell: echo {{ string_value | quote }} # Concatenate a list into a specific string
{{ list | join("$") }}

# Have the last name of a specific file path
{{  path  |  basename  }}

# Have the directory from a specific path
{{  path  |  dirname  }} # Have the directory from a specific windows path
{{  path  |  win_dirname  }} 
```

这就结束了我们对 Jinja2 过滤器的介绍。这是一个庞大的主题，值得有一本专门的书来讲解，但是，我希望这个实用指南能给你一些开始和寻找信息的指引。

# 总结

Ansible 是一个非常强大和多功能的自动化引擎，可用于各种任务。在解决 playbook 创建和大规模自动化的更复杂挑战之前，了解如何使用它的基础知识至关重要。Ansible 依赖一种称为 YAML 的语言，这是一种简单易读（和写）的语法，支持快速开发易于阅读和易于维护的代码，并从其编写的 Python 语言中继承了许多有价值的特性，包括 Jinja2 过滤器。

在本章中，您学习了使用各种 Ansible 程序的基础知识。然后，您了解了 YAML 语法以及将代码分解为可管理的块的方法，以便更容易阅读和维护。我们探讨了在 Ansible 中使用临时命令、变量定义和结构，以及如何利用 Jinja2 过滤器来操作 playbooks 中的数据。

在下一章中，我们将更深入地了解 Ansible 清单，并探索一些更高级的概念，这些概念在处理它们时可能会对您有用。

# 问题

1.  Ansible 的哪个组件允许您定义一个块以执行任务组作为 play？

A) `handler`

B) `service`

C) `hosts`

D) `tasks`

E) `name`

1.  您使用 YAML 格式的哪种基本语法来开始一个文件？

A) `###`

B) `---`

C) `%%%`

D) `===`

E) `***`

1.  真或假 - 为了解释和转换 Ansible 中的输出数据，您需要使用 Jinja2 模板。

A) True

B) False

# 进一步阅读

+   要了解更多配置变量，请转到[`docs.ansible.com/ansible/latest/reference_appendices/config.html#ansible-configuration-settings`](https://docs.ansible.com/ansible/latest/reference_appendices/config.html#ansible-configuration-settings)。
