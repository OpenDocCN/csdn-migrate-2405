# Ansible 配置管理手册（一）

> 原文：[`zh.annas-archive.org/md5/B284B07EA563637C44B0B69D722236FE`](https://zh.annas-archive.org/md5/B284B07EA563637C44B0B69D722236FE)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

自 1993 年 Mark Burgess 首次创建 CFEngine 以来，配置管理工具一直在不断发展。随着 Puppet 和 Chef 等更现代的工具的出现，现在系统管理员可以选择的工具越来越多。

Ansible 是配置管理领域中较新的工具之一。其他工具侧重于完整性和可配置性，而 Ansible 则背离了这一趋势，专注于简单性和易用性。

在这本书中，我们旨在向你展示如何从 Ansible 的 CLI 工具的起步开始，编写剧本，然后管理大型和复杂的环境。最后，我们教你如何通过编写插件来构建自己的模块，并扩展 Ansible 以添加新功能。

# 本书涵盖了什么

第一章, *开始使用 Ansible*，教你 Ansible 的基础知识，如在 Windows 和 Linux 上安装它，如何构建清单，如何使用模块，以及最重要的是如何获取帮助。

第二章, *简单剧本*，教你如何结合多个模块创建 Ansible 剧本来管理你的主机，还涵盖了一些有用的模块。

第三章, *高级剧本*，深入探讨了 Ansible 的脚本语言，并教授了更复杂的语言构造；在这里我们还解释了如何调试剧本。

第四章, *大型项目*，教你如何使用技术将 Ansible 的配置扩展到大规模部署，包括如何管理你可能用来配置系统的各种秘密。

第五章, *自定义模块*，教你如何通过编写模块和插件来扩展 Ansible 的当前功能。

# 你需要为这本书做些什么

要使用这本书，你至少需要以下内容：

+   文本编辑器

+   一台安装了 Linux 操作系统的机器

+   Python 2.6.x 或 Python 2.7.x

然而，要充分利用 Ansible，你应该有几台 Linux 机器可供管理。如果需要，你可以使用虚拟化平台模拟许多主机。要使用 Windows 模块，你需要一台要管理的 Windows 机器和一台用作控制器的 Linux 机器。

# 这本书是为谁准备的

这本书适用于想要了解 Ansible 工作原理基础的人。预期你具有如何设置和配置 Linux 机器的基础知识。在本书的部分内容中，我们涵盖了 BIND、MySQL 和其他 Linux 守护程序的配置文件；对这些的工作知识会有所帮助，但并非必需。

# 约定

在这本书中，你会发现一些文本样式，用于区分不同类型的信息。以下是一些这些样式的示例，以及它们的含义解释。

文本中的代码单词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下："这是使用 `vars_files` 指令以类似的方式完成的。"

代码块设置如下：

```
[group]
machine1
machine2
machine3
```

当我们希望引起你对代码块的特定部分的注意时，相关行或项会以粗体显示：

```
tasks:
  - name: install apache
    action: yum name=httpd state=installed

  - name: configure apache
    copy: src=files/httpd.conf dest=/etc/httpd/conf/httpd.conf
```

任何命令行输入或输出都以以下方式书写：

```
**ansible machinename -u root -k -m ping**

```

**新术语**和**重要单词**以粗体显示。你在屏幕上看到的单词，比如菜单或对话框中的单词，会在文本中以这种方式出现："点击**下一步**按钮会将你移动到下一个屏幕"。

### 注意

警告或重要提示会以以下方式显示。

### 提示

提示和技巧看起来像这样。


# 第一章：开始使用 Ansible

**Ansible**与今天可用的其他配置管理工具有很大不同。它旨在使配置几乎在各个方面都变得容易，从其简单的英语配置语法到其易于设置。您会发现，Ansible 允许您停止编写自定义配置和部署脚本，而只需简单地继续您的工作。

Ansible 只需要安装在您用来管理基础架构的机器上。它不需要在被管理机上安装客户端，也不需要在使用之前设置任何服务器基础设施。甚至在安装后几分钟内就应该能够使用，正如我们将在本章中向您展示的那样。

本章涵盖的主题如下：

+   安装 Ansible

+   配置 Ansible

+   使用 Ansible 命令行

+   使用 Ansible 管理 Windows 机器

+   如何获取帮助

# 所需的硬件和软件

你将在一台机器上使用 Ansible 命令行，我们将其称为**控制机**，并用它来配置另一台机器，我们将其称为**被管理机**。目前，Ansible 仅支持 Linux 或 OS X 控制机；然而，被管理机可以是 Linux、OS X、其他类 Unix 的机器或 Windows。Ansible 对控制机的要求不多，对被管理机的要求更少。

控制机的要求如下：

+   Python 2.6 或更高版本

+   paramiko

+   PyYAML

+   Jinja2

+   httplib2

+   基于 Unix 的操作系统

被管理机需要 Python 2.4 或更高版本和 simplejson；然而，如果您的 Python 是 2.5 或更高版本，您只需要 Python。被管理的 Windows 机器将需要打开 Windows 远程，并且需要大于 3.0 的 Windows PowerShell 版本。虽然 Windows 机器有更多的要求，但所有工具都是免费提供的，Ansible 项目甚至包括帮助您轻松设置依赖项的脚本。

# 安装方法

如果您想使用 Ansible 来管理一组现有的机器或基础架构，您可能希望使用这些系统上包含的任何软件包管理器。这意味着您将获得 Ansible 的更新，因为您的发行版更新它，这可能会滞后于其他方法几个版本。但是，这意味着您将运行经过测试的版本，可以在您使用的系统上正常工作。

如果您运行现有基础架构，但需要更新版本的 Ansible，可以通过 pip 安装 Ansible。**Pip**是一个用于管理 Python 软件和库包的工具。Ansible 发布的版本一经发布就会推送到 pip，因此如果您与 pip 保持最新，您应该始终运行最新版本。

如果你想象自己开发了很多模块，可能会贡献给 Ansible，你应该运行从源代码安装的版本。由于你将运行最新且测试最少的 Ansible 版本，可能会遇到一两个问题。

## 从您的发行版安装

大多数现代发行版都包含一个自动管理软件包依赖关系和更新的软件包管理器。这使得通过软件包管理器安装 Ansible 成为开始使用 Ansible 最简单的方法；通常只需要一个命令。它也会随着您更新您的机器而更新，尽管可能会滞后一两个版本。以下是在最常见的发行版上安装 Ansible 的命令。如果您使用其他软件包，请参考您的软件包的用户指南或您的发行版的软件包列表：

+   Fedora、RHEL、CentOS 和兼容系统：

```
**$ yum install ansible**

```

+   Ubuntu、Debian 和兼容系统：

```
**$ apt-get install ansible**

```

### 注意

请注意，RHEL 和 CentOS 需要安装 EPEL 存储库。有关 EPEL 的详细信息，包括如何安装它，可以在[`fedoraproject.org/wiki/EPEL`](https://fedoraproject.org/wiki/EPEL)找到。

如果您使用的是 Ubuntu，并希望使用最新版本而不是操作系统提供的版本，可以使用 Ansible 提供的 Ubuntu PPA。有关设置的详细信息，请访问[`launchpad.net/~ansible/+archive/ubuntu/ansible`](https://launchpad.net/~ansible/+archive/ubuntu/ansible)。

## 从 pip 安装

Pip，就像发行版的软件包管理器一样，将处理查找、安装和更新您要求的软件包及其依赖关系。这使得通过 pip 安装 Ansible 与通过软件包管理器安装一样简单。但是需要注意的是，它不会随操作系统更新。此外，更新操作系统可能会破坏您的 Ansible 安装；但是，这不太可能发生。如果您是 Python 用户，可能希望在隔离环境（虚拟环境）中安装 Ansible：这是不受支持的，因为 Ansible 尝试将其模块安装到系统中。您应该使用 pip 在系统范围内安装 Ansible。

以下是通过 pip 安装 Ansible 的命令：

```
**$ pip install ansible**

```

## 从源代码安装

从源代码安装是获取最新版本的好方法，但可能没有经过正确测试，与发布的版本不同。您还需要自行更新到新版本，并确保 Ansible 将继续与操作系统更新一起工作。要克隆`git`存储库并安装它，请运行以下命令。您可能需要 root 访问权限才能执行此操作：

```
**$ git clone git://github.com/ansible/ansible.git**
**$ cd ansible**
**$ sudo make install**

```

### 提示

**下载示例代码**

您可以从您在[`www.packtpub.com`](http://www.packtpub.com)的帐户中下载您购买的所有 Packt 图书的示例代码文件。如果您在其他地方购买了本书，可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册，以便直接通过电子邮件接收文件。

# 设置 Ansible

Ansible 需要能够获取您想要配置的机器的清单，以便对其进行管理。由于清单插件的原因，可以通过多种方式完成这一点。基本安装包含了几种不同的清单插件。我们将在本书的后面介绍这些。现在，我们将介绍简单的主机文件清单。

默认的 Ansible 清单文件名为 hosts，位于`/etc/ansible`。它的格式类似于`INI`文件。组名用方括号括起来，下面的所有内容，直到下一个组标题，都分配给该组。机器可以同时属于多个组。组用于允许您一次配置多台机器。您可以在后续示例中使用组而不是主机名作为主机模式，Ansible 将一次在整个组上运行模块。

在以下示例中，我们有一个名为`webservers`的组中的三台机器，分别是`site01`、`site02`和`site01-dr`。我们还有一个`production`组，其中包括`site01`、`site02`、`db01`和`bastion`。

```
**[webservers]**
**site01**
**site02**
**site01-dr**

**[production]**
**site01**
**site02**
**db01**
**bastion**

```

一旦您将主机放入 Ansible 清单中，就可以开始针对它们运行命令。Ansible 包括一个名为`ping`的简单模块，可让您测试自己与主机之间的连接。让我们从命令行使用 Ansible 针对我们的一台机器，以确认我们可以配置它们。

Ansible 旨在简单易用，开发人员采用的一种方式是使用 SSH 连接到受管机器。然后通过 SSH 连接发送代码并执行它。这意味着您不需要在受管机器上安装 Ansible。这也意味着 Ansible 使用与您已经用于管理机器的相同通道。这使得设置更加容易，因为在大多数情况下不需要任何设置，也不需要在防火墙中打开端口。

首先，我们使用 Ansible 的`ping`模块检查要配置的服务器的连接。该模块简单地连接到以下服务器：

```
**$ ansible site01 -u root -k -m ping**

```

这应该要求输入 SSH 密码，然后产生类似以下的结果：

```
**site01 | success >> {**
 **"changed": false,**
 **"ping": "pong"**
**}**

```

如果您为远程系统设置了 SSH 密钥，您可以省略`-k`参数以跳过提示并使用密钥。您还可以通过在清单中按主机或在全局 Ansible 配置中配置来始终使用特定用户名。

全局设置用户名，编辑`/etc/ansible/ansible.cfg`并更改在`[defaults]`部分设置`remote_user`的行。您还可以更改`remote_port`以更改 Ansible 将 SSH 到的默认端口。这将更改所有机器的默认设置，但可以在清单文件中按服务器或组的基础上进行覆盖。

要在清单文件中设置用户名，只需将`ansible_ssh_user`附加到清单中的行。例如，以下代码部分显示了一个清单，其中`site01`主机使用用户名`root`，`site02`主机使用用户名`daniel`。您还可以使用其他变量。`ansible_ssh_host`变量允许您设置不同的主机名，`ansible_ssh_port`变量允许您设置不同的端口，这在`site01-dr`主机上进行了演示。最后，`db01`主机使用用户名`fred`，并使用`ansible_ssh_private_key_file`设置了私钥。

```
**[webservers]      #1**
**site01 ansible_ssh_user=root     #2**
**site02 ansible_ssh_user=daniel      #3**
**site01-dr ansible_ssh_host=site01.dr ansible_ssh_port=65422      #4**
**[production]      #5**
**site01      #6**
**site02      #7**
**db01 ansible_ssh_user=fred ansible_ssh_private_key_file=/home/fred/.ssh.id_rsa     #8**
**bastion      #9**

```

如果您不愿意让 Ansible 直接访问受管机器上的 root 帐户，或者您的机器不允许 SSH 访问 root 帐户（例如 Ubuntu 的默认配置），您可以配置 Ansible 使用`sudo`来获取 root 访问权限。使用`sudo`的 Ansible 意味着您可以强制执行与以前相同的审计。配置 Ansible 使用`sudo`与配置端口一样简单，只是它需要在受管机器上配置`sudo`。

第一步是向`/etc/sudoers`文件添加一行；在受管节点上，如果选择使用自己的帐户，可能已经设置了这个。您可以使用`sudo`密码，也可以使用无密码`sudo`。如果决定使用密码，您将需要使用`-k`参数到 Ansible，或者在`/etc/ansible/ansible.cfg`中将`ask_sudo_pass`值设置为`true`。要使 Ansible 使用 sudo，请在命令行中添加`--sudo`。

```
**ansible site01 -s -m command -a 'id -a'**

```

如果这样做，它应该返回类似于以下内容：

```
**site01 | success | rc=0 >>**
**uid=0(root) gid=0(root) groups=0(root) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023**

```

## 在 Windows 上设置它

最近，Ansible 添加了管理 Windows 机器的功能。现在，您可以使用 Ansible 轻松管理 Windows 机器，就像管理 Linux 机器一样。

这使用 Windows PowerShell 远程工具，就像在 Linux 机器上使用 SSH 一样，远程执行模块。已添加了几个新模块，明确支持 Windows，但还为一些现有模块提供了与 Windows 管理的机器一起工作的能力。

要开始管理 Windows 机器，您必须执行一些复杂的设置。您需要按照以下步骤操作：

1.  在清单中创建一些 Windows 机器

1.  安装 Python-winrm 以允许 Ansible 连接到 Windows 机器

1.  升级到 PowerShell 3.0+以支持 Windows 模块

1.  启用 Windows 远程，以便 Ansible 可以连接

Windows 机器与清单中的所有其他机器以相同的方式创建。它们通过`ansible_connection`变量的值进行区分。当`ansible_connection`设置为`winrm`时，它将尝试通过 winrm 连接到远程计算机上的 Windows PowerShell。Ansible 还使用`ansible_ssh_user`，`ansible_ssh_pass`和`ansible_ssh_port`值，就像在其他机器上一样。尽管它们的名称中有 ssh，但它们用于提供将用于连接到 Windows PowerShell 远程服务的端口和凭据。以下是示例 Windows 机器的样子：

```
**[windows]**
**dc.ad.example.com**
**web01.ad.example.com**
**web02.ad.example.com**

**[windows:vars]**
**ansible_connection=winrm**
**ansible_ssh_user=daniel**
**ansible_ssh_pass=s3cr3t**
**ansible_ssh_port=5986**

```

出于安全原因，您可能不希望将密码存储在清单文件中。您可以通过简单地省略`ansible_ssh_user`和`ansible_ssh_pass`变量，并使用 Ansible 的`-k`和`-u`参数来让 Ansible 提示输入密码，就像我们之前为 Unix 系统展示的那样。您也可以选择将它们存储在 Ansible 保险库中，这将在本书的后面介绍。

创建清单后，您需要在控制器机器上安装 winrm Python 库。这个库将使 Ansible 能够连接到 Windows 远程管理服务并配置远程 Windows 系统。

目前，这个库还相当实验性，并且它与 Ansible 的连接并不完美，因此您必须安装与您使用的 Ansible 版本相匹配的特定版本。随着 Ansible 1.8 的发布，这应该会稍微解决一些问题。大多数发行版尚未打包该库，因此您可能希望通过 pip 安装它。作为 root 用户，您需要运行：

```
**$ pip install https://github.com/diyan/pywinrm/archive/df049454a9309280866e0156805ccda12d71c93a.zip**

```

然而，对于更新版本，您应该能够直接运行：

```
**pip install http://github.com/diyan/pywinrm/archive/master.zip**

```

这将安装与 Ansible 1.7 兼容的特定版本的 winrm。对于其他更新版本的 Ansible，您可能需要不同的版本，最终 winrm Python 库应该由不同的发行版打包。您的机器现在将能够连接到并管理 Windows 机器与 Ansible。

接下来，您需要在要管理的机器上执行一些设置步骤。其中第一步是确保您已安装了 PowerShell 3.0 或更高版本。您可以使用以下命令检查已安装的版本：

```
**$PSVersionTable.PSVersion.Major**

```

如果您收到的值不是 3 或高于 3，则需要升级您的 PowerShell 版本。您可以选择通过手动下载和安装最新的 Windows 管理框架来完成此操作，或者您可以使用 Ansible 项目提供的脚本。为了节省空间，我们将在此处解释脚本化安装；手动安装留给读者作为练习。

```
**Invoke-WebRequest https://raw.githubusercontent.com/ansible/ansible/release1.7.0/examples/scripts/upgrade_to_ps3.ps1 -OutFile upgrade_to_ps3.ps1**
**.\upgrade_to_ps3.ps1**

```

第一个命令从 GitHub 上的 Ansible 项目存储库下载升级脚本并将其保存到磁盘上。第二个命令将检测您的操作系统以下载正确版本的 Windows 管理框架并安装它。

接下来，您需要配置 Windows 远程管理服务。Ansible 项目提供了一个脚本，将自动配置 Windows 远程管理，以符合 Ansible 的预期配置方式。虽然您可以手动设置它，但强烈建议您使用此脚本，以防止错误配置。要下载并运行此脚本，请打开 PowerShell 终端并运行以下命令：

```
**Invoke-WebRequest https://raw.githubusercontent.com/ansible/ansible/release1.7.0/examples/scripts/ConfigureRemotingForAnsible.ps1 -OutFile ConfigureRemotingForAnsible.ps1**
**.\ConfigureRemotingForAnsible.ps1**

```

第一个命令从 GitHub 上的 Ansible 项目下载配置脚本，第二个命令运行它。如果一切正常，您应该从第二个脚本中收到`Ok`的输出。

现在，您应该能够连接到您的机器并使用 Ansible 对其进行配置。与之前一样，让我们运行一个 ping 命令来确认 Ansible 能够远程执行其模块。虽然 Unix 机器可以使用`ping`模块，但 Windows 机器使用`win_ping`模块。使用方式几乎完全相同；但是，由于我们已将密码添加到清单文件中，您不需要`-k`选项。

```
**$ ansible web01.ad.example.com -u daniel -m win_ping**

```

如果一切正常，您应该看到以下输出：

```
**web01.ad.example.com | success >> {**
 **"changed": false,**
 **"ping": "pong"**
**}**

```

输出表明 Ansible 能够连接到 Windows 远程管理服务，成功登录并在远程主机上执行模块。如果这个工作正常，那么您应该能够使用所有其他 Windows 模块来管理您的机器。

# Ansible 的第一步

Ansible 模块以类似于`key=value`的键值对形式接受参数，在远程服务器上执行任务，并将有关任务的信息返回为`JSON`。键值对允许模块在请求时知道该做什么。它们可以是硬编码的值，或者在 playbooks 中可以使用变量，这将在第二章中进行介绍，*简单的 Playbooks*。模块返回的数据让 Ansible 知道托管主机是否有任何更改，或者之后是否应该更改 Ansible 保存的任何信息。

模块通常在 playbooks 中运行，因为这样可以将许多模块链接在一起，但也可以在命令行上使用。之前，我们使用`ping`命令来检查 Ansible 是否已正确设置并能够访问配置的节点。`ping`模块只检查 Ansible 的核心是否能够在远程机器上运行，但实际上什么也不做。

一个稍微更有用的模块名为`setup`。该模块连接到配置的节点，收集有关系统的数据，然后返回这些值。在命令行中运行时，这对我们来说并不特别方便。但是，在 playbook 中，您可以稍后在其他模块中使用收集到的值。

要从命令行运行 Ansible，您需要传递两个参数，通常是三个。首先是要匹配要应用模块的机器的主机模式。其次，您需要提供要运行的模块的名称，以及可选的要传递给模块的参数。对于主机模式，您可以使用组名、机器名、通配符和波浪号(~)，后跟与主机名匹配的正则表达式。或者，为了表示所有这些，您可以使用单词`all`或简单地使用`*`。以这种方式在命令行上运行 Ansible 模块被称为临时的 Ansible 命令。

要在您的节点之一上运行`setup`模块，您需要以下命令行：

```
**$ ansible machinename -u root -k -m setup**

```

`setup`模块将连接到机器并返回一些有用的事实。`setup`模块本身提供的所有事实都以`ansible_`开头，以区别于变量。

该模块将在 Windows 和 Unix 机器上运行。目前，Unix 机器将提供比 Windows 机器更多的信息。但是，随着 Ansible 的新版本发布，您可以期望看到更多的 Windows 功能被包含在 Ansible 中。

```
**machinename | success >> {**
 **"ansible_facts": {**
 **"ansible_distribution": "Microsoft Windows NT 6.3.9600.0",**
 **"ansible_distribution_version": "6.3.9600.0",**
 **"ansible_fqdn": "ansibletest",**
 **"ansible_hostname": "ANSIBLETEST",**
 **"ansible_ip_addresses": [**
 **"100.72.124.51",**
 **"fe80::1fd:fc3b:1eff:350d"**
 **],**
 **"ansible_os_family": "Windows",**
 **"ansible_system": "Win32NT",**
 **"ansible_totalmem": "System.Object[]"**
 **},**
 **"changed": false**
**}**

```

以下是您将使用的最常见值的表格；并非所有这些值都适用于所有机器。特别是 Windows 机器从 setup 模块返回的数据要少得多。

| 字段 | 示例 | 描述 |
| --- | --- | --- |
| `ansible_architecture` | x86_64 | 这是托管机器的架构 |
| `ansible_distribution` | CentOS | 这是托管机器上的 Linux 或 Unix 发行版 |
| `ansible_distribution_version` | 6.3 | 这是先前发行版的版本 |
| `ansible_domain` | example.com | 这是服务器主机名的域名部分 |
| `ansible_fqdn` | machinename.example.com | 这是托管机器的完全限定域名 |
| `ansible_interfaces` | ["lo", "eth0"] | 这是机器拥有的所有接口的列表，包括环回接口 |
| `ansible_kernel` | 2.6.32-279.el6.x86_64 | 这是托管机器上安装的内核版本 |
| `ansible_memtotal_mb` | 996 | 这是托管机器上可用的总内存（以兆字节为单位） |
| `ansible_processor_count` | 1 | 这是托管机器上可用的 CPU 总数 |
| `ansible_virtualization_role` | guest | 这确定了机器是客户机还是主机机器 |
| `ansible_virtualization_type` | kvm | 这是托管机器上的虚拟化设置的类型 |

在 Unix 机器上，这些变量是使用 Python 从受控机器中收集的；如果在远程节点上安装了 facter 或 ohai，`setup`模块将执行它们并返回它们的数据。与其他事实一样，ohai 事实以`ohai_`开头，facter 事实以`facter_`开头。虽然`setup`模块在命令行上似乎不太有用，但一旦开始编写 playbooks，它就会变得有用。请注意，facter 和 ohai 在 Windows 主机上不可用。

如果 Ansible 中的所有模块都像`setup`和`ping`模块那样少，我们将无法在远程机器上进行任何更改。几乎所有 Ansible 提供的其他模块，如`file`模块，都允许我们实际配置远程机器。

`file`模块可以使用单个路径参数调用；这将导致它返回有关所讨论文件的信息。如果给它更多的参数，它将尝试更改文件的属性，并告诉您是否已更改了任何内容。Ansible 模块将告诉您是否已更改任何内容，这在编写 playbooks 时变得更加重要。

您可以调用`file`模块，如以下命令所示，以查看有关`/etc/fstab`的详细信息：

```
**$ ansible machinename -u root -k -m file -a 'path=/etc/fstab'**

```

上述命令应该引发以下响应：

```
**machinename | success >> {**
 **"changed": false,**
 **"group": "root",**
 **"mode": "0644",**
 **"owner": "root",**
 **"path": "/etc/fstab",**
 **"size": 779,**
 **"state":**
 **"file"**
**}**

```

或者，响应可能是类似以下命令以在`/tmp`中创建一个新的测试目录：

```
**$ ansible machinename -u root -k -m file -a 'path=/tmp/teststate=directory mode=0700 owner=root'**

```

上述命令应该返回类似以下内容：

```
**machinename | success >> {**
 **"changed": true,**
 **"group": "root",**
 **"mode": "0700",**
 **"owner": "root",**
 **"path": "/tmp/test",**
 **"size": 4096,**
 **"state": "directory"**
**}**

```

我们可以看到在响应中将`changed`变量设置为`true`，因为目录不存在或具有不同的属性，并且需要进行更改以使其与提供的参数给出的状态匹配。如果使用相同的参数再次运行它，`changed`的值将设置为`false`，这意味着该模块没有对系统进行任何更改。

有几个模块接受与`file`模块类似的参数，其中一个例子是`copy`模块。`copy`模块在控制器机器上获取一个文件，将其复制到受控机器，并根据需要设置属性。例如，要将`/etc/fstab`文件复制到受控机器上的`/tmp`，您将使用以下命令：

```
**$ ansible machinename -m copy -a 'src=/etc/fstab dest=/tmp/fstab'**

```

第一次运行上述命令时，应该返回类似以下内容：

```
**machinename | success >> {**
 **"changed": true,**
 **"dest": "/tmp/fstab",**
 **"group": "root",**
 **"md5sum": "fe9304aa7b683f58609ec7d3ee9eea2f",**
 **"mode": "0700",**
 **"owner": "root",**
 **"size": 637,**
 **"src": "/root/.ansible/tmp/ansible-1374060150.96- 77605185106940/source",**
 **"state": "file"**
**}**

```

还有一个名为`command`的模块，它将在受控机器上运行任意命令。这使您可以配置它以运行任意命令，例如`preprovided`安装程序或自编写脚本；它还可用于重新启动机器。请注意，此模块不在 shell 中运行命令，因此无法执行重定向、使用管道、扩展 shell 变量或后台命令。

Ansible 模块努力防止在不需要时进行更改。这被称为幂等性，并且可以使针对多个服务器运行命令变得更快。不幸的是，Ansible 无法知道您的命令是否已更改任何内容，因此为了帮助它更具幂等性，您必须给它一些帮助。它可以通过`creates`或`removes`参数来实现。如果给出`creates`参数，如果文件名参数存在，则不会运行命令。`removes`参数则相反；如果文件名存在，则会运行命令。

您可以按以下方式运行该命令：

```
**$ ansible machinename -m command -a 'rm -rf /tmp/testing removes=/tmp/testing'**

```

如果没有名为`/tmp/testing`的文件或目录，则命令输出将指示它已被跳过，如下所示：

```
**machinename | skipped**

```

否则，如果文件存在，它将如下所示的代码：

```
**ansibletest | success | rc=0 >>**

```

通常最好使用`command`模块的替代模块。其他模块提供更多选项，并且可以更好地捕捉它们所在的问题领域。例如，在这种情况下，使用`file`模块比使用`command`模块要少得多，因为如果状态设置为`absent`，`file`模块将递归删除某些内容。因此，前面的命令等同于以下命令：

```
**$ ansible machinename -m file -a 'path=/tmp/testing state=absent'**

```

如果您需要在运行命令时使用通常在 shell 中可用的功能，您将需要`shell`模块。这样您就可以使用重定向、管道或作业后台。您可以使用可执行参数选择要使用的 shell。您可以按以下方式使用`shell`模块：

```
**$ ansible machinename -m shell -a '/opt/fancyapp/bin/installer.sh >/var/log/fancyappinstall.log creates=/var/log/fancyappinstall.log'**

```

# 模块帮助

不幸的是，我们没有足够的空间来涵盖 Ansible 中可用的每个模块；幸运的是，Ansible 包含一个名为`ansible-doc`的命令，可以检索帮助信息。所有包含在 Ansible 中的模块都有这些数据；然而，对于从其他地方收集的模块，您可能会找到更少的帮助。`ansible-doc`命令还允许您查看可用的所有模块列表。

要获取可用模块的列表以及每种类型的简短描述，请使用以下命令：

```
**$ ansible-doc -l**

```

要查看特定模块的帮助文件，将其作为`ansible-doc`的单个参数提供。例如，要查看`file`模块的帮助信息，请使用以下命令：

```
**$ ansible-doc file**

```

# 总结

在本章中，我们已经介绍了选择安装类型以安装 Ansible 以及如何构建清单文件以反映您的环境。之后，我们看到了如何以临时方式使用 Ansible 模块来执行简单任务。最后，我们讨论了如何了解系统上可用的模块以及如何使用命令行获取使用模块的说明。

在下一章中，您将学习如何在 playbook 中一起使用多个模块。这使您能够执行比单个模块更复杂的任务。


# 第二章：简单的 Playbooks

Ansible 可以作为一个命令行工具来进行小的更改。然而，它真正的力量在于其脚本能力。在设置机器时，我们几乎总是需要一次做多件事情。Ansible 使用名为**playbook**的概念来实现这一点。使用 playbooks，我们可以一次执行多个操作，并跨多个系统执行。它们提供了一种编排部署、确保一致的配置，或者简单执行常见任务的方式。

Playbooks 以**YAML**形式表示，大部分情况下，Ansible 使用标准的 YAML 解析器。这意味着我们在编写 playbooks 时可以使用 YAML 的所有功能。例如，我们可以在 playbook 中使用与 YAML 相同的注释系统。playbook 的许多行也可以用 YAML 数据类型编写和表示。有关更多信息，请参阅[`www.yaml.org/`](http://www.yaml.org/)。

Playbooks 还开启了许多机会。它们允许我们将状态从一个命令传递到另一个命令。例如，我们可以在一台机器上获取文件的内容，将其注册为变量，然后在另一台机器上使用该值。这使我们能够创建复杂的部署机制，这是仅使用 Ansible 命令无法实现的。此外，由于每个模块都试图是幂等的，我们应该能够多次运行 playbook，只有在需要时才会进行更改。

执行 playbook 的命令是`ansible-playbook`。它接受类似于 Ansible 命令行工具的参数。例如，`-k`（`--ask-pass`）和`-K`（`--ask-sudo`）会让 Ansible 分别提示输入 SSH 和 sudo 密码；`-u`可以用来设置 SSH 连接的用户名。然而，这些选项也可以在 playbook 的目标部分内设置。例如，要使用名为`example-play.yml`的 play，我们可以使用以下命令：

```
**$ ansible-playbook example-play.yml**

```

Ansible playbooks 由一个或多个 play 组成。一个 play 包括三个部分：

+   **目标部分**定义了 play 将在哪些主机上运行以及如何运行。这是我们设置 SSH 用户名和其他 SSH 相关设置的地方。

+   **变量部分**定义了在运行 play 时将可用的变量。

+   **任务部分**按照我们希望 Ansible 运行的顺序列出了所有模块。

我们可以在单个 YAML 文件中包含尽可能多的 play。YAML 文件以`---`开头，并包含许多键值和列表。在 YAML 中，行缩进用于指示变量嵌套给解析器，这也使文件更易于阅读。

一个完整的 Ansible play 示例如下代码片段所示：

```
---
- hosts: webservers
  user: root
  vars:
    apache_version: 2.6
    motd_warning: 'WARNING: Use by ACME Employees ONLY'
    testserver: yes
  tasks:
    - name: setup a MOTD
      copy:
        dest: /etc/motd
        content: "{{ motd_warning }}"
```

在接下来的几个部分中，我们将逐一检查每个部分，并详细解释它们的工作原理。

# 目标部分

目标部分看起来像以下代码片段：

```
- hosts: webservers
  user: root
```

这是一个非常简单的版本，但在大多数情况下可能是我们所需要的。每个 play 都存在于一个列表中。根据 YAML 语法，行必须以破折号开头。play 将要运行的主机必须在`hosts`的值中设置。这个值使用与使用 Ansible 命令行选择主机时相同的语法，我们在上一章中讨论过。Ansible 的主机模式匹配功能也在上一章中讨论过。在下一行中，用户告诉 Ansible playbook 要连接到机器的用户。

在这个部分中，我们可以提供的其他行如下：

| 名称 | 描述 |
| --- | --- |
| `sudo` | 如果要让 Ansible 在连接到 play 中的机器后使用`sudo`成为 root 用户，则将其设置为`yes`。 |
| `user` | 这定义了最初连接到机器的用户名，在配置了`sudo`之前。 |
| `sudo_user` | 这是 Ansible 将尝试使用`sudo`成为的用户。例如，如果我们将`sudo`设置为`yes`，`user`设置为`daniel`，将`sudo_user`设置为`kate`将导致 Ansible 在登录后使用`sudo`从`daniel`到`kate`。如果您在交互式 SSH 会话中执行此操作，我们可以在以`daniel`登录时使用`sudo -u kate`。 |
| `connection` | 这允许我们告诉 Ansible 要使用什么传输来连接到远程主机。我们将主要使用`ssh`或`paramiko`来连接远程主机。但是，当在`localhost`上运行时，我们也可以使用`local`来避免连接开销。大多数情况下，我们将在这里使用`local`、`winrm`或`ssh`。 |
| `gather_facts` | 除非我们告诉它不要这样做，否则 Ansible 将自动在远程主机上运行 setup 模块。如果我们不需要来自 setup 模块的变量，我们可以现在设置这个并节省一些时间。 |

# 变量部分

在这里，我们可以定义适用于所有机器上整个 play 的变量。我们还可以让 Ansible 提示变量，如果它们没有在命令行上提供。这使我们可以轻松地维护 play，并防止我们在 play 的几个部分中更改相同的内容。这也使我们可以将整个 play 的整个配置存储在顶部，这样我们可以轻松阅读和修改它，而不用担心 play 的其余部分。

play 中的这一部分变量可以被机器事实（由模块设置的事实）覆盖，但它们本身会覆盖我们在清单中设置的事实。因此，它们用于定义我们可能在稍后的模块中收集的默认值，但不能用于保留清单变量的默认值，因为它们将覆盖这些默认值。

变量声明发生在`vars`部分，看起来像目标部分中的值，并包含一个 YAML 字典或列表。一个例子看起来像以下代码片段：

```
vars:
  apache_version: 2.6
  motd_warning: 'WARNING: Use by ACME Employees ONLY'
  testserver: yes
```

变量也可以通过给 Ansible 提供要加载的变量文件列表来从外部 YAML 文件中加载。这是通过使用`vars_files`指令以类似的方式完成的。然后简单地提供另一个包含自己的字典的 YAML 文件的名称。这意味着，我们可以将变量存储和分发分开，从而可以与他人共享我们的 playbook。

使用`vars_files`，在我们的 playbook 中，文件看起来像以下代码片段：

```
vars_files:
  conf/country-AU.yml
  conf/datacenter-SYD.yml
  conf/cluster-mysql.yml
```

在前面的例子中，Ansible 会在与 playbook 路径相关的`conf`文件夹中查找`country-AU.yml`、`datacenter-SYD.yml`和`cluster-mysql.yml`。每个 YAML 文件看起来类似于以下代码片段：

```
---
ntp: ntp1.au.example.com
TZ: Australia/Sydney
```

最后，我们可以让 Ansible 与用户交互地询问每个变量。当我们有不希望用于自动化的变量，并且需要人工输入时，这是很有用的。一个有用的例子是提示输入用于解密 HTTPS 服务器的秘密密钥的密码短语。

我们可以使用以下代码片段指示 Ansible 提示变量：

```
vars_prompt:
  - name: https_passphrase
    prompt: Key Passphrase
    private: yes
```

在前面的例子中，`https_passphrase`是输入数据将被存储的地方。用户将被提示输入`Key Passphrase`，因为`private`设置为`yes`，所以当用户输入时，值不会在屏幕上显示。

我们可以使用`{{ variablename }}`来使用变量、事实和清单变量。我们甚至可以使用点表示法引用复杂的变量，比如字典。例如，一个名为`httpd`的变量，其中有一个名为`maxclients`的键，将被访问为`{{ httpd.maxclients }}`。这也适用于来自 setup 模块的事实。例如，我们可以使用`{{ ansible_eth0.ipv4.address }}`来获取名为`eth0`的网络接口的 IPv4 地址。

在变量部分设置的变量在同一 playbook 中的不同 play 之间不会保留。但是，由 setup 模块收集的事实或由`set_fact`设置的事实会保留。这意味着如果我们在同一台机器上运行第二个 play，或者在较早的 play 中运行机器的子集，我们可以在目标部分将`gather_facts`设置为`false`。`setup`模块有时可能需要一段时间才能运行，因此这可以显著加快 play 的速度，特别是在将串行设置为较低值的 play 中。

# 任务部分

任务部分是每个剧本的最后部分。它包含我们希望 Ansible 按照我们希望的顺序执行的操作列表。我们可以用几种风格来表达每个模块的参数。我们建议您尽可能坚持一种风格，并仅在必要时使用其他风格。这样可以使我们的 playbooks 更容易阅读和维护。以下代码片段展示了任务部分的三种风格：

```
tasks:
  - name: install apache
    action: yum name=httpd state=installed

  - name: configure apache
    copy: src=files/httpd.conf dest=/etc/httpd/conf/httpd.conf

  - name: restart apache
    service:
      name: httpd
      state: restarted
```

在这里，我们看到了三种不同的语法风格被用来在 CentOS 机器上安装、配置和启动 Apache web 服务器。第一个任务向我们展示了如何使用原始语法安装 Apache，这需要我们在`action`关键字内部首先调用模块。第二个任务使用了第二种风格，将 Apache 的配置文件复制到指定位置。在这种风格中，使用模块名称代替`action`关键字，其值简单地成为其参数。最后，第三种风格的最后一个任务展示了如何使用服务模块来重新启动 Apache。在这种风格中，我们像往常一样使用模块名称作为关键字，但我们将参数作为 YAML 字典提供。当我们向单个模块提供大量参数时，或者模块需要以复杂形式提供参数时，这种风格会很有用，比如云形成模块。后一种风格正在迅速成为编写 playbooks 的首选方式，因为越来越多的模块需要复杂的参数。在本书中，我们将使用这种风格，以节省示例的空间并防止行换行。

请注意，任务不需要名称。但是，它们可以成为良好的文档，并且在需要时允许我们稍后引用每个任务。当运行 playbook 时，名称也会输出到控制台，以便用户了解发生了什么。如果我们不提供名称，Ansible 将只使用任务或处理程序的动作行。

### 注意

与其他配置管理工具不同，Ansible 不提供完整的依赖系统。这既是一种福音也是一种诅咒；有了完整的依赖系统，我们可能永远不确定对特定机器将应用哪些更改。然而，Ansible 确保我们的更改将按照它们编写的顺序执行。因此，如果一个模块依赖于在其之前执行的另一个模块，只需在 playbook 中将一个放在另一个之前即可。

# 处理程序部分

处理程序部分在语法上与任务部分相同，并支持调用模块的相同格式。只有当调用处理程序的任务在执行过程中记录到有变化发生时，处理程序才会被调用。要触发处理程序，向任务添加一个 notify 关键字，其值设置为任务的名称。

当 Ansible 完成任务列表的运行时，处理程序将在先前触发时运行。它们按照处理程序部分中列出的顺序运行，即使它们在任务部分中被多次调用，它们也只会运行一次。这经常用于在升级和配置后重新启动守护程序。以下 play 演示了我们将如何将**ISC** **DHCP**（动态主机配置协议）服务器升级到最新版本、配置它并设置它在启动时启动。如果这个 playbook 在 ISC DHCP 守护程序已经运行最新版本并且配置文件没有改变的服务器上运行，处理程序将不会被调用，DHCP 也不会被重新启动。例如，考虑以下代码：

```
---
- hosts: dhcp
  tasks:
  - name: update to latest DHCP
    yum
      name: dhcp
      state: latest
    notify: restart dhcp

  - name: copy the DHCP config
    copy:
      src: dhcp/dhcpd.conf
      dest: /etc/dhcp/dhcpd.conf
    notify: restart dhcp

  - name: start DHCP at boot
    service:
      name: dhcpd
      state: started
      enabled: yes

  handlers:
  - name: restart dhcp
    service:
      name: dhcpd
      state: restarted
```

每个处理程序只能是一个单独的模块，但我们可以从单个任务中通知一系列处理程序。这使我们能够从任务列表中的单个步骤触发许多处理程序。例如，如果我们刚刚检出了任何 Django 应用的更新版本，我们可以设置一个处理程序来迁移数据库，部署静态文件并重新启动 Apache。我们可以通过在通知操作上简单使用 YAML 列表来实现这一点。这可能看起来像以下代码片段：

```
---
- hosts: qroud
  tasks:
  - name: checkout Qroud
    git:
      repo:git@github.com:smarthall/Qroud.git
      dest: /opt/apps/Qroud force=no
    notify:
      - migrate db
      - generate static
      - restart httpd

  handlers:
  - name: migrate db
    command: ./manage.py migrate –all
    args:
      chdir: /opt/apps/Qroud

  - name: generate static
    command: ./manage.py collectstatic -c –noinput
    args:
       chdir: /opt/apps/Qroud

  - name: restart httpd
    service:
      name: httpd
      state: restarted
```

我们可以看到`git`模块用于检出一些公共 GitHub 代码，如果导致任何更改，它会触发`migrate db`、`generate static`和`restart httpd`操作。

# playbook 模块

在 playbooks 中使用模块与在命令行中使用模块有一些不同。这主要是因为我们可以从先前的模块和`setup`模块中获得许多事实。某些模块在 Ansible 命令行中无法工作，因为它们需要访问这些变量。其他模块在命令行版本中可以工作，但在 playbook 中使用时可以提供增强功能。

## 模板模块

`template`模块是一个需要 Ansible 提供事实的最常用的模块之一。该模块允许我们设计配置文件的大纲，然后让 Ansible 在正确的位置插入值。为了实现这一点，Ansible 使用 Jinja2 模板语言。实际上，Jinja2 模板可以比这更复杂，包括条件语句、`for`循环和宏等内容。以下是一个用于配置 BIND 的 Jinja2 配置模板的示例：

```
# {{ ansible_managed }}
options {
  listen-on port 53 {
    127.0.0.1;
    {% for ip in ansible_all_ipv4_addresses %}
      {{ ip }};
    {% endfor %}
  };
  listen-on-v6 port 53 { ::1; };
  directory       "/var/named";
  dump-file       "/var/named/data/cache_dump.db";
  statistics-file "/var/named/data/named_stats.txt";
  memstatistics-file "/var/named/data/named_mem_stats.txt";
};

zone "." IN {
  type hint;
  file "named.ca";
};

include "/etc/named.rfc1912.zones";
include "/etc/named.root.key";

{# Variables for zone config #}
{% if 'authorativenames' in group_names %}
  {% set zone_type = 'master' %}
  {% set zone_dir = 'data' %}
{% else %}
  {% set zone_type = 'slave' %}
  {% set zone_dir = 'slaves' %}
{% endif %}

zone "internal.example.com" IN {
  type {{ zone_type }};
  file "{{ zone_dir }}/internal.example.com";
  {% if 'authorativenames' not in group_names %}
    masters { 192.168.2.2; };
  {% endif %}
};
```

按照惯例，Jinja2 模板的文件扩展名为`.j2`；然而，这并不是严格要求的。现在让我们将这个示例分解成其各个部分。示例从以下代码行开始：

```
# {{ ansible_managed }}
```

这一行在文件顶部添加了一个注释，显示文件来自哪个模板、主机、模板的修改时间和所有者。将这些作为注释放在模板中是一个好的做法，它确保人们知道如果他们希望永久更改它们应该编辑什么。

稍后，在第五行，有一个`for`循环：

```
    {% for ip in ansible_all_ipv4_addresses %}
      {{ ip }};
    {% endfor %}
```

`For`循环会遍历列表中的所有元素，每个元素遍历一次。它们可以选择将项目分配给我们选择的变量，以便我们可以在循环内部使用它。这个循环遍历`ansible_all_ipv4_addresses`中的所有值，这是由`setup`模块提供的一个列表，其中包含主机的所有 IPv4 地址。在`for`循环内部，它简单地将它们中的每一个添加到配置中，以确保 BIND 将在该接口上监听。

在第 24 行的模板中也可以添加注释。

```
{# Variables for zone config #}
```

在`{#`和`#}`之间的任何内容都会被 Jinja2 模板处理器忽略。这使我们可以在模板中添加注释，而这些注释不会出现在最终文件中。如果我们正在做一些复杂的事情，在模板中设置变量，或者配置文件不允许注释，这是特别方便的。

接下来的几行是`if`语句的一部分，为模板后面的使用设置了`zone_type`和`zone_dir`变量：

```
{% if 'authorativenames' in group_names %}
  {% set zone_type = 'master' %}
  {% set zone_dir = 'data' %}
{% else %}
  {% set zone_type = 'slave' %}
  {% set zone_dir = 'slaves' %}
{% endif %}
```

在`{% if %}`和`{% else %}`之间的任何内容，如果`if`标签中的语句为`false`，则会被忽略。在这里，我们检查值`authorativenames`是否在适用于此主机的组名称列表中。如果是`true`，则下面的两行将设置两个自定义变量。`zone_type`设置为 master，`zone_dir`设置为 data。如果此主机不在`authorativenames`组中，则`zone_type`和`zone_dir`将分别设置为`slave`和`slaves`。

最后，从第 33 行开始，我们提供了区域的实际配置：

```
zone "internal.example.com" IN {
  type {{ zone_type }};
  file "{{ zone_dir }}/internal.example.com";
  {% if zone_type == 'slave' %}
    masters { 192.168.2.2; };
  {% endif %}
};
```

我们将类型设置为我们之前创建的`zone_type`变量，并将位置设置为`zone_dir`。最后，我们检查区域类型是否为从属，如果是，我们将其主配置为特定的 IP 地址。

要使此模板设置权威名称服务器，我们需要在清单文件中创建一个名为`authorativenames`的组，并在其中添加一些主机。如何做到这一点在第一章中已经讨论过，*开始使用 Ansible*。

我们可以简单地调用`templates`模块和机器的事实将被发送，包括机器所在的组。这就像调用任何其他模块一样简单。`template`模块还接受类似`copy`模块的参数，如 owner、group 和 mode。例如考虑以下代码：

```
---
- name: Setup BIND
  host: allnames
  tasks:
  - name: configure BIND
    template: src=templates/named.conf.j2 dest=/etc/named.conf owner=root group=named mode=0640
```

## set_fact 模块

`set_fact`模块允许我们在 Ansible play 中在机器上构建自己的事实。然后可以在模板中使用这些事实或作为 playbook 中的变量。事实就像来自`setup`模块等模块的参数一样，它们是基于每个主机的。我们应该使用这个来避免将复杂的逻辑放入模板中。例如，如果我们试图配置一个缓冲区以占用内存的一定百分比，我们应该在 playbook 中计算该值。

以下示例显示了如何使用`set_fact`来配置 MySQL 服务器，使其具有大约机器上可用总内存的一半的 InnoDB 缓冲区大小：

```
---
- name: Configure MySQL
  hosts: mysqlservers
  tasks:
  - name: install MySql
    yum:
      name: mysql-server
      state: installed

  - name: Calculate InnoDB buffer pool size
    set_fact:
      innodb_buffer_pool_size_mb="{{ansible_memtotal_mb/2}}"

  - name: Configure MySQL
    template:
      src: templates/my.cnf.j2
      dest: /etc/my.cnf
      owner: root
      group: root
      mode: 0644
    notify: restart mysql

  - name: Start MySQL
    service:
      name: mysqld
      state: started
      enabled: yes

  handlers:
  - name: restart mysql
    service:
      name: mysqld
      state: restarted
```

这里的第一个任务只是使用 yum 安装 MySQL。第二个任务通过获取受管机器的总内存，除以二，去除任何非整数余数，并将其放入名为`innodb_buffer_pool_size_mb`的事实中。然后下一行将一个模板加载到`/etc/my.cnf`中以配置 MySQL。最后，启动 MySQL 并设置为在启动时启动。还包括一个处理程序，以在其配置更改时重新启动 MySQL。

然后模板只需要获取`innodb_buffer_pool_size`的值并将其放入配置中。这意味着我们可以在缓冲池应该是内存的五分之一或八分之一的地方重复使用相同的模板，并简单地更改那些主机的 playbook。在这种情况下，模板将看起来像以下代码片段：

```
# {{ ansible_managed }}
[mysqld]
datadir=/var/lib/mysql
socket=/var/lib/mysql/mysql.sock
# Disabling symbolic-links is recommended to prevent assorted security risks
symbolic-links=0
# Settings user and group are ignored when systemd is used.
# If we need to run mysqld under a different user or group,
# customize our systemd unit file for mysqld according to the
# instructions in http://fedoraproject.org/wiki/Systemd

# Configure the buffer pool
innodb_buffer_pool_size = {{ innodb_buffer_pool_size_mb|default(128) }}M

[mysqld_safe]
log-error=/var/log/mysqld.log
pid-file=/var/run/mysqld/mysqld.pid
```

我们可以看到在前面的模板中，我们只是将 play 中获取的变量放入模板中。如果模板没有看到`innodb_buffer_pool_size_mb`事实，它将简单地使用默认值`128`。

## 暂停模块

`pause`模块停止 playbook 的执行一段时间。我们可以配置它等待一段特定的时间，或者我们可以让它提示用户继续。当从 Ansible 命令行使用时实际上是无用的，但在 playbook 中使用时非常方便。

通常，当我们希望用户确认后继续，或者在特定点需要手动干预时，会使用`pause`模块。例如，如果我们刚刚将新版本的 Web 应用部署到服务器上，并且需要用户手动检查以确保它看起来正常，然后再配置它们接收生产流量之前，我们可以在那里设置一个暂停。它还可以方便地警告用户可能出现的问题，并给他们继续的选项。这将使 Ansible 打印出服务器的名称，并要求用户按*Enter*键继续。如果与目标部分中的 serial 键一起使用，它将针对 Ansible 正在运行的每组主机询问一次。这样，我们可以让用户以自己的节奏运行部署，同时他们可以交互式地监视进度。

不太有用的是，此模块可以简单地等待指定的一段时间。这并不总是有用，因为通常我们不知道特定操作可能需要多长时间，猜测可能会产生灾难性的结果。我们不应该用它来等待网络守护程序启动；相反，我们应该使用`wait_for`模块（在下一节中描述）来执行此任务。以下播放首先演示了在用户交互模式和定时模式中使用`pause`模块：

```
---
- hosts: localhost
  tasks:
  - name: wait on user input
    pause:
      prompt: "Warning! Press ENTER to continue or CTRL-C to quit."

  - name: timed wait
    pause:
      seconds: 30
```

## wait_for 模块

`wait_for`模块用于轮询特定的 TCP 端口，并且直到该端口接受远程连接后才继续执行。轮询是从远程机器进行的。如果我们只提供一个端口，或者将主机参数设置为`localhost`，则轮询将尝试连接到受控机器。我们可以利用`local_action`从控制器机器运行命令，并使用`ansible_hostname`变量作为我们的主机参数，使其尝试从控制器机器连接到受控机器。

此模块特别适用于需要一段时间才能启动的守护程序，或者我们希望在后台运行的事物。Apache Tomcat 附带一个 init 脚本，当我们尝试启动它时，它会立即返回，使 Tomcat 在后台启动。根据 Tomcat 配置加载的应用程序，它可能需要 2 秒到 10 分钟不等的时间才能完全启动并准备好接受连接。我们可以计时应用程序的启动并使用`pause`模块。然而，下一次部署可能需要更长或更短的时间，这将破坏我们的部署机制。使用`wait_for`模块，我们可以让 Ansible 识别 Tomcat 何时准备好接受连接。以下是一个执行此操作的播放：

```
---
- hosts: webapps
  tasks:
  - name: Install Tomcat
    yum:
      name: tomcat7
      state: installed

  - name: Start Tomcat
    service:
      name: tomcat7
      state: started

  - name: Wait for Tomcat to start
    wait_for:
      port: 8080
      state: started
```

在此播放完成后，Tomcat 应该已安装、启动并准备好接受请求。我们可以在此示例中追加更多模块，并依赖于 Tomcat 可用并监听。

## assemble 模块

`assemble`模块将受控机器上的多个文件组合在一起，并将它们保存到受控机器上的另一个文件中。在 playbooks 中，当我们有一个`config`文件不允许包含或在其包含中使用通配符时，这是有用的。对于例如 root 用户的`authorized_keys`文件非常有用。以下播放将发送一堆 SSH 公钥到受控机器，然后让它将它们全部组合在一起并放置在 root 用户的主目录中：

```
---
- hosts: all
  tasks:
  - name: Make a Directory in /opt
    file:
      path: /opt/sshkeys
      state: directory
      owner: root
      group: root
      mode: 0700

  - name: Copy SSH keys over
    copy:
      src: "keys/{{ item }}.pub"
      dest: "/opt/sshkeys/{{ item }}.pub"
      owner: root
      group: root
      mode: 0600
    with_items:
      - dan
      - kate
      - mal

  - name: Make the root users SSH config directory
    file:
      path: /root/.ssh
      state: directory
      owner: root
      group: root
      mode: 0700

  - name: Build the authorized_keys file
    assemble:
      src: /opt/sshkeys
      dest: /root/.ssh/authorized_keys
      owner: root
      group: root
      mode: 0700
```

到目前为止，这一切应该看起来很熟悉。我们可能会注意到任务中的`with_items`键以及`{{ items }}`变量。这些将在第三章中稍后解释，但现在我们需要知道的是，我们提供给`with_items`键的任何项目都将替换为`{{ items }}`变量，类似于`for`循环的工作方式。这简单地让我们一次轻松地将多个文件复制到远程主机。

最后一个任务展示了`assemble`模块的用法。我们将包含要连接到输出中的文件的目录作为`src`参数传递，然后将`dest`作为输出文件传递。它还接受许多创建文件的其他模块相同的参数（`owner`、`group`和`mode`）。它还按照`ls -1`命令列出的顺序组合文件。这意味着我们可以使用与`udev`和`rc.d`相同的方法，并在文件前面添加数字，以确保它们以正确的顺序结束。

## add_host 模块

`add_host`模块是 playbook 中可用的最强大的模块之一。`add_host`让我们可以在 play 中动态添加新的机器。我们可以使用`uri`模块从我们的**配置管理数据库**（**CMDB**）中获取主机，然后将其添加到当前 play 中。该模块还会将我们的主机添加到一个组中，如果该组尚不存在，则动态创建该组。

该模块简单地接受`name`和`groups`参数，这些参数相当不言自明，并设置主机名和组。我们还可以发送额外的参数，这些参数的处理方式与清单文件中的额外值的处理方式相同。这意味着我们可以设置`ansible_ssh_user`、`ansible_ssh_port`等。

如果我们使用云提供商，如 RackSpace 或 Amazon EC2，Ansible 中有可用的模块可以让我们管理计算资源。如果我们找不到它们在清单中，我们可能会决定在 play 开始时创建机器。如果我们这样做，我们可以使用此模块将机器添加到清单中，以便稍后对其进行配置。以下是使用 Google Compute 模块执行此操作的示例：

```
---
- name: Create infrastructure
  hosts: localhost
  connection: local
  tasks:
    - name: Make sure the mailserver exists
      gce:
        image: centos-6
        name: mailserver
        tags: mail
        zone: us-central1-a
      register: mailserver
      when: '"mailserver" not in groups.all'

    - name: Add new machine to inventory
      add_hosts:
        name: mailserver
        ansible_ssh_host: "{{ mailserver.instance_data[0].public_ip }}"
        groups: tag_mail
      when: not mailserver|skipped
```

## group_by 模块

除了在 play 中动态创建主机，我们还可以创建组。`group_by`模块可以根据关于机器的事实创建组，包括我们使用之前解释的`add_fact`模块设置的事实。`group_by`模块接受一个参数`key`，它接受机器将被添加到的组的名称。通过将其与变量的使用结合起来，我们可以使模块根据其操作系统、虚拟化技术或我们可以访问的任何其他事实将服务器添加到组中。然后我们可以在任何后续 play 的目标部分或模板中使用此组。

因此，如果我们想创建一个根据操作系统对主机进行分组的组，我们将调用该模块如下：

```
---
- name: Create operating system group
  hosts: all
  tasks:
    - group_by: key=os_{{ ansible_distribution }}

- name: Run on CentOS hosts only
  hosts: os_CentOS
  tasks:
  - name: Install Apache
    yum: name=httpd state=latest

- name: Run on Ubuntu hosts only
  hosts: os_Ubuntu
  tasks:
  - name: Install Apache
    apt: pkg=apache2 state=latest
```

然后我们可以使用这些组来使用正确的打包程序安装软件包。在实践中，这经常用于避免 Ansible 在执行时输出大量的“跳过”消息。我们可以创建一个组，用于应该发生操作的机器，而不是为每个需要跳过的任务添加`when`子句，然后使用一个单独的 play 来单独配置这些机器。以下是在不使用`when`子句的情况下在 Debian 和 RedHat 机器上安装 ssl 私钥的示例：

```
---
- name: Catergorize hosts
  hosts: all
  tasks:
    - name: Gather hosts by OS
      group_by:
        key: "os_{{ ansible_os_family }}"

- name: Install keys on RedHat
  hosts: os_RedHat
  tasks:
    - name: Install SSL certificate
      copy:
        src: sslcert.pem
        dest: /etc/pki/tls/private/sslcert.pem

- name: Install keys on Debian
  hosts: os_Debian
  tasks:
    - name: Install SSL certificate
      copy:
        src: sslcert.pem
        dest: /etc/ssl/private/sslcert.pem
```

## slurp 模块

`slurp`模块从远程系统抓取文件，使用 base 64 对其进行编码，然后返回结果。我们可以利用 register 关键字将内容放入事实中。在使用`slurp`模块获取文件时，我们应该注意文件大小。该模块将整个文件加载到内存中，因此使用`slurp`处理大文件可能会消耗所有可用的 RAM 并导致系统崩溃。文件还需要从受控机器传输到控制器机器，对于大文件，这可能需要相当长的时间。

将此模块与复制模块结合使用可以在两台机器之间复制文件。这在以下 playbook 中进行了演示：

```
---
- name: Fetch a SSH key from a machine
  hosts: bastion01
  tasks:
    - name: Fetch key
      slurp:
        src: /root/.ssh/id_rsa.pub
      register: sshkey

- name: Copy the SSH key to all hosts
  hosts: all
  tasks:
    - name: Make directory for key
      file:
        state: directory
        path: /root/.ssh
        owner: root
        group: root
        mode: 0700

    - name: Install SSH key
      copy:
        contents: "{{ hostvars.bastion01.sshkey|b64decode }}"
        dest: /root/.ssh/authorized_keys
        owner: root
        group: root
        mode: 0600
```

### 注意

请注意，由于`slurp`模块使用 base 64 对数据进行编码，因此我们必须使用名为`b64decode`的 jinja2 过滤器来在复制模块使用数据之前对数据进行解码。过滤器将在第三章*高级 Playbooks*中进行更详细的介绍。

# Windows playbook modules

Windows 支持是 Ansible 的新功能，因此没有为其提供许多模块。仅适用于 Windows 的模块以`win_`开头命名。还有一些可用的模块，可以在 Windows 和 Unix 系统上使用，例如我们之前介绍的`slurp`模块。

在 Windows 模块中，需要特别注意引用路径字符串。反斜杠是 YAML 中的重要字符，它们用于转义字符，并且在 Windows 路径中，它们表示目录。因此，YAML 可能会将我们路径的某些部分误解为转义序列。为了防止这种情况，我们在字符串上使用单引号。此外，如果我们的路径本身是一个目录，我们应该省略尾随的反斜杠，以便 YAML 不会将字符串的结尾误解为转义序列。如果我们必须以反斜杠结尾，那么将其变为双反斜杠，第二个将被忽略。以下是一些正确和不正确的字符串示例：

```
# Correct
'C:\Users\Daniel\Documents\secrets.txt'
'C:\Program Files\Fancy Software Inc\Directory'
'D:\\' # \\ becomes \
# Incorrect
"C:\Users\Daniel\newcar.jpg" # \n becomes a new line
'C:\Users\Daniel\Documents\' # \' becomes '
```

# 云基础设施模块

基础设施模块不仅允许我们管理机器的设置，还允许我们创建这些机器本身。除此之外，我们还可以自动化围绕它们的大部分基础设施。这可以作为对亚马逊云形成等服务的简单替代。

在创建我们希望在同一 playbook 中的后续 play 中管理的机器时，我们将希望使用`add_hosts`模块将机器添加到内存中的清单中，以便它可以成为进一步 play 的目标。我们可能还希望运行`group_by`模块，将它们排列成我们将其他机器排列的组。还应该使用`wait_for`模块来检查机器是否响应 SSH 连接，然后再尝试管理它。

云基础设施模块可能有点复杂，因此我们将展示如何设置和安装 Amazon 模块。有关如何配置其他模块的详细信息，请参阅其文档，使用`ansible-doc`。

## AWS 模块

AWS 模块的工作方式类似于大多数 AWS 工具的工作方式。这是因为它们使用了流行的 python **boto**库，该库与许多其他工具一起使用，并遵循了亚马逊发布的原始 AWS 工具的约定。

最好以与我们安装 Ansible 相同的方式安装 boto。对于大多数用例，我们将在托管的机器上运行模块，因此我们只需要在那里安装 boto 模块。我们可以以以下方式安装 boto 库：

+   Centos/RHEL/Fedora: `yum install python-boto`

+   Ubuntu: `apt-get install python-boto`

+   Pip: `pip install boto`

然后我们需要设置正确的环境变量。最简单的方法是在本地机器上使用 localhost 连接运行模块。如果我们这样做，那么我们的 shell 中的变量将被传递并自动可用于 Ansible 模块。这里是 boto 库用于连接到 AWS 的变量：

| 变量名 | 描述 |
| --- | --- |
| `AWS_ACCESS_KEY` | 这是有效 IAM 帐户的访问密钥 |
| `AWS_SECRET_KEY` | 这是对应于上面访问密钥的秘密密钥 |
| `AWS_REGION` | 这是默认区域，除非被覆盖 |

我们可以使用以下代码在我们的示例中设置这些环境变量：

```
export AWS_ACCESS_KEY="AKIAIOSFODNN7EXAMPLE"
export AWS_SECRET_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
export AWS_REGION="us-east-1"
```

这些只是示例凭据，不起作用。一旦我们设置好这些，我们就可以使用 AWS 模块。在下一段代码中，我们将结合本章的几个模块来创建一个机器并将其添加到清单中。以下示例中使用了一些尚未讨论的功能，比如`register`和`delegate_to`，这些将在第三章 *高级 Playbooks*中介绍：

```
---
- name: Setup an EC2 instance
  hosts: localhost
  connection: local
  tasks:
    - name: Create an EC2 machine
      ec2:
        key_name: daniel-keypair
        instance_type: t2.micro
        image: ami-b66ed3de
        wait: yes
        group: webserver
        vpc_subnet_id: subnet-59483
        assign_public_ip: yes
      register: newmachines

    - name: Wait for SSH to start
      wait_for:
        host: "{{ newmachines.instances[0].public_ip }}"
        port: 22
        timeout: 300
      delegate_to: localhost

    - name: Add the machine to the inventory
      add_host:
        hostname: "{{ newmachines.instances[0].public_ip }}"
        groupname: new

- name: Configure the new machines
  hosts: new
  sudo: yes
  tasks:
    - name: Install a MOTD
      template:
        src: motd.j2
        dest: /etc/motd
```

# 总结

在本章中，我们介绍了 playbook 文件中可用的部分。我们还学习了如何使用变量使我们的 playbooks 易于维护，如何在进行更改时触发处理程序，最后，我们看了一下在 playbook 中使用某些模块时更有用的一些模块。您可以使用官方文档进一步探索 Ansible 提供的模块，网址为[`docs.ansible.com/modules_by_category.html`](http://docs.ansible.com/modules_by_category.html)。

在下一章中，我们将深入研究 playbooks 的更复杂功能。这将使我们能够构建更复杂的 playbooks，能够部署和配置整个系统。


# 第三章：高级 playbooks

到目前为止，我们看到的 playbooks 都很简单，只是按顺序运行了一些模块。Ansible 允许更多地控制 playbook 的执行。使用以下技术，你应该能够执行甚至最复杂的部署：

+   并行运行操作

+   循环

+   条件执行

+   任务委派

+   额外变量

+   使用变量查找文件

+   环境变量

+   外部数据查找

+   存储数据

+   处理数据

+   调试 playbooks

# 并行运行操作

默认情况下，Ansible 最多只会分叉五次，因此一次只会在五台不同的机器上运行一个操作。如果你有大量的机器，或者你已经降低了最大分叉值，那么你可能希望异步启动任务。Ansible 执行此操作的方法是启动任务，然后轮询以等待其完成。这允许 Ansible 在所有所需的机器上启动作业，同时仍然使用最大分叉。

要并行运行操作，请使用`async`和`poll`关键字。`async`关键字触发 Ansible 并行运行任务，并且它的值将是 Ansible 等待命令完成的最长时间。`poll`的值表示 Ansible 轮询检查命令是否已完成的频率。

如果你想要在整个机群上运行`updatedb`，代码可能如下所示：

```
- hosts: all
  tasks:
    - name: Install mlocate
      yum: name=mlocate state=installed

    - name: Run updatedb
      command: /usr/bin/updatedb
      async: 300
      poll: 10
```

当你在超过五台机器上运行前面的例子时，你会注意到`yum`模块的行为与`command`模块不同。`yum`模块将在前五台机器上运行，然后在下一个五台机器上运行，依此类推。然而，`command`模块将在所有机器上运行，并在完成后指示状态。

如果你的命令启动了最终监听端口的守护进程，你可以启动它而不轮询，这样 Ansible 就不会检查它是否完成。然后你可以继续其他操作，并稍后使用`wait_for`模块检查完成情况。要配置 Ansible 不等待任务完成，将`poll`的值设置为`0`。

最后，如果你的任务运行时间非常长，你可以告诉 Ansible 等待任务完成的时间。为此，将`async`的值设置为`0`。

在以下情况下，你将想要使用 Ansible 的轮询：

+   你有一个可能会超时的长时间任务

+   你需要在大量机器上运行一个操作

+   你有一个不需要等待完成的操作

还有一些情况，你不应该使用`async`或`poll`：

+   如果你的任务获取了锁，阻止其他任务运行

+   你的任务只需要很短的时间运行

# 循环

Ansible 允许你多次重复使用一个模块，例如，如果你有几个应该设置相似权限的文件。这可以节省大量重复工作，并允许你迭代 facts 和 variables。

为此，你可以在操作上使用`with_items`关键字，并将值设置为你要迭代的项目列表。这将为模块创建一个名为`item`的变量，该变量将被设置为模块迭代时依次设置的每个项目。一些模块，如`yum`，将对此进行优化，以便它们不会为每个软件包执行单独的事务，而是一次性操作所有软件包。

使用`with_items`，代码如下：

```
tasks:
- name: Secure config files file:
    path: "/etc/{{ item }}"
    mode: 0600
    owner: root
    group: root with_items: - my.cnf - shadow - fstab
```

除了循环固定的项目或变量之外，Ansible 还为我们提供了一个称为**lookup 插件**的工具。这些插件允许你告诉 Ansible 从外部某处获取数据。例如，你可能想要找到所有匹配特定模式的文件，然后上传它们。

在这个例子中，我们上传目录中的所有公钥，然后将它们组合成 root 用户的`authorized_keys`文件，如下例所示：

```
tasks: - name: Make key directory file:
    path: /root/.sshkeys
    ensure: directory
    mode: 0700
    owner: root
    group: root - name: Upload public keys copy:
    src: "{{ item }}"
    dest: /root/.sshkeys
    mode: 0600
    owner: root
    group: root with_fileglob: - keys/*.pub - name: Assemble keys into authorized_keys file assemble:
    src: /root/.sshkeys
    dest: /root/.ssh/authorized_keys
    mode: 0600
    owner: root
    group: root
```

可以在以下情况下使用重复模块：

+   多次重复使用相似设置的模块

+   迭代列表的所有值

+   使用`assemble`模块创建许多文件，以便将其合并为一个大文件以供以后使用

+   与`with_fileglob`查找插件结合使用时，复制文件目录

# 条件执行

某些模块（例如`copy`模块）提供了配置以跳过模块执行的机制。您还可以配置自己的跳过条件，只有在解析为`true`时才执行模块。如果您的服务器使用不同的打包系统或具有不同的文件系统布局，则这可能很方便。它还可以与`set_fact`模块一起使用，以允许您计算许多不同的事情。

要跳过一个模块，您可以使用`when`键；这让您可以提供一个条件。如果您设置的条件解析为 false，则将跳过该模块。您分配给`when`的值是 Python 表达式。您可以在此时使用任何可用的变量或事实。

### 注意

如果要根据条件处理列表中的某些项目，只需使用`when`子句。`when`子句将单独处理列表中的每个项目；正在处理的项目可作为变量使用`{{ item }}`。

以下代码是一个示例，显示如何在 Debian 和 Red Hat 系统上选择`apt`和`yum`之间的选择。

```
---
- name: Install VIM
  hosts: all
  tasks:
    - name: Install VIM via yum
      yum:
        name: vim-enhanced
        state: installed
      when: ansible_os_family == "RedHat"

    - name: Install VIM via apt
      apt:
        name: vim
        state: installed
      when: ansible_os_family == "Debian"

    - name: Unexpected OS family
      debug:
        msg: "OS Family {{ ansible_os_family }} is not supported"
        fail: yes
      when: ansible_os_family != "RedHat" and ansible_os_family != "Debian"
```

还有第三个子句，用于打印消息并在未识别操作系统时失败。

### 注意

此功能可用于在特定点暂停，并等待用户干预以继续。通常，当 Ansible 遇到错误时，它将简单地停止正在进行的操作，而不运行任何处理程序。使用此功能，您可以添加`pause`模块，并在其中设置一个条件，以在意外情况下触发。这样，`pause`模块将在正常情况下被忽略；但是，在意外情况下，它将允许用户干预，并在安全时继续。任务将如下所示：

```
name: pause for unexpected conditions
pause: prompt="Unexpected OS"
when: ansible_os_family != "RedHat"
```

跳过操作有许多用途；以下是其中一些：

+   解决操作系统之间的差异

+   提示用户，然后执行他们请求的操作

+   通过避免不会改变任何内容但可能需要一段时间才能执行的模块来提高性能

+   拒绝更改具有特定文件的系统

+   检查自定义脚本是否已运行

# 任务委派

默认情况下，Ansible 会在配置的机器上同时运行其任务。当您有一堆单独的机器需要配置时，或者每台机器负责向其他远程机器通信其状态时，这非常有用。但是，如果您需要在与 Ansible 操作的主机不同的主机上执行操作，可以使用委派。

Ansible 可以配置为在除正在配置的主机之外的其他主机上运行任务，使用`delegate_to`键。模块仍将为每台机器运行一次，但是不会在目标机器上运行，而是在委派的主机上运行。可用的事实将适用于当前主机。在这里，我们展示了一个将使用`get_url`选项从一堆 Web 服务器下载配置的 playbook。

```
---
- name: Fetch configuration from all webservers
  hosts: webservers
  tasks:
    - name: Get config
      get_url:
        dest: "configs/{{ ansible_hostname }}"
        force: yes
        url: "http://{{ ansible_hostname }}/diagnostic/config"
      delegate_to: localhost
```

如果您正在委派给`localhost`，在定义操作时可以使用快捷方式，该快捷方式会自动使用本地机器。如果您将操作行的键定义为`local_action`，则委派给`localhost`是隐含的。如果我们在先前的示例中使用了这个功能，它会稍微缩短，并且看起来像这样：

```
--- #1
- name: Fetch configuration from all webservers     #2
  hosts: webservers     #3
  tasks:     #4
    - name: Get config     #5
      local_action: get_url dest=configs/{{ ansible_hostname }}.cfg url=http://{{ ansible_hostname }}/diagnostic/config     #6
```

委派不仅限于本地机器。您可以委派给清单中的任何主机。您可能希望委派的其他原因包括：

+   在部署之前从负载均衡器中删除主机

+   更改 DNS 以将流量从即将更改的服务器转移

+   在存储设备上创建 iSCSI 卷

+   使用外部服务器检查网络外部访问是否正常工作

# 额外变量

您可能已经在上一章的模板示例中看到我们使用了一个名为`group_names`的变量。这是 Ansible 本身提供的魔术变量之一。在撰写本文时，有七个这样的变量，这些变量将在接下来的章节中描述。

## hostvars 变量

`hostvars`变量允许您检索当前 play 已处理的所有主机的变量。如果在当前 play 中尚未在受管主机上运行`setup`模块，则只有其变量可用。您可以像访问其他复杂变量一样访问它，例如`${hostvars.hostname.fact}`，因此要获取名为`ns1`的服务器上运行的 Linux 发行版，它将是`${hostvars.ns1.ansible_distribution}`。以下示例将一个名为 zone master 的变量设置为名为`ns1`的服务器。然后调用`template`模块，该模块将使用此设置每个区域的主服务器。

```
---
- name: Setup DNS Servers
  hosts: allnameservers
  tasks:
    - name: Install BIND
      yum:
        name: named
        state: installed

- name: Setup Slaves
  hosts: slavenamesservers
  tasks:
    - name: Get the masters IP
      set_fact:
        dns_master: "{{ hostvars.ns1.ansible_default_ipv4.address }}"

    - name: Configure BIND
      template:
        dest: /etc/named.conf src: templates/named.conf.j2
```

### 注意

使用`hostvars`，您可以进一步将模板与环境分离。如果您嵌套变量调用，那么在 play 的变量部分放置 IP 地址的地方，您可以添加主机名。要查找名为`the_machine`变量中的机器的地址，您可以使用`{{ hostvars.[the_machine].default_ipv4.address }}`。

## groups 变量

`groups`变量包含按清单组分组的所有主机的列表。这使您可以访问您配置的所有主机。这是一个潜力非常强大的工具。它允许您在整个组中进行迭代，并对每个主机应用当前机器的操作。

```
---
- name: Configure the database
  hosts: dbservers
  user: root
  tasks:
    - name: Install mysql
      yum:
        name: "{{ item }}"
        state: installed
      with_items:
      - mysql-server
      - MySQL-python

    - name: Start mysql
      service:
        name: mysqld
        state: started
        enabled: true

    - name: Create a user for all app servers
      with_items: groups.appservers
      mysql_user:
        name: kate
        password: test
        host: "{{ hostvars.[item].ansible_eth0.ipv4.address }}" state: present
```

### 注意

`groups`变量不包含组中的实际主机；它包含表示其在清单中的名称的字符串。这意味着如果需要，您必须使用嵌套变量扩展来访问`hostvars`变量。

您甚至可以使用此变量为包含所有其他机器的`host`密钥的所有机器创建`known_hosts`文件。这将允许您从一台机器 SSH 到另一台机器，而无需确认远程主机的身份。它还将在机器离开服务或更换机器时处理删除机器或更新机器。以下是执行此操作的`known_hosts`文件的模板：

```
{% for host in groups['all'] %}
{{ hostvars[host]['ansible_hostname'] }}
{{ hostvars[host]['ansible_ssh_host_key_rsa_public'] }}
{% endfor %}
```

使用此模板的 playbook 将如下所示：

```
---
hosts: all
tasks:
- name: Setup known hosts
  hosts: all
  tasks:
    - name: Create known_hosts
      template:
        src: templates/known_hosts.j2 dest: /etc/ssh/ssh_known_hosts
        owner: root
        group: root mode: 0644
```

## group_names 变量

`group_names`变量包含当前主机所在的所有组的名称列表。这不仅对于调试很有用，而且对于检测组成员资格的条件也很有用。这在上一章中用于设置域名服务器。

此变量主要用于跳过任务或在模板中作为条件。例如，如果 SSH 守护程序有两种配置，一种安全，一种不太安全，但您只想在安全组中的机器上使用安全配置，您可以这样做：

```
- name: Setup SSH
  hosts: sshservers
  tasks:
    - name: For secure machines
      set_fact:
        sshconfig: files/ssh/sshd_config_secure
      when: "'secure' in group_names"

    - name: For non-secure machines
      set_fact:
        sshconfig: files/ssh/sshd_config_default
      when: "'secure' not in group_names"

    - name: Copy over the config
      copy:
        src: "{{ sshconfig }}"
        dest: /tmp/sshd_config
```

### 注意

在上一个示例中，我们使用`set_fact`模块为每种情况设置事实，然后使用`copy`模块。我们本可以在`set_facts`模块的位置使用`copy`模块，并少使用一个任务。之所以这样做是因为`set_fact`模块在本地运行，而`copy`模块在远程运行。当您首先使用`set_facts`模块并仅调用一次`copy`模块时，副本将并行在所有机器上制作。如果使用两个带条件的`copy`模块，那么每个都将在相关机器上单独执行。由于`copy`是这两个任务中较长的任务，因此它最能从并行运行中受益。

## inventory_hostname 变量

`inventory_hostname`变量存储了在清单中记录的服务器的主机名。如果你选择不在当前主机上运行`setup`模块，或者由于各种原因，`setup`模块检测到的值不正确，你应该使用这个。当你正在进行机器的初始设置并更改主机名时，这很有用。

## inventory_hostname_short 变量

`inventory_hostname_short`变量与前一个变量相同；但是，它只包括第一个点之前的字符。因此对于`host.example.com`，它将返回`host`。

## inventory_dir 变量

`inventory_dir`变量是包含清单文件的目录的路径名。

## inventory_file 变量

`inventory_file`变量与前一个变量相同，只是它还包括文件名。

# 使用变量查找文件

所有模块都可以通过解引用`{{`和`}}`将变量作为其参数的一部分。你可以使用这个基于变量加载特定文件。例如，你可能想要根据使用的架构选择不同的`config`文件用于 NRPE（Nagios 检查守护程序）。以下是它的样子：

```
---
- name: Configure NRPE for the right architecture
  hosts: ansibletest
  user: root
  tasks:
    - name: Copy in the correct NRPE config file
      copy:
        src: "files/nrpe.{{ ansible_architecture }}.conf" dest: "/etc/nagios/nrpe.cfg"
```

在`copy`和`template`模块中，你还可以配置 Ansible 查找一组文件，并且它会使用找到的第一个文件。这让你可以配置一个要查找的文件；如果找不到该文件，将使用第二个文件，依此类推直到列表末尾。如果找不到文件，那么模块将失败。该功能使用`first_available_file`键触发，并在操作中引用`{{ item }}`。以下代码是此功能的示例：

```
---
- name: Install an Apache config file
  hosts: ansibletest
  user: root
  tasks:
   - name: Get the best match for the machine
     copy:
       dest: /etc/apache.conf
       src: "{{ item }}"
     first_available_file:
      - "files/apache/{{ ansible_os_family }}-{{ ansible_architecture }}.cfg"
      - "files/apache/default-{{ ansible_architecture }}.cfg"
      - files/apache/default.cfg
```

### 注意

记住你可以从 Ansible 命令行工具运行 setup 模块。当你在 playbooks 或模板中大量使用变量时，这非常方便。要检查特定 play 可用的事实，只需复制主机模式的值并运行以下命令：

```
**ansible [host pattern] -m setup**

```

在 CentOS x86_64 机器上，这个配置将首先在通过`files/apache/`导航时查找`RedHat-x86_64.cfg`文件。如果该文件不存在，它将在通过`file/apache/`导航时查找`default-x86_64.cfg`文件，最后如果什么都不存在，它将尝试使用`default.cfg`。

# 环境变量

通常，Unix 命令利用某些环境变量。这些的普遍例子是 C makefiles、安装程序和 AWS 命令行工具。幸运的是，Ansible 使这变得非常容易。如果你想要在远程机器上上传文件到 Amazon S3，你可以设置 Amazon 访问密钥如下。你还会看到我们安装 EPEL 以便安装 pip，而 pip 用于安装 AWS 工具。

```
---
- name: Upload a remote file via S3
  hosts: ansibletest
  user: root
  tasks:
    - name: Setup EPEL
      command: >
        rpm -ivh http://download.fedoraproject.org/pub/epel/6/i386/ epel-release-6-8.noarch.rpm
        creates=/etc/yum.repos.d/epel.repo

    - name: Install pip
      yum:
        name: python-pip
        state: installed

    - name: Install the AWS tools
      pip:
        name: awscli
        state: present

    - name: Upload the file
      shell: >
        aws s3 put-object
        --bucket=my-test-bucket
        --key={{ ansible_hostname }}/fstab
        --body=/etc/fstab
        --region=eu-west-1
      environment:
        AWS_ACCESS_KEY_ID: XXXXXXXXXXXXXXXXXXX
        AWS_SECRET_ACCESS_KEY: XXXXXXXXXXXXXXXXXXXXX
```

### 注意

在内部，Ansible 将环境变量设置到 Python 代码中；这意味着任何已经使用环境变量的模块都可以利用这里设置的变量。如果你编写自己的模块，你应该考虑某些参数是否最好作为环境变量而不是参数来使用。

一些 Ansible 模块，如`get_url`、`yum`和`apt`，也会使用环境变量来设置它们的代理服务器。你可能希望设置环境变量的其他情况包括：

+   运行应用程序安装程序

+   在使用`shell`模块时将额外项添加到路径

+   从系统库搜索路径中未包含的位置加载库

+   在运行模块时使用`LD_PRELOAD`黑客

# 外部数据查找

Ansible 在 0.9 版中引入了查找插件。这些插件允许 Ansible 从外部源获取数据。Ansible 提供了几个插件，但你也可以编写自己的插件。这真的打开了大门，让你在配置中更加灵活。

查找插件是用 Python 编写的，并在控制机器上运行。它们以两种不同的方式执行：直接调用和`with_*`键。直接调用在您想像变量一样使用它们时很有用。使用`with_*`键在您想要将它们用作循环时很有用。在前面的部分中，我们介绍了`with_fileglob`，这是一个示例。

在下一个示例中，我们直接使用查找插件从`environment`中获取`http_proxy`的值，并将其发送到配置的机器。这确保我们正在配置的机器将使用相同的代理服务器下载文件。

```
---
- name: Downloads a file using a proxy
  hosts: all
  tasks:
    - name: Download file
      get_url:
        dest: /var/tmp/file.tar.gz url: http://server/file.tar.gz
      environment:
        http_proxy: "{{ lookup('env', 'http_proxy') }}"
```

### 注意

您还可以在变量部分使用查找插件。这不会立即查找结果并将其放入变量中，而是将其存储为宏，并在每次使用时查找。如果您使用的值可能随时间变化，这是很重要的。

在`with_*`形式中使用查找插件将允许您迭代通常无法迭代的内容。您可以使用任何此类插件，但返回列表的插件最有用。在下面的代码中，我们展示了如何动态注册`webapp` farm。

```
---
- name: Registers the app server farm
  hosts: localhost
  connection: local
  vars:
    hostcount: 5
  tasks:
   - name: Register the webapp farm
      local_action: add_host name={{ item }} groupname=webapp
      with_sequence: start=1 end={{ hostcount }} format=webapp%02x
```

如果您使用此示例，您将附加一个任务来创建每个虚拟机，然后创建一个新的 play 来配置它们。

查找插件有用的情况如下：

+   将整个 Apache 配置目录复制到`conf.d`样式目录

+   使用环境变量来调整 playbook 的操作

+   从 DNS TXT 记录获取配置

+   将命令的输出获取到一个变量中

# 存储结果

几乎每个模块都会输出一些内容，即使是`debug`模块也是如此。大多数情况下，唯一使用的变量是名为`changed`的变量。`changed`变量帮助 Ansible 决定是否运行处理程序，以及输出的颜色。但是，如果您希望，可以存储返回的值并在以后的 playbook 中使用它们。在这个例子中，我们查看`/tmp`目录中的模式，并创建一个名为`/tmp/subtmp`的新目录，其模式与此处显示的相同。

```
---
- name: Using register
  hosts: ansibletest
  user: root
  tasks:
    - name: Get /tmp info
      file:
        dest: /tmp
        state: directory
      register: tmp

    - name: Set mode on /var/tmp
      file:
        dest: /tmp/subtmp
        mode: "{{ tmp.mode }}"
        state: directory
```

一些模块，例如前面示例中的`file`模块，可以配置为仅提供信息。通过结合注册功能，您可以创建可以检查环境并计算如何进行的 playbook。

### 注意

结合注册功能和`set_fact`模块允许您对从模块返回的数据进行数据处理。这使您能够计算值并对这些值执行数据处理。这使您的 playbook 比以往更加智能和灵活。

注册允许您根据您已经可用的模块为主机创建自己的事实。这在许多不同的情况下都很有用：

+   获取远程目录中的文件列表并使用 fetch 下载它们

+   在前一个任务更改时运行任务，然后运行处理程序

+   获取远程主机 SSH 密钥的内容并构建`known_hosts`文件

# 处理数据

Ansible 使用 Jinja2 过滤器允许您以基本模板无法实现的方式转换数据。当 playbooks 中可用的数据不是我们想要的格式，或者在可以与模块或模板一起使用之前需要进一步的复杂处理时，我们使用过滤器。过滤器可以用于我们通常使用变量的任何地方，例如在模板中，作为模块的参数以及在条件语句中。通过提供变量名称、管道字符，然后是过滤器名称来使用过滤器。我们可以使用多个过滤器名称，用管道字符分隔，以使用多个管道，然后从左到右应用。下面是一个示例，我们确保所有用户都使用小写用户名创建：

```
---
- name: Create user accounts
  hosts: all
  vars:
    users:
  tasks:
    - name: Create accounts
      user: name={{ item|lower }} state=present
      with_items:
        - Fred
        - John
        - DanielH
```

以下是一些您可能会发现有用的流行过滤器：

| 过滤器 | 描述 |
| --- | --- |
| `min` | 当参数是一个列表时，它只返回最小值。 |
| `max` | 当参数是一个列表时，仅返回最大值。 |
| `random` | 当参数是一个列表时，它会从列表中随机选择一个项目。 |
| `changed` | 当在使用 register 关键字创建的变量上使用时，如果任务更改了任何内容，则返回`true`；否则返回`false`。 |
| `failed` | 当在使用 register 关键字创建的变量上使用时，如果任务失败，则返回`true`；否则返回`false`。 |
| `skipped` | 当在使用 register 关键字创建的变量上使用时，如果任务更改了任何内容，则返回`true`；否则返回`false`。 |
| `default(X)` | 如果变量不存在，则将使用 X 的值。 |
| `unique` | 当参数是一个列表时，返回一个没有重复项的列表。 |
| `b64decode` | 将变量中的 base64 编码字符串转换为其二进制表示。这在与 slurp 模块一起使用时非常有用，因为它将其数据作为 base64 编码的字符串返回。 |
| `replace(X, Y)` | 返回一个将字符串中任何出现的`X`替换为`Y`的副本。 |
| `join(X)` | 当变量是一个列表时，返回一个所有条目由`X`分隔的字符串。 |

# 调试 playbooks

有几种方法可以调试 playbook。Ansible 包括冗长模式和专门用于调试的`debug`模块。您还可以使用`fetch`和`get_url`等模块进行帮助。这些调试技术也可以用于检查模块在您希望学习如何使用它们时的行为。

## 调试模块

使用`debug`模块非常简单。它接受两个可选参数，`msg`和`fail.msg`，用于设置模块将打印的消息和`fail`，如果设置为`yes`，则表示对 Ansible 的失败，这将导致它停止处理该主机的 playbook。我们在前面的跳过模块部分中使用了此模块，以便在操作系统未被识别时退出 playbook。

在下面的示例中，我们将展示如何使用`debug`模块列出机器上所有可用的接口：

```
---
- name: Demonstrate the debug module
  hosts: ansibletest
  user: root
  vars:
    hostcount: 5
  tasks:
    - name: Print interface
      debug:
        msg: "{{ item }}"
      with_items: ansible_interfaces
```

上述代码给出了以下输出：

```
PLAY [Demonstrate the debug module] *********************************

GATHERING FACTS *****************************************************
ok: [ansibletest]

TASK: [Print interface] *********************************************
ok: [ansibletest] => (item=lo) => {"item": "lo", "msg": "lo"}
ok: [ansibletest] => (item=eth0) => {"item": "eth0", "msg": "eth0"}

PLAY RECAP **********************************************************
ansibletest                : ok=2    changed=0    unreachable=0    failed=0
```

正如您所看到的，`debug`模块很容易用于查看 play 期间变量的当前值。

## 冗长模式

调试的另一个选项是冗长选项。当使用冗长模式运行 Ansible 时，它会在运行后打印出每个模块返回的所有值。如果您在上一节中使用了`register`关键字，则这将特别有用。要在冗长模式下运行`ansible-playbook`，只需在命令行中添加`--verbose`即可。

```
**ansible-playbook --verbose playbook.yml**

```

## 检查模式

除了冗长模式，Ansible 还包括检查模式和差异模式。您可以通过在命令行中添加`--check`来使用检查模式，并使用`--diff`来使用差异模式。检查模式指示 Ansible 在实际上不对远程系统进行任何更改的情况下执行 play。这允许您获取 Ansible 计划对配置系统进行的更改的列表。

### 注意

这里需要注意的是，Ansible 的检查模式并不完美。任何不实现检查功能的模块都将被跳过。此外，如果跳过了提供更多变量的模块，或者变量取决于实际更改某些内容的模块（例如文件大小），那么它们将不可用。当使用`command`或`shell`模块时，这是一个明显的限制。

差异模式显示了`template`模块所做的更改。这是因为`template`文件只能处理文本文件。如果您要提供来自 copy 模块的二进制文件的差异，结果几乎无法阅读。差异模式还与检查模式一起工作，以显示由于处于检查模式而未进行的计划更改。

## 暂停模块

另一种技术是使用`pause`模块在检查配置的机器运行时暂停 playbook。这样，您可以在 play 的当前位置看到模块所做的更改，然后在其余的 play 继续执行时观察。

# 总结

在本章中，我们探讨了编写 playbooks 的更高级细节。现在，您应该能够使用委派、循环、条件和事实注册等功能，使您的 plays 更容易维护和编辑。我们还看了如何从其他主机访问信息，为模块配置环境，并从外部来源收集数据。最后，我们介绍了一些调试 plays 的技巧，以解决它们的行为与预期不符的问题。

在下一章中，我们将介绍如何在更大的环境中使用 Ansible。它将包括改进 playbooks 性能的方法，这些 playbooks 可能需要很长时间才能执行。我们还将介绍一些使 plays 易于维护的功能，特别是按目的将它们分成多个部分。


# 第四章：更大的项目

到目前为止，我们一直在一个 playbook 文件中查看单个 play。这种方法适用于简单的基础设施，或者在使用 Ansible 作为简单的部署机制时。然而，如果您有一个庞大而复杂的基础设施，那么您将需要采取措施防止事情失控。本章将包括以下主题：

+   将您的 playbooks 分成不同的文件，并从其他位置包括它们

+   使用角色包括执行类似功能的多个文件

+   增加 Ansible 配置机器速度的方法

# 包括

您将面临的第一个问题之一是，您的 playbooks 将迅速增加。大型 playbooks 可能变得难以阅读和维护。Ansible 允许您通过包括来解决这个问题。

包括允许您将您的 plays 分成多个部分。然后您可以从其他 plays 中包括每个部分。这使您可以为不同的目的构建几个不同的部分，全部包括在一个主要 play 中。

有四种包括，即变量包括，playbook 包括，任务包括和处理程序包括。从外部`vars_file`文件中包括变量已经在第二章中讨论过了，*简单 Playbooks*。以下是每个包括的描述：

+   **变量包括**：它们允许您将变量放在外部的 YAML 文件中

+   **Playbook 包括**：它们用于在单个 play 中包括其他文件中的 plays

+   **任务包括**：它们让您将常见任务放在其他文件中，并在需要时包括它们

+   **处理程序包括**：它们让您将所有处理程序放在一个地方

我们将在下一节中讨论这些包括；然而，从外部`vars_file`文件中包括变量已经在第二章中讨论过了，*简单 Playbooks*，所以我们不会详细讨论它。

## 任务包括

任务包括可用于重复的许多常见任务。例如，您可能有一组任务，它们在配置之前从监视器和负载均衡器中删除一个机器。您可以将这些任务放在一个单独的 YAML 文件中，然后从主任务中包括它们。

任务包括继承自它们所包含的 play 的事实。您还可以提供自己的变量，这些变量被传递到任务中并可供使用。

最后，任务包括可以对它们应用条件。如果这样做，条件将由 Ansible 自动分别添加到每个包含的任务中。任务仍然都包括在内。在大多数情况下，这不是一个重要的区别；然而，在变量可能改变的情况下，这是重要的。

作为任务包括的文件包含了一系列任务。如果您假设任何变量、主机或组的存在，那么您应该在文件顶部的注释中说明它们。这样可以更容易地供希望以后重用文件的人使用。

因此，如果您想创建一堆用户并设置他们的环境与他们的公钥，您将把执行单个用户的任务拆分到一个文件中。这个文件看起来类似于以下代码：

```
---
# Requires a user variable to specify user to setup
- name: Create user account
  user:
    name: "{{ user }}"
    state: present

- name: Make user SSH config dir
  file:
    path: "/home/{{ user }}/.ssh"
    owner: "{{ user }}"
    group: "{{ user }}"
    mode: 0600
    state: directory

- name: Copy in public key
  copy:
    src: "keys/{{ user }}.pub"
    dest: "/home/{{ user }}/.ssh/authorized_keys"
    mode: 0600
    owner: "{{ user }}"
    group: "{{ user }}"
```

我们期望一个名为`user`的变量将被传递给我们，并且他们的公钥将在`keys`目录中。账户被创建，`ssh config`目录被创建，最后我们可以将这个公钥复制进去。使用这个`config`文件的最简单方法是使用您在第三章中学到的`with_items`关键字。这将类似于以下代码：

```
---
- hosts: ansibletest
  user: root
  tasks:
    - include: usersetup.yml user={{ item }}
      with_items:
        - mal
        - dan
        - kate
```

## 处理程序包括

在编写 Ansible playbooks 时，你会不断发现自己多次重复使用相同的处理程序。例如，用于重新启动 MySQL 的处理程序在任何地方看起来都是一样的。为了使这更容易，Ansible 允许你在处理程序部分包含其他文件。处理程序包含看起来与任务包含相同。你应该确保在每个处理程序上包含一个名称；否则，你将无法在任务中轻松地引用它们。处理程序包含文件看起来类似于以下代码：

```
---
- name: config sendmail
  command: make -C /etc/mail
  notify: reload sendmail

- name: config aliases
  command: newaliases
  notify: reload sendmail

- name: reload sendmail
  service:
    name: sendmail
    state: reloaded

- name: restart sendmail
  service:
    name: sendmail
    state: restarted
```

这个文件提供了在配置`sendmail`后你想要处理的几个常见任务。通过在它们自己的文件中包含以下处理程序，你可以在需要更改`sendmail`配置时轻松重用它们。

+   第一个处理程序重新生成`sendmail`数据库的`config`文件，并稍后触发`sendmail`的`reload`文件

+   第二个处理程序初始化`aliases`数据库，并安排`sendmail`的`reload`文件

+   第三个处理程序重新加载`sendmail`；它可以由前两个作业触发，也可以直接从任务触发

+   第四个处理程序在触发时重新启动`sendmail`；如果你将`sendmail`升级到新版本，这将很有用

### 注意

处理程序可以触发其他处理程序，前提是它们只触发稍后指定的处理程序，而不是被触发的处理程序。这意味着你可以设置一系列互相调用的处理程序。这样可以避免在任务的通知部分中有长长的处理程序列表。

使用前面的处理程序文件现在很容易。我们只需要记住，如果我们更改了`sendmail`配置文件，那么我们应该触发`config sendmail`，如果我们更改了`aliases`文件，我们应该触发`config aliases`。以下代码向我们展示了一个例子：

```
---
  hosts: mailers
  tasks:
    - name: update sendmail
      yum:
        name: sendmail
        state: latest
      notify: restart sendmail

    - name: configure sendmail
      template:
        src: templates/sendmail.mc.j2 dest: /etc/mail/sendmail.mc
      notify: config sendmail

  handlers:
    - include: sendmailhandlers.yml
```

这个 playbook 确保`sendmail`已安装。如果它没有安装，或者没有运行最新版本，那么它会安装或更新它。更新后，它会安排重新启动，以便我们可以确信最新版本在 playbook 完成后运行。在下一步中，我们用我们的模板替换`sendmail`配置文件。如果`config`文件被模板更改，那么`sendmail`配置文件将被重新生成，最后`sendmail`将被重新加载。

## Playbook includes

当你想要包含一整套为一组机器指定的任务时，应该使用 Playbook includes。例如，你可能有一个 play，收集几台机器的主机密钥，并构建一个`known_hosts`文件复制到所有机器上。

虽然任务包含允许你包含任务，但 playbook 包含允许你包含整个 plays。这允许你选择你希望运行的主机，并为通知事件提供处理程序。因为你包含整个 playbook 文件，所以你也可以包含多个 plays。

Playbook includes 允许你嵌入完全独立的文件。因此，你应该提供它所需的任何变量。如果它依赖于任何特定的主机或组，这应该在文件顶部的注释中注明。

当你希望同时运行多个不同的操作时，这是很方便的。例如，假设我们有一个名为`drfailover.yml`的 playbook，用于切换到我们的 DR 站点，另一个名为`upgradeapp.yml`用于升级应用程序，另一个名为`drfailback.yml`用于失败回退，最后是`drupgrade.yml`。所有这些 playbooks 可能分别使用有效；然而，在执行站点升级时，你可能希望一次执行它们所有。你可以像下面的代码中所示那样做：

```
---
- include "drfailover.yml"
- include "upgradeapp.yml"
- include "drfailback.yml"

- name: Notify management
  hosts: local
  tasks:
    - mail
        to: "mgmt-team@example.com"
        msg: 'The application has been upgraded and is now live'

- include "drupgrade.yml"
```

正如你所看到的，你可以在包含其他 playbooks 的 playbooks 中放置完整的 plays。

# 角色

如果你的 playbooks 开始扩展超出了包含可以帮助你解决的范围，或者你开始收集大量模板，你可能想要使用角色。Ansible 中的角色允许你以定义的结构将文件组合在一起。它们本质上是包含的扩展，可以自动处理一些事情，这有助于你在存储库中组织它们。

角色允许你将变量、文件、任务、模板和处理程序放在一个文件夹中，然后轻松地包含它们。你还可以在角色内包含其他角色，这实际上创建了一个依赖树。与任务包含类似，它们可以接收传递给它们的变量。使用这些功能，你应该能够构建自包含的角色，方便与他人分享。

角色通常用于管理机器提供的服务，但它们也可以是守护进程、选项或简单的特性。你可能想要在角色中配置的内容如下：

+   Web 服务器，如 Nginx 或 Apache

+   根据机器的安全级别定制的每日消息

+   运行 PostgreSQL 或 MySQL 的数据库服务器

要管理 Ansible 中的角色，请执行以下步骤：

1.  创建一个名为 roles 的文件夹，其中包含你的 playbooks。

1.  在`roles`文件夹中，为每个你想要的角色创建一个文件夹。

1.  在每个角色的文件夹中，创建名为`files`、`handlers`、`meta`、`tasks`、`templates`和最后`vars`的文件夹。如果你不打算使用所有这些，可以省略你不需要的部分。当使用角色时，Ansible 会默默地忽略任何缺少的文件或目录。

1.  在你的 playbooks 中，添加关键字`roles`，后面跟着你想应用到主机的角色列表。

1.  例如，如果你有`common`、`apache`、`website1`和`website2`角色，你的目录结构将类似于以下示例。`site.yml`文件用于重新配置整个站点，`webservers1.yml`和`webservers2.yml`文件用于配置每个 Web 服务器群。![Roles](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-cfg-mgt-2e/img/4267_04_01.jpg)

以下文件是`website1.yml`中可能包含的内容。它显示了一个应用`common`、`apache`和`website1`角色到清单中的`website1`组的 playbook。`website1`角色使用了更详细的格式，允许我们向角色传递变量，如下所示：

```
---
- name: Setup servers for website1.example.com
  hosts: website1
  roles:
    - common
    - apache
    - { role: website1, port: 80 }
```

对于名为`common`的角色，Ansible 将尝试加载`roles/common/tasks/main.yml`作为任务包含，`roles/common/handlers/main.yml`作为处理程序包含，`roles/common/vars/main.yml`作为变量文件包含。如果所有这些文件都缺失，Ansible 将抛出错误；但是，如果其中一个文件存在，那么其他缺失的文件将被忽略。默认安装的 Ansible 使用以下目录（其他目录可能由不同的模块使用）：

| 目录 | 描述 |
| --- | --- |
| `tasks` | `tasks`文件夹应包含一个`main.yml`文件，其中应包含此角色的任务列表。这些角色中包含的任何任务都将在此文件夹中查找它们的文件。这使你可以将大量任务拆分成单独的文件，并使用任务包含的其他功能。 |
| `files` | `files`文件夹是角色中由`copy`或`script`模块使用的文件的默认位置。 |
| `templates` | `templates`目录是模板模块自动查找角色中包含的 jinja2 模板的位置。 |
| `handlers` | `handlers`文件夹应包含一个`main.yml`文件，指定角色的处理程序，该文件夹中的任何包含也将在相同位置查找文件。 |
| `vars` | `vars`文件夹应包含一个`main.yml`文件，其中包含此角色的变量。 |
| `meta` | `meta`文件夹应包含一个`main.yml`文件。该文件可以包含角色的设置和其依赖项列表。此功能仅在 Ansible 1.3 及以上版本中可用。 |
| `default` | 如果您希望将变量发送到此角色，并且希望使它们可选，则应使用`default`文件夹。此文件夹中的`main.yml`文件将被读取，以获取可以被从 playbook 调用角色的变量覆盖的变量的初始值。此功能仅在 Ansible 1.3 及以上版本中可用。 |

在使用角色时，复制、模板和脚本模块的行为会略有改变。除了通过查找位于 playbook 文件所在目录中的文件来搜索文件外，Ansible 还将在角色的位置中查找文件。例如，如果您使用名为`common`的角色，这些模块的行为将更改为以下行为：

+   复制模块将在`roles/common/files`中查找文件。

+   模板模块将首先在`roles/common/templates`中查找模板。

+   脚本模块首先会在`roles/common/files`中查找文件。

+   其他模块可能决定在`roles/common/`内的其他文件夹中查找它们的数据。模块的文档可以使用`ansible-doc`检索，就像在第一章的*模块帮助*部分中讨论的那样，*开始使用 Ansible*。

# 角色元数据

使用角色元数据允许我们指定我们的角色依赖于其他角色。例如，如果您部署的应用程序需要发送电子邮件，则您的角色可以依赖于 Postfix 角色。这意味着在设置和安装应用程序之前，将安装和设置 Postfix。

`meta/main.yml`文件将类似于以下代码：

```
---
allow_duplicates: no
dependencies:
  - apache
```

`allow_duplicates`行设置为`no`，这是默认值。如果将其设置为`no`，则 Ansible 不会第二次运行角色，如果使用相同的参数两次。如果将其设置为`yes`，即使之前已经运行过，它也会重复运行角色。您可以将其设置为`off`而不是设置为`no`。

依赖项的格式与角色相同。这意味着您可以在这里传递变量；可以是静态值，也可以是传递给当前角色的变量。

# 角色默认值

与 Ansible 1.3 一起包含的第二个功能是变量默认值。如果在角色的默认目录中放置`main.yml`文件，则这些变量将被读入角色；但是，它们可以被`vars/main.yml`文件中的变量或包含角色时传递的变量覆盖。这允许您将传递给角色的变量设置为可选。这些文件看起来与其他变量文件完全相同。例如，如果在角色中使用名为`port`的变量，并且要将其默认为端口`80`，则`defaults/main.yml`文件将类似于以下代码：

```
---
port: 80
```

# 加快速度

随着您向 Ansible 配置中添加越来越多的机器和服务，您会发现事情变得越来越慢。幸运的是，有几个技巧可以让您在更大的规模上使用 Ansible。

## 配置

Ansible 不仅仅局限于能够配置我们的机器；我们还可以使用它来创建我们将要配置的机器。我们不仅仅局限于制作将要配置的机器，还可以制作网络、负载均衡器、DNS 条目，甚至整个基础架构。您甚至可以在配置机器之前自动执行此操作，方法是使用`group`、`group_by`和`add_host`模块。

在以下示例中，我们使用 Google Compute 创建两台机器，然后在它们上安装并启动 MySQL 服务器：

```
---
- name: Setup MySQL Infrastructure
  hosts: localhost
  connection: local
  tasks:
    - name: Start GCE Nodes
      gce:
        image: centos-6
        name: "mysql-{{ item }}"
        tags: mysql
        zone: us-central1-a
      with_sequence: count=2
      register: nodes
      when: '"mysql-{{ item }}" not in groups.all'

    - name: Wait for the nodes to start
      wait_for:
          host: "{{ item.instance_data[0].public_ip }}"
          port: 22
      with_items: nodes.results
      when: not item|skipped

    - name: Register the hosts in a group
      add_host:
          name: "{{ item.instance_data[0].name }}"
          ansible_ssh_host: "{{ item.instance_data[0].public_ip }}"
          groups: "tag_mysql"
      with_items: nodes.results
      when: not item|skipped

- name: Setup MySQL
  hosts: tag_mysql
  tasks:
    - name: Install MySQL
      yum:
        name: mysql
        state: present

    - name: Start MySQL
      service:
        name: mysqld
        state: started
        enabled: yes
```

## 标签

Ansible 标签是一种功能，允许您选择需要运行的 playbook 的部分，以及应该跳过的部分。虽然 Ansible 模块是幂等的，如果没有更改，它们将自动跳过，但这通常需要连接到远程主机。yum 模块通常在确定模块是否最新时速度相当慢，因为它需要刷新所有存储库。

如果您知道不需要运行某些操作，可以选择仅运行已标记特定标签的任务。这甚至不会尝试运行任务，它只是简单地跳过。即使没有任何操作要执行，这将节省几乎所有模块的时间。

假设您有一台拥有大量 shell 帐户的机器，但也设置了几个服务来运行。现在，想象一下一个用户的 SSH 密钥已经被泄露，需要立即删除。您可以简单地运行现有的 playbooks，带有 SSH 密钥标签，它只会运行必要的步骤来复制新密钥，立即跳过其他任何操作。

如果您有一个包含整个基础架构的 playbook，并且其中包含 playbook 包含，这将特别有用。通过这种设置，您可以尽快部署安全补丁，更改密码，并在整个基础架构中撤销密钥。

标记任务非常简单；只需添加一个名为`tag`的键，并将其值设置为您想要赋予它的标签列表。以下代码向我们展示了如何做到这一点：

```
---
- name: Install and setup our webservers
  hosts: webservers
  tasks:
  - name: install latest software
    yum
      name: "{{ item }}"
      state: latest
    notify: restart apache
    tags:
      - patch
    with_items:
    - httpd
    - webalizer

  - name: Create subdirectories
    file
      dest: "/var/www/html/{{ item }}"
      state: directory
      mode: 755 owner: apache
      group: apache
    tags:
      - deploy
    with_items:
      - pub

  - name: Copy in web files
    copy
      src: "website/{{ item }}"
      dest: "/var/www/html/{{ item }}"
      mode: 0755
      owner: apache
      group: apache
    tags:
      - deploy
    with_items:
      - index.html
      - logo.png
      - style.css
      - app.js
      - pub/index.html

  - name: Copy webserver config
    tags:
      - deploy
      - config
    copy
      src: website/httpd.conf
      dest: /etc/httpd/conf/httpd.conf
      mode: 0644
      owner: root
      group: root
    notify: reload apache

  - name: set apache to start on startup
    service
      name: httpd
      state: started
      enabled: yes

  handlers:
  - name: reload apache
    service: name=httpd state=reloaded

  - name: restart apache
    service: name=httpd state=restarted
```

此 play 定义了`patch`、`deploy`和`config`标签。如果您事先知道要执行的操作，可以使用正确的参数运行 Ansible，仅运行您选择的操作。如果您在命令行上没有提供标签，则默认情况下会运行每个任务。例如，如果您希望 Ansible 仅运行标记为`deploy`的任务，您将运行以下命令：

```
**$ ansible-playbook webservers.yml --tags deploy**

```

除了处理离散任务外，角色也可以使用标签，这使得 Ansible 仅应用于在命令行上提供的标签的角色。您可以类似地应用它们，就像它们应用于任务一样。例如，请参考以下代码：

```
---
- hosts: website1
  roles:
    - common
    - { role: apache, tags: ["patch"] }
    - { role: website2, tags: ["deploy", "patch"] }
```

在上述代码中，`common`角色不会得到任何标签，并且如果应用了任何标签，它将不会运行。如果应用了`patch`标签，则将应用`apache`和`website2`角色，但不会应用`common`。如果应用了`deploy`标签；只有`website2`标签将被运行。这将缩短打补丁服务器或运行部署所需的时间，因为不必要的步骤将被完全跳过。

## Ansible 的拉模式

Ansible 包含了一个拉模式，可以显著提高 playbook 的可扩展性。到目前为止，我们只讨论了使用 Ansible 通过 SSH 配置另一台机器。这与 Ansible 的拉模式形成对比，后者在您希望配置的主机上运行。由于`ansible-pull`在配置它的机器上运行，它不需要与其他机器建立连接，并且运行速度更快。在这种模式下，您可以在 git 存储库中提供配置，Ansible 会下载并用于配置您的机器。

您应该在以下情况下使用 Ansible 的拉模式：

+   在配置节点时，您的节点可能不可用，比如自动扩展服务器群的成员

+   您有大量的机器需要配置，即使使用大量的 forks 值，也需要很长时间来配置它们

+   您希望机器在存储库更改时自动更新其配置

+   您希望在可能没有网络访问权限的机器上运行 Ansible，比如在 kick start 后安装

然而，拉模式确实具有以下缺点，使其不适用于某些情况：

+   要连接到其他机器并收集变量，或者复制文件，您需要在受控节点上拥有凭据

+   您需要协调服务器群上的 playbook 运行；例如，如果一次只能使三台服务器脱机

+   服务器位于严格的防火墙后，不允许来自用于为 Ansible 配置它们的节点的传入 SSH 连接

拉取模式在您的 playbook 中不需要任何特殊设置，但是需要在要配置的节点上进行一些设置。在某些情况下，您可以使用 Ansible 的正常推送模式来执行此操作。以下是在机器上设置拉取模式的小玩法：

```
---
- name: Ansible Pull Mode
  hosts: pullhosts
  tasks:
    - name: Setup EPEL
      command: "rpm -ivh http://download.fedoraproject.org/pub/epel/6/i386/epel-release-6-8.noarch.rpm"
      args: creates=/etc/yum.repos.d/epel.repo

    - name: Install Ansible + Dependencies
      yum:
        name: "{{ item }}"
        state: latest
        enablerepo: epel
      with_items:
      - ansible
      - git-core

    - name: Make directory to put downloaded playbooks in
      file:
        state: directory
        path: /opt/ansiblepull

    - name: Setup cron
      cron:
        name: "ansible-pull"
        user: root
        minute: "*/5"
        state: present
        job: "ansible-pull -U https://git.int.example.com.com/gitrepos/ansiblepull.git -D /opt/ansiblepull {{ inventory_hostname_short }}.yml"
```

在本例中，我们执行了以下步骤：

1.  首先，我们安装并设置了**EPEL**。这是一个为 CentOS 提供额外软件的存储库。Ansible 可在 EPEL 存储库中获得。

1.  接下来，我们安装了 Ansible，并确保启用了 EPEL 存储库。

1.  然后，我们为 Ansible 的拉取模式创建了一个目录，以放置 playbooks。保留这些文件意味着您不需要一直下载整个 git 存储库；只需要更新即可。

1.  最后，我们设置了一个定时任务，每五分钟尝试运行`ansible-pull`模式配置。

### 注意

前面的代码从内部 HTTPS git 服务器下载存储库。如果您想要下载存储库而不是 SSH，则需要添加一步来安装 SSH 密钥，或者生成密钥并将其复制到 git 机器上。

# 存储机密信息

最终，您将需要在您的 Ansible 配方中包含敏感数据。到目前为止，我们讨论过的所有配方都必须以纯文本形式存储在磁盘上；如果您还将其存储在源代码控制中，则第三方甚至可能访问这些数据。这是有风险的，可能违反您的公司政策。

可以使用 Ansible 保险库来避免这种情况。保险库是加密的文件，可以由 Ansible 透明地解密。您可以将它们用于包含、变量文件、角色中的任务列表以及 Ansible 使用的任何其他 YAML 格式文件。您还可以将其与包含在`ansible-playbook`的`-e`命令行参数中的 JSON 和 YAML 文件一起使用。保险库文件由`ansible-vault`命令管理，并且可以像未加密的文件一样使用。

`ansible-vault`命令有几种模式，这些模式作为第一个参数给出。此表描述了这些模式：

| 模式 | 操作 |
| --- | --- |
| `创建` | 这将启动您的默认编辑器以创建一个新的加密文件 |
| `加密` | 这将加密现有文件，将其转换为保险库 |
| `编辑` | 这将编辑一个保险库，允许您更改内容 |
| `重新设置密码` | 这将更改用于加密保险库的密码 |
| `解密` | 这将解密保险库，将其转换回常规文件 |

例如，要为您的暂存环境创建一个新的变量文件，您将运行：

```
**$ ansible-vault create vars/staging.yml**

```

这个命令将提示您输入密码，要求您确认密码，然后打开您的编辑器，以便您添加内容；最后，加密的内容将保存在`vars/staging.yml`中。

在使用保险库文件时，您需要提供密码以便进行解密。有三种方法可以做到这一点。您可以给 Ansible 提供`--ask-vault-pass`参数，这将导致 Ansible 每次启动时提示输入密码。您还可以使用`--vault-password-file`参数，该参数指向包含密码的文件。最后，您可以将`vault_password_file`添加到`ansible.cfg`文件中，以便每次命令都自动使用保险库密码文件。重要的是要注意，每次 Ansible 运行只能提供一个密码，因此您不能包含具有不同密码的几个不同文件。

为了让 Ansible 提示输入密码来运行加密的 playbook，您需要执行以下操作：

```
**$ ansible-playbook --ask-vault-pass encrypted.yml**

```

### 注意

密码文件也可以是可执行文件。要打印到屏幕，请打印到标准错误，要从用户那里读取，您可以像往常一样使用`stdin`，最后脚本需要在退出之前将密码打印到`stdout`。

# 总结

在本章中，我们已经介绍了从简单设置转移到更大规模部署时所需的技术。我们讨论了如何使用包含来将你的 playbook 分成多个部分。然后，我们看了一下如何打包相关的包含，并使用角色自动全部包含它们。最后，我们讨论了拉取模式，它允许你在远程节点上自动化部署 playbook。

在下一章中，我们将介绍如何编写自己的模块。我们首先通过使用 bash 脚本构建一个简单的模块来开始。然后，我们将看看 Ansible 是如何搜索模块的，以及如何让它找到你自己定制的模块。接下来，我们将介绍如何使用 Python 编写更高级的模块，利用 Ansible 提供的功能。最后，我们将编写一个脚本，配置 Ansible 从外部来源获取清单。
