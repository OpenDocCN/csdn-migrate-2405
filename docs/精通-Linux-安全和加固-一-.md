# 精通 Linux 安全和加固（一）

> 原文：[`zh.annas-archive.org/md5/FE09B081B50264BD581CF4C8AD742097`](https://zh.annas-archive.org/md5/FE09B081B50264BD581CF4C8AD742097)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

在这本书中，我们将介绍适用于任何基于 Linux 的服务器或工作站的安全和加固技术。我们的目标是让坏人更难对您的系统进行恶意操作。

# 这本书是为谁准备的

我们的目标读者是一般的 Linux 管理员，无论他们是否专门从事 Linux 安全工作。我们提出的技术可以用于 Linux 服务器或 Linux 工作站。

我们假设我们的目标读者在 Linux 命令行上有一些实践经验，并且具备 Linux 基础知识。

# 这本书涵盖了什么

第一章，*在虚拟环境中运行 Linux*，概述了 IT 安全领域，并告知读者为什么学习 Linux 安全是一个不错的职业选择。我们还将介绍如何建立一个进行实践练习的实验室环境。我们还将展示如何建立一个虚拟实验室环境来进行实践练习。

第二章，*保护用户账户*，介绍了始终使用根用户账户的危险，并将介绍使用 sudo 的好处。然后我们将介绍如何锁定普通用户账户，并确保用户使用高质量的密码。

第三章，*使用防火墙保护服务器*，涉及使用各种类型的防火墙工具。

第四章，*加密和 SSH 加固*，确保重要信息——无论是静态还是传输中的——都受到适当的加密保护。对于传输中的数据，默认的 Secure Shell 配置并不安全，如果保持原样可能会导致安全漏洞。本章介绍了如何解决这个问题。

第五章，*掌握自主访问控制*，介绍了如何设置文件和目录的所有权和权限。我们还将介绍 SUID 和 SGID 对我们有什么作用，以及使用它们的安全影响。最后我们将介绍扩展文件属性。

第六章，*访问控制列表和共享目录管理*，解释了普通的 Linux 文件和目录权限设置并不是非常精细。通过访问控制列表，我们可以只允许特定人访问文件，或者允许多人以不同的权限访问文件。我们还将整合所学知识来管理一个共享目录给一个群组使用。

第七章，*使用 SELinux 和 AppArmor 实施强制访问控制*，讨论了 SELinux，这是包含在 Red Hat 类型的 Linux 发行版中的强制访问控制技术。我们将在这里简要介绍如何使用 SELinux 防止入侵者破坏系统。AppArmor 是另一种包含在 Ubuntu 和 Suse 类型的 Linux 发行版中的强制访问控制技术。我们将在这里简要介绍如何使用 AppArmor 防止入侵者破坏系统。

第八章，*扫描、审计和加固*，讨论了病毒对 Linux 用户来说还不是一个巨大的问题，但对 Windows 用户来说是。如果您的组织有 Windows 客户端访问 Linux 文件服务器，那么这一章就是为您准备的。您可以使用 auditd 来审计对文件、目录或系统调用的访问。它不会防止安全漏洞，但会让您知道是否有未经授权的人试图访问敏感资源。SCAP，即安全内容应用协议，是由国家标准与技术研究所制定的合规性框架。开源实现的 OpenSCAP 可以用来将一个硬化策略应用到 Linux 计算机上。

第九章，《漏洞扫描和入侵检测》，解释了如何扫描我们的系统，以查看我们是否遗漏了任何内容，因为我们已经学会了如何为最佳安全性配置我们的系统。我们还将快速查看入侵检测系统。

第十章，《忙碌蜜蜂的安全提示和技巧》，解释了由于你正在处理安全问题，我们知道你很忙碌。因此，本章向您介绍了一些快速提示和技巧，以帮助您更轻松地完成工作。

# 为了充分利用本书

为了充分利用本书，您不需要太多。但是，以下内容将非常有帮助：

1.  对基本 Linux 命令和如何在 Linux 文件系统中导航有一定的了解。

1.  对于诸如 less 和 grep 之类的工具有基本的了解。

1.  熟悉命令行编辑工具，如 vim 或 nano。

1.  对使用 systemctl 命令控制 systemd 服务有基本的了解。

对于硬件，您不需要任何花哨的东西。您只需要一台能够运行 64 位虚拟机的机器。因此，您可以使用几乎任何一台配备现代 Intel 或 AMD CPU 的主机机器。（这个规则的例外是 Intel Core i3 和 Core i5 CPU。尽管它们是 64 位 CPU，但它们缺乏运行 64 位虚拟机所需的硬件加速。具有讽刺意味的是，远远更老的 Intel Core 2 CPU 和 AMD Opteron CPU 可以正常工作。）对于内存，我建议至少 8GB。

您可以在主机上运行任何三种主要操作系统，因为我们将使用的虚拟化软件适用于 Windows、MacOS 和 Linux。

# 下载彩色图像

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图像。您可以在这里下载：[`www.packtpub.com/sites/default/files/downloads/MasteringLinuxSecurityandHardening_ColorImages.pdf`](http://www.packtpub.com/sites/default/files/downloads/MasteringLinuxSecurityandHardening_ColorImages.pdf)。

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：指示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。这是一个例子：“让我们使用`getfacl`来查看`acl_demo.txt`文件上是否已经设置了任何访问控制列表。”

代码块设置如下：

```
   [base]
        name=CentOS-$releasever - Base
        mirrorlist=http://mirrorlist.centos.org/?
        release=$releasever&arch=$basearch&repo=os&infra=$infra
          #baseurl=http://mirror.centos.org/centos/
           $releasever/os/$basearch/
        gpgcheck=1
        gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-7
        priority=1
```

任何命令行输入或输出都以以下方式编写：

```
[donnie@localhost ~]$ tar cJvf new_perm_dir_backup.tar.xz new_perm_dir/ --acls
new_perm_dir/
new_perm_dir/new_file.txt
[donnie@localhost ~]$
```

**粗体**：表示一个新术语、一个重要词或屏幕上看到的词。例如，菜单或对话框中的单词会以这样的方式出现在文本中。这是一个例子：“点击 Network 菜单项，并将 Attached to 设置从 NAT 更改为 Bridged Adapter。”

警告或重要提示会以这种方式出现。

提示和技巧会以这种方式出现。

# 联系我们

我们始终欢迎读者的反馈。

**一般反馈**：发送电子邮件至`feedback@packtpub.com`，并在主题中提及书名。如果您对本书的任何方面有疑问，请发送电子邮件至`questions@packtpub.com`与我们联系。

**勘误**：尽管我们已经非常小心地确保了内容的准确性，但错误是难免的。如果您在本书中发现了错误，我们将不胜感激，如果您能向我们报告。请访问[www.packtpub.com/submit-errata](http://www.packtpub.com/submit-errata)，选择您的书，点击勘误提交表格链接，并输入详细信息。

**盗版**：如果您在互联网上发现我们作品的任何非法副本，我们将不胜感激，如果您能向我们提供位置地址或网站名称。请通过`copyright@packtpub.com`与我们联系，并附上材料链接。

如果您有兴趣成为一名作者：如果您在某个专业领域有专长，并且有兴趣撰写或为一本书做出贡献，请访问[authors.packtpub.com](http://authors.packtpub.com/)。

# 评论

请留下评论。当您阅读并使用了这本书之后，为什么不在购买书籍的网站上留下评论呢？潜在的读者可以看到并使用您的客观意见来做出购买决定，我们在 Packt 可以了解您对我们产品的看法，而我们的作者也可以看到您对他们书籍的反馈。谢谢！

有关 Packt 的更多信息，请访问[packtpub.com](https://www.packtpub.com/)。


# 第一章：在虚拟环境中运行 Linux

所以，你可能会问自己，“*为什么我需要学习 Linux 安全？Linux 不是已经很安全了吗？毕竟，它不是 Windows*。”但事实是，有很多原因。

事实上，Linux 在安全方面确实比 Windows 有一些优势。这些包括：

+   与 Windows 不同，Linux 是从头开始设计的多用户操作系统。因此，在 Linux 系统上用户安全性往往会更好一些。

+   Linux 在管理用户和非特权用户之间提供了更好的分离。这使得入侵者更难一些，也使得用户更难意外地用一些恶意软件感染 Linux 机器。

+   Linux 比 Windows 更抵抗病毒和恶意软件感染。

+   某些 Linux 发行版带有内置机制，如 Red Hat 和 CentOS 中的 SELinux 和 Ubuntu 中的 AppArmor，可以防止入侵者控制系统。

+   Linux 是自由开源软件。这使得任何有技能的人都可以审计 Linux 代码以寻找漏洞或后门。

但即使有这些优势，Linux 也和人类创造的其他一切一样，不是完美的。

本章将涵盖的主题包括：

+   每个 Linux 管理员都需要了解 Linux 安全

+   威胁环境的一些内容，以及攻击者如何有时能够侵入 Linux 系统的一些例子

+   跟进 IT 安全新闻的资源

+   如何在 VirtualBox 上设置 Ubuntu Server 和 CentOS 虚拟机，以及如何在 CentOS 虚拟机中安装 EPEL 存储库

+   如何创建虚拟机快照

+   如何在 Windows 主机上安装 Cygwin，以便 Windows 用户可以从他们的 Windows 主机连接到虚拟机

# 威胁环境

如果你在过去几年一直关注 IT 技术新闻，你可能至少看过一些关于攻击者如何侵入 Linux 服务器的文章。例如，虽然 Linux 不太容易受到病毒感染，但已经有几起攻击者在 Linux 服务器上种植其他类型的恶意软件的案例。这些案例包括：

+   **僵尸网络恶意软件**：它会导致服务器加入由远程攻击者控制的僵尸网络。其中一个更著名的案例涉及将 Linux 服务器加入了对其他网络发动*拒绝服务*攻击的僵尸网络。

+   **勒索软件**：它旨在加密用户数据，直到服务器所有者支付赎金。但即使支付了赎金，也不能保证数据能够恢复。

+   加密货币挖矿软件：它会导致服务器的 CPU 额外努力工作并消耗更多能量。被挖掘的加密货币会进入种植软件的攻击者的账户。

当然，也有很多不涉及恶意软件的侵犯，比如攻击者找到了窃取用户凭据、信用卡数据或其他敏感信息的方法。

一些安全漏洞是因为纯粹的疏忽。这是一个例子，一个粗心的 Adobe 管理员将公司的私人安全密钥放在了公共安全博客上：[`www.theinquirer.net/inquirer/news/3018010/adobe-stupidly-posts-private-pgp-key-on-its-security-blog`](https://www.theinquirer.net/inquirer/news/3018010/adobe-stupidly-posts-private-pgp-key-on-its-security-blog)。

# 那么，这是如何发生的呢？

无论你运行 Linux、Windows 还是其他系统，安全漏洞的原因通常是相同的。它们可能是操作系统中的安全漏洞，或者是运行在该操作系统上的应用程序中的安全漏洞。通常情况下，一个与漏洞相关的安全漏洞本可以通过管理员及时应用安全更新来防止。

另一个重要问题是配置不良的服务器。Linux 服务器的标准开箱即用配置实际上是相当不安全的，可能会引起一系列问题。配置不良的服务器的一个原因只是缺乏受过适当培训的人员来安全地管理 Linux 服务器。（当然，这对本书的读者来说是个好消息，因为相信我，IT 安全工作是不缺乏高薪的。）

在我们阅读本书的过程中，我们将看到如何以正确的方式做生意，使我们的服务器尽可能安全。

# 跟上安全新闻

如果您从事 IT 业务，即使您不是安全管理员，您也希望跟上最新的安全新闻。在互联网时代，这很容易做到。

首先，有很多专门从事网络安全新闻的网站。例如*Packet Storm Security*和*The Hacker News*。定期的技术新闻网站和 Linux 新闻网站，如*The INQUIRER*，*The Register*，*ZDNet*和*LXer*也会报道网络安全漏洞。如果您更喜欢观看视频而不是阅读，您会发现很多优秀的 YouTube 频道，如*BeginLinux Guru*。

最后，无论您使用哪个 Linux 发行版，请务必关注您的 Linux 发行版的新闻和当前文档。发行版维护者应该有一种方式来让您知道如果他们产品中出现了安全问题。

安全新闻网站的链接如下：

+   Packet Storm Security：[`packetstormsecurity.com/`](https://packetstormsecurity.com/)

+   The Hacker News：[`thehackernews.com/`](http://thehackernews.com/)

一般技术新闻网站的链接如下：

+   The INQUIRER：[`www.theinquirer.net/`](https://www.theinquirer.net/)

+   The Register：[`www.theregister.co.uk/`](http://www.theregister.co.uk/)

+   ZDNet：[`www.zdnet.com/`](http://www.zdnet.com/)

您还可以查看一些一般的 Linux 学习资源。Linux 新闻网站：

+   LXer：[`lxer.com/`](http://lxer.com/)

+   *BeginLinux Guru*在 YouTube 上：[`www.youtube.com/channel/UC88eard_2sz89an6unmlbeA`](https://www.youtube.com/channel/UC88eard_2sz89an6unmlbeA)

（完全披露：我是*BeginLinux Guru*。）

在阅读本书时要记住的一件事是，您将永远不会看到完全、100%安全的操作系统，它将安装在从不开机的计算机上。

# VirtualBox 和 Cygwin 简介

每当我写作或教学时，我都会尽力不让学生失眠。在整本书中，您会看到一些理论，但我主要喜欢提供好的实用信息。还会有很多逐步实践的实验。

做实验的最佳方式是使用 Linux 虚拟机。我们将做的大部分工作都适用于任何 Linux 发行版，但我们也会做一些特定于 Red Hat Enterprise Linux 或 Ubuntu Linux 的事情。（Red Hat Enterprise Linux 是企业使用最广泛的，而 Ubuntu 在云部署中最受欢迎。）

红帽是一家价值十亿美元的公司，所以毫无疑问他们在 Linux 市场上的地位。但是，由于 Ubuntu Server 是免费的，我们不能仅仅根据其母公司的价值来判断其受欢迎程度。事实是，Ubuntu Server 是最广泛使用的 Linux 发行版，用于部署基于云的应用程序。

有关详情，请参阅：[`www.zdnet.com/article/ubuntu-linux-continues-to-dominate-openstack-and-other-clouds/`](http://www.zdnet.com/article/ubuntu-linux-continues-to-dominate-openstack-and-other-clouds/)。

由于 Red Hat 是收费产品，我们将使用由 Red Hat 源代码构建并免费的 CentOS 7 来替代。您可以使用几种不同的虚拟化平台，但我自己的首选是 VirtualBox。

VirtualBox 适用于 Windows、Linux 和 Mac 主机，并且对所有这些主机都是免费的。它具有其他平台上需要付费的功能，例如创建虚拟机快照的能力。

我们将要做的一些实验将要求您模拟从主机机器到远程 Linux 服务器的连接。如果您的主机机器是 Linux 或 Mac 机器，您只需打开终端并使用内置的安全外壳工具。如果您的主机机器运行 Windows，则需要安装某种 Bash 外壳，我们将通过安装 Cygwin 来完成。

# 在 VirtualBox 中安装虚拟机

对于那些从未使用过 VirtualBox 的人，以下是一个快速入门指南：

1.  下载并安装 VirtualBox 和 VirtualBox 扩展包。您可以从以下网址获取：[`www.virtualbox.org/`](https://www.virtualbox.org/)。

1.  下载 Ubuntu Server 和 CentOS 7 的安装`.iso`文件。您可以从以下网址获取：[`www.ubuntu.com/`](https://www.ubuntu.com/)和[`www.centos.org/`](https://www.centos.org/)。

1.  启动 VirtualBox 并单击屏幕顶部的新图标。在要求的位置填写信息。将虚拟驱动器大小增加到 20 GB，但将其他所有设置保持为默认设置：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sec-hdn/img/5323d37a-850e-494b-8b2b-e34cf13972af.png)

1.  启动新的虚拟机。单击对话框框的左下角的文件夹图标，并导航到您下载的`.iso`文件存储的目录。选择以下屏幕截图中显示的 Ubuntu`.iso`文件或 CentOS`.iso`文件中的一个：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sec-hdn/img/dab65846-598e-4b54-89c9-af8ffc106097.png)

1.  单击对话框框上的“开始”按钮以开始安装操作系统。请注意，对于 Ubuntu Server，您将不会安装桌面界面。对于 CentOS 虚拟机，选择 KDE 桌面或 Gnome 桌面，如您所需。（我们将至少进行一个需要 CentOS 机器桌面界面的练习。）

1.  对另一个 Linux 发行版重复该过程。

1.  通过输入以下内容更新 Ubuntu 虚拟机：

```
 sudo apt update
 sudo apt dist-upgrade
```

1.  暂时不要更新 CentOS 虚拟机，因为我们将在下一个练习中进行更新。

在安装 Ubuntu 时，您将被要求创建一个普通用户帐户和密码。它不会要求您创建根用户密码，而是会自动将您添加到 sudo 组，以便您具有管理员特权。

当您到达 CentOS 安装程序的用户帐户创建屏幕时，请确保为您自己的用户帐户选中“使此用户成为管理员”复选框，因为默认情况下未选中。它将为您提供创建根用户密码的机会，但这完全是可选的—事实上，我从来没有这样做。

CentOS 安装程序的用户帐户创建屏幕如下所示：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sec-hdn/img/97ee3e45-b6b1-4165-bcf2-5e1e02cd6f1c.png)

# 在 CentOS 虚拟机上的 EPEL 存储库

尽管 Ubuntu 软件包存储库几乎包含了您在本课程中所需的所有内容，但 CentOS 软件包存储库—我们可以说—是不足的。为了在 CentOS 实验中使用所需的软件包，您需要安装**EPEL**（企业 Linux 的额外软件包）存储库。（EPEL 项目由 Fedora 团队运行。）当您在 Red Hat 和 CentOS 系统上安装第三方存储库时，您还需要安装一个`priorities`软件包，并编辑`.repo`文件以为每个存储库设置适当的优先级。这将防止第三方存储库的软件包覆盖官方的 Red Hat 和 CentOS 软件包，如果它们恰好具有相同的名称。以下步骤将帮助您安装所需的软件包并编辑`.repo`文件：

1.  您需要安装 EPEL 的两个软件包在正常的 CentOS 存储库中。运行以下命令：

```
 sudo yum install yum-plugin-priorities epel-release
```

1.  安装完成后，转到`/etc/yum.repos.d`目录，并在您喜欢的文本编辑器中打开`CentOS-Base.repo`文件。在`base`、`updates`和`extras`部分的最后一行之后，添加一行`priority=1`。在`centosplus`部分的最后一行之后，添加一行`priority=2`。保存文件并关闭编辑器。您编辑过的每个部分应该看起来像这样（除了适当的名称和优先级数字）：

```
        [base]
        name=CentOS-$releasever - Base
        mirrorlist=http://mirrorlist.centos.org/?
        release=$releasever&arch=$basearch&repo=os&infra=$infra
          #baseurl=http://mirror.centos.org/centos/
           $releasever/os/$basearch/
        gpgcheck=1
        gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-7
        priority=1
```

1.  打开`epel.repo`文件进行编辑。在`epel`部分的最后一行之后，添加一行`priority=10`。在每个剩余部分的最后一行之后，添加一行`priority=11`。

1.  更新系统，然后通过运行以下命令创建已安装和可用软件包的列表：

```
 sudo yum upgrade
 sudo yum list > yum_list.txt
```

# 为 VirtualBox 虚拟机配置网络

我们的一些培训场景将要求您模拟连接到远程服务器。您可以通过使用主机机器连接到虚拟机来实现这一点。当您首次在 VirtualBox 上创建虚拟机时，网络设置为 NAT 模式。为了从主机连接到虚拟机，您需要将虚拟机的网络适配器设置为桥接适配器模式。以下是您可以执行此操作的方法：

1.  关闭您已经创建的任何虚拟机。

1.  在 VirtualBox 管理器屏幕上，打开虚拟机的设置对话框。

1.  单击网络菜单项，并将附加到设置从 NAT 更改为桥接适配器：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sec-hdn/img/1922abb1-ca77-4d89-83b4-a878720d7533.png)

1.  展开高级项目，并将混杂模式设置更改为允许全部：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sec-hdn/img/140d886d-3721-41ae-b61e-d8c2ea6cb77e.png)

1.  重新启动虚拟机并设置其使用静态 IP 地址。

如果您从子网范围的高端分配静态 IP 地址，将更容易防止与从互联网网关分配的低号 IP 地址发生冲突。

# 使用 VirtualBox 创建虚拟机快照

与虚拟机一起工作的一个美妙之处是，如果出现问题，您可以创建快照并回滚到快照。使用 VirtualBox，这很容易做到。

1.  在 VirtualBox 管理器屏幕的右上角，单击“快照”按钮：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sec-hdn/img/09d49f2f-e616-4403-9da7-d9e7c8c949c4.png)

1.  在屏幕中间的左侧，您将看到一个相机图标。单击该图标以打开快照对话框。要么填写所需的快照名称，要么接受默认名称。可选地，您可以创建一个描述：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sec-hdn/img/6ec078e5-0ff4-4751-94d4-77b555203215.png)

1.  在对虚拟机进行更改后，您可以通过关闭虚拟机，然后右键单击快照名称并选择适当的菜单项来回滚到快照：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sec-hdn/img/b5852d38-9e29-4f31-adf7-2a9fa2e8e1d2.png)

# 使用 Cygwin 连接到您的虚拟机

如果您的主机机器是 Linux 或 Mac 机器，您只需打开主机的终端并使用已经存在的工具连接到虚拟机。但是，如果您正在运行 Windows 机器，您需要安装某种 Bash shell 并使用其网络工具。Windows 10 Pro 现在带有由 Ubuntu 人员提供的 Bash shell，如果您愿意，可以使用它。但是，如果您没有 Windows 10 Pro，或者如果您更喜欢使用其他东西，您可以考虑 Cygwin。

Cygwin 是 Red Hat 公司的一个项目，是专为 Windows 构建的免费开源 Bash shell。它是免费的，而且易于安装。

# 在 Windows 主机上安装 Cygwin

以下是一个快速的 Cygwin 入门指南：

1.  在主机机器的浏览器中，从以下网址下载适用于您的 Windows 版本的适当的`setup*.exe`文件：[`www.cygwin.com/`](http://www.cygwin.com/)。

1.  双击设置图标开始安装。在大多数情况下，只需接受默认值，直到您到达软件包选择屏幕。 （唯一的例外是您选择下载镜像的屏幕。）

1.  在软件包选择屏幕的顶部，从“视图”菜单中选择“类别”：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sec-hdn/img/a7955ecd-56fb-4cc9-b120-4f1f57754662.png)

1.  展开“网络”类别：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sec-hdn/img/aa78f65c-4fcf-41bc-9753-2bdf7e80d2e4.png)

1.  向下滚动，直到看到 openssh 软件包。在“新”列下，点击“跳过”。（这将导致“跳过”位置出现版本号。）

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sec-hdn/img/d2faa751-5cf6-427f-b7d1-581c69445eca.png)

1.  在您选择了适当的软件包之后，您的屏幕应该是这样的：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sec-hdn/img/0cc4c271-38a6-41a2-8ecb-663d8c60157a.png)

1.  在右下角，点击“下一步”。如果出现“解决依赖关系”屏幕，请也点击“下一步”。

1.  保留您下载的安装文件，因为您稍后将使用它来安装更多软件包，或者更新 Cygwin。（当您打开 Cygwin 时，任何更新的软件包将显示在“视图”菜单上的“待处理”视图中。）

1.  一旦您从 Windows“开始”菜单中打开 Cygwin，您可以根据需要调整其大小，并使用*Ctrl* + *+*或*Ctrl* + *-*键组合来调整字体大小：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sec-hdn/img/d6812407-13b9-4495-bcf2-03d46fec1930.png)

# 总结

所以，我们已经很好地开始了我们的 Linux 安全和加固之旅。在本章中，我们看到了为什么了解如何保护和加固 Linux 系统与了解如何保护和加固 Windows 系统一样重要。我们提供了一些例子，说明了一个配置不良的 Linux 系统是如何被入侵的，并且我们提到了学习 Linux 安全对您的职业发展是有好处的。之后，我们看了如何使用 VirtualBox 和 Cygwin 设置虚拟化实验室环境。

在下一章中，我们将看看如何锁定用户账户，并确保错误的人永远不会获得管理员特权。到时见。


# 第二章：保护用户账户

管理用户是 IT 管理中更具挑战性的方面之一。您需要确保用户始终可以访问其内容，并且可以执行所需的任务来完成工作。您还需要确保用户的内容始终受到未经授权用户的保护，并且用户不能执行与其工作描述不符的任何任务。这是一个艰巨的任务，但我们的目标是表明这是可行的。

在本章中，我们将涵盖以下主题：

+   以 root 用户登录的危险

+   使用 sudo 的优势

+   如何为完整的管理用户和仅具有特定委派权限的用户设置 sudo 权限

+   使用 sudo 的高级技巧和技巧

+   锁定用户的主目录

+   强制执行强密码标准

+   设置和强制执行密码和帐户过期

+   防止暴力破解密码攻击

+   锁定用户帐户

+   设置安全横幅

# 以 root 用户登录的危险

Unix 和 Linux 操作系统相对于 Windows 的一个巨大优势是，Unix 和 Linux 更好地将特权管理帐户与普通用户帐户分开。事实上，旧版本的 Windows 容易受到安全问题的影响，例如**随意**病毒感染，一个常见的做法是设置具有管理权限的用户帐户，而没有新版本 Windows 中的**用户访问控制**的保护。（即使有用户访问控制，Windows 系统仍然会被感染，只是不太频繁。）在 Unix 和 Linux 中，更难以感染一个正确配置的系统。

您可能已经知道 Unix 或 Linux 系统上的超级管理员帐户是 root 帐户。如果您以 root 用户身份登录，您可以对该系统执行任何您想要执行的操作。因此，您可能会认为，“是的，这很方便，所以我会这样做。”但是，始终以 root 用户登录可能会带来一系列安全问题。考虑以下。以 root 用户登录可能会：

+   使您更容易意外执行导致系统损坏的操作

+   使其他人更容易执行导致系统损坏的操作

因此，如果您总是以 root 用户登录，甚至只是使 root 用户帐户容易访问，可以说您正在为攻击者和入侵者做很大一部分工作。此外，想象一下，如果您是一家大公司的 Linux 管理员，允许用户执行管理员任务的唯一方法是给他们所有的 root 密码。如果其中一个用户离开公司会发生什么？您不希望该人仍然有能力登录系统，因此您必须更改密码并将新密码分发给所有其他用户。而且，如果您只希望用户对某些任务具有管理员权限，而不是具有完整的 root 权限呢？

我们需要一种机制，允许用户执行管理任务，而不会冒着他们始终以 root 用户登录的风险，并且还允许用户仅具有他们真正需要执行某项工作的管理权限。在 Linux 和 Unix 中，我们通过 sudo 实用程序实现了这种机制。

# 使用 sudo 的优势

正确使用，sudo 实用程序可以极大地增强系统的安全性，并且可以使管理员的工作更加轻松。使用 sudo，您可以执行以下操作：

+   为某些用户分配完整的管理权限，同时为其他用户分配他们需要执行与其工作直接相关的任务所需的权限。

+   允许用户通过输入其自己的普通用户密码执行管理任务，以便您不必将 root 密码分发给每个人和他的兄弟。

+   增加入侵者进入系统的难度。如果您实施了 sudo 并禁用了 root 用户帐户，潜在的入侵者将不知道要攻击哪个帐户，因为他们不知道哪个帐户具有管理员权限。

+   创建 sudo 策略，即使网络中有 Unix、BSD 和 Linux 混合的机器，也可以在整个企业网络中部署。

+   提高您的审计能力，因为您将能够看到用户如何使用他们的管理员权限。

关于最后一条要点，考虑一下我 CentOS 7 虚拟机的`secure`日志中的以下片段：

```
Sep 29 20:44:33 localhost sudo: donnie : TTY=pts/0 ; PWD=/home/donnie ; USER=root ; COMMAND=/bin/su -
Sep 29 20:44:34 localhost su: pam_unix(su-l:session): session opened for user root by donnie(uid=0)
Sep 29 20:50:39 localhost su: pam_unix(su-l:session): session closed for user root
```

您可以看到，我使用`su -`登录到 root 命令提示符，然后退出登录。当我登录时，我做了一些需要 root 权限的事情，但没有记录下来。但记录下来的是我使用 sudo 做的事情。也就是说，因为这台机器上禁用了 root 帐户，我使用了我的 sudo 特权来让`su -`为我工作。让我们看另一个片段，以展示更多关于这是如何工作的细节：

```
Sep 29 20:50:45 localhost sudo: donnie : TTY=pts/0 ; PWD=/home/donnie ; USER=root ; COMMAND=/bin/less /var/log/secure
Sep 29 20:55:30 localhost sudo: donnie : TTY=pts/0 ; PWD=/home/donnie ; USER=root ; COMMAND=/sbin/fdisk -l
Sep 29 20:55:40 localhost sudo: donnie : TTY=pts/0 ; PWD=/home/donnie ; USER=root ; COMMAND=/bin/yum upgrade
Sep 29 20:59:35 localhost sudo: donnie : TTY=tty1 ; PWD=/home/donnie ; USER=root ; COMMAND=/bin/systemctl status sshd
Sep 29 21:01:11 localhost sudo: donnie : TTY=tty1 ; PWD=/home/donnie ; USER=root ; COMMAND=/bin/less /var/log/secure
```

这一次，我使用我的 sudo 特权来打开一个日志文件，查看我的硬盘配置，执行系统更新，检查安全外壳守护程序的状态，再次查看日志文件。因此，如果您是我公司的安全管理员，您将能够看到我是否滥用了我的 sudo 权限。

现在，您可能会问，“*有什么办法阻止一个人只是做一个 sudo su - 以防止他或她的不端行为被发现吗？*” 这很容易。只是不要给人们去 root 命令提示符的权限。

# 为完整的管理员用户设置 sudo 权限

在我们看如何限制用户的操作之前，让我们首先看一下如何允许用户做任何事情，包括登录到 root 命令提示符。有几种方法可以做到这一点。

# 方法 1 - 将用户添加到预定义的管理员组

第一种方法，也是最简单的方法，是将用户添加到预定义的管理员组，然后，如果尚未完成，配置 sudo 策略以允许该组完成其工作。这很简单，只是不同的 Linux 发行版系列使用不同的管理员组。

在 Unix、BSD 和大多数 Linux 系统上，您可以将用户添加到`wheel`组中。 (红帽家族的成员，包括 CentOS，属于这个类别。) 当我在我的 CentOS 机器上执行`groups`命令时，我得到了这个：

```
[donnie@localhost ~]$ groups
donnie wheel
[donnie@localhost ~]$
```

这表明我是`wheel`组的成员。通过执行`sudo visudo`，我将打开 sudo 策略文件。向下滚动，我们将看到赋予`wheel`组强大权限的行：

```
## Allows people in group wheel to run all commands
%wheel ALL=(ALL) ALL
```

百分号表示我们正在使用一个组。三个 ALL 表示该组的成员可以在部署了此策略的网络中的任何计算机上，作为任何用户执行任何命令。唯一的小问题是组成员将被提示输入他们自己的普通用户帐户密码以执行 sudo 任务。再往下滚动一点，你会看到以下内容：

```
## Same thing without a password
# %wheel ALL=(ALL) NOPASSWD: ALL
```

如果我们注释掉前面片段中的`%wheel`行，并从此片段中的`%wheel`行前面删除注释符号，那么`wheel`组的成员将能够在不输入任何密码的情况下执行所有 sudo 任务。这是我真的不建议的事情，即使在家庭使用中也是如此。在商业环境中，允许人们拥有无密码 sudo 权限是绝对不可以的。

要将现有用户添加到`wheel`组中，使用`usermod`命令和`-G`选项。您可能还想使用`-a`选项，以防止将用户从其他组中删除。对于我们的示例，让我们添加 Maggie：

```
sudo usermod -a -G wheel maggie
```

您还可以在创建用户帐户时将其添加到`wheel`组中。现在让我们为 Frank 做到这一点：

```
sudo useradd -G wheel frank
```

请注意，使用`useradd`时，我假设我们正在使用红帽系列的操作系统，该操作系统具有预定义的默认设置来创建用户账户。对于使用`wheel`组的非红帽类型的发行版，您需要重新配置默认设置或使用额外的选项开关来创建用户的主目录并分配正确的 shell。您的命令可能如下所示：

**`sudo useradd -G wheel -m -d /home/frank -s /bin/bash frank`**

对于 Debian 系列的成员，包括 Ubuntu，程序是相同的，只是您将使用`sudo`组而不是`wheel`组。 （考虑到 Debian 人一直以来都是与众不同的，这种情况似乎是合理的。）

这种技术会在以下情况下非常有用，即当您需要在 Rackspace、DigitalOcean 或 Vultr 等云服务上创建虚拟专用服务器时。当您登录到这些服务并最初创建虚拟机时，云服务将要求您以 root 用户身份登录到该虚拟机。（即使在 Ubuntu 上也会发生这种情况，尽管在进行本地安装 Ubuntu 时会禁用 root 用户帐户。）

在这种情况下，您首先要做的是为自己创建一个普通用户帐户，并为其提供完整的 sudo 权限。然后，退出 root 帐户并使用普通用户帐户重新登录。然后，您将需要使用以下命令禁用 root 帐户：

**`sudo passwd -l root`**

您还需要进行一些额外的配置来锁定安全外壳访问，但我们将在第四章中进行介绍，*加密和 SSH 加固*。

# 方法 2 - 在 sudo 策略文件中创建条目

好的，将用户添加到`wheel`组或`sudo`组对于只使用一个这两个管理组的单个计算机或部署 sudo 策略的网络非常有效。但是，如果您想要在既有红帽又有 Ubuntu 机器的网络上部署 sudo 策略，或者如果您不想去每台机器上添加用户到管理员组，那么只需在 sudo 策略文件中创建一个条目。您可以为单个用户创建条目，也可以创建用户别名。如果在您的 CentOS 虚拟机上执行`sudo visudo`，您将看到一个已注释的用户别名示例：

```
# User_Alias ADMINS = jsmith, mikem
```

您可以取消注释此行并添加您自己的一组用户名，或者您可以只添加一个包含您自己用户别名的行。要为用户别名的成员提供完整的 sudo 权限，请添加另一行，看起来像这样：

```
ADMINS ALL=(ALL) ALL
```

还可以为单个用户添加`visudo`条目，在非常特殊的情况下可能需要这样做。例如：

```
frank ALL=(ALL) ALL
```

但为了便于管理，最好选择用户组或用户别名。

sudo 策略文件是`/etc/sudoers`文件。我总是犹豫告诉学生这一点，因为偶尔会有学生尝试在常规文本编辑器中编辑它。但这是行不通的，请不要尝试。请始终使用命令`sudo visudo`编辑`sudoers`。

# 为仅具有特定委派权限的用户设置 sudo

IT 安全哲学的一个基本原则是为网络用户提供足够的权限，以便他们完成工作，但不得超出此范围。因此，您希望尽可能少的人拥有完整的 sudo 权限。（如果启用了 root 用户帐户，则希望更少的人知道 root 密码。）您还希望根据其具体工作来委派权限给人员。备份管理员将需要执行备份任务，帮助台人员将需要执行用户管理任务，依此类推。使用 sudo，您可以委派这些权限，并禁止用户执行与其工作描述不符的任何其他管理工作。

解释这一点的最好方法是让您在 CentOS 虚拟机上打开`visudo`。因此，继续启动 CentOS VM 并输入以下命令：

```
sudo visudo
```

与 Ubuntu 不同，CentOS 有一个完全注释和有文档的`sudoers`文件。我已经向您展示了创建`ADMIN`用户别名的行，您可以为其他目的创建其他用户别名。例如，您可以为备份管理员创建`BACKUPADMINS`用户别名，为 Web 服务器管理员创建`WEBADMINS`用户别名，或者任何其他您想要的。因此，您可以添加类似以下内容的行：

```
User_Alias SOFTWAREADMINS = vicky, cleopatra
```

这很好，除了 Vicky 和 Cleopatra 仍然无法做任何事情。您需要将一些职责分配给用户别名。

如果您查看稍后提到的示例用户别名，您将看到一个示例`Command Aliases`列表。其中一个例子恰好是`SOFTWARE`，其中包含管理员需要安装或删除软件或更新系统的命令。它被注释掉，就像所有其他示例命令别名一样，因此您需要在使用之前从行首删除井号符号：

```
Cmnd_Alias SOFTWARE = /bin/rpm, /usr/bin/up2date, /usr/bin/yum
```

现在，只需将`SOFTWARE`命令别名分配给`SOFTWAREADMINS`用户别名即可：

```
SOFTWAREADMINS ALL=(ALL) SOFTWARE
```

`SOFTWAREADMINS`用户别名的成员 Vicky 和 Cleopatra 现在可以以 root 权限运行`rpm`、`up2date`和`yum`命令。

在取消注释并将它们分配给用户、组或用户别名之后，除了一个预定义的命令别名都可以使用。唯一的例外是`SERVICES`命令别名：

```
Cmnd_Alias SERVICES = /sbin/service, /sbin/chkconfig, /usr/bin/systemctl start, /usr/bin/systemctl stop, /usr/bin/systemctl reload, /usr/bin/systemctl restart, /usr/bin/systemctl status, /usr/bin/systemctl enable, /usr/bin/systemctl disable
```

`SERVICES`别名的问题在于它还列出了`systemctl`命令的不同子命令。sudo 的工作方式是，如果一个命令单独列出，那么分配的用户可以使用该命令的任何子命令、选项或参数。因此，在`SOFTWARE`示例中，`SOFTWARE`用户别名的成员可以运行如下命令：

```
sudo yum upgrade
```

但是，当命令在命令别名中列出时带有子命令、选项或参数，那么分配给命令别名的任何人都可以运行。在当前配置中，`SERVICES`命令别名中的`systemctl`命令就无法工作。为了了解原因，让我们将 Charlie 和 Lionel 设置为`SERVICESADMINS`用户别名，然后取消注释`SERVICES`命令别名，就像我们之前已经做过的那样：

```
User_Alias SERVICESADMINS = charlie, lionel
SERVICESADMINS ALL=(ALL) SERVICES
```

现在，看看当 Lionel 尝试检查 Secure Shell 服务的状态时会发生什么：

```
[lionel@centos-7 ~]$ sudo systemctl status sshd
[sudo] password for lionel:
Sorry, user lionel is not allowed to execute '/bin/systemctl status sshd' as root on centos-7.xyzwidgets.com.
[lionel@centos-7 ~]$
```

好吧，所以 Lionel 可以运行`sudo systemctl status`，这几乎没有用，但他无法做任何有意义的事情，比如指定他想要检查的服务。这有点问题。有两种方法可以解决这个问题，但只有一种方法是您想要使用的。您可以删除所有`systemctl`子命令，并使`SERVICES`别名看起来像这样：

```
Cmnd_Alias SERVICES = /sbin/service, /sbin/chkconfig, /usr/bin/systemctl
```

但是，如果这样做，Lionel 和 Charlie 也将能够关闭或重新启动系统，编辑服务文件，或将机器从一个 systemd 目标更改为另一个。这可能不是您想要的。因为`systemctl`命令涵盖了许多不同的功能，您必须小心，不要允许委派用户访问太多这些功能。更好的解决方案是为每个`systemctl`子命令添加通配符：

```
Cmnd_Alias SERVICES = /sbin/service, /sbin/chkconfig, /usr/bin/systemctl start *, /usr/bin/systemctl stop *, /usr/bin/systemctl reload *, /usr/bin/systemctl restart *, /usr/bin/systemctl status *, /usr/bin/systemctl enable *, /usr/bin/systemctl disable *
```

现在，Lionel 和 Charlie 可以执行此命令别名中列出的任何服务的`systemctl`功能：

```
[lionel@centos-7 ~]$ sudo systemctl status sshd
[sudo] password for lionel:
● sshd.service - OpenSSH server daemon
 Loaded: loaded (/usr/lib/systemd/system/sshd.service; enabled; vendor preset: enabled)
 Active: active (running) since Sat 2017-09-30 18:11:22 EDT; 23min ago
 Docs: man:sshd(8)
 man:sshd_config(5)
 Main PID: 13567 (sshd)
 CGroup: /system.slice/sshd.service
 └─13567 /usr/sbin/sshd -D

Sep 30 18:11:22 centos-7.xyzwidgets.com systemd[1]: Starting OpenSSH server daemon...
Sep 30 18:11:22 centos-7.xyzwidgets.com sshd[13567]: Server listening on 0.0.0.0 port 22.
Sep 30 18:11:22 centos-7.xyzwidgets.com sshd[13567]: Server listening on :: port 22.
Sep 30 18:11:22 centos-7.xyzwidgets.com systemd[1]: Started OpenSSH server daemon.
[lionel@centos-7 ~]$
```

请记住，您不仅限于使用用户别名和命令别名。您还可以将特权分配给 Linux 组或个别用户。您还可以将单个命令分配给用户别名、Linux 组或个别用户。例如：

```
katelyn ALL=(ALL) STORAGE
gunther ALL=(ALL) /sbin/fdisk -l
%backup_admins ALL=(ALL) BACKUP
```

Katelyn 现在可以执行`STORAGE`命令别名中的所有命令，而 Gunther 只能使用`fdisk`来查看分区表。`backup_admins` Linux 组的成员可以执行`BACKUP`命令别名中的命令。

我们将在这个主题中看到的最后一件事是主机别名示例，这些示例出现在用户别名示例之前：

```
# Host_Alias     FILESERVERS = fs1, fs2
# Host_Alias     MAILSERVERS = smtp, smtp2
```

每个主机别名由服务器主机名列表组成。这样可以让您在一台机器上创建一个`sudoers`文件，并在整个网络上部署它。例如，您可以创建一个`WEBSERVERS`主机别名，一个`WEBADMINS`用户别名，以及一个`WEBCOMMANDS`命令别名，并附带适当的命令。

你的配置看起来应该是这样的：

```
Host_Alias    WEBSERVERS = webserver1, webserver2
User_Alias    WEBADMINS = junior, kayla
Cmnd_Alias    WEBCOMMANDS = /usr/bin/systemctl status httpd, /usr/bin/systemctl start httpd, /usr/bin/systemctl stop httpd, /usr/bin/systemctl restart httpd

WEBADMINS    WEBSERVERS=(ALL) WEBCOMMANDS
```

现在，当用户在网络上的服务器上键入命令时，sudo 首先查看该服务器的主机名。如果用户被授权在该服务器上执行该命令，那么 sudo 允许它。否则，sudo 拒绝它。在中小型企业中，手动将主`sudoers`文件复制到网络上的所有服务器可能会很好用。但是，在大型企业中，您需要简化和自动化这个过程。为此，您可以使用 Puppet、Chef 或 Ansible 等工具。 （这三种技术超出了本书的范围，但您可以在 Packt 网站上找到关于它们三者的大量书籍和视频课程。）

所有这些技术在您的 Ubuntu VM 上以及在 CentOS VM 上都可以使用。唯一的问题是，Ubuntu 没有预定义的命令别名，所以你必须自己输入它们。

无论如何，我知道你已经厌倦了阅读，所以让我们开始工作吧。

# 分配有限 sudo 特权的实践实验

在这个实验中，您将创建一些用户并为他们分配不同级别的特权。为了简化，我们将使用 CentOS 虚拟机。

1.  登录到 CentOS 虚拟机，并为 Lionel、Katelyn 和 Maggie 创建用户帐户：

```
 sudo useradd lionel
 sudo ueradd katelyn
 sudo useradd maggie
 sudo passwd lionel
 sudo passwd katelyn
 sudo passwd maggie
```

1.  打开`visudo`：

```
        sudo visudo
```

找到`STORAGE`命令别名，并从其前面删除注释符号。

1.  在文件末尾添加以下行，使用制表符分隔列：

```
        lionel     ALL=(ALL)    ALL
        katelyn  ALL=(ALL) /usr/bin/systemctl status sshd
        maggie  ALL=(ALL) STORAGE
```

保存文件并退出`visudo`。

1.  为了节省时间，我们将使用`su`来登录不同的用户账户。您不需要注销自己的帐户来执行这些步骤。首先，登录 Lionel 的帐户，并通过运行几个 root 级别的命令来验证他是否拥有完整的 sudo 特权：

```
 su - lionel
 sudo su -
 exit
 sudo systemctl status sshd
 sudo fdisk -l
 exit
```

1.  这次，以 Katelyn 的身份登录，并尝试运行一些 root 级别的命令。（不过，如果它们不都起作用，也不要太失望。）

```
 su - katelyn
 sudo su -
 sudo systemctl status sshd
 sudo systemctl restart sshd
 sudo fdisk -l
 exit
```

1.  最后，以 Maggie 的身份登录，并运行为 Katelyn 运行的相同一组命令。

1.  请记住，尽管我们在这个实验中只有三个单独的用户，但你可以通过在用户别名或 Linux 组中设置它们来处理更多的用户。

由于 sudo 是一个很好的安全工具，你会认为每个人都会使用它，对吧？遗憾的是，情况并非如此。几乎每当你查看 Linux 教程网站或 Linux 教程 YouTube 频道时，你都会看到正在进行演示的人以 root 用户命令提示符登录。在某些情况下，我甚至看到远程登录云虚拟机时以 root 用户身份登录的人。现在，如果已经以 root 用户身份登录是一个坏主意，那么通过互联网以 root 用户身份登录就更糟糕了。无论如何，看到每个人都从 root 用户的 shell 进行教程演示让我非常疯狂。

尽管说了这么多，有一些事情在 sudo 中是行不通的。Bash shell 内部命令，比如`cd`不能使用它，将内核值注入`/proc`文件系统也不能使用它。对于这样的任务，一个人必须转到 root 命令提示符。尽管如此，确保只有绝对需要使用 root 用户命令提示符的用户才能访问它。

# 使用 sudo 的高级技巧和技巧

现在我们已经了解了设置良好的 sudo 配置的基础知识，我们面临一个悖论。也就是说，尽管 sudo 是一个安全工具，但你可以用它做的某些事情可能会使你的系统比以前更不安全。让我们看看如何避免这种情况。

# sudo 计时器

默认情况下，sudo 计时器设置为 5 分钟。这意味着一旦用户执行了一个`sudo`命令并输入了密码，他或她可以在 5 分钟内执行另一个`sudo`命令，而无需再次输入密码。尽管这显然很方便，但如果用户离开他们的桌子时仍然保持命令终端打开，这也可能会有问题。如果 5 分钟计时器尚未到期，其他人可能会来执行一些根级任务。如果您的安全需求需要，您可以通过向`sudoers`文件的`Defaults`部分添加一行来轻松禁用此计时器。这样，用户每次运行`sudo`命令时都必须输入他们的密码。您可以将此设置为所有用户的全局设置，也可以仅为某些个别用户设置。

# 禁用 sudo 计时器的实践实验

在本实验中，您将禁用 CentOS VM 上的 sudo 计时器。

1.  登录到您用于上一个实验的相同的 CentOS 虚拟机。我们将使用您已经创建的用户帐户。

1.  在您自己的用户帐户命令提示符下，输入以下命令：

```
 sudo fdisk -l
 sudo systemctl status sshd
 sudo iptables -L
```

您会发现您只需要输入一次密码就可以执行所有三个命令。

1.  使用以下命令打开`visudo`：

```
        sudo visudo
```

在文件的`Defaults`规范部分中，添加以下行：

```
        Defaults     timestamp_timeout = 0
```

保存文件并退出`visudo`。

1.  执行您在*步骤 2*中执行的命令。这一次，您会发现每次都需要输入密码。

1.  打开`visudo`并修改您添加的行，使其看起来像这样：

```
        Defaults:lionel     timestamp_timeout = 0
```

保存文件并退出`visudo`。

1.  从您自己的帐户 shell 中，重复您在*步骤 2*中执行的命令。然后，以 Lionel 的身份登录并再次执行命令。

1.  请注意，这个相同的过程也适用于 Ubuntu。

# 防止用户具有 root shell 访问权限

假设您想要为具有有限 sudo 特权的用户设置一个用户，但是您通过添加类似于以下内容的行来实现：

```
maggie     ALL=(ALL)     /bin/bash, /bin/zsh
```

很抱歉告诉您，您根本没有限制 Maggie 的访问权限。您实际上给了她 Bash shell 和 Zsh shell 的完全 sudo 特权。因此，请不要像这样向您的`sudoers`添加行，因为这会给您带来麻烦。

# 防止用户使用 shell 转义

某些程序，特别是文本编辑器和分页器，具有方便的*shell 转义*功能。这允许用户在不必先退出程序的情况下运行 shell 命令。例如，在 Vi 和 Vim 编辑器的命令模式中，某人可以通过执行`:!ls`来运行`ls`命令。执行该命令将如下所示：

```
# useradd defaults file
GROUP=100
HOME=/home
INACTIVE=-1
EXPIRE=
SHELL=/bin/bash
SKEL=/etc/skel
CREATE_MAIL_SPOOL=yes

~
~
:!ls
```

输出将如下所示：

```
[donnie@localhost default]$ sudo vim useradd
[sudo] password for donnie:

grub nss useradd

Press ENTER or type command to continue
grub nss useradd

Press ENTER or type command to continue
```

现在，假设您希望 Frank 能够编辑`sshd_config`文件，仅限于该文件。您可能会诱惑添加一行到您的 sudo 配置，看起来像这样：

```
frank     ALL=(ALL)     /bin/vim /etc/ssh/sshd_config
```

这看起来应该可以工作，对吧？但实际上不行，因为一旦 Frank 使用他的 sudo 特权打开了`sshd_config`文件，他就可以使用 Vim 的 shell 转义功能执行其他根级命令，这将包括能够编辑其他配置文件。您可以通过让 Frank 使用`sudoedit`而不是 vim 来解决这个问题：

```
frank     ALL=(ALL)     sudoedit /etc/ssh/sshd_config
```

`sudoedit`没有 shell 转义功能，因此您可以安全地允许 Frank 使用它。

其他具有 shell 转义功能的程序包括以下内容：

+   emacs

+   less

+   view

+   more

# 防止用户使用其他危险程序

即使没有 shell 转义功能的某些程序，如果您给予用户无限制的使用特权，仍然可能会很危险。这些包括以下内容：

+   cat

+   cut

+   awk

+   sed

如果您必须授予某人 sudo 特权以使用其中一个程序，最好将其使用限制在特定文件中。这就引出了我们的下一个提示。

# 限制用户使用命令的操作

假设您创建了一个 sudo 规则，以便 Sylvester 可以使用`systemctl`命令：

```
sylvester     ALL=(ALL) /usr/bin/systemctl
```

这使得 Sylvester 可以充分利用`systemctl`的功能。他可以控制守护进程，编辑服务文件，关闭或重启，以及`systemctl`的其他功能。这可能不是你想要的。最好指定 Sylvester 被允许执行哪些`systemctl`功能。假设你希望他只能控制安全外壳服务。你可以让这行看起来像这样：

```
sylvester     ALL=(ALL) /usr/bin/systemctl * sshd
```

Sylvester 现在可以做所有他需要做的安全外壳服务的事情，但他不能关闭或重启系统，编辑服务文件，或更改 systemd 目标。但是，如果你希望 Sylvester 只能对安全外壳服务执行某些特定的操作呢？那么，你将不得不省略通配符，并指定你希望 Sylvester 执行的所有操作：

```
sylvester     ALL=(ALL) /usr/bin/systemctl status sshd, /usr/bin/systemctl restart sshd
```

现在，Sylvester 只能重新启动安全外壳服务或检查其状态。

在编写 sudo 策略时，你需要了解网络上不同 Linux 和 Unix 发行版之间的差异。例如，在 Red Hat 7 和 CentOS 7 系统上，`systemctl`二进制文件位于`/usr/bin`目录中。在 Debian/Ubuntu 系统上，它位于`/bin`目录中。如果你必须向混合操作系统的大型企业网络部署`sudoers`文件，你可以使用主机别名来确保服务器只允许执行适合其操作系统的命令。

此外，要注意一些系统服务在不同的 Linux 发行版上有不同的名称。在红帽和 CentOS 系统上，安全外壳服务是`sshd`。在 Debian/Ubuntu 系统上，它只是普通的`ssh`。

# 让用户以其他用户身份运行

在下面的这行中，`(ALL)`表示 Sylvester 可以以任何用户身份运行`systemctl`命令：

```
sylvester     ALL=(ALL) /usr/bin/systemctl status sshd, /usr/bin/systemctl restart sshd
```

这实际上给了 Sylvester 这些命令的 root 权限，因为 root 用户绝对是任何用户。如果需要的话，可以将`(ALL)`更改为`(root)`，以指定 Sylvester 只能以 root 用户身份运行这些命令：

```
sylvester     ALL=(root) /usr/bin/systemctl status sshd, /usr/bin/systemctl restart sshd
```

好吧，可能没有太多意义，因为没有什么改变。Sylvester 以前对这些`systemctl`命令拥有 root 权限，现在仍然拥有。但是，这个功能还有更多实际的用途。假设 Vicky 是数据库管理员，你希望她以`database`用户身份运行：

```
vicky    ALL=(database)    /usr/local/sbin/some_database_script.sh
```

然后 Vicky 可以以`database`用户的身份运行该命令，输入以下代码：

```
sudo -u database some_database_script.sh
```

这是一个你可能不经常使用的功能，但无论如何要记住。你永远不知道什么时候会派上用场。

好了，这就结束了我们对 sudo 的讨论。现在让我们把注意力转向确保我们普通用户的安全。

# 以红帽或 CentOS 的方式锁定用户的主目录

这是另一个领域，不同的 Linux 发行版家族之间的业务方式不同。正如我们将看到的，每个发行版家族都有不同的默认安全设置。监督不同 Linux 发行版混合环境的安全管理员需要考虑到这一点。

红帽企业 Linux 及其所有后代，如 CentOS，有一个美好的特点，就是它们的开箱即用安全性比其他任何 Linux 发行版都要好。这使得加固红帽类型系统变得更快更容易，因为很多工作已经完成。其中一个已经为我们完成的工作是锁定用户的主目录：

```
[donnie@localhost home]$ sudo useradd charlie
[sudo] password for donnie:
[donnie@localhost home]$

[donnie@localhost home]$ ls -l
total 0
drwx------. 2 charlie charlie 59 Oct 1 15:25 charlie
drwx------. 2 donnie donnie 79 Sep 27 00:24 donnie
drwx------. 2 frank frank 59 Oct 1 15:25 frank
[donnie@localhost home]$
```

在红帽类型系统上，默认情况下，`useradd`实用程序创建权限设置为`700`的用户主目录。这意味着只有拥有主目录的用户可以访问它。所有其他普通用户都被锁定了。我们可以通过查看`/etc/login.defs`文件来了解原因。向文件底部滚动，你会看到：

```
CREATE_HOME     yes
UMASK 077
```

`login.defs`文件是两个文件之一，用于配置`useradd`的默认设置。这个`UMASK`行决定了在创建家目录时的权限值。红帽类型的发行版将其配置为`077`值，这将从*组*和*其他*中删除所有权限。这个`UMASK`行在所有 Linux 发行版的`login.defs`文件中，但是红帽类型的发行版是唯一一个默认将`UMASK`设置为如此严格值的发行版。非红帽类型的发行版通常将`UMASK`值设置为`022`，这将创建权限值为`755`的家目录。这允许每个人进入其他人的家目录并访问彼此的文件。

# 以 Debian/Ubuntu 方式锁定用户的家目录

Debian 及其后代，如 Ubuntu，有两个用户创建实用程序：

+   Debian/Ubuntu 上的`useradd`

+   Debian/Ubuntu 上的`adduser`

# Debian/Ubuntu 上的 useradd

`useradd`实用程序是存在的，但是 Debian 和 Ubuntu 没有像 Red Hat 和 CentOS 那样方便的预配置默认设置。如果您在默认的 Debian/Ubuntu 机器上只是执行`sudo useradd frank`，Frank 将没有家目录，并且将被分配错误的默认 shell。因此，在 Debian 或 Ubuntu 系统上使用`useradd`创建用户帐户，命令看起来会像这样：

```
sudo useradd -m -d /home/frank -s /bin/bash frank
```

在这个命令中：

+   `-m`创建家目录。

+   `-d`指定家目录。

+   `-s`指定 Frank 的默认 shell。（如果没有`-s`，Debian/Ubuntu 将为 Frank 分配`/bin/sh` shell。）

当您查看家目录时，您会发现它们是完全开放的，每个人都有执行和读取权限：

```
donnie@packt:/home$ ls -l
total 8
drwxr-xr-x 3 donnie donnie 4096 Oct 2 00:23 donnie
drwxr-xr-x 2 frank frank 4096 Oct 1 23:58 frank
donnie@packt:/home$
```

正如您所看到的，Frank 和我都可以进入对方的东西。（不，我不希望 Frank 进入我的东西。）每个用户都可以更改自己目录的权限，但是你的用户中有多少人知道如何做到这一点呢？因此，让我们自己来解决这个问题：

```
cd /home
sudo chmod 700 *
```

让我们看看现在有什么：

```
donnie@packt:/home$ ls -l
total 8
drwx------ 3 donnie donnie 4096 Oct 2 00:23 donnie
drwx------ 2 frank frank 4096 Oct 1 23:58 frank
donnie@packt:/home$
```

看起来好多了。

要更改家目录的默认权限设置，请打开`/etc/login.defs`进行编辑。查找一行，上面写着：

```
UMASK     022
```

更改为：

```
UMASK     077
```

现在，新用户的家目录将在创建时被锁定，就像红帽一样。

# Debian/Ubuntu 上的`adduser`

`adduser`实用程序是一种交互式方式，可以使用单个命令创建用户帐户和密码，这是 Debian 系列 Linux 发行版独有的。大多数缺少的默认设置已经为`adduser`设置好了。默认设置唯一的问题是它使用宽松的`755`权限值创建用户家目录。幸运的是，这很容易更改。（我们马上就会看到如何更改。）

尽管`adduser`对于仅仅创建用户帐户很方便，但它不像`useradd`那样灵活，并且不适合在 shell 脚本中使用。`adduser`能做的一件事是在创建帐户时自动加密用户的家目录。要使其工作，您首先必须安装`ecryptfs-utils`软件包。因此，要为 Cleopatra 创建一个带加密家目录的帐户，您可以这样做：

```
sudo apt install ecryptfs-utils

donnie@ubuntu-steemnode:~$ sudo adduser --encrypt-home cleopatra
[sudo] password for donnie:
Adding user `cleopatra' ...
Adding new group `cleopatra' (1004) ...
Adding new user `cleopatra' (1004) with group `cleopatra' ...
Creating home directory `/home/cleopatra' ...
Setting up encryption ...

************************************************************************
YOU SHOULD RECORD YOUR MOUNT PASSPHRASE AND STORE IT IN A SAFE LOCATION.
 ecryptfs-unwrap-passphrase ~/.ecryptfs/wrapped-passphrase
THIS WILL BE REQUIRED IF YOU NEED TO RECOVER YOUR DATA AT A LATER TIME.
************************************************************************

Done configuring.

Copying files from `/etc/skel' ...
Enter new UNIX password:
Retype new UNIX password:
passwd: password updated successfully
Changing the user information for cleopatra
Enter the new value, or press ENTER for the default
 Full Name []: Cleopatra Tabby Cat
 Room Number []: 1
 Work Phone []: 555-5556
 Home Phone []: 555-5555
 Other []:
Is the information correct? [Y/n] Y
donnie@ubuntu-steemnode:~$
```

第一次 Cleopatra 登录时，她需要运行前面输出中提到的`ecryptfs-unwrap-passphrase`命令。然后她需要把密码写下来并存放在安全的地方：

```
cleopatra@ubuntu-steemnode:~$ ecryptfs-unwrap-passphrase
Passphrase:
d2a6cf0c3e7e46fd856286c74ab7a412
cleopatra@ubuntu-steemnode:~$
```

当我们到达加密章节时，我们将更详细地研究整个加密过程。

# 配置 adduser 的实践实验

在这个实验中，我们将使用`adduser`实用程序，这是 Debian/Ubuntu 系统特有的：

1.  在您的 Ubuntu 虚拟机上，打开`/etc/adduser.conf`文件进行编辑。找到一行，上面写着：

```
        DIR_MODE=0755
```

更改为：

```
        DIR_MODE=0700
```

保存文件并退出文本编辑器。

1.  安装`ecryptfs-utils`软件包：

```
        sudo apt install ecryptfs-utils
```

1.  为 Cleopatra 创建一个带加密家目录的用户帐户，然后查看结果：

```
 sudo adduser --encrypt-home cleopatra
 ls -l /home
```

1.  以 Cleopatra 的身份登录并运行`ecryptfs-unwrap-passphrase`命令：

```
 su - cleopatra
 ecryptfs-unwrap-passphrase
 exit
```

请注意，`adduser`要求的一些信息是可选的，您可以只按*Enter*键输入这些项目。

# 强制执行强密码标准

您可能不会认为一个听起来无害的话题，比如*强密码标准*会如此具有争议性，但事实上是如此。您无疑已经听说过整个计算机生涯中的常识说法：

+   制作一定最小长度的密码

+   制作由大写字母、小写字母、数字和特殊字符组成的密码

+   确保密码不包含字典中找到的任何单词，也不基于用户自己的个人数据

+   强制用户定期更改他们的密码

但是，使用您喜欢的搜索引擎，您会发现不同的专家对这些标准的细节存在分歧。例如，您会看到关于密码是否应该每 30、60 或 90 天更改的分歧，关于密码是否需要包含所有四种类型的字符的分歧，甚至关于密码的最小长度应该是多少的分歧。

最有趣的争议来自于——所有地方中最有趣的争议。他现在说，我们应该使用长而又容易记住的口令。他还说，只有在被破坏后才应该更改它们。

比尔·伯尔是前国家标准与技术研究所的工程师，他创建了我之前概述的强密码标准，他分享了自己为什么现在否定自己的工作的想法。

参考：[`www.pcmag.com/news/355496/you-might-not-need-complex-alphanumeric-passwords-after-all`](https://www.pcmag.com/news/355496/you-might-not-need-complex-alphanumeric-passwords-after-all)。

然而，尽管如此，现实是大多数组织仍然固守使用定期过期的复杂密码的想法，如果你无法说服他们改变想法，你就必须遵守他们的规定。而且，如果你使用传统密码，你确实希望它们足够强大，能够抵抗任何形式的密码攻击。所以现在，我们将看一下在 Linux 系统上强制执行强密码标准的机制。

我必须承认，我以前从未想过在 Linux 系统上尝试创建口令来替代密码。所以，我刚刚在我的 CentOS 虚拟机上尝试了一下，看看它是否有效。

我为我的黑白礼服猫玛吉创建了一个账户。对于她的密码，我输入了口令“我喜欢其他猫”。你可能会想，“哦，那太糟糕了。这不符合任何复杂性标准，而且使用了字典中的单词。这怎么安全？”但是，事实上，这是一个由空格分隔的短语，这使得它安全且非常难以暴力破解。

现在，在现实生活中，我永远不会创建一个表达我对猫的爱的口令，因为很容易发现我真的很爱猫。相反，我会选择一个关于我生活中更隐秘的部分的口令，除了我之外没有人知道。

无论如何，与密码相比，口令有两个优点。它们比传统密码更难破解，但对用户来说更容易记住。但是为了额外的安全性，不要创建关于每个人都知道的生活事实的口令。

# 安装和配置 pwquality

我们将使用`pwquality`模块进行**PAM**（**可插拔认证模块**）的设置。这是一种较新的技术，已经取代了旧的`cracklib`模块。在 Red Hat 7 或 CentOS 7 系统上，默认安装了`pwquality`，即使进行了最小安装。如果你`cd`进入`/etc/pam.d`目录，你可以进行`grep`操作，查看 PAM 配置文件是否已经设置好。`retry=3`表示用户在登录系统时只有三次尝试输入密码的机会。

```
[donnie@localhost pam.d]$ grep 'pwquality' *
password-auth:password    requisite     pam_pwquality.so try_first_pass local_users_only retry=3 authtok_type=
password-auth-ac:password    requisite     pam_pwquality.so try_first_pass local_users_only retry=3 authtok_type=
system-auth:password    requisite     pam_pwquality.so try_first_pass local_users_only retry=3 authtok_type=
system-auth-ac:password    requisite     pam_pwquality.so try_first_pass local_users_only retry=3 authtok_type=
[donnie@localhost pam.d]$
```

对于你的 Ubuntu 系统，你需要自己安装`pwquality`。你可以使用以下命令来安装：

```
sudo apt install libpam-pwquality
```

现在我们`cd`进入`/etc/pam.d`目录，并执行与之前相同的`grep`命令。我们会看到安装`libpam-pwquality`模块会自动更新 PAM 配置文件：

```
donnie@packt:/etc/pam.d$ grep 'pwquality' *
common-password:password        requisite                       pam_pwquality.so retry=3
donnie@packt:/etc/pam.d$
```

对于两种操作系统，其余的步骤都是一样的，只需要编辑`/etc/security/pwquality.conf`文件。当你在文本编辑器中打开这个文件时，你会发现所有内容都被注释掉了，这意味着没有密码复杂性标准生效。你还会发现它有很好的文档说明，因为每个设置都有自己的解释性注释。

你可以根据需要设置密码复杂性标准，只需取消相应行的注释并设置适当的值。让我们看看其中一个设置：

```
# Minimum acceptable size for the new password (plus one if
# credits are not disabled which is the default). (See pam_cracklib manual.)
# Cannot be set to lower value than 6.
# minlen = 8
```

最小长度设置是基于 credit 系统的。这意味着对于密码中的每一种不同类型的字符类，最小要求的密码长度将减少一个字符。例如，让我们将`minlen`设置为`19`，并尝试为 Katelyn 分配密码`turkeylips`：

```
minlen = 19

[donnie@localhost ~]$ sudo passwd katelyn
Changing password for user katelyn.
New password:
BAD PASSWORD: The password is shorter than 18 characters
Retype new password:
[donnie@localhost ~]$
```

因为`turkeylips`中的小写字符计为一个字符类的 credit，所以我们只需要有 18 个字符而不是 19 个。如果我们再试一次，使用`TurkeyLips`，我们会得到：

```
[donnie@localhost ~]$ sudo passwd katelyn
Changing password for user katelyn.
New password:
BAD PASSWORD: The password is shorter than 17 characters
Retype new password:
[donnie@localhost ~]$
```

这一次，大写的`T`和大写的`L`计为第二种字符类，所以我们只需要密码中有 17 个字符。

在`minlen`行的下面，你会看到 credit 行。假设你不希望小写字母计入 credit，你会找到这一行：

```
# lcredit = 1
```

此外，你需要将`1`改为`0`：

```
lcredit = 0
```

然后，尝试为 Katelyn 分配密码`turkeylips`：

```
[donnie@localhost ~]$ sudo passwd katelyn
Changing password for user katelyn.
New password:
BAD PASSWORD: The password is shorter than 19 characters
Retype new password:
[donnie@localhost ~]$
```

这一次，`pwquality`确实需要 19 个字符。如果我们将 credit 值设置为大于 1 的值，我们将得到同一类类型的多个字符的 credit，直到达到该值。

我们也可以将 credit 值设置为负数，以要求密码中包含一定数量的字符类型。我们有以下示例：

```
dcredit = -3
```

这将要求密码中至少有三个数字。然而，使用这个功能是一个非常糟糕的主意，因为试图破解密码的人很快就会发现你要求的模式，这将帮助攻击者更精确地发起攻击。如果你需要要求密码包含多种字符类型，最好使用`minclass`参数。

```
# minclass = 3
```

它已经设置为 3，这将要求密码中包含来自三种不同类的字符。要使用这个值，你只需要删除注释符。

`pwquality.conf`中的其余参数基本上都是以相同的方式工作，每个参数都有一个很好的注释来解释它的作用。

如果你使用 sudo 权限来设置其他人的密码，系统会抱怨如果你创建的密码不符合复杂性标准，但它会允许你这样做。如果一个普通用户试图在没有 sudo 权限的情况下更改自己的密码，系统将不允许设置不符合复杂性标准的密码。

# 设置密码复杂性标准的实践实验

在这个实验中，你可以根据需要使用 CentOS 或 Ubuntu 虚拟机。唯一的区别是你不需要为 CentOS 执行*步骤 1*：

1.  仅适用于 Ubuntu，安装`libpam-pwquality`包：

```
        sudo apt install libpam-pwquality
```

1.  在您喜欢的文本编辑器中打开`/etc/security/pwquality.conf`文件。从`minlen`行前面删除注释符号，并将值更改为`19`。现在应该看起来像这样：

```
        minlen = 19
```

保存文件并退出编辑器。

1.  为 Goldie 创建一个用户帐户，并尝试为她分配密码，`turkeylips`，`TurkeyLips`和`Turkey93Lips`。注意每个警告消息的变化。

1.  在`pwquality.conf`文件中，注释掉`minlen`行。取消注释`minclass`行和`maxclassrepeat`行。将`maxclassrepeat`值更改为`5`。现在应该看起来像：

```
        minclass = 3
        maxclassrepeat = 5
```

保存文件并退出文本编辑器。

1.  尝试为 Goldie 的帐户分配不符合您设置的复杂性标准的各种密码，并查看结果。

在您的 CentOS 机器上的`/etc/login.defs`文件中，您会看到以下行：

`PASS_MIN_LEN 5`

据说这是设置最小密码长度，但实际上，`pwquality`会覆盖它。因此，您可以将此值设置为任何值，它都不会起作用。

# 设置和执行密码和帐户到期

您绝对不希望未使用的用户帐户保持活动状态。曾经发生过管理员为临时使用设置用户帐户的情况，例如为会议设置用户帐户，然后在不再需要帐户后就忘记了它们。另一个例子是，如果您的公司雇佣的合同工合同在特定日期到期。允许这些帐户在临时员工离开公司后保持活动和可访问性将是一个巨大的安全问题。在这种情况下，您需要一种方法来确保在不再需要时不会忘记临时用户帐户。如果您的雇主认同用户应定期更改密码的传统智慧，那么您还需要确保这样做。

密码到期数据和帐户到期数据是两回事。它们可以分别设置，也可以一起设置。当某人的密码过期时，他或她可以更改密码，一切都会很好。如果有人的帐户到期，只有具有适当管理员权限的人才能解锁它。

要开始，请查看您自己帐户的到期日期。（请注意，您不需要 sudo 权限来查看您自己的数据，但您仍然需要指定您自己的用户名。）

```
donnie@packt:~$ chage -l donnie
[sudo] password for donnie:
Last password change : Oct 03, 2017
Password expires : never
Password inactive : never
Account expires : never
Minimum number of days between password change : 0
Maximum number of days between password change : 99999
Number of days of warning before password expires : 7
donnie@packt:~$
```

您可以在这里看到没有设置到期日期。这里的一切都是根据出厂默认值设置的。除了明显的项目之外，这里是您看到的内容的详细说明：

+   **密码无效**：如果这被设置为一个正数，我的帐户在系统锁定我的帐户之前将有那么多天时间更改过期的密码。

+   密码更改之间的最少天数：因为这被设置为`0`，我可以随意更改我的密码。如果它被设置为一个正数，我必须在更改密码后等待那么多天才能再次更改密码。

+   **密码更改之间的最大天数**：这被设置为默认值`99999`，意味着我的密码永远不会过期。

+   **密码到期前的天数警告**：默认值为`7`，但当密码设置为永不过期时，这是毫无意义的。

使用`chage`实用程序，您可以为其他用户设置密码和帐户到期数据，或者使用`-l`选项查看到期数据。任何非特权用户都可以使用`chage -l`而无需 sudo 来查看自己的数据。要设置数据或查看其他人的数据，您需要 sudo。我们稍后将更仔细地看看`chage`。

在我们看如何更改到期日期之前，让我们首先看看默认设置存储在哪里。我们首先看看`/etc/login.defs`文件。三行相关的行是：

```
PASS_MAX_DAYS 99999
PASS_MIN_DAYS 0
PASS_WARN_AGE 7
```

您可以编辑这些值以适应您组织的需求。例如，将`PASS_MAX_DAYS`更改为`30`的值将导致从那时起所有新用户密码的到期日期为 30 天。（顺便说一句，在`login.defs`中设置默认密码到期日期对于 Red Hat 或 CentOS 和 Debian/Ubuntu 都适用。）

# 为 useradd 配置默认到期日期-仅适用于 Red Hat 或 CentOS

`/etc/default/useradd`文件包含其余的默认设置。在这种情况下，我们将查看来自 CentOS 机器的设置。

Ubuntu 也有相同的`useradd`配置文件，但它不起作用。无论您如何配置，Ubuntu 版本的`useradd`都不会读取它。因此，关于此文件的说明仅适用于 Red Hat 或 CentOS。

```
# useradd defaults file
GROUP=100
HOME=/home
INACTIVE=-1
EXPIRE=
SHELL=/bin/bash
SKEL=/etc/skel
CREATE_MAIL_SPOOL=yes
```

`EXPIRE=`行设置了新用户帐户的默认到期日期。默认情况下，没有默认到期日期。`INACTIVE=-1`表示用户帐户在用户密码过期后不会自动锁定。如果我们将其设置为正数，那么任何新用户在帐户被锁定之前将有这么多天来更改过期密码。要更改`useradd`文件中的默认值，您可以手动编辑文件，也可以使用`useradd -D`和适当的选项开关来更改要更改的项目。例如，要设置默认到期日期为 2019 年 12 月 31 日，命令将是：

```
sudo useradd -D -e 2019-12-31
```

要查看新配置，您可以打开`useradd`文件，也可以执行`sudo useradd -D`：

```
[donnie@localhost ~]$ sudo useradd -D
GROUP=100
HOME=/home
INACTIVE=-1
EXPIRE=2019-12-31
SHELL=/bin/bash
SKEL=/etc/skel
CREATE_MAIL_SPOOL=yes
[donnie@localhost ~]$
```

您现在已经设置了任何新创建的用户帐户都具有相同的到期日期。您也可以使用`INACTIVE`设置或`SHELL`设置来做同样的事情：

```
sudo useradd -D -f 5
sudo useradd -D -s /bin/zsh

[donnie@localhost ~]$ sudo useradd -D
GROUP=100
HOME=/home
INACTIVE=5
EXPIRE=2019-12-31
SHELL=/bin/zsh
SKEL=/etc/skel
CREATE_MAIL_SPOOL=yes
[donnie@localhost ~]$
```

现在，任何新创建的用户帐户都将具有 Zsh shell 设置为默认 shell，并且必须在五天内更改过期密码，以防止帐户被自动锁定。

`useradd`不会执行任何安全检查，以确保您分配的默认 shell 已安装在系统上。在我们的情况下，Zsh 没有安装，但`useradd`仍然允许您创建具有 Zsh 作为默认 shell 的帐户。

那么，这个`useradd`配置功能在现实生活中有多有用呢？可能并不那么有用，除非您需要一次性创建大量具有相同设置的用户帐户。即使如此，精明的管理员也会使用 shell 脚本自动化该过程，而不是在此配置文件中搞来搞去。

# 使用 useradd 和 usermod 为每个帐户设置到期日期

您可能会发现在`login.defs`中设置默认密码到期日期很有用，但您可能不会发现在`useradd`配置文件中配置很有用。实际上，您想要创建所有用户帐户具有相同的帐户到期日期的几率有多大呢？在`login.defs`中设置密码到期日期更有用，因为您只需说明您希望新密码在特定天数内到期，而不是让它们在特定日期到期。

很可能，您会根据您知道帐户将在特定日期不再需要的情况来为每个帐户设置帐户到期日期。您可以通过以下三种方式来实现这一点：

+   使用`useradd`命令和适当的选项开关来在创建帐户时设置到期日期。（如果您需要一次性创建大量帐户，并且它们具有相同的到期日期，您可以使用 shell 脚本自动化该过程。）

+   使用`usermod`来修改现有帐户的到期日期。（`usermod`的美妙之处在于它使用与`useradd`相同的选项开关。）

+   使用`chage`来修改现有帐户的到期日期。（这个命令使用完全不同的一组选项开关。）

您可以使用`useradd`和`usermod`来设置帐户到期日期，但不能用于设置密码到期日期。影响帐户到期日期的唯一两个选项开关是：

+   `-e`：使用此选项为帐户设置到期日期，格式为 YYYY-MM-DD

+   `-f`：使用此选项设置用户密码过期后要锁定其帐户的天数

假设您想为 Charlie 创建一个帐户，该帐户将在 2020 年底到期。在红帽或 CentOS 机器上，您可以输入以下内容：

```
sudo useradd -e 2020-12-31 charlie
```

在非红帽或 CentOS 机器上，您需要添加选项开关来创建主目录并分配正确的默认 shell：

```
sudo useradd -m -d /home/charlie -s /bin/bash -e 2020-12-31 charlie
```

使用`chage -l`验证您输入的内容：

```
donnie@ubuntu-steemnode:~$ sudo chage -l charlie
Last password change : Oct 06, 2017
Password expires : never
Password inactive : never
Account expires : Dec 31, 2020
Minimum number of days between password change : 0
Maximum number of days between password change : 99999
Number of days of warning before password expires : 7
donnie@ubuntu-steemnode:~$
```

现在，假设 Charlie 的合同已经延长，您需要将他的帐户到期日期更改为 2021 年 1 月底。您可以在任何 Linux 发行版上以相同的方式使用`usermod`：

```
sudo usermod -e 2021-01-31 charlie
```

再次使用`chage -l`验证一切是否正确：

```
donnie@ubuntu-steemnode:~$ sudo chage -l charlie
Last password change : Oct 06, 2017
Password expires : never
Password inactive : never
Account expires : Jan 31, 2021
Minimum number of days between password change : 0
Maximum number of days between password change : 99999
Number of days of warning before password expires : 7
donnie@ubuntu-steemnode:~$
```

可选地，您可以设置带有过期密码的帐户在被锁定之前的天数：

```
sudo usermod -f 5 charlie
```

但是，如果您现在这样做，您不会看到`chage -l`输出中的任何差异，因为我们仍然没有为 Charlie 的密码设置到期日期。

# 使用`chage`在每个帐户上设置到期日期

您只能使用`chage`来修改现有帐户，并且您将用它来设置帐户到期或密码到期。以下是相关的选项开关：

| `-d` | 如果您在某人的帐户上使用`-d 0`选项，您将强制用户在下次登录时更改密码。 |
| --- | --- |
| `-E` | 这相当于`useradd`或`usermod`的小写`-e`。它设置了用户帐户的到期日期。 |
| `-I` | 这相当于`useradd`或`usermod`的`-f`。它设置了带有过期密码的帐户在被锁定之前的天数。 |
| `-m` | 这将设置更改密码之间的最小天数。换句话说，如果 Charlie 今天更改了密码，`-m 5`选项将强制他等待五天才能再次更改密码。 |
| `-M` | 这将设置密码过期前的最大天数。（但要注意，如果 Charlie 上次设置密码是 89 天前，使用`-M 90`选项将导致他的密码明天过期，而不是 90 天后。） |
| `-W` | 这将设置密码即将过期的警告天数。 |

您可以一次设置这些数据项中的一个，也可以一次设置它们全部。实际上，为了避免让您为每个单独的项目提供不同的演示而感到沮丧，让我们一次设置它们全部，除了`-d 0`，然后我们将看看我们得到了什么：

```
sudo chage -E 2021-02-28 -I 4 -m 3 -M 90 -W 4 charlie

donnie@ubuntu-steemnode:~$ sudo chage -l charlie
Last password change : Oct 06, 2017
Password expires : Jan 04, 2018
Password inactive : Jan 08, 2018
Account expires : Feb 28, 2021
Minimum number of days between password change : 3
Maximum number of days between password change : 90
Number of days of warning before password expires : 4
donnie@ubuntu-steemnode:~$
```

所有到期日期现在已经设置。

对于我们的最后一个示例，假设您刚刚为 Samson 创建了一个新帐户，并且希望在他首次登录时强制他更改密码。有两种方法可以做到这一点。无论哪种方式，您都需要在初始设置密码后执行。我们有以下代码：

```

sudo chage -d 0 samson

or

sudo passwd -e samson

donnie@ubuntu-steemnode:~$ sudo chage -l samson
Last password change                    : password must be changed
Password expires                        : password must be changed
Password inactive                       : password must be changed
Account expires                         : never
Minimum number of days between password change        : 0
Maximum number of days between password change        : 99999
Number of days of warning before password expires    : 7
donnie@ubuntu-steemnode:~$
```

# 设置帐户和密码到期日期的实践实验

在这个实验中，您将创建一对新的用户帐户，设置到期日期，并查看结果。您可以在 CentOS 或 Ubuntu 虚拟机上进行此实验。（唯一的区别将在`useradd`命令上。）

1.  为 Samson 创建一个带有到期日期为 2023 年 6 月 30 日的用户帐户，并查看结果。

对于 CentOS：

```
 sudo useradd -e 2023-06-30 samson
 sudo chage -l samson
```

对于 Ubuntu：

```
 sudo useradd -m -d /home/samson -s /bin/bash -e 2023-06-30
 sudo chage -l samson
```

1.  使用`usermod`将 Samson 的帐户到期日期更改为 2023 年 7 月 31 日：

```
 sudo usermod -e 2023-07-31
 sudo chage -l samson
```

1.  为 Samson 的帐户分配一个密码，然后强制他在首次登录时更改密码。以 Samson 的身份登录，更改他的密码，然后注销到您自己的帐户：

```
 sudo passwd samson
 sudo passwd -e samson
 sudo chage -l samson
 su - samson
 exit
```

1.  使用`chage`设置更改密码的等待期为 5 天，密码过期期限为 90 天，不活动期为 2 天，警告期为 5 天：

```
        sudo chage -m 5 -M 90 -I 2 -W 5 samson
 sudo chage -l samson
```

1.  保留此帐户，因为您将在下一节的实验中使用它。

# 防止暴力密码攻击

令人惊讶的是，这又是一个引发一些争议的话题。我的意思是，没有人否认自动锁定遭受攻击的用户账户的智慧。有争议的部分涉及我们应该在锁定账户之前允许多少次失败的登录尝试。

回到计算机的石器时代，那是很久以前，我还有一头浓密的头发，早期的 Unix 操作系统只允许用户创建最多八个小写字母的密码。所以在那些日子里，早期人类可以通过坐在键盘前输入随机密码来暴力破解别人的密码。这就是当时开始有用户账户在只有三次登录尝试失败后被锁定的理念。如今，使用强密码，或者更好的是强大的口令，设置三次登录尝试失败后锁定账户将会有三个作用：

+   它会不必要地让用户感到沮丧

+   这会给帮助台人员带来额外的工作

+   如果一个账户真的遭受攻击，它会在你有机会收集有关攻击者的信息之前锁定该账户

将锁定值设置为更现实的值，比如 100 次登录尝试失败，仍然可以提供良好的安全性，同时也给你足够的时间来收集有关攻击者的信息。同样重要的是，你不会给用户和帮助台人员带来不必要的挫败感。

无论你的雇主允许你允许多少次登录尝试失败，你仍然需要知道如何设置它。所以，让我们开始吧。

# 配置 pam_tally2 PAM 模块

为了让这个魔法生效，我们将依赖我们的好朋友 PAM 模块。`pam_tally2`模块已经安装在 CentOS 和 Ubuntu 上，但尚未配置。对于我们的两台虚拟机，我们将编辑`/etc/pam.d/login`文件。配置它很容易，因为在`pam_tally2`手册的底部有一个示例。

```
EXAMPLES
       Add the following line to /etc/pam.d/login to lock the account after 4 failed logins. Root account will be locked as well. The accounts will be automatically unlocked after 20 minutes. The module does not have to be called in the account phase because the login calls pam_setcred(3) correctly.

           auth required pam_securetty.so
           auth required pam_tally2.so deny=4 even_deny_root unlock_time=1200
           auth required pam_env.so
           auth required pam_unix.so
           auth required pam_nologin.so
           account required pam_unix.so
           password required pam_unix.so
           session required pam_limits.so
           session required pam_unix.so
           session required pam_lastlog.so nowtmp
           session optional pam_mail.so standard
```

在示例的第二行中，我们看到`pam_tally2`设置为：

+   `deny=4`: 这意味着在只有四次登录尝试失败后，遭受攻击的用户账户将被锁定

+   `even_deny_root`: 这意味着即使是 root 用户账户在遭受攻击时也会被锁定

+   `unlock_time=1200`: 在 1200 秒或 20 分钟后，账户将自动解锁

现在，如果你查看你的虚拟机上的实际`login`文件，你会发现它们看起来并不像手册中的示例`login`文件。没关系，我们仍然可以让它生效。

一旦你配置了`login`文件并且有了登录失败，你会在`/var/log`目录中看到一个新文件被创建。你可以使用`pam_tally2`工具查看该文件中的信息。你也可以使用`pam_tally2`手动解锁被锁定的账户，如果你不想等待超时期：

```
donnie@ubuntu-steemnode:~$ sudo pam_tally2
Login Failures Latest failure From
charlie 5 10/07/17 16:38:19
donnie@ubuntu-steemnode:~$ sudo pam_tally2 --user=charlie --reset
Login Failures Latest failure From
charlie 5 10/07/17 16:38:19
donnie@ubuntu-steemnode:~$ sudo pam_tally2
donnie@ubuntu-steemnode:~$
```

注意，当我对查理的账户进行重置后，再次查询时没有输出。

# 配置 pam_tally2 的实践实验

配置`pam_tally2`非常容易，因为它只需要在`/etc/pam.d/login`文件中添加一行。为了更方便，你可以直接从`pam_tally2`手册中的示例中复制并粘贴该行。尽管我之前说过将失败登录次数增加到 100，但现在我们将该数字保持为`4`。（我知道你不想要做 100 次失败登录来演示这个。）

1.  在 CentOS 或 Ubuntu 虚拟机上，打开`/etc/pam.d/login`文件进行编辑。查找调用`pam_securetty`模块的行。（在 Ubuntu 上大约在第 32 行，在 CentOS 上大约在第 2 行。）

在那一行下面，插入以下行：

```
        auth required pam_tally2.so deny=4 
        even_deny_root unlock_time=1200
```

保存文件并退出编辑器。

1.  在这一步中，你需要退出你自己的账户，因为`pam_tally2`不能与`su`一起使用。所以，退出登录，然后故意使用错误的密码，尝试登录到你在上一个实验中创建的`samson`账户。一直这样做，直到看到账户被锁定的消息。请注意，当`deny`值设置为`4`时，实际上需要五次失败的登录尝试才能锁定 Samson 的账户。

1.  重新登录你自己的用户账户。运行这个命令并注意输出：

```
        sudo pam_tally2
```

1.  在这一步中，你将模拟自己是一个帮助台工作人员，Samson 刚打电话请求你解锁他的账户。在确认你确实在和真正的 Samson 交谈后，输入以下命令：

```
        sudo pam_tally2 --user=samson --reset
 sudo pam_tally2
```

1.  现在你已经看到了这是如何工作的，打开`/etc/pam.d/login`文件进行编辑，并将`deny=`参数从`4`更改为`100`，然后保存文件。（这将使您的配置在现代安全理念方面更加现实。）

# 锁定用户账户

好的，你刚刚看到了如何让 Linux 自动锁定遭受攻击的用户账户。有时候你也会想手动锁定用户账户。让我们看下面的例子：

+   当用户度假时，你希望确保没有人在他离开期间对他的账户进行操作

+   当用户因可疑活动而受到调查时

+   当用户离开公司时

关于最后一点，你可能会问自己：“*为什么我们不能只删除那些不在这里工作的人的账户呢？*”当然，你当然可以很容易地这样做。但在这样做之前，你需要查看当地的法律，确保自己不会陷入麻烦。例如，在美国，我们有萨班斯-奥克斯法，限制上市公司可以从他们的计算机中删除哪些文件。如果你删除了一个用户账户，以及该用户的主目录和邮件存储，你可能会触犯萨班斯-奥克斯法或者你自己国家的等同法律。

无论如何，有两个工具可以用来临时锁定用户账户：

+   使用`usermod`来锁定用户账户

+   使用`passwd`来锁定用户账户

# 使用 usermod 来锁定用户账户

假设 Katelyn 已经休产假，至少会离开几周。我们可以通过以下方式锁定她的账户：

```
sudo usermod -L katelyn
```

当你查看`/etc/shadow`文件中 Katelyn 的条目时，你会看到她的密码哈希前面有一个感叹号，如下所示：

```
katelyn:!$6$uA5ecH1A$MZ6q5U.cyY2SRSJezV000AudP.ckXXndBNsXUdMI1vPO8aFmlLXcbGV25K5HSSaCv4RlDilwzlXq/hKvXRkpB/:17446:0:99999:7:::
```

这个感叹号阻止系统能够读取她的密码，从而有效地将她锁在了系统外。

要解锁她的账户，只需按照以下步骤：

```
sudo usermod -U katelyn
```

你会看到感叹号已经被移除，这样她现在可以登录她的账户了。

# 使用 passwd 来锁定用户账户

你也可以通过以下方式锁定 Katelyn 的账户：

```
sudo passwd -l katelyn
```

这与`usermod -L`的功能相同，但方式略有不同。首先，`passwd -l`会给出一些关于正在进行的操作的反馈，而`usermod -L`则没有任何反馈。在 Ubuntu 上，反馈看起来像这样：

```
donnie@ubuntu-steemnode:~$ sudo passwd -l katelyn
[sudo] password for donnie:
passwd: password expiry information changed.
donnie@ubuntu-steemnode:~$
```

在 CentOS 上，反馈看起来像这样：

```
[donnie@localhost ~]$ sudo passwd -l katelyn
Locking password for user katelyn.
passwd: Success
[donnie@localhost ~]$
```

此外，在 CentOS 机器上，你会看到`passwd -l`在密码哈希前面放置了两个感叹号，而不是一个。无论哪种方式，效果都是一样的。

要解锁 Katelyn 的账户，只需执行以下操作：

```
sudo passwd -u katelyn
```

在 Red Hat 或 CentOS 7 版本之前，`usermod -U`只会移除`passwd -l`在 shadow 文件密码哈希前面放置的一个感叹号，因此账户仍然被锁定。不过，这没什么大不了的，因为再次运行`usermod -U`将移除第二个感叹号。

在 Red Hat 或 CentOS 7 中，已经修复了。`passwd -l`命令仍然会在 shadow 文件中放置两个感叹号，但`usermod -U`现在会将两者都删除。 （真是遗憾，因为这破坏了我喜欢给学生做的一个完美的演示。）

# 锁定根用户账户

云现在是大生意，现在很常见租用来自 Rackspace、DigitalOcean 或 Microsoft Azure 等公司的虚拟专用服务器。这些可以用于各种用途，如下：

+   你可以运行自己的网站，在那里安装自己的服务器软件，而不是让托管服务来做

+   你可以为其他人设置一个基于 Web 的应用

+   最近，我在 YouTube 上看到了一个加密挖矿频道的演示，演示了如何在租用的虚拟专用服务器上设置权益证明主节点

这些云服务的共同之处之一是，当你第一次设置你的账户并且提供商为你设置了一个虚拟机器时，他们会让你登录到根用户账户。（即使在 Ubuntu 上也会发生，尽管 Ubuntu 的本地安装上禁用了根账户。）

我知道有些人只是不断登录到这些基于云的服务器的根账户，却毫不在意，但这真的是一个可怕的想法。有僵尸网络，比如 Hail Mary 僵尸网络，不断扫描互联网上暴露 Secure Shell 端口的服务器。当僵尸网络找到一个时，它们会对该服务器的根用户账户进行暴力密码攻击。是的，有时候僵尸网络会成功闯入，特别是如果根账户设置了弱密码。

所以，当你设置基于云的服务器时，你要做的第一件事就是为自己创建一个普通用户账户，并为其设置完整的 sudo 权限。然后，退出根用户账户，登录到你的新账户，并执行以下操作：

```
sudo passwd -l root
```

我的意思是，真的，为什么要冒险让你的根账户受到威胁？

# 设置安全横幅

有一件你真的，真的不想要的事情就是有一个登录横幅，上面写着“*欢迎来到我们的网络*”。我这么说是因为很多年前，我参加了一门关于事件处理的 SANS 课程。我们的导师告诉我们一个故事，讲述了一家公司将一名涉嫌入侵网络的人告上法庭，结果案子被驳回。原因是什么？据称的入侵者说，“*嗯，我看到了写着‘欢迎来到网络’的消息，所以我以为我真的是受欢迎的*。” 是的，据说这就足以让案子被驳回。

几年后，我在我的一堂 Linux 管理员课上向学生们讲述了这个故事。一名学生说，“*这毫无意义。我们所有人家门口都有欢迎地垫，但这并不意味着小偷可以随意进来*。” 我不得不承认他说得有道理，现在我不得不怀疑这个故事的真实性。

无论如何，为了安全起见，你确实希望设置登录消息，明确表示只有授权用户才能访问系统。

# 使用 motd 文件

`/etc/motd`文件将向通过 Secure Shell 登录系统的任何人显示消息横幅。在你的 CentOS 机器上，已经有一个空的`motd`文件。在你的 Ubuntu 机器上，`motd`文件不存在，但创建一个很简单。无论哪种方式，打开文件编辑器并创建你的消息。保存文件并通过 Secure Shell 远程登录进行测试。你应该会看到类似的东西：

```
maggie@192.168.0.100's password:
Last login: Sat Oct 7 20:51:09 2017
Warning: Authorized Users Only!

All others will be prosecuted.
[maggie@localhost ~]$
```

`motd`代表每日消息。

# 使用问题文件

问题文件，也可以在`/etc`目录中找到，在本地终端上显示一个消息，就在登录提示的上方。默认的问题文件只包含宏代码，会显示有关机器的信息。看下面的例子：

```
Ubuntu 16.04.3 LTS \n \l
```

或者，在 CentOS 机器上：

```
\S
Kernel \r on an \m
```

在 Ubuntu 机器上，横幅看起来会像这样：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sec-hdn/img/17b9b93c-b66b-41ee-92ab-b5c7b8d075f4.png)

在 CentOS 机器上，它看起来会像这样：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sec-hdn/img/98ec685f-3936-4ff7-874f-d1a0f255274b.png)

您可以在问题文件中放置安全消息，并在重新启动后显示出来：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sec-hdn/img/6f5d8a0a-0649-4a5a-81ff-edf844876f80.png)

实际上，在问题文件中放置安全消息真的有意义吗？如果您的服务器被妥善锁在一个带有受控访问的服务器房间里，那可能没有。

# 使用 issue.net 文件

别这样做。这是用于 telnet 登录的，任何在其服务器上启用 telnet 的人都是严重搞砸了。然而，出于某种奇怪的原因，`issue.net` 文件仍然挂在 `/etc` 目录中。

# 总结

在本章中，我们涵盖了很多内容，希望您找到了一些实用的建议。我们首先向您展示了始终以 root 用户身份登录的危险，以及您应该改用 sudo。除了向您展示 sudo 的基础用法之外，我们还研究了一些不错的 sudo 提示和技巧。然后，我们转向用户管理，看看如何锁定用户的主目录，如何强制执行强密码策略，以及如何强制执行帐户和密码过期策略。接着，我们讨论了一种防止暴力密码攻击的方法，如何手动锁定用户帐户，并设置安全横幅。

在下一章中，我们将看看如何使用各种防火墙实用程序。我会在那里见到你。


# 第三章：使用防火墙保护您的服务器

安全是最好分层处理的事情之一。我们称之为*深度安全*。因此，在任何公司网络上，您都会发现一个防火墙设备将互联网与**非军事区**（**DMZ**）分开，您的面向互联网的服务器就在其中。您还会在 DMZ 和内部局域网之间发现防火墙设备，并在每台独立的服务器和客户端上安装防火墙软件。我们希望尽可能地让入侵者难以到达我们网络中的最终目的地。

有趣的是，尽管所有主要的 Linux 发行版中，只有 SUSE 发行版和 Red Hat 类型的发行版已经设置并启用了防火墙。当您查看您的 Ubuntu 虚拟机时，您会发现它是完全开放的，就好像它在热烈欢迎任何潜在的入侵者一样。

由于本书的重点是加固我们的 Linux 服务器，我们将把本章重点放在我们服务器和客户端上的最后一道防线，即防火墙上。

在本章中，我们将涵盖：

+   iptables 的概述

+   Ubuntu 系统的 Uncomplicated Firewall

+   Red Hat 系统的 firewalld

+   nftables，一种更通用的防火墙系统

# iptables 的概述

一个常见的误解是 iptables 是 Linux 防火墙的名称。实际上，Linux 防火墙的名称是**netfilter**，每个 Linux 发行版都内置了它。我们所知道的 iptables 只是我们可以用来管理 netfilter 的几个命令行实用程序之一。它最初是作为 Linux 内核 2.6 版本的一个功能引入的，所以它已经存在了很长时间。使用 iptables，您确实有一些优势：

+   它已经存在了足够长的时间，以至于大多数 Linux 管理员已经知道如何使用它

+   在 shell 脚本中使用 iptables 命令创建自己的自定义防火墙配置很容易

+   它具有很大的灵活性，您可以使用它来设置一个简单的端口过滤器、路由器或虚拟专用网络

+   它预装在几乎每个 Linux 发行版上，尽管大多数发行版不会预先配置它

+   它有很好的文档，可以在互联网上免费获得书籍长度的教程

但是，您可能知道，也有一些缺点：

+   IPv4 和 IPv6 需要它们自己特殊的 iptables 实现。因此，如果您的组织在迁移到 IPv6 的过程中仍需要运行 IPv4，您将不得不在每台服务器上配置两个防火墙，并为每个运行单独的守护程序（一个用于 IPv4，另一个用于 IPv6）。

+   如果您需要进行需要**ebtables**的 Mac 桥接，这是 iptables 的第三个组件，具有自己独特的语法。

+   arptables，iptables 的第四个组件，也需要自己的守护程序和语法。

+   每当您向正在运行的 iptables 防火墙添加规则时，整个 iptables 规则集都必须重新加载，这可能会对性能产生巨大影响。

直到最近，iptables 是每个 Linux 发行版上的默认防火墙管理器。大多数发行版仍然是如此，但 Red Hat Enterprise Linux 7 及其所有后代现在使用了一种称为**firewalld**的新技术。Ubuntu 自带**Uncomplicated Firewall**（**ufw**），这是一个易于使用的 iptables 前端。我们将在本章末尾探讨一种更新的技术**nftables**。

本章的目的是只看 iptables 的 IPv4 组件。（IPv6 组件的语法会非常相似。）

# iptables 的基本用法

iptables 由四个规则表组成，每个表都有自己独特的目的：

+   **过滤表**：对于我们的服务器和客户端的基本保护，这是我们通常会使用的唯一表

+   **NAT 表**：**网络地址转换**（**NAT**）用于将公共互联网连接到私有网络

+   **篡改表**：这用于在网络数据包通过防火墙时进行更改

+   **安全表**：安全表仅用于安装了 SELinux 的系统

由于我们目前只对基本主机保护感兴趣，我们只会查看过滤器表。每个表由规则链组成，过滤器表由`INPUT`，`FORWARD`和`OUTPUT`链组成。由于我们的 CentOS 7 机器使用 Red Hat 的 firewalld，我们将在我们的 Ubuntu 机器上查看这个。

虽然 Red Hat Enterprise Linux 7 及其后代确实已经安装了 iptables，但默认情况下已禁用，以便我们可以使用 firewalld。不可能同时运行 iptables 和 firewalld，因为它们是两种完全不兼容的完全不同的动物。因此，如果您需要在 Red Hat 7 系统上运行 iptables，可以这样做，但必须首先禁用 firewalld。

然而，如果您的组织仍在使用 Red Hat 或 CentOS 的第 6 版运行其网络，则您的机器仍在使用 iptables，因为 firewalld 对它们不可用。

我们将首先使用`sudo iptables -L`命令查看当前配置：

```
donnie@ubuntu:~$ sudo iptables -L
[sudo] password for donnie:
Chain INPUT (policy ACCEPT)
target prot opt source destination

Chain FORWARD (policy ACCEPT)
target prot opt source destination

Chain OUTPUT (policy ACCEPT)
target prot opt source destination
donnie@ubuntu:~$
```

而且请记住，我们说您需要一个独立的 iptables 组件来处理 IPv6。在这里，我们将使用`sudo ip6tables -L`命令：

```
donnie@ubuntu:~$ sudo ip6tables -L
Chain INPUT (policy ACCEPT)
target     prot opt source               destination

Chain FORWARD (policy ACCEPT)
target     prot opt source               destination

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination
donnie@ubuntu:~$

```

在这两种情况下，您会看到没有规则，并且机器是完全开放的。与 SUSE 和 Red Hat 的人不同，Ubuntu 的人希望您自己设置防火墙。我们将首先创建一个规则，允许来自我们的主机请求连接的服务器的传入数据包通过：

```
sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
```

这是这个命令的分解：

+   `-A INPUT`：`-A`将规则放在指定链的末尾，本例中是`INPUT`链。如果我们想要将规则放在链的开头，我们将使用`-I`。

+   `-m`：这调用了一个 iptables 模块。在这种情况下，我们调用`conntrack`模块来跟踪连接状态。这个模块允许 iptables 确定我们的客户端是否与另一台机器建立了连接。

+   `--ctstate`：我们的规则的`ctstate`或连接状态部分正在寻找两件事。首先，它正在寻找客户端与服务器建立的连接。然后，它寻找从服务器返回的相关连接，以允许它连接到客户端。因此，如果用户使用 Web 浏览器连接到网站，此规则将允许来自 Web 服务器的数据包通过防火墙传递到用户的浏览器。

+   `-j`：这代表*jump*。规则跳转到特定目标，本例中是`ACCEPT`。（请不要问我是谁想出了这个术语。）因此，此规则将接受从客户端请求连接的服务器返回的数据包。

我们的新规则集如下：

```
donnie@ubuntu:~$ sudo iptables -L
Chain INPUT (policy ACCEPT)
target prot opt source destination
ACCEPT all -- anywhere anywhere ctstate RELATED,ESTABLISHED

Chain FORWARD (policy ACCEPT)
target prot opt source destination

Chain OUTPUT (policy ACCEPT)
target prot opt source destination
donnie@ubuntu:~$
```

接下来，我们将打开端口`22`，以便允许我们通过安全外壳进行连接。目前，我们不想打开更多的端口，所以我们将以阻止其他所有内容的规则结束：

```
sudo iptables -A INPUT -p tcp --dport ssh -j ACCEPT
sudo iptables -A INPUT -j DROP
```

这是分解：

+   `-A INPUT`：与以前一样，我们希望使用`-A`将此规则放在 INPUT 链的末尾。

+   `-p tcp`：`-p`表示此规则影响的协议。此规则影响 TCP 协议，其中安全外壳是其中的一部分。

+   `--dport ssh`：当选项名称由多个字母组成时，我们需要在其前面加上两个破折号，而不是一个。`--dport`选项指定我们希望此规则操作的目标端口。（请注意，我们也可以将规则的这部分列为`--dport 22`，因为`22`是 SSH 端口的编号。）

+   `-j ACCEPT`：将所有内容与`-j ACCEPT`放在一起，我们就有了一个允许其他机器通过安全外壳连接到这台机器的规则。

+   最后的`DROP`规则悄悄地阻止所有未经特别允许的连接和数据包。

实际上，我们可以以两种方式编写最终的阻止规则：

+   `sudo iptables -A INPUT -j DROP`：它会导致防火墙默默地阻止数据包，而不会向这些数据包的源发送任何通知。

+   `sudo iptables -A INPUT -j REJECT`：它也会导致防火墙阻止数据包，但它还会向源发送有关数据包被阻止的消息。一般来说，最好使用`DROP`，因为我们通常希望使恶意行为者更难以弄清楚我们的防火墙配置。

无论哪种方式，您总是希望将此规则放在链的末尾，因为在它之后的任何`ALLOW`规则都将不起作用。

最后，我们对`INPUT`链有了一个几乎完整的、可用的规则集：

```
donnie@ubuntu:~$ sudo iptables -L
Chain INPUT (policy ACCEPT)
target     prot opt source               destination
ACCEPT     all  --  anywhere             anywhere             ctstate RELATED,ESTABLISHED
ACCEPT     tcp  --  anywhere             anywhere             tcp dpt:ssh
DROP       all  --  anywhere             anywhere

Chain FORWARD (policy ACCEPT)
target     prot opt source               destination

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination
donnie@ubuntu:~$
```

它几乎完成了，因为还有一件小事我们忘了。也就是说，我们需要允许环回接口的流量。这没关系，因为这给了我们一个很好的机会，看看如果我们不想把它放在最后，我们如何在想要的位置插入规则。在这种情况下，我们将在`INPUT 1`处插入规则，这是`INPUT`链的第一个位置：

```
sudo iptables -I INPUT 1 -i lo -j ACCEPT
```

当我们查看我们的新规则集时，我们会看到一些非常奇怪的东西：

```
donnie@ubuntu:~$ sudo iptables -L
Chain INPUT (policy ACCEPT)
target prot opt source destination
ACCEPT all -- anywhere anywhere
ACCEPT all -- anywhere anywhere ctstate RELATED,ESTABLISHED
ACCEPT tcp -- anywhere anywhere tcp dpt:ssh
DROP all -- anywhere anywhere

Chain FORWARD (policy ACCEPT)
target prot opt source destination

Chain OUTPUT (policy ACCEPT)
target prot opt source destination
donnie@ubuntu:~$
```

嗯...

第一条规则和最后一条规则看起来是一样的，只是一个是`DROP`，另一个是`ACCEPT`。让我们再次使用`-v`选项查看一下：

```
donnie@ubuntu:~$ sudo iptables -L -v
Chain INPUT (policy ACCEPT 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination
 0     0 ACCEPT     all  --  lo     any     anywhere             anywhere
 393 25336 ACCEPT     all  --  any    any     anywhere             anywhere             ctstate RELATED,ESTABLISHED
 0     0 ACCEPT     tcp  --  any    any     anywhere             anywhere             tcp dpt:ssh
 266 42422 DROP       all  --  any    any     anywhere             anywhere

Chain FORWARD (policy ACCEPT 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination

Chain OUTPUT (policy ACCEPT 72 packets, 7924 bytes)
 pkts bytes target     prot opt in     out     source               destination
donnie@ubuntu:~$
```

现在，我们看到`lo`，即环回，出现在第一条规则的`in`列下，`any`出现在最后一条规则的`in`列下。这一切看起来很不错，除了如果我们现在重新启动机器，规则将消失。我们需要做的最后一件事是使它们永久。有几种方法可以做到这一点，但在 Ubuntu 机器上最简单的方法是安装`iptables-persistent`软件包：

```
sudo apt install iptables-persistent
```

在安装过程中，您将看到两个屏幕，询问您是否要保存当前的 iptables 规则集。第一个屏幕将用于 IPv4 规则，第二个屏幕将用于 IPv6 规则：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sec-hdn/img/052567bc-129d-4fcc-a237-81b925648105.png)

现在，您将在`/etc/iptables`目录中看到两个新的规则文件：

```
donnie@ubuntu:~$ ls -l /etc/iptables*
total 8
-rw-r--r-- 1 root root 336 Oct 10 10:29 rules.v4
-rw-r--r-- 1 root root 183 Oct 10 10:29 rules.v6
donnie@ubuntu:~$
```

如果您现在重新启动机器，您会看到您的 iptables 规则仍然存在并生效。

# 基本 iptables 用法的实验室

您将在您的 Ubuntu 虚拟机上进行此实验室。

1.  关闭您的 Ubuntu 虚拟机，并创建一个快照。

您将在下一节的实验室中回滚到此快照。

1.  使用以下命令查看您的 iptables 规则，或者缺少规则：

```
 sudo iptables -L
```

1.  创建您需要的基本防火墙规则，允许安全外壳访问，但拒绝其他所有内容：

```
 sudo iptables -A INPUT -m conntrack 
                                      --ctstate ESTABLISHED,RELATED
                      -j ACCEPT
 sudo iptables -A INPUT -p tcp --dport ssh -j ACCEPT
 sudo iptables -A INPUT -j DROP
```

1.  使用以下命令查看结果：

```
 sudo iptables -L
```

1.  哎呀，看来您忘记了环回接口。在列表顶部为其添加一个规则：

```
 sudo iptables -I INPUT 1 -i lo -j ACCEPT
```

1.  使用这两个命令查看结果。注意每个输出之间的差异：

```
 sudo iptables -L
 sudo iptables -L -v
```

1.  安装`iptables-persistent`软件包，并在提示时选择保存 IPv4 和 IPv6 规则：

```
         sudo apt install iptables-persistent
```

1.  重新启动虚拟机，并验证您的规则是否仍然有效。

1.  实验室结束。

现在，我知道你在想，“*哇，为了设置一个基本防火墙，要跳过这么多环节*。”是的，你是对的。所以，请给我一点时间来摆脱我刚刚用 iptables 做的事情，我会向您展示 Ubuntu 人民是如何简化事情的。

您可以在这里了解如何在 Ubuntu 上使用 iptables 的全部信息：[`help.ubuntu.com/community/IptablesHowTo`](https://help.ubuntu.com/community/IptablesHowTo)。

# Ubuntu 系统的 Uncomplicated Firewall

Uncomplicated Firewall 已经安装在您的 Ubuntu 机器上。它仍然使用 iptables 服务，但提供了一组大大简化的命令。执行一个简单的命令来启用它，您就有了一个良好的、预配置的防火墙。桌面机器上有一个图形化的前端，但由于我们正在学习服务器安全性，我们只会在这里介绍命令行实用程序。

# ufw 的基本用法

ufw 默认处于禁用状态，因此您需要启用它：

```
donnie@ubuntu:~$ sudo ufw enable
Command may disrupt existing ssh connections. Proceed with operation (y|n)? y
Firewall is active and enabled on system startup
donnie@ubuntu:~$
```

为了做到这一点，我从我信任的 OpenSUSE 工作站的终端远程登录到了虚拟机。它警告我说我的安全 Shell 连接可能会中断，但并没有发生。 （这可能是因为连接跟踪规则，也可能是我运气好。）我会留给你去运行`sudo iptables -L`，因为 ufw 创建了一个非常庞大的默认规则集，这在这本书中是不可能显示的。

接下来，让我们添加一条规则，以便将来可以通过安全 Shell 进行远程连接：

```
sudo ufw allow 22/tcp
```

运行`sudo iptables -L`，你会看到新规则出现在`ufw-user-input`链中：

```
Chain ufw-user-input (1 references)
target     prot opt source               destination
ACCEPT     tcp  --  anywhere             anywhere             tcp dpt:ssh
```

在前面的`sudo ufw allow 22/tcp`命令中，我们必须指定 TCP 协议，因为 TCP 是我们安全 Shell 所需的。我们也可以只通过不指定协议来为 TCP 和 UDP 打开端口。例如，如果你正在设置 DNS 服务器，你会希望为两种协议打开端口`53`（你会看到端口`53`的条目列为`domain`端口）：

```
sudo ufw allow 53

Chain ufw-user-input (1 references)
target     prot opt source               destination
ACCEPT     tcp  --  anywhere             anywhere             tcp dpt:ssh
ACCEPT     tcp  --  anywhere             anywhere             tcp dpt:domain
ACCEPT     udp  --  anywhere             anywhere             udp dpt:domain
```

如果你运行`sudo ip6tables -L`，你会看到 IPv6 的规则也被添加到了前面两个示例中。

# 基本 ufw 使用的实验。

你将在你的 Ubuntu 虚拟机的干净快照上进行这个实验：

1.  关闭你的 Ubuntu 虚拟机并恢复快照。（你要这样做是为了摆脱你刚刚做的所有 iptables 的东西。）

1.  当你重新启动虚拟机后，验证 iptables 规则现在已经消失：

```
 sudo iptables -L
```

1.  查看 ufw 的状态，启用它，并查看结果：

```
 sudo ufw status
 sudo ufw enable
 sudo ufw status
 sudo iptables -L
 sudo ip6tables -L
```

1.  打开`22/tcp`端口以允许安全 Shell 访问：

```
 sudo ufw allow 22/tcp
 sudo iptables -L
 sudo ip6tables -L
```

1.  这次，为 TCP 和 UDP 同时打开端口`53`：

```
        sudo ufw allow 53
 sudo iptables -L
 sudo ip6tables -L
```

1.  实验结束。

# Red Hat 系统的 firewalld

到目前为止，我们已经看过 iptables，这是一个通用的防火墙管理系统，适用于所有的 Linux 发行版，以及 ufw，它只适用于 Ubuntu。接下来，我们将把注意力转向**firewalld**，它是专门针对 Red Hat Enterprise Linux 7 及其所有后代的。

与 Ubuntu 的 ufw 不同，firewalld 不仅仅是 iptables 的易于使用的前端。相反，它是一个全新的防火墙业务方式，并且与 iptables 不兼容。不过，要明白的是，iptables 仍然安装在 Red Hat 7 系列上，但没有启用，因为你不能同时启用 iptables 和 firewalld。如果你必须使用利用 iptables 的旧 shell 脚本，你可以禁用 firewalld 并启用 iptables。

iptables 和 firewalld 不兼容的原因是，iptables 将其规则存储在`/etc/sysconfig`目录中的纯文本文件中，而 firewalld 将其规则文件存储在`/etc/firewalld`目录和`/usr/lib/firewalld`目录中的`.xml`格式文件中。此外，iptables 不理解 firewalld 所理解的区域和服务的概念，规则本身的格式也完全不同。因此，即使你可以同时运行 iptables 和 firewalld，你最终只会混淆系统并破坏防火墙。

关键是，你可以在 Red Hat 或 CentOS 机器上运行 iptables 或 firewalld，但不能同时运行两者。

如果你在桌面机上运行 Red Hat 或 CentOS，你会在应用程序菜单中看到有一个 firewalld 的 GUI 前端。然而，在文本模式服务器上，你只能使用 firewalld 命令。出于某种原因，Red Hat 的人们没有为文本模式服务器创建一个类似 ncurses 的程序，就像他们在旧版本的 Red Hat 上为 iptables 配置所做的那样。

firewalld 的一个重要优势是它是动态管理的。这意味着你可以在不重启防火墙服务的情况下更改防火墙配置，并且不会中断到服务器的任何现有连接。

# 验证 firewalld 的状态

让我们首先验证 firewalld 的状态。有两种方法可以做到这一点。我们可以使用`firewall-cmd`的`--state`选项：

```
[donnie@localhost ~]$ sudo firewall-cmd --state
running
[donnie@localhost ~]$
```

或者，如果我们想要更详细的状态，我们可以像检查 systemd 机器上的任何其他守护程序一样检查守护程序：

```
[donnie@localhost ~]$ sudo systemctl status firewalld
● firewalld.service - firewalld - dynamic firewall daemon
 Loaded: loaded (/usr/lib/systemd/system/firewalld.service; enabled; vendor preset: enabled)
 Active: active (running) since Fri 2017-10-13 13:42:54 EDT; 1h 56min ago
 Docs: man:firewalld(1)
 Main PID: 631 (firewalld)
 CGroup: /system.slice/firewalld.service
 └─631 /usr/bin/python -Es /usr/sbin/firewalld --nofork --nopid

Oct 13 13:42:55 localhost.localdomain firewalld[631]: WARNING: ICMP type 'reject-route' is not supported by the kernel for ipv6.
Oct 13 13:42:55 localhost.localdomain firewalld[631]: WARNING: reject-route: INVALID_ICMPTYPE: No supported ICMP type., ignoring for run-time.
Oct 13 15:19:41 localhost.localdomain firewalld[631]: WARNING: ICMP type 'beyond-scope' is not supported by the kernel for ipv6.
Oct 13 15:19:41 localhost.localdomain firewalld[631]: WARNING: beyond-scope: INVALID_ICMPTYPE: No supported ICMP type., ignoring for run-time.
Oct 13 15:19:41 localhost.localdomain firewalld[631]: WARNING: ICMP type 'failed-policy' is not supported by the kernel for ipv6.
Oct 13 15:19:41 localhost.localdomain firewalld[631]: WARNING: failed-policy: INVALID_ICMPTYPE: No supported ICMP type., ignoring for run-time.
Oct 13 15:19:41 localhost.localdomain firewalld[631]: WARNING: ICMP type 'reject-route' is not supported by the kernel for ipv6.
Oct 13 15:19:41 localhost.localdomain firewalld[631]: WARNING: reject-route: INVALID_ICMPTYPE: No supported ICMP type., ignoring for run-time.
[donnie@localhost ~]$
```

# firewalld 区域

firewalld 是一个相当独特的工具，因为它带有几个预配置的区域和服务。如果您查看您的 CentOS 机器的`/usr/lib/firewalld/zones`目录，您将看到以`.xml`格式的区域文件：

```
[donnie@localhost ~]$ cd /usr/lib/firewalld/zones
[donnie@localhost zones]$ ls
block.xml dmz.xml drop.xml external.xml home.xml internal.xml public.xml trusted.xml work.xml
[donnie@localhost zones]$
```

每个区域文件都指定了要打开的端口以及要为各种给定情况阻止的端口。区域还可以包含有关 ICMP 消息、转发端口、伪装信息和丰富语言规则的规则。

例如，公共区域的`.xml`文件，它被设置为默认值，看起来像这样：

```
<?xml version="1.0" encoding="utf-8"?>
<zone>
  <short>Public</short>
  <description>For use in public areas. You do not trust the other computers on networks to not harm your computer. Only selected incoming connections are accepted.</description>
  <service name="ssh"/>
  <service name="dhcpv6-client"/>
</zone>
```

在`service name`行中，您可以看到唯一打开的端口是用于安全外壳访问和用于 DHCPv6 发现的端口。查看`home.xml`文件，您将看到它还打开了用于多播 DNS 的端口，以及允许此计算机从 Samba 服务器或 Windows 服务器访问共享目录的端口：

```
<?xml version="1.0" encoding="utf-8"?>
<zone>
  <short>Home</short>
  <description>For use in home areas. You mostly trust the other computers on networks to not harm your computer. Only selected incoming connections are accepted.</description>
  <service name="ssh"/>
  <service name="mdns"/>
  <service name="samba-client"/>
  <service name="dhcpv6-client"/>
</zone>
```

`firewall-cmd`实用程序是您用于配置 firewalld 的工具。您可以使用它查看系统上区域文件的列表，而无需`cd`到区域文件目录中：

```
[donnie@localhost ~]$ sudo firewall-cmd --get-zones
[sudo] password for donnie:
block dmz drop external home internal public trusted work
[donnie@localhost ~]$
```

查看每个区域配置的快速方法是使用`--list-all-zones`选项：

```
[donnie@localhost ~]$ sudo firewall-cmd --list-all-zones
block
 target: %%REJECT%%
 icmp-block-inversion: no
 interfaces:
 sources:
 services:
 ports:
 protocols:
 masquerade: no
 forward-ports:
 source-ports:
 icmp-blocks:
 rich rules:
, , ,
, , ,
```

当然，这只是输出的一部分，因为所有区域的列表超出了我们可以在这里显示的范围。更有可能的是，您只想查看有关特定区域的信息：

```
[donnie@localhost ~]$ sudo firewall-cmd --info-zone=internal
internal
 target: default
 icmp-block-inversion: no
 interfaces:
 sources:
 services: ssh mdns samba-client dhcpv6-client
 ports:
 protocols:
 masquerade: no
 forward-ports:
 source-ports:
 icmp-blocks:
 rich rules:

[donnie@localhost ~]$
```

因此，`internal`区域允许`ssh`、`mdns`、`samba-client`和`dhcpv6-client`服务。这对于在内部局域网上设置客户端机器非常方便。

任何给定的服务器或客户端都将安装一个或多个网络接口适配器。机器中的每个适配器可以分配一个且仅一个 firewalld 区域。要查看默认区域：

```
[donnie@localhost ~]$ sudo firewall-cmd --get-default-zone
public
[donnie@localhost ~]$
```

这很好，但它并没有告诉您与该区域关联的任何网络接口的信息。要查看该信息：

```
[donnie@localhost ~]$ sudo firewall-cmd --get-active-zones
public
 interfaces: enp0s3
[donnie@localhost ~]$
```

当您首次安装 Red Hat 或 CentOS 时，防火墙将已经处于活动状态，并且公共区域将作为默认值。现在，假设您正在将服务器设置在 DMZ 中，并且希望确保其防火墙针对此进行了锁定。您可以将默认区域更改为`dmz`区域。让我们看看`dmz.xml`文件，看看它对我们有什么作用：

```
<?xml version="1.0" encoding="utf-8"?>
<zone>
  <short>DMZ</short>
  <description>For computers in your demilitarized zone that are publicly-accessible with limited access to your internal network. Only selected incoming connections are accepted.</description>
  <service name="ssh"/>
</zone>
```

因此，DMZ 允许的唯一事物是安全外壳。好的，现在足够了，让我们将`dmz`区域设置为默认值：

```
[donnie@localhost ~]$ sudo firewall-cmd --set-default-zone=dmz
[sudo] password for donnie:
success
[donnie@localhost ~]$
```

我们将验证：

```
[donnie@localhost ~]$ sudo firewall-cmd --get-default-zone
dmz
[donnie@localhost ~]$
```

我们一切都很好。除了在 DMZ 中面向互联网的服务器可能需要做的不仅仅是允许 SSH 连接。这就是我们将使用 firewalld 服务的地方。但是，在我们看看之前，让我们考虑另一个重要的问题。

不要修改`/usr/lib/firewalld`目录中的文件。每当您修改 firewalld 配置时，您会看到修改后的文件出现在`/etc/firewalld`目录中。到目前为止，我们只修改了默认区域。因此，我们将在`/etc/firewalld`中看到这个：

```
[donnie@localhost ~]$ sudo ls -l /etc/firewalld
total 12
-rw-------. 1 root root 2003 Oct 11 17:37 firewalld.conf
-rw-r--r--. 1 root root 2006 Aug 4 17:14 firewalld.conf.old
. . .
```

我们可以对这两个文件进行`diff`，以查看它们之间的差异：

```
[donnie@localhost ~]$ sudo diff /etc/firewalld/firewalld.conf /etc/firewalld/firewalld.conf.old
6c6
< DefaultZone=dmz
---
> DefaultZone=public
[donnie@localhost ~]$
```

因此，这两个文件中较新的文件显示`dmz`区域现在是默认区域。

要获取有关 firewalld 区域的更多信息，请输入：

`man firewalld.zones`

# firewalld 服务

每个服务文件都包含需要为特定服务打开的端口列表。可选地，服务文件可能包含一个或多个目标地址，或调用任何所需的模块，例如用于连接跟踪。对于某些服务，您只需要打开一个端口。其他服务，例如 Samba 服务，需要打开多个端口。无论哪种方式，有时记住与每个服务相关的服务名称比端口号更方便。

服务文件位于`/usr/lib/firewalld/services`目录中。您可以使用`firewall-cmd`命令查看它们的列表，就像您可以查看区域列表一样：

```
[donnie@localhost ~]$ sudo firewall-cmd --get-services
[sudo] password for donnie:
RH-Satellite-6 amanda-client amanda-k5-client bacula bacula-client bitcoin bitcoin-rpc bitcoin-testnet bitcoin-testnet-rpc ceph ceph-mon cfengine condor-collector ctdb dhcp dhcpv6 dhcpv6-client dns docker-registry dropbox-lansync elasticsearch freeipa-ldap freeipa-ldaps freeipa-replication freeipa-trust ftp ganglia-client ganglia-master high-availability http https imap imaps ipp ipp-client ipsec iscsi-target kadmin kerberos kibana klogin kpasswd kshell ldap ldaps libvirt libvirt-tls managesieve mdns mosh mountd ms-wbt mssql mysql nfs nrpe ntp openvpn ovirt-imageio ovirt-storageconsole ovirt-vmconsole pmcd pmproxy pmwebapi pmwebapis pop3 pop3s postgresql privoxy proxy-dhcp ptp pulseaudio puppetmaster quassel radius rpc-bind rsh rsyncd samba samba-client sane sip sips smtp smtp-submission smtps snmp snmptrap spideroak-lansync squid ssh synergy syslog syslog-tls telnet tftp tftp-client tinc tor-socks transmission-client vdsm vnc-server wbem-https xmpp-bosh xmpp-client xmpp-local xmpp-server
[donnie@localhost ~]$
```

`dropbox-lansync`服务对我们 Dropbox 用户非常有用。让我们看看这打开了哪些端口：

```
[donnie@localhost ~]$ sudo firewall-cmd --info-service=dropbox-lansync
[sudo] password for donnie:
dropbox-lansync
 ports: 17500/udp 17500/tcp
 protocols:
 source-ports:
 modules:
 destination:
[donnie@localhost ~]$
```

看起来 Dropbox 使用端口`17500` UDP 和 TCP。

现在，假设我们在 DMZ 中设置了我们的 Web 服务器，并将`dmz`区域设置为其默认值：

```
[donnie@localhost ~]$ sudo firewall-cmd --info-zone=dmz
dmz (active)
 target: default
 icmp-block-inversion: no
 interfaces: enp0s3
 sources:
 services: ssh
 ports:
 protocols:
 masquerade: no
 forward-ports:
 source-ports:
 icmp-blocks:
 rich rules:

[donnie@localhost ~]$
```

正如我们之前看到的，只有安全外壳端口是打开的。让我们修复一下，以便用户实际访问我们的网站：

```
[donnie@localhost ~]$ sudo firewall-cmd --add-service=http
success
[donnie@localhost ~]$
```

当我们再次查看`dmz`区域的信息时，我们会看到：

```
[donnie@localhost ~]$ sudo firewall-cmd --info-zone=dmz
dmz (active)
 target: default
 icmp-block-inversion: no
 interfaces: enp0s3
 sources:
 services: ssh http
 ports:
 protocols:
 masquerade: no
 forward-ports:
 source-ports:
 icmp-blocks:
 rich rules:

[donnie@localhost ~]$
```

我们看到`http`服务现在是允许的。但是当我们在`info`命令中添加`--permanent`选项时会发生什么：

```
[donnie@localhost ~]$ sudo firewall-cmd --permanent --info-zone=dmz
dmz
 target: default
 icmp-block-inversion: no
 interfaces:
 sources:
 services: ssh
 ports:
 protocols:
 masquerade: no
 forward-ports:
 source-ports:
 icmp-blocks:
 rich rules:
[donnie@localhost ~]$
```

糟糕！`http`服务不在这里。怎么回事？

对于任何命令行对区域或服务的更改，您都需要添加`--permanent`选项，以使更改在重新启动后持久生效。但是，如果没有`--permanent`选项，更改将立即生效。有了`--permanent`选项，您必须重新加载防火墙配置才能使更改生效。为了演示，我将重新启动虚拟机以摆脱`http`服务。

好的，我已经重新启动，`http`服务现在已经消失了：

```
[donnie@localhost ~]$ sudo firewall-cmd --info-zone=dmz
[sudo] password for donnie:
dmz (active)
 target: default
 icmp-block-inversion: no
 interfaces: enp0s3
 sources:
 services: ssh
 ports:
 protocols:
 masquerade: no
 forward-ports:
 source-ports:
 icmp-blocks:
 rich rules:

[donnie@localhost ~]$
```

这次，我将使用一个命令添加两个服务，并指定更改为永久性：

```
[donnie@localhost ~]$ sudo firewall-cmd --permanent --add-service={http,https}
[sudo] password for donnie:
success
[donnie@localhost ~]$
```

您可以使用单个命令添加尽可能多的服务，但是您必须用逗号分隔它们，并在一对花括号中将整个列表括起来。让我们看看结果：

```
[donnie@localhost ~]$ sudo firewall-cmd --info-zone=dmz
dmz (active)
 target: default
 icmp-block-inversion: no
 interfaces: enp0s3
 sources:
 services: ssh
 ports:
 protocols:
 masquerade: no
 forward-ports:
 source-ports:
 icmp-blocks:
 rich rules:

[donnie@localhost ~]$
```

自从我们决定将此配置变为永久性后，它还没有生效。但是，如果我们在`--info-zone`命令中添加`--permanent`选项，我们会看到配置文件确实已经更改：

```
[donnie@localhost ~]$ sudo firewall-cmd --permanent --info-zone=dmz
dmz
 target: default
 icmp-block-inversion: no
 interfaces:
 sources:
 services: ssh http https
 ports:
 protocols:
 masquerade: no
 forward-ports:
 source-ports:
 icmp-blocks:
 rich rules:

[donnie@localhost ~]$
```

现在，我们需要通过重新加载配置来使更改生效：

```
[donnie@localhost ~]$ sudo firewall-cmd --reload
success
[donnie@localhost ~]$
```

再次运行`sudo firewall-cmd --info-zone=dmz`命令，您将看到新配置现在已生效。

要从区域中删除服务，只需用`--remove-service`替换`--add-service`。

请注意，在所有这些服务命令中，我们从未指定我们正在处理的区域。这是因为如果我们不指定区域，firewalld 会假定我们正在处理默认区域。如果要将服务添加到除默认区域以外的其他区域，只需在命令中添加`--zone=`选项。

# 向 firewalld 区域添加端口

拥有服务文件很方便，只是并非您需要运行的每个服务都有自己预定义的服务文件。假设您在服务器上安装了 Webmin，它需要打开端口`10000/tcp`。快速的`grep`操作将显示端口`10000`不在我们预定义的任何服务中：

```
donnie@localhost services]$ pwd
/usr/lib/firewalld/services
[donnie@localhost services]$ grep '10000' *
[donnie@localhost services]$
```

因此，让我们将该端口添加到我们的默认区域，即`dmz`区域：

```
donnie@localhost ~]$ sudo firewall-cmd --add-port=10000/tcp
[sudo] password for donnie:
success
[donnie@localhost ~]$
```

同样，这不是永久性的，因为我们没有包括`--permanent`选项。让我们再做一次，然后重新加载：

```
[donnie@localhost ~]$ sudo firewall-cmd --permanent --add-port=10000/tcp
success
[donnie@localhost ~]$ sudo firewall-cmd --reload
success
[donnie@localhost ~]$
```

您还可以通过在一对花括号中包含逗号分隔的列表一次添加多个端口，就像我们在服务中所做的那样（是的，我故意没有加上`--permanent`）：

```
[donnie@localhost ~]$ sudo firewall-cmd --add-port={636/tcp,637/tcp,638/udp}
success
[donnie@localhost ~]$
```

当然，您也可以用`--remove-port`替换`--add-port`来从区域中删除端口。

# firewalld 丰富的语言规则

到目前为止，我们所看到的可能是您在一般使用场景中所需的全部内容，但是，为了更精细的控制，您需要了解**丰富的语言规则**。（是的，这确实是它们的名称。）

与 iptables 规则相比，丰富的语言规则稍微不那么神秘，并且更接近普通英语。因此，如果您是新手编写防火墙规则，您可能会发现丰富的语言更容易学习。另一方面，如果您已经习惯编写 iptables 规则，您可能会发现丰富语言的某些元素有点古怪。让我们看一个例子：

```
sudo firewall-cmd --add-rich-rule='rule family="ipv4" source address="200.192.0.0/24" service name="http" drop'
```

因此，我们正在添加一个丰富的规则。请注意，整个规则被一对单引号包围，并且每个参数的分配值被一对双引号包围。使用此规则，我们正在说我们正在使用 IPv4，并且我们希望静默地阻止`http`端口接受来自`200.192.0.0/24`网络的数据包。我们没有使用`--permanent`选项，因此当我们重新启动机器时，此规则将消失。让我们看看我们的区域在添加了这条新规则后是什么样子：

```
[donnie@localhost ~]$ sudo firewall-cmd --info-zone=dmz
[sudo] password for donnie:
dmz (active)
 target: default
 icmp-block-inversion: no
 interfaces: enp0s3
 sources:
 services: ssh http https
 ports: 10000/tcp 636/tcp 637/tcp 638/udp
 protocols:
 masquerade: no
 forward-ports:
 source-ports:
 icmp-blocks:
 rich rules:
 rule family="ipv4" source address="200.192.0.0/24" service name="http" drop
[donnie@localhost ~]$
```

丰富的规则显示在底部。在我们测试了这条规则以确保它能够满足我们的需求之后，我们将使其永久化：

```
sudo firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="200.192.0.0/24" service name="http" drop'

sudo firewall-cmd --reload
```

您可以轻松地通过将`family="ipv4"`替换为`family="ipv6"`并提供适当的 IPv6 地址范围来为 IPv6 编写规则。

有些规则是通用的，适用于 IPv4 或 IPv6。假设我们想要记录关于**网络时间协议**（**NTP**）数据包的消息，并且您希望每分钟记录不超过一条消息。创建该规则的命令如下：

```
sudo firewall-cmd --permanent --add-rich-rule='rule service name="ntp" audit limit value="1/m" accept'
```

当然，firewalld 丰富的语言规则还有很多内容，我们无法在这里全部呈现。但是，至少您现在知道了基础知识。有关更多信息，请参阅`man`页面：

```
man firewalld.richlanguage
```

# firewalld 命令的实践实验

通过这个实验，您将练习基本的 firewalld 命令：

1.  登录到您的 CentOS 7 虚拟机并运行以下命令。观察每个命令后的输出：

```
 sudo firewall-cmd --get-zones
 sudo firewall-cmd --get-default-zone
 sudo firewall-cmd --get-active-zones
```

1.  简要查看处理 firewalld 区域的`man`页面：

```
 man firewalld.zones
 man firewalld.zone
```

（是的，有两个。一个解释了区域配置文件，另一个解释了区域本身。）

1.  查看所有可用区域的配置信息：

```
 sudo firewall-cmd --list-all-zones
```

1.  查看预定义服务列表。然后，查看有关`dropbox-lansync`服务的信息：

```
 sudo firewall-cmd --get-services
 sudo firewall-cmd --info-service=dropbox-lansync
```

1.  将默认区域设置为`dmz`。查看有关该区域的信息，添加`http`和`https`服务，然后再次查看区域信息：

```
 sudo firewall-cmd --set-default-zone=dmz
 sudo firewall-cmd --permanent --add-service={http,https}
 sudo firewall-cmd --info-zone=dmz
 sudo firewall-cmd --permanent --info-zone=dmz
```

1.  重新加载防火墙配置，并再次查看区域信息。还要查看正在允许的服务列表：

```
 sudo firewall-cmd --reload
 sudo firewall-cmd --info-zone=dmz
 sudo firewall-cmd --list-services
```

1.  永久打开端口`10000/tcp`，并查看结果：

```
 sudo firewall-cmd --permanent --add-port=10000/tcp
 sudo firewall-cmd --list-ports
 sudo firewall-cmd --reload
 sudo firewall-cmd --list-ports
 sudo firewall-cmd --info-zone=dmz
```

1.  删除刚刚添加的端口：

```
 sudo firewall-cmd --permanent --remove-port=10000/tcp
 sudo firewall-cmd --reload
 sudo firewall-cmd --list-ports
 sudo firewall-cmd --info-zone=dmz
```

1.  查看 firewalld 的主要页面列表：

```
 apropos firewall
```

1.  实验结束。

# nftables-一种更通用的防火墙系统

现在让我们把注意力转向 nftables，这个新来的。那么，nftables 有什么优点？（是的，这是一个双关语。）

+   现在，您可以忘记需要单独的守护程序和实用程序来处理所有不同的网络组件。 iptables，ip6tables，ebtables 和 arptables 的功能现在都合并在一个整洁的软件包中。 nft 实用程序现在是您唯一需要的防火墙实用程序。

+   使用 nftables，您可以创建多维树来显示您的规则集。这使得故障排除变得更加容易，因为现在更容易跟踪数据包通过所有规则。

+   使用 iptables，默认情况下会安装过滤器、NAT、mangle 和安全表，无论您是否使用每个表。使用 nftables，您只创建您打算使用的表，从而提高性能。

+   与 iptables 不同，您可以在一条规则中指定多个操作，而不必为每个操作创建多个规则。

+   与 iptables 不同，新规则是原子性添加的。（这是说，不再需要重新加载整个规则集才能添加一个规则。）

+   nftables 具有自己的内置脚本引擎，允许您编写更高效和更易读的脚本。

+   如果您已经有很多仍然需要使用的 iptables 脚本，您可以安装一组实用程序，以帮助您将它们转换为 nftables 格式。

# nftables 表和链

如果您习惯于 iptables，您可能会认识到一些 nftables 术语。唯一的问题是，一些术语以不同的方式使用，具有不同的含义。这就是我所说的一些内容：

+   **Tables**: nftables 中的表指的是特定的协议家族。表类型有 ip、ip6、inet、arp、bridge 和 netdev。

+   **Chains**: nftables 中的链大致相当于 iptables 中的表。例如，在 nftables 中，你可以有 filter、route 或 NAT 链。

# 开始使用 nftables

让我们从 Ubuntu 虚拟机的干净快照开始，并安装 nftables 包。

nftables 的命令行实用程序是`nft`。你可以在 Bash shell 中执行`nft`命令，或者可以执行`sudo nft -i`以运行交互模式下的 nft。对于我们目前的演示，我们将在 Bash shell 中运行命令。

现在，让我们来看一下已安装的表的列表：

```
sudo apt install nftables
sudo nft list tables
```

嗯...你没有看到任何表，对吧？所以，让我们加载一些表。

如果你在`/etc`目录中查看`nftables.conf`文件，你会看到一个基本的 nft 防火墙配置的开端：

```
#!/usr/sbin/nft -f
flush ruleset
table inet filter {
        chain input {
                type filter hook input priority 0;

                # accept any localhost traffic
                iif lo accept

                # accept traffic originated from us
                ct state established,related accept

                # activate the following line to accept 
                  common local services
                # tcp dport { 22, 80, 443 } ct state new accept

                # accept neighbour discovery otherwise 
                  IPv6 connectivity breaks.
                ip6 nexthdr icmpv6 icmpv6 type { nd-neighbor-solicit,
                  nd-router-advert, nd-neighbor-advert } accept

                # count and drop any other traffic
                counter drop
        }
}
```

这是所有这些意思的分解：

+   `#!/usr/sbin/nft -f`: 虽然你可以用 nftables 命令创建普通的 Bash shell 脚本，但最好使用 nftables 附带的内置脚本引擎。这样，我们可以使我们的脚本更易读，并且不必在每个想要执行的命令前面输入`nft`。

+   `flush ruleset`: 我们想要从一个干净的状态开始，所以我们将清除已经加载的任何规则。

+   `table inet filter`: 这创建了一个 inet 家族的过滤器，适用于 IPv4 和 IPv6。这个表的名称是`filter`，但也可以是更具描述性的名称。

+   `chain input`: 在第一对花括号中，我们有一个名为`input`的链。（再次强调，名称可以更具描述性。）

+   `type filter hook input priority 0;`: 在接下来的一对花括号中，我们定义了我们的链，然后列出了规则。这个链被定义为`filter`类型。`hook input`表示这个链是用来处理传入的数据包的。因为这个链既有`hook`又有`priority`，所以它将直接接受来自网络堆栈的数据包。

+   最后，我们有一个非常基本的主机防火墙的标准规则，从`iif`规则开始，允许环回接口接受数据包（**iif**代表**输入接口**）。

+   接下来是标准的连接跟踪（`ct`）规则，它接受对这个主机发出的连接请求的流量。

+   然后，有一个被注释掉的规则，用于接受安全外壳和安全和非安全的网页流量。`ct state new`表示防火墙将允许其他主机在这些端口上启动与我们服务器的连接。

+   `ipv6`规则接受邻居发现数据包，允许 IPv6 功能。

+   最后的`counter drop`规则会默默地阻止所有其他流量，并计算它阻止的数据包和字节数。这是一个例子，说明一个规则可以执行两种不同的操作。

如果你的 Ubuntu 服务器上只需要一个基本的、简单的防火墙，最好的办法就是编辑`/etc/nftables.conf`文件以满足你自己的需求。首先，让我们从`tcp dport`行的前面删除注释符号，并且去掉`80`和`443`端口。现在这行应该是这样的：

```
tcp dport 22 ct state new accept
```

请注意，当你只打开一个端口时，你不需要将该端口号括在花括号中。当打开多个端口时，只需在花括号中包含逗号分隔的列表，第一个元素前面和最后一个元素后面留有空格。

加载配置文件，并查看结果：

```
sudo nft -f /etc/nftables.conf

donnie@ubuntu2:~$ sudo nft list table inet filter
table inet filter {
 chain input {
 type filter hook input priority 0; policy accept;
 iif lo accept
 ct state established,related accept
 tcp dport ssh ct state new accept
 ip6 nexthdr ipv6-icmp icmpv6 type { nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert} accept
 counter packets 67 bytes 10490 drop
 }
}
donnie@ubuntu2:~$
```

现在，假设我们想要阻止某些 IP 地址到达这台机器的安全外壳端口。我们可以编辑文件，在打开`22`端口的规则之上放置一个`drop`规则。文件的相关部分将如下所示：

```
tcp dport 22 ip saddr { 192.168.0.7, 192.168.0.10 } drop
tcp dport 22 ct state new accept
```

重新加载文件后，我们将阻止来自两个不同 IPv4 地址的 SSH 访问。请注意，我们将`drop`规则放在`accept`规则之前，因为如果首先读取`accept`规则，`drop`规则将永远不会生效。

另一个非常酷的事情要注意的是，我们在同一个配置文件中混合了 IPv4（ip）规则和 IPv6（ip6）规则。这就是使用 inet 类型表的美妙之处。为了简单和灵活性，您应尽可能使用 inet 表，而不是单独的 ip 和 ip6 表。

大多数情况下，当您只需要一个简单的主机防火墙时，最好的选择就是使用此`nftables.conf`文件作为起点，并编辑文件以满足自己的需求。但是，有时您可能会发现命令行组件也很有用。

# 使用 nft 命令

使用 nft 实用程序有两种方法。您可以直接从 Bash shell 执行所有操作，每个要执行的操作之前都要加上 nft，然后是`nft`子命令。您还可以在交互模式下使用 nft。对于我们现在的目的，我们将使用 Bash shell。

让我们首先删除先前的配置，并创建一个 inet 表，因为我们希望它适用于 IPv4 和 IPv6。我们希望给它一个相当描述性的名称，所以让我们称之为`ubuntu_filter`：

```
sudo nft delete table inet filter
sudo nft list tables
sudo nft add table inet ubuntu_filter
sudo nft list tables
```

接下来，我们将在我们刚刚创建的表中添加一个`input`过滤器链。（请注意，由于我们是从 Bash shell 执行此操作，因此需要使用反斜杠转义分号。）

```
sudo nft add chain inet ubuntu_filter input { type filter hook input priority 0\; policy drop\; }
```

在此命令中，`ubuntu_filter`之后的第一个`input`是链的名称。（我们本可以给它一个更具描述性的名称，但目前，`input`就可以了。）在一对花括号内，我们正在为此链设置参数。

每个 nftables 协议族都有自己的一组钩子，定义了数据包的处理方式。目前，我们只关注 ip/ip6/inet 族，它们具有以下钩子：

+   预处理

+   输入

+   前进

+   产出

+   出口

其中，我们目前只关注输入和输出钩子，这将适用于过滤器类型链。通过为我们的输入链指定一个钩子和优先级，我们正在表示我们希望此链成为基本链，它将直接从网络堆栈接受数据包。您还会看到，某些参数必须以分号结尾，如果您从 Bash shell 运行命令，则需要用反斜杠转义分号。最后，我们正在指定默认策略为`drop`。如果我们没有指定`drop`作为默认策略，那么默认策略将是`accept`。

您输入的每个`nft`命令都会立即生效。因此，如果您远程执行此操作，一旦创建了具有默认`drop`策略的过滤器链，您将立即断开安全外壳连接。

有些人喜欢创建具有默认`accept`策略的链，然后在最后添加一个`drop`规则。其他人喜欢创建具有默认`drop`策略的链，然后在最后不添加 drop 规则。使用默认`accept`规则的优势在于，您可以远程执行这些防火墙命令，而不必担心被锁定。

验证链是否已添加，您应该会看到类似于此的内容：

```
donnie@ubuntu2:~$ sudo nft list table inet ubuntu_filter
[sudo] password for donnie:
table inet filter {
 chain input {
 type filter hook input priority 0; policy drop;
 }
}
donnie@ubuntu2:~$
```

这很好，但我们仍然需要一些规则。让我们从连接跟踪规则和打开安全外壳端口的规则开始。然后我们将验证它们是否已添加：

```
sudo nft add rule inet ubuntu_filter input ct state established accept
sudo nft add rule inet ubuntu_filter input tcp dport 22 ct state new accept

donnie@ubuntu2:~$ sudo nft list table inet ubuntu_filter
table inet ubuntu_filter {
 chain input {
 type filter hook input priority 0; policy drop;
 ct state established accept
 tcp dport ssh ct state new accept
 }
}
donnie@ubuntu2:~ 
```

好的，看起来不错。您现在有一个基本的工作防火墙，允许安全外壳连接。好吧，除了我们在 ufw 章节中所做的一样，我们忘记创建一个允许环回适配器接受数据包的规则。由于我们希望此规则位于规则列表的顶部，因此我们将使用`insert`而不是`add`：

```
sudo nft insert rule inet ubuntu_filter input iif lo accept

donnie@ubuntu2:~$ sudo nft list table inet ubuntu_filter
table inet ubuntu_filter {
 chain input {
 type filter hook input priority 0; policy drop;
 iif lo accept
 ct state established accept
 tcp dport ssh ct state new accept
 }
}
donnie@ubuntu2:~$
```

现在，我们已经准备就绪。但是，如果我们想在特定位置插入规则怎么办？为此，您需要使用带有`-a`选项的`list`来查看`handles`规则：

```
donnie@ubuntu2:~$ sudo nft list table inet ubuntu_filter -a
table inet ubuntu_filter {
 chain input {
 type filter hook input priority 0; policy drop;
 iif lo accept # handle 4
 ct state established accept # handle 2
 tcp dport ssh ct state new accept # handle 3
 }
}
donnie@ubuntu2:~$
```

正如您所看到的，句柄的编号没有真正的规律或原因。假设我们想要插入一个关于阻止某些 IP 地址访问安全外壳端口的规则。我们看到`ssh accept`规则是`handle 3`，所以我们需要在它之前插入我们的`drop`规则。我们的命令看起来像这样：

```
sudo nft insert rule inet ubuntu_filter input position 3 tcp dport 22 ip saddr { 192.168.0.7, 192.168.0.10 } drop

donnie@ubuntu2:~$ sudo nft list table inet ubuntu_filter -a
table inet ubuntu_filter {
 chain input {
 type filter hook input priority 0; policy drop;
 iif lo accept # handle 4
 ct state established accept # handle 2
 tcp dport ssh ip saddr { 192.168.0.10, 192.168.0.7} drop # handle 6
 tcp dport ssh ct state new accept # handle 3
 }
}
donnie@ubuntu2:~$
```

因此，要将规则放置在具有`handle 3`标签的规则之前，我们必须`插入`到`位置 3`。我们刚刚插入的新规则具有标签`handle 6`。要删除规则，我们将指定规则的句柄号码：

```
sudo nft delete rule inet ubuntu_filter input handle 6

donnie@ubuntu2:~$ sudo nft list table inet ubuntu_filter -a
table inet ubuntu_filter {
 chain input {
 type filter hook input priority 0; policy drop;
 iif lo accept # handle 4
 ct state established accept # handle 2
 tcp dport ssh ct state new accept # handle 3
 }
}
donnie@ubuntu2:~$
```

与 iptables 一样，您从命令行执行的所有操作在重新启动机器后都会消失。为了使其永久生效，让我们将`list`子命令的输出重定向到一个配置文件中（当然，我们需要给文件一个与默认文件名不同的唯一名称）：

```
sudo sh -c "nft list table inet ubuntu_filter > new_nftables.conf"
```

由于 Bash shell 的一个怪癖，我们无法像通常那样将输出重定向到`/etc`目录中的文件，即使我们使用`sudo`也不行。这就是为什么我不得不添加`sh -c`命令，用双引号括起来的`nft list`命令。现在，当我们查看文件时，我们会发现有一些东西丢失了：

```
table inet ubuntu_filter {
        chain input {
                type filter hook input priority 0; policy drop;
                iif lo accept
                ct state established accept
                tcp dport ssh ct state new accept
        }
}
```

你们这些敏锐的人会发现我们缺少`flush`规则和`shebang`行来指定我们想要解释此脚本的 shell。让我们添加它们：

```
#!/usr/sbin/nft -f
flush ruleset

table inet ubuntu_filter {
        chain input {
                type filter hook input priority 0; policy drop;
                iif lo accept
                ct state established accept
                tcp dport ssh ct state new accept
        }
}
```

好多了。让我们通过加载新配置并观察`list`输出来测试它：

```
sudo nft -f /etc/new_nftables.conf

donnie@ubuntu2:~$ sudo nft list table inet ubuntu_filter
table inet ubuntu_filter {
 chain input {
 type filter hook input priority 0; policy drop;
 iif lo accept
 ct state established accept
 tcp dport ssh ct state new accept
 }
}
donnie@ubuntu2:~$
```

这就是创建自己的简单主机防火墙的全部内容。当然，与仅在文本编辑器中创建脚本文件不同，从命令行运行命令确实需要更多的输入。但是，这样做可以让您在创建规则时即时测试它们。以这种方式创建您的配置，然后将`list`输出重定向到新的配置文件中，可以让您摆脱不得不跟踪所有这些花括号的负担。

还可以将我们刚刚执行的所有`nft`命令放入一个常规的、老式的 Bash shell 脚本中。相信我，你真的不想这样做。只需像我们在这里所做的那样使用 nft-native 脚本格式，您将拥有一个性能更好、更易读的脚本。

# Ubuntu 上的 nftables 实验

对于这个实验，您需要一个干净的 Ubuntu 虚拟机快照：

1.  将您的 Ubuntu 虚拟机恢复到一个干净的快照，以清除您之前创建的任何防火墙配置。使用以下命令进行验证：

```
 sudo ufw status
 sudo iptables -L
```

您应该看到 iptables 列出的规则为空，ufw 状态应为`inactive`。

1.  安装`nftables`软件包：

```
 sudo apt install nftables
```

1.  列出表，不应该有任何输出。加载默认配置文件，并列出表和规则：

```
 sudo nft list tables
 sudo nft -f /etc/nftables.conf
 sudo nft list tables
 sudo nft list table inet filter
```

1.  备份 nftables 配置文件：

```
 sudo cp /etc/nftables.conf /etc/nftables.conf.bak
```

1.  打开您的文本编辑器中的原始`/etc/nftables.conf`文件。在`tcp dport . . . accept`行之前，插入以下行：

```
        tcp dport ssh ip saddr { 192.168.0.7, 192.168.0.10 } drop
```

保存文件并退出文本编辑器。

1.  重新加载配置并查看结果：

```
 sudo nft list tables
 sudo nft -f /etc/nftables.conf
 sudo nft list tables
 sudo nft list table inet filter
```

1.  实验结束。

# 总结

在本章中，我们看了四种不同的 netfilter 防火墙前端。我们首先看了我们值得信赖的老朋友 iptables。我们看到，即使它已经存在很长时间并且仍然有效，它确实有一些缺点。然后我们看到 Ubuntu 的简化防火墙如何大大简化了设置基于 iptables 的防火墙。对于红帽用户，我们看了看 firewalld，这是特定于红帽类型的发行版。最后，我们通过查看最新的 Linux 防火墙技术 nftables 来结束了一切。

在分配的空间中，我只能呈现您设置基本主机保护所需的基本要点。但至少足够让您开始。
