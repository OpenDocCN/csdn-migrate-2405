# 红帽企业 Linux 8 管理（一）

> 原文：[`zh.annas-archive.org/md5/0CCDE6F20D3A1D212C45A9BF7E65144A`](https://zh.annas-archive.org/md5/0CCDE6F20D3A1D212C45A9BF7E65144A)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

Linux 无处不在，从个人设备到最大的超级计算机，从大学的计算机实验室到华尔街或国际空间站，甚至火星！**Red Hat Enterprise Linux**（简称**RHEL**）是企业环境中使用最广泛的 Linux 发行版，了解如何使用它是任何技术人员的关键技能。无论您是完全投身于管理基础设施，还是作为开发人员对您想要部署的平台更感兴趣，学习 Linux - 更准确地说是 RHEL - 将帮助您更加有效，甚至可能提升您的职业生涯。

在这本书中，我们从非常实用的角度涵盖了基本的 RHEL 管理技能，提供了我们从“战场”经验中学到的例子和技巧。您可以从头到尾地跟随，每一步都可以练习，同时了解事物是如何构建的以及它们为什么会表现出这样的行为。

希望您喜欢这本书，能充分利用它，并在阅读后拥有扎实的 RHEL 管理技能基础。这就是我们写这本书的目的。

享受阅读...和练习！

# 这本书适合谁

任何希望在 Linux 上构建和工作 IT 基础设施的人都将从这本书中受益，作为不同有用任务、技巧和最佳实践的参考。它将帮助任何寻求通过 Red Hat 认证系统管理员（RHCSA）考试的人，尽管它不能替代官方培训，在整个过程中将进行实验室和特别设计的测试。本书的范围调整到 RHCSA，通过来自实际经验的建议和许多实际示例进行扩展。

# 这本书涵盖了什么

*第一章*，*安装 RHEL8*，介绍了从获取软件和订阅到安装系统本身的 RHEL 安装过程。

*第二章*，*RHEL8 高级安装选项*，介绍了安装程序的高级用例，包括在云中部署实例和自动化安装。

*第三章*，*基本命令和简单的 Shell 脚本*，解释了在系统管理过程中将使用的日常命令，以及如何通过 shell 脚本自动化它们。

*第四章*，*常规操作工具*，展示了我们系统中可用的简单工具，可用于日常操作，例如启动或启用系统服务，或通过日志查看系统中正在进行的操作。

*第五章*，*使用用户、组和权限保护系统*，介绍了如何在任何 Linux 系统中管理用户、组和权限，其中包括一些关于 Red Hat Enterprise Linux 的具体内容。

*第六章*，*启用网络连接*，介绍了连接系统到网络的步骤以及可能的配置方式。

*第七章*，*添加、打补丁和管理软件*，回顾了在我们的系统中添加、删除和更新的步骤，包括升级和回滚的示例。

*第八章*，*远程管理系统*，介绍了如何远程连接到您的系统以提高效率。其中包括使用`ssh`连接创建密钥和使用终端复用器（`tmux`）。

*第九章*，*使用 firewalld 保护网络连接*，指导您了解 RHEL 中的网络防火墙配置以及如何正确管理它，包括管理区域、服务和端口。

*第十章*, *使用 SELinux 使系统更加安全*，介绍了 SELinux 的使用和基本故障排除。

*第十一章*, *使用 OpenSCAP 进行系统安全配置文件*，解释了如何使用 OpenSCAP 运行安全配置文件，并检查 RHEL 是否符合典型的规定。

*第十二章*, *管理本地存储和文件系统*，涵盖了文件系统的创建、挂载点和一般存储管理。

*第十三章*, *使用 LVM 进行灵活的存储管理*，解释了 LVM 如何通过添加磁盘和扩展逻辑卷来实现更灵活的存储管理。

*第十四章*, *使用 Stratis 和 VDO 进行高级存储管理*，介绍了 VDO 以及如何在我们的系统中使用它来去重存储，以及使用 Stratis 更轻松地管理存储。

*第十五章*, *理解引导过程*，解释了系统引导的过程以及使其重要的细节。

*第十六章*, *使用 tuned 进行内核调优和管理性能配置文件*，解释了内核调优的工作原理以及如何使用 tuned 进行预定义配置文件的使用。

*第十七章*, *使用 Podman、Buildah 和 Skopeo 管理容器*，介绍了容器和用于管理和构建容器的工具。

*第十八章*, *练习题–1*，让您测试您所学到的知识。

*第十九章*, *练习题–2*，提供更复杂的测试以检验您所学到的知识。

# 充分利用本书

所有软件要求将在各章中指出。请注意，本书假定您可以访问物理或虚拟机，或者可以访问互联网以创建云账户，以执行本书将引导您完成的操作。

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/Preface_Table.jpg)

**如果您使用本书的数字版本，我们建议您自己输入代码或从书的 GitHub 存储库中访问代码（链接在下一节中提供）。这样做将帮助您避免与复制和粘贴代码相关的任何潜在错误。**

# 下载示例代码文件

您可以从 GitHub 上 https://github.com/PacktPublishing/Red-Hat-Enterprise-Linux-8-Administration 下载本书的示例代码文件。如果代码有更新，将在 GitHub 存储库中进行更新。

我们还提供了来自我们丰富书籍和视频目录的其他代码包，可在 https://github.com/PacktPublishing/ 上找到。快去看看吧！

# 下载彩色图片

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图和图表的彩色图片。您可以在这里下载：[`static.packt-cdn.com/downloads/9781800569829_ColorImages.pdf`](https://static.packt-cdn.com/downloads/9781800569829_ColorImages.pdf)。

# 使用的约定

本书中使用了许多文本约定。

`文本中的代码`：表示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 用户名。例如："将下载的`RHEL8.iso`磁盘映像文件挂载为系统中的另一个磁盘。"

代码块设置如下：

```
#!/bin/bash
echo "Hello world"
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项将以粗体显示：

```
[default]
branch = main
repo = myrepo
username = bender
protocol = https
```

任何命令行输入或输出都以以下形式书写：

```
$ mkdir scripts
$ cd scripts
```

**粗体**：表示新术语、重要词汇或屏幕上看到的词语。例如，菜单或对话框中的词语以**粗体**显示。例如："从**管理**面板中选择**系统信息**"。

提示或重要说明

看起来像这样。

# 联系我们

我们始终欢迎读者的反馈意见。

请发送电子邮件至`customercare@packtpub.com`，并在主题中提及书名。

**勘误**：尽管我们已经尽最大努力确保内容的准确性，但错误是难免的。如果您在本书中发现了错误，我们将不胜感激地接受您的报告。请访问[www.packtpub.com/support/errata](http://www.packtpub.com/support/errata)并填写表格。

**盗版**：如果您在互联网上发现我们作品的任何非法副本，请向我们提供位置地址或网站名称，我们将不胜感激。请通过 copyright@packt.com 与我们联系，并提供材料链接。

**如果您有兴趣成为作者**：如果您在某个专业领域有专长，并且有兴趣撰写或为书籍做出贡献，请访问[authors.packtpub.com](http://authors.packtpub.com)。

# 分享您的想法

阅读完《Red Hat Enterprise Linux 8 Administration》后，我们很想听听您的想法！请点击这里直接访问亚马逊的书评页面，分享您的反馈意见。

您的评论对我们和技术社区都很重要，将帮助我们确保提供卓越的内容质量。


# 第一部分：系统管理-软件、用户、网络和服务管理

部署和配置系统，并保持其更新是每个系统管理员日常工作中执行的基本任务。在本节中，重新构建了这样做的核心部分，以便您可以按顺序跟踪任务，并正确地学习、练习和理解它们。

本节包括以下章节：

+   第一章，安装 RHEL8

+   第二章，RHEL8 高级安装选项

+   第三章，基本命令和简单的 Shell 脚本

+   第四章，常规操作工具

+   第五章，使用用户、组和权限保护系统

+   第六章，启用网络连接

+   第七章，添加、打补丁和管理软件


# 第一章：安装 RHEL8

开始使用**Red Hat Enterprise Linux**或**RHEL**的第一步是让它运行起来。无论是在您自己的笔记本电脑上作为主系统，还是在虚拟机或物理服务器上，都需要安装它以便熟悉您想要学习使用的系统。强烈建议您在阅读本书时获取一个物理或虚拟机来使用该系统。

在本章中，您将部署自己的 RHEL8 系统，以便能够跟随本书中提到的所有示例，并了解更多关于 Linux 的知识。

本章将涵盖的主题如下：

+   获取 RHEL 软件和订阅

+   安装 RHEL8

# 技术要求

开始的最佳方式是拥有一个**RHEL8**虚拟机来进行工作。您可以在主计算机上作为虚拟机进行操作，也可以使用物理计算机。在本章的后续部分，我们将审查这两种选择，您将能够运行自己的 RHEL8 系统。

提示

虚拟机是模拟完整计算机的一种方式。要能够在自己的笔记本电脑上创建这个模拟计算机，如果您使用的是 macOS 或 Windows，您需要安装虚拟化软件，例如 Virtual Box。如果您已经在运行 Linux，则已经准备好进行虚拟化，您只需要添加`virt-manager`软件包。

# 获取 RHEL 软件和订阅

要能够部署 RHEL，您需要一个**红帽订阅**来获取要使用的镜像，以及访问软件和更新的存储库。您可以免费从红帽的开发者门户网站获取**开发者订阅**，使用以下链接：[developers.redhat.com](http://developers.redhat.com)。然后需要按照以下步骤进行操作：

1.  在[developers.redhat.com](http://developers.redhat.com)上登录或创建帐户。

1.  转到[developers.redhat.com](http://developers.redhat.com)页面，然后点击**登录**按钮：![图 1.1 - developers.redhat.com 首页，指示点击登录的位置](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_01_001.jpg)

图 1.1 - developers.redhat.com 首页，指示点击登录的位置

1.  一旦进入登录页面，使用您的帐户，如果没有帐户，可以通过点击右上角的**注册**或直接在注册框中点击**立即创建**按钮来创建帐户，如下所示：![图 1.2 - 红帽登录页面（所有红帽资源通用）](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_01_002.jpg)

图 1.2 - 红帽登录页面（所有红帽资源通用）

您可以选择在几个服务中使用您的凭据（换句话说，*Google*，*GitHub*或*Twitter*）。

1.  登录后，转到**Linux**部分

您可以在内容之前的导航栏中找到**Linux**部分：

![图 1.3 - 在 developers.redhat.com 访问 Linux 页面](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_01_003.jpg)

图 1.3 - 在 developers.redhat.com 访问 Linux 页面

点击**下载 RHEL**，它将显示为下一页上的一个漂亮的按钮：

![图 1.4 - 在 developers.redhat.com 访问 RHEL 下载页面](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_01_004.jpg)

图 1.4 - 在 developers.redhat.com 访问 RHEL 下载页面

然后选择**x86_64（9 GB）**架构的 ISO 镜像（这是 Intel 和 AMD 计算机上使用的架构）：

![图 1.5 - 选择 x86_64 的 RHEL8 ISO 下载](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_01_005.jpg)

图 1.5 - 选择 x86_64 的 RHEL8 ISO 下载

1.  获取**RHEL8 ISO**镜像的方法如下：

![图 1.6 - 下载 x86_64 的 RHEL8 对话框](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_01_006.jpg)

图 1.6 - 下载 x86_64 的 RHEL8 对话框

ISO 镜像是一个文件，其中包含完整 DVD 的内容的精确副本（即使我们没有使用 DVD）。稍后将使用此文件来安装我们的机器，无论是将其转储到 USB 驱动器进行*Bare Metal*安装，解压缩以进行网络安装，还是附加到虚拟机安装（或在服务器中使用带外功能，如 IPMI、iLO 或 iDRAC）。

提示

验证 ISO 镜像，并确保我们获取的镜像没有损坏或被篡改，可以使用一种称为“校验和”的机制。校验和是一种审查文件并提供一组字母和数字的方法，可用于验证文件是否与原始文件完全相同。Red Hat 在客户门户的下载部分提供了用于此目的的`sha256`校验和列表（[`access.redhat.com/`](https://access.redhat.com/)）。有关该过程的文章在这里：[`access.redhat.com/solutions/8367`](https://access.redhat.com/solutions/8367)。

我们有软件，即 ISO 镜像，可以在任何计算机上安装 RHEL8。这些是全球生产机器中使用的相同位，您可以使用您的开发者订阅进行学习。现在是时候在下一节中尝试它们了。

# 安装 RHEL8

在本章的这一部分，我们将按照典型的安装过程在一台机器上安装 RHEL。我们将遵循默认步骤，审查每个步骤的可用选项。

## 物理服务器安装准备

在开始安装之前，物理服务器需要进行一些初始设置。常见步骤包括配置*内部阵列*中的磁盘，将其连接到网络，为预期的*接口聚合*（组合，绑定）准备交换机，准备访问外部*磁盘阵列*（换句话说，*光纤通道阵列*），设置带外功能，并保护**BIOS**配置。

我们不会详细介绍这些准备工作，除了启动顺序。服务器将需要从外部设备（如*USB 闪存驱动器*或*光盘*）启动（开始加载系统）。

要从带有 Linux 或 macOS 的计算机创建可引导的 USB 闪存驱动器，只需使用`dd`应用程序进行“磁盘转储”即可。执行以下步骤：

1.  在系统中找到您的 USB 设备，通常在 Linux 中为`/dev/sdb`，在 macOS 中为`/dev/disk2`（在 macOS 中，此命令需要特殊权限，请以`sudo dmesg | grep removable`运行）：

```
sdb disk, referred to as sdb1, is mounted. We will need to *unmount* all the partitions mounted. In this example, this is straightforward as there is only one. To do so, we can run the following command:

```

$ sudo umount /dev/sdb1

```

 Dump the image! (Warning, this will erase the selected disk!):

```

$ sudo dd if=rhel-8.3-x86_64-dvd.iso of=/dev/sdb bs=512k

```

TipAlternative methods are available for creating a boot device. Alternative graphical tools are available for creating a boot device that can help select both the image and the target device. In Fedora Linux (the community distribution where RHEL was based on, and a workstation for many engineers and developers), the **Fedora Media Writer** tool can be used. For other environments, the **UNetbootin** tool could also serve to create your boot media.
```

现在，有了 USB 闪存驱动器，我们可以在任何物理机器上安装，从小型笔记本电脑到大型服务器。下一部分涉及使物理机器从**USB 闪存驱动器**启动。执行该操作的机制将取决于所使用的服务器。但是，在启动过程中提供选择启动设备的选项已经变得很常见。以下是如何在笔记本电脑上选择临时启动设备的示例：

1.  中断正常启动。在这种情况下，启动过程显示我可以通过按*Enter*来做到：![图 1.7 - 中断正常启动的 BIOS 消息示例](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_01_007.jpg)

图 1.7 - 中断正常启动的 BIOS 消息示例

1.  选择临时启动设备，这种情况下通过按*F12*键：![图 1.8 - 中断启动的 BIOS 菜单示例](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_01_008.jpg)

图 1.8 - 中断启动的 BIOS 菜单示例

1.  选择要从中启动的设备。我们希望从我们的 USB 闪存驱动器启动，在这种情况下是**USB HDD：ChipsBnk Flash Disk**：

![图 1.9 - 选择 USB HDD 启动设备的 BIOS 菜单示例](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_01_009.jpg)

图 1.9 - 选择 USB HDD 启动设备的 BIOS 菜单示例

让系统从 USB 驱动器启动安装程序。

一旦我们知道如何准备带有 RHEL 安装程序的 USB 驱动器，以及如何使物理机从中引导，我们就可以跳到本章的*运行 RHEL 安装*部分并进行安装。如果我们有一个迷你服务器（换句话说，Intel NUC）、一台旧计算机或一台笔记本电脑，可以用作跟随本书的机器，这将非常有用。

接下来，我们将看看如何在您的安装中准备虚拟机，以防您考虑使用当前的主要笔记本电脑（或工作站）跟随本书，但仍希望保留一个单独的机器进行工作。

## 虚拟服务器安装准备

`virt-manager`将添加运行所需的所有底层组件（这些组件包括**KVM**、**Libvirt**、**Qemu**和**virsh**等）。其他推荐用于 Windows 或 macOS 系统的免费虚拟化软件包括**Oracle VirtualBox**和**VMware Workstation Player**。

本节中的示例将使用`virt-manager`执行，但可以轻松适用于任何其他虚拟化软件，无论是在笔记本电脑还是在最大的部署中。

上面已经描述了准备步骤，并需要获取`rhel-8.3-x86_64-dvd.iso`。一旦下载并且如果可能的话，检查其完整性（如在*获取 RHEL 软件和订阅*部分的最后提示中提到的），让我们准备部署一个虚拟机：

1.  启动您的虚拟化软件，这里是`virt-manager`：![图 1.10 - 虚拟管理器主菜单](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_01_010.jpg)

图 1.10 - 虚拟管理器主菜单

1.  通过转到**文件**，然后单击**新建虚拟机**来创建一个新的虚拟机。选择**本地安装媒体（ISO 镜像或 CDROM）**：![图 1.11 - 虚拟管理器 - 新 VM 菜单](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_01_011.jpg)

图 1.11 - 虚拟管理器 - 新 VM 菜单

1.  选择*ISO 镜像*。这样，虚拟机将配置为具有**虚拟 DVD/CDROM 驱动器**，并已准备好从中引导。这是惯例行为。但是，当使用不同的虚拟化软件时，您可能希望执行检查：![图 1.12 - 选择 ISO 镜像作为安装介质的虚拟管理器菜单](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_01_012.jpg)

图 1.12 - 选择 ISO 镜像作为安装介质的虚拟管理器菜单

1.  为我们正在创建的虚拟机分配内存和 CPU（注意：虚拟机通常称为**VM**）。对于**Red Hat Enterprise Linux 8**（也称为**RHEL8**），最低内存为 1.5 GB，建议每个逻辑 CPU 为 1.5 GB。我们将使用最低设置（1.5 GB 内存，1 个 CPU 核心）：![图 1.13 - 选择内存和 CPU 的虚拟管理器菜单](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_01_013.jpg)

图 1.13 - 选择内存和 CPU 的虚拟管理器菜单

现在是为虚拟机分配至少一个磁盘的时候了。在这种情况下，我们将分配一个具有最小磁盘空间 10 GB 的单个磁盘，但在以后的章节中，我们将能够分配更多的磁盘来测试其他功能：

![图 1.14 - 创建新磁盘并将其添加到虚拟机的虚拟管理器菜单](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_01_014.jpg)

图 1.14 - 创建新磁盘并将其添加到虚拟机的虚拟管理器菜单

1.  我们的虚拟机已经具备了开始所需的一切：引导设备、内存、CPU 和磁盘空间。在最后一步中，添加了网络接口，所以现在我们甚至有了网络。让我们回顾一下数据并启动它：

图 1.15 - 选择虚拟机名称和网络的虚拟管理器菜单

](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_01_015.jpg)

图 1.15 - 选择虚拟机名称和网络的虚拟管理器菜单

经过这些步骤后，我们将拥有一个完全功能的虚拟机。现在是时候通过在其上安装 RHEL 操作系统来完成这个过程了。在下一节中查看如何执行此操作。

## 运行 RHEL 安装

一旦我们为安装准备好了虚拟或物理服务器，就该进行安装了。如果我们到达以下屏幕，就说明之前的所有步骤都已正确执行：

![图 1.16 – RHEL8 安装的初始启动屏幕，选择安装](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_01_016.jpg)

图 1.16 – RHEL8 安装的初始启动屏幕，选择安装

我们提供了三个选项（*以白色选择*）：

+   **安装 Red Hat Enterprise Linux 8.3**：此选项将启动并运行安装程序。

+   **测试此媒体并安装 Red Hat Enterprise Linux 8.3**：此选项将检查正在使用的镜像，以确保其没有损坏，并且安装可以确保进行。建议首次使用刚下载的 ISO 镜像或刚创建的媒体（例如 USB 闪存驱动器或 DVD）时使用此选项（在虚拟机中，运行检查大约需要 1 分钟）。

+   **故障排除**：此选项将帮助您在安装出现问题、运行系统出现问题或硬件出现问题时审查其他选项。让我们快速查看此菜单上可用的选项：

– **以基本图形模式安装 Red Hat Enterprise Linux 8.3**：此选项适用于具有旧图形卡和/或不受支持的图形卡的系统。如果识别出可视化问题，它可以帮助完成系统安装。

– **救援 Red Hat Enterprise Linux 系统**：当我们的系统存在启动问题或者我们想要访问它以审查它时（换句话说，审查可能受损的系统），可以使用此选项。它将启动一个基本的内存系统来执行这些任务。

– **运行内存测试**：可以检查系统内存以防止问题，例如全新服务器的情况，我们希望确保其内存正常运行，或者系统出现问题和紧急情况可能表明与内存有关的问题。

– **从本地驱动器引导**：如果您从安装媒体引导，但已经安装了系统。

– **返回主菜单**：返回上一个菜单。

重要提示

RHEL 引导菜单将显示几个选项。所选项将显示为白色，其中一个单独的字母以不同的颜色显示，例如“i”表示安装，“m”表示测试媒体。这些是快捷方式。按下带有该字母的键将直接带我们到此菜单项。

让我们继续进行**测试此媒体并安装 Red Hat Enterprise Linux 8.3**，以便安装程序审查我们正在使用的 ISO 镜像：

![图 1.17 – RHEL8 ISO 镜像自检](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_01_017.jpg)

图 1.17 – RHEL8 ISO 镜像自检

完成后，将到达第一个安装屏幕。安装程序称为**Anaconda**（一个笑话，因为它是用一种叫做**Python**的语言编写的，并且遵循逐步方法）。在安装过程中，我们将选择的选项需要引起注意，因为我们将在本书的*使用 Anaconda 自动部署*部分中对它们进行审查。

### 本地化

安装的第一步是选择安装语言。对于此安装，我们将选择**英语**，然后选择**英语（美国）**：

![图 1.18 – RHEL8 安装菜单 – 语言](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_01_018.jpg)

图 1.18 – RHEL8 安装菜单 – 语言

如果您无法轻松找到您的语言，您可以在列表下的框中输入它进行搜索。选择语言后，我们可以单击**继续**按钮继续。这将带我们到**安装摘要**屏幕：

![图 1.19 – RHEL8 安装菜单 – 主页](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_01_019.jpg)

图 1.19 – RHEL8 安装菜单 – 主页

在**安装摘要**屏幕上，显示了所有必需的配置部分，其中许多部分（没有警告标志和红色文字）已经预先配置为默认值。

让我们回顾一下**本地化**设置。首先是**键盘**：

![图 1.20 – RHEL8 安装 – 键盘选择图标](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_01_020.jpg)

图 1.20 – RHEL8 安装 – 键盘选择图标

我们可以查看键盘设置，这不仅有助于更改键盘，还可以在需要时添加额外的布局以在它们之间切换：

![图 1.21 – RHEL8 安装 – 键盘选择对话框](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_01_021.jpg)

图 1.21 – RHEL8 安装 – 键盘选择对话框

这可以通过点击`spa`直到出现，然后选择它，然后点击**添加**来完成：

![图 1.22 – RHEL8 安装 – 键盘选择列表](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_01_022.jpg)

图 1.22 – RHEL8 安装 – 键盘选择列表

要将其设置为默认选项，需要点击下方的**^**按钮。在本例中，我们将保留它作为次要选项，以便安装支持软件。完成后，点击**完成**：

![图 1.23 – RHEL8 安装 – 带有不同键盘的键盘选择对话框](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_01_023.jpg)

图 1.23 – RHEL8 安装 – 带有不同键盘的键盘选择对话框

现在，我们将继续进行**语言支持**：

![图 1.24 – RHEL8 安装 – 语言选择图标](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_01_024.jpg)

图 1.24 – RHEL8 安装 – 语言选择图标

在这里，我们还可以添加我们的本地语言。在本例中，我将使用**Español**，然后**Español (España)**。这将再次包括安装支持所添加语言所需的软件：

![图 1.25 – RHEL8 安装 – 带有不同语言的语言选择对话框](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_01_025.jpg)

图 1.25 – RHEL8 安装 – 带有不同语言的语言选择对话框

我们将继续配置两种语言，尽管您可能希望选择您自己的本地化语言。

现在，我们将继续进行**时间和日期**的设置，如下所示：

![图 1.26 – RHEL8 安装 – 时间和日期选择图标](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_01_026.jpg)

图 1.26 – RHEL8 安装 – 时间和日期选择图标

默认配置设置为美国纽约市。您在这里有两种可能性：

+   使用您的本地时区。当您希望所有日志都在该时区注册时，建议使用此选项（换句话说，因为您只在一个时区工作，或者因为每个时区都有本地团队）。在本例中，我们选择了**西班牙，马德里，欧洲**时区：

![图 1.27 – RHEL8 安装 – 时间和日期选择对话框 – 选择马德里](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_01_027.jpg)

图 1.27 – RHEL8 安装 – 时间和日期选择对话框 – 选择马德里

+   使用**协调世界时**（也称为**UTC**）以使全球各地的服务器具有相同的时区。可以在**区域：** | **Etc**下选择，然后选择**城市：** | **协调世界时**：

![图 1.28 – RHEL8 安装 – 时间和日期选择对话框 – 选择 UTC](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_01_028.jpg)

图 1.28 – RHEL8 安装 – 时间和日期选择对话框 – 选择 UTC

我们将继续使用西班牙，马德里，欧洲的本地化时间，尽管您可能希望选择您的本地化时区。

提示

如屏幕所示，有一个选项可以选择**网络时间**，以使机器的时钟与其他机器同步。只有在配置网络后才能选择此选项。

### 软件

完成**本地化**配置（或几乎完成；我们可能稍后再回来配置网络时间）后，我们将继续进行**软件**部分，或者更确切地说，是其中的**连接到红帽**：

![图 1.29 – RHEL8 安装 – 连接到红帽选择图标](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_01_029.jpg)

图 1.29 – RHEL8 安装 – 连接到红帽选择图标

在这一部分，我们可以使用我们自己的 Red Hat 帐户，就像我们之前在[developers.redhat.com](http://developers.redhat.com)下创建的那样，以访问系统的最新更新。要配置它，我们需要先配置网络。

出于本部署的目的，我们现在不会配置这一部分。我们将在本书的*第七章*中，*添加、打补丁和管理软件*，中了解如何管理订阅和获取更新。

重要提示

使用 Red Hat Satellite 进行系统管理：对于拥有超过 100 台服务器的大型部署，Red Hat 提供了“Red Hat Satellite”，具有高级软件管理功能（例如版本化内容视图、使用 OpenSCAP 进行集中安全扫描以及简化的 RHEL 补丁和更新）。可以使用激活密钥连接到 Red Hat Satellite，从而简化系统管理。

现在让我们转到**安装源**，如下所示：

![图 1.30 – RHEL8 安装 – 安装源图标](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_01_030.jpg)

图 1.30 – RHEL8 安装 – 安装源图标

这可以用于使用远程源进行安装。当使用仅包含安装程序的引导 ISO 映像时，这非常有用。在这种情况下，由于我们使用的是完整的 ISO 映像，它已经包含了完成安装所需的所有软件（也称为*软件包*）。

下一步是**软件选择**，如下截图所示：

![图 1.31 – RHEL8 安装 – 软件选择图标](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_01_031.jpg)

图 1.31 – RHEL8 安装 – 软件选择图标

在这一步中，我们可以选择要在系统上安装的预定义软件包集，以便系统可以执行不同的任务。虽然在这个阶段这样做可能非常方便，但我们将采用更加手动的方法，并选择**最小安装**配置文件，以便稍后向系统添加软件。

这种方法还有一个优点，即通过仅安装系统中所需的最小软件包来减少**攻击面**：

![图 1.32 – RHEL8 安装 – 软件选择菜单；选择最小安装](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_01_032.jpg)

图 1.32 – RHEL8 安装 – 软件选择菜单；选择最小安装

### 系统

一旦选择了软件包集，让我们继续进行**系统**配置部分。我们将从安装目标开始，选择要用于安装和配置的磁盘：

![图 1.33 – RHEL8 安装 – 安装目标图标，带有警告标志，因为此步骤尚未完成](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_01_033.jpg)

图 1.33 – RHEL8 安装 – 安装目标图标，带有警告标志，因为此步骤尚未完成

这个任务非常重要，因为它不仅会定义系统在磁盘上的部署方式，还会定义磁盘的分布方式和使用的工具。即使在这个部分，我们不会使用高级选项。我们将花一些时间来审查主要选项。

这是默认的**设备选择**屏幕，只发现了一个本地标准磁盘，没有**专用和网络磁盘**选项，并准备运行**自动**分区。可以在以下截图中看到：

![图 1.34 – RHEL8 安装 – 安装目标菜单，选择自动分区](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_01_034.jpg)

图 1.34 – RHEL8 安装 – 安装目标菜单，选择自动分区

在这一部分点击**完成**将完成继续安装所需的最小数据集。

让我们来回顾一下各个部分。

**本地标准磁盘**是安装程序要使用的一组磁盘。可能情况是我们有几个磁盘，而我们只想使用特定的磁盘：

![图 1.35 – RHEL8 安装 – 安装目标菜单，选择了几个本地磁盘](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_01_035.jpg)

图 1.35 – RHEL8 安装 – 安装目标菜单，选择了几个本地磁盘

这是一个有三个可用磁盘并且只使用第一个和第三个的例子。

在我们的情况下，我们只有一个磁盘，它已经被选择了：

![图 1.36 – RHEL8 安装 – 安装目标菜单，选择了一个本地磁盘](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_01_036.jpg)

图 1.36 – RHEL8 安装 – 安装目标菜单，选择了一个本地磁盘

通过选择**加密我的数据**，可以轻松使用全盘加密，这在笔记本安装或在低信任环境中安装时是非常推荐的：

![图 1.37 – RHEL8 安装 – 安装目标菜单，未选择数据加密选项](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_01_037.jpg)

图 1.37 – RHEL8 安装 – 安装目标菜单，未选择数据加密选项

在这个例子中，我们将不加密我们的驱动器。

**自动**安装选项将自动分配磁盘空间：

![图 1.38 – RHEL8 安装 – 安装目标菜单；存储配置（自动）](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_01_038.jpg)

图 1.38 – RHEL8 安装 – 安装目标菜单；存储配置（自动）

它将通过创建以下资源来实现：

+   `/boot`: 用于分配系统核心（`kernel`）和在引导过程中帮助的文件的空间（例如初始引导镜像`initrd`）。

+   `/boot/efi`: 用于支持 EFI 启动过程的空间。

+   `/"`: 根文件系统。这是系统所在的主要存储空间。其他磁盘/分区将被分配到文件夹中（这样做时，它们将被称为`挂载点`）。

+   `/home`: 用户存储个人文件的空间。

让我们选择这个选项，然后点击**完成**。

提示

系统分区和引导过程：如果您仍然不完全理解有关系统分区和引导过程的一些扩展概念，不要担心。有一章节专门介绍了文件系统、分区以及如何管理磁盘空间，名为*管理本地存储和文件系统*。要了解引导过程，有一章节名为*理解引导过程*，它逐步审查了完整的系统启动顺序。

下一步涉及审查**Kdump**或**内核转储**。这是一种允许系统在发生关键事件并崩溃时保存状态的机制（它会转储内存，因此得名）：

![图 1.39 – RHEL8 安装 – Kdump 配置图标](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_01_039.jpg)

图 1.39 – RHEL8 安装 – Kdump 配置图标

为了工作，它将为自己保留一些内存，等待在系统崩溃时进行操作。默认配置对需求进行了良好的计算：

![图 1.40 – RHEL8 安装 – Kdump 配置菜单](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_01_040.jpg)

图 1.40 – RHEL8 安装 – Kdump 配置菜单

点击**完成**将带我们进入下一步**网络和主机名**，如下所示：

![图 1.41 – RHEL8 安装 – 网络和主机名配置图标](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_01_041.jpg)

图 1.41 – RHEL8 安装 – 网络和主机名配置图标

本节将帮助系统连接到网络。在虚拟机的情况下，对外部网络的访问将由**虚拟化软件**处理。默认配置通常使用**网络地址转换**（**NAT**）和**动态主机配置协议**（**DHCP**），这将为虚拟机提供网络配置和对外部网络的访问。

一旦进入配置页面，我们可以看到有多少网络接口分配给我们的机器。在这种情况下，只有一个，如下所示：

![图 1.42 – RHEL8 安装 – 网络和主机名配置菜单](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_01_042.jpg)

图 1.42 – RHEL8 安装 – 网络和主机名配置菜单

首先，我们可以通过点击右侧的**开/关**切换来启用接口。关闭它的话，看起来是这样的：

![图 1.43 - RHEL8 安装 - 网络和主机名配置切换（关）](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_01_043.jpg)

图 1.43 - RHEL8 安装 - 网络和主机名配置切换（关）

并且要打开它的话，应该是这样的：

![图 1.44 - RHEL8 安装 - 网络和主机名配置切换（开）](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_01_044.jpg)

图 1.44 - RHEL8 安装 - 网络和主机名配置切换（开）

我们将看到接口现在有配置（**IP 地址**，**默认路由**和**DNS**）：

![图 1.45 - RHEL8 安装 - 网络和主机名配置信息详情](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_01_045.jpg)

图 1.45 - RHEL8 安装 - 网络和主机名配置信息详情

为了使这个改变永久化，我们将点击屏幕右下角的**配置**按钮来编辑接口配置：

![图 1.46 - RHEL8 安装 - 网络和主机名配置；接口配置；以太网选项卡](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_01_046.jpg)

图 1.46 - RHEL8 安装 - 网络和主机名配置；接口配置；以太网选项卡

单击**常规**选项卡将呈现主要选项。我们将选择**优先自动连接**，并将值保留为**0**，就像这样：

![图 1.47 - RHEL8 安装 - 网络和主机名配置；接口配置；常规选项卡](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_01_047.jpg)

图 1.47 - RHEL8 安装 - 网络和主机名配置；接口配置；常规选项卡

点击**保存**将使更改永久化，并且默认启用这个网络接口。

现在是给我们的虚拟服务器取一个名字的时候了。我们将去到`rhel8.example.com`，然后点击**应用**：

![图 1.48 - RHEL8 安装 - 网络和主机名配置；主机名详情](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_01_048.jpg)

图 1.48 - RHEL8 安装 - 网络和主机名配置；主机名详情

提示

域名`example.com`是用于演示目的，并且可以放心在任何场合使用，知道它不会与其他系统或域名发生冲突或引起任何麻烦。

网络页面将会是这样的：

![图 1.49 - RHEL8 安装 - 网络和主机名配置菜单；配置完成](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_01_049.jpg)

图 1.49 - RHEL8 安装 - 网络和主机名配置菜单；配置完成

单击**完成**将带我们返回到主安装程序页面，系统连接到网络并准备好一旦安装完成就连接。

名为*启用网络连接*的章节将更详细地描述在 RHEL 系统中配置网络的可用选项。

重要提示

现在系统已连接到网络，我们可以回到**时间和日期**并启用网络时间（这是安装程序自动完成的），以及转到**连接到 Red Hat**来订阅系统到 Red Hat 的**内容分发网络**（或**CDN**）。系统订阅到 CDN 的详细说明将在*第七章*中详细解释，*添加、打补丁和管理软件*。

现在是时候通过转到**安全策略**来审查最终系统选项，安全配置文件了：

![图 1.50 - RHEL8 安装 - 安全策略配置图标](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_01_050.jpg)

图 1.50 - RHEL8 安装 - 安全策略配置图标

在其中，我们将看到一个可以在我们系统中默认启用的安全配置文件列表：

![图 1.51 - RHEL8 安装 - 安全策略配置菜单](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_01_051.jpg)

图 1.51 - RHEL8 安装 - 安全策略配置菜单

安全配置有一些要求在这个安装中我们没有涵盖（比如有单独的`/var`或`/tmp`分区）。我们可以点击**应用安全策略**来关闭它，然后点击**完成**：

![图 1.52 – RHEL8 安装 – 安全策略配置切换（关闭）](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_01_052.jpg)

图 1.52 – RHEL8 安装 – 安全策略配置切换（关闭）

有关此主题的更多信息将在*第十一章**，使用 OpenSCAP 进行系统安全配置*中进行讨论。

### 用户设置

Unix 或 Linux 系统中的主管理员用户称为`root`。

我们可以通过点击**根密码**部分来启用根用户，尽管这并非必需，在安全受限的环境中，建议您不要这样做。我们将在本章中这样做，以便学习如何做以及解释所涵盖的情况：

![图 1.53 – RHEL8 安装 – 根密码配置图标（因为尚未设置而显示警告）](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_01_053.jpg)

图 1.53 – RHEL8 安装 – 根密码配置图标（因为尚未设置而显示警告）

点击**根密码**后，我们将看到一个对话框来输入密码：

![图 1.54 – RHEL8 安装 – 根密码配置菜单](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_01_054.jpg)

图 1.54 – RHEL8 安装 – 根密码配置菜单

建议密码具有以下内容：

+   超过 10 个字符（最少 6 个）

+   小写和大写

+   数字

+   特殊字符（如$、@、%和&）

如果密码不符合要求，它会警告我们，并强制我们点击**完成**两次以使用弱密码。

现在是时候通过点击**用户创建**来为系统创建用户了：

![图 1.55 – RHEL8 安装 – 用户创建配置图标（因为尚未完成而显示警告）](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_01_055.jpg)

图 1.55 – RHEL8 安装 – 用户创建配置图标（因为尚未完成而显示警告）

这将带我们进入一个输入用户数据的部分：

![图 1.56 – RHEL8 安装 – 用户创建配置菜单](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_01_056.jpg)

图 1.56 – RHEL8 安装 – 用户创建配置菜单

在此处将适用与前一部分相同的密码规则。

点击`root`密码）。

提示

作为良好的实践，不要为根帐户和用户帐户使用相同的密码。

*第五章**，使用用户、组和权限保护系统*包括如何使用和管理`sudo`工具为用户分配管理权限的部分。

点击**完成**返回到主安装程序屏幕。安装程序已准备好继续安装。主页面将如下所示：

![图 1.57 – RHEL8 安装 – 完成后的主菜单](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_01_057.jpg)

图 1.57 – RHEL8 安装 – 完成后的主菜单

点击**开始安装**将启动安装过程：

重要提示

如果省略了开始安装所需的任何步骤，**开始安装**按钮将变灰，因此无法点击。

![图 1.58 – RHEL8 安装 – 安装进行中](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_01_058.jpg)

图 1.58 – RHEL8 安装 – 安装进行中

安装完成后，我们可以点击**重新启动系统**，它将准备好使用：

![图 1.59 – RHEL8 安装 – 安装完成](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_01_059.jpg)

图 1.59 – RHEL8 安装 – 安装完成

重要的是要记住从虚拟机中卸载 ISO 镜像（或从服务器中移除 USB 存储设备），并检查系统中的引导顺序是否正确配置。

您的第一个 Red Hat Enterprise Linux 8 系统现在已准备就绪！恭喜。

正如您所看到的，很容易在虚拟机或物理机中安装 RHEL，并准备好用于运行任何我们想要运行的服务。在云中，该过程非常不同，因为机器是从镜像实例化来运行的。在下一章中，我们将回顾如何在云中的虚拟机实例中运行 RHEL。

# 总结

*Red Hat 认证系统管理员*考试完全是基于实际经验的实践。为了做好准备，最好的方法就是尽可能多地练习，这也是本书开始提供*Red Hat Enterprise Linux 8*（RHEL8）访问权限并提供如何部署自己的虚拟机的替代方案的原因。

安装涵盖了不同的场景。这些是最常见的情况，包括使用物理机器、虚拟机或云实例。在本章中，我们专注于使用虚拟机或物理机。

在使用物理硬件时，我们将专注于许多人喜欢重复使用旧硬件，购买二手或廉价的迷你服务器，甚至将自己的笔记本电脑用作 Linux 体验的主要安装设备这一事实。

在虚拟机的情况下，我们考虑的是那些希望将所有工作都保留在同一台笔记本电脑上，但又不想干扰他们当前的操作系统（甚至可能不是 Linux）的人。这也可以与前一个选项很好地配合，即在自己的迷你服务器上使用虚拟机。

在本章之后，您将准备好继续阅读本书的其余部分，至少有一个 Red Hat Enterprise Linux 8 实例可供使用和练习。

在下一章中，我们将回顾一些高级选项，例如使用云来部署 RHEL 实例，自动化安装和最佳实践。

让我们开始吧！


# 第二章：RHEL8 高级安装选项

在上一章中，我们学习了如何在物理或虚拟机上安装**Red Hat Enterprise Linux**，或**RHEL**，以便在阅读本书时使用。在本章中，我们将回顾如何在云中使用 RHEL *实例*以及在这样做时出现的主要差异。

您还将学习不仅如何部署系统，而且如何做出最佳选择，并能够以*自动化方式*执行部署。

为了完成安装，已包括了一个关于*最佳实践*的部分，以便您可以从第一天开始避免长期问题。

这些是本章将涵盖的主题：

+   使用 Anaconda 自动化 RHEL 部署

+   在云上部署 RHEL

+   安装最佳实践

# 技术要求

在本章中，我们将回顾使用**Anaconda**进行自动化安装过程。为此，您需要使用我们在上一章中创建的*RHEL8 部署*。

我们还将创建云实例，为此您需要在所选云环境中创建一个帐户。我们将使用**Google Cloud Platform**。

# 使用 Anaconda 自动化 RHEL 部署

完成了在本地部署 RHEL 的第一步后，您可以以 root 用户登录到机器上，并列出`root`用户在其文件夹中拥有的文件：

```
[root@rhel8 ~]# ls /root/
anaconda-ks.cfg
```

您会找到`anaconda-ks.cfg`文件。这是一个重要的文件，称为`kickstart`，它包含了在安装过程中安装程序**Anaconda**的响应。让我们来看看这个文件的内容。

重要提示

在云映像中，没有`anaconda-ks.cfg`文件。

此文件可以被重用以安装其他系统，使用与我们用于此安装的相同选项。让我们回顾一下我们在上一次安装中添加的选项。

以`#`开头的行是注释，对安装过程没有影响。

指定正在使用的版本的注释如下：

```
#version=RHEL8
```

然后进行了一种类型的安装。它可以是`图形`或`文本`（对于无头系统，通常使用第二种）：

```
# Use graphical install
graphical
```

安装应用程序包或任何其他软件包的软件源由`repo`条目指定。由于我们使用的是 ISO 镜像，它被访问（在 Linux 术语中被挂载）就像是一个*CDROM*：

```
repo --name="AppStream" --baseurl=file:///run/install/sources/mount-0000-cdrom/AppStream
```

部分由`％`符号指定。在这种情况下，我们将输入`packages`部分，其中包含要安装的软件包列表，并使用`％end`特殊标记来关闭它们。有两个选择：由以`@^`符号开头的定义的软件包组（在这种情况下是`minimal-environment`）和不需要任何前缀的软件包的名称（在这种情况下是`kexec-tools`软件包，负责安装我们之前解释的`kdump`功能）：

```
%packages
@^minimal-environment
kexec-tools
%end
```

我们继续点击没有部分的选项。在这种情况下，我们有键盘布局和系统语言支持。正如你所看到的，我们添加了*英语美国键盘*（标记为`us`）和*西班牙*，*西班牙*（标记为`es`）：

```
# Keyboard layouts
keyboard --xlayouts='us','es'
```

对于系统语言，我们还添加了英语美国（`en_US`）和西班牙，西班牙（`es_ES`）。操作系统中有几种管理、存储和表示文本的方式。如今最常见的是`UTF-8`，它使我们能够在一个单一标准下拥有许多字符集。这就是为什么系统语言后面有`.UTF-8`：

```
# System language
lang en_US.UTF-8 --addsupport=es_ES.UTF-8
```

提示

**Unicode（或通用编码字符集）转换格式 - 8 位**，简称 UTF-8，是一种字符编码，它扩展了以前的能力，以支持中文、西里尔文或阿拉伯文（以及许多其他语言）在同一文本中（比如代表网页或控制台的文本）。UTF-8 于 1993 年推出，被全球网页的 95.9%使用。以前的字符集只支持美国英语或拉丁字符，比如 1963 年发布的**美国信息交换标准代码**，或**ASCII**。要了解更多有关字符编码及其演变的信息，请查看 UTF-8 和 ASCII 的维基百科页面。

现在，是时候配置网络接口了。在这种情况下，我们只有一个名为`enp1s0`的网络接口。配置使用 IPv4 和`rhel8.example.com`：

```
# Network information
network  --bootproto=dhcp --device=enp1s0 --ipv6=auto --activate
network  --hostname=rhel8.example.com
```

现在，我们需要定义安装介质。在这种情况下，我们使用了一个模拟的 CDROM/DVD，使用我们下载的 ISO 镜像文件：

```
# Use CDROM installation media
cdrom
```

`firstboot`选项默认启用。在本例中，由于安装不包括*图形界面*，它不会运行，但将被添加到`kickstart`文件中。我们可以安全地删除它，如下所示：

```
# Run the Setup Agent on first boot
firstboot --enable
```

现在，让我们配置磁盘。首先，为了安全起见，我们将指示安装程序忽略除目标磁盘（在本例中为`vda`）之外的所有磁盘：

```
ignoredisk --only-use=vda
```

重要提示

磁盘的名称将根据您运行的平台而变化。通常，它将是`vda`、`xda`或`sda`。在本例中，我们展示了由安装程序 Anaconda 定义的`vda`磁盘，就像我们在上一章中使用的那样。

现在，我们必须安装引导加载程序以启用系统引导。我们将在`vda`上这样做，并指示它使用`crashkernel`选项，该选项启用`kdump`机制（在系统崩溃时转储内存）：

```
# System bootloader configuration
bootloader --append="crashkernel=auto" --location=mbr --boot-drive=vda
```

现在，我们必须对磁盘进行分区。在这种情况下，这将是完全自动化的：

```
autopart
```

系统要使用的空间必须声明。我们将在此示例中清除整个磁盘：

```
# Partition clearing information
clearpart --none --initlabel
```

让我们将时区设置为欧洲马德里：

```
# System timezone
timezone Europe/Madrid --isUtc
```

现在，我们将设置 root 密码并创建一个用户（请注意，加密密码已经被删除以确保安全）：

```
# Root password
rootpw --iscrypted $xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
user --groups=wheel --name=user --password=$xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx --iscrypted --gecos="user"
```

提示

上一章生成的 Anaconda 文件包含加密密码哈希的示例。如果我们想要更改它，可以通过运行`python -c 'import crypt,getpass;pw=getpass.getpass();print(crypt.crypt(pw) if (pw==getpass.getpass("Confirm: ")) else exit())'`命令生成新的加密密码哈希，并将其包含在此处。

现在，我们需要一个特殊的部分，可以在其中配置`kdump`，以便我们可以自动保留内存：

```
%addon com_redhat_kdump --enable --reserve-mb='auto' 
%end
```

我们还需要一个特殊的部分，指定将用于安装的密码策略：

```
%anaconda
pwpolicy root --minlen=6 --minquality=1 --notstrict --nochanges --notempty
pwpolicy user --minlen=6 --minquality=1 --notstrict --nochanges --emptyok
pwpolicy luks --minlen=6 --minquality=1 --notstrict --nochanges --notempty
%end
```

有了这个，我们的`kickstart`文件以重新安装系统就完成了。

要使用它，我们需要将 kickstart 选项传递给安装程序。为此，我们编辑内核参数。让我们看看如何做到这一点。

我们首先按*Tab*，在启动时，选择**安装 Red Hat Enterprise Linux 8.3**。以**vmlinuz**开头的引导行将出现在屏幕底部：

![图 2.1 - RHEL8 安装程序 - 编辑引导行](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_02_001.jpg)

图 2.1 - RHEL8 安装程序 - 编辑引导行

让我们删除`quiet`选项，并添加一个让安装程序知道 kickstart 位置的选项：

![图 2.2 - RHEL8 安装程序 - 将 kickstart 选项添加到引导行](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_02_002.jpg)

图 2.2 - RHEL8 安装程序 - 将 kickstart 选项添加到引导行

我们添加的选项如下：

```
inst.ks=hd:sdc1:/anaconda-ks.cfg
```

我们可以看看它的三个部分：

+   `hd`：kickstart 将在磁盘上，比如第二个 USB 驱动器上。

+   `sdc1`：托管文件的设备。

+   `/anaconda-ks.cfg`：设备中 kickstart 文件的路径。

有了这个，我们可以重现我们所做的完整安装。

提示

*Red Hat Enterprise Linux 8 自定义 Anaconda*指南提供了详细的选项，如果您希望创建自己的*Anaconda Kickstart*文件或进一步自定义此文件，可以在此处访问：[`access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html-single/customizing_anaconda/index`](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html-single/customizing_anaconda/index)。

正如您所见，创建 kickstart 文件并自动部署 Red Hat Enterprise Linux 非常容易。

现在，让我们来看看另一种使 RHEL 8 实例可用的方法：在云中。

# 在云上部署 RHEL

**在云上部署 Red Hat Enterprise Linux**与我们之前进行的部署有一些不同。让我们看看这些区别是什么：

+   我们不会使用 ISO 镜像或 Anaconda 来执行部署，而是使用预先配置的镜像，通常由云提供商准备和提供：

- 该镜像可以稍后进行自定义和调整以满足我们的需求。

+   我们将无法在安装时选择系统的配置细节（例如选择时区），但之后可以选择。

+   将会有一个自动化机制来更改设置，例如添加用户及其凭据以访问系统或配置网络：

- 云提供商通常使用`cloud-init`来实现此目的的最常见和最知名的机制。

- 一些由云提供商提供的镜像包括`cloud-init`软件。

- 通常使用由用户在云提供商生成的 SSH 密钥通过`ssh`协议远程访问系统（请查看*第八章*，*远程管理系统*，以获取有关如何访问系统的更多详细信息）。

重要提示

在创建 RHEL 镜像方面，可以为云或虚拟化创建我们自己的镜像。为此，我们可以使用 Red Hat Enterprise Linux 镜像构建器（[`developers.redhat.com/blog/2019/05/08/red-hat-enterprise-linux-8-image-builder-building-custom-system-images/`](https://developers.redhat.com/blog/2019/05/08/red-hat-enterprise-linux-8-image-builder-building-custom-system-images/)）。但是，它不是 RHCSA 的一部分，因此本书不会涵盖它。相反，我们将遵循采用默认镜像并对其进行自定义的方法。

云提供商提出了一个初始的免费试用优惠，您可以免费尝试他们的服务。这是开始使用 RHEL 和云服务的好方法。

在本书中，我们将以 Google Cloud 为例，因此不会涵盖其他云。我们将提供一个简要示例，说明如何在此云环境中创建和修改 Red Hat Enterprise Linux 8 实例。为此，我们将使用**Google Cloud**（截至 2020 年 12 月，它提供了一个初始信用，可以持续整本书所需的时间）。

要遵循本章，您需要完成以下步骤：

1.  如果您没有 Google 帐户，您将需要创建一个（如果您使用 Gmail 和/或 Android 手机，您可能已经有一个）。

1.  在[`accounts.google.com`](https://accounts.google.com)登录您的 Google 帐户（或检查您是否已登录）。您将需要注册免费试用，此时您将需要提供信用卡号码。

1.  转到[`cloud.google.com/free`](https://cloud.google.com/free)并领取您的免费信用额度。

1.  转到[`console.cloud.google.com`](https://console.cloud.google.com)的云控制台。

1.  转到**项目**菜单，在顶部菜单栏中显示为**无组织**，以显示新帐户的项目：![图 2.3 – RHEL8 在 Google Cloud 中–组织菜单访问](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_02_003.jpg)

图 2.3 – RHEL8 在 Google Cloud 中–组织菜单访问

1.  点击**新项目**：![图 2.4 – RHEL8 在 Google Cloud 中–组织菜单](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_02_004.jpg)

图 2.4 - Google 云中的 RHEL8 - 组织菜单

1.  将其命名为`RHEL8`，然后单击**创建**：![图 2.5 - Google 云中的 RHEL8 - 组织菜单; 创建新项目](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_02_005.jpg)

图 2.5 - Google 云中的 RHEL8 - 组织菜单; 创建新项目

重要提示

根据您的 Google 帐户配置方式，您可能需要在此步骤之后启用计费。

1.  转到左上角菜单（也称为**汉堡菜单**，旁边有三条水平线），单击**计算引擎**，然后单击**VM 实例**：![图 2.6 - Google 云中的 RHEL8 - 访问 VM 实例菜单](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_02_006.jpg)

图 2.6 - Google 云中的 RHEL8 - 访问 VM 实例菜单

1.  一旦**计算引擎**准备就绪（可能需要几分钟），点击**创建**：![图 2.7 - Google 云中的 RHEL8 - 创建新的 VM 实例](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_02_007.jpg)

图 2.7 - Google 云中的 RHEL8 - 创建新的 VM 实例

1.  我们将实例命名为`rhel8-instance`：![图 2.8 - Google 云中的 RHEL8 - 创建新的 VM 实例; 名称](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_02_008.jpg)

图 2.8 - Google 云中的 RHEL8 - 创建新的 VM 实例; 名称

1.  选择最方便的区域（或保留已提供的区域）：![图 2.9 - Google 云中的 RHEL8 - 创建新的 VM 实例，区域和区域](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_02_009.jpg)

图 2.9 - Google 云中的 RHEL8 - 创建新的 VM 实例，区域和区域

1.  将机器系列和类型设置为**通用**|**e2-medium**：![图 2.10 - Google 云中的 RHEL8 - 创建新的 VM 实例，类型和大小](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_02_010.jpg)

图 2.10 - Google 云中的 RHEL8 - 创建新的 VM 实例，类型和大小

1.  点击**更改**旁边的引导磁盘：![图 2.11 - Google 云中的 RHEL8 - 更改引导磁盘](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_02_011.jpg)

图 2.11 - Google 云中的 RHEL8 - 更改引导磁盘

1.  将**操作系统**更改为**Red Hat 企业 Linux**，**版本**更改为**Red Hat 企业 Linux 8**。然后，点击**选择**：![图 2.12 - Google 云中的 RHEL8 - 创建新的 VM 实例，图像选择和磁盘大小](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_02_012.jpg)

图 2.12 - Google 云中的 RHEL8 - 创建新的 VM 实例，图像选择和磁盘大小

1.  点击**创建**，等待实例创建完成：![图 2.13 - Google 云中的 RHEL8 - VM 实例列表](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_02_013.jpg)

图 2.13 - Google 云中的 RHEL8 - VM 实例列表

1.  稍后，我们将学习如何通过`SSH`连接。现在，点击**连接**下的`SSH`旁边的三角形，并选择**在浏览器窗口中打开**，如下所示：![图 2.14 - Google 云中的 RHEL8 - VM 实例，访问控制台](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_02_014.jpg)

图 2.14 - Google 云中的 RHEL8 - VM 实例，访问控制台

1.  有了这个，您的新鲜的 RHEL8 实例将被部署，如下截图所示：

![图 2.15 - Google 云中的 RHEL8 - VM 实例，控制台](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_02_015.jpg)

图 2.15 - Google 云中的 RHEL8 - VM 实例，控制台

在云中设置需要一些时间，配置您的帐户，并找到`SSH`密钥（将在*第八章*，*远程管理系统*中显示），但一旦全部设置好，就很容易启动一个新实例。

要成为管理员，您只需要运行以下命令：

```
[miguel@rhel8-instance ~]$ sudo -i
[root@rhel8-instance ~]#
```

现在，您可以使用`timedatectl`检查时间配置并更改：

```
[root@rhel8-instance ~]# timedatectl 
               Local time: Sat 2020-12-12 17:13:29 UTC
           Universal time: Sat 2020-12-12 17:13:29 UTC
                 RTC time: Sat 2020-12-12 17:13:29
                Time zone: UTC (UTC, +0000)
System clock synchronized: yes
              NTP service: active
          RTC in local TZ: no
[root@rhel8-instance ~]# timedatectl set-timezone Europe/Madrid
[root@rhel8-instance ~]# timedatectl 
               Local time: Sat 2020-12-12 18:20:32 CET
           Universal time: Sat 2020-12-12 17:20:32 UTC
                 RTC time: Sat 2020-12-12 17:20:32
                Time zone: Europe/Madrid (CET, +0100)
System clock synchronized: yes
              NTP service: active
          RTC in local TZ: no
```

您还可以使用`localectl`更改语言配置：

```
[root@rhel8-instance ~]# localectl 
   System Locale: LANG=en_US.UTF-8
       VC Keymap: us
      X11 Layout: n/a
```

要更改`locale`或语言支持，您需要首先安装其*语言包*，如下所示：

```
[root@rhel8-instance ~]# yum install glibc-langpack-es –y
... [output omitted] ...
[root@rhel8-instance ~]# localectl set-locale es_ES.utf8
[root@rhel8-instance ~]# localectl 
   System Locale: LANG=es_ES.utf8
       VC Keymap: us
      X11 Layout: n/a
```

现在，您已经配置了一台机器，可以在本书中使用。这些区域设置不需要继续，只是为了创建具有与上一章相同配置的机器。

现在我们知道如何使用 Anaconda 自动重新部署 VM，并在云中获取实例，让我们继续并查看在执行安装时需要考虑的一些最佳实践。

# 安装最佳实践

**Red Hat Enterprise Linux 安装**有许多选项可供选择，您应该根据特定的用例进行定制。然而，一些常见的建议适用。让我们看看最常见的类型。

第一种类型是**蓝图**：

+   标准化核心安装并为其创建一个蓝图：

- 这个蓝图应该足够小，可以作为所有其他蓝图和部署的基础。

+   在需要时为常见情况构建一组蓝图：

- 尽量使用自动化平台来构建扩展案例（即，Ansible）。

- 尽量使案例模块化（即，应用服务器；数据库蓝图可以合并成一个单一的机器）。

- 了解您必须应用于模板蓝图的要求，并适应您将使用的环境。

第二种类型是**软件**：

+   安装的软件越少，攻击面就越小。尽量保持服务器上所需的最小软件包集（即，尽量不要向服务器添加图形用户界面）。

+   在可能的情况下，标准化安装的工具，以便在紧急情况下能够迅速反应。

+   打包第三方应用程序，以便进行健康的生命周期管理（无论是使用 RPM 还是容器）。

+   建立一个补丁安装计划。

第三种类型是**网络**：

+   在虚拟机中，尽量不要过多使用网络接口。

+   在物理机器上，尽可能使用接口组合/绑定。使用 VLAN 对网络进行分段。

第四种类型是**存储**：

+   对于服务器，使用`/boot`或`/boot/efi`）。

+   如果您认为需要缩减文件系统，请使用*ext4*；否则，选择默认的*xfs*。

+   谨慎地对磁盘进行分区：

- 保持默认的引导分区及其默认大小。如果更改它，请扩大它（在升级过程中可能需要空间）。

- 默认的交换分区是最安全的选择，除非第三方软件有特定要求。

- 对于长期存在的系统，至少要有单独的分区用于`/`（根）`/var`，`/usr`，`/tmp`和`/home`，甚至考虑为`/var/log`和`/opt`单独设置一个（对于临时云实例或短期存在的系统，不适用）。

第五种类型是**安全**：

+   不要禁用*SELinux*。它在最新版本中得到了很大改进，很可能不会干扰您的系统（如果需要，将其设置为宽容模式，而不是完全禁用它）。

+   不要禁用防火墙。使用服务部署自动化端口开放。

+   尽可能将日志重定向到一个中央位置。

+   标准化安全工具和配置，以检查系统完整性和审计（即*AIDE*，*logwatch*和*auditd*）。

+   审查软件安装（*RPM*）*GPG*密钥，以及 ISO 映像，以确保完整性。

+   尽量避免使用密码（特别是您的 root 帐户），并在需要时使用强密码。

+   使用*OpenSCAP*审查您的系统以检查安全性（如果需要，从安全团队的帮助下创建自己的硬件 SCAP 配置文件）。

最后，我们将看看**杂项**类型：

+   保持系统时间同步。

+   审查*logrotate*策略，以避免由于日志而导致“磁盘已满”的错误。

遵循这些最佳实践将帮助您避免问题，并使安装基础更易管理。有了这些，您就知道如何以有条理、可重复的方式在系统上部署 Red Hat Enterprise Linux，同时以快速和有弹性的方式为其他团队提供服务。

# 总结

在上一章中，我们提到了如何准备一台机器，可以在整本书中使用。与此相对的是使用云实例，通过这种方式，我们可以从公共云中消费虚拟机实例，这可能简化我们的消费，并为我们提供足够的免费信用来准备 *RHCSA*。此外，一旦自我训练过程完成，这些机器仍然可以用来提供你自己的公共服务（比如部署博客）。

在作为专业人士使用 Linux 时，理解标准化环境的需求以及这样做的影响也很重要。从一开始就采用一套良好的实践方法（自动化安装、跟踪已安装的软件、减少攻击面等）是关键。

完成了这一章，现在你可以继续阅读本书的其余部分了，因为你现在已经有了一个可用于工作和练习的红帽企业 Linux 8 实例。在下一章中，我们将回顾系统的基础知识，让自己感到舒适，并增强使用系统的信心。


# 第三章：基本命令和简单的 shell 脚本

一旦您的第一个**Red Hat Enterprise Linux (RHEL)**系统运行起来，您就想开始使用它，练习并熟悉它。在本章中，我们将回顾登录系统、浏览系统和了解其管理基础知识的基础知识。

本章描述的一套命令和实践将在管理系统时经常使用，因此重要的是要仔细学习它们。

本章将涵盖以下主题：

+   以用户身份登录和管理多用户环境

+   使用 su 命令切换用户

+   使用命令行、环境变量和浏览文件系统

+   理解命令行中的 I/O 重定向

+   使用 grep 和 sed 过滤输出

+   清单、创建、复制和移动文件和目录、链接和硬链接

+   使用 tar 和 gzip

+   创建基本的 shell 脚本

+   使用系统文档资源

# 以用户身份登录和管理多用户环境

**登录**是用户在系统中识别自己的过程，通常是通过提供**用户名**和**密码**来完成的，这两个信息通常被称为*凭据*。

系统可以以多种方式访问。我们在这里讨论的初始情况是，当用户安装物理机器（如笔记本电脑）或通过虚拟化软件界面访问时，用户如何访问系统。在这种情况下，我们通过*控制台*访问系统。

在安装过程中，用户被创建并分配了密码，并且没有安装图形界面。在这种情况下，我们将通过其*文本控制台*访问系统。我们要做的第一件事是使用它登录系统。一旦启动机器并完成引导过程，我们将默认进入多用户文本模式环境，其中我们被要求提供我们的**登录**：

![图 3.1 - 登录过程，用户名请求](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_03_001.jpg)

图 3.1 - 登录过程，用户名请求

闪烁的光标将告诉我们，我们已经准备好输入我们的用户名，这里是`user`，然后按*Enter*。会出现一个要求输入密码的行：

![图 3.2 - 登录过程，密码请求](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_03_002.jpg)

图 3.2 - 登录过程，密码请求

现在我们可以输入用户的密码来完成登录，并通过键盘上的*Enter*键开始一个会话。请注意，在输入密码时屏幕上不会显示任何字符，以避免窃听。这将是正在运行的会话：

![图 3.3 - 登录过程，登录完成，会话运行](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_03_003.jpg)

图 3.3 - 登录过程，登录完成，会话运行

现在我们已经完全以名为`user`的用户的*凭据*完全登录到系统。这将决定我们在系统中可以做什么，我们可以访问哪些文件，甚至我们分配了多少磁盘空间。

控制台可以有多个会话。为了实现这一点，我们有不同的终端可以登录。默认终端可以通过同时按下*Ctrl + Alt + F1*键来到达。在我们的情况下，什么也不会发生，因为我们已经在那个终端上了。我们可以通过按*Ctrl + Alt + F2*来到第二个终端，按*Ctrl + Alt + F3*来到第三个终端，以此类推，直到剩下的终端（默认情况下分配了六个）。这样，我们可以在不同的终端中运行不同的命令。

## 使用 root 账户

普通用户无法对系统进行更改，比如创建新用户或向整个系统添加新软件。为此，我们需要一个具有管理权限的用户，而默认用户就是`root`。这个用户始终存在于系统中，其标识符为`0`。

在之前的安装中，我们已经配置了 root 密码，使得可以通过控制台访问该账户。要在系统中使用它，我们只需要在显示的终端之一中输入`root`，然后按下*Enter*，然后提供其`root`：

![图 3.4 - 登录过程，以 root 用户完成登录](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_03_004.jpg)

图 3.4 - 登录过程，以 root 用户完成登录

## 使用和理解命令提示符

一旦我们登录并等待输入和运行命令的命令行出现，就称为**命令提示符**。

在其默认配置中，它将在括号之间显示*用户名*和*主机名*，以便让我们知道我们正在使用哪个用户。接下来，我们看到路径，这里是`~`，它是`/home/user`的快捷方式，对于`user`用户，以及`/root`对于`root`用户）

最后一个部分，也可能是最重要的部分，是提示符前面的符号：

+   `$`符号用于没有管理权限的常规用户。

+   `#`符号用于 root 或一旦用户获得管理权限。

重要提示

当使用带有`#`符号的提示符时要小心，因为您将以管理员身份运行，系统很可能不会阻止您损坏它。

一旦我们在系统中标识了自己，我们就已经登录并有了一个运行的会话。现在是时候学习如何在下一节中从一个用户切换到另一个用户了。

# 使用 su 命令切换用户

由于我们已经进入了一个**多用户系统**，因此可以合理地认为我们将能够在用户之间切换。即使可以通过为每个用户打开会话来轻松完成此操作，但有时我们希望在同一个会话中以其他用户的身份行事。

为此，我们可以使用`su`工具。该工具的名称通常被称为**替代用户**。

让我们利用上次以`root`登录的会话，并将自己转换为`user`用户。

在这之前，我们可以通过运行`whoami`命令来询问我当前登录的用户是谁：

```
[root@rhel8 ~]# whoami
root
```

现在我们可以从`root`切换到`user`：

```
[root@rhel8 ~]# su user
[user@rhel8 root]$ whoami 
user
```

现在我们有了一个`user`用户的会话。我们可以使用`exit`命令结束此会话：

```
[user@rhel8 root]$ exit
exit
[root@rhel8 ~]# whoami
root
```

正如您可能已经看到的，当我们以`root`登录时，我们可以像任何用户一样行事，而无需知道其密码。但是我们如何冒充`root`呢？我们可以通过运行`su`命令并指定`root`用户来做到这一点。在这种情况下，将要求输入 root 用户的密码：

```
[user@rhel8 ~]$ su root
Password: 
[root@rhel8 user]# whoami
root
```

由于`root`是 ID 为`0`且最重要的用户，因此在运行`su`而不指定要转换的用户时，它将默认转换为`root`：

```
[user@rhel8 ~]$ su
Password: 
[root@rhel8 user]# whoami
root
```

每个用户都可以在自己的环境中定义多个选项，例如他们喜欢的编辑器。如果我们想完全冒充其他用户并采用他们的偏好（或在`su`命令后加上`-`：

```
[user@rhel8 ~]$ su -
Password: 
Last login: mar dic 22 04:57:29 CET 2020 on pts/0
[root@rhel8 ~]#
```

此外，我们可以从`root`切换到`user`：

```
[root@rhel8 ~]# su - user
Last login: Tue Dec 22 04:53:02 CET 2020 from 192.168.122.1 on pts/0
[user@rhel8 ~]$
```

正如您所观察到的，它的行为就像进行了新的登录，但在同一个会话中。现在，让我们继续管理系统中不同用户的权限，如下一节所述。

# 理解用户、组和基本权限

多用户环境的定义在于能够同时处理多个用户。但是为了能够管理系统资源，有两种能力可以帮助完成任务：

+   **组**：可以聚合用户并以块为它们提供权限。

每个用户都有一个*主要组*。

默认情况下，为每个用户创建一个组，并将其分配为与用户名相同的主要组。

+   `ugo`）。

整个系统都有一组默认分配给每个文件和目录的权限。在更改它们时要小心。

UNIX 中有一个原则，Linux 继承了它，那就是：*一切皆为文件*。即使可能有一些特例，这个原则在几乎任何情况下都是正确的。这意味着磁盘在系统中表示为文件（换句话说，就像安装中提到的`/dev/sdb`），进程可以表示为文件（在`/proc`下），系统中的许多其他组件都表示为文件。

这意味着，在分配文件权限时，我们也可以分配给许多其他组件和功能的权限，因为在 Linux 中，一切都表示为文件。

提示

**POSIX**代表**可移植操作系统接口**，是由 IEEE 计算机学会指定的一系列标准：[`en.wikipedia.org/wiki/POSIX`](https://en.wikipedia.org/wiki/POSIX)。

## 用户

用户是为人们以及在系统中运行的程序提供安全限制的一种方式。有三种类型的用户：

+   **普通用户**：分配给个人执行其工作的用户。他们受到了限制。

+   **超级用户**：也称为''root''。这是系统中的主管理帐户，对其拥有完全访问权限。

+   **系统用户**：这些是通常分配给运行进程或''守护进程''的用户帐户，以限制它们在系统中的范围。系统用户不打算登录到系统。

用户有一个称为**UID（用户 ID）**的数字，系统用它来内部识别每个用户。

我们之前使用`whoami`命令来显示我们正在使用的用户，但是为了获取更多信息，我们将使用`id`命令：

```
[user@rhel8 ~]$ id
uid=1000(user) gid=1000(user) groups=1000(user),10(wheel) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```

我们还可以查看系统中其他用户帐户的相关信息，甚至获取`root`的信息：

```
[user@rhel8 ~]$ id root
uid=0(root) gid=0(root) groups=0(root)
```

现在，让我们通过运行`id`来查看我们收到的有关`user`的信息：

+   `uid=1000(user)`：用户 ID 是系统中用户的数字标识符。在这种情况下，它是`1000`。在 RHEL 中，1000 及以上的标识符用于普通用户，而 999 及以下的标识符保留给系统用户。

+   `gid=1000(user)`：组 ID 是分配给用户的主要组的数字标识符。

+   `groups=1000(user),10(wheel)`：这些是用户所属的组，在这种情况下，''user''使用`sudo`工具（稍后将解释）。

+   `context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023`：这是用户的 SELinux 上下文。它将使用**SELinux**在系统中定义多个限制（在*第十章*中将深入解释，*使用 SELinux 保护系统*）。

与 ID 相关的数据存储在系统中的`/etc/passwd`文件中。请注意，该文件非常敏感，最好使用与之相关的工具进行管理。如果我们想要编辑它，我们将使用`vipw`，这是一个工具，将确保（除其他事项外）只有一个管理员在任何时候编辑文件。`/etc/passwd`文件包含每个用户的信息。这是`user`的行：

```
user:x:1000:1000:user:/home/user:/bin/bash
```

每个字段在每行中由冒号`:`分隔。让我们来看看它们的含义：

+   `user`：分配给用户的用户名。

+   `x`：加密密码的字段。在这种情况下，它显示为`x`，因为它已经移动到`/etc/shadow`，普通用户无法直接访问，以使系统更安全。

+   `1000`（第一个）：*UID*值。

+   `1000`（第二个）：*GID*值。

+   `user`：帐户的描述。

+   `/home/user`：分配给用户的主目录。这将是用户将要工作的默认目录（或者如果你愿意的话，文件夹），以及他们的偏好设置将被存储的地方。

+   `/bin/bash`：用户的命令解释器。Bash 是 RHEL 中的默认解释器。其他替代品，如`tcsh`，`zsh`或`fish`可在 RHEL 中安装。

## 组

`/srv/finance`目录。当财务团队有新员工时，为了让他们能够访问该文件夹，我们只需要将分配给这个人的用户添加到`finance`组中（如果有人离开团队，我们只需要从`finance`组中删除他们的帐户）。

组有一个称为**GID**的数字，系统用它来在内部识别它们。

组的数据存储在系统中的`/etc/group`文件中。为了以确保一致性并避免损坏的方式编辑此文件，我们必须使用`vigr`工具。文件中每行包含一个组，不同字段用冒号`:`分隔。让我们看一下`wheel`组的行：

```
wheel:x:10:user
```

让我们回顾一下每个字段的含义：

+   `wheel`：这是组的名称。在这种情况下，这个组是特殊的，因为它被配置为默认情况下用作为普通用户提供管理员特权的组。

+   `x`：这是组密码字段。它目前已经过时，应始终包含`x`。它保留用于兼容性目的。

+   `10`：这是组本身的 GID 值。

+   `user`：这是属于该组的用户列表（用逗号分隔，如`user1`，`user2`和`user3`）。

组的类型如下：

+   **主要组**：这是用户新创建的文件分配的组。

+   **私有组**：这是一个特定的组，与用户同名，为每个用户创建。添加新用户帐户时，将自动为其创建一个私有组。很常见的是''主要组''和''私有组''是一样的。

+   `wheel`组用于为用户启用管理员特权，或者`cdrom`组用于在系统中提供对 CD 和 DVD 设备的访问。

## 文件权限

要查看`root`。我们将使用`ls`命令列出文件，并查看与它们关联的权限。我们将在*第五章*中学习如何更改权限，*使用用户、组和权限保护系统*。

一旦以`root`身份登录系统，我们可以运行`ls`命令：

```
[root@rhel8 ~]# ls
anaconda-ks.cfg
```

这显示了*root 用户主目录*中存在的文件，用`~`表示。在这种情况下，它显示了在上一章中我们审查过的*Anaconda*创建的*kickstart*文件。

我们可以通过在`ls`后附加`-l`选项来获取列表的长版本：

```
[root@rhel8 ~]# ls -l
total 4
-rw-------. 1 root root 1393 Dec  7 16:45 anaconda-ks.cfg
```

我们在输出中看到以下内容：

+   `total 4`：这是文件在磁盘上占用的总空间，以千字节为单位（请注意，我们使用的是 4K 块，因此每个小于该大小的文件将占用至少 4K）。

+   `-rw-------.`：这些是分配给文件的权限。

权限的结构可以在以下图表中看到：

![图 3.5 - Linux 权限结构](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_03_005.jpg)

图 3.5 - Linux 权限结构

第一个字符是文件可能具有的*特殊权限*。如果它是一个常规文件，并且没有特殊权限（就像在这种情况下），它将显示为`-`：

+   目录将显示为`d`。请考虑在 Linux 中，一切都是文件，目录是具有特殊权限的文件。

+   链接，通常是符号链接，将显示为`l`。这些行为类似于从不同目录的文件的快捷方式。

+   特殊权限以不同的用户或组身份运行文件，称为`s`。

+   一个特殊权限，使所有者只能删除或重命名文件，称为`t`。

接下来的三个字符`rw-`是*所有者*的权限：

+   第一个字符`r`是分配的读权限。

+   第二个字符`w`是分配的写权限。

+   第三个字符`x`，不存在并显示为`-`，是可执行权限。请注意，对于目录的可执行权限意味着能够进入它们。

接下来的三个字符`---`是*组*权限，与所有者权限的工作方式相同。在这种情况下，没有授予组访问权限。

最后三个字符`---`是*其他人*的权限，这意味着用户和/或组不会显示为分配给文件的权限：

+   `1`: 这表示对该文件的**链接**（硬链接）的数量。这是为了防止我们删除另一个文件夹中使用的文件等目的。

+   `root`: 这表示文件的（第一次）所有者。

+   `root`: 这表示文件分配给的（第二次）组。

+   `1393`: 这表示以字节为单位的大小。

+   `Dec 7 16:45`: 这表示文件上次修改的日期和时间。

+   `anaconda-ks.cfg`: 这表示文件名。

当我们列出一个目录（在其他系统中称为*文件夹*）时，输出将显示目录本身的内容。我们可以使用`-d` `option`列出目录本身的信息。现在让我们来看看`/etc`，这个存储系统范围配置的目录：

```
[root@rhel8 ~]# ls -l -d /etc
drwxr-xr-x. 81 root root 8192 Dec 23 17:03 /etc
```

正如你所看到的，很容易获取有关系统中文件和目录的信息。现在让我们在下一节中学习更多关于命令行以及如何在文件系统中导航，以便轻松地在系统中移动。

# 使用命令行、环境变量和浏览文件系统

正如我们之前所看到的，一旦我们登录系统，我们就可以访问命令行。熟练地浏览命令行和文件系统对于在环境中感到舒适并充分利用它至关重要。

## 命令行和环境变量

命令行由一个程序提供，也称为*解释器*或**shell**。它的行为取决于我们使用的 shell，但在本节中，我们将介绍 Linux 中最常用的 shell，也是 RHEL 默认提供的 shell：**bash**。

知道你正在使用哪个 shell 的一个简单技巧是运行以下命令：

```
[root@rhel8 ~]# echo $SHELL
/bin/bash
```

`echo`命令将在屏幕上显示我们给它的内容。有些内容需要*替换*或*解释*，比如环境变量。需要替换的内容以`$`符号开头。在这种情况下，我们告诉系统`echo`变量`SHELL`的内容。让我们用它来处理其他变量：

```
[root@rhel8 ~]# echo $USER
root
[root@rhel8 ~]# echo $HOME
/root
```

这些是可以为每个用户自定义的**环境变量**。现在让我们为另一个用户检查这些：

```
[root@rhel8 ~]# su - user
Last login: Wed Dec 23 17:03:32 CET 2020 from 192.168.122.1 on pts/0
[user@rhel8 ~]$ echo $USER
user
[user@rhel8 ~]$  echo $HOME
/home/user
```

正如你所看到的，你可以随时引用`$USER`，它将被当前用户替换，或者引用`$HOME`，它将被替换为用户专用的目录，也称为**主目录**。

这些是一些最常见和重要的*环境变量*：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_03_Table_01.jpg)

`~/.bashrc`文件应该被编辑以更改当前用户的这些值。

## 浏览文件系统

现在是时候将我们自己移动到`/`了。系统的其余内容将悬挂在那个文件夹下，任何其他磁盘或设备都将被分配一个目录以供访问。

重要说明

根目录和 root 用户的主目录是两回事。root 用户默认分配了主目录`/root`，而根目录是系统中所有目录的母目录，用`/`表示。

我们可以通过运行`pwd`命令来查看我们所在的目录：

```
[user@rhel8 ~]$ pwd
/home/user
```

我们可以使用`cd`命令来更改目录：

```
[user@rhel8 ~]$ cd /var/tmp
[user@rhel8 tmp]$ pwd
/var/tmp
```

正如你已经知道的，有一个`~`。我们可以使用这个快捷方式去到它：

```
[user@rhel8 tmp]$ cd ~
[user@rhel8 ~]$ pwd
/home/user
```

一些目录的快捷方式包括以下内容：

+   **"~":** 这是当前用户的主目录。

+   **".":** 这是当前目录。

+   **"..":** 这是父目录。

+   **"-":** 这是先前使用的目录。

有关在 Linux 和 RHEL 中管理文件和目录的更多详细信息，请参阅*列出、创建、复制和移动文件和目录、链接和硬链接*部分。

## Bash 自动补全

快捷方式是到达常用目录或当前工作目录的相对引用的更快方式。但是，bash 包括一些快速到达其他目录的功能，这称为**自动补全**。它依赖于*Tab*键（键盘最左边具有两个相对箭头的键，在*Caps Lock*上方）。

当到达一个文件夹或文件时，我们可以按*Tab*键来完成它的名称。例如，如果我们想进入`/boot/grub2`文件夹，我们输入以下内容：

```
[user@rhel8 ~]$ cd /bo 
```

然后，当我们按下*Tab*键时，它会自动补全为`/boot/`，甚至添加最终的`/`，因为它是一个目录：

```
[user@rhel8 ~]$ cd /boot/
```

现在我们输入我们想要进入的目录`grub2`的第一个字母，即`g`：

```
[user@rhel8 ~]$ cd /boot/g
```

然后，当我们按下*Tab*键时，它会自动补全为`/boot/grub2/`：

```
[root@rhel8 ~]# cd /boot/grub2/
```

现在我们可以按*Enter*键并进入那里。

如果我们按下*Tab + Tab*（在完成期间按两次*Tab*），这将显示可用目标的列表，例如：

```
[root@rhel8 ~]# cd /r
root/ run/  
```

它也可以用于完成命令。我们可以输入一个字母，例如`h`，按下*Tab + Tab*，这将显示所有以`h`开头的命令：

```
[root@rhel8 ~]# h
halt         hardlink     hash         h dparm       head         help         hexdump      history      hostid       hostname     hostnamectl  hwclock      
```

这种能力可以通过安装`bash-completion`软件包来扩展，以帮助完成我们命令的其他部分：

```
[root@rhel8 ~]# yum install bash-completion –y
```

### 以前的命令

有一种方法可以恢复最后运行的命令，这被称为**历史记录**，以防您想要再次运行它们。只需按下*向上箭头*键（带有向上箭头的键）即可，以及以前的命令将出现在屏幕上。

如果您的历史记录中有太多命令，您可以通过运行`history`命令快速搜索它们：

```
[user@rhel8 ~]$ history 
   1  su root
   2  su
   3  su -
   4  id
   5  id root
   6  grep user /etc/passwd
   7  echo $USER
   8   echo $HOME
   9  declare
   10  echo $SHELL
   11  echo EDITOR
   12  echo $EDITOR
   13  grep wheel /etc/gro
   14  grep wheel /etc/group
   15  cat /etc/group
   16  grep nobody /etc/group /etc/passwd
```

您可以使用`!`命令再次运行任何这些命令。只需使用命令的编号运行`!`，它将再次运行：

```
[user@rhel8 ~]$ !5
id root
uid=0(root) gid=0(root) groups=0(root)
```

提示

命令`!!`将再次运行最后一个命令，无论编号如何。

现在是时候享受您的超快命令行了。让我们在下一节中更多地了解 Linux 中目录的结构，以便知道去哪里查找东西。

## 文件系统层次结构

Linux 有一个由*Linux 基金会*维护的标准，定义了**文件系统层次结构**，几乎在每个 Linux 发行版中都使用，包括*RHEL*。这个标准被称为**FHS**，或**文件系统层次结构标准**。让我们在这里回顾一下标准中最重要的文件夹和系统本身：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_03_Table_02.jpg)

提示

RHEL 的早期版本用于将`/bin`用于基本二进制文件和`/usr/bin`用于非基本二进制文件。现在，两者的内容都驻留在`/usr/bin`中。他们还使用`/var/lock`和`/var/run`来运行`/run`中的内容。此外，他们过去用于将`/lib`用于基本库和`/usr/lib`用于非基本库，这些都合并到一个目录`/usr/lib`中。最后但并非最不重要的是，`/sbin`是基本超级用户二进制文件的目录，`/usr/sbin`是合并到`/usr/sbin`下的非基本二进制文件的目录。

在分区时，我们可能会问自己，磁盘空间去哪了？

这些是 RHEL 8''最小''安装的分配值和建议：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_03_Table_03.jpg)

熟悉系统中的主要目录是很重要的，以便充分利用它们。建议浏览不同的系统目录，并查看其中的内容，以便熟悉结构。在下一节中，我们将学习如何在命令行上执行重定向，以了解更多关于命令和文件交互的内容。

# 了解命令行中的 I/O 重定向

我们已经运行了几个命令来确定系统的信息，例如使用`ls`列出文件，并且我们从运行的命令中得到了一些信息，**输出**，包括文件名和文件大小。该信息或*输出*可能很有用，我们希望能够正确地处理、存储和管理它。

在谈论命令*输出*和**输入**时，有三个需要理解的来源或目标：

+   **STDOUT**：也称为**标准输出**，这是命令将其常规消息放置以提供有关其正在执行的操作的信息的地方。在终端上，在交互式 shell（就像我们迄今为止使用的那样），此输出将显示在屏幕上。这将是我们管理的主要输出。

+   **STDERR**：也称为**标准错误**，这是命令将其错误消息放置在其中以进行处理的地方。在我们的交互式 shell 中，除非我们明确重定向它，否则此输出也将显示在屏幕上，同时显示标准输出。

+   **STDIN**：也称为**标准输入**，这是命令获取要处理的数据的地方。

我们将在下一段中提到这些，以更好地理解它们。

命令输入和输出的使用方式需要以下运算符：

+   `|`：**管道**运算符用于获取一个命令的输出并将其作为下一个命令的输入。它将数据从一个命令传输到另一个命令。

+   `>`：**重定向**运算符用于将命令的输出放入文件中。如果文件存在，它将被覆盖。

+   `<`：**反向重定向**可以应用于使用文件作为命令的输入。使用它不会删除用作输入的文件。

+   `>>`：**重定向并添加**运算符用于将命令的输出附加到文件中。如果文件不存在，它将使用提供给它的输出创建文件。

+   `2>`：**重定向 STDERR**运算符将仅重定向发送到错误消息处理程序的输出。（注意，为了使其工作，''2''和''>''之间不应包含空格！）

+   `1>`：**重定向 STDOUT**运算符将仅重定向发送到标准输出而不是错误消息处理程序的输出。

+   `>&2`：**重定向到 STDERR**运算符将输出重定向到标准错误处理程序。

+   `>&1`：**重定向到 STDOUT**运算符将输出重定向到标准输出处理程序。

为了更好地理解这些，我们将在本节和下一节中进行一些示例。

让我们列出文件并将其放入文件中。首先，我们使用`-m`选项列出`/var`中的文件，用逗号分隔条目：

```
[root@rhel8 ~]# ls -m /var/
adm, cache, crash, db, empty, ftp, games, gopher, kerberos, lib, local, lock, log, mail, nis, opt, preserve, run, spool, tmp, yp
```

现在，我们再次运行命令，将输出重定向到`/root/var-files.txt`文件中：

```
[root@rhel8 ~]# ls –m /var/ > /root/var-files.txt
[root@rhel8 ~]#
```

正如我们所看到的，屏幕上没有显示任何输出，但是我们将能够在当前工作目录中找到新文件，即`/root`中的新创建的文件：

```
[root@rhel8 ~]# ls /root
anaconda-ks.cfg  var-files.txt
```

要在屏幕上查看文件的内容，我们使用`cat`命令，用于连接几个文件的输出，但通常用于此目的：

```
[root@rhel8 ~]# ls –m /var/ > /root/var-files.txt
[root@rhel8 ~]#
[root@rhel8 ~]# cat var-files.txt 
adm, cache, crash, db, empty, ftp, games, gopher, kerberos, lib, local, lock,
log, mail, nis, opt, preserve, run, spool, tmp, yp
```

我们还可以将`/var/lib`的内容添加到此文件中。首先，我们可以列出它：

```
[root@rhel8 ~]# ls -m /var/lib/
alternatives, authselect, chrony, dbus, dhclient, dnf, games, initramfs, logrotate, misc, NetworkManager, os-prober, plymouth, polkit-1, portables, private, rhsm, rpm, rpm-state, rsyslog, selinux, sss, systemd, tpm, tuned, unbound
```

现在，要将这些内容附加到`/root/var-files.txt`文件中，我们使用`>>`运算符：

```
[root@rhel8 ~]# ls -m /var/lib/ >> var-files.txt 
[root@rhel8 ~]# cat var-files.txt 
adm, cache, crash, db, empty, ftp, games, gopher, kerberos, lib, local, lock, log, mail, nis, opt, preserve, run, spool, tmp, yp
alternatives, authselect, chrony, dbus, dhclient, dnf, games, initramfs, logrotate, misc, NetworkManager, os-prober, plymouth, polkit-1, portables, private, rhsm, rpm, rpm-state, rsyslog, selinux, sss, systemd, tpm, tuned, unbound 
```

`/root/var-files.txt`文件现在包含了`/var`和`/var/lib`的逗号分隔列表。

现在我们可以尝试列出一个不存在的目录以查看错误消息的打印：

```
[root@rhel8 ~]# ls -m /non
ls: cannot access '/non': No such file or directory
```

我们看到的输出是一个错误，并且系统对其进行了不同的处理，而不是常规消息。我们可以尝试将输出重定向到文件：

```
[root@rhel8 ~]# ls -m /non > non-listing.txt
ls: cannot access '/non': No such file or directory
[root@rhel8 ~]# cat non-listing.txt 
[root@rhel8 ~]#
```

我们看到，使用标准重定向，使用命令提供错误消息，将在屏幕上显示错误消息，并创建一个空文件。这是因为文件包含了通过`STDOUT`显示的常规信息消息的输出。我们仍然可以通过使用`2>`捕获错误的输出，重定向`STDERR`：

```
[root@rhel8 ~]# ls /non 2> /root/error.txt
[root@rhel8 ~]# cat /root/error.txt 
ls: cannot access '/non': No such file or directory
```

现在我们可以独立重定向标准输出和错误输出。

现在我们想要计算`/var`中文件和目录的数量。为此，我们将使用`wc`命令，该命令代表*单词计数*，并使用`-w`选项仅计算单词数。为此，我们将使用`|`表示的*管道*将`ls`的输出重定向到它：

```
[root@rhel8 ~]# ls -m /var/ | wc -w
21
```

我们还可以使用它来计算`/etc`中的条目：

```
 [root@rhel8 ~]# ls -m /etc/ | wc -w
174
```

管道`|`非常适合重用一个命令的输出，并将其发送到另一个命令以处理该输出。现在我们更了解如何使用更常见的运算符来重定向输入和输出。有几种处理输出的方法，我们将在下一节中看到更多示例。

# 使用 grep 和 sed 过滤输出

`grep`命令在系统管理中被广泛使用（并且常常被输入错误）。它有助于在一行中找到模式，无论是在文件中还是通过**标准输入**（**STDIN**）。

让我们对`/usr`中的文件进行递归搜索，并将其放在`/root/usr-files.txt`中：

```
[root@rhel8 ~]# find /usr/ > /root/usr-files.txt
[root@rhel8 ~]# ls -lh usr-files.txt 
-rw-r--r--. 1 root root 1,9M dic 26 12:38 usr-files.txt
```

如您所见，这是一个大小为 1.9 MB 的文件，很难浏览。系统中有一个名为`gzip`的实用程序，我们想知道`/usr`中的哪些文件包含`gzip`模式。为此，我们运行以下命令：

```
[root@rhel8 ~]# grep gzip usr-files.txt 
/usr/bin/gzip
/usr/lib64/python3.6/__pycache__/gzip.cpython-36.opt-2.pyc
/usr/lib64/python3.6/__pycache__/gzip.cpython-36.opt-1.pyc
/usr/lib64/python3.6/__pycache__/gzip.cpython-36.pyc
/usr/lib64/python3.6/gzip.py
/usr/share/licenses/gzip
/usr/share/licenses/gzip/COPYING
/usr/share/licenses/gzip/fdl-1.3.txt
/usr/share/doc/gzip
/usr/share/doc/gzip/AUTHORS
/usr/share/doc/gzip/ChangeLog
/usr/share/doc/gzip/NEWS
/usr/share/doc/gzip/README
/usr/share/doc/gzip/THANKS
/usr/share/doc/gzip/TODO
/usr/share/man/man1/gzip.1.gz
/usr/share/info/gzip.info.gz
/usr/share/mime/application/gzip.xml
```

如您所见，我们已经通过创建一个包含所有内容的文件并使用`grep`搜索到了`/usr`目录下的所有包含`gzip`的文件。我们可以在不创建文件的情况下做同样的事情吗？当然可以，通过使用*管道*。我们可以将`find`的输出重定向到`grep`并获得相同的输出：

```
[root@rhel8 ~]# find /usr/ | grep gzip
/usr/bin/gzip
/usr/lib64/python3.6/__pycache__/gzip.cpython-36.opt-2.pyc
/usr/lib64/python3.6/__pycache__/gzip.cpython-36.opt-1.pyc
/usr/lib64/python3.6/__pycache__/gzip.cpython-36.pyc
/usr/lib64/python3.6/gzip.py
/usr/share/licenses/gzip
/usr/share/licenses/gzip/COPYING
/usr/share/licenses/gzip/fdl-1.3.txt
/usr/share/doc/gzip
/usr/share/doc/gzip/AUTHORS
/usr/share/doc/gzip/ChangeLog
/usr/share/doc/gzip/NEWS
/usr/share/doc/gzip/README
/usr/share/doc/gzip/THANKS
/usr/share/doc/gzip/TODO
/usr/share/man/man1/gzip.1.gz
/usr/share/info/gzip.info.gz
/usr/share/mime/application/gzip.xml
```

在这个命令中，`find`的标准输出被发送到`grep`进行处理。我们甚至可以使用`-l`选项计算文件的实例数，但这次使用`wc`来计算行数：

```
[root@rhel8 ~]# find /usr/ | grep gzip | wc -l
18
```

我们现在已经连接了两个管道，一个用于过滤输出，另一个用于计数。当在系统中搜索和查找信息时，我们经常会发现自己这样做。

`grep`的一些非常常见的选项如下：

+   `-i`：用于**忽略大小写**。这将匹配无论是大写还是小写或二者的组合的模式。

+   `-v`：用于**反转匹配**。这将显示所有不匹配搜索模式的条目。

+   -r：用于**递归**。我们可以告诉 grep 在目录中的所有文件中搜索模式，同时浏览所有文件（如果我们有权限）。

还有一种方法可以过滤输出中的列。假设我们有一个文件列表在我们的主目录中，并且我们想看到它的大小。我们运行以下命令：

```
[root@rhel8 ~]# ls -l
total 1888
-rw-------. 1 root root    1393 dic  7 16:45 anaconda-ks.cfg
-rw-r--r--. 1 root root      52 dic 26 12:17 error.txt
-rw-r--r--. 1 root root       0 dic 26 12:08 non-listing.txt
-rw-r--r--. 1 root root 1917837 dic 26 12:40 usr-files.txt
-rw-r--r--. 1 root root     360 dic 26 12:12 var-files.txt
```

假设我们只想要包含其名称中有`files`的内容的大小，即第五列。我们可以使用`awk`来实现：

```
[root@rhel8 ~]# ls -l | grep files | awk '{ print $5}' 
1917837
360
```

`awk`工具将帮助我们根据正确的列进行过滤。它非常有用，可以在长输出中找到进程中的标识符或获取特定的数据列表。

提示

请考虑`awk`在处理输出方面非常强大，我们将使用其最小功能。

我们可以用`-F`替换分隔符，并获取系统中可用用户的列表：

```
[root@rhel8 ~]# awk -F: '{ print $1}' /etc/passwd
root
bin
daemon
adm
lp
sync
shutdown
halt
mail
operator
games
ftp
nobody
dbus
systemd-coredump
systemd-resolve
tss
polkitd
unbound
sssd
chrony
sshd
rngd
user
```

`awk`和`grep`工具是 Linux 系统管理员生活中非常常见的处理工具，重要的是要充分理解它们，以便管理系统提供的输出。我们已经应用了基本知识来过滤按行和列接收的输出。现在让我们继续学习如何管理系统中的文件，以便更好地处理我们刚刚生成的存储输出。

# 列出、创建、复制和移动文件和目录、链接和硬链接

重要的是要知道如何从命令行管理文件和目录（也称为文件夹）。这将作为管理和复制重要数据（如配置文件或数据文件）的基础。

## 目录

让我们首先创建一个目录来保存一些工作文件。我们可以通过运行`mkdir`来实现，缩写为**make directory**：

```
[user@rhel8 ~]$ mkdir mydir
[user@rhel8 ~]$ ls -l
total 0
drwxrwxr-x. 2 user user 6 Dec 23 19:53 mydir
```

可以使用`rmdir`命令删除文件夹，缩写为**remove directory**：

```
[user@rhel8 ~]$ ls -l
total 0
drwxrwxr-x. 2 user user 6 Dec 23 19:53 mydir
[user@rhel8 ~]$ mkdir deleteme
[user@rhel8 ~]$ ls -l
total 0
drwxrwxr-x. 2 user user 6 Dec 23 20:15 deleteme
drwxrwxr-x. 2 user user 6 Dec 23 19:53 mydir
[user@rhel8 ~]$ rmdir deleteme
[user@rhel8 ~]$ ls -l
total 0
drwxrwxr-x. 2 user user 6 Dec 23 19:53 mydir
```

但是，`rmdir`只会删除空目录：

```
[user@rhel8 ~]$ ls /etc/ > ~/mydir/etc-files.txt
[user@rhel8 ~]$ rmdir mydir
rmdir: failed to remove 'mydir': Directory not empty
```

我们如何使用删除（`rm`）命令删除目录及其包含的所有其他文件和目录？首先，让我们创建并删除一个单个文件`var-files.txt`：

```
[user@rhel8 ~]$ ls /var/ > ~/var-files.txt
[user@rhel8 ~]$ ls -l var-files.txt 
-rw-rw-r--. 1 user user 109 Dec 26 15:31 var-files.txt
[user@rhel8 ~]$ rm var-files.txt 
[user@rhel8 ~]$ ls -l var-files.txt 
ls: cannot access 'var-files.txt': No such file or directory
```

删除完整的目录分支，包括其中的内容，我们可以使用`-r`选项，简称**递归**：

```
[user@rhel8 ~]$ rm -r mydir/
[user@rhel8 ~]$ ls -l
total 0
```

重要提示

在删除时使用递归模式时要非常小心，因为它既没有恢复命令，也没有垃圾箱来保存在命令行中已删除的文件。

让我们来看看复习表：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_03_Table_04.jpg)

现在我们知道如何在 Linux 系统中创建和删除目录，让我们开始复制和移动内容。

## 复制和移动

现在，让我们复制一些文件来玩，使用`cp`（例如将`awk`示例复制到我们的主目录中：

```
[user@rhel8 ~]$ mkdir myawk
[user@rhel8 ~]$ cp /usr/share/awk/* myawk/
[user@rhel8 ~]$ ls myawk/ | wc -l
26
```

要同时复制多个文件，我们使用了`*`符号。这样可以通过逐个指定文件的方式，只需输入`*`即可。我们还可以输入初始字符，然后加上`*`，所以让我们尝试使用通配符复制一些更多的文件，首先：

```
[user@rhel8 ~]$ mkdir mysystemd
[user@rhel8 ~]$ cp /usr/share/doc/systemd/* mysystemd/
[user@rhel8 ~]$ cd mysystemd/
[user@rhel8 mysystemd]$ ls
20-yama-ptrace.conf  CODING_STYLE  DISTRO_PORTING  ENVIRONMENT.md  GVARIANT-SERIALIZATION  HACKING  NEWS  README  TRANSIENT-SETTINGS.md  TRANSLATORS  UIDS-GIDS.md
```

您会看到运行`ls TR*`只显示以`TR`开头的文件：

```
[user@rhel8 mysystemd]$ ls TR*
TRANSIENT-SETTINGS.md  TRANSLATORS
```

它将以相同的方式处理文件结尾：

```
[user@rhel8 mysystemd]$ ls *.md
ENVIRONMENT.md  TRANSIENT-SETTINGS.md  UIDS-GIDS.md
```

如您所见，它只显示以`.md`结尾的文件。

我们可以使用`-r`选项复制完整的文件和目录分支，用于`cp`：

```
[user@rhel8 mysystemd]$ cd ~
[user@rhel8 ~]$ mkdir myauthselect
[user@rhel8 ~]$ cp -r /usr/share/authselect/* myauthselect
[user@rhel8 ~]$ ls myauthselect/
default  vendor
```

递归选项对于复制完整分支非常有用。我们也可以使用`mv`命令轻松移动目录或文件。让我们将所有新目录放在一个新创建的名为`docs`的目录中：

```
[user@rhel8 ~]$ mv my* docs/ 
[user@rhel8 ~]$ ls docs/
myauthselect  myawk  mysystemd
```

您可以看到，使用`mv`时，您无需使用递归选项来管理文件和目录的完整分支。它也可以用于重命名文件和/或目录：

```
[user@rhel8 ~]$ cd docs/mysystemd/
[user@rhel8 mysystemd]$ ls
20-yama-ptrace.conf  CODING_STYLE  DISTRO_PORTING  ENVIRONMENT.md  GVARIANT-SERIALIZATION  HACKING  NEWS  README  TRANSIENT-SETTINGS.md  TRANSLATORS  UIDS-GIDS.md
[user@rhel8 mysystemd]$ ls -l NEWS
-rw-r--r--. 1 user user 451192 Dec 26 15:59 NEWS
[user@rhel8 mysystemd]$ mv NEWS mynews
[user@rhel8 mysystemd]$ ls -l NEWS
ls: cannot access 'NEWS': No such file or directory
[user@rhel8 mysystemd]$ ls -l mynews 
-rw-r--r--. 1 user user 451192 Dec 26 15:59 mynews
```

有一个专门用于创建空文件的命令，即`touch`：

```
[user@rhel8 ~]$ ls -l  docs/
total 4
drwxrwxr-x. 4 user user   35 Dec 26 16:08 myauthselect
drwxrwxr-x. 2 user user 4096 Dec 26 15:51 myawk
drwxrwxr-x. 2 user user  238 Dec 26 16:21 mysystemd
[user@rhel8 ~]$ touch docs/mytouch
[user@rhel8 ~]$ ls -l  docs/
total 4
drwxrwxr-x. 4 user user   35 Dec 26 16:08 myauthselect
drwxrwxr-x. 2 user user 4096 Dec 26 15:51 myawk
drwxrwxr-x. 2 user user  238 Dec 26 16:21 mysystemd
-rw-rw-r--. 1 user user    0 Dec 26 16:27 mytouch
```

当应用于现有文件或文件夹时，它将更新其访问时间为当前时间：

```
[user@rhel8 ~]$ touch docs/mysystemd
[user@rhel8 ~]$ ls -l  docs/
total 4
drwxrwxr-x. 4 user user   35 Dec 26 16:08 myauthselect
drwxrwxr-x. 2 user user 4096 Dec 26 15:51 myawk
drwxrwxr-x. 2 user user  238 Dec 26 16:28 mysystemd
-rw-rw-r--. 1 user user    0 Dec 26 16:27 mytouch
```

让我们检查一下复习表：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_03_Table_05.jpg)

现在我们知道如何复制、删除、重命名和移动文件和目录，甚至是完整的目录分支。现在让我们来看看另一种处理它们的方式——链接。

## 符号链接和硬链接

我们可以使用**链接**在两个位置拥有相同的文件。有两种类型的链接：

+   **硬链接**：文件系统中将有两个（或更多）指向相同文件的条目。内容将一次写入磁盘。对于同一文件，不能在两个不同的文件系统中创建硬链接。目录不能创建硬链接。

+   **符号链接**：创建指向系统中任何位置的文件或目录的符号链接。

两者都是使用`ln`，表示*链接*，实用程序创建的。

现在让我们创建硬链接：

```
[user@rhel8 ~]$ cd docs/      
[user@rhel8 docs]$ ln mysystemd/README MYREADME
[user@rhel8 docs]$ ls -l
total 20
drwxrwxr-x. 4 user user    35 Dec 26 16:08 myauthselect
drwxrwxr-x. 2 user user  4096 Dec 26 15:51 myawk
-rw-r--r--. 2 user user 13826 Dec 26 15:59 MYREADME
drwxrwxr-x. 2 user user   238 Dec 26 16:28 mysystemd
-rw-rw-r--. 1 user user     0 Dec 26 16:27 mytouch
[user@rhel8 docs]$ ln MYREADME MYREADME2
[user@rhel8 docs]$ ls -l
total 36
drwxrwxr-x. 4 user user    35 Dec 26 16:08 myauthselect
drwxrwxr-x. 2 user user  4096 Dec 26 15:51 myawk
-rw-r--r--. 3 user user 13831 Dec 26 16:32 MYREADME
-rw-r--r--. 3 user user 13831 Dec 26 16:32 MYREADME2
drwxrwxr-x. 2 user user   238 Dec 26 16:28 mysystemd
-rw-rw-r--. 1 user user     0 Dec 26 16:27 mytouch
drwxrwxr-x. 2 user user     6 Dec 26 16:35 test
```

检查文件的引用数量增加（在上一个示例中加粗显示）。

现在让我们创建一个指向目录的符号链接，使用`ln -s`（*s 代表符号*）：

```
[user@rhel8 docs]$ ln -s mysystemd mysystemdlink
[user@rhel8 docs]$ ls -l
total 36
drwxrwxr-x. 4 user user    35 Dec 26 16:08 myauthselect
drwxrwxr-x. 2 user user  4096 Dec 26 15:51 myawk
-rw-r--r--. 3 user user 13831 Dec 26 16:32 MYREADME
-rw-r--r--. 3 user user 13831 Dec 26 16:32 MYREADME2
drwxrwxr-x. 2 user user   238 Dec 26 16:28 mysystemd
lrwxrwxrwx. 1 user user     9 Dec 26 16:40 mysystemdlink -> mysystemd
-rw-rw-r--. 1 user user     0 Dec 26 16:27 mytouch
drwxrwxr-x. 2 user user     6 Dec 26 16:35 test
```

检查符号链接创建时如何被视为不同类型，因为它以`l`开头，表示*链接*（在上一个示例中加粗显示），而不是以`d`开头，表示*目录*（在上一个示例中也加粗显示）。

提示

如果不确定使用硬链接还是符号链接，使用符号链接作为默认选择。

让我们检查一下复习表：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_03_Table_06.jpg)

如您所见，创建链接和符号链接非常简单，并且可以帮助从不同位置访问相同的文件或目录。在下一节中，我们将介绍如何打包和压缩一组文件和目录。

# 使用 tar 和 gzip

有时，我们希望将完整的目录（包括文件）打包成一个文件，以便进行备份，或者只是为了更轻松地共享它。可以帮助将文件聚合成一个的命令是`tar`。

首先，我们需要安装`tar`：

```
[root@rhel8 ~]# yum install tar -y
```

我们可以尝试创建一个`root`的`/etc`目录分支的备份：

```
[root@rhel8 ~]# tar -cf etc-backup.tar /etc
tar: Removing leading '/' from member names
[root@rhel8 ~]# ls -lh etc-backup.tar 
-rw-r--r--. 1 root root 21M dic 27 16:08 etc-backup.tar
```

让我们检查所使用的选项：

+   `-c`：代表创建。TAR 可以将文件放在一起，也可以解压缩它们。

+   `-f`：代表文件。我们指定下一个参数将使用文件。

我们可以尝试解压缩它：

```
[root@rhel8 ~]# mkdir tmp
[root@rhel8 ~]# cd tmp/
[root@rhel8 tmp]# tar -xf ../etc-backup.tar 
[root@rhel8 tmp]# ls
etc
```

让我们检查一下所使用的新选项：

+   `-x`：用于提取。它解压缩一个 TAR 文件。

请注意，我们创建了一个名为`tmp`的目录来工作，并且我们使用`..`快捷方式指向了`tmp`的父目录（它指的是当前工作目录的父目录）。

让我们使用`gzip`来压缩一个文件。我们可以复制`/etc/services`并对其进行压缩：

```
[root@rhel8 etc]# cd ..
[root@rhel8 tmp]# cp /etc/services .
[root@rhel8 tmp]# ls -lh services 
-rw-r--r--. 1 root root 677K dic 27 16:16 services
[root@rhel8 tmp]# gzip services 
[root@rhel8 tmp]# ls -lh services.gz 
-rw-r--r--. 1 root root 140K dic 27 16:16 services.gz
```

请注意，使用`gzip`时，这将压缩指定的文件，并向其添加`.gz`扩展名，原始文件将不会被保留。还要注意，新创建的文件大小是原始文件的五分之一。

要恢复它，我们可以运行`gunzip`：

```
-rw-r--r--. 1 root root 140K dic 27 16:16 services.gz
[root@rhel8 tmp]# gunzip services.gz 
[root@rhel8 tmp]# ls -lh services 
-rw-r--r--. 1 root root 677K dic 27 16:16 services
```

现在我们可以将两者结合起来，打包并压缩它们：

```
[root@rhel8 ~]# tar cf etc-backup.tar /etc/
tar: Removing leading '/' from member names
[root@rhel8 ~]# ls -lh etc-backup.tar 
-rw-r--r--. 1 root root 21M dic 27 16:20 etc-backup.tar
[root@rhel8 ~]# gzip etc-backup.tar 
[root@rhel8 ~]# ls etc-backup.tar.gz 
etc-backup.tar.gz
[root@rhel8 ~]# ls -lh etc-backup.tar.gz 
-rw-r--r--. 1 root root 4,9M dic 27 16:20 etc-backup.tar.gz
```

这样，我们可以分两步进行打包和压缩。

`tar`命令足够智能，能够在单个步骤中执行打包和压缩：

```
[root@rhel8 ~]# rm -f etc-backup.tar.gz 
[root@rhel8 ~]# tar -czf etc-backup.tar.gz /etc/
tar: Removing leading '/' from member names
[root@rhel8 ~]# ls -lh etc-backup.tar.gz 
-rw-r--r--. 1 root root 4,9M dic 27 16:22 etc-backup.tar.gz
```

让我们检查一下新选项：

+   `-z`：这将使用`gzip`压缩新创建的 tar 文件。它也适用于解压缩。

我们可能希望在解压缩时审查相同的选项：

```
[root@rhel8 ~]# cd tmp/
[root@rhel8 tmp]# rm -rf etc
[root@rhel8 tmp]# tar -xzf ../etc-backup.tar.gz 
[root@rhel8 tmp]# ls
etc
```

正如您所看到的，使用`tar`和`gzip`非常容易打包和压缩文件。还有其他可用的压缩方法，如`bzip2`或`xz`，具有更高的压缩比，您可能也想尝试。现在，让我们继续将我们学到的所有命令组合成一种强大的自动化方式——通过创建 shell 脚本。

# 创建基本的 shell 脚本

作为系统管理员，或者 sysadmin，有时您想要多次运行一系列命令。您可以通过每次运行每个命令来手动执行此操作；但是，有一种更有效的方法可以这样做，即创建一个**s****hell 脚本**。

shell 脚本只不过是一个包含要运行的命令列表的文本文件，并引用将解释它的 shell。

在本书中，我们不会涵盖如何使用**文本编辑器**；但是，我们将提供三种在 Linux 中使用的文本编辑器的建议，这可能会有所帮助：

+   **Nano**：这可能是最适合初学者使用的最简单的文本编辑器。精简，简单，直接，您可能希望开始安装并尝试使用它。

+   **Vi**或**Vim**：Vi 是 RHEL 中默认的文本编辑器，甚至在最小安装中也包括在内，并且在许多 Linux 发行版中都有。即使您不会每天使用它，熟悉它的基础知识也是很好的，因为它几乎会出现在您将使用的任何 Linux 系统中。**Vim**代表**vi-improved**。

+   **Emacs**：这可能是有史以来最先进和复杂的文本编辑器。它可以做任何事情，甚至包括阅读电子邮件或通过**Emacs Doctor**进行一些心理分析。

我们可以通过编辑一个名为`hello.sh`的新文件并将以下行作为其内容来创建我们的第一个 shell 脚本：

```
echo ''hello world!''
```

然后我们可以使用`bash`**命令解释器**运行它，使用以下命令：

```
[root@rhel8 ~]# bash hello.sh 
hello world!
```

有一种不需要输入`bash`的方法。我们可以添加一个引用解释器的初始行，因此`hello.sh`的文件内容如下：

```
#!/bin/bash
echo ''hello world!''
```

现在我们正在更改权限以使其可执行：

```
[root@rhel8 ~]# ls -l hello.sh 
-rw-r--r--. 1 root root 32 dic 27 18:20 hello.sh
[root@rhel8 ~]# chmod +x hello.sh 
[root@rhel8 ~]# ls -l hello.sh 
-rwxr-xr-x. 1 root root 32 dic 27 18:20 hello.sh
```

然后我们就像这样运行它：

```
[root@rhel8 ~]# ./hello.sh 
hello world!
```

我们已经创建了我们的第一个 shell 脚本。恭喜！

提示

为了在任何工作目录中运行命令，命令必须在路径中，如`$PATH`变量所述。如果我们的命令（或 shell 脚本）不在路径中指定的目录之一中，我们将指定运行目录，在这种情况下，使用`.`当前目录的快捷方式和`/`分隔符。

让我们在其中使用一些变量。我们可以通过简单地放置变量的名称和我们想要的值来定义一个变量。让我们尝试用一个变量替换单词`world`。要使用它，我们在变量的名称前面加上`$`符号，它将被使用。脚本将如下所示：

```
#!/bin/bash
PLACE=''world''
echo ''hello $PLACE!''
```

我们可以运行脚本，获得与之前相同的输出：

```
[root@rhel8 ~]# ./hello.sh 
hello world!
```

为了更清晰，当使用变量的值时，我们将把它的名称放在大括号之间，`{`''和''`}`，并将其视为一种良好的做法。

先前的脚本将如下所示：

```
#!/bin/bash
PLACE=''world''
echo ''hello ${PLACE}!''
```

现在我们知道如何创建一个基本脚本，但是我们可能想通过使用一些编程能力来更深入地控制它，从循环开始。让我们开始吧！

## for 循环

如果我们想对一系列位置运行相同的命令怎么办？这就是`for`**循环**的用途。它可以帮助迭代一组元素，例如列表或计数器。

`for`循环语法如下：

+   `for`：指定迭代

+   `do`：指定操作

+   `done`：结束循环

我们可以定义一个以空格分隔的列表来尝试并用我们的第一个`for`循环来迭代它：

```
#!/bin/bash
PLACES_LIST=''Madrid Boston Singapore World''
for PLACE in ${PLACES_LIST}; do
echo ''hello ${PLACE}!''
done
```

让我们运行它。输出将如下所示：

```
[root@rhel8 ~]# ./hello.sh
hello Madrid!
hello Boston!
hello Singapore!
hello World!
```

使用`for`循环时，可以非常有趣，当`$(`和`)`。

提示

反引号，`'`，也可以用于运行命令并将其输出作为列表，但为了清晰起见，我们将坚持使用先前的表达式。

一个可以使用的外部命令的例子可以是`ls`。让我们创建`txtfiles.sh`脚本，内容如下：

```
#!/bin/bash
for TXTFILE in $(ls *.txt); do
  echo ''TXT file ${TXTFILE} found! ''
done
```

使其可执行并运行：

```
[root@rhel8 ~]# chmod +x txtfiles.sh 
[root@rhel8 ~]# ./txtfiles.sh 
TXT file error.txt found!
TXT file non-listing.txt found!
TXT file usr-files.txt found!
TXT file var-files.txt found!
```

您看，我们现在可以迭代一组文件，包括，例如，更改它们的名称，查找和替换其中的内容，或者仅对一组文件进行特定的备份。

我们已经看到了使用`for`循环迭代列表的几种方法，当涉及自动化任务时，这可能非常有用。现在，让我们继续学习脚本中的另一个编程能力——条件语句。

## 条件语句

有时，我们可能希望对列表中的一个元素执行不同的操作，或者对此使用`if`条件。

`if`条件语法是`if`：指定条件。

条件通常在括号之间指定，`[`和`]`。

+   `then`：指定操作

+   `fi`：结束循环

让我们将之前的`hello.sh`脚本改成用西班牙语说`hello to Madrid`，就像这样：

```
#!/bin/bash
PLACES_LIST=''Madrid Boston Singapore World''
for PLACE in ${PLACES_LIST}; do
    if [ ${PLACE} = ''Madrid'' ]; then
        echo ''¡Hola ${PLACE}!''
    fi
done
```

然后，运行它：

```
[root@rhel8 ~]# ./hello.sh 
¡Hola Madrid!
```

我们有一个问题；它只说`hello to Madrid`。如果我们想对不符合条件的项目运行先前的代码会发生什么？这时我们使用`else`来扩展条件。语法如下：

+   `else`：当条件*不*匹配时，这被用作`then`元素。

现在我们有了一个使用`else`的条件语句的示例：

```
#!/bin/bash
PLACES_LIST=''Madrid Boston Singapore World''
for PLACE in ${PLACES_LIST}; do
    if [ ${PLACE} = ''Madrid'' ]; then
        echo ''¡Hola ${PLACE}!''
    else
        echo ''hello ${PLACE}!''
    fi
done
```

现在我们可以运行它：

```
[root@rhel8 ~]# ./hello.sh 
¡Hola Madrid!
hello Boston!
hello Singapore!
hello World!
```

如您所见，在脚本中使用条件语句很简单，并且可以在运行命令的条件下提供很多控制。现在我们需要控制当某些情况可能无法正确运行时。这就是退出代码（或错误代码）的用途。让我们开始吧！

## 退出代码

当运行程序时，它会提供一个`$?`。

让我们通过运行`ls hello.sh`来看一下：

```
[root@rhel8 ~]# ls hello.sh 
hello.sh
[root@rhel8 ~]# echo $?
0
```

当程序正常运行时，*退出代码*为零，`0`。

当我们尝试列出一个不存在的文件（或运行任何其他命令不正确或出现问题）时会发生什么？让我们尝试列出一个`nonexistent`文件：

```
[root@rhel8 ~]# ls nonexistentfile.txt
ls: cannot access 'nonexistentfile.txt': No such file or directory
[root@rhel8 ~]# echo $?
2
```

您看，*退出代码*不等于零。我们将查看文档并检查与之关联的数字，以了解问题的性质。

在脚本中运行命令时，检查退出代码并相应地采取行动。现在让我们回顾一下在下一节中找到有关命令的更多信息的地方，比如退出代码或其他选项。

# 使用系统文档资源

系统包括资源，可在使用系统时帮助您并指导您提高系统管理员技能。这被称为**系统文档**。让我们检查默认情况下在您的 RHEL 安装中可用的三种不同资源：man 页面、info 页面和其他文档。

## Man 页面

获取文档的最常用资源是`man`。

系统中安装的几乎所有实用程序都有 man 页面来帮助您使用它（换句话说，指定工具的所有选项以及它们的作用）。您可以运行`man tar`并检查输出：

```
[root@rhel8 ~]# man tar
TAR(1)                                    GNU TAR Manual                                   TAR(1)

NAME
       tar - an archiving utility

SYNOPSIS
   Traditional usage
       tar {A|c|d|r|t|u|x}[GnSkUWOmpsMBiajJzZhPlRvwo] [ARG...]

   UNIX-style usage
       tar -A [OPTIONS] ARCHIVE ARCHIVE

       tar -c [-f ARCHIVE] [OPTIONS] [FILE...]

       tar -d [-f ARCHIVE] [OPTIONS] [FILE...]
```

您可以在其中查看（使用*箭头*键、空格键和/或*Page Up*和*Page Down*进行导航），并通过按字母`q`（表示*退出*）退出。

`man`页面中有相关主题的章节。使用`apropos`命令很容易搜索这些内容。让我们以`tar`为例看看：

```
[root@rhel8 ~]# apropos tar
dbus-run-session (1) - start a process as a new D-Bus session
dnf-needs-restarting (8) - DNF needs_restarting Plugin
dracut-pre-udev.service (8) - runs the dracut hooks before udevd is started
gpgtar (1)           - Encrypt or sign files into an archive
gtar (1)             - an archiving utility
open (1)             - start a program on a new virtual terminal (VT).
openvt (1)           - start a program on a new virtual terminal (VT).
scsi_start (8)       - start one or more SCSI disks
setarch (8)          - change reported architecture in new program environment and set personalit...
sg_reset (8)         - sends SCSI device, target, bus or host reset; or checks reset state
sg_rtpg (8)          - send SCSI REPORT TARGET PORT GROUPS command
sg_start (8)         - send SCSI START STOP UNIT command: start, stop, load or eject medium
sg_stpg (8)          - send SCSI SET TARGET PORT GROUPS command
systemd-notify (1)   - Notify service manager about start-up completion and other daemon status c...
systemd-rc-local-generator (8) - Compatibility generator for starting /etc/rc.local and /usr/sbin...
systemd.target (5)   - Target unit configuration
tar (1)              - an archiving utility
tar (5)              - format of tape archive files
unicode_start (1)    - put keyboard and console in unicode mode
```

正如你所看到的，它不仅匹配`tar`还匹配`start`。这并不完美，但它可以提供与 tar 相关的有用信息，比如`gpgtar`。

手册页面有一个章节。正如你在前面的例子中看到的，对于`tar`，有两个章节的手册页面，一个是命令行实用程序（第一部分），另一个是存档格式（第五部分）：

```
tar (1)              - an archiving utility
tar (5)              - format of tape archive files
```

我们可以通过运行以下命令访问第五部分的页面以了解格式：

```
[root@rhel8 ~]# man 5 tar
```

现在我们可以看到`tar 格式`页面：

```
TAR(5)                               BSD File Formats Manual                               TAR(5)

NAME
     tar — format of tape archive files

DESCRIPTION
     The tar archive format collects any number of files, directories, and other file system objects (symbolic links, device nodes, etc.) into a single stream of bytes.  The format was ...
```

您可以看到手册页面是了解更多关于典型命令的绝佳资源。这也是**Red Hat 认证系统管理员**考试的绝佳资源。建议是查看本章中先前显示的所有命令的 man 页面，以及即将到来的章节。考虑 man 页面是系统中的主要信息资源。现在让我们回顾其他可用的信息资源。

## 信息页面

**Info 页面**通常比 man 页面更具描述性，而且更具交互性。它们更有助于开始一个主题。

我们可以尝试通过运行以下命令获取`ls`命令的`info`：

```
[root@rhel8 ~]# info ls
```

我们可以看到它的信息页面：

```
Next: dir invocation,  Up: Directory listing

10.1 'ls': List directory contents
==================================

The 'ls' program lists information about files (of any type, including
directories).  Options and file arguments can be intermixed arbitrarily,
```

信息页面可以*重定向到其他主题，以下划线显示*，可以将光标放在上面并按*Enter*进行跟踪。

与 man 页面一样，按`q`退出。

请花一些时间查看本章涵盖的主要主题的信息页面（在许多情况下，信息页面将不可用，但那些可用的可能非常有价值）。

如果我们找不到一个主题的 man 或 info 页面怎么办？让我们在下一节中讨论这个问题。

## 其他文档资源

对于其他文档资源，您可以转到`/usr/share/doc`目录。在那里，您会找到随系统安装的工具附带的其他文档。

让我们看看我们有多少项：

```
[root@rhel8 doc]# cd /usr/share/doc/
[root@rhel8 doc]# ls | wc -l
219
```

您可以看到在`/usr/share/doc`目录下有 219 个可用目录。

作为一个很好的例子，让我们进入`bash`目录：

```
[root@rhel8 doc]# cd bash/
```

然后，让我们使用`less`来查看`INTRO`文件（记住，使用`q`退出）：

```
[root@rhel8 bash]# ls 
bash.html  bashref.html  FAQ  INTRO  RBASH  README
[root@rhel8 bash]# less INTRO
                       BASH - The Bourne-Again Shell

Bash is the shell, or command language interpreter, that will appear in the GNU operating system.  Bash is an sh-compatible shell that
incorporates useful features from the Korn shell (ksh) and C shell
(csh).  It is intended to conform to the IEEE POSIX P1003.2/ISO 9945.2 Shell and Tools standard.  It offers functional improvements
```

这是一个更好地理解 bash 的好读物。现在您有很多文档资源，您将能够在日常任务中以及在**RHCSA**考试中使用。

# 摘要

在本章中，我们学习了如何使用用户和`root`登录系统，了解权限和安全性的基础知识。我们现在也更熟悉使用命令行自动完成、浏览目录和文件、打包和解包它们、重定向命令输出和解析它，甚至使用 shell 脚本自动化进程。更重要的是，我们有一种方法可以在任何 RHEL 系统中获取我们正在做的（或想要做的）信息，这些信息包含在包含的文档中。这些技能是即将到来的章节的基础。如果您感到困惑，或者您的进展不如您所想的那么快，请不要犹豫重新阅读本章。

现在是时候扩展您的知识，涵盖即将到来的章节中更高级的主题。在接下来的章节中，您将开始习惯*常规操作工具*，您将回顾在管理系统时所采取的最常见操作。享受吧！
