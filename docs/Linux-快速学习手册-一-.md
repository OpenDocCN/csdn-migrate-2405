# Linux 快速学习手册（一）

> 原文：[`zh.annas-archive.org/md5/d44a95bd11f73f80156880d7ba808e3a`](https://zh.annas-archive.org/md5/d44a95bd11f73f80156880d7ba808e3a)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

前言

Linux 在 IT 行业中需求量巨大，因为它为全球超过 90%的超级计算机和服务器提供动力。Linux 也是公共云中最受欢迎的操作系统。Linux 是全球顶级公司的基础架构，如亚马逊、谷歌、IBM 和 Paypal。您现在就需要开始学习 Linux！*快速学习 Linux，第一版*是在两年的时间内编写的，从 2018 年 5 月到 2020 年 5 月。这本书采用了一种现代的学习 Linux 的方法，您一定会欣赏它的独特性和友好的语气。

# 第一章：这本书是为谁准备的

如果您一直想学习 Linux，但仍然害怕这样做，那么这本书就是为您准备的！很多人认为 Linux 是一种只有黑客和极客才知道如何使用的复杂操作系统，因此他们放弃了学习 Linux 的梦想。好吧，让我来给您一个惊喜！Linux 是简单易学的，而这本书就是最好的证明！您可能已经看过各种解释 Linux 的来源，它们都以复杂和枯燥的方式解释 Linux。而这本书恰恰相反；它以一种愉快和友好的方式教会您 Linux，这样您永远不会感到无聊，而且您总是会有动力学习更多。*快速学习 Linux*不假设任何先前的 Linux 知识，这使它非常适合初学者。然而，中级和高级的 Linux 用户仍然会发现这本书非常有用，因为它涵盖了广泛的主题。

# 这本书涵盖了什么内容

第一章，*您的第一个按键*。在这个介绍性的章节中，您将了解 Linux 的历史以及 Linux 在当今世界的影响以及它可能如何塑造未来。您还将学习如何安装 Linux 虚拟机并运行一些简单的命令。

第二章，*攀登树*。在本章中，您将学习 Linux 文件系统层次结构的组织方式，并探索各种 Linux 命令，这些命令将帮助您浏览 Linux 目录树。

第三章，*遇见编辑器*。在 Linux 上，您所做的大部分工作都与文件有关！在本章中，您将学习如何使用流行的文本编辑器，如`nano`和`vi`来查看和编辑 Linux 文件。您还将学习一些方便的命令，让您可以在自己的终端舒适地查看文件！

第四章，*复制、移动和删除文件*。在本章中，您将学习如何对文件执行各种操作。您将学习如何复制、移动和删除文件。您还将学习如何重命名和隐藏文件！

第五章，*阅读您的手册*！让我们诚实一点！您无法记住所有存在的 Linux 命令；没有人可以！这就是为什么在本章中，您将学习如何利用和使用各种 Linux 帮助和文档工具。

第六章，*硬链接与软链接*。在本章中，您将首先了解文件`inode`的概念。您还将学习如何创建硬链接和软链接，以及它们之间的区别。

第七章，*谁是 Root？*是时候终于见到 root 用户了！在本章中，您将了解普通用户的限制，还将意识到 root 用户有多么强大；您还将学习如何在系统上切换不同的用户。

第八章，*控制人口*。您可以把 Linux 想象成一个强大的大国！在本章中，您将学习如何在 Linux 中引入各种用户和组。您将学习如何修改用户和组属性。您还将学习如何更改文件权限和所有权。

第九章，*管道和 I/O 重定向*。在这一章中，您将学习如何使用 Linux 管道将一个命令的输出发送到另一个命令的输入，从而实现更复杂的任务。您还将学习如何进行输入和输出重定向。

第十章，*分析和操作文件*。在这一章中，您将探索一系列 Linux 命令，这些命令将帮助您分析和操作文件。您将学习如何查看文件之间的差异，显示行数，查看文件大小等等！

第十一章，*让我们玩寻找和寻找*。不知道文件在哪里？别担心！在这一章中，您将学习如何使用 locate 和 find 命令在 Linux 系统上搜索文件。

第十二章，*你得到了一个软件包*。在这一章中，您将学习如何在 Linux 系统上安装、删除、搜索和更新软件。您将了解 Linux 中使用的软件术语，包括*软件包*、*仓库*和*软件包管理系统*。

第十三章，*终结进程*。在这一章中，您将学习如何与 Linux 进程交互。您将了解子进程和父进程之间的区别。您还将了解如何在后台运行进程。此外，您还将学习如何终止进程！

第十四章，*sudo 的力量*。在这一章中，您将学习如何授予用户和组`sudo`访问权限，以便他们可以执行管理任务。您将学习如何使用`visudo`命令编辑`sudoers`文件，并学习添加`sudo`规则的正确语法。

第十五章，*网络出了什么问题？*您的网络出了问题！在这一章中，您将学习如何排除网络连接问题。您将学习如何查看您的 IP 地址、DNS、网关和主机配置。此外，您还将学习如何重新启动您的网络接口。

第十六章，*Bash 脚本编程很有趣*。在这一章中，您将学习如何创建 bash 脚本。您将学习如何使用条件语句为您的 bash 脚本增加智能。此外，您还将学习如何循环和创建 bash 函数。

第十七章，*你需要一个定时任务*。不想全天候被电脑绑定？`cron`任务可以帮到你！在这一章中，您将学习如何使用`cron`任务安排任务。您还将学习如何使用`at`实用程序安排一次性任务。

第十八章，*归档和压缩文件*。在这一章中，您将学习如何将文件组合成一个归档文件。您还将学习如何使用各种压缩工具压缩您的归档文件，节省一些磁盘空间。

第十九章，*创建您自己的命令*。您想定义自己的 Linux 命令吗？在这一章中，您将学习如何使用别名来创建自己的 Linux 命令。您还将学习如何创建临时和永久别名。

第二十章，*每个人都需要磁盘空间*。在这一章中，您将学习如何分区硬盘。您还将学习如何创建和挂载文件系统。此外，您还将学习如何修复损坏的文件系统。此外，您还将学习如何使用 Linux LVM 创建逻辑卷。

第二十一章，*echo“再见，我的朋友”。*您的下一步可能是什么？让我给您一些建议，告诉您在阅读本书后该做些什么。

# 要充分利用本书

这本书的唯一要求基本上是任何能工作的计算机！

| **本书涵盖的软件/硬件** | **操作系统要求** |
| --- | --- |
| 任何虚拟化软件，如 VirtualBox，VMware Player 或 VMware Fusion | Windows，macOS 或 Linux |

**如果你正在使用本书的数字版本，我们建议你自己输入命令和脚本。这样做将帮助你避免与复制和粘贴命令和脚本相关的任何潜在错误。**

我非常相信“熟能生巧”的原则。你练习 Linux 的次数越多，你就会越熟悉它。你可以将 Linux 安装为你的主要操作系统；这样你就可以每天都使用 Linux。如果这对你来说不是一个选择，那为什么不买一个便宜的树莓派来玩玩呢？

## 下载彩色图像

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图像。您可以在这里下载：[`www.packtpub.com/sites/default/files/downloads/9781800566002_ColorImages.pdf`](http://www.packtpub.com/sites/default/files/downloads/9781800566002_ColorImages.pdf)。

## 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词，数据库表名，文件夹名，文件名，文件扩展名，路径名，虚拟 URL，用户输入和 Twitter 句柄。例如："`exit`和`cd`命令是 shell 内置命令的两个例子。"

当我们希望引起你对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```
[default]
exten => s,1,Dial(Zap/1|30)
exten => s,2,Voicemail(u100)
exten => s,102,Voicemail(b100)
exten => i,1,Voicemail(s0)
```

任何命令行输入或输出都以以下形式书写：

```
$ mkdir css
$ cd css
```

**粗体**：表示一个新术语，一个重要的词，或者屏幕上看到的词。例如："**文件名**是 inode 数据结构的一部分。"

警告或重要提示会以这种形式出现。

技巧和窍门会以这种形式出现。


你的第一个按键

我想欢迎你来到这本书的第一章。当你阅读这本书时，你会感觉自己在读一个故事，但这不是一般的故事，这是 Linux 的故事。在这一章中，你将了解 Linux 的起源以及 Linux 对当今世界的影响。你还将了解 Linux 如何塑造计算机的未来。最后，你将学会如何在计算机上安装 Linux 虚拟机。所以，不多说了，让我们开始吧。

# 第二章：一点历史

Linux 的故事始于 1991 年，当时芬兰赫尔辛基大学的计算机科学学生 Linus Torvalds 开始写一个免费的操作系统作为业余爱好！现在想想，他的业余项目竟然成为了历史上最大的开源项目。哦，如果你还没有意识到，这个免费的操作系统就是 Linux。网上有很多关于开源的定义，其中一些对于没有经验的读者来说有些混乱，所以这里有一个简化的解释：

**什么是开源？**

开源项目是指其源代码对公众开放查看和编辑的软件项目。

源代码只是用于开发软件的代码（程序）的集合；在 Linux 的上下文中，它指的是构建 Linux 操作系统的编程代码。现在你知道什么是开源，很容易想象什么是封闭源：

**什么是封闭源？**

封闭源项目是指其源代码不对公众开放查看和编辑的软件项目。

Linux 是开源项目的最著名的例子。另一方面，微软 Windows 是封闭源项目的最著名的例子。

有些人不知道什么是操作系统，但不用担心；我会帮你解释。这里有一个简单的操作系统定义：

**什么是操作系统？**

操作系统是一种管理计算机资源（如内存和磁盘空间）的软件程序。它还允许计算机的硬件和软件相互通信。操作系统也可能包括其他应用程序：文本编辑器、文件管理器、图形用户界面、软件管理器等。

这里有很多不同的操作系统；以下是一些例子：

+   Linux

+   Android

+   macOS

+   Microsoft Windows

+   Apple iOS

+   BlackBerry

请记住，这个列表非常简短，无法全面涵盖。有大量的操作系统，甚至很难统计它们的数量。

谈到操作系统时，我们必须提到内核，它是任何操作系统的核心。

**什么是内核？**

内核只是任何操作系统的核心。它是操作系统的一部分，用于组织对 CPU、内存和磁盘等系统资源的访问。

请注意，在定义中，我说内核是操作系统的一部分。下图可以帮助你形象地理解内核和操作系统之间的区别。

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/lrn-linux-qk/img/99c8c1fa-9fa9-4e6c-a765-1e30375b7225.png)

图 1：操作系统 vs. 内核

与微软 Windows 或 macOS 不同，Linux 有许多不同的风味；这些风味被称为发行版，也被简称为 distros。

**什么是 Linux 发行版？**

由于 Linux 是开源的，许多人和组织已经修改了 Linux 内核以及 Linux 操作系统的其他组件，以开发和定制适合他们需求的 Linux 版本。

实际上有数百种 Linux 发行版！你可以去[www.distrowatch.com](http://www.distrowatch.com)查看庞大的 Linux 发行版列表。

[distrowatch.com](http://www.distrowatch.com)的好处在于它显示了世界上所有 Linux 发行版的受欢迎程度排名。您甚至会发现一些 Linux 发行版是根据特定目的设计的。例如，Scientific Linux 是许多科学家中受欢迎的 Linux 发行版，因为它预装了许多科学应用程序，这使它成为科学界的首选 Linux。

# 今天的 Linux 和未来

1991 年，Linux 只是一个小宝宝。但这个宝宝迅速成长，变得非常受欢迎。如今，Linux 为全球超过 90%的顶级超级计算机提供动力。而且让你惊讶的是，你可能已经使用 Linux 多年而没有注意到。怎么可能？如果你曾经使用过安卓智能手机，那么你就使用过 Linux，因为安卓是一个 Linux 发行版！如果你还不相信我，去[distrowatch.com](http://www.distrowatch.com)搜索安卓。

更严肃的问题是，大多数政府服务器都运行 Linux，这就是为什么您会看到很多政府技术工作需要懂得 Linux 的人。此外，亚马逊、eBay、PayPal、沃尔玛等大公司都依赖 Linux 来运行他们的先进和复杂的应用程序。此外，Linux 在云端占据主导地位，超过 75%的云解决方案都在运行 Linux。

Linux 的故事真是鼓舞人心。曾经的爱好现在已经成为互联网的主导力量，而 Linux 的未来看起来更加光明。著名的汽车制造商和汽车制造商如雷克萨斯和丰田现在正在采用 Linux 技术，比如**汽车级 Linux**（**AGL**）。您可以在[www.automotivelinux.org](http://www.automotivelinux.org)上找到更多信息。

Linux 还运行在许多嵌入式设备上，并且是流行的树莓派、Beagle Bone 和许多其他微控制器的基础。您甚至可能会惊讶地知道一些洗衣机也在运行 Linux！所以每当你去洗衣服的时候，花点时间，感谢我们生活中有 Linux。

# 安装 Linux 虚拟机

有多种安装 Linux 系统的方法。例如，如果您目前正在作为主要操作系统运行 Windows，那么您可能可以在 Windows 旁边双启动 Linux，但这种方法对初学者不友好。安装过程中的任何错误可能会给您带来很多头痛，而且在某些情况下，您甚至可能无法再启动 Windows！我想要帮您避免很多痛苦和烦恼，所以我将向您展示如何将 Linux 安装为虚拟机。

什么是虚拟机？

虚拟机就是在另一台计算机（主机）内运行的计算机。虚拟机共享主机资源，表现得就像独立的物理机一样。

您还可以拥有嵌套虚拟机，这意味着您可以在另一个虚拟机内运行虚拟机。

安装虚拟机的过程很简单，您只需要按照以下步骤进行：

1.  安装 VirtualBox（或 VMware Player）。

1.  下载任何 Linux 发行版的 ISO 镜像。

1.  打开 VirtualBox 并开始安装过程。

第一步是安装 VirtualBox，这是一个跨平台的虚拟化应用程序，可以让我们创建虚拟机。VirtualBox 是免费的，可以在 macOS、Windows 和 Linux 上运行。快速搜索一下：VirtualBox 下载就可以搞定。如果你感到有点懒，你可以在以下链接下载 VirtualBox：[www.virtualbox.org/wiki/Downloads](http://www.virtualbox.org/wiki/Downloads)。

安装完 VirtualBox 后，您现在需要下载任何 Linux 发行版的 ISO 镜像。在本书中，您将使用 Ubuntu，这在初学者中可能是最受欢迎的 Linux 发行版。您可以在以下链接下载 Ubuntu：[www.ubuntu.com/download/desktop](http://www.ubuntu.com/download/desktop)。

我建议您下载最新的 Ubuntu **LTS**（**长期支持**）版本，因为它经过了充分测试，并且有更好的支持。

最后一步，您需要打开 VirtualBox，并使用您从*步骤 2*下载的 Ubuntu ISO 镜像创建一个 Linux 虚拟机。

打开 VirtualBox 时，您需要从菜单栏中选择“新建”。

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/lrn-linux-qk/img/ee3ba116-6f34-41a6-8b17-7602b315c928.png)

图 2：创建新虚拟机

然后，您需要选择新虚拟机的名称和类型。

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/lrn-linux-qk/img/1be7c48a-82b6-46e9-b127-5606082e131b.png)

图 3：选择名称和类型

之后，点击“继续”，选择要为虚拟机分配多少内存。我强烈建议选择`2`GB 或更多。例如，在下面的截图中，我选择为我的虚拟机分配`4096`MB 的内存（RAM），相当于`4`GB。

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/lrn-linux-qk/img/50b7d3ff-f1bd-44ad-b2db-d03f7abf61eb.png)

图 4：选择内存大小

之后，点击“继续”，确保选择“现在创建虚拟硬盘”，如下截图所示，然后点击“创建”。

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/lrn-linux-qk/img/7add8ea6-d469-432d-9bdf-0c9b53e5a92b.png)

图 5：创建硬盘

之后，选择**VDI**（**VirtualBox 磁盘映像**），如下截图所示，然后点击继续。

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/lrn-linux-qk/img/666ae5c5-6fee-4611-8321-e259938acf64.png)

图 6：硬盘文件类型

现在选择“动态分配”，如下截图所示，然后点击“继续”。

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/lrn-linux-qk/img/b8ebdc9c-3567-47a9-a70d-db4ef233ca6e.png)

图 7：物理硬盘上的存储

现在您可以选择虚拟机的硬盘大小。我强烈建议您选择`10`GB 或更高。在下面的截图中，我选择了`20`GB 作为我的虚拟机的硬盘大小。

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/lrn-linux-qk/img/3c5bd5c0-f106-46cf-9b4b-84c07f4de223.png)

图 8：硬盘大小

选择硬盘大小后，点击“创建”完成虚拟机的创建。

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/lrn-linux-qk/img/b3bda4ba-53ba-4eed-b01c-b88d0066be1c.jpg)

图 9：虚拟机已创建

您可以点击绿色的“启动”按钮来启动您的虚拟机。然后，您需要选择一个启动盘，如下截图所示。

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/lrn-linux-qk/img/f83622bf-00aa-4c3f-899a-edbe00a956e1.png)

图 10：选择启动盘

选择您已下载的 Ubuntu ISO 镜像，然后点击“启动”以启动 Ubuntu 安装程序，如下截图所示。

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/lrn-linux-qk/img/c8b65b80-43f4-4ede-9e64-773dbf785b5d.png)

图 11：Ubuntu 安装程序

现在您可以选择安装 Ubuntu。接下来，您将需要选择语言和键盘布局。之后，您应该继续接受默认设置。

最终，您将来到创建新用户的步骤，如下截图所示。

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/lrn-linux-qk/img/b75186d4-fe18-4d23-8612-7010452bf009.png)

图 12：创建新用户

我选择了用户名`elliot`，因为我是《黑客军团》这部电视剧的忠实粉丝，而且 Elliot 在轻松地黑入 E Corp 时一直在使用 Linux！我强烈建议您选择`elliot`作为您的用户名，这样您就可以更轻松地跟着本书学习。

然后您可以点击“继续”，系统安装将开始，如下截图所示。

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/lrn-linux-qk/img/90acf23b-99c8-40d3-b8b4-9b3e5e6400d1.jpg)

图 13：系统安装

安装过程将需要几分钟。在安装完成时，请耐心等待或自己泡杯咖啡。

安装完成后，您需要重新启动虚拟机，如下截图所示。

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/lrn-linux-qk/img/c938673a-ea0b-4896-aaea-ef3e199d805e.png)

图 14：安装完成

您可以点击“立即重启”。之后，可能会要求您移除安装介质，您可以通过选择“设备” -+ “光驱” -+ “从虚拟驱动器中移除磁盘”来完成。

最后，您应该看到登录界面，如下截图所示。

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/lrn-linux-qk/img/7311d52b-7ef1-4685-bd85-edae747c4d22.png)

图 15：Ubuntu 登录

现在您可以输入密码，万岁！您现在已经进入了 Linux 系统。

还有其他方法可以用来尝试 Linux 系统。例如，您可以在**AWS**（**亚马逊网络服务**）上创建一个账户，并在 Amazon EC2 实例上启动一个 Linux 虚拟机。同样，您也可以在 Microsoft Azure 上创建一个 Linux 虚拟机。所以，可以说你很幸运生活在这个时代！过去，要在 Linux 上运行起来是一个痛苦的过程。

# 终端与 Shell

**图形用户界面**（**GUI**）相当容易理解。您可以轻松地四处走动，连接到互联网并打开您的网络浏览器。所有这些都很容易，正如您在下面的截图中所看到的。

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/lrn-linux-qk/img/93e299ca-a754-4d58-8c0d-0ccea2cba423.jpg)

图 16：图形用户界面

您可以使用**Ubuntu 软件**在系统上安装新的软件程序。

您可以使用**Dash**与在 Microsoft Windows 上使用“开始”菜单启动应用程序的方式相同。

**LibreOffice Writer**是一个出色的文字处理器，与 Microsoft Word 具有相同的功能，只有一个区别；它是免费的！

现在，您可以成为一个休闲的 Linux 用户，这意味着您可以使用 Linux 来执行日常用户所做的基本任务：浏览 YouTube，发送电子邮件，搜索 Google 等。但是，要成为一个高级用户，您需要熟练使用 Linux 的**命令行界面**。

要访问 Linux 的**命令行界面**，您需要打开终端仿真器，通常简称为**终端**。

**什么是终端仿真器？**

终端仿真器是一种模拟物理终端（控制台）的程序。终端与 Shell（命令行界面）进行交互。

好了，现在您可能会摸着头皮问自己：“什么是 Shell？”

**什么是 Shell？**

Shell 是一个命令行解释器，也就是说，它是一个处理和执行命令的程序。

好了，够了，不要再讲理论了。让我们通过一个示例来理解并把所有东西联系在一起。继续打开终端，点击 Dash，然后搜索`终端`。您也可以使用快捷键*Ctrl*+*Alt*+*T*来打开终端。当终端打开时，您将看到一个新窗口，就像下面的截图所示。

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/lrn-linux-qk/img/444147ac-e059-4571-b5dc-4f80d4357a76.png)

图 17：终端

它看起来有点像 Microsoft Windows 上的命令提示符。好了，现在在您的终端上输入`date`，然后按*Enter*：

```
elliot©ubuntu-linux:-$ date 
Tue Feb 17 16:39:13 CST 2020
```

现在让我们讨论发生了什么，`date`是一个打印当前日期和时间的 Linux 命令，当您按下*Enter*后，Shell（在幕后工作）然后执行了`date`命令，并在您的终端上显示了输出。

您不应该混淆**终端**和**Shell**。终端是您在屏幕上看到的窗口，您可以在其中输入命令，而 Shell 负责执行命令。就是这样，没有更多，也没有更少。

您还应该知道，如果您输入任何无意义的内容，您将会收到**命令未找到**的错误，就像下面的例子中所示的那样：

```
elliot©ubuntu-linux:-$ blabla 
blabla: command not found
```

# 一些简单的命令

恭喜您学会了您的第一个 Linux 命令（`date`）。现在让我们继续学习更多！

通常在显示日期后会显示日历，对吧？要显示当前月份的日历，您可以运行`cal`命令：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/lrn-linux-qk/img/2c75f247-1580-4633-8913-55f3f22de3b6.png)

图 18：cal 命令

您还可以显示整年的日历，例如，要获取完整的 2022 年日历，您可以运行：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/lrn-linux-qk/img/2f2a0044-ca10-4aed-973b-857717fe5bf4.png)

图 19：2022 年的 cal 命令

您还可以指定一个月份，例如，要显示 1993 年 2 月的日历，您可以运行以下命令：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/lrn-linux-qk/img/b0b8c99a-cab9-49b0-b780-86a5874adee2.png)

图 20：1993 年 2 月的 cal 命令

您现在在终端上有很多输出。您可以运行`clear`命令来清除终端屏幕：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/lrn-linux-qk/img/299b7a1a-5392-4079-93af-eaf9d6c627f2.jpg)

图 21：清除前

这是在运行`clear`命令后你的终端会看起来的样子：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/lrn-linux-qk/img/8bcfbb4d-a446-4148-a472-12801c8b5638.png)

图 22：清除后

您可以使用`lscpu`命令，它是**列出 CPU**的缩写，来显示 CPU 架构信息：

```
elliot©ubuntu-linux:-$ lscpu 
Architecture:          x86_64
CPU op-mode(s):        32-bit, 64-bit 
Byte Order:            Little Endian
CPU(s):                1
On-line CPU(s) list:   0
Thread(s) per core:    1 
Core(s) per socket:    1 
Socket(s):             1
NUMA node(s):          1
Vendor ID:             GenuineIntel
CPU family:            6
Model:                 61
Model name:            Intel(R) Core(TM) i5-5300U CPU© 2.30GHz Stepping: 4
CPU MHz:               2294.678
BogoMIPS:              4589.35
Hypervisor vendor:     KVM 
Virtualization type:   full 
Lid cache:             32K
L1i cache:             32K
L2 cache:              256K
L3 cache:              3072K 
NUMA nodeO CPU(s):     0
Flags:                 fpu vme de pse tsc msr pae mce cx8 apic sep mtrr
```

您可以使用`uptime`命令来检查系统已运行多长时间。`uptime`命令还会显示：

+   当前时间。

+   当前已登录的用户数。

+   过去 1、5 和 15 分钟的系统负载平均值。

```
elliot©ubuntu-linux:-$ uptime
18:48:04 up 4 days, 4:02, 1 user, load average: 0.98, 2.12, 3.43
```

您可能会对`uptime`命令的输出感到害怕，但不用担心，下表会为您解释输出内容。

| `18:48:04` | 输出中看到的第一件事是当前时间。 |
| --- | --- |
| `已运行 4 天 4 小时 2 分钟` | 这基本上是说系统已经运行了 4 天 4 小时 2 分钟。 |
| `1 个用户` | 目前只有一个用户登录。 |
| `负载平均值：0.98, 2.12, 3.43` | 过去 1、5 和 15 分钟的系统负载平均值。 |

表 1：uptime 命令输出

您可能以前没有听说过负载平均值。要理解负载平均值，首先必须了解系统负载。

**什么是系统负载？**

简单来说，系统负载是 CPU 在给定时间内执行的工作量。

因此，计算机上运行的进程（或程序）越多，系统负载就越高，运行的进程越少，系统负载就越低。现在，既然您了解了系统负载是什么，那么理解负载平均值就很容易了。

**什么是负载平均值？**

负载平均值是在 1、5 和 15 分钟内计算的平均系统负载。

因此，您在`uptime`命令输出的末尾看到的三个数字分别是 1、5 和 15 分钟的负载平均值。例如，如果您的负载平均值为：

```
load average: 2.00, 4.00, 6.00
```

然后这三个数字分别代表以下内容：

+   `2.00 --+`：过去一分钟的负载平均值。

+   `4.00 --+`：过去五分钟的负载平均值。

+   `6.00 --+`：过去十五分钟的负载平均值。

从负载平均值的定义中，我们可以得出以下关键点：

1.  负载平均值为`0.0`表示系统处于空闲状态（什么也不做）。

1.  如果 1 分钟负载平均值高于`5`或`15`分钟的平均值，则这意味着您的系统负载正在增加。

1.  如果 1 分钟负载平均值低于`5`或`15`分钟的平均值，则这意味着您的系统负载正在减少。

例如，负载平均值为：

```
load average: 1.00, 3.00, 7.00
```

显示系统负载随时间减少。另一方面，负载平均值为：

```
load average: 5.00, 3.00, 2.00
```

表明系统负载随时间增加。作为实验，首先通过运行`uptime`命令记录负载平均值，然后打开您的网络浏览器并打开多个选项卡，然后重新运行`uptime`；您会看到负载平均值已经增加。之后关闭浏览器并再次运行`uptime`，您会看到负载平均值已经减少。

您可以运行`reboot`命令来重新启动系统：

```
elliot©ubuntu-linux:-$ reboot
```

您可以运行`pwd`命令来打印当前工作目录的名称：

```
elliot©ubuntu-linux:-$ pwd
/home/elliot
```

当前工作目录是用户在特定时间工作的目录。默认情况下，当您登录到 Linux 系统时，您的当前工作目录设置为您的主目录：

```
/home/your_username
```

**什么是目录？**

在 Linux 中，我们将文件夹称为目录。目录是包含其他文件的文件。

您可以运行`ls`命令来列出当前工作目录的内容：

```
elliot©ubuntu-linux:-$ ls
Desktop Documents Downloads Music Pictures Public Videos
```

如果您想更改密码，可以运行`passwd`命令：

```
elliot©ubuntu-linux:-$ passwd 
Changing password for elliot. 
(current) UNIX password:
Enter new UNIX password:
Retype new UNIX password:
passwd: password updated successfully
```

您可以使用`hostname`命令来显示系统的主机名：

```
elliot©ubuntu-linux:-$ hostname 
ubuntu-linux
```

您可以使用`free`命令来显示系统上的空闲和已使用内存量：

```
elliot©ubuntu-linux:-$ free
 total      used    free   shared   buff/cache  available 
Mem:    4039732   1838532  574864    71900      1626336    1848444
Swap:    969960         0  969960
```

默认情况下，`free`命令以千字节为单位显示输出，但只有外星人才能理解这个输出。

通过使用`-h`选项运行`free`命令，您可以获得对我们人类有意义的输出：

```
elliot©ubuntu-linux:-$ free -h
 total     used     free     shared     buff/cache     available
Mem:      3.9G     1.8G     516M        67M           1.6G          1.7G
Swap:     947M       OB     947M 
```

这样好多了，对吧？`-h`是`--human`的缩写，它以人类可读的格式显示输出。

您可能已经注意到，这是我们第一次使用选项运行命令。大多数 Linux 命令都有选项，您可以使用这些选项轻微更改它们的默认行为。

您还应该知道，命令选项要么以单破折号（`-`）开头，要么以双破折号（`--`）开头。如果您使用命令选项的缩写名称，则可以使用单破折号。另一方面，如果您使用命令选项的全名，则需要使用双破折号：

```
elliot©ubuntu-linux:-$ free --human
 total     used     free     shared     buff/cache     available
Mem:      3.9G     1.8G     516M        67M           1.6G          1.7G
Swap:     947M       OB     947M 
```

如您所见，`free`命令的前两次运行产生了相同的输出。唯一的区别是第一次，我们使用了缩写命令选项名称`-h`，因此我们使用了单破折号。而第二次，我们使用了完整的命令选项名称`--human`，因此我们使用了双破折号。

在使用命令选项的缩写名称与完整命令选项名称时，您可以自由选择。

您可以使用`df`命令来显示系统上可用的磁盘空间量：

```
elliot©ubuntu-linux:-$ df
Filesystem     1K-blocks     Used     Available     Use%      Mounted on
udev             1989608        0       1989608       0%            /dev
tmpfs             403976     1564        402412       1%            /run
/dev/sda1       20509264  6998972      12445436      36%           /
tmpfs            2019864    53844       1966020       3%        /dev/shm
tmpfs               5120        4          5116       1%       /run/lock
tmpfs            2019864        0       2019864       0%  /sys/fs/cgroup
/dev/loop0         91648    91648             0     100% /snap/core/6130
tmpfs             403972       28        403944       1%   /run/user/121
tmpfs             403972       48        403924       1%  /run/user/1000
```

同样，您可能希望使用`-h`选项以显示更好的格式：

```
elliot©ubuntu-linux:-$ df -h
Filesystem       Size      Used      Avail     Use%      Mounted on
udev             1.9G         0       1.9G       0%            /dev
tmpfs            395M      1.6M       393M       1%            /run
/dev/sda1         20G      6.7G        12G      36%            /
tmpfs            2.0G       57M       1.9G       3%        /dev/shm
tmpfs            5.0M      4.0K       5.0M       1%       /run/lock
tmpfs            2.0G         0       2.0G       0%  /sys/fs/cgroup
/dev/loop0        90M       90M          0     100% /snap/core/6130
tmpfs            395M       28K       395M       1%   /run/user/121
tmpfs            395M       48K       395M       1%  /run/user/1000
```

如果您无法理解输出中的所有内容，不要担心，因为我将在接下来的章节中详细解释一切。本章的整个想法是让您有所了解；我们稍后将深入研究。

`echo`命令是另一个非常有用的命令；它允许您在终端上打印一行文本。例如，如果您想在终端上显示`Cats are better than Dogs!`这一行，那么您可以运行：

```
elliot©ubuntu-linux:-$ echo Cats are better than Dogs! 
Cats are better than Dogs!
```

您可能会问自己，“这有什么用？”好吧，我向您保证，当您读完本书时，您会意识到`echo`命令的巨大好处。

你可以在终端上花费大量时间，输入命令。有时，您可能想要重新运行一个命令，但可能忘记了命令的名称或您使用的选项，或者您只是懒得不想再次输入。无论情况如何，`history`命令都不会让你失望。

让我们运行`history`命令，看看我们得到了什么：

```
elliot©ubuntu-linux:-$ history
1 date
2 blabla
3 cal
4 cal 2022
5 cal feb 1993
6 clear
7 lscpu
8 uptime
9 reboot
10 pwd
11 ls
12 passwd
13 hostname
14 free
15 free -h
16 free --human
17 df
18 df -h
19 echo Cats are better than Dogs!
20 history
```

正如预期的那样，`history`命令按时间顺序显示了我们迄今为止运行的所有命令。在我的历史列表中，`lscpu`命令是第`7`个，所以如果我想重新运行`lspcu`，我只需要运行`!7`：

```
elliot©ubuntu-linux:-$ !7 
lscpu
Architecture:         x86_64
CPU op-mode(s):       32-bit, 64-bit
Byte Order:           Little Endian 
CPU(s):               1
On-line CPU(s) list:  0
Thread(s) per core:   1
Core(s) per socket:   1
Socket(s):            1
NUMA node(s):         1
Vendor ID:            GenuineIntel
CPU family:           6
Model:                61
Model name:           Intel(R) Core(TM) i5-5300U CPU @ 2.30GHz
Stepping:             4
CPU MHz:              2294.678
BogoMIPS:             4589.35
Hypervisor vendor:    KVM
Virtualization type:  full
Lid cache:            32K
L1i cache:            32K
12 cache:             256K
13 cache:             3072K 
NUMA node0 CPU(s):    0
Flags:                fpu vme de pse tsc msr pae mce cx8 apic sep mtrr
```

**向上和向下箭头键**

您可以在命令行历史记录上上下滚动。每次按*向上箭头*键，您就可以在命令历史记录中向上滚动一行。

您还可以使用*向下箭头*键来反向滚动。

您可以使用`uname`命令来显示系统的内核信息。当您运行`uname`命令而没有任何选项时，它只会打印内核名称：

```
elliot©ubuntu-linux:-$ uname 
Linux
```

您可以使用`-v`选项打印当前内核版本信息：

```
elliot©ubuntu-linux:-$ uname -v
#33-Ubuntu SMP Wed Apr 29 14:32:27 UTC 2020
```

您还可以使用`-r`选项打印当前内核发布信息：

```
elliot©ubuntu-linux:-$ uname -r 
5.4.0-29-generic
```

您还可以使用`-a`选项一次打印当前内核的所有信息：

```
elliot©ubuntu-linux:-$ uname -a
Linux ubuntu-linux 5.4.0-29-generic #33-Ubuntu SMP
Wed Apr 29 14:32:27 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
```

您还可以运行`lsb_release -a`命令来显示您当前运行的 Ubuntu 版本：

```
elliot©ubuntu-linux:-$ lsb_release -a 
No LSB modules are available.
Distributor ID: Ubuntu 
Description: Ubuntu 20.04 LTS 
Release: 20.04
Codename: focal
```

最后，您将在本章学习的最后一个命令是`exit`命令，它终止当前的终端会话：

```
elliot©ubuntu-linux:-$ exit
```

**一个酷炫的事实**

您现在可能已经观察到，Linux 命令名称基本上与它们的功能相似。例如，`pwd`命令字面上代表**打印工作目录**，`ls`代表**列表**，`lscpu`代表**列出 CPU**，等等。这个事实使得记住 Linux 命令变得更容易。

恭喜！您已经完成了第一章。现在是您的第一个知识检查练习的时间。

# 知识检查

对于以下练习，打开您的终端并尝试解决以下任务：

1.  显示 2023 年的整个日历。

1.  以人类可读的格式显示系统的内存信息。

1.  显示您的主目录的内容。

1.  更改当前用户密码。

1.  在您的终端上打印出“Mr. Robot 是一部很棒的电视节目！”

## 正确还是错误

1.  `DATE`命令显示当前日期和时间。

1.  重新启动您的 Linux 系统，只需运行`restart`命令。

1.  运行`free -h`和`free --human`命令之间没有区别。

1.  如果您的平均负载值递增，系统负载随时间增加。

```
load average: 2.12, 3.09, 4.03
```

1.  如果您的平均负载值是递减的，系统负载随时间减少。

```
load average: 0.30, 1.09, 2.03
```


攀爬树

在这一章中，你将攀爬一个非常特殊的树，那就是 Linux 文件系统。在这次攀爬的旅程中，你将学到：

+   Linux 文件系统层次结构。

+   根目录是什么？

+   绝对路径与相对路径。

+   如何浏览 Linux 文件系统。

# 第三章：Linux 文件系统

好了，你已经在树的根部准备好攀爬了。在 Linux 中，就像实际的树一样，文件系统的开始是从根目录开始的。你可以使用`cd`命令后跟一个斜杠来到达根目录：

```
elliot@ubuntu-linux:~$ cd /
```

`cd`命令是**Change Directory**的缩写，是 Linux 中最常用的命令之一。没有它，你无法在 Linux 中移动。就像你的四肢（手臂和腿），你能在没有四肢的情况下爬树吗？

斜杠字符代表根目录。现在为了确保你在根目录，你可以运行`pwd`：

```
elliot@ubuntu-linux:~$ pwd
/
```

果然，我们在 Linux 文件系统的根目录。每当你迷失方向不知道自己在哪里时，`pwd`就在这里拯救你。

好了，当我们还在根目录时，让我们看看里面有什么！运行`ls`命令来查看当前目录的内容：

```
elliot@ubuntu-linux:/$ ls
bin etc lib proc tmp var boot 
dev home opt root sbin usr
```

为了更好地查看内容，你可以使用`ls`命令的长列表`-l`选项：

```
elliot@ubuntu-linux:/$ ls -l
drwxr-xr-x   2 root root           4096 Dec 28 15:36 bin
drwxr-xr-x 125 root root          12288 Jan  1 11:01 etc
drwxr-xr-x  21 root root           4096 Dec 26 23:52 lib
dr-xr-xr-x 227 root root              0 Jan  3 02:33 proc
drwxrwxrwt  15 root root           4096 Jan  3 02:35 tmp
drwxr-xr-x  14 root root           4096 Jul 24 21:14 var
drwxr-xr-x   3 root root           4096 Dec 29 07:17 boot
drwxr-xr-x  18 root root           4000 Jan  3 02:33 dev
drwxr-xr-x   3 root root           4096 Dec 26 23:47 home
drwxr-xr-x   3 root root           4096 Dec 27 15:07 opt
drwx------   4 root root           4096 Dec 29 09:39 root
drwxr-xr-x   2 root root          12288 Dec 28 15:36 sbin
drwxr-xr-x  10 root root           4096 Jul 24 21:03 usr
```

这个输出给了你很多有价值的信息，我们将在接下来的章节中详细讨论。但现在，我们关注输出的第一列的第一个字母。看一下输出的第一列：

```
drwxr-xr-x 
drwxr-xr-x 
drwxr-xr-x 
drwxr-xr-x
.
.
.
.
```

你会看到第一个字母是`d`，这意味着文件是一个目录。第一个字母揭示了文件类型。输出的最后一列显示了文件名。

**其他文件！**

你的根目录下会有更多的文件。我只选择了最重要和最常见的文件，这些文件应该存在于每个 Linux 发行版中。所以当你看到比这本书中列出的文件更多时，不要惊慌。

现在每个目录都有特殊的用途，就像你在下表中看到的那样：

| / | 这是你的文件系统的根，一切都从这里开始。 |
| --- | --- |
| /etc | 这个目录包含系统配置文件。 |
| /home | 这是所有用户（除了 root 用户）的默认主目录。 |
| /root | 这是 root 用户的主目录。 |
| /dev | 这是你的设备，比如硬盘、USB 驱动器和光驱所在的地方。 |
| /opt | 这是你可以安装额外第三方软件的地方。 |
| /bin | 这是你的系统上必要的二进制文件（程序）所在的地方。 |
| /sbin | 这是系统管理员通常使用的系统二进制文件（程序）存储的地方。 |
| /tmp | 这是临时文件存储的地方；它们通常在系统重启后被删除，所以不要在这里存储重要文件！ |
| /var | 这个目录包含可能会改变大小的文件，比如邮件储存和日志文件。 |
| /boot | 所有系统启动所需的文件都存储在这里。 |
| /lib | 这个目录包含了/bin 和/sbin 目录中必要二进制文件所需的库。库基本上是一组可以被程序使用的预编译函数。 |
| /proc | 运行进程的信息存储在这里。 |
| /usr | 这个目录包含了用户之间共享的文件和实用程序。 |

表 2：解释 Linux 目录

你也可以运行`man hier`命令来阅读更多关于 Linux 文件系统层次结构的信息：

```
elliot@ubuntu-linux:/$ man hier
```

好了，现在让我们在 Linux 目录树上进一步攀爬。看一下*图 1*，你就会明白为什么我们选择了一棵树来描述 Linux 文件系统的结构。

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/lrn-linux-qk/img/79a50d42-f14e-4fe6-a412-62b50953310c.png)

图 1：Linux 目录树

前面的图只显示了很少的文件，绝不代表整个目录树，因为 Linux 文件系统实际上包含成千上万的文件。因此，您可以将前面的图像视为实际 Linux 目录树的子树。

# 浏览目录树

好吧，让我们再爬一点。例如，让我们进入`/home`目录，看看系统上有多少用户。您只需运行`cd /home`命令即可：

```
elliot@ubuntu-linux:~$ cd /home 
elliot@ubuntu-linux:/home$
```

注意您的命令提示符如何更改，因为它现在显示您在主目录。

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/lrn-linux-qk/img/53676501-79e3-4dbd-97d3-a5d42af9fc78.png)

图 2：您现在在/home

现在让我们运行`ls`来查看`/home`目录的内容：

```
elliot@ubuntu-linux:/home$ ls 
angela elliot
```

这是我系统上的两个用户（除了 root 用户）。`/root`是 root 用户的主目录。您可能只有一个用户在`/home`；您将在本书后面学习如何向系统添加其他用户。

**谁是 root 用户？**

root 用户是允许在系统上执行任何操作的超级用户。root 用户可以安装软件，添加用户，管理磁盘分区等。root 用户的主目录是`/root`，不要与`/`（文件系统的根）混淆。

如果您想要证明您当前在`/home`目录，可以运行`pwd`命令：

```
elliot@ubuntu-linux:/home$ pwd
/home
```

确实！我们在`/home`目录。现在让我们进入用户`elliot`的主目录。现在，信不信由你，有两种方法可以导航到`elliot`的主目录。您可以简单地运行`cd elliot`命令：

```
elliot@ubuntu-linux:/home$ cd elliot 
elliot@ubuntu-linux:~$ pwd
/home/elliot
```

或者您可以运行`cd /home/elliot`命令：

```
elliot@ubuntu-linux:/home$ cd /home/elliot 
elliot@ubuntu-linux:~$ pwd
/home/elliot
```

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/lrn-linux-qk/img/7254d293-d5d7-4f55-aa19-27333469d3d1.png)

图 3：现在您在/home/elliot

请注意，这两个命令都将我们带到了`elliot`的主目录。但是，运行`cd elliot`比运行`cd /home/elliot`要容易得多，当然。

嗯，想想吧，我们最初在`/home`目录，这就是为什么我们能够运行`cd elliot`进入`/home/elliot`的原因。

但是，在其他情况下，我们将被迫使用完整路径（绝对路径）`/home/elliot`来到达我们的目的地。为了演示，让我们首先切换到`/etc`目录：

```
elliot@ubuntu-linux:~$ cd /etc 
elliot@ubuntu-linux:/etc$ pwd
/etc
```

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/lrn-linux-qk/img/54cd2e8c-6b0e-42cb-b217-160e38baf5a4.png)

图 4：现在您在/etc

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/lrn-linux-qk/img/5392da2b-ffd7-48bb-82ce-cebea60f31c5.png)

图 5：您想要进入/home/elliot

*图 4*和*5*可以帮助您可视化。您现在在`/etc`，想要进入`/home/elliot`。为了进入`elliot`的主目录，我们不能再使用短路径（相对路径）运行`cd elliot`命令：

```
elliot@ubuntu-linux:/etc$ cd elliot
bash: cd: elliot: No such file or directory
```

如您所见，Shell 生气了并返回了一个错误`bash: cd: elliot: No such file or directory`。在这种情况下，我们必须使用完整路径（绝对路径）`/home/elliot`：

```
elliot@ubuntu-linux:/etc$ cd /home/elliot 
elliot@ubuntu-linux:~$ pwd
/home/elliot
```

如果您现在还没有注意到，我们一直在使用斜杠(`/`)作为目录分隔符。

**目录分隔符**

在 Linux 中，斜杠(`/`)是目录分隔符，有时也称为路径分隔符。在 Windows 中，情况正好相反，因为反斜杠(`\`)被用作目录分隔符。但是，要小心，因为前导斜杠是我们文件系统的根。例如，在`/home/elliot/Desktop`中，只有第二个和第三个斜杠是目录分隔符，但第一个斜杠代表文件系统的根。

意识到绝对路径和相对路径之间的区别是至关重要的。

**绝对路径与相对路径**

文件的绝对路径只是该文件的完整路径，并且始终以前导斜杠开头。例如，`/opt/- google/chrome`是绝对路径的一个例子。

另一方面，文件的相对路径从不以根目录开头，始终相对于当前工作目录。例如，如果您当前在`/var`，那么`log/boot.log`就是有效的相对路径。

作为一个经验法则，如果你想区分相对路径和绝对路径，看一下路径是否以根目录（斜杠）开头；如果是的话，你可以得出结论这是绝对路径，否则，这是相对路径。

下面的图表显示了相对路径`Desktop/hello.txt`，只有当你的当前工作目录是`/home/elliot`时才有效。

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/lrn-linux-qk/img/fb656147-eb70-42d1-b62e-030c994f0873.png)

图 6：这是一个相对路径

下面的图片显示了绝对路径`/home/elliot/Desktop`，无论你当前的工作目录是什么，它都会一直有效。

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/lrn-linux-qk/img/64478dee-c47a-46c2-b446-6f439ad8fda7.png)

图 7：这是一个绝对路径

现在让我们进入 Elliot 的`Desktop`目录看看他在那里有什么。我们将使用绝对路径：

```
elliot@ubuntu-linux:/$ cd /home/elliot/Desktop 
elliot@ubuntu-linux:~/Desktop$ pwd
/home/elliot/Desktop
```

我们接着运行`pwd`来确认我们确实在想要的目录中。现在让我们运行`ls`来查看 Elliot 的桌面上的内容：

```
elliot@ubuntu-linux:~/Desktop$ ls 
hello.txt
```

注意`hello.txt`文件在 Elliot 的桌面上，所以我们实际上可以在桌面上看到它。

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/lrn-linux-qk/img/f8f7032f-daed-4827-a8f0-7cc625997a36.png)

图 8：Elliot 的桌面

如你在上面的图片中所见，Elliot 的桌面上有一个名为`hello.txt`的文件。你可以使用`cat`命令来查看文本文件的内容：

```
elliot@ubuntu-linux:~/Desktop$ cat hello.txt 
Hello Friend!
Are you from fsociety?
```

如果你在桌面上打开`hello.txt`文件，你会看到相同的内容，当然，就像你在下面的截图中看到的那样。

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/lrn-linux-qk/img/e97ae210-c57e-4df2-8c73-c1305666bf74.png)

图 9：hello.txt 的内容

# 父目录和当前目录

在文件系统的每个目录下都有两个特殊的目录：

1.  当前工作目录用一个点(`.`)表示

1.  父目录用两个点(`..`)表示

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/lrn-linux-qk/img/525d4989-07bd-4e5a-96aa-8831c012a775.png)

图 10：可视化父目录和当前目录

通过几个例子很容易理解这两个目录。举个例子，让我们首先切换到`/home/elliot`，这样它就成为我们的当前工作目录：

```
elliot@ubuntu-linux:~/Desktop$ cd /home/elliot 
elliot@ubuntu-linux:~$ pwd
/home/elliot
```

现在运行`cd .`命令：

```
elliot@ubuntu-linux:~$ cd . 
elliot@ubuntu-linux:~$ pwd
/home/elliot
```

正如你所期望的，什么都没有发生！我们仍然在`/home/elliot`，这是因为一个点(`.`)代表当前工作目录。就好像你告诉某人，“去你所在的地方！”

现在运行`cd ..`命令：

```
elliot@ubuntu-linux:~$ cd .. 
elliot@ubuntu-linux:/home$ pwd
/home
```

我们回到了上一个目录！换句话说，我们切换到了`/home/elliot`的父目录，也就是`/home`。

让我们再运行一个`cd ..`：

```
elliot@ubuntu-linux:/home$ cd .. 
elliot@ubuntu-linux:/$ pwd
/
```

我们确实一直在回去，现在我们在我们的目录树的根目录。好吧，让我们再次运行`cd ..`：

```
elliot@ubuntu-linux:/$ cd .. 
elliot@ubuntu-linux:/$ pwd
/
```

嗯，我们还在同一个目录！我们的路径没有改变，这是因为我们已经在我们的目录树的根目录了，所以我们无法再回去了。因此，根目录(`/`)是唯一一个**父目录=当前目录**的目录，你可以通过查看*图 10*来进行可视化。

你也可以插入目录分隔符`cd ../..`一次性回到两个目录：

```
elliot@ubuntu-linux:~$ pwd
/home/elliot
elliot@ubuntu-linux:~$ cd ../.. 
elliot@ubuntu-linux:/$ pwd
/
```

你也可以运行`cd ../../..`来回到三个目录，依此类推。

# 快速移动

现在我将向你展示一些很酷的技巧，这些技巧将使你在浏览 Linux 目录树时更快更高效。

## 回到家！

让我们切换到`/var/log`目录：

```
elliot@ubuntu-linux:~$ cd /var/log 
elliot@ubuntu-linux:/var/log$ pwd
/var/log
```

你现在可以运行`cd ~`命令来进入你的家目录：

```
elliot@ubuntu-linux:/var/log$ cd ~ 
elliot@ubuntu-linux:~$ pwd
/home/elliot
```

哇！让我们再做一次，但这次，我们切换到用户`angela`。如果你不知道，这个字符叫做波浪号，应该位于键盘上数字*1*键的旁边：

```
elliot@ubuntu-linux:~$ whoami 
elliot
elliot@ubuntu-linux:~$ su angela 
Password:
angela@ubuntu-linux:/home/elliot$ whoami 
angela
```

注意这里我使用了两个新命令。`whoami`命令打印当前登录用户的名称。我还使用了切换用户`su`命令来切换到用户`angela`。你可以使用`su`命令来切换到系统上的任何用户；你只需要运行`su`，然后跟上用户名。

现在，作为用户`angela`，我将导航到`/var/log`目录：

```
angela@ubuntu-linux:/home/elliot$ cd /var/log 
angela@ubuntu-linux:/var/log$ pwd
/var/log
```

然后我运行`cd ~`命令：

```
angela@ubuntu-linux:/var/log$ cd ~ 
angela@ubuntu-linux:~$ pwd
/home/angela
```

哇！我在 Angela 的主目录。无论您当前的工作目录是什么，运行`cd ~`命令都会直接将您带回到您的主目录。

## 带我回去！

现在，如果`angela`想尽快返回到她以前的工作目录怎么办？

运行`cd -`命令是将`angela`快速返回到她以前的工作目录的最快方法：

```
angela@ubuntu-linux:~$ pwd
/home/angela
angela@ubuntu-linux:~$ cd -
/var/log
```

酷！`angela`回到了`/var/log`。所以每当您想返回到以前的工作目录时，只需运行`cd -`命令。

# 隐藏文件

在 Linux 文件系统的每个目录下都存在当前目录` .`和父目录` ..`。但是当我们运行`ls`命令时为什么看不到它们呢？

```
elliot@ubuntu-linux:~/Desktop$ pwd
/home/elliot/Desktop 
elliot@ubuntu-linux:~/Desktop$ ls 
hello.txt
elliot@ubuntu-linux:~/Desktop$ ls -l 
total 4
-rw-r--r-- 1 elliot elliot 37 Jan 19 14:20 hello.txt
```

如您所见，我甚至尝试运行`ls -l`，仍然看不到当前目录或父目录。

您需要使用`ls`命令的`-a`选项如下：

```
elliot@ubuntu-linux:~/Desktop$ ls -a
. .. hello.txt
```

万岁！现在您可以看到所有文件了。`-a`选项显示所有文件，包括隐藏文件，当然您也可以使用完整的选项名称`--all`，它将做同样的事情：

```
elliot@ubuntu-linux:~/Desktop$ ls --all
. .. hello.txt
```

原来，任何以` .`（点）开头的文件名都是隐藏的。

隐藏的文件名以` .`开头

任何以点开头的文件名都是隐藏的。这就是为什么当前目录和父目录是隐藏的。

为了进一步演示，进入您的用户主目录并运行`ls`命令：

```
angela@ubuntu-linux:~$ ls 
Music
```

现在运行`ls -a`命令：

```
angela@ubuntu-linux:~$ ls -a
. .. .bash_logout .bashrc Music .profile
```

您现在可以看到主目录中的隐藏文件！请注意，所有隐藏的文件名都以点开头。

# 传递命令参数

到目前为止，我们只在当前工作目录上运行了`ls`命令。但是，您可以列出任何目录的内容，而无需更改到该目录。例如，如果您当前的工作目录是`/home/elliot`：

```
elliot@ubuntu-linux:~$ pwd
/home/elliot
```

您可以通过运行`ls -a /home/angela`命令列出`/home/angela`中的所有文件：

```
elliot@ubuntu-linux:~$ ls -a /home/angela
. .. .bash_history .bash_logout .bashrc Music .profile 
elliot@ubuntu-linux:~$ pwd
/home/elliot 
elliot@ubuntu
```

我能够在`/home/elliot`的同时列出`/home/angela`的内容。这是可能的，因为`ls`命令接受任何文件作为参数。

**什么是参数？**

参数，也称为命令行参数，只是作为输入提供给命令的任何文件名或数据。![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/lrn-linux-qk/img/1605fa32-1bc3-4a70-a403-d093fab29d97.png)

图 11：Linux 命令结构

您可以在前面的图像中看到 Linux 命令的一般结构。

在 Linux 术语中，当谈论命令选项和参数时，我们使用动词**传递**。为了使用正确的 Linux 术语，例如，在前面的图像中，我们说：“我们将`/home/angela`目录作为`ls`命令的参数传递。”

您会经常发现 Linux 用户非常热衷于使用正确的术语。此外，使用正确的术语可以帮助您通过工作面试并获得梦想的工作！

请注意在前面的图中，我们使用了复数名词*选项*和*参数*。这是因为一些命令可以接受多个选项和参数。

例如，我们可以通过运行`ls -a -l /home/angela`命令来列出`/home/angela`中的所有文件的长列表：

```
elliot@ubuntu-linux:~$ ls -a -l /home/angela 
total 28
drwxr-xr-x 3 angela angela 4096 Jan 20 13:43 .
drwxr-xr-x 9  root    root 4096 Jan 17 04:37 ..
-rw------- 1 angela angela   90 Jan 20 13:43 .bash_history
-rw-r--r-- 1 angela angela  220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 angela angela 3771 Apr  4  2018 .bashrc
drwxrwxr-x 2 angela angela 4096 Jan 19 19:42 Music
-rw-r--r-- 1 angela angela  807 Apr  4  2018 .profile
```

所以现在您可以看到`/home/angela`中所有文件的长列表，包括隐藏文件，还要注意这里选项的顺序无关紧要，所以如果您运行`ls -l -a /home/angela`命令：

```
elliot@ubuntu-linux:~$ ls -l -a /home/angela 
total 28
drwxr-xr-x 3 angela angela 4096 Jan 20 13:43 .
drwxr-xr-x 9   root   root 4096 Jan 17 04:37 ..
-rw------- 1 angela angela   90 Jan 20 13:43 .bash_history
-rw-r--r-- 1 angela angela  220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 angela angela 3771 Apr  4  2018 .bashrc
drwxrwxr-x 2 angela angela 4096 Jan 19 19:42 Music
-rw-r--r-- 1 angela angela  807 Apr  4  2018 .profile
```

您将得到相同的结果。这是传递两个命令选项的示例，那么传递两个参数呢？好吧，您可以通过将`/home/elliot`作为第二个参数，同时对`/home/angela`和`/home/elliot`中的所有文件进行长列表，而无需更改到它：

```
elliot@ubuntu-linux:~$ ls -l -a /home/angela /home/elliot
/home/angela:

total 28
drwxr-xr-x 3 angela angela 4096 Jan 20 13:43 .
drwxr-xr-x 9 root   root   4096 Jan 17 04:37 ..
-rw------- 1 angela angela   90 Jan 20 13:43 .bash_history
-rw-r--r-- 1 angela angela  220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 angela angela 3771 Apr  4  2018 .bashrc
drwxrwxr-x 2 angela angela 4096 Jan 19 19:42  Music
-rw-r--r-- 1 angela angela  807 Apr  4  2018 .profile

/home/elliot:
total 28
drwxr-xr-x 3 elliot elliot 4096 Jan 20 16:26 .
drwxr-xr-x 9 root   root   4096 Jan 17 04:37 ..
-rw------- 1 elliot elliot   90 Jan 20 13:43 .bash_history
-rw-r--r-- 1 elliot elliot  220 Dec 26 23:47 .bash_logout
-rw-r--r-- 1 elliot elliot 3771 Dec 26 23:47 .bashrc
drwxr-xr-x 2 elliot elliot 4096 Jan 19 14:20  Desktop
-rw-r--r-- 1 elliot elliot  807 Apr 4   2018 .profile
```

所以现在，您可以同时看到`/home/elliot`和`/home/angela`目录的内容。

# touch 命令

让我们再次对`/home/elliot`中的所有文件进行长列表，讨论一些非常重要的事情：

```
elliot@ubuntu-linux:~$ ls -a -l /home/elliot 
total 28
drwxr-xr-x 3 elliot elliot 4096 Jan 20 16:26 .
drwxr-xr-x 9 root   root   4096 Jan 17 04:37 ..
-rw------- 1 elliot elliot   90 Jan 20 13:43 .bash_history
-rw-r--r-- 1 elliot elliot  220 Dec 26 23:47 .bash_logout
-rw-r--r-- 1 elliot elliot 3771 Dec 26 23:47 .bashrc
drwxr-xr-x 2 elliot elliot 4096 Jan 19 14:20  Desktop
-rw-r--r-- 1 elliot elliot  807 Apr  4  2018 .profile
```

关注输出的最后两列：

| `Jan 20 16:26` | `.` |
| --- | --- |
| `Jan 17 04:37` | `..` |
| `Jan 20 13:43` | `.bash_history` |
| `Dec 26 23:47` | `.bash_logout` |
| `Dec 26 23:47` | `.bashrc` |
| `Jan 19 14:20` | `Desktop` |
| `Apr 4 2018` | `.profile` |

`Table 3`：`ls -a -l /home/elliot` 的最后两列

你已经知道输出的最后一列（`Table 3` 的第二列）显示文件名，但是前一列（`Table 3` 的第一列）显示的所有这些日期是什么呢？

`Table 3` 的第一列中的日期表示每个文件的最后修改时间，即文件被修改（编辑）的最后时间。

你可以使用 `touch` 命令更改文件的修改时间。

为了演示，让我们首先获取 `elliot` 的 `Desktop` 目录的修改时间，你可以通过运行 `ls -l -d /home/elliot/Desktop` 命令来实现：

```
elliot@ubuntu-linux:~$ ls -l -d /home/elliot/Desktop
drwxr-xr-x 2 elliot elliot 4096 Jan 19 14:20 /home/elliot/Desktop
```

请注意我们使用了 `-d` 选项，因此它对目录 `/home/elliot/Desktop` 进行了长列表，而不是列出目录的内容。

最后修改时间显示为：`Jan 19 14:20`。

现在如果你运行 `touch /home/elliot/Desktop` 命令：

```
elliot@ubuntu-linux:~$ touch /home/elliot/Desktop 
elliot@ubuntu-linux:~$ ls -l -d /home/elliot/Desktop
drwxr-xr-x 2 elliot elliot 4096 Jan 20 19:42 /home/elliot/Desktop 
elliot@ubuntu-linux:~$ date
Sun Jan 20 19:42:08 CST 2020
```

你会看到目录 `/home/elliot/Desktop` 的最后修改时间现在已经更改为 `Jan 20 19:42`，这反映了当前时间。

当然，你会在你的系统上得到不同的结果，因为你不会和我同时运行命令。

好的，很好，现在我们明白了 `touch` 命令可以用来更新文件的修改时间。它还能做其他事情吗？嗯，让我们看看。

如果我们尝试更新一个不存在的文件的修改时间会发生什么？只有尝试才能知道。请注意，用户 `elliot` 的主目录中只有一个可见（非隐藏）文件，那就是 `Desktop` 目录：

```
elliot@ubuntu-linux:~$ pwd
/home/elliot
elliot@ubuntu-linux:~$ ls -l 
total 4
drwxr-xr-x 2 elliot elliot 4096 Jan 20 19:42 Desktop
```

看看当用户 `elliot` 运行 `touch blabla` 命令时会发生什么：

```
elliot@ubuntu-linux:~$ touch blabla 
elliot@ubuntu-linux:~$ ls -l
total 4
-rw-r--r-- 1 elliot elliot    0 Jan 20 20:00 blabla
drwxr-xr-x 2 elliot elliot 4096 Jan 20 19:42 Desktop
```

它创建了一个名为 `blabla` 的空文件。

你可以使用 `touch` 命令做两件事：

1.  你可以更新现有文件的最后修改和访问时间。

1.  你可以创建新的空文件。

`touch` 命令只能创建常规文件；它不能创建目录。另外，请注意它更新修改和访问时间，那么有什么区别呢？

+   修改时间 > 文件最后一次被更改或修改的时间。

+   访问时间 > 文件最后一次被访问（读取）的时间。

默认情况下，`touch` 命令会同时更改文件的修改和访问时间。我在 `elliot` 的主目录中创建了三个文件：`file1`、`file2` 和 `file3`：

```
elliot@ubuntu-linux:~$ ls -l 
total 8
drwxr-xr-x 6 elliot elliot 4096 Jan 25 22:13 Desktop
drwxr-xr-x 3 elliot elliot 4096 Jan 25 22:18 dir1
-rw-r--r-- 1 elliot elliot    0 Feb 29  2004 file1
-rw-r--r-- 1 elliot elliot    0 Apr 11  2010 file2
-rw-r--r-- 1 elliot elliot    0 Oct  3  1998 file3
```

现在只更改 `file1` 的修改时间。我们向 `touch` 命令传递 `-m` 选项：

```
elliot@ubuntu-linux:~$ touch -m file1 
elliot@ubuntu-linux:~$ ls -l
total 8
drwxr-xr-x 6 elliot elliot 4096 Jan 25 22:13 Desktop
drwxr-xr-x 3 elliot elliot 4096 Jan 25 22:18 dir1
-rw-r--r-- 1 elliot elliot    0 Jan 25 23:08 file1
-rw-r--r-- 1 elliot elliot    0 Apr 11  2010 file2
-rw-r--r-- 1 elliot elliot    0 Oct  3  1998 file3 
elliot@ubuntu-linux:~$
```

正如你所看到的，`file1` 的修改时间现在已经改变。我答应过只更改修改时间，对吧？如果你向 `ls` 命令传递 `-u` 选项和 `-l` 选项，你将得到最后访问时间而不是修改时间：

```
elliot@ubuntu-linux:~$ ls -l 
total 8
drwxr-xr-x 6 elliot elliot 4096 Jan 25 22:13 Desktop
drwxr-xr-x 3 elliot elliot 4096 Jan 25 22:18 dir1
-rw-r--r-- 1 elliot elliot 0    Jan 25 23:08 file1
-rw-r--r-- 1 elliot elliot 0    Apr 11  2010 file2
-rw-r--r-- 1 elliot elliot 0    Oct 3   1998 file3
elliot@ubuntu-linux:~$ ls -l -u 
total 8 
drwxr-xr-x 6 elliot elliot 4096 Jan 25 22:13 Desktop
drwxr-xr-x 3 elliot elliot 4096 Jan 25 22:18 dir1
-rw-r--r-- 1 elliot elliot 0    Feb 29 2004  file1
-rw-r--r-- 1 elliot elliot 0    Apr 11 2010  file2
-rw-r--r-- 1 elliot elliot 0    Oct 3  1998  file3
```

正如你所看到的，`file1` 的最后修改时间已经改变为 `Jan 25 23:08`，但访问时间保持不变：`Feb 29 2004`。这一次，让我们只改变 `file2` 的访问时间。为此，我们向 `touch` 命令传递 `-a` 选项：

```
elliot@ubuntu-linux:~$ touch -a file2 
elliot@ubuntu-linux:~$ ls -l
total 8
drwxr-xr-x 6 elliot elliot 4096 Jan 25 22:13 Desktop
drwxr-xr-x 3 elliot elliot 4096 Jan 25 22:18 dir1
-rw-r--r-- 1 elliot elliot    0 Jan 25 23:08 file1
-rw-r--r-- 1 elliot elliot    0 Apr 11  2010 file2
-rw-r--r-- 1 elliot elliot    0 Oct  3  1998 file3 
elliot@ubuntu-linux:~$ ls -l -u
total 8
drwxr-xr-x 6 elliot elliot 4096 Jan 25 22:13 Desktop
drwxr-xr-x 3 elliot elliot 4096 Jan 25 22:18 dir1
-rw-r--r-- 1 elliot elliot   0  Feb 29  2004 file1
-rw-r--r-- 1 elliot elliot   0  Jan 25 23:20 file2
-rw-r--r-- 1 elliot elliot   0  Oct  3  1998 file3 
elliot@ubuntu-linux:~$
```

正如你所看到的，`file2` 的修改时间保持不变，但访问时间已更改为当前时间。现在要同时更改 `file3` 的修改和访问时间，你可以运行不带选项的 `touch` 命令：

```
elliot@ubuntu-linux:~$ ls -l file3
-rw-r--r-- 1 elliot elliot 0 Oct 3 1998 file3 
elliot@ubuntu-linux:~$ touch file3 
elliot@ubuntu-linux:~$ ls -l file3
-rw-r--r-- 1 elliot elliot 0 Jan 25 23:27 file3 
elliot@ubuntu-linux:~$ ls -l -u file3
-rw-r--r-- 1 elliot elliot 0 Jan 25 23:27 file3
```

太棒了！你还可以向 `ls` 命令传递 `-t` 选项，按修改时间排序列出文件，最新的排在前面：

```
elliot@ubuntu-linux:~$ ls -l -t 
total 8
-rw-r--r-- 1 elliot elliot    0 Jan 25 23:27 file3
-rw-r--r-- 1 elliot elliot    0 Jan 25 23:08 file1
drwxr-xr-x 3 elliot elliot 4096 Jan 25 22:18 dir1
drwxr-xr-x 6 elliot elliot 4096 Jan 25 22:13 Desktop
-rw-r--r-- 1 elliot elliot    0 Apr 11  2010 file2
```

你可以添加 `-u` 选项以按访问时间排序：

```
elliot@ubuntu-linux:~$ ls -l -t -u 
total 8
-rw-r--r-- 1 elliot elliot    0 Jan 25 23:27 file3
-rw-r--r-- 1 elliot elliot    0 Jan 25 23:20 file2
-rw-r--r-- 1 elliot elliot    0 Jan 25 23:20 file1
drwxr-xr-x 3 elliot elliot 4096 Jan 25 22:18 dir1
drwxr-xr-x 6 elliot elliot 4096 Jan 25 22:13 Desktop
```

你还可以传递 `-r` 选项来反向排序：

```
elliot@ubuntu-linux:~$ ls -l -t -r 
total 8
-rw-r--r-- 1 elliot elliot    0 Apr 11  2010 file2
drwxr-xr-x 6 elliot elliot 4096 Jan 25 22:13 Desktop
drwxr-xr-x 3 elliot elliot 4096 Jan 25 22:18 dir1
-rw-r--r-- 1 elliot elliot    0 Jan 25 23:08 file1
-rw-r--r-- 1 elliot elliot    0 Jan 25 23:27 file3
```

# 创建目录

在 Linux 中创建目录，我们使用 `mkdir` 命令，它是 **make directory** 的缩写。

在 `elliot` 的桌面上，通过运行 `mkdir games` 命令创建一个名为 `games` 的目录：

```
elliot@ubuntu-linux:~/Desktop$ mkdir games 
elliot@ubuntu-linux:~/Desktop$ ls -l 
total 8
drwxr-xr-x 2 elliot elliot 4096 Jan 20 20:20 games
-rw-r--r-- 1 elliot elliot 37 Jan 19 14:20 hello.txt 
elliot@ubuntu-linux:~/Desktop$
```

请注意，我的当前工作目录是 `/home/elliot/Destkop`；这就是为什么我能够使用相对路径的原因。

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/lrn-linux-qk/img/53b62972-d736-4a08-87ed-b880f540c414.jpg)

图 12：桌面上创建的 `games` 目录

您还可以同时创建多个目录。例如，您可以通过运行`mkdir Music Movies Books`命令在桌面上创建三个目录-`Music`，`Movies`和`Books`：

```
elliot@ubuntu-linux:~/Desktop$ mkdir Music Movies Books 
elliot@ubuntu-linux:~/Desktop$ ls -l
total 20
drwxr-xr-x 2 elliot elliot 4096 Jan 21 01:54 Books
drwxr-xr-x 2 elliot elliot 4096 Jan 20 20:20 games
-rw-r--r-- 1 elliot elliot   37 Jan 19 14:20 hello.txt
drwxr-xr-x 2 elliot elliot 4096 Jan 21 01:54 Movies
drwxr-xr-x 2 elliot elliot 4096 Jan 21 01:54 Music
```

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/lrn-linux-qk/img/ce2df5e4-c1ec-4ecd-afb5-0789d584b925.jpg)

图 13：在桌面上创建的目录

您还可以使用`-p`选项创建整个目录路径。例如，您可以通过运行`mkdir -p dir1/dir2/dir3`命令创建路径`/home/elliot/dir1/dir2/dir3`：

```
elliot@ubuntu-linux:~$ pwd
/home/elliot
elliot@ubuntu-linux:~$ mkdir -p dir1/dir2/dir3 
elliot@ubuntu-linux:~$ ls 
blabla Desktop dir1 
elliot@ubuntu-linux:~$ cd dir1 
elliot@ubuntu-linux:~/dir1$ ls 
dir2
elliot@ubuntu-linux:~/dir1$ cd dir2 
elliot@ubuntu-linux:~/dir1/dir2$ ls 
dir3
elliot@ubuntu-linux:~/dir1/dir2$ cd dir3 
elliot@ubuntu-linux:~/dir1/dir2/dir3$ pwd
/home/elliot/dir1/dir2/dir3 
elliot@ubuntu-linux:~/dir1/dir2/dir3$
```

它在`/home/elliot`目录中创建了`dir1`，然后在`dir1`中创建了`dir2`，最后在`dir2`中创建了`dir3`。

您可以使用递归的`-R`选项对`/home/elliot/dir1`进行递归列表，并查看`/home/elliot/dir1`下的所有文件，而无需更改每个目录：

```
elliot@ubuntu-linux:~$ ls -R dir1 
dir1:
dir2

dir1/dir2:
dir3

dir1/dir2/dir3: 
elliot@ubuntu-linux:~$
```

正如你所看到的，它列出了`/home/elliot/dir1`下的所有文件。它甚至显示了层次结构。

您还可以通过将它们包含在一对大括号中，并且每个子目录之间用逗号分隔，来创建具有多个子目录的新目录，就像以下示例中一样：

```
elliot@ubuntu-linux:~/dir1/dir2/dir3$ mkdir -p dir4/{dir5,dir6,dir7} 
elliot@ubuntu-linux:~/dir1/dir2/dir3$ ls -R dir4
dir4:
dir5 dir6 dir7 

dir4/dir5: 

dir4/dir6:

dir4/dir7:
```

正如您所看到的，我们创建了`dir4`，并在其中创建了三个目录-`dir5`，`dir6`和`dir7`。

# 组合命令选项

您已经学会了许多可以与`ls`命令一起使用的不同选项。`表 4`总结了到目前为止我们使用过的所有选项。

| **ls 选项** | **作用** |
| --- | --- |
| `-l` | 文件的长格式和详细列表。 |
| `-a` | 列出隐藏文件。 |
| `-d` | 仅列出目录本身，而不是它们的内容。 |
| `-t` | 按修改时间对文件进行排序。 |
| `-u` | 与`-l`一起使用时，显示访问时间而不是修改时间。与`-lt`一起使用时，将按访问时间排序并显示访问时间。 |
| `-r` | 将列表顺序反转。 |
| `-R` | 递归列出子目录。 |

表 4：常用 ls 命令选项

您经常会希望同时使用两个或更多的命令选项。例如，`ls -a -l`通常用于对目录中的所有文件进行长列表。

此外，`ls -l -a -t -r`是一个非常受欢迎的组合，因为有时您可能希望按修改时间排序文件的列表（从最旧到最新）。因此，组合命令选项更有效，因此运行`ls -latr`命令：

```
elliot@ubuntu-linux:~$ ls -latr 
total 120
-rw-r--r--  1 elliot elliot       0    Apr 11  2010 file2
-rw-r--r--  1 elliot elliot     807    Dec 26 23:47 .profile
-rw-r--r--  1 elliot elliot    3771    Dec 26 23:47 .bashrc
drwxr-xr-x  9 root   root      4096    Jan 17 04:37 ..
-rw-r--r--  1 elliot elliot     220    Jan 20 17:23 .bash_logout
drwxr-xr-x  6 elliot elliot    4096    Jan 25 22:13 Desktop
-rw-r--r--  1 elliot elliot       0    Jan 25 23:08 file1
-rw-r--r--  1 elliot elliot       0    Jan 25 23:27 file3
drwxr-xr-x  3 elliot elliot    4096    Jan 25 23:52 dir1
-rw-------  1 elliot elliot    3152    Jan 26 00:01 .bash_history
drwxr-xr-x 17 elliot elliot    4096    Jan 30 23:32 .
```

将产生与运行`ls -l -a -t -r`命令相同的结果：

```
elliot@ubuntu-linux:~$ ls -l -a -t -r 
total 120
-rw-r--r--  1 elliot elliot    0 Apr 11  2010 file2
-rw-r--r--  1 elliot elliot  807 Dec 26 23:47 .profile
-rw-r--r--  1 elliot elliot 3771 Dec 26 23:47 .bashrc
drwxr-xr-x  9 root   root   4096 Jan 17 04:37 ..
-rw-r--r--  1 elliot elliot  220 Jan 20 17:23 .bash_logout
drwxr-xr-x  6 elliot elliot 4096 Jan 25 22:13 Desktop
-rw-r--r--  1 elliot elliot    0 Jan 25 23:08 file1
-rw-r--r--  1 elliot elliot    0 Jan 25 23:27 file3
drwxr-xr-x  3 elliot elliot 4096 Jan 25 23:52 dir1
-rw-------  1 elliot elliot 3152 Jan 26 00:01 .bash_history
drwxr-xr-x 17 elliot elliot 4096 Jan 30 23:32 .
```

在本章结束之前，我想向您展示一个非常酷的技巧。首先，让我们创建一个名为`averylongdirectoryname`的目录：

```
elliot@ubuntu-linux:~$ mkdir averylongdirectoryname 
elliot@ubuntu-linux:~$ ls -ld averylongdirectoryname
drwxr-xr-x 2 elliot elliot 4096 Mar 2 12:57 averylongdirectoryname
```

**制表完成**是 Linux 命令行中最有用的功能之一。您可以使用此功能让 shell 自动完成（建议）命令名称和文件路径。为了演示，输入（不要运行）以下文本到您的终端：

```
elliot@ubuntu-linux:~$ cd ave
```

现在按下键盘上的*Tab*键，shell 将自动为您完成目录名称：

```
elliot@ubuntu-linux:~$ cd averylongdirectoryname/
```

相当酷！好的，这就是本章的结束，现在是时候进行可爱的知识检查了。

# 知识检查

对于以下练习，打开终端并尝试解决以下任务：

1.  对`/var/log`中的所有文件进行长列表。

1.  显示文件`/etc/hostname`的内容。

1.  在`/home/elliot`中创建三个文件-`file1`，`file2`和`file3`。

1.  列出`elliot`的主目录中的所有文件（包括隐藏文件）。

1.  在`/home/elliot`中创建一个名为`fsociety`的目录。

## 真或假

1.  `/home/root`是 root 用户的主目录。

1.  `dir1/dir2/dir3`是绝对路径的一个例子。

1.  `/home/elliot/Desktop`是绝对路径的一个例子。

1.  `touch -m file1`将更新`file1`的访问时间。

1.  `mkdir dir1 dir2 dir3`将创建三个目录-`dir1`，`dir2`和`dir3`。


见编辑器

首先，让我告诉您一些可能会让您感到惊讶的事情。Linux 实现了所谓的“一切皆文件”的哲学。这意味着在您的 Linux 系统上，一切都由文件表示。例如，您的硬盘由一个文件表示。运行的程序（进程）由一个文件表示。甚至您的外围设备，如键盘、鼠标和打印机，都由文件表示。

说到这一点，“一切皆文件”的哲学的一个直接结果是，Linux 管理员花费大量时间编辑和查看文件。因此，您经常会看到 Linux 管理员非常擅长使用文本编辑器。本章就是专门讲这个的。我希望您能够非常熟练地使用 Linux 中的各种文本编辑器。

有很多，我是说很多文本编辑器可以使用。但是，在本章中，我将介绍最受欢迎的 Linux 编辑器，这些编辑器可以完成工作。

# 第四章：图形编辑器 - gedit 和 kate

我们首先从那些最基本和简单的编辑器开始。这些是图形编辑器！如果您使用任何 Linux 发行版的**GNOME**版本，那么默认情况下会安装文本编辑器`gedit`。另一方面，如果您使用 Linux 的**KDE**版本，那么默认情况下会安装文本编辑器`kate`。

**桌面环境**

GNOME 和 KDE 是桌面环境的两个例子。每个桌面环境都实现了不同的图形用户界面，这是说您的桌面看起来会有所不同的一种花哨的方式！

无论如何，在图形编辑器上真的没有太多可以讨论的。它们非常直观和易于使用。例如，如果您想要使用`gedit`查看文本文件，那么您可以运行`gedit`命令，后面跟上任何文件名：

```
elliot@ubuntu-linux:~$ gedit /proc/cpuinfo
```

这将打开`gedit`图形编辑器，并显示您的 CPU 信息。

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/lrn-linux-qk/img/d37da084-50a9-4032-b1e9-a886707e6a80.png)

图 1：使用 gedit 打开/proc/cpuinfo

如果您没有`gedit`而是有`kate`，那么您可以运行：

```
elliot@ubuntu-linux:~$ kate /proc/cpuinfo
```

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/lrn-linux-qk/img/cc6c07d1-6c84-44da-b26f-986f3b6839c2.png)

图 2：使用 kate 打开/proc/cpuinfo

您还可以使用图形编辑器在系统上创建新文件。例如，如果您想在`/home/elliot`中创建一个名为`cats.txt`的文件，那么您可以运行`gedit /home/elliot/cats.txt`命令：

```
elliot@ubuntu-linux:~$ gedit /home/elliot/cats.txt
```

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/lrn-linux-qk/img/40a3c327-7211-46ab-b713-7cfcf87bc12b.png)

图 3：使用 gedit 创建 cats.txt

现在插入一行“I love cats!”然后保存并关闭文件。文件`cats.txt`现在存在于我的主目录中，我可以使用`cat`命令查看它：

```
elliot@ubuntu-linux:~$ pwd
/home/elliot
elliot@ubuntu-linux:~$ ls -l cats.txt
-rw-r--r-- 1 elliot elliot 13 Feb 2 14:54 cats.txt 
elliot@ubuntu-linux:~$ cat cats.txt
I love cats!
```

同样，您可以使用任何其他图形文本编辑器在系统上创建文件。

好了！关于图形文本编辑器的讨论就到此为止。让我们继续探索非图形文本编辑器的严肃世界。

# nano 编辑器

`nano`编辑器是一个非常流行且易于使用的命令行编辑器。您可以通过运行`nano`命令来打开`nano`编辑器：

```
elliot@ubuntu-linux:~$ nano
```

这将打开您的`nano`编辑器，您应该会看到以下截图中的屏幕：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/lrn-linux-qk/img/b9b1e0e2-b634-4d2d-8d74-a6df75c96d78.png)

图 4：在 nano 内部

现在添加以下截图中显示的六行：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/lrn-linux-qk/img/6167db42-a28c-44c4-afcf-6c032c0e9694.png)

图 5：添加这六行

看一下`nano`编辑器屏幕底部；您会看到很多快捷键：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/lrn-linux-qk/img/0345a1b9-485d-4917-a0a7-64666bf49078.png)

图 6：nano 快捷键

我在下表中列出了所有有用的 nano 快捷键：

| **nano 快捷方式** | **它的作用** |
| --- | --- |
| *Ctrl*+*O* | 保存当前文件（写出）。 |
| *Ctrl*+*K* | 剪切当前行并将其存储在缓冲区中。 |
| *Ctrl*+*U* | 粘贴存储在缓冲区中的行。 |
| *Ctrl*+*W* | 在文件中搜索字符串（单词）。 |
| *Ctrl*+*\* | 用另一个字符串替换文件中的字符串（单词）。 |
| *Ctrl*+*R* | 读取另一个文件。 |
| *Ctrl*+*G* | 查看如何使用 nano 的帮助信息。 |
| *Ctrl*+*V* | 转到下一页。 |
| *Ctrl*+*Y* | 转到上一页。 |
| *Ctrl*+*X* | 退出 nano 编辑器。 |

表 5：nano 快捷键

请注意，按下*Ctrl*+*O*快捷键是通过按下*Ctrl*，然后按字母*O*触发的。您不必按下*+*键或大写字母*O*。 

现在让我们使用快捷键*Ctrl*+*O*保存文件；它会要求您输入文件名，您可以输入`facts.txt`。

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/lrn-linux-qk/img/48bb5470-d558-429b-b1ef-8514afb5ac00.png)

图 7：保存文件

然后按*Enter*确认。现在让我们退出`nano`编辑器（使用*Ctrl*+*X*快捷键）来验证文件`facts.txt`是否已创建：

```
elliot@ubuntu-linux:~$ ls -l facts.txt
-rw-r--r-- 1 elliot elliot 98 Apr 30 15:17 facts.txt
```

现在让我们再次打开`facts.txt`来修复我们添加的错误事实！要用`nano`编辑器打开文件`facts.txt`，您可以运行`nano facts.txt`命令：

```
elliot@ubuntu-linux:~$ nano facts.txt
```

文件`facts.txt`中的第一行说“苹果是蓝色的。”我们肯定需要纠正这个错误的事实，所以让我们使用快捷键*Ctrl*+*\*将单词`blue`替换为`red`。

当您按下*Ctrl*+*\*时，它会要求您输入要替换的单词；您可以输入`blue`，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/lrn-linux-qk/img/f1f7099a-5a54-4f3a-aef0-2ca1e043e558.png)

图 8：要替换的单词

按*Enter*，然后它会要求您输入替换的单词。您可以输入`red`，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/lrn-linux-qk/img/0a1da2ab-e958-469b-ab96-965e7cc4d551.png)

图 9：替换单词

然后按*Enter*，它将遍历单词`blue`的每个实例，并询问您是否要替换它。幸运的是，我们只有一个`blue`的出现。

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/lrn-linux-qk/img/ebbefa8c-324b-45d1-af78-539a5a0aab9b.png)

图 10：用红色替换蓝色

按*Y*，嘭！单词`red`替换了`blue`。

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/lrn-linux-qk/img/9ee45d73-7f0e-4c74-9238-21cf16f8f38a.png)

图 11：红色替换蓝色

这里还有一个词需要改变。我们都同意地球不是平的，对吧？希望我们都同意！现在让我们像之前一样精确地用单词`round`替换`flat`，结果应该像下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/lrn-linux-qk/img/6a4e95ea-5677-4bce-8374-b43102783ab5.png)

图 12：用圆形替换平的

现在让我们保存并退出文件。因此我们使用*Ctrl*+*O*快捷键保存，然后使用*Ctrl*+*X*退出。

`nano`编辑器非常简单易用。熟能生巧，所以您使用得越多，它对您来说就会变得越容易。您可以练习`表 5`中的所有快捷键。

# vi 编辑器

`nano`编辑器通常是初学者的首选编辑器。它是一个很棒的编辑器，但我们只能说它不是最高效的编辑器。`vi`编辑器是一个更高级的 Linux 编辑器，具有大量功能，并且是高级 Linux 用户中最受欢迎的编辑器。

让我们用`vi`编辑器打开`facts.txt`文件；为此，您运行`vi facts.txt`命令：

```
elliot@ubuntu-linux:~$ vi facts.txt
```

这将打开`vi`编辑器，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/lrn-linux-qk/img/7294c42b-a5b4-4086-bed9-adbf69da2e48.png)

图 13：在 vi 中打开 facts.txt 文件

与`nano`编辑器不同，`vi`编辑器以两种不同的模式工作：

1.  `插入`模式

1.  `命令`模式

`插入`模式使您能够在文件中插入文本。另一方面，`命令`模式允许您执行复制、粘贴和删除文本等操作。`命令`模式还允许您搜索和替换文本以及许多其他操作。

## 插入模式

默认情况下，您首次打开`vi`编辑器时会进入`命令`模式，而在`命令`模式下无法插入文本。要插入文本，您需要切换到`插入`模式。有几种方法可以切换到`插入`模式；`表 6`列出了所有方法。

| **键** | **功能** |
| --- | --- |
| `i` | 在当前光标位置之前插入文本。 |
| `I` | 在当前行的开头插入文本。 |
| `a` | 在当前光标位置之后添加文本。 |
| `A` | 在当前行的末尾添加文本。 |
| o | 在当前行下方创建一个新行。 |
| O | 在当前行上方创建一个新行。 |

表 6：vi 插入模式

您可以使用箭头键在`vi`编辑器中导航，就像在`nano`编辑器中一样。现在导航到文件`facts.txt`的最后一行，然后按字母`o`切换到`insert`模式。现在您可以添加一行“Linux is cool!”

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/lrn-linux-qk/img/4afe6d76-edfc-4fc1-9231-a4834c36d9ed.png)

图 14：在 vi 中添加一行

在`insert`模式下，您可以添加任意多的文本。要切换回`command`模式，您需要按下*Esc*键。

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/lrn-linux-qk/img/0542f500-99c6-4570-b5a1-e191424aa661.png)

图 15：在插入模式和命令模式之间切换

上述屏幕截图说明了如何在`command`模式和`insert`模式之间来回切换。

## 命令模式

除了添加文本之外，您想做的任何事情都可以从`command`模式中实现。您可以在`vi`编辑器中使用大量命令。您可能会认为我在开玩笑，但是有很多关于`vi`编辑器的书籍和课程。但是，“表 7”将让您熟悉`vi`编辑器，并列出了您可以使用的最流行的命令。

| **vi 命令** | **它的作用** |
| --- | --- |
| yy | 复制（yank）当前行。 |
| 3yy | 复制（yank）三行（从当前行开始）。 |
| yw | 复制（yank）光标位置开始的一个单词。 |
| 2yw | 复制（yank）光标位置开始的两个单词。 |
| p | 在当前光标位置之后粘贴。 |
| P | 在当前光标位置之前粘贴。 |
| dd | 剪切（删除）当前行。 |
| 4dd | 剪切（删除）四行（从当前行开始）。 |
| dw | 剪切（删除）光标位置开始的一个单词。 |
| x | 删除光标位置的字符。 |
| u | 撤销上一次更改。 |
| U | 撤销对该行的所有更改。 |
| /red | 在文件中搜索单词`red`。 |
| :%s/bad/good | 用`good`替换`bad`。 |
| 设置行号 | 显示行号。 |
| :set nonumber | 隐藏行号。 |
| :7 | 转到第 7 行。 |
| G | 跳转到文件末尾。 |
| gg | 跳转到文件开头。 |

表 7：vi 命令

正如您所看到的，“表 7”有很多命令，所以我不会逐一介绍所有的命令；这留给您作为练习。但是，我将讨论一些命令，以帮助您开始使用`vi`编辑器。

让我们首先显示行号，因为这将使我们的生活更加轻松！要做到这一点，您可以运行`:set` number 命令，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/lrn-linux-qk/img/69d9a7ee-ea10-4a4c-b8e1-3b06d013cc33.png)

图 16：显示行号

现在让我们复制第 4 行。您需要确保光标在第 4 行上；您可以通过运行`:4`命令来实现这一点，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/lrn-linux-qk/img/aacc68b4-97a6-4ff0-b832-abfa34dfb557.png)

图 17：转到第 4 行

现在按下序列`yy`，它会复制整行。让我们在文件末尾粘贴三次。因此，导航到最后一行，然后按* p *三次，它会将复制的行粘贴三次，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/lrn-linux-qk/img/407eff49-cf61-4f82-a73f-ccc8df800a97.png)

图 18：在 vi 中复制和粘贴

好了！让我们将单词`cool`替换为`awesome`，因为我们都知道 Linux 不仅仅是酷；它是令人敬畏的！要做到这一点，您可以运行`:%s/cool/awesome`命令，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/lrn-linux-qk/img/9bd62bc6-483e-495b-99ec-7693d3c6c39d.png)

图 19：用 awesome 替换 cool

让我们也将单词`Roses`替换为`Cherries`，因为我们都知道并不是所有的玫瑰都是红色的。要做到这一点，运行`:%s/Roses/Cherries`命令，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/lrn-linux-qk/img/b92a6c73-a27c-4037-8d8b-caeeeca9ae83.png)

图 20：用 Cherries 替换 Roses

它甚至会告诉您发生了多少次替换。

**酷提示**

您应该知道`:%s/old/new`只会替换所有行中单词`old`的第一次出现。要替换所有行中单词`old`的所有出现，应使用全局选项`:%s/old/new/g`

要理解并理解上面的提示，向您的`facts.txt`文件添加行“蓝蓝蓝蓝”，并尝试使用`:%s/blue/purple`命令将单词`blue`替换为`purple`。您会看到它只会替换第一个`blue`的出现。要使其替换所有`blue`的出现，您必须使用全局选项

`:%s/blue/purple/g`。

## 保存并退出 vi

最终，当您完成在`vi`中查看或编辑文件时，您会想要退出`vi`编辑器。您可以使用多种方法退出`vi`编辑器，`表 8`列出了所有方法。

| **vi 命令** | **它的作用** |
| --- | --- |
| `:w` | 保存文件但不退出`vi`。 |
| `:wq` | 保存文件并退出`vi`。 |
| `ZZ` | 保存文件并退出`vi`（与`:wq`相同，只是更快！）。 |
| `:x` | 保存文件并退出`vi`（与`:wq`或`ZZ`相同）。 |
| `:q` | 不保存退出`vi`。 |
| `:q!` | 强制退出`vi`而不保存。 |

表 8：保存和退出 vi

所以让我们保存文件并退出`vi`编辑器。当然，您可以使用以下任何命令：

1.  `:wq`

1.  `:x`

1.  `ZZ`

它们都实现了相同的结果，即保存并退出`vi`。

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/lrn-linux-qk/img/4e4023a5-29b5-4fb4-b352-7265fabbd287.png)

图 21：保存并退出 vi

如果您成功退出了`vi`编辑器，我要祝贺您，因为您是精英中的一员。互联网上有数百个关于一些人打开`vi`编辑器后从未能退出的模因和漫画！

# 文件查看命令

在某些情况下，您可能只想查看文件而不编辑它。虽然您仍然可以使用文本编辑器如`nano`或`vi`来查看文件，但在 Linux 中有更快的查看文件的方法。

## cat 命令

`cat`命令是 Linux 中最受欢迎和经常使用的命令之一。`cat`（**concatenate**的缩写）命令将文件连接并打印到标准输出（终端）。

要查看我们创建的`facts.txt`文件，可以运行`cat facts.txt`命令：

```
elliot@ubuntu-linux:~$ cat facts.txt 
Apples are red.
Grapes are green.
Bananas are yellow.
Cherries are red.
Sky is high.
Earth is round.
Linux is awesome!
Cherries are red.
Cherries are red.
Cherries are red.
```

现在，您可以在终端舒适地查看`facts.txt`文件的内容，而无需打开任何文本编辑器。

`cat`命令不仅可以查看文件，还可以连接（放在一起）文件。为了演示，使用您喜欢的文本编辑器创建以下三个文件：

1.  `file1.txt`（插入行“第一个文件”）

1.  `file2.txt`（插入行“第二个文件”）

1.  `file3.txt`（插入行“第三个文件”）

现在让我们使用`cat`命令查看这三个文件的每一个：

```
elliot@ubuntu-linux:~$ cat file1.txt 
First File
elliot@ubuntu-linux:~$ cat file2.txt 
Second File
elliot@ubuntu-linux:~$ cat file3.txt 
Third File
```

现在让我们通过运行`cat file1.txt file2.txt`命令来连接`file1.txt`和`file2.txt`：

```
elliot@ubuntu-linux:~$ cat file1.txt file2.txt 
First File
Second File
```

我们还可以连接所有三个文件：

```
elliot@ubuntu-linux:~$ cat file1.txt file2.txt file3.txt 
First File
Second File 
Third File
```

请记住，顺序很重要；例如，运行`cat file2.txt file1.txt`命令：

```
elliot@ubuntu-linux:~$ cat file2.txt file1.txt 
Second File
First File
```

这将在`file1.txt`之前输出`file2.txt`的文本。

## tac 命令

`tac`命令是`cat`命令的孪生兄弟。它基本上是反向编写的`cat`，它做的事情与`cat`命令相同，但是以相反的方式！

例如，如果您想以相反的顺序查看`facts.txt`文件，可以运行`tac facts.txt`命令：

```
elliot@ubuntu-linux:~$ tac facts.txt 
Cherries are red.
Cherries are red.
Cherries are red.
Linux is awesome!
Earth is round.
Sky is high.
Cherries are red.
Bananas are yellow.
Grapes are green.
Apples are red.
```

`tac`命令也可以像`cat`命令一样连接文件。

## more 命令

使用`cat`命令查看文件是一个不错的选择，当文件很小，且没有很多行文本需要显示时。如果要查看一个大文件，最好使用`more`命令。`more`命令一次显示文件的一页内容；它基本上是一个分页程序。

让我们用`more`命令查看文件`/etc/services`的内容：

```
elliot@ubuntu-linux:~$ more /etc/services 
# Network services, Internet style
# Note that it is presently the policy of IANA to assign a single well-known 
# port number for both TCP and UDP; hence, officially ports have two entries 
# even if the protocol doesn't support UDP operations.

tcpmux 1/tcp # TCP port service multiplexer 
systat 11/tcp users
netstat 15/tcp ftp 21/tcp
fsp 21/udp fspd
ssh 22/tcp # SSH Remote Login Protocol 
telnet 23/tcp
smtp 25/tcp mail 
whois 43/tcp nicname
tacacs 49/tcp # Login Host Protocol (TACACS) 
tacacs 49/udp
--More--(7%)
```

它会显示`/etc/services`文件的第一页，并在底部显示一个百分比值，显示你已经浏览了文件的进度。你可以使用以下键在`more`中导航：

+   *Enter* > 向下滚动一行。

+   空格键 > 前往下一页。

+   *b* > 返回上一页。

+   *q* > 退出。

`/etc/services`文件存储了许多可以在 Linux 上运行的服务（应用程序）的信息。

## less 命令

`less`命令是`more`命令的改进版本。是的，你读对了；less 比 more 更好！事实上，著名的成语*less is more*源于`less`比`more`提供更多的想法。

`less`命令是另一个分页程序，就像`more`一样；它允许你一次查看一个页面的文本文件。`less`的优点是你可以使用上/下箭头键在文件中导航。此外，`less`比`more`更快。

你可以通过运行以下命令使用`less`查看`/etc/services`文件：

```
elliot@ubuntu-linux:~$ less /etc/services
```

你也可以在`less`中使用`more`导航键。

## 正面还是反面？

正如其名称所示，`head`命令显示文件的前几行。默认情况下，它显示文件的前十行。例如，我们知道`facts.txt`中有十行，因此运行`head facts.txt`命令将显示所有文件内容：

```
elliot@ubuntu-linux:~$ head facts.txt 
Apples are red.
Grapes are green.
Bananas are yellow.
Cherries are red.
Sky is high.
Earth is round.
Linux is awesome!
Cherries are red.
Cherries are red.
Cherries are red.
```

你也可以传递`-n`选项来指定你希望查看的行数。例如，要显示`facts.txt`的前三行，你可以运行`head -n 3 facts.txt`命令：

```
elliot@ubuntu-linux:~$ head -n 3 facts.txt 
Apples are red.
Grapes are green.
Bananas are yellow.
```

另一方面，`tail`命令显示文件的最后几行。默认情况下，它显示最后十行。你也可以使用`-n`选项来指定你希望查看的行数。例如，要显示`facts.txt`中的最后两行，你可以运行`tail -n 2 facts.txt`命令：

```
elliot@ubuntu-linux:~$ tail -n 2 facts.txt 
Cherries are red.
Cherries are red.
```

你知道现在是几点吗？是时候进行一些知识检查了。

# 知识检查

对于以下练习，打开你的终端并尝试解决以下任务：

1.  只查看文件`facts.txt`的前两行。

1.  只查看文件`facts.txt`的最后一行。

1.  以相反的顺序显示文件`facts.txt`的内容。

1.  使用`vi`编辑器打开文件`facts.txt`。

1.  退出`vi`编辑器，认为自己是精英之一。
