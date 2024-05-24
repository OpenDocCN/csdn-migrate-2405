# 使用 Linux 工作（一）

> 原文：[`zh.annas-archive.org/md5/1386224BACCE1A8CB295702FCFA899BB`](https://zh.annas-archive.org/md5/1386224BACCE1A8CB295702FCFA899BB)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

我们的使命是帮助 Linux 用户摆脱低效的习惯。

在本书中，您将学到：

+   最好的终端之一是什么（小提示：您需要拆分屏幕功能）。

+   剪贴板管理器如何记住您复制的内容，省去您的麻烦。

+   如何使用自人类出现以来最伟大/最聪明的控制台编辑器。是的，它就是 Vim。我们将深入探讨它的用途。

+   Zsh 及其强大的`oh-my-zsh`框架，提供超过 200 个插件，供开发人员和追求高效率的人使用。

+   详细介绍了终端命令：如何查找和替换文本、文本的部分、文本的小部分甚至非文本内容。

+   如何使用管道和子 shell 创建自定义命令，自动化日常任务。

+   以及更多内容。本书适用于所有新接触 Linux 环境的程序员。

但我们是谁呢？

**Petru**：臭名昭著的程序员，拥有多年的 Linux 经验。他打字飞快，喜欢甜甜圈，脑子里装满了 Linux！在发现 Linux 并每周切换到不同的发行版，用各种极客的东西烦恼女朋友之后，现在他用极客的话题和科技界的最新消息烦恼每个人。

他把时间花在编写前端、后端、数据库、Linux 服务器和云上。

**Bogdan**：逃兵！他尝试了 20 多个 Linux 和 Unix 发行版，包括 Plan 9、HP-UX 和所有的 BSD。但在女友因为他花太多时间在电脑前而离开他之后，他...转向了 Mac。

现在，他把时间花在教授超过一万名学生的 8 个在线课程上。

我们在这里帮助您提高终端的工作效率！

如果您不知道如何使用`sed`，如果您不太习惯使用`pipe`命令，如果您使用的是默认终端，如果您仍在使用 BASH，那么本书适合您。

立即阅读，提高您的终端工作效率！

# 本书涵盖内容

第一章，*介绍*，介绍了改变用户体验所需的最基本工具。

第二章，*高效的 Shell - 重新定义您的工作方式*，重新定义您的工作方式。颜色、编辑器和自定义配置，都根据您的需求进行定制。

第三章，*Vim 功夫*，解释了终端战士的方式。这包括配置和高级用法，涵盖了大多数需求。

第四章，*CLI - 隐藏的秘方*，展示了从好到优秀的不同方式，并将命令行功能提升到新的领域。

第五章，*开发者的宝藏*，解释了如何通过这些简单的技巧提高生产力。正是这些小事情产生了巨大的差异。

第六章，*终端艺术*，让您对有限资源所能创造的创意感到惊叹。这是乐趣开始的地方。

# 您需要为本书做好以下准备

理想情况下，您可以准备一个全新的 Ubuntu 操作系统，并在阅读时进行示例。请记住，[`github.com/petruisfan/linux-for-developers`](https://github.com/petruisfan/linux-for-developers)上有一个 git 仓库可用。

请继续克隆本地项目，以便您可以使用项目的示例文件。

# 本书适合谁阅读

本书适用于已经具备一定基础知识的 Linux 用户，他们希望提高自己的技能，在命令行环境中变得更加高效。本书适用于希望学习大师们使用的技巧和窍门，而不必经历在广阔的开源工具和技术海洋中进行的所有试错。本书适用于希望在终端提示符下感到自如，并渴望从那里完成绝大多数任务的用户。

# 约定

在本书中，您将找到一些区分不同信息类型的文本样式。以下是一些样式的示例及其含义的解释。

文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 用户名显示如下："打开终端并输入`sudo apt install zsh`来安装`zsh`，如图所示。"

代码块设置如下：

```
case ${CMD} in
    publicip)
        print_public_ip
        ;;
    ip)
        IFACE=$(getarg iface $@)
        print_ip $IFACE
        ;;
    *)
        echo "invalid command"
esac
```

任何命令行输入或输出都以以下方式编写：

```
sh -c "$(curl -fsSL https://raw.githubusercontent.com/robbyrussell/oh-my-zsh/master/tools/install.sh)"

```

**新术语**和**重要单词**以粗体显示。您在屏幕上看到的单词，例如菜单或对话框中的单词，会以这种方式出现在文本中："转到 shell 并启用**在当前目录中打开新标签页**。"

### 注意

警告或重要提示会以这种方式出现在一个框中。

### 提示

技巧和窍门会以这种方式出现。

# 读者反馈

我们非常欢迎读者的反馈。请告诉我们您对本书的看法，喜欢或不喜欢的地方。读者的反馈对我们很重要，因为它帮助我们开发出您真正能够充分利用的标题。

要向我们发送一般反馈，请简单地发送电子邮件至`<feedback@packtpub.com>`，并在主题中提及书籍的标题。

如果您在某个专题上有专业知识，并且有兴趣撰写或为一本书做贡献，请参阅我们的作者指南，网址为[www.packtpub.com/authors](http://www.packtpub.com/authors)。

# 客户支持

现在您是 Packt 图书的自豪拥有者，我们有很多东西可以帮助您充分利用您的购买。

## 勘误

尽管我们已经尽一切努力确保内容的准确性，但错误是难免的。如果您在我们的书籍中发现错误，比如文本或代码中的错误，我们将非常感激您向我们报告。通过这样做，您可以帮助其他读者避免沮丧，并帮助我们改进本书的后续版本。如果您发现任何勘误，请访问[`www.packtpub.com/submit-errata`](http://www.packtpub.com/submit-errata)，选择您的书籍，点击**勘误提交表**链接，并输入您的勘误详情。一旦您的勘误被验证，您的提交将被接受，并将勘误上传到我们的网站或添加到该书籍的勘误列表中的勘误部分。

要查看先前提交的勘误，请访问[`www.packtpub.com/books/content/support`](https://www.packtpub.com/books/content/support)，并在搜索框中输入书名。所需信息将出现在**勘误**部分下面。

## 盗版

互联网上的盗版行为是所有媒体都面临的持续问题。在 Packt，我们非常重视保护我们的版权和许可。如果您在互联网上发现我们作品的任何形式的非法副本，请立即向我们提供位置地址或网站名称，以便我们采取补救措施。

请通过`<copyright@packtpub.com>`与我们联系，并附上涉嫌盗版材料的链接。

我们感谢您在保护我们的作者和我们提供有价值内容的能力方面的帮助。

## 问题

如果您对本书的任何方面有问题，可以通过`<questions@packtpub.com>`与我们联系，我们将尽力解决问题。


# 第一章：介绍

这本书分为多个部分。在第一部分中，我们将探索一个新的终端，并向你展示如何安装和配置它。在第二部分中，我们将集中讨论配置你的 shell，添加插件，理解正则表达式，并使用管道和子 shell。然后，所有内容将汇集成一个 shell 脚本课程。在第三部分中，我们将使用 Vim，我们推荐的编辑器。我们将涵盖从配置它到学习键盘快捷键，安装插件，甚至将其用作密码管理器的所有内容。所以让我们开始吧。

在接下来的章节中，我们将学习以下主题：

+   了解 Terminator 的工作原理

+   使用 Guake 进行快速命令或长时间运行的任务

+   使用 ClipIt 复制粘贴文本

因此，我们将从一个终端开始，之后一切都会变得疯狂！当涉及到在终端上长时间工作时，我们的选择是使用 Terminator，因为它具有快速和简单的分屏功能。然后，我们将专注于 Guake，这是一个非常快速且无论你在哪里都可以打开的终端。最后，你将了解 Clipit 的工作原理，并有效地使用其复制和粘贴功能。

# 你准备好了吗？

我们将深入探讨 Linux 环境，为你提供提高生产力的技巧和窍门，让你更熟悉命令行，并自动化你的任务。

这本书基于 Ubuntu Linux 16.04 版本，这是最新的长期支持版本。我们选择 Ubuntu 是因为它是最常见的 Linux 发行版，使用起来非常简单，有很多图形工具，并且你可以找到一个庞大的在线社区来回答你的所有问题。Ubuntu 也是最受支持的 Linux 发行版。这意味着那些创建软件的公司，尤其是图形软件，并为 Linux 提供这些软件的公司，通常会从 Ubuntu 开始。

这使我们更容易使用 Skype、Slack 或 Visual Studio Code 等工具。尽管本书基于 Ubuntu，但大多数命令与 Ubuntu 无关，因此你可以轻松地使用其他发行版并应用相同的教训。本书的很大一部分甚至适用于 Mac，因为我们可以在 Mac 上安装相同的工具-bash、zsh、vim 在 Linux 和 Mac 上的工作方式相同-并且随着 Windows 10 的发布，bash 支持已经内置，因此可以轻松安装和使用 zsh 和 vim 等工具。在 Windows 10 之前，有一些工具，如 cygwin，可以让你在 Windows 环境中使用 Linux 命令行。

我们建议你在一个开放的终端中阅读和实践，这样你可以执行命令并检查结果。在开始之前，你需要从我们的 GitHub 存储库下载所有源文件（位于此处：[`github.com/petruisfan/linux-for-developers`](https://github.com/petruisfan/linux-for-developers)）。

！[你准备好了吗？]（img/image_01_001.jpg）

# 终结者-终极终端

为了提高工作效率，你首先需要一个好的终端。在整本书中，我们将主要使用命令行，这意味着我们将主要使用的软件是终端。我们推荐一个很棒的终端是**Terminator**，可以从软件中心安装。

让我们转到启动器，点击软件中心图标。打开后，点击搜索输入框，写入“terminator”，如下图所示。它可能会是结果列表中的第一个。点击**安装**。

！[终结者-终极终端]（img/image_01_002.jpg）

安装终结者后，将其图标拖到启动器上是一个好主意。为此，你只需按下 Windows 键打开 dash，写入`terminator`，然后将其图标拖放到启动器上：

！[终结者-终极终端]（img/image_01_003.jpg）

好了，现在让我们点击图标开始。你可以最大化窗口以获得更多的操作空间。

## 首选项菜单

这是一个自定义终端，可以在字体样式和其他工具方面找到一些惊喜。您现在看到的是默认设置。让我们进入首选项菜单，看看我们可以更新什么。首先，让我们隐藏标题栏，因为它并没有给我们太多信息，而且尽可能拥有尽可能多的屏幕空间（以及尽可能少的干扰）总是一个好主意。

现在让我们看一下其他一些首选项：

1.  让我们改变字体。我们将使它比通常的大一点，以便易于阅读。让我们选择 Monospace 16，如下面的截图所示：![首选项菜单](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_01_004.jpg)

1.  我们还希望有良好的对比度，以便能够轻松区分字母。为此，我们将选择黑色背景白色字体的主题。![首选项菜单](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_01_005.jpg)

1.  启用无限滚动也是个好主意，因为您不希望终端输出在`500`行后被截断。很多时候，您只想滚动并查看以前的输出。此外，在滚动时，如果有很多文本，您可能不希望被带回页面底部，因此取消选中**输出时滚动**选项。![首选项菜单](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_01_006.jpg)

看！这是我们新配置的终端。现在是时候检查一下我们可以用这个**新的**终端做什么了。接下来是*特点*部分！

## 特点

现在是时候看一下 Terminator 的一些有用功能及其键盘快捷键了。这是正常的 Terminator 界面的样子：

![特点](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_01_010.jpg)

现在让我们来玩一下：

+   分割屏幕：*Ctrl* + *Shift* + *O*进行水平分割：![特点](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_01_011.jpg)

+   *Ctrl* + *Shift* + *E*进行垂直分割：![特点](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_01_012.jpg)

这可能是 Terminator 最酷的功能，也是我们将最常使用的功能，因为它非常有助于查看多个窗格并轻松在它们之间切换。您可以任意次数地分割屏幕，以任何组合方式。

调整屏幕大小：*Ctrl* + *Shift* + *箭头*或拖放：

![特点](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_01_013.jpg)

+   使用*Ctrl* + *Shift* + *箭头*轻松在窗口之间移动。

+   使用*Ctrl* + *Shift* + *W*或*Ctrl* + *D*关闭屏幕。

+   使用*Ctrl* + *Shift* + *T*创建选项卡。当您没有更多的空间来分割屏幕时使用：![特点](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_01_014.jpg)

+   文本缩放：*Ctrl* *+* *+*和*Ctrl* *+* *-* - 在您需要演示或有视力不佳的人时非常有用：![特点](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_01_015.jpg)

能够将屏幕分割以便将终端排列成网格，并能够使用键盘快捷键分割、切换和调整窗格是 Terminator 的最大优势。许多人没有意识到的一个大的生产力杀手是在鼠标和键盘之间切换。虽然大多数人更喜欢使用鼠标，但我们建议尽可能多地使用键盘，并学习您最常用的计算机程序的键盘快捷键。

提高生产力最终意味着有更多的时间专注于真正重要的事情，而不是浪费时间苦苦使用计算机。

再见终端！欢迎 Terminator！

# Guake - 不是 Quake！

Terminator 在各种任务中表现良好，尤其是在处理多个项目的长时间会话时。然而，有时候您需要快速访问终端以便运行命令、检查状态或在前台长时间运行任务，而不需要打开太多选项卡。在这种情况下，Guake 非常出色。它是一个方便易用的终端，您可以通过按下*F12*在任何工作区的现有窗口之上打开它。

我们将使用一个简单的命令行来安装它。如下所示，打开终端并输入`sudo apt install guake`：

![Guake - 不是 Quake！](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_01_016.jpg)

### 注意

`apt` 是 Ubuntu 在 16.04 版本中推出的新软件包管理器，旨在成为 `apt-get` 命令的更易于使用的版本，并增加了一些额外的视觉效果。

现在 Guake 已安装完成，我们将转到 dash 并打开它。只需按下 *F12* 即可。一旦运行，您可以在屏幕右上方看到通知。它应该是这个样子的：

![Guake – 不是 Quake！](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_01_017.jpg)

就像使用 Terminator 一样，我们将检查其首选项。首先，转到 shell 并启用**在当前目录中打开新标签页**：

![Guake – 不是 Quake！](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_01_018.jpg)

我相信您可以猜到这是做什么的。然后，滚动并插入一个非常大的数字，比如 99,999。还要确保**滚动** | **在输出时**未选中：

![Guake – 不是 Quake！](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_01_019.jpg)

同样，我们将默认字体更改为 `Monospace 16`，将**光标闪烁模式**设置为关闭，并点击**关闭**：

![Guake – 不是 Quake！](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_01_020.jpg)

我们可以通过按下 *F11* 来全屏使用 Guake，也可以通过拖动边缘来调整其大小。如果您愿意，可以尝试调整默认设置，看看哪种最适合您。

Guake 在 Ubuntu 重新启动时不会自动启动，所以我们需要将其添加到启动应用程序中。要做到这一点，再次打开 dash，输入启动应用程序并点击添加。在所有三个字段中输入 Guake，然后点击添加并关闭。

它之所以如此方便，是因为您可以随时在当前窗口上方打开它，快速输入命令，然后稍后再次打开它以检查命令的状态。

### 提示

实际上，我们还使其稍微透明，这样当它打开在我们有一些命令的网页上时，我们仍然可以阅读页面上的内容并在阅读时输入命令，而无需切换窗口。这是另一个很棒的提高生产力的技巧！

# ClipIt – 最好的复制粘贴工具

我们相信，人类最伟大的发明之一就是复制粘贴。从某个随机位置复制一段文本并粘贴到另一个不那么随机的位置，这是一个巨大的时间节省器！如果计算机没有这个功能，人类仍然会远远落后！想象一下，每次都要输入每个小命令、每个 URL、每个代码块！这将是一种巨大的时间浪费！因此，作为一个如此重要的功能，复制粘贴应该有自己的工具来管理您复制的所有重要文本。这些类型的工具被称为剪贴板管理器。每个操作系统都有很多选择，Ubuntu 上有一个很好的免费工具叫做 `clipIt`。打开终端，输入 `sudo apt install clipit` 进行安装。

![ClipIt – 最好的复制粘贴工具](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_01_021.jpg)

在 Guake 中运行 `ClipIt` 是一个很好的场景。默认情况下，`ClipIt` 占用一个终端窗口，但是通过 Guake 的帮助，我们可以将其隐藏起来！

![ClipIt – 最好的复制粘贴工具](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_01_022.jpg)

该工具会自动添加到启动应用程序中，所以下次重启时会自动启动。

要调用 `ClipIt`，按下 *Ctrl* + *Alt* + *H* 或点击菜单栏中的剪贴板图标。

![ClipIt – 最好的复制粘贴工具](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_01_023.jpg)

它第一次启动时会警告您它以纯文本形式存储数据，因此如果其他用户使用您的帐户，使用它可能不安全。目前，它只包含最新的剪贴板元素。

让我们快速举个例子来说明它的用法。

我们使用 `cat` 命令查看 `.profile` 文件的内容。假设我们想要复制一些文本行并在另一个终端中运行它们，终端看起来像这样：

![ClipIt – 最好的复制粘贴工具](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_01_024.jpg)

例如，我们可能想要更新 PATH 变量，然后源化 `.bashrc` 文件并再次更新 PATH 变量。而不是再次从文件中复制内容，我们只需按下 *Ctrl* + *Alt* + *H*，然后从剪贴板历史中选择要粘贴的内容：

![ClipIt – 最好的复制粘贴工具](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_01_025.jpg)

这只是一个非常基本的例子。当您在电脑上长时间工作并且需要粘贴一些您几个小时前从网站上复制的内容时，`ClipIt`非常有用。它默认的历史记录大小为 50 个项目，并且会在浮动窗口中显示最后 10 个项目。您可以在设置中增加这些限制：

![ClipIt - 最好的复制粘贴工具](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_01_026.jpg)

使用`ClipIt`，您可以无限次复制和粘贴，而不会丢失任何数据。它就像是您剪贴板的时光机！


# 第二章：高效的 Shell-重新发明你的工作方式

在本章中，我们将从简短介绍 Vim 开始，然后查看最基本的命令，以帮助您开始进行基本的 CRUD（创建、读取、更新、删除）操作。然后，我们将升级 shell 解释器为 zsh，并使用强大的`oh-my-zsh`框架赋予其超能力。我们将介绍一些基本的正则表达式，例如使用 grep 搜索文本。然后，我们将释放 Unix 管道的力量，并使用子 shell 运行嵌入命令。本章的后半部分将帮助我们了解如何通过展示一些更高级的 shell 脚本技术来提高生产力并自动化我们的许多日常工作。

在本章中，我们将涵盖以下内容：

+   使用 Vim 工作

+   使用`oh-my-zsh`框架管理 zsh

+   使用管道和子 shell 编写和运行超强大的一行命令

+   探索 shell 脚本库

我们将专注于编辑文件。为此，我们需要选择一个文件编辑器。有很多选择，但考虑到最快的编辑文件的方式当然是不离开终端。我们推荐使用 Vim。Vim 是一个很棒的编辑器！它有很多配置选项，有一个庞大的社区，产生了很多插件和漂亮的主题。它还具有高级文本编辑功能，使其超级可配置和超级快速。

所以，让我们继续。打开终端并输入`sudo apt install vim`以安装 Vim：

![高效的 Shell-重新发明你的工作方式](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_02_001.jpg)

Vim 以其奇特的键盘控制而闻名，很多人因此而避免使用 Vim。但是一旦掌握了基础知识，它就非常容易使用。

让我们不带参数地启动`vim`：

![高效的 Shell-重新发明你的工作方式](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_02_002.jpg)

这是默认屏幕；您可以在第二行看到版本。

+   要开始编辑文本，请按下*Insert*键；这将带我们进入插入模式，我们可以开始输入。我们可以在屏幕底部看到我们处于插入模式：![高效的 Shell-重新发明你的工作方式](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_02_003.jpg)

+   再次按下*Insert*键进入替换模式并覆盖文本。

+   按下*Esc*键退出插入或替换模式。

+   输入*yy*复制一行。

+   输入*p*粘贴该行。

+   输入*dd*剪切该行。

+   输入*:w*保存任何更改。可选择指定文件名：![高效的 Shell-重新发明你的工作方式](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_02_004.jpg)

+   要保存正在编辑的文本文件，请输入`vim.txt`

+   输入`:q`退出 Vim

让我们再次打开文件并进行一些小的更改：

+   `:wq`：写入并同时退出

+   `:q!`：不保存退出

现在你已经熟悉了这些命令，我们可以直接从命令行进行基本文件编辑。这是任何人在使用 Vim 时需要了解的最基本的知识，我们将在接下来的章节中使用这些知识。

我们还将有一个关于 Vim 的整个章节，我们将更详细地介绍如何在最酷的终端编辑器中提高生产力！

# Oh-my-zsh-你的终端从未如此好用！

Bash 可能是最常用的 shell。它具有许多功能和强大的脚本能力，但在用户交互方面，`zsh`更好。它的大部分功能来自于强大的`oh-my-zsh`框架。在本节中，我们将安装`zsh`。

让我们从`oh-my-zsh`框架开始，我们将看一些基本的配置选项：

+   打开终端并输入`sudo apt install zsh`以安装`zsh`，如下图所示：![Oh-my-zsh-你的终端从未如此好用！](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_02_005.jpg)

安装完毕后，转到此链接[`github.com/robbyrussell/oh-my-zsh`](https://github.com/robbyrussell/oh-my-zsh)，按照安装`oh-my-zsh`框架的说明进行操作。安装过程是一个使用`curl`或`wget`的一行命令。让我们依次使用这两个命令进行安装：

**通过 curl：**

```
sh -c "$(curl -fsSL https://raw.githubusercontent.com/robbyrussell/oh-my-zsh/master/tools/install.sh)"

```

**通过 wget：**

```
sh -c "$(wget https://raw.githubusercontent.com/robbyrussell/oh-my-zsh/master/tools/install.sh -O -)"

```

你会看到命令给出一个错误，说`git`没有安装，所以我们也需要安装它。以下命令用于安装 git：

```
sudo apt install git

```

![Oh-my-zsh – 你的终端从未如此美好！](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_02_006.jpg)

注意在 Ubuntu 中安装软件是多么容易。这也是一个很大的生产力提升；我们可能需要的每个常见软件包都已经预打包在远程软件仓库中，我们只需要一个命令就可以将新软件添加到我们的计算机中。

现在我们已经安装了`git`，让我们再次运行命令。我们可以看到这次它成功运行，并且将我们带到了新的 shell 中。`Oh-my-zsh`还将默认 shell 更改为`zsh`。

安装完成后，首先要做的是选择一个主题。运行以下命令查看所有可用的主题：

```
ls ~/.oh-my-zsh/themes

```

![Oh-my-zsh – 你的终端从未如此美好！](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_02_007.jpg)

### 注意

你还可以去`git`仓库查看主题，以及它们的截图。我们将使用*candy*主题，因为它在提示符中有很多有用的信息：*用户名*、*主机名*、*时间*、*文件夹*和*git*分支/*git*状态。

时间非常有用，例如，如果你想知道一个命令执行了多长时间，而你没有使用*time*工具来测量命令的总运行时间。然后，你可以查看提示符，看到命令开始时的时间和提示符，以知道命令何时完成，从而可以计算总时间。

要更改主题，打开`~/.zshrc`并修改`ZSH_THEME`变量。保存文件并打开一个新的终端窗口。让我们初始化一个空的`git`目录，这样我们就可以看到提示符的样子。你可以看到我们在主分支上：

![Oh-my-zsh – 你的终端从未如此美好！](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_02_008.jpg)

让我们创建一个文件，比如`readme.md`。提示符中的`*`表示目录不干净。我们可以用`git status`命令来验证这一点：

![Oh-my-zsh – 你的终端从未如此美好！](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_02_009.jpg)

你可以看到它是如何被验证的。在我们清理了目录之后，`*`就消失了。如果我们切换分支，提示符会显示我们在新分支上。

让我们快速创建一个演示。在你的终端上运行以下命令：

```
git branch test
git checkout test
```

![Oh-my-zsh – 你的终端从未如此美好！](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_02_010.jpg)

现在你可以在提示符中看到分支名称，并且还有一些其他很酷的功能可以让你去探索：

+   **命令补全**：开始输入，例如，ip，然后按下*Tab*。我们可以看到所有以 IP 开头的命令，我们可以再次按下*Tab*来浏览不同的选项。你可以使用箭头键进行导航，按下*Enter*选择所需的命令：![Oh-my-zsh – 你的终端从未如此美好！](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_02_011.jpg)

+   **参数补全**：例如输入`ls -`然后按下*Tab*，我们可以在这里看到所有选项和每个选项的简短描述。再次按下*Tab*开始浏览它们，按下*Enter*进行选择。![Oh-my-zsh – 你的终端从未如此美好！](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_02_012.jpg)

+   **历史导航**：点击向上箭头键在历史记录中搜索，通过光标前面写的字符串进行过滤。例如，如果我输入`vim`并按向上箭头键，我可以看到我历史记录中所有使用 Vim 打开的文件。

+   **历史搜索**：按下*Ctrl* + *R*开始输入，再次按下*Ctrl* + *R*搜索相同的出现在历史中的命令。例如*~*，然后按下*Ctrl* + *R*来查看所有包含*~*的命令。

+   **导航**：在这里按下*Ctrl* + 左/右箭头可以跳到一个单词，*Ctrl* + *W*可以删除一个单词，或者*Ctrl* + *U*可以删除整行。

+   **cd 补全不区分大小写**：例如，`cd doc`会扩展为`cd Documents`。

+   **cd directory completion**: 如果您懒惰并且只想在路径中指定几个关键字母，我们也可以这样做。例如，`cd /us/sh/zs` + *Tab*将扩展为`cd /usr/share/zsh`。

+   **Kill completion:** 只需输入`kill`，然后按下*Tab*键，您将看到一个要杀死的`pids`列表。从那里，您可以选择要杀死的进程。

+   **chown completion**: 输入`chown`并按下 tab 键，您将看到一个要更改所有者的用户列表。同样适用于组。

+   **Argument expansion**: 输入`ls *`并按下*Tab*键。您会看到`*`扩展到当前目录中的所有文件和文件夹。要获取子集，请输入`ls Do*`并按下*Tab*键。它只会扩展到文档和下载。

+   **Adds lots of aliases:** 只需输入 alias 即可查看完整列表。一些非常有用的别名是：

```
.. - go up one folder
… - go up two folders
- - cd o the last directory
ll - ls with -lh
```

![Oh-my-zsh – your terminal never felt this good before!](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_02_013.jpg)

要查看快捷方式列表，请运行`bindkey`命令。终端是您将花费大量时间的地方之一，因此精通我们的 shell 并尽可能高效地使用它非常重要。了解好的快捷方式和查看相关和简洁的信息，例如我们的提示符，可以使我们的工作更轻松。

# 基本正则表达式

*您有一个问题，并且想要使用正则表达式解决它吗？现在您有两个问题了！* 这只是互联网上许多正则表达式笑话之一。

在本节中，您将学习正则表达式的工作原理，因为我们将在接下来的章节中使用它们。我们为我们的游乐场准备了一个文件，如果您想在自己的计算机上尝试 grep 命令，可以从 GitHub 存储库中获取。

让我们首先打开我们的文本文件，这样我们就可以看到它的内容，然后分割屏幕，这样我们就可以同时看到文件和命令。

首先，最简单且可能最常见的正则表达式是查找单个单词。

为此，我们将使用`grep "joe" file.txt`命令：

![基本正则表达式](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_02_014.jpg)

`joe`是我们要搜索的字符串，`file.txt`是我们执行搜索的文件。您可以看到 grep 打印了包含我们字符串的行，并且该单词以另一种颜色突出显示。这只会匹配单词的确切大小写（因此，如果我们使用小写的`j`，这个正则表达式将不再起作用）。要进行不区分大小写的搜索，`grep`有一个`-i`选项。这意味着 grep 将打印包含我们单词的行，即使单词的大小写不同，比如 JoE，JOE，joE 等等：

```
grep -i "joe" file.txt
```

![基本正则表达式](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_02_015.jpg)

如果我们不确定字符串中有哪些字符，我们可以使用`.*`来匹配任意数量的字符。例如，要查找以"word"开头并以"day"结尾的句子，我们将使用`grep "word.*day" file.txt`命令：

+   `.` - 匹配任何字符

+   `*` - 匹配前一个字符多次

在这里，您可以看到它匹配了文件中的第一行。

一个非常常见的情况是在文件中找到空行。为此，我们使用`grep "^\s$" file.txt`命令：

+   其中`\s`：表示空格，

+   `^`：表示行的开头。

+   `$`：表示行尾。

我们有两个没有空格的空行。如果在行之间添加一个空格，它将匹配包含一个空格的行。这些被称为**锚点**。

`grep`可以使用一个小技巧来计算匹配的数量。为此，我们使用`-c`参数：

![基本正则表达式](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_02_016.jpg)

要查找所有只包含字母和空格的行，请使用：

+   `grep`

+   `""`：打开引号

+   `^$`：从行的开头到结尾

+   `[]*`：匹配这些字符任意次数

+   `A-Za-z`：任何大写和小写字母

如果我们运行到这里的命令，我们只会得到第一行。如果我们添加：

+   - 0-9 任何数字我们匹配另外两行，

+   如果我们添加：- \s 任何空格，我们还会匹配空行和全大写行

+   如果我们运行到这里的命令，我们只会得到输出的第一行，其余的不会显示

+   然后，如果我们添加 0-9，我们匹配任何数字（所以前两行被匹配）

+   如果我们添加\s，我们将匹配任何类型的空格（因此空行也将匹配）

```
grep "^[A-Za-z0-9\s]*$" file.txt

```

![基本正则表达式](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_02_017.jpg)

有时我们需要搜索不在字符串中的内容：

```
grep "^[⁰-9]*$" file.txt

```

此命令将找到所有不仅包含数字字符的行。`[^]`表示匹配所有不在其中的字符，在我们的例子中是任何非数字字符。

方括号是我们正则表达式中的标记。如果我们想在搜索字符串中使用它们，我们必须对它们进行转义。因此，为了找到具有方括号之间内容的行，请执行以下操作：

```
grep "\[.*\]" file.txt

```

这是任何具有方括号中字符的行。要查找所有具有这些字符`!`的行，请键入：

```
grep "\!" file.txt

```

现在让我们来看一个基本的`sed`，找到`Joe`单词并替换为`All`单词：

```
sed "s/Joe/All/g" file.txt

```

![基本正则表达式](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_02_018.jpg)

这将替换字符串`Joe`的每个出现为字符串`All`。我们将在接下来的章节中深入探讨这个问题。

正则表达式（如 Vim）是许多人害怕的东西，因为它们在开始时似乎很难学习。尽管它们可能看起来神秘，但一旦掌握，正则表达式就是方便的伙伴：它们不仅限于我们的 shell，因为语法在大多数编程语言、数据库、编辑器和任何其他包含字符串搜索的地方非常相似。我们将在接下来的章节中详细介绍正则表达式。

# 管道和子 shell-你的 shell 的盐和胡椒

在本节中，我们将探讨如何利用 shell 提高工作效率。Linux 命令行非常棒，因为我们可以使用各种工具。更棒的是，我们可以将这些工具链接在一起，形成更强大的工具，使我们的工作更加高效。我们不会介绍基本的 shell 命令，而是将研究一些酷炫的管道和子 shell 组合，这些组合可以让我们的生活更轻松。

让我们从一个基本的管道开始；在这个例子中，我们使用以下命令计算当前路径的长度：

```
pwd | wc -c

```

![管道和子 shell-你的 shell 的盐和胡椒](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_02_019.jpg)

`pwd`，您可能知道，代表`print working directory`。`|`是管道符号，它的作用是将左侧命令的输出发送到右侧的命令。在我们的例子中，`pwd`将其输出发送到`wc -c`，它计算字符的数量。管道最酷的事情是您可以创建任意数量的管道链。

让我们看另一个例子，我们将看到如何查找驱动器上的已使用空间：

```
df -h | grep /home | tr -s " " | cut -f 2 -d " "

```

![管道和子 shell-你的 shell 的盐和胡椒](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_02_020.jpg)

+   `"df -h"`：以人类可读的格式显示磁盘使用情况

+   `"| grep /home"`：这只显示主目录

+   `'| tr -s " "'`: 这将多个空格替换为一个空格

+   `'| cut -f 2 -d " "'`: 这使用空格作为分隔符选择第二列

正如您所看到的，该命令打印出`173G`，即`/home`分区的大小。这是一个常见的用例，通过链接多个命令，每个命令都减少输出，直到我们获得所需的信息而不是其他信息。在我们的例子中，这是已使用的磁盘空间。

要计算文件夹中的所有目录数量，请使用以下命令：

```
ls -p | grep / | wc -l

```

![管道和子 shell-你的 shell 的盐和胡椒](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_02_021.jpg)

基本思想是计算以/结尾的所有行。在这里，我们可以看到我们只有一个目录。

管道是查找和终止进程的好选择。假设我们想要查找`nautilus`进程的进程 ID，并终止所有正在运行的实例。我们可以使用以下命令：

```
ps aux | grep nautilus | grep -v grep | awk '{print $2}' | xargs kill

```

![管道和子 shell-你的 shell 的盐和胡椒](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_02_022.jpg)

+   `ps aux`：这将打印出所有带有 PID 的进程

+   `| grep nautilus`：查找与 nautilus 匹配的项

+   `| grep -v grep`：反转`grep`以排除`grep`进程

+   `| awk '{print $2}'`：选择行中的第二个单词，即 PID

+   `| xargs kill`：这里使用`xargs`将每个 PID 分发给一个 kill 命令。它特别用于不从标准输入读取参数的命令。

现在我们已经杀死了`nautilus`。这只是一个演示性的例子。还有其他方法可以做到这一点。

让我们再次打开`nautilus`并通过按下*Ctrl* + *Z*，然后输入`bg`命令将其发送到后台。

现在让我们运行以下命令：

```
pgrep nautilus

```

要查看`nautilus`的所有`pids`并向所有这些进程发送 kill 信号，请使用以下命令行：

```
pkill nautilus

```

现在是一些网络操作的时间！您可能知道`ifconfig`命令，它用于打印有关网络接口的信息。要获取特定接口（在我们的例子中是无线接口`wlp3s0`）的 IP 地址，请运行以下命令：

```
ifconfig wlp3s0 | grep "inet addr:" | awk '{print $2}' | cut -f 2 -d ":"

```

![管道和子 shell-你的 shell 的盐和胡椒](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_02_023.jpg)

+   `ifconfig wlp3s0`：打印`wlp3s0`接口的网络信息

+   `| grep "inet addr:"`：获取包含 IP 地址的行

+   `| awk '{print $2}'`：选择行中的第二个单词（我们也可以使用 cut）

+   `| cut -f 2 -d ":"`：这是由`":"`分割的，只打印第二个单词

现在，我们在屏幕上看到了您的私有 IP 地址。

一个常见的用例也可能是计算文件中单词的频率。

这里我们有一个包含在`lorem.txt`中的标准 lorem ipsum 文本。为了获取单词频率，请使用以下命令：

```
cat lorem.txt | tr " " "\n" | grep -v "^\s*$" | sed "s/[,.]//g" | sort | uniq -c | sort -n

```

![管道和子 shell-你的 shell 的盐和胡椒](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_02_024.jpg)

+   `cat lorem.txt`

+   `| tr " " "\n"`：将每个空格转换为换行符

+   `| grep -v "^\s*$"`：消除空行

+   `| sed "s/[,.]//g"`：消除逗号（,）和句号（.），只选择单词

+   `| sort`：按字母顺序排序结果

+   `| uniq -c`：仅显示唯一的行

+   `| sort -n`：按数值排序

附加`grep -w id`以查找单词 ID 的频率，或者附加`grep -w 4`以查看出现四次的所有单词。

现在让我们继续我们的第一个子 shell 示例。子 shell 可以通过将它们括在`$()`中或使用反引号（*`*）来编写。反引号通常位于键盘上的*Esc*键下方。在所有示例中，我们将使用第一种形式，因为它更容易阅读。

我们的第一个例子是列出当前文件夹中的所有文件夹：

```
ls $(ls)

```

`ls`子 shell 返回当前目录中的文件和文件夹，而子 shell 外部的`ls`将逐个列出它们，显示附加详细信息：

+   计算当前目录中的所有文件和目录的数量

+   考虑到逗号（,）和句号（.）是标记当前目录和父目录的硬链接，我们需要计算除这两个之外的所有条目

+   可以使用`expr $(ls -a | wc -l ) - 2`命令来完成这个操作：![管道和子 shell-你的 shell 的盐和胡椒](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_02_025.jpg)

在这里，子 shell 将返回条目的数量（在本例中为五）。我们要找的数字是条目数减去特殊文件夹（"`.`"和"`..`"）的数量。为了进行算术运算，我们使用`expr`命令，就像我们的示例中一样。

请注意，子 shell 包含一个管道。好处是我们可以以任何方式组合管道和子 shell，以获得所需的结果。

想象一下管道和子 shell 就像是你的 shell 的乐高积木。它们远远超出了其功能，并为您提供了无限组合的新可能性。最终，这一切取决于您的想象力和您学会如何使用它们的能力。

# 为了娱乐和利润而编写 shell 脚本

管道和子 shell 是扩展我们的 shell 功能的一种方式。最终的方式是编写 shell 脚本。在处理无法用一行命令自动化的复杂任务时，必须考虑这些场景。

好消息是几乎所有的任务都可以通过使用 shell 脚本来自动化。我们不会介绍 shell 脚本的入门知识。相反，我们将看一些更高级的用例来编写它们。

让我们开始我们的 shell 脚本之旅！首先，让我们打开一个名为`script.sh`的文件，并分割屏幕以便我们在编写时进行测试。每个 shell 脚本都应该以`#!`开头，后面跟着它使用的解释器。这一行被称为**shebang**。我们将使用 bash 作为我们的默认解释器。

使用 bash 是一个好主意，因为它是一个常见的解释器，大多数 Linux 发行版和 OS X 都带有它：

```
#!/bin/bash

```

让我们从一个简单的用例开始：读取传递到命令行的参数。我们将把第一个命令行参数`$1`的值赋给一个名为 ARG 的变量，然后将其打印回屏幕：

```
ARG=${1}
echo ${ARG}
```

让我们保存我们的脚本，赋予它执行权限，然后用一个参数运行它：

```
./script.sh test

```

![Shell scripting for fun and profit](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_02_026.jpg)

正如您所看到的，值 test 被打印回屏幕。在某些情况下，我们希望为变量分配默认值。为了做到这一点，在变量赋值后添加“:-”，然后是默认值：

```
ARG=${1:-"default value"}

```

现在，如果我们重新运行脚本，我们可以看到不传递参数将会`echo default value`。就像管道一样，我们可以将多个默认值赋值链接在一起。我们可以定义另一个变量`AUX`，将其赋值为`123`，并使用相同的语法将其值赋给 ARG 变量，然后使用`"default value"`脚本，如下所示：

```
AUX="123"
ARG=${1:-${AUX:-"default value"}}

```

![Shell scripting for fun and profit](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_02_027.jpg)

在这种情况下，ARG 将始终接收 123 作为其默认值。

现在让我们来看一下字符串选择器。要选择一个子字符串，使用“:”，加上起始位置加上“:”，再加上字符数：

```
LINE="some long line of text"echo "${LINE:5:4}" 

```

![Shell scripting for fun and profit](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_02_028.jpg)

在我们的例子中，我们将选择四个字符，从第五个字符开始。运行脚本后，我们可以在屏幕上看到值`long`被打印出来。

大多数 shell 脚本都设计为从命令行运行并接收可变数量的参数。为了在不知道参数总数的情况下读取命令行参数，我们将使用一个`while`语句，该语句检查第一个参数是否为空，使用-z（或不等于 0）条件表达式。在 while 循环中，让我们回显变量的值并运行 shift，将命令行参数向左移动一个位置：

```
while [[ ! -z ${1} ]]; do
echo ${1}
shift  # shift cli arguments
done

```

![Shell scripting for fun and profit](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_02_029.jpg)

如果我们使用参数*a* *b* *c*运行我们的脚本，我们可以看到我们的 while 循环遍历了参数并将每个参数打印在单独的行上。现在让我们扩展我们的 CLI 参数解析器，并添加一个用于解释参数的*case*语句。

让我们假设我们的脚本将有一个帮助选项。Posix 标准建议使用`--`作为长参数版本，使用一个`-`作为短版本。因此，`-h`和`--help`都将打印帮助消息。此外，建议始终有一个默认情况，并在用户发送无效选项时打印一条消息，然后以非零退出值退出：

```
while [[ ! -z ${1} ]]; do
    case "$1" in
        --help|-h)
            echo "This is a help message"
            shift
            ;;
        *)
            echo "invalid option"
            exit 1
            ;;
    esac
done
```

![Shell scripting for fun and profit](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_02_030.jpg)

如果我们使用-h 运行脚本，我们可以看到打印的帮助消息，就像我们使用`--help`一样。如果我们使用任何其他选项运行脚本，将打印无效选项文本，并以退出码 1 退出脚本。要获取上一个命令的退出码，请使用`"$?"`。

现在让我们来看一下 shell 中的基本函数。语法与其他编程语言非常相似。让我们编写一个名为`print_ip`的函数，它将打印指定为第一个参数的接口的 IP。我们将使用子 shell 并将值赋给名为 IP 的变量。我们已经将完整的命令复制到剪贴板中；它与我们在关于管道的课程中看到的相同：

```
function print_ip() {
    IP=$(
        ifconfig ${1} | \
        grep "inet addr:" | \
        awk '{print $2}' | \
        cut -f 2 -d ":"
    )   
    echo ${IP}
}
```

！Shell 脚本的乐趣和利润

现在让我们在我们的 switch 语句中添加另一个 case，用于`-i`或`--ip`选项。该选项后面将跟随接口的名称，然后我们将将其传递给`print_ip`函数。一个选项有两个参数意味着我们需要调用 shift 命令两次：

```
--ip|-i)
    print_ip ${2}
    shift
    shift
    ;;
```

让我们执行`ifconfig`以获取我们的无线接口的名称。我们可以看到它是`wlp3s0`。

现在让我们运行：

```
./script.sh --ip wlp3s0
```

我们可以看到 IP 地址。这是一个非常基本的用例，我们可以看到如何传递命令行参数。我们可以为我们的 case 语句添加无限选项，为处理参数定义函数，甚至可以将多个选项链接在一起，形成接收命令行参数作为结构化信息的复杂脚本。

高效意味着运行任务更快 - 真的很快！而且当涉及到速度时，bash 并不是脚本解释器的首选。幸运的是，我们还有一些诀窍！如果一个 shell 脚本需要运行多个独立的任务，我们可以使用*&*符号将进程发送到后台，并继续执行下一个命令。

让我们创建两个函数，`long_running_task 1`和`2`，并在内部添加一个`sleep`命令，以模拟一个`long_running`任务：

```
function long_running_task_1() {
    sleep 1
}

function long_running_task_2() {
    sleep 2
}
```

第一个长时间运行的任务函数将休眠一秒钟，下一个将休眠两秒钟。

然后，为了测试目的，让我们在我们的 switch 语句中添加另一个 case，称为`-p / --`parallel，并运行这两个长时间运行的任务：

```
--parallel|-p)
    long_running_task_1 
    long_running_task_2
```

现在，如果我们运行这个：

```
./script.sh -p
```

脚本将花费总共三秒钟才能完成。我们可以使用*time*实用程序来测量这个时间：

！Shell 脚本的乐趣和利润

如果我们在后台运行两个函数，我们可以将运行时间减少到两个函数中运行时间最长的时间（因为有等待）。当运行长时间运行的任务时，我们可能希望脚本等待最长运行时间的任务完成，在我们的例子中是任务 2。我们可以通过获取第二个任务的`pid`来实现这一点。这里使用`$!`来获取最后一次运行命令的`pid`。然后我们使用等待 shell 内置命令等待执行完成：

```
--parallel|-p)
    long_running_task_1 &
    long_running_task_2 &
    PID=$!
    wait ${PID}
```

再次使用时间实用程序运行脚本后，我们可以看到完成任务总共需要两秒钟。

谁会想到我们可以在 shell 中进行并行处理？

如果执行时间较长，我们可以在脚本完成时添加通知：

```
notify-send script.sh "execution finished"
```

！Shell 脚本的乐趣和利润

这样我们就可以启动脚本，在其他任务上工作，并在脚本完成时收到通知。您可以让您的想象力在并行处理和通知方面发挥作用，可以实现的事情多得让人无法想象。

在本章中，我们已经看到了一些常见的预定义 shell 变量。它们是：

+   `$1`：第一个参数

+   `$?`：最后一次命令的返回代码

+   `$!`：最后一次运行命令的`pid`

其他常用的预定义 shell 变量包括：

+   `$#`：参数个数

+   `$*`：参数列表

+   `$@`：所有参数

+   `$0`：shell/脚本的名称

+   `$$`：当前运行 shell 的 PID

Bash 有很多功能，我们建议阅读其 man 页面以获取更多信息。

当正确使用时，Shell 脚本是令人惊叹的。它们可以微调系统命令，就像我们在示例中看到的那样，只获取 IP 地址，而不是整个`ifconfig`输出等等。作为一个务实的终端用户，您应该确定您在命令行中最常见的任务以及可以使用 Shell 脚本自动化的任务。您应该创建自己的 Shell 脚本集合并将它们添加到路径中，以便可以从任何目录轻松访问它们。

# Shell 脚本库

为了真正利用使用 shell 脚本自动化任务的优势，将所有常见任务组织成可重用的命令并使其在路径中可用非常重要。为此，最好在主目录中创建一个`bin`文件夹用于存储脚本，并创建一个`bin/lib`目录用于存储常见的代码片段。在处理大量 shell 脚本时，重用大块功能非常重要。可以通过为 shell 脚本编写库函数来实现这一点，这些函数可以从多个位置调用。

在这里，我们将创建一个名为`util.sh`的库脚本，它将在其他脚本中被引用。通过引用该脚本，我们可以从库脚本内部访问函数和变量。

我们将从先前的脚本中添加`print_ip`函数。

现在我们将添加另一个名为`getarg`的函数，其他脚本将使用它来读取命令行参数和值。我们将简单地从剪贴板历史中粘贴它，使用 ClipIt 进行选择。

您可以通过查看我们的 ClipIt 部分来了解更多关于 ClipIt 的信息！

```
Function to read cli argument:
function getarg() {
    NAME=${1}
    while [[ ! -z ${2} ]]; do
        if [[ "--${NAME}" == "${2}" ]]; then
            echo "${3}"
            break
        fi
        shift
    done
}   
```

![Shell 脚本库](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_02_034.jpg)

这只是一个简单的函数，它将接收参数名称作为第一个参数，CLI 参数列表作为第二个参数，并在 CLI 参数列表中搜索参数名称。我们将在后面看到它的实际应用。

我们要创建的最后一个函数称为`get_public_ip`。它在功能上与`print_ip`函数类似，只是它用于打印计算机的公共 IP。这意味着，如果您连接到无线路由器并访问 Internet，您将获得路由器的 IP，这是其他站点看到的 IP。`print_ip`函数只显示私有子网的 IP 地址。

该命令已经复制到剪贴板中。它被称为**dig**，我们使用它来访问[`www.opendns.com/`](https://www.opendns.com/)以读取公共`ip`。您可以在其 man 页面或通过 Google 搜索中找到有关它的更多信息：

```
function get_public_ip() {
    dig +short myip.opendns.com @resolver1.opendns.com
}
```

现在我们已经准备好了库函数，让我们去创建我们的提高生产力的脚本。让我们创建一个名为**iputils**的脚本，在其中添加一些用于读取 IP 地址的常见任务。

我们将首先添加 shebang，然后是一个巧妙的小技巧，以确保我们始终在与执行的脚本相同的文件夹中。我们将使用`BASH_SOURCE`变量来确定**当前工作目录**（或**CWD**）变量的值。您可以在这里看到我们使用了嵌套子 shell 来实现这一点：

```
CWD=$( cd "$(dirname "${BASH_SOURCE[0]}" )/" && pwd )
cd ${CWD}

```

接下来，我们将引用`util`脚本，以便将库函数导出到内存中。然后，我们可以从当前脚本中访问它们：

```
source ${CWD}/lib/util.sh

```

让我们在使用子 shell 的情况下向我们的`getarg`函数添加一个简单的调用，并搜索`cmd`参数。此外，让我们输出我们找到的内容，以便测试我们的脚本：

```
CMD=$(getarg cmd $@)
echo ${CMD}

```

接下来，我们需要使用`chmod`命令给脚本赋予执行权限。此外，为了能够从任何位置运行脚本，`bin`文件夹必须在 PATH 变量中。输出该变量并检查 bin 文件夹是否存在，如果不存在，则在`~/.zshrc`中更新该变量。

让我们通过使用`getarg`函数读取命令行参数并输出它来测试脚本。

如果您在终端中使用 tab 键自动补全搜索`iputils`命令，并且命令似乎不存在，那可能是因为您需要告诉`zsh`重新加载其路径命令。要做到这一点，输入"rehash"命令。

现在运行：

```
iputil --cmd ip

```

这应该在任何文件夹中都可以工作，并在屏幕上打印出`ip`。

现在我们已经验证了一切都没问题，让我们为命令行参数编写一些代码。如果我们使用`--cmd ip`标志运行脚本，脚本应该在屏幕上打印出来。这可以通过已经熟悉的`case`语句来实现。在这里，我们还想传入另一个参数`--iface`，以获取打印 IP 所需的接口。添加一个默认情况并回显一个消息说`invalid`参数也是一个好习惯：

```
case ${CMD} in
    ip)
        IFACE=$(getarg iface $@)
        print_ip ${IFACE}
        ;;
    publicip)
        get_public_ip
        ;;
    *)
        echo "Invalid argument"
esac
```

保存脚本，然后让我们测试一下。

首先，让我们从`ifconfig`命令中获取接口名称，然后通过运行此命令来测试脚本：

```
iputil --cmd ip --iface wlp3s0

```

![Shell 脚本库](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_02_035.jpg)

我们可以看到它在屏幕上打印出了我们的私有`ip`。

现在让我们在脚本中添加最后一个`cmd`：`publicip`。

为此，我们只需从我们的`lib`工具中调用`get_public_ip`函数。保存并运行此命令：

```
iputil --cmd publicip

```

我们看到命令运行成功；我们的公共`ip`被打印在屏幕上。这是完整的脚本：

```
#!/bin/bash 

CWD=$( cd "$( dirname "${BASH_SOURCE[0]}" )/" && pwd )
cd ${CWD}

source ${CWD}/lib.sh

CMD=$(getarg cmd $@)

case ${CMD} in
    publicip)
        print_public_ip
        ;;
    ip)
        IFACE=$(getarg iface $@)
        print_ip $IFACE
        ;;
    *)
        echo "invalid command"
esac
```

举个例子，前段时间互联网上有一堆关于一个男人的文章，他习惯于自动化一切超过 90 秒的工作。他编写的脚本包括指示咖啡机开始制作拿铁，这样当他到达咖啡机时，拿铁已经完成，他不需要等待。他还编写了一个脚本，在晚上 9 点后，每当他在公司的服务器上登录活动时，自动向妻子发送一条“工作晚了”的短信，并从预设列表中自动选择一个原因。

当然，这个例子有点复杂，但最终都是关于你的想象力。写得好的自动化脚本可以处理你的例行工作，让你有时间发掘你的创造潜力。


# 第三章：Vim 功夫

Vim 的默认配置通常相当一般。为了更好地使用 Vim 的功能，我们将通过其配置文件发挥其全部潜力。然后，我们将学习一些键盘快捷键，帮助我们加快工作流程。我们还将介绍一些常用的插件，使 Vim 变得更好用。我们将看到 Vim 如何通过加密文件来存储密码。每章结束时，将展示如何自动化 Vim 并轻松配置工作环境。

在本章中，我们将涵盖以下内容：

+   使用 Vim 工作

+   探索 Vim 的插件功能

+   使用 Vim 密码管理器存储密码

+   自动化 Vim 配置

在终端中提高生产力时，一个重要的方面是永远不要离开终端！当完成任务时，我们经常需要编辑文件并打开一个外部（GUI）编辑器。

走错了！

为了提高我们的生产力，我们需要抛弃那些过去的日子，在终端中完成工作，而不是打开完整的 IDE 来编辑一行简单的文本。现在，关于哪个是最好的终端文本编辑器的争论很多，每个编辑器都有其优缺点。我们推荐 Vim，这是一个超级可配置的编辑器，一旦掌握，甚至可以胜过一个 IDE。

为了启动我们的 Vim 生产力，我们首先需要一个配置良好的`vimrc`文件。

# 强化 Vim

让我们首先在我们的`home`文件夹中打开一个名为`.vimrc`的新隐藏文件，并粘贴几行代码：

```
set nocompatible
filetype off

" Settings to replace tab. Use :retab for replacing tab in existing files.
set tabstop=4
set shiftwidth=4
set expandtab

" Have Vim jump to the last position when reopening a file
if has("autocmd")
   au BufReadPost * if line("'\"") > 1 && line("'\"") <= line("$") | exe "normal! g'\"" | endif

" Other general vim options:
syntax on
set showmatch      " Show matching brackets.
set ignorecase     " Do case insensitive matching
set incsearch      " show partial matches for a search phrase
set nopaste
set number           
set undolevels=1000
```

![Supercharging Vim](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_03_001.jpg)

现在让我们关闭并重新打开文件，以便我们可以看到配置生效。让我们更详细地了解一些选项。

首先，正如你可能已经猜到的，以`"`开头的行是注释，可以忽略。第 5、6 和 7 行告诉`vim`始终使用空格而不是制表符，并将制表符大小设置为 4 个空格。第 10 到 12 行告诉`vim`始终打开一个文件，并将光标设置为上次打开文件时的位置：

+   `syntax on`：这个命令启用语法高亮，使得代码更容易阅读

+   `set nopaste`：这个命令设置为`nopaste`模式，这意味着你可以粘贴代码而不让 Vim 尝试猜测如何格式化它

+   `set number`：这告诉 Vim 始终显示行号

+   `set undolevels=1000`：这告诉 Vim 记住我们对文件所做的最后 1000 次更改，以便我们可以轻松地撤销和重做

现在，大多数这些功能可以很容易地打开或关闭。例如，假设我们想要从在 Vim 中打开的文件中复制、粘贴几行到另一个文件中。使用这个配置，我们也会粘贴行号。可以通过输入`:set nonumber`快速关闭行号，或者如果语法很烦人，可以通过运行`syntax off`轻松关闭它。

另一个常见的功能是状态行，可以通过粘贴以下选项进行配置：

```
" Always show the status line
set laststatus=2

" Format the status line
set statusline=\ %{HasPaste()}%F%m%r%h\ %w\ \ CWD:\ %r%{getcwd()}%h\ \ \ Line:\ %l\ \ Column:\ %c

" Returns true if paste mode is enabled
function! Has Paste()
    if &paste
        return 'PASTE MODE  '
    en  
    return ''
end function
```

关闭文件并重新打开。现在我们可以在页面底部看到一个带有额外信息的状态栏。这个状态栏也是可以高度配置的，我们可以在里面放很多不同的东西。这个特定的状态栏包含了文件名、当前目录、行号和列号，还有粘贴模式（开启或关闭）。要将粘贴模式设置为开启，我们使用`:set paste`命令，状态栏上会显示出相应的更改。

Vim 还有更改配色方案的选项。要做到这一点，进入`/usr/share/vim/vim74/colors`目录，从中选择一个配色方案：

![Supercharging Vim](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_03_002.jpg)

让我们选择 desert！

## 配色方案 desert

关闭并重新打开文件，你会发现它与之前的配色主题并没有太大的不同。如果我们想要一个更激进的配色方案，我们可以将配色方案设置为蓝色，这将大大改变 Vim 的外观。但在本课程的其余部分，我们将坚持使用**desert**。

Vim 还可以通过外部工具进行超级增强。在编程世界中，我们经常发现自己在编辑 JSON 文件，如果 JSON 没有缩进，这可能是一项非常困难的任务。有一个 Python 模块可以用来自动缩进 JSON 文件，Vim 可以配置为在内部使用它。我们只需要打开配置文件并粘贴以下行：

```
map j !python -m json.tool<CR>

```

基本上，这告诉 Vim，当处于可视模式时，如果我们按下*J*，它应该调用 Python 并使用选定的文本。让我们手动编写一个`json`字符串，通过按下*V*进入可视模式，使用箭头选择文本，然后按下*J*。

而且，不需要额外的软件包，我们添加了一个 JSON 格式化的快捷方式：

![配色方案 desert](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_03_003.jpg)

我们也可以对`xml`文件执行相同的操作，但首先我们需要安装一个用于处理它们的工具：

```
sudo apt install libxml2-utils

```

![配色方案 desert](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_03_004.jpg)

要安装 XML 实用程序包，我们必须将以下行添加到配置文件中：

```
map l !xmllint --format --recover -<CR>

```

当处于可视模式时，将*L*键映射为`xmllint`。让我们编写一个 HTML 片段，实际上是一个有效的`xml`文件，按下`V`进入可视模式，选择文本，然后按下*L*。

这种类型的扩展（以及拼写检查器、语法检查器、字典等等）可以带到 Vim 中，并立即可用。

一个配置良好的`vim`文件可以节省您在命令行中的大量时间。虽然在开始时可能需要一些时间来设置和找到适合您的配置，但随着时间的推移，这种投资将在未来产生巨大的回报，因为我们在 Vim 中花费的时间越来越多。很多时候，我们甚至没有打开 GUI 编辑器的奢侈，比如在通过`ssh`会话远程工作时。信不信由你，命令行编辑器是救命稻草，没有它们很难实现高效的工作。

# 键盘功夫

现在我们已经设置好了 Vim，是时候学习一些更多的命令行快捷方式了。我们将首先看一下缩进。

在 Vim 中可以通过进入可视模式并键入*V*选择文本的部分或键入*V*选择整行，然后键入*>*或*<*进行缩进。然后按下`.`重复上次的操作：

![键盘功夫](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_03_005.jpg)

通过按下`u`可以撤消任何操作，然后通过按下*Ctrl* + *R*（即撤消和重做）可以重做。这相当于大多数流行编辑器中的*Ctrl* + *Z*和*Ctrl* + *Shift* + *Z*。

在可视模式下，我们可以通过按下*U*将所有文本转换为大写，按下*u*将所有文本转换为小写，按下*~*来反转当前大小写：

![键盘功夫](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_03_006.jpg)

其他方便的快捷方式包括：

+   `G`：转到文件末尾

+   `gg`：转到文件开头

+   `全选`：这实际上不是一个快捷方式，而是一组命令的组合：`gg V G`，即转到文件开头，选择整行，然后移动到末尾。

Vim 还有一个方便的快捷方式，可以打开光标下的单词的 man 页。只需按下 K，就会显示该特定单词的 man 页（如果有的话）：

![键盘功夫](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_03_007.jpg)

在 Vim 中查找文本就像按下`/`一样简单。只需输入`/*`加上要查找的文本，然后按下*Enter*开始搜索。Vim 将转到该文本的第一个出现位置。按下`n`查找下一个出现位置，*N*查找上一个出现位置。

我们最喜欢的编辑器具有强大的查找和替换功能，类似于`sed`命令。假设我们想要将所有出现的字符串`CWD`替换为字符串`DIR`。只需输入：

```
:1,$s/CWD/DIR/g
:1,$ - start from line one, till the end of the file
s - substitute 
/CWD/DIR/ - replace CWD with DIR
g - global, replace all occurrences.

```

![键盘功夫](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_03_008.jpg)

让我们再来看一个常见的例子，这在编程中经常出现：注释代码行。假设我们想要在 shell 脚本中注释掉第 10 到 20 行。要做到这一点，输入：

```
:10,20s/^/#\ /g

```

![键盘功夫](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_03_009.jpg)![键盘功夫](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_03_010.jpg)

这意味着用#和空格替换行的开头。要删除文本行，请输入：

```
:30,$d

```

这将删除从第 30 行到末尾的所有内容。

有关正则表达式的更多信息可以在各章节中找到。还可以查看关于`sed`的部分，以获取更多的文本操作示例。这些命令是 Vim 中最长的命令之一，我们经常会弄错。要编辑我们刚刚写的命令并再次运行它，我们可以通过按下*q:*打开命令历史记录，然后导航到包含要编辑的命令的行，按下 Insert 键，更新该行，然后按下*Esc*和*Enter*运行命令。就是这么简单！

！键盘功夫

另一个经常有用的操作是排序。让我们创建一个包含未排序文本行的文件，使用经典的 lorem ipsum 文本：

```
cat lorem.txt | tr " " "\n" | grep -v "^\s*$" | sed "s/[,.]//g" > sort.txt

```

！键盘功夫

打开`sort.txt`并运行`:sort`。我们可以看到行都按字母顺序排序了。

！键盘功夫

现在让我们继续讲解窗口管理。Vim 有将屏幕分割为并行编辑文件的选项。只需输入`:split`进行水平分割，输入`:vsplit`进行垂直分割：

！键盘功夫！键盘功夫

当 Vim 分割屏幕时，它会在另一个窗格中打开相同的文件；要打开另一个文件，只需输入`:e`。好处在于我们有自动补全功能，所以我们只需按下*Tab*，Vim 就会为我们开始写文件名。如果我们不知道要选择哪些文件，我们可以直接从 Vim 中运行任意的 shell 命令，完成后再返回。例如，当我们输入`:!ls`时，shell 会打开，显示命令的输出，并等待我们按下*Enter*键返回到文件中。

在分割模式下，按下*Ctrl* + *W*可以在窗口之间切换。要关闭窗口，按下`:q`。如果要将文件另存为不同的名称（类似于其他编辑器的“另存为”命令），只需按下`:w`，然后输入新文件名，比如`mycopy.txt`。

Vim 还可以同时打开多个文件；只需在`vim`命令后指定文件列表：

```
vim file1 file2 file3

```

文件打开后，使用`:bn`移动到下一个文件。要关闭所有文件，按下`:qa`。

Vim 还有一个内置的资源管理器。只需打开 Vim 并输入`:Explore`即可。之后，我们可以浏览目录结构并打开新文件：

！键盘功夫

它还有另一个选项。让我们打开一个文件，删除其中一行，并将其保存为新名称。退出并使用`vimdiff`打开这两个文件。现在我们可以直观地看到它们之间的差异。这适用于各种更改，比起普通的 diff 命令输出要好得多。

键盘快捷键确实让使用 Vim 时有很大的不同，并开启了一个全新的可能性世界。一开始可能有点难记住，但一旦开始使用，就会像点击一个按钮一样简单。

# Vim 的插件增强

在本节中，我们将看看如何向 Vim 添加外部插件。Vim 有自己的编程语言用于编写插件，我们在编写`vimrc`文件时已经看到了一瞥。幸运的是，我们不必学习所有这些，因为我们可以想到的大部分东西都已经有插件了。为了管理插件，让我们安装插件管理器 pathogen。打开：[`github.com/tpope/vim-pathogen`](https://github.com/tpope/vim-pathogen)。

按照安装说明进行操作。如您所见，这只是一个一行命令：

```
mkdir -p ~/.vim/autoload ~/.vim/bundle && \curl -LSso ~/.vim/autoload/pathogen.vim https://tpo.pe/pathogen.vim

```

完成后，在`.vimrc`中添加 pathogen：

```
execute pathogen#infect()
```

大多数集成开发环境都会显示文件夹结构的树形布局，与打开的文件并行显示。Vim 也可以做到这一点，最简单的方法是安装名为**NERDtree**的插件。

打开：[`github.com/scrooloose/nerdtree`](https://github.com/scrooloose/nerdtree)，并按照安装说明进行操作：

```
cd ~/.vim/bundle git clone https://github.com/scrooloose/nerdtree.git

```

现在我们应该准备好了。让我们打开一个文件，输入`:NERDtree`。我们可以在这里看到当前文件夹的树状结构，可以浏览和打开新文件。如果我们想要用 Vim 替代我们的 IDE，这绝对是一个必备插件！

![Vim 插件类固醇](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_03_017.jpg)

另一个非常方便的插件是称为**Snipmate**的插件，用于编写代码片段。要安装它，请访问此链接并按照说明进行操作：[`github.com/garbas/vim-snipmate`](https://github.com/garbas/vim-snipmate)。

![Vim 插件类固醇](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_03_018.jpg)

正如我们所看到的，在安装`snipmate`之前，还需要安装另一组插件：

+   `git clone https://github.com/tomtom/tlib_vim.git`

+   `git clone https://github.com/MarcWeber/vim-addon-mw-utils.git`

+   `git clone https://github.com/garbas/vim-snipmate.git`

+   `git clone https://github.com/honza/vim-snippets.git`

如果我们查看 readme 文件，可以看到一个 C 文件的示例，其中包含了`for`关键字的自动补全。让我们打开一个扩展名为.c 的文件，输入`for`，然后按下*Tab*键。我们可以看到自动补全的效果。

我们还安装了`vim-snipmate`包，其中包含了许多不同语言的代码片段。如果我们查看`~/.vim/bundle/vim-snippets/snippets/`，我们可以看到许多代码片段文件：

![Vim 插件类固醇](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_03_019.jpg)

让我们来看看`javascript`的代码片段：

```
vim ~/.vim/bundle/vim-snippets/snippets/javascript/javascript.snippets

```

![Vim 插件类固醇](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_03_020.jpg)

在这里我们可以看到所有可用的代码片段。输入`fun`并按下*Tab*键进行函数自动补全。代码片段预先配置了变量，这样您可以输入函数名并按下*Tab*键来进入下一个变量以完成。有一个用于编写 if-else 代码块的代码片段，一个用于编写`console.log`的代码片段，以及许多其他用于常见代码块的代码片段。学习它们的最佳方式是浏览文件并开始使用代码片段。

有很多插件可供选择。人们制作了各种插件包，保证能让您的 Vim 变得更强大。一个很酷的项目是[`vim.spf13.com/`](http://vim.spf13.com/)

它被昵称为终极 Vim 插件包，基本上包含了所有插件和键盘快捷键。这是给更高级用户使用的，所以在使用插件包之前一定要理解基本概念。记住，学习的最佳方式是手动安装插件并逐个尝试它们。

# Vim 密码管理器

Vim 还可以用于安全存储信息，通过使用不同的`cryp`方法对文本文件进行加密。要查看 Vim 当前使用的`cryp`方法，输入：

```
:set cryptmethod?
```

我们可以看到在我们的例子中是`zip`，它实际上不是一种`crypto`方法，安全性方面并不提供太多。要查看不同的替代方法，我们可以输入：

```
:h 'cryptmethod'
```

![Vim 密码管理器](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_03_021.jpg)

出现了一个描述不同加密方法的页面。我们可以选择`zip`、`blowfish`和`blowfish2`。最安全和推荐的方法当然是`blowfish2`。要更改加密方法，输入：

```
:set cryptmethod=blowfish2
```

这也可以添加到`vimrc`中，以便成为默认的加密方式。现在我们可以安全地使用 Vim 加密文件。

一个常见的场景是存储密码文件。

让我们打开一个名为`passwords.txt`的新文件，里面添加一些虚拟密码，并保存。下一步是用密码加密文件，我们输入`:X`。

Vim 会提示您输入密码两次。如果您在不保存文件的情况下退出，加密将不会应用。现在，再次加密它，保存并退出文件。

当我们重新打开文件时，Vim 会要求输入相同的密码。如果我们输入错误，Vim 会显示一些来自解密失败的随机字符。只有输入正确的密码，我们才能得到实际的文件内容：

![Vim 密码管理器](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_03_022.jpg)

使用 Vim 保存加密文件，结合在私有的`git`仓库或私有的 Dropbox 文件夹等地方备份文件，可以是一种有效的存储密码的方式：

Vim 密码管理器

它还有一个好处，就是相对于使用相当标准且可能被破解的在线服务来说，它是一种存储密码的独特方法。这也可以称为*安全通过模糊性*。

# 即时配置恢复

我们在本章中看到的配置可能需要一些时间来手动设置，但是一旦一切都配置好了，我们可以创建一个脚本，可以立即恢复 Vim 配置。

为此，我们将到目前为止发出的所有命令粘贴到一个 bash 脚本中，可以运行该脚本以将 Vim 配置还原到完全相同的状态。这个脚本缺少的只是`home`文件夹中的`vimrc`文件，我们也可以通过一个称为 heredocs 的技术来恢复它。只需键入 cat，将输出重定向到`vimrc`，并使用 heredoc 作为输入，以`eof`为分隔符：

即时配置恢复

```
cat > ~/.vimrc << EOF
...
<vimrc content>
...
EOF

```

使用 heredocs 是在 bash 脚本中操作大块文本的常用技术。基本上，它将代码部分视为一个单独的文件（在我们的例子中是 cat 之后直到 EOF 之前的所有内容）。通过这个脚本，我们可以恢复我们所做的所有 Vim 配置，并且可以在任何我们工作的计算机上运行它，这样我们就可以立即设置好我们的 Vim！

希望您喜欢这个材料，我们在下一章见！


# 第四章：CLI - 隐藏的配方

本章将首先关注 sed，这是一个可以吓到很多 Linux 用户的工具之一。我们将看一些基本的`sed`命令，可以将几个小时的重构工作缩短为几分钟。我们将看到如何使用 Linux 计算机定位任何文件。此外，我们还将看到当 Tmux 进入我们的技能集时，远程工作将变得更好。您可以使用最好的终端复用器运行长时间的命令，分割屏幕，并且不会丢失工作。然后，您将学习如何使用 netstat 和 nmap 等命令发现和与您的网络进行交互。最后，我们将看到 Autoenv 如何自动切换环境，以及如何使用 rm 命令通过命令行使用垃圾箱实用程序与垃圾进行交互。

在本章中，我们将涵盖以下内容：

+   了解 sed 的工作原理

+   使用 tmux，一个终端复用器

+   使用 Autoenv 自动切换环境

+   使用 rm 命令行删除文件或目录

# Sed – one-liner productivity treasure

如果一张图片价值 1000 个字，那么 sed 一行命令绝对相当于一千行代码！在 Linux CLI 中，最令人恐惧的命令之一就是，你猜对了，sed！由于其晦涩的用法，它一直被程序员和系统管理员所恐惧，但它可以作为一个非常强大的工具，快速编辑大量的数据。

我们创建了五个文件来演示这个强大工具的功能。第一个文件是一个简单的文件，包含了一行谦虚的文本：*橙色是新的黑色*。让我们从创建一个简单的`sed`命令开始，将单词*black*替换为*white*。

sed 的第一个参数是替换命令。它由 3 个`/`分成 3 个部分。第一部分是`s`表示替换，第二部分是要替换的单词，在我们的例子中是`black`，第三部分是替换后的单词`white`。

第二个参数是输入，对我们来说是一个文件：

```
sed "s/black/white/" 1.txt

```

![Sed – one-liner productivity treasure](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_04_001.jpg)

现在，结果将被打印在屏幕上，您可以看到单词 black 已被替换为 white。

我们的第二个示例包含另一行文本，这次包含了大小写都为黑色的单词。如果我们使用这个新文件运行相同的命令，我们将看到它只替换与大小写匹配的单词。如果我们想进行不区分大小写的替换，我们将在`sed`命令的末尾添加两个字符；`g`和`l`。

+   `g`：表示全局替换，用于替换文件中的所有出现。如果没有这个参数，它只会替换第一个参数。

+   `l`：表示不区分大小写搜索。

```
sed "s/black/white/gI" 2.txt

```

![Sed – one-liner productivity treasure](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_04_002.jpg)

正如您所看到的，两个单词都被替换了。如果我们想将结果保存在文件中而不是打印到屏幕上，我们使用`-i`参数，它表示内联替换。

在某些情况下，我们可能还希望保存我们的初始文件，以防我们在`sed`命令中出现错误。为此，我们在`-i`之后指定一个后缀，它将创建一个备份文件。在我们的例子中，我们使用`.bak`后缀：

```
sed -i.bak "s/black/white/g" 2.txt

```

![Sed – one-liner productivity treasure](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_04_003.jpg)

如果我们检查文件的内容，我们可以看到初始文件包含更新后的文本，备份文件包含原始文本。

现在，让我们看一个更实际的例子。假设我们有一个包含多个变量的 shell 脚本，我们想用花括号括起来：

![Sed – one-liner productivity treasure](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_04_004.jpg)

为了实现这个，我们将写下以下命令：

+   `s`：表示替换。

+   `g`：表示全局；意思是替换所有找到的出现。

+   `\$`：匹配以美元符号开头的所有字符串。这里需要转义美元符号，以免与*行的开头*锚点混淆。

+   我们将在`$`后面的字符串括起来，这样我们就可以在命令的替换部分中引用它。

+   `[ ]`：用于指定一系列字符

+   `A-Z`：它匹配所有大写字符

+   `0-9`：它匹配所有数字

+   `_`：它匹配`_`

+   `\+`：在`[ ]`中的任何字符必须出现一次或多次

在替换部分，我们将使用：

+   `\$`：美元符号

+   `{ }`：我们要添加的花括号。

+   `\1`：之前在( )中匹配的字符串

```
sed 's/\$\([A-Z0-9_]\+\)/\${\1}/g' 3.txt

```

![Sed – one-liner productivity treasure](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_04_005.jpg)

其他常见的情况是替换`xml`或`html`文件中的内容。

这里我们有一个带有`<strong>`文本的基本 html 文件。现在，我们知道`<strong>`文本对于搜索引擎优化具有更多的语义价值，所以也许我们想让我们的强调标签成为一个简单的`<b>`（加粗），并手动决定页面上的`<strong>`单词。为此，我们说：

+   `s`：这是用于替换的。

+   `<strong`：我们要搜索的实际文本。

+   `\(\)`：这将再次用于选择一段文本，然后将其添加回去。

+   `.*`：这意味着任何字符，出现任意次数。我们想选择"`<strong`"和"`strong>`"之间的所有内容。

+   `</`：这是标签的关闭。我们要保持它不变。

+   `<b\1b>`：只需添加`<b b>`，以及之前在`( )`中找到的文本。

```
sed "s/<strong\(.*</\)strong>/<b\1b>/g" 4.xml

```

![Sed – one-liner productivity treasure](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_04_006.jpg)

正如你所看到的，文本被正确更新，`red`类仍然适用于新标签，旧文本仍然包含在我们的标签之间，这正是我们想要的：

![Sed – one-liner productivity treasure](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_04_007.jpg)

除了替换，sed 还可以用于删除文本行。我们的`5.txt`文件包含了`lorem ipsum`文本中的所有单词。如果我们想删除第三行的文本，我们将发出以下命令：

```
sed -i 3d 5.txt

```

按下*:e,*在 vim 中重新加载文件，我们可以看到单词`dolor`不再存在。例如，如果我们想删除文件的前 10 行，我们只需运行：

```
sed -i 1,10d 5.txt

```

按下*:e*，你会看到这些行不再存在。对于我们的最后一个例子，如果我们向下滚动，我们可以看到多个空行。可以使用以下命令删除这些行。

```
sed -i "/^$/d" 5.txt

```

![Sed – one-liner productivity treasure](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_04_008.jpg)

它代表：

+   `^`：行首锚点

+   `$`：行尾锚点

+   `d`：删除

重新加载文件，你会看到这些行不再存在。

现在，正如你所想象的那样，这只是一些基本的例子。sed 的功能远远超过这个，使用它的可能性比我们今天看到的还要多得多。我们建议你对今天介绍的功能有一个很好的理解，因为这些功能可能是你最常使用的。它并不像一开始看起来那么复杂，在许多场景中非常方便。

# 你可以逃跑，但你无法躲避...来自 find

数十个项目，数百个文件夹和数千个文件；这个场景听起来熟悉吗？如果答案是“是”，那么你可能不止一次发现自己无法找到特定的文件。`find`命令将帮助我们在项目中定位任何文件以及更多其他功能。但首先，为了创建一个快速的游乐场，让我们从 GitHub 下载 electron 开源项目：

Git 克隆[`github.com/electron/electron`](https://github.com/electron/electron)

然后`cd`进入它：

```
cd electron

```

我们在这里看到了许多不同的文件和文件夹，就像在任何一个正常大小的软件项目中一样。为了找到一个特定的文件，比如`package.json`，我们将使用：

```
find . -name package.json

```

![You can run, but you can't hide… from find](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_04_009.jpg)

`.`：这在当前文件夹中开始搜索

`-name`：这有助于搜索文件名

如果我们要在项目中查找所有的 readme 文件，前面的命令格式是没有帮助的。我们需要发出一个不区分大小写的查找命令。为了演示目的，我们还将创建一个`readme.md`文件：

```
touch lib/readme.md

```

我们还将使用`-iname`参数进行不区分大小写的搜索：

```
find . -iname readme.md

```

![You can run, but you can't hide… from find](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_04_010.jpg)

你可以看到这里找到了`readme.md`和`README.md`。现在，如果我们要搜索所有 JavaScript 文件，我们将使用：

```
find . -name "*.js"

```

![你可以跑，但你无法躲避...来自 find](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_04_011.jpg)

正如你所看到的，有相当多的结果。为了缩小结果范围，让我们将 find 限制在`default_app`文件夹中：

```
find default_app -name "*.js"

```

![你可以跑，但你无法躲避...来自 find](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_04_012.jpg)

正如你所看到的，这个文件夹中只有两个`js`文件。如果我们要找到所有不是 JavaScript 的文件，只需在名称参数之前加上`!`标记：

```
find default_app ! -name "*.js"

```

![你可以跑，但你无法躲避...来自 find](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_04_013.jpg)

你可以看到这里所有不以`js`结尾的文件。如果我们要查找目录中的所有类型为文件的 inode，我们将使用`-type f`参数：

```
find lib -type f

```

![你可以跑，但你无法躲避...来自 find](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_04_014.jpg)

同样，我们可以使用`-type d`来查找特定位置的所有目录：

```
find lib -type d

```

![你可以跑，但你无法躲避...来自 find](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_04_015.jpg)

Find 还可以根据时间标识符定位文件。例如，为了找到在`/usr/share`目录中在过去 24 小时内修改的所有文件，执行以下命令：

```
find /usr/share -mtime -1

```

![你可以跑，但你无法躲避...来自 find](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_04_016.jpg)

我有一个相当长的列表。你可以看到`-mtime -3`扩大了列表。

如果我们要找到最近一小时内修改的所有文件，我们可以使用`-mmin -60`：

```
find ~/.local/share -mmin -60

```

![你可以跑，但你无法躲避...来自 find](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_04_017.jpg)

一个好的搜索文件夹是`~/.local/share`，如果我们使用`-mmin -90`，列表会再次扩大。

使用`-atime -1`参数，find 还可以显示在过去 24 小时内访问的文件列表，如下所示：

```
find ~/.local/share -atime -1

```

![你可以跑，但你无法躲避...来自 find](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_04_018.jpg)

在处理大量项目文件时，有时候在某些项目中会保留空文件，并且我们忘记删除它们。为了定位所有空文件，只需执行以下操作：

```
find . -empty

```

![你可以跑，但你无法躲避...来自 find](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_04_019.jpg)

正如我们所看到的，electron 有一些空文件。Find 还会显示空目录或链接。

删除空文件将保持我们的项目清洁，但是当涉及到减小大小时，我们有时想知道哪些文件占用了大部分空间。Find 还可以根据文件大小进行搜索。例如，让我们找到所有大于`1`兆字节的文件：

```
find . -size +1M

```

使用-1M 可以缩小范围。

正如我们在开始时所说，find 可以做比在项目中定位文件更多的事情。使用`-exec`参数，它可以与几乎任何其他命令结合使用，从而使其具有几乎无限的功能。例如，如果我们想要找到所有包含文本`manager`的`javascript`文件，我们可以将 find 与`grep`命令结合使用，命令如下：

```
find . -name "*.js" -exec grep -li 'manager' {} \;

```

![你可以跑，但你无法躲避...来自 find](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_04_020.jpg)

这将在 find 返回的所有文件上执行 grep 命令。让我们还使用 vim 在文件中搜索，以便验证结果是否正确。正如你所看到的，这个文件中出现了文本"manager"。你不必担心`{} \;`，它只是标准的-exec 语法。

继续实际示例，假设你有一个文件夹，你想删除在过去 100 天内修改的所有文件。我们可以看到我们的`default_app`文件夹包含这样的文件。如果我们将 find 与`rm`结合使用，如下所示：

```
find default_app -mtime -100 -exec rm -rf {} \;

```

我们可以进行快速清理。Find 可以用于智能备份。例如，如果我们要备份项目中的所有`json`文件，我们将使用管道和标准输出重定向将 find 与`cpio`备份实用程序结合使用：

```
find . -name "*.json" | cpio -o > backup.cpio

```

![你可以跑，但你无法躲避...来自 find](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_04_021.jpg)

我们可以看到这个命令创建了一个`backup.cpio`文件，类型为`cpio`归档文件。

现在这可能也可以用`-exec`来写，但是你必须明白管道也可以在这种情况下使用，以及重定向。

在生成报告时，您可能需要计算所写行数：

+   为了做到这一点，我们将 find 与`wc -l`结合起来：

```
find . -iname "*.js" -exec wc -l {} \; 

```

+   这将给出我们所有的`js`文件和行数。我们可以将其传递给 cut：

```
find . -iname "*.js" -exec wc -l {} \; | cut -f 1 -d ' ' 

```

+   只输出行数，然后将其传递给 paste 命令，我们可以这样做：

```
find . -iname "*.js" -exec wc -l {} \; | cut -f 1 -d ' ' | paste -sd+ 

```

+   上面的命令将使用`+`符号作为分隔符合并所有行。当然，这可以转换为一个算术运算，我们可以使用二进制计算器（`bc`）来计算：

```
find . -iname "*.js" -exec wc -l {} \; | cut -f 1 -d ' ' | paste -sd+ | bc

```

![你可以逃跑，但无法躲避...来自 find](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_04_022.jpg)

这个最后的命令将告诉我们我们的`javascript`文件包含多少行。当然，这些不是实际的代码行，因为它们可能是空行或注释。要精确计算代码行数，可以使用`sloc`实用程序。

为了批量重命名文件，比如将所有的`js`文件的文件扩展名改为`node`，我们可以使用以下命令：

```
find . -type f -iname "*.js" -exec rename "s/js$/node/g" {} \;

```

你可以看到重命名的语法与 sed 非常相似。此外，没有剩余的`.js`文件了，因为所有文件都已重命名为`.node`：

![你可以逃跑，但无法躲避...来自 find](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_04_023.jpg)

一些软件项目要求所有源代码文件都有版权头。由于一开始不需要这个，所以我们经常会发现我们必须在所有文件的开头添加版权信息的情况。

为了做到这一点，我们可以将 find 与 sed 结合起来，像这样：

```
find . -name "*.node" -exec sed -i "1s/^/\/** Copyright 2016 all rights reserved *\/\n/" {} \;

```

基本上，这个命令告诉计算机找到所有的`.node`文件，并在每个文件的开头添加版权声明，然后换行。

我们可以检查一个随机文件，是的，版权声明在那里：

![你可以逃跑，但无法躲避...来自 find](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_04_024.jpg)

更新所有文件的版本号：

```
find . -name pom.xml -exec sed -i "s/<version>4.02/<version>4.03/g" {} \;

```

正如你可以想象的那样，find 有很多用途。我给你展示的例子只是冰山一角。学习 find，以及`sed`和`git cli`可以让你摆脱 IDE 的束缚，无论是查找、重构还是使用`git`，都可以更轻松地切换到其他 IDE，因为你不需要学习所有的功能。你只需要使用友好的 CLI 工具。

# tmux - 虚拟控制台、后台作业等

在本节中，我们将介绍另一个非常好用的工具，叫做 tmux。当在远程`ssh`会话中工作时，tmux 非常方便，因为它可以让你从上次离开的地方继续工作。如果你在 Mac 上工作，无法安装 terminator，它还可以替代 terminator 的一些功能。

要在 Ubuntu 上开始使用`tmux`，我们首先需要安装它：

```
sudo apt install tmux

```

![tmux - 虚拟控制台、后台作业等](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_04_025.jpg)

然后只需运行命令：

```
tmux

```

![tmux - 虚拟控制台、后台作业等](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_04_026.jpg)

然后你将发现自己在一个全新的虚拟控制台中：

![tmux - 虚拟控制台、后台作业等](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_04_027.jpg)

为了演示目的，我们将打开一个新的选项卡，你可以使用`tmux ls`命令查看打开的会话列表：

![tmux - 虚拟控制台、后台作业等](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_04_028.jpg)

让我们开始一个新的`tmux`命名会话：

```
tmux new -s mysession

```

![tmux - 虚拟控制台、后台作业等](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_04_029.jpg)

在这里我们可以看到打开一个`tmux`会话会保持当前目录。要在`tmux`内部列出和切换`tmux`会话，按下*Ctrl* + *B* *S*。

我们可以看到我们可以切换到另一个 tmux 会话，在其中执行命令，然后如果需要的话切换回我们的初始会话。要分离（保持会话运行并返回到正常终端），按下*Ctrl* + *b d*；

现在我们可以看到我们有两个打开的会话。

附加到会话：

```
tmux a -t mysession

```

![tmux - 虚拟控制台、后台作业等](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_04_030.jpg)

当您登录到远程服务器并希望执行长时间运行的任务，然后离开并在任务结束时返回时，此场景非常方便。我们将使用一个名为 infinity.sh 的快速脚本来复制此场景。我们将执行它。它正在写入标准输出。现在让我们从 tmux 中分离出来。

如果我们查看脚本，它只是一个简单的无限循环，每秒打印一次文本。

现在当我们回到会话时，我们可以看到脚本在我们分离会话时正在运行，并且仍然将数据输出到控制台。我将通过按下*Ctrl* + *c*手动停止它。

好了，让我们进入我们的第一个 tmux 会话并关闭它。为了手动终止正在运行的 tmux 会话，请使用：

```
tmux kill-session -t mysession

```

![tmux-虚拟控制台，后台作业等](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_04_031.jpg)

这将终止当前会话。如果我们切换到第二个标签，我们可以看到我们已经从 tmux 注销了。让我们也关闭这个 terminator 标签，并打开一个全新的 tmux 会话：

![tmux-虚拟控制台，后台作业等](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_04_032.jpg)

Tmux 使您有可能像 terminator 一样水平地拆分屏幕，使用*Ctrl* + *b* + "，垂直拆分屏幕使用*Ctrl* + *b* + *%*。之后，使用*Ctrl* + *b* +箭头在窗格之间导航：

![tmux-虚拟控制台，后台作业等](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_04_033.jpg)

您还可以创建窗口（选项卡）：

+   *Ctrl* + *b c*：创建：![tmux-虚拟控制台，后台作业等](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_04_034.jpg)

+   *Ctrl* + *b w*：列表：![tmux-虚拟控制台，后台作业等](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_04_035.jpg)

+   *Ctrl* + *b &*：删除![tmux-虚拟控制台，后台作业等](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_04_036.jpg)

这些功能与 terminator 提供的功能非常相似。

您可以在需要在远程`ssh`连接中拥有两个或多个窗格甚至选项卡的情况下使用 tmux，但您不想打开多个`ssh`会话。您也可以在本地使用它作为 terminator 的替代品，但是键盘快捷键的使用要困难得多。虽然它们可以更改，但您将失去在远程使用 tmux 的选项，因为不鼓励在另一个 tmux 会话中打开 tmux 会话。此外，配置新的 tmux 键盘快捷键可能会使 tmux 在处理大量服务器时变得繁琐，因为快捷键的差异。

# 网络-谁在监听？

在处理网络应用程序时，能够查看开放的端口和连接，并能够与不同主机上的端口进行交互以进行测试是非常方便的。在本节中，我们将介绍一些网络基本命令以及它们在什么情况下可能会派上用场。

第一个命令是`netstat`：

```
netstat -plnt

```

![网络-谁在监听？](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_04_037.jpg)

这将显示主机上所有打开的端口。您可以在这里看到，在默认的 Ubuntu 桌面安装中，我们只有一个打开的端口，即端口`53`。我们可以在特殊文件`/etc/services`中查找此信息。此文件包含程序和协议的所有基本端口号。我们在这里看到端口`53`是 DNS 服务器：

![网络-谁在监听？](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_04_038.jpg)

仅通过分析输出，我们无法确定哪个程序正在监听此端口，因为此进程不属于当前用户。这就是为什么*PID/程序名称*列为空的原因。如果我们使用`sudo`再次运行相同的命令，我们会看到此进程被命名为`dnsmasq`，如果我们想要更多信息，可以在 man 页面中查找。它是一个轻量级的 DHCP 和缓存 DNS 服务器：

![网络-谁在监听？](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_04_039.jpg)

从此命令中获取的其他有用信息：

+   程序协议，在这种情况下是 dhcp。

+   未复制的总字节。

+   未确认的总字节。

+   本地和外部地址和端口。获取端口是我们使用此命令的主要原因。这对于确定端口是仅在本地主机上打开还是在网络上监听传入连接也很重要。

+   端口的状态。通常为**LISTEN**。

+   PID 和程序名称，这有助于我们确定哪个程序在监听哪个端口。

现在，如果我们运行一个应该在特定端口上监听的程序，而我们不知道它是否工作，我们可以通过`netstat`找出。让我们通过运行以下命令来打开最基本的 HTTP 服务器：

```
python -m SimpleHTTPServer

```

![网络-谁在监听？](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_04_040.jpg)

从输出中可以看到，它在接口`0.0.0.0`上的端口`8000`上进行监听。如果我们打开一个新的窗格并运行`netstat`命令，我们将看到打开的端口和 PID/名称。

您可能已经知道这一点，但为了安全起见，我们将在我们的机器上添加不同的主机名作为静态`dns`条目。这在开发需要连接到服务器的应用程序时非常有用，而服务器更改其 IP 地址时，或者当您想在本地机器上模拟远程服务器时。为此，我们输入：

```
sudo vim /etc/hosts

```

![网络-谁在监听？](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_04_041.jpg)

您可以从现有内容快速了解文件的格式。让我们为本地主机添加一个别名，以便我们可以使用不同的名称访问它。添加以下行：

```
127.0.0.1     myhostname.local

```

我们建议在本地主机上使用不存在的顶级域名，例如.local 或.dev。这是为了避免覆盖任何现有地址，因为`/etc/hosts`在`dns`解析中具有优先权。现在，如果我们在浏览器中打开端口`8000`的地址，我们将看到我们的本地 Python 服务器正在运行并提供内容。

下一个命令是`nmap`。正如你所看到的，它在 Ubuntu 上默认没有安装，所以让我们通过输入以下命令来安装它：

```
sudo apt install nmap 

```

![网络-谁在监听？](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_04_042.jpg)

Nmap 是一个用于检查远程主机上所有开放端口的命令，也称为端口扫描器。如果我们在我们的网络网关上运行`nmap`，在我们的情况下是`192.68.0.1`，我们将获得网关上的所有开放端口：

类型：**nmap 192.168.0.1**

![网络-谁在监听？](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_04_043.jpg)

正如您所看到的，这里再次打开了`dns`端口，http 和 https 服务器，它们用作配置路由器的网页，以及端口`49152`，此时不特定于任何常见协议，因此被标记为未知。Nmap 无法确定这些特定程序是否实际在主机上运行；它所做的只是验证哪些端口是开放的，并写入通常在该端口上运行的默认应用程序。

如果我们不确定要连接到哪个服务器，或者我们想知道当前网络中有多少服务器，我们可以在本地网络地址上运行`nmap`，将网络掩码指定为目标网络。我们从`ifconfig`获取此信息；如果我们的 IP 地址是`192.168.0.159`，我们的网络掩码是`255.255.255.0`，那么命令将如下所示：

```
nmap -sP 192.168.0.0/24

```

![网络-谁在监听？](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_04_044.jpg)

在`/24 = 255.255.255.0`中，基本上网络将具有从`192.168.0.0`到`192.168.0.255`的 IP 地址。我们在这里看到有三个活动主机，甚至还给出了延迟，因此我们可以确定哪个主机更近。

当开发客户端-服务器应用程序时，Nmap 非常有用，例如，当您想查看服务器上可以访问的端口时。但是，`nmap`可能会错过非标准的应用程序特定端口。要实际连接到给定端口，我们将使用预安装在 Ubuntu 桌面上的 telnet。只需输入主机名，后跟端口，即可查看特定端口是否接受连接。

```
telnet 192.168.0.1 80

```

![网络-谁在监听？](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_04_045.jpg)

如果端口正在监听并接受连接，telnet 将输出如下消息：

+   尝试`192.168.0.1`...

+   连接到`192.168.0.1`

+   转义字符是`^]`

这意味着您也可以从您的应用程序进行连接。所以如果您在连接时遇到困难，通常是客户端的问题；服务器工作正常。

要退出 telnet，按下：*Ctrl* +*]*，然后按下*Ctrl* + *d*。

此外，在某些情况下，我们需要获取特定主机名的 IP 地址。最简单的方法是使用 host 命令：

```
host ubuntu.com

```

![Network - 谁在监听？](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_04_046.jpg)

我们只学习了基础知识，你需要的最低限度的元素，以便开始使用主机名和端口进行工作。为了更深入地了解网络和数据包流量，我们建议查看渗透测试或网络流量分析工具（如 Wireshark）的课程。这是一个这样的课程：[`www.packtpub.com/networking-and-servers/mastering-wireshark"`](https://www.packtpub.com/networking-and-servers/mastering-wireshark)。

# Autoenv - 设置一个持久的、基于项目的环境

项目与项目之间不同，环境也是如此。我们可能在本地机器上开发应用程序，具有某些环境变量，如调试级别、API 密钥或内存大小。然后我们想要将应用程序部署到一个具有相同环境变量的暂存或生产服务器上。一个方便加载环境的工具是`autoenv`。

要安装它，我们需要打开官方的 GitHub 页面并按照说明进行操作：

[`github.com/kennethreitz/autoenv`](https://github.com/kennethreitz/autoenv)

首先我们将在我们的主目录中克隆该项目，然后我们将以下行添加到我们的.zshrc 配置文件中，以便每次 zsh 启动时默认加载 autoenv：

```
source ~/.autoenv/activate.sh

```

现在让我们创建一个带有两个虚构项目的示例工作区，项目 1 和项目 2。

我们打开一个项目 1 的环境文件：

```
vim project1/.env

```

现在让我们假设项目 1 使用一个名为`ENV`的环境变量，我们将其设置为`dev`：

```
export ENV=dev

```

![Autoenv - 设置一个持久的、基于项目的环境](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_04_047.jpg)

现在让我们为项目 2 做同样的事情，但是使用不同的`ENV`值；`qa`：

```
export ENV=qa

```

![Autoenv - 设置一个持久的、基于项目的环境](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_04_048.jpg)

保存并关闭两个文件。现在当我们 cd 到项目 1 文件夹中时，我们会看到以下消息：

```
autoenv:
autoenv: WARNING:
autoenv: This is the first time you are about to source /home/hacker/course/work/project1/.env:
autoenv:
autoenv:     --- (begin contents) ---------------------------------------
autoenv:     export ENV=dev$
autoenv:
autoenv:     --- (end contents) -----------------------------------------
autoenv:
autoenv: Are you sure you want to allow this? (y/N)
```

按下*y*加载文件。每次加载新的环境文件时都会发生这种情况。现在，如果我们使用 grep 命令搜索 ENV 变量的环境，我们可以看到它存在，并且值为`dev`：

![Autoenv - 设置一个持久的、基于项目的环境](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_04_049.jpg)

现在让我们将目录更改为`project 2`：

![Autoenv - 设置一个持久的、基于项目的环境](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_04_050.jpg)

我们可以看到相同的警告消息被发出。当我们使用 grep 命令搜索 ENV 变量时，我们现在可以看到它的值是`qa`。如果我们离开这个文件夹，环境变量仍然被定义，并且将在其他脚本覆盖它或当前会话关闭时定义。即使我们 cd 到 project1 的更深的目录中，.env 文件也会被加载。

现在让我们看一个更复杂的 project1 的例子。

假设我们想要从`package.json`中获取版本，并且我们还想要使用一个名为 COMPOSE_FILE 的变量，该变量将指定一个不同的文件用于 docker compose。Docker 用户知道这是什么意思，但如果你不知道...谷歌一下！

这是一个例子：

```
export environment=dev
export version=`cat package.json | grep version | cut -f 4 -d "\""`
export COMPOSE_FILE=docker-compose.yml
```

为了使其生效，我们需要首先复制一个`package.json`文件，并测试`cat`命令是否有效：

![Autoenv - 设置一个持久的、基于项目的环境](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_04_051.jpg)

一切看起来都很好，所以让我们`cd`到我们的文件夹中：

![Autoenv - 设置一个持久的、基于项目的环境](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_04_052.jpg)

正如您所看到的，环境变量已经设置好了：

![Autoenv - 设置一个持久的、基于项目的环境](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_04_053.jpg)

`Autoenv`非常方便，不仅限于导出环境变量。您可以执行一些操作，比如在进入某个项目或运行`git pull`或更新终端的外观和感觉时发出提醒，以便为每个项目提供独特的感觉。

## 不要删除垃圾

命令可以分为无害和有害两类。大多数命令属于第一类，但有一个非常常见的命令在计算机世界中已经造成了很多损害。这个可怕的命令就是`rm`，它已经抹掉了许多硬盘，使得宝贵的数据卷无法访问。Linux 桌面从其他桌面借鉴了垃圾桶的概念，删除文件的默认操作是将其发送到“垃圾桶”。将文件发送到垃圾桶是一个好的做法，以防止意外删除。但是这个垃圾桶并不是一个神奇的位置；它只是一个隐藏的文件夹，通常位于`~/.local`。

在这部分中，我们将介绍一个与垃圾桶一起工作的实用工具。我们将使用以下命令进行安装：

```
sudo apt install trash-cli

```

![不要删除垃圾](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_04_054.jpg)

这将安装多个命令。让我们看一下当前目录，其中包含相当多的文件。假设我们不需要以 file.`*`开头的文件。

为了删除文件，我们将使用以下命令：

```
trash filename

```

![不要删除垃圾](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_04_055.jpg)

（有一个单独的命令用于处理垃圾桶。我们将重新加载路径。）我们列出所有垃圾桶命令。列出垃圾桶内容的命令是：

```
trash-list

```

![不要删除垃圾](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_04_056.jpg)

在这里我们可以看到垃圾桶中的文件。它只显示使用垃圾命令放入垃圾桶的文件。我们可以看到它们被删除的日期、时间和确切位置。如果我们有多个具有相同名称和路径的文件，它们将在这里列出，我们可以通过删除日期来识别它们。

为了从垃圾桶中恢复文件，我们将使用以下命令：

```
restore-trash

```

![不要删除垃圾](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_04_057.jpg)

它将显示一个选项列表，并要求输入要恢复的文件对应的编号。在这种情况下，我们将选择 1，表示我们要恢复`json`文件。

我们打开文件，可以看到内容在过程中没有被改变。

为了删除垃圾桶中的所有文件，我们使用以下命令：

```
trash-empty

```

![不要删除垃圾](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wk-linux/img/image_04_058.jpg)

这相当于一开始就使用`rm`命令。现在如果我们再次列出垃圾桶，我们会发现它没有任何内容。

尽管互联网上充斥着`rm -rf /`的笑话，但这实际上是一个严重的问题，可能会导致头痛和浪费时间来恢复造成的损害。如果您长时间使用`rm`命令而无法养成使用垃圾桶的习惯，我们建议为`rm`添加一个别名，以实际运行垃圾命令。在这种情况下，将文件堆积在垃圾桶中比冒险删除可能需要的文件更好，无论是在提交之前还是删除整个根分区！
