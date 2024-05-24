# 红帽企业 Linux 故障排除指南（一）

> 原文：[`zh.annas-archive.org/md5/4376391B1DCEF164F3ED989478713CD5`](https://zh.annas-archive.org/md5/4376391B1DCEF164F3ED989478713CD5)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

《精通 Linux Shell 脚本编程》将成为你的圣经，也是一个手册，用于在 Linux、OS X 或 Unix 中创建和编辑 bash shell 脚本。从基础知识开始，我们迅速帮助你用实际示例创建有用的脚本。这样，你的学习变得高效而迅速。每一章中，我们都提供了代码的解释和示例，因此这本书不仅是一本学习书，还可以作为一个现成的参考书，如果你需要了解如何编写特定任务的程序。

# 本书内容

第一章，“Bash 脚本的什么和为什么”，解释了如何创建和命名脚本。一旦你创建了脚本，你就可以将其设置为可执行，并欢迎自己进入这个世界。如果你对脚本几乎一无所知，那么你可以从这里开始。

第二章，“创建交互式脚本”，介绍了我们需要以更灵活的方式工作并在脚本执行过程中接受参数甚至提示用户输入的脚本。我相信你已经看到过类似的脚本，询问安装目录或要连接的服务器。

第三章，“附加条件”，介绍了关键词的使用，比如“if”，以及像“test”这样的命令。它告诉我们如何在代码中开始创建决策结构，然后在没有提供参数的情况下提示用户输入；否则，我们可以静默运行。

第四章，“创建代码片段”，介绍了非常强大的 vim 文本编辑器，还有语法高亮帮助我们编辑脚本。然而，我们也可以读取当前脚本的文件。通过这种方式，我们可以创建代表常用代码块的代码片段。

第五章，“替代语法”，告诉我们如何将测试命令缩写为单个，我们还可以根据需要使用[[和((。

第六章，“循环迭代”，介绍了循环也是条件语句。我们可以在条件为真或假时重复一段代码。通过使用 for、while 或 until，我们可以让脚本完成重复的代码序列。

第七章，“使用函数创建构建块”，介绍了函数如何封装我们在脚本中需要重复的代码。这可以提高可读性，以及脚本的易维护性。

第八章，“介绍 sed”，流编辑器，告诉我们如何使用 sed 动态编辑文件并在脚本中实现它。在这一章中，我们将学习如何使用和处理 sed。

第九章，“自动化 Apache 虚拟主机”，介绍了当我们创建一个脚本来在 Apache HTTPD 服务器上创建虚拟主机时，我们可以带走的实用配方。我们在脚本中使用 sed 来编辑用于定义虚拟主机的模板。

第十章，“Awk 基础”，介绍了我们如何开始处理命令行中的文本数据，使用 awk 是 Linux 中另一个非常强大的工具。

[第十一章，*使用 Awk 总结日志*，告诉我们关于我们在 awk 中查看的第一个实际示例，允许我们处理 Web 服务器上的日志文件。它还介绍了如何报告最经常访问服务器的 IP 地址，以及发生了多少错误以及错误的类型。

第十二章，*使用 Awk 进行更好的 lastlog*，查看了我们可以在 awk 中使用的更多示例，以过滤和格式化 lastlog 命令提供的数据。它深入到我们想要的具体信息，并删除我们不需要的信息。

第十三章，*使用 Perl 作为 Bash 脚本的替代方案*，介绍了 Perl 脚本语言及其提供的优势。我们不仅限于使用 bash，还有 Perl 作为脚本语言。

第十四章，*使用 Python 作为 Bash 脚本的替代方案*，向您介绍了 Python 和 Python 之禅，这将帮助您学习所有编程语言。与 Perl 一样，Python 是一种可以扩展脚本功能的脚本语言。

# 本书所需内容

使用带有 bash shell 的任何 Linux 发行版应该足以完成本书。在本书中，我们使用的是在 Raspberry Pi 上使用 Raspbian 发行版生成的示例；但是，任何 Linux 发行版都应该足够。如果您在苹果系统的 OS X 命令行中，则应该能够完成大部分练习，而无需 Linux。

# 本书适合人群

*精通 Linux Shell 脚本*是为那些想要在日常生活中自动化任务、节省时间和精力的 Linux 管理员编写的。您需要具有命令行经验，并熟悉需要自动化的任务。预期具有基本的脚本知识。

# 约定

在本书中，您将找到一些文本样式，用于区分不同类型的信息。以下是一些这些样式的示例及其含义的解释。

文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下："我们再次看到`basename`首先被评估，但我们没有看到运行该命令所涉及的更详细的步骤。"

代码块设置如下：

```
#!/bin/bash
echo "You are using $0"
echo "Hello $*"
exit 0
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```
#!/bin/bash
echo "You are using $0"
echo "Hello $*"
exit 0
```

任何命令行输入或输出都将按以下方式编写：

```
$ bash -x $HOME/bin/hello2.sh fred

```

**新术语**和**重要单词**以粗体显示。您在屏幕上看到的单词，例如菜单或对话框中的单词，会以这样的方式出现在文本中："单击**下一步**按钮将您移至下一个屏幕。"

### 注意

警告或重要说明会以这样的方式出现在一个框中。

### 提示

提示和技巧会以这种方式出现。

# 读者反馈

我们的读者的反馈总是受欢迎的。让我们知道您对本书的看法——您喜欢或不喜欢什么。读者的反馈对我们很重要，因为它有助于我们开发您真正能够充分利用的书籍。

要向我们发送一般反馈，只需发送电子邮件至`<feedback@packtpub.com>`，并在您的消息主题中提及书名。

如果您在某个专题上有专业知识，并且有兴趣编写或为书籍做出贡献，请参阅我们的作者指南[www.packtpub.com/authors](http://www.packtpub.com/authors)。

# 客户支持

现在您是 Packt 书籍的自豪所有者，我们有很多事情可以帮助您充分利用您的购买。

## 下载示例代码

您可以从[`www.packtpub.com`](http://www.packtpub.com)的帐户中下载您购买的所有 Packt Publishing 图书的示例代码文件。如果您在其他地方购买了这本书，您可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)注册，直接将文件发送到您的电子邮件。

## 下载本书的彩色图片

我们还为您提供了一个 PDF 文件，其中包含本书中使用的截图/图表的彩色图片。彩色图片将帮助您更好地理解输出中的变化。您可以从以下网址下载此文件：[`www.packtpub.com/sites/default/files/downloads/MasteringLinuxShellScripting_ColorImages.pdf`](http://www.packtpub.com/sites/default/files/downloads/MasteringLinuxShellScripting_ColorImages.pdf)。

## 勘误

尽管我们已经尽一切努力确保内容的准确性，但错误还是会发生。如果您在我们的书中发现错误——可能是文本或代码中的错误——我们将不胜感激，如果您能向我们报告。通过这样做，您可以帮助其他读者避免挫败感，并帮助我们改进本书的后续版本。如果您发现任何勘误，请访问[`www.packtpub.com/submit-errata`](http://www.packtpub.com/submit-errata)报告，选择您的书，点击**勘误提交表**链接，并输入您的勘误详情。一旦您的勘误经过验证，您的提交将被接受，并且勘误将被上传到我们的网站或添加到该书标题的勘误部分的任何现有勘误列表中。

要查看先前提交的勘误，请转到[`www.packtpub.com/books/content/support`](https://www.packtpub.com/books/content/support)并在搜索字段中输入书名。所需信息将出现在**勘误**部分下。

## 盗版

互联网上侵犯版权材料的盗版问题是所有媒体的持续问题。在 Packt，我们非常重视版权和许可的保护。如果您在互联网上发现我们作品的任何形式的非法副本，请立即向我们提供位置地址或网站名称，以便我们采取补救措施。

请通过链接`<copyright@packtpub.com>`与我们联系，提供涉嫌盗版材料的链接。

我们感谢您在保护我们的作者和我们为您提供有价值的内容的能力方面的帮助。

## 问题

如果您对本书的任何方面有问题，可以通过`<questions@packtpub.com>`与我们联系，我们将尽力解决问题。


# 第一章：使用 Bash 脚本的“什么”和“为什么”

欢迎来到 bash 脚本的“什么”和“为什么”。我的名字是 Andrew Mallett，我是一个 bash 脚本迷，或者更准确地说是一个脚本迷。作为管理员，我看不出手动执行重复任务的必要性。当我们选择脚本来执行我们不喜欢的繁琐任务时，我们就有更多时间做更有趣的事情。在本章中，我们将向您介绍 bash 脚本的“什么”和“为什么”。如果您是新手，它将帮助您熟悉脚本，并为那些有更多经验并希望提高技能的人提供一些很好的见解。在本章中，每个元素都旨在增加您的知识，以帮助您实现您的目标。在这个过程中，我们将涵盖以下主题：

+   Bash 漏洞

+   bash 命令层次结构

+   为脚本准备文本编辑器

+   创建和执行脚本

+   调试您的脚本

# Bash 漏洞

对于本书，我将完全在运行 Raspbian 的 Raspberry Pi 2 上工作，Raspbian 是类似于 Debian 和 Ubuntu 的 Linux 发行版；尽管对您来说，您选择使用的操作系统和 bash 的版本都是无关紧要的，实际上，我使用的 bash 版本是 4.2.37(1)。如果您使用的是 OS X 操作系统，默认的命令行环境是**bash**。

要返回正在使用的操作系统，请输入以下命令（如果已安装）：

```
$ lsb_release -a

```

我的系统的输出如下截图所示：

![Bash 漏洞](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00002.jpeg)

确定您正在使用的 bash 版本的最简单方法是打印一个变量的值。以下命令将显示您的 bash 版本：

```
$ echo $BASH_VERSION

```

以下截图显示了我的系统的输出：

![Bash 漏洞](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00003.jpeg)

2014 年，bash 中出现了一个广为人知的 bug，这个 bug 已经存在多年了——shell-shock bug。如果您的系统保持最新状态，那么这可能不是一个问题，但值得检查。该 bug 允许恶意代码从格式不正确的函数中执行。作为标准用户，您可以运行以下代码来测试系统上的漏洞。这段代码来自 Red Hat，不是恶意的，但如果您不确定，请寻求建议。

以下是来自 Red Hat 的用于测试漏洞的代码：

```
$ env 'x=() { :;}; echo vulnerable''BASH_FUNC_x()=() { :;}; echo vulnerable' bash -c "echo test"

```

如果您的系统没有这个第一个漏洞，输出应该如下截图所示：

![Bash 漏洞](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00004.jpeg)

要测试这个 bug 的最后一个漏洞，我们可以使用以下测试，同样来自 Red Hat：

```
cd /tmp; rm -f /tmp/echo; env 'x=() { (a)=>\' bash -c "echo date"; cat /tmp/echo

```

修补版本的 bash 的输出应该如下截图所示：

![Bash 漏洞](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00005.jpeg)

如果这两个命令行的输出不同，那么您的系统可能容易受到 shell-shock 的影响，我建议更新 bash，或者至少向安全专业人员寻求进一步建议。

# bash 命令层次结构

当在 bash shell 上工作时，当您舒适地坐在提示符前急切地等待输入命令时，您很可能会认为只需输入并按下*Enter*键就是一件简单的事情。您应该知道，事情从来不会像我们想象的那么简单。

## 命令类型

例如，如果我们输入`ls`来列出文件，我们可能会认为我们正在运行该命令。这是可能的，但我们经常运行别名。别名存在于内存中，作为命令或带有选项的快捷方式；在检查文件之前，我们使用这些别名。bash shell 内置命令`type`可以在这里帮助我们。`type`命令将显示在命令行输入的给定单词的命令类型。命令类型如下所示：

+   别名

+   功能

+   Shell 内置

+   关键词

+   文件

这个列表也代表了它们被搜索的顺序。正如我们所看到的，直到最后才搜索可执行文件`ls`。

以下命令演示了简单使用`type`：

```
$ type ls
ls is aliased to `ls --color=auto'

```

我们可以进一步扩展这一点，以显示给定命令的所有匹配项：

```
$ type -a ls
ls is aliased to `ls --color=auto'
ls is /bin/ls

```

如果我们只需要输入输出，我们可以使用`-t`选项。当我们需要从脚本内部测试命令类型并且只需要返回类型时，这是有用的。这将排除多余的信息；因此，使我们人类更容易阅读。考虑以下命令和输出：

```
$ type -t ls
alias

```

输出清晰简单，正是计算机或脚本所需的。

内置的`type`也可以用于识别 shell 关键字，如 if、case、function 等。以下命令显示了`type`被用于多个参数和类型：

```
$ type ls quote pwd do id

```

命令的输出显示在以下屏幕截图中：

![Command type](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00006.jpeg)

当使用`type`时，我们还会看到函数定义被打印出来。

## 命令 PATH

只有当提供程序的完整路径或相对路径时，Linux 才会在`PATH`环境中检查可执行文件。一般来说，除非它在`PATH`中，否则不会搜索当前目录。通过将目录添加到`PATH`变量中，我们可以将当前目录包含在`PATH`中。这在以下代码示例中显示：

```
$ export PATH=$PATH:.

```

这将当前目录附加到`PATH`变量的值中，每个`PATH`项都使用冒号分隔。现在，您的`PATH`已更新以包括当前工作目录，并且每次更改目录时，脚本都可以轻松执行。一般来说，将脚本组织到结构化的目录层次结构中可能是一个好主意。考虑在您的主目录中创建一个名为`bin`的子目录，并将脚本添加到该文件夹中。将`$HOME/bin`添加到您的`PATH`变量将使您能够通过名称找到脚本，而无需文件路径。

以下命令行列表只会在目录不存在时创建该目录：

```
$ test -d $HOME/bin || mkdir $HOME/bin

```

尽管上述命令行列表并不是严格必要的，但它确实显示了在 bash 中进行脚本编写不仅限于实际脚本，我们还可以直接在命令行中使用条件语句和其他语法。从我们的角度来看，我们知道前面的命令将在您是否有`bin`目录的情况下工作。使用`$HOME`变量确保命令将在不考虑当前文件系统上下文的情况下工作。

在本书中，我们将把脚本添加到`$HOME/bin`目录中，以便无论我们的工作目录如何，都可以执行它们。

# 为脚本准备文本编辑器

在整本书中，我将在树莓派的命令行上工作，这将包括创建和编辑脚本。当然，您可以选择您希望编辑脚本的方式，并且可能更喜欢使用图形编辑器，我将在 gedit 中展示一些设置。我将进行一次到 Red Hat 系统的旅行，以展示本章中 gedit 的屏幕截图。

为了帮助使命令行编辑器更易于使用，我们可以启用选项，并且可以通过隐藏的配置文件持久化这些选项。gedit 和其他 GUI 编辑器及其菜单将提供类似的功能。

## 配置 vim

编辑命令行通常是必须的，也是我日常生活的一部分。在编辑器中设置使生活更轻松的常见选项，给我们提供了所需的可靠性和一致性，有点像脚本本身。我们将在 vi 或 vim 编辑器文件`$HOME/.vimrc`中设置一些有用的选项。

我们设置的选项在以下列表中详细说明：

+   **showmode**：确保我们在插入模式下看到

+   **nohlsearch**：不会突出显示我们搜索的单词

+   **autoindent**：我们经常缩进我们的代码；这使我们可以返回到最后的缩进级别，而不是在每次换行时返回到新行的开头

+   **tabstop=4**：将制表符设置为四个空格

+   **expandtab**：将制表符转换为空格，在文件移动到其他系统时非常有用

+   **syntax on**：请注意，这不使用 set 命令，而是用于打开语法高亮

当这些选项设置时，`$HOME/.vimrc`文件应该看起来类似于这样：

```
setshowmodenohlsearch
setautoindenttabstop=4
setexpandtab
syntax on
```

## 配置 nano

nano 文本编辑器的重要性正在增加，并且它是许多系统中的默认编辑器。就我个人而言，我不喜欢它的导航或缺乏导航功能。它可以像 vim 一样进行自定义。这次我们将编辑`$HOME/.nanorc`文件。您编辑后的文件应该看起来像下面的样子：

```
setautoindent
settabsize 4
include /usr/share/nano/sh.nanorc
```

最后一行启用了 shell 脚本的语法高亮。

## 配置 gedit

图形编辑器，如 gedit，可以使用首选项菜单进行配置，非常简单直接。

启用制表符间距设置为**4**个空格，并将制表符扩展为空格，可以使用**首选项** | **编辑器**选项卡，如下截图所示：

![配置 gedit](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00007.jpeg)

### 提示

**下载示例代码**

您可以从您在[`www.packtpub.com`](http://www.packtpub.com)的帐户中下载示例代码文件，用于您购买的所有 Packt Publishing 图书。如果您在其他地方购买了本书，您可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册，文件将直接通过电子邮件发送给您。

另一个非常有用的功能可以在**首选项** | **插件**选项卡中找到。在这里，我们可以启用**片段**插件，用于插入代码示例。如下截图所示：

![配置 gedit](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00008.jpeg)

在本书的其余部分，我们将在命令行和 vim 中工作；请随意使用您最擅长的编辑器。我们现在已经奠定了创建良好脚本的基础，尽管在 bash 脚本中，空白、制表符和空格并不重要；但是一个布局良好、间距一致的文件易于阅读。当我们在本书的后面看 Python 时，您将意识到在某些语言中，空白对语言是重要的，因此最好尽早养成良好的习惯。

# 创建和执行脚本

有了我们准备好的编辑器，我们现在可以快速地创建和执行我们的脚本。如果您在阅读本书时具有一些先前的经验，我会警告您，我们将从基础知识开始，但我们也将包括查看位置参数；请随时按照自己的步调前进。

## 你好，世界！

如你所知，几乎是必须以`hello world`脚本开始，就这一点而言，我们不会让你失望。我们将首先创建一个新的脚本`$HOME/bin/hello1.sh`。文件的内容应该如下截图所示：

![Hello World!](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00009.jpeg)

我希望你没有太多困难；毕竟只有三行。我鼓励您在阅读时运行示例，以帮助您真正通过实践来巩固信息。

+   `#!/bin/bash`：通常，这总是脚本的第一行，并被称为 shebang。shebang 以注释开头，但系统仍然使用这一行。在 shell 脚本中，注释使用`#`符号。shebang 指示系统执行脚本的解释器。我们在 shell 脚本中使用 bash，根据需要，我们可能会使用 PHP 或 Perl 来执行其他脚本。如果我们不添加这一行，那么命令将在当前 shell 中运行；如果我们运行另一个 shell，可能会出现问题。

+   `echo "Hello World"`：`echo`命令将在内置 shell 中被捕获，并可用于编写标准输出`STDOUT`，默认为屏幕。要打印的信息用双引号括起来，稍后将会有更多关于引号的内容。

+   `exit 0`：`exit`命令是一个内置的 shell 命令，用于离开或退出脚本。`exit`代码作为整数参数提供。除了`0`之外的任何值都将指示脚本执行中的某种错误。

## 执行脚本

将脚本保存在我们的`PATH`环境中，它仍然不能作为独立的脚本执行。我们需要根据需要为文件分配和执行权限。对于一个简单的测试，我们可以直接用 bash 运行文件。以下命令向您展示了如何做到这一点：

```
$ bash $HOME/bin/hello1.sh

```

我们应该得到`Hello World`文本显示在我们的屏幕上。这不是一个长期的解决方案，因为我们需要将脚本放在`$HOME/bin`目录中，具体来说，以便在任何位置轻松运行脚本而不必输入完整路径。我们需要添加执行权限，如下面的代码所示：

```
$ chmod +x $HOME/bin/hello1.sh

```

现在我们应该能够简单地运行脚本，如下面的截图所示：

![执行脚本](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00010.jpeg)

## 检查退出状态

这个脚本很简单，但我们仍然需要知道如何使用脚本和其他应用程序的退出代码。我们在创建`$HOME/bin`目录时生成的命令行列表，就是如何使用退出代码的一个很好的例子：

```
$ command1 || command 2

```

在前面的例子中，只有在`command1`以某种方式失败时才会执行`command2`。具体来说，只有当`command1`以除`0`以外的状态代码退出时，`command2`才会运行。

同样，在以下摘录中：

```
$ command1 && command2

```

只有在`command1`成功并发出`0`的退出代码时，我们才会执行`command2`。

要明确从我们的脚本中读取退出代码，我们可以查看`$?`变量，如下面的例子所示：

```
$ hello1.sh
$ echo $?

```

预期的输出是`0`，因为这是我们添加到文件最后一行的内容，几乎没有其他任何可能出错导致我们无法达到那一行。

## 确保唯一的名称

现在我们可以创建和执行一个简单的脚本，但是我们需要考虑一下名字。在这种情况下，`hello1.sh`就足够好，不太可能与系统上的其他任何东西冲突。我们应该避免使用可能与现有别名、函数、关键字和构建命令冲突的名称，以及避免使用已经在使用中的程序的名称。

向文件添加`sh`后缀并不能保证名称是唯一的，但在 Linux 中，我们不使用文件扩展名，后缀是文件名的一部分。这有助于为您的脚本提供一个唯一的标识。此外，后缀被编辑器用来帮助您识别文件以进行语法高亮。如果您还记得，我们特意向 nano 文本编辑器添加了语法高亮文件`sh.nanorc`。每个文件都是特定于后缀和后续语言的。

回顾本章中的命令层次结构，我们可以使用类型来确定文件`hello.sh`的位置和类型：

```
$ type hello1.sh  #To determine the type and path
$ type -a hello1.sh  #To print all commands found if the name is NOT unique
$ type -t hello1.sh ~To print the simple type of the command

```

这些命令和输出可以在以下截图中看到：

![确保唯一的名称](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00011.jpeg)

## 你好，多莉！

可能我们在脚本中需要更多的内容而不仅仅是一个简单的固定消息。静态消息内容确实有其存在的价值，但我们可以通过增加一些灵活性使这个脚本更加有用。

在本章中，我们将看一下我们可以向脚本提供的位置参数或参数，下一章我们将看到如何使脚本交互，并在运行时提示用户输入。

### 带参数运行脚本

我们可以带参数运行脚本，毕竟这是一个自由的世界，Linux 鼓励您自由地使用代码做您想做的事情。但是，如果脚本不使用这些参数，它们将被默默地忽略。以下代码显示了带有单个参数运行脚本：

```
$ hello1.shfred

```

脚本仍然会运行，不会产生错误。输出也不会改变，仍然会打印 hello world：

| 参数标识符 | 描述 |
| --- | --- |
| `$0` | 脚本本身的名称，通常在使用说明中使用。 |
| `$1` | 位置参数，传递给脚本的第一个参数。 |
| `${10}` | 需要两个或更多位数来表示参数位置。大括号用于将变量名称与任何其他内容分隔开。预期是单个数字。 |
| `$#` | 当我们需要设置正确脚本执行所需的参数数量时，参数计数特别有用。 |
| `$*` | 指代所有参数。 |

为了使脚本使用参数，我们可以稍微更改脚本内容。让我们首先复制脚本，添加执行权限，然后编辑新的`hello2.sh`：

```
$ cp $HOME/bin/hello1.sh $HOME/bin/hello2.sh
$ chmod +x $HOME/bin/hello2.sh

```

我们需要编辑`hello2.sh`文件，以便在命令行传递参数时使用参数。以下屏幕截图显示了允许我们现在拥有自定义消息的命令行参数的最简单用法。

![使用参数运行脚本](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00012.jpeg)

现在运行脚本，我们可以按以下方式提供参数：

```
$ hello2.sh fred

```

现在输出应该是**Hello fred**。如果我们不提供参数，那么变量将为空，只会打印**Hello**。您可以参考以下屏幕截图查看执行参数和输出：

![使用参数运行脚本](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00013.jpeg)

如果我们调整脚本以使用`$*`，则会打印所有参数。我们将看到**Hello**，然后是所有提供的参数列表。如果我们编辑脚本并将`echo`行替换为以下内容：

```
echo "Hello $*"

```

使用以下参数执行脚本：

```
$ hello2.shfredwilma  betty barney

```

将导致以下屏幕截图中显示的输出：

![使用参数运行脚本](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00014.jpeg)

如果我们想要打印`Hello <name>`，每个都在单独的行上，我们需要等一会儿，直到我们涵盖循环结构。for 循环将很好地实现这一点。

### 正确引用的重要性

到目前为止，我们已经使用了简单的双引号机制来包裹我们想要在 echo 中使用的字符串。

在第一个脚本中，无论我们使用单引号还是双引号都无所谓。`echo "Hello World"`将与`echo 'Hello World'`完全相同。

然而，在第二个脚本中情况就不同了，因此了解 bash 中可用的引用机制非常重要。

正如我们所见，使用双引号`echo "Hello $1"`将导致**Hello fred**或提供的值。而如果我们使用单引号`echo 'Hello $1'`，则屏幕上打印的输出将是**Hello $1**，我们看到变量名称而不是其值。

引号的作用是保护特殊字符，例如两个单词之间的空格；两个引号都保护空格不被解释。空格通常被 shell 读取为默认字段，由 shell 分隔。换句话说，所有字符都被 shell 读取为没有特殊含义的文字。这会导致`$`符号打印其文字格式，而不是允许 bash 扩展其值。由于被单引号保护，bash shell 无法扩展变量的值。

这就是双引号拯救我们的地方。双引号将保护除`$`之外的所有字符，允许 bash 扩展存储的值。

如果我们需要在带引号的字符串中使用文字`$`以及需要扩展的变量；我们可以使用双引号，但用反斜杠(`\`)转义所需的`$`。例如，`echo "$USER earns \$4"`将打印为**Fred earns $4**，如果当前用户是 Fred 的话。

尝试在命令行中使用所有引用机制尝试以下示例。随时根据需要提高您的小时费率：

```
$ echo "$USER earns $4"
$ echo '$USER earns $4'
$ echo "$USER earns \$4"

```

以下屏幕截图显示了输出：

![正确引用的重要性](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00015.jpeg)

## 打印脚本名称

`$0`变量代表脚本名称，通常在使用说明中使用。由于我们还没有看条件语句，所以脚本名称将打印在显示的名称上方。

编辑你的脚本，使其读取 `$HOME/bin/hello2.sh` 的以下完整代码块：

```
#!/bin/bash
echo "You are using $0"
echo "Hello $*"
exit 0
```

命令的输出如下截图所示：

![打印脚本名称](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00016.jpeg)

如果我们不想打印路径，只想显示脚本的名称，我们可以使用 `basename` 命令，该命令从路径中提取名称。调整脚本，使第二行现在读取如下：

```
echo "You are using $(basename $0)"

```

`$(….)` 语法用于评估内部命令的输出。我们首先运行 `basename $0` 并将结果输入到一个未命名的变量中，用 `$` 表示。

新的输出将如下截图所示：

![打印脚本名称](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00017.jpeg)

使用反引号也可以实现相同的结果，这样不太容易阅读，但我们提到这一点是因为你可能需要理解和修改其他人编写的脚本。`$(….)` 语法的替代方法如下例所示：

```
echo "You are using 'basename $0'"

```

请注意，使用的字符是反引号，*而不是*单引号。在英国和美国键盘上，这些字符位于数字 *1* 键旁边的左上部分。

# 调试你的脚本

到目前为止，我们看到的脚本非常简单，几乎不会出错或需要调试。随着脚本的增长和包含条件语句的决策路径，我们可能需要使用一定级别的调试来更好地分析脚本的进展。

Bash 为我们提供了两个选项，`-v` 和 `-x`。

如果我们想查看脚本的详细输出以及脚本逐行评估的详细信息，我们可以使用 `-v` 选项。这可以在 shebang 中使用，但直接使用 bash 运行脚本通常更容易：

```
$ bash -v $HOME/bin/hello2.sh fred

```

在这个例子中，这是特别有用的，因为我们可以看到嵌入式 `basename` 命令的每个元素是如何处理的。第一步是删除引号，然后是括号。看一下以下输出：

![调试你的脚本](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00018.jpeg)

更常用的是 `-x` 选项，它显示命令的执行过程。了解脚本选择的决策分支是很有用的。以下是使用情况：

```
$ bash -x $HOME/bin/hello2.sh fred

```

我们再次看到首先评估了 `basename`，但我们没有看到运行该命令所涉及的更详细的步骤。接下来的截图捕获了命令和输出：

![调试你的脚本](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00019.jpeg)

# 总结

这标志着本章的结束，我相信你可能会发现这很有用。特别是对于那些刚开始使用 bash 脚本的人来说，本章一定已经为你打下了坚实的基础，你可以在此基础上建立你的知识。

我们首先确保 bash 是安全的，不容易受到嵌入式函数 shell-shock 的影响。有了安全的 bash，我们考虑了别名、函数等在命令之前检查的执行层次结构；了解这一点可以帮助我们规划一个良好的命名结构和定位脚本的路径。

很快，我们就开始编写简单的脚本，其中包含静态内容，但我们看到了使用参数添加灵活性有多么容易。脚本的退出代码可以使用 `$?` 变量读取，我们可以使用 `||` 和 `&&` 创建命令行列表，这取决于列表中前一个命令的成功或失败。

最后，我们通过查看脚本的调试来结束这一章。当脚本很简单时，实际上并不需要，但在以后增加复杂性时会很有用。

在下一章中，我们将创建交互式脚本，这些脚本在脚本执行期间读取用户的输入。


# 第二章：创建交互式脚本

在第一章的*使用 Bash 脚本的什么和为什么*中，我们学习了如何创建脚本以及使用一些基本元素。这些包括我们在执行脚本时可以传递的可选参数。在本章中，我们将通过使用 read shell 内置命令来扩展这一点，以允许交互式脚本。交互式脚本是在脚本执行期间提示信息的脚本。在这样做的过程中，我们将涵盖以下主题：

+   使用带有选项的`echo`

+   使用`read`的基本脚本

+   添加注释

+   使用提示增强`read`脚本

+   限制输入字符的数量

+   控制输入文本的可见性

+   简单的脚本来强化我们的学习

# 使用带有选项的 echo

到目前为止，在本书中，我们已经看到`echo`命令非常有用，并且将在我们的许多脚本中使用，如果不是全部。我们还看到这既是一个内置命令，也是一个命令文件。运行`echo`命令时，将使用内置命令，除非我们指定文件的完整路径。我们可以使用以下命令进行测试：

```
$ test -a echo

```

要获得内置命令的帮助，我们可以使用`man bash`并搜索`echo`；但是，`echo`命令与内部命令相同，因此我建议您在大多数情况下使用`man echo`来显示命令选项。

到目前为止，我们已经看到的`echo`的基本用法将产生文本输出和一个新行。这通常是期望的响应，所以我们不必担心下一个提示会附加到输出的末尾。新行将脚本输出与下一个 shell 提示分隔开。如果我们不提供任何文本字符串来打印，`echo`将只打印新行到`STDOUT`。我们可以直接从命令行使用以下命令进行测试。我们不需要从脚本运行`echo`或者实际上运行任何其他命令。从命令行运行`echo`将简单地输入如下命令：

```
$ echo

```

输出将显示我们发出的命令和随后的提示之间的清晰新行。我们可以在下面的截图中看到这一点：

![使用带有选项的 echo](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00020.jpeg)

如果我们想要抑制新行，特别是在提示用户时非常有用，我们可以通过以下两种方式使用`echo`来实现：

```
$ echo -n "Which directory do you want to use? "
$ echo -e "Which directory do you want to use? \c"

```

结果将是抑制换行。在初始示例中，使用`-n`选项来抑制换行。第二个示例使用更通用的`-e`选项，允许在文本字符串中添加转义序列。为了在同一行上继续，我们使用`\c`作为转义序列。

这看起来不太好，作为脚本的最后部分或者从命令行运行时，命令提示符将会跟随。如下截图所示：

![使用带有选项的 echo](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00021.jpeg)

# 使用 read 的基本脚本

当作为提示用户输入的脚本的一部分使用时，抑制换行正是我们想要的。我们将首先将现有的`hello2.sh`脚本复制到`hello3.sh`，并构建一个交互式脚本。最初，我们将使用`echo`作为提示机制，但随着我们逐渐增强脚本，我们将直接从 shell 内置的`read`命令生成提示：

```
$ cp $HOME/bin/hello2.sh $HOME/bin/hello3.sh
$ chmod +x $HOME/bin/hello3.sh

```

编辑`$HOME/bin/hello3.sh`脚本，使其读取如下内容：

```
#!/bin/bash
echo -n "Hello I  $(basename $0) may I ask your name: "
read
echo "Hello $REPLY"
exit 0
```

当执行脚本时，我们将被问候并提示输入我们自己的名字。这是使用`echo`语句中的`$REPLY`变量回显出来的。由于我们尚未向`read`内置命令提供变量名，因此使用了默认的`$REPLY`变量。脚本执行和输出如下截图所示。花些时间在您自己的系统上练习脚本：

![使用 read 的基本脚本](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00022.jpeg)

这一小步已经让我们走了很长的路，而且像这样的脚本有很多用途，我们都使用过提示选项和目录的安装脚本。我承认这仍然相当琐碎，但随着我们深入本章，我们将更接近一些更有用的脚本。

# 脚本注释

我们应该在脚本的早期引入注释。脚本注释以`#`符号开头。`#`符号之后的任何内容都是注释，不会被脚本评估。shebang，`#!/bin/bash`，主要是一个注释，因此不会被脚本评估。运行脚本的 shell 读取 shebang，因此知道要将脚本交给哪个命令解释器。注释可以位于行的开头或部分位置。Shell 脚本没有多行注释的概念。

如果您还不熟悉注释，那么它们被添加到脚本中，告诉所有关于谁编写了脚本，脚本是何时编写和最后更新的，以及脚本的功能。这是脚本的元数据。

以下是脚本中注释的示例：

```
#!/bin/bash
# Welcome script to display a message to users on login
# Author: @theurbanpenguin
# Date: 1/1/1971
```

注释和添加解释代码正在做什么以及为什么是一个很好的做法。这将帮助您和需要在以后编辑脚本的同事。

# 使用 read 提示增强脚本

我们已经看到了如何使用内置的 read 来填充一个变量。到目前为止，我们已经使用`echo`来生成提示，但是这可以通过`-p`选项传递给 read 本身。`read`命令将忽略额外的换行符，因此在一定程度上减少了行数和复杂性。

我们可以在命令行本身测试这个。尝试输入以下命令以查看`read`的运行情况：

```
$ read -p "Enter your name: " name

```

我们使用`read`命令和`-p`选项。跟在选项后面的参数是出现在提示中的文本。通常，我们会确保文本末尾有一个空格，以确保我们可以清楚地看到我们输入的内容。这里提供的最后一个参数是我们想要填充的变量，我们简单地称之为`name`。变量也是区分大小写的。即使我们没有提供最后一个参数，我们仍然可以存储用户的响应，但这次是在`REPLY`变量中。

### 提示

请注意，当我们返回变量的值时，我们使用`$`，但在写入变量时不使用。简单来说，当读取变量时，我们引用`$VAR`，当设置变量时，我们引用`VAR=value`。

以下插图显示了使用`-p`选项的`read`命令的语法：

![使用 read 提示增强脚本](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00023.jpeg)

我们可以编辑脚本，使其看起来类似于`hello3.sh`中的以下片段：

```
#!/bin/bash
read -p "May I ask your name: " name
echo "Hello $name"
exit 0
```

`read`提示不能评估消息字符串中的命令，就像我们以前使用的那样。

# 限制输入字符的数量

到目前为止，我们使用的脚本不需要功能，但是我们可能需要要求用户按任意键继续。目前，我们已经设置了这样的方式，即在按下*Enter*键之前变量不会被填充。用户必须按*Enter*键继续。如果我们使用`-n`选项后跟一个整数，我们可以指定在继续之前要接受的字符，这里我们将设置为`1`。看一下以下代码片段：

```
#!/bin/bash
read -p "May I ask your name: " name
echo "Hello $name"
read -n1 -p "Press any key to exit"
echo
exit 0
```

现在，脚本将在显示名称后暂停，直到我们按下任意键；实际上，我们可以在继续之前按下任意键，因为我们只接受`1`个按键。而在之前，我们需要保留默认行为，因为我们无法知道输入的名称有多长。我们必须等待用户按*Enter*键。

### 提示

请注意，我们在这里添加了额外的 echo 以确保脚本结束前发出一个新行。这确保了 shell 提示从新行开始。

# 控制输入文本的可见性

尽管我们将输入限制为单个字符，但我们确实可以在屏幕上看到文本。同样，如果我们输入名称，我们会在按下*Enter*之前看到输入的文本。在这种情况下，这只是不整洁，但如果我们输入敏感数据，比如 PIN 码或密码，我们应该隐藏文本。我们可以使用静默选项或`-s`来实现这一点。在脚本中进行简单编辑即可实现这一点：

```
#!/bin/bash
read -p "May I ask your name: " name
echo "Hello $name"
read -sn1 -p "Press any key to exit"
echo
exit 0
```

现在，当我们使用键继续时，它不会显示在屏幕上。我们可以在下面的截图中看到脚本的行为：

![控制输入文本的可见性](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00024.jpeg)

# 通过简单脚本增强学习

我们的脚本仍然有点琐碎，我们还没有看条件语句，所以我们可以测试正确的输入，但让我们看一些简单的脚本，我们可以用一些功能来构建。

## 使用脚本进行备份

现在我们已经创建了一些脚本，我们可能希望将它们备份到不同的位置。如果我们创建一个提示我们的脚本，我们可以选择要备份的位置和文件类型。

考虑以下脚本作为您的第一个练习。创建脚本并将其命名为`$HOME/backup.sh`：

```
#!/bin/bash
# Author: @theurbanpenguin
# Web: www.theurbapenguin.com
# Script to prompt to back up files and location
# The files will be search on from the user's home
# directory and can only be backed up to a directory
# within $HOME
# Last Edited: July 4 2015
read -p "Which file types do you want to backup " file_suffix
read -p "Which directory do you want to backup to " dir_name
# The next lines creates the directory if it does not exist
test -d $HOME/$dir_name || mkdir -m 700 $HOME/$dir_name
# The find command will copy files the match the
# search criteria ie .sh . The -path, -prune and -o
# options are to exclude the backdirectory from the
# backup.
find $HOME -path $HOME/$dir_name -prune -o \
 -name "*$file_suffix" -exec cp {} $HOME/$dir_name/ \;
exit 0
```

您会看到文件被注释了；尽管黑白的可读性有点困难。如果您有这本书的电子副本，您应该在下面的截图中看到颜色：

![使用脚本进行备份](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00025.jpeg)

当脚本运行时，您可以选择`.sh`文件进行备份，并将`backup`作为目录。脚本执行如下截图所示，以及目录的列表：

![使用脚本进行备份](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00026.jpeg)

现在您可以看到，如果我们可以开始创建有意义的脚本，尽管我强烈建议添加错误检查用户输入，如果这个脚本不是用于个人使用。随着我们进入书籍，我们将涵盖这一点。

## 连接到服务器

让我们看一些实用的脚本，我们可以用来连接服务器。首先，我们将查看 ping，然后在第二个脚本中，我们将查看提示 SSH 凭据。

## 版本 1 - ping

这是我们所有人都可以做到的，不需要特殊的服务。这将简化控制台用户可能不了解命令细节的`ping`命令。这将对服务器进行三次 ping 而不是正常的无限次数。如果服务器存活，则没有输出，但如果服务器失败，则报告`服务器死机`。将脚本创建为`$HOME/bin/ping_server.sh`：

```
#!/bin/bash
# Author: @theurbanpenguin
# Web: www.theurbapenguin.com
# Script to ping a server
# Last Edited: July 4 2015
read -p "Which server should be pinged " server_addr
ping -c3 $server_addr 2>&1 > /dev/null || echo "Server dead"
```

以下截图显示了成功和失败的输出：

![版本 1 - ping](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00027.jpeg)

## 版本 2 - SSH

通常在服务器上安装并运行 SSH，因此如果您的系统正在运行 SSH 或者您可以访问 SSH 服务器，您可能可以运行此脚本。在此脚本中，我们提示服务器地址和用户名，并将它们传递给 SSH 客户端。将脚本创建为`$HOME/bin/connect_server.sh`：

```
#!/bin/bash
# Author: @theurbanpenguin
# Web: www.theurbapenguin.com
# Script to prompt fossh connection
# Last Edited: July 4 2015
read -p "Which server do you want to connect to: " server_name
read -p "Which username do you want to use: " user_name
ssh ${user_name}@$server_name
```

### 提示

请注意脚本最后一行中使用大括号来将变量与`@`符号分隔。

## 版本 3 - MySQL/MariaDB

在下一个脚本中，我们将提供数据库连接的详细信息以及要执行的 SQL 查询。如果您的系统上有 MariaDB 或 MySQL 数据库服务器，或者您可以连接到一个，您将能够运行此脚本。为演示，我将使用运行 Ubuntu-Mate 15.04 和 MariaDB 版本 10 的 Raspberry Pi；然而，这对于任何 MySQL 服务器或从版本 5 开始的 MariaDB 都应该适用。脚本收集用户和密码信息以及要执行的 SQL 命令。将脚本创建为`$HOME/bin/run_mql.sh`：

```
#!/bin/bash
# Author: @theurbanpenguin
# Web: www.theurbapenguin.com
# Script to prompt for MYSQL user password and command
# Last Edited: July 4 2015
read -p "MySQL User: " user_name
read -sp "MySQL Password: " mysql_pwd
echo
read -p "MySQL Command: " mysql_cmd
read -p "MySQL Database: " mysql_db
mysql -u $user_name -p$mysql_pwd$mysql_db -e"$mysql_cmd"
```

在脚本中，我们可以看到当我们将 MySQL 密码输入到`read`命令中时，我们使用`-s`选项来抑制密码的显示。同样，我们直接使用`echo`来确保下一个提示从新的一行开始。

脚本输入如下截图所示：

![版本 3 - MySQL/MariaDB](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00028.jpeg)

现在，我们可以轻松地看到密码抑制的工作原理，以及向 MySQL 命令添加的便利性。

# 总结

为自己的 shell 脚本拥有“我会读”的徽章感到自豪。我们已经开发了交互式脚本，并在脚本执行过程中提示用户输入。这些提示可以用来简化用户在命令行上的操作。这样，他们就不需要记住命令行选项，也不会在命令行历史中存储密码。在使用密码时，我们可以使用`read -sp`选项来静默存储值。

在下一章中，我们将花时间来研究 bash 中的条件语句。


# 第三章：附加条件

我想我们现在可以说我们已经进入了脚本的细节部分。这些是使用条件编写到我们的脚本中的细节，用于测试语句是否应该运行。我们现在准备在脚本中添加一些智能，使我们的脚本变得更健壮，更易于使用和更可靠。条件语句可以用简单的命令行列表`AND`或`OR`命令一起编写，或者更常见的是在传统的`if`语句中。

在本章中，我们将涵盖以下主题：

+   使用命令行列表进行简单决策路径

+   使用列表验证用户输入

+   使用测试 shell 内置

+   使用`if`创建条件语句

+   使用`else`扩展`if`

+   使用`elif`添加更多条件

+   使用`elif`创建`backup.sh`脚本

+   使用 case 语句

+   脚本-使用`grep`的前端

# 使用命令行列表进行简单决策路径

我们在本书的第一章和第二章中的一些脚本中都使用了命令行列表。列表是我们可以创建的最简单的条件语句之一，因此我们认为在完全解释它们之前，在早期的示例中使用它们是合适的。

命令行列表是使用`AND`或`OR`符号连接的两个或多个语句：

+   `&&`: `AND`

+   `||`: `OR`

两个语句使用`AND`符号连接时，只有在第一个命令成功运行时，第二个命令才会运行。而使用`OR`符号连接时，只有在第一个命令失败时，第二个命令才会运行。

命令的成功或失败取决于从应用程序读取的退出代码。零表示应用程序成功完成，而非零表示失败。我们可以通过读取系统变量`$?`来测试应用程序的成功或失败。下面是一个示例：

```
$ echo $?

```

如果我们需要确保脚本是从用户的主目录运行的，我们可以将这个构建到脚本的逻辑中。这可以从命令行测试，不一定要在脚本中。考虑以下命令行示例：

```
$ test $PWD == $HOME || cd $HOME

```

双竖线表示`OR`列表。这确保了只有在第一个语句不成立时才执行第二个语句。简单来说，如果我们当前不在主目录中，那么在命令行列表结束时我们会在主目录中。我们很快会在测试命令中看到更多内容。

我们可以将这个应用到几乎任何我们想要的命令，而不仅仅是测试。例如，我们可以查询用户是否已登录到系统，如果是，我们可以使用`write`命令直接向他们的控制台发送消息。与之前类似，我们可以在脚本之前在命令行中测试这个。下面是一个命令行示例：

```
$ who | grep pi > /dev/null 2>&1 && write pi < message.txt

```

如果我们在脚本中使用这个，几乎可以肯定我们会用变量替换用户名。一般来说，如果我们需要多次引用相同的值，那么使用变量是个好主意。在这种情况下，我们正在搜索`pi`用户。

当我们分解命令行列表时，我们首先使用`who`命令列出已登录的用户。我们将列表传输到`grep`以搜索所需的用户名。我们对搜索的输出不感兴趣，只关心成功或失败。考虑到这一点，我们将所有输出重定向到`/dev/null`。双和符号表示只有在第一个语句返回 true 时，列表中的第二个语句才运行。如果`pi`用户已登录，我们使用`write`向用户发送消息。以下截图说明了这个命令和输出。

![使用命令行列表进行简单决策路径](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00029.jpeg)

# 使用列表验证用户输入

在这个脚本中，我们将确保第一个位置参数已经被提供了一个值。我们可以修改我们在第一章中创建的`hello2.sh`脚本，*使用 Bash 进行脚本编写的什么和为什么*，在显示`hello`文本之前检查用户输入。

您可以将`hello2.sh`脚本复制到`hello4.sh`，或者从头开始创建一个新的脚本。输入的内容不会很多，脚本将被创建为`$HOME/bin/hello4.sh`，如下所示：

![使用列表验证用户输入](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00030.jpeg)

我们可以使用以下命令确保脚本是可执行的：

```
$ chmod +x $HOME/bin/hello4.sh

```

然后我们可以带参数或不带参数运行脚本。`test`语句正在寻找`$1`变量是否为零字节。如果是，那么我们将看不到`hello`语句；否则它将打印**Hello**消息。简单来说，如果我们提供一个名字，我们将看到`hello`消息。

以下屏幕截图显示了当您没有向脚本提供参数时会看到的输出，然后是提供的参数：

![使用列表验证用户输入](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00031.jpeg)

# 使用测试 shell 内置

现在可能是时候我们停下来，看一看这个`test`命令。这既是一个 shell 内置命令，也是一个独立的可执行文件。当然，除非我们指定文件的完整路径，否则我们将首先使用内置命令。

当运行测试命令而没有任何表达式要评估时，测试将返回 false。因此，如果我们运行如下命令所示的测试：

```
$ test

```

退出状态将是`1`，即使没有显示错误输出。`test`命令将始终返回`True`或`False`或`0`或`1`。`test`的基本语法是：

```
test EXPRESSION

```

或者，我们可以使用以下命令来反转`test`命令：

```
test ! EXPRESSION

```

如果我们需要包含多个表达式，这些表达式可以使用`-a`和`-o`选项分别进行`AND`或`OR`连接：

```
test EXPRESSION -a EXPRESSION
test EXPRESSION -o EXPRESSION

```

我们还可以以简写版本编写，用方括号替换测试以包围表达式，如下例所示：

```
[ EXPRESION ]

```

## 测试字符串

我们可以测试两个字符串的相等或不相等。例如，测试 root 用户的一种方法是使用以下命令：

```
test $USER = root

```

我们也可以使用方括号表示法来编写这个：

```
[ $USER = root ]

```

同样，我们可以使用以下两种方法测试非 root 帐户：

```
test ! $USER = root
[ ! $USER = root ]

```

我们还可以测试字符串的零值和非零值。我们在本章的早些时候的一个示例中看到了这一点。

要测试字符串是否有值，我们可以使用`-n`选项。我们可以通过检查用户环境中变量的存在来检查当前连接是否是通过 SSH 进行的。我们在以下两个示例中使用`test`和方括号来展示这一点：

```
test -n $SSH_TTY
[ -n $SSH_TTY ]

```

如果这是真的，那么连接是通过 SSH 建立的；如果是假的，那么连接不是通过 SSH。

正如我们之前看到的，当决定一个变量是否设置时，测试零字符串值是有用的：

```
test -z $1

```

或者，更简单地，我们可以使用：

```
[ -z $1 ]

```

对于这个查询的真实结果意味着没有输入参数被提供给脚本。

## 测试整数

此外，bash 脚本的测试字符串值可以测试整数值和整数。测试脚本的另一种方法是计算位置参数的数量，并测试该数字是否大于`0`：

```
test $# -gt 0
```

或者使用括号，如下所示：

```
[ $# -gt 0 ]
```

在关系中，顶部位置参数变量`$#`表示传递给脚本的参数数量。要测试整数值的相等性，使用`-eq`选项，而不是`=`符号。

## 测试文件类型

在测试值时，我们可以测试文件的存在或文件类型。例如，我们可能只想在文件是符号链接时才删除文件。我在编译内核时使用这个功能。`/usr/src/linux`目录应该是最新内核源代码的符号链接。如果我在编译新内核之前下载了更新版本，我需要删除现有的链接并创建新的链接。以防万一有人创建了`/usr/src/linux`目录，我们可以在删除之前测试它是否是一个链接：

```
# [ -h /usr/src/linux ] &&rm /usr/src/linux

```

`-h`选项测试文件是否有链接。其他选项包括：

+   `-d`：这显示它是一个目录

+   `-e`：这显示文件以任何形式存在

+   `-x`：这显示文件是可执行的

+   `-f`：这显示文件是一个普通文件

+   `-r`：这显示文件是可读的

+   `-p`：这显示文件是命名管道

+   `-b`：这显示文件是块设备

+   `-c`：这显示文件是字符设备

还有更多选项存在，因此根据需要深入主页。我们将在整本书中使用不同的选项；因此，为您提供实用和有用的示例。

# 使用 if 创建条件语句

正如我们迄今所见，可以使用命令行列表构建简单的条件。这些条件可以使用测试和不使用测试来编写。随着任务复杂性的增加，使用`if`创建语句将更容易。这肯定会提高脚本的可读性和逻辑布局。在某种程度上，它也符合我们的思维和语言表达方式，`if`在我们的口语中和 bash 脚本中都是语义的一部分。

即使在脚本中占用多行，使用`if`语句也可以实现更多功能并使脚本更易读。说了这些，让我们来看看如何创建`if`条件。以下是使用`if`语句的脚本示例：

```
#!/bin/bash
# Welcome script to display a message to users
# Author: @theurbanpenguin
# Date: 1/1/1971
if [ $# -lt 1 ] ; then
echo "Usage: $0 <name>"
exit 1
fi
echo "Hello $1"
exit 0
```

`if`语句内的代码仅在条件评估为真时运行，`if`块的结尾用`fi`表示-`if`反过来。在`vim`中的颜色编码可以帮助提高可读性，您可以在以下截图中看到：

![使用 if 创建条件语句](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00032.jpeg)

在脚本中，我们可以轻松添加多个语句以在条件为真时运行。在我们的情况下，这包括使用错误指示退出脚本，以及使用`usage`语句来帮助用户。这确保我们只在提供要欢迎的名称时才显示**Hello**消息。

我们可以在以下截图中查看带有参数和不带参数的脚本执行：

![使用 if 创建条件语句](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00033.jpeg)

为了帮助我们理解`if`条件语句的布局，以下插图演示了使用伪代码的语法：

![使用 if 创建条件语句](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00034.jpeg)

缩进代码并非必需，但有助于可读性，强烈建议这样做。将`then`语句添加到与`if`相同的行上，同样有助于代码的可读性，并且分号是必需的，用于将`if`与`then`分隔开来。

# 使用 else 扩展 if

当脚本需要继续执行而不管`if`条件的结果时，通常需要处理评估的两种条件。当条件为真时该怎么办，以及当条件评估为假时该怎么办。这就是我们可以使用`else`关键字的地方。这允许在条件为真时执行一块代码，在条件为假时执行另一块代码。下图显示了这种情况的伪代码：

![使用 else 扩展 if](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00035.jpeg)

如果我们考虑扩展之前创建的`hello5.sh`脚本，可以轻松地实现无论参数是否存在都能正确执行。我们可以将其重新创建为`hello6.sh`，如下所示：

```
#!/bin/bash
# Welcome script to display a message to users
# Author: @theurbanpenguin
# Date: 1/1/1971
if [ $# -lt 1 ] ; then
read -p "Enter a name: "
name=$REPLY
else
name=$1
fi
echo "Hello $name"
exit 0
```

脚本现在设置了一个命名变量，这有助于可读性，我们可以从输入参数或`read`提示中为`$name`分配正确的值，无论哪种方式，脚本都能正常工作并开始成形。

# 更多的 elif 条件

当我们需要更高程度的控制时，我们可以使用`elif`关键字。与`else`不同，`elif`需要为每个`elif`测试额外的条件。通过这种方式，我们可以应对不同的情况。我们可以添加尽可能多的`elif`条件。以下是伪代码示例：

```
if condition; then
statement
elif condition; then
statement
else
statement
fi
exit 0
```

脚本可以通过提供更简化的选择来为操作员提供更复杂的代码。尽管脚本逐渐变得更加复杂以满足要求，但对于操作员来说，执行变得大大简化了。我们的工作是使用户能够轻松地从命令行运行更复杂的操作。通常，这将需要向我们的脚本添加更多的复杂性；然而，我们将获得脚本化应用的可靠性。

## 使用 elif 创建 backup2.sh

我们可以重新查看我们创建的用于运行之前备份的脚本。这个脚本`$HOME/bin/backup.sh`提示用户选择文件类型和存储备份的目录。备份使用的工具是`find`和`cp`。

有了这些新的知识，我们现在可以允许脚本使用`tar`命令和操作员选择的压缩级别运行备份。无需选择文件类型，因为完整的主目录将被备份，不包括备份目录本身。

操作员可以根据三个字母`H`、`M`和`L`选择压缩。选择将影响传递给`tar`命令的选项和创建的备份文件。选择高将使用`bzip2`压缩，中使用`gzip`压缩，低创建一个未压缩的`tar`存档。这个逻辑存在于后续的扩展`if`语句中：

```
if [ $file_compression = "L" ] ; then
tar_opt=$tar_l
elif [ $file_compression = "M" ]; then
tar_opt=$tar_m
else
tar_opt=$tar_h
fi
```

根据用户的选择，我们可以为`tar`命令配置正确的选项。由于我们有三个条件需要评估，因此适合使用`if`、`elif`和`else`语句。要查看变量是如何配置的，我们可以查看脚本中的以下摘录：

```
tar_l="-cvf $backup_dir/b.tar --exclude $backup_dir $HOME"
tar_m="-czvf $backup_dir/b.tar.gz --exclude $backup_dir $HOME"
tar_h="-cjvf $backup_dir/b.tar.bzip2 --exclude $backup_dir $HOME"
```

完整的脚本可以创建为`$HOME/bin/backup2.sh`，应该读取如下代码：

```
#!/bin/bash
# Author: @theurbanpenguin
# Web: www.theurbapenguin.com
read -p "Choose H, M or L compression " file_compression
read -p "Which directory do you want to backup to " dir_name
# The next lines creates the directory if it does not exist
test -d $HOME/$dir_name || mkdir -m 700 $HOME/$dir_name
backup_dir=$HOME/$dir_name
tar_l="-cvf $backup_dir/b.tar --exclude $backup_dir $HOME"
tar_m="-czvf $backup_dir/b.tar.gz --exclude $backup_dir $HOME"
tar_h="-cjvf $backup_dir/b.tar.bzip2 --exclude $backup_dir $HOME"
if [ $file_compression = "L" ] ; then
tar_opt=$tar_l
elif [ $file_compression = "M" ]; then
tar_opt=$tar_m
else
tar_opt=$tar_h
fi
tar $tar_opt
exit 0
```

当我们执行脚本时，需要以大写字母选择`H`、`M`或`L`，因为这是脚本内部进行选择的方式。以下截图显示了初始脚本执行，选择了`M`：

![使用 elif 创建 backup2.sh](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00036.jpeg)

# 使用 case 语句

与使用多个`elif`语句不同，当对单个表达式进行评估时，`case`语句可能提供了更简单的机制。

使用伪代码列出了`case`语句的基本布局：

```
case expression in
 case1) 
  statement1
  statement2
 ;;
 case2)
  statement1
  statement2
 ;;
 *)
  statement1
 ;;
esac
```

我们看到的语句布局与其他语言中存在的`switch`语句并没有太大不同。在 bash 中，我们可以使用`case`语句测试简单的值，比如字符串或整数。Case 语句可以适用于各种字母，比如`[a-f]`或`a`到`f`，但它们不能轻松处理整数范围，比如`[1-20]`。

`case`语句首先会展开表达式，然后尝试依次与每个项目进行匹配。当找到匹配时，所有语句都会执行直到`;;`。这表示该匹配的代码结束。如果没有匹配，将匹配`*`表示的`else`语句。这需要是列表中的最后一项。

考虑以下脚本`grade.sh`，用于评估成绩：

```
#!/bin/bash
# Script to evaluate grades
# Usage: grade.sh student grade
# Author: @theurbanpenguin
# Date: 1/1/1971
if [ ! $# -eq2 ] ; then
echo "You must provide <student><grade>
exit 2
fi
case $2 in
  [A-C]|[a-c]) echo "$1 is a star pupil"
  ;;
  [Dd]) echo "$1 needs to try a little harder!"
  ;;
  [E-F]|[e-f]) echo "$1 could do a lot better next year"
  ;;
  *) echo "Grade could not be evaluated for $1"
esac
```

脚本首先使用`if`语句检查脚本是否提供了确切的两个参数。如果没有提供，脚本将以错误状态退出：

```
if [ ! $# -eq2 ] ; then
echo "You must provide <student><grade>
exit 2
fi
```

然后`case`语句扩展表达式，这是在这个例子中的`$2`变量的值。这代表我们提供的等级。然后我们尝试首先匹配大写和小写的字母`A`到`C`。`[A-C]`用于匹配`A`或`B`或`C`。竖线然后添加了一个额外的`OR`来与`a`、`b`或`c`进行比较：

```
[A-C]|[a-c]) echo "$1 is a star pupil"
;;
```

我们对其他提供的等级`A`到`F`进行了类似的测试。

以下屏幕截图显示了不同等级的脚本执行：

![使用 case 语句](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00037.jpeg)

# 脚本-使用 grep 构建前端

作为本章的结束，我们可以将我们学到的一些功能组合在一起，构建一个脚本，提示操作员输入文件名、搜索字符串和要使用`grep`命令执行的操作。我们可以将脚本创建为`$HOME/bin/search.sh`，不要忘记将其设置为可执行文件：

```
#!/bin/bash
#Author: @theurbanpenguin
usage="Usage: search.sh file string operation"

if [ ! $# -eq3 ] ; then
echo "$usage"
exit 2
fi

[ ! -f $1 ]&& exit 3

case $3 in
    [cC])
mesg="Counting the matches in $1 of $2"
opt="-c"
    ;;
    [pP])
mesg="Print the matches of $2 in $1"
        opt=""
    ;;
    [dD])
mesg="Printing all lines but those matching $3 from $1"
opt="-v"
    ;;
    *) echo "Could not evaluate $1 $2 $3";;
esac
echo $mesg
grep $opt $2 $1
```

我们首先通过以下代码检查是否有三个输入参数：

```
if [ ! $# -eq3 ] ; then
echo "$usage"
exit 2
fi
```

下一个检查使用命令行列表来退出脚本，如果文件参数不是常规文件，则使用`test -f`：

```
[ ! -f $1 ]&& exit 3
```

`case`语句允许三种操作：

+   计算匹配的行数

+   打印匹配的行

+   打印除匹配行之外的所有行

以下屏幕截图显示了在`/etc/ntp.conf`文件中搜索以字符串 server 开头的行。在这个例子中，我们选择了计数选项：

![脚本-使用 grep 构建前端](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00038.jpeg)

# 摘要

在脚本编写中最重要且耗时的任务之一是构建所有我们需要使脚本可用和健壮的条件语句。经常提到 80-20 法则。这是指你花费 20%的时间编写主要脚本，80%的时间用于确保脚本中正确处理所有可能的情况。这就是我所说的脚本的程序完整性，我们试图仔细和准确地涵盖每种情况。

我们首先查看了一个简单的命令行列表测试。如果需要的操作很简单，那么这些功能提供了很好的功能，并且很容易添加。如果需要更复杂的功能，我们将添加`if`语句。

使用`if`语句，我们可以根据需要扩展它们，使用`else`和`elif`关键字。不要忘记`elif`关键字需要它们自己的条件来评估。

最后，我们看到了如何在需要评估单个表达式的情况下使用`case`。

在下一章中，我们将了解从已准备好的代码片段中读取的重要性。我们将创建一个样本`if`语句，可以保存为代码片段，在编辑时读入脚本。


# 第四章：创建代码片段

如果您喜欢使用命令行，但也喜欢使用图形**集成开发环境**（**IDE**）的一些功能，那么本章可能会为您揭示一些新的想法。我们可以使用命令行中的`vi`或`vim`文本编辑器为常用的脚本元素创建快捷方式。

在本章中，我们将涵盖以下主题：

+   在`.vimrc`中创建缩写

+   使用`vim`文本编辑器阅读片段

+   在终端中使用颜色

# 缩写

我们已经短暂地进入了`~/.vimrc`文件，现在我们将重新访问这个文件，看看缩写或`abbr`控制。这个文件充当了`vim`文本编辑器的运行控制机制，很可能已经安装在您的 Linux 发行版上。旧的发行版或 Unix 变种可能会有原始的`vi`文本编辑器，并且会使用`~/.exrc`文件。如果您不确定您的`vi`版本的身份和要使用的正确运行控制文件，只需输入`vi`命令。如果打开了一个空白页面，那么确实是`vi`。但是，如果打开了带有`vim`启动屏幕的新空白文档，那么您正在使用改进的`vim`或`Vi`。

缩写允许在较长的字符串的位置使用快捷字符串。这些缩写可以在`vim`会话中从最后一行模式设置，但通常在控制文件中设置。shebang 可以很容易地表示为一个缩写，如下所示：

```
abbr _sh #!/bin/bash
```

缩写的基本语法如下命令所示：

```
abbr <shortcut><string>
```

使用这个缩写，我们只需要在编辑模式下输入`_sh`。在输入快捷代码后按下*ENTER*键，shebang 的完整文本就会打印出来。实际上，不仅仅是*ENTER*键，按下`abbr`代码后的任意键都会展开快捷方式。像这样的简单元素可以大大增加使用`vim`作为我们的文本编辑器的体验。下面的截图显示了更新后的`~/.vimrc`文件：

![Abbreviations](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00039.jpeg)

我们不限于单个缩写代码，可以添加更多的`abbr`条目。例如，为了支持 Perl 脚本的 shebang，可以在行上添加：

```
abbr _pl #!/usr/bin/perl
```

下划线的使用并不是必需的，但目的是保持快捷代码的唯一性，避免输入错误。我们也不限于单行；尽管如此，缩写通常用于单行。考虑以下`if`语句的缩写：

```
abbr _if if [-z $1];then<CR>echo "> $0 <name><CR>exit 2<CR>fi
```

尽管这样做是有效的，但`if`语句的格式化不会完美，多行缩写远非理想。这就是我们可以考虑使用预先准备的代码片段的地方。

# 使用代码片段

我们所说的代码片段的含义只是准备好的代码，我们可以读入我们当前的脚本。这对于`vim`能够在编辑过程中读取其他文本文件的内容来说特别容易。

```
ESC
:r <path-and-filename>
```

例如，如果我们需要读取位于`$HOME/snippets`中的名为`if`的文件的内容，我们将在`vim`中使用以下键序列：

```
ESC
:r $HOME/snippets/if
```

该文件的内容被读入当前文档的当前光标位置下方。通过这种方式，我们可以使代码片段尽可能复杂，并保持正确的缩进以帮助可读性和一致性。

因此，我们将把创建一个片段目录放在我们的主目录中作为我们的职责：

```
$ mkdir -m 700 $HOME/snippets

```

不需要共享目录，因此在创建时将模式设置为`700`或私有用户是一个好习惯。

在创建代码片段时，您可以选择使用伪代码或真实示例。我更喜欢使用真实示例，这些示例经过编辑以反映接收脚本的要求。一个简单的`if`片段的内容将是：

```
if [ -z $1 ] ; then
    echo "Usage: $0 <name>"
    exit 2
fi
```

这为我们提供了创建带有实际示例的`if`语句的布局。在这种情况下，我们检查`$1`是否未设置，并在退出脚本之前向用户发送错误。关键在于保持片段简短，以限制需要进行的更改，但易于理解和扩展，根据需要。

## 给终端带来色彩

如果我们要向用户和执行脚本的操作员显示文本消息，我们可以提供颜色以帮助解释消息。使用红色作为错误的同义词，绿色表示成功，可以更轻松地为我们的脚本添加功能。并非所有，但肯定是绝大多数的 Linux 终端都支持颜色。内置命令`echo`在与`-e`选项一起使用时可以向用户显示颜色。

要以红色显示文本，我们可以使用`echo`命令，如下所示：

```
$ echo -e "\03331mError\033[0m"

```

以下截图显示了代码和输出：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00041.jpeg)
    
给终端带来色彩红色文本将立即引起注意，可能导致脚本执行失败。以这种方式使用颜色符合基本的应用设计原则。如果您觉得代码复杂，那么只需使用友好的变量来表示颜色和重置代码。在前面的代码中，我们使用了红色和最终的重置代码来将文本设置回 shell 默认值。我们可以轻松地为这些颜色代码和其他颜色创建变量：

```
RED="\03331m"
GREEN="\033[32m"
BLUE="\033[34m"
RESET="\033[0m"
```

### 提示

`\033`值是*ESCAPE*字符，`[31m`是红色的颜色代码。在使用变量时，我们需要小心，以确保它们与文本正确分隔。

修改前面的示例，我们可以看到如何轻松实现这一点：

```
$ echo -e ${RED}Error$RESET"
```

### 提示

我们使用大括号确保`RED`变量被识别并与`Error`单词分隔开。

将变量定义保存到`$HOME/snippets/color`文件中将允许它们在其他脚本中使用。有趣的是，我们不需要编辑这个脚本；我们可以使用`source`命令在运行时将这些变量定义读入脚本。在接收脚本中，我们需要添加以下行：

```
source $HOME/snippets/color
```

使用 shell 内置的`source`命令将颜色变量读入脚本执行时。以下截图显示了`hello5.sh`脚本的修改版本，现在我们称之为`hello7.sh`，它使用了这些颜色：

![给终端带来色彩当我们执行脚本时，我们可以看到这种效果。在下面的截图中，您将看到执行和输出，无论是否提供了参数：![给终端带来色彩](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00042.jpeg)

我们可以通过颜色编码的输出轻松识别脚本的成功和失败；绿色的**Hello fred**是我们提供参数的地方，红色的`Usage`语句是我们没有提供所需名称的地方。

# 摘要

对于任何管理员脚本重用始终是效率追求中的首要问题。在命令行使用`vim`可以快速有效地编辑脚本，并且可以节省缩写的输入。最好在用户的个人`.vimrc`文件中设置这些缩写，并使用`abbr`控制进行定义。除了缩写，我们可以看到使用代码片段的意义。这些是预先准备好的代码块，可以读入当前脚本。

最后，我们看了一下在命令行中使用颜色的价值，脚本将提供反馈。乍一看，这些颜色代码并不友好，但我们可以通过使用变量来简化这个过程。这些变量可以在脚本内在运行时设置，并通过`source`命令将它们的值读入当前环境。

在下一章中，我们将看看其他机制，我们可以使用它们来编写测试表达式，简化整数和变量的使用。


# 第五章：替代语法

在脚本编程的旅程中，我们已经看到我们可以使用`test`命令来确定条件状态。我们进一步发现，我们还可以使用单方括号。在这里，我们将回顾`test`命令，并更详细地查看单方括号。在更多了解方括号之后，我们将进入更高级的变量或参数管理；因此，提供默认值并理解引用问题。

最后，我们将看到在像 bash、korn 和 zsh 这样的高级 shell 中，我们可以使用双括号！利用双圆括号和双方括号可以简化整体语法，并允许使用数学符号的标准化。

在本章中，我们将涵盖以下主题：

+   测试条件

+   提供参数默认值

+   当有疑问时-引用！

+   使用`[[`进行高级测试

+   使用`((`进行高级测试

# 回顾测试

到目前为止，我们已经使用内置的`test`命令来驱动我们的条件语句。使用`test`的其他选项，我们可以查看返回的值来确定文件系统中文件的状态。运行没有任何选项的测试将返回一个错误的输出：

```
$ test

```

## 测试文件

通常，我们可以使用`test`来检查围绕文件的条件。例如，要测试文件是否存在，我们可以使用`-e`选项。以下命令将测试`/etc/hosts`文件的存在：

```
test -e /etc/hosts

```

我们可以再次运行此测试，但这次要检查文件不仅存在，而且是一个常规文件，而不是具有某些特殊目的。特定的文件类型可以是目录、管道、链接等。常规文件的选项是`-f`。

```
$ test -f /etc/hosts

```

## 添加逻辑

如果我们需要在脚本内部打开一个文件，我们将测试该文件既是常规文件，又具有读取权限。为了使用`test`实现这一点，我们还可以包括`-a`选项来将多个条件连接在一起。在以下示例代码中，我们将使用`-r`条件来检查文件是否可读：

```
$ test -f /etc/hosts -a -r /etc/hosts

```

同样，支持使用`-o`来`OR`表达式中的两个条件。

## 以前未见过的方括号

作为`test`命令的替代，我们可以使用单方括号来实现相同的条件测试。重复之前的条件测试并省略命令本身。我们将在以下代码中重写这一点：

```
 $ [ -f /etc/hosts -a -r /etc/hosts ]

```

许多时候，即使作为经验丰富的管理员，我们也习惯于语言元素，并接受它们。我觉得许多 Linux 管理员会惊讶地发现``既是一个 shell 内置命令，又是一个独立的文件。使用`type`命令，我们可以验证这一点：

```
$ type -a [

```

我们可以在以下截图中看到此命令的输出，确认其存在：

![以前未见过的方括号

我们可以看到，在我使用的 Raspbian 发行版中，有内置的`[`命令和`/usr/bin/[`命令。正如我们所见，这两个命令都模仿了`test`命令，但需要一个闭括号。

现在我们对在 bash 和早期的 Bourne shell 中找到的`[`命令有了更多了解，我们现在可以继续添加一些命令行列表语法。除了命令行列表，我们还可以在以下代码示例中看到所需的功能正在工作：

```
$ FILE=/etc/hosts
$ [ -f $FILE -a -r $FILE ] && cat $FILE

```

设置了参数`FILE`变量后，我们可以测试它既是常规文件，又可被用户读取，然后再尝试列出文件内容。这样，脚本就变得更加健壮，而无需复杂的脚本逻辑。我们可以在以下截图中看到代码的使用：

![以前未见过的方括号](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00044.jpeg)

这种缩写方式非常常见，很容易识别。如果缩写不增加可读性，我们应该谨慎使用。我们在编写脚本时的目标应该是编写清晰易懂的代码，避免不必要的快捷方式。

# 提供参数默认值

在 bash 参数中，有命名空间在内存中允许我们访问存储的值。参数有两种类型：

+   变量

+   特殊参数

特殊参数是只读的，并且由 shell 预设。变量由我们自己以及 bash 维护。一般来说，在谈论语法时，bash 会用参数的家族名称来指代变量。

## 变量

变量是一种参数类型。这些可以由系统或我们自己设置。例如，`$USER`是一个由系统设置但可以被我们编写的变量参数。因此，它不是特殊参数的只读要求。

## 特殊参数

特殊参数是第二种参数类型，由 shell 本身管理，并且呈现为只读。我们之前在参数中遇到过这些，比如`$0`，但让我们再看看另一个`$-`。我们可以扩展这些参数以了解它们的用途，使用`echo`命令：

```
$ echo "My shell is $0 and the shell options are: $-"

```

从我添加的注释文本中，我们可以理解`$-`选项代表配置的 shell 选项。这些可以使用`set -o`命令显示，但也可以使用`$-`在程序中读取。

我们可以在以下截图中看到这一点：

![特殊参数](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00045.jpeg)

这里设置的选项如下：

+   `h`: 这是 hashall，允许使用`PATH`参数找到程序

+   `i`: 这显示这是一个交互式 shell

+   `m`: 这是 monitor 的缩写，允许使用`bg`和`fg`命令将命令放入后台或从后台调出

+   `B`: 这允许大括号扩展或`mkdirdir{1,2}`，我们创建`dir1`和`dir2`

+   `H`: 这允许历史扩展或运行命令，比如`!501`来重复历史中的命令

## 设置默认值

使用`test`命令或括号，我们可以为变量提供默认值，包括命令行参数。拿我们之前使用过的`hello4.sh`脚本来说，如果`name`参数是零字节，我们可以修改它并设置它：

```
#!/bin/bash
name=$1
[ -z $name ] && name="Anonymous"
echo "Hello $name"
exit 0
```

这段代码是功能性的，但我们可以选择如何编写默认值。我们也可以直接为参数分配默认值。考虑以下代码，直接进行默认赋值：

```
name=${1-"Anonymous"}
```

在 bash 中，这被称为**参数替换**，可以用以下伪代码表示：

```
${parameter-default}
```

无论何处，如果一个变量（参数）没有被声明并且具有空值，将使用默认值。如果参数已经被显式声明为空值，我们将使用`:-`语法，如下例所示：

```
parameter=
${parameter:-default}
```

通过现在编辑脚本，我们可以创建`hello8.sh`来利用 bash 参数替换提供默认值：

```
#!/bin/bash
#Use parameter substitution to provide default value
name=${1-"Anonymous"}
echo "Hello $name"
exit 0
```

这个脚本及其输出，无论是否提供了值，都显示在以下的截图中：

![设置默认值](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00046.jpeg)

`hello8.sh`脚本提供了我们需要的功能，逻辑直接内置到参数赋值中。现在逻辑和赋值是脚本中的一行代码，这是保持脚本简单和可读性的重要一步。

# 当怀疑时 - 引用！

既然已经确定变量是一种参数，我们应该始终记住这一点，特别是在阅读手册和 HOWTO 时。文档经常提到参数，并在这样做时包括变量，以及 bash 特殊参数，如`$1`等。为此，我们将看看为什么在命令行或脚本中使用参数时最好引用这些参数。现在学习这一点可以在以后节省我们很多痛苦和心痛，特别是当我们开始研究循环时。

首先，我们应该用于读取变量值的正确术语是**参数扩展**。对你和我来说，这是读取一个变量，但对 bash 来说这太简单了。正确的命名，比如参数扩展，减少了任何对其含义的歧义，但同时增加了复杂性。在下面的例子中，代码的第一行将`fred`的值分配给`name`参数。代码的第二行使用参数扩展来打印存储在内存中的值。`$`符号用于允许参数的扩展：

```
$ name=fred
$ echo "The value is: $name"

```

在这个例子中，我们使用了双引号来允许`echo`打印单个字符串，因为我们使用了空格。如果不使用引号，echo 可能会将其视为多个参数。空格是大多数 shell（包括 bash）中的默认字段分隔符。通常，当我们没有考虑使用引号时，我们看不到直接的空格。考虑我们之前使用的命令行代码的以下摘录：

```
$ FILE=/etc/hosts
$ [ -f $FILE -a -r $FILE ] && cat $FILE

```

尽管这样可以工作，我们可能有点幸运，特别是如果我们正在从我们自己没有创建的文件列表中填充`FILE`参数。一个文件可能在其名称中包含空格是很有可能的。现在让我们使用不同的文件重新播放这段代码。考虑以下命令：

```
$ FILE="my file"
$ [ -f $FILE -a -r $FILE ] && cat $FILE

```

尽管在结构上代码没有改变，但现在失败了。这是因为我们向``命令提供了太多的参数。即使我们使用`test`命令，失败的结果也是一样的。

尽管我们已经正确引用了文件名分配给参数`FILE`，但在参数扩展时我们`没有`保护空格。我们可以看到代码失败，如下面的截图所示：

![当你犹豫时-引用！

我们可以看到，这对我们的脚本来说还没有准备好。唉，我们曾经认为坚固的东西现在已经支离破碎，就像泰坦尼克号一样，我们的代码已经沉没了。

然而，一个简单的解决方案是恢复引用参数扩展，除非特别不需要。通过对代码进行简单的编辑，我们可以使这艘船不会沉没：

```
$ FILE="my file"
$ [ -f "$FILE" -a -r "$FILE" ] && cat "$FILE"

```

现在我们可以自豪地站在白星航运公司的码头上，因为我们看到泰坦尼克号 II 在以下代码示例中被推出，这在下面的截图中被捕捉到：

![当你犹豫时-引用！](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00048.jpeg)

这些微小的引号可以产生真正令人惊讶，有时甚至有点难以置信的影响。当扩展变量时，我们绝不能忽视引号。为了确保我们强调这一点，我们可以在另一个更简单的例子中突出这种现象。让我们考虑现在只想删除文件的情况。在第一个例子中，我们不使用引号：

```
$ rm $FILE

```

这段代码将导致失败，因为参数扩展将导致以下感知命令：

```
$ rm my file

```

这段代码将失败，因为它无法找到`my`文件或`file`文件。更糟糕的是，可能我们会意外地删除错误的文件，如果其中任何一个名称被错误地解析。

而引用参数扩展将拯救一切，就像我们在第二个例子中看到的那样：

```
$ rm "$FILE"

```

这被正确地扩展为我们在以下代码示例中说明的期望命令：

```
$ rm "my file"

```

我确实希望这些例子能够说明在扩展参数时需要小心，并且你意识到了其中的陷阱。

# 使用[[进行高级测试

使用双括号`[[条件]]`允许我们进行更高级的条件测试，但与 Bourne Shell 不兼容。双括号首次作为 korn shell 中的定义关键字引入，并且也可用于 bash 和 zsh。与单括号不同，这不是一个命令而是一个关键字。使用 type 命令可以确认这一点：

```
$ type [[

```

## 空格

`[[`不是一个命令在空格方面是重要的。作为关键字，`[[`在 bash 扩展它们之前解析其参数。因此，单个参数将始终表示为单个参数。即使违反最佳实践，`[[`可以减轻参数值中空格相关的一些问题。重新考虑我们之前测试的条件，当使用`[[`时，我们可以省略引号，如下例所示：

```
$ echo "The File Contents">"my file"
$ FILE="my file"
$ [[ -f $FILE && -r $FILE ]] && cat "$FILE"

```

当使用`cat`时，我们仍然需要引用参数，如您所见，我们可以在双括号中使用引号，但它们变得可选。请注意，我们还可以使用更传统的`&&`和`||`来分别表示`-a`和`-o`。

## 其他高级功能

一些额外功能可以包括在双括号中。即使在使用它们时失去了可移植性，也有一些很好的功能可以克服这一损失。请记住，如果我们只使用 bash，那么我们可以使用双括号，但不能在 Bourne Shell 中运行我们的脚本。我们在下面的部分中获得的高级功能包括模式匹配和正则表达式。

### 模式匹配

使用双括号，我们不仅可以匹配字符串，还可以使用模式匹配。例如，我们可能需要专门处理以`.pl`结尾的 Perl 脚本文件。我们可以在条件中轻松实现这一点，包括模式作为匹配，如下例所示：

```
$ [[ $FILE = *.pl ]] &&cp"$FILE" scripts/

```

### 正则表达式

我们不仅可以使用`=~`运算符进行简单的模式匹配，还可以匹配正则表达式。我们可以使用正则表达式重写上一个示例：

```
$ [[ $FILE =~ \.pl$ ]] &&cp "$FILE" scripts/

```

### 提示

由于单个点或句号在正则表达式中具有特殊含义，因此我们需要用`\`进行转义。

以下截图显示了正则表达式匹配与名为`my.pl`和`my.apl`的文件一起工作。匹配正确显示了以`.pl`结尾的文件：

![正则表达式](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00049.jpeg)

### 正则表达式脚本

不能忽视正则表达式的威力。使用正则表达式进行条件测试的另一个简单演示是公开颜色的美式和英式拼写：color 和 colour。我们可以提示用户是否要为脚本选择彩色或单色输出，同时考虑两种拼写。在脚本中执行此操作的行如下：

```
if [[ $REPLY =~ colou?r ]] ; then

```

正则表达式通过使 u 可选来满足 color 的两种拼写：u?。此外，我们可以通过设置 shell 选项来禁用大小写敏感性，从而允许*COLOR*和 color 的匹配：

```
shopt -s nocasematch

```

此选项可以在脚本末尾使用以下命令再次禁用：

```
shopt -s nocasematch

```

当我们使用我们命名的变量参数`$GREEN`和`$RESET`时，我们会影响输出的颜色。只有在我们引用颜色定义文件时，绿色才会显示。当我们选择单色显示时，选择单色将确保变量参数为空且无效。

完整的脚本显示在以下截图中：

![正则表达式脚本](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00050.jpeg)

# 使用(( ))进行算术运算

在使用 bash 和其他高级 shell 时，我们可以使用`(( ))`符号来简化脚本中的数学运算。

## 简单的数学

在 bash 中，双括号结构允许进行算术展开。在最简单的格式中，我们可以轻松进行整数运算。这成为了`let`内置的替代品。以下示例展示了使用`let`命令和双括号来实现相同的结果：

```
$ a=(( 2 + 3 ))
$ let a=2+3

```

在这两种情况下，`a`参数都被填充为`2 + 3`的和。

## 参数操作

也许，在脚本编写中对我们更有用的是使用双括号的 C 风格参数操作。我们经常可以使用这个来在循环中递增计数器，并限制循环迭代的次数。考虑以下代码：

```
$ COUNT=1
$ (( COUNT++ ))
echo $COUNT

```

在这个例子中，我们首先将`COUNT`设置为`1`，然后使用`++`运算符对其进行递增。当在最后一行中输出时，参数将具有值`2`。我们可以在以下截图中看到结果：

![参数操作](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00051.jpeg)

我们可以通过以下语法来以长格式实现相同的结果：

```
$ COUNT=1
$ (( COUNT=COUNT+1 ))
echo $COUNT

```

当然，这允许对`COUNT`参数进行任何增量，而不仅仅是单个单位的增加。同样地，我们可以使用`--`运算符进行倒数，如下例所示：

```
$ COUNT=10
$ (( COUNT-- ))
echo $COUNT

```

我们从`10`开始，然后在双括号中将值减少`1`。

### 提示

请注意，我们不使用`$`来扩展括号内的参数。它们用于参数操作，因此我们不需要显式地扩展参数。

## 标准算术测试

另一个我们可以从这些双括号中获得的优势是在测试中。我们可以简单地使用`>`而不是使用`-gt`来表示大于。我们可以在以下代码中演示这一点：

```
$(( COUNT > 1 )) && echo "Count is greater than 1"

```

以下截图为您演示了这一点：

![标准算术测试](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00052.jpeg)

正是这种标准化，无论是在 C 风格的操作还是测试中，使双括号对我们如此有用。这种用法既适用于命令行，也适用于脚本。当我们研究循环结构时，我们将广泛使用这个特性。

# 总结

在本章中，我真诚地希望我们为您介绍了许多新颖有趣的选择。这是一个范围广泛的领域，我们从回顾测试的使用开始，发现`[`是一个命令而不是语法结构。它作为一个命令的主要影响在于空格，我们还讨论了引用变量的必要性。

即使我们通常称变量为变量。我们也看到它们的正确名称，特别是在文档中是参数。读取变量是参数展开。理解参数展开可以帮助我们理解关键字`[[`的用法。双方括号不是命令，也不展开参数。这意味着即使变量包含空格，我们也不需要引用变量。此外，我们可以使用双方括号进行高级测试，如模式匹配或正则表达式。

最后，我们看了双括号符号的算术展开和参数操作。它最大的特点是可以轻松地递增和递减计数器。

在下一章中，我们将进入 bash 中的循环结构，并利用本章中学到的一些新技能。


# 第六章：使用循环迭代

记住，脚本是给懒人用的。我们是世界上有更重要事情要做的人，而不是重复一项任务 100 次或更多次；循环是我们的朋友。

循环结构是脚本的生命线。这些循环是可以可靠和一致地重复多次执行相同任务的工作引擎。想象一下，有 10 万行文本在 CSV 文件中，必须检查是否有错误条目。一旦开发完成，脚本可以轻松而准确地完成这项任务，但在人类的情况下，可靠性和准确性将很快失败。

所以让我们看看如何通过在本章中涵盖以下主题来节省时间和理智：

+   for 循环

+   循环控制

+   while 和 until

+   从文件中读取

+   操作菜单

# for 循环

我们所有的循环控制都可以很简单，我们将从`for`循环开始。`for`是 bash 中的关键字，在工作中类似于`if`。我们可以使用命令类型来验证这一点，如下例所示：

```
$ type for
for is a shell keyword

```

作为保留的 shell 关键字，我们可以在脚本中和直接在命令行中使用`for`循环。这样，我们可以在脚本内外利用循环，优化命令行的使用。一个简单的`for`循环如下例所示：

```
# for u in bob joe ; do
useradd $u
echo '$u:Password1' | chpasswd
passwd -e $u
done
```

在`for`循环中，我们从右侧的列表中读取以填充左侧的变量参数，这种情况下我们将从包含`bob`和`joe`的列表中读取，并插入到参数变量`u`中。列表中的每个项目都会逐个插入到变量中。这样，只要列表中有要处理的项目，循环就会执行，直到列表耗尽。

实际上，对我们来说，执行此循环意味着我们将：

+   创建用户`bob`

+   为`bob`设置密码

+   让用户`bob`的密码过期，这样在第一次登录时就需要重置

然后我们循环回去，重复为用户`joe`执行相同的过程。

我们可以在以下截图中查看前面的示例；在通过`sudo -i`获得 root 访问权限后，我们继续运行循环并创建用户：

![For loops](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00053.jpeg)

在`for`循环中读取的列表可以动态或静态生成，如最后一个例子所示。要创建动态列表，我们可以使用各种通配技术来填充列表。例如，要处理目录中的所有文件，我们可以使用`*`，如下例所示：

```
for f in * ; do
stat "$f"
done
```

### 注意

当生成列表时，比如使用文件通配符，我们应该引用变量参数的扩展。如果没有引号，可能会包含一个空格，导致命令失败。这就是我们在`stat`命令中看到的情况。

在以下示例中，我们隔离以`ba*`开头的文件名。然后我们使用`stat`命令打印 inode 元数据。代码和输出如下截图所示：

![For loops](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00054.jpeg)

这个列表也可以从另一个命令的输出或一系列命令的输出中生成。例如，如果我们需要打印所有已登录用户的当前工作目录，我们可以尝试类似以下的操作：

```
$ for user in $(who | cut -f1 -d"") ; do
lsof -u $user -a -c bash | grep cwd
done

```

在前面的例子中，我们可以看到参数名称的选择取决于您；我们不限于单个字符，我们可以在此示例中使用`$user`name。使用小写我们不会覆盖系统变量`$USER`。以下截图演示了循环和随后的输出：

![For loops](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00055.jpeg)

`lsof`命令将列出打开的文件，我们可以依次搜索每个用户打开的文件，并使用`bash`命令作为当前工作目录。

使用我们迄今为止创建的脚本，我们可以创建一个名为`hello9.sh`的新脚本。如果我们将`$HOME/bin/hello2.sh`脚本复制到新脚本中，我们可以编辑它以使用`for`循环：

```
#!/bin/bash
echo "You are using $(basename $0)"
for n in $*
do
    echo "Hello $n"
done
exit 0
```

该循环用于遍历提供的每个命令行参数并分别向每个用户打招呼。当我们执行脚本时，我们可以看到我们现在可以为每个用户显示 hello 消息。这在下面的截图中显示：

![For 循环](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00056.jpeg)

尽管我们在这里看到的仍然相对琐碎，但我们现在应该意识到脚本和循环可以做些什么。此脚本的参数可以是我们已经使用过的用户名或其他任何内容。如果我们坚持使用用户名，那么创建用户帐户并设置密码将非常容易，就像我们之前看到的那样。

# 控制循环

进入循环后，我们可能需要提前退出循环，或者可能需要排除某些项目不进行处理。如果我们只想在列表中处理目录，而不是任何类型的文件，那么为了实现这一点，我们有循环控制关键字，如`break`和`continue`。

`break`关键字用于退出循环，不再处理条目，而`continue`关键字用于停止处理当前条目并恢复处理下一个条目。

假设我们只想处理目录，我们可以在循环中实现一个测试，并确定文件类型：

```
$ for f in * ; do
[ -d "$f" ] || continue
chmod 3777 "$f"
done

```

在循环中，我们想要设置包括 SGID 和粘性位的权限，但仅适用于目录。`*`搜索将返回所有文件，循环内的第一条语句将确保我们只处理目录。如果测试是针对当前循环进行的，目标未通过测试并不是一个目录；`continue`关键字将检索下一个循环列表项。如果测试返回 true 并且我们正在处理一个目录，那么我们将处理后续语句并执行`chmod`命令。

如果我们需要运行循环直到找到一个目录，然后退出循环，我们可以调整代码，以便可以遍历每个文件。如果文件是一个目录，那么我们使用`break`关键字退出循环：

```
$ for f in * ; do
[ -d "$f" ] &&break
done
echo "We have found a directory $f"

```

在下面的截图中，我们可以看到我刚刚编写的代码在运行中的情况：

![控制循环](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00057.jpeg)

通过使用以下代码，我们可以打印列表中找到的每个目录：

```
for f in * ; do
[ -d "$f" ] || continue
dir_name="$dir_name $f"
done
echo "$dir_name"

```

我们可以通过仅在循环中处理目录项目来实现结果。我们可以使用`if`测试仅处理常规文件。在这个例子中，我们将目录名附加到`dir_name`变量。一旦退出循环，我们打印完整的目录列表。我们可以在下面的截图中看到这一点：

![控制循环](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00058.jpeg)

使用这些示例和您自己的想法，您现在应该能够看到如何使用`continue`和`break`关键字控制循环。

## While 循环和 until 循环

使用`for`循环时，我们遍历列表，无论是我们创建的列表还是动态生成的列表。使用`while`或`until`循环时，我们根据条件变为真或假来循环。

`while`循环在条件为真时循环，相反`until`循环在条件为假时循环。以下命令将从 10 倒数到零。循环的每次迭代都打印变量，然后将值减 1：

```
$ COUNT=10
$ while (( COUNT >= 0 )) ; do
echo -e "$COUNT \c"
(( COUNT-- ))
done ; echo

```

我们可以在下面的截图中看到这个命令的输出；从而确认倒计时到零：

![While 循环和 until 循环](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00059.jpeg)

### 注意

在这里使用的`\c`转义序列允许抑制`echo`通常使用的换行符。这样，我们可以保持单行输出的倒计时。我想您会同意这是一个不错的效果。

使用`until`循环可以获得此循环的功能；只需要快速重新考虑逻辑，因为我们希望循环直到条件变为真。通常，关于使用哪种循环是个人选择，以及逻辑对您来说哪种循环效果最好。以下示例显示了使用`until`循环编写的循环：

```
$ COUNT=10
$ until (( COUNT < 0 )) ; do
echo -e "$COUNT \c"
(( COUNT-- ))
done ; echo

```

# 从文件中读取输入

现在，看起来这些循环可以做的不仅仅是倒数。我们可能希望从文本文件中读取数据并处理每一行。我们在本书中早些时候看到的 shell 内置`read`命令可以用于逐行读取文件。这样，我们可以使用循环处理文件的每一行。

为了演示其中一些功能，我们将使用一个包含服务器地址的文件。这些可以是主机名或 IP 地址。在下面的示例中，我们将使用 Google DNS 服务器的 IP 地址。以下命令显示了`servers.txt`文件的内容：

```
$cat servers.txt
8.8.8.8
8.8.4.4

```

使用`while`循环的条件中使用`read`命令，我们可以循环读取文件中的行。我们在`done`关键字后直接指定输入文件。对于从文件中读取的每一行，我们可以使用`ping`命令测试服务器是否正常运行，如果服务器响应，我们将其添加到可用服务器列表中。循环结束后，将打印此列表。在下面的示例中，我们可以看到我们开始添加书中涵盖的脚本元素：

```
$ while read server ; do
ping -c1 $server && servers_up="$servers_up $server"
done < servers.txt
echo "The following servers are up: $servers_up"

```

我们可以在以下截图中验证操作：

![从文件中读取输入](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00060.jpeg)

使用这种循环，我们可以开始构建非常实用的脚本，以处理从命令行或脚本中提供的信息。很容易用`$1`代表传递到脚本中的位置参数来替换我们读取的文件名。让我们返回到`ping_server.sh`脚本，并调整它以接受输入参数。我们可以将脚本复制到新的`$HOME/bin/ping_server_from_file.sh`文件中。在脚本中，我们首先测试输入参数是否为文件。然后，我们创建一个包含日期的标题的输出文件。当我们进入循环时，我们将可用服务器追加到此文件，并在脚本结束时列出文件：

```
#!/bin/bash
# Author: @theurbanpenguin
# Web: www.theurbapenguin.com
# Script to ping servers from file
# Last Edited: August 2015
if [ ! -f"$1 ] ; then
  echo "The input to $0 should be a filename"
  exit 1
fi
echo "The following servers are up on $(date +%x)"> server.out
done
while read server
do
  ping -c1 "$server"&& echo "Server up: $server">> server.out
done
cat server.out
```

现在我们可以以以下方式执行脚本：

```
$ ping_server_from_file.sh servers.txt

```

脚本执行的输出应该类似于以下截图：

![从文件中读取输入](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00061.jpeg)

# 创建操作员菜单

我们可以为需要从 shell 获取有限功能并且不想学习命令行使用细节的 Linux 操作员提供菜单。我们可以使用他们的登录脚本为他们启动菜单。此菜单将提供要选择的命令选项列表。菜单将循环，直到用户选择退出菜单。我们可以创建一个新的`$HOME/bin/menu.sh`脚本，菜单循环的基础如下：

```
while true
do
……
done
```

我们在这里创建的循环是无限的。`true`命令将始终返回 true 并持续循环；但是，我们可以提供循环控制机制，以允许用户离开菜单。要开始构建菜单的结构，我们需要在循环中输出一些文本，询问用户选择的命令。每次加载菜单之前，我们将清除屏幕，并在所需命令执行后出现额外的读取提示。

这允许用户在清除屏幕并重新加载菜单之前读取命令的输出。此时脚本将如下所示：

```
#!/bin/bash
# Author: @theurbanpenguin
# Web: www.theurbapenguin.com
# Sample menu
# Last Edited: August 2015

while true
do
  clear
  echo "Choose an item: a,b or c"
  echo "a: Backup"
  echo "b: Display Calendar"
  echo "c: Exit"
  read -sn1
  read -n1 -p "Press any key to continue"
done
```

如果在此阶段执行脚本，将没有机制可以离开脚本。我们还没有添加任何代码到菜单选择；但是，您可以使用*Ctrl* + *c*键测试功能并退出。

此时，菜单应该类似于以下截图中显示的输出：

![创建操作员菜单](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00062.jpeg)

为了构建菜单选择背后的代码，我们将实现一个`case`语句。这将被添加在两个`read`命令之间，如下所示：

```
read -sn1
 case "$REPLY" in
 a) tar -czvf $HOME/backup.tgz ${HOME}/bin;;
 b) cal;;
 c) exit 0;;
 esac
 read -n1 -p "Press any key to continue"

```

我们可以看到我们已经添加到`case`语句中的三个选项，`a`，`b`和`c`：

+   选项 a：这将运行`tar`命令来备份脚本

+   选项 b：这将运行`cal`命令来显示当前月份

+   选项 c：这将退出脚本

为了确保用户在退出其登录脚本时注销，我们将运行：

```
exec menu.sh

```

`exec`命令用于确保在`menu.sh`文件完成后保留 shell。这样，用户永远不需要体验 Linux shell。完整的脚本显示在以下截图中：

![创建操作菜单](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-sh-scp/img/00063.jpeg)

# 摘要

在本章中，我们已经开始取得进展。我们已经能够将许多我们以前使用的元素结合成连贯和功能性的脚本。尽管本章的重点是循环，但我们已经使用了命令行列表，`if`语句，`case`语句和算术计算。

我们在本章开头描述循环为我们脚本的工作马，并且我们已经能够用`for`，`while`和`until`循环来证明这一点。`for`循环用于遍历列表的元素。列表可以是静态的或动态的，重点是动态列表，我们展示了如何通过文件通配符或命令扩展简单地创建这些列表。

`while`和`until`循环受条件控制。`while`循环在提供的条件为真时循环。`until`循环将在提供的条件返回真或返回假时循环。`continue`和`break`关键字是特定于循环的，以及`exit`，我们可以控制循环流程。

在下一章中，我们将学习使用函数将脚本模块化。
