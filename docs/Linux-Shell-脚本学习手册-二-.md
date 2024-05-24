# Linux Shell 脚本学习手册（二）

> 原文：[`zh.annas-archive.org/md5/77969218787D4338964B84D125FE6927`](https://zh.annas-archive.org/md5/77969218787D4338964B84D125FE6927)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：Hello World!

在本章中，我们将终于开始编写 shell 脚本。在编写和运行我们自己的`Hello World!`脚本之后，我们将研究一些适用于所有未来脚本的最佳实践。我们将使用许多技术来提高脚本的可读性，并在可能的情况下遵循 KISS 原则（保持简单，愚蠢）。

本章将介绍以下命令：`head`，`tail`和`wget`。

本章将涵盖以下主题：

+   第一步

+   可读性

+   KISS

# 技术要求

我们将直接在虚拟机上创建我们的 shell 脚本；我们暂时不会使用 Atom/Notepad++。

本章的所有脚本都可以在 GitHub 上找到：[`github.com/PacktPublishing/Learn-Linux-Shell-Scripting-Fundamentals-of-Bash-4.4/tree/master/Chapter07`](https://github.com/PacktPublishing/Learn-Linux-Shell-Scripting-Fundamentals-of-Bash-4.4/tree/master/Chapter07)。

# 第一步

在获取有关 Linux 的一些背景信息，准备我们的系统，并了解 Linux 脚本编写的重要概念之后，我们终于到达了我们将编写实际 shell 脚本的地步！

总之，shell 脚本只不过是多个 Bash 命令的顺序排列。脚本通常用于自动化重复的任务。它们可以交互式或非交互式地运行（即带有或不带有用户输入），并且可以与他人共享。让我们创建我们的`Hello World`脚本！我们将在我们的`home`目录中创建一个文件夹，用于存储每个章节的所有脚本：

```
reader@ubuntu:~$ ls -l
total 4
-rw-rw-r-- 1 reader reader  0 Aug 19 11:54 emptyfile
-rw-rw-r-- 1 reader reader 23 Aug 19 11:54 textfile.txt
reader@ubuntu:~$ mkdir scripts
reader@ubuntu:~$ cd scripts/
reader@ubuntu:~/scripts$ mkdir chapter_07
reader@ubuntu:~/scripts$ cd chapter_07/
reader@ubuntu:~/scripts/chapter_07$ vim hello-world.sh
```

接下来，在`vim`屏幕中，输入以下文本（注意我们在两行之间*使用了空行*）：

```
#!/bin/bash

echo "Hello World!"
```

正如我们之前解释的，`echo`命令将文本打印到终端。让我们使用`bash`命令运行脚本：

```
reader@ubuntu:~/scripts/chapter_07$ bash hello-world.sh
Hello World!
reader@ubuntu:~/scripts/chapter_07
```

恭喜，你现在是一个 shell 脚本编写者！也许还不是一个非常优秀或全面的*编写者*，但无论如何都是一个 shell 脚本编写者。

请记住，如果`vim`还没有完全满足你的需求，你可以随时退回到`nano`。或者，更好的是，再次运行`vimtutor`并刷新那些`vim`操作！

# shebang

你可能想知道第一行是什么意思。第二行（或者第三行，如果你算上空行的话）应该很清楚，但第一行是新的。它被称为**shebang**，有时也被称为*sha-bang*，*hashbang*，*pound-bang*和/或*hash-pling*。它的功能非常简单：它告诉系统使用哪个二进制文件来执行脚本。它的格式始终是`#!<binary path>`。对于我们的目的，我们将始终使用`#!/bin/bash` shebang，但对于 Perl 或 Python 脚本，分别是`#!/usr/bin/perl`和`#!/usr/bin/python3`。乍一看，这似乎是不必要的。我们创建了名为`hello-world.sh`的脚本，而 Perl 或 Python 脚本将使用`hello-world.pl`和`hello-world.py`。那么，为什么我们需要 shebang 呢？

对于 Python，它允许我们轻松区分 Python 2 和 Python 3。通常情况下，人们会期望尽快切换到编程语言的新版本，但对于 Python 来说，这似乎需要付出更多的努力，这就是为什么今天我们会看到 Python 2 和 Python 3 同时在使用中的原因。

Bash 脚本不以`.bash`结尾，而是以`.sh`结尾，这是*shell*的一般缩写。因此，除非我们为 Bash 指定 shebang，否则我们将以*正常*的 shell 执行结束。虽然对于一些脚本来说这没问题（`hello-world.sh`脚本将正常工作），但当我们使用 Bash 的高级功能时，就会遇到问题。

# 运行脚本

如果您真的留心观察，您会注意到我们执行了一个没有可执行权限的脚本，使用了`bash`命令。如果我们已经指定了如何运行它，为什么还需要 shebang 呢？在这种情况下，我们不需要 shebang。但是，我们需要确切地知道它是哪种类型的脚本，并找到系统上正确的二进制文件来运行它，这可能有点麻烦，特别是当您有很多脚本时。幸运的是，我们有更好的方法来运行这些脚本：使用可执行权限。让我们看看如何通过设置可执行权限来运行我们的`hello-world.sh`脚本：

```
reader@ubuntu:~/scripts/chapter_07$ ls -l
total 4
-rw-rw-r-- 1 reader reader 33 Aug 26 12:08 hello-world.sh
reader@ubuntu:~/scripts/chapter_07$ ./hello-world.sh
-bash: ./hello-world.sh: Permission denied
reader@ubuntu:~/scripts/chapter_07$ chmod +x hello-world.sh 
reader@ubuntu:~/scripts/chapter_07$ ./hello-world.sh
Hello World! reader@ubuntu:~/scripts/chapter_07$ /home/reader/scripts/chapter_07/hello-world.sh Hello World!
reader@ubuntu:~/scripts/chapter_07$ ls -l
total 4
-rwxrwxr-x 1 reader reader 33 Aug 26 12:08 hello-world.sh
reader@ubuntu:~/scripts/chapter_07$
```

我们可以通过运行*完全限定*或在相同目录中使用`./`来执行脚本（或任何文件，只要对于该文件来说有意义）。只要设置了可执行权限，我们就需要前缀`./`。这是因为安全性的原因：通常当我们执行一个命令时，`PATH`变量会被探索以找到该命令。现在想象一下，有人在您的主目录中放置了一个恶意的名为`ls`的二进制文件。如果没有`./`规则，运行`ls`命令将导致运行该二进制文件，而不是`/bin/ls`（它在您的`PATH`上）。

因为我们只是使用`./hello-world.sh`来运行脚本，所以现在我们需要再次使用 shebang。否则，Linux 会默认使用`/bin/sh`，这不是我们在**Bash**脚本书中想要的，对吧？

# 可读性

在编写 shell 脚本时，您应该始终确保代码尽可能易读。当您正在创建脚本时，所有逻辑、命令和脚本流程对您来说可能是显而易见的，但如果您一段时间后再看脚本，这就不再是显而易见的了。更糟糕的是，您很可能会与其他人一起编写脚本；这些人在编写脚本时从未考虑过您的考虑（反之亦然）。我们如何在脚本中促进更好的可读性呢？注释和冗长是我们实现这一目标的两种方式。

# 注释

任何优秀的软件工程师都会告诉您，在代码中放置相关注释会提高代码的质量。注释只不过是一些解释您在做什么的文本，前面加上一个特殊字符，以确保您编写代码的语言不会解释这些文本。对于 Bash 来说，这个字符是*井号* `#`（目前更为人所熟知的是在#HashTags 中的使用）。在阅读其他来源时，它也可能被称为*井号*或*哈希*。其他注释字符的例子包括`//`（Java，C++），`--`（SQL），以及`<!-- comment here -->`（HTML，XML）。`#`字符也被用作 Python 和 Perl 的注释。

注释可以放在行的开头，以确保整行不被解释，或者放在行的其他位置。在这种情况下，直到`#`之前的所有内容都将被处理。让我们看一个修订后的`Hello World`脚本中这两种情况的例子。

```
#!/bin/bash

# Print the text to the Terminal.
echo "Hello World!"
```

或者，我们可以使用以下语法：

```
#!/bin/bash

echo "Hello World!" # Print the text to the Terminal.
```

一般来说，我们更喜欢将注释放在命令的上面单独的一行。然而，一旦我们引入循环、重定向和其他高级结构，*内联注释*可以确保比整行注释更好的可读性。然而，最重要的是：**任何相关的注释总比没有注释更好，无论是整行还是内联**。按照惯例，我们总是更喜欢保持注释非常简短（一到三个单词）或者使用带有适当标点的完整句子。在需要简短句子会显得过于夸张的情况下，使用一些关键词；否则，选择完整句子。我们保证这将使您的脚本看起来更加专业。

# 脚本头

在我们的脚本编写中，我们总是在脚本开头包含一个*标题*。虽然这对于脚本的功能来说并不是必需的，但当其他人使用您的脚本时（或者再次，当您使用其他人的脚本时），它可以帮助很大。标题可以包括您认为需要的任何信息，但通常我们总是从以下字段开始：

+   作者

+   版本

+   日期

+   描述

+   用法

通过使用注释实现简单的标题，我们可以让偶然发现脚本的人了解脚本是何时编写的，由谁编写的（如果他们有问题的话）。此外，简单的描述为脚本设定了一个目标，使用信息确保首次使用脚本时不会出现试错。让我们创建`hello-world.sh`脚本的副本，将其命名为`hello-world-improved.sh`，并实现标题和功能的注释：

```
reader@ubuntu:~/scripts/chapter_07$ ls -l
total 4
-rwxrwxr-x 1 reader reader 33 Aug 26 12:08 hello-world.sh
reader@ubuntu:~/scripts/chapter_07$ cp hello-world.sh hello-world-improved.sh
reader@ubuntu:~/scripts/chapter_07$ vi hello-world-improved.sh
```

确保脚本看起来像下面这样，但一定要输入*当前日期*和*您自己的名字*：

```
#!/bin/bash

#####################################
# Author: Sebastiaan Tammer
# Version: v1.0.0
# Date: 2018-08-26
# Description: Our first script!
# Usage: ./hello-world-improved.sh
#####################################

# Print the text to the Terminal.
echo "Hello World!"
```

现在，看起来不错吧？唯一可能突出的是，我们现在有一个包含任何功能的 12 行脚本。在这种情况下，的确，这似乎有点过分。然而，我们正在努力学习良好的实践。一旦脚本变得更加复杂，我们用于 shebang 和标题的这 10 行将不会有任何影响，但可用性显著提高。顺便说一下，我们正在引入一个新的`head`命令。

```
reader@ubuntu:~/scripts/chapter_07$ head hello-world-improved.sh
#!/bin/bash

#####################################
# Author: Sebastiaan Tammer
# Version: v1.0.0

# Date: 2018-08-26
# Description: Our first script!
# Usage: ./hello-world-improved.sh
#####################################

reader@ubuntu:~/scripts/chapter_07$
```

`head`命令类似于`cat`，但它不会打印整个文件；默认情况下，它只打印前 10 行。巧合的是，这恰好与我们创建的标题长度相同。因此，任何想要使用您的脚本的人（老实说，**您**在 6 个月后也是*任何人*）只需使用`head`打印标题，并获取开始使用脚本所需的所有信息。

在引入`head`的同时，如果我们不介绍`tail`也是不负责任的。正如名称可能暗示的那样，`head`打印文件的顶部，而`tail`打印文件的末尾。虽然这对我们的脚本标题没有帮助，但在查看错误或警告的日志文件时非常有用：

```
reader@ubuntu:~/scripts/chapter_07$ tail /var/log/auth.log
Aug 26 14:45:28 ubuntu systemd-logind[804]: Watching system buttons on /dev/input/event1 (Sleep Button)
Aug 26 14:45:28 ubuntu systemd-logind[804]: Watching system buttons on /dev/input/event2 (AT Translated Set 2 keyboard)
Aug 26 14:45:28 ubuntu sshd[860]: Server listening on 0.0.0.0 port 22.
Aug 26 14:45:28 ubuntu sshd[860]: Server listening on :: port 22.
Aug 26 15:00:02 ubuntu sshd[1079]: Accepted password for reader from 10.0.2.2 port 51752 ssh2
Aug 26 15:00:02 ubuntu sshd[1079]: pam_unix(sshd:session): session opened for user reader by (uid=0)
Aug 26 15:00:02 ubuntu systemd: pam_unix(systemd-user:session): session opened for user reader by (uid=0)
Aug 26 15:00:02 ubuntu systemd-logind[804]: New session 1 of user reader.
Aug 26 15:17:01 ubuntu CRON[1272]: pam_unix(cron:session): session opened for user root by (uid=0)
Aug 26 15:17:01 ubuntu CRON[1272]: pam_unix(cron:session): session closed for user root
reader@ubuntu:~/scripts/chapter_07$
```

# 冗长

回到我们如何改善脚本的可读性。虽然注释是改善我们对脚本理解的好方法，但如果脚本中的命令使用许多晦涩的标志和选项，我们需要在注释中使用许多词语来解释一切。而且，正如您可能期望的那样，如果我们需要五行注释来解释我们的命令，那么可读性会降低而不是提高！冗长是在不要太多但也不要太少的解释之间取得平衡。例如，您可能不必向任何人解释您是否以及为什么使用`ls`命令，因为那是非常基本的。然而，`tar`命令可能相当复杂，因此简短地解释您要实现的目标可能是值得的。

在这种情况下，我们想讨论三种类型的冗长。它们分别是：

+   注释的冗长

+   命令的冗长

+   命令输出的冗长

# 注释的冗长

冗长的问题在于很难给出明确的规则。几乎总是非常依赖于上下文。因此，虽然我们可以说，确实，我们不必评论`echo`或`ls`，但情况并非总是如此。假设我们使用`ls`命令的输出来迭代一些文件；也许我们想在注释中提到这一点？或者甚至这种情况对我们的预期读者来说是如此清晰，以至于对整个循环进行简短的评论就足够了？

答案是，非常不令人满意，*这取决于情况*。如果您不确定，通常最好还是包括注释，但您可能希望保持更加简洁。例如，您可以选择*使用 ls 构建迭代列表*，而不是*此 ls 实例列出所有文件，然后我们可以用它来进行脚本的其余部分的迭代*。这在很大程度上是一种实践技能，所以一定要至少开始练习：随着您编写更多的 shell 脚本，您肯定会变得更好。

# 命令的冗长

命令输出的冗长是一个有趣的问题。在之前的章节中，您已经了解了许多命令，有时还有相应的标志和选项，可以改变该命令的功能。大多数选项都有短语法和长语法，可以实现相同的功能。以下是一个例子：

```
reader@ubuntu:~$ ls -R
.:
emptyfile  scripts  textfile.txt
./scripts:
chapter_07
./scripts/chapter_07:
hello-world-improved.sh  hello-world.sh
reader@ubuntu:~$ ls --recursive
.:
emptyfile  scripts  textfile.txt
./scripts:
chapter_07
./scripts/chapter_07:
hello-world-improved.sh  hello-world.sh
reader@ubuntu:~$
```

我们使用`ls`递归打印我们的主目录中的文件。我们首先使用简写选项`-R`，然后使用长`--recursive`变体。从输出中可以看出，命令完全相同，即使`-R`更短且输入更快。但是，`--recursive`选项更冗长，因为它比`-R`给出了更好的提示，说明我们在做什么。那么，何时使用哪个？简短的答案是：**在日常工作中使用简写选项，在编写脚本时使用长选项**。虽然这对大多数情况都适用，但这并不是一个绝对可靠的规则。有些简写命令使用得非常普遍，以至于使用长选项可能会更令读者困惑，尽管听起来有些违反直觉。例如，在使用 SELinux 或 AppArmor 时，`ls`的`-Z`命令会打印安全上下文。这个的长选项是`--context`，但是这个选项没有`-Z`选项那么出名（根据我们的经验）。在这种情况下，使用简写会更好。

然而，我们已经看到了一个复杂的命令，但是当我们使用长选项时，它会更加可读：`tar`。让我们看看创建存档的两种方法：

```
reader@ubuntu:~/scripts/chapter_07$ ls -l
total 8
-rwxrwxr-x 1 reader reader 277 Aug 26 15:13 hello-world-improved.sh
-rwxrwxr-x 1 reader reader  33 Aug 26 12:08 hello-world.sh
reader@ubuntu:~/scripts/chapter_07$ tar czvf hello-world.tar.gz hello-world.sh
hello-world.sh
reader@ubuntu:~/scripts/chapter_07$ tar --create --gzip --verbose --file hello-world-improved.tar.gz hello-world-improved.sh
hello-world-improved.sh
reader@ubuntu:~/scripts/chapter_07$ ls -l
total 16
-rwxrwxr-x 1 reader reader 277 Aug 26 15:13 hello-world-improved.sh
-rw-rw-r-- 1 reader reader 283 Aug 26 16:28 hello-world-improved.tar.gz
-rwxrwxr-x 1 reader reader  33 Aug 26 12:08 hello-world.sh
-rw-rw-r-- 1 reader reader 317 Aug 26 16:26 hello-world.tar.gz
reader@ubuntu:~/scripts/chapter_07$
```

第一个命令`tar czvf`只使用了简写。这样的命令非常适合作为完整的行注释或内联注释：

```
#!/bin/bash
<SNIPPED>
# Verbosely create a gzipped tarball.
tar czvf hello-world.tar.gz hello-world.sh
```

或者，您可以使用以下内容：

```
#!/bin/bash
<SNIPPED>
# Verbosely create a gzipped tarball.
tar czvf hello-world.tar.gz hello-world.sh
```

`tar --create --gzip --verbose --file` 命令本身已经足够冗长，不需要注释，因为适当的注释实际上与长选项所表达的意思相同！

简写用于节省时间。对于日常任务来说，这是与系统交互的好方法。但是，在 shell 脚本中，清晰和冗长更为重要。使用长选项是一个更好的主意，因为使用这些选项时可以避免额外的注释。然而，一些命令使用得非常频繁，以至于长标志实际上可能更加令人困惑；在这里要根据您的最佳判断，并从经验中学习。

# 命令输出的冗长

最后，当运行 shell 脚本时，您将看到脚本中命令的输出（除非您想使用*重定向*来删除该输出，这将在第十二章中解释，*在脚本中使用管道和重定向*）。一些命令默认是冗长的。这些命令的很好的例子是`ls`和`echo`命令：它们的整个功能就是在屏幕上打印一些东西。

如果我们回到`tar`命令，我们可以问自己是否需要看到正在存档的所有文件。如果脚本中的逻辑是正确的，我们可以假设正在存档正确的文件，并且这些文件的列表只会使脚本的其余输出变得混乱。默认情况下，`tar`不会打印任何内容；到目前为止，我们一直使用`-v`/`--verbose`选项。但是，对于脚本来说，这通常是不可取的行为，因此我们可以安全地省略此选项（除非我们有充分的理由不这样做）。

大多数命令默认具有适当的冗长性。`ls`的输出是打印的，但`tar`默认是隐藏的。对于大多数命令，可以通过使用`--verbose`或`--quiet`选项（或相应的简写，通常是`-v`或`-q`）来反转冗长性。`wget`就是一个很好的例子：这个命令用于从互联网上获取文件。默认情况下，它会输出大量关于连接、主机名解析、下载进度和下载目的地的信息。然而，很多时候，所有这些东西都不是很有趣！在这种情况下，我们使用`wget`的`--quiet`选项，因为对于这种情况来说，这是命令的**适当冗长性**。

在编写 shell 脚本时，始终考虑所使用命令的冗长性。如果不够，查看 man 页面以找到增加冗长性的方法。如果太多，同样查看 man 页面以找到更安静的选项。我们遇到的大多数命令都有一个或两个选项，有时在不同的级别（`-q`和`-qq`甚至更安静的操作！）。

# 保持简单，愚蠢（KISS）

KISS 原则是处理 shell 脚本的一个很好的方法。虽然它可能显得有点严厉，但给出它的精神是重要的：它应该被视为很好的建议。*Python 之禅*中还给出了更多的建议，这是 Python 的设计原则：

+   简单胜于复杂

+   复杂比复杂好

+   可读性很重要

*Python 之禅*中还有大约 17 个方面，但这三个对于 Bash 脚本编写也是最相关的。最后一个，'*可读性很重要'*，现在应该是显而易见的。然而，前两个，'*简单胜于复杂'*和'*复杂胜于复杂'*与 KISS 原则密切相关。保持简单是一个很好的目标，但如果不可能，复杂的解决方案总是比复杂的解决方案更好（没有人喜欢复杂的脚本！）。

在编写脚本时，有一些事情你可以记住：

+   如果你正在构思的解决方案似乎变得非常复杂，请做以下任一事情：

+   研究你的问题；也许有另一个工具可以代替你现在使用的工具。

+   看看是否可以将事情分成离散的步骤，这样它会变得更复杂但不那么复杂。

+   问问自己是否需要一行代码完成所有操作，或者是否可能将命令拆分成多行以增加可读性。在使用管道或其他形式的重定向时，如第十二章中更详细地解释的那样，*在脚本中使用管道和重定向*，这是需要牢记的事情。

+   如果它起作用，那*可能*不是一个坏解决方案。但是，请确保解决方案不要*太*简单，因为边缘情况可能会在以后造成麻烦。

# 总结

我们从创建和运行我们的第一个 shell 脚本开始了这一章。学习一门新的软件语言时，几乎是强制性的，我们在终端上打印了 Hello World！接着，我们解释了 shebang：脚本的第一行，它是对 Linux 系统的一条指令，告诉它在运行脚本时应该使用哪个解释器。对于 Bash 脚本，约定是文件名以.sh 结尾，带有`#!/bin/bash`的 shebang。

我们解释了可以运行脚本的多种方式。我们可以从解释器开始，并将脚本名称作为参数传递（例如：`bash hello-world.sh`）。在这种情况下，shebang 是不需要的，因为我们在命令行上指定了解释器。然而，通常情况下，我们通过设置可执行权限并直接调用文件来运行脚本；在这种情况下，shebang 用于确定使用哪个解释器。因为你无法确定用户将如何运行你的脚本，包含 shebang 应该被视为强制性的。

为了提高我们脚本的质量，我们描述了如何提高我们 shell 脚本的可读性。我们解释了何时以及如何在我们的脚本中使用注释，以及如何使用注释创建一个我们可以通过使用`head`命令轻松查看的脚本头。我们还简要介绍了与`head`密切相关的`tail`命令。除了注释，我们还解释了**冗长性**的概念。

冗长性可以在多个级别找到：注释的冗长性，命令的冗长性和命令输出的冗长性。我们认为，在脚本中使用命令的长选项几乎总是比使用简写更好的主意，因为它增加了可读性，并且可以防止需要额外的注释，尽管我们已经确定，太多的注释几乎总是比没有注释更好。

我们以简要描述 KISS 原则结束了本章，我们将其与 Python 中的一些设计原则联系起来。读者应该意识到，如果有一个简单的解决方案，它往往是最好的。如果简单的解决方案不可行，应优先选择复杂的解决方案而不是复杂的解决方案。

本章介绍了以下命令：`head`，`tail`和`wget`。

# 问题

1.  按照惯例，当我们学习一门新的编程或脚本语言时，我们首先要做什么？

1.  Bash 的 shebang 是什么？

1.  为什么需要 shebang？

1.  我们可以以哪三种方式运行脚本？

1.  为什么我们在创建 shell 脚本时要如此强调可读性？

1.  为什么我们使用注释？

1.  为什么我们建议为您编写的所有 shell 脚本包括脚本头？

1.  我们讨论了哪三种冗长性类型？

1.  KISS 原则是什么？

# 进一步阅读

如果您想更深入地了解本章主题，以下资源可能会有趣：

+   **你好，世界（长教程）**：[`bash.cyberciti.biz/guide/Hello,_World!_Tutorial`](https://bash.cyberciti.biz/guide/Hello,_World!_Tutorial)

+   **Bash 编码风格指南**：[`bluepenguinlist.com/2016/11/04/bash-scripting-tutorial/`](https://bluepenguinlist.com/2016/11/04/bash-scripting-tutorial/)

+   **KISS**：[`people.apache.org/%7Efhanik/kiss.html`](https://people.apache.org/%7Efhanik/kiss.html)


# 第八章：变量和用户输入

在本章中，我们将首先描述变量是什么，以及我们为什么需要它们。我们将解释变量和常量之间的区别。接下来，我们将提供一些关于变量命名的可能性，并介绍一些关于命名约定的最佳实践。最后，我们将讨论用户输入以及如何正确处理它：无论是使用位置参数还是交互式脚本。我们将以介绍`if-then`结构和退出代码结束本章，我们将使用它们来结合位置参数和交互提示。

本章将介绍以下命令：`read`，`test`和`if`。

本章将涵盖以下主题：

+   什么是变量？

+   变量命名

+   处理用户输入

+   交互式与非交互式脚本

# 技术要求

除了具有来自前几章的文件的 Ubuntu 虚拟机外，不需要其他资源。

本章的所有脚本都可以在 GitHub 上找到：[`github.com/PacktPublishing/Learn-Linux-Shell-Scripting-Fundamentals-of-Bash-4.4/tree/master/Chapter08`](https://github.com/PacktPublishing/Learn-Linux-Shell-Scripting-Fundamentals-of-Bash-4.4/tree/master/Chapter08)。对于 `name-improved.sh` 脚本，只能在网上找到最终版本。在执行脚本之前，请务必验证头部中的脚本版本。

# 什么是变量？

变量是许多（如果不是所有）编程和脚本语言中使用的标准构建块。变量允许我们存储信息，以便稍后可以引用和使用它，通常是多次。例如，我们可以使用`textvariable`变量来存储句子`This text is contained in the variable`。在这种情况下，`textvariable`的变量名称被称为键，变量的内容（文本）被称为值，构成了变量的键值对。

在我们的程序中，当我们需要文本时，我们总是引用`textvariable`变量。现在可能有点抽象，但我们相信在本章的其余部分看到示例之后，变量的用处将变得清晰起来。

实际上，我们已经看到了 Bash 变量的使用。还记得在第四章 *Linux 文件系统*中，我们看过`BASH_VERSION`和`PATH`变量。让我们看看如何在 shell 脚本中使用变量。我们将使用我们的`hello-world-improved.sh`脚本，而不是直接使用`Hello world`文本，我们将首先将其放入一个变量中并引用它：

```
reader@ubuntu:~/scripts/chapter_08$ cp ../chapter_07/hello-world-improved.sh hello-world-variable.sh
reader@ubuntu:~/scripts/chapter_08$ ls -l
total 4
-rwxrwxr-x 1 reader reader 277 Sep  1 10:35 hello-world-variable.sh
reader@ubuntu:~/scripts/chapter_08$ vim hello-world-variable.sh
```

首先，我们将`hello-world-improved.sh`脚本从`chapter_07`目录复制到新创建的`chapter_08`目录中，并命名为`hello-world-variable.sh`。然后，我们使用`vim`进行编辑。给它以下内容：

```
#!/bin/bash

#####################################
# Author: Sebastiaan Tammer
# Version: v1.0.0
# Date: 2018-09-01
# Description: Our first script using variables!
# Usage: ./hello-world-variable.sh
#####################################

hello_text="Hello World!"

# Print the text to the terminal.
echo ${hello_text}

reader@ubuntu:~/scripts/chapter_08$ ./hello-world-variable.sh 
Hello World!
reader@ubuntu:~/scripts/chapter_08$
```

恭喜，您刚刚在脚本中使用了您的第一个变量！正如您所看到的，您可以通过在`${...}`语法中包装其名称来使用变量的内容。从技术上讲，只需在名称前面放置`$`就足够了（例如，`echo $hello_text`）。但是，在那种情况下，很难区分变量名称何时结束以及程序的其余部分开始——例如，如果您在句子中间使用变量（或者更好的是，在单词中间！）。如果使用`${..}`，那么变量名称在`}`处结束是清晰的。

在运行时，我们定义的变量将被实际内容替换，而不是变量名称：这个过程称为*变量插值*，并且在所有脚本/编程语言中都会使用。我们永远不会在脚本中看到或直接使用变量的值，因为在大多数情况下，值取决于运行时配置。

您还将看到我们编辑了头部中的信息。虽然很容易忘记，但如果头部不包含正确的信息，就会降低可读性。请务必确保您的头部是最新的！

如果我们进一步解剖这个脚本，你会看到`hello_text`变量是标题之后的第一行功能性代码。我们称这个为**给变量赋值**。在一些编程/脚本语言中，你首先必须在*分配*之前*声明*一个变量（大多数情况下，这些语言有简写形式，你可以一次性声明和分配）。

声明的需要来自于一些语言是*静态类型*的事实（变量类型——例如字符串或整数——应该在分配值之前声明，并且编译器将检查你是否正确地进行了赋值——例如不将字符串赋值给整数类型的变量），而其他语言是*动态类型*的。对于动态类型的语言，语言只是假定变量的类型是从分配给它的内容中得到的。如果它被分配了一个数字，它将是一个整数；如果它被分配了文本，它将是一个字符串，依此类推。

基本上，变量可以被**赋值**一个值，**声明**或**初始化**。尽管从技术上讲，这些是不同的事情，但你经常会看到这些术语被互换使用。不要太过纠结于此；最重要的是记住你正在*创建变量及其内容*！

Bash 并没有真正遵循任何一种方法。Bash 的简单变量（不包括数组，我们稍后会解释）始终被视为字符串，除非操作明确指定我们应该进行算术运算。看一下下面的脚本和结果（我们为了简洁起见省略了标题）：

```
reader@ubuntu:~/scripts/chapter_08$ vim hello-int.sh 
reader@ubuntu:~/scripts/chapter_08$ cat hello-int.sh 
#/bin/bash

# Assign a number to the variable.
hello_int=1

echo ${hello_int} + 1
reader@ubuntu:~/scripts/chapter_08$ bash hello-int.sh 
1 + 1
```

你可能期望我们打印出数字 2。然而，正如所述，Bash 认为一切都是字符串；它只是打印出变量的值，然后是空格、加号、另一个空格和数字 1。如果我们想要进行实际的算术运算，我们需要一种专门的语法，以便 Bash 知道它正在处理数字：

```
reader@ubuntu:~/scripts/chapter_08$ vim hello-int.sh 
reader@ubuntu:~/scripts/chapter_08$ cat hello-int.sh 
#/bin/bash

# Assign a number to the variable.
hello_int=1

echo $(( ${hello_int} + 1 ))

reader@ubuntu:~/scripts/chapter_08$ bash hello-int.sh 
2
```

通过在`$((...))`中包含`variable + 1`，我们告诉 Bash 将其作为算术表达式进行评估。

# 我们为什么需要变量？

希望你现在明白了如何使用变量。然而，你可能还没有完全理解为什么我们会*想要*或*需要*使用变量。这可能只是为了小小的回报而额外工作，对吧？考虑下一个例子：

```
reader@ubuntu:~/scripts/chapter_08$ vim name.sh 
reader@ubuntu:~/scripts/chapter_08$ cat name.sh 
#!/bin/bash

#####################################
# Author: Sebastiaan Tammer
# Version: v1.0.0
# Date: 2018-09-01
# Description: Script to show why we need variables.
# Usage: ./name.sh
#####################################

# Assign the name to a variable.
name="Sebastiaan"

# Print the story.
echo "There once was a guy named ${name}. ${name} enjoyed Linux and Bash so much that he wrote a book about it! ${name} really hopes everyone enjoys his book."

reader@ubuntu:~/scripts/chapter_08$ bash name.sh 
There once was a guy named Sebastiaan. Sebastiaan enjoyed Linux and Bash so much that he wrote a book about it! Sebastiaan really hopes everyone enjoys his book.
reader@ubuntu:~/scripts/chapter_08$
```

正如你所看到的，我们不止一次使用了`name`变量，而是三次。如果我们没有这个变量，而我们需要编辑这个名字，我们就需要在文本中搜索每个使用了这个名字的地方。

此外，如果我们在某个地方拼写错误，写成*Sebastian*而不是*Sebastiaan*（如果你感兴趣，这种情况*经常*发生），那么阅读文本和编辑文本都需要更多的努力。此外，这只是一个简单的例子：通常，变量会被多次使用（至少比三次多得多）。

此外，变量通常用于存储程序的*状态*。对于 Bash 脚本，你可以想象创建一个临时目录，在其中执行一些操作。我们可以将这个临时目录的位置存储在一个变量中，任何需要在临时目录中进行的操作都将使用这个变量来找到位置。程序完成后，临时目录应该被清理，变量也将不再需要。对于每次运行程序，临时目录的名称将不同，因此变量的内容也将不同，或者*可变*。

变量的另一个优点是它们有一个名称。因此，如果我们创建一个描述性的名称，我们可以使应用程序更容易阅读和使用。我们已经确定可读性对于 shell 脚本来说总是必不可少的，而使用适当命名的变量可以帮助我们实现这一点。

# 变量还是常量？

到目前为止的例子中，我们实际上使用的是**常量**作为变量。变量这个术语意味着它可以改变，而我们的例子总是在脚本开始时分配一个变量，并在整个过程中使用它。虽然这有其优点（如前面所述，为了一致性或更容易编辑），但它还没有充分利用变量的全部功能。

常量是变量，但是一种特殊类型。简单来说，常量是*在脚本开始时定义的变量，不受用户输入的影响，在执行过程中不改变值*。

在本章后面，当我们讨论处理用户输入时，我们将看到真正的变量。在那里，变量的内容由脚本的调用者提供，这意味着脚本的输出每次调用时都会不同，或者*多样化*。在本书后面，当我们描述条件测试时，我们甚至会根据脚本本身的逻辑在脚本执行过程中改变变量的值。

# 变量命名

接下来是命名的问题。你可能已经注意到到目前为止我们看到的变量有些什么：Bash 变量`PATH`和`BASH_VERSION`都是完全大写的，但在我们的例子中，我们使用小写，用下划线分隔单词（`hello_text`）。考虑以下例子：

```
#!/bin/bash

#####################################
# Author: Sebastiaan Tammer
# Version: v1.0.0
# Date: 2018-09-08
# Description: Showing off different styles of variable naming.
# Usage: ./variable-naming.sh
#####################################

# Assign the variables.
name="Sebastiaan"
home_type="house"
LOCATION="Utrecht"
_partner_name="Sanne"
animalTypes="gecko and hamster"

# Print the story.
echo "${name} lives in a ${home_type} in ${LOCATION}, together with ${_partner_name} and their two pets: a ${animalTypes}."
```

如果我们运行这个，我们会得到一个不错的小故事：

```
reader@ubuntu:~/scripts/chapter_08$ bash variable-naming.sh 
Sebastiaan lives in a house in Utrecht, together with Sanne and their two pets: a gecko and hamster.
```

所以，我们的变量运行得很好！从技术上讲，我们在这个例子中所做的一切都是正确的。然而，它们看起来很混乱。我们使用了四种不同的命名约定：用下划线分隔的小写、大写、_ 小写，最后是驼峰命名法。虽然这些在技术上是有效的，但要记住可读性很重要：最好选择一种命名变量的方式，并坚持下去。

正如你所期望的，对此有很多不同的意见（可能和制表符与空格的辩论一样多！）。显然，我们也有自己的意见，我们想要分享：对于普通变量，使用**用下划线分隔的小写**，对于常量使用**大写**。从现在开始，你将在所有后续脚本中看到这种做法。

前面的例子会是这样的：

```
reader@ubuntu:~/scripts/chapter_08$ cp variable-naming.sh variable-naming-proper.sh
reader@ubuntu:~/scripts/chapter_08$ vim variable-naming-proper.sh
vim variable-naming-proper.sh
reader@ubuntu:~/scripts/chapter_08$ cat variable-naming-proper.sh 
#!/bin/bash

#####################################
# Author: Sebastiaan Tammer
# Version: v1.0.0
# Date: 2018-09-08
# Description: Showing off uniform variable name styling.
# Usage: ./variable-naming-proper.sh
#####################################

NAME="Sebastiaan"
HOME_TYPE="house"
LOCATION="Utrecht"
PARTNER_NAME="Sanne"
ANIMAL_TYPES="gecko and hamster"

# Print the story.
echo "${NAME} lives in a ${HOME_TYPE} in ${LOCATION}, together with ${PARTNER_NAME} and their two pets: a ${ANIMAL_TYPES}."
```

我们希望你同意这看起来*好多了*。在本章后面，当我们介绍用户输入时，我们将使用普通变量，而不是到目前为止一直在使用的常量。

无论你在命名变量时决定了什么，最终只有一件事情真正重要：一致性。无论你喜欢小写、驼峰命名法还是大写，它对脚本本身没有影响（除了某些可读性的利弊，如前所述）。然而，同时使用多种命名约定会极大地混淆事情。一定要确保明智地选择一个约定，然后**坚持下去！**

为了保持清洁，我们通常避免使用大写变量，除了常量。这样做的主要原因是（几乎）Bash 中的所有*环境变量*都是用大写字母写的。如果你在脚本中使用大写变量，有一件重要的事情要记住：**确保你选择的名称不会与预先存在的 Bash 变量发生冲突**。这些包括`PATH`、`USER`、`LANG`、`SHELL`、`HOME`等等。如果你在脚本中使用相同的名称，可能会得到一些意想不到的行为。

最好避免这些冲突，并为你的变量选择唯一的名称。例如，你可以选择`SCRIPT_PATH`变量，而不是`PATH`。

# 处理用户输入

到目前为止，我们一直在处理非常静态的脚本。虽然为每个人准备一个可打印的故事很有趣，但它几乎不能算作一个功能性的 shell 脚本。至少，你不会经常使用它！因此，我们想要介绍 shell 脚本中非常重要的一个概念：**用户输入**。

# 基本输入

在非常基本的层面上，调用脚本后在命令行上输入的所有内容都可以作为输入使用。然而，这取决于脚本如何使用它！例如，考虑以下情况：

```
reader@ubuntu:~/scripts/chapter_08$ ls
hello-int.sh hello-world-variable.sh name.sh variable-naming-proper.sh variable-naming.sh
reader@ubuntu:~/scripts/chapter_08$ bash name.sh 
There once was a guy named Sebastiaan. Sebastiaan enjoyed Linux and Bash so much that he wrote a book about it! Sebastiaan really hopes everyone enjoys his book.
reader@ubuntu:~/scripts/chapter_08$ bash name.sh Sanne
There once was a guy named Sebastiaan. Sebastiaan enjoyed Linux and Bash so much that he wrote a book about it! Sebastiaan really hopes everyone enjoys his book
```

当我们第一次调用`name.sh`时，我们使用了最初预期的功能。第二次调用时，我们提供了额外的参数：`Sanne`。然而，因为脚本根本不解析用户输入，我们看到的输出完全相同。

让我们修改`name.sh`脚本，以便在调用脚本时实际使用我们指定的额外输入：

```
reader@ubuntu:~/scripts/chapter_08$ cp name.sh name-improved.sh
reader@ubuntu:~/scripts/chapter_08$ vim name-improved.sh
reader@ubuntu:~/scripts/chapter_08$ cat name-improved.sh 
#!/bin/bash

#####################################
# Author: Sebastiaan Tammer
# Version: v1.0.0
# Date: 2018-09-08
# Description: Script to show why we need variables; now with user input!
# Usage: ./name-improved.sh <name>
#####################################

# Assign the name to a variable.
name=${1}

# Print the story.
echo "There once was a guy named ${name}. ${name} enjoyed Linux and Bash so much that he wrote a book about it! ${name} really hopes everyone enjoys his book."

reader@ubuntu:~/scripts/chapter_08$ bash name-improved.sh Sanne
There once was a guy named Sanne. Sanne enjoyed Linux and Bash so much that he wrote a book about it! Sanne really hopes everyone enjoys his book.
```

现在看起来好多了！脚本现在接受用户输入；具体来说，是人的名字。它通过使用`$1`构造来实现这一点：这是*第一个位置参数*。我们称这些参数为位置参数，因为位置很重要：第一个参数将始终被写入`$1`，第二个参数将被写入`$2`，依此类推。我们无法交换它们。只有当我们开始考虑使我们的脚本与标志兼容时，我们才会获得更多的灵活性。如果我们向脚本提供更多的参数，我们可以使用`$3`、`$4`等来获取它们。

你可以提供的参数数量是有限制的。然而，这个限制足够高，以至于你永远不必真正担心它。如果你达到了这一点，你的脚本将变得非常笨重，以至于没有人会使用它！

你可能想将一个句子作为**一个**参数传递给一个 Bash 脚本。在这种情况下，如果你希望将其解释为*单个位置参数*，你需要用单引号或双引号将整个句子括起来。如果不这样做，Bash 将认为句子中的每个空格是参数之间的分隔符；传递句子**This Is Cool**将导致脚本有三个参数：This、Is 和 Cool。

请注意，我们再次更新了标题，包括*Usage*下的新输入。然而，从功能上讲，脚本并不是那么好；我们用男性代词来指代一个女性名字！让我们快速修复一下，看看如果我们现在*省略用户输入*会发生什么：

```
reader@ubuntu:~/scripts/chapter_08$ vim name-improved.sh 
reader@ubuntu:~/scripts/chapter_08$ tail name-improved.sh 
# Date: 2018-09-08
# Description: Script to show why we need variables; now with user input!
# Usage: ./name-improved.sh
#####################################

# Assign the name to a variable.
name=${1}

# Print the story.
echo "There once was a person named ${name}. ${name} enjoyed Linux and Bash so much that he/she wrote a book about it! ${name} really hopes everyone enjoys his/her book."

reader@ubuntu:~/scripts/chapter_08$ bash name-improved.sh 
There once was a person named .  enjoyed Linux and Bash so much that he/she wrote a book about it!  really hopes everyone enjoys his/her book.
```

因此，我们已经使文本更加中性化。然而，当我们在没有提供名字作为参数的情况下调用脚本时，我们搞砸了输出。在下一章中，我们将更深入地讨论错误检查和输入验证，但现在请记住，如果变量缺失/为空，Bash**不会提供错误**；你完全有责任处理这个问题。我们将在下一章中进一步讨论这个问题，因为这是 Shell 脚本中的另一个非常重要的主题。

# 参数和参数

我们需要退一步，讨论一些术语——参数和参数。这并不是非常复杂，但可能有点令人困惑，有时会被错误使用。

基本上，参数是你传递给脚本的东西。在脚本中定义的内容被视为参数。看看下面的例子，看看它是如何工作的：

```
reader@ubuntu:~/scripts/chapter_08$ vim arguments-parameters.sh
reader@ubuntu:~/scripts/chapter_08$ cat arguments-parameters.sh 
#!/bin/bash

#####################################
# Author: Sebastiaan Tammer
# Version: v1.0.0
# Date: 2018-09-08
# Description: Explaining the difference between argument and parameter.
# Usage: ./arguments-parameters.sh <argument1> <argument2>
#####################################

parameter_1=${1}
parameter_2=${2}

# Print the passed arguments:
echo "This is the first parameter, passed as an argument: ${parameter_1}"
echo "This is the second parameter, also passed as an argument: ${parameter_2}"

reader@ubuntu:~/scripts/chapter_08$ bash arguments-parameters.sh 'first-arg' 'second-argument'
This is the first parameter, passed as an argument: first-arg
This is the second parameter, also passed as an argument: second-argument
```

我们在脚本中以这种方式使用的变量称为参数，但在传递给脚本时被称为参数。在我们的`name-improved.sh`脚本中，参数是`name`变量。这是静态的，与脚本版本绑定。然而，参数每次脚本运行时都不同：可以是`Sebastiaan`，也可以是`Sanne`，或者其他任何名字。

记住，当我们谈论参数时，你可以将其视为*运行时参数*；每次运行都可能不同的东西。如果我们谈论脚本的参数，我们指的是脚本期望的静态信息（通常由运行时参数提供，或者脚本中的一些逻辑提供）。

# 交互式与非交互式脚本

到目前为止，我们创建的脚本使用了用户输入，但实际上并不能称之为交互式。一旦脚本启动，无论是否有参数传递给参数，脚本都会运行并完成。

但是，如果我们不想使用一长串参数，而是提示用户提供所需的信息呢？

输入`read`命令。`read`的基本用法是查看来自命令行的输入，并将其存储在`REPLY`变量中。自己试一试：

```
reader@ubuntu:~$ read
This is a random sentence!
reader@ubuntu:~$ echo $REPLY
This is a random sentence!
reader@ubuntu:~$
```

在启动`read`命令后，您的终端将换行并允许您输入任何内容。一旦您按下*Enter*（或者实际上，直到 Bash 遇到*换行*键），输入将保存到`REPLY`变量中。然后，您可以 echo 此变量以验证它是否实际存储了您的文本。

`read`有一些有趣的标志，使其在 shell 脚本中更易用。我们可以使用`-p`标志和一个参数（用引号括起来的要显示的文本）来向用户显示提示，并且我们可以将要存储响应的变量的名称作为最后一个参数提供：

```
reader@ubuntu:~$ read -p "What day is it? "
What day is it? Sunday
reader@ubuntu:~$ echo ${REPLY}
Sunday
reader@ubuntu:~$ read -p "What day is it? " day_of_week
What day is it? Sunday
reader@ubuntu:~$ echo ${day_of_week}
Sunday
```

在上一个示例中，我们首先使用了`read -p`，而没有指定要保存响应的变量。在这种情况下，`read`的默认行为将其放在`REPLY`变量中。一行后，我们用`day_of_week`结束了`read`命令。在这种情况下，完整的响应保存在一个名为此名称的变量中，如紧随其后的`echo ${day_of_week}`中所示。

现在让我们在实际脚本中使用`read`。我们将首先使用`read`创建脚本，然后使用到目前为止使用的位置参数：

```
reader@ubuntu:~/scripts/chapter_08$ vim interactive.sh
reader@ubuntu:~/scripts/chapter_08$ cat interactive.sh 
#!/bin/bash

#####################################
# Author: Sebastiaan Tammer
# Version: v1.0.0
# Date: 2018-09-09
# Description: Show of the capabilities of an interactive script.
# Usage: ./interactive.sh
#####################################

# Prompt the user for information.
read -p "Name a fictional character: " character_name
read -p "Name an actual location: " location
read -p "What's your favorite food? " food

# Compose the story.
echo "Recently, ${character_name} was seen in ${location} eating ${food}!

reader@ubuntu:~/scripts/chapter_08$ bash interactive.sh
Name a fictional character: Donald Duck
Name an actual location: London
What's your favorite food? pizza
Recently, Donald Duck was seen in London eating pizza!
```

这样做得相当不错。用户只需调用脚本，而无需查看如何使用它，并且进一步提示提供信息。现在，让我们复制和编辑此脚本，并使用位置参数提供信息：

```
reader@ubuntu:~/scripts/chapter_08$ cp interactive.sh interactive-arguments.sh
reader@ubuntu:~/scripts/chapter_08$ vim interactive-arguments.sh 
reader@ubuntu:~/scripts/chapter_08$ cat interactive-arguments.sh 
#!/bin/bash

#####################################
# Author: Sebastiaan Tammer
# Version: v1.0.0
# Date: 2018-09-09
# Description: Show of the capabilities of an interactive script, 
# using positional arguments.
# Usage: ./interactive-arguments.sh <fictional character name> 
# <actual location name> <your favorite food>
#####################################

# Initialize the variables from passed arguments.
character_name=${1}
location=${2}
food=${3}

# Compose the story.
echo "Recently, ${character_name} was seen in ${location} eating ${food}!"

reader@ubuntu:~/scripts/chapter_08$ bash interactive-arguments.sh "Mickey Mouse" "Paris" "a hamburger"
Recently, Mickey Mouse was seen in Paris eating a hamburger!
```

首先，我们将`interactive.sh`脚本复制到`interactive-arguments.sh`。我们编辑了此脚本，不再使用`read`，而是从传递给脚本的参数中获取值。我们编辑了标题，使用*新名称和新用法*，并通过提供另一组参数来运行它。再次，我们看到了一个不错的小故事。

因此，您可能会想知道，何时应该使用哪种方法？两种方法最终都得到了相同的结果。但就我们而言，这两个脚本都不够可读或简单易用。请查看以下表格，了解每种方法的优缺点：

|  | **优点** | **缺点** |
| --- | --- | --- |
| 读取 |

+   用户无需了解要提供的参数；他们只需运行脚本，并提示提供所需的任何信息

+   不可能忘记提供信息

|

+   如果要多次重复运行脚本，则需要每次输入响应

+   无法以非交互方式运行；例如，在计划任务中

|

| 参数 |
| --- |

+   可以轻松重复

+   也可以以非交互方式运行

|

+   用户需要在尝试运行脚本**之前**了解要提供的参数

+   很容易忘记提供所需的部分信息

|

基本上，一种方法的优点是另一种方法的缺点，反之亦然。似乎我们无法通过使用任一方法来取胜。那么，我们如何创建一个健壮的交互式脚本，也可以以非交互方式运行呢？

# 结合位置参数和 read

通过结合两种方法，当然可以！在我们开始执行脚本的实际功能之前，我们需要验证是否已提供了所有必要的信息。如果没有，我们可以提示用户提供缺失的信息。

我们将稍微提前查看第十一章，*条件测试和脚本循环*，并解释`if-then`逻辑的基本用法。我们将结合`test`命令，该命令可用于检查变量是否包含值或为空。*如果*是这种情况，*那么*我们可以使用`read`提示用户提供缺失的信息。

在本质上，`if-then`逻辑只不过是说`if <某事>，then 做 <某事>`。在我们的例子中，`if`角色名的变量为空，`then`使用`read`提示输入这个信息。我们将在我们的脚本中为所有三个参数执行此操作。

因为我们提供的参数是位置参数，我们不能只提供第一个和第三个参数；脚本会将其解释为第一个和第二个参数，第三个参数缺失。根据我们目前的知识，我们受到了这个限制。在第十五章中，*使用 getopts 解析 Bash 脚本参数*，我们将探讨如何使用标志提供信息。在这种情况下，我们可以分别提供所有信息，而不必担心顺序。然而，现在我们只能接受这种限制！

在我们解释`test`命令之前，我们需要回顾一下**退出代码**。基本上，每个运行并退出的程序都会返回一个代码给最初启动它的父进程。通常，如果一个进程完成并且执行成功，它会以**代码 0**退出。如果程序的执行不成功，它会以*任何其他代码*退出；然而，这通常是**代码 1**。虽然有关于退出代码的约定，通常你会遇到 0 表示良好退出，1 表示不良退出。

当我们使用`test`命令时，它也会生成符合指南的退出代码：如果测试成功，我们会看到退出代码 0。如果不成功，我们会看到另一个代码（可能是 1）。你可以使用`echo $?`命令查看上一个命令的退出代码。

让我们来看一个例子：

```
reader@ubuntu:~/scripts/chapter_08$ cd
reader@ubuntu:~$ ls -l
total 8
-rw-rw-r-- 1 reader reader    0 Aug 19 11:54 emptyfile
drwxrwxr-x 4 reader reader 4096 Sep  1 09:51 scripts
-rwxrwxr-x 1 reader reader   23 Aug 19 11:54 textfile.txt
reader@ubuntu:~$ mkdir scripts
mkdir: cannot create directory ‘scripts’: File exists
reader@ubuntu:~$ echo $?
1
reader@ubuntu:~$ mkdir testdir
reader@ubuntu:~$ echo $?
0
reader@ubuntu:~$ rmdir testdir/
reader@ubuntu:~$ echo $?
0
reader@ubuntu:~$ rmdir scripts/
rmdir: failed to remove 'scripts/': Directory not empty
reader@ubuntu:~$ echo $?
1
```

在上一个例子中发生了很多事情。首先，我们试图创建一个已经存在的目录。由于在同一位置不能有两个同名目录，所以`mkdir`命令失败了。当我们使用`$?`打印退出代码时，返回了`1`。

接下来，我们成功创建了一个新目录`testdir`。在执行该命令后，我们打印了退出代码，看到了成功的数字：`0`。成功删除空的`testdir`后，我们再次看到了退出代码`0`。当我们尝试使用`rmdir`删除非空的`scripts`目录（这是不允许的）时，我们收到了一个错误消息，并看到退出代码再次是`1`。

让我们回到`test`。我们需要做的是验证一个变量是否为空。如果是，我们希望启动一个`read`提示，让用户输入。首先我们将在`${PATH}`变量上尝试这个（它永远不会为空），然后在`empty_variable`上尝试（它确实为空）。要测试一个变量是否为空，我们使用`test -z <变量名>`：

```
reader@ubuntu:~$ test -z ${PATH}
reader@ubuntu:~$ echo $?
1
reader@ubuntu:~$ test -z ${empty_variable}
reader@ubuntu:~$ echo $?
0
```

虽然这乍看起来似乎是错误的，但想一想。我们正在测试一个变量是否**为空**。由于`$PATH`不为空，测试失败并产生了退出代码 1。对于`${empty_variable}`（我们从未创建过），我们确信它确实为空，退出代码 0 证实了这一点。

如果我们想要将 Bash 的`if`与`test`结合起来，我们需要知道`if`期望一个以退出代码 0 结束的测试。因此，如果测试成功，我们可以做一些事情。这与我们的例子完全吻合，因为我们正在测试空变量。如果你想测试另一种情况，你需要测试一个非零长度的变量，这是`test`的`-n`标志。

让我们先看一下`if`语法。实质上，它看起来像这样：`if <退出代码 0>; then <做某事>; fi`。你可以选择将其放在多行上，但在一行上使用;也会终止它。让我们看看我们是否可以为我们的需求进行操作：

```
reader@ubuntu:~$ if test -z ${PATH}; then read -p "Type something: " PATH; fi
reader@ubuntu:~$ if test -z ${empty_variable}; then read -p "Type something: " empty_variable; fi
Type something: Yay!
reader@ubuntu:~$ echo ${empty_variable} 
Yay!
reader@ubuntu:~$ if test -z ${empty_variable}; then read -p "Type something: " empty_variable; fi
reader@ubuntu:~
```

首先，我们在`PATH`变量上使用了我们构建的`if-then`子句。由于它不是空的，我们不希望出现提示：幸好我们没有得到！我们使用了相同的结构，但现在是使用`empty_variable`。看哪，由于`test -z`返回了退出码 0，所以`if-then`子句的`then`部分被执行，并提示我们输入一个值。在输入值之后，我们可以将其输出。再次运行`if-then`子句不会给我们`read`提示，因为此时变量`empty_variable`不再为空！

最后，让我们将这种`if-then`逻辑融入到我们的`new interactive-ultimate.sh`脚本中：

```
reader@ubuntu:~/scripts/chapter_08$ cp interactive.sh interactive-ultimate.sh
reader@ubuntu:~/scripts/chapter_08$ vim interactive-ultimate.sh 
reader@ubuntu:~/scripts/chapter_08$ cat interactive-ultimate.sh 
#!/bin/bash

#####################################
# Author: Sebastiaan Tammer
# Version: v1.0.0
# Date: 2018-09-09
# Description: Show the best of both worlds!
# Usage: ./interactive-ultimate.sh [fictional-character-name] [actual-
# location] [favorite-food]
#####################################

# Grab arguments.
character_name=$1
location=$2
food=$3

# Prompt the user for information, if it was not passed as arguments.
if test -z ${character_name}; then read -p "Name a fictional character: " character_name; fi
if test -z ${location}; then read -p "Name an actual location: " location; fi
if test -z ${food}; then read -p "What's your favorite food? " food; fi

# Compose the story.
echo "Recently, ${character_name} was seen in ${location} eating ${food}!"

reader@ubuntu:~/scripts/chapter_08$ bash interactive-ultimate.sh 
"Goofy"

Name an actual location: Barcelona
What's your favorite food? a hotdog
Recently, Goofy was seen in Barcelona eating a hotdog!
```

成功！我们被提示输入`location`和`food`，但`character_name`成功地从我们传递的参数中解析出来。我们创建了一个脚本，可以完全交互使用，而无需提供参数，但也可以使用参数进行非交互操作。

虽然这个脚本很有信息量，但效率并不是很高。最好是将`test`直接与传递的参数（`$1`，`$2`，`$3`）结合起来，这样我们只需要一行。在本书的后面，我们将开始使用这样的优化，但现在更重要的是将事情写得详细一些，这样您就可以更容易地理解它们！

# 总结

在本章开始时，我们解释了什么是变量：它是一个标准的构建块，允许我们存储信息，以便以后引用。我们更喜欢使用变量有很多原因：我们可以存储一个值一次并多次引用它，如果需要更改值，我们只需更改一次，新值将在所有地方使用。

我们解释了常量是一种特殊类型的变量：它只在脚本开始时定义一次，不受用户输入的影响，在脚本执行过程中不会改变。

我们继续讨论了一些关于变量命名的注意事项。我们演示了 Bash 在变量命名方面非常灵活：它允许许多不同风格的变量命名。但是，我们解释了如果在同一个脚本或多个脚本之间使用多种不同的命名约定，可读性会受到影响。最好的方法是选择一种变量命名方式，并坚持下去。我们建议使用大写字母表示常量，使用小写字母和下划线分隔其他变量。这将减少本地变量和环境变量之间冲突的机会。

接下来，我们探讨了用户输入以及如何处理它。我们赋予我们脚本的用户改变脚本结果的能力，这几乎是大多数现实生活中功能脚本的必备功能。我们描述了两种不同的用户交互方法：使用位置参数的基本输入，以及使用`read`构造的交互式输入。

我们在本章结束时简要介绍了 if-then 逻辑和`test`命令。我们使用这些概念创建了一种处理用户输入的强大方式，将位置参数与`read`提示结合起来处理缺少的信息，同时介绍了单独使用每种方法的利弊。这样创建了一个脚本，可以根据使用情况进行交互和非交互操作。

本章介绍了以下命令：`read`、`test`和`if`。

# 问题

1.  什么是变量？

1.  我们为什么需要变量？

1.  什么是常量？

1.  为什么变量的命名约定特别重要？

1.  什么是位置参数？

1.  参数和参数之间有什么区别？

1.  我们如何使脚本交互式？

1.  我们如何创建一个既可以进行非交互操作又可以进行交互操作的脚本？

# 进一步阅读

如果您想更深入地了解本章主题，以下资源可能会很有趣：

+   **Bash 变量**：[`ryanstutorials.net/bash-scripting-tutorial/bash-variables.php`](https://ryanstutorials.net/bash-scripting-tutorial/bash-variables.php)

+   谷歌 Shell 风格指南：[`google.github.io/styleguide/shell.xml`](https://google.github.io/styleguide/shell.xml)


# 第九章：错误检查和处理

在本章中，我们将描述如何检查错误并优雅地处理它们。我们将首先解释退出状态的概念，然后进行一些使用`test`命令的功能检查。之后，我们将开始使用`test`命令的简写表示法。本章的下一部分专门讨论错误处理：我们将使用`if-then-exit`和`if-then-else`来处理简单的错误。在本章的最后部分，我们将介绍一些可以防止错误发生的方法，因为预防胜于治疗。

本章将介绍以下命令：`mktemp`，`true`和`false`。

本章将涵盖以下主题：

+   错误检查

+   错误处理

+   错误预防

# 技术要求

本章只需要 Ubuntu 虚拟机。如果您从未更新过您的机器，现在可能是一个好时机！`sudo apt update && sudo apt upgrade -y`命令会完全升级您的机器上的所有工具。如果您选择这样做，请确保重新启动您的机器，以加载升级后的内核。在 Ubuntu 上，如果存在`/var/log/reboot-required`文件，您可以确定需要重新启动。

本章的所有脚本都可以在 GitHub 上找到：[`github.com/PacktPublishing/Learn-Linux-Shell-Scripting-Fundamentals-of-Bash-4.4/tree/master/Chapter09`](https://github.com/PacktPublishing/Learn-Linux-Shell-Scripting-Fundamentals-of-Bash-4.4/tree/master/Chapter09)。

# 错误检查

在上一章中，我们花了一些时间解释了如何在脚本中捕获和使用*用户输入*。虽然这使得我们的脚本更加动态，从而更加实用，但我们也引入了一个新概念：**人为错误**。假设您正在编写一个脚本，您希望向用户提出一个是/否问题。您可能期望一个合理的用户使用以下任何一个作为答案：

+   y

+   n

+   是

+   否

+   是

+   否

+   是

+   不

+   YES

+   否

虽然 Bash 允许我们检查我们能想到的所有值，但有时用户仍然可以通过提供您不希望的输入来*破坏*脚本。例如，用户用他们的母语回答是/否问题：`ja`，`si`，`nei`，或者其他无数的可能性。实际上，您会发现您*永远*无法考虑到用户提供的每种可能的输入。鉴于事实如此，最好的解决方案是处理最常见的预期输入，并用通用错误消息捕获所有其他输入，告诉用户*如何正确提供答案*。我们将在本章后面看到如何做到这一点，但首先，我们将开始查看如何甚至确定是否发生了错误，通过检查命令的**退出状态**。

# 退出状态

退出状态，通常也称为*退出代码*或*返回代码*，是 Bash 向其父进程通信进程成功或不成功终止的方式。在 Bash 中，所有进程都是从调用它们的 shell 中*fork*出来的。以下图解释了这一点：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-linux-sh-scp/img/ee93b0e8-d32a-41ec-ace1-c7e41a598265.png)

当命令运行时，例如前面图中的`ps -f`，当前 shell 被复制（包括环境变量！），命令在副本中运行，称为*fork*。命令/进程完成后，它终止 fork 并将退出状态返回给最初从中 fork 出来的 shell（在交互会话的情况下，将是您的用户会话）。在那时，您可以通过查看退出代码来确定进程是否成功执行。如前一章所述，退出代码为 0 被认为是 OK，而所有其他代码应被视为 NOT OK。由于 fork 被终止，我们需要返回代码，否则我们将无法将状态传递回我们的会话！

因为我们已经在上一章的交互式会话中看到了如何获取退出状态（提示：我们查看了`$?`变量的内容！），让我们看看如何在脚本中做同样的事情：

```
reader@ubuntu:~/scripts/chapter_09$ vim return-code.sh
reader@ubuntu:~/scripts/chapter_09$ cat return-code.sh 
#!/bin/bash

#####################################
# Author: Sebastiaan Tammer
# Version: v1.0.0
# Date: 2018-09-29
# Description: Teaches us how to grab a return code.
# Usage: ./return-code.sh
#####################################

# Run a command that should always work:
mktemp
mktemp_rc=$?

# Run a command that should always fail:
mkdir /home/
mkdir_rc=$?

echo "mktemp returned ${mktemp_rc}, while mkdir returned ${mkdir_rc}!"

reader@ubuntu:~/scripts/chapter_09$ bash return-code.sh 
/tmp/tmp.DbxKK1s4aV
mkdir: cannot create directory ‘/home’: File exists
mktemp returned 0, while mkdir returned 1!
```

通过脚本，我们从 shebang 和 header 开始。由于在此脚本中我们不使用用户输入，因此用法只是脚本名称。我们运行的第一个命令是`mktemp`。这个命令用于创建一个具有随机名称的临时*文件*，如果我们需要在磁盘上有一个临时数据的地方，这可能会很有用。或者，如果我们向`mktemp`提供了`-d`标志，我们将创建一个具有随机名称的临时*目录*。因为随机名称足够长，并且我们应该始终在`/tmp/`中有写权限，我们期望`mktemp`命令几乎总是成功的，因此返回退出状态为 0。我们通过在命令**直接完成后**运行变量赋值来将返回代码保存到`mktemp_rc`变量中。这就是返回代码的最大弱点所在：我们只能在命令完成后直接使用它们。如果我们在之后做任何其他事情，返回代码将被设置为该操作，覆盖先前的退出状态！

接下来，我们运行一个我们期望总是失败的命令：`mkdir /home/`。我们期望它失败的原因是因为在我们的系统上（以及几乎每个 Linux 系统上），`/home/`目录已经存在。在这种情况下，它无法再次创建，这就是为什么该命令以退出状态 1 失败。同样，在`mkdir`命令之后，我们将退出状态保存到`mkdir_rc`变量中。

最后，我们需要检查我们的假设是否正确。使用`echo`，我们打印两个变量的值以及一些文本，以便知道我们在哪里打印了哪个值。这里还有一件事要注意：我们在包含变量的句子中使用了*双引号*。如果我们使用*单引号*，变量将不会被*展开*（Bash 术语是用变量的值替换变量名）。或者，我们可以完全省略引号，`echo`也会按预期执行，但是当我们开始使用重定向时，这可能会开始出现问题，这就是为什么我们认为在处理包含变量的字符串时始终使用双引号是一个好习惯。

# 功能检查

现在，我们知道如何检查进程的退出状态以确定它是否成功。然而，这并不是我们验证命令成功/失败的唯一方法。对于我们运行的大多数命令，我们还可以执行功能检查以查看我们是否成功。在上一个脚本中，我们尝试创建`/home/`目录。但是，如果我们更关心`/home/`目录的存在，而不是进程的退出状态呢？

以下脚本显示了我们如何对系统状态执行*功能检查*：

```
reader@ubuntu:~/scripts/chapter_09$ vim functional-check.sh
reader@ubuntu:~/scripts/chapter_09$ cat functional-check.sh 
#!/bin/bash

#####################################
# Author: Sebastiaan Tammer
# Version: v1.0.0
# Date: 2018-09-29
# Description: Introduces functional checks.
# Usage: ./functional-check.sh
#####################################

# Create a directory.
mkdir /tmp/temp_dir
mkdir_rc=$?

# Use test to check if the directory was created.
test -d /tmp/temp_dir
test_rc=$?

# Check out the return codes:
echo "mkdir resulted in ${mkdir_rc}, test resulted in ${test_rc}."

reader@ubuntu:~/scripts/chapter_09$ bash functional-check.sh 
mkdir resulted in 0, test resulted in 0.
reader@ubuntu:~/scripts/chapter_09$ bash functional-check.sh 
mkdir: cannot create directory ‘/tmp/temp_dir’: File exists
mkdir resulted in 1, test resulted in 0.
```

我们从通常的管道开始前面的脚本。接下来，我们想用`mkdir`创建一个目录。我们获取退出状态并将其存储在一个变量中。接下来，我们使用`test`命令（我们在上一章中简要探讨过）来验证`/tmp/temp_dir/`是否是一个目录（因此，如果它被创建了**某个时间**）。然后，我们用`echo`打印返回代码，方式与我们在 return-code.sh 中做的一样。

接下来，我们运行脚本两次。这里发生了一些有趣的事情。第一次运行脚本时，文件系统上不存在`/tmp/temp_dir/`目录，因此被创建。因此，`mkdir`命令的退出代码为 0。由于它成功创建了，`test -d`也成功，并像预期的那样给我们返回了退出状态 0。

现在，在脚本的第二次运行中，`mkdir`命令并没有成功完成。这是预期的，因为脚本的第一次运行已经创建了该目录。由于我们没有在两次运行之间删除它，`mkdir`的第二次运行是不成功的。然而，`test -d`仍然可以正常运行：**目录存在**，即使它并没有在脚本的那次运行中创建。

在创建脚本时，请确保仔细考虑如何检查错误。有时，返回代码是你需要的：当你需要确保命令已成功运行时就是这种情况。然而，有时功能性检查可能更合适。当最终结果很重要时（例如，目录必须存在），但造成所需状态的原因并不那么重要时，这通常是情况。

# 测试简写

`test`命令是我们 shell 脚本工具中最重要的命令之一。因为 shell 脚本经常很脆弱，特别是涉及用户输入时，我们希望尽可能使其健壮。虽然解释`test`命令的每个方面需要一整章，但以下是`test`可以做的事情：

+   检查文件是否存在

+   检查目录是否存在

+   检查变量是否不为空

+   检查两个变量是否具有相同的值

+   检查 FILE1 是否比 FILE2 旧

+   检查 INTEGER1 是否大于 INTEGER2

等等等等——这应该至少让你对可以用`test`检查的事情有所印象。在*进一步阅读*部分，我们包含了有关测试的广泛来源。确保看一看，因为它肯定会帮助你进行 shell 脚本编写冒险！

对于大多数脚本和编程语言，没有`test`命令这样的东西。显然，在这些语言中测试同样重要，但与 Bash 不同的是，测试通常直接与`if-then-else`逻辑集成在一起（我们将在本章的下一部分讨论）。幸运的是，Bash 有一个`test`命令的简写，这使它与其他语言的语法更接近：`[`和`[[`。

看一下以下代码，以更好地了解我们如何用这种简写替换`test`命令：

```
reader@ubuntu:~/scripts/chapter_09$ vim test-shorthand.sh
reader@ubuntu:~/scripts/chapter_09$ cat test-shorthand.sh 
#!/bin/bash

#####################################
# Author: Sebastiaan Tammer
# Version: v1.0.0
# Date: 2018-09-29
# Description: Write faster tests with the shorthand!
# Usage: ./test-shorthand.sh
#####################################

# Test if the /tmp/ directory exists using the full command:
test -d /tmp/
test_rc=$?

# Test if the /tmp/ directory exists using the simple shorthand:
[ -d /tmp/ ]
simple_rc=$?

# Test if the /tmp/ directory exists using the extended shorthand:
[[ -d /tmp/ ]]
extended_rc=$?

# Print the results.
echo "The return codes are: ${test_rc}, ${simple_rc}, ${extended_rc}."

reader@ubuntu:~/scripts/chapter_09$ bash test-shorthand.sh 
The return codes are: 0, 0, 0.
```

正如你所看到的，在我们介绍的`test`语法之后，我们开始进行管道操作。接下来，我们用`[`替换了 test 这个词，并以`]`结束了这一行。这是 Bash 与其他脚本/编程语言共有的部分。请注意，与大多数语言不同，Bash 要求在`[`之后和`]`之前有**空格**！最后，我们使用了扩展的简写语法，以`[[`开头，以`]]`结尾。当我们打印返回代码时，它们都返回`0`，这意味着所有测试都成功了，即使使用了不同的语法。

[ ]和[[ ]]之间的区别很小，但可能非常重要。简单地说，[ ]的简写语法在变量或路径中包含空格时可能会引入问题。在这种情况下，测试会将空格视为分隔符，这意味着字符串`hello there`变成了两个参数而不是一个（`hello + there`）。还有其他区别，但最终我们的建议非常简单：**使用[[ ]]的扩展简写语法**。有关更多信息，请参阅测试部分的*进一步阅读*。

# 变量复习

作为一个小小的奖励，我们对`test-shorthand.sh`脚本进行了轻微改进。在上一章中，我们解释了，如果我们在脚本中多次使用相同的值，最好将其作为变量。如果变量的值在脚本执行过程中不会改变，并且不受用户输入的影响，我们使用一个常量。看看我们如何在之前的脚本中加入这个：

```
reader@ubuntu:~/scripts/chapter_09$ cp test-shorthand.sh test-shorthand-variable.sh
reader@ubuntu:~/scripts/chapter_09$ vim test-shorthand-variable.sh 
reader@ubuntu:~/scripts/chapter_09$ cat test-shorthand-variable.sh 
#!/bin/bash

#####################################
# Author: Sebastiaan Tammer
# Version: v1.0.0
# Date: 2018-09-29
# Description: Write faster tests with the shorthand, now even better 
# with a CONSTANT!
# Usage: ./test-shorthand-variable.sh
#####################################

DIRECTORY=/tmp/

# Test if the /tmp/ directory exists using the full command:
test -d ${DIRECTORY}
test_rc=$?

# Test if the /tmp/ directory exists using the simple shorthand:
[ -d ${DIRECTORY} ]
simple_rc=$?

# Test if the /tmp/ directory exists using the extended shorthand:
[[ -d ${DIRECTORY} ]]
extended_rc=$?

# Print the results.
echo "The return codes are: ${test_rc}, ${simple_rc}, ${extended_rc}."

reader@ubuntu:~/scripts/chapter_09$ bash test-shorthand-variable.sh 
The return codes are: 0, 0, 0.
```

虽然最终结果是相同的，但如果我们想要更改它，这个脚本更加健壮。此外，它向我们展示了我们可以在`test`简写中使用变量，这些变量将自动被 Bash 展开。

# Bash 调试

我们还有一个更聪明的方法来证明值是否被正确展开：使用 Bash 脚本**带有调试日志**运行。看一下以下执行：

```
reader@ubuntu:~/scripts/chapter_09$ bash -x test-shorthand-variable.sh 
+ DIRECTORY=/tmp/
+ test -d /tmp/
+ test_rc=0
+ '[' -d /tmp/ ']'
+ simple_rc=0
+ [[ -d /tmp/ ]]
+ extended_rc=0
+ echo 'The return codes are: 0, 0, 0.'
The return codes are: 0, 0, 0.
```

如果您将此与实际脚本进行比较，您将看到脚本文本`test -d ${DIRECTORY}`在运行时解析为`test -d /tmp/`。这是因为我们没有运行`bash test-shorthand-variable.sh`，而是运行`bash -x test-shorthand-variable.sh`。在这种情况下，`-x`标志告诉 Bash*打印命令及其参数在执行时*——这是一个非常方便的事情，如果您曾经编写脚本并不确定为什么脚本没有按照您的期望执行！

# 错误处理

到目前为止，我们已经看到了如何检查错误。然而，除了检查错误之外，还有一个同样重要的方面：处理错误。我们将首先结合我们以前的`if`和`test`的经验来处理错误，然后介绍更智能的处理错误的方法！

# if-then-exit

正如您可能还记得的，Bash 使用的`if-then`结构对（几乎）所有编程语言都是通用的。在其基本形式中，想法是您测试一个条件（IF），如果该条件为真，则执行某些操作（THEN）。

这是一个非常基本的例子：如果`name`的长度大于或等于 2 个字符，则`echo "hello ${name}"`。在这种情况下，我们假设一个名字至少要有 2 个字符。如果不是，输入是无效的，我们不会给它一个“hello”。

在下面的脚本`if-then-exit.sh`中，我们将看到我们的目标是使用`cat`打印文件的内容。然而，在这之前，我们检查文件是否存在，如果不存在，我们将退出脚本，并向调用者显示指定出了什么问题的消息：

```
reader@ubuntu:~/scripts/chapter_09$ vim if-then-exit.sh 
reader@ubuntu:~/scripts/chapter_09$ cat if-then-exit.sh 
#!/bin/bash

#####################################
# Author: Sebastiaan Tammer
# Version: v1.0.0
# Date: 2018-09-30
# Description: Use the if-then-exit construct.
# Usage: ./if-then-exit.sh
#####################################

FILE=/tmp/random_file.txt

# Check if the file exists.
if [[ ! -f ${FILE} ]]; then 
  echo "File does not exist, stopping the script!"
  exit 1
fi

# Print the file content.
cat ${FILE}

reader@ubuntu:~/scripts/chapter_09$ bash -x if-then-exit.sh
+ FILE=/tmp/random_file.txt
+ [[ ! -f /tmp/random_file.txt ]]
+ echo 'File does not exist, stopping the script!'
File does not exist, stopping the script!
+ exit 1
```

到目前为止，这个脚本应该是清楚的。我们使用了测试的*扩展简写语法*，就像我们在本书的其余部分中所做的那样。`-f`标志在`test`的 man 页面中被描述为*文件存在且是一个常规文件*。然而，在这里我们遇到了一个小问题：我们想要打印文件（使用`cat`），但只有在文件存在时才这样做；否则，我们想要使用`echo`打印消息。在本章后面，当我们介绍`if-then-else`时，我们将看到如何使用正测试来实现这一点。不过，目前我们希望测试在我们检查的文件**不是**一个现有文件时给我们一个 TRUE。在这种情况下，从语义上讲，我们正在做以下事情：如果文件不存在，则打印一条消息并退出。Bash 中的测试语法没有一个标志可以做到这一点。幸运的是，我们可以使用一个强大的构造：感叹号，！，它可以对测试进行否定/反转！

这些示例如下：

+   if [[-f /tmp/file]]; then *做某事* -> 如果文件/tmp/file 存在，则执行*做某事*

+   if [[！-f /tmp/file]]; then *做某事* -> 如果文件/tmp/file 不存在，则执行*做某事*

+   if [[-n ${variable}]]; then *做某事* -> 如果变量${variable}不为空，则执行*做某事*

+   if [[！-n ${variable}]]; then *做某事* -> 如果变量${variable}**不**为空，则执行*做某事*（因此，双重否定意味着只有在变量实际为空时才执行 do-something）

+   if [[-z ${variable}]]; then *做某事* -> 如果变量${variable}为空，则执行*做某事*

+   if [[！-z ${variable}]]; then *做某事* -> 如果变量${variable}**不**为空，则执行*做某事*

正如你应该知道的那样，最后四个例子是重叠的。这是因为标志`-n`（非零）和`-z`（零）已经是彼此的对立面。由于我们可以用!否定测试，这意味着`-z`等于`! -n`，而`! -z`与`-n`相同。在这种情况下，使用`-n`或!`-z`都无关紧要。我们建议您在使用另一个标志的否定之前，先使用特定的标志。

让我们回到我们的脚本。当我们使用否定的文件存在测试发现文件不存在时，我们向调用者打印了有用的消息并退出了脚本。在这种情况下，我们从未达到`cat`命令，但由于文件根本不存在，`cat`永远不会成功。如果我们让执行继续到那一点，我们将收到`cat`的错误消息。对于`cat`来说，这条消息并不比我们自己的消息更糟糕，但对于其他一些命令来说，错误消息绝对不总是像我们希望的那样清晰；在这种情况下，我们自己的检查并附上清晰的消息并不是一件坏事！

这里有另一个例子，我们在其中使用 if 和 test 来查看我们将在变量中捕获的状态代码：

```
reader@ubuntu:~/scripts/chapter_09$ vim if-then-exit-rc.sh
reader@ubuntu:~/scripts/chapter_09$ cat if-then-exit-rc.sh 
#!/bin/bash

#####################################
# Author: Sebastiaan Tammer
# Version: v1.0.0
# Date: 2018-09-30
# Description: Use return codes to stop script flow.
# Usage: ./if-then-exit-rc.sh
#####################################

# Create a new top-level directory.
mkdir /temporary_dir
mkdir_rc=$?

# Test if the directory was created successfully.
if [[ ${mkdir_rc} -ne 0 ]]; then
  echo "mkdir did not successfully complete, stop script execution!"
  exit 1
fi

# Create a new file in our temporary directory.
touch /temporary_dir/tempfile.txt

reader@ubuntu:~/scripts/chapter_09$ bash if-then-exit-rc.sh
mkdir: cannot create directory ‘/temporary_dir’: Permission denied
mkdir did not successfully complete, stop script execution!
```

在脚本的第一个功能部分中，我们试图创建顶层目录`/temporary_dir/`。由于只有 root 用户拥有这些特权，而我们既不是以 root 用户身份运行，也没有使用`sudo`，所以`mkdir`失败了。当我们在`mkdir_rc`变量中捕获退出状态时，我们不知道确切的值（如果需要，我们可以打印它），但我们知道一件事：它不是`0`，这个值是保留用于成功执行的。因此，我们有两个选择：我们可以检查退出状态是否**不等于 0**，或者状态代码是否**等于 1**（这实际上是`mkdir`在这种情况下向父 shell 报告的）。我们通常更喜欢**检查成功的缺席**，而不是检查特定类型的失败（如不同的返回代码，如 1、113、127、255 等）。如果我们只在退出代码为 1 时停止，那么我们将在所有不得到 1 的情况下继续脚本：这有希望是 0，但我们不能确定。总的来说，任何不成功的事情都需要停止脚本！

对于这种情况，检查返回代码是否不是`0`，我们使用整数（记住，*数字*的一个花哨的词）比较。如果我们检查`man test`，我们可以看到`-ne`标志被描述为`INTEGER1 -ne INTEGER2：INTEGER1 不等于 INTEGER2`。因此，对于我们的逻辑，这意味着，如果在变量中捕获的返回代码**不等于**`0`，命令就没有成功执行，我们应该停止。记住，我们也可以使用`-eq`（**等于**）标志，并用`!`否定它以达到相同的效果。

在当前形式中，脚本比严格需要的要长一点。我们首先将返回代码存储在一个变量中，然后再比较该变量。我们还可以直接在`if-test`结构中使用退出状态，就像这样：

```
reader@ubuntu:~/scripts/chapter_09$ cp if-then-exit-rc.sh if-then-exit-rc-improved.sh
reader@ubuntu:~/scripts/chapter_09$ vim if-then-exit-rc-improved.sh
reader@ubuntu:~/scripts/chapter_09$ cat if-then-exit-rc-improved.sh 
#!/bin/bash

#####################################
# Author: Sebastiaan Tammer
# Version: v1.0.0
# Date: 2018-09-30
# Description: Use return codes to stop script flow.
# Usage: ./if-then-exit-rc-improved.sh
#####################################

# Create a new top-level directory.
mkdir /temporary_dir

# Test if the directory was created successfully.
if [[ $? -ne 0 ]]; then
  echo "mkdir did not successfully complete, stop script execution!"
  exit 1
fi

# Create a new file in our temporary directory.
touch /temporary_dir/tempfile.txt

reader@ubuntu:~/scripts/chapter_09$ bash if-then-exit-rc-improved.sh 
mkdir: cannot create directory ‘/temporary_dir’: Permission denied
mkdir did not successfully complete, stop script execution!
```

虽然这*只*节省了一行（变量赋值），但也节省了一个不必要的变量。你可以看到我们将测试改为比较 0 和$?。我们知道无论如何我们都想检查执行，所以我们也可以立即这样做。如果以后需要再做，我们仍然需要将其保存在一个变量中，因为记住：退出状态只在运行命令后直接可用。在那之后，它已经被后续命令的退出状态覆盖了。

# if-then-else

到目前为止，你应该已经对`if-then`逻辑有了一些了解。然而，你可能觉得还缺少了一些东西。如果是这样，你是对的！一个`if-then`结构没有 ELSE 语句是不完整的。`if-then-else`结构允许我们指定如果 if 子句中的测试**不**为真时应该发生什么。从语义上讲，它可以被翻译为：

如果条件，那么做某事，否则（其他情况）做其他事情

我们可以通过拿我们之前的一个脚本`if-then-exit.sh`来很容易地说明这一点，并优化脚本的流程和代码：

```
reader@ubuntu:~/scripts/chapter_09$ cp if-then-exit.sh if-then-else.sh
reader@ubuntu:~/scripts/chapter_09$ vim if-then-else.sh 
reader@ubuntu:~/scripts/chapter_09$ cat if-then-else.sh 
#!/bin/bash

#####################################
# Author: Sebastiaan Tammer
# Version: v1.0.0
# Date: 2018-09-30
# Description: Use the if-then-else construct.
# Usage: ./if-then-else.sh
#####################################

FILE=/tmp/random_file.txt

# Check if the file exists.
if [[ ! -f ${FILE} ]]; then 
  echo "File does not exist, stopping the script!"
  exit 1
else
  cat ${FILE} # Print the file content.
fi

reader@ubuntu:~/scripts/chapter_09$ bash if-then-else.sh 
File does not exist, stopping the script!
reader@ubuntu:~/scripts/chapter_09$ touch /tmp/random_file.txt
reader@ubuntu:~/scripts/chapter_09$ bash -x if-then-else.sh 
+ FILE=/tmp/random_file.txt
+ [[ ! -f /tmp/random_file.txt ]]
+ cat /tmp/random_file.txt
```

现在，这开始看起来像是一些东西！我们将`cat`命令移到了`if-then-else`逻辑块中。现在，它感觉（而且确实是！）像一个单一的命令：如果文件不存在，则打印错误消息并退出，否则打印其内容。不过，我们在错误情况下使用了 then 块有点奇怪；按照惯例，then 块是为成功条件保留的。我们可以通过交换 then 和 else 块来使我们的脚本更加直观；但是，我们还需要反转我们的测试条件。让我们来看一下：

```
reader@ubuntu:~/scripts/chapter_09$ cp if-then-else.sh if-then-else-proper.sh
reader@ubuntu:~/scripts/chapter_09$ vim if-then-else-proper.sh 
reader@ubuntu:~/scripts/chapter_09$ cat if-then-else-proper.sh 
#!/bin/bash

#####################################
# Author: Sebastiaan Tammer
# Version: v1.0.0
# Date: 2018-09-30
# Description: Use the if-then-else construct, now properly.
# Usage: ./if-then-else-proper.sh file-name
#####################################

file_name=$1

# Check if the file exists.
if [[ -f ${file_name} ]]; then 
  cat ${file_name} # Print the file content.
else
  echo "File does not exist, stopping the script!"
  exit 1
fi

reader@ubuntu:~/scripts/chapter_09$ bash -x if-then-else-proper.sh /home/reader/textfile.txt 
+ FILE=/home/reader/textfile.txt
+ [[ -f /home/reader/textfile.txt ]]
+ cat /home/reader/textfile.txt
Hi, this is some text.
```

我们在这个脚本中所做的更改如下：

+   我们用用户输入变量`file_name`替换了硬编码的 FILE 常量

+   我们去掉了`test`的!反转

+   我们交换了 then 和 else 执行块

现在，脚本首先检查文件是否存在，如果存在，则打印其内容（成功场景）。如果文件不存在，脚本将打印错误消息并以退出代码 1 退出（失败场景）。在实践中，`else`通常用于失败场景，`then`用于成功场景。但这并不是铁律，可能会有所不同，根据您可用的测试类型。如果您正在编写脚本，并且希望使用 else 块来处理成功场景，那就尽管去做：只要您确定这是您情况下的正确选择，绝对没有什么可耻的！

您可能已经注意到，在`if-then-else`块中，我们在 then 或 else 中执行的命令之前始终有两个空格。在脚本/编程中，这称为缩进。在 Bash 中，它只有一个功能：提高可读性。通过用两个空格缩进这些命令，我们知道它们是 then-else 逻辑的一部分。同样，很容易看到`then`在哪里结束，`else`在哪里开始。请注意，在某些语言中，特别是 Python，空白是编程语言语法的一部分，不能省略！

到目前为止，我们只使用`if-then-else`逻辑来检测错误，然后退出`1`。然而，在某些情况下，*then*和*else*都可以用来实现脚本的目标，而不是其中一个用于错误处理。看一下以下脚本：

```
reader@ubuntu:~/scripts/chapter_09$ vim empty-file.sh 
reader@ubuntu:~/scripts/chapter_09$ cat empty-file.sh 
#!/bin/bash

#####################################
# Author: Sebastiaan Tammer
# Version: v1.0.0
# Date: 2018-10-02
# Description: Make sure the file given as an argument is empty.
# Usage: ./empty-file.sh <file-name>
#####################################

# Grab the first argument.
file_name=$1

# If the file exists, overwrite it with the always empty file 
# /dev/null; otherwise, touch it.
if [[ -f ${file_name} ]]; then
  cp /dev/null ${file_name}
else
  touch ${file_name}
fi

# Check if either the cp or touch worked correctly.
if [[ $? -ne 0 ]]; then
  echo "Something went wrong, please check ${file_name}!"
  exit 1
else
  echo "Succes, file ${file_name} is now empty."
fi

reader@ubuntu:~/scripts/chapter_09$ bash -x empty-file.sh /tmp/emptyfile
+ file_name=/tmp/emptyfile
+ [[ -f /tmp/emptyfile ]]
+ touch /tmp/emptyfile
+ [[ 0 -ne 0 ]]
+ echo 'Succes, file /tmp/emptyfile is now empty.'
Succes, file /tmp/emptyfile is now empty.
reader@ubuntu:~/scripts/chapter_09$ bash -x empty-file.sh /tmp/emptyfile
+ file_name=/tmp/emptyfile
+ [[ -f /tmp/emptyfile ]]
+ cp /dev/null /tmp/emptyfile
+ [[ 0 -ne 0 ]]
+ echo 'Succes, file /tmp/emptyfile is now empty.'
Succes, file /tmp/emptyfile is now empty.
```

我们使用此脚本来确保文件存在且为空。基本上，有两种情况：文件存在（*可能*不为空）或不存在。在我们的**if**测试中，我们检查文件是否存在。如果存在，我们通过将`/dev/null`（始终为空）复制到用户给定的位置来用空文件替换它。否则，如果文件不存在，我们只需使用`touch`创建它。

正如您在脚本执行中所看到的，第一次运行此脚本时，文件不存在，并且使用`touch`创建。在直接之后的脚本运行中，文件存在（因为它是在第一次运行中创建的）。这次，我们可以看到`cp`被使用。因为我们想确保这些操作中的任何一个是否成功，我们包含了额外的**if**块，用于处理退出状态检查，就像我们以前看到的那样。

# 简写语法

到目前为止，我们已经看到了使用 if 块来查看我们之前的命令是否成功运行的一些用法。虽然功能很棒，但在每个可能发生错误的命令之后使用 5-7 行真的会增加脚本的总长度！更大的问题将是可读性：如果一半的脚本是错误检查，可能很难找到代码的底部。幸运的是，我们可以在命令之后直接检查错误的方法。我们可以使用 || 命令来实现这一点，这是逻辑 OR 的 Bash 版本。它的对应物 && 是逻辑 AND 的实现。为了说明这一点，我们将介绍两个新命令：`true` 和 `false`。如果您查看各自的 man 页面，您将找到可能得到的最清晰的答案：

+   true：不执行任何操作，成功

+   false：不执行任何操作，不成功

以下脚本说明了我们如何使用 || 和 && 来创建逻辑应用程序流。如果逻辑运算符是陌生的领域，请先查看 *进一步阅读* 部分下的 *逻辑运算符* 链接：

```
reader@ubuntu:~/scripts/chapter_09$ vim true-false.sh 
reader@ubuntu:~/scripts/chapter_09$ cat true-false.sh 
#!/bin/bash

#####################################
# Author: Sebastiaan Tammer
# Version: v1.0.0
# Date: 2018-10-02
# Description: Shows the logical AND and OR (&& and ||).
# Usage: ./true-false.sh
#####################################

# Check out how an exit status of 0 affects the logical operators:
true && echo "We get here because the first part is true!"
true || echo "We never see this because the first part is true :("

# Check out how an exit status of 1 affects the logical operators:
false && echo "Since we only continue after && with an exit status of 0, this is never printed."
false || echo "Because we only continue after || with a return code that is not 0, we see this!"

reader@ubuntu:~/scripts/chapter_09$ bash -x true-false.sh 
+ true
+ echo 'We get here because the first part is true!'
We get here because the first part is true!
+ true
+ false
+ false
+ echo 'Because we only continue after || with a return code that is not 0, we see this!'
Because we only continue after || with a return code that is not 0, we see this!
```

正如我们所预期的，只有在前一个命令返回退出代码 0 时，才会执行 && 之后的代码，而只有在退出代码 **不是** 0 时（通常是 1）才会执行 || 之后的代码。如果您仔细观察，您实际上可以在脚本的调试中看到这种情况发生。您可以看到 `true` 被执行了两次，以及 `false`。然而，我们实际上看到的第一个 `echo` 是在第一个 true 之后，而我们看到的第二个 `echo` 是在第二个 false 之后！我们已经在前面的代码中突出显示了这一点，以方便您查看。

现在，我们如何使用这个来处理错误呢？错误将给出一个不为 0 的退出状态，因此这与 `false` 命令是可比的。在我们的例子中，逻辑运算符 || 后面的代码在 false 之后被打印出来。这是有道理的，因为 `false` 或 `echo` 应该成功。在这种情况下，由于 `false`（默认）失败，`echo` 被执行。在下面的简单示例中，我们将向您展示如何在脚本中使用 || 运算符：

```
reader@ubuntu:~/scripts/chapter_09$ vim logical-or.sh
reader@ubuntu:~/scripts/chapter_09$ cat logical-or.sh 
#!/bin/bash

#####################################
# Author: Sebastiaan Tammer
# Version: v1.0.0
# Date: 2018-10-02
# Description: Use the logical OR for error handling.
# Usage: ./logical-or.sh
#####################################

# This command will surely fail because we don't have the permissions needed:
cat /etc/shadow || exit 123

reader@ubuntu:~/scripts/chapter_09$ cat /etc/shadow
cat: /etc/shadow: Permission denied
reader@ubuntu:~/scripts/chapter_09$ echo $?
1
reader@ubuntu:~/scripts/chapter_09$ bash logical-or.sh 
cat: /etc/shadow: Permission denied
reader@ubuntu:~/scripts/chapter_09$ echo $?
123
```

我们尝试 `cat` 一个我们没有权限的文件（这是一件好事，因为 `/etc/shadow` 包含系统上所有用户的哈希密码）。当我们正常执行此操作时，我们会收到 1 的退出状态，就像我们的手动 `cat` 中所看到的那样。但是，在我们的脚本中，我们使用 `exit 123`。如果我们的逻辑运算符起作用，我们将不会以默认的 `1` 退出，而是以退出状态 `123`。当我们调用脚本时，我们会收到相同的 `Permission denied` 错误，但是这次当我们打印返回代码时，我们会看到预期的 `123`。

如果您真的想要确认，只有在第一部分失败时才会执行 || 后面的代码，请使用 `sudo` 运行脚本。在这种情况下，您将看到 `/etc/shadow` 的内容，因为 root 具有这些权限，退出代码将是 0，而不是之前的 1 和 123。

同样，如果您只想在完全确定第一个命令已成功完成时执行代码，也可以使用 &&。要以非常优雅的方式处理潜在错误，最好在 || 之后结合使用 `echo` 和 `exit`。在接下来的示例中，您将在接下来的几页中看到如何实现这一点！我们将在本书的其余部分中使用处理错误的方式，所以现在不要担心语法 - 在本书结束之前，您将遇到它很多次。

# 错误预防

到目前为止，您应该已经牢固掌握了我们如何处理（用户输入）错误。显然，这里的上下文是一切：根据情况，一些错误以不同的方式处理。本章中还有一个更重要的主题，那就是 *错误预防*。虽然知道如何处理错误是一回事，但如果我们能在脚本执行过程中完全避免错误，那就更好了。

# 检查参数

正如我们在上一章中指出的，当处理传递给脚本的位置参数时，有一些非常重要的事情。其中之一是空格，它表示参数之间的边界。如果我们需要向脚本传递包含空格的参数，我们需要将该参数用单引号或双引号括起来，否则它将被解释为多个参数。位置参数的另一个重要方面是确切地获得正确数量的参数：既不要太少，也绝对不要太多。

通过在使用位置参数的脚本中以检查传递的参数数量开始，我们可以验证用户是否正确调用了脚本。否则，我们可以指导用户如何正确调用它！以下示例向您展示了我们如何做到这一点：

```
reader@ubuntu:~/scripts/chapter_09$ vim file-create.sh 
reader@ubuntu:~/scripts/chapter_09$ cat file-create.sh 
#!/bin/bash

#####################################
# Author: Sebastiaan Tammer
# Version: v1.0.0
# Date: 2018-10-01
# Description: Create a file with contents with this script.
# Usage: ./file-create.sh <directory_name> <file_name> <file_content>
#####################################

# We need exactly three arguments, check how many have been passed to 
# the script.
if [[ $# -ne 3 ]]; then
  echo "Incorrect usage!"
  echo "Usage: $0 <directory_name> <file_name> <file_content>"
  exit 1
fi
# Arguments are correct, lets continue.

# Save the arguments into variables.
directory_name=$1
file_name=$2
file_content=$3

# Create the absolute path for the file.
absolute_file_path=${directory_name}/${file_name}

# Check if the directory exists; otherwise, try to create it.
if [[ ! -d ${directory_name} ]]; then
  mkdir ${directory_name} || { echo "Cannot create directory, exiting script!"; exit 1; }
fi

# Try to create the file, if it does not exist.
if [[ ! -f ${absolute_file_path} ]]; then
  touch ${absolute_file_path} || { echo "Cannot create file, exiting script!"; exit 1; }
fi

# File has been created, echo the content to it.
echo ${file_content} > ${absolute_file_path}

reader@ubuntu:~/scripts/chapter_09$ bash -x file-create.sh /tmp/directory/ newfile "Hello this is my file"
+ [[ 3 -ne 3 ]]
+ directory_name=/tmp/directory/
+ file_name=newfile
+ file_content='Hello this is my file'
+ absolute_file_path=/tmp/directory//newfile
+ [[ ! -d /tmp/directory/ ]]
+ mkdir /tmp/directory/
+ [[ ! -f /tmp/directory//newfile ]]
+ touch /tmp/directory//newfile
+ echo Hello this is my file
reader@ubuntu:~/scripts/chapter_09$ cat /tmp/directory/newfile 
Hello this is my file
```

为了正确说明这个原则和我们之前看到的一些其他原则，我们创建了一个相当大而复杂的脚本（与您之前看到的相比）。为了更容易理解这一点，我们将它分成几部分，并依次讨论每一部分。我们将从头部开始：

```
#!/bin/bash

#####################################
# Author: Sebastiaan Tammer
# Version: v1.0.0
# Date: 2018-10-01
# Description: Create a file with contents with this script.
# Usage: ./file-create.sh <directory_name> <file_name> <file_content>
#####################################
...
```

现在，shebang 和大多数字段应该感觉很自然。然而，在指定位置参数时，我们喜欢在**<>**中将它们括起来，如果它们是**必需的**，则在**[]**中将它们括起来，如果它们是**可选的**（例如，如果它们有默认值，我们将在本章末尾看到）。这是脚本编写中的常见模式，您最好遵循它！脚本的下一部分是实际检查参数数量的部分：

```
...
# We need exactly three arguments, check how many have been passed to the script.
if [[ $# -ne 3 ]]; then
  echo "Incorrect usage!"
  echo "Usage: $0 <directory_name> <file_name> <file_content>"
  exit 1
fi
# Arguments are correct, lets continue.
...
```

这一部分的魔力来自$#的组合。类似于$?退出状态构造，$#解析为传递给脚本的参数数量。因为这是一个整数，我们可以使用`test`的`-ne`和`-eq`标志将其与我们需要的参数数量进行比较：三个。任何*不是三个*的都不适用于这个脚本，这就是为什么我们以这种方式构建检查。如果*测试结果为正*（这意味着负结果！），我们执行`then-logic`，告诉用户他们错误地调用了脚本。为了防止再次发生这种情况，还传递了使用脚本的正确方法。我们在这里使用了另一个技巧，即$0 符号。这解析为脚本名称，这就是为什么在错误调用的情况下，脚本名称会很好地打印在实际预期参数旁边，就像这样：

```
reader@ubuntu:~/scripts/chapter_09$ bash file-create.sh 1 2 3 4 5
Incorrect usage!
Usage: file-create.sh <directory_name> <file_name> <file_content>
```

由于这个检查和对用户的提示，我们预期用户只会错误地调用此脚本一次。因为我们还没有开始处理脚本的功能，所以我们不会出现脚本中一半的任务已经完成的情况，即使我们在脚本开始时就知道它永远不会完成，因为缺少脚本需要的信息。让我们继续下一部分脚本：

```
...
# Save the arguments into variables.
directory_name=$1
file_name=$2
file_content=$3

# Create the absolute path for the file.
absolute_file_path=${directory_name}/${file_name}
...
```

作为回顾，我们可以看到我们将位置用户输入分配给一个我们选择的变量名，以表示它所保存的内容。因为我们需要多次使用最终文件的绝对路径，我们根据用户输入结合两个变量来形成文件的绝对路径。脚本的下一部分包含实际功能：

```
...
# Check if the directory exists; otherwise, try to create it.
if [[ ! -d ${directory_name} ]]; then
  mkdir ${directory_name} || { echo "Cannot create directory, exiting script!"; exit 1; }
fi

# Try to create the file, if it does not exist.
if [[ ! -f ${absolute_file_path} ]]; then
  touch ${absolute_file_path} || { echo "Cannot create file, exiting script!"; exit 1; }
fi

# File has been created, echo the content to it.
echo ${file_content} > ${absolute_file_path}
```

对于文件和目录，我们进行类似的检查：我们检查目录/文件是否已经存在，或者我们是否需要创建它。通过使用`echo`和`exit`的||简写，我们检查`mkdir`和`touch`是否返回退出状态 0。请记住，如果它们返回*除 0 以外的任何值*，则||之后和花括号内的所有内容都将被执行，这种情况下会退出脚本！

最后一部分包含了将回显重定向到文件的操作。简单地说，echo 的输出被重定向到一个文件中。重定向将在第十二章中深入讨论，“在脚本中使用管道和重定向”。现在，接受我们用于`${file_content}`的文本将被写入文件中（您可以自行检查）。

# 管理绝对路径和相对路径

我们还没有讨论的一个问题是：使用绝对路径和相对路径运行脚本。这可能看起来像是一个微不足道的差异，但实际上并非如此。大多数你运行的命令，无论是直接交互还是从你调用的脚本中运行，都使用你的当前工作目录作为它们的当前工作目录。你可能期望脚本中的命令默认为脚本所在的目录，但由于脚本只是你当前 shell 的一个分支（正如本章开头所解释的那样），它也继承了当前工作目录。我们可以通过创建一个复制文件到相对路径的脚本来最好地说明这一点：

```
reader@ubuntu:~/scripts/chapter_09$ vim log-copy.sh 
reader@ubuntu:~/scripts/chapter_09$ cat log-copy.sh 
#!/bin/bash

#####################################
# Author: Sebastiaan Tammer
# Version: v1.0.0
# Date: 2018-10-02
# Description: Copy dpkg.log to a local directory.
# Usage: ./log-copy.sh
#####################################

# Create the directory in which we'll store the file.
if [[ ! -d dpkg ]]; then
  mkdir dpkg || { echo "Cannot create the directory, stopping script."; exit 1; }
fi

# Copy the log file to our new directory.
cp /var/log/dpkg.log dpkg || { echo "Cannot copy dpkg.log to the new directory."; exit 1; }

reader@ubuntu:~/scripts/chapter_09$ ls -l dpkg
ls: cannot access 'dpkg': No such file or directory
reader@ubuntu:~/scripts/chapter_09$ bash log-copy.sh 
reader@ubuntu:~/scripts/chapter_09$ ls -l dpkg
total 632
-rw-r--r-- 1 reader reader 643245 Oct  2 19:39 dpkg.log
reader@ubuntu:~/scripts/chapter_09$ cd /tmp
reader@ubuntu:/tmp$ ls -l dpkg
ls: cannot access 'dpkg': No such file or directory
reader@ubuntu:/tmp$ bash /home/reader/scripts/chapter_09/log-copy.sh 
reader@ubuntu:/tmp$ ls -l dpkg
total 632
-rw-r--r-- 1 reader reader 643245 Oct  2 19:39 dpkg.log
```

脚本本身非常简单——检查目录是否存在，否则创建它。您可以使用我们的简写错误处理来检查`mkdir`的错误。接下来，将一个已知文件（`/var/log/dpkg.log`）复制到`dpkg`目录中。第一次运行时，我们与脚本位于同一目录。我们可以看到在那里创建了`dpkg`目录，并且文件被复制到其中。然后，我们将当前工作目录移动到`/tmp/`，并再次运行脚本，这次使用绝对路径而不是第一次调用的相对路径。现在，我们可以看到`dpkg`目录被创建在`/tmp/dpkg/`下！这并不是非常意外的，但我们如何可以“避免”这种情况呢？脚本开头的一行代码就可以解决这个问题：

```
reader@ubuntu:~/scripts/chapter_09$ cp log-copy.sh log-copy-improved.sh
reader@ubuntu:~/scripts/chapter_09$ vim log-copy-improved.sh 
reader@ubuntu:~/scripts/chapter_09$ cat log-copy-improved.sh 
#!/bin/bash

#####################################
# Author: Sebastiaan Tammer
# Version: v1.0.0
# Date: 2018-10-02
# Description: Copy dpkg.log to a local directory.
# Usage: ./log-copy-improved.sh
#####################################

# Change directory to the script location.
cd $(dirname $0)

# Create the directory in which we'll store the file.
if [[ ! -d dpkg ]]; then
  mkdir dpkg || { echo "Cannot create the directory, stopping script."; exit 1; }
fi

# Copy the log file to our new directory.
cp /var/log/dpkg.log dpkg || { echo "Cannot copy dpkg.log to the new directory."; exit 1; }

reader@ubuntu:~/scripts/chapter_09$ cd /tmp/
reader@ubuntu:/tmp$ rm -rf /tmp/dpkg/
reader@ubuntu:/tmp$ rm -rf /home/reader/scripts/chapter_09/dpkg/
reader@ubuntu:/tmp$ bash -x /home/reader/scripts/chapter_09/log-copy-improved.sh 
++ dirname /home/reader/scripts/chapter_09/log-copy-improved.sh
+ cd /home/reader/scripts/chapter_09
+ [[ ! -d dpkg ]]
+ mkdir dpkg
+ cp /var/log/dpkg.log dpkg
reader@ubuntu:/tmp$ ls -l dpkg
ls: cannot access 'dpkg': No such file or directory
```

正如代码执行所示，现在我们可以相对于脚本位置执行所有操作。这是通过一点点 Bash 魔法和`dirname`命令实现的。这个命令也很简单：它从我们传递的任何内容中打印目录名，这里是`$0`。你可能记得，$0 解析为脚本名称，因为它被调用。从`/tmp/`，这是绝对路径；如果我们从另一个目录调用它，它可能是一个相对路径。如果我们在与脚本相同的目录中，`dirname`，$0 将结果为`.`，这意味着我们`cd`到当前目录。这并不是真正需要的，但它也不会造成任何伤害。这似乎是一个小小的代价，换来了一个更加健壮的脚本，现在我们可以从任何地方调用它！

现在，我们不会详细讨论`$(...)`语法。我们将在第十二章中进一步讨论这个问题，“在脚本中使用管道和重定向”。在这一点上，记住这使我们能够在一行中获取一个值，然后将其传递给`cd`。

# 处理 y/n

在本章的开始，我们向您提出了一个思考的问题：通过陈述是或否来要求用户同意或不同意某事。正如我们讨论过的，有许多可能的答案可以期待用户给出。实际上，用户可以以五种方式给出“是”的答案：y、Y、yes、YES 和 Yes。

对于“否”也是一样。让我们看看如何在不使用任何技巧的情况下进行检查：

```
reader@ubuntu:~/scripts/chapter_09$ vim yes-no.sh 
reader@ubuntu:~/scripts/chapter_09$ cat yes-no.sh 
#!/bin/bash

#####################################
# Author: Sebastiaan Tammer
# Version: v1.0.0
# Date: 2018-10-01
# Description: Dealing with yes/no answers.
# Usage: ./yes-no.sh
#####################################

read -p "Do you like this question? " reply_variable

# See if the user responded positively.
if [[ ${reply_variable} = 'y' || ${reply_variable} = 'Y' || ${reply_variable} = 'yes' || ${reply_variable} = 'YES' || ${reply_variable} = 'Yes' ]]; then
  echo "Great, I worked really hard on it!"
  exit 0
fi

# Maybe the user responded negatively?
if [[ ${reply_variable} = 'n' || ${reply_variable} = 'N' || ${reply_variable} = 'no' || ${reply_variable} = 'NO' || ${reply_variable} = 'No' ]]; then
  echo "You did not? But I worked so hard on it!"
  exit 0
fi

# If we get here, the user did not give a proper response.
echo "Please use yes/no!"
exit 1

reader@ubuntu:~/scripts/chapter_09$ bash yes-no.sh 
Do you like this question? Yes
Great, I worked really hard on it!
reader@ubuntu:~/scripts/chapter_09$ bash yes-no.sh 
Do you like this question? n
You did not? But I worked so hard on it!
reader@ubuntu:~/scripts/chapter_09$ bash yes-no.sh 
Do you like this question? maybe 
Please use yes/no!
```

虽然这样做是有效的，但并不是一个非常可行的解决方案。更糟糕的是，如果用户在尝试输入“是”时碰巧开启了大写锁定键，我们最终会得到“yES”！我们需要包括这种情况吗？答案当然是否定的。Bash 有一个称为**参数扩展**的巧妙功能。我们将在第十六章中更深入地解释这一点，“Bash 参数替换和扩展”，但现在，我们可以给你一个它能做什么的预览：

```
reader@ubuntu:~/scripts/chapter_09$ cp yes-no.sh yes-no-optimized.sh
reader@ubuntu:~/scripts/chapter_09$ vim yes-no-optimized.sh 
reader@ubuntu:~/scripts/chapter_09$ cat yes-no-optimized.sh 
#!/bin/bash

#####################################
# Author: Sebastiaan Tammer
# Version: v1.0.0
# Date: 2018-10-01
# Description: Dealing with yes/no answers, smarter this time!
# Usage: ./yes-no-optimized.sh
#####################################

read -p "Do you like this question? " reply_variable

# See if the user responded positively.
if [[ ${reply_variable,,} = 'y' || ${reply_variable,,} = 'yes' ]]; then
  echo "Great, I worked really hard on it!"
  exit 0
fi

# Maybe the user responded negatively?
if [[ ${reply_variable^^} = 'N' || ${reply_variable^^} = 'NO' ]]; then
  echo "You did not? But I worked so hard on it!"
  exit 0
fi

# If we get here, the user did not give a proper response.
echo "Please use yes/no!"
exit 1

reader@ubuntu:~/scripts/chapter_09$ bash yes-no-optimized.sh 
Do you like this question? YES
Great, I worked really hard on it!
reader@ubuntu:~/scripts/chapter_09$ bash yes-no-optimized.sh 
Do you like this question? no
You did not? But I worked so hard on it!
```

现在，我们不再对每个答案进行五次检查，而是只使用两次：一个用于完整单词（是/否），一个用于简短的单字母答案（y/n）。但是，当我们只指定了*yes*时，答案*YES*是如何工作的呢？这个问题的解决方案在于我们在变量内部包含的,,和^^。因此，我们使用了${reply_variable,,}和${reply_variable^^}，而不是${reply_variable}。在,,,的情况下，变量首先解析为其值，然后转换为*所有小写字母*。因此，所有三个答案——*YES, Yes 和 yes*——都可以与*yes*进行比较，因为 Bash 会将它们扩展为这样。你可能猜到^^的作用是什么：它将字符串的内容转换为大写，这就是为什么我们可以将其与 NO 进行比较，即使我们给出的答案是 no。

始终试图站在用户的角度。他们正在处理许多不同的工具和命令。在这些情况下，处理不同方式的是/否写法的逻辑已经被整合。这甚至可以让最友好的系统管理员有点懒惰，并训练他们选择单字母答案。但你也不想惩罚那些真正听你话的系统管理员！因此，要点是以友好的方式处理最*合理*的答案。

# 摘要

在本章中，我们讨论了 Bash 脚本中错误的许多方面。首先描述了错误**检查**。首先，我们解释了退出状态是命令用来传达其执行是否被视为成功或失败的一种方式。介绍了`test`命令及其简写`[[...]]`符号。该命令允许我们在脚本中执行功能性检查。其中的示例包括比较字符串和整数，以及检查文件或目录是否被创建和可访问/可写。我们对变量进行了快速复习，然后简要介绍了使用调试标志`-x`运行脚本。

本章的第二部分涉及错误**处理**。我们描述了（非官方的）`if-then-exit`结构，我们用它来检查命令执行并在失败时退出。在随后的示例中，我们看到当我们想要检查它们时，我们并不总是需要将返回码写入变量中；我们可以直接在测试用例中使用$?。接着，我们预览了如何使用`if-then-else`逻辑更好地处理错误。我们通过介绍了错误处理的简写语法来结束本章的第二部分，这将在本书的其余部分中继续使用。

在本章的第三部分和最后一部分中，我们解释了错误**预防**。我们学习了如何检查参数是否正确，以及在调用脚本时如何避免绝对路径和相对路径的问题。在本章的最后部分，我们回答了一开始提出的问题：我们如何最好地处理用户的是/否输入？通过使用一些简单的 Bash 参数扩展（这将在本书的最后一章中进一步解释），我们能够简单地为我们的脚本的用户提供多种回答方式。

本章介绍了以下命令：`mktemp`、`true`和`false`。

# 问题

1.  我们为什么需要退出状态？

1.  退出状态、退出码和返回码之间有什么区别？

1.  我们在 test 中使用哪个标志来测试以下内容？

+   现有的目录

+   可写文件

+   现有的符号链接

1.  `test -d /tmp/`的首选简写语法是什么？

1.  如何在 Bash 会话中打印调试信息？

1.  我们如何检查变量是否有内容？

1.  抓取返回码的 Bash 格式是什么？

1.  `||`和`&&`中，哪个是逻辑与，哪个是逻辑或？

1.  抓取参数数量的 Bash 格式是什么？

1.  我们如何确保用户从任何工作目录调用脚本都没有关系？

1.  在处理用户输入时，Bash 参数扩展如何帮助我们？

# 进一步阅读

如果您想深入了解本章主题，以下资源可能会很有趣：

+   测试命令：[`wiki.bash-hackers.org/commands/classictest`](http://wiki.bash-hackers.org/commands/classictest)

+   Bash 调试：[`tldp.org/LDP/Bash-Beginners-Guide/html/sect_02_03.html`](http://tldp.org/LDP/Bash-Beginners-Guide/html/sect_02_03.html)

+   逻辑运算符：[`secure.php.net/manual/en/language.operators.logical.php`](https://secure.php.net/manual/en/language.operators.logical.php)


# 第十章：正则表达式

本章介绍了正则表达式以及我们可以用来利用其功能的主要命令。我们将首先了解正则表达式背后的理论，然后深入到使用`grep`和`sed`的正则表达式的实际示例中。

我们还将解释通配符及其在命令行上的使用方式。

本章将介绍以下命令：`grep`、`set`、`egrep`和`sed`。

本章将涵盖以下主题：

+   什么是正则表达式？

+   通配符

+   使用`egrep`和`sed`的正则表达式

# 技术要求

本章的所有脚本都可以在 GitHub 上找到：[`github.com/tammert/learn-linux-shell-scripting/tree/master/chapter_10`](https://github.com/tammert/learn-linux-shell-scripting/tree/master/chapter_10)。除此之外，Ubuntu 虚拟机仍然是我们在本章中测试和运行脚本的方式。

# 介绍正则表达式

您可能以前听说过*正则表达式*或*regex*这个术语。对于许多人来说，正则表达式似乎非常复杂，通常是从互联网或教科书中摘取的，而没有完全掌握它的作用。

虽然这对于完成一项任务来说是可以的，但是比普通系统管理员更好地理解正则表达式可以让你在创建脚本和在终端上工作时脱颖而出。

一个精心设计的正则表达式可以帮助您保持脚本简短、简单，并且能够适应未来的变化。

# 什么是正则表达式？

实质上，正则表达式是一段*文本*，它作为其他文本的*搜索模式*。正则表达式使得很容易地说，例如，我想选择所有包含五个字符的单词的行，或者查找所有以`.log`结尾的文件。

一个示例可能有助于您的理解。首先，我们需要一个可以用来探索正则表达式的命令。在 Linux 中与正则表达式一起使用的最著名的命令是`grep`。

`grep`是一个缩写，意思是***g**lobal **r**egular **e**xpression **p**rint*。您可以看到，这似乎是解释这个概念的一个很好的候选者！

# grep

我们将按以下方式立即深入：

```
reader@ubuntu:~/scripts/chapter_10$ vim grep-file.txt
reader@ubuntu:~/scripts/chapter_10$ cat grep-file.txt 
We can use this regular file for testing grep.
Regular expressions are pretty cool
Did you ever realise that in the UK they say colour,
but in the USA they use color (and realize)!
Also, New Zealand is pretty far away.
reader@ubuntu:~/scripts/chapter_10$ grep 'cool' grep-file.txt 
Regular expressions are pretty cool
reader@ubuntu:~/scripts/chapter_10$ cat grep-file.txt | grep 'USA'
but in the USA they use color (and realize)!
```

首先，让我们探索`grep`的基本功能，然后再深入到正则表达式。`grep`的功能非常简单，如`man grep`中所述：*打印匹配模式的行*。

在前面的示例中，我们创建了一个包含一些句子的文件。其中一些以大写字母开头；它们大多以不同的方式结束；它们使用一些相似但不完全相同的单词。这些特征以及更多特征将在后续示例中使用。

首先，我们使用`grep`来匹配一个单词（默认情况下搜索区分大小写），并打印出来。`grep`有两种操作模式：

+   `grep <pattern> <file>`

+   `grep <pattern>`（需要以管道或`|`的形式输入）

第一种操作模式允许您指定一个文件名，从中您想要指定需要打印的行，如果它们匹配您指定的模式。`grep 'cool' grep-file.txt`命令就是一个例子。

还有另一种使用`grep`的方式：在流中。流是指*在传输中*到达您的终端的东西，但在移动过程中可以被更改。在这种情况下，对文件的`cat`通常会将所有行打印到您的终端上。

然而，通过管道符号（`|`），我们将`cat`的输出重定向到`grep`；在这种情况下，我们只需要指定要匹配的模式。任何不匹配的行将被丢弃，并且不会显示在您的终端上。

正如您所看到的，完整的语法是`cat grep-file.txt | grep 'USA'`。

管道是一种重定向形式，我们将在第十二章中进一步讨论，*在脚本中使用管道和重定向*。现在要记住的是，通过使用管道，`cat`的*输出*被用作`grep`的*输入*，方式与文件名被用作输入相同。在讨论`grep`时，我们（暂时）将使用首先解释的不使用重定向的方法。

因为单词*cool*和*USA*只在一行中找到，所以`grep`的两个实例都只打印那一行。但是如果一个单词在多行中找到，`grep`会按照它们遇到的顺序（通常是从上到下）打印它们：

```
reader@ubuntu:~/scripts/chapter_10$ grep 'use' grep-file.txt 
We can use this regular file for testing grep.
but in the USA they use color (and realize)!
```

使用`grep`，可以指定我们希望搜索是不区分大小写的，而不是默认的区分大小写的方法。例如，这是在日志文件中查找错误的一个很好的方法。一些程序使用单词*error*，其他使用*ERROR*，我们甚至偶尔会遇到*Error*。通过向`grep`提供`-i`标志，所有这些结果都可以返回：

```
reader@ubuntu:~/scripts/chapter_10$ grep 'regular' grep-file.txt 
We can use this regular file for testing grep.
reader@ubuntu:~/scripts/chapter_10$ grep -i 'regular' grep-file.txt 
We can use this regular file for testing grep.
Regular expressions are pretty cool
```

通过提供`-i`，我们现在看到了*regular*和*Regular*都已经匹配，并且它们的行已经被打印出来。

# 贪婪性

默认情况下，正则表达式被认为是贪婪的。这可能看起来是一个奇怪的术语来描述一个技术概念，但它确实非常合适。为了说明为什么正则表达式被认为是贪婪的，看看这个例子：

```
reader@ubuntu:~/scripts/chapter_10$ grep 'in' grep-file.txt 
We can use this regular file for testing grep.
Did you ever realise that in the UK they say colour,
but in the USA they use color (and realize)!
reader@ubuntu:~/scripts/chapter_10$ grep 'the' grep-file.txt 
Did you ever realise that in the UK they say colour,
but in the USA they use color (and realize)!
```

正如你所看到的，`grep`默认情况下不会寻找完整的单词。它查看文件中的字符，如果一个字符串匹配搜索（不管它们之前或之后是什么），那么该行就会被打印出来。

在第一个例子中，`in`匹配了正常的单词**in**，但也匹配了 test**in**g。在第二个例子中，两行都有两个匹配项，**the**和**the**y。

如果你只想返回整个单词，请确保在`grep`搜索模式中包含空格：

```
reader@ubuntu:~/scripts/chapter_10$ grep ' in ' grep-file.txt 
Did you ever realise that in the UK they say colour,
but in the USA they use color (and realize)!
reader@ubuntu:~/scripts/chapter_10$ grep ' the ' grep-file.txt 
Did you ever realise that in the UK they say colour,
but in the USA they use color (and realize)!
```

正如你所看到的，现在对' in '的搜索并没有返回包含单词**testing**的行，因为字符**in**没有被空格包围。

正则表达式只是一个特定搜索模式的定义，它在个别脚本/编程语言中的实现方式是不同的。我们在 Bash 中使用的正则表达式与 Perl 或 Java 中使用的不同。在一些语言中，贪婪性可以被调整甚至关闭，但是`grep`和`sed`下的正则表达式总是贪婪的。这并不是一个问题，只是在定义搜索模式时需要考虑的事情。

# 字符匹配

我们现在知道了如何搜索整个单词，即使我们对大写和小写不是很确定。

我们还看到，（大多数）Linux 应用程序下的正则表达式是贪婪的，因此我们需要确保通过指定空格和字符锚点来正确处理这一点，我们将很快解释。

在这两种情况下，我们知道我们在寻找什么。但是如果我们真的不知道我们在寻找什么，或者可能只知道一部分呢？这个困境的答案是字符匹配。

在正则表达式中，有两个字符可以用作其他字符的替代品：

+   `.`（点）匹配任何一个字符（除了换行符）

+   `*`（星号）匹配前面字符的任意重复次数（甚至零次）

一个例子将有助于理解这一点：

```
reader@ubuntu:~/scripts/chapter_10$ vim character-class.txt 
reader@ubuntu:~/scripts/chapter_10$ cat character-class.txt 
eee
e2e
e e
aaa
a2a
a a
aabb
reader@ubuntu:~/scripts/chapter_10$ grep 'e.e' character-class.txt 
eee
e2e
e e
reader@ubuntu:~/scripts/chapter_10$ grep 'aaa*' character-class.txt 
aaa
aabb
reader@ubuntu:~/scripts/chapter_10$ grep 'aab*' character-class.txt 
aaa
aabb
```

在那里发生了很多事情，其中一些可能会感觉非常违反直觉。我们将逐一讨论它们，并详细说明发生了什么：

```
reader@ubuntu:~/scripts/chapter_10$ grep 'e.e' character-class.txt 
eee
e2e
e e
```

在这个例子中，我们使用点来替代*任何字符*。正如我们所看到的，这包括字母（e**e**e）和数字（e**2**e）。但是，它也匹配了最后一行上两个 e 之间的空格字符。

这里是另一个例子：

```
reader@ubuntu:~/scripts/chapter_10$ grep 'aaa*' character-class.txt 
aaa
aabb
```

当我们使用`*`替代时，我们正在寻找**零个或多个**前面的字符。在搜索模式`aaa*`中，这意味着以下字符串是有效的：

+   `aa`

+   `aaa`

+   `aaaa`

+   `aaaaa`

...等等。在第一个结果之后的一切都应该是清楚的，为什么`aa`也匹配`aaa*`呢？因为*零或更多*中的零！在这种情况下，如果最后的`a`是零，我们只剩下`aa`。

在最后一个例子中发生了同样的事情：

```
reader@ubuntu:~/scripts/chapter_10$ grep 'aab*' character-class.txt 
aaa
aabb
```

模式`aab*`匹配**aa**a 中的 aa，因为`b*`可以是零，这使得模式最终变成`aa`。当然，它也匹配一个或多个 b（`aabb`完全匹配）。

当你对你要找的东西只有一个大概的想法时，这些通配符就非常有用。然而，有时你会对你需要的东西有更具体的想法。

在这种情况下，我们可以使用括号[...]来缩小我们的替换范围到某个字符集。以下示例应该让你对如何使用这个有一个很好的想法：

```
reader@ubuntu:~/scripts/chapter_10$ grep 'f.r' grep-file.txt 
We can use this regular file for testing grep.
Also, New Zealand is pretty far away.
reader@ubuntu:~/scripts/chapter_10$ grep 'f[ao]r' grep-file.txt 
We can use this regular file for testing grep.
Also, New Zealand is pretty far away.
reader@ubuntu:~/scripts/chapter_10$ grep 'f[abcdefghijklmnopqrstuvwxyz]r' grep-file.txt 
We can use this regular file for testing grep.
Also, New Zealand is pretty far away.
reader@ubuntu:~/scripts/chapter_10$ grep 'f[az]r' grep-file.txt 
Also, New Zealand is pretty far away.
reader@ubuntu:~/scripts/chapter_10$ grep 'f[a-z]r' grep-file.txt 
We can use this regular file for testing grep.
Also, New Zealand is pretty far away.
reader@ubuntu:~/scripts/chapter_10$ grep 'f[a-k]r' grep-file.txt 
Also, New Zealand is pretty far away.
reader@ubuntu:~/scripts/chapter_10$ grep 'f[k-q]r' grep-file.txt 
We can use this regular file for testing grep
```

首先，我们演示使用`.`（点）来替换任何字符。在这种情况下，模式**f.r**匹配**for**和**far**。

接下来，我们在`f[ao]r`中使用括号表示法，以表明我们将接受一个在`f`和`r`之间的单个字符，它在`ao`的字符集中。不出所料，这又返回了**far**和**for**。

如果我们用`f[az]r`模式来做这个，我们只能匹配**far**和**fzr**。由于字符串`fzr`不在我们的文本文件中（显然也不是一个单词），我们只看到打印出**far**的那一行。

接下来，假设你想匹配一个字母，但不是一个数字。如果你使用`.`（点）进行搜索，就像第一个例子中那样，这将返回字母和数字。因此，你也会得到，例如，**f2r**作为匹配（如果它在文件中的话，实际上并不是）。

如果你使用括号表示法，你可以使用以下表示法：`f[abcdefghijklmnopqrstuvwxyz]r`。这匹配`f`和`r`之间的任何字母 a-z。然而，在键盘上输入这个并不好（相信我）。

幸运的是，POSIX 正则表达式的创建者引入了一个简写：`[a-z]`，就像前面的例子中所示的那样。我们也可以使用字母表的一个子集，如：`f[a-k]r`。由于字母**o**不在 a 和 k 之间，它不匹配**for**。

最后，一个例子证明了这是一个强大而实用的模式：

```
reader@ubuntu:~/scripts/chapter_10$ grep reali[sz]e grep-file.txt 
Did you ever realise that in the UK they say colour,
but in the USA they use color (and realize)!
```

希望这一切仍然是有意义的。在转向行锚之前，我们将进一步结合表示法。

在前面的例子中，你看到我们可以使用括号表示法来处理美式英语和英式英语之间的一些差异。然而，这只有在拼写的差异是一个字母时才有效，比如 realise/realize。

在颜色/colour 的情况下，有一个额外的字母我们需要处理。这听起来像是一个零或更多的情况，不是吗？

```
reader@ubuntu:~/scripts/chapter_10$ grep 'colo[u]*r' grep-file.txt 
Did you ever realise that in the UK they say colour,
but in the USA they use color (and realize)!
```

通过使用模式`colo[u]*r`，我们搜索包含以**colo**开头的单词的行，可能包含任意数量的**u**，并以**r**结尾。由于`color`和`colour`都适用于这个模式，两行都被打印出来。

你可能会想要使用点字符和零或更多的`*`表示法。然而，仔细看看在这种情况下会发生什么：

```
reader@ubuntu:~/scripts/chapter_10$ grep 'colo.*r' grep-file.txt 
Did you ever realise that in the UK they say colour,
but in the USA they use color (and realize)!
```

再次，两行都匹配。但是，由于第二行中包含另一个**r**，所以字符串`color (and r`被匹配，以及`colour`和`color`。

这是一个典型的例子，正则表达式模式对我们的目的来说太贪婪了。虽然我们不能告诉它变得不那么贪婪，但`grep`中有一个选项，让我们只寻找匹配的单词。

表示法`-w`评估空格和行尾/行首，以便只找到完整的单词。用法如下：

```
reader@ubuntu:~/scripts/chapter_10$ grep -w 'colo.*r' grep-file.txt 
Did you ever realise that in the UK they say colour,
but in the USA they use color (and realize)!
```

现在，只有单词`colour`和`color`被匹配。之前，我们在单词周围放置了空格以促进这种行为，但由于单词`colour`在行尾，它后面没有空格。

自己尝试一下，看看为什么用`colo.*r`搜索模式括起来不起作用，但使用`-w`选项却起作用。

一些正则表达式的实现有`{3}`表示法，用来补充`*`表示法。在这种表示法中，你可以精确指定模式应该出现多少次。搜索模式`[a-z]{3}`将匹配所有恰好三个字符的小写字符串。在 Linux 中，这只能用扩展的正则表达式来实现，我们将在本章后面看到。

# 行锚

我们已经简要提到了行锚。根据我们目前为止提出的解释，我们只能在一行中搜索单词；我们还不能设置对单词在行中的位置的期望。为此，我们使用行锚。

在正则表达式中，`^`（插入符）字符表示行的开头，`$`（美元）表示行的结尾。我们可以在搜索模式中使用这些，例如，在以下情况下：

+   查找单词 error，但只在行的开头：`^error`

+   查找以句点结尾的行：`\.$`

+   查找空行：`^$`

第一个用法，查找行的开头，应该是很清楚的。下面的例子使用了`grep -i`（记住，这允许我们不区分大小写地搜索），展示了我们如何使用这个来按行位置进行过滤：

```
reader@ubuntu:~/scripts/chapter_10$ grep -i 'regular' grep-file.txt 
We can use this regular file for testing grep.
Regular expressions are pretty cool
reader@ubuntu:~/scripts/chapter_10$ grep -i '^regular' grep-file.txt 
Regular expressions are pretty cool
```

在第一个搜索模式`regular`中，我们返回了两行。这并不意外，因为这两行都包含单词*regular*（尽管大小写不同）。

现在，为了只选择以单词*Regular*开头的行，我们使用插入符字符`^`来形成模式`^regular`。这只返回单词在该行的第一个位置的行。（请注意，如果我们没有选择在`grep`上包括`-i`，我们可以使用`[Rr]egular`代替。）

下一个例子，我们查找以句点结尾的行，会有点棘手。你会记得，在正则表达式中，句点被认为是一个特殊字符；它是任何其他一个字符的替代。如果我们正常使用它，我们会看到文件中的所有行都返回（因为所有行都以*任何一个字符*结尾）。

要实际搜索文本中的句点，我们需要**转义**句点，即用反斜杠前缀它；这告诉正则表达式引擎不要将句点解释为特殊字符，而是搜索它：

```
reader@ubuntu:~/scripts/chapter_10$ grep '.$' grep-file.txt 
We can use this regular file for testing grep.
Regular expressions are pretty cool
Did you ever realise that in the UK they say colour,
but in the USA they use color (and realize)!
Also, New Zealand is pretty far away.
reader@ubuntu:~/scripts/chapter_10$ grep '\.$' grep-file.txt 
We can use this regular file for testing grep.
Also, New Zealand is pretty far away.
```

由于`\`用于转义特殊字符，你可能会遇到在文本中寻找反斜杠的情况。在这种情况下，你可以使用反斜杠来转义反斜杠的特殊功能！在这种情况下，你的模式将是`\\`，它与`\`字符串匹配。

在这个例子中，我们遇到了另一个问题。到目前为止，我们总是用单引号引用所有模式。然而，并不总是需要这样！例如，`grep cool grep-file.txt` 和 `grep 'cool' grep-file.txt` 一样有效。

那么，我们为什么要这样做呢？提示：尝试前面的例子，使用点行结束，不用引号。然后记住，在 Bash 中，美元符号也用于表示变量。如果我们引用它，Bash 将不会扩展`$`，这将返回问题结果。

我们将在第十六章中讨论 Bash 扩展，*Bash 参数替换和扩展*。

最后，我们介绍了`^$`模式。这搜索一个行的开头，紧接着一个行的结尾。只有一种情况会发生这种情况：一个空行。

为了说明为什么你想要找到空行，让我们看一个新的`grep`标志：`-v`。这个标志是`--invert-match`的缩写，这应该给出一个关于它实际上做什么的好提示：它打印不匹配的行，而不是匹配的行。

通过使用`grep -v '^$' <文件名>`，你可以打印一个没有空行的文件。在一个随机的配置文件上试一试：

```
reader@ubuntu:/etc$ cat /etc/ssh/ssh_config 

# This is the ssh client system-wide configuration file.  See
# ssh_config(5) for more information.  This file provides defaults for
# users, and the values can be changed in per-user configuration files
# or on the command line.

# Configuration data is parsed as follows:
<SNIPPED>
reader@ubuntu:/etc$ grep -v '^$' /etc/ssh/ssh_config 
# This is the ssh client system-wide configuration file.  See
# ssh_config(5) for more information.  This file provides defaults for
# users, and the values can be changed in per-user configuration files
# or on the command line.
# Configuration data is parsed as follows:
<SNIPPED>
```

正如你所看到的，`/etc/ssh/ssh_config` 文件以一个空行开头。然后，在注释块之间，还有另一行空行。通过使用 `grep -v '^$'`，这些空行被移除了。虽然这是一个不错的练习，但这并没有真正为我们节省多少行。

然而，有一个搜索模式是广泛使用且非常强大的：过滤配置文件中的注释。这个操作可以快速概述实际配置了什么，并省略所有注释（尽管注释本身也有其价值，但在你只想看到配置选项时可能会妨碍）。

为了做到这一点，我们将行首的插入符号与井号结合起来，表示注释：

```
reader@ubuntu:/etc$ grep -v '^#' /etc/ssh/ssh_config 

Host *
    SendEnv LANG LC_*
    HashKnownHosts yes
    GSSAPIAuthentication yes
```

这仍然打印所有空行，但不再打印注释。在这个特定的文件中，共有 51 行，只有四行包含实际的配置指令！所有其他行要么是空的，要么包含注释。很酷，对吧？

使用 `grep`，也可以同时使用多个模式。通过使用这种方法，可以结合过滤空行和注释行，快速概述配置选项。使用 `-e` 选项定义多个模式。在这种情况下，完整的命令是 `grep -v -e '^$' -e '^#' /etc/ssh/ssh_config`。试试看！

# 字符类

我们现在已经看到了许多如何使用正则表达式的示例。虽然大多数事情都很直观，但我们也看到，如果我们想要过滤大写和小写字符串，我们要么必须为 `grep` 指定 `-i` 选项，要么将搜索模式从 `[a-z]` 更改为 `[a-zA-z]`。对于数字，我们需要使用 `[0-9]`。

有些人可能觉得这样工作很好，但其他人可能不同意。在这种情况下，可以使用另一种可用的表示法：`[[:pattern:]]`。

下一个例子同时使用了这种新的双括号表示法和旧的单括号表示法：

```
reader@ubuntu:~/scripts/chapter_10$ grep [[:digit:]] character-class.txt 
e2e
a2a
reader@ubuntu:~/scripts/chapter_10$ grep [0-9] character-class.txt 
e2e
a2a
```

正如你所看到的，这两种模式都导致相同的行：包含数字的行。同样的方法也适用于大写字符：

```
reader@ubuntu:~/scripts/chapter_10$ grep [[:upper:]] grep-file.txt 
We can use this regular file for testing grep.
Regular expressions are pretty cool
Did you ever realise that in the UK they say colour,
but in the USA they use color (and realize)!
Also, New Zealand is pretty far away.
reader@ubuntu:~/scripts/chapter_10$ grep [A-Z] grep-file.txt 
We can use this regular file for testing grep.
Regular expressions are pretty cool
Did you ever realise that in the UK they say colour,
but in the USA they use color (and realize)!
Also, New Zealand is pretty far away.
```

最终，使用哪种表示法是个人偏好的问题。不过，双括号表示法有一点值得一提：它更接近其他脚本/编程语言的实现。例如，大多数正则表达式实现使用 `\w`（单词）来选择字母，使用 `\d`（数字）来搜索数字。在 `\w` 的情况下，大写变体直观地是 `\W`。

为了方便起见，这里是一个包含最常见的 POSIX 双括号字符类的表格：

| **表示法** | **描述** | **单括号等效** |
| --- | --- | --- |
| `[[:alnum:]]` | 匹配小写字母、大写字母或数字 | [a-z A-Z 0-9] |
| `[[:alpha:]]` | 匹配小写字母和大写字母 | [a-z A-Z] |
| `[[:digit:]]` | 匹配数字 | [0-9] |
| `[[:lower:]]` | 匹配小写字母 | [a-z] |
| `[[:upper:]]` | 匹配大写字母 | [A-Z] |
| `[[:blank:]]` | 匹配空格和制表符 | [ \t] |

我们更喜欢使用双括号表示法，因为它更好地映射到其他正则表达式实现。在脚本中可以自由选择使用任何一种！但是，一如既往：确保你选择一种，并坚持使用它；不遵循标准会导致令人困惑的杂乱脚本。本书中的其余示例将使用双括号表示法。

# 通配符

我们现在已经掌握了正则表达式的基础知识。在 Linux 上，还有一个与正则表达式密切相关的主题：*通配符*。即使你可能没有意识到，你在本书中已经看到了通配符的示例。

更好的是，实际上你已经有很大的机会在实践中使用了*通配符模式*。如果在命令行上工作时，你曾经使用通配符字符 `*`，那么你已经在使用通配符！

# 什么是通配符？

简单地说，glob 模式描述了将通配符字符注入文件路径操作。所以，当你执行`cp * /tmp/`时，你将当前工作目录中的所有文件（不包括目录！）复制到`/tmp/`目录中。

`*`扩展到工作目录中的所有常规文件，然后所有这些文件都被复制到`/tmp/`中。

这是一个简单的例子：

```
reader@ubuntu:~/scripts/chapter_10$ ls -l
total 8
-rw-rw-r-- 1 reader reader  29 Oct 14 10:29 character-class.txt
-rw-rw-r-- 1 reader reader 219 Oct  8 19:22 grep-file.txt
reader@ubuntu:~/scripts/chapter_10$ cp * /tmp/
reader@ubuntu:~/scripts/chapter_10$ ls -l /tmp/
total 20
-rw-rw-r-- 1 reader reader   29 Oct 14 16:35 character-class.txt
-rw-rw-r-- 1 reader reader  219 Oct 14 16:35 grep-file.txt
<SNIPPED>
```

我们使用`*`来选择它们两个。相同的 glob 模式也可以用于`rm`：

```
reader@ubuntu:/tmp$ ls -l
total 16
-rw-rw-r-- 1 reader reader   29 Oct 14 16:37 character-class.txt
-rw-rw-r-- 1 reader reader  219 Oct 14 16:37 grep-file.txt
drwx------ 3 root root 4096 Oct 14 09:22 systemd-private-c34c8acb350...
drwx------ 3 root root 4096 Oct 14 09:22 systemd-private-c34c8acb350...
reader@ubuntu:/tmp$ rm *
rm: cannot remove 'systemd-private-c34c8acb350...': Is a directory
rm: cannot remove 'systemd-private-c34c8acb350...': Is a directory
reader@ubuntu:/tmp$ ls -l
total 8
drwx------ 3 root root 4096 Oct 14 09:22 systemd-private-c34c8acb350...
drwx------ 3 root root 4096 Oct 14 09:22 systemd-private-c34c8acb350...
```

默认情况下，`rm`只会删除文件而不是目录（正如你从前面的例子中的错误中看到的）。正如第六章所述，*文件操作*，添加`-r`将递归地删除目录。

再次，请考虑这样做的破坏性：没有警告，你可能会删除当前树位置内的每个文件（当然，如果你有权限的话）。前面的例子展示了`*` glob 模式有多么强大：它会扩展到它能找到的每个文件，无论类型如何。

# 与正则表达式的相似之处

正如所述，glob 命令实现了与正则表达式类似的效果。不过也有一些区别。例如，正则表达式中的`*`字符代表*前一个字符的零次或多次出现*。对于 globbing 来说，它是一个通配符，代表任何字符，更类似于正则表达式的`.*`表示。

与正则表达式一样，glob 模式可以由普通字符和特殊字符组合而成。看一个例子，其中`ls`与不同的参数/ globbing 模式一起使用：

```
reader@ubuntu:~/scripts/chapter_09$ ls -l
total 68
-rw-rw-r-- 1 reader reader  682 Oct  2 18:31 empty-file.sh
-rw-rw-r-- 1 reader reader 1183 Oct  1 19:06 file-create.sh
-rw-rw-r-- 1 reader reader  467 Sep 29 19:43 functional-check.sh
<SNIPPED>
reader@ubuntu:~/scripts/chapter_09$ ls -l *
-rw-rw-r-- 1 reader reader  682 Oct  2 18:31 empty-file.sh
-rw-rw-r-- 1 reader reader 1183 Oct  1 19:06 file-create.sh
-rw-rw-r-- 1 reader reader  467 Sep 29 19:43 functional-check.sh
<SNIPPED>
reader@ubuntu:~/scripts/chapter_09$ ls -l if-then-exit.sh 
-rw-rw-r-- 1 reader reader 416 Sep 30 18:51 if-then-exit.sh
reader@ubuntu:~/scripts/chapter_09$ ls -l if-*.sh
-rw-rw-r-- 1 reader reader 448 Sep 30 20:10 if-then-else-proper.sh
-rw-rw-r-- 1 reader reader 422 Sep 30 19:56 if-then-else.sh
-rw-rw-r-- 1 reader reader 535 Sep 30 19:44 if-then-exit-rc-improved.sh
-rw-rw-r-- 1 reader reader 556 Sep 30 19:18 if-then-exit-rc.sh
-rw-rw-r-- 1 reader reader 416 Sep 30 18:51 if-then-exit.sh
```

在上一章的`scripts`目录中，我们首先运行了一个普通的`ls -l`。如你所知，这会打印出目录中的所有文件。现在，如果我们使用`ls -l *`，我们会得到完全相同的结果。看起来，鉴于缺少参数，`ls`会为我们注入一个通配符 glob。

接下来，我们使用`ls`的替代模式，其中我们将文件名作为参数。在这种情况下，因为每个目录的文件名是唯一的，我们只会看到返回的单行。

但是，如果我们想要所有以`if-`开头的*scripts*（以`.sh`结尾）呢？我们使用`if-*.sh`的 globbing 模式。在这个模式中，`*`通配符被扩展为匹配，正如`man glob`所说，*任何字符串，包括空字符串*。

# 更多的 globbing

在 Linux 中，globbing 非常常见。如果你正在处理一个处理文件的命令（根据*一切皆为文件*原则，大多数命令都是如此），那么你很有可能可以使用 globbing。为了让你对此有所了解，考虑以下例子：

```
reader@ubuntu:~/scripts/chapter_10$ cat *
eee
e2e
e e
aaa
a2a
a a
aabb
We can use this regular file for testing grep.
Regular expressions are pretty cool
Did you ever realise that in the UK they say colour,
but in the USA they use color (and realize)!
Also, New Zealand is pretty far away.
```

`cat`命令与通配符 glob 模式结合使用，打印出当前工作目录中**所有文件**的内容。在这种情况下，由于所有文件都是 ASCII 文本，这并不是真正的问题。正如你所看到的，文件都是紧挨在一起打印出来的；它们之间甚至没有空行。

如果你`cat`一个二进制文件，你的屏幕会看起来像这样：

```
reader@ubuntu:~/scripts/chapter_10$ cat /bin/chvt 
@H!@8    @@@�888�� �� �  H 88 8 �TTTDDP�td\\\llQ�tdR�td�� � /lib64/ld-linux-x86-64.so.2GNUGNU��H������)�!�@`��a*�K��9���X' Q��/9'~���C J
```

最糟糕的情况是二进制文件包含某个字符序列，这会对你的 Bash shell 进行临时更改，使其无法使用（是的，这种情况我们遇到过很多次）。这里的教训应该很简单：**在使用 glob 时要小心！**

到目前为止，我们看到的其他命令可以处理 globbing 模式的命令包括`chmod`、`chown`、`mv`、`tar`、`grep`等等。现在可能最有趣的是`grep`。我们已经在单个文件上使用了正则表达式与`grep`，但我们也可以使用 glob 来选择文件。

让我们来看一个最荒谬的`grep`与 globbing 的例子：在*everything*中找到*anything*。

```
reader@ubuntu:~/scripts/chapter_10$ grep .* *
grep: ..: Is a directory
character-class.txt:eee
character-class.txt:e2e
character-class.txt:e e
character-class.txt:aaa
character-class.txt:a2a
character-class.txt:a a
character-class.txt:aabb
grep-file.txt:We can use this regular file for testing grep.
grep-file.txt:Regular expressions are pretty cool
grep-file.txt:Did you ever realise that in the UK they say colour,
grep-file.txt:but in the USA they use color (and realize)!
grep-file.txt:Also, New Zealand is pretty far away.
```

在这里，我们使用了正则表达式`.*`的搜索模式（任何东西，零次或多次）与`*`的 glob 模式（任何文件）。正如你所期望的那样，这应该匹配每个文件的每一行。

当我们以这种方式使用`grep`时，它的功能基本上与之前的`cat *`相同。但是，当`grep`用于多个文件时，输出会包括文件名（这样您就知道找到该行的位置）。

请注意：globbing 模式总是与文件相关，而正则表达式是用于*文件内部*，用于实际内容。由于语法相似，您可能不会对此感到太困惑，但如果您曾经遇到过模式不按您的预期工作的情况，那么花点时间考虑一下您是在进行 globbing 还是正则表达式会很有帮助！

# 高级 globbing

基本的 globbing 主要是使用通配符，有时与部分文件名结合使用。然而，正如正则表达式允许我们替换单个字符一样，glob 也可以。

正则表达式通过点来实现这一点；在 globbing 模式中，问号被使用：

```
reader@ubuntu:~/scripts/chapter_09$ ls -l if-then-*
-rw-rw-r-- 1 reader reader 448 Sep 30 20:10 if-then-else-proper.sh
-rw-rw-r-- 1 reader reader 422 Sep 30 19:56 if-then-else.sh
-rw-rw-r-- 1 reader reader 535 Sep 30 19:44 if-then-exit-rc-improved.sh
-rw-rw-r-- 1 reader reader 556 Sep 30 19:18 if-then-exit-rc.sh
-rw-rw-r-- 1 reader reader 416 Sep 30 18:51 if-then-exit.sh
reader@ubuntu:~/scripts/chapter_09$ ls -l if-then-e???.sh
-rw-rw-r-- 1 reader reader 422 Sep 30 19:56 if-then-else.sh
-rw-rw-r-- 1 reader reader 416 Sep 30 18:51 if-then-exit.sh
```

现在，globbing 模式`if-then-e???.sh`应该不言自明了。在`?`出现的地方，任何字符（字母、数字、特殊字符）都是有效的替代。

在前面的例子中，所有三个问号都被字母替换。正如您可能已经推断出的那样，正则表达式`.`字符与 globbing 模式`?`字符具有相同的功能：它有效地代表一个字符。

最后，我们用于正则表达式的单括号表示法也可以用于 globbing。一个快速的例子展示了我们如何在`cat`中使用它：

```
reader@ubuntu:/tmp$ echo ping > ping # Write the word ping to the file ping.
reader@ubuntu:/tmp$ echo pong > pong # Write the word pong to the file pong.
reader@ubuntu:/tmp$ ls -l
total 16
-rw-rw-r-- 1 reader reader    5 Oct 14 17:17 ping
-rw-rw-r-- 1 reader reader    5 Oct 14 17:17 pong
reader@ubuntu:/tmp$ cat p[io]ng
ping
pong
reader@ubuntu:/tmp$ cat p[a-z]ng
ping
pong
```

# 禁用 globbing 和其他选项

尽管 globbing 功能强大，但这也是它危险的原因。因此，您可能希望采取激烈措施并关闭 globbing。虽然这是可能的，但我们并没有在实践中看到过。但是，对于一些工作或脚本，关闭 globbing 可能是一个很好的保障。

使用`set`命令，我们可以像 man 页面所述那样*更改 shell 选项的值*。在这种情况下，使用`-f`将关闭 globbing，正如我们在尝试重复之前的例子时所看到的：

```
reader@ubuntu:/tmp$ cat p?ng
ping
pong
reader@ubuntu:/tmp$ set -f
reader@ubuntu:/tmp$ cat p?ng
cat: 'p?ng': No such file or directory
reader@ubuntu:/tmp$ set +f
reader@ubuntu:/tmp$ cat p?ng
ping
pong
```

通过在前缀加上减号（`-`）来关闭选项，通过在前缀加上加号（`+`）来打开选项。您可能还记得，这不是您第一次使用这个功能。当我们调试 Bash 脚本时，我们开始的不是`bash`，而是`bash -x`。

在这种情况下，Bash 子 shell 在调用脚本之前执行了`set -x`命令。如果您在当前终端中使用`set -x`，您的命令将开始看起来像这样：

```
reader@ubuntu:/tmp$ cat p?ng
ping
pong
reader@ubuntu:/tmp$ set -x
reader@ubuntu:/tmp$ cat p?ng
+ cat ping pong
ping
pong
reader@ubuntu:/tmp$ set +x
+ set +x
reader@ubuntu:/tmp$ cat p?ng
ping
pong
```

请注意，我们现在可以看到 globbing 模式是如何解析的：从`cat p?ng`到`cat ping pong`。尽量记住这个功能；如果您曾经因为不知道脚本为什么不按照您的意愿执行而抓狂，一个简单的`set -x`可能会产生很大的不同！如果不行，您总是可以通过`set +x`恢复正常行为，就像例子中所示的那样。

`set`有许多有趣的标志，可以让您的生活更轻松。要查看您的 Bash 版本中`set`的功能概述，请使用`help set`命令。因为`set`是一个 shell 内置命令（您可以用`type set`来验证），所以不幸的是，查找`man set`的 man 页面是行不通的。

# 使用 egrep 和 sed 的正则表达式

我们现在已经讨论了正则表达式和 globbing。正如我们所看到的，它们非常相似，但仍然有一些需要注意的区别。在我们的正则表达式示例中，以及一些 globbing 示例中，我们已经看到了`grep`的用法。

在这部分中，我们将介绍另一个命令，它与正则表达式结合使用时非常方便：`sed`（不要与`set`混淆）。我们将从一些用于`grep`的高级用法开始。

# 高级 grep

我们已经讨论了一些用于更改`grep`默认行为的流行选项：`--ignore-case`（`-i`）、`--invert-match`（`-v`）和`--word-regexp`（`-w`）。作为提醒，这是它们的作用：

+   `-i`允许我们进行不区分大小写的搜索

+   `-v`只打印*不*匹配的行，而不是匹配的行

+   `-w`只匹配由空格和/或行锚和/或标点符号包围的完整单词

还有三个其他选项我们想和你分享。第一个新选项，`--only-matching`（`-o`）只打印匹配的单词。如果你的搜索模式不包含任何正则表达式，这可能是一个相当无聊的选项，就像在这个例子中所看到的：

```
reader@ubuntu:~/scripts/chapter_10$ grep -o 'cool' grep-file.txt 
cool
```

它确实如你所期望的那样：它打印了你要找的单词。然而，除非你只是想确认这一点，否则可能并不那么有趣。

现在，如果我们在使用一个更有趣的搜索模式（包含正则表达式）时做同样的事情，这个选项就更有意义了：

```
reader@ubuntu:~/scripts/chapter_10$ grep -o 'f.r' grep-file.txt 
for
far
```

在这个（简化的！）例子中，你实际上得到了新的信息：你搜索模式中的任何单词都会被打印出来。虽然对于这样一个短的单词在这样一个小的文件中来说可能并不那么令人印象深刻，但想象一下在一个更大的文件中使用一个更复杂的搜索模式！

这带来了另一个问题：`grep`非常*快*。由于 Boyer-Moore 算法，`grep`可以在非常大的文件（100 MB+）中进行非常快速的搜索。

第二个额外选项，`--count`（`-c`），不返回任何行。但是，它会返回一个数字：搜索模式匹配的行数。一个众所周知的例子是查看包安装的日志文件时：

```
reader@ubuntu:/var/log$ grep 'status installed' dpkg.log
2018-04-26 19:07:29 status installed base-passwd:amd64 3.5.44
2018-04-26 19:07:29 status installed base-files:amd64 10.1ubuntu2
2018-04-26 19:07:30 status installed dpkg:amd64 1.19.0.5ubuntu2
<SNIPPED>
2018-06-30 17:59:37 status installed linux-headers-4.15.0-23:all 4.15.0-23.25
2018-06-30 17:59:37 status installed iucode-tool:amd64 2.3.1-1
2018-06-30 17:59:37 status installed man-db:amd64 2.8.3-2
<SNIPPED>
2018-07-01 09:31:15 status installed distro-info-data:all 0.37ubuntu0.1
2018-07-01 09:31:17 status installed libcurl3-gnutls:amd64 7.58.0-2ubuntu3.1
2018-07-01 09:31:17 status installed libc-bin:amd64 2.27-3ubuntu1
```

在这个常规的`grep`中，我们看到显示了哪个包在哪个日期安装的日志行。但是，如果我们只想知道*某个日期安装了多少个包*呢？`--count`来帮忙！

```
reader@ubuntu:/var/log$ grep 'status installed' dpkg.log | grep '2018-08-26'
2018-08-26 11:16:16 status installed base-files:amd64 10.1ubuntu2.2
2018-08-26 11:16:16 status installed install-info:amd64 6.5.0.dfsg.1-2
2018-08-26 11:16:16 status installed plymouth-theme-ubuntu-text:amd64 0.9.3-1ubuntu7
<SNIPPED>
reader@ubuntu:/var/log$ grep 'status installed' dpkg.log | grep -c '2018-08-26'
40
```

我们将这个`grep`操作分为两个阶段。第一个`grep 'status installed'`过滤掉所有与成功安装相关的行，跳过中间步骤，比如*unpacked*和*half-configured*。

我们在管道后面使用`grep`的替代形式（我们将在第十二章中进一步讨论，*在脚本中使用管道和重定向*）来匹配另一个搜索模式到已经过滤的数据。第二个`grep '2018-08-26'`用于按日期过滤。

现在，如果没有`-c`选项，我们会看到 40 行。如果我们对包感兴趣，这可能是一个不错的选择，但否则，只打印数字比手动计算行数要好。

或者，我们可以将其写成一个单独的 grep 搜索模式，使用正则表达式。自己试一试：`grep '2018-08-26 .* status installed' dpkg.log`（确保用你运行更新/安装的某一天替换日期）。

最后一个选项非常有趣，特别是对于脚本编写，就是`--quiet`（`-q`）选项。想象一种情况，你想知道文件中是否存在某个搜索模式。如果找到了搜索模式，就删除文件。如果没有找到搜索模式，就将其添加到文件中。

你知道，你可以使用一个很好的`if-then-else`结构来完成这个任务。但是，如果你使用普通的`grep`，当你运行脚本时，你会在终端上看到文本被打印出来。

这并不是一个很大的问题，但是一旦你的脚本变得足够大和复杂，大量的输出到屏幕会使脚本难以使用。为此，我们有`--quiet`选项。看看这个示例脚本，看看你会如何做到这一点：

```
reader@ubuntu:~/scripts/chapter_10$ vim grep-then-else.sh 
reader@ubuntu:~/scripts/chapter_10$ cat grep-then-else.sh 
#!/bin/bash

#####################################
# Author: Sebastiaan Tammer
# Version: v1.0.0
# Date: 2018-10-16
# Description: Use grep exit status to make decisions about file manipulation.
# Usage: ./grep-then-else.sh
#####################################

FILE_NAME=/tmp/grep-then-else.txt

# Touch the file; creates it if it does not exist.
touch ${FILE_NAME}

# Check the file for the keyword.
grep -q 'keyword' ${FILE_NAME}
grep_rc=$?

# If the file contains the keyword, remove the file. Otherwise, write 
# the keyword to the file.
if [[ ${grep_rc} -eq 0 ]]; then
  rm ${FILE_NAME}  
else
  echo 'keyword' >> ${FILE_NAME}
fi

reader@ubuntu:~/scripts/chapter_10$ bash -x grep-then-else.sh 
+ FILE_NAME=/tmp/grep-then-else.txt
+ touch /tmp/grep-then-else.txt
+ grep --quiet keyword /tmp/grep-then-else.txt
+ grep_rc='1'
+ [[ '1' -eq 0 ]]
+ echo keyword
reader@ubuntu:~/scripts/chapter_10$ bash -x grep-then-else.sh 
+ FILE_NAME=/tmp/grep-then-else.txt
+ touch /tmp/grep-then-else.txt
+ grep -q keyword /tmp/grep-then-else.txt
+ grep_rc=0
+ [[ 0 -eq 0 ]]
+ rm /tmp/grep-then-else.txt
```

正如你所看到的，关键在于退出状态。如果`grep`找到一个或多个搜索模式的匹配，就会返回退出代码 0。如果`grep`没有找到任何内容，返回代码将是 1。

你可以在命令行上自己看到这一点：

```
reader@ubuntu:/var/log$ grep -q 'glgjegeg' dpkg.log
reader@ubuntu:/var/log$ echo $?
1
reader@ubuntu:/var/log$ grep -q 'installed' dpkg.log 
reader@ubuntu:/var/log$ echo $?
0
```

在`grep-then-else.sh`中，我们抑制了`grep`的所有输出。但是，我们仍然可以实现我们想要的效果：脚本的每次运行在*then*和*else*条件之间变化，正如我们的`bash -x`调试输出清楚地显示的那样。

没有`--quiet`，脚本的非调试输出将如下所示：

```
reader@ubuntu:/tmp$ bash grep-then-else.sh 
reader@ubuntu:/tmp$ bash grep-then-else.sh 
keyword
reader@ubuntu:/tmp$ bash grep-then-else.sh 
reader@ubuntu:/tmp$ bash grep-then-else.sh 
keyword
```

它实际上并没有为脚本添加任何东西，是吗？更好的是，很多命令都有`--quiet`，`-q`或等效选项。

在编写脚本时，始终考虑命令的输出是否相关。如果不相关，并且可以使用退出状态，这几乎总是会使输出体验更清晰。

# 介绍`egrep`

到目前为止，我们已经看到`grep`与各种选项一起使用，这些选项改变了它的行为。有一个最后重要的选项我们想要和你分享：`--extended-regexp` (`-E`)。正如`man grep`页面所述，这意味着*将 PATTERN 解释为扩展正则表达式*。

与 Linux 中找到的默认正则表达式相比，扩展正则表达式具有更接近其他脚本/编程语言中的正则表达式的搜索模式（如果你已经有这方面的经验）。

具体来说，在使用扩展正则表达式而不是默认正则表达式时，以下构造是可用的：

| ? | 匹配前一个字符的重复*零次或多次* |
| --- | --- |
| + | 匹配前一个字符的重复*一次或多次* |
| {n} | 匹配前一个字符的重复*恰好 n 次* |
| {n,m} | 匹配前一个字符的重复*介于 n 和 m 次之间* |
| {,n} | 匹配前一个字符的重复*n 次或更少次* |
| {n,} | 匹配前一个字符的重复*n 次或更多次* |
| (xx&#124;yy) | 交替字符，允许我们在搜索模式中找到 xx *或* yy（对于具有多个字符的模式非常有用，否则，`[xy]`表示法就足够了） |

正如你可能已经看到的，`grep`的 man 页面包含了一个关于正则表达式和搜索模式的专门部分，你可能会发现它作为一个快速参考非常方便。

现在，在我们开始使用新的 ERE 搜索模式之前，我们将介绍一个*新*命令：`egrep`。如果你试图找出它的作用，你可能会从`which egrep`开始，结果是`/bin/egrep`。这可能会让你认为它是一个独立的二进制文件，而不是你现在已经使用了很多的`grep`。

然而，最终，`egrep`只不过是一个小小的包装脚本：

```
reader@ubuntu:~/scripts/chapter_10$ cat /bin/egrep
#!/bin/sh
exec grep -E "$@"
```

你可以看到，这只是一个 shell 脚本，但没有通常的`.sh`扩展名。它使用`exec`命令来*用新的进程映像替换当前进程映像*。

你可能还记得，通常情况下，命令是在当前环境的一个分支中执行的。在这种情况下，因为我们使用这个脚本来*包装*（这就是为什么它被称为包装脚本）`grep -E`作为`egrep`，所以替换它而不是再次分支是有意义的。

`"$@"`构造也是新的：它是一个*数组*（如果你对这个术语不熟悉，可以想象为一个有序列表）的参数。在这种情况下，它基本上将`egrep`接收到的所有参数传递到`grep -E`中。

因此，如果完整的命令是`egrep -w [[:digit:]] grep-file.txt`，它将被包装并最终作为`grep -E -w [[:digit:]] grep-file.txt`执行。

实际上，使用`egrep`或`grep -E`并不重要。我们更喜欢使用`egrep`，这样我们就可以确定我们正在处理扩展的正则表达式（因为在我们的经验中，扩展功能经常被使用）。但是，对于简单的搜索模式，不需要使用 ERE。

我们建议你找到自己的系统，决定何时使用每个命令。

现在我们来看一些扩展正则表达式搜索模式的例子：

```
reader@ubuntu:~/scripts/chapter_10$ egrep -w '[[:lower:]]{5}' grep-file.txt 
but in the USA they use color (and realize)!
reader@ubuntu:~/scripts/chapter_10$ egrep -w '[[:lower:]]{7}' grep-file.txt 
We can use this regular file for testing grep.
Did you ever realise that in the UK they say colour,
but in the USA they use color (and realize)!
reader@ubuntu:~/scripts/chapter_10$ egrep -w '[[:alpha:]]{7}' grep-file.txt 
We can use this regular file for testing grep.
Regular expressions are pretty cool
Did you ever realise that in the UK they say colour,
but in the USA they use color (and realize)!
Also, New Zealand is pretty far away.
```

第一个命令`egrep -w [[:lower:]]{5} grep-file.txt`，显示了所有恰好五个字符长的单词，使用小写字母。不要忘记这里需要`-w`选项，因为否则，任何五个字母连续在一起也会匹配，忽略单词边界（在这种情况下，**prett**y 中的**prett**也会匹配）。结果只有一个五个字母的单词：color。

接下来，我们对七个字母的单词做同样的操作。我们现在得到了更多的结果。然而，因为我们只使用小写字母，我们错过了两个也是七个字母长的单词：Regular 和 Zealand。我们通过使用`[[:alpha:]]`而不是`[[:lower:]]`来修复这个问题。（我们也可以使用`-i`选项使所有内容不区分大小写—`egrep -iw [[:lower:]]{7} grep-file.txt`。

虽然这在功能上是可以接受的，但请再考虑一下。在这种情况下，你将搜索由七个*小写*字母组成的*不区分大小写*单词。这实际上没有任何意义。在这种情况下，我们总是选择逻辑而不是功能，这意味着将`[[:lower:]]`改为`[[:alpha:]]`，而不是使用`-i`选项。

所以我们知道了如何搜索特定长度的单词（或行，如果省略了`-w`选项）。现在我们来搜索比最小长度或最大长度更长或更短的单词。

这里有一个例子：

```
reader@ubuntu:~/scripts/chapter_10$ egrep -w '[[:lower:]]{5,}' grep-file.txt
We can use this regular file for testing grep.
Regular expressions are pretty cool
Did you ever realise that in the UK they say colour,
but in the USA they use color (and realize)!
Also, New Zealand is pretty far away.
reader@ubuntu:~/scripts/chapter_10$ egrep -w '[[:alpha:]]{,3}' grep-file.txt
We can use this regular file for testing grep.
Regular expressions are pretty cool
Did you ever realise that in the UK they say colour,
but in the USA they use color (and realize)!
Also, New Zealand is pretty far away.
reader@ubuntu:~/scripts/chapter_10$ egrep '.{40,}' grep-file.txt
We can use this regular file for testing grep.
Did you ever realise that in the UK they say colour,
but in the USA they use color (and realize)!
```

这个例子演示了边界语法。第一个命令，`egrep -w '[[:lower:]]{5,}' grep-file.txt`，寻找了至少五个字母的小写单词。如果你将这些结果与之前寻找确切五个字母长的单词的例子进行比较，你现在会发现更长的单词也被匹配到了。

接下来，我们反转边界条件：我们只想匹配三个字母或更少的单词。我们看到所有两个和三个字母的单词都被匹配到了（因为我们从`[[:lower:]]`切换到了`[[:alpha:]]`，UK 和行首大写字母也被匹配到了）。

在最后一个例子中，`egrep '.{40,}' grep-file.txt`，我们去掉了`-w`，所以我们匹配整行。我们匹配任何字符（由点表示），并且我们希望一行至少有 40 个字符（由`{40,}`表示）。在这种情况下，只有五行中的三行被匹配到了（因为其他两行较短）。

引用对于搜索模式非常重要。如果你在模式中不使用引号，特别是在使用{和}等特殊字符时，你将需要用反斜杠对它们进行转义。这可能会导致令人困惑的情况，你会盯着屏幕想知道为什么你的搜索模式不起作用，甚至会报错。只要记住：如果你始终对搜索模式使用单引号，你就会更有可能避免这些令人沮丧的情况。

我们想要展示的扩展正则表达式的最后一个概念是*alternation*。这使用了管道语法（不要与用于重定向的管道混淆，这将在第十二章中进一步讨论，*在脚本中使用管道和重定向*）来传达*匹配 xxx 或 yyy*的含义。

一个例子应该能说明问题：

```
reader@ubuntu:~/scripts/chapter_10$ egrep 'f(a|o)r' grep-file.txt 
We can use this regular file for testing grep.
Also, New Zealand is pretty far away.
reader@ubuntu:~/scripts/chapter_10$ egrep 'f[ao]r' grep-file.txt
We can use this regular file for testing grep.
Also, New Zealand is pretty far away.
reader@ubuntu:~/scripts/chapter_10$ egrep '(USA|UK)' grep-file.txt 
Did you ever realise that in the UK they say colour,
but in the USA they use color (and realize)!
```

在只有一个字母差异的情况下，我们可以选择使用扩展的 alternation 语法，或者之前讨论过的括号语法。我们建议使用最简单的语法来实现目标，这种情况下就是括号语法。

然而，一旦我们要寻找超过一个字符差异的模式，使用括号语法就变得非常复杂。在这种情况下，扩展的 alternation 语法是清晰而简洁的，特别是因为`|`或`||`在大多数脚本/编程逻辑中代表`OR`构造。对于这个例子，这就像是说：我想要找到包含单词 USA 或单词 UK 的行。

因为这种语法与语义视图相对应得很好，它感觉直观且易懂，这是我们在脚本中应该始终努力的事情！

# 流编辑器 sed

由于我们现在对正则表达式、搜索模式和（扩展）`grep`非常熟悉，是时候转向 GNU/Linux 领域中最强大的工具之一了：`sed`。这个术语是**s**tream **ed**itor 的缩写，它确实做到了它所暗示的：编辑流。

在这种情况下，流可以是很多东西，但通常是文本。这个文本可以在文件中找到，但也可以从另一个进程中*流式传输*，比如`cat grep-file.txt | sed ...`。在这个例子中，`cat`命令的输出（等同于`grep-file.txt`的内容）作为`sed`命令的输入。

我们将在我们的示例中查看就地文件编辑和流编辑。

# 流编辑

首先，我们将看一下使用`sed`进行实际流编辑。流编辑允许我们做一些很酷的事情：例如，我们可以更改文本中的一些单词。我们还可以删除我们不关心的某些行（例如，不包含单词 ERROR 的所有内容）。

我们将从一个简单的例子开始，搜索并替换一行中的一个单词：

```
reader@ubuntu:~/scripts/chapter_10$ echo "What a wicked sentence"
What a wicked sentence
reader@ubuntu:~/scripts/chapter_10$ echo "What a wicked sentence" | sed 's/wicked/stupid/'
What a stupid sentence
```

就像这样，`sed`将我的积极句子转变成了不太积极的东西。`sed`使用的模式（在`sed`术语中，这只是称为*script*）是`s/wicked/stupid/`。`s`代表搜索替换，*script*的第一个单词被第二个单词替换。

观察一下对于具有多个匹配项的多行会发生什么：

```
reader@ubuntu:~/scripts/chapter_10$ vim search.txt
reader@ubuntu:~/scripts/chapter_10$ cat search.txt 
How much wood would a woodchuck chuck
if a woodchuck could chuck wood?
reader@ubuntu:~/scripts/chapter_10$ cat search.txt | sed 's/wood/stone/'
How much stone would a woodchuck chuck
if a stonechuck could chuck wood?
```

从这个例子中，我们可以学到两件事：

+   默认情况下，`sed`只会替换每行中每个单词的第一个实例。

+   `sed`不仅匹配整个单词，还匹配部分单词。

如果我们想要替换每行中的所有实例怎么办？这称为*全局*搜索替换，语法只有非常轻微的不同：

```
reader@ubuntu:~/scripts/chapter_10$ cat search.txt | sed 's/wood/stone/g'
How much stone would a stonechuck chuck
if a stonechuck could chuck stone?
```

通过在`sed` *script*的末尾添加`g`，我们现在全局替换所有实例，而不仅仅是每行的第一个实例。

另一种可能性是，您可能只想在第一行上进行搜索替换。您可以使用`head -1`仅选择该行，然后将其发送到`sed`，但这意味着您需要在后面添加其他行。

我们可以通过在`sed`脚本前面放置行号来选择要编辑的行，如下所示：

```
reader@ubuntu:~/scripts/chapter_10$ cat search.txt | sed '1s/wood/stone/'
How much stone would a woodchuck chuck
if a woodchuck could chuck wood?
reader@ubuntu:~/scripts/chapter_10$ cat search.txt | sed '1s/wood/stone/g'
How much stone would a stonechuck chuck
if a woodchuck could chuck wood?
reader@ubuntu:~/scripts/chapter_10$ cat search.txt | sed '1,2s/wood/stone/g'
How much stone would a stonechuck chuck
if a stonechuck could chuck stone?
```

第一个脚本，`'1s/wood/stone/'`，指示`sed`将第一行中的第一个*wood*实例替换为*stone*。下一个脚本，`'1s/wood/stone/g'`，告诉`sed`将*wood*的所有实例替换为*stone*，但只在第一行上。最后一个脚本，`'1,2s/wood/stone/g'`，使`sed`替换所有行（包括！）中（和包括！）`1`和`2`之间的所有*wood*实例。

# 就地编辑

虽然在将文件发送到`sed`之前`cat`文件并不是*那么*大的问题，幸运的是，我们实际上不需要这样做。`sed`的用法如下：`sed [OPTION] {script-only-if-no-other-script} [input-file]`。正如您在最后看到的那样，还有一个选项`[input-file]`。

让我们拿之前的一个例子，然后去掉`cat`：

```
reader@ubuntu:~/scripts/chapter_10$ sed 's/wood/stone/g' search.txt 
How much stone would a stonechuck chuck
if a stonechuck could chuck stone?
reader@ubuntu:~/scripts/chapter_10$ cat search.txt 
How much wood would a woodchuck chuck
if a woodchuck could chuck wood?
```

如您所见，通过使用可选的`[input-file]`参数，`sed`根据脚本处理文件中的所有行。默认情况下，`sed`会打印它处理的所有内容。在某些情况下，这会导致行被打印两次，即当使用`sed`的`print`函数时（我们稍后会看到）。

这个例子展示的另一个非常重要的事情是：这种语法不会编辑原始文件；只有打印到`STDOUT`的内容会发生变化。有时，您可能希望编辑文件本身——对于这些情况，`sed`有`--in-place`（`-i`）选项。

确保您理解这**会对磁盘上的文件进行不可逆转的更改**。而且，就像 Linux 中的大多数事情一样，没有撤销按钮或回收站！

让我们看看如何使用`sed -i`来持久更改文件（当然，在我们备份之后）：

```
reader@ubuntu:~/scripts/chapter_10$ cat search.txt 
How much wood would a woodchuck chuck
if a woodchuck could chuck wood?
reader@ubuntu:~/scripts/chapter_10$ cp search.txt search.txt.bak
reader@ubuntu:~/scripts/chapter_10$ sed -i 's/wood/stone/g' search.txt
reader@ubuntu:~/scripts/chapter_10$ cat search.txt
How much stone would a stonechuck chuck
if a stonechuck could chuck stone?
```

这一次，不是将处理后的文本打印到屏幕上，而是`sed`悄悄地更改了磁盘上的文件。由于这种破坏性的本质，我们事先创建了一个备份。但是，`sed`的`--in-place`选项也可以提供这种功能，方法是添加文件后缀：

```
reader@ubuntu:~/scripts/chapter_10$ ls
character-class.txt  error.txt  grep-file.txt  grep-then-else.sh  search.txt  search.txt.bak
reader@ubuntu:~/scripts/chapter_10$ mv search.txt.bak search.txt
reader@ubuntu:~/scripts/chapter_10$ cat search.txt 
How much wood would a woodchuck chuck
if a woodchuck could chuck wood?
reader@ubuntu:~/scripts/chapter_10$ sed -i'.bak' 's/wood/stone/g' search.txt
reader@ubuntu:~/scripts/chapter_10$ cat search.txt
How much stone would a stonechuck chuck
if a stonechuck could chuck stone?
reader@ubuntu:~/scripts/chapter_10$ cat search.txt.bak 
How much wood would a woodchuck chuck
if a woodchuck could chuck wood?
```

`sed`的语法有点吝啬。如果在`-i`和`'.bak'`之间加上一个空格，您将会得到奇怪的错误（这通常对于选项带有参数的命令来说是正常的）。在这种情况下，因为脚本定义紧随其后，`sed`很难区分文件后缀和脚本字符串。

只要记住，如果您想使用这个，您需要小心这个语法！

# 行操作

虽然`sed`的单词操作功能很棒，但它也允许我们操作整行。例如，我们可以按行号删除某些行：

```
reader@ubuntu:~/scripts/chapter_10$ echo -e "Hi,\nthis is \nPatrick"
Hi,
this is 
Patrick
reader@ubuntu:~/scripts/chapter_10$ echo -e "Hi,\nthis is \nPatrick" | sed 'd'
reader@ubuntu:~/scripts/chapter_10$ echo -e "Hi,\nthis is \nPatrick" | sed '1d'
this is 
Patrick
```

通过使用`echo -e`结合换行符（`\n`），我们可以创建多行语句。`-e`在`man echo`页面上解释为*启用反斜杠转义的解释*。通过将这个多行输出传递给`sed`，我们可以使用删除功能，这是一个简单地使用字符`d`的脚本。

如果我们在行号前加上一个前缀，例如`1d`，则删除第一行。如果不这样做，所有行都将被删除，这对我们来说没有输出。

另一个，通常更有趣的可能性是删除包含某个单词的行：

```
reader@ubuntu:~/scripts/chapter_10$ echo -e "Hi,\nthis is \nPatrick" | sed '/Patrick/d'
Hi,
this is 
reader@ubuntu:~/scripts/chapter_10$ echo -e "Hi,\nthis is \nPatrick" | sed '/patrick/d'
Hi,
this is 
Patrick
```

与我们使用脚本进行单词匹配的`sed`搜索替换功能一样，如果存在某个单词，我们也可以删除整行。从前面的例子中可以看到，这是区分大小写的。幸运的是，如果我们想以不区分大小写的方式进行操作，总是有解决办法。在`grep`中，这将是`-i`标志，但对于`sed`，`-i`已经保留给了`--in-place`功能。

那我们该怎么做呢？当然是使用我们的老朋友正则表达式！请参阅以下示例：

```
reader@ubuntu:~/scripts/chapter_10$ echo -e "Hi,\nthis is \nPatrick" | sed '/[Pp]atrick/d'
Hi,
this is
reader@ubuntu:~/scripts/chapter_10$ echo -e "Hi,\nthis is \nPatrick" | sed '/.atrick/d'
Hi,
this is
```

虽然它不像`grep`提供的功能那样优雅，但在大多数情况下它确实完成了工作。它至少应该让您意识到，使用正则表达式与`sed`使整个过程更加灵活和更加强大。

与大多数事物一样，增加了灵活性和功能，也增加了复杂性。但是，我们希望通过这对正则表达式和`sed`的简要介绍，两者的组合不会感到难以管理的复杂。

与从文件或流中删除行不同，您可能更适合只显示一些文件。但是，这里有一个小问题：默认情况下，`sed`会打印它处理的所有行。如果您给`sed`指令打印一行（使用`p`脚本*），它将打印该行两次——一次是匹配脚本，另一次是默认打印。

这看起来有点像这样：

```
reader@ubuntu:~/scripts/chapter_10$ cat error.txt 
Process started.
Running normally.
ERROR: TCP socket broken.
ERROR: Cannot connect to database.
Exiting process.
reader@ubuntu:~/scripts/chapter_10$ sed '/ERROR/p' error.txt 
Process started.
Running normally.
ERROR: TCP socket broken.
ERROR: TCP socket broken.
ERROR: Cannot connect to database.
ERROR: Cannot connect to database.
Exiting process.
```

打印和删除脚本的语法类似：`'/word/d'`和`'/word/p'`。要抑制`sed`的默认行为，即打印所有行，添加`-n`（也称为`--quiet`或`--silent`）：

```
reader@ubuntu:~/scripts/chapter_10$ sed -n '/ERROR/p' error.txt 
ERROR: TCP socket broken.
ERROR: Cannot connect to database.
```

您可能已经发现，使用`sed`脚本打印和删除行与`grep`和`grep -v`具有相同的功能。在大多数情况下，您可以选择使用哪种。但是，一些高级功能，例如删除匹配的行，但仅从文件的前 10 行中删除，只能使用`sed`完成。作为一个经验法则，任何可以使用单个语句使用`grep`实现的功能都应该使用`grep`来处理；否则，转而使用`sed`。

有一个`sed`的最后一个用例我们想要强调：您有一个文件或流，您需要删除的不是整行，而只是这些行中的一些单词。使用`grep`，这是（很容易地）无法实现的。然而，`sed`有一种非常简单的方法来做到这一点。

搜索和替换与仅仅删除一个单词有什么不同？只是替换模式！

请参阅以下示例：

```
reader@ubuntu:~/scripts/chapter_10$ cat search.txt
How much stone would a stonechuck chuck
if a stonechuck could chuck stone?
reader@ubuntu:~/scripts/chapter_10$ sed 's/stone//g' search.txt
How much  would a chuck chuck
if a chuck could chuck ?
```

通过将单词 stone 替换为*nothing*（因为这正是在`sed`脚本中第二个和第三个反斜杠之间存在的内容），我们完全删除了单词 stone。然而，在这个例子中，你可以看到一个常见的问题，你肯定会遇到：删除单词后会有额外的空格。

这带我们来到了`sed`的另一个技巧，可以帮助你解决这个问题：

```
reader@ubuntu:~/scripts/chapter_10$ sed -e 's/stone //g' -e 's/stone//g' search.txt
How much would a chuck chuck
if a chuck could chuck ?
```

通过提供`-e`，后跟一个`sed`脚本，你可以让`sed`在你的流上运行多个脚本（按顺序！）。默认情况下，`sed`期望至少有一个脚本，这就是为什么如果你只处理一个脚本，你不需要提供`-e`。对于比这更多的脚本，你需要在每个脚本之前添加一个`-e`。

# 最后的话

正则表达式很**难**。在 Linux 上更难的是，正则表达式已经由不同的程序（具有不同的维护者和不同的观点）略有不同地实现。

更糟糕的是，一些正则表达式的特性被一些程序隐藏为扩展的正则表达式，而在其他程序中被认为是默认的。在过去的几年里，这些程序的维护者似乎已经朝着更全局的 POSIX 标准迈进，用于*正则*正则表达式和*扩展*正则表达式，但直到今天，仍然存在一些差异。

我们对处理这个问题有一些建议：**试一试**。也许你不记得星号在 globbing 中代表什么，与正则表达式不同，或者问号为什么会有不同的作用。也许你会忘记用`-E`来“激活”扩展语法，你的扩展搜索模式会返回奇怪的错误。

你肯定会忘记引用搜索模式一次，如果它包含像点或$这样的字符（由 Bash 解释），你的命令会崩溃，通常会有一个不太清晰的错误消息。

只要知道我们都犯过这些错误，只有经验才能让这变得更容易。事实上，在写这一章时，几乎没有一个命令像我们在脑海中想象的那样立即起作用！你并不孤单，你不应该因此感到难过。*继续努力，直到成功，并且直到你明白为什么第一次没有成功。*

# 总结

本章解释了正则表达式，以及在 Linux 下使用它们的两个常见工具：`grep`和`sed`。

我们首先解释了正则表达式是与文本结合使用的*搜索模式*，用于查找匹配项。这些搜索模式允许我们在文本中进行非常灵活的搜索，其中文本的内容在运行时不一定已知。

搜索模式允许我们，例如，仅查找单词而不是数字，查找行首或行尾的单词，或查找空行。搜索模式包括通配符，可以表示某个字符或字符类的一个或多个。

我们介绍了`grep`命令，以展示我们如何在 Bash 中使用正则表达式的基本功能。

本章的第二部分涉及 globbing。Globbing 用作文件名和路径的通配符机制。它与正则表达式有相似之处，但也有一些关键的区别。Globbing 可以与大多数处理文件的命令一起使用（而且，由于 Linux 下的大多数*东西*都可以被视为文件，这意味着几乎所有命令都支持某种形式的 globbing）。

本章的后半部分描述了如何使用`egrep`和`sed`的正则表达式。`egrep`是`grep -E`的简单包装器，允许我们使用扩展语法进行正则表达式，我们讨论了一些常用的高级`grep`功能。

与默认的正则表达式相比，扩展的正则表达式允许我们指定某些模式的长度以及它们重复的次数，同时还允许我们使用交替。

本章的最后部分描述了`sed`，流编辑器。`sed`是一个复杂但非常强大的命令，可以让我们做比`grep`更令人兴奋的事情。

本章介绍了以下命令：`grep`、`set`、`egrep`和`sed`。

# 问题

1.  什么是搜索模式？

1.  为什么正则表达式被认为是贪婪的？

1.  在搜索模式中，哪个字符被认为是除换行符外的任意一个字符的通配符？

1.  在 Linux 正则表达式搜索模式中，星号如何使用？

1.  什么是行锚点？

1.  列举三种字符类型。

1.  什么是 globbing？

1.  在 Bash 下，扩展正则表达式语法可以实现哪些普通正则表达式无法实现的功能？

1.  在决定使用`grep`还是`sed`时，有什么好的经验法则？

1.  为什么 Linux/Bash 上的正则表达式如此困难？

# 进一步阅读

如果您想更深入地了解本章主题，以下资源可能会很有趣：

+   Linux 文档项目关于正则表达式：[`www.tldp.org/LDP/abs/html/x17129.html`](http://www.tldp.org/LDP/abs/html/x17129.html)

+   Linux 文档项目关于 Globbing：[`www.tldp.org/LDP/abs/html/globbingref.html`](http://www.tldp.org/LDP/abs/html/globbingref.html)

+   Linux 文档项目关于 Sed：[`tldp.org/LDP/abs/html/x23170.html`](http://tldp.org/LDP/abs/html/x23170.html)
