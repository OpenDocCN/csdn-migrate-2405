# Linux 快速学习手册（二）

> 原文：[`zh.annas-archive.org/md5/d44a95bd11f73f80156880d7ba808e3a`](https://zh.annas-archive.org/md5/d44a95bd11f73f80156880d7ba808e3a)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

复制、移动和删除文件

如果您以前拥有过计算机，那么您就知道能够在文件之间复制和移动文件是多么重要。这就是为什么我专门写了一整章来讨论这个问题：复制、移动和删除文件。

# 第五章：复制一个文件

有时您需要复制单个文件。幸运的是，在命令行上这是一个简单的操作。我在我的主目录中有一个名为`cats.txt`的文件：

```
elliot@ubuntu-linux:~$ cat cats.txt 
I love cars!
I love cats!
I love penguins!
elliot@ubuntu-linux:~$
```

我可以使用`cp`命令复制名为`cats.txt`的文件并命名为`copycats.txt`，方法如下：

```
elliot@ubuntu-linux:~$ cp cats.txt copycats.txt 
elliot@ubuntu-linux:~$ cat copycats.txt
I love cars!
I love cats!
I love penguins!
elliot@ubuntu-linux:~$
```

如您所见，复制的文件`copycats.txt`与原始文件`cats.txt`具有相同的内容。

我也可以将文件`cats.txt`复制到另一个目录。例如，我可以通过运行`cp cats.txt /tmp`命令将文件`cats.txt`复制到`/tmp`中：

```
elliot@ubuntu-linux:~$ cp cats.txt /tmp
elliot@ubuntu-linux:~$ cd /tmp
elliot@ubuntu-linux:/tmp$ ls
cats.txt
elliot@ubuntu-linux:/tmp$
```

请注意，复制的文件与原始文件具有相同的名称。我也可以在**`/tmp`**中用不同的名称再复制一份：

```
elliot@ubuntu-linux:~$ cp cats.txt /tmp/cats2.txt
elliot@ubuntu-linux:~$ cd /tmp
elliot@ubuntu-linux:/tmp$ ls 
cats2.txt  cats.txt
elliot@ubuntu-linux:/tmp$
```

# 复制多个文件

您可能还想一次复制多个文件。为了演示，让我们首先在 Elliot 的主目录中创建三个文件`apple.txt`、`banana.txt`和`carrot.txt`：

```
elliot@ubuntu-linux:~$ touch apple.txt banana.txt carrot.txt
elliot@ubuntu-linux:~$ ls
apple.txt carrot.txt copycats.txt dir1 
banana.txt cats.txt Desktop
elliot@ubuntu-linux:~$
```

要将三个新创建的文件复制到`/tmp`，您可以运行`cp apple.txt ba- nana.txt carrot.txt /tmp`命令：

```
elliot@ubuntu-linux:~$ cp apple.txt banana.txt carrot.txt /tmp
elliot@ubuntu-linux:~$ cd /tmp
elliot@ubuntu-linux:/tmp$ ls
apple.txt banana.txt carrot.txt cats2.txt cats.txt
elliot@ubuntu-linux:/tmp$
```

小菜一碟！一般来说，`cp`命令遵循以下语法：

```
cp source_file(s) destination
```

# 复制一个目录

您可能还想复制整个目录；这也很容易实现。为了演示，在您的主目录中创建一个名为`cities`的目录，并在`cities`中创建三个文件`paris`、`tokyo`和`london`，如下所示：

```
elliot@ubuntu-linux:~$ mkdir cities
elliot@ubuntu-linux:~$ cd cities/
elliot@ubuntu-linux:~/cities$ touch paris tokyo london
elliot@ubuntu-linux:~/cities$ ls
london paris tokyo
```

现在，如果您想将`cities`目录复制到`/tmp`，您必须向`cp`命令传递递归的`-r`选项，如下所示：

```
elliot@ubuntu-linux:~/cities$ cd ..
elliot@ubuntu-linux:~$ cp -r cities /tmp
```

如果您省略了`-r`选项，将会收到错误消息：

```
elliot@ubuntu-linux:~$ cp cities /tmp
cp: -r not specified; omitting directory 'cities'
```

您可以通过列出`/tmp`中的文件来验证`cities`目录是否已复制到`/tmp`中：

```
elliot@ubuntu-linux:~$ cd /tmp
elliot@ubuntu-linux:/tmp$ ls
apple.txt banana.txt carrot.txt cats2.txt cats.txt cities
elliot@ubuntu-linux:/tmp$ ls cities
london paris tokyo
```

# 复制多个目录

您还可以像复制多个文件一样复制多个目录；唯一的区别是您必须向`cp`命令传递递归的`-r`选项。

为了演示，在 Elliot 的主目录中创建三个目录`d1`、`d2`和`d3`：

```
elliot@ubuntu-linux:~$ mkdir d1 d2 d3
```

现在，您可以通过运行`cp -r d1 d2 d3 /tmp`命令将所有三个目录复制到`/tmp`中：

```
elliot@ubuntu-linux:~$ cp -r d1 d2 d3 /tmp
elliot@ubuntu-linux:~$ cd /tmp
elliot@ubuntu-linux:/tmp$ ls
apple.txt banana.txt carrot.txt cats2.txt cats.txt cities d1 d2 d3
```

# 移动一个文件

有时，您可能希望将文件（或目录）移动到不同的位置，而不是复制并浪费磁盘空间。

为此，您可以使用`mv`命令。例如，您可以通过运行`mv copycats.txt /tmp`命令，将文件`copycats.txt`从 Elliot 的主目录移动到`/tmp`：

```
elliot@ubuntu-linux:~$ mv copycats.txt /tmp
elliot@ubuntu-linux:~$ ls
apple.txt   carrot.txt cities d2  Desktop  Downloads
banana.txt  cats.txt   d1     d3  dir1     Pictures
elliot@ubuntu-linux:~$ cd /tmp
elliot@ubuntu-linux:/tmp$ ls
apple.txt  carrot.txt cats.txt copycats.txt d2
banana.txt cats2.txt  cities   d1           d3
```

请注意，`copycats.txt`现在已经从 Elliot 的主目录中消失，因为它已经迁移到`/tmp`中。

# 移动多个文件

您也可以像复制多个文件一样移动多个文件。例如，您可以将三个文件`apple.txt`、`banana.txt`和`carrot.txt`从`/tmp`移动到`/home/elliot/d1`，方法如下：

```
elliot@ubuntu-linux:/tmp$ mv apple.txt banana.txt carrot.txt /home/elliot/d1
elliot@ubuntu-linux:/tmp$ ls
cats2.txt cats.txt cities copycats.txt d1 d2 d3
elliot@ubuntu-linux:/tmp$ cd /home/elliot/d1
elliot@ubuntu-linux:~/d1$ ls
apple.txt banana.txt carrot.txt
elliot@ubuntu-linux:~/d1$
```

如您所见，三个文件`apple.txt`、`banana.txt`和`carrot.txt`不再位于`/tmp`中，因为它们都移动到了`/home/elliot/d1`。一般来说，`mv`命令遵循以下语法：

```
mv source_file(s) destination
```

# 移动一个目录

您还可以使用`mv`命令移动目录。例如，如果要移动目录`d3`并将其放入`d2`中，则可以运行`mv d3 d2`命令：

```
elliot@ubuntu-linux:~$ mv d3 d2
elliot@ubuntu-linux:~$ cd d2
elliot@ubuntu-linux:~/d2$ ls 
d3
elliot@ubuntu-linux:~/d2$
```

请注意，移动目录不需要使用递归的`-r`选项。

# 移动多个目录

您还可以一次移动多个目录。为了演示，在 Elliot 的主目录中创建一个名为`big`的目录：

```
elliot@ubuntu-linux:~$ mkdir big
```

现在您可以将三个目录`d1`、`d2`和`cities`移动到`big`目录中，方法如下：

```
elliot@ubuntu-linux:~$ mv d1 d2 cities big
elliot@ubuntu-linux:~$ ls big
cities d1 d2
elliot@ubuntu-linux:~$
```

# 重命名文件

您还可以使用`mv`命令重命名文件。例如，如果要将文件`cats.txt`重命名为`dogs.txt`，可以运行`mv cats.txt dogs.txt`命令：

```
elliot@ubuntu-linux:~$ mv cats.txt dogs.txt
elliot@ubuntu-linux:~$ cat dogs.txt
I love cars!
I love cats!
I love penguins!
elliot@ubuntu-linux:~$
```

如果要将目录`big`重命名为`small`，可以运行`mv big small`命令：

```
elliot@ubuntu-linux:~$ mv big small
elliot@ubuntu-linux:~$ ls small 
cities d1 d2
elliot@ubuntu-linux:~$
```

总之，这就是`mv`命令的工作原理：

1.  如果目标目录存在，`mv`命令将移动源文件到目标目录。

1.  如果目标目录不存在，`mv`命令将重命名源文件。

请记住，您一次只能重命名一个文件（或一个目录）。

# 隐藏文件

您可以通过将文件重命名为以点开头的名称来隐藏任何文件。

让我们试试吧；您可以通过将文件重命名为`.dogs.txt`来隐藏文件`dogs.txt`，如下所示：

```
elliot@ubuntu-linux:~$ ls
apple.txt banana.txt carrot.txt dogs.txt Desktop dir1 small
elliot@ubuntu-linux:~$ mv dogs.txt .dogs.txt
elliot@ubuntu-linux:~$ ls
apple.txt banana.txt carrot.txt Desktop dir1 small
elliot@ubuntu-linux:~$
```

正如您所看到的，文件`dogs.txt`现在被隐藏了，因为它被重命名为`.dogs.txt`。您可以通过重命名它并删除文件名前面的点来取消隐藏`.dogs.txt`：

```
elliot@ubuntu-linux:~$ mv .dogs.txt dogs.txt
elliot@ubuntu-linux:~$ ls
apple.txt banana.txt carrot.txt dogs.txt Desktop dir1 small
elliot@ubuntu-linux:~$
```

是的，先生！您也可以以相同的方式隐藏和取消隐藏目录。我会留下这个让你作为练习。

# 删除文件

您可以使用`rm`命令来删除文件。例如，如果要删除文件`dogs.txt`，可以运行`rm dogs.txt`命令：

```
elliot@ubuntu-linux:~$ ls
apple.txt banana.txt carrot.txt dogs.txt Desktop dir1 small
elliot@ubuntu-linux:~$ rm dogs.txt
elliot@ubuntu-linux:~$ ls
apple.txt banana.txt carrot.txt Desktop dir1 small
```

您也可以一次删除多个文件。例如，您可以通过运行`rm apple.txt banana.txt carrot.txt`命令来删除三个文件`apple.txt`，`banana.txt`和`carrot.txt`：

```
elliot@ubuntu-linux:~$ rm apple.txt banana.txt carrot.txt
elliot@ubuntu-linux:~$ ls
Desktop dir1 small 
elliot@ubuntu-linux:~$
```

# 删除目录

您可以通过传递递归的`-r`选项来删除目录的`rm`命令。为了演示，让我们首先在 Elliot 的主目录中创建一个名为`garbage`的目录：

```
elliot@ubuntu-linux:~$ mkdir garbage
elliot@ubuntu-linux:~$ ls
Desktop dir1 garbage small
```

现在让我们尝试删除`garbage`目录：

```
elliot@ubuntu-linux:~$ rm garbage
rm: cannot remove 'garbage': Is a directory
elliot@ubuntu-linux:~$
```

糟糕！我出错了，因为我没有传递递归的`-r`选项。这次我会传递递归选项：

```
elliot@ubuntu-linux:~$ rm -r garbage
elliot@ubuntu-linux:~$ ls
Desktop dir1 small
```

太棒了！我们摆脱了`garbage`目录。

你也可以使用`rmdir`命令来删除只有空目录。为了演示，让我们创建一个名为`garbage2`的新目录，并在其中创建一个名为`old`的文件：

```
elliot@ubuntu-linux:~$ mkdir garbage2
elliot@ubuntu-linux:~$ cd garbage2
elliot@ubuntu-linux:~/garbage2$ touch old
```

现在让我们回到 Elliot 的主目录，并尝试使用`rmdir`命令删除`garbage2`：

```
elliot@ubuntu-linux:~/garbage2$ cd ..
elliot@ubuntu-linux:~$ rmdir garbage2
rmdir: failed to remove 'garbage2': Directory not empty
```

正如您所看到的，它不允许您删除非空目录。因此，让我们删除`garbage2`中的文件`old`，然后重新尝试删除`garbage2`：

```
elliot@ubuntu-linux:~$ rm garbage2/old
elliot@ubuntu-linux:~$ rmdir garbage2
elliot@ubuntu-linux:~$ ls
Desktop dir1 small 
elliot@ubuntu-linux:~$
```

哇！`garbage2`目录永远消失了。这里要记住的一件事是，`rm -r`命令将删除任何目录（空目录和非空目录）。另一方面，`rmdir`命令只会删除空目录。

在本章的最后一个示例中，让我们创建一个名为`garbage3`的目录，然后在其中创建两个文件`a1.txt`和`a2.txt`：

```
elliot@ubuntu-linux:~$ mkdir garbage3
elliot@ubuntu-linux:~$ cd garbage3/
elliot@ubuntu-linux:~/garbage3$ touch a1.txt a2.txt
elliot@ubuntu-linux:~/garbage3$ ls
a1.txt a2.txt
```

现在让我们回到 Elliot 的主目录，尝试删除`garbage3`：

```
elliot@ubuntu-linux:~/garbage3$ cd ..
elliot@ubuntu-linux:~$ rmdir garbage3
rmdir: failed to remove 'garbage3': Directory not empty
elliot@ubuntu-linux:~$ rm -r garbage3
elliot@ubuntu-linux:~$ ls
Desktop dir1 Downloads Pictures small
elliot@ubuntu-linux:~$
```

正如您所看到的，`rmdir`命令未能删除非空目录`garbage3`，而`rm -r`命令成功删除了它。

没有什么比一个好的知识检查练习更能让信息牢固地留在你的脑海中了。

# 知识检查

对于以下练习，打开您的终端并尝试解决以下任务：

1.  在您的主目录中创建三个文件`hacker1`，`hacker2`和`hacker3`。

1.  在您的主目录中创建三个目录`Linux`，`Windows`和`Mac`。

1.  在您在任务 2 中创建的`Linux`目录中创建一个名为`cool`的文件。

1.  在您在任务 2 中创建的`Windows`目录中创建一个名为`boring`的文件。

1.  在您在任务 2 中创建的`Mac`目录中创建一个名为`expensive`的文件。

1.  将两个文件`hacker1`和`hacker2`复制到`/tmp`目录。

1.  将两个目录`Windows`和`Mac`复制到`/tmp`目录。

1.  将文件`hacker3`移动到`/tmp`目录。

1.  将目录`Linux`移动到`/tmp`目录。

1.  从您的主目录中的`Mac`目录中删除文件`expensive`。

1.  从您的主目录中删除目录`Mac`。

1.  从您的主目录中删除目录`Windows`。

1.  从您的主目录中删除文件`hacker2`。

1.  将文件`hacker1`重命名为`hacker01`。

## 真或假

1.  `cp`命令可以复制目录，而不使用递归选项`-r`。

1.  在移动目录时，您必须使用递归选项`-r`。

1.  您可以使用`mv`命令来重命名文件或目录。

1.  您可以使用`rmdir`命令删除非空目录。

1.  您可以使用`rm -r`命令删除非空目录。


阅读你的手册！

你现在可能会对自己说：“Linux 太难了！有很多命令，甚至有更多的命令选项！我不可能掌握所有这些命令并记住它们。”如果这是你的想法，相信我，你是聪明的。记住所有存在的 Linux 命令是不可能的，即使是最有经验的 Linux 管理员也永远不可能记住所有命令，甚至连 Linus Torvalds 本人也不可能！

那么等等？如果是这样，那么解决方案是什么呢？答案就在美丽的 Linux 文档世界中。Linux 有非常完善的文档，以至于很难在其中迷失。Linux 中有各种工具，不仅可以帮助你记住命令，还可以帮助你理解如何使用它们。

在我的职业生涯中遇到了许多 Linux 专业人士，我注意到最熟练的 Linux 管理员不是那些记住了所有命令的人，而是那些知道如何充分利用 Linux 文档的人。女士们先生们，我强烈建议你系好安全带，仔细阅读本章。我向你保证，你心中的恐惧很快就会消失！

# 第六章：Linux 命令的四个类别

所有 Linux 命令必须属于以下四个类别中的一个：

1.  **可执行程序**：通常是用 C 编程语言编写的。`cp`命令就是一个可执行命令的例子。

1.  **别名**：基本上是命令（或一组命令）的另一个名称。

1.  **shell 内置命令**：shell 也支持内部命令。`exit`和`cd`命令就是 shell 内置命令的两个例子。

1.  **shell 函数**：这些函数帮助我们完成特定任务，在编写 shell 脚本时至关重要。稍后我们会更详细地介绍这个，现在只需要知道它们存在即可。

# 确定命令的类型

你可以使用`type`命令来确定命令的类型（类别）。例如，如果你想知道`pwd`命令的类型，只需运行`type pwd`命令：

```
elliot@ubuntu-linux:~$ type pwd 
pwd is a shell builtin
```

所以现在你知道`pwd`命令是一个 shell 内置命令。现在让我们弄清楚`ls`命令的类型：

```
elliot@ubuntu-linux:~$ type ls
ls is aliased to `ls --color=auto'
```

你可以看到，`ls`命令被别名为`ls --color=auto`。现在你知道为什么每次运行`ls`命令时都会看到彩色的输出了。让我们看看`date`命令的类型：

```
elliot@ubuntu-linux:~$ type date 
date is /bin/date
```

任何位于`/bin`或`/sbin`中的命令都是可执行程序。因此，我们可以得出`date`命令是一个可执行程序，因为它位于`/bin`中。

最后，让我们确定`type`命令本身的类型：

```
elliot@ubuntu-linux:~$ type type 
type is a shell builtin
```

原来`type`命令是一个 shell 内置命令。

# 查找命令的位置

每次运行一个可执行命令时，系统中都会有一个文件被执行。你可以使用`which`命令来确定可执行命令的位置。例如，如果你想知道`rm`命令的位置，可以运行`which rm`命令：

```
elliot@ubuntu-linux:~$ which rm
/bin/rm
```

所以现在你知道`rm`位于`/bin`目录中。让我们看看`reboot`命令的位置：

```
elliot@ubuntu-linux:~$ which reboot
/sbin/reboot
```

你可以看到，`reboot`命令位于`/sbin`目录中。

# 这个命令是做什么的？

你可以使用`whatis`命令来获取一个命令的简要描述。例如，如果你想知道`free`命令的目的，可以运行`whatis free`命令：

```
elliot@ubuntu-linux:~$ whatis free
free (1)             - Display amount of free and used memory in the system
```

你可以看到，`free`命令，正如我们已经知道的那样，显示系统中的空闲和已使用内存量。酷！现在让我们看看`df`命令的作用：

```
elliot@ubuntu-linux:~$ whatis df
df (1)               - report file system disk space usage
```

最后，让我们看看`which`命令的作用：

```
elliot@ubuntu-linux:~$ whatis which 
which (1)            - locate a command
```

正如我们已经知道的那样，`which`显示了一个命令的位置。

# man 页面

`whatis`命令给出了一个命令的简要描述；然而，它并不教你如何使用一个命令。为此，你可以使用`man`页面。

`man`页面是一个**手册**页面，其中有适当的文档，可帮助您了解如何使用命令。就像您购买新手机时，会得到一本手册，告诉您如何使用手机以及如何在手机上更新软件等。

一般来说，如果要阅读命令的`man`页面，可以运行：

```
man command_name
```

例如，如果要查看`touch`命令的`man`页面，可以运行`man touch`命令：

```
elliot@ubuntu-linux:~$ man touch
```

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/lrn-linux-qk/img/f8c6a647-777e-4f3b-88db-a75530e8e132.png)

图 1：touch man 页面

正如您在前面的屏幕截图中看到的，`touch` man 页面显示了如何使用该命令，并列出并解释了所有命令选项。

`表 9`向您展示了在浏览`man`页面时如何移动。

| **man 键** | **它的作用** |
| --- | --- |
| 空格 | 向前滚动一页。 |
| *Ctrl*+*F* | 向前滚动一页（与空格相同）。 |
| *Ctrl*+*B* | 向后滚动一页。 |
| `/word` | 将在`man`页面中搜索单词（模式）。例如，`/access`将在`man`页面中搜索单词`access` |
| *q* | 将退出`man`页面。 |
| *n* | 在搜索单词后，您可以使用*n*来查找`man`页面中单词的下一个出现。 |
| *N* | 在搜索单词后，您可以使用*N*来查找`man`页面中单词的上一个出现。 |

我无法再次强调`man`页面的重要性。相信我，在最黑暗的时刻，它们可以成为您最好的朋友！

您还应该知道`man`本身有一个 man 页面：

```
elliot@ubuntu-linux:~$ man man
```

它描述了如何使用`man`页面。

# shell 内置命令的帮助

如果您足够玩转`man`页面，您可能会注意到许多 shell 内置命令没有`man`页面。例如，`cd`或`exit`命令没有`man`页面：

```
elliot@ubuntu-linux:~$ type cd 
cd is a shell builtin 
elliot@ubuntu-linux:~$ man cd 
No manual entry for cd 
elliot@ubuntu-linux:~$ type exit 
exit is a shell builtin 
elliot@ubuntu-linux:~$ man exit 
No manual entry for exit
```

这是因为 shell 内置命令没有`man`页面，但不要慌！您仍然可以使用`help`命令找到如何使用 shell 内置命令的帮助。例如，要获取有关如何使用`exit`命令的帮助，您可以运行：

```
elliot@ubuntu-linux:~$ help exit 
exit: exit [n]
 Exit the shell.

 Exits the shell with a status of N. If N is omitted, the exit status 
 is that of the last command executed.
```

类似地，要获取有关如何使用`cd`命令的帮助，您可以运行`help cd`命令：

```
elliot@ubuntu-linux:~$ help cd 
cd: cd [-L|-P] [dir]
 Change the shell working directory.

 Change the current directory to DIR. The default DIR is the value of 
 the HOME shell variable.

 The variable CDPATH defines the search path for the directory containing DIR. 
 Alternative directory names in CDPATH are separated by a colon (:). 
 A null directory name is the same as the current directory. 
 If DIR begins with a slash (/), then CDPATH is not used.

 If the directory is not found, and the shell option `cdable_vars' is set, 
 the word is assumed to be a variable name. If that variable has a value, 
 its value is used for DIR.

 Options:
 -L force symbolic links to be followed
 -P use the physical directory structure without following symbolic links
 The default is to follow symbolic links, as if `-L' were specified. 

 Exit Status:
 Returns 0 if the directory is changed; non-zero otherwise.
```

# 信息页面

GNU 项目推出了`info`页面，作为`man`页面的替代文档。GNU 项目曾声称`man`页面已过时，需要替换，因此他们推出了`info`页面。

您可以通过运行以下命令查看任何命令的`info`页面：

```
info command_name
```

例如，要查看`ls`命令的`info`页面，可以运行`info ls`命令：

```
elliot@ubuntu-linux:~$ info ls

Next: dir invocation, Up: Directory listing

10.1 ‘ls': List directory contents
==================================

The ‘ls' program lists information about files (of any type, including directories). Options and file arguments can be intermixed arbitrarily, as usual.

For non-option command-line arguments that are directories, by default ‘ls' lists the contents of directories, not recursively, and omitting files with names beginning with ‘.'. For other non-option arguments, by default ‘ls' lists just the file name. If no non-option argument is specified, ‘ls' operates on the current directory, acting as if it had been invoked with a single argument of ‘.'.

By default, the output is sorted alphabetically, according to the locale settings in effect.(1) If standard output is a terminal, the output is in columns (sorted vertically) and control characters are output as question marks; otherwise, the output is listed one per line and control characters are output as-is.

Because ‘ls' is such a fundamental program, it has accumulated many options over the years. They are described in the subsections below; within each section, options are listed alphabetically (ignoring case). The division of options into the subsections is not absolute, since some options affect more than one aspect of ‘ls''s operation.
```

`info`页面有时提供比`man`页面更详细的信息。但是，`man`页面仍然是 Linux 上帮助文档的最受欢迎的去处。

# 非常有帮助的 apropos 命令

`apropos`命令是最有帮助但却被低估的 Linux 命令之一。让我们看一下`apropos`命令的简要描述：

```
elliot@ubuntu-linux:~$ whatis apropos
apropos (1)          - search the manual page names and descriptions
```

哇！`apropos`命令帮助您搜索正确的命令以实现特定任务。例如，假设您想重命名文件，但不确定要使用哪个 Linux 命令；在这种情况下，您可以运行`apropos rename`命令：

```
elliot@ubuntu-linux:~$ apropos rename
file-rename (1p)     - renames multiple files
File::Rename (3pm)   - Perl extension for renaming multiple files 
gvfs-rename (1)      - (unknown subject)
mmove (1)            - move or rename an MSDOS file or subdirectory 
mren (1)             - rename an existing MSDOS file
mv (1)               - move (rename) files 
prename (1p)         - renames multiple files 
rename (1)           - renames multiple files
rename.ul (1)        - rename files
```

轰隆！它列出了所有具有`rename`一词显示在其 man 页面描述中的命令。我打赌您可以在输出中找到`mv`命令。

假设您想查看日历，但不确定要使用哪个命令；在这种情况下，您可以运行：

```
elliot@ubuntu-linux:~$ apropos calendar
cal (1)              - displays a calendar and the date of Easter
calendar (1)         - reminder service
ncal (1)             - displays a calendar and the date of Easter
```

您可以看到它在输出中显示了`cal`命令。

对于最后一个例子，假设您想显示 CPU 信息，但不知道要使用哪个命令；在这种情况下，您可以运行：

```
elliot@ubuntu-linux:~$ apropos cpu 
chcpu (8)            - configure CPUs
cpuid (4)            - x86 CPUID access device
cpuset (7)           - confine processes to processor and memory node subsets 
lscpu (1)            - display information about the CPU architecture
msr (4)              - x86 CPU MSR access device
sched (7)            - overview of CPU scheduling
taskset (1)          - set or retrieve a process's CPU affinity
```

就是这样！您可以看到它列出了我们之前使用过的`lscpu`命令。每当您忘记一个命令或不确定要使用哪个命令时，`apropos`命令就在这里拯救您。您只需向`apropos`命令提供一个关键词（最好是动词），以突出您想要完成的任务：

```
apropos keyword
```

**酷技巧**

`man -k`命令将显示与`apropos`命令相同的结果。

```
elliot@ubuntu-linux:~$ man -k cpu 
chcpu (8)            - configure CPUs
cpuid (4)            - x86 CPUID access device
cpuset (7)           - confine processes to processor and memory node subsets 
lscpu (1)            - display information about the CPU architecture
msr (4)              - x86 CPU MSR access device
sched (7)            - overview of CPU scheduling
taskset (1)          - set or retrieve a process's CPU affinity
```

# `/usr/share/doc`目录

`/usr/share/doc`目录是在 Linux 中寻求帮助的另一个绝佳地方。这个目录有非常详尽的文档；它不仅仅向你展示如何使用一个命令；有时甚至会显示开发该命令的作者的姓名和联系信息。此外，它还可能包括一个`TODO`文件，其中包含一个未完成的任务/功能列表；贡献者通常会查看`TODO`文件来帮助修复错误和开发新功能。

为了演示，让我们去`nano`文档目录：

```
elliot@ubuntu-linux:~$ cd /usr/share/doc/nano 
elliot@ubuntu-linux:/usr/share/doc/nano$ pwd
/usr/share/doc/nano
```

现在列出目录的内容，看看里面有什么：

```
elliot@ubuntu-linux:/usr/share/doc/nano$ ls
AUTHORS               copyright faq.html        nano.html   README    TODO 
changelog.Debian.gz   examples  IMPROVEMENTS.gz NEWS.gz     THANKS.gz
```

太棒了！你可以查看`AUTHORS`文件，看看谁贡献了`nano`编辑器程序的开发团队。你还可以查看`TODO`文件，如果你渴望知道是否还有什么事情要做！你还可以查看`README`文件，了解`nano`编辑器的一般描述。甚至还有一个包含常见问题的`faq.html`链接。

正如你在本章中看到的，Linux 有各种有用的工具可供你使用；所以确保你充分利用它们！

# 知识检测

对于以下练习，打开你的终端并尝试解决以下任务：

1.  你需要知道`echo`命令是一个 shell 内置命令还是可执行程序，你会运行哪个命令？

1.  显示`uptime`命令可执行文件的位置。

1.  显示`mkdir`命令的简要描述。

1.  你忘记了如何使用`mv`命令，你打算怎么办？

1.  你忘记了用来显示日历的命令，你打算怎么办？

1.  `history`命令是一个 shell 内置命令，因此它没有 man 页面。你想要清除你的历史记录，但不知道该怎么做。你打算怎么办？

## 真或假

1.  `whereis`命令用于定位命令。

1.  你可以互换使用`man -p`和`apropos`。

1.  你可以使用`whatis`命令来获取一个命令的简要描述。

1.  你可以使用`type`命令来确定一个命令是别名、shell 内置命令还是可执行程序。


硬链接与软链接

在本章中，我们进一步了解 Linux 文件，并讨论硬链接和软链接之间的区别。如果您以前在 Windows（或 macOS）中创建过快捷方式，您将很快掌握软链接的概念。但在讨论硬链接和软链接之前，您首先必须了解 inode 的概念。

# 第七章：文件 inode

当您去杂货店时，您会发现每种产品都有一组属性，例如：

+   产品类型：巧克力

+   产品价格：$2.50

+   产品供应商：Kit Kat

+   剩余金额：199

这些属性可以通过扫描产品的条形码在杂货店的任何产品上显示。当然，每个条形码都是唯一的。嗯，您可以将这个类比应用到 Linux。Linux 上的每个文件都有一组属性，例如：

+   文件类型

+   文件大小

+   文件所有者

+   文件权限

+   硬链接数量

+   文件时间戳

这些属性存储在称为 inode（索引节点）的数据结构中，每个 inode 由一个编号（inode 编号）标识。因此，您可以将 inode 编号视为杂货店中的条形码。Linux 上的每个文件都有一个 inode 编号，每个 inode 编号指向一个文件数据结构，即 inode。以下是 inode 的正式定义：

**什么是 inode？**

inode 只是一个存储文件信息（属性）的文件数据结构，并且每个 inode 都由一个编号（inode 编号）唯一标识。

# 显示文件 inode 编号

有两个命令可以用来查看文件的 inode 编号：

1.  `ls -i`文件

1.  `stat`文件

例如，要查看`facts.txt`的 inode 编号，您可以运行`ls -i facts.txt`命令：

```
elliot@ubuntu-linux:~$ ls -i facts.txt 
924555 facts.txt
```

它将为您输出 inode 编号。您还可以使用`stat`命令：

```
elliot@ubuntu-linux:~$ stat facts.txt 
File: facts.txt
Size: 173 Blocks: 8 IO Block: 4096 regular file
Device: 801h/2049d Inode: 924555 Links: 1
Access: (0644/-rw-r--r--) Uid: ( 1000/ tom) Gid: ( 1000/ tom) 
Access: 2019-05-08 13:41:16.544000000 -0600
Modify: 2019-05-08 12:50:44.112000000 -0600
Change: 2019-05-08 12:50:44.112000000 -0600
Birth: -
```

`stat`命令不仅列出文件的 inode 编号；它还列出所有文件属性，正如您从命令输出中看到的那样。

# 创建软链接

现在，既然您了解了文件 inode 是什么，您可以轻松理解硬链接和软链接的概念。让我们从软链接开始：

**什么是软链接？**

软链接（也称为符号链接）只是指向另一个文件的文件。

一图胜过千言万语，因此以下图表将帮助您可视化软链接。

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/lrn-linux-qk/img/cd68ca82-ecf6-448a-bc85-a2a2781e55c1.png)

图 1：软链接可视化

要创建软链接，我们使用`ln`命令和`-s`选项，如下所示：

```
ln -s original_file soft_link
```

因此，要创建名为`soft.txt`的软链接到`facts.txt`文件，您可以运行`ln -s facts.txt soft.txt`命令：

```
elliot@ubuntu-linux:~$ ln -s facts.txt soft.txt
```

现在让我们对刚刚创建的软链接文件`soft.txt`进行长列表：

```
elliot@ubuntu-linux:~$ ls -l soft.txt
lrwxrwxrwx 1 tom tom 9 May 8 21:48 soft.txt -> facts.txt
```

您会注意到两件事。首先，输出的第一列中的字母`l`，表示文件是一个链接（软链接），其次您可以看到右箭头`soft.txt → facts.txt`，这基本上告诉我们`soft.txt`是一个指向文件`facts.txt`的软链接。

现在让我们检查文件`soft.txt`的内容：

```
elliot@ubuntu-linux:~$ cat soft.txt 
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

当然，它包含与原始文件`facts.txt`相同的数据。实际上，如果您编辑软链接，它实际上也会编辑原始文件。

为了演示，用任何文本编辑器打开文件`soft.txt`，并在文件的最末尾添加一行“草是绿色的。”，然后保存并退出，这样`soft.txt`的内容将如下所示：

```
elliot@ubuntu-linux:~$ cat soft.txt 
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
Grass is green.
```

现在让我们检查原始文件`facts.txt`的内容：

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
Grass is green.
```

正如您所看到的，新行“草是绿色的。”也在那里。这是因为每次您编辑软链接时，它实际上也会编辑指向的原始文件。

现在，如果您删除软链接，原始文件不会受到任何影响，它仍然完好无损：

```
elliot@ubuntu-linux:~$ rm soft.txt 
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
Grass is green.
```

现在让我们再次创建软链接`soft.txt`：

```
elliot@ubuntu-linux:~$ ln -s facts.txt soft.txt
```

如果您删除原始文件`facts.txt`，软链接`soft.txt`将变得无用！但在删除`facts.txt`文件之前，让我们在`/tmp`中制作一个副本，因为以后我们会需要它：

```
elliot@ubuntu-linux:~$ cp facts.txt /tmp
```

现在让我们从`elliot`的主目录中删除文件`facts.txt`，看看软链接会发生什么：

```
elliot@ubuntu-linux:~$ rm facts.txt 
elliot@ubuntu-linux:~$ cat soft.txt 
cat: soft.txt: No such file or directory
```

如您所见，软链接`soft.txt`变得无用，因为它现在指向无处。请记住，文件`soft.txt`仍然存在，如下截图所示。

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/lrn-linux-qk/img/e811db2d-563a-4f9d-aaab-28ab68e72bd2.png)

图 2：soft.txt 变得无用！

以下图表向您展示了原始文件`facts.txt`被删除后，软链接`soft.txt`指向无处。

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/lrn-linux-qk/img/4ca73beb-0143-44b9-be29-5c5d02bccfe7.png)

图 3：soft.txt 指向无处

现在，如果我们将`facts.txt`移回`elliot`的主目录：

```
elliot@ubuntu-linux:~$ mv /tmp/facts.txt /home/elliot
```

软链接`soft.txt`将再次有用！您可以说我们复活了软链接！

```
elliot@ubuntu-linux:~$ cat soft.txt 
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
Grass is green.
```

让我们比较软链接`soft.txt`和原始文件`facts.txt`的 inode 号：

```
elliot@ubuntu-linux:~$ ls -i soft.txt facts.txt 
925155 facts.txt 924556 soft.txt
```

如您所见，两个文件的 inode 号是不同的。最后，让我们对软链接`soft.txt`运行`stat`命令：

```
elliot@ubuntu-linux:~$ stat soft.txt 
File: soft.txt -> facts.txt
Size: 9 Blocks: 0 IO Block: 4096 symbolic link
Device: 801h/2049d Inode: 924556 Links: 1
Access: (0777/lrwxrwxrwx) Uid: ( 1000/ tom) Gid: ( 1000/ tom) 
Access: 2019-05-08 22:04:58.636000000 -0600
Modify: 2019-05-08 22:02:18.356000000 -0600
Change: 2019-05-08 22:02:18.356000000 -0600
Birth: -
```

如您所见，它将文件列为符号链接，这是软链接的另一个名称。

因此，正如您迄今所见，软链接具有以下属性：

+   软链接的 inode 与原始文件不同。

+   一旦原始文件被删除，软链接就变得无用。

+   对软链接的任何更改实际上都是对原始文件的更改。

+   您可以创建对目录的软链接。

您可以创建对目录的软链接，就像您可以创建对文件的软链接一样。为了演示，让我们首先在`elliot`的主目录中创建一个名为`sports`的目录。并在`sports`中创建三个文件-`swimming`，`soccer`和`hockey`，如下所示：

```
elliot@ubuntu-linux:~$ mkdir sports
elliot@ubuntu-linux:~$ touch sports/swimming sports/soccer sports/hockey 
elliot@ubuntu-linux:~$ ls sports
hockey soccer swimming
```

现在让我们创建名为`softdir1`的软链接到`sports`目录：

```
elliot@ubuntu-linux:~$ ln -s sports softdir1
```

现在如果您切换到`softdir1`，实际上是切换到`sports`，因此您将看到相同的目录内容：

```
elliot@ubuntu-linux:~$ cd softdir1 
elliot@ubuntu-linux:~/softdir1$ ls 
hockey soccer swimming
```

当然，对目录也是一样的；也就是说，如果您删除原始目录，软链接将变得无用！

# 创建硬链接

当涉及到硬链接时，情况有些不同。这是因为硬链接是原始文件的副本。以下是硬链接的定义：

**什么是硬链接？**

硬链接只是现有文件的附加名称。它具有与原始文件相同的 inode，因此与原始文件无法区分。

您可以将其视为昵称。当有人用您的昵称称呼您时，他们仍然在指代您。

硬链接具有以下属性：

+   硬链接具有与原始文件相同的 inode（共享）。

+   如果原始文件被删除，硬链接仍然保持完整。

+   对硬链接的任何更改都会反映在原始文件中。

+   您无法创建对目录的硬链接。

以下图表可帮助您可视化硬链接：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/lrn-linux-qk/img/ec54b906-da01-41fc-87c8-c2571ebb9a2d.png)

图 4：硬链接可视化

我们使用相同的`ln`命令来创建硬链接，但这次我们省略了`-s`选项：

```
ln original_file hard_link
```

因此，要创建名为`hard.txt`的硬链接到文件`facts.txt`，您只需运行命令`ln facts.txt hard.txt`：

```
elliot@ubuntu-linux:~$ ln facts.txt hard.txt
```

现在让我们对硬链接`hard.txt`和原始文件`facts.txt`进行长列表：

```
elliot@ubuntu-linux:~$ ls -l hard.txt
-rw-rw-r-- 2 tom tom 210 May 9 00:07 hard.txt 
elliot@ubuntu-linux:~$ ls -l facts.txt
-rw-rw-r-- 2 tom tom 210 May 9 00:07 facts.txt
```

它们是相同的！硬链接也与原始文件一样具有相同的内容：

```
elliot@ubuntu-linux:~$ cat hard.txt 
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
Grass is green.
```

现在使用您选择的文本编辑器向硬链接`hard.txt`的末尾添加一行“游泳是一项运动。”：

```
elliot@ubuntu-linux:~$ cat hard.txt 
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
Grass is green.
Swimming is a sport.
```

现在就像软链接的情况一样，原始文件的内容也发生了变化：

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
Grass is green.
Swimming is a sport.
```

现在让我们检查两个文件的 inode 号：

```
elliot@ubuntu-linux:~ ls -i hard.txt facts.txt 
925155 facts.txt 925155 hard.txt
```

请注意，两个文件具有相同的 inode 号。现在让我们对两个文件运行`stat`命令：

```
elliot@ubuntu-linux:~$ stat hard.txt facts.txt 
File: hard.txt
Size: 210 Blocks: 8 IO Block: 4096 regular file
Device: 801h/2049d Inode: 925155 Links: 2
Access: (0664/-rw-rw-r--) Uid: ( 1000/ elliot) Gid: ( 1000/ elliot) 
Access: 2019-05-09 00:07:36.884000000 -0600
Modify: 2019-05-09 00:07:25.708000000 -0600
Change: 2019-05-09 00:07:25.720000000 -0600
Birth: -
File: facts.txt
Size: 210 Blocks: 8 IO Block: 4096 regular file
Device: 801h/2049d Inode: 925155 Links: 2
Access: (0664/-rw-rw-r--) Uid: ( 1000/ elliot) Gid: ( 1000/ elliot)
Access: 2019-05-09 00:07:36.884000000 -0600
Modify: 2019-05-09 00:07:25.708000000 -0600
Change: 2019-05-09 00:07:25.720000000 -0600
Birth: -
```

`stat`命令的输出对两个文件都是相同的。而且，这里的`链接数：2`表示有两个硬链接指向该文件。嗯！我们只创建了一个硬链接指向文件`facts.txt`，那么为什么会列出两个硬链接呢？原来，原始文件是指向自身的硬链接，所以任何文件至少有一个硬链接（指向自身）。

现在与软链接的情况不同，如果你删除原始文件`facts.txt`：

```
elliot@ubuntu-linux:~$ rm facts.txt
```

硬链接保持不变：

```
elliot@ubuntu-linux:~$ cat hard.txt 
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
Grass is green.
Swimming is a sport.
```

下图显示了为什么硬链接保持不变。

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/lrn-linux-qk/img/5072e80d-4954-4b5b-8441-aabf89fc7768.png)

图 5：hard.txt 保持不变

现在注意，在删除文件`facts.txt`后，文件`hard.txt`的硬链接计数将减少到一个：

```
elliot@ubuntu-linux:~$ stat hard.txt 
File: hard.txt
Size: 210 Blocks: 8 IO Block: 4096 regular file
Device: 801h/2049d Inode: 925155 Links: 1
Access: (0664/-rw-rw-r--) Uid: ( 1000/ elliot) Gid: ( 1000/ elliot) 
Access: 2019-05-09 00:17:21.176000000 -0600
Modify: 2019-05-09 00:07:25.708000000 -0600
Change: 2019-05-09 00:17:18.696000000 -0600
Birth: -
```

你不能创建一个指向目录的硬链接。如果你不相信我，那就试着创建一个名为`variables`的硬链接指向`/var`目录：

```
elliot@ubuntu-linux:~$ ln /var variables
ln: /var: hard link not allowed for directory
```

我告诉过你，目录不允许有硬链接！你为什么怀疑我？

**令人震惊的事实**

没有办法区分原始文件和硬链接。例如，如果给你两个文件，其中一个恰好是另一个文件的硬链接，那么没有办法知道哪个文件是原始文件！这就像鸡和蛋的困境；没有人知道哪个先出现！

# 知识检测

对于以下练习，打开你的终端并尝试解决以下任务：

1.  显示`/var/log`目录的 inode 编号。

1.  显示`/boot`目录的硬链接数。

1.  在你的主目录中创建一个名为`coins`的新目录。

1.  创建一个指向`coins`的软链接，名为`currency`。

1.  在`coins`目录中，创建两个文件——`silver`和`gold`。

1.  在`currency`目录中创建一个新文件`bronze`。

1.  列出`coins`和`currency`两个目录的内容。

1.  在你的主目录中创建一个包含“咖啡很棒”的新文件`beverages`，并创建一个名为`drinks`的硬链接指向`beverages`。

1.  在`drinks`文件中添加一行“柠檬很清爽”，然后删除`beverages`文件。

1.  显示你的`drinks`文件的内容。

## 真或假

1.  **文件名**是 inode 数据结构的一部分。

1.  **文件大小**是 inode 数据结构的一部分。

1.  你可以创建指向目录的软链接。

1.  你可以创建指向目录的硬链接。

1.  目录的最小硬链接数为`2`。

1.  软链接与原始文件具有相同的 inode 编号。

1.  硬链接与原始文件具有相同的 inode 编号。


谁是 root？

到目前为止，用户`elliot`已经能够在系统上做了很多事情。但是，有很多事情用户`elliot`无法做！为了演示，让我们尝试在`/var`目录中创建一个名为`happy`的文件：

```
elliot@ubuntu-linux:~$ touch /var/happy
touch: cannot touch '/var/happy': Permission denied
```

哎呀！我们得到了`Permission denied`错误。

现在让我们尝试在`/etc`中创建名为`games`的新目录：

```
elliot@ubuntu-linux:/$ mkdir /etc/games
mkdir: cannot create directory ‘/etc/games': Permission denied
```

再次！我们得到了相同的错误，`Permission denied`！

这里发生了什么？嗯，用户`elliot`没有权限在系统上做任何他想做的事情！那么谁？谁有权限在系统上做任何事情？是 root 用户。

**谁是 root？**

`root`是具有在系统上执行任何操作权限的 Linux 用户。`root`也被称为超级用户。

# 第八章：访问 root 用户

您可以运行`sudo -i`命令首次访问系统上的`root`用户：

```
elliot@ubuntu-linux:~$ sudo -i
[sudo] password for elliot:
root@ubuntu-linux:~#
```

您将被提示输入密码，然后突然之间，您拥有了超级权限！

注意命令提示符的变化，而不是美元符号（`$`），它现在显示`#`来欢迎 root 用户。

让我们运行`whoami`命令，确保我们现在已登录为 root 用户：

```
root@ubuntu-linux:~# whoami 
root
```

太棒了！现在让我们显示当前工作目录：

```
root@ubuntu-linux:~# pwd
/root
```

记得之前我告诉过你，`root`用户的主目录是`/root`而不是在`/home`下。

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/lrn-linux-qk/img/f5edc3f1-29b6-486b-b355-08e82f6ca86d.png)

图 1：/root 是 root 用户的主目录

现在让我们重新运行我们两次被拒绝的命令，但这次，我们以`root`用户身份运行两个命令。

```
root@ubuntu-linux:~# touch /var/happy 
root@ubuntu-linux:~# ls -l /var/happy
-rw-r--r-- 1 root root 0 Apr 15 10:53 /var/happy
```

正如您所看到的，没有什么可以阻止`root`用户做任何事情！现在让我们在`/etc`中创建目录`games`：

```
root@ubuntu-linux:~# mkdir /etc/games 
root@ubuntu-linux:~# ls -ld /etc/games
drwxr-xr-x 2 root root 4096 Apr 15 10:55 /etc/games
```

我们没有错误，这是因为您作为`root`用户有权进行任何操作。但是请永远记住，伴随着强大的力量而来的是巨大的责任。

# 设置 root 密码

您还可以使用`su`命令切换到`root`用户，但首先，您需要设置`root`的密码：

```
root@ubuntu-linux:~# passwd 
Enter new UNIX password:
Retype new UNIX password:
passwd: password updated successfully
```

太棒了，现在退出`root`用户：

```
root@ubuntu-linux:~# exit 
logout
elliot@ubuntu-linux:~$ whoami 
elliot
```

现在您可以使用`su root`命令切换到`root`用户：

```
elliot@ubuntu-linux:~$ su root 
Password:
root@ubuntu-linux:/home/elliot# whoami 
root
```

# 破折号的区别

请注意，我的当前工作目录现在是`/home/elliot`而不是`/root`。如果我想更改，我可以退出到用户`elliot`，然后重新运行`su`命令，但这次，在用户名之前加上破折号（连字符）。

```
root@ubuntu-linux:/home/elliot# exit 
exit
elliot@ubuntu-linux:~$ su - root 
Password:
root@ubuntu-linux:~# pwd
/root
```

那么有什么区别吗？

这是交易。当您在用户名之前不添加破折号时，shell 会保留当前用户的 shell 环境设置，其中包括当前工作目录。另一方面，当您添加破折号时，shell 会获取新用户（您切换到的用户）的环境设置。

所以让我们练习一下。如果您想切换到用户`elliot`但保留`root`的 shell 环境设置，则不需要破折号：

```
root@ubuntu-linux:~# pwd
/root
root@ubuntu-linux:~# su elliot 
elliot@ubuntu-linux:/root$ pwd
/root
elliot@ubuntu-linux:/root$
```

注意当我切换到用户`elliot`时，当前工作目录没有更改。现在，让我们退出并再次切换到用户`elliot`，但这次，在用户名之前加上破折号：

```
elliot@ubuntu-linux:/root$ exit 
exit
root@ubuntu-linux:~# pwd
/root
root@ubuntu-linux:~# su - elliot 
elliot@ubuntu-linux:~$ pwd
/home/elliot
```

现在注意当前工作目录如何从`/root`更改为`/home/elliot`。因此，在这里，shell 获取了用户`elliot`的环境设置。

**一个很酷的提示**

如果您运行`su`而不指定用户名，则`su`将切换到 root 用户。因此，如果您想节省一些输入，每次想切换到 root 用户时都可以省略用户名。

让我们尝试一下我们很酷的提示！作为用户`elliot`，运行`su`命令而不指定用户名：

```
elliot@ubuntu-linux:~$ su 
Password:
root@ubuntu-linux:/home/elliot#
```

然后，您可以输入`root`密码以登录为`root`。

您还可以使用破折号获取`root`的 shell 环境设置：

```
elliot@ubuntu-linux:~$ su - 
Password:
root@ubuntu-linux:~# pwd
/root
```

这次我降落在`/root`，因为我使用了破折号。

嗯，这是一个简短的章节，但`root`用户肯定值得有一个专门的部分。还要记住，当你是`root`用户时，你拥有超级权限，可以在系统上做任何事情。所以如果你不非常小心，你可能会损坏你的系统，这就是为什么有一个非常著名的 Linux 迷因说，“不要喝酒然后使用 root！”

# 知识检查

对于以下练习，打开你的终端并尝试解决以下任务：

1.  切换到`root`用户。

1.  更改`root`用户的密码。

1.  切换到用户`elliot`并登陆到`/home/elliot`。

1.  现在切换到 root 用户，但保留当前工作目录`/home/elliot`。

## 真或假

1.  `root`用户是 Linux 中最强大的用户。

1.  使用`su`命令而不指定用户名将切换到 root 用户。

1.  我们使用`passroot`命令来更改`root`用户的密码。


控制人口

Linux 是一个多用户操作系统，这意味着许多用户可以同时访问系统。在现实生活中，你几乎不会找到只有一个用户的 Linux 服务器。相反，你会在一个服务器上看到很多用户。所以让我们真实地为我们的系统添加各种用户和组。在本章中，您将学习如何向 Linux 系统添加用户和组。您还将学习如何以各种方式管理用户和组帐户。此外，您还将学习如何管理 Linux 文件权限。

# 第九章：/etc/passwd 文件

在 Linux 中，用户信息存储在`/etc/passwd`文件中。`/etc/passwd`中的每一行都对应于一个用户。当您首次打开`/etc/passwd`时，您会看到很多用户，然后您会想，*这些用户都是从哪里来的？*答案很简单：这些用户中的大多数是服务用户，它们由您的系统用于启动各种应用程序和服务。然而，本章的主要重点将是系统用户；这些是像您和我一样的真正的人！

`/etc/passwd`中的每一行都由 7 个字段组成，每个字段用冒号分隔，每个字段代表一个用户属性。例如，用户`elliot`的条目看起来可能是这样的：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/lrn-linux-qk/img/88acbe14-424a-4da1-90fc-6ea1e8522129.png)

图 1：/etc/passwd 中的 7 个字段

以下表格详细说明了`/etc/passwd`中的这七个字段，并解释了每一个：

| **字段** | **它存储什么？** |
| --- | --- |
| 1 | 这个字段存储用户名。 |
| 2 | 这个字段通常有一个`X`，这意味着用户的密码已加密并存储在文件`/etc/shadow`中。 |
| 3 | 这个字段存储**UID**（**用户 ID**）号码。 |
| 4 | 这个字段存储用户的主要**GID**（**组 ID**）。 |
| 5 | 这个字段存储用户的注释，通常是用户的名字和姓氏。 |
| 6 | 这个字段存储用户的主目录路径。 |
| 7 | 这个字段存储用户的默认 shell。 |

表 10：理解/etc/passwd

# 添加用户

在您可以在系统上添加用户之前，您必须成为`root`：

```
elliot@ubuntu-linux:~$ su - 
Password:
root@ubuntu-linux:~#
```

现在，我们准备好添加用户了。我们都喜欢汤姆和杰瑞，所以让我们从添加用户`tom`开始。为此，您需要运行命令`useradd -m tom`：

```
root@ubuntu-linux:~# useradd -m tom
```

就像这样，用户`tom`现在已经添加到我们的系统中。您还会看到在`/etc/passwd`文件的末尾添加了一个新行，用于新用户`tom`；让我们用可爱的`tail`命令查看一下：

```
root@ubuntu-linux:~# tail -n 1 /etc/passwd 
tom:x:1007:1007::/home/tom:/bin/sh
```

我们使用`useradd`命令的`-m`选项来确保为用户`tom`创建一个新的主目录。所以让我们尝试切换到`/home/tom`目录，以确保它确实已经创建：

```
root@ubuntu-linux:~# cd /home/tom 
root@ubuntu-linux:/home/tom# pwd
/home/tom
```

太棒了！我们验证了`/home/tom`已经创建。

在创建新用户后，您可能想要做的第一件事是设置用户的密码。您可以通过运行命令`passwd tom`来设置`tom`的密码：

```
root@ubuntu-linux:~# passwd tom 
Enter new UNIX password:
Retype new UNIX password:
passwd: password updated successfully
```

现在，让我们创建用户`jerry`。但是这次，我们将为用户`jerry`选择以下属性：

| UID | `777` |
| --- | --- |
| 注释 | `Jerry the Mouse` |
| Shell | `/bin/bash` |

这很容易通过`useradd`命令来完成：

```
root@ubuntu-linux:~# useradd -m -u 777 -c "Jerry the Mouse" -s /bin/bash jerry
```

`-u`选项用于设置`jerry`的 UID。我们还使用了`-c`选项为用户`jerry`添加注释，最后我们使用了`-s`选项为`jerry`设置默认 shell。

现在，让我们查看`/etc/passwd`文件的最后两行，进行一些比较：

```
root@ubuntu-linux:~# tail -n 2 /etc/passwd 
tom:x:1007:1007::/home/tom:/bin/sh 
jerry:x:777:1008:Jerry the Mouse:/home/jerry:/bin/bash
```

请注意，用户`tom`的注释字段为空，因为我们在创建用户`tom`时没有添加任何注释，还要注意用户`tom`的 UID 是由系统选择的，但我们为用户`jerry`选择了`777`。另外，注意用户`tom`的默认 shell 是由系统选择的`/bin/sh`，这是`/bin/bash`的旧版本。然而，我们为用户`jerry`选择了更新的 shell`/bin/bash`。

现在，让我们为用户`jerry`设置密码：

```
root@ubuntu-linux:~# passwd jerry 
Enter new UNIX password:
Retype new UNIX password:
passwd: password updated successfully
```

太棒了！我们现在已经创建了两个用户：`tom`和`jerry`。现在，让我们切换到用户`tom`：

```
root@ubuntu-linux:~# su - tom
$ whoami tom
$ pwd
/home/tom
$
```

我们成功切换到了用户`tom`，但是你可以看到，shell 看起来很不一样，因为命令提示符不显示用户名或主机名。这是因为用户`tom`的默认 shell 是`/bin/sh`。你可以使用`echo $SHELL`命令来显示用户的默认 shell：

```
$ echo $SHELL
/bin/sh
```

如你所见，它显示了`/bin/sh`。现在，让我们退出并切换到用户`jerry`：

```
$ exit
root@ubuntu-linux:~# su - jerry 
jerry@ubuntu-linux:~$ whoami 
jerry
jerry@ubuntu-linux:~$ echo $SHELL
/bin/bash
```

一切看起来都更好了，因为我们确实将他的默认 shell 设置为`/bin/bash`。好了，现在让我们切换回`root`用户：

```
jerry@ubuntu-linux:~$ exit 
logout
root@ubuntu-linux:~#
```

# 修改用户属性

所以我们不满意用户`tom`的默认 shell 是`/bin/sh`，我们想把它改成`/bin/bash`。我们可以使用`usermod`命令来修改用户属性。

例如，要将用户`tom`的默认 shell 更改为`/bin/bash`，你可以运行命令`usermod -s /bin/bash tom`：

```
root@ubuntu-linux:~# usermod -s /bin/bash tom
```

请注意，你也可以使用命令选项的全名；所以你可以使用`--shell`代替`-s`。无论如何，让我们看看我们是否成功地更改了用户`tom`的默认 shell：

```
root@ubuntu-linux:~# su - tom 
tom@ubuntu-linux:~$ whoami 
tom
tom@ubuntu-linux:~$ echo $SHELL
/bin/bash
```

太棒了！我们成功了。你也可以通过运行命令`usermod -u 444 tom`将`tom`的 UID 更改为`444`：

```
root@ubuntu-linux:~# usermod -u 444 tom
```

我们确实可以通过查看`/etc/passwd`文件来检查`tom`的 UID 是否已更改：

```
root@ubuntu-linux:~# tail -n 2 /etc/passwd 
tom:x:444:1007::/home/tom:/bin/bash 
jerry:x:777:1008:Jerry the Mouse:/home/jerry:/bin/bash
```

我们甚至可以修改用户`tom`的注释字段。现在，它是空的，但你可以通过运行命令将用户`tom`的注释字段设置为`"Tom the Cat"`：

```
root@ubuntu-linux:~# usermod --comment "Tom the Cat" tom
```

而且，我们可以通过查看`/etc/passwd`文件来验证评论是否已更改：

```
root@ubuntu-linux:~# tail -n 2 /etc/passwd 
tom:x:444:1007:Tom the Cat:/home/tom:/bin/bash 
jerry:x:777:1008:Jerry the Mouse:/home/jerry:/bin/bash
```

# 定义骨架

如果你列出`/home/jerry`和`/home/tom`的内容，你会发现它们是空的：

```
root@ubuntu-linux:~# ls -l /home/tom 
total 0
root@ubuntu-linux:~# ls -l /home/jerry 
total 0
```

`/home/jerry`和`/home/tom`都是空的原因是骨架文件`/etc/skel`也是空的：

```
root@ubuntu-linux:~# ls -l /etc/skel 
total 0
```

**/etc/skel 是什么？**

这是骨架文件。在`/etc/skel`中创建的任何文件或目录都将被复制到任何新创建的用户的主目录中。

现在，用你最喜欢的文本编辑器，在`/etc/skel`中创建文件`welcome.txt`，并在其中插入一行`"Hello Friend!"`：

```
root@ubuntu-linux:/etc/skel# ls 
welcome.txt
root@ubuntu-linux:/etc/skel# cat welcome.txt 
Hello Friend!
```

好了，现在你已经在`/etc/skel`中创建了文件`welcome.txt`，这意味着任何新创建的用户现在都会在他们的主目录中有文件`welcome.txt`。为了演示，让我们创建一个名为`edward`的新用户，然后我们将看一下他的主目录：

```
root@ubuntu-linux:~# useradd -m -c "Edward Snowden" -s /bin/bash edward
```

现在，让我们为用户`edward`设置密码：

```
root@ubuntu-linux:~# passwd edward 
Enter new UNIX password:
Retype new UNIX password:
passwd: password updated successfully
```

现在，关键时刻到了！让我们切换到用户`edward`，并列出他的主目录的内容：

```
root@ubuntu-linux:~# su - edward 
edward@ubuntu-linux:~$ ls 
welcome.txt
edward@ubuntu-linux:~$ cat welcome.txt 
Hello Friend!
```

你可以看到文件`welcome.txt`被复制到了`edward`的主目录。系统中创建的每个新用户现在都将有一个很酷的问候消息！请注意，像`tom`和`jerry`这样的旧用户不会在他们的主目录中有文件`welcome.txt`，因为它们是在我们在`/etc/skel`中添加文件`welcome.txt`之前创建的。

# 更改默认值

我们已经厌倦了每次创建新用户时都要指定默认 shell。但幸运的是，有一个文件可以指定为任何新创建的用户设置默认 shell。这个神奇的文件是`/etc/default/useradd`。

打开文件`/etc/default/useradd`，查找以下行：

```
SHELL=/bin/sh
```

将其更改为：

```
SHELL=/bin/bash
```

太棒了！现在，任何新创建的用户都将以`/bin/bash`作为默认 shell。让我们通过创建一个名为`spy`的新用户来测试一下：

```
root@ubuntu-linux:~# useradd -m spy
```

现在，为用户`spy`设置密码：

```
root@ubuntu-linux:~# passwd spy 
Enter new UNIX password:
Retype new UNIX password:
passwd: password updated successfully
```

最后，让我们切换到用户`spy`并检查默认 shell：

```
root@ubuntu-linux:~# su - spy 
spy@ubuntu-linux:~$ echo $SHELL
/bin/bash
spy@ubuntu-linux:~$ exit 
logout
root@ubuntu-linux:~#
```

万岁！我们可以看到`bash`是用户`spy`的默认 shell。

请记住，`/bin/sh`和`/bin/bash`不是你系统上唯一两个有效的 shell；还有更多！查看文件`/etc/shells`，以查看系统上所有有效 shell 的完整列表：

```
root@ubuntu-linux:~# cat /etc/shells 
# /etc/shells: valid login shells
/bin/sh
/bin/bash
/bin/rbash
/bin/dash
```

你可以在`/etc/default/useradd`中更改其他用户默认值，包括：

+   默认的`home`目录（`HOME=/home`）

+   默认的`skel`目录（`SKEL=/etc/skel`）

我会把这个留给你作为练习。

# 删除用户

有时，不再需要用户在系统上，例如，离开公司的员工或只需要临时访问服务器的用户。无论哪种情况，您都需要知道如何删除用户。

我们创建的最后一个用户是`spy`，对吧？好吧，我们的系统上不需要间谍，所以让我们删除用户`spy`；您可以通过运行命令`userdel spy`来删除用户`spy`：

```
root@ubuntu-linux:~# userdel spy
```

就像那样，用户`spy`被删除了。但是，`spy`的主目录仍然存在：

```
root@ubuntu-linux:~# ls -ld /home/spy
drwxr-xr-x 2 1008 1010 4096 Apr 17 10:24 /home/spy
```

我们将不得不手动删除它：

```
root@ubuntu-linux:~# rm -r /home/spy
```

但这很不方便。想象一下，每次删除一个用户后，您都必须手动删除他们的主目录。幸运的是，有一个更好的解决方案；您可以使用`-r`选项自动删除用户的主目录。

让我们尝试一下用户`edward`：

```
root@ubuntu-linux:~# userdel -r edward
```

现在，让我们来检查一下用户`edward`的主目录是否仍然存在：

```
root@ubuntu-linux:~# ls -ld /home/edward
ls: cannot access '/home/edward': No such file or directory
```

正如您所看到的，`edward`的主目录已被删除。

# /etc/group 文件

在学校，孩子们通常被分成不同的小组。例如，喜欢跳舞的孩子将成为舞蹈组的一部分。书呆子孩子将组成科学组。如果你想知道，我曾经是体育组的一部分，因为我跑得相当快！

在 Linux 中，具有相似特征的用户被放置在同一组中，这与我们有相同的概念。

什么是组？

组是共享相同角色或目的的用户集合。

所有组的信息都存储在文件`/etc/group`中。就像`/etc/passwd`文件一样，`/etc/group`中的每一行都对应于一个组，每一行都由`4`个字段组成。例如，Linux 中最著名的组之一是`sudo`组：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/lrn-linux-qk/img/93e2c12d-c25a-4a51-a415-bc252f582ca1.png)

图 2：/etc/group 中的 4 个字段

以下表格详细说明了`/etc/group`中的这四个字段，并解释了每一个：

| **字段** | **它存储什么？** |
| --- | --- |
| 1 | 此字段存储组名。 |
| 2 | 此字段通常包含`X`，这意味着组密码已加密并存储在文件`/etc/gshadow`中。 |
| 3 | 此字段存储**GID**（**组 ID**）号码。 |
| 4 | 此字段存储组成员的用户名。 |

表 11：理解/etc/group

# 添加组

让我们创建一个名为`cartoon`的组。为此，您需要运行命令`groupadd cartoon`：

```
root@ubuntu-linux:~# groupadd cartoon
```

请注意，将添加包含组信息的新行到文件`/etc/group`的末尾：

```
root@ubuntu-linux:~# tail -n 1 /etc/group 
cartoon:x:1009:
```

请注意，组`cartoon`目前没有成员，这就是为什么第四个字段目前为空的原因。

让我们创建另一个名为`developers`的组，但这次，我们将指定`888`的 GID：

```
root@ubuntu-linux:~# groupadd --gid 888 developers
```

让我们检查`/etc/group`中的`developers`组条目：

```
root@ubuntu-linux:~# tail -n 1 /etc/group 
developers:x:888:
```

而且它看起来就像我们期望的那样。很酷！

# 添加组成员

用户`tom`和`jerry`都是卡通人物，因此将它们都添加到`cartoon`组是有意义的。

要将`tom`添加到`cartoon`组，只需运行命令`usermod -aG cartoon tom`：

```
root@ubuntu-linux:~# usermod -aG cartoon tom
```

同样，您可以将`jerry`添加到`cartoon`组中：

```
root@ubuntu-linux:~# usermod -aG cartoon jerry
```

现在，让我们来看看`/etc/group`文件：

```
root@ubuntu-linux:~# tail -n 2 /etc/group 
cartoon:x:1009:tom,jerry 
developers:x:888:
```

正如您所看到的，`tom`和`jerry`现在都列为`cartoon`组的成员。

您可以使用`id`命令查看系统上任何用户的组成员资格。例如，如果您想要检查`tom`属于哪些组，可以运行命令`id tom`：

```
root@ubuntu-linux:~# id tom
uid=444(tom) gid=1007(tom) groups=1007(tom),1009(cartoon)
```

让我们通过创建三个新用户`sara`，`peter`和`rachel`来进行更多练习：

```
root@ubuntu-linux:~# useradd -m sara 
root@ubuntu-linux:~# useradd -m peter 
root@ubuntu-linux:~# useradd -m rachel
```

并记得为每个用户设置密码：

```
root@ubuntu-linux:~# passwd sara 
Enter new UNIX password:
Retype new UNIX password:
passwd: password updated successfully 
root@ubuntu-linux:~# passwd peter 
Enter new UNIX password:
Retype new UNIX password:
passwd: password updated successfully 
root@ubuntu-linux:~# passwd rachel 
Enter new UNIX password:
Retype new UNIX password:
passwd: password updated successfully 
root@ubuntu-linux:~#
```

现在想象一下，如果所有三个新用户都是软件开发人员；这意味着他们有相同的角色，因此他们应该是同一组的成员。因此，让我们将所有三个用户添加到`developers`组中：

```
root@ubuntu-linux:~# usermod -aG developers sara 
root@ubuntu-linux:~# usermod -aG developers peter 
root@ubuntu-linux:~# usermod -aG developers rachel
```

现在，让我们来看看`/etc/group`文件：

```
root@ubuntu-linux:~# tail -n 5 /etc/group 
cartoon:x:1009:tom,jerry 
developers:x:888:sara,peter,rachel 
sara:x:1001:
peter:x:1002: 
rachel:x:1003:
```

我们可以看到`developers`组现在有三个成员-`sara`，`peter`和`rachel`。但是有一些奇怪的地方！看起来当我们创建用户`sara`，`peter`和`rachel`时，它也创建了它们作为组！但是为什么会发生这种情况呢？好吧，让我在下一节中向您解释。

# 主要与次要组

Linux 中的每个用户必须是主要组的成员。主要组有时也被称为登录组。默认情况下，每当创建新用户时，也会创建一个与用户名称相同的组，并且该组将成为新用户的主要组。

另一方面，用户可能是或不是次要组的成员。次要组有时也被称为附加组。您可以将次要组视为用户除了用户的主要组之外的任何组的成员。

如果您还不理解主要和次要组的概念，不要担心；到本章结束时，它将变得非常清晰。

让我们创建一个名为`dummy`的新用户：

```
root@ubuntu-linux:~# useradd -m dummy
```

现在，如果您查看`/etc/group`文件的最后一行，您将看到一个名为`dummy`的组也被创建：

```
root@ubuntu-linux:~# tail -n 1 /etc/group 
dummy:x:1004:
```

这个`dummy`组是用户`dummy`的主要组；如果您对用户`dummy`运行`id`命令：

```
root@ubuntu-linux:~# id dummy
uid=1004(dummy) gid=1004(dummy) groups=1004(dummy)
```

您将看到用户`dummy`确实是`dummy`组的成员。现在，让我们将用户`dummy`添加到`cartoon`组：

```
root@ubuntu-linux:~# usermod -aG cartoon dummy
```

让我们再次对用户`dummy`运行`id`命令：

```
root@ubuntu-linux:~# id dummy
uid=1004(dummy) gid=1004(dummy) groups=1004(dummy),1009(cartoon)
```

您可以看到用户`dummy`是两个组`dummy`和`cartoon`的成员。但是，`dummy`是主要组，`cartoon`是次要组。

主要组始终在`id`命令的输出中以`gid=`开头：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/lrn-linux-qk/img/1bd2ceec-8da8-4c6f-a814-bfafe9f97945.png)

图 3：主要与次要组

现在让我们将用户`dummy`添加到`developers`组：

```
root@ubuntu-linux:~# usermod -aG developers dummy
```

接下来，再次对用户`dummy`运行`id`命令：

```
root@ubuntu-linux:~# id dummy
uid=1004(dummy) gid=1004(dummy) groups=1004(dummy),1009(cartoon),888(developers)
```

如您所见，用户`dummy`是两个次要组`cartoon`和`developers`的成员。

好了！够了这些虚拟的东西。让我们删除用户`dummy`：

```
root@ubuntu-linux:~# userdel -r dummy
```

每个用户必须是唯一主要组的成员；但是，对主要组的选择没有限制！

为了演示，让我们创建一个名为`smurf`的用户，`cartoon`是用户`smurf`的主要组。这可以通过使用`useradd`命令的`--gid`选项轻松完成：

```
root@ubuntu-linux:~# useradd -m --gid cartoon smurf
```

现在，看一下`/etc/group`文件：

```
root@ubuntu-linux:~# tail -n 1 /etc/group 
rachel:x:1003:
```

您将看到没有使用名称`smurf`创建的组。太神奇了！那是因为我们已经为用户`smurf`指定了另一个主要组。

现在让我们检查用户`smurf`的组成员资格：

```
root@ubuntu-linux:~# id smurf
uid=1004(smurf) gid=1009(cartoon) groups=1009(cartoon)
```

如您所见，`smurf`只是`cartoon`组的成员，这当然也是他的主要组。

您还可以更改现有用户的主要组。例如，您可以将`developers`组设置为用户`smurf`的主要组，如下所示：

```
root@ubuntu-linux:~# usermod -g developers smurf 
root@ubuntu-linux:~# id smurf
uid=1004(smurf) gid=888(developers) groups=888(developers)
```

# 删除组

如果不再需要组，可以删除组。为了演示，让我们创建一个名为`temp`的组：

```
root@ubuntu-linux:~# groupadd temp
```

现在，您可以使用`groupdel`命令删除`temp`组：

```
root@ubuntu-linux:~# groupdel temp
```

现在，让我们尝试删除`temp`组：

```
root@ubuntu-linux:~# groupdel sara
groupdel: cannot remove the primary group of user 'sara'
```

我们收到错误消息，因为我们不允许删除现有用户的主要组。

# 文件所有权和权限

Linux 中的每个文件都由特定的用户和特定的组拥有。为了演示，让我们切换到用户`smurf`，并在`smurf`的主目录中创建一个名为`mysmurf`的文件：

```
root@ubuntu-linux:~# su - smurf 
smurf@ubuntu-linux:~$ touch mysmurf
```

现在对文件`mysmurf`进行长列表：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/lrn-linux-qk/img/61c1ebc2-7c65-47fc-aae3-f6775ddc3448.png)

图 4：用户和组所有者

您将在输出的第三列中看到拥有文件的用户（用户所有者）的名称，默认情况下是创建文件的用户。

在输出的第四列中，您将看到文件的组（组所有者）的名称，默认情况下是用户所有者的主要组。

`developers`组是用户`smurf`的主要组，因此`developers`成为文件`mysmurf`的组所有者。

如果您在`elliot`的主目录中的`sports`目录上进行长列表：

```
smurf@ubuntu-linux:~$ ls -ld /home/elliot/sports
drwxr-xr-x 2 elliot elliot 4096 Oct 22 12:56 /home/elliot/sports
```

您将看到用户`elliot`是用户所有者，组`elliot`是组所有者；这是因为组`elliot`是用户`elliot`的主要组。

# 更改文件所有权

您可以使用`chown`命令更改文件的所有权。一般来说，`chown`命令的语法如下：

```
chown  user:group file
```

例如，您可以更改文件`mysmurf`的所有权，使用户`elliot`成为所有者，组`cartoon`成为组所有者，如下所示：

```
smurf@ubuntu-linux:~$
smurf@ubuntu-linux:~$ chown elliot:cartoon mysmurf
chown: changing ownership of 'mysmurf': Operation not permitted
```

哦！只有`root`用户可以做到；让我们切换到`root`用户并再试一次：

```
smurf@ubuntu-linux:~$ su - 
Password:
root@ubuntu-linux:~# cd /home/smurf
root@ubuntu-linux:/home/smurf# chown elliot:cartoon mysmurf
```

成功！现在让我们查看文件`mysmurf`的所有权：

```
root@ubuntu-linux:/home/smurf# ls -l mysmurf
-rw-r--r-- 1 elliot cartoon 0 Oct 22 15:09 mysmurf
```

如您所见，我们已成功更改了`mysmurf`的所有权。此外，您还可以更改用户所有者，而不更改组所有者。例如，如果您希望用户`root`成为`mysmurf`的所有者，可以运行以下命令：

```
root@ubuntu-linux:/home/smurf# chown root mysmurf 
root@ubuntu-linux:/home/smurf# ls -l mysmurf
-rw-r--r-- 1 root cartoon 0 Oct 22 15:09 mysmurf
```

如您所见，只有用户所有者更改为`root`，但`cartoon`仍然是组所有者。

您还可以更改组所有者，而不更改用户所有者。例如，如果您希望组`developers`成为`mysmurf`的组所有者，则可以运行：

```
root@ubuntu-linux:/home/smurf# chown :developers mysmurf 
root@ubuntu-linux:/home/smurf# ls -l mysmurf
-rw-r--r-- 1 root developers 0 Oct 22 15:09 mysmurf
```

**供您参考**

`chgrp`也可以用于更改文件的组所有者。我会留给你作为练习！

# 理解文件权限

在 Linux 中，每个文件都为三个不同的实体分配了访问权限；这些实体是：

+   文件的用户所有者

+   文件的组所有者

+   其他所有人（也称为其他/全局）

我们已经熟悉了用户所有者和组所有者；其他所有人指的是系统上不是用户所有者也不是组所有者的任何用户。

您可以将这三个实体视为您、您的朋友和其他所有人。有一些事情你不愿意与任何人分享，其他一些事情你愿意与朋友分享，还有一些事情你可能愿意与所有人分享。

每个文件都有三种类型的访问权限：

+   读取

+   写

+   执行

每个这些访问权限的含义对文件和目录来说并不相同。以下图解释了文件与目录的访问权限之间的区别：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/lrn-linux-qk/img/ea2e97b3-f43d-49c3-9310-4346e1389bbf.png)

图 5：文件与目录权限

您可以通过进行长列表查看文件的权限。例如，要查看`mysmurf`文件上设置的当前权限，可以运行：

```
root@ubuntu-linux:~# ls -l /home/smurf/mysmurf
-rw-r--r-- 1 root developers 0 Oct 22 15:09 /home/smurf/mysmurf
```

现在注意输出的第一列，即`-rw-r--r--`。请注意，它由十个槽组成；第一个槽确定了文件的类型。剩下的九个槽分为三组，每组有三个槽，就像下图中的一样：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/lrn-linux-qk/img/82df07a6-cba1-4bb5-8bc7-e4e7a413aad4.png)

图 6：理解权限

注意第一个槽确定了文件类型；它可以是：

+   `-`表示常规文件

+   `d`表示目录

+   `l`表示软链接

+   `b`表示块设备

+   `c`表示字符设备

接下来的三个槽确定了文件所有者被授予的权限。这些槽中的第一个确定了读取权限；它可以是：

+   `r`表示读取权限

+   `-`表示无读取访问

这些槽中的第二个确定了写权限；它可以是：

+   `w`表示写访问

+   `-`表示无写访问

第三个槽确定了执行权限；它可以是：

+   `x`表示执行访问

+   `-`表示无执行访问

相同的逻辑也适用于接下来的三个槽，用于确定组所有者的权限，最后是最后三个槽，用于确定其他所有人的权限。

现在让我们动手做一些示例，以加强我们对文件权限的理解。让我们首先编辑`mysmurf`文件，并添加以下行`Smurfs are blue!`，使其看起来像这样：

```
root@ubuntu-linux:~# cat /home/smurf/mysmurf 
Smurfs are blue!
```

现在切换到用户`smurf`，并尝试读取文件`mysmurf`的内容：

```
root@ubuntu-linux:~# su - smurf 
smurf@ubuntu-linux:~$ cat mysmurf 
Smurfs are blue!
```

酷！用户`smurf`可以读取文件`mysmurf`的内容。请记住，用户`smurf`不是文件的所有者，但他是`developers`组的成员：

```
smurf@ubuntu-linux:~$ id smurf
uid=1004(smurf) gid=888(developers) groups=888(developers)
```

因此，`smurf`可以读取文件，因为`mysmurf`的组权限是`r--`。但是他能编辑文件吗？让我们看看如果用户`smurf`尝试向文件`mysmurf`添加一行`我是 smurf！`会发生什么：

```
smurf@ubuntu-linux:~$ echo "I am smurf!" >> mysmurf 
bash: mysmurf: Permission denied
```

权限被拒绝！是的，这是因为组所有者（或其他人）没有写权限。只有用户所有者对文件`mysmurf`有读和写权限，而在这种情况下所有者恰好是`root`。现在，如果我们改变文件所有权并使`smurf`成为文件`mysmurf`的所有者，那么他将能够编辑文件；所以让我们首先改变文件所有权：

```
smurf@ubuntu-linux:~$ su - 
Password:
root@ubuntu-linux:~# chown smurf /home/smurf/mysmurf 
root@ubuntu-linux:~# ls -l /home/smurf/mysmurf
-rw-r--r-- 1 smurf developers 17 Oct 23 11:06 /home/smurf/mysmurf
```

现在让我们切换回用户`smurf`，并尝试编辑文件`mysmurf`：

```
root@ubuntu-linux:~# su - smurf
smurf@ubuntu-linux:~$ echo "I am smurf!" >> mysmurf 
smurf@ubuntu-linux:~$ cat mysmurf
Smurfs are blue!
I am smurf!
```

酷！所以用户`smurf`成功编辑了文件。现在让我们切换到用户`elliot`，并尝试向`mysmurf`文件添加一行`我不是 smurf！`：

```
smurf@ubuntu-linux:~$ su - elliot 
Password:
elliot@ubuntu-linux:~$ cd /home/smurf/
elliot@ubuntu-linux:/home/smurf$ echo "I am not smurf!" >> mysmurf 
bash: mysmurf: Permission denied
```

权限被拒绝！请注意，`elliot`不是用户所有者，甚至不是`developers`组的成员，因此他被视为其他人。但是，他可以读取文件，因为其他人有读权限`r--`：

```
elliot@ubuntu-linux:/home/smurf$ cat mysmurf 
Smurfs are blue!
I am smurf!
```

# 更改文件权限

现在，如果我们想要给`elliot`权限来编辑文件`mysmurf`，而不像之前那样改变文件所有权呢？好吧！这很简单；您可以使用`chmod`命令来更改文件权限。

让我们首先切换到`root`用户：

```
elliot@ubuntu-linux:/home/smurf$ su - 
Password:
root@ubuntu-linux:~# cd /home/smurf 
root@ubuntu-linux:/home/smurf#
```

现在您可以通过运行以下命令为其他人（其他所有人）添加写权限：

```
root@ubuntu-linux:/home/smurf# chmod o+w mysmurf
```

这里`o+w`表示**其他人+写**，这意味着向其他人添加写权限。现在对`mysmurf`进行长列表：

```
root@ubuntu-linux:/home/smurf# ls -l mysmurf
-rw-r--rw- 1 smurf developers 29 Oct 23 11:34 mysmurf
```

如您所见，其他人现在可以读取和写入`mysmurf`文件的`rw-`。现在，切换回用户`elliot`，并尝试再次添加一行`我不是 smurf！`：

```
root@ubuntu-linux:/home/smurf# su elliot
elliot@ubuntu-linux:/home/smurf$ echo "I am not smurf!" >> mysmurf 
elliot@ubuntu-linux:/home/smurf$ cat mysmurf
Smurfs are blue!
I am smurf!
I am not smurf!
```

成功！用户`elliot`可以编辑文件`mysmurf`。现在是时候讨论执行权限了；让我们转到`elliot`的主目录，并创建一个名为`mydate.sh`的文件：

```
elliot@ubuntu-linux:/home/smurf$ cd /home/elliot 
elliot@ubuntu-linux:~$ touch mydate.sh
```

现在向文件`mydate.sh`添加以下两行：

```
#!/bin/bash 
date
```

您可以通过运行以下两个`echo`命令添加这两行：

```
elliot@ubuntu-linux:~$ echo '#!/bin/bash' >> mydate.sh 
elliot@ubuntu-linux:~$ echo date >> mydate.sh
```

现在不要担心`#/bin/bash`行的含义；我会在以后的章节中解释。无论如何，让我们查看文件`mydate.sh`的内容：

```
elliot@ubuntu-linux:~$ cat mydate.sh 
#!/bin/bash
date
```

现在对文件`mydate.sh`进行长列表：

```
elliot@ubuntu-linux:~$ ls -l mydate.sh
-rw-rw-r-- 1 elliot elliot 17 Oct 23 12:28 mydate.sh
```

请注意，这里每个人（用户所有者、组所有者和其他人）都没有执行权限。让我们为每个人添加执行权限；您可以通过运行以下命令来实现：

```
elliot@ubuntu-linux:~$ chmod a+x mydate.sh 
elliot@ubuntu-linux:~$ ls -l mydate.sh
-rwxrwxr-x 1 elliot elliot 17 Oct 23 12:28 mydate.sh
```

这里`a+x`表示**所有+执行**，这意味着向每个人添加执行权限。还要注意，我们之所以能够作为用户`elliot`运行`chmod`命令，是因为他是文件`mydate.sh`的所有者。

最后，只需输入`mydate.sh`的完整路径，然后按*Enter*：

```
elliot@ubuntu-linux:~$ /home/elliot/mydate.sh 
Wed Oct 23 12:38:51 CST 2019
```

哇！当前日期显示出来了！您已经创建了您的第一个 Bash 脚本并运行了它！Bash 脚本将在以后的章节中详细介绍。但是现在至少您知道文件可执行是什么意思。现在通过运行以下命令删除执行权限：

```
elliot@ubuntu-linux:~$ chmod a-x mydate.sh 
elliot@ubuntu-linux:~$ ls -l mydate.sh
-rw-rw-r-- 1 elliot elliot 17 Oct 23 12:28 mydate.sh
```

这里`a-x`表示**所有-执行**，这意味着从每个人那里删除执行权限。现在尝试再次运行脚本：

```
elliot@ubuntu-linux:~$ /home/elliot/mydate.sh 
bash: /home/elliot/mydate.sh: Permission denied
```

我们收到了权限被拒绝的错误！这是因为文件`mydate.sh`不再可执行。大多数 Linux 命令都是可执行文件。例如，看一下`date`命令。首先，我们运行`which`命令以获取`date`命令的位置：

```
elliot@ubuntu-linux:~$ which date
/bin/date
```

现在对`/bin/date`进行长列表：

```
elliot@ubuntu-linux:~$ ls -l /bin/date
-rwxr-xr-x 1 root root 100568 Jan 18 2018 /bin/date
```

如您所见，每个人都有执行权限。现在看看当您删除执行权限时会发生什么：

```
elliot@ubuntu-linux:~$ su - 
Password:
root@ubuntu-linux:~# chmod a-x /bin/date
```

现在尝试运行`date`命令：

```
root@ubuntu-linux:~# date
-su: /bin/date: Permission denied
```

`date`命令不再起作用！请让我们通过重新添加执行权限来修复：

```
root@ubuntu-linux:~# chmod a+x /bin/date 
root@ubuntu-linux:~# date
Wed Oct 23 12:56:15 CST 2019
```

现在让我们删除文件`mysmurf`的用户所有者读取权限：

```
root@ubuntu-linux:~# cd /home/smurf/ 
root@ubuntu-linux:/home/smurf# chmod u-r mysmurf 
root@ubuntu-linux:/home/smurf# ls -l mysmurf
--w-r--rw- 1 smurf developers 45 Oct 23 12:02 mysmurf
```

这里的`u-r`表示**用户读取**，意思是从用户所有者中删除读取权限。现在让我们切换到用户`smurf`，并尝试读取文件`mysmurf`：

```
root@ubuntu-linux:/home/smurf# su - smurf 
smurf@ubuntu-linux:~$ cat mysmurf
cat: mysmurf: Permission denied
```

可怜的`smurf`。他甚至不能读取自己的文件。但由于他是文件所有者，他可以恢复读取权限：

```
smurf@ubuntu-linux:~$ chmod u+r mysmurf 
smurf@ubuntu-linux:~$ cat mysmurf Smurfs are blue!
I am smurf!
I am not smurf!
```

您已经看到如何使用`chmod`命令添加（`+`）和删除（`-`）权限。您还可以使用等号`=`来设置权限。例如，如果您希望文件`mysmurf`的组所有者（`developers`）只有写入权限，您可以运行以下命令：

```
smurf@ubuntu-linux:~$ chmod g=w mysmurf 
smurf@ubuntu-linux:~$ ls -l mysmurf
-rw--w-rw- 1 smurf developers 45 Oct 23 12:02 mysmurf
```

所以现在，`developers`组成员只对文件`mysmurf`有写入权限`-w-`。以下是更多示例：

+   `chmod ug=rwx mysmurf`：这将给用户所有者和组所有者完全权限。

+   `chmod o-rw mysmurf`：这将从其他用户中删除读取和写入权限。

+   `chmod a= mysmurf`：这将为每个人提供零（无）权限。

+   `chmod go= mysmurf`：这将给组所有者和其他用户零权限。

+   `chmod u+rx mysmurf`：这将为用户所有者添加读取和执行权限。

让我们给每个人零权限：

```
smurf@ubuntu-linux:~$ chmod a= mysmurf 
smurf@ubuntu-linux:~$ ls -l mysmurf
---------- 1 smurf developers 45 Oct 23 12:02 mysmurf
```

所以现在用户`smurf`无法读取，写入或执行文件：

```
smurf@ubuntu-linux:~$ cat mysmurf 
cat: mysmurf: Permission denied
smurf@ubuntu-linux:~$ echo "Hello" >> mysmurf
-su: mysmurf: Permission denied
```

`root`用户呢？好吧，让我们切换到`root`来找出：

```
smurf@ubuntu-linux:~$ su - 
Password:
root@ubuntu-linux:~# cd /home/smurf/ 
root@ubuntu-linux:/home/smurf# cat mysmurf 
Smurfs are blue!
I am smurf!
I am not smurf!
root@ubuntu-linux:/home/smurf# echo "I got super powers" >> mysmurf 
root@ubuntu-linux:/home/smurf# cat mysmurf
Smurfs are blue!
I am smurf!
I am not smurf!
I got super powers
root@ubuntu-linux:/home/smurf# ls -l mysmurf
---------- 1 smurf developers 64 Oct 23 13:38 mysmurf
```

正如你所看到的，`root`用户可以做任何事情！这是因为`root`可以绕过文件权限！换句话说，文件权限不适用于`root`用户。

# 目录权限

现在让我们看看读取，写入和执行权限在目录上是如何工作的。最简单的例子将是`root`的主目录`/root`。让我们在`/root`上进行长列表：

```
root@ubuntu-linux:~# ls -ld /root
drwx------ 5 root root 4096 Oct 22 14:28 /root
```

正如您所看到的，`root`所有者被授予完全权限，其他人被授予零权限。让我们在`/root`内创建一个名为`gold`的文件：

```
root@ubuntu-linux:~# touch /root/gold
```

现在让我们切换到用户`smurf`，并尝试列出`/root`目录的内容：

```
root@ubuntu-linux:~# su - smurf 
smurf@ubuntu-linux:~$ ls /root
ls: cannot open directory '/root': Permission denied
```

用户`smurf`收到了权限被拒绝的错误，因为他在目录`/root`上没有读取权限。现在，`smurf`能在`/root`内创建文件吗？

```
smurf@ubuntu-linux:~$ touch /root/silver
touch: cannot touch '/root/silver': Permission denied
```

他不能，因为他在`/root`上没有写入权限。他能删除`/root`内的文件吗？

```
smurf@ubuntu-linux:~$ rm /root/gold
rm: cannot remove '/root/gold': Permission denied
```

同样，没有写入权限，所以他无法在`/root`中删除文件。最后，用户`smurf`能否切换到`/root`目录？

```
smurf@ubuntu-linux:~$ cd /root
-su: cd: /root: Permission denied
```

他不能，因为`smurf`需要执行权限才能切换到`/root`目录。现在，让我们切换回`root`用户并开始添加一些权限：

```
smurf@ubuntu-linux:~$ exit 
logout
root@ubuntu-linux:~# chmod o+rx /root
```

在这里，我们为其他用户添加了读取和执行权限，所以用户`smurf`现在可以列出`/root`目录的内容：

```
root@ubuntu-linux:~# su - smurf 
smurf@ubuntu-linux:~$ ls /root 
gold
```

他甚至可以切换到`/root`目录，因为我们还添加了执行权限：

```
smurf@ubuntu-linux:~$ cd /root 
smurf@ubuntu-linux:/root$
```

但他仍然没有写入权限，所以他无法在`/root`中创建或删除文件：

```
smurf@ubuntu-linux:/root$ rm gold
rm: remove write-protected regular empty file 'gold'? y 
rm: cannot remove 'gold': Permission denied 
smurf@ubuntu-linux:/root$ touch silver
touch: cannot touch 'silver': Permission denied
```

让我们为其他用户添加写入权限：

```
smurf@ubuntu-linux:/root$ su - 
Password:
root@ubuntu-linux:~# chmod o+w /root
```

最后，切换到用户`smurf`并尝试在`/root`中创建或删除文件：

```
smurf@ubuntu-linux:~$ cd /root 
smurf@ubuntu-linux:/root$ rm gold
rm: remove write-protected regular empty file 'gold'? y 
smurf@ubuntu-linux:/root$ touch silver
smurf@ubuntu-linux:/root$ ls 
silver
```

所以`smurf`现在可以在`/root`中创建和删除文件，因为他有写入权限。

# 使用八进制表示法

您可以使用数字`4`，`2`和`1`来设置文件权限，而不是字母`r`，`w`和`x`。看一下下面的图片：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/lrn-linux-qk/img/781e3f37-978e-435b-b053-d927a1b3ac16.png)

图 7：理解八进制表示法

请注意，第一个数字`7`基本上是三个数字的相加：`4（r）+ 2（w）+ 1（x）`，这将为文件所有者设置完全权限。第二个数字`6`是两个数字的相加：`4（r）+ 2（w）`，这将为组所有者设置读取和写入权限。最后，第三个数字`4`，这将为其他用户设置读取权限。

我知道你在想什么：“为什么我要做数学，当我可以使用文字表示`rwx`？”相信我，我理解你。很多人更喜欢文字表示法而不是数字表示法，但有些人太喜欢数字了！

让我们用八进制表示法做一些练习。文件`mysmurf`当前没有任何权限：

```
smurf@ubuntu-linux:~$ ls -l mysmurf
---------- 1 smurf developers 64 Oct 23 13:38 mysmurf
```

我们可以使用`777`为每个人提供完全权限：

```
smurf@ubuntu-linux:~$ chmod 777 mysmurf 
smurf@ubuntu-linux:~$ ls -l mysmurf
-rwxrwxrwx 1 smurf developers 64 Oct 23 13:38 mysmurf
```

太棒了！现在你可以使用三位数`421`来给予文件所有者读取权限，给予组所有者写入权限，以及给予其他用户执行权限：

```
smurf@ubuntu-linux:~$ chmod 421 mysmurf 
smurf@ubuntu-linux:~$ ls -l mysmurf
-r---w---x 1 smurf developers 64 Oct 23 13:38 mysmurf
```

让我们再举一个例子。如果你想给予文件所有者完全权限，给予组所有者读取权限，以及其他用户零权限，那很简单；正确的三位数将是`740`：

```
smurf@ubuntu-linux:~$ chmod 740 mysmurf 
smurf@ubuntu-linux:~$ ls -l mysmurf
-rwxr----- 1 smurf developers 64 Oct 23 13:38 mysmurf
```

一旦你掌握了，数字就很容易使用。只需要记住：

+   `4`：读取

+   `2`：写入

+   `1`：执行

+   `0`：零权限

以下表总结了所有可能的权限组合：

| **数字** | **意义** | **字面等价** |
| --- | --- | --- |
| 0 | 零/无权限 | `---` |
| 1 | 执行 | `--x` |
| 2 | 写入 | `-w-` |
| 3 | 写入 + 执行 | `-wx` |
| 4 | 读取 | `r--` |
| 5 | 读取 + 执行 | `r-x` |
| 6 | 读取 + 写入 | `rw-` |
| 7 | 读取 + 写入 + 执行 | `rwx` |

表 12：八进制表示法与字面表示法

这一章有点冗长。休息一下，然后回来完成知识检测练习！

# 知识检测

对于以下练习，打开你的终端并尝试解决以下任务：

1.  创建一个用户`abraham`，用户 ID 为`333`。

1.  创建一个新的组`admins`。

1.  将用户`abraham`添加到`admins`组。

1.  将`admins`设为目录`/home/abraham`的组所有者。

1.  `admins`组的成员只能列出目录`/home/abraham`的内容。

## 真或假

1.  `chmod a=rxw facts.txt`将会得到与`chmod 777 facts.txt`相同的结果。

1.  `chmod a=rw facts.txt`将会得到与`chmod 665 facts.txt`相同的结果。

1.  用户`elliot`可以有多个主要组。
