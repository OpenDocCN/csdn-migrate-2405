# Linux Shell 编程训练营（一）

> 原文：[`zh.annas-archive.org/md5/65C572CE82539328A9B0D1458096FD51`](https://zh.annas-archive.org/md5/65C572CE82539328A9B0D1458096FD51)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

在 Linux Shell Scripting Bootcamp 中，您将首先学习脚本创建的基础知识。您将学习如何验证参数，以及如何检查文件的存在。接着，您将熟悉 Linux 系统上变量的工作原理以及它们与脚本的关系。您还将学习如何创建和调用子例程以及创建交互式脚本。最后，您将学习如何调试脚本和脚本编写的最佳实践，这将使您每次都能编写出优秀的代码！通过本书，您将能够编写能够高效地从网络中获取数据并处理数据的 shell 脚本。

# 本书涵盖内容

第一章，开始 shell 脚本，从脚本设计的基础知识开始。展示了如何使脚本可执行，以及创建一个信息丰富的`Usage`消息。还介绍了返回代码的重要性，并使用和验证参数。

第二章，使用变量，讨论了如何声明和使用环境变量和本地变量。我们还讨论了如何执行数学运算以及如何使用数组。

第三章，使用循环和 sleep 命令，介绍了使用循环执行迭代操作的方法。它还展示了如何在脚本中创建延迟。读者还将学习如何在脚本中使用循环和`sleep`命令。

第四章，创建和调用子例程，从一些非常简单的脚本开始，然后继续介绍一些接受参数的简单子例程。

第五章，创建交互式脚本，解释了使用`read`内置命令来查询键盘的用法。此外，我们探讨了一些不同的读取选项，并介绍了陷阱的使用。

第六章，使用脚本自动化任务，描述了创建脚本来自动执行任务。还介绍了使用 cron 在特定时间自动运行脚本的正确方法。还讨论了执行压缩备份的存档命令`zip`和`tar`。

第七章，处理文件，介绍了使用重定向运算符将文件写出以及使用`read`命令读取文件的方法。还讨论了校验和和文件加密，以及将文件内容转换为变量的方法。

第八章，使用 wget 和 curl，讨论了在脚本中使用`wget`和`curl`的用法。除此之外，还讨论了返回代码，并提供了一些示例脚本。

第九章，调试脚本，解释了一些防止常见语法和逻辑错误的技术。还讨论了使用重定向运算符将脚本的输出发送到另一个终端的方法。

第十章，脚本编写最佳实践，讨论了一些实践和技术，将帮助读者每次都编写出优秀的代码。

# 本书适用对象

任何安装了 Bash 的 Linux 机器都应该能够运行这些脚本。这包括台式机、笔记本电脑、嵌入式设备、BeagleBone 等。运行 Cygwin 或其他模拟 Linux 环境的 Windows 机器也可以。

没有最低内存要求。

# 本书适用对象

这本书既适用于想要在 shell 中做出惊人成就的 GNU/Linux 用户，也适用于寻找方法让他们在 shell 中的生活更加高效的高级用户。

# 约定

在本书中，您将找到一些区分不同信息类型的文本样式。以下是一些样式的示例及其含义的解释。

文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下：您可以看到`echo`语句`Start of x loop`被显示为代码块如下所示：

```
echo "Start of x loop"
x=0
while [ $x -lt 5 ]
do
 echo "x: $x"
 let x++

```

任何命令行输入或输出都以以下方式编写：

```
guest1 $ ps auxw | grep script7

```

**新术语**和**重要单词**以粗体显示。例如，屏幕上看到的单词，例如菜单或对话框中的单词，会以这样的方式出现在文本中：“点击**下一步**按钮将您移至下一个屏幕。”

### 注意

警告或重要提示会显示在这样的框中。

### 提示

提示和技巧会以这样的方式出现。

# 读者反馈

我们的读者的反馈总是受欢迎的。让我们知道您对本书的看法——您喜欢或不喜欢的地方。读者的反馈对我们很重要，因为它可以帮助我们开发您真正能够充分利用的书籍。

要向我们发送一般反馈，只需发送电子邮件至`<feedback@packtpub.com>`，并在主题中提及书籍的标题。

如果您在某个专题上有专业知识，并且有兴趣撰写或为书籍做出贡献，请参阅我们的作者指南，网址为[www.packtpub.com/authors](http://www.packtpub.com/authors)。

# 客户支持

现在您是 Packt 书籍的自豪所有者，我们有一些东西可以帮助您充分利用您的购买。

## 下载示例代码

您可以从[`www.packtpub.com`](http://www.packtpub.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了本书，您可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册，以便文件直接通过电子邮件发送给您。

您可以按照以下步骤下载代码文件：

1.  使用您的电子邮件地址和密码登录或注册到我们的网站。

1.  将鼠标指针悬停在顶部的**支持**选项卡上。

1.  点击**代码下载和勘误**。

1.  在**搜索**框中输入书名。

1.  选择您要下载代码文件的书籍。

1.  从下拉菜单中选择您购买本书的地点。

1.  点击**下载代码**。

您还可以通过在 Packt Publishing 网站上的书籍网页上点击**代码文件**按钮来下载代码文件。可以通过在**搜索**框中输入书名来访问此页面。请注意，您需要登录到您的 Packt 帐户。

下载文件后，请确保使用最新版本的以下工具解压或提取文件夹：

+   WinRAR / 7-Zip for Windows

+   Zipeg / iZip / UnRarX for Mac

+   7-Zip / PeaZip for Linux

该书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Linux-Shell-Scripting-Bootcamp`](https://github.com/PacktPublishing/Linux-Shell-Scripting-Bootcamp)。我们还有来自丰富书籍和视频目录的其他代码包，可在[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)上找到。去看看吧！

## 勘误

尽管我们已经尽一切努力确保内容的准确性，但错误确实会发生。如果您在我们的书籍中发现错误——也许是文本或代码中的错误——我们将不胜感激，如果您能向我们报告。通过这样做，您可以帮助其他读者避免挫折，并帮助我们改进本书的后续版本。如果您发现任何勘误，请访问[`www.packtpub.com/submit-errata`](http://www.packtpub.com/submit-errata)报告，选择您的书籍，点击**勘误提交表**链接，并输入您的勘误详情。一旦您的勘误被验证，您的提交将被接受，并且勘误将被上传到我们的网站或添加到该标题的勘误部分的任何现有勘误列表中。

要查看先前提交的勘误表，请访问[`www.packtpub.com/books/content/support`](https://www.packtpub.com/books/content/support)，并在搜索框中输入书名。所需信息将出现在**勘误表**部分。

## 在互联网上盗版受版权保护的材料是一个持续存在的问题，涉及所有媒体。在 Packt，我们非常重视版权和许可的保护。如果您在互联网上发现我们作品的任何形式的非法副本，请立即向我们提供位置地址或网站名称，以便我们采取补救措施。

盗版

请通过`<copyright@packtpub.com>`与我们联系，并附上涉嫌盗版材料的链接。

我们感谢您帮助保护我们的作者和我们为您提供有价值内容的能力。

## 问题

如果您对本书的任何方面有问题，可以通过`<questions@packtpub.com>`与我们联系，我们将尽力解决问题。


# 第一章：开始使用 Shell 脚本

本章是关于 shell 脚本的简要介绍。它将假定读者对脚本基础知识大多熟悉，并将作为复习。

本章涵盖的主题如下：

+   脚本的一般格式。

+   如何使文件可执行。

+   创建良好的使用消息和处理返回代码。

+   展示如何从命令行传递参数。

+   展示如何使用条件语句验证参数。

+   解释如何确定文件的属性。

# 入门

您始终可以在访客账户下创建这些脚本，并且大多数脚本都可以从那里运行。当需要 root 访问权限来运行特定脚本时，将明确说明。

本书将假定用户已在该帐户的路径开头放置了(`.`)。如果没有，请在文件名前加上`./`来运行脚本。例如：

```
 $ ./runme
```

使用`chmod`命令使脚本可执行。

建议用户在其访客账户下创建一个专门用于本书示例的目录。例如，像这样的东西效果很好：

```
$ /home/guest1/LinuxScriptingBook/chapters/chap1
```

当然，随意使用最适合您的方法。

遵循 bash 脚本的一般格式，第一行将只包含此内容：

```
#!/bin/sh
```

请注意，在其他情况下，`#`符号后面的文本被视为注释。

例如，

# 整行都是注释

```
chmod 755 filename   # This text after the # is a comment
```

根据需要使用注释。有些人每行都加注释，有些人什么都不加注释。我试图在这两个极端之间取得平衡。

## 使用好的文本编辑器

我发现大多数人在 UNIX/Linux 环境下使用 vi 创建和编辑文本文档时感到舒适。这很好，因为 vi 是一个非常可靠的应用程序。我建议不要使用任何类型的文字处理程序，即使它声称具有代码开发选项。这些程序可能仍然会在文件中放入不可见的控制字符，这可能会导致脚本失败。除非您擅长查看二进制文件，否则可能需要花费数小时甚至数天来解决这个问题。

此外，我认为，如果您计划进行大量的脚本和/或代码开发，建议查看 vi 之外的其他文本编辑器。您几乎肯定会变得更加高效。

# 演示脚本的使用

这是一个非常简单的脚本示例。它可能看起来不起眼，但这是每个脚本的基础：

## 第一章 - 脚本 1

```
#!/bin/sh
#
#  03/27/2017
#
exit 0
```

### 注意

按照惯例，在本书中，脚本行通常会编号。这仅用于教学目的，在实际脚本中，行不会编号。

以下是带有行号的相同脚本：

```
1  #!/bin/sh
2  #
3  # 03/27/2017
4  #
5  exit 0
6
```

以下是每行的解释：

+   第 1 行告诉操作系统要使用哪个 shell 解释器。请注意，在某些发行版上，`/bin/sh`实际上是指向解释器的符号链接。

+   以`#`开头的行是注释。此外，`#`后面的任何内容也被视为注释。

+   在脚本中包含日期是一个好习惯，可以在注释部分和/或`Usage`部分（下一节介绍）中包含日期。

+   第 5 行是此脚本的返回代码。这是可选的，但强烈建议。

+   第 6 行是空行，也是脚本的最后一行。

使用您喜欢的文本编辑器，编辑一个名为`script1`的新文件，并将前面的脚本复制到其中，不包括行号。保存文件。

要将文件转换为可执行脚本，请运行以下命令：

```
$ chmod 755 script1
```

现在运行脚本：

```
$ script1
```

如果您没有像介绍中提到的那样在路径前加上`.`，则运行：

```
$ ./script1
```

现在检查返回代码：

```
$ echo $?
0
```

这是一个执行得更有用的脚本：

## 第一章 - 脚本 2

```
#!/bin/sh
#
# 3/26/2017
#
ping -c 1 google.com        # ping google.com just 1 time
echo Return code: $?
```

`ping`命令成功返回零，失败返回非零。如您所见，`echoing $?`显示了其前一个命令的返回值。稍后会详细介绍。

现在让我们传递一个参数并包括一个`Usage`语句：

## 第一章 - 脚本 3

```
  1  #!/bin/sh
  2  #
  3  # 6/13/2017
  4  #
  5  if [ $# -ne 1 ] ; then
  6   echo "Usage: script3 file"
  7   echo " Will determine if the file exists."
  8   exit 255
  9  fi
 10  
 11  if [ -f $1 ] ; then
 12   echo File $1 exists.
 13   exit 0
 14  else
 15   echo File $1 does not exist.
 16   exit 1
 17  fi
 18  
```

以下是每行的解释：

+   第`5`行检查是否给出了参数。如果没有，将执行第`6`到`9`行。请注意，通常最好在脚本中包含一个信息性的`Usage`语句。还要提供有意义的返回代码。

+   第`11`行检查文件是否存在，如果是，则执行第`12`-`13`行。否则运行第`14`-`17`行。

+   关于返回代码的说明：在 Linux/UNIX 下，如果命令成功，则返回零是标准做法，如果不成功则返回非零。这样返回的代码可以有一些有用的含义，不仅对人类有用，对其他脚本和程序也有用。但这并不是强制性的。如果你希望你的脚本返回不是错误而是指示其他条件的代码，那么请这样做。

下一个脚本扩展了这个主题：

## 第一章 - 脚本 4

```
  1  #!/bin/sh
  2  #
  3  # 6/13/2017
  4  #
  5  if [ $# -ne 1 ] ; then
  6   echo "Usage: script4 filename"
  7   echo " Will show various attributes of the file given."
  8   exit 255
  9  fi
 10  
 11  echo -n "$1 "                # Stay on the line
 12  
 13  if [ ! -e $1 ] ; then
 14   echo does not exist.
 15   exit 1                      # Leave script now
 16  fi
 17  
 18  if [ -f $1 ] ; then
 19   echo is a file.
 20  elif [ -d $1 ] ; then
 21   echo is a directory.
 22  fi
 23  
 24  if [ -x $1 ] ; then
 25   echo Is executable.
 26  fi
 27  
 28  if [ -r $1 ] ; then
 29   echo Is readable.
 30  else
 31   echo Is not readable.
 32  fi
 33  
 34  if [ -w $1 ] ; then
 35   echo Is writable.
 36  fi
 37  
 38  if [ -s $1 ] ; then
 39   echo Is not empty.
 40  else
 41   echo Is empty.
 42  fi
 43  
 44  exit 0                       # No error
 45  
```

以下是每行的解释：

+   第`5`-`9`行：如果脚本没有使用参数运行，则显示`Usage`消息并以返回代码`255`退出。

+   第`11`行显示了如何`echo`一个文本字符串但仍然保持在同一行（没有换行）。

+   第`13`行显示了如何确定给定的参数是否是现有文件。

+   第`15`行如果文件不存在，则退出脚本没有继续的理由。

剩下的行的含义可以通过脚本本身确定。请注意，可以对文件执行许多其他检查，这只是其中的一部分。

以下是在我的系统上运行`script4`的一些示例：

```
guest1 $ script4
Usage: script4 filename
 Will show various attributes of the file given.

guest1 $ script4 /tmp
/tmp is a directory.
Is executable.
Is readable.
Is writable.
Is not empty.

guest1 $ script4 script4.numbered
script4.numbered is a file.
Is readable.
Is not empty.

guest1 $ script4 /usr
/usr is a directory.
Is executable.
Is readable.
Is not empty.

guest1 $ script4 empty1
empty1 is a file.
Is readable.
Is writable.
Is empty.

guest1 $ script4 empty-noread
empty-noread is a file.
Is not readable.
Is empty.
```

下一个脚本显示了如何确定传递给它的参数数量：

## 第一章 - 脚本 5

```
#!/bin/sh
#
# 3/27/2017
#
echo The number of parameters is: $#
exit 0
```

让我们尝试一些例子：

```
guest1 $ script5
The number of parameters is: 0

guest1 $ script5 parm1
The number of parameters is: 1

guest1 $ script5 parm1 Hello
The number of parameters is: 2

guest1 $ script5 parm1 Hello 15
The number of parameters is: 3

guest1 $ script5 parm1 Hello 15 "A string"
The number of parameters is: 4

guest1 $ script5 parm1 Hello 15 "A string" lastone
The number of parameters is: 5
```

### 提示

记住，引用的字符串被计算为 1 个参数。这是传递包含空格的字符串的一种方法。

下一个脚本显示了如何更详细地处理多个参数：

## 第一章 - 脚本 6

```
#!/bin/sh
#
# 3/27/2017
#

if [ $# -ne 3 ] ; then
 echo "Usage: script6 parm1 parm2 parm3"
 echo " Please enter 3 parameters."

 exit 255
fi

echo Parameter 1: $1
echo Parameter 2: $2
echo Parameter 3: $3

exit 0
```

这个脚本的行没有编号，因为它相当简单。`$#`包含传递给脚本的参数数量。

# 总结

在本章中，我们讨论了脚本设计的基础知识。展示了如何使脚本可执行，以及创建信息性的`Usage`消息。还介绍了返回代码的重要性，以及参数的使用和验证。

下一章将更详细地讨论变量和条件语句。


# 第二章：使用变量

本章将展示变量在 Linux 系统和脚本中的使用方式。

本章涵盖的主题有：

+   在脚本中使用变量

+   使用条件语句验证参数

+   字符串的比较运算符

+   环境变量

# 在脚本中使用变量

变量只是一些值的占位符。值可以改变；但是，变量名称将始终相同。这是一个简单的例子：

```
   a=1
```

这将值`1`分配给变量`a`。这里还有一个：

```
   b=2
```

要显示变量包含的内容，请使用`echo`语句：

```
   echo Variable a is: $a
```

### 注意

请注意变量名称前面的`$`。这是为了显示变量的内容而必需的。

如果您在任何时候看不到您期望的结果，请首先检查`$`。

以下是使用命令行的示例：

```
$ a=1
$ echo a
a
$ echo $a
1
$ b="Jim"
$ echo b
b
$ echo $b
Jim
```

Bash 脚本中的所有变量都被视为字符串。这与 C 等编程语言不同，那里一切都是强类型的。在前面的示例中，即使`a`和`b`看起来是整数，它们也是字符串。

这是一个简短的脚本，让我们开始：

## 第二章-脚本 1

```
#!/bin/sh
#
# 6/13/2017
#
echo "script1"

# Variables
a="1"
b=2
c="Jim"
d="Lewis"
e="Jim Lewis"
pi=3.141592

# Statements
echo $a
echo $b
echo $c
echo $d
echo $e
echo $pi
echo "End of script1"
```

在我的系统上运行时的输出如下：

第二章-脚本 1

由于所有变量都是字符串，我也可以这样做：

```
a="1"
b="2"
```

当字符串包含空格时，引用字符串很重要，例如这里的变量`d`和`e`。

### 注意

我发现如果我引用程序中的所有字符串，但不引用数字，那么更容易跟踪我如何使用变量（即作为字符串还是数字）。

# 使用条件语句验证参数

当将变量用作数字时，可以测试和比较变量与其他变量。

以下是可以使用的一些运算符的列表：

| 运算符 | 说明 |
| --- | --- |
| `-eq` | 这代表等于 |
| `-ne` | 这代表不等于 |
| `-gt` | 这代表大于 |
| `-lt` | 这代表小于 |
| `-ge` | 这代表大于或等于 |
| `-le` | 这代表小于或等于 |
| `!` | 这代表否定运算符 |

让我们在下一个示例脚本中看一下这个：

## 第二章-脚本 2

```
#!/bin/sh
#
# 6/13/2017
#
echo "script2"

# Numeric variables
a=100
b=100
c=200
d=300

echo a=$a b=$b c=$c d=$d     # display the values

# Conditional tests
if [ $a -eq $b ] ; then
 echo a equals b
fi

if [ $a -ne $b ] ; then
 echo a does not equal b
fi

if [ $a -gt $c ] ; then
 echo a is greater than c
fi

if [ $a -lt $c ] ; then
 echo a is less than c
fi

if [ $a -ge $d ] ; then
 echo a is greater than or equal to d
fi

if [ $a -le $d ] ; then
 echo a is less than or equal to d
fi

echo Showing the negation operator:
if [ ! $a -eq $b ] ; then
 echo Clause 1
else
 echo Clause 2
fi
echo "End of script2"
```

输出如下：

![第二章-脚本 2](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-sh-scp-bc/img/B07040_02_02.jpg)

为了帮助理解本章，请在您的系统上运行脚本。尝试更改变量的值，看看它如何影响输出。

我们在第一章中看到了否定运算符，*开始使用 Shell 脚本*，当我们查看文件时。作为提醒，它否定了表达式。您还可以说它执行与原始语句相反的操作。

考虑以下示例：

```
a=1
b=1
if [ $a -eq $b ] ; then
  echo Clause 1
else
  echo Clause 2
fi
```

运行此脚本时，它将显示`条款 1`。现在考虑这个：

```
a=1
b=1
if [ ! $a -eq $b ] ; then    # negation
  echo Clause 1
else
  echo Clause 2
fi
```

由于否定运算符，它现在将显示`条款 2`。在您的系统上试一试。

# 字符串的比较运算符

字符串的比较与数字的比较不同。以下是部分列表：

| 运算符 | 说明 |
| --- | --- |
| `=` | 这代表等于 |
| `!=` | 这代表不等于 |
| `>` | 这代表大于 |
| `<` | 这代表小于 |

现在让我们看一下*脚本 3*：

## 第二章-脚本 3

```
  1  #!/bin/sh
  2  #
  3  # 6/13/2017
  4  #
  5  echo "script3"
  6  
  7  # String variables
  8  str1="Kirk"
  9  str2="Kirk"
 10  str3="Spock"
 11  str3="Dr. McCoy"
 12  str4="Engineer Scott"
 13  str5="A"
 14  str6="B"
 15  
 16  echo str1=$str1 str2=$str2 str3=$str3 str4=$str4
 17  
 18  if [ "$str1" = "$str2" ] ; then
 19   echo str1 equals str2
 20  else
 21   echo str1 does not equal str2
 22  fi
 23  
 24  if [ "$str1" != "$str2" ] ; then
 25   echo str1 does not equal str2
 26  else
 27   echo str1 equals str2
 28  fi
 29  
 30  if [ "$str1" = "$str3" ] ; then
 31   echo str1 equals str3
 32  else
 33   echo str1 does not equal str3
 34  fi
 35  
 36  if [ "$str3" = "$str4" ] ; then
 37   echo str3 equals str4
 38  else
 39   echo str3 does not equal str4
 40  fi
 41  
 42  echo str5=$str5 str6=$str6
 43  
 44  if [ "$str5" \> "$str6" ] ; then        # must escape the >
 45   echo str5 is greater than str6
 46  else
 47   echo str5 is not greater than str6
 48  fi
 49  
 50  if [[ "$str5" > "$str6" ]] ; then       # or use double brackets
 51   echo str5 is greater than str6
 52  else
 53   echo str5 is not greater than str6
 54  fi
 55  
 56  if [[ "$str5" < "$str6" ]] ; then       # double brackets
 57   echo str5 is less than str6
 58  else
 59   echo str5 is not less than str6
 60  fi
 61  
 62  if [ -n "$str1" ] ; then     # test if str1 is not null
 63   echo str1 is not null
 64  fi
 65  
 66  if [ -z "$str7" ] ; then     # test if str7 is null
 67   echo str7 is null
 68  fi
 69  echo "End of script3"
 70
```

这是我系统的输出：

![第二章-脚本 3](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-sh-scp-bc/img/B07040_02_03.jpg)

让我们逐行看一下这个：

+   第 7-14 行设置了变量

+   第 16 行显示它们的值

+   第 18 行检查相等性

+   第 24 行使用不等运算符

+   直到第 50 行的内容都是不言自明的

+   第 44 行需要一些澄清。为了避免语法错误，必须转义`>`和`<`运算符

+   这是通过使用反斜杠（或转义）`\`字符来实现的

+   第 50 行显示了如何使用双括号处理大于运算符。正如您在第 58 行中看到的那样，它也适用于小于运算符。我的偏好将是在需要时使用双括号。

+   第 62 行显示了如何检查一个字符串是否为`not null`。

+   第 66 行显示了如何检查一个字符串是否为`null`。

仔细查看这个脚本，确保你能够清楚地理解它。还要注意`str7`被显示为`null`，但实际上我们并没有声明`str7`。在脚本中这样做是可以的，不会产生错误。然而，作为编程的一般规则，最好在使用变量之前声明所有变量。这样你和其他人都能更容易理解和调试你的代码。

在编程中经常出现的一种情况是有多个条件需要测试。例如，如果某件事是真的，而另一件事也是真的，就采取这个行动。这是通过使用逻辑运算符来实现的。

这里是*脚本 4*，展示了逻辑运算符的使用：

## 第二章 - 脚本 4

```
#!/bin/sh
#
# 5/1/2017
#
echo "script4 - Linux Scripting Book"

if [ $# -ne 4 ] ; then
 echo "Usage: script4 number1 number2 number3 number4"
 echo "       Please enter 4 numbers."

 exit 255
fi

echo Parameters: $1 $2 $3 $4

echo Showing logical AND
if [[ $1 -eq $2 && $3 -eq $4 ]] ; then      # logical AND
 echo Clause 1
else
 echo Clause 2
fi

echo Showing logical OR
if [[ $1 -eq $2 || $3 -eq $4 ]] ; then      # logical OR
 echo Clause 1
else
 echo Clause 2
fi

echo "End of script4"
exit 0
```

这是我的系统上的输出：

![第二章 - 脚本 4](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-sh-scp-bc/img/B07040_02_04.jpg)

在你的系统上使用不同的参数运行这个脚本。在每次尝试时，尝试确定输出是什么，然后运行它。直到你每次都能做对为止，重复这个过程。现在理解这个概念将对我们在后面处理更复杂的脚本时非常有帮助。

现在让我们看一下*脚本 5*，看看如何执行数学运算：

## 第二章 - 脚本 5

```
#!/bin/sh
#
# 5/1/2017
#
echo "script5 - Linux Scripting Book"

num1=1
num2=2
num3=0
num4=0
sum=0

echo num1=$num1
echo num2=$num2

let sum=num1+num2
echo "The sum is: $sum"

let num1++
echo "num1 is now: $num1"

let num2--
echo "num2 is now: $num2"

let num3=5
echo num3=$num3

let num3=num3+10
echo "num3 is now: $num3"

let num3+=10
echo "num3 is now: $num3"

let num4=50
echo "num4=$num4"

let num4-=10
echo "num4 is now: $num4"

echo "End of script5"
```

以下是输出：

![第二章 - 脚本 5](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-sh-scp-bc/img/B07040_02_05.jpg)

如你所见，变量和以前一样设置。使用`let`命令执行数学运算。注意没有使用`$`前缀：

```
let sum=num1+num2
```

还要注意一些操作的简写方式。例如，假设你想将变量`num1`增加`1`。你可以这样做：

```
let num1=num1+1
```

或者，你可以使用简写表示法：

```
let num1++
```

运行这个脚本，并改变一些值，以了解数学运算的工作原理。我们将在后面的章节中更详细地讨论这个问题。

# 环境变量

到目前为止，我们只谈到了脚本中局部的变量。还有一些系统范围的环境变量（env vars），它们在任何 Linux 系统中都扮演着非常重要的角色。以下是一些，读者可能已经知道其中一些：

| 变量 | 角色 |
| --- | --- |
| `HOME` | 用户的主目录 |
| `PATH` | 用于搜索命令的目录 |
| `PS1` | 命令行提示符 |
| `HOSTNAME` | 主机名 |
| `SHELL` | 正在使用的 shell |
| `USER` | 本次会话的用户 |
| `EDITOR` | 用于`crontab`和其他程序的文本编辑器 |
| `HISTSIZE` | 历史命令中将显示的命令数 |
| `TERM` | 正在使用的命令行终端的类型 |

这些大多是不言自明的，但我会提到一些。

`PS1`环境变量控制 shell 提示作为命令行的一部分显示的内容。默认设置通常是类似`[guest1@big1 ~]$`的东西，这并不像它本来可以做的那样有用。至少，一个好的提示至少显示主机名和当前目录。

例如，当我在这一章上工作时，我的系统提示看起来就像这样：

```
   big1 ~/LinuxScriptingBook/chapters/chap2 $
```

`big1`是我的系统的主机名，`~/LinuxScriptingBook/chapters/chap2`是当前目录。记住波浪号`~`代表用户的`home`目录；所以在我的情况下，这会扩展到：

```
 /home/guest1/LinuxScriptingBook/chapters/chap2
```

`"$"`表示我是在一个访客账户下运行。

为了启用这个功能，我的`PS1`环境变量在`/home/guest1/.bashrc`中定义如下：

```
   export PS1="\h \w $ "
```

`"\h"`显示主机名，`\w`显示当前目录。这是一个非常有用的提示，我已经使用了很多年。这是如何显示用户名的方法：

```
   export PS1="\u \h \w $ "
```

现在提示看起来是这样的：

```
 guest1 big1 ~/LinuxScriptingBook/chapters/chap2 $
```

如果你在`.bashrc`文件中更改`PS1`变量，请确保在文件中已经存在的任何其他行之后这样做。

例如，这是我的`guest1`账户下原始`.bashrc`文件的内容：

```
# .bashrc

# Source global definitions
if [ -f /etc/bashrc ]; then
    . /etc/bashrc
fi

# User specific aliases and functions
```

在这些行之后放置你的`PS1`定义。

### 注意

如果你每天登录很多不同的机器，有一个我发现非常有用的`PS1`技巧。这将在后面的章节中展示。

你可能已经注意到，在本书的示例中，我并不总是使用一个良好的`PS1`变量。这是在书的创作过程中编辑掉的，以节省空间。

`EDITOR`变量非常有用。这告诉系统要使用哪个文本编辑器来编辑用户的`crontab`（`crontab -e`）等内容。如果没有设置，默认为 vi 编辑器。可以通过将其放入用户的`.bashrc`文件中进行更改。这是我 root 账户的样子：

```
   export EDITOR=/lewis/bin64/kw
```

当我运行`crontab -l`（或`-e`）时，我的自己编写的文本编辑器会出现，而不是 vi。非常方便！

在这里我们将看一下*脚本 6*，它展示了我`guest1`账户下系统上的一些变量：

## 第二章 - 脚本 6

```
#!/bin/sh
#
# 5/1/2017
#
echo "script6 - Linux Scripting Book"

echo HOME - $HOME
echo PATH - $PATH
echo HOSTNAME - $HOSTNAME
echo SHELL - $SHELL
echo USER - $USER
echo EDITOR - $EDITOR
echo HISTSIZE - $HISTSIZE
echo TERM - $TERM

echo "End of script6"
```

这是输出：

![第二章 - 脚本 6](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-sh-scp-bc/img/B07040_02_06.jpg)

你也可以创建和使用自己的环境变量。这是 Linux 系统的一个非常强大的功能。这里有一些我在`/root/.bashrc`文件中使用的例子：

```
BIN=/lewis/bin64
DOWN=/home/guest1/Downloads
DESK=/home/guest1/Desktop
JAVAPATH=/usr/lib/jvm/java-1.7.0-openjdk-1.7.0.99.x86_64/include/
KW_WORKDIR=/root
L1=guest1@192.168.1.21
L4=guest1@192.168.1.2
LBCUR=/home/guest1/LinuxScriptingBook/chapters/chap2
export BIN DOWN DESK JAVAPATH KW_WORKDIR L1 L4 LBCUR
```

+   `BIN`：这是我的可执行文件和脚本的目录在根目录下

+   `DOWN`：这是用于电子邮件附件下载的目录等

+   `DESK`：这是屏幕截图的下载目录

+   `JAVAPATH`：这是我编写 Java 应用程序时要使用的目录

+   `KW_WORKDIR`：这是我的编辑器放置其工作文件的位置

+   `L1`和`L2`：这是我笔记本电脑的 IP 地址

+   `LBCUR`：这是我为本书工作的当前目录

确保导出你的变量，以便其他终端可以访问它们。还记得当你做出改变时要源化你的`.bashrc`。在我的系统上，命令是：

```
    guest1 $ . /home/guest1/.bashrc
```

### 提示

不要忘记命令开头的句点！

我将在后面的章节中展示这些环境变量如何与别名配对。例如，我的系统上的`bin`命令是一个将当前目录更改为`/lewis/bin64`目录的别名。这是 Linux 系统中最强大的功能之一，然而，我总是惊讶地发现它并不经常被使用。

我们在本章中要介绍的最后一种变量类型叫做数组。假设你想编写一个包含实验室中所有机器 IP 地址的脚本。你可以这样做：

```
L0=192.168.1.1
L1=192.168.1.10
L2=192.168.1.15
L3=192.168.1.16
L4=192.168.1.20
L5=192.168.1.26
```

这将起作用，事实上我在我的家庭办公室/实验室中做了类似的事情。然而，假设你有很多机器。使用数组可以让你的生活变得简单得多。

看一下*脚本 7*：

## 第二章 - 脚本 7

```
#!/bin/sh
#
# 5/1/2017
#
echo "script7 - Linux Scripting Book"

array_var=(1 2 3 4 5 6)

echo ${array_var[0]}
echo ${array_var[1]}
echo ${array_var[2]}
echo ${array_var[3]}
echo ${array_var[4]}
echo ${array_var[5]}

echo "List all elements:"
echo ${array_var[*]}

echo "List all elements (alternative method):"
echo ${array_var[@]}

echo "Number of elements: ${#array_var[*]}"
labip[0]="192.168.1.1"
labip[1]="192.168.1.10"
labip[2]="192.168.1.15"
labip[3]="192.168.1.16"
labip[4]="192.168.1.20"

echo ${labip[0]}
echo ${labip[1]}
echo ${labip[2]}
echo ${labip[3]}
echo ${labip[4]}

echo "List all elements:"
echo ${labip[*]}

echo "Number of elements: ${#labip[*]}"
echo "End of script7"
```

这是我系统上的输出：

![第二章 - 脚本 7](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-sh-scp-bc/img/B07040_02_07.jpg)

在你的系统上运行这个脚本并尝试进行实验。如果你以前从未见过或使用过数组，不要让它们吓到你；你很快就会熟悉它们。这是另一个容易忘记`${数组变量}`语法的地方，所以如果脚本不按你的意愿执行（或生成错误），首先检查这个。

在下一章中，当我们讨论循环时，我们将更详细地讨论数组。

# 总结

在本章中，我们介绍了如何声明和使用环境变量和本地变量。我们讨论了如何进行数学运算以及如何处理数组。

我们还介绍了在脚本中使用变量。*脚本 1*展示了如何分配一个变量并显示其值。*脚本 2*展示了如何处理数字变量，*脚本 3*展示了如何比较字符串。*脚本 4*展示了逻辑运算符，*脚本 5*展示了如何进行数学运算。*脚本 6*展示了如何使用环境变量，*脚本 7*展示了如何使用数组。


# 第三章：使用循环和 sleep 命令

本章展示了如何使用循环执行迭代操作。它还展示了如何在脚本中创建延迟。读者将学习如何在脚本中使用循环和`sleep`命令。

本章涵盖的主题如下：

+   标准的`for`、`while`和`until`循环。

+   循环的嵌套，以及如何避免混淆。

+   介绍`sleep`命令以及它在脚本中如何用于造成延迟。

+   讨论使用`sleep`的一个常见陷阱。

# 使用循环

任何编程语言最重要的特性之一就是能够执行一个任务或多个任务，然后在满足结束条件时停止。这是通过使用循环来实现的。

下一节展示了一个非常简单的`while`循环的例子：

## 第三章 - 脚本 1

```
#!/bin/sh
#
# 5/2/2017
#
echo "script1 - Linux Scripting Book"
x=1
while [ $x -le 10 ]
do
 echo x: $x
 let x++
done

echo "End of script1"

exit 0
```

以下是输出：

![第三章 - 脚本 1](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-sh-scp-bc/img/B07040_03_01.jpg)

我们首先将变量`x`设置为`1`。`while`语句检查`x`是否小于或等于`10`，如果是，则运行`do`和`done`语句之间的命令。它将继续这样做，直到`x`等于`11`，此时`done`语句后的行将被运行。

在你的系统上运行这个。理解这个脚本非常重要，这样我们才能进入更高级的循环。

让我们在下一节看另一个脚本，看看你能否确定它有什么问题。

## 第三章 - 脚本 2

```
#!/bin/sh
#
# 5/2/2017
#
echo "script2 - Linux Scripting Book"

x=1
while [ $x -ge 0 ]
do
 echo x: $x
 let x++
done

echo "End of script2"

exit 0
```

随意跳过这个脚本的运行，除非你真的想要。仔细看`while`测试。它说当`x`大于或等于`0`时，运行循环内的命令。`x`会不会不满足这个条件？不会，这就是所谓的无限循环。不用担心；你仍然可以通过按下*Ctrl* + *C*（按住*Ctrl*键然后按*C*键）来终止脚本。

我想立即介绍无限循环，因为你几乎肯定会偶尔这样做，我想让你知道当发生这种情况时如何终止脚本。当我刚开始学习时，我肯定做过几次。

好了，让我们做一些更有用的事情。假设你正在开始一个新项目，需要在你的系统上创建一些目录。你可以一次执行一个命令，或者在脚本中使用循环。

我们将在*脚本 3*中看到这个。

## 第三章 - 脚本 3

```
#!/bin/sh
#
# 5/2/2017
#
echo "script3 - Linux Scripting Book"

x=1
while [ $x -le 10 ]
do
 echo x=$x
 mkdir chapter$x
 let x++
done
echo "End of script3"

exit 0
```

这个简单的脚本假设你是从基本目录开始的。运行时，它将创建`chapter 1`到`chapter 10`的目录，然后继续到结束。

在运行对计算机进行更改的脚本时，最好在真正运行之前确保逻辑是正确的。例如，在运行这个脚本之前，我注释掉了`mkdir`行。然后我运行脚本，确保它在显示`x`等于`10`后停止。然后我取消注释该行并真正运行它。

# 屏幕操作

我们将在下一节中看到另一个使用循环在屏幕上显示文本的脚本：

## 第三章 - 脚本 4

```
#!/bin/sh
#
# 5/2/2017
#
echo "script4 - Linux Scripting Book"

if [ $# -ne 1 ] ; then
 echo "Usage: script4 string"
 echo "Will display the string on every line."
 exit 255
fi

tput clear                   # clear the screen

x=1
while [ $x -le $LINES ]
do
 echo "********** $1 **********"
 let x++
done

exit 0
```

在执行这个脚本之前运行以下命令：

```
echo $LINES
```

如果终端中没有显示行数，请运行以下命令：

```
export LINES=$LINES
```

然后继续运行脚本。在我的系统上，当使用`script4` `Linux`运行时，输出如下：

![第三章 - 脚本 4](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-sh-scp-bc/img/B07040_03_02.jpg)

好吧，我同意这可能不是非常有用，但它确实展示了一些东西。`LINES`环境变量包含当前终端中的行数。这对于在更复杂的脚本中限制输出可能很有用，这将在后面的章节中展示。这个例子还展示了如何在脚本中操作屏幕。

如果需要导出`LINES`变量，你可能希望将其放在你的`.bashrc`文件中并重新加载它。

我们将在下一节中看另一个脚本：

## 第三章 - 脚本 5

```
#!/bin/sh
#
# 5/2/2017
#
# script5 - Linux Scripting Book

tput clear                   # clear the screen

row=1
while [ $row -le $LINES ]
do
 col=1
 while [ $col -le $COLUMNS ]
 do
  echo -n "#"
  let col++
 done
 echo ""                     # output a carriage return
 let row++
done

exit 0
```

这与*脚本 4*类似，它展示了如何在终端的范围内显示输出。注意，你可能需要像我们使用`LINES`变量一样导出`COLUMNS`环境变量。

您可能已经注意到这个脚本中有一点不同。在`while`语句内部有一个`while`语句。这称为嵌套循环，在编程中经常使用。

我们首先声明`row=1`，然后开始外部`while`循环。然后将`col`变量设置为`1`，然后启动内部循环。这个内部循环显示了该行每一列的字符。当到达行的末尾时，循环结束，`echo`语句输出回车。然后增加`row`变量，然后再次开始该过程。在最后一行结束后结束。

通过仅使用`LINES`和`COLUMNS`环境变量，可以将实际屏幕写入。您可以通过运行程序然后扩展终端来测试这一点。

在使用嵌套循环时，很容易混淆哪里放什么。这是我每次都尝试做的事情。当我第一次意识到程序（可以是脚本、C、Java 等）需要一个循环时，我首先编写循环体，就像这样：

```
 while [ condition ]
 do
    other statements will go here
 done
```

这样我就不会忘记`done`语句，而且它也排列得很整齐。如果我需要另一个循环，我只需再次执行它：

```
 while [ condition ]
 do
   while [ condition ]
   do
     other statements will go here
   done
 done
```

您可以嵌套任意多个循环。

# 缩进您的代码

现在可能是谈论缩进的好时机。在过去（即 30 多年前），每个人都使用等宽字体的文本编辑器来编写他们的代码，因此只需一个空格的缩进就可以相对容易地保持一切对齐。后来，当人们开始使用具有可变间距字体的文字处理器时，变得更难看到缩进，因此使用了更多的空格（或制表符）。我的建议是使用您感觉最舒适的方式。但是，话虽如此，您可能必须学会阅读和使用公司制定的任何代码风格。

到目前为止，我们只谈到了`while`语句。现在让我们在下一节中看看`until`循环：

## 第三章 - 脚本 6

```
#!/bin/sh
#
# 5/3/2017
#
echo "script6 - Linux Scripting Book"

echo "This shows the while loop"

x=1
while [ $x -lt 11 ]          # perform the loop while the condition 
do                           # is true
 echo "x: $x"
 let x++
done

echo "This shows the until loop"

x=1
until [ $x -gt 10 ]          # perform the loop until the condition 
do                           # is true
 echo "x: $x"
 let x++
done

echo "End of script6"

exit 0
```

输出：

![第三章 - 脚本 6](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-sh-scp-bc/img/B07040_03_03.jpg)

看看这个脚本。两个循环的输出是相同的；但是，条件是相反的。第一个循环在条件为真时继续，第二个循环在条件为真时继续。这是一个不那么微妙的区别，所以要注意这一点。

# 使用`for`语句

循环的另一种方法是使用`for`语句。在处理文件和其他列表时通常使用。`for`循环的一般语法如下：

```
 for variable in list
 do
     some commands
 done
```

列表可以是字符串集合，也可以是文件名通配符等。我们可以在下一节中给出的示例中看一下这一点。

## 第三章 - 脚本 7

```
#!/bin/sh
#
# 5/4/2017
#
echo "script7 - Linux Scripting Book"

for i in jkl.c bob Linux "Hello there" 1 2 3
do
 echo -n "$i "
done

for i in script*             # returns the scripts in this directory
do
 echo $i
done

echo "End of script7"
exit 0
```

以及我的系统输出。这是我的`chap3`目录：

![第三章 - 脚本 7](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-sh-scp-bc/img/B07040_03_04.jpg)

下一个脚本显示了`for`语句如何与文件一起使用：

## 第三章 - 脚本 8

```
#!/bin/sh
#
# 5/3/2017
#
echo "script8 - Linux Scripting Book"

if [ $# -eq 0 ] ; then
 echo "Please enter at least 1 parameter."
 exit 255
fi

for i in $*                  # the "$*" returns every parameter given 
do                           # to the script
 echo -n "$i "
done

echo ""                      # carriage return
echo "End of script8"

exit 0
```

以下是输出：

![第三章 - 脚本 8](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-sh-scp-bc/img/B07040_03_05.jpg)

您可以使用`for`语句做一些其他事情，请参阅 Bash 的`man`页面以获取更多信息。

# 提前离开循环

有时在编写脚本时，您会遇到一种情况，希望在满足结束条件之前提前退出循环。可以使用`break`和`continue`命令来实现这一点。

这是一个显示这些命令的脚本。我还介绍了`sleep`命令，将在下一个脚本中详细讨论。

## 第三章 - 脚本 9

```
#!/bin/sh
#
# 5/3/2017
#
echo "script9 - Linux Scripting Book"

FN1=/tmp/break.txt
FN2=/tmp/continue.txt

x=1
while [ $x -le 1000000 ]
do
 echo "x:$x"
 if [ -f $FN1 ] ; then
  echo "Running the break command"
  rm -f $FN1
  break
 fi

 if [ -f $FN2 ] ; then
  echo "Running the continue command"
  rm -f $FN2
  continue
 fi

 let x++
 sleep 1
done

echo "x:$x"

echo "End of script9"

exit 0
```

这是我的系统输出：

![第三章 - 脚本 9](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-sh-scp-bc/img/B07040_03_06.jpg)

在您的系统上运行此命令，并在另一个终端中`cd`到`/tmp`目录。运行命令`touch continue.txt`并观察发生了什么。如果愿意，您可以多次执行此操作（请记住，上箭头会调用上一个命令）。请注意，当命中`continue`命令时，变量`x`不会增加。这是因为控制立即返回到`while`语句。

现在运行`touch break.txt`命令。脚本将结束，再次，`x`没有被增加。这是因为`break`立即导致循环结束。

`break`和`continue`命令在脚本中经常使用，因此一定要充分尝试，真正理解发生了什么。

# 睡眠命令

我之前展示了`sleep`命令，让我们更详细地看一下。一般来说，`sleep`命令用于在脚本中引入延迟。例如，在前面的脚本中，如果我没有使用`sleep`，输出会太快而无法看清发生了什么。

`sleep`命令接受一个参数，指示延迟的时间。例如，`sleep 1`表示引入 1 秒的延迟。以下是一些示例：

```
sleep 1       # sleep 1 second (the default is seconds)
sleep 1s      # sleep 1 second
sleep 1m      # sleep 1 minute
sleep 1h      # sleep 1 hour
sleep 1d      # sleep 1 day
```

`sleep`命令实际上比这里展示的更有能力。有关更多信息，请参阅`man`页面（`man sleep`）。

以下是一个更详细展示了`sleep`工作原理的脚本：

## 第三章 - 脚本 10

```
#!/bin/sh
#
# 5/3/2017
#
echo "script10 - Linux Scripting Book"

echo "Sleeping seconds..."
x=1
while [ $x -le 5 ]
do
 date
 let x++
 sleep 1
done

echo "Sleeping minutes..."
x=1
while [ $x -le 2 ]
do
 date
 let x++
 sleep 1m
done

echo "Sleeping hours..."
x=1
while [ $x -le 2 ]
do
 date
 let x++
 sleep 1h
done

echo "End of script10"
exit 0
```

和输出：

![第三章 - 脚本 10](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-sh-scp-bc/img/B07040_03_07.jpg)

您可能已经注意到，我按下了*Ctrl* + *C*来终止脚本，因为我不想等待 2 个小时才能完成。这种类型的脚本在 Linux 系统中被广泛使用，用于监视进程，观察文件等。

在使用`sleep`命令时有一个常见的陷阱需要提到。

### 注意

请记住，`sleep`命令会在脚本中引入延迟。明确地说，当您编写`sleep 60`时，这意味着引入 60 秒的延迟；而不是每 60 秒运行一次脚本。这是一个很大的区别。

我们将在下一节中看到一个例子：

## 第三章 - 脚本 11

```
#!/bin/sh
#
# 5/3/2017
#
echo "script11 - Linux Scripting Book"

while [ true ]
do
 date
 sleep 60                    # 60 seconds
done

echo "End of script11"

exit 0
```

这是我的系统输出。最终会出现不同步的情况：

![第三章 - 脚本 11](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-sh-scp-bc/img/B07040_03_08.jpg)

对于绝大多数脚本来说，这永远不会成为一个问题。只要记住，如果您要完成的任务是时间关键的，比如每天晚上准确在 12:00 运行一个命令，您可能需要考虑其他方法。请注意，`crontab`也不会做到这一点，因为在运行命令之前会有大约 1 到 2 秒的延迟。

# 监视一个进程

在本章中，还有一些其他主题需要我们看一下。假设您希望在系统上运行的进程结束时收到警报。

以下是一个脚本，当指定的进程结束时通知用户。请注意，还有其他方法可以完成这个任务，这只是一种方法。

## 第三章 - 脚本 12

```
#!/bin/sh
#
# 5/3/2017
#
echo "script12 - Linux Scripting Book"

if [ $# -ne 1 ] ; then
 echo "Usage: script12 process-directory"
 echo " For example: script12 /proc/20686"
 exit 255
fi

FN=$1                        # process directory i.e. /proc/20686
rc=1
while [ $rc -eq 1 ]
do
 if [ ! -d $FN ] ; then      # if directory is not there
  echo "Process $FN is not running or has been terminated."
  let rc=0
 else
  sleep 1
 fi
done

echo "End of script12"
exit 0
```

要查看此脚本的运行情况，请运行以下命令：

+   在终端中运行`script9`

+   在另一个终端中运行`ps auxw | grep script9`。输出将类似于这样：

```
guest1   20686  0.0  0.0 106112  1260 pts/34   S+   17:20   0:00 /bin/sh ./script9
guest1   23334  0.0  0.0 103316   864 pts/18   S+   17:24   0:00 grep script9
```

+   使用`script9`的进程 ID（在本例中为`20686`），并将其用作运行`script12`的参数：

```
$ script12 /proc/20686
```

如果您愿意，可以让它运行一段时间。最终返回到运行`script9`的终端，并使用*Ctrl* + *C*终止它。您将看到`script12`输出一条消息，然后也终止。随时尝试这个，因为它包含了很多重要信息。

您可能会注意到，在这个脚本中，我使用了一个变量`rc`来确定何时结束循环。我可以使用我们在本章前面看到的`break`命令。然而，使用控制变量（通常被称为）被认为是更好的编程风格。

当您启动一个命令然后它花费的时间比您预期的时间长时，这样的脚本非常有用。

例如，前段时间我使用`mkfs`命令在一个外部 1TB USB 驱动器上启动了一个格式化操作。它花了几天的时间才完成，我想确切地知道何时完成，以便我可以继续使用该驱动器。

# 创建编号的备份文件

现在作为一个奖励，这是一个可以直接运行的脚本，可以用来创建编号的备份文件。在我想出这个方法之前（很多年前），我会手工制作备份的仪式。我的编号方案并不总是一致的，我很快意识到让脚本来做这件事会更容易。这正是计算机擅长的事情。

我称这个脚本为`cbS`。我写这个脚本已经很久了，我甚至不确定它代表什么。也许是**计算机备份脚本**之类的东西。

## 第三章-脚本 13

```
#!/bin/sh
#
echo "cbS by Lewis 5/4/2017"

if [ $# -eq 0 ] ; then
 echo "Usage: cbS filename(s) "
 echo " Will make a numbered backup of the files(s) given."
 echo " Files must be in the current directory."
 exit 255
fi

rc=0                         # return code, default is no error
for fn in $*                 # for each filename given on the command line
do
 if [ ! -f $fn ] ; then      # if not found
  echo "File $fn not found."
  rc=1                       # one or more files were not found
 else
  cnt=1                      # file counter
  loop1=0                    # loop flag
  while [ $loop1 -eq 0 ]
  do
   tmp=bak-$cnt.$fn
   if [ ! -f $tmp ] ; then
     cp $fn $tmp
     echo "File "$tmp" created."
     loop1=1                 # end the inner loop
   else
     let cnt++               # try the next one
   fi
  done
 fi
done

exit $rc                     # exit with return code
```

它以一个`Usage`消息开始，因为它至少需要一个文件名来操作。

请注意，这个命令要求文件在当前目录中，所以像`cbS /tmp/file1.txt`这样的操作会产生错误。

`rc`变量被初始化为`0`。如果找不到文件，它将被设置为`1`。

现在让我们来看内部循环。这里的逻辑是使用`cp`命令从原始文件创建一个备份文件。备份文件的命名方案是`bak-(数字).原始文件名`，其中`数字`是下一个顺序中的数字。代码通过查看所有的`bak-#.文件名`文件来确定下一个数字是什么。直到找不到一个为止。然后那个就成为新的文件名。

在你的系统上让这个脚本运行起来。随意给它取任何你喜欢的名字，但要小心给它取一个不同于现有的 Linux 命令的名字。使用`which`命令来检查。

这是我系统上的一些示例输出：

![第三章-脚本 13](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-sh-scp-bc/img/B07040_03_09.jpg)

这个脚本可以得到很大的改进。它可以被制作成适用于路径/文件，并且应该检查`cp`命令是否有错误。这种编码水平将在后面的章节中介绍。

# 总结

在本章中，我们介绍了不同类型的循环语句以及它们之间的区别。还介绍了嵌套循环和`sleep`命令。还提到了使用`sleep`命令时的常见陷阱，并介绍了一个备份脚本，展示了如何轻松创建编号的备份文件。

在下一章中，我们将介绍子程序的创建和调用。


# 第四章：创建和调用子程序

本章介绍了如何在脚本中创建和调用子程序。

本章涵盖的主题如下：

+   显示一些简单的子程序。

+   显示更高级的例程。

+   再次提到返回代码以及它们在脚本中的工作方式。

在前几章中，我们主要看到了一些不太复杂的简单脚本。脚本实际上可以做更多的事情，我们将很快看到。

首先，让我们从一些简单但强大的脚本开始。这些主要是为了让读者了解脚本可以快速完成的工作。

# 清屏

`tput clear`终端命令可用于清除当前的命令行会话。您可以一直输入`tput clear`，但只输入`cls`会不会更好？

这是一个简单的清除当前屏幕的脚本：

## 第四章 - 脚本 1

```
#!/bin/sh
#
# 5/8/2017
#
tput clear
```

请注意，这是如此简单，以至于我甚至都没有包括`Usage`消息或返回代码。记住，要在您的系统上将其作为命令执行，请执行以下操作：

+   `cd $HOME/bin`

+   创建/编辑名为`cls`的文件

+   将上述代码复制并粘贴到此文件中

+   保存文件

+   运行`chmod 755 cls`

现在您可以在任何终端（在该用户下）输入`cls`，屏幕将被清除。试试看。

# 文件重定向

在这一点上，我们需要讨论文件重定向。这是将命令或脚本的输出复制到文件而不是显示在屏幕上的能力。这是通过使用重定向运算符来完成的，实际上就是大于号。

这是我在我的系统上运行的一些命令的屏幕截图：

![文件重定向](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-sh-scp-bc/img/B07040_04_01.jpg)

如您所见，`ifconfig`命令的输出被发送（或重定向）到`ifconfig.txt`文件。

# 命令管道

现在让我们看看命令管道，即运行一个命令并将其输出作为另一个命令的输入的能力。

假设您的系统上正在运行名为`loop1`的程序或脚本，并且您想知道其 PID。您可以运行`ps auxw`命令到一个文件，然后使用`grep`命令在文件中搜索`loop1`。或者，您可以使用管道一步完成如下操作：

![命令管道](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-sh-scp-bc/img/B07040_04_02.jpg)

很酷，对吧？这是 Linux 系统中非常强大的功能，并且被广泛使用。我们很快将看到更多。

接下来的部分显示了另一个非常简短的使用一些命令管道的脚本。它清除屏幕，然后仅显示`dmesg`的前 10 行：

## 第四章 - 脚本 2

```
#!/bin/sh
#
# 5/8/2017
#
tput clear
dmesg | head
```

以下是输出：

![第四章 - 脚本 2](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-sh-scp-bc/img/B07040_04_03.jpg)

接下来的部分显示文件重定向。

## 第四章 - 脚本 3

```
#!/bin/sh
#
# 5/8/2017
#
FN=/tmp/dmesg.txt
dmesg > $FN
echo "File $FN created."
exit 0
```

在您的系统上试一试。

这显示了创建一个脚本来执行通常在命令行上键入的命令是多么容易。还要注意`FN`变量的使用。如果以后要使用不同的文件名，您只需在一个地方进行更改。

# 子程序

现在让我们真正进入子程序。为此，我们将使用更多的`tput`命令：

```
tput cup <row><col>         # moves the cursor to row, col
tput cup 0 0                # cursor to the upper left hand side
tput cup $LINES $COLUMNS    # cursor to bottom right hand side
tput clear                  # clears the terminal screen
tput smso                   # bolds the text that follows
tput rmso                   # un-bolds the text that follows
```

这是脚本。这主要是为了展示子程序的概念，但也可以作为编写交互式工具的指南使用。

## 第四章 - 脚本 4

```
#!/bin/sh
# 6/13/2017
# script4

# Subroutines
cls()
{
 tput clear
 return 0
}

home()
{
 tput cup 0 0
 return 0
}

end()
{
 let x=$COLUMNS-1
 tput cup $LINES $x
 echo -n "X"                 # no newline or else will scroll
}

bold()
{
 tput smso
}

unbold()
{
 tput rmso
}

underline()
{
 tput smul
}

normalline()
{
 tput rmul
}

# Code starts here
rc=0                         # return code
if [ $# -ne 1 ] ; then
 echo "Usage: script4 parameter"
 echo "Where parameter can be: "
 echo " home      - put an X at the home position"
 echo " cls       - clear the terminal screen"
 echo " end       - put an X at the last screen position"
 echo " bold      - bold the following output"
 echo " underline - underline the following output"
 exit 255
fi

parm=$1                      # main parameter 1

if [ "$parm" = "home" ] ; then
 echo "Calling subroutine home."
 home
 echo -n "X"
elif [ "$parm" = "cls" ] ; then
 cls
elif [ "$parm" = "end" ] ; then
 echo "Calling subroutine end."
 end
elif [ "$parm" = "bold" ] ; then
 echo "Calling subroutine bold."
 bold
 echo "After calling subroutine bold."
 unbold
 echo "After calling subroutine unbold."
elif [ "$parm" = "underline" ] ; then
 echo "Calling subroutine underline."
 underline
 echo "After subroutine underline."
 normalline
 echo "After subroutine normalline."
else
 echo "Unknown parameter: $parm"
 rc=1
fi

exit $rc
```

以下是输出：

![第四章 - 脚本 4](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-sh-scp-bc/img/B07040_04_04.jpg)

在您的系统上尝试一下。如果您使用`home`参数运行它，可能会对您看起来有点奇怪。代码在`home 位置`（0,0）放置了一个大写的`X`，这会导致提示打印一个字符。这里没有错，只是看起来有点奇怪。如果这对您来说仍然不合理，不要担心，继续查看*脚本 5*。

# 使用参数

好的，让我们向这个脚本添加一些例程，以展示如何在`子例程`中使用参数。为了使输出看起来更好，首先调用`cls`例程清除屏幕：

## 第四章 - 脚本 5

```
#!/bin/sh
# 6/13/2017
# script5

# Subroutines
cls()
{
 tput clear
 return 0
}

home()
{
 tput cup 0 0
 return 0
}

end()
{
 let x=$COLUMNS-1
 tput cup $LINES $x
 echo -n "X"                 # no newline or else will scroll
}

bold()
{
 tput smso
}

unbold()
{
 tput rmso
}

underline()
{
 tput smul
}

normalline()
{
 tput rmul
}

move()                       # move cursor to row, col
{
 tput cup $1 $2
}

movestr()                    # move cursor to row, col
{
 tput cup $1 $2
 echo $3
}

# Code starts here
cls                          # clear the screen to make the output look better
rc=0                         # return code
if [ $# -ne 1 ] ; then
 echo "Usage: script5 parameter"
 echo "Where parameter can be: "
 echo " home      - put an X at the home position"
 echo " cls       - clear the terminal screen"
 echo " end       - put an X at the last screen position"
 echo " bold      - bold the following output"
 echo " underline - underline the following output"
 echo " move      - move cursor to row,col"
 echo " movestr   - move cursor to row,col and output string"
 exit 255
fi

parm=$1                      # main parameter 1

if [ "$parm" = "home" ] ; then
 home
 echo -n "X"
elif [ "$parm" = "cls" ] ; then
 cls
elif [ "$parm" = "end" ] ; then
 move 0 0
 echo "Calling subroutine end."
end
elif [ "$parm" = "bold" ] ; then
 echo "Calling subroutine bold."
 bold
 echo "After calling subroutine bold."
 unbold
 echo "After calling subroutine unbold."
elif [ "$parm" = "underline" ] ; then
 echo "Calling subroutine underline."
 underline
 echo "After subroutine underline."
 normalline
 echo "After subroutine normalline."
elif [ "$parm" = "move" ] ; then
 move 10 20
 echo "This line started at row 10 col 20"
elif [ "$parm" = "movestr" ] ; then
 movestr 15 40 "This line started at 15 40"
else
 echo "Unknown parameter: $parm"
 rc=1
fi

exit $rc
```

由于此脚本只有两个额外的功能，您可以直接运行它们。这将逐个命令显示如下：

```
guest1 $ script5
```

![第四章-脚本 5](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-sh-scp-bc/img/B07040_04_05.jpg)

```
guest1 $ script5 move
```

![第四章-脚本 5](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-sh-scp-bc/img/B07040_04_06.jpg)

```
guest1 $ script5 movestr
```

![第四章-脚本 5](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-sh-scp-bc/img/B07040_04_07.jpg)

由于我们现在将光标放在特定位置，输出对您来说应该更有意义。请注意，命令行提示重新出现在上次光标位置的地方。

您可能已经注意到，子例程的参数与脚本的参数工作方式相同。参数 1 是`$1`，参数 2 是`$2`，依此类推。这既是好事也是坏事，好的是您不必学习任何根本不同的东西。但坏的是，如果不小心，很容易混淆`$1`，`$2`等变量。

一个可能的解决方案，也是我使用的解决方案，是将主脚本中的`$1`，`$2`等变量分配给一个有意义的变量。

例如，在这些示例脚本中，我将`parm1`设置为`$1（parm1=$1）`，依此类推。

请仔细查看下一节中的脚本：

## 第四章-脚本 6

```
#!/bin/sh
#
# 6/13/2017
# script6

# Subroutines
sub1()
{
 echo "Entering sub1"
 rc1=0                       # default is no error
 if [ $# -ne 1 ] ; then
  echo "sub1 requires 1 parameter"
  rc1=1                      # set error condition
 else
  echo "1st parm: $1"
 fi

 echo "Leaving sub1"
 return $rc1                 # routine return code
}

sub2()
{
 echo "Entering sub2"
 rc2=0                       # default is no error
 if [ $# -ne 2 ] ; then
  echo "sub2 requires 2 parameters"
  rc2=1                      # set error condition
 else
  echo "1st parm: $1"
  echo "2nd parm: $2"
 fi
 echo "Leaving sub2"
 return $rc2                 # routine return code
}

sub3()
{
 echo "Entering sub3"
 rc3=0                       # default is no error
 if [ $# -ne 3 ] ; then
  echo "sub3 requires 3 parameters"
  rc3=1                      # set error condition
 else
  echo "1st parm: $1"
  echo "2nd parm: $2"
  echo "3rd parm: $3"
 fi
 echo "Leaving sub3"
 return $rc3                 # routine return code
}

cls()                        # clear screen
{
 tput clear
 return $?                   # return code from tput
}

causeanerror()
{
 echo "Entering causeanerror"
 tput firephasers
 return $?                   # return code from tput
}

# Code starts here
cls                          # clear the screen
rc=$?
echo "return code from cls: $rc"
rc=0                         # reset the return code
if [ $# -ne 3 ] ; then
 echo "Usage: script6 parameter1 parameter2 parameter3"
 echo "Where all parameters are simple strings."
 exit 255
fi

parm1=$1                     # main parameter 1
parm2=$2                     # main parameter 2
parm3=$3                     # main parameter 3

# show main parameters
echo "parm1: $parm1  parm2: $parm2  parm3: $parm3"

sub1 "sub1-parm1"
echo "return code from sub1: $?"

sub2 "sub2-parm1"
echo "return code from sub2: $?"

sub3 $parm1 $parm2 $parm3
echo "return code from sub3: $?"

causeanerror
echo "return code from causeanerror: $?"

exit $rc
```

以下是输出

![第四章-脚本 6](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-sh-scp-bc/img/B07040_04_08.jpg)

这里有一些新概念，所以我们会非常仔细地讲解这个。

首先，我们定义了子例程。请注意，已添加了返回代码。还包括了一个`cls`例程，以便显示返回代码。

我们现在开始编码。调用`cls`例程，然后将其返回值存储在`rc`变量中。然后将显示显示脚本标题的`echo`语句。

那么，为什么我必须将`cls`命令的返回代码放入`rc`变量中呢？我不能在显示脚本标题的`echo`之后直接显示它吗？不行，因为`echo $?`总是指的是紧随其后的命令。这很容易被忘记，所以请确保您理解这一点。

好的，现在我们将`rc`变量重置为`0`并继续。我本可以使用不同的变量，但由于`rc`的值不会再次需要，我选择重用`rc`变量。

现在，在检查参数时，如果没有三个参数，将显示`Usage`语句。

输入三个参数后，我们会显示它们。这总是一个好主意，特别是在首次编写脚本/程序时。如果不需要，您随时可以将其删除。

第一个子例程`sub1`以`1`个参数运行。这将进行检查，如果需要，将显示错误。

`sub2`也是一样的情况，但在这种情况下，我故意设置它只运行一个参数，以便显示错误消息。

对于`sub3`，您可以看到主要参数仍然可以从子例程中访问。实际上，所有命名变量都可以访问，还有通配符`*`和其他文件扩展标记。只有主脚本参数无法访问，这就是为什么我们将它们放入变量中的原因。

最后，创建了最终例程以展示如何处理错误。您可以看到，`tput`命令本身显示了错误，然后我们还在脚本中捕获了它。

最后，脚本以主`rc`变量退出。

正如前面提到的，这个脚本包含了很多内容，所以一定要仔细研究它。请注意，当我想在`tput`中显示错误时，我只是假设`firephasers`将成为一个未知的命令。如果一些相位器实际上从我的计算机中射出（或更糟的是，射入），我会感到非常惊讶！

# 备份您的工作

现在，作为另一个奖励，下一节显示了我用来每 60 秒备份当前书籍章节的脚本：

## 第四章-脚本 7

```
#!/bin/sh
#
# Auto backs up the file given if it has changed
# Assumes the cbS command exists
# Checks that ../back exists
# Copies to specific USB directory
# Checks if filename.bak exists on startup, copy if it doesn't

echo "autobackup by Lewis 5/9/2017 A"
if [ $# -ne 3 ] ; then
 echo "Usage: autobackup filename USB-backup-dir delay"
 exit 255
fi

# Create back directory if it does not exist
if [ ! -d back ] ; then
 mkdir back
fi

FN=$1                        # filename to monitor
USBdir=$2                    # USB directory to copy to
DELAY=$3                     # how often to check

if [ ! -f $FN ] ; then       # if no filename abort
 echo "File: $FN does not exist."
 exit 5
fi

if [ ! -f $FN.bak ] ; then
 cp $FN $FN.bak
fi

filechanged=0
while [ 1 ]
do
 cmp $FN $FN.bak
 rc=$?
 if [ $rc -ne 0 ] ; then
  cp $FN back
  cp $FN $USBdir
  cd back
  cbS $FN
  cd ..
  cp $FN $FN.bak
  filechanged=1
 fi

 sleep $DELAY
done
```

在我的系统上的输出

![第四章-脚本 7](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-sh-scp-bc/img/B07040_04_09.jpg)

这个脚本中没有我们尚未涵盖的内容。顶部的非正式注释主要是为了我自己，这样我就不会忘记我写了什么或为什么写了。

检查参数并在不存在时创建后备子目录。我似乎总是记不住要创建它，所以我让脚本来做。

接下来，设置了主要变量，然后如果`.bak`文件不存在就创建它（这有助于逻辑）。

在`while`循环中，你可以看到它永远运行，使用`cmp` Linux 命令来查看原始文件是否与备份文件发生了变化。如果是，`cmp`命令返回非零值，文件将使用我们的`cbS`脚本作为带编号的备份复制回`subdir`。该文件也会被复制到备份目录，这种情况下是我的 USB 驱动器。循环会一直持续，直到我开始新的章节，这时我按下*Ctrl* + *C*退出。

这是脚本自动化的一个很好的例子，将在第六章*使用脚本自动化任务*中更详细地介绍。

# 总结

我们从一些非常简单的脚本开始，然后继续展示一些简单的子程序。

然后我们展示了一些带参数的子程序。再次提到了返回码，以展示它们在子程序中的工作原理。我们包括了几个脚本来展示这些概念，并且还额外免费包含了一个特别的奖励脚本。

在下一章中，我们将介绍如何创建交互式脚本。
