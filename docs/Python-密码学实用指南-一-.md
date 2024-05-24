# Python 密码学实用指南（一）

> 原文：[`zh.annas-archive.org/md5/fe5e9f4d664790ea92fb33d78ca9108d`](https://zh.annas-archive.org/md5/fe5e9f4d664790ea92fb33d78ca9108d)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

密码学在保护关键系统和敏感信息方面有着悠久而重要的历史。本书将向您展示如何使用 Python 加密、评估、比较和攻击数据。总的来说，本书将帮助您处理加密中的常见错误，并向您展示如何利用这些错误。

# 这本书适合谁

这本书适用于希望学习如何加密数据、评估和比较加密方法以及如何攻击它们的安全专业人员。

# 本书内容

第一章，*混淆*，介绍了凯撒密码和 ROT13，简单的字符替换密码，以及 base64 编码。然后我们转向 XOR。最后，有一些挑战来测试您的学习，包括破解凯撒密码、反向 base64 编码和解密 XOR 加密而不使用密钥。

第二章，*哈希*，介绍了较旧的 MD5 和较新的 SHA 哈希技术，以及 Windows 密码哈希。最弱的哈希类型是常见的使用，其次是 Linux 密码哈希，这是常见使用中最强大的哈希类型。之后，有一些挑战需要完成。首先是破解一些 Windows 哈希并恢复密码，然后您将被要求破解哈希，甚至不知道使用了多少轮哈希算法，最后您将被要求破解那些强大的 Linux 哈希。

第三章，*强加密*，介绍了当今用于隐藏数据的主要模式。它足够强大，可以满足美国军方的需求。然后，介绍了它的两种模式，ECB 和 CBC；CBC 是更强大和更常见的模式。我们还将讨论填充预言攻击，这使得可能克服 AES CBC 的一些部分，如果设计者犯了错误，并且过于详细的错误消息向攻击者提供了信息。最后，我们介绍了 RSA，这是当今主要的公钥算法，它使得可以在不交换给定私钥的情况下通过不安全的通道发送秘密信息。在此之后，我们将进行一个挑战，我们将破解 RSA，即当它错误地使用两个相似的质数而不是两个随机质数时。

# 充分利用本书

您不需要有编程经验或任何特殊的计算机。任何能运行 Python 的计算机都可以完成这些项目，您也不需要太多的数学，因为我们不会发明新的加密技术，只是学习如何使用现有的标准加密技术，这些技术不需要比基本代数更多的东西。

# 下载本书的示例代码文件

您可以从[www.packtpub.com](http://www.packtpub.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了这本书，您可以访问[www.packtpub.com/support](http://www.packtpub.com/support)注册，直接将文件发送到您的邮箱。

您可以按照以下步骤下载代码文件：

1.  在[www.packtpub.com](http://www.packtpub.com/support)上登录或注册。

1.  选择“支持”选项卡。

1.  点击“代码下载和勘误”。

1.  在搜索框中输入书名，然后按照屏幕上的说明操作。

下载文件后，请确保使用最新版本的解压缩软件解压缩文件夹：

+   WinRAR/7-Zip for Windows

+   Mac 的 Zipeg/iZip/UnRarX

+   Linux 的 7-Zip/PeaZip

该书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Hands-On-Cryptography-with-Python`](https://github.com/PacktPublishing/Hands-On-Cryptography-with-Python)。如果代码有更新，将在现有的 GitHub 存储库上进行更新。

我们还有其他代码包，来自我们丰富的图书和视频目录，可在[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)上找到。去看看吧！

# 下载彩色图片

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图像。您可以在这里下载：[`www.packtpub.com/sites/default/files/downloads/HandsOnCryptographywithPython_ColorImages.pdf`](https://www.packtpub.com/sites/default/files/downloads/HandsOnCryptographywithPython_ColorImages.pdf)。

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。这是一个例子："如果我们输入`HELLO`，它会打印出`KHOOR`的正确答案。"

代码块设置如下：

```py
alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
str_in = raw_input("Enter message, like HELLO: ")

n = len(str_in)
str_out = ""

for i in range(n):
   c = str_in[i]
   loc = alpha.find(c)
   print i, c, loc, 
   newloc = loc + 3
   str_out += alpha[newloc]
   print newloc, str_out

print "Obfuscated version:", str_out
```

任何命令行输入或输出都以以下形式编写：

```py
$ python
```

**粗体**：表示新术语、重要单词或屏幕上看到的单词。例如，菜单或对话框中的单词会在文本中显示为这样。这是一个例子："从管理面板中选择系统信息"。

警告或重要说明会以这种方式出现。提示和技巧会以这种方式出现。


# 第一章：混淆

Python 是最适合初学者的语言，这也是它如此受欢迎的原因。您可以用几行代码编写强大的代码，最重要的是，您可以完全精确地处理任意大的整数。本书涵盖了基本的密码学概念；经典的加密方法，如凯撒密码和 XOR；混淆和扩散的概念，决定了加密系统的强度；使用混淆隐藏数据；对数据进行哈希以确保完整性和密码；以及强大的加密方法和对这些方法的攻击，包括填充预言攻击。您不需要有编程经验来学习这些内容。您不需要任何特殊的计算机；任何可以运行 Python 的计算机都可以完成这些项目。我们不会发明新的加密技术，只是学习如何使用标准的现有技术，这些技术不需要任何比基本代数更复杂的东西。

我们将首先处理混淆，即加密的基本概念，以及隐藏数据以使其更难阅读的老式加密技术。后一种过程是加密模块与其他方法结合使用以制定更强大、更现代的加密技术的基本活动之一。

在本章中，我们将涵盖以下主题：

+   关于密码学

+   安装和设置 Python

+   凯撒密码和 ROT13

+   base64 编码

+   XOR

# 关于密码学

最近，随着所有货币（如比特币、以太坊和莱特币）的引入，密码一词变得过载。当我们将密码称为一种保护形式时，我们指的是应用于系统中的通信链路、存储设备、软件和消息的密码学概念。密码学在保护关键系统和敏感信息方面具有悠久而重要的历史。

在第二次世界大战期间，德国人使用 Enigma 机器加密通信，而盟军则竭尽全力破译这种加密。Enigma 机器使用一系列转子将明文转换为密文，通过了解转子的位置，盟军能够将密文解密为明文。这是一个重大的成就，但需要大量的人力和资源。今天仍然有可能破解某些加密技术；然而，攻击加密系统的其他方面，如协议、集成点甚至用于实现加密的库，往往更为可行。

密码学有着悠久的历史；然而，如今，您将遇到新概念，如区块链，可以用作帮助保护物联网的工具。区块链基于一组众所周知的密码原语。密码学的其他新方向包括抗量子算法，这些算法可以抵御理论上的量子计算机的攻击，并使用诸如 BB84 和 BB92 之类的协议来利用量子纠缠的概念，并为使用经典加密算法创建高质量的密钥。

# 安装和设置 Python

Python 从来都不容易安装。为了继续，请确保我们已经在我们的机器上设置了 Python。我们将看到如何在 macOS 或 Linux 上使用 Python 以及如何在 Windows 上安装它。

# 在 Mac 或 Linux 上使用 Python

在 macOS 或 Linux 系统上，您无需安装 Python，因为它已经包含在内。您只需要打开一个终端窗口并输入`python`命令。这将使您进入交互模式，在这里您可以逐个执行`python`命令。您可以通过执行`exit()`命令来关闭交互模式。因此，基本上，要创建一个脚本，我们使用`nano`文本编辑器，然后输入文件名。然后输入`python`命令并保存文件。然后可以使用`python`后跟脚本名称来运行脚本。因此，让我们看看如何在 macOS 或 Linux 上使用 Python，以下是具体步骤：

1.  在 macOS 或 Linux 系统上打开终端并运行`python`命令。这将打开 Python 的交互模式，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00005.jpeg)

1.  当你使用`print`命令时，它会立即打印`Hello`：

```py
>>> print "Hello"
Hello
```

1.  然后，我们将使用以下命令离开：

```py
>>> exit()
```

1.  如前所述，要在交互模式下使用 Python，我们将输入如下命令：

```py
$ nano hello.py
```

1.  在`hello.py`文件中，我们可以写入如下命令：

```py
print "HELLO"
```

1.  按*Ctrl* + *X*保存文件，然后只有在你修改了文件后才按*Y*和*Enter*。

1.  现在，让我们输入 Python，然后输入脚本名称：

```py
$ python hello.py
```

当你运行它时，你会得到以下输出：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00006.jpeg)

前面的命令运行脚本并打印出`HELLO`；如果你有 macOS 或 Linux 系统，这就是你所需要做的。

# 在 Windows 上安装 Python

如果你使用 Windows，你需要下载并安装 Python。

以下是你需要遵循的步骤：

1.  从[`www.python.org/downloads/`](https://www.python.org/downloads/)下载 Python

1.  在命令提示符窗口中运行它

1.  用 Python 开始交互模式

1.  使用`exit()`关闭

要创建一个脚本，你只需使用记事本，输入文本，用*Ctrl* + *S*保存文件，然后用`python`后跟脚本名称运行它。让我们开始安装。

使用之前给出的链接打开 Python 页面并下载 Python。它为您提供各种版本的 Python。在本书中，我们将使用 Python 2.7.12。

有时，你无法立即安装它，因为 Windows 将其标记为不受信任：

1.  你必须先在属性中解除阻止，这样它才能运行，并运行安装程序

1.  当你按照安装程序的步骤进行时，你会看到一个名为 Add python.exe to path 的可选步骤。你需要选择那个选项

该选项的目的是使 Python 能够在终端窗口中从命令行运行，Windows 上称为命令提示符。

现在让我们继续我们的安装：

1.  打开终端并输入以下命令：

```py
$ python
```

1.  当你运行它时，你会看到它有效。所以，现在我们将输入一个命令：

```py
print "HELLO"
```

参考以下截图：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00007.jpeg)

1.  我们可以使用之前显示的`exit()`命令退出。

1.  现在，如果我们想要制作一个脚本，我们输入以下命令：

```py
notepad hello.py
```

1.  这将打开记事本：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00008.jpeg)

1.  我们想要创建一个文件。在文件中，我们输入以下命令：

```py
print "HELLO"
```

1.  然后保存并关闭它。为了运行它，我们需要输入以下命令：

```py
$ python hello.py
```

它运行并打印`HELLO`。

通常，当你在 Windows 上安装 Python 时，它无法正确设置路径，所以你必须执行以下命令来创建一个符号链接；否则，Python 将无法从命令行正确启动：

1.  `**cd c: \Windows**`

1.  `**mklink /H python.exe**`

1.  `**c: \python27\python.exe**`

在下一节中，我们将看看凯撒密码和 ROT13 混淆技术。

# 凯撒密码和 ROT13

在本节中，我们将解释什么是凯撒密码以及如何在 Python 中实现它。然后，我们将考虑其他`shift`值，模运算和 ROT13。

凯撒密码是一个古老的技巧，你只需将字母向字母表中的后三个字符移动。这是一个例子：

+   明文：`ABCDEFGHIJKLMNOPQRSTUVWXYZ`

+   密文：`DEFGHIJKLMNOPQRSTUVWXYZABC`

所以，`HELLO`变成了`KHOOR`。

为了实现它，我们将使用`string.find()`方法。Python 的交互模式非常适合测试新方法，因此很容易创建一个字符串。你可以制作一个非常简单的脚本来实现凯撒密码，使用一个名为`alpha`的字符串来表示字母表。然后你可以从用户那里获取输入，这就是明文方法，然后设置一个值`n`，它等于字符串的长度，字符串输出等于一个空字符串。然后我们有一个循环，它重复了`n`次，找到字符串中的字符，然后找到该字符在`alpha`字符串中的位置。然后打印出这三个值，以便我们可以确保脚本正常工作，然后它将`loc`（位置）加上`3`，并将相应的字符放入字符串输出中，然后再次打印出部分值，以便我们可以看到脚本是否正常工作。最后，我们打印出最终的输出。添加额外的打印语句是开始编程的一个很好的方法，因为你可以发现错误。

# 在 Python 中实现凯撒密码

让我们继续打开终端，并按照以下步骤在 Python 中实现凯撒密码：

1.  我们将首先在 Python 的交互模式下使用它，然后制作一个只包含一些字母的字符串来测试这种方法：

```py
>>> str = "ABCDE"
>>> str.find("A")
0
>>> str.find("B")
1
>>> exit()
```

1.  因为我们了解了字符串方法的工作原理，我们将退出并进入`nano`文本编辑器，查看我们脚本的第一个版本：

```py
$ nano caesar1.py
```

1.  当你运行这个命令时，你会得到以下代码：

```py
alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
str_in = raw_input("Enter message, like HELLO: ")

n = len(str_in)
str_out = ""

for i in range(n):
   c = str_in[i]
   loc = alpha.find(c)
   print i, c, loc, 
   newloc = loc + 3
   str_out += alpha[newloc]
   print newloc, str_out

print "Obfuscated version:", str_out
```

你可以在脚本中看到字母表和用户输入。你计算字符串的长度，对于每个字符，`C`将是正在处理的一个字符，`loc`将是该字符的数字位置，`newloc`将是`loc`加上`3`，然后我们可以将该字符添加到字符串输出中。让我们看看这个。

1.  使用*Ctrl*+*X*离开，然后输入以下命令：

```py
$ python caesar1.py
```

1.  当你运行这个命令时，你会得到以下输出：

```py
Enter message, like HELLO:
```

1.  如果我们输入`HELLO`，它会打印出`KHOOR`的正确答案：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00009.jpeg)

当我们运行这个脚本时，它接受`HELLO`的输入，并将其逐个字符地分解开来，以便对每个字符进行处理。`H`被发现是第 7 个字符，所以加上`3`得到`10`，结果是`K`。它逐个字符地显示了它的工作原理。因此，脚本的第一个版本是成功的。

为了进一步清理代码，我们将删除不必要的`print`语句并切换到`shift`变量。我们将创建一个`shift`变量。它也来自原始输入，但我们必须将其转换为整数，因为原始输入被解释为`文本`，您不能将`文本`添加到整数。这是接下来的脚本中唯一的更改。如果您给它一个`3`的`shift`值，您会得到`KHOOR`；如果您给它一个`10`的`shift`值，您会得到`ROVVY`；但如果您输入一个`14`的`shift`值，它会崩溃，显示字符串索引超出范围。这里的问题是，我们已经多次添加到`loc`变量，最终，我们超过了`Z`，变量就不再有效了。为了改进这一点，在向变量添加内容后，我们将检查它是否大于或等于`26`，以及是否可以从中减去`26`。一旦您运行这个，您可以使用`14`的移位，这将起作用。我们可以使用`24`的移位，它也可以工作。但是，如果我们使用`44`的移位，它又超出范围了。这是因为当超过`26`时，仅仅减去`26`一次并不够，正确的解决方案是模运算。如果我们加上`％26`，它将计算数字模`26`，这将防止它离开`0`到`25`的范围。它将除以`26`并保留余数，这在这种情况下是预期的。随着我们在密码学中继续前进，我们将看到模函数更多次。您可以输入任何您选择的`shift`值，比如`300`，它永远不会崩溃，但会将其转换为`0`到`25`之间的数字。

让我们看看脚本如何处理其他移位值：

1.  看看凯撒脚本：

```py
$ nano caesar2.py
```

1.  运行它时，您将得到以下内容：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00010.jpeg)

1.  这是一个允许我们改变`shift`值但不处理`shift`值变得太大的脚本。让我们运行以下命令：

```py
$ python caesar2.py
```

1.  如果输入`HELLO`并给它一个`3`的移位，它是好的，但如果我们再次运行它并给它一个`20`的移位，它就会崩溃：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00011.jpeg)

因此，预料之中，这个有一些限制。

1.  让我们继续看`caesar3`：

```py
$ nano caesar3.py
```

1.  运行后，我们得到以下输出：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00012.jpeg)

`Caesar3`试图通过捕捉它来解决这个问题，如果我们知道加法导致它大于或等于`26`，则从中减去`26`。

1.  让我们运行以下命令：

```py
$ python caesar3.py
```

1.  我们将给它`shift`字符和`shift`为`20`，它会很好：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00013.jpeg)

1.  如果我们给它一个`40`的偏移量，它就不起作用：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00014.jpeg)

有一些改进，但我们仍然无法处理任何`shift`值。

1.  让我们继续到`caesar4`：

```py
$ nano caesar4.py
```

1.  当您运行命令时，您将得到这个：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00015.jpeg)

这是使用百分号进行模运算的脚本，这不会失败。

1.  让我们运行以下命令：

```py
$ python caesar4.py
```

1.  当您运行命令时，您将得到这个：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00016.jpeg)

这是处理所有凯撒移位值的脚本。

# ROT13

ROT13 只不过是一个`shift`等于`13`个字符的凯撒密码。在接下来的脚本中，我们将硬编码移位为`13`。如果您运行一次 ROT13，它会将`HELLO`更改为`URYYB`，如果您再次使用相同的过程对其进行加密，输入`URYYB`，它将变回`HELLO`，因为第一个移位只是`13`个字符，再移位`13`个字符将总移位变为`26`，这样就可以很好地包裹，这就是这个脚本有用和重要的地方：

1.  现在让我们看一下使用以下命令的 ROT13 脚本：

```py
$ nano rot13.py
```

1.  当您运行上述命令时，您可以看到脚本文件：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00017.jpeg)

1.  它与我们上次凯撒密码移位的脚本完全相同，移位为`13`。按照这里所示的脚本运行：

```py
$ python rot13.py
```

以下是输出：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00018.jpeg)

1.  如果我们输入消息`URYYB`并运行它，它会变回`HELLO`：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00019.jpeg)

这很重要，因为有很多具有这种属性的加密函数；当你加密一次然后再次加密时，你会反转这个过程。它不会变得更加加密，而是变得未加密。在下一节中，我们将涵盖 base64 编码。

# base64 编码

我们现在将讨论将 ASCII 数据编码为字节，并对这些字节进行 base64 编码。我们还将涵盖二进制数据的 base64 编码和解码，以恢复原始输入。

# ASCII 数据

在 ASCII 中，每个字符变成一个字节：

+   `A`在十进制中是`65`，在二进制中是`0b01000001`。这里，你在最高位没有`128`，然后在下一个位上有`64`的`1`，最后有`1`，所以你有*64 + 1=65*。

+   接下来是`B`，基数为`66`，`C`，基数为`67`。`B`的二进制是`0b01000010`，`C`的二进制是`0b01000011`。

三个字母的字符串`ABC`可以解释为一个 24 位的字符串，看起来像这样：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00020.gif)

我们添加了这些蓝线只是为了显示字节的分隔位置。要将其解释为 base64，你需要将其分成 6 位一组。6 位有 64 种组合，所以你需要 64 个字符来编码它。

使用的字符如下：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00021.jpeg)

我们使用大写字母表示前 26 个，小写字母表示另外 26 个，数字表示另外 10 个，总共 62 个字符。在最常见的 base64 形式中，最后两个字符使用`+`和`/`：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00022.gif)

如果你有一个 ASCII 字符串有三个字符，它变成 24 位，解释为 3 组 8 位。如果你把它们分成 4 组 6 位，你有 4 个 0 到 63 之间的数字，在这种情况下，它们变成`Q`、`U`、`J`和`D`。在 Python 中，你只需要一个字符串，后面跟着命令：

```py
>>> "ABC".encode("base64")
'QUJD\n'
```

这将进行编码。然后在最后添加一个额外的回车，这既不重要也不影响解码。

如果你有的不是 3 个字节的组合呢？

等号`=`用于指示填充，如果输入字符串长度不是 3 个字节的倍数。

如果输入有四个字节，那么 base64 编码以两个等号结束，只是表示它必须添加两个填充字符。如果有五个字节，就有一个等号，如果有六个字节，那么就没有等号，表示输入完全适合 base64，不需要填充。填充是空的。

你取`ABCD`进行编码，然后你取`ABCD`并加上一个显式的零字节。`x00`表示一个具有八位零的单个字符，你得到相同的结果，只是多了一个`A`和一个等号，如果你用两个零字节填满它，你会得到大写的`A`。记住：大写的`A`是`base64`中的第一个字符。它代表六位零。

让我们来看看 Python 中的 base64 编码：

1.  我们将启动`python`并创建一个字符串。如果你只是用引号创建一个字符串并按*Enter*，它会立即打印出来：

```py
>>> "ABC"
'ABC'
```

1.  Python 会自动打印每次计算的结果。如果我们用`base64`对其进行编码，我们会得到这个结果：

```py
>>> "ABC".encode(""base64")
'QUJD\n'
```

1.  它变成`QUJD`，最后有一个额外的回车，如果我们让它更长：

```py
>>> "ABCD".encode("base64")
'QUJDRA==\n'
```

1.  这里有两个等号，因为我们从四个字节开始，它必须再添加两个字节使其成为 3 的倍数：

```py
>>> "ABCDE".encode("base64")
'QUJDREU=\n'
>>> "ABCDEF".encode("base64")
'QUJDREVG\n'
```

1.  有五个字节的输入，我们有一个等号；有六个字节的输入，我们没有等号，而是一共有八个字符使用`base64`。

1.  让我们回到带有两个等号的`ABCD`：

```py
>>>"ABCD".encode("base64")
'QUJDRA==\n'
```

1.  你可以看到填充是如何通过在这里明确放置它来完成的：

```py
>>> "ABCD\x00\x00".encode("base64")
'QUJDRAA=\n'
```

有一个零的第一个字节，现在我们得到另一个单个等号。

1.  让我们再加入一个字节的零：

```py
>>> "ABCD\x00\x00".encode("base64")
'QUJDRAAA\n'
```

这里没有填充，我们看到最后的字符都是`A`，表明已经填充了二进制零。

# 二进制数据

下一个问题是处理二进制数据。可执行文件是二进制的，而不是 ASCII。此外，图像、电影和许多其他文件都包含二进制数据。ASCII 数据始终以第一个位为零开始，但`base64`可以很好地处理二进制数据。这是一个常见的可执行文件，一个法医实用程序；它以`MZê`开头，并且有不可打印的 ASCII 字符：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00023.jpeg)

由于这是一个十六进制查看器，您可以看到十六进制的原始数据，在右侧，它尝试将其打印为 ASCII。Windows 程序在开头有这个字符串，并且这个程序不能在 DOS 模式下运行，但它们有很多不可打印的字符，比如`FF`和`0`，这对 Python 来说并不重要。像这样编码数据的简单方法是直接从文件中读取它。您可以使用`with`命令。它将使用文件名和读取二进制模式打开一个文件，并使用句柄`f`读取它。`with`命令在这里只是告诉 Python 打开文件，并且如果由于某些错误无法打开文件，则关闭句柄，然后以完全相同的方式解码它。要解码以这种方式编码的数据，只需取输出字符串，并将`.encode`替换为`.decode`。

现在让我们看看如何处理二进制数据：

1.  我们将首先退出 Python，以便我们可以查看文件系统，然后我们将使用以下命令查找`Ac`文件：

```py
>>> exit()
$ ls Ac*
AccessData Registry Viewer_1.8.3.exe
```

这是文件名。由于这是一个比较长的块，我们只需复制并粘贴它。

1.  现在我们启动 Python 并使用以下命令`clear`屏幕：

```py
$ clear
```

1.  我们将重新开始`python`：

```py
$ python
```

1.  好的，现在我们使用以下命令：

```py
>>> with open("AccessData Registry Viewer_1.8.3.exe", "rb") as f:
... data = f.read()
... print data.encode("base64")
```

这里我们首先输入文件名，然后是读取二进制模式。我们将给它一个文件名句柄`f`。我们将获取所有数据并将其放入一个单一变量数据中。我们可以只对数据进行`base64`编码，它会自动打印出来。如果您在 Python 中有一个预期的块，您必须按*Enter*键两次，以便它知道块已完成，然后`base64`对其进行编码。

1.  您会得到一个很长的`base64`块，这不太可读，但这是处理这种数据的一种方便方式；比如，如果您想要通过电子邮件发送它或将其放入其他文本格式中。因此，为了进行解码，让我们编码一些更简单的东西，以便我们可以轻松地看到结果：

```py
>>> "ABC".encode("base64")
'QUJD\n'
```

1.  如果我们想要使用它，可以使用以下命令将其放入一个`c`变量中：

```py
>>> c = "ABC".encode("base64")
>>> print c
QUJD
```

1.  现在我们可以打印`c`以确保我们得到了预期的结果。我们有`QUJD`，这是我们预期的结果。所以，现在我们可以使用以下命令对其进行解码：

```py
>>> c.decode("base64")
'ABC'
```

`base64`不是加密。它不隐藏任何东西，而只是另一种表示方法。在下一节中，我们将介绍 XOR。

# XOR

本节解释了 XOR 在单个位上的真值表，然后展示了如何在字节上进行操作。XOR 可以撤销自身，因此解密与加密是相同的操作。您可以使用单个字节或多个字节密钥进行 XOR，并且我们将使用循环来测试密钥。以下是 XOR 的真值表：

+   `0 ^ 0 = 0`

+   `0 ^ 1 = 1`

+   `1 ^ 0 = 1`

+   `1 ^ 1 = 0`

如果您输入两个位，并且这两个位相同，则答案是`0`。如果位不同，则答案是`1`。

XOR 一次操作一个位。Python 使用`^`运算符表示 XOR。

真值表显示了它的工作原理。您输入可能是`0`和`1`的位，并将它们进行异或运算，然后最终得到 50%的 1 和 0，这意味着异或不会破坏任何信息。

这是字节的异或：

+   `A 0b01000001`

+   `B 0b01000010`

+   `XOR 0b00000011`

`A`是数字`65`，所以你有`64`的`1`和`1`的`1`；`B`大 1，如果你将它们进行 XOR 操作，所有的位匹配前 6 位，它们都是`0`。最后两位不同，它们变成了`1`。这是二进制值`3`，它不是一个可打印的字符，但你可以将它表示为一个整数。

密钥可以是单字节或多字节。如果密钥是单字节，比如`B`，那么你可以使用相同的字节来加密每个明文字符。只需一直重复使用密钥：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00024.gif)

为这个字节重复`B`，那个字节也是`B`，依此类推。如果密钥是多字节的，那么你就重复这个模式：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00025.gif)

你用`B`代表第一个字节，`C`代表下一个字节，然后再次用`B`代表下一个字节，`C`代表下一个字节，依此类推。

在 Python 中，你需要循环遍历字符串的字节并计算一个索引来显示你所在的字节。然后我们从用户那里输入一些文本，计算它的长度，然后遍历从`1`到字符串长度的索引，从`0`开始。然后我们取文本字节并在这里打印出来，这样你就可以看到循环是如何工作的。所以，如果我们给它一个五个字符的明文，比如`HELLO`，它就会一个接一个地打印出字符。

要进行异或操作，我们将输入一个明文和一个密钥，然后取一个文本字节和一个密钥字节，进行异或操作，然后打印出结果。

注意`%len( key)`，这可以防止你超出密钥的末尾。它将一直重复密钥中的字节。因此，如果密钥是三个字节长，这将是模三，所以它将计数为`0`，`1`，`2`，然后回到`0 1 2 0 1 2`，依此类推。这样，你可以处理任意长度的明文。

如果你结合大写和小写字母，你经常会发现 XOR 产生无法打印的字节的情况。在接下来的例子中，我们使用了`HELLO`，`Kitty`和一个`qrs`的密钥。请注意，其中一些字节是可以打印的，而其中一些包含奇怪的字符，比如*Esc*和*Tab*，这些很难打印。因此，处理输出的最佳方式不是尝试将其作为 ASCII 打印，而是将其作为`hex`编码的值打印。我们不是一个接一个地打印字节，而是将它们组合成一个`cipher`变量，最后，我们以`hex`形式打印出整个明文，整个密钥，然后是整个密文。这样，它可以正确处理这些难以打印的奇怪值。

让我们在 Python 中尝试这个循环：

1.  我们打开终端并输入以下命令：

```py
$ nano xor1.py
```

1.  当你运行它时，你会得到以下输出：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00026.jpeg)

1.  这是第一个`xor1.py`，所以我们从用户那里输入文本，计算它的长度，然后一个接一个地打印出字节，以查看循环是如何工作的。让我们运行它并给它`HELLO`：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00027.jpeg)

1.  它只是一个接一个地打印出字节。现在，让我们看一下下一个 XOR 2：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00028.jpeg)

这里输入`text`和`key`，然后以相同的方式进行处理，遍历`text`的每个字节，使用模运算挑选出`key`的正确字节，执行异或操作，然后打印出结果。

1.  所以如果我们在这里运行相同的文件，我们取`HELLO`和一个`key`如下所示：

```py
$ nano xor2.py
$ python xor2.py
```

因此，输出如下：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00029.jpeg)

它逐个计算字节。请注意，这里我们得到了两个等号，这就是为什么你会使用多字节`key`的原因，因为明文在变化，但密钥也在变化，而这种模式在输出中没有反映出来，所以它是更有效的混淆。

1.  清除并查看第三个`xor2a.py`文件：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00030.jpeg)

这样你就可以看到，这解决了无法打印的字节的问题。

1.  因此，我们创建了一个名为`cipher`的变量，在这里组合了每个输出字节，最后，我们用`hex`编码它，而不是直接尝试将其打印出来：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00031.jpeg)

1.  如果你给它`HELLO`，然后输入一个`qrs`的键，它会给你明文`HELLO Kitty`，键，然后是十六进制编码的输出，这可以轻松处理有趣的字符，比如`0 7`和`0 5`。在下一节中，你将看到挑战 1 – 凯撒密码。

# 挑战 1 – 凯撒密码

经过凯撒密码的复习，我们将有一个解决它的例子，然后是你的挑战。记住凯撒密码是如何工作的。你有一个可用字符的字母表，你输入消息和一个`shift`值，然后你只需将字符向前移动那么多步，如果超出字母表的末尾就回到开头。我们最终得到的脚本适用于任何`shift`值，包括正常的数字，比如`3`，甚至大于`26`的数字；它们只是循环并且可以混淆你输入的任何数据。

这是一个例子：

1.  对于密文，你可以尝试从`0`到`25`的所有`shift`值，其中一个将是可读的。这是一个简单的暴力攻击。让我们来看看。

在这里，在 Python 中，去`caesar4`脚本，我们之前有过。它接受一个字符串并将其按你指定的任何值进行移位。如果我们使用那个脚本，我们可以运行它如下：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00032.jpeg)

1.  然后，如果我们输入`HELLO`并将其移位`3`，它就会变成`KHOOR`。

1.  如果我们想要破解它，我们可以使用以下解决方案脚本：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00033.jpeg)

1.  所以，如果我们使用那个脚本，我们可以运行它：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00034.jpeg)

1.  如果我们输入`KHOOR`，它将以各种值进行移位，你可以看到在`23`时可读的值是`HELLO`。所以，我们之前讨论的更长的密文等等的例子，在`3`时变得可读，你会看到它是`DEMONSTRATION`：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00035.jpeg)

1.  你的挑战是解密这个字符串：`MYXQBKDEVKDSYXC`。

在下一节中，我们将有一个关于`base64`的挑战。

# 挑战 2 – base64

经过`base64`的复习，我们将进行一个例子，向你展示如何解码一些混淆的文本，然后我们为你准备了一个简单的和一个困难的挑战。

这是`base64`的复习：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00036.jpeg)

`base64`编码文本会变得更长。这是要解码的示例文本：

```py
U2FtcGxliHRleHQ=
```

它解码成示例文本字符串。让我们看看。

参考以下步骤：

1.  如果你在立即模式下运行`python`，它将执行四个简单的任务：

```py
$ python
```

1.  所以，如果我们取`ABC`并用`base64`编码，我们会得到这个字符串：

```py
>>> "ABC".encode("base64")
'QUJD\n'
```

1.  如果我们用`base64`解码它，我们会得到原始文本：

```py
>>> "QUJD".decode("base64")
'ABC'
```

1.  所以，挑战文本如下，如果你解码它，你会得到示例文本字符串：

```py
>>> "U2FtcGxliHRleHQ=".decode("base64")
'Sample text'
```

1.  这对于简单情况足够了；你的第一个挑战看起来是这样的：

```py
Decode this: VGhpcyBpcyB0b28gZWFzeQ==
```

1.  这是一个要解码的长字符串，用于你的更长的挑战：

```py
Decode this:
VWtkc2EwbEliSFprVTJeFl6SlZaMWxUUW5OaU1qbDNVSGM5UFFvPQo=
```

这个长字符串之所以这么长，是因为它被`base64`编码了不止一次，而是多次。所以，你需要尝试解码它，直到它变成可读的内容。在下一节中，我们将有*挑战 3 – 异或*。

# 挑战 3 – 异或

在这一节中，我们将复习异或的工作原理，然后给你一个例子，然后提出两个挑战。

所以，这是我们之前讨论过的一个异或程序：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00037.jpeg)

你输入任意文本和一个任意的键，然后逐个字节地遍历它们，挑选出一个文本字节和一个键字节，然后用异或结合它们并打印出结果。所以，如果你输入`HELLO`和`qrs`，你会得到用异或加密的东西。

这里有一个例子：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00038.jpeg)

它会解密成`EXAMPLE`。所以，这是解密；记住异或会解开自己。

如果你想破解其中一个，一个简单的方法就是尝试每个键并打印出每个结果，然后读出可读的键。

所以，我们尝试从`0`到`9`的所有单个数字键。

结果是你输入密文，用每个值加密它，当你得到正确的键值时，它将变成可读的文本。

让我们来看看：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00039.jpeg)

这是解密例程，它简单地从用户输入文本，然后尝试这个字符串中的每个密钥，`0`到`9`。对于这些中的每一个，它将 XOR 文本组合成一个名为`clear`的变量，以便可以为每个密钥打印一行，然后清晰结果。因此，如果我们运行它并输入我的密文，它会给我们 10 行。

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00040.jpeg)

我们只是浏览了这些行并看到哪一个变得可读，您可以看到正确的密钥和正确的明文在`6`处。第一个挑战就在这里：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00041.jpeg)

这与我们之前看到的类似。密钥是一个数字，它将解密为可读的内容。这是一个以十六进制格式的更长的示例：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00042.gif)

密钥是两个 ASCII 数字，因此您将不得不尝试 100 种选择来找到将其转换为可读字符串的方法。

# 总结

在本章中，设置 Python 之后，我们介绍了简单的替换密码、凯撒密码，然后是`base64`编码。我们每次收集六位数据而不是八位数据，然后我们看了 XOR 编码，其中位根据密钥逐个翻转。我们还看到了一个非常简单的真值表。您完成的挑战是破解凯撒密码而不知道密钥，通过将`base64`反向解码以获取原始字节，并尝试所有可能的密钥进行暴力攻击来破解 XOR 加密。在第二章 *哈希*中，我们将介绍不同类型的哈希算法。


# 第二章：哈希

哈希有两个主要目的：第一个是在文件上放置一个指纹，以便您可以判断它是否已被更改，第二个是隐藏密码，以便您仍然可以识别正确的密码并启用登录，但是窃取哈希的人不能轻松地从中恢复密码。

在本章中，我们将涵盖以下主题：

+   MD5 和 SHA 哈希

+   Windows 密码哈希

+   Linux 密码哈希

+   挑战 1 - 破解 Windows 哈希

+   挑战 2 - 破解多轮哈希

+   挑战 3 - 破解 Linux 哈希

# MD5 和 SHA 哈希

在解释哈希函数是什么之后，我们将处理 MD5，然后是 SHA 系列：SHA-1，SHA-2 和 SHA-3。我们还将获取一些关于破解哈希的信息。

# 哈希是什么？

如前所述，使用哈希的一个目的是在文件上放置一个指纹。您可以使用哈希算法将文件中的所有字节组合在一起，从而创建一个固定的哈希值。如果更改文件的任何部分并重新计算哈希，则会得到完全不同的值。因此，如果您有两个应该相同的文件，您可以计算每个文件的哈希值，如果两个文件的哈希值匹配，则文件相同。

一个非常常见的哈希是 MD5；它已经存在了几十年。它的长度为 128 位，对于哈希函数来说相当短，对于大多数目的来说足够可靠。人们用它来对下载和恶意软件样本等进行指纹识别，有时也用于隐藏密码。它不是一个完美的哈希函数：已知有一些碰撞，并且有一些算法可以在一些计算时间的代价下创建碰撞，这些碰撞是哈希到相同值的文件对。因此，如果您找到两个具有匹配 MD5 的文件，您并不完全确定它们是相同的文件，但它们通常是。

在 Python 中计算它们非常容易。您只需导入哈希库，然后进行计算。您调用哈希库来创建一个新对象。第一个参数是使用的算法，即 MD5。第二个参数是要进行哈希处理的数据的内容。

在这里，我们将使用`HELLO`作为示例，然后您需要在末尾使用十六进制摘要，否则它将只打印数据结构的地址，而不是显示实际值。我们将使用`HELLO`的哈希，MD5 和十六进制，它有 128 位长。因此，这是 128 除以 4，或 32 个十六进制字符，如果您向`HELLO`添加另一个字符，比如感叹号，哈希将完全改变；一个值的哈希与下一个值的哈希之间没有任何相似之处。

**安全哈希算法**（**SHA**）旨在改进 MD5，直到大约一年前，SHA-1 没有发生碰撞，当时一些谷歌公司的研究人员发现了如何在 SHA-1 中发生碰撞，因此谨慎的人们正在转向 SHA-2。还有另一个由**国家标准技术研究所**批准的算法，称为**SHA-3**，几乎没有人使用，因为据所有人的预期，SHA-2 将在很长一段时间内保持安全。但是，如果发生了危及 SHA-2 的情况，SHA-3 将可供我们使用。SHA-2 和 SHA-3 都有各种长度，但最常见的长度是 256 和 512 位。

您可以在 Python 中轻松计算 SHA-1 和 SHA-2 哈希，但 SHA-3 并不常用，它还不是这个哈希库的一部分。因此，如果您使用 SHA-1 算法，您将得到一个 SHA-1 哈希。它看起来像 MD5 哈希，但更长。然后有 SHA-256 和 SHA-512，它们都是 SHA-2 哈希。您可以看到，尽管它们更安全，但它们更长，而且有些不太方便：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00043.jpeg)

所以，让我们来看看。

打开终端并执行`python`命令以启动 Python 终端：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00044.jpeg)

然后，您可以运行以下命令：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00045.jpeg)

您必须导入`hashlib`。然后，您可以添加`hashlib.new`。第一个参数是算法，这种情况下是`md5`。下一个参数是要进行哈希的数据，这里是`HELLO`，然后添加`hexdigest`以查看十六进制值。所以，这是`HELLO`的哈希，如果我们在末尾添加另一个字符，使其变成`HELLOa`，那么我们会得到一个完全不同的答案。

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00046.jpeg)

如果我们想使用不同的算法，我们只需输入 SHA-1：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00047.jpeg)

现在我们得到了一个很长的哈希值，如果我们添加`sha256`作为字符，我们会得到一个更长的哈希值：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00048.jpeg)

这些哈希对于几乎任何目的都足够了。

如果您有某物的哈希值，并且想要计算它来自哪些数据，原则上，这并没有唯一的解决方案。不过，在实践中，对于像密码这样的短对象，是有的。因此，如果有人使用`MD5`函数来隐藏密码，这是一些旧的 Web 应用程序所做的，那么您可以通过猜测密码来反转它，直到找到匹配项。没有数学方法可以撤消哈希函数，因此您只需制作一个库。在`MD5`哈希`HELLO`的示例中，如果您只是进行一系列猜测，您将得到正确的答案。这就是哈希破解的工作原理；这不是一个复杂的想法，只是有点不方便。

我们可以获取`HELLO`的 MD5 哈希并继续猜测：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00049.jpeg)

如果我们在猜测单词，可能需要猜测数百万个单词才能得到所示的值，但是如果我们能够猜到正确的值，当哈希值匹配时，我们就知道它是正确的。这个的难度取决于您每秒可以计算多少个哈希值，而 MD5 和 SHA 系列都设计为非常快速计算，因此您实际上可以尝试数百万个密码。在下一节中，我们将讨论 Windows 密码哈希。

# Windows 密码哈希

在本节中，我们将看到如何使用 Cain 获取哈希，然后了解 MD4 和 Unicode 的工作原理。然后，我们将讨论如何使用 Google 破解哈希和如何使用单词列表破解哈希。

# 使用 Cain 获取哈希

Cain 是一个免费的黑客工具，可以从正在运行的操作系统中收集 Windows 哈希。为了测试它，我们将在 Windows Server 上创建三个帐户，这是 Windows 操作系统的最新版本。您可以使用命令提示符中的用户命令来执行此操作。您可以添加一个名为`John`的用户，密码为`P@sw0rd`，一个名为`Paul`的用户，密码为`P@sw0rd`，以及一个名为`Ringo`的用户，密码为`P@sw0rd999`：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00050.jpeg)

如果运行 Cain，它可以收集哈希。以下屏幕截图显示了三个用户及其哈希值：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00051.jpeg)

LM Hash 部分是一个已经不再被任何 Windows 版本使用的过时系统，因此它只包含一个没有信息的虚拟值。当您登录时 Windows 实际使用的哈希称为 NT Hash。请注意，如果两个用户使用相同的密码，它们将具有完全相同的哈希值：`464`值。这是该系统的一个弱点。不幸的是，这是一个非常薄弱且陈旧的密码系统。

# MD4 和 Unicode

这是 Microsoft 使用的算法。它将密码编码为 Unicode 而不是 ASCII，然后当您通过 MD4 运行它（这是一个非常古老的算法，甚至比 MD5 还要古老），它会产生 NT 哈希值：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00052.jpeg)

使用 Unicode 的原因是因为 Microsoft 是一个国际操作系统，允许您使用中文和日文等语言的密码，这些语言不是每个字符使用 8 位编码，而是每个字符使用 16 位编码。

# 使用 Google 破解哈希

由于密码哈希没有变化，任何两个具有相同密码的用户将具有相同的哈希，过去 24 年来已经破解了单词列表的所有黑客都将他们的结果放在了互联网上，导致了这样一种情况：你可以直接谷歌经常使用的密码哈希：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00053.jpeg)

如果你只是把一个哈希放到谷歌上，你经常会发现有人已经为你破解了并放在了互联网上。例如，这里有一个`P@sw0rd`，已经有一个已知的结果，所以你可以破解它。这种简单的方法适用于很多密码，但这种技术对于我们用于用户`Ringo`的密码`P@sw0rd999`不起作用。

# 使用单词列表破解哈希

因此，在密码无法破解的情况下，你需要自己计算：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00054.jpeg)

你只需使用相同的过程。进行一系列的猜测，对它们进行哈希，然后寻找你的答案。如果你的猜测列表最终达到正确的值，你当然会在这里找到它。因此，你可以看到密码`P@sw0rd999`的`5c2c...`。

这很简单，所以让我们在 Python 中试一试。

在终端窗口中，我们将输入`python`命令。接下来我们将导入`hashlib`库：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00055.jpeg)

因此，你可以看到进行编码的行。我们输入密码，编码为`utf-16le`，这是 Unicode；然后，我们用 MD4 进行哈希，并将其表示为`hexdigest`。

这是`P@sw0rd`的数字。现在，如果我们尝试访问`Ringo`用户，我们需要有一个包含两个哈希值的列表，这些值最终需要达到正确的值：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00056.jpeg)

如果我们只是按顺序使用`997`，`998`和`999`进行计数，我们将得到我们正在寻找的`5c2c...`值。

# Linux 密码哈希

在本节中，我们将首先讨论如何从操作系统中获取哈希值，然后看看加盐和拉伸过程是如何使 Linux 哈希值更加安全的。然后我们将讨论现代版本的 Linux 使用的特定哈希算法，最后看看如何使用单词列表和 Python 破解哈希。

在这里，我们创建了三个用户来测试软件，方式与我们之前在 Windows 上做的方式类似。`John`和`Paul`有相同的密码，而`Ringo`有不同的密码：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00057.jpeg)

你可以从`/etc/shadow`文件中获取哈希值，从中我们将打印出最后三条记录。因此，你会看到`John`，`Paul`和`Ringo`，每个用户名后面都跟着`$6`，这表明它是密码的第 6 种类型，这是最现代和安全的形式。然后是一长串随机字符，直到下一个美元符号，然后是一个更长的随机字符串，这就是密码哈希本身。

你可以看到的第一件事是密码哈希，它比 Windows 密码哈希要长得多，更复杂。接下来要观察的是，即使`John`和`Paul`有相同的密码，它们的哈希完全不同，因为在对它们进行哈希之前，它们会添加一个随机的`salt`，以掩盖这些密码是相同的事实，从而使密码更加安全。加盐是在进行哈希之前添加随机字符的过程；这里也使用了拉伸。它不仅仅使用一轮 MD4，而是使用了 5000 轮 SHA-512，这简单地使得计算哈希需要更多的 CPU 时间。这样做的目的是减缓试图制作密码哈希字典的攻击者的速度。

你可以在`/etc/login.defs`文件中找到该方法的详细信息，该文件显示现代版本的 Linux 使用`SHA512`和`5000`轮的加密方法：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00058.jpeg)

因此，该过程要求你将`salt`与密码结合起来。你执行一个包括 5000 轮 SHA-512 哈希的算法。它实际上有超过 20 个步骤，涉及将两个哈希值放在一起并混合位，但它比仅仅重复相同的哈希算法要复杂一些。

我们将使用`passlive`库。在 Python 中使用它之前，你必须使用`pip install passlib`命令进行安装。一旦你安装好了，你就可以导入`sha512_crypt`模块。以下是你如何使用它：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00059.jpeg)

让我们开始 Python 终端。然后我们可以像之前展示的那样导入`passlib`库，因为我们已经将其放入`pip install`中。

现在，我们可以计算第一个，它将使用影子文件中的`salt`值并对其进行哈希，如前面的屏幕截图所示。

正如你所看到的，我们得到了正确的结果（以`r7k`开头）。如果我们进行字典攻击，我们将得到一系列密码猜测，如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00060.jpeg)

只需尝试它们，直到找到与之匹配的那个。

# 挑战 1 – 破解 Windows 哈希

在对 Windows 哈希进行审查和进行 1 位数哈希的示例之后，我们将给你两个挑战——一个是 2 位数密码，另一个是 7 位数密码。以下是 Python 中 Windows 哈希的样子：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00061.jpeg)

该算法使用`hashlib`对密码的哈希进行 MD4，但在此之前，将其编码为`utf-16le`，然后计算结果的`hexdigest`以获得长数字，该数字以`464`开头，在这种情况下，这是一个 Windows 密码哈希。

因此，你可以编写一个程序，尝试这个字符串中的所有字符，它将由 10 个数字组成，然后计算每个字符的哈希。你将得到一个简单的包含 10 个值的字典：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00062.jpeg)

你可以使用一个 1 位数密码来破解这个 1 位数哈希，方法如下：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00063.jpeg)

因此，这是一个挑战。密码是 00 到 99 之间的 2 位数，这是哈希：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00064.jpeg)

因此，你需要创建一个循环，尝试 100 个可能的值。

接下来是一个 7 位数密码，这是哈希：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00065.jpeg)

因此，你将不得不尝试 1000 万个值。这只需要几秒钟，这就是为什么 Windows 密码哈希非常薄弱——你可以每秒尝试数百万个。

# 挑战 2 – 破解多轮哈希

在审查了 Python 中 MD5 和 SHA 的工作原理之后，我们将看到多轮哈希是什么，然后你将得到两个挑战来解决。

MD5 和 SHA 都很容易计算：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00066.jpeg)

从`hashlib`库中，你只需要使用`hashlib.new`方法，并将算法的名称放在第一个参数中，密码放在第二个参数中，然后将十六进制摘要添加到其中，以便看到十六进制的实际结果，而不仅仅是对象的地址。要进行多轮，你只需重复该过程。

你需要将密码放入`h`，然后使用当前的`h`来计算下一个`h`，并一遍又一遍地重复这个过程。以下是一个打印多轮 MD5 哈希的前 10 轮的小脚本：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00067.jpeg)

这种技术称为**拉伸**，它被更强大的密码哈希例程所使用，比如我们在前面部分看到的 Linux 密码哈希。

这是你的第一个挑战：一个 3 位数密码使用 MD5 哈希 100 次。从这个哈希中找到它：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00068.jpeg)

这里还有一个挑战。在这个挑战中，你有一个未知轮数的 SHA-1，但不超过 5000。因此，你只需尝试所有值，并从这个哈希中找到结果的 3 位数密码。

# 挑战 3 – 破解 Linux 哈希

在审查了 Linux 哈希之后，我们将向你展示你的挑战。

Linux 哈希是经过盐处理和拉伸的，有各种版本。我们正在讨论当前版本，即版本 6，也就是最安全的形式：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00069.jpeg)

哈希是以美元符号开头的长字符串；`6`表示版本，然后是一个美元符号，后面跟着`salt`，再加一个美元符号，后面是哈希。要在 Python 中计算它们，您需要导入一个特殊的 SHA-512 `crypt`库，就像您之前看到的格式一样。

这是您的第三个挑战：以这种格式的 3 位密码。`salt`值为`penguins`，`hash`是以`P`开头的一长串混乱字符。

# 摘要

在本章中，我们介绍了 MD5 和 SHA-1 哈希算法，Windows 密码哈希算法和 Linux 密码哈希算法。在挑战中，您破解了一个 Windows 密码哈希以恢复明文密码，以及使用未知数量的 MD5 和 SHA-1 轮次破解了另一个密码哈希。最后，您破解了 Linux 密码哈希以恢复明文密码。

在第三章，*强加密*中，我们将介绍两种主要的强加密方法，即 AES 和 RSA。


# 第三章：强加密

强加密甚至可以对抗决心坚定的对手，比如敌对军事机构，如果做得正确的话。强加密的两种主要方法是 AES 和 RSA，它们都得到了美国政府的批准。你不需要有编程经验来学习这个，也不需要任何特殊的计算机；任何能运行 Python 的计算机都可以完成这些项目。而且你不需要太多的数学，因为我们不打算发明新的加密技术，只是学习如何使用标准的现有的那些，这些不需要任何比基本代数更高级的东西。

在本章中，我们将涵盖以下内容：

+   AES 强加密

+   ECB 和 CBC 模式

+   填充预言攻击

+   RSA 强加密

+   接下来呢？

# AES 强加密

在这一部分，我们将看一下**高级加密标准**（**AES**），私钥加密，密钥和块大小，如何影响 AES，以及 Python 和混淆和扩散。

AES 是美国国家标准技术研究所批准的加密标准，被认为非常安全。它甚至被批准用于保管机密军事信息。它是私钥加密，这是几千年来一直在使用的加密类型，发送方和接收方都使用相同的密钥。它是块密码，因此输入数据必须放在长度为 128 位的块中，明文块用密钥加密，产生密文块：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00070.jpeg)

有三种密钥大小：128、192 和 256 位。最常见的 AES 类型是 128 位密钥大小，这就是我们在这个例子中要使用的。在 Python 中，使用起来非常容易。

首先，你需要从`crypto cipher`导入`AES`模块，然后你需要一个 16 字节的密钥和明文，这是 16 字节的整数倍。然后你将用密钥创建一个新的 AES 对象，然后用密码加密计算它。这会给你一个 16 字节的字符串，可能是不可打印的，所以最好将其编码为十六进制以打印出来；当然，如果你解密它，你会回到原始的明文。这具有许多理想的加密属性，其中之一是混淆。如果你改变密钥的一位，它会改变整个密文。

因此，如果我们将密钥改为`kex`，你会看到所有的密文都改变了。这就是你想要的。两个非常相似的密钥会产生完全不同的结果，因此你无法找到任何模式来推断密钥的信息。

同样，扩散是一种理想的属性，如果你用相同的密钥对同一明文进行两次加密，但你改变了明文的一位，整个密文再次改变。看下面的例子：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00071.jpeg)

在这里，我们有字节，得到相同的`433`结尾于`6a8`。如果我们把最后一个字母改成`t`，你会发现它以`90c`开头，以`5d2`结尾；也就是说，它完全改变了。

让我们在 Python 中看一下：

1.  打开终端窗口并启动`python`。我们将输入以下命令，如截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00072.jpeg)

1.  我们导入`AES`模块，有一个 16 字节的密钥和一个 16 字节的明文。我们创建了一个 AES 对象，对其进行了加密，然后我们在这里打印出了十六进制值：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00073.jpeg)

1.  现在，我们改变密钥：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00074.jpeg)

我们来到密钥行，将其改为`z`，然后再次进行操作，用该密钥创建一个新的 AES 对象。进行加密并再次打印出结果，你会看到一切都不同了。

现在它以`b`开头，以`4`结尾，完全改变了。

1.  现在，我们将保留密钥不变，改变明文。让我们把`t`改成`F`。现在如果我们加密它并以十六进制打印出结果，一切又都改变了；尽管这与上面的密钥相同：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00075.jpeg)

因此，这显示了混淆和扩散，这是可取的特性。在下一节中，我们将讨论 ECB 和 CBC 模式。

# ECB 和 CBC 模式

我们将比较**电子密码本**（**ECB**）和**密码块链接**（**CBC**）并向您展示如何在 Python 中实现 AES CBC。

# ECB

在 ECB 方法中，每个明文块都分别使用密钥加密，因此如果你有两个相同的明文块，它们将产生相同的密文：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00076.jpeg)

如果你有一张图片，上面有大片的纯色，比如灰色和黑色，然后你加密它，你会得到不同的颜色，但图案不会改变：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00077.jpeg)

这不好。你仍然可以看到这是一只企鹅的图片，这不是大多数人对加密的期望。你期望加密隐藏数据，以便查看加密数据的攻击者无法知道消息是什么，而这里这种属性是不存在的。

因此，CBC 被认为是这个问题的最佳解决方案。

# CBC

除了密钥，你还需要添加一个初始化向量，它在加密之前与明文进行异或运算。然后对于下一个块，你取加密产生的密文，并将其用作第二个块的初始化向量。第三个块的输出被用作第三个块的初始化向量。因此，即使每个块中的输入明文相同，每个块中的密文也会不同：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00078.jpeg)

这导致更多的混淆：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00079.jpeg)

你可以看到企鹅现在完全看不见，所有字节都是随机的，所以这几乎是每个目的的首选。

要在 Python 中执行它，这是我们之前在 EBC 模式下执行的 AES 的方法。默认情况下，你不需要指定模式。

如果你想使用 CBC 模式，你可以输入以下命令：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00080.jpeg)

AES 模式 CBC 当你创建密码对象时。你还需要提供一个初始化向量，它可以是 16 字节，就像密钥一样。如果你加密 16 字节的文本块，由于初始化向量，结果中没有明显的差异，但它只是一个十六进制块。要看到这种效果，你需要使明文更长。当你加密它时，你会得到一个十六进制的块。这就是 ECB 模式，它并没有消除数据中的所有模式。这是具有相同重复输入的 CBC 模式。正如你所看到的，输出没有模式，并且无论你走多远，都不会重复。因此，它更有效地隐藏了数据。

让我们来看看。我们在终端中启动 Python，然后添加这段代码：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00081.jpeg)

因此，你可以看到 16 字节的密钥和 16 字节的 AES 明文在 ECB 模式下。我们对其进行加密并打印答案。

如果我们想要使它更长，我们添加这个：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00082.jpeg)

你可以在 Python 中对字符串对象进行乘法运算，如果你只是打印它出来，你会看到它只是同样的东西三次。

现在我们可以加密`plain3`：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00083.jpeg)

当我们打印出来时，它将在 33 处有重复的模式。现在，如果我们改变模式，我们需要一个`iv`：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00084.jpeg)

我们只需要 16 个字节，所以我们将 16 个字节添加到`iv`。接下来，我们创建一个新的`AES`对象。现在，在`iv`中，我们再次加密`plain3`，然后再次打印出结果。

你可以看到它有`61f`，你可以看到不再有重复。因此，如果你真的想要模糊输入，这是一种更有效的加密方式。

# 填充预言攻击

在本节中，我们将看到 PKCS＃7 系统中填充的工作原理，然后向您展示带有`PADDING ERROR`消息的系统。此外，我们还将处理填充预言攻击，这使得可能制作解码我们想要的 20 个明文的密文。

这是加密例程：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00085.jpeg)

我们将有三个数据块，每个块长 16 字节。我们将使用 AES 在 CBC 模式下加密数据，因此初始化向量和密钥就会出现。你会产生三个密文块，第一个块之后的每一个块都使用前一个加密例程的输出作为初始化向量与明文进行异或。

这是 PKCS#7 填充的工作方式：

+   如果需要一个字节的填充，使用`01`

+   如果需要两个字节的填充，使用`0202`

+   如果需要三个字节的填充，使用`030303`

+   等等...

如果我们这里的消息只有 47 个字节长，那么我们无法填满最后一个块，所以我们必须添加一个字节的填充。你可以使用各种数字作为填充，但在这个系统中，我们使用一个二进制值 1，如果你需要一个字节的填充，如果你需要两个字节，你就用两个字节，如果你需要三个字节的填充，你就用三个字节。这意味着，如果我们解密它，我们将得到三个密文块。我们解密它，我们将得到 47 字节的消息：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00086.jpeg)

这里的最后一个字节将始终是填充字节，即`0-1`，二进制值为`1`。

这是一个易受攻击的系统的示例。这只是使用我们以前制作的相同技术，我们只是用 AES 和 CBC 模式加密东西，你可以保存在`pador.py`中，然后你可以导入它以使其易于使用和更加现实。已经有真实的系统使用了这个。所以，我们导入，加密和解密方法，以便我们可以输入一个 47 个字节的消息并对其进行加密。我们将得到一个长长的十六进制输出。

如果我们解密它，我们将得到我们原始的输入加上一个字节的`0`1。x01 是 Python 表示法，表示二进制值为`1`的单个字节。如果你修改输入，保持前 47 个字节不变，并将最后一个字节更改为`A`或`65`并解密它，你将得到一个填充错误。这个错误消息看起来可能无害，但实际上它可能完全颠覆加密。

让我们来看看：

1.  打开终端并启动`python`。

1.  我们将输入以下命令：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00087.jpeg)

1.  我们将加密和解密例程。你可以看到我们有明文。当我们加密 47 个字节的明文时，我们得到一个长长的二进制块：

```py
941dc2865db9204c40dd6f0898cbe0086fc6d915e288ed4ef223766a02967b81c6c431778a40f517e9e4aa86856e0a3b68297e102b1ec93713bf89750cdfa80e
```

1.  当我们解密时，我们得到以下结果：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00088.jpeg)

我们可以看到，它实际上在末尾添加了一个字节的填充。

现在，我们应该做变形的。如果我们将我们修改后的文本设置为原始明文，直到第 47 个字符，然后我们在末尾添加`"A"`，当我们解密它时，我们得到`'PADDING ERROR'`：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00089.jpeg)

这是我们可以利用来颠覆系统的错误消息。所以，填充预言攻击的工作方式如下更改：

1.  将密文`[16:31]`更改为任何字节

1.  更改密文`[31]`直到填充有效。

1.  中间`[47]`必须是`1`

这是 CBC 的图示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00090.jpeg)

保持密文的前 16 个字节不变。将其更改为任何你喜欢的东西，比如全 A，然后解密。会发生的是，因为你改变了第二个块中的字节，第二个块将变成随机字符，第三个块也是如此。但除非最后一个块的最后一个字节是 1，否则会出现填充错误。所以，你可以用穷举法。你将一个字节更改为所有 256 个可能的值，直到该字节变为`1`，当发生这种情况时，你就知道这个值是`1`。你知道这个值，因为它没有给你一个填充错误消息，你可以对它们进行异或运算，以确定这个中间值。因此，逐个字节向左进行，你可以确定这些中间值。如果你知道它们，你可以输入密文，使得你喜欢的任何东西出现在第三个块中。因此，即使你不知道密钥或初始化向量，你也可以打败加密。

这是执行此操作的代码：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00091.jpeg)

并将得到以下输出：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00092.jpeg)

我们将密文设置为原始密文的前 16 个字节，然后是 15 个`A`。然后，我们改变下一个字节的所有可能的`256`个值，并且保持第三个数据块不变。之后，我们查看何时不再出现填充错误，那将是`234`，因此中间值是`234`异或一：

1.  现在，如果我们想要得到下一个字节，我们必须安排两个字节的填充，两者都将是`2`，如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00093.jpeg)

因此，密文的最后两个字节`46`和`47`都将是两。因此，我们将密文`31`设置为创建两个所需的值。现在我们知道中间值，我们可以计算它。

1.  我们改变密文`30`直到填充有效，这将确定中间的下一个字节：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00094.jpeg)

1.  保持第一个块不变，并添加 14 个字节的变化下一个字节的填充。保持所选值为`233`的字节，这样你就知道解密输出的最后一个字节将是`2`，当填充错误消息消失时，你可以拿这个数字，与`2`异或，得到中间值的下一个值。因此，现在我们可以制作消息。我们必须重复这个过程更多次以获得更多字节，但是对于这个演示，我们将只接受一个字母长的消息。我们将制作一个以`A`开头，后面跟着一个二进制值为`1`的有效填充。这是我们的目标，为了做到这一点，我们只需要将密文`30`和`31`设置为这些选择的值：

+   `ciphertext[30] = ord("A") ^ 113`

+   `ciphertext[31] = 16 235`

1.  因为我们知道中间值是`113`和`235`，我们只需要用我们想要的值异或这些中间值。

1.  我们将创建一个解密为以`A`结尾和二进制`1`的消息的密文，让我们看看它是如何进行的。现在，这个有点复杂，所以我们选择在文本编辑器中保存一些文本，这样我们可以逐个阶段地进行：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00095.jpeg)

1.  这是我们的 Python 代码：

```py
>>> from pador import encr, decr 

>>> prefix = c[0:16] + "A"*14
>>> for i in range(256):
...   mod = prefix + chr(i) + chr(233) + c[32:]
...   if decr(mod) != "PADDING ERROR":
...     print i, "is correctly padded"
```

1.  好的，我们导入了库，我们已经有了。在这里，我们保持前 16 个字节不变，并用 15 个`A`填充。然后，我们有一个循环，改变下一个字节的每个可能的值，并保持第三个数据块不变。我们运行循环，直到不再出现填充错误。这告诉我们`234`是给我们正确填充的值：

```py
234 is correctly padded
```

1.  因此，我们将`234`带到`1`，这告诉我们中间值，所有的缩进都被切断了，所以是`234`异或`1`。这告诉我们值是`235`。这是中间值。对于下一个位，使用非常相似的过程，所以现在我们有 14 个字节的填充。我们将改变下一个字节，接下来的字节是`233`，始终选择为`2`。因此，当我们通过这个循环运行时，它在`115`处被正确填充：

```py
...
115 is correctly padded
```

1.  因此，`115`异或`2`是`113`：

```py
>>> 115 ^ 2
113
```

因此，`113`是中间值的下一个字节。

1.  现在我们知道这两个数字`235`和`113`，我们可以控制明文的最后两个字节。现在我们将保持输入数据的第一个块不变。我们有 14 个字节的填充：

```py
>>> prefix = c[0:16] + "A"*14 
>>> c30 = ord("A") ^ 113 
>>> c31 = 1 ^ 235 mod = prefix + chr(c30) + chr(c31) + c[32:] 
>>> decr(mod)
```

1.  我们选择用两个字节`235`和`113`来制作`A`和一个二进制`1`。当我们创建修改后的密文并解密它时，我们得到以下消息：

```py
"This simple sent\xc6\x8d\x12;y.\xdc\xa2\xb4\xa9)7c\x95b\xd1I\xd0(\xbb\x1f\x8d\xebRlY'\x17\xf6wA\x01"
```

数据的第一个块没有被修改。第二个块和大部分第三个块已经改变为随机字符，但我们控制了最后两个字节，我们可以让它们说我们想要的任何东西。因此，我们能够创建一个解密至少部分为我们选择的两个值的密文，即使我们不知道密钥或初始化向量。

# 使用 RSA 进行强加密

在本节中，我们将介绍公钥加密、RSA 算法以及在 Python 中的实现。

# 公钥加密

在公钥加密中，我们解决了这个问题：例如，谷歌想要从用户那里接收机密数据，例如密码和信用卡号，但他们没有安全的通信渠道；他们拥有的是公共互联网，发送的任何数据都可能被任意数量的攻击者窃听。因此，没有办法交付共享的秘密密钥，对称加密算法，例如 AES，无法解决这个问题。这就是公钥加密的作用。

谷歌创建了一对密钥。他们保持私钥保密，不告诉任何人，并且公开公钥，以便任何人都可以知道。想要向谷歌发送秘密信息的人可以用公钥加密它们，然后通过不安全的渠道发送，因为唯一能解密的是谷歌，谷歌拥有私钥。邮箱的工作原理就是这样。任何人都可以去邮箱把信放在顶部槽里，但底部的门是锁着的，只有拥有私钥的邮递员才能把信拿出来。私钥和公钥必须有关联，但它们必须通过单向函数相关联，以便从私钥轻松计算出公钥，这是谷歌在首次设置密钥对时必须做的。但是从公钥计算出私钥必须非常困难，因此公开公钥是安全的，没有人会找到私钥。

# RSA 算法

有各种单向函数可以用于此目的，但在 RSA 中，该函数是分解一个大数：

+   私钥`d`由两个大素数`p`和`q`组成

+   公钥是`n = p * q`的乘积，以及任意值`e`

+   如果`p`和`q`很大，将`n`分解为`p`和`q`是非常困难的

如果将两个素数`p`和`q`相乘以创建它们的乘积`n`，那么将`n`分解为`p`和`q`是一个众所周知的困难问题。如果`p`和`q`足够大，这几乎是不可能的。这就是单向函数。你可以轻松地将`p`和`q`相乘以创建公钥`n`，但是公钥的知识不能用于实际确定`p`和`q`：

+   **公钥**：这是两个数字`(n,e)`

+   `e`可以是任何素数，通常是`65537`

+   **加密**：`y = x^(e)mod n`

+   **解密**：`x = y^d mod n`

+   `x`是明文，`y`是密文

因此，公钥是`n`，它是两个素数的乘积和另一个任意数`e`，通常只是这个值`65,537`。任何希望秘密发送明文`x`的人，将其提升到`e`的幂，模`n`，并将其加密的内容发送到不安全的渠道，例如互联网，给接收者。接收者有私钥，因此可以找到解密密钥`d`，并将密文取模`n`，然后变成解密的消息。解密密钥是这样计算的：

+   `phin = (p-1) * (q-1)`

+   `d*e = 1 mod phin`

由于 Google 知道`p`和`q`的秘密，他们可以计算出这个数字`phin`，即`p - 1`乘以`q - 1`，然后他们选择一个解密密钥，使得`d`乘以`e`对`Phi`的`n`取模等于`1`。其他人无法进行这种计算，因为他们不知道`p`和`q`的值。因此，在 Python 中，您可以导入`RSA`模块，然后生成任意长度的密钥。在这个例子中，我们使用了`2048`位，这是当前国家标准研究所的推荐。然后，他们有一个公钥。有一条要加密的消息，你加密它，结果是这个非常长的密文，长度为`2048`位。密文很长，计算速度很慢，所以你通常不会用这种方法发送长消息。在 RSA 中，你只需要发送一个秘密密钥，然后你使用 AES 来加密之后的所有内容，以加快计算速度。本章介绍了一种称为教科书 RSA 的东西，其中包含许多基本要素，但实际上并不足够安全，因为你必须添加一个在 RFC 8017 中指定的填充。这会向消息添加哈希值、掩码和填充，并保护密钥免受一些攻击。让我们在 Python 中看一下这个。

# Python 中的实现

这是我们如何在 Python 中实现我们所讨论的内容：

1.  我们启动`python`，然后添加以下代码：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00096.jpeg)

1.  所示的最后一步大约需要 2 到 4 秒钟才能生成密钥；这是因为它必须找到两个大素数，而这些是非常困难的计算：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00097.jpeg)

1.  它必须猜一个数字并测试它，通常情况下，它必须为每个大素数尝试超过一百次猜测，因此这个过程非常耗时。但是，这是自动发生的，现在我们可以用密钥加密消息，生成这个非常长的密文：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00098.jpeg)

1.  现在，我们可以测试一下，看看我们是否改变了消息的一个比特，或者将明文的最后一个字母改为`f`。如果我们加密这个，结果将类似于以下内容：

```py
>>> plain = 'encrypt this messagf'
>>> ciphertext = publicKey.encrypt(plain, 0) [0
... ciphertext = publicKey.encrypt(plain, 0) [0
keyboardInterrupt
>>> ciphertext = publicKey.encrypt(plain, 0) [0]
>>> print ciphertext.encode ("hex")
```

1.  现在，我们打印结果：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00099.jpeg)

正如您所看到的，所有的`4ac`都变成了`1dc`，然后结束于`578`到`633`。这是强加密的理想特性。输入的任何更改都会改变所有输出，剪辑大约一半的位数。

# 挑战-用类似的因子破解 RSA

在本节中，我们将涵盖诸如大整数-在 Python 和`decimal`库中的主题。我们还将看一个大数因式分解的例子，然后为您提供两个挑战来解决。

# Python 中的大整数

Python 可以进行乘法和除法-并且可以完全精确地进行任意大的整数的乘法和除法：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00100.jpeg)

如果我们有`1001`，然后计算`1001`的平方，我们当然会得到正确的答案；即使我们取一个像`10**100 + 1`这样的数字，它也能正确地得到这个数字的一百位数，每一端都是`1`。现在，如果我们再对这个数字求平方，它也能正确地得到它的一百位数，每一端都是`1`。

因此，对于简单的整数运算，Python 的精度是无限的。但是，如果我们想要平方根，我们需要导入`math`库：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00101.jpeg)

正如您在前面的代码中所看到的，`math`库不保留任意数量的位数。如果我们取`10 **100 + 1`并对其求平方，然后取平方根，我们得到的不是`10 **100 + 1`。我们得到的是`10 ** 100`，这意味着它舍入到了少于`100`位数的一些数字，对于许多目的来说这是可以接受的。但是，对于我们想要做的事情来说不够，我们想要因式分解大整数。

为了做到这一点，您使用`decimal`库，并按照所示导入它：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00102.jpeg)

正如你所看到的，我们已经导入了`decimal`库，并将`a`的值设置为`10 **100+ 1`。这里`b`等于 a 的平方，然后不是使用`math`库计算`b`的平方根，而是使用`decimal`库计算`b`的十进制值。使用它的平方根方法，这会再次给出错误的答案，因为默认情况下，`decimal`库会四舍五入。但是如果将精度设置得更高，你将得到完全正确的答案，这就是为什么`decimal`库对我们的目的更好。这个`getcontext().prec`命令让我们设置它保留足够的位数，以便我们想要的精度。

好的，所以，在一般情况下，你无法分解一个大数，这就是 RSA 安全的原因。但是，如果在使用数字时出现错误，并且以某种方式可以预测，那么 RSA 就可以被破解：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00103.jpeg)

这里的错误是使用两个彼此接近的质数因子，而不是为这两个质数因子选择独立的随机数。因此，这个大数字是两个质数因子的乘积，因此你可以将其分解。因此，如果我们将该数字放入一个名为`n`的值中，我们将精度设置为`50`位并计算平方根。我们发现平方根是`1`后面跟着许多个零，然后以`83`结束+一个分数。

现在，如果这个数字是两个质数的乘积，并且这两个质数彼此接近，一个数字必须小于平方根，另一个数字必须大于平方根。

因此，如果我们从平方根开始，每次向后跳两个数字，尝试接近平方根的数字，我们最终会找到质数因子，我们找到了：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00104.jpeg)

当然，我们可以向后跳两步，因为偶数肯定不是质数，所以我们不需要测试偶数。

正如我们所看到的，现在我们找到了一个数字，其中`n`模这个数字的结果为零，因此这是一个质数因子。

我们可以通过将`n`除以第一个质数来得到另一个质数因子：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00105.jpeg)

因此，这里是原始数字`n`，它是两个质数的乘积，我们有其中一个质数；`q`是`n`除以`p`，你可以看到。为了测试它，如果我们计算`p*q`，我们会再次得到原始数字。因此，我们已经将一个大数字分解为`p`和`q`，这就足够破解 RSA 了。

所以，让我们在 Python 中尝试一下。转到终端并运行`python`：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00106.jpeg)

所以，我们有`n`等于所示的大数字。我们将这个数字导入`decimal`库，并将位置设置为`50`位。现在，如果我们取平方根，我们得到`1`后面跟着许多个零，然后是`83`，然后是一个分数。然后，我们复制平方根的整数部分：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00107.jpeg)

现在我们将`p`设置在该数字的范围内，如下所示：

```py
>>> for p in range(100000000000000000083, 100000000000000000030, -2):
```

这开始了一个循环，我们所要做的就是打印：

```py
...  print p, n%p
...
```

它将计算`n`模`p`，结果将为零。如果这是一个整数倍数，按两次*Enter*运行循环：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00108.jpeg)

所以，我们可以看到这个数字是`p`：

```py
100000000000000000039 0
```

如果我们复制那个数字，我们可以将`p`设置为那个数字，然后将`q`设置为`n`除以`p`：

```py
>>> p = 100000000000000000039
>>> q = n/p
```

如果我们打印，我们将得到以下结果：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00109.jpeg)

你可以看到`n`与`p*q`匹配。所以，我们现在已经将那个长数字分解为了它的互补质数。

这是第一个挑战：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00110.jpeg)

这是第二个挑战：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00111.jpeg)

在这两种情况下，你都能够将它们分解。

# 接下来呢？

**物联网**（**IoT**）有着光明的未来，很快将连接数十亿的设备。对于物联网，安全一直是一个主要关注点。但好消息是，加密为保护物联网免受黑客攻击提供了各种选择；因此，这是物联网即将到来的时代的关键。

# 物联网中的加密

当我们谈论在物联网中使用加密时，我们谈论的是在通信堆栈的许多层上使用加密。如果我们看一下 OSI 模型，我们可以看到加密在第 2 层及以上使用，链接在第 2 层操作，网络在第 3 层操作，传输在第 4 层操作：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-crpt-py/img/00112.jpeg)

在应用层，加密也用于通过认证和加密来保护通信。在我们开始描述物联网协议的特定加密方法之前，让我们先谈谈现有无线协议的利用工具的现成性。随着物联网的成熟，要记住有许多工具可用于利用物联网无线通信协议，这些工具将继续迅速跟上支持物联网引入的新技术。

例如，看看 1989 年推出的 Wi-Fi 802.11，2004 年推出的 AirCrack 工具至今仍然是一款受欢迎且得到良好支持的工具。还有许多工具可用于利用蓝牙通信和蜂窝通信。

除此之外，驱动加密的密钥必须在设备（模块）级别以及整个企业范围内得到安全管理。让我们来探讨其中一些。

# ZigBee 加密密钥

ZigBee 使用许多密钥进行加密操作：

+   **链路密钥**：这是基于制造商预先配置的主密钥建立的。链路密钥提供了两个 ZigBee 节点之间的点对点安全连接。链路密钥还用于建立派生密钥，包括数据密钥、密钥传输密钥和密钥装载密钥

+   **密钥传输密钥**：这个密钥是在使用链路密钥和 1 字节字符串 0x00 作为输入字符串执行专门的密钥散列函数的结果

# ZigBee 密钥管理的复杂性

如前所述，密钥管理是具有挑战性的。让我们来看看密钥管理有多具有挑战性。例如，以 ZigBee 协议为例。在 ZigBee 网络中可以使用三种主要类型的密钥。主密钥通常由供应商预先安装，并保护两个 ZigBee 节点之间的交换，因为它们生成链路密钥。链路密钥支持节点之间的通信，网络密钥支持广播通信。

密钥管理功能可能内置于实用程序的媒体管理软件中，例如，也可能作为独立软件提供。然而，所有这些密钥在它们的整个生命周期中都需要得到充分的安全保护。

# 蓝牙-LE

蓝牙低功耗协议采用加密技术来配对设备以建立未来的关系。蓝牙-LE 在这些加密过程中使用各种密钥，包括**长期密钥**（LTK），用于生成链路层加密的 128 位密钥，以及**连接签名解析密钥**（CSRK），用于在 ATT 层对数据进行数字签名。

通过这一切，我们来到了本书的结尾。加密应用应该根据威胁环境进行定制。加密是基于强大、精心设计的算法，并与通信堆栈的所有层相关联。它无处不在，对物联网系统的安全至关重要。

# 总结

在本章中，我们介绍了 AES，这是当今常用的最强大的私钥系统，以及它的两种模式，ECB 和 CBC。我们还介绍了针对 CBC 的填充预言攻击，这是可能的，当错误消息给予攻击者比他们应该获得的更多有关加密过程的信息时。

最后，我们介绍了 RSA，这是当今用于通过互联网发送秘密的主要公钥算法，我们还研究了一个挑战，即在两个素数相似而不是独立和随机选择的情况下我们是如何破解 RSA 的。我们还研究了加密技术的未来以及它如何帮助保护物联网设备。
