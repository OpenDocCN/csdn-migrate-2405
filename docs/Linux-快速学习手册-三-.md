# Linux 快速学习手册（三）

> 原文：[`zh.annas-archive.org/md5/d44a95bd11f73f80156880d7ba808e3a`](https://zh.annas-archive.org/md5/d44a95bd11f73f80156880d7ba808e3a)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

管道和 I/O 重定向

Linux 的一个主要原则是*每个程序都做一件事情*，因此，每个 Linux 命令都设计成能够高效地完成单个任务。在本章中，你将学习如何使用 Linux 管道来结合命令的功能，以执行更复杂的任务。你还将学习有关 I/O（输入/输出）重定向，这将使你能够读取用户输入并将命令输出保存到文件中。

# 第十章：Linux 管道

在 Linux 中，你可以使用管道将一个命令的输出发送到另一个命令的输入（参数）中：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/lrn-linux-qk/img/cb57d2c1-6ca4-4c4f-aac2-f12da4d9ecb4.png)

图 1- Linux 管道

在你的键盘上，管道由竖线字符表示。Linux 管道非常有用，因为它们允许你以一种简单的方式完成相对复杂的任务，而且在整本书中，你会发现它们经常派上用场。

在我们做一个例子之前，让我们先将`hard.txt`文件重命名为`facts.txt`，因为我们在第六章中删除了`facts.txt`文件，*硬链接与软链接*：

```
elliot@ubuntu-linux:~$ mv hard.txt facts.txt
```

现在让我们使用`head`命令来查看`facts.txt`的前五行：

```
elliot@ubuntu-linux:~$ head -n 5 facts.txt 
Apples are red.
Grapes are green.
Bananas are yellow.
Cherries are red.
Sky is high.
```

现在我想显示文件`facts.txt`的第五行`Sky is high.`；我该怎么做呢？

这就是 Linux 管道的威力所在。如果你将前一个命令的输出传输到`tail -n 1`命令，你将得到第五行：

```
elliot@ubuntu-linux:~$ head -n 5 facts.txt | tail -n 1 
Sky is high.
```

因此，通过使用管道，我能够将`head -n 5 facts.txt`命令的输出发送到`tail -n 1`命令的输入（参数）中。

让我们做另一个例子。如果你想显示文件`facts.txt`的第七行，那么你将使用`head`命令显示前七行，然后使用管道`tail`最后一行：

```
elliot@ubuntu-linux:~$ head -n 7 facts.txt | tail -n 1 
Linux is awesome
```

你也可以同时使用多个管道，就像下面的图表中演示的那样：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/lrn-linux-qk/img/6eb7018e-8a8e-499a-8308-651eea5d1b14.png)

图 2：两个管道

例如，你已经知道`lscpu`命令会显示处理器信息。`lscpu`命令的第四行输出显示了你的机器有多少个 CPU。你可以使用两个管道显示`lscpu`命令的第四行：

```
elliot@ubuntu-linux:~$ lscpu | head -n 4 | tail -n 1 
CPU(s):       1
```

所以让我们分解一下这里发生了什么。我们使用的第一个管道是显示`lscpu`命令的前四行：

```
elliot@ubuntu-linux:~$ lscpu | head -n 4 
Architecture:    x86_64
CPU op-mode(s):  32-bit, 64-bit 
Byte Order:      Little Endian
CPU(s):          1
```

然后我们使用第二个管道来`tail`最后一行，这样就得到了第四行：

```
elliot@ubuntu-linux:~$ lscpu | head -n 4 | tail -n 1 
CPU(s):        1
```

你可以类似地显示`lscpu`的第二行，其中显示了 CPU 的操作模式，但我会把这个留给你作为一个练习。

# 输入和输出重定向

在本节中，你将学习 Linux 最酷的功能之一，即 I/O（输入/输出）重定向。大多数 Linux 命令都使用三种不同的数据流：

+   标准输入（也称为`stdin`）

+   标准输出（也称为`stdout`）

+   标准错误（也称为`stderr`）

到目前为止，我们讨论的大多数命令都会产生一些输出。这些输出被发送到一个称为标准输出（也称为`stdout`）的特殊文件中。默认情况下，标准输出文件链接到终端，这就是为什么每次运行命令时，你都会在终端上看到输出。有时候命令会产生错误消息。这些错误消息被发送到另一个称为标准错误（也称为`stderr`）的特殊文件中，它也默认链接到终端。

# 重定向标准输出

你知道运行`date`命令会在你的终端上显示当前日期：

```
elliot@ubuntu-linux:~$ date 
Sat May 11 06:02:44 CST 2019
```

现在通过使用大于号`>`，你可以将`date`命令的输出重定向到文件而不是你的终端！看一下：

```
elliot@ubuntu-linux:~$ date > mydate.txt
```

如你所见，屏幕上没有显示任何输出！这是因为输出被重定向到文件`mydate.txt`：

```
elliot@ubuntu-linux:~$ cat mydate.txt 
Sat May 11 06:04:49 CST 2019
```

太棒了！让我们再试一些例子。你可以使用`echo`命令在你的终端上打印一行：

```
elliot@ubuntu-linux:~$ echo "Mars is a planet." 
Mars is a planet.
```

如果您想将输出重定向到一个名为`planets.txt`的文件，您可以运行以下命令：

```
elliot@ubuntu-linux:~$ echo "Mars is a planet." > planets.txt 
elliot@ubuntu-linux:~$ cat planets.txt
Mars is a planet
```

太棒了！请注意，文件`planets.txt`也在这个过程中创建了。现在让我们向文件`planets.txt`添加更多的行星：

```
elliot@ubuntu-linux:~$ echo "Saturn is a planet." > planets.txt 
elliot@ubuntu-linux:~$ cat planets.txt
Saturn is a planet.
```

嗯。我们添加了一行“土星是一个行星。”但现在删除了“火星是一个行星。”！这是因为用`>`重定向标准输出会覆盖文件。在这种情况下，我们需要的是向文件追加，这可以通过使用双大于号`>>`来实现。所以现在让我们向文件`planets.txt`追加一行“火星是一个行星。”：

```
elliot@ubuntu-linux:~$ echo "Mars is a planet." >> planets.txt 
elliot@ubuntu-linux:~$ cat planets.txt
Saturn is a planet.
Mars is a planet.
```

太棒了！正如你所看到的，它将“火星是一个行星。”添加到文件的末尾。让我们再添加一个行星：

```
elliot@ubuntu-linux:~$ echo "Venus is a planet." >> planets.txt 
elliot@ubuntu-linux:~$ cat planets.txt
Saturn is a planet.
Mars is a planet.
Venus is a planet.
```

太棒了！这里还有一件事情你需要知道，那就是标准输出（`stdout`）链接到文件描述符 1。

**文件描述符是什么？**

文件描述符是一个在计算机操作系统中唯一标识打开文件的数字。

然后运行命令：

```
elliot@ubuntu-linux:~$ date > mydate.txt
```

与运行命令相同：

```
elliot@ubuntu-linux:~$ date 1> mydate.txt
```

请注意，`1>`中的`1`是指文件描述符 1（`stdout`）。

# 重定向标准错误

如果您尝试显示一个不存在的文件的内容，您将收到一个错误消息：

```
elliot@ubuntu-linux:~$ cat blabla 
cat: blabla: No such file or directory
```

现在，这个错误消息来自标准错误（`stderr`）。如果您尝试以与标准输出相同的方式重定向错误，它将不起作用：

```
elliot@ubuntu-linux:~$ cat blabla > error.txt 
cat: blabla: No such file or directory
```

正如您所看到的，它仍然在您的终端上显示错误消息。这是因为`stderr`链接到文件描述符 2。因此，要重定向错误，您必须使用`2>`：

```
elliot@ubuntu-linux:~$ cat blabla 2> error.txt
```

现在如果您显示文件`error.txt`的内容，您将看到错误消息：

```
elliot@ubuntu-linux:~$ cat error.txt 
cat: blabla: No such file or directory
```

让我们尝试删除一个不存在的文件：

```
elliot@ubuntu-linux:~$ rm brrrr
rm: cannot remove 'brrrr': No such file or directory
```

这也会产生一个错误消息。我们可以将这个错误消息追加到文件中

使用`2>>`的`error.txt`：

```
elliot@ubuntu-linux:~$ rm brrrr 2>> error.txt
```

现在如果您显示文件`error.txt`的内容：

```
elliot@ubuntu-linux:~$ cat error.txt 
cat: blabla: No such file or directory
rm: cannot remove 'brrrr': No such file or directory
```

您将看到两个错误消息。

# 将所有输出重定向到同一个文件

有些情况下，您可能同时获得标准输出和错误消息。例如，如果您运行以下命令：

```
elliot@ubuntu-linux:~$ cat planets.txt blabla 
Saturn is a planet.
Mars is a planet.
Venus is a planet.
cat: blabla: No such file or directory
```

您会看到它显示了文件`planets.txt`的内容，但在最后一行也显示了一个错误消息（因为没有文件`blabla`来连接）。

您可以选择将错误重定向到另一个文件：

```
elliot@ubuntu-linux:~$ cat planets.txt blabla 2> err.txt 
Saturn is a planet.
Mars is a planet.
Venus is a planet.
```

这样，您只能在屏幕上看到标准输出。或者您可以选择重定向标准输出：

```
elliot@ubuntu-linux:~$ cat planets.txt blabla 1> output.txt 
cat: blabla: No such file or directory
```

这样，您只能在屏幕上看到错误。那么，如果您想将标准输出和错误重定向到同一个文件呢？在这种情况下，您必须运行：

```
elliot@ubuntu-linux:~$ cat planets.txt blabla > all.txt 2>&1
```

`&1`是指标准输出，而`2>`是指标准错误。所以我们基本上是在说：“将 stderr 重定向到我们正在重定向 stdout 的地方。”

现在如果您显示文件`all.txt`的内容：

```
elliot@ubuntu-linux:~$ cat all.txt 
Saturn is a planet.
Mars is a planet.
Venus is a planet.
cat: blabla: No such file or directory
```

您可以看到它包括`stdout`和`stderr`。

# 丢弃输出

有时候你不需要将输出重定向到任何地方；你只是想抛弃它并摆脱它。在这种情况下，你可以将输出重定向到`/dev/null`。这通常与错误消息一起使用。例如：

```
elliot@ubuntu-linux:~$ cat planets.txt blabla 2> /dev/null 
Saturn is a planet.
Mars is a planet.
Venus is a planet.
```

这将把错误消息重定向到`/dev/null`。您可以将`/dev/null`视为垃圾收集器。

# 重定向标准输入

一些 Linux 命令通过标准输入与用户输入交互（默认情况下是键盘）。例如，`read`命令从用户那里读取输入并将其存储在一个变量中。例如，您可以运行命令`read weather`：

```
elliot@ubuntu-linux:~$ read weather 
It is raining.
```

然后它将等待您输入一行文本。我输入了一行“下雨了。”，所以它将这行存储在`weather`变量中。您可以使用`echo`命令来显示变量的内容：

```
elliot@ubuntu-linux:~$ echo $weather 
It is raining.
```

请注意，您必须在变量名之前加上美元符号。`read`命令在 shell 脚本中特别有用，我们稍后会涉及到。现在请注意，我使用键盘写下了`It is raining.`这一行。然而，我可以使用小于号`<`将标准输入重定向到文件中，例如：

```
elliot@ubuntu-linux:~$ read message < mydate.txt
```

这将读取文件`mydate.txt`的内容并将其存储在`message`变量中：

```
elliot@ubuntu-linux:~$ echo $message 
Sat May 11 06:34:52 CST 2019
```

正如您所看到的，变量`message`现在具有与文件`my-date.txt`相同的内容。

# 知识检查

对于以下练习，打开您的终端并尝试解决以下任务：

1.  仅显示文件`facts.txt`的第 5 行。

1.  将`free`命令的输出保存到名为`system.txt`的文件中。

1.  将`lscpu`命令的输出追加到文件`system.txt`中。

1.  运行命令`rmdir /var`并将错误消息重定向到文件`error.txt`。


分析和操作文件

在本章中，你将学习各种 Linux 命令，这些命令将帮助你分析和操作文件。你还将学习如何比较两个文件并获取文件大小。你还将学习如何显示文件的类型，并显示文件中的字符数、单词数和行数。此外，你还将学习如何对文件进行排序、删除重复行等等！

# 第十一章：找出不同之处

你可以使用`diff`命令比较两个文件的内容，并突出它们之间的差异。

为了演示，让我们首先复制文件`facts.txt`并命名为`facts2.txt`：

```
elliot@ubuntu-linux:~$ cp facts.txt facts2.txt
```

现在让我们将行`"Brazil is a country."`附加到文件`facts2.txt`中：

```
elliot@ubuntu-linux:~$ echo "Brazil is a country." >> facts2.txt
```

现在，在两个文件上运行`diff`命令：

```
elliot@ubuntu-linux:~$ diff facts.txt facts2.txt 
12a13
> Brazil is a country.
```

酷！它输出了两个文件之间的差异，这种情况下是行`Brazil is a country.`。

# 查看文件大小

你可以使用`du`命令查看文件大小。**du**代表**磁盘使用**。如果你想查看文件中有多少字节，你可以使用`du`命令和`-b`选项：

```
elliot@ubuntu-linux:~$ du -b facts.txt
210 facts.txt
```

`facts.txt`文件有`210`字节。一个字符等于一个字节的大小，所以现在你知道`facts.txt`文件确切地有`210`个字符。

你还可以使用`-h`选项，它将以人类可读的格式打印文件大小。例如，要查看`dir1`目录及其内容的大小，你可以运行：

```
elliot@ubuntu-linux:~$ du -h dir1 
4.0K     dir1/cities
16K     dir1/directory2 
24K     dir1
```

# 计算字符、单词和行数

单词计数`wc`命令是另一个非常方便的命令。它计算文件中的行数、单词数和字符数。例如，要显示文件`facts.txt`中的行数，你可以使用`-l`选项：

```
elliot@ubuntu-linux:~$ wc -l facts.txt
12 facts.txt
```

文件`facts.txt`中总共有`12`行。要显示单词的数量，你可以使用`-w`选项：

```
elliot@ubuntu-linux:~$ wc -w facts.txt
37 facts.txt
```

所以文件`facts.txt`中总共有`37`个单词。要显示字符（字节）的数量，你可以使用`-c`选项：

```
elliot@ubuntu-linux:~$ wc -c facts.txt
210 facts.txt
```

文件`facts.txt`中总共有`210`个字符。没有任何选项，`wc`命令将以并列的方式显示行数、单词数和字符数：

```
elliot@ubuntu-linux:~$ wc facts.txt
12 37 210 facts.txt
```

# 查看文件类型

你可以使用`file`命令来确定文件的类型。例如，如果你想确定文件`/var`的类型，你可以运行：

```
elliot@ubuntu-linux:~$ file /var
/var: directory
```

正如你所期望的那样，输出显示`/var`是一个目录。如果你想显示`facts.txt`文件的类型，你可以运行：

```
elliot@ubuntu-linux:~$ file facts.txt 
facts.txt: ASCII text
```

输出显示`facts.txt`是一个 ASCII 文本文件。

**ASCII 是什么？**

**ASCII**，即**美国信息交换标准代码**，是用数字表示`128`个英文字符的代码，每个字母被分配一个从`0`到`127`的数字。

你的计算机不理解人类语言（字母），只理解数字！因此，英语语言中的每个字符都被转换为一个数字。你的计算机将任何文本文件都视为一堆堆的数字！

现在让我们创建一个名为`soft.txt`的软链接到`facts.txt`文件：

```
elliot@ubuntu-linux:~$ ln -s soft.txt facts.txt
```

并在`soft.txt`上运行`file`命令：

```
elliot@ubuntu-linux:~$ file soft.txt 
soft.txt: symbolic link to facts.txt
```

如你所见，它显示`soft.txt`是一个指向`facts.txt`的符号（软）链接。

# 文件排序

你可以使用`sort`命令对文本文件进行排序。例如，你可以通过运行命令按字母顺序查看`facts.txt`文件：

```
elliot@ubuntu-linux:~$ sort facts.txt 
Apples are red.
Bananas are yellow.
Cherries are red.
Cherries are red.
Cherries are red.
Cherries are red.
Earth is round.
Grapes are green.
Grass is green.
Linux is awesome!
Sky is high.
Swimming is a sport.
```

你还可以使用`-r`选项以相反的顺序进行排序：

```
elliot@ubuntu-linux:~$ sort -r facts.txt 
Swimming is a sport.
Sky is high.
Linux is awesome!
Grass is green.
Grapes are green.
Earth is round.
Cherries are red.
Cherries are red.
Cherries are red.
Cherries are red.
Bananas are yellow.
Apples are red.
```

你也可以使用`-n`选项按数字值而不是文字值进行排序。

# 显示唯一行

你可以使用`uniq`命令省略文件中重复的行。例如，注意文件`facts.txt`中的行`Cherries are red.`被包含了四次：

要查看`facts.txt`而不重复的行，你可以运行：

```
elliot@ubuntu-linux:~$ uniq facts.txt 
Apples are red.
Grapes are green.
Bananas are yellow.
Cherries are red.
Sky is high.
Earth is round.
Linux is awesome!
Cherries are red.
Grass is green.
Swimming is a sport.
```

注意`Cherries are red.`在输出中仍然显示了两次。这是因为`uniq`命令只省略了重复的行而不是重复的行！如果你想省略重复的行，你必须首先对文件进行`sort`，然后使用管道在排序输出上应用`uniq`命令：

```
elliot@ubuntu-linux:~$ sort facts.txt | uniq 
Apples are red.
Bananas are yellow.
Cherries are red.
Earth is round.
Grapes are green.
Grass is green.
Linux is awesome!
Sky is high.
Swimming is a sport.
```

哇！我们成功地省略了重复和重复的行。

# 搜索模式

`grep`命令是 Linux 中最受欢迎和有用的命令之一。您可以使用`grep`打印与特定模式匹配的文本行。例如，如果您只想显示`facts.txt`中包含单词`green`的行，则可以运行：

```
elliot@ubuntu-linux:~$ grep green facts.txt 
Grapes are green.
Grass is green.
```

如您所见，它只打印了包含单词`green`的两行。

`grep`命令在与管道一起使用时也可能非常有用。例如，要仅列出您的主目录中的`txt`文件，可以运行以下命令：

```
elliot@ubuntu-linux:~$ ls | grep txt 
all.txt
error.txt 
facts2.txt 
facts.txt 
Mars.txt 
mydate.txt 
output.txt 
planets.txt 
soft.txt
```

您可以使用`-i`选项使您的搜索不区分大小写。例如，如果您想要打印包含单词`Earth`的行在`facts.txt`中，然后使用以下命令：

```
elliot@ubuntu-linux:~$ grep earth facts.txt 
elliot@ubuntu-linux:~$
```

这将不显示任何结果，因为`grep`默认区分大小写。但是，如果您传递`-i`选项：

```
elliot@ubuntu-linux:~$ grep -i earth facts.txt 
Earth is round.
```

它将使搜索不区分大小写，因此它将显示行`Earth is round.`

# 流编辑器

您可以使用流编辑器命令`sed`来过滤和转换文本。例如，要在`facts.txt`中用单词`Cloud`替换单词`Sky`，可以运行以下命令：

```
elliot@ubuntu-linux:~$ sed 's/Sky/Cloud/' facts.txt 
Apples are red.
Grapes are green.
Bananas are yellow.
Cherries are red.
Cloud is high.
Earth is round.
Linux is awesome!
Cherries are red.
Cherries are red.
Cherries are red.
Grass is green.
Swimming is a sport.
```

如您在输出中所见，单词`Sky`被替换为`Cloud`。但是，文件`facts.txt`没有被编辑。要覆盖（编辑）文件，可以使用`-i`选项：

```
elliot@ubuntu-linux:~$ sed -i 's/Sky/Cloud/' facts.txt 
elliot@ubuntu-linux:~$ cat facts.txt
Apples are red.
Grapes are green.
Bananas are yellow.
Cherries are red.
Cloud is high.
Earth is round.
Linux is awesome!
Cherries are red.
Cherries are red.
Cherries are red.
Grass is green.
Swimming is a sport.
```

如您所见，更改已反映在文件中。

# 翻译字符

您可以使用`tr`命令来翻译字符。我这里不是在谈论将文本翻译成不同的语言；相反，我是在使用“翻译”一词的第二个含义，即从一种形式转换为另一种形式。

如果您阅读`tr`命令的`man`页面，您会在描述中看到：**从标准输入翻译、压缩和/或删除字符，写入标准输出**。因此，`tr`命令不接受任何参数。

`tr`命令的一个常见用途是将小写字母转换为大写字母（反之亦然）。例如，如果您想要以大写形式显示`facts.txt`中的所有单词，可以运行：

```
elliot@ubuntu-linux:~$ cat facts.txt | tr [:lower:] [:upper:] 
APPLES ARE RED.
GRAPES ARE GREEN.
BANANAS ARE YELLOW.
CHERRIES ARE RED.
CLOUD IS HIGH.
EARTH IS ROUND.
LINUX IS AWESOME!
CHERRIES ARE RED.
CHERRIES ARE RED.
CHERRIES ARE RED.
GRASS IS GREEN.
SWIMMING IS A SPORT.
```

您还可以显示所有单词的小写形式：

```
elliot@ubuntu-linux:~$ cat facts.txt | tr [:upper:] [:lower:] 
apples are red.
grapes are green. 
bananas are yellow. 
cherries are red. 
cloud is high. 
earth is round. 
linux is awesome! 
cherries are red. 
cherries are red. 
cherries are red. 
grass is green. 
swimming is a sport.
```

你也可以使用`-d`选项来删除字符。例如，要删除`facts.txt`中的所有空格，可以运行：

```
elliot@ubuntu-linux:~$ cat facts.txt | tr -d ' ' 
Applesarered.
Grapesaregreen.
Bananasareyellow.
Cherriesarered.
Cloudishigh.
Earthisround.
Linuxisawesome!
Cherriesarered.
Cherriesarered.
Cherriesarered.
Grassisgreen.
Swimmingisasport.
```

**一个很酷的提示**

`tr`命令不会更改（编辑）文件的内容。它只会将更改写入标准输出。但是，您可以使用输出重定向将输出存储到另一个文件中。

例如，运行以下命令：

```
elliot@ubuntu-linux:~$ cat facts.txt | tr [:lower:] [:upper:] > upper.txt
```

将命令的输出存储到：

```
cat facts.txt | tr [:lower:] [:upper:]
```

文件`upper.txt`中。

# 切割文本

如果您只想查看文件的一部分（或一节），那么`cut`命令可能非常有用。例如，您可以看到`facts.txt`文件中的每行都由单个空格分隔的多个单词组成。如果您只想查看每行的第一个单词（第一列/字段），那么可以运行以下命令：

```
elliot@ubuntu-linux:~$ cut -d ' ' -f1 facts.txt 
Apples
Grapes 
Bananas 
Cherries 
Cloud 
Earth 
Linux 
Cherries 
Cherries 
Cherries 
Grass 
Swimming
```

`-d`选项是分隔符，必须是单个字符。在这种情况下，我选择了空格字符`' '`作为分隔符。我还使用了`-f1`选项来仅查看第一个字段（列）。

如果您想查看每行的第三个单词（第三个字段），则可以使用`-f3`而不是`-f1`，如下所示：

```
elliot@ubuntu-linux:~$ cut -d ' ' -f3 facts.txt 
red.
green. 
yellow. 
red. 
high. 
round. 
awesome! 
red. 
red. 
red. 
green. 
a
```

您还可以一次选择多个字段。例如，要查看每行的第一个和第三个单词，可以使用`-f1,3`：

```
elliot@ubuntu-linux:~$ cut -d ' ' -f1,3 facts.txt 
Apples red.
Grapes green.
Bananas yellow.
Cherries red.
Cloud high.
Earth round.
Linux awesome!
Cherries red.
Cherries red.
Cherries red.
Grass green.
Swimming a 
```

# 使用 awk 进行文本处理

`awk`是一个非常强大的工具，您可以在 Linux 中用来分析和处理文本。实际上，`awk`不像您迄今为止学到的任何命令，这是因为`awk`实际上是一种编程语言。您会发现有些书专门写来解释和讨论`awk`的用法。但是，我只会在这里向您展示`awk`的基础知识，您可以自己深入研究。

您可以使用`awk`来实现与`cut`命令相同的功能。例如，要查看文件`facts.txt`中每行的第一个单词，可以运行：

```
elliot@ubuntu-linux:~$ awk '{print $1}' facts.txt 
Apples
Grapes 
Bananas 
Cherries 
Cloud 
Earth 
Linux 
Cherries 
Cherries 
Cherries 
Grass 
Swimming
```

请注意，我们不需要指定空格字符`' '`作为分隔符，就像我们在`cut`命令中所做的那样，这是因为`awk`足够聪明，可以自己弄清楚。您还可以一次查看多个字段；例如，要查看每行的第一个和第二个单词，您可以运行：

```
elliot@ubuntu-linux:~$ awk '{print $1,$2}' facts.txt 
Apples are
Grapes are 
Bananas are 
Cherries are 
Cloud is 
Earth is 
Linux is 
Cherries are 
Cherries are 
Cherries are 
Grass is 
Swimming is
```

`awk`比`cut`有一个优势，那就是`awk`足够聪明，即使每个字段之间有多个字符分隔，也能将文件分隔成不同的字段。`cut`命令只有在文件有单个分隔符时才有效，比如单个空格、冒号、逗号等。

为了演示，创建一个名为`animals.txt`的文件，并插入以下四行：

```
fox        is smart
whale is   big
cheetah  is           fast 
penguin     is cute
```

不要编辑格式；保持空格混乱：

```
elliot@ubuntu-linux:~$ cat animals.txt 
fox        is smart
whale is   big
cheetah  is           fast 
penguin     is cute
```

现在，如果您尝试使用`cut`命令仅显示每行中的第三个单词，它将失败，因为每个单词之间有多个空格分隔。

然而，`awk`足够聪明，可以弄清楚：

```
elliot@ubuntu-linux:~$ awk '{print $3}' animals.txt 
smart
big 
fast 
cute
```

正如您所看到的，每行中的第三个单词被显示出来。您也可以使用`awk`来搜索模式，就像`grep`命令一样。例如，要打印包含`facts.txt`中单词`red`的行，您可以运行以下命令：

```
elliot@ubuntu-linux:~$ awk '/red/{print}' facts.txt 
Apples are red.
Cherries are red. 
Cherries are red. 
Cherries are red. 
Cherries are red. 
```

# 通配符字符

通配符字符是 Linux 中的特殊字符，它们用于指定一组（类）字符。`表 13`列出了所有 Linux 通配符：

| **通配符** | **它的作用** |
| --- | --- |
| `*` | 匹配任何字符。 |
| `?` | 匹配任何单个字符。 |
| `[characters]` | 匹配属于字符集的字符。例如，`[abc]`将匹配字符`a`、`b`或`c`。 |
| `[!characters]` | 匹配不属于字符集的任何字符。基本上是`[characters]`的否定。例如，`[!abc]`将匹配任何不是`a`、`b`或`c`的字符。 |
| `[[:class:]]` | 匹配属于字符类的任何字符。 |

表 13：Linux 通配符

在我们讨论`tr`命令时，您已经看到了字符类。记住`[:lower:]`和`[:upper:]`代表小写和大写字母，这是字符类的两个示例。`表 14`列出了最常见的字符类：

| 字符类 | 它代表什么 |
| --- | --- |
| `[:alnum:]` | 代表所有的字母数字，即任何字母或数字。 |
| `[:alpha:]` | 代表所有的字母，即任何字母。 |
| `[:digit:]` | 代表所有的数字，即任何数字。 |
| `[:lower:]` | 代表任何小写字母。 |
| `[:upper:]` | 代表任何大写字母。 |

表 14：字符类

好了，够了这些理论！让我们看一些例子。您可以使用`*`通配符来列出您的主目录中的所有`txt`文件：

```
elliot@ubuntu-linux:~$ ls -l *.txt
-rw-rw-r-- 1 elliot elliot  96 May 11 07:01 all.txt
-rw-rw-r-- 1 elliot elliot  91 May 12 06:10 animals.txt
-rw-rw-r-- 1 elliot elliot  92 May 11 06:48 error.txt
-rw-rw-r-- 1 elliot elliot 231 May 11 08:28 facts2.txt
-rw-rw-r-- 1 elliot elliot 212 May 11 18:37 facts.txt
-rw-rw-r-- 1 elliot elliot  18 May 11 06:12 Mars.txt
-rw-rw-r-- 1 elliot elliot  29 May 11 06:34 mydate.txt
-rw-rw-r-- 1 elliot elliot  57 May 11 07:00 output.txt
-rw-rw-r-- 1 elliot elliot  57 May 11 06:20 planets.txt
lrwxrwxrwx 1 elliot elliot  9  May  8 22:02 soft.txt -> facts.txt
-rw-rw-r-- 1 elliot elliot 212 May 12 05:09 upper.txt
```

如果您只想列出以字母`f`开头的文件名，您可以使用`f*`：

```
elliot@ubuntu-linux:~$ ls -l f*
-rw-rw-r-- 1 elliot elliot 231 May 11 08:28 facts2.txt
-rw-rw-r-- 1 elliot elliot 212 May 11 18:37 facts.txt
```

如果您想列出包含三个字母后跟`.txt`扩展名的文件名，那么您可以使用`?`通配符：

```
elliot@ubuntu-linux:~$ ls -l ???.txt
-rw-rw-r-- 1 elliot elliot 96 May 11 07:01 all.txt
```

您还可以同时使用多个通配符。例如，如果您只想列出以字母`a`或`f`开头的文件名，您可以使用`[af]`通配符，后跟`*`通配符：

```
elliot@ubuntu-linux:~$ ls -l [af]*
-rw-rw-r-- 1 elliot elliot 96 May 11 07:01 all.txt
-rw-rw-r-- 1 elliot elliot 91 May 12 06:10 animals.txt
-rw-rw-r-- 1 elliot elliot 231 May 11 08:28 facts2.txt
-rw-rw-r-- 1 elliot elliot 212 May 11 18:37 facts.txt
```

您还可以使用集合否定，例如，要列出所有以除`f`之外的任何字母开头的`.txt`文件名，您可以运行`[!f]*`：

```
elliot@ubuntu-linux:~$ ls -l [!f]*.txt
-rw-rw-r-- 1 elliot elliot 96 May 11 07:01 all.txt
-rw-rw-r-- 1 elliot elliot 91 May 12 06:10 animals.txt
-rw-rw-r-- 1 elliot elliot 92 May 11 06:48 error.txt
-rw-rw-r-- 1 elliot elliot 18 May 11 06:12 Mars.txt
-rw-rw-r-- 1 elliot elliot 29 May 11 06:34 mydate.txt
-rw-rw-r-- 1 elliot elliot 57 May 11 07:00 output.txt
-rw-rw-r-- 1 elliot elliot 57 May 11 06:20 planets.txt
lrwxrwxrwx 1 elliot elliot 9 May 8 22:02 soft.txt -> facts.txt
-rw-rw-r-- 1 elliot elliot 212 May 12 05:09 upper.txt
```

现在，在我们做一些字符类的示例之前，让我们创建以下四个文件：

```
elliot@ubuntu-linux:~$ touch One TWO 7wonders GTA1
```

现在，如果您想列出以大写字母结尾的文件名，您可以使用字符类`[:upper:]`如下：

```
elliot@ubuntu-linux:~$ ls -l *[[:upper:]]
-rw-rw-r-- 1 elliot elliot 0 May 12 18:14 TWO
```

请注意，字符类本身也被括号括起来。

如果您想列出以数字（数字）开头的文件名，您可以使用字符类`[:digit:]`如下：

```
elliot@ubuntu-linux:~$ ls -l [[:digit:]]*
-rw-rw-r-- 1 elliot elliot 0 May 12 18:14 7wonders
```

唯一匹配的是文件`7wonders`。

# 正则表达式

到目前为止，我们一直在使用文件名的通配符。**正则表达式**（简称 **Regex**）是 Linux 的另一个功能，它允许您在文本文件中搜索特定的模式。正则表达式也经常与 `grep` 命令一起使用。

`表 15` 列出了最常见的正则表达式及其用途：

| **正则表达式** | **它的作用** |
| --- | --- |
| `*` | 匹配前面字符或表达式的零个或多个。 |
| `+` | 匹配前面字符或表达式的一个或多个。 |
| `.` | 匹配任何单个字符。与 `?` 通配符相同。 |
| `^` | 匹配行首的后面表达式。例如，`^dog` 将匹配所有以单词 `dog` 开头的行。 |
| `$` | 匹配行尾的前面表达式。例如，`bird$` 将匹配所有以单词 `bird` 结尾的行。 |
| `\` | 用作转义字符，以匹配反斜杠后面的特殊字符。例如，`\*` 匹配星号（*）。 |
| `[characters]` | 匹配属于字符集字符的字符。例如，`[abc]` 将匹配字符 `a`，`b` 或 `c`。 |
| `[^characters]` | 匹配不属于字符集字符的任何字符。基本上是对 `[characters]` 的否定。例如，`[!abc]` 将匹配不是 `a`，`b` 或 `c` 的任何字符。 |
| `{x,y}` | 匹配前面表达式的 x 到 y 次出现。 |
| `{x}` | 匹配前面表达式的 x 次出现。 |
| `{x,}` | 匹配前面表达式的 x 次或更多出现。 |
| `{,x}` | 匹配前面表达式的最多 x 次出现。 |

表 15：正则表达式

嗯，这是一个很长的正则表达式列表。让我们练习一下。创建一个名为 `practice.txt` 的文件，其中包含以下文本：

```
111222333
my cell number is 123-456-789\. 
you are a smart man
man is a linux command. 
man ... oh man.
dog is a cute pet. 
g
dg 
ddg 
dddg
Two stars ** 
tan
tantan 
tantantan
```

要在 `grep` 命令中使用正则表达式，可以使用 `-E` 选项或 `egrep` 命令。`egrep` 命令只是 `grep -E` 的别名。

现在，请注意 `***` 正则表达式与 `***` 通配符是不同的。要了解区别，请运行以下命令：

```
elliot@ubuntu-linux:~$ egrep d*g practice.txt
```

这将给出以下输出：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/lrn-linux-qk/img/0d507805-036b-437b-a485-843fb7e3717a.png)

图 1：* 正则表达式

注意，`d*g` 没有匹配单词 `dog`；相反，它匹配了：

+   `g`（d 的零次出现）

+   `dg`（d 的一次出现）

+   `ddg`（d 的两次出现）

+   `dddg`（d 的三次出现）

这是因为 `** *regex` 匹配前面字符或表达式的零个或多个，而 `*** 通配符` 匹配任何字符。

现在，要匹配一个或多个出现的 `d` 后跟 `g`，可以使用正则表达式 `d+g`：

```
elliot@ubuntu-linux:~$ egrep d+g practice.txt 
dg
ddg 
dddg
```

要匹配特殊字符 `*`，可以在单引号或双引号之间使用反斜杠，如下所示：

```
elliot@ubuntu-linux:~$ egrep "\*" practice.txt 
Two stars **
```

要匹配包含字母 `m` 后跟任何单个字符，然后是字母 `n` 的任何模式，可以运行：

```
elliot@ubuntu-linux:~$ egrep m.n practice.txt 
you are a smart man
man is a linux command. 
man ... oh man.
```

要匹配以单词 `man` 开头的行，可以运行：

```
elliot@ubuntu-linux:~$ egrep ^man practice.txt 
man is a linux command.
man ... oh man.
```

要匹配以单词 `man` 结尾的行，可以运行：

```
elliot@ubuntu-linux:~$ egrep man$ practice.txt 
you are a smart man
```

您也可以使用字符类。例如，要搜索包含至少一个数字的所有行，可以运行：

```
elliot@ubuntu-linux:~$ egrep "[[:digit:]]{1,}" practice.txt 
111222333
my cell number is 123-456-789.
```

您还可以搜索特定模式，如电话号码：

```
elliot@ubuntu-linux:~$ egrep "[[:digit:]]{3}-[[:digit:]]{3}-[[:digit:]]{3}" 
practice.txt
my cell number is 123-456-789.
```

这将搜索包含三个数字后跟一个破折号，然后是另外三个数字后跟另一个破折号，然后是另外三个数字的行。

我知道你认为 `regex` 很复杂，很难记住所有这些，你是对的！这就是为什么有一个包含我们讨论的所有正则表达式的 `man` 页面：

```
elliot@ubuntu-linux:~$ man regex
```

此外，`grep` man 页面包括对本章讨论的所有正则表达式的解释。

# 知识检查

对于以下练习，打开您的终端并尝试解决以下任务：

1.  显示文件 `/etc/hostname` 的大小（以字节为单位）。

1.  仅显示文件 `/etc/group` 中的组名。

1.  显示文件 `/etc/services` 中的总行数。

1.  仅显示文件 `/etc/passwd` 中包含单词 "bash" 的行。

1.  显示`uptime`命令的输出为全大写字母。


让我们玩寻找游戏

我们有时都会忘记放东西的地方；我总是忘记放我的钱包和保存文件的位置。我很确定你也会忘记放文件的位置，因此在本章中，您将学习两种不同的搜索和定位文件的方法。

# 第十二章：locate 命令

如果您知道文件的名称，但不确定文件的位置，您可以使用`locate`命令获取文件的路径。

`locate`命令在预先构建的文件数据库中搜索文件位置，因此在使用`locate`命令之前更新文件数据库至关重要。如果您不更新数据库，`locate`命令可能无法检索新创建文件的位置。

# 更新文件数据库

要更新文件数据库，您必须以 root 用户身份运行`updatedb`命令：

```
root@ubuntu-linux:~# updatedb
```

`updatedb`命令不会显示任何输出。

现在，假设我们忘记了文件`facts.txt`的位置，我们不记得它在哪里；在这种情况下，您可以运行`locate`命令，然后跟上文件名：

```
root@ubuntu-linux:~# locate facts.txt
/home/elliot/facts.txt
/var/facts.txt
```

哇！它显示了文件`facts.txt`的位置。

现在我将向您展示如果搜索新创建的文件而不更新文件数据库会发生什么。

在`/home`目录中创建一个名为`ghost.txt`的空文件：

```
root@ubuntu-linux:/# touch /home/ghost.txt
```

现在尝试搜索文件`ghost.txt`：

```
root@ubuntu-linux:/# locate ghost.txt 
root@ubuntu-linux:/#
```

`locate`命令找不到它！为什么？........那是因为您创建了一个新文件，文件数据库还不知道它。您必须先运行`updatedb`命令来更新文件数据库：

```
root@ubuntu-linux:/# updatedb 
root@ubuntu-linux:/# locate ghost.txt
/home/ghost.txt
```

是的！更新文件数据库后，`locate`命令现在可以获取文件`ghost.txt`的位置。

您还可以使用`locate`命令来使用通配符。例如，`locate *.log`将搜索系统中的所有日志文件。您还可以使用`-r`选项在搜索中启用`regex`。

# find 命令

`find`命令是您可以在 Linux 中用于搜索文件的更强大的命令。与`locate`命令不同，`find`命令实时运行，因此您无需更新任何文件数据库。`find`命令的一般语法如下：

```
find [starting-point(s)] [options] [expression]
```

`find`命令将在您指定的每个起点（目录）下搜索。

例如，要在您的`/home`目录下搜索所有`.txt`文件，您可以运行：

```
root@ubuntu-linux:~# find /home -name "*.txt"
/home/elliot/facts2.txt
/home/elliot/dir1/directory2/file1.txt
/home/elliot/dir1/directory2/file3.txt
/home/elliot/dir1/directory2/file2.txt
/home/elliot/soft.txt
/home/elliot/facts.txt
/home/elliot/practise.txt
/home/elliot/upper.txt
/home/elliot/mydate.txt
/home/elliot/all.txt
/home/elliot/Mars.txt
/home/elliot/output.txt
/home/elliot/planets.txt
/home/elliot/error.txt
/home/elliot/animals.txt
/home/ghost.txt
```

`-name`选项搜索文件名；您可以在`find`命令中使用许多其他选项。

`-type`选项搜索文件类型；例如，要在`/home/elliot/dir1`中搜索所有目录，您可以运行：

```
root@ubuntu-linux:~# find /home/elliot/dir1 -type d
/home/elliot/dir1
/home/elliot/dir1/cities
/home/elliot/dir1/directory2
```

请注意，它只列出了`/home/elliot/dir1`中的目录。要列出常规文件，您可以运行：

```
root@ubuntu-linux:~# find /home/elliot/dir1 -type f
/home/elliot/dir1/cities/paris
/home/elliot/dir1/cities/london
/home/elliot/dir1/cities/berlin
/home/elliot/dir1/directory2/file1.txt
/home/elliot/dir1/directory2/file3.txt
/home/elliot/dir1/directory2/file2.txt
```

要搜索常规文件和目录，您可以使用逗号：

```
root@ubuntu-linux:~# find /home/elliot/dir1 -type d,f
/home/elliot/dir1
/home/elliot/dir1/cities
/home/elliot/dir1/cities/paris
/home/elliot/dir1/cities/london
/home/elliot/dir1/cities/berlin
/home/elliot/dir1/directory2
/home/elliot/dir1/directory2/file1.txt
/home/elliot/dir1/directory2/file3.txt
/home/elliot/dir1/directory2/file2.txt
```

现在，以 root 用户身份在`/root`中创建两个文件`large.txt`和`LARGE.TXT`：

```
root@ubuntu-linux:~# touch large.txt LARGE.TXT
```

假设您忘记了这两个文件的位置；在这种情况下，您可以使用`/`作为起点：

```
root@ubuntu-linux:~# find / -name large.txt
/root/large.txt
```

请注意，它只列出了`large.txt`的位置。如果您还想要另一个文件`LARGE.TXT`怎么办？在这种情况下，您可以使用`-iname`选项，使搜索不区分大小写：

```
root@ubuntu-linux:~# find / -iname large.txt
/root/LARGE.TXT
/root/large.txt
```

让我们将行“12345”附加到文件`large.txt`中：

```
root@ubuntu-linux:~# echo 12345 >> large.txt
```

请注意文件`large.txt`和`LARGE.txt`的大小：

```
root@ubuntu-linux:~# du -b large.txt LARGE.TXT
6 large.txt
0 LARGE.TXT
```

文件`LARGE.TXT`的大小为零字节，因为它是空的。您可以使用`-size`选项根据文件大小搜索文件。

例如，要在`/root`目录下搜索空文件，您可以运行以下命令：

```
root@ubuntu-linux:~# find /root -size 0c
/root/LARGE.TXT
```

如您所见，它列出了`LARGE.TXT`，因为它有零个字符；`0c`表示零个字符（或字节）。现在，如果您想在`/root`下搜索大小为`6`字节的文件，您可以运行：

```
root@ubuntu-linux:~# find /root -size 6c
/root/large.txt
```

如您所见，它列出了文件`large.txt`。

您甚至可以在搜索中使用大小范围；`Table 16`向您展示了使用`find`命令的大小范围的一些示例。

| **命令** | **作用** |
| --- | --- |
| `find / -size +100M` | 将搜索所有大于`100` MB 的文件。 |
| `find / -size -5c` | 将搜索所有小于`5`字节的文件。 |
| `find / -size +50M -size -100M` | 将搜索所有大于`50` MB 但小于`100` MB 的文件。 |
| `find / -size +1G` | 将搜索所有大于`1` GB 的文件。 |

表 16：使用大小范围

`-mtime`和`-atime`选项根据修改和访问时间搜索文件。`-exec`也是一个有用的命令选项，允许您对`find`结果运行另一个命令。

例如，您可以通过运行以下命令在`/root`中对所有空文件进行长列表：

```
root@ubuntu-linux:~# find /root -size 0c -exec ls -l {} +
-rw-r--r-- 1 root root 0 May 16 14:31 /root/LARGE.TXT
```

很多人在使用`-exec`选项时忘记包括`{} +`；`{} +`引用了在查找结果中找到的所有文件。

您可以在`-exec`选项中使用任何命令。例如，您可能希望删除从查找结果中获得的文件，而不是进行长列表。在这种情况下，您可以运行：

```
root@ubuntu-linux:~# find /root -size 0c -exec rm {} +
```

现在文件`LARGE.TXT`已被删除：

```
root@ubuntu-linux:~# ls -l LARGE.TXT
ls: cannot access 'LARGE.TXT': No such file or directory
```

我强烈建议您阅读`man`页面，以探索可以使用的众多其他选项。

# 知识检查

对于以下练习，打开您的终端并尝试解决以下任务：

1.  使用`locate`命令找到文件`boot.log`的路径。

1.  查找所有大小大于`50` MB 的文件。

1.  查找所有大小在`70` MB 和`100` MB 之间的文件。

1.  查找所有属于用户`smurf`的文件。

1.  查找所有属于组`developers`的文件。


您得到了一个软件包

在本章中，您将学习如何在 Linux 系统上管理软件应用程序。您将学习如何使用 Debian 软件包管理器来下载、安装、删除、搜索和更新软件包。

# 第十三章：什么是软件包？

在 Linux 中，软件包是一个压缩的存档文件，其中包含特定软件应用程序运行所需的所有必要文件。例如，像 Firefox 这样的网络浏览器以一个包的形式提供，其中包含了 Firefox 运行所需的所有文件。

# 软件包管理器的作用

软件包管理器是我们在 Linux 中用来管理软件包的程序；也就是说，下载、安装、删除、搜索和更新软件包。请记住，不同的 Linux 发行版有不同的软件包管理器。例如，`dpkg`代表 Debian 软件包管理器，是 Ubuntu 和其他基于 Debian 的 Linux 发行版的软件包管理器。另一方面，基于 RedHat 的 Linux 发行版如 Fedora 和 CentOS 使用`rpm`，代表 RedHat 软件包管理器。其他 Linux 发行版如 SUSE 使用`zypper`作为软件包管理器等等。

# 软件包从哪里来？

很少有经验丰富的 Linux 用户会像 Windows 或 macOS 用户那样去网站下载软件包。相反，每个 Linux 发行版都有其软件包来源列表，大部分软件包都来自这些来源。这些来源也被称为**存储库**。以下图示了在您的 Linux 系统上下载软件包的过程：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/lrn-linux-qk/img/db4d532e-24a0-4944-ab21-aa59b9014390.png)

图 1：软件包存储在存储库中。请注意，软件包存储在多个存储库中

# 如何下载软件包

在 Ubuntu 和其他 Debian Linux 发行版上，您可以使用命令行实用程序`apt-get`来管理软件包。在幕后，`apt-get`利用软件包管理器`dpkg`。要下载软件包，您可以运行命令`apt-get download`后跟软件包名称：

```
apt-get download package_name
```

作为`root`用户，切换到`/tmp`目录：

```
root@ubuntu-linux:~# cd /tmp
```

要下载`cmatrix`软件包，您可以运行以下命令：

```
root@ubuntu-linux:/tmp# apt-get download cmatrix
Get:1 http://ca.archive.ubuntu.com/ubuntu bionic/universe amd64 cmatrix amd64
1.2a-5build3 [16.1 kB]
Fetched 16.1 kB in 1s (32.1 kB/s) 
```

`cmatrix`软件包将被下载到`/tmp`目录中：

```
root@ubuntu-linux:/tmp# ls 
cmatrix_1.2a-5build3_amd64.deb
```

请注意软件包名称中的`.deb`扩展名，这表示它是一个 Debian 软件包。在 RedHat 发行版上，软件包名称以`.rpm`扩展名结尾。您可以通过运行以下命令`dpkg -c`来列出`cmatrix`软件包中的文件：

```
root@ubuntu-linux:/tmp# dpkg -c cmatrix_1.2a-5build3_amd64.deb
drwxr-xr-x root/root     0 2018-04-03 06:17 ./
drwxr-xr-x root/root     0 2018-04-03 06:17 ./usr/
drwxr-xr-x root/root     0 2018-04-03 06:17 ./usr/bin/
-rwxr-xr-x root/root 18424 2018-04-03 06:17 ./usr/bin/cmatrix
drwxr-xr-x root/root     0 2018-04-03 06:17 ./usr/share/
drwxr-xr-x root/root     0 2018-04-03 06:17 ./usr/share/consolefonts/
-rw-r--r-- root/root  4096 1999-05-13 08:55 ./usr/share/consolefonts/matrix.fnt
drwxr-xr-x root/root     0 2018-04-03 06:17 ./usr/share/doc/
drwxr-xr-x root/root     0 2018-04-03 06:17 ./usr/share/doc/cmatrix/
-rw-r--r-- root/root  2066 2000-04-03 19:29 ./usr/share/doc/cmatrix/README
-rw-r--r-- root/root   258 1999-05-13 09:12 ./usr/share/doc/cmatrix/TODO
-rw-r--r-- root/root  1128 2018-04-03 06:17 ./usr/share/doc/cmatrix/copyright
drwxr-xr-x root/root     0 2018-04-03 06:17 ./usr/share/man/
drwxr-xr-x root/root     0 2018-04-03 06:17 ./usr/share/man/man1/
-rw-r--r-- root/root   932 2018-04-03 06:17 ./usr/share/man/man1/cmatrix.1.gz
drwxr-xr-x root/root     0 2018-04-03 06:17 ./usr/share/menu/
-rw-r--r-- root/root   392 2018-04-03 06:17 ./usr/share/menu/cmatrix
```

请注意，我们只下载了软件包，但尚未安装。如果您运行`cmatrix`命令，将不会发生任何事情：

```
root@ubuntu-linux:/tmp# cmatrix
bash: /usr/bin/cmatrix: No such file or directory
```

# 如何安装软件包

您可以使用`dpkg`命令的`-i`选项来安装已下载的软件包：

```
root@ubuntu-linux:/tmp# dpkg -i cmatrix_1.2a-5build3_amd64.deb 
Selecting previously unselected package cmatrix.
(Reading database ... 178209 files and directories currently installed.) Preparing to unpack cmatrix_1.2a-5build3_amd64.deb ...
Unpacking cmatrix (1.2a-5build3) ... 
Setting up cmatrix (1.2a-5build3) ...
Processing triggers for man-db (2.8.3-2ubuntu0.1) ... 
root@ubuntu-linux:/tmp#
```

就是这样！现在运行`cmatrix`命令：

```
root@ubuntu-linux:/tmp# cmatrix
```

您将在终端上看到矩阵运行，就像下图中一样：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/lrn-linux-qk/img/18aeaee2-1d00-49f9-817d-e4a6f47959d6.png)

图 2：cmatrix

我们已经采取了安装`cmatrix`软件包的长途旅程。我们首先下载了软件包，然后安装了它。您可以通过运行命令`apt-get install`后跟软件包名称来立即安装软件包（无需下载）：

```
apt-get install package_name
```

例如，您可以通过运行以下命令安装**GNOME Chess**游戏：

```
root@ubuntu-linux:/tmp# apt-get install gnome-chess 
Reading package lists... Done
Building dependency tree
Reading state information... Done 
Suggested packages:
 bbchess crafty fairymax fruit glaurung gnuchess phalanx sjeng stockfish toga2 
The following NEW packages will be installed:
 gnome-chess
0 upgraded, 1 newly installed, 0 to remove and 357 not upgraded. 
Need to get 0 B/1,514 kB of archives.
After this operation, 4,407 kB of additional disk space will be used. 
Selecting previously unselected package gnome-chess.
(Reading database ... 178235 files and directories currently installed.) Preparing to unpack .../gnome-chess_1%3a3.28.1-1_amd64.deb ...
Unpacking gnome-chess (1:3.28.1-1) ...
Processing triggers for mime-support (3.60ubuntu1) ...
Processing triggers for desktop-file-utils (0.23-1ubuntu3.18.04.2) ... 
Processing triggers for libglib2.0-0:amd64 (2.56.3-0ubuntu0.18.04.1) ... 
Setting up gnome-chess (1:3.28.1-1) ...
Processing triggers for man-db (2.8.3-2ubuntu0.1) ... 
Processing triggers for gnome-menus (3.13.3-11ubuntu1.1) ... 
Processing triggers for hicolor-icon-theme (0.17-2) ...
```

现在您可以通过运行`gnome-chess`命令来启动游戏：

```
root@ubuntu-linux:/tmp# gnome-chess
```

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/lrn-linux-qk/img/8f33af2e-d60f-4ac0-a46d-e659edb64dcc.png)

图 3：GNOME Chess

# 如何删除软件包

您可以通过运行命令`apt-get remove`后跟软件包名称来轻松删除一个软件包：

```
apt-get remove package_name
```

例如，如果你厌倦了矩阵生活方式，并决定删除`cmatrix`软件包，你可以运行：

```
root@ubuntu-linux:/tmp# apt-get remove cmatrix 
Reading package lists... Done
Building dependency tree
Reading state information... Done
The following packages will be REMOVED:
 cmatrix
0 upgraded, 0 newly installed, 1 to remove and 357 not upgraded. 
After this operation, 49.2 kB disk space will be freed.
Do you want to continue? [Y/n] y
(Reading database ... 178525 files and directories currently installed.) 
Removing cmatrix (1.2a-5build3) ...
Processing triggers for man-db (2.8.3-2ubuntu0.1) ...
```

现在，如果您运行`cmatrix`命令，您将收到一个错误：

```
root@ubuntu-linux:/tmp# cmatrix
Command 'cmatrix' not found, but can be installed with: 
apt install cmatrix
```

`apt-get remove`命令会删除（卸载）一个软件包，但不会删除软件包的配置文件。您可以使用`apt-get purge`命令来删除软件包以及其配置文件。

例如，如果您想删除`gnome-chess`软件包以及其配置文件，您可以运行：

```
root@ubuntu-linux:/tmp# apt-get purge gnome-chess 
Reading package lists... Done
Building dependency tree
Reading state information... Done
The following package was automatically installed and is no longer required:    
  hoichess
Use 'apt autoremove' to remove it.
The following packages will be REMOVED:
 gnome-chess*
0 upgraded, 0 newly installed, 1 to remove and 357 not upgraded. 
After this operation, 4,407 kB disk space will be freed.
Do you want to continue? [Y/n] y
(Reading database ... 178515 files and directories currently installed.) 
Removing gnome-chess (1:3.28.1-1) ...
Processing triggers for mime-support (3.60ubuntu1) ...
Processing triggers for desktop-file-utils (0.23-1ubuntu3.18.04.2) ... 
Processing triggers for libglib2.0-0:amd64 (2.56.3-0ubuntu0.18.04.1) ... Processing triggers for man-db (2.8.3-2ubuntu0.1) ...
Processing triggers for gnome-menus (3.13.3-11ubuntu1.1) ... 
Processing triggers for hicolor-icon-theme (0.17-2) ...
(Reading database ... 178225 files and directories currently installed.) 
Purging configuration files for gnome-chess (1:3.28.1-1) ...
```

您甚至可以在输出的最后一行中看到`Purging configuration files for gnome-chess (1:3.28.1-1) ...`，这意味着`gnome-chess`的配置文件也正在被删除。

# 如何搜索软件包

有时您不确定软件包名称。在这种情况下，您无法安装它，直到查找它。您可以使用`apt-cache search`命令，后跟搜索词或关键词来搜索软件包：

```
apt-cache search keyword
```

例如，假设您想安装`wireshark`软件包，但您只记得软件包名称中有`shark`这个词。在这种情况下，您可以运行以下命令：

```
root@ubuntu-linux:/tmp# apt-cache search shark
dopewars - drug-dealing game set in streets of New York City
dopewars-data - drug-dealing game set in streets of New York City - data files forensics-extra - Forensics Environment - extra console components (metapackage) kernelshark - Utilities for graphically analyzing function tracing in the kernel libcrypto++-dev - General purpose cryptographic library - C++ development libshark-dev - development files for Shark
libshark0 - Shark machine learning library
libwireshark-data - network packet dissection library -- data files 
libwireshark-dev - network packet dissection library -- development files libwireshark10 - network packet dissection library -- shared library 
libwiretap-dev - network packet capture library -- development files
libwsutil-dev - network packet dissection utilities library -- development files libwsutil8 - network packet dissection utilities library -- shared library netmate - netdude clone that shows pcap dump lines in network header style plowshare-modules - plowshare drivers for various file sharing websites
shark-doc - documentation for Shark
tcpxtract - extract files from network traffic based on file signatures 
tshark - network traffic analyzer - console version
wifite - Python script to automate wireless auditing using aircrack-ng tools wireshark - network traffic analyzer - meta-package
wireshark-common - network traffic analyzer - common files 
wireshark-dev - network traffic analyzer - development tools 
wireshark-doc - network traffic analyzer - documentation 
wireshark-gtk - network traffic analyzer - GTK+ version 
wireshark-qt - network traffic analyzer - Qt version
zeitgeist-explorer - GUI application for monitoring and debugging zeitgeist forensics-extra-gui - Forensics Environment - extra GUI components (metapackage) horst - Highly Optimized Radio Scanning Tool
libvirt-wireshark - Wireshark dissector for the libvirt protocol 
libwiretap7 - network packet capture library -- shared library 
libwscodecs1 - network packet dissection codecs library -- shared library minetest-mod-animals - Minetest mod providing animals
nsntrace - perform network trace of a single process by using network namespaces libwireshark11 - network packet dissection library -- shared library 
libwiretap8 - network packet capture library -- shared library
libwscodecs2 - network packet dissection codecs library -- shared library libwsutil9 - network packet dissection utilities library -- shared library
```

然后您会被大量输出淹没，列出所有软件包名称中包含`shark`这个词的软件包。我敢打赌您可以在输出的中间找到`wireshark`软件包。我们可以通过使用`-n`选项获得一个更短和精炼的输出：

```
root@ubuntu-linux:/tmp# apt-cache -n search shark
kernelshark - Utilities for graphically analyzing function tracing in the kernel libshark-dev - development files for Shark
libshark0 - Shark machine learning library
libwireshark-data - network packet dissection library -- data files 
libwireshark-dev - network packet dissection library -- development files
libwireshark10 - network packet dissection library -- shared library 
shark-doc - documentation for Shark
tshark - network traffic analyzer - console version 
wireshark - network traffic analyzer - meta-package 
wireshark-common - network traffic analyzer - common files 
wireshark-dev - network traffic analyzer - development tools 
wireshark-doc - network traffic analyzer - documentation 
wireshark-gtk - network traffic analyzer - GTK+ version 
wireshark-qt - network traffic analyzer - Qt version
libndpi-wireshark - extensible deep packet inspection library - wireshark dissector 
libvirt-wireshark - Wireshark dissector for the libvirt protocol
libwireshark11 - network packet dissection library -- shared library
```

这将只列出软件包名称中包含`shark`这个词的软件包。现在，您可以通过运行以下命令来安装`wireshark`：

```
root@ubuntu-linux:/tmp# apt-get install wireshark
```

# 如何显示软件包信息

要查看软件包信息，您可以使用`apt-cache show`命令，后跟软件包名称：

```
apt-cache show package_name
```

例如，要显示`cmatrix`软件包信息，您可以运行：

```
root@ubuntu-linux:~# apt-cache show cmatrix 
Package: cmatrix
Architecture: amd64 
Version: 1.2a-5build3 
Priority: optional 
Section: universe/misc 
Origin: Ubuntu
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com> 
Original-Maintainer: Diego Fernández Durán <diego@goedi.net>
Bugs: https://bugs.launchpad.net/ubuntu/+filebug 
Installed-Size: 48
Depends: libc6 (>= 2.4), libncurses5 (>= 6), libtinfo5 (>= 6) 
Recommends: kbd
Suggests: cmatrix-xfont
Filename: pool/universe/c/cmatrix/cmatrix_1.2a-5build3_amd64.deb 
Size: 16084
MD5sum: 8dad2a99d74b63cce6eeff0046f0ac91 
SHA1: 3da3a0ec97807e6f53de7653e4e9f47fd96521c2
SHA256: cd50212101bfd71479af41e7afc47ea822c075ddb1ceed83895f8eaa1b79ce5d Homepage: http://www.asty.org/cmatrix/
Description-en_CA: simulates the display from "The Matrix" 
Screen saver for the terminal based in the movie "The Matrix".
 * Support terminal resize.
 * Screen saver mode: any key closes it.
 * Selectable color.
 * Change text scroll rate.
Description-md5: 9af1f58e4b6301a6583f036c780c6ae6
```

您可以在输出中看到许多有用的信息，包括软件包描述和软件包维护者的联系信息，如果您发现错误并希望报告它，则这些信息很有用。您还将了解软件包是否依赖于其他软件包。

**软件包依赖**可能会变成一场噩梦，因此我强烈建议您尽可能使用`apt-get install`命令来安装软件包，因为它在安装软件包时会检查和解决软件包依赖关系。另一方面，`dpkg -i`命令不会检查软件包依赖关系。记住这一点！

您可以使用`apt-cache depends`命令来列出软件包依赖关系：

```
apt-cache depends package_name
```

例如，要查看为使`cmatrix`正常工作而需要安装的软件包列表，您可以运行以下命令：

```
root@ubuntu-linux:~# apt-cache depends cmatrix 
cmatrix
 Depends: libc6 
 Depends: libncurses5 
 Depends: libtinfo5 
 Recommends: kbd 
 Suggests: cmatrix-xfont
```

正如您所看到的，`cmatrix`软件包依赖于三个软件包：

+   `libc6`

+   `libncurses5`

+   `libtinfo5`

这三个软件包必须安装在系统上，以便`cmatrix`正常运行。

# 列出所有软件包

您可以使用`dpkg -l`命令来列出系统上安装的所有软件包：

```
root@ubuntu-linux:~# dpkg -l
```

您还可以使用`apt-cache pkgnames`命令来列出所有可供您安装的软件包：

```
root@ubuntu-linux:~# apt-cache pkgnames 
libdatrie-doc
libfstrcmp0-dbg 
libghc-monadplus-doc 
librime-data-sampheng 
python-pyao-dbg 
fonts-georgewilliams
python3-aptdaemon.test 
libcollada2gltfconvert-dev 
python3-doc8
r-bioc-hypergraph
.
.
.
.
.
```

您可以将输出导入到`wc -l`命令中，以获得可用软件包的总数：

```
root@ubuntu-linux:~# apt-cache pkgnames | wc -l 64142
```

哇！这是一个庞大的数字；我的系统上有超过 64,000 个可用软件包。

您可能还想知道您的系统用于获取所有这些软件包的存储库（源）。这些存储库包含在文件`/etc/ap- t/sources.list`中，以及在目录`/etc/apt/- sources.list.d/`下具有后缀`.list`的任何文件中。您可以查看`man`页面：

```
root@ubuntu-linux:~# man sources.list
```

了解如何向系统添加存储库。

您还可以使用`apt-cache policy`命令来列出系统上启用的所有存储库：

```
root@ubuntu-linux:~# apt-cache policy 
Package files:
100 /var/lib/dpkg/status 
    release a=now
500 http://dl.google.com/linux/chrome/deb stable/main amd64 
    Packages release v=1.0,o=Google LLC,a=stable,n=stable,l=Google,c=main,
    b=amd64 origin dl.google.com
100 http://ca.archive.ubuntu.com/ubuntu bionic-backports/main i386 
    Packages release v=18.04,o=Ubuntu,a=bionic-backports,n=bionic,l=Ubuntu,
    c=main,b=i386 origin ca.archive.ubuntu.com
100 http://ca.archive.ubuntu.com/ubuntu bionic-backports/main amd64 
    Packages release v=18.04,o=Ubuntu,a=bionic-backports,n=bionic,l=Ubuntu,
    c=main,b=amd64 origin ca.archive.ubuntu.com
500 http://ca.archive.ubuntu.com/ubuntu bionic/multiverse i386 
    Packages release v=18.04,o=Ubuntu,a=bionic,n=bionic,
    l=Ubuntu,c=multiverse,b=i386 origin ca.archive.ubuntu.com
500 http://ca.archive.ubuntu.com/ubuntu bionic/multiverse amd64 
    Packages release v=18.04,o=Ubuntu,a=bionic,n=bionic,l=Ubuntu,
    c=multiverse,b=amd64 origin ca.archive.ubuntu.com
500 http://ca.archive.ubuntu.com/ubuntu bionic/universe i386 
    Packages release v=18.04,o=Ubuntu,a=bionic,n=bionic,l=Ubuntu,
    c=universe,b=i386 origin ca.archive.ubuntu.com
500 http://ca.archive.ubuntu.com/ubuntu bionic/universe amd64 
    Packages release v=18.04,o=Ubuntu,a=bionic,n=bionic,l=Ubuntu,
    c=universe,b=amd64 origin ca.archive.ubuntu.com
500 http://ca.archive.ubuntu.com/ubuntu bionic/restricted i386 
    Packages release v=18.04,o=Ubuntu,a=bionic,n=bionic,l=Ubuntu,
    c=restricted,b=i386 origin ca.archive.ubuntu.com
500 http://ca.archive.ubuntu.com/ubuntu bionic/restricted amd64 
    Packages release v=18.04,o=Ubuntu,a=bionic,n=bionic,l=Ubuntu,
    c=restricted,b=amd64 origin ca.archive.ubuntu.com
500 http://ca.archive.ubuntu.com/ubuntu bionic/main i386 
    Packages release v=18.04,o=Ubuntu,a=bionic,
    n=bionic,l=Ubuntu,c=main,b=i386 origin ca.archive.ubuntu.com
500 http://ca.archive.ubuntu.com/ubuntu bionic/main amd64 
    Packages release v=18.04,o=Ubuntu,a=bionic,n=bionic,
    l=Ubuntu,c=main,b=amd64 origin ca.archive.ubuntu.com
Pinned packages:
```

如果您渴望知道哪个存储库提供了特定的软件包，您可以使用`apt-cache policy`命令，后跟软件包名称：

```
apt-cache policy package_name
```

例如，要知道哪个存储库提供了`cmatrix`软件包，您可以运行：

```
root@ubuntu-linux:~# apt-cache policy cmatrix 
cmatrix:
 Installed: 1.2a-5build3 
 Candidate: 1.2a-5build3 
 Version table:
*** 1.2a-5build3 500
 500 http://ca.archive.ubuntu.com/ubuntu bionic/universe amd64 Packages
 100 /var/lib/dpkg/status
```

从输出中，您可以看到`cmatrix`软件包来自于[`ca.archive.ubuntu.com/ubuntu`](http://ca.archive.ubuntu.com/ubuntu)的 bionic/universe 存储库。

# 修补您的系统

如果某个软件包有可用的更新版本，那么您可以使用`apt-get install --only-upgrade`命令，后跟软件包名称来升级它：

```
apt-get install --only-upgrade package_name
```

例如，您可以通过运行以下命令来升级`nano`软件包：

```
root@ubuntu-linux:~# apt-get install --only-upgrade nano 
Reading package lists... Done
Building dependency tree
Reading state information... Done
nano is already the newest version (2.9.3-2).
The following package was automatically installed and is no longer required: 
 hoichess
Use 'apt autoremove' to remove it.
0 upgraded, 0 newly installed, 0 to remove and 357 not upgraded.
```

您还可以通过运行以下命令来升级系统上安装的所有软件包：

1.  `apt-get update`

1.  `apt-get upgrade`

第一个命令`apt-get update`将更新可用软件包及其版本的列表，但不会进行任何安装或升级：

```
root@ubuntu-linux:~# apt-get update
Ign:1 http://dl.google.com/linux/chrome/deb stable InRelease 
Hit:2 http://ca.archive.ubuntu.com/ubuntu bionic InRelease
Hit:3 http://ppa.launchpad.net/linuxuprising/java/ubuntu bionic InRelease 
Hit:4 http://dl.google.com/linux/chrome/deb stable Release
Hit:5 http://security.ubuntu.com/ubuntu bionic-security InRelease 
Hit:6 http://ca.archive.ubuntu.com/ubuntu bionic-updates InRelease 
Hit:8 http://ca.archive.ubuntu.com/ubuntu bionic-backports InRelease 
Reading package lists... Done
```

第二个命令`apt-get upgrade`将升级系统上安装的所有软件包：

```
root@ubuntu-linux:~# apt-get upgrade 
Reading package lists... Done 
Building dependency tree
Reading state information... Done 
Calculating upgrade... Done
The following package was automatically installed and is no longer required: 
 hoichess
Use 'apt autoremove' to remove it.
The following packages have been kept back:
 gstreamer1.0-gl libcogl20 libgail-3-0 libgl1-mesa-dri libgstreamer-gl1.0-0 
 libreoffice-calc libreoffice-core libreoffice-draw libreoffice-gnome 
    libreoffice-gtk3 
 libwayland-egl1-mesa libxatracker2 linux-generic linux-headers-generic
 software-properties-common software-properties-gtk ubuntu-desktop 
The following packages will be upgraded:
 apt apt-utils aptdaemon aptdaemon-data aspell base-files bash bind9-host bluez 
 python2.7-minimal python3-apt python3-aptdaemon python3-aptdaemon.gtk3widgets 
 python3-problem-report python3-update-manager python3-urllib3 python3.6
342 upgraded, 0 newly installed, 0 to remove and 30 not upgraded. 
Need to get 460 MB of archives.
After this operation, 74.3 MB of additional disk space will be used. 
Do you want to continue? [Y/n]
```

请记住顺序很重要；也就是说，在运行`apt-get upgrade`命令之前，您需要运行`apt-get update`命令。

在 Linux 术语中，升级系统上安装的所有软件包的过程称为**打补丁系统**。

# 知识检查

对于以下练习，打开您的终端并尝试解决以下任务：

1.  在您的系统上安装`tmux`软件包。

1.  列出`vim`软件包的所有依赖项。

1.  在您的系统上安装`cowsay`软件包。

1.  删除`cowsay`软件包以及其所有配置文件。

1.  升级系统上的所有软件包（打补丁您的系统）。


杀死进程

在您的系统上运行的任何程序都是一个进程。在本章中，您将学习有关 Linux 进程的所有内容。您将学习如何查看进程信息。您还将学习如何向进程发送不同的信号。此外，您将了解前台和后台进程之间的区别。

# 第十四章：什么是进程？

进程只是运行程序的一个实例。因此，您系统上运行的任何程序都是一个进程。以下都是进程的例子：

+   在您的系统上运行的 Firefox 或任何网络浏览器都是一个进程。

+   您正在运行的终端现在就是一个进程。

+   您在系统上玩的任何游戏都是一个进程。

+   复制文件是一个进程。

就像文件一样，每个进程都由特定用户拥有。进程的所有者只是启动该进程的用户。

要列出所有由特定用户拥有的进程，您可以运行命令`ps -u`后跟用户名：

```
ps -u username
```

例如，要列出所有由`elliot`拥有的进程，您可以运行：

```
root@ubuntu-linux:~# ps -u elliot
 PID TTY       TIME CMD
1365 ?     00:00:00 systemd
1366 ?     00:00:00 (sd-pam)
1379 ?     00:00:00 gnome-keyring-d
1383 tty2  00:00:00 gdm-x-session
1385 tty2  00:00:18 Xorg
1389 ?     00:00:00 dbus-daemon
1393 tty2  00:00:00 gnome-session-b
1725 ?     00:00:00 ssh-agent
1797 ?     00:00:00 gvfsd
. 
. 
. 
.
```

输出中的第一列列出了**进程标识符**（**PIDs**）。PID 是一个唯一标识进程的数字，就像文件`inodes`一样。输出的最后一列列出了进程名称。

您可以使用`ps -e`命令列出系统上正在运行的所有进程：

```
root@ubuntu-linux:~# ps -e 
PID TTY     TIME  CMD
1  ?     00:00:01 systemd
2  ?     00:00:00 kthreadd
4  ?     00:00:00 kworker/0:0H
6  ?     00:00:00 mm_percpu_wq
7  ?     00:00:00 ksoftirqd/0
8  ?     00:00:00 rcu_sched
9  ?     00:00:00 rcu_bh
10 ?     00:00:00 migration/0
11 ?     00:00:00 watchdog/0
12 ?     00:00:00 cpuhp/0
13 ?     00:00:00 kdevtmpfs
.
.
.
.
```

您还可以使用`-f`选项来获取更多信息：

```
root@ubuntu-linux:~# ps -ef
UID    PID  PPID C STIME TTY    TIME    CMD
root      1    0 0 11:23    ? 00:00:01 /sbin/init splash
root      2    0 0 11:23    ? 00:00:00 [kthreadd]
root      4    2 0 11:23    ? 00:00:00 [kworker/0:0H]
root      6    2 0 11:23    ? 00:00:00 [mm_percpu_wq]
root      7    2 0 11:23    ? 00:00:00 [ksoftirqd/0]
root      8    2 0 11:23    ? 00:00:01 [rcu_sched]
root      9    2 0 11:23    ? 00:00:00 [rcu_bh]
root     10    2 0 11:23    ? 00:00:00 [migration/0]
elliot 1835 1393 1 11:25 tty2 00:00:58 /usr/bin/gnome-shell
elliot 1853 1835 0 11:25 tty2 00:00:00 ibus-daemon --xim --panel disable
elliot 1857 1365 0 11:25    ? 00:00:00 /usr/lib/gnome-shell/gnome-shell
elliot 1865 1853 0 11:25 tty2 00:00:00 /usr/lib/ibus/ibus-dconf
elliot 1868    1 0 11:25 tty2 00:00:00 /usr/lib/ibus/ibus-x11 --kill-daemon
elliot 1871 1365 0 11:25    ? 00:00:00 /usr/lib/ibus/ibus-portal
. 
. 
. 
```

输出的第一列列出了进程所有者的用户名。输出的第三列列出了**父进程标识符**（**PPID**）。那么，父进程是什么？

# 父进程与子进程

父进程是启动了一个或多个子进程的进程。一个完美的例子将是您的终端和您的 bash shell；当您打开终端时，您的 bash shell 也会启动。

要获取进程的 PID，您可以使用`pgrep`命令后跟进程名称：

```
pgrep process_name
```

例如，要获取您的终端进程的 PID，您可以运行：

```
elliot@ubuntu-linux:~$ pgrep terminal 
10009
```

我的终端的 PID 是`10009`。现在，让我们获取 bash 进程的 PID：

```
elliot@ubuntu-linux:~$ pgrep bash 
10093
```

我的 bash shell 的 PID 是`10093`。现在，您可以使用`-p`选项后跟 bash PID 来获取您的 bash 进程的信息：

```
elliot@ubuntu-linux:~$ ps -fp 10093
UID     PID   PPID  C  STIME  TTY   TIME   CMD
elliot 10093 10009  0  13:37 pts/1 00:00:00 bash
```

您可以从输出中看到，我的 bash 进程的 PPID 等于我的终端进程的 PID。这证明了终端进程已启动了 bash 进程。在这种情况下，bash 进程被称为终端进程的子进程：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/lrn-linux-qk/img/c2580a3e-58f9-4bee-a96a-f64ba220be44.png)

图 1：父进程与子进程

`top`命令是一个非常有用的命令，您可以使用它实时查看进程的信息。您可以查看其`man`页面以了解如何使用它：

```
elliot@ubuntu-linux:~$ man top 
```

上述命令的输出如下截图所示：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/lrn-linux-qk/img/af6b849c-c266-4a45-8ac4-416ca8afc82e.png)

图 2：top 命令

# 前台与后台进程

Linux 中有两种类型的进程：

+   前台进程

+   后台进程

前台进程是附加到您的终端的进程。您必须等待前台进程完成，然后才能继续使用您的终端。

另一方面，后台进程是不附加到您的终端的进程，因此您可以在后台进程运行时使用您的终端。

`yes`命令会重复输出跟在其后的任何字符串，直到被杀死：

```
elliot@ubuntu-linux:~$ whatis yes
yes (1)               - output a string repeatedly until killed
```

例如，要在您的终端上重复输出单词`hello`，您可以运行命令：

```
elliot@ubuntu-linux:~$ yes hello 
hello
hello 
hello 
hello 
hello 
hello 
hello 
hello 
hello 
hello
.
.
.
```

请注意，它将继续运行，您无法在终端上执行其他操作；这是前台进程的一个典型例子。要收回您的终端，您需要杀死该进程。您可以通过按以下*Ctrl* + *C*键组合来杀死该进程：

```
hello 
hello 
hello 
hello 
hello
^C
elliot@ubuntu-linux:~$

```

一旦你按下*Ctrl* + *C*，进程将被终止，你可以继续使用你的终端。让我们做另一个例子；你可以使用`firefox`命令从你的终端启动 Firefox：

```
elliot@ubuntu-linux:~$ firefox
```

Firefox 浏览器将启动，但你将无法在终端上做任何事情直到关闭 Firefox；这是另一个前台进程的例子。现在，按下*Ctrl* + *C*来终止 Firefox 进程，这样你就可以重新使用你的终端了。

你可以通过添加&字符来将 Firefox 作为后台进程启动，如下所示：

```
elliot@ubuntu-linux:~$ firefox &
[1] 3468
elliot@ubuntu-linux:~$
```

Firefox 现在作为后台进程运行，你可以继续使用你的终端而不必关闭 Firefox。

# 向进程发送信号

你可以通过信号与进程进行交互和通信。有各种信号，每个信号都有不同的目的。要列出所有可用的信号，你可以运行`kill -L`命令：

```
elliot@ubuntu-linux:~$ kill -L
1) SIGHUP 2) SIGINT 3) SIGQUIT 4) SIGILL 5) SIGTRAP
6) SIGABRT 7) SIGBUS 8) SIGFPE 9) SIGKILL 10) SIGUSR1
11) SIGSEGV 12) SIGUSR2 13) SIGPIPE 14) SIGALRM 15) SIGTERM
16) SIGSTKFLT 17) SIGCHLD 18) SIGCONT 19) SIGSTOP 20) SIGTSTP
21) SIGTTIN 22) SIGTTOU 23) SIGURG 24) SIGXCPU 25) SIGXFSZ
26) SIGVTALRM 27) SIGPROF 28) SIGWINCH 29) SIGIO 30) SIGPWR
31) SIGSYS 34) SIGRTMIN 35) SIGRTMIN+1 36) SIGRTMIN+2 37) SIGRTMIN+3
38) SIGRTMIN+4 39) SIGRTMIN+5 40) SIGRTMIN+6 41) SIGRTMIN+7 42) SIGRTMIN+8
43) SIGRTMIN+9 44) SIGRTMIN+10 45) SIGRTMIN+11 46) SIGRTMIN+12 47) SIGRTMIN+13
48) SIGRTMIN+14 49) SIGRTMIN+15 50) SIGRTMAX-14 51) SIGRTMAX-13 52) SIGRTMAX-12
53) SIGRTMAX-11 54) SIGRTMAX-10 55) SIGRTMAX-9 56) SIGRTMAX-8 57) SIGRTMAX-7
58) SIGRTMAX-6 59) SIGRTMAX-5 60) SIGRTMAX-4 61) SIGRTMAX-3 62) SIGRTMAX-2
63) SIGRTMAX-1 64) SIGRTMAX
```

注意到每个信号都有一个数字值。例如，`19`是`SIGSTOP`信号的数字值。

为了了解信号的工作原理，让我们首先将 Firefox 作为后台进程启动：

```
elliot@ubuntu-linux:~$ firefox &
[1] 4218
```

注意到 Firefox 在我的系统上的 PID 是`4218`。我可以通过发送`SIGKILL`信号来终止 Firefox，如下所示：

```
elliot@ubuntu-linux:~$ kill -SIGKILL 4218
[1]+ Killed             firefox
```

这将立即关闭 Firefox。你也可以使用`SIGKILL`信号的数字值：

```
elliot@ubuntu-linux:~$ kill -9 4218
```

一般来说，`kill`命令的语法如下：

```
kill -SIGNAL PID
```

让我们再次将 Firefox 作为后台进程启动：

```
elliot@ubuntu-linux:~$ firefox & 
[1] 4907
```

注意到 Firefox 在我的系统上的 PID 是`4907`。现在继续在 Firefox 上播放 YouTube 视频。在你这样做之后，回到你的终端并向 Firefox 发送`SIGSTOP`信号：

```
elliot@ubuntu-linux:~$ kill -SIGSTOP 4907
```

你会注意到 Firefox 变得无响应，你的 YouTube 视频停止了；没问题 - 我们可以通过向 Firefox 发送`SIGCONT`信号来解决这个问题：

```
elliot@ubuntu-linux:~$ kill -SIGCONT 4907
```

这将使 Firefox 恢复，并且你的 YouTube 视频现在会继续播放。

到目前为止，你已经学会了三种信号：

+   `SIGKILL`：终止一个进程

+   `SIGSTOP`：停止一个进程

+   `SIGCONT`：继续一个进程

你可以使用`pkill`命令使用进程名称而不是进程标识符。例如，要关闭你的终端进程，你可以运行以下命令：

```
elliot@ubuntu-linux:~$ pkill -9 terminal
```

现在让我们做一些有趣的事情；打开你的终端并运行以下命令：

```
elliot@ubuntu-linux:~$ pkill -SIGSTOP terminal
```

哈哈！你的终端现在被冻结了。我会让你处理这个！

你可以向进程发送许多其他信号；查看以下`man`页面以了解每个信号的用途：

```
elliot@ubuntu-linux:~$ man signal
```

# 处理进程优先级

每个进程都有一个由友好度量表确定的优先级，范围从**-20**到**19**。友好值越低，进程的优先级越高，所以友好值为**-20**给予进程最高的优先级。另一方面，友好值为**19**给予进程最低的优先级：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/lrn-linux-qk/img/9505008f-5775-4723-9777-c7c8e53e87ac.png)

图 3：友好度量表

你可能会问自己：*我们为什么关心进程的优先级？*答案是效率！你的 CPU 就像一个繁忙餐厅里的服务员。一个高效的服务员会一直忙碌，确保所有顾客都得到满意的服务。同样，你的 CPU 分配时间给系统上运行的所有进程。优先级高的进程会得到 CPU 的更多关注。另一方面，优先级低的进程不会得到 CPU 的太多关注。

## 查看进程优先级

将 Firefox 作为后台进程启动：

```
elliot@ubuntu-linux:~$ firefox &
 [1] 6849
```

你可以使用`ps`命令查看进程的友好值：

```
elliot@ubuntu-linux:~$ ps -o nice -p 6849
NI
0
```

我的 Firefox 进程有一个友好值为**0**，这是默认值（平均优先级）。

## 为新进程设置优先级

你可以使用`nice`命令以你期望的优先级启动一个进程。`nice`命令的一般语法如下：

```
nice -n -20 →19 process
```

假设你要升级系统上的所有软件包；给这样一个进程尽可能高的优先级是明智的。为此，你可以以`root`用户身份运行以下命令：

```
root@ubuntu-linux:~# nice -n -20 apt-get upgrade
```

## 改变一个进程的优先级

您可以使用`renice`命令更改正在运行的进程的优先级。我们已经看到 Firefox 正在以默认进程优先级零运行；让我们更改 Firefox 的优先级，并将其设置为可能的最低优先级：

```
root@ubuntu-linux:~# renice -n 19 -p 6849
6849 (process ID) old priority 0, new priority 19
```

太棒了！现在我希望 Firefox 对我来说不会很慢；毕竟，我刚刚告诉我的 CPU 不要太关注 Firefox！

# /proc 目录

Linux 中的每个进程都由`/proc`中的一个目录表示。例如，如果您的 Firefox 进程的 PID 为`6849`，那么目录`/proc/6849`将表示 Firefox 进程：

```
root@ubuntu-linux:~# pgrep firefox
6849
root@ubuntu-linux:~# cd /proc/6849
root@ubuntu-linux:/proc/6849#
```

在进程的目录中，您可以找到关于进程的许多有价值和富有洞察力的信息。例如，您将找到一个名为`exe`的软链接，指向进程的可执行文件：

```
root@ubuntu-linux:/proc/6849# ls -l exe
lrwxrwxrwx 1 elliot elliot 0 Nov 21 18:02 exe -> /usr/lib/firefox/firefox
```

您还会找到`status`文件，其中存储了有关进程的各种信息；这些信息包括进程状态、PPID、进程使用的内存量等等：

```
root@ubuntu-linux:/proc/6849# head status 
Name: firefox
Umask: 0022
State: S (sleeping) Tgid: 6849
Ngid: 0
Pid: 6849
PPid: 1990
TracerPid: 0
Uid: 1000 1000 1000 1000
Gid: 1000 1000 1000 1000
```

`limits`文件显示了为进程设置的当前限制：

```
root@ubuntu-linux:/proc/7882# cat limits
Limit                  Soft Limit   Hard Limit   Units
Max cpu time           unlimited    unlimited    seconds
Max file size          unlimited    unlimited    bytes
Max data size          unlimited    unlimited    bytes
Max stack size         8388608      unlimited    bytes
Max core file size     0            unlimited    bytes
Max resident set       unlimited    unlimited    bytes
Max processes          15599        15599        processes
Max open files         4096         4096         files
Max locked memory      16777216     16777216     bytes
Max address space      unlimited    unlimited    bytes
Max file locks         unlimited    unlimited    locks
Max pending signals    15599        15599        signals
Max msgqueue size      819200       819200       bytes
Max nice priority      0            0 
Max realtime priority  0            0 
Max realtime timeout   unlimited    unlimited    us
```

`fd`目录将显示进程当前在系统上正在使用的所有文件：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/lrn-linux-qk/img/b80b52ee-796b-450e-8186-b7e7ee62705c.png)

图 4：fd 目录

您还可以使用`lsof`命令列出进程当前正在使用的所有文件：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/lrn-linux-qk/img/cccfab95-38f4-4dd3-b54a-8116d9054551.png)

图 5：lsof 命令

# 知识检查

对于以下练习，打开您的终端并尝试解决以下任务：

1.  列出您正在运行的终端的进程 ID。

1.  列出您正在运行的终端的父进程 ID。

1.  使用`kill`命令关闭您的终端。

1.  将 Firefox 作为后台进程启动。

1.  将 Firefox 的优先级更改为最高优先级。
