# 现代 Python 标准库秘籍（一）

> 原文：[`zh.annas-archive.org/md5/3fab99a8deba9438823e5414cd05b6e8`](https://zh.annas-archive.org/md5/3fab99a8deba9438823e5414cd05b6e8)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

Python 是一种非常强大和广泛使用的语言，具有功能齐全的标准库。人们说它是“电池已包含”，这意味着您将需要做的大部分工作都可以在标准库中找到。

这样庞大的功能集可能会让开发人员感到迷失，而且并不总是清楚哪些可用工具最适合解决特定任务。对于这些任务中的许多，也将提供外部库，您可以安装以解决相同的问题。因此，您可能不仅会想知道从标准库提供的所有功能中选择哪个类或函数来使用，还会想知道何时最好切换到外部库来实现您的目标。

本书试图提供 Python 标准库中可用工具的概述，以解决许多常见任务，并提供利用这些工具实现特定结果的配方。对于基于标准库的解决方案可能变得过于复杂或有限的情况，它还将尝试建议标准库之外的工具，以帮助您迈出下一步。

# 本书的受众

本书非常适合希望在 Python 中编写富有表现力、高度响应、可管理、可扩展和具有弹性的代码的开发人员。预期具有 Python 的先前编程知识。

# 本书涵盖的内容

第一章，“容器和数据结构”，涵盖了标准库提供的不太明显的数据结构和容器的情况。虽然像`list`和`dict`这样的基本容器被视为理所当然，但本章将深入探讨不太常见的容器和内置容器的更高级用法。

第二章，“文本管理”，涵盖了文本操作、字符串比较、匹配以及为基于文本的软件格式化输出时最常见的需求。

第三章，“命令行”，涵盖了如何编写基于终端/Shell 的软件，解析参数，编写交互式 Shell，并实现日志记录。

第四章，“文件系统和目录”，涵盖了如何处理目录和文件、遍历文件系统以及处理与文件系统和文件名相关的多种编码类型。

第五章，“日期和时间”，涵盖了如何解析日期和时间、格式化它们，并对日期进行数学运算以计算过去和未来的日期。

第六章，“读/写数据”，涵盖了如何读取和写入常见文件格式的数据，如 CSV、XML 和 ZIP，以及如何正确管理编码文本文件。

第七章，“算法”，涵盖了一些常见的排序、搜索和压缩算法，以及您可能需要在任何类型的数据集上应用的常见操作。

第八章，“加密”，涵盖了标准库提供的与安全相关的功能，或者可以使用标准库中可用的哈希函数来实现的功能。

第九章，“并发”，涵盖了标准库提供的各种并发模型，如线程、进程和协程，特别关注这些执行者的编排。

第十章，“网络”，涵盖了标准库提供的实现基于网络的应用程序的功能，以及如何从一些常见协议（如 FTP 和 IMAP）中读取数据，以及如何实现通用的 TCP/IP 应用程序。

第十一章，“Web 开发”，涵盖了如何实现基于 HTTP 的应用程序、简单的 HTTP 服务器和功能齐全的 Web 应用程序。它还将涵盖如何通过 HTTP 与第三方软件进行交互。

第十二章，*多媒体*，涵盖了检测文件类型、检查图像和生成声音的基本操作。

第十三章，*图形用户界面*，涵盖了 UI 应用程序的最常见构建块，可以组合在一起创建桌面环境的简单应用程序。

第十四章，*开发工具*，涵盖了标准库提供的工具，帮助开发人员进行日常工作，如编写测试和调试软件。

# 充分利用本书

读者预期已经具有 Python 和编程的先验知识。来自其他语言或对 Python 有中级了解的开发人员将从本书中获益。

本书假定读者已经安装了 Python 3.5+，并且大多数配方都展示了 Unix 系统（如 macOS 或 Linux）的示例，但也可以在 Windows 系统上运行。Windows 用户可以依赖于 Windows 子系统来完美地复制这些示例。

# 下载示例代码文件

您可以从[www.packtpub.com](https://www.packtpub.com/)的帐户中下载本书的示例代码文件。如果您在其他地方购买了本书，您可以访问[www.packtpub.com/support](http://www.packtpub.com/support)并注册，以便文件直接通过电子邮件发送给您。

您可以按照以下步骤下载代码文件：

1.  在[www.packtpub.com](http://www.packtpub.com/support)上登录或注册。

1.  选择“支持”选项卡。

1.  点击“代码下载和勘误”。

1.  在搜索框中输入书名，然后按照屏幕上的说明操作。

下载文件后，请确保使用最新版本的解压缩或提取文件夹：

+   Windows 上的 WinRAR/7-Zip

+   Mac 上的 Zipeg/iZip/UnRarX

+   Linux 上的 7-Zip/PeaZip

本书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Modern-Python-Standard-Library-Cookbook`](https://github.com/PacktPublishing/Modern-Python-Standard-Library-Cookbook)。我们还有其他代码包来自我们丰富的图书和视频目录，可在[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)上找到。去看看吧！

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码单词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。例如："我们还可以通过将`ChainMap`与`defaultdict`结合来摆脱最后的`.get`调用。"

代码块设置如下：

```py
for word in 'hello world this is a very nice day'.split():
    if word in counts:
        counts[word] += 1
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目会以粗体设置：

```py
class Bunch(dict):
    def __init__(self, **kwds):
        super().__init__(**kwds)
        self.__dict__ = self
```

任何命令行输入或输出都以以下方式编写：

```py
>>> print(population['japan'])
127
```

**粗体**：表示新术语、重要单词或屏幕上看到的单词。例如，菜单或对话框中的单词会在文本中以这种方式出现。例如："如果涉及**持续集成**系统"

警告或重要提示会以这种方式出现。提示和技巧会以这种方式出现。

# 各节

本书中，您会发现一些经常出现的标题（*准备工作*，*如何做*，*它是如何工作的*，*还有更多*，和*另请参阅*）。

为了清晰地说明如何完成一个配方，使用以下各节：

# 准备工作

本节告诉您配方中可以期待什么，并描述了如何设置配方所需的任何软件或任何预备设置。

# 如何做…

本节包含遵循配方所需的步骤。

# 它是如何工作的…

本节通常包括对前一节中发生的事情的详细解释。

# 还有更多…

本节包含有关配方的其他信息，以使您对配方更加了解。

# 另请参阅

本节提供了与食谱相关的其他有用信息的链接。


# 第一章：容器和数据结构

在本章中，我们将涵盖以下食谱：

+   计数频率-计算任何可散列值的出现次数

+   带有回退的字典-为任何丢失的键设置回退值

+   解包多个-关键字参数-如何多次使用`**`

+   有序字典-保持字典中键的顺序

+   MultiDict-每个键具有多个值的字典

+   优先处理条目-高效获取排序条目的顶部

+   Bunch-表现得像对象的字典

+   枚举-处理已知状态集

# 介绍

Python 具有一组非常简单和灵活的内置容器。作为 Python 开发人员，您几乎可以用`dict`或`list`实现任何功能。Python 字典和列表的便利性是如此之大，以至于开发人员经常忘记它们的限制。与任何数据结构一样，它们都经过了优化，并且设计用于特定用例，可能在某些情况下效率低下，甚至无法处理它们。

曾经试图在字典中两次放入一个键吗？好吧，你不能，因为 Python 字典被设计为具有唯一键的哈希表，但*MultiDict*食谱将向您展示如何做到这一点。曾经试图在不遍历整个列表的情况下从列表中获取最低/最高值吗？列表本身不能，但在*优先处理条目*食谱中，我们将看到如何实现这一点。

标准 Python 容器的限制对 Python 专家来说是众所周知的。因此，多年来，标准库已经发展出了克服这些限制的方法，经常有一些模式是如此常见，以至于它们的名称被广泛认可，即使它们没有正式定义。

# 计数频率

在许多类型的程序中，一个非常常见的需求是计算值或事件的出现次数，这意味着计数频率。无论是需要计算文本中的单词，博客文章上的点赞次数，还是跟踪视频游戏玩家的得分，最终计数频率意味着计算特定值的数量。

对于这种需求，最明显的解决方案是保留我们需要计数的计数器。如果有两个、三个或四个，也许我们可以在一些专用变量中跟踪它们，但如果有数百个，保留这么多变量显然是不可行的，我们很快就会得到一个基于容器的解决方案来收集所有这些计数器。

# 如何做到...

以下是此食谱的步骤：

1.  假设我们想要跟踪文本中单词的频率；标准库来拯救我们，并为我们提供了一种非常好的跟踪计数和频率的方法，即通过专用的`collections.Counter`对象。

1.  `collections.Counter`对象不仅跟踪频率，还提供了一些专用方法来检索最常见的条目，至少出现一次的条目，并快速计算任何可迭代对象。

1.  您提供给`Counter`的任何可迭代对象都将被“计数”其值的频率：

```py
>>> txt = "This is a vast world you can't traverse world in a day"
>>>
>>> from collections import Counter
>>> counts = Counter(txt.split())
```

1.  结果将会正是我们所期望的，即我们短语中单词的频率字典：

```py
Counter({'a': 2, 'world': 2, "can't": 1, 'day': 1, 'traverse': 1, 
         'is': 1, 'vast': 1, 'in': 1, 'you': 1, 'This': 1})
```

1.  然后，我们可以轻松查询最常见的单词：

```py
>>> counts.most_common(2)
[('world', 2), ('a', 2)]
```

1.  获取特定单词的频率：

```py
>>> counts['world']
2
```

或者，获取总出现次数：

```py
>>> sum(counts.values())
12
```

1.  我们甚至可以对计数器应用一些集合操作，例如合并它们，减去它们，或检查它们的交集：

```py
>>> Counter(["hello", "world"]) + Counter(["hello", "you"])
Counter({'hello': 2, 'you': 1, 'world': 1})
>>> Counter(["hello", "world"]) & Counter(["hello", "you"])
Counter({'hello': 1})
```

# 它是如何工作的...

我们的计数代码依赖于`Counter`只是一种特殊类型的字典，字典可以通过提供一个可迭代对象来构建。可迭代对象中的每个条目都将添加到字典中。

在计数器的情况下，添加一个元素意味着增加其计数；对于我们列表中的每个“单词”，我们会多次添加该单词（每次它在列表中出现一次），因此它在`Counter`中的值每次遇到该单词时都会继续增加。

# 还有更多...

依赖`Counter`实际上并不是跟踪频率的唯一方法；我们已经知道`Counter`是一种特殊类型的字典，因此复制`Counter`的行为应该是非常简单的。

我们每个人可能都会得到这种形式的字典：

```py
counts = dict(hello=0, world=0, nice=0, day=0)
```

每当我们遇到`hello`、`world`、`nice`或`day`的新出现时，我们就会增加字典中关联的值，并称之为一天：

```py
for word in 'hello world this is a very nice day'.split():
    if word in counts:
        counts[word] += 1
```

通过依赖`dict.get`，我们也可以很容易地使其适应计算任何单词，而不仅仅是我们可以预见的那些：

```py
for word in 'hello world this is a very nice day'.split():
    counts[word] = counts.get(word, 0) + 1
```

但标准库实际上提供了一个非常灵活的工具，我们可以使用它来进一步改进这段代码，那就是`collections.defaultdict`。

`defaultdict`是一个普通的字典，对于任何缺失的值都不会抛出`KeyError`，而是调用我们可以提供的函数来生成缺失的值。

因此，诸如`defaultdict(int)`这样的东西将创建一个字典，为任何它没有的键提供`0`，这对我们的计数目的非常方便：

```py
from collections import defaultdict

counts = defaultdict(int)
for word in 'hello world this is a very nice day'.split():
    counts[word] += 1
```

结果将会完全符合我们的期望：

```py
defaultdict(<class 'int'>, {'day': 1, 'is': 1, 'a': 1, 'very': 1, 'world': 1, 'this': 1, 'nice': 1, 'hello': 1})
```

对于每个单词，第一次遇到它时，我们将调用`int`来获得起始值，然后加`1`。由于`int`在没有任何参数的情况下调用时会返回`0`，这就实现了我们想要的效果。

虽然这大致解决了我们的问题，但对于计数来说远非完整解决方案——我们跟踪频率，但在其他方面，我们是自己的。如果我们想知道我们的词袋中最常见的词是什么呢？

`Counter`的便利性基于其提供的一组专门用于计数的附加功能；它不仅仅是一个具有默认数值的字典，它是一个专门用于跟踪频率并提供方便的访问方式的类。

# 带有回退的字典

在处理配置值时，通常会在多个地方查找它们——也许我们从配置文件中加载它们——但我们可以用环境变量或命令行选项覆盖它们，如果没有提供选项，我们可以有一个默认值。

这很容易导致像这样的长链的`if`语句：

```py
value = command_line_options.get('optname')
if value is None:
    value = os.environ.get('optname')
if value is None:
    value = config_file_options.get('optname')
if value is None:
    value = 'default-value'
```

这很烦人，而对于单个值来说可能只是烦人，但随着添加更多选项，它将变成一个庞大、令人困惑的条件列表。

命令行选项是一个非常常见的用例，但问题与链式作用域解析有关。在 Python 中，变量是通过查看`locals()`来解析的；如果找不到它们，解释器会查看`globals()`，如果还找不到，它会查找内置变量。

# 如何做到...

对于这一步，您需要按照以下步骤进行：

1.  与使用多个`if`实例相比，`dict.get`的默认值链的替代方案可能并不会改进代码太多，如果我们想要添加一个额外的作用域，我们将不得不在每个查找值的地方都添加它。

1.  `collections.ChainMap`是这个问题的一个非常方便的解决方案；我们可以提供一个映射容器的列表，它将在它们所有中查找一个键。

1.  我们之前的涉及多个不同`if`实例的示例可以转换为这样的形式：

```py
import os
from collections import ChainMap

options = ChainMap(command_line_options, os.environ, config_file_options)
value = options.get('optname', 'default-value')
```

1.  我们还可以通过将`ChainMap`与`defaultdict`结合来摆脱最后的`.get`调用。在这种情况下，我们可以使用`defaultdict`为每个键提供一个默认值：

```py
import os
from collections import ChainMap, defaultdict

options = ChainMap(command_line_options, os.environ, config_file_options,
                   defaultdict(lambda: 'default-value'))
value = options['optname']
value2 = options['other-option']
```

1.  打印`value`和`value2`将会得到以下结果：

```py
optvalue
default-value
```

`optname`将从包含它的`command_line_options`中检索，而`other-option`最终将由`defaultdict`解析。

# 它是如何工作的...

`ChainMap`类接收多个字典作为参数；每当向`ChainMap`请求一个键时，它实际上会逐个查看提供的字典，以检查该键是否在其中任何一个中可用。一旦找到键，它就会返回，就好像它是`ChainMap`自己拥有的键一样。

未提供的选项的默认值是通过将`defaultdict`作为提供给`ChainMap`的最后一个字典来实现的。每当在之前的任何字典中找不到键时，它会在`defaultdict`中查找，`defaultdict`使用提供的工厂函数为所有键返回默认值。

# 还有更多...

`ChainMap`的另一个很棒的功能是它也允许更新，但是它总是更新第一个字典，而不是更新找到键的字典。结果是一样的，因为在下一次查找该键时，我们会发现第一个字典覆盖了该键的任何其他值（因为它是检查该键的第一个地方）。优点是，如果我们将空字典作为提供给`ChainMap`的第一个映射，我们可以更改这些值而不触及原始容器：

```py
>>> population=dict(italy=60, japan=127, uk=65) >>> changes = dict()
>>> editablepop = ChainMap(changes, population)

>>> print(editablepop['japan'])
127
>>> editablepop['japan'] += 1
>>> print(editablepop['japan'])
128
```

但即使我们将日本的人口更改为 1.28 亿，原始人口也没有改变：

```py
>>> print(population['japan'])
127
```

我们甚至可以使用`changes`来找出哪些值被更改了，哪些值没有被更改：

```py
>>> print(changes.keys()) 
dict_keys(['japan']) 
>>> print(population.keys() - changes.keys()) 
{'italy', 'uk'}
```

顺便说一句，如果字典中包含的对象是可变的，并且我们直接对其进行改变，`ChainMap`无法避免改变原始对象。因此，如果我们在字典中存储的不是数字，而是列表，每当我们向字典追加值时，我们将改变原始字典：

```py
>>> citizens = dict(torino=['Alessandro'], amsterdam=['Bert'], raleigh=['Joseph']) >>> changes = dict() 
>>> editablecits = ChainMap(changes, citizens) 
>>> editablecits['torino'].append('Simone') 
>>> print(editablecits['torino']) ['Alessandro', 'Simone']
>>> print(changes)
{}
>>> print(citizens)
{'amsterdam': ['Bert'], 
 'torino': ['Alessandro', 'Simone'], 
 'raleigh': ['Joseph']} 
```

# 解包多个关键字参数

经常情况下，你会发现自己需要从字典中向函数提供参数。如果你曾经面临过这种需求，你可能也会发现自己需要从多个字典中获取参数。

通常，Python 函数通过解包（`**`语法）从字典中接受参数，但到目前为止，在同一次调用中两次解包还不可能，也没有简单的方法来合并两个字典。

# 如何做...

这个食谱的步骤是：

1.  给定一个函数`f`，我们希望按以下方式从两个字典`d1`和`d2`传递参数：

```py
>>> def f(a, b, c, d):
...     print (a, b, c, d)
...
>>> d1 = dict(a=5, b=6)
>>> d2 = dict(b=7, c=8, d=9)
```

1.  `collections.ChainMap`可以帮助我们实现我们想要的；它可以处理重复的条目，并且适用于任何 Python 版本：

```py
>>> f(**ChainMap(d1, d2))
5 6 8 9
```

1.  在 Python 3.5 及更新版本中，你还可以通过字面语法组合多个字典来创建一个新字典，然后将结果字典作为函数的参数传递：

```py
>>> f(**{**d1, **d2})
5 7 8 9
```

1.  在这种情况下，重复的条目也被接受，但按照`ChainMap`的优先级的相反顺序处理（从右到左）。请注意，`b`的值为`7`，而不是`ChainMap`中的`6`，这是由于优先级的反向顺序造成的。

由于涉及到大量的解包运算符，这种语法可能更难阅读，而使用`ChainMap`对于读者来说可能更加明确发生了什么。

# 它是如何工作的...

正如我们已经从之前的示例中知道的那样，`ChainMap`在所有提供的字典中查找键，因此它就像所有字典的总和。解包运算符（`**`）通过将所有键放入容器，然后为每个键提供一个参数来工作。

由于`ChainMap`具有所有提供的字典键的总和，它将提供包含在所有字典中的键给解包运算符，从而允许我们从多个字典中提供关键字参数。

# 还有更多...

自 Python 3.5 通过 PEP 448，现在可以解包多个映射以提供关键字参数：

```py
>>> def f(a, b, c, d):
...     print (a, b, c, d)
...
>>> d1 = dict(a=5, b=6)
>>> d2 = dict(c=7, d=8)
>>> f(**d1, **d2)
5 6 7 8
```

这种解决方案非常方便，但有两个限制：

+   仅适用于 Python 3.5+

+   它无法处理重复的参数

如果你不知道你要解包的映射/字典来自哪里，很容易出现重复参数的问题：

```py
>>> d1 = dict(a=5, b=6)
>>> d2 = dict(b=7, c=8, d=9)
>>> f(**d1, **d2)
Traceback (most recent call last):
File "<stdin>", line 1, in <module>
TypeError: f() got multiple values for keyword argument 'b'
```

在前面的示例中，`b`键在`d1`和`d2`中都有声明，这导致函数抱怨它收到了重复的参数。

# 有序字典

对于新用户来说，Python 字典最令人惊讶的一个方面是，它们的顺序是不可预测的，而且在不同的环境中可能会发生变化。因此，您在自己的系统上期望的键的顺序可能在朋友的计算机上完全不同。

这经常会在测试期间导致意外的失败；如果涉及到持续集成系统，则运行测试的系统上的字典键的排序可能与您的系统上的排序不同，这可能导致随机失败。

假设您有一小段代码，它生成了一个带有一些属性的 HTML 标签：

```py
>>> attrs = dict(style="background-color:red", id="header")
>>> '<span {}>'.format(' '.join('%s="%s"' % a for a in attrs.items()))
'<span id="header" style="background-color:red">'
```

也许会让你感到惊讶的是，在某些系统上，你最终会得到这样的结果：

```py
'<span id="header" style="background-color:red">'
```

而在其他情况下，结果可能是这样的：

```py
'<span style="background-color:red" id="header">'
```

因此，如果您期望能够比较生成的字符串，以检查您的函数在生成此标签时是否做对了，您可能会感到失望。

# 如何做到这一点...

键的排序是一个非常方便的功能，在某些情况下，它实际上是必需的，因此 Python 标准库提供了`collections.OrderedDict`容器。

在`collections.OrderedDict`的情况下，键始终按插入的顺序排列：

```py
>>> attrs = OrderedDict([('id', 'header'), ('style', 'background-color:red')])
>>> '<span {}>'.format(' '.join('%s="%s"' % a for a in attrs.items()))
'<span id="header" style="background-color:red">'
```

# 它是如何工作的...

`OrderedDict`同时存储键到值的映射和一个用于保留它们顺序的键列表。

因此，每当您查找键时，查找都会通过映射进行，但每当您想要列出键或对容器进行迭代时，您都会通过键列表来确保它们按照插入的顺序进行处理。

使用`OrderedDict`的主要问题是，Python 在 3.6 之前的版本中没有保证关键字参数的任何特定顺序：

```py
>>> attrs = OrderedDict(id="header", style="background-color:red")
```

即使使用了`OrderedDict`，这将再次引入完全随机的键顺序。这不是因为`OrderedDict`没有保留这些键的顺序，而是因为它们可能以随机顺序接收到。

由于 PEP 468 的原因，现在在 Python 3.6 和更新版本中保证了参数的顺序（字典的顺序仍然不确定；请记住，它们是有序的只是偶然的）。因此，如果您使用的是 Python 3.6 或更新版本，我们之前的示例将按预期工作，但如果您使用的是较旧版本的 Python，您将得到一个随机的顺序。

幸运的是，这是一个很容易解决的问题。与标准字典一样，`OrderedDict`支持任何可迭代的内容作为其内容的来源。只要可迭代对象提供了一个键和一个值，就可以用它来构建`OrderedDict`。

因此，通过在元组中提供键和值，我们可以在任何 Python 版本中在构建时提供它们并保留顺序：

```py
>>> OrderedDict((('id', 'header'), ('style', 'background-color:red')))
OrderedDict([('id', 'header'), ('style', 'background-color:red')])
```

# 还有更多...

Python 3.6 引入了保留字典键顺序的保证，作为对字典的一些更改的副作用，但它被认为是一个内部实现细节，而不是语言保证。自 Python 3.7 以来，它成为语言的一个官方特性，因此如果您使用的是 Python 3.6 或更新版本，可以放心地依赖于字典的顺序。

# MultiDict

如果您曾经需要提供一个反向映射，您可能已经发现 Python 缺乏一种方法来为字典中的每个键存储多个值。这是一个非常常见的需求，大多数语言都提供了某种形式的多映射容器。

Python 倾向于有一种单一的做事方式，因为为键存储多个值意味着只是为键存储一个值列表，所以它不提供专门的容器。

存储值列表的问题在于，为了能够将值附加到我们的字典中，列表必须已经存在。

# 如何做到这一点...

按照以下步骤进行此操作：

1.  正如我们已经知道的，`defaultdict`将通过调用提供的可调用函数为每个缺失的键创建一个默认值。我们可以将`list`构造函数作为可调用函数提供：

```py
>>> from collections import defaultdict
>>> rd = defaultdict(list)
```

1.  因此，我们通过使用`rd[k].append(v)`而不是通常的`rd[k] = v`来将键插入到我们的多映射中：

```py
>>> for name, num in [('ichi', 1), ('one', 1), ('uno', 1), ('un', 1)]:
...   rd[num].append(name)
...
>>> rd
defaultdict(<class 'list'>, {1: ['ichi', 'one', 'uno', 'un']})
```

# 它是如何工作的...

`MultiDict`通过为每个键存储一个列表来工作。每当访问一个键时，都会检索包含该键所有值的列表。

在缺少键的情况下，将提供一个空列表，以便为该键添加值。

这是因为每次`defaultdict`遇到缺少的键时，它将插入一个由调用`list`生成的值。调用`list`实际上会提供一个空列表。因此，执行`rd[v]`将始终提供一个列表，取决于`v`是否是已经存在的键。一旦我们有了列表，添加新值只是追加它的问题。

# 还有更多...

Python 中的字典是关联容器，其中键是唯一的。一个键只能出现一次，且只有一个值。

如果我们想要支持每个键多个值，实际上可以通过将`list`保存为键的值来满足需求。然后，该列表可以包含我们想要保留的所有值：

```py
>>> rd = {1: ['one', 'uno', 'un', 'ichi'],
...       2: ['two', 'due', 'deux', 'ni'],
...       3: ['three', 'tre', 'trois', 'san']}
>>> rd[2]
['two', 'due', 'deux', 'ni']
```

如果我们想要为`2`（例如西班牙语）添加新的翻译，我们只需追加该条目：

```py
>>> rd[2].append('dos')
>>> rd[2]
['two', 'due', 'deux', 'ni', 'dos']
```

当我们想要引入一个新的键时，问题就出现了：

```py
>>> rd[4].append('four')
Traceback (most recent call last):
    File "<stdin>", line 1, in <module>
KeyError: 4
```

对于键`4`，没有列表存在，因此我们无法追加它。因此，我们的自动反向映射片段无法轻松适应处理多个值，因为它在尝试插入值时会出现键错误：

```py
>>> rd = {}
>>> for k,v in d.items():
...     rd[v].append(k)
Traceback (most recent call last):
    File "<stdin>", line 2, in <module>
KeyError: 1
```

检查每个条目是否已经在字典中，然后根据情况采取行动并不是非常方便。虽然我们可以依赖字典的`setdefault`方法来隐藏该检查，但是通过使用`collections.defaultdict`可以获得更加优雅的解决方案。

# 优先处理条目

选择一组值的第一个/顶部条目是一个非常频繁的需求；这通常意味着定义一个优先于其他值的值，并涉及排序。

但是排序可能很昂贵，并且每次添加条目到您的值时重新排序肯定不是一种非常方便的方式来从一组具有某种优先级的值中选择第一个条目。

# 如何做...

堆是一切具有优先级的完美匹配，例如优先级队列：

```py
import time
import heapq

class PriorityQueue:
    def __init__(self):
        self._q = []

    def add(self, value, priority=0):
        heapq.heappush(self._q, (priority, time.time(), value))

    def pop(self):
        return heapq.heappop(self._q)[-1]
```

然后，我们的`PriorityQueue`可以用于检索给定优先级的条目：

```py
>>> def f1(): print('hello')
>>> def f2(): print('world')
>>>
>>> pq = PriorityQueue()
>>> pq.add(f2, priority=1)
>>> pq.add(f1, priority=0)
>>> pq.pop()()
hello
>>> pq.pop()()
world
```

# 它是如何工作的...

`PriorityQueue`通过在堆中存储所有内容来工作。堆在检索排序集的顶部/第一个元素时特别高效，而无需实际对整个集进行排序。

我们的优先级队列将所有值存储在一个三元组中：`priority`，`time.time()`和`value`。

我们元组的第一个条目是`priority`（较低的优先级更好）。在示例中，我们记录了`f1`的优先级比`f2`更好，这确保了当我们使用`heap.heappop`获取要处理的任务时，我们首先得到`f1`，然后是`f2`，这样我们最终得到的是`hello world`消息而不是`world hello`。

第二个条目`timestamp`用于确保具有相同优先级的任务按其插入顺序进行处理。最旧的任务将首先被处理，因为它将具有最小的时间戳。

然后，我们有值本身，这是我们要为任务调用的函数。

# 还有更多...

对于排序的一个非常常见的方法是将条目列表保存在一个元组中，其中第一个元素是我们正在排序的`key`，第二个元素是值本身。

对于记分牌，我们可以保留每个玩家的姓名和他们得到的分数：

```py
scores = [(123, 'Alessandro'),
          (143, 'Chris'),
          (192, 'Mark']
```

将这些值存储在元组中有效，因为比较两个元组是通过将第一个元组的每个元素与另一个元组中相同索引位置的元素进行比较来执行的：

```py
>>> (10, 'B') > (10, 'A')
True
>>> (11, 'A') > (10, 'B')
True
```

如果您考虑字符串，就可以很容易地理解发生了什么。`'BB' > 'BB'`与`('B', 'B') > ('B', 'A')`相同；最终，字符串只是字符列表。

我们可以利用这个属性对我们的`scores`进行排序，并检索比赛的获胜者：

```py
>>> scores = sorted(scores)
>>> scores[-1]
(192, 'Mark')
```

这种方法的主要问题是，每次我们向列表添加条目时，我们都必须重新对其进行排序，否则我们的计分板将变得毫无意义：

```py
>>> scores.append((137, 'Rick'))
>>> scores[-1]
(137, 'Rick')
>>> scores = sorted(scores)
>>> scores[-1]
(192, 'Mark')
```

这很不方便，因为如果我们有多个地方向列表添加元素，很容易错过重新排序的地方，而且每次对整个列表进行排序可能会很昂贵。

Python 标准库提供了一种数据结构，当我们想要找出比赛的获胜者时，它是完美的匹配。

在`heapq`模块中，我们有一个完全工作的堆数据结构的实现，这是一种特殊类型的树，其中每个父节点都小于其子节点。这为我们提供了一个具有非常有趣属性的树：根元素始终是最小的。

并且它是建立在列表之上的，这意味着`l[0]`始终是`heap`中最小的元素：

```py
>>> import heapq
>>> l = []
>>> heapq.heappush(l, (192, 'Mark'))
>>> heapq.heappush(l, (123, 'Alessandro'))
>>> heapq.heappush(l, (137, 'Rick'))
>>> heapq.heappush(l, (143, 'Chris'))
>>> l[0]
(123, 'Alessandro')
```

顺便说一句，您可能已经注意到，堆找到了我们比赛的失败者，而不是获胜者，而我们对找到最好的玩家，即最高价值的玩家感兴趣。

这是一个我们可以通过将所有分数存储为负数来轻松解决的小问题。如果我们将每个分数存储为`* -1`，那么堆的头部将始终是获胜者：

```py
>>> l = []
>>> heapq.heappush(l, (-143, 'Chris'))
>>> heapq.heappush(l, (-137, 'Rick'))
>>> heapq.heappush(l, (-123, 'Alessandro'))
>>> heapq.heappush(l, (-192, 'Mark'))
>>> l[0]
(-192, 'Mark')
```

# Bunch

Python 非常擅长变形对象。每个实例都可以有自己的属性，并且在运行时添加/删除对象的属性是完全合法的。

偶尔，我们的代码需要处理未知形状的数据。例如，在用户提交的数据的情况下，我们可能不知道用户提供了哪些字段；也许我们的一些用户有名字，一些有姓氏，一些有一个或多个中间名字段。

如果我们不是自己处理这些数据，而只是将其提供给其他函数，我们实际上并不关心数据的形状；只要我们的对象具有这些属性，我们就没问题。

一个非常常见的情况是在处理协议时，如果您是一个 HTTP 服务器，您可能希望向您后面运行的应用程序提供一个`request`对象。这个对象有一些已知的属性，比如`host`和`path`，还可能有一些可选的属性，比如`query`字符串或`content`类型。但是，它也可以有客户端提供的任何属性，因为 HTTP 在头部方面非常灵活，我们的客户端可能提供了一个`x-totally-custom-header`，我们可能需要将其暴露给我们的代码。

在表示这种类型的数据时，Python 开发人员通常倾向于查看字典。最终，Python 对象本身是建立在字典之上的，并且它们符合将任意值映射到名称的需求。

因此，我们可能最终会得到以下内容：

```py
>>> request = dict(host='www.example.org', path='/index.html')
```

这种方法的一个副作用在于，一旦我们不得不将这个对象传递给其他代码，特别是第三方代码时，就变得非常明显。函数通常使用对象工作，虽然它们不需要特定类型的对象，因为鸭子类型是 Python 中的标准，但它们会期望某些属性存在。

另一个非常常见的例子是在编写测试时，Python 作为一种鸭子类型的语言，希望提供一个假对象而不是提供对象的真实实例是绝对合理的，特别是当我们需要模拟一些属性的值（如使用`@property`声明），因此我们不希望或无法创建对象的真实实例。

在这种情况下，使用字典是不可行的，因为它只能通过`request['path']`语法访问其值，而不能通过`request.path`访问，这可能是我们提供对象给函数时所期望的。

此外，我们访问这个值的次数越多，就越清楚使用点符号表示法传达了代码意图的实体协作的感觉，而字典传达了纯粹数据的感觉。

一旦我们记住 Python 对象可以随时改变形状，我们可能会尝试创建一个对象而不是字典。不幸的是，我们无法在初始化时提供属性：

```py
>>> request = object(host='www.example.org', path='/index.html')
Traceback (most recent call last):
    File "<stdin>", line 1, in <module>
TypeError: object() takes no parameters
```

如果我们尝试在构建对象后分配这些属性，情况也不会有所改善：

```py
>>> request = object()
>>> request.host = 'www.example.org'
Traceback (most recent call last):
    File "<stdin>", line 1, in <module>
AttributeError: 'object' object has no attribute 'host'
```

# 如何做...

通过一点努力，我们可以创建一个利用字典来包含我们想要的任何属性并允许通过属性和字典访问的类：

```py
>>> class Bunch(dict):
...    def __getattribute__(self, key):
...        try: 
...            return self[key]
...        except KeyError:
...            raise AttributeError(key)
...    
...    def __setattr__(self, key, value): 
...        self[key] = value
...
>>> b = Bunch(a=5)
>>> b.a
5
>>> b['a']
5
```

# 它是如何工作的...

`Bunch`类继承自`dict`，主要是为了提供一个值可以被存储的上下文，然后大部分工作由`__getattribute__`和`__setattr__`完成。因此，对于在对象上检索或设置的任何属性，它们只会检索或设置`self`中的一个键（记住我们继承自`dict`，所以`self`实际上是一个字典）。

这使得`Bunch`类能够将任何值存储和检索为对象的属性。方便的特性是它在大多数情况下既可以作为对象又可以作为`dict`来使用。

例如，可以找出它包含的所有值，就像任何其他字典一样：

```py
>>> b.items()
dict_items([('a', 5)])
```

它还能够将它们作为属性访问：

```py
>>> b.c = 7
>>> b.c
7
>>> b.items()
dict_items([('a', 5), ('c', 7)])
```

# 还有更多...

我们的`bunch`实现还不完整，因为它将无法通过任何类名称测试（它总是被命名为`Bunch`），也无法通过任何继承测试，因此无法伪造其他对象。

第一步是使`Bunch`能够改变其属性，还能改变其名称。这可以通过每次创建`Bunch`时动态创建一个新类来实现。该类将继承自`Bunch`，除了提供一个新名称外不会做任何其他事情：

```py
>>> class BunchBase(dict):
...    def __getattribute__(self, key):
...        try: 
...            return self[key]
...        except KeyError:
...            raise AttributeError(key)
...    
...    def __setattr__(self, key, value): 
...        self[key] = value
...
>>> def Bunch(_classname="Bunch", **attrs):
...     return type(_classname, (BunchBase, ), {})(**attrs)
>>>
```

`Bunch`函数从原来的类本身变成了一个工厂，将创建所有作为`Bunch`的对象，但可以有不同的类。每个`Bunch`将是`BunchBase`的子类，其中在创建`Bunch`时可以提供`_classname`名称：

```py
>>> b = Bunch("Request", path="/index.html", host="www.example.org")
>>> print(b)
{'path': '/index.html', 'host': 'www.example.org'}
>>> print(b.path)
/index.html
>>> print(b.host)
www.example.org
```

这将允许我们创建任意类型的`Bunch`对象，并且每个对象都将有自己的自定义类型：

```py
>>> print(b.__class__)
<class '__main__.Request'>
```

下一步是使我们的`Bunch`实际上看起来像它必须模仿的任何其他类型。这对于我们想要在另一个对象的位置使用`Bunch`的情况是必要的。由于`Bunch`可以具有任何类型的属性，因此它可以代替任何类型的对象，但为了能够这样做，它必须通过自定义类型的类型检查。

我们需要回到我们的`Bunch`工厂，并使`Bunch`对象不仅具有自定义类名，还要看起来是从自定义父类继承而来。

为了更好地理解发生了什么，我们将声明一个示例`Person`类型；这个类型将是我们的`Bunch`对象尝试伪造的类型：

```py
class Person(object):
    def __init__(name, surname):
        self.name = name
        self.surname = surname

    @property
    def fullname(self):
        return '{} {}'.format(self.name, self.surname)
```

具体来说，我们将通过一个自定义的`print`函数打印`Hello Your Name`，该函数仅适用于`Person`：

```py
def hello(p):
    if not isinstance(p, Person):
        raise ValueError("Sorry, can only greet people")
    print("Hello {}".format(p.fullname))
```

我们希望改变我们的`Bunch`工厂，接受该类并创建一个新类型：

```py
def Bunch(_classname="Bunch", _parent=None, **attrs):
    parents = (_parent, ) if parent else tuple()
    return type(_classname, (BunchBase, ) + parents, {})(**attrs)
```

现在，我们的`Bunch`对象将显示为我们想要的类的实例，并且始终显示为`_parent`的子类：

```py
>>> p = Bunch("Person", Person, fullname='Alessandro Molina')
>>> hello(p)
Hello Alessandro Molina
```

`Bunch`可以是一种非常方便的模式；在其完整和简化版本中，它被广泛用于许多框架中，具有各种实现，但都可以实现几乎相同的结果。

展示的实现很有趣，因为它让我们清楚地知道发生了什么。有一些非常聪明的方法可以实现`Bunch`，但可能会让人难以猜测发生了什么并进行自定义。

实现`Bunch`模式的另一种可能的方法是通过修补包含类的所有属性的`__dict__`类：

```py
class Bunch(dict):
    def __init__(self, **kwds):
        super().__init__(**kwds)
        self.__dict__ = self
```

在这种形式下，每当创建`Bunch`时，它将以`dict`的形式填充其值（通过调用`super().__init__`，这是`dict`的初始化），然后，一旦所有提供的属性都存储在`dict`中，它就会用`self`交换`__dict__`对象，这是包含所有对象属性的字典。这使得刚刚填充了所有值的`dict`也成为了包含对象所有属性的`dict`。

我们之前的实现是通过替换我们查找属性的方式来工作的，而这个实现是替换我们查找属性的地方。

# 枚举

枚举是存储只能表示几种状态的值的常见方式。每个符号名称都绑定到一个特定的值，通常是数字，表示枚举可以具有的状态。

枚举在其他编程语言中非常常见，但直到最近，Python 才没有对枚举提供明确的支持。

# 如何做到...

通常，枚举是通过将符号名称映射到数值来实现的；在 Python 中，通过`enum.IntEnum`是允许的：

```py
>>> from enum import IntEnum
>>> 
>>> class RequestType(IntEnum):
...     POST = 1
...     GET = 2
>>>
>>> request_type = RequestType.POST
>>> print(request_type)
RequestType.POST
```

# 它是如何工作的...

`IntEnum`是一个整数，除了在类定义时创建所有可能的值。`IntEnum`继承自`int`，因此它的值是真正的整数。

在`RequestType`的定义过程中，所有`enum`的可能值都在类体内声明，并且这些值通过元类进行重复验证。

此外，`enum`提供了对特殊值`auto`的支持，它的意思是*只是放一个值进去，我不在乎*。通常你只关心它是`POST`还是`GET`，你通常不关心`POST`是`1`还是`2`。

最后但并非最不重要的是，如果枚举定义了至少一个可能的值，那么枚举就不能被子类化。

# 还有更多...

`IntEnum`的值在大多数情况下表现得像`int`，这通常很方便，但如果开发人员不注意类型，它们可能会引起问题。

例如，如果提供了另一个枚举或整数值，而不是正确的枚举值，函数可能会意外执行错误的操作：

```py
>>> def do_request(kind):
...    if kind == RequestType.POST:
...        print('POST')
...    else:
...        print('OTHER')
```

例如，使用`RequestType.POST`或`1`调用`do_request`将做完全相同的事情：

```py
>>> do_request(RequestType.POST)
POST
>>> do_request(1)
POST
```

当我们不想将枚举视为数字时，可以使用`enum.Enum`，它提供了不被视为普通数字的枚举值：

```py
>>> from enum import Enum
>>> 
>>> class RequestType(Enum):
...     POST = 1
...     GET = 2
>>>
>>> do_request(RequestType.POST)
POST
>>> do_request(1)
OTHER
```

因此，一般来说，如果你需要一个简单的枚举值集合或依赖于`enum`的可能状态，`Enum`更安全，但如果你需要依赖于`enum`的一组数值，`IntEnum`将确保它们表现得像数字。


# 第二章：文本管理

在本章中，我们将涵盖以下配方：

+   模式匹配-正则表达式不是解析模式的唯一方法；Python 提供了更简单且同样强大的工具来解析模式

+   文本相似性-检测两个相似字符串的性能可能很困难，但 Python 有一些易于使用的内置工具

+   文本建议-Python 寻找最相似的一个建议给用户正确的拼写

+   模板化-在生成文本时，模板化是定义规则的最简单方法

+   保留空格拆分字符串-在空格上拆分可能很容易，但当您想保留一些空格时会变得更加困难

+   清理文本-从文本中删除任何标点符号或奇怪的字符

+   文本标准化-在处理国际文本时，通常方便避免处理特殊字符和单词拼写错误

+   对齐文本-在输出文本时，正确对齐文本大大增加了可读性

# 介绍

Python 是为系统工程而生的，当与 shell 脚本和基于 shell 的软件一起工作时，经常需要创建和解析文本。这就是为什么 Python 有非常强大的工具来处理文本。

# 模式匹配

在文本中寻找模式时，正则表达式通常是解决这类问题的最常见方式。它们非常灵活和强大，尽管它们不能表达所有种类的语法，但它们通常可以处理大多数常见情况。

正则表达式的强大之处在于它们可以生成的广泛符号和表达式集。问题在于，对于不习惯正则表达式的开发人员来说，它们可能看起来就像纯噪音，即使有经验的人也经常需要花一点时间才能理解下面的表达式：

```py
"^(*d{3})*( |-)*d{3}( |-)*d{4}$"
```

这个表达式实际上试图检测电话号码。

对于大多数常见情况，开发人员需要寻找非常简单的模式：例如，文件扩展名（它是否以`.txt`结尾？），分隔文本等等。

# 如何做...

`fnmatch`模块提供了一个简化的模式匹配语言，对于大多数开发人员来说，语法非常快速和易于理解。

很少有字符具有特殊含义：

+   `*`表示任何文本

+   `?`表示任何字符

+   `[...]`表示方括号内包含的字符

+   `[!...]`表示除了方括号内包含的字符之外的所有内容

您可能会从系统 shell 中认出这个语法，所以很容易看出`*.txt`意味着*每个具有.txt 扩展名的名称*：

```py
>>> fnmatch.fnmatch('hello.txt', '*.txt')
True
>>> fnmatch.fnmatch('hello.zip', '*.txt')
False
```

# 还有更多...

实际上，`fnmatch`可以用于识别由某种常量值分隔的文本片段。

例如，如果我有一个模式，定义了变量的`类型`，`名称`和`值`，通过`:`分隔，我们可以通过`fnmatch`识别它，然后声明所描述的变量：

```py
>>> def declare(decl):
...   if not fnmatch.fnmatch(decl, '*:*:*'):
...     return False
...   t, n, v = decl.split(':', 2)
...   globals()[n] = getattr(__builtins__, t)(v)
...   return True
... 
>>> declare('int:somenum:3')
True
>>> somenum
3
>>> declare('bool:somebool:True')
True
>>> somebool
True
>>> declare('int:a')
False
```

显然，`fnmatch`在文件名方面表现出色。如果您有一个文件列表，很容易提取只匹配特定模式的文件：

```py
>>> os.listdir()
['.git', '.gitignore', '.vscode', 'algorithms.rst', 'concurrency.rst', 
 'conf.py', 'crypto.rst', 'datastructures.rst', 'datetimes.rst', 
 'devtools.rst', 'filesdirs.rst', 'gui.rst', 'index.rst', 'io.rst', 
 'make.bat', 'Makefile', 'multimedia.rst', 'networking.rst', 
 'requirements.txt', 'terminal.rst', 'text.rst', 'venv', 'web.rst']
>>> fnmatch.filter(os.listdir(), '*.git*')
['.git', '.gitignore']
```

虽然非常方便，`fnmatch`显然是有限的，但当一个工具达到其极限时，最好的事情之一就是提供与可以克服这些限制的替代工具兼容的兼容性。

例如，如果我想找到所有包含单词`git`或`vs`的文件，我不能在一个`fnmatch`模式中做到这一点。我必须声明两种不同的模式，然后将结果连接起来。但是，如果我可以使用正则表达式，那是绝对可能的。

`fnmatch.translate`在`fnmatch`模式和正则表达式之间建立桥梁，提供描述`fnmatch`模式的正则表达式，以便可以根据需要进行扩展。

例如，我们可以创建一个匹配这两种模式的正则表达式：

```py
>>> reg = '({})|({})'.format(fnmatch.translate('*.git*'), 
                             fnmatch.translate('*vs*'))
>>> reg
'(.*\.git.*\Z(?ms))|(.*vs.*\Z(?ms))'
>>> import re
>>> [s for s in os.listdir() if re.match(reg, s)]
['.git', '.gitignore', '.vscode']
```

`fnmatch`的真正优势在于它是一种足够简单和安全的语言，可以向用户公开。假设您正在编写一个电子邮件客户端，并且希望提供搜索功能，如果您有来自 Jane Smith 和 Smith Lincoln 的电子邮件，您如何让用户搜索名为 Smith 或姓为 Smith 的人？

使用`fnmatch`很容易，因为您可以将其提供给用户，让他们编写`*Smith`或`Smith*`，具体取决于他们是在寻找名为 Smith 的人还是姓氏为 Smith 的人：

```py
>>> senders = ['Jane Smith', 'Smith Lincoln']
>>> fnmatch.filter(senders, 'Smith*')
['Smith Lincoln']
>>> fnmatch.filter(senders, '*Smith')
['Jane Smith']
```

# 文本相似性

在许多情况下，当处理文本时，我们可能需要识别与其他文本相似的文本，即使这两者并不相等。这在记录链接、查找重复条目或更正打字错误时非常常见。

查找文本相似性并不是一项简单的任务。如果您尝试自己去做，您很快就会意识到它很快变得复杂和缓慢。

Python 库提供了在`difflib`模块中检测两个序列之间差异的工具。由于文本本身是一个序列（字符序列），我们可以应用提供的函数来检测字符串的相似性。

# 如何做...

执行此食谱的以下步骤：

1.  给定一个字符串，我们想要比较：

```py
>>> s = 'Today the weather is nice'
```

1.  此外，我们想将一组字符串与第一个字符串进行比较：

```py
>>> s2 = 'Today the weater is nice'
>>> s3 = 'Yesterday the weather was nice'
>>> s4 = 'Today my dog ate steak'
```

1.  我们可以使用`difflib.SequenceMatcher`来计算字符串之间的相似度（从 0 到 1）。

```py
>>> import difflib
>>> difflib.SequenceMatcher(None, s, s2, False).ratio()
0.9795918367346939
>>> difflib.SequenceMatcher(None, s, s3, False).ratio()
0.8
>>> difflib.SequenceMatcher(None, s, s4, False).ratio()
0.46808510638297873
```

因此，`SequenceMatcher`能够检测到`s`和`s2`非常相似（98%），除了`weather`中的拼写错误之外，它们实际上是完全相同的短语。然后它指出`Today the weather is nice`与`Yesterday the weather was nice`相似度为 80%，最后指出`Today the weather is nice`和`Today my dog ate steak`几乎没有共同之处。

# 还有更多...

`SequenceMatcher`提供了对一些值标记为*junk*的支持。您可能期望这意味着这些值被忽略，但实际上并非如此。

使用和不使用垃圾计算比率在大多数情况下将返回相同的值：

```py
>>> a = 'aaaaaaaaaaaaaXaaaaaaaaaa'
>>> b = 'X'
>>> difflib.SequenceMatcher(lambda c: c=='a', a, b, False).ratio()
0.08
>>> difflib.SequenceMatcher(None, a, b, False).ratio()
0.08    
```

即使我们提供了一个报告所有`a`结果为垃圾的`isjunk`函数（`SequenceMatcher`的第一个参数），`a`的结果也没有被忽略。

您可以通过使用`.get_matching_blocks()`来看到，在这两种情况下，字符串匹配的唯一部分是`X`在位置`13`和`0`处的`a`和`b`：

```py
>>> difflib.SequenceMatcher(None, a, b, False).get_matching_blocks()
[Match(a=13, b=0, size=1), Match(a=24, b=1, size=0)]
>>> difflib.SequenceMatcher(lambda c: c=='a', a, b, False).get_matching_blocks()
[Match(a=13, b=0, size=1), Match(a=24, b=1, size=0)]
```

如果您想在计算差异时忽略一些字符，您将需要在运行`SequenceMatcher`之前剥离它们，也许使用一个丢弃它们的翻译映射：

```py
>>> discardmap = str.maketrans({"a": None})
>>> difflib.SequenceMatcher(None, a.translate(discardmap), b.translate(discardmap), False).ratio()
1.0
```

# 文本建议

在我们之前的食谱中，我们看到`difflib`如何计算两个字符串之间的相似度。这意味着我们可以计算两个单词之间的相似度，并向我们的用户提供建议更正。

如果已知*正确*单词的集合（通常对于任何语言都是如此），我们可以首先检查单词是否在这个集合中，如果不在，我们可以寻找最相似的单词建议给用户正确的拼写。

# 如何做...

遵循此食谱的步骤是：

1.  首先，我们需要一组有效的单词。为了避免引入整个英语词典，我们只会抽样一些单词：

```py
dictionary = {'ability', 'able', 'about', 'above', 'accept',    
              'according', 
              'account', 'across', 'act', 'action', 'activity', 
              'actually', 
              'add', 'address', 'administration', 'admit', 'adult', 
              'affect', 
              'after', 'again', 'against', 'age', 'agency', 
              'agent', 'ago', 
              'agree', 'agreement', 'ahead', 'air', 'all', 'allow',  
              'almost', 
              'alone', 'along', 'already', 'also', 'although', 
              'always', 
              'American', 'among', 'amount', 'analysis', 'and', 
              'animal', 
              'another', 'answer', 'any', 'anyone', 'anything', 
              'appear', 
              'apply', 'approach', 'area', 'argue', 
              'arm', 'around', 'arrive', 
              'art', 'article', 'artist', 'as', 'ask', 'assume', 
              'at', 'attack', 
              'attention', 'attorney', 'audience', 'author',  
              'authority', 
              'available', 'avoid', 'away', 'baby', 'back', 'bad', 
              'bag', 
              'ball', 'bank', 'bar', 'base', 'be', 'beat', 
              'beautiful', 
              'because', 'become'}
```

1.  然后我们可以编写一个函数，对于提供的任何短语，都会在我们的字典中查找单词，如果找不到，就通过`difflib`提供最相似的候选词：

```py
import difflib

def suggest(phrase):
    changes = 0
    words = phrase.split()
    for idx, w in enumerate(words):
        if w not in dictionary:
            changes += 1
            matches = difflib.get_close_matches(w, dictionary)
            if matches:
                words[idx] = matches[0]
    return changes, ' '.join(words)
```

1.  我们的`suggest`函数将能够检测拼写错误并建议更正的短语：

```py
>>> suggest('assume ani answer')
(1, 'assume any answer')
>>> suggest('anoter agrement ahead')
(2, 'another agreement ahead')
```

第一个返回的参数是检测到的错误单词数，第二个是具有最合理更正的字符串。

1.  如果我们的短语没有错误，我们将得到原始短语的`0`：

```py
>>> suggest('beautiful art')
(0, 'beautiful art')
```

# 模板

向用户显示文本时，经常需要根据软件状态动态生成文本。

通常，这会导致这样的代码：

```py
name = 'Alessandro'
messages = ['Message 1', 'Message 2']

txt = 'Hello %s, You have %s message' % (name, len(messages))
if len(messages) > 1:
    txt += 's'
txt += ':n'
for msg in messages:
    txt += msg + 'n'
print(txt)
```

这使得很难预见消息的即将到来的结构，而且在长期内也很难维护。生成文本时，通常更方便的是反转这种方法，而不是将文本放入代码中，我们应该将代码放入文本中。这正是模板引擎所做的，虽然标准库提供了非常完整的格式化解决方案，但缺少一个开箱即用的模板引擎，但可以很容易地扩展为一个模板引擎。

# 如何做...

本教程的步骤如下：

1.  `string.Formatter`对象允许您扩展其语法，因此我们可以将其专门化以支持将代码注入到它将要接受的表达式中：

```py
import string

class TemplateFormatter(string.Formatter):
    def get_field(self, field_name, args, kwargs):
        if field_name.startswith("$"):
            code = field_name[1:]
            val = eval(code, {}, dict(kwargs))
            return val, field_name
        else:
            return super(TemplateFormatter, self).get_field(field_name, args, kwargs)
```

1.  然后，我们的`TemplateFormatter`可以用来以更简洁的方式生成类似于我们示例的文本：

```py
messages = ['Message 1', 'Message 2']

tmpl = TemplateFormatter()
txt = tmpl.format("Hello {name}, "
                  "You have {$len(messages)} message{$len(messages) and 's'}:n{$'\n'.join(messages)}", 
                  name='Alessandro', messages=messages)
print(txt)
```

结果应该是：

```py
Hello Alessandro, You have 2 messages:
Message 1
Message 2
```

# 它是如何工作的...

`string.Formatter`支持与`str.format`方法支持的相同语言。实际上，它根据 Python 称为*格式化字符串语法*的内容解析包含在`{}`中的表达式。`{}`之外的所有内容保持不变，而`{}`中的任何内容都会被解析为`field_name!conversion:format_spec`规范。因此，由于我们的`field_name`不包含`!`或`:`，它可以是任何其他内容。

然后提取的`field_name`被提供给`Formatter.get_field`，以查找`format`方法提供的参数中该字段的值。

因此，例如，采用这样的表达式：

```py
string.Formatter().format("Hello {name}", name='Alessandro')
```

这导致：

```py
Hello Alessandro
```

因为`{name}`被识别为要解析的块，所以会在`.format`参数中查找名称，并保留其余部分不变。

这非常方便，可以解决大多数字符串格式化需求，但缺乏像循环和条件语句这样的真正模板引擎的功能。

我们所做的是扩展`Formatter`，不仅解析`field_name`中指定的变量，还评估 Python 表达式。

由于我们知道所有的`field_name`解析都要经过`Formatter.get_field`，在我们自己的自定义类中覆盖该方法将允许我们更改每当评估像`{name}`这样的`field_name`时发生的情况：

```py
class TemplateFormatter(string.Formatter):
    def get_field(self, field_name, args, kwargs):
```

为了区分普通变量和表达式，我们使用了`$`符号。由于 Python 变量永远不会以`$`开头，因此我们不会与提供给格式化的参数发生冲突（因为`str.format($something=5`实际上是 Python 中的语法错误）。因此，像`{$something}`这样的`field_name`不意味着查找`''$something`的值，而是评估`something`表达式：

```py
if field_name.startswith("$"):
    code = field_name[1:]
    val = eval(code, {}, dict(kwargs))
```

`eval`函数运行在字符串中编写的任何代码，并将执行限制为表达式（Python 中的表达式总是导致一个值，与不导致值的语句不同），因此我们还进行了语法检查，以防止模板用户编写`if something: x='hi'`，这将不会提供任何值来显示在渲染模板后的文本中。

然后，由于我们希望用户能够查找到他们提供的表达式引用的任何变量（如`{$len(messages)}`），我们将`kwargs`提供给`eval`作为`locals`变量，以便任何引用变量的表达式都能正确解析。我们还提供一个空的全局上下文`{}`，以便我们不会无意中触及软件的任何全局变量。

剩下的最后一部分就是将`eval`提供的表达式执行结果作为`field_name`解析的结果返回：

```py
return val, field_name
```

真正有趣的部分是所有处理都发生在`get_field`阶段。转换和格式规范仍然受支持，因为它们是应用于`get_field`返回的值。

这使我们可以写出这样的东西：

```py
{$3/2.0:.2f}
```

我们得到的输出是`1.50`，而不是`1.5`。这是因为我们在我们专门的`TemplateFormatter.get_field`方法中首先评估了`3/2.0`，然后解析器继续应用格式规范（`.2f`）到结果值。

# 还有更多...

我们的简单模板引擎很方便，但仅限于我们可以将生成文本的代码表示为一组表达式和静态文本的情况。

问题在于更高级的模板并不总是可以表示。我们受限于简单的表达式，因此实际上任何不能用`lambda`表示的东西都不能由我们的模板引擎执行。

虽然有人会认为通过组合多个`lambda`可以编写非常复杂的软件，但大多数人会认为语句会导致更可读的代码。

因此，如果你需要处理非常复杂的文本，你应该使用功能齐全的模板引擎，并寻找像 Jinja、Kajiki 或 Mako 这样的解决方案。特别是对于生成 HTML，像 Kajiki 这样的解决方案，它还能够验证你的 HTML，非常方便，可以比我们的`TemplateFormatter`做得更多。

# 拆分字符串并保留空格

通常在按空格拆分字符串时，开发人员倾向于依赖`str.split`，它能够很好地完成这个目的。但是当需要*拆分一些空格并保留其他空格*时，事情很快变得更加困难，实现一个自定义解决方案可能需要投入时间来进行适当的转义。

# 如何做...

只需依赖`shlex.split`而不是`str.split`：

```py
>>> import shlex
>>>
>>> text = 'I was sleeping at the "Windsdale Hotel"'
>>> print(shlex.split(text))
['I', 'was', 'sleeping', 'at', 'the', 'Windsdale Hotel']
```

# 工作原理...

`shlex`是最初用于解析 Unix shell 代码的模块。因此，它支持通过引号保留短语。通常在 Unix 命令行中，由空格分隔的单词被提供为调用命令的参数，但如果你想将多个单词作为单个参数提供，可以使用引号将它们分组。

这正是`shlex`所复制的，为我们提供了一个可靠的驱动拆分的方法。我们只需要用双引号或单引号包裹我们想要保留的所有内容。

# 清理文本

在分析用户提供的文本时，我们通常只对有意义的单词感兴趣；标点、空格和连词可能很容易妨碍我们。假设你想要统计一本书中单词的频率，你不希望最后得到"world"和"world"被计为两个不同的单词。

# 如何做...

你需要执行以下步骤：

1.  提供要清理的文本：

```py
txt = """And he looked over at the alarm clock,
ticking on the chest of drawers. "God in Heaven!" he thought.
It was half past six and the hands were quietly moving forwards,
it was even later than half past, more like quarter to seven.
Had the alarm clock not rung? He could see from the bed that it
had been set for four o'clock as it should have been; it certainly must have rung.
Yes, but was it possible to quietly sleep through that furniture-rattling noise?
True, he had not slept peacefully, but probably all the more deeply because of that."""
```

1.  我们可以依赖`string.punctuation`来知道我们想要丢弃的字符，并制作一个转换表来丢弃它们全部：

```py
>>> import string
>>> trans = str.maketrans('', '', string.punctuation)
>>> txt = txt.lower().translate(trans)
```

结果将是我们文本的清理版本：

```py
"""and he looked over at the alarm clock
ticking on the chest of drawers god in heaven he thought
it was half past six and the hands were quietly moving forwards
it was even later than half past more like quarter to seven
had the alarm clock not rung he could see from the bed that it
had been set for four oclock as it should have been it certainly must have rung
yes but was it possible to quietly sleep through that furniturerattling noise
true he had not slept peacefully but probably all the more deeply because of that"""
```

# 工作原理...

这个示例的核心是使用转换表。转换表是将字符链接到其替换的映射。像`{'c': 'A'}`这样的转换表意味着任何`'c'`都必须替换为`'A'`。

`str.maketrans`是用于构建转换表的函数。第一个参数中的每个字符将映射到第二个参数中相同位置的字符。然后最后一个参数中的所有字符将映射到`None`：

```py
>>> str.maketrans('a', 'b', 'c')
{97: 98, 99: None}
```

`97`，`98`和`99`是`'a'`，`'b'`和`'c'`的 Unicode 值：

```py
>>> print(ord('a'), ord('b'), ord('c'))
97 98 99
```

然后我们的映射可以传递给`str.translate`来应用到目标字符串上。有趣的是，任何映射到`None`的字符都将被删除：

```py
>>> 'ciao'.translate(str.maketrans('a', 'b', 'c'))
'ibo'
```

在我们之前的示例中，我们将`string.punctuation`作为`str.maketrans`的第三个参数。

`string.punctuation`是一个包含最常见标点字符的字符串：

```py
>>> string.punctuation
'!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~'
```

通过这样做，我们建立了一个事务映射，将每个标点字符映射到`None`，并没有指定任何其他映射：

```py
>>> str.maketrans('', '', string.punctuation)
{64: None, 124: None, 125: None, 91: None, 92: None, 93: None,
 94: None, 95: None, 96: None, 33: None, 34: None, 35: None,
 36: None, 37: None, 38: None, 39: None, 40: None, 41: None,
 42: None, 43: None, 44: None, 45: None, 46: None, 47: None,
 123: None, 126: None, 58: None, 59: None, 60: None, 61: None,
 62: None, 63: None}
```

这样一来，一旦应用了`str.translate`，标点字符就都被丢弃了，保留了所有其他字符：

```py
>>> 'This, is. A test!'.translate(str.maketrans('', '', string.punctuation))
'This is A test'
```

# 文本规范化

在许多情况下，一个单词可以用多种方式书写。例如，写"Über"和"Uber"的用户可能意思相同。如果你正在为博客实现标记等功能，你肯定不希望最后得到两个不同的标记。

因此，在保存标签之前，您可能希望将它们标准化为普通的 ASCII 字符，以便它们最终被视为相同的标签。

# 如何做...

我们需要的是一个翻译映射，将所有带重音的字符转换为它们的普通表示：

```py
import unicodedata, sys

class unaccented_map(dict):
    def __missing__(self, key):
        ch = self.get(key)
        if ch is not None:
            return ch
        de = unicodedata.decomposition(chr(key))
        if de:
            try:
                ch = int(de.split(None, 1)[0], 16)
            except (IndexError, ValueError):
                ch = key
        else:
            ch = key
        self[key] = ch
        return ch

unaccented_map = unaccented_map()
```

然后我们可以将其应用于任何单词来进行规范化：

```py
>>> 'Über'.translate(unaccented_map) Uber >>> 'garçon'.translate(unaccented_map) garcon
```

# 它是如何工作的...

我们已经知道如何解释*清理文本*食谱中解释的那样，`str.translate`是如何工作的：每个字符都在翻译表中查找，并且用表中指定的替换进行替换。

因此，我们需要的是一个翻译表，将`"Ü"`映射到`"U"`，将`"ç"`映射到`"c"`，依此类推。

但是我们如何知道所有这些映射呢？这些字符的一个有趣特性是它们可以被认为是带有附加符号的普通字符。就像`à`可以被认为是带有重音的`a`。

Unicode 等价性知道这一点，并提供了多种写入被认为是相同字符的方法。我们真正感兴趣的是分解形式，这意味着将字符写成定义它的多个分隔符。例如，`é`将被分解为`0065`和`0301`，这是`e`和重音的代码点。

Python 提供了一种通过`unicodedata.decompostion`函数知道字符分解版本的方法：

```py
>>> import unicodedata
>>> unicodedata.decomposition('é')
'0065 0301'
```

第一个代码点是基本字符的代码点，而第二个是添加的符号。因此，要规范化我们的`è`，我们将选择第一个代码点`0065`并丢弃符号：

```py
>>> unicodedata.decomposition('é').split()[0]
'0065'
```

现在我们不能单独使用代码点，但我们想要它表示的字符。幸运的是，`chr`函数提供了一种从其代码点的整数表示中获取字符的方法。

`unicodedata.decomposition`函数提供的代码点是表示十六进制数字的字符串，因此首先我们需要将它们转换为整数：

```py
>>> int('0065', 16)
101
```

然后我们可以应用`chr`来知道实际的字符：

```py
>>> chr(101)
'e'
```

现在我们知道如何分解这些字符并获得我们想要将它们全部标准化为的基本字符，但是我们如何为它们构建一个翻译映射呢？

答案是我们不需要。事先为所有字符构建翻译映射并不是很方便，因此我们可以使用字典提供的功能，在需要时动态地为字符构建翻译。

翻译映射是字典，每当字典需要查找它不知道的键时，它可以依靠`__missing__`方法为该键生成一个值。因此，我们的`__missing__`方法必须做我们刚才做的事情，并使用`unicodedata.decomposition`来获取字符的规范化版本，每当`str.translate`尝试在我们的翻译映射中查找它时。

一旦我们计算出所请求字符的翻译，我们只需将其存储在字典本身中，这样下次再被请求时，我们就不必再计算它。

因此，我们的食谱的`unaccented_map`只是一个提供`__missing__`方法的字典，该方法依赖于`unicodedata.decompostion`来检索每个提供的字符的规范化版本。

如果它无法找到字符的非规范化版本，它将只返回原始版本一次，以免字符串被损坏。

# 对齐文本

在打印表格数据时，通常非常重要的是确保文本正确对齐到固定长度，既不长也不短于我们为表格单元保留的空间。

如果文本太短，下一列可能会开始得太早；如果太长，它可能会开始得太晚。这会导致像这样的结果：

```py
col1 | col2-1
col1-2 | col2-2
```

或者这样：

```py
col1-000001 | col2-1
col1-2 | col2-2
```

这两者都很难阅读，并且远非显示正确表格的样子。

给定固定的列宽（20 个字符），我们希望我们的文本始终具有确切的长度，以便它不会导致错位的表格。

# 如何做...

以下是此食谱的步骤：

1.  一旦将`textwrap`模块与`str`对象的特性结合起来，就可以帮助我们实现预期的结果。首先，我们需要打印的列的内容：

```py
cols = ['hello world', 
        'this is a long text, maybe longer than expected, surely long enough', 
        'one more column']
```

1.  然后我们需要修复列的大小：

```py
COLSIZE = 20
```

1.  一旦这些准备好了，我们就可以实际实现我们的缩进函数：

```py
import textwrap, itertools

def maketable(cols):
    return 'n'.join(map(' | '.join, itertools.zip_longest(*[
        [s.ljust(COLSIZE) for s in textwrap.wrap(col, COLSIZE)] for col in cols
    ], fillvalue=' '*COLSIZE)))
```

1.  然后我们可以正确地打印任何表格：

```py
>>> print(maketable(cols))
hello world          | this is a long text, | one more column     
                     | maybe longer than    |                     
                     | expected, surely     |                     
                     | long enough          |                     
```

# 它是如何工作的...

我们必须解决三个问题来实现我们的`maketable`函数：

+   长度小于 20 个字符的文本

+   将长度超过 20 个字符的文本拆分为多行

+   填充列中缺少的行

如果我们分解我们的`maketable`函数，它的第一件事就是将长度超过 20 个字符的文本拆分为多行：

```py
[textwrap.wrap(col, COLSIZE) for col in cols]
```

将其应用于每一列，我们得到了一个包含列的列表，每个列包含一列行：

```py
[['hello world'], 
 ['this is a long text,', 'maybe longer than', 'expected, surely', 'long enough'],
 ['one more column']]
```

然后我们需要确保每行长度小于 20 个字符的文本都扩展到恰好 20 个字符，以便我们的表保持形状，这是通过对每行应用`ljust`方法来实现的：

```py
[[s.ljust(COLSIZE) for s in textwrap.wrap(col, COLSIZE)] for col in cols]
```

将`ljust`与`textwrap`结合起来，就得到了我们想要的结果：包含每个 20 个字符的行的列的列表：

```py
[['hello world         '], 
 ['this is a long text,', 'maybe longer than   ', 'expected, surely    ', 'long enough         '],
 ['one more column     ']]
```

现在我们需要找到一种方法来翻转行和列，因为在打印时，由于`print`函数一次打印一行，我们需要按行打印。此外，我们需要确保每列具有相同数量的行，因为按行打印时需要打印所有行。

这两个需求都可以通过`itertools.zip_longest`函数解决，它将生成一个新列表，通过交错提供的每个列表中包含的值，直到最长的列表用尽。由于`zip_longest`会一直进行，直到最长的可迭代对象用尽，它支持一个`fillvalue`参数，该参数可用于指定用于填充较短列表的值：

```py
list(itertools.zip_longest(*[
    [s.ljust(COLSIZE) for s in textwrap.wrap(col, COLSIZE)] for col in cols
], fillvalue=' '*COLSIZE))
```

结果将是一列包含一列的行的列表，对于没有值的行，将有空列：

```py
[('hello world         ', 'this is a long text,', 'one more column     '), 
 ('                    ', 'maybe longer than   ', '                    '), 
 ('                    ', 'expected, surely    ', '                    '), 
 ('                    ', 'long enough         ', '                    ')]
```

文本的表格形式现在清晰可见。我们函数中的最后两个步骤涉及在列之间添加`|`分隔符，并通过`' | '.join`将列合并成单个字符串：

```py
map(' | '.join, itertools.zip_longest(*[
    [s.ljust(COLSIZE) for s in textwrap.wrap(col, COLSIZE)] for col in cols
], fillvalue=' '*COLSIZE))
```

这将导致一个包含所有三列文本的字符串列表：

```py
['hello world          | this is a long text, | one more column     ', 
 '                     | maybe longer than    |                     ', 
 '                     | expected, surely     |                     ', 
 '                     | long enough          |                     ']
```

最后，行可以被打印。为了返回单个字符串，我们的函数应用了最后一步，并通过应用最终的`'n'.join()`将所有行连接成一个由换行符分隔的单个字符串，从而返回一个包含整个文本的单个字符串，准备打印：

```py
'''hello world          | this is a long text, | one more column     
                        | maybe longer than    |                     
                        | expected, surely     |                     
                        | long enough          |                     '''
```


# 第三章：命令行

在本章中，我们将涵盖以下配方：

+   基本日志记录-日志记录允许您跟踪软件正在做什么，通常与其输出无关

+   记录到文件-当记录频繁时，有必要将日志存储在磁盘上

+   记录到 Syslog-如果您的系统有 Syslog 守护程序，则可能希望登录到 Syslog 而不是使用独立文件

+   解析参数-在使用命令行工具编写时，您需要为几乎任何工具解析选项

+   交互式 shell-有时选项不足，您需要一种交互式的 REPL 来驱动您的工具

+   调整终端文本大小-为了正确对齐显示的输出，我们需要知道终端窗口的大小

+   运行系统命令-如何将其他第三方命令集成到您的软件中

+   进度条-如何在文本工具中显示进度条

+   消息框-如何在文本工具中显示 OK/取消消息框

+   输入框-如何在文本工具中请求输入

# 介绍

编写新工具时，首先出现的需求之一是使其能够与周围环境进行交互-显示结果，跟踪错误并接收输入。

用户习惯于命令行工具与他们和系统交互的某些标准方式，如果从头开始遵循这个标准可能是耗时且困难的。

这就是为什么 Python 标准库提供了工具来实现能够通过 shell 和文本进行交互的软件的最常见需求。

在本章中，我们将看到如何实现某些形式的日志记录，以便我们的程序可以保留日志文件；我们将看到如何实现基于选项和交互式软件，然后我们将看到如何基于文本实现更高级的图形输出。

# 基本日志记录

控制台软件的首要要求之一是记录其所做的事情，即发生了什么以及任何警告或错误。特别是当我们谈论长期运行的软件或在后台运行的守护程序时。

遗憾的是，如果您曾经尝试使用 Python 的`logging`模块，您可能已经注意到除了错误之外，您无法获得任何输出。

这是因为默认启用级别是“警告”，因此只有警告和更严重的情况才会被跟踪。需要进行一些小的调整，使日志通常可用。

# 如何做...

对于这个配方，步骤如下：

1.  `logging`模块允许我们通过`basicConfig`方法轻松设置日志记录配置：

```py
>>> import logging, sys
>>> 
>>> logging.basicConfig(level=logging.INFO, stream=sys.stderr,
...                     format='%(asctime)s %(name)s %(levelname)s: %(message)s')
>>> log = logging.getLogger(__name__)
```

1.  现在我们的`logger`已经正确配置，我们可以尝试使用它：

```py
>>> def dosum(a, b, count=1):
...     log.info('Starting sum')
...     if a == b == 0:
...         log.warning('Will be just 0 for any count')
...     res = (a + b) * count
...     log.info('(%s + %s) * %s = %s' % (a, b, count, res))
...     print(res)
... 
>>> dosum(5, 3)
2018-02-11 22:07:59,870 __main__ INFO: Starting sum
2018-02-11 22:07:59,870 __main__ INFO: (5 + 3) * 1 = 8
8
>>> dosum(5, 3, count=2)
2018-02-11 22:07:59,870 __main__ INFO: Starting sum
2018-02-11 22:07:59,870 __main__ INFO: (5 + 3) * 2 = 16
16
>>> dosum(0, 1, count=5)
2018-02-11 22:07:59,870 __main__ INFO: Starting sum
2018-02-11 22:07:59,870 __main__ INFO: (0 + 1) * 5 = 5
5
>>> dosum(0, 0)
2018-02-11 22:08:00,621 __main__ INFO: Starting sum
2018-02-11 22:08:00,621 __main__ WARNING: Will be just 0 for any count
2018-02-11 22:08:00,621 __main__ INFO: (0 + 0) * 1 = 0
0
```

# 它是如何工作的...

`logging.basicConfig`配置`root`记录器（主记录器，如果找不到用于使用的记录器的特定配置，则 Python 将使用它）以在`INFO`级别或更高级别写入任何内容。这将允许我们显示除调试消息之外的所有内容。`format`参数指定了我们的日志消息应该如何格式化；在这种情况下，我们添加了日期和时间，记录器的名称，我们正在记录的级别以及消息本身。最后，`stream`参数告诉记录器将其输出写入标准错误。

一旦我们配置了`root`记录器，任何我们选择的日志记录，如果没有特定的配置，都将使用`root`记录器。

因此，下一行`logging.getLogger(__name__)`会获得一个与执行的 Python 模块类似命名的记录器。如果您将代码保存到文件中，则记录器的名称将类似于`dosum`（假设您的文件名为`dosum.py`）；如果没有，则记录器的名称将为`__main__`，就像前面的示例中一样。

Python 记录器在使用`logging.getLogger`检索时首次创建，并且对`getLogger`的任何后续调用只会返回已经存在的记录器。对于非常简单的程序，名称可能并不重要，但在更大的软件中，通常最好抓取多个记录器，这样您可以区分消息来自软件的哪个子系统。

# 还有更多...

也许你会想知道为什么我们配置`logging`将其输出发送到`stderr`，而不是标准输出。这样可以将我们软件的输出（通过打印语句写入`stdout`）与日志信息分开。这通常是一个好的做法，因为您的工具的用户可能需要调用您的工具的输出，而不带有日志消息生成的所有噪音，这样做可以让我们以以下方式调用我们的脚本：

```py
$ python dosum.py 2>/dev/null
8
16
5
0
```

我们只会得到结果，而不会有所有的噪音，因为我们将`stderr`重定向到`/dev/null`，这在 Unix 系统上会导致丢弃所有写入`stderr`的内容。

# 记录到文件

对于长时间运行的程序，将日志记录到屏幕并不是一个非常可行的选择。在运行代码数小时后，最旧的日志消息将丢失，即使它们仍然可用，也不容易阅读所有日志或搜索其中的内容。

将日志保存到文件允许无限长度（只要我们的磁盘允许）并且可以使用`grep`等工具进行搜索。

默认情况下，Python 日志配置为写入屏幕，但在配置日志时很容易提供一种方式来写入任何文件。

# 如何做到...

为了测试将日志记录到文件，我们将创建一个简短的工具，根据当前时间计算最多*n*个斐波那契数。如果是下午 3:01，我们只想计算 1 个数字，而如果是下午 3:59，我们想计算 59 个数字。

软件将提供计算出的数字作为输出，但我们还想记录计算到哪个数字以及何时运行：

```py
import logging, sys

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Please provide logging file name as argument')
        sys.exit(1)

    logging_file = sys.argv[1]
    logging.basicConfig(level=logging.INFO, filename=logging_file,
                        format='%(asctime)s %(name)s %(levelname)s: %(message)s')

log = logging.getLogger(__name__)

def fibo(num):
    log.info('Computing up to %sth fibonacci number', num)
    a, b = 0, 1
    for n in range(num):
        a, b = b, a+b
        print(b, '', end='')
    print(b)

if __name__ == '__main__':
    import datetime
    fibo(datetime.datetime.now().second)
```

# 工作原理...

代码分为三个部分：初始化日志记录、`fibo`函数和我们工具的`main`函数。我们明确地以这种方式划分代码，因为`fibo`函数可能会在其他模块中使用，在这种情况下，我们不希望重新配置`logging`；我们只想使用程序提供的日志配置。因此，`logging.basicConfig`调用被包装在`__name__ == '__main__'`中，以便只有在模块被直接调用为工具时才配置`logging`，而不是在被其他模块导入时。

当调用多个`logging.basicConfig`实例时，只有第一个会被考虑。如果我们在其他模块中导入时没有将日志配置包装在`if`中，它可能最终会驱动整个软件的日志配置，这取决于模块导入的顺序，这显然是我们不想要的。

与之前的方法不同，`basicConfig`是使用`filename`参数而不是`stream`参数进行配置的。这意味着将创建`logging.FileHandler`来处理日志消息，并且消息将被追加到该文件中。

代码的核心部分是`fibo`函数本身，最后一部分是检查代码是作为 Python 脚本调用还是作为模块导入。当作为模块导入时，我们只想提供`fibo`函数并避免运行它，但当作为脚本执行时，我们想计算斐波那契数。

也许你会想知道为什么我使用了两个`if __name__ == '__main__'`部分；如果将两者合并成一个，脚本将继续工作。但通常最好确保在尝试使用日志之前配置`logging`，否则结果将是我们最终会使用`logging.lastResort`处理程序，它只会写入`stderr`直到日志被配置。

# 记录到 Syslog

类 Unix 系统通常提供一种通过`syslog`协议收集日志消息的方法，这使我们能够将存储日志的系统与生成日志的系统分开。

特别是在跨多个服务器分布的应用程序的情况下，这非常方便；您肯定不想登录到 20 个不同的服务器上收集您的 Python 应用程序的所有日志，因为它在多个节点上运行。特别是对于 Web 应用程序来说，这在云服务提供商中现在非常常见，因此能够在一个地方收集所有 Python 日志非常方便。

这正是使用`syslog`允许我们做的事情；我们将看到如何将日志消息发送到运行在我们系统上的守护程序，但也可以将它们发送到任何系统。

# 准备工作

虽然这个方法不需要`syslog`守护程序才能工作，但您需要一个来检查它是否正常工作，否则消息将无法被读取。在 Linux 或 macOS 系统的情况下，这通常是开箱即用的，但在 Windows 系统的情况下，您需要安装一个 Syslog 服务器或使用云解决方案。有许多选择，只需在 Google 上快速搜索，就可以找到一些便宜甚至免费的替代方案。

# 如何做...

当使用一个定制程度很高的日志记录解决方案时，就不再能依赖于`logging.basicConfig`，因此我们将不得不手动设置日志记录环境：

```py
import logging
import logging.config

# OSX logs through /var/run/syslog this should be /dev/log 
# on Linux system or a tuple ('ADDRESS', PORT) to log to a remote server
SYSLOG_ADDRESS = '/var/run/syslog'

logging.config.dictConfig({
    'version': 1,
    'formatters': {
        'default': {
            'format': '%(asctime)s %(name)s: %(levelname)s %(message)s'
        },
    },
    'handlers': {
        'syslog': {
            'class': 'logging.handlers.SysLogHandler',
            'formatter': 'default',
            'address': SYSLOG_ADDRESS
        }
    },
    'root': {
        'handlers': ['syslog'],
        'level': 'INFO'
    }
})

log = logging.getLogger()
log.info('Hello Syslog!')
```

如果这样操作正常，您的消息应该被 Syslog 记录，并且在 macOS 上运行`syslog`命令或在 Linux 上作为`/var/log/syslog`的`tail`命令时可见：

```py
$ syslog | tail -n 2
Feb 18 17:52:43 Pulsar Google Chrome[294] <Error>: ... SOME CHROME ERROR MESSAGE ...
Feb 18 17:53:48 Pulsar 2018-02-18 17[4294967295] <Info>: 53:48,610 INFO root Hello Syslog!
```

`syslog`文件路径可能因发行版而异；如果`/var/log/syslog`不起作用，请尝试`/var/log/messages`或参考您的发行版文档。

# 还有更多...

由于我们依赖于`dictConfig`，您会注意到我们的配置比以前的方法更复杂。这是因为我们自己配置了日志基础设施的部分。

每当您配置日志记录时，都要使用记录器写入您的消息。默认情况下，系统只有一个记录器：`root`记录器（如果您调用`logging.getLogger`而不提供任何特定名称，则会得到该记录器）。

记录器本身不处理消息，因为写入或打印日志消息是处理程序的职责。因此，如果您想要读取您发送的日志消息，您需要配置一个处理程序。在我们的情况下，我们使用`SysLogHandler`，它写入到 Syslog。

处理程序负责写入消息，但实际上并不涉及消息应该如何构建/格式化。您会注意到，除了您自己的消息之外，当您记录某些内容时，还会得到日志级别、记录器名称、时间戳以及由日志系统为您添加的一些细节。将这些细节添加到消息中通常是格式化程序的工作。格式化程序获取记录器提供的所有信息，并将它们打包成应该由处理程序写入的消息。

最后但并非最不重要的是，您的日志配置可能非常复杂。您可以设置一些消息发送到本地文件，一些消息发送到 Syslog，还有一些应该打印在屏幕上。这将涉及多个处理程序，它们应该知道哪些消息应该处理，哪些消息应该忽略。允许这种知识是过滤器的工作。一旦将过滤器附加到处理程序，就可以控制哪些消息应该由该处理程序保存，哪些应该被忽略。

Python 日志系统现在可能看起来非常直观，这是因为它是一个非常强大的解决方案，可以以多种方式进行配置，但一旦您了解了可用的构建模块，就可以以非常灵活的方式将它们组合起来。

# 解析参数

当编写命令行工具时，通常会根据提供给可执行文件的选项来改变其行为。这些选项通常与可执行文件名称一起在`sys.argv`中可用，但解析它们并不像看起来那么容易，特别是当必须支持多个参数时。此外，当选项格式不正确时，通常最好提供一个使用消息，以便通知用户正确使用工具的方法。

# 如何做...

执行此食谱的以下步骤：

1.  `argparse.ArgumentParser`对象是负责解析命令行选项的主要对象：

```py
import argparse
import operator
import logging
import functools

parser = argparse.ArgumentParser(
    description='Applies an operation to one or more numbers'
)
parser.add_argument("number", 
                    help="One or more numbers to perform an operation on.",
                    nargs='+', type=int)
parser.add_argument('-o', '--operation', 
                    help="The operation to perform on numbers.",
                    choices=['add', 'sub', 'mul', 'div'], default='add')
parser.add_argument("-v", "--verbose", action="store_true",
                    help="increase output verbosity")

opts = parser.parse_args()

logging.basicConfig(level=logging.INFO if opts.verbose else logging.WARNING)
log = logging.getLogger()

operation = getattr(operator, opts.operation)
log.info('Applying %s to %s', opts.operation, opts.number)
print(functools.reduce(operation, opts.number))
```

1.  一旦我们的命令没有任何参数被调用，它将提供一个简短的使用文本：

```py
$ python /tmp/doop.py
usage: doop.py [-h] [-o {add,sub,mul,div}] [-v] number [number ...]
doop.py: error: the following arguments are required: number
```

1.  如果我们提供了`-h`选项，`argparse`将为我们生成一个完整的使用指南：

```py
$ python /tmp/doop.py -h
usage: doop.py [-h] [-o {add,sub,mul,div}] [-v] number [number ...]

Applies an operation to one or more numbers

positional arguments:
number                One or more numbers to perform an operation on.

optional arguments:
-h, --help            show this help message and exit
-o {add,sub,mul,div}, --operation {add,sub,mul,div}
                        The operation to perform on numbers.
-v, --verbose         increase output verbosity
```

1.  使用该命令将会得到预期的结果：

```py
$ python /tmp/dosum.py 1 2 3 4 -o mul
24
```

# 工作原理...

我们使用了`ArgumentParser.add_argument`方法来填充可用选项的列表。对于每个参数，还可以提供一个`help`选项，它将为该参数声明`help`字符串。

位置参数只需提供参数的名称：

```py
parser.add_argument("number", 
                    help="One or more numbers to perform an operation on.",
                    nargs='+', type=int)
```

`nargs`选项告诉`ArgumentParser`我们期望该参数被指定的次数，`+`值表示至少一次或多次。然后`type=int`告诉我们参数应该被转换为整数。

一旦我们有了要应用操作的数字，我们需要知道操作本身：

```py
parser.add_argument('-o', '--operation', 
                    help="The operation to perform on numbers.",
                    choices=['add', 'sub', 'mul', 'div'], default='add')
```

在这种情况下，我们指定了一个选项（以破折号`-`开头），可以提供`-o`或`--operation`。我们声明唯一可能的值是`'add'`、`'sub'`、`'mul'`或`'div'`（提供不同的值将导致`argparse`抱怨），如果用户没有指定默认值，则为`add`。

作为最佳实践，我们的命令只打印结果；能够询问一些关于它将要做什么的日志是很方便的。因此，我们提供了`verbose`选项，它驱动了我们为命令启用的日志级别：

```py
parser.add_argument("-v", "--verbose", action="store_true",
                    help="increase output verbosity")
```

如果提供了该选项，我们将只存储`verbose`模式已启用（`action="store_true"`使得`True`被存储在`opts.verbose`中），并且我们将相应地配置`logging`模块，这样我们的`log.info`只有在`verbose`被启用时才可见。

最后，我们可以实际解析命令行选项并将结果返回到`opts`对象中：

```py
opts = parser.parse_args()
```

一旦我们有了可用的选项，我们配置日志，以便我们可以读取`verbose`选项并相应地配置它：

```py
logging.basicConfig(level=logging.INFO if opts.verbose else logging.WARNING)
```

一旦选项被解析并且`logging`被配置，剩下的就是在提供的数字集上执行预期的操作并打印结果：

```py
operation = getattr(operator, opts.operation)
log.info('Applying %s to %s', opts.operation, opts.number)
print(functools.reduce(operation, opts.number))
```

# 还有更多...

如果你将命令行选项与第一章*容器和数据结构*中的*带回退的字典*食谱相结合，你可以扩展工具的行为，不仅可以从命令行读取选项，还可以从环境变量中读取，当你无法完全控制命令的调用方式但可以设置环境变量时，这通常非常方便。

# 交互式 shell

有时，编写命令行工具是不够的，你需要能够提供某种交互。假设你想要编写一个邮件客户端。在这种情况下，必须要调用`mymail list`来查看你的邮件，或者从你的 shell 中读取特定的邮件，等等，这是不太方便的。此外，如果你想要实现有状态的行为，比如一个`mymail reply`实例，它应该回复你正在查看的当前邮件，这甚至可能是不可能的。

在这些情况下，交互式程序更好，Python 标准库通过`cmd`模块提供了编写这样一个程序所需的所有工具。

我们可以尝试为我们的`mymail`程序编写一个交互式 shell；它不会读取真实的电子邮件，但我们将伪造足够的行为来展示一个功能齐全的 shell。

# 如何做...

此示例的步骤如下：

1.  `cmd.Cmd`类允许我们启动交互式 shell 并基于它们实现命令：

```py
EMAILS = [
    {'sender': 'author1@domain.com', 'subject': 'First email', 
     'body': 'This is my first email'},
    {'sender': 'author2@domain.com', 'subject': 'Second email', 
     'body': 'This is my second email'},
]

import cmd
import shlex

class MyMail(cmd.Cmd):
    intro = 'Simple interactive email client.'
    prompt = 'mymail> '

    def __init__(self, *args, **kwargs):
        super(MyMail, self).__init__(*args, **kwargs)
        self.selected_email = None

    def do_list(self, line):
        """list

        List emails currently in the Inbox"""
        for idx, email in enumerate(EMAILS):
            print('[{idx}] From: {e[sender]} - 
                    {e[subject]}'.format(
                    idx=idx, e=email
            ))

    def do_read(self, emailnum):
        """read [emailnum]

        Reads emailnum nth email from those listed in the Inbox"""
        try:
            idx = int(emailnum.strip())
        except:
            print('Invalid email index {}'.format(emailnum))
            return

        try:
            email = EMAILS[idx]
        except IndexError:
            print('Email {} not found'.format(idx))
            return

        print('From: {e[sender]}\n'
              'Subject: {e[subject]}\n'
              '\n{e[body]}'.format(e=email))
        # Track the last read email as the selected one for reply.
        self.selected_email = idx

    def do_reply(self, message):
        """reply [message]

        Sends back an email to the author of the received email"""
        if self.selected_email is None:
            print('No email selected for reply.')
            return

        email = EMAILS[self.selected_email]
        print('Replied to {e[sender]} with: {message}'.format(
            e=email, message=message
        ))

    def do_send(self, arguments):
        """send [recipient] [subject] [message]

        Send a new email with [subject] to [recipient]"""
        # Split the arguments with shlex 
        # so that we allow subject or message with spaces. 
        args = shlex.split(arguments)
        if len(args) < 3:
            print('A recipient, a subject and a message are 
                  required.')
            return

        recipient, subject, message = args[:3]
        if len(args) >= 4:
            message += ' '.join(args[3:])

        print('Sending email {} to {}: "{}"'.format(
            subject, recipient, message
        ))

    def complete_send(self, text, line, begidx, endidx):
        # Provide autocompletion of recipients for send command.
        return [e['sender'] for e in EMAILS if e['sender'].startswith(text)]

    def do_EOF(self, line):
        return True

if __name__ == '__main__':
    MyMail().cmdloop()
```

1.  启动我们的脚本应该提供一个很好的交互提示：

```py
$ python /tmp/mymail.py 
Simple interactive email client.
mymail> help

Documented commands (type help <topic>):
========================================
help  list  read  reply  send

Undocumented commands:
======================
EOF
```

1.  如文档所述，我们应该能够读取邮件列表，阅读特定的邮件，并回复当前打开的邮件：

```py
mymail> list
[0] From: author1@domain.com - First email
[1] From: author2@domain.com - Second email
mymail> read 0
From: author1@domain.com
Subject: First email

This is my first email
mymail> reply Thanks for your message!
Replied to author1@domain.com with: Thanks for your message!
```

1.  然后，我们可以依赖更高级的发送命令，这些命令还为我们的新邮件提供了收件人的自动完成：

```py
mymail> help send
send [recipient] [subject] [message]

Send a new email with [subject] to [recipient]
mymail> send author
author1@domain.com  author2@domain.com  
mymail> send author2@domain.com "Saw your email" "I saw your message, thanks for sending it!"
Sending email Saw your email to author2@domain.com: "I saw your message, thanks for sending it!"
mymail> 
```

# 工作原理...

`cmd.Cmd`循环通过`prompt`类属性打印我们提供的`prompt`并等待命令。在`prompt`之后写的任何东西都会被分割，然后第一部分会被查找我们自己的子类提供的方法列表。

每当提供一个命令时，`cmd.Cmd.cmdloop`调用相关的方法，然后重新开始。

任何以`do_*`开头的方法都是一个命令，`do_`之后的部分是命令名称。如果在交互提示中使用`help`命令，则实现命令的方法的 docstring 将被报告在我们工具的文档中。

`Cmd`类不提供解析命令参数的功能，因此，如果您的命令有多个参数，您必须自己拆分它们。在我们的情况下，我们依赖于`shlex`，以便用户可以控制参数的拆分方式。这使我们能够解析主题和消息，同时提供了一种包含空格的方法。否则，我们将无法知道主题在哪里结束，消息从哪里开始。

`send`命令还支持自动完成收件人，通过`complete_send`方法。如果提供了`complete_*`方法，当按下*Tab*自动完成命令参数时，`Cmd`会调用它。该方法接收需要完成的文本以及有关整行文本和光标当前位置的一些详细信息。由于没有对参数进行解析，光标的位置和整行文本可以帮助提供不同的自动完成行为。在我们的情况下，我们只能自动完成收件人，因此无需区分各个参数。

最后但并非最不重要的是，`do_EOF`命令允许在按下*Ctrl* + *D*时退出命令行。否则，我们将无法退出交互式 shell。这是`Cmd`提供的一个约定，如果`do_EOF`命令返回`True`，则表示 shell 可以退出。

# 调整终端文本大小

我们在第二章的*文本管理*中看到了*对齐文本*的示例，其中展示了在固定空间内对齐文本的可能解决方案。可用空间的大小在`COLSIZE`常量中定义，选择适合大多数终端的三列（大多数终端适合 80 列）。

但是，如果用户的终端窗口小于 60 列会发生什么？我们的对齐会被严重破坏。此外，在非常大的窗口上，虽然文本不会被破坏，但与窗口相比会显得太小。

因此，每当显示应保持正确对齐属性的文本时，通常最好考虑用户终端窗口的大小。

# 如何做...

步骤如下：

1.  `shutil.get_terminal_size`函数可以指导终端窗口的大小，并为无法获得大小的情况提供后备。我们将调整`maketable`函数，以适应终端大小。

```py
import shutil
import textwrap, itertools

def maketable(cols):
    term_size = shutil.get_terminal_size(fallback=(80, 24))
    colsize = (term_size.columns // len(cols)) - 3
    if colsize < 1:
        raise ValueError('Column too small')
    return '\n'.join(map(' | '.join, itertools.zip_longest(*[
        [s.ljust(colsize) for s in textwrap.wrap(col, colsize)] for col in cols
    ], fillvalue=' '*colsize)))
```

1.  现在可以在多列中打印任何文本，并看到它适应您的终端窗口的大小：

```py
COLUMNS = 5
TEXT = ['Lorem ipsum dolor sit amet, consectetuer adipiscing elit. '
        'Aenean commodo ligula eget dolor. Aenean massa. '
        'Cum sociis natoque penatibus et magnis dis parturient montes, '
        'nascetur ridiculus mus'] * COLUMNS

print(maketable(TEXT))
```

如果尝试调整终端窗口大小并重新运行脚本，您会注意到文本现在总是以不同的方式对齐，以确保它适合可用的空间。

# 工作原理...

我们的`maketable`函数现在通过获取终端宽度(`term_size.columns`)并将其除以要显示的列数来计算列的大小，而不是依赖于列的大小的常量。

始终减去三个字符，因为我们要考虑`|`分隔符占用的空间。

终端的大小(`term_size`)通过`shutil.get_terminal_size`获取，它将查看`stdout`以检查连接终端的大小。

如果无法检索大小或连接的输出不是终端，则使用回退值。您可以通过将脚本的输出重定向到文件来检查回退值是否按预期工作：

```py
$ python myscript.py > output.txt
```

如果您打开`output.txt`，您应该会看到 80 个字符的回退值被用作文件没有指定宽度。

# 运行系统命令

在某些情况下，特别是在编写系统工具时，可能有一些工作需要转移到另一个命令。例如，如果你需要解压文件，在许多情况下，将工作转移到`gunzip`/`zip`命令可能更合理，而不是尝试在 Python 中复制相同的行为。

在 Python 中有许多处理这项工作的方法，它们都有微妙的差异，可能会让任何开发人员的生活变得困难，因此最好有一个通常有效的解决方案来解决最常见的问题。

# 如何做...

执行以下步骤：

1.  结合`subprocess`和`shlex`模块使我们能够构建一个在大多数情况下都可靠的解决方案：

```py
import shlex
import subprocess

def run(command):
    try:
        result = subprocess.check_output(shlex.split(command), 
                                         stderr=subprocess.STDOUT)
        return 0, result
    except subprocess.CalledProcessError as e:
        return e.returncode, e.output
```

1.  很容易检查它是否按预期工作，无论是成功还是失败的命令：

```py
for path in ('/', '/should_not_exist'):
    status, out = run('ls "{}"'.format(path))
    if status == 0:
        print('<Success>')
    else:
        print('<Error: {}>'.format(status))
    print(out)
```

1.  在我的系统上，这样可以正确列出文件系统的根目录，并对不存在的路径进行抱怨：

```py
<Success>
Applications
Developer
Library
LibraryPreferences
Network
...

<Error: 2>
ls: cannot access /should_not_exist: No such file or directory
```

# 工作原理...

调用命令本身是由`subprocess.check_output`函数执行的，但在调用之前，我们需要正确地将命令拆分为包含命令本身及其参数的列表。依赖于`shlex`使我们能够驱动和区分参数应如何拆分。要查看其效果，可以尝试在任何类 Unix 系统上比较`run('ls / var')`和`run('ls "/ var"')`。第一个将打印很多文件，而第二个将抱怨路径不存在。这是因为在第一种情况下，我们实际上向`ls`发送了两个不同的参数（`/`和`var`），而在第二种情况下，我们发送了一个单一的参数（`"/ var"`）。如果我们没有使用`shlex`，就无法区分这两种情况。

传递`stderr=subprocess.STDOUT`选项，然后处理命令失败的情况（我们可以检测到，因为`run`函数将返回一个非零的状态），允许我们接收失败的描述。

调用我们的命令的繁重工作由`subprocess.check_output`执行，实际上，它是`subprocess.Popen`的包装器，将执行两件事：

1.  使用`subprocess.Popen`生成所需的命令，配置为将输出写入管道，以便父进程（我们自己的程序）可以从该管道中读取并获取输出。

1.  生成线程以持续从打开的管道中消耗内容，以与子进程通信。这确保它们永远不会填满，因为如果它们填满了，我们调用的命令将会被阻塞，因为它将无法再写入任何输出。

# 还有更多...

需要注意的一点是，我们的`run`函数将寻找一个可满足请求命令的可执行文件，但不会运行任何 shell 表达式。因此，无法将 shell 脚本发送给它。如果需要，可以将`shell=True`选项传递给`subprocess.check_output`，但这是极不鼓励的，因为它允许将 shell 代码注入到我们的程序中。

假设您想编写一个命令，打印用户选择的目录的内容；一个非常简单的解决方案可能是以下内容：

```py
import sys
if len(sys.argv) < 2:
    print('Please provide a directory')
    sys.exit(1)
_, out = run('ls {}'.format(sys.argv[1]))
print(out)
```

现在，如果我们在`run`中允许`shell=True`，并且用户提供了诸如`/var; rm -rf /`这样的路径，会发生什么？用户可能最终会删除整个系统磁盘，尽管我们仍然依赖于`shlex`来分割参数，但通过 shell 运行命令仍然不安全。

# 进度条

当进行需要大量时间的工作时（通常是需要 I/O 到较慢的端点，如磁盘或网络的任何工作），让用户知道您正在前进以及还有多少工作要做是一个好主意。进度条虽然不精确，但是是给我们的用户一个关于我们已经完成了多少工作以及还有多少工作要做的概览的很好的方法。

# 如何做...

配方步骤如下：

1.  进度条本身将由装饰器显示，这样我们就可以将其应用到任何我们想要以最小的努力报告进度的函数上。

```py
import shutil, sys

def withprogressbar(func):
    """Decorates ``func`` to display a progress bar while running.

    The decorated function can yield values from 0 to 100 to
    display the progress.
    """
    def _func_with_progress(*args, **kwargs):
        max_width, _ = shutil.get_terminal_size()

        gen = func(*args, **kwargs)
        while True:
            try:
                progress = next(gen)
            except StopIteration as exc:
                sys.stdout.write('\n')
                return exc.value
            else:
                # Build the displayed message so we can compute
                # how much space is left for the progress bar 
                  itself.
                message = '[%s] {}%%'.format(progress)
                # Add 3 characters to cope for the %s and %%
                bar_width = max_width - len(message) + 3  

                filled = int(round(bar_width / 100.0 * progress))
                spaceleft = bar_width - filled
                bar = '=' * filled + ' ' * spaceleft
                sys.stdout.write((message+'\r') % bar)
                sys.stdout.flush()

    return _func_with_progress
```

1.  然后我们需要一个实际执行某些操作并且可能想要报告进度的函数。在这个例子中，它将是一个简单的等待指定时间的函数。

```py
import time

@withprogressbar
def wait(seconds):
    """Waits ``seconds`` seconds and returns how long it waited."""
    start = time.time()
    step = seconds / 100.0
    for i in range(1, 101):
        time.sleep(step)
        yield i  # Send % of progress to withprogressbar

    # Return how much time passed since we started, 
    # which is in fact how long we waited for real.
    return time.time() - start
```

1.  现在调用被装饰的函数应该告诉我们它等待了多长时间，并在等待时显示一个进度条。

```py
print('WAITED', wait(5))
```

1.  当脚本运行时，您应该看到您的进度条和最终结果，看起来像这样：

```py
$ python /tmp/progress.py 
[=====================================] 100%
WAITED 5.308781862258911
```

# 工作原理...

所有的工作都由`withprogressbar`函数完成。它充当装饰器，因此我们可以使用`@withprogressbar`语法将其应用到任何函数上。

这非常方便，因为报告进度的代码与实际执行工作的代码是隔离的，这使我们能够在许多不同的情况下重用它。

为了创建一个装饰器，它在函数本身运行时与被装饰的函数交互，我们依赖于 Python 生成器。

```py
gen = func(*args, **kwargs)
while True:
    try:
        progress = next(gen)
    except StopIteration as exc:
        sys.stdout.write('\n')
        return exc.value
    else:
        # display the progressbar
```

当我们调用被装饰的函数（在我们的例子中是`wait`函数）时，实际上我们将调用装饰器中的`_func_with_progress`。该函数将要做的第一件事就是调用被装饰的函数。

```py
gen = func(*args, **kwargs)
```

由于被装饰的函数包含一个`yield progress`语句，每当它想显示一些进度（在`wait`中的`for`循环中的`yield i`），函数将返回`generator`。

每当生成器遇到`yield progress`语句时，我们将其作为应用于生成器的下一个函数的返回值收到。

```py
progress = next(gen)
```

然后我们可以显示我们的进度并再次调用`next(gen)`，这样被装饰的函数就可以继续前进并返回新的进度（被装饰的函数当前在`yield`处暂停，直到我们在其上调用`next`，这就是为什么我们的整个代码都包裹在`while True:`中的原因，让函数永远继续，直到它完成它要做的工作）。

当被装饰的函数完成了所有它要做的工作时，它将引发一个`StopIteration`异常，该异常将包含被装饰函数在`.value`属性中返回的值。

由于我们希望将任何返回值传播给调用者，我们只需自己返回该值。如果被装饰的函数应该返回其完成的工作的某些结果，比如一个`download(url)`函数应该返回对下载文件的引用，这一点尤为重要。

在返回之前，我们打印一个新行。

```py
sys.stdout.write('\n')
```

这确保了进度条后面的任何内容不会与进度条本身重叠，而是会打印在新的一行上。

然后我们只需显示进度条本身。配方中进度条部分的核心基于只有两行代码：

```py
sys.stdout.write((message+'\r') % bar)
sys.stdout.flush()
```

这两行将确保我们的消息在屏幕上打印，而不像`print`通常做的那样换行。相反，这将回到同一行的开头。尝试用`'\n'`替换`'\r'`，你会立即看到区别。使用`'\r'`，你会看到一个进度条从 0 到 100%移动，而使用`'\n'`，你会看到许多进度条被打印。

然后需要调用`sys.stdout.flush()`来确保进度条实际上被显示出来，因为通常只有在新的一行上才会刷新输出，而我们只是一遍又一遍地打印同一行，除非我们明确地刷新它，否则它不会被刷新。

现在我们知道如何绘制进度条并更新它，函数的其余部分涉及计算要显示的进度条：

```py
message = '[%s] {}%%'.format(progress)
bar_width = max_width - len(message) + 3  # Add 3 characters to cope for the %s and %%

filled = int(round(bar_width / 100.0 * progress))
spaceleft = bar_width - filled
bar = '=' * filled + ' ' * spaceleft
```

首先，我们计算`message`，这是我们想要显示在屏幕上的内容。消息是在没有进度条本身的情况下计算的，对于进度条，我们留下了一个`%s`占位符，以便稍后填充它。

我们这样做是为了知道在我们显示周围的括号和百分比后，进度条本身还有多少空间。这个值是`bar_width`，它是通过从屏幕宽度的最大值（在我们的函数开始时使用`shutil.get_terminal_size()`检索）中减去我们的消息的大小来计算的。我们必须添加的三个额外字符将解决在我们的消息中`%s`和`%%`消耗的空间，一旦消息显示到屏幕上，`%s`将被进度条本身替换，`%%`将解析为一个单独的`%`。

一旦我们知道了进度条本身有多少空间可用，我们就计算出应该用`'='`（已完成的部分）填充多少空间，以及应该用空格`' '`（尚未完成的部分）填充多少空间。这是通过计算要填充和匹配我们的进度的百分比的屏幕大小来实现的：

```py
filled = int(round(bar_width / 100.0 * progress))
```

一旦我们知道要用`'='`填充多少，剩下的就只是空格：

```py
spaceleft = bar_width - filled
```

因此，我们可以用填充的等号和`spaceleft`空格来构建我们的进度条：

```py
bar = '=' * filled + ' ' * spaceleft
```

一旦进度条准备好了，它将通过`%`字符串格式化操作符注入到在屏幕上显示的消息中：

```py
sys.stdout.write((message+'\r') % bar)
```

如果你注意到了，我混合了两种字符串格式化（`str.format`和`%`）。我这样做是因为我认为这样做可以更清楚地说明格式化的过程，而不是在每个格式化步骤上都要正确地进行转义。

# 消息框

尽管现在不太常见，但能够创建交互式基于字符的用户界面仍然具有很大的价值，特别是当只需要一个带有“确定”按钮的简单消息对话框或一个带有“确定/取消”对话框时；通过一个漂亮的文本对话框，可以更好地引导用户的注意力。

# 准备工作

`curses`库只包括在 Unix 系统的 Python 中，因此 Windows 用户可能需要一个解决方案，比如 CygWin 或 Linux 子系统，以便能够拥有包括`curses`支持的 Python 设置。

# 如何做到这一点...

对于这个配方，执行以下步骤：

1.  我们将制作一个`MessageBox.show`方法，我们可以在需要时用它来显示消息框。`MessageBox`类将能够显示只有确定或确定/取消按钮的消息框。

```py
import curses
import textwrap
import itertools

class MessageBox(object):
    @classmethod
    def show(cls, message, cancel=False, width=40):
        """Show a message with an Ok/Cancel dialog.

        Provide ``cancel=True`` argument to show a cancel button 
        too.
        Returns the user selected choice:

            - 0 = Ok
            - 1 = Cancel
        """
        dialog = MessageBox(message, width, cancel)
        return curses.wrapper(dialog._show)

    def __init__(self, message, width, cancel):
        self._message = self._build_message(width, message)
        self._width = width
        self._height = max(self._message.count('\n')+1, 3) + 6
        self._selected = 0
        self._buttons = ['Ok']
        if cancel:
            self._buttons.append('Cancel')

    def _build_message(self, width, message):
        lines = []
        for line in message.split('\n'):
            if line.strip():
                lines.extend(textwrap.wrap(line, width-4,                                             
                             replace_whitespace=False))
            else:
                lines.append('')
        return '\n'.join(lines)

    def _show(self, stdscr):
        win = curses.newwin(self._height, self._width, 
                            (curses.LINES - self._height) // 2, 
                            (curses.COLS - self._width) // 2)
        win.keypad(1)
        win.border()
        textbox = win.derwin(self._height - 1, self._width - 3, 
                             1, 2)
        textbox.addstr(0, 0, self._message)
        return self._loop(win)

    def _loop(self, win):
        while True:
            for idx, btntext in enumerate(self._buttons):
                allowedspace = self._width // len(self._buttons)
                btn = win.derwin(
                    3, 10, 
                    self._height - 4, 
                    (((allowedspace-10)//2*idx) + allowedspace*idx 
                       + 2)
                )
                btn.border()
                flag = 0
                if idx == self._selected:
                    flag = curses.A_BOLD
                btn.addstr(1, (10-len(btntext))//2, btntext, flag)
            win.refresh()

            key = win.getch()
            if key == curses.KEY_RIGHT:
                self._selected = 1
            elif key == curses.KEY_LEFT:
                self._selected = 0
            elif key == ord('\n'):
                return self._selected
```

1.  然后我们可以通过`MessageBox.show`方法来使用它：

```py
MessageBox.show('Hello World,\n\npress enter to continue')
```

1.  我们甚至可以用它来检查用户的选择：

```py
if MessageBox.show('Are you sure?\n\npress enter to confirm',
                   cancel=True) == 0:
    print("Yeah! Let's continue")
else:
    print("That's sad, hope to see you soon")
```

# 它是如何工作的...

消息框基于`curses`库，它允许我们在屏幕上绘制基于文本的图形。当我们使用对话框时，我们将进入全屏文本图形模式，一旦退出，我们将恢复先前的终端状态。

这使我们能够在更复杂的程序中交错使用`MessageBox`类，而不必用`curses`编写整个程序。这是由`curses.wrapper`函数允许的，该函数在`MessageBox.show`类方法中用于包装实际显示框的`MessageBox._show`方法。

消息显示是在`MessageBox`初始化程序中准备的，通过`MessageBox._build_message`方法，以确保当消息太长时自动换行，并正确处理多行文本。消息框的高度取决于消息的长度和结果行数，再加上我们始终包括的六行，用于添加边框（占用两行）和按钮（占用四行）。

然后，`MessageBox._show`方法创建实际的框窗口，为其添加边框，并在其中显示消息。消息显示后，我们进入`MessageBox._loop`，等待用户在 OK 和取消之间做出选择。

`MessageBox._loop`方法通过`win.derwin`函数绘制所有必需的按钮及其边框。每个按钮宽 10 个字符，高 3 个字符，并根据`allowedspace`的值显示自身，该值为每个按钮保留了相等的框空间。然后，一旦绘制了按钮框，它将检查当前显示的按钮是否为所选按钮；如果是，则使用粗体文本显示按钮的标签。这使用户可以知道当前选择的选项。

绘制了两个按钮后，我们调用`win.refresh()`来实际在屏幕上显示我们刚刚绘制的内容。

然后我们等待用户按任意键以相应地更新屏幕；左/右箭头键将在 OK/取消选项之间切换，*Enter*将确认当前选择。

如果用户更改了所选按钮（通过按左或右键），我们将再次循环并重新绘制按钮。我们只需要重新绘制按钮，因为屏幕的其余部分没有改变；窗口边框和消息仍然是相同的，因此无需覆盖它们。屏幕的内容始终保留，除非调用了`win.erase()`方法，因此我们永远不需要重新绘制不需要更新的屏幕部分。

通过这种方式，我们还可以避免重新绘制按钮本身。这是因为只有取消/确定文本在从粗体到普通体和反之时需要重新绘制。

用户按下*Enter*键后，我们退出循环，并返回当前选择的 OK 和取消之间的选择。这允许调用者根据用户的选择采取行动。

# 输入框

在编写基于控制台的软件时，有时需要要求用户提供无法通过命令选项轻松提供的长文本输入。

在 Unix 世界中有一些这样的例子，比如编辑`crontab`或一次调整多个配置选项。其中大多数依赖于启动一个完整的第三方编辑器，比如**nano**或**vim**，但是可以很容易地使用 Python 标准库滚动一个解决方案，这在许多情况下将足够满足我们的工具需要长或复杂的用户输入。

# 准备就绪

`curses`库仅包含在 Unix 系统的 Python 中，因此 Windows 用户可能需要一个解决方案，例如 CygWin 或 Linux 子系统，以便能够拥有包括`curses`支持的 Python 设置。

# 如何做...

对于这个示例，执行以下步骤：

1.  Python 标准库提供了一个`curses.textpad`模块，其中包含一个带有`emacs`的多行文本编辑器的基础，例如键绑定。我们只需要稍微扩展它以添加一些所需的行为和修复：

```py
import curses
from curses.textpad import Textbox, rectangle

class TextInput(object):
    @classmethod
    def show(cls, message, content=None):
        return curses.wrapper(cls(message, content)._show)

    def __init__(self, message, content):
        self._message = message
        self._content = content

    def _show(self, stdscr):
        # Set a reasonable size for our input box.
        lines, cols = curses.LINES - 10, curses.COLS - 40

        y_begin, x_begin = (curses.LINES - lines) // 2, 
                           (curses.COLS - cols) // 2
        editwin = curses.newwin(lines, cols, y_begin, x_begin)
        editwin.addstr(0, 1, "{}: (hit Ctrl-G to submit)"
         .format(self._message))
        rectangle(editwin, 1, 0, lines-2, cols-1)
        editwin.refresh()

        inputwin = curses.newwin(lines-4, cols-2, y_begin+2, 
        x_begin+1)
        box = Textbox(inputwin)
        self._load(box, self._content)
        return self._edit(box)

    def _load(self, box, text):
        if not text:
            return
        for c in text:
            box._insert_printable_char(c)

    def _edit(self, box):
        while True:
            ch = box.win.getch()
            if not ch:
                continue
            if ch == 127:
                ch = curses.KEY_BACKSPACE
            if not box.do_command(ch):
                break
            box.win.refresh()
        return box.gather()
```

1.  然后我们可以从用户那里读取输入：

```py
result = TextInput.show('Insert your name:')
print('Your name:', result)
```

1.  我们甚至可以要求它编辑现有文本：

```py
result = TextInput.show('Insert your name:', 
                        content='Some Text\nTo be edited')
print('Your name:', result)
```

# 工作原理...

一切都始于`TextInput._show`方法，该方法准备了两个窗口；第一个绘制帮助文本（在我们的示例中为'插入您的姓名：'），以及文本区域的边框框。

一旦绘制完成，它会创建一个专门用于`Textbox`的新窗口，因为文本框将自由地插入、删除和编辑该窗口的内容。

如果我们有现有的内容（`content=参数`），`TextInput._load`函数会负责在继续编辑之前将其插入到文本框中。提供的内容中的每个字符都通过`Textbox._insert_printable_char`函数注入到文本框窗口中。

然后我们最终可以进入编辑循环（`TextInput._edit`方法），在那里我们监听按键并做出相应反应。实际上，`Textbox.do_command`已经为我们完成了大部分工作，因此我们只需要将按下的键转发给它，以将字符插入到我们的文本中或对特殊命令做出反应。这个方法的特殊部分是我们检查字符 127，它是*Backspace*，并将其替换为`curses.KEY_BACKSPACE`，因为并非所有终端在按下*Backspace*键时发送相同的代码。一旦字符被`do_command`处理，我们就可以刷新窗口，以便任何新文本出现并再次循环。

当用户按下*Ctrl* + *G*时，编辑器将认为文本已完成并退出编辑循环。在这之前，我们调用`Textbox.gather`来获取文本编辑器的全部内容并将其发送回调用者。

需要注意的是，内容实际上是从`curses`窗口的内容中获取的。因此，它实际上包括您屏幕上看到的所有空白空间。因此，`Textbox.gather`方法将剥离空白空间，以避免将大部分空白空间包围您的文本发送回给您。如果您尝试编写包含多个空行的内容，这一点就非常明显；它们将与其余空白空间一起被剥离。
