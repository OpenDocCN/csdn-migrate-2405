# Python 学徒（一）

> 原文：[`zh.annas-archive.org/md5/4702C628AD6B03CA92F1B4B8E471BB27`](https://zh.annas-archive.org/md5/4702C628AD6B03CA92F1B4B8E471BB27)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

## 前言

这本书是通过迂回的方式产生的。2013 年，当我们成立了位于挪威的软件咨询和培训公司 *Sixty North* 时，我们受到了在线视频培训材料出版商 *Pluralsight* 的追捧，他们希望我们为迅速增长的大规模在线开放课程（MOOC）市场制作 Python 培训视频。当时，我们没有制作视频培训材料的经验，但我们确定希望仔细构建我们的 Python 入门内容，以尊重某些限制。例如，我们希望最少使用前向引用，因为这对我们的观众来说非常不方便。我们都是言辞之人，遵循图灵奖得主莱斯利·兰波特的格言 *“如果你在不写作的情况下思考，你只是以为自己在思考”*，因此，我们首先通过撰写脚本来攻击视频课程制作。

很快，我们的在线视频课程被 *Pluralsight* 以 [Python 基础知识](https://www.pluralsight.com/courses/python-fundamentals) 的形式写成、录制并发布，受到了极其积极的反响，这种反响已经持续了几年。从最早的日子起，我们就想到这个脚本可以成为一本书的基础，尽管可以说我们低估了将内容从一个好的脚本转化为一本更好的书所需的努力。

*Python 学徒* 就是这种转变的结果。它可以作为独立的 Python 教程，也可以作为我们视频课程的配套教材，具体取决于哪种学习方式更适合您。*Python 学徒* 是三本书中的第一本，另外两本分别是 [*Python 熟练者*](https://leanpub.com/python-journeyman) 和 [*Python 大师*](https://leanpub.com/python-master)。后两本书对应于我们随后的 *Pluralsight* 课程 [*Python - 进阶*](https://app.pluralsight.com/library/courses/python-beyond-basics/) 和 [*高级 Python*](https://app.pluralsight.com/library/courses/advanced-python/)。

### 勘误和建议

本书中的所有材料都经过了彻底的审查和测试；然而，不可避免地会出现一些错误。如果您发现了错误，我们会非常感激您通过 *Leanpub* [Python 学徒讨论](https://leanpub.com/python-apprentice/feedback) 页面让我们知道，这样我们就可以进行修正并部署新版本。

### 本书中使用的约定

本书中的代码示例显示为带有语法高亮的固定宽度文本：

```py
>>> def square(x):
...     return x * x
...

```

我们的一些示例显示了保存在文件中的代码，而其他一些示例（如上面的示例）来自交互式 Python 会话。在这种交互式情况下，我们包括 Python 会话中的提示符，如三角形箭头（`>>>`）和三个点（`...`）提示符。您不需要输入这些箭头或点。同样，对于操作系统的 shell 命令，我们将使用 Linux、macOS 和其他 Unix 系统的美元提示符（`$`），或者在特定操作系统对于当前任务无关紧要的情况下使用。

```py
$ python3 words.py

```

在这种情况下，您不需要输入 `$` 字符。

对于特定于 Windows 的命令，我们将使用一个前导大于提示符：

```py
> python words.py

```

同样，无需输入 `>` 字符。

对于需要放置在文件中而不是交互输入的代码块，我们显示的代码没有任何前导提示符：

```py
def write_sequence(filename, num):
    """Write Recaman's sequence to a text file."""
    with open(filename, mode='wt', encoding='utf-8') as f:
        f.writelines("{0}\n".format(r)
                     for r in islice(sequence(), num + 1))

```

我们努力确保我们的代码行足够短，以便每一行逻辑代码对应于您的书中的一行物理代码。然而，电子书发布到不同设备的变化和偶尔需要长行代码的真正需求意味着我们无法保证行不会换行。然而，我们可以保证，如果一行换行，出版商已经在最后一列插入了一个反斜杠字符 `\`。您需要自行判断这个字符是否是代码的合法部分，还是由电子书平台添加的。

```py
>>> print("This is a single line of code which is very long. Too long, in fact, to fi\
t on a single physical line of code in the book.")

```

如果您在上述引用的字符串中看到一条反斜杠，那么它*不*是代码的一部分，不应该输入。

偶尔，我们会对代码行进行编号，这样我们就可以很容易地从下一个叙述中引用它们。这些行号不应该作为代码的一部分输入。编号的代码块看起来像这样：

```py
 1 def write_grayscale(filename, pixels):
 2    height = len(pixels)
 3    width = len(pixels[0])
 4 
 5    with open(filename, 'wb') as bmp:
 6        # BMP Header
 7        bmp.write(b'BM')
 8 
 9        # The next four bytes hold the filesize as a 32-bit
10         # little-endian integer. Zero placeholder for now.
11         size_bookmark = bmp.tell()
12         bmp.write(b'\x00\x00\x00\x00')

```

有时我们需要呈现不完整的代码片段。通常这是为了简洁起见，我们要向现有的代码块添加代码，并且我们希望清楚地了解代码块的结构，而不重复所有现有的代码块内容。在这种情况下，我们使用包含三个点的 Python 注释`# ...`来指示省略的代码：

```py
class Flight:

    # ...

    def make_boarding_cards(self, card_printer):
        for passenger, seat in sorted(self._passenger_seats()):
            card_printer(passenger, seat, self.number(), self.aircraft_model())

```

这里暗示了在`Flight`类块中的`make_boarding_cards()`函数之前已经存在一些其他代码。

最后，在书的文本中，当我们提到一个既是标识符又是函数的标识符时，我们将使用带有空括号的标识符，就像我们在前面一段中使用`make_boarding_cards()`一样。


## 第一章：欢迎学徒！

欢迎来到《Python 学徒》！我们的目标是为您提供对 Python 编程语言的实用和全面的介绍，为您提供您在几乎任何 Python 项目中成为高效成员所需的工具和见解。Python 是一种庞大的语言，我们并不打算在这本书中涵盖所有需要了解的内容。相反，我们希望帮助您建立坚实的基础，让您在 Python 这个有时令人困惑的宇宙中找到方向，并让您有能力自主继续学习。

这本书主要面向有其他语言编程经验的人。如果你目前正在使用 C++、C#或 Java 等主流命令式或面向对象的语言进行编程，那么你将拥有你需要从这本书中获益的背景知识。如果你有其他类型语言的经验，比如函数式或基于角色的语言，那么你可能会在学习 Python 时遇到一些困难，但不会遇到严重的困难。大多数程序员发现 Python 非常易于接近和直观，只需稍加练习，他们很快就能熟悉它。

另一方面，如果你没有任何编程经验，这本书可能会有点吓人。你将不仅学习一种编程语言，同时学习许多所有语言共同的主题和问题。公平地说，我们并没有花很多时间来解释这些“假定知识”领域。这并不意味着你不能从这本书中学到东西！这只是意味着你可能需要更努力地学习，多次阅读章节，并可能需要他人的指导。然而，这种努力的回报是，你将开始发展处理其他语言的知识和直觉，这对于专业程序员来说是至关重要的技能。

在本章中，我们将快速了解 Python 语言。我们将介绍 Python 是什么（提示：它不仅仅是一种语言！），看看它是如何开发的，以及它对许多程序员如此吸引人的原因。我们还将简要预览本书的其余结构。

## Python 促销

首先，Python 有什么好处？为什么你想学它？对于这些问题有很多好答案。其中一个是 Python 很强大。Python 语言表达力强，高效，它带有一个[很棒的标准库](https://docs.python.org/3/library/index.html)，并且它是一个[巨大的精彩第三方库的中心](https://pypi.python.org/pypi)。使用 Python，你可以从简单的脚本到复杂的应用程序，你可以快速完成，你可以安全地完成，而且你可以用比你可能认为可能的更少的代码行数完成。

但这只是 Python 之所以伟大的一部分。另一个是 Python 非常开放。它是开源的，所以如果你愿意，你可以[了解它的每个方面](https://docs.python.org/devguide/setup.html)。同时，Python 非常受欢迎，并且有一个[伟大的社区来支持你](https://www.python.org/community/)当你遇到问题时。这种开放性和庞大的用户群意味着几乎任何人 - 从业余程序员到专业软件开发人员 - 都可以以他们需要的水平参与到这种语言中。

Python 拥有庞大的用户群体的另一个好处是它在越来越多的地方出现。你可能想要学习 Python，仅仅因为它是你想要使用的某种技术的语言，这并不奇怪 - 世界上许多最受欢迎的网络和科学软件包都是用 Python 编写的。

但对于许多人来说，这些原因都不如更重要的东西：Python 很有趣！Python 的表达力强，可读性强的风格，快速的编辑和运行开发周期，以及“电池包含”哲学意味着你可以坐下来享受编写代码，而不是与编译器和棘手的语法斗争。而且 Python 会随着你的成长而成长。当你的实验变成原型，你的原型变成产品时，Python 使编写软件的体验不仅更容易，而且真正令人愉快。

用[兰德尔·门罗的话来说](https://xkcd.com/353/)，“快来加入我们！编程再次变得有趣！”

## 概述

本书包括 10 章（不包括本章）。这些章节是相互关联的，所以除非您已经对 Python 有一定了解，否则需要按顺序进行学习。我们将从安装 Python 到您的系统并对其进行定位开始。

然后，我们将涵盖语言元素、特性、习惯用法和库，所有这些都是通过实际示例驱动的，您将能够随着文本一起构建这些示例。我们坚信，通过实践而非仅仅阅读，您将学到更多，因此我们鼓励您自己运行这些示例。

在本书结束时，您将了解 Python 语言的基础知识。您还将了解如何使用第三方库，以及开发它们的基础知识。我们甚至会介绍测试的基础知识，以便您可以确保和维护您开发的代码的质量。

章节包括：

1.  **入门：**我们将介绍安装 Python，了解一些基本的 Python 工具，并涵盖语言和语法的核心要素。

1.  **字符串和集合：**我们将介绍一些基本的复杂数据类型：字符串、字节序列、列表和字典。

1.  **模块化：**我们将介绍 Python 用于构建代码结构的工具，如函数和模块。

1.  **内置类型和对象模型：**我们将详细研究 Python 的类型系统和对象系统，并培养对 Python 引用语义的深刻理解。

1.  **集合类型：**我们将更深入地介绍一些 Python 集合类型，并介绍一些新的类型。

1.  **处理异常：**我们了解 Python 的异常处理系统以及异常在语言中的核心作用。

1.  **理解、可迭代和生成器：**我们将探讨 Python 中优雅、普遍和强大的面向序列的部分，如理解和生成器函数。

1.  **使用类定义新类型：**我们介绍如何使用类来开发自己的复杂数据类型，以支持面向对象编程。

1.  **文件和资源管理：**我们将介绍如何在 Python 中处理文件，并介绍 Python 用于资源管理的工具。

1.  **使用 Python 标准库进行单元测试：**我们将向您展示如何使用 Python 的`unittest`包来生成预期的无缺陷代码。

## Python 是什么？

### 它是一种编程语言！

那么 Python 是什么？简单地说，Python 是一种编程语言。它最初是由 Guido van Rossum 在 20 世纪 80 年代末在荷兰开发的。Guido 继续积极参与指导语言的发展和演变，以至于他被赋予了“终身仁慈独裁者”的称号，或者更常见的*BDFL*。Python 是作为一个开源项目开发的，可以自由下载和使用。非营利性的[Python 软件基金会](https://www.python.org/psf/)管理 Python 的知识产权，在推广语言方面发挥着重要作用，并在某些情况下资助其发展。

在技术层面上，Python 是一种强类型语言。这意味着语言中的每个对象都有一个确定的类型，通常没有办法规避该类型。与此同时，Python 是动态类型的，这意味着在运行代码之前没有对代码进行类型检查。这与 C++或 Java 等静态类型语言形成对比，编译器会为您进行大量的类型检查，拒绝错误使用对象的程序。最终，对 Python 类型系统的最佳描述是它使用*鸭子类型*，其中对象在运行时才确定其适用于上下文。我们将在第八章中更详细地介绍这一点。

Python 是一种通用编程语言。它并不是用于任何特定领域或环境，而是可以丰富地用于各种任务。当然，也有一些领域不太适合它 - 例如在极端时间敏感或内存受限的环境中 - 但大多数情况下，Python 像许多现代编程语言一样灵活和适应性强，比大多数编程语言更灵活。

Python 是一种解释型语言。从技术上讲，这有点错误，因为 Python 在执行之前通常会被编译成一种字节码形式。然而，这种编译是隐形的，使用 Python 的体验通常是立即执行代码，没有明显的编译阶段。编辑和运行之间的中断缺失是使用 Python 的一大乐趣之一。

Python 的语法旨在清晰、可读和富有表现力。与许多流行的语言不同，Python 使用空格来界定代码块，并在这个过程中摒弃了大量不必要的括号，同时强制执行统一的布局。这意味着所有 Python 代码在重要方面看起来都是相似的，你可以很快学会阅读 Python。与此同时，Python 富有表现力的语法意味着你可以在一行代码中表达很多含义。这种富有表现力、高度可读的代码意味着 Python 的维护相对容易。

Python 语言有多种实现。最初 - 也是迄今为止最常见的 - 实现是用 C 编写的。这个版本通常被称为*CPython*。当有人谈论“运行 Python”时，通常可以安全地假设他们在谈论 CPython，这也是我们在本书中将使用的实现。

Python 的其他实现包括：

+   [Jython](http://www.jython.org/)，编写以针对 Java 虚拟机

+   [IronPython](http://ironpython.net/)，编写以针对.NET 平台

+   [PyPy](http://pypy.org/)，用一种称为 RPython 的语言编写（有点循环），该语言旨在开发像 Python 这样的动态语言

这些实现通常落后于 CPython，后者被认为是该语言的“标准”。本书中学到的大部分内容都适用于所有这些实现。

#### Python 语言的版本

Python 语言目前有两个重要的常用版本：Python 2 和 Python 3。这两个版本代表了语言中一些关键元素的变化，除非你采取特殊预防措施，否则为其中一个版本编写的代码通常不会适用于另一个版本。Python 2 比 Python 3 更老，更为成熟，但 Python 3 解决了较老版本中的一些已知缺陷。Python 3 是 Python 的明确未来，如果可能的话，你应该使用它。

虽然 Python 2 和 3 之间存在一些关键差异，但这两个版本的大部分基础知识是相同的。如果你学会了其中一个，大部分知识都可以顺利转移到另一个版本。在本书中，我们将教授 Python 3，但在必要时我们会指出版本之间的重要差异。

### 这是一个标准库！

除了作为一种编程语言外，Python 还附带一个强大而广泛的标准库。Python 哲学的一部分是“电池包含”，这意味着你可以直接使用 Python 来处理许多复杂的现实任务，无需安装第三方软件包。这不仅非常方便，而且意味着通过使用有趣、引人入胜的示例来学习 Python 更容易 - 这也是我们在本书中的目标！

“电池包含”方法的另一个重要影响是，这意味着许多脚本 - 即使是非平凡的脚本 - 可以立即在任何 Python 安装上运行。这消除了在安装软件时可能面临的其他语言的常见烦人障碍。

标准库有相当高水平的良好文档。API 有很好的文档，模块通常有良好的叙述描述，包括快速入门指南、最佳实践信息等。[标准库文档始终可在线获取](https://docs.python.org/3/library/index.html)，如果需要，你也可以在本地安装它。

由于标准库是 Python 的重要组成部分，我们将在本书中涵盖其中的部分内容。即便如此，我们也不会涵盖其中的一小部分，因此鼓励你自行探索。

### 这是一种哲学

最后，没有描述 Python 的内容是完整的，没有提到对许多人来说，Python 代表了编写代码的一种哲学。清晰和可读性的原则是编写正确或*pythonic*代码的一部分。在所有情况下，*pythonic*的含义并不总是清晰，有时可能没有单一的正确写法。但 Python 社区关注简单、可读性和明确性的事项意味着 Python 代码往往更…嗯…美丽！

Python 的许多原则体现在所谓的“Python 之禅”中。这个“禅”不是一套严格的规则，而是一套在编码时牢记的指导原则或准则。当你试图在几种行动方案之间做出决定时，这些原则通常可以给你一个正确的方向。我们将在本书中突出显示“Python 之禅”的元素。

## 千里之行，始于足下。

我们认为 Python 是一种很棒的语言，我们很高兴能帮助你开始学习它。当你读完这本书时，你将能够编写大量的 Python 程序，甚至能够阅读更复杂的程序。更重要的是，你将拥有你需要的基础知识，可以去探索语言中所有更高级的主题，希望我们能让你对 Python 感到兴奋，真正去做。Python 是一种庞大的语言，拥有庞大的软件生态系统，围绕它构建了大量软件，发现它所提供的一切可能是一次真正的冒险。

欢迎来到 Python！


## 第二章：入门

在本章中，我们将介绍如何在 Windows、Ubuntu Linux 和 macOS 上获取和安装 Python。我们还将编写我们的第一个基本 Python 代码，并熟悉 Python 编程文化的基本知识，比如 Python 之禅，同时永远不要忘记语言名称的滑稽起源。

### 获取和安装 Python 3

Python 语言有两个主要版本，*Python 2*是广泛部署的传统语言，*Python 3*是语言的现在和未来。许多 Python 代码在 Python 2 的最后一个版本（即[Python 2.7](https://www.python.org/download/releases/2.7/)）和 Python 3 的最新版本之间可以无需修改地工作，比如[Python 3.5](https://www.python.org/download/releases/3.5.1/)。然而，主要版本之间存在一些关键差异，严格意义上来说，这两种语言是不兼容的。我们将在本书中使用 Python 3.5，但在介绍过程中我们将指出与 Python 2 的主要差异。此外，很可能，作为一本关于 Python 基础知识的书，我们所介绍的一切都适用于未来版本的 Python 3，因此不要害怕在这些版本推出时尝试它们。

在我们开始使用 Python 进行编程之前，我们需要获得一个 Python 环境。Python 是一种高度可移植的语言，可在所有主要操作系统上使用。您将能够在 Windows、Mac 或 Linux 上阅读本书，并且我们只有在安装 Python 3 时才会涉及到平台特定的主要部分。当我们涵盖这三个平台时，可以随意跳过对您不相关的部分。

#### Windows

1.  对于 Windows，您需要访问[官方 Python 网站](http://python.org)，然后通过单击左侧的链接转到下载页面。对于 Windows，您应该根据您的计算机是 32 位还是 64 位选择其中一个 MSI 安装程序。

1.  下载并运行安装程序。

1.  在安装程序中，决定您是只为自己安装 Python，还是为计算机上的所有用户安装 Python。

1.  选择 Python 分发的位置。默认位置将在`C:\Python35`中，位于`C:`驱动器的根目录下。我们不建议将 Python 安装到`Program Files`中，因为 Windows Vista 及更高版本中用于隔离应用程序的虚拟化文件存储可能会干扰轻松安装第三方 Python 包。

1.  在向导的*自定义 Python*页面上，我们建议保持默认设置，这将使用不到 40MB 的空间。

1.  除了安装 Python 运行时和标准库外，安装程序还将使用 Python 解释器注册各种文件类型，例如`*.py`文件。

1.  Python 安装完成后，您需要将 Python 添加到系统的`PATH`环境变量中。要做到这一点，从控制面板中选择*系统和安全*，然后选择*系统*。另一种更简单的方法是按住 Windows 键，然后按键盘上的 Break 键。在左侧的任务窗格中选择*高级系统设置*以打开*系统属性*对话框的*高级*选项卡。单击*环境变量*以打开子对话框。

1.  如果您拥有管理员权限，您应该能够将路径`C:\Python35`和`C:\Python35\Scripts`添加到与`PATH`系统变量关联的分号分隔的条目列表中。如果没有，您应该能够创建或附加到特定于您的用户的`PATH`变量，其中包含相同的值。

1.  现在打开一个*新*的控制台窗口——Powershell 或 cmd 都可以——并验证您是否可以从命令行运行 python：

```py
 > python
Python 3.5.0 (v3.5.0:374f501f4567, Sep 13 2015, 02:27:37) [MSC v.1900 64 bit (AMD64)]\
 on win32
Type "help", "copyright", "credits" or "license" for more information.
>>>

```

**欢迎使用 Python！**

三角箭头提示您 Python 正在等待您的输入。

在这一点上，您可能想要跳过，同时我们展示如何在 Mac 和 Linux 上安装 Python。

#### macOS

1.  对于 macOS，您需要访问官方 Python 网站[`python.org`](http://python.org)。点击左侧的链接进入下载页面。在下载页面上，找到与您的 macOS 版本匹配的 macOS 安装程序，并单击链接下载它。

1.  一个 DMG 磁盘映像文件将被下载，您可以从下载堆栈或 Finder 中打开它。

1.  在打开的 Finder 窗口中，您将看到文件`Python.mpkg`多包安装程序文件。使用“次要”点击操作打开该文件的上下文菜单。从该菜单中，选择“打开”。

1.  在某些版本的 macOS 上，您现在可能会收到文件来自未知开发者的通知。按下此对话框上的“打开”按钮以继续安装。

1.  您现在在 Python 安装程序中。按照说明，通过向导进行点击。

1.  无需定制安装，并且应保持标准设置。当可用时，单击“安装”按钮安装 Python。您可能会被要求输入密码以授权安装。安装完成后，单击“关闭”以关闭安装程序。

1.  现在 Python 3 已安装，请打开一个终端窗口并验证您是否可以从命令行运行 Python 3：

```py
 > python
Python 3.5.0 (default, Nov  3 2015, 13:17:02) 
[GCC 4.2.1 Compatible Apple LLVM 6.1.0 (clang-602.0.53)] on darwin
Type "help", "copyright", "credits" or "license" for more information.
>>> 

```

**欢迎使用 Python！**

三重箭头提示显示 Python 正在等待您的输入。

#### Linux

1.  要在 Linux 上安装 Python，您需要使用系统的软件包管理器。我们将展示如何在最新版本的 Ubuntu 上安装 Python，但在大多数其他现代 Linux 发行版上，该过程非常相似。

1.  在 Ubuntu 上，首先启动“Ubuntu 软件中心”。通常可以通过单击启动器中的图标来运行。或者，您可以在仪表板上搜索“Ubuntu 软件中心”并单击选择来运行它。

1.  一旦进入软件中心，在右上角的搜索栏中输入搜索词“python 3.5”并按回车键。

1.  您将获得一个结果，上面写着“Python（v3.5）”，下面以较小的字体写着“Python 解释器（v3.5）”。选择此条目并单击出现的“安装”按钮。

1.  此时可能需要输入密码来安装软件。

1.  现在您应该看到一个进度指示器出现，安装完成后将消失。

1.  打开终端（使用`Ctrl-Alt-T`）并验证您是否可以从命令行运行 Python 3.5：

```py
$ python3.5
Python 3.5.0+ (default, Oct 11 2015, 09:05:38)
[GCC 5.2.1 20151010] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>>

```

**欢迎使用 Python！**

三重箭头提示显示 Python 正在等待您的输入。

### 启动 Python 命令行 REPL

现在 Python 已安装并运行，您可以立即开始使用它。这是了解语言的好方法，也是正常开发过程中进行实验和快速测试的有用工具。

这个 Python 命令行环境是一个*读取-求值-打印-循环*。Python 将**读取**我们输入的任何内容，**求值**它，**打印**结果，然后**循环**回到开始。您经常会听到它被缩写为“REPL”。

启动时，REPL 将打印有关您正在运行的 Python 版本的一些信息，然后会给出一个三重箭头提示。此提示告诉您 Python 正在等待您输入。

在交互式 Python 会话中，您可以输入 Python 程序的片段并立即看到结果。让我们从一些简单的算术开始：

```py
>>> 2 + 2
4
>>> 6 * 7
42

```

正如您所看到的，Python 读取我们的输入，对其进行求值，打印结果，并循环执行相同的操作。

我们可以在 REPL 中为变量赋值：

```py
>>> x = 5

```

通过输入它们的名称打印它们的内容：

```py
>>> x
5

```

并在表达式中引用它们：

```py
>>> 3 * x
15

```

在 REPL 中，您可以使用特殊的下划线变量来引用最近打印的值，这是 Python 中非常少数的晦涩快捷方式之一：

```py
>>> _
15

```

或者您可以在表达式中使用特殊的下划线变量：

```py
>>> _ * 2
30

```

请注意，并非所有语句都有返回值。当我们将 5 赋给`x`时，没有返回值，只有将变量`x`带入的副作用。其他语句具有更明显的副作用。

尝试：

```py
>>> print('Hello, Python')
Hello, Python

```

您会发现 Python 立即评估并执行此命令，打印字符串“Hello, Python”，然后返回到另一个提示符。重要的是要理解，这里的响应不是由 REPL 评估和显示的表达式结果，而是`print()`函数的副作用。

### 离开 REPL

在这一点上，我们应该向您展示如何退出 REPL 并返回到系统 shell 提示符。我们通过向 Python 发送*文件结束*控制字符来实现这一点，尽管不幸的是，发送此字符的方式在不同平台上有所不同。

#### Windows

如果您在 Windows 上，按`Ctrl-Z`退出。

#### Unix

如果您在 Mac 或 Linux 上，按`Ctrl-D`退出。

如果您经常在不同平台之间切换，而在类 Unix 系统上意外按下`Ctrl-Z`，您将意外地挂起 Python 解释器并返回到操作系统 shell。要通过再次使 Python 成为前台进程来重新激活 Python，请运行`fg`命令：

```py
$ fg

```

然后按`Enter`键几次，以获取三角形箭头 Python 提示符：

```py
>>>

```

### 代码结构和重要缩进

启动 Python 3 解释器：

```py
> python

```

在 Windows 上或：

```py
$ python3

```

在 Mac 或 Linux 上。

Python 的控制流结构，如 for 循环、while 循环和 if 语句，都是由以冒号结尾的语句引入的，表示后面要跟着构造的主体。例如，for 循环需要一个主体，所以如果您输入：

```py
>>> for i in range(5):
...

```

Python 会向您显示三个点的提示，要求您提供主体。

Python 一个与众不同的（有时是有争议的）方面是，前导空格在语法上是有意义的。这意味着 Python 使用缩进级别来标示代码块，而不是其他语言使用的大括号。按照惯例，当代 Python 代码每个级别缩进四个空格。

因此，当 Python 向我们显示三个点的提示时，我们提供这四个空格和一个语句来形成循环的主体：

```py
...     x = i * 10

```

我们的循环主体将包含第二个语句，因此在下一个三点提示符处按`Return`后，我们将输入另外四个空格，然后调用内置的`print()`函数：

```py
...     print(x)

```

要终止我们的块，我们必须在 REPL 中输入一个空行：

```py
...

```

块完成后，Python 执行挂起的代码，打印出小于 50 的 10 的倍数：

```py
0
10
20
30
40

```

* * *

看着屏幕上的 Python 代码，我们可以看到缩进清晰地匹配 - 实际上*必须*匹配 - 程序的结构。

![Python 源代码](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-aprt/img/significant_whitespace_code.png)

Python 源代码

即使我们用灰色线代替代码，程序的结构也是清晰的。

![灰色的代码](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-aprt/img/significant_whitespace_bars.png)

灰色的代码

每个以冒号结尾的语句都会开始一个新行，并引入一个额外的缩进级别，直到取消缩进将缩进恢复到先前的级别。每个缩进级别通常是四个空格，尽管我们稍后会更详细地介绍规则。

Python 对重要空白的处理方式有三个很大的优势：

1.  它强制开发人员在代码块中使用单一级别的缩进。这通常被认为是任何语言中的良好实践，因为它使代码更易读。

1.  具有重要空白的代码不需要被不必要的大括号混乱，您也不需要就大括号应该放在哪里进行代码标准的辩论。Python 代码中的所有代码块都很容易识别，每个人都以相同的方式编写它们。

1.  重要的空白要求作者、Python 运行时系统和未来需要阅读代码的维护者对代码的结构给出一致的解释。因此，你永远不会有从 Python 的角度来看包含一个代码块，但从肤浅的人类角度来看却不像包含代码块的代码。

* * *

Python 缩进的规则可能看起来复杂，但在实践中它们是非常简单的。

+   你使用的空白可以是空格或制表符。一般的共识是*空格优于制表符*，*四个空格已经成为 Python 社区的标准*。

+   一个基本的规则是**绝对不要**混合使用空格和制表符。Python 解释器会抱怨，你的同事会追捕你。

+   如果你愿意，你可以在不同的时间使用不同数量的缩进。基本规则是*相同缩进级别的连续代码行被认为是同一个代码块的一部分*。

+   这些规则有一些例外，但它们几乎总是与以其他方式改善代码可读性有关，例如通过将必要的长语句分成多行。

这种严格的代码格式化方法是“Guido 所期望的编程”或者更恰当地说是“Guido 所*打算的编程”！重视代码质量，如可读性的哲学贯穿于 Python 文化的核心，现在我们将暂停一下来探讨一下。

### Python 文化

许多编程语言都处于文化运动的中心。它们有自己的社区、价值观、实践和哲学，Python 也不例外。Python 语言本身的发展是通过一系列称为*Python 增强提案*或*PEPs*的文件来管理的。其中一份 PEP，称为 PEP 8，解释了你应该如何格式化你的代码，我们在本书中遵循它的指导方针。例如，PEP 8 建议我们在新的 Python 代码中使用四个空格进行缩进。

另一个 PEP，称为 PEP 20，被称为“Python 的禅宗”。它涉及到 20 条格言，描述了 Python 的指导原则，其中只有 19 条被写下来。方便的是，Python 的禅宗从来都不会比最近的 Python 解释器更远，因为它总是可以通过在 REPL 中输入来访问：

```py
>>> import this
The Zen of Python, by Tim Peters

Beautiful is better than ugly.
Explicit is better than implicit.
Simple is better than complex.
Complex is better than complicated.
Flat is better than nested.
Sparse is better than dense.
Readability counts.
Special cases aren't special enough to break the rules.
Although practicality beats purity.
Errors should never pass silently.
Unless explicitly silenced.
In the face of ambiguity, refuse the temptation to guess.
There should be one-- and preferably only one --obvious way to do it.
Although that way may not be obvious at first unless you're Dutch.
Now is better than never.
Although never is often better than *right* now.
If the implementation is hard to explain, it's a bad idea.
If the implementation is easy to explain, it may be a good idea.
Namespaces are one honking great idea -- let's do more of those!

```

在本书中，我们将突出显示 Python 禅宗中的特定智慧之处，以了解它们如何适用于我们所学到的知识。由于我们刚刚介绍了 Python 的重要缩进，现在是我们第一个禅宗时刻的好时机。

* * *

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-aprt/img/zen-readability-counts.png)

随着时间的推移，你会开始欣赏 Python 的重要空白，因为它为*你的*代码带来了优雅，以及你可以轻松阅读*他人的*代码。

* * *

### 导入标准库模块

如前所述，Python 附带了一个庞大的标准库，这是 Python 的一个重要方面，通常被称为“电池包括在内”。标准库被组织为*模块*，这是我们将在后面深入讨论的一个主题。在这个阶段重要的是要知道，你可以通过使用`import`关键字来访问标准库模块。

导入模块的基本形式是`import`关键字后跟一个空格和模块的名称。例如，让我们看看如何使用标准库的`math`模块来计算平方根。在三角箭头提示下，我们输入：

```py
>>> import math

```

由于`import`是一个不返回值的语句，如果导入成功，Python 不会打印任何内容，我们会立即返回到提示符。我们可以通过使用模块的名称，后跟一个点，后跟您需要的模块中的属性的名称，来访问导入模块的内容。与许多面向对象的语言一样，点运算符用于深入到对象结构中。作为 Python 专家，我们知道`math`模块包含一个名为`sqrt()`的函数。让我们尝试使用它：

```py
>>> math.sqrt(81)
9.0

```

### 获取`help()`

但是我们如何找出`math`模块中还有哪些其他函数可用？

REPL 有一个特殊的函数`help()`，它可以检索已提供文档的对象的任何嵌入式文档，例如标准库模块。

要获取帮助，请在提示符处输入“help”：

```py
>>> help
Type help() for interactive help, or help(object) for help about object.

```

我们将让您在自己的时间里探索第一种形式——交互式帮助。在这里，我们将选择第二个选项，并将`math`模块作为我们想要帮助的对象传递：

```py
>>> help(math)
Help on module math:

NAME
    math

MODULE REFERENCE
        http://docs.python.org/3.3/library/math

    The following documentation is automatically generated from the Python
    source files.  It may be incomplete, incorrect or include features that
    are considered implementation detail and may vary between Python
    implementations.  When in doubt, consult the module reference at the
    location listed above.

DESCRIPTION
    This module is always available.  It provides access to the
    mathematical functions defined by the C standard.

FUNCTIONS
    acos(...)
    acos(x)

        Return the arc cosine (measured in radians) of x.

```

您可以使用空格键翻页帮助，如果您使用的是 Mac 或 Linux，则可以使用箭头键上下滚动。

浏览函数时，您会发现有一个名为`factorial`的数学函数，用于计算阶乘。按“q”退出帮助浏览器，返回到 Python REPL。

现在练习使用`help()`来请求`factorial`函数的特定帮助：

```py
>>> help(math.factorial)
Help on built-in function factorial in module math:

factorial(...)
    factorial(x) -> Integral

    Find x!. Raise a ValueError if x is negative or non-integral.

```

按“q”返回到 REPL。

让我们稍微使用一下`factorial()`。该函数接受一个整数参数并返回一个整数值：

```py
>>> math.factorial(5)
120
>>> math.factorial(6)
720

```

请注意，我们需要使用模块命名空间来限定函数名。这通常是一个很好的做法，因为它清楚地表明了函数的来源。尽管如此，它可能导致代码过于冗长。

#### 使用`math.factorial()`计算水果的数量

让我们使用阶乘来计算从五种水果中抽取三种水果的方式，使用我们在学校学到的一些数学：

```py
>>> n = 5
>>> k = 3
>>> math.factorial(n) / (math.factorial(k) * math.factorial(n - k))
10.0

```

这个简单的表达式对于所有这些对 math 模块的引用来说相当冗长。Python 的`import`语句有一种替代形式，允许我们使用`from`关键字将模块中的特定函数引入当前命名空间：

```py
>>> from math import factorial
>>> factorial(n) / (factorial(k) * factorial(n - k))
10.0

```

这是一个很好的改进，但对于这样一个简单的表达式来说仍然有点冗长。

导入语句的第三种形式允许我们重命名导入的函数。这对于可读性或避免命名空间冲突是有用的。尽管它很有用，但我们建议尽量少地和审慎地使用这个功能：

```py
>>> from math import factorial as fac
>>> fac(n) / (fac(k) * fac(n - k))
10.0

```

#### 不同类型的数字

请记住，当我们单独使用`factorial()`时，它返回一个整数。但是我们上面用于计算组合的更复杂的表达式产生了一个浮点数。这是因为我们使用了`/`，Python 的浮点除法运算符。由于我们知道我们的操作只会返回整数结果，我们可以通过使用`//`，Python 的整数除法运算符来改进我们的表达式：

```py
>>> from math import factorial as fac
>>> fac(n) // (fac(k) * fac(n - k))
10

```

值得注意的是，许多其他编程语言在上面的表达式中会在`n`的中等值上失败。在大多数编程语言中，常规的有符号整数只能存储小于![2^{31}](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-aprt/img/leanpub_equation_0.png)的值：

```py
>>> 2**31 - 1
2147483647

```

然而，阶乘增长得如此之快，以至于您可以将最大的阶乘放入 32 位有符号整数中为 12！因为 13！太大了：

```py
>>> fac(13)
6227020800

```

在大多数广泛使用的编程语言中，您要么需要更复杂的代码，要么需要更复杂的数学来计算从 13 个水果中抽取三个水果的方式。

Python 遇到这样的问题，并且可以计算任意大的整数，仅受计算机内存的限制。为了进一步证明这一点，让我们尝试计算从 100 种不同的水果中挑选多少种不同的水果对（假设我们可以拿到这么多水果！）：

```py
>>> n = 100
>>> k = 2
>>> fac(n) // (fac(k) * fac(n - k))
4950

```

只是为了强调一下表达式的第一项的大小有多大，计算 100!：

```py
>>> fac(n)
9332621544394415268169923885626670049071596826438162146859296389521759999322991560894\
1463976156518286253697920827223758251185210916864000000000000000000000000

```

这个数字甚至比已知宇宙中的原子数量还要大得多，有很多数字。如果像我们一样，你很好奇到底有多少位数字，我们可以将整数转换为文本字符串，并像这样计算其中的字符数：

```py
>>> len(str(fac(n)))
158

```

这绝对是很多数字。还有很多水果。它也开始展示了 Python 的不同数据类型——在这种情况下，整数、浮点数和文本字符串——如何以自然的方式协同工作。在下一节中，我们将在此基础上继续深入研究整数、字符串和其他内置类型。

### 标量数据类型：整数、浮点数、None 和布尔值

Python 带有许多内置数据类型。这些包括像整数这样的原始标量类型，以及像字典这样的集合类型。这些内置类型足够强大，可以单独用于许多编程需求，并且它们可以用作创建更复杂数据类型的构建块。

我们将要看的基本内置标量类型是：

+   `int`——有符号、无限精度整数

+   `float`——IEEE 754 浮点数

+   `None`——特殊的、唯一的空值

+   `bool`——true/false 布尔值

现在我们只会看一下它们的基本细节，展示它们的文字形式以及如何创建它们。

#### `int`

我们已经看到 Python 整数的很多用法。Python 整数是有符号的，对于所有实际目的来说，具有无限精度。这意味着它们可以容纳的值的大小没有预定义的限制。

Python 中的整数字面量通常以十进制指定：

```py
>>> 10
10

```

它们也可以用`0b`前缀指定为二进制：

```py
>>> 0b10
2

```

八进制，使用`0o`前缀：

```py
>>> 0o10
8

```

或十六进制，使用`0x`前缀：

```py
>>> 0x10
16

```

我们还可以通过调用`int`构造函数来构造整数，该构造函数可以将其他数字类型（如浮点数）转换为整数：

```py
>>> int(3.5)
3

```

请注意，当使用`int`构造函数时，四舍五入总是朝着零的方向进行：

```py
>>> int(-3.5)
-3
>>> int(3.5)
3

```

我们还可以将字符串转换为整数：

```py
>>> int("496")
496

```

但要注意，如果字符串不表示整数，Python 会抛出异常（稍后会更多地讨论这些！）。

在从字符串转换时，甚至可以提供一个可选的数字基数。例如，要从基数 3 转换，只需将 3 作为构造函数的第二个参数传递：

```py
>>> int("10000", 3)
81

```

#### 浮点数

Python 通过`float`类型支持浮点数。Python 浮点数实现为[IEEE-754 双精度浮点数](https://en.wikipedia.org/wiki/IEEE_floating_point)，具有 53 位二进制精度。这相当于十进制中 15 到 16 个有效数字。

任何包含小数点的文字数字都会被 Python 解释为`float`：

```py
>>> 3.125
3.125

```

科学计数法可以使用，因此对于大数字——例如![3\times10⁸](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-aprt/img/leanpub_equation_1.png)，即每秒米数的光速的近似值——我们可以写成：

```py
>>> 3e8
300000000.0

```

对于像普朗克常数![1.616\times10^{ - 35}](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-aprt/img/leanpub_equation_2.png)这样的小数字，我们可以输入：

```py
>>> 1.616e-35
1.616e-35

```

请注意，Python 会自动切换显示表示形式为最可读的形式。

至于整数，我们可以使用`float`构造函数从其他数字或字符串类型转换为浮点数。例如，构造函数可以接受一个`int`：

```py
>>> float(7)
7.0

```

或一个字符串：

```py
>>> float("1.618")
1.618

```

##### 特殊浮点值

通过将某些字符串传递给`float`构造函数，我们可以创建特殊的浮点值`NaN`（缩写为**N**ot **a** **N**umber），以及正无穷大和负无穷大：

```py
>>> float("nan")
nan
>>> float("inf")
inf
>>> float("-inf")
-inf

```

##### 提升为浮点数

任何涉及`int`和`float`的计算结果都会提升为`float`：

```py
>>> 3.0 + 1
4.0

```

您可以在 Python 文档中了解更多关于 Python 数字类型的信息（http://docs.python.org/3/library/stdtypes.html#numeric-types-int-float-complex）。

#### `None`

Python 有一个特殊的空值叫做`None`，拼写为大写的“N”。`None`经常用来表示值的缺失。Python REPL 从不打印`None`结果，因此在 REPL 中键入`None`没有任何效果：

```py
>>> None
>>>

```

`None`可以绑定到变量名，就像任何其他对象一样：

```py
>>> a = None

```

我们可以使用 Python 的`is`运算符测试对象是否为`None`：

```py
>>> a is None
True

```

我们可以看到这里的响应是`True`，这方便我们进入`bool`类型。

#### bool

`bool`类型表示逻辑状态，并在 Python 的几个控制流结构中扮演重要角色，我们很快就会看到。

正如您所期望的那样，有两个 bool 值，`True`和`False`，都以大写字母开头：

```py
>>> True
True
>>> False
False

```

还有一个`bool`构造函数，可以用于将其他类型转换为`bool`。让我们看看它是如何工作的。对于`int`，零被认为是“falsey”，所有其他值都被认为是“truthy”：

```py
>>> bool(0)
False
>>> bool(42)
True
>>> bool(-1)
True

```

我们在`float`中看到相同的行为，只有零被认为是“falsey”：

```py
>>> bool(0.0)
False
>>> bool(0.207)
True
>>> bool(-1.117)
True
>>> bool(float("NaN"))
True

```

在从集合（例如字符串或列表）转换时，只有空集合被视为“falsey”。在从列表转换时，我们看到只有空列表（在这里以`[]`的文字形式显示）被评估为`False`：

```py
>>> bool([])
False
>>> bool([1, 5, 9])
True

```

类似地，对于字符串，只有空字符串`""`在传递给`bool`时才会被评估为`False`：

```py
>>> bool("")
False
>>> bool("Spam")
True

```

特别地，您不能使用`bool`构造函数来从`True`和`False`的字符串表示中进行转换：

```py
>>> bool("False")
True

```

由于字符串“False”不为空，它将被评估为`True`！

这些转换为`bool`非常重要，因为它们在 Python 的 if 语句和 while 循环中被广泛使用，这些结构接受它们的条件中的`bool`值。

### 关系运算符

布尔值通常由 Python 的关系运算符产生，这些运算符可用于比较对象。

两个最常用的关系运算符是 Python 的相等和不相等测试，实际上是测试值的等价或不等价。也就是说，如果一个对象可以用于替代另一个对象，则两个对象是*等价的。我们将在本书的后面学习更多关于对象等价的概念。现在，我们将比较简单的整数。

让我们首先给变量`g`赋值或绑定一个值：

```py
>>> g = 20

```

我们使用`==`来测试相等：

```py
>>> g == 20
True
>>> g == 13
False

```

或者使用`!=`进行不等式比较：

```py
>>> g != 20
False
>>> g != 13
True

```

#### 丰富的比较运算符

我们还可以使用丰富的比较运算符来比较数量的顺序。使用`<`来确定第一个参数是否小于第二个参数：

```py
>>> g < 30
True

```

同样，使用`>`来确定第一个是否大于第二个：

```py
>>> g > 30
False

```

您可以使用`<=`来测试小于或等于：

```py
>>> g <= 20
True

```

大于或等于使用`>=`：

```py
>>> g >= 20
True

```

如果您对来自其他语言的关系运算符有经验，那么 Python 的运算符可能一点也不令人惊讶。只需记住这些运算符正在比较等价性，而不是身份，这是我们将在接下来的章节中详细介绍的区别。

### 控制流：if 语句和 while 循环

现在我们已经检查了一些基本的内置类型，让我们看看两个依赖于`bool`类型转换的重要控制流结构：if 语句和 while 循环。

#### 条件控制流：if 语句

条件语句允许我们根据表达式的值来分支执行。语句的形式是`if`关键字，后跟一个表达式，以冒号结束以引入一个新的块。让我们在 REPL 中尝试一下：

```py
>>> if True:

```

记住在块内缩进四个空格，我们添加一些代码，如果条件为`True`，则执行该代码，然后跟一个空行来终止该块：

```py
...     print("It's true!")
...
It's true!

```

在这一点上，该块将被执行，因为显然条件是`True`。相反，如果条件是`False`，则块中的代码不会执行：

```py
>>> if False:
...     print("It's true!")
...
>>>

```

与`bool()`构造函数一样，与 if 语句一起使用的表达式将被转换为`bool`，因此：

```py
>>> if bool("eggs"):
...     print("Yes please!")
...
Yes please!

```

与以下内容完全等价：

```py
>>> if "eggs":
...     print("Yes please!")
...
Yes please!

```

由于这种有用的简写，使用`bool`构造函数进行显式转换为`bool`在 Python 中很少使用。

#### `if...else`

if 语句支持一个可选的`else`子句，该子句放在由`else`关键字引入的块中（后跟一个冒号），并且缩进到与`if`关键字相同的级别。让我们首先创建（但不完成）一个 if 块：

```py
>>> h = 42
>>> if h > 50:
...     print("Greater than 50")

```

在这种情况下开始`else`块，我们只需在三个点之后省略缩进：

```py
... else:
...     print("50 or smaller")
...
50 or smaller

```

#### `if...elif...else`

对于多个条件，您可能会尝试做这样的事情：

```py
>>> if h > 50:
...     print("Greater than 50")
... else:
...     if h < 20:
...         print("Less than 20")
...     else:
...         print("Between 20 and 50")
...
Between 20 and 50

```

每当您发现自己有一个包含嵌套 if 语句的 else 块时，就像这样，您应该考虑使用 Python 的`elif`关键字，它是一个组合的`else-if`。

在 Python 的禅宗中提醒我们，“平面比嵌套更好”：

```py
>>> if h > 50:
...     print("Greater than 50")
... elif h < 20:
...     print("Less than 20")
... else:
...      print("Between 20 and 50")
...
Between 20 and 50

```

这个版本读起来更容易。

#### 条件重复：while 循环

Python 有两种类型的循环：for 循环和 while 循环。我们已经在介绍重要的空格时简要遇到了 for 循环，并且很快会回到它们，但现在我们将介绍 while 循环。

在 Python 中，while 循环由`while`关键字引入，后面跟着一个布尔表达式。与 if 语句的条件一样，表达式被隐式转换为布尔值，就好像它已经传递给了`bool()`构造函数。`while`语句以冒号结束，因为它引入了一个新的块。

让我们在 REPL 中编写一个循环，从五倒数到一。我们将初始化一个名为`c`的计数器变量，循环直到达到零为止。这里的另一个新语言特性是使用增强赋值运算符`-=`，在每次迭代中从计数器的值中减去一。类似的增强赋值运算符也适用于其他基本数学运算，如加法和乘法：

```py
>>> c = 5
>>> while c != 0:
...     print(c)
...     c -= 1
...
5
4
3
2
1

```

因为条件 - 或谓词 - 将被隐式转换为`bool`，就像存在对`bool()`构造函数的调用一样，我们可以用以下版本替换上面的代码：

```py
>>> c = 5
>>> while c:
...     print(c)
...     c -= 1
...
5
4
3
2
1

```

这是因为将`c`的整数值转换为`bool`的结果为`True`，直到我们达到零，转换为`False`。也就是说，在这种情况下使用这种简短形式可能被描述为非 Pythonic，因为根据 Python 的禅宗，显式优于隐式。我们更看重第一种形式的可读性，而不是第二种形式的简洁性。

在 Python 中，while 循环经常用于需要无限循环的情况。我们通过将`True`作为谓词表达式传递给 while 结构来实现这一点：

```py
>>> while True:
...     print("Looping!")
...
Looping!
Looping!
Looping!
Looping!
Looping!
Looping!
Looping!
Looping!

```

现在您可能想知道我们如何走出这个循环并重新控制我们的 REPL！只需按`Ctrl-C`：

```py
Looping!
Looping!
Looping!
Looping!
Looping!
Looping!^C
Traceback (most recent call last):
File "<stdin>", line 2, in <module>
KeyboardInterrupt
>>>

```

Python 拦截按键并引发一个特殊的异常，该异常终止循环。我们将在第六章后面更详细地讨论异常是什么，以及如何使用它们。

##### 使用`break`退出循环

许多编程语言支持一个循环结构，该结构将谓词测试放在循环的末尾而不是开头。例如，C、C++、C#和 Java 支持 do-while 结构。其他语言也有重复-直到循环。在 Python 中不是这种情况，Python 的习惯用法是使用`while True`以及通过`break`语句实现早期退出。

`break`语句跳出循环 - 如果有多个循环被嵌套，只跳出最内层的循环 - 并在循环体之后立即继续执行。

让我们看一个`break`的例子，一路上介绍一些其他 Python 特性，并逐行检查它：

```py
>>> while True:
...     response = input()
...     if int(response) % 7 == 0:
...         break
...

```

我们从`while True:`开始一个无限循环。在 while 块的第一条语句中，我们使用内置的`input()`函数从用户那里请求一个字符串。我们将该字符串赋给一个名为`response`的变量。

现在我们使用 if 语句来测试提供的值是否能被七整除。我们使用`int()`构造函数将响应字符串转换为整数，然后使用取模运算符`%`来除以七并给出余数。如果余数等于零，则响应可以被七整除，我们进入 if 块的主体。

在 if 块内，现在有两个缩进级别，我们从八个空格开始并使用`break`关键字。`break`终止最内层的循环 - 在本例中是 while 循环 - 并导致执行跳转到循环后的第一条语句。

在这里，“语句”是程序的结尾。我们在三个点的提示符下输入一个空行，以关闭 if 块和 while 块。

我们的循环将开始执行，并将在调用`input()`时暂停，等待我们输入一个数字。让我们试试几个：

```py
12
67
34
28
>>>

```

一旦我们输入一个可以被七整除的数字，谓词就变为`True`，我们进入 if 块，然后我们真正地跳出循环到程序的末尾，返回到 REPL 提示符。

### 总结

+   从 Python 开始

+   获取和安装 Python 3

+   开始读取-求值-打印循环或 REPL

+   简单的算术

+   通过将对象绑定到名称创建变量

+   使用内置的`print()`函数打印

+   使用`Ctrl-Z`（Windows）或`Ctrl-D`（Unix）退出 REPL

+   成为 Pythonic

+   重要的缩进

+   PEP 8 - Python 代码风格指南

+   PEP 20 - Python 之禅

+   以各种形式使用 import 语句导入模块

+   查找和浏览`help()`

+   基本类型和控制流

+   `int`，`float`，`None`和`bool`，以及它们之间的转换

+   用于相等性和排序测试的关系运算符

+   带有`else`和`elif`块的 if 语句

+   带有隐式转换为`bool`的 while 循环

+   使用`Ctrl-C`中断无限循环

+   使用`break`跳出循环

+   使用`input()`从用户那里请求文本

+   增强赋值运算符


## 第三章：字符串和集合

Python 包括丰富的内置集合类型，这些类型通常足以满足复杂程序的需求，而无需定义自己的数据结构。我们将概述一些基本的集合类型，足以让我们编写一些有趣的代码，尽管我们将在后面的章节中重新讨论这些集合类型，以及一些额外的类型。

让我们从这些类型开始：

+   `str` - 不可变的 Unicode 代码点字符串

+   `bytes` - 不可变的字节字符串

+   `list` - 可变的对象序列

+   `dict` - 可变的键值对映射

在这个过程中，我们还将介绍 Python 的 for 循环。

### `str` - 一个不可变的 Unicode 代码点序列

Python 中的字符串具有数据类型`str`，我们已经广泛地使用了它们。字符串是 Unicode 代码点的序列，大部分情况下你可以将代码点看作字符，尽管它们并不严格等价。Python 字符串中的代码点序列是不可变的，所以一旦你构造了一个字符串，就不能修改它的内容。

#### 字符串引用样式

Python 中的字面字符串由引号括起来：

```py
>>> 'This is a string'

```

你可以使用单引号，就像我们上面所做的那样。或者你可以使用双引号，就像下面所示的那样：

```py
>>> "This is also a string"

```

但是，你必须保持一致。例如，你不能使用双引号和单引号配对：

```py
>>> "inconsistent'
  File "<stdin>", line 1
    "inconsistent'
                  ^
SyntaxError: EOL while scanning string literal

```

支持两种引用样式使你可以轻松地将另一种引号字符合并到字面字符串中，而不必使用丑陋的转义字符技巧：

```py
>>> "It's a good thing."
"It's a good thing."
>>> '"Yes!", he said, "I agree!"'
'"Yes!", he said, "I agree!"'

```

请注意，REPL 在将字符串回显给我们时利用了相同的引用灵活性。

* * *

### 禅境时刻

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-aprt/img/zen-practicality-beats-purity.png)

乍一看，支持两种引用样式似乎违反了 Python 风格的一个重要原则。来自 Python 之禅：

> “应该有一种 - 最好只有一种 - 显而易见的方法来做到这一点。”

然而，在这种情况下，同一来源的另一句格言占据了主导地位：

> “……实用性胜过纯粹性，”

支持两种引用样式的实用性比另一种选择更受重视：单一引用样式与更频繁使用丑陋的转义序列的结合，我们很快就会遇到。

* * *

#### 相邻字符串的连接

Python 编译器将相邻的字面字符串连接成一个字符串：

```py
>>> "first" "second"
'firstsecond'

```

虽然乍一看这似乎毫无意义，但正如我们将在后面看到的那样，它可以用于很好地格式化代码。

#### 多行字符串和换行符

如果要创建包含换行符的字面字符串，有两种选择：使用多行字符串或使用转义序列。首先，让我们看看多行字符串。

多行字符串由三个引号字符而不是一个来界定。下面是一个使用三个双引号的例子：

```py
>>> """This is
... a multiline
... string"""
'This is\na multiline\nstring'

```

请注意，当字符串被回显时，换行符由`\n`转义序列表示。

我们也可以使用三个单引号：

```py
>>> '''So
... is
... this.'''
'So\nis\nthis.'

```

作为使用多行引用的替代方案，我们可以自己嵌入控制字符：

```py
>>> m = 'This string\nspans mutiple\nlines'
>>> m
'This string\nspans mutiple\nlines'

```

为了更好地理解我们在这种情况下所表示的内容，我们可以使用内置的`print()`函数来查看字符串：

```py
>>> print(m)
This string
spans mutiple
lines

```

如果你在 Windows 上工作，你可能会认为换行应该由回车换行对`\r\n`表示，而不仅仅是换行字符`\n`。在 Python 中不需要这样做，因为 Python 3 具有一个称为*通用换行符支持*的功能，它可以将简单的`\n`转换为你的平台上的本机换行序列。你可以在[PEP 278](http://www.python.org/dev/peps/pep-0278/)中了解更多关于通用换行符支持的信息。

我们也可以使用转义序列进行其他用途，比如用`\t`来插入制表符，或者在字符串中使用`\"`来使用引号字符：

```py
>>> "This is a \" in a string"
'This is a " in a string'

```

或者反过来：

```py
>>> 'This is a \' in a string'
"This is a ' in a string"

```

正如您所看到的，Python 比我们更聪明地使用了最方便的引号分隔符，尽管当我们在字符串中使用两种类型的引号时，Python 也会使用转义序列：

```py
>>> 'This is a \" and a \' in a string'
'This is a " and a \' in a string'

```

因为反斜杠具有特殊含义，所以要在字符串中放置一个反斜杠，我们必须用反斜杠本身来转义反斜杠：

```py
>>> k = 'A \\ in a string'
'A \\ in a string'

```

为了让自己确信该字符串中确实只有一个反斜杠，我们可以使用`print()`来打印它：

```py
>>> print(k)
A \ in a string

```

您可以在[Python 文档](http://docs.python.org/3/reference/lexical_analysis.html#strings)中阅读更多关于转义序列的信息。

#### 原始字符串

有时，特别是在处理诸如 Windows 文件系统路径或大量使用反斜杠的正则表达式模式^(2)时，要求双重反斜杠可能会很丑陋和容易出错。Python 通过原始字符串来解决这个问题。原始字符串不支持任何转义序列，非常直观。要创建原始字符串，请在开头引号前加上小写的`r`：

```py
>>> path = r'C:\Users\Merlin\Documents\Spells'
>>>
>>> path
'C:\\Users\\Merlin\\Documents\\Spells'
>>> print(path)
C:\Users\Merlin\Documents\Spells

```

#### `str`构造函数

我们可以使用`str`构造函数来创建其他类型的字符串表示，比如整数：

```py
>>> str(496)
>>> '496'

```

或浮点数：

```py
>>> str(6.02e23)
'6.02e+23'

```

#### 字符串作为序列

Python 中的字符串是所谓的*序列*类型，这意味着它们支持查询有序元素序列的某些常见操作。例如，我们可以使用方括号和基于零的整数索引来访问单个字符：

```py
>>> s = 'parrot'
>>> s[4]
'o'

```

与许多其他编程语言相比，Python 没有与字符串类型不同的单独的字符类型。索引操作返回一个包含单个代码点元素的完整字符串，这一点我们可以使用 Python 的内置`type()`函数来证明：

```py
>>> type(s[4])
<class 'str'>

```

我们将在本书的后面更详细地讨论类型和类。

#### 字符串方法

字符串对象还支持作为方法实现的各种操作。我们可以使用`help()`来列出字符串类型的方法：

```py
>>> help(str)

```

当您按下回车时，您应该看到这样的显示：

```py
Help on class str in module builtins:

class str(object)
 |  str(object='') -> str
 |  str(bytes_or_buffer[, encoding[, errors]]) -> str
 |
 |  Create a new string object from the given object. If encoding or
 |  errors is specified, then the object must expose a data buffer
 |  that will be decoded using the given encoding and error handler.
 |  Otherwise, returns the result of object.__str__() (if defined)
 |  or repr(object).
 |  encoding defaults to sys.getdefaultencoding().
 |  errors defaults to 'strict'.
 |
 |  Methods defined here:
 |
 |  __add__(self, value, /)
 |      Return self+value.
 |
 |  __contains__(self, key, /)
 |      Return key in self.
 |
 |  __eq__(self, value, /)
:

```

在任何平台上，您可以通过按空格键以每次前进一页的方式浏览帮助页面，直到看到`capitalize()`方法的文档，跳过所有以双下划线开头和结尾的方法：

```py
 |      Create and return a new object.  See help(type) for accurate signature.
 |
 |  __repr__(self, /)
 |      Return repr(self).
 |
 |  __rmod__(self, value, /)
 |      Return value%self.
 |
 |  __rmul__(self, value, /)
 |      Return self*value.
 |
 |  __sizeof__(...)
 |      S.__sizeof__() -> size of S in memory, in bytes
 |
 |  __str__(self, /)
 |      Return str(self).
 |
 |  capitalize(...)
 |      S.capitalize() -> str
 |
 |      Return a capitalized version of S, i.e. make the first character
 |      have upper case and the rest lower case.
 |
:

```

按下'q'退出帮助浏览器，然后我们将尝试使用`capitalize()`。让我们创建一个值得大写的字符串 - 一个首都的名字！

```py
>>> c = "oslo"

```

在 Python 中调用对象的方法时，我们在对象名称之后和方法名称之前使用点。方法是函数，所以我们必须使用括号来指示应该调用方法。

```py
>>> c.capitalize()
'Oslo'

```

请记住，字符串是不可变的，所以`capitalize()`方法没有直接修改`c`。相反，它返回了一个新的字符串。我们可以通过显示`c`来验证这一点，它保持不变：

```py
>>> c
'oslo'

```

您可能想花点时间熟悉一下字符串类型提供的各种有用方法，可以通过浏览帮助来了解。

#### 带 Unicode 的字符串

字符串完全支持 Unicode，因此您可以轻松地在国际字符中使用它们，甚至在文字中，因为 Python 3 的默认源代码编码是 UTF-8。例如，如果您可以访问挪威字符，您可以简单地输入这个：

```py
>>> "Vi er så glad for å høre og lære om Python!"
'Vi er så glad for å høre og lære om Python!'

```

或浮点数：

```py
>>> "Vi er s\u00e5 glad for \u00e5 h\xf8re og l\u00e6re om Python!"
'Vi er så glad for å høre og lære om Python!'

```

不过，我们相信这有点不太方便。

同样，您可以使用`\x`转义序列，后跟一个 2 字符的十六进制字符串，以在字符串文字中包含一个字节的 Unicode 代码点：

```py
>>> '\xe5'
'å'

```

您甚至可以使用一个转义的八进制字符串，使用一个反斜杠后跟三个零到七之间的数字，尽管我们承认我们从未见过这种用法，除非无意中作为错误：

```py
>>> '\345'
'å'

```

在否则类似的`bytes`类型中没有这样的 Unicode 功能，我们将在下一节中介绍。

### `bytes` - 一个不可变的字节序列

`bytes`类型类似于`str`类型，不同之处在于每个实例不是 Unicode 代码点的序列，而是字节的序列。因此，`bytes`对象用于原始二进制数据和固定宽度的单字节字符编码，如 ASCII。

#### 文字`bytes`

与字符串一样，它们有一个简单的文字形式，由单引号或双引号分隔，尽管对于文字`bytes`，开头引号必须由小写`b`前缀：

```py
>>> b'data'
b'data'
>>> b"data"
b'data'

```

还有一个`bytes`构造函数，但它有相当复杂的行为，我们将在本系列的第二本书*The Python Journeyman*中进行介绍。在我们的旅程中的这一点上，我们只需要认识到`bytes`文字并理解它们支持与`str`相同的许多操作，如索引和分割：

```py
>>> d = b'some bytes'
>>> d.split()
[b'some', b'bytes']

```

您会看到`split()`方法返回一个`bytes`对象的`list`。

#### 在`bytes`和`str`之间转换

要在`bytes`和`str`之间转换，我们必须知道用于表示字符串的 Unicode 代码点的字节序列的编码。Python 支持各种所谓的*codecs*，如 UTF-8、UTF-16、ASCII、Latin-1、Windows-1251 等等-请参阅 Python 文档以获取[当前 codecs 列表](http://docs.python.org/3/library/codecs.html#standard-encodings)

在 Python 中，我们可以将 Unicode`str`*编码*为`bytes`对象，反之亦然，我们可以将`bytes`对象*解码*为 Unicode`str`。在任何方向上，我们都必须指定编码。Python 不会-通常也不能-阻止您使用 CP037 编解码`bytes`对象中存储的 UTF-16 数据，例如处理旧 IBM 主机上的字符串。如果你幸运的话，解码将在运行时失败并显示`UnicodeError`；如果你不幸的话，你将得到一个充满垃圾的`str`，这将不会被你的程序检测到。

![编码和解码字符串。](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-aprt/img/encoding-decoding.png)

编码和解码字符串。

让我们开始一个交互式会话，查看字符串，其中包含 29 个字母的挪威字母表-一个全字母句：

```py
>>> norsk = "Jeg begynte å fortære en sandwich mens jeg kjørte taxi på vei til quiz"

```

我们现在将使用 UTF-8 编解码器将其编码为`bytes`对象，使用`str`对象的`encode()`方法：

```py
>>> data = norsk.encode('utf-8')
>>> data
b'Jeg begynte \xc3\xa5 fort\xc3\xa6re en sandwich mens jeg kj\xc3\xb8rte taxi p\xc3\x\
a5 vei til quiz'

```

看看每个挪威字母是如何被渲染为一对字节的。

我们可以使用`bytes`对象的`decode()`方法来反转这个过程。同样，我们必须提供正确的编码：

```py
>>> norwegian = data.decode('utf-8')

```

我们可以检查编码/解码往返是否给我们带来了与我们开始时相等的结果：

```py
>>> norwegian == norsk
True

```

并显示它以好的方式：

```py
>>> norwegian
'Jeg begynte å fortære en sandwich mens jeg kjørte taxi på vei til quiz'

```

在这个时刻，所有这些与编码有关的操作可能看起来像是不必要的细节-特别是如果您在一个英语环境中操作-但这是至关重要的，因为文件和网络资源（如 HTTP 响应）是作为字节流传输的，而我们更喜欢使用 Unicode 字符串的便利。

### `list`-对象的序列

Python `list`，例如字符串`split()`方法返回的那些，是对象的序列。与字符串不同，`list`是可变的，因为其中的元素可以被替换或移除，并且可以插入或追加新元素。`list`是 Python 数据结构的工作马。

文字列表由方括号分隔，并且`list`中的项目由逗号分隔。这是一个包含三个数字的`list`：

```py
>>> [1, 9, 8]
[1, 9, 8]

```

这是一个包含三个字符串的`list`：

```py
>>> a = ["apple", "orange", "pear"]

```

我们可以使用零为基础的索引用方括号检索元素：

```py
>>> a[1]
"orange"

```

我们可以通过分配给特定元素来替换元素：

```py
>>> a[1] = 7
>>> a
['apple', 7, 'pear']

```

看看`list`在包含的对象的类型方面可以是异构的。我们现在有一个包含`str`、`int`和另一个`str`的`list`。

创建一个空列表通常是有用的，我们可以使用空方括号来做到这一点：

```py
>>> b = []

```

我们可以以其他方式修改`list`。让我们使用`append()`方法在`list`的末尾添加一些`float`：

```py
>>> b.append(1.618)
>>> b
[1.618]
>>> b.append(1.414)
[1.618, 1.414]

```

有许多其他有用的方法可以操作`list`，我们将在后面的章节中介绍。现在，我们只需要能够执行基本的`list`操作。

还有一个`list`构造函数，可以用来从其他集合（如字符串）创建列表：

```py
>>> list("characters")
['c', 'h', 'a', 'r', 'a', 'c', 't', 'e', 'r', 's']

```

尽管 Python 中的显著空格规则起初似乎非常严格，但实际上有很大的灵活性。例如，如果一行末尾有未关闭的括号、大括号或括号，可以继续到下一行。这对于表示长的字面集合或甚至改善短集合的可读性非常有用：

```py
>>> c = ['bear',
...      'giraffe',
...      'elephant',
...      'caterpillar',]
>>> c
['bear', 'giraffe', 'elephant', 'caterpillar']

```

还要注意，我们可以在最后一个元素后使用额外的逗号，这是一个方便的功能，可以提高代码的可维护性。

### `dict` - 将键与值关联起来

字典 - 体现在`dict`类型中 - 对 Python 语言的工作方式非常基本，并且被广泛使用。字典将键映射到值，在某些语言中被称为映射或关联数组。让我们看看如何在 Python 中创建和使用字典。

使用花括号创建字面上的字典，其中包含键值对。每对由逗号分隔，每个键与其对应的值由冒号分隔。在这里，我们使用字典创建一个简单的电话目录：

```py
>>> d = {'alice': '878-8728-922', 'bob': '256-5262-124', 'eve': '198-2321-787'}

```

我们可以使用方括号运算符按键检索项目：

```py
>>> d['alice']
'878-8728-922'

```

我们可以通过方括号进行赋值来更新与特定键关联的值：

```py
>>> d['alice'] = '966-4532-6272'
>>> d
{'bob': '256-5262-124', 'eve': '198-2321-787', 'alice': '966-4532-6272'}

```

如果我们为尚未添加的键赋值，将创建一个新条目：

```py
>>> d['charles'] = '334-5551-913'
>>> d
{'bob': '256-5262-124', 'eve': '198-2321-787',
'charles': '334-5551-913', 'alice': '966-4532-6272'}

```

请注意，字典中的条目不能依赖于以任何特定顺序存储，并且实际上 Python 选择的顺序甚至可能在同一程序的多次运行之间发生变化。

与列表类似，可以使用空的花括号创建空字典：

```py
>>> e = {}

```

这只是对字典的一个非常粗略的介绍，但我们将在第五章中更详细地重新讨论它们。

### for 循环 - 迭代一系列项目

现在我们有了制作一些有趣的数据结构的工具，我们将看看 Python 的另一种循环结构，即 for 循环。在 Python 中，for 循环对应于许多其他编程语言中称为 for-each 循环的东西。它们从集合中逐个请求项目 - 或更严格地说是从可迭代系列中（但稍后会详细介绍） - 并将它们依次分配给我们指定的变量。让我们创建一个`list`集合，并使用 for 循环对其进行迭代，记得将 for 循环内的代码缩进四个空格：

```py
>>> cities = ["London", "New York", "Paris", "Oslo", "Helsinki"]
>>> for city in cities:
...     print(city)
...
London
New York
Paris
Oslo
Helsinki

```

因此，对`list`进行迭代会逐个返回项目。如果对字典进行迭代，你会得到看似随机顺序的键，然后可以在 for 循环体内使用这些键来检索相应的值。让我们定义一个字典，将颜色名称字符串映射到存储为整数的十六进制整数颜色代码：

```py
>>> colors = {'crimson': 0xdc143c, 'coral': 0xff7f50, 'teal': 0x008080}
>>> for color in colors:
...    print(color, colors[color])
...
coral 16744272
crimson 14423100
teal 32896

```

在这里，我们使用内置的`print()`函数接受多个参数的能力，分别传递每种颜色的键和值。还要注意返回给我们的颜色代码是十进制的。

现在，在我们将学到的一些东西整合到一个有用的程序中之前，练习使用`Ctrl-Z`（Windows）或`Ctrl-D`（Mac 或 Linux）退出 Python REPL。

### 把所有东西放在一起

让我们稍微偏离一下，尝试一下我们在稍大的示例中介绍的一些工具。教科书通常避免这种实用主义，特别是在早期章节，但我们认为将新的想法应用到实际情况中是有趣的。为了避免走样，我们需要引入一些“黑匣子”组件来完成工作，但你以后会详细了解它们，所以不用担心。

我们将在 REPL 中编写一个更长的片段，并简要介绍`with`语句。我们的代码将使用 Python 标准库函数`urlopen()`从网络中获取一些经典文学的文本数据。以下是在 REPL 中输入的完整代码。我们已经用行号注释了这段代码片段，以便参考解释中的行：

```py
1 >>> from urllib.request import urlopen
2 >>> with urlopen('http://sixty-north.com/c/t.txt') as story:
3 ...     story_words = []
4 ...     for line in story:
5 ...         line_words = line.split()
6 ...         for word in line_words:
7 ...             story_words.append(word)
8 ...

```

我们将逐行解释这段代码，依次解释每一行。

1.  要访问`urlopen()`，我们需要从`request`模块中导入该函数，该模块本身位于标准库`urllib`包中。

1.  我们将使用 URL 调用`urlopen()`来获取故事文本。我们使用一个称为 with 块的 Python 构造来管理从 URL 获取的资源，因为从网络获取资源需要操作系统套接字等。我们将在后面的章节中更多地讨论`with`语句，但现在知道，对于使用外部资源的对象使用`with`语句是良好的做法，以避免所谓的*资源泄漏*。`with`语句调用`urlopen()`函数，并将响应对象绑定到名为`story`的变量。

1.  请注意，`with`语句以冒号结尾，引入了一个新的代码块，因此在代码块内部我们必须缩进四个空格。我们创建一个空的`list`，最终将保存从检索到的文本中提取出的所有单词。

1.  我们打开一个 for 循环，它将遍历整个故事。请记住，for 循环会从`in`关键字右侧的表达式（在本例中是`story`）逐个请求项目，并依次将它们分配给左侧的名称（在本例中是`line`）。碰巧，由`story`引用的 HTTP 响应对象类型以这种方式迭代时会从响应主体中产生连续的文本行，因此 for 循环会逐行从故事中检索文本。`for`语句也以冒号结尾，因为它引入了 for 循环的主体，这是一个新的代码块，因此需要进一步缩进。

1.  对于每一行文本，我们使用`split()`方法将其按空白边界分割成单词，得到一个我们称为`line_words`的单词列表。

1.  现在我们使用嵌套在第一个循环内部的第二个 for 循环来遍历这个单词列表。

1.  我们依次将每个单词`append()`到累积的`story_words`列表中。

1.  最后，在三个点的提示下输入一个空行，以关闭所有打开的代码块——在本例中，内部 for 循环、外部 for 循环和 with 块都将被终止。代码块将被执行，稍后，Python 现在将我们返回到常规的三角形提示符。此时，如果 Python 给出错误，比如`SyntaxError`或`IndentationError`，您应该回去，检查您输入的内容，并仔细重新输入代码，直到 Python 接受整个代码块而不抱怨。如果出现`HTTPError`，则表示无法通过互联网获取资源，您应该检查您的网络连接或稍后重试，尽管值得检查您是否正确输入了 URL。

我们可以通过要求 Python 评估`story_words`的值来查看我们收集到的单词：

```py
>>> story_words
[b'It', b'was', b'the', b'best', b'of', b'times', b'it', b'was', b'the',
b'worst', b'of', b'times',b'it', b'was', b'the', b'age', b'of', b'wisdom',
b'it', b'was', b'the', b'age', b'of', b'foolishness', b'it', b'was',
b'the', b'epoch', b'of', b'belief', b'it', b'was', b'the', b'epoch', b'of',
b'incredulity', b'it', b'was', b'the', b'season', b'of', b'Light', b'it',
b'was', b'the', b'season', b'of', b'Darkness', b'it', b'was', b'the',
b'spring', b'of', b'hope', b'it', b'was', b'the', b'winter', b'of',
b'despair', b'we', b'had', b'everything', b'before', b'us', b'we', b'had',
b'nothing', b'before', b'us', b'we', b'were', b'all', b'going', b'direct',
b'to', b'Heaven', b'we', b'were', b'all', b'going', b'direct', b'the',
b'other', b'way', b'in', b'short', b'the', b'period', b'was', b'so', b'far',
b'like', b'the', b'present', b'period', b'that', b'some', b'of', b'its',
b'noisiest', b'authorities', b'insisted', b'on', b'its', b'being',
b'received', b'for', b'good', b'or', b'for', b'evil', b'in', b'the',
b'superlative', b'degree', b'of', b'comparison', b'only']

```

在 REPL 中进行这种探索性编程对于 Python 来说非常常见，因为它允许我们在决定使用它们之前弄清楚代码的各个部分。在这种情况下，请注意每个用单引号引起来的单词前面都有一个小写字母`b`，这意味着我们有一个`bytes`对象的列表，而我们更希望有一个`str`对象的列表。这是因为 HTTP 请求通过网络向我们传输了原始字节。要获得一个字符串列表，我们应该将每行中的字节流从 UTF-8 解码为 Unicode 字符串。我们可以通过插入`decode()`方法的调用来做到这一点，然后对生成的 Unicode 字符串进行操作。Python REPL 支持一个简单的命令历史记录，通过仔细使用上下箭头键，我们可以重新输入我们的片段，尽管没有必要重新导入`urlopen`，所以我们可以跳过第一行：

```py
1 >>> with urlopen('http://sixty-north.com/c/t.txt') as story:
2 ...     story_words = []
3 ...     for line in story:
4 ...         line_words = line.decode('utf-8').split()
5 ...         for word in line_words:
6 ...             story_words.append(word)
7 ...

```

这里我们改变了第四行 - 当你到达命令历史的那部分时，你可以使用左右箭头键编辑它，插入对`decode()`的必要调用。当我们重新运行这个块并重新查看`story_words`时，我们应该看到我们有一个字符串列表：

```py
>>> story_words
['It', 'was', 'the', 'best', 'of', 'times', 'it',
'was', 'the', 'worst', 'of', 'times', 'it', 'was', 'the', 'age', 'of',
'wisdom', 'it', 'was', 'the', 'age', 'of', 'foolishness', 'it', 'was',
'the', 'epoch', 'of', 'belief', 'it', 'was', 'the', 'epoch', 'of',
'incredulity', 'it', 'was', 'the', 'season', 'of', 'Light', 'it',
'was', 'the', 'season', 'of', 'Darkness', 'it', 'was', 'the',
'spring', 'of', 'hope', 'it', 'was', 'the', 'winter', 'of', 'despair',
'we', 'had', 'everything', 'before', 'us', 'we', 'had', 'nothing',
'before', 'us', 'we', 'were', 'all', 'going', 'direct', 'to',
'Heaven', 'we', 'were', 'all', 'going', 'direct', 'the', 'other',
'way', 'in', 'short', 'the', 'period', 'was', 'so', 'far', 'like',
'the', 'present', 'period', 'that', 'some', 'of', 'its', 'noisiest',
'authorities', 'insisted', 'on', 'its', 'being', 'received', 'for',
'good', 'or', 'for', 'evil', 'in', 'the', 'superlative', 'degree',
'of', 'comparison', 'only']

```

我们几乎达到了在 Python REPL 中舒适输入和修改的极限，所以在下一章中，我们将看看如何将这段代码移到一个文件中，在那里可以更容易地在文本编辑器中处理。

### 总结

+   `str` Unicode 字符串和`bytes`字符串：

+   我们看了看引号的各种形式（单引号或双引号）来引用字符串，这对于将引号本身合并到字符串中非常有用。Python 在你使用哪种引号风格上很灵活，但在界定特定字符串时必须保持一致。

+   我们演示了所谓的三重引号，由三个连续的引号字符组成，可以用来界定多行字符串。传统上，每个引号字符本身都是双引号，尽管也可以使用单引号。

+   我们看到相邻的字符串文字会被隐式连接。

+   Python 支持通用换行符，所以无论你使用什么平台，只需使用一个`\n`字符，就可以放心地知道它将在 I/O 期间被适当地从本机换行符转换和转换。

+   转义序列提供了将换行符和其他控制字符合并到文字字符串中的另一种方法。

+   用于转义的反斜杠可能会对 Windows 文件系统路径或正则表达式造成阻碍，因此可以使用带有`r`前缀的原始字符串来抑制转义机制。

+   其他类型，比如整数，可以使用`str()`构造函数转换为字符串。

+   可以使用带有整数从零开始的索引的方括号检索单个字符，返回一个字符字符串。

+   字符串支持丰富多样的操作，比如通过它们的方法进行分割。

+   在 Python 3 中，文字字符串可以直接包含任何 Unicode 字符，这在源代码中默认解释为 UTF-8。

+   `bytes`类型具有许多字符串的功能，但它是字节序列而不是 Unicode 代码点序列。

+   `bytes`文字以小写的`b`为前缀。

+   要在字符串和字节实例之间转换，我们使用`str`的`encode()`方法或`bytes`的`decode()`方法，在这两种情况下都要传递编解码器的名称，这是我们必须事先知道的。

+   列表

+   列表是可变的、异构的对象序列。

+   列表文字由方括号界定，项目之间用逗号分隔。

+   可以通过使用包含从零开始的整数索引的方括号从列表中检索单个元素。

+   与字符串相反，可以通过对索引项赋值来替换单个列表元素。

+   列表可以通过`append()`来扩展，也可以使用`list()`构造函数从其他序列构造。

+   `dict`

+   字典将键与值关联起来。

+   字面上的字典由花括号括起来。键值对之间用逗号分隔，每个键与其相应的值用冒号关联。

+   `for` 循环

+   For 循环逐个从可迭代对象（如 `list`）中取出项目，并将相同的名称绑定到当前项目。

+   它们对应于其他语言中称为 for-each 循环的内容。
