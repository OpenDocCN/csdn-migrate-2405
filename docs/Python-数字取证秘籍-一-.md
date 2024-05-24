# Python 数字取证秘籍（一）

> 原文：[`zh.annas-archive.org/md5/941c711b36df2129e5f7d215d3712f03`](https://zh.annas-archive.org/md5/941c711b36df2129e5f7d215d3712f03)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

在本书开始时，我们努力展示了 Python 在当今数字调查中几乎无穷无尽的用例。技术在我们的日常生活中扮演着越来越重要的角色，并且没有停止的迹象。现在，比以往任何时候都更重要的是，调查人员必须开发编程技能，以处理日益庞大的数据集。通过利用本书中探讨的 Python 配方，我们使复杂的事情变得简单，高效地从大型数据集中提取相关信息。您将探索、开发和部署 Python 代码和库，以提供可以立即应用于您的调查的有意义的结果。

在整本书中，配方包括与法证证据容器一起工作、解析移动和桌面操作系统的证据、从文档和可执行文件中提取嵌入式元数据，以及识别妥协指标等主题。您还将学习如何将脚本与应用程序接口（API）（如 VirusTotal 和 PassiveTotal）以及工具（如 Axiom、Cellebrite 和 EnCase）集成。到本书结束时，您将对 Python 有扎实的理解，并将知道如何在调查中使用它来处理证据。

# 本书涵盖的内容

《第一章》（part0029.html#RL0A0-260f9401d2714cb9ab693c4692308abe），*基本脚本和文件信息配方*，向您介绍了本书中使用的 Python 的约定和基本特性。在本章结束时，您将创建一个强大而有用的数据和元数据保存脚本。

《第二章》（part0071.html#23MNU0-260f9401d2714cb9ab693c4692308abe），*创建证据报告配方*，演示了使用法证证据创建报告的实用方法。从电子表格到基于 Web 的仪表板，我们展示了各种报告格式的灵活性和实用性。

《第三章》（part0097.html#2SG6I0-260f9401d2714cb9ab693c4692308abe），*深入移动取证配方*，介绍了 iTunes 备份处理、已删除的 SQLite 数据库记录恢复，以及从 Cellebrite XML 报告中映射 Wi-Fi 接入点 MAC 地址。

《第四章》（part0127.html#3P3NE0-260f9401d2714cb9ab693c4692308abe），*提取嵌入式元数据配方*，揭示了包含嵌入式元数据的常见文件类型以及如何提取它。我们还向您提供了如何将 Python 脚本与流行的法证软件 EnCase 集成的知识。

《第五章》（part0158.html#4MLOS0-260f9401d2714cb9ab693c4692308abe），*网络和妥协指标配方*，侧重于网络和基于 Web 的证据，以及如何从中提取更多信息。您将学习如何从网站保留数据，与处理后的 IEF 结果交互，为 X-Ways 创建哈希集，并识别恶意域名或 IP 地址。

《第六章》（part0185.html#5GDO20-260f9401d2714cb9ab693c4692308abe），*阅读电子邮件和获取名称的配方*，探讨了个人电子邮件消息和整个邮箱的许多文件类型，包括 Google Takeout MBox，以及如何使用 Python 进行提取和分析。

《第七章》（part0212.html#6A5N80-260f9401d2714cb9ab693c4692308abe），*基于日志的证据配方*，说明了如何处理来自多种日志格式的证据，并使用 Python 信息报告或其他行业工具（如 Splunk）进行摄取。您还将学习如何开发和使用 Python 配方来解析文件并在 Axiom 中创建证据。

《第八章》（part0241.html#75QNI0-260f9401d2714cb9ab693c4692308abe），*与法证证据容器配方一起工作*，展示了与法证证据容器交互和处理所需的基本法证库，包括 EWF 和原始格式。您将学习如何从法证容器中访问数据，识别磁盘分区信息，并遍历文件系统。

第九章，*探索 Windows 取证工件配方第一部分*，利用了在第八章中开发的框架，*处理取证证据容器配方*，来处理取证证据容器中的各种 Windows 工件。这些工件包括`$I`回收站文件、各种注册表工件、LNK 文件和 Windows.edb 索引。

第十章，*探索 Windows 取证工件配方第二部分*，继续利用在第八章中开发的框架，*处理取证证据容器配方*，来处理取证证据容器中的更多 Windows 工件。这些工件包括预取文件、事件日志、`Index.dat`、卷影副本和 Windows 10 SRUM 数据库。

# 本书所需的内容

为了跟随并执行本食谱中的配方，使用一台连接到互联网的计算机，并安装最新的 Python 2.7 和 Python 3.5。配方可能需要安装额外的第三方库；有关如何执行此操作的说明将在配方中提供。

为了更轻松地开发和实施这些配方，建议您设置和配置一个 Ubuntu 虚拟机进行开发。这些配方（除非另有说明）是在 Ubuntu 16.04 环境中使用 Python 2.7 和 3.5 构建和测试的。一些配方将需要使用 Windows 操作系统，因为许多取证工具只能在此平台上运行。

# 本书适合对象

如果您是数字取证检察官、网络安全专家或热衷于了解 Python 基础知识并希望将其提升到更高水平的分析师，那么这本书适合您。在学习的过程中，您将了解到许多适用于解析取证证据的库。您将能够使用和构建我们开发的脚本，以提升其分析能力。

# 章节

本书中，您会经常看到几个标题（准备工作，如何做…，它是如何工作的…，还有更多…，以及另请参阅）。

为了清晰地说明如何完成一个配方，我们使用以下这些部分：

# 准备工作

本节告诉您配方中可以期待什么，并描述了为配方设置任何软件或所需的任何初步设置的方法。

# 如何做…

本节包含跟随配方所需的步骤。

# 它是如何工作的…

本节通常包括对前一节中发生的事情的详细解释。

# 还有更多…

本节包含有关配方的其他信息，以使读者更加了解配方。

# 另请参阅

本节提供了有用的链接，以获取配方的其他有用信息。

# 约定

在本书中，您会发现许多文本样式，用于区分不同类型的信息。以下是一些这些样式的示例及其含义的解释。

文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 用户名显示如下：“我们可以通过调用`get_data()`函数来收集所需的信息。”

代码块设置如下：

```py
def hello_world():
   print(“Hello World!”)
hello_world()
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```py
def hello_world():
    print(“Hello World!”)
hello_world()
```

任何命令行输入或输出都是按照以下格式编写的：

```py
# pip install tqdm==4.11.2
```

**新术语**和**重要单词**以粗体显示。您在屏幕上看到的单词，例如菜单或对话框中的单词，会以这种方式出现在文本中：“从管理面板中选择系统信息。”

警告或重要说明会以这种方式出现。提示和技巧会以这种方式出现。


# 第一章：基本脚本和文件信息配方

本章涵盖了以下配方：

+   像成年人一样处理参数

+   迭代松散文件

+   记录文件属性

+   复制文件、属性和时间戳

+   对文件和数据流进行哈希处理

+   使用进度条跟踪

+   记录结果

+   多人合作，事半功倍

# 介绍

数字取证涉及识别和分析数字媒体，以协助法律、商业和其他类型的调查。我们分析的结果往往对调查的方向产生重大影响。鉴于“摩尔定律”或多或少成立，我们预期要审查的数据量正在稳步增长。因此，可以断定，调查人员必须依赖某种程度的自动化来有效地审查证据。自动化，就像理论一样，必须经过彻底的审查和验证，以免导致错误的结论。不幸的是，调查人员可能使用工具来自动化某些过程，但并不完全了解工具、潜在的取证物件或输出的重要性。这就是 Python 发挥作用的地方。

在《Python 数字取证食谱》中，我们开发和详细介绍了一些典型场景的示例。目的不仅是演示 Python 语言的特性和库，还要说明它的一个巨大优势：即对物件的基本理解。没有这种理解，就不可能首先开发代码，因此迫使您更深入地理解物件。再加上 Python 的相对简单和自动化的明显优势，很容易理解为什么这种语言被社区如此迅速地接受。

确保调查人员理解我们脚本的产品的一种方法是提供有意义的文档和代码解释。这就是本书的目的。本书中演示的示例展示了如何配置参数解析，这既易于开发，又简单易懂。为了增加脚本的文档，我们将介绍有效记录脚本执行过程和遇到的任何错误的技术。

数字取证脚本的另一个独特特性是与文件及其相关元数据的交互。取证脚本和应用程序需要准确地检索和保留文件属性，包括日期、权限和文件哈希。本章将介绍提取和呈现这些数据给审查员的方法。

与操作系统和附加卷上找到的文件进行交互是数字取证中设计的任何脚本的核心。在分析过程中，我们需要访问和解析具有各种结构和格式的文件。因此，准确和正确地处理和与文件交互非常重要。本章介绍的示例涵盖了本书中将继续使用的常见库和技术：

+   解析命令行参数

+   递归迭代文件和文件夹

+   记录和保留文件和文件夹的元数据

+   生成文件和其他内容的哈希值

+   用进度条监视代码

+   记录配方执行信息和错误

+   通过多进程改善性能

访问[www.packtpub.com/books/content/support](http://www.packtpub.com/books/content/support)下载本章的代码包。

# 像成年人一样处理参数

配方难度：简单

Python 版本：2.7 或 3.5

操作系统：任何

A 人：我来这里是为了进行一场好的争论！

B 人：啊，不，你没有，你来这里是为了争论！

A 人：一个论点不仅仅是矛盾。

B 人：好吧！可能吧！

A 人：不，不行！一个论点是一系列相关的陈述

旨在建立一个命题。

B 人：不，不是！

A 人：是的，是的！不仅仅是矛盾。

除了蒙提·派森([`www.montypython.net/scripts/argument.php`](http://www.montypython.net/scripts/argument.php))之外，参数是任何脚本的一个组成部分。参数允许我们为用户提供一个接口，以指定改变代码行为的选项和配置。有效地使用参数，不仅仅是矛盾，可以使工具更加灵活，并成为审查人员喜爱的工具。

# 入门

此脚本中使用的所有库都包含在 Python 的标准库中。虽然还有其他可用的参数处理库，例如`optparse`和`ConfigParser`，但我们的脚本将利用`argparse`作为我们的事实命令行处理程序。虽然`optparse`是以前版本的 Python 中使用的库，但`argparse`已成为创建参数处理代码的替代品。`ConfigParser`库从配置文件中解析参数，而不是从命令行中解析。这对于需要大量参数或有大量选项的代码非常有用。在本书中，我们不会涵盖`ConfigParser`，但如果发现您的`argparse`配置变得难以维护，值得探索一下。

要了解有关`argparse`库的更多信息，请访问[`docs.python.org/3/library/argparse.html`](https://docs.python.org/3/library/argparse.html)。

# 如何做…

在此脚本中，我们执行以下步骤：

1.  创建位置参数和可选参数。

1.  向参数添加描述。

1.  使用选择选项配置参数。

# 工作原理…

首先，我们导入`print_function`和`argparse`模块。通过从`__future__`库导入`print_function`，我们可以像在 Python 3.X 中编写打印语句一样编写它们，但仍然在 Python 2.X 中运行它们。这使我们能够使配方与 Python 2.X 和 3.X 兼容。在可能的情况下，我们在本书中的大多数配方中都这样做。

在创建有关配方的一些描述性变量之后，我们初始化了我们的`ArgumentParser`实例。在构造函数中，我们定义了`description`和`epilog`关键字参数。当用户指定`-h`参数时，这些数据将显示，并且可以为用户提供有关正在运行的脚本的额外上下文。`argparse`库非常灵活，如果需要，可以扩展其复杂性。在本书中，我们涵盖了该库的许多不同特性，这些特性在其文档页面上有详细说明：

```py
from __future__ import print_function
import argparse

__authors__ = ["Chapin Bryce", "Preston Miller"]
__date__ = 20170815
__description__ = 'A simple argparse example'

parser = argparse.ArgumentParser(
    description=__description__,
    epilog="Developed by {} on {}".format(
        ", ".join(__authors__), __date__)
)
```

创建了解析器实例后，我们现在可以开始向我们的命令行处理程序添加参数。有两种类型的参数：位置参数和可选参数。位置参数以字母开头，与可选参数不同，可选参数以破折号开头，并且需要执行脚本。可选参数以单个或双破折号字符开头，不是位置参数（即，顺序无关紧要）。如果需要，可以手动指定这些特性以覆盖我们描述的默认行为。以下代码块说明了如何创建两个位置参数：

```py
# Add Positional Arguments
parser.add_argument("INPUT_FILE", help="Path to input file")
parser.add_argument("OUTPUT_FILE", help="Path to output file")
```

除了更改参数是否必需，我们还可以指定帮助信息，创建默认值和其他操作。`help`参数有助于传达用户应提供的内容。其他重要参数包括`default`、`type`、`choices`和`action`。`default`参数允许我们设置默认值，而`type`将输入的类型（默认为字符串）转换为指定的 Python 对象类型。`choices`参数使用定义的列表、字典或集合来创建用户可以选择的有效选项。

`action`参数指定应用于给定参数的操作类型。一些常见的操作包括`store`，这是默认操作，用于存储与参数关联的传递值；`store_true`，将`True`分配给参数；以及`version`，打印由版本参数指定的代码版本：

```py
# Optional Arguments
parser.add_argument("--hash", help="Hash the files", action="store_true")

parser.add_argument("--hash-algorithm",
                    help="Hash algorithm to use. ie md5, sha1, sha256",
                    choices=['md5', 'sha1', 'sha256'], default="sha256"
                    )

parser.add_argument("-v", "--version", "--script-version",
                    help="Displays script version information",
                    action="version", version=str(__date__)
                    )

parser.add_argument('-l', '--log', help="Path to log file", required=True)
```

当我们定义和配置了我们的参数后，我们现在可以解析它们并在我们的代码中使用提供的输入。以下片段显示了我们如何访问这些值并测试用户是否指定了可选参数。请注意我们如何通过我们分配的名称来引用参数。如果我们指定了短和长的参数名，我们必须使用长名：

```py
# Parsing and using the arguments
args = parser.parse_args()

input_file = args.INPUT_FILE
output_file = args.OUTPUT_FILE

if args.hash:
    ha = args.hash_algorithm
    print("File hashing enabled with {} algorithm".format(ha))
if not args.log:
    print("Log file not defined. Will write to stdout")
```

当组合成一个脚本并在命令行中使用`-h`参数执行时，上述代码将提供以下输出：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00005.jpeg)

如此所示，`-h`标志显示了脚本帮助信息，由`argparse`自动生成，以及`--hash-algorithm`参数的有效选项。我们还可以使用`-v`选项来显示版本信息。`--script-version`参数以与`-v`或`-version`参数相同的方式显示版本，如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00006.jpeg)

下面的屏幕截图显示了当我们选择我们的一个有效的哈希算法时在控制台上打印的消息：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00007.jpeg)

# 还有更多...

这个脚本可以进一步改进。我们在这里提供了一些建议：

+   探索额外的`argparse`功能。例如，`argparse.FileType`对象可用于接受`File`对象作为输入。

+   我们还可以使用`argparse.ArgumentDefaultsHelpFormatter`类来显示我们为用户设置的默认值。当与可选参数结合使用时，这对于向用户显示如果没有指定将使用什么是有帮助的。

# 迭代松散的文件

示例难度：简单

Python 版本：2.7 或 3.5

操作系统：任何

通常需要迭代一个目录及其子目录以递归处理所有文件。在这个示例中，我们将说明如何使用 Python 遍历目录并访问其中的文件。了解如何递归地浏览给定的输入目录是关键的，因为我们经常在我们的脚本中执行这个操作。

# 入门

这个脚本中使用的所有库都包含在 Python 的标准库中。在大多数情况下，用于处理文件和文件夹迭代的首选库是内置的`os`库。虽然这个库支持许多有用的操作，但我们将专注于`os.path()`和`os.walk()`函数。让我们使用以下文件夹层次结构作为示例来演示 Python 中的目录迭代是如何工作的：

```py
SecretDocs/
|-- key.txt
|-- Plans
|   |-- plans_0012b.txt
|   |-- plans_0016.txt
|   `-- Successful_Plans
|       |-- plan_0001.txt
|       |-- plan_0427.txt
|       `-- plan_0630.txt
|-- Spreadsheets
|   |-- costs.csv
|   `-- profit.csv
`-- Team
    |-- Contact18.vcf
    |-- Contact1.vcf
    `-- Contact6.vcf

4 directories, 11 files
```

# 如何做…

在这个示例中执行以下步骤：

1.  为要扫描的输入目录创建一个位置参数。

1.  遍历所有子目录并将文件路径打印到控制台。

# 它是如何工作的…

我们创建了一个非常基本的参数处理程序，接受一个位置输入`DIR_PATH`，即要迭代的输入目录的路径。例如，我们将使用`~/Desktop`路径作为脚本的输入参数，它是`SecretDocs`的父目录。我们解析命令行参数并将输入目录分配给一个本地变量。现在我们准备开始迭代这个输入目录：

```py
from __future__ import print_function
import argparse
import os

__authors__ = ["Chapin Bryce", "Preston Miller"]
__date__ = 20170815
__description__ = "Directory tree walker"

parser = argparse.ArgumentParser(
    description=__description__,
    epilog="Developed by {} on {}".format(
        ", ".join(__authors__), __date__)
)
parser.add_argument("DIR_PATH", help="Path to directory")
args = parser.parse_args()
path_to_scan = args.DIR_PATH
```

要迭代一个目录，我们需要提供一个表示其路径的字符串给`os.walk()`。这个方法在每次迭代中返回三个对象，我们已经在 root、directories 和 files 变量中捕获了这些对象：

+   `root`：这个值以字符串形式提供了当前目录的相对路径。使用示例目录结构，root 将从`SecretDocs`开始，最终变成`SecretDocs/Team`和`SecretDocs/Plans/SuccessfulPlans`。

+   `directories`：这个值是当前根目录中的子目录列表。我们可以遍历这个目录列表，尽管在后续的`os.walk()`调用中，这个列表中的条目将成为根值的一部分。因此，这个值并不经常使用。

+   `files`：这个值是当前根位置的文件列表。

在命名目录和文件变量时要小心。在 Python 中，`dir`和`file`名称被保留用于其他用途，不应该用作变量名。

```py
# Iterate over the path_to_scan
for root, directories, files in os.walk(path_to_scan):
```

通常会创建第二个 for 循环，如下面的代码所示，以遍历该目录中的每个文件，并对它们执行某些操作。使用`os.path.join()`方法，我们可以将根目录和`file_entry`变量连接起来，以获取文件的路径。然后我们将这个文件路径打印到控制台上。例如，我们还可以将这个文件路径追加到一个列表中，然后对列表进行迭代以处理每个文件：

```py
    # Iterate over the files in the current "root"
    for file_entry in files:
        # create the relative path to the file
        file_path = os.path.join(root, file_entry)
        print(file_path)
```

我们也可以使用`root + os.sep() + file_entry`来实现相同的效果，但这不如我们使用的连接路径的方法那样符合 Python 的风格。使用`os.path.join()`，我们可以传递两个或更多的字符串来形成单个路径，比如目录、子目录和文件。

当我们用示例输入目录运行上述脚本时，我们会看到以下输出：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00008.jpeg)

如所见，`os.walk()`方法遍历目录，然后会进入任何发现的子目录，从而扫描整个目录树。

# 还有更多...

这个脚本可以进一步改进。以下是一个建议：

+   查看并使用`glob`库实现类似功能，与`os`模块不同，它允许对文件和目录进行通配符模式递归搜索

# 记录文件属性

配方难度：简单

Python 版本：2.7 或 3.5

操作系统：任何

现在我们可以遍历文件和文件夹，让我们学习如何记录这些对象的元数据。文件元数据在取证中扮演着重要的角色，因为收集和审查这些信息是大多数调查中的基本任务。使用单个 Python 库，我们可以跨平台收集一些最重要的文件属性。

# 开始

此脚本中使用的所有库都包含在 Python 的标准库中。`os`库再次可以在这里用于收集文件元数据。收集文件元数据最有帮助的方法之一是`os.stat()`函数。需要注意的是，`stat()`调用仅提供当前操作系统和挂载卷的文件系统可用的信息。大多数取证套件允许检查员将取证图像挂载为系统上的卷，并通常保留 stat 调用可用的`file`属性。在第八章，*使用取证证据容器配方*中，我们将演示如何打开取证获取以直接提取文件信息。

要了解更多关于`os`库的信息，请访问[`docs.python.org/3/library/os.html`](https://docs.python.org/3/library/os.html)。

# 如何做...

我们将使用以下步骤记录文件属性：

1.  获取要处理的输入文件。

1.  打印各种元数据：MAC 时间，文件大小，组和所有者 ID 等。

# 它是如何工作的...

首先，我们导入所需的库：`argparse`用于处理参数，`datetime`用于解释时间戳，`os`用于访问`stat()`方法。`sys`模块用于识别脚本正在运行的平台（操作系统）。接下来，我们创建我们的命令行处理程序，它接受一个参数`FILE_PATH`，表示我们将从中提取元数据的文件的路径。在继续执行脚本之前，我们将这个输入分配给一个本地变量：

```py
from __future__ import print_function
import argparse
from datetime import datetime as dt
import os
import sys

__authors__ = ["Chapin Bryce", "Preston Miller"]
__date__ = 20170815
__description__ = "Gather filesystem metadata of provided file"

parser = argparse.ArgumentParser(
    description=__description__,
    epilog="Developed by {} on {}".format(", ".join(__authors__), __date__)
)
parser.add_argument("FILE_PATH",
                    help="Path to file to gather metadata for")
args = parser.parse_args()
file_path = args.FILE_PATH
```

时间戳是收集的最常见的文件元数据属性之一。我们可以使用`os.stat()`方法访问创建、修改和访问时间戳。时间戳以表示自 1970-01-01 以来的秒数的浮点数返回。使用`datetime.fromtimestamp()`方法，我们将这个值转换为可读格式。

`os.stat()`模块根据平台不同而解释时间戳。例如，在 Windows 上，`st_ctime`值显示文件的创建时间，而在 macOS 和 UNIX 上，这个属性显示文件元数据的最后修改时间，类似于 NTFS 条目的修改时间。然而，`os.stat()`的其余部分在不同平台上是相同的。

```py
stat_info = os.stat(file_path)
if "linux" in sys.platform or "darwin" in sys.platform:
    print("Change time: ", dt.fromtimestamp(stat_info.st_ctime))
elif "win" in sys.platform:
    print("Creation time: ", dt.fromtimestamp(stat_info.st_ctime))
else:
    print("[-] Unsupported platform {} detected. Cannot interpret "
          "creation/change timestamp.".format(sys.platform)
          )
print("Modification time: ", dt.fromtimestamp(stat_info.st_mtime))
print("Access time: ", dt.fromtimestamp(stat_info.st_atime))
```

我们继续打印时间戳后的文件元数据。文件模式和`inode`属性分别返回文件权限和整数`inode`。设备 ID 指的是文件所在的设备。我们可以使用`os.major()`和`os.minor()`方法将这个整数转换为主设备标识符和次设备标识符：

```py
print("File mode: ", stat_info.st_mode)
print("File inode: ", stat_info.st_ino)
major = os.major(stat_info.st_dev)
minor = os.minor(stat_info.st_dev)
print("Device ID: ", stat_info.st_dev)
print("\tMajor: ", major)
print("\tMinor: ", minor)
```

`st_nlink`属性返回文件的硬链接数。我们可以分别使用`st_uid`和`st_gid`属性打印所有者和组信息。最后，我们可以使用`st_size`来获取文件大小，它返回一个表示文件大小的整数（以字节为单位）。

请注意，如果文件是符号链接，则`st_size`属性反映的是指向目标文件的路径的长度，而不是目标文件的大小。

```py
print("Number of hard links: ", stat_info.st_nlink)
print("Owner User ID: ", stat_info.st_uid)
print("Group ID: ", stat_info.st_gid)
print("File Size: ", stat_info.st_size)
```

但等等，这还不是全部！我们可以使用`os.path()`模块来提取更多的元数据。例如，我们可以使用它来确定文件是否是符号链接，就像下面展示的`os.islink()`方法一样。有了这个，我们可以警告用户，如果`st_size`属性不等于目标文件的大小。`os.path()`模块还可以获取绝对路径，检查它是否存在，并获取父目录。我们还可以使用`os.path.dirname()`函数或访问`os.path.split()`函数的第一个元素来获取父目录。`split()`方法更常用于从路径中获取文件名：

```py
# Gather other properties
print("Is a symlink: ", os.path.islink(file_path))
print("Absolute Path: ", os.path.abspath(file_path))
print("File exists: ", os.path.exists(file_path))
print("Parent directory: ", os.path.dirname(file_path))
print("Parent directory: {} | File name: {}".format(
    *os.path.split(file_path)))
```

通过运行脚本，我们可以获取有关文件的相关元数据。请注意，`format()`方法允许我们打印值，而不必担心它们的数据类型。通常情况下，如果我们直接打印变量而不使用字符串格式化，我们需要先将整数和其他数据类型转换为字符串：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00009.jpeg)

# 还有更多...

这个脚本可以进一步改进。我们在这里提供了一些建议：

+   将这个方法与*遍历松散文件*方法结合起来，递归地提取给定一系列目录中文件的元数据

+   实现逻辑以按文件扩展名、修改日期或文件大小进行过滤，以仅收集符合所需条件的文件的元数据信息

# 复制文件、属性和时间戳

方法难度：简单

Python 版本：2.7 或 3.5

操作系统：Windows

保留文件是数字取证中的一项基本任务。通常情况下，最好将文件容器化为可以存储松散文件的哈希和其他元数据的格式。然而，有时我们需要以数字取证的方式从一个位置复制文件到另一个位置。使用这个方法，我们将演示一些可用于复制文件并保留常见元数据字段的方法。

# 入门

这个方法需要安装两个第三方模块`pywin32`和`pytz`。此脚本中使用的所有其他库都包含在 Python 的标准库中。这个方法主要使用两个库，内置的`shutil`和第三方库`pywin32`。`shutil`库是我们在 Python 中复制文件的首选，我们可以使用它来保留大部分时间戳和其他文件属性。然而，`shutil`模块无法保留它复制的文件的创建时间。相反，我们必须依赖于特定于 Windows 的`pywin32`库来保留它。虽然`pywin32`库是特定于平台的，但它非常有用，可以与 Windows 操作系统进行交互。

要了解有关`shutil`库的更多信息，请访问[`docs.python.org/3/library/shutil.html`](https://docs.python.org/3/library/shutil.html)。

要安装`pywin32`，我们需要访问其 SourceForge 页面[`sourceforge.net/projects/pywin32/`](https://sourceforge.net/projects/pywin32/)并下载与我们的 Python 安装相匹配的版本。要检查我们的 Python 版本，我们可以导入`sys`模块并在解释器中调用`sys.version`。在选择正确的`pywin32`安装程序时，版本和架构都很重要。

要了解有关`sys`库的更多信息，请访问[`docs.python.org/3/library/sys.html`](https://docs.python.org/3/library/sys.html)。

除了安装`pywin32`库之外，我们还需要安装`pytz`，这是一个第三方库，用于在 Python 中管理时区。我们可以使用`pip`命令安装这个库：

```py
pip install pytz==2017.2
```

# 如何做…

我们执行以下步骤来在 Windows 系统上进行取证复制文件：

1.  收集源文件和目标参数。

1.  使用`shutil`来复制和保留大多数文件元数据。

1.  使用`win32file`手动设置时间戳属性。

# 它是如何工作的…

现在让我们深入研究复制文件并保留其属性和时间戳。我们使用一些熟悉的库来帮助我们执行这个配方。一些库，如`pytz`，`win32file`和`pywintypes`是新的。让我们在这里简要讨论它们的目的。`pytz`模块允许我们更细致地处理时区，并允许我们为`pywin32`库初始化日期。

为了让我们能够以正确的格式传递时间戳，我们还必须导入`pywintypes`。最后，`win32file`库，通过我们安装的`pywin32`提供了在 Windows 中进行文件操作的各种方法和常量：

```py
from __future__ import print_function
import argparse
from datetime import datetime as dt
import os
import pytz
from pywintypes import Time
import shutil
from win32file import SetFileTime, CreateFile, CloseHandle
from win32file import GENERIC_WRITE, FILE_SHARE_WRITE
from win32file import OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL

__authors__ = ["Chapin Bryce", "Preston Miller"]
__date__ = 20170815
__description__ = "Gather filesystem metadata of provided file"

```

这个配方的命令行处理程序接受两个位置参数，`source`和`dest`，分别代表要复制的源文件和输出目录。这个配方有一个可选参数`timezone`，允许用户指定一个时区。

为了准备源文件，我们存储绝对路径并从路径的其余部分中分离文件名，如果目标是目录，则稍后可能需要使用。我们最后的准备工作涉及从用户那里读取时区输入，这是四个常见的美国时区之一，以及 UTC。这使我们能够为后续在配方中使用初始化`pytz`时区对象：

```py
parser = argparse.ArgumentParser(
    description=__description__,
    epilog="Developed by {} on {}".format(
        ", ".join(__authors__), __date__)
)
parser.add_argument("source", help="Source file")
parser.add_argument("dest", help="Destination directory or file")
parser.add_argument("--timezone", help="Timezone of the file's timestamp",
                    choices=['EST5EDT', 'CST6CDT', 'MST7MDT', 'PST8PDT'],
                    required=True)
args = parser.parse_args()

source = os.path.abspath(args.source)
if os.sep in args.source:
    src_file_name = args.source.split(os.sep, 1)[1]
else:
    src_file_name = args.source

dest = os.path.abspath(args.dest)
tz = pytz.timezone(args.timezone)
```

在这一点上，我们可以使用`shutil.copy2()`方法将源文件复制到目标。这个方法接受目录或文件作为目标。`shutil` `copy()`和`copy2()`方法之间的主要区别在于`copy2()`方法还保留文件属性，包括最后写入时间和权限。这个方法不会在 Windows 上保留文件创建时间，为此我们需要利用`pywin32`绑定。

为此，我们必须通过使用以下`if`语句构建`copy2()`调用复制的文件的目标路径，以便在命令行提供目录时连接正确的路径：

```py
shutil.copy2(source, dest)
if os.path.isdir(dest):
    dest_file = os.path.join(dest, src_file_name)
else:
    dest_file = dest
```

接下来，我们为`pywin32`库准备时间戳。我们使用`os.path.getctime()`方法收集相应的 Windows 创建时间，并使用`datetime.fromtimestamp()`方法将整数值转换为日期。有了我们的`datetime`对象准备好了，我们可以通过使用指定的`timezone`使值具有时区意识，并在将时间戳打印到控制台之前将其提供给`pywintype.Time()`函数：

```py
created = dt.fromtimestamp(os.path.getctime(source))
created = Time(tz.localize(created))
modified = dt.fromtimestamp(os.path.getmtime(source))
modified = Time(tz.localize(modified))
accessed = dt.fromtimestamp(os.path.getatime(source))
accessed = Time(tz.localize(accessed))

print("Source\n======")
print("Created: {}\nModified: {}\nAccessed: {}".format(
    created, modified, accessed))
```

准备工作完成后，我们可以使用`CreateFile()`方法打开文件，并传递表示复制文件的字符串路径，然后是由 Windows API 指定的用于访问文件的参数。这些参数及其含义的详细信息可以在[`msdn.microsoft.com/en-us/library/windows/desktop/aa363858(v=vs.85).aspx﻿`](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363858(v=vs.85).aspx)上进行查看：

```py
handle = CreateFile(dest_file, GENERIC_WRITE, FILE_SHARE_WRITE,
                    None, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, None)
SetFileTime(handle, created, accessed, modified)
CloseHandle(handle)
```

一旦我们有了一个打开的文件句柄，我们可以调用`SetFileTime()`函数按顺序更新文件的创建、访问和修改时间戳。设置了目标文件的时间戳后，我们需要使用`CloseHandle()`方法关闭文件句柄。为了向用户确认文件时间戳的复制成功，我们打印目标文件的创建、修改和访问时间：

```py
created = tz.localize(dt.fromtimestamp(os.path.getctime(dest_file)))
modified = tz.localize(dt.fromtimestamp(os.path.getmtime(dest_file)))
accessed = tz.localize(dt.fromtimestamp(os.path.getatime(dest_file)))
print("\nDestination\n===========")
print("Created: {}\nModified: {}\nAccessed: {}".format(
    created, modified, accessed))
```

脚本输出显示了成功保留时间戳的文件从源复制到目标的过程：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00010.jpeg)

# 还有更多…

这个脚本可以进一步改进。我们在这里提供了一些建议：

+   对源文件和目标文件进行哈希处理，以确保它们被成功复制。哈希处理在下一节的文件和数据流哈希处理配方中介绍。

+   输出文件复制的日志以及在复制过程中遇到的任何异常。

# 对文件和数据流进行哈希处理

配方难度：简单

Python 版本：2.7 或 3.5

操作系统：任意

文件哈希是确定文件完整性和真实性的广泛接受的标识符。虽然一些算法已经容易受到碰撞攻击，但这个过程在这个领域仍然很重要。在这个配方中，我们将介绍对一串字符和文件内容流进行哈希处理的过程。

# 入门

此脚本中使用的所有库都包含在 Python 的标准库中。为了生成文件和其他数据源的哈希值，我们实现了`hashlib`库。这个内置库支持常见的算法，如 MD5、SHA-1、SHA-256 等。在撰写本书时，许多工具仍然利用 MD5 和 SHA-1 算法，尽管当前的建议是至少使用 SHA-256。或者，可以使用文件的多个哈希值来进一步减少哈希冲突的几率。虽然我们将展示其中一些算法，但还有其他不常用的算法可供选择。

要了解有关`hashlib`库的更多信息，请访问[`docs.python.org/3/library/hashlib.html`](https://docs.python.org/3/library/hashlib.html)。

# 如何做…

我们使用以下步骤对文件进行哈希处理：

1.  使用指定的输入文件和算法打印哈希文件名。

1.  使用指定的输入文件和算法打印哈希文件数据。

# 工作原理…

首先，我们必须像下面所示导入`hashlib`。为了方便使用，我们已经定义了一个算法字典，我们的脚本可以使用`MD5`、`SHA-1`、`SHA-256`和`SHA-512`。通过更新这个字典，我们可以支持其他具有`update()`和`hexdigest()`方法的哈希函数，包括一些不属于`hashlib`库的库中的函数：

```py
from __future__ import print_function
import argparse
import hashlib
import os

__authors__ = ["Chapin Bryce", "Preston Miller"]
__date__ = 20170815
__description__ = "Script to hash a file's name and contents"

available_algorithms = {
    "md5": hashlib.md5,
    "sha1": hashlib.sha1,
    "sha256": hashlib.sha256,
    "sha512": hashlib.sha512
}

parser = argparse.ArgumentParser(
    description=__description__,
    epilog="Developed by {} on {}".format(", ".join(__authors__), __date__)
)
parser.add_argument("FILE_NAME", help="Path of file to hash")
parser.add_argument("ALGORITHM", help="Hash algorithm to use",
                    choices=sorted(available_algorithms.keys()))
args = parser.parse_args()

input_file = args.FILE_NAME
hash_alg = args.ALGORITHM
```

注意我们如何使用字典和命令行提供的参数来定义我们的哈希算法对象，然后使用括号来初始化对象。这在添加新的哈希算法时提供了额外的灵活性。

定义了我们的哈希算法后，我们现在可以对文件的绝对路径进行哈希处理，这是在为 iOS 设备的 iTunes 备份命名文件时使用的类似方法，通过将字符串传递到`update()`方法中。当我们准备显示计算出的哈希的十六进制值时，我们可以在我们的`file_name`对象上调用`hexdigest()`方法：

```py
file_name = available_algorithms[hash_alg]()
abs_path = os.path.abspath(input_file)
file_name.update(abs_path.encode())

print("The {} of the filename is: {}".format(
    hash_alg, file_name.hexdigest()))
```

让我们继续打开文件并对其内容进行哈希处理。虽然我们可以读取整个文件并将其传递给 `hash` 函数，但并非所有文件都足够小以适应内存。为了确保我们的代码适用于更大的文件，我们将使用以下示例中的技术以分段方式读取文件并以块的方式进行哈希处理。

通过以 `rb` 打开文件，我们将确保读取文件的二进制内容，而不是可能存在的字符串内容。打开文件后，我们将定义缓冲区大小以读取内容，然后读取第一块数据。

进入 while 循环，我们将根据文件中的内容更新我们的哈希对象。只要文件中有内容，这是可能的，因为 `read()` 方法允许我们传递一个要读取的字节数的整数，如果整数大于文件中剩余的字节数，它将简单地传递给我们剩余的字节。

读取整个文件后，我们调用对象的 `hexdigest()` 方法来向检查员显示文件哈希：

```py
file_content = available_algorithms[hash_alg]()
with open(input_file, 'rb') as open_file:
    buff_size = 1024
    buff = open_file.read(buff_size)

    while buff:
        file_content.update(buff)
        buff = open_file.read(buff_size)

print("The {} of the content is: {}".format(
    hash_alg, file_content.hexdigest()))
```

当我们执行代码时，我们会看到两个打印语句的输出，显示文件的绝对路径和内容的哈希值。我们可以通过在命令行中更改算法来为文件生成额外的哈希：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00011.jpeg)

# 还有更多…

这个脚本可以进一步改进。以下是一个建议：

+   添加对其他哈希算法的支持，并在 `available_algorithms` 全局变量中创建相应的条目

# 使用进度条进行跟踪

示例难度：简单

Python 版本：2.7 或 3.5

操作系统：任何

不幸的是，处理以千兆字节或兆字节为单位的数据时，长时间运行的脚本是司空见惯的。虽然您的脚本可能在顺利处理这些数据，但用户可能会认为它在三个小时后没有任何进展的情况下已经冻结。幸运的是，一些开发人员构建了一个非常简单的进度条库，让我们没有理由不将其纳入我们的代码中。

# 入门

此示例需要安装第三方模块 `tqdm`。此脚本中使用的所有其他库都包含在 Python 的标准库中。`tqdm` 库，发音为 taqadum，可以通过 `pip` 安装或从 GitHub 下载 [`github.com/tqdm/tqdm`](https://github.com/tqdm/tqdm)。要使用本示例中显示的所有功能，请确保您使用的是 4.11.2 版本，在 `tqdm` GitHub 页面上或使用以下命令通过 `pip` 获取：

```py
pip install tqdm==4.11.2
```

# 如何做…

要创建一个简单的进度条，我们按照以下步骤进行：

1.  导入 `tqdm` 和 `time`。

1.  使用 `tqdm` 和循环创建多个示例。

# 工作原理…

与所有其他示例一样，我们从导入开始。虽然我们只需要 `tqdm` 导入来启用进度条，但我们将使用时间模块来减慢脚本的速度，以更好地可视化进度条。我们使用水果列表作为我们的样本数据，并确定哪些水果的名称中包含 "berry" 或 "berries"：

```py
from __future__ import print_function
from time import sleep
import tqdm

fruits = [
    "Acai", "Apple", "Apricots", "Avocado", "Banana", "Blackberry",
    "Blueberries", "Cherries", "Coconut", "Cranberry", "Cucumber",
    "Durian", "Fig", "Grapefruit", "Grapes", "Kiwi", "Lemon", "Lime",
    "Mango", "Melon", "Orange", "Papaya", "Peach", "Pear", "Pineapple",
    "Pomegranate", "Raspberries", "Strawberries", "Watermelon"
]
```

以下的 for 循环非常简单，遍历我们的水果列表，在休眠一秒钟之前检查水果名称中是否包含子字符串 `berr`。通过在迭代器周围包装 `tqdm()` 方法，我们自动获得一个漂亮的进度条，显示完成百分比、已用时间、剩余时间、完成的迭代次数和总迭代次数。

这些显示选项是 `tqdm` 的默认选项，并且使用我们的列表对象的属性收集所有必要的信息。例如，该库几乎可以通过收集长度并根据每次迭代的时间和已经过的数量来计算其余部分，从而了解进度条的几乎所有细节：

```py
contains_berry = 0
for fruit in tqdm.tqdm(fruits):
    if "berr" in fruit.lower():
        contains_berry += 1
    sleep(.1)
print("{} fruit names contain 'berry' or 'berries'".format(contains_berry))
```

通过指定关键字参数，可以轻松地扩展默认配置以超出进度条。进度条对象也可以在循环开始之前创建，并使用列表对象`fruits`作为可迭代参数。以下代码展示了如何使用列表、描述和提供单位名称定义我们的进度条。

如果我们不是使用列表，而是使用另一种迭代器类型，该类型没有定义`__len__`属性，我们将需要手动使用`total`关键字提供总数。如果迭代的总数不可用，将仅显示有关经过的时间和每秒迭代次数的基本统计信息。

一旦我们进入循环，我们可以使用`set_postfix()`方法显示发现的结果数量。每次迭代都会在进度条右侧提供我们找到的命中数量的更新：

```py
contains_berry = 0
pbar = tqdm.tqdm(fruits, desc="Reviewing names", unit="fruits")
for fruit in pbar:
    if "berr" in fruit.lower():
        contains_berry += 1
    pbar.set_postfix(hits=contains_berry)
    sleep(.1)
print("{} fruit names contain 'berry' or 'berries'".format(contains_berry))
```

进度条的另一个常见用途是在一系列整数中测量执行。由于这是该库的常见用法，开发人员在库中构建了一个称为`trange()`的范围调用。请注意，我们可以在这里指定与之前相同的参数。由于数字较大，我们将在此处使用一个新参数`unit_scale`，它将大数字简化为一个带有字母表示数量的小数字：

```py
for i in tqdm.trange(10000000, unit_scale=True, desc="Trange: "):
    pass
```

当我们执行代码时，将显示以下输出。我们的第一个进度条显示默认格式，而第二个和第三个显示了我们添加的自定义内容：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00012.jpeg)

# 还有更多…

这个脚本可以进一步改进。以下是一个建议：

+   进一步探索`tqdm`库为开发人员提供的功能。考虑使用`tqdm.write()`方法在不中断进度条的情况下打印状态消息。

# 记录结果

食谱难度：简单

Python 版本：2.7 或 3.5

操作系统：任何

进度条之外，我们通常需要向用户提供消息，描述执行过程中发生的任何异常、错误、警告或其他信息。通过日志记录，我们可以在执行过程中提供这些信息，并在文本文件中供将来参考。

# 入门

此脚本中使用的所有库都包含在 Python 的标准库中。本食谱将使用内置的`logging`库向控制台和文本文件生成状态消息。

要了解更多关于`logging`库的信息，请访问[`docs.python.org/3/library/logging.html`](https://docs.python.org/3/library/logging.html)。

# 如何做…

以下步骤可用于有效记录程序执行数据：

1.  创建日志格式化字符串。

1.  在脚本执行期间记录各种消息类型。

# 工作原理…

现在让我们学习记录结果。在导入之后，我们通过使用`__file__`属性表示的脚本名称初始化一个实例来创建我们的`logger`对象。通过初始化`logging`对象，我们将为此脚本设置级别并指定各种格式化程序和处理程序。格式化程序提供了灵活性，可以定义每条消息显示哪些字段，包括时间戳、函数名称和消息级别。格式化字符串遵循 Python 字符串格式化的标准，这意味着我们可以为以下字符串指定填充：

```py
from __future__ import print_function
import logging
import sys

logger = logging.getLogger(__file__)
logger.setLevel(logging.DEBUG)

msg_fmt = logging.Formatter("%(asctime)-15s %(funcName)-20s"
                            "%(levelname)-8s %(message)s")
```

处理程序允许我们指定日志消息应记录在哪里，包括日志文件、标准输出（控制台）或标准错误。在下面的示例中，我们使用标准输出作为我们的流处理程序，并使用脚本名称加上`.log`扩展名作为文件处理程序。最后，我们将这些处理程序注册到我们的记录器对象中：

```py
strhndl = logging.StreamHandler(sys.stdout)
strhndl.setFormatter(fmt=msg_fmt)

fhndl = logging.FileHandler(__file__ + ".log", mode='a')
fhndl.setFormatter(fmt=msg_fmt)

logger.addHandler(strhndl)
logger.addHandler(fhndl)
```

日志库默认使用以下级别，按严重性递增：`NOTSET`、`DEBUG`、`INFORMATION`、`WARNING`、`ERROR`和`CRITICAL`。为了展示格式字符串的一些特性，我们将从函数中记录几种类型的消息：

```py
logger.info("information message")
logger.debug("debug message")

def function_one():
    logger.warning("warning message")

def function_two():
    logger.error("error message")

function_one()
function_two()
```

当我们执行此代码时，我们可以看到从脚本调用中获得的以下消息信息。检查生成的日志文件与在控制台中记录的内容相匹配：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00013.jpeg)

# 还有更多...

这个脚本可以进一步改进。这是一个建议：

+   在脚本出现错误或用户验证过程时，提供尽可能多的信息通常很重要。因此，我们建议实施额外的格式化程序和日志级别。使用`stderr`流是记录的最佳实践，因为我们可以在控制台上提供输出，而不会中断`stdout`。

# 多人成群，事情好办

食谱难度：中等

Python 版本：2.7 或 3.5

操作系统：任何

虽然 Python 以单线程闻名，但我们可以使用内置库来启动新进程来处理任务。通常，当有一系列可以同时运行的任务并且处理尚未受到硬件限制时，这是首选，例如网络带宽或磁盘速度。

# 入门

此脚本中使用的所有库都包含在 Python 的标准库中。使用内置的`multiprocessing`库，我们可以处理大多数需要多个进程有效地解决问题的情况。

要了解有关`multiprocessing`库的更多信息，请访问[`docs.python.org/3/library/multiprocessing.html`](https://docs.python.org/3/library/multiprocessing.html)。

# 如何做...

通过以下步骤，我们展示了 Python 中的基本多进程支持：

1.  设置日志以记录`multiprocessing`活动。

1.  使用`multiprocessing`将数据附加到列表。

# 它是如何工作的...

现在让我们看看如何在 Python 中实现多进程。我们导入了`multiprocessing`库，缩写为`mp`，因为它太长了；`logging`和`sys`库用于线程状态消息；`time`库用于减慢我们示例的执行速度；`randint`方法用于生成每个线程应等待的时间：

```py
from __future__ import print_function
import logging
import multiprocessing as mp
from random import randint
import sys
import time
```

在创建进程之前，我们设置一个函数，它们将执行。这是我们在返回主线程之前应该执行的每个进程的任务。在这种情况下，我们将线程睡眠的秒数作为唯一参数。为了打印允许我们区分进程的状态消息，我们使用`current_process()`方法访问每个线程的名称属性：

```py
def sleepy(seconds):
    proc_name = mp.current_process().name
    logger.info("{} is sleeping for {} seconds.".format(
        proc_name, seconds))
    time.sleep(seconds)
```

定义了我们的工作函数后，我们创建了我们的`logger`实例，从上一个食谱中借用代码，并将其设置为仅记录到控制台。

```py
logger = logging.getLogger(__file__)
logger.setLevel(logging.DEBUG)
msg_fmt = logging.Formatter("%(asctime)-15s %(funcName)-7s "
                            "%(levelname)-8s %(message)s")
strhndl = logging.StreamHandler(sys.stdout)
strhndl.setFormatter(fmt=msg_fmt)
logger.addHandler(strhndl)
```

现在我们定义要生成的工作人员数量，并在 for 循环中创建它们。使用这种技术，我们可以轻松调整正在运行的进程数量。在我们的循环内，我们使用`Process`类定义每个`worker`，并设置我们的目标函数和所需的参数。一旦定义了进程实例，我们就启动它并将对象附加到列表以供以后使用：

```py
num_workers = 5
workers = []
for w in range(num_workers):
    p = mp.Process(target=sleepy, args=(randint(1, 20),))
    p.start()
    workers.append(p)
```

通过将`workers`附加到列表中，我们可以按顺序加入它们。在这种情况下，加入是指在执行继续之前等待进程完成的过程。如果我们不加入我们的进程，其中一个进程可能会在脚本的末尾继续并在其他进程完成之前完成代码。虽然这在我们的示例中不会造成很大问题，但它可能会导致下一段代码过早开始：

```py
for worker in workers:
    worker.join()
    logger.info("Joined process {}".format(worker.name))
```

当我们执行脚本时，我们可以看到进程随着时间的推移开始和加入。由于我们将这些项目存储在列表中，它们将以有序的方式加入，而不管一个工作人员完成需要多长时间。这在下面可见，因为`Process-5`在完成之前睡了 14 秒，与此同时，`Process-4`和`Process-3`已经完成：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00014.jpeg)

# 还有更多...

这个脚本可以进一步改进。我们在这里提供了一个建议：

+   与使用函数参数在线程之间传递数据不同，可以考虑使用管道和队列作为共享数据的替代方法。关于这些对象的更多信息可以在[`docs.python.org/3/library/multiprocessing.html#exchanging-objects-between-processes`](https://docs.python.org/3/library/multiprocessing.html#exchanging-objects-between-processes.)找到。[﻿](https://docs.python.org/3/library/multiprocessing.html#exchanging-objects-between-processes.)


# 第二章：创建物件报告配方

在本章中，我们将涵盖以下配方：

+   使用 HTML 模板

+   创建一份纸质追踪

+   使用 CSV

+   使用 Excel 可视化事件

+   审计您的工作

# 介绍

在您开始从事网络安全职业的前几个小时内，您可能已经弯腰在屏幕前，疯狂地扫描电子表格以寻找线索。这听起来很熟悉，因为这是真实的，也是大多数调查的日常流程的一部分。电子表格是网络安全的基础。其中包含了各种流程的细节以及从有价值的物件中提取的具体信息。在这本食谱书中，我们经常会将解析后的物件数据输出到电子表格中，因为它便携且易于使用。然而，考虑到每个网络安全专业人员都曾经为非技术人员创建过技术报告，电子表格可能不是最佳选择。

为什么要创建报告？我想我以前听到过紧张的审查员喃喃自语。今天，一切都建立在信息交换之上，人们希望尽快了解事情。但这并不一定意味着他们希望得到一个技术电子表格并自己弄清楚。审查员必须能够有效地将技术知识传达给非专业观众，以便正确地完成他们的工作。即使一个物件可能非常好，即使它是某个案例的象征性证据，它很可能需要向非技术人员进行详细解释，以便他们完全理解其含义和影响。放弃吧；报告会一直存在，对此无能为力。

在本章中，您将学习如何创建多种不同类型的报告以及一个用于自动审计我们调查的脚本。我们将创建 HTML、XLSX 和 CSV 报告，以便以有意义的方式总结数据：

+   开发 HTML 仪表板模板

+   解析 FTK Imager 获取日志

+   构建强大的 CSV 写入器

+   使用 Microsoft Excel 绘制图表和数据

+   在调查过程中创建截图的审计跟踪

访问[www.packtpub.com/books/content/support](http://www.packtpub.com/books/content/support)下载本章的代码捆绑包。

# 使用 HTML 模板

配方难度：简单

Python 版本：2.7 或 3.5

操作系统：任意

HTML 可以是一份有效的报告。有很多时髦的模板可以使即使是技术报告看起来也很吸引人。这是吸引观众的第一步。或者至少是一种预防措施，防止观众立刻打瞌睡。这个配方使用了这样一个模板和一些测试数据，以创建一个视觉上引人注目的获取细节的例子。我们在这里确实有很多工作要做。

# 入门

这个配方介绍了使用`jinja2`模块的 HTML 模板化。`jinja2`库是一个非常强大的工具，具有许多不同的文档化功能。我们将在一个相当简单的场景中使用它。此脚本中使用的所有其他库都包含在 Python 的标准库中。我们可以使用 pip 来安装`jinja2`：

```py
pip install jinja2==2.9.6
```

除了`jinja2`之外，我们还将使用一个稍微修改过的模板，称为轻量级引导式仪表板。这个稍微修改过的仪表板已经随配方的代码捆绑提供了。

要了解更多关于`jinja2`库的信息，请访问[`jinja.pocoo.org/docs/2.9/`](http://jinja.pocoo.org/docs/2.9/)。

要下载轻量级引导式仪表板，请访问[`www.creative-tim.com/product/light-bootstrap-dashboard`](https://www.creative-tim.com/product/light-bootstrap-dashboard)。

# 如何做...

我们遵循以下原则部署 HTML 仪表板：

1.  设计 HTML 模板全局变量。

1.  处理测试获取元数据。

1.  使用插入的获取元数据呈现 HTML 模板。

1.  在所需的输出目录中创建报告。

# 它是如何工作的...

首先，我们导入所需的库来处理参数解析、创建对象计数和复制文件：

```py
from __future__ import print_function
import argparse
from collections import Counter
import shutil
import os
import sys
```

这个配方的命令行处理程序接受一个位置参数 `OUTPUT_DIR`，它表示 HTML 仪表板的期望输出路径。在检查目录是否存在并在不存在时创建它之后，我们调用 `main()` 函数并将输出目录传递给它：

```py
if __name__ == "__main__":
    # Command-line Argument Parser
    parser = argparse.ArgumentParser(
        description=__description__,
        epilog="Developed by {} on {}".format(
            ", ".join(__authors__), __date__)
    )
    parser.add_argument("OUTPUT_DIR", help="Desired Output Path")
    args = parser.parse_args()

    main(args.OUTPUT_DIR)
```

在脚本顶部定义了一些全局变量：`DASH`、`TABLE` 和 `DEMO`。这些变量代表脚本生成的各种 HTML 和 JavaScript 文件。这是一本关于 Python 的书，所以我们不会深入讨论这些文件的结构和工作原理。不过，让我们看一个示例，展示 `jinja2` 如何弥合这些类型文件和 Python 之间的差距。

以下代码片段捕获了全局变量 `DEMO` 的一部分。请注意，字符串块被传递给 `jinja2.Template()` 方法。这使我们能够创建一个对象，可以使用 `jinja2` 与之交互并动态插入数据到 JavaScript 文件中。具体来说，以下代码块显示了两个我们可以使用 `jinja2` 插入数据的位置。这些位置由双大括号和我们在 Python 代码中将引用它们的关键字（`pi_labels` 和 `pi_series`）表示：

```py
DEMO = Template("""type = ['','info','success','warning','danger']; 
[snip] 
        Chartist.Pie('#chartPreferences', dataPreferences,
          optionsPreferences);

        Chartist.Pie('#chartPreferences', {
          labels: [{{pi_labels}}],
          series: [{{pi_series}}]
        });
[snip] 
""") 
```

现在让我们转向 `main()` 函数。由于您将在第二个配方中理解的原因，这个函数实际上非常简单。这个函数创建一个包含示例获取数据的列表列表，向控制台打印状态消息，并将该数据发送到 `process_data()` 方法：

```py
def main(output_dir):
    acquisition_data = [
        ["001", "Debbie Downer", "Mobile", "08/05/2017 13:05:21", "32"],
        ["002", "Debbie Downer", "Mobile", "08/05/2017 13:11:24", "16"],
        ["003", "Debbie Downer", "External", "08/05/2017 13:34:16", "128"],
        ["004", "Debbie Downer", "Computer", "08/05/2017 14:23:43", "320"],
        ["005", "Debbie Downer", "Mobile", "08/05/2017 15:35:01", "16"],
        ["006", "Debbie Downer", "External", "08/05/2017 15:54:54", "8"],
        ["007", "Even Steven", "Computer", "08/07/2017 10:11:32", "256"],
        ["008", "Even Steven", "Mobile", "08/07/2017 10:40:32", "32"],
        ["009", "Debbie Downer", "External", "08/10/2017 12:03:42", "64"],
        ["010", "Debbie Downer", "External", "08/10/2017 12:43:27", "64"]
    ]
    print("[+] Processing acquisition data")
    process_data(acquisition_data, output_dir)
```

`process_data()` 方法的目的是将示例获取数据转换为 HTML 或 JavaScript 格式，以便我们可以将其放置在 `jinja2` 模板中。这个仪表板将有两个组件：可视化数据的一系列图表和原始数据的表格。以下代码块处理了后者。我们通过遍历获取列表并使用适当的 HTML 标记将表的每个元素添加到 `html_table` 字符串中来实现这一点：

```py
def process_data(data, output_dir):
    html_table = ""
    for acq in data:
        html_table += "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td>" \
            "<td>{}</td></tr>\n".format(
                acq[0], acq[1], acq[2], acq[3], acq[4])
```

接下来，我们使用 `collections` 库中的 `Counter()` 方法快速生成一个类似字典的对象，表示样本数据中每个项目的出现次数。例如，第一个 `Counter` 对象 `device_types` 创建了一个类似字典的对象，其中每个键都是不同的设备类型（例如，移动设备、外部设备和计算机），值表示每个键的出现次数。这使我们能够快速总结数据集中的数据，并减少了在绘制此信息之前所需的工作量。

一旦我们创建了 `Counter` 对象，我们再次遍历每个获取以执行更多手动的获取日期信息的总结。这个 `date_dict` 对象维护了所有获取数据的键，并将在该天进行的所有获取的大小添加为键的值。我们特别在空格上拆分，以仅从日期时间字符串中隔离出日期值（例如，`08/15/2017`）。如果特定日期已经在字典中，我们直接将获取大小添加到键中。否则，我们创建键并将其值分配给获取大小。一旦我们创建了各种总结对象，我们调用 `output_html()` 方法来用这些信息填充 HTML 仪表板：

```py
    device_types = Counter([x[2] for x in data])
    custodian_devices = Counter([x[1] for x in data])

    date_dict = {}
    for acq in data:
        date = acq[3].split(" ")[0]
        if date in date_dict:
            date_dict[date] += int(acq[4])
        else:
            date_dict[date] = int(acq[4])
    output_html(output_dir, len(data), html_table,
                device_types, custodian_devices, date_dict)
```

`output_html()` 方法首先通过在控制台打印状态消息并将当前工作目录存储到变量中来开始。我们将文件夹路径附加到 light-bootstrap-dashboard，并使用 `shutil.copytree()` 将 bootstrap 文件复制到输出目录。随后，我们创建三个文件路径，表示三个 `jinja2` 模板的输出位置和名称：

```py
def output_html(output, num_devices, table, devices, custodians, dates):
    print("[+] Rendering HTML and copy files to {}".format(output))
    cwd = os.getcwd()
    bootstrap = os.path.join(cwd, "light-bootstrap-dashboard")
    shutil.copytree(bootstrap, output)

    dashboard_output = os.path.join(output, "dashboard.html")
    table_output = os.path.join(output, "table.html")
    demo_output = os.path.join(output, "assets", "js", "demo.js")
```

让我们先看看两个 HTML 文件，因为它们相对简单。在为两个 HTML 文件打开文件对象之后，我们使用`jinja2.render()`方法，并使用关键字参数来引用`Template`对象中花括号中的占位符。使用 Python 数据呈现文件后，我们将数据写入文件。简单吧？幸运的是，JavaScript 文件并不难：

```py
    with open(dashboard_output, "w") as outfile:
        outfile.write(DASH.render(num_custodians=len(custodians.keys()),
                                  num_devices=num_devices,
                                  data=calculate_size(dates)))

    with open(table_output, "w") as outfile:
        outfile.write(TABLE.render(table_body=table))
```

虽然在语法上与前一个代码块相似，但这次在呈现数据时，我们将数据提供给`return_labels()`和`return_series()`方法。这些方法从`Counter`对象中获取键和值，并适当地格式化以与 JavaScript 文件一起使用。您可能还注意到在前一个代码块中对`dates`字典调用了`calculate_size()`方法。现在让我们来探讨这三个支持函数：

```py
    with open(demo_output, "w") as outfile:
        outfile.write(
            DEMO.render(bar_labels=return_labels(dates.keys()),
                        bar_series=return_series(dates.values()),
                        pi_labels=return_labels(devices.keys()),
                        pi_series=return_series(devices.values()),
                        pi_2_labels=return_labels(custodians.keys()),
                        pi_2_series=return_series(custodians.values())))
```

`calculate_size()`方法简单地使用内置的`sum()`方法返回每个日期键收集的总大小。`return_labels()`和`return_series()`方法使用字符串方法适当地格式化数据。基本上，JavaScript 文件期望标签在单引号内，这是通过`format()`方法实现的，标签和系列都必须用逗号分隔：

```py
def calculate_size(sizes):
    return sum(sizes.values())

def return_labels(list_object):
    return ", ".join("'{}'".format(x) for x in list_object)

def return_series(list_object):
    return ", ".join(str(x) for x in list_object)
```

当我们运行这个脚本时，我们会收到报告的副本，以及加载和呈现页面所需的资产，放在指定的输出目录中。我们可以将这个文件夹压缩并提供给团队成员，因为它被设计为可移植的。查看这个仪表板，我们可以看到包含图表信息的第一页：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00015.jpeg)

以及作为采集信息表的第二页：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00016.jpeg)

# 还有更多…

这个脚本可以进一步改进。我们在这里提供了一些建议：

+   添加对其他类型报告的支持，以更好地突出显示数据

+   包括通过额外的 javascript 导出表格和图表以进行打印和分享的能力

# 创建一份纸质记录

菜谱难度：中等

Python 版本：2.7 或 3.5

操作系统：任何

大多数成像工具都会创建记录采集介质细节和其他可用元数据的审计日志。承认吧；除非出现严重问题，否则这些日志大多不会被触及，如果证据验证了。让我们改变这种情况，利用前一个菜谱中新创建的 HTML 仪表板，并更好地利用这些采集数据。

# 入门

此脚本中使用的所有库都存在于 Python 的标准库中，或者是从之前的脚本中导入的函数。

# 如何做…

我们通过以下步骤解析采集日志：

1.  识别和验证 FTK 日志。

1.  解析日志以提取相关字段。

1.  创建一个包含采集数据的仪表板。

# 它是如何工作的…

首先，我们导入所需的库来处理参数解析、解析日期和我们在上一个菜谱中创建的`html_dashboard`脚本：

```py
from __future__ import print_function
import argparse
from datetime import datetime
import os
import sys
import html_dashboard
```

这个菜谱的命令行处理程序接受两个位置参数，`INPUT_DIR`和`OUTPUT_DIR`，分别代表包含采集日志的目录路径和期望的输出路径。在创建输出目录（如果需要）并验证输入目录存在后，我们调用`main()`方法并将这两个变量传递给它：

```py
if __name__ == "__main__":
    # Command-line Argument Parser
    parser = argparse.ArgumentParser(
        description=__description__,
        epilog="Developed by {} on {}".format(
            ", ".join(__authors__), __date__)
    )
    parser.add_argument("INPUT_DIR", help="Input Directory of Logs")
    parser.add_argument("OUTPUT_DIR", help="Desired Output Path")
    args = parser.parse_args()

    if os.path.exists(args.INPUT_DIR) and os.path.isdir(args.INPUT_DIR):
        main(args.INPUT_DIR, args.OUTPUT_DIR)
    else:
        print("[-] Supplied input directory {} does not exist or is not "
              "a file".format(args.INPUT_DIR))
        sys.exit(1)
```

在`main()`函数中，我们使用`os.listdir()`函数获取输入目录的目录列表，并仅识别具有`.txt`文件扩展名的文件。这很重要，因为 FTK Imager 创建带有`.txt`扩展名的获取日志。这有助于我们仅通过扩展名避免处理一些不应该处理的文件。然而，我们将进一步进行。在创建可能的 FTK 日志列表后，我们创建一个占位符列表`ftk_data`，用于存储处理过的获取数据。接下来，我们遍历每个潜在的日志，并设置一个具有所需键的字典来提取。为了进一步排除误报，我们调用`validate_ftk()`方法，该方法根据其检查结果返回`True`或`False`布尔值。让我们快速看一下它是如何工作的：

```py
def main(in_dir, out_dir):
    ftk_logs = [x for x in os.listdir(in_dir)
                if x.lower().endswith(".txt")]
    print("[+] Processing {} potential FTK Imager Logs found in {} "
          "directory".format(len(ftk_logs), in_dir))
    ftk_data = []
    for log in ftk_logs:
        log_data = {"e_numb": "", "custodian": "", "type": "",
                    "date": "", "size": ""}
        log_name = os.path.join(in_dir, log)
        if validate_ftk(log_name):
```

值得庆幸的是，每个 FTK Imager 日志的第一行都包含`"Created by AccessData"`这几个词。我们可以依靠这一点来验证该日志很可能是有效的 FTK Imager 日志。使用输入的`log_file`路径，我们打开文件对象并使用`readline()`方法读取第一行。提取第一行后，我们检查短语是否存在，如果存在则返回`True`，否则返回`False`：

```py
def validate_ftk(log_file):
    with open(log_file) as log:
        first_line = log.readline()
        if "Created By AccessData" not in first_line:
            return False
        else:
            return True
```

回到`main()`方法，在验证了 FTK Imager 日志之后，我们打开文件，将一些变量设置为`None`，并开始迭代文件中的每一行。基于这些日志的可靠布局，我们可以使用特定关键字来识别当前行是否是我们感兴趣的行。例如，如果该行包含短语`"Evidence Number:"`，我们可以确定该行包含证据编号值。实际上，我们分割短语并取冒号右侧的值，并将其与字典`e_numb`键关联。这种逻辑可以应用于大多数所需的值，但也有一些例外。

对于获取时间，我们必须使用`datetime.strptime()`方法将字符串转换为实际的`datetime`对象。我们必须这样做才能以 HTML 仪表板期望的格式存储它。我们在字典中使用`datetime`对象的`strftime()`方法并将其与`date`键关联：

```py
            with open(log_name) as log_file:
                bps, sec_count = (None, None)
                for line in log_file:
                    if "Evidence Number:" in line:
                        log_data["e_numb"] = line.split(
                            "Number:")[1].strip()
                    elif "Notes:" in line:
                        log_data["custodian"] = line.split(
                            "Notes:")[1].strip()
                    elif "Image Type:" in line:
                        log_data["type"] = line.split("Type:")[1].strip()
                    elif "Acquisition started:" in line:
                        acq = line.split("started:")[1].strip()
                        date = datetime.strptime(
                            acq, "%a %b %d %H:%M:%S %Y")
                        log_data["date"] = date.strftime(
                            "%M/%d/%Y %H:%M:%S")
```

每个扇区的字节数和扇区计数与其他部分处理方式略有不同。由于 HTML 仪表板脚本期望接收数据大小（以 GB 为单位），我们需要提取这些值并计算获取的媒体大小。一旦识别出来，我们将每个值转换为整数，并将其分配给最初为`None`的两个局部变量。在完成对所有行的迭代后，我们检查这些变量是否不再是`None`，如果不是，则将它们发送到`calculate_size()`方法。该方法执行必要的计算并将媒体大小存储在字典中：

```py
def calculate_size(bytes, sectors):
    return (bytes * sectors) / (1024**3)
```

处理完文件后，提取的获取数据的字典将附加到`ftk_data`列表中。在处理完所有日志后，我们调用`html_dashboard.process_data()`方法，并向其提供获取数据和输出目录。`process_data()`函数当然与上一个示例中的完全相同。因此，您知道这些获取数据将替换上一个示例中的示例获取数据，并用真实数据填充 HTML 仪表板：

```py
                    elif "Bytes per Sector:" in line:
                        bps = int(line.split("Sector:")[1].strip())
                    elif "Sector Count:" in line:
                        sec_count = int(
                            line.split("Count:")[1].strip().replace(
                                ",", "")
                        )
                if bps is not None and sec_count is not None:
                    log_data["size"] = calculate_size(bps, sec_count)

            ftk_data.append(
                [log_data["e_numb"], log_data["custodian"],
                 log_data["type"], log_data["date"], log_data["size"]]
            )

    print("[+] Creating HTML dashboard based acquisition logs "
          "in {}".format(out_dir))
    html_dashboard.process_data(ftk_data, out_dir)
```

当我们运行这个工具时，我们可以看到获取日志信息，如下两个截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00017.jpeg)![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00018.jpeg)

# 还有更多...

这个脚本可以进一步改进。以下是一个建议：

+   创建额外的脚本以支持来自其他获取工具的日志，例如**Guymager**，**Cellebrite**，**MacQuisition**等等

# 处理 CSV 文件

食谱难度：简单

Python 版本：2.7 或 3.5

操作系统：任意

每个人都曾经在 CSV 电子表格中查看过数据。它们是无处不在的，也是大多数应用程序的常见输出格式。使用 Python 编写 CSV 是创建处理数据报告的最简单方法之一。在这个配方中，我们将演示如何使用`csv`和`unicodecsv`库来快速创建 Python 报告。

# 入门

这个配方的一部分使用了`unicodecsv`模块。该模块替换了内置的 Python 2 `csv`模块，并添加了 Unicode 支持。Python 3 的`csv`模块没有这个限制，可以在不需要任何额外库支持的情况下使用。此脚本中使用的所有其他库都包含在 Python 的标准库中。`unicodecsv`库可以使用`pip`安装：

```py
pip install unicodecsv==0.14.1
```

要了解更多关于`unicodecsv`库的信息，请访问[`github.com/jdunck/python-unicodecsv`](https://github.com/jdunck/python-unicodecsv)。

# 如何做...

我们按照以下步骤创建 CSV 电子表格：

1.  识别调用脚本的 Python 版本。

1.  使用 Python 2 和 Python 3 的约定在当前工作目录的电子表格中输出一个列表和一个字典列表。

# 它是如何工作的...

首先，我们导入所需的库来写入电子表格。在这个配方的后面，我们还导入了`unicodecsv`模块：

```py
from __future__ import print_function
import csv
import os
import sys
```

这个配方不使用`argparse`作为命令行处理程序。相反，我们根据 Python 的版本直接调用所需的函数。我们可以使用`sys.version_info`属性确定正在运行的 Python 版本。如果用户使用的是 Python 2.X，我们调用`csv_writer_py2()`和`unicode_csv_dict_writer_py2()`方法。这两种方法都接受四个参数，最后一个参数是可选的：要写入的数据、标题列表、所需的输出目录，以及可选的输出 CSV 电子表格的名称。或者，如果使用的是 Python 3.X，我们调用`csv_writer_py3()`方法。虽然相似，但在两个版本的 Python 之间处理 CSV 写入的方式有所不同，而`unicodecsv`模块仅适用于 Python 2：

```py
if sys.version_info < (3, 0):
    csv_writer_py2(TEST_DATA_LIST, ["Name", "Age", "Cool Factor"],
                   os.getcwd())
    unicode_csv_dict_writer_py2(
        TEST_DATA_DICT, ["Name", "Age", "Cool Factor"], os.getcwd(),
        "dict_output.csv")

elif sys.version_info >= (3, 0):
    csv_writer_py3(TEST_DATA_LIST, ["Name", "Age", "Cool Factor"],
                   os.getcwd())
```

这个配方有两个表示样本数据类型的全局变量。其中第一个`TEST_DATA_LIST`是一个嵌套列表结构，包含字符串和整数。第二个`TEST_DATA_DICT`是这些数据的另一种表示，但存储为字典列表。让我们看看各种函数如何将这些样本数据写入输出 CSV 文件：

```py
TEST_DATA_LIST = [["Bill", 53, 0], ["Alice", 42, 5],
                  ["Zane", 33, -1], ["Theodore", 72, 9001]]

TEST_DATA_DICT = [{"Name": "Bill", "Age": 53, "Cool Factor": 0},
                  {"Name": "Alice", "Age": 42, "Cool Factor": 5},
                  {"Name": "Zane", "Age": 33, "Cool Factor": -1},
                  {"Name": "Theodore", "Age": 72, "Cool Factor": 9001}]
```

`csv_writer_py2()`方法首先检查输入的名称是否已提供。如果仍然是默认值`None`，我们就自己分配输出名称。接下来，在控制台打印状态消息后，我们在所需的输出目录中以`"wb"`模式打开一个`File`对象。请注意，在 Python 2 中重要的是以`"wb"`模式打开 CSV 文件，以防止在生成的电子表格中的行之间出现干扰间隙。一旦我们有了`File`对象，我们使用`csv.writer()`方法将其转换为`writer`对象。有了这个，我们可以使用`writerow()`和`writerows()`方法分别写入单个数据列表和嵌套列表结构。现在，让我们看看`unicodecsv`如何处理字典列表：

```py
def csv_writer_py2(data, header, output_directory, name=None):
    if name is None:
        name = "output.csv"

    print("[+] Writing {} to {}".format(name, output_directory))

    with open(os.path.join(output_directory, name), "wb") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(header)

        writer.writerows(data)
```

`unicodecsv`模块是内置`csv`模块的替代品，可以互换使用。不同之处在于，`unicodecsv`自动处理 Unicode 字符串的方式与 Python 2 中的内置`csv`模块不同。这在 Python 3 中得到了解决。

首先，我们尝试导入`unicodecsv`模块，并在退出脚本之前，如果导入失败，则在控制台打印状态消息。如果我们能够导入库，我们检查是否提供了名称输入，并在打开`File`对象之前创建一个名称。使用这个`File`对象，我们使用`unicodecsv.DictWriter`类，并提供它的标题列表。默认情况下，该对象期望提供的`fieldnames`列表中的键表示每个字典中的所有键。如果不需要这种行为，或者如果不是这种情况，可以通过将 extrasaction 关键字参数设置为字符串`ignore`来忽略它。这样做将导致所有未在`fieldnames`列表中指定的附加字典键被忽略，并且不会添加到 CSV 电子表格中。

设置`DictWriter`对象后，我们使用`writerheader()`方法写入字段名称，然后使用`writerows()`方法，这次将字典列表写入 CSV 文件。另一个重要的事情要注意的是，列将按照提供的`fieldnames`列表中元素的顺序排列：

```py
def unicode_csv_dict_writer_py2(data, header, output_directory, name=None):
    try:
        import unicodecsv
    except ImportError:
        print("[+] Install unicodecsv module before executing this"
              " function")
        sys.exit(1)

    if name is None:
        name = "output.csv"

    print("[+] Writing {} to {}".format(name, output_directory))
    with open(os.path.join(output_directory, name), "wb") as csvfile:
        writer = unicodecsv.DictWriter(csvfile, fieldnames=header)
        writer.writeheader()

        writer.writerows(data)
```

最后，`csv_writer_py3()`方法的操作方式基本相同。但是，请注意`File`对象创建方式的不同。与在 Python 3 中以`"wb"`模式打开文件不同，我们以`"w"`模式打开文件，并将 newline 关键字参数设置为空字符串。在这样做之后，其余的操作与之前描述的方式相同：

```py
def csv_writer_py3(data, header, output_directory, name=None):
    if name is None:
        name = "output.csv"

    print("[+] Writing {} to {}".format(name, output_directory))

    with open(os.path.join(output_directory, name), "w", newline="") as \
            csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(header)

        writer.writerows(data)
```

当我们运行这段代码时，我们可以查看两个新生成的 CSV 文件中的任何一个，并看到与以下截图中相同的信息：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00019.jpeg)

# 还有更多...

这个脚本可以进一步改进。以下是一个建议：

+   使用更健壮的 CSV 写入器和附加功能集和选项。这里的想法是，您可以提供不同类型的数据，并有一个处理它们的方法。

# 使用 Excel 可视化事件

配方难度：简单

Python 版本：2.7 或 3.5

操作系统：任何

让我们从上一个配方进一步进行 Excel。Excel 是一个非常强大的电子表格应用程序，我们可以做很多事情。我们将使用 Excel 创建一个表格，并绘制数据的图表。

# 入门

有许多不同的 Python 库，对 Excel 及其许多功能的支持各不相同。在这个配方中，我们使用`xlsxwriter`模块来创建数据的表格和图表。这个模块可以用于更多的用途。可以使用以下命令通过`pip`安装这个模块：

```py
pip install xlsxwriter==0.9.9
```

要了解更多关于`xlsxwriter`库的信息，请访问[`xlsxwriter.readthedocs.io/`](https://xlsxwriter.readthedocs.io/)。

我们还使用了一个基于上一个配方编写的自定义`utilcsv`模块来处理与 CSV 的交互。此脚本中使用的所有其他库都包含在 Python 的标准库中。

# 如何做...

我们通过以下步骤创建 Excel 电子表格：

1.  创建工作簿和工作表对象。

1.  创建电子表格数据的表格。

1.  创建事件日志数据的图表。

# 它是如何工作的...

首先，我们导入所需的库来处理参数解析、创建对象计数、解析日期、编写 XLSX 电子表格，以及我们的自定义`utilcsv`模块，该模块在这个配方中处理 CSV 的读取和写入：

```py
from __future__ import print_function
import argparse
from collections import Counter
from datetime import datetime
import os
import sys
from utility import utilcsv

try:
    import xlsxwriter
except ImportError:
    print("[-] Install required third-party module xlsxwriter")
    sys.exit(1)
```

这个配方的命令行处理程序接受一个位置参数：`OUTPUT_DIR`。这代表了`XLSX`文件的期望输出路径。在调用`main()`方法之前，我们检查输出目录是否存在，如果不存在则创建它：

```py
if __name__ == "__main__":
    # Command-line Argument Parser
    parser = argparse.ArgumentParser(
        description=__description__,
        epilog="Developed by {} on {}".format(
            ", ".join(__authors__), __date__)
    )
    parser.add_argument("OUTPUT_DIR", help="Desired Output Path")
    args = parser.parse_args()

    if not os.path.exists(args.OUTPUT_DIR):
        os.makedirs(args.OUTPUT_DIR)

    main(args.OUTPUT_DIR)
```

`main()`函数实际上非常简单；它的工作是在控制台打印状态消息，使用`csv_reader()`方法（这是从上一个配方稍微修改的函数），然后使用`xlsx_writer()`方法将结果数据写入输出目录：

```py
def main(output_directory):
    print("[+] Reading in sample data set")
    # Skip first row of headers
    data = utilcsv.csv_reader("redacted_sample_event_log.csv")[1:]
    xlsx_writer(data, output_directory)
```

`xlsx_writer()`从打印状态消息和在输出目录中创建`workbook`对象开始。接下来，我们为仪表板和数据工作表创建了两个`worksheet`对象。仪表板工作表将包含一个总结数据工作表上原始数据的图表：

```py
def xlsx_writer(data, output_directory):
    print("[+] Writing output.xlsx file to {}".format(output_directory))
    workbook = xlsxwriter.Workbook(
        os.path.join(output_directory, "output.xlsx"))
    dashboard = workbook.add_worksheet("Dashboard")
    data_sheet = workbook.add_worksheet("Data")
```

我们在`workbook`对象上使用`add_format()`方法来为电子表格创建自定义格式。这些格式是带有键值对配置格式的字典。根据键名，大多数键都是不言自明的。有关各种格式选项和功能的描述可以在[`xlsxwriter.readthedocs.io/format.html`](http://xlsxwriter.readthedocs.io/format.html)找到：

```py
    title_format = workbook.add_format({
        'bold': True, 'font_color': 'white', 'bg_color': 'black',
        'font_size': 30, 'font_name': 'Calibri', 'align': 'center'
    })
    date_format = workbook.add_format(
        {'num_format': 'mm/dd/yy hh:mm:ss AM/PM'})
```

设置格式后，我们可以枚举列表中的每个列表，并使用`write()`方法写入每个列表。这个方法需要一些输入；第一个和第二个参数是行和列，然后是要写入的值。请注意，除了`write()`方法之外，我们还使用`write_number()`和`write_datetime()`方法。这些方法保留了 XLSX 电子表格中的数据类型。特别是对于`write_datetime()`方法，我们提供了`date_format`变量来适当地格式化日期对象。循环遍历所有数据后，我们成功地将数据存储在电子表格中，并保留了其值类型。但是，我们可以在 XLSX 电子表格中做的远不止这些。

我们使用`add_table()`方法创建刚刚写入的数据的表格。为了实现这一点，我们必须使用 Excel 符号来指示表格的左上角和右下角列。除此之外，我们还可以提供一个对象字典来进一步配置表格。在这种情况下，字典只包含表格每列的标题名称：

```py
    for i, record in enumerate(data):
        data_sheet.write_number(i, 0, int(record[0]))
        data_sheet.write(i, 1, record[1])
        data_sheet.write(i, 2, record[2])
        dt = datetime.strptime(record[3], "%m/%d/%Y %H:%M:%S %p")
        data_sheet.write_datetime(i, 3, dt, date_format)
        data_sheet.write_number(i, 4, int(record[4]))
        data_sheet.write(i, 5, record[5])
        data_sheet.write_number(i, 6, int(record[6]))
        data_sheet.write(i, 7, record[7])

    data_length = len(data) + 1
    data_sheet.add_table(
        "A1:H{}".format(data_length),
        {"columns": [
            {"header": "Index"},
            {"header": "File Name"},
            {"header": "Computer Name"},
            {"header": "Written Date"},
            {"header": "Event Level"},
            {"header": "Event Source"},
            {"header": "Event ID"},
            {"header": "File Path"}
        ]}
    )
```

完成数据工作表后，现在让我们把焦点转向仪表板工作表。我们将在这个仪表板上创建一个图表，按频率分解事件 ID。首先，我们使用`Counter`对象计算这个频率，就像 HTML 仪表板配方中所示的那样。接下来，我们通过合并多列并设置标题文本和格式来为这个页面设置一个标题。

完成后，我们遍历事件 ID 频率`Counter`对象，并将它们写入工作表。我们从第 100 行开始写入，以确保数据不会占据前台。一旦数据写入，我们使用之前讨论过的相同方法将其转换为表格：

```py
    event_ids = Counter([x[6] for x in data])
    dashboard.merge_range('A1:Q1', 'Event Log Dashboard', title_format)
    for i, record in enumerate(event_ids):
        dashboard.write(100 + i, 0, record)
        dashboard.write(100 + i, 1, event_ids[record])

    dashboard.add_table("A100:B{}".format(
        100 + len(event_ids)),
        {"columns": [{"header": "Event ID"}, {"header": "Occurrence"}]}
    )
```

最后，我们可以绘制我们一直在谈论的图表。我们使用`add_chart()`方法，并将类型指定为柱状图。接下来，我们使用`set_title()`和`set_size()`方法来正确配置这个图表。剩下的就是使用`add_series()`方法将数据添加到图表中。这个方法使用一个带有类别和值键的字典。在柱状图中，类别值代表*x*轴，值代表*y*轴。请注意使用 Excel 符号来指定构成类别和值键的单元格范围。选择数据后，我们在`worksheet`对象上使用`insert_chart()`方法来显示它，然后关闭`workbook`对象：

```py
    event_chart = workbook.add_chart({'type': 'bar'})
    event_chart.set_title({'name': 'Event ID Breakdown'})
    event_chart.set_size({'x_scale': 2, 'y_scale': 5})

    event_chart.add_series(
        {'categories': '=Dashboard!$A$101:$A${}'.format(
            100 + len(event_ids)),
         'values': '=Dashboard!$B$101:$B${}'.format(
             100 + len(event_ids))})
    dashboard.insert_chart('C5', event_chart)

    workbook.close()
```

当我们运行这个脚本时，我们可以在 XLSX 电子表格中查看数据和我们创建的总结事件 ID 的图表：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00020.jpeg)

# 审计您的工作

配方难度：简单

Python 版本：2.7 或 3.5

操作系统：任何

保持详细的调查笔记是任何调查的关键。没有这些，很难将所有的线索放在一起或准确地回忆发现。有时，有一张屏幕截图或一系列屏幕截图可以帮助您回忆您在审查过程中所采取的各种步骤。

# 开始吧

为了创建具有跨平台支持的配方，我们选择使用`pyscreenshot`模块。该模块依赖于一些依赖项，特别是**Python Imaging Library**（**PIL**）和一个或多个后端。这里使用的后端是 WX GUI 库。这三个模块都可以使用`pip`安装：

```py
pip install pyscreenshot==0.4.2
pip install Pillow==4.2.1
pip install wxpython==4.0.0b1
```

要了解有关 pyscreenshot 库的更多信息，请访问[`pypi.python.org/pypi/pyscreenshot`](https://pypi.python.org/pypi/pyscreenshot)。

此脚本中使用的所有其他库都包含在 Python 的标准库中。

# 如何做...

我们使用以下方法来实现我们的目标：

1.  处理用户提供的参数。

1.  根据用户提供的输入进行截图。

1.  将截图保存到指定的输出文件夹。

# 它是如何工作的...

首先，我们导入所需的库来处理参数解析、脚本休眠和截图：

```py
from __future__ import print_function 
import argparse 
from multiprocessing import freeze_support 
import os 
import sys 
import time

try: 
    import pyscreenshot 
    import wx 
except ImportError: 
    print("[-] Install wx and pyscreenshot to use this script") 
    sys.exit(1)
```

这个配方的命令行处理程序接受两个位置参数，`OUTPUT_DIR`和`INTERVAL`，分别表示所需的输出路径和截图之间的间隔。可选的`total`参数可用于对应该采取的截图数量设置上限。请注意，我们为`INTERVAL`和`total`参数指定了整数类型。在验证输出目录存在后，我们将这些输入传递给`main()`方法：

```py
if __name__ == "__main__": 
    # Command-line Argument Parser 
    parser = argparse.ArgumentParser( 
        description=__description__, 
        epilog="Developed by {} on {}".format( 
            ", ".join(__authors__), __date__) 
    ) 
    parser.add_argument("OUTPUT_DIR", help="Desired Output Path") 
    parser.add_argument( 
        "INTERVAL", help="Screenshot interval (seconds)", type=int) 
    parser.add_argument( 
        "-total", help="Total number of screenshots to take", type=int) 
    args = parser.parse_args() 

    if not os.path.exists(args.OUTPUT_DIR): 
        os.makedirs(args.OUTPUT_DIR) 

    main(args.OUTPUT_DIR, args.INTERVAL, args.total)
```

`main()`函数创建一个无限的`while`循环，并开始逐个递增一个计数器以获取每个截图。随后，脚本在提供的时间间隔后休眠，然后使用`pyscreenshot.grab()`方法来捕获截图。捕获了截图后，我们创建输出文件名，并使用截图对象的`save()`方法将其保存到输出位置。就是这样。我们打印一个状态消息通知用户，然后检查是否提供了`total`参数以及计数器是否等于它。如果是，退出`while`循环，否则，它将永远继续。作为一种谨慎/智慧的提醒，如果您选择不提供`total`限制，请确保在完成审阅后手动停止脚本。否则，您可能会回到一个不祥的蓝屏和满硬盘：

```py
def main(output_dir, interval, total): 
    i = 0 
    while True: 
        i += 1 
        time.sleep(interval) 
        image = pyscreenshot.grab() 
        output = os.path.join(output_dir, "screenshot_{}.png").format(i) 
        image.save(output) 
        print("[+] Took screenshot {} and saved it to {}".format( 
            i, output_dir)) 
        if total is not None and i == total: 
            print("[+] Finished taking {} screenshots every {} " 
                  "seconds".format(total, interval)) 
            sys.exit(0)
```

随着截图脚本每五秒运行一次，并将图片存储在我们选择的文件夹中，我们可以看到以下输出，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00021.gif)

# 还有更多...

这个脚本可以进一步改进。我们在这里提供了一些建议：

+   为脚本添加视频录制支持

+   添加自动创建带有日期作为存档名称的截图的功能


# 第三章：深入移动取证食谱

本章涵盖以下食谱：

+   解析 PLIST 文件

+   处理 SQLite 数据库

+   识别 SQLite 数据库中的间隙

+   处理 iTunes 备份

+   将 Wi-Fi 标记在地图上

+   深入挖掘以恢复消息

# 介绍

也许这已经成为陈词滥调，但事实仍然如此，随着技术的发展，它继续与我们的生活更加紧密地融合。这从未如此明显，如第一部智能手机的发展。这些宝贵的设备似乎永远不会离开其所有者，并且通常比人类伴侣更多地接触。因此，毫不奇怪，智能手机可以为调查人员提供大量关于其所有者的见解。例如，消息可能提供有关所有者心态或特定事实的见解。它们甚至可能揭示以前未知的信息。位置历史是我们可以从这些设备中提取的另一个有用的证据，可以帮助验证个人的不在场证明。我们将学习提取这些信息以及更多内容。

智能手机上证据价值的常见来源是 SQLite 数据库。这些数据库在大多数智能手机操作系统中作为应用程序的事实存储。因此，本章中的许多脚本将专注于从这些数据库中提取数据并推断。除此之外，我们还将学习如何处理 PLIST 文件，这些文件通常与苹果操作系统一起使用，包括 iOS，并提取相关数据。本章中的脚本专注于解决特定问题，并按复杂性排序：

+   学习处理 XML 和二进制 PLIST 文件

+   使用 Python 与 SQLite 数据库交互

+   识别 SQLite 数据库中的缺失间隙

+   将 iOS 备份转换为人类可读格式

+   处理 Cellebrite 的输出并执行 Wi-Fi MAC 地址地理位置查找

+   从 SQLite 数据库中识别潜在完整的已删除内容

访问[www.packtpub.com/books/content/support](http://www.packtpub.com/books/content/support)下载本章的代码包。

# 解析 PLIST 文件

食谱难度：简单

Python 版本：2.7 或 3.5

操作系统：任何

这个食谱将处理每个 iOS 备份中存在的`Info.plist`文件，并提取设备特定信息，如设备名称、IMEI、序列号、产品制造、型号和 iOS 版本，以及最后备份日期。属性列表，或 PLIST，有两种不同的格式：XML 或二进制。通常，在处理二进制 PLIST 时，需要在 macOS 平台上使用 plutil 实用程序将其转换为可读的 XML 格式。然而，我们将介绍一个处理两种类型的 Python 库，即可轻松处理。一旦我们从`Info.plist`文件中提取相关数据元素，我们将把这些数据打印到控制台上。

# 入门

此食谱需要安装第三方库`biplist`。此脚本中使用的所有其他库都包含在 Python 的标准库中。`biplist`模块提供了处理 XML 和二进制 PLIST 文件的方法。

要了解更多关于`biplist`库的信息，请访问[`github.com/wooster/biplist`](https://github.com/wooster/biplist)。

Python 有一个内置的 PLIST 库，`plistlib`；然而，发现这个库不像`biplist`那样广泛支持二进制 PLIST 文件。

要了解更多关于`plistlib`库的信息，请访问[`docs.python.org/3/library/plistlib.html`](https://docs.python.org/3/library/plistlib.html)。

使用`pip`可以完成安装`biplist`：

```py
pip install biplist==1.0.2
```

确保获取自己的`Info.plist`文件以便使用此脚本进行处理。如果找不到`Info.plist`文件，任何 PLIST 文件都应该合适。我们的脚本并不那么具体，理论上应该适用于任何 PLIST 文件。

# 如何做…

我们将采用以下步骤处理 PLIST 文件：

1.  打开输入的 PLIST 文件。

1.  将 PLIST 数据读入变量。

1.  将格式化的 PLIST 数据打印到控制台。

# 它是如何工作的...

首先，我们导入所需的库来处理参数解析和处理 PLIST 文件：

```py
from __future__ import print_function
import argparse
import biplist
import os
import sys
```

该配方的命令行处理程序接受一个位置参数`PLIST_FILE`，表示我们将处理的 PLIST 文件的路径：

```py
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=__description__,
        epilog="Developed by {} on {}".format(
            ", ".join(__authors__), __date__)
    )
    parser.add_argument("PLIST_FILE", help="Input PList File")
    args = parser.parse_args()
```

我们使用`os.exists()`和`os.path.isfile()`函数来验证输入文件是否存在并且是一个文件，而不是一个目录。我们不对这个文件进行进一步的验证，比如确认它是一个 PLIST 文件而不是一个文本文件，而是依赖于`biplist`库（和常识）来捕捉这样的错误。如果输入文件通过了我们的测试，我们调用`main()`函数并将 PLIST 文件路径传递给它：

```py
    if not os.path.exists(args.PLIST_FILE) or \
            not os.path.isfile(args.PLIST_FILE):
        print("[-] {} does not exist or is not a file".format(
            args.PLIST_FILE))
        sys.exit(1)

    main(args.PLIST_FILE)
```

`main()`函数相对简单，实现了读取 PLIST 文件然后将数据打印到控制台的目标。首先，我们在控制台上打印一个更新，表示我们正在尝试打开文件。然后，我们使用`biplist.readPlist()`方法打开并读取 PLIST 到我们的`plist_data`变量中。如果 PLIST 文件损坏或无法访问，`biplist`会引发`InvalidPlistException`或`NotBinaryPlistException`错误。我们在`try`和`except`块中捕获这两种错误，并相应地`exit`脚本：

```py
def main(plist):
    print("[+] Opening {} file".format(plist))
    try:
        plist_data = biplist.readPlist(plist)
    except (biplist.InvalidPlistException,
            biplist.NotBinaryPlistException) as e:
        print("[-] Invalid PLIST file - unable to be opened by biplist")
        sys.exit(2)
```

一旦我们成功读取了 PLIST 数据，我们遍历结果中的`plist_data`字典中的键，并将它们打印到控制台上。请注意，我们打印`Info.plist`文件中除了`Applications`和`iTunes Files`键之外的所有键。这两个键包含大量数据，会淹没控制台，因此不适合这种类型的输出。我们使用 format 方法来帮助创建可读的控制台输出：

```py
    print("[+] Printing Info.plist Device "
          "and User Information to Console\n")
    for k in plist_data:
        if k != 'Applications' and k != 'iTunes Files':
            print("{:<25s} - {}".format(k, plist_data[k]))
```

请注意第一个花括号中的额外格式化字符。我们在这里指定左对齐输入字符串，并且宽度为 25 个字符。正如你在下面的截图中所看到的，这确保了数据以有序和结构化的格式呈现：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00022.jpeg)

# 还有更多...

这个脚本可以进一步改进。我们在这里提供了一些建议：

+   而不是将数据打印到控制台，添加一个 CSV 函数将数据写入 CSV 文件

+   添加支持处理一个目录中的所有 PLIST 文件

# 处理 SQLite 数据库

配方难度：简单

Python 版本：3.5

操作系统：任何

如前所述，SQLite 数据库是移动设备上的主要数据存储库。Python 有一个内置的`sqlite3`库，可以用来与这些数据库进行交互。在这个脚本中，我们将与 iPhone 的`sms.db`文件交互，并从`message`表中提取数据。我们还将利用这个脚本的机会介绍`csv`库，并将消息数据写入电子表格。

要了解更多关于`sqlite3`库的信息，请访问[`docs.python.org/3/library/sqlite3.html`](https://docs.python.org/3/library/sqlite3.html)。

# 入门

此脚本中使用的所有库都包含在 Python 的标准库中。对于这个脚本，请确保有一个`sms.db`文件可以进行查询。通过一些小的修改，你可以使用这个脚本与任何数据库；然而，我们将特别讨论它与 iOS 10.0.1 设备的 iPhone 短信数据库相关。

# 如何做到...

该配方遵循以下基本原则：

1.  连接到输入数据库。

1.  查询表 PRAGMA 以提取列名。

1.  获取所有表内容。

1.  将所有表内容写入 CSV。

# 它是如何工作的...

首先，我们导入所需的库来处理参数解析、写入电子表格和与 SQLite 数据库交互：

```py
from __future__ import print_function
import argparse
import csv
import os
import sqlite3
import sys
```

该配方的命令行处理程序接受两个位置参数`SQLITE_DATABASE`和`OUTPUT_CSV`，分别表示输入数据库和期望的 CSV 输出的文件路径：

```py
if __name__ == '__main__':
    # Command-line Argument Parser
    parser = argparse.ArgumentParser(
        description=__description__,
        epilog="Developed by {} on {}".format(
            ", ".join(__authors__), __date__)
    )
    parser.add_argument("SQLITE_DATABASE", help="Input SQLite database")
    parser.add_argument("OUTPUT_CSV", help="Output CSV File")
    args = parser.parse_args()
```

接下来，我们使用`os.dirname()`方法仅提取输出文件的目录路径。我们这样做是为了检查输出目录是否已经存在。如果不存在，我们使用`os.makedirs()`方法创建输出路径中尚不存在的每个目录。这样可以避免以后尝试将输出 CSV 写入不存在的目录时出现问题：

```py
    directory = os.path.dirname(args.OUTPUT_CSV)
    if directory != '' and not os.path.exists(directory):
        os.makedirs(directory)
```

一旦我们验证了输出目录存在，我们将提供的参数传递给`main()`函数：

```py
    main(args.SQLITE_DATABASE, args.OUTPUT_CSV)
```

`main()`函数向用户的控制台打印状态更新，然后检查输入文件是否存在且是否为文件。如果不存在，我们使用`sys.exit()`方法退出脚本，使用大于 0 的值指示脚本由于错误退出：

```py
def main(database, out_csv):
    print("[+] Attempting connection to {} database".format(database))
    if not os.path.exists(database) or not os.path.isfile(database):
        print("[-] Database does not exist or is not a file")
        sys.exit(1)
```

接下来，我们使用`sqlite3.conn()`方法连接到输入数据库。重要的是要注意，`sqlite3.conn()`方法会打开所提供名称的数据库，无论它是否存在。因此，重要的是在尝试打开连接之前检查文件是否存在。否则，我们可能会创建一个空数据库，在与其交互时可能会导致脚本出现问题。一旦建立了连接，我们需要创建一个`Cursor`对象来与数据库交互：

```py
    # Connect to SQLite Database
    conn = sqlite3.connect(database)
    c = conn.cursor()
```

现在，我们可以使用`Cursor`对象的`execute()`命令对数据库执行查询。此时，我们传递给 execute 函数的字符串只是标准的 SQLlite 查询。在大多数情况下，您可以运行与与 SQLite 数据库交互时通常运行的任何查询。从给定命令返回的结果存储在`Cursor`对象中。我们需要使用`fetchall()`方法将结果转储到我们可以操作的变量中：

```py
    # Query DB for Column Names and Data of Message Table
    c.execute("pragma table_info(message)")
    table_data = c.fetchall()
    columns = [x[1] for x in table_data]
```

`fetchall()`方法返回一组结果的元组。每个元组的第一个索引中存储了每列的名称。通过使用列表推导，我们将`message`表的列名存储到列表中。这在稍后将数据结果写入 CSV 文件时会发挥作用。在获取了`message`表的列名后，我们直接查询该表的所有数据，并将其存储在`message_data`变量中：

```py
    c.execute("select * from message")
    message_data = c.fetchall()
```

提取数据后，我们向控制台打印状态消息，并将输出的 CSV 和消息表列和数据传递给`write_csv()`方法：

```py
    print("[+] Writing Message Content to {}".format(out_csv))
    write_csv(out_csv, columns, message_data)
```

您会发现大多数脚本最终都会将数据写入 CSV 文件。这样做有几个原因。在 Python 中编写 CSV 非常简单，对于大多数数据集，可以用几行代码完成。此外，将数据放入电子表格中可以根据列进行排序和过滤，以帮助总结和理解大型数据集。

在开始写入 CSV 文件之前，我们使用`open()`方法创建文件对象及其别名`csvfile`。打开此文件的方式取决于您是否使用 Python 2.x 或 Python 3.x。对于 Python 2.x，您以`wb`模式打开文件，而不使用 newline 关键字参数。对于 Python 3.x，您可以以`w`模式打开文件，并将 newline 关键字设置为空字符串。在可能的情况下，代码是针对 Python 3.x 编写的，因此我们使用后者。未以这种方式打开文件对象会导致输出的 CSV 文件在每行之间包含一个空行。

打开文件对象后，我们将其传递给`csv.writer()`方法。我们可以使用该对象的`writerow()`和`writerows()`方法分别写入列标题列表和元组列表。顺便说一句，我们可以遍历`msgs`列表中的每个元组，并为每个元组调用`writerow()`。`writerows()`方法消除了不必要的循环，并在这里使用：

```py
def write_csv(output, cols, msgs):
    with open(output, "w", newline="") as csvfile:
        csv_writer = csv.writer(csvfile)
        csv_writer.writerow(cols)
        csv_writer.writerows(msgs)
```

当我们运行此脚本时，会看到以下控制台消息。在 CSV 中，我们可以收集有关发送和接收的消息的详细信息，以及包括日期、错误、来源等在内的有趣的元数据：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00023.jpeg)![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00024.jpeg)

# 识别 SQLite 数据库中的间隙

食谱难度：简单

Python 版本：2.7 或 3.5

操作系统：任意

这个食谱将演示如何通过编程方式使用主键来识别给定表中的缺失条目。这种技术允许我们识别数据库中不再有效的记录。我们将使用这个方法来识别从 iPhone 短信数据库中删除了哪些消息以及删除了多少条消息。然而，这也适用于使用自增主键的任何表。

要了解更多关于 SQLite 表和主键的信息，请访问 [`www.sqlite.org/lang_createtable.html`](https://www.sqlite.org/lang_createtable.html)。

管理 SQLite 数据库及其表的一个基本概念是主键。主键通常是表中特定行的唯一整数列。常见的实现是自增主键，通常从第一行开始为 `1`，每一行递增 `1`。当从表中删除行时，主键不会改变以适应或重新排序表。

例如，如果我们有一个包含 10 条消息的数据库，并删除了消息 `4` 到 `6`，那么主键列中将会有一个从 `3` 到 `7` 的间隙。通过我们对自增主键的理解，我们可以推断消息 `4` 到 `6` 曾经存在，但现在不再是数据库中的有效条目。通过这种方式，我们可以量化数据库中不再有效的消息数量以及与之相关的主键值。我们将在后续的食谱 *深入挖掘以恢复消息* 中使用这个信息，然后去寻找这些条目，以确定它们是否完整且可恢复。

# 入门

此脚本中使用的所有库都包含在 Python 的标准库中。这个食谱需要一个数据库来运行。在这个例子中，我们将使用 iPhone `sms.db` 数据库。

# 如何做...

在这个食谱中，我们将执行以下步骤：

1.  连接到输入数据库。

1.  查询表 PRAGMA 以识别表的主键。

1.  获取所有主键值。

1.  计算并在控制台上显示表中的间隙。

# 工作原理...

首先，我们导入所需的库来处理参数解析和与 SQLite 数据库交互：

```py
from __future__ import print_function
import argparse
import os
import sqlite3
import sys
```

这个食谱的命令行处理程序接受两个位置参数，`SQLITE_DATABASE` 和 `TABLE`，分别表示输入数据库的路径和要查看的表的名称。一个可选参数 `column`，由破折号表示，可以用来手动提供主键列（如果已知）：

```py
if __name__ == "__main__":
    # Command-line Argument Parser
    parser = argparse.ArgumentParser(
        description=__description__,
        epilog="Developed by {} on {}".format(
            ", ".join(__authors__), __date__)
    )
    parser.add_argument("SQLITE_DATABASE", help="Input SQLite database")
    parser.add_argument("TABLE", help="Table to query from")
    parser.add_argument("--column", help="Optional column argument")
    args = parser.parse_args()
```

如果提供了可选的列参数，我们将它作为关键字参数与数据库和表名一起传递给 `main()` 函数。否则，我们只将数据库和表名传递给 `main()` 函数，而不包括 `col` 关键字参数：

```py
    if args.column is not None:
        main(args.SQLITE_DATABASE, args.TABLE, col=args.column)
    else:
        main(args.SQLITE_DATABASE, args.TABLE)
```

`main()` 函数，与前一个食谱一样，首先执行一些验证，验证输入数据库是否存在且是一个文件。因为我们在这个函数中使用了关键字参数，所以我们必须在函数定义中使用 `**kwargs` 参数来指示这一点。这个参数充当一个字典，存储所有提供的关键字参数。在这种情况下，如果提供了可选的列参数，这个字典将包含一个 `col` 键值对：

```py
def main(database, table, **kwargs):
    print("[+] Attempting connection to {} database".format(database))
    if not os.path.exists(database) or not os.path.isfile(database):
        print("[-] Database does not exist or is not a file")
        sys.exit(1)
```

在验证输入文件后，我们使用 `sqlite3` 连接到这个数据库，并创建我们用来与之交互的 `Cursor` 对象：

```py
    # Connect to SQLite Database
    conn = sqlite3.connect(database)
    c = conn.cursor()
```

为了确定所需表的主键，我们使用带有插入括号的表名的`pragma table_info`命令。我们使用`format()`方法动态地将表的名称插入到否则静态的字符串中。在我们将命令的结果存储在`table_data`变量中后，我们对表名输入进行验证。如果用户提供了一个不存在的表名，我们将得到一个空列表作为结果。我们检查这一点，如果表不存在，就退出脚本。

```py
    # Query Table for Primary Key
    c.execute("pragma table_info({})".format(table))
    table_data = c.fetchall()
    if table_data == []:
        print("[-] Check spelling of table name - '{}' did not return "
              "any results".format(table))
        sys.exit(2)
```

在这一点上，我们为脚本的其余部分创建了一个`if-else`语句，具体取决于用户是否提供了可选的列参数。如果`col`是`kwargs`字典中的一个键，我们立即调用`find_gaps()`函数，并将`Cursor`对象`c`、表名和用户指定的主键列名传递给它。否则，我们尝试在`table_data`变量中识别主键。

先前在`table_data`变量中执行并存储的命令为给定表中的每一列返回一个元组。每个元组的最后一个元素是`1`或`0`之间的二进制选项，其中`1`表示该列是主键。我们遍历返回的元组中的每个最后一个元素，如果它们等于`1`，则将元组的索引一中存储的列名附加到`potential_pks`列表中。

```py
    if "col" in kwargs:
        find_gaps(c, table, kwargs["col"])

    else:
        # Add Primary Keys to List
        potential_pks = []
        for row in table_data:
            if row[-1] == 1:
                potential_pks.append(row[1])
```

一旦我们确定了所有的主键，我们检查列表以确定是否存在零个或多个键。如果存在这些情况中的任何一种，我们会提醒用户并退出脚本。在这些情况下，用户需要指定哪一列应被视为主键列。如果列表包含单个主键，我们将该列的名称与数据库游标和表名一起传递给`find_gaps()`函数。

```py
        if len(potential_pks) != 1:
            print("[-] None or multiple primary keys found -- please "
                  "check if there is a primary key or specify a specific "
                  "key using the --column argument")
            sys.exit(3)

        find_gaps(c, table, potential_pks[0])
```

`find_gaps()`方法首先通过在控制台显示一条消息来提醒用户脚本的当前执行状态。我们尝试在`try`和`except`块中进行数据库查询。如果用户指定的列不存在或拼写错误，我们将从`sqlite3`库接收到`OperationalError`。这是用户提供的参数的最后验证步骤，如果触发了 except 块，脚本将退出。如果查询成功执行，我们获取所有数据并将其存储在`results`变量中。

```py
def find_gaps(db_conn, table, pk):
    print("[+] Identifying missing ROWIDs for {} column".format(pk))
    try:
        db_conn.execute("select {} from {}".format(pk, table))
    except sqlite3.OperationalError:
        print("[-] '{}' column does not exist -- "
              "please check spelling".format(pk))
        sys.exit(4)
    results = db_conn.fetchall()
```

我们使用列表推导和内置的`sorted()`函数来创建排序后的主键列表。`results`列表包含索引`0`处的一个元素的元组，即主键，对于`sms.db`的`message`表来说，就是名为 ROWID 的列。有了排序后的 ROWID 列表，我们可以快速计算表中缺少的条目数。这将是最近的 ROWID 减去列表中存在的 ROWID 数。如果数据库中的所有条目都是活动的，这个值将为零。

我们假设最近的 ROWID 是实际最近的 ROWID。有可能删除最后几个条目，而配方只会将最近的活动条目检测为最高的 ROWID。

```py
    rowids = sorted([x[0] for x in results])
    total_missing = rowids[-1] - len(rowids)
```

如果列表中没有缺少任何值，我们将这一幸运的消息打印到控制台，并以`0`退出，表示成功终止。另一方面，如果我们缺少条目，我们将其打印到控制台，并显示缺少条目的计数。

```py
    if total_missing == 0:
        print("[*] No missing ROWIDs from {} column".format(pk))
        sys.exit(0)
    else:
        print("[+] {} missing ROWID(s) from {} column".format(
            total_missing, pk))
```

为了计算缺失的间隙，我们使用`range()`方法生成从第一个 ROWID 到最后一个 ROWID 的所有 ROWIDs 的集合，然后将其与我们拥有的排序列表进行比较。`difference()`函数可以与集合一起使用，返回一个新的集合，其中包含第一个集合中不在括号中的对象中的元素。然后我们将识别的间隙打印到控制台，这样脚本的执行就完成了。

```py
    # Find Missing ROWIDs
    gaps = set(range(rowids[0], rowids[-1] + 1)).difference(rowids)
    print("[*] Missing ROWIDS: {}".format(gaps))
```

此脚本的输出示例可能如下截图所示。请注意，控制台可以根据已删除消息的数量迅速变得混乱。然而，这并不是此脚本的预期结束。我们将在本章后面的更高级的食谱“深入挖掘以恢复消息”中使用此脚本的逻辑，来识别并尝试定位潜在可恢复的消息：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00025.jpeg)

# 另请参阅

有关 SQLite 数据库结构和主键的更多信息，请参阅其广泛的文档[`www.sqlite.org/`](https://www.sqlite.org/)。

# 处理 iTunes 备份

食谱难度：简单

Python 版本：2.7 或 3.5

操作系统：任何

在这个食谱中，我们将把未加密的 iTunes 备份转换成人类可读的格式，这样我们就可以轻松地探索其内容，而无需任何第三方工具。备份文件可以在主机计算机的`MobileSync\Backup`文件夹中找到。

有关 Windows 和 OS X 默认 iTunes 备份位置的详细信息，请访问[`support.apple.com/en-us/HT204215`](https://support.apple.com/en-us/HT204215)。

如果苹果产品已备份到计算机上，将会有许多文件夹，其名称是表示备份文件夹中特定设备的 GUID。这些文件夹包含了一段时间内每个设备的差异备份。

在 iOS 10 中引入的新备份格式中，文件存储在包含文件名前两个十六进制字符的子文件夹中。每个文件的名称都是设备上路径的`SHA-1`哈希。在设备的备份文件夹的根目录中，有一些感兴趣的文件，例如我们之前讨论过的`Info.plist`文件和`Manifest.db`数据库。此数据库存储了每个备份文件的详细信息，包括其`SHA-1`哈希、文件路径和名称。我们将使用这些信息来使用人类友好的名称重新创建本机备份文件夹结构。

# 入门

此脚本中使用的所有库都包含在 Python 的标准库中。要跟随操作，您需要获取一个未加密的 iTunes 备份文件进行操作。确保备份文件是较新的 iTunes 备份格式（iOS 10+），与之前描述的内容相匹配。

# 如何做...

我们将使用以下步骤来处理此食谱中的 iTunes 备份：

1.  识别`MobileSync\Backup`文件夹中的所有备份。

1.  遍历每个备份。

1.  读取 Manifest.db 文件，并将`SHA-1`哈希名称与文件名关联起来。

1.  将备份文件复制并重命名到输出文件夹，使用适当的文件路径和名称。

# 工作原理...

首先，我们导入所需的库来处理参数解析、日志记录、文件复制和与 SQLite 数据库交互。我们还设置了一个变量，用于稍后构建食谱的日志记录组件：

```py
from __future__ import print_function
import argparse
import logging
import os
from shutil import copyfile
import sqlite3
import sys

logger = logging.getLogger(__name__)
```

此食谱的命令行处理程序接受两个位置参数，`INPUT_DIR`和`OUTPUT_DIR`，分别表示 iTunes 备份文件夹和所需的输出文件夹。可以提供一个可选参数来指定日志文件的位置和日志消息的冗长程度。

```py
if __name__ == "__main__":
    # Command-line Argument Parser
    parser = argparse.ArgumentParser(
        description=__description__,
        epilog="Developed by {} on {}".format(
            ", ".join(__authors__), __date__)
    )
    parser.add_argument(
        "INPUT_DIR",
        help="Location of folder containing iOS backups, "
        "e.g. ~\Library\Application Support\MobileSync\Backup folder"
    )
    parser.add_argument("OUTPUT_DIR", help="Output Directory")
    parser.add_argument("-l", help="Log file path",
                        default=__file__[:-2] + "log")
    parser.add_argument("-v", help="Increase verbosity",
                        action="store_true")
    args = parser.parse_args()
```

接下来，我们开始为此食谱设置日志。我们检查用户是否提供了可选的冗长参数，如果有，我们将将级别从`INFO`增加到`DEBUG`：

```py
    if args.v:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)
```

对于此日志，我们设置消息格式并为控制台和文件输出配置处理程序，并将它们附加到我们定义的`logger`：

```py
    msg_fmt = logging.Formatter("%(asctime)-15s %(funcName)-13s"
                                "%(levelname)-8s %(message)s")
    strhndl = logging.StreamHandler(sys.stderr)
    strhndl.setFormatter(fmt=msg_fmt)
    fhndl = logging.FileHandler(args.l, mode='a')
    fhndl.setFormatter(fmt=msg_fmt)

    logger.addHandler(strhndl)
    logger.addHandler(fhndl)
```

设置好日志文件后，我们向日志记录一些调试详细信息，包括提供给此脚本的参数以及有关主机和 Python 版本的详细信息。我们排除了`sys.argv`列表的第一个元素，这是脚本的名称，而不是提供的参数之一：

```py
    logger.info("Starting iBackup Visualizer")
    logger.debug("Supplied arguments: {}".format(" ".join(sys.argv[1:])))
    logger.debug("System: " + sys.platform)
    logger.debug("Python Version: " + sys.version)
```

使用`os.makedirs()`函数，如果必要，我们将为所需的输出目录创建任何必要的文件夹，如果它们尚不存在：

```py
    if not os.path.exists(args.OUTPUT_DIR):
        os.makedirs(args.OUTPUT_DIR)
```

最后，如果输入目录存在并且确实是一个目录，我们将提供的输入和输出目录传递给`main()`函数。如果输入目录未通过验证，我们将在退出脚本之前向控制台打印错误并记录：

```py
    if os.path.exists(args.INPUT_DIR) and os.path.isdir(args.INPUT_DIR):
        main(args.INPUT_DIR, args.OUTPUT_DIR)
    else:
        logger.error("Supplied input directory does not exist or is not "
                     "a directory")
        sys.exit(1)
```

`main()`函数首先调用`backup_summary()`函数来识别输入文件夹中存在的所有备份。在继续`main()`函数之前，让我们先看看`backup_summary()`函数并了解它的作用：

```py
def main(in_dir, out_dir):
    backups = backup_summary(in_dir)
```

`backup_summary()`函数使用`os.listdir()`方法列出输入目录的内容。我们还实例化`backups`字典，用于存储每个发现的备份的详细信息：

```py
def backup_summary(in_dir):
    logger.info("Identifying all iOS backups in {}".format(in_dir))
    root = os.listdir(in_dir)
    backups = {}
```

对于输入目录中的每个项目，我们使用`os.path.join()`方法与输入目录和项目。然后我们检查这是否是一个目录，而不是一个文件，以及目录的名称是否为 40 个字符长。如果目录通过了这些检查，这很可能是一个备份目录，因此我们实例化两个变量来跟踪备份中文件的数量和这些文件的总大小：

```py
    for x in root:
        temp_dir = os.path.join(in_dir, x)
        if os.path.isdir(temp_dir) and len(x) == 40:
            num_files = 0
            size = 0
```

我们使用第一章中讨论的`os.walk()`方法，并为备份文件夹下的根目录、子目录和文件创建列表。因此，我们可以使用文件列表的长度，并在迭代备份文件夹时继续将其添加到`num_files`变量中。类似地，我们使用一个巧妙的一行代码将每个文件的大小添加到`size`变量中：

```py
            for root, subdir, files in os.walk(temp_dir):
                num_files += len(files)
                size += sum(os.path.getsize(os.path.join(root, name))
                            for name in files)
```

在我们完成对备份的迭代之后，我们使用备份的名称作为键将备份添加到`backups`字典中，并将备份文件夹路径、文件计数和大小作为值存储。一旦我们完成了所有备份的迭代，我们将这个字典返回给`main()`函数。让我们接着来看：

```py
            backups[x] = [temp_dir, num_files, size]

    return backups
```

在`main()`函数中，如果找到了任何备份，我们将每个备份的摘要打印到控制台。对于每个备份，我们打印一个任意的标识备份的数字，备份的名称，文件数量和大小。我们使用`format()`方法并手动指定换行符(`\n`)来确保控制台保持可读性：

```py
    print("Backup Summary")
    print("=" * 20)
    if len(backups) > 0:
        for i, b in enumerate(backups):
            print("Backup No.: {} \n"
                  "Backup Dev. Name: {} \n"
                  "# Files: {} \n"
                  "Backup Size (Bytes): {}\n".format(
                      i, b, backups[b][1], backups[b][2])
                  )
```

接下来，我们使用`try-except`块将`Manifest.db`文件的内容转储到`db_items`变量中。如果找不到`Manifest.db`文件，则识别的备份文件夹可能是旧格式或无效的，因此我们使用`continue`命令跳过它。让我们简要讨论一下`process_manifest()`函数，它使用`sqlite3`连接到并提取`Manifest.db`文件表中的所有数据：

```py
            try:
                db_items = process_manifest(backups[b][0])
            except IOError:
                logger.warn("Non-iOS 10 backup encountered or "
                            "invalid backup. Continuing to next backup.")
                continue
```

`process_manifest()` 方法以备份的目录路径作为唯一输入。对于这个输入，我们连接`Manifest.db`字符串，表示这个数据库应该存在在一个有效的备份中的位置。如果发现这个文件不存在，我们记录这个错误并向`main()`函数抛出一个`IOError`，正如我们刚才讨论的那样，这将导致在控制台上打印一条消息，并继续下一个备份：

```py
def process_manifest(backup):
    manifest = os.path.join(backup, "Manifest.db")

    if not os.path.exists(manifest):
        logger.error("Manifest DB not found in {}".format(manifest))
        raise IOError
```

如果文件确实存在，我们连接到它，并使用`sqlite3`创建`Cursor`对象。`items`字典使用每个条目在`Files`表中的`SHA-1`哈希作为键，并将所有其他数据存储为列表中的值。请注意，这里有一种替代方法来访问查询结果，而不是在以前的示例中使用的`fetchall()`函数。在我们从`Files`表中提取了所有数据之后，我们将字典返回给`main()`函数：

```py
    conn = sqlite3.connect(manifest)
    c = conn.cursor()
    items = {}
    for row in c.execute("SELECT * from Files;"):
        items[row[0]] = [row[2], row[1], row[3]]

    return items
```

回到`main()`函数，我们立即将返回的字典，现在称为`db_items`，传递给`create_files()`方法。我们刚刚创建的字典将被下一个函数用来执行对文件`SHA-1`哈希的查找，并确定其真实文件名、扩展名和本地文件路径。`create_files()`函数执行这些查找，并将备份文件复制到输出文件夹，并使用适当的路径、名称和扩展名。

`else`语句处理了`backup_summary()`函数未找到备份的情况。我们提醒用户应该是适当的输入文件夹，并退出脚本。这完成了`main()`函数；现在让我们继续进行`create_files()`方法：

```py
            create_files(in_dir, out_dir, b, db_items)
        print("=" * 20)

    else:
        logger.warning(
            "No valid backups found. The input directory should be "
            "the parent-directory immediately above the SHA-1 hash "
            "iOS device backups")
        sys.exit(2)
```

我们通过在日志中打印状态消息来启动`create_files()`方法：

```py
def create_files(in_dir, out_dir, b, db_items):
    msg = "Copying Files for backup {} to {}".format(
        b, os.path.join(out_dir, b))
    logger.info(msg)
```

接下来，我们创建一个计数器来跟踪在清单中找到但在备份中找不到的文件数量。然后，我们遍历从`process_manifest()`函数生成的`db_items`字典中的每个键。我们首先检查关联的文件名是否为`None`或空字符串，否则继续到下一个`SHA-1`哈希项：

```py
    files_not_found = 0
    for x, key in enumerate(db_items):
        if db_items[key][0] is None or db_items[key][0] == "":
            continue
```

如果关联的文件名存在，我们创建几个表示输出目录路径和输出文件路径的变量。请注意，输出路径被附加到备份名称`b`的名称上，以模仿输入目录中备份文件夹的结构。我们使用输出目录路径`dirpath`首先检查它是否存在，否则创建它：

```py
        else:
            dirpath = os.path.join(
                out_dir, b, os.path.dirname(db_items[key][0]))
            filepath = os.path.join(out_dir, b, db_items[key][0])
            if not os.path.exists(dirpath):
                os.makedirs(dirpath)
```

我们创建了一些路径变量，包括输入目录中备份文件的位置。我们通过创建一个字符串，其中包括备份名称、`SHA-1`哈希键的前两个字符和`SHA-1`键本身，它们之间用斜杠分隔来实现这一点。然后将其连接到输入目录中：

```py
            original_dir = b + "/" + key[0:2] + "/" + key
            path = os.path.join(in_dir, original_dir)
```

有了所有这些路径创建好后，我们现在可以开始执行一些验证步骤，然后将文件复制到新的输出目的地。首先，我们检查输出文件是否已经存在于输出文件夹中。在开发这个脚本的过程中，我们注意到一些文件具有相同的名称，并存储在输出文件夹中的同一文件夹中。这导致数据被覆盖，并且备份文件夹和输出文件夹之间的文件计数不匹配。为了解决这个问题，如果文件已经存在于备份中，我们会附加一个下划线和一个整数`x`，表示循环迭代次数，这对我们来说是一个唯一的值：

```py
            if os.path.exists(filepath):
                filepath = filepath + "_{}".format(x)
```

解决了文件名冲突后，我们使用`shutil.copyfile()`方法来复制由路径变量表示的备份文件，并将其重命名并存储在输出文件夹中，由`filepath`变量表示。如果路径变量指的是不在备份文件夹中的文件，它将引发`IOError`，我们会捕获并记录到日志文件中，并添加到我们的计数器中：

```py
            try:
                copyfile(path, filepath)
            except IOError:
                logger.debug("File not found in backup: {}".format(path))
                files_not_found += 1
```

然后，我们向用户提供一个警告，告知在`Manifest.db`中未找到的文件数量，以防用户未启用详细日志记录。一旦我们将备份目录中的所有文件复制完毕，我们就使用`shutil.copyfile()`方法逐个复制备份文件夹中存在的非混淆的 PLIST 和数据库文件到输出文件夹中：

```py
    if files_not_found > 0:
        logger.warning("{} files listed in the Manifest.db not"
                       "found in backup".format(files_not_found))

    copyfile(os.path.join(in_dir, b, "Info.plist"),
             os.path.join(out_dir, b, "Info.plist"))
    copyfile(os.path.join(in_dir, b, "Manifest.db"),
             os.path.join(out_dir, b, "Manifest.db"))
    copyfile(os.path.join(in_dir, b, "Manifest.plist"),
             os.path.join(out_dir, b, "Manifest.plist"))
    copyfile(os.path.join(in_dir, b, "Status.plist"),
             os.path.join(out_dir, b, "Status.plist"))
```

当我们运行这段代码时，我们可以在输出中看到以下更新后的文件结构：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00026.jpeg)

# 还有更多...

这个脚本可以进一步改进。我们在这里提供了一个建议：

+   添加功能以转换加密的 iTunes 备份。使用第三方库，如`pycrypto`，可以通过提供正确的密码来解密备份。

# 将 Wi-Fi 标记在地图上

食谱难度：中等

Python 版本：3.5

操作系统：任意

没有与外部世界的连接，移动设备只不过是一块昂贵的纸砖。幸运的是，开放的 Wi-Fi 网络随处可见，有时移动设备会自动连接到它们。在 iPhone 上，设备连接过的 Wi-Fi 网络列表存储在一个名为`com.apple.wifi.plist`的二进制 PLIST 文件中。这个 PLIST 记录了 Wi-Fi 的 SSID、BSSID 和连接时间等信息。在这个教程中，我们将展示如何从标准的 Cellebrite XML 报告中提取 Wi-Fi 详细信息，或者提供 Wi-Fi MAC 地址的逐行分隔文件。由于 Cellebrite 报告格式可能随时间而变化，我们基于使用 UFED Physical Analyzer 版本 6.1.6.19 生成的报告进行 XML 解析。

WiGLE 是一个在线可搜索的存储库，截至撰写时，拥有超过 3 亿个 Wi-Fi 网络。我们将使用 Python 的`requests`库访问 WiGLE 的 API，以基于 Wi-Fi MAC 地址执行自动搜索。要安装`requests`库，我们可以使用`pip`，如下所示：

```py
pip install requests==2.18.4
```

如果在 WiGLE 存储库中找到网络，我们可以获取关于它的大量数据，包括其纬度和经度坐标。有了这些信息，我们可以了解用户设备所在的位置，以及可能的用户本身，以及连接的时间。

要了解更多关于 WiGLE 并使用 WiGLE，请访问网站[`wigle.net/.`](https://wigle.net/)

# 入门

这个教程需要从 WiGLE 网站获取 API 密钥。要注册免费的 API 密钥，请访问[`wigle.net/account`](https://wigle.net/account)并按照说明显示您的 API 密钥。有两个 API 值，名称和密钥。对于这个教程，请创建一个文件，其中 API 名称值在前，后跟一个冒号（没有空格），然后是 API 密钥。脚本将读取此格式以对您进行 WiGLE API 身份验证。

在撰写时，为了查询 WiGLE API，您必须向服务贡献数据。这是因为整个网站都是建立在社区共享数据的基础上的，这鼓励用户与他人分享信息。有许多贡献数据的方式，如[`wigle.net`](https://wigle.net)上所记录的那样。

# 如何操作...

这个教程遵循以下步骤来实现目标：

1.  将输入标识为 Cellebrite XML 报告或 MAC 地址的逐行文本文件。

1.  将任一类型的输入处理为 Python 数据集。

1.  使用`requests`查询 WiGLE API。

1.  将返回的 WiGLE 结果优化为更方便的格式。

1.  将处理后的输出写入 CSV 文件。

# 它是如何工作的...

首先，我们导入所需的库来处理参数解析、编写电子表格、处理 XML 数据以及与 WiGLE API 交互：

```py
from __future__ import print_function
import argparse
import csv
import os
import sys
import xml.etree.ElementTree as ET
import requests
```

这个教程的命令行处理程序接受两个位置参数，`INPUT_FILE`和`OUTPUT_CSV`，分别表示带有 Wi-Fi MAC 地址的输入文件和期望的输出 CSV。默认情况下，脚本假定输入文件是 Cellebrite XML 报告。用户可以使用可选的`-t`标志指定输入文件的类型，并在`xml`或`txt`之间进行选择。此外，我们可以设置包含我们 API 密钥的文件的路径。默认情况下，这在用户目录的基础上设置，并命名为`.wigle_api`，但您可以更新此值以反映您的环境中最容易的内容。

保存您的 API 密钥的文件应具有额外的保护措施，通过文件权限或其他方式，以防止您的密钥被盗。

```py
if __name__ == "__main__":
    # Command-line Argument Parser
    parser = argparse.ArgumentParser(
        description=__description__,
        epilog="Developed by {} on {}".format(
            ", ".join(__authors__), __date__),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("INPUT_FILE", help="INPUT FILE with MAC Addresses")
    parser.add_argument("OUTPUT_CSV", help="Output CSV File")
    parser.add_argument(
        "-t", help="Input type: Cellebrite XML report or TXT file",
        choices=('xml', 'txt'), default="xml")
    parser.add_argument('--api', help="Path to API key file",
                        default=os.path.expanduser("~/.wigle_api"),
                        type=argparse.FileType('r'))
    args = parser.parse_args()
```

我们执行标准的数据验证步骤，并检查输入文件是否存在且为文件，否则退出脚本。我们使用`os.path.dirname（）`来提取目录路径并检查其是否存在。如果目录不存在，我们使用`os.makedirs（）`函数来创建目录。在调用`main（）`函数之前，我们还读取并拆分 API 名称和密钥：

```py
    if not os.path.exists(args.INPUT_FILE) or \
            not os.path.isfile(args.INPUT_FILE):
        print("[-] {} does not exist or is not a file".format(
            args.INPUT_FILE))
        sys.exit(1)

    directory = os.path.dirname(args.OUTPUT_CSV)
    if directory != '' and not os.path.exists(directory):
        os.makedirs(directory)

    api_key = args.api.readline().strip().split(":")
```

在我们执行参数验证之后，我们将所有参数传递给`main（）`函数：

```py
    main(args.INPUT_FILE, args.OUTPUT_CSV, args.t, api_key)
```

在`main()`函数中，我们首先确定我们正在处理的输入类型。默认情况下，`type`变量是`"xml"`，除非用户另有指定。根据文件类型，我们将其发送到适当的解析器，该解析器将以字典形式返回提取的 Wi-Fi 数据元素。然后将此字典与输出 CSV 一起传递给`query_wigle()`函数。此函数负责查询、处理并将查询结果写入 CSV 文件。首先，让我们来看看解析器，从`parse_xml()`函数开始：

```py
def main(in_file, out_csv, type, api_key):
    if type == 'xml':
        wifi = parse_xml(in_file)
    else:
        wifi = parse_txt(in_file)

    query_wigle(wifi, out_csv, api_key)
```

我们使用`xml.etree.ElementTree`解析 Cellebrite XML 报告，我们已将其导入为`ET`。

要了解有关`xml`库的更多信息，请访问[`docs.python.org/3/library/xml.etree.elementtree.html`](https://docs.python.org/3/library/xml.etree.elementtree.html)。

解析由取证工具生成的报告可能是棘手的。这些报告的格式可能会发生变化，并破坏您的脚本。因此，我们不能假设此脚本将继续在未来的 Cellebrite Physical Analyzer 软件版本中运行。正因为如此，我们已包含了一个选项，可以使用此脚本与包含 MAC 地址的文本文件一起使用。

与任何 XML 文件一样，我们需要首先访问文件并使用`ET.parse()`函数对其进行解析。然后我们使用`getroot()`方法返回 XML 文件的根元素。我们将此根元素作为文件中搜索报告中的 Wi-Fi 数据标记的初始立足点：

```py
def parse_xml(xml_file):
    wifi = {}
    xmlns = "{http://pa.cellebrite.com/report/2.0}"
    print("[+] Opening {} report".format(xml_file))
    xml_tree = ET.parse(xml_file)
    print("[+] Parsing report for all connected WiFi addresses")
    root = xml_tree.getroot()
```

我们使用`iter()`方法来迭代根元素的子元素。我们检查每个子元素的标记，寻找模型标记。如果找到，我们检查它是否具有位置类型属性：

```py
    for child in root.iter():
        if child.tag == xmlns + "model":
            if child.get("type") == "Location":
```

对于找到的每个位置模型，我们使用`findall()`方法迭代其每个字段元素。此元素包含有关位置工件的元数据，例如网络的时间戳、BSSID 和 SSID。我们可以检查字段是否具有名称属性，其值为`"Timestamp"`，并将其值存储在`ts`变量中。如果值没有任何文本内容，我们继续下一个字段：

```py
                for field in child.findall(xmlns + "field"):
                    if field.get("name") == "TimeStamp":
                        ts_value = field.find(xmlns + "value")
                        try:
                            ts = ts_value.text
                        except AttributeError:
                            continue
```

类似地，我们检查字段的名称是否与`"Description"`匹配。此字段包含 Wi-Fi 网络的 BSSID 和 SSID，以制表符分隔的字符串。我们尝试访问此值的文本，并在没有文本时引发`AttributeError`：

```py
                    if field.get("name") == "Description":
                        value = field.find(xmlns + "value")
                        try:
                            value_text = value.text
                        except AttributeError:
                            continue
```

因为 Cellebrite 报告中可能存在其他类型的`"Location"`工件，我们检查值的文本中是否存在字符串`"SSID"`。如果是，我们使用制表符特殊字符将字符串拆分为两个变量。我们从值的文本中提取的这些字符串包含一些不必要的字符，我们使用字符串切片将其从字符串中删除：

```py
                        if "SSID" in value.text:
                            bssid, ssid = value.text.split("\t")
                            bssid = bssid[7:]
                            ssid = ssid[6:]
```

在从报告中提取时间戳、BSSID 和 SSID 之后，我们可以将它们添加到`wifi`字典中。如果 Wi-Fi 的 BSSID 已经存储为其中一个键，我们将时间戳和 SSID 附加到列表中。这样我们就可以捕获到这个 Wi-Fi 网络的所有历史连接以及网络名称的任何更改。如果我们还没有将此 MAC 地址添加到`wifi`字典中，我们将创建键/值对，包括存储 API 调用结果的 WiGLE 字典。在解析所有位置模型工件之后，我们将`wifi`字典返回给`main()`函数：

```py
                            if bssid in wifi.keys():
                                wifi[bssid]["Timestamps"].append(ts)
                                wifi[bssid]["SSID"].append(ssid)
                            else:
                                wifi[bssid] = {
                                    "Timestamps": [ts], "SSID": [ssid],
                                    "Wigle": {}}
    return wifi
```

与 XML 解析器相比，TXT 解析器要简单得多。我们遍历文本文件的每一行，并将每一行设置为一个 MAC 地址，作为一个空字典的键。在处理文件中的所有行之后，我们将字典返回给`main()`函数：

```py
def parse_txt(txt_file):
    wifi = {}
    print("[+] Extracting MAC addresses from {}".format(txt_file))
    with open(txt_file) as mac_file:
        for line in mac_file:
            wifi[line.strip()] = {"Timestamps": ["N/A"], "SSID": ["N/A"],
                                  "Wigle": {}}
    return wifi
```

有了 MAC 地址的字典，我们现在可以转到`query_wigle()`函数，并使用`requests`进行 WiGLE API 调用。首先，我们在控制台打印一条消息，通知用户当前的执行状态。接下来，我们遍历字典中的每个 MAC 地址，并使用`query_mac_addr()`函数查询 BSSID 的站点：

```py
def query_wigle(wifi_dictionary, out_csv, api_key):
    print("[+] Querying Wigle.net through Python API for {} "
          "APs".format(len(wifi_dictionary)))
    for mac in wifi_dictionary:
        wigle_results = query_mac_addr(mac, api_key)
```

`query_mac_addr()`函数接受我们的 MAC 地址和 API 密钥，并构造请求的 URL。我们使用 API 的基本 URL，并在其末尾插入 MAC 地址。然后将此 URL 提供给`requests.get()`方法，以及`auth kwarg`来提供 API 名称和密钥。`requests`库处理形成并发送带有正确 HTTP 基本身份验证的数据包到 API。`req`对象现在已准备好供我们解释，因此我们可以调用`json()`方法将数据返回为字典：

```py
def query_mac_addr(mac_addr, api_key):
    query_url = "https://api.wigle.net/api/v2/network/search?" \
        "onlymine=false&freenet=false&paynet=false" \
        "&netid={}".format(mac_addr)
    req = requests.get(query_url, auth=(api_key[0], api_key[1]))
    return req.json()
```

使用返回的`wigle_results`字典，我们检查`resultCount`键，以确定在`Wigle`数据库中找到了多少结果。如果没有结果，我们将一个空列表附加到`Wigle`字典中的结果键。同样，如果有结果，我们直接将返回的`wigle_results`字典附加到数据集中。API 确实对每天可以执行的调用次数有限制。当达到限制时，将生成`KeyError`，我们捕获并打印到控制台。我们还提供其他错误的报告，因为 API 可能会扩展错误报告。在搜索每个地址并将结果添加到字典后，我们将其与输出 CSV 一起传递给`prep_output()`方法：

```py
        try:
            if wigle_results["resultCount"] == 0:
                wifi_dictionary[mac]["Wigle"]["results"] = []
                continue
            else:
                wifi_dictionary[mac]["Wigle"] = wigle_results
        except KeyError:
            if wigle_results["error"] == "too many queries today":
                print("[-] Wigle daily query limit exceeded")
                wifi_dictionary[mac]["Wigle"]["results"] = []
                continue
            else:
                print("[-] Other error encountered for "
                      "address {}: {}".format(mac, wigle_results['error']))
                wifi_dictionary[mac]["Wigle"]["results"] = []
                continue
    prep_output(out_csv, wifi_dictionary)
```

如果您还没有注意到，数据变得越来越复杂，这使得编写和处理它变得更加复杂。`prep_output()`方法基本上将字典展平为易于编写的块。我们需要这个函数的另一个原因是，我们需要为每个特定 Wi-Fi 网络连接的实例创建单独的行。虽然该网络的 WiGLE 结果将是相同的，但连接时间戳和网络 SSID 可能是不同的。

为了实现这一点，我们首先为最终处理的结果和与 Google Maps 相关的字符串创建一个字典。我们使用这个字符串来创建一个查询，其中包含纬度和经度，以便用户可以轻松地将 URL 粘贴到其浏览器中，以在 Google Maps 中查看地理位置详细信息：

```py
def prep_output(output, data):
    csv_data = {}
    google_map = "https://www.google.com/maps/search/"
```

我们遍历字典中的每个 MAC 地址，并创建两个额外的循环，以遍历 MAC 地址的所有时间戳和所有 WiGLE 结果。通过这些循环，我们现在可以访问到目前为止收集的所有数据，并开始将数据添加到新的输出字典中。

由于初始字典的复杂性，我们创建了一个名为`shortres`的变量，用作输出字典的更深部分的快捷方式。这样可以防止我们在每次需要访问字典的那部分时不必要地写入整个目录结构。`shortres`变量的第一个用法可以看作是我们从 WiGLE 结果中提取此网络的纬度和经度，并将其附加到 Google Maps 查询中：

```py
    for x, mac in enumerate(data):
        for y, ts in enumerate(data[mac]["Timestamps"]):
            for z, result in enumerate(data[mac]["Wigle"]["results"]):
                shortres = data[mac]["Wigle"]["results"][z]
                g_map_url = "{}{},{}".format(
                    google_map, shortres["trilat"], shortres["trilong"])
```

在一行中（相当复杂），我们添加一个键值对，其中键是基于循环迭代计数器的唯一键，值是展平的字典。我们首先创建一个新字典，其中包含 BSSID、SSID、时间戳和新创建的 Google Maps URL。因为我们想简化输出，我们需要合并新字典和存储在`shortres`变量中的 WiGLE 结果。

我们可以遍历第二个字典中的每个键，并逐个添加其键值对。但是，使用 Python 3.5 中引入的一个特性会更快，我们可以通过在每个字典之前放置两个`*`符号来合并这两个字典。这将合并两个字典，并且如果有任何重名的键，它将用第二个字典中的数据覆盖第一个字典中的数据。在这种情况下，我们没有任何键重叠，所以这将简单地合并字典。

请参阅以下 StackOverflow 帖子以了解更多关于字典合并的信息：

[`stackoverflow.com/questions/38987/how-to-merge-two-python-dictionaries-in-a-single-expression`](https://stackoverflow.com/questions/38987/how-to-merge-two-python-dictionaries-in-a-single-expression)。

在合并了所有字典之后，我们继续使用`write_csv()`函数最终写入输出：

```py
                csv_data["{}-{}-{}".format(x, y, z)] = {
                    **{
                        "BSSID": mac, "SSID": data[mac]["SSID"][y],
                        "Cellebrite Connection Time": ts,
                        "Google Map URL": g_map_url},
                    **shortres
                }

    write_csv(output, csv_data)
```

在这个示例中，我们重新介绍了`csv.DictWriter`类，它允许我们轻松地将字典写入 CSV 文件。这比我们之前使用的`csv.writer`类更可取，因为它为我们提供了一些好处，包括对列进行排序。为了利用这一点，我们需要知道我们使用的所有字段。由于 WiGLE 是动态的，报告的结果可能会改变，我们选择动态查找输出字典中所有键的名称。通过将它们添加到一个集合中，我们确保只有唯一的键：

```py
def write_csv(output, data):
    print("[+] Writing data to {}".format(output))
    field_list = set()
    for row in data:
        for field in data[row]:
            field_list.add(field)
```

一旦我们确定了输出中所有的键，我们就可以创建 CSV 对象。请注意，使用`csv.DictWriter`对象时，我们使用了两个关键字参数。如前所述，第一个是字典中所有键的列表，我们已经对其进行了排序。这个排序后的列表就是结果 CSV 中列的顺序。如果`csv.DictWriter`遇到一个不在提供的`field_list`中的键，由于我们的预防措施，它会忽略错误而不是引发异常，这是由`extrasaction kwarg`中的配置决定的：

```py
    with open(output, "w", newline="") as csvfile:
        csv_writer = csv.DictWriter(csvfile, fieldnames=sorted(
            field_list), extrasaction='ignore')
```

一旦我们设置好写入器，我们可以使用`writeheader()`方法根据提供的字段名称自动写入列。之后，只需简单地遍历数据中的每个字典，并使用`writerow()`函数将其写入 CSV 文件。虽然这个函数很简单，但想象一下，如果我们没有先简化原始数据结构，我们会有多大的麻烦：

```py
        csv_writer.writeheader()
        for csv_row in data:
            csv_writer.writerow(data[csv_row])
```

运行此脚本后，我们可以在 CSV 报告中看到各种有用的信息。前几列包括 BSSID、Google 地图 URL、城市和县：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00027.jpeg)

然后我们会看到一些时间戳，比如第一次出现的时间、最近出现的时间，以及更具体的位置，比如地区和道路：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00028.jpeg)

最后，我们可以了解到 SSID、坐标、网络类型和使用的认证方式：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00029.jpeg)

# 深入挖掘以恢复消息

示例难度：困难

Python 版本：3.5

操作系统：任意

在本章的前面，我们开发了一个从数据库中识别缺失记录的示例。在这个示例中，我们将利用该示例的输出，识别可恢复的记录及其在数据库中的偏移量。这是通过了解 SQLite 数据库的一些内部机制，并利用这种理解来实现的。

有关 SQLite 文件内部的详细描述，请查看[`www.sqlite.org/fileformat.html`](https://www.sqlite.org/fileformat.html)。

通过这种技术，我们将能够快速审查数据库并识别可恢复的消息。

当从数据库中删除一行时，类似于文件，条目不一定会被覆盖。根据数据库活动和其分配算法，这个条目可能会持续一段时间。例如，当触发`vacuum`命令时，我们恢复数据的机会会减少。

我们不会深入讨论 SQLite 结构；可以说每个条目由四个元素组成：有效载荷长度、ROWID、有效载荷头和有效载荷本身。前面的配方识别了缺失的 ROWID 值，我们将在这里使用它来查找数据库中所有这样的 ROWID 出现。我们将使用其他数据，例如已知的标准有效载荷头值，与 iPhone 短信数据库一起验证任何命中。虽然这个配方专注于从 iPhone 短信数据库中提取数据，但它可以修改为适用于任何数据库。我们稍后将指出需要更改的几行代码，以便将其用于其他数据库。

# 入门

此脚本中使用的所有库都包含在 Python 的标准库中。如果您想跟着操作，请获取 iPhone 短信数据库。如果数据库不包含任何已删除的条目，请使用 SQLite 连接打开它并删除一些条目。这是一个很好的测试，可以确认脚本是否按预期在您的数据集上运行。

# 操作步骤...

这个配方由以下步骤组成：

1.  连接到输入数据库。

1.  查询表 PRAGMA 并识别活动条目间隙。

1.  将 ROWID 间隙转换为它们的 varint 表示。

1.  在数据库的原始十六进制中搜索缺失的条目。

1.  将输出结果保存到 CSV 文件中。

# 工作原理...

首先，我们导入所需的库来处理参数解析、操作十六进制和二进制数据、编写电子表格、创建笛卡尔积的元组、使用正则表达式进行搜索以及与 SQLite 数据库交互：

```py
from __future__ import print_function
import argparse
import binascii
import csv
from itertools import product
import os
import re
import sqlite3
import sys
```

这个配方的命令行处理程序有三个位置参数和一个可选参数。这与本章前面的*在 SQLite 数据库中识别间隙*配方基本相同；但是，我们还添加了一个用于输出 CSV 文件的参数：

```py
if __name__ == "__main__":
    # Command-line Argument Parser
    parser = argparse.ArgumentParser(
        description=__description__,
        epilog="Developed by {} on {}".format(
            ", ".join(__authors__), __date__)
    )
    parser.add_argument("SQLITE_DATABASE", help="Input SQLite database")
    parser.add_argument("TABLE", help="Table to query from")
    parser.add_argument("OUTPUT_CSV", help="Output CSV File")
    parser.add_argument("--column", help="Optional column argument")
    args = parser.parse_args()
```

在解析参数后，我们将提供的参数传递给`main()`函数。如果用户提供了可选的列参数，我们将使用`col`关键字参数将其传递给`main()`函数：

```py
    if args.column is not None:
        main(args.SQLITE_DATABASE, args.TABLE,
             args.OUTPUT_CSV, col=args.column)
    else:
        main(args.SQLITE_DATABASE, args.TABLE, args.OUTPUT_CSV)
```

因为这个脚本利用了我们之前构建的内容，`main()`函数在很大程度上是重复的。我们不会重复关于代码的注释（对于一行代码，只能说这么多），我们建议您参考*在 SQLite 数据库中识别间隙*配方，以了解代码的这部分内容。

为了让大家回忆起来，以下是该配方的摘要：`main()`函数执行基本的输入验证，从给定表中识别潜在的主键（除非用户提供了列），并调用`find_gaps()`函数。`find_gaps()`函数是前一个脚本的另一个保留部分，几乎与前一个相同，只有一行不同。这个函数现在不再打印所有已识别的间隙，而是将已识别的间隙返回给`main()`函数。`main()`函数的其余部分和此后涵盖的所有其他代码都是新的。这是我们继续理解这个配方的地方。

识别了间隙后，我们调用一个名为`varint_converter()`的函数来处理每个间隙，将其转换为其 varint 对应项。Varint，也称为可变长度整数，是大小为 1 到 9 个字节的大端整数。SQLite 使用 Varint，因为它们所占的空间比存储 ROWID 整数本身要少。因此，为了有效地搜索已删除的 ROWID，我们必须首先将其转换为 varint，然后再进行搜索：

```py
    print("[+] Carving for missing ROWIDs")
    varints = varint_converter(list(gaps))
```

对于小于或等于 127 的 ROWID，它们的 varint 等价物就是整数的十六进制表示。我们使用内置的`hex()`方法将整数转换为十六进制字符串，并使用字符串切片来删除前置的`0x`。例如，执行`hex(42)`返回字符串`0x2a`；在这种情况下，我们删除了前导的`0x`十六进制标识符，因为我们只对值感兴趣：

```py
def varint_converter(rows):
    varints = {}
    varint_combos = []
    for i, row in enumerate(rows):
        if row <= 127:
            varints[hex(row)[2:]] = row
```

如果缺失的 ROWID 是`128`或更大，我们开始一个无限的`while`循环来找到相关的 varint。在开始循环之前，我们使用列表推导来创建一个包含数字`0`到`255`的列表。我们还实例化一个值为`1`的计数器变量。`while`循环的第一部分创建一个元组列表，其元素数量等于`counter`变量，包含`combos`列表的每个组合。例如，如果 counter 等于`2`，我们会看到一个元组列表，表示所有可能的 2 字节 varints，如`[(0, 0), (0, 1), (0, 2), ..., (255, 255)]`。完成这个过程后，我们再次使用列表推导来删除所有第一个元素小于或等于`127`的元组。由于`if-else`循环的这部分处理大于或等于`128`的行，我们知道 varint 不能等于或小于`127`，因此这些值被排除在考虑之外：

```py
        else:
            combos = [x for x in range(0, 256)]
            counter = 1
            while True:
                counter += 1
                print("[+] Generating and finding all {} byte "
                      "varints..".format(counter))
                varint_combos = list(product(combos, repeat=counter))
                varint_combos = [x for x in varint_combos if x[0] >= 128]
```

创建了 n 字节 varints 列表后，我们循环遍历每个组合，并将其传递给`integer_converter()`函数。这个函数将这些数字视为 varint 的一部分，并将它们解码为相应的 ROWID。然后，我们可以将返回的 ROWID 与缺失的 ROWID 进行比较。如果匹配，我们将一个键值对添加到`varints`字典中，其中键是 varint 的十六进制表示，值是缺失的 ROWID。此时，我们将`i`变量增加`1`，并尝试获取下一个行元素。如果成功，我们处理该 ROWID，依此类推，直到我们已经到达将生成`IndexError`的 ROWIDs 的末尾。我们捕获这样的错误，并将`varints`字典返回给`main()`函数。

关于这个函数需要注意的一件重要的事情是，因为输入是一个排序过的 ROWIDs 列表，我们只需要计算 n 字节 varint 组合一次，因为下一个 ROWID 只能比前一个更大而不是更小。另外，由于我们知道下一个 ROWID 至少比前一个大一，我们继续循环遍历我们创建的 varint 组合，而不重新开始，因为下一个 ROWID 不可能更小。这些技术展示了`while`循环的一个很好的用例，因为它们大大提高了该方法的执行速度：

```py
                for varint_combo in varint_combos:
                    varint = integer_converter(varint_combo)
                    if varint == row:
                        varints["".join([hex(v)[2:].zfill(2) for v in
                                         varint_combo])] = row
                        i += 1
                        try:
                            row = rows[i]
                        except IndexError:
                            return varints
```

`integer_converter()`函数相对简单。这个函数使用内置的`bin()`方法，类似于已经讨论过的`hex()`方法，将整数转换为其二进制等价物。我们遍历建议的 varint 中的每个值，首先使用`bin()`进行转换。这将返回一个字符串，这次前缀值为`0b`，我们使用字符串切片去除它。我们再次使用`zfill()`来确保字节具有所有位，因为`bin()`方法默认会去除前导的`0`位。之后，我们移除每个字节的第一位。当我们遍历我们的 varint 中的每个数字时，我们将处理后的位添加到一个名为`binary`的变量中。

这个过程可能听起来有点混乱，但这是解码 varints 的手动过程。

有关如何手动将 varints 转换为整数和其他 SQLite 内部的更多详细信息，请参阅*Forensics from the sausage factory*上的这篇博文：

[`forensicsfromthesausagefactory.blogspot.com/2011/05/analysis-of-record-structure-within.html`](https://forensicsfromthesausagefactory.blogspot.com/2011/05/analysis-of-record-structure-within.html).[﻿](https://forensicsfromthesausagefactory.blogspot.com/2011/05/analysis-of-record-structure-within.html)

在我们完成对数字列表的迭代后，我们使用`lstrip()`来去除二进制字符串中的任何最左边的零值。如果结果字符串为空，我们返回`0`；否则，我们将处理后的二进制数据转换并返回为从二进制表示的基数 2 的整数：

```py
def integer_converter(numbs):
    binary = ""
    for numb in numbs:
        binary += bin(numb)[2:].zfill(8)[1:]
    binvar = binary.lstrip("0")
    if binvar != '':
        return int(binvar, 2)
    else:
        return 0
```

回到`main（）`函数，我们将`varints`字典和数据库文件的路径传递给`find_candidates（）`函数：

```py
    search_results = find_candidates(database, varints)
```

我们搜索的两个候选者是`"350055"`和`"360055"`。如前所述，在数据库中，跟随单元格的 ROWID 是有效载荷头长度。iPhone 短信数据库中的有效载荷头长度通常是两个值中的一个：要么是 0x35，要么是 0x36。在有效载荷头长度之后是有效载荷头本身。有效载荷头的第一个序列类型将是 0x00，表示为 NULL 值，数据库的主键--第一列，因此第一个序列类型--将始终被记录为。接下来是序列类型 0x55，对应于表中的第二列，消息 GUID，它始终是一个 21 字节的字符串，因此将始终由序列类型 0x55 表示。任何经过验证的命中都将附加到结果列表中。

通过搜索 ROWID varint 和这三个附加字节，我们可以大大减少误报的数量。请注意，如果您正在处理的数据库不是 iPhone 短信数据库，则需要更改这些候选者的值，以反映表中 ROWID 之前的任何静态内容：

```py
def find_candidates(database, varints):
    results = []
    candidate_a = "350055"
    candidate_b = "360055"
```

我们以`rb`模式打开数据库以搜索其二进制内容。为了做到这一点，我们必须首先读取整个数据库，并使用`binascii.hexlify（）`函数将这些数据转换为十六进制。由于我们已经将 varints 存储为十六进制，因此现在可以轻松地搜索这些数据集以查找 varint 和其他周围的数据。我们通过循环遍历每个 varint 并创建两个不同的搜索字符串来开始搜索过程，以考虑 iPhone 短信数据库中的两个静态支点之一：

```py
    with open(database, "rb") as infile:
        hex_data = str(binascii.hexlify(infile.read()))
    for varint in varints:
        search_a = varint + candidate_a
        search_b = varint + candidate_b
```

然后，我们使用`re.finditer（）`方法基于`search_a`和`search_b`关键字来迭代每个命中。对于每个结果，我们附加一个包含 ROWID、使用的搜索词和文件内的偏移量的列表。我们必须除以 2 来准确报告字节数，而不是十六进制数字的数量。在完成搜索数据后，我们将结果返回给`main（）`函数：

```py
        for result in re.finditer(search_a, hex_data):
            results.append([varints[varint], search_a, result.start() / 2])

        for result in re.finditer(search_b, hex_data):
            results.append([varints[varint], search_b, result.start() / 2])

    return results
```

最后一次，我们回到`main（）`函数。这次我们检查是否有搜索结果。如果有，我们将它们与 CSV 输出一起传递给`csvWriter（）`方法。否则，我们在控制台上打印状态消息，通知用户没有识别到完整可恢复的 ROWID：

```py
    if search_results != []:
        print("[+] Writing {} potential candidates to {}".format(
            len(search_results), out_csv))
        write_csv(out_csv, ["ROWID", "Search Term", "Offset"],
                  search_results)
    else:
        print("[-] No search results found for missing ROWIDs")
```

`write_csv（）`方法一如既往地简单。我们打开一个新的 CSV 文件，并为嵌套列表结构中存储的三个元素创建三列。然后，我们使用`writerows（）`方法将结果数据列表中的所有行写入文件：

```py
def write_csv(output, cols, msgs):
    with open(output, "w", newline="") as csvfile:
        csv_writer = csv.writer(csvfile)
        csv_writer.writerow(cols)
        csv_writer.writerows(msgs)
```

当我们查看导出的报告时，我们可以清楚地看到我们的行 ID、搜索的十六进制值以及记录被发现的数据库内的偏移量：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00030.jpeg)

# 还有更多…

这个脚本可以进一步改进。我们在这里提供了一个建议：

+   而不是硬编码候选者，接受这些候选者的文本文件或命令行条目，以增加该脚本的灵活性
