# Python 数据结构和算法实用指南（一）

> 原文：[`zh.annas-archive.org/md5/66ae3d5970b9b38c5ad770b42fec806d`](https://zh.annas-archive.org/md5/66ae3d5970b9b38c5ad770b42fec806d)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

数据结构和算法是信息技术和计算机科学工程学习中最重要的核心学科之一。本书旨在提供数据结构和算法的深入知识，以及编程实现经验。它专为初学者和中级水平的研究 Python 编程的研究生和本科生设计，并通过示例解释复杂的算法。

在这本书中，您将学习基本的 Python 数据结构和最常见的算法。本书将提供 Python 的基本知识，并让读者深入了解数据算法。在书中，我们提供 Python 实现，并解释它们与几乎每个重要和流行的数据结构算法的关系。我们将研究提供数据分析中最常见问题的解决方案的算法，包括搜索和排序数据，以及能够从数据中提取重要统计信息。通过这本易于阅读的书，您将学习如何创建复杂的数据结构，如链表、栈、堆和队列，以及排序算法，包括冒泡排序、插入排序、堆排序和快速排序。我们还描述了各种选择算法，包括随机选择和确定性选择。我们详细讨论了各种数据结构算法和设计范例，如贪婪算法、分治算法和动态规划，以及它们如何在实时应用中使用。此外，我们使用直观的图示例解释了树和图等复杂数据结构的概念。您还将学习各种重要的字符串处理和模式匹配算法，如 KMP 和 Boyer-Moore 算法，以及它们在 Python 中的简单实现。您将学习在预处理、建模和转换数据等任务中使用的常见技术和结构。

拥有对数据结构和算法的深入理解的重要性不言而喻。这是一个重要的武器库，可以帮助您理解新问题并找到优雅的解决方案。通过更深入地了解算法和数据结构，您可能会发现它们的用途远远超出最初的意图。您将开始考虑您编写的代码以及它对内存量的影响。Python 进一步打开了许多专业人士和学生欣赏编程的大门。这种语言很有趣，而且在描述问题时非常简洁。我们利用这种语言的大众吸引力来研究许多广泛研究和标准化的数据结构和算法。本书以简洁地介绍 Python 编程语言开始。因此，在阅读本书之前并不需要您了解 Python。

# 本书的读者对象

本书适用于正在学习初级或中级数据结构和算法课程的 Python 开发人员。本书还适用于所有那些参加或曾参加数据结构和算法课程的本科和研究生工程学生，因为它涵盖了几乎所有在这门课程中学习的算法、概念和设计。因此，本书也可以作为数据结构和算法课程的教材。本书还是一种对于希望使用特定数据结构部署各种应用程序的通用软件开发人员的有用工具，因为它提供了存储相关数据的有效方式。它还提供了学习复杂算法的实用和简单的方法。

假设读者具有一些 Python 的基本知识。但是，这并不是强制性的，因为本书在快速概述 Python 及其面向对象的概念。本书不需要读者具有任何与计算机相关的概念的先验知识，因为所有的概念和算法都有足够详细的解释，配有大量的例子和图示。大多数概念都是通过日常场景来解释，以便更容易理解概念和算法。

# 充分利用本书

1.  本书中的代码需要在 Python 3.7 或更高版本上运行。

1.  Python 交互环境也可以用来运行代码片段。

1.  建议读者通过执行本书中提供的代码来学习算法和概念，以便更好地理解算法。

1.  本书旨在给读者提供实际的经验，因此建议您为所有的算法进行编程，以便充分利用本书。

# 下载示例代码文件

您可以从您在[www.packt.com](http://www.packt.com)的账户中下载本书的示例代码文件。如果您在其他地方购买了本书，您可以访问[www.packt.com/support](http://www.packt.com/support)并注册，文件将直接发送到您的邮箱。

您可以按照以下步骤下载代码文件：

1.  在[www.packt.com](http://www.packt.com)上登录或注册。

1.  选择“支持”选项卡。

1.  点击“下载代码和勘误”。

1.  在搜索框中输入书名，然后按照屏幕上的说明操作。

下载文件后，请确保使用最新版本的以下软件解压或提取文件夹：

+   WinRAR/7-Zip for Windows

+   Zipeg/iZip/UnRarX for Mac

+   7-Zip/PeaZip for Linux

本书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Hands-On-Data-Structures-and-Algorithms-with-Python-Second-Edition`](https://github.com/PacktPublishing/Hands-On-Data-Structures-and-Algorithms-with-Python-Second-Edition)。如果代码有更新，将在现有的 GitHub 存储库上进行更新。

我们还提供了来自我们丰富书籍和视频目录的其他代码包，可在[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)上找到。去看看吧！

# 下载彩色图片

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图片。您可以在这里下载：`www.packtpub.com/sites/default/files/downloads/9781788995573_ColorImages.pdf`

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 用户名。这是一个例子：“我们实例化`CountVectorizer`类，并将`training_data.data`传递给`count_vect`对象的`fit_transform`方法。”

代码块设置如下：

```py
class Node: 
    def __init__(self, data=None): 
        self.data = data 
        self.next = None
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```py
def dequeue(self):  
    if not self.outbound_stack: 
        while self.inbound_stack: 
            self.outbound_stack.append(self.inbound_stack.pop()) 
    return self.outbound_stack.pop()
```

任何命令行输入或输出都以以下形式书写：

```py
0     1      2
0   4.0  45.0  984.0
1   0.1   0.1    5.0
2  94.0  23.0   55.0
```

**粗体**：表示一个新术语、一个重要词或屏幕上看到的词。

警告或重要提示会以这种形式出现。提示和技巧会以这种形式出现。


# 第一章：Python 对象、类型和表达式

数据结构和算法是一个大型复杂软件项目的核心要素之一。它们是一种系统化的方式，用于在软件中存储和组织数据，以便能够高效地使用。Python 具有高效的高级数据结构和有效的面向对象编程语言。Python 是许多高级数据任务的首选语言，原因很充分。它是最容易学习的高级编程语言之一。直观的结构和语义意味着对于那些不是计算机科学家，但可能是生物学家、统计学家或初创公司的负责人来说，Python 是执行各种数据任务的简单方式。它不仅仅是一种脚本语言，而是一种功能齐全的面向对象的编程语言。

在 Python 中，有许多有用的数据结构和算法内置在语言中。此外，由于 Python 是一种基于对象的语言，相对容易创建自定义数据对象。在本书中，我们将研究 Python 的内部库和一些外部库，并学习如何从头开始构建自己的数据对象。

在本章中，我们将讨论以下主题：

+   获得对数据结构和算法的一般工作知识

+   理解核心数据类型及其功能

+   探索 Python 编程语言的面向对象的方面

# 技术要求

本书使用 Python 编程语言（版本 3.7）介绍数据结构和算法。本书假设您已经了解 Python。但是，如果您有点生疏，来自其他语言，或者根本不了解 Python，不用担心 - 这一章应该能让您迅速掌握。

以下是 GitHub 链接：[`github.com/PacktPublishing/Hands-On-Data-Structures-and-Algorithms-with-Python-Second-Edition/tree/master/Chapter01`](https://github.com/PacktPublishing/Hands-On-Data-Structures-and-Algorithms-with-Python-Second-Edition/tree/master/Chapter01)。

如果您对 Python 不熟悉，请访问[`docs.python.org/3/tutorial/index.html`](https://docs.python.org/3/tutorial/index.html)，您也可以在[`www.python.org/doc/`](https://www.python.org/doc/)找到文档。这些都是很好的资源，可以轻松学习这种编程语言。

# 安装 Python

要安装 Python，我们使用以下方法。

Python 是一种解释性语言，语句是逐行执行的。程序员通常可以将一系列命令写在源代码文件中。对于 Python，源代码存储在一个带有`.py`文件扩展名的文件中。

Python 通常已经完全集成并安装在大多数 Linux 和 Mac 操作系统上。通常，预安装的 Python 版本是 2.7。您可以使用以下命令检查系统上安装的版本：

```py
>>> import sys
>>> print(sys.version)
3.7.0 (v3.7.0:1bf9cc5093, Jun 27 2018, 04:06:47) [MSC v.1914 32 bit (Intel)]
```

您还可以使用以下命令在 Linux 上安装不同版本的 Python：

1.  打开终端

1.  `sudo apt-get update`

1.  `sudo apt-get install -y python3-pip`

1.  `pip3 install <package_name>`

Python 必须安装在 Windows 操作系统的系统上，因为它不像 Linux/macOS 那样预安装。可以从此链接下载 Python 的任何版本：[`www.python.org/downloads/`](https://www.python.org/downloads/)。您可以下载软件安装程序并运行它 - 选择为所有用户安装，然后单击下一步。您需要指定要安装软件包的位置，然后单击下一步。之后，在自定义 Python 对话框中选择将 Python 添加到环境变量的选项，然后再次单击下一步进行最终安装。安装完成后，您可以通过打开命令提示符并输入以下命令来确认安装：

```py
python -V
```

最新的稳定 Python 版本是 Python 3.7.0。可以通过在命令行中输入以下内容来执行 Python 程序：

```py
python <sourcecode_filename>.py
```

# 理解数据结构和算法

算法和数据结构是计算机中最基本的概念。它们是构建复杂软件的主要构建模块。理解这些基础概念在软件设计中是非常重要的，这涉及以下三个特征：

+   算法如何操作数据结构中包含的信息

+   3. 数据在内存中的排列方式

+   1. 特定数据结构的性能特征是什么

在这本书中，我们将从几个角度来审视这个话题。首先，我们将从数据结构和算法的角度来看 Python 编程语言的基础知识。其次，重要的是我们要有正确的数学工具。我们需要理解计算机科学的基本概念，为此我们需要数学。通过采取一种启发式的方法，制定一些指导原则意味着，一般来说，我们不需要比高中数学更多的知识来理解这些关键思想的原则。

另一个重要方面是评估。衡量算法的性能需要理解数据规模的增加如何影响数据的操作。当我们处理大型数据集或实时应用程序时，我们的算法和结构尽可能高效是至关重要的。

最后，我们需要一个强大的实验设计策略。能够将现实世界的问题概念化为编程语言的算法和数据结构，需要能够理解问题的重要元素以及将这些元素映射到编程结构的方法。

为了更好地理解算法思维的重要性，让我们考虑一个现实世界的例子。假设我们在一个陌生的市场，我们被要求购买一些物品。我们假设市场是随机布局的，每个供应商销售一个随机子集的物品，其中一些物品可能在我们的清单上。我们的目标是尽量减少每个购买物品的价格，同时最小化在市场上花费的时间。解决这个问题的一种方法是编写以下类似的算法：

1. 供应商是否有我们清单上的物品，且成本低于该物品的预测成本？

2. 如果是，购买并从清单中删除；如果不是，继续下一个供应商。

2. 如果没有更多的供应商，结束。

3. 如果我们必须使用编程语言来实现这个简单的迭代器，我们需要数据结构来定义和存储我们想要购买的物品清单和供应商正在销售的物品清单。我们需要确定最佳的匹配物品的方式，并且我们需要一些逻辑来决定是否购买。

关于这个算法，我们可以做出几点观察。首先，由于成本计算是基于预测的，我们不知道真实成本是多少。因此，我们不会购买物品，因为我们低估了物品的成本，导致我们在市场结束时仍有剩余物品。为了处理这种情况，我们需要一种有效的方式来存储数据，以便我们可以有效地回溯到成本最低的供应商。

此外，我们需要了解比较我们购物清单上的物品与每个供应商出售的物品所花费的时间。这很重要，因为随着我们购物清单上物品的数量或每个供应商出售的物品数量的增加，搜索物品需要更多的时间。我们搜索物品的顺序和数据结构的形状可以对搜索所需的时间产生很大的影响。显然，我们希望安排我们的清单以及我们访问每个供应商的顺序，以便最小化搜索时间。

此外，考虑一下当我们将购买条件更改为以*最便宜*的价格购买，而不仅仅是低于平均预测价格时会发生什么。这会完全改变问题。我们不再是顺序地从一个供应商到另一个供应商，而是需要遍历市场一次，并且有了这个知识，我们可以根据我们想要访问的供应商对我们的购物清单进行排序。

显然，将现实世界的问题转化为编程语言这样的抽象构造涉及许多微妙之处。例如，随着我们在市场上的进展，我们对产品成本的了解会提高，因此我们预测的平均价格变量会变得更加准确，直到在最后一个摊位，我们对市场的了解是完美的。假设任何形式的回溯算法都会产生成本，我们可以看到有理由重新审视整个策略。高价格波动、数据结构的大小和形状，以及回溯的成本等条件都决定了最合适的解决方案。整个讨论清楚地表明了数据结构和算法在构建复杂解决方案中的重要性。

# Python 用于数据

Python 具有几种内置的数据结构，包括列表、字典和集合，我们可以用它们来构建定制对象。此外，还有一些内部库，如 collections 和 math 对象，它们允许我们创建更高级的结构，并对这些结构进行计算。最后，还有像 SciPy 包中发现的外部库。这些库允许我们执行一系列高级数据任务，如逻辑和线性回归、可视化和数学计算，比如矩阵和向量的操作。外部库对于开箱即用的解决方案非常有用。然而，我们也必须意识到，与从头开始构建定制对象相比，通常会有性能损失。通过学习如何自己编写这些对象，我们可以将它们针对特定任务，使它们更有效率。这并不排除外部库的作用，我们将在第十二章《设计技术和策略》中讨论这一点。

首先，我们将概述一些关键的语言特性，这些特性使 Python 成为数据编程的绝佳选择。

# Python 环境

由于其可读性和灵活性，Python 是全球最受欢迎和广泛使用的编程语言之一。Python 环境的一个特点是其交互式控制台，允许您将 Python 用作桌面可编程计算器，也可以用作编写和测试代码片段的环境。

控制台的`读取...评估...打印`循环是与更大代码库交互的非常方便的方式，比如运行函数和方法或创建类的实例。这是 Python 相对于编译语言（如 C/C++或 Java）的主要优势之一，后者的`编写...编译...测试...重新编译`循环与 Python 的`读取...评估...打印`循环相比，可以大大增加开发时间。能够输入表达式并立即得到响应可以大大加快数据科学任务的速度。

除了官方的 CPython 版本外，还有一些优秀的 Python 发行版。其中最受欢迎的两个可以在以下网址找到：Anaconda（https://www.continuum.io/downloads）和 Canopy（https://www.enthought.com/products/canopy/）。大多数发行版都带有自己的开发环境。Canopy 和 Anaconda 都包括用于科学、机器学习和其他数据应用的库。大多数发行版都带有编辑器。

除了 CPython 版本外，还有许多 Python 控制台的实现。其中最值得注意的是基于网络的计算环境 IPython/Jupyter 平台。

# 变量和表达式

要通过算法实现解决现实世界的问题，我们首先必须选择变量，然后对这些变量应用操作。变量是附加到对象的标签。变量不是对象，也不是对象的容器；它们只是作为对象的指针或引用。例如，考虑以下代码：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/745e0608-bbd2-46b2-a213-47194b782fc8.png)

在这里，我们创建了一个指向列表对象的变量`a`。我们创建另一个变量`b`，它指向相同的列表对象。当我们向这个列表对象添加一个元素时，这个变化会反映在`a`和`b`中。

在 Python 中，变量名在程序执行期间附加到不同的数据类型；不需要首先声明变量的数据类型。每个值都有一个类型（例如字符串或整数）；然而，指向这个值的变量名没有特定的类型。更具体地说，变量指向一个对象，可以根据分配给它们的值的类型而改变它们的类型。考虑以下例子：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/2b7de8f3-a61b-4ac6-a154-12653f2518c8.png)

在前面的代码示例中，`a`的类型从`int`变为`float`，具体取决于变量中存储的值。

# 变量作用域

函数内部变量的作用域规则很重要。每当函数执行时，都会创建一个局部环境（命名空间）。这个局部命名空间包含所有由函数分配的变量和参数名。每当调用函数时，Python 解释器首先查找函数本身的局部命名空间——如果找不到匹配项，然后查找全局命名空间。如果名称仍然找不到，那么它会在内置命名空间中搜索。如果还是找不到，解释器会引发`NameError`异常。考虑以下代码：

```py
a=15;b=25
def my_function():
  global a 
  a=11;b=21

my_function() 
print(a)  #prints 11 
print(b)  #prints 25
```

在前面的代码中，我们定义了两个`global`变量。我们需要使用关键字`global`告诉解释器，在函数内部我们正在引用一个`global`变量。当我们将这个变量更改为`11`时，这些更改会反映在全局范围内。然而，我们将`b`变量设置为`21`是函数内部的局部变量，对它进行的任何更改都不会反映在全局范围内。当我们运行函数并打印`b`时，我们看到它保留了它的全局值。

此外，让我们考虑另一个有趣的例子：

```py
>>> a = 10
>>> def my_function():
...     print(a)
>>> my_function ()
10
```

代码可以正常工作，并输出`10`，但看看下面的代码：

```py
>>> a = 10 
>>> def my_function():
...     print(a)
...     a= a+1 
>>> my_function()
 UnboundLocalError: local variable 'a' referenced before assignment
```

前面的代码出错了，因为在作用域内对变量进行赋值会使该变量成为该作用域的局部变量。在前面的例子中，在`my_function()`中对变量`a`进行赋值，编译器会将`a`视为局部变量，这就是为什么之前的`print()`函数尝试打印一个未初始化的局部变量`a`，从而导致错误。可以通过声明为`global`来访问外部作用域变量来解决这个问题：

```py
>>> a = 10
>>> def my_function():
...     global a
...     print(a)
...     a = a+1
>>> my_function()
10
```

因此，在 Python 中，函数内部引用的变量隐式地是全局的，如果`a`变量在函数体内的任何地方被赋值，它会被假定为局部变量，除非显式声明为全局变量。

# 流程控制和迭代

Python 程序由一系列语句组成。解释器按顺序执行每个语句，直到没有更多的语句为止。这对于作为主程序运行的文件以及通过`import`加载的文件都是如此。所有语句，包括变量赋值、函数定义、类定义和模块导入，都具有相同的地位。没有比其他更高优先级的特殊语句，每个语句都可以放在程序的任何位置。通常，程序中的所有指令/语句都按顺序执行。然而，控制程序执行流的主要方法有两种——条件语句和循环。

`if...else`和`elif`语句控制条件执行语句。一般格式是一系列`if`和`elif`语句，后跟最终的`else`语句：

```py
x='one' 
if x==0:
   print('False')
elif  x==1:
   print('True')
else:  print('Something else')

#prints'Something else'
```

请注意使用`==`运算符来比较两个值。如果两个值相等，则返回`True`；否则返回`False`。还要注意，将`x`设置为字符串将返回`Something else`，而不会像在静态类型的语言中那样生成类型错误。动态类型的语言，如 Python，允许对具有不同类型的对象进行灵活赋值。

控制程序流的另一种方法是使用循环。Python 提供了两种构建循环的方式，如`while`和`for`循环语句。`while`循环重复执行语句，直到布尔条件为真。`for`循环提供了一种通过一系列元素重复执行循环的方法。下面是一个例子：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/8bddf69a-d89b-49c0-a9a6-358dbcb2dd2e.png)

在这个例子中，`while`循环执行语句，直到条件`x < 3`为真。让我们考虑另一个使用*for*循环的例子：

```py
>>>words = ['cat', 'dog', 'elephant']
>>> for w in words:
...     print(w)
... 
cat
dog
elephant
```

在这个例子中，*for*循环执行对列表中所有项目的迭代。

# 数据类型和对象概述

Python 包含各种内置数据类型。这些包括四种数值类型（`int`、`float`、`complex`、`bool`）、四种序列类型（`str`、`list`、`tuple`、`range`）、一种映射类型（`dict`）和两种集合类型。还可以创建用户定义的对象，如函数或类。我们将在本章中讨论字符串和列表数据类型，下一章中讨论其余的内置类型。

Python 中的所有数据类型都是**对象**。实际上，在 Python 中几乎所有的东西都是对象，包括模块、类和函数，以及字面量，如字符串和整数。Python 中的每个对象都有一个**类型**、一个**值**和一个**标识**。当我们写`greet= "helloworld"`时，我们创建了一个字符串对象的实例，其值为`"hello world"`，标识为`greet`。对象的标识充当指向对象在内存中位置的指针。对象的类型，也称为对象的类，描述了对象的内部表示，以及它支持的方法和操作。一旦创建了对象的实例，它的标识和类型就不能被改变。

我们可以使用内置函数`id()`来获取对象的标识。这将返回一个标识整数，在大多数系统上，这将指向其内存位置，尽管您不应该依赖于这一点在您的任何代码中。

此外，有许多比较对象的方法；例如，参见以下内容：

```py
if a==b:    # a and b have the same value

if a is b:    # if a and b are the same object

if type(a) is type(b):   #a and b are the same type
```

需要区分**可变**和**不可变**对象之间的重要区别。可变对象如列表可以改变其值。它们有`insert()`或`append()`等方法，可以改变对象的值。不可变对象如字符串不能改变其值，因此当我们运行它们的方法时，它们只是返回一个值，而不是改变底层对象的值。当然，我们可以通过将其分配给一个变量或将其用作函数中的参数来使用这个值。例如，`int`类是不可变的——一旦创建了它的实例，它的值就不能改变，但是，引用这个对象的标识符可以被重新分配另一个值。

# 字符串

字符串是不可变的序列对象，每个字符代表序列中的一个元素。与所有对象一样，我们使用方法来执行操作。字符串是不可变的，不会改变实例；每个方法只是返回一个值。这个值可以存储为另一个变量，或作为参数传递给函数或方法。

以下表格列出了一些最常用的字符串方法及其描述：

| 方法 | 描述 |
| --- | --- |
| `s.capitalize` | 返回只有第一个字符大写的字符串，其余字符保持小写。 |
| `s.count(substring,[start,end])` | 计算子字符串的出现次数。 |
| `s.expandtabs([tabsize])` | 用空格替换制表符。 |
| `s.endswith(substring,[start, end]` | 如果字符串以指定的子字符串结尾，则返回`True`。 |
| `s.find(substring,[start,end])` | 返回子字符串第一次出现的索引。 |
| `s.isalnum()` | 如果字符串`s`中所有字符都是字母数字，则返回`True`。 |
| `s.isalpha()` | 如果字符串`s`中所有字符都是字母，则返回`True`。 |
| `s.isdigit()` | 如果字符串中所有字符都是数字，则返回`True`。 |
| `s.split([separator],[maxsplit])` | 以空格或可选分隔符分割字符串。返回一个列表。 |
| `s.join(t)` | 连接序列`t`中的字符串。 |
| `s.lower()` | 将字符串转换为全小写。 |
| `s.replace(old, new[maxreplace])` | 用新的子字符串替换旧的子字符串。 |
| `s.startswith(substring, [start, end]])` | 如果字符串以指定的子字符串开头，则返回`True`。 |
| `s.swapcase()` | 返回字符串中交换大小写的副本。 |
| `s.strip([characters])` | 移除空格或可选字符。 |
| `s.lstrip([characters])` | 返回删除前导字符的字符串副本。 |

像所有序列类型一样，字符串支持索引和切片。我们可以通过使用索引`s[i]`检索字符串的任何字符。我们可以通过使用`s[i:j]`检索字符串的一个切片，其中`i`和`j`是切片的起点和终点。我们可以通过使用步长返回一个扩展的切片，如下所示—`s[i:j:stride]`。以下代码应该能说明这一点：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/3da1c070-0671-4a9b-91cb-38e3ec444994.png)

前两个例子非常直接，分别返回索引`1`处的字符和字符串的前七个字符。请注意，索引从`0`开始。在第三个例子中，我们使用了步长为`2`。这导致每隔一个字符被返回。在最后一个例子中，我们省略了结束索引，切片返回整个字符串中每隔一个字符。

只要值是整数，就可以使用任何表达式、变量或运算符作为索引：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/045aeaf6-1be2-49ba-a3ea-059b09cb361e.png)

另一个常见的操作是使用循环遍历字符串：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/55d863c4-45e2-4aa1-936e-7e41915b13a3.png)

鉴于字符串是不可变的，一个常见的问题是如何执行插入值等操作。我们需要想办法为我们需要的结果构建新的字符串对象，而不是改变一个字符串。例如，如果我们想要在问候语中插入一个单词，我们可以将一个变量赋值给以下内容：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/93ff7c53-9bb0-4339-9ad3-bdaf2bb16046.png)

正如这段代码所示，我们使用切片操作符在索引位置`5`处拆分字符串，并使用`+`进行连接。Python 从不将字符串的内容解释为数字。如果我们需要对字符串执行数学运算，我们需要先将它们转换为数字类型：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/d4bd788f-9566-4712-b1ab-6b09c31cc858.png)

# 列表

列表是最常用的内置数据结构之一，因为它们可以存储任意数量的不同数据类型。它们是对象的简单表示，并且由整数索引，从零开始，如我们在*字符串*中看到的那样。

下表包含了最常用的列表方法及其描述：

| **方法** | **描述** |
| --- | --- |
| `list(s)` | 返回序列`s`的列表。 |
| `s.append(x)` | 在列表`s`的末尾添加元素`x`。 |
| `s.extend(x)` | 在列表`s`的末尾添加列表`x`。 |
| `s.count(x)` | 返回列表`s`中`x`出现的次数。 |
| `s.index(x,[start],[stop])` | 返回最小的索引`i`，其中`s[i]==x`。我们可以为查找包括可选的开始和结束索引。 |
| `s.insert(i,e)` | 在索引`i`处插入`x`。 |
| `s.pop(i)` | 返回列表`s`中的元素`i`并将其移除。 |
| `s.remove(x)` | 从列表`s`中移除元素`x`。 |
| `s.reverse()` | 颠倒列表`s`的顺序。 |
| `s.sort(key,[reverse])` | 用可选的 key 对列表`s`进行排序并反转。 |

在 Python 中，与其他语言相比，列表的实现是不同的。Python 不会创建变量的多个副本。例如，当我们将一个变量的值分配给另一个变量时，两个变量都指向存储值的相同内存地址。只有在变量改变其值时才会分配一个副本。这个特性使得 Python 在内存上更有效，因为它只在需要时才创建多个副本。

这对于可变的复合对象（如列表）有重要的影响。考虑以下代码：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/14c189e7-ddb4-4e04-89b7-84b8635d7bb6.png)

在上述代码中，`list1`和`list2`变量都指向同一内存位置。但是，当我们通过`list2`将`y`更改为`4`时，实际上也更改了`list1`指向的相同`y`变量。

`list`的一个重要特性是它可以包含嵌套结构；也就是说，列表可以包含其他列表。例如，在以下代码中，列表`items`包含了另外三个列表：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/43641e4c-00c8-455c-bb6c-e1ee22e484b7.png)

我们可以使用方括号运算符访问列表的值，并且由于列表是可变的，它们是就地复制的。以下示例演示了我们如何使用这一点来更新元素；例如，在这里我们将面粉的价格提高了 20%：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/c19d6173-458d-4901-b494-d34600607c0f.png)

我们可以使用非常常见和直观的方法，即**列表推导**，从表达式中创建一个列表。它允许我们通过一个表达式直接创建一个列表。考虑以下示例，使用这个表达式创建了一个列表`l`：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/b27ed8e2-fff4-49b6-95c4-84808f5c1f5f.png)

列表推导可以非常灵活；例如，考虑以下代码。它基本上展示了执行函数组合的两种不同方式，其中我们将一个函数（`x*4`）应用于另一个函数（`x*2`）。以下代码打印出了两个列表，分别表示`f1`和`f2`的函数组合，首先使用 for 循环计算，然后使用列表推导计算：

```py
def f1(x): return x*2 
def f2(x): return x*4

lst=[]
for i in range(16):
   lst.append(f1(f2(i)))

print(lst)
print([f1(x) for x in range(64) if x in [f2(j) for j in range(16)]])

```

输出的第一行是来自于 for 循环结构。第二行是来自于列表推导表达式：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/39930806-6c10-4d9c-afbc-8a39002c8708.png)

列表推导也可以用来复制嵌套循环的操作，以更紧凑的形式。例如，我们将`list1`中的每个元素与彼此相乘：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/79b4fd28-f816-49d9-98de-145f8aa50ff3.png)

我们还可以使用列表推导与其他对象（如字符串）一起构建更复杂的结构。例如，以下代码创建了一个单词及其字母计数的列表：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/db9ed782-f9e2-45cf-a87f-96f4001a4224.png)

正如我们将看到的，列表构成了我们将要研究的许多数据结构的基础。它们的多功能性、易于创建和使用使它们能够构建更专业化和复杂的数据结构。

# 函数作为一等对象

在 Python 中，不仅数据类型被视为对象。函数和类都被称为一等对象，允许它们以与内置数据类型相同的方式进行操作。根据定义，一等对象具有以下特点：

+   在运行时创建

+   分配为变量或数据结构中

+   作为函数的参数传递

+   作为函数结果返回

在 Python 中，术语**一等对象**有点不准确，因为它暗示了某种层次结构，而所有 Python 对象本质上都是一等对象。

为了看看这是如何工作的，让我们定义一个简单的函数：

```py
def greeting(language): 
   if language=='eng': 
        return 'hello world'
      if language =='fr'
        return 'Bonjour le monde'
      else: return  'language not supported'

```

由于用户定义的函数是对象，我们可以将它们包含在其他对象中，比如列表中：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/68d69688-ec25-41e1-8c34-932ae3496c25.png)

函数也可以作为其他函数的参数使用。例如，我们可以定义以下函数：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/8ae8379b-84a1-4848-b182-2edb6099f0d5.png)

在这里，`callf()`接受一个函数作为参数，将语言变量设置为`'eng'`，然后调用带有语言变量作为参数的函数。我们可以看到，如果我们想要生成一个以各种语言返回特定句子的程序，这将是有用的。在这里，我们有一个设置语言的中心位置。除了我们的问候函数，我们还可以创建返回不同句子的类似函数。通过在一个地方设置语言，程序逻辑的其余部分不必担心这一点。如果我们想要改变语言，我们只需改变语言变量，其他一切都可以保持不变。

# 高阶函数

接受其他函数作为参数或返回函数的函数称为**高阶函数**。Python 3 包含两个内置的高阶函数——`filter()`和`map()`。请注意，在 Python 的早期版本中，这些函数返回列表；在 Python 3 中，它们返回一个迭代器，使它们更加高效。`map()`函数提供了一种简单的方法来将每个项目转换为可迭代对象。例如，这是一种在序列上执行操作的高效、紧凑的方法。请注意使用`lambda`匿名函数：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/7315856e-a4c1-44e6-8072-af7c4f03d3f6.png)

同样，我们可以使用内置的 filter 函数来过滤列表中的项目：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/7a36c976-240b-448f-bf5a-bed8d610d781.png)

请注意，map 和 filter 执行与列表推导可以实现的相同功能。除了在使用内置函数 map 和 filter 时，与列表推导相比，性能特性没有太大的区别，除了在不使用`lambda`运算符时稍微有一点性能优势。尽管如此，大多数风格指南建议使用列表推导而不是内置函数，可能是因为它们更容易阅读。

创建我们自己的高阶函数是函数式编程风格的一个标志。高阶函数的一个实际例子是以下演示的。在这里，我们将`len`函数作为 sort 函数的键传递。这样，我们可以按长度对单词列表进行排序：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/0d25a0df-964c-447a-8c22-a25b83b4eb96.png)

这是另一个不区分大小写的排序示例：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/56fc79db-0fb0-404e-9f1c-a839e62eca5e.png)

请注意`list.sort()`方法和内置的 sorted 函数之间的区别。`list.sort()`方法是列表对象的一个方法，它对现有的列表实例进行排序而不复制它。这种方法改变了目标对象并返回`None`。在 Python 中，一个重要的约定是改变对象的函数或方法返回`None`，以明确表示没有创建新对象并且对象本身已经改变。

另一方面，内置的 sorted 函数返回一个新的列表。它实际上接受任何可迭代对象作为参数，但它总是返回一个列表。*list sort*和*sorted*都接受两个可选的关键字参数。

对更复杂的结构进行排序的一个简单方法是使用 lambda 运算符来使用元素的索引进行排序，例如：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/2cb6f820-9f35-4208-8dc7-9abf5407197b.png)

在这里，我们按价格对项目进行了排序。

# 递归函数

递归是计算机科学中最基本的概念之一。在执行过程中，当一个函数调用自身一次或多次时，它被称为*递归*。循环迭代和递归在*循环*通过布尔条件或一系列元素重复执行语句的意义上是不同的，而递归则重复调用一个函数。在 Python 中，我们可以通过在其自身函数体内调用它来实现递归函数。为了防止递归函数变成无限循环，我们需要至少一个测试终止情况的参数来结束递归。这有时被称为基本情况。应该指出，递归与迭代不同。虽然两者都涉及重复，但迭代循环通过一系列操作，而递归重复调用一个函数。从技术上讲，递归是迭代的一种特殊情况，通常总是可以将迭代函数转换为递归函数，反之亦然。递归函数的有趣之处在于它们能够用有限的语句描述一个无限的对象。

以下代码应该演示了递归和迭代之间的区别。这两个函数都简单地打印出低和高之间的数字，第一个使用迭代，第二个使用递归：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/1511f7af-2b45-439a-bcfa-ab700239a3b9.png)

请注意，对于`iterTest`，迭代示例，我们使用 while 语句来测试条件，然后调用打印方法，最后递增低值。递归示例测试条件，打印，然后调用自身，在其参数中递增低变量。一般来说，迭代更有效率；然而，递归函数通常更容易理解和编写。递归函数还可用于操作递归数据结构，如链表和树，我们将会看到。

# 生成器和协程

我们可以创建不仅返回一个结果而且返回整个结果序列的函数，方法是使用 yield 语句。这些函数被称为**生成器**。Python 包含生成器函数，这是一种创建迭代器的简单方法，特别适用于替代不可行的长列表。生成器产生项目而不是构建列表。例如，以下代码显示了为什么我们可能选择使用生成器而不是创建列表：

```py
#compares the running time of a list compared to a generator 
import time
#generator function creates an iterator of odd numbers between n and m 
def oddGen(n,m):
    while n<m:
      yield n
      n+=2

#builds a list of odd numbers between n and m 
def oddLst(n,m):
     lst=[]
     while n<m:
        lst.append(n)
        n+=2
     return lst

#the time it takes to perform sum on an iterator
t1=time.time()
sum(oddGen(1,1000000))
print("Time to sum an iterator: %f" % (time.time() - t1))
#the time it takes to build and sum a list
t1=time.time()
sum(oddLst(1,1000000))
print("Time to build and sum a list: %f" % (time.time() - t1))

```

这将打印出以下内容：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/8c1bd48e-7fc3-4d72-9e55-251c14fd0573.png)

正如我们所看到的，构建一个列表来进行这种计算需要更长的时间。使用生成器的性能改进是因为值是按需生成的，而不是保存在内存中作为列表。计算可以在所有元素生成之前开始，并且只有在需要时才生成元素。

在上面的例子中，sum 方法在需要进行计算时将每个数字加载到内存中。这是通过生成器对象重复调用`__next__()`特殊方法实现的。生成器永远不会返回除`None`之外的值。

通常，生成器对象用于 for 循环。例如，我们可以利用前面代码中创建的`oddLst`生成器函数来打印出`1`到`10`之间的奇数：

```py
for i in oddLst (1,10):print(i)
```

我们还可以创建一个**生成器表达式**，它除了用括号替换方括号外，使用与列表推导相同的语法并执行与列表推导相同的操作。然而，生成器表达式不会创建一个列表；它创建一个**生成器对象**。这个对象不会创建数据，而是根据需要创建数据。这意味着生成器对象不支持`append()`和`insert()`等序列方法。

但是，您可以使用`list()`函数将生成器转换为列表：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/b912eedf-5db9-4363-a0c1-ac65aa3b96fb.png)

# 类和对象编程

类是创建新类型对象的一种方式，它们是面向对象编程的核心。一个类定义了一组在该类的所有实例之间共享的属性。通常，类是一组函数、变量和属性。

面向对象的范式是令人信服的，因为它为我们提供了一种具体的方式来思考和表示程序的核心功能。通过围绕对象和数据而不是动作和逻辑组织我们的程序，我们有了一种强大而灵活的方式来构建复杂的应用程序。当然，动作和逻辑仍然存在，但通过将它们体现在对象中，我们有了一种封装功能的方式，允许对象以非常具体的方式改变。这使得我们的代码更少容易出错，更容易扩展和维护，并能够模拟现实世界的对象。

在 Python 中使用 class 语句创建类。这定义了与一组类实例关联的一组共享属性。一个类通常由一些方法、类变量和计算属性组成。重要的是要理解，定义一个类本身并不会创建该类的任何实例。要创建一个实例，必须将一个变量分配给一个类。类主体由一系列在类定义期间执行的语句组成。在类内部定义的函数称为**实例方法**。它们通过将该类的实例作为第一个参数传递来对类实例应用一些操作。这个参数按照惯例被称为 self，但它可以是任何合法的标识符。这里是一个简单的例子：

```py
class Employee(object):
    numEmployee=0
    def init (self,name,rate):
        self.owed=0 
        self.name=name
        self.rate=rate 
      Employee.numEmployee += 1

    def del (self): 
        Employee.numEmployee-=1

    def hours(self,numHours):
         self.owed += numHours*self.rate
         return ("%.2f hours worked" % numHours)

    def pay(self):
        self.owed=0
        return("payed %s " % self.name)
```

类变量，比如`numEmployee`，在类的所有实例之间共享值。在这个例子中，`numEmployee`用于计算员工实例的数量。请注意，`Employee`类实现了`__init__`和`__del__`特殊方法，我们将在下一节讨论。

我们可以通过以下方式创建`Employee`对象的实例，运行方法，并返回类和实例变量：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/3c5ad41c-37f0-4906-925a-5d2acef07238.png)

# 特殊方法

我们可以使用`dir(object)`函数获取特定对象的属性列表。以两个下划线开始和结束的方法称为**特殊方法**。除了以下例外，特殊方法通常由 Python 解释器调用，而不是由程序员调用；例如，当我们使用`+`运算符时，我们实际上是在调用`to _add_()`。例如，我们可以使用`len(my_object)`而不是使用`my_object._len_()`；在字符串对象上使用`len()`实际上要快得多，因为它返回表示对象在内存中的大小的值，而不是调用对象的`_len_`方法。

作为常见做法，我们在程序中实际调用的唯一特殊方法是`_init_`方法，以调用我们自己的类定义中的超类的初始化程序。强烈建议不要使用双下划线语法来定义自己的对象，因为可能会与 Python 自己的特殊方法产生当前或将来的冲突。

然而，我们可能希望在自定义对象中实现特殊方法，以赋予它们一些内置类型的行为。在下面的代码中，我们创建了一个实现了`_repr_`方法的类。这个方法创建了一个对象的字符串表示，对于检查目的很有用：

```py
class my_class():
    def __init__(self,greet):
        self.greet=greet 
    def __repr__(self):
        return 'a custom object (%r) ' % (self.greet)
```

当我们创建这个对象的实例并进行检查时，我们可以看到我们得到了我们定制的字符串表示。注意使用`%r`格式占位符返回对象的标准表示。这是有用的最佳实践，因为在这种情况下，它向我们显示`greet`对象是由引号表示的字符串：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/d231a9ec-fcf0-4387-9c07-2b9f3fecddaf.png)

# 继承

继承是面向对象编程语言中最强大的功能之一。它允许我们从其他类继承功能。通过继承，可以创建一个修改现有类行为的新类。继承意味着如果通过继承另一个类创建一个类的对象，那么该对象将具有两个类的所有功能、方法和变量；即父类和新类。我们继承功能的现有类称为父类/基类，新类称为派生/子类。

继承可以用一个非常简单的例子来解释——我们创建一个`employee`类，具有员工姓名和每小时支付的费率等属性。现在我们可以创建一个新的`specialEmployee`类，继承自`employee`类的所有属性。

在 Python 中，继承是通过在类定义中传递继承的类作为参数来完成的。它经常用于修改现有方法的行为。

`specialEmployee`类的实例与`Employee`实例相同，只是`hours()`方法发生了变化。例如，在下面的代码中，我们创建一个新的`specialEmployee`类，它继承了`Employee`类的所有功能，并且还改变了`hours()`方法：

```py
class specialEmployee(Employee):
    def hours(self,numHours):
        self.owed += numHours*self.rate*2 
        return("%.2f hours worked" % numHours)
```

为了子类定义新的类变量，需要定义一个`__init__()`方法，如下所示：

```py
class specialEmployee(Employee):
    def __init__(self,name,rate,bonus):
        Employee.__init__(self,name,rate)    #calls the base classes                                                     
        self.bonus=bonus

    def   hours(self,numHours):
        self.owed += numHours*self.rate+self.bonus     
        return("%.2f hours worked" % numHours)

```

注意，基类的方法不会自动调用，派生类需要调用它们。我们可以使用内置的`isinstance(obj1,obj2)`函数测试类成员资格。如果`obj1`属于`obj2`的类或任何派生自`obj2`的类，则返回`True`。让我们考虑以下示例来理解这一点，其中`obj1`和`obj2`分别是`Employee`和`specialEmployee`类的对象：

```py
#Example issubclass() to check whether a class is a subclass of another class  
#Example isinstance() to check if an object belongs to a class or not 

print(issubclass(specialEmployee, Employee))
print(issubclass(Employee, specialEmployee)) 

d = specialEmployee("packt", 20, 100) 
b = Employee("packt", 20)  
print(isinstance(b, specialEmployee)) 
print(isinstance(b, Employee)) 

# the output prints  
True 
False 
False 
True
```

通常，所有方法都在类内定义的实例上操作。但这不是必需的。有两种类型的方法——**静态方法**和**类方法**。静态方法与类方法非常相似，主要绑定到类，而不是与类的对象绑定。它在类内定义，不需要类的实例来执行。它不对实例执行任何操作，并且使用`@staticmethod`类装饰器定义。静态方法无法访问实例的属性，因此它们最常见的用法是作为一种方便的方式来将实用函数组合在一起。

类方法在类本身上操作，不与实例一起工作。类方法的工作方式与类变量相关联，而不是该类的实例。类方法是使用`@classmethod`装饰器定义的，并且在类中与实例方法区分开。它作为第一个参数传递，按照惯例命名为`cls`。`exponentialB`类继承自`exponentialA`类，并将基类变量更改为`4`。我们也可以运行父类的`exp()`方法如下：

```py
class exponentialA(object):
    base=3
    @classmethod
    def exp(cls,x):
        return(cls.base**x) 

    @staticmethod   def addition(x, y):  
        return (x+y)

class exponentialB(exponentialA):
        base=4

a = exponentialA() 
b= a.exp(3) 
print("the value: 3 to the power 3 is", b) 
print('The sum is:', exponentialA.addition(15, 10)) 
print(exponentialB.exp(3))

#prints the following output
the value: 3 to the power 3 is 27 
The sum is: 25 
64
```

静态方法和类方法之间的区别在于，静态方法对类一无所知，它只处理参数，而类方法仅与类一起工作，其参数始终是类本身。

类方法可能有几个有用的原因。例如，因为子类继承了其父类的所有相同特性，所以有可能会破坏继承的方法。使用类方法是定义确切运行哪些方法的一种方式。

# 数据封装和属性

除非另有规定，所有属性和方法都可以自由访问。这也意味着从基类中定义的所有内容都可以从派生类中访问。当我们构建面向对象的应用程序时，这可能会导致问题，因为我们可能希望隐藏对象的内部实现。这可能会导致派生类中定义的对象与基类之间的命名空间冲突。为了防止这种情况，我们使用双下划线定义私有属性，例如`__privateMethod()`。这些方法名称会自动更改为`__Classname_privateMethod()`，以防止与基类中定义的方法发生命名冲突。请注意，这并不严格隐藏私有属性，而只是提供了一种防止命名冲突的机制。

建议在使用类**属性**定义可变属性时使用私有属性。属性是一种属性，它在调用时不返回存储的值，而是计算其值。例如，我们可以使用以下方式重新定义`exp()`属性：

```py
class Bexp(Aexp):
    base=3
    def exp(self):
        return(x**cls.base)
```

# 摘要

本章为我们提供了 Python 编程的基本基础和介绍。我们描述了 Python 提供的各种数据结构和算法。我们涵盖了变量的使用，列表，一些控制结构，并学习了如何使用条件语句。我们还讨论了 Python 中如何使用函数。我们讨论了各种类型的对象，以及 Python 语言面向对象的一些内容。我们创建了自己的对象并从中继承。

Python 还提供了更多功能。当我们准备在后面的章节中研究一些算法的实现时，下一章将重点介绍数字、序列、映射和集合。这些也是 Python 中的数据类型，在为一系列操作组织数据时非常有用。

# 进一步阅读

+   *学习 Python* 作者：Fabrizio Romano: [`www.packtpub.com/application-development/learning-python`](https://www.packtpub.com/application-development/learning-python)。


# 第二章：Python 数据类型和结构

在本章中，我们将更详细地研究 Python 数据类型。我们已经介绍了两种数据类型，字符串和列表，`str()`和`list()`。然而，这些数据类型是不够的，我们经常需要更专门的数据对象来表示/存储我们的数据。 Python 有各种其他标准数据类型，用于存储和管理数据，我们将在本章中讨论。除了内置类型之外，还有几个内部模块，允许我们解决处理数据结构时的常见问题。首先，我们将回顾一些适用于所有数据类型的操作和表达式，并将讨论更多与 Python 数据类型相关的内容。

本章的目标如下：

+   了解 Python 3.7 支持的各种重要内置数据类型

+   探索各种高性能替代品的其他附加集合，以替代内置数据类型

# 技术要求

本章中使用的所有代码都在以下 GitHub 链接中提供：[`github.com/PacktPublishing/Hands-On-Data-Structures-and-Algorithms-with-Python-Second-Edition/tree/master/Chapter02`](https://github.com/PacktPublishing/Hands-On-Data-Structures-and-Algorithms-with-Python-Second-Edition/tree/master/Chapter02)。

# 内置数据类型

Python 数据类型可以分为三类：数字、序列和映射。还有一个表示`Null`或值的缺失的`None`对象。不应忘记其他对象，如类、文件和异常也可以被正确地视为*类型*；但是，它们在这里不会被考虑。

Python 中的每个值都有一个数据类型。与许多编程语言不同，在 Python 中，您不需要显式声明变量的类型。Python 在内部跟踪对象类型。

Python 内置数据类型概述如下表所示：

| **类别** | **名称** | **描述** |
| --- | --- | --- |
| None | `None` | 它是一个空对象。 |
| 数字 | `int` | 这是一种整数数据类型。 |
|  | `float` | 这种数据类型可以存储浮点数。 |
|  | `complex` | 它存储复数。 |
|  | `bool` | 它是布尔类型，返回`True`或`False`。 |
| 序列 | `str` | 用于存储一串字符。 |
|  | `liXst` | 它可以存储任意对象的列表。 |
|  | `Tuple` | 它可以存储一组任意项目。 |
|  | `range` | 用于创建一系列整数。 |
| 映射 | `dict` | 它是一种以*键/值*对存储数据的字典数据类型。 |
|  | `set` | 它是一个可变的无序唯一项集合。 |
|  | `frozenset` | 它是一个不可变的集合。 |

# None 类型

`None`类型是不可变的。它用作`None`来表示值的缺失；它类似于许多编程语言中的`null`，如 C 和 C++。当实际上没有要返回的内容时，对象返回`None`。当`False`布尔表达式时，也会返回`None`。`None`经常用作函数参数的默认值，以检测函数调用是否传递了值。

# 数字类型

数字类型包括整数（`int`），即无限范围的整数，浮点数（`float`），复数（`complex`），由两个浮点数表示，以及布尔值（`bool`）在 Python 中。 Python 提供了允许标准算术运算符（`+`，`-`，`*`和`/`）对它们进行操作的`int`数据类型，类似于其他编程语言。布尔数据类型有两个可能的值，`True`和`False`。这些值分别映射为`1`和`0`。让我们考虑一个例子：

```py
>>> a=4; b=5   # Operator (=) assigns the value to variable
>>>print(a, "is of type", type(a))
4 is of type 
<class 'int'>
>>> 9/5  
1.8
>>>c= b/a  *# division returns a floating point number* *>>>* print(c, "is of type", type(c))
1.25 is of type <class 'float'>
>>> c   # No need to explicitly declare the datatype
1.25
```

变量`a`和`b`是`int`类型，`c`是浮点类型。除法运算符（`/`）始终返回`float`类型；但是，如果希望在除法后获得`int`类型，可以使用地板除法运算符（`//`），它会丢弃任何小数部分，并返回小于或等于`x`的最大整数值。考虑以下例子：

```py
>>> a=4; b=5   
>>>d= b//a
*>>>* print(d, "is of type", type(d))1 is of type <class 'int'>
>>>7/5  # true division
1.4
>>> -7//5  # floor division operator
-2
```

建议读者谨慎使用除法运算符，因为其功能根据 Python 版本而异。在 Python 2 中，除法运算符仅返回`integer`，而不是`float`。

指数运算符（`**`）可用于获取数字的幂（例如，`x ** y`），模数运算符（`%`）返回除法的余数（例如，`a% b`返回`a/b`的余数）：

```py
>>> a=7; b=5 
>>> e= b**a  # The operator (**)calculates power 
>>>e
78125
>>>a%b
2
```

复数由两个浮点数表示。它们使用`j`运算符分配，以表示复数的虚部。我们可以通过`f.real`和`f.imag`访问实部和虚部，如下面的代码片段所示。复数通常用于科学计算。Python 支持复数的加法，减法，乘法，幂，共轭等，如下所示：

```py
>>> f=3+5j
>>>print(f, "is of type", type(f))(3+5j) is of type <class 'complex'>
>>> f.real
3.0
>>> f.imag
5.0
>>> f*2   # multiplication
(6+10j)
>>> f+3  # addition
(6+5j)
>>> f -1  # subtraction
(2+5j)  
```

在 Python 中，布尔类型使用真值表示，即`True`和`False`；这类似于`0`和`1`。Python 中有一个`bool`类，返回`True`或`False`。布尔值可以与逻辑运算符（如`and`，`or`和`not`）结合使用：

```py
>>>bool(2)
True
>>>bool(-2)
True
>>>bool(0)
False
```

布尔运算返回`True`或`False`。布尔运算按优先级排序，因此如果表达式中出现多个布尔运算，则优先级最高的运算将首先发生。以下表格按优先级降序列出了三个布尔运算符：

| **运算符** | **示例** |
| --- | --- |
| `not x` | 如果`x`为`True`，则返回`False`，如果`x`为`False`，则返回`True`。 |
| `x and y` | 如果`x`和`y`都为`True`，则返回`True`；否则返回`False`。 |
| `x or` `y` | 如果`x`或`y`中有一个为`True`，则返回`True`；否则返回`False`。 |

Python 在评估布尔表达式时非常高效，因为它只在需要时评估运算符。例如，如果在表达式`x or y`中`x`为`True`，则无需评估`y`，因为表达式无论如何都是`True`，这就是为什么在 Python 中不会评估`y`。类似地，在表达式`x and y`中，如果`x`为`False`，解释器将简单地评估`x`并返回`False`，而不会评估`y`。

比较运算符（`<`，`<=`，`>`，`>=`，`==`和`!=`）适用于数字，列表和其他集合对象，并在条件成立时返回`True`。对于集合对象，比较运算符比较元素的数量，等价运算符（`==`）在每个集合对象在结构上等价且每个元素的值相同时返回`True`。让我们看一个例子：

```py
>>>See_boolean = (4 * 3 > 10) and (6 + 5 >= 11)
>>>print(See_boolean)
True
>>>if (See_boolean):
...    print("Boolean expression returned True")
   else:
...  print("Boolean expression returned False")
...

Boolean expression returned True
```

# 表示错误

应该注意的是，浮点数的本机双精度表示会导致一些意外的结果。例如，考虑以下情况：

```py
>>> 1-0.9
0.09999999999999998
>>> 1-0.9==.1
False
```

这是因为大多数十进制小数无法准确表示为二进制小数，这是大多数底层硬件表示浮点数的方式。对于可能存在此问题的算法或应用程序，Python 提供了一个 decimal 模块。该模块允许精确表示十进制数，并便于更好地控制属性，如舍入行为，有效数字的数量和精度。它定义了两个对象，一个表示十进制数的`Decimal`类型，另一个表示各种计算参数的`Context`类型，如精度，舍入和错误处理。其用法示例如下：

```py
>>> import decimal
>>> x=decimal.Decimal(3.14)
>>> y=decimal.Decimal(2.74)
>>> x*y
Decimal('8.603600000000001010036498883')
>>> decimal.getcontext().prec=4
>>> x*y
Decimal('8.604')
```

在这里，我们创建了一个全局上下文，并将精度设置为`4`。`Decimal`对象可以被视为`int`或`float`一样对待。它们可以进行相同的数学运算，并且可以用作字典键，放置在集合中等等。此外，`Decimal`对象还有几种数学运算的方法，如自然指数`x.exp()`，自然对数`x.ln()`和以 10 为底的对数`x.log10()`。

Python 还有一个`fractions`模块，实现了有理数类型。以下示例展示了创建分数的几种方法：

```py
>>> import fractions
>>> fractions.Fraction(3,4)
Fraction(3, 4)
>>> fractions.Fraction(0.5)
Fraction(1, 2)
>>> fractions.Fraction("0.25") 
Fraction(1, 4)
```

在这里还值得一提的是 NumPy 扩展。它具有数学对象的类型，如数组、向量和矩阵，以及线性代数、傅里叶变换、特征向量、逻辑操作等功能。

# 成员资格、身份和逻辑操作

成员资格运算符（`in`和`not in`）用于测试序列中的变量，如列表或字符串，并执行您所期望的操作；如果在`y`中找到了`x`变量，则`x in y`返回`True`。`is`运算符比较对象标识。例如，以下代码片段展示了对比等价性和对象标识：

```py
>>> x=[1,2,3]
>>> y=[1,2,3]
>>> x==y  # test equivalence 
True
>>> x is y   # test object identity
False
>>> x=y   # assignment
>>> x is y
True
```

# 序列

序列是由非负整数索引的对象的有序集合。序列包括`string`、`list`、`tuple`和`range`对象。列表和元组是任意对象的序列，而字符串是字符的序列。然而，`string`、`tuple`和`range`对象是不可变的，而`list`对象是可变的。所有序列类型都有许多共同的操作。请注意，对于不可变类型，任何操作都只会返回一个值，而不会实际更改该值。

对于所有序列，索引和切片操作适用于前一章节中描述的方式。`string`和`list`数据类型在第一章中有详细讨论，*Python 对象、类型和表达式*。在这里，我们介绍了一些对所有序列类型（`string`、`list`、`tuple`和`range`对象）都通用的重要方法和操作。

所有序列都有以下方法：

| **方法** | **描述** |
| --- | --- |
| `len(s)` | 返回`s`中元素的数量。 |
| `min(s,[,default=obj, key=func])` | 返回`s`中的最小值（对于字符串来说是按字母顺序）。 |
| `max(s,[,default=obj, key=func])` | 返回`s`中的最大值（对于字符串来说是按字母顺序）。 |
| `sum(s,[,start=0])` | 返回元素的和（如果`s`不是数字，则返回`TypeError`）。 |
| `all(s)` | 如果`s`中所有元素都为`True`（即不为`0`、`False`或`Null`），则返回`True`。 |
| `any(s)` | 检查`s`中是否有任何项为`True`。 |

此外，所有序列都支持以下操作：

| **操作** | **描述** |
| --- | --- |
| `s+r` | 连接两个相同类型的序列。 |
| `s*n` | 创建`n`个`s`的副本，其中`n`是整数。 |
| `v1,v2...,vn=s` | 从`s`中解包`n`个变量到`v1`、`v2`等。 |
| `s[i]` | 索引返回`s`的第`i`个元素。 |
| `s[i:j:stride]` | 切片返回`i`和`j`之间的元素，可选的步长。 |
| `x in s` | 如果`s`中存在`x`元素，则返回`True`。 |
| `x not in s` | 如果`s`中不存在`x`元素，则返回`True`。 |

让我们考虑一个示例代码片段，实现了对`list`数据类型的一些前述操作：

```py
>>>list() # an empty list   
>>>list1 = [1,2,3, 4]
>>>list1.append(1)  # append value 1 at the end of the list
>>>list1
[1, 2, 3, 4, 1]
>>>list2 = list1 *2    
[1, 2, 3, 4, 1, 1, 2, 3, 4, 1]
>>> min(list1)
1
>>> max(list1)
4
>>>list1.insert(0,2)  # insert an value 2 at index 0
>>> list1
[2, 1, 2, 3, 4, 1]
>>>list1.reverse()
>>> list1
[1, 4, 3, 2, 1, 2]
>>>list2=[11,12]
>>>list1.extend(list2)
>>> list1
[1, 4, 3, 2, 1, 2, 11, 12]
>>>sum(list1)
36
>>> len(list1)
8
>>> list1.sort()
>>> list1
[1, 1, 2, 2, 3, 4, 11, 12]
>>>list1.remove(12)   #remove value 12 form the list
>>> list1
[1, 1, 2, 2, 3, 4, 11]
```

# 了解元组

元组是任意对象的不可变序列。元组是一个逗号分隔的值序列；然而，通常的做法是将它们括在括号中。当我们想要在一行中设置多个变量，或者允许函数返回不同对象的多个值时，元组非常有用。元组是一种有序的项目序列，类似于`list`数据类型。唯一的区别是元组是不可变的；因此，一旦创建，它们就不能被修改，不像`list`。元组由大于零的整数索引。元组是**可散列**的，这意味着我们可以对它们的列表进行排序，并且它们可以用作字典的键。

我们还可以使用内置函数`tuple()`创建一个元组。如果没有参数，这将创建一个空元组。如果`tuple()`的参数是一个序列，那么这将创建一个由该序列元素组成的元组。在创建只有一个元素的元组时，重要的是要记住使用尾随逗号——没有尾随逗号，这将被解释为一个字符串。元组的一个重要用途是通过在赋值的左侧放置一个元组来一次性分配多个变量。

考虑一个例子：

```py
>>> t= tuple()   # create an empty tuple
>>> type(t)
<class 'tuple'>
>>> t=('a',)  # create a tuple with 1 element
>>> t
('a',)
>>> print('type is ',type(t))
type is  <class 'tuple'>
>>> tpl=('a','b','c')
>>> tpl('a', 'b', 'c')
>>> tuple('sequence')
('s', 'e', 'q', 'u', 'e', 'n', 'c', 'e')
>>> x,y,z= tpl   #multiple assignment 
>>> x
'a'
>>> y
'b'
>>> z
'c'
>>> 'a' in tpl  # Membership can be tested
True
>>> 'z' in tpl
False
```

大多数运算符，如切片和索引运算符，都像列表一样工作。然而，由于元组是不可变的，尝试修改元组的元素会导致`TypeError`。我们可以像比较其他序列一样比较元组，使用`==`、`>`和`<`运算符。考虑一个示例代码片段：

```py
>>> tupl = 1, 2,3,4,5  # braces are optional
>>>print("tuple value at index 1 is ", tupl[1])
tuple value at index 1 is  2
>>> print("tuple[1:3] is ", tupl[1:3])
tuple[1:3] is (2, 3)
>>>tupl2 = (11, 12,13)
>>>tupl3= tupl + tupl2   # tuple concatenation
>>> tupl3
(1, 2, 3, 4, 5, 11, 12, 13)
>>> tupl*2      # repetition for tuples
(1, 2, 3, 4, 5, 1, 2, 3, 4, 5)
>>> 5 in tupl    # membership test
True
>>> tupl[-1]     # negative indexing
5
>>> len(tupl)   # length function for tuple
5
>>> max(tupl)
5
>>> min(tupl)
1
>>> tupl[1] = 5 # modification in tuple is not allowed.
Traceback (most recent call last):  
  File "<stdin>", line 1, in <module>
TypeError: 'tuple' object does not support item assignment
>>>print (tupl== tupl2)
False
>>>print (tupl>tupl2)
False
```

让我们考虑另一个例子来更好地理解元组。例如，我们可以使用多个赋值来交换元组中的值：

```py
>>> l = ['one','two']
>>> x,y = l
('one', 'two')
>>> x,y = y,x
>>> x,y
('two', 'one')
```

# 从字典开始

在 Python 中，`字典`数据类型是最受欢迎和有用的数据类型之一。字典以键和值对的映射方式存储数据。字典主要是对象的集合；它们由数字、字符串或任何其他不可变对象索引。字典中的键应该是唯一的；然而，字典中的值可以被更改。Python 字典是唯一的内置映射类型；它们可以被看作是从一组键到一组值的映射。它们使用`{key:value}`的语法创建。例如，以下代码可以用来创建一个将单词映射到数字的字典，使用不同的方法：

```py
>>>a= {'Monday':1,'Tuesday':2,'Wednesday':3} #creates a dictionary 
>>>b =dict({'Monday':1 , 'Tuesday': 2, 'Wednesday': 3})
>>> b
{'Monday': 1, 'Tuesday': 2, 'Wednesday': 3}
>>> c= dict(zip(['Monday','Tuesday','Wednesday'], [1,2,3]))
>>> c={'Monday': 1, 'Tuesday': 2, 'Wednesday': 3}
>>> d= dict([('Monday',1), ('Tuesday',2), ('Wednesday',3)])
>>>d
{'Monday': 1, 'Tuesday': 2, 'Wednesday': 3}
```

我们可以添加键和值。我们还可以更新多个值，并使用`in`运算符测试值的成员资格或出现情况，如下面的代码示例所示：

```py
>>>d['Thursday']=4     #add an item
>>>d.update({'Friday':5,'Saturday':6})  #add multiple items
>>>d
{'Monday': 1, 'Tuesday': 2, 'Wednesday': 3, 'Thursday': 4, 'Friday': 5, 'Saturday': 6}
>>>'Wednesday' in d  # membership test (only in keys)
True
>>>5 in d       # membership do not check in values
False

```

如果列表很长，使用`in`运算符在列表中查找元素会花费太多时间。在列表中查找元素所需的运行时间随着列表大小的增加而线性增加。而字典中的`in`运算符使用哈希函数，这使得字典非常高效，因为查找元素所花费的时间与字典的大小无关。

注意当我们打印字典的`{key: value}`对时，它并没有按特定顺序进行。这不是问题，因为我们使用指定的键来查找每个字典值，而不是一个有序的整数序列，就像对字符串和列表一样：

```py
>>> dict(zip('packt', range(5)))
{'p': 0, 'a': 1, 'c': 2, 'k': 3, 't': 4}
>>> a = dict(zip('packt', range(5)))
>>> len(a)   # length of dictionary a
5
>>> a['c']  # to check the value of a key
2
>>> a.pop('a')  
1
>>> a{'p': 0, 'c': 2, 'k': 3, 't': 4}
>>> b= a.copy()   # make a copy of the dictionary
>>> b
{'p': 0, 'c': 2, 'k': 3, 't': 4}
>>> a.keys()
dict_keys(['p', 'c', 'k', 't'])
>>> a.values()
dict_values([0, 2, 3, 4])
>>> a.items()
dict_items([('p', 0), ('c', 2), ('k', 3), ('t', 4)])
>>> a.update({'a':1})   # add an item in the dictionary
>>> a{'p': 0, 'c': 2, 'k': 3, 't': 4, 'a': 1}
>>> a.update(a=22)  # update the value of key 'a'
>>> a{'p': 0, 'c': 2, 'k': 3, 't': 4, 'a': 22}

```

以下表格包含了所有字典方法及其描述：

| **方法** | **描述** |
| --- | --- |
| `len(d)` | 返回字典`d`中的项目总数。 |
| `d.clear()` | 从字典`d`中删除所有项目。 |
| `d.copy()` | 返回字典`d`的浅拷贝。 |
| `d.fromkeys(s[,value])` | 返回一个新字典，其键来自序列`s`，值设置为`value`。 |
| `d.get(k[,v])` | 如果找到，则返回`d[k]`；否则返回`v`（如果未给出`v`，则返回`None`）。 |
| `d.items()` | 返回字典`d`的所有`键:值`对。 |
| `d.keys()` | 返回字典`d`中定义的所有键。 |
| `d.pop(k[,default])` | 返回`d[k]`并从`d`中删除它。 |
| `d.popitem()` | 从字典`d`中删除一个随机的`键:值`对，并将其作为元组返回。 |
| `d.setdefault(k[,v])` | 返回`d[k]`。如果找不到，它返回`v`并将`d[k]`设置为`v`。 |
| `d.update(b)` | 将`b`字典中的所有对象添加到`d`字典中。 |
| `d.values()` | 返回字典`d`中的所有值。 |

# Python

应该注意，当将`in`运算符应用于字典时，其工作方式与应用于列表时略有不同。当我们在列表上使用`in`运算符时，查找元素所需的时间与列表的大小之间的关系被认为是线性的。也就是说，随着列表的大小变大，找到元素所需的时间最多是线性增长的。算法运行所需的时间与其输入大小之间的关系通常被称为其时间复杂度。我们将在接下来的章节中更多地讨论这个重要的主题。

与`list`对象相反，当`in`运算符应用于字典时，它使用哈希算法，这会导致每次查找时间的增加几乎独立于字典的大小。这使得字典作为处理大量索引数据的一种方式非常有用。我们将在第四章和第十四章中更多地讨论这个重要主题，即哈希的增长率。

# 对字典进行排序

如果我们想对字典的键或值进行简单的排序，我们可以这样做：

```py
>>> d = {'one': 1, 'two': 2, 'three': 3, 'four': 4, 'five': 5, 'six': 6} 
>>> sorted(list(d)) 
['five', 'four', 'one', 'six', 'three', 'two']  
>>> sorted(list(d.values())) 
[1, 2, 3, 4, 5, 6] 

```

请注意，前面代码中的第一行按字母顺序对键进行排序，第二行按整数值的顺序对值进行排序。

`sorted()`方法有两个感兴趣的可选参数：`key`和`reverse`。`key`参数与字典键无关，而是一种传递函数给排序算法以确定排序顺序的方法。例如，在下面的代码中，我们使用`__getitem__`特殊方法根据字典的值对字典键进行排序：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/f060180f-67e3-4a18-a2cf-de92fa784c2c.png)

基本上，前面的代码对`d`中的每个键使用相应的值进行排序。我们也可以根据字典键的排序顺序对值进行排序。然而，由于字典没有一种方法可以通过其值返回一个键，就像列表的`list.index`方法一样，使用可选的`key`参数来做到这一点有点棘手。另一种方法是使用列表推导式，就像下面的例子演示的那样：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/8d05572b-0a3c-4320-9d9c-b6cf38b5243e.png)

`sorted()`方法还有一个可选的`reverse`参数，毫不奇怪，它确实做到了它所说的—反转排序列表的顺序，就像下面的例子一样：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/bf6f08ee-d55a-4c47-8424-f493cbe2fc19.png)

现在，假设我们有以下字典，其中英语单词作为键，法语单词作为值。我们的任务是将字符串值放在正确的数字顺序中：

```py
d2={'one':'uno','two':'deux','three':'trois','four':'quatre','five':'cinq','six':'six'}
```

当然，当我们打印这个字典时，它可能不会按正确的顺序打印。因为所有的键和值都是字符串，我们没有数字顺序的上下文。为了将这些项目放在正确的顺序中，我们需要使用我们创建的第一个字典，将单词映射到数字作为对英语到法语字典进行排序的一种方式：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/06a4e849-5cde-45c4-893c-d2182152f278.png)

请注意，我们正在使用第一个字典`d`的值来对第二个字典`d2`的键进行排序。由于我们两个字典中的键是相同的，我们可以使用列表推导式来对法语到英语字典的值进行排序：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/25cc0171-9321-4d8f-8b78-aafc7196f837.png)

当然，我们可以定义自己的自定义方法，然后将其用作排序方法的关键参数。例如，在这里，我们定义一个简单地返回字符串的最后一个字母的函数：

```py
def corder(string): 
    return (string[len(string)-1])
```

然后，我们可以将其用作排序函数的关键，按其最后一个字母对每个元素进行排序：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/95c948bf-cd5b-4254-add5-e98835006e00.png)

# 文本分析的字典

字典的常见用途是计算序列中相似项的出现次数；一个典型的例子是计算文本中单词的出现次数。以下代码创建了一个字典，其中文本中的每个单词都用作键，出现次数作为其值。这使用了一个非常常见的嵌套循环习语。在这里，我们使用它来遍历文件中的行的外部循环和字典的键的内部循环：

```py
def wordcount(fname):  
   try: 
        fhand=open(fname) 
   except:
        print('File can not be opened') 
        exit() 

   count=dict() 
   for line in fhand: 
        words=line.split() 
        for word in words: 
            if word not in count: 
                count[word]=1  
            else: 
                count[word]+=1 
   return(count)

```

这将返回一个字典，其中每个唯一单词在文本文件中都有一个元素。一个常见的任务是将这些项目过滤成我们感兴趣的子集。您需要在运行代码的同一目录中保存一个文本文件。在这里，我们使用了`alice.txt`，这是《爱丽丝梦游仙境》的一个简短摘录。要获得相同的结果，您可以从[davejulian.net/bo5630](http://davejulian.net/bo5630)下载`alice.txt`，或者使用您自己的文本文件。在下面的代码中，我们创建了另一个字典`filtered`，其中包含来自`count`的子集：

```py
count=wordcount('alice.txt') 
filtered={key:value for key, value in count.items() if value <20 and value>16 }
```

当我们打印过滤字典时，我们得到以下结果：

```py
{'once': 18, 'eyes': 18, 'There': 19, 'this,': 17, 'before': 19, 'take': 18, 'tried': 18, 'even': 17, 'things': 19, 'sort': 17, 'her,': 18, '`And': 17, 'sat': 17, '`But': 19, "it,'": 18, 'cried': 18, '`Oh,': 19, 'and,': 19, "`I'm": 19, 'voice': 17, 'being': 19, 'till': 19, 'Mouse': 17, '`but': 19, 'Queen,': 17}
```

请注意使用**字典推导**来构建过滤字典。字典推导的工作方式与我们在第一章中看到的列表推导相同，即*Python 对象、类型和表达式*。

# 集合

集合是无序的唯一项集合。集合本身是可变的——我们可以向其中添加和删除项目；但是，项目本身必须是不可变的。集合的一个重要区别是它们不能包含重复的项目。集合通常用于执行诸如交集、并集、差集和补集等数学运算。

与序列类型不同，集合类型不提供任何索引或切片操作。Python 中有两种类型的集合对象，可变的`set`对象和不可变的`frozenset`对象。使用花括号内的逗号分隔的值创建集合。顺便说一句，我们不能使用`a={}`创建一个空集，因为这将创建一个字典。要创建一个空集，我们要么写`a=set()`，要么写`a=frozenset()`。

集合的方法和操作描述在下表中：

| **方法** | **描述** |
| --- | --- |
| `len(a)` | 提供了`a`集合中元素的总数。 |
| `a.copy()` | 提供了`a`集合的另一个副本。 |
| `a.difference(t)` | 提供了`a`集合中存在但不在`t`中的元素的集合。 |
| `a.intersection(t)` | 提供了两个集合`a`和`t`中都存在的元素的集合。 |
| `a.isdisjoint(t)` | 如果两个集合`a`和`t`中没有共同的元素，则返回`True`。 |
| `a.issubset(t)` | 如果`a`集合的所有元素也在`t`集合中，则返回`True`。 |
| `a.issuperset(t)` | 如果`t`集合的所有元素也在`a`集合中，则返回`True`。 |
| `a.symmetric_difference(t)` | 返回一个既在`a`集合中又在`t`集合中的元素的集合，但不在两者中都存在。 |
| `a.union(t)` | 返回一个既在`a`集合中又在`t`集合中的元素的集合。 |

在上表中，参数`t`可以是任何支持迭代的 Python 对象，所有方法都适用于`set`和`frozenset`对象。重要的是要意识到这些方法的操作符版本要求它们的参数是集合，而方法本身可以接受任何可迭代类型。例如，对于任何集合`s`，`s-[1,2,3]`将生成不支持的操作数类型。使用等效的`s.difference([1,2,3])`将返回一个结果。

可变的`set`对象具有其他方法，如下表所述：

| **方法** | **描述** |
| --- | --- |
| `s.add(item)` | 将项目添加到`s`；如果项目已经添加，则不会发生任何事情。 |
| `s.clear()` | 从集合`s`中删除所有元素。 |
| `s.difference_update(t)` | 从`s`集合中删除那些也在其他集合`t`中的元素。 |
| `s.discard(item)` | 从集合`s`中删除项目。 |
| `s.intersection_update(t)` | 从集合`s`中删除不在集合`s`和`t`的交集中的项目。 |
| `s.pop()` | 从集合`s`中返回一个任意项目，并从`s`集合中删除它。 |
| `s.remove(item)` | 从`s`集合中删除项目。 |
| `s.symetric_difference_update(t)` | 从集合`s`中删除不在集合`s`和`t`的对称差集中的所有元素。 |
| `s.update(t)` | 将可迭代对象`t`中的所有项目附加到`s`集合。 |

在这里，考虑一个简单的示例，显示了添加、删除、丢弃和清除操作：

```py
>>> s1 = set()
>>> s1.add(1)
>>> s1.add(2)
>>> s1.add(3)
>>> s1.add(4)
>>> s1
{1, 2, 3, 4}
>>> s1.remove(4)
>>> s1
{1, 2, 3}
>>> s1.discard(3)
>>> s1
{1, 2}
>>>s1.clear()
>>>s1
set()
```

以下示例演示了一些简单的集合操作及其结果：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/1a0c26a1-0555-49b8-8608-248609446dc5.png)

请注意，`set`对象不在乎其成员不全是相同类型，只要它们都是不可变的。如果您尝试在集合中使用可变对象，例如列表或字典，您将收到一个不可哈希类型错误。可哈希类型都有一个哈希值，在实例的整个生命周期中不会改变。所有内置的不可变类型都是可哈希的。所有内置的可变类型都不可哈希，因此不能用作集合的元素或字典的键。

还要注意在前面的代码中，当我们打印出`s1`和`s2`的并集时，只有一个值为`'ab'`的元素。这是集合的一个自然属性，它们不包括重复项。

除了这些内置方法之外，我们还可以对集合执行许多其他操作。例如，要测试集合的成员资格，请使用以下方法：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/5c5e5c1a-63b6-4006-afac-81716a723380.png)

我们可以使用以下方法循环遍历集合中的元素：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/2399773c-55a5-49a9-9a07-415c66c31853.png)

# 不可变集合

Python 有一个名为`frozenset`的不可变集合类型。它的工作方式几乎与`set`完全相同，除了不允许更改值的方法或操作，例如`add()`或`clear()`方法。这种不可变性有几种有用之处。

例如，由于普通集合是可变的，因此不可哈希，它们不能用作其他集合的成员。另一方面，`frozenset`是不可变的，因此可以用作集合的成员：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/a230c9f0-720b-45ec-b2d3-42635c4e0682.png)

此外，`frozenset`的不可变属性意味着我们可以将其用作字典的键，如下例所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/b92757f5-6d64-4355-866e-0cdb00e71f53.png)

# 数据结构和算法的模块

除了内置类型之外，还有几个 Python 模块可以用来扩展内置类型和函数。在许多情况下，这些 Python 模块可能提供效率和编程优势，使我们能够简化我们的代码。

到目前为止，我们已经查看了字符串、列表、集合和字典的内置数据类型，以及十进制和分数模块。它们通常被术语**抽象数据类型**（**ADT**）描述。 ADT 可以被认为是可以在数据上执行的操作集的数学规范。它们由其行为而不是其实现来定义。除了我们已经查看的 ADT 之外，还有几个 Python 库提供了对内置数据类型的扩展。这将在下一节中讨论。

# 集合

`collections`模块提供了更专门的、高性能的替代品，用于内置数据类型，以及一个实用函数来创建命名元组。以下表列出了`collections`模块的数据类型和操作及其描述：

| **数据类型或操作** | **描述** |
| --- | --- |
| `namedtuple()` | 创建具有命名字段的元组子类。 |
| `deque` | 具有快速追加和弹出的列表。 |
| `ChainMap` | 类似字典的类，用于创建多个映射的单个视图。 |
| `Counter` | 用于计算可散列对象的字典子类。 |
| `OrderedDict` | 记住条目顺序的字典子类。 |
| `defaultdict` | 调用函数以提供缺失值的字典子类。 |
| `UserDict UserList UserString` | 这三种数据类型只是它们基础基类的简单包装器。它们的使用在很大程度上已被能够直接对其各自的基类进行子类化所取代。可以用来作为属性访问基础对象。 |

# 双端队列

双端队列，通常发音为*decks*，是类似列表的对象，支持线程安全、内存高效的追加。双端队列是可变的，并支持列表的一些操作，如索引。双端队列可以通过索引分配，例如，`dq[1] = z`；但是，我们不能直接切片双端队列。例如，`dq[1:2]`会导致`TypeError`（我们将看一种从双端队列返回切片作为列表的方法）。

双端队列比列表的主要优势在于，在双端队列的开头插入项目要比在列表的开头插入项目快得多，尽管在双端队列的末尾插入项目的速度比列表上的等效操作略慢一些。双端队列是线程安全的，并且可以使用`pickle`模块进行序列化。

一个有用的思考双端队列的方式是填充和消耗项目。双端队列中的项目通常是从两端顺序填充和消耗的：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/bdd5dc25-b4ee-4f13-80dd-c2e7b82634c1.png)

我们可以使用`pop()`和`popleft()`方法来消耗双端队列中的项目，如下例所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/13e07836-1988-41fc-ba5a-aa3b008691b0.png)

我们还可以使用`rotate(n)`方法将所有项目向右移动和旋转`n`步，对于`n`整数的正值或`n`步的负值向左移动，使用正整数作为参数，如下例所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/bb9cb7b6-1956-438a-b247-b56375078185.png)

请注意，我们可以使用`rotate`和`pop`方法来删除选定的元素。还值得知道的是，返回双端队列切片的简单方法，可以按以下方式完成：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/811e6dec-b990-403d-a4a2-02d5214f0f38.png)

`itertools.islice()`方法的工作方式与列表上的切片相同，只是它不是以列表作为参数，而是以可迭代对象作为参数，并返回所选值，按起始和停止索引，作为列表。

双端队列的一个有用特性是它们支持一个`maxlen`可选参数，用于限制双端队列的大小。这使得它非常适合一种称为**循环缓冲区**的数据结构。这是一种固定大小的结构，实际上是端对端连接的，它们通常用于缓冲数据流。以下是一个基本示例：

```py
dq2=deque([],maxlen=3) 
for i in range(6):
    dq2.append(i) 
    print(dq2)
```

这将打印出以下内容：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/2d67615b-9051-493c-9727-6a2f6244f6f1.png)

在这个例子中，我们从右侧填充并从左侧消耗。请注意，一旦缓冲区已满，最旧的值将首先被消耗，然后从右侧替换值。在第四章中，当实现循环列表时，我们将再次看循环缓冲区。

# ChainMap 对象

`collections.chainmap`类是在 Python 3.2 中添加的，它提供了一种将多个字典或其他映射链接在一起，以便它们可以被视为一个对象的方法。此外，还有一个`maps`属性，一个`new_child()`方法和一个`parents`属性。`ChainMap`对象的基础映射存储在列表中，并且可以使用`maps[i]`属性来检索第`i`个字典。请注意，尽管字典本身是无序的，`ChainMap`对象是有序的字典列表。

`ChainMap`在使用包含相关数据的多个字典的应用程序中非常有用。消费应用程序期望按优先级获取数据，如果两个字典中的相同键出现在基础列表的开头，则该键将优先考虑。`ChainMap`通常用于模拟嵌套上下文，例如当我们有多个覆盖配置设置时。以下示例演示了`ChainMap`的可能用例：

```py
>>> import collections
>>> dict1= {'a':1, 'b':2, 'c':3}
>>> dict2 = {'d':4, 'e':5}
>>> chainmap = collections.ChainMap(dict1, dict2)  # linking two dictionaries
>>> chainmap
ChainMap({'a': 1, 'b': 2, 'c': 3}, {'d': 4, 'e': 5})
>>> chainmap.maps
[{'a': 1, 'b': 2, 'c': 3}, {'d': 4, 'e': 5}]
>>> chainmap.values
<bound method Mapping.values of ChainMap({'a': 1, 'b': 2, 'c': 3}, {'d': 4, 'e': 5})
>>>> chainmap['b']   #accessing values 
2
>>> chainmap['e']
5
```

使用`ChainMap`对象而不仅仅是字典的优势在于我们保留了先前设置的值。添加子上下文会覆盖相同键的值，但不会从数据结构中删除它。当我们需要保留更改记录以便可以轻松回滚到先前的设置时，这可能很有用。

我们可以通过为`map()`方法提供适当的索引来检索和更改任何字典中的任何值。此索引表示`ChainMap`中的一个字典。此外，我们可以使用`parents()`方法检索父设置，即默认设置：

```py
>>> from collections import ChainMap
>>> defaults= {'theme':'Default','language':'eng','showIndex':True, 'showFooter':True}
>>> cm= ChainMap(defaults)   #creates a chainMap with defaults configuration
>>> cm.maps[{'theme': 'Default', 'language': 'eng', 'showIndex': True, 'showFooter': True}]
>>> cm.values()
ValuesView(ChainMap({'theme': 'Default', 'language': 'eng', 'showIndex': True, 'showFooter': True}))
>>> cm2= cm.new_child({'theme':'bluesky'}) # create a new chainMap with a child that overrides the parent.
>>> cm2['theme']  #returns the overridden theme'bluesky'
>>> cm2.pop('theme')  # removes the child theme value
'bluesky' 
>>> cm2['theme']
'Default'
>>> cm2.maps[{}, {'theme': 'Default', 'language': 'eng', 'showIndex': True, 'showFooter': True}]
>>> cm2.parents
ChainMap({'theme': 'Default', 'language': 'eng', 'showIndex': True, 'showFooter': True})
```

# 计数器对象

`Counter`是字典的一个子类，其中每个字典键都是可散列对象，关联的值是该对象的整数计数。有三种初始化计数器的方法。我们可以将任何序列对象、`key:value`对的字典或格式为`(object=value,...)`的元组传递给它，如下例所示：

```py
>>> from collections import Counter
>>> Counter('anysequence')
Counter({'e': 3, 'n': 2, 'a': 1, 'y': 1, 's': 1, 'q': 1, 'u': 1, 'c': 1})
>>> c1 = Counter('anysequence')
>>> c2= Counter({'a':1, 'c': 1, 'e':3})
>>> c3= Counter(a=1, c= 1, e=3)
>>> c1
Counter({'e': 3, 'n': 2, 'a': 1, 'y': 1, 's': 1, 'q': 1, 'u': 1, 'c': 1})
>>> c2
Counter({'e': 3, 'a': 1, 'c': 1})
>>> c3
Counter({'e': 3, 'a': 1, 'c': 1})
```

我们还可以创建一个空的计数器对象，并通过将其`update`方法传递给一个可迭代对象或字典来填充它。请注意，`update`方法添加计数，而不是用新值替换它们。填充计数器后，我们可以以与字典相同的方式访问存储的值，如下例所示：

```py
>>> from collections import Counter
>>> ct = Counter()  # creates an empty counter object
>>> ct
Counter()
>>> ct.update('abca') # populates the object
>>> ct
Counter({'a': 2, 'b': 1, 'c': 1})
>>> ct.update({'a':3}) # update the count of 'a'
>>> ct
Counter({'a': 5, 'b': 1, 'c': 1})
>>> for item in ct:
 ...  print('%s: %d' % (item, ct[item]))
 ...
a: 5
b: 1
c: 1
```

计数器对象和字典之间最显着的区别是计数器对象对于缺失的项返回零计数，而不是引发键错误。我们可以使用其`elements()`方法从`Counter`对象创建迭代器。这将返回一个迭代器，其中不包括小于一的计数，并且顺序不被保证。在下面的代码中，我们执行一些更新，从`Counter`元素创建一个迭代器，并使用`sorted()`按字母顺序对键进行排序：

```py
>>> ct
Counter({'a': 5, 'b': 1, 'c': 1})
>>> ct['x']
0
>>> ct.update({'a':-3, 'b':-2, 'e':2})
>>> ct
Counter({'a': 2, 'e': 2, 'c': 1, 'b': -1})
>>>sorted(ct.elements())
['a', 'a', 'c', 'e', 'e']
```

另外两个值得一提的`Counter`方法是`most_common()`和`subtract()`。最常见的方法接受一个正整数参数，确定要返回的最常见元素的数量。元素作为(key,value)元组的列表返回。

减法方法的工作方式与更新相同，只是它不是添加值，而是减去它们，如下例所示：

```py
>>> ct.most_common()
[('a', 2), ('e', 2), ('c', 1), ('b', -1)]
>>> ct.subtract({'e':2})
>>> ct
Counter({'a': 2, 'c': 1, 'e': 0, 'b': -1})
```

# 有序字典

有序字典的重要之处在于它们记住插入顺序，因此当我们对它们进行迭代时，它们会按照插入顺序返回值。这与普通字典相反，普通字典的顺序是任意的。当我们测试两个字典是否相等时，这种相等性仅基于它们的键和值；但是，对于`OrderedDict`，插入顺序也被视为两个具有相同键和值的`OrderedDict`对象之间的相等性测试，但是插入顺序不同将返回`False`：

```py
>>> import collections
>>> od1=  collections.OrderedDict()
>>> od1['one'] = 1
>>> od1['two'] = 2
>>> od2 =  collections.OrderedDict()
>>> od2['two'] = 2
>>> od2['one'] = 1
>>> od1==od2
False
```

类似地，当我们使用`update`从列表添加值时，`OrderedDict`将保留与列表相同的顺序。这是在迭代值时返回的顺序，如下例所示：

```py
>>> kvs = [('three',3), ('four',4), ('five',5)]
>>> od1.update(kvs)
>>> od1
OrderedDict([('one', 1), ('two', 2), ('three', 3), ('four', 4), ('five', 5)])
>>> for k, v in od1.items(): print(k, v)
```

```py
...
one 1
two 2
three 3
four 4
five 5
```

`OrderedDict`经常与 sorted 方法一起使用，以创建一个排序的字典。在下面的示例中，我们使用 Lambda 函数对值进行排序，并且在这里我们使用数值表达式对整数值进行排序：

```py
>>> od3 = collections.OrderedDict(sorted(od1.items(), key= lambda t : (4*t[1])- t[1]**2))
>>>od3
OrderedDict([('five', 5), ('four', 4), ('one', 1), ('three', 3), ('two', 2)])
>>> od3.values() 
odict_values([5, 4, 1, 3, 2])
```

# defaultdict

`defaultdict`对象是`dict`的子类，因此它们共享方法和操作。它作为初始化字典的便捷方式。使用`dict`时，当尝试访问尚未在字典中的键时，Python 会抛出`KeyError`。`defaultdict`覆盖了一个方法，`missing(key)`，并创建了一个新的实例变量，`default_factory`。使用`defaultdict`，而不是抛出错误，它将运行作为`default_factory`参数提供的函数，该函数将生成一个值。`defaultdict`的一个简单用法是将`default_factory`设置为`int`，并用它快速计算字典中项目的计数，如下例所示：

```py
>>> from collections import defaultdict
>>> dd = defaultdict(int)
>>> words = str.split('red blue green red yellow blue red green green red')
>>> for word in words: dd[word] +=1
...
>>> dd
defaultdict(<class 'int'>, {'red': 4, 'blue': 2, 'green': 3, 'yellow': 1})

```

您会注意到，如果我们尝试使用普通字典来做这件事，当我们尝试添加第一个键时，我们会得到一个键错误。我们提供给`defaultdict`的`int`实际上是`int()`函数，它只是返回零。

当然，我们可以创建一个函数来确定字典的值。例如，以下函数在提供的参数是主要颜色（即`red`，`green`或`blue`）时返回`True`，否则返回`False`：

```py
def isprimary(c):
     if (c=='red') or (c=='blue') or (c=='green'): 
         return True 
     else: 
         return False
```

# 了解命名元组

`namedtuple`方法返回一个类似元组的对象，其字段可以通过命名索引以及普通元组的整数索引进行访问。这允许在某种程度上自我记录和更易读的代码。在需要轻松跟踪每个元组代表的内容的应用程序中，这可能特别有用。此外，`namedtuple`从元组继承方法，并且与元组向后兼容。

字段名称作为逗号和/或空格分隔的值传递给`namedtuple`方法。它们也可以作为字符串序列传递。字段名称是单个字符串，可以是任何合法的 Python 标识符，不能以数字或下划线开头。一个典型的例子如下所示：

```py
>>> from collections import namedtuple
>>> space = namedtuple('space', 'x y z')
>>> s1= space(x=2.0, y=4.0, z=10) # we can also use space(2.0,4.0, 10)
>>> s1
space(x=2.0, y=4.0, z=10)
>>> s1.x * s1.y * s1.z   # calculate the volume
80.0
```

除了继承的元组方法之外，命名元组还定义了三种自己的方法，`_make()`，`asdict()`和`_replace`。这些方法以下划线开头，以防止与字段名称可能发生冲突。`_make()`方法将可迭代对象作为参数，并将其转换为命名元组对象，如下例所示：

```py
>>> sl = [4,5,6]
>>> space._make(sl)
space(x=4, y=5, z=6)
>>> s1._1
4
```

`_asdict`方法返回一个`OrderedDict`对象，其中字段名称映射到索引键，值映射到字典值。`_replace`方法返回元组的新实例，替换指定的值。此外，`_fields`返回列出字段名称的字符串元组。`_fields_defaults`方法提供将字段名称映射到默认值的字典。考虑以下示例代码片段：

```py
>>> s1._asdict()
OrderedDict([('x', 3), ('_1', 4), ('z', 5)])
>>> s1._replace(x=7, z=9)
space2(x=7, _1=4, z=9)
>>> space._fields
('x', 'y', 'z')
>>> space._fields_defaults
{}
```

# 数组

`array`模块定义了一种类似于列表数据类型的数据类型数组，除了它们的内容必须是由机器架构或底层 C 实现确定的单一类型的约束。

数组的类型是在创建时确定的，并且由以下类型代码之一表示：

| **代码** | **C 类型** | **Python 类型** | **最小字节数** |
| --- | --- | --- | --- |
| 'b' | `signedchar` | int | 1 |
| 'B' | `unsignedchar` | int | 1 |
| 'u' | `Py_UNICODE` | Unicodecharacter | 2 |
| 'h' | `signedshort` | int | 2 |
| 'H' | `unsignedshort` | int | 2 |
| 'i' | `signedint` | int | 2 |
| 'I' | `unsignedint` | int | 2 |
| 'l' | `signedlong` | int | 4 |
| 'L' | `unsignedlong` | int | 8 |
| 'q' | `signedlonglong` | int | 8 |
| 'Q' | `unsignedlonlong` | int | 8 |
| 'f' | `float` | float | 4 |
| 'd' | `double` | float | 8 |

数组对象支持属性和方法：

| **属性或方法** | **描述** |
| --- | --- |
| `a.itemsize` | 一个数组项的大小（以字节为单位）。 |
| `a.append(x)` | 在`a`数组的末尾添加一个`x`元素。 |
| `a.buffer_info()` | 返回一个元组，包含用于存储数组的缓冲区的当前内存位置和长度。 |
| `a.byteswap()` | 交换`a`数组中每个项目的字节顺序。 |
| `a.count(x)` | 返回`a`数组中`x`的出现次数。 |
| `a.extend(b)` | 在`a`数组的末尾添加可迭代对象`b`的所有元素。 |
| `a.frombytes(s)` | 从字符串`s`中附加元素，其中字符串是机器值的数组。 |
| `a.fromfile(f,n)` | 从文件中读取`n`个机器值，并将它们附加到数组的末尾。 |
| `a.fromlist(l)` | 将`l`列表中的所有元素附加到数组。 |
| `a.fromunicode(s)` | 用 Unicode 字符串`s`扩展`u`类型的数组。 |
| `index(x)` | 返回`x`元素的第一个（最小）索引。 |
| `a.insert(i,x)` | 在数组的`i`索引位置插入值为`x`的项目。 |
| `a.pop([i])` | 返回索引`i`处的项目，并从数组中删除它。 |
| `a.remove(x)` | 从数组中删除第一个出现的`x`项。 |
| `a.reverse()` | 颠倒`a`数组中项目的顺序。 |
| `a.tofile(f)` | 将所有元素写入`f`文件对象。 |
| `a.tolist()` | 将数组转换为列表。 |
| `a.tounicode()` | 将`u`类型的数组转换为 Unicode 字符串。 |

数组对象支持所有正常的序列操作，如索引、切片、连接和乘法。

与列表相比，使用数组是存储相同类型数据的更有效的方法。在下面的例子中，我们创建了一个整数数组，其中包含从`0`到一百万减去`1`的数字，以及一个相同的列表。在整数数组中存储一百万个整数，大约需要相当于等效列表的 90%的内存：

```py
>>> import array
>>> ba = array.array('i', range(10**6))
>>> bl = list(range(10**6))
>>> import sys
>>> 100*sys.getsizeof(ba)/sys.getsizeof(bl)
90.92989871246161
```

因为我们对节省空间感兴趣，也就是说，我们处理大型数据集和有限的内存大小，通常我们对数组进行原地操作，只有在需要时才创建副本。通常，enumerate 用于对每个元素执行操作。在下面的片段中，我们执行简单的操作，为数组中的每个项目添加一。

值得注意的是，当对创建列表的数组执行操作时，例如列表推导，使用数组的内存效率优势将被抵消。当我们需要创建一个新的数据对象时，一个解决方案是使用生成器表达式来执行操作。

使用这个模块创建的数组不适合需要矢量操作的矩阵工作。在下一章中，我们将构建自己的抽象数据类型来处理这些操作。对于数值工作来说，NumPy 扩展也很重要，可以在[www.numpy.org](http://www.numpy.org/)上找到。

# 总结

在最后两章中，我们介绍了 Python 的语言特性和数据类型。我们研究了内置数据类型和一些内部 Python 模块，尤其是`collections`模块。还有其他几个与本书主题相关的 Python 模块，但与其单独检查它们，不如在开始使用它们时，它们的使用和功能应该变得不言自明。还有一些外部库，例如 SciPy。

在下一章中，我们将介绍算法设计的基本理论和技术。 


# 第三章：算法设计原则

我们为什么要学习算法设计？当然有很多原因，我们学习某些东西的动机很大程度上取决于我们自己的情况。对于对算法设计感兴趣有重要专业原因。算法是所有计算的基础。我们可以将计算机视为一台硬件，带有硬盘、内存芯片、处理器等。然而，如果缺少的是算法，现代技术将不可能存在。让我们在接下来的章节中了解更多。

在本章中，我们将讨论以下主题：

+   算法简介

+   递归和回溯

+   大 O 符号

# 技术要求

我们需要使用 Python 安装`matplotlib`库来绘制本章的图表。

可以通过在终端上运行以下命令在 Ubuntu/Linux 上安装：

```py
python3 -mpip install matplotlib
```

您还可以使用以下内容：

```py
sudo apt-get install python3-matplotlib 
```

在 Windows 上安装`matplotlib`：

如果 Python 已经安装在 Windows 操作系统上，可以从以下链接获取`matplotlib`并在 Windows 上安装：[`github.com/matplotlib/matplotlib/downloads`](https://github.com/matplotlib/matplotlib/downloads) 或 [`matplotlib.org`](https://matplotlib.org)。

本章的代码文件可以在以下链接找到：[`github.com/PacktPublishing/Hands-On-Data-Structures-and-Algorithms-with-Python-Second-Edition/tree/master/Chapter03`](https://github.com/PacktPublishing/Hands-On-Data-Structures-and-Algorithms-with-Python-Second-Edition/tree/master/Chapter03)。

# 算法简介

算法的理论基础，以图灵机的形式，是在数字逻辑电路实际上能够实现这样的机器的几十年前建立的。图灵机本质上是一个数学模型，它使用预定义的一组规则，将一组输入转换为一组输出。图灵机的第一批实现是机械的，下一代可能会看到数字逻辑电路被量子电路或类似的东西所取代。无论平台如何，算法都起着中心主导作用。

算法对技术创新的影响是另一个方面。显而易见的例子是页面排名搜索算法，Google 搜索引擎就是基于其变体。使用这些和类似的算法允许研究人员、科学家、技术人员等快速搜索大量信息。这对新研究的速度、新发现的速度以及新的创新技术的开发速度产生了巨大影响。算法是执行特定任务的顺序指令集。它们非常重要，因为我们可以将一个复杂的问题分解为一个小问题，以准备执行一个大问题的简单步骤——这是算法最重要的部分。一个好的算法是解决特定问题的高效程序的关键。学习算法也很重要，因为它训练我们对某些问题进行非常具体的思考。它可以通过隔离问题的组成部分并定义这些组成部分之间的关系来增加我们的问题解决能力。总之，学习算法有一些重要原因：

+   它们对计算机科学和*智能*系统至关重要

+   它们在许多其他领域中很重要（计算生物学、经济学、生态学、通信、生态学、物理等）

+   它们在技术创新中发挥作用

+   它们改进问题解决和分析思维

解决给定问题主要有两个重要方面。首先，我们需要一个有效的机制来存储、管理和检索数据，这对解决问题很重要（这属于数据结构）；其次，我们需要一个有效的算法，这是一组有限的指令来解决问题。因此，研究数据结构和算法对使用计算机程序解决任何问题至关重要。有效的算法应具有以下特征：

+   它应该尽可能具体

+   算法的每个指令都应该被正确定义

+   不应该有任何模糊的指令

+   算法的所有指令都应该在有限的时间内和有限的步骤内可执行

+   它应该有清晰的输入和输出来解决问题

+   算法的每个指令在解决给定问题时都很重要

算法在其最简单的形式中只是一系列操作 - 一系列指令。它可能只是一个形式为 do *x*，然后 do *y*，然后 do *z*，然后完成的线性构造。然而，为了使事情更有用，我们添加了类似于 do *x*然后 do *y*的子句；在 Python 中，这些是 if-else 语句。在这里，未来的行动取决于某些条件；比如数据结构的状态。为此，我们还添加了操作、迭代、while 和 for 语句。扩展我们的算法素养，我们添加了递归。递归通常可以实现与迭代相同的结果，但它们在根本上是不同的。递归函数调用自身，将相同的函数应用于逐渐减小的输入。任何递归步骤的输入是前一个递归步骤的输出。

# 算法设计范式

一般来说，我们可以分辨出三种算法设计的广泛方法。它们是：

+   分而治之

+   贪婪算法

+   动态规划

正如其名称所示，分而治之范式涉及将问题分解为较小的简单子问题，然后解决这些子问题，最后将结果组合以获得全局最优解。这是一种非常常见和自然的问题解决技术，可以说是算法设计中最常用的方法。例如，归并排序是一种对 n 个自然数列表进行递增排序的算法。

在这个算法中，我们迭代地将列表分成相等的部分，直到每个子列表包含一个元素，然后我们将这些子列表组合在一起，以排序顺序创建一个新列表。我们将在本节/章节后面更详细地讨论归并排序。

分而治之算法范式的一些例子如下：

+   二分搜索

+   归并排序

+   快速排序

+   Karatsuba 算法用于快速乘法

+   斯特拉森矩阵乘法

+   最接近的点对

贪婪算法通常涉及优化和组合问题。在贪婪算法中，目标是在每一步中从许多可能的解决方案中获得最佳的最优解，并且我们试图获得局部最优解，这可能最终导致我们获得整体最优解。通常，贪婪算法用于优化问题。以下是许多流行的标准问题，我们可以使用贪婪算法来获得最优解：

+   克鲁斯卡尔最小生成树

+   迪杰斯特拉最短路径

+   背包问题

+   普林姆最小生成树算法

+   旅行推销员问题

贪婪算法通常涉及优化和组合问题；经典的例子是将贪婪算法应用于旅行推销员问题，其中贪婪方法总是首先选择最近的目的地。这种最短路径策略涉及找到局部问题的最佳解决方案，希望这将导致全局解决方案。

另一个经典的例子是将贪婪算法应用于旅行推销员问题；这是一个 NP 难问题。在这个问题中，贪婪方法总是首先选择当前城市中最近的未访问城市；这样，我们不能确定我们得到了最佳解决方案，但我们肯定得到了一个最优解。这种最短路径策略涉及在希望这将导致全局解决方案的情况下找到局部问题的最佳解决方案。

动态规划方法在我们的子问题重叠时非常有用。这与分治法不同。与将问题分解为独立子问题不同，动态规划中间结果被缓存并可以在后续操作中使用。与分治法一样，它使用递归；然而，动态规划允许我们在不同阶段比较结果。这对于某些问题来说可能比分治法具有性能优势，因为通常从内存中检索先前计算的结果比重新计算要快。动态规划也使用递归来解决问题。例如，矩阵链乘法问题可以使用动态规划来解决。矩阵链乘法问题确定了在给定一系列矩阵时，最有效的矩阵相乘的顺序，它找到需要最少操作次数的乘法顺序。

例如，让我们看看三个矩阵——*P*、*Q*和*R*。要计算这三个矩阵的乘法，我们有许多可能的选择（因为矩阵乘法是可结合的），比如*(PQ)R = P(QR)*。因此，如果这些矩阵的大小是——*P*是 20×30，*Q*是 30×45，*R*是 45×50，那么*(PQ)R*和*P(QR)*的乘法次数将是：

+   *(PQ)R* = 20 x 30 x 45 + 20 x 45 x 50 = 72,000

+   *P(QR)* =  20 x 30 x 50 + 30 x 45 x 50 = 97,500

从这个例子可以看出，如果我们使用第一个选项进行乘法，那么我们需要 72,000 次乘法，与第二个选项相比要少。这在以下代码中显示：

```py
def MatrixChain(mat, i, j):   
    if i == j:   
        return 0   
    minimum_computations = sys.maxsize  
    for k in range(i, j): 
        count = (MatrixChain(mat, i, k) + MatrixChain(mat, k+1, j)+ mat[i-1] * mat[k] * mat[j])   
        if count < minimum_computations:  
              minimum_computations= count;    
        return minimum_computations;  

matrix_sizes = [20, 30, 45, 50];  
print("Minimum multiplications are", MatrixChain(matrix_sizes , 1, len(matrix_sizes)-1));

#prints 72000
```

第十三章，*设计技术和策略*，对算法设计策略进行了更详细的讨论。

# 递归和回溯

递归对于分治问题特别有用；然而，确切地了解发生了什么可能很困难，因为每个递归调用本身都会产生其他递归调用。递归函数可能会陷入无限循环，因此需要每个递归函数都遵守一些属性。递归函数的核心是两种类型的情况：

+   **基本情况**：这些告诉递归何时终止，意味着一旦满足基本条件，递归将停止

+   **递归情况**：函数调用自身，我们朝着实现基本条件的目标前进

一个自然适合递归解决方案的简单问题是计算阶乘。递归阶乘算法定义了两种情况：当*n*为零时的基本情况（终止条件），以及当*n*大于零时的递归情况（函数本身的调用）。一个典型的实现如下：

```py
def factorial(n): 
    # test for a base case      
    if  n==0: 
        return 1 
        #make a calculation and a recursive call
    else: 
        f= n*factorial(n-1) 
    print(f) 
    return(f) 

factorial(4)
```

要计算`4`的阶乘，我们需要四次递归调用加上初始父调用。在每次递归中，方法变量的副本都存储在内存中。一旦方法返回，它就会从内存中删除。以下是我们可以可视化这个过程的一种方式：

递归或迭代哪个更好的解决方案可能并不清楚；毕竟，它们都重复一系列操作，并且都非常适合分治方法和算法设计。迭代一直进行，直到问题解决为止。递归将问题分解成越来越小的块，然后将结果组合起来。迭代对程序员来说通常更容易，因为控制保持在循环内部，而递归可以更接近表示阶乘等数学概念。递归调用存储在内存中，而迭代不是。这在处理器周期和内存使用之间产生了一种权衡，因此选择使用哪种可能取决于任务是处理器密集型还是内存密集型。以下表格概述了递归和迭代之间的主要区别：

| **递归** | **迭代** |
| --- | --- |
| 函数调用自身。 | 一组指令在循环中重复执行。 |
| 当满足终止条件时停止。 | 当满足循环条件时停止执行。 |
| 无限递归调用可能会导致与堆栈溢出相关的错误。 | 无限迭代将无限运行，直到硬件断电。 |
| 每个递归调用都需要内存空间。 | 每次迭代不需要内存存储。 |
| 代码大小一般来说相对较小。 | 代码大小一般来说相对较小。 |
| 递归通常比迭代慢。 | 它更快，因为不需要栈。 |

# 回溯

回溯是一种特别适用于遍历树结构等类型问题的递归形式，其中对于每个节点我们有许多选项可供选择。随后，我们会得到一组不同的选项，根据所做的选择系列，会达到一个目标状态或者一个死胡同。如果是后者，我们必须回溯到先前的节点并遍历不同的分支。回溯是一种用于穷举搜索的分治方法。重要的是，回溯**修剪**了无法给出结果的分支。

下面给出了回溯的一个例子。在这里，我们使用了递归方法来生成给定字符串 `s` 的所有可能排列，长度为 `n`：

```py
def bitStr(n,s):
 if n==1: return s 
 return [digit + bits for digit in bitStr(1,s) for bits in bitStr(n-1,s)] 

print(bitStr(3,'abc'))
```

这产生了以下输出：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/933bcc38-2e75-47b4-917e-7d5ee731f5b7.png)

注意这个推导中的双重列表压缩和两个递归调用。这递归地连接了初始序列的每个元素，当 *n* =1 时返回，与先前递归调用生成的字符串的每个元素。在这个意义上，它是 *回溯*，以揭示先前未生成的组合。返回的最终字符串是初始字符串的所有 *n* 个字母组合。

# 分治——长乘法

为了使递归不仅仅是一个巧妙的技巧，我们需要了解如何将其与其他方法进行比较，例如迭代，并了解何时使用它将导致更快的算法。我们都熟悉的迭代算法是我们在小学数学课上学到的程序，用于将两个大数相乘。那就是长乘法。如果你记得的话，长乘法涉及迭代乘法和进位操作，然后是移位和加法操作。

我们的目标是检查如何衡量这个过程的效率，并尝试回答这个问题——这是我们用来将两个大数相乘的最有效的过程吗？

在下图中，我们可以看到将两个四位数相乘需要 16 次乘法运算，我们可以概括地说，一个 *n* 位数需要大约 *n*^(*2*) 次乘法运算：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/0bc9b9a7-2672-436c-b651-f1d56260339c.png)

以计算原语的数量，如乘法和加法，来分析算法的方法很重要，因为它为我们提供了一种理解完成某个计算所需的时间与该计算的输入大小之间关系的方法。特别是，我们想知道当输入，即数字的位数*n*非常大时会发生什么。这个主题被称为**渐近分析**或**时间复杂度**，对我们研究算法至关重要，在本章和本书的其余部分我们将经常回顾这个主题。

# 递归方法

事实证明，在长乘法的情况下，答案是肯定的，实际上有几种算法可以减少操作次数。其中最著名的替代长乘法的算法之一是**Karatsuba 算法**，首次发表于 1962 年。这采用了一种基本不同的方法：而不是迭代地相乘单个数字，它在逐渐减小的输入上递归地进行乘法运算。递归程序在输入的较小子集上调用自身。构建递归算法的第一步是将一个大数分解为几个较小的数。这样做的最自然的方式是将数字分成两半，前半部分是最高有效数字，后半部分是最低有效数字。例如，我们的四位数 2345 变成了一对两位数 23 和 45。我们可以使用以下更一般的分解来写出任意两个*n*位数*x*和*y*的分解，其中*m*是小于*n*的任意正整数：

！[](Images/a3c99940-655a-414f-81bf-3f12983cecde.png)

！[](Images/b3b0c275-29d8-4f19-a38d-f3b935180c21.png)

现在我们可以将我们的乘法问题*x*，*y*重写如下：

！[](Images/feea5e6e-0ba8-42af-820e-c61603ca563e.png)

当我们展开时，我们得到以下结果：

！[](Images/31fa81b7-71ca-471f-a4a5-8d92229fc993.png)

更方便的是，我们可以这样写（方程 3.1）：

！[](Images/3eecd139-882e-4cf6-bfb1-1d89f560583b.png)                          ... (3.1)

在哪里：

！[](Images/d46fac6b-adc9-4d6e-aeb8-efdf3c003ddd.png)

应该指出，这表明了一种递归方法来乘两个数字，因为这个过程本身涉及乘法。具体来说，乘积*ac*、*ad*、*bc*和*bd*都涉及比输入数字小的数字，因此我们可以将相同的操作应用为整体问题的部分解决方案。到目前为止，这个算法包括四个递归乘法步骤，目前还不清楚它是否比经典的长乘法方法更快。

到目前为止，我们所讨论的关于递归方法的乘法，自 19 世纪末以来就为数学家所熟知。Karatsuba 算法通过以下观察改进了这一点。我们实际上只需要知道三个量：*z*[*2*]= *ac*，*z*[*1*]*=ad +bc*，和*z*[*0*]= *bd*来解方程 3.1。我们只需要知道*a*、*b*、*c*和*d*的值，因为它们对计算涉及的总和和乘积有贡献。这表明或许我们可以减少递归步骤的数量。事实证明，情况确实如此。

由于乘积*ac*和*bd*已经处于最简形式，看来我们无法消除这些计算。然而，我们可以做出以下观察：

！[](Images/88959a91-37a3-4a23-93c4-083e43baa17a.png)

当我们减去我们在上一个递归步骤中计算的量*ac*和*bd*时，我们得到我们需要的量，即(*ad + bc*)：

！[](Images/4d502318-8937-4c95-a555-5be65f889dce.png)

这表明我们确实可以计算*ad + bc*的和，而不必分别计算每个单独的数量。总之，我们可以通过将四个递归步骤减少到三个来改进方程 3.1。这三个步骤如下：

1.  递归计算*ac*

1.  递归计算*bd*

1.  递归计算（*a + b*）（*c + d*）并减去*ac*和*bd*

以下示例展示了 Karatsuba 算法的 Python 实现。在以下代码中，最初，我们检查给定数字中是否有任何一个小于 10，然后就不需要运行递归函数。接下来，我们确定较大值的数字位数，并在数字位数为奇数时加一。最后，我们递归调用函数三次来计算*ac*、*bd*和（*a + d*）（*c + d*）。以下代码打印任意两个数字的乘积；例如，它打印出`4264704`来表示`1234`和`3456`的乘积。Karatsuba 算法的实现如下：

```py
from math import log10 
def karatsuba(x,y): 

    #The base case for recursion 
    if x<10 or y<10:
        return x*y 

    #sets n, the number of digits in the highest input number
    n=max(int(log10(x)+1), int(log10(y)+1)) 

    #rounds up n/2  
    n_2 = int(math.ceil(n/2.0)) 
    #adds 1 if n is uneven  
    n = n if n%2 == 0  else n+1 
    #splits the input numbers 
    a, b = divmod(x, 10**n_2) 
    c, d = divmod(y,10**n_2) 
    #applies the three recursive steps 
    ac = karatsuba(a,c) 
    bd = karatsuba(b,d)  
    ad_bc = karatsuba((a+b),(c+d))-ac-bd 

    #performs the multiplication 
    return (((10**n)*ac)+bd+((10**n_2)*(ad_bc)))

t= karatsuba(1234,3456)
print(t)

# outputs - 4264704
```

# 运行时间分析

算法的性能通常由其输入数据的大小（**n**）以及算法使用的时间和内存空间来衡量。所需的**时间**由算法执行的关键操作（如比较操作）来衡量，而算法的空间需求则由在程序执行期间存储变量、常量和指令所需的存储空间来衡量。算法的空间需求在执行期间也可能动态变化，因为它取决于变量大小，这在运行时决定，例如动态内存分配、内存堆栈等。

算法所需的运行时间取决于输入大小；随着输入大小（**n**）的增加，运行时间也会增加。例如，对于输入大小为 5,000 的列表，排序算法将需要更多的运行时间来排序，而对于输入大小为 50 的列表，运行时间较短。因此，可以清楚地看出，要计算时间复杂度，输入大小是重要的。此外，对于特定输入，运行时间取决于算法中要执行的关键操作。例如，对于排序算法，关键操作是**比较操作**，它将占用大部分时间，而不是赋值或其他任何操作。要执行的关键操作越多，运行算法所需的时间就越长。

应该注意的是，算法设计的一个重要方面是评估效率，无论是在空间（内存）还是时间（操作次数）方面。应该提到的是，用于衡量算法内存性能的度量标准与衡量算法运行时间的度量标准相同。我们可以以多种方式来衡量运行时间，最明显的方式可能是简单地测量算法所需的总时间。这种方法的主要问题在于算法运行所需的时间非常依赖于其运行的硬件。衡量算法运行时间的一个与平台无关的方法是计算所涉及的操作次数。然而，这也是有问题的，因为没有明确的方法来量化一个操作。这取决于编程语言、编码风格以及我们决定如何计算操作。然而，如果我们将这种计算操作的想法与一个期望相结合，即随着输入大小的增加，运行时间将以特定方式增加，我们就可以使用这个想法。也就是说，输入大小**n**和算法运行时间之间存在数学关系。基本上有三个因素决定了算法的运行时间性能；它们可以描述如下：

+   最坏情况复杂度是上界复杂度；它是算法执行所需的最大运行时间。在这种情况下，关键操作将执行最大次数。

+   最佳情况复杂度是下界复杂度；这是算法执行所需的最小运行时间。在这种情况下，关键操作将执行最少次数。

+   平均情况复杂度是算法执行所需的平均运行时间。

最坏情况分析是有用的，因为它给出了我们的算法保证不会超过的严格上界。忽略小的常数因子和低阶项，实际上就是忽略那些在输入规模较大时对总运行时间没有很大贡献的事物。这不仅使我们的工作在数学上更容易，而且还使我们能够专注于对性能影响最大的事物。

我们在 Karatsuba 算法中看到，乘法操作的数量增加到输入大小*n*的平方。如果我们有一个四位数，乘法操作的数量是 16；一个八位数需要 64 次操作。通常，我们实际上并不关心算法在*n*的小值时的行为，所以我们经常忽略随着*n*线性增加的因子。这是因为在较大的*n*值时，随着*n*的增加，增长最快的操作将占主导地位。

我们将通过一个示例来更详细地解释这个归并排序算法。排序是第十章的主题，*排序*，然而，作为一个前导和了解运行时性能的有用方式，我们将在这里介绍归并排序。

归并排序算法是 60 多年前开发的经典算法。它仍然广泛应用于许多最流行的排序库中。它相对简单而高效。它是一种使用分而治之方法的递归算法。这涉及将问题分解为更小的子问题，递归地解决它们，然后以某种方式组合结果。归并排序是分而治之范式最明显的演示之一。

归并排序算法由三个简单的步骤组成：

1.  递归地对输入数组的左半部分进行排序

1.  递归地对输入数组的右半部分进行排序

1.  将两个排序好的子数组合并成一个

典型问题是将一组数字按数字顺序排序。归并排序通过将输入分成两半，并同时处理每一半来工作。我们可以用以下图表来形象地说明这个过程：

这是归并排序算法的 Python 代码：

```py
def mergeSort(A): 
#base case if the input array is one or zero just return. 
if len(A) > 1: 
    # splitting input array 
    print('splitting ', A ) 
    mid=len(A)//2   
    left=A[:mid]   
    right=A[mid:] 
    #recursive calls to mergeSort for left and right subarrays 
    mergeSort(left)   
    mergeSort(right) 
    #initalizes pointers for left(i) right(j) and output array (k)

    #3 initalization operations 
    i = j = k = 0 
    #Traverse and merges the sorted arrays 
    while i < len(left) and j < len(right):  
    #if left < right comparison operation 
        if left[i] < right[j]:  
        #if left < right Assignment operation  
            A[k] = left[i]  
            i=i+1 
        else:   
            #if right <= left assignment 
            A[k]=right[j] 
            j=j+1   
            k=k+1   

    while i< len(left):   
    #Assignment operation 
        A[k] = left[i] 
        i=i+1   
        k=k+1   

    while j< len(right):   
    # Assignment operation    
        A[k] = right[j] 
        j=j+1 
        k=k+1 

print('merging',A) 
return(A)
```

我们运行这个程序得到以下结果：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/d2f8424e-f06e-47ff-ac59-5a0d32a0f06f.png)

我们感兴趣的问题是如何确定运行时性能，也就是说，算法完成所需的时间与*n*的大小相关的增长率是多少？为了更好地理解这一点，我们可以将每个递归调用映射到一个树结构上。树中的每个节点都是递归调用，处理逐渐变小的子问题：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/40e4b2b0-3c6a-4630-8f5d-643da4b7210c.png)

每次调用归并排序都会随后创建两个递归调用，因此我们可以用二叉树来表示这一点。每个子节点都接收输入的一个子集。最终，我们想知道算法完成所需的总时间与*n*的大小相关。首先，我们可以计算树的每个级别的工作量和操作数量。

关注运行时分析，在第一级，问题分成两个*n*/2 个子问题；在第二级，有四个*n*/4 个子问题，依此类推。问题是，递归何时结束，也就是说，何时达到基本情况？这只是当数组要么是零要么是一时。

递归级别的数量恰好是将*n*除以二直到得到最多为一的数字的次数。这恰好是 log2 的定义。由于我们将初始递归调用计为级别零，总级别数为 log[2]*n* + 1。

让我们暂停一下，重新定义一下。到目前为止，我们一直用字母*n*来描述输入中的元素数量。这指的是递归的第一级中的元素数量，也就是初始输入的长度。我们需要区分后续递归级别的输入大小。为此，我们将使用字母*m*，或者特别是*m*[*j*]来表示递归级别*j*的输入长度。

此外，还有一些细节我们忽略了，我相信你也开始好奇了。例如，当*m*/2 不是整数时会发生什么，或者当我们的输入数组中有重复元素时会发生什么？事实证明，这对我们的分析并没有重要影响；我们将在《第十二章设计技术和策略》中重新审视归并排序算法的一些细节。

使用递归树来分析算法的优势在于我们可以计算每个递归级别的工作量。我们定义这个工作量就是总操作次数，这当然与输入的大小有关。以平台无关的方式来测量和比较算法的性能是很重要的。实际运行时间当然取决于其运行的硬件。计算操作次数很重要，因为它给了我们一个与算法性能直接相关的度量，而不受平台的影响。

一般来说，由于归并排序的每次调用都会进行两次递归调用，所以调用次数在每个级别都会翻倍。与此同时，每个调用都在处理其父级别一半大小的输入。我们可以形式化地说，在第*j*级，其中*j*是整数*0, 1, 2 ... log[2]n*，有两个大小为*n/2^j*的子问题。

要计算总操作次数，我们需要知道合并两个子数组所包含的操作次数。让我们来数一下之前 Python 代码中的操作次数。我们感兴趣的是在进行两次递归调用之后的所有代码。首先，我们有三个赋值操作。然后是三个`while`循环。在第一个循环中，我们有一个 if-else 语句，在每个操作中，都有一个比较，然后是一个赋值。由于在 if-else 语句中只有一个这样的操作集，我们可以将这段代码计算为每次递归执行两次的操作。接下来是两个`while`循环，每个循环都有一个赋值操作。这使得每次归并排序递归的总操作次数为*4m + 3*。

由于*m*至少必须为一，操作次数的上限是 7*m*。必须指出，这并不是一个精确的数字。当然，我们可以决定以不同的方式计算操作次数。我们没有计算增量操作或任何维护操作；然而，在高值的*n*下，这并不重要，因为我们更关心运行时间相对于*n*的增长率。

这可能看起来有点令人生畏，因为每次递归调用本身都会产生更多的递归调用，似乎呈指数级增长。使这一切变得可控的关键事实是，随着递归调用次数翻倍，每个子问题的大小减半。这两股相反的力量得到了很好的抵消，我们可以证明这一点。

要计算递归树每个级别的最大操作次数，我们只需将子问题的数量乘以每个子问题的操作次数，如下所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/f963cdb9-6851-4a7b-9ee5-a7437f7c0f5c.png)

重要的是，这表明，因为*2^j*取消了每个级别的操作数量，所以每个级别的操作数量是独立的。这给了我们每个级别执行的操作数量的上限，在这个例子中是 7*n*。需要指出的是，这包括在该级别上每个递归调用执行的操作数量，而不是在后续级别上进行的递归调用。这表明工作是完成的，因为随着每个级别递归调用的数量翻倍，而每个子问题的输入大小减半，这正好抵消了这一事实。

要找到完整归并排序的总操作数，我们只需将每个级别上的操作数乘以级别数。这给出了以下结果：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/e06dc99e-5e0a-4f6b-829f-2ad033c7a5ed.png)

当我们展开这个式子时，我们得到以下结果：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/d0ad8584-5760-4081-aac4-65ab789871f5.png)

从中可以得出一个关键点，即输入大小和总运行时间之间存在对数关系。如果你还记得学校数学，对数函数的显著特点是它非常快速地变平。作为输入变量，*x*增加，输出变量*y*增加的幅度越来越小。

例如，将对数函数与线性函数进行比较：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/a70898f7-13ed-4b6b-92d4-a71a04c40e64.png)

在前面的例子中，将*n*log[2] *n*分量与![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/2b34c45d-a9f3-4b96-8893-66994aba5875.png)进行比较：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/66071838-ae0b-4bb1-b942-01638c4ef2e2.png)

注意，对于非常低的*n*值，完成时间*t*实际上比运行时间为 n2 的算法更低。然而，对于大约 40 以上的值，对数函数开始主导，使输出变得平坦，直到相对较中等大小的*n* = 100 时，性能比运行时间为*n*²的算法高出一倍以上。还要注意，在高*n*值时，常数因子+7 的消失是无关紧要的。

用于生成这些图表的代码如下：

```py
import matplotlib.pyplotasplt 
import math   
x = list(range(1,100))   
l=[]; l2=[]; a=1   
plt.plot(x, [y*y for y in x])  
plt.plot(x, [(7*y)*math.log(y,2) for y in x]) 
plt.show()
```

如果尚未安装`matplotlib`库，您需要安装它才能运行。详细信息可以在以下地址找到；我鼓励您尝试使用列表推导表达式来生成图表。例如，我们可以添加以下`plot`语句：

```py
plt.plot(x, [(6*y)* math.log(y, 2) for y in x])
```

这给出了以下输出：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/4a4614bc-1fd3-49e5-ad08-f9c7ce354585.png)

前面的图表显示了计算六次操作或七次操作的差异。我们可以看到这两种情况的分歧，这在谈论应用程序的具体情况时很重要。然而，我们在这里更感兴趣的是一种表征增长率的方法。我们不太关心绝对值，而是关心这些值随着*n*的增加而如何变化。通过这种方式，我们可以看到两条较低的曲线与顶部（*x*²）曲线相比具有相似的增长率。我们说这两条较低的曲线具有相同的**复杂度类**。这是一种理解和描述不同运行时行为的方法。我们将在下一节中正式化这个性能指标。

# 渐近分析

算法的渐近分析是指计算算法的运行时间。要确定哪个算法更好，给定两个算法，一个简单的方法是运行两个程序，对于给定的输入，执行时间最短的算法比另一个更好。然而，可能对于特定的输入，一个算法比另一个更好，而对于算法可能表现更差的任何其他输入值。

在渐近分析中，我们比较两个算法的输入大小而不是实际运行时间，并测量随着输入大小的增加，所需时间的增加情况。这通过以下代码表示：

```py
# Linear search program to search an element, return the index position of the #array
def searching(search_arr, x):     
    for i in range(len(search_arr)):         
        if search_arr [i] == x:             
                return i     
    return -1

search_ar= [3, 4, 1, 6, 14]
x=4

searching(search_ar, x)
print("Index position for the element x is :",searching(search_ar, x))

#outputs index position of the element x that is - 1
```

假设数组的大小为`n`，*T(n)*是执行线性搜索所需的关键操作总数，这个例子中的关键操作是比较。让我们以线性搜索为例来理解最坏情况、平均情况和最佳情况的复杂性：

+   **最坏情况分析**：我们考虑上界运行时间，即算法所需的最长时间。在线性搜索中，最坏情况发生在要搜索的元素在最后一次比较中被找到或者在列表中未找到。在这种情况下，将会有最大数量的比较，即数组中的元素总数。因此，最坏情况的时间复杂度是Θ(n)。

+   **平均情况分析**：在这种分析中，我们考虑元素可能在列表中被找到的所有可能情况，然后计算平均运行时间复杂度。例如，在线性搜索中，如果要搜索的元素在*0*索引处找到，那么所有位置的比较次数将为*1*，类似地，对于在*1, 2, 3, … (n-1)*索引位置找到的元素，比较次数将分别为 2, 3，直到*n*。因此，平均时间复杂度可以定义为`average-case complexity= (1+2+3…n)/n = n(n+1)/2`。

+   **最佳情况分析**：最佳情况的运行时间复杂度是算法运行所需的最短时间；它是下界运行时间。在线性搜索中，最佳情况是要搜索的元素在第一次比较中被找到。在这个例子中，很明显最佳情况的时间复杂度不取决于列表的长度。因此，最佳情况的时间复杂度将是*Θ(1)*。

通常，我们使用最坏情况分析来分析算法，因为它为我们提供了运行时间的上界，而最佳情况分析是最不重要的，因为它为我们提供了算法所需的最小时间的下界。此外，计算平均情况分析非常困难。

为了计算这些情况，我们需要知道上界和下界。我们已经看到了用数学表达式表示算法运行时间的方法，基本上是添加和乘法操作。使用渐近分析，我们只需创建两个表达式，分别用于最佳和最坏情况。

# 大 O 符号

大 O 符号中的 O 代表 order，意味着增长率被定义为函数的阶。它衡量最坏情况的运行时间复杂度，即算法所需的最长时间。我们说一个函数*T*(*n*)是另一个函数*F*(*n*)的大 O，我们定义如下：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/ca98e7da-6adf-45dd-bb3d-2d818e74f5b1.png)

输入大小*n*的函数*g*(*n*)基于这样的观察：对于所有足够大的*n*值，*g*(*n*)都受到*f*(*n*)的常数倍的上界限制。目标是找到小于或等于*f*(*n*)的增长率最小的增长率。我们只关心在较高的*n*值发生的情况。变量*n**0*表示增长率不重要的阈值以下。函数*T(n)*表示**紧密上界**F(n)。在下图中，我们可以看到*T*(*n*) = *n*^(*2*) + 500 = *O*(*n*^(*2*))，其中*C* = 2，*n*[*0*]约为 23：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/34695609-21eb-4181-ad54-229cd55006af.png)

您还会看到符号*f*(*n*) = *O*(*g*(*n*))。这描述了*O*(*g*(*n*))实际上是一个包含所有增长速度与*f*(n)相同或更小的函数的集合。例如，*O*(*n*^(*2*))也包括函数*O(n)*，*O(nlogn)*等。让我们考虑另一个例子。

函数`f(x)= 19n log[2]n  +56 `的大 O 时间复杂度为*O(nlogn)*。

在下表中，我们按照从低到高的顺序列出了最常见的增长率。我们有时将这些增长率称为函数的**时间复杂度**或函数的复杂度类：

| **复杂度类** | **名称** | **示例操作** |
| --- | --- | --- |
| 常数 | 常数 | 追加，获取项目，设置项目。 |
| 对数 | 对数 | 在排序数组中查找元素。 |
| 线性 | 线性 | 复制，插入，删除，迭代。 |
| 线性对数 | 线性对数 | 对列表进行排序，归并排序。 |
| 二次 | 二次 | 在图中两个节点之间找到最短路径。嵌套循环。 |
| 三次 | 三次 | 矩阵乘法。 |
| 指数 | 指数 | 汉诺塔问题，回溯。 |

# 组合复杂度类

通常，我们需要找到一系列基本操作的总运行时间。事实证明，我们可以组合简单操作的复杂度类来找到更复杂的组合操作的复杂度类。目标是分析函数或方法中的组合语句，以了解执行多个操作的总时间复杂度。组合两个复杂度类的最简单方法是将它们相加。当我们有两个连续的操作时就会发生这种情况。例如，考虑将元素插入列表然后对该列表进行排序的两个操作。我们可以看到插入项目需要*O(n)*时间，排序需要*O(nlogn)*时间。我们可以将总时间复杂度写为*O(n + nlogn)*，也就是说，我们将两个函数放在*O(...)*中。我们只对最高阶项感兴趣，因此这让我们只剩下*O(nlogn)*。

如果我们重复一个操作，例如在`while`循环中，那么我们将复杂度类乘以操作执行的次数。如果一个时间复杂度为*O(f(n))*的操作重复执行*O(n)*次，那么我们将两个复杂度相乘：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/4e850cfb-5448-44c5-976f-747b075798b0.png)

例如，假设函数`f(...)`的时间复杂度为*O(n²)*，并且在`while`循环中执行了*n*次，如下所示：

```py
for i in range(n): 
        f(...)
```

然后，这个循环的时间复杂度变为*O(n²) * O(n) = O(n * n²) = O(n³)*。在这里，我们只是将操作的时间复杂度乘以这个操作执行的次数。循环的运行时间最多是循环内部语句的运行时间乘以迭代次数。一个单独的嵌套循环，也就是一个循环嵌套在另一个循环中，假设两个循环都运行 n 次，将在 n²时间内运行，就像下面的例子中演示的那样：

```py
for i in range(0,n): 
    for j in range(0,n)  
            #statements
```

每个语句都是一个常数*c*，执行*nn*次，因此我们可以将运行时间表示为以下形式：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/252c1e30-173c-4958-923c-369eb1bc0fcb.png)

对于嵌套循环中的连续语句，我们将每个语句的时间复杂度相加，然后乘以语句执行的次数，例如：

```py
n=500  #c0 
#executes n times  
for i in range(0,n):  
    print(i)    #c1
   #executes n times   
for i in range(0,n):  
#executes n times  
    for j in range(0,n):  
            print(j)  #c2
```

这可以写成`c[0] +c[1 ]n + cn^(2 )= O(n²)`。

我们可以定义（以 2 为底）对数复杂度，将问题的大小减少一半，以常数时间。例如，考虑以下代码片段：

```py
i=1   
while i<=n: 
    i=i*2 
    print(i)   
```

注意 i 在每次迭代时都会加倍；如果我们以*n*=10 运行它，我们会看到它打印出四个数字：2，4，8 和 16。如果我们将*n*加倍，我们会看到它打印出五个数字。随着*n*的每次加倍，迭代次数只增加了一个。如果我们假设*k*次迭代，我们可以将其写成如下形式：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/b31931aa-a8aa-451c-b30c-b8590dfcf074.png)

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/7ed3d882-ac80-4bc2-93b7-5c00efc6350d.png)

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/8ab8d784-60cc-4838-9816-7f1c9269a84e.png)

由此可得，总时间 = ***O**(log(n))*。

尽管大 O 符号是渐近分析中最常用的符号，但还有两个相关的符号应该简要提到。它们是 Omega 符号和 Theta 符号。

# Omega 符号（Ω）

Omega 符号描述了算法的严格下界，类似于大 O 符号描述了严格的上界。Omega 符号计算算法的最佳运行时间复杂度。它提供了最高的增长率*T(n)*，它小于或等于给定算法。它可以计算如下：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/69e1d0c6-1542-4193-be5e-5e43ebcbc465.png)

# Theta 符号（ϴ）

通常情况下，给定函数的上界和下界是相同的，Theta 符号的目的是确定是否是这种情况。定义如下：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/391dc9e6-d17d-40c8-a353-f80e5b7576e9.png)

尽管 Omega 和 Theta 符号需要完全描述增长率，但最实用的是大 O 符号，这是你经常看到的符号。

# 摊销分析

通常我们对单个操作的时间复杂度不太感兴趣；我们更关心操作序列的平均运行时间。这就是摊销分析。它与平均情况分析不同，我们将很快讨论，因为我们对输入值的数据分布没有任何假设。然而，它考虑了数据结构的状态变化。例如，如果列表已排序，则任何后续的查找操作应该更快。摊销分析考虑了数据结构的状态变化，因为它分析操作序列，而不仅仅是聚合单个操作。

摊销分析描述了算法运行时间的上界；它对算法中的每个操作施加了额外的成本。序列的额外考虑成本可能比初始昂贵的操作要便宜。

当我们有少量昂贵的操作，比如排序，和大量更便宜的操作，比如查找时，标准的最坏情况分析可能会导致过于悲观的结果，因为它假设每次查找都必须比较列表中的每个元素直到找到匹配项。我们应该考虑到一旦我们对列表进行排序，我们可以使后续的查找操作变得更便宜。

到目前为止，在我们的运行时分析中，我们假设输入数据是完全随机的，并且只关注输入大小对运行时间的影响。算法分析还有另外两种常见的方法，它们是：

+   平均情况分析

+   基准测试

平均情况分析将找到基于对各种输入值的相对频率的一些假设的平均运行时间。使用真实世界的数据，或者复制真实世界数据的分布的数据，往往是基于特定数据分布的，然后计算平均运行时间。

基准测试就是简单地有一组约定的典型输入，用于衡量性能。基准测试和平均时间分析都依赖于一些领域知识。我们需要知道典型或预期的数据集是什么。最终，我们将尝试通过微调到一个非常特定的应用设置来提高性能。

让我们看一种简单的方法来衡量算法的运行时间性能。这可以通过简单地计时算法完成给定各种输入大小所需的时间来完成。正如我们之前提到的，这种衡量运行时间性能的方式取决于它运行的硬件。显然，更快的处理器会给出更好的结果，然而，随着输入大小的增加，它们的相对增长率将保留算法本身的特征，而不是运行在硬件上。绝对时间值将在硬件（和软件）平台之间有所不同；然而，它们的相对增长仍将受到算法的时间复杂度的限制。

让我们以一个嵌套循环的简单例子来说明。很明显，这个算法的时间复杂度是*O(n²)*，因为在外部循环的每个*n*次迭代中，内部循环也有*n*次迭代。例如，我们简单的嵌套 for 循环包含在内部循环中执行的一个简单语句：

```py
def nest(n):   
for i in range(n):   
     for j in range(n):  
            i+j
```

以下代码是一个简单的测试函数，它使用不断增加的`n`值运行`nest`函数。在每次迭代中，我们使用`timeit.timeit`函数计算这个函数完成所需的时间。`timeit`函数在这个例子中接受三个参数，一个表示要计时的函数的字符串表示，一个导入`nest`函数的`setup`函数，以及一个`int`参数，表示执行主语句的次数。

由于我们对`nest`函数完成所需的时间与输入大小`n`感兴趣，对于我们的目的来说，每次迭代调用`nest`函数一次就足够了。以下函数返回每个`n`值的计算运行时间的列表：

```py
import timeit 
def test2(n): 
    ls=[]   
    for n in range(n):
        t=timeit.timeit("nest(" + str(n) + ")", setup="from _main_ import nest", number=1)  
        ls.append(t) 
    return ls
```

在下面的代码中，我们运行`test2`函数并绘制结果，以及适当缩放的`n²`函数进行比较，用虚线表示：

```py
import matplotlib.pyplot as plt 
n=1000 
plt.plot(test2(n)) 
plt.plot([x*x/10000000 for x in range(n)])
```

这给出了以下结果：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/0f25b101-61b9-454e-9adb-9f8774b28063.png)

正如我们所看到的，这基本上符合我们的预期。应该记住，这既代表了算法本身的性能，也代表了底层软件和硬件平台的行为，正如测量运行时间的变化和运行时间的相对大小所指示的那样。显然，更快的处理器会导致更快的运行时间，而且性能也会受到其他运行进程、内存限制、时钟速度等的影响。

# 总结

在本章中，我们已经对算法设计进行了一般性概述。重要的是，我们研究了一种独立于平台的算法性能衡量方法。我们研究了一些不同的算法问题解决方法。我们研究了一种递归相乘大数的方法，也研究了归并排序的递归方法。我们学习了如何使用回溯进行穷举搜索和生成字符串。我们还介绍了基准测试的概念以及一种简单的依赖于平台的衡量运行时间的方法。

在接下来的章节中，我们将参考特定的数据结构重新讨论这些想法。在下一章中，我们将讨论链表和其他指针结构。
