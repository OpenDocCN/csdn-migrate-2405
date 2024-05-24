# Python3 面向对象编程第二版（三）

> 原文：[`zh.annas-archive.org/md5/B484D481722F7AFA9E5B1ED7225BED43`](https://zh.annas-archive.org/md5/B484D481722F7AFA9E5B1ED7225BED43)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：Python 面向对象的快捷方式

Python 的许多方面看起来更像是结构化或函数式编程，而不是面向对象编程。尽管面向对象编程在过去的二十年中是最可见的范例，但旧模型最近又出现了。与 Python 的数据结构一样，这些工具大多是在基础面向对象实现之上的语法糖；我们可以将它们看作是在（已经抽象化的）面向对象范例之上构建的进一步抽象层。在本章中，我们将涵盖一些不严格面向对象的 Python 特性。

+   处理常见任务的内置函数

+   文件 I/O 和上下文管理器

+   方法重载的替代方法

+   函数作为对象

# Python 内置函数

Python 中有许多函数，可以在某些类型的对象上执行任务或计算结果，而不是作为基础类的方法。它们通常抽象出适用于多种类型的类的常见计算。这是鸭子类型的最佳体现；这些函数接受具有某些属性或方法的对象，并能够使用这些方法执行通用操作。其中许多，但并非全部，都是特殊的双下划线方法。我们已经使用了许多内置函数，但让我们快速浏览一下重要的函数，并学习一些巧妙的技巧。

## len()函数

最简单的例子是`len()`函数，它计算某种容器对象中的项目数量，例如字典或列表。你以前见过它：

```py
>>> len([1,2,3,4])
4

```

为什么这些对象没有长度属性，而是必须对它们调用一个函数？从技术上讲，它们有。大多数`len()`将适用于的对象都有一个名为`__len__()`的方法，返回相同的值。因此，`len(myobj)`似乎调用了`myobj.__len__()`。

为什么我们应该使用`len()`函数而不是`__len__`方法？显然，`__len__`是一个特殊的双下划线方法，这表明我们不应该直接调用它。这一定有一个解释。Python 开发人员不会轻易做出这样的设计决定。

主要原因是效率。当我们在对象上调用`__len__`时，对象必须在其命名空间中查找该方法，并且如果该对象上定义了特殊的`__getattribute__`方法（每次访问对象的属性或方法时都会调用），还必须调用该方法。此外，该特定方法的`__getattribute__`可能已经被编写为执行一些不好的操作，比如拒绝让我们访问`__len__`之类的特殊方法！`len()`函数不会遇到任何这些问题。它实际上调用了基础类上的`__len__`函数，因此`len(myobj)`映射到`MyObj.__len__(myobj)`。

另一个原因是可维护性。将来，Python 开发人员可能希望更改`len()`，以便它可以计算没有`__len__`的对象的长度，例如，通过计算迭代器返回的项目数量。他们只需要更改一个函数，而不是在整个系统中无数次更改`__len__`方法。

`len()`作为外部函数的另一个极其重要且经常被忽视的原因是向后兼容性。这在文章中经常被引用为“出于历史原因”，这是作者用来表示某事之所以是某种方式的一个轻蔑的短语，因为很久以前犯了一个错误，我们现在被困在这种情况下。严格来说，`len()`并不是一个错误，而是一个设计决策，但这个决策是在一个不那么面向对象的时代做出的。它经受住了时间的考验，并且有一些好处，所以要习惯它。

## 反转

`reversed()`函数接受任何序列作为输入，并返回该序列的一个副本，顺序相反。通常在`for`循环中使用，当我们想要从后到前循环遍历项目时。

与 `len` 类似，`reversed` 调用参数类的 `__reversed__()` 函数。如果该方法不存在，`reversed` 将使用对 `__len__` 和 `__getitem__` 的调用构建反转序列，这些方法用于定义序列。如果我们想要自定义或优化过程，只需要重写 `__reversed__`：

```py
normal_list=[1,2,3,4,5]

class CustomSequence():
 **def __len__(self):
        return 5

 **def __getitem__(self, index):
        return "x{0}".format(index)

class FunkyBackwards():

 **def __reversed__(self):
        return "BACKWARDS!"

for seq in normal_list, CustomSequence(), FunkyBackwards():
    print("\n{}: ".format(seq.__class__.__name__), end="")
    for item in reversed(seq):
        print(item, end=", ")
```

最后的 `for` 循环打印了正常列表的反转版本，以及两个自定义序列的实例。输出显示 `reversed` 在所有三个上都起作用，但当我们自己定义 `__reversed__` 时结果大不相同：

```py
list: 5, 4, 3, 2, 1,
CustomSequence: x4, x3, x2, x1, x0,
FunkyBackwards: B, A, C, K, W, A, R, D, S, !,

```

当我们反转 `CustomSequence` 时，`__getitem__` 方法将为每个项目调用，它只是在索引之前插入一个 `x`。对于 `FunkyBackwards`，`__reversed__` 方法返回一个字符串，其中的每个字符在 `for` 循环中单独输出。

### 注意

前面两个类不是很好的序列，因为它们没有定义 `__iter__` 的正确版本，所以对它们进行正向 `for` 循环将永远不会结束。

## 枚举

有时，当我们在 `for` 循环中循环容器时，我们希望访问索引（列表中的当前位置）的当前项目。`for` 循环不提供索引，但 `enumerate` 函数给了我们更好的东西：它创建了一个元组序列，其中每个元组中的第一个对象是索引，第二个是原始项目。

如果我们需要直接使用索引号，这很有用。考虑一些简单的代码，输出文件中的每一行及其行号：

```py
import sys
filename = sys.argv[1]

with open(filename) as file:
 **for index, line in enumerate(file):
        print("{0}: {1}".format(index+1, line), end='')
```

使用自己的文件名作为输入文件运行此代码可以显示它的工作原理：

```py
1: import sys
2: filename = sys.argv[1]
3:
4: with open(filename) as file:
5:     for index, line in enumerate(file):
6:         print("{0}: {1}".format(index+1, line), end='')
```

`enumerate` 函数返回一个元组序列，我们的 `for` 循环将每个元组拆分为两个值，`print` 语句将它们格式化在一起。它为每行号添加一个索引，因为 `enumerate`，像所有序列一样，是从零开始的。

我们只触及了一些更重要的 Python 内置函数。正如你所看到的，其中许多函数调用了面向对象的概念，而其他一些则遵循纯粹的函数式或过程式范式。标准库中还有许多其他函数；其中一些更有趣的包括：

+   `all` 和 `any`，它们接受一个可迭代对象，并在所有或任何项目评估为真时返回 `True`（例如非空字符串或列表，非零数，不是 `None` 的对象，或字面值 `True`）。

+   `eval`，`exec` 和 `compile`，它们将字符串作为代码在解释器中执行。对于这些要小心；它们不安全，所以不要执行未知用户提供给你的代码（一般来说，假设所有未知用户都是恶意的、愚蠢的或两者兼有）。

+   `hasattr`，`getattr`，`setattr` 和 `delattr`，它们允许通过它们的字符串名称操作对象的属性。

+   `zip`，它接受两个或更多序列，并返回一个新的元组序列，其中每个元组包含来自每个序列的单个值。

+   还有更多！请参阅解释器帮助文档，了解 `dir(__builtins__)` 中列出的每个函数。

## 文件 I/O

到目前为止，我们所涉及的与文件系统有关的示例完全是在文本文件上进行的，没有太多考虑到底层发生了什么。然而，操作系统实际上将文件表示为字节序列，而不是文本。我们将深入探讨字节和文本之间的关系，第八章 *字符串和序列化*。现在，请注意，从文件中读取文本数据是一个相当复杂的过程。Python，特别是 Python 3，在幕后为我们处理了大部分工作。我们是不是很幸运？

文件的概念早在有人创造面向对象编程这个术语之前就已经存在。然而，Python 封装了操作系统提供的接口，提供了一个良好的抽象，使我们能够使用文件（或类似文件，即鸭子类型）对象。

`open()`内置函数用于打开文件并返回文件对象。要从文件中读取文本，我们只需要将文件名传递给函数。文件将被打开以进行读取，并且字节将使用平台默认编码转换为文本。

当然，我们并不总是想要读取文件；通常我们想要向其中写入数据！要打开一个文件进行写入，我们需要将`mode`参数作为第二个位置参数传递，值为`"w"`：

```py
contents = "Some file contents"
file = open("filename", "w")
file.write(contents)
file.close()
```

我们还可以将值`"a"`作为模式参数传递，以追加到文件末尾，而不是完全覆盖现有文件内容。

这些具有内置包装器的文件，用于将字节转换为文本，非常好，但如果我们想要打开的文件是图像、可执行文件或其他二进制文件，那将非常不方便，不是吗？

要打开二进制文件，我们修改模式字符串以附加`'b'`。因此，`'wb'`将打开一个用于写入字节的文件，而`'rb'`允许我们读取它们。它们的行为类似于文本文件，但没有将文本自动编码为字节。当我们读取这样的文件时，它将返回`bytes`对象而不是`str`，当我们向其写入时，如果尝试传递文本对象，它将失败。

### 注意

这些模式字符串用于控制文件的打开方式，相当晦涩，既不符合 Python 的风格，也不是面向对象的。然而，它们与几乎所有其他编程语言保持一致。文件 I/O 是操作系统必须处理的基本工作之一，所有编程语言都必须使用相同的系统调用与操作系统进行通信。幸运的是，Python 返回一个带有有用方法的文件对象，而不是大多数主要操作系统用于标识文件句柄的整数！

一旦文件被打开以进行读取，我们可以调用`read`、`readline`或`readlines`方法来获取文件的内容。`read`方法将整个文件的内容作为`str`或`bytes`对象返回，具体取决于模式中是否有`'b'`。在大文件上不要在没有参数的情况下使用此方法。您不希望尝试将如此多的数据加载到内存中！

还可以从文件中读取固定数量的字节；我们将整数参数传递给`read`方法，描述我们想要读取多少字节。对`read`的下一次调用将加载下一个字节序列，依此类推。我们可以在`while`循环中执行此操作，以管理的方式读取整个文件。

`readline`方法从文件中返回一行（每行以换行符、回车符或两者结尾，具体取决于创建文件的操作系统）。我们可以重复调用它以获取其他行。复数`readlines`方法返回文件中所有行的列表。与`read`方法一样，它不适用于非常大的文件。这两种方法甚至在文件以`bytes`模式打开时也适用，但只有在解析具有合理位置换行符的类文本数据时才有意义。例如，图像或音频文件中不会有换行符（除非换行符字节恰好表示某个像素或声音），因此应用`readline`是没有意义的。

为了可读性，并且避免一次性将大文件读入内存，通常最好直接在文件对象上使用`for`循环。对于文本文件，它将一次读取一行，我们可以在循环体内对其进行处理。对于二进制文件，最好使用`read()`方法读取固定大小的数据块，传递一个参数来指定要读取的最大字节数。

写入文件就像写入文件一样简单；文件对象上的`write`方法将一个字符串（或字节，用于二进制数据）对象写入文件。可以重复调用它来写入多个字符串，一个接一个。`writelines`方法接受一个字符串序列，并将迭代的每个值写入文件。`writelines`方法*不*在序列中的每个项目后附加新行。它基本上是一个命名不当的便利函数，用于写入字符串序列的内容，而无需使用`for`循环显式迭代。

最后，我是指最后，我们来到`close`方法。当我们完成读取或写入文件时，应调用此方法，以确保任何缓冲写入都写入磁盘，文件已经得到适当清理，并且与文件关联的所有资源都释放回操作系统。从技术上讲，当脚本退出时，这将自动发生，但最好是明确地清理自己的东西，特别是在长时间运行的进程中。

## 将其放入上下文中

当我们完成文件时需要关闭文件，这可能会使我们的代码变得相当丑陋。因为在文件 I/O 期间可能随时发生异常，我们应该将对文件的所有调用包装在`try`...`finally`子句中。无论 I/O 是否成功，文件都应在`finally`子句中关闭。这不是很 Pythonic。当然，有一种更优雅的方法来做到这一点。

如果我们在类似文件的对象上运行`dir`，我们会看到它有两个名为`__enter__`和`__exit__`的特殊方法。这些方法将文件对象转换为所谓的**上下文管理器**。基本上，如果我们使用一种称为`with`语句的特殊语法，这些方法将在嵌套代码执行之前和之后被调用。对于文件对象，`__exit__`方法确保文件被关闭，即使引发异常。我们不再需要显式管理文件的关闭。这是`with`语句在实践中的样子：

```py
with open('filename') as file:
    for line in file:
        print(line, end='')
```

`open`调用返回一个文件对象，该对象具有`__enter__`和`__exit__`方法。返回的对象由`as`子句分配给名为`file`的变量。我们知道当代码返回到外部缩进级别时，文件将被关闭，并且即使引发异常，也会发生这种情况。

`with`语句在标准库中的几个地方使用，需要执行启动或清理代码。例如，`urlopen`调用返回一个对象，可以在`with`语句中使用以在完成时清理套接字。线程模块中的锁可以在语句执行后自动释放锁。

最有趣的是，因为`with`语句可以应用于具有适当特殊方法的任何对象，我们可以在自己的框架中使用它。例如，记住字符串是不可变的，但有时您需要从多个部分构建一个字符串。出于效率考虑，通常通过将组件字符串存储在列表中并在最后将它们连接来完成。让我们创建一个简单的上下文管理器，允许我们构建一个字符序列，并在退出时自动将其转换为字符串：

```py
class StringJoiner(list):
    def __enter__(self):
        return self

    **def __exit__(self, type, value, tb):
        self.result = "".join(self)
```

这段代码将两个特殊方法添加到`list`类中，这两个方法是上下文管理器所需的。`__enter__`方法执行任何必需的设置代码（在本例中没有），然后返回将分配给`with`语句中`as`后面的变量的对象。通常情况下，就像我们在这里做的一样，这只是上下文管理器对象本身。`__exit__`方法接受三个参数。在正常情况下，这些参数都被赋予`None`的值。然而，如果在`with`块内发生异常，它们将被设置为与异常类型、值和回溯相关的值。这允许`__exit__`方法执行任何可能需要的清理代码，即使发生异常。在我们的例子中，我们采取了不负责任的路径，并通过连接字符串中的字符来创建一个结果字符串，而不管是否抛出异常。

虽然这是我们可以编写的最简单的上下文管理器之一，而且它的实用性是可疑的，但它确实可以与`with`语句一起使用。看看它的运行情况：

```py
import random, string
with StringJoiner() as joiner:
    for i in range(15):
        joiner.append(random.choice(string.ascii_letters))

print(joiner.result)
```

这段代码构造了一个包含 15 个随机字符的字符串。它使用从`list`继承的`append`方法将这些字符附加到`StringJoiner`上。当`with`语句超出范围（回到外部缩进级别）时，将调用`__exit__`方法，并且连接器对象上的`result`属性变得可用。我们打印这个值来看一个随机字符串。

# 方法重载的替代方法

许多面向对象的编程语言的一个显著特点是一种称为**方法重载**的工具。方法重载简单地指的是具有相同名称但接受不同参数集的多个方法。在静态类型的语言中，如果我们想要一个方法既接受整数又接受字符串，这是很有用的。在非面向对象的语言中，我们可能需要两个函数，称为`add_s`和`add_i`，来适应这种情况。在静态类型的面向对象语言中，我们需要两个方法，都称为`add`，一个接受字符串，一个接受整数。

在 Python 中，我们只需要一个方法，它接受任何类型的对象。它可能需要对对象类型进行一些测试（例如，如果它是一个字符串，将其转换为整数），但只需要一个方法。

然而，方法重载在我们希望一个方法具有相同名称但接受不同数量或一组不同参数时也很有用。例如，电子邮件消息方法可能有两个版本，其中一个接受“from”电子邮件地址的参数。另一个方法可能会查找默认的“from”电子邮件地址。Python 不允许具有相同名称的多个方法，但它提供了一个不同但同样灵活的接口。

我们已经看到了在之前的例子中发送参数给方法和函数的一些可能方式，但现在我们将涵盖所有细节。最简单的函数不接受任何参数。我们可能不需要一个例子，但为了完整起见，这里有一个：

```py
def no_args():
    pass
```

调用方式如下：

```py
no_args()
```

接受参数的函数将在逗号分隔的列表中提供这些参数的名称。只需要提供每个参数的名称。

在调用函数时，这些位置参数必须按顺序指定，不能遗漏或跳过任何一个。这是我们在之前的例子中指定参数的最常见方式：

```py
def mandatory_args(x, y, z):
    pass
```

调用它：

```py
mandatory_args("a string", a_variable, 5)
```

任何类型的对象都可以作为参数传递：对象、容器、原始类型，甚至函数和类。前面的调用显示了一个硬编码的字符串、一个未知的变量和一个整数传递给函数。

## 默认参数

如果我们想要使参数可选，而不是创建具有不同参数集的第二个方法，我们可以在单个方法中指定默认值，使用等号。如果调用代码没有提供此参数，它将被分配一个默认值。但是，调用代码仍然可以选择通过传入不同的值来覆盖默认值。通常，`None`、空字符串或空列表是合适的默认值。

以下是带有默认参数的函数定义：

```py
def default_arguments(x, y, z, a="Some String", b=False):
    pass
```

前三个参数仍然是必需的，并且必须由调用代码传递。最后两个参数有默认参数。

有几种方法可以调用这个函数。我们可以按顺序提供所有参数，就好像所有参数都是位置参数一样：

```py
default_arguments("a string", variable, 8, "", True)
```

或者，我们可以按顺序提供必需的参数，将关键字参数分配它们的默认值：

```py
default_arguments("a longer string", some_variable, 14)
```

我们还可以在调用函数时使用等号语法提供不同顺序的值，或者跳过我们不感兴趣的默认值。例如，我们可以跳过第一个关键字参数并提供第二个参数：

```py
default_arguments("a string", variable, 14, b=True)
```

令人惊讶的是，我们甚至可以使用等号语法来改变位置参数的顺序，只要所有参数都被提供：

```py
>>> default_arguments(y=1,z=2,x=3,a="hi")
3 1 2 hi False

```

有这么多选项，可能很难选择一个，但是如果你把位置参数看作一个有序列表，把关键字参数看作一种字典，你会发现正确的布局往往会自然而然地出现。如果需要要求调用者指定参数，就把它设为必需的；如果有一个合理的默认值，那就把它设为关键字参数。选择如何调用方法通常会自行解决，取决于需要提供哪些值，哪些可以保持默认值。

关键字参数需要注意的一点是，我们提供的默认参数在函数首次解释时进行评估，而不是在调用时。这意味着我们不能有动态生成的默认值。例如，以下代码的行为不会完全符合预期：

```py
number = 5
def funky_function(number=number):
    print(number)

number=6
funky_function(8)
funky_function()
print(number)
```

如果我们运行这段代码，首先输出数字 8，但接着对于没有参数的调用输出数字 5。我们已经将变量设置为数字 6，正如输出的最后一行所证明的那样，但当函数被调用时，打印出数字 5；默认值是在函数定义时计算的，而不是在调用时计算的。

这在空容器（如列表、集合和字典）中有些棘手。例如，通常要求调用代码提供一个我们的函数将要操作的列表，但列表是可选的。我们希望将一个空列表作为默认参数。我们不能这样做；它将在代码首次构造时创建一个列表：

```py
>>> def hello(b=[]):
...     b.append('a')
...     print(b)
...
>>> hello()
['a']
>>> hello()
['a', 'a']

```

哎呀，这不是我们预期的结果！通常的解决方法是将默认值设为`None`，然后在方法内部使用习惯用法`iargument = argument if argument else []`。请注意！

## 可变参数列表

仅仅使用默认值并不能让我们获得方法重载的所有灵活优势。使 Python 真正灵活的是能够编写接受任意数量的位置或关键字参数的方法，而不需要显式命名它们。我们还可以将任意列表和字典传递给这样的函数。

例如，一个接受链接或链接列表并下载网页的函数可以使用这样的可变参数，或者**varargs**。我们可以接受任意数量的参数，其中每个参数都是不同的链接。我们通过在函数定义中指定`*`运算符来实现这一点：

```py
def get_pages(*links):
    for link in links:
        #download the link with urllib
        print(link)
```

`*links`参数表示“我将接受任意数量的参数，并将它们全部放入名为`links`的列表中”。如果我们只提供一个参数，它将是一个具有一个元素的列表；如果我们不提供参数，它将是一个空列表。因此，所有这些函数调用都是有效的：

```py
get_pages()
get_pages('http://www.archlinux.org')
get_pages('http://www.archlinux.org',
        'http://ccphillips.net/')
```

我们也可以接受任意关键字参数。这些参数以字典的形式传入函数。它们在函数声明中用两个星号（如`**kwargs`）指定。这个工具通常用于配置设置。以下类允许我们指定一组具有默认值的选项：

```py
class Options:
    default_options = {
            'port': 21,
            'host': 'localhost',
            'username': None,
            'password': None,
            'debug': False,
            }
    **def __init__(self, **kwargs):
        self.options = dict(Options.default_options)
        self.options.update(kwargs)

    def __getitem__(self, key):
        return self.options[key]
```

这个类中所有有趣的东西都发生在`__init__`方法中。我们在类级别有一个默认选项和值的字典。`__init__`方法的第一件事是复制这个字典。我们这样做是为了避免直接修改字典，以防我们实例化两组不同的选项。（请记住，类级别的变量在类的实例之间是共享的。）然后，`__init__`使用新字典上的`update`方法将任何非默认值更改为提供的关键字参数。`__getitem__`方法简单地允许我们使用新类使用索引语法。以下是演示该类工作的会话：

```py
>>> options = Options(username="dusty", password="drowssap",
 **debug=True)
>>> options['debug']
True
>>> options['port']
21
>>> options['username']
'dusty'

```

我们可以使用字典索引语法访问我们的选项实例，字典包括默认值和我们使用关键字参数设置的值。

关键字参数语法可能是危险的，因为它可能违反“明确胜于隐式”的规则。在前面的示例中，可能会将任意关键字参数传递给`Options`初始化程序，以表示默认字典中不存在的选项。这可能不是一件坏事，这取决于类的目的，但它使得使用该类的人很难发现哪些有效选项是可用的。它还使得很容易输入令人困惑的拼写错误（例如，“Debug”而不是“debug”），从而添加两个选项，而实际上只应该存在一个选项。

当我们需要接受要传递给第二个函数的任意参数时，关键字参数也非常有用，但我们不知道这些参数是什么。我们在第三章中看到了这一点，当我们构建多重继承的支持时。当然，我们可以在一个函数调用中结合可变参数和可变关键字参数语法，并且我们也可以使用正常的位置参数和默认参数。以下示例有些牵强，但演示了这四种类型的作用：

```py
import shutil
import os.path
def augmented_move(target_folder, *filenames,
        **verbose=False, **specific):
    '''Move all filenames into the target_folder, allowing
    specific treatment of certain files.'''

    def print_verbose(message, filename):
        '''print the message only if verbose is enabled'''
        if verbose:
            print(message.format(filename))

    for filename in filenames:
        target_path = os.path.join(target_folder, filename)
        if filename in specific:
            if specific[filename] == 'ignore':
                print_verbose("Ignoring {0}", filename)
            elif specific[filename] == 'copy':
                print_verbose("Copying {0}", filename)
                shutil.copyfile(filename, target_path)
        else:
            print_verbose("Moving {0}", filename)
            shutil.move(filename, target_path)
```

此示例将处理任意文件列表。第一个参数是目标文件夹，默认行为是将所有剩余的非关键字参数文件移动到该文件夹中。然后是一个仅限关键字参数，`verbose`，它告诉我们是否要打印有关每个处理的文件的信息。最后，我们可以提供一个包含要对特定文件名执行的操作的字典；默认行为是移动文件，但如果在关键字参数中指定了有效的字符串操作，它可以被忽略或复制。请注意函数参数的顺序；首先指定位置参数，然后是`*filenames`列表，然后是任何特定的仅限关键字参数，最后是一个`**specific`字典，用于保存剩余的关键字参数。

我们创建一个内部辅助函数`print_verbose`，只有在设置了`verbose`键时才会打印消息。这个函数通过将这个功能封装到一个单一位置来保持代码的可读性。

在常见情况下，假设所讨论的文件存在，可以调用此函数：

```py
>>> augmented_move("move_here", "one", "two")

```

这个命令将文件`one`和`two`移动到`move_here`目录中，假设它们存在（函数中没有错误检查或异常处理，因此如果文件或目标目录不存在，它将失败）。由于`verbose`默认为`False`，移动将在没有任何输出的情况下发生。

如果我们想要看到输出，我们可以这样调用它：

```py
>>> augmented_move("move_here", "three", verbose=True)
Moving three

```

这将移动名为`three`的一个文件，并告诉我们它在做什么。请注意，在这个例子中不可能将`verbose`指定为位置参数；我们必须传递关键字参数。否则，Python 会认为它是`*filenames`列表中的另一个文件名。

如果我们想要复制或忽略列表中的一些文件，而不是移动它们，我们可以传递额外的关键字参数：

```py
>>> augmented_move("move_here", "four", "five", "six",
 **four="copy", five="ignore")

```

这将移动第六个文件并复制第四个文件，但不会显示任何输出，因为我们没有指定`verbose`。当然，我们也可以这样做，关键字参数可以以任何顺序提供：

```py
>>> augmented_move("move_here", "seven", "eight", "nine",
 **seven="copy", verbose=True, eight="ignore")
Copying seven
Ignoring eight
Moving nine

```

## 解包参数

还有一个关于可变参数和关键字参数的巧妙技巧。我们在之前的一些示例中使用过它，但现在解释也不算晚。给定一个值的列表或字典，我们可以将这些值传递到函数中，就好像它们是普通的位置参数或关键字参数。看看这段代码：

```py
def show_args(arg1, arg2, arg3="THREE"):
    print(arg1, arg2, arg3)

some_args = range(3)
more_args = {
        "arg1": "ONE",
        "arg2": "TWO"}

print("Unpacking a sequence:", end=" ")

show_args(*some_args)
print("Unpacking a dict:", end=" ")

show_args(**more_args)

```

当我们运行它时，它看起来是这样的：

```py
Unpacking a sequence: 0 1 2
Unpacking a dict: ONE TWO THREE

```

该函数接受三个参数，其中一个具有默认值。但是当我们有一个包含三个参数的列表时，我们可以在函数调用中使用`*`运算符将其解包为三个参数。如果我们有一个参数字典，我们可以使用`**`语法将其解包为一组关键字参数。

当映射从用户输入或外部来源（例如互联网页面或文本文件）收集的信息到函数或方法调用时，这通常是最有用的。

还记得我们之前的例子吗？它使用文本文件中的标题和行来创建包含联系信息的字典列表？我们可以使用关键字解包将这些参数传递给专门构建的`Contact`对象上的`__init__`方法，该对象接受相同的参数集。看看你是否可以调整示例使其工作。

# 函数也是对象

过分强调面向对象原则的编程语言往往不赞成不是方法的函数。在这种语言中，你应该创建一个对象来包装所涉及的单个方法。有许多情况下，我们希望传递一个简单调用以执行操作的小对象。这在事件驱动编程中最常见，例如图形工具包或异步服务器；我们将在第十章和第十一章中看到一些使用它的设计模式，*Python 设计模式 I*和*Python 设计模式 II*。

在 Python 中，我们不需要将这些方法包装在对象中，因为函数本身就是对象！我们可以在函数上设置属性（尽管这不是常见的活动），并且我们可以传递它们以便在以后调用。它们甚至有一些可以直接访问的特殊属性。这里是另一个刻意的例子：

```py
def my_function():
    print("The Function Was Called")
my_function.description = "A silly function"

def second_function():
    print("The second was called")
second_function.description = "A sillier function."

def another_function(function):
    print("The description:", end=" ")
    print(function.description)
    print("The name:", end=" ")
    print(function.__name__)
    print("The class:", end=" ")
    print(function.__class__)
    print("Now I'll call the function passed in")
    function()

another_function(my_function)
another_function(second_function)

```

如果我们运行这段代码，我们可以看到我们能够将两个不同的函数传递到我们的第三个函数中，并获得不同的输出：

```py
The description: A silly function
The name: my_function
The class: <class 'function'>
Now I'll call the function passed in
The Function Was Called
The description: A sillier function.
The name: second_function
The class: <class 'function'>
Now I'll call the function passed in
The second was called
```

我们在函数上设置了一个名为`description`的属性（诚然，这些描述并不是很好）。我们还能够看到函数的`__name__`属性，并访问它的类，证明了函数确实是一个具有属性的对象。然后我们使用可调用语法（括号）调用了该函数。

函数作为顶级对象的一个最常见的用途是将它们传递以便在以后的某个日期执行，例如当满足某个条件时。让我们构建一个事件驱动的定时器，它正是这样做的：

```py
import datetime
import time

class TimedEvent:
    **def __init__(self, endtime, callback):
        self.endtime = endtime
        self.callback = callback

    def ready(self):
        return self.endtime <= datetime.datetime.now()

class Timer:
    def __init__(self):
        self.events = []

    **def call_after(self, delay, callback):
        end_time = datetime.datetime.now() + \
                datetime.timedelta(seconds=delay)

        self.events.append(TimedEvent(end_time, callback))

    def run(self):
        while True:
            ready_events = (e for e in self.events if e.ready())
            for event in ready_events:
                **event.callback(self)
                self.events.remove(event)
            time.sleep(0.5)
```

在生产中，这段代码应该有额外的文档，使用文档字符串！`call_after`方法至少应该提到`delay`参数是以秒为单位的，并且`callback`函数应该接受一个参数：调用的定时器。

这里有两个类。`TimedEvent`类实际上并不是其他类可以访问的；它只是存储`endtime`和`callback`。我们甚至可以在这里使用`tuple`或`namedtuple`，但是为了方便起见，给对象赋予一个告诉我们事件是否准备运行的行为，我们使用了一个类。

`Timer`类只是存储了一个即将到来的事件列表。它有一个`call_after`方法来添加一个新的事件。这个方法接受一个`delay`参数，表示在执行回调之前等待的秒数，以及`callback`函数本身：在正确的时间执行的函数。这个`callback`函数应该接受一个参数。

`run`方法非常简单；它使用生成器表达式来过滤出任何时间到来的事件，并按顺序执行它们。然后定时器循环无限继续，因此必须使用键盘中断（*Ctrl* + *C*或*Ctrl* + *Break*）来中断它。在每次迭代后，我们休眠半秒，以免使系统陷入停顿。

这里需要注意的重要事情是涉及回调函数的那些行。函数像任何其他对象一样被传递，定时器从不知道或关心函数的原始名称是什么，或者它是在哪里定义的。当该函数被调用时，定时器只是将圆括号语法应用于存储的变量。

这是一组测试定时器的回调函数：

```py
from timer import Timer
import datetime

def format_time(message, *args):
    now = datetime.datetime.now().strftime("%I:%M:%S")
    print(message.format(*args, now=now))

def one(timer):
    format_time("{now}: Called One")

def two(timer):
    format_time("{now}: Called Two")

def three(timer):
    format_time("{now}: Called Three")

class Repeater:
    def __init__(self):
        self.count = 0
    def repeater(self, timer):
        format_time("{now}: repeat {0}", self.count)
        self.count += 1
        timer.call_after(5, self.repeater)

timer = Timer()
timer.call_after(1, one)
timer.call_after(2, one)
timer.call_after(2, two)
timer.call_after(4, two)
timer.call_after(3, three)
timer.call_after(6, three)
repeater = Repeater()
timer.call_after(5, repeater.repeater)
format_time("{now}: Starting")
timer.run()
```

这个例子让我们看到多个回调函数如何与定时器交互。第一个函数是`format_time`函数。它使用字符串的`format`方法将当前时间添加到消息中，并演示了可变参数的作用。`format_time`方法将接受任意数量的位置参数，使用可变参数语法，然后将它们作为位置参数转发给字符串的`format`方法。之后，我们创建了三个简单的回调方法，它们只是输出当前时间和一个简短的消息，告诉我们哪个回调已经被触发。

`Repeater`类演示了方法也可以用作回调，因为它们实际上只是函数。它还展示了回调函数中的`timer`参数的用处：我们可以在当前正在运行的回调中向定时器添加一个新的定时事件。然后，我们创建了一个定时器，并向其中添加了几个在不同时间后调用的事件。最后，我们启动了定时器；输出显示事件按预期顺序运行：

```py
02:53:35: Starting
02:53:36: Called One
02:53:37: Called One
02:53:37: Called Two
02:53:38: Called Three
02:53:39: Called Two
02:53:40: repeat 0
02:53:41: Called Three
02:53:45: repeat 1
02:53:50: repeat 2
02:53:55: repeat 3
02:54:00: repeat 4
```

Python 3.4 引入了类似于这样的通用事件循环架构。我们将在第十三章 *并发*中讨论它。

## 使用函数作为属性

函数作为对象的一个有趣的效果是，它们可以被设置为其他对象的可调用属性。可以向已实例化的对象添加或更改函数：

```py
class A:
    def print(self):
        print("my class is A")

def fake_print():
    print("my class is not A")

a = A()
a.print()
a.print = fake_print
a.print()
```

这段代码创建了一个非常简单的类，其中包含一个不告诉我们任何新信息的`print`方法。然后我们创建了一个新的函数，告诉了我们一些我们不相信的东西。

当我们在`A`类的实例上调用`print`时，它的行为与预期一样。如果我们将`print`方法设置为指向一个新函数，它会告诉我们一些不同的东西：

```py
my class is A
my class is not A
```

还可以替换类的方法而不是对象的方法，尽管在这种情况下，我们必须将`self`参数添加到参数列表中。这将更改该对象的所有实例的方法，即使已经实例化了这些实例。显然，这样替换方法既危险又令人困惑。阅读代码的人会看到已调用一个方法，并在原始类上查找该方法。但是在原始类上的方法并不是被调用的方法。弄清楚到底发生了什么可能会变成一个棘手的，令人沮丧的调试过程。

它确实有其用途。通常，在运行时替换或添加方法（称为**monkey-patching**）在自动化测试中使用。如果测试客户端-服务器应用程序，我们可能不希望在测试客户端时实际连接到服务器；这可能导致资金的意外转移或向真实人员发送尴尬的测试电子邮件。相反，我们可以设置我们的测试代码来替换发送请求到服务器的对象的一些关键方法，这样它只记录这些方法已被调用。

Monkey-patching 也可以用于修复第三方代码中的错误或添加我们正在交互的功能，并且不会以我们需要的方式行为。但是，它应该谨慎应用；它几乎总是一个“混乱的黑客”。不过，有时它是适应现有库以满足我们需求的唯一方法。

## 可调用对象

就像函数是可以在其上设置属性的对象一样，也可以创建一个可以像函数一样被调用的对象。

任何对象都可以通过简单地给它一个接受所需参数的`__call__`方法来使其可调用。让我们通过使其可调用来使我们的`Repeater`类，从计时器示例中，更容易使用：

```py
class Repeater:
    def __init__(self):
        self.count = 0

    **def __call__(self, timer):
        format_time("{now}: repeat {0}", self.count)
        self.count += 1

        timer.call_after(5, self)

timer = Timer()

timer.call_after(5, Repeater())
format_time("{now}: Starting")
timer.run()
```

这个示例与之前的类没有太大的不同；我们所做的只是将`repeater`函数的名称更改为`__call__`并将对象本身作为可调用传递。请注意，当我们进行`call_after`调用时，我们传递参数`Repeater()`。这两个括号创建了一个类的新实例；它们并没有显式调用类。这发生在稍后，在计时器内部。如果我们想要在新实例化的对象上执行`__call__`方法，我们将使用相当奇怪的语法：`Repeater()()`。第一组括号构造了对象；第二组执行了`__call__`方法。如果我们发现自己这样做，我们可能没有使用正确的抽象。只有在对象被视为函数时才实现`__call__`函数。

# 案例研究

为了将本章介绍的一些原则联系起来，让我们构建一个邮件列表管理器。该管理器将跟踪分类为命名组的电子邮件地址。当发送消息时，我们可以选择一个组，并将消息发送到分配给该组的所有电子邮件地址。

现在，在我们开始处理这个项目之前，我们应该有一种安全的方法来测试它，而不会向一群真实的人发送电子邮件。幸运的是，Python 在这方面有所帮助；就像测试 HTTP 服务器一样，它有一个内置的**简单邮件传输协议**（**SMTP**）服务器，我们可以指示它捕获我们发送的任何消息，而不实际发送它们。我们可以使用以下命令运行服务器：

```py
python -m smtpd -n -c DebuggingServer localhost:1025

```

在命令提示符下运行此命令将在本地机器上的端口 1025 上启动运行 SMTP 服务器。但是，我们已经指示它使用`DebuggingServer`类（它与内置的 SMTP 模块一起提供），它不会将邮件发送给预期的收件人，而是在接收到邮件时将其简单地打印在终端屏幕上。好吧，是不是很整洁？

现在，在编写邮件列表之前，让我们编写一些实际发送邮件的代码。当然，Python 也支持标准库中的邮件发送，但它的接口有点奇怪，所以我们将编写一个新的函数来清晰地包装它：

```py
import smtplib
from email.mime.text import MIMEText

def send_email(subject, message, from_addr, *to_addrs,
        host="localhost", port=1025, **headers):

    email = MIMEText(message)
    email['Subject'] = subject
    email['From'] = from_addr
    for header, value in headers.items():
        email[header] = value

    sender = smtplib.SMTP(host, port)
    for addr in to_addrs:
        del email['To']
        email['To'] = addr
        sender.sendmail(from_addr, addr, email.as_string())
    sender.quit()
```

我们不会过分深入地讨论此方法中的代码；标准库中的文档可以为您提供使用`smtplib`和`email`模块的所有信息。

我们在函数调用中使用了变量参数和关键字参数语法。变量参数列表允许我们在默认情况下提供单个`to`地址的字符串，并允许在需要时提供多个地址。任何额外的关键字参数都将映射到电子邮件标头。这是变量参数和关键字参数的一个令人兴奋的用法，但它实际上并不是对调用函数的人来说一个很好的接口。实际上，它使得程序员想要做的许多事情都变得不可能。

传递给函数的标头表示可以附加到方法的辅助标头。这些标头可能包括`Reply-To`、`Return-Path`或*X-pretty-much-anything*。但是为了成为 Python 中的有效标识符，名称不能包括`-`字符。一般来说，该字符表示减法。因此，不可能使用`Reply-To = my@email.com`来调用函数。看来我们太急于使用关键字参数，因为这是我们在本章中刚学到的新工具。

我们将需要将参数更改为普通字典；这将起作用，因为任何字符串都可以用作字典中的键。默认情况下，我们希望这个字典是空的，但我们不能将默认参数设置为空字典。因此，我们将默认参数设置为`None`，然后在方法的开头设置字典：

```py
def send_email(subject, message, from_addr, *to_addrs,
        host="localhost", port=1025, headers=None):

    headers = {} if headers is None else headers
```

如果我们在一个终端中运行我们的调试 SMTP 服务器，我们可以在 Python 解释器中测试这段代码：

```py
>>> send_email("A model subject", "The message contents",
 **"from@example.com", "to1@example.com", "to2@example.com")

```

然后，如果我们检查调试 SMTP 服务器的输出，我们会得到以下内容：

```py
---------- MESSAGE FOLLOWS ----------
Content-Type: text/plain; charset="us-ascii"
MIME-Version: 1.0
Content-Transfer-Encoding: 7bit
Subject: A model subject
From: from@example.com
To: to1@example.com
X-Peer: 127.0.0.1

The message contents
------------ END MESSAGE ------------
---------- MESSAGE FOLLOWS ----------
Content-Type: text/plain; charset="us-ascii"
MIME-Version: 1.0
Content-Transfer-Encoding: 7bit
Subject: A model subject
From: from@example.com
To: to2@example.com
X-Peer: 127.0.0.1

The message contents
------------ END MESSAGE ------------

```

很好，它已经将我们的电子邮件发送到了两个预期的地址，并包括主题和消息内容。现在我们可以发送消息了，让我们来处理电子邮件组管理系统。我们需要一个对象，以某种方式将电子邮件地址与它们所在的组匹配起来。由于这是一对多的关系（任何一个电子邮件地址可以在多个组中；任何一个组可以与多个电子邮件地址相关联），我们学习过的数据结构似乎都不太理想。我们可以尝试一个将组名与相关电子邮件地址列表匹配的字典，但这样会重复电子邮件地址。我们也可以尝试一个将电子邮件地址与组匹配的字典，这样会导致组的重复。两者都不太理想。让我们尝试后一种版本，尽管直觉告诉我，组到电子邮件地址的解决方案可能更直接。

由于我们字典中的值始终是唯一电子邮件地址的集合，我们可能应该将它们存储在`set`容器中。我们可以使用`defaultdict`来确保每个键始终有一个`set`容器可用：

```py
from collections import defaultdict
class MailingList:
    '''Manage groups of e-mail addresses for sending e-mails.'''
    def __init__(self):
        self.email_map = defaultdict(set)

    def add_to_group(self, email, group):
        self.email_map[email].add(group)
```

现在，让我们添加一个方法，允许我们收集一个或多个组中的所有电子邮件地址。这可以通过将组列表转换为一个集合来完成：

```py
    def emails_in_groups(self, *groups):
        groups = set(groups)
        emails = set()
        for e, g in self.email_map.items():
            if g & groups:
                emails.add(e)
        return emails
```

首先，看看我们正在迭代的内容：`self.email_map.items()`。这个方法当然会返回字典中每个项目的键-值对元组。值是表示组的字符串集合。我们将这些拆分成两个变量，命名为`e`和`g`，分别代表电子邮件和组。只有当传入的组与电子邮件地址组相交时，我们才将电子邮件地址添加到返回值集合中。`g & groups`语法是`g.intersection(groups)`的快捷方式；`set`类通过实现特殊的`__and__`方法来调用`intersection`。

### 提示

这段代码可以通过使用集合推导式变得更加简洁，我们将在第九章*迭代器模式*中讨论。

现在，有了这些基本组件，我们可以轻松地向我们的`MailingList`类添加一个发送消息到特定组的方法：

```py
def send_mailing(self, subject, message, from_addr,
        *groups, headers=None):
    emails = self.emails_in_groups(*groups)
    send_email(subject, message, from_addr,
            *emails, headers=headers)
```

这个函数依赖于可变参数列表。作为输入，它接受一个组列表作为可变参数。它获取指定组的电子邮件列表，并将它们作为可变参数传递到`send_email`中，以及传递给这个方法的其他参数。

可以通过确保 SMTP 调试服务器在一个命令提示符中运行，并在第二个提示符中使用以下代码来加载代码来测试程序：

```py
python -i mailing_list.py

```

使用以下命令创建一个`MailingList`对象：

```py
>>> m = MailingList()

```

然后创建一些虚假的电子邮件地址和组，类似于：

```py
>>> m.add_to_group("friend1@example.com", "friends")
>>> m.add_to_group("friend2@example.com", "friends")
>>> m.add_to_group("family1@example.com", "family")
>>> m.add_to_group("pro1@example.com", "professional")

```

最后，使用以下命令发送电子邮件到特定组：

```py
>>> m.send_mailing("A Party",
"Friends and family only: a party", "me@example.com", "friends",
"family", headers={"Reply-To": "me2@example.com"})

```

指定组中每个地址的电子邮件应该显示在 SMTP 服务器的控制台上。

邮件列表的工作正常，但它有点无用；一旦我们退出程序，我们的信息数据库就丢失了。让我们修改它，添加一些方法来从文件中加载和保存电子邮件组列表。

总的来说，当在磁盘上存储结构化数据时，很有必要认真考虑它的存储方式。存在众多数据库系统的原因之一是，如果其他人已经考虑过数据的存储方式，你就不必再考虑了。我们将在下一章中看一些数据序列化机制，但对于这个例子，让我们保持简单，选择可能有效的第一个解决方案。

我心目中的数据格式是存储每个电子邮件地址，后跟一个空格，再跟一个逗号分隔的组列表。这种格式似乎是合理的，我们将采用它，因为数据格式化不是本章的主题。然而，为了说明为什么你需要认真考虑如何在磁盘上格式化数据，让我们来强调一下这种格式的一些问题。

首先，空格字符在技术上是合法的电子邮件地址。大多数电子邮件提供商禁止它（有充分的理由），但定义电子邮件地址的规范说，如果电子邮件地址在引号中，它可以包含空格。如果我们要在我们的数据格式中使用空格作为标记，我们应该在这个空格和电子邮件中的空格之间进行区分。出于简单起见，我们将假装这不是真的，但现实生活中的数据编码充满了这样愚蠢的问题。其次，考虑逗号分隔的组列表。如果有人决定在组名中放一个逗号会发生什么？如果我们决定在组名中禁止逗号，我们应该添加验证以确保这一点到我们的`add_to_group`方法。为了教学上的清晰，我们也将忽略这个问题。最后，有许多安全问题需要考虑：有人是否可以通过在他们的电子邮件地址中放一个虚假的逗号来把自己放入错误的组？如果解析器遇到无效文件会怎么做？

从这次讨论中得出的要点是，尽量使用经过现场测试的数据存储方法，而不是设计自己的数据序列化协议。你可能会忽略很多奇怪的边缘情况，最好使用已经遇到并解决了这些边缘情况的代码。

但是忘了那个，让我们只是写一些基本的代码，使用大量的一厢情愿来假装这种简单的数据格式是安全的：

```py
email1@mydomain.com group1,group2
email2@mydomain.com group2,group3

```

执行此操作的代码如下：

```py
    def save(self):
        with open(self.data_file, 'w') as file:
            for email, groups in self.email_map.items():
                file.write(
                    '{} {}\n'.format(email, ','.join(groups))
                )

    def load(self):
        self.email_map = defaultdict(set)
        try:
            with open(self.data_file) as file:
                for line in file:
                    email, groups = line.strip().split(' ')
                    groups = set(groups.split(','))
                    self.email_map[email] = groups
        except IOError:
            pass
```

在`save`方法中，我们使用上下文管理器打开文件并将文件写入格式化字符串。记住换行符；Python 不会为我们添加它。`load`方法首先重置字典（以防它包含来自对`load`的先前调用的数据），使用`for`...`in`语法，循环遍历文件中的每一行。同样，换行符包含在行变量中，所以我们必须调用`.strip()`来去掉它。我们将在下一章中学习更多关于这种字符串操作的知识。

在使用这些方法之前，我们需要确保对象具有`self.data_file`属性，可以通过修改`__init__`来实现：

```py
    def __init__(self, data_file):
        self.data_file = data_file
        self.email_map = defaultdict(set)
```

我们可以在解释器中测试这两种方法，如下所示：

```py
>>> m = MailingList('addresses.db')
>>> m.add_to_group('friend1@example.com', 'friends')
>>> m.add_to_group('family1@example.com', 'friends')
>>> m.add_to_group('family1@example.com', 'family')
>>> m.save()

```

生成的`addresses.db`文件包含以下行，如预期的那样：

```py
friend1@example.com friends
family1@example.com friends,family

```

我们还可以成功地将这些数据加载回`MailingList`对象中：

```py
>>> m = MailingList('addresses.db')
>>> m.email_map
defaultdict(<class 'set'>, {})
>>> m.load()
>>> m.email_map
defaultdict(<class 'set'>, {'friend2@example.com': {'friends\n'}, 'family1@example.com': {'family\n'}, 'friend1@example.com': {'friends\n'}})

```

正如您所看到的，我忘记了`load`命令，也可能很容易忘记`save`命令。为了使任何想要在自己的代码中使用我们的`MailingList`API 的人更容易一些，让我们提供支持上下文管理器的方法：

```py
    def __enter__(self):
        self.load()
        return self

    def __exit__(self, type, value, tb):
        self.save()
```

这些简单的方法只是将它们的工作委托给 load 和 save，但现在我们可以在交互式解释器中编写这样的代码，并知道以前存储的所有地址都已经被加载，并且在我们完成时整个列表将保存到文件中：

```py
>>> with MailingList('addresses.db') as ml:
...    ml.add_to_group('friend2@example.com', 'friends')
...    ml.send_mailing("What's up", "hey friends, how's it going", 'me@example.com', 'friends')

```

# 练习

如果您以前没有遇到`with`语句和上下文管理器，我鼓励您像往常一样，浏览您的旧代码，并确保所有打开文件的地方都使用`with`语句安全关闭。还要寻找可以编写自己的上下文管理器的地方。丑陋或重复的`try`...`finally`子句是一个很好的起点，但您可能会发现它们在任何需要在上下文中执行之前和/或之后的任务时都很有用。

您可能已经在现在之前使用了许多基本的内置函数。我们涵盖了其中的一些，但没有详细讨论。尝试使用`enumerate`、`zip`、`reversed`、`any`和`all`，直到您知道在合适的情况下会记得使用它们。特别重要的是`enumerate`函数；因为不使用它会导致一些非常丑陋的代码。

还要探索一些将函数作为可调用对象传递的应用程序，以及使用`__call__`方法使您自己的对象可调用。您可以通过将属性附加到函数或在对象上创建`__call__`方法来获得相同的效果。在哪种情况下您会使用一种语法，何时更适合使用另一种语法？

如果有大量的电子邮件需要发送，我们的邮件列表对象可能会使电子邮件服务器不堪重负。尝试重构它，以便您可以为不同的目的使用不同的`send_email`函数。其中一个函数可以是我们在这里使用的版本。另一个版本可能会将电子邮件放入队列，由不同的线程或进程中的服务器发送。第三个版本可能只是将数据输出到终端，从而避免了需要虚拟的 SMTP 服务器。您能否构建带有回调的邮件列表，以便`send_mailing`函数使用传入的任何内容？如果没有提供回调，则默认使用当前版本。

参数、关键字参数、可变参数和可变关键字参数之间的关系可能有点令人困惑。我们看到它们在多重继承时是如何痛苦地相互作用的。设计一些其他示例，看看它们如何能够很好地协同工作，以及了解它们何时不适用。

# 总结

在本章中，我们涵盖了一系列杂项主题。每个主题都代表了 Python 中流行的重要非面向对象的特性。仅仅因为我们可以使用面向对象的原则，并不意味着我们总是应该这样做！

但是，我们也看到 Python 通常通过为传统面向对象的语法提供语法快捷方式来实现这些功能。了解这些工具背后的面向对象原则使我们能够更有效地在自己的类中使用它们。

我们讨论了一系列内置函数和文件 I/O 操作。在调用带有参数、关键字参数和可变参数列表时，我们有许多不同的语法可供选择。上下文管理器对于将一段代码夹在两个方法调用之间的常见模式非常有用。甚至函数也是对象，反之亦然，任何普通对象都可以被调用。

在下一章中，我们将学习更多关于字符串和文件操作的知识，甚至会花一些时间来学习标准库中最不面向对象的主题之一：正则表达式。


# 第八章：字符串和序列化

在我们涉及更高级别的设计模式之前，让我们深入研究 Python 中最常见的对象之一：字符串。我们会发现字符串比看上去更复杂，还会涵盖搜索字符串的模式和序列化数据以便存储或传输。

特别是，我们将讨论：

+   字符串、字节和字节数组的复杂性

+   字符串格式化的内在和外在

+   几种序列化数据的方法

+   神秘的正则表达式

# 字符串

字符串是 Python 中的基本原语；我们几乎在我们迄今讨论的每个例子中都使用了它们。它们所做的就是表示一个不可变的字符序列。然而，虽然你以前可能没有考虑过，"字符"是一个有点模糊的词；Python 字符串能表示重音字符的序列吗？中文字符？希腊、西里尔或波斯字符呢？

在 Python 3 中，答案是肯定的。Python 字符串都以 Unicode 表示，这是一个可以表示地球上任何语言中的几乎任何字符的字符定义标准（还包括一些虚构的语言和随机字符）。这在很大程度上是无缝的。因此，让我们把 Python 3 字符串看作是不可变的 Unicode 字符序列。那么我们可以用这个不可变序列做什么呢？我们在之前的例子中已经提到了许多字符串可以被操作的方式，但让我们快速地在一个地方概括一下：字符串理论的速成课程！

## 字符串操作

如你所知，可以通过用单引号或双引号包裹一系列字符来在 Python 中创建字符串。可以使用三个引号字符轻松创建多行字符串，并且可以通过将它们并排放置来连接多个硬编码字符串。以下是一些例子：

```py
a = "hello"
b = 'world'
c = '''a multiple
line string'''
d = """More
multiple"""
e = ("Three " "Strings "
        "Together")
```

解释器会自动将最后一个字符串组合成一个字符串。也可以使用`+`运算符连接字符串（如`"hello " + "world"`）。当然，字符串不一定是硬编码的。它们也可以来自各种外部来源，如文本文件、用户输入，或者在网络上编码。

### 提示

相邻字符串的自动连接可能会导致一些滑稽的错误，当逗号丢失时。然而，当需要将长字符串放置在函数调用中而不超过 Python 风格指南建议的 79 个字符行长度限制时，这是非常有用的。

与其他序列一样，字符串可以被迭代（逐个字符），索引，切片或连接。语法与列表相同。

`str`类上有许多方法，可以使操作字符串更容易。Python 解释器中的`dir`和`help`命令可以告诉我们如何使用它们；我们将直接考虑一些更常见的方法。

几种布尔方便方法帮助我们确定字符串中的字符是否与某种模式匹配。以下是这些方法的摘要。其中大多数方法，如`isalpha`，`isupper`/`islower`，`startswith`/`endswith`都有明显的解释。`isspace`方法也相当明显，但请记住，所有空白字符（包括制表符、换行符）都被考虑在内，而不仅仅是空格字符。

`istitle`方法返回`True`，如果每个单词的第一个字符都是大写，其他字符都是小写。请注意，它并不严格执行英语的标题格式定义。例如，Leigh Hunt 的诗歌"The Glove and the Lions"应该是一个有效的标题，即使并非所有单词都是大写。Robert Service 的"The Cremation of Sam McGee"也应该是一个有效的标题，即使最后一个单词中间有一个大写字母。

对于`isdigit`，`isdecimal`和`isnumeric`方法要小心，因为它们比您期望的更微妙。许多 Unicode 字符被认为是数字，除了我们习惯的十个数字之外。更糟糕的是，我们用来从字符串构造浮点数的句点字符不被视为十进制字符，因此`'45.2'.isdecimal()`返回`False`。真正的十进制字符由 Unicode 值 0660 表示，如 45.2 中的 0660（或`45\u06602`）。此外，这些方法不验证字符串是否为有效数字；"127.0.0.1"对所有三种方法都返回`True`。我们可能认为应该使用该十进制字符而不是句点来表示所有数字数量，但将该字符传递给`float()`或`int()`构造函数会将该十进制字符转换为零：

```py
>>> float('45\u06602')
4502.0

```

用于模式匹配的其他有用方法不返回布尔值。`count`方法告诉我们给定子字符串在字符串中出现了多少次，而`find`，`index`，`rfind`和`rindex`告诉我们给定子字符串在原始字符串中的位置。两个`r`（表示“右”或“反向”）方法从字符串的末尾开始搜索。如果找不到子字符串，`find`方法返回`-1`，而`index`在这种情况下会引发`ValueError`。看看其中一些方法的实际应用：

```py
>>> s = "hello world"
>>> s.count('l')
3
>>> s.find('l')
2
>>> s.rindex('m')
Traceback (most recent call last):
 **File "<stdin>", line 1, in <module>
ValueError: substring not found

```

其余大多数字符串方法返回字符串的转换。`upper`，`lower`，`capitalize`和`title`方法创建具有给定格式的所有字母字符的新字符串。`translate`方法可以使用字典将任意输入字符映射到指定的输出字符。

对于所有这些方法，请注意输入字符串保持不变；而是返回一个全新的`str`实例。如果我们需要操作结果字符串，我们应该将其赋值给一个新变量，如`new_value = value.capitalize()`。通常，一旦我们执行了转换，我们就不再需要旧值了，因此一个常见的习惯是将其赋值给相同的变量，如`value = value.title()`。

最后，一些字符串方法返回或操作列表。`split`方法接受一个子字符串，并在该子字符串出现的地方将字符串拆分为字符串列表。您可以将数字作为第二个参数传递以限制结果字符串的数量。`rsplit`如果不限制字符串的数量，则行为与`split`相同，但如果您提供了限制，它将从字符串的末尾开始拆分。`partition`和`rpartition`方法仅在子字符串的第一次或最后一次出现时拆分字符串，并返回一个包含三个值的元组：子字符串之前的字符，子字符串本身和子字符串之后的字符。

作为`split`的反向操作，`join`方法接受一个字符串列表，并通过将原始字符串放在它们之间来返回所有这些字符串组合在一起的字符串。`replace`方法接受两个参数，并返回一个字符串，其中第一个参数的每个实例都已被第二个参数替换。以下是其中一些方法的实际应用：

```py
>>> s = "hello world, how are you"
>>> s2 = s.split(' ')
>>> s2
['hello', 'world,', 'how', 'are', 'you']
>>> '#'.join(s2)
'hello#world,#how#are#you'
>>> s.replace(' ', '**')
'hello**world,**how**are**you'
>>> s.partition(' ')
('hello', ' ', 'world, how are you')

```

这就是最常见的`str`类上的方法的快速浏览！现在，让我们看看 Python 3 的方法，用于组合字符串和变量以创建新字符串。

## 字符串格式化

Python 3 具有强大的字符串格式化和模板机制，允许我们构造由硬编码文本和插入的变量组成的字符串。我们在许多先前的示例中使用过它，但它比我们使用的简单格式化说明符要灵活得多。

任何字符串都可以通过在其上调用`format()`方法将其转换为格式化字符串。此方法返回一个新字符串，其中输入字符串中的特定字符已被替换为作为参数和关键字参数传递给函数的值。`format`方法不需要固定的参数集；在内部，它使用了我们在第七章中讨论的`*args`和`**kwargs`语法，*Python 面向对象的快捷方式*。

在格式化字符串中替换的特殊字符是开放和关闭的大括号字符：`{`和`}`。我们可以在字符串中插入这些对，并且它们将按顺序被任何传递给`str.format`方法的位置参数替换：

```py
template = "Hello {}, you are currently {}."
print(template.format('Dusty', 'writing'))
```

如果我们运行这些语句，它将按顺序用变量替换大括号：

```py
Hello Dusty, you are currently writing.

```

如果我们想要在一个字符串中重用变量或者决定在不同位置使用它们，这种基本语法就不是特别有用。我们可以在花括号中放置从零开始的整数，以告诉格式化程序在字符串的特定位置插入哪个位置变量。让我们重复一下名字：

```py
template = "Hello {0}, you are {1}. Your name is {0}."
print(template.format('Dusty', 'writing'))
```

如果我们使用这些整数索引，我们必须在所有变量中使用它们。我们不能将空大括号与位置索引混合使用。例如，这段代码会因为适当的`ValueError`异常而失败：

```py
template = "Hello {}, you are {}. Your name is {0}."
print(template.format('Dusty', 'writing'))
```

### 转义大括号

大括号字符在字符串中通常很有用，除了格式化之外。我们需要一种方法来在我们希望它们以它们自己的形式显示而不是被替换的情况下对它们进行转义。这可以通过加倍大括号来实现。例如，我们可以使用 Python 来格式化一个基本的 Java 程序：

```py
template = """
public class {0} {{
    public static void main(String[] args) {{
        System.out.println("{1}");
    }}
}}"""

print(template.format("MyClass", "print('hello world')"));
```

在模板中，无论我们看到`{{`或`}}`序列，也就是包围 Java 类和方法定义的大括号，我们知道`format`方法将用单个大括号替换它们，而不是一些传递给`format`方法的参数。以下是输出：

```py
public class MyClass {
 **public static void main(String[] args) {
 **System.out.println("print('hello world')");
 **}
}

```

输出的类名和内容已被替换为两个参数，而双大括号已被替换为单大括号，从而给我们一个有效的 Java 文件。结果是，这是一个打印最简单的 Java 程序的最简单的可能的 Python 程序，可以打印最简单的可能的 Python 程序！

### 关键字参数

如果我们要格式化复杂的字符串，要记住参数的顺序或者更新模板如果我们选择插入一个新的参数可能会变得很繁琐。因此，`format`方法允许我们在大括号内指定名称而不是数字。然后将命名变量作为关键字参数传递给`format`方法：

```py
template = """
From: <{from_email}>
To: <{to_email}>
Subject: {subject}

{message}"""
print(template.format(
    from_email = "a@example.com",
    to_email = "b@example.com",
 **message = "Here's some mail for you. "
 **" Hope you enjoy the message!",
    subject = "You have mail!"
    ))
```

我们还可以混合使用索引和关键字参数（与所有 Python 函数调用一样，关键字参数必须跟在位置参数后面）。我们甚至可以将未标记的位置大括号与关键字参数混合使用：

```py
print("{} {label} {}".format("x", "y", label="z"))
```

如预期的那样，这段代码输出：

```py
x z y

```

### 容器查找

我们不仅限于将简单的字符串变量传递给`format`方法。任何原始类型，如整数或浮点数都可以打印。更有趣的是，可以使用复杂对象，包括列表、元组、字典和任意对象，并且可以从`format`字符串中访问这些对象的索引和变量（但不能访问方法）。

例如，如果我们的电子邮件消息将发件人和收件人的电子邮件地址分组到一个元组中，并将主题和消息放在一个字典中，出于某种原因（也许是因为这是现有`send_mail`函数所需的输入），我们可以这样格式化它：

```py
emails = ("a@example.com", "b@example.com")
message = {
        'subject': "You Have Mail!",
        'message': "Here's some mail for you!"
        }
template = """
From: <{0[0]}>
To: <{0[1]}>
Subject: {message[subject]}
{message[message]}"""
print(template.format(emails, message=message))
```

模板字符串中大括号内的变量看起来有点奇怪，所以让我们看看它们在做什么。我们已经将一个参数作为基于位置的参数传递，另一个作为关键字参数。两个电子邮件地址通过`0[x]`查找，其中`x`可以是`0`或`1`。初始的零表示，与其他基于位置的参数一样，传递给`format`的第一个位置参数（在这种情况下是`emails`元组）。

带有数字的方括号是我们在常规 Python 代码中看到的相同类型的索引查找，所以`0[0]`映射到`emails[0]`，在`emails`元组中。索引语法适用于任何可索引的对象，所以当我们访问`message[subject]`时，我们看到类似的行为，除了这次我们在字典中查找一个字符串键。请注意，与 Python 代码不同的是，在字典查找中我们不需要在字符串周围加上引号。

如果我们有嵌套的数据结构，甚至可以进行多层查找。我建议不要经常这样做，因为模板字符串很快就变得难以理解。如果我们有一个包含元组的字典，我们可以这样做：

```py
emails = ("a@example.com", "b@example.com")
message = {
        'emails': emails,
        'subject': "You Have Mail!",
        'message': "Here's some mail for you!"
        }
template = """
From: <{0[emails][0]}>
To: <{0[emails][1]}>
Subject: {0[subject]}
{0[message]}"""
print(template.format(message))
```

### 对象查找

索引使`format`查找功能强大，但我们还没有完成！我们还可以将任意对象作为参数传递，并使用点符号来查找这些对象的属性。让我们再次更改我们的电子邮件消息数据，这次是一个类：

```py
class EMail:
    def __init__(self, from_addr, to_addr, subject, message):
        self.from_addr = from_addr
        self.to_addr = to_addr
        self.subject = subject
        self.message = message

email = EMail("a@example.com", "b@example.com",
        "You Have Mail!",
         "Here's some mail for you!")

template = """
From: <{0.from_addr}>
To: <{0.to_addr}>
Subject: {0.subject}

{0.message}"""
print(template.format(email))
```

在这个例子中，模板可能比之前的例子更易读，但创建一个电子邮件类的开销会给 Python 代码增加复杂性。为了将对象包含在模板中而创建一个类是愚蠢的。通常，如果我们要格式化的对象已经存在，我们会使用这种查找。所有的例子都是如此；如果我们有一个元组、列表或字典，我们会直接将其传递到模板中。否则，我们只需创建一组简单的位置参数和关键字参数。

### 使其看起来正确

在模板字符串中包含变量是很好的，但有时变量需要一点强制转换才能使它们在输出中看起来正确。例如，如果我们在货币计算中，可能会得到一个我们不想在模板中显示的长小数：

```py
subtotal = 12.32
tax = subtotal * 0.07
total = subtotal + tax

print("Sub: ${0} Tax: ${1} Total: ${total}".format(
    subtotal, tax, total=total))
```

如果我们运行这个格式化代码，输出看起来并不像正确的货币：

```py
Sub: $12.32 Tax: $0.8624 Total: $13.182400000000001

```

### 注意

从技术上讲，我们不应该在货币计算中使用浮点数；我们应该使用`decimal.Decimal()`对象来构造。浮点数是危险的，因为它们的计算在特定精度水平之后本质上是不准确的。但我们正在看字符串，而不是浮点数，货币是格式化的一个很好的例子！

为了修复前面的`format`字符串，我们可以在花括号内包含一些额外的信息，以调整参数的格式。我们可以定制很多东西，但花括号内的基本语法是相同的；首先，我们使用早期的布局（位置、关键字、索引、属性访问）中适合的布局来指定我们想要放入模板字符串中的变量。然后我们跟着一个冒号，然后是特定的格式语法。这是一个改进版：

```py
print("Sub: ${0:0.2f} Tax: ${1:0.2f} "
        "Total: ${total:0.2f}".format(
            subtotal, tax, total=total))
```

冒号后面的`0.2f`格式说明符基本上是这样说的，从左到右：对于小于一的值，确保小数点左侧显示一个零；显示小数点后两位；将输入值格式化为浮点数。

我们还可以指定每个数字在屏幕上占据特定数量的字符，方法是在精度的句点之前放置一个值。这对于输出表格数据非常有用，例如：

```py
orders = [('burger', 2, 5),
        ('fries', 3.5, 1),
        ('cola', 1.75, 3)]

print("PRODUCT    QUANTITY    PRICE    SUBTOTAL")
for product, price, quantity in orders:
    subtotal = price * quantity
 **print("{0:10s}{1: ⁹d}    ${2: <8.2f}${3: >7.2f}".format(
 **product, quantity, price, subtotal))

```

好的，这是一个看起来相当可怕的格式字符串，让我们看看它是如何工作的，然后再将其分解成可理解的部分：

```py
PRODUCT    QUANTITY    PRICE    SUBTOTAL
burger        5        $2.00    $  10.00
fries         1        $3.50    $   3.50
cola          3        $1.75    $   5.25

```

厉害！那么，这实际上是如何发生的呢？在`for`循环中的每一行中，我们正在格式化四个变量。第一个变量是一个字符串，并且使用`{0:10s}`进行格式化。`s`表示它是一个字符串变量，`10`表示它应该占用十个字符。默认情况下，对于字符串，如果字符串的长度小于指定的字符数，它会在字符串的右侧附加空格，使其足够长（但要注意，如果原始字符串太长，它不会被截断！）。我们可以更改这种行为（在格式字符串中填充其他字符或更改对齐方式），就像我们对下一个值`quantity`所做的那样。

`quantity`值的格式化程序是`{1: ⁹d}`。`d`表示整数值。`9`告诉我们该值应该占用九个字符。但是对于整数，额外的字符默认情况下是零，而不是空格。这看起来有点奇怪。因此，我们明确指定一个空格（在冒号后面）作为填充字符。插入符`^`告诉我们数字应该对齐在这个可用填充的中心；这使得列看起来更专业一些。说明符必须按正确的顺序，尽管所有都是可选的：首先填充，然后对齐，然后大小，最后类型。

我们对价格和小计的说明符做了类似的处理。对于`price`，我们使用`{2: <8.2f}`，对于`subtotal`，我们使用`{3: >7.2f}`。在这两种情况下，我们指定空格作为填充字符，但是我们分别使用`<`和`>`符号，表示数字应该在八个或七个字符的最小空间内左对齐或右对齐。此外，每个浮点数应该格式化为两位小数。

不同类型的“类型”字符也会影响格式化输出。我们已经看到了`s`、`d`和`f`类型，分别代表字符串、整数和浮点数。大多数其他格式说明符都是这些类型的替代版本；例如，`o`代表八进制格式，`X`代表十六进制格式。`n`类型说明符可以用于在当前区域设置的格式中格式化整数分隔符。对于浮点数，`%`类型将乘以 100 并将浮点数格式化为百分比。

虽然这些标准格式适用于大多数内置对象，但其他对象也可以定义非标准的说明符。例如，如果我们将`datetime`对象传递给`format`，我们可以使用`datetime.strftime`函数中使用的说明符，如下所示：

```py
import datetime
print("{0:%Y-%m-%d %I:%M%p }".format(
    datetime.datetime.now()))
```

甚至可以为我们自己创建的对象编写自定义格式化程序，但这超出了本书的范围。如果您需要在代码中执行此操作，请查看如何覆盖`__format__`特殊方法。最全面的说明可以在 PEP 3101 中找到[`www.python.org/dev/peps/pep-3101/`](http://www.python.org/dev/peps/pep-3101/)，尽管细节有点枯燥。您可以通过网络搜索找到更易理解的教程。

Python 的格式化语法非常灵活，但是很难记住。我每天都在使用它，但偶尔还是不得不查阅文档中忘记的概念。它也不足以满足严肃的模板需求，比如生成网页。如果您需要做更多的字符串基本格式化，可以查看几个第三方模板库。

## 字符串是 Unicode

在本节的开头，我们将字符串定义为不可变的 Unicode 字符集合。这实际上有时会使事情变得非常复杂，因为 Unicode 实际上并不是一种存储格式。例如，如果从文件或套接字中获取字节字符串，它们实际上不会是 Unicode。它们实际上是内置类型`bytes`。字节是不可变的序列...嗯，字节。字节是计算机中最低级别的存储格式。它们代表 8 位，通常描述为介于 0 和 255 之间的整数，或者介于 0 和 FF 之间的十六进制等价物。字节不代表任何特定的内容；一系列字节可以存储编码字符串的字符，或者图像中的像素。

如果我们打印一个字节对象，任何映射到 ASCII 表示的字节都将打印为它们原始的字符，而非 ASCII 字节（无论它们是二进制数据还是其他字符）都将以`\x`转义序列转义的十六进制代码打印出来。你可能会觉得奇怪，一个字节，表示为一个整数，可以映射到一个 ASCII 字符。但 ASCII 实际上只是一个代码，其中每个字母都由不同的字节模式表示，因此，不同的整数。字符“a”由与整数 97 相同的字节表示，这是十六进制数 0x61。具体来说，所有这些都是对二进制模式 01100001 的解释。

许多 I/O 操作只知道如何处理`bytes`，即使字节对象引用文本数据。因此，了解如何在`bytes`和 Unicode 之间转换至关重要。

问题在于有许多种方法可以将`bytes`映射到 Unicode 文本。字节是机器可读的值，而文本是一种人类可读的格式。它们之间是一种编码，它将给定的字节序列映射到给定的文本字符序列。

然而，有多种这样的编码（ASCII 只是其中之一）。当使用不同的编码进行映射时，相同的字节序列代表完全不同的文本字符！因此，`bytes`必须使用与它们编码时相同的字符集进行解码。如果我们收到未知编码的字节而没有指定编码，我们能做的最好的事情就是猜测它们的编码格式，而我们可能会猜错。

### 将字节转换为文本

如果我们从某个地方有一个`bytes`数组，我们可以使用`bytes`类的`.decode`方法将其转换为 Unicode。这个方法接受一个字符串作为字符编码的名称。有许多这样的名称；西方语言的常见名称包括 ASCII、UTF-8 和拉丁-1。

字节序列（十六进制）63 6c 69 63 68 e9，实际上代表了拉丁-1 编码中单词 cliché的字符。以下示例将对这个字节序列进行编码，并使用拉丁-1 编码将其转换为 Unicode 字符串：

```py
characters = b'\x63\x6c\x69\x63\x68\xe9'
print(characters)
print(characters.decode("latin-1"))

```

第一行创建了一个`bytes`对象；字符串前面的`b`字符告诉我们，我们正在定义一个`bytes`对象，而不是一个普通的 Unicode 字符串。在字符串中，每个字节都使用十六进制数字指定。在这种情况下，`\x`字符在字节字符串中转义，并且每个都表示“下面的两个字符使用十六进制数字表示一个字节”。

只要我们使用了理解拉丁-1 编码的 shell，两个`print`调用将输出以下字符串：

```py
b'clich\xe9'
cliché

```

第一个`print`语句将 ASCII 字符的字节呈现为它们自己。未知的（对 ASCII 来说是未知的）字符保持在其转义的十六进制格式中。输出包括一行开头的`b`字符，提醒我们这是一个`bytes`表示，而不是一个字符串。

下一个调用使用 latin-1 编码解码字符串。`decode`方法返回一个带有正确字符的普通（Unicode）字符串。然而，如果我们使用西里尔文“iso8859-5”编码解码相同的字符串，我们最终会得到字符串'clichщ'！这是因为`\xe9`字节在这两种编码中映射到不同的字符。

### 将文本转换为字节

如果我们需要将传入的字节转换为 Unicode，显然我们也会遇到将传出的 Unicode 转换为字节序列的情况。这是通过`str`类上的`encode`方法完成的，就像`decode`方法一样，需要一个字符集。以下代码创建一个 Unicode 字符串，并以不同的字符集对其进行编码：

```py
characters = "cliché"
print(characters.encode("UTF-8"))
print(characters.encode("latin-1"))
print(characters.encode("CP437"))
print(characters.encode("ascii"))
```

前三种编码为重音字符创建了不同的字节集。第四种甚至无法处理该字节：

```py
b'clich\xc3\xa9'
b'clich\xe9'
b'clich\x82'
Traceback (most recent call last):
 **File "1261_10_16_decode_unicode.py", line 5, in <module>
 **print(characters.encode("ascii"))
UnicodeEncodeError: 'ascii' codec can't encode character '\xe9' in position 5: ordinal not in range(128)

```

现在你明白编码的重要性了吗？重音字符对于每种编码都表示为不同的字节；如果我们在解码字节为文本时使用错误的编码，我们会得到错误的字符。

在最后一种情况下，异常并不总是期望的行为；可能有些情况下我们希望以不同的方式处理未知字符。`encode`方法接受一个名为`errors`的可选字符串参数，可以定义如何处理这些字符。这个字符串可以是以下之一：

+   `strict`

+   `replace`

+   `ignore`

+   `xmlcharrefreplace`

`strict`替换策略是我们刚刚看到的默认值。当遇到一个字节序列在请求的编码中没有有效表示时，会引发异常。当使用`replace`策略时，字符将被替换为不同的字符；在 ASCII 中，它是一个问号；其他编码可能使用不同的符号，比如一个空盒子。`ignore`策略简单地丢弃它不理解的任何字节，而`xmlcharrefreplace`策略创建一个代表 Unicode 字符的`xml`实体。这在将未知字符串转换为 XML 文档中使用时非常有用。以下是每种策略对我们示例单词的影响：

| 策略 | "cliché".encode("ascii", strategy) |
| --- | --- |
| `replace` | `b'clich?'` |
| `ignore` | `b'clich'` |
| `xmlcharrefreplace` | `b'cliché'` |

可以调用`str.encode`和`bytes.decode`方法而不传递编码字符串。编码将设置为当前平台的默认编码。这将取决于当前操作系统和区域设置；您可以使用`sys.getdefaultencoding()`函数查找它。不过，通常最好明确指定编码，因为平台的默认编码可能会更改，或者程序可能有一天会扩展到处理更多来源的文本。

如果您要对文本进行编码，但不知道要使用哪种编码，最好使用 UTF-8 编码。UTF-8 能够表示任何 Unicode 字符。在现代软件中，它是确保以任何语言甚至多种语言交换文档的事实标准编码。其他各种可能的编码对于传统文档或仍然默认使用不同字符集的地区非常有用。

UTF-8 编码使用一个字节来表示 ASCII 和其他常见字符，对于更复杂的字符最多使用四个字节。UTF-8 很特殊，因为它向后兼容 ASCII；使用 UTF-8 编码的任何 ASCII 文档将与原始 ASCII 文档相同。

### 提示

我永远记不住是使用`encode`还是`decode`来将二进制字节转换为 Unicode。我总是希望这些方法的名称改为"to_binary"和"from_binary"。如果您有同样的问题，请尝试在脑海中用"binary"替换"code"；"enbinary"和"debinary"与"to_binary"和"from_binary"非常接近。自从想出这个记忆方法以来，我已经节省了很多时间，因为不用再查找方法帮助文件。

## 可变字节字符串

`bytes`类型和`str`一样是不可变的。我们可以在`bytes`对象上使用索引和切片表示法，并搜索特定的字节序列，但我们不能扩展或修改它们。当处理 I/O 时，这可能非常不方便，因为通常需要缓冲传入或传出的字节，直到它们准备好发送。例如，如果我们从套接字接收数据，可能需要多次`recv`调用才能接收到整个消息。

这就是`bytearray`内置的作用。这种类型的行为有点像列表，只是它只包含字节。该类的构造函数可以接受一个`bytes`对象来初始化它。`extend`方法可以用来附加另一个`bytes`对象到现有的数组中（例如，当更多的数据来自套接字或其他 I/O 通道时）。

切片表示法可以在`bytearray`上使用，以内联修改项目。例如，这段代码从`bytes`对象构造了一个`bytearray`，然后替换了两个字节：

```py
b = bytearray(b"abcdefgh")
b[4:6] = b"\x15\xa3"
print(b)
```

输出如下：

```py
bytearray(b'abcd\x15\xa3gh')

```

要小心；如果我们想要操作`bytearray`中的单个元素，它将期望我们传递一个介于 0 和 255 之间的整数作为值。这个整数代表一个特定的`bytes`模式。如果我们尝试传递一个字符或`bytes`对象，它将引发异常。

单字节字符可以使用`ord`（ordinal 的缩写）函数转换为整数。这个函数返回单个字符的整数表示：

```py
b = bytearray(b'abcdef')
b[3] = ord(b'g')
b[4] = 68
print(b)
```

输出如下：

```py
bytearray(b'abcgDf')

```

在构造数组之后，我们用字节 103 替换索引为`3`（第四个字符，因为索引从`0`开始，就像列表一样）。这个整数是由`ord`函数返回的，是小写`g`的 ASCII 字符。为了说明，我们还用字节号`68`替换了上一个字符，它映射到大写`D`的 ASCII 字符。

`bytearray`类型有一些方法，使它可以像列表一样行为（例如，我们可以向其附加整数字节），但也像`bytes`对象；我们可以使用`count`和`find`方法，就像它们在`bytes`或`str`对象上的行为一样。不同之处在于`bytearray`是一种可变类型，这对于从特定输入源构建复杂的字节序列是有用的。

# 正则表达式

你知道使用面向对象的原则真的很难做的事情是什么吗？解析字符串以匹配任意模式，就是这样。已经有相当多的学术论文使用面向对象的设计来设置字符串解析，但结果总是非常冗长和难以阅读，并且在实践中并不广泛使用。

在现实世界中，大多数编程语言中的字符串解析都是由正则表达式处理的。这些表达式并不冗长，但是，哦，它们真的很难阅读，至少在你学会语法之前是这样。尽管正则表达式不是面向对象的，但 Python 正则表达式库提供了一些类和对象，可以用来构建和运行正则表达式。

正则表达式用于解决一个常见问题：给定一个字符串，确定该字符串是否与给定的模式匹配，并且可选地收集包含相关信息的子字符串。它们可以用来回答类似的问题：

+   这个字符串是一个有效的 URL 吗？

+   日志文件中所有警告消息的日期和时间是什么？

+   `/etc/passwd`中的哪些用户属于给定的组？

+   访客输入的 URL 请求了哪个用户名和文档？

有许多类似的情况，正则表达式是正确的答案。许多程序员犯了一个错误，实现了复杂而脆弱的字符串解析库，因为他们不知道或不愿意学习正则表达式。在本节中，我们将获得足够的正则表达式知识，以避免犯这样的错误！

## 匹配模式

正则表达式是一种复杂的迷你语言。它们依赖于特殊字符来匹配未知的字符串，但让我们从字面字符开始，比如字母、数字和空格字符，它们总是匹配它们自己。让我们看一个基本的例子：

```py
import re

search_string = "hello world"
pattern = "hello world"

match = re.match(pattern, search_string)

if match:
    print("regex matches")
```

Python 标准库模块用于正则表达式的称为`re`。我们导入它并设置一个搜索字符串和要搜索的模式；在这种情况下，它们是相同的字符串。由于搜索字符串与给定模式匹配，条件通过并且`print`语句执行。

请记住，`match`函数将模式与字符串的开头匹配。因此，如果模式是`"ello world"`，将找不到匹配。令人困惑的是，解析器一旦找到匹配就停止搜索，因此模式`"hello wo"`可以成功匹配。让我们构建一个小的示例程序来演示这些差异，并帮助我们学习其他正则表达式语法：

```py
import sys
import re

pattern = sys.argv[1]
search_string = sys.argv[2]
match = re.match(pattern, search_string)

if match:
    template = "'{}' matches pattern '{}'"
else:
    template = "'{}' does not match pattern '{}'"

print(template.format(search_string, pattern))
```

这只是一个通用版本的早期示例，它从命令行接受模式和搜索字符串。我们可以看到模式的开头必须匹配，但是一旦在以下命令行交互中找到匹配，就会返回一个值：

```py
$ python regex_generic.py "hello worl" "hello world"
'hello world' matches pattern 'hello worl'
$ python regex_generic.py "ello world" "hello world"
'hello world' does not match pattern 'ello world'

```

我们将在接下来的几个部分中使用这个脚本。虽然脚本总是通过命令行`python regex_generic.py "<pattern>" "<string>"`调用，但我们只会在以下示例中看到输出，以节省空间。

如果您需要控制项目是否发生在行的开头或结尾（或者字符串中没有换行符，发生在字符串的开头和结尾），可以使用`^`和`$`字符分别表示字符串的开头和结尾。如果要匹配整个字符串的模式，最好包括这两个：

```py
'hello world' matches pattern '^hello world$'
'hello worl' does not match pattern '^hello world$'

```

### 匹配一组字符

让我们从匹配任意字符开始。句号字符在正则表达式模式中使用时，可以匹配任何单个字符。在字符串中使用句号意味着您不在乎字符是什么，只是有一个字符在那里。例如：

```py
'hello world' matches pattern 'hel.o world'
'helpo world' matches pattern 'hel.o world'
'hel o world' matches pattern 'hel.o world'
'helo world' does not match pattern 'hel.o world'

```

请注意，最后一个示例不匹配，因为在模式中句号的位置上没有字符。

这样做很好，但是如果我们只想匹配几个特定的字符怎么办？我们可以将一组字符放在方括号中，以匹配其中任何一个字符。因此，如果我们在正则表达式模式中遇到字符串`[abc]`，我们知道这五个（包括两个方括号）字符只会匹配字符串中的一个字符，并且进一步地，这一个字符将是`a`、`b`或`c`中的一个。看几个例子：

```py
'hello world' matches pattern 'hel[lp]o world'
'helpo world' matches pattern 'hel[lp]o world'
'helPo world' does not match pattern 'hel[lp]o world'

```

这些方括号集应该被称为字符集，但更常见的是被称为**字符类**。通常，我们希望在这些集合中包含大量的字符，并且将它们全部打出来可能会很单调和容易出错。幸运的是，正则表达式设计者考虑到了这一点，并给了我们一个快捷方式。在字符集中，短横线字符将创建一个范围。如果您想匹配"所有小写字母"、"所有字母"或"所有数字"，可以使用如下方法：

```py
'hello   world' does not match pattern 'hello [a-z] world'
'hello b world' matches pattern 'hello [a-z] world'
'hello B world' matches pattern 'hello [a-zA-Z] world'
'hello 2 world' matches pattern 'hello [a-zA-Z0-9] world'

```

还有其他匹配或排除单个字符的方法，但如果您想找出它们是什么，您需要通过网络搜索找到更全面的教程！

### 转义字符

如果在模式中放置句号字符可以匹配任意字符，那么如何在字符串中匹配一个句号呢？一种方法是将句号放在方括号中以创建一个字符类，但更通用的方法是使用反斜杠进行转义。下面是一个正则表达式，用于匹配 0.00 到 0.99 之间的两位小数：

```py
'0.05' matches pattern '0\.[0-9][0-9]'
'005' does not match pattern '0\.[0-9][0-9]'
'0,05' does not match pattern '0\.[0-9][0-9]'

```

对于这个模式，两个字符`\.`匹配单个`.`字符。如果句号字符缺失或是另一个字符，它就不匹配。

这个反斜杠转义序列用于正则表达式中的各种特殊字符。您可以使用`\[`来插入一个方括号而不开始一个字符类，`\(`来插入一个括号，我们稍后会看到它也是一个特殊字符。

更有趣的是，我们还可以使用转义符号后跟一个字符来表示特殊字符，例如换行符（`\n`）和制表符（`\t`）。此外，一些字符类可以更简洁地用转义字符串表示；`\s`表示空白字符，`\w`表示字母、数字和下划线，`\d`表示数字：

```py
'(abc]' matches pattern '\(abc\]'
' 1a' matches pattern '\s\d\w'
'\t5n' does not match pattern '\s\d\w'
'5n' matches pattern '\s\d\w'

```

### 匹配多个字符

有了这些信息，我们可以匹配大多数已知长度的字符串，但大多数情况下，我们不知道模式内要匹配多少个字符。正则表达式也可以处理这个问题。我们可以通过附加几个难以记住的标点符号来修改模式以匹配多个字符。

星号（`*`）字符表示前面的模式可以匹配零次或多次。这可能听起来很愚蠢，但它是最有用的重复字符之一。在我们探索原因之前，考虑一些愚蠢的例子，以确保我们理解它的作用：

```py
'hello' matches pattern 'hel*o'
'heo' matches pattern 'hel*o'
'helllllo' matches pattern 'hel*o'

```

因此，模式中的`*`字符表示前面的模式（`l`字符）是可选的，如果存在，可以重复多次以匹配模式。其余的字符（`h`，`e`和`o`）必须出现一次。

匹配单个字母多次可能是非常罕见的，但如果我们将星号与匹配多个字符的模式结合起来，就会变得更有趣。例如，`.*`将匹配任何字符串，而`[a-z]*`将匹配任何小写单词的集合，包括空字符串。

例如：

```py
'A string.' matches pattern '[A-Z][a-z]* [a-z]*\.'
'No .' matches pattern '[A-Z][a-z]* [a-z]*\.'
'' matches pattern '[a-z]*.*'

```

模式中的加号（`+`）与星号类似；它表示前面的模式可以重复一次或多次，但与星号不同的是，它不是可选的。问号（`?`）确保模式出现零次或一次，但不会更多。让我们通过玩数字来探索一些例子（记住`\d`与`[0-9]`匹配相同的字符类）：

```py
'0.4' matches pattern '\d+\.\d+'
'1.002' matches pattern '\d+\.\d+'
'1.' does not match pattern '\d+\.\d+'
'1%' matches pattern '\d?\d%'
'99%' matches pattern '\d?\d%'
'999%' does not match pattern '\d?\d%'

```

### 将模式分组在一起

到目前为止，我们已经看到了如何可以多次重复一个模式，但我们在可以重复的模式上受到了限制。如果我们想重复单个字符，那么我们已经覆盖了，但如果我们想要重复一系列字符呢？将任何一组模式括在括号中允许它们在应用重复操作时被视为单个模式。比较这些模式：

```py
'abccc' matches pattern 'abc{3}'
'abccc' does not match pattern '(abc){3}'
'abcabcabc' matches pattern '(abc){3}'

```

与复杂模式结合使用，这种分组功能极大地扩展了我们的模式匹配能力。这是一个匹配简单英语句子的正则表达式：

```py
'Eat.' matches pattern '[A-Z][a-z]*( [a-z]+)*\.$'
'Eat more good food.' matches pattern '[A-Z][a-z]*( [a-z]+)*\.$'
'A good meal.' matches pattern '[A-Z][a-z]*( [a-z]+)*\.$'

```

第一个单词以大写字母开头，后面跟着零个或多个小写字母。然后，我们进入一个匹配一个空格后跟一个或多个小写字母的单词的括号。整个括号部分重复零次或多次，模式以句号结束。句号后不能有任何其他字符，这由`$`匹配字符串结束来表示。

我们已经看到了许多最基本的模式，但正则表达式语言支持更多。我在使用正则表达式的头几年里，每次需要做一些事情时都会查找语法。值得将 Python 的`re`模块文档加入书签，并经常复习。几乎没有什么是正则表达式无法匹配的，当解析字符串时，它们应该是你首选的工具。

## 从正则表达式获取信息

现在让我们专注于 Python 方面。正则表达式语法与面向对象编程完全不同。然而，Python 的`re`模块提供了一个面向对象的接口来进入正则表达式引擎。

我们一直在检查`re.match`函数是否返回有效对象。如果模式不匹配，该函数将返回`None`。但是，如果匹配，它将返回一个有用的对象，我们可以内省有关模式的信息。

到目前为止，我们的正则表达式已经回答了诸如“这个字符串是否与此模式匹配？”的问题。匹配模式是有用的，但在许多情况下，一个更有趣的问题是，“如果这个字符串匹配这个模式，相关子字符串的值是多少？”如果您使用组来标识您想要稍后引用的模式的部分，您可以从匹配返回值中获取它们，如下一个示例所示：

```py
pattern = "^[a-zA-Z.]+@([a-z.]*\.[a-z]+)$"
search_string = "some.user@example.com"
match = re.match(pattern, search_string)

if match:
 **domain = match.groups()[0]
    print(domain)
```

描述有效电子邮件地址的规范非常复杂，准确匹配所有可能性的正则表达式非常长。因此，我们作弊并制作了一个简单的正则表达式，用于匹配一些常见的电子邮件地址；重点是我们想要访问域名（在`@`符号之后），以便我们可以连接到该地址。通过将模式的该部分包装在括号中，并在匹配返回的对象上调用`groups()`方法，可以轻松实现这一点。

`groups`方法返回模式内匹配的所有组的元组，您可以对其进行索引以访问特定值。组从左到右排序。但是，请记住，组可以是嵌套的，这意味着您可以在另一个组内部有一个或多个组。在这种情况下，组按其最左边的括号顺序返回，因此外部组将在其内部匹配组之前返回。

除了匹配函数之外，`re`模块还提供了另外两个有用的函数，`search`和`findall`。`search`函数找到匹配模式的第一个实例，放宽了模式从字符串的第一个字母开始的限制。请注意，您可以通过使用匹配并在模式的前面放置`^.*`字符来获得类似的效果，以匹配字符串的开头和您要查找的模式之间的任何字符。

`findall`函数的行为类似于 search，只是它找到匹配模式的所有非重叠实例，而不仅仅是第一个。基本上，它找到第一个匹配，然后将搜索重置为该匹配字符串的末尾，并找到下一个匹配。

与其返回预期的匹配对象列表，它返回一个匹配字符串的列表。或元组。有时是字符串，有时是元组。这根本不是一个很好的 API！与所有糟糕的 API 一样，您将不得不记住差异并不依赖直觉。返回值的类型取决于正则表达式内括号组的数量：

+   如果模式中没有组，则`re.findall`将返回一个字符串列表，其中每个值都是与模式匹配的源字符串的完整子字符串

+   如果模式中恰好有一个组，则`re.findall`将返回一个字符串列表，其中每个值都是该组的内容

+   如果模式中有多个组，则`re.findall`将返回一个元组列表，其中每个元组包含匹配组的值，按顺序排列

### 注意

当您在设计自己的 Python 库中的函数调用时，请尝试使函数始终返回一致的数据结构。通常设计函数可以接受任意输入并处理它们是很好的，但返回值不应该从单个值切换到列表，或者从值列表切换到元组列表，具体取决于输入。让`re.findall`成为一个教训！

以下交互式会话中的示例将有望澄清差异：

```py
>>> import re
>>> re.findall('a.', 'abacadefagah')
['ab', 'ac', 'ad', 'ag', 'ah']
>>> re.findall('a(.)', 'abacadefagah')
['b', 'c', 'd', 'g', 'h']
>>> re.findall('(a)(.)', 'abacadefagah')
[('a', 'b'), ('a', 'c'), ('a', 'd'), ('a', 'g'), ('a', 'h')]
>>> re.findall('((a)(.))', 'abacadefagah')
[('ab', 'a', 'b'), ('ac', 'a', 'c'), ('ad', 'a', 'd'), ('ag', 'a', 'g'), ('ah', 'a', 'h')]

```

### 使重复的正则表达式高效

每当调用正则表达式方法之一时，引擎都必须将模式字符串转换为内部结构，以便快速搜索字符串。这种转换需要相当长的时间。如果一个正则表达式模式将被多次重复使用（例如，在`for`或`while`循环内），最好只进行一次这种转换。

这是使用`re.compile`方法实现的。它返回一个已经编译过的正则表达式的面向对象版本，并且具有我们已经探索过的方法（`match`、`search`、`findall`）等。我们将在案例研究中看到这方面的例子。

这绝对是一个简短的正则表达式介绍。到目前为止，我们对基础知识有了很好的了解，并且会意识到何时需要进行进一步的研究。如果我们遇到字符串模式匹配问题，正则表达式几乎肯定能够解决。但是，我们可能需要在更全面地涵盖该主题的情况下查找新的语法。但现在我们知道该找什么了！让我们继续进行一个完全不同的主题：为存储序列化数据。

# 序列化对象

如今，我们认为能够将数据写入文件并在任意以后的日期检索出来是理所当然的。尽管这很方便（想象一下，如果我们不能存储任何东西，计算机的状态会是什么样子！），但我们经常发现自己需要将我们在内存中存储的数据转换为某种笨拙的文本或二进制格式，以便进行存储、在网络上传输或在远程服务器上进行远程调用。

Python 的`pickle`模块是一种以面向对象的方式直接存储对象的特殊存储格式。它基本上将一个对象（以及它作为属性持有的所有对象）转换为一系列字节，可以根据需要进行存储或传输。

对于基本工作，`pickle`模块有一个非常简单的接口。它由四个基本函数组成，用于存储和加载数据；两个用于操作类似文件的对象，两个用于操作`bytes`对象（后者只是文件类似接口的快捷方式，因此我们不必自己创建`BytesIO`文件类似对象）。

`dump`方法接受一个要写入的对象和一个类似文件的对象，用于将序列化的字节写入其中。这个对象必须有一个`write`方法（否则它就不会像文件一样），并且该方法必须知道如何处理`bytes`参数（因此，对于文本输出打开的文件将无法工作）。

`load`方法恰恰相反；它从类似文件的对象中读取序列化的对象。这个对象必须具有适当的类似文件的`read`和`readline`参数，每个参数当然都必须返回`bytes`。`pickle`模块将从这些字节中加载对象，并且`load`方法将返回完全重建的对象。以下是一个存储然后加载列表对象中的一些数据的示例：

```py
import pickle

some_data = ["a list", "containing", 5,
        "values including another list",
        ["inner", "list"]]

with open("pickled_list", 'wb') as file:
 **pickle.dump(some_data, file)

with open("pickled_list", 'rb') as file:
 **loaded_data = pickle.load(file)

print(loaded_data)
assert loaded_data == some_data
```

这段代码按照预期工作：对象被存储在文件中，然后从同一个文件中加载。在每种情况下，我们使用`with`语句打开文件，以便它会自动关闭。文件首先被打开以进行写入，然后第二次以进行读取，具体取决于我们是存储还是加载数据。

最后的`assert`语句会在新加载的对象不等于原始对象时引发错误。相等并不意味着它们是相同的对象。事实上，如果我们打印两个对象的`id()`，我们会发现它们是不同的。但是，因为它们都是内容相等的列表，所以这两个列表也被认为是相等的。

`dumps`和`loads`函数的行为与它们的类似文件的对应函数类似，只是它们返回或接受`bytes`而不是类似文件的对象。`dumps`函数只需要一个参数，即要存储的对象，并返回一个序列化的`bytes`对象。`loads`函数需要一个`bytes`对象，并返回还原的对象。方法名称中的`'s'`字符代表字符串；这是 Python 古老版本的一个遗留名称，那时使用的是`str`对象而不是`bytes`。

两个`dump`方法都接受一个可选的`protocol`参数。如果我们正在保存和加载只会在 Python 3 程序中使用的拾取对象，我们不需要提供此参数。不幸的是，如果我们正在存储可能会被旧版本的 Python 加载的对象，我们必须使用一个更旧且效率低下的协议。这通常不是问题。通常，加载拾取对象的唯一程序将是存储它的程序。拾取是一种不安全的格式，因此我们不希望将其不安全地发送到未知的解释器。

提供的参数是一个整数版本号。默认版本是 3，代表 Python 3 拾取使用的当前高效存储系统。数字 2 是旧版本，将存储一个可以在所有解释器上加载回 Python 2.3 的对象。由于 2.6 是仍然广泛使用的 Python 中最古老的版本，因此通常版本 2 的拾取就足够了。版本 0 和 1 在旧解释器上受支持；0 是 ASCII 格式，而 1 是二进制格式。还有一个优化的版本 4，可能有一天会成为默认版本。

因此，作为一个经验法则，如果您知道您要拾取的对象只会被 Python 3 程序加载（例如，只有您的程序会加载它们），请使用默认的拾取协议。如果它们可能会被未知的解释器加载，传递一个值为 2 的协议值，除非您真的相信它们可能需要被古老版本的 Python 加载。

如果我们向`dump`或`dumps`传递一个协议，我们应该使用关键字参数来指定它：`pickle.dumps(my_object, protocol=2)`。这并不是严格必要的，因为该方法只接受两个参数，但是写出完整的关键字参数会提醒我们代码的读者数字的目的。在方法调用中有一个随机整数会很难阅读。两个是什么？存储对象的两个副本，也许？记住，代码应该始终可读。在 Python 中，较少的代码通常比较长的代码更易读，但并非总是如此。要明确。

可以在单个打开的文件上多次调用`dump`或`load`。每次调用`dump`都会存储一个对象（以及它所组成或包含的任何对象），而调用`load`将加载并返回一个对象。因此，对于单个文件，存储对象时的每个单独的`dump`调用应该在以后的某个日期还原时有一个关联的`load`调用。

## 自定义拾取

对于大多数常见的 Python 对象，拾取“只是起作用”。基本的原始类型，如整数、浮点数和字符串可以被拾取，任何容器对象，如列表或字典，只要这些容器的内容也是可拾取的。此外，任何对象都可以被拾取，只要它的所有属性也是可拾取的。

那么，什么使属性无法被拾取？通常，这与时间敏感的属性有关，这些属性在将来加载时是没有意义的。例如，如果我们在对象的属性上存储了一个打开的网络套接字、打开的文件、运行中的线程或数据库连接，那么将这些对象拾取是没有意义的；当我们尝试以后重新加载它们时，很多操作系统状态将会消失。我们不能假装一个线程或套接字连接存在并使其出现！不，我们需要以某种方式自定义如何存储和还原这样的瞬态数据。

这是一个每小时加载网页内容以确保其保持最新的类。它使用`threading.Timer`类来安排下一次更新：

```py
from threading import Timer
import datetime
from urllib.request import urlopen

class UpdatedURL:
    def __init__(self, url):
        self.url = url
        self.contents = ''
        self.last_updated = None
        self.update()

    def update(self):
        self.contents = urlopen(self.url).read()
        self.last_updated = datetime.datetime.now()
        self.schedule()

    def schedule(self):
        self.timer = Timer(3600, self.update)
        self.timer.setDaemon(True)
        self.timer.start()
```

`url`、`contents`和`last_updated`都是可 pickle 的，但如果我们尝试 pickle 这个类的一个实例，事情在`self.timer`实例上会有点混乱：

```py
>>> u = UpdatedURL("http://news.yahoo.com/")
>>> import pickle
>>> serialized = pickle.dumps(u)
Traceback (most recent call last):
 **File "<pyshell#3>", line 1, in <module>
 **serialized = pickle.dumps(u)
_pickle.PicklingError: Can't pickle <class '_thread.lock'>: attribute lookup lock on _thread failed

```

这不是一个非常有用的错误，但看起来我们正在尝试 pickle 我们不应该 pickle 的东西。那将是`Timer`实例；我们在 schedule 方法中存储了对`self.timer`的引用，而该属性无法被序列化。

当`pickle`尝试序列化一个对象时，它只是尝试存储对象的`__dict__`属性；`__dict__`是一个字典，将对象上的所有属性名称映射到它们的值。幸运的是，在检查`__dict__`之前，`pickle`会检查是否存在`__getstate__`方法。如果存在，它将存储该方法的返回值，而不是`__dict__`。

让我们为我们的`UpdatedURL`类添加一个`__getstate__`方法，它简单地返回`__dict__`的副本，而不包括计时器：

```py
    def __getstate__(self):
        new_state = self.__dict__.copy()
        if 'timer' in new_state:
            del new_state['timer']
        return new_state
```

如果我们现在 pickle 对象，它将不再失败。我们甚至可以使用`loads`成功地恢复该对象。然而，恢复的对象没有计时器属性，因此它将无法像设计时那样刷新内容。我们需要在对象被反 pickle 时以某种方式创建一个新的计时器（以替换丢失的计时器）。

正如我们所期望的那样，有一个互补的`__setstate__`方法，可以实现以自定义反 pickle。这个方法接受一个参数，即`__getstate__`返回的对象。如果我们实现了这两个方法，`__getstate__`不需要返回一个字典，因为`__setstate__`将知道如何处理`__getstate__`选择返回的任何对象。在我们的情况下，我们只想恢复`__dict__`，然后创建一个新的计时器：

```py
    def __setstate__(self, data):
        self.__dict__ = data
        self.schedule()
```

`pickle`模块非常灵活，并提供其他工具来进一步自定义 pickling 过程，如果您需要的话。然而，这些超出了本书的范围。我们已经涵盖的工具对于许多基本的 pickling 任务已经足够了。通常被 pickle 的对象是相对简单的数据对象；例如，我们不太可能 pickle 整个运行中的程序或复杂的设计模式。

## 序列化网络对象

从未知或不受信任的来源加载 pickled 对象并不是一个好主意。可以向 pickled 文件中注入任意代码，以恶意攻击计算机。pickles 的另一个缺点是它们只能被其他 Python 程序加载，并且不能轻松地与其他语言编写的服务共享。

多年来已经使用了许多用于此目的的格式。XML（可扩展标记语言）曾经非常流行，特别是在 Java 开发人员中。YAML（另一种标记语言）是另一种格式，偶尔也会看到它被引用。表格数据经常以 CSV（逗号分隔值）格式交换。其中许多已经逐渐被遗忘，而且您将随着时间的推移遇到更多。Python 对所有这些都有坚实的标准或第三方库。

在对不受信任的数据使用这样的库之前，请确保调查每个库的安全性问题。例如，XML 和 YAML 都有模糊的特性，如果恶意使用，可以允许在主机机器上执行任意命令。这些特性可能不会默认关闭。做好你的研究。

**JavaScript 对象表示法**（**JSON**）是一种用于交换基本数据的人类可读格式。JSON 是一种标准格式，可以被各种异构客户端系统解释。因此，JSON 非常适用于在完全解耦的系统之间传输数据。此外，JSON 没有任何对可执行代码的支持，只能序列化数据；因此，很难向其中注入恶意语句。

因为 JSON 可以被 JavaScript 引擎轻松解释，所以经常用于从 Web 服务器传输数据到支持 JavaScript 的 Web 浏览器。如果提供数据的 Web 应用程序是用 Python 编写的，它需要一种将内部数据转换为 JSON 格式的方法。

有一个模块可以做到这一点，它的名称可预测地叫做`json`。该模块提供了与`pickle`模块类似的接口，具有`dump`、`load`、`dumps`和`loads`函数。对这些函数的默认调用几乎与`pickle`中的调用相同，因此我们不再重复细节。有一些区别；显然，这些调用的输出是有效的 JSON 表示，而不是一个被 pickled 的对象。此外，`json`函数操作`str`对象，而不是`bytes`。因此，在转储到文件或从文件加载时，我们需要创建文本文件而不是二进制文件。

JSON 序列化器不像`pickle`模块那样健壮；它只能序列化诸如整数、浮点数和字符串之类的基本类型，以及诸如字典和列表之类的简单容器。每种类型都有直接映射到 JSON 表示，但 JSON 无法表示类、方法或函数。无法以这种格式传输完整的对象。因为我们将对象转储为 JSON 格式的接收者通常不是 Python 对象，所以它无法以与 Python 相同的方式理解类或方法。尽管其名称中有“对象”一词，但 JSON 是一种**数据**表示法；对象，你会记得，由数据和行为组成。

如果我们有要序列化仅包含数据的对象，我们总是可以序列化对象的`__dict__`属性。或者我们可以通过提供自定义代码来从某些类型的对象创建或解析 JSON 可序列化字典来半自动化这个任务。

在`json`模块中，存储和加载函数都接受可选参数来自定义行为。`dump`和`dumps`方法接受一个名为`cls`（缩写为类，这是一个保留关键字）的关键字参数。如果传递了这个参数，它应该是`JSONEncoder`类的子类，并且应该重写`default`方法。此方法接受任意对象并将其转换为`json`可以解析的字典。如果它不知道如何处理对象，我们应该调用`super()`方法，以便它可以以正常方式处理序列化基本类型。

`load`和`loads`方法也接受`cls`参数，该参数可以是`JSONDecoder`的子类。但是，通常只需使用`object_hook`关键字参数将函数传递给这些方法。此函数接受一个字典并返回一个对象；如果它不知道如何处理输入字典，它可以原样返回。

让我们来看一个例子。假设我们有以下简单的联系人类，我们想要序列化：

```py
class Contact:
    def __init__(self, first, last):
        self.first = first
        self.last = last

    @property
    def full_name(self):
        return("{} {}".format(self.first, self.last))
```

我们可以只序列化`__dict__`属性：

```py
>>> c = Contact("John", "Smith")
>>> json.dumps(c.__dict__)
'{"last": "Smith", "first": "John"}'

```

但是，以这种方式访问特殊（双下划线）属性有点粗糙。另外，如果接收代码（也许是网页上的一些 JavaScript）希望提供`full_name`属性呢？当然，我们可以手工构建字典，但让我们创建一个自定义编码器：

```py
import json
class ContactEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Contact):
            return {'is_contact': True,
                    'first': obj.first,
                    'last': obj.last,
                    'full': obj.full_name}
        return super().default(obj)
```

`default`方法基本上是检查我们试图序列化的对象是什么类型；如果是联系人，我们手动将其转换为字典；否则，我们让父类处理序列化（假设它是一个基本类型，`json`知道如何处理）。请注意，我们传递了一个额外的属性来标识这个对象是一个联系人，因为在加载时没有办法知道。这只是一个约定；对于更通用的序列化机制，可能更合理的是在字典中存储一个字符串类型，或者甚至包括包和模块在内的完整类名。请记住，字典的格式取决于接收端的代码；必须就数据的规范方式达成一致。

我们可以使用这个类来通过将类（而不是实例化对象）传递给`dump`或`dumps`函数来编码一个联系人：

```py
>>> c = Contact("John", "Smith")
>>> json.dumps(c, cls=ContactEncoder)
'{"is_contact": true, "last": "Smith", "full": "John Smith",
"first": "John"}'

```

对于解码，我们可以编写一个接受字典并检查`is_contact`变量存在性的函数，以决定是否将其转换为联系人：

```py
def decode_contact(dic):
        if dic.get('is_contact'):
            return Contact(dic['first'], dic['last'])
        else:
            return dic
```

我们可以使用`object_hook`关键字参数将这个函数传递给`load`或`loads`函数：

```py
>>> data = ('{"is_contact": true, "last": "smith",'
 **'"full": "john smith", "first": "john"}')

>>> c = json.loads(data, object_hook=decode_contact)
>>> c
<__main__.Contact object at 0xa02918c>
>>> c.full_name
'john smith'

```

# 案例研究

让我们在 Python 中构建一个基本的基于正则表达式的模板引擎。这个引擎将解析一个文本文件（比如一个 HTML 页面），并用从这些指令输入的文本替换某些指令。这是我们希望用正则表达式做的最复杂的任务；事实上，一个完整的版本可能会利用适当的语言解析机制。

考虑以下输入文件：

```py
/** include header.html **/
<h1>This is the title of the front page</h1>
/** include menu.html **/
<p>My name is /** variable name **/.
This is the content of my front page. It goes below the menu.</p>
<table>
<tr><th>Favourite Books</th></tr>
/** loopover book_list **/
<tr><td>/** loopvar **/</td></tr>

/** endloop **/
</table>
/** include footer.html **/
Copyright &copy; Today
```

这个文件包含形式为`/** <directive> <data> **/`的“标签”，其中数据是可选的单词，指令是：

+   `include`：在这里复制另一个文件的内容

+   `variable`：在这里插入变量的内容

+   `loopover`：重复循环的内容，对应一个列表变量

+   `endloop`：标志循环文本的结束

+   `loopvar`：插入循环变量中的单个值

这个模板将根据传递给它的变量呈现不同的页面。这些变量将从所谓的上下文文件中传递进来。这将被编码为一个表示相关变量的键的`json`对象。我的上下文文件可能看起来像这样，但你可以自己推导出你自己的：

```py
{
    "name": "Dusty",
    "book_list": [
        "Thief Of Time",
        "The Thief",
        "Snow Crash",
        "Lathe Of Heaven"
    ]
}
```

在我们进入实际的字符串处理之前，让我们为处理文件和从命令行获取数据编写一些面向对象的样板代码：

```py
import re
import sys
import json
from pathlib import Path

DIRECTIVE_RE = re.compile(
 **r'/\*\*\s*(include|variable|loopover|endloop|loopvar)'
 **r'\s*([^ *]*)\s*\*\*/')

class TemplateEngine:
    def __init__(self, infilename, outfilename, contextfilename):
        self.template = open(infilename).read()
        self.working_dir = Path(infilename).absolute().parent
 **self.pos = 0
        self.outfile = open(outfilename, 'w')
        with open(contextfilename) as contextfile:
            self.context = json.load(contextfile)

    def process(self):
        print("PROCESSING...")

if __name__ == '__main__':
    infilename, outfilename, contextfilename = sys.argv[1:]
    engine = TemplateEngine(infilename, outfilename, contextfilename)
    engine.process()
```

这都是相当基础的，我们创建一个类，并用从命令行传入的一些变量对其进行初始化。

注意我们如何通过跨两行来使正则表达式变得更可读？我们使用原始字符串（r 前缀），这样我们就不必对所有反斜杠进行双重转义。这在正则表达式中很常见，但仍然很混乱。（正则表达式总是如此，但通常是值得的。）

`pos`表示我们正在处理的内容中的当前字符；我们马上会看到更多。

现在“剩下的就是”实现那个 process 方法。有几种方法可以做到这一点。让我们以一种相当明确的方式来做。

process 方法必须找到与正则表达式匹配的每个指令，并对其进行适当的处理。但是，它还必须负责将每个指令之前、之后和之间的普通文本输出到输出文件中，不经修改。

正则表达式的编译版本的一个很好的特性是，我们可以通过传递`pos`关键字参数告诉`search`方法从特定位置开始搜索。如果我们临时定义对指令进行适当处理为“忽略指令并从输出文件中删除它”，我们的处理循环看起来非常简单：

```py
def process(self):
    match = DIRECTIVE_RE.search(self.template, pos=self.pos)
    while match:
        self.outfile.write(self.template[self.pos:match.start()])
 **self.pos = match.end()
        match = DIRECTIVE_RE.search(self.template, pos=self.pos)
    self.outfile.write(self.template[self.pos:])
```

这个函数在英语中找到文本中与正则表达式匹配的第一个字符串，输出从当前位置到该匹配的开始的所有内容，然后将位置前进到上述匹配的结束。一旦匹配完毕，它就会输出自上次位置以来的所有内容。

当然，在模板引擎中忽略指令是相当无用的，所以让我们设置用不同的方法委托到类上的不同方法的代码来替换那个位置前进的行：

```py
def process(self):
    match = DIRECTIVE_RE.search(self.template, pos=self.pos)
    while match:
        self.outfile.write(self.template[self.pos:match.start()])
 **directive, argument = match.groups()
 **method_name = 'process_{}'.format(directive)
 **getattr(self, method_name)(match, argument)
        match = DIRECTIVE_RE.search(self.template, pos=self.pos)
    self.outfile.write(self.template[self.pos:])
```

所以我们从正则表达式中获取指令和单个参数。指令变成一个方法名，我们动态地在`self`对象上查找该方法名（在模板编写者提供无效指令的情况下，这里可能需要一些错误处理更好）。我们将匹配对象和参数传递给该方法，并假设该方法将适当地处理一切，包括移动`pos`指针。

现在我们的面向对象的架构已经到了这一步，实际上实现委托的方法是非常简单的。`include`和`variable`指令是完全直接的。

```py
def process_include(self, match, argument):
    with (self.working_dir / argument).open() as includefile:
        self.outfile.write(includefile.read())
 **self.pos = match.end()

def process_variable(self, match, argument):
    self.outfile.write(self.context.get(argument, ''))
 **self.pos = match.end()

```

第一个方法简单地查找包含的文件并插入文件内容，而第二个方法在上下文字典中查找变量名称（这些变量是在`__init__`方法中从`json`中加载的），如果不存在则默认为空字符串。

处理循环的三种方法要复杂一些，因为它们必须在它们之间共享状态。为了简单起见（我相信你迫不及待地想看到这一漫长章节的结束，我们快到了！），我们将把这些方法作为类本身的实例变量来处理。作为练习，你可能会考虑更好的架构方式，特别是在阅读完接下来的三章之后。

```py
    def process_loopover(self, match, argument):
        self.loop_index = 0
 **self.loop_list = self.context.get(argument, [])
        self.pos = self.loop_pos = match.end()

    def process_loopvar(self, match, argument):
 **self.outfile.write(self.loop_list[self.loop_index])
        self.pos = match.end()

    def process_endloop(self, match, argument):
 **self.loop_index += 1
        if self.loop_index >= len(self.loop_list):
            self.pos = match.end()
            del self.loop_index
            del self.loop_list
            del self.loop_pos
        else:
 **self.pos = self.loop_pos

```

当我们遇到`loopover`指令时，我们不必输出任何内容，但我们必须在三个变量上设置初始状态。假定`loop_list`变量是从上下文字典中提取的列表。`loop_index`变量指示在循环的这一次迭代中应该输出列表中的哪个位置，而`loop_pos`被存储，这样当我们到达循环的结尾时就知道要跳回到哪里。

`loopvar`指令输出`loop_list`变量中当前位置的值，并跳到指令的结尾。请注意，它不会增加循环索引，因为`loopvar`指令可以在循环内多次调用。

`endloop`指令更复杂。它确定`loop_list`中是否还有更多的元素；如果有，它就跳回到循环的开始，增加索引。否则，它重置了用于处理循环的所有变量，并跳到指令的结尾，这样引擎就可以继续处理下一个匹配。

请注意，这种特定的循环机制非常脆弱；如果模板设计者尝试嵌套循环或忘记调用`endloop`，那对他们来说会很糟糕。我们需要进行更多的错误检查，可能还要存储更多的循环状态，以使其成为一个生产平台。但我承诺这一章快要结束了，所以让我们在查看我们的示例模板如何与其上下文一起呈现后，直接转到练习：

```py
<html>
    <body>

<h1>This is the title of the front page</h1>
<a href="link1.html">First Link</a>
<a href="link2.html">Second Link</a>

<p>My name is Dusty.
This is the content of my front page. It goes below the menu.</p>
<table>
<tr><th>Favourite Books</th></tr>

<tr><td>Thief Of Time</td></tr>

<tr><td>The Thief</td></tr>

<tr><td>Snow Crash</td></tr>

<tr><td>Lathe Of Heaven</td></tr>

</table>
    </body>
</html>

Copyright &copy; Today
```

由于我们规划模板的方式，会产生一些奇怪的换行效果，但它的工作效果如预期。

# 练习

在本章中，我们涵盖了各种主题，从字符串到正则表达式，再到对象序列化，然后再回来。现在是时候考虑这些想法如何应用到你自己的代码中了。

Python 字符串非常灵活，而 Python 是一个非常强大的基于字符串的操作工具。如果您在日常工作中没有进行大量的字符串处理，请尝试设计一个专门用于操作字符串的工具。尝试想出一些创新的东西，但如果遇到困难，可以考虑编写一个网络日志分析器（每小时有多少请求？有多少人访问了五个以上的页面？）或一个模板工具，用其他文件的内容替换某些变量名。

花费大量时间玩弄字符串格式化运算符，直到您记住了语法。编写一堆模板字符串和对象传递给格式化函数，并查看您得到了什么样的输出。尝试一些奇特的格式化运算符，比如百分比或十六进制表示法。尝试填充和对齐运算符，并查看它们在整数、字符串和浮点数上的不同行为。考虑编写一个自己的类，其中有一个`__format__`方法；我们没有详细讨论这一点，但探索一下您可以自定义格式化的程度。

确保您理解`bytes`和`str`对象之间的区别。在旧版本的 Python 中，这个区别非常复杂（没有`bytes`，`str`同时充当`bytes`和`str`，除非我们需要非 ASCII 字符，此时有一个单独的`unicode`对象，类似于 Python 3 的`str`类。这甚至比听起来的更令人困惑！）。现在更清晰了；`bytes`用于二进制数据，`str`用于字符数据。唯一棘手的部分是知道如何以及何时在两者之间转换。练习时，尝试将文本数据写入以`bytes`方式打开的文件（您将不得不自己对文本进行编码），然后从同一文件中读取。

尝试使用`bytearray`进行一些实验；看看它如何同时像一个字节对象和一个列表或容器对象。尝试向一个缓冲区写入数据，直到达到一定长度之前将其返回。您可以通过使用`time.sleep`调用来模拟将数据放入缓冲区的代码，以确保数据不会到达得太快。

在网上学习正则表达式。再多学习一些。特别是要了解有名分组、贪婪匹配与懒惰匹配以及正则表达式标志，这些是我们在本章中没有涵盖的三个特性。要有意识地决定何时不使用它们。许多人对正则表达式有非常强烈的意见，要么过度使用它们，要么根本不使用它们。试着说服自己只在适当的时候使用它们，并找出何时是适当的时候。

如果您曾经编写过一个适配器，用于从文件或数据库中加载少量数据并将其转换为对象，请考虑改用 pickle。Pickles 不适合存储大量数据，但对于加载配置或其他简单对象可能会有用。尝试多种编码方式：使用 pickle、文本文件或小型数据库。哪种方式对您来说最容易使用？

尝试对数据进行 pickling 实验，然后修改保存数据的类，并将 pickle 加载到新类中。什么有效？什么无效？有没有办法对一个类进行重大更改，比如重命名属性或将其拆分为两个新属性，但仍然可以从旧的 pickle 中获取数据？（提示：尝试在每个对象上放置一个私有的 pickle 版本号，并在更改类时更新它；然后可以在`__setstate__`中放置一个迁移路径。）

如果您从事任何网络开发工作，请尝试使用 JSON 序列化器进行一些实验。就个人而言，我更喜欢只序列化标准的 JSON 可序列化对象，而不是编写自定义编码器或`object_hooks`，但期望的效果实际上取决于前端（通常是 JavaScript）和后端代码之间的交互。

在模板引擎中创建一些新的指令，这些指令需要多个或任意数量的参数。您可能需要修改正则表达式或添加新的正则表达式。查看 Django 项目的在线文档，看看是否有任何其他模板标签您想要使用。尝试模仿它们的过滤器语法，而不是使用变量标签。当您学习了迭代和协程时，重新阅读本章，看看是否能找到一种更

# 总结

在本章中，我们涵盖了字符串操作、正则表达式和对象序列化。硬编码的字符串和程序变量可以使用强大的字符串格式化系统组合成可输出的字符串。区分二进制和文本数据很重要，`bytes`和`str`有特定的用途必须要理解。它们都是不可变的，但在操作字节时可以使用`bytearray`类型。

正则表达式是一个复杂的主题，但我们只是触及了表面。有许多种方法可以序列化 Python 数据；pickle 和 JSON 是最流行的两种方法之一。

在下一章中，我们将看一种设计模式，这种模式对于 Python 编程非常基础，以至于它已经被赋予了特殊的语法支持：迭代器模式。
