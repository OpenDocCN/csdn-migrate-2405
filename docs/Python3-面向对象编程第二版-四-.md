# Python3 面向对象编程第二版（四）

> 原文：[`zh.annas-archive.org/md5/B484D481722F7AFA9E5B1ED7225BED43`](https://zh.annas-archive.org/md5/B484D481722F7AFA9E5B1ED7225BED43)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第九章：迭代器模式

我们已经讨论了许多 Python 内置和习惯用法，乍一看似乎不是面向对象的，实际上在底层提供了对主要对象的访问。在本章中，我们将讨论`for`循环，看起来如此结构化，实际上是一组面向对象原则的轻量级包装。我们还将看到一系列扩展到这个语法的类型。我们将涵盖：

+   什么是设计模式

+   迭代器协议——最强大的设计模式之一

+   列表、集合和字典的理解

+   生成器和协程

# 简要介绍设计模式

当工程师和建筑师决定建造桥梁、塔楼或建筑物时，他们遵循某些原则以确保结构完整性。桥梁有各种可能的设计（例如悬索桥或悬臂桥），但如果工程师不使用标准设计之一，并且没有一个新的杰出设计，那么他/她设计的桥梁可能会倒塌。

设计模式试图将正确设计的结构的正式定义引入软件工程。有许多不同的设计模式来解决不同的通用问题。创建设计模式的人首先确定开发人员在各种情况下面临的常见问题。然后，他们建议可能被认为是该问题的理想解决方案，从面向对象设计的角度来看。

了解设计模式并选择在我们的软件中使用它并不保证我们正在创建一个“正确”的解决方案。1907 年，魁北克大桥（至今仍是世界上最长的悬臂桥）在建造完成之前倒塌，因为设计它的工程师严重低估了用于建造的钢材重量。同样，在软件开发中，我们可能错误地选择或应用设计模式，并创建在正常操作情况下或在超出其原始设计限制时“倒塌”的软件。

任何一个设计模式都提出了一组以特定方式相互作用的对象，以解决一个通用问题。程序员的工作是识别何时面临特定版本的问题，并在解决方案中调整通用设计。

在本章中，我们将介绍迭代器设计模式。这种模式是如此强大和普遍，以至于 Python 开发人员提供了多种语法来访问该模式的基础面向对象原则。我们将在接下来的两章中介绍其他设计模式。其中一些具有语言支持，一些没有，但没有一个像迭代器模式一样成为 Python 程序员日常生活的固有部分。

# 迭代器

在典型的设计模式术语中，迭代器是一个具有`next()`方法和`done()`方法的对象；后者在序列中没有剩余项目时返回`True`。在没有迭代器的内置支持的编程语言中，迭代器将被循环遍历，如下所示：

```py
while not iterator.done():
    item = iterator.next()
    # do something with the item
```

在 Python 中，迭代是一个特殊的特性，所以该方法得到了一个特殊的名称`__next__`。可以使用内置的`next(iterator)`来访问这个方法。迭代器协议不是使用`done`方法，而是引发`StopIteration`来通知循环已经完成。最后，我们有更加可读的`for item in iterator`语法来实际访问迭代器中的项目，而不是使用`while`循环。让我们更详细地看一下这些。

## 迭代器协议

抽象基类`Iterator`，在`collections.abc`模块中，定义了 Python 中的迭代器协议。正如前面提到的，它必须有一个`__next__`方法，`for`循环（和其他支持迭代的功能）可以调用它来从序列中获取一个新的元素。此外，每个迭代器还必须满足`Iterable`接口。任何提供`__iter__`方法的类都是可迭代的；该方法必须返回一个`Iterator`实例，该实例将覆盖该类中的所有元素。由于迭代器已经在元素上循环，因此它的`__iter__`函数传统上返回它自己。

这可能听起来有点混乱，所以看一下以下的例子，但请注意，这是解决这个问题的一种非常冗长的方式。它清楚地解释了迭代和所讨论的两个协议，但在本章的后面，我们将看到几种更可读的方法来实现这种效果：

```py
class CapitalIterable:
    def __init__(self, string):
        self.string = string

    def __iter__(self):
        return CapitalIterator(self.string)

class CapitalIterator:
    def __init__(self, string):
        self.words = [w.capitalize() for w in string.split()]
        self.index = 0

    def __next__(self):
        if self.index == len(self.words):
            raise StopIteration()

        word = self.words[self.index]
        self.index += 1
        return word

    def __iter__(self):
        return self
```

这个例子定义了一个`CapitalIterable`类，其工作是循环遍历字符串中的每个单词，并输出它们的首字母大写。这个可迭代对象的大部分工作都交给了`CapitalIterator`实现。与这个迭代器互动的规范方式如下：

```py
>>> iterable = CapitalIterable('the quick brown fox jumps over the lazy dog')
>>> iterator = iter(iterable)
>>> while True:
...     try:
...         print(next(iterator))
...     except StopIteration:
...         break
...** 
The
Quick
Brown
Fox
Jumps
Over
The
Lazy
Dog

```

这个例子首先构造了一个可迭代对象，并从中检索了一个迭代器。这种区别可能需要解释；可迭代对象是一个具有可以循环遍历的元素的对象。通常，这些元素可以被多次循环遍历，甚至可能在同一时间或重叠的代码中。另一方面，迭代器代表可迭代对象中的特定位置；一些项目已被消耗，一些项目尚未被消耗。两个不同的迭代器可能在单词列表中的不同位置，但任何一个迭代器只能标记一个位置。

每次在迭代器上调用`next()`时，它会按顺序从可迭代对象中返回另一个标记。最终，迭代器将被耗尽（不再有任何元素返回），在这种情况下会引发`Stopiteration`，然后我们跳出循环。

当然，我们已经知道了一个更简单的语法来从可迭代对象中构造一个迭代器：

```py
>>> for i in iterable:
...     print(i)
...** 
The
Quick
Brown
Fox
Jumps
Over
The
Lazy
Dog

```

正如你所看到的，`for`语句，尽管看起来并不是非常面向对象，实际上是一种显然面向对象设计原则的快捷方式。在我们讨论理解时，请记住这一点，因为它们似乎是面向对象工具的完全相反。然而，它们使用与`for`循环完全相同的迭代协议，只是另一种快捷方式。

# 理解

理解是简单但强大的语法，允许我们在一行代码中转换或过滤可迭代对象。结果对象可以是一个完全正常的列表、集合或字典，也可以是一个生成器表达式，可以在一次性中高效地消耗。

## 列表理解

列表理解是 Python 中最强大的工具之一，所以人们倾向于认为它们是高级的。它们不是。事实上，我已经在以前的例子中使用了理解，并假设你会理解它们。虽然高级程序员确实经常使用理解，但并不是因为它们很高级，而是因为它们很琐碎，并处理软件开发中最常见的一些操作。

让我们来看看其中一个常见的操作；即将一组项目转换为相关项目的列表。具体来说，假设我们刚刚从文件中读取了一个字符串列表，现在我们想将其转换为一个整数列表。我们知道列表中的每个项目都是整数，并且我们想对这些数字进行一些操作（比如计算平均值）。以下是一种简单的方法来解决这个问题：

```py
input_strings = ['1', '5', '28', '131', '3']

output_integers = []
for num in input_strings:
    output_integers.append(int(num))
```

这个例子运行良好，只有三行代码。如果你不习惯理解，你可能甚至不会觉得它看起来很丑！现在，看看使用列表理解的相同代码：

```py
input_strings = ['1', '5', '28', '131', '3']output_integers = [int(num) for num in input_strings]
```

我们只剩下一行，而且，对于性能来说，我们已经删除了列表中每个项目的`append`方法调用。总的来说，很容易看出发生了什么，即使你不习惯理解推导语法。

方括号表示，我们正在创建一个列表。在这个列表中是一个`for`循环，它遍历输入序列中的每个项目。唯一可能令人困惑的是列表的左大括号和`for`循环开始之间发生了什么。这里发生的事情应用于输入列表中的*每个*项目。所讨论的项目由循环中的`num`变量引用。因此，它将每个单独的元素转换为`int`数据类型。

这就是基本列表推导的全部内容。它们并不那么高级。推导是高度优化的 C 代码；当循环遍历大量项目时，列表推导比`for`循环要快得多。如果仅凭可读性不足以说服你尽可能多地使用它们，速度应该是一个令人信服的理由。

将一个项目列表转换为相关列表并不是列表推导唯一能做的事情。我们还可以选择通过在推导中添加`if`语句来排除某些值。看一下：

```py
output_ints = [int(n) for n in input_strings if len(n) < 3]
```

我将变量的名称从`num`缩短为`n`，将结果变量缩短为`output_ints`，这样它仍然可以放在一行上。除此之外，这个例子和前一个例子之间的唯一不同是`if len(n) < 3`部分。这个额外的代码排除了任何长度超过两个字符的字符串。`if`语句应用于`int`函数之前，因此它测试字符串的长度。由于我们的输入字符串本质上都是整数，它排除了任何大于 99 的数字。现在列表推导就是这样了！我们用它们将输入值映射到输出值，同时应用过滤器来包括或排除满足特定条件的任何值。

任何可迭代对象都可以成为列表推导的输入；我们可以将任何可以放在`for`循环中的东西也放在推导中。例如，文本文件是可迭代的；文件的迭代器上的每次调用`__next__`将返回文件的一行。我们可以使用`zip`函数将制表符分隔的文件加载到字典中，其中第一行是标题行：

```py
import sys
filename = sys.argv[1]

with open(filename) as file:
    header = file.readline().strip().split('\t')
 **contacts = [
 **dict(
 **zip(header, line.strip().split('\t'))
 **) for line in file
 **]

for contact in contacts:
    print("email: {email} -- {last}, {first}".format(
        **contact))
```

这次，我添加了一些空格，使其更易读一些（列表推导不一定要放在一行上）。这个例子从文件的标题和分割行创建了一个字典列表。

嗯，什么？如果那段代码或解释没有意义，不要担心；有点令人困惑。一个列表推导在这里做了大量的工作，代码很难理解、阅读，最终也难以维护。这个例子表明列表推导并不总是最好的解决方案；大多数程序员都会同意，`for`循环比这个版本更可读。

### 提示

记住：我们提供的工具不应该被滥用！始终选择合适的工具，即编写可维护的代码。

## 集合和字典推导

推导不仅限于列表。我们也可以使用类似的语法用大括号创建集合和字典。让我们从集合开始。创建集合的一种方法是将列表推导包装在`set()`构造函数中，将其转换为集合。但是，为什么要浪费内存在一个被丢弃的中间列表上，当我们可以直接创建一个集合呢？

这是一个例子，它使用命名元组来模拟作者/标题/流派三元组，然后检索写作特定流派的所有作者的集合：

```py
from collections import namedtuple

Book = namedtuple("Book", "author title genre")
books = [
        Book("Pratchett", "Nightwatch", "fantasy"),
        Book("Pratchett", "Thief Of Time", "fantasy"),
        Book("Le Guin", "The Dispossessed", "scifi"),
        Book("Le Guin", "A Wizard Of Earthsea", "fantasy"),
        Book("Turner", "The Thief", "fantasy"),
        Book("Phillips", "Preston Diamond", "western"),
        Book("Phillips", "Twice Upon A Time", "scifi"),
        ]

fantasy_authors = {
 **b.author for b in books if b.genre == 'fantasy'}

```

与演示数据设置相比，突出显示的集合推导确实很短！如果我们使用列表推导，特里·普拉切特当然会被列出两次。因为集合的性质消除了重复项，我们最终得到：

```py
>>> fantasy_authors
{'Turner', 'Pratchett', 'Le Guin'}

```

我们可以引入冒号来创建字典理解。这将使用*键:值*对将序列转换为字典。例如，如果我们知道标题，可能会很有用快速查找字典中的作者或流派。我们可以使用字典理解将标题映射到书籍对象：

```py
fantasy_titles = {
        b.title: b for b in books if b.genre == 'fantasy'}
```

现在，我们有了一个字典，可以使用正常的语法按标题查找书籍。

总之，理解不是高级 Python，也不是应该避免使用的“非面向对象”工具。它们只是一种更简洁和优化的语法，用于从现有序列创建列表、集合或字典。

## 生成器表达式

有时我们希望处理一个新的序列，而不将新的列表、集合或字典放入系统内存中。如果我们只是逐个循环遍历项目，并且实际上并不关心是否创建最终的容器对象，那么创建该容器就是对内存的浪费。在逐个处理项目时，我们只需要当前对象在任一时刻存储在内存中。但是当我们创建一个容器时，所有对象都必须在开始处理它们之前存储在该容器中。

例如，考虑一个处理日志文件的程序。一个非常简单的日志文件可能包含以下格式的信息：

```py
Jan 26, 2015 11:25:25    DEBUG        This is a debugging message.
Jan 26, 2015 11:25:36    INFO         This is an information method.
Jan 26, 2015 11:25:46    WARNING      This is a warning. It could be serious.
Jan 26, 2015 11:25:52    WARNING      Another warning sent.
Jan 26, 2015 11:25:59    INFO         Here's some information.
Jan 26, 2015 11:26:13    DEBUG        Debug messages are only useful if you want to figure something out.
Jan 26, 2015 11:26:32    INFO         Information is usually harmless, but helpful.
Jan 26, 2015 11:26:40    WARNING      Warnings should be heeded.
Jan 26, 2015 11:26:54    WARNING      Watch for warnings.
```

流行的网络服务器、数据库或电子邮件服务器的日志文件可能包含大量的数据（我最近不得不清理近 2TB 的日志文件）。如果我们想处理日志中的每一行，我们不能使用列表理解；它会创建一个包含文件中每一行的列表。这可能不适合在 RAM 中，并且可能会使计算机陷入困境，这取决于操作系统。

如果我们在日志文件上使用`for`循环，我们可以在将下一行读入内存之前一次处理一行。如果我们能使用理解语法来达到相同的效果，那不是很好吗？

这就是生成器表达式的用武之地。它们使用与理解相同的语法，但它们不创建最终的容器对象。要创建生成器表达式，将理解包装在`()`中，而不是`[]`或`{}`。

以下代码解析了以前呈现格式的日志文件，并输出了一个只包含`WARNING`行的新日志文件：

```py
import sys

inname = sys.argv[1]
outname = sys.argv[2]

with open(inname) as infile:
    with open(outname, "w") as outfile:
 **warnings = (l for l in infile if 'WARNING' in l)
        for l in warnings:
            outfile.write(l)
```

这个程序在命令行上接受两个文件名，使用生成器表达式来过滤警告（在这种情况下，它使用`if`语法，并且保持行不变），然后将警告输出到另一个文件。如果我们在示例文件上运行它，输出如下：

```py
Jan 26, 2015 11:25:46    WARNING     This is a warning. It could be serious.
Jan 26, 2015 11:25:52    WARNING     Another warning sent.
Jan 26, 2015 11:26:40    WARNING     Warnings should be heeded.
Jan 26, 2015 11:26:54    WARNING     Watch for warnings.
```

当然，对于这样一个短的输入文件，我们可以安全地使用列表理解，但是如果文件有数百万行，生成器表达式将对内存和速度产生巨大影响。

生成器表达式在函数调用内部经常最有用。例如，我们可以对生成器表达式调用`sum`、`min`或`max`，而不是列表，因为这些函数一次处理一个对象。我们只对结果感兴趣，而不关心任何中间容器。

一般来说，应尽可能使用生成器表达式。如果我们实际上不需要列表、集合或字典，而只需要过滤或转换序列中的项目，生成器表达式将是最有效的。如果我们需要知道列表的长度，或对结果进行排序、去除重复项或创建字典，我们将不得不使用理解语法。

# 生成器

生成器表达式实际上也是一种理解；它将更高级（这次确实更高级！）的生成器语法压缩成一行。更高级的生成器语法看起来甚至不那么面向对象，但我们将发现，它再次是一种简单的语法快捷方式，用于创建一种对象。

让我们进一步看一下日志文件的例子。如果我们想要从输出文件中删除`WARNING`列（因为它是多余的：这个文件只包含警告），我们有几种选择，不同的可读性级别。我们可以使用生成器表达式来实现：

```py
import sys
inname, outname = sys.argv[1:3]

with open(inname) as infile:
    with open(outname, "w") as outfile:
 **warnings = (l.replace('\tWARNING', '')
 **for l in infile if 'WARNING' in l)
        for l in warnings:
            outfile.write(l)
```

这是完全可读的，尽管我不想使表达式比那更复杂。我们也可以使用普通的`for`循环来实现：

```py
import sys
inname, outname = sys.argv[1:3]

with open(inname) as infile:
    with open(outname, "w") as outfile:
 **for l in infile:
 **if 'WARNING' in l:
 **outfile.write(l.replace('\tWARNING', ''))

```

这是可维护的，但在如此少的行数中有这么多级别的缩进有点丑陋。更令人担忧的是，如果我们想对这些行做一些不同的事情，而不仅仅是打印它们，我们也必须复制循环和条件代码。现在让我们考虑一个真正面向对象的解决方案，没有任何捷径：

```py
import sys
inname, outname = sys.argv[1:3]

class WarningFilter:
 **def __init__(self, insequence):
 **self.insequence = insequence
 **def __iter__(self):
 **return self
 **def __next__(self):
 **l = self.insequence.readline()
 **while l and 'WARNING' not in l:
 **l = self.insequence.readline()
 **if not l:
 **raise StopIteration
 **return l.replace('\tWARNING', '')

with open(inname) as infile:
    with open(outname, "w") as outfile:
        filter = WarningFilter(infile)
        for l in filter:
            outfile.write(l)
```

毫无疑问：这是如此丑陋和难以阅读，以至于你甚至可能无法理解发生了什么。我们创建了一个以文件对象为输入的对象，并提供了一个像任何迭代器一样的`__next__`方法。

这个`__next__`方法从文件中读取行，如果它们不是`WARNING`行，则将它们丢弃。当它遇到`WARNING`行时，它会返回它。然后`for`循环将再次调用`__next__`来处理下一个`WARNING`行。当我们用尽行时，我们引发`StopIteration`来告诉循环我们已经完成迭代。与其他例子相比，这看起来相当丑陋，但也很强大；既然我们手头有一个类，我们可以随心所欲地使用它。

有了这个背景，我们终于可以看到生成器的实际应用了。下一个例子与前一个例子*完全*相同：它创建了一个带有`__next__`方法的对象，当输入用尽时会引发`StopIteration`。

```py
import sys
inname, outname = sys.argv[1:3]

def warnings_filter(insequence):
 **for l in insequence:
 **if 'WARNING' in l:
 **yield l.replace('\tWARNING', '')

with open(inname) as infile:
    with open(outname, "w") as outfile:
        filter = warnings_filter(infile)
        for l in filter:
            outfile.write(l)
```

好吧，这看起来相当可读，也许...至少很简短。但这到底是怎么回事，一点道理也没有。`yield`又是什么？

事实上，`yield`是生成器的关键。当 Python 在函数中看到`yield`时，它会将该函数包装成一个对象，类似于我们前面例子中的对象。将`yield`语句视为类似于`return`语句；它退出函数并返回一行。然而，当函数再次被调用（通过`next()`）时，它将从上次离开的地方开始——在`yield`语句之后的行——而不是从函数的开头开始。在这个例子中，`yield`语句之后没有行，所以它跳到`for`循环的下一个迭代。由于`yield`语句在`if`语句内，它只会产生包含`WARNING`的行。

虽然看起来像是一个函数在循环处理行，但实际上它创建了一种特殊类型的对象，即生成器对象：

```py
>>> print(warnings_filter([]))
<generator object warnings_filter at 0xb728c6bc>

```

我将一个空列表传递给函数，作为迭代器。函数所做的就是创建并返回一个生成器对象。该对象上有`__iter__`和`__next__`方法，就像我们在前面的例子中创建的那样。每当调用`__next__`时，生成器运行函数，直到找到一个`yield`语句。然后返回`yield`的值，下次调用`__next__`时，它将从上次离开的地方继续。

这种生成器的使用并不是很高级，但如果你没有意识到函数正在创建一个对象，它可能看起来像魔术。这个例子很简单，但通过在单个函数中多次调用`yield`，你可以获得非常强大的效果；生成器将简单地从最近的`yield`开始，并继续到下一个`yield`。

## 从另一个可迭代对象中产生值

通常，当我们构建一个生成器函数时，我们最终会处于这样一种情况：我们希望从另一个可迭代对象中产生数据，可能是我们在生成器内部构造的列表推导或生成器表达式，或者是一些外部传递到函数中的项目。以前一直可以通过循环遍历可迭代对象并逐个产生每个项目来实现这一点。然而，在 Python 3.3 版本中，Python 开发人员引入了一种新的语法，使这一点更加优雅。

让我们稍微调整一下生成器示例，使其不再接受一系列行，而是接受一个文件名。这通常会被认为是不好的，因为它将对象与特定的范例联系在一起。在可能的情况下，我们应该操作输入的迭代器；这样，相同的函数可以在日志行来自文件、内存或基于网络的日志聚合器的情况下使用。因此，以下示例是为了教学目的而人为构造的。

这个版本的代码说明了你的生成器可以在从另一个可迭代对象（在本例中是生成器表达式）产生信息之前做一些基本的设置：

```py
import sys
inname, outname = sys.argv[1:3]

def warnings_filter(infilename):
    with open(infilename) as infile:
 **yield from (
 **l.replace('\tWARNING', '')
 **for l in infile
 **if 'WARNING' in l
 **)

filter = warnings_filter(inname)
with open(outname, "w") as outfile:
    for l in filter:
        outfile.write(l)
```

这段代码将前面示例中的`for`循环合并到了一个生成器表达式中。请注意，我将生成器表达式的三个子句（转换、循环和过滤）放在不同的行上，以使它们更易读。还要注意，这种转换并没有帮助太多；前面的`for`循环示例更易读。

因此，让我们考虑一个比其替代方案更易读的示例。构建一个生成器，从多个其他生成器中产生数据，这是有用的。例如，`itertools.chain`函数按顺序从可迭代对象中产生数据，直到它们全部耗尽。这可以使用`yield from`语法实现得太容易了，因此让我们考虑一个经典的计算机科学问题：遍历一棵通用树。

通用树数据结构的常见实现是计算机的文件系统。让我们模拟 Unix 文件系统中的一些文件夹和文件，以便我们可以使用`yield from`有效地遍历它们：

```py
class File:
    def __init__(self, name):
        self.name = name

class Folder(File):
    def __init__(self, name):
        super().__init__(name)
        self.children = []

root = Folder('')
etc = Folder('etc')
root.children.append(etc)
etc.children.append(File('passwd'))
etc.children.append(File('groups'))
httpd = Folder('httpd')
etc.children.append(httpd)
httpd.children.append(File('http.conf'))
var = Folder('var')
root.children.append(var)
log = Folder('log')
var.children.append(log)
log.children.append(File('messages'))
log.children.append(File('kernel'))
```

这个设置代码看起来很费力，但在一个真实的文件系统中，它会更加复杂。我们需要从硬盘中读取数据，并将其结构化成树。然而，一旦在内存中，输出文件系统中的每个文件的代码就非常优雅。

```py
def walk(file):
    if isinstance(file, Folder):
 **yield file.name + '/'
        for f in file.children:
 **yield from walk(f)
    else:
 **yield file.name

```

如果这段代码遇到一个目录，它会递归地要求`walk()`生成其每个子目录下所有文件的列表，然后产生所有这些数据以及自己的文件名。在它遇到一个普通文件的简单情况下，它只会产生那个文件名。

顺便说一句，解决前面的问题而不使用生成器是非常棘手的，以至于这个问题是一个常见的面试问题。如果你像这样回答，准备好让你的面试官既印象深刻又有些恼火，因为你回答得太容易了。他们可能会要求你解释到底发生了什么。当然，有了你在本章学到的原则，你不会有任何问题。

`yield from`语法在编写链式生成器时是一个有用的快捷方式，但它更常用于不同的目的：通过协程传输数据。我们将在第十三章中看到许多这样的例子，但现在，让我们先了解一下协程是什么。

# 协程

协程是非常强大的构造，经常被误解为生成器。许多作者不恰当地将协程描述为“带有一些额外语法的生成器”。这是一个容易犯的错误，因为在 Python 2.5 时引入协程时，它们被介绍为“我们在生成器语法中添加了一个`send`方法”。这更加复杂的是，当你在 Python 中创建一个协程时，返回的对象是一个生成器。实际上，区别要微妙得多，在你看到一些例子之后会更有意义。

### 注意

虽然 Python 中的协程目前与生成器语法紧密耦合，但它们与我们讨论过的迭代器协议只是表面上相关。即将发布的 Python 3.5 版本将使协程成为一个真正独立的对象，并提供一种新的语法来处理它们。

另一件需要记住的事情是，协程很难理解。它们在实际中并不经常使用，你可能会在 Python 中开发多年而不会错过或甚至遇到它们。有一些库广泛使用协程（主要用于并发或异步编程），但它们通常是这样编写的，以便你可以在不实际理解它们如何工作的情况下使用协程！所以如果你在这一节迷失了方向，不要绝望。

但是你不会迷失方向，因为已经学习了以下示例。这是最简单的协程之一；它允许我们保持一个可以通过任意值增加的累加值：

```py
def tally():
    score = 0
    while True:
 **increment = yield score
        score += increment
```

这段代码看起来像不可能工作的黑魔法，所以我们将在逐行描述之前看到它的工作原理。这个简单的对象可以被棒球队的记分应用程序使用。可以为每个团队保留单独的计分，并且他们的得分可以在每个半局结束时递增。看看这个交互式会话：

```py
>>> white_sox = tally()
>>> blue_jays = tally()
>>> next(white_sox)
0
>>> next(blue_jays)
0
>>> white_sox.send(3)
3
>>> blue_jays.send(2)
2
>>> white_sox.send(2)
5
>>> blue_jays.send(4)
6

```

首先我们构造两个`tally`对象，一个用于每个团队。是的，它们看起来像函数，但与上一节中的生成器对象一样，函数内部有`yield`语句告诉 Python 要花大量精力将简单函数转换为对象。

然后我们对每个协程对象调用`next()`。这与对任何生成器调用`next`的操作相同，也就是说，它执行代码的每一行，直到遇到`yield`语句，返回该点的值，然后*暂停*直到下一个`next()`调用。

到目前为止，没有什么新鲜的。但是回顾一下我们协程中的`yield`语句：

```py
increment = yield score
```

与生成器不同，这个 yield 函数看起来应该返回一个值并将其分配给一个变量。事实上，这正是发生的事情。协程仍然在`yield`语句处暂停，等待通过另一个`next()`调用再次激活。

或者，正如你在交互式会话中看到的那样，调用一个名为`send()`的方法。`send()`方法与`next()`完全相同，只是除了将生成器推进到下一个`yield`语句外，它还允许你从生成器外部传入一个值。这个值被分配给`yield`语句的左侧。

对于许多人来说，真正令人困惑的是这发生的顺序：

+   `yield`发生，生成器暂停

+   `send()`来自函数外部，生成器被唤醒

+   发送的值被分配给`yield`语句的左侧

+   生成器继续处理，直到遇到另一个`yield`语句

因此，在这个特定的示例中，我们构造了协程并通过调用`next()`将其推进到`yield`语句，然后每次调用`send()`都会将一个值传递给协程，协程将这个值加到其分数中，然后返回到`while`循环的顶部，并继续处理直到达到`yield`语句。`yield`语句返回一个值，这个值成为最近一次`send`调用的返回值。不要错过：`send()`方法不仅仅提交一个值给生成器，它还返回即将到来的`yield`语句的值，就像`next()`一样。这就是我们定义生成器和协程之间的区别的方式：生成器只产生值，而协程也可以消耗值。

### 注意

`next(i)`，`i.__next__()`和`i.send(value)`的行为和语法相当不直观和令人沮丧。第一个是普通函数，第二个是特殊方法，最后一个是普通方法。但是这三个都是做同样的事情：推进生成器直到产生一个值并暂停。此外，`next()`函数和相关方法可以通过调用`i.send(None)`来复制。在这里有两个不同的方法名称是有价值的，因为它有助于我们的代码读者轻松地看到他们是在与协程还是生成器进行交互。我只是觉得在某些情况下，它是一个函数调用，而在另一种情况下，它是一个普通方法，有点令人恼火。

## 回到日志解析

当然，前面的示例也可以很容易地使用几个整数变量和在它们上调用`x += increment`来编写。让我们看一个第二个示例，其中协程实际上为我们节省了一些代码。这个例子是我在真实工作中不得不解决的问题的一个简化版本（出于教学目的）。它从先前关于处理日志文件的讨论中逻辑上延伸出来，这完全是偶然的；那些示例是为本书的第一版编写的，而这个问题是四年后出现的！

Linux 内核日志包含看起来有些类似但又不完全相同的行：

```py
unrelated log messages
sd 0:0:0:0 Attached Disk Drive
unrelated log messages
sd 0:0:0:0 (SERIAL=ZZ12345)
unrelated log messages
sd 0:0:0:0 [sda] Options
unrelated log messages
XFS ERROR [sda]
unrelated log messages
sd 2:0:0:1 Attached Disk Drive
unrelated log messages
sd 2:0:0:1 (SERIAL=ZZ67890)
unrelated log messages
sd 2:0:0:1 [sdb] Options
unrelated log messages
sd 3:0:1:8 Attached Disk Drive
unrelated log messages
sd 3:0:1:8 (SERIAL=WW11111)
unrelated log messages
sd 3:0:1:8 [sdc] Options
unrelated log messages
XFS ERROR [sdc]
unrelated log messages
```

有许多交错的内核日志消息，其中一些与硬盘有关。硬盘消息可能与其他消息交错，但它们以可预测的格式和顺序出现，其中具有已知序列号的特定驱动器与总线标识符（如`0:0:0:0`）相关联，并且与该总线相关联的块设备标识符（如`sda`）。最后，如果驱动器的文件系统损坏，它可能会出现 XFS 错误。

现在，考虑到前面的日志文件，我们需要解决的问题是如何获取任何存在 XFS 错误的驱动器的序列号。稍后，数据中心技术人员可能会使用这个序列号来识别并更换驱动器。

我们知道可以使用正则表达式识别各行，但是我们必须在循环遍历行时更改正则表达式，因为根据之前找到的内容，我们将寻找不同的内容。另一个困难的地方是，如果我们找到错误字符串，关于包含该字符串的总线以及附加到该总线上的驱动器的序列号的信息已经被处理。通过以相反的顺序迭代文件的行，这个问题很容易解决。

在查看此示例之前，请注意 - 基于协程的解决方案所需的代码量非常少，令人不安：

```py
import re

def match_regex(filename, regex):
    with open(filename) as file:
        lines = file.readlines()
    for line in reversed(lines):
        match = re.match(regex, line)
        if match:
 **regex = yield match.groups()[0]

def get_serials(filename):
    ERROR_RE = 'XFS ERROR (\[sd[a-z]\])'
 **matcher = match_regex(filename, ERROR_RE)
    device = next(matcher)
    while True:
        bus = matcher.send(
            '(sd \S+) {}.*'.format(re.escape(device)))
        serial = matcher.send('{} \(SERIAL=([^)]*)\)'.format(bus))
 **yield serial
        device = matcher.send(ERROR_RE)

for serial_number in get_serials('EXAMPLE_LOG.log'):
    print(serial_number)
```

这段代码将工作分为两个独立的任务。第一个任务是循环遍历所有行，并输出与给定正则表达式匹配的任何行。第二个任务是与第一个任务进行交互，并指导它在任何给定时间搜索什么正则表达式。

首先看一下`match_regex`协程。记住，它在构造时不执行任何代码；相反，它只是创建一个协程对象。一旦构造完成，协程外部的某人最终会调用`next()`来启动代码运行，此时它会存储两个变量`filename`和`regex`的状态。然后它读取文件中的所有行并以相反的顺序对它们进行迭代。将传入的每一行与正则表达式进行比较，直到找到匹配项。当找到匹配项时，协程会产生正则表达式的第一个组并等待。

在将来的某个时候，其他代码将发送一个新的正则表达式进行搜索。请注意，协程从不关心它试图匹配什么正则表达式；它只是循环遍历行并将它们与正则表达式进行比较。决定提供什么正则表达式是其他人的责任。

在这种情况下，那个“别人”是`get_serials`生成器。它不关心文件中的行，事实上它甚至不知道它们。它做的第一件事是从`match_regex`协程构造函数创建一个`matcher`对象，并给它一个默认的正则表达式来搜索。它将协程推进到它的第一个`yield`并存储它返回的值。然后它进入一个循环，指示匹配器对象根据存储的设备 ID 搜索总线 ID，然后根据该总线 ID 搜索序列号。

在向外部的`for`循环中空闲地产生该序列号，然后指示匹配器查找另一个设备 ID 并重复循环。

基本上，协程（`match_regex`，因为它使用`regex = yield`语法）的工作是在文件中搜索下一个重要的行，而生成器（`get_serial`，它使用没有赋值的`yield`语法）的工作是决定哪一行是重要的。生成器有关于这个特定问题的信息，比如文件中行的顺序。另一方面，协程可以插入到任何需要搜索文件以获取给定正则表达式的问题中。

## 关闭协程和抛出异常

普通生成器通过引发`StopIteration`来从内部信号退出。如果我们将多个生成器链接在一起（例如通过在另一个生成器内部迭代一个生成器），`StopIteration`异常将被传播到外部。最终，它将触发一个`for`循环，看到异常并知道是时候退出循环了。

协程通常不遵循迭代机制；而不是通过一个直到遇到异常的数据，通常是将数据推送到其中（使用`send`）。通常是负责推送的实体告诉协程何时完成；它通过在相关协程上调用`close()`方法来实现这一点。

当调用`close()`方法时，将在协程等待发送值的点引发一个`GeneratorExit`异常。通常，协程应该将它们的`yield`语句包装在`try`...`finally`块中，以便执行任何清理任务（例如关闭关联的文件或套接字）。

如果我们需要在协程内部引发异常，我们可以类似地使用`throw()`方法。它接受一个异常类型，可选的`value`和`traceback`参数。当我们在一个协程中遇到异常并希望在相邻的协程中引发异常时，后者是非常有用的，同时保持回溯。

如果您正在构建健壮的基于协程的库，这两个功能都是至关重要的，但在日常编码生活中，我们不太可能遇到它们。

## 协程、生成器和函数之间的关系

我们已经看到协程的运行情况，现在让我们回到讨论它们与生成器的关系。在 Python 中，就像往常一样，这个区别是相当模糊的。事实上，所有的协程都是生成器对象，作者经常交替使用这两个术语。有时，他们将协程描述为生成器的一个子集（只有从`yield`返回值的生成器被认为是协程）。在 Python 中，这在技术上是正确的，正如我们在前面的部分中所看到的。

然而，在更广泛的理论计算机科学领域，协程被认为是更一般的原则，生成器是协程的一种特定类型。此外，普通函数是协程的另一个独特子集。

协程是一个可以在一个或多个点传入数据并在一个或多个点获取数据的例程。在 Python 中，数据传入和传出的点是`yield`语句。

函数，或子例程，是最简单的协程类型。你可以在一个点传入数据，并在函数返回时在另一个点获取数据。虽然函数可以有多个`return`语句，但对于任何给定的函数调用，只能调用其中一个。

最后，生成器是一种协程类型，可以在一个点传入数据，但可以在多个点传出数据。在 Python 中，数据将在`yield`语句处传出，但你不能将数据传回。如果你调用了`send`，数据将被悄悄丢弃。

所以理论上，生成器是协程的一种类型，函数是协程的一种类型，还有一些既不是函数也不是生成器的协程。够简单吧？那为什么在 Python 中感觉更复杂呢？

在 Python 中，生成器和协程都是使用看起来像是构造函数的语法构造的。但是生成的对象根本不是函数；它是一种完全不同类型的对象。函数当然也是对象。但它们有不同的接口；函数是可调用的并返回值，生成器使用`next()`提取数据，协程使用`send`推送数据。

# 案例研究

Python 目前最流行的领域之一是数据科学。让我们实现一个基本的机器学习算法！机器学习是一个庞大的主题，但总体思想是利用从过去数据中获得的知识对未来数据进行预测或分类。这些算法的用途很广泛，数据科学家们每天都在找到新的应用机器学习的方法。一些重要的机器学习应用包括计算机视觉（如图像分类或人脸识别）、产品推荐、识别垃圾邮件和语音识别。我们将研究一个更简单的问题：给定一个 RGB 颜色定义，人们会将该颜色识别为什么名称？

在标准 RGB 颜色空间中有超过 1600 万种颜色，人类只为其中的一小部分制定了名称。虽然有成千上万的名称（有些相当荒谬；只需去任何汽车经销商或化妆品商店），让我们构建一个试图将 RGB 空间划分为基本颜色的分类器：

+   红色

+   紫色

+   蓝色

+   绿色

+   黄色

+   橙色

+   灰色

+   白色

+   粉色

我们需要的第一件事是一个数据集来训练我们的算法。在生产系统中，你可能会从*颜色列表*网站上获取数据，或者对成千上万的人进行调查。相反，我创建了一个简单的应用程序，它会渲染一个随机颜色，并要求用户选择前述九个选项中的一个来对其进行分类。这个应用程序包含在本章的示例代码中的`kivy_color_classifier`目录中，但我们不会详细介绍这段代码，因为它在这里的唯一目的是生成样本数据。

### 注

Kivy 有一个非常精心设计的面向对象的 API，你可能想自己探索一下。如果你想开发可以在许多系统上运行的图形程序，从你的笔记本电脑到你的手机，你可能想看看我的书《在 Kivy 中创建应用》，*O'Reilly*。

在这个案例研究中，该应用程序的重要之处在于输出，这是一个包含每行四个值的**逗号分隔值**（**CSV**）文件：红色、绿色和蓝色值（表示为 0 到 1 之间的浮点数），以及用户为该颜色分配的前述九个名称中的一个。数据集看起来像这样：

```py
0.30928279150905513,0.7536768153744394,0.3244011790604804,Green
0.4991001855115986,0.6394567277907686,0.6340502030888825,Grey
0.21132621004927998,0.3307376167520666,0.704037576789711,Blue
0.7260420945787928,0.4025279573860123,0.49781705131696363,Pink
0.706469868610228,0.28530423638868196,0.7880240251003464,Purple
0.692243900051664,0.7053550777777416,0.1845069151913028,Yellow
0.3628979381122397,0.11079495501215897,0.26924540840045075,Purple
0.611273677646518,0.48798521783547677,0.5346130557761224,Purple
.
.
.
0.4014121109376566,0.42176706818252674,0.9601866228083298,Blue
0.17750449496124632,0.8008214961070862,0.5073944321437429,Green
```

在我感到无聊并决定开始对这个数据集进行机器学习之前，我制作了 200 个数据点（其中很少有不真实的数据）。如果你想使用我的数据（没有人告诉我我是色盲，所以应该是相当合理的），这些数据点已经包含在本章的示例中。

我们将实现一个较简单的机器学习算法，称为 k 最近邻算法。该算法依赖于数据集中点之间的某种“距离”计算（在我们的情况下，我们可以使用三维版本的毕达哥拉斯定理）。给定一个新的数据点，它找到一定数量（称为 k，如 k 最近邻）的数据点，这些数据点在通过该距离计算时最接近它。然后以某种方式组合这些数据点（对于线性计算，平均值可能有效；对于我们的分类问题，我们将使用众数），并返回结果。

我们不会过多地讨论算法的具体内容；相反，我们将专注于如何将迭代器模式或迭代器协议应用于这个问题。

现在，让我们编写一个程序，按顺序执行以下步骤：

1.  从文件中加载样本数据并构建模型。

1.  生成 100 种随机颜色。

1.  对每种颜色进行分类，并将其输出到与输入相同格式的文件中。

一旦有了这个第二个 CSV 文件，另一个 Kivy 程序可以加载文件并渲染每种颜色，要求人类用户确认或否认预测的准确性，从而告诉我们我们的算法和初始数据集的准确性如何。

第一步是一个相当简单的生成器，它加载 CSV 数据并将其转换为符合我们需求的格式：

```py
import csv

dataset_filename = 'colors.csv'

def load_colors(filename):
    with open(filename) as dataset_file:
 **lines = csv.reader(dataset_file)
        for line in lines:
 **yield tuple(float(y) for y in line[0:3]), line[3]

```

我们以前没有见过`csv.reader`函数。它返回文件中行的迭代器。迭代器返回的每个值都是一个字符串列表。在我们的情况下，我们可以只是按逗号分割就可以了，但`csv.reader`还负责处理引号和逗号分隔值格式的各种其他细微差别。

然后我们循环遍历这些行，并将它们转换为颜色和名称的元组，其中颜色是由三个浮点值整数组成的元组。这个元组是使用生成器表达式构造的。可能有更易读的方法来构造这个元组；你认为生成器表达式的代码简洁和速度是否值得混淆？它不是返回一个颜色元组的列表，而是逐个产生它们，从而构造一个生成器对象。

现在，我们需要一百种随机颜色。有很多方法可以做到这一点：

+   使用嵌套生成器表达式的列表推导：`[tuple(random() for r in range(3)) for r in range(100)]`

+   一个基本的生成器函数

+   一个实现`__iter__`和`__next__`协议的类

+   将数据通过一系列协程

+   甚至只是一个基本的`for`循环

生成器版本似乎是最易读的，所以让我们将该函数添加到我们的程序中：

```py
from random import random

def generate_colors(count=100):
    for i in range(count):
 **yield (random(), random(), random())

```

注意我们对要生成的颜色数量进行了参数化。现在我们可以在将来的其他生成颜色任务中重用这个函数。

现在，在进行分类步骤之前，我们需要一个函数来计算两种颜色之间的“距离”。由于可以将颜色看作是三维的（例如，红色、绿色和蓝色可以映射到*x*、*y*和*z*轴），让我们使用一些基本的数学：

```py
import math

def color_distance(color1, color2):
    channels = zip(color1, color2)
    sum_distance_squared = 0
    for c1, c2 in channels:
        sum_distance_squared += (c1 - c2) ** 2
    return math.sqrt(sum_distance_squared)
```

这是一个看起来非常基本的函数；它似乎甚至没有使用迭代器协议。没有`yield`函数，也没有推导。然而，有一个`for`循环，而且`zip`函数的调用也在进行一些真正的迭代（记住`zip`会产生包含每个输入迭代器中一个元素的元组）。

然而，需要注意的是，这个函数将在我们的 k 最近邻算法中被调用很多次。如果我们的代码运行得太慢，并且我们能够确定这个函数是瓶颈，我们可能希望用一个不太易读但更优化的生成器表达式来替换它：

```py
def color_distance(color1, color2):
    return math.sqrt(sum((x[0] - x[1]) ** 2 for x in zip(
    color1, color2)))
```

然而，我强烈建议在证明可读版本太慢之前不要进行这样的优化。

现在我们已经有了一些管道，让我们来实际做 k 最近邻实现。这似乎是使用协程的好地方。下面是一些测试代码，以确保它产生合理的值：

```py
def nearest_neighbors(model_colors, num_neighbors):
    model = list(model_colors)
 **target = yield
    while True:
        distances = sorted(
            ((color_distance(c[0], target), c) for c in model),
        )
 **target = yield [
 **d[1] for d in distances[0:num_neighbors]
 **]

model_colors = load_colors(dataset_filename)
target_colors = generate_colors(3)
get_neighbors = nearest_neighbors(model_colors, 5)
next(get_neighbors)

for color in target_colors:
    distances = get_neighbors.send(color)
    print(color)
    for d in distances:
        print(color_distance(color, d[0]), d[1])
```

该协程接受两个参数，要用作模型的颜色列表和要查询的邻居数。它将模型转换为列表，因为它将被多次迭代。在协程的主体中，它使用`yield`语法接受一个 RGB 颜色值的元组。然后它将`sorted`调用与一个奇怪的生成器表达式结合在一起。看看你是否能弄清楚那个生成器表达式在做什么。

它为模型中的每种颜色返回一个`(distance, color_data)`元组。请记住，模型本身包含`(color, name)`的元组，其中`color`是三个 RGB 值的元组。因此，该生成器返回一个奇怪数据结构的迭代器，看起来像这样：

```py
(distance, (r, g, b), color_name)
```

然后，`sorted`调用按照它们的第一个元素（距离）对结果进行排序。这是一段复杂的代码，根本不是面向对象的。您可能希望将其分解为一个普通的`for`循环，以确保您理解生成器表达式的工作原理。如果您将一个键参数传递给`sorted`函数而不是构造一个元组，想象一下这段代码会是什么样子也是一个很好的练习。

`yield`语句稍微复杂一些；它从前 k 个`(distance, color_data)`元组中提取第二个值。更具体地说，它为距离最近的 k 个值产生了`((r, g, b), color_name)`元组。或者，如果您更喜欢更抽象的术语，它为给定模型中目标的 k 个最近邻产生了值。

剩下的代码只是测试这种方法的样板；它构造了模型和颜色生成器，启动了协程，并在`for`循环中打印结果。

剩下的两个任务是根据最近邻选择颜色，并将结果输出到 CSV 文件。让我们创建两个协程来处理这些任务。我们先做输出，因为它可以独立测试：

```py
def write_results(filename="output.csv"):
    with open(filename, "w") as file:
        writer = csv.writer(file)
        while True:
 **color, name = yield
            writer.writerow(list(color) + [name])

results = write_results()
next(results)
for i in range(3):
    print(i)
    results.send(((i, i, i), i * 10))
```

该协程将一个打开的文件作为状态，并在使用`send()`发送的情况下将代码行写入其中。测试代码确保协程正常工作，所以现在我们可以用第三个协程连接这两个协程了。

第二个协程使用了一个有点奇怪的技巧：

```py
from collections import Counter
def name_colors(get_neighbors):
 **color = yield
    while True:
 **near = get_neighbors.send(color)
        name_guess = Counter(
            n[1] for n in near).most_common(1)[0][0]
 **color = yield name_guess

```

这个协程接受一个现有的协程作为参数。在这种情况下，它是`nearest_neighbors`的一个实例。这段代码基本上通过`nearest_neighbors`实例代理所有发送到它的值。然后它对结果进行一些处理，以获取返回的值中最常见的颜色。在这种情况下，也许将原始协程调整为返回一个名称会更有意义，因为它没有被用于其他任何事情。然而，有许多情况下传递协程是有用的；这就是我们的做法。

现在，我们所要做的就是将这些不同的协程和管道连接在一起，并通过一个单一的函数调用启动整个过程：

```py
def process_colors(dataset_filename="colors.csv"):
    model_colors = load_colors(dataset_filename)
    get_neighbors = nearest_neighbors(model_colors, 5)
 **get_color_name = name_colors(get_neighbors)
    output = write_results()
 **next(output)
 **next(get_neighbors)
 **next(get_color_name)

    for color in generate_colors():
 **name = get_color_name.send(color)
 **output.send((color, name))

process_colors()
```

因此，与我们定义的几乎所有其他函数不同，这个函数是一个完全正常的函数，没有任何`yield`语句。它不会被转换为协程或生成器对象。但是，它确实构造了一个生成器和三个协程。请注意，`get_neighbors`协程是如何传递给`name_colors`构造函数的。注意所有三个协程是如何通过调用`next`推进到它们的第一个`yield`语句的。

一旦所有管道都创建好了，我们就使用`for`循环将生成的每种颜色发送到`get_color_name`协程中，然后将该协程产生的每个值传送到输出协程，将其写入文件。

就是这样！我创建了第二个 Kivy 应用程序，加载了生成的 CSV 文件，并将颜色呈现给用户。用户可以根据他们认为机器学习算法的选择是否与他们的选择相匹配来选择*是*或*否*。这并不科学准确（容易出现观察偏差），但对于玩耍来说已经足够了。用我的眼睛看，它成功率约为 84%，比我 12 年级的平均成绩要好。对于我们第一次的机器学习经历来说，这已经不错了，对吧？

你可能会想，“这与面向对象编程有什么关系？这段代码中甚至没有一个类！”在某些方面，你是对的；协程和生成器通常不被认为是面向对象的。然而，创建它们的函数会返回对象；实际上，你可以将这些函数看作构造函数。构造的对象具有适当的`send()`和`__next__()`方法。基本上，协程/生成器语法是一种特定类型的对象的语法快捷方式，如果没有它，创建这种对象会非常冗长。

这个案例研究是一个自下而上设计的练习。我们创建了各种低级对象，执行特定的任务，并在最后将它们全部连接在一起。我发现这在开发协程时是一个常见的做法。另一种选择，自上而下的设计有时会导致更多的代码块而不是独特的个体。总的来说，我们希望在太大和太小的方法之间找到一个合适的平衡，以及它们如何组合在一起。当然，这是真的，无论是否像我们在这里做的那样使用迭代器协议。

# 练习

如果你在日常编码中很少使用推导，那么你应该做的第一件事是搜索一些现有的代码，找到一些`for`循环。看看它们中是否有任何可以轻松转换为生成器表达式或列表、集合或字典推导的。

测试列表推导是否比`for`循环更快的说法。这可以通过内置的`timeit`模块来实现。使用`timeit.timeit`函数的帮助文档来了解如何使用它。基本上，编写两个做同样事情的函数，一个使用列表推导，一个使用`for`循环。将每个函数传递给`timeit.timeit`，并比较结果。如果你感到有冒险精神，也可以比较生成器和生成器表达式。使用`timeit`测试代码可能会让人上瘾，所以请记住，除非代码被执行了大量次数，比如在一个巨大的输入列表或文件上，否则代码不需要非常快。

玩转生成器函数。从需要多个值的基本迭代器开始（数学序列是典型的例子；如果你想不出更好的例子，斐波那契数列就太过于使用了）。尝试一些更高级的生成器，比如接受多个输入列表并以某种方式产生合并值的生成器。生成器也可以用在文件上；你能写一个简单的生成器来显示两个文件中相同的行吗？

协程滥用迭代器协议，但实际上并不满足迭代器模式。你能否构建一个从日志文件中获取序列号的非协程版本的代码？采用面向对象的方法，这样你就可以在一个类上存储额外的状态。如果你能创建一个可以替换现有协程的对象，你将学到很多关于协程的知识。

看看你是否能将案例研究中使用的协程抽象出来，以便可以在各种数据集上使用 k 最近邻算法。你可能希望构建一个接受其他协程或执行距离和重组计算的函数作为参数的协程，并调用这些函数来找到实际的最近邻。

# 总结

在本章中，我们了解到设计模式是有用的抽象，为常见的编程问题提供了“最佳实践”解决方案。我们介绍了我们的第一个设计模式，迭代器，以及 Python 使用和滥用这种模式的多种方式。原始的迭代器模式非常面向对象，但在代码编写时也相当丑陋和冗长。然而，Python 的内置语法将丑陋的部分抽象出来，为我们留下了一个清晰的接口来使用这些面向对象的构造。

理解和生成器表达式可以在一行中将容器构造与迭代结合起来。生成器对象可以使用`yield`语法来构造。协程看起来像生成器，但用途完全不同。

在接下来的两章中，我们将介绍更多的设计模式。


# 第十章：Python 设计模式 I

在上一章中，我们简要介绍了设计模式，并介绍了迭代器模式，这是一个非常有用和常见的模式，已经被抽象成编程语言核心的一部分。在本章中，我们将回顾其他常见的模式，以及它们在 Python 中的实现。与迭代一样，Python 通常提供替代语法，以使处理此类问题更简单。我们将介绍这些模式的“传统”设计和 Python 版本。总之，我们将看到：

+   许多特定的模式

+   Python 中每种模式的典型实现

+   Python 语法以替换某些模式

# 装饰器模式

装饰器模式允许我们用其他对象包装提供核心功能的对象，从而改变这个功能。使用装饰对象的任何对象将与未装饰的对象完全相同地交互（即，装饰对象的接口与核心对象的接口相同）。

装饰器模式有两个主要用途：

+   增强组件发送数据到第二个组件的响应

+   支持多个可选行为

第二个选项通常是多重继承的一个合适替代方案。我们可以构建一个核心对象，然后在该核心周围创建一个装饰器。由于装饰器对象具有与核心对象相同的接口，因此我们甚至可以将新对象包装在其他装饰器中。在 UML 中的样子如下：

![装饰器模式](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py3-oop-2e/img/8781OS_10_01.jpg)

在这里，**Core**和所有装饰器都实现了特定的**接口**。装饰器通过组合维护对**接口**的另一个实例的引用。在调用时，装饰器在调用其包装的接口之前或之后进行一些附加处理。包装对象可以是另一个装饰器，也可以是核心功能。虽然多个装饰器可以相互包装，但是所有这些装饰器中的对象提供了核心功能。

## 装饰器示例

让我们看一个网络编程的例子。我们将使用 TCP 套接字。`socket.send()`方法接受输入字节的字符串，并将其输出到另一端的接收套接字。有很多库接受套接字并访问此函数以在流上发送数据。让我们创建这样一个对象；它将是一个交互式 shell，等待客户端的连接，然后提示用户输入一个字符串响应：

```py
import socket

def respond(client):
    response = input("Enter a value: ")
    **client.send(bytes(response, 'utf8'))
    client.close()

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(('localhost',2401))
server.listen(1)
try:
    while True:
        client, addr = server.accept()
        respond(client)
finally:
    server.close()
```

`respond`函数接受一个套接字参数，并提示发送回复的数据，然后发送它。要使用它，我们构造一个服务器套接字，并告诉它在本地计算机上的端口`2401`上进行监听（我随机选择了端口）。当客户端连接时，它调用`respond`函数，该函数交互地请求数据并做出适当的响应。要注意的重要事情是，`respond`函数只关心套接字接口的两种方法：`send`和`close`。为了测试这一点，我们可以编写一个非常简单的客户端，连接到相同的端口并在退出之前输出响应：

```py
import socket

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(('localhost', 2401))
print("Received: {0}".format(client.recv(1024)))
client.close()
```

要使用这些程序：

1.  在一个终端中启动服务器。

1.  打开第二个终端窗口并运行客户端。

1.  在服务器窗口的**输入值：**提示中，输入一个值并按回车键。

1.  客户端将接收您输入的内容，将其打印到控制台并退出。再次运行客户端；服务器将提示输入第二个值。

现在，再次查看我们的服务器代码，我们看到两个部分。`respond`函数将数据发送到套接字对象中。剩下的脚本负责创建该套接字对象。我们将创建一对装饰器，定制套接字行为，而无需扩展或修改套接字本身。

让我们从一个“日志记录”装饰器开始。在将数据发送到客户端之前，该对象会将发送到服务器控制台的任何数据输出：

```py
class LogSocket:
    def __init__(self, socket):
        self.socket = socket

 **def send(self, data):
 **print("Sending {0} to {1}".format(
 **data, self.socket.getpeername()[0]))
 **self.socket.send(data)

 **def close(self):
 **self.socket.close()

```

这个类装饰了一个套接字对象，并向客户端套接字提供`send`和`close`接口。一个更好的装饰器还应该实现（并可能自定义）所有剩余的套接字方法。它还应该正确实现`send`的所有参数（实际上接受一个可选的标志参数），但让我们保持我们的例子简单！每当在这个对象上调用`send`时，它都会在将数据发送到客户端之前将输出记录到屏幕上，使用原始套接字。

我们只需要改变原始代码中的一行，就可以使用这个装饰器。我们不再用套接字调用`respond`，而是用一个装饰过的套接字调用它：

```py
respond(LogSocket(client))
```

虽然这很简单，但我们必须问自己为什么我们不直接扩展套接字类并覆盖`send`方法。我们可以调用`super().send`在记录后执行实际发送。这种设计也没有问题。

当面临装饰器和继承之间的选择时，只有在我们需要根据某些条件动态修改对象时，才应该使用装饰器。例如，我们可能只想在服务器当前处于调试模式时启用日志装饰器。当我们有多个可选行为时，装饰器也比多重继承更胜一筹。例如，我们可以编写第二个装饰器，每当调用`send`时，它都使用`gzip`压缩数据：

```py
import gzip
from io import BytesIO

class GzipSocket:
    def __init__(self, socket):
        self.socket = socket

    def send(self, data):
        buf = BytesIO()
        zipfile = gzip.GzipFile(fileobj=buf, mode="w")
        zipfile.write(data)
        zipfile.close()
 **self.socket.send(buf.getvalue())

    def close(self):
        self.socket.close()
```

这个版本中的`send`方法在发送到客户端之前压缩传入的数据。

现在我们有了这两个装饰器，我们可以编写代码，在响应时动态地在它们之间切换。这个例子并不完整，但它说明了我们可能遵循的混合装饰器的逻辑：

```py
        client, addr = server.accept()
        if log_send:
            client = LoggingSocket(client)
        if client.getpeername()[0] in compress_hosts:
            client = GzipSocket(client)
        respond(client)
```

这段代码检查了一个名为`log_send`的假设配置变量。如果启用了它，它会将套接字包装在`LoggingSocket`装饰器中。类似地，它检查连接的客户端是否在已知接受压缩内容的地址列表中。如果是，它会将客户端包装在`GzipSocket`装饰器中。请注意，这两个装饰器中的任何一个、两个或都可能被启用，取决于配置和连接的客户端。尝试使用多重继承来编写这个，并看看你会有多困惑！

## Python 中的装饰器

装饰器模式在 Python 中很有用，但也有其他选择。例如，我们可能能够使用我们在第七章中讨论过的猴子补丁来获得类似的效果。单继承，其中“可选”计算是在一个大方法中完成的，也是一个选择，多重继承不应该被写入，只是因为它对先前看到的特定示例不合适！

在 Python 中，对函数使用这种模式是非常常见的。正如我们在之前的章节中看到的，函数也是对象。事实上，函数装饰是如此常见，以至于 Python 提供了一种特殊的语法，使得很容易将这样的装饰器应用到函数上。

例如，我们可以更一般地看待日志示例。我们可能会发现，与其仅在套接字上发送调用，不如记录对某些函数或方法的所有调用会更有帮助。以下示例实现了一个刚好做到这一点的装饰器：

```py
import time

def log_calls(func):
 **def wrapper(*args, **kwargs):
        now = time.time()
        print("Calling {0} with {1} and {2}".format(
            func.__name__, args, kwargs))
 **return_value = func(*args, **kwargs)
        print("Executed {0} in {1}ms".format(
            func.__name__, time.time() - now))
        return return_value
 **return wrapper

def test1(a,b,c):
    print("\ttest1 called")

def test2(a,b):
    print("\ttest2 called")

def test3(a,b):
    print("\ttest3 called")
    time.sleep(1)

test1 = log_calls(test1)
test2 = log_calls(test2)
test3 = log_calls(test3)

test1(1,2,3)
test2(4,b=5)
test3(6,7)
```

这个装饰器函数与我们之前探讨的示例非常相似；在那些情况下，装饰器接受一个类似套接字的对象，并创建一个类似套接字的对象。这一次，我们的装饰器接受一个函数对象，并返回一个新的函数对象。这段代码由三个独立的任务组成：

+   一个名为`log_calls`的函数，接受另一个函数

+   这个函数定义了（内部）一个名为`wrapper`的新函数，在调用原始函数之前做一些额外的工作

+   这个新函数被返回

三个示例函数演示了装饰器的使用。第三个示例包括一个睡眠调用来演示定时测试。我们将每个函数传递给装饰器，装饰器返回一个新函数。我们将这个新函数赋给原始变量名，有效地用装饰后的函数替换了原始函数。

这种语法允许我们动态地构建装饰函数对象，就像我们在套接字示例中所做的那样；如果我们不替换名称，甚至可以为不同情况保留装饰和非装饰版本。

通常这些装饰器是应用于不同函数的永久性通用修改。在这种情况下，Python 支持一种特殊的语法，在函数定义时应用装饰器。当我们讨论`property`装饰器时，我们已经看到了这种语法；现在，让我们了解一下它是如何工作的。

我们可以使用`@decorator`语法一次完成所有操作，而不是在方法定义之后应用装饰器函数：

```py
@log_calls
def test1(a,b,c):
    print("\ttest1 called")
```

这种语法的主要好处是我们可以很容易地看到函数在定义时已经被装饰。如果装饰器是后来应用的，阅读代码的人可能会错过函数已经被修改的事实。回答类似“为什么我的程序将函数调用记录到控制台？”这样的问题可能会变得更加困难！然而，这种语法只能应用于我们定义的函数，因为我们无法访问其他模块的源代码。如果我们需要装饰第三方库中的函数，我们必须使用之前的语法。

装饰器语法比我们在这里看到的要复杂得多。我们没有空间在这里涵盖高级主题，所以请查看 Python 参考手册或其他教程获取更多信息。装饰器可以被创建为可调用对象，而不仅仅是返回函数的函数。类也可以被装饰；在这种情况下，装饰器返回一个新类，而不是一个新函数。最后，装饰器可以接受参数，以便根据每个函数的情况进行自定义。

# 观察者模式

观察者模式对于状态监控和事件处理情况非常有用。这种模式允许一个给定的对象被一个未知和动态的“观察者”对象组监视。

每当核心对象上的值发生变化时，它都会通过调用`update()`方法来通知所有观察者对象发生了变化。每个观察者在核心对象发生变化时可能负责不同的任务；核心对象不知道或不关心这些任务是什么，观察者通常也不知道或不关心其他观察者在做什么。

这里是 UML：

![观察者模式](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py3-oop-2e/img/8781OS_10_02.jpg)

## 一个观察者示例

观察者模式可能在冗余备份系统中很有用。我们可以编写一个维护特定值的核心对象，然后让一个或多个观察者创建该对象的序列化副本。这些副本可以存储在数据库中，远程主机上，或者本地文件中。让我们使用属性来实现核心对象：

```py
class Inventory:
    def __init__(self):
        self.observers = []
        self._product = None
        self._quantity = 0

    def attach(self, observer):
        self.observers.append(observer)

    @property
    def product(self):
        return self._product
    @product.setter
    def product(self, value):
        self._product = value
        self._update_observers()

    @property
    def quantity(self):
        return self._quantity
    @quantity.setter
    def quantity(self, value):
        self._quantity = value
        self._update_observers()

    def _update_observers(self):
        for observer in self.observers:
            observer()
```

这个对象有两个属性，当设置时，会在自身上调用`_update_observers`方法。这个方法只是循环遍历可用的观察者，并让每个观察者知道发生了一些变化。在这种情况下，我们直接调用观察者对象；对象将必须实现`__call__`来处理更新。在许多面向对象的编程语言中，这是不可能的，但在 Python 中这是一个有用的快捷方式，可以帮助我们的代码更易读。

现在让我们实现一个简单的观察者对象；这个对象只会将一些状态打印到控制台上：

```py
class ConsoleObserver:
    def __init__(self, inventory):
        self.inventory = inventory

 **def __call__(self):
        print(self.inventory.product)
        print(self.inventory.quantity)
```

这里没有什么特别激动人心的；观察对象在初始化程序中设置，当观察者被调用时，我们会“做一些事情”。我们可以在交互式控制台中测试观察者：

```py
>>> i = Inventory()
>>> c = ConsoleObserver(i)
>>> i.attach(c)
>>> i.product = "Widget"
Widget
0
>>> i.quantity = 5
Widget
5

```

将观察者附加到库存对象后，每当我们更改两个观察属性中的一个时，观察者都会被调用并调用其动作。我们甚至可以添加两个不同的观察者实例：

```py
>>> i = Inventory()
>>> c1 = ConsoleObserver(i)
>>> c2 = ConsoleObserver(i)
>>> i.attach(c1)
>>> i.attach(c2)
>>> i.product = "Gadget"
Gadget
0
Gadget
0

```

这次当我们更改产品时，有两组输出，每个观察者一个。这里的关键思想是我们可以轻松地添加完全不同类型的观察者，同时备份数据到文件、数据库或 Internet 应用程序。

观察者模式将被观察的代码与观察的代码分离。如果我们不使用这种模式，我们将不得不在每个属性中放置代码来处理可能出现的不同情况；记录到控制台，更新数据库或文件等。所有这些任务的代码都将混在观察对象中。维护它将是一场噩梦，并且在以后的日期添加新的监视功能将是痛苦的。

# 策略模式

策略模式是面向对象编程中抽象的常见演示。该模式在不同对象中实现了单个问题的不同解决方案。客户端代码可以在运行时动态选择最合适的实现。

通常，不同的算法有不同的权衡；一个可能比另一个更快，但使用的内存更多，而第三个算法可能在多个 CPU 存在或提供分布式系统时最合适。这是 UML 中的策略模式：

![策略模式](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py3-oop-2e/img/8781OS_10_03.jpg)

连接到策略模式的**用户**代码只需要知道它正在处理**抽象**接口。所选择的实际实现以不同的方式执行相同的任务；无论如何，接口都是相同的。

## 策略示例

策略模式的典型示例是排序例程；多年来，已经发明了许多用于对对象集合进行排序的算法；快速排序、合并排序和堆排序都是具有不同特性的快速排序算法，每种算法在不同情况下都有用，具体取决于输入的大小和类型，它们的顺序有多乱，以及系统的要求。

如果我们有需要对集合进行排序的客户端代码，我们可以将其传递给具有`sort()`方法的对象。该对象可以是`QuickSorter`或`MergeSorter`对象，但无论哪种情况，结果都将是相同的：排序后的列表。用于排序的策略从调用代码中抽象出来，使其模块化和可替换。

当然，在 Python 中，我们通常只调用`sorted`函数或`list.sort`方法，并相信它会以接近最佳的方式进行排序。因此，我们确实需要看一个更好的例子。

让我们考虑一个桌面壁纸管理器。当图像显示在桌面背景上时，可以以不同的方式调整到屏幕大小。例如，假设图像小于屏幕，则可以在屏幕上平铺，居中显示，或者缩放以适应。还有其他更复杂的策略可以使用，例如缩放到最大高度或宽度，与纯色、半透明或渐变背景颜色结合，或其他操作。虽然我们可能希望稍后添加这些策略，但让我们从基本策略开始。

我们的策略对象需要两个输入；要显示的图像和屏幕宽度和高度的元组。它们各自返回一个新的图像，大小与屏幕相同，并根据给定的策略进行调整。您需要使用`pip3 install pillow`安装`pillow`模块，以使此示例工作。

```py
from PIL import Image

class TiledStrategy:
    def make_background(self, img_file, desktop_size):
        in_img = Image.open(img_file)
        out_img = Image.new('RGB', desktop_size)
        num_tiles = [
            o // i + 1 for o, i in
            zip(out_img.size, in_img.size)
        ]
        for x in range(num_tiles[0]):
            for y in range(num_tiles[1]):
                out_img.paste(
                    in_img,
                    (
                        in_img.size[0] * x,
                        in_img.size[1] * y,
                        in_img.size[0] * (x+1),
                        in_img.size[1] * (y+1)
                    )
                )
        return out_img

class CenteredStrategy:
    def make_background(self, img_file, desktop_size):
        in_img = Image.open(img_file)
        out_img = Image.new('RGB', desktop_size)
        left = (out_img.size[0] - in_img.size[0]) // 2
        top = (out_img.size[1] - in_img.size[1]) // 2
        out_img.paste(
            in_img,
            (
                left,
                top,
                left+in_img.size[0],
                top + in_img.size[1]
            )
        )
        return out_img

class ScaledStrategy:
    def make_background(self, img_file, desktop_size):
        in_img = Image.open(img_file)
        out_img = in_img.resize(desktop_size)
        return out_img
```

这里我们有三种策略，每种策略都使用`PIL`来执行它们的任务。各个策略都有一个`make_background`方法，接受相同的参数集。一旦选择了适当的策略，就可以调用它来创建一个正确大小的桌面图像版本。`TiledStrategy`循环遍历可以适应图像宽度和高度的输入图像数量，并将其重复复制到每个位置。`CenteredStrategy`计算出需要在图像的四个边缘留下多少空间来使其居中。`ScaledStrategy`强制图像到输出大小（忽略纵横比）。

考虑如果没有策略模式，如何在这些选项之间进行切换。我们需要把所有的代码放在一个很大的方法中，并使用一个笨拙的`if`语句来选择预期的选项。每次我们想要添加一个新的策略，我们都需要使方法变得更加笨拙。

## Python 中的策略

策略模式的前面的经典实现，在大多数面向对象的库中非常常见，但在 Python 编程中很少见。

这些类分别代表什么都不做，只提供一个函数的对象。我们可以轻松地称这个函数为`__call__`，并直接使对象可调用。由于没有与对象关联的其他数据，我们只需要创建一组顶级函数，并将它们作为我们的策略传递。

因此，设计模式哲学的反对者会说，“因为 Python 有一流函数，策略模式是不必要的”。事实上，Python 的一流函数允许我们以更直接的方式实现策略模式。知道模式存在仍然可以帮助我们选择程序的正确设计，但使用更可读的语法来实现它。策略模式，或者它的顶级函数实现，应该在我们需要允许客户端代码或最终用户从同一接口的多个实现中进行选择时使用。

# 状态模式

状态模式在结构上类似于策略模式，但其意图和目的是非常不同的。状态模式的目标是表示状态转换系统：在这些系统中，一个对象可以处于特定状态，某些活动可能会驱使它转移到不同的状态。

为了使这个工作起来，我们需要一个管理者，或者提供切换状态接口的上下文类。在内部，这个类包含一个指向当前状态的指针；每个状态都知道它被允许处于哪些其他状态，并且会根据在其上调用的动作来过渡到这些状态。

因此，我们有两种类型的类，上下文类和多个状态类。上下文类维护当前状态，并将动作转发给状态类。状态类通常对于调用上下文的任何其他对象都是隐藏的；它就像一个黑匣子，偶然会在内部执行状态管理。在 UML 中它是这样的。

![状态模式](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py3-oop-2e/img/8781OS_10_04.jpg)

## 状态示例

为了说明状态模式，让我们构建一个 XML 解析工具。上下文类将是解析器本身。它将以字符串作为输入，并将工具放在初始解析状态中。各种解析状态将吃掉字符，寻找特定的值，当找到该值时，转换到不同的状态。目标是为每个标签及其内容创建一个节点对象树。为了保持事情可管理，我们只解析 XML 的一个子集 - 标签和标签名称。我们将无法处理标签上的属性。它将解析标签的文本内容，但不会尝试解析“混合”内容，其中包含文本内的标签。这是一个我们将能够解析的“简化 XML”文件的例子：

```py
<book>
    <author>Dusty Phillips</author>
    <publisher>Packt Publishing</publisher>
    <title>Python 3 Object Oriented Programming</title>
    <content>
        <chapter>
            <number>1</number>
            <title>Object Oriented Design</title>
        </chapter>
        <chapter>
            <number>2</number>
            <title>Objects In Python</title>
        </chapter>
    </content>
</book>
```

在查看状态和解析器之前，让我们考虑一下这个程序的输出。我们知道我们想要一个`Node`对象的树，但`Node`是什么样子呢？显然，它需要知道它正在解析的标签的名称，并且由于它是一棵树，它可能需要维护指向父节点的指针和按顺序排列的节点子节点列表。有些节点有文本值，但不是所有节点都有。让我们先看看这个`Node`类：

```py
class Node:
    def __init__(self, tag_name, parent=None):
        self.parent = parent
        self.tag_name = tag_name
        self.children = []
        self.text=""

    def __str__(self):
        if self.text:
            return self.tag_name + ": " + self.text
        else:
            return self.tag_name
```

这个类在初始化时设置默认属性值。提供`__str__`方法来帮助可视化树结构完成时的情况。

现在，看看示例文档，我们需要考虑解析器可能处于哪些状态。显然，它将从尚未处理任何节点的状态开始。我们需要一个状态来处理开放标签和关闭标签。当我们在具有文本内容的标签内部时，我们还需要将其处理为单独的状态。

状态切换可能会很棘手；我们如何知道下一个节点是开放标签、关闭标签还是文本节点？我们可以在每个状态中放入一些逻辑来解决这个问题，但实际上创建一个新状态来唯一目的是确定下一个要切换到的状态更有意义。如果我们将这个过渡状态称为**ChildNode**，我们最终得到以下状态：

+   **FirstTag**

+   **ChildNode**

+   **OpenTag**

+   **CloseTag**

+   **Text**

**FirstTag**状态将切换到**ChildNode**，负责决定切换到其他三个状态中的哪一个；当这些状态完成时，它们将切换回**ChildNode**。以下状态转换图显示了可用的状态更改：

![状态示例](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py3-oop-2e/img/8781OS_10_05.jpg)

状态负责获取“字符串的剩余部分”，处理它们所知道的部分，然后告诉解析器处理剩下的部分。现在，首先构造`Parser`类：

```py
class Parser:
    def __init__(self, parse_string):
        self.parse_string = parse_string
        self.root = None
        self.current_node = None

        self.state = FirstTag()

    def process(self, remaining_string):
        remaining = self.state.process(remaining_string, self)
        if remaining:
            self.process(remaining)

    def start(self):
        self.process(self.parse_string)
```

初始化程序在类上设置了一些变量，个别状态将访问这些变量。`parse_string`实例变量是我们试图解析的文本。`root`节点是 XML 结构中的“顶部”节点。`current_node`实例变量是我们当前正在向其添加子节点的变量。

这个解析器的重要特性是`process`方法，它接受剩余的字符串，并将其传递给当前状态。解析器（`self`参数）也被传递到状态的`process`方法中，以便状态可以操作它。状态预计在完成处理时返回未解析字符串的剩余部分。然后解析器递归调用这个剩余字符串上的`process`方法来构造树的其余部分。

现在，让我们来看看`FirstTag`状态：

```py
class FirstTag:
    def process(self, remaining_string, parser):
        i_start_tag = remaining_string.find('<')
        i_end_tag = remaining_string.find('>')
        tag_name = remaining_string[i_start_tag+1:i_end_tag]
        root = Node(tag_name)
        parser.root = parser.current_node = root
 **parser.state = ChildNode()
        **return remaining_string[i_end_tag+1:]

```

这个状态找到第一个标签的开放和关闭尖括号的索引（`i_`代表索引）。您可能认为这个状态是不必要的，因为 XML 要求在开放标签之前没有文本。但是，可能需要消耗空白字符；这就是为什么我们搜索开放尖括号而不是假设它是文档中的第一个字符。请注意，此代码假定输入文件有效。正确的实现将严格测试无效输入，并尝试恢复或显示极具描述性的错误消息。

该方法提取标签的名称并将其分配给解析器的根节点。它还将其分配给`current_node`，因为接下来我们将向其添加子节点。

然后是重要的部分：该方法将解析器对象上的当前状态更改为`ChildNode`状态。然后返回字符串的剩余部分（在开放标签之后）以便进行处理。

`ChildNode`状态，看起来相当复杂，结果却只需要一个简单的条件：

```py
class ChildNode:
    def process(self, remaining_string, parser):
        stripped = remaining_string.strip()
        if stripped.startswith("</"):
            parser.state = CloseTag()
        elif stripped.startswith("<"):
            parser.state = OpenTag()
        else:
            parser.state = TextNode()
        return stripped
```

“strip（）”调用从字符串中删除空格。然后解析器确定下一个项是开放标签、关闭标签还是文本字符串。根据发生的可能性，它将解析器设置为特定状态，然后告诉它解析字符串的其余部分。

`OpenTag`状态类似于`FirstTag`状态，只是它将新创建的节点添加到先前的`current_node`对象的`children`中，并将其设置为新的`current_node`。然后在继续之前将处理器放回`ChildNode`状态：

```py
class OpenTag:
    def process(self, remaining_string, parser):
        i_start_tag = remaining_string.find('<')
        i_end_tag = remaining_string.find('>')
        tag_name = remaining_string[i_start_tag+1:i_end_tag]
        node = Node(tag_name, parser.current_node)
        parser.current_node.children.append(node)
        parser.current_node = node
        parser.state = ChildNode()
        return remaining_string[i_end_tag+1:]
```

`CloseTag`状态基本上做相反的事情；它将解析器的`current_node`设置回父节点，以便可以将外部标签中的任何进一步的子节点添加到其中：

```py
class CloseTag:
    def process(self, remaining_string, parser):
        i_start_tag = remaining_string.find('<')
        i_end_tag = remaining_string.find('>')
        assert remaining_string[i_start_tag+1] == "/"
        tag_name = remaining_string[i_start_tag+2:i_end_tag]
        assert tag_name == parser.current_node.tag_name
        parser.current_node = parser.current_node.parent
        parser.state = ChildNode()
        return remaining_string[i_end_tag+1:].strip()
```

两个`assert`语句有助于确保解析字符串一致。方法末尾的`if`语句确保处理器在完成时终止。如果节点的父节点是`None`，则意味着我们正在处理根节点。

最后，`TextNode`状态非常简单地提取下一个关闭标签之前的文本，并将其设置为当前节点的值：

```py
class TextNode:
    def process(self, remaining_string, parser):
        i_start_tag = remaining_string.find('<')
        text = remaining_string[:i_start_tag]
        parser.current_node.text = text
        parser.state = ChildNode()
        return remaining_string[i_start_tag:]
```

现在我们只需在我们创建的解析器对象上设置初始状态。初始状态是一个`FirstTag`对象，所以只需将以下内容添加到`__init__`方法中：

```py
        self.state = FirstTag()
```

为了测试这个类，让我们添加一个主脚本，从命令行打开一个文件，解析它，并打印节点：

```py
if __name__ == "__main__":
    import sys
    with open(sys.argv[1]) as file:
        contents = file.read()
        p = Parser(contents)
        p.start()

        nodes = [p.root]
        while nodes:
            node = nodes.pop(0)
            print(node)
            nodes = node.children + nodes
```

这段代码打开文件，加载内容，并解析结果。然后按顺序打印每个节点及其子节点。我们最初在节点类上添加的`__str__`方法负责格式化节点以进行打印。如果我们在之前的示例上运行脚本，它将输出树如下：

```py
book
author: Dusty Phillips
publisher: Packt Publishing
title: Python 3 Object Oriented Programming
content
chapter
number: 1
title: Object Oriented Design
chapter
number: 2
title: Objects In Python

```

将此与原始简化的 XML 文档进行比较告诉我们解析器正在工作。

## 状态与策略

状态模式看起来与策略模式非常相似；实际上，两者的 UML 图是相同的。实现也是相同的；我们甚至可以将我们的状态编写为一等函数，而不是将它们包装在对象中，就像策略建议的那样。

虽然这两种模式具有相同的结构，但它们解决的问题完全不同。策略模式用于在运行时选择算法；通常，针对特定用例只会选择其中一个算法。另一方面，状态模式旨在允许在某些过程发展时动态地在不同状态之间切换。在代码中，主要区别在于策略模式通常不知道其他策略对象。在状态模式中，状态或上下文需要知道它可以切换到哪些其他状态。

## 状态转换作为协程

状态模式是面向对象的标准解决方案，用于状态转换问题。但是，这种模式的语法相当冗长。通过构造对象为协程，您可以获得类似的效果。还记得我们在第九章中构建的正则表达式日志文件解析器吗？那是一个伪装的状态转换问题。该实现与定义状态模式中使用的所有对象（或函数）的实现之间的主要区别在于，协程解决方案允许我们将更多的样板代码编码为语言结构。有两种实现，但没有一种本质上比另一种更好，但您可能会发现协程更易读，根据“易读”的定义（首先您必须了解协程的语法！）。

# 单例模式

单例模式是最具争议的模式之一；许多人指责它是一种“反模式”，一种应该避免而不是推广的模式。在 Python 中，如果有人使用单例模式，几乎可以肯定他们做错了什么，可能是因为他们来自更严格的编程语言。

那么为什么要讨论它呢？单例是所有设计模式中最著名的之一。它在过度面向对象的语言中很有用，并且是传统面向对象编程的重要部分。更相关的是，单例背后的思想是有用的，即使我们在 Python 中以完全不同的方式实现了这个思想。

单例模式背后的基本思想是允许某个对象的确切一个实例存在。通常，这个对象是一种类似于我们在第五章中讨论的管理类，*何时使用面向对象编程*。这些对象通常需要被各种其他对象引用，并且将对管理对象的引用传递给需要它们的方法和构造函数可能会使代码难以阅读。

相反，当使用单例时，单独的对象从类中请求管理对象的单个实例，因此无需传递对它的引用。UML 图表并未完全描述它，但为了完整起见，这里是：

![单例模式](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py3-oop-2e/img/8781OS_10_06.jpg)

在大多数编程环境中，通过使构造函数私有（以便没有人可以创建它的其他实例），然后提供一个静态方法来检索单个实例来强制实施单例。该方法在第一次调用时创建一个新实例，然后在每次再次调用时返回相同的实例。

## 单例实现

Python 没有私有构造函数，但为此，它有更好的东西。我们可以使用`__new__`类方法来确保只创建一个实例：

```py
class OneOnly:
    _singleton = None
    def __new__(cls, *args, **kwargs):
        if not cls._singleton:
            cls._singleton = super(OneOnly, cls
                ).__new__(cls, *args, **kwargs)
        return cls._singleton
```

当调用`__new__`时，通常会构造该类的新实例。当我们重写它时，我们首先检查我们的单例实例是否已创建；如果没有，我们使用`super`调用来创建它。因此，无论何时我们在`OneOnly`上调用构造函数，我们总是得到完全相同的实例：

```py
>>> o1 = OneOnly()
>>> o2 = OneOnly()
>>> o1 == o2
True
>>> o1
<__main__.OneOnly object at 0xb71c008c>
>>> o2
<__main__.OneOnly object at 0xb71c008c>

```

这两个对象是相等的，并且位于相同的地址；因此，它们是同一个对象。这种特定的实现并不是非常透明，因为不明显地创建了一个单例对象。每当我们调用构造函数时，我们期望得到该对象的一个新实例；在这种情况下，这个约定被违反了。也许，如果我们真的认为需要一个单例，类上的良好文档字符串可以缓解这个问题。

但我们并不需要它。Python 程序员不喜欢强迫他们的代码使用者进入特定的思维方式。我们可能认为一个类只需要一个实例，但其他程序员可能有不同的想法。单例可能会干扰分布式计算、并行编程和自动化测试，例如。在所有这些情况下，拥有特定对象的多个或替代实例可能非常有用，即使“正常”操作可能永远不需要一个。

模块变量可以模拟单例

通常，在 Python 中，可以使用模块级变量来充分模拟单例模式。它不像单例那样“安全”，因为人们随时可以重新分配这些变量，但与我们在第二章中讨论的私有变量一样，在 Python 中是可以接受的。如果有人有正当理由更改这些变量，我们为什么要阻止他们呢？它也不会阻止人们实例化对象的多个实例，但同样，如果他们有正当理由这样做，为什么要干涉呢？

理想情况下，我们应该为它们提供一种机制来访问“默认单例”值，同时也允许它们在需要时创建其他实例。虽然从技术上讲根本不是单例，但它提供了最符合 Python 风格的单例行为机制。

使用模块级变量而不是单例，我们在定义类之后实例化类的实例。我们可以改进我们的状态模式以使用单例。我们可以创建一个模块级变量，而不是在每次改变状态时创建一个新对象，这样始终可以访问该变量：

```py
class FirstTag:
    def process(self, remaining_string, parser):
        i_start_tag = remaining_string.find('<')
        i_end_tag = remaining_string.find('>')
        tag_name = remaining_string[i_start_tag+1:i_end_tag]
        root = Node(tag_name)
        parser.root = parser.current_node = root
 **parser.state = child_node
        return remaining_string[i_end_tag+1:]

class ChildNode:
    def process(self, remaining_string, parser):
        stripped = remaining_string.strip()
        if stripped.startswith("</"):
 **parser.state = close_tag
        elif stripped.startswith("<"):
 **parser.state = open_tag
        else:
 **parser.state = text_node
        return stripped

class OpenTag:
    def process(self, remaining_string, parser):
        i_start_tag = remaining_string.find('<')
        i_end_tag = remaining_string.find('>')
        tag_name = remaining_string[i_start_tag+1:i_end_tag]
        node = Node(tag_name, parser.current_node)
        parser.current_node.children.append(node)
        parser.current_node = node
 **parser.state = child_node
        return remaining_string[i_end_tag+1:]
class TextNode:
    def process(self, remaining_string, parser):
        i_start_tag = remaining_string.find('<')
        text = remaining_string[:i_start_tag]
        parser.current_node.text = text
 **parser.state = child_node
        return remaining_string[i_start_tag:]

class CloseTag:
    def process(self, remaining_string, parser):
        i_start_tag = remaining_string.find('<')
        i_end_tag = remaining_string.find('>')
        assert remaining_string[i_start_tag+1] == "/"
        tag_name = remaining_string[i_start_tag+2:i_end_tag]
        assert tag_name == parser.current_node.tag_name
        parser.current_node = parser.current_node.parent
 **parser.state = child_node
        return remaining_string[i_end_tag+1:].strip()

first_tag = FirstTag()
child_node = ChildNode()
text_node = TextNode()
open_tag = OpenTag()
close_tag = CloseTag()

```

我们所做的只是创建可以重复使用的各种状态类的实例。请注意，即使在定义变量之前，我们也可以在类内部访问这些模块变量？这是因为类内部的代码直到调用方法时才会执行，到这个时候整个模块都将被定义。

这个例子的不同之处在于，我们不是浪费内存创建必须进行垃圾回收的大量新实例，而是为每个状态重用单个状态对象。即使同时运行多个解析器，也只需要使用这些状态类。

当我们最初创建基于状态的解析器时，您可能会想知道为什么我们没有将解析器对象传递给每个单独的状态的`__init__`，而是像我们所做的那样将其传递给 process 方法。然后状态可以被引用为`self.parser`。这是状态模式的一个完全有效的实现，但它不允许利用单例模式。如果状态对象保持对解析器的引用，那么它们就不能同时用于引用其他解析器。

### 提示

请记住，这是两种不同目的的模式；单例模式的目的可能有助于实现状态模式，但这并不意味着这两种模式有关联。

# 模板模式

模板模式对于消除重复代码很有用；它是支持我们在第五章中讨论的**不要重复自己**原则的实现，*何时使用面向对象编程*。它设计用于在需要完成一些具有部分但不完全相同步骤的几个不同任务的情况下。通用步骤在基类中实现，不同的步骤在子类中被覆盖以提供自定义行为。在某种程度上，它类似于广义策略模式，只是使用基类共享算法的相似部分。以下是它的 UML 格式：

![模板模式](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py3-oop-2e/img/8781OS_10_07.jpg)

## 模板示例

让我们以创建一个汽车销售报告为例。我们可以在 SQLite 数据库表中存储销售记录。SQLite 是一个简单的基于文件的数据库引擎，允许我们使用 SQL 语法存储记录。Python 3 在其标准库中包含了 SQLite，因此不需要额外的模块。

我们有两个需要执行的常见任务：

+   选择所有新车销售并以逗号分隔的格式将其输出到屏幕上

+   输出所有销售人员及其总销售额的逗号分隔列表，并将其保存到可以导入电子表格的文件中

这些似乎是非常不同的任务，但它们有一些共同的特点。在这两种情况下，我们都需要执行以下步骤：

1.  连接到数据库。

1.  构建一个查询以获取新车辆或总销售额。

1.  发出查询。

1.  将结果格式化为逗号分隔的字符串。

1.  将数据输出到文件或电子邮件。

这两个任务的查询构建和输出步骤不同，但其余步骤相同。我们可以使用模板模式将通用步骤放入基类中，将不同的步骤放入两个子类中。

在开始之前，让我们创建一个数据库并使用几行 SQL 将一些示例数据放入其中：

```py
import sqlite3

conn = sqlite3.connect("sales.db")

conn.execute("CREATE TABLE Sales (salesperson text, "
        "amt currency, year integer, model text, new boolean)")
conn.execute("INSERT INTO Sales values"
        " ('Tim', 16000, 2010, 'Honda Fit', 'true')")
conn.execute("INSERT INTO Sales values"
        " ('Tim', 9000, 2006, 'Ford Focus', 'false')")
conn.execute("INSERT INTO Sales values"
        " ('Gayle', 8000, 2004, 'Dodge Neon', 'false')")
conn.execute("INSERT INTO Sales values"
        " ('Gayle', 28000, 2009, 'Ford Mustang', 'true')")
conn.execute("INSERT INTO Sales values"
        " ('Gayle', 50000, 2010, 'Lincoln Navigator', 'true')")
conn.execute("INSERT INTO Sales values"
        " ('Don', 20000, 2008, 'Toyota Prius', 'false')")
conn.commit()
conn.close()
```

希望即使您不懂 SQL，也能看出这里发生了什么；我们创建了一个表来保存数据，并使用六个插入语句添加了销售记录。数据存储在名为`sales.db`的文件中。现在我们有一个示例可以用来开发我们的模板模式。

由于我们已经概述了模板必须执行的步骤，我们可以从定义包含这些步骤的基类开始。每个步骤都有自己的方法（以便轻松地选择性地覆盖任何一个步骤），并且我们还有一个管理方法，依次调用这些步骤。没有任何方法内容，它可能看起来像这样：

```py
class QueryTemplate:
    def connect(self):
        pass
    def construct_query(self):
        pass
    def do_query(self):
        pass
    def format_results(self):
        pass
    def output_results(self):
        pass

 **def process_format(self):
        self.connect()
        self.construct_query()
        self.do_query()
        self.format_results()
        self.output_results()
```

`process_format`方法是外部客户端要调用的主要方法。它确保每个步骤按顺序执行，但它不在乎该步骤是在这个类中实现还是在子类中实现。对于我们的例子，我们知道两个类之间的三个方法将是相同的：

```py
import sqlite3

class QueryTemplate:
    def connect(self):
 **self.conn = sqlite3.connect("sales.db")

    def construct_query(self):
 **raise NotImplementedError()

    def do_query(self):
 **results = self.conn.execute(self.query)
 **self.results = results.fetchall()

    def format_results(self):
 **output = []
 **for row in self.results:
 **row =[str(i) for i in row]
 **output.append(", ".join(row))
 **self.formatted_results = "\n".join(output)

    def output_results(self):
 **raise NotImplementedError()

```

为了帮助实现子类，两个未指定的方法会引发`NotImplementedError`。这是在 Python 中指定抽象接口的常见方式，当抽象基类看起来太笨重时。这些方法可以有空实现（使用`pass`），或者可以完全未指定。然而，引发`NotImplementedError`有助于程序员理解该类是要被子类化并且这些方法被重写；空方法或不存在的方法更难以识别需要被实现并且如果我们忘记实现它们时调试。

现在我们有一个模板类，它处理了乏味的细节，但足够灵活，可以执行和格式化各种查询。最好的部分是，如果我们想要将数据库引擎从 SQLite 更改为另一个数据库引擎（例如 py-postgresql），我们只需要在这里，在这个模板类中做，而不必触及我们可能编写的两个（或两百个）子类。

现在让我们来看看具体的类：

```py
import datetime
class NewVehiclesQuery(QueryTemplate):
 **def construct_query(self):
        self.query = "select * from Sales where new='true'"

 **def output_results(self):
        print(self.formatted_results)

class UserGrossQuery(QueryTemplate):
 **def construct_query(self):
        self.query = ("select salesperson, sum(amt) " +
        " from Sales group by salesperson")

 **def output_results(self):
        filename = "gross_sales_{0}".format(
                datetime.date.today().strftime("%Y%m%d")
                )
        with open(filename, 'w') as outfile:
            outfile.write(self.formatted_results)
```

这两个类实际上相当简短，考虑到它们的功能：连接到数据库，执行查询，格式化结果并输出它们。超类处理了重复的工作，但让我们轻松地指定那些在任务之间变化的步骤。此外，我们还可以轻松地更改在基类中提供的步骤。例如，如果我们想要输出除逗号分隔字符串之外的其他内容（例如：要上传到网站的 HTML 报告），我们仍然可以重写`format_results`。

# 练习

在撰写本章时，我发现很难，但也非常有教育意义，找到应该使用特定设计模式的好例子。与其像我在之前的章节中建议的那样检查当前或旧项目以查看可以应用这些模式的地方，不如考虑这些模式和可能出现的不同情况。尝试超越自己的经验。如果你当前的项目是银行业务，考虑在零售或销售点应用这些设计模式。如果你通常编写 Web 应用程序，考虑在编写编译器时使用设计模式。

看看装饰器模式，并想出一些适用它的好例子。专注于模式本身，而不是我们讨论的 Python 语法；它比实际模式更一般。然而，装饰器的特殊语法是你可能想要寻找现有项目中适用的地方。

使用观察者模式的一些好领域是什么？为什么？不仅考虑如何应用模式，还要考虑如何在不使用观察者的情况下实现相同的任务？选择使用它会得到什么，或失去什么？

考虑策略模式和状态模式之间的区别。在实现上，它们看起来非常相似，但它们有不同的目的。你能想到模式可以互换的情况吗？重新设计一个基于状态的系统以使用策略，或者反之亦然，是否合理？设计实际上会有多大的不同？

模板模式是继承的明显应用，可以减少重复的代码，你可能以前就使用过它，只是不知道它的名字。试着想出至少半打不同的场景，它在这些场景中会有用。如果你能做到这一点，你将会在日常编码中经常找到它的用武之地。

# 摘要

本章详细讨论了几种常见的设计模式，包括示例、UML 图和 Python 与静态类型面向对象语言之间的差异讨论。装饰器模式通常使用 Python 更通用的装饰器语法来实现。观察者模式是一种有用的方式，可以将事件与对这些事件采取的行动分离开来。策略模式允许选择不同的算法来完成相同的任务。状态模式看起来类似，但实际上是用来表示系统可以使用明确定义的操作在不同状态之间移动。单例模式在一些静态类型语言中很受欢迎，但在 Python 中几乎总是反模式。

在下一章中，我们将结束对设计模式的讨论。


# 第十一章：Python 设计模式 II

在本章中，我们将介绍几种设计模式。我们将再次介绍经典的示例以及 Python 中的任何常见替代实现。我们将讨论：

+   适配器模式

+   外观模式

+   延迟初始化和享元模式

+   命令模式

+   抽象工厂模式

+   组合模式

# 适配器模式

与我们在第八章中审查的大多数模式不同，*字符串和序列化*，适配器模式旨在与现有代码交互。我们不会设计一个全新的实现适配器模式的对象集。适配器用于允许两个现有对象一起工作，即使它们的接口不兼容。就像显示适配器允许 VGA 投影仪插入 HDMI 端口一样，适配器对象位于两个不同接口之间，实时进行翻译。适配器对象的唯一目的是执行这项翻译工作。适应可能涉及各种任务，例如将参数转换为不同的格式，重新排列参数的顺序，调用不同命名的方法或提供默认参数。

在结构上，适配器模式类似于简化的装饰器模式。装饰器通常提供与它们替代的相同接口，而适配器在两个不同的接口之间进行映射。这是它的 UML 形式：

![适配器模式](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py3-oop-2e/img/8781OS_11_01.jpg)

在这里，**Interface1**期望调用名为**make_action(some, arguments)**的方法。我们已经有了完美的**Interface2**类，它做了我们想要的一切（为了避免重复，我们不想重写它！），但它提供了一个名为**different_action(other, arguments)**的方法。**Adapter**类实现了**make_action**接口，并将参数映射到现有接口。

这里的优势在于，从一个接口到另一个接口的映射代码都在一个地方。另一种方法将非常丑陋；每当我们需要访问这段代码时，我们都必须在多个地方执行翻译。

例如，想象一下我们有以下现有类，它接受格式为“YYYY-MM-DD”的字符串日期并计算当天的人的年龄：

```py
class AgeCalculator:
    def __init__(self, birthday):
        self.year, self.month, self.day = (
                int(x) for x in birthday.split('-'))

    def calculate_age(self, date):
        year, month, day = (
                int(x) for x in date.split('-'))
        age = year - self.year
        if (month,day) < (self.month,self.day):
            age -= 1
        return age
```

这是一个非常简单的类，它做了它应该做的事情。但是我们不得不想一下程序员在想什么，使用一个特定格式的字符串，而不是使用 Python 非常有用的内置`datetime`库。作为一名负责任的程序员，我们尽可能地重用代码，我们编写的大多数程序将与`datetime`对象交互，而不是字符串。

我们有几种选择来解决这种情况；我们可以重写类以接受`datetime`对象，这可能更准确。但是，如果这个类是由第三方提供的，我们不知道或无法更改其内部结构，我们需要尝试其他方法。我们可以使用现有的类，每当我们想要计算`datetime.date`对象上的年龄时，我们可以调用`datetime.date.strftime('%Y-%m-%d')`将其转换为正确的格式。但是这种转换会发生在很多地方，更糟糕的是，如果我们将`%m`误写为`%M`，它将给出当前分钟而不是输入的月份！想象一下，如果你在十几个不同的地方写了这个，只有在意识到错误时才能回去更改它。这不是可维护的代码，它违反了 DRY 原则。

相反，我们可以编写一个适配器，允许将普通日期插入普通的`AgeCalculator`类中：

```py
import datetime
class DateAgeAdapter:
    def _str_date(self, date):
        return date.strftime("%Y-%m-%d")

    def __init__(self, birthday):
        birthday = self._str_date(birthday)
 **self.calculator = AgeCalculator(birthday)

    def get_age(self, date):
        date = self._str_date(date)
 **return self.calculator.calculate_age(date)

```

这个适配器将`datetime.date`和`datetime.time`（它们对`strftime`有相同的接口）转换为我们原始的`AgeCalculator`可以使用的字符串。现在我们可以使用原始代码来使用我们的新接口。我将方法签名更改为`get_age`，以演示调用接口可能也在寻找不同的方法名，而不仅仅是不同类型的参数。

创建一个类作为适配器是实现这种模式的常见方式，但通常情况下，在 Python 中还有其他方法可以实现。继承和多重继承可以用于向类添加功能。例如，我们可以在`date`类上添加一个适配器，以便它与原始的`AgeCalculator`类一起使用：

```py
import datetime
class AgeableDate(datetime.date):
    def split(self, char):
        return self.year, self.month, self.day
```

正是这样的代码让人怀疑 Python 是否应该合法。我们已经为我们的子类添加了一个`split`方法，它接受一个参数（我们忽略）并返回一个年、月和日的元组。这与原始的`AgeCalculator`类完美配合，因为代码在特殊格式的字符串上调用`strip`，而在这种情况下，`strip`返回一个年、月和日的元组。`AgeCalculator`代码只关心`strip`是否存在并返回可接受的值；它并不关心我们是否真的传入了一个字符串。它真的能工作：

```py
>>> bd = AgeableDate(1975, 6, 14)
>>> today = AgeableDate.today()
>>> today
AgeableDate(2015, 8, 4)
>>> a = AgeCalculator(bd)
>>> a.calculate_age(today)
40

```

它能工作，但这是一个愚蠢的想法。在这种特定情况下，这样的适配器很难维护。我们很快会忘记为什么需要向`date`类添加`strip`方法。方法名是模棱两可的。这可能是适配器的性质，但显式创建适配器而不是使用继承通常可以澄清其目的。

有时候，我们可以使用猴子补丁来给现有的类添加方法，而不是继承。它不适用于`datetime`对象，因为它不允许在运行时添加属性，但在普通类中，我们可以添加一个新方法，以提供调用代码所需的适应接口。或者，我们可以扩展或猴子补丁`AgeCalculator`本身，以用更适合我们需求的方法替换`calculate_age`方法。

最后，通常可以将函数用作适配器；这显然不符合适配器模式的实际设计，但如果我们记得函数本质上是带有`__call__`方法的对象，它就成为一个明显的适配器适应。

# 外观模式

外观模式旨在为复杂的组件系统提供一个简单的接口。对于复杂的任务，我们可能需要直接与这些对象交互，但通常系统有一个“典型”的用法，这些复杂的交互并不是必要的。外观模式允许我们定义一个新对象，封装了系统的典型用法。每当我们想要访问常见功能时，我们可以使用单个对象的简化接口。如果项目的另一部分需要访问更复杂的功能，它仍然可以直接与系统交互。外观模式的 UML 图表实际上取决于子系统，但在模糊的方式下，它看起来像这样：

![外观模式](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py3-oop-2e/img/8781OS_11_02.jpg)

外观在许多方面类似于适配器。主要区别在于，外观试图从复杂的接口中抽象出一个简单的接口，而适配器只是试图将一个现有的接口映射到另一个接口。

让我们为一个电子邮件应用程序编写一个简单的外观。Python 中用于发送电子邮件的低级库，正如我们在第七章中看到的那样，*Python 面向对象的快捷方式*，非常复杂。用于接收消息的两个库甚至更糟。

有一个简单的类可以让我们发送单个电子邮件，并列出当前在 IMAP 或 POP3 连接中的收件箱中的电子邮件将是很好的。为了保持我们的示例简短，我们将坚持使用 IMAP 和 SMTP：两个完全不同的子系统，碰巧处理电子邮件。我们的外观只执行两项任务：向特定地址发送电子邮件，并在 IMAP 连接上检查收件箱。它对连接做了一些常见的假设，比如 SMTP 和 IMAP 的主机位于同一地址，它们的用户名和密码相同，并且它们使用标准端口。这涵盖了许多电子邮件服务器的情况，但如果程序员需要更多的灵活性，他们可以绕过外观直接访问这两个子系统。

该类使用电子邮件服务器的主机名、用户名和密码进行初始化：

```py
import smtplib
import imaplib

class EmailFacade:
    def __init__(self, host, username, password):
        self.host = host
        self.username = username
        self.password = password
```

`send_email`方法格式化电子邮件地址和消息，并使用`smtplib`发送它。这不是一个复杂的任务，但需要相当多的调整来将传递到外观中的“自然”输入参数转换为正确的格式，以使`smtplib`能够发送消息：

```py
    def send_email(self, to_email, subject, message):
        if not "@" in self.username:
            from_email = "{0}@{1}".format(
                    self.username, self.host)
        else:
            from_email = self.username
        message = ("From: {0}\r\n"
                "To: {1}\r\n"
                "Subject: {2}\r\n\r\n{3}").format(
                    from_email,
                    to_email,
                    subject,
                    message)

        smtp = smtplib.SMTP(self.host)
        smtp.login(self.username, self.password)
        smtp.sendmail(from_email, [to_email], message)
```

方法开头的`if`语句捕获了`username`是否是整个“from”电子邮件地址，还是`@`符号左侧的部分；不同的主机以不同的方式处理登录详细信息。

最后，获取当前收件箱中的消息的代码是一团糟；IMAP 协议过度设计，而`imaplib`标准库只是协议的薄层封装：

```py
    def get_inbox(self):
        mailbox = imaplib.IMAP4(self.host)
        mailbox.login(bytes(self.username, 'utf8'),
            bytes(self.password, 'utf8'))
        mailbox.select()
        x, data = mailbox.search(None, 'ALL')
        messages = []
        for num in data[0].split():
            x, message = mailbox.fetch(num, '(RFC822)')
            messages.append(message[0][1])
        return messages
```

现在，如果我们把所有这些加在一起，我们就有了一个简单的外观类，可以以相当简单的方式发送和接收消息，比直接与这些复杂的库进行交互要简单得多。

尽管在 Python 社区中很少被命名，但外观模式是 Python 生态系统的一个组成部分。因为 Python 强调语言的可读性，语言及其库倾向于为复杂的任务提供易于理解的接口。例如，`for`循环，`list`推导和生成器都是对更复杂的迭代器协议的外观。`defaultdict`实现是一个外观，它在字典中键不存在时抽象掉烦人的边缘情况。第三方的 requests 库是一个强大的外观，可以覆盖不太可读的 HTTP 请求库。

# 减少内存占用的设计模式

减少内存占用的设计模式是一种内存优化模式。初学者 Python 程序员往往忽视内存优化，认为内置的垃圾收集器会处理它们。这通常是可以接受的，但是在开发具有许多相关对象的较大应用程序时，关注内存问题可能会有巨大的回报。

减少内存占用的设计模式基本上确保共享状态的对象可以使用相同的内存来存储该共享状态。通常只有在程序表现出内存问题后才会实施它。在某些情况下，从一开始设计最佳配置可能是有意义的，但请记住，过早优化是创建一个过于复杂以至于无法维护的程序的最有效方式。

让我们来看看减少内存占用的设计模式的 UML 图：

![减少内存占用的设计模式](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py3-oop-2e/img/8781OS_11_03.jpg)

每个**享元**都没有特定的状态；每当它需要对**特定状态**执行操作时，该状态需要被调用代码传递给**享元**。传统上，返回享元的工厂是一个单独的对象；它的目的是为了根据标识该享元的键返回一个享元。它的工作方式类似于我们在第十章中讨论的单例模式，*Python 设计模式 I*；如果享元存在，我们返回它；否则，我们创建一个新的。在许多语言中，工厂被实现为`Flyweight`类本身上的静态方法，而不是作为一个单独的对象。

想象一下汽车销售的库存系统。每辆汽车都有一个特定的序列号和特定的颜色。但是关于那辆车的大部分细节对于特定车型的所有车辆来说都是相同的。例如，本田 Fit DX 车型是一辆几乎没有特色的车。LX 车型有空调、倾斜、巡航和电动窗户和锁。Sport 车型有时尚的轮毂、USB 充电器和扰流板。如果没有享元模式，每个单独的汽车对象都必须存储一个长长的列表，其中包含它拥有或不拥有的功能。考虑到本田一年销售的汽车数量，这将导致大量的内存浪费。使用享元模式，我们可以为与车型相关的功能列表拥有共享对象，然后简单地引用该车型，以及序列号和颜色，用于单独的车辆。在 Python 中，享元工厂通常使用那个奇怪的`__new__`构造函数来实现，类似于我们在单例模式中所做的。与单例模式不同，单例模式只需要返回类的一个实例，我们需要能够根据键返回不同的实例。我们可以将项目存储在字典中，并根据键查找它们。然而，这种解决方案存在问题，因为只要项目在字典中，它就会一直保留在内存中。如果我们卖完了 LX 车型的 Fit，那么 Fit 享元就不再需要了，但它仍然会留在字典中。当然，我们可以在卖车时清理它，但这不是垃圾收集器的作用吗？

我们可以利用 Python 的`weakref`模块来解决这个问题。这个模块提供了一个`WeakValueDictionary`对象，基本上允许我们在字典中存储项目，而垃圾收集器不会关心它们。如果一个值在一个弱引用字典中，并且在应用程序的任何其他地方都没有对该对象的其他引用（也就是说，我们卖完了 LX 车型），垃圾收集器最终会为我们清理它。

让我们首先为我们的汽车享元构建工厂：

```py
import weakref

class CarModel:
 **_models = weakref.WeakValueDictionary()

    def __new__(cls, model_name, *args, **kwargs):
 **model = cls._models.get(model_name)
        if not model:
            model = super().__new__(cls)
 **cls._models[model_name] = model

        return model
```

基本上，每当我们用给定的名称构造一个新的享元时，我们首先在弱引用字典中查找该名称；如果存在，我们返回该模型；如果不存在，我们创建一个新的。无论哪种方式，我们都知道`__init__`方法在每次调用时都会被调用，无论它是一个新的还是现有的对象。因此，我们的`__init__`方法可以看起来像这样：

```py
    def __init__(self, model_name, air=False, tilt=False,
            cruise_control=False, power_locks=False,
            alloy_wheels=False, usb_charger=False):
 **if not hasattr(self, "initted"):
            self.model_name = model_name
            self.air = air
            self.tilt = tilt
            self.cruise_control = cruise_control
            self.power_locks = power_locks
            self.alloy_wheels = alloy_wheels
            self.usb_charger = usb_charger
            self.initted=True
```

`if`语句确保我们只在第一次调用`__init__`时初始化对象。这意味着我们以后可以只用车型名称调用工厂，并得到相同的享元对象。然而，如果享元没有外部引用存在，它将被垃圾收集，我们必须小心不要意外地创建一个具有空值的新享元。

让我们为我们的享元添加一个方法，假设它查找特定车型的序列号，并确定它是否曾经参与过任何事故。这个方法需要访问汽车的序列号，这个序列号因汽车而异；它不能与享元一起存储。因此，这些数据必须由调用代码传递给方法：

```py
 **def check_serial(self, serial_number):
        print("Sorry, we are unable to check "
                "the serial number {0} on the {1} "
                "at this time".format(
                    serial_number, self.model_name))
```

我们可以定义一个存储额外信息的类，以及对享元的引用：

```py
class Car:
    def __init__(self, model, color, serial):
        self.model = model
        self.color = color
        self.serial = serial

    def check_serial(self):
        return self.model.check_serial(self.serial)
```

我们还可以跟踪可用模型以及停车场上的个别汽车：

```py
>>> dx = CarModel("FIT DX")
>>> lx = CarModel("FIT LX", air=True, cruise_control=True,
... power_locks=True, tilt=True)
>>> car1 = Car(dx, "blue", "12345")
>>> car2 = Car(dx, "black", "12346")
>>> car3 = Car(lx, "red", "12347")

```

现在，让我们演示弱引用的工作方式：

```py
>>> id(lx)
3071620300
>>> del lx
>>> del car3
>>> import gc
>>> gc.collect()
0
>>> lx = CarModel("FIT LX", air=True, cruise_control=True,
... power_locks=True, tilt=True)
>>> id(lx)
3071576140
>>> lx = CarModel("FIT LX")
>>> id(lx)
3071576140
>>> lx.air
True

```

`id`函数告诉我们对象的唯一标识符。当我们在删除对 LX 模型的所有引用并强制进行垃圾回收后第二次调用它时，我们看到 ID 已经改变了。`CarModel __new__`工厂字典中的值已被删除，并创建了一个新的值。然而，如果我们尝试构造第二个`CarModel`实例，它将返回相同的对象（ID 相同），即使我们在第二次调用中没有提供任何参数，`air`变量仍然设置为`True`。这意味着对象第二次没有被初始化，就像我们设计的那样。

显然，使用享元模式可能比只在单个汽车类上存储特性更复杂。我们何时应该选择使用它呢？享元模式旨在节省内存；如果我们有数十万个相似的对象，将相似的属性合并到享元中对内存消耗会产生巨大影响。通常，用于优化 CPU、内存或磁盘空间的编程解决方案会导致比未经优化的代码更复杂。因此，在决定代码可维护性和优化之间进行权衡时，重要的是要权衡权衡。在选择优化时，尽量使用享元等模式，以确保优化引入的复杂性局限于代码的单个（有良好文档记录的）部分。

# 命令模式

命令模式在必须执行的操作和在以后通常由对象调用这些操作之间增加了一层抽象。在命令模式中，客户端代码创建一个`Command`对象，可以在以后执行。这个对象知道一个接收者对象，在命令在其上执行时管理自己的内部状态。`Command`对象实现了一个特定的接口（通常有一个`execute`或`do_action`方法，并且还跟踪执行操作所需的任何参数。最后，一个或多个`Invoker`对象在正确的时间执行命令。

这是 UML 图：

![命令模式](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py3-oop-2e/img/8781OS_11_04.jpg)

命令模式的一个常见示例是在图形窗口上的操作。通常，一个操作可以通过菜单栏上的菜单项、键盘快捷键、工具栏图标或上下文菜单来调用。这些都是`Invoker`对象的示例。实际发生的操作，例如`Exit`、`Save`或`Copy`，是`CommandInterface`的实现。用于接收退出的 GUI 窗口，用于接收保存的文档，以及用于接收复制命令的`ClipboardManager`，都是可能的`Receivers`的示例。

让我们实现一个简单的命令模式，为`Save`和`Exit`操作提供命令。我们将从一些适度的接收者类开始：

```py
import sys

class Window:
    def exit(self):
        sys.exit(0)

class Document:
    def __init__(self, filename):
        self.filename = filename
        self.contents = "This file cannot be modified"

    def save(self):
        with open(self.filename, 'w') as file:
            file.write(self.contents)
```

这些模拟类模拟了在工作环境中可能会做更多事情的对象。窗口需要处理鼠标移动和键盘事件，文档需要处理字符插入、删除和选择。但是在我们的示例中，这两个类将做我们需要的事情。

现在让我们定义一些调用者类。这些将模拟可能发生的工具栏、菜单和键盘事件；再次强调，它们实际上并没有连接到任何东西，但我们可以看到它们与命令、接收者和客户端代码是解耦的：

```py
class ToolbarButton:
    def __init__(self, name, iconname):
        self.name = name
        self.iconname = iconname

    def click(self):
 **self.command.execute()

class MenuItem:
    def __init__(self, menu_name, menuitem_name):
        self.menu = menu_name
        self.item = menuitem_name

    def click(self):
 **self.command.execute()

class KeyboardShortcut:
    def __init__(self, key, modifier):
        self.key = key
        self.modifier = modifier

    def keypress(self):
 **self.command.execute()

```

注意各种动作方法如何在各自的命令上调用`execute`方法？这段代码没有显示在每个对象上设置`command`属性。它们可以被传递到`__init__`函数中，但是因为它们可能会被更改（例如，使用可定制的按键绑定编辑器），所以在对象之后设置属性更有意义。

现在，让我们连接命令本身：

```py
class SaveCommand:
    def __init__(self, document):
        self.document = document

    def execute(self):
        self.document.save()

class ExitCommand:
    def __init__(self, window):
        self.window = window

    def execute(self):
        self.window.exit()
```

这些命令很简单；它们展示了基本的模式，但重要的是要注意，如果需要的话，我们可以存储状态和其他信息与命令。例如，如果我们有一个插入字符的命令，我们可以维护当前正在插入的字符的状态。

现在我们所要做的就是连接一些客户端和测试代码，使命令起作用。对于基本测试，我们可以在脚本的末尾包含以下内容：

```py
window = Window()
document = Document("a_document.txt")
save = SaveCommand(document)
exit = ExitCommand(window)

save_button = ToolbarButton('save', 'save.png')
save_button.command = save
save_keystroke = KeyboardShortcut("s", "ctrl")
save_keystroke.command = save
exit_menu = MenuItem("File", "Exit")
exit_menu.command = exit
```

首先我们创建两个接收者和两个命令。然后我们创建几个可用的调用者，并在每个调用者上设置正确的命令。为了测试，我们可以使用`python3 -i filename.py`，并运行像`exit_menu.click()`这样的代码，这将结束程序，或者`save_keystroke.keystroke()`，这将保存虚假文件。

不幸的是，前面的例子并不像 Python。它们有很多“样板代码”（不完成任何任务，只提供模式结构），而且`Command`类彼此之间都非常相似。也许我们可以创建一个通用的命令对象，以函数作为回调？

事实上，为什么要麻烦呢？我们可以为每个命令使用函数或方法对象吗？我们可以编写一个函数，直接将其用作命令，而不是具有`execute()`方法的对象。这是 Python 中命令模式的常见范例：

```py
import sys

class Window:
    def exit(self):
        sys.exit(0)

class MenuItem:
    def click(self):
        self.command()

window = Window()
menu_item = MenuItem()
menu_item.command = window.exit

```

现在看起来更像 Python。乍一看，它看起来像我们完全删除了命令模式，并且紧密连接了`menu_item`和`Window`类。但是如果我们仔细看，我们会发现根本没有紧密耦合。任何可调用对象都可以设置为`MenuItem`上的命令，就像以前一样。`Window.exit`方法可以附加到任何调用者上。命令模式的大部分灵活性都得到了保留。我们为可读性牺牲了完全解耦，但在我看来，以及许多 Python 程序员看来，这段代码比完全抽象的版本更易于维护。

当然，由于我们可以向任何对象添加`__call__`方法，我们并不局限于函数。前面的例子是一种有用的快捷方式，当被调用的方法不必维护状态时，但在更高级的用法中，我们也可以使用这段代码：

```py
class Document:
    def __init__(self, filename):
        self.filename = filename
        self.contents = "This file cannot be modified"

    def save(self):
        with open(self.filename, 'w') as file:
            file.write(self.contents)

class KeyboardShortcut:
    def keypress(self):
        self.command()
class SaveCommand:
    def __init__(self, document):
        self.document = document

 **def __call__(self):
 **self.document.save()

document = Document("a_file.txt")
shortcut = KeyboardShortcut()
save_command = SaveCommand(document)
shortcut.command = save_command
```

这里有一些看起来像第一个命令模式的东西，但更符合习惯。正如你所看到的，让调用者调用可调用对象而不是具有执行方法的命令对象并没有限制我们的任何方式。事实上，这给了我们更多的灵活性。当适用时，我们可以直接链接到函数，但是当情况需要时，我们也可以构建一个完整的可调用命令对象。

命令模式通常被扩展以支持可撤销的命令。例如，文本程序可能会将每个插入操作包装在一个单独的命令中，该命令不仅具有`execute`方法，还具有`undo`方法，用于删除该插入。图形程序可能会将每个绘图操作（矩形、线条、自由像素等）包装在一个命令中，该命令具有`undo`方法，将像素重置为其原始状态。在这种情况下，命令模式的解耦显然更有用，因为每个操作都必须维护足够的状态以便在以后的某个日期撤消该操作。

# 抽象工厂模式

抽象工厂模式通常用于当我们有多种可能的系统实现取决于一些配置或平台问题时。调用代码从抽象工厂请求对象，不知道将返回什么类的对象。返回的底层实现可能取决于各种因素，如当前区域设置、操作系统或本地配置。

抽象工厂模式的常见例子包括操作系统独立工具包的代码、数据库后端和特定国家的格式化程序或计算器。一个操作系统独立的 GUI 工具包可能使用一个抽象工厂模式，在 Windows 下返回一组 WinForm 小部件，在 Mac 下返回一组 Cocoa 小部件，在 Gnome 下返回一组 GTK 小部件，在 KDE 下返回一组 QT 小部件。Django 提供了一个抽象工厂，根据当前站点的配置设置返回一组与特定数据库后端交互的对象关系类（MySQL、PostgreSQL、SQLite 等）。如果应用程序需要在多个地方部署，每个地方可以通过仅更改一个配置变量来使用不同的数据库后端。不同的国家有不同的系统来计算零售商品的税额、小计和总额；抽象工厂可以返回特定的税收计算对象。

抽象工厂模式的 UML 类图很难理解，没有具体的例子，所以让我们先创建一个具体的例子。我们将创建一组依赖于特定区域设置的格式化程序，帮助我们格式化日期和货币。将有一个选择特定工厂的抽象工厂类，以及一对示例具体工厂，一个用于法国，一个用于美国。每个工厂将创建日期和时间的格式化程序对象，可以查询以格式化特定值。这是图表：

![抽象工厂模式](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py3-oop-2e/img/8781OS_11_05.jpg)

将该图像与之前更简单的文本进行比较，可以看出图片并不总是价值千言万语，尤其是考虑到我们甚至没有在这里允许工厂选择代码。

当然，在 Python 中，我们不必实现任何接口类，所以我们可以丢弃`DateFormatter`、`CurrencyFormatter`和`FormatterFactory`。格式化类本身非常简单，但冗长：

```py
class FranceDateFormatter:
    def format_date(self, y, m, d):
        y, m, d = (str(x) for x in (y,m,d))
        y = '20' + y if len(y) == 2 else y
        m = '0' + m if len(m) == 1 else m
        d = '0' + d if len(d) == 1 else d
        return("{0}/{1}/{2}".format(d,m,y))

class USADateFormatter:
    def format_date(self, y, m, d):
        y, m, d = (str(x) for x in (y,m,d))
        y = '20' + y if len(y) == 2 else y
        m = '0' + m if len(m) == 1 else m
        d = '0' + d if len(d) == 1 else d
        return("{0}-{1}-{2}".format(m,d,y))

class FranceCurrencyFormatter:
    def format_currency(self, base, cents):
        base, cents = (str(x) for x in (base, cents))
        if len(cents) == 0:
            cents = '00'
        elif len(cents) == 1:
            cents = '0' + cents

        digits = []
        for i,c in enumerate(reversed(base)):
            if i and not i % 3:
                digits.append(' ')
            digits.append(c)
        base = ''.join(reversed(digits))
        return "{0}€{1}".format(base, cents)

class USACurrencyFormatter:
    def format_currency(self, base, cents):
        base, cents = (str(x) for x in (base, cents))
        if len(cents) == 0:
            cents = '00'
        elif len(cents) == 1:
            cents = '0' + cents
        digits = []
        for i,c in enumerate(reversed(base)):
            if i and not i % 3:
                digits.append(',')
            digits.append(c)
        base = ''.join(reversed(digits))
        return "${0}.{1}".format(base, cents)
```

这些类使用一些基本的字符串操作来尝试将各种可能的输入（整数、不同长度的字符串等）转换为以下格式：

|   | 美国 | 法国 |
| --- | --- | --- |
| **日期** | mm-dd-yyyy | dd/mm/yyyy |
| **货币** | $14,500.50 | 14 500€50 |

在这段代码中，输入显然可以进行更多的验证，但是让我们保持简单和愚蠢，以便进行这个例子。

现在我们已经设置好了格式化程序，我们只需要创建格式化程序工厂：

```py
class USAFormatterFactory:
    def create_date_formatter(self):
        return USADateFormatter()
    def create_currency_formatter(self):
        return USACurrencyFormatter()

class FranceFormatterFactory:
    def create_date_formatter(self):
        return FranceDateFormatter()
    def create_currency_formatter(self):
        return FranceCurrencyFormatter()
```

现在我们设置选择适当格式化程序的代码。由于这种事情只需要设置一次，我们可以将其设置为单例——但是单例在 Python 中并不是很有用。让我们将当前格式化程序作为模块级变量：

```py
country_code = "US"
factory_map = {
        "US": USAFormatterFactory,
        "FR": FranceFormatterFactory}
formatter_factory = factory_map.get(country_code)()
```

在这个例子中，我们硬编码了当前的国家代码；在实践中，它可能会检查区域设置、操作系统或配置文件来选择代码。这个例子使用字典将国家代码与工厂类关联起来。然后我们从字典中获取正确的类并实例化它。

当我们想要为更多的国家添加支持时，很容易看出需要做什么：创建新的格式化程序类和抽象工厂本身。请记住，`Formatter`类可能会被重用；例如，加拿大的货币格式与美国相同，但其日期格式比其南邻更合理。

抽象工厂通常返回一个单例对象，但这并不是必需的；在我们的代码中，它每次调用时都返回每个格式化程序的新实例。没有理由不能将格式化程序存储为实例变量，并为每个工厂返回相同的实例。

回顾这些例子，我们再次看到，对于工厂来说，似乎有很多样板代码在 Python 中并不感觉必要。通常，可能需要抽象工厂的要求可以更容易地通过为每种工厂类型（例如：美国和法国）使用单独的模块来实现，并确保在工厂模块中访问正确的模块。这些模块的包结构可能如下所示：

```py
localize/
    __init__.py
    backends/
        __init__.py
        USA.py
        France.py
        …
```

这个技巧在`localize`包的`__init__.py`中可以包含将所有请求重定向到正确后端的逻辑。有多种方法可以实现这一点。

如果我们知道后端永远不会动态更改（即在没有重新启动的情况下），我们可以在`__init__.py`中放一些`if`语句来检查当前的国家代码，并使用通常不可接受的`from .backends.USA import *`语法从适当的后端导入所有变量。或者，我们可以导入每个后端并设置一个`current_backend`变量指向特定的模块：

```py
from .backends import USA, France

if country_code == "US":
    current_backend = USA
```

根据我们选择的解决方案，我们的客户端代码将不得不调用`localize.format_date`或`localize.current_backend.format_date`来获取以当前国家区域设置格式化的日期。最终结果比原始的抽象工厂模式更符合 Python 的风格，并且在典型的使用情况下同样灵活。

# 组合模式

组合模式允许从简单组件构建复杂的类似树状结构的结构。这些组件，称为组合对象，能够表现得像容器和变量，具体取决于它们是否有子组件。组合对象是容器对象，其中内容实际上可能是另一个组合对象。

传统上，组合对象中的每个组件必须是叶节点（不能包含其他对象）或复合节点。关键是复合和叶节点都可以具有相同的接口。UML 图非常简单：

![组合模式](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py3-oop-2e/img/8781OS_11_06.jpg)

然而，这种简单的模式允许我们创建复杂的元素排列，所有这些元素都满足组件对象的接口。以下是这样一个复杂排列的具体实例：

![组合模式](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py3-oop-2e/img/8781OS_11_07.jpg)

组合模式通常在文件/文件夹样式的树中非常有用。无论树中的节点是普通文件还是文件夹，它仍然受到移动、复制或删除节点等操作的影响。我们可以创建一个支持这些操作的组件接口，然后使用组合对象来表示文件夹，使用叶节点来表示普通文件。

当然，在 Python 中，我们可以再次利用鸭子类型来隐式提供接口，因此我们只需要编写两个类。让我们首先定义这些接口：

```py
class Folder:
    def __init__(self, name):
        self.name = name
        self.children = {}

    def add_child(self, child):
        pass

    def move(self, new_path):
        pass

    def copy(self, new_path):
        pass

    def delete(self):
        pass

class File:
    def __init__(self, name, contents):
        self.name = name
        self.contents = contents

    def move(self, new_path):
        pass

    def copy(self, new_path):
        pass

    def delete(self):
        pass
```

对于每个文件夹（复合）对象，我们维护一个子对象的字典。通常，列表就足够了，但在这种情况下，使用字典来按名称查找子对象将很有用。我们的路径将被指定为由`/`字符分隔的节点名称，类似于 Unix shell 中的路径。

考虑涉及的方法，我们可以看到移动或删除节点的行为方式是相似的，无论它是文件节点还是文件夹节点。然而，复制对于文件夹节点必须进行递归复制，而复制文件节点是一个微不足道的操作。

为了利用相似的操作，我们可以将一些常见的方法提取到一个父类中。让我们将被丢弃的`Component`接口更改为基类：

```py
class Component:
 **def __init__(self, name):
 **self.name = name

    def move(self, new_path):
        new_folder =get_path(new_path)
        del self.parent.children[self.name]
        new_folder.children[self.name] = self
        self.parent = new_folder

    def delete(self):
        del self.parent.children[self.name]

class Folder(Component):
    def __init__(self, name):
 **super().__init__(name)
        self.children = {}

    def add_child(self, child):
        pass

    def copy(self, new_path):
        pass

class File(Component):
    def __init__(self, name, contents):
 **super().__init__(name)
        self.contents = contents

    def copy(self, new_path):
        pass

root = Folder('')
def get_path(path):
 **names = path.split('/')[1:]
 **node = root
 **for name in names:
 **node = node.children[name]
 **return node

```

我们已经在`Component`类上创建了`move`和`delete`方法。它们都访问一个我们尚未设置的神秘的`parent`变量。`move`方法使用一个模块级的`get_path`函数，根据路径从预定义的根节点找到一个节点。所有文件都将被添加到这个根节点或该节点的子节点。对于`move`方法，目标应该是一个当前存在的文件夹，否则我们会得到一个错误。就像技术书籍中的许多示例一样，错误处理是非常缺乏的，以帮助专注于正在考虑的原则。

让我们首先设置那个神秘的`parent`变量；这发生在文件夹的`add_child`方法中：

```py
    def add_child(self, child):
        child.parent = self
        self.children[child.name] = child
```

好了，这就够简单的了。让我们看看我们的复合文件层次结构是否正常工作：

```py
$ python3 -i 1261_09_18_add_child.py

>>> folder1 = Folder('folder1')
>>> folder2 = Folder('folder2')
>>> root.add_child(folder1)
>>> root.add_child(folder2)
>>> folder11 = Folder('folder11')
>>> folder1.add_child(folder11)
>>> file111 = File('file111', 'contents')
>>> folder11.add_child(file111)
>>> file21 = File('file21', 'other contents')
>>> folder2.add_child(file21)
>>> folder2.children
{'file21': <__main__.File object at 0xb7220a4c>}
>>> folder2.move('/folder1/folder11')
>>> folder11.children
{'folder2': <__main__.Folder object at 0xb722080c>, 'file111': <__main__.File object at 0xb72209ec>}
>>> file21.move('/folder1')
>>> folder1.children
{'file21': <__main__.File object at 0xb7220a4c>, 'folder11': <__main__.Folder object at 0xb722084c>}

```

是的，我们可以创建文件夹，将文件夹添加到其他文件夹中，将文件添加到文件夹中，并对它们进行移动！在文件层次结构中，我们还能要求什么呢？

嗯，我们可以要求实现复制，但为了节约树木，让我们把它作为一个练习留下。

复合模式对各种类似树状结构非常有用，包括 GUI 小部件层次结构、文件层次结构、树集、图形和 HTML DOM。按照传统的实现方式，在 Python 中实现时，它可以是一个有用的模式，就像之前的示例所演示的那样。有时，如果只创建了一个浅树，我们可以使用列表的列表或字典的字典，并且不需要实现自定义组件、叶子和复合类。其他时候，我们可以只实现一个复合类，并将叶子和复合对象视为一个类。另外，Python 的鸭子类型可以很容易地将其他对象添加到复合层次结构中，只要它们具有正确的接口。

# 练习

在深入研究每个设计模式的练习之前，先花点时间为上一节中的`File`和`Folder`对象实现`copy`方法。`File`方法应该非常简单；只需创建一个具有相同名称和内容的新节点，并将其添加到新的父文件夹中。`Folder`上的`copy`方法要复杂得多，因为你首先必须复制文件夹，然后递归地将它的每个子项复制到新位置。你可以不加选择地在子项上调用`copy()`方法，无论每个子项是文件还是文件夹对象。这将彰显出复合模式有多么强大。

现在，和上一章一样，看看我们讨论过的模式，并考虑你可能实现它们的理想位置。您可能希望将适配器模式应用于现有代码，因为当与现有库进行接口时通常适用，而不是新代码。您如何使用适配器来强制两个接口正确地相互交互？

你能想到一个足够复杂的系统来证明使用外观模式是合理的吗？考虑外观在现实生活中的使用情况，比如汽车的驾驶员界面，或者工厂中的控制面板。在软件中也是类似的，只不过外观接口的用户是其他程序员，而不是受过培训的人。在你最新的项目中，是否有复杂的系统可以从外观模式中受益？

你可能没有任何巨大的、占用内存的代码，可以从享元模式中受益，但你能想到它可能有用的情况吗？任何需要处理大量重叠数据的地方，都可以使用享元。在银行业中会有用吗？在 Web 应用程序中呢？享元模式在什么时候是有意义的？什么时候又是多余的？

命令模式呢？你能想到任何常见（或更好的是，不常见的）例子，表明从调用中分离出动作会很有用吗？看看你每天使用的程序，想象它们内部是如何实现的。很可能它们中的许多都在某种情况下使用了命令模式。

抽象工厂模式，或者我们讨论过的更具 Python 风格的派生模式，对于创建一键配置的系统非常有用。你能想到这样的系统在哪些地方会有用吗？

最后，考虑一下组合模式。在编程中，我们周围都有类似树的结构；其中一些，比如我们的文件层次结构示例，是显而易见的；其他一些则相当微妙。可能会出现哪些情况，组合模式会很有用呢？你能想到在自己的代码中可以使用它的地方吗？如果你稍微调整一下模式；例如，包含不同类型的叶子或组合节点，用于不同类型的对象？

# 总结

在本章中，我们详细介绍了几种设计模式，包括它们的经典描述以及在 Python 中实现它们的替代方法，Python 通常比传统的面向对象语言更灵活和多才多艺。适配器模式用于匹配接口，而外观模式适用于简化接口。享元模式是一个复杂的模式，只有在需要内存优化时才有用。在 Python 中，命令模式通常更适合使用一等函数作为回调来实现。抽象工厂允许根据配置或系统信息在运行时分离实现。组合模式通常用于类似树的结构。

在下一章中，我们将讨论测试 Python 程序的重要性，以及如何进行测试。
