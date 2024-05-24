# Python 学徒（四）

> 原文：[`zh.annas-archive.org/md5/4702C628AD6B03CA92F1B4B8E471BB27`](https://zh.annas-archive.org/md5/4702C628AD6B03CA92F1B4B8E471BB27)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

## 第十章：文件和资源管理

读写文件是许多现实世界程序的关键部分。然而，*文件*的概念有点抽象。在某些情况下，文件可能意味着硬盘上的一系列字节；在其他情况下，它可能意味着例如远程系统上的 HTTP 资源。这两个实体共享一些行为。例如，您可以从每个实体中读取一系列字节。同时，它们并不相同。例如，您通常可以将字节写回本地文件，而无法对 HTTP 资源进行这样的操作。

在本章中，我们将看一下 Python 对文件的基本支持。由于处理本地文件既常见又重要，我们将主要关注与它们一起工作。但请注意，Python 及其库生态系统为许多其他类型的实体提供了类似*文件*的 API，包括基于 URI 的资源、数据库和许多其他数据源。这种使用通用 API 非常方便，使得可以编写可以在各种数据源上工作而无需更改的代码变得容易。

在本章中，我们还将看一下*上下文管理器*，这是 Python 管理资源的主要手段之一。上下文管理器允许您编写在发生异常时健壮且可预测的代码，确保资源（如文件）在发生错误时被正确关闭和处理。

### 文件

要在 Python 中打开本地文件，我们调用内置的`open()`函数。这需要一些参数，但最常用的是：

+   `file`：文件的路径。*这是必需的*。

+   `mode`：读取、写入、追加和二进制或文本。这是可选的，但我们建议始终明确指定以便清晰。显式优于隐式。

+   `encoding`：如果文件包含编码的文本数据，要使用哪种编码。通常最好指定这一点。如果不指定，Python 将为您选择默认编码。

#### 二进制和文本模式

在文件系统级别，当然，文件只包含一系列字节。然而，Python 区分以二进制和文本模式打开的文件，即使底层操作系统没有这样做。当您以二进制模式打开文件时，您正在指示 Python 使用文件中的数据而不进行任何解码；二进制模式文件反映了文件中的原始数据。

另一方面，以文本模式打开的文件将其内容视为包含`str`类型的文本字符串。当您从文本模式文件中获取数据时，Python 首先使用平台相关的编码或者`open()`的`encoding`参数对原始字节进行解码。

默认情况下，文本模式文件还支持 Python 的*通用换行符*。这会导致我们程序字符串中的单个可移植换行符(`'\n'`)与文件系统中存储的原始字节中的平台相关换行表示（例如 Windows 上的回车换行(`'\r\n'`)）之间的转换。

#### 编码的重要性

正确编码对于正确解释文本文件的内容至关重要，因此我们希望重点强调一下。Python^(24)无法可靠地确定文本文件的编码，因此不会尝试。然而，如果不知道文件的编码，Python 就无法正确操作文件中的数据。这就是为什么告诉 Python 要使用哪种编码非常重要。

如果您不指定编码，Python 将使用`sys.getdefaultencoding()`中的默认编码。在我们的情况下，默认编码是`'utf-8'`：

```py
>>> import sys
>>> sys.getdefaultencoding()
'utf-8'

```

但请记住，您的系统上的默认编码与您希望交换文件的另一个系统上的默认编码可能不同。最好是为了所有相关方都明确决定文本到字节的编码，通过在对`open()`的调用中指定它。您可以在[Python 文档](https://docs.python.org/3/library/codecs.html#standard-encodings)中获取支持的文本编码列表。

#### 打开文件进行写入

让我们通过以*写入*模式打开文件来开始处理文件。我们将明确使用 UTF-8 编码，因为我们无法知道您的默认编码是什么。我们还将使用关键字参数使事情更加清晰：

```py
>>> f = open('wasteland.txt', mode='wt', encoding='utf-8')

```

第一个参数是文件名。`mode`参数是一个包含不同含义字母的字符串。在这种情况下，‘w’表示*写入*，‘t’表示*文本*。

所有模式字符串应该由*读取*、*写入*或*追加*模式中的一个组成。此表列出了模式代码以及它们的含义：

| 代码 | 意义 |
| --- | --- |
| `r` | 以读取模式打开文件。流定位在 |
|   | 文件的开头。这是默认设置。 |
| `r+` | 用于读取和写入。流定位在 |
|   | 文件的开头。 |
| `w` | 截断文件至零长度或创建文件以进行写入。 |
|   | 流定位在文件的开头。 |
| `w+` | 用于读取和写入。如果文件不存在，则创建 |
|   | 存在，则截断。流定位在 |
|   | 文件的开头。 |
| `a` | 用于写入。如果文件不存在，则创建 |
|   | 流定位在文件的末尾。后续写入 |
|   | 文件的写入将始终结束在文件的当前末尾 |
|   | 无论有任何寻址或类似。 |
| `a+` | 用于读取和写入。如果文件不存在，则创建文件 |
|   | 存在。流定位在文件的末尾。 |
|   | 对文件的后续写入将始终结束在文件的当前末尾 |
|   | 无论有任何寻址或 |
|   | 类似。 |

前面的内容之一应与下表中的选择器结合使用，以指定*文本*或*二进制*模式：

| 代码 | 意义 |
| --- | --- |
| `t` | 文件内容被解释为编码文本字符串。从文件中接受和返回 |
|   | 文件将根据指定的文本编码进行编码和解码，并进行通用换行符转换 |
|   | 指定的文本编码，并且通用换行符转换将 |
|   | 生效（除非明确禁用）。所有写入方法 |
|   | `str`对象。 |
|   | *这是默认设置*。 |
| `b` | 文件内容被视为原始字节。所有写入方法 |
|   | 从文件中接受和返回`bytes`对象。 |

典型模式字符串的示例可能是`'wb'`表示“写入二进制”，或者`'at'`表示“追加文本”。虽然模式代码的两部分都支持默认设置，但为了可读性起见，我们建议明确指定。

`open()`返回的对象的确切类型取决于文件的打开方式。这就是动态类型的作用！然而，对于大多数目的来说，`open()`返回的实际类型并不重要。知道返回的对象是*类似文件的对象*就足够了，因此我们可以期望它支持某些属性和方法。

#### 向文件写入

我们之前已经展示了如何请求模块、方法和类型的`help()`，但实际上我们也可以请求实例的帮助。当你记住*一切*都是对象时，这是有意义的。

```py
>>> help(f)
. . .
 |  write(self, text, /)
 |      Write string to stream.
 |      Returns the number of characters written (which is always equal to
 |      the length of the string).
. . .

```

浏览帮助文档，我们可以看到`f`支持`write()`方法。使用‘q’退出帮助，并在 REPL 中继续。

现在让我们使用`write()`方法向文件写入一些文本：

```py
>>> f.write('What are the roots that clutch, ')
32

```

对`write()`的调用返回写入文件的代码点或字符数。让我们再添加几行：

```py
>>> f.write('what branches grow\n')
19
>>> f.write('Out of this stony rubbish? ')
27

```

你会注意到我们在写入文件时明确包括换行符。调用者有责任在需要时提供换行符；Python 不提供`writeline()`方法。

#### 关闭文件

当我们完成写入后，应该记得通过调用`close()`方法关闭文件：

```py
>>> f.close()

```

请注意，只有在关闭文件后，我们才能确保我们写入的数据对外部进程可见。关闭文件很重要！

还要记住，关闭文件后就不能再从文件中读取或写入。这样做会导致异常。

#### Python 之外的文件

如果现在退出 REPL，并查看你的文件系统，你会看到你确实创建了一个文件。在 Unix 上使用`ls`命令：

```py
$ ls -l
-rw-r--r--   1 rjs  staff    78 12 Jul 11:21 wasteland.txt

```

你应该看到`wasteland.txt`文件大小为 78 字节。

在 Windows 上使用`dir`：

```py
> dir
 Volume is drive C has no label.
 Volume Serial Number is 36C2-FF83

 Directory of c:\Users\pyfund

12/07/2013  20:54                79 wasteland.txt
 1 File(s)             79 bytes
 0 Dir(s)  190,353,698,816 bytes free

```

在这种情况下，你应该看到`wasteland.txt`大小为 79 字节，因为 Python 对文件的通用换行行为已经将行尾转换为你平台的本地行尾。

`write()`方法返回的数字是传递给`write()`的字符串中的码点（或字符）的数量，而不是编码和通用换行符转换后写入文件的字节数。通常情况下，在处理文本文件时，你不能通过`write()`返回的数量之和来确定文件的字节长度。

#### 读取文件

要读取文件，我们再次使用`open()`，但这次我们以`'rt'`作为模式，表示*读取文本*：

```py
>>> g = open('wasteland.txt', mode='rt', encoding='utf-8')

```

如果我们知道要读取多少字节，或者想要读取整个文件，我们可以使用`read()`。回顾我们的 REPL，我们可以看到第一次写入是 32 个字符长，所以让我们用`read()`方法读取回来：

```py
>>> g.read(32)
'What are the roots that clutch, '

```

在文本模式下，`read()`方法接受要从文件中读取的*字符*数，而不是字节数。调用返回文本并将文件指针移动到所读取内容的末尾。因为我们以文本模式打开文件，返回类型是`str`。

要读取文件中*所有*剩余的数据，我们可以调用`read()`而不带参数：

```py
>>> g.read()
'what branches grow\nOut of this stony rubbish? '

```

这给我们一个字符串中的两行部分 —— 注意中间的换行符。

在文件末尾，进一步调用`read()`会返回一个空字符串：

```py
>>> g.read()
''

```

通常情况下，当我们完成读取文件时，会使用`close()`关闭文件。不过，为了本练习的目的，我们将保持文件处于打开状态，并使用参数为零的`seek()`将文件指针移回文件的开头：

```py
>>> g.seek(0)
0

```

`seek()`的返回值是新的文件指针位置。

##### 逐行读取

对于文本使用`read()`相当麻烦，幸运的是 Python 提供了更好的工具来逐行读取文本文件。其中第一个就是`readline()`函数：

```py
>>> g.readline()
'What are the roots that clutch, what branches grow\n'
>>> g.readline()
'Out of this stony rubbish? '

```

每次调用`readline()`都会返回一行文本。如果文件中存在换行符，返回的行将以单个换行符结尾。

这里的最后一行没有以换行符结尾，因为文件末尾没有换行序列。你不应该*依赖*于`readline()`返回的字符串以换行符结尾。还要记住，通用换行符支持会将平台本地的换行序列转换为`'\n'`。

一旦我们到达文件末尾，进一步调用`readline()`会返回一个空字符串：

```py
>>> g.readline()
''

```

##### 一次读取多行

让我们再次将文件指针倒回并以不同的方式读取文件：

```py
>>> g.seek(0)

```

有时，当我们知道我们想要读取文件中的每一行时 —— 并且如果我们确信有足够的内存来这样做 —— 我们可以使用`readlines()`方法将文件中的所有行读入列表中：

```py
>>> g.readlines()
['What are the roots that clutch, what branches grow\n',
'Out of this stony rubbish? ']

```

如果解析文件涉及在行之间来回跳转，这将特别有用；使用行列表比使用字符流更容易。

这次，在继续之前我们会关闭文件：

```py
>>> g.close()

```

#### 追加到文件

有时我们希望追加到现有文件中，我们可以通过使用模式`'a'`来实现。在这种模式下，文件被打开以进行写入，并且文件指针被移动到任何现有数据的末尾。在这个例子中，我们将`'a'`与`'t'`结合在一起，以明确使用文本模式：

```py
>>> h = open('wasteland.txt', mode='at', encoding='utf-8')

```

虽然 Python 中没有`writeline()`方法，但有一个`writelines()`方法，它可以将可迭代的字符串系列写入流。如果您希望在字符串上有行结束符*，则必须自己提供。这乍一看可能有点奇怪，但它保持了与`readlines()`的对称性，同时也为我们使用`writelines()`将任何可迭代的字符串系列写入文件提供了灵活性：

```py
>>> h.writelines(
... ['Son of man,\n',
... 'You cannot say, or guess, ',
... 'for you know only,\n',
... 'A heap of broken images, ',
... 'where the sun beats\n'])
>>> h.close()

```

请注意，这里只完成了三行——我们说*完成*，因为我们追加的文件本身没有以换行符结束。

#### 文件对象作为迭代器

这些越来越复杂的文本文件读取工具的顶点在于文件对象支持*迭代器*协议。当您在文件上进行迭代时，每次迭代都会产生文件中的下一行。这意味着它们可以在 for 循环和任何其他可以使用迭代器的地方使用。

此时，我们有机会创建一个 Python 模块文件`files.py`：

```py
import sys

def main(filename):
    f = open(filename, mode='rt', encoding='utf-8')
    for line in f:
        print(line)
    f.close()

if __name__ == '__main__':
    main(sys.argv[1])

```

我们可以直接从系统命令行调用它，传递我们的文本文件的名称：

```py
$ python3 files.py wasteland.txt
What are the roots that clutch, what branches grow

Out of this stony rubbish? Son of man,

You cannot say, or guess, for you know only

A heap of broken images, where the sun beats

```

您会注意到诗歌的每一行之间都有空行。这是因为文件中的每一行都以换行符结尾，然后`print()`添加了自己的换行符。

为了解决这个问题，我们可以使用`strip()`方法在打印之前删除每行末尾的空白。相反，我们将使用`stdout`流的`write()`方法。这与我们之前用来写入文件的`write()`方法*完全*相同，因为`stdout`流本身就是一个类似文件的对象，所以可以使用它。

我们从`sys`模块中获得了对`stdout`流的引用：

```py
import sys

def main(filename):
    f = open(filename, mode='rt', encoding='utf-8')
    for line in f:
        sys.stdout.write(line)
    f.close()

if __name__ == '__main__':
    main(sys.argv[1])

```

如果我们重新运行我们的程序，我们会得到：

```py
$ python3 files.py wasteland.txt
What are the roots that clutch, what branches grow
Out of this stony rubbish? Son of man,
You cannot say, or guess, for you know only
A heap of broken images, where the sun beats

```

现在，不幸的是，是时候离开二十世纪最重要的诗歌之一，开始着手处理*几乎*同样令人兴奋的东西，上下文管理器。

### 上下文管理器

对于接下来的一组示例，我们将需要一个包含一些数字的数据文件。使用下面的`recaman.py`中的代码，我们将一个名为[Recaman 序列](http://mathworld.wolfram.com/RecamansSequence.html)的数字序列写入文本文件，每行一个数字：

```py
import sys
from itertools import count, islice

def sequence():
    """Generate Recaman's sequence."""
    seen = set()
    a = 0
    for n in count(1):
        yield a
        seen.add(a)
        c = a - n
        if c < 0 or c in seen:
            c = a + n
        a = c

def write_sequence(filename, num):
    """Write Recaman's sequence to a text file."""
    f = open(filename, mode='wt', encoding='utf-8')
    f.writelines("{0}\n".format(r)
                 for r in islice(sequence(), num + 1))
    f.close()

if __name__ == '__main__':
    write_sequence(filename=sys.argv[1],
                   num=int(sys.argv[2]))

```

Recaman 序列本身对这个练习并不重要；我们只需要一种生成数字数据的方法。因此，我们不会解释`sequence()`生成器。不过，随意进行实验。

该模块包含一个用于产生 Recaman 数的生成器，以及一个使用`writelines()`方法将序列的开头写入文件的函数。生成器表达式用于将每个数字转换为字符串并添加换行符。`itertools.islice()`用于截断否则无限的序列。

通过执行模块，将文件名和序列长度作为命令行参数传递，我们将前 1000 个 Recaman 数写入文件：

```py
$ python3 recaman.py recaman.dat 1000

```

现在让我们创建一个补充模块`series.py`，它可以重新读取这个数据文件：

```py
"""Read and print an integer series."""

import sys

def read_series(filename):
    f = open(filename, mode='rt', encoding='utf-8')
    series = []
    for line in f:
        a = int(line.strip())
        series.append(a)
    f.close()
    return series

def main(filename):
    series = read_series(filename)
    print(series)

if __name__ == '__main__':
    main(sys.argv[1])

```

我们从打开的文件中一次读取一行，使用`strip()`字符串方法去除换行符，并将其转换为整数。如果我们从命令行运行它，一切都应该如预期般工作：

```py
$ python3 series.py recaman.dat
[0, 1, 3, 6, 2, 7, 13,
 ...
,3683, 2688, 3684, 2687, 3685, 2686, 3686]

```

现在让我们故意制造一个异常情况。在文本编辑器中打开`recaman.dat`，并用不是字符串化整数的内容替换其中一个数字：

```py
0
1
3
6
2
7
13
oops!
12
21

```

保存文件，然后重新运行`series.py`：

```py
$ python3 series.py recaman.dat
Traceback (most recent call last):
  File "series.py", line 19, in <module>
    main(sys.argv[1])
  File "series.py", line 15, in main
    series = read_series(filename)
  File "series.py", line 9, in read_series
    a = int(line.strip())
ValueError: invalid literal for int() with base 10: 'oops!'

```

当传递我们的新的无效行时，`int()`构造函数会引发`ValueError`。异常未处理，因此程序以堆栈跟踪终止。

#### 使用`finally`管理资源

这里的一个问题是我们的`f.close()`调用从未执行过。

为了解决这个问题，我们可以插入一个`try`..`finally`块：

```py
def read_series(filename):
    try:
        f = open(filename, mode='rt', encoding='utf-8')
        series = []
        for line in f:
            a = int(line.strip())
            series.append(a)
    finally:
        f.close()
    return series

```

现在文件将始终关闭，即使存在异常。进行这种更改开启了另一种重构的机会：我们可以用列表推导来替换 for 循环，并直接返回这个列表：

```py
def read_series(filename):
    try:
        f = open(filename, mode='rt', encoding='utf-8')
        return [ int(line.strip()) for line in f ]
    finally:
        f.close()

```

即使在这种情况下，`close()`仍然会被调用；无论`try`块如何退出，`finally`块都会被调用。

#### with-blocks

到目前为止，我们的例子都遵循一个模式：`open()`一个文件，处理文件，`close()`文件。`close()`很重要，因为它通知底层操作系统你已经完成了对文件的操作。如果你在完成文件操作后不关闭文件，可能会丢失数据。可能会有待写入的缓冲区，可能不会完全写入。此外，如果你打开了很多文件，你的系统可能会耗尽资源。由于我们总是希望每个`open()`都与一个`close()`配对，我们希望有一个机制，即使我们忘记了，也能强制执行这种关系。

这种资源清理的需求是很常见的，Python 实现了一个特定的控制流结构，称为*with-blocks*来支持它。with-blocks 可以与支持*上下文管理器*协议的任何对象一起使用，这包括`open()`返回的文件对象。利用文件对象是上下文管理器的事实，我们的`read_series()`函数可以变成：

```py
def read_series(filename):
    with open(filename, mode='rt', encoding='utf-8') as f:
        return [int(line.strip()) for line in f]

```

我们不再需要显式调用`close()`，因为`with`结构将在执行退出块时为我们调用它，无论我们如何退出块。

现在我们可以回去修改我们的 Recaman 系列写作程序，也使用一个 with-block，再次消除了显式的`close()`的需要：

```py
def write_sequence(filename, num):
    """Write Recaman's sequence to a text file."""
    with open(filename, mode='wt', encoding='utf-8') as f:
        f.writelines("{0}\n".format(r)
                     for r in islice(sequence(), num + 1))

```

* * *

### 禅的时刻

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-aprt/img/zen-beautiful-is-better-than-ugly.png)

with-block 的语法如下：

```py
with EXPR as VAR:
    BLOCK

```

这被称为*语法糖*，用于更复杂的`try...except`和`try...finally`块的安排：

```py
mgr = (EXPR)
exit = type(mgr).__exit__  # Not calling it yet
value = type(mgr).__enter__(mgr)
exc = True
try:
    try:
        VAR = value  # Only if "as VAR" is present
        BLOCK
    except:
        # The exceptional case is handled here
        exc = False
        if not exit(mgr, *sys.exc_info()):
            raise
        # The exception is swallowed if exit() returns true
finally:
    # The normal and non-local-goto cases are handled here
    if exc:
        exit(mgr, None, None, None)

```

^(25)

你更喜欢哪个？

我们中很少有人希望我们的代码看起来如此复杂，但这就是没有`with`语句的情况下它需要看起来的样子。糖可能对你的健康不好，但对你的代码可能非常有益！

* * *

### 二进制文件

到目前为止，我们已经看过文本文件，其中我们将文件内容处理为 Unicode 字符串。然而，有许多情况下，文件包含的数据并不是编码文本。在这些情况下，我们需要能够直接处理文件中存在的确切字节，而不需要任何中间编码或解码。这就是*二进制模式*的用途。

#### BMP 文件格式

为了演示处理二进制文件，我们需要一个有趣的二进制数据格式。BMP 是一种包含设备无关位图的图像文件格式。它足够简单，我们可以从头开始制作一个 BMP 文件写入器。^(26)将以下代码放入一个名为`bmp.py`的模块中：

```py
 1 # bmp.py
 2 
 3 """A module for dealing with BMP bitmap image files."""
 4 
 5 
 6 def write_grayscale(filename, pixels):
 7    """Creates and writes a grayscale BMP file.
 8 
 9    Args:
10         filename: The name of the BMP file to me created.
11 
12         pixels: A rectangular image stored as a sequence of rows.
13             Each row must be an iterable series of integers in the
14             range 0-255.
15 
16     Raises:
17         OSError: If the file couldn't be written.
18     """
19     height = len(pixels)
20     width = len(pixels[0])
21 
22     with open(filename, 'wb') as bmp:
23         # BMP Header
24         bmp.write(b'BM')
25 
26         # The next four bytes hold the filesize as a 32-bit
27         # little-endian integer. Zero placeholder for now.
28         size_bookmark = bmp.tell()
29         bmp.write(b'\x00\x00\x00\x00')
30 
31         # Two unused 16-bit integers - should be zero
32         bmp.write(b'\x00\x00')
33         bmp.write(b'\x00\x00')
34 
35         # The next four bytes hold the integer offset
36         # to the pixel data. Zero placeholder for now.
37         pixel_offset_bookmark = bmp.tell()
38         bmp.write(b'\x00\x00\x00\x00')
39 
40         # Image Header
41         bmp.write(b'\x28\x00\x00\x00')  # Image header size in bytes - 40 decimal
42         bmp.write(_int32_to_bytes(width))   # Image width in pixels
43         bmp.write(_int32_to_bytes(height))  # Image height in pixels
44         # Rest of header is essentially fixed
45         bmp.write(b'\x01\x00')          # Number of image planes
46         bmp.write(b'\x08\x00')          # Bits per pixel 8 for grayscale
47         bmp.write(b'\x00\x00\x00\x00')  # No compression
48         bmp.write(b'\x00\x00\x00\x00')  # Zero for uncompressed images
49         bmp.write(b'\x00\x00\x00\x00')  # Unused pixels per meter
50         bmp.write(b'\x00\x00\x00\x00')  # Unused pixels per meter
51         bmp.write(b'\x00\x00\x00\x00')  # Use whole color table
52         bmp.write(b'\x00\x00\x00\x00')  # All colors are important
53 
54         # Color palette - a linear grayscale
55         for c in range(256):
56             bmp.write(bytes((c, c, c, 0)))  # Blue, Green, Red, Zero
57 
58         # Pixel data
59         pixel_data_bookmark = bmp.tell()
60         for row in reversed(pixels):  # BMP files are bottom to top
61             row_data = bytes(row)
62             bmp.write(row_data)
63             padding = b'\x00' * ((4 - (len(row) % 4)) % 4)  # Pad row to multiple
64                                                             # of four bytes
65             bmp.write(padding)
66 
67         # End of file
68         eof_bookmark = bmp.tell()
69 
70         # Fill in file size placeholder
71         bmp.seek(size_bookmark)
72         bmp.write(_int32_to_bytes(eof_bookmark))
73 
74         # Fill in pixel offset placeholder
75         bmp.seek(pixel_offset_bookmark)
76         bmp.write(_int32_to_bytes(pixel_data_bookmark))

```

这可能看起来很复杂，但你会发现它相对简单。

为了简单起见，我们决定只处理 8 位灰度图像。这些图像有一个很好的特性，即每个像素一个字节。`write_grayscale()`函数接受两个参数：文件名和像素值的集合。正如文档字符串所指出的那样，这个集合应该是整数序列的序列。例如，一个`int`对象的列表列表就可以了。此外：

+   每个`int`必须是从 0 到 255 的像素值

+   每个内部列表都是从左到右的像素行

+   外部列表是从上到下的像素行的列表。

我们要做的第一件事是通过计算行数（第 19 行）来确定图像的大小，以给出高度，并计算零行中的项目数来获得宽度（第 20 行）。我们假设，但不检查，所有行的长度都相同（在生产代码中，这是我们想要进行检查的）。

接下来，我们使用`'wb'`模式字符串在*二进制写入*模式下`open()`（第 22 行）文件。我们不指定编码 - 这对于原始二进制文件没有意义。

在 with 块内，我们开始编写所谓的“BMP 头”，这是 BMP 格式的开始。

头部必须以所谓的“魔术”字节序列`b'BM'`开头，以识别它为 BMP 文件。我们使用`write()`方法（第 24 行），因为文件是以二进制模式打开的，所以我们必须传递一个`bytes`对象。

接下来的四个字节应该包含一个 32 位整数，其中包含文件大小，这是我们目前还不知道的值。我们本可以提前计算它，但我们将采取不同的方法：我们将写入一个占位符值，然后返回到这一点以填写细节。为了能够回到这一点，我们使用文件对象的`tell()`方法（第 28 行）；这给了我们文件指针从文件开头的偏移量。我们将把这个偏移量存储在一个变量中，它将充当一种书签。我们写入四个零字节作为占位符（第 29 行），使用转义语法来指定这些零。

接下来的两对字节是未使用的，所以我们也将零字节写入它们（第 32 和 33 行）。

接下来的四个字节是另一个 32 位整数，应该包含从文件开头到像素数据开始的偏移量（以字节为单位）。我们也不知道这个值，所以我们将使用`tell()`（第 37 行）存储另一个书签，并写入另外四个字节的占位符（第 38 行）；当我们知道更多信息时，我们将很快返回到这里。

接下来的部分称为“图像头”。我们首先要做的是将图像头的长度写入一个 32 位整数（第 41 行）。在我们的情况下，头部总是 40 个字节长。我们只需将其硬编码为十六进制。注意 BMP 格式是小端序的 - 最不重要的字节先写入。

接下来的四个字节是图像宽度，作为小端序的 32 位整数。我们在这里调用一个模块范围的实现细节函数，名为`_int32_to_bytes()`，它将一个`int`对象转换为一个包含恰好四个字节的`bytes`对象（第 42 行）。然后我们再次使用相同的函数来处理图像高度（第 43 行）。

头部的其余部分对于 8 位灰度图像基本上是固定的，这里的细节并不重要，除了要注意整个头部实际上总共是 40 个字节（第 45 行）。

8 位 BMP 图像中的每个像素都是颜色表中 256 个条目的索引。每个条目都是一个四字节的 BGR 颜色。对于灰度图像，我们需要按线性比例写入 256 个 4 字节的灰度值（第 54 行）。这段代码是实验的肥沃土壤，这个函数的一个自然增强功能将是能够单独提供这个调色板作为可选的函数参数。

最后，我们准备写入像素数据，但在这之前，我们要使用`tell()`（第 59 行）方法记录当前文件指针的偏移量，因为这是我们需要稍后返回并填写的位置之一。

写入像素数据本身是相当简单的。我们使用内置函数`reversed()`（第 60 行）来翻转行的顺序；BMP 图像是从底部向顶部写入的。对于每一行，我们将整数的可迭代系列传递给`bytes()`构造函数（第 61 行）。如果任何整数超出了 0-255 的范围，构造函数将引发`ValueError`。

BMP 文件中的每一行像素数据必须是四个字节的整数倍长，与图像宽度无关。为了做到这一点（第 63 行），我们取行长度模四，得到一个介于零和三之间的数字，这是我们行末尾距离*前一个*四字节边界的字节数。为了得到填充字节数，使我们达到*下一个*四字节边界，我们从四中减去这个模数值，得到一个介于 4 到 1 之间的值。然而，我们永远不希望用四个字节填充，只用一、二或三个，所以我们必须再次取模四，将四字节填充转换为零字节填充。

这个值与重复操作符应用于单个零字节一起使用，以产生一个包含零、一个、两个或三个字节的字节对象。我们将这些写入文件，以终止每一行（第 65 行）。

在像素数据之后，我们已经到达了文件的末尾。我们之前承诺记录了这个偏移值，所以我们使用`tell()`（第 68 行）将当前位置记录到一个文件末尾书签变量中。

现在我们可以回来实现我们的承诺，通过用我们记录的真实偏移量替换占位符。首先是文件长度。为此，我们`seek()`（第 71 行）回到我们在文件开头附近记住的`size_bookmark`，并使用我们的`_int32_to_bytes()`函数将存储在`eof_bookmark`中的大小作为小端 32 位整数`write()`（第 72 行）。

最后，我们`seek()`（第 75 行）到由`pixel_offset_bookmark`标记的像素数据偏移量的位置，并将存储在`pixel_data_bookmark`中的 32 位整数（第 76 行）写入。

当我们退出 with 块时，我们可以放心，上下文管理器将关闭文件并将任何缓冲写入文件系统。

#### 位运算符

处理二进制文件通常需要在字节级别拆分或组装数据。这正是我们的`_int32_to_bytes()`函数在做的事情。我们将快速查看它，因为它展示了一些我们以前没有见过的 Python 特性：

```py
def _int32_to_bytes(i):
    """Convert an integer to four bytes in little-endian format."""
    return bytes((i & 0xff,
                  i >> 8 & 0xff,
                  i >> 16 & 0xff,
                  i >> 24 & 0xff))

```

该函数使用`>>`（*位移*）和`&`（*按位与*）运算符从整数值中提取单个字节。请注意，按位与使用和符号来区分它与*逻辑与*，后者是拼写出来的单词“and”。`>>`运算符将整数的二进制表示向右移动指定的位数。该例程在每次移位后使用`&`提取最低有效字节。得到的四个整数用于构造一个元组，然后传递给`bytes()`构造函数以产生一个四字节序列。

#### 写一个 BMP 文件

为了生成一个 BMP 图像文件，我们需要一些像素数据。我们包含了一个简单的模块`fractal.py`，它为标志性的[Mandelbrot 集合分形](https://en.wikipedia.org/wiki/Mandelbrot_set)生成像素值。我们不打算详细解释分形生成代码，更不用说背后的数学。但这段代码足够简单，而且不依赖于我们以前遇到的任何 Python 特性：

```py
# fractal.py

"""Computing Mandelbrot sets."""

import math

def mandel(real, imag):
    """The logarithm of number of iterations needed to
 determine whether a complex point is in the
 Mandelbrot set.

 Args:
 real: The real coordinate
 imag: The imaginary coordinate

 Returns:
 An integer in the range 1-255.
 """
    x = 0
    y = 0
    for i in range(1, 257):
        if x*x + y*y > 4.0:
            break
        xt = real + x*x - y*y
        y = imag + 2.0 * x * y
        x = xt
    return int(math.log(i) * 256 / math.log(256)) - 1

def mandelbrot(size_x, size_y):
    """Make an Mandelbrot set image.

 Args:
 size_x: Image width
 size_y: Image height

 Returns:
 A list of lists of integers in the range 0-255.
 """
    return [ [mandel((3.5 * x / size_x) - 2.5,
                     (2.0 * y / size_y) - 1.0)
              for x in range(size_x) ]
            for y in range(size_y) ]

```

关键是`mandelbrot()`函数使用嵌套的列表推导来生成一个范围在 0-255 的整数列表的列表。这个列表代表了分形的图像。每个点的整数值是由`mandel()`函数产生的。

##### 生成分形图像

让我们启动一个 REPL，并将`fractal`和`bmp`模块一起使用。首先，我们使用`mandelbrot()`函数生成一个 448x256 像素的图像。使用长宽比为 7:4 的图像会获得最佳结果：

```py
>>> import fractal
>>> pixels = fractal.mandelbrot(448, 256)

```

这个对`mandelbrot()`的调用可能需要一秒左右 - 我们的分形生成器简单而不是高效！

我们可以查看返回的数据结构：

```py
>>> pixels
[[31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31,
  31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31,
  ...
  49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49]]

```

这是一个整数列表的列表，就像我们所承诺的那样。让我们把这些像素值写入一个 BMP 文件：

```py
>>> import bmp
>>> bmp.write_grayscale("mandel.bmp", pixels)

```

找到文件并在图像查看器中打开它，例如通过在 Web 浏览器中打开它。

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-aprt/img/mandel.png)

#### 读取二进制文件

现在我们正在生成美丽的 Mandelbrot 图像，我们应该尝试用 Python 读取这些 BMP 文件。我们不打算编写一个完整的 BMP 阅读器，尽管那将是一个有趣的练习。我们只是制作一个简单的函数来确定 BMP 文件中的像素维度。我们将把代码添加到`bmp.py`中：

```py
def dimensions(filename):
    """Determine the dimensions in pixels of a BMP image.

 Args:
 filename: The filename of a BMP file.

 Returns:
 A tuple containing two integers with the width
 and height in pixels.

 Raises:
 ValueError: If the file was not a BMP file.
 OSError: If there was a problem reading the file.
 """

    with open(filename, 'rb') as f:
        magic = f.read(2)
        if magic != b'BM':
            raise ValueError("{} is not a BMP file".format(filename))

        f.seek(18)
        width_bytes = f.read(4)
        height_bytes = f.read(4)

        return (_bytes_to_int32(width_bytes),
                _bytes_to_int32(height_bytes))

```

当然，我们使用 with 语句来管理文件，所以我们不必担心它是否被正确关闭。在 with 块内，我们通过查找我们在 BMP 文件中期望的前两个魔术字节来执行简单的验证检查。如果不存在，我们会引发`ValueError`，这当然会导致上下文管理器关闭文件。

回顾一下我们的 BMP 写入器，我们可以确定图像尺寸恰好存储在文件开头的 18 个字节处。我们`seek()`到该位置，并使用`read()`方法读取两个四字节的块，分别代表尺寸的两个 32 位整数。因为我们以二进制模式打开文件，`read()`返回一个`bytes`对象。我们将这两个`bytes`对象传递给另一个实现细节函数`_bytes_to_int32()`，它将它们重新组装成一个整数。这两个整数，代表图像的宽度和高度，作为一个元组返回。

`_bytes_to_int32（）`函数使用`<<`（*按位左移*）和`|`（*按位或*），以及对`bytes`对象的索引，来重新组装整数。请注意，对`bytes`对象进行索引返回一个整数：

```py
def _bytes_to_int32(b):
    """Convert a bytes object containing four bytes into an integer."""
    return b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24)

```

如果我们使用我们的新的读取器代码，我们可以看到它确实读取了正确的值：

```py
>>> bmp.dimensions("mandel.bmp")
(448, 256)

```

### 类似文件的对象

Python 中有一个“类似文件的对象”的概念。这并不像特定的协议^(27)那样正式，但由于鸭子类型所提供的多态性，在实践中它运作良好。

之所以没有严格规定它，是因为不同类型的数据流和设备具有许多不同的功能、期望和行为。因此，实际上定义一组模拟它们的协议将是相当复杂的，而且实际上并没有太多的实际意义，除了一种理论成就感。这就是 EAFP^(28)哲学的优势所在：如果你想在类似文件的对象上执行`seek()`，而事先不知道它是否支持随机访问，那就试试看（字面上！）。只是要做好准备，如果`seek()`方法不存在，或者*存在*但行为不符合你的期望，那么就会失败。

你可能会说“如果它看起来像一个文件，读起来像一个文件，那么它就是一个文件”。

#### 你已经看到了类似文件的对象！

我们已经看到了类似文件的对象的实际应用；当我们以文本和二进制模式打开文件时，返回给我们的对象实际上是不同类型的，尽管都具有明确定义的类似文件的行为。Python 标准库中还有其他类型实现了类似文件的行为，实际上我们在书的开头就看到了其中一个，当时我们使用`urlopen()`从互联网上的 URL 检索数据。

#### 使用类似文件的对象

让我们通过编写一个函数来利用类似文件的对象的多态性，来统计文件中每行的单词数，并将该信息作为列表返回：

```py
>>> def words_per_line(flo):
...    return [len(line.split()) for line in flo.readlines()]

```

现在我们将打开一个包含我们之前创建的 T.S.艾略特杰作片段的常规文本文件，并将其传递给我们的新函数：

```py
>>> with open("wasteland.txt", mode='rt', encoding='utf-8') as real_file:
...     wpl = words_per_line(real_file)
...
>>> wpl
[9, 8, 9, 9]

```

`real_file`的实际类型是：

```py
>>> type(real_file)
<class '_io.TextIOWrapper'>

```

但通常你不应该关心这个具体的类型；这是 Python 内部的实现细节。你只需要关心它的行为“像一个文件”。

现在我们将使用代表 URL 引用的 Web 资源的类似文件对象执行相同的操作：

```py
>>> from urllib.request import urlopen
>>> with urlopen("http://sixty-north.com/c/t.txt") as web_file:
...    wpl = words_per_line(web_file)
...
>>> wpl
[6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 5, 5, 7, 8, 14, 12, 8]

```

`web_file`的类型与我们刚刚看到的类型相当不同：

```py
>>> type(web_file)
<class 'http.client.HTTPResponse'>

```

然而，由于它们都是类似文件的对象，我们的函数可以与两者一起使用。

类似文件的对象并没有什么神奇之处；它只是一个方便且相当非正式的描述，用于描述我们可以对对象提出的一组期望，这些期望是通过鸭子类型来实现的。

### 其他资源

with 语句结构可以与实现上下文管理器协议的任何类型的对象一起使用。我们不会在本书中向您展示如何实现上下文管理器 - 为此，您需要参考*The Python Journeyman* - 但我们会向您展示一种简单的方法，使您自己的类可以在 with 语句中使用。将这段代码放入模块`fridge.py`中：

```py
# fridge.py

"""Demonstrate raiding a refrigerator."""

class RefrigeratorRaider:
    """Raid a refrigerator."""

    def open(self):
        print("Open fridge door.")

    def take(self, food):
        print("Finding {}...".format(food))
        if food == 'deep fried pizza':
            raise RuntimeError("Health warning!")
        print("Taking {}".format(food))

    def close(self):
        print("Close fridge door.")

def raid(food):
    r = RefrigeratorRaider()
    r.open()
    r.take(food)
    r.close()

```

我们将`raid()`导入 REPL 并开始肆虐：

```py
>>> from fridge import raid
>>> raid("bacon")
Open fridge door.
Finding bacon...
Taking bacon
Close fridge door.

```

重要的是，我们记得关闭了门，所以食物会保存到我们下次袭击。让我们尝试另一次袭击，找一些稍微不那么健康的东西：

```py
>>> raid("deep fried pizza")
Open fridge door.
Finding deep fried pizza...
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
  File "./fridge.py", line 23, in raid
    r.take(food)
  File "./fridge.py", line 14, in take
    raise RuntimeError("Health warning!")
RuntimeError: Health warning!

```

这次，我们被健康警告打断，没有来得及关闭门。我们可以通过使用 Python 标准库中的[`contextlib`模块](https://docs.python.org/3/library/contextlib.html)中的`closing()`函数来解决这个问题。导入函数后，我们将`RefrigeratorRaider`构造函数调用包装在`closing()`的调用中。这样可以将我们的对象包装在一个上下文管理器中，在退出之前始终调用包装对象上的`close()`方法。我们使用这个对象来初始化一个 with 块：

```py
"""Demonstrate raiding a refrigerator."""

from contextlib import closing

class RefrigeratorRaider:
    """Raid a refrigerator."""

    def open(self):
        print("Open fridge door.")

    def take(self, food):
        print("Finding {}...".format(food))
        if food == 'deep fried pizza':
            raise RuntimeError("Health warning!")
        print("Taking {}".format(food))

    def close(self):
        print("Close fridge door.")

def raid(food):
    with closing(RefrigeratorRaider()) as r:
        r.open()
        r.take(food)
        r.close()

```

现在当我们执行袭击时：

```py
>>> raid("spam")
Open fridge door.
Finding spam...
Taking spam
Close fridge door.
Close fridge door.

```

我们看到我们对`close()`的显式调用是不必要的，所以让我们来修复一下：

```py
def raid(food):
    with closing(RefrigeratorRaider()) as r:
        r.open()
        r.take(food)

```

更复杂的实现会检查门是否已经关闭，并忽略其他请求。

那么它是否有效呢？让我们再试试吃一些油炸比萨：

```py
>>> raid("deep fried pizza")
Open fridge door.
Finding deep fried pizza...
Close fridge door.
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
  File "./fridge.py", line 23, in raid
    r.take(food)
  File "./fridge.py", line 14, in take
    raise RuntimeError("Health warning!")
RuntimeError: Health warning!

```

这一次，即使触发了健康警告，上下文管理器仍然为我们关闭了门。

### 总结

+   文件是使用内置的`open()`函数打开的，该函数接受文件模式来控制读取/写入/追加行为，以及文件是作为原始二进制数据还是编码文本数据进行处理。

+   对于文本数据，应指定文本编码。

+   文本文件处理字符串对象，并执行通用换行符转换和字符串编码。

+   二进制文件处理`bytes`对象，不进行换行符转换或编码。

+   在写文件时，您有责任为换行符提供换行字符。

+   文件在使用后应始终关闭。

+   文件提供各种面向行的方法进行读取，并且也是迭代器，逐行产生行。

+   文件是上下文管理器，可以与上下文管理器一起使用，以确保执行清理操作，例如关闭文件。

+   文件样对象的概念定义不严格，但在实践中非常有用。尽量使用 EAFP 来充分利用它们。

+   上下文管理器不仅限于类似文件的对象。我们可以使用`contextlib`标准库模块中的工具，例如`closing()`包装器来创建我们自己的上下文管理器。

沿途我们发现：

+   `help()`可以用于实例对象，而不仅仅是类型。

+   Python 支持按位运算符`&`、`|`、`<<`和`>>`。


## 第十一章：使用 Python 标准库进行单元测试

当我们构建甚至是轻微复杂的程序时，代码中会有无数种缺陷的方式。这可能发生在我们最初编写代码时，但当我们对其进行修改时，我们同样有可能引入缺陷。为了帮助掌握缺陷并保持代码质量高，拥有一组可以运行的测试通常非常有用，这些测试可以告诉您代码是否按照您的期望行事。

为了帮助进行这样的测试，Python 标准库包括[`unittest`模块](https://docs.python.org/3/library/unittest.html)。尽管其名称暗示了它只有单元测试，但实际上，这个模块不仅仅用于单元测试。事实上，它是一个灵活的框架，可以自动化各种测试，从验收测试到集成测试再到单元测试。它的关键特性，就像许多语言中的许多测试框架一样，是帮助您进行*自动化*和*可重复*的测试。有了这样的测试，您可以在任何时候廉价且轻松地验证代码的行为。

### 测试用例

`unittest`模块围绕着一些关键概念构建，其中心是*测试用例*的概念。测试用例 - 体现在[`unittest.TestCase`类](https://docs.python.org/3/library/unittest.html#unittest.TestCase)中 - 将一组相关的测试方法组合在一起，它是`unittest`框架中的测试组织的基本单元。正如我们稍后将看到的，单个测试方法是作为`unittest.TestCase`子类上的方法实现的。

### 固定装置

下一个重要概念是*固定装置*。固定装置是在每个测试方法之前和/或之后运行的代码片段。固定装置有两个主要目的：

1.  *设置*固定装置确保测试环境在运行测试之前处于预期状态。

1.  *清理*固定装置在测试运行后清理环境，通常是通过释放资源。

例如，设置固定装置可能在运行测试之前在数据库中创建特定条目。类似地，拆卸固定装置可能会删除测试创建的数据库条目。测试不需要固定装置，但它们非常常见，通常对于使测试可重复至关重要。

### 断言

最终的关键概念是*断言*。断言是测试方法中的特定检查，最终决定测试是否通过或失败。除其他事项外，断言可以：

+   进行简单的布尔检查

+   执行对象相等性测试

+   验证是否抛出了适当的异常

如果断言失败，那么测试方法也会失败，因此断言代表了您可以执行的最低级别的测试。您可以在`unittest`文档中找到[断言的完整列表](https://docs.python.org/3/library/unittest.html#assert-methods)。

### 单元测试示例：文本分析

有了这些概念，让我们看看如何实际在实践中使用`unittest`模块。在这个例子中，我们将使用*测试驱动开发*^(29)来编写一个简单的文本分析函数。这个函数将以文件名作为唯一参数。然后它将读取该文件并计算：

+   文件中的行数

+   文件中的字符数

TDD 是一个迭代的开发过程，因此我们不会在 REPL 上工作，而是将我们的测试代码放在一个名为`text_analyzer.py`的文件中。首先，我们将创建我们的第一个测试^(30)，并提供足够的支持代码来实际运行它。

```py
# text_analyzer.py

import unittest

class TextAnalysisTests(unittest.TestCase):
    """Tests for the ``analyze_text()`` function."""

    def test_function_runs(self):
        """Basic smoke test: does the function run."""
        analyze_text()

if __name__ == '__main__':
    unittest.main()

```

我们首先导入`unittest`模块。然后，我们通过定义一个从`unittest.TestCase`派生的类`TextAnalysisTests`来创建我们的测试用例。这是您使用`unittest`框架创建测试用例的方法。

要在测试用例中定义单独的测试方法，只需在`TestCase`子类上创建以“`test_`”开头的方法。`unittest`框架在执行时会自动发现这样的方法，因此您不需要显式注册您的测试方法。

在这种情况下，我们定义了最简单的测试：我们检查`analyze_text()`函数是否运行！我们的测试没有进行任何明确的检查，而是依赖于测试方法如果抛出任何异常则会失败的事实。在这种情况下，如果`analyze_text()`没有被定义，我们的测试将失败。

最后，我们定义了惯用的“main”块，当这个模块被执行时调用`unittest.main()`。`unittest.main()`将在模块中搜索所有的`TestCase`子类，并执行它们所有的测试方法。

#### 运行初始测试

由于我们正在使用测试驱动设计，我们期望我们的测试一开始会失败。事实上，我们的测试失败了，原因很简单，我们还没有定义`analyze_text()`：

```py
$ python text_analyzer.py
E
======================================================================
ERROR: test_function_runs (__main__.TextAnalysisTests)
----------------------------------------------------------------------
Traceback (most recent call last):
  File "text_analyzer.py", line 5, in test_function_runs
    analyze_text()
NameError: global name 'analyze_text' is not defined

----------------------------------------------------------------------
Ran 1 test in 0.001s

FAILED (errors=1)

```

正如你所看到的，`unittest.main()`生成了一个简单的报告，告诉我们运行了多少个测试，有多少个失败了。它还向我们展示了测试是如何失败的，比如在我们尝试运行不存在的函数`analyze_text()`时，它告诉我们我们得到了一个`NameError`。

#### 使测试通过

通过定义`analyze_text()`来修复我们失败的测试。请记住，在测试驱动开发中，我们只编写足够满足测试的代码，所以现在我们只是创建一个空函数。为了简单起见，我们将把这个函数放在`text_analyzer.py`中，尽管通常你的测试代码和实现代码会在不同的模块中：

```py
# text_analyzer.py

def analyze_text():
    """Calculate the number of lines and characters in a file.
 """
    pass

```

将这个函数放在模块范围。再次运行测试，我们发现它们现在通过了：

```py
% python text_analyzer.py
.
----------------------------------------------------------------------
Ran 1 test in 0.001s

OK

```

我们已经完成了一个 TDD 周期，但当然我们的代码还没有真正做任何事情。我们将迭代地改进我们的测试和实现，以得到一个真正的解决方案。

### 使用固定装置创建临时文件

接下来要做的事情是能够向`analyze_text()`传递一个文件名，以便它知道要处理什么。当然，为了让`analyze_text()`工作，这个文件名应该指的是一个实际存在的文件！为了确保我们的测试中存在一个文件，我们将定义一些固定装置。

我们可以定义的第一个固定装置是`TestCase.setUp()`方法。如果定义了，这个方法会在`TestCase`中的每个测试方法之前运行。在这种情况下，我们将使用`setUp()`为我们创建一个文件，并将文件名记住为`TestCase`的成员：

```py
# text_analyzer.py

class TextAnalysisTests(unittest.TestCase):
    . . .
    def setUp(self):
        "Fixture that creates a file for the text methods to use."
        self.filename = 'text_analysis_test_file.txt'
        with open(self.filename, 'w') as f:
            f.write('Now we are engaged in a great civil war,\n'
                    'testing whether that nation,\n'
                    'or any nation so conceived and so dedicated,\n'
                    'can long endure.')

```

我们可以使用的第二个固定装置是`TestCase.tearDown()`。`tearDown()`方法在`TestCase`中的每个测试方法之后运行，在这种情况下，我们将使用它来删除在`setUp()`中创建的文件：

```py
# text_analyzer.py

import os
. . .
class TextAnalysisTests(unittest.TestCase):
    . . .
    def tearDown(self):
        "Fixture that deletes the files used by the test methods."
        try:
            os.remove(self.filename)
        except OSError:
            pass

```

请注意，由于我们在`tearDown()`中使用了`os`模块，我们需要在文件顶部导入它。

还要注意`tearDown()`如何吞没了`os.remove()`抛出的任何异常。我们这样做是因为`tearDown()`实际上不能确定文件是否存在，所以它尝试删除文件，并假设任何异常都可以安全地被忽略。

### 使用新的固定装置

有了我们的两个固定装置，我们现在每个测试方法之前都有一个文件被创建，并且在每个测试方法之后都被删除。这意味着每个测试方法都是从一个稳定的、已知的状态开始的。这对于制作可重复的测试是至关重要的。让我们通过修改现有的测试将这个文件名传递给`analyze_text()`：

```py
# text_analyzer.py

class TextAnalysisTests(unittest.TestCase):
    . . .
    def test_function_runs(self):
        "Basic smoke test: does the function run."
        analyze_text(self.filename)

```

记住我们的`setUp()`将文件名存储在`self.filename`上。由于传递给固定装置的`self`参数与传递给测试方法的实例相同，我们的测试可以使用该属性访问文件名。

当我们运行我们的测试时，我们发现这个测试失败了，因为`analyze_text()`还没有接受任何参数：

```py
% python text_analyzer.py
E
======================================================================
ERROR: test_function_runs (__main__.TextAnalysisTests)
----------------------------------------------------------------------
Traceback (most recent call last):
  File "text_analyzer.py", line 25, in test_function_runs
    analyze_text(self.filename)
TypeError: analyze_text() takes no arguments (1 given)

----------------------------------------------------------------------
Ran 1 test in 0.003s

FAILED (errors=1)

```

我们可以通过向`analyze_text()`添加一个参数来修复这个问题：

```py
# text_analyzer.py

def analyze_text(filename):
    pass

```

如果我们再次运行我们的测试，我们会再次通过：

```py
% python text_analyzer.py
.
----------------------------------------------------------------------
Ran 1 test in 0.003s

OK

```

我们仍然没有一个做任何有用事情的实现，但你可以开始看到测试如何驱动实现。

### 使用断言来测试行为

现在我们满意`analyze_text()`存在并接受正确数量的参数，让我们看看是否可以让它做真正的工作。我们首先想要的是函数返回文件中的行数，所以让我们定义那个测试：

```py
# text_analyzer.py

class TextAnalysisTests(unittest.TestCase):
    . . .
    def test_line_count(self):
        "Check that the line count is correct."
        self.assertEqual(analyze_text(self.filename), 4)

```

这里我们看到了我们的第一个断言示例。`TestCase`类有[许多断言方法](https://docs.python.org/3/library/unittest.html#assert-methods)，在这种情况下，我们使用`assertEqual()`来检查我们的函数计算的行数是否等于四。如果`analyze_text()`返回的值不等于四，这个断言将导致测试方法失败。如果我们运行我们的新测试，我们会看到这正是发生的：

```py
% python text_analyzer.py
.F
======================================================================
FAIL: test_line_count (__main__.TextAnalysisTests)
----------------------------------------------------------------------
Traceback (most recent call last):
  File "text_analyzer.py", line 28, in test_line_count
    self.assertEqual(analyze_text(self.filename), 4)
AssertionError: None != 4

----------------------------------------------------------------------
Ran 2 tests in 0.003s

FAILED (failures=1)

```

在这里我们看到我们现在运行了两个测试，其中一个通过了，而新的一个失败了，出现了`AssertionError`。

#### 计算行数

现在让我们暂时违反 TDD 规则，加快一点速度。首先我们将更新函数以返回文件中的行数：

```py
# text_analyzer.py

def analyze_text(filename):
    """Calculate the number of lines and characters in a file.

 Args:
 filename: The name of the file to analyze.

 Raises:
 IOError: If ``filename`` does not exist or can't be read.

 Returns: The number of lines in the file.
 """
    with open(filename, 'r') as f:
        return sum(1 for _ in f)

```

这个改变确实给了我们想要的结果^(33)：

```py
% python text_analyzer.py
..
----------------------------------------------------------------------
Ran 2 tests in 0.003s

OK

```

#### 计算字符

所以让我们添加一个我们想要的另一个功能的测试，即计算文件中字符的数量。由于`analyze_text()`现在应该返回两个值，我们将它返回一个元组，第一个位置是行数，第二个位置是字符数。我们的新测试看起来像这样：

```py
# text_analyzer.py

class TextAnalysisTests(unittest.TestCase):
    . . .
    def test_character_count(self):
        "Check that the character count is correct."
        self.assertEqual(analyze_text(self.filename)[1], 131)

```

并且如预期的那样失败了：

```py
% python text_analyzer.py
E..
======================================================================
ERROR: test_character_count (__main__.TextAnalysisTests)
----------------------------------------------------------------------
Traceback (most recent call last):
  File "text_analyzer.py", line 32, in test_character_count
    self.assertEqual(analyze_text(self.filename)[1], 131)
TypeError: 'int' object has no attribute '__getitem__'

----------------------------------------------------------------------
Ran 3 tests in 0.004s

FAILED (errors=1)

```

这个结果告诉我们它无法索引`analyze_text()`返回的整数。所以让我们修复`analyze_text()`以返回正确的元组：

```py
# text_analyzer.py

def analyze_text(filename):
    """Calculate the number of lines and characters in a file.

 Args:
 filename: The name of the file to analyze.

 Raises:
 IOError: If ``filename`` does not exist or can't be read.

 Returns: A tuple where the first element is the number of lines in
 the files and the second element is the number of characters.

 """
    lines = 0
    chars = 0
    with open(filename, 'r') as f:
        for line in f:
            lines += 1
            chars += len(line)
    return (lines, chars)

```

这修复了我们的新测试，但我们发现我们破坏了旧的测试：

```py
% python text_analyzer.py
..F
======================================================================
FAIL: test_line_count (__main__.TextAnalysisTests)
----------------------------------------------------------------------
Traceback (most recent call last):
  File "text_analyzer.py", line 34, in test_line_count
    self.assertEqual(analyze_text(self.filename), 4)
AssertionError: (4, 131) != 4

----------------------------------------------------------------------
Ran 3 tests in 0.004s

FAILED (failures=1)

```

幸运的是，这很容易修复，因为我们只需要在早期的测试中考虑新的返回类型：

```py
# text_analyzer.py

class TextAnalysisTests(unittest.TestCase):
    . . .
    def test_line_count(self):
        "Check that the line count is correct."
        self.assertEqual(analyze_text(self.filename)[0], 4)

```

现在一切又通过了：

```py
% python text_analyzer.py
...
----------------------------------------------------------------------
Ran 3 tests in 0.004s

OK

```

### 测试异常

我们还想测试的另一件事是，当`analyze_text()`传递一个不存在的文件名时，它会引发正确的异常，我们可以这样测试：

```py
# text_analyzer.py

class TextAnalysisTests(unittest.TestCase):
    . . .
    def test_no_such_file(self):
        "Check the proper exception is thrown for a missing file."
        with self.assertRaises(IOError):
            analyze_text('foobar')

```

在这里，我们使用了`TestCase.assertRaises()`断言。这个断言检查指定的异常类型——在这种情况下是`IOError`——是否从 with 块的主体中抛出。

由于`open()`对于不存在的文件引发`IOError`，我们的测试已经通过，无需进一步实现：

```py
% python text_analyzer.py
....
----------------------------------------------------------------------
Ran 4 tests in 0.004s

OK

```

### 测试文件是否存在

最后，我们可以通过编写一个测试来验证`analyze_text()`不会删除文件——这是对函数的合理要求！：

```py
# text_analyzer.py

class TextAnalysisTests(unittest.TestCase):
    . . .
    def test_no_deletion(self):
        "Check that the function doesn't delete the input file."
        analyze_text(self.filename)
        self.assertTrue(os.path.exists(self.filename))

```

`TestCase.assertTrue()` 检查传递给它的值是否评估为`True`。还有一个等效的`assertFalse()`，它对 false 值进行相同的测试。

正如你可能期望的那样，这个测试已经通过了：

```py
% python text_analyzer.py
.....
----------------------------------------------------------------------
Ran 5 tests in 0.002s

OK

```

所以现在我们有了一个有用的、通过的测试集！这个例子很小，但它演示了`unittest`模块的许多重要部分。`unittest`模块还有[更多的部分](https://docs.python.org/3/library/unittest.html)，但是你可以通过我们在这里看到的技术走得很远。

* * *

### 禅宗时刻

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-aprt/img/zen-in-the-face-of-ambiguity-refuse-the-temptation-to-guess.png)

猜测的诱惑，或者用一厢情愿的想法忽略模棱两可，可能会带来短期收益。但它往往会导致未来的混乱，以及难以理解和修复的错误。在进行下一个快速修复之前，问问自己需要什么信息才能正确地进行操作。

* * *

### 总结

+   `unittest`模块是一个开发可靠自动化测试的框架。

+   通过从`unittest.TestCase`继承来定义*测试用例*。

+   `unittest.main()`函数对于运行模块中的所有测试非常有用。

+   `setUp()`和`tearDown()`装置用于在每个测试方法之前和之后运行代码。

+   测试方法是通过在测试用例对象上创建以`test_`开头的方法名称来定义的。

+   各种`TestCase.assert...`方法可用于在不满足正确条件时使测试方法失败。

+   使用`TestCase.assertRaises()`在 with 语句中检查测试中是否抛出了正确的异常。


## 第十二章：使用 PDB 进行调试

即使有全面的自动化测试套件，我们仍然可能遇到需要调试器来弄清楚发生了什么的情况。幸运的是，Python 包含了一个强大的调试器，即标准库中的 PDB。PDB 是一个命令行调试器，如果您熟悉像 GDB 这样的工具，那么您已经对如何使用 PDB 有了一个很好的了解。

PDB 相对于其他 Python 调试器的主要优势在于，作为 Python 本身的一部分，PDB 几乎可以在 Python 存在的任何地方使用，包括将 Python 语言嵌入到较大系统中的专用环境，例如 ESRI 的*ArcGIS*地理信息系统。也就是说，使用所谓的*图形*调试器可能会更加舒适，例如*Jetbrains*的*PyCharm*或*Microsoft*的*Python Tools for Visual Studio*中包含的调试器。您应该随时跳过本章，直到熟悉 PDB 变得更加紧迫；您不会错过我们在本书中或在*Python 学徒*或*Python 大师*中依赖的任何内容。

PDB 与许多调试工具不同，它实际上并不是一个单独的程序，而是像任何其他 Python 模块一样的模块。您可以将`pdb`导入任何程序，并使用`set_trace()`函数调用启动调试器。此函数在程序执行的任何点开始调试器。

对于我们对 PDB 的第一次尝试，让我们使用 REPL 并使用`set_trace()`启动调试器：

```py
>>> import pdb
>>> pdb.set_trace()
--Return--
> <stdin>(1)<module>()->None
(Pdb)

```

您会看到在执行`set_trace()`后，您的提示从三个尖括号变为`(Pdb)`-这是您知道自己在调试器中的方式。

### 调试命令

我们要做的第一件事是查看调试器中有哪些命令，方法是键入`help`：

```py
(Pdb) help

Documented commands (type help <topic>):
========================================
EOF    cl         disable  interact  next     return  u          where
a      clear      display  j         p        retval  unalias
alias  commands   down     jump      pp       run     undisplay
args   condition  enable   l         print    rv      unt
b      cont       exit     list      q        s       until
break  continue   h        ll        quit     source  up
bt     d          help     longlist  r        step    w
c      debug      ignore   n         restart  tbreak  whatis

Miscellaneous help topics:
==========================
pdb  exec

```

这列出了几十个命令，其中一些你几乎在每个调试会话中都会使用，而另一些你可能根本不会使用。

您可以通过键入`help`后跟命令名称来获取有关命令的具体帮助。例如，要查看`continue`的功能，请键入`help continue`：

```py
    (Pdb) help continue
    c(ont(inue))
            Continue execution, only stop when a breakpoint is encountered.

```

命令名称中的奇怪括号告诉您，`continue`可以通过键入`c`、`cont`或完整单词`continue`来激活。了解常见 PDB 命令的快捷方式可以极大地提高您在调试时的舒适度和速度。

### 回文调试

我们将不列出所有常用的 PDB 命令，而是调试一个简单的函数。我们的函数`is_palindrome()`接受一个整数，并确定整数的数字是否是回文。回文是一个正向和反向都相同的序列。

我们要做的第一件事是创建一个新文件`palindrome.py`，其中包含以下代码：

```py
import unittest

def digits(x):
    """Convert an integer into a list of digits.

 Args:
 x: The number whose digits we want.

 Returns: A list of the digits, in order, of ``x``.

 >>> digits(4586378)
 [4, 5, 8, 6, 3, 7, 8]
 """

    digs = []
    while x != 0:
        div, mod = divmod(x, 10)
        digs.append(mod)
        x = mod
    digs.reverse()
    return digs

def is_palindrome(x):
    """Determine if an integer is a palindrome.

 Args:
 x: The number to check for palindromicity.

 Returns: True if the digits of ``x`` are a palindrome,
 False otherwise.

 >>> is_palindrome(1234)
 False
 >>> is_palindrome(2468642)
 True
 """
    digs = digits(x)
    for f, r in zip(digs, reversed(digs)):
        if f != r:
            return False
    return True

class Tests(unittest.TestCase):
    """Tests for the ``is_palindrome()`` function."""
    def test_negative(self):
        "Check that it returns False correctly."
        self.assertFalse(is_palindrome(1234))

    def test_positive(self):
        "Check that it returns True correctly."
        self.assertTrue(is_palindrome(1234321))

    def test_single_digit(self):
        "Check that it works for single digit numbers."
        for i in range(10):
            self.assertTrue(is_palindrome(i))

if __name__ == '__main__':
    unittest.main()

```

正如您所看到的，我们的代码有三个主要部分。第一个是`digits()`函数，它将整数转换为数字列表。

第二个是`is_palindrome()`函数，它首先调用`digits()`，然后检查结果列表是否是回文。

第三部分是一组单元测试。我们将使用这些测试来驱动程序。

正如您可能期望的，由于这是一个关于调试的部分，这段代码中有一个错误。我们将首先运行程序并注意到错误，然后我们将看看如何使用 PDB 来找到错误。

#### 使用 PDB 进行错误调试

因此，让我们运行程序。我们有三个测试希望运行，由于这是一个相对简单的程序，我们期望它运行得非常快：

```py
$ python palindrome.py

```

我们看到这个程序似乎运行了很长时间！如果您查看其内存使用情况，还会看到它随着运行时间的增加而增加。显然出现了问题，所以让我们使用 Ctrl-C 来终止程序。

让我们使用 PDB 来尝试理解这里发生了什么。由于我们不知道问题可能出在哪里，也不知道在哪里放置`set_trace()`调用，所以我们将使用命令行调用来在 PDB 的控制下启动程序：

```py
$ python -m pdb palindrome.py
> /Users/sixty_north/examples/palindrome.py(1)<module>()
-> import unittest
(Pdb)

```

在这里，我们使用了`-m`参数，告诉 Python 执行特定的模块 - 在这种情况下是 PDB - 作为脚本。其余的参数传递给该脚本。所以在这里，我们告诉 Python 执行 PDB 模块作为脚本，并将我们的错误文件的名称传递给它。

我们看到的是，我们立即进入了 PDB 提示符。指向`import unittest`的箭头告诉我们，这是我们继续执行时将执行的下一条语句。但是那条语句在哪里？

让我们使用`where`命令来找出：

```py
(Pdb) where
  /Library/Frameworks/Python.framework/Versions/3.5/lib/python3.5/bdb.py(387)run()
-> exec cmd in globals, locals
  <string>(1)<module>()
> /Users/sixty_north/examples/palindrome.py(1)<module>()
-> import unittest

```

`where`命令报告我们当前的调用堆栈，最近的帧在底部，我们可以看到 PDB 已经在`palindrome.py`的第一行暂停了执行。这强调了 Python 执行的一个重要方面，我们之前已经讨论过：一切都在运行时评估。在这种情况下，我们在`import`语句之前暂停了执行。

我们可以通过使用`next`命令执行此导入到下一条语句：

```py
(Pdb) next
> /Users/sixty_north/examples/palindrome.py(3)<module>()
-> def digits(x):
(Pdb)

```

我们看到这将我们带到`digits()`函数的`def`调用。当我们执行另一个`next`时，我们移动到`is_palindrome()`函数的定义：

```py
(Pdb) next
> /Users/sixty_north/examples/palindrome.py(12)<module>()
-> def is_palindrome(x):
(Pdb)

```

#### 使用采样查找无限循环

我们可以继续使用`next`来移动程序的执行，但由于我们不知道错误出在哪里，这可能不是一个非常有用的技术。相反，记住我们程序的问题是似乎一直在运行。这听起来很像一个无限循环！

因此，我们不是逐步执行我们的代码，而是让它执行，然后当我们认为我们可能在那个循环中时，我们将使用 Ctrl-C 中断回到调试器：

```py
(Pdb) cont
^C
Program interrupted. (Use 'cont' to resume).
> /Users/sixty_north/examples/palindrome.py(9)digits()
-> x = mod
(Pdb)

```

让程序运行几秒钟后，我们按下 Ctrl-C，这将停止程序并显示我们在`palindrome.py`的`digits()`函数中。如果我们想在那一行看到源代码，我们可以使用 PDB 命令`list`：

```py
(Pdb) list
  4       "Convert an integer into a list of digits."
  5       digs = []
  6       while x != 0:
  7           div, mod = divmod(x, 10)
  8           digs.append(mod)
  9  ->       x = mod
 10       return digs
 11
 12   def is_palindrome(x):
 13       "Determine if an integer is a palindrome."
 14       digs = digits(x)
(Pdb)

```

我们看到这确实是在一个循环内部，这证实了我们的怀疑可能涉及无限循环。

我们可以使用`return`命令尝试运行到当前函数的末尾。如果这不返回，我们将有非常强有力的证据表明这是一个无限循环：

```py
(Pdb) r

```

我们让它运行几秒钟，以确认我们从未退出该函数，然后我们按下 Ctrl-C。一旦我们回到 PDB 提示符，让我们使用`quit`命令退出 PDB：

```py
(Pdb) quit
%

```

#### 设置显式断点

由于我们知道问题出在`digits()`中，让我们使用之前提到的`pdb.set_trace()`函数在那里设置一个显式断点：

```py
def digits(x):
    """Convert an integer into a list of digits.

 Args:
 x: The number whose digits we want.

 Returns: A list of the digits, in order, of ``x``.

 >>> digits(4586378)
 [4, 5, 8, 6, 3, 7, 8]
 """

    import pdb; pdb.set_trace()

    digs = []
    while x != 0:
        div, mod = divmod(x, 10)
        digs.append(mod)
        x = mod
    digs.reverse()
    return digs

```

记住，`set_trace()`函数将停止执行并进入调试器。

所以现在我们可以执行我们的脚本，而不指定 PDB 模块：

```py
% python palindrome.py
> /Users/sixty_north/examples/palindrome.py(8)digits()
-> digs = []
(Pdb)

```

我们看到我们几乎立即进入 PDB 提示符，执行在我们的`digits()`函数的开始处暂停。

为了验证我们知道我们在哪里，让我们使用`where`来查看我们的调用堆栈：

```py
(Pdb) where
  /Users/sixty_north/examples/palindrome.py(35)<module>()
-> unittest.main()
  /Library/Frameworks/Python.framework/Versions/3.5/lib/python3.5/unittest/main.py(95\
)__init__()
-> self.runTests()
  /Library/Frameworks/Python.framework/Versions/3.5/lib/python3.5/unittest/main.py(22\
9)runTests()
-> self.result = testRunner.run(self.test)
  /Library/Frameworks/Python.framework/Versions/3.5/lib/python3.5/unittest/runner.py(\
151)run()
-> test(result)
  /Library/Frameworks/Python.framework/Versions/3.5/lib/python3.5/unittest/suite.py(7\
0)__call__()
-> return self.run(*args, **kwds)
  /Library/Frameworks/Python.framework/Versions/3.5/lib/python3.5/unittest/suite.py(1\
08)run()
-> test(result)
  /Library/Frameworks/Python.framework/Versions/3.5/lib/python3.5/unittest/suite.py(7\
0)__call__()
-> return self.run(*args, **kwds)
  /Library/Frameworks/Python.framework/Versions/3.5/lib/python3.5/unittest/suite.py(1\
08)run()
-> test(result)
  /Library/Frameworks/Python.framework/Versions/3.5/lib/python3.5/unittest/case.py(39\
1)__call__()
-> return self.run(*args, **kwds)
  /Library/Frameworks/Python.framework/Versions/3.5/lib/python3.5/unittest/case.py(32\
7)run()
-> testMethod()
  /Users/sixty_north/examples/palindrome.py(25)test_negative()
-> self.assertFalse(is_palindrome(1234))
  /Users/sixty_north/examples/palindrome.py(17)is_palindrome()
-> digs = digits(x)
> /Users/sixty_north/examples/palindrome.py(8)digits()
-> digs = []

```

记住，最近的帧在此列表的末尾。经过很多`unittest`函数后，我们看到我们确实在`digits()`函数中，并且它是由`is_palindrome()`调用的，正如我们所预期的那样。

#### 逐步执行

现在我们要做的是观察执行，并看看为什么我们从未退出这个函数的循环。让我们使用`next`移动到循环体的第一行：

```py
(Pdb) next
> /Users/sixty_north/examples/palindrome.py(9)digits()
-> while x != 0:
(Pdb) next
> /Users/sixty_north/examples/palindrome.py(10)digits()
-> div, mod = divmod(x, 10)
(Pdb)

```

现在让我们看一下一些变量的值，并尝试决定我们期望发生什么。我们可以使用`print`命令来检查值^(34)：

```py
(Pdb) print(digs)
[]
(Pdb) print x
1234

```

这看起来是正确的。`digs`列表 - 最终将包含数字序列 - 是空的，`x`是我们传入的。我们期望`divmod()`函数返回`123`和`4`，所以让我们试试看：

```py
(Pdb) next
> /Users/sixty_north/examples/palindrome.py(11)digits()
-> digs.append(mod)
(Pdb) print div,mod
123 4

```

这看起来正确：`divmod()`已经从我们的数字中剪掉了最低有效位数字，下一行将该数字放入我们的结果列表中：

```py
(Pdb) next
> /Users/sixty_north/examples/palindrome.py(12)digits()
-> x = mod

```

如果我们查看`digs`，我们会看到它现在包含`mod`：

```py
(Pdb) print digs
[4]

```

下一行现在将更新`x`，以便我们可以继续从中剪切数字：

```py
(Pdb) next
> /Users/sixty_north/examples/palindrome.py(9)digits()
-> while x != 0:

```

我们看到执行回到了 while 循环，正如我们所预期的那样。让我们查看`x`，确保它有正确的值：

```py
(Pdb) print x
4

```

等一下！我们期望`x`保存的是不在结果列表中的数字。相反，它只包含结果列表中的数字。显然我们在更新`x`时犯了一个错误！

如果我们查看我们的代码，很快就会发现我们应该将`div`而不是`mod`分配给`x`。让我们退出 PDB：

```py
(Pdb) quit

```

请注意，由于 PDB 和`unittest`的交互方式，您可能需要运行几次`quit`。

#### 修复错误

当您退出 PDB 后，让我们删除`set_trace()`调用并修改`digits()`来解决我们发现的问题：

```py
def digits(x):
    """Convert an integer into a list of digits.

    Args:
      x: The number whose digits we want.

    Returns: A list of the digits, in order, of ``x``.

    >>> digits(4586378)
    [4, 5, 8, 6, 3, 7, 8]
    """

    digs = []
    while x != 0:
        div, mod = divmod(x, 10)
        digs.append(mod)
        x = div
    digs.reverse()
    return digs

```

如果我们现在运行我们的程序，我们会看到我们通过了所有的测试，并且运行非常快：

```py
$ python palindrome.py
...
----------------------------------------------------------------------
Ran 3 tests in 0.001s

OK

```

这就是一个基本的 PDB 会话，并展示了 PDB 的一些核心特性。然而，PDB 还有许多其他命令和特性，学习它们的最佳方法是开始使用 PDB 并尝试这些命令。这个回文程序可以作为学习 PDB 大多数特性的一个很好的例子。

### 总结

+   Python 的标准调试器称为 PDB。

+   PDB 是一个标准的命令行调试器。

+   `pdb.set_trace()`方法可用于停止程序执行并进入调试器。

+   当您处于调试器中时，您的 REPL 提示将更改为（Pdb）。

+   您可以通过输入“help”来访问 PDB 的内置帮助系统。

+   您可以使用`python -m pdb`后跟脚本名称来从头开始在 PDB 下运行程序。

+   PDB 的`where`命令显示当前的调用堆栈。

+   PDB 的`next`命令让执行继续到下一行代码。

+   PDB 的`continue`命令让程序执行无限期地继续，或者直到您使用 control-c 停止它。

+   PDB 的`list`命令显示您当前位置的源代码。

+   PDB 的`return`命令恢复执行，直到当前函数的末尾。

+   PDB 的`print`命令让您在调试器中查看对象的值。

+   使用`quit`退出 PDB。

在这个过程中，我们发现：

+   `divmod()`可以一次计算除法运算的商和余数。

+   `reversed()`函数可以反转一个序列。

+   您可以通过在 Python 命令后传递`-m`来使其作为脚本运行一个模块。

+   调试使得清楚 Python 在运行时评估一切。
