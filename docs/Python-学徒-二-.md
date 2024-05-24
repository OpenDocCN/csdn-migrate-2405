# Python 学徒（二）

> 原文：[`zh.annas-archive.org/md5/4702C628AD6B03CA92F1B4B8E471BB27`](https://zh.annas-archive.org/md5/4702C628AD6B03CA92F1B4B8E471BB27)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

## 第四章：模块化

模块化对于除了微不足道的软件系统以外的任何东西都是一个重要的属性，因为它赋予我们能力去创建自包含、可重复使用的部分，这些部分可以以新的方式组合来解决不同的问题。在 Python 中，与大多数编程语言一样，最细粒度的模块化设施是可重复使用函数的定义。但是 Python 还给了我们几种其他强大的模块化机制。

相关函数的集合本身被组合在一起形成了一种称为*模块*的模块化形式。模块是可以被其他模块引用的源代码文件，允许在一个模块中定义的函数在另一个模块中被重用。只要你小心避免任何循环依赖，模块是组织程序的一种简单灵活的方式。

在之前的章节中，我们已经看到我们可以将模块导入 REPL。我们还将向您展示模块如何直接作为程序或脚本执行。作为这一部分的一部分，我们将调查 Python 执行模型，以确保您对代码何时被评估和执行有一个很好的理解。我们将通过向您展示如何使用命令行参数将基本配置数据传递到您的程序中并使您的程序可执行来结束本章。

为了说明本章，我们将从上一章末尾开发的从网络托管的文本文档中检索单词的代码片段开始。我们将通过将代码组织成一个完整的 Python 模块来详细说明该代码。

### 在一个.py 文件中组织代码

让我们从第二章中我们使用的代码片段开始。打开一个文本编辑器 - 最好是一个支持 Python 语法高亮的编辑器 - 并配置它在按下 tab 键时插入四个空格的缩进级别。你还应该检查你的编辑器是否使用 UTF 8 编码保存文件，因为这是 Python 3 运行时的默认设置。

在你的主目录下创建一个名为`pyfund`的目录。这是我们将放置本章代码的地方。

所有的 Python 源文件都使用`.py`扩展名，所以让我们把我们在 REPL 中写的片段放到一个名为`pyfund/words.py`的文本文件中。文件的内容应该是这样的：

```py
from urllib.request import urlopen

with urlopen('http://sixty-north.com/c/t.txt') as story:
    story_words = []
    for line in story:
        line_words = line.decode('utf-8').split()
        for word in line_words:
            story_words.append(word)

```

你会注意到上面的代码和我们之前在 REPL 中写的代码之间有一些细微的差异。现在我们正在使用一个文本文件来编写我们的代码，所以我们可以更加注意可读性，例如，在`import`语句后我们加了一个空行。

在继续之前保存这个文件。

#### 从操作系统 shell 运行 Python 程序

切换到带有操作系统 shell 提示符的控制台，并切换到新的`pyfund`目录：

```py
$ cd pyfund

```

我们可以通过调用 Python 并传递模块的文件名来执行我们的模块：

```py
$ python3 words.py

```

在 Mac 或 Linux 上，或者：

```py
> python words.py

```

在 Windows 上。

当你按下回车键后，经过短暂的延迟，你将返回到系统提示符。并不是很令人印象深刻，但如果你没有得到任何响应，那么程序正在按预期运行。另一方面，如果你看到一些错误，那么就有问题了。例如，`HTTPError`表示有网络问题，而其他类型的错误可能意味着你输入了错误的代码。

让我们在程序的末尾再添加一个 for 循环，每行打印一个单词。将这段代码添加到你的 Python 文件的末尾：

```py
for word in story_words:
    print(word)

```

如果你去命令提示符并再次执行代码，你应该会看到一些输出。现在我们有了一个有用程序的开端！

#### 将模块导入到 REPL 中

我们的模块也可以导入到 REPL 中。让我们试试看会发生什么。启动 REPL 并导入你的模块。当导入一个模块时，你使用`import <module-name>`，省略模块名称的`.py`扩展名。在我们的情况下，看起来是这样的：

```py
$ python
Python 3.5.0 (default, Nov  3 2015, 13:17:02)
[GCC 4.2.1 Compatible Apple LLVM 6.1.0 (clang-602.0.53)] on darwin
Type "help", "copyright", "credits" or "license" for more information.
>>> import words
It
was
the
best
of
times
. . .

```

当导入模块时，模块中的代码会立即执行！这也许不是你期望的，而且肯定不是很有用。为了更好地控制代码的执行时间，并允许其被重用，我们需要将代码放入一个函数中。

### 定义函数

使用`def`关键字定义函数，后面跟着函数名、括号中的参数列表和一个冒号来开始一个新的块。让我们在 REPL 中快速定义一些函数来了解一下：

```py
>>> def square(x):
...     return x * x
...

```

我们使用`return`关键字从函数中返回一个值。

正如我们之前所看到的，我们通过在函数名后的括号中提供实际参数来调用函数：

```py
>>> square(5)
5

```

函数并不需要显式返回一个值 - 也许它们会产生副作用：

```py
>>> def launch_missiles():
...     print("Missiles launched!")
...
>>> launch_missiles()
Missiles launched!

```

您可以使用`return`关键字而不带参数来提前从函数中返回：

```py
>>> def even_or_odd(n):
...     if n % 2 == 0:
...         print("even")
...         return
...     print("odd")
...
>>> even_or_odd(4)
even
>>> even_or_odd(5)
odd

```

如果函数中没有显式的`return`，Python 会在函数末尾隐式添加一个`return`。这个隐式的返回，或者没有参数的`return`，实际上会导致函数返回`None`。不过要记住，REPL 不会显示`None`结果，所以我们看不到它们。通过将返回的对象捕获到一个命名变量中，我们可以测试是否为`None`：

```py
>>> w = even_or_odd(31)
odd
>>> w is None
True

```

### 将我们的模块组织成函数

让我们使用函数来组织我们的 words 模块。

首先，我们将除了导入语句之外的所有代码移动到一个名为`fetch_words()`的函数中。您可以通过添加`def`语句并将其下面的代码缩进一级来实现这一点：

```py
from urllib.request import urlopen

def fetch_words():
    with urlopen('http://sixty-north.com/c/t.txt') as story:
        story_words = []
        for line in story:
            line_words = line.decode('utf-8').split()
            for word in line_words:
                story_words.append(word)

    for word in story_words:
        print(word)

```

保存模块，并使用新的 Python REPL 重新加载模块：

```py
$ python3
Python 3.5.0 (default, Nov  3 2015, 13:17:02)
[GCC 4.2.1 Compatible Apple LLVM 6.1.0 (clang-602.0.53)] on darwin
Type "help", "copyright", "credits" or "license" for more information.
>>> import words

```

模块已导入，但直到我们调用`fetch_words()`函数时，单词才会被获取：

```py
>>> words.fetch_words()
It
was
the
best
of
times

```

或者我们可以导入我们的特定函数：

```py
>>> from words import fetch_words
>>> fetch_words()
It
was
the
best
of
times

```

到目前为止一切都很好，但当我们尝试直接从操作系统 shell 运行我们的模块时会发生什么？

从 Mac 或 Linux 使用`Ctrl-D`退出 REPL，或者从 Windows 使用`Ctrl-Z`，然后运行 Python 3 并传递模块文件名：

```py
$ python3 words.py

```

没有单词被打印。这是因为现在模块所做的只是定义一个函数，然后立即退出。为了创建一个我们可以有用地从中导入函数到 REPL *并且*可以作为脚本运行的模块，我们需要学习一个新的 Python 习惯用法。

#### `__name__`和从命令行执行模块

Python 运行时系统定义了一些特殊变量和属性，它们的名称由双下划线分隔。其中一个特殊变量叫做`__name__`，它为我们的模块提供了一种方式来确定它是作为脚本运行还是被导入到另一个模块或 REPL 中。要查看如何操作，请添加：

```py
print(__name__)

```

在`fetch_words()`函数之外的模块末尾添加。

首先，让我们将修改后的 words 模块重新导入到 REPL 中：

```py
$ python3
Python 3.5.0 (default, Nov  3 2015, 13:17:02)
[GCC 4.2.1 Compatible Apple LLVM 6.1.0 (clang-602.0.53)] on darwin
Type "help", "copyright", "credits" or "license" for more information.
>>> import words
words

```

我们可以看到，当导入`__name__`时，它确实会评估为模块的名称。

顺便说一句，如果再次导入模块，print 语句将*不会*被执行；模块代码只在第一次导入时执行一次：

```py
>>> import words
>>>

```

现在让我们尝试将模块作为脚本运行：

```py
$ python3 words.py
__main__

```

在这种情况下，特殊的`__name__`变量等于字符串“**main**”，也由双下划线分隔。我们的模块可以利用这种行为来检测它的使用方式。我们用一个 if 语句替换 print 语句，该语句测试`__name__`的值。如果值等于“**main**”，那么我们的函数就会被执行：

```py
if __name__ == '__main__':
    fetch_words()

```

现在我们可以安全地导入我们的模块，而不会过度执行我们的函数：

```py
$ python3
>>> import words
>>>

```

我们可以有用地将我们的函数作为脚本运行：

```py
$ python3 words.py
It
was
the
best
of
times

```

### Python 执行模型

为了在 Python 中有一个真正坚实的基础，了解 Python 的*执行模型*是很重要的。我们指的是定义模块导入和执行期间发生的函数定义和其他重要事件的规则。为了帮助你发展这种理解，我们将专注于`def`关键字，因为你已经熟悉它。一旦你了解了 Python 如何处理`def`，你就会知道大部分关于 Python 执行模型的知识。

重要的是要理解这一点：**`def`不仅仅是一个声明，它是一个*语句***。这意味着`def`实际上是在运行时执行的，与其他顶层模块范围代码一起。`def`的作用是将函数体中的代码绑定到`def`后面的名称。当模块被导入或运行时，所有顶层语句都会运行，这是模块命名空间中的函数定义的方式。

重申一下，`def`是在运行时执行的。这与许多其他语言中处理函数定义的方式非常不同，特别是在编译语言如 C++、Java 和 C#中。在这些语言中，函数定义是由编译器在*编译时*处理的，而不是在运行时。^(4)实际执行程序时，这些函数定义已经固定。在 Python 中没有编译器^(5)，函数在执行之前并不存在任何形式，除了源代码。事实上，由于函数只有在导入时处理其`def`时才被定义，因此在从未导入的模块中的函数将永远不会被定义。

理解 Python 函数定义的这种动态特性对于后面本书中的重要概念至关重要，所以确保你对此感到舒适。如果你有 Python 调试器，比如在 IDE 中，你可以花一些时间逐步执行你的`words.py`模块。

#### 模块、脚本和程序之间的区别

有时我们会被问及 Python 模块、Python 脚本和 Python 程序之间的区别。任何`.py`文件都构成一个 Python 模块，但正如我们所见，模块可以被编写为方便导入、方便执行，或者使用`if __name__ == "__main__"`的习惯用法，两者兼而有之。

我们强烈建议即使是简单的脚本也要可导入，因为如果可以从 Python REPL 访问代码，这样可以极大地简化开发和测试。同样，即使是只在生产环境中导入的模块也会受益于具有可执行的测试代码。因此，我们创建的几乎所有模块都采用了定义一个或多个可导入函数的形式，并附有后缀以便执行。

将模块视为 Python 脚本或 Python 程序取决于上下文和用法。将 Python 仅视为脚本工具是错误的，因为许多大型复杂的应用程序都是专门使用 Python 构建的，而不是像 Windows 批处理文件或 Unix shell 脚本那样。

### 设置带有命令行参数的主函数

让我们进一步完善我们的单词获取模块。首先，我们将进行一些小的重构，将单词检索和收集与单词打印分开：

```py
from urllib.request import urlopen

# This fetches the words and returns them as a list.
def fetch_words():
    with urlopen('http://sixty-north.com/c/t.txt') as story:
        story_words = []
        for line in story:
            line_words = line.decode('utf-8').split()
            for word in line_words:
                story_words.append(word)
    return story_words

# This prints a list of words
def print_words(story_words):
    for word in story_words:
      print(word)

if __name__ == '__main__':
    words = fetch_words()
    print_words(words)

```

我们这样做是因为它分离了两个重要的关注点：在导入时，我们宁愿得到单词列表，但在直接运行时，我们更希望单词被打印出来。

接下来，我们将从`if __name__ == '__main__'`块中提取代码到一个名为`main()`的函数中：

```py
def main():
    words = fetch_words()
    print_words(words)

if __name__ == '__main__':
    main()

```

通过将这段代码移到一个函数中，我们可以在 REPL 中测试它，而在模块范围的 if 块中是不可能的。

现在我们可以在 REPL 中尝试这些函数：

```py
>>> from words import (fetch_words, print_words)
>>> print_words(fetch_words())

```

我们利用这个机会介绍了`import`语句的一些新形式。第一种新形式使用逗号分隔的列表从模块中导入多个对象。括号是可选的，但如果列表很长，它们可以允许您将此列表分成多行。这种形式可能是最广泛使用的`import`语句的形式之一。

第二种新形式使用星号通配符从模块中导入所有内容：

```py
>>> from words import *

```

后一种形式仅建议在 REPL 上进行临时使用。它可能会在程序中造成严重破坏，因为导入的内容现在可能超出您的控制范围，从而在将来可能导致潜在的命名空间冲突。

完成这些后，我们可以从 URL 获取单词：

```py
>>> fetch_words()
['It', 'was', 'the', 'best', 'of', 'times', 'it', 'was', 'the', 'worst',
'of', 'times', 'it', 'was', 'the', 'age', 'of', 'wisdom', 'it', 'was',
'the', 'age', 'of', 'foolishness', 'it', 'was', 'the', 'epoch', 'of',
'belief', 'it', 'was', 'the', 'epoch', 'of', 'incredulity', 'it', 'was',
'the', 'season', 'of', 'Light', 'it', 'was', 'the', 'season', 'of',
'Darkness', 'it', 'was', 'the', 'spring', 'of', 'hope', 'it', 'was', 'the',
'winter', 'of', 'despair', 'we', 'had', 'everything', 'before', 'us', 'we',
'had', 'nothing', 'before', 'us', 'we', 'were', 'all', 'going', 'direct',
'to', 'Heaven', 'we', 'were', 'all', 'going', 'direct', 'the', 'other',
'way', 'in', 'short', 'the', 'period', 'was', 'so', 'far', 'like', 'the',
'present', 'period', 'that', 'some', 'of', 'its', 'noisiest', 'authorities',
'insisted', 'on', 'its', 'being', 'received', 'for', 'good', 'or', 'for',
'evil', 'in', 'the', 'superlative', 'degree', 'of', 'comparison', 'only']

```

由于我们已将获取代码与打印代码分开，因此我们还可以打印*任何*单词列表：

```py
>>> print_words(['Any', 'list', 'of', 'words'])
Any
list
of
words

```

事实上，我们甚至可以运行主程序：

```py
>>> main()
It
was
the
best
of
times

```

请注意，`print_words()`函数对列表中的项目类型并不挑剔。它可以很好地打印数字列表：

```py
>>> print_words([1, 7, 3])
1
7
3

```

因此，也许`print_words()`不是最好的名称。实际上，该函数也没有提到列表-它可以很高兴地打印任何 for 循环能够迭代的集合，例如字符串：

```py
>>> print_words("Strings are iterable too")
S
t
r
i
n
g
s

a
r
e

i
t
e
r
a
b
l
e

t
o
o

```

因此，让我们进行一些小的重构，并将此函数重命名为`print_items()`，并相应地更改函数内的变量名：

```py
def print_items(items):
    for item in items:
        print(item)

```

最后，对我们的模块的一个明显改进是用一个可以传递的值替换硬编码的 URL。让我们将该值提取到`fetch_words()`函数的参数中：

```py
def fetch_words(url):
    with urlopen(url) as story:
        story_words = []
        for line in story:
            line_words = line.decode('utf-8').split()
            for word in line_words:
                story_words.append(word)
    return story_words

```

#### 接受命令行参数

最后一次更改实际上破坏了我们的`main()`，因为它没有传递新的`url`参数。当我们将模块作为独立程序运行时，我们需要接受 URL 作为命令行参数。在 Python 中访问命令行参数是通过`sys`模块的一个属性`argv`，它是一个字符串列表。要使用它，我们必须首先在程序顶部导入`sys`模块：

```py
import sys

```

然后我们从列表中获取第二个参数（索引为 1）：

```py
def main():
    url = sys.argv[1]
    words = fetch_words(url)
    print_items(words)

```

当然，这按预期工作：

```py
$ python3 words.py http://sixty-north.com/c/t.txt
It
was
the
best
of
times

```

这看起来很好，直到我们意识到我们无法从 REPL 有用地测试`main()`，因为它引用`sys.argv[1]`，在该环境中这个值不太可能有用：

```py
$ python3
Python 3.5.0 (default, Nov  3 2015, 13:17:02)
[GCC 4.2.1 Compatible Apple LLVM 6.1.0 (clang-602.0.53)] on darwin
Type "help", "copyright", "credits" or "license" for more information.
>>> from words import *
>>> main()
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
  File "/Users/sixtynorth/projects/sixty-north/the-python-apprentice/manuscript/code/\
pyfund/words.py", line 21, in main
    url = sys.argv[1]
IndexError: list index out of range
>>>

```

解决方案是允许将参数列表作为`main()`函数的形式参数传递，使用`sys.argv`作为`if __name__ == '__main__'`块中的实际参数：

```py
def main(url):
    words = fetch_words(url)
    print_items(words)

if __name__ == '__main__':
    main(sys.argv[1])

```

再次从 REPL 进行测试，我们可以看到一切都按预期工作：

```py
>>> from words import *
>>> main("http://sixty-north.com/c/t.txt")
It
was
the
best
of
times

```

Python 是开发命令行工具的好工具，您可能会发现您需要处理许多情况的命令行参数。对于更复杂的命令行处理，我们建议您查看[Python 标准库`argparse`](https://docs.python.org/3/library/argparse.html)模块或[受启发的第三方`docopt`模块](http://docopt.org/)。

* * *

### 禅意时刻

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-aprt/img/zen-sparse-is-better-than-dense.png)

您会注意到我们的顶级函数之间有两个空行。这是现代 Python 代码的传统。

根据[PEP 8 风格指南](https://www.python.org/dev/peps/pep-0008/)，在模块级函数之间使用两个空行是习惯的。我们发现这种约定对我们有所帮助，使代码更容易导航。同样，我们在函数内使用单个空行进行逻辑分隔。

* * *

### 文档字符串

我们之前看到了如何在 REPL 上询问 Python 函数的帮助。让我们看看如何将这种自我记录的能力添加到我们自己的模块中。

Python 中的 API 文档使用一种称为*docstrings*的设施。 Docstrings 是出现在命名块（例如函数或模块）的第一条语句中的文字字符串。让我们记录`fetch_words()`函数：

```py
def fetch_words(url):
    """Fetch a list of words from a URL."""
    with urlopen(url) as story:
        story_words = []
        for line in story:
            line_words = line.decode('utf-8').split()
            for word in line_words:
                story_words.append(word)
    return story_words

```

我们甚至使用三引号字符串来编写单行文档字符串，因为它们可以很容易地扩展以添加更多细节。

Python 文档字符串的一个约定在[PEP 257](https://www.python.org/dev/peps/pep-0257/)中有记录，尽管它并没有被广泛采用。各种工具，如[Sphinx](http://www.sphinx-doc.org/)，可用于从 Python 文档字符串构建 HTML 文档，每个工具都规定了其首选的文档字符串格式。我们的首选是使用[Google 的 Python 风格指南](https://google.github.io/styleguide/pyguide.html)中提出的形式，因为它适合被机器解析，同时在控制台上仍然可读：

```py
def fetch_words(url):
    """Fetch a list of words from a URL.

 Args:
 url: The URL of a UTF-8 text document.

 Returns:
 A list of strings containing the words from
 the document.
 """
    with urlopen(url) as story:
        story_words = []
        for line in story:
            line_words = line.decode('utf-8').split()
            for word in line_words:
                story_words.append(word)
    return story_words

```

现在我们将从 REPL 中访问这个`help()`：

```py
$ python3
Python 3.5.0 (default, Nov  3 2015, 13:17:02)
[GCC 4.2.1 Compatible Apple LLVM 6.1.0 (clang-602.0.53)] on darwin
Type "help", "copyright", "credits" or "license" for more information.
>>> from words import *
>>> help(fetch_words)

Help on function fetch_words in module words:

fetch_words(url)
    Fetch a list of words from a URL.

    Args:
        url: The URL of a UTF-8 text document.

    Returns:
        A list of strings containing the words from
        the document.
(END)

```

我们将为其他函数添加类似的文档字符串：

```py
def print_items(items):
    """Print items one per line.

 Args:
 items: An iterable series of printable items.
 """
    for item in items:
        print(item)

def main(url):
    """Print each word from a text document from at a URL.

 Args:
 url: The URL of a UTF-8 text document.
 """
    words = fetch_words(url)
    print_items(words)

```

以及模块本身的文档字符串。模块文档字符串应放在模块的开头，任何语句之前：

```py
"""Retrieve and print words from a URL.

Usage:

 python3 words.py <URL>
"""

import sys
from urllib.request import urlopen

```

现在当我们在整个模块上请求`help()`时，我们会得到相当多有用的信息：

```py
$ python3
Python 3.5.0 (default, Nov  3 2015, 13:17:02)
[GCC 4.2.1 Compatible Apple LLVM 6.1.0 (clang-602.0.53)] on darwin
Type "help", "copyright", "credits" or "license" for more information.
>>> import words
>>> help(words)

Help on module words:

NAME
    words - Retrieve and print words from a URL.

DESCRIPTION
    Usage:

        python3 words.py <URL>

FUNCTIONS
    fetch_words(url)
        Fetch a list of words from a URL.

        Args:
            url: The URL of a UTF-8 text document.

        Returns:
            A list of strings containing the words from
            the document.

    main(url)
        Print each word from a text document from at a URL.

        Args:
            url: The URL of a UTF-8 text document.

    print_items(items)
        Print items one per line.

        Args:
            items: An iterable series of printable items.

FILE
    /Users/sixtynorth/the-python-apprentice/words.py

(END)

```

### 注释

我们认为文档字符串是 Python 代码中大多数文档的正确位置。它们解释了如何使用模块提供的功能，而不是它的工作原理。理想情况下，您的代码应该足够清晰，不需要辅助解释。尽管如此，有时需要解释为什么选择了特定的方法或使用了特定的技术，我们可以使用 Python 注释来做到这一点。Python 中的注释以`#`开头，直到行尾。

作为演示，让我们记录这样一个事实，即为什么我们在调用`main()`时使用`sys.argv[1]`而不是`sys.argv[0]`可能不是立即明显的：

```py
if __name__ == '__main__':
    main(sys.argv[1])  # The 0th arg is the module filename.

```

### Shebang

在类 Unix 系统上，脚本的第一行通常包括一个特殊的注释`#!`，称为*shebang*。这允许程序加载器识别应该使用哪个解释器来运行程序。Shebang 还有一个额外的目的，方便地在文件顶部记录 Python 代码是 Python 2 还是 Python 3。

您的 shebang 命令的确切细节取决于系统上 Python 的位置。典型的 Python 3 shebang 使用 Unix 的`env`程序来定位您的`PATH`环境变量上的 Python 3，这一点非常重要，它与 Python 虚拟环境兼容：

```py
#!/usr/bin/env python3

```

#### Linux 和 Mac 上可执行的 Python 程序

在 Mac 或 Linux 上，我们必须在 shebang 生效之前使用`chmod`命令将脚本标记为可执行：

```py
$ chmod +x words.py

```

做完这些之后，我们现在可以直接运行我们的脚本：

```py
$ ./words.py http://sixty-north.com/c/t.txt

```

#### Windows 上可执行的 Python 程序

从 Python 3.3 开始，Windows 上的 Python 也支持使用 shebang 来使 Python 脚本直接可执行，即使看起来只能在类 Unix 系统上正常工作的 shebang 也会在 Windows 上按预期工作。这是因为 Windows Python 发行版现在使用一个名为*PyLauncher*的程序。 PyLauncher 的可执行文件名为`py.exe`，它将解析 shebang 并找到适当版本的 Python。

例如，在 Windows 的`cmd`提示符下，这个命令就足以用 Python 3 运行你的脚本（即使你也安装了 Python 2）：

```py
> words.py http://sixty-north.com/c/t.txt

```

在 Powershell 中，等效的是：

```py
PS> .\words.py http://sixty-north.com/c/t.txt

```

您可以在[PEP 397](https://www.python.org/dev/peps/pep-0397/)中了解更多关于 PyLauncher 的信息。

### 总结

+   Python 模块：

+   Python 代码放在名为模块的`*.py`文件中。

+   模块可以通过将它们作为 Python 解释器的第一个参数直接执行。

+   模块也可以被导入到 REPL 中，此时模块中的所有顶级语句将按顺序执行。

+   Python 函数：

+   使用`def`关键字定义命名函数，后面跟着函数名和括号中的参数列表。

+   我们可以使用`return`语句从函数中返回对象。

+   没有参数的返回语句返回`None`，在每个函数体的末尾也是如此。

+   模块执行：

+   我们可以通过检查特殊的`__name__`变量的值来检测模块是否已导入或执行。如果它等于字符串`"__main__"`，我们的模块已直接作为程序执行。通过在模块末尾使用顶层`if __name__ == '__main__'`习语来执行函数，如果满足这个条件，我们的模块既可以被有用地导入，又可以被执行，这是一个重要的测试技术，即使对于短脚本也是如此。

+   模块代码只在第一次导入时执行一次。

+   `def`关键字是一个语句，将可执行代码绑定到函数名。

+   命令行参数可以作为字符串列表访问，通过`sys`模块的`argv`属性。零号命令行参数是脚本文件名，因此索引为 1 的项是第一个真正的参数。

+   Python 的动态类型意味着我们的函数可以非常通用，关于它们参数的类型。

+   文档字符串：

+   作为函数定义的第一行的文字字符串形成函数的文档字符串。它们通常是包含使用信息的三引号多行字符串。

+   在 REPL 中，可以使用`help()`检索文档字符串中提供的函数文档。

+   模块文档字符串应放置在模块的开头，先于任何 Python 语句，如导入语句。

+   注释：

+   Python 中的注释以井号字符开头，并延续到行尾。

+   模块的第一行可以包含一个特殊的注释，称为 shebang，允许程序加载器在所有主要平台上启动正确的 Python 解释器。


## 第五章：内置类型和对象模型

Python 语言最基本的设计元素之一是其对*对象*的使用。对象不仅是用户级构造的中心数据结构，也是语言本身许多内部工作的中心数据结构。在本章中，我们将开始发展对这一概念的理解，无论是在原则上还是在实践中，希望您开始意识到对象在整个 Python 中是多么普遍。

我们将看看对象是什么，如何使用它们以及如何管理对它们的引用。我们还将开始探索 Python 中*类型*的概念，并且我们将看到 Python 的类型既类似于许多其他流行语言中的类型，又有所不同。作为这一探索的一部分，我们将更深入地了解一些我们已经遇到的集合类型，并介绍一些其他集合类型。

### Python 对象引用的性质

在之前的章节中，我们已经讨论并在 Python 中使用了“变量”，但变量到底是什么？考虑将整数分配给变量这样简单的事情：

```py
>>> x = 1000

```

当我们这样做时，实际上发生了什么？首先，Python 创建了一个值为`1000`的`int` *对象*。这个对象在本质上是匿名的，因为它本身没有名称（`x`或其他）。它是由 Python 运行时系统分配和跟踪的对象。

创建对象后，Python 创建了一个名为`x`的*对象引用*，并安排`x` ^(6)指向`int(1000)`对象：

![将名称'x'分配给一个值为 1000 的整数对象](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-aprt/img/x_equals_1000.png)

将名称‘x’分配给一个值为 1000 的整数对象

#### 重新分配引用

现在我们将使用另一个赋值来修改`x`的值：

```py
>>> x = 500

```

这**不会**导致我们之前构造的`int(1000)`对象的任何更改。Python 中的整数对象是不可变的，不能被更改。实际上，这里发生的是 Python 首先创建一个新的不可变整数对象，其值为 500，然后将`x`引用重定向到新对象：

![将名称'x'重新分配给一个值为 500 的新整数对象](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-aprt/img/x_equals_500.png)

重新将名称‘x’分配给一个值为 500 的新整数对象

由于我们没有对原始`int(1000)`对象的其他引用，我们现在无法从我们的代码中访问它。因此，Python 垃圾收集器可以在选择时收集它。^(7)

#### 分配一个引用给另一个引用

当我们从一个变量分配到另一个变量时，我们实际上是从一个对象引用分配到另一个对象引用，这样两个引用就指向同一个对象。例如，让我们将现有变量`x`分配给一个新变量`y`：

```py
>>> y = x

```

这给我们了这个引用对象图：

![将现有名称'x'分配给名称'y'](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-aprt/img/y_equals_x.png)

将现有名称“x”分配给名称“y”

现在两个引用都指向同一个对象。我们现在将`x`重新分配给另一个新的整数：

```py
>>> x = 3000

```

这样做会给我们一个引用对象图，显示我们的两个引用和两个对象：

![将一个新的整数 3000 分配给'x'](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-aprt/img/x_equals_3000.png)

将一个新的整数 3000 分配给‘x’

在这种情况下，垃圾收集器没有工作要做，因为所有对象都可以从活动引用中访问。

#### 使用`id()`探索值与标识的差异

让我们使用内置的`id()`函数深入探讨对象和引用之间的关系。`id()`接受任何对象作为参数，并返回一个整数标识符，该标识符对于对象的整个生命周期是唯一且恒定的。让我们使用`id()`重新运行先前的实验：

```py
>>> a = 496
>>> id(a)
4302202064
>>> b = 1729
>>> id(b)
4298456016
>>> b = a
>>> id(b)
4302202064
>>> id(a) == id(b)
True

```

在这里，我们看到最初 `a` 和 `b` 指向不同的对象，因此 `id()` 为每个变量给出了不同的值。然而，当我们将 `a` 分配给 `b` 时，两个名称都指向同一个对象，因此 `id()` 为两者给出了相同的值。这里的主要教训是，`id()` 可以用来确定对象的 *身份*，而不依赖于对它的任何特定引用。

#### 使用 `is` 测试身份相等

实际上，在生产 Python 代码中很少使用 `id()` 函数。它的主要用途是在对象模型教程（比如这个！）和作为调试工具中。比 `id()` 函数更常用的是测试身份相等的 `is` 运算符。也就是说，`is` 测试两个引用是否指向同一个对象：

```py
>>> a is b
True

```

我们在第一章已经遇到了 `is` 运算符，当时我们测试了 `None`：

```py
>>> a is None
False

```

重要的是要记住，`is` 总是测试 *身份相等*，也就是说，两个引用是否指向完全相同的对象。我们将深入研究另一种主要类型的相等，*值相等*，稍后会详细介绍。

#### 在不进行变异的情况下进行变异

即使看起来自然会进行变异的操作也不一定如此。考虑增强赋值运算符：

```py
>>> t = 5
>>> id(t)
4297261280
>>> t += 2
>>> id(t)
4297261344

```

乍一看，似乎我们要求 Python 将整数值 `t` 增加两个。但这里的 `id()` 结果清楚地显示，在增强赋值之前和之后，`t` 指向两个不同的对象。

而不是修改整数对象，这里展示的实际发生的情况。最初，我们有名称 `t` 指向一个 `int(5)` 对象：

!['x' 指向整数 5](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-aprt/img/t_plus_eq_2_01.png)

‘x’ 指向整数 5

接下来，为了执行将 `2` 增强赋值给 `t`，Python 在幕后创建了一个 `int(2)` 对象。请注意，我们从未对此对象进行命名引用；它完全由 Python 代表我们管理：

![Python 在幕后创建一个整数 2](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-aprt/img/t_plus_eq_2_02.png)

Python 在幕后创建一个整数 2

然后，Python 在 `t` 和匿名 `int(2)` 之间执行加法运算，得到 —— 你猜对了！ —— 另一个整数对象，这次是 `int(7)`：

![Python 创建一个新的整数作为加法的结果](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-aprt/img/t_plus_eq_2_03.png)

Python 创建一个新的整数作为加法的结果

最后，Python 的增强赋值运算符将名称 `t` 重新分配给新的 `int(7)` 对象，使其他整数对象由垃圾收集器处理：

![Python 重新分配了名称 't' 给加法的结果](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-aprt/img/t_plus_eq_2_04.png)

Python 重新分配了名称 ‘t’ 给加法的结果

#### 对可变对象的引用

Python 对所有类型都显示这种名称绑定行为。*赋值运算符只会将对象绑定到名称，它永远不会通过值复制对象*。为了更清楚地说明这一点，让我们看另一个使用可变对象的例子：列表。与我们刚刚看到的不可变的 `int` 不同，`list` 对象具有可变状态，这意味着 `list` 对象的值可以随时间改变。

为了说明这一点，我们首先创建一个具有三个元素的列表对象，并将列表对象绑定到名为 `r` 的引用：

```py
>>> r = [2, 4, 6]
>>> r
[2, 4, 6]

```

然后，我们将引用 `r` 分配给一个新的引用 `s`：

```py
>>> s = r
>>> s
[2, 4, 6]

```

这种情况的引用对象图表清楚地表明我们有两个名称指向单个 `list` 实例：

!['s' 和 'r' 指向同一个列表对象](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-aprt/img/s_r_list.png)

‘s’ 和 ‘r’ 指向同一个列表对象

当我们通过更改由 `s` 引用的列表来修改列表时，我们看到由 `r` 引用的列表也发生了变化：

```py
>>> s[1] = 17
>>> s
[2, 17, 6]
>>> r
[2, 17, 6]

```

同样，这是因为名称 `s` 和 `r` 指向相同的 *可变* 对象 ^(8)，我们可以通过使用之前学到的 `is` 关键字来验证这一事实：

```py
>>> s is r
True

```

这次讨论的主要观点是，Python 实际上并没有变量的隐喻意义上的值。它只有对对象的命名引用，这些引用的行为更像是标签，允许我们检索对象。也就是说，在 Python 中谈论变量仍然很常见，因为这很方便。我们将在本书中继续这样做，确信您现在了解了幕后发生了什么。

#### 值的相等性（等同性）与身份的相等性

让我们将该行为与值相等性或等同性的测试进行对比。我们将创建两个相同的列表：

```py
>>> p = [4, 7, 11]
>>> q = [4, 7, 11]
>>> p == q
True
>>> p is q
False

```

在这里，我们看到`p`和`q`指的是不同的对象，但它们指的对象具有相同的值。

！'p'和'q'不同的列表对象，具有相同的值

'p'和'q'不同的列表对象，具有相同的值

正如您期望的那样，在测试值相等性时，对象应始终等同于自身^(9)：

```py
>>> p == p
True

```

值相等性和身份是“相等”的基本不同概念，重要的是要在脑海中将它们分开。

值比较也值得一提，它是以编程方式定义的。当您定义类型时，您可以控制该类如何确定值的相等性。相反，身份比较是由语言定义的，您无法更改该行为。

### 参数传递语义 - 按对象引用传递

现在让我们看看所有这些与函数参数和返回值的关系。当我们调用函数时，我们实际上创建了新的名称绑定 - 那些在函数定义中声明的名称绑定 - 到现有对象 - 那些在调用时传递的对象。^(10) 因此，如果您想知道您的函数如何工作，真正理解 Python 引用语义是很重要的。

#### 在函数中修改外部对象

为了演示 Python 的参数传递语义，我们将在 REPL 中定义一个函数，该函数将一个值附加到列表并打印修改后的列表。首先我们将创建一个`list`并将其命名为`m`：

```py
>>> m = [9, 15, 24]

```

然后我们将定义一个名为`modify()`的函数，该函数将附加到传递给它的列表并打印该列表。该函数接受一个名为`k`的单个形式参数：

```py
>>> def modify(k):
...     k.append(39)
...     print("k =", k)
...

```

然后我们调用`modify()`，将我们的列表`m`作为实际参数传递：

```py
>>> modify(m)
k = [9, 15, 24, 39]

```

这确实打印了具有四个元素的修改后的列表。但是我们在函数外部的列表引用`m`现在指向什么？

```py
>>> m
[9, 15, 24, 39]

```

由`m`引用的列表已被修改，因为它是函数内部由`k`引用的同一列表。正如我们在本节开头提到的，当我们将对象引用传递给函数时，我们实质上是将实际参数引用（在本例中为`m`）分配给形式参数引用（在本例中为`k`）。

！在函数内外引用同一列表

在函数内外引用同一列表

正如我们所见，赋值会导致被赋值的引用指向与被赋值的引用相同的对象。这正是这里正在发生的事情。如果您希望函数修改对象的副本，那么函数有责任进行复制。

#### 在函数中绑定新对象

让我们看另一个有教育意义的例子。首先，我们将创建一个新列表`f`：

```py
>>> f = [14, 23, 37]

```

然后我们将创建一个名为`replace()`的新函数。顾名思义，`replace()`不会修改其参数，而是会更改其参数所引用的对象：

```py
>>> def replace(g):
...     g = [17, 28, 45]
...     print("g =", g)
...

```

我们现在使用实际参数`f`调用`replace()`：

```py
>>> replace(f)
g = [17, 28, 45]

```

这正是我们所期望的。但是外部引用`f`现在的值是多少？

```py
>>> f
[14, 23, 37]

```

`f`仍然指向原始的未修改列表。这一次，函数没有修改传入的对象。发生了什么？

答案是：对象引用`f`被分配给了形式参数`g`，所以`g`和`f`确实引用了同一个对象，就像前面的例子一样。

![最初'f'和'g'引用相同的列表对象](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-aprt/img/f_g_list_01.png)

最初'f'和'g'引用相同的列表对象

然而，在函数的第一行，我们重新分配了引用`g`，指向一个新构造的列表`[17, 28, 45]`，所以在函数内部，对原始`[14, 23, 37]`列表的引用被覆盖了，尽管未修改的对象本身仍然被`f`引用在函数外部。

![重新分配后，'f'和'g'引用不同的对象](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-aprt/img/f_g_list_02.png)

重新分配后，'f'和'g'引用不同的对象

#### 参数传递是引用绑定

所以我们已经看到通过函数参数引用修改对象是完全可能的，但也可以重新绑定参数引用到新值。如果你想改变列表参数的内容，并且希望在函数外部看到这些变化，你可以像这样修改列表的内容：

```py
>>> def replace_contents(g):
...     g[0] = 17
...     g[1] = 28
...     g[2] = 45
...     print("g =", g)
...
>>> f
[14, 23, 37]
>>> replace_contents(f)
g = [17, 28, 45]

```

确实，如果你检查`f`的内容，你会发现它们已经被修改了：

```py
>>> f
[17, 28, 45]

```

函数参数是通过所谓的“对象引用传递”传递的。这意味着引用的*值*被复制到函数参数中，而不是所引用对象的值；没有对象被复制。

### Python 返回语义

Python 的`return`语句使用与函数参数相同的对象引用传递语义。当你在 Python 中从函数返回一个对象时，你真正做的是将一个对象引用传递回调用者。如果调用者将返回值分配给一个引用，他们所做的只是将一个新的引用分配给返回的对象。这使用了与显式引用赋值和参数传递相同的语义和机制。

我们可以通过编写一个返回它的唯一参数的函数来证明这一点：

```py
>>> def f(d):
...     return d
...

```

如果我们创建一个对象，比如一个列表，并通过这个简单的函数传递它，我们会发现它返回的是我们传入的完全相同的对象：

```py
>>> c = [6, 10, 16]
>>> e = f(c)
>>> c is e
True

```

记住，只有当两个名称引用完全相同的对象时，`is`才会返回`True`，所以这个例子表明列表没有被复制。

### 详细的函数参数

现在我们理解了对象引用和对象之间的区别，我们将看一些函数参数的更多功能。

#### 默认参数值

使用`def`关键字定义函数时指定的形式函数参数是一个逗号分隔的参数名称列表。通过提供默认值，这些参数可以变成可选的。考虑一个函数，它在控制台上打印一个简单的横幅：

```py
1 >>> def banner(message, border='-'):
2 ...     line = border * len(message)
3 ...     print(line)
4 ...     print(message)
5 ...     print(line)
6 ...

```

这个函数接受两个参数，并且我们提供了一个默认值——在这种情况下是`'-'`——在一个字面字符串中。当我们使用默认参数定义函数时，具有默认参数的参数必须在没有默认值的参数之后，否则我们将得到一个`SyntaxError`。

在函数的第 2 行，我们将我们的边框字符串乘以消息字符串的长度。这一行展示了两个有趣的特点。首先，它演示了我们如何使用内置的`len()`函数确定 Python 集合中的项目数。其次，它展示了如何将一个字符串（在这种情况下是单个字符字符串边框）乘以一个整数，结果是一个包含原始字符串重复多次的新字符串。我们在这里使用这个特性来使一个与我们的消息长度相等的字符串。

在 3 到 5 行，我们打印全宽边框、消息和再次边框。

当我们调用我们的`banner()`函数时，我们不需要提供边框字符串，因为我们提供了一个默认值：

```py
>>> banner("Norwegian Blue")
--------------
Norwegian Blue
--------------

```

然而，如果我们提供可选参数，它会被使用：

```py
>>> banner("Sun, Moon and Stars", "*")
***************
Sun, Moon and Stars
***************

```

#### 关键字参数

在生产代码中，这个函数调用并不特别自我说明。我们可以通过在调用站点命名`border`参数来改善这种情况：

```py
>>> banner("Sun, Moon and Stars", border="*")
***************
Sun, Moon and Stars
***************

```

在这种情况下，`message`字符串被称为“位置参数”，`border`字符串被称为“关键字参数”。在调用中，位置参数按照函数定义中声明的形式参数的顺序进行匹配。另一方面，关键字参数则按名称进行匹配。如果我们为我们的两个参数使用关键字参数，我们可以自由地以任何顺序提供它们：

```py
>>> banner(border=".", message="Hello from Earth")
................
Hello from Earth
................

```

但请记住，所有关键字参数必须在任何位置参数之后指定。

#### 默认参数何时被评估？

当您为函数提供默认参数值时，您通过提供一个*表达式*来实现。这个表达式可以是一个简单的文字值，也可以是一个更复杂的函数调用。为了实际使用您提供的默认值，Python 必须在某个时候评估该表达式。

因此，关键是要确切了解 Python 何时评估默认值表达式。这将帮助您避免一个常见的陷阱，这个陷阱经常会使 Python 的新手陷入困境。让我们使用 Python 标准库`time`模块仔细研究这个问题：

```py
>>> import time

```

我们可以通过使用`time`模块的`ctime()`函数轻松地将当前时间作为可读字符串获取：

```py
>>> time.ctime()
'Sat Feb 13 16:06:29 2016'

```

让我们编写一个使用从`ctime()`检索的值作为默认参数值的函数：

```py
>>> def show_default(arg=time.ctime()):
...     print(arg)
...
>>> show_default()
Sat Feb 13 16:07:11 2016

```

到目前为止一切顺利，但请注意当您几秒钟后再次调用`show_default()`时会发生什么：

```py
>>> show_default()
Sat Feb 13 16:07:11 2016

```

再一次：

```py
>>> show_default()
Sat Feb 13 16:07:11 2016

```

正如你所看到的，显示的时间永远不会进展。

还记得我们说过`def`是一个语句，当执行时将函数定义绑定到函数名吗？好吧，默认参数表达式只在`def`语句执行时评估一次。在许多情况下，默认值是一个简单的不可变常量，如整数或字符串，因此这不会引起任何问题。但是对于那些通常在使用可变集合作为参数默认值时出现的困惑陷阱，这可能是一个令人困惑的陷阱。

让我们仔细看看。考虑这个使用空列表作为默认参数的函数。它接受一个菜单作为字符串列表，将项目`"spam"`附加到列表中，并返回修改后的菜单：

```py
>>> def add_spam(menu=[]):
...     menu.append("spam")
...     return menu
...

```

让我们来制作一个简单的培根和鸡蛋早餐：

```py
>>> breakfast = ['bacon', 'eggs']

```

当然，我们会向其中添加垃圾邮件：

```py
>>> add_spam(breakfast)
['bacon', 'eggs', 'spam']

```

我们将为午餐做类似的事情：

```py
>>> lunch = ['baked beans']
>>> add_spam(lunch)
['baked beans', 'spam']

```

到目前为止没有什么意外的。但是看看当您依赖默认参数而不传递现有菜单时会发生什么：

```py
>>> add_spam()
['spam']

```

当我们向空菜单添加`'spam'`时，我们只得到`spam`。这可能仍然是您所期望的，但如果我们再次这样做，我们的菜单中就会添加两个`spam`：

```py
>>> add_spam()
['spam', 'spam']

```

还有三个：

```py
>>> add_spam()
['spam', 'spam', 'spam']

```

还有四个：

```py
>>> add_spam()
['spam', 'spam', 'spam', 'spam']

```

这里发生的情况是这样的。首先，在`def`语句执行时，用于默认参数的空列表被创建一次。这是一个像我们迄今为止看到的任何其他普通列表一样的列表，Python 将在整个程序执行期间使用这个确切的列表。

第一次我们实际使用默认值，然后，我们最终直接将`spam`添加到默认列表对象中。当我们第二次使用默认值时，我们使用的是同一个默认列表对象——我们刚刚添加了`spam`的对象，并且我们最终将第二个`spam`实例添加到其中。第三次调用会无限地添加第三个 spam。或者也许是无限地恶心。

解决这个问题很简单，但也许不是显而易见的：**始终使用不可变对象，如整数或字符串作为默认值**。遵循这个建议，我们可以通过使用不可变的`None`对象作为标记来解决这个特定的问题：

```py
>>> def add_spam(menu=None):
...     if menu is None:
...         menu = []
...     menu.append('spam')
...     return menu
...
>>> add_spam()
['spam']
>>> add_spam()
['spam']
>>> add_spam()
['spam']

```

现在我们的`add_spam()`函数按预期工作。

### Python 类型系统

编程语言可以通过几个特征来区分，但其中最重要的特征之一是它们的类型系统的性质。Python 可以被描述为具有*动态*和*强*类型系统。让我们来研究一下这意味着什么。

#### Python 中的动态类型

动态类型意味着对象引用的类型直到程序运行时才能解析，并且在编写程序时无需事先指定。看一下这个简单的函数来添加两个对象：

```py
>>> def add(a, b):
...     return a + b
...

```

在这个定义中我们没有提到任何类型。我们可以用整数使用`add()`：

```py
>>> add(5, 7):
12

```

我们也可以用它来表示浮点数：

```py
>>> add(3.1, 2.4)
5.5

```

你可能会惊讶地看到它甚至适用于字符串：

```py
>>> add("news", "paper")
'newspaper'

```

事实上，这个函数适用于任何类型，比如`list`，对于这些类型，加法运算符已经被定义：

```py
>>> add([1, 6], [21, 107])
[1, 6, 21, 107]

```

这些示例说明了类型系统的动态性：`add()`函数的两个参数`a`和`b`可以引用任何类型的对象。

#### Python 中的强类型

另一方面，类型系统的强度可以通过尝试为未定义加法的类型（如字符串和浮点数）`add()`来证明：

```py
>>> add("The answer is", 42)
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
  File "<stdin>", line 2, in add
TypeError: Can't convert 'int' object to str implicitly

```

尝试这样做会导致`TypeError`，因为 Python 通常不会在对象类型之间执行隐式转换，或者试图将一种类型强制转换为另一种类型。这个主要的例外是用于 if 语句和 while 循环谓词的`bool`转换。^(11)

### 变量声明和作用域

正如我们所见，Python 中不需要类型声明，变量本质上只是未经类型化的名称绑定到对象。因此，它们可以被重新绑定 - 或重新分配 - 任意多次，甚至可以是不同类型的对象。

但是当我们将一个名称绑定到一个对象时，该绑定存储在哪里？要回答这个问题，我们必须看一下 Python 中的作用域和作用域规则。

#### LEGB 规则

Python 中有四种*作用域*类型，它们按层次排列。每个作用域都是存储名称并在其中查找名称的上下文。从最狭窄到最宽广的四个作用域是：

+   本地 - 在当前函数内定义的名称。

+   封闭 - 在任何封闭函数中定义的名称。（这个作用域对本书的内容并不重要。）

+   全局 - 在模块的顶层定义的名称。每个模块都带有一个新的全局作用域。

+   内置 - 通过特殊的`builtins`模块内置到 Python 语言中的名称。

这些作用域共同构成了 LEGB 规则：

> **LEGB 规则**
> 
> 名称在最相关的上下文中查找。

重要的是要注意，Python 中的作用域通常不对应于缩进所标示的源代码块。for 循环、with 块等不会引入新的嵌套作用域。

#### 作用域的实际应用

考虑我们的`words.py`模块。它包含以下全局名称：

+   `main` - 由`def main()`绑定

+   `sys` - 由`import sys`绑定

+   `__name__` - 由 Python 运行时提供

+   `urlopen` - 由`from urllib.request import urlopen`绑定

+   `fetch_words` - 由`def fetch_words()`绑定

+   `print_items` - 由`def print_items()`绑定

模块范围名称绑定通常是由`import`语句和函数或类定义引入的。在模块范围内使用其他对象是可能的，这通常用于常量，尽管它也可以用于变量。

在`fetch_words()`函数内部，我们有六个本地名称：

+   `word` - 由内部 for 循环绑定

+   `line_words` - 通过赋值绑定

+   `line` - 由外部 for 循环绑定

+   `story_words` - 通过赋值绑定

+   `url` - 由形式函数参数绑定

+   `story` - 由 with 语句绑定

这些绑定中的每一个都是在首次使用时创建的，并在函数完成时继续存在于函数作用域内，此时引用将被销毁。

#### 全局和本地作用域中的相同名称

非常偶尔，我们需要在函数内部从模块范围重新绑定全局名称。考虑以下简单模块：

```py
count = 0

def show_count():
    print(count)

def set_count(c):
    count = c

```

如果我们将这个模块保存在`scopes.py`中，我们可以将其导入 REPL 进行实验：

```py
$ python3
Python 3.5.0 (default, Nov  3 2015, 13:17:02)
[GCC 4.2.1 Compatible Apple LLVM 6.1.0 (clang-602.0.53)] on darwin
Type "help", "copyright", "credits" or "license" for more information.
>>> from scopes import *
>>> show_count()
count =  0

```

当调用`show_count()`时，Python 在本地命名空间（L）中查找名称`count`。它找不到，所以在下一个最外部的命名空间中查找，这种情况下是全局模块命名空间（G），在那里它找到名称`count`并打印所引用的对象。

现在我们用一个新值调用`set_count()`：

```py
>>> set_count(5)

```

然后我们再次调用`show_count()`：

```py
>>> show_count()
count =  0

```

您可能会惊讶，在调用`set_count(5)`后，`show_count()`显示`0`，所以让我们一起来看看发生了什么。

当我们调用`set_count()`时，赋值`count = c`在*本地*作用域中为名称`count`创建了一个*新*绑定。这个新绑定当然是指传递的对象`c`。关键是，在模块范围定义的全局`count`不会进行查找。我们创建了一个新变量，它遮蔽了同名的全局变量，从而阻止访问。

#### `global`关键字

为了避免在全局范围内遮蔽名称，我们需要指示 Python 将`set_count()`函数中的名称`count`解析为模块命名空间中定义的`count`。我们可以使用`global`关键字来做到这一点。让我们修改`set_count()`来这样做：

```py
def set_count(c):
    global count
    count = c

```

`global`在本地作用域中引入了一个来自全局作用域的名称绑定。

退出并重新启动 Python 解释器以运行我们修改后的模块：

```py
>>> from scopes import *
>>> show_count()
count =  0
>>> set_count(5)
>>> show_count()
count =  5

```

它现在展示了所需的行为。

* * *

### 禅的时刻

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-aprt/img/zen-special-cases.png)

正如我们所展示的，Python 中的所有变量都是对象的引用，即使在基本类型（如整数）的情况下也是如此。这种对对象导向的彻底方法是 Python 的一个重要主题，实际上 Python 中的几乎所有东西都是对象，包括函数和模块。

* * *

### 一切都是对象

让我们回到我们的`words`模块，并在 REPL 中进一步进行实验。这次我们只会导入模块：

```py
$ python3
Python 3.5.0 (default, Nov  3 2015, 13:17:02)
[GCC 4.2.1 Compatible Apple LLVM 6.1.0 (clang-602.0.53)] on darwin
Type "help", "copyright", "credits" or "license" for more information.
>>> import words

```

`import`语句在当前命名空间中将模块对象绑定到名称`words`。我们可以使用`type()`内置函数确定任何对象的类型：

```py
>>> type(words)
<class 'module'>

```

如果我们想要查看对象的属性，我们可以在 Python 交互会话中使用`dir()`内置函数来审视对象：

```py
>>> dir(words)
['__builtins__', '__cached__', '__doc__', '__file__', '__initializing__',
'__loader__', '__name__', '__package__', 'fetch_words', 'main',
'print_items', 'sys', 'urlopen']

```

`dir()`函数返回模块属性名称的排序列表，包括：

+   我们定义的一些，比如函数`fetch_words()`

+   任何导入的名称，比如`sys`和`urlopen`

+   各种特殊的*dunder*属性，比如`__name__`和`__doc__`，揭示了 Python 的内部工作。

#### 检查一个函数

我们可以使用`type()`函数对任何这些属性进行更多了解。例如，我们可以看到`fetch_words`是一个函数对象：

```py
>>> type(words.fetch_words)
<class 'function'>

```

我们可以反过来在函数上使用`dir()`来揭示它的属性：

```py
>>> dir(words.fetch_words)
['__annotations__', '__call__', '__class__', '__closure__', '__code__',
'__defaults__', '__delattr__', '__dict__', '__dir__', '__doc__', '__eq__',
'__format__', '__ge__', '__get__', '__getattribute__', '__globals__',
'__gt__', '__hash__', '__init__', '__kwdefaults__', '__le__', '__lt__',
'__module__', '__name__', '__ne__', '__new__', '__qualname__', '__reduce__',
'__reduce_ex__', '__repr__', '__setattr__', '__sizeof__', '__str__',
'__subclasshook__']

```

我们可以看到函数对象有*许多*与 Python 函数在幕后实现方式有关的特殊属性。现在，我们只看一些简单的属性。

正如您所期望的那样，它的`__name__`属性是函数对象的名称作为字符串：

```py
>>> words.fetch_words.__name__
'fetch_words'

```

同样，`__doc__`是我们提供的文档字符串，给出了一些关于内置`help()`函数如何实现的线索。

```py
>>> words.fetch_words.__doc__
'Fetch a list of words from a URL.\n\n Args:\n url: The URL of a
UTF-8 text document.\n\n    Returns:\n        A list of strings containing
the words from\n        the document.\n    '

```

这只是一个小例子，展示了您可以在运行时审查 Python 对象，还有许多更强大的工具可以帮助您了解更多关于您正在使用的对象。也许这个例子最有教育意义的部分是，我们正在处理一个*函数对象*，这表明 Python 的普遍对象导向包括其他语言中可能根本无法访问的语言元素。

### 总结

+   Python 对象引用

+   将 Python 视为对对象的命名引用，而不是变量和值。

+   赋值不会将值放入一个盒子中。它会将一个名称标签附加到一个对象上。

+   从一个引用分配到另一个引用会在同一个对象上放置两个名称标签。

+   Python 垃圾收集器将回收不可达的对象-那些没有名称标签的对象。

+   对象标识和等价性

+   `id()`函数返回一个唯一且恒定的标识符，但在生产中很少使用。

+   `is`运算符确定身份的相等性。也就是说，两个名称是否引用同一个对象。

+   我们可以使用双等号运算符测试等价性。

+   函数参数和返回值

+   函数参数通过对象引用传递，因此如果它们是可变对象，函数可以修改它们的参数。

+   如果通过赋值重新绑定形式函数参数，则传入对象的引用将丢失。要更改可变参数，应该替换其*内容*而不是替换整个对象。

+   返回语句也通过对象引用传递。不会进行复制。

+   函数参数可以指定默认值。

+   默认参数表达式在执行`def`语句时只被评估一次。

+   Python 类型系统

+   Python 使用动态类型，因此我们不需要提前指定引用类型。

+   Python 使用强类型。类型不会被强制匹配。

+   范围

+   根据 LEGB 规则，Python 引用名称在四个嵌套范围中查找：局部函数中，封闭函数中，全局（或模块）命名空间中和内置函数。

+   全局引用可以从局部范围读取

+   从局部范围分配给全局引用需要使用 global 关键字声明引用为全局引用。

+   对象和内省

+   Python 中的所有内容都是对象，包括模块和函数。它们可以像其他对象一样对待。

+   `import`和`def`关键字会绑定到命名引用。

+   内置的`type()`函数可以用来确定对象的类型。

+   内置的`dir()`函数可以用来内省对象并返回其属性名称的列表。

+   函数或模块对象的名称可以通过其`__name__`属性访问。

+   函数或模块对象的文档字符串可以通过其`__doc__`属性访问。

+   杂项

+   我们可以使用`len()`来测量字符串的长度。

+   如果我们将字符串“乘以”一个整数，我们将得到一个新的字符串，其中包含操作数字符串的多个副本。这称为“重复”操作。


## 第六章：探索内置的集合类型

我们已经遇到了一些内置集合

+   `str` - 不可变的 Unicode 代码点序列

+   `list` - 可变的对象序列

+   `dict` - 从不可变键到可变对象的可变字典映射

我们只是浅尝辄止地了解了这些集合的工作原理，所以我们将在本章更深入地探索它们的功能。我们还将介绍三种新的内置集合类型：

+   `tuple` - 不可变的对象序列

+   `range` - 用于整数的算术级数

+   `set` - 一个包含唯一不可变对象的可变集合

我们不会在这里进一步讨论`bytes`类型。我们已经讨论了它与`str`的基本区别，大部分关于`str`的内容也适用于`bytes`。

这不是 Python 集合类型的详尽列表，但对于你在野外遇到或可能自己编写的绝大多数 Python 3 程序来说，这完全足够了。

在本章中，我们将按照上述顺序介绍这些集合，最后概述*协议*，这些协议将这些集合联系在一起，并允许它们以一致和可预测的方式使用。

### `tuple` - 一个不可变的对象序列

Python 中的元组是任意对象的不可变序列。一旦创建，其中的对象就不能被替换或移除，也不能添加新元素。

#### 文字元组

元组具有与列表类似的文字语法，只是它们用括号而不是方括号括起来。这是一个包含字符串、浮点数和整数的文字元组：

```py
>>> t = ("Norway", 4.953, 3)
>>> t
('Norway', 4.953, 3)

```

#### 元组元素访问

我们可以使用方括号通过零基索引访问元组的元素：

```py
>>> t[0]
'Norway'
>>> t[2]
3

```

#### 元组的长度

我们可以使用内置的`len()`函数来确定元组中的元素数量：

```py
>>> len(t)
3

```

#### 对元组进行迭代

我们可以使用 for 循环对其进行迭代：

```py
>>> for item in t:
>>>    print(item)
Norway
4.953
3

```

#### 元组的连接和重复

我们可以使用加号运算符连接元组：

```py
>>> t + (338186.0, 265E9)
('Norway', 4.953, 3, 338186.0, 265000000000.0)

```

同样，我们可以使用乘法运算符重复它们：

```py
>>> t * 3
('Norway', 4.953, 3, 'Norway', 4.953, 3, 'Norway', 4.953, 3)

```

#### 嵌套元组

由于元组可以包含任何对象，因此完全可以有嵌套元组：

```py
>>> a = ((220, 284), (1184, 1210), (2620, 2924), (5020, 5564), (6232, 6368))

```

我们使用索引运算符的重复应用来访问内部元素：

```py
>>> a[2][1]
2924

```

#### 单元素元组

有时需要一个单元素元组。要写这个，我们不能只使用括号中的简单对象。这是因为 Python 将其解析为数学表达式的优先控制括号中的对象：

```py
>>> h = (391)
>>> h
391
>>> type(h)
<class 'int'>

```

要创建一个单元素元组，我们使用尾随逗号分隔符，你会记得，我们允许在指定文字元组、列表和字典时使用尾随逗号。带有尾随逗号的单个元素被解析为单个元素元组：

```py
>>> k = (391,)
>>> k
(391,)
>>> type(k)
<class 'tuple'>

```

#### 空元组

这让我们面临一个问题，如何指定一个空元组。实际上答案很简单，我们只需使用空括号：

```py
>>> e = ()
>>> e
>>> type(e)
<class 'tuple'>

```

#### 可选的括号

在许多情况下，可以省略文字元组的括号：

```py
>>> p = 1, 1, 1, 4, 6, 19
>>> p
(1, 1, 1, 4, 6, 19)
>>> type(p)
<class 'tuple'>

```

#### 返回和解包元组

这个特性经常在从函数返回多个值时使用。在这里，我们创建一个函数来返回序列的最小值和最大值，这是由两个内置函数`min()`和`max()`完成的：

```py
>>> def minmax(items):
...     return min(items), max(items)
...
>>> minmax([83, 33, 84, 32, 85, 31, 86])
(31, 86)

```

将多个值作为元组返回经常与 Python 的一个称为*元组解包*的精彩特性一起使用。元组解包是一种所谓的*解构操作*，它允许我们将数据结构解包为命名引用。例如，我们可以将`minmax()`函数的结果分配给两个新引用，如下所示：

```py
>>> lower, upper = minmax([83, 33, 84, 32, 85, 31, 86])
>>> lower
31
>>> upper
86

```

这也适用于嵌套元组：

```py
>>> (a, (b, (c, d))) = (4, (3, (2, 1)))
>>> a
4
>>> b
3
>>> c
2
>>> d
1

```

#### 使用元组解包交换变量

元组解包导致了 Python 中交换两个（或更多）变量的美丽习惯用法：

```py
>>> a = 'jelly'
>>> b = 'bean'
>>> a, b = b, a
>>> a
bean
>>> b
jelly

```

### 元组构造函数

如果需要从现有集合对象（如列表）创建元组，可以使用`tuple()`构造函数。在这里，我们从一个`list`创建一个`tuple`：

```py
>>> tuple([561, 1105, 1729, 2465])
(561, 1105, 1729, 2465)

```

在这里，我们创建一个包含字符串字符的元组：

```py
>>> tuple("Carmichael")
('C', 'a', 'r', 'm', 'i', 'c', 'h', 'a', 'e', 'l')

```

#### 成员资格测试

最后，与 Python 中大多数集合类型一样，我们可以使用`in`运算符测试成员资格：

```py
>>>  5 in (3, 5, 17, 257, 65537)
True

```

或使用`not in`运算符进行非成员资格测试：

```py
>>> 5 not in (3, 5, 17, 257, 65537)
False

```

### 字符串的应用

我们在第二章已经详细介绍了`str`类型，但现在我们将花时间更深入地探索它的功能。

#### 字符串的长度

与任何其他 Python 序列一样，我们可以使用内置的`len()`函数确定字符串的长度。

```py
>>> len("llanfairpwllgwyngyllgogerychwyrndrobwllllantysiliogogogoch")
58

```

![威尔士安格尔西岛上的兰韦尔普尔古因吉尔戈盖里希温德罗布尔兰蒂斯利奥戈戈戈乔火车站的标志 - 欧洲最长的地名。](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-aprt/img/llanfair.png)

威尔士安格尔西岛上的兰韦尔普尔古因吉尔戈盖里希温德罗布尔兰蒂斯利奥戈戈戈乔火车站的标志 - 欧洲最长的地名。

#### 连接字符串

使用加号运算符支持字符串的连接：

```py
>>> "New" + "found" + "land"
Newfoundland

```

或相关的增强赋值运算符：

```py
>>> s = "New"
>>> s += "found"
>>> s += "land"
>>> s
'Newfoundland'

```

![纽芬兰岛，世界第十六大岛，是英语中相对较少的封闭的三重复合词之一。](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-aprt/img/newfoundland.png)

纽芬兰岛是世界第十六大岛，是英语中相对较少的封闭的三重复合词之一。

请记住，字符串是不可变的，因此在这里，增强赋值运算符在每次使用时将一个新的字符串对象绑定到`s`上。修改`s`的假象是可行的，因为`s`是对对象的引用，而不是对象本身。也就是说，虽然字符串本身是不可变的，但对它的引用是可变的。

#### 连接字符串

对于连接大量字符串，避免使用`+`或`+=`运算符。相反，应优先使用`join()`方法，因为它效率更高。这是因为使用加法运算符或其增强赋值版本进行连接可能会导致生成大量临时变量，从而导致内存分配和复制的成本。让我们看看`join()`是如何使用的。

`join()`是`str`上的一个方法，它接受一个字符串集合作为参数，并通过在它们之间插入分隔符来生成一个新的字符串。`join()`的一个有趣之处在于分隔符的指定方式：它是在调用`join()`的字符串。

与 Python 的许多部分一样，示例是最好的解释。将 HTML 颜色代码字符串列表连接成分号分隔的字符串：

```py
>>> colors = ';'.join(['#45ff23', '#2321fa', '#1298a3', '#a32312'])
>>> colors
'#45ff23;#2321fa;#1298a3;#a32312'

```

在这里，我们在我们希望使用的分隔符上调用`join()` - 分号 - 并传入要连接的字符串列表。

将一组字符串连接在一起的广泛且快速的 Python 习惯用法是使用空字符串作为分隔符进行`join()`：

```py
>>> ''.join(['high', 'way', 'man'])
highwayman

```

#### 分割字符串

然后我们可以再次使用`split()`方法来分割字符串（我们已经遇到过，但这次我们将提供它的可选参数）：

```py
>>> colors.split(';')
['#45ff23', '#2321FA', '#1298A3', '#A32912']

```

可选参数允许您指定要在其上分割字符串的字符串 - 不仅仅是字符。因此，例如，您可以通过在单词“and”上分割来解析匆忙的早餐订单：

```py
>>> 'eggsandbaconandspam'.split('and')
['eggs', 'bacon', 'spam']

```

* * *

### 禅之时刻

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-aprt/img/zen-the-way-may-not-be-obvious.png)

这种使用`join()`的方法常常让初学者感到困惑，但随着使用，Python 采取的方法将被认为是自然和优雅的。

* * *

#### 字符串分区

另一个非常有用的字符串方法是`partition()`，它将字符串分成三个部分；分隔符之前的部分，分隔符本身，以及分隔符之后的部分：

```py
>>> "unforgettable".partition('forget')
('un', 'forget', 'table')

```

`partition()`方法返回一个元组，因此这通常与元组解包一起使用：

```py
>>> departure, separator, arrival = "London:Edinburgh".partition(':')
>>> departure
London
>>> arrival
Edinburgh

```

通常，我们对捕获分隔符值不感兴趣，所以您可能会看到下划线变量名被使用。这在 Python 语言中并没有特殊对待，但有一个不成文的惯例，即下划线变量用于未使用或虚拟值：

```py
>>> origin, _, destination = "Seattle-Boston".partition('-')

```

这个约定得到了许多 Python 感知开发工具的支持，这些工具将抑制对下划线未使用变量的警告。

#### 字符串格式化

最有趣和经常使用的字符串方法之一是`format()`。这取代了旧版本 Python 中使用的字符串插值技术，虽然没有取代它，并且我们在本书中没有涵盖。`format()`方法可以有用地调用任何包含所谓的*替换字段*的字符串，这些字段用花括号括起来。作为`format()`参数提供的对象被转换为字符串，并用于填充这些字段。这里是一个例子：

```py
>>> "The age of {0} is {1}".format('Jim', 32)
'The age of Jim is 32'

```

在这种情况下，字段名称（`0`和`1`）与`format()`的位置参数匹配，并且每个参数在幕后被转换为字符串。

一个字段名称可能被多次使用：

```py
>>> "The age of {0} is {1}. {0}'s birthday is on {2}".format('Fred', 24, 'October 31')

```

然而，如果字段名恰好只使用一次，并且按照相同的顺序作为参数，它们可以被省略：

```py
>>> "Reticulating spline {} of {}.".format(4, 23)
'Reticulating spline 4 of 23.'

```

如果向`format()`提供了关键字参数，则可以使用命名字段而不是序数：

```py
>>> "Current position {latitude} {longitude}".format(latitude="60N", longitude="5E")
'Current position 60N 5E'

```

可以使用方括号索引到序列，并放在替换字段中：

```py
>>> "Galactic position x={pos[0]}, y={pos[1]}, z={pos[2]}".format(pos=(65.2, 23.1, 82\
.2))
'Galactic position x=65.2, y=23.1, z=82.2'

```

我们甚至可以访问对象属性。在这里，我们使用关键字参数将整个`math`模块传递给`format()`（记住 - 模块也是对象！），然后从替换字段中访问它的两个属性：

```py
>>> import math
>>> "Math constants: pi={m.pi}, e={m.e}".format(m=math)
'Math constants: pi=3.141592653589793 e=2.718281828459045'

```

格式化字符串还可以让我们对字段对齐和浮点格式化有很多控制。这里是相同的常量，只显示到小数点后三位：

```py
>>> "Math constants: pi={m.pi:.3f}, e={m.e:.3f}".format(m=math)
'Math constants: pi=3.142, e=2.718'

```

#### 其他字符串方法

我们建议您花一些时间熟悉其他字符串方法。记住，您可以使用以下方法找出它们是什么：

```py
>>> help(str)

```

### `range` - 一组均匀间隔的整数

让我们继续看看`range`，许多开发人员不认为它是一个集合^(12)，尽管我们会看到在 Python 3 中它绝对是。

`range`是一种用于表示整数的算术级数的序列类型。范围是通过调用`range()`构造函数创建的，没有文字形式。通常我们只提供停止值，因为 Python 默认为零起始值：

```py
>>> range(5)
range(0, 5)

```

范围有时用于创建连续的整数，用作循环计数器：

```py
>>> for i in range(5):
...     print(i)
...
0
1
2
3
4

```

请注意，提供给`range()`的停止值比序列的末尾多一个，这就是为什么之前的循环没有打印 5 的原因。

#### 起始值

如果需要，我们还可以提供一个起始值：

```py
>>> range(5, 10)
range(5, 10)

```

将这个放在`list()`构造函数中是一种强制生成每个项目的方便方式：

```py
>>> list(range(5, 10))
[5, 6, 7, 8, 9]

```

这种所谓的半开放范围约定 - 停止值不包括在序列中 - 乍看起来很奇怪，但如果你处理连续范围，它实际上是有道理的，因为一个范围指定的结束是下一个范围的开始：

```py
>>> list(range(10, 15))
[10, 11, 12, 13, 14]
>>> list(range(5, 10)) + list(range(10, 15))
[5, 6, 7, 8, 9, 10, 11, 12, 13, 14]

```

#### 步长参数

Range 还支持步长参数：

```py
>>> list(range(0, 10, 2))
[0, 2, 4, 6, 8]

```

请注意，为了使用步长参数，我们必须提供所有三个参数。范围很奇怪，因为它通过计算其参数来确定它们的含义。只提供一个参数意味着该参数是`stop`值。两个参数是`start`和`stop`，三个参数是`start`，`stop`和`step`。Python `range()`以这种方式工作，因此第一个参数`start`可以是可选的，这在通常情况下是不可能的。此外，`range`构造函数不支持关键字参数。你几乎可以说它是不符合 Python 风格的！

![arguably unPythonic constructor for range, where the interpretation of the arguments depends on whether one, two, or three are provided.](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-aprt/img/range-constructor.png)

对于范围的构造函数，这可能是不符合 Python 风格的，因为参数的解释取决于提供了一个、两个还是三个参数。

#### 不使用`range`：`enumerate()`

在这一点上，我们将向您展示另一个样式不佳的代码示例，但这次是您可以，也应该避免的。这是一个打印列表中元素的不好的方法：

```py
>>> s = [0, 1, 4, 6, 13]
>>> for i in range(len(s)):
...     print(s[i])
...
0
1
4
6
13

```

尽管这样做是有效的，但绝对不是 Pythonic 的。始终更喜欢使用对象本身的迭代：

```py
>>> s = [0, 1, 4, 6, 13]
>>> for v in s:
...     print(v)
0
1
4
6
13

```

如果您需要一个计数器，您应该使用内置的`enumerate()`函数，它返回一个可迭代的成对序列，每对都是一个`tuple`。每对的第一个元素是当前项目的索引，每对的第二个元素是项目本身：

```py
>>> t = [6, 372, 8862, 148800, 2096886]
>>> for p in enumerate(t):
>>>     print(p)
(0, 6)
(1, 372)
(2, 8862)
(3, 148800)
(4, 2096886)

```

更好的是，我们可以使用元组解包，避免直接处理元组：

```py
>>> for i, v in enumerate(t):
...     print("i = {}, v = {}".format(i, v))
...
i = 0, v = 6
i = 1, v = 372
i = 2, v = 8862
i = 3, v = 148800
i = 4, v = 2096886

```

### `list`的操作

我们已经稍微介绍了列表，并且已经充分利用了它们。我们知道如何使用文字语法创建列表，使用`append()`方法添加到列表中，并使用带有正数、从零开始的索引的方括号索引来获取和修改它们的内容。

![零和正整数从列表的前面索引，因此索引四是列表中的第五个元素。](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-aprt/img/list-forward-index.png)

零和正整数从列表的前面索引，因此索引四是列表中的第五个元素。

现在我们将深入研究一下。

#### 列表（和其他序列）的负索引

列表（以及其他 Python 序列，对于元组也适用）的一个非常方便的特性是能够从末尾而不是从开头进行索引。这是通过提供*负*索引来实现的。例如：

```py
>>> r = [1, -4, 10, -16, 15]
>>> r[-1]
15
>>> r[-2]
-16

```

![负整数是从末尾向后的-1，因此索引-5 是最后但第四个元素。](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-aprt/img/list-reverse-index.png)

负整数是从末尾向后的-1，因此索引-5 是最后但第四个元素。

这比计算正索引的笨拙等效方法要优雅得多，否则您将需要使用它来检索最后一个元素：

```py
>>> r[len(r) - 1]

```

请注意，使用-0 进行索引与使用 0 进行索引相同，并返回列表中的第一个元素。由于 0 和负零之间没有区别，负索引基本上是基于 1 而不是基于 0 的。如果您正在计算具有相当复杂逻辑的索引，这一点很重要：负索引很容易出现一次性错误。^(13)

#### 切片列表

切片是一种扩展索引的形式，允许我们引用列表的部分。为了使用它，我们传递一个半开放范围的开始和停止索引，用冒号分隔，作为方括号索引参数。这是如何做的：

```py
>>> s = [3, 186, 4431, 74400, 1048443]
>>> s[1:3]
[186, 4431]

```

请注意，第二个索引超出了返回范围的末尾。

![切片`[1:4]`。切片提取列表的一部分。切片范围是半开放的，因此停止索引处的值不包括在内。](images/m05----slice-forward-indexes.png)

切片`[1:4]`。切片提取列表的一部分。切片范围是半开放的，因此停止索引处的值不包括在内。

此功能可以与负索引结合使用。例如，除了第一个和最后一个元素之外，可以获取所有元素：

```py
>>> s[1:-1]
[186, 4431, 74400]

```

![切片`[1：-1]`对于排除列表的第一个和最后一个元素非常有用。](images/m05----slice-backward-indexes.png)

切片`[1：-1]`对于排除列表的第一个和最后一个元素非常有用。

开始和停止索引都是可选的。要从第三个元素开始切片到列表的末尾：

```py
>>> s[3:]
[74400, 1048443]

```

![切片`[3：]`保留了从第四个元素到最后一个元素的所有元素。](images/m05----slice-to-end.png)

切片`[3：]`保留了从第四个元素到最后一个元素的所有元素。

要从开头切片到第三个元素，但不包括第三个元素：

```py
>>> s[:3]
[3, 186, 4431]

```

![切片`[:3]`保留了列表开头的所有元素，直到，

但*不*包括第四个元素。](images/m05----slice-from-beginning.png)

切片`[:3]`保留了列表开头的所有元素，但*不*包括第四个元素。

请注意，这两个列表是互补的，并且一起形成整个列表，展示了半开范围约定的便利性。

![切片`[:3]`和`[3:]`是互补的。](images/m05----complementary-slices.png)

切片`[:3]`和`[3:]`是互补的。

由于开始和停止切片索引都是可选的，完全可以省略两者并检索所有元素：

```py
>>> s[:]
[3, 186, 4431, 74400, 1048443]

```

这被称为*完整切片*，在 Python 中是一种重要的技术。

![切片`[:]`是完整切片，包含列表中的所有元素。这是一个重要的习语，用于复制列表。](images/m05----full-slice.png)

切片`[:]`是完整切片，包含列表中的所有元素。这是一个重要的习语，用于复制列表。

#### 复制列表

事实上，完整切片是*复制*列表的重要习语。请记住，分配引用永远不会复制对象，而只是复制对对象的引用：

```py
>>> t = s
>>> t is s
True

```

我们使用完整切片将其复制到一个新列表中：

```py
>>> r = s[:]

```

并确认使用完整切片获得的列表具有独特的身份：

```py
>>> r is s
False

```

尽管它具有等效的值：

```py
>>> r == s
True

```

重要的是要理解，虽然我们有一个可以独立修改的新列表对象，但其中的元素是对原始列表引用的相同对象的引用。如果这些对象都是可变的并且被修改（而不是替换），则更改将在两个列表中都可见。

我们展示这种完整切片列表复制习语，因为您可能会在实际应用中看到它，而且它的作用并不是立即明显的。您应该知道还有其他更可读的复制列表的方法，比如`copy()`方法：

```py
>>> u = s.copy()
>>> u is s
False

```

或者简单调用列表构造函数，传递要复制的列表：

```py
>>> v = list(s)

```

在这些技术之间的选择在很大程度上是品味的问题。我们更偏好使用列表构造函数的第三种形式，因为它具有使用任何可迭代系列作为源的优势，而不仅仅是列表。

#### 浅复制

然而，您必须意识到，所有这些技术都执行*浅*复制。也就是说，它们创建一个新的列表，其中包含对源列表中相同对象的引用，但它们不复制被引用的对象。为了证明这一点，我们将使用嵌套列表，其中内部列表充当可变对象。这是一个包含两个元素的列表，每个元素本身都是一个列表：

```py
>>> a = [ [1, 2], [3, 4] ]

```

我们使用完整切片复制这个列表：

```py
>>> b = a[:]

```

并且让我们确信我们实际上有不同的列表：

```py
>>> a is b
False

```

具有等效值：

```py
>>> a == b
True

```

然而，请注意，这些不同列表中的引用不仅指向*等效*对象：

```py
>>> a[0]
[1, 2]
>>> b[0]
[1, 2]

```

但实际上是指向*相同*的对象：

```py
>>> a[0] is b[0]
True

```

![复制是浅层的。当复制列表时，对包含对象的引用（黄色菱形）进行复制，但被引用的对象（蓝色矩形）不会被复制。](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-aprt/img/copies-are-shallow.png)

复制是浅层的。当复制列表时，对包含对象的引用（黄色菱形）进行复制，但被引用的对象（蓝色矩形）不会被复制。

这种情况持续到我们将`a`的第一个元素重新绑定到一个新构造的列表为止：

```py
>>> a[0] = [8, 9]

```

现在，`a`和`b`的第一个元素指向不同的列表：

```py
>>> a[0]
[8, 9]
>>> b[0]
[1, 2]

```

![列表`a`和`b`的第一个元素现在是唯一拥有的，而第二个元素是共享的。](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-aprt/img/unique-and-shared-elements.png)

列表`a`和`b`的第一个元素现在是唯一拥有的，而第二个元素是共享的。

`a`和`b`的第二个元素仍然指向相同的对象。我们将通过`a`列表对该对象进行变异来证明这一点：

```py
>>> a[1].append(5)
>>> a[1]
[3, 4, 5]

```

我们看到改变通过`b`列表反映出来：

```py
>>> b[1]
[3, 4, 5]

```

![修改两个列表所引用的对象。](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-aprt/img/mutating-shared-elements.png)

修改两个列表所引用的对象。

为了完整起见，这是`a`和`b`列表的最终状态：

```py
>>> a
[[8, 9], [3, 4, 5]]
>>> b
[[1, 2], [3, 4, 5]]

```

![列表`a`的最终状态。](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-aprt/img/final-state-a.png)

列表`a`的最终状态。

![列表`b`的最终状态。](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-aprt/img/final-state-b.png)

列表`b`的最终状态。

如果需要对这样的层次数据结构执行真正的深层复制-根据我们的经验，这种情况很少见-我们建议查看 Python 标准库中的`copy`模块。

#### 重复列表

与字符串和元组一样，列表支持使用乘法运算符进行重复。很容易使用：

```py
>>> c = [21, 37]
>>> d = c * 4
>>> d
[21, 37, 21, 37, 21, 37, 21, 37]

```

尽管在这种形式中很少见。它最常用于将已知大小的列表初始化为常量值，例如零：

```py
>>> [0] * 9
[0, 0, 0, 0, 0, 0, 0, 0, 0]

```

但要注意，在可变元素的情况下，这里也存在同样的陷阱，因为重复将重复*对每个元素的引用*，而不是复制值。让我们再次使用嵌套列表作为我们的可变元素来演示：

```py
>>> s = [ [-1, +1] ] * 5
>>> s
[[-1, 1], [-1, 1], [-1, 1], [-1, 1], [-1, 1]]

```

![重复是浅层的。](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-aprt/img/repetition-is-shallow.png)

重复是浅层的。

如果我们现在修改外部列表的第三个元素：

```py
>>> s[2].append(7)

```

我们通过外部列表元素的所有五个引用看到了变化：

```py
>>> s
[[-1, 1, 7], [-1, 1, 7], [-1, 1, 7], [-1, 1, 7], [-1, 1, 7]]

```

![改变列表中重复内容的变异。对对象的任何更改都会反映在外部列表的每个索引中。](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-aprt/img/repetition-mutation.png)

改变列表中重复内容的变异。对对象的任何更改都会反映在外部列表的每个索引中。

#### 使用`index()`查找列表元素

要在列表中找到一个元素，使用`index()`方法并传递你要搜索的对象。元素将被比较直到找到你要找的那个：

```py
>>> w = "the quick brown fox jumps over the lazy dog".split()
>>> w
['the', 'quick', 'brown', 'fox', 'jumps', 'over', 'the', 'lazy', 'dog']
>>> i = w.index('fox')
>>> i
3
>>> w[i]
'fox'

```

如果搜索一个不存在的值，你会收到一个`ValueError`：

```py
>>> w.index('unicorn')
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
ValueError: 'unicorn' is not in list

```

我们将在第六章学习如何优雅地处理这些错误。

#### 使用`count()`和`in`进行成员测试。

另一种搜索的方法是使用`count()`来计算匹配的元素：

```py
>>> w.count("the")
2

```

如果只想测试成员资格，可以使用`in`运算符：

```py
>>> 37 in [1, 78, 9, 37, 34, 53]
True

```

或者使用`not in`进行非成员测试：

```py
>>> 78 not in [1, 78, 9, 37, 34, 53]
False

```

#### 使用`del`按索引删除列表元素

使用一个我们尚未熟悉的关键字来删除元素：`del`。`del`关键字接受一个参数，即对列表元素的引用，并将其从列表中删除，从而缩短列表：

```py
>>> u = "jackdaws love my big sphinx of quartz".split()
>>> u
['jackdaws', 'love', 'my', 'big', 'sphinx', 'of', 'quartz']
>>> del u[3]
>>> u
['jackdaws', 'love', 'my', 'sphinx', 'of', 'quartz']

```

#### 使用`remove()`按值删除列表元素

也可以使用`remove()`方法按值而不是按位置删除元素：

```py
>>> u.remove('jackdaws')
>>> u
['love', 'my', 'sphinx', 'of', 'quartz']

```

这相当于更冗长的形式：

```py
>>> del u[u.index('jackdaws')]

```

尝试`remove()`一个不存在的项目也会引发`ValueError`：

```py
>>> u.remove('pyramid')
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
ValueError: list.remove(x): x not in list

```

#### 插入到列表

可以使用`insert()`方法将项目插入列表，该方法接受新项目的索引和新项目本身：

```py
>>> a = 'I accidentally the whole universe'.split()
>>> a
['I', 'accidentally', 'the', 'whole', 'universe']
>>> a.insert(2, "destroyed")
>>> a
['I', 'accidentally', 'destroyed', 'the', 'whole', 'universe']
>>> ' '.join(a)
'I accidentally destroyed the whole universe'

```

#### 连接列表

使用加法运算符连接列表会产生一个新的列表，而不会修改任何操作数：

```py
>>> m = [2, 1, 3]
>>> n = [4, 7, 11]
>>> k = m + n
>>> k
[2, 1, 3, 4, 7, 11]

```

增强赋值运算符`+=`会就地修改被赋值的对象：

```py
>>> k += [18, 29, 47]
>>> k
[2, 1, 3, 4, 7, 11, 18, 29, 47]

```

也可以使用`extend()`方法来实现类似的效果：

```py
>>> k.extend([76, 129, 199])
>>> k
[2, 1, 3, 4, 7, 11, 18, 29, 47, 76, 123, 199]

```

增强赋值和`extend()`方法将与右侧的任何可迭代系列一起工作。

#### 重新排列`list`元素

在我们离开列表之前，让我们看看两个可以就地重新排列元素的操作：反转和排序。

可以通过调用`reverse()`方法来就地反转列表：

```py
>>> g = [1, 11, 21, 1211, 112111]
>>> g.reverse()
>>> g
[112111, 1211, 21, 11, 1]

```

可以使用`sort()`方法就地对列表进行排序：

```py
>>> d = [5, 17, 41, 29, 71, 149, 3299, 7, 13, 67]
>>> d.sort()
>>> d
[5, 7, 13, 17, 29, 41, 67, 71, 149, 3299]

```

`sort()`方法接受两个可选参数，`key`和`reverse`。后者不言自明，当设置为`True`时，会进行降序排序：

```py
>>> d.sort(reverse=True)
>>> d
[3299, 149, 71, 67, 41, 29, 17, 13, 7, 5]

```

`key`参数更有趣。它接受任何*可调用*对象，然后用于从每个项目中提取*键*。然后根据这些键的相对顺序对项目进行排序。在 Python 中有几种类型的可调用对象，尽管到目前为止我们遇到的唯一一种是谦卑的函数。例如，`len()`函数是一个可调用对象，用于确定集合的长度，例如字符串。

考虑以下单词列表：

```py
>>> h = 'not perplexing do handwriting family where I illegibly know doctors'.split()
>>> h
['not', 'perplexing', 'do', 'handwriting', 'family', 'where', 'I', 'illegibly', 'know\
', 'doctors']
>>> h.sort(key=len)
>>> h
['I', 'do', 'not', 'know', 'where', 'family', 'doctors', 'illegibly', 'perplexing', '\
handwriting']
>>> ' '.join(h)
'I do not know where family doctors illegibly perplexing handwriting'

```

#### 不在原地重新排列

有时候，*in situ*排序或反转并不是所需的。例如，它可能会导致函数参数被修改，给函数带来混乱的副作用。对于`reverse()`和`sort()`列表方法的 out-of-place 等价物，可以使用`reversed()`和`sorted()`内置函数，它们分别返回一个反向迭代器和一个新的排序列表。例如：

```py
>>> x = [4, 9, 2, 1]
>>> y = sorted(x)
>>> y
[1, 2, 4, 9]
>>> x
[4, 9, 2, 1]

```

和：

```py
>>> p = [9, 3, 1, 0]
>>> q = reversed(p)
>>> q
<list_reverseiterator object at 0x1007bf290>
>>> list(q)
[0, 1, 3, 9]

```

注意我们如何使用列表构造函数来评估`reversed()`的结果。这是因为`reversed()`返回一个迭代器，这是我们以后会更详细地讨论的一个主题。

这些函数的优点是它们可以用于任何有限的可迭代源对象。

### 字典

现在我们将回到字典，它是许多 Python 程序的核心，包括 Python 解释器本身。我们之前简要地看过字面上的字典，看到它们用花括号界定，并包含逗号分隔的键值对，每对由冒号绑定在一起：

```py
>>> urls = {'Google': 'http://google.com',
...         'Twitter': 'http://twitter.com',
...         'Sixty North': 'http://sixty-north.com',
...         'Microsoft': 'http://microsoft.com' }
>>>

```

![一个 URL 字典。字典键的顺序不被保留。](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-aprt/img/dictionary.png)

一个 URL 字典。字典键的顺序不被保留。

值可以通过键访问：

```py
>>> urls['Twitter']
http://twitter.com

```

由于每个键只与一个值相关联，并且查找是通过键进行的，因此在任何单个字典中，键必须是唯一的。但是，拥有重复的值是可以的。

在内部，字典维护了对键对象和值对象的引用对。键对象*必须*是不可变的，所以字符串、数字和元组都可以，但列表不行。值对象可以是可变的，在实践中通常是可变的。我们的示例 URL 映射使用字符串作为键和值，这是可以的。

与其他集合一样，还有一个名为`dict()`的命名构造函数，它可以将其他类型转换为字典。我们可以使用构造函数从存储在元组中的可迭代的键值对系列中复制，就像这样：

```py
>>> names_and_ages = [ ('Alice', 32), ('Bob', 48), ('Charlie', 28), ('Daniel', 33) ]
>>> d = dict(names_and_ages)
>>> d
{'Charlie': 28, 'Bob': 48, 'Alice': 32, 'Daniel': 33}

```

请记住，字典中的项目不以任何特定顺序存储，因此列表中的项目顺序不被保留。

只要键是合法的 Python 标识符，甚至可以直接从传递给`dict()`的关键字参数创建字典：

```py
>>> phonetic = dict(a='alfa', b='bravo', c='charlie', d='delta', e='echo', f='foxtrot\
')
>>> phonetic
{'a': 'alfa', 'c': 'charlie', 'b': 'bravo', 'e': 'echo', 'd': 'delta', 'f': 'foxtrot'}

```

同样，关键字参数的顺序不被保留。

#### 复制字典

与列表一样，默认情况下字典复制是浅复制，只复制对键和值对象的引用，而不是对象本身。有两种复制字典的方法，我们最常见的是第二种。第一种技术是使用`copy()`方法：

```py
>>> d = dict(goldenrod=0xDAA520, indigo=0x4B0082, seashell=0xFFF5EE)
>>> e = d.copy()
>>> e
{'indigo': 4915330, 'goldenrod': 14329120, 'seashell': 16774638}

```

第二种方法是将现有的字典传递给`dict()`构造函数：

```py
>>> f = dict(e)
>>> f
{'indigo': 4915330, 'seashell': 16774638, 'goldenrod': 14329120}

```

#### 更新字典

如果需要使用另一个字典的定义来扩展字典，可以使用`update()`方法。这个方法被调用在要更新的字典上，并传递要合并的字典的内容：

```py
>>> g = dict(wheat=0xF5DEB3, khaki=0xF0E68C, crimson=0xDC143C)
>>> f.update(g)
>>> f
>>> {'crimson': 14423100, 'indigo': 4915330, 'goldenrod': 14329120,
      'wheat': 16113331, 'khaki': 15787660, 'seashell': 16774638}

```

如果`update()`的参数包括已经存在于目标字典中的键，则这些键关联的值将被源字典中对应的值替换掉：

```py
>>> stocks = {'GOOG': 891, 'AAPL': 416, 'IBM': 194}
>>> stocks.update({'GOOG': 894, 'YHOO': 25})
>>> stocks
{'YHOO': 25, 'AAPL': 416, 'IBM': 194, 'GOOG': 894}

```

#### 遍历字典键

正如我们在前面的章节中看到的，字典是可迭代的，因此可以与 for 循环一起使用。字典在每次迭代中只产生一个*键*，我们需要使用方括号运算符进行查找来检索相应的值：

```py
>>> colors = dict(aquamarine='#7FFFD4', burlywood='#DEB887',
...               chartreuse='#7FFF00', cornflower='#6495ED',
...               firebrick='#B22222', honeydew='#F0FFF0',
...               maroon='#B03060', sienna='#A0522D')
>>> for key in colors:
...     print("{key} => {value}".format(key=key, value=colors[key]))
...
firebrick => #B22222
maroon => #B03060
aquamarine => #7FFFD4
burlywood => #DEB887
honeydew => #F0FFF0
sienna => #A0522D
chartreuse => #7FFF00
cornflower => #6495ED

```

注意，键以任意顺序返回，既不是它们被指定的顺序，也不是任何其他有意义的排序顺序。

#### 遍历字典值

如果我们只想遍历值，可以使用`values()`字典方法。这将返回一个对象，它提供了一个可迭代的*视图*，而不会导致值被复制：

```py
>>> for value in colors.values():
...     print(value)
...
#B22222
#B03060
#7FFFD4
#DEB887
#F0FFF0
#A0522D
#DEB887
#6495ED

```

没有有效或方便的方法来从值中检索相应的*键*，所以我们只打印值

为了对称起见，还有一个`keys()`方法，尽管由于直接对字典对象进行迭代会产生键，因此这种方法不太常用：

```py
>>> for key in colors.keys():
...     print(key)
...
firebrick
maroon
aquamarine
burlywood
honeydew
sienna
chartreuse
cornflower

```

#### 遍历键值对

通常，我们想要同时遍历键和值。字典中的每个键值对称为*项*，我们可以使用`items()`字典方法获得项的可迭代视图。当迭代`items()`视图时，会将每个键值对作为一个元组产生。通过在 for 语句中使用元组解包，我们可以在一次操作中获取键和值，而无需额外查找：

```py
>>> for key, value in colors.items():
...     print("{key} => {value}".format(key=key, value=value))
...
firebrick => #B22222
maroon => #B03060
aquamarine => #7FFFD4
burlywood => #DEB887
honeydew => #F0FFF0
sienna => #A0522D
chartreuse => #DEB887
cornflower => #6495ED

```

#### 用于字典键的成员测试

使用`in`和`not in`运算符对字典的成员测试适用于键：

```py
>>> symbols = dict(
...     usd='\u0024', gbp='\u00a3', nzd='\u0024', krw='\u20a9',
...     eur='\u20ac', jpy='\u00a5',  nok='kr', hhg='Pu', ils='\u20aa')
>>> symbols
{'jpy': '¥', 'krw': '₩', 'eur': '€', 'ils': '₪', 'nzd': '$', 'nok': 'kr',
  'gbp': '£', 'usd': '$', 'hhg': 'Pu'}
>>> 'nzd' in symbols
True
>>> 'mkd' not in symbols
True

```

#### 移除字典条目

至于列表，要从字典中删除条目，我们使用`del`关键字：

```py
>>> z = {'H': 1, 'Tc': 43, 'Xe': 54, 'Un': 137, 'Rf': 104, 'Fm': 100}
>>> del z['Un']
>>> z
{'H': 1, 'Fm': 100, 'Rf': 104, 'Xe': 54, 'Tc': 43}

```

#### 字典的可变性

字典中的键应该是不可变的，尽管值可以被修改。这是一个将元素符号映射到该元素不同同位素的质量数列表的字典：

```py
>>> m = {'H': [1, 2, 3],
...      'He': [3, 4],
...      'Li': [6, 7],
...      'Be': [7, 9, 10],
...      'B': [10, 11],
...      'C': [11, 12, 13, 14]}

```

看看我们如何将字典文字分成多行。这是允许的，因为字典文字的花括号是开放的。

我们的字符串键是不可变的，这对于字典的正确功能是件好事。但是，如果我们发现一些新的同位素，修改字典的值也没有问题：

```py
>>> m['H'] += [4, 5, 6, 7]
>>> m
{'H': [1, 2, 3, 4, 5, 6, 7], 'Li': [6, 7], 'C': [11, 12, 13, 14], 'B':
[10, 11], 'He': [3, 4], 'Be': [7, 9, 10]}

```

在这里，增强赋值运算符应用于通过‘H’（表示氢）键访问的*列表*对象；字典没有被修改。

当然，字典本身是可变的；我们知道可以添加新的条目：

```py
>>> m['N'] = [13, 14, 15]

```

#### 漂亮的打印

对于复合数据结构，比如我们的同位素表，将它们以更可读的形式打印出来会很有帮助。我们可以使用 Python 标准库中的漂亮打印模块`pprint`来做到这一点，其中包含一个名为`pprint`的函数：

```py
>>> from pprint import pprint as pp

```

请注意，如果我们没有将`pprint`函数绑定到另一个名称`pp`，函数引用将覆盖模块引用，阻止进一步访问模块的内容^(14)：

```py
>>> pp(m)
{'B': [10, 11],
  'Be': [7, 9, 10],
  'C': [11, 12, 13, 14],
  'H': [1, 2, 3, 4, 5, 6, 7],
  'He': [3, 4],
  'Li': [6, 7],
  'N': [13, 14, 15]}

```

给我们提供了一个更易理解的显示。

让我们离开字典，看看一个新的内置数据结构，`set`。

### `set` - 一个无序的唯一元素的集合

`set`数据类型是一个无序的唯一元素的集合。集合是可变的，因为可以向集合添加和移除元素，但每个元素本身必须是不可变的，就像字典的键一样。

![集合是无序的不同元素的组合。](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-aprt/img/set.png)

集合是无序的不同元素的组合。

集合的文字形式与字典非常相似，同样由花括号括起来，但每个项目都是单个对象，而不是由冒号连接的一对对象：

```py
>>> p = {6, 28, 496, 8128, 33550336}

```

请注意，与字典一样，`set`是无序的。

```py
>>> p
{33550336, 8128, 28, 496, 6}

```

当然，集合的类型是`set`：

```py
>>> type(p)
<class 'set'>

```

#### 集合构造函数

请记住，有点令人困惑的是，空花括号创建的是一个空的*字典*，而不是一个空的集合：

```py
>>> d = {}
>>> type(d)
<class 'dict'>

```

要创建一个空集合，我们必须使用`set()`构造函数：

```py
>>> e = set()
>>> e
set()

```

这也是 Python 对我们空集合的回显形式。

`set()`构造函数可以从任何可迭代序列（如列表）创建集合：

```py
>>> s = set([2, 4, 16, 64, 4096, 65536, 262144])
>>> s
{64, 4096, 2, 4, 65536, 16, 262144}

```

输入序列中的重复项将被丢弃。事实上，集合的常见用途是从对象序列中高效地移除重复项：

```py
>>> t = [1, 4, 2, 1, 7, 9, 9]
>>> set(t)
{1, 2, 4, 9, 7}

```

#### 遍历集合

当然，集合是可迭代的，尽管顺序是任意的：

```py
>>> for x in {1, 2, 4, 8, 16, 32}:
>>>     print(x)
32
1
2
4
8
16

```

#### 集合的成员测试

成员测试是集合的基本操作，与其他集合类型一样，使用`in`和`not in`运算符执行：

```py
>>> q = { 2, 9, 6, 4 }
>>> 3 in q
False
>>> 3 not in q
True

```

#### 向集合添加元素

要向集合添加单个元素，请使用`add()`方法：

```py
>>> k = {81, 108}
>>> k
{81, 108}
>>> k.add(54)
>>> k
{81, 108, 54}
>>> k.add(12)
>>> k
{81, 108, 54, 12}

```

添加已经存在的元素不会产生任何效果：

```py
>>> k.add(108)

```

尽管也不会产生错误。

可以一次性从任何可迭代序列中添加多个元素，包括另一个集合，使用`update()`方法：

```py
>>> k.update([37, 128, 97])
>>> k
{128, 81, 37, 54, 97, 12, 108}

```

#### 从集合中移除元素

提供了两种方法来从集合中删除元素。第一种`remove()`要求要删除的元素必须存在于集合中，否则会给出`KeyError`：

```py
>>> k.remove(97)
>>> k
{128, 81, 37, 54, 12, 108}
>>> k.remove(98)
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
KeyError: 98

```

第二种方法`discard()`不那么挑剔，如果元素不是集合的成员，则没有影响：

```py
>>> k.discard(98)
>>> k
{128, 81, 37, 54, 12, 108}

```

#### 复制集合

与其他内置集合一样，`set`具有`copy()`方法，执行集合的浅复制（复制引用而不是对象）：

```py
>>> j = k.copy()
>>> j
{128, 81, 37, 54, 108, 12}

```

正如我们已经展示的，可以使用`set()`构造函数：

```py
>>> m = set(j)
>>> m
{128, 81, 37, 54, 108, 12}

```

#### 集合代数操作

也许集合类型最有用的方面是提供的一组强大的集合代数操作。这些操作使我们能够轻松计算集合的并集、差集和交集，并评估两个集合是否具有子集、超集或不相交的关系。

为了演示这些方法，我们将根据不同的表型构建一些人的集合：

```py
>>> blue_eyes = {'Olivia', 'Harry', 'Lily', 'Jack', 'Amelia'}
>>> blond_hair = {'Harry', 'Jack', 'Amelia', 'Mia', 'Joshua'}
>>> smell_hcn = {'Harry', 'Amelia'}
>>> taste_ptc = {'Harry', 'Lily', 'Amelia', 'Lola'}
>>> o_blood = {'Mia', 'Joshua', 'Lily', 'Olivia'}
>>> b_blood = {'Amelia', 'Jack'}
>>> a_blood = {'Harry'}
>>> ab_blood = {'Joshua', 'Lola'}

```

![集合代数操作。](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-aprt/img/set-algebra.png)

集合代数操作。

##### 联合

要查找所有金发、蓝眼睛或两者都有的人，我们可以使用`union()`方法：

```py
>>> blue_eyes.union(blond_hair)
{'Olivia', 'Jack', 'Joshua', 'Harry', 'Mia', 'Amelia', 'Lily'}

```

集合并集将所有在两个集合中的元素收集在一起。

我们可以演示`union()`是可交换操作（即，我们可以交换操作数的顺序），使用值相等运算符来检查结果集的等价性：

```py
>>> blue_eyes.union(blond_hair) == blond_hair.union(blue_eyes)
True

```

##### 交集

要找到所有金发*和*蓝眼睛的人，我们可以使用`intersection()`方法：

```py
>>> blue_eyes.intersection(blond_hair)
{'Amelia', 'Jack', 'Harry'}

```

它只收集两个集合中都存在的元素。

这也是可交换的：

```py
>>> blue_eyes.intersection(blond_hair) == blond_hair.intersection(blue_eyes)
True

```

#### 差异

要识别金发但*没有*蓝眼睛的人，我们可以使用`difference()`方法：

```py
>>> blond_hair.difference(blue_eyes)
{'Joshua', 'Mia'}

```

这找到了第一个集合中存在但不在第二个集合中的所有元素。

这是非交换的，因为金发但没有蓝眼睛的人与有蓝眼睛但没有金发的人不同：

```py
>>> blond_hair.difference(blue_eyes) == blue_eyes.difference(blond_hair)
False

```

##### 对称差

然而，如果我们想确定哪些人只有金发*或*蓝眼睛，但不是两者都有，我们可以使用`symmetric_difference()`方法：

```py
>>> blond_hair.symmetric_difference(blue_eyes)
{'Olivia', 'Joshua', 'Mia', 'Lily'}

```

这收集了第一个集合*或*第二个集合中存在的所有元素，但不是两者都有。

从名称上可以看出，`symmetric_difference()`确实是可交换的：

```py
>>> blond_hair.symmetric_difference(blue_eyes) == blue_eyes.symmetric_difference(blon\
d_hair)
True

```

##### 子集关系

![设置关系。](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-aprt/img/set-relationships.png)

设置关系。

此外，还提供了三种谓词方法，告诉我们集合之间的关系。我们可以使用`issubset()`方法检查一个集合是否是另一个集合的子集。例如，要检查所有能闻到氰化氢的人是否也有金发：

```py
>>> smell_hcn.issubset(blond_hair)
True

```

这检查第一个集合中的所有元素是否也存在于第二个集合中。

要测试所有能品尝苯硫脲（PTC）的人是否也能闻到氰化氢，使用`issuperset()`方法：

```py
>>> taste_ptc.issuperset(smell_hcn)
True

```

这检查第二个集合中的所有元素是否都存在于第一个集合中。

![苯硫脲（PTC）的表示。它具有不寻常的特性，即根据品尝者的遗传学，它可能非常苦或几乎没有味道。](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-aprt/img/ptc.png)

苯硫脲（PTC）的表示。它具有不寻常的特性，即根据品尝者的遗传学，它可能非常苦或几乎没有味道。

要测试两个集合是否没有共同成员，使用`isdisjoint()`方法。例如，你的血型要么是 A 型，要么是 O 型，永远不会同时有：

```py
>>> a_blood.isdisjoint(o_blood)
True

```

### 集合协议

在 Python 中，协议是类型必须支持的一组操作或方法。协议不需要在源代码中定义为单独的接口或基类，就像在 C#或 Java 等名义类型的语言中那样。只要对象提供这些操作的功能实现即可。

我们可以根据它们支持的协议来组织我们在 Python 中遇到的不同集合：

| 协议 | 实现集合 |
| --- | --- |
| 容器 | `str`, `list`, `dict`, `range`, `tuple`, `set`, `bytes` |
| 大小 | `str`, `list`, `dict`, `range`, `tuple`, `set`, `bytes` |
| 可迭代 | `str`, `list`, `dict`, `range`, `tuple`, `set`, `bytes` |
| 序列 | `str`, `list`, `tuple`, `range`, `bytes` |
| 可变序列 | `list` |
| 可变集 | `set` |
| 可变映射 | `dict` |

对协议的支持要求类型具有特定的行为。

#### 容器协议

*容器*协议要求支持使用`in`和`not in`运算符进行成员测试：

```py
item in container
item not in container

```

#### 大小协议

*大小*协议要求可以通过调用`len(sized_collection)`来确定集合中的元素数量。

#### 可迭代协议

迭代是一个如此重要的概念，我们在本书的后面专门为它开辟了一个章节。简而言之，*可迭代*提供了一种逐个产生元素的方法，只要它们被请求。

*可迭代*的一个重要特性是它们可以与 for 循环一起使用：

```py
for item in iterable:
    print(item)

```

#### 序列协议

*序列*协议要求可以使用整数索引和方括号检索项目：

```py
item = sequence[index]

```

可以使用`index()`搜索项目：

```py
i = sequence.index(item)

```

可以使用`count()`对项目进行计数：

```py
num = sequence.count(item)

```

并且可以使用`reversed()`生成序列的反向副本：

```py
r = reversed(sequence)

```

此外，*序列*协议要求对象支持*可迭代*、*大小*和*容器*。

#### 其他协议

我们不会在这里涵盖*可变序列*、*可变映射*和*可变集*。由于我们只涵盖了每个协议的一个代表类型，协议概念所提供的一般性在这一时刻并没有给我们带来太多好处。

### 总结

+   元组是不可变的序列类型

+   文字语法是可选的，可以在逗号分隔的列表周围加上括号。

+   单个元组的值使用尾随逗号的特殊语法。

+   元组解包 - 用于多个返回值和交换

+   字符串

+   字符串连接最有效的方法是使用`join()`方法，而不是使用加法或增强赋值运算符。

+   `partition()`方法是一个有用且优雅的字符串解析工具。

+   `format()`方法提供了一个强大的方法，用字符串化的值替换占位符。

+   范围

+   `range`对象表示算术级数。

+   `enumerate()`内置函数通常是生成循环计数器的一个更好的选择，而不是`range()`。

+   列表

+   列表支持使用负索引从列表末尾进行索引

+   切片语法允许我们复制列表的全部或部分。

+   完整切片是 Python 中常见的习语，尽管`copy()`方法和`list()`构造函数不那么晦涩。

+   Python 中的列表（和其他集合）副本是浅层副本。引用被复制，但被引用的对象没有被复制。

+   字典从键映射到值

+   对字典进行迭代和成员测试是针对键进行的。

+   `keys()`、`values()`和`items()`方法提供了对字典不同方面的视图，允许方便的迭代。

+   集合存储无序的唯一元素集合。

+   集合支持强大的集合代数操作和谓词。

+   内置的集合可以根据它们支持的协议进行组织，比如*可迭代*、*序列*和*映射*。

顺便说一句，我们还发现：

+   下划线通常用于虚拟或多余的变量

+   `pprint`模块支持复杂数据结构的漂亮打印。
