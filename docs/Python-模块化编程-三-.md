# Python 模块化编程（三）

> 原文：[`zh.annas-archive.org/md5/253F5AD072786A617BB26982B7C4733F`](https://zh.annas-archive.org/md5/253F5AD072786A617BB26982B7C4733F)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：高级模块技术

在本章中，我们将研究一些更高级的模块和包的工作技术。特别是，我们将：

+   检查`import`语句可以使用的更不寻常的方式，包括可选导入、本地导入，以及通过更改`sys.path`来调整导入工作方式的方法

+   简要检查与导入模块和包相关的一些“陷阱”

+   看看如何使用 Python 交互解释器来帮助更快地开发你的模块和包

+   学习如何在模块或包内使用全局变量

+   看看如何配置一个包

+   了解如何将数据文件包含为 Python 包的一部分。

# 可选导入

尝试打开 Python 交互解释器并输入以下命令：

```py
import nonexistent_module

```

解释器将返回以下错误消息：

```py
ImportError: No module named 'nonexistent_module'

```

这对你来说不应该是个惊喜；如果在`import`语句中打错字，甚至可能在你自己的程序中看到这个错误。

这个错误的有趣之处在于它不仅适用于你打错字的情况。你也可以用它来测试这台计算机上是否有某个模块或包，例如：

```py
try:
    import numpy
    has_numpy = True
except ImportError:
    has_numpy = False
```

然后可以使用这个来让你的程序利用模块（如果存在），或者如果模块或包不可用，则执行其他操作，就像这样：

```py
if has_numpy:
    array = numpy.zeros((num_rows, num_cols), dtype=numpy.int32)
else:
    array = []
    for row in num_rows:
        array.append([])
```

在这个例子中，我们检查`numpy`库是否已安装，如果是，则使用`numpy.zeros()`创建一个二维数组。否则，我们使用一个列表的列表。这样，你的程序可以利用 NumPy 库的速度（如果已安装），同时如果这个库不可用，仍然可以工作（尽管速度较慢）。

### 注意

请注意，这个例子只是虚构的；你可能无法直接使用一个列表的列表而不是 NumPy 数组，并且在不做任何更改的情况下使你的程序的其余部分工作。但是，如果模块存在，则执行一项操作，如果不存在，则执行另一项操作的概念是相同的。

像这样使用可选导入是一个很好的方法，让你的模块或包利用其他库，同时如果它们没有安装也可以工作。当然，你应该在包的文档中始终提到这些可选导入，这样你的用户就会知道如果这些可选模块或包被安装会发生什么。

# 本地导入

在第三章中，*使用模块和包*，我们介绍了**全局命名空间**的概念，并展示了`import`语句如何将导入的模块或包的名称添加到全局命名空间。这个描述实际上是一个轻微的过度简化。事实上，`import`语句将导入的模块或包添加到*当前*命名空间，这可能是全局命名空间，也可能不是。

在 Python 中，有两个命名空间：全局命名空间和本地命名空间。全局命名空间是存储源文件中所有顶层定义的地方。例如，考虑以下 Python 模块：

```py
import random
import string

def set_length(length):
    global _length
    _length = length

def make_name():
    global _length

    letters = []
    for i in range(length):
        letters.append(random.choice(string.letters))
    return "".join(letters)
```

当你导入这个 Python 模块时，你将向全局命名空间添加四个条目：`random`、`string`、`set_length`和`make_name`。

### 注意

Python 解释器还会自动向全局命名空间添加几个其他条目。我们现在先忽略这些。

如果你然后调用`set_length()`函数，这个函数顶部的`global`语句将向模块的全局命名空间添加另一个条目，名为`_length`。`make_name()`函数也包括一个`global`语句，允许它在生成随机名称时引用全局`_length`值。

到目前为止一切都很好。可能不那么明显的是，在每个函数内部，还有一个称为**本地命名空间**的第二个命名空间，其中包含所有不是全局的变量和其他定义。在`make_name()`函数中，`letters`列表以及`for`语句使用的变量`i`都是*本地*变量——它们只存在于本地命名空间中，当函数退出时它们的值就会丢失。

本地命名空间不仅用于本地变量：你也可以用它来进行本地导入。例如，考虑以下函数：

```py
def delete_backups(dir):
    import os
    import os.path
    for filename in os.listdir(dir):
        if filename.endswith(".bak"):
            remove(os.path.join(dir, filename))
```

注意`os`和`os.path`模块是在函数内部导入的，而不是在模块或其他源文件的顶部。因为这些模块是在函数内部导入的，所以`os`和`os.path`名称被添加到本地命名空间而不是全局命名空间。

在大多数情况下，你应该避免使用本地导入：将所有的`import`语句放在源文件的顶部（使所有的导入语句都是全局的）可以更容易地一眼看出你的源文件依赖于哪些模块。然而，有两种情况下本地导入可能会有用：

1.  如果你要导入的模块或包特别大或初始化速度慢，使用本地导入而不是全局导入将使你的模块更快地导入。导入模块时的延迟只会在调用函数时显示出来。如果函数只在某些情况下被调用，这将特别有用。

1.  本地导入是避免循环依赖的好方法。如果模块 A 依赖于模块 B，模块 B 又依赖于模块 A，那么如果两组导入都是全局的，你的程序将崩溃。然而，将一组导入更改为本地导入将打破相互依赖，因为导入直到调用函数时才会发生。

作为一般规则，你应该坚持使用全局导入，尽管在特殊情况下，本地导入也可以非常有用。

# 使用 sys.path 调整导入

当你使用`import`命令时，Python 解释器必须搜索你想要导入的模块或包。它通过查找**模块搜索路径**来实现，这是一个包含各种目录的列表，模块或包可以在其中找到。模块搜索路径存储在`sys.path`中，Python 解释器将依次检查此列表中的目录，直到找到所需的模块或包。

当 Python 解释器启动时，它会使用以下目录初始化模块搜索路径：

+   包含当前执行脚本的目录，或者如果你在终端窗口中运行 Python 交互解释器，则为当前目录

+   `PYTHONPATH`环境变量中列出的任何目录

+   解释器的`site-packages`目录中的内容，包括`site-packages`目录中路径配置文件引用的任何模块

### 注意

`site-packages`目录用于保存各种第三方模块和包。例如，如果你使用 Python 包管理器`pip`来安装 Python 模块或包，那么该模块或包通常会放在`site-packages`目录中。

+   包含组成 Python 标准库的各种模块和包的多个目录

这些目录在`sys.path`中出现的顺序很重要，因为一旦找到所需名称的模块或包，搜索就会停止。

如果你愿意，你可以打印出你的模块搜索路径的内容，尽管列表可能会很长，而且很难理解，因为通常有许多包含 Python 标准库各个部分的目录，以及任何你可能安装的第三方包使用的其他目录：

```py
>>> import sys
>>> print(sys.path)
['', '/usr/local/lib/python3.3/site-packages', '/Library/Frameworks/SQLite3.framework/Versions/B/Python/3.3', '/Library/Python/3.3/site-packages/numpy-override', '/Library/Python/3.3/site-packages/pip-1.5.6-py3.3.egg', '/usr/local/lib/python3.3.zip', '/usr/local/lib/python3.3', '/usr/local/lib/python3.3/plat-darwin', '/usr/local/lib/python3.3/lib-dynload', '/Library/Frameworks/Python.framework/Versions/3.3/lib/python3.3', '/Library/Frameworks/Python.framework/Versions/3.3/lib/python3.3/plat-darwin']

```

重要的是要记住，这个列表是按顺序搜索的，直到找到匹配项为止。一旦找到具有所需名称的模块或包，搜索就会停止。

现在，`sys.path`不仅仅是一个只读列表。如果您更改此列表，例如通过添加新目录，您将更改 Python 解释器搜索模块的位置。

### 注意

实际上，有一些模块是内置到 Python 解释器中的；这些模块总是直接导入，忽略模块搜索路径。要查看已内置到您的 Python 解释器中的模块，可以执行以下命令：

```py
import sys
print(sys.builtin_module_names)
```

如果尝试导入这些模块之一，无论您对模块搜索路径做了什么，始终会使用内置版本。

虽然您可以对`sys.path`进行任何更改，例如删除或重新排列此列表的内容，但最常见的用法是向列表添加条目。例如，您可能希望将您创建的各种模块和包存储在一个特殊的目录中，然后可以从任何需要它的 Python 程序中访问。例如，假设您在`/usr/local/shared-python-libs`目录中有一个包含您编写的几个模块和包的目录，您希望在多个不同的 Python 程序中使用。在该目录中，假设您有一个名为`utils.py`的模块和一个名为`approxnums`的包，您希望在程序中使用。虽然简单的`import utils`会导致`ImportError`，但您可以通过以下方式使`shared-python-libs`目录的内容可用于程序：

```py
import sys
sys.path.append("/usr/local/shared-python-libs")
import utils, approxnums
```

### 提示

您可能想知道为什么不能只将共享模块和包存储在`site-packages`目录中。这有两个原因：首先，因为`site-packages`目录通常受保护，只有管理员才能写入，这使得在该目录中创建和修改文件变得困难。第二个原因是，您可能希望将自己的共享模块与您安装的其他第三方模块分开。

在前面的例子中，我们通过将我们的`shared-python-libs`目录附加到此列表的末尾来修改了`sys.path`。虽然这样做有效，但要记住，模块搜索路径是按顺序搜索的。如果在模块搜索路径上的任何目录中有任何其他模块命名为`utils.py`，那么该模块将被导入，而不是您的`shared-python-libs`目录中的模块。因此，与其附加，您通常会以以下方式修改`sys.path`：

```py
sys.path.insert(1, "/usr/local/shared-python-libs")
```

请注意，我们使用的是`insert(1, ...)`而不是`insert(0, ...)`。这会将新目录添加为`sys.path`中的*第二*个条目。由于模块搜索路径中的第一个条目通常是包含当前执行脚本的目录，将新目录添加为第二个条目意味着程序的目录将首先被搜索。这有助于避免混淆的错误，其中您在程序目录中定义了一个模块，却发现导入了一个同名的不同模块。因此，当向`sys.path`添加目录时，使用`insert(1, ...)`是一个良好的做法。

请注意，与任何其他技术一样，修改`sys.path`可能会被滥用。如果您的可重用模块或包修改了`sys.path`，您的代码用户可能会因为您更改了模块搜索路径而困惑，从而出现微妙的错误。一般规则是，您应该只在主程序中而不是在可重用模块中更改模块搜索路径，并始终清楚地记录您所做的工作，以免出现意外。

# 导入陷阱

虽然模块和包非常有用，但在使用模块和包时可能会遇到一些微妙的问题，这些问题可能需要很长时间才能解决。在本节中，我们将讨论一些您在使用模块和包时可能遇到的更常见的问题。

## 使用现有名称作为您的模块或包

假设您正在编写一个使用 Python 标准库的程序。例如，您可能会使用`random`模块来执行以下操作：

```py
import random
print(random.choice(["yes", "no"]))
```

您的程序一直正常工作，直到您决定主脚本中有太多数学函数，因此对其进行重构，将这些函数移动到一个单独的模块中。您决定将此模块命名为`math.py`，并将其存储在主程序的目录中。一旦这样做，之前的代码将会崩溃，并显示以下错误：

```py
Traceback (most recent call last):
 **File "main.py", line 5, in <module>
 **import random
 **File "/Library/Frameworks/Python.framework/Versions/3.3/lib/python3.3/random.py", line 41, in <module>
 **from math import log as _log, exp as _exp, pi as _pi, e as _e, ceil as _ceil
ImportError: cannot import name log

```

这到底是怎么回事？原本正常运行的代码现在崩溃了，尽管您没有对其进行更改。更糟糕的是，回溯显示它在程序导入 Python 标准库的模块时崩溃！

要理解这里发生了什么，您需要记住，默认情况下，模块搜索路径包括当前程序目录作为第一个条目——在指向 Python 标准库各个部分的其他条目之前。通过在程序中创建一个名为`math.py`的新模块，您已经使得 Python 解释器无法从 Python 标准库加载`math.py`模块。这不仅适用于您编写的代码，还适用于模块搜索路径上的*任何*模块或包，它们可能尝试从 Python 标准库加载此模块。在这个例子中，失败的是`random`模块，但它可能是任何依赖于`math`库的模块。

这被称为**名称屏蔽**，是一个特别阴险的问题。为了避免这种情况，您在选择程序中顶层模块和包的名称时，应该始终小心，以确保它们不会屏蔽 Python 标准库中的模块，无论您是否使用该模块。

避免名称屏蔽的一种简单方法是利用包来组织您在程序中编写的模块和包。例如，您可以创建一个名为`lib`的顶层包，并在`lib`包内创建各种模块和包。由于 Python 标准库中没有名为`lib`的模块或包，因此无论您为`lib`包内的模块和包选择什么名称，都不会有屏蔽标准库模块的风险。

## 将 Python 脚本命名为模块或包

名称屏蔽的一个更微妙的例子可能发生在您有一个 Python 脚本，其名称与 Python 标准库中的一个模块相同。例如，假设您想弄清楚`re`模块（[`docs.python.org/3.3/library/re.html`](https://docs.python.org/3.3/library/re.html)）的工作原理。如果您之前没有使用过正则表达式，这个模块可能会有点令人困惑，因此您可能决定编写一个简单的测试脚本来了解它的工作原理。这个测试脚本可能包括以下代码：

```py
import re

pattern = input("Regular Expression: ")
s = input("String: ")

results = re.search(pattern, s)

print(results.group(), results.span())
```

这个程序可能会帮助您弄清楚`re`模块的作用，但如果您将此脚本保存为`re.py`，当运行程序时会出现一个神秘的错误：

```py
$ python re.py
Regular Expression: [0-9]+
String: test123abc
Traceback (most recent call last):
...
File "./re.py", line 9, in <module>
 **results = re.search(pattern, s)
AttributeError: 'module' object has no attribute 'search'

```

你能猜到这里发生了什么吗？答案再次在于模块搜索路径。您的脚本名称`re.py`屏蔽了 Python 标准库中的`re`模块，因此当您的程序尝试导入`re`模块时，实际上加载的是脚本本身。您在这里看到`AttributeError`，是因为脚本成功地将自身作为模块加载，但该模块并没有您期望的`search()`函数。

### 注意

让脚本导入自身作为模块也可能导致意外问题；我们马上就会看到这一点。

这个问题的解决方法很简单：永远不要使用 Python 标准库模块的名称作为脚本的名称。而是将你的测试脚本命名为类似`re_test.py`的东西。

## 将包目录添加到 sys.path

一个常见的陷阱是将包目录添加到`sys.path`。让我们看看当你这样做时会发生什么。

创建一个目录来保存一个测试程序，并在这个主目录中创建一个名为`package`的子目录。然后，在`package`目录中创建一个空的包初始化（`__init__.py`）文件。同时，在同一个目录中创建一个名为`module.py`的模块。然后，将以下内容添加到`module.py`文件中：

```py
print("### Initializing module.py ###")
```

当导入模块时，这会打印出一条消息。接下来，在你的最顶层目录中创建一个名为`good_imports.py`的 Python 源文件，并输入以下 Python 代码到这个文件中：

```py
print("Calling import package.module...")
import package.module
print("Calling import package.module as module...")
import package.module as module
print("Calling from package import module...")
from package import module
```

保存这个文件后，打开一个终端或命令行窗口，并使用`cd`命令将当前目录设置为你最外层的目录（包含你的`good_imports.py`脚本的目录），然后输入`python good_imports.py`来运行这个程序。你应该会看到以下输出：

```py
$ python good_imports.py
Calling import package.module...
### Initializing module.py ###
Calling import package.module as module...
Calling from package import module...

```

正如你所看到的，第一个`import`语句加载了模块，导致打印出`### Initializing module.py ###`的消息。对于后续的`import`语句，不会发生初始化——相反，已经导入的模块副本会被使用。这是我们想要的行为，因为它确保我们只有一个模块的副本。这对于那些在全局变量中保存信息的模块非常重要，因为拥有不同副本的模块，其全局变量中的值不同，可能会导致各种奇怪和令人困惑的行为。

不幸的是，如果我们将一个包或包的子目录添加到`sys.path`中，我们可能会得到这样的结果。要看到这个问题的实际情况，创建一个名为`bad_imports.py`的新顶级脚本，并输入以下内容到这个文件中：

```py
import os.path
import sys

cur_dir = os.path.abspath(os.path.dirname(__file__))
package_dir = os.path.join(cur_dir, "package")

sys.path.insert(1, package_dir)

print("Calling import package.module as module...")
import package.module as module
print("Calling import module...")
import module
```

这个程序将`package_dir`设置为`package`目录的完整目录路径，然后将这个目录添加到`sys.path`中。然后，它进行了两个单独的`import`语句，一个是从名为`package`的包中导入`module`，另一个是直接导入`module`。这两个`import`语句都可以工作，因为模块可以以这两种方式访问。然而，结果并不是你可能期望的：

```py
$ python bad_imports.py
Calling import package.module as module...
### Initializing module.py ###
Calling import module...
### Initializing module.py ###

```

正如你所看到的，模块被导入了*两次*，一次是作为`package.module`，另一次是作为`module`。你最终会得到两个独立的模块副本，它们都被初始化，并作为两个不同的模块出现在 Python 系统中。

拥有两个模块副本可能会导致各种微妙的错误和问题。这就是为什么你永远不应该直接将 Python 包或 Python 包的子目录添加到`sys.path`中。

### 提示

当然，将包含包的目录添加到`sys.path`是可以的；只是不要添加包目录本身。

## 执行和导入相同的模块

另一个更微妙的双重导入问题的例子是，如果您执行一个 Python 源文件，然后导入同一个文件，就好像它是一个模块一样。要了解这是如何工作的，请创建一个目录来保存一个新的示例程序，并在该目录中创建一个名为`test.py`的新的 Python 源文件。然后，输入以下内容到这个文件中：

```py
import helpers

def do_something(n):
    return n * 2

if __name__ == "__main__":
    helpers.run_test()
```

当这个文件作为脚本运行时，它调用`helpers.run_test()`函数来开始运行一个测试。这个文件还定义了一个函数`do_something()`，执行一些有用的功能。现在，在同一个目录中创建第二个名为`helpers.py`的 Python 源文件，并输入以下内容到这个文件中：

```py
import test

def run_test():
    print(test.do_something(10))
```

正如你所看到的，`helpers.py`模块正在将`test.py`作为模块导入，然后调用`do_something()`函数作为运行测试的一部分。换句话说，即使`test.py`作为脚本执行，它也会作为模块被导入（间接地）作为该脚本的执行的一部分。

让我们看看当你运行这个程序时会发生什么：

```py
$ python test.py
20

```

到目前为止一切顺利。程序正在运行，尽管模块导入复杂，但似乎工作正常。但让我们更仔细地看一下；在你的`test.py`脚本顶部添加以下语句：

```py
print("Initializing test.py")
```

就像我们之前的例子一样，我们使用`print()`语句来显示模块何时被加载。这给了模块初始化的机会，我们期望只看到初始化发生一次，因为内存中应该只有每个模块的一个副本。

然而，在这种情况下，情况并非如此。尝试再次运行程序：

```py
$ python test.py
Initializing test.py
Initializing test.py
20

```

正如你所看到的，模块被初始化了*两次*——一次是当它作为脚本运行时，另一次是当`helpers.py`导入该模块时。

为了避免这个问题，请确保你编写的任何脚本只用作脚本。将任何其他代码（例如我们之前示例中的`do_something()`函数）从你的脚本中移除，这样你就永远不需要导入它们。

### 提示

请注意，这并不意味着你不能有变色龙模块，既可以作为模块又可以作为脚本，正如第三章中所描述的那样，*使用模块和包*。只是要小心，你执行的脚本只使用模块本身定义的函数。如果你开始从同一个包中导入其他模块，你可能应该将所有功能移动到一个不同的模块中，然后将其导入到你的脚本中，而不是让它们都在同一个文件中。

# 使用 Python 交互解释器的模块和包

除了从 Python 脚本中调用模块和包，直接从 Python 交互解释器中调用它们通常也很有用。这是使用 Python 编程的**快速应用开发**（**RAD**）技术的一个很好的方法：你对 Python 模块或包进行某种更改，然后立即通过从 Python 交互解释器调用该模块或包来看到你的更改的结果。

然而，还有一些限制和问题需要注意。让我们更仔细地看看你如何使用交互解释器来加快模块和包的开发；我们也会看到不同的方法可能更适合你。

首先创建一个名为`stringutils.py`的新 Python 模块，并将以下代码输入到这个文件中：

```py
import re

def extract_numbers(s):
    pattern = r'[+-]?\d+(?:\.\d+)?'
    numbers = []
    for match in re.finditer(pattern, s):
        number = s[match.start:match.end+1]
        numbers.append(number)
    return numbers
```

这个模块代表我们第一次尝试编写一个从字符串中提取所有数字的函数。请注意，它还没有工作——如果你尝试使用它，`extract_numbers()`函数将崩溃。它也不是特别高效（一个更简单的方法是使用`re.findall()`函数）。但我们故意使用这段代码来展示你如何将快速应用开发技术应用到你的 Python 模块中，所以请耐心等待。

这个函数使用`re`（正则表达式）模块来找到与给定表达式模式匹配的字符串部分。复杂的`pattern`字符串用于匹配数字，包括可选的`+`或`-`在前面，任意数量的数字，以及可选的小数部分在末尾。

使用`re.finditer()`函数，我们找到与我们的正则表达式模式匹配的字符串部分。然后提取字符串的每个匹配部分，并将结果附加到`numbers`列表中，然后将其返回给调用者。

这就是我们的函数应该做的事情。让我们来测试一下。

打开一个终端或命令行窗口，并使用`cd`命令切换到包含`stringutils.py`模块的目录。然后，输入`python`启动 Python 交互解释器。当 Python 命令提示符出现时，尝试输入以下内容：

```py
>>> import stringutils
>>> print(stringutils.extract_numbers("Tes1t 123.543 -10.6 5"))
Traceback (most recent call last):
 **File "<stdin>", line 1, in <module>
 **File "./stringutils.py", line 7, in extract_numbers
 **number = s[match.start:match.end+1]
TypeError: unsupported operand type(s) for +: 'builtin_function_or_method' and 'int'

```

正如你所看到的，我们的模块还没有工作——我们在其中有一个 bug。更仔细地看，我们可以看到问题在我们的`stringutils.py`模块的第 7 行：

```py
        number = s[match.start:match.end+1]
```

错误消息表明您正在尝试将内置函数（在本例中为`match.end`）添加到一个数字（`1`），这当然是行不通的。`match.start`和`match.end`值应该是字符串的开始和结束的索引，但是快速查看`re`模块的文档显示`match.start`和`match.end`是函数，而不是简单的数字，因此我们需要调用这些函数来获取我们想要的值。这样做很容易；只需编辑您的文件的第 7 行，使其看起来像下面这样：

```py
        number = s[match.start():match.end()+1]
```

现在我们已经更改了我们的模块，让我们看看会发生什么。我们将从重新执行`print()`语句开始，看看是否有效：

```py
>>> print(stringutils.extract_numbers("Tes1t 123.543 -10.6 5"))

```

### 提示

您知道您可以按键盘上的上箭头和下箭头键来浏览您之前在 Python 交互解释器中键入的命令历史记录吗？这样可以避免您不得不重新键入命令；只需使用箭头键选择您想要的命令，然后按*Return*执行它。

您将立即看到与之前看到的相同的错误消息-没有任何变化。这是因为您将模块导入 Python 解释器；一旦导入了模块或包，它就会保存在内存中，磁盘上的源文件将被忽略。

为了使您的更改生效，您需要**重新加载**模块。要做到这一点，请在 Python 解释器中键入以下内容：

```py
import importlib
importlib.reload(stringutils)

```

### 提示

如果您使用的是 Python 2.x，则无法使用`importlib`模块。相反，只需键入`reload(stringutils)`。如果您使用的是 Python 3.3 版本，则使用`imp`而不是`importlib`。

现在尝试重新执行`print()`语句：

```py
>>> stringutils.extract_numbers("Hell1o 123.543 -10.6 5 there")
['1o', '123.543 ', '-10.6 ', '5 ']

```

这好多了-我们的程序现在可以正常运行了。然而，我们还需要解决一个问题：当我们提取组成数字的字符时，我们提取了一个多余的字符，所以数字`1`被返回为`1o`等等。要解决这个问题，请从源文件的第 7 行中删除`+1`：

```py
        number = s[match.start():match.end()]
```

然后，再次重新加载模块并重新执行您的`print()`语句。您应该会看到以下内容：

```py
['1', '123.543', '-10.6', '5']

```

完美！如果您愿意，您可以使用`float()`函数将这些字符串转换为浮点数，但对于我们的目的，这个模块现在已经完成了。

让我们退一步，回顾一下我们所做的事情。我们有一个有错误的模块，并使用 Python 交互解释器来帮助识别和修复这些问题。我们反复测试我们的程序，注意到一个错误，并修复它，使用 RAD 方法快速找到和纠正我们模块中的错误。

在开发模块和包时，通常有助于在交互解释器中进行测试，以便在进行过程中找到并解决问题。您只需记住，每次对 Python 源文件进行更改时，您都需要调用`importlib.reload()`来重新加载受影响的模块或包。

以这种方式使用 Python 交互解释器也意味着您可以使用完整的 Python 系统进行测试。例如，您可以使用 Python 标准库中的`pprint`模块来漂亮地打印复杂的字典或列表，以便您可以轻松地查看一个函数返回的信息。

然而，在`importlib.reload()`过程中存在一些限制：

+   想象一下，您有两个模块 A 和 B。模块 A 使用`from B import...`语句从模块 B 加载功能。如果您更改了模块 B，那么模块 A 将不会使用更改后的功能，除非您也重新加载该模块。

+   如果您的模块在初始化时崩溃，它可能会处于奇怪的状态。例如，想象一下，您的模块包括以下顶层代码，它应该初始化一个客户列表：

```py
customers = []
customers.append("Mike Wallis")
cusotmers.append("John Smith")
```

这个模块将被导入，但由于变量名拼写错误，它将在初始化期间引发异常。如果发生这种情况，您首先需要在 Python 交互解释器中使用`import`命令使模块可用，然后使用`imp.reload()`来加载更新后的源代码。

+   因为您必须手动输入命令或从 Python 命令历史记录中选择命令，所以反复运行相同的代码可能会变得乏味，特别是如果您的测试涉及多个步骤。在使用交互式解释器时，很容易错过某个步骤。

因此，最好使用交互式解释器来修复特定问题或帮助您快速开发特定的小代码片段。当测试变得复杂或者需要与多个模块一起工作时，自定义编写的脚本效果更好。

# 处理全局变量

我们已经看到如何使用全局变量在模块内的不同函数之间共享信息。我们已经看到如何在模块内将全局变量定义为顶级变量，导致它们在导入模块时首次初始化，并且我们还看到如何在函数内使用`global`语句允许该函数访问和更改全局变量的值。

在本节中，我们将进一步学习如何在*模块之间*共享全局变量。在创建包时，通常需要定义可以被该包内任何模块访问或更改的变量。有时，还需要将变量提供给包外的 Python 代码。让我们看看如何实现这一点。

创建一个名为`globtest`的新目录，并在此目录中创建一个空的包初始化文件，使其成为 Python 包。然后，在此目录中创建一个名为`globals.py`的文件，并输入以下内容到此文件中：

```py
language = None
currency = None
```

在这个模块中，我们已经定义了两个全局变量，我们希望在我们的包中使用，并为每个变量设置了默认值`None`。现在让我们在另一个模块中使用这些全局变量。

在`globtest`目录中创建另一个名为`test.py`的文件，并输入以下内容到此文件中：

```py
from . import globals

def test():
    globals.language = "EN"
    globals.currency = "USD"
    print(globals.language, globals.currency)
```

要测试您的程序，请打开终端或命令行窗口，使用`cd`命令移动到包含您的`globtest`包的目录，并输入`python`启动 Python 交互解释器。然后，尝试输入以下内容：

```py
>>>** **from globtest import test
>>> test.test()
EN USD

```

如您所见，我们已成功设置了存储在我们的`globals`模块中的`language`和`currency`全局变量的值，然后再次检索这些值以打印它们。因为我们将这些全局变量存储在一个单独的模块中，所以您可以在当前包内的任何地方或者甚至在导入您的包的其他代码中检索或更改这些全局变量。使用单独的模块来保存包的全局变量是管理包内全局变量的一种绝佳方式。

然而，需要注意一点：要使全局变量在模块之间共享，必须导入包含该全局变量的*模块*，而不是变量本身。例如，以下内容不起作用：

```py
from .test import language
```

这个声明的作用是将`language`变量的副本导入到当前模块的全局命名空间中，而不是原始全局命名空间。这意味着全局变量不会与其他模块共享。要使变量在模块之间共享，需要导入`globals`模块，而不是其中的变量。

# 包配置

随着您开发更复杂的模块和包，通常会发现您的代码在使用之前需要以某种方式*配置*。例如，想象一下，您正在编写一个使用数据库的包。为了做到这一点，您的包需要知道要使用的数据库引擎，数据库的名称，以及用于访问该数据库的用户名和密码。

你可以将这些信息硬编码到程序的源代码中，但这样做是一个非常糟糕的主意，有两个原因：

+   不同的计算机和不同的操作系统将使用不同的数据库设置。由于用于访问数据库的信息会因计算机而异，任何想要使用你的包的人都必须直接编辑源代码以输入正确的数据库详细信息，然后才能运行包。

+   用于访问数据库的用户名和密码是非常敏感的信息。如果你与其他人分享你的包，甚至只是将你的包源代码存储在 GitHub 等公共仓库上，那么其他人就可以发现你的数据库访问凭据。这是一个巨大的安全风险。

这些数据库访问凭据是*包配置*的一个例子——在你的包运行之前需要的信息，但你不希望将其构建到包的源代码中。

如果你正在构建一个应用程序而不是一个独立的模块或包，那么你的配置任务就简单得多了。Python 标准库中有一些模块可以帮助配置，例如`configparser`、`shlex`和`json`。使用这些模块，你可以将配置设置存储在磁盘上的文件中，用户可以编辑。当你的程序启动时，你将这些设置加载到内存中，并根据需要访问它们。因为配置设置是存储在应用程序外部的，用户不需要编辑你的源代码来配置程序，如果你的源代码被发布或共享，你也不会暴露敏感信息。

然而，当编写模块和包时，基于文件的配置方法就不那么方便了。没有明显的地方来存储包的配置文件，要求配置文件位于特定位置会使你的模块或包更难以作为不同程序的一部分进行重用。

相反，模块或包的配置通常是通过向模块或包的初始化函数提供参数来完成的。我们在上一章中看到了一个例子，在那里`quantities`包在初始化时需要你提供一个`locale`值：

```py
quantities.init("us")
```

这将配置的工作交给了周围的应用程序；应用程序可以利用配置文件或任何其他喜欢的配置方案，并且是应用程序在包初始化时提供包的配置设置：

![包配置](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mdl-prog-py/img/B05102_7_01.jpg)

这对包开发者来说更加方便，因为包所需要做的就是记住它所得到的设置。

虽然`quantities`包只使用了一个配置设置（区域的名称），但是包通常会使用许多设置。为包提供配置设置的一个非常方便的方式是使用 Python 字典。例如：

```py
mypackage.init({'log_errors'  : True,
                'db_password' : "test123",
                ...})
```

使用字典这种方式可以很容易地支持包的配置设置的*默认值*。以下 Python 代码片段展示了一个包的`init()`函数如何接受配置设置，提供默认值，并将设置存储在全局变量中，以便在需要时可以访问：

```py
def init(settings):
    global config

    config = {}
    config['log_errors']  = settings.get("log_errors",  False)
    config['db_password'] = settings.get("db_password", "")
    ...
```

使用`dict.get()`这种方式，如果已经提供了设置，你就可以检索到该设置，同时提供一个默认值以供在未指定设置时使用。这是处理 Python 模块或包中配置的理想方式，使得模块或包的用户可以根据需要配置它，同时仍然将配置设置的存储方式和位置的细节留给应用程序。

# 包数据

软件包可能包含的不仅仅是 Python 源文件。有时，您可能还需要包含其他类型的文件。例如，一个软件包可能包括一个或多个图像文件，一个包含美国所有邮政编码列表的大型文本文件，或者您可能需要的任何其他类型的数据。如果您可以将某些东西存储在文件中，那么您可以将此文件包含为 Python 软件包的一部分。

通常，您会将软件包数据放在软件包目录中的一个单独的子目录中。要访问这些文件，您的软件包需要知道在哪里找到这个子目录。虽然您可以将该目录的位置硬编码到您的软件包中，但如果您的软件包要被重用或移动，这种方法将行不通。这也是不必要的，因为您可以使用以下代码轻松找到模块所在的目录：

```py
cur_dir = os.path.abspath(os.path.dirname(__file__))
```

这将为您提供包含当前模块的完整路径。使用`os.path.join()`函数，然后可以访问包含数据文件的子目录，并以通常的方式打开它们：

```py
phone_numbers = []
cur_dir = os.path.abspath(os.path.dirname(__file__))
file = open(os.path.join(cur_dir, "data", "phone_numbers.txt"))
for line in file:
    phone_numbers.append(line.strip())
file.close()
```

将数据文件包含在软件包中的好处是，数据文件实际上是软件包源代码的一部分。当您分享软件包或将其上传到 GitHub 等源代码存储库时，数据文件将自动包含在软件包的其余部分中。这使得更容易跟踪软件包使用的数据文件。

# 总结

在本章中，我们看了一些与在 Python 中使用模块和软件包相关的更高级方面。我们看到`try..except`语句如何用于实现可选导入，以及如何将`import`语句放在函数内，以便在执行该函数时仅导入模块。然后我们了解了模块搜索路径以及如何修改`sys.path`以改变 Python 解释器查找模块和软件包的方式。

然后，我们看了一些与使用模块和软件包相关的陷阱。我们了解了名称屏蔽，其中您定义了与 Python 标准库中的模块或软件包相同名称的模块或软件包，这可能导致意外的失败。我们看了一下，给 Python 脚本与标准库模块相同的名称也可能导致名称屏蔽问题，以及如何将软件包目录或子目录添加到`sys.path`可能导致模块被加载两次，从而导致该模块中的全局变量出现微妙的问题。我们看到执行一个模块然后导入它也会导致该模块被加载两次，这可能再次导致问题。

接下来，我们将看看如何使用 Python 交互式解释器作为一种快速应用程序开发（RAD）工具，快速查找和修复模块和软件包中的问题，以及`importlib.reload()`命令允许您在更改底层源代码后重新加载模块

我们通过学习如何定义在整个软件包中使用的全局变量，如何处理软件包配置以及如何在软件包中存储和访问数据文件来完成了对高级模块技术的调查。

在下一章中，我们将看一些您可以测试、部署和分享 Python 模块和软件包的方式。


# 第八章：测试和部署模块

在本章中，我们将进一步探讨共享模块的概念。在您共享模块或包之前，您需要对其进行测试，以确保其正常工作。您还需要准备您的代码并了解如何部署它。为了学习这些内容，我们将涵盖以下主题：

+   了解单元测试如何用于确保您的模块或包正常工作

+   了解如何准备模块或包以供发布

+   了解 GitHub 如何用于与他人共享您的代码

+   审查提交代码到 Python 包索引所涉及的步骤

+   了解如何使用 pip 安装和使用其他人编写的包

# 测试模块和包

测试是编程的正常部分：您测试代码以验证其是否正常工作并识别任何错误或其他问题，然后您可以修复。然后，您继续测试，直到您满意您的代码正常工作为止。

然而，程序员经常只进行**临时测试**：他们启动 Python 交互解释器，导入他们的模块或包，并进行各种调用以查看发生了什么。在上一章中，我们使用`importlib.reload()`函数进行了一种临时测试形式，以支持您的代码的 RAD 开发。

临时测试很有用，但并不是唯一的测试形式。如果您与他人共享您的模块和包，您将希望您的代码没有错误，并临时测试无法保证这一点。一个更好和更系统的方法是为您的模块或包创建一系列**单元测试**。单元测试是 Python 代码片段，用于测试代码的各个方面。由于测试是由 Python 程序完成的，因此您可以在需要测试代码时运行程序，并确保每次运行测试时都会测试所有内容。单元测试是确保在进行更改时错误不会进入您的代码的绝佳方法，并且您可以在需要共享代码时运行它们，以确保其正常工作。

### 注意

单元测试并不是您可以进行的唯一一种程序化测试。**集成测试**结合各种模块和系统，以确保它们正确地一起工作，**GUI 测试**用于确保程序的用户界面正常工作。然而，单元测试对于测试模块和包是最有用的，这也是我们将在本章中重点关注的测试类型。

以下是一个非常简单的单元测试示例：

```py
import math
assert math.floor(2.6197) == 2
```

`assert`语句检查其后的表达式。如果此表达式不计算为`True`，则会引发`AssertionError`。这使您可以轻松检查给定函数是否返回您期望的结果；在此示例中，我们正在检查`math.floor()`函数是否正确返回小于或等于给定浮点数的最大整数。

因为模块或包最终只是一组 Python 函数（或方法，它们只是分组到类中的函数），因此很可能编写一系列调用您的函数并检查返回值是否符合预期的`assert`语句。

当然，这是一个简化：通常调用一个函数的结果会影响另一个函数的输出，并且您的函数有时可以执行诸如与远程 API 通信或将数据存储到磁盘文件中等相当复杂的操作。然而，在许多情况下，您仍然可以使用一系列`assert`语句来验证您的模块和包是否按您的预期工作。

## 使用 unittest 标准库模块进行测试

虽然您可以将您的`assert`语句放入 Python 脚本中并运行它们，但更好的方法是使用 Python 标准库中的`unittest`模块。该模块允许您将单元测试分组为**测试用例**，在运行测试之前和之后运行额外的代码，并访问各种不同类型的`assert`语句，以使您的测试更加容易。

让我们看看如何使用`unittest`模块为我们在第六章中实现的`quantities`包实施一系列单元测试。将此包的副本放入一个方便的目录中，并在同一目录中创建一个名为`test_quantities.py`的新的 Python 源文件。然后，将以下代码添加到此文件中：

```py
import unittest
import quantities

class TestQuantities(unittest.TestCase):
    def setUp(self):
        quantities.init("us")

    def test_new(self):
        q = quantities.new(12, "km")
        self.assertEqual(quantities.value(q), 12)
        self.assertEqual(quantities.units(q), "kilometer")

    def test_convert(self):
        q1 = quantities.new(12, "km")
        q2 = quantities.convert(q1, "m")
        self.assertEqual(quantities.value(q2), 12000)
        self.assertEqual(quantities.units(q2), "meter")

if __name__ == "__main__":
    unittest.main()
```

### 提示

请记住，您不需要手动输入此程序。所有这些源文件，包括`quantities`包的完整副本，都作为本章的示例代码的一部分可供下载。

让我们更仔细地看看这段代码做了什么。首先，`TestQuantities`类用于保存多个相关的单元测试。通常，您会为需要执行的每个主要单元测试组定义一个单独的`unittest.TestCase`子类。在我们的`TestQuantities`类中，我们定义了一个`setUp()`方法，其中包含需要在运行测试之前执行的代码。如果需要，我们还可以定义一个`tearDown()`方法，在测试完成后执行。

然后，我们定义了两个单元测试，我们称之为`test_new()`和`test_convert()`。它们分别测试`quantities.new()`和`quantities.convert()`函数。您通常会为需要测试的每个功能单独创建一个单元测试。您可以随意命名您的单元测试，只要方法名以`test`开头即可。

在我们的`test_new()`单元测试中，我们创建一个新的数量，然后调用`self.assertEqual()`方法来确保已创建预期的数量。正如您所见，我们不仅仅局限于使用内置的`assert`语句；您可以调用几十种不同的`assertXXX()`方法来以各种方式测试您的代码。如果断言失败，所有这些方法都会引发`AssertionError`。

我们测试脚本的最后部分在脚本执行时调用`unittest.main()`。这个函数会查找您定义的任何`unittest.TestCase`子类，并依次运行每个测试用例。对于每个测试用例，如果存在，将调用`setUp()`方法，然后调用您定义的各种`testXXX()`方法，最后，如果存在，将调用`teardown()`方法。

让我们尝试运行我们的单元测试。打开一个终端或命令行窗口，使用`cd`命令将当前目录设置为包含您的`test_quantities.py`脚本的目录，并尝试输入以下内容：

```py
python test_quantities.py

```

一切顺利的话，您应该会看到以下输出：

```py
..
---------------------------------------------------------------
Ran 2 tests in 0.000s

OK

```

默认情况下，`unittest`模块不会显示有关已运行的测试的详细信息，除了它已经无问题地运行了您的单元测试。如果您需要更多细节，您可以增加测试的**详细程度**，例如通过在测试脚本中的`unittest.main()`语句中添加参数：

```py
    unittest.main(verbosity=2)
```

或者，您可以使用`-v`命令行选项来实现相同的结果：

```py
python test_quantities.py -v

```

## 设计您的单元测试

单元测试的目的是检查您的代码是否正常工作。一个很好的经验法则是为包中的每个公共可访问模块单独编写一个测试用例，并为该模块提供的每个功能单独编写一个单元测试。单元测试代码应该至少测试功能的通常操作，以确保其正常工作。如果需要，您还可以选择在单元测试中编写额外的测试代码，甚至额外的单元测试，以检查代码中特定的**边缘情况**。

举个具体的例子，在我们在前一节中编写的`test_convert()`方法中，您可能希望添加代码来检查如果用户尝试将距离转换为重量，则是否会引发适当的异常。例如：

```py
q = quantities.new(12, "km")
with self.assertRaises(ValueError):
    quantities.convert(q, "kg")
```

问题是：您应该为多少边缘情况进行测试？有数百种不同的方式可以使用您的模块不正确。您应该为这些每一种编写单元测试吗？

一般来说，不值得尝试测试每种可能的边缘情况。当然，您可能希望测试一些主要可能性，只是为了确保您的模块能够处理最明显的错误，但除此之外，编写额外的测试可能不值得努力。

## 代码覆盖

**覆盖率**是您的单元测试测试了您的代码多少的度量。要理解这是如何工作的，请考虑以下 Python 函数：

```py
[1] def calc_score(x, y):
[2]     if x == 1:
[3]         score = y * 10
[4]     elif x == 2:
[5]         score = 25 + y
[6]     else:
[7]         score = y
[8]
[9]     return score
```

### 注意

我们已经在每一行的开头添加了行号，以帮助我们计算代码覆盖率。

现在，假设我们为我们的`calc_score()`函数创建以下单元测试代码：

```py
assert calc_score(1, 5) == 50
assert calc_score(2, 10) == 35
```

我们的单元测试覆盖了`calc_score()`函数的多少？我们的第一个`assert`语句调用`calc_score()`，`x`为`1`，`y`为`5`。如果您按照行号，您会发现使用这组参数调用此函数将导致执行第 1、2、3 和 9 行。类似地，第二个`assert`语句调用`calc_score()`，`x`为`2`，`y`为`10`，导致执行第 1、4、5 和 9 行。

总的来说，这两个 assert 语句导致执行第 1、2、3、4、5 和 9 行。忽略空行，我们的测试没有包括第 6 和第 7 行。因此，我们的单元测试覆盖了函数中的八行中的六行，给我们一个代码覆盖率值为 6/8 = 75%。

### 注意

我们在这里看的是**语句覆盖率**。还有其他更复杂的衡量代码覆盖率的方法，我们在这里不会深入讨论。

显然，您不会手动计算代码覆盖率。有一些出色的工具可以计算 Python 测试代码的代码覆盖率。例如，看看`coverage`包（[`pypi.python.org/pypi/coverage`](https://pypi.python.org/pypi/coverage)）。

代码覆盖的基本概念是，您希望您的测试覆盖*所有*您的代码。无论您是否使用诸如`coverage`之类的工具来衡量代码覆盖率，编写单元测试以尽可能包含接近 100%的代码是一个好主意。

## 测试驱动开发

当我们考虑测试 Python 代码的想法时，值得提到**测试驱动开发**的概念。使用测试驱动开发，您首先选择您希望您的模块或包执行的操作，然后编写单元测试以确保模块或包按照您的期望工作—*在您编写它之前*。这样，单元测试充当了模块或包的一种规范；它们告诉您您的代码应该做什么，然后您的任务是编写代码以使其通过所有测试。

测试驱动开发可以是实现模块和包的有用方式。当然，您是否使用它取决于您，但是如果您有纪律写单元测试，测试驱动开发可以是确保您正确实现了代码的一个很好的方式，并且您的模块在代码增长和变化的过程中继续按照您的期望工作。

## Mocking

如果您的模块或包调用外部 API 或执行其他复杂、昂贵或耗时的操作，您可能希望在 Python 标准库中调查`unittest.mock`包。**Mocking**是用程序中的虚拟函数替换某些功能的过程，该虚拟函数立即返回适合测试的数据。

模拟是一个复杂的过程，要做对可能需要一些时间，但如果您想要对本来会太慢、每次运行都会花费金钱或依赖外部系统运行的代码运行单元测试，这种技术绝对是值得的。

## 为您的模块和包编写单元测试

现在我们已经介绍了单元测试的概念，看了一下`unittest`标准库模块的工作原理，并研究了编写单元测试的一些更复杂但重要的方面，现在让我们看看单元测试如何可以用来辅助开发和测试您的模块和包。

首先，您应该至少为您的模块或包定义的主要函数编写单元测试。从测试最重要的函数开始，并为更明显的错误条件添加测试，以确保错误被正确处理。您可以随时为代码中更隐晦的部分添加额外的测试。

如果您为单个模块编写单元测试，您应该将测试代码放在一个单独的 Python 脚本中，例如命名为`tests.py`，并将其放在与您的模块相同的目录中。下面的图片展示了在编写单个模块时组织代码的好方法：

![为您的模块和包编写单元测试](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mdl-prog-py/img/B05012_8_01.jpg)

如果您在同一个目录中有多个模块，您可以将所有模块的单元测试合并到`tests.py`脚本中，或者将其重命名为类似`test_my_module.py`的名称，以明确测试的是哪个模块。

对于一个包，确保将`tests.py`脚本放在包所在的目录中，而不是包内部：

![为您的模块和包编写单元测试](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mdl-prog-py/img/B05012_8_02.jpg)

如果您将`test.py`脚本放在包目录中，当您的单元测试尝试导入包时，您可能会遇到问题。

您的`tests.py`脚本应该为包中每个公开可访问的模块定义一个`unittest.TestCase`对象，并且这些对象中的每一个都应该有一个`testXXX()`方法，用于定义模块中的每个函数或主要功能。

这样做可以通过执行以下命令简单地测试您的模块或包：

```py
python test.py

```

每当您想要检查您的模块是否工作时，特别是在上传或与其他人分享您的模块或包之前，您应该运行单元测试。

# 准备模块或包以供发布

在第六章*创建可重用模块*中，我们看了一些使模块或包适合重用的东西：

+   它必须作为一个独立的单元运行

+   一个包应该理想地使用相对导入

+   您的模块或包中的任何外部依赖关系必须清楚地注明

我们还确定了三个有助于创建优秀可重用模块或包的东西：

+   它应该解决一个普遍的问题

+   您的代码应该遵循标准的编码约定

+   您的模块或包应该有清晰的文档

准备您的模块或包以供发布的第一步是确保您至少遵循了这些准则中的前三条，最好是所有六条。

第二步是确保您至少编写了一些单元测试，并且您的模块或包通过了所有这些测试。最后，您需要决定*如何*发布您的代码。

如果你想与朋友或同事分享你的代码，或者写一篇博客文章并附上你的代码链接，那么最简单的方法就是将其上传到 GitHub 等源代码仓库中。我们将在下一节中看看如何做到这一点。除非你将其设为私有，否则任何拥有正确链接的人都可以访问你的代码。人们可以在线查看你的源代码（包括文档），下载你的模块或包用于他们自己的程序，并且“fork”你的代码，创建他们自己的私人副本，然后进行修改。

如果你想与更广泛的受众分享你的代码，最好的方法是将其提交到**Python Package Index**（**PyPI**）。这意味着其他人可以通过在 PyPI 索引中搜索来找到你的模块或包，并且任何人都可以使用**pip**，Python 包管理器来安装它。本章的后续部分将描述如何将你的模块或包提交到 PyPI，以及如何使用 pip 来下载和使用模块和包。

# 将你的工作上传到 GitHub。

GitHub（[`github.com/`](https://github.com/)）是一个流行的基于 Web 的存储和管理源代码的系统。虽然有几种替代方案，但 GitHub 在编写和分享开源 Python 代码的人中特别受欢迎，这也是我们在本书中将使用的源代码管理系统。

在深入讨论 GitHub 的具体内容之前，让我们先看看源代码管理系统是如何工作的，以及为什么你可能想要使用它。

想象一下，你正在编写一个复杂的模块，并在文本编辑器中打开了你的模块进行一些更改。在进行这些更改的过程中，你不小心选择了 100 行代码，然后按下了*删除*键。在意识到自己做了什么之前，你保存并关闭了文件。太迟了：那 100 行文本已经消失了。

当然，你可能（并且希望）有一个备份系统，定期备份你的源文件。但如果你在过去几分钟内对一些丢失的代码进行了更改，那么你很可能已经丢失了这些更改。

现在考虑这样一种情况：你与同事分享了一个模块或包，他们决定做一些更改。也许有一个需要修复的错误，或者他们想要添加一个新功能。他们改变了你的代码，并在附有说明的情况下将其发送回给你。不幸的是，除非你比较原始版本和修改后的源文件中的每一行，否则你无法确定你的同事对你的文件做了什么。

源代码管理系统解决了这些问题。你不仅仅是在硬盘上的一个目录中拥有你的模块或包的副本，而是在像 GitHub 这样的源代码管理系统中创建一个**仓库**，并将你的源代码**提交**到这个仓库中。然后，当你对文件进行更改，修复错误和添加功能时，你将每个更改都提交回仓库。源代码仓库跟踪了你所做的每一次更改，允许你准确地查看随时间发生的变化，并在必要时撤消先前所做的更改。

你不仅仅局限于让一个人来工作在一个模块或包上。人们可以**fork**你的源代码仓库，创建他们自己的私人副本，然后使用这个私人副本来修复错误和添加新功能。一旦他们这样做了，他们可以向你发送一个**pull request**，其中包括他们所做的更改。然后你可以决定是否将这些更改合并到你的项目中。

不要太担心这些细节，源代码管理是一个复杂的话题，使用 GitHub 等工具可以执行许多复杂的技巧来管理源代码。要记住的重要事情是，创建一个存储库来保存模块或软件包的源代码的主要副本，将代码提交到这个存储库中，然后每次修复错误或添加新功能时都要继续提交。以下插图总结了这个过程：

![将您的工作上传到 GitHub](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mdl-prog-py/img/B05012_8_03.jpg)

源代码管理系统的诀窍是定期提交 - 每次添加新功能或修复错误时，您都应立即提交更改。这样，存储库中一个版本和下一个版本之间的差异只是添加了一个功能或修复了一个问题的代码。如果在提交之前对源代码进行了多次更改，存储库将变得不那么有用。

既然我们已经了解了源代码管理系统的工作原理，让我们实施一个真实的示例，看看如何使用 GitHub 来管理您的源代码。首先，转到 GitHub 的主要网站（[`github.com/`](https://github.com/)）。如果您没有 GitHub 帐户，您需要注册，选择一个唯一的用户名，并提供联系电子邮件地址和密码。如果您以前使用过 GitHub，可以使用已设置的用户名和密码登录。

请注意，注册和使用 GitHub 是免费的；唯一的限制是您创建的每个存储库都将是公开的，因此任何希望的人都可以查看您的源代码。如果您想要，您可以设置私有存储库，但这些会产生月费。但是，由于我们使用 GitHub 与他人分享我们的代码，拥有私有存储库是没有意义的。只有在您想要与一组特定的人分享代码并阻止其他人访问时，才需要私有（付费）存储库。如果您处于必须这样做的位置，支付私有存储库是您最不用担心的事情。

登录 GitHub 后，您的下一个任务是安装**Git**的命令行工具。Git 是 GitHub 使用的基础源代码管理工具包；您将使用`git`命令从命令行处理您的 GitHub 存储库。

要安装所需的软件，请转到[`git-scm.com/downloads`](https://git-scm.com/downloads)并下载适用于您特定操作系统的安装程序。下载完成后，运行安装程序，并按照安装`git`命令行工具的说明进行操作。完成后，打开终端或命令行窗口，尝试输入以下命令：

```py
git --version

```

一切顺利的话，您应该看到已安装的`git`命令行工具的版本号。

完成这些先决条件后，让我们使用 GitHub 创建一个示例存储库。返回[`github.com/`](https://github.com/)网页，点击绿色高亮显示的**+新存储库**按钮。您将被要求输入要创建的存储库的详细信息：

![将您的工作上传到 GitHub](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mdl-prog-py/img/B05012_8_04.jpg)

要设置存储库，请输入`test-package`作为存储库的名称，并从**添加.gitignore**下拉菜单中选择**Python**。`.gitignore`文件用于从存储库中排除某些文件；为 Python 使用`.gitignore`文件意味着 Python 创建的临时文件不会包含在存储库中。

最后，点击**创建存储库**按钮创建新存储库。

### 提示

确保不要选择**使用 README 初始化此存储库**选项。您不希望在此阶段创建一个 README 文件；很快就会清楚原因。

现在 GitHub 上已经创建了存储库，我们的下一个任务是**克隆**该存储库的副本到您计算机的硬盘上。为此，创建一个名为`test-package`的新目录来保存存储库的本地副本，打开终端或命令行窗口，并使用`cd`命令移动到您的新`test-package`目录。然后，输入以下命令：

```py
git clone https://<username>@github.com/<username>/test-package.git .

```

确保您在上述命令中替换`<username>`的两个实例为您的 GitHub 用户名。您将被提示输入 GitHub 密码以进行身份验证，并且存储库的副本将保存到您的新目录中。

因为存储库目前是空的，您在目录中看不到任何内容。但是，有一些隐藏文件`git`用来跟踪您对存储库的本地副本。要查看这些隐藏文件，您可以从终端窗口使用`ls`命令：

```py
$ ls -al
drwxr-xr-x@  7 erik  staff   238 19 Feb 21:28 .
drwxr-xr-x@  7 erik  staff   238 19 Feb 14:35 ..
drwxr-xr-x@ 14 erik  staff   476 19 Feb 21:28 .git
-rw-r--r--@  1 erik  staff   844 19 Feb 15:09 .gitignore

```

`.git`目录包含有关您的新 GitHub 存储库的信息，而`.gitignore`文件包含您要求 GitHub 为您设置的忽略 Python 临时文件的指令。

现在我们有了一个（最初为空的）存储库，让我们在其中创建一些文件。我们需要做的第一件事是为我们的包选择一个唯一的名称。因为我们的包将被提交到 Python 包索引，所以名称必须是真正唯一的。为了实现这一点，我们将使用您的 GitHub 用户名作为我们包名称的基础，就像这样：

```py
<username>-test-package
```

例如，由于我的 GitHub 用户名是"erikwestra"，我将为这个包使用`erikwestra-test-package`。确保您根据您的 GitHub 用户名选择一个名称，以确保包名称是真正唯一的。

现在我们有了一个包的名称，让我们创建一个描述这个包的 README 文件。在您的`test-package`目录中创建一个名为`README.rst`的新文本文件，并将以下内容放入此文件中：

```py
<username>-test-package
-----------------------

This is a simple test package. To use it, type::

    from <username>_test_package import test
    test.run()
```

确保您用您的 GitHub 用户名替换每个`<username>`的出现。这个文本文件是以**reStructuredText 格式**。reStructuredText 是 PyPI 用来显示格式化文本的格式语言。

### 注意

虽然 GitHub 可以支持 reStructuredText，但默认情况下它使用一种名为**Markdown**的不同文本格式。Markdown 和 reStructuredText 是两种竞争格式，不幸的是，PyPI 需要 reStructuredText，而 GitHub 默认使用 Markdown。这就是为什么我们告诉 GitHub 在设置存储库时不要创建 README 文件的原因；如果我们这样做了，它将以错误的格式存在。

当用户在 GitHub 上查看您的存储库时，他们将看到此文件的内容按照 reStructuredText 规则整齐地格式化：

![将您的工作上传到 GitHub](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mdl-prog-py/img/B05012_8_05.jpg)

如果您想了解更多关于 reStructuredText 的信息，您可以在[`docutils.sourceforge.net/rst.html`](http://docutils.sourceforge.net/rst.html)上阅读所有相关内容。

现在我们已经为我们的包设置了 README 文件，让我们创建包本身。在`test-package`内创建另一个名为`<username>_test_package`的目录，将空的包初始化文件（`__init__.py`）放入此目录。然后，在`<username>_test_package`目录内创建另一个名为`test.py`的文件，并将以下内容放入此文件：

```py
import string
import random

def random_name():
    chars = []
    for i in range(random.randrange(3, 10)):
        chars.append(random.choice(string.ascii_letters))
    return "".join(chars)

def run():
    for i in range(10):
        print(random_name())
```

这只是一个例子，当然。调用`test.run()`函数将导致显示十个随机名称。更有趣的是，我们现在已经为我们的测试包定义了初始内容。但是，我们所做的只是在我们的本地计算机上创建了一些文件；这并不会影响 GitHub，如果您在 GitHub 中重新加载存储库页面，您的新文件将不会显示出来。

要使我们的更改生效，我们需要**提交**更改到存储库。我们将首先查看我们的本地副本与存储库中的副本有何不同。为此，请返回到您的终端窗口，`cd`进入`test-package`目录，并键入以下命令：

```py
git status

```

您应该看到以下输出：

```py
# On branch master
# Untracked files:
#   (use "git add <file>..." to include in what will be committed)
#
#  README.rst
#  <username>_test_package/
nothing added to commit but untracked files present (use "git add" to track)

```

描述可能有点令人困惑，但并不太复杂。基本上，GitHub 告诉您有一个新文件`README.rst`和一个新目录，名为`<username>_test_package`，它不知道（或者在 GitHub 的说法中是“未跟踪”）。让我们将这些新条目添加到我们的存储库中：

```py
git add README.rst
git add <username>_test_package

```

确保您将`<username>`替换为您的 GitHub 用户名。如果您现在键入`git status`，您将看到我们创建的文件已添加到存储库的本地副本中：

```py
# On branch master
# Changes to be committed:
#   (use "git reset HEAD <file>..." to unstage)
#
#  new file:   README.rst
#  new file:   <username>_test_package/__init__.py
#  new file:   <username>_test_package/test.py

```

每当您向项目添加新目录或文件时，您需要使用`git add`命令将其添加到存储库中。随时可以通过键入`git status`命令并查找“未跟踪”文件来查看是否漏掉了任何文件。

现在我们已经包含了我们的新文件，让我们将更改提交到存储库。键入以下命令：

```py
git commit -a -m 'Initial commit.'

```

这将向您的存储库的本地副本提交一个新更改。`-a`选项告诉 GitHub 自动包括任何更改的文件，`-m`选项允许您输入一个简短的消息，描述您所做的更改。在这种情况下，我们的提交消息设置为值"`Initial commit.`"。

现在我们已经提交了更改，我们需要从本地计算机上传到 GitHub 存储库。为此，请键入以下命令：

```py
git push

```

您将被提示输入您的 GitHub 密码以进行身份验证，并且您提交的更改将存储到 GitHub 上的存储库中。

### 注意

GitHub 将`commit`命令与`push`命令分开，因为您可能需要在更改程序时进行多次提交，而不一定在线上。例如，如果您在长途飞行中，可以在本地工作，每次更改时进行提交，然后在降落并再次拥有互联网访问时一次性推送所有更改。

现在您的更改已推送到服务器，您可以在 GitHub 上重新加载页面，您新创建的软件包将出现在存储库中：

![将您的工作上传到 GitHub](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mdl-prog-py/img/B05012_8_06.jpg)

您还将看到您的`README.rst`文件的内容显示在文件列表下面，描述了您的新软件包及其使用方法。

每当您对软件包进行更改时，请确保按照以下步骤保存更改到存储库中：

1.  使用`git status`命令查看发生了什么变化。如果您添加了需要包含在存储库中的任何文件，请使用`git add`将它们添加进去。

1.  使用`git commit -a -m '<commit message>'`命令将更改提交到您的 GitHub 存储库的本地副本。确保输入适当的提交消息来描述您所做的更改。

1.  当您准备好这样做时，请使用`git push`命令将提交的更改发送到 GitHub。

当然，使用 GitHub 还有很多内容，还有许多命令和选项，一旦您开始使用，您无疑会想要探索，但这已经足够让您开始了。

一旦您为您的 Python 模块或软件包设置了 GitHub 存储库，就可以轻松地与其他人共享您的代码。您只需要分享您的 GitHub 存储库的链接，其他人就可以下载他们想要的文件。

为了使这个过程更加简单，并使您的软件包可以被更广泛的用户搜索到，您应该考虑将您的软件包提交到 Python 软件包索引。接下来我们将看看涉及到这样做的步骤。

# 提交到 Python 软件包索引

要将您的 Python 软件包提交到 Python 软件包索引，您首先必须在[`pypi.python.org/pypi`](https://pypi.python.org/pypi)免费注册一个帐户。单击页面右上角框中的**注册**链接：

![提交到 Python 软件包索引](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mdl-prog-py/img/B05012_8_07.jpg)

您需要选择一个用户名和密码，并提供一个电子邮件地址。记住您输入的用户名和密码，因为您很快就会需要它。当您提交表单时，您将收到一封包含链接的电子邮件，您需要点击该链接以完成注册。

在将项目提交到 PyPI 之前，您需要添加两个文件，一个是`setup.py`脚本，用于打包和上传您的软件包，另一个是`LICENSE.txt`文件，用于描述您的软件包可以使用的许可证。现在让我们添加这两个文件。

在您的`test-package`目录中创建一个名为`setup.py`的文件，并输入以下内容：

```py
from distutils.core import setup

setup(name="<username>-test-package",
      packages=["<username>_test_package"],
      version="1.0",
      description="Test Package",
      author="<your name>",
      author_email="<your email address>",
      url="https://github.com/<username>/test-package",
      download_url="https://github.com/<username>/test-package/tarball/1.0",
      keywords=["test", "python"],
      classifiers=[])
```

确保将每个`<username>`替换为您的 GitHub 用户名，并将`<your name>`和`<your email address>`替换为相关值。因为这只是一个测试，我们为此软件包使用名称`<username>-test-package`；对于真实项目，我们将为我们的软件包使用一个更有意义（但仍然是唯一的）名称。

### 注意

请注意，此版本的`setup.py`脚本使用了**Distutils**软件包。Distutils 是 Python 标准库的一部分，是创建和分发代码的简单方法。还有一个名为**Setuptools**的替代库，许多人更喜欢它，因为它是一个功能更多、更现代的库，并且通常被视为 Distutils 的继任者。但是，Setuptools 目前不是 Python 标准库的一部分。由于它更容易使用并且具有我们需要的所有功能，我们在这里使用 Distutils 来尽可能简化这个过程。如果您熟悉使用它，请随时使用 Setuptools 而不是 Distutils，因为对于我们在这里所做的事情，两者是相同的。

最后，我们需要创建一个名为`LICENSE.txt`的新文本文件。该文件将保存您发布软件包的软件许可证。包含许可证非常重要，以便人们准确知道他们可以和不能做什么，您不能提交一个没有提供许可证的软件包。

虽然您可以在`LICENSE.txt`文件中放入任何您喜欢的内容，但通常应使用现有的软件许可证之一。例如，您可能想使用[`opensource.org/licenses/MIT`](https://opensource.org/licenses/MIT)提供的 MIT 许可证——该许可证使您的代码可供他人任何目的使用，同时确保您不会对其使用中可能出现的任何问题负责。

有了这两个文件，您最终可以将您的新软件包提交到 Python 软件包索引。要做到这一点，请在您的终端或命令行窗口中键入以下命令：

```py
python setup.py register

```

此命令将尝试使用 Python 软件包索引注册您的新软件包。您将被要求输入您的 PyPI 用户名和密码，并有机会存储这些信息，以便您不必每次都重新输入。一旦软件包成功注册，您可以通过输入以下命令上传软件包内容：

```py
python setup.py sdist upload

```

在将您的软件包上传到 PyPI 之前，您会看到一些警告，您可以安全地忽略这些警告。然后，您可以转到 PyPI 网站，您将看到您的新软件包已列出：

![提交到 Python 软件包索引](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mdl-prog-py/img/B05012_8_08.jpg)

如你所见，**Home Page**链接指向你在 GitHub 上的项目页面，并且有一个直接下载链接，用于你的包的 1.0 版本。然而，不幸的是，这个下载链接还不起作用，因为你还没有告诉 GitHub 你的包的 1.0 版本是什么样子。为了做到这一点，你必须在 GitHub 中创建一个与你的系统版本 1.0 相对应的**标签**；GitHub 将会创建一个与该标签匹配的可下载版本的你的包。

在创建 1.0 版本之前，你应该提交你对仓库所做的更改。这本来就是一个好习惯，所以让我们看看如何做：首先输入`git status`，查看已添加或更改的文件，然后使用`git add`逐个添加每个未跟踪的文件。完成后，输入`git commit -a -m 'Preparing for PyPI submission'`将你的更改提交到仓库。最后，输入`git push`将你提交的更改发送到 GitHub。

完成所有这些后，你可以通过输入以下命令创建与你的包的 1.0 版本相对应的标签：

```py
git tag 1.0 -m 'Version 1.0 of the <username>_test_package.'

```

确保你用你的 GitHub 用户名替换`<username>`，以便包名正确。最后，使用以下`git push`命令的变体将新创建的标签复制到 GitHub 服务器：

```py
git push --tags

```

再次，你将被要求输入你的 GitHub 密码。当这个命令完成时，你将在`https://github.com/<username>/test-package/tarball/1.0`上找到你的包的 1.0 版本可供下载，其中`<username>`是你的 GitHub 用户名。如果你现在去 PyPI 寻找你的测试包，你将能够点击**Download URL**链接下载你的 1.0 包的副本。

如果你的新包出现在 Python 包索引中，并且你可以通过**Download**链接成功下载你的包的 1.0 版本，那么你应该得到表扬。恭喜！这是一个复杂的过程，但它将为你的可重用模块和包提供尽可能多的受众。

# 使用 pip 下载和安装模块和包

在本书的第四章和第五章中，我们使用了**pip**，Python 包管理器，来安装我们想要使用的各种库。正如我们在第七章中所学到的，pip 通常会将一个包安装到 Python 的`site-packages`目录中。由于这个目录在模块搜索路径中列出，你新安装的模块或包就可以被导入和在你的代码中使用。

现在让我们使用 pip 来安装我们在上一节中创建的测试包。由于我们知道我们的包已经被命名为`<username>_test_package`，其中`<username>`是你的 GitHub 用户名，你可以通过在终端或命令行窗口中输入以下命令，直接将这个包安装到你的`site-packages`目录中：

```py
pip install <username>_test_package

```

确保你用你的 GitHub 用户名替换`<username>`。请注意，如果你没有权限写入 Python 安装的`site-packages`目录，你可能需要在这个命令的开头添加`sudo`：

```py
sudo pip install <username>_test_package

```

如果你这样做，你将被提示在运行`pip`命令之前输入你的管理员密码。

一切顺利的话，你应该看到各种命令被运行，因为你新创建的包被下载和安装。假设这成功了，你可以开始你的 Python 解释器，并访问你的新包，就像它是 Python 标准库的一部分一样。例如：

```py
>>> from <username>_test_package import test
>>> test.run()
IFIbH
AAchwnW
qVtRUuSyb
UPF
zXkY
TMJEAZm
wRJCqgomV
oMzmv
LaDeVg
RDfMqScM

```

当然，不仅你可以做到这一点。其他 Python 开发人员也可以以完全相同的方式访问你的新包。这使得开发人员非常容易地下载和使用你的包。

除了一些例外情况，您可以使用 pip 从 Python 软件包索引安装任何软件包。默认情况下，pip 将安装软件包的最新可用版本；要指定特定版本，您可以在安装软件包时提供版本号，就像这样：

```py
pip install <username>_test_package == 1.0

```

这将安装您的测试软件包的 1.0 版本。如果您已经安装了一个软件包，并且有一个更新的版本可用，您可以使用`--upgrade`命令行选项将软件包升级到更新的版本：

```py
pip install --upgrade <username>_test_package

```

您还可以使用`list`命令获取已安装的软件包列表：

```py
pip list

```

还有一个 pip 的功能需要注意。您可以创建一个**要求文件**，列出您想要的所有软件包，并一次性安装它们。典型的要求文件看起来可能是这样的：

```py
Django==1.8.2
Pillow==3.0.0
reportlab==3.2.0
```

要求文件列出了您想要安装的各种软件包及其关联的版本号。

按照惯例，要求文件的名称为`requirements.txt`，并放置在项目的顶层目录中。要求文件非常有用，因为它们使得通过一个命令轻松地重新创建 Python 开发环境成为可能，包括程序所依赖的所有软件包。这是通过以下方式完成的：

```py
pip install -r requirements.txt

```

由于要求文件存储在程序源代码旁边，通常会在源代码存储库中包含`requirements.txt`文件。这意味着您可以克隆存储库到新计算机，并且只需一个命令，重新安装程序所依赖的所有模块和包。

虽然您可以手动创建一个要求文件，但通常会使用 pip 为您创建此文件。安装所需的模块和软件包后，您可以使用以下命令创建`requirements.txt`文件：

```py
pip freeze > requirements.txt

```

这个命令的好处是，您可以在任何时候重新运行它，以满足您的要求变化。如果您发现您的程序需要使用一个新的模块或软件包，您可以使用`pip install`来安装新的模块或软件包，然后立即调用`pip freeze`来创建一个包含新依赖项的更新要求文件。

在安装和使用模块和软件包时，还有一件事需要注意：有时，您需要安装*不同*版本的模块或软件包。例如，也许您想运行一个需要 Django 软件包 1.6 版本的特定程序，但您只安装了 1.4 版本。如果您更新 Django 到 1.6 版本，可能会破坏依赖于它的其他程序。

为了避免这种情况，您可能会发现在您的计算机上设置一个**虚拟环境**非常有用。虚拟环境就像一个单独的 Python 安装，拥有自己安装的模块和软件包。您可以为每个项目创建一个单独的虚拟环境，这样每个项目都可以有自己的依赖关系，而不会干扰您可能在计算机上安装的其他项目的要求。

当您想要使用特定的虚拟环境时，您必须**激活**它。然后，您可以使用`pip install`将各种软件包安装到该环境中，并使用您安装的软件包运行程序。当您想要完成对该环境的工作时，您可以**停用**它。这样，您可以根据需要在不同项目上工作时在虚拟环境之间切换。

虚拟环境是处理不同且可能不兼容的软件包要求的项目的非常强大的工具。您可以在[`docs.python-guide.org/en/latest/dev/virtualenvs/`](http://docs.python-guide.org/en/latest/dev/virtualenvs/)找到有关虚拟环境的更多信息。

# 总结

在本章中，我们了解了各种测试 Python 模块和包的方法。我们了解了单元测试以及 Python 标准库中的`unittest`包如何更容易地编写和使用你开发的模块和包的单元测试。我们看到单元测试如何使用`assert`语句（或者如果你使用`unittest.TestCase`类，则使用各种`assertXXX()`方法）来在特定条件未满足时引发`AssertionError`。通过编写各种单元测试，你可以确保你的模块和包按照你的期望工作。

我们接着看了准备模块或包进行发布的过程，并了解了 GitHub 如何提供一个优秀的存储库来存储和管理你的模块和包的源代码。

在创建了我们自己的测试包之后，我们通过了将该包提交到 Python Package Index 的过程。最后，我们学会了如何使用 pip，Python 包管理器，将一个包从 PyPI 安装到系统的`site-packages`目录中，然后看了一下使用要求文件或虚拟环境来帮助管理程序依赖的方法。

在本书的最后一章中，我们将看到模块化编程如何更普遍地作为良好编程技术的基础。


# 第九章：模块化编程作为良好编程技术的基础

在本书中，我们已经走了很长的路。从学习 Python 中模块和包的工作原理，以及如何使用它们更好地组织代码，我们发现了许多常见的实践，用于应用模块化模式来解决各种编程问题。我们已经看到模块化编程如何允许我们以最佳方式处理现实世界系统中的变化需求，并学会了使模块或包成为在新项目中重复使用的合适候选者的条件。我们已经看到了许多 Python 中处理模块和包的更高级技术，以及避免在这一过程中可能遇到的陷阱的方法。

最后，我们看了测试代码的方法，如何使用源代码管理系统来跟踪您对代码的更改，以及如何将您的模块或包提交到 Python 包索引（PyPI），以便其他人可以找到并使用它。

利用我们迄今为止学到的知识，您将能够熟练应用模块化技术到您的 Python 编程工作中，创建健壮且编写良好的代码，可以在各种程序中重复使用。您还可以与其他人分享您的代码，无论是在您的组织内部还是更广泛的 Python 开发者社区内。

在本章中，我们将使用一个实际的例子来展示模块和包远不止于组织代码：它们有助于更有效地处理编程的*过程*。我们将看到模块对于任何大型系统的设计和开发是至关重要的，并演示使用模块化技术创建健壮、有用和编写良好的模块是成为一名优秀程序员的重要组成部分。

# 编程的过程

作为程序员，我们往往过于关注程序的技术细节。也就是说，我们关注*产品*而不是编程的*过程*。解决特定编程问题的困难是如此之大，以至于我们忘记了问题本身会随着时间的推移而发生变化。无论我们多么努力避免，变化都是不可避免的：市场的变化、需求的变化和技术的变化。作为程序员，我们需要能够有效地应对这种变化，就像我们需要能够实施、测试和调试我们的代码一样。

回到第四章*用于真实世界编程的模块*，我们看了一个面临变化需求挑战的示例程序。我们看到模块化设计如何使我们能够在程序的范围远远超出最初设想的情况下最小化需要重写的代码量。

现在我们已经更多地了解了模块化编程和相关技术，可以帮助使其更加有效，让我们再次通过这个练习。这一次，我们将选择一个简单的包，用于计算某个事件或对象的发生次数。例如，想象一下，您需要记录在农场散步时看到每种动物的数量。当您看到每种动物时，通过将其传递给计数器来记录其存在，最后，计数器将告诉您每种动物您看到了多少只。例如：

```py
>>> counter.reset()
>>> counter.add("sheep")
>>> counter.add("cow")
>>> counter.add("sheep")
>>> counter.add("rabbit")
>>> counter.add("cow")
>>> print(counter.totals())
[("cow", 2), ("rabbit", 1), ("sheep", 2)]

```

这是一个简单的包，但它为我们提供了一个很好的目标，可以应用我们在前几章学到的一些更有用的技术。特别是，我们将利用**文档字符串**来记录我们包中每个函数的功能，并编写一系列**单元测试**来确保我们的包按照我们的预期工作。

让我们开始创建一个目录来保存我们的新项目，我们将其称为 Counter。在方便的地方创建一个名为`counter`的目录，然后在该目录中添加一个名为`README.rst`的新文件。由于我们希望最终将这个包上传到 Python 包索引，我们将使用 reStructuredText 格式来编写我们的 README 文件。在该文件中输入以下内容：

```py
About the ``counter`` package
-----------------------------

``counter`` is a package designed to make it easy to keep track of the number of times some event or object occurs.  Using this package, you **reset** the counter, **add** the various values to the counter, and then retrieve the calculated **totals** to see how often each value occurred.
```

让我们更仔细地看看这个包可能如何使用。假设您想要统计在给定时间范围内观察到的每种颜色的汽车数量。您将首先进行以下调用：

```py
    counter.reset()
```

然后当您识别到特定颜色的汽车时，您将进行以下调用：

```py
    counter.add(color)
```

最后，一旦时间结束，您将以以下方式获取各种颜色及其出现次数：

```py
    for color,num_occurrences in counter.totals():
        print(color, num_occurrences)
```

然后计数器可以被重置以开始计算另一组值。

现在让我们实现这个包。在我们的`counter`目录中，创建另一个名为`counter`的目录来保存我们包的源代码，并在这个最里层的`counter`目录中创建一个包初始化文件(`__init__.py`)。我们将按照之前使用的模式，在一个名为`interface.py`的模块中定义我们包的公共函数，然后将其导入`__init__.py`文件中，以便在包级别提供各种函数。为此，编辑`__init__.py`文件，并在该文件中输入以下内容：

```py
from .interface import *
```

我们的下一个任务是实现`interface`模块。在`counter`包目录中创建`interface.py`文件，并在该文件中输入以下内容：

```py
def reset():
    pass

def add(value):
    pass

def totals():
    pass
```

这些只是我们`counter`包的公共函数的占位符；我们将逐一实现这些函数，从`reset()`函数开始。

遵循使用文档字符串记录每个函数的推荐做法，让我们从描述这个函数做什么开始。编辑现有的`reset()`函数定义，使其看起来像以下内容：

```py
def reset():
    """ Reset our counter.

        This should be called before we start counting.
    """
    pass
```

请记住，文档字符串是一个三引号字符串（跨越多行的字符串），它“附加”到一个函数上。文档字符串通常以对函数做什么的一行描述开始。如果需要更多信息，这将后跟一个空行，然后是一行或多行更详细描述函数的信息。正如您所看到的，我们的文档字符串包括一行描述和一行额外提供有关函数的更多信息。

现在我们需要实现这个函数。由于我们的计数器包需要跟踪每个唯一值出现的次数，将这些信息存储在一个将唯一值映射到出现次数的字典中是有意义的。我们可以将这个字典存储为一个私有全局变量，由我们的`reset()`函数初始化。知道了这一点，我们可以继续实现我们`reset()`函数的其余部分：

```py
def reset():
    """ Reset our counter.

        This should be called before we start counting.
    """
    global _counts
    _counts = {} # Maps value to number of occurrences.
```

有了私有的`_counts`全局变量定义，我们现在可以实现`add()`函数。这个函数记录给定值的出现次数，并将结果存储到`_counts`字典中。用以下代码替换`add()`函数的占位实现：

```py
def add(value):
    """ Add the given value to our counter.
    """
    global _counts

    try:
        _counts[value] += 1
    except KeyError:
        _counts[value] = 1
```

这里不应该有任何意外。我们的最终函数`totals()`返回了添加到`_counts`字典中的值，以及每个值出现的次数。以下是必要的代码，应该替换您现有的`totals()`函数的占位符：

```py
def totals():
    """ Return the number of times each value has occurred.

        We return a list of (value, num_occurrences) tuples, one
        for each unique value included in the count.
    """
    global _counts

    results = []
    for value in sorted(_counts.keys()):
        results.append((value, _counts[value]))
    return results
```

这完成了我们对`counter`包的第一个实现。我们将尝试使用我们在上一章学到的临时测试技术来测试它：打开一个终端或命令行窗口，使用`cd`命令将当前目录设置为最外层的`counter`目录。然后，输入`python`启动 Python 交互解释器，并尝试输入以下命令：

```py
import counter
counter.reset()
counter.add(1)
counter.add(2)
counter.add(1)
print(counter.totals())

```

一切顺利的话，您应该会看到以下输出：

```py
[(1, 2), (2, 1)]

```

这告诉您值`1`出现了两次，值`2`出现了一次——这正是您对`add()`函数的调用所表明的。

现在我们的软件包似乎正在工作，让我们创建一些单元测试，以便更系统地测试我们的软件包。在最外层的`counter`目录中创建一个名为`tests.py`的新文件，并将以下代码输入到这个文件中：

```py
import unittest
import counter

class CounterTestCase(unittest.TestCase):
    """ Unit tests for the ``counter`` package.
    """
    def test_counter_totals(self):
        counter.reset()
        counter.add(1)
        counter.add(2)
        counter.add(3)
        counter.add(1)
        self.assertEqual(counter.totals(),
                         [(1, 2), (2, 1), (3, 1)])

    def test_counter_reset(self):
        counter.reset()
        counter.add(1)
        counter.reset()
        counter.add(2)
        self.assertEqual(counter.totals(), [(2, 1)])

if __name__ == "__main__":
    unittest.main()
```

如您所见，我们编写了两个单元测试：一个用于检查我们添加的值是否反映在计数器的总数中，另一个用于确保`reset()`函数正确地重置计数器，丢弃了在调用`reset()`之前添加的任何值。

要运行这些测试，退出 Python 交互解释器，按下*Control* + *D*，然后在命令行中输入以下内容：

```py
python tests.py

```

一切顺利的话，您应该会看到以下输出，表明您的两个单元测试都没有出现错误：

```py
..
---------------------------------------------------------------------
Ran 2 tests in 0.000s

OK

```

## 不可避免的变化

在这个阶段，我们现在有一个完全正常工作的`counter`软件包，具有良好的文档和单元测试。然而，想象一下，您的软件包的要求现在发生了变化，对您的设计造成了重大问题：现在不再是简单地计算唯一值的数量，而是需要支持*值的范围*。例如，您的软件包的用户可能会定义从 0 到 5、5 到 10 和 10 到 15 的值范围；每个范围内的值都被分组在一起进行计数。以下插图显示了如何实现这一点：

![不可避免的变化](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mdl-prog-py/img/B05012_9_01.jpg)

为了使您的软件包支持范围，您需要更改接口以接受可选的范围值列表。例如，要计算 0 到 5、5 到 10 和 10 到 15 之间的值，可以使用以下参数调用`reset()`函数：

```py
counter.reset([0, 5, 10, 15])
```

如果没有参数传递给`counter.reset()`，那么整个软件包应该继续像现在一样工作，记录唯一值而不是范围。

让我们实现这个新功能。首先，编辑`reset()`函数，使其看起来像下面这样：

```py
def reset(ranges=None):
    """ Reset our counter.

        If 'ranges' is supplied, the given list of values will be
        used as the start and end of each range of values.  In
        this case, the totals will be calculated based on a range
        of values rather than individual values.

        This should be called before we start counting.
    """
    global _ranges
    global _counts

    _ranges = ranges
    _counts = {} # If _ranges is None, maps value to number of
                 # occurrences.  Otherwise, maps (min_value,
                 # max_value) to number of occurrences.
```

这里唯一的区别，除了更改文档，就是我们现在接受一个可选的`ranges`参数，并将其存储到私有的`_ranges`全局变量中。

现在让我们更新`add()`函数以支持范围。更改您的源代码，使得这个函数看起来像下面这样：

```py
def add(value):
    """ Add the given value to our counter.
    """
    global _ranges
    global _counts

    if _ranges == None:
        key = value
    else:
        for i in range(len(_ranges)-1):
            if value >= _ranges[i] and value < _ranges[i+1]:
                key = (_ranges[i], _ranges[i+1])
                break

    try:
        _counts[key] += 1
    except KeyError:
        _counts[key] = 1
```

这个函数的接口没有变化；唯一的区别在于，在幕后，我们现在检查我们是否正在计算值范围的总数，如果是的话，我们将键设置为标识范围的`(min_value, max_value)`元组。这段代码有点混乱，但它可以很好地隐藏这个函数的使用代码中的复杂性。

我们需要更新的最后一个函数是`totals()`函数。如果我们使用范围，这个函数的行为将会改变。编辑接口模块的副本，使`totals()`函数看起来像下面这样：

```py
def totals():
    """ Return the number of times each value has occurred.

        If we are currently counting ranges of values, we return a
        list of  (min_value, max_value, num_occurrences) tuples,
        one for each range.  Otherwise, we return a list of
        (value, num_occurrences) tuples, one for each unique value
        included in the count.
    """
    global _ranges
    global _counts

    if _ranges != None:
        results = []
        for i in range(len(_ranges)-1):
            min_value = _ranges[i]
            max_value = _ranges[i+1]
            num_occurrences = _counts.get((min_value, max_value),
                                          0)
            results.append((min_value, max_value,
                            num_occurrences))
        return results
    else:
        results = []
        for value in sorted(_counts.keys()):
            results.append((value, _counts[value]))
        return results
```

这段代码有点复杂，但我们已经更新了函数的文档字符串，以描述新的行为。现在让我们测试我们的代码；启动 Python 解释器，尝试输入以下指令：

```py
import counter
counter.reset([0, 5, 10, 15])
counter.add(5.7)
counter.add(4.6)
counter.add(14.2)
counter.add(0.3)
counter.add(7.1)
counter.add(2.6)
print(counter.totals())
```

一切顺利的话，您应该会看到以下输出：

```py
[(0, 5, 3), (5, 10, 2), (10, 15, 1)]
```

这对应于您定义的三个范围，并显示有三个值落入第一个范围，两个值落入第二个范围，只有一个值落入第三个范围。

## 变更管理

在这个阶段，似乎您更新后的软件包是成功的。就像我们在第六章中看到的例子一样，*创建可重用模块*，我们能够使用模块化编程技术来限制需要支持软件包中一个重大新功能所需的更改数量。我们进行了一些测试，更新后的软件包似乎正在正常工作。

然而，我们不会止步于此。由于我们向我们的包添加了一个重要的新功能，我们应该添加一些单元测试来确保这个功能的正常工作。编辑您的`tests.py`脚本，并将以下新的测试用例添加到此模块：

```py
class RangeCounterTestCase(unittest.TestCase):
    """ Unit tests for the range-based features of the
        ``counter`` package.
    """
    def test_range_totals(self):
        counter.reset([0, 5, 10, 15])
        counter.add(3)
        counter.add(9)
        counter.add(4.5)
        counter.add(12)
        counter.add(19.1)
        counter.add(14.2)
        counter.add(8)
        self.assertEqual(counter.totals(),
                         [(0, 5, 2), (5, 10, 2), (10, 15, 2)])
```

这与我们用于临时测试的代码非常相似。保存更新后的`tests.py`脚本后，运行它。这应该会显示出一些非常有趣的东西：您的新包突然崩溃了：

```py
ERROR: test_range_totals (__main__.RangeCounterTestCase)
-----------------------------------------------------------------
Traceback (most recent call last):
  File "tests.py", line 35, in test_range_totals
    counter.add(19.1)
  File "/Users/erik/Project Support/Work/Packt/PythonModularProg/First Draft/Chapter 9/code/counter-ranges/counter/interface.py", line 36, in add
    _counts[key] += 1
UnboundLocalError: local variable 'key' referenced before assignment
```

我们的`test_range_totals()`单元测试失败，因为我们的包在尝试将值`19.1`添加到我们的范围计数器时会出现`UnboundLocalError`。稍加思考就会发现问题所在：我们定义了三个范围，`0-5`，`5-10`和`10-15`，但现在我们试图将值`19.1`添加到我们的计数器中。由于`19.1`超出了我们设置的范围，我们的包无法为这个值分配一个范围，因此我们的`add()`函数崩溃了。

很容易解决这个问题；将以下突出显示的行添加到您的`add()`函数中：

```py
def add(value):
    """ Add the given value to our counter.
    """
    global _ranges
    global _counts

    if _ranges == None:
        key = value
    else:
 **key = None
        for i in range(len(_ranges)-1):
            if value >= _ranges[i] and value < _ranges[i+1]:
                key = (_ranges[i], _ranges[i+1])
                break
 **if key == None:
 **raise RuntimeError("Value out of range: {}".format(value))

    try:
        _counts[key] += 1
    except KeyError:
        _counts[key] = 1
```

这会导致我们的包在用户尝试添加超出我们设置的范围的值时返回`RuntimeError`。

不幸的是，我们的单元测试仍然崩溃，只是现在以`RuntimeError`的形式失败。为了解决这个问题，从`test_range_totals()`单元测试中删除`counter.add(19.1)`行。我们仍然希望测试这种错误情况，但我们将在单独的单元测试中进行。在您的`RangeCounterTestCase`类的末尾添加以下内容：

```py
    def test_out_of_range(self):
        counter.reset([0, 5, 10, 15])
        with self.assertRaises(RuntimeError):
            counter.add(19.1)
```

这个单元测试专门检查我们之前发现的错误情况，并确保包在提供的值超出请求的范围时正确返回`RuntimeError`。

注意，我们现在为我们的包定义了四个单独的单元测试。我们仍在测试包，以确保它在没有范围的情况下运行，以及测试我们所有基于范围的代码。因为我们已经实施（并开始充实）了一系列针对我们的包的单元测试，我们可以确信，为了支持范围所做的任何更改都不会破坏不使用新基于范围的功能的任何现有代码。

正如您所看到的，我们使用的模块化编程技术帮助我们最大限度地减少了对代码所需的更改，并且我们编写的单元测试有助于确保更新后的代码继续按我们期望的方式工作。通过这种方式，模块化编程技术的使用使我们能够以最有效的方式处理不断变化的需求和编程的持续过程。

# 处理复杂性

无法逃避计算机程序是复杂的这一事实。事实上，随着对包的要求发生变化，这种复杂性似乎只会随着时间的推移而增加——程序很少在进行过程中变得更简单。模块化编程技术是处理这种复杂性的一种极好方式。通过应用模块化技术和技术，您可以：

+   使用模块和包来保持您的代码组织良好，无论它变得多么复杂

+   使用模块化设计的标准模式，包括分而治之技术、抽象和封装，将这种复杂性降至最低

+   将单元测试技术应用于确保在更改和扩展模块或包的范围时，您的代码仍然按预期工作。

+   编写模块和函数级别的文档字符串，清楚地描述代码的每个部分所做的工作，以便在程序增长和更改时能够跟踪一切。

要了解这些模块化技术和技术有多么重要，只需想一想，如果在开发一个大型、复杂和不断变化的系统时不使用它们，你将会陷入多么混乱的境地。没有模块化设计技术和标准模式的应用，比如分而治之、抽象和封装，你会发现自己编写了结构混乱的意大利面代码，带来许多意想不到的副作用，并且新功能和变化散布在你的源代码中。没有单元测试，你将无法确保你的代码在进行更改时仍然能够正常工作。最后，缺乏嵌入式文档将使跟踪系统的各个部分变得非常困难，导致错误和没有经过深思熟虑的更改，因为你继续开发和扩展你的代码。

出于这些原因，很明显模块化编程技术对于任何大型系统的设计和开发至关重要，因为它们帮助你以最佳方式处理复杂性。

# 成为一名有效的程序员

既然你已经看到模块化编程技术有多么有用，你可能会想知道为什么会有人不想使用它们。除了缺乏理解之外，为什么程序员会避开模块化原则和技术呢？

Python 语言从头开始就被设计为支持良好的模块化编程技术，并且通过优秀的工具（如 Python 标准库、单元测试和文档字符串）的添加，它鼓励你将这些技术应用到你的日常编程实践中。同样，使用缩进来定义代码的结构自动鼓励你编写格式良好的源代码，其中代码的缩进反映了程序的逻辑组织。这些都不是随意的选择：Python 在每一步都鼓励良好的编程实践。

当然，就像你可以使用 Python 编写结构混乱和难以理解的意大利面代码一样，你也可以在开发程序时避免使用模块化技术和实践。但你为什么要这样呢？

程序员有时在编写他们认为是“一次性”的代码时会采取捷径。例如，也许你正在编写一个小程序，你只打算使用一次，然后再也不需要使用了。为什么要花额外的时间将推荐的模块化编程实践应用到这个一次性的程序上呢？

问题是，一次性代码有一个有趣的习惯，就是变成永久的，并发展成为一个更大的复杂系统。经常情况下，最初的一次性代码成为一个大型和复杂系统的基础。你六个月前写的代码可能会在新程序中被找到和重用。最终，你永远不知道什么是一次性代码，什么不是。

基于这些原因，无论代码有多大或多小，始终应该应用模块化编程实践。虽然你可能不想花很多时间为一个简单的一次性脚本编写大量的文档字符串和单元测试，但你仍然可以应用基本的模块化技术来帮助保持代码的组织。不要只把模块化编程技术留给你的“大”项目。

幸运的是，Python 实现的模块化编程方式非常容易使用，过一段时间后，你开始在编写一行代码之前就以模块化的方式思考。我认为这是一件好事，因为模块化编程技术是成为一名优秀程序员的重要组成部分，你应该在编程时练习这些技术。

# 总结

在本章，甚至整本书中，我们已经看到模块化编程技术的应用如何帮助你以最有效的方式处理编程的*过程*。你不是在回避变化，而是能够管理它，使得你的代码能够持续工作，并且通过新的需求不断改进。

我们已经看到了另一个需要根据不断扩大的需求进行更改的程序的例子，并且已经看到了模块化技术的应用，包括使用文档字符串和单元测试，有助于编写健壮且易于理解的代码，随着不断的开发和更改而不断改进。

我们已经看到了模块化技术的应用是处理程序复杂性的重要部分，而这种复杂性随着时间的推移只会增加。我们已经了解到，正因为如此，使用模块化编程技术是成为优秀程序员的重要组成部分。最后，我们已经看到，模块化技术是每次你坐下来编程时都可以使用的东西，即使是简单的一次性脚本，而不是要为你的“大”项目保留的东西。

希望你觉得这个关于模块化编程世界的介绍有用，并且现在开始将模块化技术和模式应用到你自己的编程中。我鼓励你继续尽可能多地了解围绕良好的模块化编程实践的各种工具，比如使用文档字符串和 Sphinx 库来为你的包自动生成文档，以及使用`virtualenv`来设置和使用虚拟环境来管理你程序的包依赖关系。你继续使用模块化实践和技术，它将变得更容易，你作为程序员也将变得更有效率。愉快的编程！
