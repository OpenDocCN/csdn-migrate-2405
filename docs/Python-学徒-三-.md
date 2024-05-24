# Python 学徒（三）

> 原文：[`zh.annas-archive.org/md5/4702C628AD6B03CA92F1B4B8E471BB27`](https://zh.annas-archive.org/md5/4702C628AD6B03CA92F1B4B8E471BB27)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

## 第七章：异常

异常处理是一种停止“正常”程序流程并在某个周围上下文或代码块中继续的机制。

中断正常流程的行为称为“引发”异常。在某个封闭的上下文中，引发的异常必须被*处理*，这意味着控制流被转移到异常处理程序。如果异常传播到程序的起始点，那么未处理的异常将导致程序终止。异常对象包含有关异常事件发生的位置和原因的信息，被从引发异常的点传输到异常处理程序，以便处理程序可以询问异常对象并采取适当的行动。

如果您已经在其他流行的命令式语言（如 C++或 Java）中使用过异常，那么您已经对 Python 中异常的工作原理有了一个很好的了解。

关于什么构成“异常事件”的长期而令人厌倦的辩论一直存在，核心问题是异常性实际上是一个程度的问题（有些事情比其他事情更异常）。这是有问题的，因为编程语言通过坚持事件要么完全异常要么根本不异常的假二分法来强加了一个错误的二分法。

Python 的哲学在使用异常方面处于自由的一端。异常在 Python 中无处不在，了解如何处理异常至关重要。

### 异常和控制流

由于异常是一种控制流的手段，在 REPL 中演示可能会很笨拙，因此在本章中，我们将使用 Python 模块来包含我们的代码。让我们从一个非常简单的模块开始，以便探索这些重要的概念和行为。将以下代码放入名为`exceptional.py`的模块中：

```py
"""A module for demonstrating exceptions."""

def convert(s):
    """Convert to an integer."""
    x = int(s)
    return x

```

将此模块中的`convert()`函数导入 Python REPL 中：

```py
$ python3
Python 3.5.1 (v3.5.1:37a07cee5969, Dec  5 2015, 21:12:44)
[GCC 4.2.1 (Apple Inc. build 5666) (dot 3)] on darwin
Type "help", "copyright", "credits" or "license" for more information.
>>> from exceptional import convert

```

并使用一个字符串调用我们的函数，以查看它是否产生了预期的效果：

```py
>>> convert("33")
33

```

如果我们使用无法转换为整数的对象调用我们的函数，我们将从`int()`调用中获得一个回溯：

```py
>>> convert("hedgehog")
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
  File "./exceptional.py", line 7, in convert
    x = int(s)
ValueError: invalid literal for int() with base 10: 'hedgehog'

```

这里发生的是`int()`引发了一个异常，因为它无法合理地执行转换。我们没有设置处理程序，所以它被 REPL 捕获并显示了堆栈跟踪。换句话说，异常未被处理。

堆栈跟踪中提到的`ValueError`是异常对象的*类型*，错误消息`"invalid literal for int() with base 10: 'hedgehog'"`是异常对象的有效负载的一部分，已被 REPL 检索并打印。

请注意，异常在调用堆栈中传播了几个级别：

| 调用堆栈 | 效果 |
| --- | --- |
| `int()` | 异常在此引发 |
| `convert()` | 异常在这里概念上通过 |
| REPL | 异常在这里被捕获 |

### 处理异常

让我们通过使用`try`..`except`结构来使我们的`convert()`函数更加健壮，处理`ValueError`。`try`和`except`关键字都引入了新的代码块。`try`块包含可能引发异常的代码，`except`块包含在引发异常时执行错误处理的代码。修改`convert()`函数如下：

```py
def convert(s):
    """Convert a string to an integer."""
    try:
        x = int(s)
    except ValueError:
        x = -1
    return x

```

我们已经决定，如果提供了一个非整数字符串，我们将返回负一。为了加强您对控制流的理解，我们还将添加一些打印语句：

```py
def convert(s):
    """Convert a string to an integer."""
    try:
        x = int(s)
        print("Conversion succeeded! x =", x)
    except ValueError:
        print("Conversion failed!")
        x = -1
    return x

```

让我们在重新启动 REPL 后进行交互式测试：

```py
>>> from exceptional import convert
>>> convert("34")
Conversion succeeded! x = 34
34
>>> convert("giraffe")
Conversion failed!
-1

```

请注意，当我们将'giraffe'作为函数参数传递时，`try`块中在引发异常后的`print()`*没有*被执行。相反，执行直接转移到了`except`块的第一条语句。

`int()`构造函数只接受数字或字符串，所以让我们看看如果我们将另一种类型的对象，比如列表，传递给它会发生什么：

```py
>>> convert([4, 6, 5])
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
  File "./exceptional.py", line 8, in convert
    x = int(s)
TypeError: int() argument must be a string or a number, not 'list'

```

这次我们的处理程序没有拦截异常。如果我们仔细看跟踪，我们会发现这次我们收到了一个`TypeError` - 一种不同类型的异常。

### 处理多个异常

每个`try`块可以有多个对应的`except`块，拦截不同类型的异常。让我们也为`TypeError`添加一个处理程序：

```py
def convert(s):
    """Convert a string to an integer."""
    try:
        x = int(s)
        print("Conversion succeeded! x =", x)
    except ValueError:
        print("Conversion failed!")
        x = -1
    except TypeError:
        print("Conversion failed!")
        x = -1
    return x

```

现在，如果我们在一个新的 REPL 中重新运行相同的测试，我们会发现`TypeError`也被处理了：

```py
>>> from exceptional import convert
>>> convert([1, 3, 19])
Conversion failed!
-1

```

我们的两个异常处理程序之间存在一些代码重复，有重复的`print`语句和赋值。我们将赋值移到`try`块的前面，这不会改变程序的行为：

```py
def convert(s):
    """Convert a string to an integer."""
    x = -1
    try:
        x = int(s)
        print("Conversion succeeded! x =", x)
    except ValueError:
        print("Conversion failed!")
    except TypeError:
        print("Conversion failed!")
    return x

```

然后我们将利用`except`语句接受异常类型元组的能力，将两个处理程序合并为一个：

```py
def convert(s):
    """Convert a string to an integer."""
    x = -1
    try:
        x = int(s)
        print("Conversion succeeded! x =", x)
    except (ValueError, TypeError):
        print("Conversion failed!")
    return x

```

现在我们看到一切仍然按设计工作：

```py
>>> from exceptional import convert
>>> convert(29)
Conversion succeeded! x = 29
29
>>> convert("elephant")
Conversion failed!
-1
>>> convert([4, 5, 1])
Conversion failed!
-1

```

### 程序员错误

既然我们对异常行为的控制流感到自信，我们可以删除打印语句了：

```py
def convert(s):
    """Convert a string to an integer."""
    x = -1
    try:
        x = int(s)
    except (ValueError, TypeError):
    return x

```

但是现在当我们尝试导入我们的程序时：

```py
>>> from exceptional import convert
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
  File "./exceptional.py", line 11
    return x
          ^
IndentationError: expected an indented block

```

我们得到了另一种类型的异常，一个`IndentationError`，因为我们的`except`块现在是空的，Python 程序中不允许空块。

这不是一个*有用*的异常类型，可以用`except`块捕获！Python 程序出现的几乎所有问题都会导致异常，但某些异常类型，比如`IndentationError`、`SyntaxError`和`NameError`，是程序员错误的结果，应该在开发过程中被识别和纠正，而不是在运行时处理。这些异常的存在大多数情况下是有用的，如果你正在创建一个 Python 开发工具，比如 Python IDE，将 Python 本身嵌入到一个更大的系统中以支持应用程序脚本，或者设计一个动态加载代码的插件系统。

### 空块 - `pass`语句

话虽如此，我们仍然有一个问题，那就是如何处理我们的空`except`块。解决方案以`pass`关键字的形式出现，这是一个什么都不做的特殊语句！它是一个空操作，它的唯一目的是允许我们构造在语法上允许但在语义上为空的块：

```py
def convert(s):
    """Convert a string to an integer."""
    x = -1
    try:
        x = int(s)
    except (ValueError, TypeError):
        pass
    return x

```

不过，在这种情况下，通过使用多个`return`语句进一步简化会更好，完全摆脱`x`变量：

```py
def convert(s):
    """Convert a string to an integer."""
    try:
        return int(s)
    except (ValueError, TypeError):
        return -1

```

### 异常对象

有时，我们想要获取异常对象 - 在这种情况下是`ValueError`或`TypeError`类型的对象，并对其进行详细的询问出了什么问题。我们可以通过在`except`语句的末尾添加一个`as`子句并使用一个变量名来获得对异常对象的命名引用：

```py
def convert(s):
    """Convert a string to an integer."""
    try:
        return int(s)
    except (ValueError, TypeError) as e:
        return -1

```

我们将修改我们的函数，在返回之前向`stderr`流打印异常详细信息的消息。要打印到`stderr`，我们需要从`sys`模块中获取对流的引用，所以在我们的模块顶部，我们需要`import sys`。然后我们可以将`sys.stderr`作为一个名为`file`的关键字参数传递给`print()`：

```py
import sys

def convert(s):
    """Convert a string to an integer."""
    try:
        return int(s)
    except (ValueError, TypeError) as e:
        print("Conversion error: {}".format(str(e)), file=sys.stderr)
        return -1

```

我们利用异常对象可以使用`str()`构造函数转换为字符串的事实。

让我们在 REPL 中看看：

```py
>>> from exceptional import convert
>>> convert("fail")
Conversion error: invalid literal for int() with base 10: 'fail'
-1

```

### 轻率的返回代码

让我们在我们的模块中添加第二个函数`string_log()`，它调用我们的`convert()`函数并计算结果的自然对数：

```py
from math import log

def string_log(s):
    v = convert(s)
    return log(v)

```

在这一点上，我们必须承认，我们在这里通过将完全正常的`int()`转换（在失败时引发异常）包装在我们的`convert()`函数中，返回一个老式的负错误代码，这是非常不符合 Python 风格的。请放心，这种不可饶恕的 Python 异端行为仅仅是为了展示错误返回代码的最大愚蠢：它们可以被调用者忽略，在程序的后期对毫无戒心的代码造成严重破坏。稍微好一点的程序可能会在继续进行日志调用之前测试`v`的值。

如果没有这样的检查，当传递负错误代码值时，`log()`当然会失败：

```py
>>> from exceptional import string_log
>>> string_log("ouch!")
Conversion error: invalid literal for int() with base 10: 'ouch!'
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
  File "./exceptional.py", line 15, in string_log
    return log(v)
ValueError: math domain error

```

当然，`log()`失败的后果是引发另一个异常，也是`ValueError`。

更好，而且更符合 Python 风格的是，完全忘记错误返回代码，并恢复到从`convert()`引发异常。

### 重新引发异常

我们可以发出我们的错误消息并重新引发我们当前正在处理的异常对象，而不是返回一个非 Python 风格的错误代码。这可以通过在我们的异常处理块的末尾用`raise`语句替换`return -1`来完成：

```py
def convert(s):
    """Convert a string to an integer."""
    try:
        return int(s)
    except (ValueError, TypeError) as e:
        print("Conversion error: {}".format(str(e)), file=sys.stderr)
        raise

```

没有参数`raise`重新引发当前正在处理的异常。

在 REPL 中进行测试，我们可以看到原始异常类型被重新引发，无论是`ValueError`还是`TypeError`，我们的“Conversion error”消息都会打印到`stderr`：

```py
>>> from exceptional import string_log
>>> string_log("25")
3.2188758248682006
>>> string_log("cat")
Conversion error: invalid literal for int() with base 10: 'cat'
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
  File "./exceptional.py", line 14, in string_log
    v = convert(s)
  File "./exceptional.py", line 6, in convert
    return int(s)
ValueError: invalid literal for int() with base 10: 'cat'
>>> string_log([5, 3, 1])
Conversion error: int() argument must be a string or a number, not 'list'
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
  File "./exceptional.py", line 14, in string_log
    v = convert(s)
  File "./exceptional.py", line 6, in convert
    return int(s)
TypeError: int() argument must be a string or a number, not 'list'

```

### 异常是函数 API 的一部分

异常是函数 API 的重要组成部分。函数的调用者需要知道在各种条件下期望哪些异常，以便他们可以确保适当的异常处理程序已经就位。我们将使用寻找平方根作为示例，使用一个自制的平方根函数，由亚历山大的赫罗（尽管他可能没有使用 Python）提供。

![函数的调用者需要知道期望哪些异常。](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-aprt/img/callers-need-to-know.png)

函数的调用者需要知道期望哪些异常。

将以下代码放入一个名为`roots.py`的文件中：

```py
def sqrt(x):
    """Compute square roots using the method of Heron of Alexandria.

 Args:
 x: The number for which the square root is to be computed.

 Returns:
 The square root of x.
 """
    guess = x
    i = 0
    while guess * guess != x and i < 20:
        guess = (guess + x / guess) / 2.0
        i += 1
    return guess

def main():
    print(sqrt(9))
    print(sqrt(2))

if __name__ == '__main__':
    main()

```

在这个程序中，我们之前没有遇到过的只有一个语言特性：逻辑`and`运算符，我们在这种情况下使用它来测试循环的每次迭代上两个条件是否为`True`。Python 还包括一个逻辑`or`运算符，它可以用来测试它的操作数是否一个或两个都为`True`。

运行我们的程序，我们可以看到赫罗是真的有所发现：

```py
$ python3 roots.py
3.0
1.41421356237

```

#### Python 引发的异常

让我们在`main()`函数中添加一行新代码，它对-1 进行平方根运算：

```py
def main():
    print(sqrt(9))
    print(sqrt(2))
    print(sqrt(-1))

```

如果我们运行它，我们会得到一个新的异常：

```py
$ python3 sqrt.py
3.0
1.41421356237
Traceback (most recent call last):
  File "sqrt.py", line 14, in <module>
    print(sqrt(-1))
  File "sqrt.py", line 7, in sqrt
    guess = (guess + x / guess) / 2.0
ZeroDivisionError: float division

```

发生的情况是 Python 拦截了除零，这发生在循环的第二次迭代中，并引发了一个异常-`ZeroDivisionError`。

#### 捕获异常

让我们修改我们的代码，在异常传播到调用堆栈的顶部之前捕获异常（从而导致我们的程序停止），使用`try`..`except`结构：

```py
def main():
    print(sqrt(9))
    print(sqrt(2))
    try:
        print(sqrt(-1))
    except ZeroDivisionError:
        print("Cannot compute square root of a negative number.")

    print("Program execution continues normally here.")

```

现在当我们运行脚本时，我们看到我们干净地处理了异常：

```py
$ python sqrt.py
3.0
1.41421356237
Cannot compute square root of a negative number.
Program execution continues normally here.

```

我们应该小心避免初学者在异常处理块中使用过于严格的范围的错误；我们可以很容易地对我们所有对`sqrt()`的调用使用一个`try`..`except`块。我们还添加了第三个打印语句，以显示封闭块的执行是如何终止的：

```py
def main():
    try:
        print(sqrt(9))
        print(sqrt(2))
        print(sqrt(-1))
        print("This is never printed.")
    except ZeroDivisionError:
        print("Cannot compute square root of a negative number.")

    print("Program execution continues normally here.")

```

#### 显式引发异常

这是对我们开始的改进，但最有可能`sqrt()`函数的用户不希望它抛出`ZeroDivisionError`。

Python 为我们提供了几种标准的异常类型来表示常见的错误。如果函数参数提供了非法值，习惯上会引发`ValueError`。我们可以通过使用`raise`关键字和通过调用`ValueError`构造函数创建的新异常对象来实现这一点。

我们可以处理除零的两种方法。第一种方法是将寻找平方根的 while 循环包装在`try`..`except ZeroDivisionError`结构中，然后在异常处理程序内部引发一个新的`ValueError`异常。

```py
def sqrt(x):
    """Compute square roots using the method of Heron of Alexandria.

 Args:
 x: The number for which the square root is to be computed.

 Returns:
 The square root of x.
 """
    guess = x
    i = 0
    try:
        while guess * guess != x and i < 20:
            guess = (guess + x / guess) / 2.0
            i += 1
    except ZeroDivisionError:
        raise ValueError()
    return guess

```

虽然它可以工作，但这将是浪费的；我们会明知道继续进行一个最终毫无意义的非平凡计算。

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-aprt/img/wasteful.png)

### 守卫子句

我们知道这个例程总是会失败，所以我们可以在早期检测到这个前提条件，并在那一点上引发异常，这种技术称为*守卫子句*：

```py
def sqrt(x):
    """Compute square roots using the method of Heron of Alexandria.

 Args:
 x: The number for which the square root is to be computed.

 Returns:
 The square root of x.

 Raises:
 ValueError: If x is negative.
 """

    if x < 0:
        raise ValueError("Cannot compute square root of negative number {}".format(x))

    guess = x
    i = 0
    while guess * guess != x and i < 20:
        guess = (guess + x / guess) / 2.0
        i += 1
    return guess

```

测试是一个简单的 if 语句和一个调用`raise`传递一个新铸造的异常对象。`ValueError()`构造函数接受一个错误消息。看看我们如何修改文档字符串，以明确`sqrt()`将引发哪种异常类型以及在什么情况下。

但是看看如果我们运行程序会发生什么-我们仍然会得到一个回溯和一个不优雅的程序退出：

```py
$ python roots.py
3.0
1.41421356237
Traceback (most recent call last):
  File "sqrt.py", line 25, in <module>
    print(sqrt(-1))
  File "sqrt.py", line 12, in sqrt
    raise ValueError("Cannot compute square root of negative number {0}".format(x))
ValueError: Cannot compute square root of negative number -1

```

这是因为我们忘记修改我们的异常处理程序来捕获`ValueError`而不是`ZeroDivisionError`。让我们修改我们的调用代码来捕获正确的异常类，并将捕获的异常对象分配给一个命名变量，这样我们就可以在捕获后对其进行询问。在这种情况下，我们的询问是`print`异常对象，它知道如何将自己显示为 stderr 的消息：

```py
import sys

def main():
    try:
        print(sqrt(9))
        print(sqrt(2))
        print(sqrt(-1))
        print("This is never printed.")
    except ValueError as e:
        print(e, file=sys.stderr)

    print("Program execution continues normally here.")

```

再次运行程序，我们可以看到我们的异常被优雅地处理了：

```py
$ python3 sqrt.py
3.0
1.41421356237
Cannot compute square root of negative number -1
Program execution continues normally here.

```

### 异常、API 和协议

异常是函数的 API 的一部分，更广泛地说，是某些*协议*的一部分。例如，实现序列协议的对象应该为超出范围的索引引发`IndexError`异常。

引发的异常与函数的参数一样，是函数规范的一部分，必须适当地记录。

Python 中有几种常见的异常类型，通常当您需要在自己的代码中引发异常时，内置类型之一是一个不错的选择。更少见的是，您需要定义新的异常类型，但我们在本书中没有涵盖这一点。（请参阅本系列的下一本书*Python Journeyman*，了解如何做到这一点。）

如果您决定您的代码应该引发哪些异常，您应该在现有代码中寻找类似的情况。您的代码遵循现有模式的越多，人们集成和理解起来就越容易。例如，假设您正在编写一个键值数据库：使用`KeyError`来指示对不存在的键的请求是很自然的，因为这是`dict`的工作方式。也就是说，Python 中的“映射”集合遵循某些协议，异常是这些协议的一部分。

让我们看一些常见的异常类型。

#### IndexError

当整数索引超出范围时，会引发`IndexError`。

当我们在列表末尾索引时，您可以看到这一点：

```py
>>> z = [1, 4, 2]
>>> z[4]
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
IndexError: list index out of range

```

#### ValueError

当对象的类型正确，但包含不适当的值时，会引发`ValueError`。

当尝试从非数字字符串构造`int`时，我们已经看到了这一点：

```py
>>> int("jim")
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
ValueError: invalid literal for int() with base 10: 'jim'

```

#### KeyError

当查找映射失败时，会引发`KeyError`。

您可以在这里看到，当我们在字典中查找一个不存在的键时：

```py
>>> codes = dict(gb=44, us=1, no=47, fr=33, es=34)
>>> codes['de']
  Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
KeyError: 'de'

```

### 选择不防范`TypeError`

我们不倾向于保护 Python 中的`TypeErrors`。这样做违反了 Python 中的动态类型的规则，并限制了我们编写的代码的重用潜力。

例如，我们可以使用内置的`isinstance()`函数测试参数是否为`str`，如果不是，则引发`TypeError`异常：

```py
def convert(s):
    """Convert a string to an integer."""
    if not isinstance(s, str):
        raise TypeError("Argument must be a string")

    try:
        return int(s)
    except (ValueError, TypeError) as e:
        print("Conversion error: {}".format(str(e)), file=sys.stderr)
        raise

```

但是我们还希望允许作为`float`实例的参数。如果我们想要检查我们的函数是否能够处理诸如有理数、复数或任何其他类型的数字的类型，情况很快就会变得复杂，而且无论如何，谁能说它会呢？！

或者我们可以在函数内部拦截`TypeError`并重新引发它，但是有什么意义呢？

![通常不必处理 TypeErrors。](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-aprt/img/just-let-it-fail.png)

通常不必处理 TypeErrors。

通常在 Python 中，向函数添加类型检查是不值得的。如果函数使用特定类型-即使是您在设计函数时可能不知道的类型-那就太好了。如果不是，执行可能最终会导致`TypeError`。同样，我们往往不会非常频繁地*捕获*`TypeErrors`。

### Pythonic 风格- EAFP 与 LBYL

现在让我们看看 Python 哲学和文化的另一个原则，即“宁求原谅，不要问权限”。

处理可能失败的程序操作只有两种方法。第一种方法是在尝试操作之前检查所有易于失败的操作的前提条件是否满足。第二种方法是盲目地希望一切顺利，但准备好处理后果如果事情不顺利。

在 Python 文化中，这两种哲学被称为“先入为主”（LBYL）和“宁求原谅，不要问权限”（EAFP）-顺便说一句，这是由编译器发明者 Grace Hopper 女将军创造的。

Python 强烈支持 EAFP，因为它将“快乐路径”的主要逻辑以最可读的形式呈现，而与主要流程交织在一起的异常情况则单独处理。

让我们考虑一个例子-处理一个文件。处理的细节并不重要。我们只需要知道`process_file()`函数将打开一个文件并从中读取一些数据。

首先是 LBYL 版本：

```py
import os

p = '/path/to/datafile.dat'

if os.path.exists(p):
    process_file(p)
else:
    print('No such file as {}'.format(p))

```

在尝试调用`process_file()`之前，我们检查文件是否存在，如果不存在，我们避免调用并打印一条有用的消息。这种方法存在一些明显的问题，有些是显而易见的，有些是隐匿的。一个明显的问题是我们只执行了存在性检查。如果文件存在但包含垃圾怎么办？如果路径指的是一个目录而不是一个文件怎么办？根据 LBYL，我们应该为这些情况添加预防性测试。

一个更微妙的问题是这里存在竞争条件。例如，文件可能在存在性检查和`process_file()`调用之间被另一个进程删除……这是一个经典的竞争条件。实际上没有好的方法来处理这个问题-无论如何都需要处理`process_file()`的错误！

现在考虑另一种选择，使用更符合 Python 风格的 EAFP 方法：

```py
p = '/path/to/datafile.dat'

try:
    process_file(f)
except OSError as e:
  print('Could not process file because {}'.format(str(e)))

```

在这个版本中，我们尝试在事先不进行检查的情况下进行操作，但我们已经准备好了异常处理程序来处理任何问题。我们甚至不需要详细了解可能出现的问题。在这里，我们捕获了`OSError`，它涵盖了各种条件，比如文件未找到以及在期望文件的位置使用目录。

EAFP 在 Python 中是标准的，遵循这种哲学主要是通过异常来实现的。没有异常，并且被迫使用错误代码，你需要直接在逻辑的主流程中包含错误处理。由于异常中断了主流程，它们允许你非局部地处理异常情况。

异常与 EAFP 结合也更优越，因为与错误代码不同，*异常不能轻易被忽略*。默认情况下，异常会产生很大影响，而错误代码默认情况下是静默的。因此，基于异常/EAFP 的风格使问题很难被悄悄忽略。

### 清理操作

有时，你需要执行一个清理操作，无论操作是否成功。在后面的模块中，我们将介绍上下文管理器，这是这种常见情况的现代解决方案，但在这里我们将介绍`try`..`finally`结构，因为在简单情况下创建上下文管理器可能有些过头。无论如何，了解`try`..`finally`对于制作自己的上下文管理器是有用的。

考虑这个函数，它使用标准库`os`模块的各种功能来更改当前工作目录，创建一个新目录，并恢复原始工作目录：

```py
import os

def make_at(path, dir_name):
    original_path = os.getcwd()
    os.chdir(path)
    os.mkdir(dir_name)
    os.chdir(original_path)

```

乍一看，这似乎是合理的，但是如果`os.mkdir()`的调用因某种原因失败，Python 进程的当前工作目录将不会恢复到其原始值，并且`make_at()`函数将产生意外的副作用。

为了解决这个问题，我们希望函数在任何情况下都能恢复原始的当前工作目录。我们可以通过`try`..`finally`块来实现这一点。`finally`块中的代码将被执行，无论执行是通过到达块的末尾而正常离开`try`块，还是通过引发异常而异常地离开。

这种结构可以与`except`块结合在一起，如下所示，用于添加一个简单的失败日志记录设施：

```py
import os
import sys

def make_at(path, dir_name):
  original_path = os.getcwd()
  try:
      os.chdir(path)
      os.mkdir(dir_name)
  except OSError as e:
      print(e, file=sys.stderr)
      raise
  finally:
      os.chdir(original_path)

```

现在，如果`os.mkdir()`引发`OSError`，则将运行`OSError`处理程序并重新引发异常。但由于`finally`块始终运行，无论 try 块如何结束，我们可以确保最终的目录更改将在所有情况下发生。

* * *

### 禅意时刻

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-aprt/img/zen-errors-should-never-pass-silently.png)

* * *

### 特定于平台的代码

从 Python 中检测单个按键 - 例如在控制台上的“按任意键继续。”功能 - 需要使用特定于操作系统的模块。我们不能使用内置的`input()`函数，因为它等待用户按*Enter*键然后给我们一个字符串。要在 Windows 上实现这一点，我们需要使用仅限于 Windows 的`msvcrt`模块的功能，在 Linux 和 macOS 上，我们需要使用仅限于 Unix 的`tty`和`termios`模块的功能，以及`sys`模块。

这个例子非常有教育意义，因为它演示了许多 Python 语言特性，包括`import`和`def`作为*语句*，而不仅仅是声明：

```py
"""keypress - A module for detecting a single keypress."""

try:
    import msvcrt

    def getkey():
        """Wait for a keypress and return a single character string."""
        return msvcrt.getch()

except ImportError:

    import sys
    import tty
    import termios

    def getkey():
        """Wait for a keypress and return a single character string."""
        fd = sys.stdin.fileno()
        original_attributes = termios.tcgetattr(fd)
        try:
            tty.setraw(sys.stdin.fileno())
            ch = sys.stdin.read(1)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, original_attributes)
        return ch

    # If either of the Unix-specific tty or termios modules are
    # not found, we allow the ImportError to propagate from here

```

请记住，顶层模块代码在首次导入时执行。在第一个 try 块中，我们尝试`import msvcrt`，即 Microsoft Visual C Runtime。如果成功，然后我们继续定义一个名为`getkey()`的函数，该函数委托给`msvcrt.getch()`函数。即使在这一点上我们在 try 块内部，该函数也将在当前范围内声明，即模块范围。

然而，如果`msvcrt`的导入失败，因为我们不在 Windows 上运行，将引发`ImportError`，并且执行将转移到 except 块。这是一个明确消除错误的情况，因为我们将尝试在异常处理程序中采取替代行动。

在 except 块内，我们导入了三个在类 Unix 系统上实现`getkey()`所需的模块，然后继续使用替代定义`getkey()`，再次将函数实现绑定到模块范围内的名称。

这个 Unix 实现的`getkey()`使用`try`..`finally`结构，在将终端置于原始模式以读取单个字符的目的后，恢复各种终端属性。

如果我们的程序在既不是 Windows 也不是类 Unix 的系统上运行，`import tty`语句将引发第二个`ImportError`。这次我们不尝试拦截此异常；我们允许它传播到我们的调用者 - 无论尝试导入此`keypress`模块的是什么。我们知道如何发出此错误，但不知道如何处理它，因此我们将这个决定推迟给我们的调用者。错误不会悄悄地传递。

如果调用者具有更多的知识或可用的替代策略，它可以依次拦截此异常并采取适当的操作，也许降级到使用 Python 的`input()`内置函数并向用户提供不同的消息。

### 总结

+   引发异常会中断正常的程序流程，并将控制转移到异常处理程序。

+   异常处理程序使用`try`..`except`结构定义。

+   `try`块定义了可以检测异常的上下文。

+   相应的`except`块为特定类型的异常定义处理程序。

+   Python 广泛使用异常，并且许多内置语言功能依赖于它们。

+   `except`块可以捕获异常对象，通常是标准类型，如`ValueError`，`KeyError`或`IndexError`。

+   程序员错误，如`IndentationError`和`SyntaxError`通常不应该被处理。

+   可以使用`raise`关键字发出异常条件，它接受异常对象的单个参数。

+   在`except`块中没有参数的`raise`重新引发当前正在处理的异常。

+   我们倾向于不经常检查`TypeErrors`。这样做会否定 Python 动态类型系统所提供的灵活性。

+   异常对象可以使用`str()`构造函数转换为字符串，以便打印消息载荷。

+   函数抛出的异常是其 API 的一部分，应该得到适当的文档支持。

+   在引发异常时，最好使用最合适的内置异常类型。

+   可以使用`try`..`finally`结构执行清理和恢复操作，这可能可以与`except`块一起使用。

在这个过程中，我们看到：

+   `print()`函数的输出可以使用可选的`file`参数重定向到`stderr`。

+   Python 支持逻辑运算符`and`和`or`来组合布尔表达式。

+   返回代码很容易被忽略。

+   可以使用“宁可请求原谅，也不要问权限”的方法来实现特定于平台的操作，通过拦截`ImportErrors`并提供替代实现。


## 第八章：推导式、可迭代对象和生成器

*对象序列*的抽象概念在编程中是无处不在的。它可以用来模拟简单的字符串、复杂对象的列表和无限长的传感器输出流等各种概念。也许你不会感到惊讶的是，Python 包含了一些非常强大和优雅的工具来处理序列。事实上，Python 对于创建和操作序列的支持是许多人认为这门语言的亮点之一。

在这一章中，我们将看到 Python 提供的三个用于处理序列的关键工具：推导式、可迭代对象和生成器。*推导式*包括了一个专门的语法，用于声明性地创建各种类型的序列。*可迭代对象*和*迭代协议*构成了 Python 中序列和迭代的核心抽象和 API；它们允许你定义新的序列类型，并对迭代进行精细控制。最后，*生成器*允许我们以命令式的方式定义惰性序列，在许多情况下是一种令人惊讶的强大技术。

让我们直接进入推导式。

### 推导式

在 Python 中，推导式是一种简洁的语法，用于以声明性或函数式风格描述列表、集合或字典。这种简写是可读的和表达性强的，这意味着推导式非常有效地传达了人类读者的意图。一些推导式几乎读起来像自然语言，使它们成为很好的自我文档化。

#### 列表推导式

如上所示，*列表推导式*是创建列表的一种简写方式。它是使用简洁的语法来描述*如何定义列表元素*的表达式。推导式比解释更容易演示，所以让我们打开一个 Python REPL。首先，我们将通过拆分一个字符串来创建一个单词列表：

```py
>>> words = "If there is hope it lies in the proles".split()
>>> words
['If', 'there', 'is', 'hope', 'it', 'lies', 'in', 'the', 'proles']

```

现在是列表推导式的时候了。推导式被包含在方括号中，就像一个字面上的列表一样，但它包含的不是字面上的元素，而是一段描述如何构造列表元素的声明性代码片段。

```py
>>> [len(word) for word in words]
[2, 5, 2, 4, 2, 4, 2, 3, 6]

```

这里，新列表是通过将名称`word`依次绑定到`words`中的每个值，然后评估`len(word)`来创建新列表中的相应值而形成的。换句话说，这构建了一个包含`words`中字符串长度的新列表；很难想象有更有效地表达这个新列表的方式了！

##### 列表推导式语法

列表推导式的一般形式是：

```py
[ expr(item) for item in iterable ]

```

也就是说，对于右侧的`iterable`中的每个`item`，我们在左侧评估`expr(item)`表达式（几乎总是，但不一定是关于该项的）。我们使用该表达式的结果作为我们正在构建的列表的下一个元素。

上面的推导式是以下命令式代码的声明性等价物：

```py
>>> lengths = []
>>> for word in words:
...     lengths.append(len(word))
...
>>> lengths
[2, 5, 2, 4, 2, 4, 2, 3, 6]

```

##### 列表推导式的元素

请注意，在列表推导式中我们迭代的源对象不需要是列表本身。它可以是任何实现了可迭代协议的对象，比如元组。

推导式的表达式部分可以是任何 Python 表达式。在这里，我们使用 `range()` 来找出前 20 个阶乘中每个数的十进制位数 —— `range()` 是一个可迭代对象 —— 以生成源序列。

```py
>>> from math import factorial
>>> f = [len(str(factorial(x))) for x in range(20)]
>>> f
[1, 1, 1, 1, 2, 3, 3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 14, 15, 16, 18]

```

还要注意，列表推导式产生的对象类型只不过是一个普通的 `list`：

```py
>>> type(f)
<class 'list'>

```

在我们看其他类型的推导式并考虑如何对无限序列进行迭代时，牢记这一点是很重要的。

#### 集合推导式

集合支持类似的推导式语法，使用的是花括号，正如你所期望的那样。我们之前的“阶乘中的数字位数”结果包含了重复项，但通过构建一个集合而不是一个列表，我们可以消除它们：

```py
>>> s = {len(str(factorial(x))) for x in range(20)}
>>> s
{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 14, 15, 16, 18}

```

与列表推导式类似，集合推导式产生标准的 `set` 对象：

```py
>>> type(s)
<class 'set'>

```

请注意，由于集合是无序容器，所以结果集不一定以有意义的顺序存储。

#### 字典理解

第三种理解类型是字典理解。与集合理解语法类似，字典理解也使用大括号。它与集合理解的区别在于，我们现在提供了两个以冒号分隔的表达式 - 第一个用于键，第二个用于值 - 这将同时为结果字典中的每个新项目进行评估。这是一个我们可以玩的字典：

```py
>>> country_to_capital = { 'United Kingdom': 'London',
...                        'Brazil': 'Brasília',
...                        'Morocco': 'Rabat',
...                        'Sweden': 'Stockholm' }

```

字典理解的一个很好的用途是反转字典，这样我们就可以在相反的方向上执行高效的查找：

```py
>>> capital_to_country = {capital: country for country, capital in country_to_capital\
.items()}
>>> from pprint import pprint as pp
>>> pp(capital_to_country)
{'Brasília': 'Brazil',
 'London': 'United Kingdom',
 'Rabat': 'Morocco',
 'Stockholm': 'Sweden'}

```

请注意，字典理解不直接作用于字典源！^(16) 如果我们想要从源字典中获取键和值，那么我们应该使用`items()`方法结合元组解包来分别访问键和值。

你的理解应该产生一些相同的键，后面的键将覆盖先前的键。在这个例子中，我们将单词的首字母映射到单词本身，但只保留最后一个 h 开头的单词：

```py
>>> words = ["hi", "hello", "foxtrot", "hotel"]
>>> { x[0]: x for x in words }
{'h': 'hotel', 'f': 'foxtrot'}

```

##### 理解的复杂性

记住，你可以在任何理解中使用的表达式的复杂性没有限制。但是为了你的同行程序员着想，你应该避免过度。相反，将复杂的表达式提取到单独的函数中以保持可读性。以下是接近于字典理解的合理限制：

```py
>>> import os
>>> import glob
>>> file_sizes = {os.path.realpath(p): os.stat(p).st_size for p in glob.glob('*.py')}
>>> pp(file_sizes)
{'/Users/pyfund/examples/exceptional.py': 400,
 '/Users/pyfund/examples/keypress.py': 778,
 '/Users/pyfund/examples/scopes.py': 133,
 '/Users/pyfund/examples/words.py': 1185}

```

这使用`glob`模块在目录中查找所有的 Python 源文件。然后它创建了一个从这些文件中的路径到文件大小的字典。

#### 过滤理解

所有三种集合理解类型都支持一个可选的过滤子句，它允许我们选择由左侧表达式评估的源的哪些项目。过滤子句是通过在理解的序列定义之后添加`if <boolean expression>`来指定的；如果布尔表达式对输入序列中的项目返回 false，则在结果中不会对该项目进行评估。

为了使这个有趣，我们首先定义一个确定其输入是否为质数的函数：

```py
>>> from math import sqrt
>>> def is_prime(x):
...     if x < 2:
...         return False
...     for i in range(2, int(sqrt(x)) + 1):
...         if x % i == 0:
...             return False
...     return True
...

```

现在我们可以在列表理解的过滤子句中使用这个来产生小于 100 的所有质数：

```py
>>> [x for x in range(101) if is_prime(x)]
[2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, \
83, 89, 97]

```

##### 结合过滤和转换

我们在这里有一个看起来有点奇怪的`x for x`构造，因为我们没有对过滤值应用任何转换；关于`x`的表达式只是`x`本身。然而，没有什么能阻止我们将过滤谓词与转换表达式结合起来。这是一个将具有三个约数的数字映射到这些约数的元组的字典理解：

```py
>>> prime_square_divisors = {x*x:(1, x, x*x) for x in range(101) if is_prime(x)}
>>> pp(prime_square_divisors)
{4: (1, 2, 4),
 9: (1, 3, 9),
 25: (1, 5, 25),
 49: (1, 7, 49),
 121: (1, 11, 121),
 169: (1, 13, 169),
 289: (1, 17, 289),
 361: (1, 19, 361),
 529: (1, 23, 529),
 841: (1, 29, 841),
 961: (1, 31, 961),
 1369: (1, 37, 1369),
 1681: (1, 41, 1681),
 1849: (1, 43, 1849),
 2209: (1, 47, 2209),
 2809: (1, 53, 2809),
 3481: (1, 59, 3481),
 3721: (1, 61, 3721),
 4489: (1, 67, 4489),
 5041: (1, 71, 5041),
 5329: (1, 73, 5329),
 6241: (1, 79, 6241),
 6889: (1, 83, 6889),
 7921: (1, 89, 7921),
 9409: (1, 97, 9409)}

```

* * *

### 禅的时刻

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-aprt/img/zen-simple-is-better-than-complex.png)

理解通常比替代方法更易读。然而，过度使用理解是可能的。有时，一个长或复杂的理解可能比等价的 for 循环*更*难读。关于何时应该优先选择哪种形式没有硬性规定，但在编写代码时要谨慎，并尽量选择适合你情况的最佳形式。

首先，你的理解理想上应该是纯函数的 - 也就是说，它们不应该有任何副作用。如果你需要创建副作用，比如在迭代过程中打印到控制台，那么使用另一种构造，比如 for 循环。

* * *

### 迭代协议

理解迭代的最常用语言特性是推导和 for 循环。它们都从源中逐个获取项目并依次处理。然而，推导和 for 循环默认情况下都会遍历整个序列，有时需要更精细的控制。在本节中，我们将看到如何通过研究两个重要概念来实现这种精细控制，这两个概念构成了大量 Python 语言行为的基础：*可迭代*对象和*迭代器*对象，这两个对象都反映在标准 Python 协议中。

*可迭代协议*定义了可迭代对象必须实现的 API。也就是说，如果要使用 for 循环或推导来迭代对象，该对象必须实现可迭代协议。内置类如`list`实现了可迭代协议。您可以将实现可迭代协议的对象传递给内置的`iter()`函数，以获取可迭代对象的*迭代器*。

*迭代器*则支持*迭代器协议*。该协议要求我们可以将迭代器对象传递给内置的`next()`函数，以从底层集合中获取下一个值。

#### 迭代协议的示例

通常情况下，在 Python REPL 上进行演示将有助于将所有这些概念凝结成可以操作的东西。我们从一个包含季节名称的列表作为我们的可迭代对象开始：

```py
>>> iterable = ['Spring', 'Summer', 'Autumn', 'Winter']

```

然后我们要求可迭代对象使用内置的`iter()`给我们一个迭代器：

```py
>>> iterator = iter(iterable)

```

接下来我们使用内置的`next()`从迭代器中请求一个值：

```py
>>> next(iterator)
'Spring'

```

每次调用`next()`都会通过序列移动迭代器：

```py
>>> next(iterator)
'Summer'
>>> next(iterator)
'Autumn'
>>> next(iterator)
'Winter'

```

但是当我们到达末尾时会发生什么？

```py
>>> next(iterator)
Traceback (most recent call last):
    File "<stdin>", line 1, in <module>
StopIteration

```

在 Python 中，异常会引发`StopIteration`异常，这显示了 Python 的自由主义精神。那些来自对异常处理更为严格的其他编程语言的人可能会觉得这有点令人不安，但实际上，还有什么比到达集合的末尾更特殊的呢？毕竟它只有一个结束！

考虑到可迭代系列可能是潜在的无限数据流，这种尝试对 Python 语言设计决策进行合理化的做法更有意义。在这种情况下到达末尾确实是一件值得写信或引发异常的事情。

#### 迭代协议的更实际的示例

使用 for 循环和推导时，这些较低级别的迭代协议的实用性可能不太明显。为了演示更具体的用途，这里有一个小型实用函数，当传递一个可迭代对象时，它会返回该系列的第一个项目，或者如果该系列为空，则引发`ValueError`：

```py
>>> def first(iterable):
...     iterator = iter(iterable)
...     try:
...         return next(iterator)
...     except StopIteration:
...         raise ValueError("iterable is empty")
...

```

这在任何可迭代对象上都能按预期工作，本例中包括`list`和`set`：

```py
>>> first(["1st", "2nd", "3rd"])
'1st'
>>> first({"1st", "2nd", "3rd"})
'1st'
>>> first(set())
Traceback (most recent call last):
  File "./iterable.py", line 17, in first
    return next(iterator)
StopIteration

During handling of the above exception, another exception occurred:

Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
  File "./iterable.py", line 19, in first
    raise ValueError("iterable is empty")
ValueError: iterable is empty

```

值得注意的是，高级迭代构造，如 for 循环和推导，直接建立在这种低级别的迭代协议之上。

### 生成器函数

现在我们来介绍*生成器函数*^(17)，这是 Python 编程语言中最强大和优雅的特性之一。Python 生成器提供了使用函数中的代码描述可迭代系列的方法。这些序列是惰性求值的，这意味着它们只在需要时计算下一个值。这一重要特性使它们能够模拟没有明确定义结束的无限值序列，例如来自传感器的数据流或活动日志文件。通过精心设计生成器函数，我们可以制作通用的流处理元素，这些元素可以组合成复杂的管道。

#### `yield`关键字

生成器由任何在其定义中至少使用一次`yield`关键字的 Python 函数定义。它们也可以包含没有参数的`return`关键字，就像任何其他函数一样，在定义的末尾有一个隐式的`return`。

为了理解生成器的作用，让我们从 Python REPL 中的一个简单示例开始。让我们定义生成器，然后我们将研究生成器的工作原理。

生成器函数由`def`引入，就像普通的 Python 函数一样：

```py
>>> def gen123():
...     yield 1
...     yield 2
...     yield 3
...

```

现在让我们调用`gen123()`并将其返回值赋给`g`：

```py
>>> g = gen123()

```

正如你所看到的，`gen123()`就像任何其他 Python 函数一样被调用。但它返回了什么？

```py
>>> g
<generator object gen123 at 0x1006eb230>

```

#### 生成器是迭代器

`g`是一个生成器对象。生成器实际上是 Python 的*迭代器*，因此我们可以使用迭代器协议从系列中检索或产生连续的值：

```py
>>> next(g)
1
>>> next(g)
2
>>> next(g)
3

```

请注意，现在我们已经从生成器中产生了最后一个值后会发生什么。对`next()`的后续调用会引发`StopIteration`异常，就像任何其他 Python 迭代器一样：

```py
>>> next(g)
Traceback (most recent call last):
    File "<stdin>", line 1, in <module>
StopIteration

```

因为生成器是迭代器，而迭代器也必须是可迭代的，它们可以在所有期望可迭代对象的常规 Python 结构中使用，例如 for 循环：

```py
>>> for v in gen123():
...     print(v)
...
1
2
3

```

请注意，对生成器函数的每次调用都会返回一个新的生成器对象：

```py
>>> h = gen123()
>>> i = gen123()
>>> h
<generator object gen123 at 0x1006eb2d0>
>>> i
<generator object gen123 at 0x1006eb280>
>>> h is i
False

```

还要注意每个生成器对象可以独立推进：

```py
>>> next(h)
1
>>> next(h)
2
>>> next(i)
1

```

#### 生成器代码何时执行？

让我们更仔细地看一下我们的生成器函数体中的代码是如何执行的，以及关键的*何时*执行。为了做到这一点，我们将创建一个稍微复杂一点的生成器，它将用老式的打印语句跟踪它的执行：

```py
>>> def gen246():
...     print("About to yield 2")
...     yield 2
...     print("About to yield 4")
...     yield 4
...     print("About to yield 6")
...     yield 6
...     print("About to return")
...
>>> g = gen246()

```

此时生成器对象已经被创建并返回，但是生成器函数体内的代码尚未执行。让我们对`next()`进行初始调用：

```py
>>> next(g)
About to yield 2
2

```

看看当我们请求第一个值时，生成器体运行到第一个`yield`语句为止。代码执行到足够的地方，以便字面上`yield`下一个值。

```py
>>> next(g)
About to yield 4
4

```

当我们从生成器请求下一个值时，生成器函数的执行会在离开的地方*恢复*，并继续运行直到下一个`yield`：

```py
>>> next(g)
About to yield 6
6

```

在最后一个值返回后，下一个请求会导致生成器函数执行，直到它在函数体的末尾返回，这将引发预期的`StopIteration`异常。

```py
>>> next(g)
About to return
Traceback (most recent call last):
    File "<stdin>", line 1, in <module>
StopIteration

```

现在我们已经看到生成器执行是通过对`next()`的调用来启动，并通过`yield`语句来中断，我们可以继续将更复杂的代码放在生成器函数体中。

#### 在生成器函数中保持显式状态

现在我们将看看我们的生成器函数如何在每次请求下一个值时恢复执行，并在本地变量中保持状态。在这个过程中，我们的生成器将变得更有趣和更有用。我们将展示两个演示惰性评估的生成器，稍后我们将把它们合并成一个生成器管道。

##### 第一个有状态的生成器：`take()`

我们将要查看的第一个生成器是`take()`，它从序列的前面检索指定数量的元素：

```py
def take(count, iterable):
    """Take items from the front of an iterable.

    Args:
        count: The maximum number of items to retrieve.
        iterable: The source of the items.

    Yields:
        At most 'count' items from 'iterable'.
    """
    counter = 0
    for item in iterable:
        if counter == count:
            return
        counter += 1
        yield item

```

请注意，该函数定义了一个生成器，因为它包含至少一个`yield`语句。这个特定的生成器还包含一个`return`语句来终止产生的值流。生成器使用一个计数器来跟踪到目前为止已经产生了多少元素，当请求超出请求的计数时返回。

由于生成器是惰性的，并且只在请求时产生值，我们将在`run_take()`函数中使用 for 循环来驱动执行：

```py
def run_take():
    items = [2, 4, 6, 8, 10]
    for item in take(3, items):
        print(item)

```

在这里，我们创建了一个名为`items`的源`list`，并将其与`3`一起传递给我们的生成器函数。在内部，for 循环将使用迭代器协议从`take()`生成器中检索值，直到它终止。

##### 第二个有状态的生成器：`distinct()`

现在让我们把第二个生成器带入图片。这个名为`distinct()`的生成器函数通过跟踪它已经在`set`中看到的元素来消除重复项：

```py
def distinct(iterable):
    """Return unique items by eliminating duplicates.

    Args:
        iterable: The source of the items.

    Yields:
        Unique elements in order from 'iterable'.
    """
    seen = set()
    for item in iterable:
        if item in seen:
            continue
        yield item
        seen.add(item)

```

在这个生成器中，我们还使用了一个之前没有见过的控制流构造：`continue`关键字。`continue`语句结束当前循环的迭代，并立即开始下一个迭代。在这种情况下执行时，执行将被转移到`for`语句，但与`break`一样，它也可以与 while 循环一起使用。

在这种情况下，`continue`用于跳过已经产生的任何值。我们还可以添加一个`run_distinct()`函数来使用`distinct()`：

```py
def run_distinct():
    items = [5, 7, 7, 6, 5, 5]
    for item in distinct(items):
        print(item)

```

##### 理解这些生成器！

在这一点上，您应该花一些时间探索这两个生成器，然后再继续。确保您了解它们的工作方式以及它们如何在维护状态时控制流进出。如果您正在使用 IDE 运行这些示例，您可以使用调试器通过在生成器和使用它们的代码中设置断点来跟踪控制流。您也可以使用 Python 的内置`pdb`调试器（我们稍后会介绍）或者甚至只是使用老式的打印语句来实现相同的效果。

无论如何，确保在继续下一节之前，您真正了解这些生成器的工作方式。

#### 惰性生成器管道

现在您已经了解了单独的生成器，我们将把它们两个安排成一个惰性管道。我们将使用`take()`和`distinct()`一起从集合中获取前三个唯一的项目：

```py
def run_pipeline():
    items = [3, 6, 6, 2, 1, 1]
    for item in take(3, distinct(items)):
        print(item)

```

请注意，`distinct()`生成器只做足够的工作来满足`take()`生成器的需求，后者正在迭代它 - 它永远不会到达源列表的最后两个项目，因为它们不需要产生前三个唯一的项目。这种对计算的懒惰方法非常强大，但它产生的复杂控制流可能很难调试。在开发过程中，强制评估所有生成的值通常很有用，最简单的方法是插入一个对`list()`构造函数的调用：

```py
take(3, list(distinct(items)))

```

这个交错调用`list()`导致`distinct()`生成器在`take()`执行其工作之前彻底处理其源项目。有时，当您调试惰性计算的序列时，这可以让您了解正在发生什么。

#### 懒惰和无限

生成器是惰性的，这意味着计算只会在下一个结果被请求时才会发生。生成器的这种有趣和有用的特性意味着它们可以用来模拟无限序列。由于值只在调用者请求时产生，并且不需要构建数据结构来包含序列的元素，因此生成器可以安全地用于生成永无止境（或者只是非常大）的序列，比如：

+   传感器读数

+   数学序列（例如素数、阶乘等）^(18)

+   多太字节文件的内容

##### 生成 Lucas 系列

让我们介绍一个 Lucas 系列的生成器函数^(19)：

```py
def lucas():
    yield 2
    a = 2
    b = 1
    while True:
        yield b
        a, b = b, a + b

```

Lucas 系列以`2, 1`开始，之后每个值都是前两个值的和。因此，序列的前几个值是：

```py
2, 1, 3, 4, 7, 11

```

第一个`yield`产生值`2`。然后函数初始化`a`和`b`，它们保存着函数进行时所需的“前两个值”。然后函数进入一个无限的 while 循环，其中：

1.  它产生`b`的值

1.  `a`和`b`被更新以保存新的“前两个”值，使用元组解包的巧妙应用

现在我们有了一个生成器，它可以像任何其他可迭代对象一样使用。例如，要打印 Lucas 数，您可以使用以下循环：

```py
>>> for x in lucas():
...     print(x)
...
2
1
3
4
7
11
18
29
47
76
123
199

```

当然，由于 Lucas 序列是无限的，这将永远运行，打印出值，直到您的计算机耗尽内存。使用 Control-C 来终止循环。

### 生成器表达式

生成器表达式是推导和生成器函数之间的交叉。它们使用与推导类似的语法，但它们会产生一个*生成器对象*，该对象会懒惰地产生指定的序列。生成器表达式的语法与列表推导非常相似：

```py
( expr(item) for item in iterable )

```

它由括号界定，而不是用于列表推导的方括号。

生成器表达式在您希望使用推导的声明性简洁性进行懒惰评估的情况下非常有用。例如，这个生成器表达式产生了前一百万个平方数的列表：

```py
>>> million_squares = (x*x for x in range(1, 1000001))

```

此时，还没有创建任何一个平方数；我们只是将序列的规范捕捉到了一个生成器对象中：

```py
>>> million_squares
<generator object <genexpr> at 0x1007a12d0>

```

我们可以通过使用它来创建一个（长！）`list`来强制评估生成器：

```py
>>> list(million_squares)
. . .
999982000081, 999984000064, 999986000049, 999988000036, 999990000025,
999992000016, 999994000009, 999996000004, 999998000001, 1000000000000]

```

这个列表显然消耗了大量的内存 - 在这种情况下，列表对象和其中包含的整数对象大约为 40MB。

##### 生成器对象只运行一次

注意，生成器对象只是一个迭代器，一旦以这种方式耗尽，就不会再产生任何项目。重复前面的语句会返回一个空列表：

```py
>>> list(million_squares)
[]

```

生成器是一次性对象。每次调用生成器*函数*时，我们都会创建一个新的生成器对象。要从生成器表达式中重新创建生成器，我们必须再次执行表达式本身。

##### 无内存迭代

让我们通过使用内置的`sum()`函数来计算前*一千万*个平方数的和来提高赌注，该函数接受一个可迭代的数字序列。如果我们使用列表推导，我们可以期望它消耗大约 400MB 的内存。使用生成器表达式，内存使用将是微不足道的：

```py
>>> sum(x*x for x in range(1, 10000001))
333333383333335000000

```

这将在一秒钟左右产生一个结果，并且几乎不使用内存。

##### 可选的括号

仔细观察，您会发现在这种情况下，我们没有为生成器表达式提供单独的括号，除了`sum()`函数调用所需的括号。这种优雅的能力使得用于函数调用的括号也可以用于生成器表达式，有助于可读性。如果您愿意，您可以包含第二组括号。

##### 在生成器表达式中使用 if 子句

与推导一样，您可以在生成器表达式的末尾包含一个 if 子句。重复使用我们承认效率低下的`is_prime()`谓词，我们可以这样确定前一千个整数中是质数的整数的总和：

```py
>>> sum(x for x in range(1001) if is_prime(x))
76127

```

请注意，这与计算前 1000 个质数的总和不同，这是一个更棘手的问题，因为我们事先不知道在我们累积了一千个质数之前需要测试多少个整数。

### “电池包含”迭代工具

到目前为止，我们已经介绍了 Python 提供的创建可迭代对象的许多方法。推导、生成器和遵循可迭代或迭代器协议的任何对象都可以用于迭代，因此应该清楚迭代是 Python 的一个核心特性。

Python 提供了许多用于执行常见迭代器操作的内置函数。这些函数构成了一种用于处理迭代器的*词汇*，它们可以组合在一起，以产生非常简洁、可读的代码中的强大语句。我们已经遇到了其中一些函数，包括用于生成整数索引的`enumerate()`和用于计算数字总和的`sum()`。

#### 介绍`itertools`

除了内置函数之外，`itertools`模块还包含了大量用于处理可迭代数据流的有用函数和生成器。

我们将通过使用内置的`sum()`和`itertools`中的两个生成器函数：`islice()`和`count()`来解决前一千个质数问题来开始演示这些函数。

早些时候，我们为了懒惰地检索序列的开头而制作了自己的`take()`生成器函数。然而，我们不需要费心，因为`islice()`允许我们执行类似于内置列表切片功能的懒惰切片。要获取前 1000 个质数，我们需要做类似这样的事情：

```py
from itertools import islice, count

islice(all_primes, 1000)

```

但是如何生成`all_primes`呢？以前，我们一直使用`range()`来创建原始的整数序列，以供我们的质数测试使用，但范围必须始终是有限的，即在两端都有界。我们想要的是`range()`的开放版本，这正是`itertools.count()`提供的。使用`count()`和`islice()`，我们的前 1000 个质数表达式可以写成：

```py
>>> thousand_primes = islice((x for x in count() if is_prime(x)), 1000)

```

这返回一个特殊的`islice`对象，它是可迭代的。我们可以使用列表构造函数将其转换为列表。

```py
>>> thousand_primes
<itertools.islice object at 0x1006bae10>
>>> list(thousand_primes)
[2, 3, 5, 7, 11, 13 ... ,7877, 7879, 7883, 7901, 7907, 7919]

```

现在回答我们关于前 1000 个质数之和的问题很容易，记得重新创建生成器：

```py
>>> sum(islice((x for x in count() if is_prime(x)), 1000))
3682913

```

#### 布尔序列

另外两个非常有用的内置函数是`any()`和`all()`。它们相当于逻辑运算符`and`和`or`，但适用于`bool`值的可迭代序列，

```py
>>> any([False, False, True])
True
>>> all([False, False, True])
False

```

在这里，我们将使用`any()`与生成器表达式一起来回答一个问题，即 1328 到 1360 范围内是否有任何质数：

```py
>>> any(is_prime(x) for x in range(1328, 1361))
False

```

对于完全不同类型的问题，我们可以检查所有这些城市名称是否都是以大写字母开头的专有名词：

```py
>>> all(name == name.title() for name in ['London', 'Paris', 'Tokyo', 'New York', 'Sy\
dney', 'Kuala Lumpur'])
True

```

#### 使用`zip`合并序列

我们将要看的最后一个内置函数是`zip()`，顾名思义，它给我们提供了一种同步迭代两个可迭代序列的方法。例如，让我们一起`zip`两列温度数据，一个来自星期日，一个来自星期一：

```py
>>> sunday = [12, 14, 15, 15, 17, 21, 22, 22, 23, 22, 20, 18]
>>> monday = [13, 14, 14, 14, 16, 20, 21, 22, 22, 21, 19, 17]
>>> for item in zip(sunday, monday):
...     print(item)
...
(12, 13)
(14, 14)
(15, 14)
(15, 14)
(17, 16)
(21, 20)
(22, 21)
(22, 22)
(23, 22)
(22, 21)
(20, 19)
(18, 17)

```

我们可以看到，当迭代时，`zip()`会产生元组。这反过来意味着我们可以在 for 循环中使用元组解包来计算这些天每小时的平均温度：

```py
>>> for sun, mon in zip(sunday, monday):
...     print("average =", (sun + mon) / 2)
...
average = 12.5
average = 14.0
average = 14.5
average = 14.5
average = 16.5
average = 20.5
average = 21.5
average = 22.0
average = 22.5
average = 21.5
average = 19.5
average = 17.5

```

##### 使用`zip()`处理两个以上的序列

事实上，`zip()`可以接受任意数量的可迭代参数。让我们添加第三个时间序列，并使用其他内置函数来计算相应时间的统计数据：

```py
>>> tuesday = [2, 2, 3, 7, 9, 10, 11, 12, 10, 9, 8, 8]
>>> for temps in zip(sunday, monday, tuesday):
...     print("min = {:4.1f}, max={:4.1f}, average={:4.1f}".format(
...            min(temps), max(temps), sum(temps) / len(temps)))
...
min =  2.0, max=13.0, average= 9.0
min =  2.0, max=14.0, average=10.0
min =  3.0, max=15.0, average=10.7
min =  7.0, max=15.0, average=12.0
min =  9.0, max=17.0, average=14.0
min = 10.0, max=21.0, average=17.0
min = 11.0, max=22.0, average=18.0
min = 12.0, max=22.0, average=18.7
min = 10.0, max=23.0, average=18.3
min =  9.0, max=22.0, average=17.3
min =  8.0, max=20.0, average=15.7
min =  8.0, max=18.0, average=14.3

```

注意我们如何使用字符串格式化功能来控制数字列的宽度为四个字符。

#### 使用`chain()`懒惰地连接序列

也许，我们想要一个长的星期日、星期一和星期二的温度序列。我们可以使用`itertools.chain()`来*懒惰地*连接可迭代对象，而不是通过急切地组合三个温度列表来创建一个新列表：

```py
>>> from itertools import chain
>>> temperatures = chain(sunday, monday, tuesday)

```

`temperatures`是一个可迭代对象，首先产生来自`星期日`的值，然后是来自`星期一`的值，最后是来自`星期二`的值。虽然它是懒惰的，但它从来不会创建一个包含所有元素的单个列表；事实上，它从来不会创建任何中间列表！

现在我们可以检查所有这些温度是否都高于冰点，而不会造成数据重复的内存影响：

```py
>>> all(t > 0 for t in temperatures)
True

```

### 将所有内容汇总在一起

在总结之前，让我们把我们做的一些事情整合起来，让你的计算机计算卢卡斯质数：

```py
>>> for x in (p for p in lucas() if is_prime(p)):
...     print(x)
...
2
3
7
11
29
47
199
521
2207
3571
9349
3010349
54018521
370248451
6643838879
119218851371
5600748293801
688846502588399
32361122672259149

```

当你看够了这些内容后，我们建议你花一些时间探索`itertools`模块。你越熟悉 Python 对可迭代对象的现有支持，你自己的代码就会变得更加优雅和简洁。

### 总结

+   理解是描述列表、集合和字典的简洁语法。

+   理解操作可迭代源对象，并应用可选的谓词过滤器和强制表达式，这两者通常都是关于当前项目的。

+   可迭代对象是我们可以逐个迭代的对象。

+   我们使用内置的`iter()`函数从可迭代对象中检索迭代器。

+   迭代器每次传递给内置的`next()`函数时，都会从底层可迭代序列中逐个产生项目。

+   当集合耗尽时，迭代器会引发`StopIteration`异常。

#### 生成器

+   生成器函数允许我们使用命令式代码描述序列。

+   生成器函数至少包含一次使用`yield`关键字。

+   生成器是迭代器。当迭代器使用`next()`进行推进时，生成器会开始或恢复执行，直到包括下一个`yield`为止。

+   对生成器函数的每次调用都会创建一个新的生成器对象。

+   生成器可以在迭代之间的局部变量中维护显式状态。

+   生成器是懒惰的，因此可以模拟无限的数据系列。

+   生成器表达式具有类似的语法形式，可以更声明式和简洁地创建生成器对象。

#### 迭代工具

+   Python 包括一套丰富的工具，用于处理可迭代系列，包括内置函数如`sum()`、`any()`和`zip()`，以及`itertools`模块中的工具。


## 第九章：使用类定义新类型

使用内置的标量和集合类型可以在 Python 中走得很远。对于许多问题，内置类型以及 Python 标准库中提供的类型完全足够。但有时候，它们并不完全符合要求，创建自定义类型的能力就是*类*的用武之地。

正如我们所见，Python 中的所有对象都有一个类型，当我们使用内置的`type()`函数报告该类型时，结果是以该类型的*类*为基础的：

```py
>>> type(5)
<class 'int'>
>>> type("python")
<class 'str'>
>>> type([1, 2, 3])
<class 'list'>
>>> type(x*x for x in [2, 4, 6])
<class 'generator'>

```

类用于定义一个或多个对象的结构和行为，我们称之为类的*实例*。总的来说，Python 中的对象在创建时具有固定的类型^(20) - 或者在被销毁之前^(21)。将类视为一种模板或模具，用于构建新对象可能有所帮助。对象的类控制其初始化以及通过该对象可用的属性和方法。例如，在字符串对象上，我们可以使用的方法，如`split()`，是在`str`类中定义的。

类是 Python 中面向对象编程（OOP）的重要机制，尽管 OOP 可以用于使复杂问题更易处理，但它往往会使简单问题的解决方案变得不必要复杂。Python 的一个很棒的地方是它高度面向对象，而不会强迫你处理类，直到你真正需要它们。这使得该语言与 Java 和 C#截然不同。

### 定义类

类定义由`class`关键字引入，后面跟着类名。按照惯例，在 Python 中，新的类名使用驼峰命名法 - 有时被称为帕斯卡命名法 - 每个组件单词的首字母都大写，不使用下划线分隔。由于在 REPL 中定义类有点麻烦，我们将使用 Python 模块文件来保存我们在本章中使用的类定义。

让我们从非常简单的类开始，逐步添加功能。在我们的示例中，我们将通过将此代码放入`airtravel.py`来模拟两个机场之间的客机航班：

```py
"""Model for aircraft flights."""

class Flight:
    pass

```

`class`语句引入了一个新的块，所以我们在下一行缩进。空块是不允许的，所以最简单的类至少需要一个无用的`pass`语句才能在语法上被接受。

就像使用`def`来定义函数一样，`class`是一个*语句*，可以出现在程序的任何地方，并将类定义绑定到类名。当执行`airtravel`模块中的顶层代码时，类将被定义。

现在我们可以将我们的新类导入 REPL 并尝试它。

```py
>>> from airtravel import Flight

```

我们刚刚导入的东西是类对象。在 Python 中，一切都是对象，类也不例外。

```py
>>> Flight
<class 'airtravel.Flight'>

```

要使用这个类来创建一个新对象，我们必须调用它的构造函数，这是通过*调用*类来完成的，就像调用函数一样。构造函数返回一个新对象，这里我们将其赋给一个名为`f`的变量：

```py
>>> f = Flight()

```

如果我们使用`type()`函数来请求`f`的类型，我们会得到`airtravel.Flight`：

```py
>>> type(f)
<class 'airtravel.Flight'>

```

`f`的类型就是类。

### 实例方法

让我们通过添加所谓的*实例方法*来使我们的类更有趣，该方法返回航班号。方法只是在类块内定义的函数，实例方法是可以在我们的类的实例对象上调用的函数，比如`f`。实例方法必须接受对其调用方法的实例的引用作为第一个形式参数^(22)，按照惯例，这个参数**总是**被称为`self`。

我们还没有办法配置航班号的值，所以我们将返回一个常量字符串：

```py
class Flight:

    def number(self):
        return "SN060"

```

并从一个新的 REPL 开始：

```py
>>> from airtravel import Flight
>>> f = Flight()
>>> f.number()
SN060

```

请注意，当我们调用该方法时，我们不会为实际参数`self`在参数列表中提供实例`f`。这是因为标准的方法调用形式与点一起，就像这样：

```py
>>> f.number()
SN060

```

是语法糖：

```py
>>> Flight.number(f)
SN060

```

如果你尝试后者，你会发现它按预期工作，尽管你几乎永远不会看到这种形式被真正使用。

### 实例初始化程序

这个类并不是很有用，因为它只能表示一个特定的航班。我们需要在创建`Flight`时使航班号可配置。为此，我们需要编写一个初始化程序方法。

如果提供，初始化程序方法将作为创建新对象的过程的一部分被调用，当我们调用构造函数时。初始化程序方法必须被称为`__init__()`，用于 Python 运行时机制的双下划线限定。与所有其他实例方法一样，`__init__()`的第一个参数必须是`self`。

在这种情况下，我们还向`__init__()`传递了第二个形式参数，即航班号：

```py
class Flight:

    def __init__(self, number):
        self._number = number

    def number(self):
        return self._number

```

初始化程序不应返回任何东西-它修改了由`self`引用的对象。

如果你来自 Java、C#或 C++背景，很容易认为`__init__()`是构造函数。这并不完全准确；在 Python 中，`__init__()`的目的是在调用`__init__()`时配置已经存在的对象。然而，`self`参数在 Python 中类似于 Java、C#或 C++中的`this`。在 Python 中，实际的构造函数是由 Python 运行时系统提供的，它的其中一个功能是检查实例初始化程序的存在并在存在时调用它。

在初始化程序中，我们分配给新创建实例的*属性*称为`_number`。分配给尚不存在的对象属性足以使其存在。

就像我们不需要在创建变量之前声明它们一样，我们也不需要在创建对象属性之前声明它们。我们选择了带有前导下划线的`_number`有两个原因。首先，因为它避免了与同名方法的名称冲突。方法是函数，函数是对象，这些函数绑定到对象的属性，所以我们已经有一个名为`number`的属性，我们不想替换它。其次，有一个广泛遵循的约定，即对象的实现细节不应该由对象的客户端消费或操作，应该以下划线开头。

我们还修改了我们的`number()`方法来访问`_number`属性并返回它。

传递给飞行构造函数的任何实际参数都将转发到初始化程序，因此要创建和配置我们的`Flight`对象，我们现在可以这样做：

```py
>>> from airtravel import Flight
>>> f = Flight("SN060")
>>> f.number()
SN060

```

我们还可以直接访问实现细节：

```py
>>> f._number
SN060

```

尽管这不建议用于生产代码，但对于调试和早期测试非常方便。

#### 缺乏访问修饰符

如果你来自像 Java 或 C#这样的束缚和纪律语言，具有`public`、`private`和`protected`访问修饰符，Python 的“一切都是公开的”方法可能看起来过于开放。

Pythonista 之间普遍的文化是“我们都是自愿成年人”。实际上，前导下划线约定已经被证明足以保护我们所使用的大型和复杂的 Python 系统。人们知道不直接使用这些属性，事实上他们也不倾向于这样做。就像许多教条一样，缺乏访问修饰符在理论上比在实践中更成问题。

### 验证和不变量

对于对象的初始化程序来说，建立所谓的*类不变量*是一个好的做法。不变量是关于该类的对象应该在对象的生命周期内持续存在的真理。对于航班来说，这样的不变量是，航班号始终以大写的两个字母航空公司代码开头，后面跟着三位或四位数字路线号。

在 Python 中，我们在`__init__()`方法中建立类不变量，并在无法实现时引发异常：

```py
class Flight:

    def __init__(self, number):
        if not number[:2].isalpha():
            raise ValueError("No airline code in '{}'".format(number))

        if not number[:2].isupper():
            raise ValueError("Invalid airline code '{}'".format(number))

        if not (number[2:].isdigit() and int(number[2:]) <= 9999):
            raise ValueError("Invalid route number '{}'".format(number))

        self._number = number

    def number(self):
        return self._number

```

我们使用字符串切片和字符串类的各种方法进行验证。在本书中，我们还首次看到逻辑否定运算符`not`。

在 REPL 中的*Ad hoc*测试是开发过程中非常有效的技术：

```py
>>> from airtravel import Flight
>>> f = Flight("SN060")
>>> f = Flight("060")
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
  File "./airtravel.py", line 8, in __init__
    raise ValueError("No airline code in '{};".format(number))
ValueError: No airline code in '060'
>>> f = Flight("sn060")
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
  File "./airtravel.py", line 11, in __init__
    raise ValueError("Invalid airline code '{}'".format(number))
ValueError: Invalid airline code 'sn060'
>>> f = Flight("snabcd")
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
  File "./airtravel.py", line 11, in __init__
    raise ValueError("Invalid airline code '{}'".format(number))
ValueError: Invalid airline code 'snabcd'
>>> f = Flight("SN12345")
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
  File "./airtravel.py", line 11, in __init__
    raise ValueError("Invalid airline code '{}'".format(number))
ValueError: Invalid airline code 'sn12345'

```

现在我们确信有一个有效的航班号，我们将添加第二个方法，只返回航空公司代码。一旦类不变量被建立，大多数查询方法都可以非常简单：

```py
def airline(self):
    return self._number[:2]

```

### 添加第二个类

我们想要做的事情之一是接受座位预订。为此，我们需要知道座位布局，为此我们需要知道飞机的类型。让我们制作第二个类来模拟不同类型的飞机：

```py
class Aircraft:

    def __init__(self, registration, model, num_rows, num_seats_per_row):
        self._registration = registration
        self._model = model
        self._num_rows = num_rows
        self._num_seats_per_row = num_seats_per_row

    def registration(self):
        return self._registration

    def model(self):
        return self._model

```

初始化程序为飞机创建了四个属性：注册号、型号名称、座位行数和每行座位数。在生产代码场景中，我们可以验证这些参数，以确保例如行数不是负数。

这足够简单了，但对于座位计划，我们希望有一些更符合我们预订系统的东西。飞机的行数从一开始编号，每行的座位用字母表示，字母表中省略了‘I’，以避免与‘1’混淆。

![飞机座位计划。](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-aprt/img/seating-plan.png)

飞机座位计划。

我们将添加一个`seating_plan()`方法，它返回允许的行和座位，包含一个`range`对象和一个座位字母的字符串的 2 元组：

```py
def seating_plan(self):
  return (range(1, self._num_rows + 1),
          "ABCDEFGHJK"[:self._num_seats_per_row])

```

值得停顿一下，确保你理解这个函数是如何工作的。对`range()`构造函数的调用产生一个范围对象，它可以用作飞机行数的可迭代系列。字符串及其切片方法返回一个每个座位一个字符的字符串。这两个对象-范围和字符串-被捆绑成一个元组。

让我们构造一个有座位计划的飞机：

```py
  >>> from airtravel import *
  >>> a = Aircraft("G-EUPT", "Airbus A319", num_rows=22, num_seats_per_row=6)
  >>> a.registration()
  'G-EUPT'
  >>> a.model()
  'Airbus A319'
  >>> a.seating_plan()
  (range(1, 23), 'ABCDEF')

```

看看我们如何为行和座位使用关键字参数进行文档目的。回想一下，范围是半开放的，所以 23 正确地超出了范围的末端。

### 合作类

德米特尔法则是一个面向对象的设计原则，它说你不应该调用从其他调用中接收到的对象的方法。换句话说：只与你直接的朋友交谈。

![德米特尔法则-只与你直接的朋友交谈。这个法则实际上只是一个指导方针，是以一个面向方面的编程项目命名的，而这个项目又是以象征着自下而上哲学的希腊农业女神的名字命名的只是一个指导方针，是以一个面向方面的编程项目命名的，这又是以农业女神的名字命名的，她象征着自下而上的哲学其自下而上的哲学](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-aprt/img/law-of-demeter.png)

德米特尔法则-只与你直接的朋友交谈。这个法则实际上只是一个指导方针，是以一个面向方面的编程项目命名的，而这个项目又是以象征着自下而上哲学的希腊农业女神的名字命名的

我们现在将修改我们的`Flight`类，以在构造时接受一个飞机对象，并且我们将遵循德米特尔法则，通过添加一个方法来报告飞机型号。这个方法将代表客户委托`Aircraft`，而不是允许客户“通过”`Flight`并询问`Aircraft`对象：

```py
class Flight:
    """A flight with a particular passenger aircraft."""

    def __init__(self, number, aircraft):
        if not number[:2].isalpha():
            raise ValueError("No airline code in '{}'".format(number))

        if not number[:2].isupper():
            raise ValueError("Invalid airline code '{}'".format(number))

        if not (number[2:].isdigit() and int(number[2:]) <= 9999):
            raise ValueError("Invalid route number '{}'".format(number))

        self._number = number
        self._aircraft = aircraft

    def number(self):
        return self._number

    def airline(self):
        return self._number[:2]

    def aircraft_model(self):
        return self._aircraft.model()

```

我们还为类添加了一个文档字符串。这些工作方式就像函数和模块的文档字符串一样，并且必须是类主体内的第一个非注释行。

现在我们可以用特定的飞机构造一个航班：

```py
>>> from airtravel import *
>>> f = Flight("BA758", Aircraft("G-EUPT", "Airbus A319", num_rows=22,
...                              num_seats_per_row=6))
>>> f.aircraft_model()
'Airbus A319'

```

注意，我们构造了`Aircraft`对象，并直接将其传递给`Flight`构造函数，而无需为其命名中间引用。

* * *

### 禅宗时刻

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-aprt/img/zen-complex-is-better-than-complicated.png)

`aircraft_model()`方法是“复杂比复杂好”的一个例子：

```py
def aircraft_model(self):
    return self._aircraft.model()

```

Flight 类更加*复杂*——它包含额外的代码来深入到飞机引用中找到模型。然而，所有的`Flight`客户端现在可以更少*复杂*；它们都不需要知道`Aircraft`类，从而大大简化了系统。

* * *

### 预订座位

现在我们可以继续实现一个简单的预订系统。对于每个航班，我们需要跟踪谁坐在每个座位上。我们将使用一个字典列表来表示座位分配。列表将包含每个座位行的一个条目，每个条目将是一个从座位字母到乘客姓名的映射的字典。如果一个座位没有被占用，相应的字典值将包含`None`。

我们在`Flight.__init__()`中使用这个片段初始化座位计划：

```py
rows, seats = self._aircraft.seating_plan()
self._seating = [None] + [{letter: None for letter in seats} for _ in rows]

```

在第一行中，我们检索飞机的座位计划，并使用元组解包将行和座位标识符放入本地变量`rows`和`seats`中。在第二行中，我们为座位分配创建一个列表。我们选择浪费列表开头的一个条目，而不是不断处理行索引是基于一的事实，而 Python 列表使用基于零的索引。这个第一个浪费的条目是包含`None`的单元素列表。对于飞机中的每一行，我们将这个列表连接到另一个列表中。这个列表是通过列表推导构建的，它遍历了从前一行的`_aircraft`中检索到的行号的`range`对象。

![座位计划数据结构的对象图，这是一个列表的字典。](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-aprt/img/seating-data-structure.png)

座位计划数据结构的对象图，这是一个字典列表。

我们实际上对行号不感兴趣，因为我们知道它将与最终列表中的列表索引匹配，所以我们通过使用虚拟下划线变量将其丢弃。

列表推导的项目表达式本身就是一个推导；具体来说是一个字典推导！这遍历每个行字母，并创建从单个字符字符串到`None`的映射，以指示空座位。

我们使用列表推导，而不是使用乘法运算符进行列表复制，因为我们希望为每一行创建一个不同的字典对象；记住，重复是浅层的。

在我们将代码放入初始化程序后，代码如下：

```py
def __init__(self, number, aircraft):
    if not number[:2].isalpha():
        raise ValueError("No airline code in '{}'".format(number))

    if not number[:2].isupper():
        raise ValueError("Invalid airline code '{}'".format(number))

    if not (number[2:].isdigit() and int(number[2:]) <= 9999):
        raise ValueError("Invalid route number '{}'".format(number))

    self._number = number
    self._aircraft = aircraft

    rows, seats = self._aircraft.seating_plan()
    self._seating = [None] + [{letter: None for letter in seats} for _ in rows]

```

在我们进一步之前，让我们在 REPL 中测试我们的代码：

```py
>>> from airtravel import *
>>> f = Flight("BA758", Aircraft("G-EUPT", "Airbus A319", num_rows=22,
...                              num_seats_per_row=6))
>>>

```

由于一切都是“公开的”，我们可以在开发过程中访问实现细节。很明显，我们在开发过程中故意违反了惯例，因为前导下划线提醒我们什么是“公开的”和什么是“私有的”：

```py
>>> f._seating
[None, {'F': None, 'D': None, 'E': None, 'B': None, 'C': None, 'A': None},
{'F': None, 'D': None, 'E': None, 'B': None, 'C': None, 'A': None}, {'F': None,
'D': None, 'E': None, 'B': None, 'C': None, 'A': None}, {'F': None, 'D': None,
'E': None, 'B': None, 'C': None, 'A': None}, {'F': None, 'D': None, 'E': None,
'B': None, 'C': None, 'A': None}, {'F': None, 'D': None, 'E': None, 'B': None,
'C': None, 'A': None}, {'F': None, 'D': None, 'E': None, 'B': None, 'C': None,
'A': None}, {'F': None, 'D': None, 'E': None, 'B': None, 'C': None, 'A': None},
{'F': None, 'D': None, 'E': None, 'B': None, 'C': None, 'A': None}, {'F': None,
'D': None, 'E': None, 'B': None, 'C': None, 'A': None}, {'F': None, 'D': None,
'E': None, 'B': None, 'C': None, 'A': None}, {'F': None, 'D': None, 'E': None,
'B': None, 'C': None, 'A': None}, {'F': None, 'D': None, 'E': None, 'B': None,
'C': None, 'A': None}, {'F': None, 'D': None, 'E': None, 'B': None, 'C': None,
'A': None}, {'F': None, 'D': None, 'E': None, 'B': None, 'C': None, 'A': None},
{'F': None, 'D': None, 'E': None, 'B': None, 'C': None, 'A': None}, {'F': None,
'D': None, 'E': None, 'B': None, 'C': None, 'A': None}, {'F': None, 'D': None,
'E': None, 'B': None, 'C': None, 'A': None}, {'F': None, 'D': None, 'E': None,
'B': None, 'C': None, 'A': None}, {'F': None, 'D': None, 'E': None, 'B': None,
'C': None, 'A': None}, {'F': None, 'D': None, 'E': None, 'B': None, 'C': None,
'A': None}, {'F': None, 'D': None, 'E': None, 'B': None, 'C': None, 'A': None}]

```

这是准确的，但不是特别美观。让我们尝试用漂亮的打印：

```py
>>> from pprint import pprint as pp
>>> pp(f._seating)
[None,
  {'A': None, 'B': None, 'C': None, 'D': None, 'E': None, 'F': None},
  {'A': None, 'B': None, 'C': None, 'D': None, 'E': None, 'F': None},
  {'A': None, 'B': None, 'C': None, 'D': None, 'E': None, 'F': None},
  {'A': None, 'B': None, 'C': None, 'D': None, 'E': None, 'F': None},
  {'A': None, 'B': None, 'C': None, 'D': None, 'E': None, 'F': None},
  {'A': None, 'B': None, 'C': None, 'D': None, 'E': None, 'F': None},
  {'A': None, 'B': None, 'C': None, 'D': None, 'E': None, 'F': None},
  {'A': None, 'B': None, 'C': None, 'D': None, 'E': None, 'F': None},
  {'A': None, 'B': None, 'C': None, 'D': None, 'E': None, 'F': None},
  {'A': None, 'B': None, 'C': None, 'D': None, 'E': None, 'F': None},
  {'A': None, 'B': None, 'C': None, 'D': None, 'E': None, 'F': None},
  {'A': None, 'B': None, 'C': None, 'D': None, 'E': None, 'F': None},
  {'A': None, 'B': None, 'C': None, 'D': None, 'E': None, 'F': None},
  {'A': None, 'B': None, 'C': None, 'D': None, 'E': None, 'F': None},
  {'A': None, 'B': None, 'C': None, 'D': None, 'E': None, 'F': None},
  {'A': None, 'B': None, 'C': None, 'D': None, 'E': None, 'F': None},
  {'A': None, 'B': None, 'C': None, 'D': None, 'E': None, 'F': None},
  {'A': None, 'B': None, 'C': None, 'D': None, 'E': None, 'F': None},
  {'A': None, 'B': None, 'C': None, 'D': None, 'E': None, 'F': None},
  {'A': None, 'B': None, 'C': None, 'D': None, 'E': None, 'F': None},
  {'A': None, 'B': None, 'C': None, 'D': None, 'E': None, 'F': None},
  {'A': None, 'B': None, 'C': None, 'D': None, 'E': None, 'F': None}]

```

太好了！

#### 为乘客分配座位

现在我们将为`Flight`添加行为，将座位分配给乘客。为了保持简单，乘客将是一个字符串名称：

```py
 1 class Flight:
 2 
 3    # ...
 4 
 5    def allocate_seat(seat, passenger):
 6        """Allocate a seat to a passenger.
 7 
 8        Args:
 9            seat: A seat designator such as '12C' or '21F'.
10             passenger: The passenger name.
11 
12         Raises:
13             ValueError: If the seat is unavailable.
14         """
15         rows, seat_letters = self._aircraft.seating_plan()
16 
17         letter = seat[-1]
18         if letter not in seat_letters:
19             raise ValueError("Invalid seat letter {}".format(letter))
20 
21         row_text = seat[:-1]
22         try:
23             row = int(row_text)
24         except ValueError:
25             raise ValueError("Invalid seat row {}".format(row_text))
26 
27         if row not in rows:
28             raise ValueError("Invalid row number {}".format(row))
29 
30         if self._seating[row][letter] is not None:
31             raise ValueError("Seat {} already occupied".format(seat))
32 
33         self._seating[row][letter] = passenger

```

大部分代码都是座位指示符的验证，其中包含一些有趣的片段：

+   第 6 行：方法是函数，因此也应该有文档字符串。

+   第 17 行：我们通过在`seat`字符串中使用负索引来获取座位字母。

+   第 18 行：我们通过使用`in`成员测试运算符检查`seat_letters`的成员资格来测试座位字母是否有效。

+   第 21 行：我们使用字符串切片提取行号，以去掉最后一个字符。

+   第 23 行：我们尝试使用`int()`构造函数将行号子字符串转换为整数。如果失败，我们捕获`ValueError`，并在处理程序中引发一个更合适的消息负载的*新*`ValueError`。

+   第 27 行：我们通过使用`in`运算符对`rows`对象进行验证行号。我们可以这样做，因为`range()`对象支持*容器*协议。

+   第 30 行：我们使用`None`进行身份测试来检查请求的座位是否空闲。如果被占用，我们会引发`ValueError`。

+   第 33 行：如果我们走到这一步，一切都很好，我们可以分配座位。

这段代码也包含一个错误，我们很快就会发现！

在 REPL 中尝试我们的座位分配器：

```py
>>> from airtravel import *
>>> f = Flight("BA758", Aircraft("G-EUPT", "Airbus A319",
...            num_rows=22, num_seats_per_row=6))
>>> f.allocate_seat('12A', 'Guido van Rossum')
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
  TypeError: allocate_seat() takes 2 positional arguments but 3 were given

```

哦，天哪！在你的面向对象的 Python 职业生涯早期，你很可能经常会看到像这样的`TypeError`消息。问题出现在我们忘记在`allocate_seat()`方法的定义中包含`self`参数：

```py
def allocate_seat(self, seat, passenger):
    # ...

```

一旦我们修复了这个问题，我们可以再试一次：

```py
>>> from airtravel import *
>>> from pprint import pprint as pp
>>> f = Flight("BA758", Aircraft("G-EUPT", "Airbus A319",
...            num_rows=22, num_seats_per_row=6))
>>> f.allocate_seat('12A', 'Guido van Rossum')
>>> f.allocate_seat('12A', 'Rasmus Lerdorf')
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
  File "./airtravel.py", line 57, in allocate_seat
    raise ValueError("Seat {} already occupied".format(seat))
ValueError: Seat 12A already occupied
>>> f.allocate_seat('15F', 'Bjarne Stroustrup')
>>> f.allocate_seat('15E', 'Anders Hejlsberg')
>>> f.allocate_seat('E27', 'Yukihiro Matsumoto')
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
  File "./airtravel.py", line 45, in allocate_seat
    raise ValueError("Invalid seat letter {}".format(letter))
ValueError: Invalid seat letter 7
>>> f.allocate_seat('1C', 'John McCarthy')
>>> f.allocate_seat('1D', 'Richard Hickey')
>>> f.allocate_seat('DD', 'Larry Wall')
Traceback (most recent call last):
  File "./airtravel.py", line 49, in allocate_seat
    row = int(row_text)
ValueError: invalid literal for int() with base 10: 'D'

During handling of the above exception, another exception occurred:

Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
  File "./airtravel.py", line 51, in allocate_seat
    raise ValueError("Invalid seat row {}".format(row_text))
ValueError: Invalid seat row D

>>> pp(f._seating)
[None,
  {'A': None,
  'B': None,
  'C': 'John McCarthy',
  'D': 'Richard Hickey',
  'E': None,
  'F': None},
  {'A': None, 'B': None, 'C': None, 'D': None, 'E': None, 'F': None},
  {'A': None, 'B': None, 'C': None, 'D': None, 'E': None, 'F': None},
  {'A': None, 'B': None, 'C': None, 'D': None, 'E': None, 'F': None},
  {'A': None, 'B': None, 'C': None, 'D': None, 'E': None, 'F': None},
  {'A': None, 'B': None, 'C': None, 'D': None, 'E': None, 'F': None},
  {'A': None, 'B': None, 'C': None, 'D': None, 'E': None, 'F': None},
  {'A': None, 'B': None, 'C': None, 'D': None, 'E': None, 'F': None},
  {'A': None, 'B': None, 'C': None, 'D': None, 'E': None, 'F': None},
  {'A': None, 'B': None, 'C': None, 'D': None, 'E': None, 'F': None},
  {'A': None, 'B': None, 'C': None, 'D': None, 'E': None, 'F': None},
  {'A': 'Guido van Rossum',
  'B': None,
  'C': None,
  'D': None,
  'E': None,
  'F': None},
  {'A': None, 'B': None, 'C': None, 'D': None, 'E': None, 'F': None},
  {'A': None, 'B': None, 'C': None, 'D': None, 'E': None, 'F': None},
  {'A': None,
  'B': None,
  'C': None,
  'D': None,
  'E': 'Anders Hejlsberg',
  'F': 'Bjarne Stroustrup'},
  {'A': None, 'B': None, 'C': None, 'D': None, 'E': None, 'F': None},
  {'A': None, 'B': None, 'C': None, 'D': None, 'E': None, 'F': None},
  {'A': None, 'B': None, 'C': None, 'D': None, 'E': None, 'F': None},
  {'A': None, 'B': None, 'C': None, 'D': None, 'E': None, 'F': None},
  {'A': None, 'B': None, 'C': None, 'D': None, 'E': None, 'F': None},
  {'A': None, 'B': None, 'C': None, 'D': None, 'E': None, 'F': None},
  {'A': None, 'B': None, 'C': None, 'D': None, 'E': None, 'F': None}]

```

荷兰人在 12 排有些孤单，所以我们想把他和丹麦人一起移回 15 排。为此，我们需要一个`relocate_passenger()`方法。

### 为实现细节命名方法

首先，我们将进行一些小的重构，并将座位标识符解析和验证逻辑提取到它自己的方法`_parse_seat()`中。我们在这里使用了前导下划线，因为这个方法是一个实现细节：

```py
class Flight:

    # ...

    def _parse_seat(self, seat):
        """Parse a seat designator into a valid row and letter.

 Args:
 seat: A seat designator such as 12F

 Returns:
 A tuple containing an integer and a string for row and seat.
 """
        row_numbers, seat_letters = self._aircraft.seating_plan()

        letter = seat[-1]
        if letter not in seat_letters:
            raise ValueError("Invalid seat letter {}".format(letter))

        row_text = seat[:-1]
        try:
            row = int(row_text)
        except ValueError:
            raise ValueError("Invalid seat row {}".format(row_text))

        if row not in row_numbers:
            raise ValueError("Invalid row number {}".format(row))

        return row, letter

```

新的`_parse_seat()`方法返回一个整数行号和一个座位字母字符串的元组。这使得`allocate_seat()`变得更简单：

```py
def allocate_seat(self, seat, passenger):
    """Allocate a seat to a passenger.

 Args:
 seat: A seat designator such as '12C' or '21F'.
 passenger: The passenger name.

 Raises:
 ValueError: If the seat is unavailable.
 """
    row, letter = self._parse_seat(seat)

    if self._seating[row][letter] is not None:
        raise ValueError("Seat {} already occupied".format(seat))

    self._seating[row][letter] = passenger

```

注意到调用`_parse_seat()`也需要使用`self`前缀进行显式限定。

#### 实现`relocate_passenger()`

现在我们已经为我们的`relocate_passenger()`方法奠定了基础：

```py
class Flight:

    # ...

    def relocate_passenger(self, from_seat, to_seat):
        """Relocate a passenger to a different seat.

 Args:
 from_seat: The existing seat designator for the
 passenger to be moved.

 to_seat: The new seat designator.
 """
        from_row, from_letter = self._parse_seat(from_seat)
        if self._seating[from_row][from_letter] is None:
            raise ValueError("No passenger to relocate in seat {}".format(from_seat))

        to_row, to_letter = self._parse_seat(to_seat)
        if self._seating[to_row][to_letter] is not None:
            raise ValueError("Seat {} already occupied".format(to_seat))

        self._seating[to_row][to_letter] = self._seating[from_row][from_letter]
        self._seating[from_row][from_letter] = None

```

这解析和验证了`from_seat`和`to_seat`参数，然后将乘客移动到新位置。

每次重新创建`Flight`对象也变得很烦人，所以我们也会为此添加一个*模块*级别的便利函数：

```py
def make_flight():
    f = Flight("BA758", Aircraft("G-EUPT", "Airbus A319",
                num_rows=22, num_seats_per_row=6))
    f.allocate_seat('12A', 'Guido van Rossum')
    f.allocate_seat('15F', 'Bjarne Stroustrup')
    f.allocate_seat('15E', 'Anders Hejlsberg')
    f.allocate_seat('1C', 'John McCarthy')
    f.allocate_seat('1D', 'Richard Hickey')
    return f

```

在 Python 中，将相关的函数和类混合放在同一个模块中是非常正常的。现在，从 REPL：

```py
>>> from airtravel import make_flight
>>> f = make_flight()
>>> f
<airtravel.Flight object at 0x1007a6690>

```

你可能会觉得很奇怪，我们只导入了一个函数`make_flight`，但我们却可以访问`Flight`类。这是非常正常的，这是 Python 动态类型系统的一个强大方面，它促进了代码之间的这种非常松散的耦合。

让我们继续把 Guido 移回到 15 排和他的欧洲同胞一起：

```py
>>> f.relocate_passenger('12A', '15D')
>>> from pprint import pprint as pp
>>> pp(f._seating)
[None,
  {'A': None,
  'B': None,
  'C': 'John McCarthy',
  'D': 'Richard Hickey',
  'E': None,
  'F': None},
  {'A': None, 'B': None, 'C': None, 'D': None, 'E': None, 'F': None},
  {'A': None, 'B': None, 'C': None, 'D': None, 'E': None, 'F': None},
  {'A': None, 'B': None, 'C': None, 'D': None, 'E': None, 'F': None},
  {'A': None, 'B': None, 'C': None, 'D': None, 'E': None, 'F': None},
  {'A': None, 'B': None, 'C': None, 'D': None, 'E': None, 'F': None},
  {'A': None, 'B': None, 'C': None, 'D': None, 'E': None, 'F': None},
  {'A': None, 'B': None, 'C': None, 'D': None, 'E': None, 'F': None},
  {'A': None, 'B': None, 'C': None, 'D': None, 'E': None, 'F': None},
  {'A': None, 'B': None, 'C': None, 'D': None, 'E': None, 'F': None},
  {'A': None, 'B': None, 'C': None, 'D': None, 'E': None, 'F': None},
  {'A': None, 'B': None, 'C': None, 'D': None, 'E': None, 'F': None},
  {'A': None, 'B': None, 'C': None, 'D': None, 'E': None, 'F': None},
  {'A': None, 'B': None, 'C': None, 'D': None, 'E': None, 'F': None},
  {'A': None,
  'B': None,
  'C': None,
  'D': 'Guido van Rossum',
  'E': 'Anders Hejlsberg',
  'F': 'Bjarne Stroustrup'},
  {'A': None, 'B': None, 'C': None, 'D': None, 'E': None, 'F': None},
  {'A': None, 'B': None, 'C': None, 'D': None, 'E': None, 'F': None},
  {'A': None, 'B': None, 'C': None, 'D': None, 'E': None, 'F': None},
  {'A': None, 'B': None, 'C': None, 'D': None, 'E': None, 'F': None},
  {'A': None, 'B': None, 'C': None, 'D': None, 'E': None, 'F': None},
  {'A': None, 'B': None, 'C': None, 'D': None, 'E': None, 'F': None},
  {'A': None, 'B': None, 'C': None, 'D': None, 'E': None, 'F': None}]

```

#### 计算可用座位

在预订期间知道有多少个座位是很重要的。为此，我们将编写一个`num_available_seats()`方法。这使用了两个嵌套的生成器表达式。外部表达式过滤出所有不是`None`的行，以排除我们的虚拟第一行。外部表达式中每个项目的值是每行中`None`值的总和。内部表达式遍历字典的值，并为每个找到的`None`添加 1：

```py
def num_available_seats(self):
    return sum( sum(1 for s in row.values() if s is None)
                for row in self._seating
                if row is not None )

```

注意我们如何将外部表达式分成三行以提高可读性。

```py
>>> from airtravel import make_flight
>>> f = make_flight()
>>> f.num_available_seats()
127

```

快速检查显示我们的新计算是正确的：

```py
>>> 6 * 22 - 5
127

```

### 有时你只需要一个函数

现在我们将展示如何在不需要类的情况下编写良好的面向对象代码是完全可能的。我们需要按字母顺序为乘客制作登机牌。但是，我们意识到航班类可能不是打印登机牌的细节的好位置。我们可以继续创建一个`BoardingCardPrinter`类，尽管这可能有些过度。记住，函数也是对象，对于许多情况来说完全足够。不要觉得没有充分理由就要创建类。

我们不希望让卡片打印机从航班中查询所有乘客的详细信息，我们将遵循面向对象设计原则“告诉！不要问。”，让`Flight` *告诉*一个简单的卡片打印函数该做什么。

首先是卡片打印机，它只是一个模块级函数：

```py
def console_card_printer(passenger, seat, flight_number, aircraft):
    output = "| Name: {0}"     \
              "  Flight: {1}"   \
              "  Seat: {2}"     \
              "  Aircraft: {3}" \
              " |".format(passenger, flight_number, seat, aircraft)
    banner = '+' + '-' * (len(output) - 2) + '+'
    border = '|' + ' ' * (len(output) - 2) + '|'
    lines = [banner, border, output, border, banner]
    card = '\n'.join(lines)
    print(card)
    print()

```

我们在这里引入的一个 Python 特性是使用行继续反斜杠字符‘\’，它允许我们将长语句分成几行。这里使用了它，连同相邻字符串的隐式连接，以产生一个没有换行的长字符串。

我们测量这个输出行的长度，围绕它建立一些横幅和边框，然后使用`join()`方法将行连接在一起，该方法在换行符上调用。然后打印整张卡片，然后是一个空行。卡片打印机对`Flights`或`Aircraft`一无所知-它们之间的耦合非常松散。您可能很容易想象具有相同接口的 HTML 卡片打印机。

#### 使`Flight`创建登机牌

我们向`Flight`类添加一个新方法`make_boarding_cards()`，它接受一个`card_printer`：

```py
class Flight:

    # ...

    def make_boarding_cards(self, card_printer):
        for passenger, seat in sorted(self._passenger_seats()):
            card_printer(passenger, seat, self.number(), self.aircraft_model())

```

这告诉`card_printer`打印每个乘客，已经排序了从`_passenger_seats()`实现细节方法（注意前导下划线）获得的乘客-座位元组列表。实际上，这个方法是一个生成器函数，它搜索所有座位的占用情况，找到后产生乘客和座位号：

```py
def _passenger_seats(self):
    """An iterable series of passenger seating allocations."""
    row_numbers, seat_letters = self._aircraft.seating_plan()
    for row in row_numbers:
        for letter in seat_letters:
            passenger = self._seating[row][letter]
            if passenger is not None:
                yield (passenger, "{}{}".format(row, letter))

```

现在，如果我们在 REPL 上运行这个，我们可以看到新的登机牌打印系统起作用了：

```py
>>> from airtravel import console_card_printer, make_flight
>>> f = make_flight()
>>> f.make_boarding_cards(console_card_printer)
+-------------------------------------------------------------------------+
|                                                                         |
| Name: Anders Hejlsberg  Flight: BA758  Seat: 15E  Aircraft: Airbus A319 |
|                                                                         |
+-------------------------------------------------------------------------+

+--------------------------------------------------------------------------+
|                                                                          |
| Name: Bjarne Stroustrup  Flight: BA758  Seat: 15F  Aircraft: Airbus A319 |
|                                                                          |
+--------------------------------------------------------------------------+

+-------------------------------------------------------------------------+
|                                                                         |
| Name: Guido van Rossum  Flight: BA758  Seat: 12A  Aircraft: Airbus A319 |
|                                                                         |
+-------------------------------------------------------------------------+

+---------------------------------------------------------------------+
|                                                                     |
| Name: John McCarthy  Flight: BA758  Seat: 1C  Aircraft: Airbus A319 |
|                                                                     |
+---------------------------------------------------------------------+

+----------------------------------------------------------------------+
|                                                                      |
| Name: Richard Hickey  Flight: BA758  Seat: 1D  Aircraft: Airbus A319 |
|                                                                      |
+----------------------------------------------------------------------+

```

### 多态和鸭子类型

多态是一种编程语言特性，它允许我们通过统一接口使用不同类型的对象。多态的概念适用于函数和更复杂的对象。我们刚刚在卡片打印示例中看到了多态的一个例子。`make_boarding_card()`方法不需要知道实际的-或者我们说“具体的”-卡片打印类型，只需要知道其接口的抽象细节。这个接口本质上只是它的参数顺序。用假想的`html_card_printer`替换我们的`console_card_printer`将会实现多态。

Python 中的多态是通过鸭子类型实现的。鸭子类型又以美国诗人詹姆斯·惠特科姆·赖利的“鸭子测试”而命名。

![詹姆斯·惠特科姆·赖利-美国诗人和作家](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-aprt/img/james-whitcomb-riley.png)

詹姆斯·惠特科姆·赖利-美国诗人和作家

> 当我看到一只走路像鸭子、游泳像鸭子、嘎嘎叫像鸭子的鸟时，我就称那只鸟为鸭子。

鸭子类型，其中对象的适用性仅在运行时确定，是 Python 对象系统的基石。这与许多静态类型的语言不同，其中编译器确定对象是否可以使用。特别是，这意味着对象的适用性不是基于继承层次结构、基类或除了对象在使用时具有的属性之外的任何东西。

这与诸如 Java 之类的语言形成鲜明对比，后者依赖于所谓的*名义子类型*，通过从基类和接口继承。我们很快会在 Python 的上下文中更多地讨论继承。

#### 重构`Aircraft`

让我们回到我们的`Aircraft`类：

```py
class Aircraft:

    def __init__(self, registration, model, num_rows, num_seats_per_row):
        self._registration = registration
        self._model = model
        self._num_rows = num_rows
        self._num_seats_per_row = num_seats_per_row

    def registration(self):
        return self._registration

    def model(self):
        return self._model

    def seating_plan(self):
        return (range(1, self._num_rows + 1),
                "ABCDEFGHJK"[:self._num_seats_per_row])

```

这个类的设计有些缺陷，因为使用它实例化的对象依赖于提供与飞机型号匹配的座位配置。在这个练习中，我们可以假设每架飞机型号的座位安排是固定的。

也许更好、更简单的方法是完全摆脱`Aircraft`类，并为每种特定型号的飞机制作单独的类，具有固定的座位配置。这是空中客车 A319：

```py
class AirbusA319:

    def __init__(self, registration):
        self._registration = registration

    def registration(self):
        return self._registration

    def model(self):
        return "Airbus A319"

    def seating_plan(self):
        return range(1, 23), "ABCDEF"

```

这是波音 777：

```py
class Boeing777:

    def __init__(self, registration):
        self._registration = registration

    def registration(self):
        return self._registration

    def model(self):
        return "Boeing 777"

    def seating_plan(self):
        # For simplicity's sake, we ignore complex
        # seating arrangement for first-class
        return range(1, 56), "ABCDEGHJK"

```

这两个飞机类与彼此或我们原始的`Aircraft`类之间没有明确的关系，除了具有相同的接口（初始化程序除外，现在需要的参数更少）。因此，我们可以在彼此之间使用这些新类型。

让我们将我们的`make_flight()`方法更改为`make_flights()`，这样我们就可以使用它们了：

```py
def make_flights():
    f = Flight("BA758", AirbusA319("G-EUPT"))
    f.allocate_seat('12A', 'Guido van Rossum')
    f.allocate_seat('15F', 'Bjarne Stroustrup')
    f.allocate_seat('15E', 'Anders Hejlsberg')
    f.allocate_seat('1C', 'John McCarthy')
    f.allocate_seat('1D', 'Richard Hickey')

    g = Flight("AF72", Boeing777("F-GSPS"))
    g.allocate_seat('55K', 'Larry Wall')
    g.allocate_seat('33G', 'Yukihiro Matsumoto')
    g.allocate_seat('4B', 'Brian Kernighan')
    g.allocate_seat('4A', 'Dennis Ritchie')

    return f, g

```

不同类型的飞机在与`Flight`一起使用时都可以正常工作，因为它们都像鸭子一样嘎嘎叫。或者像飞机一样飞。或者其他什么：

```py
>>> from airtravel import *
>>> f, g = make_flights()
>>> f.aircraft_model()
'Airbus A319'
>>> g.aircraft_model()
'Boeing 777'
>>> f.num_available_seats()
127
>>> g.num_available_seats()
491
>>> g.relocate_passenger('55K', '13G')
>>> g.make_boarding_cards(console_card_printer)
+---------------------------------------------------------------------+
|                                                                     |
| Name: Brian Kernighan  Flight: AF72  Seat: 4B  Aircraft: Boeing 777 |
|                                                                     |
+---------------------------------------------------------------------+

+--------------------------------------------------------------------+
|                                                                    |
| Name: Dennis Ritchie  Flight: AF72  Seat: 4A  Aircraft: Boeing 777 |
|                                                                    |
+--------------------------------------------------------------------+

+-----------------------------------------------------------------+
|                                                                 |
| Name: Larry Wall  Flight: AF72  Seat: 13G  Aircraft: Boeing 777 |
|                                                                 |
+-----------------------------------------------------------------+

+-------------------------------------------------------------------------+
|                                                                         |
| Name: Yukihiro Matsumoto  Flight: AF72  Seat: 33G  Aircraft: Boeing 777 |
|                                                                         |
+-------------------------------------------------------------------------+

```

鸭子类型和多态在 Python 中非常重要。事实上，它是我们讨论的集合协议的基础，如*迭代器*、*可迭代*和*序列*。

### 继承和实现共享

继承是一种机制，其中一个类可以从基类*派生*，从而使我们能够在子类中使行为更具体。在像 Java 这样的名义类型语言中，基于类的继承是实现运行时多态性的手段。但在 Python 中并非如此，正如我们刚刚展示的那样。直到调用方法或属性查找的实际对象绑定到对象时，即*延迟绑定*，我们才能尝试使用任何对象进行多态，并且如果对象合适，它将成功。

尽管 Python 中的继承可以用于促进多态性——毕竟，派生类将具有与基类相同的接口——但 Python 中的继承最有用的是在类之间共享实现。

#### 飞机的基类

像往常一样，通过示例会更容易理解。我们希望我们的飞机类`AirbusA319`和`Boeing777`提供一种返回总座位数的方法。我们将在两个类中添加一个名为`num_seats()`的方法来实现这一点：

```py
def num_seats(self):
    rows, row_seats = self.seating_plan()
    return len(rows) * len(row_seats)

```

由于可以从座位计划中计算出来，所以两个类中的实现可以是相同的。

不幸的是，现在我们在两个类中有重复的代码，随着我们添加更多的飞机类型，代码重复将变得更糟。

解决方案是将`AirbusA319`和`Boeing777`的共同元素提取到一个基类中，两种飞机类型都将从中派生。让我们重新创建`Aircraft`类，这次的目标是将其用作基类：

```py
class Aircraft:

    def num_seats(self):
        rows, row_seats = self.seating_plan()
        return len(rows) * len(row_seats)

```

`Aircraft`类只包含我们想要继承到派生类中的方法。这个类本身无法使用，因为它依赖于一个叫做`seating_plan()`的方法，这个方法在这个级别不可用。任何尝试单独使用它都会失败：

```py
>>> from airtravel import *
>>> base = Aircraft()
>>> base.num_seats()
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
  File "./airtravel.py", line 125, in num_seats
    rows, row_seats = self.seating_plan()
AttributeError: 'Aircraft' object has no attribute 'seating_plan'

```

类在*抽象*方面是不可用的，因为单独实例化它是没有用的。

#### 从`Aircraft`继承

现在是派生类。我们使用括号在`class`语句中的类名后面立即包含基类名来指定 Python 中的继承。

这是空客类：

```py
class AirbusA319(Aircraft):

    def __init__(self, registration):
        self._registration = registration

    def registration(self):
        return self._registration

    def model(self):
        return "Airbus A319"

    def seating_plan(self):
        return range(1, 23), "ABCDEF"

```

这是波音类：

```py
class Boeing777(Aircraft):

    def __init__(self, registration):
        self._registration = registration

    def registration(self):
        return self._registration

    def model(self):
        return "Boeing 777"

    def seating_plan(self):
        # For simplicity's sake, we ignore complex
        # seating arrangement for first-class
        return range(1, 56), "ABCDEGHJK"

```

让我们在 REPL 中练习一下：

```py
>>> from airtravel import *
>>> a = AirbusA319("G-EZBT")
>>> a.num_seats()
132
>>> b = Boeing777("N717AN")
>>> b.num_seats()
495

```

我们可以看到两个子类型飞机都继承了`num_seats`方法，现在它可以正常工作，因为在运行时成功解析了对`seating_plan()`的调用。

#### 将通用功能提升到基类

现在我们有了基本的`Aircraft`类，我们可以通过将其他通用功能提升到其中来进行重构。例如，初始化程序和`registration()`方法在两个子类型之间是相同的：

```py
class Aircraft:

    def __init__(self, registration):
        self._registration = registration

    def registration(self):
        return self._registration

    def num_seats(self):
        rows, row_seats = self.seating_plan()
        return len(rows) * len(row_seats)

class AirbusA319(Aircraft):

    def model(self):
        return "Airbus A319"

    def seating_plan(self):
        return range(1, 23), "ABCDEF"

class Boeing777(Aircraft):

    def model(self):
        return "Boeing 777"

    def seating_plan(self):
        # For simplicities sake, we ignore complex
        # seating arrangement for first-class
        return range(1, 56), "ABCDEGHJK"

```

这些派生类只包含该飞机类型的具体信息。所有通用功能都是通过继承从基类中共享的。

由于鸭子类型的存在，继承在 Python 中的使用要少于其他语言。这通常被认为是一件好事，因为继承是类之间非常紧密的耦合。

### 摘要

+   Python 中的所有类型都有一个“类”。

+   类定义了对象的结构和行为。

+   对象的类是在创建对象时确定的，几乎总是在对象的生命周期内固定的。

+   类是 Python 中面向对象编程的关键支持。

+   类是使用`class`关键字定义的，后面跟着类名，类名采用驼峰命名法。

+   类的实例是通过调用类来创建的，就好像它是一个函数一样。

+   实例方法是在类内部定义的函数，应该接受一个名为`self`的对象实例作为第一个参数。

+   方法是使用`instance.method()`语法调用的，这是将实例作为形式参数`self`传递给方法的语法糖。

+   可以提供一个可选的特殊初始化方法`__init__()`，用于在创建时配置`self`对象。

+   如果存在构造函数，则调用`__init__()`方法。

+   `__init__()`方法*不是*构造函数。在初始化程序被调用时，对象已经被构造。初始化程序在返回给构造函数的调用者之前配置新创建的对象。

+   传递给构造函数的参数将转发到初始化程序。

+   实例属性通过分配给它们而存在。

+   按照惯例，实现细节的属性和方法以下划线为前缀。Python 中没有公共、受保护或私有访问修饰符。

+   从类外部访问实现细节在开发、测试和调试过程中非常有用。

+   类不变量应该在初始化程序中建立。如果不变量无法建立，则引发异常以表示失败。

+   方法可以有文档字符串，就像常规函数一样。

+   类可以有文档字符串。

+   即使在对象方法内部，方法调用也必须用`self`限定。

+   你可以在一个模块中拥有任意多的类和函数。相关的类和全局函数通常以这种方式分组在一起。

+   Python 中的多态是通过鸭子类型实现的，其中属性和方法仅在使用时解析 - 这种行为称为延迟绑定。

+   Python 中的多态不需要共享基类或命名接口。

+   Python 中的类继承主要用于共享实现，而不是必须的多态。

+   所有方法都被继承，包括初始方法。

在这个过程中，我们发现：

+   字符串支持切片，因为它们实现了*序列*协议。

+   遵循迪米特法则可以减少耦合。

+   我们可以嵌套理解。

+   有时候，在理解中丢弃当前项目是有用的，使用一个虚拟引用，通常是下划线。

+   处理基于一的集合时，通常更容易只浪费第零个列表条目。

+   当一个简单的函数足够时，不要感到被迫使用类。函数也是对象。

+   复杂的理解或生成器表达式可以分成多行以帮助可读性。

+   语句可以使用反斜杠行继续字符分成多行。只有在提高可读性时才节俭地使用这个功能。

+   面向对象的设计，其中一个对象*告诉*另一个对象信息，可以比其中一个对象查询另一个对象更松散耦合。“告诉！不要问。”
