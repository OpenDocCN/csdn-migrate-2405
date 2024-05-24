# Python3 面向对象编程第二版（二）

> 原文：[`zh.annas-archive.org/md5/B484D481722F7AFA9E5B1ED7225BED43`](https://zh.annas-archive.org/md5/B484D481722F7AFA9E5B1ED7225BED43)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：预料之外的情况

程序非常脆弱。如果代码总是返回有效的结果那就太理想了，但有时候无法计算出有效的结果。例如，不能除以零，或者访问五项列表中的第八项。

在过去，唯一的解决方法是严格检查每个函数的输入，以确保它们是有意义的。通常，函数有特殊的返回值来指示错误条件；例如，它们可以返回一个负数来表示无法计算出正值。不同的数字可能表示不同的错误。调用这个函数的任何代码都必须明确检查错误条件并相应地采取行动。很多代码并没有这样做，程序就会崩溃。然而，在面向对象的世界中，情况并非如此。

在本章中，我们将学习**异常**，这些特殊的错误对象只有在有意义处理它们时才需要处理。特别是，我们将涵盖：

+   如何引发异常

+   当异常发生时如何恢复

+   如何以不同的方式处理不同类型的异常

+   当异常发生时进行清理

+   创建新类型的异常

+   使用异常语法进行流程控制

# 引发异常

原则上，异常只是一个对象。有许多不同的异常类可用，我们也可以轻松地定义更多自己的异常类。它们所有的共同之处就是它们都继承自一个内置类叫做`BaseException`。当这些异常对象在程序的控制流中被处理时，它们就变得特殊起来。当异常发生时，原本应该发生的一切都不会发生，除非在异常发生时本来就应该发生。有道理吗？别担心，你会明白的！

引发异常的最简单方法是做一些愚蠢的事情！你很可能已经这样做过，并看到了异常输出。例如，每当 Python 遇到你的程序中无法理解的一行时，它就会以`SyntaxError`退出，这是一种异常。这是一个常见的例子：

```py
>>> print "hello world"
 **File "<stdin>", line 1
 **print "hello world"
 **^
SyntaxError: invalid syntax

```

这个`print`语句在 Python 2 和之前的版本中是一个有效的命令，但在 Python 3 中，因为`print`现在是一个函数，我们必须用括号括起参数。所以，如果我们将前面的命令输入到 Python 3 解释器中，就会得到`SyntaxError`。

除了`SyntaxError`，还有一些其他常见的异常，我们可以处理，如下例所示：

```py
>>> x = 5 / 0
Traceback (most recent call last):
 **File "<stdin>", line 1, in <module>
ZeroDivisionError: int division or modulo by zero

>>> lst = [1,2,3]
>>> print(lst[3])
Traceback (most recent call last):
 **File "<stdin>", line 1, in <module>
IndexError: list index out of range

>>> lst + 2
Traceback (most recent call last):
 **File "<stdin>", line 1, in <module>
TypeError: can only concatenate list (not "int") to list

>>> lst.add
Traceback (most recent call last):
 **File "<stdin>", line 1, in <module>
AttributeError: 'list' object has no attribute 'add'

>>> d = {'a': 'hello'}
>>> d['b']
Traceback (most recent call last):
 **File "<stdin>", line 1, in <module>
KeyError: 'b'

>>> print(this_is_not_a_var)
Traceback (most recent call last):
 **File "<stdin>", line 1, in <module>
NameError: name 'this_is_not_a_var' is not defined

```

有时这些异常是我们程序中出了问题的指示器（在这种情况下，我们会去到指示的行号并修复它），但它们也会出现在合法的情况下。`ZeroDivisionError`并不总是意味着我们收到了无效的输入。它也可能意味着我们收到了不同的输入。用户可能误输入了零，或者故意输入了零，或者它可能代表一个合法的值，比如一个空的银行账户或一个新生儿的年龄。

你可能已经注意到所有前面的内置异常都以`Error`结尾。在 Python 中，`error`和`exception`这两个词几乎可以互换使用。错误有时被认为比异常更严重，但它们的处理方式完全相同。事实上，前面例子中的所有错误类都以`Exception`（它扩展自`BaseException`）作为它们的超类。

## 引发异常

我们将在一分钟内处理异常，但首先，让我们发现如果我们正在编写一个需要通知用户或调用函数输入某种无效的程序，我们应该做什么。如果我们能使用 Python 使用的相同机制，那不是很好吗？好吧，我们可以！这是一个简单的类，只有当它们是偶数的整数时才向列表添加项目：

```py
class EvenOnly(list):
    def append(self, integer):
        if not isinstance(integer, int):
            **raise TypeError("Only integers can be added")
        if integer % 2:
            **raise ValueError("Only even numbers can be added")
        super().append(integer)
```

这个类扩展了内置的`list`，就像我们在第二章中讨论的那样，*Python 中的对象*，并覆盖了`append`方法以检查两个条件，以确保项目是偶数。我们首先检查输入是否是`int`类型的实例，然后使用模运算符确保它可以被 2 整除。如果两个条件中的任何一个不满足，`raise`关键字会引发异常。`raise`关键字后面紧跟着作为异常引发的对象。在前面的例子中，两个对象是从内置类`TypeError`和`ValueError`新构造的。引发的对象也可以是我们自己创建的新异常类的实例（我们很快就会看到），在其他地方定义的异常，甚至是先前引发和处理的异常对象。如果我们在 Python 解释器中测试这个类，我们可以看到在异常发生时输出了有用的错误信息，就像以前一样：

```py
>>> e = EvenOnly()
>>> e.append("a string")
Traceback (most recent call last):
 **File "<stdin>", line 1, in <module>
 **File "even_integers.py", line 7, in add
 **raise TypeError("Only integers can be added")
TypeError: Only integers can be added

>>> e.append(3)
Traceback (most recent call last):
 **File "<stdin>", line 1, in <module>
 **File "even_integers.py", line 9, in add
 **raise ValueError("Only even numbers can be added")
ValueError: Only even numbers can be added
>>> e.append(2)

```

### 注意

虽然这个类对于演示异常很有效，但它并不擅长其工作。仍然可以使用索引表示法或切片表示法将其他值放入列表中。可以通过覆盖其他适当的方法来避免所有这些问题，其中一些是双下划线方法。

## 异常的影响

当引发异常时，似乎会立即停止程序执行。在引发异常后应该运行的任何行都不会被执行，除非处理异常，否则程序将以错误消息退出。看看这个简单的函数：

```py
def no_return():
    print("I am about to raise an exception")
    **raise Exception("This is always raised")
    print("This line will never execute")
    return "I won't be returned"
```

如果我们执行这个函数，我们会看到第一个`print`调用被执行，然后引发异常。第二个`print`语句从未执行，`return`语句也从未执行：

```py
>>> no_return()
I am about to raise an exception
Traceback (most recent call last):
 **File "<stdin>", line 1, in <module>
 **File "exception_quits.py", line 3, in no_return
 **raise Exception("This is always raised")
Exception: This is always raised

```

此外，如果我们有一个调用另一个引发异常的函数的函数，在第二个函数被调用的地方之后，第一个函数中的任何内容都不会被执行。引发异常会停止所有执行，直到函数调用堆栈，直到它被处理或迫使解释器退出。为了演示，让我们添加一个调用先前函数的第二个函数：

```py
def call_exceptor():
    print("call_exceptor starts here...")
    **no_return()
    print("an exception was raised...")
    print("...so these lines don't run")
```

当我们调用这个函数时，我们看到第一个`print`语句被执行，以及`no_return`函数中的第一行。但一旦引发异常，就不会执行其他任何内容：

```py
>>> call_exceptor()
call_exceptor starts here...
I am about to raise an exception
Traceback (most recent call last):
 **File "<stdin>", line 1, in <module>
 **File "method_calls_excepting.py", line 9, in call_exceptor
 **no_return()
 **File "method_calls_excepting.py", line 3, in no_return
 **raise Exception("This is always raised")
Exception: This is always raised

```

很快我们会看到，当解释器实际上没有采取捷径并立即退出时，我们可以在任一方法内部对异常做出反应并处理。事实上，异常可以在初始引发后的任何级别上处理。

从下到上查看异常的输出（称为回溯），注意两个方法是如何列出的。在`no_return`内部，异常最初被引发。然后，在其上方，我们看到在`call_exceptor`内部，那个讨厌的`no_return`函数被调用，异常上升到调用方法。从那里，它再上升一级到主解释器，不知道该怎么处理它，于是放弃并打印了回溯。

## 处理异常

现在让我们看看异常的另一面。如果我们遇到异常情况，我们的代码应该如何反应或从中恢复？我们通过在`try`...`except`子句中包装可能引发异常的任何代码（无论是异常代码本身，还是调用任何可能在其中引发异常的函数或方法）来处理异常。最基本的语法看起来像这样：

```py
try:
    no_return()
except:
    print("I caught an exception")
print("executed after the exception")
```

如果我们使用我们现有的`no_return`函数运行这个简单的脚本，我们知道它总是会引发异常，我们会得到这个输出：

```py
I am about to raise an exception
I caught an exception
executed after the exception
```

`no_return`函数愉快地通知我们它即将引发异常，但我们欺骗了它并捕获了异常。一旦捕获，我们就能够清理自己（在这种情况下，通过输出我们正在处理的情况），然后继续前进，而不受那个冒犯性的函数的干扰。`no_return`函数中剩余的代码仍未执行，但调用函数的代码能够恢复并继续。

请注意`try`和`except`周围的缩进。`try`子句包装可能引发异常的任何代码。然后，`except`子句与`try`行处于相同的缩进级别。在`except`子句之后缩进处理异常的任何代码。然后，正常的代码在原始缩进级别上恢复。

前面代码的问题是它会捕获任何类型的异常。如果我们编写的代码可能引发`TypeError`和`ZeroDivisionError`，我们可能想捕获`ZeroDivisionError`，但让`TypeError`传播到控制台。你能猜到语法是什么吗？

这是一个相当愚蠢的函数：

```py
def funny_division(divider):
    try:
        return 100 / divider
    **except ZeroDivisionError:
        return "Zero is not a good idea!"

print(funny_division(0))
print(funny_division(50.0))
print(funny_division("hello"))
```

该功能通过`print`语句进行测试，显示其行为符合预期：

```py
Zero is not a good idea!
2.0
Traceback (most recent call last):
 **File "catch_specific_exception.py", line 9, in <module>
 **print(funny_division("hello"))
 **File "catch_specific_exception.py", line 3, in funny_division
 **return 100 / anumber
TypeError: unsupported operand type(s) for /: 'int' and 'str'.

```

输出的第一行显示，如果我们输入`0`，我们会得到适当的模拟。如果我们使用有效的数字调用（请注意它不是整数，但仍然是有效的除数），它会正确运行。但是，如果我们输入一个字符串（你一直在想如何获得`TypeError`，对吧？），它会引发异常。如果我们使用一个没有指定`ZeroDivisionError`的空`except`子句，当我们发送一个字符串时，它会指责我们除以零，这根本不是正确的行为。

我们甚至可以捕获两个或更多不同的异常，并用相同的代码处理它们。以下是一个引发三种不同类型异常的示例。它使用相同的异常处理程序处理`TypeError`和`ZeroDivisionError`，但如果您提供数字`13`，它也可能引发`ValueError`：

```py
def funny_division2(anumber):
    try:
        if anumber == 13:
            raise ValueError("13 is an unlucky number")
        return 100 / anumber
    **except (ZeroDivisionError, TypeError):
        return "Enter a number other than zero"

for val in (0, "hello", 50.0, 13):

    print("Testing {}:".format(val), end=" ")
    print(funny_division2(val))
```

底部的`for`循环循环遍历了几个测试输入并打印了结果。如果你对`print`语句中的`end`参数感到困惑，它只是将默认的尾随换行符转换为空格，以便与下一行的输出连接在一起。以下是程序的运行：

```py
Testing 0: Enter a number other than zero
Testing hello: Enter a number other than zero
Testing 50.0: 2.0
Testing 13: Traceback (most recent call last):
 **File "catch_multiple_exceptions.py", line 11, in <module>
 **print(funny_division2(val))
 **File "catch_multiple_exceptions.py", line 4, in funny_division2
 **raise ValueError("13 is an unlucky number")
ValueError: 13 is an unlucky number

```

数字`0`和字符串都被`except`子句捕获，并打印出合适的错误消息。数字`13`的异常没有被捕获，因为它是一个`ValueError`，而这种类型的异常没有被处理。这一切都很好，但是如果我们想捕获不同的异常并对它们采取不同的处理怎么办？或者也许我们想对异常进行处理，然后允许它继续向上层函数传播，就好像它从未被捕获过一样？对于这些情况，我们不需要任何新的语法。可以堆叠`except`子句，只有第一个匹配的子句会被执行。对于第二个问题，`raise`关键字，不带参数，将重新引发最后一个异常，如果我们已经在异常处理程序中。观察以下代码：

```py
def funny_division3(anumber):
    try:
        if anumber == 13:
            raise ValueError("13 is an unlucky number")
        return 100 / anumber
    **except ZeroDivisionError:
        return "Enter a number other than zero"
    **except TypeError:
        return "Enter a numerical value"
    **except ValueError:
        print("No, No, not 13!")
        **raise

```

最后一行重新引发了`ValueError`，因此在输出`No, No, not 13!`后，它将再次引发异常；我们仍然会在控制台上获得原始的堆栈跟踪。

如果我们像前面的例子中那样堆叠异常子句，只有第一个匹配的子句会被执行，即使有多个子句符合条件。多个子句如何匹配呢？请记住，异常是对象，因此可以被子类化。正如我们将在下一节中看到的，大多数异常都扩展了`Exception`类（它本身是从`BaseException`派生的）。如果我们在捕获`TypeError`之前捕获`Exception`，那么只有`Exception`处理程序会被执行，因为`TypeError`是通过继承成为`Exception`的。

这在某些情况下非常有用，例如我们想要专门处理一些异常，然后将所有剩余的异常作为更一般的情况处理。在捕获所有特定异常后，我们只需捕获`Exception`并在那里处理一般情况。

有时，当我们捕获异常时，我们需要引用`Exception`对象本身。这最常发生在我们使用自定义参数定义自己的异常时，但也可能与标准异常相关。大多数异常类在其构造函数中接受一组参数，我们可能希望在异常处理程序中访问这些属性。如果我们定义自己的异常类，甚至可以在捕获时调用自定义方法。捕获异常作为变量的语法使用`as`关键字：

```py
try:
    raise ValueError("This is an argument")
except ValueError as e:
    print("The exception arguments were", e.args)
```

如果我们运行这个简单的片段，它会打印出我们在初始化`ValueError`时传递的字符串参数。

我们已经看到了处理异常的语法的几种变体，但我们仍然不知道如何执行代码，无论是否发生异常。我们也无法指定只有在没有发生异常时才执行的代码。另外两个关键字`finally`和`else`可以提供缺失的部分。两者都不需要额外的参数。以下示例随机选择一个要抛出的异常并引发它。然后运行一些不那么复杂的异常处理代码，演示了新引入的语法：

```py
import random
some_exceptions = [ValueError, TypeError, IndexError, None]

try:
    choice = random.choice(some_exceptions)
    print("raising {}".format(choice))
    if choice:
        raise choice("An error")
except ValueError:
    print("Caught a ValueError")
except TypeError:
    print("Caught a TypeError")
except Exception as e:
    print("Caught some other error: %s" %
        ( e.__class__.__name__))
else:
    print("This code called if there is no exception")
finally:
    print("This cleanup code is always called")
```

如果我们运行这个例子——它几乎涵盖了每种可能的异常处理场景——几次，每次都会得到不同的输出，这取决于`random`选择的异常。以下是一些示例运行：

```py
$ python finally_and_else.py
raising None
This code called if there is no exception
This cleanup code is always called

$ python finally_and_else.py
raising <class 'TypeError'>
Caught a TypeError
This cleanup code is always called

$ python finally_and_else.py
raising <class 'IndexError'>
Caught some other error: IndexError
This cleanup code is always called

$ python finally_and_else.py
raising <class 'ValueError'>
Caught a ValueError
This cleanup code is always called

```

请注意`finally`子句中的`print`语句无论发生什么都会被执行。当我们需要在代码运行结束后执行某些任务时（即使发生异常），这是非常有用的。一些常见的例子包括：

+   清理一个打开的数据库连接

+   关闭一个打开的文件

+   通过网络发送关闭握手

当我们在`try`子句内部执行`return`语句时，`finally`子句也非常重要。在返回值之前，`finally`处理程序仍将被执行。

还要注意当没有引发异常时的输出：`else`和`finally`子句都会被执行。`else`子句可能看起来多余，因为只有在没有引发异常时才应执行的代码可以直接放在整个`try`...`except`块之后。不同之处在于，如果捕获并处理了异常，`else`块仍将被执行。我们稍后在讨论使用异常作为流程控制时会更多地了解这一点。

在`try`块之后可以省略任何`except`、`else`和`finally`子句（尽管单独使用`else`是无效的）。如果包含多个子句，则`except`子句必须首先出现，然后是`else`子句，最后是`finally`子句。`except`子句的顺序通常从最具体到最一般。

## 异常层次结构

我们已经看到了几个最常见的内置异常，你可能会在你的常规 Python 开发过程中遇到其余的异常。正如我们之前注意到的，大多数异常都是`Exception`类的子类。但并非所有异常都是如此。`Exception`本身实际上是从一个叫做`BaseException`的类继承而来的。事实上，所有异常都必须扩展`BaseException`类或其子类之一。

有两个关键异常，`SystemExit`和`KeyboardInterrupt`，它们直接从`BaseException`而不是`Exception`派生。`SystemExit`异常在程序自然退出时引发，通常是因为我们在代码中的某个地方调用了`sys.exit`函数（例如，当用户选择退出菜单项，单击窗口上的“关闭”按钮，或输入命令关闭服务器时）。该异常旨在允许我们在程序最终退出之前清理代码，因此我们通常不需要显式处理它（因为清理代码发生在`finally`子句内）。

如果我们处理它，通常会重新引发异常，因为捕获它会阻止程序退出。当然，也有一些情况，我们可能希望阻止程序退出，例如，如果存在未保存的更改，我们希望提示用户是否真的要退出。通常，如果我们处理`SystemExit`，那是因为我们想对其进行特殊处理，或者直接预期它。我们特别不希望它在捕获所有正常异常的通用子句中被意外捕获。这就是为什么它直接从`BaseException`派生出来的原因。

`KeyboardInterrupt`异常在命令行程序中很常见。当用户使用依赖于操作系统的组合键（通常是*Ctrl* + *C*）明确中断程序执行时，它会被抛出。这是用户有意中断运行中程序的标准方式，与`SystemExit`一样，它几乎总是应该通过终止程序来响应。此外，与`SystemExit`一样，它应该在`finally`块内处理任何清理任务。

这是一个完全说明异常层次结构的类图：

![异常层次结构](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py3-oop-2e/img/8781OS_04_01.jpg)

当我们使用`except：`子句而没有指定任何类型的异常时，它将捕获`BaseException`的所有子类；也就是说，它将捕获所有异常，包括这两个特殊的异常。由于我们几乎总是希望这些得到特殊处理，因此不明智地使用没有参数的`except：`语句。如果要捕获除`SystemExit`和`KeyboardInterrupt`之外的所有异常，请明确捕获`Exception`。

此外，如果您确实想捕获所有异常，我建议使用语法`except BaseException：`而不是原始的`except：`。这有助于明确告诉您代码的未来读者，您有意处理特殊情况异常。

## 定义我们自己的异常

通常，当我们想要引发异常时，我们会发现没有内置的异常适合。幸运的是，我们可以轻松地定义自己的新异常。类的名称通常设计为传达出了什么问题，我们可以在初始化程序中提供任意参数以包含额外信息。

我们所要做的就是从`Exception`类继承。我们甚至不必向类添加任何内容！当然，我们可以直接扩展`BaseException`，但那样它将不会被通用的`except Exception`子句捕获。

这是我们可能在银行应用程序中使用的一个简单异常：

```py
class InvalidWithdrawal(Exception):
    pass

raise InvalidWithdrawal("You don't have $50 in your account")
```

最后一行说明了如何引发新定义的异常。我们能够将任意数量的参数传递到异常中。通常使用字符串消息，但可以存储任何在以后的异常处理程序中可能有用的对象。`Exception.__init__`方法设计为接受任何参数并将它们存储为名为`args`的属性中的元组。这使得异常更容易定义，而无需覆盖`__init__`。

当然，如果我们确实想要自定义初始化程序，我们可以自由地这样做。这是一个初始化程序接受当前余额和用户想要提取的金额的异常。此外，它添加了一个方法来计算请求超支了多少：

```py
class InvalidWithdrawal(Exception):
    **def __init__(self, balance, amount):
        **super().__init__("account doesn't have ${}".format(
            **amount))
        self.amount = amount
        self.balance = balance

    def overage(self):
        return self.amount - self.balance

raise InvalidWithdrawal(25, 50)

```

结尾处的`raise`语句说明了如何构造这个异常。正如你所看到的，我们可以对异常做任何其他对象可以做的事情。我们可以捕获异常并将其作为一个工作对象传递，尽管通常将工作对象的引用作为异常的属性包含在异常中，然后传递它。

如果出现`InvalidWithdrawal`异常，我们会这样处理：

```py
try:
    raise InvalidWithdrawal(25, 50)
except InvalidWithdrawal as e:
    print("I'm sorry, but your withdrawal is "
            "more than your balance by "
            "${}".format(e.overage()))
```

在这里，我们看到了`as`关键字的有效使用。按照惯例，大多数 Python 程序员将异常变量命名为`e`，尽管通常情况下，你可以自由地将其命名为`ex`、`exception`或者`aunt_sally`。

定义自己的异常有很多原因。通常情况下，向异常中添加信息或以某种方式记录异常是很有用的。但是，自定义异常的实用性真正体现在创建面向其他程序员访问的框架、库或 API 时。在这种情况下，要小心确保你的代码引发的异常对客户程序员是有意义的。它们应该易于处理，并清楚地描述发生了什么。客户程序员应该很容易看到如何修复错误（如果它反映了他们代码中的错误）或处理异常（如果这是他们需要知道的情况）。

异常并不是异常的。新手程序员倾向于认为异常只对异常情况有用。然而，异常情况的定义可能模糊不清，需要根据具体情况解释。考虑以下两个函数：

```py
def divide_with_exception(number, divisor):
    try:
        print("{} / {} = {}".format(
            number, divisor, number / divisor * 1.0))
    except ZeroDivisionError:
        print("You can't divide by zero")

def divide_with_if(number, divisor):
    if divisor == 0:
        print("You can't divide by zero")
    else:
        print("{} / {} = {}".format(
            number, divisor, number / divisor * 1.0))
```

这两个函数的行为是一样的。如果`divisor`是零，会打印一个错误消息；否则，会显示一个打印除法结果的消息。我们可以通过使用`if`语句来避免`ZeroDivisionError`被抛出。同样地，我们可以通过明确检查参数是否在列表范围内来避免`IndexError`，并且通过检查键是否在字典中来避免`KeyError`。

但我们不应该这样做。首先，我们可能会编写一个`if`语句，检查索引是否低于列表的参数，但忘记检查负值。

### 注意

记住，Python 列表支持负索引；`-1`指的是列表中的最后一个元素。

最终，我们会发现这一点，并且必须找到我们检查代码的所有地方。但如果我们简单地捕获了`IndexError`并处理它，我们的代码就能正常工作。

Python 程序员倾向于遵循“宁可请求原谅，而不是事先获得许可”的模式，也就是说，他们执行代码，然后处理任何出现的问题。相反，事先检查再执行的方法通常是不被赞同的。这样做的原因有几个，但主要原因是不应该需要消耗 CPU 周期来寻找在正常代码路径中不会出现的异常情况。因此，明智的做法是将异常用于异常情况，即使这些情况只是稍微异常。进一步地，我们实际上可以看到异常语法也对流程控制是有效的。与`if`语句一样，异常可以用于决策、分支和消息传递。

想象一个销售小部件和小工具的公司的库存应用程序。当客户购买时，商品可以是有货的，这种情况下商品将从库存中移除并返回剩余商品数量，或者可能是缺货。现在，缺货在库存应用程序中是一个完全正常的事情。这绝对不是一个特殊情况。但如果缺货了，我们应该返回什么呢？一个说缺货的字符串？一个负数？在这两种情况下，调用方法都必须检查返回值是正整数还是其他值，以确定是否缺货。这看起来有点混乱。相反，我们可以引发`OutOfStockException`并使用`try`语句来控制程序流程。有道理吗？此外，我们还要确保不会将同一商品卖给两个不同的客户，或者出售尚未备货的商品。促进这一点的一种方法是锁定每种商品，以确保只有一个人可以同时更新它。用户必须锁定商品，操作商品（购买、补充库存、计算剩余商品数量...），然后解锁商品。以下是一个带有描述部分方法应该做什么的文档字符串的不完整的`Inventory`示例：

```py
class Inventory:
    def lock(self, item_type):
        '''Select the type of item that is going to
        be manipulated. This method will lock the
        item so nobody else can manipulate the
        inventory until it's returned. This prevents
        selling the same item to two different
        customers.'''
        pass

    def unlock(self, item_type):
        '''Release the given type so that other
        customers can access it.'''
        pass

    def purchase(self, item_type):
        '''If the item is not locked, raise an
        exception. If the item_type  does not exist,
        raise an exception. If the item is currently
        out of stock, raise an exception. If the item
        is available, subtract one item and return
        the number of items left.'''
        pass
```

我们可以将这个对象原型交给开发人员，让他们实现方法，以确保它们按照预期工作，而我们则可以在需要进行购买的代码上进行工作。我们将使用 Python 强大的异常处理来考虑不同的分支，具体取决于购买方式：

```py
item_type = 'widget'
inv = Inventory()
inv.lock(item_type)
try:
    num_left = inv.purchase(item_type)
except InvalidItemType:
    print("Sorry, we don't sell {}".format(item_type))
except OutOfStock:
    print("Sorry, that item is out of stock.")
else:
    print("Purchase complete. There are "
            "{} {}s left".format(num_left, item_type))
finally:
    inv.unlock(item_type)
```

注意所有可能的异常处理子句是如何被用来确保在正确的时间发生正确的操作。即使`OutOfStock`并不是一个非常特殊的情况，我们仍然可以使用异常来适当处理它。这段代码也可以用`if`...`elif`...`else`结构来编写，但这样不容易阅读或维护。

我们还可以使用异常来在不同的方法之间传递消息。例如，如果我们想要告知客户商品预计何时会再次备货，我们可以确保我们的`OutOfStock`对象在构造时需要一个`back_in_stock`参数。然后，当我们处理异常时，我们可以检查该值并向客户提供额外信息。附加到对象的信息可以很容易地在程序的两个不同部分之间传递。异常甚至可以提供一个方法，指示库存对象重新订购或预订商品。

使用异常来控制流程可以设计出一些方便的程序。从这次讨论中重要的是要明白异常并不是我们应该尽量避免的坏事。发生异常并不意味着你应该阻止这种特殊情况的发生。相反，这只是一种在两个可能不直接调用彼此的代码部分之间传递信息的强大方式。

# 案例研究

我们一直在以相当低的细节水平来看待异常的使用和处理——语法和定义。这个案例研究将帮助我们将它与之前的章节联系起来，这样我们就可以看到异常在对象、继承和模块的更大背景下是如何使用的。

今天，我们将设计一个简单的中央认证和授权系统。整个系统将放置在一个模块中，其他代码将能够查询该模块对象以进行认证和授权。我们应该承认，从一开始，我们并不是安全专家，我们设计的系统可能存在安全漏洞。我们的目的是研究异常，而不是保护系统。然而，对于其他代码可以与之交互的基本登录和权限系统来说，这是足够的。稍后，如果其他代码需要更安全，我们可以让安全或密码专家审查或重写我们的模块，最好不改变 API。

认证是确保用户确实是他们所说的人的过程。我们将遵循当今常见的网络系统的做法，使用用户名和私人密码组合。其他的认证方法包括语音识别、指纹或视网膜扫描仪以及身份证。

另一方面，授权是确定给定（经过认证的）用户是否被允许执行特定操作的全部内容。我们将创建一个基本的权限列表系统，用于存储允许执行每个操作的特定人员的列表。

此外，我们将添加一些管理功能，以允许新用户被添加到系统中。为简洁起见，我们将略去添加密码或在添加后更改权限的编辑，但这些（非常必要的）功能当然可以在将来添加。

这是一个简单的分析；现在让我们继续设计。显然，我们需要一个`User`类来存储用户名和加密密码。这个类还将允许用户通过检查提供的密码是否有效来登录。我们可能不需要一个`Permission`类，因为可以将它们作为字符串映射到使用字典的用户列表中。我们应该有一个中央的`Authenticator`类，用于处理用户管理和登录或注销。谜题的最后一块是一个`Authorizor`类，用于处理权限和检查用户是否可以执行某项活动。我们将在`auth`模块中提供这些类的单个实例，以便其他模块可以使用这个中央机制来满足其所有的认证和授权需求。当然，如果他们想要为非中央授权活动实例化私有实例，他们是可以自由这样做的。

随着我们的进行，我们还将定义几个异常。我们将从一个特殊的`AuthException`基类开始，它接受`username`和可选的`user`对象作为参数；我们大部分自定义的异常都将继承自这个基类。

让我们首先构建`User`类；这似乎足够简单。一个新用户可以用用户名和密码初始化。密码将被加密存储，以减少被盗的可能性。我们还需要一个`check_password`方法来测试提供的密码是否正确。以下是完整的类：

```py
import hashlib

class User:
    def __init__(self, username, password):
        '''Create a new user object. The password
        will be encrypted before storing.'''
        self.username = username
        self.password = self._encrypt_pw(password)
        self.is_logged_in = False

    def _encrypt_pw(self, password):
        '''Encrypt the password with the username and return
        the sha digest.'''
        hash_string = (self.username + password)
        hash_string = hash_string.encode("utf8")
        return hashlib.sha256(hash_string).hexdigest()

    def check_password(self, password):
        '''Return True if the password is valid for this
        user, false otherwise.'''
        encrypted = self._encrypt_pw(password)
        return encrypted == self.password
```

由于加密密码的代码在`__init__`和`check_password`中都需要，我们将其提取到自己的方法中。这样，如果有人意识到它不安全并需要改进，它只需要在一个地方进行更改。这个类可以很容易地扩展到包括强制或可选的个人详细信息，比如姓名、联系信息和出生日期。

在我们编写代码添加用户之前（这将发生在尚未定义的`Authenticator`类中），我们应该检查一些用例。如果一切顺利，我们可以添加一个带有用户名和密码的用户；`User`对象被创建并插入到字典中。但是，有哪些情况可能不顺利呢？显然，我们不希望添加一个已经存在于字典中的用户名的用户。如果这样做，我们将覆盖现有用户的数据，新用户可能会访问该用户的权限。因此，我们需要一个`UsernameAlreadyExists`异常。另外，出于安全考虑，如果密码太短，我们也应该引发异常。这两个异常都将扩展`AuthException`，这是我们之前提到的。因此，在编写`Authenticator`类之前，让我们定义这三个异常类：

```py
class AuthException(Exception):
    def __init__(self, username, user=None):
        super().__init__(username, user)
        self.username = username
        self.user = user

class UsernameAlreadyExists(AuthException):
    pass

class PasswordTooShort(AuthException):
    pass
```

`AuthException`需要一个用户名，并具有一个可选的用户参数。第二个参数应该是与该用户名关联的`User`类的实例。我们正在定义的这两个具体异常只需要通知调用类发生异常情况，因此我们不需要为它们添加任何额外的方法。

现在让我们开始`Authenticator`类。它可以简单地将用户名映射到用户对象，因此我们将从初始化函数中的字典开始。添加用户的方法需要在创建新的`User`实例并将其添加到字典之前检查两个条件（密码长度和先前存在的用户）：

```py
class Authenticator:
    def __init__(self):
        '''Construct an authenticator to manage
        users logging in and out.'''
        self.users = {}

    def add_user(self, username, password):
        if username in self.users:
            **raise UsernameAlreadyExists(username)
        if len(password) < 6:
            **raise PasswordTooShort(username)
        **self.users[username] = User(username, password)

```

当然，如果需要，我们可以扩展密码验证以引发其他方式太容易破解的密码的异常。现在让我们准备`login`方法。如果我们刚才没有考虑异常，我们可能只希望该方法根据登录是否成功返回`True`或`False`。但我们正在考虑异常，这可能是一个不太异常的情况使用它们的好地方。我们可以引发不同的异常，例如，如果用户名不存在或密码不匹配。这将允许尝试登录用户的任何人使用`try`/`except`/`else`子句优雅地处理情况。因此，首先我们添加这些新异常：

```py
class InvalidUsername(AuthException):
    pass

class InvalidPassword(AuthException):
    pass
```

然后我们可以为我们的`Authenticator`类定义一个简单的`login`方法，如果有必要，引发这些异常。如果不需要，它会标记`user`已登录并返回：

```py
    def login(self, username, password):
        try:
            user = self.users[username]
        **except KeyError:
            **raise InvalidUsername(username)

        if not user.check_password(password):
            **raise InvalidPassword(username, user)

        user.is_logged_in = True
        return True
```

注意`KeyError`是如何处理的。这可以使用`if username not in self.users:`来处理，但我们选择直接处理异常。我们最终吞掉了这个第一个异常，并引发了一个更适合用户界面 API 的全新异常。

我们还可以添加一个方法来检查特定用户名是否已登录。在这里决定是否使用异常更加棘手。如果用户名不存在，我们应该引发异常吗？如果用户没有登录，我们应该引发异常吗？

要回答这些问题，我们需要考虑方法如何被访问。最常见的情况是，这个方法将用于回答“我应该允许他们访问*<something>*吗？”这个问题的答案要么是“是的，用户名有效并且他们已登录”，要么是“不，用户名无效或者他们未登录”。因此，布尔返回值就足够了。在这里没有必要使用异常，只是为了使用异常。

```py
    def is_logged_in(self, username):
        if username in self.users:
            return self.users[username].is_logged_in
        return False
```

最后，我们可以向我们的模块添加一个默认的认证器实例，以便客户端代码可以轻松地使用`auth.authenticator`进行访问：

```py
authenticator = Authenticator()
```

这行代码放在模块级别，不在任何类定义之外，因此可以将 auth.authenticator 作为`auth.authenticator`进行访问。现在我们可以开始`Authorizor`类，它将权限映射到用户。`Authorizor`类不应允许用户访问权限，如果他们没有登录，因此他们将需要引用特定的认证器。我们还需要在初始化时设置权限字典：

```py
class Authorizor:
    def __init__(self, authenticator):
        self.authenticator = authenticator
        self.permissions = {}
```

现在我们可以编写方法来添加新的权限，并设置哪些用户与每个权限相关联：

```py
    def add_permission(self, perm_name):
        '''Create a new permission that users
        can be added to'''
        try:
            perm_set = self.permissions[perm_name]
        except KeyError:
            self.permissions[perm_name] = set()
        else:
            raise PermissionError("Permission Exists")

    def permit_user(self, perm_name, username):
        '''Grant the given permission to the user'''
        try:
            perm_set = self.permissions[perm_name]
        except KeyError:
            raise PermissionError("Permission does not exist")
        else:
            if username not in self.authenticator.users:
                raise InvalidUsername(username)
            perm_set.add(username)
```

第一个方法允许我们创建新的权限，除非它已经存在，否则会引发异常。第二个方法允许我们将用户名添加到权限中，除非权限或用户名尚不存在。

我们使用`set`而不是`list`来存储用户名，这样即使您多次授予用户权限，集合的性质意味着用户只会出现一次。我们将在后面的章节中进一步讨论集合。

这两种方法都会引发`PermissionError`。这个新错误不需要用户名，所以我们将它直接扩展为`Exception`，而不是我们自定义的`AuthException`：

```py
class PermissionError(Exception):
    pass
```

最后，我们可以添加一个方法来检查用户是否具有特定的`permission`。为了获得访问权限，他们必须同时登录到认证器并且在被授予该特权的人员集合中。如果这些条件中的任何一个不满足，就会引发异常：

```py
    def check_permission(self, perm_name, username):
        if not self.authenticator.is_logged_in(username):
            raise NotLoggedInError(username)
        try:
            perm_set = self.permissions[perm_name]
        except KeyError:
            raise PermissionError("Permission does not exist")
        else:
            if username not in perm_set:
                raise NotPermittedError(username)
            else:
                return True
```

这里有两个新的异常；它们都使用用户名，所以我们将它们定义为`AuthException`的子类：

```py
class NotLoggedInError(AuthException):
    pass

class NotPermittedError(AuthException):
    pass
```

最后，我们可以添加一个默认的`authorizor`来配合我们的默认验证器：

```py
authorizor = Authorizor(authenticator)
```

这完成了一个基本的身份验证/授权系统。我们可以在 Python 提示符下测试系统，检查用户`joe`是否被允许在油漆部门执行任务：

```py
>>> import auth
>>> auth.authenticator.add_user("joe", "joepassword")
>>> auth.authorizor.add_permission("paint")
>>> auth.authorizor.check_permission("paint", "joe")
Traceback (most recent call last):
 **File "<stdin>", line 1, in <module>
 **File "auth.py", line 109, in check_permission
 **raise NotLoggedInError(username)
auth.NotLoggedInError: joe
>>> auth.authenticator.is_logged_in("joe")
False
>>> auth.authenticator.login("joe", "joepassword")
True
>>> auth.authorizor.check_permission("paint", "joe")
Traceback (most recent call last):
 **File "<stdin>", line 1, in <module>
 **File "auth.py", line 116, in check_permission
 **raise NotPermittedError(username)
auth.NotPermittedError: joe
>>> auth.authorizor.check_permission("mix", "joe")
Traceback (most recent call last):
 **File "auth.py", line 111, in check_permission
 **perm_set = self.permissions[perm_name]
KeyError: 'mix'

During handling of the above exception, another exception occurred:
Traceback (most recent call last):
 **File "<stdin>", line 1, in <module>
 **File "auth.py", line 113, in check_permission
 **raise PermissionError("Permission does not exist")
auth.PermissionError: Permission does not exist
>>> auth.authorizor.permit_user("mix", "joe")
Traceback (most recent call last):
 **File "auth.py", line 99, in permit_user
 **perm_set = self.permissions[perm_name]
KeyError: 'mix'

During handling of the above exception, another exception occurred:

Traceback (most recent call last):
 **File "<stdin>", line 1, in <module>
 **File "auth.py", line 101, in permit_user
 **raise PermissionError("Permission does not exist")
auth.PermissionError: Permission does not exist
>>> auth.authorizor.permit_user("paint", "joe")
>>> auth.authorizor.check_permission("paint", "joe")
True

```

虽然冗长，但前面的输出显示了我们所有的代码和大部分异常的运行情况，但要真正理解我们定义的 API，我们应该编写一些实际使用它的异常处理代码。这是一个基本的菜单界面，允许某些用户更改或测试程序：

```py
import auth

# Set up a test user and permission
auth.authenticator.add_user("joe", "joepassword")
auth.authorizor.add_permission("test program")
auth.authorizor.add_permission("change program")
auth.authorizor.permit_user("test program", "joe")

class Editor:
    def __init__(self):
        self.username = None
        self.menu_map = {
                "login": self.login,
                "test": self.test,
                "change": self.change,
                "quit": self.quit
           }

    def login(self):
        logged_in = False
        while not logged_in:
            username = input("username: ")
            password = input("password: ")
            try:
                logged_in = auth.authenticator.login(
                        username, password)
            except auth.InvalidUsername:
                print("Sorry, that username does not exist")
            except auth.InvalidPassword:
                print("Sorry, incorrect password")
            else:
                self.username = username
    def is_permitted(self, permission):
        try:
            auth.authorizor.check_permission(
                permission, self.username)
        except auth.NotLoggedInError as e:
            print("{} is not logged in".format(e.username))
            return False
        except auth.NotPermittedError as e:
            print("{} cannot {}".format(
                e.username, permission))
            return False
        else:
            return True

    def test(self):
        if self.is_permitted("test program"):
            print("Testing program now...")

    def change(self):
        if self.is_permitted("change program"):
            print("Changing program now...")

    def quit(self):
        raise SystemExit()

    def menu(self):
        try:
            answer = ""
            while True:
                print("""
Please enter a command:
\tlogin\tLogin
\ttest\tTest the program
\tchange\tChange the program
\tquit\tQuit
""")
                answer = input("enter a command: ").lower()
                try:
                    func = self.menu_map[answer]
                except KeyError:
                    print("{} is not a valid option".format(
                        answer))
                else:
                    func()
        finally:
            print("Thank you for testing the auth module")

Editor().menu()
```

这个相当长的例子在概念上非常简单。`is_permitted`方法可能是最有趣的；这是一个大部分是内部方法，由`test`和`change`调用，以确保用户在继续之前被允许访问。当然，这两种方法都是存根，但我们这里不是在编写编辑器；我们是通过测试身份验证和授权框架来说明异常和异常处理程序的使用！

# 练习

如果您以前从未处理过异常，首先要做的是查看您编写的任何旧 Python 代码，并注意是否有应该处理异常的地方。您会如何处理它们？您是否需要处理它们？有时，让异常传播到控制台是向用户传达信息的最佳方式，特别是如果用户也是脚本的编码者。有时，您可以从错误中恢复并允许程序继续。有时，您只能将错误重新格式化为用户可以理解的内容，并向他们显示。

一些常见的查找地方包括文件 I/O（您的代码是否可能尝试读取不存在的文件？）、数学表达式（您要除以的值是否可能为零？）、列表索引（列表是否为空？）和字典（键是否存在？）。问问自己是否应该忽略问题，通过先检查值来处理它，还是通过异常来处理它。特别注意可能使用`finally`和`else`的地方，以确保在所有条件下执行正确的代码。

现在写一些新代码。想想一个需要身份验证和授权的程序，并尝试编写一些使用我们在案例研究中构建的`auth`模块的代码。如果模块不够灵活，可以随意修改模块。尝试以明智的方式处理所有异常。如果您在想出需要身份验证的内容方面遇到困难，可以尝试在第二章中的记事本示例中添加授权，或者在`auth`模块本身中添加授权-如果任何人都可以开始添加权限，那么这个模块就不是一个非常有用的模块！也许在允许添加或更改权限之前，需要管理员用户名和密码。

最后，尝试考虑代码中可能引发异常的地方。可以是您编写或正在处理的代码；或者您可以编写一个新项目作为练习。您可能最容易设计一个小型框架或 API，供其他人使用；异常是您的代码和其他人之间的绝妙沟通工具。请记住，设计和记录任何自行引发的异常作为 API 的一部分，否则他们将不知道如何处理这些异常！

# 总结

在本章中，我们深入讨论了引发、处理、定义和操作异常的细节。异常是一种强大的方式，可以在不要求调用函数显式检查返回值的情况下传达异常情况或错误条件。有许多内置异常，引发它们非常容易。处理不同异常事件的语法有几种不同的形式。

在下一章中，我们将讨论到目前为止所学的一切，以及如何在 Python 应用程序中最好地应用面向对象编程原则和结构。


# 第五章：何时使用面向对象编程

在前几章中，我们已经涵盖了面向对象编程的许多定义特性。我们现在知道了面向对象设计的原则和范例，并且我们已经涵盖了 Python 中面向对象编程的语法。

然而，我们并不知道如何以及何时在实践中利用这些原则和语法。在本章中，我们将讨论我们所获得的知识的一些有用应用，并在此过程中学习一些新的主题：

+   如何识别对象

+   数据和行为，再次

+   使用属性将数据包装在行为中

+   使用行为限制数据

+   不要重复自己的原则

+   识别重复的代码

# 将对象视为对象

这可能看起来很明显；你通常应该在你的代码中为问题域中的单独对象提供一个特殊的类。我们在前几章的案例研究中看到了这样的例子；首先，我们确定问题中的对象，然后对其数据和行为进行建模。

在面向对象分析和编程中，识别对象是一项非常重要的任务。但这并不总是像我们一直在做的那样简单，只需数一下短段落中的名词。记住，对象是既有数据又有行为的东西。如果我们只处理数据，通常最好将其存储在列表、集合、字典或其他 Python 数据结构中（我们将在第六章中全面介绍）。另一方面，如果我们只处理行为，而没有存储数据，一个简单的函数更合适。

然而，对象既有数据又有行为。熟练的 Python 程序员使用内置数据结构，除非（或直到）明显需要定义一个类。如果它不帮助组织我们的代码，就没有理由添加额外的抽象层。另一方面，“明显”的需求并不总是不言自明的。

我们经常可以通过将数据存储在几个变量中来启动我们的 Python 程序。随着程序的扩展，我们将会发现我们正在将相同的一组相关变量传递给一组函数。这是思考将变量和函数分组到一个类中的时候。如果我们设计一个在二维空间中模拟多边形的程序，我们可能会从每个多边形被表示为点列表开始。点将被建模为描述该点位置的两元组（*x*，*y*）。这是所有数据，存储在一组嵌套的数据结构中（具体来说，是一个元组列表）：

```py
square = [(1,1), (1,2), (2,2), (2,1)]
```

现在，如果我们想要计算多边形周长的距离，我们只需要计算两点之间的距离。为此，我们还需要一个函数来计算两点之间的距离。以下是两个这样的函数：

```py
import math

def distance(p1, p2):
    return math.sqrt((p1[0]-p2[0])**2 + (p1[1]-p2[1])**2)

def perimeter(polygon):
    perimeter = 0
    points = polygon + [polygon[0]]
    for i in range(len(polygon)):
        perimeter += distance(points[i], points[i+1])
    return perimeter
```

现在，作为面向对象的程序员，我们清楚地意识到`polygon`类可以封装点列表（数据）和`perimeter`函数（行为）。此外，`point`类，就像我们在第二章中定义的那样，*Python 中的对象*，可以封装`x`和`y`坐标以及`distance`方法。问题是：这样做有价值吗？

对于以前的代码，也许是，也许不是。有了我们最近在面向对象原则方面的经验，我们可以以创纪录的速度编写一个面向对象的版本。让我们比较一下它们

```py
import math

class Point:
 **def __init__(self, x, y):
 **self.x = x
 **self.y = y

    def distance(self, p2):
        return math.sqrt((self.x-p2.x)**2 + (self.y-p2.y)**2)

class Polygon:
 **def __init__(self):
 **self.vertices = []

 **def add_point(self, point):
 **self.vertices.append((point))

    def perimeter(self):
        perimeter = 0
        points = self.vertices + [self.vertices[0]]
        for i in range(len(self.vertices)):
            perimeter += points[i].distance(points[i+1])
        return perimeter
```

正如我们从突出显示的部分所看到的，这里的代码量是我们之前版本的两倍，尽管我们可以争辩说`add_point`方法并不是严格必要的。

现在，为了更好地理解这两个 API 的区别，让我们比较一下两种使用情况。这是如何使用面向对象的代码来计算正方形的周长：

```py
>>> square = Polygon()
>>> square.add_point(Point(1,1))
>>> square.add_point(Point(1,2))
>>> square.add_point(Point(2,2))
>>> square.add_point(Point(2,1))
>>> square.perimeter()
4.0

```

你可能会认为这相当简洁易读，但让我们将其与基于函数的代码进行比较：

```py
>>> square = [(1,1), (1,2), (2,2), (2,1)]
>>> perimeter(square)
4.0

```

嗯，也许面向对象的 API 并不那么紧凑！也就是说，我认为它比函数示例更容易*阅读*：在第二个版本中，我们怎么知道元组列表应该表示什么？我们怎么记得我们应该传递什么样的对象（一个包含两个元组的列表？这不直观！）到`perimeter`函数中？我们需要大量的文档来解释这些函数应该如何使用。

相比之下，面向对象的代码相对自我说明，我们只需要查看方法列表及其参数就能知道对象的功能和如何使用它。当我们为函数版本编写所有文档时，它可能会比面向对象的代码更长。

最后，代码长度并不是代码复杂性的良好指标。一些程序员会陷入复杂的“一行代码”中，这一行代码可以完成大量工作。这可能是一个有趣的练习，但结果通常是难以阅读的，即使对于原始作者来说，第二天也是如此。最小化代码量通常可以使程序更易读，但不要盲目地假设这是正确的。

幸运的是，这种权衡是不必要的。我们可以使面向对象的`Polygon` API 像函数实现一样易于使用。我们只需要修改我们的`Polygon`类，使其可以用多个点构造。让我们给它一个接受`Point`对象列表的初始化器。事实上，让我们也允许它接受元组，并且如果需要，我们可以自己构造`Point`对象：

```py
    def __init__(self, points=None):
        points = points if points else []
        self.vertices = []
        for point in points:
            if isinstance(point, tuple):
                point = Point(*point)
            self.vertices.append(point)
```

这个初始化器遍历列表，并确保任何元组都转换为点。如果对象不是元组，我们将其保留，假设它要么已经是`Point`对象，要么是一个未知的鸭子类型对象，可以像`Point`对象一样工作。

然而，在面向对象和更数据导向的代码版本之间并没有明显的赢家。它们都做同样的事情。如果我们有新的函数接受一个多边形参数，比如`area(polygon)`或`point_in_polygon(polygon, x, y)`，面向对象的代码的好处就变得越来越明显。同样，如果我们为多边形添加其他属性，比如`color`或`texture`，将这些数据封装到一个单一的类中就变得更有意义。

这种区别是一个设计决策，但一般来说，数据集越复杂，就越有可能有多个特定于该数据的函数，使用具有属性和方法的类就越有用。

在做出这个决定时，还要考虑类将如何使用。如果我们只是试图在更大的问题背景下计算一个多边形的周长，使用函数可能是编码最快、使用最方便的“一次性”方法。另一方面，如果我们的程序需要以各种方式操作多个多边形（计算周长、面积、与其他多边形的交集、移动或缩放它们等），我们肯定已经确定了一个需要非常灵活的对象。

此外，要注意对象之间的交互。寻找继承关系；继承是不可能优雅地建模而不使用类的，所以一定要使用它们。寻找我们在第一章中讨论的其他类型的关系，*面向对象设计*，关联和组合。组合在技术上可以使用只有数据结构来建模；例如，我们可以有一个包含元组值的字典列表，但通常更容易创建一些对象类，特别是如果与数据相关联有行为。

### 注意

不要因为可以使用对象就匆忙使用对象，但是*永远*不要忽视需要使用类时创建类。

# 使用属性为类数据添加行为

在整本书中，我们一直在关注行为和数据的分离。这在面向对象编程中非常重要，但我们将看到，在 Python 中，这种区别可能会变得模糊不清。Python 非常擅长模糊区别；它并不完全帮助我们“打破常规思维”。相反，它教会我们停止思考常规思维。

在深入细节之前，让我们讨论一些糟糕的面向对象理论。许多面向对象的语言（Java 是最臭名昭著的）教导我们永远不要直接访问属性。他们坚持要求我们像这样编写属性访问：

```py
class Color:
    def __init__(self, rgb_value, name):
        self._rgb_value = rgb_value
        self._name = name

    def set_name(self, name):
        self._name = name

    def get_name(self):
        return self._name
```

变量前缀带有下划线，以表明它们是私有的（其他语言实际上会强制它们为私有）。然后，get 和 set 方法提供对每个变量的访问。这个类在实践中将被使用如下：

```py
>>> c = Color("#ff0000", "bright red")
>>> c.get_name()
'bright red'
>>> c.set_name("red")
>>> c.get_name()
'red'

```

这并不像 Python 偏爱的直接访问版本那样易读：

```py
class Color:
    def __init__(self, rgb_value, name):
        self.rgb_value = rgb_value
        self.name = name

c = Color("#ff0000", "bright red")
print(c.name)
c.name = "red"
```

那么为什么有人会坚持基于方法的语法呢？他们的理由是，有一天我们可能希望在设置或检索值时添加额外的代码。例如，我们可以决定缓存一个值并返回缓存的值，或者我们可能希望验证该值是否是合适的输入。

在代码中，我们可以决定更改`set_name()`方法如下：

```py
def set_name(self, name):
    if not name:
        raise Exception("Invalid Name")
    self._name = name
```

现在，在 Java 和类似的语言中，如果我们最初编写我们的原始代码以直接访问属性，然后稍后将其更改为像前面的方法一样的方法，我们会有问题：任何访问属性的代码现在都必须访问方法。如果他们不将访问样式从属性访问更改为函数调用，他们的代码将会出错。在这些语言中的口头禅是我们永远不应该将公共成员变为私有。这在 Python 中并没有太多意义，因为它没有真正的私有成员的概念！

Python 给我们提供了`property`关键字，使方法看起来像属性。因此，我们可以编写我们的代码以使用直接成员访问，如果我们意外地需要更改实现以在获取或设置属性值时进行一些计算，我们可以这样做而不改变接口。让我们看看它是什么样子的：

```py
class Color:
    def __init__(self, rgb_value, name):
        self.rgb_value = rgb_value
        self._name = name

    def _set_name(self, name):
        if not name:
            raise Exception("Invalid Name")
        self._name = name

    def _get_name(self):
        return self._name

 **name = property(_get_name, _set_name)

```

如果我们一开始使用的是早期的非基于方法的类，直接设置了`name`属性，我们可以稍后将代码更改为前面的样子。我们首先将`name`属性更改为（半）私有的`_name`属性。然后我们添加另外两个（半）私有方法来获取和设置该变量，在设置时进行验证。

最后，我们在底部有`property`声明。这就是魔法。它在`Color`类上创建了一个名为`name`的新属性，现在替换了先前的`name`属性。它将此属性设置为属性，每当访问或更改属性时，它都会调用我们刚刚创建的两个方法。这个新版本的`Color`类可以像以前的版本一样使用，但是现在在设置`name`属性时进行验证：

```py
>>> c = Color("#0000ff", "bright red")
>>> print(c.name)
bright red
>>> c.name = "red"
>>> print(c.name)
red
>>> c.name = ""
Traceback (most recent call last):
 **File "<stdin>", line 1, in <module>
 **File "setting_name_property.py", line 8, in _set_name
 **raise Exception("Invalid Name")
Exception: Invalid Name

```

因此，如果我们以前编写了访问`name`属性的代码，然后将其更改为使用我们的`property`对象，先前的代码仍将起作用，除非它发送了一个空的`property`值，这正是我们想要在第一次禁止的行为。成功！

请记住，即使使用`name`属性，先前的代码也不是 100％安全的。人们仍然可以直接访问`_name`属性，并将其设置为空字符串。但是，如果他们访问我们明确标记为下划线的变量以表明它是私有的，那么他们就必须处理后果，而不是我们。

## 属性详细信息

将`property`函数视为返回一个对象，该对象通过我们指定的方法代理对属性值的设置或访问的任何请求。`property`关键字就像是这样一个对象的构造函数，并且该对象被设置为给定属性的公共成员。

这个`property`构造函数实际上可以接受两个额外的参数，一个删除函数和一个属性的文档字符串。`delete`函数在实践中很少被提供，但它可以用于记录已删除的值，或者可能否决删除，如果我们有理由这样做的话。文档字符串只是描述属性的字符串，与我们在第二章中讨论的文档字符串没有什么不同，*Python 中的对象*。如果我们不提供此参数，文档字符串将从第一个参数的文档字符串中复制：获取方法。这是一个愚蠢的例子，只是在任何方法被调用时简单地说明：

```py
class Silly:
    def _get_silly(self):
        print("You are getting silly")
        return self._silly
    def _set_silly(self, value):
        print("You are making silly {}".format(value))
        self._silly = value
    def _del_silly(self):
        print("Whoah, you killed silly!")
        del self._silly

    silly = property(_get_silly, _set_silly,
            _del_silly, "This is a silly property")
```

如果我们实际使用这个类，当我们要求它时，它确实打印出正确的字符串：

```py
>>> s = Silly()
>>> s.silly = "funny"
You are making silly funny
>>> s.silly
You are getting silly
'funny'
>>> del s.silly
Whoah, you killed silly!

```

此外，如果我们查看`Silly`类的帮助文件（通过在解释器提示符处发出`help(silly)`），它会显示我们的`silly`属性的自定义文档字符串：

```py
Help on class Silly in module __main__:

class Silly(builtins.object)
 |  Data descriptors defined here:
 |  
 |  __dict__
 |      dictionary for instance variables (if defined)
 |  
 |  __weakref__
 |      list of weak references to the object (if defined)
 |  
 |  silly
 |      This is a silly property
```

再次，一切都按我们计划的那样运行。实际上，属性通常只使用前两个参数定义：获取和设置函数。如果我们想为属性提供文档字符串，我们可以在获取函数上定义它；属性代理将把它复制到自己的文档字符串中。删除函数通常为空，因为对象属性很少被删除。如果程序员尝试删除没有指定删除函数的属性，它将引发异常。因此，如果有正当理由删除我们的属性，我们应该提供该函数。

## 装饰器 - 创建属性的另一种方式

如果您以前从未使用过 Python 装饰器，您可能希望跳过本节，在我们讨论第十章中的装饰器模式之后再回来。然而，您不需要理解正在发生什么，就可以使用装饰器语法使属性方法更易读。

属性函数可以与装饰器语法一起使用，将获取函数转换为属性：

```py
class Foo:
    @property
    def foo(self):
        return "bar"
```

这将`property`函数应用为装饰器，并且等同于之前的`foo = property(foo)`语法。从可读性的角度来看，主要区别在于我们可以在方法的顶部将`foo`函数标记为属性，而不是在定义之后，那样很容易被忽视。这也意味着我们不必创建带有下划线前缀的私有方法来定义属性。

更进一步，我们可以指定一个新属性的设置函数如下：

```py
class Foo:
    @property
    def foo(self):
        return self._foo

    @foo.setter
    def foo(self, value):
        self._foo = value
```

这个语法看起来很奇怪，尽管意图是明显的。首先，我们将`foo`方法装饰为获取器。然后，我们通过应用最初装饰的`foo`方法的`setter`属性，装饰第二个同名方法！`property`函数返回一个对象；这个对象总是带有自己的`setter`属性，然后可以应用为其他函数的装饰器。使用相同的名称来命名获取和设置方法并不是必需的，但它确实有助于将访问一个属性的多个方法分组在一起。

我们还可以使用`@foo.deleter`指定删除函数。我们不能使用`property`装饰器指定文档字符串，因此我们需要依赖属性从初始获取方法复制文档字符串。

这是我们之前的`Silly`类重写，使用`property`作为装饰器：

```py
class Silly:
    @property
    def silly(self):
        "This is a silly property"
        print("You are getting silly")
        return self._silly

    @silly.setter
    def silly(self, value):
        print("You are making silly {}".format(value))
        self._silly = value

    @silly.deleter
    def silly(self):
        print("Whoah, you killed silly!")
        del self._silly
```

这个类的操作*完全*与我们之前的版本相同，包括帮助文本。您可以使用您认为更可读和优雅的任何语法。

## 决定何时使用属性

随着内置属性模糊了行为和数据之间的界限，很难知道该选择哪一个。我们之前看到的示例用例是属性最常见的用法之一；我们在类上有一些数据，然后希望添加行为。在决定使用属性时，还有其他因素需要考虑。

在 Python 中，数据、属性和方法在类上都是属性。方法可调用的事实并不能将其与其他类型的属性区分开；事实上，我们将在第七章中看到，*Python 面向对象的快捷方式*，可以创建可以像函数一样被调用的普通对象。我们还将发现函数和方法本身也是普通对象。

方法只是可调用的属性，属性只是可定制的属性，这一事实可以帮助我们做出这个决定。方法通常应该表示动作；可以对对象进行的或由对象执行的事情。当调用一个方法时，即使只有一个参数，它也应该*做*一些事情。方法名称通常是动词。

确认属性不是一个动作后，我们需要在标准数据属性和属性之间做出决定。通常情况下，除非需要以某种方式控制对该属性的访问，否则始终使用标准属性。在任何情况下，您的属性通常是一个名词。属性和属性之间唯一的区别在于，当检索、设置或删除属性时，我们可以自动调用自定义操作。

让我们看一个更现实的例子。自定义行为的常见需求是缓存难以计算或昂贵的查找（例如需要网络请求或数据库查询）的值。目标是将值存储在本地，以避免重复调用昂贵的计算。

我们可以通过属性上的自定义 getter 来实现这一点。第一次检索值时，我们执行查找或计算。然后我们可以将值作为对象的私有属性（或专用缓存软件中）进行本地缓存，下次请求值时，我们返回存储的数据。以下是我们如何缓存网页：

```py
from urllib.request import urlopen

class WebPage:
    def __init__(self, url):
        self.url = url
        self._content = None

    @property
    def content(self):
        if not self._content:
            print("Retrieving New Page...")
            self._content = urlopen(self.url).read()
        return self._content
```

我们可以测试这段代码，以确保页面只被检索一次：

```py
>>> import time
>>> webpage = WebPage("http://ccphillips.net/")
>>> now = time.time()
>>> content1 = webpage.content
Retrieving New Page...
>>> time.time() - now
22.43316888809204
>>> now = time.time()
>>> content2 = webpage.content
>>> time.time() - now
1.9266459941864014
>>> content2 == content1
True

```

当我最初测试这段代码时，我使用的是糟糕的卫星连接，第一次加载内容花了 20 秒。第二次，我在 2 秒内得到了结果（这实际上只是我在解释器中输入这些行所花费的时间）。

自定义 getter 对于需要根据其他对象属性动态计算的属性也很有用。例如，我们可能想要计算整数列表的平均值：

```py
class AverageList(list):
    @property
    def average(self):
        return sum(self) / len(self)
```

这个非常简单的类继承自`list`，因此我们可以免费获得类似列表的行为。我们只需向类添加一个属性，然后，我们的列表就可以有一个平均值：

```py
>>> a = AverageList([1,2,3,4])
>>> a.average
2.5

```

当然，我们也可以将其制作成一个方法，但那么我们应该将其命名为`calculate_average()`，因为方法表示动作。但是名为`average`的属性更合适，既更容易输入，也更容易阅读。

自定义 setter 对于验证是有用的，正如我们已经看到的，但它们也可以用于将值代理到另一个位置。例如，我们可以为`WebPage`类添加一个内容 setter，以便在设置值时自动登录到我们的 Web 服务器并上传新页面。

# 管理对象

我们一直专注于对象及其属性和方法。现在，我们将看看如何设计更高级的对象：管理其他对象的对象。将一切联系在一起的对象。

这些对象与我们迄今为止看到的大多数示例的不同之处在于，我们的示例倾向于代表具体的想法。管理对象更像办公室经理；他们不在现场做实际的“可见”工作，但没有他们，部门之间就没有沟通，也没有人知道他们应该做什么（尽管，如果组织管理不善，这也可能是真的！）。类上的属性倾向于引用其他执行“可见”工作的对象；这样一个类上的行为在适当的时候委托给这些其他类，并在它们之间传递消息。

例如，我们将编写一个程序，对存储在压缩 ZIP 文件中的文本文件执行查找和替换操作。我们需要创建对象来表示 ZIP 文件和每个单独的文本文件（幸运的是，我们不必编写这些类，它们在 Python 标准库中可用）。管理对象将负责确保按顺序执行三个步骤：

1.  解压缩压缩文件。

1.  执行查找和替换操作。

1.  压缩新文件。

该类使用`.zip`文件名和搜索和替换字符串进行初始化。我们创建一个临时目录来存储解压后的文件，以保持文件夹的清洁。Python 3.4 的`pathlib`库在文件和目录操作方面提供帮助。我们将在第八章中了解更多相关信息，但在下面的示例中，接口应该是相当清晰的：

```py
import sys
import shutil
import zipfile
from pathlib import Path

class ZipReplace:
    def __init__(self, filename, search_string, replace_string):
        self.filename = filename
        self.search_string = search_string
        self.replace_string = replace_string
        self.temp_directory = Path("unzipped-{}".format(
                filename))
```

然后，我们为三个步骤创建一个整体的“管理器”方法。这个方法将责任委托给其他方法。显然，我们可以在一个方法中完成所有三个步骤，或者在一个脚本中完成所有三个步骤而不创建对象。将三个步骤分开有几个优点：

+   **可读性**：每个步骤的代码都是一个独立的单元，易于阅读和理解。方法名称描述了方法的功能，不需要太多额外的文档来理解发生了什么。

+   **可扩展性**：如果子类想要使用压缩的 TAR 文件而不是 ZIP 文件，它可以重写`zip`和`unzip`方法，而无需复制`find_replace`方法。

+   **分区**：外部类可以创建此类的实例，并直接在某个文件夹上调用`find_replace`方法，而无需对内容进行`zip`。

委托方法是以下代码中的第一个；其他方法包括在内是为了完整性：

```py
    def zip_find_replace(self):
        self.unzip_files()
        self.find_replace()
        self.zip_files()

    def unzip_files(self):
        self.temp_directory.mkdir()
        with zipfile.ZipFile(self.filename) as zip:
            zip.extractall(str(self.temp_directory))

    def find_replace(self):
        for filename in self.temp_directory.iterdir():
            with filename.open() as file:
                contents = file.read()
            contents = contents.replace(
                    self.search_string, self.replace_string)
            with filename.open("w") as file:
                file.write(contents)

    def zip_files(self):
        with zipfile.ZipFile(self.filename, 'w') as file:
            for filename in self.temp_directory.iterdir():
                file.write(str(filename), filename.name)
        shutil.rmtree(str(self.temp_directory))

if __name__ == "__main__":
    ZipReplace(*sys.argv[1:4]).zip_find_replace()
```

为简洁起见，压缩和解压文件的代码文档很少。我们目前的重点是面向对象的设计；如果您对`zipfile`模块的内部细节感兴趣，请参考标准库中的文档，可以在线查看，也可以在交互式解释器中键入“import zipfile；help(zipfile)”来查看。请注意，此示例仅搜索 ZIP 文件中的顶层文件；如果解压后的内容中有任何文件夹，它们将不会被扫描，也不会扫描这些文件夹中的任何文件。

示例中的最后两行允许我们通过传递`zip`文件名、搜索字符串和替换字符串作为参数从命令行运行程序：

```py
python zipsearch.py hello.zip hello hi

```

当然，这个对象不一定要从命令行创建；它可以从另一个模块中导入（用于执行批量 ZIP 文件处理），或者作为 GUI 界面的一部分访问，甚至可以作为一个高级管理对象的一部分，该对象知道从哪里获取 ZIP 文件（例如，从 FTP 服务器检索它们或将它们备份到外部磁盘）。

随着程序变得越来越复杂，被建模的对象变得越来越不像物理对象。属性是其他抽象对象，方法是改变这些抽象对象状态的动作。但是，无论多么复杂，每个对象的核心都是一组具体的属性和明确定义的行为。

## 删除重复的代码

管理风格类中的代码，比如`ZipReplace`，通常是非常通用的，可以以多种方式应用。可以使用组合或继承来帮助将代码放在一个地方，从而消除重复代码。在我们看任何示例之前，让我们讨论一点理论。具体来说，为什么重复的代码是一件坏事？

有几个原因，但它们都归结为可读性和可维护性。当我们编写一个与早期代码类似的新代码时，最容易的方法是复制旧代码，并更改需要更改的内容（变量名、逻辑、注释），使其在新位置上运行。或者，如果我们正在编写似乎类似但不完全相同于项目中其他地方的代码，通常更容易编写具有类似行为的新代码，而不是弄清楚如何提取重叠的功能。

但是，一旦有人阅读和理解代码，并且遇到重复的代码块，他们就会面临两难境地。可能有意义的代码突然需要被理解。一个部分与另一个部分有何不同？它们又有何相同之处？在什么条件下调用一个部分？我们什么时候调用另一个部分？你可能会说你是唯一阅读你的代码的人，但是如果你八个月不碰那段代码，它对你来说将会和对一个新手编程者一样难以理解。当我们试图阅读两个相似的代码片段时，我们必须理解它们为何不同，以及它们如何不同。这浪费了读者的时间；代码应该始终以可读性为首要考虑因素。

### 注意

我曾经不得不尝试理解某人的代码，其中有三个相同的副本，每个副本都有 300 行非常糟糕的代码。在我终于理解这三个“相同”的版本实际上执行略有不同的税收计算之前，我已经与这段代码一起工作了一个月。一些微妙的差异是有意的，但也有明显的地方，某人在一个函数中更新了一个计算而没有更新其他两个函数。代码中微妙而难以理解的错误数不胜数。最终，我用大约 20 行易于阅读的函数替换了所有 900 行。

阅读这样的重复代码可能很烦人，但代码维护更加痛苦。正如前面的故事所示，保持两个相似的代码片段更新可能是一场噩梦。每当我们更新其中一个部分时，我们必须记住同时更新两个部分，并且必须记住多个部分的不同之处，以便在编辑每个部分时修改我们的更改。如果我们忘记更新两个部分，我们最终会遇到极其恼人的错误，通常表现为“但我已经修复过了，为什么还会发生？”

结果是，阅读或维护我们的代码的人必须花费天文数字般的时间来理解和测试它，与我们一开始就以非重复的方式编写代码相比。当我们自己进行维护时，这甚至更加令人沮丧；我们会发现自己说：“为什么我第一次就没做对呢？”通过复制粘贴现有代码节省的时间在第一次进行维护时就丢失了。代码被阅读和修改的次数比编写的次数要多得多，而且频率也更高。可理解的代码应该始终是最重要的。

这就是为什么程序员，尤其是 Python 程序员（他们倾向于比平均水平更重视优雅的代码），遵循所谓的“不要重复自己”（DRY）原则。DRY 代码是可维护的代码。我给初学者的建议是永远不要使用编辑器的复制粘贴功能。对于中级程序员，我建议他们在按下*Ctrl* + *C*之前三思。

但是，我们应该怎么做，而不是重复编码？最简单的解决方案通常是将代码移入一个函数中，该函数接受参数以考虑不同的部分。这并不是一个非常面向对象的解决方案，但通常是最佳的。

例如，如果我们有两段代码，它们将 ZIP 文件解压缩到两个不同的目录中，我们可以很容易地编写一个函数，该函数接受一个参数，用于指定应将其解压缩到的目录。这可能会使函数本身稍微难以阅读，但一个好的函数名称和文档字符串很容易弥补这一点，任何调用该函数的代码都将更容易阅读。

这就足够的理论了！故事的寓意是：始终努力重构代码，使其更易于阅读，而不是编写只是更易于编写的糟糕代码。

## 实践中

让我们探讨两种重用现有代码的方法。在编写代码以替换 ZIP 文件中的文本文件中的字符串后，我们后来又被承包商要求将 ZIP 文件中的所有图像缩放到 640 x 480。看起来我们可以使用与`ZipReplace`中使用的非常相似的范例。第一个冲动可能是保存该文件的副本，并将`find_replace`方法更改为`scale_image`或类似的内容。

但是，这样做并不酷。如果有一天我们想要将`unzip`和`zip`方法更改为也能打开 TAR 文件呢？或者也许我们想要为临时文件使用一个保证唯一的目录名称。在任何一种情况下，我们都必须在两个不同的地方进行更改！

我们将首先演示基于继承的解决方案来解决这个问题。首先，我们将修改我们原来的`ZipReplace`类，将其改为一个用于处理通用 ZIP 文件的超类：

```py
import os
import shutil
import zipfile
from pathlib import Path

class ZipProcessor:
    def __init__(self, zipname):
        self.zipname = zipname
        self.temp_directory = Path("unzipped-{}".format(
                zipname[:-4]))

    def process_zip(self):
        self.unzip_files()
        self.process_files()
        self.zip_files()

    def unzip_files(self):
        self.temp_directory.mkdir()
        with zipfile.ZipFile(self.zipname) as zip:
            zip.extractall(str(self.temp_directory))

    def zip_files(self):
        with zipfile.ZipFile(self.zipname, 'w') as file:
            for filename in self.temp_directory.iterdir():
                file.write(str(filename), filename.name)
        shutil.rmtree(str(self.temp_directory))
```

我们将`filename`属性更改为`zipname`，以避免与各种方法内的`filename`局部变量混淆。尽管这实际上并不是一种设计上的改变，但这有助于使代码更易读。

我们还删除了`__init__`中的两个参数（`search_string`和`replace_string`），这些参数是特定于`ZipReplace`的。然后我们将`zip_find_replace`方法重命名为`process_zip`，并让它调用一个（尚未定义的）`process_files`方法，而不是`find_replace`；这些名称更改有助于展示我们新类的更一般化特性。请注意，我们已经完全删除了`find_replace`方法；该代码是特定于`ZipReplace`，在这里没有任何业务。

这个新的`ZipProcessor`类实际上并没有定义`process_files`方法；因此，如果我们直接运行它，它将引发异常。因为它不是直接运行的，我们在原始脚本的底部删除了主调用。

现在，在我们继续进行图像处理应用程序之前，让我们修复原始的`zipsearch`类，以利用这个父类：

```py
from zip_processor import ZipProcessor
import sys
import os

class ZipReplace(ZipProcessor):
    def __init__(self, filename, search_string,
            replace_string):
        super().__init__(filename)
        self.search_string = search_string
        self.replace_string = replace_string

    def process_files(self):
        '''perform a search and replace on all files in the
        temporary directory'''
        for filename in self.temp_directory.iterdir():
            with filename.open() as file:
                contents = file.read()
            contents = contents.replace(
                    self.search_string, self.replace_string)
            with filename.open("w") as file:
                file.write(contents)

if __name__ == "__main__":
    ZipReplace(*sys.argv[1:4]).process_zip()
```

这段代码比原始版本要短一些，因为它继承了它的 ZIP 处理能力。我们首先导入我们刚刚编写的基类，并使`ZipReplace`扩展该类。然后我们使用`super()`来初始化父类。`find_replace`方法仍然在这里，但我们将其重命名为`process_files`，以便父类可以从其管理接口调用它。因为这个名称不像旧名称那样描述性强，我们添加了一个文档字符串来描述它正在做什么。

现在，考虑到我们现在所做的工作量相当大，而我们所拥有的程序在功能上与我们开始时的程序并无不同！但是经过这样的工作，我们现在更容易编写其他操作 ZIP 存档文件的类，比如（假设请求的）照片缩放器。此外，如果我们想要改进或修复 ZIP 功能，我们只需更改一个`ZipProcessor`基类，就可以对所有类进行操作。维护将更加有效。

看看现在创建一个利用`ZipProcessor`功能的照片缩放类是多么简单。（注意：这个类需要第三方的`pillow`库来获取`PIL`模块。你可以用`pip install pillow`来安装它。）

```py
from zip_processor import ZipProcessor
import sys
from PIL import Image

class ScaleZip(ZipProcessor):

    def process_files(self):
        '''Scale each image in the directory to 640x480'''
        for filename in self.temp_directory.iterdir():
            im = Image.open(str(filename))
            scaled = im.resize((640, 480))
            scaled.save(str(filename))

if __name__ == "__main__":
    ScaleZip(*sys.argv[1:4]).process_zip()
```

看看这个类是多么简单！我们之前做的所有工作都得到了回报。我们只需要打开每个文件（假设它是一个图像；如果无法打开文件，它将会崩溃），对其进行缩放，然后保存。`ZipProcessor`类会在我们不做任何额外工作的情况下处理压缩和解压缩。

# 案例研究

对于这个案例研究，我们将尝试进一步探讨这个问题，“何时应该选择对象而不是内置类型？”我们将建模一个可能在文本编辑器或文字处理器中使用的“文档”类。它应该有什么对象、函数或属性？

我们可能会从`str`开始，用于“文档”内容，但在 Python 中，字符串是不可变的。一旦定义了一个`str`，它就永远存在。我们无法在其中插入字符或删除字符，而不创建一个全新的字符串对象。这将导致大量的`str`对象占用内存，直到 Python 的垃圾收集器决定在我们身后清理它们。

因此，我们将使用字符列表而不是字符串，这样我们可以随意修改它。此外，“文档”类需要知道列表中的当前光标位置，并且可能还应该存储文档的文件名。

### 注意

真正的文本编辑器使用基于二叉树的数据结构称为“绳索”来模拟它们的文档内容。这本书的标题不是“高级数据结构”，所以如果你对这个迷人的主题感兴趣，你可能想在网上搜索绳索数据结构。

现在，它应该有什么方法？我们可能想对文本文档做很多事情，包括插入、删除和选择字符，剪切、复制、粘贴、选择和保存或关闭文档。看起来有大量的数据和行为，所以把所有这些东西放到自己的“文档”类中是有道理的。

一个相关的问题是：这个类应该由一堆基本的 Python 对象组成，比如`str`文件名、`int`光标位置和字符的`list`？还是这些东西中的一些或全部应该是专门定义的对象？那么单独的行和字符呢，它们需要有自己的类吗？

我们将在进行时回答这些问题，但让我们先从最简单的“文档”类开始，看看它能做什么：

```py
class Document:
    def __init__(self):
        self.characters = []
        self.cursor = 0
        self.filename = ''

    def insert(self, character):
        self.characters.insert(self.cursor, character)
        self.cursor += 1

    def delete(self):
        del self.characters[self.cursor]

    def save(self):
        with open(self.filename, 'w') as f:
            f.write(''.join(self.characters))

    def forward(self):
        self.cursor += 1

    def back(self):
        self.cursor -= 1
```

这个简单的类允许我们完全控制编辑基本文档。看看它的运行情况：

```py
>>> doc = Document()
>>> doc.filename = "test_document"
>>> doc.insert('h')
>>> doc.insert('e')
>>> doc.insert('l')
>>> doc.insert('l')
>>> doc.insert('o')
>>> "".join(doc.characters)
'hello'
>>> doc.back()
>>> doc.delete()
>>> doc.insert('p')
>>> "".join(doc.characters)
'hellp'

```

看起来它正在工作。我们可以把键盘的字母和箭头键连接到这些方法，文档会很好地跟踪一切。

但是，如果我们想连接的不仅仅是箭头键。如果我们还想连接“Home”和“End”键怎么办？我们可以在“文档”类中添加更多的方法，用于在字符串中向前或向后搜索换行符（在 Python 中，换行符或`\n`表示一行的结束和新行的开始），但如果我们为每个可能的移动操作（按单词移动、按句子移动、*Page Up*、*Page Down*、行尾、空白开始等）都这样做，这个类会很庞大。也许把这些方法放在一个单独的对象上会更好。因此，让我们把光标属性转换为一个对象，它知道自己的位置并可以操纵该位置。我们可以将向前和向后的方法移到该类中，并为“Home”和“End”键添加几个方法：

```py
class Cursor:
    def __init__(self, document):
        self.document = document
        self.position = 0

    def forward(self):
        self.position += 1

    def back(self):
        self.position -= 1

    def home(self):
        while self.document.characters[
                self.position-1] != '\n':
            self.position -= 1
            if self.position == 0:
                # Got to beginning of file before newline
                break

    def end(self):
        while self.position < len(self.document.characters
                ) and self.document.characters[
                    self.position] != '\n':
            self.position += 1
```

这个类将文档作为初始化参数，因此方法可以访问文档字符列表的内容。然后，它提供了简单的方法来向前和向后移动，以及移动到`home`和`end`位置。

### 提示

这段代码并不是很安全。你很容易就能超出结束位置，如果你试图在一个空文件上回家，它会崩溃。这些例子被保持短小是为了让它们易读，但这并不意味着它们是防御性的！你可以通过练习来改进这段代码的错误检查；这可能是一个扩展你异常处理技能的绝佳机会。

`Document` 类本身几乎没有改变，除了移动到 `Cursor` 类的两个方法：

```py
class Document:
    def __init__(self):
        self.characters = []
        self.cursor = Cursor(self)
        self.filename = ''

       def insert(self, character):
        self.characters.insert(self.cursor.position,
                character)
        self.cursor.forward()

    def delete(self):
        del self.characters[self.cursor.position]

    def save(self):
        f = open(self.filename, 'w')
        f.write(''.join(self.characters))
        f.close()
```

我们只需更新任何访问旧光标整数的内容，以使用新对象。我们可以测试 `home` 方法是否真的移动到换行符：

```py
>>> d = Document()
>>> d.insert('h')
>>> d.insert('e')
>>> d.insert('l')
>>> d.insert('l')
>>> d.insert('o')
>>> d.insert('\n')
>>> d.insert('w')
>>> d.insert('o')
>>> d.insert('r')
>>> d.insert('l')
>>> d.insert('d')
>>> d.cursor.home()
>>> d.insert("*")
>>> print("".join(d.characters))
hello
*world

```

现在，因为我们一直在使用字符串 `join` 函数（将字符连接起来以便查看实际文档内容），我们可以在 `Document` 类中添加一个属性来给出完整的字符串：

```py
    @property
    def string(self):
        return "".join(self.characters)
```

这使得我们的测试变得更简单：

```py
>>> print(d.string)
hello
world

```

这个框架很简单（尽管可能有点耗时！）扩展到创建和编辑完整的纯文本文档。现在，让我们扩展它以便适用于富文本；可以有**粗体**、下划线或*斜体*字符的文本。

我们可以有两种方法来处理这个问题；第一种是在我们的字符列表中插入“假”字符，它们像指令一样起作用，比如“粗体字符直到找到一个停止粗体字符”。第二种是为每个字符添加指示其格式的信息。虽然前一种方法可能更常见，但我们将实现后一种解决方案。为此，我们显然需要一个字符类。这个类将有一个表示字符的属性，以及三个布尔属性，表示它是否是粗体、斜体或下划线。

嗯，等等！这个 `Character` 类会有任何方法吗？如果没有，也许我们应该使用 Python 的许多数据结构之一；元组或命名元组可能就足够了。有没有我们想对字符执行的操作？

显然，我们可能想对字符执行一些操作，比如删除或复制它们，但这些是需要在 `Document` 级别处理的事情，因为它们实际上是在修改字符列表。有没有需要对单个字符执行的操作？

实际上，既然我们在思考 `Character` 类实际上是什么...它是什么？能不能说 `Character` 类是一个字符串？也许我们应该在这里使用继承关系？然后我们就可以利用 `str` 实例带来的众多方法。

我们在谈论什么样的方法？有 `startswith`、`strip`、`find`、`lower` 等等。这些方法中的大多数都希望在包含多个字符的字符串上工作。相比之下，如果 `Character` 是 `str` 的子类，我们可能最好重写 `__init__` 来在提供多字符字符串时引发异常。由于我们免费获得的所有这些方法实际上并不适用于我们的 `Character` 类，看来我们毋需使用继承。

这让我们回到了最初的问题；`Character` 是否应该是一个类？`object` 类上有一个非常重要的特殊方法，我们可以利用它来表示我们的字符。这个方法叫做 `__str__`（两个下划线，像 `__init__` 一样），它在字符串操作函数中使用，比如 `print` 和 `str` 构造函数，将任何类转换为字符串。默认实现做了一些无聊的事情，比如打印模块和类的名称以及它在内存中的地址。但如果我们重写它，我们可以让它打印任何我们喜欢的东西。对于我们的实现，我们可以让它用特殊字符前缀字符，表示它们是否是粗体、斜体或下划线。因此，我们将创建一个表示字符的类，就是这样：

```py
class Character:
    def __init__(self, character,
            bold=False, italic=False, underline=False):
        assert len(character) == 1
        self.character = character
        self.bold = bold
        self.italic = italic
        self.underline = underline

    def __str__(self):
        bold = "*" if self.bold else ''
        italic = "/" if self.italic else ''
        underline = "_" if self.underline else ''
        return bold + italic + underline + self.character
```

这个类允许我们创建字符，并在应用`str()`函数时在它们前面加上一个特殊字符。没有太多激动人心的地方。我们只需要对`Document`和`Cursor`类进行一些小的修改，以便与这个类一起工作。在`Document`类中，我们在`insert`方法的开头添加了这两行：

```py
    def insert(self, character):
        if not hasattr(character, 'character'):
            character = Character(character)
```

这是一段相当奇怪的代码。它的基本目的是检查传入的字符是`Character`还是`str`。如果是字符串，它将被包装在`Character`类中，以便列表中的所有对象都是`Character`对象。然而，完全有可能有人使用我们的代码想要使用既不是`Character`也不是字符串的类，使用鸭子类型。如果对象有一个字符属性，我们就假设它是一个“`Character`-like”对象。但如果没有，我们就假设它是一个“`str`-like”对象，并将其包装在`Character`中。这有助于程序利用鸭子类型和多态性；只要对象有一个字符属性，它就可以在`Document`类中使用。

这个通用检查可能非常有用，例如，如果我们想要制作一个带有语法高亮的程序员编辑器：我们需要关于字符的额外数据，比如字符属于什么类型的语法标记。请注意，如果我们要做很多这种比较，最好实现`Character`作为一个抽象基类，并使用适当的`__subclasshook__`，如第三章中讨论的那样，*当对象相似时*。

此外，我们需要修改`Document`上的字符串属性，以接受新的`Character`值。我们只需要在连接之前对每个字符调用`str()`即可：

```py
    @property
    def string(self):
 **return "".join((str(c) for c in self.characters))

```

这段代码使用了一个生成器表达式，我们将在第九章中讨论，*迭代器模式*。这是一个快捷方式，可以对序列中的所有对象执行特定的操作。

最后，我们还需要检查`Character.character`，而不仅仅是我们之前存储的字符串字符，在`home`和`end`函数中，我们要查看它是否匹配换行符：

```py
    def home(self):
        while self.document.characters[
                self.position-1].character != '\n':
            self.position -= 1
            if self.position == 0:
                # Got to beginning of file before newline
                break

    def end(self):
        while self.position < len(
                self.document.characters) and \
                self.document.characters[
                        self.position
                        ].character != '\n':
            self.position += 1
```

这完成了字符的格式化。我们可以测试一下，看看它是否有效：

```py
>>> d = Document()
>>> d.insert('h')
>>> d.insert('e')
>>> d.insert(Character('l', bold=True))
>>> d.insert(Character('l', bold=True))
>>> d.insert('o')
>>> d.insert('\n')
>>> d.insert(Character('w', italic=True))
>>> d.insert(Character('o', italic=True))
>>> d.insert(Character('r', underline=True))
>>> d.insert('l')
>>> d.insert('d')
>>> print(d.string)
he*l*lo
/w/o_rld
>>> d.cursor.home()
>>> d.delete()
>>> d.insert('W')
>>> print(d.string)
he*l*lo
W/o_rld
>>> d.characters[0].underline = True
>>> print(d.string)
_he*l*lo
W/o_rld

```

正如预期的那样，每当我们打印字符串时，每个粗体字符前面都有一个`*`字符，每个斜体字符前面都有一个`/`字符，每个下划线字符前面都有一个`_`字符。我们所有的函数似乎都能工作，而且我们可以在事后修改列表中的字符。我们有一个可以插入到适当的用户界面中并与键盘进行输入和屏幕进行输出的工作的富文本文档对象。当然，我们希望在屏幕上显示真正的粗体、斜体和下划线字符，而不是使用我们的`__str__`方法，但它对我们所要求的基本测试来说已经足够了。

# 练习

我们已经看过了在面向对象的 Python 程序中对象、数据和方法之间可以相互交互的各种方式。和往常一样，你的第一个想法应该是如何将这些原则应用到你自己的工作中。你有没有一些混乱的脚本散落在那里，可以用面向对象的管理器重写？浏览一下你的旧代码，寻找一些不是动作的方法。如果名称不是动词，试着将其重写为属性。

想想你用任何语言编写的代码。它是否违反了 DRY 原则？是否有重复的代码？你有没有复制和粘贴代码？你是否写了两个类似代码的版本，因为你不想理解原始代码？现在回顾一下你最近的一些代码，看看是否可以使用继承或组合重构重复的代码。尝试选择一个你仍然有兴趣维护的项目；不要选择那些你再也不想碰的代码。这有助于你在进行改进时保持兴趣！

现在，回顾一下我们在本章中看到的一些例子。从使用属性缓存检索数据的缓存网页示例开始。这个例子的一个明显问题是缓存从未刷新过。在属性的 getter 中添加一个超时，只有在页面在超时到期之前已被请求时才返回缓存的页面。你可以使用`time`模块（`time.time() - an_old_time`返回自`an_old_time`以来经过的秒数）来确定缓存是否已过期。

现在看看基于继承的`ZipProcessor`。在这里使用组合而不是继承可能是合理的。在`ZipReplace`和`ScaleZip`类中，你可以将这些类的实例传递到`ZipProcessor`构造函数中，并调用它们来进行处理。实现这一点。

你觉得哪个版本更容易使用？哪个更优雅？哪个更容易阅读？这些都是主观问题；答案因人而异。然而，知道答案很重要；如果你发现你更喜欢继承而不是组合，你就要注意不要在日常编码中过度使用继承。如果你更喜欢组合，确保你不要错过创建优雅基于继承的解决方案的机会。

最后，在我们在案例研究中创建的各种类中添加一些错误处理程序。它们应该确保只输入单个字符，不要尝试将光标移动到文件的末尾或开头，不要删除不存在的字符，也不要保存没有文件名的文件。尽量考虑尽可能多的边缘情况，并对其进行处理（考虑边缘情况大约占专业程序员工作的 90％！）考虑不同的处理方式；当用户尝试移动到文件末尾时，你应该引发异常，还是只停留在最后一个字符？

在你的日常编码中，注意复制和粘贴命令。每次在编辑器中使用它们时，考虑是否改进程序的组织结构，以便你只有一个即将复制的代码版本。

# 总结

在本章中，我们专注于识别对象，特别是那些不是立即显而易见的对象；管理和控制对象。对象应该既有数据又有行为，但属性可以用来模糊这两者之间的区别。DRY 原则是代码质量的重要指标，继承和组合可以应用于减少代码重复。

在下一章中，我们将介绍几种内置的 Python 数据结构和对象，重点关注它们的面向对象特性以及如何扩展或调整它们。


# 第六章：Python 数据结构

到目前为止，我们已经在示例中看到了许多内置的 Python 数据结构。你可能也在入门书籍或教程中涵盖了许多这些内容。在本章中，我们将讨论这些数据结构的面向对象特性，以及它们应该在何时使用而不是使用常规类，以及何时不应该使用。特别是，我们将讨论：

+   元组和命名元组

+   字典

+   列表和集合

+   如何以及为什么扩展内置对象

+   三种类型的队列

# 空对象

让我们从最基本的 Python 内置对象开始，这是我们已经看到很多次的对象，我们在创建的每个类中都扩展了它：`object`。从技术上讲，我们可以实例化一个`object`而不编写子类。

```py
>>> o = object()
>>> o.x = 5
Traceback (most recent call last):
 **File "<stdin>", line 1, in <module>
AttributeError: 'object' object has no attribute 'x'

```

不幸的是，正如你所看到的，不可能在直接实例化的`object`上设置任何属性。这不是因为 Python 开发人员想要强迫我们编写自己的类，或者有什么邪恶的目的。他们这样做是为了节省内存；大量的内存。当 Python 允许对象具有任意属性时，它需要一定量的系统内存来跟踪每个对象具有的属性，用于存储属性名称和其值。即使没有存储属性，也会为*潜在*的新属性分配内存。在典型的 Python 程序中有数十、数百或数千个对象（每个类都扩展了 object）；这小量的内存很快就会变成大量的内存。因此，Python 默认禁用`object`和其他几个内置对象上的任意属性。

### 注意

我们可以使用**slots**在我们自己的类上限制任意属性。Slots 超出了本书的范围，但现在你有了一个搜索词，如果你想要更多信息。在正常使用中，使用 slots 并没有太多好处，但如果你正在编写一个将在整个系统中复制成千上万次的对象，它们可以帮助节省内存，就像对`object`一样。

然而，创建一个空对象类非常简单；我们在最早的示例中看到了它：

```py
class MyObject:
    pass
```

而且，正如我们已经看到的，可以在这样的类上设置属性：

```py
>>> m = MyObject()
>>> m.x = "hello"
>>> m.x
'hello'

```

如果我们想要将属性分组在一起，我们可以将它们存储在一个空对象中。但是，通常最好使用其他专门用于存储数据的内置对象。本书始终强调，只有在想要指定*数据和行为*时才应该使用类和对象。创建一个空类的主要原因是为了快速地阻止某些东西，知道我们稍后会回来添加行为。将行为适应类要容易得多，而将数据结构替换为对象并更改所有引用则要困难得多。因此，重要的是从一开始就决定数据只是数据，还是伪装成对象。一旦做出了这个设计决定，其余的设计自然而然地就会落实。

# 元组和命名元组

元组是可以按顺序存储特定数量的其他对象的对象。它们是不可变的，因此我们无法在运行时添加、删除或替换对象。这可能看起来像是一个巨大的限制，但事实是，如果你需要修改一个元组，你正在使用错误的数据类型（通常列表更合适）。元组不可变的主要好处是我们可以将它们用作字典中的键，以及其他需要哈希值的对象的位置。

元组用于存储数据；无法在元组中存储行为。如果我们需要行为来操作元组，我们必须将元组传递给执行该操作的函数（或另一个对象的方法）。

元组通常应该存储一些在某种程度上不同的值。例如，我们不会在一个元组中放入三个股票符号，但我们可能会创建一个包含股票符号、当前价格、最高价和最低价的元组。元组的主要目的是将不同的数据片段聚合到一个容器中。因此，元组可能是最简单的工具，用来替换“没有数据的对象”习语。

我们可以通过用逗号分隔值来创建一个元组。通常，元组用括号括起来，以使它们易于阅读并与表达式的其他部分分开，但这并不总是强制性的。以下两个赋值是相同的（它们记录了一家相当有利可图的公司的股票、当前价格、最高价和最低价）：

```py
>>> stock = "FB", 75.00, 75.03, 74.90
>>> stock2 = ("FB", 75.00, 75.03, 74.90)

```

如果我们将元组分组到其他对象中，比如函数调用、列表推导或生成器中，括号是必需的。否则，解释器将无法知道它是一个元组还是下一个函数参数。例如，以下函数接受一个元组和一个日期，并返回一个包含日期和股票最高价和最低价之间的中间值的元组：

```py
import datetime
def middle(stock, date):
    **symbol, current, high, low = stock
    return (((high + low) / 2), date)

mid_value, date = middle(("FB", 75.00, 75.03, 74.90),
        **datetime.date(2014, 10, 31))

```

元组是直接在函数调用中通过用逗号分隔值并将整个元组括在括号中创建的。然后，这个元组后面跟着一个逗号，以将它与第二个参数分开。

这个例子也说明了元组的解包。函数内的第一行将`stock`参数解包成四个不同的变量。元组的长度必须与变量的数量完全相同，否则会引发异常。我们还可以在最后一行看到元组解包的例子，其中函数内返回的元组被解包成两个值，`mid_value`和`date`。当然，这是一个奇怪的做法，因为我们首先向函数提供了日期，但这让我们有机会看到解包的工作原理。

在 Python 中，解包是一个非常有用的功能。我们可以将变量组合在一起，使得存储和传递它们变得更简单，但是当我们需要访问它们所有时，我们可以将它们解包成单独的变量。当然，有时我们只需要访问元组中的一个变量。我们可以使用与其他序列类型（例如列表和字符串）相同的语法来访问单个值：

```py
>>> stock = "FB", 75.00, 75.03, 74.90
>>> high = stock[2]
>>> high
75.03

```

我们甚至可以使用切片表示法来提取元组的较大部分：

```py
>>> stock[1:3]
(75.00, 75.03)

```

这些例子展示了元组的灵活性，但也展示了它们的一个主要缺点：可读性。阅读这段代码的人怎么知道特定元组的第二个位置是什么？他们可以猜测，从我们分配给它的变量名，它是某种“高”，但如果我们在计算中只是访问了元组的值而没有分配它，就没有这样的指示。他们必须在代码中搜索元组声明的位置，然后才能发现它的作用。

直接访问元组成员在某些情况下是可以的，但不要养成这样的习惯。这种所谓的“魔术数字”（似乎毫无意义地出现在代码中的数字）是许多编码错误的根源，并导致了数小时的沮丧调试。尽量只在你知道所有的值一次性都会有用，并且在访问时通常会被解包时使用元组。如果必须直接访问成员或使用切片，并且该值的目的不是立即明显的，至少要包含一个解释它来自哪里的注释。

## 命名元组

那么，当我们想要将值组合在一起，但知道我们经常需要单独访问它们时，我们该怎么办？嗯，我们可以使用空对象，如前一节中讨论的（但除非我们预期稍后添加行为，否则很少有用），或者我们可以使用字典（如果我们不知道将存储多少个或哪些特定数据，这是最有用的），我们将在下一节中介绍。

然而，如果我们不需要向对象添加行为，并且事先知道需要存储哪些属性，我们可以使用命名元组。命名元组是带有态度的元组。它们是将只读数据组合在一起的绝佳方式。

构造命名元组比普通元组需要更多的工作。首先，我们必须导入`namedtuple`，因为它不是默认的命名空间中。然后，我们通过给它一个名称并概述其属性来描述命名元组。这将返回一个类似的对象，我们可以根据需要实例化多次：

```py
from collections import namedtuple
Stock = namedtuple("Stock", "symbol current high low")
stock = Stock("FB", 75.00, high=75.03, low=74.90)
```

`namedtuple`构造函数接受两个参数。第一个是命名元组的标识符。第二个是命名元组可以具有的以空格分隔的属性字符串。应该列出第一个属性，然后是一个空格（或者如果你喜欢，逗号），然后是第二个属性，然后是另一个空格，依此类推。结果是一个可以像普通类一样调用的对象，以实例化其他对象。构造函数必须具有可以作为参数或关键字参数传递的恰好正确数量的参数。与普通对象一样，我们可以创建任意数量的此“类”的实例，并为每个实例提供不同的值。

然后，生成的`namedtuple`可以像普通元组一样打包、解包和以其他方式处理，但我们也可以像访问对象一样访问它的单个属性：

```py
>>> stock.high
75.03
>>> symbol, current, high, low = stock
>>> current
75.00

```

### 提示

请记住，创建命名元组是一个两步过程。首先，使用`collections.namedtuple`创建一个类，然后构造该类的实例。

命名元组非常适合许多“仅数据”表示，但并非适用于所有情况。与元组和字符串一样，命名元组是不可变的，因此一旦设置了属性，就无法修改属性。例如，自从我们开始讨论以来，我的公司股票的当前价值已经下跌，但我们无法设置新值：

```py
>>> stock.current = 74.98
Traceback (most recent call last):
 **File "<stdin>", line 1, in <module>
AttributeError: can't set attribute

```

如果我们需要能够更改存储的数据，可能需要使用字典。

# 字典

字典是非常有用的容器，允许我们直接将对象映射到其他对象。具有属性的空对象是一种字典；属性的名称映射到属性值。这实际上比听起来更接近事实；在内部，对象通常将属性表示为字典，其中值是对象上的属性或方法（如果你不相信我，请查看`__dict__`属性）。甚至模块上的属性也是在字典中存储的。

字典在查找特定键对象映射到该值时非常高效。当您想要根据其他对象找到一个对象时，应该始终使用它们。被存储的对象称为**值**；用作索引的对象称为**键**。我们已经在一些先前的示例中看到了字典语法。

字典可以使用`dict()`构造函数或使用`{}`语法快捷方式创建。实际上，几乎总是使用后一种格式。我们可以通过使用冒号分隔键和值，并使用逗号分隔键值对来预填充字典。

例如，在股票应用程序中，我们最常常希望按股票符号查找价格。我们可以创建一个使用股票符号作为键，当前价格、最高价格和最低价格的元组作为值的字典，如下所示：

```py
stocks = {"GOOG": (613.30, 625.86, 610.50),
          "MSFT": (30.25, 30.70, 30.19)}
```

正如我们在之前的例子中看到的，我们可以通过在方括号内请求一个键来查找字典中的值。如果键不在字典中，它会引发一个异常：

```py
>>> stocks["GOOG"]
(613.3, 625.86, 610.5)
>>> stocks["RIM"]
Traceback (most recent call last):
 **File "<stdin>", line 1, in <module>
KeyError: 'RIM'

```

当然，我们可以捕获`KeyError`并处理它。但我们还有其他选择。记住，字典是对象，即使它们的主要目的是保存其他对象。因此，它们有几种与之相关的行为。其中最有用的方法之一是`get`方法；它接受一个键作为第一个参数，以及一个可选的默认值（如果键不存在）：

```py
>>> print(stocks.get("RIM"))
None
>>> stocks.get("RIM", "NOT FOUND")
'NOT FOUND'

```

为了更多的控制，我们可以使用`setdefault`方法。如果键在字典中，这个方法的行为就像`get`一样；它返回该键的值。否则，如果键不在字典中，它不仅会返回我们在方法调用中提供的默认值（就像`get`一样），它还会将键设置为相同的值。另一种思考方式是，`setdefault`只有在该值以前没有被设置时才在字典中设置一个值。然后它返回字典中的值，无论是已经存在的值，还是新提供的默认值。

```py
>>> stocks.setdefault("GOOG", "INVALID")
(613.3, 625.86, 610.5)
>>> stocks.setdefault("BBRY", (10.50, 10.62, 10.39))
(10.50, 10.62, 10.39)
>>> stocks["BBRY"]
(10.50, 10.62, 10.39)

```

`GOOG`股票已经在字典中，所以当我们尝试将其`setdefault`为一个无效值时，它只是返回了已经在字典中的值。`BBRY`不在字典中，所以`setdefault`返回了默认值，并为我们在字典中设置了新值。然后我们检查新的股票是否确实在字典中。

另外三个非常有用的字典方法是`keys()`，`values()`和`items()`。前两个返回字典中所有键和所有值的迭代器。如果我们想要处理所有键或值，我们可以像列表一样使用它们，或者在`for`循环中使用它们。`items()`方法可能是最有用的；它返回一个元组的迭代器，其中包含字典中每个项目的`(key, value)`对。这与在`for`循环中使用元组解包很好地配合，以循环遍历相关的键和值。这个例子就是这样做的，以打印出字典中每个股票及其当前值：

```py
>>> for stock, values in stocks.items():
...     print("{} last value is {}".format(stock, values[0]))
...
GOOG last value is 613.3
BBRY last value is 10.50
MSFT last value is 30.25

```

每个键/值元组都被解包成两个名为`stock`和`values`的变量（我们可以使用任何我们想要的变量名，但这两个似乎都合适），然后以格式化的字符串打印出来。

请注意，股票并没有按照插入的顺序显示出来。由于用于使键查找如此快速的高效算法（称为哈希），字典本身是无序的。

因此，一旦字典被实例化，就有许多种方法可以从中检索数据；我们可以使用方括号作为索引语法，`get`方法，`setdefault`方法，或者遍历`items`方法，等等。

最后，你可能已经知道，我们可以使用与检索值相同的索引语法来在字典中设置一个值：

```py
>>> stocks["GOOG"] = (597.63, 610.00, 596.28)
>>> stocks['GOOG']
(597.63, 610.0, 596.28)

```

谷歌的价格今天较低，所以我更新了字典中元组的值。我们可以使用这种索引语法为任何键设置一个值，而不管该键是否在字典中。如果它在字典中，旧值将被新值替换；否则，将创建一个新的键/值对。

到目前为止，我们一直在使用字符串作为字典的键，但我们并不局限于字符串键。通常在存储数据以便将其聚集在一起时，使用字符串作为键是很常见的（而不是使用具有命名属性的对象）。但我们也可以使用元组、数字，甚至是我们自己定义的对象作为字典的键。我们甚至可以在单个字典中使用不同类型的键：

```py
random_keys = {}
random_keys["astring"] = "somestring"
random_keys[5] = "aninteger"
random_keys[25.2] = "floats work too"
random_keys[("abc", 123)] = "so do tuples"

class AnObject:
    def __init__(self, avalue):
        self.avalue = avalue

my_object = AnObject(14)
random_keys[my_object] = "We can even store objects"
my_object.avalue = 12
try:
    random_keys[[1,2,3]] = "we can't store lists though"
except:
    print("unable to store list\n")

for key, value in random_keys.items():
    print("{} has value {}".format(key, value))
```

这段代码展示了我们可以提供给字典的几种不同类型的键。它还展示了一种不能使用的对象类型。我们已经广泛使用了列表，并且在下一节中将看到更多关于它们的细节。因为列表可以随时更改（例如通过添加或删除项目），它们无法哈希到一个特定的值。

具有**可哈希性**的对象基本上具有一个定义好的算法，将对象转换为唯一的整数值，以便快速查找。这个哈希值实际上是用来在字典中查找值的。例如，字符串根据字符串中的字符映射到整数，而元组则组合了元组内部项目的哈希值。任何两个被视为相等的对象（比如具有相同字符的字符串或具有相同值的元组）应该具有相同的哈希值，并且对象的哈希值永远不应该改变。然而，列表的内容可以改变，这会改变它们的哈希值（只有当列表的内容相同时，两个列表才应该相等）。因此，它们不能用作字典的键。出于同样的原因，字典也不能用作其他字典的键。

相比之下，对于可以用作字典值的对象类型没有限制。例如，我们可以使用字符串键映射到列表值，或者我们可以在另一个字典中将嵌套字典作为值。

## 字典的用例

字典非常灵活，有很多用途。字典可以有两种主要用法。第一种是所有键表示类似对象的不同实例的字典；例如，我们的股票字典。这是一个索引系统。我们使用股票符号作为值的索引。这些值甚至可以是复杂的自定义对象，而不是我们简单的元组。

第二种设计是每个键表示单个结构的某个方面的字典；在这种情况下，我们可能会为每个对象使用一个单独的字典，并且它们都具有相似（尽管通常不完全相同）的键集。这种情况通常也可以用命名元组解决。当我们确切地知道数据必须存储的属性，并且知道所有数据必须一次性提供（在构造项目时）时，应该使用这些。但是，如果我们需要随时间创建或更改字典键，或者我们不知道键可能是什么，那么字典更合适。

## 使用 defaultdict

我们已经看到如何使用`setdefault`来设置默认值，如果键不存在，但是如果我们需要每次查找值时都设置默认值，这可能会有点单调。例如，如果我们正在编写代码来计算给定句子中字母出现的次数，我们可以这样做：

```py
def letter_frequency(sentence):
    frequencies = {}
    for letter in sentence:
        **frequency = frequencies.setdefault(letter, 0)
        frequencies[letter] = frequency + 1
    return frequencies
```

每次访问字典时，我们需要检查它是否已经有一个值，如果没有，将其设置为零。当每次请求一个空键时需要做这样的事情时，我们可以使用字典的另一个版本，称为`defaultdict`：

```py
from collections import defaultdict
def letter_frequency(sentence):
    **frequencies = defaultdict(int)
    for letter in sentence:
        frequencies[letter] += 1
    return frequencies
```

这段代码看起来似乎不可能工作。`defaultdict`在其构造函数中接受一个函数。每当访问一个不在字典中的键时，它调用该函数，不带任何参数，以创建一个默认值。

在这种情况下，它调用的函数是`int`，这是整数对象的构造函数。通常，整数是通过在代码中键入整数来创建的，如果我们使用`int`构造函数创建一个整数，我们将传递要创建的项目（例如，将数字字符串转换为整数）。但是，如果我们在没有任何参数的情况下调用`int`，它会方便地返回数字零。在这段代码中，如果字母不存在于`defaultdict`中，当我们访问它时将返回数字零。然后我们将这个数字加一，以表示我们找到了该字母的一个实例，下次再找到一个实例时，将返回该数字，然后我们可以再次递增该值。

`defaultdict`对于创建容器字典非常有用。如果我们想要创建一个过去 30 天股票价格的字典，我们可以使用股票符号作为键，并将价格存储在`list`中；第一次访问股票价格时，我们希望它创建一个空列表。只需将`list`传递给`defaultdict`，它将在每次访问空键时被调用。如果我们想要将一个集合或者一个空字典与一个键关联起来，我们也可以做类似的事情。

当然，我们也可以编写自己的函数并将它们传递给`defaultdict`。假设我们想创建一个`defaultdict`，其中每个新元素都包含一个元组，该元组包含了在该时间插入字典中的项目数和一个空列表来保存其他东西。没有人知道为什么我们要创建这样一个对象，但让我们来看一下：

```py
from collections import defaultdict
num_items = 0
def tuple_counter():
    global num_items
    num_items += 1
    return (num_items, [])

d = defaultdict(tuple_counter)

```

当我们运行这段代码时，我们可以在一个语句中访问空键并插入列表：

```py
>>> d = defaultdict(tuple_counter)
>>> d['a'][1].append("hello")
>>> d['b'][1].append('world')
>>> d
defaultdict(<function tuple_counter at 0x82f2c6c>,
{'a': (1, ['hello']), 'b': (2, ['world'])})

```

当我们在最后打印`dict`时，我们看到计数器确实在工作。

### 注意

这个例子虽然简洁地演示了如何为`defaultdict`创建自己的函数，但实际上并不是很好的代码；使用全局变量意味着如果我们创建了四个不同的`defaultdict`段，每个段都使用了`tuple_counter`，它将计算所有字典中的条目数，而不是为每个字典单独计数。最好创建一个类，并将该类的方法传递给`defaultdict`。

### 计数器

您可能会认为`defaultdict(int)`比这更简单，但“我想要计算可迭代对象中特定实例的数量”这种用例是足够常见，以至于 Python 开发人员为此创建了一个特定的类。在一个单行中很容易计算以前的代码中字符串中的字符数量：

```py
from collections import Counter
def letter_frequency(sentence):
    return Counter(sentence)
```

`Counter`对象的行为类似于一个强化的字典，其中键是被计数的项目，值是这些项目的数量。其中最有用的函数之一是`most_common()`方法。它返回一个按计数排序的（键，计数）元组列表。您还可以选择将整数参数传递给`most_common()`，以请求仅返回最常见的元素。例如，您可以编写一个简单的投票应用程序如下：

```py
from collections import Counter

responses = [
    "vanilla",
    "chocolate",
    "vanilla",
    "vanilla",
    "caramel",
    "strawberry",
    "vanilla"
]

print(
    "The children voted for {} ice cream".format(
        Counter(responses).most_common(1)[0][0]
    )
)
```

据推测，您可以从数据库中获取响应，或者使用复杂的视觉算法来计算举手的孩子。在这里，我们将其硬编码，以便我们可以测试`most_common`方法。它返回一个只有一个元素的列表（因为我们在参数中请求了一个元素）。这个元素在位置零存储了最受欢迎的选择的名称，因此在调用结束时有两个`[0][0]`。我觉得它们看起来像是一个惊讶的脸，你觉得呢？你的计算机可能对它能够如此轻松地计数数据感到惊讶。它的祖先，霍勒里斯的 1890 年美国人口普查用的整理机，一定会非常嫉妒！

# 列表

列表是 Python 数据结构中最不面向对象的。虽然列表本身是对象，但在 Python 中有很多语法可以尽可能地减少它们的使用痛苦。与许多其他面向对象的语言不同，Python 中的列表是直接可用的。我们不需要导入它们，也很少需要调用它们的方法。我们可以在不明确请求迭代器对象的情况下循环遍历列表，并且可以使用自定义语法构造列表（与字典一样）。此外，列表推导和生成器表达式将它们转变为计算功能的多功能工具。

我们不会过多介绍语法；你在网络上的入门教程和本书中的先前示例中已经见过它。你不能长时间编写 Python 代码而不学会如何使用列表！相反，我们将介绍何时应该使用列表以及它们作为对象的性质。如果你不知道如何创建或附加到列表，如何从列表中检索项目，或者什么是“切片表示法”，我建议你立即查看官方 Python 教程。它可以在[`docs.python.org/3/tutorial/`](http://docs.python.org/3/tutorial/)上找到。

在 Python 中，当我们想要存储“相同”类型的对象的多个实例时，通常应该使用列表；字符串列表或数字列表；最常见的是我们自己定义的对象列表。当我们想要按某种顺序存储项目时，应该始终使用列表。通常，这是它们被插入的顺序，但它们也可以按某些标准排序。

正如我们在上一章的案例研究中看到的，当我们需要修改内容时，列表也非常有用：在列表的任意位置插入或删除，或者更新列表中的值。

与字典一样，Python 列表使用非常高效和良好调整的内部数据结构，因此我们可以关注我们存储的内容，而不是我们如何存储它。许多面向对象的语言为队列、栈、链表和基于数组的列表提供了不同的数据结构。如果需要优化对大量数据的访问，Python 确实提供了这些类的特殊实例。然而，通常情况下，列表数据结构可以同时满足所有这些目的，并且编码人员可以完全控制他们如何访问它。

不要使用列表来收集单个项目的不同属性。例如，我们不希望一个特定形状的属性列表。元组、命名元组、字典和对象都更适合这个目的。在某些语言中，它们可能创建一个列表，其中每个交替项是不同的类型；例如，他们可能为我们的字母频率列表写`['a', 1, 'b', 3]`。他们必须使用一个奇怪的循环，一次访问两个元素，或者使用模运算符来确定正在访问的位置。

在 Python 中不要这样做。我们可以使用字典将相关项目分组在一起，就像我们在上一节中所做的那样（如果排序顺序不重要），或者使用元组列表。下面是一个相当复杂的示例，演示了我们如何使用列表来进行频率示例。它比字典示例复杂得多，并且说明了选择正确（或错误）的数据结构对我们代码的可读性产生的影响。

```py
import string
CHARACTERS  = list(string.ascii_letters) + [" "]

def letter_frequency(sentence):
    **frequencies = [(c, 0) for c in CHARACTERS]
    for letter in sentence:
        index = CHARACTERS.index(letter)
        **frequencies[index] = (letter,frequencies[index][1]+1)
    return frequencies
```

这段代码以可能的字符列表开始。`string.ascii_letters`属性提供了一个按顺序排列的所有字母（大写和小写）的字符串。我们将其转换为列表，然后使用列表连接（加号运算符将两个列表合并为一个）添加一个额外的字符，即空格。这些是我们频率列表中可用的字符（如果我们尝试添加不在列表中的字母，代码将会出错，但可以使用异常处理程序来解决这个问题）。

函数内的第一行使用列表推导将`CHARACTERS`列表转换为元组列表。列表推导是 Python 中一个重要的非面向对象的工具；我们将在下一章详细介绍它们。

然后我们循环遍历句子中的每个字符。我们首先查找`CHARACTERS`列表中字符的索引，我们知道它在我们的频率列表中具有相同的索引，因为我们刚刚从第一个列表创建了第二个列表。然后我们通过创建一个新元组来更新频率列表中的索引，丢弃原始元组。除了垃圾收集和内存浪费的担忧外，这是相当难以阅读的！

像字典一样，列表也是对象，并且有几种可以在它们上调用的方法。以下是一些常见的方法：

+   `append(element)`方法将一个元素添加到列表的末尾

+   `insert(index, element)`方法在特定位置插入一个项目

+   `count(element)`方法告诉我们一个元素在列表中出现了多少次

+   `index()`方法告诉我们列表中项目的索引，如果找不到它会引发异常

+   `find()`方法也是做同样的事情，但是找不到项目时返回`-1`而不是引发异常

+   `reverse()`方法确实做了它所说的事情——将列表倒转过来

+   `sort()`方法具有一些相当复杂的面向对象的行为，我们现在来介绍一下

## 排序列表

没有任何参数时，`sort`通常会做预期的事情。如果是字符串列表，它会按字母顺序排列。这个操作是区分大小写的，所以所有大写字母会排在小写字母之前，即`Z`排在`a`之前。如果是数字列表，它们将按数字顺序排序。如果提供了一个包含不可排序项目的混合列表，排序将引发`TypeError`异常。

如果我们想把自己定义的对象放入列表并使这些对象可排序，我们需要做更多的工作。类上应该定义特殊方法`__lt__`，它代表“小于”，以使该类的实例可比较。列表上的`sort`方法将访问每个对象上的这个方法来确定它在列表中的位置。如果我们的类在某种程度上小于传递的参数，则该方法应返回`True`，否则返回`False`。下面是一个相当愚蠢的类，它可以根据字符串或数字进行排序：

```py
class WeirdSortee:
    def __init__(self, string, number, sort_num):
        self.string = string
        self.number = number
        self.sort_num = sort_num

    **def __lt__(self, object):
        **if self.sort_num:
            **return self.number < object.number
        **return self.string < object.string

    def __repr__(self):
        return"{}:{}".format(self.string, self.number)
```

`__repr__`方法使我们在打印列表时很容易看到这两个值。`__lt__`方法的实现将对象与相同类的另一个实例（或具有`string`、`number`和`sort_num`属性的任何鸭子类型对象；如果这些属性缺失，它将失败）进行比较。以下输出展示了这个类在排序时的工作原理：

```py
>>> a = WeirdSortee('a', 4, True)
>>> b = WeirdSortee('b', 3, True)
>>> c = WeirdSortee('c', 2, True)
>>> d = WeirdSortee('d', 1, True)
>>> l = [a,b,c,d]
>>> l
[a:4, b:3, c:2, d:1]
>>> l.sort()
>>> l
[d:1, c:2, b:3, a:4]
>>> for i in l:
...     i.sort_num = False
...
>>> l.sort()
>>> l
[a:4, b:3, c:2, d:1]

```

第一次调用`sort`时，它按数字排序，因为所有被比较的对象上的`sort_num`都是`True`。第二次，它按字母排序。我们只需要实现`__lt__`方法来启用排序。然而，从技术上讲，如果实现了它，类通常还应该实现类似的`__gt__`、`__eq__`、`__ne__`、`__ge__`和`__le__`方法，以便所有的`<`、`>`、`==`、`!=`、`>=`和`<=`操作符也能正常工作。通过实现`__lt__`和`__eq__`，然后应用`@total_ordering`类装饰器来提供其余的方法，你可以免费获得这些方法：

```py
from functools import total_ordering

@total_ordering
class WeirdSortee:
    def __init__(self, string, number, sort_num):
        self.string = string
        self.number = number
        self.sort_num = sort_num

    def __lt__(self, object):
        if self.sort_num:
            return self.number < object.number
        return self.string < object.string

    def __repr__(self):
        return"{}:{}".format(self.string, self.number)

    def __eq__(self, object):
        return all((
            self.string == object.string,
            self.number == object.number,
            self.sort_num == object.number
        ))
```

如果我们想要能够在我们的对象上使用运算符，这是很有用的。然而，如果我们只想自定义我们的排序顺序，即使这样也是过度的。对于这样的用例，`sort`方法可以接受一个可选的`key`参数。这个参数是一个函数，可以将列表中的每个对象转换为某种可比较的对象。例如，我们可以使用`str.lower`作为键参数，在字符串列表上执行不区分大小写的排序：

```py
>>> l = ["hello", "HELP", "Helo"]
>>> l.sort()
>>> l
['HELP', 'Helo', 'hello']
>>> l.sort(key=str.lower)
>>> l
['hello', 'Helo', 'HELP']

```

记住，即使`lower`是字符串对象上的一个方法，它也是一个可以接受单个参数`self`的函数。换句话说，`str.lower(item)`等同于`item.lower()`。当我们将这个函数作为键传递时，它会对小写值进行比较，而不是进行默认的区分大小写比较。

有一些排序键操作是如此常见，以至于 Python 团队已经提供了它们，这样你就不必自己编写了。例如，通常常见的是按列表中的第一个项目之外的其他内容对元组列表进行排序。`operator.itemgetter`方法可以用作键来实现这一点：

```py
>>> from operator import itemgetter
>>> l = [('h', 4), ('n', 6), ('o', 5), ('p', 1), ('t', 3), ('y', 2)]
>>> l.sort(key=itemgetter(1))
>>> l
[('p', 1), ('y', 2), ('t', 3), ('h', 4), ('o', 5), ('n', 6)]

```

`itemgetter`函数是最常用的一个（如果对象是字典，它也可以工作），但有时你会发现`attrgetter`和`methodcaller`也很有用，它们返回对象的属性和对象的方法调用的结果，用于相同的目的。有关更多信息，请参阅`operator`模块文档。

# 集合

列表是非常多才多艺的工具，适用于大多数容器对象应用。但是当我们想要确保列表中的对象是唯一的时，它们就不太有用了。例如，歌曲库可能包含同一位艺术家的许多歌曲。如果我们想要整理库并创建所有艺术家的列表，我们必须检查列表，看看我们是否已经添加了艺术家，然后再添加他们。

这就是集合的用武之地。集合来自数学，它们代表一个无序的（通常是）唯一数字的组。我们可以将一个数字添加到集合五次，但它只会出现一次。

在 Python 中，集合可以容纳任何可散列的对象，不仅仅是数字。可散列的对象与字典中可以用作键的对象相同；所以再次，列表和字典都不行。像数学集合一样，它们只能存储每个对象的一个副本。因此，如果我们试图创建一个歌手名单，我们可以创建一个字符串名称的集合，并简单地将它们添加到集合中。这个例子从一个（歌曲，艺术家）元组列表开始，并创建了一个艺术家的集合：

```py
song_library = [("Phantom Of The Opera", "Sarah Brightman"),
        ("Knocking On Heaven's Door", "Guns N' Roses"),
        ("Captain Nemo", "Sarah Brightman"),
        ("Patterns In The Ivy", "Opeth"),
        ("November Rain", "Guns N' Roses"),
        ("Beautiful", "Sarah Brightman"),
        ("Mal's Song", "Vixy and Tony")]

artists = set()
for song, artist in song_library:
    **artists.add(artist)

print(artists)
```

与列表和字典一样，没有内置的空集语法；我们使用`set()`构造函数创建一个集合。然而，我们可以使用花括号（从字典语法中借用）来创建一个集合，只要集合包含值。如果我们使用冒号来分隔值对，那就是一个字典，比如`{'key': 'value', 'key2': 'value2'}`。如果我们只用逗号分隔值，那就是一个集合，比如`{'value', 'value2'}`。可以使用`add`方法将项目单独添加到集合中。如果运行此脚本，我们会看到集合按照广告中的方式工作：

```py
{'Sarah Brightman', "Guns N' Roses", 'Vixy and Tony', 'Opeth'}

```

如果你注意输出，你会注意到项目的打印顺序并不是它们添加到集合中的顺序。集合和字典一样，是无序的。它们都使用基于哈希的数据结构来提高效率。因为它们是无序的，集合不能通过索引查找项目。集合的主要目的是将世界分为两组：“在集合中的事物”和“不在集合中的事物”。检查一个项目是否在集合中或循环遍历集合中的项目很容易，但如果我们想要对它们进行排序或排序，我们就必须将集合转换为列表。这个输出显示了这三种活动：

```py
>>> "Opeth" in artists
True
>>> for artist in artists:
...     print("{} plays good music".format(artist))
...
Sarah Brightman plays good music
Guns N' Roses plays good music
Vixy and Tony play good music
Opeth plays good music
>>> alphabetical = list(artists)
>>> alphabetical.sort()
>>> alphabetical
["Guns N' Roses", 'Opeth', 'Sarah Brightman', 'Vixy and Tony']

```

集合的主要*特征*是唯一性，但这并不是它的主要*目的*。当两个或更多个集合组合使用时，集合最有用。集合类型上的大多数方法都作用于其他集合，允许我们有效地组合或比较两个或更多个集合中的项目。这些方法有奇怪的名称，因为它们使用数学中使用的相同术语。我们将从三种返回相同结果的方法开始，不管哪个是调用集合，哪个是被调用集合。

`union`方法是最常见和最容易理解的。它将第二个集合作为参数，并返回一个新集合，其中包含两个集合中*任何一个*的所有元素；如果一个元素在两个原始集合中，它当然只会在新集合中出现一次。联合就像一个逻辑的`or`操作，实际上，`|`运算符可以用于两个集合执行联合操作，如果你不喜欢调用方法。

相反，交集方法接受第二个集合并返回一个新集合，其中只包含*两个*集合中的元素。这就像一个逻辑的`and`操作，并且也可以使用`&`运算符来引用。

最后，`symmetric_difference` 方法告诉我们剩下什么；它是一个集合，其中包含一个集合或另一个集合中的对象，但不包含两者都有的对象。以下示例通过比较我的歌曲库中的一些艺术家和我妹妹的歌曲库中的艺术家来说明这些方法：

```py
my_artists = {"Sarah Brightman", "Guns N' Roses",
        "Opeth", "Vixy and Tony"}

auburns_artists = {"Nickelback", "Guns N' Roses",
        "Savage Garden"}

print("All: {}".format(my_artists.union(auburns_artists)))
print("Both: {}".format(auburns_artists.intersection(my_artists)))
print("Either but not both: {}".format(
    my_artists.symmetric_difference(auburns_artists)))
```

如果我们运行这段代码，我们会发现这三种方法确实做了打印语句所暗示的事情：

```py
All: {'Sarah Brightman', "Guns N' Roses", 'Vixy and Tony',
'Savage Garden', 'Opeth', 'Nickelback'}
Both: {"Guns N' Roses"}
Either but not both: {'Savage Garden', 'Opeth', 'Nickelback',
'Sarah Brightman', 'Vixy and Tony'}

```

这些方法无论哪个集合调用另一个集合，都会返回相同的结果。我们可以说 `my_artists.union(auburns_artists)` 或 `auburns_artists.union(my_artists)`，结果都是一样的。还有一些方法，根据调用者和参数的不同会返回不同的结果。

这些方法包括 `issubset` 和 `issuperset`，它们是彼此的反义。两者都返回一个 `bool` 值。`issubset` 方法返回 `True`，如果调用集合中的所有项也在作为参数传递的集合中。`issuperset` 方法返回 `True`，如果参数中的所有项也在调用集合中。因此 `s.issubset(t)` 和 `t.issuperset(s)` 是相同的。如果 `t` 包含了 `s` 中的所有元素，它们都会返回 `True`。

最后，`difference` 方法返回调用集合中的所有元素，但不在作为参数传递的集合中；这类似于`symmetric_difference` 的一半。`difference` 方法也可以用 `-` 运算符表示。以下代码说明了这些方法的运行方式：

```py
my_artists = {"Sarah Brightman", "Guns N' Roses",
        "Opeth", "Vixy and Tony"}

bands = {"Guns N' Roses", "Opeth"}

print("my_artists is to bands:")
print("issuperset: {}".format(my_artists.issuperset(bands)))
print("issubset: {}".format(my_artists.issubset(bands)))
print("difference: {}".format(my_artists.difference(bands)))
print("*"*20)
print("bands is to my_artists:")
print("issuperset: {}".format(bands.issuperset(my_artists)))
print("issubset: {}".format(bands.issubset(my_artists)))
print("difference: {}".format(bands.difference(my_artists)))
```

这段代码简单地打印出了在一个集合上调用另一个集合时每个方法的响应。运行代码会得到以下输出：

```py
my_artists is to bands:
issuperset: True
issubset: False
difference: {'Sarah Brightman', 'Vixy and Tony'}
********************
bands is to my_artists:
issuperset: False
issubset: True
difference: set()

```

在第二种情况下，`difference` 方法返回一个空集，因为 `bands` 中没有不在 `my_artists` 中的项目。

`union`、`intersection` 和 `difference` 方法都可以接受多个集合作为参数；它们会返回我们所期望的，即在调用所有参数时创建的集合。

因此，集合上的方法清楚地表明集合是用来操作其他集合的，并且它们不仅仅是容器。如果我们有来自两个不同来源的数据，并且需要快速地以某种方式将它们合并，以确定数据重叠或不同之处，我们可以使用集合操作来高效地比较它们。或者，如果我们有可能包含已经处理过的数据的重复数据，我们可以使用集合来比较这两者，并仅处理新数据。

最后，了解到在使用 `in` 关键字检查成员资格时，集合比列表要高效得多。如果在集合或列表上使用语法 `value in container`，如果 `container` 中的一个元素等于 `value`，则返回 `True`，否则返回 `False`。但是，在列表中，它会查看容器中的每个对象，直到找到该值，而在集合中，它只是对该值进行哈希处理并检查成员资格。这意味着集合将以相同的时间找到值，无论容器有多大，但列表在搜索值时会花费越来越长的时间，因为列表包含的值越来越多。

# 扩展内置对象

我们在第三章中简要讨论了内置数据类型如何使用继承进行扩展。现在，我们将更详细地讨论何时需要这样做。

当我们有一个内置容器对象需要添加功能时，我们有两个选择。我们可以创建一个新对象，将该容器作为属性（组合），或者我们可以对内置对象进行子类化，并添加或调整方法以实现我们想要的功能（继承）。

如果我们只想使用容器来存储一些对象，使用组合通常是最好的选择，使用容器的特性。这样，很容易将数据结构传递到其他方法中，它们将知道如何与它交互。但是，如果我们想要改变容器的实际工作方式，我们需要使用继承。例如，如果我们想要确保`list`中的每个项目都是一个具有确切五个字符的字符串，我们需要扩展`list`并覆盖`append()`方法以引发无效输入的异常。我们还至少需要覆盖`__setitem__(self, index, value)`，这是列表上的一个特殊方法，每当我们使用`x[index] = "value"`语法时都会调用它，以及`extend()`方法。

是的，列表是对象。我们一直在访问列表或字典键，循环容器以及类似任务的特殊非面向对象的语法实际上是“语法糖”，它映射到对象导向范式下面。我们可能会问 Python 设计者为什么这样做。难道面向对象编程*总是*更好吗？这个问题很容易回答。在下面的假设例子中，哪个更容易阅读，作为程序员？哪个需要输入更少？

```py
c = a + b
c = a.add(b)

l[0] = 5
l.setitem(0, 5)
d[key] = value
d.setitem(key, value)

for x in alist:
    #do something with x
it = alist.iterator()
while it.has_next():
 **x = it.next()
    **#do something with x

```

突出显示的部分展示了面向对象的代码可能是什么样子（实际上，这些方法实际上存在于相关对象的特殊双下划线方法中）。Python 程序员一致认为，非面向对象的语法更容易阅读和编写。然而，所有前述的 Python 语法都映射到面向对象的方法下面。这些方法有特殊的名称（在前后都有双下划线），提醒我们有更好的语法。但是，它给了我们覆盖这些行为的手段。例如，我们可以创建一个特殊的整数，当我们将两个整数相加时总是返回`0`：

```py
class SillyInt(int):
    **def __add__(self, num):
        return 0
```

这是一个极端奇怪的事情，毫无疑问，但它完美地诠释了这些面向对象的原则：

```py
>>> a = SillyInt(1)
>>> b = SillyInt(2)
>>> a + b
0

```

`__add__`方法的绝妙之处在于我们可以将其添加到我们编写的任何类中，如果我们在该类的实例上使用`+`运算符，它将被调用。这就是字符串、元组和列表连接的工作原理，例如。

这适用于所有特殊方法。如果我们想要为自定义对象使用`x in myobj`语法，我们可以实现`__contains__`。如果我们想要使用`myobj[i] = value`语法，我们提供一个`__setitem__`方法，如果我们想要使用`something = myobj[i]`，我们实现`__getitem__`。

`list`类上有 33 个这样的特殊方法。我们可以使用`dir`函数查看所有这些方法：

```py
>>> dir(list)

['__add__', '__class__', '__contains__', '__delattr__','__delitem__', '__doc__', '__eq__', '__format__', '__ge__', '__getattribute__', '__getitem__', '__gt__', '__hash__', '__iadd__', '__imul__', '__init__', '__iter__', '__le__', '__len__', '__lt__', '__mul__', '__ne__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__reversed__', '__rmul__', '__setattr__', '__setitem__', '__sizeof__', '__str__', '__subclasshook__', 'append', 'count', 'extend', 'index', 'insert', 'pop', 'remove', 'reverse', 'sort'

```

此外，如果我们想要了解这些方法的工作方式的其他信息，我们可以使用`help`函数：

```py
>>> help(list.__add__)
Help on wrapper_descriptor:

__add__(self, value, /)
 **Return self+value.

```

列表上的加号运算符连接两个列表。我们没有空间来讨论本书中所有可用的特殊函数，但是现在您可以使用`dir`和`help`来探索所有这些功能。官方在线 Python 参考([`docs.python.org/3/`](https://docs.python.org/3/))也有很多有用的信息。特别关注`collections`模块中讨论的抽象基类。

因此，回到之前关于何时使用组合与继承的观点：如果我们需要以某种方式更改类上的任何方法，包括特殊方法，我们绝对需要使用继承。如果我们使用组合，我们可以编写执行验证或更改的方法，并要求调用者使用这些方法，但没有任何阻止他们直接访问属性。他们可以向我们的列表中插入一个不具有五个字符的项目，这可能会使列表中的其他方法感到困惑。

通常，需要扩展内置数据类型是使用错误类型的数据类型的迹象。这并不总是这样，但是如果我们想要扩展内置的话，我们应该仔细考虑是否不同的数据结构更合适。

例如，考虑创建一个记住插入键的顺序的字典需要做些什么。做到这一点的一种方法是保持一个有序的键列表，该列表存储在 `dict` 的特殊派生子类中。然后我们可以覆盖方法 `keys`、`values`、`__iter__` 和 `items` 以按顺序返回所有内容。当然，我们还必须覆盖 `__setitem__` 和 `setdefault` 以保持我们的列表最新。在 `dir(dict)` 的输出中可能还有一些其他方法需要覆盖以保持列表和字典一致（`clear` 和 `__delitem__` 记录了何时删除项目），但是在这个例子中我们不用担心它们。

因此，我们将扩展 `dict` 并添加一个有序键列表。这很简单，但我们在哪里创建实际的列表呢？我们可以将它包含在 `__init__` 方法中，这样就可以正常工作，但我们不能保证任何子类都会调用该初始化程序。还记得我们在第二章中讨论过的 `__new__` 方法吗？我说它通常只在非常特殊的情况下有用。这就是其中之一。我们知道 `__new__` 将被调用一次，并且我们可以在新实例上创建一个列表，该列表将始终对我们的类可用。考虑到这一点，这就是我们整个排序字典：

```py
from collections import KeysView, ItemsView, ValuesView
class DictSorted(dict):
    def __new__(*args, **kwargs):
        new_dict = dict.__new__(*args, **kwargs)
        new_dict.ordered_keys = []
        return new_dict

    def __setitem__(self, key, value):
        '''self[key] = value syntax'''
        if key not in self.ordered_keys:
            self.ordered_keys.append(key)
        super().__setitem__(key, value)

    def setdefault(self, key, value):
        if key not in self.ordered_keys:
            self.ordered_keys.append(key)
        return super().setdefault(key, value)

    def keys(self):
        return KeysView(self)

    def values(self):
        return ValuesView(self)

    def items(self):
        return ItemsView(self)

    def __iter__(self):
        '''for x in self syntax'''
        return self.ordered_keys.__iter__()
```

`__new__` 方法创建一个新的字典，然后在该对象上放置一个空列表。我们不覆盖 `__init__`，因为默认实现有效（实际上，只有在我们初始化一个空的 `DictSorted` 对象时才是真的。如果我们想要支持 `dict` 构造函数的其他变体，它接受字典或元组列表，我们需要修复 `__init__` 以更新我们的 `ordered_keys` 列表）。设置项目的两种方法非常相似；它们都更新键列表，但只有在项目之前没有添加时才更新。我们不希望列表中有重复项，但我们不能在这里使用集合；它是无序的！

`keys`、`items` 和 `values` 方法都返回字典的视图。collections 库为字典提供了三个只读的 `View` 对象；它们使用 `__iter__` 方法循环遍历键，然后使用 `__getitem__`（我们不需要覆盖）来检索值。因此，我们只需要定义我们自定义的 `__iter__` 方法来使这三个视图工作。你可能会认为超类会使用多态性正确地创建这些视图，但如果我们不覆盖这三个方法，它们就不会返回正确排序的视图。

最后，`__iter__` 方法是真正特殊的；它确保如果我们循环遍历字典的键（使用 `for`...`in` 语法），它将按正确的顺序返回值。它通过返回 `ordered_keys` 列表的 `__iter__` 来实现这一点，该列表返回的是与我们在列表上使用 `for`...`in` 时使用的相同的迭代器对象。由于 `ordered_keys` 是所有可用键的列表（由于我们覆盖其他方法的方式），这也是字典的正确迭代器对象。

让我们看看这些方法中的一些是如何运作的，与普通字典相比：

```py
>>> ds = DictSorted()
>>> d = {}
>>> ds['a'] = 1
>>> ds['b'] = 2
>>> ds.setdefault('c', 3)
3
>>> d['a'] = 1
>>> d['b'] = 2
>>> d.setdefault('c', 3)
3
>>> for k,v in ds.items():
...     print(k,v)
...
a 1
b 2
c 3
>>> for k,v in d.items():
...     print(k,v)
...
a 1
c 3
b 2

```

啊，我们的字典是有序的，而普通字典不是。万岁！

### 注意

如果您想在生产中使用这个类，您将不得不覆盖其他几个特殊方法，以确保在所有情况下键都是最新的。但是，您不需要这样做；这个类提供的功能在 Python 中已经可用，使用 `collections` 模块中的 `OrderedDict` 对象。尝试从 `collections` 导入该类，并使用 `help(OrderedDict)` 了解更多信息。

# 队列

队列是奇特的数据结构，因为像集合一样，它们的功能可以完全使用列表来处理。然而，虽然列表是非常多才多艺的通用工具，但有时它们并不是最有效的容器数据结构。如果您的程序使用的是小型数据集（在今天的处理器上最多有数百甚至数千个元素），那么列表可能会涵盖所有您的用例。但是，如果您需要将数据扩展到百万级别，您可能需要一个更有效的容器来满足您特定的用例。因此，Python 提供了三种类型的队列数据结构，具体取决于您要查找的访问类型。所有三种都使用相同的 API，但在行为和数据结构上有所不同。

然而，在我们开始使用队列之前，考虑一下可靠的列表数据结构。Python 列表是许多用例中最有利的数据结构：

+   它们支持对列表中的任何元素进行高效的随机访问

+   它们有严格的元素排序

+   它们支持高效的附加操作

然而，如果您在列表的末尾之外的任何位置插入元素，它们往往会很慢（特别是如果是列表的开头）。正如我们在集合部分讨论的那样，它们对于检查元素是否存在于列表中，以及通过扩展搜索也很慢。存储数据按排序顺序或重新排序数据也可能效率低下。

让我们来看看 Python `queue`模块提供的三种类型的容器。

## FIFO 队列

FIFO 代表**先进先出**，代表了“队列”这个词最常见的定义。想象一下在银行或收银台排队的人群。第一个进入队列的人先得到服务，第二个人得到第二个服务，如果有新的人需要服务，他们加入队列的末尾等待轮到他们。

Python `Queue`类就像这样。它通常被用作一种通信媒介，当一个或多个对象产生数据，而一个或多个其他对象以某种方式消耗数据时，可能以不同的速率。想象一下一个消息应用程序，它从网络接收消息，但只能一次向用户显示一条消息。其他消息可以按接收顺序缓存在队列中。FIFO 队列在这种并发应用程序中被广泛使用。（我们将在第十二章中更多地讨论并发，*测试面向对象的程序*。）

当您不需要访问数据结构内部的任何数据，只需要访问下一个要消耗的对象时，`Queue`类是一个不错的选择。使用列表会更低效，因为在列表的底层，插入数据（或从列表中删除数据）可能需要移动列表中的每个其他元素。

队列有一个非常简单的 API。一个“队列”可以有“无限”（直到计算机耗尽内存）的容量，但更常见的是限制到某个最大大小。主要方法是`put()`和`get()`，它们将一个元素添加到队列的末尾，并按顺序从前面检索它们。这两种方法都接受可选参数来控制如果操作无法成功完成会发生什么，因为队列要么为空（无法获取）要么已满（无法放置）。默认行为是阻塞或空闲等待，直到`Queue`对象有数据或空间可用来完成操作。您可以通过传递`block=False`参数来代替引发异常。或者您可以通过传递`timeout`参数在引发异常之前等待一定的时间。

该类还有方法来检查`Queue`是否`full()`或`empty()`，还有一些额外的方法来处理并发访问，我们这里不讨论。这是一个演示这些原则的交互式会话：

```py
>>> from queue import Queue
>>> lineup = Queue(maxsize=3)
>>> lineup.get(block=False)
Traceback (most recent call last):
 **File "<ipython-input-5-a1c8d8492c59>", line 1, in <module>
 **lineup.get(block=False)
 **File "/usr/lib64/python3.3/queue.py", line 164, in get
 **raise Empty
queue.Empty
>>> lineup.put("one")
>>> lineup.put("two")
>>> lineup.put("three")
>>> lineup.put("four", timeout=1)
Traceback (most recent call last):
 **File "<ipython-input-9-4b9db399883d>", line 1, in <module>
 **lineup.put("four", timeout=1)
 **File "/usr/lib64/python3.3/queue.py", line 144, in put
raise Full
queue.Full
>>> lineup.full()
True
>>> lineup.get()
'one'
>>> lineup.get()
'two'
>>> lineup.get()
'three'
>>> lineup.empty()
True

```

在底层，Python 使用`collections.deque`数据结构实现队列。双端队列是一种先进先出的数据结构，可以有效地访问集合的两端。它提供了一个比`Queue`更灵活的接口。如果你想要更多地尝试它，我建议你参考 Python 文档。

## LIFO 队列

**LIFO**（**后进先出**）队列更常被称为**栈**。想象一叠文件，你只能访问最顶部的文件。你可以在栈的顶部放另一张纸，使其成为新的顶部纸，或者你可以拿走最顶部的纸，以显示其下面的纸。

传统上，栈的操作被命名为 push 和 pop，但 Python 的`queue`模块使用与 FIFO 队列完全相同的 API：`put()`和`get()`。然而，在 LIFO 队列中，这些方法操作的是栈的“顶部”，而不是队列的前后。这是多态的一个很好的例子。如果你查看 Python 标准库中`Queue`的源代码，你会发现实际上有一个超类和子类，用于实现 FIFO 和 LIFO 队列之间的一些关键不同的操作（在栈的顶部而不是`deque`实例的前后进行操作）。

以下是 LIFO 队列的一个示例：

```py
>>> from queue import LifoQueue
>>> stack = LifoQueue(maxsize=3)
>>> stack.put("one")
>>> stack.put("two")
>>> stack.put("three")
>>> stack.put("four", block=False)
Traceback (most recent call last):
 **File "<ipython-input-21-5473b359e5a8>", line 1, in <module>
 **stack.put("four", block=False)
 **File "/usr/lib64/python3.3/queue.py", line 133, in put
 **raise Full
queue.Full

>>> stack.get()
'three'
>>> stack.get()
'two'
>>> stack.get()
'one'
>>> stack.empty()
True
>>> stack.get(timeout=1)
Traceback (most recent call last):
 **File "<ipython-input-26-28e084a84a10>", line 1, in <module>
 **stack.get(timeout=1)
 **File "/usr/lib64/python3.3/queue.py", line 175, in get
 **raise Empty
queue.Empty

```

你可能会想为什么不能只是在标准列表上使用`append()`和`pop()`方法。坦率地说，那可能是我会做的事情。我很少有机会在生产代码中使用`LifoQueue`类。与列表的末尾一起工作是一个高效的操作；实际上，`LifoQueue`在内部使用了标准列表！

有几个原因你可能想要使用`LifoQueue`而不是列表。最重要的原因是`LifoQueue`支持多个线程的干净并发访问。如果你需要在并发环境中使用类似栈的行为，你应该把列表留在家里。其次，`LifoQueue`实施了栈接口。你不能无意中在`LifoQueue`中插入一个值到错误的位置（尽管作为一个练习，你可以想出如何完全有意识地这样做）。

## 优先队列

优先队列实施了一种与以前队列实现非常不同的排序方式。再次强调，它们遵循完全相同的`get()`和`put()`API，但是不是依赖于项目到达的顺序来确定它们应该何时被返回，而是返回最“重要”的项目。按照约定，最重要或最高优先级的项目是使用小于运算符排序最低的项目。

一个常见的约定是在优先队列中存储元组，其中元组中的第一个元素是该元素的优先级，第二个元素是数据。另一个常见的范例是实现`__lt__`方法，就像我们在本章前面讨论的那样。在队列中可以有多个具有相同优先级的元素，尽管不能保证哪一个会被首先返回。

例如，搜索引擎可能使用优先队列来确保在爬行不太可能被搜索的网站之前刷新最受欢迎的网页的内容。产品推荐工具可能使用它来显示关于排名最高的产品的信息，同时加载排名较低的数据。

请注意，优先队列总是返回当前队列中最重要的元素。`get()`方法将阻塞（默认情况下）如果队列为空，但如果队列中已经有东西，它不会阻塞并等待更高优先级的元素被添加。队列对尚未添加的元素一无所知（甚至对先前提取的元素也一无所知），只根据队列当前的内容做出决定。

这个交互式会话展示了优先队列的工作原理，使用元组作为权重来确定处理项目的顺序：

```py
>>> heap.put((3, "three"))
>>> heap.put((4, "four"))
>>> heap.put((1, "one") )
>>> heap.put((2, "two"))
>>> heap.put((5, "five"), block=False)
Traceback (most recent call last):
 **File "<ipython-input-23-d4209db364ed>", line 1, in <module>
 **heap.put((5, "five"), block=False)
 **File "/usr/lib64/python3.3/queue.py", line 133, in put
 **raise Full
Full
>>> while not heap.empty():
 **print(heap.get())
(1, 'one')
(2, 'two')
(3, 'three')
(4, 'four')

```

几乎所有的优先队列都是使用`heap`数据结构实现的。Python 的实现利用`heapq`模块来有效地在普通列表中存储一个堆。我建议您查阅算法和数据结构的教科书，以获取有关堆的更多信息，更不用说我们在这里没有涵盖的许多其他迷人的结构了。无论数据结构如何，您都可以使用面向对象的原则来封装相关的算法（行为），就像`queue`模块在标准库中为我们所做的那样。

# 案例研究

为了把一切联系在一起，我们将编写一个简单的链接收集器，它将访问一个网站，并收集该站点上每个页面上的每个链接。不过，在我们开始之前，我们需要一些测试数据来使用。简单地编写一些 HTML 文件，这些文件包含彼此之间的链接，以及到互联网上其他站点的链接，就像这样：

```py
<html>
    <body>
        <a href="contact.html">Contact us</a>
        <a href="blog.html">Blog</a>
        <a href="esme.html">My Dog</a>
        <a href="/hobbies.html">Some hobbies</a>
        <a href="/contact.html">Contact AGAIN</a>
        <a href="http://www.archlinux.org/">Favorite OS</a>
    </body>
</html>
```

将其中一个文件命名为`index.html`，这样当页面被提供时它会首先显示出来。确保其他文件存在，并且保持复杂，以便它们之间有很多链接。本章的示例包括一个名为`case_study_serve`的目录（存在的最无聊的个人网站之一！）如果您不想自己设置它们。

现在，通过进入包含所有这些文件的目录来启动一个简单的 Web 服务器，并运行以下命令：

```py
python3 -m http.server

```

这将启动一个运行在 8000 端口的服务器；您可以通过在浏览器中访问`http://localhost:8000/`来查看您创建的页面。

### 注意

我怀疑没有人能够轻松地让一个网站运行起来！永远不要说，“你不能用 Python 轻松地做到这一点。”

目标是向我们的收集器传递站点的基本 URL（在本例中为：`http://localhost:8000/`），并让它创建一个包含站点上每个唯一链接的列表。我们需要考虑三种类型的 URL（指向外部站点的链接，以`http://`开头，绝对内部链接，以`/`字符开头，以及其他情况的相对链接）。我们还需要意识到页面可能会以循环方式相互链接；我们需要确保我们不会多次处理相同的页面，否则它可能永远不会结束。在所有这些唯一性发生时，听起来我们需要一些集合。

在我们开始之前，让我们从基础知识开始。我们需要什么代码来连接到一个页面并解析该页面上的所有链接？

```py
from urllib.request import urlopen
from urllib.parse import urlparse
import re
import sys
LINK_REGEX = re.compile(
        "<a [^>]*href='\"['\"][^>]*>")

class LinkCollector:
    def __init__(self, url):
        self.url = "" + urlparse(url).netloc

    def collect_links(self, path="/"):
        full_url = self.url + path
        page = str(urlopen(full_url).read())
        links = LINK_REGEX.findall(page)
        print(links)

if __name__ == "__main__":
    LinkCollector(sys.argv[1]).collect_links()
```

考虑到它的功能，这是一小段代码。它连接到命令行传递的服务器，下载页面，并提取该页面上的所有链接。`__init__`方法使用`urlparse`函数从 URL 中提取主机名；因此，即使我们传入`http://localhost:8000/some/page.html`，它仍将在主机的顶层`http://localhost:8000/`上运行。这是有道理的，因为我们想收集站点上的所有链接，尽管它假设每个页面都通过某些链接序列连接到索引。

`collect_links`方法连接到服务器并下载指定页面，并使用正则表达式在页面中找到所有链接。正则表达式是一种非常强大的字符串处理工具。不幸的是，它们有一个陡峭的学习曲线；如果您以前没有使用过它们，我强烈建议您学习任何一本完整的书籍或网站上的相关主题。如果您认为它们不值得了解，那么尝试在没有它们的情况下编写前面的代码，您会改变主意的。

示例还在`collect_links`方法的中间停止，以打印链接的值。这是测试程序的常见方法：停下来输出值，以确保它是我们期望的值。这是我们示例的输出：

```py
['contact.html', 'blog.html', 'esme.html', '/hobbies.html',
'/contact.html', 'http://www.archlinux.org/']
```

现在我们已经收集了第一页中的所有链接。我们可以用它做什么？我们不能只是将链接弹出到一个集合中以删除重复项，因为链接可能是相对的或绝对的。例如，`contact.html`和`/contact.html`指向同一个页面。因此，我们应该做的第一件事是将所有链接规范化为它们的完整 URL，包括主机名和相对路径。我们可以通过向我们的对象添加一个`normalize_url`方法来实现这一点：

```py
    def normalize_url(self, path, link):
        if link.startswith("http://"):
            return link
        elif link.startswith("/"):
            return self.url + link
        else:
            return self.url + path.rpartition(
                '/')[0] + '/' + link
```

这种方法将每个 URL 转换为包括协议和主机名的完整地址。现在两个联系页面具有相同的值，我们可以将它们存储在一个集合中。我们将不得不修改`__init__`来创建这个集合，以及`collect_links`来将所有链接放入其中。

然后，我们将不得不访问所有非外部链接并收集它们。但等一下；如果我们这样做，我们如何防止在遇到同一个页面两次时重新访问链接？看起来我们实际上需要两个集合：一个收集链接的集合，一个访问链接的集合。这表明我们明智地选择了一个集合来表示我们的数据；我们知道在操作多个集合时，集合是最有用的。让我们设置这些：

```py
class LinkCollector:
    def __init__(self, url):
        self.url = "http://+" + urlparse(url).netloc
        **self.collected_links = set()
        **self.visited_links = set()

    def collect_links(self, path="/"):
        full_url = self.url + path
        **self.visited_links.add(full_url)
        page = str(urlopen(full_url).read())
        links = LINK_REGEX.findall(page)
        **links = {self.normalize_url(path, link
            **) for link in links}
        **self.collected_links = links.union(
                **self.collected_links)
        **unvisited_links = links.difference(
                **self.visited_links)
        **print(links, self.visited_links,
                **self.collected_links, unvisited_links)

```

创建规范化链接列表的行使用了`set`推导，与列表推导没有什么不同，只是结果是一组值。我们将在下一章中详细介绍这些。再次，该方法停下来打印当前值，以便我们可以验证我们没有混淆我们的集合，并且`difference`确实是我们想要调用的方法来收集`unvisited_links`。然后我们可以添加几行代码，循环遍历所有未访问的链接，并将它们添加到收集中：

```py
        for link in unvisited_links:
            if link.startswith(self.url):
                self.collect_links(urlparse(link).path)
```

`if`语句确保我们只从一个网站收集链接；我们不想去收集互联网上所有页面的所有链接（除非我们是 Google 或互联网档案馆！）。如果我们修改程序底部的主要代码以输出收集到的链接，我们可以看到它似乎已经收集了它们所有：

```py
if __name__ == "__main__":
    collector = LinkCollector(sys.argv[1])
    collector.collect_links()
    for link in collector.collected_links:
        print(link)
```

它显示了我们收集到的所有链接，只显示了一次，即使我的示例中的许多页面多次链接到彼此：

```py
$ python3 link_collector.py http://localhost:8000
http://localhost:8000/
http://en.wikipedia.org/wiki/Cavalier_King_Charles_Spaniel
http://beluminousyoga.com
http://archlinux.me/dusty/
http://localhost:8000/blog.html
http://ccphillips.net/
http://localhost:8000/contact.html
http://localhost:8000/taichi.html
http://www.archlinux.org/
http://localhost:8000/esme.html
http://localhost:8000/hobbies.html

```

即使它收集了指向外部页面的链接，它也没有去收集我们链接到的任何外部页面的链接。如果我们想收集站点中的所有链接，这是一个很棒的小程序。但它并没有给我提供构建站点地图所需的所有信息；它告诉我我有哪些页面，但它没有告诉我哪些页面链接到其他页面。如果我们想要做到这一点，我们将不得不进行一些修改。

我们应该做的第一件事是查看我们的数据结构。收集链接的集合不再起作用；我们想知道哪些链接是从哪些页面链接过来的。因此，我们可以做的第一件事是将该集合转换为我们访问的每个页面的集合字典。字典键将表示当前集合中的确切数据。值将是该页面上的所有链接的集合。以下是更改：

```py
from urllib.request import urlopen
from urllib.parse import urlparse
import re
import sys
LINK_REGEX = re.compile(
        "<a [^>]*href='\"['\"][^>]*>")

class LinkCollector:
    def __init__(self, url):
        self.url = "http://%s" % urlparse(url).netloc
        **self.collected_links = {}
        self.visited_links = set()

    def collect_links(self, path="/"):
        full_url = self.url + path
        self.visited_links.add(full_url)
        page = str(urlopen(full_url).read())
        links = LINK_REGEX.findall(page)
        links = {self.normalize_url(path, link
            ) for link in links}
        **self.collected_links[full_url] = links
        **for link in links:
            **self.collected_links.setdefault(link, set())
        unvisited_links = links.difference(
                self.visited_links)
        for link in unvisited_links:
            if link.startswith(self.url):
                self.collect_links(urlparse(link).path)

    def normalize_url(self, path, link):
        if link.startswith("http://"):
            return link
        elif link.startswith("/"):
            return self.url + link
        else:
            return self.url + path.rpartition('/'
                    )[0] + '/' + link
if __name__ == "__main__":
    collector = LinkCollector(sys.argv[1])
    collector.collect_links()
    **for link, item in collector.collected_links.items():
        **print("{}: {}".format(link, item))

```

这是一个令人惊讶的小改变；原来创建两个集合的行已被三行代码替换，用于更新字典。其中第一行简单地告诉字典该页面的收集链接是什么。第二行使用`setdefault`为字典中尚未添加到字典中的任何项目创建一个空集。结果是一个包含所有链接的字典，将其键映射到所有内部链接的链接集，外部链接为空集。

最后，我们可以使用队列来存储尚未处理的链接，而不是递归调用`collect_links`。这种实现不支持它，但这将是创建一个多线程版本的良好第一步，该版本可以并行进行多个请求以节省时间。

```py
from urllib.request import urlopen
from urllib.parse import urlparse
import re
import sys
from queue import Queue
LINK_REGEX = re.compile("<a [^>]*href='\"['\"][^>]*>")

class LinkCollector:
    def __init__(self, url):
        self.url = "http://%s" % urlparse(url).netloc
        self.collected_links = {}
        self.visited_links = set()

    def collect_links(self):
        queue = Queue()
        queue.put(self.url)
        while not queue.empty():
            url = queue.get().rstrip('/')
            self.visited_links.add(url)
            page = str(urlopen(url).read())
            links = LINK_REGEX.findall(page)
            links = {
                self.normalize_url(urlparse(url).path, link)
                for link in links
            }
            self.collected_links[url] = links
            for link in links:
                self.collected_links.setdefault(link, set())
            unvisited_links = links.difference(self.visited_links)
            for link in unvisited_links:
                if link.startswith(self.url):
                    queue.put(link)

    def normalize_url(self, path, link):
        if link.startswith("http://"):
            return link.rstrip('/')
        elif link.startswith("/"):
            return self.url + link.rstrip('/')
        else:
            return self.url + path.rpartition('/')[0] + '/' + link.rstrip('/')

if __name__ == "__main__":
    collector = LinkCollector(sys.argv[1])
    collector.collect_links()
    for link, item in collector.collected_links.items():
        print("%s: %s" % (link, item))
```

在这个版本的代码中，我不得不手动去除`normalize_url`方法中的任何尾部斜杠，以消除重复项。

因为最终结果是一个未排序的字典，所以对链接进行处理的顺序没有限制。因此，在这里我们可以使用`LifoQueue`而不是`Queue`。由于在这种情况下没有明显的优先级可附加到链接上，使用优先级队列可能没有太多意义。

# 练习

选择正确数据结构的最佳方法是多次选择错误。拿出你最近写过的一些代码，或者写一些使用列表的新代码。尝试使用一些不同的数据结构来重写它。哪些更合理？哪些不合理？哪些代码最优雅？

尝试使用几种不同的数据结构。你可以查看你之前章节练习中做过的例子。有没有对象和方法，你本来可以使用`namedtuple`或`dict`？尝试一下，看看结果如何。有没有本来可以使用集合的字典，因为你实际上并没有访问值？有没有检查重复项的列表？集合是否足够？或者可能需要几个集合？哪种队列实现更有效？将 API 限制在堆栈顶部是否有用，而不是允许随机访问列表？

如果你想要一些具体的例子来操作，可以尝试将链接收集器改编为同时保存每个链接使用的标题。也许你可以生成一个 HTML 站点地图，列出站点上的所有页面，并包含一个链接到其他页面的链接列表，使用相同的链接标题命名。

最近是否编写了任何容器对象，可以通过继承内置对象并重写一些“特殊”双下划线方法来改进？你可能需要进行一些研究（使用`dir`和`help`，或 Python 库参考）来找出哪些方法需要重写。你确定继承是应用的正确工具吗？基于组合的解决方案可能更有效吗？在决定之前尝试两种方法（如果可能的话）。尝试找到不同的情况，其中每种方法都比另一种更好。

如果在开始本章之前，你已经熟悉各种 Python 数据结构及其用途，你可能会感到无聊。但如果是这种情况，很可能你使用数据结构太多了！看看你以前的一些代码，并重写它以使用更多自制对象。仔细考虑各种替代方案，并尝试它们所有；哪一个使系统更易读和易维护？

始终对你的代码和设计决策进行批判性评估。养成审查旧代码的习惯，并注意如果你对“良好设计”的理解自你编写代码以来有所改变。软件设计有很大的审美成分，就像带有油画的艺术家一样，我们都必须找到最适合自己的风格。

# 总结

我们已经介绍了几种内置数据结构，并试图了解如何为特定应用程序选择其中一种。有时，我们能做的最好的事情就是创建一类新的对象，但通常情况下，内置的数据结构提供了我们需要的东西。当它不提供时，我们总是可以使用继承或组合来使它们适应我们的用例。我们甚至可以重写特殊方法来完全改变内置语法的行为。

在下一章中，我们将讨论如何整合 Python 的面向对象和非面向对象的方面。在此过程中，我们将发现它比乍一看更面向对象化！
