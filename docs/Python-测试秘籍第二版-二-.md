# Python 测试秘籍第二版（二）

> 原文：[`zh.annas-archive.org/md5/98CC341CCD461D299EE4103040C60B7B`](https://zh.annas-archive.org/md5/98CC341CCD461D299EE4103040C60B7B)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第三章：使用 doctest 创建可测试的文档

在本章中，我们将介绍以下配方：

+   记录基础知识

+   捕获堆栈跟踪

+   从命令行运行 doctest

+   为 doctest 编写测试工具

+   过滤测试噪音

+   打印出所有文档，包括状态报告。

+   测试边缘情况

+   通过迭代测试边缘情况

+   使用 doctest 进行调试

+   更新项目级脚本以运行本章的 doctest

# 介绍

Python 提供了一种在函数内部嵌入注释的有用能力，可以从 Python shell 中访问。这些被称为**文档字符串**。

文档字符串不仅提供了嵌入信息的能力，还提供了可运行的代码示例。

有一句古谚说“*注释不是代码*”。这是因为注释不经过语法检查，通常不会被维护。因此，它们携带的信息随着时间的推移可能会失去其价值。`doctest`通过将注释转换为代码来解决这个问题，这可以有很多有用的用途。

在本章中，我们将探讨使用`doctest`开发测试、文档和项目支持的不同方法。不需要特殊设置，因为`doctest`是 Python 标准库的一部分。

# 记录基础知识

Python 提供了一种在代码中放置注释的开箱即用的能力，称为文档字符串。查看源代码和从 Python shell 交互检查代码时，可以阅读文档字符串。在本配方中，我们将演示如何使用这些交互式文档字符串作为可运行的测试。

这提供了什么？它为用户提供了易于阅读的代码示例。这些代码示例不仅易于阅读，而且可以运行，这意味着我们可以确保文档保持最新。

# 如何做...

通过以下步骤，我们将创建一个应用程序，其中包含可运行的文档字符串注释，并看看如何执行这些测试：

1.  创建一个名为`recipe16.py`的新文件，以放置我们为此配方编写的所有代码。

1.  创建一个函数，使用递归将十进制数转换为任何其他进制：

```py
def convert_to_basen(value, base):
    import math
    def _convert(remaining_value, base, exp):
        def stringify(value):
            if value > 9:
                return chr(value + ord('a')-10)
            else:
                return str(value)
        if remaining_value >= 0 and exp >= 0:
            factor = int(math.pow(base, exp))
            if factor <= remaining_value:
                multiple = remaining_value / factor
                return stringify(multiple) + \
                  _convert(remaining_value-multiple*factor, \
                    base, exp-1)
        else:
            return "0" + \
                _convert(remaining_value, base, exp-1)
        else:
            return ""
    return "%s/%s" % (_convert(value, base, \
                int(math.log(value, base))), base)
```

1.  在外部函数的下面添加一个文档字符串，如下面代码的突出部分所示。这个文档字符串声明包括使用该函数的几个示例：

```py
def convert_to_basen(value, base):
    """Convert a base10 number to basen
 >>> convert_to_basen(1, 2)
 '1/2'
 >>> convert_to_basen(2, 2)
 '10/2'
 >>> convert_to_basen(3, 2)
 '11/2'
 >>> convert_to_basen(4, 2)
 '100/2'
 >>> convert_to_basen(5, 2)
 '101/2'
 >>> convert_to_basen(6, 2)
 '110/2'
 >>> convert_to_basen(7, 2)
 '111/2'
 >>> convert_to_basen(1, 16)
 '1/16'
 >>> convert_to_basen(10, 16)
 'a/16'
 >>> convert_to_basen(15, 16)
 'f/16'
 >>> convert_to_basen(16, 16)
 '10/16'
 >>> convert_to_basen(31, 16)
 '1f/16'
 >>> convert_to_basen(32, 16)
 '20/16'
 """
    import math
```

1.  添加一个测试运行器块，调用 Python 的`doctest`模块：

```py
if __name__ == "__main__":
    import doctest
    doctest.testmod()
```

1.  从交互式 Python shell 导入配方并查看其文档。看看这个截图：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-test-cb-2e/img/00036.jpeg)

1.  从命令行运行代码。在下面的截图中，请注意没有任何内容被打印出来。这就是当所有测试都通过时会发生的情况。看看这个截图：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-test-cb-2e/img/00037.jpeg)

1.  从命令行运行代码，使用`-v`增加详细程度。在下面的截图中，我们看到了一部分输出，显示了运行的内容和预期的内容。在调试`doctest`时，这可能很有用：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-test-cb-2e/img/00038.jpeg)

# 它是如何工作的...

`doctest`模块查找文档字符串中的 Python 代码块，并像真正的代码一样运行它。`>>>`是我们在使用交互式 Python shell 时看到的相同提示。`>>>`后面的行显示了预期的输出。`doctest`运行它看到的语句，然后将实际输出与预期输出进行比较。

在本章的后面，我们将看到如何捕获堆栈跟踪、错误，并添加额外的代码，相当于测试装置。

# 还有更多...

`doctest`在匹配预期输出和实际结果时非常挑剔：

+   多余的空格或制表符可能会导致出现问题。

+   诸如字典之类的结构很难测试，因为 Python 不能保证项目的顺序。在每次测试运行时，项目可能以不同的顺序存储。简单地打印出一个字典肯定会出错。

+   强烈建议不要在预期输出中包含对象引用。这些值每次运行测试时也会变化。

# 捕获堆栈跟踪

一个常见的谬论是我们只应该为成功的代码路径编写测试。我们还需要针对包括生成堆栈跟踪的错误条件编写代码。通过这个示例，我们将探讨如何在文档测试中模式匹配堆栈跟踪，从而允许我们确认预期的错误。

# 如何做...

通过以下步骤，我们将看到如何使用`doctest`来验证错误条件：

1.  为此示例中的所有代码创建一个名为`recipe17.py`的新文件。

1.  创建一个函数，使用递归将十进制数转换为任何其他进制：

```py
def convert_to_basen(value, base):
    import math
    def _convert(remaining_value, base, exp):
        def stringify(value):
            if value > 9:
                return chr(value + ord('a')-10)
            else:
                return str(value)
        if remaining_value >= 0 and exp >= 0:
            factor = int(math.pow(base, exp))
            if factor <= remaining_value:
                multiple = remaining_value / factor
                return stringify(multiple) + \
                    _convert(remaining_value-multiple*factor, \
                                base, exp-1)
            else:
                return "0" + \
                    _convert(remaining_value, base, exp-1)
        else:
            return ""
    return "%s/%s" % (_convert(value, base, \
                int(math.log(value, base))), base)
```

1.  在外部函数声明的下方添加一个文档字符串，其中包含两个预期生成堆栈跟踪的示例：

```py
def convert_to_basen(value, base):
    """Convert a base10 number to basen.

 >>> convert_to_basen(0, 2)
 Traceback (most recent call last):
 ...
 ValueError: math domain error

 >>> convert_to_basen(-1, 2)
 Traceback (most recent call last):
 ...
 ValueError: math domain error
 """
    import math
```

1.  添加一个测试运行器块，调用 Python 的`doctest`模块：

```py
if __name__ == "__main__":
    import doctest
    doctest.testmod()
```

1.  从命令行运行代码。在下面的截图中，请注意没有打印任何内容。这是当所有测试都通过时发生的情况：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-test-cb-2e/img/00039.jpeg)

1.  使用`-v`从命令行运行代码以增加详细信息。在下面的截图中，我们可以看到`0`和`-1`生成了数学域错误。这是由于使用`math.log`来找到起始指数：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-test-cb-2e/img/00040.jpeg)

# 它是如何工作的...

`doctest`模块查找文档字符串中的 Python 代码块，并像真正的代码一样运行它。`>>>`是我们在交互式 Python shell 中使用时看到的相同提示。`>>>`后面的行显示了预期的输出。`doctest`运行它看到的语句，然后将实际输出与预期输出进行比较。

关于堆栈跟踪，堆栈跟踪提供了大量详细信息。模式匹配整个跟踪是无效的。通过使用省略号，我们能够跳过堆栈跟踪的中间部分，只匹配区分部分：`ValueError: math domain error`。

这是有价值的，因为我们的用户不仅会看到它如何处理良好的值，还会观察到在提供坏值时可以期望什么错误。

# 从命令行运行`doctest`

我们已经看到了如何通过在文档字符串中嵌入可运行的代码片段来开发测试。但是对于这些测试中的每一个，我们都必须使模块可运行。如果我们想要从命令行运行除了我们的`doctest`之外的其他内容怎么办？我们将不得不摆脱`doctest.testmod()`语句！

好消息是，从 Python 2.6 开始，有一个命令行选项可以在不编写运行器的情况下运行特定模块的`doctest`。

`python -m doctest -v example.py`命令将导入`example.py`并通过`doctest.testmod()`运行它。根据文档，如果模块是包的一部分并导入其他子模块，则可能会失败。

# 如何做...

在以下步骤中，我们将创建一个简单的应用程序。我们将添加一些 doctests，然后从命令行运行它们，而无需编写特殊的测试运行器：

1.  创建一个名为`recipe18.py`的新文件，用于存储为此示例编写的代码。

1.  创建一个函数，使用递归将十进制数转换为任何其他进制：

```py
def convert_to_basen(value, base):
    import math
    def _convert(remaining_value, base, exp):
        def stringify(value):
            if value > 9:
                return chr(value + ord('a')-10)
            else:
                return str(value)
        if remaining_value >= 0 and exp >= 0:
            factor = int(math.pow(base, exp))
            if factor <= remaining_value:
                multiple = remaining_value / factor
                return stringify(multiple) + \
                  _convert(remaining_value-multiple*factor, \
                                base, exp-1)
            else:
                return "0" + \
                       _convert(remaining_value, base, exp-1)
        else:
            return ""
    return "%s/%s" % (_convert(value, base, \
                         int(math.log(value, base))), base)
```

1.  在外部函数声明的下方添加一个文档字符串，其中包含一些测试：

```py
def convert_to_basen(value, base):
    """Convert a base10 number to basen.
 >>> convert_to_basen(10, 2)
 '1010/2'
 >>> convert_to_basen(15, 16)
 'f/16'
 >>> convert_to_basen(0, 2)
 Traceback (most recent call last):
 ...
 ValueError: math domain error
 >>> convert_to_basen(-1, 2)
 Traceback (most recent call last):
 ...
 ValueError: math domain error
 """
    import math
```

1.  使用`-m doctest`从命令行运行代码。如下面的截图所示，没有输出表示所有测试都已通过：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-test-cb-2e/img/00041.jpeg)

1.  使用`-v`从命令行运行代码以增加详细信息。如果我们忘记包含`-m doctest`会发生什么？使用`-v`选项可以帮助我们避免这种情况，因为它给我们一种温暖的感觉，让我们知道我们的测试正在工作。看一下这个截图：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-test-cb-2e/img/00042.jpeg)

# 它是如何工作的...

在上一章中，我们正在使用模块的`__main__`块来运行其他测试套件。如果我们想在这里做同样的事情怎么办？我们必须选择`__main__`是用于单元测试、doctests 还是两者兼而有之！如果我们甚至不想通过`__main__`运行测试，而是运行我们的应用程序怎么办？

这就是为什么 Python 添加了使用 `-m doctest` 从命令行直接调用测试的选项。

你难道不想*知道*你的测试是否正在运行或工作吗？测试套件是否真的在做它承诺的事情？使用其他工具，通常我们必须嵌入打印语句，或者故意失败，只是为了知道事情被正确地捕获了。看起来`doctest`中的`-v`选项提供了一个方便的快速浏览正在发生的事情的方式，不是吗？

# 为`doctest`编写一个测试工具

到目前为止，我们编写的测试非常简单，因为我们正在测试的函数很简单。有两个输入和一个输出，没有副作用。不需要创建对象。这对我们来说并不是最常见的用例。通常，我们有与其他对象交互的对象。

`doctest` 模块支持创建对象、调用方法和检查结果。通过这个示例，我们将更详细地探讨这个问题。

`doctest`的一个重要方面是它找到文档字符串的各个实例，并在本地上下文中运行它们。在一个文档字符串中声明的变量不能在另一个文档字符串中使用。

# 如何做...

1.  创建一个名为`recipe19.py`的新文件，包含这个示例的代码。

1.  编写一个简单的购物车应用程序：

```py
class ShoppingCart(object):
    def __init__(self):
        self.items = []
    def add(self, item, price):
        self.items.append(Item(item, price))
        return self
    def item(self, index):
        return self.items[index-1].item
    def price(self, index):
        return self.items[index-1].price
    def total(self, sales_tax):
        sum_price = sum([item.price for item in self.items])
        return sum_price*(1.0 + sales_tax/100.0)
    def __len__(self):
        return len(self.items)
class Item(object):
    def __init__(self, item, price):
        self.item = item
        self.price = price
```

1.  在`ShoppingCart`类声明之前，在模块顶部插入一个文档字符串：

```py
"""
This is documentation for the this entire recipe.
With it, we can demonstrate usage of the code.

>>> cart = ShoppingCart().add("tuna sandwich", 15.0)
>>> len(cart)
1
>>> cart.item(1)
'tuna sandwich'
>>> cart.price(1)
15.0
>>> print (round(cart.total(9.25), 2))
16.39
"""
class ShoppingCart(object):
...
```

1.  使用`-m doctest`和`-v`进行运行：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-test-cb-2e/img/00043.jpeg)

1.  将我们刚刚从`recipe19.py`中编写的所有代码复制到一个名为`recipe19b.py`的新文件中。

1.  在`recipe19b.py`中，在模块顶部定义`cart`变量后添加另一个文档字符串：

```py
def item(self, index):
    """
    >>> cart.item(1)
    'tuna sandwich'
    """
    return self.items[index-1].item
```

1.  运行这个示例的变体。为什么它失败了？`cart`不是在之前的文档字符串中声明的吗？看一下这个截图：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-test-cb-2e/img/00044.jpeg)

# 工作原理...

`doctest`模块查找每个文档字符串。对于它找到的每个文档字符串，它都会创建模块全局变量的浅拷贝，然后运行代码并检查结果。除此之外，每个创建的变量都是局部作用域的，当测试完成时会被清除。这意味着我们稍后添加的第二个文档字符串无法看到我们在第一个文档字符串中创建的`cart`。这就是为什么第二次运行失败的原因。

与一些 unittest 示例中使用的`setUp`方法相比，`doctest`没有等价的方法。如果`doctest`没有`setUp`选项，那么这个示例有什么价值呢？它突显了所有开发人员在使用之前必须了解的`doctest`的一个关键限制。

# 还有更多...

`doctest` 模块提供了一种非常方便的方式来为我们的文档添加可测试性。但这并不能替代完整的测试框架，比如 unittest。正如前面所述，没有`setUp`的等价物。在文档字符串中嵌入的 Python 代码也没有语法检查。

将 `doctest` 的正确级别与 unittest（或者我们可能选择的任何其他测试框架）混合在一起是一个判断的问题。

# 过滤测试噪音

各种选项帮助`doctest`忽略噪音，比如在测试用例中的空白。这是有用的，因为它允许我们更好地结构化预期的结果，以便用户更容易阅读。

我们还可以标记一些可以跳过的测试。这可以用在我们想要记录已知问题，但尚未修补系统的地方。

当我们试图进行全面测试但专注于系统的其他部分时，这两种情况都很容易被解释为噪音。在这个示例中，我们将深入研究如何放宽`doctest`的严格检查。我们还将看看如何忽略整个测试，无论是临时的还是永久的。

# 如何做...

通过以下步骤，我们将尝试过滤测试结果并放宽`doctest`的某些限制：

1.  为这个示例的代码创建一个名为`recipe20.py`的新文件。

1.  创建一个递归函数，将十进制数转换为其他进制：

```py
def convert_to_basen(value, base):
    import math
    def _convert(remaining_value, base, exp):
        def stringify(value):
            if value > 9:
                return chr(value + ord('a')-10)
            else:
                return str(value)

        if remaining_value >= 0 and exp >= 0:
            factor = int(math.pow(base, exp))
            if factor <= remaining_value:
                multiple = remaining_value / factor
                return stringify(multiple) + \
                  _convert(remaining_value-multiple*factor, \
                                base, exp-1)
            else:
                return "0" + \
                       _convert(remaining_value, base, exp-1)
        else:
            return ""
    return "%s/%s" % (_convert(value, base, \
                         int(math.log(value, base))), base)
```

1.  添加一个包含一系列值的测试来练习的文档字符串，以及记录一个尚未实现的未来功能：

```py
def convert_to_basen(value, base):
    """Convert a base10 number to basen.

 >>> [convert_to_basen(i, 16) for i in range(1,16)] #doctest:
+NORMALIZE_WHITESPACE
 ['1/16', '2/16', '3/16', '4/16', '5/16', '6/16', '7/16', '8/16',
 '9/16',  'a/16', 'b/16', 'c/16', 'd/16', 'e/16', 'f/16']

 FUTURE: Binary may support 2's complement in the future, but not
now.
 >>> convert_to_basen(-10, 2) #doctest: +SKIP
 '0110/2'
 """
    import math
```

1.  添加一个测试运行程序：

```py
if __name__ == "__main__":
    import doctest
    doctest.testmod()
```

1.  以详细模式运行测试用例，如此截图所示：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-test-cb-2e/img/00045.jpeg)

1.  将`recipe20.py`中的代码复制到一个名为`recipe20b.py`的新文件中。

1.  通过更新文档字符串来编辑`recipe20b.py`，包括另一个测试，显示我们的函数不会转换`0`：

```py
def convert_to_basen(value, base):
    """Convert a base10 number to basen.
    >>> [convert_to_basen(i, 16) for i in range(1,16)] #doctest:
+NORMALIZE_WHITESPACE
    ['1/16', '2/16', '3/16', '4/16', '5/16', '6/16', '7/16', '8/16',
    '9/16',  'a/16', 'b/16', 'c/16', 'd/16', 'e/16', 'f/16']
    FUTURE: Binary may support 2's complement in the future, but not
now.
    >>> convert_to_basen(-10, 2) #doctest: +SKIP
    '0110/2'
    BUG: Discovered that this algorithm doesn't handle 0\. Need to patch
it.
 TODO: Renable this when patched.
 >>> convert_to_basen(0, 2)
 '0/2'
 """
    import math
```

1.  运行测试用例。注意这个版本的配方有什么不同之处，以及为什么它失败了？看一下这个截图：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-test-cb-2e/img/00046.jpeg)

1.  将`recipe20b.py`中的代码复制到一个名为`recipe20c.py`的新文件中。

1.  编辑`recipe20c.py`并更新文档字符串，指示我们现在将跳过测试：

```py
def convert_to_basen(value, base): 
    """Convert a base10 number to basen. 

    >>> [convert_to_basen(i, 16) for i in range(1,16)] #doctest: +NORMALIZE_WHITESPACE 
    ['1/16', '2/16', '3/16', '4/16', '5/16', '6/16', '7/16', '8/16', 
    '9/16',  'a/16', 'b/16', 'c/16', 'd/16', 'e/16', 'f/16'] 

    FUTURE: Binary may support 2's complement in the future, but not now. 
    >>> convert_to_basen(-10, 2) #doctest: +SKIP 
    '0110/2' 

    BUG: Discovered that this algorithm doesn't handle 0\. Need to patch it. 
    TODO: Renable this when patched. 
    >>> convert_to_basen(0, 2) #doctest: +SKIP 
    '0/2' 
    """ 
    import math
```

1.  运行测试用例。看一下这个截图：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-test-cb-2e/img/00047.jpeg)

# 它是如何工作的...

在这个配方中，我们重新审视了从十进制转换为任意进制数字的函数。第一个测试显示它在一个范围内运行。通常，Python 会将这个结果数组放在一行上。为了使其更易读，我们将输出分布在两行上。我们还在值之间放了一些任意的空格，以使列更好地对齐。

这是`doctest`绝对不会支持的事情，因为它严格的模式匹配性质。通过使用`#doctest: +NORMALIZE_WHITESPACE`，我们能够要求`doctest`放宽这个限制。仍然有约束。例如，预期数组中的第一个值不能有任何空格在它前面（*相信我，我试过了，为了最大的可读性！*）但是将数组包装到下一行不再破坏测试。

我们还有一个测试用例，实际上只是作为文档。它指示了一个未来的要求，显示了我们的函数如何处理负二进制值。通过添加`#doctest: +SKIP`，我们能够命令`doctest`跳过这个特定的实例。

最后，我们看到了一个情景，我们发现我们的代码不能处理`0`。由于算法通过取对数得到最高指数，存在一个数学问题。我们通过一个测试来捕获这个边缘情况。然后我们确认代码以经典的**测试驱动设计**（**TDD**）方式失败。最后一步将是修复代码以处理这个边缘情况。但我们决定，以一种有点牵强的方式，我们没有足够的时间在当前的迭代中修复代码。为了避免破坏我们的**持续集成**（**CI**）服务器，我们用一个`TO-DO`语句标记测试，并添加`#doctest: +SKIP`。

# 还有更多...

我们用`#doctest: +SKIP`标记的两种情况都是最终我们希望移除`SKIP`标记并让它们运行的情况。可能还有其他情况我们永远不会移除`SKIP`。代码演示可能有很大的波动，可能无法轻易测试而不使其难以阅读。例如，返回字典的函数更难测试，因为结果的顺序会变化。我们可以弯曲它以通过测试，但我们可能会失去文档的价值，以便呈现给读者。

# 打印出所有的文档，包括状态报告

由于本章涉及文档和测试，让我们构建一个脚本，它接受一组模块并打印出一个完整的报告，显示所有文档以及运行任何给定的测试。

这是一个有价值的配方，因为它向我们展示了如何使用 Python 的 API 来收集一个基于代码的可运行报告。这意味着文档是准确的，也是最新的，反映了我们代码的当前状态。

# 如何做...

在接下来的步骤中，我们将编写一个应用程序和一些`doctests`。然后我们将构建一个脚本来收集一个有用的报告：

1.  创建一个名为`recipe21_report.py`的新文件，用于包含收集报告的脚本。

1.  通过导入 Python 的`inspect`库来创建一个脚本，作为深入模块的基础：`from inspect import*`。

1.  添加一个函数，专注于打印出一个项目的`__doc__`字符串或打印出未找到文档的消息：

```py
def print_doc(name, item):
    if item.__doc__:
        print "Documentation for %s" % name
        print "-------------------------------"
        print item.doc
        print "-------------------------------"
    else:
        print "Documentation for %s - None" % name
```

1.  添加一个函数，根据给定模块打印出文档。确保这个函数查找类、方法和函数，并打印出它们的文档：

```py
def print_docstrings(m, prefix=""):
    print_doc(prefix + "module %s" % m.__name__, m)

    for (name, value) in getmembers(m, isclass):
        if name == '__class__': continue
        print_docstrings(value, prefix=name + ".")
    for (name, value) in getmembers(m, ismethod):
        print_doc("%s%s()" % (prefix, name), value)
    for (name, value) in getmembers(m, isfunction):
        print_doc("%s%s()" % (prefix, name), value)
```

1.  添加一个解析命令行字符串并迭代每个提供的模块的运行器：

```py
if __name__ == "__main__":
    import sys
    import doctest

    for arg in sys.argv[1:]:
        if arg.startswith("-"): continue
        print "==============================="
        print "== Processing module %s" % arg
        print "==============================="
        m = __import__(arg)
        print_docstrings(m)
        print "Running doctests for %s" % arg
        print "-------------------------------"
        doctest.testmod(m)
```

1.  创建一个新文件`recipe21.py`，其中包含一个我们将对之前的脚本运行的应用程序和测试。

1.  在`recipe21.py`中，创建一个购物车应用程序，并填充它的文档字符串和`doctests`。这是整个食谱的文档。有了它，我们可以演示代码的用法：

```py
>>> cart = ShoppingCart().add("tuna sandwich", 15.0)
>>> len(cart)
1
>>> cart.item(1)
'tuna sandwich'
>>> cart.price(1)
15.0
>>> print round(cart.total(9.25), 2)
16.39
"""

class ShoppingCart(object):
    """
    This object is used to store the goods.
    It conveniently calculates total cost including
    tax.
    """
    def __init__(self):
        self.items = []
    def add(self, item, price):
        "Add an item to the internal list."
        self.items.append(Item(item, price))
        return self
    def item(self, index):
        "Look up the item. The cart is a 1-based index."
        return self.items[index-1].item
    def price(self, index):
        "Look up the price. The cart is a 1-based index."
        return self.items[index-1].price
    def total(self, sales_tax):
        "Add up all costs, and then apply a sales tax."
        sum_price = sum([item.price for item in self.items])
        return sum_price*(1.0 + sales_tax/100.0)
    def __len__(self):
        "Support len(cart) operation."
        return len(self.items)

class Item(object):
    def __init__(self, item, price):
        self.item = item
        self.price = price
```

1.  使用`-v`对这个模块运行报告脚本，并查看屏幕输出：

```py
===============================
== Processing module recipe21
===============================
Documentation for module recipe21
-------------------------------
This is documentation for the this entire recipe.
With it, we can demonstrate usage of the code.
>>> cart = ShoppingCart().add("tuna sandwich", 15.0)
>>> len(cart)
1
>>> cart.item(1)
'tuna sandwich'
>>> cart.price(1)
15.0
>>> print round(cart.total(9.25), 2)
16.39
-------------------------------
Documentation for Item.module Item - None
Documentation for Item.__init__() - None
Documentation for ShoppingCart.module ShoppingCart
-------------------------------
 This object is used to store the goods.
 It conveniently calculates total cost including
 tax.
…
Running doctests for recipe21
-------------------------------
Trying:
 cart = ShoppingCart().add("tuna sandwich", 15.0)
Expecting nothing
ok
Trying:
 len(cart)
Expecting:
 1
ok
5 tests in 10 items.
5 passed and 0 failed.
Test passed.
```

# 它是如何工作的...

这个脚本很小，但它收集了很多有用的信息。

通过使用 Python 的标准`inspect`模块，我们能够从模块级别开始深入研究。查找文档字符串的反射方式是通过访问对象的`__doc__`属性。它包含在模块、类、方法和函数中。它们存在于其他地方，但我们在这个食谱中限制了我们的重点。

我们以详细模式运行它，以显示测试实际上被执行。我们手动解析了命令行选项，但`doctest`自动查找`-v`来决定是否打开详细输出。为了防止我们的模块处理器捕捉到这一点并尝试将其处理为另一个模块，我们添加了一行来跳过任何`-xyz`风格的标志：

```py
 if arg.startswith("-"): continue 
```

# 还有更多...

我们可以花更多时间来增强这个脚本。例如，我们可以使用 HTML 标记将其导出，使其可以在 Web 浏览器中查看。我们还可以找到第三方库以其他方式导出它。

我们还可以在哪里寻找文档字符串以及如何处理它们上进行改进。在我们的情况下，我们只是将它们打印到屏幕上。一个更可重用的方法是返回包含所有信息的某种结构。然后，调用者可以决定是打印到屏幕上，将其编码为 HTML，还是生成 PDF 文档。

这并不是必要的，因为这个食谱的重点是看如何将 Python 提供的这些强大的开箱即用选项混合到一个快速和有用的工具中。

# 测试边缘

测试需要在我们的代码边界上进行练习，直到超出范围限制。在这个食谱中，我们将深入定义和测试使用`doctest`的边缘。

# 如何做...

通过以下步骤，我们将看到如何编写测试软件边缘的代码：

1.  创建一个名为`recipe22.py`的新文件，并使用它来放置这个食谱的所有代码。

1.  创建一个将十进制数转换为 2 进制到 36 进制之间任何进制的函数：

```py
def convert_to_basen(value, base):
    if base < 2 or base > 36:
        raise Exception("Only support bases 2-36")

    import math
    def _convert(remaining_value, base, exp):
        def stringify(value):
            if value > 9:
                return chr(value + ord('a')-10)
            else:
                return str(value)

        if remaining_value >= 0 and exp >= 0:
            factor = int(math.pow(base, exp))
            if factor <= remaining_value:
                multiple = remaining_value / factor
                return stringify(multiple) + \
                  _convert(remaining_value-multiple*factor, \
                                base, exp-1)
            else:
                return "0" + \
                       _convert(remaining_value, base, exp-1)
        else:
            return ""

    return "%s/%s" % (_convert(value, base, \
                         int(math.log(value, base))), base)
```

1.  在我们的函数声明下面添加一个文档字符串，其中包括显示 2 进制边缘、36 进制边缘和无效的 37 进制的测试：

```py
def convert_to_basen(value, base):
    """Convert a base10 number to basen.

    These show the edges for base 2.
    >>> convert_to_basen(1, 2)
    '1/2'
    >>> convert_to_basen(2, 2)
    '10/2'
    >>> convert_to_basen(0, 2)
    Traceback (most recent call last):
       ...
    ValueError: math domain error

    These show the edges for base 36.
    >>> convert_to_basen(1, 36)
    '1/36'
    >>> convert_to_basen(35, 36)
    'z/36'
    >>> convert_to_basen(36, 36)
    '10/36'
    >>> convert_to_basen(0, 36)
    Traceback (most recent call last):
       ...
    ValueError: math domain error

    These show the edges for base 37.
    >>> convert_to_basen(1, 37)
    Traceback (most recent call last):
       ...
    Exception: Only support bases 2-36
    >>> convert_to_basen(36, 37)
    Traceback (most recent call last):
       ...
    Exception: Only support bases 2-36
    >>> convert_to_basen(37, 37)
    Traceback (most recent call last):
       ...
    Exception: Only support bases 2-36
    >>> convert_to_basen(0, 37)   
    Traceback (most recent call last):
       ...
    Exception: Only support bases 2-36
    """
    if base < 2 or base > 36:
```

1.  添加一个测试运行器：

```py
if __name__ == "__main__":
    import doctest
    doctest.testmod()
```

1.  按照这个屏幕截图展示的方式运行这个食谱：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-test-cb-2e/img/00048.jpeg)

# 它是如何工作的...

这个版本有一个处理 2 进制到 36 进制的限制。

对于 36 进制，它使用`a`到`z`。这与使用`a`到`f`的 16 进制进行比较。在 10 进制中，`35`表示为 36 进制中的`z`。

我们包括了几个测试，包括 2 进制和 36 进制的`1`。我们还测试了在回卷之前的最大值和下一个值，以显示回卷。对于 2 进制，这是`1`和`2`。对于 36 进制，这是`35`和`36`。

正如我们还包括了测试 0 来显示我们的函数不处理任何基数，我们还测试了无效的 36 进制。

# 还有更多...

对于有效的输入，我们的软件能够正常工作是很重要的。同样重要的是，我们的软件对于无效的输入能够按预期工作。我们有文档可以在用户使用我们的软件时查看，记录了这些边缘情况。而且，由于 Python 的`doctest`模块，我们可以测试它，确保我们的软件表现正确。

# 另请参阅

在第一章中提到的*测试边缘*部分，*使用 Unittest 开发基本测试*。

# 通过迭代测试边缘情况

随着我们继续开发我们的代码，边缘情况将会出现。通过在可迭代列表中捕获边缘情况，我们需要编写的代码更少，以捕获另一个测试场景。这可以提高我们测试新场景的效率。

# 如何做...

1.  创建一个名为`recipe23.py`的新文件，并用它来存储这个配方的所有代码。

1.  创建一个将十进制转换为任何其他进制的函数：

```py
def convert_to_basen(value, base):
    import math

    def _convert(remaining_value, base, exp):
        def stringify(value):
            if value > 9:
                return chr(value + ord('a')-10)
            else:
                return str(value)

        if remaining_value >= 0 and exp >= 0:
            factor = int(math.pow(base, exp))
            if factor <= remaining_value:
                multiple = remaining_value / factor
                return stringify(multiple) + \
                  _convert(remaining_value-multiple*factor, \
                                base, exp-1)
            else:
                return "0" + \
                       _convert(remaining_value, base, exp-1)
        else:
            return ""

    return "%s/%s" % (_convert(value, base, \
                         int(math.log(value, base))), base)
```

1.  添加一些包含一系列输入值以生成一系列预期输出的`doctest`实例。包括一个失败的实例：

```py
def convert_to_basen(value, base):
    """Convert a base10 number to basen.

    Base 2
    >>> inputs = [(1,2,'1/2'), (2,2,'11/2')]
    >>> for value,base,expected in inputs:
    ...     actual = convert_to_basen(value,base)
    ...     assert actual == expected, 'expected: %s actual: %s' %
(expected, actual)

    >>> convert_to_basen(0, 2)
    Traceback (most recent call last):
       ...
    ValueError: math domain error

    Base 36.
    >>> inputs = [(1,36,'1/36'), (35,36,'z/36'), (36,36,'10/36')]
    >>> for value,base,expected in inputs:
    ...     actual = convert_to_basen(value,base)
    ...     assert actual == expected, 'expected: %s actual: %s' %
(expected, value)

    >>> convert_to_basen(0, 36)
    Traceback (most recent call last):
       ...
    ValueError: math domain error
    """
    import math
```

1.  添加一个测试运行器：

```py
if __name__ == "__main__":
    import doctest
    doctest.testmod()
```

1.  运行这个配方：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-test-cb-2e/img/00049.jpeg)

在前面的截图中，关键信息在这一行上：`AssertionError: expected: 11/2 actual: 10/2`。这个测试失败有点牵强吗？当然是。但是看到一个显示有用输出的测试用例并不是。重要的是要验证我们的测试是否给了我们足够的信息来修复测试或代码。

# 它是如何工作的...

我们创建了一个数组，每个条目都包含输入数据和预期输出。这为我们提供了一种简单的方式来查看一组测试用例。

然后，我们遍历了每个测试用例，计算了实际值，并通过 Python 的`assert`运行了它。一个需要的重要部分是自定义消息`'expected: %s actual: %s'`。没有它，我们将永远得不到告诉我们哪个测试用例失败的信息。

如果一个测试用例失败会怎么样？

如果数组中的一个测试失败了，那么该代码块将退出并跳过其余的测试。这是为了拥有更简洁的一组测试而进行的权衡。

# 这种类型的测试更适合于 doctest 还是 unittest？

以下是一些标准，可以帮助您决定是否值得将这些测试放入`doctest`中：

+   代码一目了然吗？

+   当用户查看文档字符串时，是否有清晰、简洁、有用的信息？

如果在文档中没有这个的价值，而且它会使代码混乱，那么这是一个明显的提示，表明这个测试块属于一个单独的测试模块。

# 另请参阅

在第一章的*通过迭代测试边缘情况*部分，*使用 Unittest 开发基本测试*

# 用 doctest 变得爱管闲事

到目前为止，我们要么是用测试运行器附加模块，要么是在命令行上输入`python -m doctest <module>`来执行我们的测试。

在上一章中，我们介绍了强大的`nose`库（有关详细信息，请参阅[`somethingaboutorange.com/mrl/projects/nose`](http://somethingaboutorange.com/mrl/projects/nose)）。

简要回顾一下，nose 具有以下功能：

+   为我们提供了方便的测试发现工具`nosetests`

+   可插拔，有大量的插件可用

+   包括一个针对查找 doctests 并运行它们的内置插件

# 准备工作

我们需要激活我们的虚拟环境（`virtualenv`），然后为这个配方安装 nose：

1.  创建一个虚拟环境，激活它，并验证工具是否正常工作。看一下这个截图：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-test-cb-2e/img/00050.jpeg)

1.  使用`pip`，按照截图中显示的方式安装`nose`：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-test-cb-2e/img/00051.jpeg)这个配方假设您已经构建了本章中的所有先前的配方。如果您只构建了其中一些，您的结果可能会有所不同。

# 如何做...

1.  对这个文件夹中的所有模块运行`nosetests -with-doctest`。您可能会注意到它打印了一个非常简短的`.....F.F...F`，表示有三个测试失败了。

1.  运行`nosetests -with-doctest -v`以获得更详细的输出。在下面的截图中，注意到失败的测试与本章前面的示例中失败的测试是相同的。还有一个有价值的地方是看到了`<module>.<method>`格式，要么是`ok`要么是`FAIL`：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-test-cb-2e/img/00052.jpeg)

1.  按照屏幕截图中显示的方式，对`recipe19.py`文件以及`recipe19`模块运行`nosetests -with-doctest`，以不同的组合方式进行测试：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-test-cb-2e/img/00053.jpeg)

# 它是如何工作的...

`nosetests`旨在发现测试用例，然后运行它们。使用这个插件时，当它发现一个文档字符串时，它会使用`doctest`库来进行程序化测试。

`doctest`插件是基于这样的假设构建的，即 doctests 不在与其他测试（如 unittest）相同的包中。这意味着它只会运行从非测试包中找到的 doctests。

`nosetests`并不复杂，也不难使用，`nosetests`旨在成为一个方便使用的工具，让测试触手可及。在这个示例中，我们已经看到了如何使用`nosetests`来获取到目前为止在本章中构建的所有 doctest。

# 更新项目级别的脚本以运行本章的 doctests

这个示例将帮助我们探索构建一个项目级别的脚本，允许我们运行不同的测试套件。我们还将专注于如何在我们的`doctest`中运行它。

# 如何做...

通过以下步骤，我们将创建一个命令行脚本，以允许我们管理一个包括运行`doctest`的项目：

1.  创建一个名为`recipe25.py`的新文件，以放置本示例的所有代码。

1.  添加代码，使用 Python 的`getopt`库解析一组选项：

```py
import getopt
import glob
import logging
import nose
import os
import os.path
import re
import sys
def usage():
    print ()
    print ("Usage: python recipe25.py [command]")
    print ()
    print ("\t--help")
    print ("\t--doctest")
    print ("\t--suite [suite]")
    print ("\t--debug-level [info|debug]")
    print ("\t--package")
    print ("\t--publish")
    print ("\t--register")
    print ()

try:
    optlist, args = getopt.getopt(sys.argv[1:],
            "h",
           ["help", "doctest", "suite=", \
            "debug-level=", "package", \
            "publish", "register"])
except getopt.GetoptError:
    # print help information and exit:
    print "Invalid command found in %s" % sys.argv
    usage()
    sys.exit(2)
```

1.  创建一个映射到`-test`的函数：

```py
def test(test_suite, debug_level):
    logger = logging.getLogger("recipe25")
    loggingLevel = debug_level
    logger.setLevel(loggingLevel)
    ch = logging.StreamHandler()
    ch.setLevel(loggingLevel)
    formatter = logging.Formatter("%(asctime)s - %(name)s - 
(levelname)s - %(message)s")
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    nose.run(argv=["", test_suite, "--verbosity=2"])
```

1.  创建一个映射到`-doctest`的函数：

```py
def doctest(test_suite=None):
    args = ["", "--with-doctest"]
    if test_suite is not None:
        print ("Running doctest suite %s" % test_suite)
        args.extend(test_suite.split(','))
        nose.run(argv=args)
    else:
        nose.run(argv=args)
```

1.  创建支持`package`、`publish`和`register`的存根函数：

```py
def package(): 
    print ("This is where we can plug in code to run " + \
          "setup.py to generate a bundle.")

def publish():
    print ("This is where we can plug in code to upload " + \
          "our tarball to S3 or some other download site.")

def register():
    print ("setup.py has a built in function to " + \
          "'register' a release to PyPI. It's " + \
          "convenient to put a hook in here.")
    # os.system("%s setup.py register" % sys.executable)
```

1.  添加一些代码来检测选项列表是否为空。如果是，让它打印出帮助菜单并退出脚本：

```py
if len(optlist) == 0:
    usage()
    sys.exit(1)
```

1.  添加一些代码来定义调试级别，然后解析选项以允许用户进行覆盖：

```py
debug_levels = {"info":logging.INFO, "debug":logging.DEBUG}
# Default debug level is INFO
debug_level = debug_levels["info"]

for option in optlist:
    if option[0] in ("--debug-level"):
        # Override with a user-supplied debug level
        debug_level = debug_levels[option[1]]
```

1.  添加一些代码，扫描命令行选项以查找`-help`，如果找到，则退出脚本：

```py
# Check for help requests, which cause all other
# options to be ignored.
for option in optlist:
    if option[0] in ("--help", "-h"):
    usage()
    sys.exit(1)
```

1.  添加代码来检查是否选择了`--doctest`。如果是，让它专门扫描`--suite`并通过`doctest()`方法运行它。否则，通过`-suite`运行`test()`方法：

```py
ran_doctests = False
for option in optlist:
    # If --doctest is picked, then --suite is a
    # suboption.
    if option[0] in ("--doctest"):
        suite = None
        for suboption in optlist:
            if suboption[0] in ("--suite"):
                suite = suboption[1]
        print "Running doctests..."
        doctest(suite)
        ran_doctests = True

if not ran_doctests:
    for option in optlist:
        if option[0] in ("--suite"):
            print "Running test suite %s..." % option[1]
            test(option[1], debug_level)
```

1.  通过迭代每个命令行选项来完成，并根据所选的选项调用其他函数：

```py
# Parse the arguments, in order
for option in optlist:
    if option[0] in ("--package"):
        package()

    if option[0] in ("--publish"):
        publish()

    if option[0] in ("--register"):
        register()
```

1.  按照屏幕截图中显示的方式使用`--help`运行脚本：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-test-cb-2e/img/00054.jpeg)

1.  使用`--doctest`运行脚本。注意以下屏幕截图中的前几行输出。它显示了测试的通过和失败以及详细的输出。看一下这个屏幕截图：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-test-cb-2e/img/00055.jpeg)输出要长得多。为了简洁起见，已经对其进行了修剪。

1.  按照屏幕截图中显示的方式，使用`-doctest -suite=recipe16,recipe17.py`运行脚本：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-test-cb-2e/img/00056.jpeg)我们故意使用`recipe16.py`和`recipe17.py`来演示它是如何与模块名和文件名一起工作的。

# 它是如何工作的...

这个脚本使用了 Python 的`getopt`库，它是模仿`getopt()`函数的（有关更多详细信息，请参阅[`docs.python.org/library/getopt.html`](http://docs.python.org/library/getopt.html)）。

我们已经连接了以下函数：

+   `Usage`：提供帮助给用户的函数。

+   `Key`：关键选项定义包括在以下块中：

```py
optlist, args = getopt.getopt(sys.argv[1:],
        "h",
       ["help", "doctest", "suite=", \
        "debug-level=", "package", \
        "publish", "register"])
```

+   +   我们解析除第一个外的所有参数，第一个是可执行文件。

+   `"h"`定义了短选项：`-h`。

+   列表定义了长选项。带有`"="`的选项接受一个参数。没有参数的是标志。

+   如果收到的选项不在列表中，就会抛出异常，我们打印出`usage()`，然后退出。

+   `doctest`：它使用`-with-doctest`通过 nose 运行模块。

+   `package`、`pubilsh`和`register`：这些与上一章中描述的函数类似。

定义了这些函数后，我们现在可以迭代解析的选项。对于这个脚本，有一个顺序：

1.  检查是否有调试覆盖。我们默认为`logging.INFO`，但我们提供切换到`logging.DEBUG`的能力。

1.  检查是否调用了`-h`或`-help`。如果是，打印出`usage()`信息，然后退出，不再解析。

1.  因为`-suite`可以单独用于运行 unittest 测试，或作为`-doctest`的子选项，我们必须解析一下，并弄清楚是否使用了`-doctest`。

1.  最后，迭代选项，并调用它们对应的函数。

为了练习，我们首先用`-help`选项调用这个脚本，打印出我们的命令选择。

然后我们用`-doctest`调用它，看它如何找到这个文件夹中的所有 doctests。在我们的例子中，我们找到了本章的所有配方，包括三个测试失败。

最后，我们用`-doctest -suite=recipe16,recipe17.py`调用脚本。这显示了我们如何选择由逗号分隔的测试子集。通过这个例子，我们看到 nose 可以通过模块名（`recipe16.py`）或文件名（`recipe17.py`）来处理。

# 还有更多...

这个脚本提供的功能可以很容易地通过已经构建的命令来处理。我们在本章前面看过`nosetests`和`doctest`，并看到它如何接受参数来灵活地选择测试。

在 Python 社区中，使用`setup.py`生成 tarballs 和注册发布也是一个常用的功能。

那么为什么要编写这个脚本呢？因为我们可以利用一个命令来利用所有这些功能。


# 第四章：使用行为驱动开发测试客户故事

在本章中，我们将涵盖以下配方：

+   测试的命名听起来像句子和故事

+   测试单独的 doctest 文档

+   使用 doctest 编写可测试的故事

+   使用 doctest 编写可测试的小说

+   使用 Voidspace Mock 和 nose 编写可测试的故事

+   使用 mockito 和 nose 编写可测试的故事

+   使用 Lettuce 编写可测试的故事

+   使用 Should DSL 编写简洁的 Lettuce 断言

+   更新项目级别的脚本以运行本章的 BDD 测试

# 介绍

**行为驱动开发**（**BDD**）是由 Dan North 作为对**测试驱动开发**（**TDD**）的回应而创建的。它专注于用自然语言编写自动化测试，以便非程序员可以阅读。

“程序员想知道从哪里开始，要测试什么，不要测试什么，一次测试多少，如何命名他们的测试，以及如何理解为什么测试失败。我越深入 TDD，就越觉得自己的旅程不是逐渐掌握的过程，而是一系列的盲目尝试。我记得当时想，‘要是当时有人告诉我该多好！’的次数远远多于我想，‘哇，一扇门打开了。’我决定一定有可能以一种直接进入好东西并避开所有陷阱的方式来呈现 TDD。” – Dan North

要了解更多关于 Dan North 的信息，请访问：[`dannorth.net/introducing-bdd/`](https://dannorth.net/introducing-bdd/)。

我们之前在单元测试配方中编写的测试的风格是`testThis`和`testThat`。BDD 采取了摆脱程序员的说法，而转向更加以客户为导向的视角。

Dan North 接着指出 Chris Stevenson 为 Java 的 JUnit 编写了一个专门的测试运行器，以不同的方式打印测试结果。让我们来看一下以下的测试代码：

```py
public class FooTest extends TestCase  {
    public void testIsASingleton() {}
    public void testAReallyLongNameIsAGoodThing() {}
}
```

当通过 AgileDox 运行此代码（[`agiledox.sourceforge.net/`](http://agiledox.sourceforge.net/)）时，将以以下格式打印出来：

```py
Foo
-is a singleton
-a really long name is a good thing
```

AgileDox 做了几件事，比如：

+   它打印出测试名称，去掉测试后缀

+   从每个测试方法中去掉测试前缀

+   它将剩余部分转换成一个句子

AgileDox 是一个 Java 工具，所以我们不会在本章中探讨它。但是有许多 Python 工具可用，我们将看一些，包括 doctest、Voidspace Mock、`mockito`和 Lettuce。所有这些工具都为我们提供了以更自然的语言编写测试的手段，并赋予客户、QA 和测试团队开发基于故事的测试的能力。

所有 BDD 的工具和风格都可以轻松填满一整本书。本章旨在介绍 BDD 的哲学以及一些强大、稳定的工具，用于有效地测试我们系统的行为。

对于本章，让我们为每个配方使用相同的购物车应用程序。创建一个名为`cart.py`的文件，并添加以下代码：

```py
class ShoppingCart(object):
    def __init__(self):
       self.items = []
    def add(self, item, price):
       for cart_item in self.items:
           # Since we found the item, we increment
           # instead of append
           if cart_item.item == item: 
              cart_item.q += 1
              return self
       # If we didn't find, then we append 
       self.items.append(Item(item, price))
       return self
    def item(self, index):
        return self.items[index-1].item
    def price(self, index):
        return self.items[index-1].price * self.items[index-1].q
    def total(self, sales_tax):
        sum_price=sum([item.price*item.q for item in self.items])
        return sum_price*(1.0 + sales_tax/100.0)
    def __len__(self):
        return sum([item.q for item in self.items])
class Item(object):
    def __int__(self,item,price,q=1):
        self.item=item
        self.price=price
        self.q=q
```

考虑以下关于这个购物车的内容：

+   它是基于一的，意味着第一个项目和价格在`[1]`，而不是`[0]`

+   它包括具有相同项目的多个项目

+   它将计算总价格，然后添加税收

这个应用程序并不复杂。相反，它为我们提供了在本章中测试各种客户故事和场景的机会，这些故事和场景不一定局限于简单的单元测试。

# 命名测试听起来像句子和故事

测试方法应该读起来像句子，测试用例应该读起来像章节的标题。这是 BDD 的哲学的一部分，目的是使测试对非程序员易于阅读。

# 准备工作

对于这个配方，我们将使用本章开头展示的购物车应用程序。

# 如何做…

通过以下步骤，我们将探讨如何编写一个自定义的`nose`插件，以 BDD 风格的报告提供结果：

1.  创建一个名为`recipe26.py`的文件来包含我们的测试用例。

1.  创建一个 unittest 测试，其中测试用例表示一个带有一个物品的购物车，测试方法读起来像句子：

```py
import unittest
from cart import *
class CartWithOneItem(unittest.TestCase):
      def setUp(self):
          self.cart = ShoppingCart().add("tuna sandwich", 15.00)
      def test_when_checking_the_size_should_be_one_based(self):
          self.assertEquals(1, len(self.cart))
      def test_when_looking_into_cart_should_be_one_based(self):
          self.assertEquals("tuna sandwich", self.cart.item(1))
          self.assertEquals(15.00, self.cart.price(1))
      def test_total_should_have_in_sales_tax(self):
          self.assertAlmostEquals(15.0*1.0925, \
                              self.cart.total(9.25), 2)
```

1.  添加一个 unittest 测试，其中测试用例表示一个带有两个物品的购物车，测试方法读起来像句子：

```py
class CartWithTwoItems(unittest.TestCase):
     def setUp(self):
         self.cart = ShoppingCart()\
                       .add("tuna sandwich", 15.00)\
                       .add("rootbeer", 3.75) 
    def test_when_checking_size_should_be_two(self):
        self.assertEquals(2, len(self.cart))
    def test_items_should_be_in_same_order_as_entered(self):
       self.assertEquals("tuna sandwich", self.cart.item(1))
       self.assertAlmostEquals(15.00, self.cart.price(1), 2)
       self.assertEquals("rootbeer", self.cart.item(2)) 
       self.assertAlmostEquals(3.75, self.cart.price(2), 2)
   def test_total_price_should_have_in_sales_tax(self):
       self.assertAlmostEquals((15.0+3.75)*1.0925,self.cart.total(9.25),2)
```

1.  添加一个 unittest 测试，其中测试用例表示一个没有物品的购物车，测试方法读起来像句子：

```py
class CartWithNoItems(unittest.TestCase): 
    def setUp(self):
       self.cart = ShoppingCart()
   def test_when_checking_size_should_be_empty(self): 
      self.assertEquals(0, len(self.cart))
   def test_finding_item_out_of_range_should_raise_error(self):
      self.assertRaises(IndexError, self.cart.item, 2)
   def test_finding_price_out_of_range_should_raise_error(self): 
      self.assertRaises(IndexError, self.cart.price, 2)
   def test_when_looking_at_total_price_should_be_zero(self):
      self.assertAlmostEquals(0.0, self.cart.total(9.25), 2)
   def test_adding_items_returns_back_same_cart(self): 
      empty_cart = self.cart
      cart_with_one_item=self.cart.add("tuna sandwich",15.00)
      self.assertEquals(empty_cart, cart_with_one_item) 
      cart_with_two_items = self.cart.add("rootbeer", 3.75) 
      self.assertEquals(empty_cart, cart_with_one_item)
      self.assertEquals(cart_with_one_item, cart_with_two_items)
```

BDD 鼓励使用非常描述性的句子作为方法名。其中有几个方法名被缩短以适应本书的格式，但有些仍然太长。

1.  创建另一个名为`recipe26_plugin.py`的文件，以包含我们定制的 BDD 运行程序。

1.  创建一个`nose`插件，可以用作`–with-bdd`来打印结果：

```py
import sys
err = sys.stderr
import nose
import re
from nose.plugins import Plugin
class BddPrinter(Plugin): 
     name = "bdd"
     def __init__(self): 
         Plugin.__init__(self) 
         self.current_module = None
```

1.  创建一个处理程序，打印出模块或测试方法，剔除多余的信息：

```py
def beforeTest(self, test): 
    test_name = test.address()[-1]
    module, test_method = test_name.split(".") 
    if self.current_module != module:
       self.current_module = module
    fmt_mod = re.sub(r"([A-Z])([a-z]+)", r"\1\2 ", module)
    err.write("\nGiven %s" % fmt_mod[:-1].lower()) 
    message = test_method[len("test"):]
    message = " ".join(message.split("_")) err.write("\n- %s" % message)
```

1.  为成功、失败和错误消息创建一个处理程序：

```py
def addSuccess(self, *args, **kwargs): 
    test = args[0]
    err.write(" : Ok")
def addError(self, *args, **kwargs): 
    test, error = args[0], args[1] 
    err.write(" : ERROR!\n")
def addFailure(self, *args, **kwargs): 
    test, error = args[0], args[1] 
    err.write(" : Failure!\n")
```

1.  创建一个名为`recipe26_plugin.py`的新文件，其中包含一个用于执行此示例的测试运行程序。

1.  创建一个测试运行程序，将测试用例引入并通过`nose`运行，以易于阅读的方式打印结果：

```py
if __name__ == "__main__": 
   import nose
   from recipe26_plugin import *
   nose.run(argv=["", "recipe26", "--with-bdd"], plugins=[BddPrinter()])
```

1.  运行测试运行程序。看一下这个截图：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-test-cb-2e/img/00057.jpeg)

1.  在测试用例中引入一些错误，并重新运行测试运行程序，看看这如何改变输出：

```py
 def test_when_checking_the_size_should_be_one_based(self):
        self.assertEquals(2, len(self.cart))
...
    def test_items_should_be_in_same_order_as_entered(self): 
        self.assertEquals("tuna sandwich", self.cart.item(1)) 
        self.assertAlmostEquals(14.00, self.cart.price(1), 2) 
        self.assertEquals("rootbeer", self.cart.item(2)) 
        self.assertAlmostEquals(3.75, self.cart.price(2), 2)
```

1.  再次运行测试。看一下这个截图：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-test-cb-2e/img/00058.jpeg)

# 工作原理...

测试用例被写成名词，描述正在测试的对象。`CartWithTwoItems`描述了围绕预先填充了两个物品的购物车的一系列测试方法。

测试方法写成句子。它们用下划线串联在一起，而不是空格。它们必须以`test_`为前缀，这样 unittest 才能捕捉到它们。`test_items_should_be_in_the_same_order_as_entered`应该表示应该按输入顺序排列的物品。

这个想法是，我们应该能够通过将这两者结合在一起来快速理解正在测试的内容：给定一个带有两个物品的购物车，物品应该按输入顺序排列。

虽然我们可以通过这种思维过程阅读测试代码，但是在脑海中减去下划线和`test`前缀的琐事，这对我们来说可能会成为真正的认知负担。为了使其更容易，我们编写了一个快速的`nose`插件，将驼峰式测试拆分并用空格替换下划线。这导致了有用的报告格式。

使用这种快速工具鼓励我们编写详细的测试方法，这些方法在输出时易于阅读。反馈不仅对我们有用，而且对我们的测试团队和客户也非常有效，可以促进沟通、对软件的信心，并有助于生成新的测试故事。

# 还有更多...

这里显示的示例测试方法被故意缩短以适应本书的格式。不要试图使它们尽可能短。相反，试着描述预期的输出。

插件无法安装。这个插件是为了快速生成报告而编写的。为了使其可重用，特别是与`nosetests`一起使用。

# 测试单独的 doctest 文档

BDD 不要求我们使用任何特定的工具。相反，它更注重测试的方法。这就是为什么可以使用 Python 的`doctest`编写 BDD 测试场景。`doctest`不限于模块的代码。通过这个示例，我们将探讨创建独立的文本文件来运行 Python 的`doctest`库。

如果这是`doctest`，为什么它没有包含在上一章的示例中？因为在单独的测试文档中编写一组测试的上下文更符合 BDD 的哲学，而不是可供检查的可测试 docstrings。

# 准备工作

对于这个示例，我们将使用本章开头展示的购物车应用程序。

# 如何做...

通过以下步骤，我们将探讨在`doctest`文件中捕获各种测试场景，然后运行它们：

1.  创建一个名为`recipe27_scenario1.doctest`的文件，其中包含`doctest`风格的测试，以测试购物车的操作：

```py
This is a way to exercise the shopping cart 
from a pure text file containing tests.
First, we need to import the modules 
>>> from cart import *
Now, we can create an instance of a cart 
>>> cart = ShoppingCart()
Here we use the API to add an object. Because it returns back the cart, we have to deal with the output
>>> cart.add("tuna sandwich", 15.00) #doctest:+ELLIPSIS 
<cart.ShoppingCart object at ...>
Now we can check some other outputs
>>> cart.item(1) 
'tuna sandwich' 
>>> cart.price(1) 
15.0
>>> cart.total(0.0) 
15.0
```

注意到文本周围没有引号。

1.  在`recipe27_scenario2.doctest`文件中创建另一个场景，测试购物车的边界，如下所示：

```py
This is a way to exercise the shopping cart 
from a pure text file containing tests.
First, we need to import the modules 
>>> from cart import *
Now, we can create an instance of a cart 
>>> cart = ShoppingCart()
Now we try to access an item out of range, expecting an exception.
>>> cart.item(5)
Traceback (most recent call last): 
...
IndexError: list index out of range
We also expect the price method to fail in a similar way.
>>> cart.price(-2)
Traceback (most recent call last): 
...
IndexError: list index out of range
```

1.  创建一个名为`recipe27.py`的文件，并放入查找以`.doctest`结尾的文件并通过`doctest`中的`testfile`方法运行它们的测试运行器代码：

```py
if __name__ == "__main__":
   import doctest
   from glob import glob
   for file in glob("recipe27*.doctest"):
      print ("Running tests found in %s" % file) 
      doctest.testfile(file)
```

1.  运行测试套件。查看以下代码：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-test-cb-2e/img/00059.jpeg)

1.  使用`-v`运行测试套件，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-test-cb-2e/img/00060.jpeg)

# 它是如何工作的...

`doctest`提供了方便的`testfile`函数，它将像处理文档字符串一样处理一块纯文本。这就是为什么与我们在文档字符串中有多个`doctest`时不需要引号的原因。这些文本文件不是文档字符串。

实际上，如果我们在文本周围包含三引号，测试将无法正常工作。让我们以第一个场景为例，在文件的顶部和底部放上`"""`，并将其保存为`recipe27_bad_ scenario.txt`。现在，让我们创建一个名为`recipe27.py`的文件，并创建一个替代的测试运行器来运行我们的坏场景，如下所示：

```py
if __name__ == "__main__":
   import doctest
   doctest.testfile("recipe27_bad_scenario.txt")

```

我们得到以下错误消息：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-test-cb-2e/img/00061.jpeg)

它已经混淆了尾部三引号作为预期输出的一部分。最好直接将它们去掉。

# 还有更多...

将文档字符串移动到单独的文件中有什么好处？这难道不是我们在第二章中讨论的*使用 doctest 创建可测试文档*中所做的相同的事情吗？是和不是。是，从技术上讲是一样的：`doctest`正在处理嵌入在测试中的代码块。

但 BDD 不仅仅是一个技术解决方案。它是由*可读* *客户端* *场景*的哲学驱动的。BDD 旨在测试系统的行为。行为通常由面向客户的场景定义。当我们的客户能够轻松理解我们捕捉到的场景时，这是非常鼓励的。当客户能够看到通过和失败，并且反过来看到已经完成的实际状态时，这是进一步增强的。

通过将测试场景与代码解耦并将它们放入单独的文件中，我们可以为我们的客户使用`doctest`创建可读的测试的关键要素。

# 这难道不违背了文档字符串的可用性吗？

在第二章中，*使用 Nose 运行自动化测试套件*，有几个示例展示了在文档字符串中嵌入代码使用示例是多么方便。它们很方便，因为我们可以从交互式 Python shell 中读取文档字符串。你认为将其中一些内容从代码中提取到单独的场景文件中有什么不同吗？你认为有些`doctest`在文档字符串中会很有用，而其他一些可能在单独的场景文件中更好地为我们服务吗？

# 使用 doctest 编写可测试的故事

在`doctest`文件中捕捉一个简洁的故事是 BDD 的关键。BDD 的另一个方面是提供一个包括结果的可读报告。

# 准备工作

对于这个示例，我们将使用本章开头展示的购物车应用程序。

# 如何做...

通过以下步骤，我们将看到如何编写自定义的`doctest`运行器来生成我们自己的报告：

1.  创建一个名为`recipe28_cart_with_no_items.doctest`的新文件，用于包含我们的`doctest`场景。

1.  创建一个`doctest`场景，演示购物车的操作，如下所示：

```py
This scenario demonstrates a testable story.
First, we need to import the modules 
>>> from cart import *
>>> cart = ShoppingCart()
#when we add an item
>>> cart.add("carton of milk", 2.50) #doctest:+ELLIPSIS 
<cart.ShoppingCart object at ...>
#the first item is a carton of milk 
>>> cart.item(1)
'carton of milk'
#the first price is $2.50 
>>> cart.price(1)
2.5
#there is only one item 
>>> len(cart)
This shopping cart lets us grab more than one of a particular item.
#when we add a second carton of milk
>>> cart.add("carton of milk", 2.50) #doctest:+ELLIPSIS 
<cart.ShoppingCart object at ...>
#the first item is still a carton of milk 
>>> cart.item(1)
'carton of milk'
#but the price is now $5.00 
>>> cart.price(1)
5.0
#and the cart now has 2 items 
>>> len(cart)
2
#for a total (with 10% taxes) of $5.50 
>>> cart.total(10.0)
5.5
```

1.  创建一个名为`recipe28.py`的新文件，用于包含我们自定义的`doctest`运行器。

1.  通过子类化`DocTestRunner`创建一个客户`doctest`运行器，如下所示：

```py
import doctest
class BddDocTestRunner(doctest.DocTestRunner): 
      """
      This is a customized test runner. It is meant 
      to run code examples like DocTestRunner,
      but if a line preceeds the code example 
      starting with '#', then it prints that 
      comment.
      If the line starts with '#when', it is printed 
      out like a sentence, but with no outcome.
      If the line starts with '#', but not '#when'
      it is printed out indented, and with the outcome.
      """
```

1.  添加一个`report_start`函数，查找示例之前以`#`开头的注释，如下所示：

```py
def report_start(self, out, test, example):
    prior_line = example.lineno-1
    line_before = test.docstring.splitlines()[prior_line] 
    if line_before.startswith("#"):
       message = line_before[1:]
       if line_before.startswith("#when"):
          out("* %s\n" % message) 
          example.silent = True 
          example.indent = False
       else:
         out(" - %s: " % message) 
         example.silent = False 
         example.indent = True
   else:
     example.silent = True 
     example.indent = False

   doctest.DocTestRunner(out, test, example)
```

1.  添加一个有条件地打印出`ok`的`report_success`函数，如下所示：

```py
def report_success(self, out, test, example, got):
    if not example.silent:
       out("ok\n")
    if self._verbose:
       if example.indent: out(" ") 
          out(">>> %s\n" % example.source[:-1])
```

1.  添加一个有条件地打印出`FAIL`的`report_failure`函数，如下所示：

```py
def report_failure(self, out, test, example, got):
    if not example.silent:
       out("FAIL\n")
    if self._verbose:
       if example.indent: out(" ") 
           out(">>> %s\n" % example.source[:-1])
```

1.  添加一个运行器，用我们的自定义运行器替换`doctest.DocTestRunner`，然后查找要运行的`doctest`文件，如下所示：

```py
if __name__ == "__main__":
   from glob import glob
   doctest.DocTestRunner = BddDocTestRunner
   for file in glob("recipe28*.doctest"):
       given = file[len("recipe28_"):]
       given = given[:-len(".doctest")]
       given = " ".join(given.split("_"))
       print ("===================================")
       print ("Given a %s..." % given)
       print ("===================================")
       doctest.testfile(file)
```

1.  使用运行器来执行我们的场景。看一下这个截图：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-test-cb-2e/img/00062.jpeg)

1.  使用带有`-v`的运行器来执行我们的场景，如此截图所示：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-test-cb-2e/img/00063.jpeg)

1.  修改测试场景，使其中一个预期结果失败，使用以下代码：

```py
#there is only one item 
>>> len(cart)
4668
```

注意，我们已将预期结果从`1`更改为`4668`，以确保失败。

1.  再次使用带有`-v`的运行器，并查看结果。看一下这个截图：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-test-cb-2e/img/00064.jpeg)

# 它是如何工作的...

`doctest`提供了一种方便的方法来编写可测试的场景。首先，我们编写了一系列我们希望购物车应用程序证明的行为。为了使事情更加完善，我们添加了许多详细的评论，以便任何阅读此文档的人都能清楚地理解事情。

这为我们提供了一个可测试的场景。但它让我们缺少一个关键的东西：*简洁的报告*。

不幸的是，`doctest`不会为我们打印出所有这些详细的评论。

为了使其从 BDD 的角度可用，我们需要能够嵌入选择性的注释，当测试序列运行时打印出来。为此，我们将子类化`doctest.DocTestRunner`并插入我们版本的处理文档字符串的方法。

# 还有更多...

`DocTestRunner`方便地为我们提供了文档字符串的处理方法，以及代码示例开始的确切行号。我们编写了`BddDocTestRunner`来查看其前一行，并检查它是否以`#`开头，这是我们自定义的文本在测试运行期间打印出来的标记。

`#when`注释被视为原因。换句话说，`when`引起一个或多个*效果*。虽然`doctest`仍将验证与`when`相关的代码；但出于 BDD 目的，我们并不真正关心结果，因此我们会默默地忽略它。

任何其他`#`注释都被视为效果。对于这些效果中的每一个，我们会去掉`#`，然后缩进打印出句子，这样我们就可以轻松地看到它与哪个`when`相关联。最后，我们打印出`ok`或`FAIL`来指示结果。

这意味着我们可以向文档添加所有我们想要的细节。但对于测试块，我们可以添加将被打印为*原因*（`#when`）或效果（`#其他`）的语句。

# 使用 doctest 编写可测试的小说

运行一系列故事测试展示了代码的预期行为。我们之前在*使用 doctest 编写可测试的故事*配方中已经看到了如何构建一个可测试的故事并生成有用的报告。

通过这个配方，我们将看到如何使用这种策略将多个可测试的故事串联起来，形成一个可测试的小说。

# 准备工作

对于此配方，我们将使用本章开头显示的购物车应用程序。

我们还将重用本章中*使用 doctest 编写可测试故事*中定义的`BddDocTestRunner`，但我们将稍微修改它，实施以下步骤。

# 如何做...

1.  创建一个名为`recipe29.py`的新文件。

1.  将包含`BddDocTestRunner`的代码从*使用 doctest 编写可测试的故事*配方复制到`recipe29.py`中。

1.  修改`__main__`可运行程序，仅搜索此配方的`doctest`场景，如下所示的代码：

```py
if __name__ == "__main__":
   from glob import glob
   doctest.DocTestRunner = BddDocTestRunner
   for file in glob("recipe29*.doctest"):
 given = file[len("recipe29_"):] 
       given = given[:-len(".doctest")]
       given = " ".join(given.split("_"))
       print ("===================================")
       print ("Given a %s..." % given)
       print ("===================================")
       doctest.testfile(file)
```

1.  创建一个名为`recipe29_cart_we_will_load_with_identical_items.doctest`的新文件。

1.  向其中添加一个场景，通过添加相同对象的两个实例来测试购物车：

```py
>>> from cart import *
>>> cart = ShoppingCart()
#when we add an item
>>> cart.add("carton of milk", 2.50) #doctest:+ELLIPSIS
<cart.ShoppingCart object at ...>
#the first item is a carton of milk
>>> cart.item(1)
'carton of milk'
#the first price is $2.50
>>> cart.price(1)
2.5
#there is only one item
>>> len(cart)
1
This shopping cart let's us grab more than one of a particular item.
#when we add a second carton of milk
>>> cart.add("carton of milk", 2.50) #doctest:+ELLIPSIS
<cart.ShoppingCart object at ...>
#the first item is still a carton of milk
>>> cart.item(1) 
'carton of milk'
#but the price is now $5.00
>>> cart.price(1)
5.0
#and the cart now has 2 items
>>> len(cart)
2
#for a total (with 10% taxes) of $5.50
>>> cart.total(10.0)
5.5

```

1.  创建另一个名为`recipe29_cart_we_will_load_with_two_different_items.docstest`的文件。

1.  在该文件中，创建另一个场景，测试通过添加两个不同实例的购物车，如下所示的代码：

```py
>>> from cart import *
>>> cart = ShoppingCart()
#when we add a carton of milk...
>>> cart.add("carton of milk", 2.50) #doctest:+ELLIPSIS 
<cart.ShoppingCart object at ...>
#when we add a frozen pizza...
>>> cart.add("frozen pizza", 3.00) #doctest:+ELLIPSIS
 <cart.ShoppingCart object at ...>
#the first item is the carton of milk
>>> cart.item(1)
'carton of milk'
#the second item is the frozen pizza
>>> cart.item(2)
'frozen pizza'
#the first price is $2.50
>>> cart.price(1)
2.5
#the second price is $3.00
>>> cart.price(2)
3.0
#the total with no tax is $5.50
>>> cart.total(0.0)
5.5
#the total with 10% tax is $6.05
>>> print (round(cart.total(10.0), 2) )
6.05
```

1.  创建一个名为`recipe29_cart_that_we_intend_to_keep_empty.doctest`的新文件。

1.  在那个文件中，创建一个第三个场景，测试购物车添加了空值，但尝试访问范围之外的值，如下面的代码所示：

```py
>>>from cart import *
#when we create an empty shopping cart 
>>> cart = ShoppingCart()
#accessing an item out of range generates an exception
>>> cart.item(5)
Traceback (most recent call last):
...
IndexError: list index out of range
#accessing a price with a negative index causes an exception
>>> cart.price(-2)
Traceback (most recent call last):
...
IndexError: list index out of range
#calculating a price with no tax results in $0.00
>>> cart.total(0.0)
0.0
#calculating a price with a tax results in $0.00
>>> cart.total(10.0)
0.0
```

1.  使用 runner 来执行我们的场景。看一下这个截图：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-test-cb-2e/img/00065.jpeg)

# 它是如何工作的...

我们重用了上一个食谱中开发的测试运行器。关键是扩展场景，以确保我们完全覆盖了预期的场景。

我们需要确保我们能处理以下情况：

+   一个有两个相同物品的购物车

+   一个有两个不同物品的购物车

+   一个空购物车的退化情况

# 还有更多...

编写测试的一个有价值的部分是选择有用的名称。在我们的情况下，每个可测试的故事都以一个空购物车开始。然而，如果我们将每个场景命名为*给定一个空购物车*，这将导致重叠，并且不会产生一个非常有效的报告。

因此，我们根据我们故事的意图来命名它们：

```py
recipe29_cart_we_will_load_with_identical_items.doctest
recipe29_cart_we_will_load_with_two_different_items.doctest
recipe29_cart_that_we_intend_to_keep_empty.doctest
```

这导致：

+   给定一个我们将装满相同物品的购物车

+   给定一个我们将装满两个不同物品的购物车

+   给定一个我们打算保持为空的购物车

这些场景的目的更加清晰。

命名场景很像软件开发的某些方面，更像是一种工艺而不是科学。调整性能往往更具科学性，因为它涉及到一个测量和调整的迭代过程。但是命名场景以及它们的原因和影响往往更像是一种工艺。它涉及与所有利益相关者的沟通，包括 QA 和客户，这样每个人都可以阅读和理解故事。

不要感到害怕。准备好接受变化

开始编写你的故事。让它们起作用。然后与利益相关者分享。反馈很重要，这就是使用基于故事的测试的目的。准备好接受批评和建议的改变。

准备好接受更多的故事请求。事实上，如果你的一些客户或 QA 想要编写他们自己的故事，也不要感到惊讶。这是一个积极的迹象。

如果你是第一次接触这种类型的客户互动，不要担心。你将培养宝贵的沟通技能，并与利益相关者建立牢固的专业关系。与此同时，你的代码质量肯定会得到提高。

# 使用 Voidspace Mock 和 nose 编写可测试的故事

当我们的代码通过方法和属性与其他类交互时，这些被称为协作者。使用 Voidspace Mock（[`www.voidspace.org.uk/python/mock/`](http://www.voidspace.org.uk/python/mock/)）来模拟协作者，由 Michael Foord 创建，为 BDD 提供了一个关键工具。模拟提供了与存根提供的固定状态相比的固定行为。虽然模拟本身并不定义 BDD，但它们的使用与 BDD 的想法密切重叠。

为了进一步展示测试的行为性质，我们还将使用`pinocchio`项目中的`spec`插件（[`darcs.idyll.org/~t/projects/pinocchio/doc`](http://darcs.idyll.org/~t/projects/pinocchio/doc)）。

正如项目网站上所述，Voidspace Mock 是实验性的。本书是使用版本 0.7.0 beta 3 编写的。在达到稳定的 1.0 版本之前，可能会发生更多的 API 更改的风险。鉴于这个项目的高质量、优秀的文档和博客中的许多文章，我坚信它应该在本书中占有一席之地。

# 准备工作

对于这个食谱，我们将使用本章开头展示的购物车应用程序，并进行一些轻微的修改：

1.  创建一个名为`recipe30_cart.py`的新文件，并复制本章介绍中创建的`cart.py`中的所有代码。

1.  修改`__init__`以添加一个额外的用于持久性的`storer`属性：

```py
class ShoppingCart(object):
     def __init__(self, storer=None):
        self.items = []
        self.storer = storer
```

1.  添加一个使用`storer`保存购物车的`store`方法：

```py
    def store(self):
        return self.storer.store_cart(self)
```

1.  添加一个`retrieve`方法，通过使用`storer`更新内部的`items`：

```py
    def restore(self, id):
       self.items = self.storer.retrieve_cart(id).items 
       return self
```

`storer`的 API 的具体细节将在本食谱的后面给出。

我们需要激活我们的虚拟环境，然后为这个示例安装 Voidspace Mock：

1.  创建一个虚拟环境，激活它，并验证工具是否正常工作。看一下下面的截图：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-test-cb-2e/img/00066.jpeg)

1.  通过输入`pip install mock`来安装 Voidspace Mock。

1.  通过输入`pip install http://darcs.idyll.org/~t/projects/pinocchio-latest.tar.gz`来安装 Pinocchio 的最新版本。

1.  这个版本的 Pinocchio 引发了一些警告。为了防止它们，我们还需要通过输入`pip install figleaf`来安装`figleaf`。

# 如何做到这一点...

通过以下步骤，我们将探讨如何使用模拟来编写可测试的故事：

1.  在`recipe30_cart.py`中，创建一个具有存储和检索购物车空方法的`DataAccess`类：

```py
class DataAccess(object):
     def store_cart(self,cart):
         pass
     def retrieve_cart(self,id):
         pass
```

1.  创建一个名为`recipe30.py`的新文件来编写测试代码。

1.  创建一个自动化的 unittest，通过模拟`DataAccess`的方法来测试购物车：

```py
import unittest
from copy import deepcopy 
from recipe30_cart import *
from mock import Mock
class CartThatWeWillSaveAndRestoreUsingVoidspaceMock(unittest. TestCase):
      def test_fill_up_a_cart_then_save_it_and_restore_it(self):
          # Create an empty shopping cart
          cart = ShoppingCart(DataAccess())
          # Add a couple of items 
          cart.add("carton of milk", 2.50) 
          cart.add("frozen pizza", 3.00)
          self.assertEquals(2, len(cart))
          # Create a clone of the cart for mocking 
          # purposes.
          original_cart = deepcopy(cart)
          # Save the cart at this point in time into a database 
          # using a mock
          cart.storer.store_cart = Mock()
          cart.storer.store_cart.return_value = 1 
          cart.storer.retrieve_cart = Mock() 
          cart.storer.retrieve_cart.return_value = original_cart
          id = cart.store()
          self.assertEquals(1, id)
          # Add more items to cart 
          cart.add("cookie dough", 1.75) 
          cart.add("ginger ale", 3.25)
          self.assertEquals(4, len(cart))
          # Restore the cart to the last point in time 
          cart.restore(id)
          self.assertEquals(2, len(cart))
          cart.storer.store_cart.assert_called_with(cart)
          cart.storer.retrieve_cart.assert_called_with(1)
```

1.  使用`nosetests`和`spec`插件运行测试：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-test-cb-2e/img/00067.jpeg)

# 它是如何工作的...

模拟是确认方法调用的测试替身，这是*行为*。这与存根不同，存根提供了预先准备的数据，允许我们确认状态。

许多模拟库都是基于*记录*/*回放*模式的。它们首先要求测试用例在使用时*记录*模拟将受到的每个行为。然后我们将模拟插入到我们的代码中，允许我们的代码对其进行调用。最后，我们执行*回放*，Mock 库将比较我们期望的方法调用和实际发生的方法调用。

记录/回放模拟的一个常见问题是，如果我们漏掉了一个方法调用，我们的测试就会失败。当试图模拟第三方系统或处理可能与复杂系统状态相关联的可变调用时，捕获所有方法调用可能变得非常具有挑战性。

Voidspace Mock 库通过使用*action*/*assert*模式而不同。我们首先生成一个模拟对象，并定义我们希望它对某些*操作*做出反应。然后，我们将其插入到我们的代码中，使我们的代码对其进行操作。最后，我们*断言*模拟发生了什么，只选择我们关心的操作。没有必要断言模拟体验的每个行为。

为什么这很重要？记录/回放要求我们记录代码、第三方系统和调用链中所有其他层次的方法调用。坦率地说，我们可能并不需要这种行为的确认水平。通常，我们主要关注的是顶层的交互。操作/断言让我们减少我们关心的行为调用。我们可以设置我们的模拟对象来生成必要的顶层操作，基本上忽略较低层次的调用，而记录/回放模拟会强制我们记录这些调用。

在这个示例中，我们模拟了`DataAccess`操作`store_cart`和`retrieve_cart`。我们定义了它们的`return_value`，并在测试结束时断言它们被调用了以下：

```py
cart.storer.store_cart.assert_called_with(cart)
cart.storer.retrieve_cart.assert_called_with(1)
```

`cart.storer`是我们用模拟注入的内部属性。

模拟方法意味着用模拟对象替换对真实方法的调用。

存根方法意味着用存根对象替换对真实方法的调用。

# 还有更多...

因为这个测试用例侧重于从购物车的角度进行存储和检索，我们不必定义真实的`DataAccess`调用。这就是为什么我们在它们的方法定义中简单地放置了`pass`。

这方便地让我们在不强迫选择购物车存储在关系数据库、NoSQL 数据库、平面文件或任何其他文件格式的情况下，处理持久性的行为。这表明我们的购物车和数据持久性很好地解耦。

# 告诉我更多关于 spec nose 插件！

我们很快地浏览了`nose`的有用的`spec`插件。它提供了与我们在*命名测试，使其听起来像句子和故事*部分手工编码的基本功能相同。它将测试用例名称和测试方法名称转换为可读的结果。它给了我们一个可运行的`spec`。这个插件可以与 unittest 一起使用，不关心我们是否使用了 Voidspace Mock。

# 为什么我们没有重用食谱“命名测试，使其听起来像句子和故事”中的插件？

另一个表达这个问题的方式是*我们为什么首先编写了那个食谱的插件？*使用测试工具的一个重要点是理解它们的工作原理，以及如何编写我们自己的扩展。*命名测试，使其听起来像句子和故事*部分不仅讨论了命名测试的哲学，还探讨了编写`nose`插件以支持这种需求的方法。在这个食谱中，我们的重点是使用 Voidspace Mock 来验证某些行为，而不是编写`nose`插件。通过现有的`spec`插件轻松生成漂亮的 BDD 报告。

# 另请参阅

*使用 mockito 和 nose 编写可测试的故事。*

# 使用 mockito 和 nose 编写可测试的故事

当我们的代码通过方法和属性与其他类交互时，这些被称为协作者。使用`mockito`（[`code.google.com/p/mockito`](http://code.google.com/p/mockito)和[`code.google.com/p/mockito-python`](http://code.google.com/p/mockito-python)）模拟协作者为 BDD 提供了一个关键工具。模拟提供了预先定义的行为，而存根提供了预先定义的状态。虽然单独的模拟本身并不定义 BDD，但它们的使用与 BDD 的思想密切相关。

为了进一步展示测试的行为性质，我们还将使用`pinocchio`项目中的`spec`插件（[`darcs.idyll.org/~t/projects/ pinocchio/doc`](http://darcs.idyll.org/~t/projects/)）。

# 准备工作

对于这个食谱，我们将使用本章开头展示的购物车应用程序，并进行一些轻微的修改：

1.  创建一个名为`recipe31_cart.py`的新文件，并复制本章开头创建的`cart.py`中的所有代码。

1.  修改`__init__`以添加一个额外的用于持久化的`storer`属性：

```py
class ShoppingCart(object):
    def __init__(self, storer=None):
    self.items = []
    self.storer = storer
```

1.  添加一个使用`storer`来保存购物车的`store`方法：

```py
   def store(self):
       return self.storer.store_cart(self)
```

1.  添加一个`retrieve`方法，通过使用`storer`来更新内部的`items`：

```py
  def restore(self, id):
      self.items = self.storer.retrieve_cart(id).items
      return self
```

存储器的 API 的具体信息将在本食谱的后面给出。

我们需要激活我们的虚拟环境，然后为这个食谱安装`mockito`：

1.  创建一个虚拟环境，激活它，并验证工具是否正常工作：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-test-cb-2e/img/00068.jpeg)

1.  通过输入`pip install mockito`来安装`mockito`。

使用与*使用 Voidspace Mock 和 nose 编写可测试的故事*食谱相同的步骤安装`pinocchio`和`figleaf`。

# 如何做...

通过以下步骤，我们将探讨如何使用模拟来编写可测试的故事：

1.  在`recipe31_cart.py`中，创建一个`DataAccess`类，其中包含用于存储和检索购物车的空方法：

```py
class DataAccess(object):
     def store_cart(self, cart):
         pass
     def retrieve_cart(self, id):
         pass
```

1.  为编写测试代码创建一个名为`recipe31.py`的新文件。

1.  创建一个自动化的单元测试，通过模拟`DataAccess`的方法来测试购物车：

```py
import unittest
from copy import deepcopy
from recipe31_cart import *
from mockito import *
class CartThatWeWillSaveAndRestoreUsingMockito(unittest.TestCase):
      def test_fill_up_a_cart_then_save_it_and_restore_it(self):
          # Create an empty shopping cart
          cart = ShoppingCart(DataAccess())
          # Add a couple of items
          cart.add("carton of milk", 2.50)
          cart.add("frozen pizza", 3.00)
          self.assertEquals(2, len(cart))
         # Create a clone of the cart for mocking
         # purposes.
         original_cart = deepcopy(cart)
         # Save the cart at this point in time into a database
         # using a mock
         cart.storer = mock()
         when(cart.storer).store_cart(cart).thenReturn(1)
         when(cart.storer).retrieve_cart(1). \   
                             thenReturn(original_cart)
         id = cart.store()
         self.assertEquals(1, id)
         # Add more items to cart
         cart.add("cookie dough", 1.75)
         cart.add("ginger ale", 3.25)
         self.assertEquals(4, len(cart))
         # Restore the cart to the last point in time
         cart.restore(id)
         self.assertEquals(2, len(cart))
         verify(cart.storer).store_cart(cart)
         verify(cart.storer).retrieve_cart(1)

```

1.  使用`spec`插件运行测试`nosetests`：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-test-cb-2e/img/00069.jpeg)

# 它是如何工作的...

这个食谱与之前的食谱非常相似，*使用 Voidspace Mock 和 nose 编写可测试的故事*。关于模拟和 BDD 的好处的详细信息，阅读那个食谱非常有用。

让我们比较 Voidspace Mock 和`mockito`的语法，以了解它们之间的区别。看一下以下 Voidspace Mock 的代码块：

```py
         cart.storer.store_cart = Mock()
         cart.storer.store_cart.return_value = 1
         cart.storer.retrieve_cart = Mock()
         cart.storer.retrieve_cart.return_value = original_cart
```

它显示了被模拟的`store_cart`函数：

```py
         cart.storer = mock()
         when(cart.storer).store_cart(cart).thenReturn(1)
         when(cart.storer).retrieve_cart(1).thenReturn(original_cart)
```

`mockito`通过模拟整个`storer`对象来实现这一点。`mockito`起源于 Java 的模拟工具，这解释了它的类似 Java 的 API，如`thenReturn`，与 Voidspace Mock 的 Python 风格的`return_value`相比。

有些人认为 Java 对 Python 的`mockito`实现的影响令人不快。坦率地说，我认为这不足以丢弃一个库。在前面的例子中，`mockito`以更简洁的方式记录了期望的行为，这绝对可以抵消类似 Java 的 API。

# 另请参阅

*使用 Voidspace Mock 和 nose 编写可测试的故事。*

# 使用 Lettuce 编写可测试的故事

**Lettuce** ([`lettuce.it`](http://lettuce.it))是一个为 Python 构建的类似 Cucumber 的 BDD 工具。

Cucumber ([`cukes.info`](http://cukes.info))是由 Ruby 社区开发的，提供了一种以文本方式编写场景的方法。通过让利益相关者阅读这些故事，他们可以轻松地辨别出软件预期要做的事情。

这个教程展示了如何安装 Lettuce，编写一个测试故事，然后将其连接到我们的购物车应用程序中，以执行我们的代码。

# 准备好...

对于这个教程，我们将使用本章开头展示的购物车应用程序。我们还需要安装 Lettuce 及其依赖项。

通过输入`pip install lettuce`来安装 Lettuce。

# 如何做...

在接下来的步骤中，我们将探讨如何使用 Lettuce 创建一些可测试的故事，并将它们连接到可运行的 Python 代码中：

1.  创建一个名为`recipe32`的新文件夹，以包含本教程中的所有文件。

1.  创建一个名为`recipe32.feature`的文件来记录我们的故事。根据我们的购物车，编写我们新功能的顶层描述：

```py
Feature: Shopping cart As a shopper
   I want to load up items in my cart
   So that I can check out and pay for them
```

1.  让我们首先创建一个场景，捕捉购物车为空时的行为：

```py
       Scenario: Empty cart
            Given an empty cart
            Then looking up the fifth item causes an error
            And looking up a negative price causes an error
            And the price with no taxes is $0.00
            And the price with taxes is $0.00
```

1.  添加另一个场景，展示当我们添加牛奶盒时会发生什么：

```py
       Scenario: Cart getting loaded with multiple of the same 
            Given an empty cart
            When I add a carton of milk for $2.50
            And I add another carton of milk for $2.50 
            Then the first item is a carton of milk
            And the price is $5.00 And the cart has 2 items
            And the total cost with 10% taxes is $5.50
```

1.  添加第三个场景，展示当我们结合一盒牛奶和一份冷冻比萨时会发生什么：

```py
    Scenario: Cart getting loaded with different items 
            Given an empty cart
            When I add a carton of milk
            And I add a frozen pizza
            Then the first item is a carton of milk
            And the second item is a frozen pizza
            And the first price is $2.50
            And the second price is $3.00
            And the total cost with no taxes is $5.50
            And the total cost with 10% taes is $6.05
```

1.  让我们通过 Lettuce 运行故事，看看结果如何，考虑到我们还没有将这个故事与任何 Python 代码联系起来。在下面的截图中，很难辨别输出的颜色。特性和场景声明是白色的。`Given`，`When`和`Then`是未定义的，颜色是黄色的。这表明我们还没有将步骤与任何代码联系起来：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-test-cb-2e/img/00070.jpeg)

1.  在`recipe32`中创建一个名为`steps.py`的新文件，以实现对`Given`的支持所需的步骤。

1.  在`steps.py`中添加一些代码来实现第一个`Given`：

```py
from lettuce import *
from cart import *
@step("an empty cart")
def an_empty_cart(step):
   world.cart = ShoppingCart()
```

1.  要运行这些步骤，我们需要确保包含`cart.py`模块的当前路径是我们的`PYTHONPATH`的一部分。

对于 Linux 和 Mac OSX 系统，输入`export PYTHONPATH=/path/to/ cart.py`。

对于 Windows 系统，转到控制面板|系统|高级，点击环境变量，要么编辑现有的`PYTHONPATH`变量，要么添加一个新的变量，指向包含`cart.py`的文件夹。

1.  再次运行故事。在下面的截图中很难看到，但是`Given an empty cart`现在是绿色的：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-test-cb-2e/img/00071.jpeg)

虽然这个截图只关注第一个场景，但是所有三个场景都有相同的`Given`。我们编写的代码满足了所有三个`Given`。

1.  添加代码到`steps.py`中，实现对第一个场景的`Then`的支持：

```py
@step("looking up the fifth item causes an error") 
def looking_up_fifth_item(step):
    try:
      world.cart.item(5)
      raise AssertionError("Expected IndexError") 
    except IndexError, e:
      pass
@step("looking up a negative price causes an error")
    def looking_up_negative_price(step):
        try:
          world.cart.price(-2)
             raise AssertionError("Expected IndexError")
        except IndexError, e:
          pass
@step("the price with no taxes is (.*)")
    def price_with_no_taxes(step, total):
       assert world.cart.total(0.0) == float(total)
@step("the price with taxes is (.*)")
    def price_with_taxes(step, total):
        assert world.cart.total(10.0) == float(total)

```

1.  再次运行故事，注意第一个场景完全通过了，如下图所示：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-test-cb-2e/img/00072.jpeg)

1.  现在在`steps.py`中添加代码，以实现对第二个场景所需的步骤：

```py
@step("I add a carton of milk for (.*)")
def add_a_carton_of_milk(step, price):
    world.cart.add("carton of milk", float(price))
@step("I add another carton of milk for (.*)")
def add_another_carton_of_milk(step, price):
    world.cart.add("carton of milk", float(price))
@step("the first item is a carton of milk")
def check_first_item(step):
    assert world.cart.item(1) == "carton of milk"
@step("the price is (.*)")
def check_first_price(step, price):
    assert world.cart.price(1) == float(price)
@step("the cart has (.*) items")
def check_size_of_cart(step, num_items): 
    assert len(world.cart) == float(num_items)
@step("the total cost with (.*)% taxes is (.*)")
def check_total_cost(step, tax_rate, total):
    assert world.cart.total(float(tax_rate))==float(total)
```

1.  最后，在`steps.py`中添加代码来实现最后一个场景所需的步骤：

```py
@step("I add a carton of milk")
def add_a_carton_of_milk(step):
    world.cart.add("carton of milk", 2.50)
@step("I add a frozen pizza")
def add_a_frozen_pizza(step):
    world.cart.add("frozen pizza", 3.00)
@step("the second item is a frozen pizza")
def check_the_second_item(step):
    assert world.cart.item(2) == "frozen pizza"
@step("the first price is (.*)")
def check_the_first_price(step, price):
   assert world.cart.price(1) == float(price)
@step("the second price is (.*)")
def check_the_second_price(step, price): 
    assert world.cart.price(2) == float(price)
@step("the total cost with no taxes is (.*)")
def check_total_cost_with_no_taxes(step, total):
    assert world.cart.total(0.0) == float(total)
@step("the total cost with (.*)% taxes is (.*)")
def check_total_cost_with_taxes(step, tax_rate, total):
    assert round(world.cart.total(float(tax_rate)),2) == float(total)
```

1.  通过输入`lettuce recipe32`运行故事，看看它们现在都通过了。在下一个截图中，我们有所有测试都通过了，一切都是绿色的：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-test-cb-2e/img/00073.jpeg)

# 它是如何工作的...

Lettuce 使用流行的`Given`/`When`/`Then`风格的 BDD 故事叙述。

+   **Givens**：这涉及设置一个场景。这通常包括创建对象。对于我们的每个场景，我们创建了一个`ShoppingCart`的实例。这与 unittest 的 setup 方法非常相似。

+   **Thens**：这对应于`Given`。这些是我们想要在一个场景中执行的操作。我们可以执行多个`Then`。

+   **Whens**：这涉及测试`Then`的最终结果。在我们的代码中，我们主要使用 Python 的断言。在少数情况下，我们需要检测异常，我们将调用包装在`try-catch`块中，如果预期的异常没有发生，则会抛出异常。

无论我们以什么顺序放置`Given`/`Then`/`When`都无所谓。Lettuce 会记录所有内容，以便所有的 Givens 首先列出，然后是所有的`When`条件，然后是所有的`Then`条件。Lettuce 通过将连续的`Given`/`When`/`Then`条件转换为`And`来进行最后的润色，以获得更好的可读性。

# 还有更多...

如果你仔细看一些步骤，你会注意到一些通配符：

```py
@step("the total cost with (.*)% taxes is (.*)")
def check_total_cost(step, tax_rate, total):
   assert world.cart.total(float(tax_rate)) == float(total)

```

`@step`字符串让我们通过使用模式匹配器动态抓取字符串的部分作为变量：

+   第一个`(.*)`是一个捕获`tax_rate`的模式

+   第二个`(.*)`是一个捕获`total`的模式

方法定义显示了这两个额外添加的变量。我们可以随意命名它们。这使我们能够实际上从`recipe32.feature`驱动测试，包括所有数据，并且只使用`steps.py`以一种通用的方式将它们连接在一起。

重要的是要指出存储在`tax_rate`和`total`中的实际值是 Unicode 字符串。因为测试涉及浮点数，我们必须转换变量，否则`assert`会失败。

# 一个故事应该有多复杂？

在这个示例中，我们将所有内容都放入一个故事中。我们的故事涉及各种购物车操作。随着我们编写更多的场景，我们可能会将其扩展为多个故事。这回到了第一章的*将* *复杂* *的* *测试* *分解* *为* *简单* *的* *测试*部分中讨论的概念，*使用 Unittest 开发基本测试*。如果我们在一个场景中包含了太多步骤，它可能会变得太复杂。最好能够在最后轻松验证的情况下可视化单个执行线程。

# 不要将布线代码与应用程序代码混合在一起

该项目的网站展示了一个构建阶乘函数的示例。它既有阶乘函数，也有单个文件中的布线。出于演示目的，这是可以的。但是对于实际的生产使用，最好将应用程序与 Lettuce 布线解耦。这鼓励了一个清晰的接口并展示了可用性。

# Lettuce 在使用文件夹时效果很好

生菜默认情况下会在我们运行它的地方寻找一个`features`文件夹，并发现任何以`.feature`结尾的文件。这样它就可以自动找到我们所有的故事并运行它们。

可以使用`-s`或`--scenarios`来覆盖 features 目录。

# 另请参阅

第一章的*将* *复杂* *的* *测试* *分解* *为* *简单* *的* *测试*部分，*使用 Unittest 开发基本测试*。

# 使用 Should DSL 来使用 Lettuce 编写简洁的断言

Lettuce ([`lettuce.it`](http://lettuce.it))是一个为 Python 构建的 BDD 工具。

**Should DSL** ([`www.should-dsl.info`](http://www.should-dsl.info))提供了一种更简单的方式来为`Then`条件编写断言。

这个示例展示了如何安装 Lettuce 和 Should DSL。然后，我们将编写一个测试故事。最后，我们将使用 Should DSL 将其与我们的购物车应用程序进行连接，以练习我们的代码。

# 准备工作

对于这个示例，我们将使用本章开头展示的购物车应用程序。我们还需要通过以下方式安装 Lettuce 及其依赖项：

+   通过输入`pip install lettuce`来安装 Lettuce

+   通过输入`pip install should_dsl`来安装 Should DSL

# 如何做...

通过以下步骤，我们将使用 Should DSL 来在我们的测试故事中编写更简洁的断言：

1.  创建一个名为`recipe33`的新目录，以包含此食谱的所有文件。

1.  在`recipe33`中创建一个名为`recipe33.feature`的新文件，以包含我们的测试场景。

1.  在`recipe33.feature`中创建一个故事，其中包含几个场景来练习我们的购物车，如下所示：

```py
Feature: Shopping cart
  As a shopper
  I want to load up items in my cart
  So that I can check out and pay for them
     Scenario: Empty cart
        Given an empty cart
        Then looking up the fifth item causes an error
        And looking up a negative price causes an error
        And the price with no taxes is 0.0
        And the price with taxes is 0.0
     Scenario: Cart getting loaded with multiple of the same
        Given an empty cart
        When I add a carton of milk for 2.50
        And I add another carton of milk for 2.50
        Then the first item is a carton of milk
        And the price is 5.00
        And the cart has 2 items
        And the total cost with 10% taxes is 5.50
     Scenario: Cart getting loaded with different items
        Given an empty cart
        When I add a carton of milk
        And I add a frozen pizza
        Then the first item is a carton of milk
        And the second item is a frozen pizza 
        And the first price is 2.50
        And the second price is 3.00
        And the total cost with no taxes is 5.50
        And the total cost with 10% taxes is 6.05
```

1.  编写一组使用 Should DSL 的断言，如下所示：

```py
from lettuce import *
from should_dsl import should, should_not
from cart import *
@step("an empty cart")
def an_empty_cart(step):
    world.cart = ShoppingCart()
@step("looking up the fifth item causes an error")
def looking_up_fifth_item(step):
   (world.cart.item, 5) |should| throw(IndexError)
@step("looking up a negative price causes an error")
def looking_up_negative_price(step):
   (world.cart.price, -2) |should| throw(IndexError)
@step("the price with no taxes is (.*)")
def price_with_no_taxes(step, total):
   world.cart.total(0.0) |should| equal_to(float(total))
@step("the price with taxes is (.*)")
def price_with_taxes(step, total):
   world.cart.total(10.0) |should| equal_to(float(total))
@step("I add a carton of milk for 2.50")
def add_a_carton_of_milk(step):
   world.cart.add("carton of milk", 2.50)
@step("I add another carton of milk for 2.50")
def add_another_carton_of_milk(step):
   world.cart.add("carton of milk", 2.50)
@step("the first item is a carton of milk")
def check_first_item(step):
   world.cart.item(1) |should| equal_to("carton of milk")
@step("the price is 5.00")
def check_first_price(step):
   world.cart.price(1) |should| equal_to(5.0)
@step("the cart has 2 items")
def check_size_of_cart(step):
   len(world.cart) |should| equal_to(2)
@step("the total cost with 10% taxes is 5.50")
def check_total_cost(step):
   world.cart.total(10.0) |should| equal_to(5.5)
@step("I add a carton of milk")
def add_a_carton_of_milk(step):
   world.cart.add("carton of milk", 2.50)
@step("I add a frozen pizza")
def add_a_frozen_pizza(step):
   world.cart.add("frozen pizza", 3.00)
@step("the second item is a frozen pizza")
def check_the_second_item(step):
   world.cart.item(2) |should| equal_to("frozen pizza")
@step("the first price is 2.50")
def check_the_first_price(step):
   world.cart.price(1) |should| equal_to(2.5)
@step("the second price is 3.00")
def check_the_second_price(step):
   world.cart.price(2) |should| equal_to(3.0)
@step("the total cost with no taxes is 5.50")
def check_total_cost_with_no_taxes(step):
   world.cart.total(0.0) |should| equal_to(5.5)
@step("the total cost with 10% taxes is (.*)")
def check_total_cost_with_taxes(step, total):
   world.cart.total(10.0) |should| close_to(float(total),\
delta=0.1)
```

1.  运行故事：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-test-cb-2e/img/00074.jpeg)

# 它是如何工作的...

前一个食谱（*使用 Lettuce 编写可测试的故事*）展示了更多关于 Lettuce 如何工作的细节。这个食谱演示了如何使用 Should DSL 来进行有用的断言。

为什么我们需要 Should DSL？我们编写的最简单的检查涉及测试值以确认购物车应用程序的行为。在前一个食谱中，我们主要使用了 Python 断言，比如：

```py
assert len(context.cart) == 2
```

这很容易理解。Should DSL 提供了一个简单的替代方案，就是这个：

```py
len(context.cart) |should| equal_to(2)
```

这看起来有很大的不同吗？有人说是，有人说不是。它更啰嗦，对于一些人来说更容易阅读。对于其他人来说，它不是。

那么为什么我们要访问这个？因为 Should DSL 不仅仅有`equal_to`。还有许多其他命令，比如这些：

+   `be`：检查身份

+   `contain, include, be_into`：验证对象是否包含或包含另一个对象

+   `be_kind_of`：检查类型

+   `be_like`：使用正则表达式进行检查

+   `be_thrown_by,throws`：检查是否引发了异常

+   `close_to`：检查值是否接近，给定一个增量

+   `end_with`：检查字符串是否以给定的后缀结尾

+   `equal_to`：检查值的相等性

+   `respond_to`：检查对象是否具有给定的属性或方法

+   `start_with`：检查字符串是否以给定的前缀开头

还有其他替代方案，但这提供了多样的比较。如果我们想象需要编写检查相同事物的断言所需的代码，那么事情会变得更加复杂。

例如，让我们考虑确认预期的异常。在前一个食谱中，我们需要确认在访问购物车范围之外的项目时是否引发了`IndexError`。简单的 Python `assert`不起作用，所以我们编写了这个模式：

```py
try:
  world.cart.price(-2)
  raise AssertionError("Expected an IndexError") 
except IndexError, e:
   pass
```

这很笨拙且丑陋。现在，想象一个更复杂、更现实的系统，以及在许多测试情况下使用这种模式来验证是否引发了适当的异常。这可能很快变成一项昂贵的编码任务。

值得庆幸的是，Should DSL 将这种异常断言模式转变为一行代码：

```py
(world.cart.price, -2) |should| throw(IndexError)
```

这是清晰而简洁的。我们可以立即理解，使用这些参数调用此方法应该引发某个异常。如果没有引发异常，或者引发了不同的异常，它将失败并给我们清晰的反馈。

如果你注意到，Should DSL 要求将方法调用拆分为一个元组，其中元组的第一个元素是方法句柄，其余是方法的参数。

# 还有更多...

在本章中列出的示例代码中，我们使用了`|should|`。但是 Should DSL 也带有`|should_not|`。有时，我们想要表达的条件最好用`|should_not|`来捕捉。结合之前列出的所有匹配器，我们有大量的机会来测试事物，无论是积极的还是消极的。

但是，不要忘记，如果阅读起来更容易，我们仍然可以使用 Python 的普通`assert`。关键是有很多表达相同行为验证的方式。

# 另请参阅

+   *使用 Lettuce 编写可测试的故事。*

# 更新项目级别的脚本以运行本章的 BDD 测试

在本章中，我们已经开发了几种策略来编写和练习 BDD 测试。这应该有助于我们开发新项目。对于任何项目来说，一个无价的工具是拥有一个顶级脚本，用于管理打包、捆绑和测试等事物。

本配方显示了如何创建一个命令行项目脚本，该脚本将使用各种运行程序运行本章中创建的所有测试。

# 准备工作

对于这个配方，我们需要编写本章中的所有配方。

# 如何做...

使用以下步骤，我们将创建一个项目级别的脚本，该脚本将运行本章中的所有测试配方：

1.  创建一个名为`recipe34.py`的新文件。

1.  添加使用`getopt`库来解析命令行参数的代码，如下所示：

```py
import getopt
import logging 
import nose 
import os 
import os.path 
import re 
import sys 
import lettuce 
import doctest
from glob import glob
def usage(): 
    print()
    print("Usage: python recipe34.py [command]" 
    print()
    print "\t--help" 
    print "\t--test" 
    print "\t--package" 
    print "\t--publish" 
    print "\t--register" 
    print()
    try:
      optlist, args = getopt.getopt(sys.argv[1:], 
               "h",
              ["help", "test", "package", "publish", "register"]) 
   except getopt.GetoptError:
       # print help information and exit:
       print "Invalid command found in %s" % sys.argv 
       usage()
       sys.exit(2)
```

1.  添加一个使用我们自定义的`nose`插件`BddPrinter`的测试函数，如下所示：

```py
def test_with_bdd():
    from recipe26_plugin import BddPrinter
    suite = ["recipe26", "recipe30", "recipe31"] 
    print("Running suite %s" % suite)
    args = [""] 
    args.extend(suite) 
    args.extend(["--with-bdd"])
    nose.run(argv=args, plugins=[BddPrinter()])
```

1.  添加一个测试函数，执行基于文件的`doctest`：

```py
def test_plain_old_doctest():
   for extension in ["doctest", "txt"]:
       for doc in glob("recipe27*.%s" % extension): 
           print("Testing %s" % doc) 
           doctest.testfile(doc)
```

1.  添加一个测试函数，使用自定义的`doctest`运行器执行多个`doctest`：

```py
def test_customized_doctests():
    def test_customized_doctests():
    from recipe28 import BddDocTestRunner
    old_doctest_runner = doctest.DocTestRunner 
    doctest.DocTestRunner = BddDocTestRunner
    for recipe in ["recipe28", "recipe29"]:
        for file in glob("%s*.doctest" % recipe): 
            given = file[len("%s_" % recipe):] 
            given = given[:-len(".doctest")] 
            given = " ".join(given.split("_"))
            print("===================================") 
            print("%s: Given a %s..." % (recipe, given)) 
            print( "===================================") 
            doctest.testfile(file)
            print()
    doctest.DocTestRunner = old_doctest_runner
```

1.  添加一个测试函数，执行 Lettuce 测试：

```py
def test_lettuce_scenarios():
    print("Running suite recipe32")
    lettuce.Runner(os.path.abspath("recipe32"), verbosity=3).run()
    print()
    print("Running suite recipe33") 
    lettuce.Runner(os.path.abspath("recipe33"), verbosity=3).run() 
    print()
```

1.  添加一个顶层测试函数，运行所有的测试函数，并可以连接到命令行选项：

```py
def test():
    def test(): 
        test_with_bdd()
        test_plain_old_doctest() 
        test_customized_doctests() 
        test_lettuce_scenarios()
```

1.  添加一些额外的存根函数，代表打包、发布和注册选项：

```py
def package():
    print "This is where we can plug in code to run " + \ 
          "setup.py to generate a bundle."
def publish():
    print "This is where we can plug in code to upload " + \ 
          "our tarball to S3 or some other download site."
def register():
    print "setup.py has a built in function to " + \ 
          "'register' a release to PyPI. It's " + \ 
          "convenient to put a hook in here."
    # os.system("%s setup.py register" % sys.executable)
```

1.  添加代码来解析命令行选项：

```py
if len(optlist) == 0:
   usage()
   sys.exit(1)
# Check for help requests, which cause all other
# options to be ignored.
for option in optlist:
   if option[0] in ("--help", "-h"):
      usage()
      sys.exit(1)
# Parse the arguments, in order
for option in optlist:
   if option[0] in ("--test"):
      test()
   if option[0] in ("--package"):
      package()
   if option[0] in ("--publish"):
      publish()
   if option[0] in ("--register"):
      registe
```

1.  不带任何选项运行脚本：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-test-cb-2e/img/00075.jpeg)

1.  使用`–test`运行脚本：

```py
(ptc)gturnquist-mbp:04 gturnquist$ python recipe34.py --test Running suite ['recipe26', 'recipe30', 'recipe31']
...
  Scenario: Cart getting loaded with different items        #
recipe33/recipe33.feature:22
     Given an empty cart                                    #
recipe33/steps.py:6
     When I add a carton of milk                            #
recipe33/steps.py:50
     And I add a frozen pizza                               #
recipe33/steps.py:54
     Then the first item is a carton of milk                #
recipe33/steps.py:34
     And the second item is a frozen pizza                  #
recipe33/steps.py:58
     And the first price is 2.50                            #
recipe32/steps.py:69
     And the second price is 3.00                           #
recipe33/steps.py:66
     And the total cost with no taxes is 5.50               #
recipe33/steps.py:70
     And the total cost with 10% taxes is 6.05              #
recipe33/steps.py:74
1 feature (1 passed)
3 scenarios (3 passed)
21 steps (21 passed) 
```

1.  使用`--package --publish --register`运行脚本。看一下这个截图：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/py-test-cb-2e/img/00076.jpeg)

# 它是如何工作的...

此脚本使用 Python 的`getopt`库。

# 另请参阅

有关如何以及为什么使用`getopt`，编写项目级别脚本的原因，以及为什么我们使用`getopt`而不是`optparse`的更多细节。
