# Python 代码整洁之道（三）

> 原文：[`zh.annas-archive.org/md5/164695888A8A98C80BA0F014DEE631C7`](https://zh.annas-archive.org/md5/164695888A8A98C80BA0F014DEE631C7)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：使用生成器

生成器是 Python 作为一种特殊语言的另一个特性。在本章中，我们将探讨它们的基本原理，它们为什么被引入到语言中以及它们解决的问题。我们还将介绍如何通过使用生成器来惯用地解决问题，以及如何使我们的生成器（或任何可迭代对象）符合 Python 的风格。

我们将了解为什么迭代（以迭代器模式的形式）在语言中得到了自动支持。从那里，我们将再次探索生成器如何成为 Python 的一个基本特性，以支持其他功能，如协程和异步编程。

本章的目标如下：

+   创建提高程序性能的生成器

+   研究迭代器（特别是迭代器模式）如何深度嵌入 Python

+   解决涉及迭代的问题

+   了解生成器作为协程和异步编程的基础是如何工作的

+   探索协程的语法支持——`yield from`、`await`和`async def`

# 技术要求

本章中的示例将适用于任何平台上的 Python 3.6 的任何版本。

本章中使用的代码可以在[`github.com/PacktPublishing/Clean-Code-in-Python`](https://github.com/PacktPublishing/Clean-Code-in-Python)找到

说明可在`README`文件中找到。

# 创建生成器

生成器在很久以前就被引入 Python 中（PEP-255），其目的是在 Python 中引入迭代的同时提高程序的性能（通过使用更少的内存）。

生成器的想法是创建一个可迭代的对象，当被迭代时，它将逐个产生它包含的元素。生成器的主要用途是节省内存——而不是在内存中拥有一个非常大的元素列表，一次性保存所有元素，我们有一个知道如何逐个产生每个特定元素的对象，只要它们被需要。

这个特性使得惰性计算或内存中的重量级对象成为可能，类似于其他函数式编程语言（例如 Haskell）提供的方式。甚至可以处理无限序列，因为生成器的惰性特性允许这样的选项。

# 首先看一下生成器

让我们从一个例子开始。现在手头的问题是，我们想处理一个大量的记录列表，并对它们进行一些指标和度量。给定一个包含有关购买信息的大型数据集，我们希望处理它以获得最低销售额、最高销售额和销售额的平均价格。

为了简化这个例子，我们将假设一个只有两个字段的 CSV，格式如下：

```py
<purchase_date>, <price>
...
```

我们将创建一个接收所有购买的对象，并且这将为我们提供必要的指标。我们可以通过简单地使用`min()`和`max()`内置函数来获得其中一些值，但这将需要多次迭代所有的购买，因此我们使用我们的自定义对象，它将在单次迭代中获取这些值。

将为我们获取数字的代码看起来相当简单。它只是一个具有一种方法的对象，该方法将一次性处理所有价格，并且在每一步中，将更新我们感兴趣的每个特定指标的值。首先，我们将在以下清单中显示第一个实现，然后在本章的后面（一旦我们更多地了解迭代），我们将重新访问这个实现，并获得一个更好（更紧凑）的版本。现在，我们暂时采用以下方式：

```py
class PurchasesStats:

    def __init__(self, purchases):
        self.purchases = iter(purchases)
        self.min_price: float = None
        self.max_price: float = None
        self._total_purchases_price: float = 0.0
        self._total_purchases = 0
        self._initialize()

    def _initialize(self):
        try:
            first_value = next(self.purchases)
        except StopIteration:
            raise ValueError("no values provided")

        self.min_price = self.max_price = first_value
        self._update_avg(first_value)

    def process(self):
        for purchase_value in self.purchases:
            self._update_min(purchase_value)
            self._update_max(purchase_value)
            self._update_avg(purchase_value)
        return self

    def _update_min(self, new_value: float):
        if new_value < self.min_price:
            self.min_price = new_value

    def _update_max(self, new_value: float):
        if new_value > self.max_price:
            self.max_price = new_value

    @property
    def avg_price(self):
        return self._total_purchases_price / self._total_purchases

    def _update_avg(self, new_value: float):
        self._total_purchases_price += new_value
        self._total_purchases += 1

    def __str__(self):
        return (
            f"{self.__class__.__name__}({self.min_price}, "
            f"{self.max_price}, {self.avg_price})"
        )
```

这个对象将接收`purchases`的所有总数并处理所需的值。现在，我们需要一个函数，将这些数字加载到这个对象可以处理的东西中。以下是第一个版本：

```py
def _load_purchases(filename):
    purchases = []
    with open(filename) as f:
        for line in f:
            *_, price_raw = line.partition(",")
            purchases.append(float(price_raw))

    return purchases
```

这段代码可以工作；它将文件中的所有数字加载到一个列表中，当传递给我们的自定义对象时，将产生我们想要的数字。但它有一个性能问题。如果你用一个相当大的数据集运行它，它将需要一段时间才能完成，如果数据集足够大以至于无法放入主内存中，甚至可能会失败。

如果我们看一下消耗这些数据的代码，它是逐个处理`purchases`的，所以我们可能会想知道为什么我们的生产者一次性将所有内容都放入内存。它创建了一个列表，将文件的所有内容都放入其中，但我们知道我们可以做得更好。

解决方案是创建一个生成器。我们不再将文件的整个内容加载到列表中，而是逐个产生结果。现在的代码看起来是这样的：

```py
def load_purchases(filename):
    with open(filename) as f:
        for line in f:
            *_, price_raw = line.partition(",")
            yield float(price_raw)
```

如果你这次测量这个过程，你会注意到内存的使用显著减少了。我们还可以看到代码看起来更简单——不需要定义列表（因此也不需要向其添加元素），`return`语句也消失了。

在这种情况下，`load_purchases`函数是一个生成器函数，或者简单地说是一个生成器。

在 Python 中，任何函数中存在`yield`关键字都会使其成为一个生成器，因此，当调用它时，除了创建一个生成器实例之外，什么都不会发生：

```py
>>> load_purchases("file")
<generator object load_purchases at 0x...>
```

生成器对象是可迭代的（我们稍后会更详细地讨论可迭代对象），这意味着它可以与`for`循环一起工作。请注意，我们在消费者代码上没有改变任何东西——我们的统计处理器保持不变，在新实现后`for`循环也没有修改。

使用可迭代对象使我们能够创建这些强大的抽象，这些抽象对`for`循环是多态的。只要我们保持可迭代接口，我们就可以透明地迭代该对象。

# 生成器表达式

生成器节省了大量内存，而且由于它们是迭代器，它们是其他需要更多内存空间的可迭代对象或容器的方便替代品，比如列表、元组或集合。

就像这些数据结构一样，它们也可以通过推导来定义，只是它被称为生成器表达式（关于它们是否应该被称为生成器推导有一个持续的争论。在本书中，我们将只用它们的规范名称来提及它们，但请随意使用你更喜欢的名称）。

同样，我们可以定义一个列表推导。如果我们用括号替换方括号，我们就得到了一个生成器，它是表达式的结果。生成器表达式也可以直接传递给那些与可迭代对象一起工作的函数，比如`sum()`和`max()`：

```py
>>> [x**2 for x in range(10)]
[0, 1, 4, 9, 16, 25, 36, 49, 64, 81]

>>> (x**2 for x in range(10))
<generator object <genexpr> at 0x...>

>>> sum(x**2 for x in range(10))
285
```

总是传递一个生成器表达式，而不是列表推导，给那些期望可迭代对象的函数，比如`min()`、`max()`和`sum()`。这样更有效率和符合 Python 的风格。

# 迭代习语

在本节中，我们将首先探讨一些在 Python 中处理迭代时非常有用的习语。这些代码示例将帮助我们更好地了解我们可以用生成器做什么类型的事情（特别是在我们已经看过生成器表达式之后），以及如何解决与它们相关的典型问题。

一旦我们看过一些习语，我们将继续更深入地探讨 Python 中的迭代，分析使迭代成为可能的方法，以及可迭代对象的工作原理。

# 迭代的习语

我们已经熟悉了内置的`enumerate()`函数，它给定一个可迭代对象，将返回另一个可迭代对象，其中元素是一个元组，其第一个元素是第二个元素的枚举（对应于原始可迭代对象中的元素）：

```py
>>> list(enumerate("abcdef"))
[(0, 'a'), (1, 'b'), (2, 'c'), (3, 'd'), (4, 'e'), (5, 'f')]
```

我们希望创建一个类似的对象，但以更低级的方式；一个可以简单地创建一个无限序列的对象。我们想要一个对象，可以从一个起始数字开始产生一个数字序列，没有任何限制。

一个简单的对象就可以解决问题。每次调用这个对象，我们都会得到序列的下一个数字*无穷*：

```py
class NumberSequence:

    def __init__(self, start=0):
        self.current = start

    def next(self):
        current = self.current
        self.current += 1
        return current
```

基于这个接口，我们必须通过显式调用它的`next()`方法来使用这个对象：

```py
>>> seq = NumberSequence()
>>> seq.next()
0
>>> seq.next()
1

>>> seq2 = NumberSequence(10)
>>> seq2.next()
10
>>> seq2.next()
11
```

但是，使用这段代码，我们无法像我们想要的那样重建`enumerate()`函数，因为它的接口不支持在常规的 Python `for`循环中进行迭代，这也意味着我们无法将其作为参数传递给期望迭代的函数。请注意以下代码的失败：

```py
>>> list(zip(NumberSequence(), "abcdef"))
Traceback (most recent call last):
 File "...", line 1, in <module>
TypeError: zip argument #1 must support iteration
```

问题在于`NumberSequence`不支持迭代。为了解决这个问题，我们必须通过实现魔术方法`__iter__()`使对象成为可迭代的。我们还改变了之前的`next()`方法，使用了魔术方法`__next__`，这使得对象成为了迭代器：

```py
class SequenceOfNumbers:

    def __init__(self, start=0):
        self.current = start

    def __next__(self):
        current = self.current
        self.current += 1
        return current

    def __iter__(self):
        return self
```

这有一个优点——不仅可以迭代元素，而且我们甚至不再需要`.next()`方法，因为有了`__next__()`，我们可以使用`next()`内置函数：

```py
>>> list(zip(SequenceOfNumbers(), "abcdef"))
[(0, 'a'), (1, 'b'), (2, 'c'), (3, 'd'), (4, 'e'), (5, 'f')]
>>> seq = SequenceOfNumbers(100)
>>> next(seq)
100
>>> next(seq)
101
```

# next()函数

`next()`内置函数将使可迭代对象前进到它的下一个元素并返回它：

```py
>>> word = iter("hello")
>>> next(word)
'h'
>>> next(word)
'e'  # ...
```

如果迭代器没有更多的元素产生，就会引发`StopIteration`异常：

```py
>>> ...
>>> next(word)
'o'
>>> next(word)
Traceback (most recent call last):
 File "<stdin>", line 1, in <module>
StopIteration
>>>
```

这个异常表示迭代已经结束，没有更多的元素可以消耗了。

如果我们希望处理这种情况，除了捕获`StopIteration`异常，我们可以在第二个参数中为这个函数提供一个默认值。如果提供了这个值，它将成为`StopIteration`抛出时的返回值：

```py
>>> next(word, "default value")
'default value'
```

# 使用生成器

通过简单地使用生成器，可以显著简化上述代码。生成器对象是迭代器。这样，我们可以定义一个函数，根据需要`yield`值，而不是创建一个类：

```py
def sequence(start=0):
    while True:
        yield start
        start += 1
```

记住，根据我们的第一个定义，函数体中的`yield`关键字使其成为一个生成器。因为它是一个生成器，所以像这样创建一个无限循环是完全可以的，因为当调用这个生成器函数时，它将运行到下一个`yield`语句被执行之前的所有代码。它将产生它的值并在那里暂停：

```py
>>> seq = sequence(10)
>>> next(seq)
10
>>> next(seq)
11

>>> list(zip(sequence(), "abcdef"))
[(0, 'a'), (1, 'b'), (2, 'c'), (3, 'd'), (4, 'e'), (5, 'f')]
```

# Itertools

使用可迭代对象的好处在于，代码与 Python 本身更好地融合在一起，因为迭代是语言的一个关键组成部分。除此之外，我们还可以充分利用`itertools`模块（ITER-01）。实际上，我们刚刚创建的`sequence()`生成器与`itertools.count()`非常相似。但是，我们还可以做更多的事情。

迭代器、生成器和 itertools 最好的一点是它们是可组合的对象，可以链接在一起。

例如，回到我们的第一个例子，处理`purchases`以获得一些指标，如果我们想做同样的事情，但只针对某个阈值以上的值怎么办？解决这个问题的天真方法是在迭代时放置条件：

```py
# ...
    def process(self):
        for purchase in self.purchases:
            if purchase > 1000.0:
                ...
```

这不仅不符合 Python 的风格，而且也很死板（死板是一个表明糟糕代码的特征）。它不能很好地处理变化。如果数字现在改变了怎么办？我们通过参数传递吗？如果我们需要多个怎么办？如果条件不同（比如小于），我们传递一个 lambda 吗？

这些问题不应该由这个对象来回答，它的唯一责任是计算一组以数字表示的购买流的明确定义的指标。当然，答案是否定的。将这样的改变是一个巨大的错误（再次强调，清晰的代码是灵活的，我们不希望通过将这个对象与外部因素耦合来使其变得死板）。这些要求必须在其他地方解决。

最好让这个对象独立于它的客户端。这个类的责任越少，对更多客户端来说就越有用，从而增加它被重用的机会。

我们不会改变这段代码，而是保持原样，并假设新数据根据该类的每个客户的要求进行了过滤。

例如，如果我们只想处理前 10 个购买金额超过 1,000 的购买，我们将执行以下操作：

```py
>>> from itertools import islice
>>> purchases = islice(filter(lambda p: p > 1000.0, purchases), 10)
>>> stats = PurchasesStats(purchases).process()  # ...
```

这种过滤方式不会对内存造成惩罚，因为它们都是生成器，评估总是延迟的。这使我们有能力像一次性过滤整个集合然后将其传递给对象一样思考，但实际上并没有将所有内容都适应到内存中。

# 通过迭代器简化代码

现在，我们将简要讨论一些可以通过迭代器和偶尔的`itertools`模块帮助改进的情况。在讨论每种情况及其提出的优化后，我们将用一个推论来结束每个观点。

# 重复迭代

现在我们已经更多地了解了迭代器，并介绍了`itertools`模块，我们可以向您展示本章的第一个示例（用于计算有关某些购买的统计信息）如何被大大简化：

```py
def process_purchases(purchases):
    min_, max_, avg = itertools.tee(purchases, 3)
    return min(min_), max(max_), median(avg)
```

在这个例子中，`itertools.tee`将原始可迭代对象分成三个新的可迭代对象。我们将使用每个对象进行不同类型的迭代，而无需重复三个不同的循环。

读者可以简单地验证，如果我们将可迭代对象作为`purchases`参数传递，这个对象只被遍历一次（感谢`itertools.tee`函数[参见参考资料]），这是我们的主要要求。还可以验证这个版本如何等价于我们的原始实现。在这种情况下，不需要手动引发`ValueError`，因为将空序列传递给`min()`函数将产生相同的效果。

如果您正在考虑在同一个对象上多次运行循环，请停下来思考一下`itertools.tee`是否有所帮助。

# 嵌套循环

在某些情况下，我们需要在多个维度上进行迭代，寻找一个值，嵌套循环是第一个想法。当找到值时，我们需要停止迭代，但`break`关键字并不完全起作用，因为我们需要从两个（或更多）`for`循环中逃离，而不仅仅是一个。

这个问题的解决方案是什么？一个信号逃脱的标志？不是。引发异常？不，这与标志相同，但更糟，因为我们知道异常不应该用于控制流逻辑。将代码移到一个更小的函数并返回它？接近，但不完全。

答案是，尽可能将迭代简化为单个`for`循环。

这是我们想要避免的代码类型：

```py
def search_nested_bad(array, desired_value):
    coords = None
    for i, row in enumerate(array):
        for j, cell in enumerate(row):
            if cell == desired_value:
                coords = (i, j)
                break

        if coords is not None:
            break

    if coords is None:
        raise ValueError(f"{desired_value} not found")

    logger.info("value %r found at [%i, %i]", desired_value, *coords)
    return coords
```

以下是一个简化版本，它不依赖于标志来表示终止，并且具有更简单、更紧凑的迭代结构：

```py
def _iterate_array2d(array2d):
    for i, row in enumerate(array2d):
        for j, cell in enumerate(row):
            yield (i, j), cell

def search_nested(array, desired_value):
    try:
        coord = next(
            coord
            for (coord, cell) in _iterate_array2d(array)
            if cell == desired_value
        )
    except StopIteration:
        raise ValueError("{desired_value} not found")

    logger.info("value %r found at [%i, %i]", desired_value, *coord)
    return coord
```

值得一提的是，创建的辅助生成器如何作为所需迭代的抽象。在这种情况下，我们只需要在两个维度上进行迭代，但如果我们需要更多，不同的对象可以处理这一点，而客户端无需知道。这就是迭代器设计模式的本质，在 Python 中是透明的，因为它自动支持迭代器对象，这是下一节讨论的主题。

尽量简化迭代，使用尽可能多的抽象，尽可能将循环展平。

# Python 中的迭代器模式

在这里，我们将从生成器中稍微偏离，更深入地了解 Python 中的迭代。生成器是可迭代对象的特殊情况，但 Python 中的迭代超越了生成器，能够创建良好的可迭代对象将使我们有机会创建更高效、更紧凑和更可读的代码。

在前面的代码清单中，我们一直在看一些可迭代对象的示例，这些对象也是迭代器，因为它们实现了`__iter__()`和`__next__()`魔术方法。虽然这在一般情况下是可以的，但并不严格要求它们总是必须实现这两个方法，这里我们将展示可迭代对象（实现`__iter__`）和迭代器（实现`__next__`）之间的细微差别。

我们还探讨了与迭代相关的其他主题，如序列和容器对象。

# 迭代的接口

可迭代对象是支持迭代的对象，从非常高的层次来看，这意味着我们可以在其上运行`for .. in ...`循环，并且不会出现任何问题。然而，可迭代并不意味着与迭代器相同。

一般来说，可迭代只是我们可以迭代的东西，并且它使用迭代器来实现。这意味着在`__iter__`魔术方法中，我们希望返回一个迭代器，即一个实现了`__next__()`方法的对象。

迭代器是一个只知道如何产生一系列值的对象，每次被已探索的内置`next()`函数调用时，它都会一次产生一个值。当迭代器没有被调用时，它只是被冻结，静静地坐着，直到再次为下一个值调用它。在这个意义上，生成器是迭代器。

| **Python 概念** | **魔术方法** | **注意事项** |
| --- | --- | --- |
| 可迭代对象 | `__iter__` | 它们与迭代器一起工作，构建迭代逻辑。这些对象可以在`for ... in ...:`循环中迭代 |
| 迭代器 | `__next__` | 定义逐个产生值的逻辑。`StopIteration`异常表示迭代结束。可以通过内置的`next()`函数逐个获取值。 |

在下面的代码中，我们将看到一个迭代器对象的示例，它不是可迭代的——它只支持一次调用其值。在这里，名称`sequence`只是指一系列连续的数字，并不是 Python 中的序列概念，我们稍后会探讨：

```py
class SequenceIterator:
    def __init__(self, start=0, step=1):
        self.current = start
        self.step = step

    def __next__(self):
        value = self.current
        self.current += self.step
        return value
```

请注意，我们可以逐个获取序列的值，但我们无法迭代这个对象（这是幸运的，否则将导致无限循环）：

```py
>>> si = SequenceIterator(1, 2)
>>> next(si)
1
>>> next(si)
3
>>> next(si)
5
>>> for _ in SequenceIterator(): pass
... 
Traceback (most recent call last):
 ...
TypeError: 'SequenceIterator' object is not iterable
```

错误消息很清楚，因为对象没有实现`__iter__()`。

仅仅为了说明的目的，我们可以将迭代分离到另一个对象中（同样，只需使对象分别实现`__iter__`和`__next__`即可，但这样做可以帮助澄清我们在这个解释中试图阐明的不同点）。

# 序列对象作为可迭代对象

正如我们刚刚看到的，如果一个对象实现了`__iter__()`魔术方法，这意味着它可以在`for`循环中使用。虽然这是一个很好的特性，但我们可以实现的迭代形式并不仅限于此。当我们编写`for`循环时，Python 会尝试查看我们使用的对象是否实现了`__iter__`，如果实现了，它将使用它来构建迭代，但如果没有，还有备用选项。

如果对象恰好是一个序列（意味着它实现了`__getitem__()`和`__len__()`魔术方法），它也可以被迭代。如果是这种情况，解释器将按顺序提供值，直到引发`IndexError`异常，这与前面提到的`StopIteration`类似，也表示迭代的结束。

为了说明这种行为，我们运行以下实验，展示了一个实现`map()`在一系列数字上的序列对象：

```py
# generators_iteration_2.py

class MappedRange:
    """Apply a transformation to a range of numbers."""

    def __init__(self, transformation, start, end):
        self._transformation = transformation
        self._wrapped = range(start, end)

    def __getitem__(self, index):
        value = self._wrapped.__getitem__(index)
        result = self._transformation(value)
        logger.info("Index %d: %s", index, result)
        return result

    def __len__(self):
        return len(self._wrapped)
```

请记住，这个示例只是为了说明这样一个对象可以用常规的`for`循环进行迭代。在`__getitem__`方法中放置了一个日志行，以探索在迭代对象时传递了哪些值，正如我们从以下测试中所看到的：

```py
>>> mr = MappedRange(abs, -10, 5)
>>> mr[0]
Index 0: 10
10
>>> mr[-1]
Index -1: 4
4
>>> list(mr)
Index 0: 10
Index 1: 9
Index 2: 8
Index 3: 7
Index 4: 6
Index 5: 5
Index 6: 4
Index 7: 3
Index 8: 2
Index 9: 1
Index 10: 0
Index 11: 1
Index 12: 2
Index 13: 3
Index 14: 4
[10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 1, 2, 3, 4]
```

需要注意的是，重要的是要强调，虽然了解这一点很有用，但它也是对象不实现`__iter__`时的后备机制，因此大多数时候我们会希望通过考虑创建适当的序列来使用这些方法，而不仅仅是我们想要迭代的对象。

在设计用于迭代的对象时，更倾向于一个适当的可迭代对象（带有`__iter__`），而不是一个偶然也可以被迭代的序列。

# 协程

正如我们已经知道的，生成器对象是可迭代的。它们实现了`__iter__()`和`__next__()`。这是由 Python 自动提供的，因此当我们创建一个生成器对象函数时，我们会得到一个可以通过`next()`函数进行迭代或推进的对象。

除了这个基本功能，它们还有更多的方法，以便它们可以作为协程（PEP-342）工作。在这里，我们将探讨生成器如何演变成协程，以支持异步编程的基础，然后在下一节中更详细地探讨 Python 的新特性和涵盖异步编程的语法。用于支持协程的(PEP-342)中添加的基本方法如下：

+   `.close()`

+   `.throw(ex_type[, ex_value[, ex_traceback]])`

+   `.send(value)`

# 生成器接口的方法

在本节中，我们将探讨上述每个方法的作用，工作原理以及预期的使用方式。通过理解如何使用这些方法，我们将能够使用简单的协程。

稍后，我们将探讨协程的更高级用法，以及如何委托给子生成器（协程）以重构代码，以及如何编排不同的协程。

# close()

调用这个方法时，生成器将接收`GeneratorExit`异常。如果没有处理，那么生成器将在不产生更多值的情况下结束，并且它的迭代将停止。

这个异常可以用来处理完成状态。一般来说，如果我们的协程进行某种资源管理，我们希望捕获这个异常并使用该控制块来释放协程持有的所有资源。一般来说，这类似于使用上下文管理器或将代码放在异常控制的`finally`块中，但专门处理这个异常使得它更加明确。

在下面的例子中，我们有一个协程，它利用一个持有数据库连接的数据库处理程序对象，并在其上运行查询，通过固定长度的页面流式传输数据（而不是一次性读取所有可用的数据）：

```py
def stream_db_records(db_handler):
    try:
        while True:
            yield db_handler.read_n_records(10)
    except GeneratorExit:
        db_handler.close()
```

在每次调用生成器时，它将返回从数据库处理程序获取的`10`行，但当我们决定明确完成迭代并调用`close()`时，我们还希望关闭与数据库的连接：

```py
>>> streamer = stream_db_records(DBHandler("testdb"))
>>> next(streamer)
[(0, 'row 0'), (1, 'row 1'), (2, 'row 2'), (3, 'row 3'), ...]
>>> next(streamer)
[(0, 'row 0'), (1, 'row 1'), (2, 'row 2'), (3, 'row 3'), ...]
>>> streamer.close()
INFO:...:closing connection to database 'testdb'
```

使用`close()`方法关闭生成器以在需要时执行收尾任务。

# throw(ex_type[, ex_value[, ex_traceback]])

这个方法将在生成器当前暂停的地方`throw`异常。如果生成器处理了发送的异常，那么特定的`except`子句中的代码将被调用，否则，异常将传播到调用者。

在这里，我们稍微修改了之前的例子，以展示当我们使用这个方法处理协程处理的异常和未处理的异常时的区别：

```py
class CustomException(Exception):
    pass

def stream_data(db_handler):
    while True:
        try:
            yield db_handler.read_n_records(10)
        except CustomException as e:
            logger.info("controlled error %r, continuing", e)
        except Exception as e:
            logger.info("unhandled error %r, stopping", e)
            db_handler.close()
            break
```

现在，接收`CustomException`已经成为控制流的一部分，如果出现这种情况，生成器将记录一条信息性消息（当然，我们可以根据每种情况的业务逻辑进行调整），然后继续执行下一个`yield`语句，这是协程从数据库读取并返回数据的地方。

这个特定的例子处理了所有异常，但如果最后一个块（`except Exception:`）不在那里，结果将是生成器在生成器暂停的地方被引发（再次是`yield`*），然后从那里传播到调用者：

```py
>>> streamer = stream_data(DBHandler("testdb"))
>>> next(streamer)
[(0, 'row 0'), (1, 'row 1'), (2, 'row 2'), (3, 'row 3'), (4, 'row 4'), ...]
>>> next(streamer)
[(0, 'row 0'), (1, 'row 1'), (2, 'row 2'), (3, 'row 3'), (4, 'row 4'), ...]
>>> streamer.throw(CustomException)
WARNING:controlled error CustomException(), continuing
[(0, 'row 0'), (1, 'row 1'), (2, 'row 2'), (3, 'row 3'), (4, 'row 4'), ...]
>>> streamer.throw(RuntimeError)
ERROR:unhandled error RuntimeError(), stopping
INFO:closing connection to database 'testdb'
Traceback (most recent call last):
 ...
StopIteration
```

当我们收到来自领域的异常时，生成器继续。然而，当它收到另一个意外的异常时，捕获了默认块，我们关闭了与数据库的连接并完成了迭代，这导致生成器停止。正如我们从引发的`StopIteration`中看到的，这个生成器不能进一步迭代。

# send(value)

在前面的例子中，我们创建了一个简单的生成器，从数据库中读取行，当我们希望完成它的迭代时，这个生成器释放了与数据库相关的资源。这是使用生成器提供的方法之一（close）的一个很好的例子，但我们还可以做更多的事情。

这样的生成器很明显是从数据库中读取了固定数量的行。

我们希望参数化那个数字（`10`），以便我们可以在不同的调用中更改它。不幸的是，`next()`函数不为我们提供这样的选项。但幸运的是，我们有`send()`：

```py
def stream_db_records(db_handler):
    retrieved_data = None
    previous_page_size = 10
    try:
        while True:
            page_size = yield retrieved_data
            if page_size is None:
                page_size = previous_page_size

            previous_page_size = page_size

            retrieved_data = db_handler.read_n_records(page_size)
    except GeneratorExit:
        db_handler.close()
```

我们现在的想法是，我们现在已经使协程能够通过`send()`方法从调用者那里接收值。这个方法实际上是区分生成器和协程的方法，因为当它被使用时，意味着`yield`关键字将出现在语句的右侧，并且它的返回值将被分配给其他东西。

在协程中，我们通常发现`yield`关键字以以下形式使用：

```py
receive = yield produced
```

在这种情况下，`yield`将做两件事。它将`produced`发送回调用者，调用者将在下一轮迭代（例如在调用`next()`之后）中接收到它，并在那里暂停。稍后，调用者将想要通过使用`send()`方法向协程发送一个值。这个值将成为`yield`语句的结果，在这种情况下赋给名为`receive`的变量。

只有当协程在`yield`语句处暂停等待某些东西产生时，向协程发送值才有效。为了实现这一点，协程必须被推进到这种状态。唯一的方法是通过调用`next()`来做到这一点。这意味着在向协程发送任何东西之前，必须通过`next()`方法至少推进一次。如果不这样做，将导致异常：

```py
>>> c = coro()
>>> c.send(1)
Traceback (most recent call last):
 ...
TypeError: can't send non-None value to a just-started generator
```

在向协程发送任何值之前，请记住通过调用`next()`来推进协程。

回到我们的例子。我们正在改变元素被生成或流式传输的方式，使其能够接收它期望从数据库中读取的记录的长度。

第一次调用`next()`时，生成器将前进到包含`yield`的行；它将向调用者提供一个值（如变量中设置的`None`），并在那里暂停。从这里，我们有两个选择。如果我们选择通过调用`next()`来推进生成器，将使用`10`的默认值，并且它将像往常一样继续进行。这是因为`next()`在技术上与`send(None)`相同，但这是在我们之前设置的值的`if`语句中处理的。

另一方面，如果我们决定通过`send(<value>)`提供一个显式值，这个值将成为`yield`语句的结果，这将被赋给包含要使用的页面长度的变量，而这个变量将被用来从数据库中读取。

后续的调用将具有这种逻辑，但重要的是现在我们可以在迭代中间动态改变要读取的数据的长度。

现在我们了解了之前的代码是如何工作的，大多数 Pythonistas 都希望有一个简化版本（毕竟，Python 也是关于简洁和干净紧凑的代码）：

```py
def stream_db_records(db_handler):
    retrieved_data = None
    page_size = 10
    try:
        while True:
            page_size = (yield retrieved_data) or page_size
            retrieved_data = db_handler.read_n_records(page_size)
    except GeneratorExit:
        db_handler.close()
```

这个版本不仅更紧凑，而且更好地说明了这个想法。`yield`周围的括号使它更清晰，表明它是一个语句（把它想象成一个函数调用），我们正在使用它的结果与先前的值进行比较。

这符合我们的预期，但我们总是要记住在向其发送任何数据之前先推进协程。如果我们忘记调用第一个`next()`，我们将得到一个`TypeError`。这个调用可以被忽略，因为它不会返回我们将使用的任何东西。

如果我们能够直接使用协程，在创建后不必记住每次使用它时都调用`next()`第一次，那将是很好的。一些作者（PYCOOK）设计了一个有趣的装饰器来实现这一点。这个装饰器的想法是推进协程，所以下面的定义可以自动工作：

```py
@prepare_coroutine
def stream_db_records(db_handler):
    retrieved_data = None
    page_size = 10
    try:
        while True:
            page_size = (yield retrieved_data) or page_size
            retrieved_data = db_handler.read_n_records(page_size)
    except GeneratorExit:
        db_handler.close()

>>> streamer = stream_db_records(DBHandler("testdb"))
>>> len(streamer.send(5))
5
```

让我们举个例子，我们创建了`prepare_coroutine()`装饰器。

# 更高级的协程

到目前为止，我们对协程有了更好的理解，并且能够创建简单的协程来处理小任务。我们可以说这些协程实际上只是更高级的生成器（这是正确的，协程只是花哨的生成器），但是，如果我们真的想要开始支持更复杂的场景，通常我们必须采用一种处理许多协程并发的设计，并且需要更多的功能。

处理许多协程时，我们发现了新的问题。随着应用程序的控制流变得更加复杂，我们希望能够在堆栈上传递值和异常，能够捕获我们可能在任何级别调用的子协程的值，并最终安排多个协程朝着共同的目标运行。

为了简化事情，生成器必须再次扩展。这就是 PEP-380 所解决的问题——通过改变生成器的语义，使其能够返回值，并引入新的`yield from`构造。

# 在协程中返回值

正如本章开头介绍的那样，迭代是一种机制，它在可迭代对象上多次调用`next()`，直到引发`StopIteration`异常。

到目前为止，我们一直在探索生成器的迭代性质——我们一次产生一个值，并且通常只关心`for`循环的每一步产生的每个值。这是一种非常逻辑的生成器思维方式，但是协程有一个不同的想法；尽管它们在技术上是生成器，但它们并不是以迭代为目的而构思的，而是以挂起代码的执行直到稍后恢复为目标。

这是一个有趣的挑战；当我们设计一个协程时，我们通常更关心挂起状态而不是迭代（迭代协程将是一个奇怪的情况）。挑战在于很容易混合它们两者。这是因为技术实现细节；Python 中对协程的支持是建立在生成器之上的。

如果我们想要使用协程来处理一些信息并挂起其执行，那么把它们看作轻量级线程（或者在其他平台上称为绿色线程）是有意义的。在这种情况下，如果它们能够返回值，就像调用任何其他常规函数一样，那将是有意义的。

但让我们记住生成器不是常规函数，因此在生成器中，构造`value = generator()`除了创建一个`generator`对象之外什么也不会做。那么使生成器返回一个值的语义是什么？它将必须在迭代完成后。

当生成器返回一个值时，迭代立即停止（不能再迭代）。为了保持语义，`StopIteration`异常仍然被引发，并且要返回的值存储在`exception`对象中。捕获它是调用者的责任。

在下面的例子中，我们创建了一个简单的`generator`，产生两个值，然后返回第三个值。请注意，我们必须捕获异常以获取这个`value`，以及它如何精确地存储在异常的属性`value`下：

```py
>>> def generator():
...     yield 1
...     yield 2
...     return 3
... 
>>> value = generator()
>>> next(value)
1
>>> next(value)
2
>>> try:
...     next(value)
... except StopIteration as e:
...     print(">>>>>> returned value ", e.value)
... 
>>>>>> returned value  3
```

# 委托到更小的协程 - yield from 语法

以前的特性很有趣，因为它为协程（生成器）打开了许多新的可能性，现在它们可以返回值。但是，这个特性本身如果没有适当的语法支持，就不会那么有用，因为以这种方式捕获返回值有点麻烦。

这是`yield from`语法的主要特性之一。除了其他事情（我们将详细审查），它可以收集子生成器返回的值。记住我们说过在生成器中返回数据很好，但不幸的是，编写语句`value = generator()`是行不通的吗？好吧，将其编写为`value = yield from generator()`就可以了。

# `yield from`的最简单用法

在其最基本的形式中，新的`yield from`语法可以用于将嵌套的`for`循环中的生成器链接成一个单一的生成器，最终将得到一个连续流中所有值的单个字符串。

典型的例子是创建一个类似于`standard`库中的`itertools.chain()`的函数。这是一个非常好的函数，因为它允许您传递任意数量的`iterables`，并将它们一起返回一个流。

天真的实现可能看起来像这样：

```py
def chain(*iterables):
    for it in iterables:
        for value in it:
            yield value
```

它接收可变数量的`iterables`，遍历所有这些 iterables，由于每个值都是`iterable`，它支持`for... in..`结构，因此我们有另一个`for`循环来获取每个特定 iterable 中的每个值，这是由调用函数产生的。这在多种情况下可能会有所帮助，例如将生成器链接在一起或尝试迭代通常不可能一次比较的东西（例如列表与元组等）。

然而，`yield from`语法允许我们更进一步，避免嵌套循环，因为它能够直接从子生成器产生值。在这种情况下，我们可以简化代码如下：

```py
def chain(*iterables):
    for it in iterables:
        yield from it
```

请注意，对于这两种实现，生成器的行为完全相同：

```py
>>> list(chain("hello", ["world"], ("tuple", " of ", "values.")))
['h', 'e', 'l', 'l', 'o', 'world', 'tuple', ' of ', 'values.']
```

这意味着我们可以在任何其他可迭代对象上使用`yield from`，它将起到作用，就好像顶层生成器（使用`yield from`的那个）自己生成这些值一样。

这适用于任何可迭代对象，甚至生成器表达式也不例外。现在我们熟悉了它的语法，让我们看看如何编写一个简单的生成器函数，它将产生一个数字的所有幂（例如，如果提供`all_powers(2, 3)`，它将产生`2⁰, 2¹,... 2³`）：

```py
def all_powers(n, pow):
    yield from (n ** i for i in range(pow + 1))
```

虽然这样简化了语法，节省了一个`for`语句的行数并不是一个很大的优势，这并不能证明向语言中添加这样的更改是合理的。

实际上，这实际上只是一个副作用，而`yield from`结构的真正存在意义是我们将在接下来的两个部分中探讨的。

# 捕获子生成器返回的值

在下面的例子中，我们有一个生成器调用另外两个嵌套的生成器，按顺序产生值。每一个嵌套的生成器都返回一个值，我们将看到顶层生成器如何能够有效地捕获返回值，因为它通过`yield from`调用内部生成器：

```py
def sequence(name, start, end):
    logger.info("%s started at %i", name, start)
    yield from range(start, end)
    logger.info("%s finished at %i", name, end)
    return end

def main():
    step1 = yield from sequence("first", 0, 5)
    step2 = yield from sequence("second", step1, 10)
    return step1 + step2
```

这是在主函数中迭代时代码的可能执行方式：

```py
>>> g = main()
>>> next(g)
INFO:generators_yieldfrom_2:first started at 0
0
>>> next(g)
1
>>> next(g)
2
>>> next(g)
3
>>> next(g)
4
>>> next(g)
INFO:generators_yieldfrom_2:first finished at 5
INFO:generators_yieldfrom_2:second started at 5
5
>>> next(g)
6
>>> next(g)
7
>>> next(g)
8
>>> next(g)
9
>>> next(g)
INFO:generators_yieldfrom_2:second finished at 10
Traceback (most recent call last):
 File "<stdin>", line 1, in <module>
StopIteration: 15
```

main 的第一行委托给内部生成器，并产生值，直接从中提取。这并不是什么新鲜事，因为我们已经见过了。请注意，`sequence()`生成器函数返回结束值，在第一行赋给名为`step1`的变量，这个值在下一个生成器实例的开始正确使用。

最后，这个其他生成器也返回第二个结束值（`10`），而主生成器则返回它们的和（`5+10=15`），这是我们在迭代停止后看到的值。

我们可以使用`yield from`在协程完成处理后捕获最后一个值。

# 向子生成器发送和接收数据

现在，我们将看到`yield from`语法的另一个很好的特性，这可能是它赋予它完整力量的原因。正如我们在探索生成器作为协程时已经介绍的，我们知道我们可以向它们发送值和抛出异常，在这种情况下，协程要么接收值进行内部处理，要么必须相应地处理异常。

如果现在我们有一个委托给其他协程的协程（就像在前面的例子中），我们也希望保留这个逻辑。手动这样做将会相当复杂（如果我们没有通过`yield from`自动处理的话，可以看一下 PEP-380 中描述的代码）。

为了说明这一点，让我们保持相同的顶层生成器（main）与之前的例子相同，但让我们修改内部生成器，使它们能够接收值并处理异常。这段代码可能不是惯用的，只是为了展示这个机制是如何工作的。

```py
def sequence(name, start, end):
    value = start
    logger.info("%s started at %i", name, value)
    while value < end:
        try:
            received = yield value
            logger.info("%s received %r", name, received)
            value += 1
        except CustomException as e:
            logger.info("%s is handling %s", name, e)
            received = yield "OK"
    return end
```

现在，我们将调用`main`协程，不仅通过迭代它，还通过向它传递值和抛出异常，以查看它们在`sequence`内部是如何处理的：

```py
>>> g = main()
>>> next(g)
INFO: first started at 0
0
>>> next(g)
INFO: first received None
1
>>> g.send("value for 1")
INFO: first received 'value for 1'
2
>>> g.throw(CustomException("controlled error"))
INFO: first is handling controlled error
'OK'
... # advance more times
INFO:second started at 5
5
>>> g.throw(CustomException("exception at second generator"))
INFO: second is handling exception at second generator
'OK'
```

这个例子向我们展示了很多不同的东西。请注意，我们从未向`sequence`发送值，而只是向`main`发送，即使如此，接收这些值的代码是嵌套生成器。即使我们从未明确向`sequence`发送任何东西，它也会接收数据，因为它是通过`yield from`传递的。

`main`协程在内部调用另外两个协程，产生它们的值，并且在任何一个特定时间点被挂起。当它停在第一个时，我们可以看到日志告诉我们，正是这个协程实例接收了我们发送的值。当我们向它抛出异常时也是一样的。当第一个协程完成时，它返回了在名为`step1`的变量中分配的值，并作为第二个协程的输入，第二个协程也会做同样的事情（它将相应地处理`send()`和`throw()`调用）。

对于每个协程产生的值也是如此。当我们处于任何给定步骤时，调用`send()`返回的值对应于子协程（`main`当前挂起的那个）产生的值。当我们抛出一个正在处理的异常时，`sequence`协程产生值`OK`，这个值传播到被调用的（`main`），然后最终到达 main 的调用者。

# 异步编程

通过我们迄今为止看到的构造，我们能够在 Python 中创建异步程序。这意味着我们可以创建具有许多协程的程序，安排它们按特定顺序工作，并在每个协程上调用`yield from`后挂起时在它们之间切换。

我们可以从中获得的主要优势是以非阻塞的方式并行化 I/O 操作的可能性。我们需要的是一个低级生成器（通常由第三方库实现），它知道如何在协程被挂起时处理实际的 I/O。协程的目的是实现挂起，以便我们的程序可以在此期间处理另一个任务。应用程序重新获取控制的方式是通过`yield from`语句，它将挂起并向调用者产生一个值（就像我们之前看到的例子中使用这个语法来改变程序的控制流）。

这大致是多年来 Python 中异步编程的工作方式，直到决定需要更好的语法支持。

协程和生成器在技术上是相同的，这导致了一些混淆。从语法上（和技术上）来看，它们是相同的，但从语义上来看，它们是不同的。当我们想要实现高效的迭代时，我们创建生成器。我们通常创建协程的目的是运行非阻塞 I/O 操作。

尽管这种差异是明显的，Python 的动态特性仍然允许开发人员混合这些不同类型的对象，在程序的非常后期出现运行时错误。记住，在最简单和最基本的`yield from`语法中，我们使用这个结构来迭代（我们创建了一种在字符串、列表等上应用的`chain`函数）。这些对象都不是协程，但它仍然有效。然后，我们看到我们可以有多个协程，使用`yield from`发送值（或异常），并获得一些结果。这显然是两种非常不同的用例，但是，如果我们写出类似以下语句的内容：

```py
result = yield from iterable_or_awaitable()
```

不清楚`iterable_or_awaitable`返回什么。它可以是一个简单的可迭代对象，比如字符串，这可能仍然是语法上正确的。或者，它可能是一个实际的协程。这个错误的代价将在以后付出。

因此，Python 中的输入系统必须得到扩展。在 Python 3.5 之前，协程只是应用了`@coroutine`装饰器的生成器，并且它们需要使用`yield from`语法进行调用。现在，有一种特定类型的对象，即协程。

这个改变也带来了语法的改变。引入了`await`和`async def`语法。前者旨在替代`yield from`，它只能与`awaitable`对象一起使用（方便地，协程恰好是这种对象）。尝试使用不符合`awaitable`接口的东西来调用`await`将引发异常。`async def`是定义协程的新方法，取代了前面提到的装饰器，实际上创建了一个对象，当调用时，将返回一个协程的实例。

不去深入讨论 Python 中异步编程的所有细节和可能性，我们可以说，尽管有新的语法和新的类型，但这并没有从本质上做任何不同于我们在本章中介绍的概念。

在 Python 中异步编程的思想是有一个事件循环（通常是`asyncio`，因为它是`标准`库中包含的一个，但还有许多其他可以正常工作的），它管理一系列协程。这些协程属于事件循环，事件循环将根据其调度机制来调用它们。当这些协程中的每一个运行时，它将调用我们的代码（根据我们在编写的协程中定义的逻辑），当我们想要将控制返回给事件循环时，我们调用`await <coroutine>`，这将异步处理一个任务。事件循环将恢复，另一个协程将代替正在运行的操作。

实际上，还有更多的细节和边缘情况超出了本书的范围。然而，值得一提的是，这些概念与本章介绍的思想相关，并且这个领域是生成器证明是语言的核心概念的另一个地方，因为有许多东西是在它们的基础上构建的。

# 总结

生成器在 Python 中随处可见。自它们在 Python 中诞生以来，它们被证明是一个很好的补充，使程序更加高效，迭代更加简单。

随着时间的推移，以及需要向 Python 添加更复杂的任务，生成器再次帮助支持协程。

而在 Python 中，协程是生成器，我们仍然不必忘记它们在语义上是不同的。生成器是为了迭代而创建的，而协程的目标是异步编程（在任何给定时间暂停和恢复程序的执行部分）。这种区别变得如此重要，以至于它使 Python 的语法（和类型系统）发生了演变。

迭代和异步编程构成了 Python 编程的最后一根主要支柱。现在，是时候看看所有这些概念如何结合在一起，并将我们在过去几章中探讨的所有这些概念付诸实践了。

接下来的章节将描述 Python 项目的其他基本方面，如测试、设计模式和架构。

# 参考资料

以下是您可以参考的信息列表：

+   *PEP-234*：迭代器（[`www.python.org/dev/peps/pep-0234/`](https://www.python.org/dev/peps/pep-0234/)）

+   *PEP-255*：简单生成器（[`www.python.org/dev/peps/pep-0255/`](https://www.python.org/dev/peps/pep-0255/)）

+   *ITER-01*：Python 的 itertools 模块（[`docs.python.org/3/library/itertools.html`](https://docs.python.org/3/library/itertools.html)）

+   *GoF*：由 Erich Gamma, Richard Helm, Ralph Johnson, John Vlissides 撰写的书籍*Design Patterns: Elements of Reusable Object-Oriented Software*

+   *PEP-342*：通过增强生成器实现协程（[`www.python.org/dev/peps/pep-0342/`](https://www.python.org/dev/peps/pep-0342/)）

+   *PYCOOK*：由 Brian Jones, David Beazley 撰写的书籍*Python Cookbook: Recipes for Mastering Python 3, Third Edition*

+   *PY99*：虚拟线程（生成器、协程和续延）（[`mail.python.org/pipermail/python-dev/1999-July/000467.html`](https://mail.python.org/pipermail/python-dev/1999-July/000467.html)）

+   *CORO-01*：协程（[`wiki.c2.com/?CoRoutine`](http://wiki.c2.com/?CoRoutine)）

+   *CORO-02*：生成器不是协程（[`wiki.c2.com/?GeneratorsAreNotCoroutines`](http://wiki.c2.com/?GeneratorsAreNotCoroutines)）

+   *TEE*：`itertools.tee` 函数（[`docs.python.org/3/library/itertools.html#itertools.tee`](https://docs.python.org/3/library/itertools.html#itertools.tee)）


# 第八章：单元测试和重构

本章探讨的思想是本书全局背景中的基本支柱，因为它们对我们的最终目标至关重要：编写更好、更易维护的软件。

单元测试（以及任何形式的自动测试）对于软件的可维护性至关重要，因此是任何优质项目中不可或缺的东西。正因为如此，本章专门致力于自动化测试作为一个关键策略，以安全地修改代码，并在逐步改进的版本中进行迭代。

在本章之后，我们将对以下内容有更深入的了解：

+   为什么自动化测试对于采用敏捷软件开发方法论的项目至关重要

+   单元测试作为代码质量的一种启发方式

+   可用于开发自动化测试和设置质量门限的框架和工具

+   利用单元测试更好地理解领域问题并记录代码

+   与单元测试相关的概念，比如测试驱动开发

# 设计原则和单元测试

在本节中，我们首先从概念角度来看一下单元测试。我们将重新审视我们在之前讨论过的一些软件工程原则，以了解这与清晰代码的关系。

之后，我们将更详细地讨论如何将这些概念付诸实践（在代码层面），以及我们可以利用哪些框架和工具。

首先，我们快速定义一下单元测试的内容。单元测试是负责验证代码的其他部分的代码。通常，任何人都会倾向于说单元测试验证应用程序的“核心”，但这样的定义将单元测试视为次要的，这并不是本书中对单元测试的思考方式。单元测试是核心，是软件的关键组成部分，应该像业务逻辑一样受到同等的考虑。

单元测试是一段代码，它导入代码的部分业务逻辑，并运行其逻辑，断言几种情景，以保证特定条件。单元测试必须具有一些特征，比如：

+   隔离：单元测试应该完全独立于任何其他外部代理，并且它们必须只关注业务逻辑。因此，它们不连接到数据库，不执行 HTTP 请求等。隔离还意味着测试在彼此之间是独立的：它们必须能够以任何顺序运行，而不依赖于任何先前的状态。

+   性能：单元测试必须运行快速。它们旨在多次重复运行。

+   自我验证：单元测试的执行决定了其结果。不需要额外的步骤来解释单元测试（更不用说手动了）。

更具体地说，在 Python 中，这意味着我们将有新的`*.py`文件，我们将在其中放置我们的单元测试，并且它们将被某个工具调用。这些文件将有`import`语句，以从我们的业务逻辑中获取我们需要的内容（我们打算测试的内容），并在这个文件中编写测试本身。之后，一个工具将收集我们的单元测试并运行它们，给出一个结果。

这最后一部分实际上就是自我验证的含义。当工具调用我们的文件时，将启动一个 Python 进程，并在其上运行我们的测试。如果测试失败，进程将以错误代码退出（在 Unix 环境中，这可以是任何不等于`0`的数字）。标准是工具运行测试，并为每个成功的测试打印一个点（`.`），如果测试失败，则打印一个`F`（测试条件未满足），如果出现异常，则打印一个`E`。

# 关于其他形式的自动化测试的说明

单元测试旨在验证非常小的单元，例如函数或方法。我们希望通过单元测试达到非常详细的粒度，尽可能测试更多的代码。为了测试一个类，我们不想使用单元测试，而是使用测试套件，这是一组单元测试。每一个单元测试将测试更具体的内容，比如该类的一个方法。

这并不是唯一的单元测试形式，也不能捕捉到每一个可能的错误。还有验收测试和集成测试，都超出了本书的范围。

在集成测试中，我们希望一次测试多个组件。在这种情况下，我们希望验证它们是否集体按预期工作。在这种情况下，有副作用是可以接受的（甚至是可取的），并且可以忽略隔离，这意味着我们希望发出 HTTP 请求，连接到数据库等。

验收测试是一种自动化的测试形式，试图从用户的角度验证系统，通常执行用例。

这两种测试方式失去了单元测试的另一个优点：速度。正如你可以想象的，它们将需要更多时间来运行，因此它们将运行得更少。

在一个良好的开发环境中，程序员将拥有整个测试套件，并且在进行代码更改、迭代、重构等过程中，会一直运行单元测试。一旦更改准备就绪，并且拉取请求已经打开，持续集成服务将对该分支运行构建，其中将运行单元测试，以及可能存在的集成或验收测试。不用说，在合并之前，构建的状态应该是成功的（绿色），但重要的是测试类型之间的差异：我们希望一直运行单元测试，并且较少频繁地运行那些需要更长时间的测试。因此，我们希望有很多小的单元测试，以及一些自动化测试，策略性地设计来尽可能覆盖单元测试无法达到的地方（例如数据库）。

最后，智者之言。请记住，本书鼓励实用主义。除了本书中给出的定义和关于单元测试的观点之外，读者必须牢记，根据您的标准和背景，最佳解决方案应该占主导地位。没有人比您更了解您的系统。这意味着，如果由于某种原因，您必须编写一个需要启动 Docker 容器来针对数据库进行测试的单元测试，那就去做吧。正如我们在整本书中反复提醒的那样，实用性胜过纯粹性。

# 单元测试和敏捷软件开发

在现代软件开发中，我们希望不断地以尽可能快的速度交付价值。这些目标背后的理念是，我们获得反馈的越早，影响就越小，改变就越容易。这些并不是新的想法；其中一些类似于几十年前的制造原则，而其他一些（比如尽快从利益相关者那里获得反馈并对其进行迭代的想法）可以在《大教堂与集市》等文章中找到。

因此，我们希望能够有效地应对变化，为此，我们编写的软件将不得不改变。就像我们在前几章中提到的，我们希望我们的软件是适应性强、灵活和可扩展的。

单单代码（无论它写得多么好和设计得多么好）不能保证它足够灵活以便进行更改。假设我们按照 SOLID 原则设计了一款软件，并且在某个部分实际上有一组符合开闭原则的组件，这意味着我们可以很容易地扩展它们而不会影响太多现有的代码。进一步假设代码是以有利于重构的方式编写的，因此我们可以根据需要进行更改。当我们进行这些更改时，有什么可以证明我们没有引入任何错误？我们怎么知道现有的功能被保留了？你会对向用户发布这个新版本感到有信心吗？他们会相信新版本的工作方式与预期一样吗？

对所有这些问题的答案是，除非我们有正式的证明，否则我们无法确定。而单元测试就是这样，它是程序按照规范工作的正式证明。

因此，单元（或自动）测试作为一个安全网，给了我们在代码上工作的信心。有了这些工具，我们可以高效地工作在我们的代码上，因此这最终决定了团队在软件产品上的速度（或能力）。测试越好，我们就越有可能快速交付价值，而不会因为不时出现的错误而停滞不前。

# 单元测试和软件设计

当涉及主代码和单元测试之间的关系时，这是另一面的问题。除了在前一节中探讨的实用原因之外，它归结为良好的软件是可测试的软件。**可测试性**（决定软件易于测试程度的质量属性）不仅仅是一种美好的东西，而是对清晰代码的驱动。

单元测试不仅仅是主代码库的补充，而是对代码编写方式有直接影响和真正影响的东西。从最初意识到我们想要为代码的某些部分添加单元测试时，我们必须对其进行更改（从而得到更好的版本），到其最终表达（在本章末尾附近探讨）时，整个代码（设计）是由它将如何通过**测试驱动设计**进行测试而驱动的。

从一个简单的例子开始，我们将向您展示一个小的用例，其中测试（以及测试我们的代码的需要）导致我们编写代码的方式得到改进。

在以下示例中，我们将模拟一个需要向外部系统发送关于每个特定任务获得的结果的指标的过程（和往常一样，只要我们专注于代码，细节就不重要）。我们有一个代表领域问题上某个任务的`Process`对象，并且它使用一个`metrics`客户端（一个外部依赖，因此我们无法控制）来将实际的指标发送到外部实体（这可能是发送数据到`syslog`或`statsd`，例如）：

```py
class MetricsClient:
    """3rd-party metrics client"""

    def send(self, metric_name, metric_value):
        if not isinstance(metric_name, str):
            raise TypeError("expected type str for metric_name")

        if not isinstance(metric_value, str):
            raise TypeError("expected type str for metric_value")

        logger.info("sending %s = %s", metric_name, metric_value)

class Process:

    def __init__(self):
        self.client = MetricsClient() # A 3rd-party metrics client

    def process_iterations(self, n_iterations):
        for i in range(n_iterations):
            result = self.run_process()
            self.client.send("iteration.{}".format(i), result)
```

在第三方客户端的模拟版本中，我们规定提供的参数必须是字符串类型。因此，如果`run_process`方法的`result`不是字符串，我们可能期望它会失败，而事实上确实如此：

```py
Traceback (most recent call last):
...
    raise TypeError("expected type str for metric_value")
TypeError: expected type str for metric_value
```

记住，这种验证不在我们的控制之内，我们无法改变代码，因此在继续之前，我们必须为方法提供正确类型的参数。但由于这是我们发现的一个错误，我们首先想要编写一个单元测试，以确保它不会再次发生。我们这样做实际上是为了证明我们修复了问题，并且保护免受这个错误的影响，无论代码被重构多少次。

通过模拟`Process`对象的`client`，我们可以测试代码，但这样做会运行比需要的更多的代码（注意我们想要测试的部分嵌套在代码中）。此外，方法相对较小是件好事，因为如果不是这样，测试将不得不运行更多不需要的部分，我们可能也需要模拟。这是另一个良好设计的例子（小而紧密的函数或方法），与可测试性相关。

最后，我们决定不费太多力气，只测试我们需要的部分，所以我们不直接在`main`方法上与`client`交互，而是委托给一个`wrapper`方法，新的类看起来是这样的：

```py
class WrappedClient:

    def __init__(self):
        self.client = MetricsClient()

    def send(self, metric_name, metric_value):
        return self.client.send(str(metric_name), str(metric_value))

class Process:
    def __init__(self):
        self.client = WrappedClient()

    ... # rest of the code remains unchanged
```

在这种情况下，我们选择为指标创建我们自己的版本的`client`，也就是说，一个围绕我们以前使用的第三方库的包装器。为此，我们放置了一个类（具有相同的接口），将根据需要转换类型。

这种使用组合的方式类似于适配器设计模式（我们将在下一章中探讨设计模式，所以现在只是一个信息性的消息），而且由于这是我们领域中的一个新对象，它可以有其相应的单元测试。拥有这个对象将使测试变得更简单，但更重要的是，现在我们看到，我们意识到这可能是代码应该一开始就应该编写的方式。尝试为我们的代码编写单元测试使我们意识到我们完全错过了一个重要的抽象！

既然我们已经将方法分离出来，让我们为其编写实际的单元测试。在本例中使用的`unittest`模块的详细信息将在我们探讨测试工具和库的章节中更详细地探讨，但现在阅读代码将给我们一个关于如何测试的第一印象，并且会使之前的概念变得不那么抽象：

```py
import unittest
from unittest.mock import Mock

class TestWrappedClient(unittest.TestCase):
    def test_send_converts_types(self):
        wrapped_client = WrappedClient()
        wrapped_client.client = Mock()
        wrapped_client.send("value", 1)

        wrapped_client.client.send.assert_called_with("value", "1")
```

`Mock`是`unittest.mock`模块中可用的一种类型，它是一个非常方便的对象，可以询问各种事情。例如，在这种情况下，我们将其用于替代第三方库（模拟成系统边界，如下一节所述），以检查它是否按预期调用（再次强调，我们不测试库本身，只测试它是否被正确调用）。注意我们运行了一个类似于我们的`Process`对象的调用，但我们期望参数被转换为字符串。

# 定义要测试的边界

测试需要付出努力。如果我们在决定要测试什么时不小心，我们将永远无法结束测试，因此浪费了大量的精力而没有取得多少成果。

我们应该将测试范围限定在我们的代码边界内。如果不这样做，我们将不得不测试依赖项（外部/第三方库或模块）或我们的代码，然后测试它们各自的依赖项，依此类推，永无止境。我们不负责测试依赖关系，因此我们可以假设这些项目有自己的测试。只需测试对外部依赖的正确调用是否使用了正确的参数（这甚至可能是对补丁的可接受使用），但我们不应该投入更多的精力。

这是另一个良好软件设计的实例。如果我们在设计时小心谨慎，并清晰地定义了系统的边界（也就是说，我们设计时朝向接口，而不是会改变的具体实现，从而颠倒了对外部组件的依赖关系以减少时间耦合），那么在编写单元测试时，模拟这些接口将会更容易得多。

在良好的单元测试中，我们希望在系统的边界上打补丁，并专注于要执行的核心功能。我们不测试外部库（例如通过`pip`安装的第三方工具），而是检查它们是否被正确调用。当我们在本章后面探讨`mock`对象时，我们将回顾执行这些类型的断言的技术和工具。

# 测试框架和工具

有很多工具可以用于编写单元测试，它们都有各自的优缺点并且服务于不同的目的。但在所有工具中，有两种最有可能覆盖几乎所有场景，因此我们将本节限制在这两种工具上。

除了测试框架和测试运行库之外，通常还可以找到配置代码覆盖率的项目，它们将其用作质量指标。由于覆盖率（作为指标使用时）是误导性的，因此在了解如何创建单元测试之后，我们将讨论为什么不应轻视它。

# 单元测试的框架和库

在本节中，我们将讨论两个编写和运行单元测试的框架。第一个是`unittest`，它在 Python 的标准库中可用，而第二个`pytest`必须通过`pip`外部安装。

+   `unittest`: [`docs.python.org/3/library/unittest.html`](https://docs.python.org/3/library/unittest.html)

+   `pytest`: [`docs.pytest.org/en/latest/`](https://docs.pytest.org/en/latest/)

当涉及到为我们的代码覆盖测试场景时，`unittest`可能就足够了，因为它有很多辅助功能。然而，对于我们有多个依赖项、连接到外部系统并且可能需要打补丁对象以及定义固定参数化测试用例的更复杂的系统，`pytest`看起来更完整。

我们将使用一个小程序作为示例，以展示如何使用这两种选项进行测试，最终将帮助我们更好地了解它们之间的比较。

演示测试工具的示例是一个支持合并请求中的代码审查的版本控制工具的简化版本。我们将从以下标准开始：

+   如果至少有一个人不同意更改，合并请求将被拒绝

+   如果没有人反对，并且至少有其他两个开发人员认为合并请求是好的，它就会被批准

+   在其他情况下，它的状态是`pending`

代码可能如下所示：

```py
from enum import Enum

class MergeRequestStatus(Enum):
    APPROVED = "approved"
    REJECTED = "rejected"
    PENDING = "pending"

class MergeRequest:
    def __init__(self):
        self._context = {
            "upvotes": set(),
            "downvotes": set(),
        }

    @property
    def status(self):
        if self._context["downvotes"]:
            return MergeRequestStatus.REJECTED
        elif len(self._context["upvotes"]) >= 2:
            return MergeRequestStatus.APPROVED
        return MergeRequestStatus.PENDING

    def upvote(self, by_user):
        self._context["downvotes"].discard(by_user)
        self._context["upvotes"].add(by_user)

    def downvote(self, by_user):
        self._context["upvotes"].discard(by_user)
        self._context["downvotes"].add(by_user)
```

# unittest

`unittest`模块是一个很好的选择，可以开始编写单元测试，因为它提供了丰富的 API 来编写各种测试条件，并且由于它在标准库中可用，因此它非常灵活和方便。

`unittest`模块基于 JUnit（来自 Java）的概念，而 JUnit 又基于来自 Smalltalk 的单元测试的原始思想，因此它是面向对象的。因此，测试是通过对象编写的，其中检查由方法验证，并且通常通过类将测试分组到场景中。

要开始编写单元测试，我们必须创建一个从`unittest.TestCase`继承的测试类，并定义我们想要在其方法中强调的条件。这些方法应该以`test_*`开头，并且可以在内部使用从`unittest.TestCase`继承的任何方法来检查必须成立的条件。

我们可能想要验证我们的情况的一些条件的示例包括：

```py
class TestMergeRequestStatus(unittest.TestCase):

    def test_simple_rejected(self):
        merge_request = MergeRequest()
        merge_request.downvote("maintainer")
        self.assertEqual(merge_request.status, MergeRequestStatus.REJECTED)

    def test_just_created_is_pending(self):
        self.assertEqual(MergeRequest().status, MergeRequestStatus.PENDING)

    def test_pending_awaiting_review(self):
        merge_request = MergeRequest()
        merge_request.upvote("core-dev")
        self.assertEqual(merge_request.status, MergeRequestStatus.PENDING)

    def test_approved(self):
        merge_request = MergeRequest()
        merge_request.upvote("dev1")
        merge_request.upvote("dev2")

        self.assertEqual(merge_request.status, MergeRequestStatus.APPROVED)
```

单元测试的 API 提供了许多有用的比较方法，其中最常见的是`assertEquals(<actual>, <expected>[, message])`，它可以用来比较操作的结果与我们期望的值，可选地使用在错误情况下显示的消息。

另一个有用的测试方法允许我们检查是否引发了某个异常。当发生异常情况时，我们在代码中引发异常，以防止在错误的假设下进行持续处理，并且通知调用者调用的方式有问题。这是应该进行测试的逻辑的一部分，这就是这个方法的作用。

假设我们现在正在进一步扩展我们的逻辑，以允许用户关闭他们的合并请求，一旦发生这种情况，我们就不希望再进行更多的投票（在合并请求已经关闭后评估合并请求是没有意义的）。为了防止这种情况发生，我们扩展我们的代码，并在不幸的事件发生时引发异常，当有人试图对已关闭的合并请求进行投票时。

在添加了两个新状态（`OPEN`和`CLOSED`）和一个新的`close()`方法之后，我们修改了之前的投票方法，以处理此检查：

```py
class MergeRequest:
    def __init__(self):
        self._context = {
            "upvotes": set(),
            "downvotes": set(),
        }
        self._status = MergeRequestStatus.OPEN

    def close(self):
        self._status = MergeRequestStatus.CLOSED

    ...
    def _cannot_vote_if_closed(self):
        if self._status == MergeRequestStatus.CLOSED:
            raise MergeRequestException("can't vote on a closed merge 
            request")

    def upvote(self, by_user):
        self._cannot_vote_if_closed()

        self._context["downvotes"].discard(by_user)
        self._context["upvotes"].add(by_user)

    def downvote(self, by_user):
        self._cannot_vote_if_closed()

        self._context["upvotes"].discard(by_user)
        self._context["downvotes"].add(by_user)
```

现在，我们想要检查这个验证是否有效。为此，我们将使用`asssertRaises`和`assertRaisesRegex`方法：

```py
    def test_cannot_upvote_on_closed_merge_request(self):
        self.merge_request.close()
        self.assertRaises(
            MergeRequestException, self.merge_request.upvote, "dev1"
        )

    def test_cannot_downvote_on_closed_merge_request(self):
        self.merge_request.close()
        self.assertRaisesRegex(
            MergeRequestException,
            "can't vote on a closed merge request",
            self.merge_request.downvote,
            "dev1",
        )
```

前者期望在调用第二个参数中的可调用对象时引发提供的异常，使用函数的其余部分的参数（`*args`和`**kwargs`），如果不是这种情况，它将失败，并表示预期引发的异常未被引发。后者也是如此，但它还检查引发的异常是否包含与提供的正则表达式匹配的消息。即使引发了异常，但消息不同（不匹配正则表达式），测试也会失败。

尝试检查错误消息，因为异常不仅会更准确地进行额外检查，确保实际上触发了我们想要的异常，还会检查是否另一个相同类型的异常偶然发生。

# 参数化测试

现在，我们想要测试合并请求的阈值接受如何工作，只需提供`context`的数据样本，而不需要整个`MergeRequest`对象。我们想要测试`status`属性的部分，即在检查它是否关闭之后的部分，但是独立地。

实现这一目标的最佳方法是将该组件分离为另一个类，使用组合，然后继续使用自己的测试套件测试这个新的抽象：

```py
class AcceptanceThreshold:
    def __init__(self, merge_request_context: dict) -> None:
        self._context = merge_request_context

    def status(self):
        if self._context["downvotes"]:
            return MergeRequestStatus.REJECTED
        elif len(self._context["upvotes"]) >= 2:
            return MergeRequestStatus.APPROVED
        return MergeRequestStatus.PENDING

class MergeRequest:
    ...
    @property
    def status(self):
        if self._status == MergeRequestStatus.CLOSED:
            return self._status

        return AcceptanceThreshold(self._context).status()
```

有了这些变化，我们可以再次运行测试并验证它们是否通过，这意味着这次小的重构没有破坏当前功能（单元测试确保回归）。有了这一点，我们可以继续实现编写特定于新类的测试的目标：

```py
class TestAcceptanceThreshold(unittest.TestCase):
    def setUp(self):
        self.fixture_data = (
            (
                {"downvotes": set(), "upvotes": set()},
                MergeRequestStatus.PENDING
            ),
            (
                {"downvotes": set(), "upvotes": {"dev1"}},
                MergeRequestStatus.PENDING,
            ),
            (
                {"downvotes": "dev1", "upvotes": set()},
                MergeRequestStatus.REJECTED
            ),
            (
                {"downvotes": set(), "upvotes": {"dev1", "dev2"}},
                MergeRequestStatus.APPROVED
            ),
        )

    def test_status_resolution(self):
        for context, expected in self.fixture_data:
            with self.subTest(context=context):
                status = AcceptanceThreshold(context).status()
                self.assertEqual(status, expected)
```

在`setUp()`方法中，我们定义了要在整个测试中使用的数据装置。在这种情况下，实际上并不需要，因为我们可以直接放在方法中，但是如果我们希望在执行任何测试之前运行一些代码，这就是写入的地方，因为这个方法在每次运行测试之前都会被调用一次。

通过编写代码的新版本，被测试代码下的参数更清晰更紧凑，并且在每种情况下都会报告结果。

为了模拟我们正在运行所有参数，测试会遍历所有数据，并对每个实例执行代码。这里一个有趣的辅助方法是使用`subTest`，在这种情况下，我们使用它来标记被调用的测试条件。如果其中一个迭代失败，`unittest`会报告相应的变量值，这些变量被传递给`subTest`（在这种情况下，它被命名为`context`，但任何一系列关键字参数都可以起到同样的作用）。例如，一个错误可能看起来像这样：

```py
FAIL: (context={'downvotes': set(), 'upvotes': {'dev1', 'dev2'}})
----------------------------------------------------------------------
Traceback (most recent call last):
  File "" test_status_resolution
    self.assertEqual(status, expected)
AssertionError: <MergeRequestStatus.APPROVED: 'approved'> != <MergeRequestStatus.REJECTED: 'rejected'>
```

如果选择参数化测试，请尽量提供每个参数实例的上下文信息，以便更容易进行调试。

# pytest

Pytest 是一个很棒的测试框架，可以通过`pip install pytest`进行安装。与`unittest`相比的一个区别是，虽然仍然可以将测试场景分类为类，并创建我们测试的面向对象模型，但这并不是强制性的，也可以通过使用`assert`语句来写更少的样板代码进行单元测试。

默认情况下，使用`assert`语句进行比较就足以让`pytest`识别单元测试并相应地报告其结果。还可以使用包中的特定函数进行更高级的用法，但这需要使用特定的函数。

一个很好的特性是命令`pytests`将运行它能够发现的所有测试，即使它们是用`unittest`编写的。这种兼容性使得逐渐从`unittest`过渡到`pytest`变得更容易。

# 使用 pytest 进行基本测试用例

我们在上一节中测试的条件可以用`pytest`中的简单函数重写。

一些简单断言的示例如下：

```py
def test_simple_rejected():
    merge_request = MergeRequest()
    merge_request.downvote("maintainer")
    assert merge_request.status == MergeRequestStatus.REJECTED

def test_just_created_is_pending():
    assert MergeRequest().status == MergeRequestStatus.PENDING

def test_pending_awaiting_review():
    merge_request = MergeRequest()
    merge_request.upvote("core-dev")
    assert merge_request.status == MergeRequestStatus.PENDING
```

布尔相等比较不需要更多的简单断言语句，而其他类型的检查，比如异常的检查需要我们使用一些函数：

```py
def test_invalid_types():
    merge_request = MergeRequest()
    pytest.raises(TypeError, merge_request.upvote, {"invalid-object"})

def test_cannot_vote_on_closed_merge_request():
    merge_request = MergeRequest()
    merge_request.close()
    pytest.raises(MergeRequestException, merge_request.upvote, "dev1")
    with pytest.raises(
        MergeRequestException,
        match="can't vote on a closed merge request",
    ):
        merge_request.downvote("dev1")
```

在这种情况下，`pytest.raises`相当于`unittest.TestCase.assertRaises`，它也接受作为方法和上下文管理器调用。如果我们想检查异常的消息，而不是使用不同的方法（如`assertRaisesRegex`），则必须使用相同的函数，但作为上下文管理器，并提供`match`参数与我们想要识别的表达式。

`pytest`还会将原始异常包装成一个自定义异常，可以通过检查其属性（例如`.value`）来预期，以便在需要检查更多条件时使用，但这个函数的使用覆盖了绝大多数情况。

# 参数化测试

使用`pytest`运行参数化测试更好，不仅因为它提供了更清晰的 API，而且因为每个测试与其参数的组合都会生成一个新的测试用例。

为了使用这个，我们必须在我们的测试上使用`pytest.mark.parametrize`装饰器。装饰器的第一个参数是一个字符串，指示要传递给`test`函数的参数的名称，第二个参数必须是可迭代的，包含这些参数的相应值。

注意测试函数的主体如何被简化为一行（在移除内部`for`循环和其嵌套的上下文管理器后），并且每个测试用例的数据都正确地与函数的主体隔离开来，这样更容易扩展和维护：

```py
@pytest.mark.parametrize("context,expected_status", (
    (
        {"downvotes": set(), "upvotes": set()},
        MergeRequestStatus.PENDING
    ),
    (
        {"downvotes": set(), "upvotes": {"dev1"}},
        MergeRequestStatus.PENDING,
    ),
    (
        {"downvotes": "dev1", "upvotes": set()},
        MergeRequestStatus.REJECTED
    ),
    (
        {"downvotes": set(), "upvotes": {"dev1", "dev2"}},
        MergeRequestStatus.APPROVED
    ),
))
def test_acceptance_threshold_status_resolution(context, expected_status):
    assert AcceptanceThreshold(context).status() == expected_status
```

使用`@pytest.mark.parametrize`来消除重复，尽可能使测试主体保持内聚，并明确指定代码必须支持的参数（测试输入或场景）。

# Fixture

`pytest`的一个很棒的功能是它如何促进创建可重用的功能，这样我们可以有效地测试数据或对象，而不需要重复。

例如，我们可能想要创建一个处于特定状态的`MergeRequest`对象，并在多个测试中使用该对象。我们通过创建一个函数并应用`@pytest.fixture`装饰器来将我们的对象定义为 fixture。想要使用该 fixture 的测试将必须具有与定义的函数相同名称的参数，`pytest`将确保提供它： 

```py
@pytest.fixture
def rejected_mr():
    merge_request = MergeRequest()

    merge_request.downvote("dev1")
    merge_request.upvote("dev2")
    merge_request.upvote("dev3")
    merge_request.downvote("dev4")

    return merge_request

def test_simple_rejected(rejected_mr):
    assert rejected_mr.status == MergeRequestStatus.REJECTED

def test_rejected_with_approvals(rejected_mr):
    rejected_mr.upvote("dev2")
    rejected_mr.upvote("dev3")
    assert rejected_mr.status == MergeRequestStatus.REJECTED

def test_rejected_to_pending(rejected_mr):
    rejected_mr.upvote("dev1")
    assert rejected_mr.status == MergeRequestStatus.PENDING

def test_rejected_to_approved(rejected_mr):
    rejected_mr.upvote("dev1")
    rejected_mr.upvote("dev2")
    assert rejected_mr.status == MergeRequestStatus.APPROVED
```

记住，测试也会影响主要代码，因此干净代码的原则也适用于它们。在这种情况下，我们在之前章节中探讨过的**不要重复自己**（**DRY**）原则再次出现，我们可以借助`pytest`的 fixture 来实现它。

除了创建多个对象或公开将在整个测试套件中使用的数据之外，还可以使用它们来设置一些条件，例如全局修补一些不希望被调用的函数，或者当我们希望使用修补对象时。

# 代码覆盖率

测试运行器支持覆盖插件（通过`pip`安装）将提供有关测试运行时执行了代码的哪些行的有用信息。这些信息对我们非常有帮助，以便我们知道代码的哪些部分需要被测试覆盖，并确定需要进行的改进（无论是在生产代码中还是在测试中）。其中最广泛使用的库之一是`coverage`（[`pypi.org/project/coverage/`](https://pypi.org/project/coverage/)）。

虽然它们非常有帮助（我们强烈建议您使用它们并配置您的项目在运行测试时在 CI 中运行覆盖），但它们也可能会产生误导；特别是在 Python 中，如果我们不仔细阅读覆盖报告，就会产生错误的印象。

# 设置其余覆盖

在`pytest`的情况下，我们必须安装`pytest-cov`软件包（在撰写本书时，本书使用的是版本`2.5.1`）。安装后，当运行测试时，我们必须告诉`pytest`运行器也将运行`pytest-cov`，以及应该覆盖哪个软件包（以及其他参数和配置）。

该软件包支持多种配置，如不同类型的输出格式，并且很容易将其与任何 CI 工具集成，但在所有这些功能中，一个强烈推荐的选项是设置标志，告诉我们哪些行尚未被测试覆盖，因为这将帮助我们诊断我们的代码，并允许我们开始编写更多的测试。

为了向您展示这是什么样子，使用以下命令：

```py
pytest \
    --cov-report term-missing \
    --cov=coverage_1 \
    test_coverage_1.py
```

这将产生类似以下的输出：

```py
test_coverage_1.py ................ [100%]

----------- coverage: platform linux, python 3.6.5-final-0 -----------
Name         Stmts Miss Cover Missing
---------------------------------------------
coverage_1.py 38      1  97%    53
```

在这里，它告诉我们有一行没有单元测试，因此我们可以查看并了解如何为其编写单元测试。这是一个常见的情况，我们意识到为了覆盖这些缺失的行，我们需要通过创建更小的方法来重构代码。结果，我们的代码看起来会好得多，就像我们在本章开头看到的例子一样。

问题在于相反的情况——我们能相信高覆盖率吗？这是否意味着我们的代码是正确的？不幸的是，拥有良好的测试覆盖率是必要的，但不足以保证代码的清洁。对代码的某些部分没有测试显然是不好的。拥有测试实际上是非常好的（我们可以说对于已经存在的测试），并且实际上断言了它们是代码质量的保证。然而，我们不能说这就是所有需要的；尽管覆盖率很高，但仍需要更多的测试。

这些是测试覆盖率的注意事项，我们将在下一节中提到。

# 测试覆盖的注意事项

Python 是解释性的，而覆盖工具利用这一点来识别在测试运行时被解释（运行）的行。然后它会在最后报告这一点。一行被解释并不意味着它被正确测试了，这就是为什么我们应该仔细阅读最终的覆盖报告并信任它所说的内容。

这实际上对于任何语言都是正确的。执行了一行代码并不意味着它已经经历了所有可能的组合。所有分支在提供的数据下成功运行只意味着代码支持了该组合，但这并不能告诉我们任何其他可能导致程序崩溃的参数组合。

使用覆盖作为发现代码中盲点的工具，而不是作为度量标准或目标。

# 模拟对象

有些情况下，我们的代码不是在测试环境中唯一存在的东西。毕竟，我们设计和构建的系统必须做一些真实的事情，这通常意味着连接到外部服务（数据库、存储服务、外部 API、云服务等）。因为它们需要具有这些副作用，它们是不可避免的。尽管我们抽象我们的代码，朝着接口编程，并且隔离代码以最小化副作用，但它们会出现在我们的测试中，我们需要一种有效的方式来处理它们。

`模拟`对象是防止不良副作用的最佳策略之一。我们的代码可能需要执行 HTTP 请求或发送通知电子邮件，但我们肯定不希望这些事件发生在我们的单元测试中。此外，单元测试应该运行得很快，因为我们希望经常运行它们（实际上是一直），这意味着我们不能承受延迟。因此，真正的单元测试不使用任何实际服务——它们不连接到任何数据库，不发出 HTTP 请求，基本上除了执行生产代码的逻辑之外什么都不做。

我们需要执行这些操作的测试，但它们不是单元测试。集成测试应该以更广泛的视角测试功能，几乎模仿用户的行为。但它们不快。因为它们连接到外部系统和服务，所以运行时间更长，成本更高。通常，我们希望有大量的单元测试能够快速运行，以便一直运行它们，而集成测试则较少运行（例如，在任何新的合并请求上）。

虽然模拟对象很有用，但滥用它们的使用范围介于代码异味和反模式之间是我们在深入讨论之前想要提到的第一个警告。

# 关于修补和模拟的公平警告

我们之前说过，单元测试帮助我们编写更好的代码，因为我们想要开始测试代码的部分时，通常必须编写可测试的代码，这通常意味着它们也是内聚的、细粒度的和小的。这些都是软件组件中具有的良好特性。

另一个有趣的收获是，测试将帮助我们注意到代码中存在代码异味的地方。我们的代码存在代码异味的主要警告之一是，我们发现自己试图 monkey-patch（或模拟）许多不同的东西，只是为了覆盖一个简单的测试用例。

`unittest`模块提供了一个在`unittest.mock.patch`中修补对象的工具。修补意味着原始代码（由导入时指定其位置的字符串给出）将被其他东西替换，而不是其原始代码，默认情况下是模拟对象。这会在运行时替换代码，并且有一个缺点，即我们失去了原始代码的联系，使我们的测试变得更加肤浅。它还带来了性能考虑，因为在运行时修改对象会带来开销，并且如果我们重构代码并移动事物，这可能会导致更新。

在我们的测试中使用 monkey-patching 或模拟可能是可以接受的，而且本身并不代表一个问题。另一方面，滥用 monkey-patching 确实是一个标志，表明我们的代码需要改进。

# 使用模拟对象

在单元测试术语中，有几种对象属于名为**测试替身**的类别。测试替身是一种对象，它将以不同种类的原因在我们的测试套件中代替真实对象（也许我们不需要实际的生产代码，而只需要一个虚拟对象，或者我们不能使用它，因为它需要访问服务或者它具有我们不希望在单元测试中出现的副作用等）。

有不同类型的测试替身，例如虚拟对象、存根、间谍或模拟。模拟是最一般的对象类型，由于它们非常灵活和多功能，因此适用于所有情况，而无需详细了解其他情况。正因为如此，标准库还包括了这种类型的对象，并且在大多数 Python 程序中都很常见。这就是我们将在这里使用的：`unittest.mock.Mock`。

**模拟**是一种根据规范创建的对象类型（通常类似于生产类的对象）和一些配置的响应（也就是说，我们可以告诉模拟在某些调用时应该返回什么，并且它的行为应该是什么）。然后，“模拟”对象将记录其内部状态的一部分，例如它是如何被调用的（使用了什么参数，多少次等），我们可以使用该信息在以后的阶段验证我们应用程序的行为。

在 Python 的情况下，标准库中提供的`Mock`对象提供了一个很好的 API，可以进行各种行为断言，例如检查模拟调用了多少次，使用了什么参数等。

# 模拟的类型

标准库在`unittest.mock`模块中提供了`Mock`和`MagicMock`对象。前者是一个可以配置为返回任何值并将跟踪对其进行的调用的测试替身。后者也是如此，但它还支持魔术方法。这意味着，如果我们编写了使用魔术方法的成语代码（并且我们正在测试的代码的某些部分将依赖于它），那么我们可能必须使用`MagicMock`实例而不仅仅是`Mock`。

当我们的代码需要调用魔术方法时，尝试使用`Mock`将导致错误。请参阅以下代码，以了解此示例：

```py
class GitBranch:
    def __init__(self, commits: List[Dict]):
        self._commits = {c["id"]: c for c in commits}

    def __getitem__(self, commit_id):
        return self._commits[commit_id]

    def __len__(self):
        return len(self._commits)

def author_by_id(commit_id, branch):
    return branch[commit_id]["author"]
```

我们想测试这个函数；但是，另一个测试需要调用`author_by_id`函数。由于某种原因，因为我们没有测试该函数，提供给该函数（并返回）的任何值都将是好的：

```py
def test_find_commit():
    branch = GitBranch([{"id": "123", "author": "dev1"}])
    assert author_by_id("123", branch) == "dev1"

def test_find_any():
    author = author_by_id("123", Mock()) is not None
    # ... rest of the tests..
```

正如预期的那样，这不起作用：

```py
def author_by_id(commit_id, branch):
    > return branch[commit_id]["author"]
    E TypeError: 'Mock' object is not subscriptable
```

使用`MagicMock`将起作用。我们甚至可以配置此类型模拟的魔术方法，以返回我们需要的内容，以便控制我们测试的执行：

```py
def test_find_any():
    mbranch = MagicMock()
    mbranch.__getitem__.return_value = {"author": "test"}
    assert author_by_id("123", mbranch) == "test"
```

# 测试替身的用例

为了看到模拟的可能用途，我们需要向我们的应用程序添加一个新组件，该组件将负责通知“构建”“状态”的合并请求。当“构建”完成时，将使用合并请求的 ID 和“构建”的“状态”调用此对象，并通过向特定的固定端点发送 HTTP`POST`请求来使用此信息更新合并请求的“状态”：

```py
# mock_2.py

from datetime import datetime

import requests
from constants import STATUS_ENDPOINT

class BuildStatus:
    """The CI status of a pull request."""

    @staticmethod
    def build_date() -> str:
        return datetime.utcnow().isoformat()

    @classmethod
    def notify(cls, merge_request_id, status):
        build_status = {
            "id": merge_request_id,
            "status": status,
            "built_at": cls.build_date(),
        }
        response = requests.post(STATUS_ENDPOINT, json=build_status)
        response.raise_for_status()
        return response

```

这个类有很多副作用，但其中一个是一个重要的难以克服的外部依赖。如果我们试图在不修改任何内容的情况下对其进行测试，那么它将在尝试执行 HTTP 连接时立即失败并出现连接错误。

作为测试目标，我们只想确保信息被正确组成，并且库请求是使用适当的参数进行调用的。由于这是一个外部依赖项，我们不测试请求；只需检查它是否被正确调用就足够了。

当尝试比较发送到库的数据时，我们将面临另一个问题，即该类正在计算当前时间戳，这在单元测试中是不可能预测的。直接修补`datetime`是不可能的，因为该模块是用 C 编写的。有一些外部库可以做到这一点（例如`freezegun`），但它们会带来性能损耗，并且对于这个例子来说会过度。因此，我们选择将我们想要的功能封装在一个静态方法中，以便我们可以修补它。

现在我们已经确定了代码中需要替换的要点，让我们编写单元测试：

```py
# test_mock_2.py

from unittest import mock

from constants import STATUS_ENDPOINT
from mock_2 import BuildStatus

@mock.patch("mock_2.requests")
def test_build_notification_sent(mock_requests):
    build_date = "2018-01-01T00:00:01"
    with mock.patch("mock_2.BuildStatus.build_date", 
    return_value=build_date):
        BuildStatus.notify(123, "OK")

    expected_payload = {"id": 123, "status": "OK", "built_at": 
    build_date}
    mock_requests.post.assert_called_with(
        STATUS_ENDPOINT, json=expected_payload
    )
```

首先，我们使用`mock.patch`作为装饰器来替换`requests`模块。这个函数的结果将创建一个`mock`对象，将作为参数传递给测试（在这个例子中命名为`mock_requests`）。然后，我们再次使用这个函数，但这次作为上下文管理器，来改变计算“构建”日期的类的方法的返回值，用我们控制的值替换它，我们将在断言中使用。

一旦我们把所有这些都放在那里，我们就可以用一些参数调用类方法，然后我们可以使用`mock`对象来检查它是如何被调用的。在这种情况下，我们使用这个方法来查看`requests.post`是否确实以我们想要的参数被调用。

这是模拟的一个很好的特性——它们不仅限制了所有外部组件的范围（在这种情况下，以防止实际发送一些通知或发出 HTTP 请求），而且还提供了一个有用的 API 来验证调用及其参数。

在这种情况下，我们能够通过设置相应的“模拟”对象来测试代码，但事实上，与主要功能的总代码行数相比，我们不得不进行相当多的补丁。关于被测试的纯生产代码与我们必须模拟的代码部分之间的比例没有明确的规则，但是通过运用常识，我们可以看到，如果我们不得不在相同的部分进行相当多的补丁，那么某些东西并没有被清晰地抽象出来，看起来像是代码异味。

在下一节中，我们将探讨如何重构代码来解决这个问题。

# 重构

**重构**是软件维护中的一个关键活动，但如果没有单元测试，就不能做到（至少是正确的）。我们时不时需要支持一个新功能或以意想不到的方式使用我们的软件。我们需要意识到，满足这些要求的唯一方法是首先重构我们的代码，使其更通用。只有这样，我们才能继续前进。

通常，在重构我们的代码时，我们希望改进其结构，使其更好，有时更通用，更可读，或更灵活。挑战在于在实现这些目标的同时保持与修改之前完全相同的功能。这意味着，在我们重构的组件的客户眼中，可能根本没有发生任何事情。

必须支持与之前相同的功能，但使用不同版本的代码这一约束意味着我们需要对修改过的代码运行回归测试。运行回归测试的唯一经济有效的方法是自动化。自动化测试的最经济有效的版本是单元测试。

# 改进我们的代码

在前面的例子中，我们能够将代码的副作用与我们无法在单元测试中控制的部分分离出来，通过对依赖于这些部分的代码进行补丁，使其可测试。这是一个很好的方法，因为毕竟，`mock.patch`函数对于这些任务来说非常方便，可以替换我们告诉它的对象，给我们一个`Mock`对象。

这样做的缺点是，我们必须提供我们将要模拟的对象的路径，包括模块，作为一个字符串。这有点脆弱，因为如果我们重构我们的代码（比如说我们重命名文件或将其移动到其他位置），所有的补丁位置都必须更新，否则测试将会失败。

在这个例子中，`notify()`方法直接依赖于一个实现细节（`requests`模块），这是一个设计问题，也就是说，它也对单元测试产生了上述的脆弱性。

我们仍然需要用双重对象（模拟）替换这些方法，但如果我们重构代码，我们可以以更好的方式来做。让我们将这些方法分开成更小的方法，最重要的是注入依赖，而不是固定它。现在代码应用了依赖反转原则，并且期望与支持接口的东西一起工作（在这个例子中是隐式的），比如`requests`模块提供的接口：

```py
from datetime import datetime

from constants import STATUS_ENDPOINT

class BuildStatus:

    endpoint = STATUS_ENDPOINT

    def __init__(self, transport):
        self.transport = transport

    @staticmethod
    def build_date() -> str:
        return datetime.utcnow().isoformat()

    def compose_payload(self, merge_request_id, status) -> dict:
        return {
            "id": merge_request_id,
            "status": status,
            "built_at": self.build_date(),
        }

    def deliver(self, payload):
        response = self.transport.post(self.endpoint, json=payload)
        response.raise_for_status()
        return response

    def notify(self, merge_request_id, status):
        return self.deliver(self.compose_payload(merge_request_id, status))
```

我们将方法分开（不再是 notify，而是 compose + deliver），创建了一个新的`compose_payload()`方法（这样我们可以替换，而不需要打补丁类），并要求注入`transport`依赖。现在`transport`是一个依赖项，更容易更改该对象为我们想要的任何双重对象。

甚至可以暴露这个对象的一个 fixture，并根据需要替换双重对象：

```py
@pytest.fixture
def build_status():
    bstatus = BuildStatus(Mock())
    bstatus.build_date = Mock(return_value="2018-01-01T00:00:01")
    return bstatus

def test_build_notification_sent(build_status):

    build_status.notify(1234, "OK")

    expected_payload = {
        "id": 1234,
        "status": "OK",
        "built_at": build_status.build_date(),
    }

```

```py
    build_status.transport.post.assert_called_with(
        build_status.endpoint, json=expected_payload
    )
```

# 生产代码并不是唯一在演变的东西

我们一直在说单元测试和生产代码一样重要。如果我们对生产代码足够小心以创建最佳的抽象，为什么我们不为单元测试做同样的事呢？

如果单元测试的代码和主要代码一样重要，那么设计时一定要考虑可扩展性，并尽可能使其易于维护。毕竟，这段代码将由原作者以外的工程师来维护，因此必须易读。

我们如此重视代码的灵活性的原因是，我们知道需求会随着时间的推移而改变和演变，最终随着领域业务规则的变化，我们的代码也将不得不改变以支持这些新需求。由于生产代码已经改变以支持新需求，测试代码也将不得不改变以支持生产代码的新版本。

在我们最初的示例中，我们为合并请求对象创建了一系列测试，尝试不同的组合并检查合并请求的状态。这是一个很好的第一步，但我们可以做得更好。

一旦我们更好地理解了问题，我们就可以开始创建更好的抽象。首先想到的是，我们可以创建一个检查特定条件的更高级抽象。例如，如果我们有一个专门针对`MergeRequest`类的测试套件对象，我们知道其功能将局限于这个类的行为（因为它应该符合 SRP），因此我们可以在这个测试类上创建特定的测试方法。这些方法只对这个类有意义，但可以帮助减少大量样板代码。

我们可以创建一个封装这一结构的断言的方法，并在所有测试中重复使用它，而不是重复断言：

```py
class TestMergeRequestStatus(unittest.TestCase):
    def setUp(self):
        self.merge_request = MergeRequest()

    def assert_rejected(self):
        self.assertEqual(
            self.merge_request.status, MergeRequestStatus.REJECTED
        )

    def assert_pending(self):
        self.assertEqual(
            self.merge_request.status, MergeRequestStatus.PENDING
        )

    def assert_approved(self):
        self.assertEqual(
            self.merge_request.status, MergeRequestStatus.APPROVED
        )

    def test_simple_rejected(self):
        self.merge_request.downvote("maintainer")
        self.assert_rejected()

    def test_just_created_is_pending(self):
        self.assert_pending()
```

如果合并请求的状态检查发生变化（或者我们想要添加额外的检查），只有一个地方（`assert_approved()`方法）需要修改。更重要的是，通过创建这些更高级的抽象，最初只是单元测试的代码开始演变成可能最终成为具有自己 API 或领域语言的测试框架，使测试更具有声明性。

# 更多关于单元测试

通过我们迄今为止重新审视的概念，我们知道如何测试我们的代码，考虑我们的设计将如何进行测试，并配置项目中的工具来运行自动化测试，这将使我们对所编写软件的质量有一定程度的信心。

如果我们对代码的信心是由编写在其上的单元测试所决定的，那么我们如何知道它们足够了？我们怎么能确定我们已经在测试场景上经历了足够多的测试，而且没有漏掉一些测试？谁说这些测试是正确的？也就是说，谁来测试这些测试？

关于我们编写的测试是否彻底的问题的第一部分，通过基于属性的测试来超越我们的测试努力来回答。

问题的第二部分可能会有不同的观点给出多个答案，但我们将简要提到变异测试作为确定我们的测试确实是正确的手段。在这方面，我们认为单元测试检查我们的主要生产代码，这也对单元测试起到了控制作用。

# 基于属性的测试

基于属性的测试包括生成测试用例的数据，目的是找到会使代码失败的情景，而这些情景在我们之前的单元测试中没有涵盖。

这个主要的库是`hypothesis`，它与我们的单元测试一起配置，将帮助我们找到会使我们的代码失败的问题数据。

我们可以想象这个库的作用是找到我们代码的反例。我们编写我们的生产代码（以及针对它的单元测试！），并声称它是正确的。现在，通过这个库，我们定义了一些必须满足我们代码的`hypothesis`，如果有一些情况下我们的断言不成立，`hypothesis`将提供一组导致错误的数据。

单元测试最好的一点是它让我们更加深入地思考我们的生产代码。`hypothesis`最好的一点是它让我们更加深入地思考我们的单元测试。

# 变异测试

我们知道测试是我们确保代码正确的正式验证方法。那么是什么确保测试是正确的呢？你可能会想到生产代码，是的，在某种程度上这是正确的，我们可以将主要代码视为对我们测试的一个平衡。

编写单元测试的重点在于我们正在保护自己免受错误的侵害，并测试我们真的不希望在生产中发生的失败场景。测试通过是好事，但如果它们通过了错误的原因就不好了。也就是说，我们可以将单元测试用作自动回归工具——如果有人在代码中引入了错误，我们期望我们的至少一个测试能够捕捉到并失败。如果这没有发生，要么是缺少了一个测试，要么是我们已有的测试没有进行正确的检查。

这就是变异测试的理念。使用变异测试工具，代码将被修改为新版本（称为变异体），这些变异体是原始代码的变体，但其中一些逻辑被改变了（例如，操作符被交换，条件被倒置等）。一个良好的测试套件应该能够捕捉到这些变异体并将其消灭，这意味着我们可以依赖这些测试。如果一些变异体在实验中幸存下来，通常这是一个不好的迹象。当然，这并不是完全精确的，所以有一些中间状态我们可能想要忽略。

为了快速向您展示这是如何工作的，并让您对此有一个实际的想法，我们将使用一个不同版本的代码来计算合并请求的状态，这是基于批准和拒绝的数量。这一次，我们已经改变了代码，改为一个简单版本，根据这些数字返回结果。我们已经将包含状态常量的枚举移到一个单独的模块中，所以现在看起来更加紧凑：

```py
# File mutation_testing_1.py
from mrstatus import MergeRequestStatus as Status

def evaluate_merge_request(upvote_count, downvotes_count):
    if downvotes_count > 0:
        return Status.REJECTED
    if upvote_count >= 2:
        return Status.APPROVED
    return Status.PENDING
```

现在我们将添加一个简单的单元测试，检查其中一个条件及其预期的“结果”：

```py
# file: test_mutation_testing_1.py
class TestMergeRequestEvaluation(unittest.TestCase):
    def test_approved(self):
        result = evaluate_merge_request(3, 0)
        self.assertEqual(result, Status.APPROVED)
```

现在，我们将安装`mutpy`，一个用于 Python 的变异测试工具，使用`pip install mutpy`，并告诉它使用这些测试运行此模块的变异测试：

```py
$ mut.py \
    --target mutation_testing_$N \
    --unit-test test_mutation_testing_$N \
    --operator AOD `# delete arithmetic operator` \
    --operator AOR `# replace arithmetic operator` \
    --operator COD `# delete conditional operator` \
    --operator COI `# insert conditional operator` \
    --operator CRP `# replace constant` \
    --operator ROR `# replace relational operator` \
    --show-mutants
```

结果将会看起来类似于这样：

```py
[*] Mutation score [0.04649 s]: 100.0%
 - all: 4
 - killed: 4 (100.0%)
 - survived: 0 (0.0%)
 - incompetent: 0 (0.0%)
 - timeout: 0 (0.0%)
```

这是一个好迹象。让我们拿一个特定的实例来分析发生了什么。输出中的一行显示了以下变异体：

```py
 - [# 1] ROR mutation_testing_1:11 : 
------------------------------------------------------
 7: from mrstatus import MergeRequestStatus as Status
 8: 
 9: 
 10: def evaluate_merge_request(upvote_count, downvotes_count):
~11:     if downvotes_count < 0:
 12:         return Status.REJECTED
 13:     if upvote_count >= 2:
 14:         return Status.APPROVED
 15:     return Status.PENDING
------------------------------------------------------
[0.00401 s] killed by test_approved (test_mutation_testing_1.TestMergeRequestEvaluation)
```

请注意，这个变异体由原始版本和第 11 行中操作符改变（`>`改为`<`）组成，结果告诉我们这个变异体被测试杀死了。这意味着使用这个代码版本（假设有人错误地进行了这个更改），函数的结果将是`APPROVED`，而测试期望它是`REJECTED`，所以测试失败，这是一个好迹象（测试捕捉到了引入的错误）。

变异测试是确保单元测试质量的一种好方法，但它需要一些努力和仔细的分析。在复杂的环境中使用这个工具，我们将不得不花一些时间分析每个场景。同样，运行这些测试是昂贵的，因为它需要运行不同版本的代码，这可能会占用太多资源并且可能需要更长的时间来完成。然而，手动进行这些检查会更加昂贵，并且需要更多的努力。不进行这些检查可能会更加危险，因为我们会危及测试的质量。

# 测试驱动开发简介

有一些专门讲述 TDD 的书籍，所以在这本书中全面涵盖这个话题是不现实的。然而，这是一个非常重要的话题，必须提到。

TDD 的理念是在编写生产代码之前编写测试，以便生产代码只是为了响应由于功能缺失而失败的测试而编写的。

我们希望先编写测试，然后编写代码的原因有多个。从实用的角度来看，我们会相当准确地覆盖我们的生产代码。由于所有的生产代码都是为了响应单元测试而编写的，很少会有功能缺失的测试（当然这并不意味着有 100%的覆盖率，但至少所有的主要函数、方法或组件都会有各自的测试，即使它们并不完全覆盖）。

这个工作流程很简单，高层次上包括三个步骤。首先，我们编写一个描述需要实现的单元测试。当我们运行这个测试时，它会失败，因为这个功能还没有被实现。然后，我们开始实现满足条件的最小代码，并再次运行测试。这次，测试应该通过。现在，我们可以改进（重构）代码。

这个循环被称为著名的**红-绿-重构**，意思是一开始测试失败（红色），然后我们让它们通过（绿色），然后我们进行重构并迭代。

# 总结

单元测试是一个非常有趣和深刻的话题，但更重要的是，它是清晰代码的关键部分。最终，单元测试决定了代码的质量。单元测试通常作为代码的镜子——当代码易于测试时，它是清晰和正确设计的，这将反映在单元测试中。

单元测试的代码和生产代码一样重要。所有适用于生产代码的原则也适用于单元测试。这意味着它们应该以同样的努力和深思熟虑来设计和维护。如果我们不关心我们的单元测试，它们将开始出现问题并变得有缺陷（或有问题），结果就是无用的。如果发生这种情况，它们很难维护，就会成为一个负担，这会使情况变得更糟，因为人们会倾向于忽视它们或完全禁用它们。这是最糟糕的情况，因为一旦发生这种情况，整个生产代码就会受到威胁。盲目前进（没有单元测试）是一种灾难。

幸运的是，Python 提供了许多用于单元测试的工具，无论是在标准库中还是通过`pip`可用。它们非常有帮助，花时间配置它们确实会在长远来看得到回报。

我们已经看到单元测试作为程序的正式规范以及软件按照规范工作的证明，我们也了解到在发现新的测试场景时，总是有改进的空间，我们总是可以创建更多的测试。在这个意义上，用不同的方法（比如基于属性的测试或变异测试）扩展我们的单元测试是一个很好的投资。

# 参考资料

以下是您可以参考的信息列表：

+   Python 标准库的`unittest`模块包含了如何开始构建测试套件的全面文档（[`docs.python.org/3/library/unittest.html`](https://docs.python.org/3/library/unittest.html)）

+   Hypothesis 官方文档（[`hypothesis.readthedocs.io/en/latest/`](https://hypothesis.readthedocs.io/en/latest/)）

+   `pytest`官方文档（[`docs.pytest.org/en/latest/`](https://docs.pytest.org/en/latest/)）

+   《大教堂与集市：关于 Linux 和开源的思考》（*CatB*），作者 Eric S. Raymond（出版商 O'Reilly Media，1999）


# 第九章：常见的设计模式

自从它们最初出现在著名的**四人帮**（**GoF**）的书籍*《设计模式：可复用面向对象软件的元素》*中以来，设计模式一直是软件工程中的一个广泛讨论的话题。设计模式有助于解决一些常见的问题，这些问题是针对特定场景的抽象。当它们被正确实现时，解决方案的一般设计可以从中受益。

在本章中，我们将从最常见的设计模式的角度来看，但不是从在特定条件下应用工具的角度（一旦设计出模式），而是分析设计模式如何有助于编写清晰的代码。在介绍实现设计模式的解决方案后，我们将分析最终实现与选择不同路径相比是如何更好的。

在这个分析的过程中，我们将看到如何在 Python 中具体实现设计模式。由此产生的结果是，我们将看到 Python 的动态特性意味着在实现上存在一些差异，与其他静态类型的语言相比，许多设计模式最初是针对这些语言而设计的。这意味着在涉及 Python 时，设计模式有一些特殊之处，你应该记住，有些情况下，试图应用一个设计模式，而它实际上并不适用于 Python，是不符合 Python 风格的。

在本章中，我们将涵盖以下主题：

+   常见的设计模式。

+   在 Python 中不适用的设计模式，以及应该遵循的惯用替代方案。

+   在 Python 中实现最常见的设计模式的 Python 风格。

+   理解良好的抽象是如何自然地演变成模式的。

# Python 中的设计模式考虑事项

面向对象的设计模式是软件构建的想法，在解决问题模型时出现在不同的场景中。因为它们是高层次的想法，很难将它们视为与特定编程语言相关联。相反，它们更多是关于对象在应用程序中如何交互的一般概念。当然，它们会有它们的实现细节，从语言到语言会有所不同，但这并不构成设计模式的本质。

这是设计模式的理论方面，它是一个关于解决方案中对象布局的抽象概念。关于面向对象设计和设计模式的其他书籍和资源有很多，所以在本书中，我们将专注于 Python 的这些实现细节。

鉴于 Python 的特性，一些经典的设计模式实际上并不需要。这意味着 Python 已经支持了使这些模式不再需要的功能。有人认为它们在 Python 中不存在，但请记住，不可见并不意味着不存在。它们确实存在，只是嵌入在 Python 本身中，所以我们可能甚至不会注意到它们。

其他的实现方式要简单得多，这要归功于语言的动态特性，其余的实现方式在其他平台上几乎是一样的，只有细微的差异。

无论如何，在 Python 中实现清晰的代码的重要目标是知道要实现哪些模式以及如何实现。这意味着要识别 Python 已经抽象出来的一些模式以及我们如何利用它们。例如，尝试实现迭代器模式的标准定义（就像我们在其他语言中所做的那样）是完全不符合 Python 风格的，因为（正如我们已经讨论过的）迭代在 Python 中已经深深嵌入，我们可以创建的对象可以直接在`for`循环中工作，这是正确的做法。

一些创建型模式也存在类似的情况。在 Python 中，类是常规对象，函数也是。正如我们之前在几个示例中看到的那样，它们可以被传递、装饰、重新分配等。这意味着无论我们想对对象进行什么样的定制，我们很可能可以在不需要任何特定的工厂类设置的情况下完成。此外，在 Python 中没有创建对象的特殊语法（例如没有 new 关键字）。这也是为什么大多数情况下，简单的函数调用就可以作为工厂。

其他模式仍然是必需的，我们将看到如何通过一些小的调整，使它们更符合 Python 的特点，充分利用语言提供的特性（魔术方法或标准库）。

在所有可用的模式中，并非所有模式都同样频繁，也不同样有用，因此我们将专注于主要的模式，那些我们期望在我们的应用程序中最常见的模式，并且我们将通过实用的方法来做到这一点。

# 设计模式的实际应用

作为 GoF 所写的这个主题的权威参考，介绍了 23 种设计模式，每一种都属于创建型、结构型和行为型中的一种。甚至还有更多的模式或现有模式的变体，但我们不应该死记所有这些模式，而是应该专注于牢记两件事。一些模式在 Python 中是看不见的，我们可能在不知不觉中使用它们。其次，并非所有模式都同样常见；其中一些模式非常有用，因此它们经常出现，而其他模式则更适用于特定情况。

在本节中，我们将重新审视最常见的模式，这些模式最有可能从我们的设计中出现。请注意这里使用了“出现”这个词。这很重要。我们不应该强制将设计模式应用于我们正在构建的解决方案，而是应该演变、重构和改进我们的解决方案，直到出现一个模式。

因此，设计模式并非是被发明出来的，而是被发现的。当我们的代码中反复出现的情况揭示出来时，类、对象和相关组件的一般和更抽象的布局以一种名称出现，我们通过这个名称来识别一个模式。

思考同样的事情，但现在是向后看，我们意识到设计模式的名称包含了许多概念。这可能是设计模式最好的地方；它们提供了一种语言。通过设计模式，更容易有效地传达设计思想。当两个或更多的软件工程师共享相同的词汇时，其中一个提到构建器，其他人可以立即想到所有的类，它们之间的关系，它们的机制等，而无需再次重复这个解释。

读者会注意到，本章中显示的代码与所讨论的设计模式的规范或原始构想不同。这有不止一个原因。第一个原因是示例采用了更加务实的方法，旨在解决特定场景的问题，而不是探索一般的设计理论。第二个原因是这些模式是根据 Python 的特点实现的，在某些情况下可能非常微妙，但在其他情况下，差异是明显的，通常简化了代码。

# 创建型模式

在软件工程中，创建型模式处理对象实例化，试图抽象掉大部分复杂性（比如确定初始化对象的参数，可能需要的所有相关对象等），以便为用户留下一个更简单、更安全的接口。对象创建的基本形式可能导致设计问题或增加设计的复杂性。创建型设计模式通过某种方式控制对象的创建来解决这个问题。

创建对象的五种模式中，我们将主要讨论用于避免单例模式并用 Borg 模式替代的变体（在 Python 应用程序中最常用），讨论它们的区别和优势。

# 工厂

正如在介绍中提到的，Python 的一个核心特性是一切都是对象，因此它们都可以平等对待。这意味着对类、函数或自定义对象没有特殊的区分。它们都可以作为参数传递、赋值等。

正因为如此，许多工厂模式实际上并不是真正需要的。我们只需简单地定义一个函数来构造一组对象，甚至可以通过参数传递要创建的类。

# 单例和共享状态（单态）

另一方面，单例模式并不是完全被 Python 抽象化的东西。事实上，大多数情况下，这种模式要么不是真正需要的，要么是一个糟糕的选择。单例存在很多问题（毕竟，它们实际上是面向对象软件的全局变量形式，因此是一种不好的实践）。它们很难进行单元测试，它们可能随时被任何对象修改，这使得它们很难预测，它们的副作用可能会带来真正的问题。

作为一个一般原则，我们应该尽量避免使用单例。如果在某些极端情况下需要它们，Python 中最简单的实现方式是使用模块。我们可以在一个模块中创建一个对象，一旦在那里，它将从模块的每个部分中可用。Python 本身确保模块已经是单例，无论它们被导入多少次，从多少地方导入，始终是相同的模块将被加载到`sys.modules`中。

# 共享状态

与其强制设计为只创建一个实例的单例，无论对象如何被调用、构造或初始化，还不如在多个实例之间复制数据。

单态模式（SNGMONO）的想法是我们可以有许多实例，它们只是普通对象，而不必关心它们是否是单例（因为它们只是对象）。这种模式的好处是这些对象的信息将以完全透明的方式同步，而无需我们担心这是如何在内部工作的。

这使得这种模式成为一个更好的选择，不仅因为它的便利性，而且因为它更少受到单例的缺点的影响（关于它们的可测试性、创建派生类等）。

我们可以在许多级别上使用这种模式，这取决于我们需要同步多少信息。

在最简单的形式中，我们可以假设只需要一个属性在所有实例中反映。如果是这种情况，实现就像使用一个类变量一样简单，我们只需要确保提供正确的接口来更新和检索属性的值。

假设我们有一个对象，必须通过最新的“标签”从 Git 存储库中拉取代码的版本。可能会有多个此对象的实例，当每个客户端调用获取代码的方法时，此对象将使用其属性中的“标签”版本。在任何时候，此“标签”都可以更新为更新版本，我们希望任何其他实例（新创建的或已创建的）在调用“获取”操作时使用这个新分支，如下面的代码所示：

```py
class GitFetcher:
    _current_tag = None

    def __init__(self, tag):
        self.current_tag = tag

    @property
    def current_tag(self):
        if self._current_tag is None:
            raise AttributeError("tag was never set")
        return self._current_tag

    @current_tag.setter
    def current_tag(self, new_tag):
        self.__class__._current_tag = new_tag

    def pull(self):
        logger.info("pulling from %s", self.current_tag)
        return self.current_tag
```

读者只需验证创建具有不同版本的`GitFetcher`类型的多个对象将导致所有对象在任何时候都设置为最新版本，如下面的代码所示：

```py
>>> f1 = GitFetcher(0.1)
>>> f2 = GitFetcher(0.2)
>>> f1.current_tag = 0.3
>>> f2.pull()
0.3
>>> f1.pull()
0.3
```

如果我们需要更多属性，或者希望更好地封装共享属性，使设计更清晰，我们可以使用描述符。

像下面代码中所示的描述符解决了问题，虽然它需要更多的代码，但它也封装了更具体的责任，部分代码实际上从我们的原始类中移开，使它们中的任何一个更具凝聚性和符合单一责任原则：

```py
class SharedAttribute:
    def __init__(self, initial_value=None):
        self.value = initial_value
        self._name = None

    def __get__(self, instance, owner):
        if instance is None:
            return self
        if self.value is None:
            raise AttributeError(f"{self._name} was never set")
        return self.value

    def __set__(self, instance, new_value):
        self.value = new_value

    def __set_name__(self, owner, name):
        self._name = name
```

除了这些考虑因素外，模式现在更具可重用性。如果我们想重复这个逻辑，我们只需创建一个新的描述符对象，它将起作用（符合 DRY 原则）。

如果我们现在想做同样的事情，但是针对当前的分支，我们创建这个新的类属性，而类的其余部分保持不变，同时仍然具有所需的逻辑，如下面的代码所示：

```py
class GitFetcher:
    current_tag = SharedAttribute()
    current_branch = SharedAttribute()

    def __init__(self, tag, branch=None):
        self.current_tag = tag
        self.current_branch = branch

    def pull(self):
        logger.info("pulling from %s", self.current_tag)
        return self.current_tag
```

这种新方法的平衡和权衡现在应该是清楚的。这种新实现使用了更多的代码，但它是可重用的，因此从长远来看它节省了代码行数（和重复的逻辑）。再次参考三个或更多实例的规则，以决定是否应该创建这样的抽象。

这种解决方案的另一个重要好处是它还减少了单元测试的重复。在这里重用代码将使我们对解决方案的整体质量更有信心，因为现在我们只需要为描述符对象编写单元测试，而不是为使用它的所有类编写单元测试（只要单元测试证明描述符是正确的，我们就可以安全地假设它们是正确的）。

# borg 模式

前面的解决方案对大多数情况都适用，但如果我们真的必须使用单例（这必须是一个非常好的例外情况），那么还有一个更好的替代方案，尽管这是一个更有风险的选择。

这是实际的单态模式，在 Python 中被称为 borg 模式。其思想是创建一个对象，能够在同一类的所有实例之间复制其所有属性。绝对复制每个属性的事实必须警示我们要注意不良副作用。尽管如此，这种模式比单例模式有很多优点。

在这种情况下，我们将之前的对象分成两个部分——一个用于 Git 标签，另一个用于分支。我们使用的代码将使 borg 模式起作用：

```py
class BaseFetcher:
    def __init__(self, source):
        self.source = source

class TagFetcher(BaseFetcher):
    _attributes = {}

    def __init__(self, source):
        self.__dict__ = self.__class__._attributes
        super().__init__(source)

    def pull(self):
        logger.info("pulling from tag %s", self.source)
        return f"Tag = {self.source}"

class BranchFetcher(BaseFetcher):
    _attributes = {}

    def __init__(self, source):
        self.__dict__ = self.__class__._attributes
        super().__init__(source)

    def pull(self):
        logger.info("pulling from branch %s", self.source)
        return f"Branch = {self.source}"
```

这两个对象都有一个基类，共享它们的初始化方法。但是它们必须再次实现它，以使 borg 逻辑起作用。其思想是使用一个类属性，它是一个字典，用于存储属性，然后使每个对象的字典（在初始化时）使用这个完全相同的字典。这意味着对一个对象的字典的任何更新都会反映在类中，因为它们的类是相同的，而字典是可变对象，是作为引用传递的。换句话说，当我们创建这种类型的新对象时，它们都将使用相同的字典，并且这个字典会不断更新。

请注意，我们不能将字典的逻辑放在基类上，因为这将使不同类的对象混合值，这不是我们想要的。这种样板解决方案会让许多人认为这实际上是一种习惯用语，而不是一种模式。

实现 DRY 原则的一种可能的抽象方式是创建一个 mixin 类，如下面的代码所示：

```py
class SharedAllMixin:
    def __init__(self, *args, **kwargs):
        try:
            self.__class__._attributes
        except AttributeError:
            self.__class__._attributes = {}

        self.__dict__ = self.__class__._attributes
        super().__init__(*args, **kwargs)

class BaseFetcher:
    def __init__(self, source):
        self.source = source

class TagFetcher(SharedAllMixin, BaseFetcher):
    def pull(self):
        logger.info("pulling from tag %s", self.source)
        return f"Tag = {self.source}"

class BranchFetcher(SharedAllMixin, BaseFetcher):
    def pull(self):
        logger.info("pulling from branch %s", self.source)
        return f"Branch = {self.source}"
```

这一次，我们使用 mixin 类在每个类中创建具有属性的字典（如果它尚不存在），然后继续相同的逻辑。

这种实现在继承方面不应该有任何主要问题，因此这是一个更可行的替代方案。

# 建造者

建造者模式是一个有趣的模式，它抽象了对象的所有复杂初始化。这种模式不依赖于语言的任何特性，因此在 Python 中同样适用于任何其他语言。

虽然它解决了一个有效的情况，但通常也是一个更可能出现在框架、库或 API 设计中的复杂情况。与描述符的建议类似，我们应该将这种实现保留给我们期望公开的 API 将被多个用户使用的情况。

这种模式的高层思想是，我们需要创建一个复杂的对象，这个对象也需要许多其他对象一起工作。我们不希望让用户创建所有这些辅助对象，然后将它们分配给主要对象，而是希望创建一个抽象，允许所有这些在一个步骤中完成。为了实现这一点，我们将有一个构建对象，它知道如何创建所有部分并将它们链接在一起，给用户一个接口（可能是一个类方法），以参数化有关所得对象应该看起来像什么的所有信息。

# 结构模式

结构模式对于需要创建更简单的接口或通过扩展功能而使对象更强大而不增加接口复杂性的情况非常有用。

这些模式最好的地方在于我们可以创建更有趣的对象，具有增强的功能，并且可以以一种干净的方式实现这一点；也就是说，通过组合多个单一对象（这个最清晰的例子就是组合模式），或者通过收集许多简单而紧密的接口。

# 适配器

适配器模式可能是最简单的设计模式之一，同时也是最有用的设计模式之一。也被称为包装器，这种模式解决了两个或多个不兼容对象的接口适配问题。

通常情况下，我们的代码的一部分与一个模型或一组类一起工作，这些类在某个方法方面是多态的。例如，如果有多个对象用于检索具有`fetch（）`方法的数据，那么我们希望保持这个接口，这样我们就不必对我们的代码进行重大更改。

但是，当我们需要添加一个新的数据源时，这个数据源却没有`fetch（）`方法。更糟糕的是，这种类型的对象不仅不兼容，而且也不是我们控制的（也许是另一个团队决定了 API，我们无法修改代码）。

我们不直接使用这个对象，而是将其接口采用到我们需要的接口上。有两种方法可以做到这一点。

第一种方法是创建一个从我们想要使用的类继承的类，并为该方法创建一个别名（如果需要，还必须调整参数和签名）。

通过继承，我们导入外部类并创建一个新类，该类将定义新方法，调用具有不同名称的方法。在这个例子中，假设外部依赖项有一个名为`search（）`的方法，它只接受一个参数进行搜索，因为它以不同的方式查询，所以我们的`adapter`方法不仅调用外部方法，而且还相应地转换参数，如下面的代码所示：

```py
from _adapter_base import UsernameLookup

class UserSource(UsernameLookup):
    def fetch(self, user_id, username):
        user_namespace = self._adapt_arguments(user_id, username)
        return self.search(user_namespace)

    @staticmethod
    def _adapt_arguments(user_id, username):
        return f"{user_id}:{username}"
```

也许我们的类已经从另一个类派生出来了，在这种情况下，这将成为多重继承的情况，Python 支持这一点，所以这不应该是一个问题。然而，正如我们以前多次看到的那样，继承会带来更多的耦合（谁知道有多少其他方法是从外部库中继承而来的？），而且它是不灵活的。从概念上讲，这也不是正确的选择，因为我们将继承保留给规范的情况（一种**是一个**的关系），在这种情况下，我们完全不清楚我们的对象是否必须是第三方库提供的那种对象之一（特别是因为我们并不完全理解那个对象）。

因此，更好的方法是使用组合。假设我们可以为我们的对象提供一个`UsernameLookup`的实例，那么代码就会变得很简单，只需在采用参数之前重定向请求，如下面的代码所示：

```py
class UserSource:
    ...
    def fetch(self, user_id, username):
        user_namespace = self._adapt_arguments(user_id, username)
        return self.username_lookup.search(user_namespace)
```

如果我们需要采用多种方法，并且我们可以想出一种通用的方法来调整它们的签名，那么使用`__getattr__()`魔术方法将请求重定向到包装对象可能是值得的，但是像所有通用实现一样，我们应该小心不要给解决方案增加更多的复杂性。

# 组合

我们的程序中将有一些部分需要我们处理由其他对象组成的对象。我们有基本对象，具有明确定义的逻辑，然后我们将有其他容器对象，将一堆基本对象分组，挑战在于我们希望处理这两种对象（基本对象和容器对象）而不会注意到任何差异。

对象按树形层次结构组织，基本对象将是树的叶子，组合对象是中间节点。客户可能希望调用它们中的任何一个来获得调用的方法的结果。然而，组合对象将充当客户端；它也将传递这个请求以及它包含的所有对象，无论它们是叶子还是其他中间节点，直到它们都被处理。

想象一个在线商店的简化版本，在这个商店里我们有产品。假设我们提供了将这些产品分组的可能性，并且我们给顾客每组产品提供折扣。产品有一个价格，当顾客来付款时，就会要求这个价格。但是一组分组的产品也有一个必须计算的价格。我们将有一个代表这个包含产品的组的对象，并且将责任委托给每个特定产品询问价格（这个产品也可能是另一组产品），等等，直到没有其他东西需要计算。这个实现如下代码所示：

```py
class Product:
    def __init__(self, name, price):
        self._name = name
        self._price = price

    @property
    def price(self):
        return self._price

class ProductBundle:
    def __init__(
        self,
        name,
        perc_discount,
        *products: Iterable[Union[Product, "ProductBundle"]]
    ) -> None:
        self._name = name
        self._perc_discount = perc_discount
        self._products = products

    @property
    def price(self):
        total = sum(p.price for p in self._products)
        return total * (1 - self._perc_discount)
```

我们通过一个属性公开公共接口，并将`price`作为私有属性。`ProductBundle`类使用这个属性来计算值，并首先添加它包含的所有产品的价格。

这些对象之间唯一的差异是它们是用不同的参数创建的。为了完全兼容，我们应该尝试模仿相同的接口，然后添加额外的方法来向包中添加产品，但使用一个允许创建完整对象的接口。不需要这些额外的步骤是一个可以证明这个小差异的优势。

# 装饰器

不要将装饰器模式与我们在第五章中介绍的 Python 装饰器的概念混淆，*使用装饰器改进我们的代码*。它们有一些相似之处，但设计模式的想法是完全不同的。

这种模式允许我们动态扩展一些对象的功能，而不需要继承。这是创建更灵活对象的多重继承的一个很好的替代方案。

我们将创建一个结构，让用户定义要应用于对象的一组操作（装饰），并且我们将看到每个步骤按指定顺序进行。

以下代码示例是一个以参数形式从传递给它的参数构造字典形式的查询的对象的简化版本（例如，它可能是我们用于运行到 elasticsearch 的查询的对象，但代码省略了分散注意力的实现细节，以便专注于模式的概念）。

在其最基本的形式中，查询只返回创建时提供的数据的字典。客户端期望使用此对象的`render()`方法。

```py
class DictQuery:
    def __init__(self, **kwargs):
        self._raw_query = kwargs

    def render(self) -> dict:
        return self._raw_query
```

现在我们想通过对数据应用转换来以不同的方式呈现查询（过滤值，标准化等）。我们可以创建装饰器并将它们应用于`render`方法，但这不够灵活，如果我们想在运行时更改它们怎么办？或者如果我们只想选择其中一些，而不选择其他一些呢？

设计是创建另一个对象，具有相同的接口和通过多个步骤增强（装饰）原始结果的能力，但可以组合。这些对象被链接在一起，每个对象都会做最初应该做的事情，再加上其他一些东西。这些其他东西就是特定的装饰步骤。

由于 Python 具有鸭子类型，我们不需要创建一个新的基类，并使这些新对象成为该层次结构的一部分，以及`DictQuery`。只需创建一个具有`render()`方法的新类就足够了（再次，多态性不应该需要继承）。这个过程在下面的代码中显示：

```py
class QueryEnhancer:
    def __init__(self, query: DictQuery):
        self.decorated = query

    def render(self):
        return self.decorated.render()

class RemoveEmpty(QueryEnhancer):
    def render(self):
        original = super().render()
        return {k: v for k, v in original.items() if v}

class CaseInsensitive(QueryEnhancer):
    def render(self):
        original = super().render()
        return {k: v.lower() for k, v in original.items()}
```

`QueryEnhancer`短语具有与`DictQuery`的客户端期望的接口兼容的接口，因此它们是可互换的。这个对象被设计为接收一个装饰过的对象。它将从中获取值并将其转换，返回代码的修改版本。

如果我们想要删除所有评估为`False`的值并将它们标准化以形成我们的原始查询，我们将不得不使用以下模式：

```py
>>> original = DictQuery(key="value", empty="", none=None, upper="UPPERCASE", title="Title")
>>> new_query = CaseInsensitive(RemoveEmpty(original))
>>> original.render()
{'key': 'value', 'empty': '', 'none': None, 'upper': 'UPPERCASE', 'title': 'Title'}
>>> new_query.render()
{'key': 'value', 'upper': 'uppercase', 'title': 'title'}
```

这是一个我们也可以以不同方式实现的模式，利用 Python 的动态特性和函数是对象的事实。我们可以使用提供给基本装饰器对象（`QueryEnhancer`）的函数来实现这种模式，并将每个装饰步骤定义为一个函数，如下面的代码所示：

```py
class QueryEnhancer:
    def __init__(
        self,
        query: DictQuery,
        *decorators: Iterable[Callable[[Dict[str, str]], Dict[str, str]]]
    ) -> None:
        self._decorated = query
        self._decorators = decorators

    def render(self):
        current_result = self._decorated.render()
        for deco in self._decorators:
            current_result = deco(current_result)
        return current_result
```

就客户端而言，由于这个类通过其`render()`方法保持兼容性，因此没有改变。但在内部，这个对象的使用方式略有不同，如下面的代码所示：

```py
>>> query = DictQuery(foo="bar", empty="", none=None, upper="UPPERCASE", title="Title")
>>> QueryEnhancer(query, remove_empty, case_insensitive).render()
{'foo': 'bar', 'upper': 'uppercase', 'title': 'title'}
```

在前面的代码中，`remove_empty`和`case_insensitive`只是转换字典的常规函数。

在这个例子中，基于函数的方法似乎更容易理解。可能存在更复杂的规则，这些规则依赖于被装饰对象的数据（不仅仅是其结果），在这种情况下，可能值得采用面向对象的方法，特别是如果我们真的想要创建一个对象层次结构，其中每个类实际上代表了我们想要在设计中明确表示的某些知识。

# 外观

Facade 是一个很好的模式。它在许多情况下都很有用，当我们想要简化对象之间的交互时。该模式适用于多个对象之间存在多对多关系，并且我们希望它们进行交互。我们不是创建所有这些连接，而是在它们前面放置一个作为外观的中间对象。

门面在这个布局中充当一个中心或单一的参考点。每当一个新对象想要连接到另一个对象时，它不需要为所有可能连接到的*N*个对象拥有*N*个接口，而是只需与门面交谈，门面会相应地重定向请求。门面后面的一切对外部对象完全不透明。

除了主要和明显的好处（对象的解耦），这种模式还鼓励更简单的设计，更少的接口和更好的封装。

这是一个我们不仅可以用来改进我们领域问题的代码，还可以用来创建更好的 API 的模式。如果我们使用这种模式并提供一个单一的接口，作为我们代码的单一真相点或入口点，那么我们的用户与暴露的功能交互将会更容易。不仅如此，通过暴露一个功能并隐藏一切在接口后面，我们可以自由地改变或重构底层代码，因为只要它在门面后面，它就不会破坏向后兼容性，我们的用户也不会受到影响。

注意，使用门面的这个想法不仅仅局限于对象和类，还适用于包（在技术上，包在 Python 中也是对象，但仍然）。我们可以使用门面的这个想法来决定包的布局；即，对用户可见和可导入的内容，以及内部的内容，不应该直接导入。

当我们创建一个目录来构建一个包时，我们将`__init__.py`文件与其余文件放在一起。这是模块的根，一种门面。其余的文件定义要导出的对象，但它们不应该被客户端直接导入。`init`文件应该导入它们，然后客户端应该从那里获取它们。这样创建了一个更好的接口，因为用户只需要知道一个单一的入口点来获取对象，更重要的是，包（其余的文件）可以根据需要进行重构或重新排列，只要`init`文件上的主要 API 得到维护，这不会影响客户端。牢记这样的原则是非常重要的，以构建可维护的软件。

Python 本身就有一个例子，使用`os`模块。这个模块将操作系统的功能分组在一起，但在底层，它使用`posix`模块来处理**可移植操作系统接口**（**POSIX**）操作系统（在 Windows 平台上称为`nt`）。这个想法是，出于可移植性的原因，我们不应该直接导入`posix`模块，而应该始终导入`os`模块。这个模块要确定它被调用的平台，并公开相应的功能。

# 行为模式

行为模式旨在解决对象应该如何合作，它们应该如何通信，以及运行时它们的接口应该是什么的问题。

我们主要讨论以下行为模式：

+   责任链

+   模板方法

+   命令

+   状态

这可以通过继承静态地实现，也可以通过组合动态地实现。无论模式使用什么，我们将在接下来的例子中看到，这些模式的共同之处在于，最终的代码在某种重要的方式上更好，无论是因为它避免了重复，还是因为它创建了良好的抽象，封装了相应的行为，并解耦了我们的模型。

# 责任链

现在我们要再次审视我们的事件系统。我们想要从日志行（例如从我们的 HTTP 应用服务器转储的文本文件）中解析系统上发生的事件的信息，并以一种方便的方式提取这些信息。

在我们先前的实现中，我们实现了一个有趣的解决方案，符合开闭原则，并依赖于使用`__subclasses__()`魔术方法来发现所有可能的事件类型，并使用正确的事件处理数据，通过每个类上封装的方法解决责任。

这个解决方案对我们的目的是有效的，并且它是相当可扩展的，但正如我们将看到的，这种设计模式将带来额外的好处。

这里的想法是，我们将以稍微不同的方式创建事件。每个事件仍然具有确定是否可以处理特定日志行的逻辑，但它还将具有一个后继者。这个后继者是一个新的事件，是行中的下一个事件，它将继续处理文本行，以防第一个事件无法这样做。逻辑很简单——我们链接这些事件，每个事件都尝试处理数据。如果可以，它就返回结果。如果不能，它将把它传递给它的后继者并重复，如下所示的代码：

```py
import re

class Event:
    pattern = None

    def __init__(self, next_event=None):
        self.successor = next_event

    def process(self, logline: str):
        if self.can_process(logline):
            return self._process(logline)

        if self.successor is not None:
            return self.successor.process(logline)

    def _process(self, logline: str) -> dict:
        parsed_data = self._parse_data(logline)
        return {
            "type": self.__class__.__name__,
            "id": parsed_data["id"],
            "value": parsed_data["value"],
        }

    @classmethod
    def can_process(cls, logline: str) -> bool:
        return cls.pattern.match(logline) is not None

    @classmethod
    def _parse_data(cls, logline: str) -> dict:
        return cls.pattern.match(logline).groupdict()

class LoginEvent(Event):
    pattern = re.compile(r"(?P<id>\d+):\s+login\s+(?P<value>\S+)")

class LogoutEvent(Event):
    pattern = re.compile(r"(?P<id>\d+):\s+logout\s+(?P<value>\S+)")
```

通过这种实现，我们创建了`event`对象，并按照它们将被处理的特定顺序排列它们。由于它们都有一个`process()`方法，它们对于这个消息是多态的，所以它们被排列的顺序对于客户端来说是完全透明的，它们中的任何一个也是透明的。不仅如此，`process()`方法也具有相同的逻辑；它尝试提取信息，如果提供的数据对于处理它的对象类型是正确的，如果不是，它就继续到下一个对象。

这样，我们可以按以下方式`process`登录事件：

```py
>>> chain = LogoutEvent(LoginEvent())
>>> chain.process("567: login User")
{'type': 'LoginEvent', 'id': '567', 'value': 'User'}
```

注意`LogoutEvent`作为其后继者接收了`LoginEvent`，当它被要求处理无法处理的内容时，它会重定向到正确的对象。从字典的`type`键上可以看出，`LoginEvent`实际上是创建了该字典的对象。

这个解决方案足够灵活，并且与我们先前的解决方案共享一个有趣的特性——所有条件都是互斥的。只要没有冲突，没有数据有多个处理程序，以任何顺序处理事件都不会成为问题。

但是如果我们不能做出这样的假设呢？通过先前的实现，我们仍然可以将`__subclasses__()`调用更改为根据我们的标准制作的列表，这样也可以正常工作。如果我们希望优先顺序在运行时（例如由用户或客户端）确定呢？那将是一个缺点。

有了新的解决方案，我们可以实现这样的要求，因为我们在运行时组装链条，所以我们可以根据需要动态地操纵它。

例如，现在我们添加了一个通用类型，将登录和注销会话事件分组，如下所示的代码：

```py
class SessionEvent(Event):
    pattern = re.compile(r"(?P<id>\d+):\s+log(in|out)\s+(?P<value>\S+)")
```

如果由于某种原因，在应用程序的某个部分，我们希望在登录事件之前捕获这个，可以通过以下`chain`来实现：

```py
chain = SessionEvent(LoginEvent(LogoutEvent()))
```

通过改变顺序，我们可以，例如，说一个通用会话事件比登录事件具有更高的优先级，但不是注销事件，依此类推。

这种模式与对象一起工作的事实使它相对于我们先前的依赖于类的实现更加灵活（虽然它们在 Python 中仍然是对象，但它们并不排除一定程度的刚性）。

# 模板方法

`template`方法是一种在正确实现时产生重要好处的模式。主要是，它允许我们重用代码，而且还使我们的对象更灵活，更容易改变，同时保持多态性。

这个想法是，有一个类层次结构，定义了一些行为，比如说它的公共接口中的一个重要方法。层次结构中的所有类共享一个公共模板，并且可能只需要更改其中的某些元素。因此，这个想法是将这个通用逻辑放在父类的公共方法中，该方法将在内部调用所有其他（私有）方法，而这些方法是派生类将要修改的方法；因此，模板中的所有逻辑都被重用。

热心的读者可能已经注意到，我们在上一节中已经实现了这种模式（作为责任链示例的一部分）。请注意，从`Event`派生的类只实现了它们特定的模式。对于其余的逻辑，模板在`Event`类中。`process`事件是通用的，并依赖于两个辅助方法`can_process()`和`process()`（后者又调用`_parse_data()`）。

这些额外的方法依赖于类属性模式。因此，为了用新类型的对象扩展这个模式，我们只需要创建一个新的派生类并放置正则表达式。之后，其余的逻辑将继承这个新属性的变化。这样做可以重用大量的代码，因为处理日志行的逻辑只在父类中定义一次。

这使得设计变得灵活，因为保持多态性也很容易实现。如果我们需要一个新的事件类型，由于某种原因需要以不同的方式解析数据，我们只需要在子类中覆盖这个私有方法，兼容性将得到保持，只要它返回与原始类型相同的类型（符合 Liskov 的替换和开闭原则）。这是因为是父类调用派生类的方法。

如果我们正在设计自己的库或框架，这种模式也很有用。通过这种方式安排逻辑，我们使用户能够相当容易地改变其中一个类的行为。他们只需要创建一个子类并覆盖特定的私有方法，结果将是一个具有新行为的新对象，保证与原始对象的调用者兼容。

# 命令

命令模式为我们提供了将需要执行的操作与请求执行的时刻分开的能力。更重要的是，它还可以将客户端发出的原始请求与接收者分开，接收者可能是一个不同的对象。在本节中，我们将主要关注模式的第一个方面；我们可以将命令如何运行与它实际执行的时刻分开。

我们知道我们可以通过实现`__call__()`魔术方法来创建可调用对象，因此我们可以初始化对象，然后以后再调用它。事实上，如果这是唯一的要求，我们甚至可以通过一个嵌套函数来实现这一点，通过闭包创建另一个函数来实现延迟执行的效果。但是这种模式可以扩展到不那么容易实现的地方。

这个想法是命令在定义后也可以被修改。这意味着客户端指定要运行的命令，然后可能更改一些参数，添加更多选项等，直到最终有人决定执行这个动作。

这种情况的例子可以在与数据库交互的库中找到。例如，在`psycopg2`（一个 PostgreSQL 客户端库）中，我们建立一个连接。从这个连接中，我们得到一个游标，然后我们可以向这个游标传递要运行的 SQL 语句。当我们调用`execute`方法时，对象的内部表示会发生变化，但实际上并没有在数据库中运行任何东西。只有当我们调用`fetchall()`（或类似的方法）时，数据才会被查询并在游标中可用。

在流行的**对象关系映射 SQLAlchemy**（**ORM SQLAlchemy**）中也是如此。查询是通过几个步骤定义的，一旦我们有了`query`对象，我们仍然可以与之交互（添加或删除过滤器，更改条件，申请排序等），直到我们决定要查询的结果。在调用每个方法之后，`query`对象会改变其内部属性并返回`self`（它自己）。

这些都是类似我们想要实现的行为的示例。创建这种结构的一个非常简单的方法是拥有一个对象，该对象存储要运行的命令的参数。之后，它还必须提供与这些参数交互的方法（添加或删除过滤器等）。可选地，我们可以向该对象添加跟踪或日志记录功能，以审计已经发生的操作。最后，我们需要提供一个实际执行操作的方法。这个方法可以是`__call__()`或自定义的方法。让我们称之为`do()`。

# 状态

状态模式是软件设计中具体化的一个明显例子，使我们的领域问题的概念成为一个显式对象，而不仅仅是一个边值。

在第八章中，*单元测试和重构*，我们有一个代表合并请求的对象，并且它有一个与之关联的状态（打开、关闭等）。我们使用枚举来表示这些状态，因为在那时，它们只是保存特定状态的字符串表示的数据。如果它们需要有一些行为，或者整个合并请求需要根据其状态和转换执行一些操作，这是不够的。

我们正在向代码的一部分添加行为，一个运行时结构，这让我们必须以对象的方式思考，因为毕竟这就是对象应该做的。这就是具体化的意义——现在状态不能只是一个带有字符串的枚举；它需要是一个对象。

想象一下，我们必须向合并请求添加一些规则，比如说，当它从打开状态变为关闭状态时，所有的批准都被移除（他们将不得不重新审查代码）——当合并请求刚刚打开时，批准的数量被设置为零（无论是重新打开的还是全新的合并请求）。另一个规则可能是，当合并请求被合并时，我们希望删除源分支，当然，我们还希望禁止用户执行无效的转换（例如，关闭的合并请求不能被合并等）。

如果我们把所有这些逻辑都放在一个地方，即`MergeRequest`类中，我们最终会得到一个责任很多（设计不佳）、可能有很多方法和非常多的`if`语句的类。很难跟踪代码并理解哪一部分应该代表哪个业务规则。

最好将这些分布到更小的对象中，每个对象负责更少的责任，状态对象是一个很好的地方。我们为要表示的每种状态创建一个对象，并在它们的方法中放置与上述规则的转换逻辑。然后，`MergeRequest`对象将有一个状态协作者，而这个协作者也将了解`MergeRequest`（需要双重分派机制来在`MergeRequest`上运行适当的操作并处理转换）。

我们定义一个基本的抽象类，其中包含要实现的方法集，然后为我们要表示的每种特定`state`创建一个子类。然后，`MergeRequest`对象将所有操作委托给`state`，如下面的代码所示：

```py
class InvalidTransitionError(Exception):
    """Raised when trying to move to a target state from an unreachable 
    source
    state.
    """

class MergeRequestState(abc.ABC):
    def __init__(self, merge_request):
        self._merge_request = merge_request

    @abc.abstractmethod
    def open(self):
        ...

    @abc.abstractmethod
    def close(self):
        ...

    @abc.abstractmethod
    def merge(self):
        ...

    def __str__(self):
        return self.__class__.__name__

class Open(MergeRequestState):
    def open(self):
        self._merge_request.approvals = 0

    def close(self):
        self._merge_request.approvals = 0
        self._merge_request.state = Closed

    def merge(self):
        logger.info("merging %s", self._merge_request)
        logger.info("deleting branch %s", 
        self._merge_request.source_branch)
        self._merge_request.state = Merged

class Closed(MergeRequestState):
    def open(self):
        logger.info("reopening closed merge request %s", 
         self._merge_request)
        self._merge_request.state = Open

    def close(self):
        pass

    def merge(self):
        raise InvalidTransitionError("can't merge a closed request")

class Merged(MergeRequestState):
    def open(self):
        raise InvalidTransitionError("already merged request")

    def close(self):
        raise InvalidTransitionError("already merged request")

    def merge(self):
        pass

class MergeRequest:
    def __init__(self, source_branch: str, target_branch: str) -> None:
        self.source_branch = source_branch
        self.target_branch = target_branch
        self._state = None
        self.approvals = 0
        self.state = Open

    @property
    def state(self):
        return self._state

    @state.setter
    def state(self, new_state_cls):
        self._state = new_state_cls(self)

    def open(self):
        return self.state.open()

    def close(self):
        return self.state.close()

    def merge(self):
        return self.state.merge()

    def __str__(self):
        return f"{self.target_branch}:{self.source_branch}"
```

以下列表概述了一些关于实现细节和设计决策的澄清：

+   状态是一个属性，因此不仅是公共的，而且有一个单一的地方定义了如何为合并请求创建状态，将`self`作为参数传递。

+   抽象基类并不是严格需要的，但拥有它也有好处。首先，它使我们正在处理的对象类型更加明确。其次，它强制每个子状态实现接口的所有方法。对此有两种替代方案：

+   我们本可以不放置方法，让`AttributeError`在尝试执行无效操作时引发，但这是不正确的，也不能表达发生了什么。

+   与这一点相关的是，我们本可以只使用一个简单的基类并留下那些方法为空，但是这样做的默认行为并不清楚应该发生什么。如果子类中的某个方法应该什么都不做（如合并的情况），那么最好让空方法保持原样，并明确表示对于特定情况，不应该做任何事情，而不是强制所有对象都遵循这个逻辑。

+   `MergeRequest`和`MergeRequestState`彼此之间有链接。一旦进行转换，前一个对象将不再有额外的引用，应该被垃圾回收，因此这种关系应该始终是 1:1。在一些小而更详细的考虑中，可以使用弱引用。

以下代码显示了如何使用对象的一些示例：

```py
>>> mr = MergeRequest("develop", "master") 
>>> mr.open()
>>> mr.approvals
0
>>> mr.approvals = 3
>>> mr.close()
>>> mr.approvals
0
>>> mr.open()
INFO:log:reopening closed merge request master:develop
>>> mr.merge()
INFO:log:merging master:develop
INFO:log:deleting branch develop
>>> mr.close()
Traceback (most recent call last):
...
InvalidTransitionError: already merged request
```

状态转换的操作被委托给`MergeRequest`始终持有的`state`对象（这可以是`ABC`的任何子类）。它们都知道如何以不同的方式响应相同的消息，因此这些对象将根据每个转换采取相应的操作（删除分支、引发异常等），然后将`MergeRequest`移动到下一个状态。

由于`MergeRequest`将所有操作委托给其`state`对象，我们会发现每次需要执行的操作都是`self.state.open()`这种形式。我们能否删除一些样板代码？

我们可以通过`__getattr__()`来实现，如下面的代码所示：

```py
class MergeRequest:
    def __init__(self, source_branch: str, target_branch: str) -> None:
        self.source_branch = source_branch
        self.target_branch = target_branch
        self._state: MergeRequestState
        self.approvals = 0
        self.state = Open

    @property
    def state(self):
        return self._state

    @state.setter
    def state(self, new_state_cls):
        self._state = new_state_cls(self)

    @property
    def status(self):
        return str(self.state)

    def __getattr__(self, method):
        return getattr(self.state, method)

    def __str__(self):
        return f"{self.target_branch}:{self.source_branch}"
```

一方面，我们重用一些代码并删除重复的行是好事。这使得抽象基类更有意义。在某个地方，我们希望将所有可能的操作记录下来，列在一个地方。那个地方过去是`MergeRequest`类，但现在这些方法都消失了，所以唯一剩下的真相来源是`MergeRequestState`。幸运的是，`state`属性上的类型注解对用户来说非常有帮助，可以知道在哪里查找接口定义。

用户可以简单地查看并了解`MergeRequest`没有的所有内容都将要求其`state`属性具有。从`init`定义中，注解会告诉我们这是`MergeRequestState`类型的对象，并通过查看此接口，我们将看到我们可以安全地要求其`open()`、`close()`和`merge()`方法。

# 空对象模式

空对象模式是与本书前几章提到的良好实践相关的一个想法。在这里，我们正在正式化它们，并为这个想法提供更多的背景和分析。

原则相当简单——函数或方法必须返回一致类型的对象。如果这得到保证，那么我们代码的客户端可以使用返回的对象进行多态，而无需对它们进行额外的检查。

在之前的例子中，我们探讨了 Python 的动态特性如何使大多数设计模式变得更容易。在某些情况下，它们完全消失，在其他情况下，它们更容易实现。设计模式最初的目标是，方法或函数不应该明确命名它们需要的对象的类。因此，它们提出了创建接口和重新排列对象的方法，使它们适应这些接口以修改设计。但在 Python 中大多数情况下，这是不需要的，我们可以只传递不同的对象，只要它们遵守必须具有的方法，解决方案就会起作用。

另一方面，对象不一定要遵守接口的事实要求我们更加小心，以确保从这些方法和函数返回的东西。就像我们的函数没有对它们接收到的东西做出任何假设一样，可以合理地假设我们代码的客户也不会做出任何假设（我们有责任提供兼容的对象）。这可以通过契约式设计来强制执行或验证。在这里，我们将探讨一种简单的模式，可以帮助我们避免这些问题。

考虑在前一节中探讨的责任链设计模式。我们看到了它有多么灵活以及它的许多优点，比如将责任解耦为更小的对象。它存在的问题之一是，我们实际上永远不知道哪个对象最终会处理消息，如果有的话。特别是在我们的例子中，如果没有合适的对象来处理日志行，那么该方法将简单地返回`None`。

我们不知道用户将如何使用我们传递的数据，但我们知道他们期望得到一个字典。因此，可能会发生以下错误：

```py
AttributeError: 'NoneType' object has no attribute 'keys'
```

在这种情况下，修复方法相当简单——`process()`方法的默认值应该是一个空字典，而不是`None`。

确保返回一致类型的对象。

但是，如果该方法没有返回字典，而是我们领域的自定义对象呢？

为了解决这个问题，我们应该有一个代表该对象的空状态的类并返回它。如果我们有一个代表系统中用户的类，并且有一个按 ID 查询用户的函数，那么在找不到用户的情况下，它应该执行以下两种操作之一：

+   引发异常

+   返回一个`UserUnknown`类型的对象

但在任何情况下，它都不应该返回`None`。短语`None`并不代表刚刚发生的事情，调用者可能会合理地尝试向其请求方法，但会因为`AttributeError`而失败。

我们之前讨论过异常及其利弊，所以我们应该提到这个`null`对象应该只有与原始用户相同的方法，并对每个方法都不做任何操作。

使用这种结构的优势不仅在于我们在运行时避免了错误，而且这个对象可能是有用的。它可以使代码更容易测试，甚至可以帮助调试（也许我们可以在方法中放置日志以了解为什么达到了这种状态，提供了什么数据等）。

通过利用 Python 的几乎所有魔术方法，可以创建一个绝对什么都不做的通用`null`对象，无论如何调用它，但几乎可以从任何客户端调用。这样的对象略微类似于`Mock`对象。不建议走这条路，因为有以下原因：

+   它失去了与领域问题的意义。回到我们的例子中，拥有`UnknownUser`类型的对象是有意义的，并且让调用者清楚地知道查询出了问题。

+   它不尊重原始接口。这是有问题的。请记住，`UnknownUser`是一个用户，因此它必须具有相同的方法。如果调用者意外地要求不存在的方法，那么在这种情况下，它应该引发`AttributeError`异常，这是好的。使用通用的`null`对象，它可以做任何事情并对任何事情做出响应，我们将丢失这些信息，可能会引入错误。如果我们选择创建一个带有`spec=User`的`Mock`对象，那么这种异常将被捕获，但再次使用`Mock`对象来表示实际上是一个空状态的东西会损害代码的意图。

这种模式是一个很好的实践，它允许我们在对象中保持多态性。

# 关于设计模式的最终想法

我们已经在 Python 中看到了设计模式的世界，并且在这样做时，我们找到了解决常见问题的解决方案，以及更多的技术，这些技术将帮助我们实现一个清晰的设计。

这些听起来都不错，但问题是，设计模式有多好呢？有人认为它们弊大于利，认为它们是为了那些类型系统有限（和缺乏一流函数）的语言而创建的，这些语言无法完成我们通常在 Python 中完成的事情。还有人声称设计模式强制了设计解决方案，产生了一些限制本来会出现的设计的偏见，而且本来会更好。让我们依次看看这些观点。

# 设计对设计的影响

设计模式，就像软件工程中的任何其他主题一样，本身并不是好坏之分，而是取决于它的实现方式。在某些情况下，实际上并不需要设计模式，一个更简单的解决方案就可以。试图在不适合的地方强行使用模式是一种过度设计的情况，这显然是不好的，但这并不意味着设计模式有问题，而且在这些情况下，问题很可能根本与模式无关。有些人试图过度设计一切，因为他们不理解灵活和适应性软件的真正含义。正如我们在本书中之前提到的，制作好的软件并不是关于预测未来的需求（进行未来学是没有意义的），而只是解决我们目前手头的问题，以一种不会阻止我们在将来对其进行更改的方式。它不必现在就处理这些变化；它只需要足够灵活，以便将来可以进行修改。当未来到来时，我们仍然必须记住三个或更多相同问题的实例才能提出通用解决方案或适当的抽象。

这通常是设计模式应该出现的时候，一旦我们正确识别了问题并能够识别模式并相应地抽象出来。

让我们回到模式与语言适应性的话题。正如我们在本章的介绍中所说，设计模式是高层次的想法。它们通常指的是对象及其相互作用的关系。很难想象这些东西会从一种语言消失到另一种语言。有些模式实际上是在 Python 中手动实现的，比如迭代器模式（正如本书前面大量讨论的那样，在 Python 中内置了迭代器模式），或者策略（因为我们可以像传递其他常规对象一样传递函数；我们不需要将策略方法封装到一个对象中，函数本身就是一个对象）。

但其他模式实际上是需要的，它们确实解决了问题，比如装饰器和组合模式。在其他情况下，Python 本身实现了设计模式，我们并不总是看到它们，就像我们在`os`部分讨论的外观模式一样。

至于我们的设计模式是否会导致我们的解决方案走向错误方向，我们在这里必须小心。再次强调，最好的做法是从领域问题的角度开始设计解决方案，创建正确的抽象，然后再看是否有设计模式从该设计中出现。假设确实有。那是一件坏事吗？已经有一个解决我们正在尝试解决的问题的解决方案这个事实不能是一件坏事。重复造轮子是坏事，这在我们的领域中经常发生。此外，应用一种已经被证明和验证的模式，应该让我们对我们正在构建的东西的质量更有信心。

# 我们模型中的名称

我们在代码中是否应该提到我们正在使用设计模式？

如果设计良好，代码干净，它应该自说明。不建议您根据您使用的设计模式来命名事物，原因有几个：

+   我们代码的用户和其他开发人员不需要知道代码背后的设计模式，只要它按预期工作即可。

+   说明设计模式会破坏意图揭示原则。在类名中添加设计模式的名称会使其失去部分原始含义。如果一个类代表一个查询，它应该被命名为`Query`或`EnhancedQuery`，以显示该对象应该执行的意图。 `EnhancedQueryDecorator`没有任何有意义的含义，`Decorator`后缀会带来更多混乱而不是清晰。

在文档字符串中提到设计模式可能是可以接受的，因为它们作为文档，并且在我们的设计中表达设计思想（再次交流）是一件好事。然而，这并不是必要的。大多数情况下，我们不需要知道设计模式在那里。

最好的设计是那些设计模式对用户完全透明的设计。一个例子是外观模式如何出现在标准库中，使用户完全透明地访问`os`模块。更优雅的例子是迭代器设计模式如何被语言完全抽象化，以至于我们甚至不必考虑它。

# 总结

设计模式一直被视为常见问题的成熟解决方案。这是一个正确的评估，但在本章中，我们从良好设计技术的角度探讨了它们，这些模式利用了干净的代码。在大多数情况下，我们看到它们如何提供了保留多态性、减少耦合和创建正确的抽象以封装所需细节的良好解决方案。所有这些特征都与第八章中探讨的概念相关，即“单元测试和重构”。

然而，设计模式最好的地方不是我们可以从应用它们中获得的干净设计，而是扩展的词汇。作为一种交流工具，我们可以使用它们的名称来表达我们设计的意图。有时，我们不需要应用整个模式，而是可能需要从我们的解决方案中采用特定的想法（例如子结构），在这里，它们也被证明是更有效地交流的一种方式。

当我们通过模式思考解决问题时，我们是在更一般的层面上解决问题。以设计模式思考，使我们更接近更高级别的设计。我们可以慢慢“放大”并更多地考虑架构。现在我们正在解决更一般的问题，是时候开始考虑系统如何在长期内发展和维护（如何扩展、改变、适应等）。

要使软件项目在这些目标中取得成功，它需要以干净的代码为核心，但架构也必须是干净的，这是我们将在下一章中讨论的内容。

# 参考资料

这里是一些你可以参考的信息列表：

+   *GoF*：由 Erich Gamma、Richard Helm、Ralph Johnson 和 John Vlissides 撰写的书籍，名为*设计模式：可复用面向对象软件的元素*

+   *SNGMONO*：一篇由 Robert C. Martin 于 2002 年撰写的文章，名为*SINGLETON and MONOSTATE*

+   《空对象模式》，作者 Bobby Woolf
