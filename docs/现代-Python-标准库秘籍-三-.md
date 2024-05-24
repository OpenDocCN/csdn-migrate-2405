# 现代 Python 标准库秘籍（三）

> 原文：[`zh.annas-archive.org/md5/3fab99a8deba9438823e5414cd05b6e8`](https://zh.annas-archive.org/md5/3fab99a8deba9438823e5414cd05b6e8)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：算法

在本章中，我们将涵盖以下配方：

+   搜索、排序、过滤-在排序的容器中进行高性能搜索

+   获取任何可迭代对象的第 n 个元素-抓取任何可迭代对象的第 n 个元素，包括生成器

+   分组相似项目-将可迭代对象分成相似项目的组

+   合并-将来自多个可迭代对象的数据合并成单个可迭代对象

+   展平列表的列表-将列表的列表转换为平面列表

+   生成排列和-计算一组元素的所有可能排列

+   累积和减少-将二进制函数应用于可迭代对象

+   记忆-通过缓存函数加速计算

+   从运算符到函数-如何保留对 Python 运算符的可调用引用

+   部分-通过预应用一些函数来减少函数的参数数量

+   通用函数-能够根据提供的参数类型改变行为的函数

+   适当的装饰-适当地装饰函数以避免丢失其签名和文档字符串

+   上下文管理器-在进入和退出代码块时自动运行代码

+   应用可变上下文管理器-如何应用可变数量的上下文管理器

# 介绍

在编写软件时，有很多事情你会发现自己一遍又一遍地做，与你正在编写的应用程序类型无关。

除了您可能需要在不同应用程序中重用的整个功能（例如登录、日志记录和授权）之外，还有一堆可以在任何类型的软件中重用的小构建块。

本章将尝试收集一堆可以用作可重用片段的配方，以实现您可能需要独立于软件目的执行的非常常见的操作。

# 搜索、排序、过滤

在编程中查找元素是一个非常常见的需求。在容器中查找项目基本上是您的代码可能会执行的最频繁的操作，因此它非常重要，它既快速又可靠。

排序经常与搜索相关联，因为当你知道你的集合是排序的时，往往可以使用更智能的查找解决方案，并且排序意味着不断搜索和移动项目，直到它们按排序顺序排列。所以它们经常一起出现。

Python 具有内置函数，可以对任何类型的容器进行排序并在其中查找项目，甚至可以利用排序序列的函数。

# 如何做...

对于这个配方，需要执行以下步骤：

1.  取以下一组元素：

```py
>>> values = [ 5, 3, 1, 7 ]
```

1.  通过`in`运算符可以在序列中查找元素：

```py
>>> 5 in values
True
```

1.  排序可以通过`sorted`函数完成：

```py
>>> sorted_value = sorted(values)
>>> sorted_values
[ 1, 3, 5, 7 ]
```

1.  一旦我们有了一个排序的容器，我们实际上可以使用`bisect`模块更快地找到包含的条目：

```py
def bisect_search(container, value):
    index = bisect.bisect_left(container, value)
    return index < len(container) and container[index] == value
```

1.  `bisect_search`可以用来知道一个条目是否在列表中，就像`in`运算符一样：

```py
>>> bisect_search(sorted_values, 5)
True
```

1.  但是，优点是对于许多排序的条目来说可能会更快：

```py
>>> import timeit
>>> values = list(range(1000))
>>> 900 in values
True
>>> bisect_search(values, 900)
True
>>> timeit.timeit(lambda: 900 in values)
timeit.timeit(lambda: bisect_search(values, 900))
13.61617108999053
>>> timeit.timeit(lambda: bisect_search(values, 900))
0.872136551013682
```

因此，在我们的示例中，`bisect_search`函数比普通查找快 17 倍。

# 它是如何工作的...

`bisect`模块使用二分搜索来查找已排序容器中元素的插入点。

如果元素存在于数组中，它的插入位置正是元素所在的位置（因为它应该正好在它所在的位置）：

```py
>>> values = [ 1, 3, 5, 7 ]
>>> bisect.bisect_left(values, 5)
2
```

如果元素缺失，它将返回下一个立即更大的元素的位置：

```py
>>> bisect.bisect_left(values, 4)
2
```

这意味着我们将获得一个位置，即使对于不存在于我们的容器中的元素。这就是为什么我们将返回的位置处的元素与我们正在寻找的元素进行比较。如果两者不同，这意味着返回了最近的元素，因此元素本身没有找到。

出于同样的原因，如果未找到元素并且它大于容器中包含的最大值，则返回容器本身的长度（因为元素应该放在最后），因此我们还需要确保`index < len(container)`来检查不在容器中的元素。

# 还有更多...

到目前为止，我们只对条目本身进行了排序和查找，但在许多情况下，您将拥有复杂的对象，您有兴趣对对象的特定属性进行排序和搜索。

例如，您可能有一个人员列表，您想按其姓名排序：

```py
class Person:
    def __init__(self, name, surname):
        self.name = name
        self.surname = surname
    def __repr__(self):
        return '<Person: %s %s>' % (self.name, self.surname)

people = [Person('Derek', 'Zoolander'),
          Person('Alex', 'Zanardi'),
          Person('Vito', 'Corleone')
          Person('Mario', 'Rossi')]
```

通过依赖`sorted`函数的`key`参数，可以对这些人按姓名进行排序，该参数指定应返回应对条目进行排序的值的可调用对象：

```py
>>> sorted_people = sorted(people, key=lambda v: v.name)
[<Person: Alex Zanardi>, <Person: Derek Zoolander>, 
 <Person: Mario Rossi>, <Person: Vito Corleone>]
```

通过`key`函数进行排序比通过比较函数进行排序要快得多。因为`key`函数只需要对每个项目调用一次（然后结果被保留），而`comparison`函数需要在每次需要比较两个项目时一遍又一遍地调用。因此，如果计算我们应该排序的值很昂贵，`key`函数方法可以实现显着的性能改进。

现在的问题是，`bisect`不允许我们提供一个键，因此为了能够在 people 列表上使用`bisect`，我们首先需要构建一个`keys`列表，然后我们可以应用`bisect`：

```py
>>> keys = [p.name for p in people]
>>> bisect_search(keys, 'Alex')
True
```

这需要通过列表进行一次额外的传递来构建`keys`列表，因此只有在您必须查找多个条目（或多次查找相同的条目）时才方便，否则在列表上进行线性搜索将更快。

请注意，即使要使用`in`运算符，您也必须构建`keys`列表。因此，如果要搜索一个属性而不构建一个特定的列表，您将不得不依赖于`filter`或列表推导。

# 获取任何可迭代对象的第 n 个元素

随机访问容器是我们经常做的事情，而且没有太多问题。对于大多数容器类型来说，这甚至是一个非常便宜的操作。另一方面，当使用通用可迭代对象和生成器时，情况并不像我们期望的那样简单，通常最终会导致我们将它们转换为列表或丑陋的`for`循环。

Python 标准库实际上有办法使这变得非常简单。

# 如何做...

`itertools`模块是一个宝库，当处理可迭代对象时具有非常有价值的功能，并且只需很少的努力就可以获得任何可迭代对象的第 n 个项目：

```py
import itertools

def iter_nth(iterable, nth):
    return next(itertools.islice(iterable, nth, nth+1))
```

给定一个随机的可迭代对象，我们可以使用它来获取我们想要的元素：

```py
>>> values = (x for x in range(10))
>>> iter_nth(values, 4)
4
```

# 它是如何工作的...

`itertools.islice`函数能够获取任何可迭代对象的切片。在我们的特定情况下，我们需要的是从我们要查找的元素到下一个元素的切片。

一旦我们有了包含我们要查找的元素的切片，我们就需要从切片本身中提取该项。

由于`islice`作用于可迭代对象，它本身返回一个可迭代对象。这意味着我们可以使用`next`来消耗它，由于我们要查找的项实际上是切片的第一个项，因此使用`next`将正确返回我们要查找的项。

如果元素超出范围（例如，我们在仅有三个元素的情况下寻找第四个元素），则会引发`StopIteration`错误，我们可以像在普通列表中一样捕获它，就像对`IndexError`一样。

# 分组相似的项目

有时，您可能会面对一个具有多个重复条目的条目列表，并且您可能希望根据某种属性对相似的条目进行分组。

例如，这里是一个名字列表：

```py
names = [('Alex', 'Zanardi'),
         ('Julius', 'Caesar'),
         ('Anakin', 'Skywalker'),
         ('Joseph', 'Joestar')]
```

我们可能希望构建一个所有名字以相同字符开头的人的组，这样我们就可以按字母顺序保留我们的电话簿，而不是让名字随机散落在这里和那里。

# 如何做...

`itertools`模块再次是一个非常强大的工具，它为我们提供了处理可迭代对象所需的基础：

```py
import itertools

def group_by_key(iterable, key):
    iterable = sorted(iterable, key=key)
    return {k: list(g) for k,g in itertools.groupby(iterable, key)}
```

给定我们的姓名列表，我们可以应用一个键函数，该函数获取名称的第一个字符，以便所有条目都将按其分组：

```py
>>> group_by_key(names, lambda v: v[0][0])
{'A': [('Alex', 'Zanardi'), ('Anakin', 'Skywalker')], 
 'J': [('Julius', 'Caesar'), ('Joseph', 'Joestar')]}
```

# 它是如何工作的...

这里的函数核心由`itertools.groupby`提供。

此函数将迭代器向前移动，抓取项目，并将其添加到当前组中。当面对具有不同键的项目时，将创建一个新组。

因此，实际上，它只会将共享相同键的附近条目分组：

```py
>>> sample = [1, 2, 1, 1]
>>> [(k, list(g)) for k,g in itertools.groupby(sample)]
[(1, [1]), (2, [2]), (1, [1, 1])]
```

正如您所看到的，这里有三个组，而不是预期的两个，因为数字`1`的第一组立即被数字`2`中断，因此我们最终得到了两个不同的`1`组。

我们在对它们进行分组之前对元素进行排序，原因是排序可以确保相等的元素都靠在一起：

```py
>>> sorted(sample)
[1, 1, 1, 2]
```

在那一点上，分组函数将创建正确数量的组，因为每个等效元素都有一个单独的块：

```py
>>> sorted_sample = sorted(sample)
>>> [(k, list(g)) for k,g in itertools.groupby(sorted_sample)]
[(1, [1, 1, 1]), (2, [2])]
```

我们在现实生活中经常使用复杂的对象，因此`group_by_key`函数还接受`key`函数。这将说明应该根据哪个键对元素进行分组。

由于排序在排序时接受一个键函数，因此我们知道在分组之前所有元素都将根据该键进行排序，因此我们将返回正确数量的组。

最后，由于`groupby`返回一个迭代器或迭代器（顶级可迭代对象中的每个组也是一个迭代器），我们将每个组转换为列表，并构建一个字典，以便可以通过`key`轻松访问这些组。

# 压缩

Zipping 意味着附加两个不同的可迭代对象，以创建一个包含两者值的新对象。

当您有多个值轨道应该同时进行时，这是非常方便的。想象一下，您有名字和姓氏，您只想得到一个人的列表：

```py
names = [ 'Sam', 'Axel', 'Aerith' ]
surnames = [ 'Fisher', 'Foley', 'Gainsborough' ]
```

# 如何做到这一点...

我们想要将名称和姓氏一起压缩：

```py
>>> people = zip(names, surnames)
>>> list(people)
[('Sam', 'Fisher'), ('Axel', 'Foley'), ('Aerith', 'Gainsborough')]
```

# 它是如何工作的...

Zip 将创建一个新的可迭代对象，其中新创建的可迭代对象中的每个项目都是通过从所提供的可迭代对象中选择一个项目而生成的集合。

因此，`result[0] = (i[0], j[0])`，`result[1] = (i[1], j[1])`，依此类推。如果`i`和`j`的长度不同，它将在两者之一耗尽时立即停止。

如果要继续直到耗尽所提供的可迭代对象中最长的一个，而不是在最短的一个上停止，可以依靠`itertools.zip_longest`。已经耗尽的可迭代对象的值将填充默认值。

# 展平列表的列表

当您有多个嵌套列表时，通常需要遍历所有列表中包含的项目，而不太关心它们实际存储的深度。

假设您有这个列表：

```py
values = [['a', 'b', 'c'],
          [1, 2, 3],
          ['X', 'Y', 'Z']]
```

如果您只想抓取其中的所有项目，那么您真的不想遍历列表中的列表，然后再遍历其中每一个项目。我们只想要叶子项目，我们根本不在乎它们在列表中的列表中。

# 如何做到这一点...

我们想要做的就是将所有列表连接成一个可迭代对象，该对象将产生项目本身，因为我们正在谈论迭代器，`itertools`模块具有正确的函数，可以让我们像单个迭代器一样链接所有列表：

```py
>>> import itertools
>>> chained = itertools.chain.from_iterable(values)
```

生成的`chained`迭代器将在消耗时逐个产生底层项目：

```py
>>> list(chained)
['a', 'b', 'c', 1, 2, 3, 'X', 'Y', 'Z']
```

# 它是如何工作的...

`itertools.chain`函数在您需要依次消耗多个可迭代对象时非常方便。

默认情况下，它接受这些可迭代对象作为参数，因此我们将不得不执行：

```py
itertools.chain(values[0], values[1], values[2])
```

但是，为了方便起见，`itertools.chain.from_iterable`将链接提供的参数中包含的条目，而不必逐个显式传递它们。

# 还有更多...

如果您知道原始列表包含多少项，并且它们的大小相同，那么很容易应用反向操作。

我们已经知道可以使用`zip`从多个来源合并条目，所以我们实际上想要做的是将原始列表的元素一起压缩，这样我们就可以从`chained`返回到原始的列表列表：

```py
>>> list(zip(chained, chained, chained))
[('a', 'b', 'c'), (1, 2, 3), ('X', 'Y', 'Z')]
```

在这种情况下，我们有三个项目列表，所以我们必须提供`chained`三次。

这是因为`zip`将顺序地从每个提供的参数中消耗一个条目。 因此，由于我们提供了相同的参数三次，实际上我们正在消耗前三个条目，然后是接下来的三个，然后是最后的三个。

如果`chained`是一个列表而不是一个迭代器，我们将不得不从列表中创建一个迭代器：

```py
>>> chained = list(chained) 
>>> chained ['a', 'b', 'c', 1, 2, 3, 'X', 'Y', 'Z'] 
>>> ichained = iter(chained) 
>>> list(zip(ichained, ichained, ichained)) [('a', 'b', 'c'), (1, 2, 3), ('X', 'Y', 'Z')]
```

如果我们没有使用`ichained`而是使用原始的`chained`，结果将与我们想要的相去甚远：

```py
>>> chained = list(chained)
>>> chained
['a', 'b', 'c', 1, 2, 3, 'X', 'Y', 'Z']
>>> list(zip(chained, chained, chained))
[('a', 'a', 'a'), ('b', 'b', 'b'), ('c', 'c', 'c'), 
 (1, 1, 1), (2, 2, 2), (3, 3, 3), 
 ('X', 'X', 'X'), ('Y', 'Y', 'Y'), ('Z', 'Z', 'Z')]
```

# 生成排列和组合

给定一组元素，如果您曾经感到有必要对这些元素的每个可能的排列执行某些操作，您可能会想知道生成所有这些排列的最佳方法是什么。

Python 在`itertools`模块中有各种函数，可帮助进行排列和组合，这些之间的区别并不总是容易理解，但一旦您调查它们的功能，它们就会变得清晰。

# 如何做...

笛卡尔积通常是在谈论组合和排列时人们所考虑的。

1.  给定一组元素`A`，`B`和`C`，我们想要提取所有可能的两个元素的组合，`AA`，`AB`，`AC`等等：

```py
>>> import itertools
>>> c = itertools.product(('A', 'B', 'C'), repeat=2)
>>> list(c)
[('A', 'A'), ('A', 'B'), ('A', 'C'),
 ('B', 'A'), ('B', 'B'), ('B', 'C'), 
 ('C', 'A'), ('C', 'B'), ('C', 'C')]
```

1.  如果您想要省略重复的条目（`AA`，`BB`，`CC`），您可以只使用排列：

```py
>>> c = itertools.permutations(('A', 'B', 'C'), 2)
>>> list(c)
[('A', 'B'), ('A', 'C'), 
 ('B', 'A'), ('B', 'C'), 
 ('C', 'A'), ('C', 'B')]
```

1.  您甚至可能希望确保相同的夫妇不会发生两次（例如`AB`与`BA`），在这种情况下，`itertools.combinations`可能是您要寻找的。

```py
>>> c = itertools.combinations(('A', 'B', 'C'), 2)
>>> list(c)
[('A', 'B'), ('A', 'C'), ('B', 'C')]
```

因此，大多数需要组合值的需求都可以通过`itertools`模块提供的函数轻松解决。

# 累积和减少

列表推导和`map`是非常方便的工具，当您需要将函数应用于可迭代对象的所有元素并返回结果值时。 但这些工具大多用于应用一元函数并保留转换值的集合（例如将所有数字加`1`），但是如果您想要应用应该一次接收多个元素的函数，它们就不太合适。

减少和累积函数实际上是为了从可迭代对象中接收多个值并返回单个值（在减少的情况下）或多个值（在累积的情况下）。

# 如何做...

这个食谱的步骤如下：

1.  减少的最简单的例子是对可迭代对象中的所有项目求和：

```py
>>> values = [ 1, 2, 3, 4, 5 ]
```

1.  这是可以通过`sum`轻松完成的事情，但是为了这个例子，我们将使用`reduce`：

```py
>>> import functools, operator
>>> functools.reduce(operator.add, values)
15
```

1.  如果您不是要获得单个最终结果，而是要保留中间步骤的结果，您可以使用`accumulate`：

```py
>>> import itertools
>>> list(itertools.accumulate(values, operator.add))
[1, 3, 6, 10, 15]
```

# 还有更多...

`accumulate`和`reduce`不仅限于数学用途。 虽然这些是最明显的例子，但它们是非常灵活的函数，它们的目的取决于它们将应用的函数。

例如，如果您有多行文本，您也可以使用`reduce`来计算所有文本的总和：

```py
>>> lines = ['this is the first line',
...          'then there is one more',
...          'and finally the last one.']
>>> functools.reduce(lambda x, y: x + len(y), [0] + lines)
69
```

或者，如果您有多个需要折叠的字典：

```py
>>> dicts = [dict(name='Alessandro'), dict(surname='Molina'),
...          dict(country='Italy')]
>>> functools.reduce(lambda d1, d2: {**d1, **d2}, dicts)
{'name': 'Alessandro', 'surname': 'Molina', 'country': 'Italy'}
```

这甚至是访问深度嵌套的字典的一种非常方便的方法：

```py
>>> import operator
>>> nesty = {'a': {'b': {'c': {'d': {'e': {'f': 'OK'}}}}}}
>>> functools.reduce(operator.getitem, 'abcdef', nesty)
'OK'
```

# 记忆化

一遍又一遍地运行函数，避免调用该函数的成本可以大大加快生成的代码。

想象一下`for`循环或递归函数，也许必须调用该函数数十次。 如果它能够保留对函数的先前调用的已知结果，而不是调用它，那么它可以大大加快代码。

最常见的例子是斐波那契数列。 该序列是通过添加前两个数字来计算的，然后将第二个数字添加到结果中，依此类推。

这意味着在序列`1`，`1`，`2`，`3`，`5`中，计算`5`需要我们计算`3 + 2`，这又需要我们计算`2 + 1`，这又需要我们计算`1 + 1`。

以递归方式进行斐波那契数列是最明显的方法，因为它导致`5 = fib(n3) + fib(n2)`，其中`3 = fib(n2) + fib(n1)`，所以你可以很容易地看到我们必须计算`fib(n2)`两次。记忆`fib(n2)`的结果将允许我们只执行这样的计算一次，然后在下一次调用时重用结果。

# 如何做...

这是这个食谱的步骤：

1.  Python 提供了内置的 LRU 缓存，我们可以用它来进行记忆化：

```py
import functools

@functools.lru_cache(maxsize=None)
def fibonacci(n):
    '''inefficient recursive version of Fibonacci number'''
    if n > 1:
        return fibonacci(n-1) + fibonacci(n-2)
    return n
```

1.  然后我们可以使用该函数来计算整个序列：

```py
fibonacci_seq = [fibonacci(n) for n in range(100)]
```

1.  结果将是一个包含所有斐波那契数的列表，直到第 100 个：

```py
>>> print(fibonacci_seq)
[0, 1, 1, 2, 3, 5, 8, 13, 21 ...
```

性能上的差异是巨大的。如果我们使用`timeit`模块来计时我们的函数，我们可以很容易地看到记忆化对性能有多大帮助。

1.  当使用`fibonacci`函数的记忆化版本时，计算在不到一毫秒内结束：

```py
>>> import timeit
>>> timeit.timeit(lambda: [fibonacci(n) for n in range(40)], number=1)
0.000033469987101
```

1.  然后，如果我们移除`@functools.lru_cache()`，实现记忆化的时间会发生根本性的变化：

```py
>>> timeit.timeit(lambda: [fibonacci(n) for n in range(40)], number=1)
89.14927123498637
```

所以很容易看出记忆化如何将性能从 89 秒提高到几分之一秒。

# 它是如何工作的...

每当调用函数时，`functools.lru_cache`都会保存返回的值以及提供的参数。

下一次调用函数时，参数将在保存的参数中搜索，如果找到，将提供先前返回的值，而不是调用函数。

实际上，这改变了调用我们的函数的成本，只是在字典中查找的成本。

所以第一次调用`fibonacci(5)`时，它被计算，然后下一次调用时它将什么都不做，之前存储的`5`的值将被返回。由于`fibonacci(6)`必须调用`fibonacci(5)`才能计算，很容易看出我们为任何`fibonacci(n)`提供了主要的性能优势，其中`n>5`。

同样，由于我们想要整个序列，所以节省不仅仅是单个调用，而是在第一个需要记忆值的列表推导式之后的每次调用。

`lru_cache`函数诞生于**最近最少使用**（**LRU**）缓存，因此默认情况下，它只保留最近的`128`个，但通过传递`maxsize=None`，我们可以将其用作标准缓存，并丢弃其中的 LRU 部分。所有调用将永远被缓存，没有限制。

纯粹针对斐波那契情况，你会注意到将`maxsize`设置为大于`3`的任何值都不会改变，因为每个斐波那契数只需要前两个调用就能计算。

# 函数到运算符

假设你想创建一个简单的计算器。第一步是解析用户将要写的公式以便执行它。基本公式由一个运算符和两个操作数组成，所以你实际上有一个函数和它的参数。

但是，考虑到`+`，`-`等等，我们的解析器如何返回相关的函数呢？通常，为了对两个数字求和，我们只需写`n1 + n2`，但我们不能传递`+`本身来调用任何`n1`和`n2`。

这是因为`+`是一个运算符而不是一个函数，但在 CPython 中它仍然只是一个函数被执行。

# 如何做...

我们可以使用`operator`模块来获取一个可调用的对象，表示我们可以存储或传递的任何 Python 运算符：

```py
import operator

operators = {
    '+': operator.add,
    '-': operator.sub,
    '*': operator.mul,
    '/': operator.truediv
}

def calculate(expression):
    parts = expression.split()

    try:
        result = int(parts[0])
    except:
        raise ValueError('First argument of expression must be numberic')

    operator = None
    for part in parts[1:]:
        try:
            num = int(part)
            if operator is None:
                raise ValueError('No operator proviede for the numbers')
        except ValueError:
            if operator:
                raise ValueError('operator already provided')
            operator = operators[part]
        else:
            result = operator(result, num)
            operator = None

    return result
```

我们的`calculate`函数充当一个非常基本的计算器（没有运算符优先级，实数，负数等）：

```py
>>> print(calculate('5 + 3'))
8
>>> print(calculate('1 + 2 + 3'))
6
>>> print(calculate('3 * 2 + 4'))
10
```

# 它是如何工作的...

因此，我们能够在`operators`字典中存储四个数学运算符的函数，并根据表达式中遇到的文本查找它们。

在`calculate`中，表达式被空格分隔，因此`5 + 3`变成了`['5'，'+'，'3']`。一旦我们有了表达式的三个元素（两个操作数和运算符），我们只需遍历部分，当我们遇到`+`时，在`operators`字典中查找以获取应该调用的关联函数，即`operator.add`。

`operator`模块包含了最常见的 Python 运算符的函数，从比较（`operator.gt`）到基于点的属性访问（`operator.attrgetter`）。

大多数提供的函数都是为了与`map`、`sorted`、`filter`等配对使用。

# 部分

我们已经知道可以使用`map`将一元函数应用于多个元素，并使用`reduce`将二元函数应用于多个元素。

有一整套函数接受 Python 中的可调用函数，并将其应用于一组项目。

主要问题是，我们想要应用的可调用函数可能具有稍有不同的签名，虽然我们可以通过将可调用函数包装到另一个适应签名的可调用函数中来解决问题，但如果你只想将函数应用到一组项目中，这并不是很方便。

例如，如果你想将列表中的所有数字乘以 3，没有一个函数可以将给定的参数乘以 3。

# 如何做...

我们可以很容易地将`operator.mul`调整为一元函数，然后将其传递给`map`以将其应用于整个列表：

```py
>>> import functools, operator
>>>
>>> values = range(10)
>>> mul3 = functools.partial(operator.mul, 3)
>>> list(map(mul3, values))
[0, 3, 6, 9, 12, 15, 18, 21, 24, 27]
```

正如你所看到的，`operator.mul`被调用时带有`3`和项目作为其参数，因此返回`item*3`。

# 它是如何工作的...

我们通过`functools.partial`创建了一个新的`mul3`可调用函数。这个可调用函数只是调用`operator.mul`，将`3`作为第一个参数传递，然后将提供给可调用函数的任何参数作为第二、第三等参数传递给`operator.mul`。

因此，最终执行`mul3(5)`意味着`operator.mul(3, 5)`。

这是因为`functools.partial`通过提供的函数硬编码提供的参数创建一个新函数。

当然，也可以传递关键字参数，这样我们就可以设置任何参数，而不是硬编码第一个参数。

然后，将生成的函数应用于所有数字通过`map`，这将导致创建一个新列表，其中包含所有从 0 到 10 的数字乘以 3。

# 通用函数

通用函数是标准库中我最喜欢的功能之一。Python 是一种非常动态的语言，通过鸭子类型，你经常能够编写适用于许多不同条件的代码（无论你收到的是列表还是元组），但在某些情况下，你确实需要根据接收到的输入有两个完全不同的代码库。

例如，我们可能希望有一个函数，以人类可读的格式打印所提供的字典内容，但我们也希望它在元组列表上正常工作，并报告不支持的类型的错误。

# 如何做...

`functools.singledispatch`装饰器允许我们基于参数类型实现通用分派：

```py
from functools import singledispatch

@singledispatch
def human_readable(d):
    raise ValueError('Unsupported argument type %s' % type(d))

@human_readable.register(dict)
def human_readable_dict(d):
    for key, value in d.items():
        print('{}: {}'.format(key, value))

@human_readable.register(list)
@human_readable.register(tuple)
def human_readable_list(d):
    for key, value in d:
        print('{}: {}'.format(key, value))
```

调用这三个函数将正确地将请求分派到正确的函数：

```py
>>> human_readable({'name': 'Tifa', 'surname': 'Lockhart'})
name: Tifa
surname: Lockhart

>>> human_readable([('name', 'Nobuo'), ('surname', 'Uematsu')])
name: Nobuo
surname: Uematsu

>>> human_readable(5)
Traceback (most recent call last):
    File "<stdin>", line 1, in <module>
    File "<stdin>", line 2, in human_readable
ValueError: Unsupported argument type <class 'int'>
```

# 它是如何工作的...

使用`@singledispatch`装饰的函数实际上被一个对参数类型的检查所取代。

每次调用`human_readable.register`都会记录到一个注册表中，指定每种参数类型应该使用哪个可调用函数：

```py
>>> human_readable.registry
mappingproxy({
    <class 'list'>: <function human_readable_list at 0x10464da60>, 
    <class 'object'>: <function human_readable at 0x10464d6a8>, 
    <class 'dict'>: <function human_readable_dict at 0x10464d950>, 
    <class 'tuple'>: <function human_readable_list at 0x10464da60>
})
```

每当调用装饰的函数时，它将在注册表中查找参数的类型，并将调用转发到关联的函数以执行。

使用`@singledispatch`装饰的函数应该始终是通用实现，即在参数没有明确支持时应该使用的实现。

在我们的示例中，这只是抛出一个错误，但通常情况下，它将尝试提供在大多数情况下有效的实现。

然后，可以使用 `@function.register` 注册特定的实现，以覆盖主要函数无法覆盖的情况，或者实际实现行为，如果主要函数只是抛出错误。

# 适当的装饰

对于第一次面对装饰器的任何人来说，装饰器通常并不直接，但一旦你习惯了它们，它们就成为扩展函数行为或实现轻量级面向方面的编程的非常方便的工具。

但即使装饰器变得自然并成为日常开发的一部分，它们也有细微之处，直到您第一次面对它们时才会变得不明显。

当您应用 `decorator` 时，可能并不立即明显，但通过使用它们，您正在改变 `decorated` 函数的签名，直到函数本身的名称和文档都丢失：

```py
def decorator(f):
    def _f(*args, **kwargs):
        return f(*args, **kwargs)
    return _f

@decorator
def sumtwo(a, b):
    """Sums a and b"""
    return a + back
```

`sumtwo` 函数被 `decorator` 装饰，但现在，如果我们尝试访问函数文档或名称，它们将不再可访问：

```py
>>> print(sumtwo.__name__)
'_f'
>>> print(sumtwo.__doc__)
None
```

即使我们为 `sumtwo` 提供了文档字符串，并且我们确切知道它的名称是 `sumtwo`，我们仍需要确保我们的装饰被正确应用并保留原始函数的属性。

# 如何做...

对于这个配方，需要执行以下步骤：

1.  Python 标准库提供了一个 `functools.wraps` 装饰器，可以应用于装饰器，以使它们保留装饰函数的属性：

```py
from functools import wraps

def decorator(f):
    @wraps(f)
    def _f(*args, **kwargs):
        return f(*args, **kwargs)
    return _f
```

1.  在这里，我们将装饰器应用于一个函数：

```py
@decorator
def sumthree(a, b):
    """Sums a and b"""
    return a + back
```

1.  正如您所看到的，它将正确保留函数的名称和文档字符串：

```py
>>> print(sumthree.__name__)
'sumthree'
>>> print(sumthree.__doc__)
'Sums a and b'
```

如果装饰的函数有自定义属性，这些属性也将被复制到新函数中。

# 还有更多...

`functools.wraps` 是一个非常方便的工具，尽最大努力确保装饰函数看起来与原始函数完全一样。

但是，虽然函数的属性可以很容易地被复制，但函数本身的签名并不容易复制。

因此，检查我们装饰的函数参数不会返回原始参数：

```py
>>> import inspect
>>> inspect.getfullargspec(sumthree)
FullArgSpec(args=[], varargs='args', varkw='kwargs', defaults=None, 
            kwonlyargs=[], kwonlydefaults=None, annotations={})
```

因此，报告的参数只是 `*args` 和 `**kwargs` 而不是 `a` 和 `b`。要访问真正的参数，我们必须通过 `__wrapped__` 属性深入到底层函数中：

```py
>>> inspect.getfullargspec(sumthree.__wrapped__)
FullArgSpec(args=['a', 'b'], varargs=None, varkw=None, defaults=None, 
            kwonlyargs=[], kwonlydefaults=None, annotations={})
```

幸运的是，标准库为我们提供了一个 `inspect.signature` 函数来做到这一点：

```py
>>> inspect.signature(sumthree)
(a, b)
```

因此，最好在想要检查函数的参数时依赖于 `inspect.signature`，以便支持装饰和未装饰的函数。

应用装饰也可能与其他装饰器冲突。最常见的例子是 `classmethod`：

```py
class MyClass(object):
    @decorator
    @classmethod
    def dosum(cls, a, b):
        return a+b
```

尝试装饰 `classmethod` 通常不起作用：

```py
>>> MyClass.dosum(3, 3)
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
    return f(*args, **kwargs)
TypeError: 'classmethod' object is not callable
```

您需要确保 `@classmethod` 始终是最后应用的装饰器，以确保它将按预期工作：

```py
class MyClass(object):
    @classmethod
    @decorator
    def dosum(cls, a, b):
        return a+b
```

在那时，`classmethod` 将按预期工作：

```py
>>> MyClass.dosum(3, 3)
6
```

Python 环境中有许多与装饰器相关的怪癖，因此有一些库试图为日常使用正确实现装饰。如果您不想考虑如何处理它们，您可能想尝试 `wrapt` 库，它将为您处理大多数装饰怪癖。

# 上下文管理器

装饰器可用于确保在进入和退出函数时执行某些操作，但在某些情况下，您可能希望确保在代码块的开头和结尾始终执行某些操作，而无需将其移动到自己的函数中或重写应该每次执行的部分。

上下文管理器存在是为了解决这个需求，将您必须一遍又一遍地重写的代码因 `try:except:finally:` 子句而被分解出来。

上下文管理器最常见的用法可能是关闭上下文管理器，它确保文件在开发人员完成使用它们后关闭，但标准库使编写新的上下文管理器变得很容易。

# 如何做...

对于这个配方，需要执行以下步骤：

1.  `contextlib`提供了与上下文管理器相关的功能，`contextlib.contextmanager`可以使编写上下文管理器变得非常容易：

```py
@contextlib.contextmanager
def logentrance():
    print('Enter')
    yield
    print('Exit')
```

1.  然后创建的上下文管理器可以像任何其他上下文管理器一样使用：

```py
>>> with logentrance():
>>>    print('This is inside')
Enter
This is inside
Exit
```

1.  在包装块内引发的异常将传播到上下文管理器，因此可以使用标准的`try:except:finally:`子句来处理它们并进行适当的清理：

```py
@contextlib.contextmanager
def logentrance():
    print('Enter')
    try:
        yield
    except:
        print('Exception')
        raise
    finally:
        print('Exit')
```

1.  更改后的上下文管理器将能够记录异常，而不会干扰异常的传播。

```py
>>> with logentrance():
        raise Exception('This is an error')
Enter
Exception
Exit
Traceback (most recent call last):
    File "<stdin>", line 1, in <module>
        raise Exception('This is an error')
Exception: This is an error
```

# 应用可变上下文管理器

在使用上下文管理器时，必须依赖`with`语句来应用它们。虽然可以通过用逗号分隔它们来在一个语句中应用多个上下文管理器，但是要应用可变数量的上下文管理器并不那么容易：

```py
@contextlib.contextmanager
def first():
    print('First')
    yield

@contextlib.contextmanager
def second():
    print('Second')
    yield
```

在编写代码时必须知道要应用的上下文管理器：

```py
>>> with first(), second():
>>>     print('Inside')
First
Second
Inside
```

但是如果有时我们只想应用`first`上下文管理器，有时又想同时应用两个呢？

# 如何做...

`contextlib.ExitStack`有各种用途，其中之一是允许我们对一个块应用可变数量的上下文管理器。

例如，我们可能只想在循环中打印偶数时同时应用两个上下文管理器：

```py
from contextlib import ExitStack

for n in range(5):
    with ExitStack() as stack:
        stack.enter_context(first())
        if n % 2 == 0:
            stack.enter_context(second())
        print('NUMBER: {}'.format(n))
```

结果将是`second`只被添加到上下文中，因此仅对偶数调用：

```py
First
Second
NUMBER: 0
First
NUMBER: 1
First
Second
NUMBER: 2
First
NUMBER: 3
First
Second
NUMBER: 4
```

正如你所看到的，对于`1`和`3`，只有`First`被打印出来。

当通过`ExitStack`上下文管理器声明的上下文退出时，`ExitStack`中注册的所有上下文管理器也将被退出。


# 第八章：密码学

本章中，我们将涵盖以下食谱：

+   要求密码-在终端软件中要求密码时，请确保不要泄漏它。

+   哈希密码-如何存储密码而不会泄漏风险？

+   验证文件的完整性-如何检查通过网络传输的文件是否已损坏。

+   验证消息的完整性-如何检查您发送给另一个软件的消息是否已被更改。

# 介绍

虽然加密通常被认为是一个复杂的领域，但它是我们作为软件开发人员日常生活的一部分，或者至少应该是，以确保我们的代码库具有最低的安全级别。

本章试图覆盖大多数您每天都必须面对的常见任务的食谱，这些任务可以帮助使您的软件对攻击具有抵抗力。

虽然用 Python 编写的软件很难受到利用，比如缓冲区溢出（除非解释器或您依赖的编译库中存在错误），但仍然有很多情况可能会泄露必须保密的信息。

# 要求密码

在基于终端的程序中，通常会向用户询问密码。通常不建议从命令选项中这样做，因为在类 Unix 系统上，可以通过运行`ps`命令获取进程列表的任何人都可以看到它们，并且可以通过运行`history`命令获取最近执行的命令列表。

虽然有方法可以调整命令参数以将其隐藏在进程列表中，但最好还是交互式地要求密码，以便不留下任何痕迹。

但是，仅仅交互地要求它们是不够的，除非您还确保在输入时不显示它们，否则任何看着您屏幕的人都可以获取您的所有密码。

# 如何做...

幸运的是，Python 标准库提供了一种从提示中输入密码而不显示它们的简单方法：

```py
>>> import getpass
>>> pwd = getpass.getpass()
Password: 
>>> print(pwd)
'HelloWorld'
```

# 它是如何工作的...

`getpass.getpass`函数将在大多数系统上使用`termios`库来禁用用户输入的字符的回显。为了避免干扰其他应用程序输入，它将在终端的新文件描述符中完成。

在不支持此功能的系统上，它将使用更基本的调用直接从`sys.stdin`读取字符而不回显它们。

# 哈希密码

避免以明文存储密码是一种已知的最佳实践，因为软件通常只需要检查用户提供的密码是否正确，并且可以存储密码的哈希值并与提供的密码的哈希值进行比较。如果两个哈希值匹配，则密码相等；如果不匹配，则提供的密码是错误的。

存储密码是一个非常标准的做法，通常它们被存储为哈希加一些盐。盐是一个随机生成的字符串，它在哈希之前与密码连接在一起。由于是随机生成的，它确保即使相同密码的哈希也会得到不同的结果。

Python 标准库提供了一套相当完整的哈希函数，其中一些非常适合存储密码。

# 如何做...

Python 3 引入了密钥派生函数，特别适用于存储密码。提供了`pbkdf2`和`scrypt`。虽然`scrypt`更加抗攻击，因为它既消耗内存又消耗 CPU，但它只能在提供 OpenSSL 1.1+的系统上运行。而`pbkdf2`可以在任何系统上运行，在最坏的情况下会使用 Python 提供的后备。

因此，从安全性的角度来看，`scrypt`更受青睐，但由于其更广泛的可用性以及自 Python 3.4 以来就可用的事实，我们将依赖于`pbkdf2`（`scrypt`仅在 Python 3.6+上可用）：

```py
import hashlib, binascii, os

def hash_password(password):
    """Hash a password for storing."""
    salt = hashlib.sha256(os.urandom(60)).hexdigest().encode('ascii')
    pwdhash = hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'), 
                                salt, 100000)
    pwdhash = binascii.hexlify(pwdhash)
    return (salt + pwdhash).decode('ascii')

def verify_password(stored_password, provided_password):
    """Verify a stored password against one provided by user"""
    salt = stored_password[:64]
    stored_password = stored_password[64:]
    pwdhash = hashlib.pbkdf2_hmac('sha512', 
                                  provided_password.encode('utf-8'), 
                                  salt.encode('ascii'), 
                                  100000)
    pwdhash = binascii.hexlify(pwdhash).decode('ascii')
    return pwdhash == stored_password
```

这两个函数可以用来对用户提供的密码进行哈希处理，以便存储在磁盘或数据库中（`hash_password`），并在用户尝试重新登录时验证密码是否与存储的密码匹配（`verify_password`）：

```py
>>> stored_password = hash_password('ThisIsAPassWord')
>>> print(stored_password)
cdd5492b89b64f030e8ac2b96b680c650468aad4b24e485f587d7f3e031ce8b63cc7139b18
aba02e1f98edbb531e8a0c8ecf971a61560b17071db5eaa8064a87bcb2304d89812e1d07fe
bfea7c73bda8fbc2204e0407766197bc2be85eada6a5
>>> verify_password(stored_password, 'ThisIsAPassWord')
True
>>> verify_password(stored_password, 'WrongPassword')
False
```

# 工作原理...

这里涉及两个函数：

+   `hash_password`：以安全的方式对提供的密码进行编码，以便存储在数据库或文件中

+   `verify_password`：给定一个编码的密码和用户提供的明文密码，它验证提供的密码是否与编码的（因此已保存的）密码匹配。

`hash_password`实际上做了多件事情；它不仅仅是对密码进行哈希处理。

它的第一件事是生成一些随机盐，应该添加到密码中。这只是从`os.urandom`读取的一些随机字节的`sha256`哈希。然后提取哈希盐的字符串表示形式作为一组十六进制数字（`hexdigest`）。

然后将盐提供给`pbkdf2_hmac`，与密码本身一起进行哈希处理，以随机化的方式哈希密码。由于`pbkdf2_hmac`需要字节作为输入，因此两个字符串（密码和盐）先前被编码为纯字节。盐被编码为纯 ASCII，因为哈希的十六进制表示只包含 0-9 和 A-F 字符。而密码被编码为`utf-8`，它可能包含任何字符。（有人的密码里有表情符号吗？）

生成的`pbkdf2`是一堆字节，因为我们想要将其存储到数据库中；我们使用`binascii.hexlify`将一堆字节转换为它们的十六进制表示形式的字符串格式。`hexlify`是一种方便的方法，可以将字节转换为字符串而不丢失数据。它只是将所有字节打印为两个十六进制数字，因此生成的数据将比原始数据大一倍，但除此之外，它与转换后的数据完全相同。

最后，该函数将哈希与其盐连接在一起。因为我们知道`sha256`哈希的`hexdigest`始终是 64 个字符长。通过将它们连接在一起，我们可以通过读取结果字符串的前 64 个字符来重新获取盐。

这将允许`verify_password`验证密码，并验证是否需要使用用于编码的盐。

一旦我们有了密码，`verify_password`就可以用来验证提供的密码是否正确。因此，它需要两个参数：哈希密码和应该被验证的新密码。

`verify_password`的第一件事是从哈希密码中提取盐（记住，我们将它放在`hash_password`结果字符串的前 64 个字符中）。

然后将提取的盐和密码候选者提供给`pbkdf2_hmac`，计算它们的哈希，然后将其转换为一个字符串，使用`binascii.hexlify`。如果生成的哈希与先前存储的密码的哈希部分匹配（盐后的字符），这意味着这两个密码匹配。

如果结果哈希不匹配，这意味着提供的密码是错误的。正如你所看到的，我们非常重要的是将盐和密码一起提供，因为我们需要它来验证密码，不同的盐会导致不同的哈希，因此我们永远无法验证密码。

# 验证文件的完整性

如果你曾经从公共网络下载过文件，你可能会注意到它们的 URL 经常是这种形式：`http://files.host.com/somefile.tar.gz#md5=3b3f5b2327421800ef00c38ab5ad81a6`。

这是因为下载可能出错，你得到的数据可能部分损坏。因此 URL 包含了一个 MD5 哈希，你可以使用`md5sum`工具来验证下载的文件是否正确。

当你从 Python 脚本下载文件时也是一样。如果提供的文件有一个 MD5 哈希用于验证，你可能想要检查检索到的文件是否有效，如果不是，那么你可以重新尝试下载它。

# 如何做到...

在`hashlib`中，有多种受支持的哈希算法，而且可能最常见的是`md5`，因此我们可以依靠`hashlib`来验证我们下载的文件：

```py
import hashlib

def verify_file(filepath, expectedhash, hashtype='md5'):
    with open(filepath, 'rb') as f:
        try:
            filehash = getattr(hashlib, hashtype)()
        except AttributeError:
            raise ValueError(
                'Unsupported hashing type %s' % hashtype
            ) from None

        while True:
            data = f.read(4096)
            if not data:
                break
            filehash.update(data)

    return filehash.hexdigest() == expectedhash
```

然后我们可以使用`verify_file`下载并验证我们的文件。

例如，我可能从**Python Package Index** (**PyPI**)下载`wrapt`分发包，并且我可能想要验证它是否已正确下载。

文件名将是`wrapt-1.10.11.tar.gz#sha256=d4d560d479f2c21e1b5443bbd15fe7ec4b37fe7e53d335d3b9b0a7b1226fe3c6`，我可以运行我的`verify_file`函数：

```py
>>> verify_file(
...     'wrapt-1.10.11.tar.gz', 
...     'd4d560d479f2c21e1b5443bbd15fe7ec4b37fe7e53d335d3b9b0a7b1226fe3c6',
...     'sha256
... )
True
```

# 工作原理...

该函数的第一步是以二进制模式打开文件。由于所有哈希函数都需要字节，而且我们甚至不知道文件的内容，因此以二进制模式读取文件是最方便的解决方案。

然后，它检查所请求的哈希算法是否在`hashlib`中可用。通过`getattr`通过尝试抓取`hashlib.md5`，`hashlib.sha256`等来完成。如果不支持该算法，它将不是有效的`hashlib`属性（因为它不会存在于模块中），并且将抛出`AttributeError`。为了使这些更容易理解，它们被捕获并引发了一个新的`ValueError`，清楚地说明该算法不受支持。

文件打开并验证算法后，将创建一个空哈希（请注意，在`getattr`之后，括号将导致返回的哈希的创建）。

我们从一个空的开始，因为文件可能非常大，我们不想一次性读取完整的文件并将其一次性传递给哈希函数。

相反，我们从一个空哈希开始，并且以 4 KB 的块读取文件，然后将每个块馈送到哈希算法以更新哈希。

最后，一旦我们计算出哈希，我们就会获取其十六进制数表示，并将其与函数提供的哈希进行比较。

如果两者匹配，那么文件就是正确下载的。

# 验证消息的完整性

在通过公共网络或对其他用户和系统可访问的存储发送消息时，我们需要知道消息是否包含原始内容，或者是否被任何人拦截和修改。

这是一种典型的中间人攻击形式，它可以修改我们内容中的任何内容，这些内容存储在其他人也可以阅读的地方，例如未加密的网络或共享系统上的磁盘。

HMAC 算法可用于保证消息未从其原始状态更改，并且经常用于签署数字文档以确保其完整性。

HMAC 的一个很好的应用场景可能是密码重置链接；这些链接通常包括有关应该重置密码的用户的参数：[`myapp.com/reset-password?user=myuser@email.net`](http://myapp.com/reset-password?user=myuser@email.net)。

但是，任何人都可以替换用户参数并重置其他人的密码。因此，我们希望确保我们提供的链接实际上没有被修改，因为它是通过附加 HMAC 发送的。

这将导致类似于以下内容：[`myapp.com/reset-password?user=myuser@email.net&signature=8efc6e7161004cfb09d05af69cc0af86bb5edb5e88bd477ba545a9929821f582`](http://myapp.com/reset-password?user=myuser@email.net&signature=8efc6e7161004cfb09d05af69cc0af86bb5edb5e88bd477ba545a9929821f582)。

此外，任何尝试修改用户都将使签名无效，从而使其无法重置其他人的密码。

另一个用例是部署 REST API 以验证和验证请求。亚马逊网络服务使用 HMAC 作为其网络服务的身份验证系统。注册时，会为您提供访问密钥和密钥。您发出的任何请求都必须使用 HMAC 进行哈希处理，使用密钥来确保您实际上是请求中所述的用户（因为您拥有其密钥），并且请求本身没有以任何方式更改，因为它的详细信息也使用 HMAC 进行了哈希处理。

HMAC 签名经常涉及到软件必须向自身发送消息或从拥有密钥的验证合作伙伴接收消息的情况。

# 如何做...

对于这个示例，需要执行以下步骤：

1.  标准库提供了一个 `hmac` 模块，结合 `hashlib` 提供的哈希函数，可以用于计算任何提供的消息的身份验证代码：

```py
import hashlib, hmac, time

def compute_signature(message, secret):
    message = message.encode('utf-8')
    timestamp = str(int(time.time()*100)).encode('ascii')

    hashdata = message + timestamp
    signature = hmac.new(secret.encode('ascii'), 
                         hashdata, 
                         hashlib.sha256).hexdigest()
    return {
        'message': message,
        'signature': signature,
        'timestamp': timestamp
    }

def verify_signature(signed_message, secret):
    timestamp = signed_message['timestamp']
    expected_signature = signed_message['signature']
    message = signed_message['message']

    hashdata = message + timestamp
    signature = hmac.new(secret.encode('ascii'), 
                         hashdata, 
                         hashlib.sha256).hexdigest()
    return signature == expected_signature
```

1.  然后，我们的函数可以用来计算签名消息，并且我们可以检查签名消息是否被以任何方式更改：

```py
>>> signed_msg = compute_signature('Hello World', 'very_secret')
>>> verify_signature(signed_msg, 'very_secret')
True
```

1.  如果尝试更改签名消息的消息字段，它将不再有效，只有真实的消息才能匹配签名：

```py
>>> signed_msg['message'] = b'Hello Boat'
>>> verify_signature(signed_msg, 'very_secret')
False
```

# 工作原理...

我们的目的是确保任何给定的消息都不能以任何方式更改，否则将使附加到消息的签名无效。

因此，`compute_signature` 函数在给定消息和私有密钥的情况下，返回发送到接收方时签名消息应包括的所有数据。发送的数据包括消息本身、签名和时间戳。时间戳包括在内，因为在许多情况下，确保消息是最近的消息是一个好主意。如果您收到使用 HMAC 签名的 API 请求或刚刚设置的 cookie，您可能希望确保您处理的是最近的消息，而不是一个小时前发送的消息。时间戳无法被篡改，因为它与消息一起包括在签名中，其存在使得攻击者更难猜测密钥，因为两个相同的消息将导致有两个不同的签名，这要归功于时间戳。

一旦消息和时间戳已知，`compute_signature` 函数将它们与密钥一起传递给 `hmac.new`，以计算签名本身。为了方便起见，签名被表示为组成十六进制数字的字符，这些数字表示签名由哪些字节组成。这确保它可以作为纯文本在 HTTP 标头或类似方式中传输。

一旦我们得到了由 `compute_signature` 返回的签名消息，可以将其存储在某个地方，并在加载时使用 `verify_signature` 来检查它是否被篡改。

`verify_signature` 函数执行与 `compute_signature` 相同的步骤。签名的消息包括消息本身、时间戳和签名。因此，`verify_signature` 获取消息和时间戳，并与密钥结合计算签名。如果计算得到的签名与签名消息中提供的签名匹配，这意味着消息没有被以任何方式更改。否则，即使对消息或时间戳进行微小更改，签名也将无效。


# 第九章：并发

在本章中，我们将介绍以下食谱：

+   线程池-通过线程池并发运行任务

+   协程-通过协程交错执行代码

+   进程-将工作分派给多个子进程

+   期货-期货代表将来会完成的任务

+   计划任务-设置在特定时间运行的任务，或每隔几秒运行一次

+   在进程之间共享数据-管理可在多个进程中访问的变量

# 介绍

并发是在相同的时间段内运行两个或多个任务的能力，无论它们是并行的还是不并行的。Python 提供了许多工具来实现并发和异步行为：线程、协程和进程。虽然其中一些由于设计（协程）或全局解释器锁（线程）的原因不允许真正的并行，但它们非常易于使用，并且可以用于执行并行 I/O 操作或以最小的工作量交错函数。当需要真正的并行时，Python 中的多进程足够容易，可以成为任何类型软件的可行解决方案。

本章将介绍在 Python 中实现并发的最常见方法，将向您展示如何执行异步任务，这些任务将在后台等待特定条件，并且如何在进程之间共享数据。

# 线程池

线程在软件中实现并发的历史上一直是最常见的方式。

理论上，当系统允许时，这些线程可以实现真正的并行，但在 Python 中，全局解释器锁（GIL）不允许线程实际上利用多核系统，因为锁将允许单个 Python 操作在任何给定时间进行。

因此，线程在 Python 中经常被低估，但实际上，即使涉及 GIL，它们也可以是运行 I/O 操作的非常方便的解决方案。

在使用协程时，我们需要一个`run`循环和一些自定义代码来确保 I/O 操作可以并行进行。使用线程，我们可以在线程中运行任何类型的函数，如果该函数进行某种 I/O 操作，例如从套接字或磁盘中读取，其他线程将同时进行。

线程的一个主要缺点是产生它们的成本。这经常被认为是协程可能是更好的解决方案的原因之一，但是有一种方法可以避免在需要线程时支付成本：`ThreadPool`。

`ThreadPool`是一组线程，通常在应用程序启动时启动，并且一直保持空闲，直到您实际上有一些工作要分派。这样，当我们有一个任务想要在单独的线程中运行时，我们只需将其发送到`ThreadPool`，`ThreadPool`将把它分配给它拥有的所有线程中的第一个可用线程。由于这些线程已经在那里运行，我们不必每次有工作要做时都支付产生线程的成本。

# 如何做...

此食谱的步骤如下：

1.  为了展示`ThreadPool`的工作原理，我们需要两个我们想要同时运行的操作。一个将从网络中获取一个 URL，这可能需要一些时间：

```py
def fetch_url(url):
    """Fetch content of a given url from the web"""
    import urllib.request
    response = urllib.request.urlopen(url)
    return response.read()
```

1.  另一个将只是等待给定条件为真，一遍又一遍地循环，直到完成：

```py
def wait_until(predicate):
    """Waits until the given predicate returns True"""
    import time
    seconds = 0
    while not predicate():
        print('Waiting...')
        time.sleep(1.0)
        seconds += 1
    print('Done!')
    return seconds
```

1.  然后我们将只下载`https://httpbin.org/delay/3`，这将需要 3 秒，并且同时等待下载完成。

1.  为此，我们将在一个`ThreadPool`（四个线程）中运行这两个任务，并等待它们都完成：

```py
>>> from multiprocessing.pool import ThreadPool
>>> pool = ThreadPool(4)
>>> t1 = pool.apply_async(fetch_url, args=('https://httpbin.org/delay/3',))
>>> t2 = pool.apply_async(wait_until, args=(t1.ready, ))
Waiting...
>>> pool.close()
>>> pool.join()
Waiting...
Waiting...
Waiting...
Done!
>>> print('Total Time:', t2.get())
Total Time: 4
>>> print('Content:', t1.get())
Content: b'{"args":{},"data":"","files":{},"form":{},
            "headers":{"Accept-Encoding":"identity",
            "Connection":"close","Host":"httpbin.org",
            "User-Agent":"Python-urllib/3.5"},
            "origin":"99.199.99.199",
            "url":"https://httpbin.org/delay/3"}\n'
```

# 它是如何工作的...

`ThreadPool`由两个主要组件组成：一堆线程和一堆队列。在创建池时，一些协调线程与您在池初始化时指定的工作线程一起启动。

工作线程将负责实际运行分派给它们的任务，而编排线程将负责管理工作线程，例如在池关闭时告诉它们退出，或在它们崩溃时重新启动它们。

如果没有提供工作线程的数量，`TaskPool`将会启动与系统核心数量相同的线程，由`os.cpu_count()`返回。

一旦线程启动，它们将等待从包含要完成的工作的队列中获取内容。一旦队列有条目，工作线程将唤醒并消耗它，开始工作。

工作完成后，工作及其结果将放回结果队列，以便等待它们的人可以获取它们。

因此，当我们创建`TaskPool`时，实际上启动了四个工作线程，这些线程开始等待从任务队列中获取工作：

```py
>>> pool = ThreadPool(4)
```

然后，一旦我们为`TaskPool`提供了工作，实际上我们将两个函数排入任务队列，一旦有工作线程可用，它就会获取其中一个并开始运行：

```py
>>> t1 = pool.apply_async(fetch_url, args=('https://httpbin.org/delay/3',))
```

与此同时，`TaskPool`返回一个`AsyncResult`对象，该对象有两个有趣的方法：`AsyncResult.ready()`告诉我们结果是否准备好（任务完成），`AsyncResult.get()`在结果可用时返回结果。

我们排队的第二个函数是等待特定谓词为`True`的函数，在这种情况下，我们提供了` t1.ready`，这是先前`AsyncResult`的就绪方法：

```py
>>> t2 = pool.apply_async(wait_until, args=(t1.ready, ))
```

这意味着第二个任务将在第一个任务完成后完成，因为它将等待直到`t1.ready() == True`。

一旦这两个任务都在运行，我们告诉`pool`我们没有更多事情要做，这样它就可以在完成任务后退出：

```py
>>> pool.close()
```

然后我们等待`pool`退出：

```py
>>> pool.join()
```

这样，我们将等待两个任务都完成，然后退出`pool`启动的所有线程。

一旦我们知道所有任务都已完成（因为`pool.join()`返回），我们可以获取结果并打印它们：

```py
>>> print('Total Time:', t2.get())
Total Time: 4
>>> print('Content:', t1.get())
Content: b'{"args":{},"data":"","files":{},"form":{},
            "headers":{"Accept-Encoding":"identity",
            "Connection":"close","Host":"httpbin.org",
            "User-Agent":"Python-urllib/3.5"},
            "origin":"99.199.99.199",
            "url":"https://httpbin.org/delay/3"}\n'
```

如果我们有更多工作要做，我们将避免运行`pool.close()`和`pool.join()`方法，这样我们就可以将更多工作发送给`TaskPool`，一旦有空闲线程，工作就会完成。

# 还有更多...

当您有多个条目需要反复应用相同操作时，`ThreadPool`特别方便。假设您有一个包含四个 URL 的列表需要下载：

```py
urls = [
    "https://httpbin.org/delay/1",
    "https://httpbin.org/delay/2",
    "https://httpbin.org/delay/3",
    "https://httpbin.org/delay/4"
]
```

在单个线程中获取它们将需要很长时间：

```py
def fetch_all_urls():
    contents = []
    for url in urls:
        contents.append(fetch_url(url))
    return contents
```

我们可以通过`timeit`模块运行函数来测试时间：

```py
>>> import timeit
>>> timeit.timeit(fetch_all_urls, number=1)
12.116707602981478
```

如果我们可以使用单独的线程来执行每个函数，那么获取所有提供的 URL 只需要最慢的一个的时间，因为下载将同时进行。

`ThreadPool`实际上为我们提供了`map`方法，该方法正是这样做的：它将一个函数应用于一系列参数：

```py
def fetch_all_urls_theraded():
    pool = ThreadPool(4)
    return pool.map(fetch_url, urls)
```

结果将是一个包含每次调用返回结果的列表，我们可以轻松测试这将比我们原始示例快得多：

```py
>>> timeit.timeit(fetch_all_urls_theraded, number=1)
4.660976745188236
```

# 协程

线程是大多数语言和用例中实现并发的最常见方式，但它们在成本方面很昂贵，而且虽然`ThreadPool`在涉及数千个线程的情况下可能是一个很好的解决方案，但通常不合理涉及数千个线程。特别是在涉及长期 I/O 时，您可能会轻松地达到数千个并发运行的操作（考虑一下 HTTP 服务器可能需要处理的并发 HTTP 请求数量），其中大多数任务将无所事事，只是大部分时间等待来自网络或磁盘的数据。

在这些情况下，异步 I/O 是首选的方法。与同步阻塞 I/O 相比，你的代码坐在那里等待读取或写入操作完成，异步 I/O 允许需要数据的任务启动读取操作，切换到做其他事情，一旦数据可用，就返回到原来的工作。

在某些情况下，可用数据的通知可能以信号的形式到来，这将中断并发运行的代码，但更常见的是，异步 I/O 是通过使用选择器（如`select`、`poll`或`epoll`）和一个事件循环来实现的，该事件循环将在选择器通知数据可用时立即恢复等待数据的函数。

这实际上导致了交错运行的功能，能够运行一段时间，达到需要一些 I/O 的时候，将控制权传递给另一个函数，只要它需要执行一些 I/O，就会立即返回。通过暂停和恢复它们的执行来交错执行的函数称为**协程**，因为它们是协作运行的。

# 如何做...

在 Python 中，协程是通过`async def`语法实现的，并通过`asyncio`事件循环执行。

例如，我们可以编写一个函数，运行两个协程，从给定的秒数开始倒计时，并打印它们的进度。这将很容易让我们看到这两个协程是同时运行的，因为我们会看到一个协程的输出与另一个协程的输出交错出现：

```py
import asyncio

async def countdown(identifier, n):
    while n > 0:
        print('left:', n, '({})'.format(identifier))
        await asyncio.sleep(1)
        n -= 1

async def main():
    await asyncio.wait([
        countdown("A", 2),
        countdown("B", 3)
    ])
```

一旦创建了一个事件循环，并在其中运行`main`，我们将看到这两个函数在运行：

```py
>>> loop = asyncio.get_event_loop()
>>> loop.run_until_complete(main())
left: 2 (A)
left: 3 (B)
left: 1 (A)
left: 2 (B)
left: 1 (B)
```

一旦执行完成，我们可以关闭事件循环，因为我们不再需要它：

```py
>>> loop.close()
```

# 它是如何工作的...

我们协程世界的核心是**事件循环**。没有事件循环，就不可能运行协程（或者说，会变得非常复杂），所以我们代码的第一件事就是创建一个事件循环：

```py
>>> loop = asyncio.get_event_loop()
```

然后我们要求事件循环等待直到提供的协程完成：

```py
loop.run_until_complete(main())
```

`main`协程只启动两个`countdown`协程并等待它们完成。这是通过使用`await`来完成的，而`asyncio.wait`函数负责等待一堆协程：

```py
await asyncio.wait([
    countdown("A", 2),
    countdown("B", 3)
])
```

`await`在这里很重要，因为我们在谈论协程，所以除非它们被明确等待，否则我们的代码会立即向前移动，因此，即使我们调用了`asyncio.wait`，我们也不会等待。

在这种情况下，我们正在等待两个倒计时完成。第一个倒计时将从`2`开始，并由字符`A`标识，而第二个倒计时将从`3`开始，并由`B`标识。

`countdown`函数本身非常简单。它只是一个永远循环并打印剩下多少时间要等待的函数。

在每个循环之间等待一秒钟，这样就等待了预期的秒数：

```py
await asyncio.sleep(1)
```

你可能会想知道为什么我们使用`asyncio.sleep`而不是`time.sleep`，原因是，当使用协程时，你必须确保每个其他会阻塞的函数也是一个协程。这样，你就知道在你的函数被阻塞时，你会让其他协程继续向前移动。

通过使用`asyncio.sleep`，我们让事件循环在第一个协程等待时推进另一个`countdown`函数，因此，我们正确地交错执行了这两个函数。

这可以通过检查输出来验证。当使用`asyncio.sleep`时，输出将在两个函数之间交错出现：

```py
left 2 (A)
left 3 (B)
left 1 (A)
left 2 (B)
left 1 (B)
```

当使用`time.sleep`时，第一个协程必须完全完成，然后第二个协程才能继续向前移动：

```py
left 2 (A)
left 1 (A)
left 3 (B)
left 2 (B)
left 1 (B)
```

因此，使用协程时的一个一般规则是，每当要调用会阻塞的东西时，确保它也是一个协程，否则你将失去协程的并发属性。

# 还有更多...

我们已经知道协程最重要的好处是事件循环能够在它们等待 I/O 操作时暂停它们的执行，以便让其他协程继续。虽然目前没有支持协程的 HTTP 协议的内置实现，但很容易推出一个后备版本来重现我们同时下载网站的示例以跟踪它花费了多长时间。

至于`ThreadPool`示例，我们将需要`wait_until`函数，它将等待任何给定的谓词为真：

```py
async def wait_until(predicate):
    """Waits until the given predicate returns True"""
    import time
    seconds = 0
    while not predicate():
        print('Waiting...')
        await asyncio.sleep(1)
        seconds += 1
    print('Done!')
    return seconds
```

我们还需要一个`fetch_url`函数来下载 URL 的内容。由于我们希望这个函数作为协程运行，所以我们不能依赖`urllib`，否则它会永远阻塞而不是将控制权传递回事件循环。因此，我们将不得不使用`asyncio.open_connection`来读取数据，这将在纯 TCP 级别工作，因此需要我们自己实现 HTTP 支持：

```py
async def fetch_url(url):
    """Fetch content of a given url from the web"""
    url = urllib.parse.urlsplit(url)
    reader, writer = await asyncio.open_connection(url.hostname, 80)
    req = ('GET {path} HTTP/1.0\r\n'
           'Host: {hostname}\r\n'
           '\r\n').format(path=url.path or '/', hostname=url.hostname)
    writer.write(req.encode('latin-1'))
    while True:
        line = await reader.readline()
        if not line.strip():
            # Read until the headers, from here on is the actualy response.
            break
    return await reader.read()
```

在这一点上，可以交错两个协程，看到下载与等待同时进行，并且在预期时间内完成：

```py
>>> loop = asyncio.get_event_loop()
>>> t1 = asyncio.ensure_future(fetch_url('http://httpbin.org/delay/3'))
>>> t2 = asyncio.ensure_future(wait_until(t1.done))
>>> loop.run_until_complete(t2)
Waiting...
Waiting...
Waiting...
Waiting...
Done!
>>> loop.close()
>>> print('Total Time:', t2.result())
Total Time: 4
>>> print('Content:', t1.result())
Content: b'{"args":{},"data":"","files":{},"form":{},
            "headers":{"Connection":"close","Host":"httpbin.org"},
            "origin":"93.147.95.71",
            "url":"http://httpbin.org/delay/3"}\n'
```

# 进程

线程和协程是与 Python GIL 并存的并发模型，并利用 I/O 操作留下的执行时间来允许其他任务继续。在现代多核系统中，能够利用系统提供的全部性能并涉及真正的并行性并将工作分配到所有可用的核心上是非常好的。

Python 标准库提供了非常精细的工具来处理多进程，这是在 Python 上利用并行性的一个很好的解决方案。由于多进程将导致多个独立的解释器，因此 GIL 不会成为障碍，并且与线程和协程相比，甚至可能更容易理解它们作为完全隔离的进程，需要合作，而不是考虑在同一系统中共享底层内存状态的多个线程/协程。

管理进程的主要成本通常是生成成本和确保您不会在任何奇怪的情况下分叉子进程的复杂性，从而导致在内存中复制不需要的数据或重用文件描述符。

`multiprocessing.ProcessPool`可以是解决所有这些问题的一个很好的解决方案，因为在软件开始时启动它将确保当我们有任务要提交给子进程时不必支付任何特定的成本。此外，通过在开始时仅创建进程，我们可以保证软件的状态可预测（并且大部分为空），被复制以创建子进程。

# 如何做...

就像在*ThreadPool*示例中一样，我们将需要两个函数，它们将作为我们在进程中并行运行的任务。

在进程的情况下，我们实际上不需要执行 I/O 来实现并发运行，因此我们的任务可以做任何事情。我将使用计算斐波那契数列并打印出进度，以便我们可以看到两个进程的输出是如何交错的：

```py
import os

def fib(n, seen):
    if n not in seen and n % 5 == 0:
        # Print out only numbers we didn't yet compute
        print(os.getpid(), '->', n)
        seen.add(n)

    if n < 2:
        return n
    return fib(n-2, seen) + fib(n-1, seen)
```

因此，现在我们需要创建运行`fib`函数并生成计算的多进程`Pool`：

```py
>>> from multiprocessing import Pool
>>> pool = Pool()
>>> t1 = pool.apply_async(fib, args=(20, set()))
>>> t2 = pool.apply_async(fib, args=(22, set()))
>>> pool.close()
>>> pool.join()
42588 -> 20
42588 -> 10
42588 -> 0
42589 -> 20
42588 -> 5
42589 -> 10
42589 -> 0
42589 -> 5
42588 -> 15
42589 -> 15
>>> t1.get()
6765
>>> t2.get()
17711
```

您可以看到两个进程的进程 ID 是如何交错的，一旦作业完成，就可以获得它们两者的结果。

# 它是如何工作的...

创建`multiprocessing.Pool`时，将通过`os.fork`或生成一个新的 Python 解释器创建与系统上的核心数量相等的进程（由`os.cpu_count()`指定），具体取决于底层系统支持的情况：

```py
>>> pool = Pool()
```

一旦启动了新进程，它们将都执行相同的操作：执行`worker`函数，该函数循环消耗发送到`Pool`的作业队列，并逐个运行它们。

这意味着如果我们创建了两个进程的`Pool`，我们将有两个工作进程。一旦我们要求`Pool`执行某些操作（通过`Pool.apply_async`，`Pool.map`或任何其他方法），作业（函数及其参数）将被放置在`multiprocessing.SimpleQueue`中，工作进程将从中获取。

一旦`worker`从队列中获取任务，它将运行它。如果有多个`worker`实例在运行，每个实例都会从队列中选择一个任务并运行它。

任务完成后，执行的函数结果将被推送回结果队列（与任务本身一起，以标识结果所属的任务），`Pool`将能够消耗结果并将其提供给最初启动任务的代码。

所有这些通信都发生在多个进程之间，因此它不能在内存中发生。相反，`multiprocessing.SimpleQueue`使用`pipe`，每个生产者将写入`pipe`，每个消费者将从`pipe`中读取。

由于`pipe`只能读取和写入字节，我们提交给`pool`的参数以及由`pool`执行的函数的结果通过`pickle`协议转换为字节。只要发送方和接收方都有相同的模块可用，它就能够在 Python 对象之间进行编组/解组。

因此，我们向`Pool`提交我们的请求：

```py
>>> t1 = pool.apply_async(fib, args=(20, set()))
```

`fib`函数，`20`和空集都被 pickled 并发送到队列中，供`Pool`的一个工作进程消耗。

与此同时，当工作进程正在获取数据并运行斐波那契函数时，我们加入池，以便我们的主进程将阻塞，直到池中的所有进程都完成：

```py
>>> pool.close()
>>> pool.join()
```

理论上，池中的进程永远不会完成（它将永远运行，不断地查找队列中的任务）。在调用`join`之前，我们关闭池。关闭池告诉池一旦它们完成当前正在做的事情，就*退出所有进程*。

然后，在`close`之后立即加入，我们等待直到池完成它现在正在做的事情，即为我们提供服务的两个请求。

与线程一样，`multiprocessing.Pool`返回`AsyncResult`对象，这意味着我们可以通过`AsyncResult.ready()`方法检查它们的完成情况，并且一旦准备就绪，我们可以通过`AsyncResult.get()`获取返回的值：

```py
>>> t1.get()
6765
>>> t2.get()
17711
```

# 还有更多...

`multiprocessing.Pool`的工作方式与`multiprocessing.pool.ThreadPool`几乎相同。实际上，它们共享很多实现，因为其中一个是另一个的子类。

但由于使用的底层技术不同，这会导致一些主要差异。一个基于线程，另一个基于子进程。

使用进程的主要好处是 Python 解释器锁不会限制它们的并行性，它们将能够实际并行运行。

另一方面，这是有成本的。使用进程在启动时间上更昂贵（fork 一个进程通常比生成一个线程慢），而且在内存使用方面更昂贵，因为每个进程都需要有自己的内存状态。虽然大部分系统通过写时复制等技术大大降低了这些成本，但线程通常比进程便宜得多。

因此，通常最好在应用程序开始时只启动进程`pool`，这样生成进程的额外成本只需支付一次。

进程不仅更昂贵，而且与线程相比，它们不共享程序的状态；每个进程都有自己的状态和内存。因此，无法在`Pool`和执行任务的工作进程之间共享数据。所有数据都需要通过`pickle`编码并通过`pipe`发送到另一端进行消耗。与可以依赖共享队列的线程相比，这将产生巨大的成本，特别是当需要发送的数据很大时。

因此，通常最好避免在参数或返回值中涉及大文件或数据时涉及进程，因为该数据将不得不多次复制才能到达最终目的地。在这种情况下，最好将数据保存在磁盘上，并传递文件的路径。

# 未来

当启动后台任务时，它可能会与您的主流程并发运行，永远不会完成自己的工作（例如`ThreadPool`的工作线程），或者它可能是某种迟早会向您返回结果并且您可能正在等待该结果的东西（例如在后台下载 URL 内容的线程）。

这些第二种类型的任务都共享一个共同的行为：它们的结果将在`_future_`中可用。因此，通常将将来可用的结果称为`Future`。编程语言并不都具有完全相同的`futures`定义，而在 Python 中，`Future`是指将来会完成的任何函数，通常返回一个结果。

`Future`是可调用本身，因此与实际用于运行可调用的技术无关。您需要一种让可调用的执行继续进行的方法，在 Python 中，这由`Executor`提供。

有一些执行器可以将 futures 运行到线程、进程或协程中（在协程的情况下，循环本身就是执行器）。

# 如何做...

要运行一个 future，我们将需要一个执行器（`ThreadPoolExecutor`、`ProcessPoolExecutor`）和我们实际想要运行的 futures。为了举例说明，我们将使用一个返回加载网页所需时间的函数，以便对多个网站进行基准测试，以查看哪个网站速度最快：

```py
import concurrent.futures
import urllib.request
import time

def benchmark_url(url):
    begin = time.time()
    with urllib.request.urlopen(url) as conn:
        conn.read()
    return (time.time() - begin, url)

class UrlsBenchmarker:
    def __init__(self, urls):
        self._urls = urls

    def run(self, executor):
        futures = self._benchmark_urls(executor)
        fastest = min([
            future.result() for future in 
                concurrent.futures.as_completed(futures)
        ])
        print('Fastest Url: {1}, in {0}'.format(*fastest))

    def _benchmark_urls(self, executor):
        futures = []
        for url in self._urls:
            future = executor.submit(benchmark_url, url)
            future.add_done_callback(self._print_timing)
            futures.append(future)
        return futures

    def _print_timing(self, future):
        print('Url {1} downloaded in {0}'.format(
            *future.result()
        ))
```

然后我们可以创建任何类型的执行器，并让`UrlsBenchmarker`在其中运行其`futures`：

```py
>>> import concurrent.futures
>>> with concurrent.futures.ThreadPoolExecutor() as executor:
...     UrlsBenchmarker([
...             'http://time.com/',
...             'http://www.cnn.com/',
...             'http://www.facebook.com/',
...             'http://www.apple.com/',
...     ]).run(executor)
...
Url http://time.com/ downloaded in 1.0580978393554688
Url http://www.apple.com/ downloaded in 1.0482590198516846
Url http://www.facebook.com/ downloaded in 1.6707532405853271
Url http://www.cnn.com/ downloaded in 7.4976489543914795
Fastest Url: http://www.apple.com/, in 1.0482590198516846
```

# 它是如何工作的...

`UrlsBenchmarker`将通过`UrlsBenchmarker._benchmark_urls`为每个 URL 触发一个 future：

```py
for url in self._urls:
    future = executor.submit(benchmark_url, url)
```

每个 future 将执行`benchmark_url`，该函数下载给定 URL 的内容并返回下载所用的时间，以及 URL 本身：

```py
def benchmark_url(url):
    begin = time.time()
    # download url here...
    return (time.time() - begin, url)
```

返回 URL 本身是必要的，因为`future`可以知道其返回值，但无法知道其参数。因此，一旦我们`submit`函数，我们就失去了它与哪个 URL 相关，并通过将其与时间一起返回，每当时间存在时我们将始终有 URL 可用。

然后对于每个`future`，通过`future.add_done_callback`添加一个回调：

```py
future.add_done_callback(self._print_timing)
```

一旦 future 完成，它将调用`UrlsBenchmarker._print_timing`，该函数打印运行 URL 所用的时间。这通知用户基准测试正在进行，并且已完成其中一个 URL。

`UrlsBenchmarker._benchmark_urls` 然后会返回一个包含所有需要在列表中进行基准测试的 URL 的`futures`。

然后将该列表传递给`concurrent.futures.as_completed`。这将创建一个迭代器，按照完成的顺序返回所有`futures`，并且只有在它们完成时才返回。因此，我们知道通过迭代它，我们只会获取已经完成的`futures`，并且一旦消耗了所有已完成的`futures`，我们将阻塞等待新的 future 完成：

```py
[
    future.result() for future in 
        concurrent.futures.as_completed(futures)
]
```

因此，只有当所有`futures`都完成时，循环才会结束。

已完成`futures`的列表被`list`推导式所消耗，它将创建一个包含这些`futures`结果的列表。

由于结果都是以（时间，URL）形式存在，我们可以使用`min`来获取具有最短时间的结果，即下载时间最短的 URL。

这是因为比较两个元组会按顺序比较元素：

```py
>>> (1, 5) < (2, 0)
True
>>> (2, 1) < (0, 5)
False
```

因此，在元组列表上调用`min`将抓取元组中第一个元素的最小值的条目：

```py
>>> min([(1, 2), (2, 0), (0, 7)])
(0, 7)
```

当有两个第一个元素具有相同值时，才会查看第二个元素：

```py
>>> min([(0, 7), (1, 2), (0, 3)])
(0, 3)
```

因此，我们获取具有最短时间的 URL（因为时间是由未来返回的元组中的第一个条目）并将其打印为最快的：

```py
fastest = min([
    future.result() for future in 
        concurrent.futures.as_completed(futures)
])
print('Fastest Url: {1}, in {0}'.format(*fastest))
```

# 还有更多...

未来执行器与 `multiprocessing.pool` 提供的工作进程池非常相似，但它们有一些差异可能会推动您朝一个方向或另一个方向。

主要区别可能是工作进程的启动方式。池会启动固定数量的工作进程，在创建池时同时创建和启动它们。因此，早期创建池会将生成工作进程的成本移到应用程序的开始。这意味着应用程序可能启动相当慢，因为它可能需要根据您请求的工作进程数量或系统核心数量来分叉许多进程。相反，执行器仅在需要时创建工作进程，并且它旨在在将来避免在有可用工作进程时创建新的工作进程。

因此，执行器通常更快地启动，但第一次将未来发送到执行器时会有更多的延迟，而池则将大部分成本集中在启动时间上。因此，如果您经常需要创建和销毁一组工作进程池的情况下，使用 `futures` 执行器可能更有效。

# 调度的任务

一种常见的后台任务是应该在任何给定时间自行在后台运行的操作。通常，这些通过 cron 守护程序或类似的系统工具进行管理，通过配置守护程序在提供的时间运行给定的 Python 脚本。

当您有一个主要应用程序需要周期性执行任务（例如过期缓存、重置密码链接、刷新待发送的电子邮件队列或类似任务）时，通过 cron 作业进行操作并不是可行的，因为您需要将数据转储到其他进程可以访问的地方：磁盘上、数据库上，或者任何类似的共享存储。

幸运的是，Python 标准库有一种简单的方法来安排在任何给定时间执行并与线程一起加入的任务。这可以是一个非常简单和有效的定时后台任务的解决方案。

# 如何做...

`sched` 模块提供了一个完全功能的调度任务执行器，我们可以将其与线程混合使用，创建一个后台调度器：

```py
import threading
import sched
import functools

class BackgroundScheduler(threading.Thread):
    def __init__(self, start=True):
        self._scheduler = sched.scheduler()
        self._running = True
        super().__init__(daemon=True)
        if start:
            self.start()

    def run_at(self, time, action, args=None, kwargs=None):
        self._scheduler.enterabs(time, 0, action, 
                                argument=args or tuple(), 
                                kwargs=kwargs or {})

    def run_after(self, delay, action, args=None, kwargs=None):
        self._scheduler.enter(delay, 0, action, 
                            argument=args or tuple(), 
                            kwargs=kwargs or {})

    def run_every(self, seconds, action, args=None, kwargs=None):
        @functools.wraps(action)
        def _f(*args, **kwargs):
            try:
                action(*args, **kwargs)
            finally:
                self.run_after(seconds, _f, args=args, kwargs=kwargs)
        self.run_after(seconds, _f, args=args, kwargs=kwargs)

    def run(self):
        while self._running:
            delta = self._scheduler.run(blocking=False)
            if delta is None:
                delta = 0.5
            self._scheduler.delayfunc(min(delta, 0.5))

    def stop(self):
        self._running = False
```

`BackgroundScheduler` 可以启动，并且可以向其中添加作业，以便在固定时间开始执行它们：

```py
>>> import time
>>> s = BackgroundScheduler()
>>> s.run_every(2, lambda: print('Hello World'))
>>> time.sleep(5)
Hello World
Hello World
>>> s.stop()
>>> s.join()
```

# 工作原理...

`BackgroundScheduler` 是 `threading.Thread` 的子类，因此它在我们的应用程序在做其他事情时在后台运行。注册的任务将在辅助线程中触发和执行，而不会妨碍主要代码：

```py
class BackgroundScheduler(threading.Thread):
        def __init__(self):
            self._scheduler = sched.scheduler()
            self._running = True
            super().__init__(daemon=True)
            self.start()
```

每当创建 `BackgroundScheduler` 时，它的线程也会启动，因此它立即可用。该线程将以 `daemon` 模式运行，这意味着如果程序在结束时仍在运行，它不会阻止程序退出。

通常 Python 在退出应用程序时会等待所有线程，因此将线程设置为 `daemon` 可以使其在无需等待它们的情况下退出。

`threading.Thread` 作为线程代码执行 `run` 方法。在我们的情况下，这是一个重复运行调度器中注册的任务的方法：

```py
def run(self):
    while self._running:
        delta = self._scheduler.run(blocking=False)
        if delta is None:
            delta = 0.5
        self._scheduler.delayfunc(min(delta, 0.5))
```

`_scheduler.run(blocking=False)` 表示从计划的任务中选择一个任务并运行它。然后，它返回在运行下一个任务之前仍需等待的时间。如果没有返回时间，这意味着没有要运行的任务。

通过 `_scheduler.delayfunc(min(delta, 0.5))`，我们等待下一个任务需要运行的时间，最多为半秒钟。

我们最多等待半秒钟，因为当我们等待时，调度的任务可能会发生变化。可能会注册一个新任务，我们希望确保它不必等待超过半秒钟才能被调度器捕捉到。

如果我们等待的时间正好是下一个任务挂起的时间，我们可能会运行，得到下一个任务在 60 秒内，然后开始等待 60 秒。但是，如果我们在等待时，用户注册了一个必须在 5 秒内运行的新任务，我们无论如何都会在 60 秒内运行它，因为我们已经在等待。通过等待最多 0.5 秒，我们知道需要半秒钟才能接收下一个任务，并且它将在 5 秒内正确运行。

等待少于下一个任务挂起的时间不会使任务运行得更快，因为调度程序不会运行任何已经超过其计划时间的任务。因此，如果没有要运行的任务，调度程序将不断告诉我们*你必须等待*，我们将等待半秒钟，直到达到下一个计划任务的计划时间为止。

`run_at`，`run_after`和`run_every`方法实际上是注册在特定时间执行函数的方法。

`run_at`和`run_after`只是包装调度程序的`enterabs`和`enter`方法，这些方法允许我们在特定时间或*n*秒后注册任务运行。

最有趣的函数可能是`run_every`，它每*n*秒运行一次任务：

```py
def run_every(self, seconds, action, args=None, kwargs=None):
    @functools.wraps(action)
    def _f(*args, **kwargs):
        try:
            action(*args, **kwargs)
        finally:
            self.run_after(seconds, _f, args=args, kwargs=kwargs)
    self.run_after(seconds, _f, args=args, kwargs=kwargs)
```

该方法接受必须运行的可调用对象，并将其包装成实际运行该函数的装饰器，但是一旦完成，它会将函数重新安排为再次执行。这样，它将一直运行，直到调度程序停止，并且每当它完成时，它都会再次安排。

# 在进程之间共享数据

在使用线程或协程时，数据是通过它们共享相同的内存空间而共享的。因此，只要注意避免竞争条件并提供适当的锁定，您就可以从任何线程访问任何对象。

相反，使用进程时，情况变得更加复杂，数据不会在它们之间共享。因此，在使用`ProcessPool`或`ProcessPoolExecutor`时，我们需要找到一种方法来在进程之间传递数据，并使它们能够共享一个公共状态。

Python 标准库提供了许多工具来创建进程之间的通信渠道：`multiprocessing.Queues`，`multiprocessing.Pipe`，`multiprocessing.Value`和`multiprocessing.Array`可用于创建一个进程可以提供并且另一个进程可以消费的队列，或者在共享内存中共享的多个进程之间的值。

虽然所有这些都是可行的解决方案，但它们有一些限制：您必须在创建任何进程之前创建所有共享值，因此如果共享值的数量是可变的并且在存储类型方面受到限制，则它们就不可行。

相反，`multiprocessing.Manager`允许我们通过共享的`Namespace`存储任意数量的共享值。

# 如何做到...

以下是此配方的步骤：

1.  `管理器`应该在应用程序开始时创建，然后所有进程都能够从中设置和读取值：

```py
import multiprocessing

manager = multiprocessing.Manager()
namespace = manager.Namespace()
```

1.  一旦我们有了我们的`namespace`，任何进程都能够向其设置值：

```py
def set_first_variable():
    namespace.first = 42
p = multiprocessing.Process(target=set_first_variable)
p.start()
p.join()

def set_second_variable():
    namespace.second = dict(value=42)
p = multiprocessing.Process(target=set_second_variable)
p.start()
p.join()

import datetime
def set_custom_variable():
    namespace.last = datetime.datetime.utcnow()
p = multiprocessing.Process(target=set_custom_variable)
p.start()
p.join()
```

1.  任何进程都能够访问它们：

```py
>>> def print_variables():
...    print(namespace.first, namespace.second, namespace.last)
...
>>> p = multiprocessing.Process(target=print_variables)
>>> p.start()
>>> p.join()
42 {'value': 42} 2018-05-26 21:39:17.433112
```

无需提前创建变量或从主进程创建，只要进程能够访问`Namespace`，所有进程都能够读取或设置任何变量。

# 它是如何工作的...

`multiprocessing.Manager`类充当服务器，能够存储任何进程都能够访问的值，只要它具有对`Manager`和它想要访问的值的引用。

通过知道它正在侦听的套接字或管道的地址，可以访问`Manager`本身，每个具有对`Manager`实例的引用的进程都知道这些：

```py
>>> manager = multiprocessing.Manager()
>>> print(manager.address)
/tmp/pymp-4l33rgjq/listener-34vkfba3
```

然后，一旦您知道如何联系管理器本身，您需要能够告诉管理器要访问的对象。

可以通过拥有代表并确定该对象的`Token`来完成：

```py
>>> namespace = manager.Namespace()
>>> print(namespace._token)
Token(typeid='Namespace', 
      address='/tmp/pymp-092482xr/listener-yreenkqo', 
      id='7f78c7fd9630')
```

特别地，`Namespace`是一种允许我们在其中存储任何变量的对象。因此，通过仅使用`namespace`令牌就可以访问`Namespace`中存储的任何内容。

所有进程，因为它们是从同一个原始进程复制出来的，都具有`namespace`的令牌和管理器的地址，因此能够访问`namespace`，并因此设置或读取其中的值。

# 还有更多...

`multiprocessing.Manager` 不受限于与源自同一进程的进程一起工作。

可以创建一个在网络上监听的`Manager`，以便任何能够连接到它的进程可能能够访问其内容：

```py
>>> import multiprocessing.managers
>>> manager = multiprocessing.managers.SyncManager(
...     address=('localhost', 50000), 
...     authkey=b'secret'
... )
>>> print(manager.address)
('localhost', 50000)
```

然后，一旦服务器启动：

```py
>>> manager.get_server().serve_forever()
```

其他进程将能够通过使用与他们想要连接的管理器完全相同的参数创建一个`manager2`实例，然后显式连接：

```py
>>> manager2 = multiprocessing.managers.SyncManager(
...     address=('localhost', 50000), 
...     authkey=b'secret'
... )
>>> manager2.connect()
```

让我们在管理器中创建一个`namespace`并将一个值设置到其中：

```py
>>> namespace = manager.Namespace()
>>> namespace.value = 5
```

知道`namespace`的令牌值后，可以创建一个代理对象通过网络从`manager2`访问`namespace`：

```py
>>> from multiprocessing.managers import NamespaceProxy
>>> ns2 = NamespaceProxy(token, 'pickle', 
...                      manager=manager2, 
...                      authkey=b'secret')
>>> print(ns2.value)
5
```
