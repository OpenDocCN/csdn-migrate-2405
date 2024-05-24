# Python 函数式编程（三）

> 原文：[`zh.annas-archive.org/md5/0A7865EB133E2D9D03688623C60BD998`](https://zh.annas-archive.org/md5/0A7865EB133E2D9D03688623C60BD998)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章. 迭代工具模块

函数式编程强调无状态编程。在 Python 中，这导致我们使用生成器表达式、生成器函数和可迭代对象。在本章中，我们将研究`itertools`库，其中有许多函数可以帮助我们处理可迭代的集合。

我们在第三章中介绍了迭代器函数，*函数、迭代器和生成器*。在本章中，我们将扩展对其的简单介绍。我们在第五章中使用了一些相关函数，*高阶函数*。

### 注意

一些函数只是表现得像是合适的、惰性的 Python 可迭代对象。重要的是要查看每个函数的实现细节。其中一些函数会创建中间对象，导致可能消耗大量内存。由于实现可能会随着 Python 版本的发布而改变，我们无法在这里提供逐个函数的建议。如果您遇到性能或内存问题，请确保检查实现。

这个模块中有大量的迭代器函数。我们将在下一章中检查一些函数。在本章中，我们将看一下三种广泛的迭代器函数。它们如下：

+   与无限迭代器一起工作的函数。这些函数可以应用于任何可迭代对象或任何集合上的迭代器；它们将消耗整个源。

+   与有限迭代器一起工作的函数。这些函数可以多次累积源，或者它们会产生源的减少。

+   tee 迭代器函数可以将迭代器克隆为几个可以独立使用的副本。这提供了一种克服 Python 迭代器的主要限制的方法：它们只能使用一次。

我们需要强调一个重要的限制，这是我们在其他地方提到过的。

### 注意

可迭代对象只能使用一次。

这可能令人惊讶，因为没有错误。一旦耗尽，它们似乎没有元素，并且每次使用时都会引发`StopIteration`异常。

迭代器的一些其他特性并不是如此深刻的限制。它们如下：

+   可迭代对象没有`len()`函数。在几乎所有其他方面，它们似乎都是容器。

+   可迭代对象可以进行`next()`操作，而容器不行。

+   `for`语句使容器和可迭代对象之间的区别变得不可见；容器将通过`iter()`函数产生一个可迭代对象。可迭代对象只是返回自身。

这些观点将为本章提供一些必要的背景。`itertools`模块的理念是利用可迭代对象的功能来创建简洁、表达力强的应用程序，而不需要复杂的管理可迭代对象的细节。

# 与无限迭代器一起工作

`itertools`模块提供了许多函数，我们可以用它们来增强或丰富可迭代的数据源。我们将看一下以下三个函数：

+   `count()`: 这是`range()`函数的无限版本

+   `cycle()`: 这将重复迭代一组值

+   `repeat()`: 这可以无限次重复单个值

我们的目标是了解这些各种迭代器函数如何在生成器表达式和生成器函数中使用。

## 使用 count()进行计数

内置的`range()`函数由上限定义：下限和步长是可选的。另一方面，`count()`函数有一个起始和可选的步长，但没有上限。

这个函数可以被认为是像`enumerate()`这样的函数的原始基础。我们可以用`zip()`和`count()`函数来定义`enumerate()`函数，如下所示：

```py
enumerate = lambda x, start=0: zip(count(start),x)

```

`enumerate()`函数的行为就像使用`count()`函数生成与某个迭代器相关联的值的`zip()`函数。

因此，以下两个命令彼此等价：

```py
zip(count(), some_iterator)
enumerate(some_iterator)

```

两者都会发出与迭代器中的项目配对的两个元组的数字序列。

`zip()`函数在使用`count()`函数时变得稍微简单，如下命令所示：

```py
zip(count(1,3), some_iterator)

```

这将提供 1、4、7、10 等值，作为枚举器的每个值的标识符。这是一个挑战，因为`enumerate`没有提供更改步长的方法。

以下命令描述了`enumerate()`函数：

```py
((1+3*e, x) for e,x in enumerate(a))

```

### 注意

`count()`函数允许非整数值。我们可以使用类似`count(0.5, 0.1)`的方法提供浮点值。如果增量值没有精确表示，这将累积相当大的误差。通常最好使用`(0.5+x*.1 for x in count())`方法来确保表示错误不会累积。

这是一种检查累积误差的方法。我们将定义一个函数，该函数将评估来自迭代器的项目，直到满足某个条件。以下是我们如何定义`until()`函数的方法：

```py
def until(terminate, iterator):
 **i = next(iterator)
 **if terminate(*i): return i
 **return until(terminate, iterator)

```

我们将从迭代器中获取下一个值。如果通过测试，那就是我们的值。否则，我们将递归地评估这个函数，以搜索通过测试的值。

我们将提供一个源可迭代对象和一个比较函数，如下所示：

```py
source = zip(count(0, .1), (.1*c for c in count()))
neq = lambda x, y: abs(x-y) > 1.0E-12

```

当我们评估`until(neq, source)`方法时，我们发现结果如下：

```py
(92.799999999999, 92.80000000000001)

```

经过 928 次迭代，错误位的总和累积到![Counting with count()](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/fp-py/img/B03652_08_01.jpg)。两个值都没有精确的二进制表示。

### 注意

`count()`函数接近 Python 递归限制。我们需要重写我们的`until()`函数，使用尾递归优化来定位具有更大累积误差的计数。

最小可检测差异可以计算如下：

```py
>>> until(lambda x, y: x != y, source)
(0.6, 0.6000000000000001)

```

仅经过六步，`count(0, 0.1)`方法已经累积了一个可测的误差![Counting with count()](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/fp-py/img/B03652_08_02.jpg)。不是很大的误差，但在 1000 步内，它将变得相当大。

## 使用 cycle()重复循环

`cycle()`函数重复一系列值。我们可以想象使用它来解决愚蠢的 fizz-buzz 问题。

访问[`rosettacode.org/wiki/FizzBuzz`](http://rosettacode.org/wiki/FizzBuzz)获取对一个相当琐碎的编程问题的全面解决方案。还可以参见[`projecteuler.net/problem=1`](https://projecteuler.net/problem=1)获取这个主题的有趣变化。

我们可以使用`cycle()`函数发出`True`和`False`值的序列，如下所示：

```py
m3= (i == 0 for i in cycle(range(3)))

m5= (i == 0 for i in cycle(range(5)))

```

如果我们将一组有限的数字压缩在一起，我们将得到一组三元组，其中一个数字和两个标志，显示该数字是否是 3 的倍数或 5 的倍数。引入有限的可迭代对象以创建正在生成的数据的适当上限是很重要的。以下是一系列值及其乘法器标志：

```py
multipliers = zip(range(10), m3, m5)

```

现在我们可以分解三元组，并使用过滤器传递是倍数的数字并拒绝所有其他数字：

```py
sum(i for i, *multipliers in multipliers if any(multipliers))

```

这个函数还有另一个更有价值的用途，用于探索性数据分析。

我们经常需要处理大量数据的样本。清洗和模型创建的初始阶段最好使用小数据集开发，并使用越来越大的数据集进行测试。我们可以使用`cycle()`函数从较大的集合中公平选择行。人口规模，![使用 cycle()重复循环](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/fp-py/img/B03652_08_03.jpg)，和期望的样本大小，![使用 cycle()重复循环](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/fp-py/img/B03652_08_04.jpg)，表示我们可以使用循环的时间长短：

![使用 cycle()重复循环](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/fp-py/img/B03652_08_05.jpg)

我们假设数据可以使用`csv`模块解析。这导致了一种优雅的方式来创建子集。我们可以使用以下命令创建子集：

```py
chooser = (x == 0 for x in cycle(range(c)))
rdr= csv.reader(source_file)
wtr= csv.writer(target_file)
wtr.writerows(row for pick, row in zip(chooser, rdr) if pick)

```

我们根据选择因子`c`创建了一个`cycle()`函数。例如，我们可能有一千万条记录的人口：选择 1,000 条记录的子集涉及选择 1/10,000 的记录。我们假设这段代码片段被安全地嵌套在一个打开相关文件的`with`语句中。我们还避免显示与 CSV 格式文件的方言问题的细节。

我们可以使用一个简单的生成器表达式来使用`cycle()`函数和来自 CSV 读取器的源数据来过滤数据。由于`chooser`表达式和用于写入行的表达式都是非严格的，所以从这种处理中几乎没有内存开销。

我们可以通过一个小改变，使用`random.randrange(c)`方法而不是`cycle(c)`方法来实现类似大小的子集的随机选择。

我们还可以重写这个方法来使用`compress()`、`filter()`和`islice()`函数，这些我们将在本章后面看到。

这种设计还可以将文件从任何非标准的类 CSV 格式重新格式化为标准的 CSV 格式。只要我们定义返回一致定义的元组的解析器函数，并编写将元组写入目标文件的消费者函数，我们就可以用相对简短、清晰的脚本进行大量的清洗和过滤。

## 使用`repeat()`重复单个值

`repeat()`函数似乎是一个奇怪的特性：它一遍又一遍地返回一个单个值。它可以作为`cycle()`函数的替代。我们可以使用`repeat(0)`方法来扩展我们的数据子集选择函数，而不是在表达式行中使用`cycle(range(100))`方法，例如，`(x==0 for x in some_function)`。

我们可以考虑以下命令：

```py
all = repeat(0)
subset= cycle(range(100))
chooser = (x == 0 for x in either_all_or_subset)

```

这使我们可以进行简单的参数更改，要么选择所有数据，要么选择数据的子集。

我们可以将这个嵌套在循环中，以创建更复杂的结构。这里有一个简单的例子：

```py
>>> list(tuple(repeat(i, times=i)) for i in range(10))
[(), (1,), (2, 2), (3, 3, 3), (4, 4, 4, 4), (5, 5, 5, 5, 5), (6, 6, 6, 6, 6, 6), (7, 7, 7, 7, 7, 7, 7), (8, 8, 8, 8, 8, 8, 8, 8), (9, 9, 9, 9, 9, 9, 9, 9, 9)]
>>> list(sum(repeat(i, times=i)) for i in range(10))
[0, 1, 4, 9, 16, 25, 36, 49, 64, 81]

```

我们使用`repeat()`函数的`times`参数创建了重复的数字序列。

# 使用有限迭代器

`itertools`模块提供了许多函数，我们可以用它们来生成有限的值序列。我们将在这个模块中看到十个函数，以及一些相关的内置函数：

+   `enumerate()`: 这个函数实际上是`__builtins__`包的一部分，但它可以与迭代器一起使用，与`itertools`模块中的其他函数非常相似。

+   `accumulate()`: 这个函数返回输入可迭代对象的一系列减少。它是一个高阶函数，可以进行各种巧妙的计算。

+   `chain()`: 这个函数将多个可迭代对象串联起来。

+   `groupby()`: 这个函数使用一个函数将单个可迭代对象分解为输入数据子集的可迭代对象序列。

+   `zip_longest()`: 这个函数将来自多个可迭代对象的元素组合在一起。内置的`zip()`函数会将序列截断到最短可迭代对象的长度。`zip_longest()`函数会用给定的填充值填充较短的可迭代对象。

+   `compress()`: 这个函数基于第二个`Boolean`值可迭代对象来过滤第一个可迭代对象。

+   `islice()`: 当应用于可迭代对象时，这个函数相当于对序列的切片。

+   `dropwhile()`和`takewhile()`: 这两个函数都使用一个`Boolean`函数来过滤可迭代的项。与`filter()`或`filterfalse()`不同，这些函数依赖于单个`True`或`False`值来改变它们对所有后续值的过滤行为。

+   `filterfalse()`: 这个函数对可迭代对象应用一个过滤函数。这是内置的`filter()`函数的补充。

+   `starmap()`: 这个函数将一个函数映射到一个元组的可迭代序列，使用每个可迭代对象作为给定函数的`*args`参数。`map()`函数使用多个并行可迭代对象做类似的事情。

我们已将这些函数分成了大致的类别。这些类别与重构可迭代对象、过滤和映射的概念大致相关。

## 使用 enumerate()分配数字

在第七章中，*其他元组技术*，我们使用`enumerate()`函数对排序数据进行了天真的排名分配。我们可以做一些事情，比如将一个值与其在原始序列中的位置配对，如下所示：

```py
pairs = tuple(enumerate(sorted(raw_values)))

```

这将对`raw_values`中的项目进行排序，创建两个具有升序数字序列的元组，并实现我们可以用于进一步计算的对象。命令和结果如下：

```py
>>> raw_values= [1.2, .8, 1.2, 2.3, 11, 18]
>>> tuple(enumerate( sorted(raw_values)))
((0, 0.8), (1, 1.2), (2, 1.2), (3, 2.3), (4, 11), (5, 18))

```

在第七章中，*其他元组技术*，我们实现了一个替代形式的 enumerate，`rank()`函数，它将以更具统计意义的方式处理并列。

这是一个常见的功能，它被添加到解析器中以记录源数据行号。在许多情况下，我们将创建某种`row_iter()`函数，以从源文件中提取字符串值。这可能会迭代 XML 文件中标签的`string`值，或者 CSV 文件的列中的值。在某些情况下，我们甚至可能会解析用 Beautiful Soup 解析的 HTML 文件中呈现的数据。

在第四章中，*与集合一起工作*，我们解析了一个 XML 文件，创建了一个简单的位置元组序列。然后我们创建了带有起点、终点和距离的`Leg`。然而，我们没有分配一个明确的`Leg`编号。如果我们对行程集合进行排序，我们将无法确定`Leg`的原始顺序。

在第七章中，*其他元组技术*，我们扩展了基本解析器，为行程的每个`Leg`创建了命名元组。增强解析器的输出如下所示：

```py
(Leg(start=Point(latitude=37.54901619777347, longitude=-76.33029518659048), end=Point(latitude=37.840832, longitude=-76.273834), distance=17.7246), Leg(start=Point(latitude=37.840832, longitude=-76.273834), end=Point(latitude=38.331501, longitude=-76.459503), distance=30.7382), Leg(start=Point(latitude=38.331501, longitude=-76.459503), end=Point(latitude=38.845501, longitude=-76.537331), distance=31.0756),...,Leg(start=Point(latitude=38.330166, longitude=-76.458504), end=Point(latitude=38.976334, longitude=-76.473503), distance=38.8019))

```

第一个`Leg`函数是在切萨皮克湾上两点之间的短途旅行。

我们可以添加一个函数，它将构建一个更复杂的元组，其中包含输入顺序信息作为元组的一部分。首先，我们将定义`Leg`类的一个稍微复杂的版本：

```py
Leg = namedtuple("Leg", ("order", "start", "end", "distance"))

```

这类似于第七章中显示的`Leg`实例，*其他元组技术*，但它包括顺序以及其他属性。我们将定义一个函数，将成对分解并创建`Leg`实例如下：

```py
def ordered_leg_iter(pair_iter):
 **for order, pair in enumerate(pair_iter):
 **start, end = pair
 **yield Leg(order, start, end, round(haversine(start, end),4))

```

我们可以使用此函数对每对起始和结束点进行枚举。我们将分解该对，然后重新组装`order`、`start`和`end`参数以及`haversine(start,end)`参数的值作为单个`Leg`实例。这个`generator`函数将与可迭代序列一起工作。

在前面的解释的背景下，它的用法如下：

```py
with urllib.request.urlopen("file:./Winter%202012-2013.kml") as source:
 **path_iter = float_lat_lon(row_iter_kml(source))
 **pair_iter = legs(path_iter)
 **trip_iter = ordered_leg_iter(pair_iter)
 **trip= tuple(trip_iter)

```

我们已经将原始文件解析为路径点，创建了起始-结束对，然后创建了一个由单个`Leg`对象构建的行程。`enumerate()`函数确保可迭代序列中的每个项目都被赋予一个唯一的数字，该数字从默认的起始值 0 递增。可以提供第二个参数值以提供替代的起始值。

## 使用 accumulate()进行累积总数

`accumulate()`函数将给定的函数折叠到可迭代对象中，累积一系列的减少。这将迭代另一个迭代器中的累积总数；默认函数是`operator.add()`。我们可以提供替代函数来改变从总和到乘积的基本行为。Python 库文档显示了`max()`函数的一个特别巧妙的用法，以创建迄今为止的最大值序列。

累积总数的一个应用是对数据进行四分位数处理。我们可以计算每个样本的累积总数，并用`int(4*value/total)`计算将它们分成四分之一。

在*使用 enumerate()分配数字*部分，我们介绍了一系列描述航行中一系列航段的纬度-经度坐标。我们可以使用距离作为四分位数航路点的基础。这使我们能够确定航行的中点。

`trip`变量的值如下：

```py
(Leg(start=Point(latitude=37.54901619777347, longitude=-76.33029518659048), end=Point(latitude=37.840832, longitude=-76.273834), distance=17.7246), Leg(start=Point(latitude=37.840832, longitude=-76.273834), end=Point(latitude=38.331501, longitude=-76.459503), distance=30.7382), ..., Leg(start=Point(latitude=38.330166, longitude=-76.458504), end=Point(latitude=38.976334, longitude=-76.473503), distance=38.8019))

```

每个`Leg`对象都有一个起点、一个终点和一个距离。四分位数的计算如下例所示：

```py
distances= (leg.distance for leg in trip)
distance_accum= tuple(accumulate(distances))
total= distance_accum[-1]+1.0
quartiles= tuple(int(4*d/total) for d in distance_accum)

```

我们提取了距离数值，并计算了每段的累积距离。累积距离的最后一个就是总数。我们将`1.0`添加到总数中，以确保`4*d/total`为 3.9983，这将截断为 3。如果没有`+1.0`，最终的项目将具有值`4`，这是一个不可能的第五个四分位数。对于某些类型的数据（具有极大的值），我们可能需要添加一个更大的值。

`quartiles`变量的值如下：

```py
(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3)

```

我们可以使用`zip()`函数将这个四分位数序列与原始数据点合并。我们还可以使用`groupby()`等函数来创建每个四分位数中各段的不同集合。

## 使用 chain()组合迭代器

我们可以使用`chain()`函数将一系列迭代器组合成一个单一的整体迭代器。这对于组合通过`groupby()`函数分解的数据非常有用。我们可以使用这个来处理多个集合，就好像它们是一个单一的集合一样。

特别是，我们可以将`chain()`函数与`contextlib.ExitStack()`方法结合使用，以处理文件集合作为单个可迭代值序列。我们可以做如下操作：

```py
from contextlib import ExitStack
import csv
def row_iter_csv_tab(*filenames):
 **with ExitStack() as stack:
 **files = [stack.enter_context(open(name, 'r', newline=''))
 **for name in filenames]
 **readers = [csv.reader(f, delimiter='\t') for f in files]
 **readers = map(lambda f: csv.reader(f, delimiter='\t'), files)
 **yield from chain(*readers)

```

我们创建了一个`ExitStack`对象，可以包含许多单独的上下文打开。当`with`语句结束时，`ExitStack`对象中的所有项目都将被正确关闭。我们创建了一个简单的打开文件对象序列；这些对象也被输入到了`ExitStack`对象中。

给定`files`变量中的文件序列，我们在`readers`变量中创建了一系列 CSV 读取器。在这种情况下，我们所有的文件都有一个共同的制表符分隔格式，这使得使用一个简单、一致的函数对文件序列进行打开非常愉快。

我们还可以使用以下命令打开文件：

```py
readers = map(lambda f: csv.reader(f, delimiter='\t'), files)

```

最后，我们将所有的读取器链接成一个单一的迭代器，使用`chain(*readers)`。这用于从所有文件中产生行的序列。

重要的是要注意，我们不能返回`chain(*readers)`对象。如果这样做，将退出`with`语句上下文，关闭所有源文件。相反，我们必须产生单独的行，以保持`with`语句上下文处于活动状态。

## 使用 groupby()对迭代器进行分区

我们可以使用`groupby()`函数将迭代器分成较小的迭代器。这是通过对给定可迭代对象中的每个项目评估给定的`key()`函数来实现的。如果键值与前一个项目的键值匹配，则两个项目属于同一分区。如果键值与前一个项目的键值不匹配，则结束前一个分区并开始一个新的分区。

`groupby()`函数的输出是两个元组的序列。每个元组都有组的键值和组中项目的可迭代对象。每个组的迭代器可以保留为元组，也可以处理以将其减少为某些摘要值。由于组迭代器的创建方式，它们无法被保留。

在*使用 accumulate()计算累积总数*部分，在本章的前面，我们展示了如何计算输入序列的四分位值。

给定具有原始数据的`trip`变量和具有四分位数分配的`quartile`变量，我们可以使用以下命令对数据进行分组：

```py
group_iter= groupby(zip(quartile, trip), key=lambda q_raw:
 **q_raw[0])
for group_key, group_iter in group_iter:
 **print(group_key, tuple(group_iter))

```

这将从原始行程数据开始，将四分位数与原始行程数据一起进行迭代。`groupby（）`函数将使用给定的`lambda`变量按四分位数分组。我们使用`for`循环来检查`groupby（）`函数的结果。这显示了我们如何获得组键值和组成员的迭代器。

`groupby（）`函数的输入必须按键值排序。这将确保组中的所有项目都是相邻的。

请注意，我们还可以使用`defaultdict（list）`方法创建组，如下所示：

```py
def groupby_2(iterable, key):
 **groups = defaultdict(list)
 **for item in iterable:
 **groups[key(item)].append(item)
 **for g in groups:
 **yield iter(groups[g])

```

我们创建了一个`defaultdict`类，其中`list`对象作为与每个键关联的值。每个项目将应用给定的`key（）`函数以创建键值。项目将附加到具有给定键的`defaultdict`类中的列表中。

一旦所有项目被分区，我们就可以将每个分区作为共享公共键的项目的迭代器返回。这类似于`groupby（）`函数，因为传递给此函数的输入迭代器不一定按照完全相同的顺序排序；可能会有相同成员的组，但顺序可能不同。

## 使用`zip_longest（）`和`zip（）`合并可迭代对象

我们在第四章*与集合一起工作*中看到了`zip（）`函数。`zip_longest（）`函数与`zip（）`函数有一个重要的区别：`zip（）`函数在最短的可迭代对象结束时停止，而`zip_longest（）`函数填充短的可迭代对象，并在最长的可迭代对象结束时停止。

`fillvalue`关键字参数允许使用除默认值`None`之外的值进行填充。

对于大多数探索性数据分析应用程序，使用默认值进行填充在统计上很难证明。**Python 标准库**文档显示了一些可以使用`zip_longest（）`函数完成的巧妙事情。很难在不远离我们对数据分析的关注的情况下扩展这些内容。

## 使用`compress（）`进行过滤

内置的`filter（）`函数使用谓词来确定是否传递或拒绝项目。我们可以使用第二个并行可迭代对象来确定要传递哪些项目，要拒绝哪些项目，而不是使用计算值的函数。

我们可以将`filter（）`函数视为具有以下定义：

```py
def filter(iterable, function):
 **i1, i2 = tee(iterable, 2)
 **return compress(i1, (function(x) for x in i2))

```

我们使用`tee（）`函数克隆了可迭代对象。（我们稍后将详细讨论这个函数。）我们对每个值评估了过滤谓词。然后我们将原始可迭代对象和过滤函数可迭代对象提供给`compress`，传递和拒绝值。这从`compress（）`函数的更原始特性中构建了`filter（）`函数的特性。

在本章的*使用 cycle（）重复循环*部分，我们看到了使用简单的生成器表达式进行数据选择。其本质如下：

```py
chooser = (x == 0 for x in cycle(range(c)))
keep= (row for pick, row in zip(chooser, some_source) if pick)

```

我们定义了一个函数，它将产生一个值`1`，后跟*c-1*个零。这个循环将被重复，允许从源中仅选择*1/c*行。

我们可以用`repeat（0）`函数替换`cycle（range（c））`函数以选择所有行。我们还可以用`random.randrange（c）`函数替换它以随机选择行。

保持表达式实际上只是一个`compress（some_source，chooser）`方法。如果我们进行这种更改，处理将变得简化：

```py
all = repeat(0)
subset = cycle(range(c))
randomized = random.randrange(c)
selection_rule = one of all, subset, or randomized
chooser = (x == 0 for x in selection_rule)
keep = compress(some_source, chooser)

```

我们定义了三种替代选择规则：`all`，`subset`和`randomized`。子集和随机化版本将从源中选择*1/c*行。`chooser`表达式将根据选择规则之一构建一个`True`和`False`值的可迭代对象。应用源可迭代对象到行选择可迭代对象来选择要保留的行。

由于所有这些都是非严格的，直到需要时才从源中读取行。这使我们能够高效地处理非常大的数据集。此外，Python 代码的相对简单意味着我们实际上不需要复杂的配置文件和相关解析器来在选择规则中进行选择。我们可以选择使用这段 Python 代码作为更大数据采样应用程序的配置。

## 使用 islice()选择子集

在第四章中，*与集合一起工作*，我们看到了使用切片表示法从集合中选择子集。我们的示例是从`list`对象中切片出成对的项目。以下是一个简单的列表：

```py
flat= ['2', '3', '5', '7', '11', '13', '17', '19', '23', '29', '31', '37', '41', '43', '47', '53', '59', '61', '67', '71',... ]

```

我们可以使用列表切片创建成对的元素，如下所示：

```py
zip(flat[0::2], flat[1::2])

```

`islice()`函数为我们提供了类似的功能，而不需要实例化`list`对象，并且看起来像以下内容：

```py
flat_iter_1= iter(flat)
flat_iter_2= iter(flat)
zip(islice(flat_iter_1, 0, None, 2), islice(flat_iter_2, 1, None, 2))

```

我们在一个扁平数据点列表上创建了两个独立的迭代器。这些可能是打开文件或数据库结果集上的两个独立迭代器。这两个迭代器需要是独立的，以便一个`islice()`函数的更改不会干扰另一个`islice()`函数。

`islice()`函数的两组参数类似于`flat[0::2]`和`flat[1::2]`方法。没有类似切片的简写，因此需要指定开始和结束参数值。步长可以省略，默认值为 1。这将从原始序列产生两个元组的序列：

```py
[(2, 3), (5, 7), (11, 13), (17, 19), (23, 29), ... (7883, 7901), (7907, 7919)]

```

由于`islice()`与可迭代对象一起工作，这种设计可以处理非常大的数据集。我们可以使用它从较大的数据集中选择一个子集。除了使用`filter()`或`compress()`函数外，我们还可以使用`islice(source,0,None,c)`方法从较大的数据集中选择![使用 islice()选择子集](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/fp-py/img/B03652_08_06.jpg)项。

## 使用 dropwhile()和 takewhile()进行有状态过滤

`dropwhile()`和`takewhile()`函数是有状态的过滤函数。它们以一种模式开始；给定的`predicate`函数是一种开关，可以切换模式。`dropwhile()`函数以拒绝模式开始；当函数变为`False`时，它切换到通过模式。`takewhile()`函数以通过模式开始；当给定函数变为`False`时，它切换到拒绝模式。

由于这些是过滤器，两个函数都将消耗整个可迭代对象。给定一个像`count()`函数这样的无限迭代器，它将无限继续。由于 Python 中没有简单的整数溢出，对`dropwhile()`或`takewhile()`函数的不考虑使用不会在整数溢出后经过几十亿次迭代后崩溃。它确实可以运行非常非常长的时间。

我们可以将这些与文件解析一起使用，以跳过输入中的标题或页脚。我们使用`dropwhile()`函数来拒绝标题行并传递剩余数据。我们使用`takewhile()`函数来传递数据并拒绝尾部行。我们将返回第三章中显示的简单 GPL 文件格式，*函数、迭代器和生成器*。该文件的标题如下所示：

```py
GIMP Palette
Name: Crayola
Columns: 16
#
```

接下来是以下示例的行：

```py
255  73 108  Radical Red
```

我们可以使用基于`dropwhile()`函数的解析器轻松定位标题的最后一行——`#`行，如下所示：

```py
with open("crayola.gpl") as source:
 **rdr = csv.reader(source, delimiter='\t')
 **rows = dropwhile(lambda row: row[0] != '#', rdr)

```

我们创建了一个 CSV 读取器，以制表符为基础解析行。这将从名称中整齐地分离出`color`三元组。三元组需要进一步解析。这将产生一个以`#`行开头并继续文件其余部分的迭代器。

我们可以使用`islice()`函数丢弃可迭代对象的第一项。然后我们可以按以下方式解析颜色细节：

```py
 **color_rows = islice(rows, 1, None)
 **colors = ((color.split(), name) for color, name in color_rows)
 **print(list(colors))

```

`islice(rows, 1, None)`表达式类似于请求`rows[1:]`切片：第一项被悄悄丢弃。一旦标题行的最后一行被丢弃，我们就可以解析颜色元组并返回更有用的颜色对象。

对于这个特定的文件，我们还可以使用 CSV 读取器函数定位的列数。我们可以使用`dropwhile(lambda row: len(row) == 1, rdr)`方法来丢弃标题行。这在一般情况下并不总是奏效。定位标题行的最后一行通常比尝试定位一些区分标题（或尾部）行与有意义的文件内容的一般特征更容易。

## 使用 filterfalse()和 filter()进行过滤的两种方法

在第五章中，*高阶函数*我们看了内置的`filter()`函数。`itertools`模块中的`filterfalse()`函数可以从`filter()`函数中定义如下：

```py
filterfalse = lambda pred, iterable:
 **filter(lambda x: not pred(x), iterable)

```

与`filter()`函数一样，谓词函数可以是`None`值。`filter(None, iterable)`方法的值是可迭代对象中的所有`True`值。`filterfalse(None, iterable)`方法的值是可迭代对象中的所有`False`值：

```py
>>> filter(None, [0, False, 1, 2])
<filter object at 0x101b43a50>
>>> list(_)
[1, 2]
>>> filterfalse(None, [0, False, 1, 2])
<itertools.filterfalse object at 0x101b43a50>
>>> list(_)
[0, False]

```

拥有`filterfalse()`函数的目的是促进重用。如果我们有一个简洁的函数可以做出过滤决定，我们应该能够使用该函数将输入分成通过和拒绝组，而不必费力地处理逻辑否定。

执行以下命令的想法是：

```py
iter_1, iter_2 = iter(some_source), iter(some_source)
good = filter(test, iter_1)
bad = filterfalse(test, iter_2)

```

这将显然包括源自所有项目。`test()`函数保持不变，我们不能通过不正确使用`()`引入微妙的逻辑错误。

## 通过 starmap()和 map()将函数应用于数据

内置的`map()`函数是一个高阶函数，它将`map()`函数应用于可迭代对象中的项目。我们可以将`map()`函数的简单版本看作如下：

```py
map(function, arg_iter) == (function(a) for a in arg_iter)

```

当`arg_iter`参数是单个值列表时，这很有效。`itertools`模块中的`starmap()`函数只是`map()`函数的`*a`版本，如下所示：

```py
starmap(function, arg_iter) == (function(*a) for a in arg_iter)

```

这反映了`map()`函数语义的小变化，以正确处理元组结构。

`map()`函数也可以接受多个可迭代对象；这些额外可迭代对象的值被压缩，并且它的行为类似于`starmap()`函数。源可迭代对象的每个压缩项都成为给定函数的多个参数。

我们可以将`map(function, iter1, iter2, ..., itern)`方法定义为以下两个命令：

```py
(function(*args) for args in zip(iter1, iter2, ..., itern))
starmap(function, zip(iter1, iter2, ..., itern))

```

各种迭代器值被用来通过`*args`构造一个参数元组。实际上，`starmap()`函数就像这种更一般的情况。我们可以从更一般的`starmap()`函数构建简单的`map()`函数。

当我们查看行程数据时，可以根据前面的命令重新定义基于`starmap()`函数的`Leg`对象的构造。在创建`Leg`对象之前，我们创建了点对。每对如下所示：

```py
((Point(latitude=37.54901619777347, longitude=-76.33029518659048), Point(latitude=37.840832, longitude=-76.273834)), ...,(Point(latitude=38.330166, longitude=-76.458504), Point(latitude=38.976334, longitude=-76.473503)))

```

我们可以使用`starmap()`函数来组装`Leg`对象，如下所示：

```py
with urllib.request.urlopen(url) as source:
 **path_iter = float_lat_lon(row_iter_kml(source))
 **pair_iter = legs(path_iter)
 **make_leg = lambda start, end: Leg(start, end, haversine(start,end))
 **trip = list(starmap(make_leg, pair_iter))

```

`legs()`函数创建反映航程的腿的起点和终点的点对象对。有了这些对，我们可以创建一个简单的函数`make_leg`，它接受一对`Points`对象，并返回一个具有起点、终点和两点之间距离的`Leg`对象。

`starmap(function, some_list)`方法的好处是可以替换潜在冗长的`(function(*args) for args in some_list)`生成器表达式。

# 使用 tee()克隆迭代器

`tee()`函数为我们提供了一种规避处理可迭代对象的重要 Python 规则的方法。这条规则非常重要，我们在这里重复一遍。

### 注意

迭代器只能使用一次。

`tee()`函数允许我们克隆一个迭代器。这似乎使我们摆脱了必须实现一个序列以便我们可以对数据进行多次遍历的限制。例如，对于一个庞大的数据集，可以按照以下方式编写一个简单的平均值：

```py
def mean(iterator):
 **it0, it1= tee(iterator,2)
 **s0= sum(1 for x in it0)
 **s1= sum(x for x in it1)
 **return s0/s1

```

这将计算平均值，而不会以任何形式在内存中出现整个数据集。

虽然在原则上很有趣，但`tee()`函数的实现受到严重限制。在大多数 Python 实现中，克隆是通过实现一个序列来完成的。虽然这可以规避小集合的“一次性”规则，但对于庞大的集合来说效果不佳。

此外，`tee()`函数的当前实现会消耗源迭代器。可能会很好地创建一些语法糖来允许对迭代器进行无限使用。这在实践中很难管理。相反，Python 要求我们仔细优化`tee()`函数。

# itertools 配方

Python 库文档的*itertools*章节，*Itertools* *Recipes*，是非常出色的。基本定义后面是一系列非常清晰和有用的配方。由于没有理由重复这些，我们将在这里引用它们。它们应该被视为 Python 中函数式编程的必读内容。

### 注意

*Python 标准库*的*10.1.2*章节，*Itertools Recipes*，是一个很好的资源。参见

[`docs.python.org/3/library/itertools.html#itertools-recipes`](https://docs.python.org/3/library/itertools.html#itertools-recipes)。

重要的是要注意，这些不是`itertools`模块中可导入的函数。需要阅读和理解一个配方，然后可能在应用程序中复制或修改它。

以下表总结了一些从 itertools 基础构建的函数式编程算法的配方：

| 函数名称 | 参数 | 结果 |
| --- | --- | --- |
| `take` | `(n, iterable)` | 这将可迭代对象的前 n 个项目作为列表返回。这在一个简单的名称中包装了`islice()`的使用。 |
| `tabulate` | `(function, start=0)` | 这返回`function(0)`和`function(1)`。这基于`map(function, count())`。 |
| `consume` | `(iterator, n)` | 这将迭代器向前推进 n 步。如果*n*是`None`，迭代器将完全消耗这些步骤。 |
| `nth` | `(iterable, n, default=None)` | 这返回第 n 个项目或默认值。这在一个简单的名称中包装了`islice()`的使用。 |
| `quantify` | `(iterable, pred=bool)` | 这计算谓词为真的次数。这使用`sum()`和`map()`，并依赖于布尔谓词在转换为整数值时的方式。 |
| `padnone` | `(iterable)` | 这返回序列元素，然后无限返回`None`。这可以创建行为类似于`zip_longest()或 map()`的函数。 |
| `ncycles` | `(iterable, n)` | 这将序列元素*n*次返回。 |
| `dotproduct` | `(vec1, vec2)` | 这是点积的基本定义。将两个向量相乘并找到结果的和。 |
| `flatten` | `(listOfLists)` | 这将嵌套的一级展平。这将各种列表链接成一个单一的列表。 |
| `repeatfunc` | `(func, times=None, *args)` | 这使用指定的参数重复调用`func`。 |
| `pairwise` | `(iterable):` | `s -> (s0,s1), (s1,s2), (s2, s3).` |
| `grouper` | `(iterable, n, fillvalue=None)` | 将数据收集到固定长度的块中。 |
| `roundrobin` | `(*iterables)` | `roundrobin('ABC', 'D', 'EF') --> A D E B F C` |
| `partition` | `(pred, iterable)` | 这使用谓词将条目分成`False`条目和`True`条目。 |
| `unique_ everseen` | `(iterable, key=None)` | 这列出唯一的元素，保留顺序。记住所有已经看到的元素。`unique_ everseen('AAAABBBCCDAABBB') - -> A B C D.` |
| `unique_justseen` | `(iterable, key=None)` | 这列出了唯一的元素，保留顺序。只记住刚看到的元素。`unique_justseen('AAAABBBCCDAABBB') - -> A B C D A B.` |
| `iter_except` | `(func, exception, first=None)` | 反复调用函数，直到引发异常。这可以用于迭代直到`KeyError`或`IndexError`。 |

# 总结

在本章中，我们已经看过了`itertools`模块中的许多函数。这个库模块提供了许多函数，帮助我们以复杂的方式处理迭代器。

我们已经看过了无限迭代器；这些重复而不终止。这些包括`count()`、`cycle()`和`repeat()`函数。由于它们不终止，消耗函数必须确定何时停止接受值。

我们还看过了许多有限迭代器。其中一些是内置的，一些是`itertools`模块的一部分。这些与源可迭代对象一起工作，因此当该可迭代对象耗尽时它们终止。这些函数包括`enumerate()`、`accumulate()`、`chain()`、`groupby()`、`zip_longest()`、`zip()`、`compress()`、`islice()`、`dropwhile()`、`takewhile()`、`filterfalse()`、`filter()`、`starmap()`和`map()`。这些函数允许我们用看起来更简单的函数替换可能复杂的生成器表达式。

此外，我们还研究了文档中的配方，这些配方提供了更多我们可以研究和复制到我们自己的应用程序中的函数。配方列表显示了丰富的常见设计模式。

在第九章中，*更多迭代工具技术*，我们将继续研究`itertools`模块。我们将看看专注于排列和组合的迭代器。这些不适用于处理大量数据。它们是一种不同类型的基于迭代器的工具。


# 第九章：更多迭代工具技术

函数式编程强调无状态编程。在 Python 中，这导致我们使用生成器表达式、生成器函数和可迭代对象。在本章中，我们将继续研究`itertools`库，其中包含许多函数，帮助我们处理可迭代集合。

在上一章中，我们看了三种广泛的迭代器函数分组。它们如下：

+   与无限迭代器一起工作的函数可以应用于任何可迭代对象或任何集合上的迭代器；它们将消耗整个源

+   与有限迭代器一起工作的函数可以多次累积源，或者它们可以产生源的减少

+   `tee()`迭代器函数将一个迭代器克隆成几个独立可用的副本

在本章中，我们将研究与排列和组合一起工作的`itertools`函数。这些包括几个函数和一些基于这些函数构建的配方。这些函数如下：

+   `product()`: 此函数形成一个等同于嵌套`for`循环的笛卡尔积

+   `permutations()`: 此函数按所有可能的顺序从宇宙*p*中发出长度为*r*的元组；没有重复的元素

+   `combinations()`: 此函数按排序顺序从宇宙*p*中发出长度为*r*的元组；没有重复的元素

+   `combinations_with_replacement()`: 此函数按照排序顺序从*p*中发出长度为*r*的元组，其中包含重复的元素

这些函数体现了从输入数据的小集合迭代可能非常大的结果集的算法。某些问题的解决方案基于详尽地枚举可能庞大的排列组合的宇宙。这些函数使得发出大量的排列组合变得简单；在某些情况下，这种简单实际上并不是最优的。

# 枚举笛卡尔积

笛卡尔积这个术语指的是枚举从多个集合中抽取的所有可能组合的想法。

从数学上讲，我们可能会说两个集合的乘积，![枚举笛卡尔积](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/fp-py/img/B03652_09_01.jpg)，有 52 对如下：

```py
{(1, C), (1, D), (1, H), (1, S), (2, C), (2, D), (2, H), (2, S), ..., (13, C), (13, D), (13, H), (13, S)}

```

我们可以通过执行以下命令来产生前述结果：

```py
>>> list(product(range(1, 14), '♣♦♥♠'))
[(1, '♣'), (1, '♦'), (1, '♥'), (1, '♠'),(2, '♣'), (2, '♦'), (2, '♥'), (2, '♠'),… (13, '♣'), (13, '♦'), (13, '♥'), (13, '♠')]

```

产品的计算可以扩展到任意数量的可迭代集合。使用大量的集合可能会导致非常大的结果集。

# 减少一个乘积

在关系数据库理论中，表之间的连接可以被视为一个经过筛选的乘积。一个没有`WHERE`子句的 SQL `SELECT`语句将产生表中行的笛卡尔积。这可以被认为是最坏情况的算法：一个没有任何过滤来选择正确结果的乘积。

我们可以使用`join()`函数来连接两个表，如下所示的命令：

```py
def join(t1, t2, where):):
 **return filter(where, product(t1, t2)))))

```

计算两个可迭代对象`t1`和`t2`的所有组合。`filter()`函数将应用给定的`where`函数来通过或拒绝不符合给定条件的项目，以匹配每个可迭代对象的适当行。当`where`函数返回一个简单的布尔值时，这将起作用。

在某些情况下，我们没有一个简单的布尔匹配函数。相反，我们被迫搜索项目之间的某种距离的最小值或最大值。

假设我们有一个`Color`对象的表如下：

```py
[Color(rgb=(239, 222, 205), name='Almond'), Color(rgb=(255, 255, 153), name='Canary'), Color(rgb=(28, 172, 120), name='Green'),...Color(rgb=(255, 174, 66), name='Yellow Orange')]

```

有关更多信息，请参见第六章，*递归和减少*，在那里我们向您展示了如何解析颜色文件以创建`namedtuple`对象。在这种情况下，我们将 RGB 保留为三元组，而不是分解每个单独的字段。

一幅图像将有一个像素集合：

```py
pixels= [(([(r, g, b), (r, g, b), (r, g, b), ...)

```

实际上，**Python Imaging Library**（**PIL**）包以多种形式呈现像素。其中之一是从（*x*，*y*）坐标到 RGB 三元组的映射。有关更多信息，请访问[Pillow 项目文档](https://pypi.python.org/pypi/Pillow)。

给定一个`PIL.Image`对象，我们可以使用以下命令迭代像素集合：

```py
def pixel_iter(image):
 **w, h = img.size
 **return ((c, img.getpixel(c)) for c in product(range(w), range(h)))

```

我们已经确定了每个坐标的范围，基于图像大小。`product(range(w), range(h))`方法的计算创建了所有可能的坐标组合。实际上，这是两个嵌套的`for`循环。

这样做的好处是为每个像素提供其坐标。然后我们可以以任意顺序处理像素，仍然可以重建图像。当使用多核或多线程来分配工作负载时，这是非常方便的。`concurrent.futures`模块提供了一种在多个核心或处理器之间分配工作的简单方法。

## 计算距离

许多决策问题要求我们找到一个足够接近的匹配。我们可能无法使用简单的相等测试。相反，我们必须使用距离度量，并找到与我们目标的最短距离的项目。对于文本，我们可能使用 Levenshtein 距离；这显示了从给定文本块到我们目标需要多少更改。

我们将使用一个稍微简单的例子。这将涉及非常简单的数学。然而，即使它很简单，如果我们天真地对待它，它也不会很好地解决问题。

在进行颜色匹配时，我们不会有一个简单的相等测试。我们很少能够检查像素颜色的确切相等。我们经常被迫定义一个最小距离函数，以确定两种颜色是否足够接近，而不是相同的 R、G 和 B 三个值。有几种常见的方法，包括欧几里得距离、曼哈顿距离，以及基于视觉偏好的其他复杂加权。

以下是欧几里得距离和曼哈顿距离函数：

```py
def euclidean(pixel, color):
 **return math.sqrt(sum(map(lambda x, y: (x-y)**2, pixel, color.rgb)))))))
def manhattan(pixel, color):
 **return sum(map(lambda x, y: abs(x-y), pixel, color.rgb)))))

```

欧几里得距离测量 RGB 空间中三个点之间直角三角形的斜边。曼哈顿距离对三个点之间的直角三角形的每条边求和。欧几里得距离提供了精度，而曼哈顿距离提供了计算速度。

展望未来，我们的目标是一个看起来像这样的结构。对于每个单独的像素，我们可以计算该像素颜色与有限颜色集中可用颜色之间的距离。单个像素的这种计算结果可能如下所示：

```py
(((0, 0), (92, 139, 195), Color(rgb=(239, 222, 205), name='Almond'), 169.10943202553784), ((0, 0), (92, 139, 195), Color(rgb=(255, 255, 153), name='Canary'), 204.42357985320578), ((0, 0), (92, 139, 195), Color(rgb=(28, 172, 120), name='Green'), 103.97114984456024), ((0, 0), (92, 139, 195), Color(rgb=(48, 186, 143), name='Mountain Meadow'), 82.75868534480233), ((0, 0), (92, 139, 195), Color(rgb=(255, 73, 108), name='Radical Red'), 196.19887869200477), ((0, 0), (92, 139, 195), Color(rgb=(253, 94, 83), name='Sunset Orange'), 201.2212712413874), ((0, 0), (92, 139, 195), Color(rgb=(255, 174, 66), name='Yellow Orange'), 210.7961100210343))

```

我们展示了一个包含多个四元组的整体元组。每个四元组包含以下内容：

+   像素的坐标，例如(0,0)

+   像素的原始颜色，例如(92, 139, 195)

+   例如，我们从七种颜色中选择一个`Color`对象，比如 Color(rgb=(239, 222, 205),name='Almond')

+   原始颜色与给定的`Color`对象之间的欧几里得距离

我们可以看到最小的欧几里得距离是最接近的匹配颜色。这种缩减很容易用`min()`函数实现。如果将整个元组分配给一个变量名`choices`，像素级的缩减将如下所示：

```py
min(choices, key=lambda xypcd: xypcd[3]))])

```

我们称每个四元组为 xypcd，即 xy 坐标、像素、颜色和距离。然后，最小距离计算将选择一个单个的四元组作为像素和颜色之间的最佳匹配。

## 获取所有像素和所有颜色

我们如何得到包含所有像素和所有颜色的结构？答案很简单，但正如我们将看到的那样，不够理想。

将像素映射到颜色的一种方法是使用`product()`函数枚举所有像素和所有颜色：

```py
xy = lambda xyp_c: xyp_c[0][0]
p = lambda xyp_c: xyp_c[0][1]
c = lambda xyp_c: xyp_c[1]
distances= (( = ((xy(item), p(item), c(item), euclidean(p(item), c(item)))
 **for item in product(pixel_iter(img), colors)))))

```

这个核心是`product(pixel_iter(img), colors)`方法，它创建了所有像素与所有颜色的组合。我们将对数据进行一些重组以使其扁平化。我们将应用`euclidean()`函数来计算像素颜色和`Color`对象之间的距离。

最终颜色的选择使用了`groupby()`函数和`min(choices,...)`表达式，如下面的命令片段所示：

```py
for _, choices in groupby(distances, key=lambda xy_p_c_d:
 **xy_p_c_d[0]):
 **print(min(choices, key=lambda xypcd: xypcd[3])))]))

```

像素和颜色的整体乘积是一个长而扁平的可迭代对象。我们将可迭代对象分组成小集合，其中坐标匹配。这将把大的可迭代对象分成小的可迭代对象，每个对象只与一个像素相关联的颜色。然后我们可以为每种颜色选择最小的颜色距离。

在一个 3,648×2,736 像素，有 133 种 Crayola 颜色的图片中，我们有一个可迭代的项数为 1,327,463,424。是的。这是由这个`distances`表达式创建的十亿种组合。这个数字并不一定是不切实际的。它完全在 Python 可以处理的范围内。然而，它揭示了对`product()`函数的天真使用的一个重要缺陷。

我们不能轻易地进行这种大规模处理，而不进行一些分析来看看它有多大。这些只对每个计算进行了 1,000,000 次的`timeit`数字如下：

+   欧几里德 2.8

+   曼哈顿 1.8

从 100 万扩展到 10 亿意味着 1,800 秒，也就是说，曼哈顿距离需要大约半小时，而计算欧几里德距离需要 46 分钟。看来 Python 的核心算术运算对于这种天真的大规模处理来说太慢了。

更重要的是，我们做错了。这种*宽度×高度×颜色*的处理方法只是一个糟糕的设计。在许多情况下，我们可以做得更好。

## 性能分析

任何大数据算法的一个关键特征是找到一种执行某种分而治之策略的方法。这对于函数式编程设计和命令式设计都是正确的。

我们有三种选项来加速这个处理；它们如下：

+   我们可以尝试使用并行处理来同时进行更多的计算。在一个四核处理器上，时间可以缩短到大约 1/4。这将把曼哈顿距离的时间缩短到 8 分钟。

+   我们可以看看缓存中间结果是否会减少冗余计算的数量。问题是有多少颜色是相同的，有多少颜色是唯一的。

+   我们可以寻找算法上的根本变化。

我们将通过计算源颜色和目标颜色之间的所有可能比较来结合最后两点。在这种情况下，与许多其他情境一样，我们可以轻松枚举整个映射，并避免在像素级别上进行冗余计算。我们还将把算法从一系列比较改为一系列简单的查找在一个映射对象中。

当考虑预先计算从源颜色到目标颜色的所有转换时，我们需要一些任意图像的整体统计数据。与本书相关的代码包括`IMG_2705.jpg`。以下是从指定图像收集一些数据的基本算法：

```py
from collections import defaultdict, Counter
palette = defaultdict(list)
for xy_p in pixel_iter(img):
 **xy, p = xy_p
 **palette[p].append(xy)
w, h = img.size
print(""("Total pixels", w*h)
print(""("Total colors", len(palette)))))

```

我们将所有给定颜色的像素收集到一个按颜色组织的列表中。从中，我们将学到以下事实中的第一个：

+   像素的总数是 9,980,928。对于一个 1000 万像素的图像来说，这并不奇怪。

+   颜色的总数是 210,303。如果我们尝试计算实际颜色和 133 种颜色之间的欧几里德距离，我们只需要进行 27,970,299 次计算，可能需要大约 76 秒。

+   使用 3 位掩码`0b11100000`，512 种可能颜色中使用了 214 种。

+   使用 4 位掩码`0b11110000`，4,096 种颜色中使用了 1,150 种。

+   使用 5 位掩码`0b11111000`，32,768 种颜色中使用了 5,845 种。

+   使用 6 位掩码`0b11111100`，262,144 种颜色中有 27,726 种颜色。

这给了我们一些关于如何重新排列数据结构、快速计算匹配颜色，然后重建图像而不进行 10 亿次比较的见解。

我们可以使用以下命令片段将掩码值应用于 RGB 字节：

```py
masked_color= tuple(map(lambda x: x&0b11100000, c))

```

这将挑选出红色、绿色和蓝色值的最重要的 3 位。如果我们使用这个来创建一个`Counter`对象，我们会看到我们有 214 个不同的值。

## 重新排列问题

对所有像素和所有颜色使用`product()`函数进行比较是一个坏主意。有 1000 万个像素，但只有 20 万种独特的颜色。在将源颜色映射到目标颜色时，我们只需要在一个简单的映射中保存 20 万个值。

我们将按以下方式处理：

+   计算源到目标颜色的映射。在这种情况下，让我们使用 3 位颜色值作为输出。每个 R、G 和 B 值来自`range(0, 256, 32)`方法中的八个值。我们可以使用这个表达式来枚举所有的输出颜色：

```py
product(range(0,256,32), range(0,256,32), range(0,256,32))

```

+   然后我们可以计算到源调色板中最近颜色的欧几里得距离，只需计算 68,096 次。这大约需要 0.14 秒。这只需要做一次，就可以计算出 20 万个映射。

+   在图像的一次遍历中，使用修改后的颜色表构建一个新的图像。在某些情况下，我们可以利用整数值的截断。我们可以使用这样的表达式（`0b11100000&r`，`0b11100000&g`，`0b11100000&b`）来去除图像颜色的最不重要的位。我们稍后将看到这种额外的计算减少。

这将用 1 亿次欧几里得距离计算替换成 1000 万次字典查找。这将用大约 30 秒的计算替换 30 分钟的计算。

我们不再为所有像素进行颜色映射，而是从输入到输出值创建一个静态映射。我们可以使用简单的查找映射从原始颜色到新颜色来构建图像。

一旦我们有了所有 20 万种颜色的调色板，我们就可以应用快速的曼哈顿距离来找到输出中最接近的颜色，比如蜡笔颜色。这将使用早期显示的颜色匹配算法来计算映射，而不是结果图像。区别将集中在使用`palette.keys()`函数而不是`pixel_iter()`函数。

我们将再次引入另一个优化：截断。这将给我们一个更快的算法。

## 结合两个转换

在结合多个转换时，我们可以从源到中间目标再到结果构建一个更复杂的映射。为了说明这一点，我们将截断颜色并应用映射。

在某些问题情境中，截断可能很困难。在其他情况下，它通常很简单。例如，将美国邮政编码从 9 位截断为 5 位是常见的。邮政编码可以进一步截断为三个字符，以确定代表更大地理区域的区域设施。

对于颜色，我们可以使用之前显示的位掩码来将三个 8 位值的颜色（24 位，1600 万种颜色）截断为三个 3 位值（9 位，512 种颜色）。

以下是一种构建颜色映射的方法，它同时结合了到给定一组颜色的距离和源颜色的截断：

```py
bit3 = range(0, 256, 0b100000)
best = (min(((((euclidean(rgb, c), rgb, c) for c in colors)
 **for rgb in product(bit3, bit3, bit3)))))
color_map = dict(((((b[1], b[2].rgb) for b in best)

```

我们创建了一个`range`对象`bit3`，它将遍历所有 8 个 3 位颜色值。

### 注意

`range`对象不像普通的迭代器；它们可以被多次使用。因此，`product(bit3, bit3, bit3)`表达式将产生我们将用作输出颜色的所有 512 种颜色组合。

对于每个截断的 RGB 颜色，我们创建了一个三元组，其中包括（0）与所有蜡笔颜色的距离，（1）RGB 颜色和（2）蜡笔“颜色”对象。当我们要求这个集合的最小值时，我们将得到最接近截断的 RGB 颜色的蜡笔“颜色”对象。

我们建立了一个字典，将截断的 RGB 颜色映射到最接近的蜡笔。为了使用这个映射，我们将在查找映射中最接近的蜡笔之前截断源颜色。这种截断与预先计算的映射的结合显示了我们可能需要结合映射技术。

以下是图像替换的命令：

```py
clone = img.copy()
for xy, p in pixel_iter(img):
 **r, g, b = p
 **repl = color_map[(([(0b11100000&r, 0b11100000&g, 0b11100000&b)]])]
 **clone.putpixel(xy, repl)
clone.show()

```

这只是使用一些 PIL 功能来用其他像素替换图片中的所有像素。

我们看到，一些函数式编程工具的天真使用可能导致表达力和简洁的算法，但也可能效率低下。计算计算复杂度的基本工具——有时被称为大 O 分析——对于函数式编程和命令式编程一样重要。

问题不在于`product()`函数效率低下。问题在于我们可以在一个低效的算法中使用`product()`函数。

# 排列一组值

当我们排列一组值时，我们将详细说明所有项目的可能顺序。有![排列一组值](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/fp-py/img/B03652_09_02.jpg)种排列![排列一组值](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/fp-py/img/B03652_09_03.jpg)项的方法。我们可以使用排列作为各种优化问题的一种蛮力解决方案。

通过访问[`en.wikipedia.org/wiki/Combinatorial_optimization`](http://en.wikipedia.org/wiki/Combinatorial_optimization)，我们可以看到对于更大的问题，穷举所有排列并不合适。使用`itertools.permutations()`函数是探索非常小问题的方便方法。

这些组合优化问题的一个常见例子是分配问题。我们有*n*个代理人和*n*个任务，但每个代理人执行给定任务的成本并不相等。想象一下，一些代理人在某些细节上有困难，而其他代理人在这些细节上表现出色。如果我们能正确分配任务给代理人，我们就可以最小化成本。

我们可以创建一个简单的网格，显示给定代理人执行给定任务的能力。对于半打代理人和任务的小问题，将有一个 36 个成本的网格。网格中的每个单元格显示代理人 0 到 5 执行任务 A 到 F。

我们可以轻松列举所有可能的排列。然而，这种方法不具有良好的可扩展性。10！等于 3,628,800。我们可以使用`list(permutations(range(10)))`方法查看这个包含 300 万项的序列。

我们期望在几秒钟内解决这样大小的问题。如果我们将问题规模扩大到 20！，我们将会遇到可扩展性问题：将有 2,432,902,008,176,640,000 种排列。如果生成 10！排列大约需要 0.56 秒，那么生成 20！排列将需要大约 12,000 年。

假设我们有一个包含 36 个值的成本矩阵，显示了六个代理人和六个任务的成本。我们可以将问题表述如下：

```py
perms = permutations(range(6)))))
alt= [(([(sum(cost[x][y] for y, x in enumerate(perm)), perm) for perm in perms]
m = min(alt)[0]
print([[([ans for s, ans in alt if s == m]))])

```

我们已经创建了六个代理人的所有任务的排列。我们已经计算了分配给每个代理人的每个任务的成本矩阵的所有成本之和。最小成本就是最佳解决方案。在许多情况下，可能会有多个最佳解决方案；我们将找到所有这些解决方案。

对于小型教科书示例，这是非常快的。对于较大的示例，逼近算法更合适。

# 生成所有组合

`itertools`模块还支持计算一组值的所有组合。在查看组合时，顺序并不重要，因此组合远少于排列。组合的数量通常表示为![生成所有组合](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/fp-py/img/B03652_09_04.jpg)。这是我们可以从整体上取`p`个项目中的`r`个项目的组合方式。

例如，有 2,598,960 种 5 张牌的扑克手。我们可以通过执行以下命令列举所有 200 万手：

```py
hands = list(combinations(tuple(product(range(13), '♠♥♦♣')), 5))

```

更实际的是，我们有一个包含多个变量的数据集。一个常见的探索技术是确定数据集中所有变量对之间的相关性。如果有*v*个变量，那么我们将枚举必须通过执行以下命令进行比较的所有变量：

```py
combinations(range(v), 2)

```

让我们从[`www.tylervigen.com`](http://www.tylervigen.com)获取一些样本数据，以展示这将如何工作。我们将选择三个具有相同时间范围的数据集：数字 7、43 和 3890。我们将简单地将数据层压成网格，重复年份列。

这是年度数据的第一行和剩余行的样子：

```py
[('year', 'Per capita consumption of cheese (US)Pounds (USDA)', 'Number of people who died by becoming tangled in their bedsheetsDeaths (US) (CDC)', 'year', 'Per capita consumption of mozzarella cheese (US)Pounds (USDA)', 'Civil engineering doctorates awarded (US)Degrees awarded (National Science Foundation)', 'year', 'US crude oil imports from VenezuelaMillions of barrels (Dept. of Energy)', 'Per capita consumption of high fructose corn syrup (US)Pounds (USDA)'),
(2000, 29.8, 327, 2000, 9.3, 480, 2000, 446, 62.6),(2001, 30.1, 456, 2001, 9.7, 501, 2001, 471, 62.5),(2002, 30.5, 509, 2002, 9.7, 540, 2002, 438, 62.8),(2003, 30.6, 497, 2003, 9.7, 552, 2003, 436, 60.9),(2004, 31.3, 596, 2004, 9.9, 547, 2004, 473, 59.8),(2005, 31.7, 573, 2005, 10.2, 622, 2005, 449, 59.1),(2006, 32.6, 661, 2006, 10.5, 655, 2006, 416, 58.2),(2007, 33.1, 741, 2007, 11, 701, 2007, 420, 56.1),(2008, 32.7, 809, 2008, 10.6, 712, 2008, 381, 53),(2009, 32.8, 717, 2009, 10.6, 708, 2009, 352, 50.1)]

```

这是我们如何使用`combinations()`函数来生成数据集中九个变量的所有组合，每次取两个：

```py
combinations(range(9), 2)

```

有 36 种可能的组合。我们将不得不拒绝涉及`year`和`year`的组合。这些将与值 1.00 显然相关。

这是一个从我们的数据集中挑选数据列的函数：

```py
def column(source, x):
 **for row in source:
 **yield row[x]

```

这使我们能够使用第四章中的`corr()`函数，比较两列数据。

这是我们如何计算所有相关组合的方法：

```py
from itertools import *
from Chapter_4.ch04_ex4 import corr
for p, q in combinations(range(9), 2):
 **header_p, *data_p = list(column(source, p))
 **header_q, *data_q = list(column(source, q))
 **if header_p == header_q: continue
 **r_pq = corr(data_p, data_q)
 **print("{"{("{2: 4.2f}: {0} vs {1}".format(header_p, header_q, r_pq)))))

```

对于每一列的组合，我们从数据集中提取了两列数据，并使用多重赋值将标题与剩余的数据行分开。如果标题匹配，我们正在比较一个变量与自身。这将对来自冗余年份列的`year`和`year`的三种组合为`True`。

给定一组列的组合，我们将计算相关函数，然后打印两个标题以及列的相关性。我们故意选择了一些显示与不遵循相同模式的数据集的虚假相关性的数据集。尽管如此，相关性仍然非常高。

结果如下：

```py
0.96: year vs Per capita consumption of cheese (US)Pounds (USDA)
0.95: year vs Number of people who died by becoming tangled in their bedsheetsDeaths (US) (CDC)
0.92: year vs Per capita consumption of mozzarella cheese (US)Pounds (USDA)
0.98: year vs Civil engineering doctorates awarded (US)Degrees awarded (National Science Foundation)
-0.80: year vs US crude oil imports from VenezuelaMillions of barrels (Dept. of Energy)
-0.95: year vs Per capita consumption of high fructose corn syrup (US)Pounds (USDA)
0.95: Per capita consumption of cheese (US)Pounds (USDA) vs Number of people who died by becoming tangled in their bedsheetsDeaths (US) (CDC)
0.96: Per capita consumption of cheese (US)Pounds (USDA) vs year
0.98: Per capita consumption of cheese (US)Pounds (USDA) vs Per capita consumption of mozzarella cheese (US)Pounds (USDA)
...
0.88: US crude oil imports from VenezuelaMillions of barrels (Dept. of Energy) vs Per capita consumption of high fructose corn syrup (US)Pounds (USDA)

```

这种模式的含义一点也不清楚。我们使用了一个简单的表达式`combinations(range(9), 2)`，来枚举所有可能的数据组合。这种简洁、表达力强的技术使我们更容易专注于数据分析问题，而不是组合算法的考虑。

# 示例

Python 库文档中的 itertools 章节非常出色。基本定义后面是一系列非常清晰和有用的示例。由于没有理由重复这些，我们将在这里引用它们。它们是 Python 中函数式编程的必读材料。

*Python 标准库*的*10.1.2*节*Itertools Recipes*是一个很好的资源。访问[`docs.python.org/3/library/itertools.html#itertools-recipes`](https://docs.python.org/3/library/itertools.html#itertools-recipes)获取更多详细信息。

这些函数定义不是`itertools`模块中可导入的函数。这些是需要阅读和理解的想法，然后可能在应用程序中复制或修改的想法。

以下表总结了一些从 itertools 基础构建的函数式编程算法的示例：

| 函数名称 | 参数 | 结果 |
| --- | --- | --- |
| `powerset` | `(iterable)` | 这会生成可迭代对象的所有子集。每个子集实际上是一个`tuple`对象，而不是一个集合实例。 |
| `random_product` | `(*args, repeat=1)` | 这从`itertools.product(*args, **kwds)`中随机选择。 |
| `random_permutation` | `(iterable, r=None)` | 这从`itertools.permutations(iterable, r)`中随机选择。 |
| `random_combination` | `(iterable, r)` | 这从`itertools.combinations(iterable, r)`中随机选择。 |

# 总结

在本章中，我们看了`itertools`模块中的许多函数。这个库模块提供了许多帮助我们以复杂的方式处理迭代器的函数。

我们看了`product()`函数，它将计算从两个或多个集合中选择的元素的所有可能组合。`permutations()`函数给我们提供了重新排列给定一组值的不同方式。`combinations()`函数返回原始集合的所有可能子集。

我们还看了`product()`和`permutations()`函数可以天真地用来创建非常大的结果集的方法。这是一个重要的警示。简洁而富有表现力的算法也可能涉及大量的计算。我们必须进行基本的复杂性分析，以确保代码能在合理的时间内完成。

在下一章中，我们将看一下`functools`模块。这个模块包括一些用于处理函数作为一等对象的工具。这是建立在第二章 *介绍一些函数特性*和第五章 *高阶函数*中展示的一些材料上。


# 第十章：Functools 模块

函数式编程强调函数作为一等对象。我们有许多接受函数作为参数或返回函数作为结果的高阶函数。在本章中，我们将查看`functools`库，其中包含一些函数来帮助我们创建和修改函数。

我们将在本章中查看一些高阶函数。之前，我们在第五章中看了高阶函数。我们还将在第十一章中继续研究高阶函数技术，*装饰器设计技术*。

在本模块中，我们将查看以下函数：

+   `@lru_cache`：这个装饰器对某些类型的应用程序可能会带来巨大的性能提升。

+   `@total_ordering`：这个装饰器可以帮助创建丰富的比较运算符。然而，它让我们看到了面向对象设计与函数式编程的更一般问题。

+   `partial（）`：它创建一个应用于给定函数的一些参数的新函数。

+   `reduce（）`：它是一个泛化的`sum（）`等归约的高阶函数。

我们将把这个库的另外两个成员推迟到第十一章，*装饰器设计技术*：`update_wrapper（）`和`wraps（）`函数。我们还将在下一章更仔细地研究编写我们自己的装饰器。

我们将完全忽略`cmp_to_key（）`函数。它的目的是帮助转换 Python 2 代码（使用比较）以在 Python 3 下运行，Python 3 使用键提取。我们只对 Python 3 感兴趣；我们将编写适当的键函数。

# 函数工具

我们在第五章中看了许多高阶函数，*高阶函数*。这些函数要么接受一个函数作为参数，要么返回一个函数（或生成器表达式）作为结果。所有这些高阶函数都有一个基本算法，可以通过注入另一个函数来定制。像`max（）`，`min（）`和`sorted（）`这样的函数接受一个`key=`函数来定制它们的行为。像`map（）`和`filter（）`这样的函数接受一个函数和一个可迭代对象，并将该函数应用于参数。在`map（）`函数的情况下，函数的结果被简单地保留。在`filter（）`函数的情况下，函数的布尔结果用于从可迭代对象中传递或拒绝值。

第五章中的所有函数，*高阶函数*都是 Python `__builtins__`包的一部分：它们无需进行`import`即可使用。它们是无处不在的，因为它们非常普遍有用。本章中的函数必须通过`import`引入，因为它们并不是如此普遍可用。

`reduce（）`函数跨越了这个界限。它最初是内置的。经过多次讨论，它从`__builtins__`包中移除，因为可能会被滥用。一些看似简单的操作可能表现得非常糟糕。

# 使用 lru_cache 进行记忆先前的结果

`lru_cache`装饰器将给定的函数转换为可能执行得更快的函数。**LRU**表示**最近最少使用**：保留了一组最近使用的项目。不经常使用的项目被丢弃以保持池的有界大小。

由于这是一个装饰器，我们可以将其应用于任何可能从缓存先前结果中受益的函数。我们可以这样使用它：

```py
from functools import lru_cache
@lru_cache(128)
def fibc(n):
 **"""Fibonacci numbers with naive recursion and caching
 **>>> fibc(20)
 **6765
 **>>> fibc(1)
 **1
 **"""
 **if n == 0: return 0
 **if n == 1: return 1
 **return fibc(n-1) + fibc(n-2)

```

这是基于第六章的一个例子，*递归和简化*。我们已经将`@lru_cache`装饰器应用于天真的斐波那契数计算。由于这个装饰，对`fibc(n)`函数的每次调用现在将被检查装饰器维护的缓存。如果参数`n`在缓存中，将使用先前计算的结果，而不是进行可能昂贵的重新计算。每个返回值都被添加到缓存中。当缓存满时，最旧的值将被弹出以腾出空间给新值。

我们强调这个例子，因为在这种情况下，天真的递归是非常昂贵的。计算任何给定的斐波那契数的复杂性，![Memoizing previous results with lru_cache](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/fp-py/img/B03652_10_01.jpg)，不仅涉及计算![Memoizing previous results with lru_cache](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/fp-py/img/B03652_10_02.jpg)，还涉及计算![Memoizing previous results with lru_cache](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/fp-py/img/B03652_10_03.jpg)。这些值的树导致了一个![Memoizing previous results with lru_cache](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/fp-py/img/B03652_10_04.jpg)的复杂度。

我们可以尝试使用`timeit`模块来经验性地确认这些好处。我们可以分别执行两种实现一千次，以查看时间的比较。使用`fib(20)`和`fibc(20)`方法显示了没有缓存的情况下这个计算是多么昂贵。因为天真的版本太慢了，`timeit`的重复次数被减少到只有 1,000 次。以下是结果：

+   Naive 3.23

+   缓存 0.0779

请注意，我们无法在`fibc()`函数上轻易使用`timeit`模块。缓存的值将保持不变：我们只会计算一次`fibc(20)`函数，这将在缓存中填充这个值。其余的 999 次迭代将简单地从缓存中获取值。我们需要在使用`fibc()`函数之间清除缓存，否则时间几乎降为 0。这是通过装饰器构建的`fibc.cache_clear()`方法来完成的。

记忆化的概念是强大的。有许多算法可以从结果的记忆化中受益。也有一些算法可能受益不那么多。

`p`个事物中以`r`个为一组的组合数通常被陈述如下：

![Memoizing previous results with lru_cache](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/fp-py/img/B03652_10_05.jpg)

这个二项式函数涉及计算三个阶乘值。在阶乘函数上使用`@lru_cache`装饰器可能是有意义的。计算一系列二项式值的程序将不需要重新计算所有这些阶乘。对于重复计算类似值的情况，加速可能会令人印象深刻。对于很少重复使用缓存值的情况，维护缓存值的开销超过了任何加速。

当重复计算类似值时，我们看到以下结果：

+   Naive Factorial 0.174

+   缓存阶乘 0.046

+   清除缓存阶乘 1.335

如果我们使用`timeit`模块重新计算相同的二项式，我们只会真正计算一次，并在其余时间返回相同的值；清除缓存的阶乘显示了在每次计算之前清除缓存的影响。清除缓存操作——`cache_clear()`函数——引入了一些开销，使其看起来比实际上更昂贵。故事的寓意是`lru_cache`装饰器很容易添加。它经常产生深远的影响；但也可能没有影响，这取决于实际数据的分布。

重要的是要注意，缓存是一个有状态的对象。这种设计推动了纯函数式编程的边界。一个可能的理想是避免赋值语句和相关状态的改变。避免有状态变量的概念通过递归函数得到了体现：当前状态包含在参数值中，而不是在变量的变化值中。我们已经看到，尾递归优化是一种必要的性能改进，以确保这种理想化的递归实际上可以很好地与可用的处理器硬件和有限的内存预算配合使用。在 Python 中，我们通过用`for`循环替换尾递归来手动进行尾递归优化。缓存是一种类似的优化：我们将根据需要手动实现它。

原则上，每次调用带有 LRU 缓存的函数都有两个结果：预期结果和一个新的缓存对象，应该用于以后的所有请求。实际上，我们将新的缓存对象封装在`fibc()`函数的装饰版本内。

缓存并不是万能的。与浮点值一起工作的应用程序可能不会从记忆化中受益太多，因为所有浮点数之间的差异都很小。浮点值的最低有效位有时只是随机噪音，这会阻止`lru_cache`装饰器中的精确相等测试。

我们将在第十六章中重新讨论这个问题，*优化和改进*。我们将看一些其他实现这个的方法。

# 定义具有完全排序的类

`total_ordering`装饰器有助于创建实现丰富的比较运算符的新类定义。这可能适用于子类`numbers.Number`的数值类。它也可能适用于半数值类。

作为一个半数值类的例子，考虑一张扑克牌。它有一个数值 rank 和一个符号 suit。只有在模拟某些游戏时，rank 才重要。这在模拟赌场二十一点时尤为重要。像数字一样，卡牌有一个顺序。我们经常对每张卡的点数进行求和，使它们类似于数字。然而，*card × card*的乘法实际上没有任何意义。

我们几乎可以用`namedtuple()`函数模拟一张扑克牌：

```py
Card1 = namedtuple("Card1", ("rank", "suit"))

```

这受到了一个深刻的限制：所有比较默认包括 rank 和 suit。这导致了以下尴尬的行为：

```py
>>> c2s= Card1(2, '\u2660')
>>> c2h= Card1(2, '\u2665')
>>> c2h == c2s
False

```

这对于二十一点游戏不起作用。它也不适用于某些扑克模拟。

我们真的希望卡片只按照它们的 rank 进行比较。以下是一个更有用的类定义。我们将分两部分展示。第一部分定义了基本属性：

```py
@total_ordering
class Card(tuple):
 **__slots__ = ()
 **def __new__( class_, rank, suit ):
 **obj= tuple.__new__(Card, (rank, suit))
 **return obj
 **def __repr__(self):
 **return "{0.rank}{0.suit}".format(self)
 **@property
 **def rank(self):
 **return self[0]
 **@property
 **def suit(self):
 **return self[1]

```

这个类扩展了`tuple`类；它没有额外的插槽，因此是不可变的。我们重写了`__new__()`方法，以便我们可以初始化一个 rank 和一个 suit 的初始值。我们提供了一个`__repr__()`方法来打印`Card`的字符串表示。我们提供了两个属性，使用属性名称提取 rank 和 suit。

类定义的其余部分显示了我们如何定义只有两个比较：

```py
 **def __eq__(self, other):
 **if isinstance(other,Card):
 **return self.rank == other.rank
 **elif isinstance(other,Number):
 **return self.rank == other
 **def __lt__(self, other):
 **if isinstance(other,Card):
 **return self.rank < other.rank
 **elif isinstance(other,Number):
 **return self.rank < other

```

我们已经定义了`__eq__()`和`__lt__()`函数。`@total_ordering`装饰器处理了所有其他比较的构造。在这两种情况下，我们允许卡片之间的比较，也允许卡片和数字之间的比较。

首先，我们只能得到 rank 的正确比较如下：

```py
>>> c2s= Card(2, '\u2660')
>>> c2h= Card(2, '\u2665')
>>> c2h == c2s
True
>>> c2h == 2
True

```

我们可以使用这个类进行许多模拟，使用简化的语法来比较卡牌的 rank。此外，我们还有一套丰富的比较运算符，如下所示：

```py
>>> c2s= Card(2, '\u2660')
>>> c3h= Card(3, '\u2665')
>>> c4c= Card(4, '\u2663')
>>> c2s <= c3h < c4c
True
>>> c3h >= c3h
True
>>> c3h > c2s
True
>>> c4c != c2s
True

```

我们不需要编写所有的比较方法函数；它们是由装饰器生成的。装饰器创建的运算符并不完美。在我们的情况下，我们要求使用整数进行比较以及在`Card`实例之间进行比较。这揭示了一些问题。

像`c4c > 3`和`3 < c4c`这样的操作会引发`TypeError`异常。这是`total_ordering`装饰器的局限性。这种混合类强制转换在实践中很少出现问题，因为这种情况相对不常见。

面向对象编程并不与函数式编程对立。两种技术在某些领域是互补的。Python 创建不可变对象的能力与函数式编程技术特别契合。我们可以轻松避免有状态对象的复杂性，但仍然受益于封装，以保持相关的方法函数在一起。定义涉及复杂计算的类属性特别有帮助；这将计算绑定到类定义，使应用程序更容易理解。

## 定义数字类

在某些情况下，我们可能希望扩展 Python 中可用的数字体系。`numbers.Number`的子类可能简化函数式程序。例如，我们可以将复杂算法的部分隔离到`Number`子类定义中，从而使应用程序的其他部分更简单或更清晰。

Python 已经提供了丰富多样的数字类型。内置类型的`int`和`float`变量涵盖了各种问题领域。在处理货币时，`decimal.Decimal`包可以优雅地处理这个问题。在某些情况下，我们可能会发现`fractions.Fraction`类比`float`变量更合适。

例如，在处理地理数据时，我们可能考虑创建`float`变量的子类，引入额外的属性，用于在纬度（或经度）和弧度之间进行转换。这个子类中的算术操作可以简化穿越赤道或本初子午线的计算。

由于 Python 的`Numbers`类旨在是不可变的，普通的函数式设计可以应用于所有各种方法函数。特殊的 Python 就地特殊方法（例如，`__iadd__()`函数）可以简单地忽略。

当使用`Number`的子类时，我们有以下一系列设计考虑：

+   相等性测试和哈希值计算。关于数字的哈希计算的核心特性在*Python 标准库*的*9.1.2 类型实现者注意事项*部分有详细说明。

+   其他比较操作符（通常通过`@total_ordering`装饰器定义）。

+   算术操作符：`+`，`-`，`*`，`/`，`//`，`%`和`**`。前向操作有特殊方法，还有额外的方法用于反向类型匹配。例如，对于表达式`a-b`，Python 使用`a`的类型来尝试找到`__sub__()`方法函数的实现：实际上是`a.__sub__(b)`方法。如果左侧值的类，在这种情况下是`a`，没有该方法或返回`NotImplemented`异常，那么将检查右侧值，看看`b.__rsub__(a)`方法是否提供结果。还有一个特殊情况，当`b`的类是`a`的类的子类时，这允许子类覆盖左侧操作选择。

+   位操作符：`&`，`|`，**^**，`>>`，`<<`和`~`。这些可能对浮点值没有意义；省略这些特殊方法可能是最好的设计。

+   一些额外的函数，如`round()`，`pow()`和`divmod()`，是通过数字特殊方法名称实现的。这些可能对这类数字有意义。

第七章，《精通面向对象的 Python》提供了创建新类型数字的详细示例。访问链接以获取更多详细信息：

[`www.packtpub.com/application-development/mastering-object-oriented-python`](https://www.packtpub.com/application-development/mastering-object-oriented-python)。

正如我们之前所指出的，函数式编程和面向对象编程可以是互补的。我们可以轻松地定义遵循函数式编程设计模式的类。添加新类型的数字是利用 Python 的面向对象特性创建更易读的函数式程序的一个例子。

# 使用 partial（）应用部分参数

`partial（）`函数导致了部分应用的东西。部分应用的函数是从旧函数和一部分所需参数构建的新函数。它与柯里化的概念密切相关。由于柯里化不适用于 Python 函数的实现方式，因此大部分理论背景在这里并不相关。然而，这个概念可以带给我们一些方便的简化。

我们可以看以下的简单例子：

```py
>>> exp2= partial(pow, 2)
>>> exp2(12)
4096
>>> exp2(17)-1
131071

```

我们创建了一个名为`exp2（y）`的函数，它是`pow（2，y）`函数。`partial（）`函数将第一个位置参数限制在`pow（）`函数中。当我们评估新创建的`exp2（）`函数时，我们得到从`partial（）`函数绑定的参数计算出的值，以及提供给`exp2（）`函数的额外参数。

位置参数的绑定以严格的从左到右的顺序进行。对于接受关键字参数的函数，在构建部分应用的函数时也可以提供这些参数。

我们也可以使用 lambda 形式创建这种部分应用的函数，如下所示：

```py
exp2= lambda y: pow(2,y)

```

两者都没有明显的优势。性能测试表明，`partial（）`函数比 lambda 形式稍快，具体如下：

+   0.37 部分

+   lambda 0.42

这是在 100 万次迭代中超过 0.05 秒：并没有显著的节省。

由于 lambda 形式具有`partial（）`函数的所有功能，因此我们可以安全地将此函数设置为不是非常有用。我们将在第十四章*PyMonad 库*中返回它，并看看我们如何使用柯里化来实现这一点。

# 使用`reduce（）`函数减少数据集

`sum（）`，`len（）`，`max（）`和`min（）`函数在某种程度上都是`reduce（）`函数表达的更一般算法的特殊化。`reduce（）`函数是一个高阶函数，它将一个函数折叠到可迭代对象中的每一对项目中。

给定一个序列对象如下：

```py
d = [2, 4, 4, 4, 5, 5, 7, 9]

```

函数`reduce（lambda x，y：x+y，d）`将`+`运算符折叠到列表中如下：

```py
2+4+4+4+5+5+7+9

```

包括`（）`可以显示有效的分组如下：

```py
((((((2+4)+4)+4)+5)+5)+7)+9

```

Python 对表达式的标准解释涉及对运算符的从左到右的评估。左折叠并没有太大的意义变化。

我们也可以提供一个初始值如下：

```py
reduce(lambda x,y: x+y**2, iterable, 0)

```

如果我们不这样做，序列的初始值将被用作初始化。当有`map（）`函数和`reduce（）`函数时，提供初始值是必不可少的。以下是如何使用显式 0 初始化器计算正确答案的：

```py
0+ 2**2+ 4**2+ 4**2+ 4**2+ 5**2+ 5**2+ 7**2+ 9**2

```

如果我们省略 0 的初始化，并且`reduce（）`函数使用第一个项目作为初始值，我们会得到以下错误答案：

```py
2+ 4**2+ 4**2+ 4**2+ 5**2+ 5**2+ 7**2+ 9**2

```

我们可以使用`reduce（）`高阶函数定义一些内置的缩减如下：

```py
sum2= lambda iterable: reduce(lambda x,y: x+y**2, iterable, 0)
sum= lambda iterable: reduce(lambda x, y: x+y, iterable)
count= lambda iterable: reduce(lambda x, y: x+1, iterable, 0)
min= lambda iterable: reduce(lambda x, y: x if x < y else y, iterable)
max= lambda iterable: reduce(lambda x, y: x if x > y else y, iterable)

```

`sum2（）`缩减函数是平方和，用于计算一组样本的标准偏差。这个`sum（）`缩减函数模仿了内置的`sum（）`函数。`count（）`缩减函数类似于`len（）`函数，但它可以在可迭代对象上工作，而`len（）`函数只能在实例化的`collection`对象上工作。

`min（）`和`max（）`函数模仿了内置的缩减。因为可迭代对象的第一个项目被用于初始化，所以这两个函数将正常工作。如果我们为这些`reduce（）`函数提供任何初始值，我们可能会错误地使用原始可迭代对象中从未出现的值。

## 结合 map（）和 reduce（）

我们可以看到如何围绕这些简单定义构建高阶函数。我们将展示一个简单的 map-reduce 函数，它结合了`map()`和`reduce()`函数，如下所示：

```py
def map_reduce(map_fun, reduce_fun, iterable):
 **return reduce(reduce_fun, map(map_fun, iterable))

```

我们从`map()`和`reduce()`函数中创建了一个复合函数，它接受三个参数：映射、缩减操作和要处理的可迭代对象或序列。

我们可以分别使用`map()`和`reduce()`函数构建一个平方和缩减，如下所示：

```py
def sum2_mr(iterable):
 **return map_reduce(lambda y: y**2, lambda x,y: x+y, iterable)

```

在这种情况下，我们使用了`lambda y: y**2`参数作为映射来对每个值进行平方。缩减只是`lambda x,y: x+y`参数。我们不需要明确提供初始值，因为初始值将是`map()`函数对其进行平方后的可迭代对象中的第一项。

`lambda x,y: x+y`参数只是`+`运算符。Python 在`operator`模块中提供了所有算术运算符作为简短的函数。以下是我们如何稍微简化我们的 map-reduce 操作：

```py
import operator
def sum2_mr2(iterable):
 **return map_reduce(lambda y: y**2, operator.add, iterable)

```

我们使用了`operator.add`方法来对值进行求和，而不是更长的 lambda 形式。

以下是我们如何在可迭代对象中计算值的数量：

```py
def count_mr(iterable):
 **return map_reduce(lambda y: 1, operator.add, iterable)

```

我们使用`lambda y: 1`参数将每个值映射为简单的 1。然后计数是使用`operator.add`方法进行`reduce()`函数。

通用的`reduce()`函数允许我们从大型数据集创建任何种类的缩减到单个值。然而，对于我们应该如何使用`reduce()`函数存在一些限制。

我们应该避免执行以下命令：

```py
reduce(operator.add, ["1", ",", "2", ",", "3"], "")

```

是的，它有效。然而，`"".join(["1", ",", "2", ",", "3"])`方法要高效得多。我们测得每百万次执行`"".join()`函数需要 0.23 秒，而执行`reduce()`函数需要 0.69 秒。

## 使用`reduce()`和`partial()`

### 注意

`sum()`函数可以看作是`partial(reduce, operator.add)`方法。这也给了我们一个提示，即我们可以创建其他映射和其他缩减。实际上，我们可以将所有常用的缩减定义为 partial 而不是 lambda。

以下是两个例子：

```py
sum2= partial(reduce, lambda x,y: x+y**2)
count= partial(reduce, lambda x,y: x+1)

```

现在我们可以通过`sum2(some_data)`或`count(some_iter)`方法使用这些函数。正如我们之前提到的，目前还不清楚这有多大的好处。可能可以用这样的函数简单地解释特别复杂的计算。

## 使用`map()`和`reduce()`来清理原始数据

在进行数据清理时，我们经常会引入各种复杂程度的过滤器来排除无效值。在某些情况下，我们还可以包括一个映射，以清理值，即在有效但格式不正确的值可以被替换为有效且正确的值的情况下。

我们可能会产生以下输出：

```py
def comma_fix(data):
 **try:
 **return float(data)
 **except ValueError:
 **return float(data.replace(",", ""))
def clean_sum(cleaner, data):
 **return reduce(operator.add, map(cleaner, data))

```

我们定义了一个简单的映射，即`comma_fix()`类，它将数据从几乎正确的格式转换为可用的浮点值。

我们还定义了一个 map-reduce，它将给定的清理函数（在本例中是`comma_fix()`类）应用于数据，然后使用`operator.add`方法进行`reduce()`函数。

我们可以按照以下方式应用先前描述的函数：

```py
>>> d = ('1,196', '1,176', '1,269', '1,240', '1,307', ... '1,435', '1,601', '1,654', '1,803', '1,734')
>>> clean_sum(comma_fix, d)
14415.0

```

我们已经清理了数据，修复了逗号，并计算了总和。这种语法非常方便，可以将这两个操作结合起来。

然而，我们必须小心，不要多次使用清理函数。如果我们还要计算平方和，我们真的不应该执行以下命令：

```py
comma_fix_squared = lambda x: comma_fix(x)**2

```

如果我们将`clean_sum(comma_fix_squared, d)`方法作为计算标准差的一部分使用，我们将对数据进行两次逗号修复操作：一次用于计算总和，一次用于计算平方和。这是一个糟糕的设计；使用`lru_cache`装饰器可以帮助缓存结果。将经过清理的中间值实现为临时的`tuple`对象可能更好。

## 使用`groupby()`和`reduce()`

一个常见的要求是在将数据分成组后对数据进行汇总。我们可以使用`defaultdict(list)`方法来分区数据。然后我们可以分别分析每个分区。在第四章*处理集合*中，我们看了一些分组和分区的方法。在第八章*Itertools 模块*中，我们看了其他方法。

以下是我们需要分析的一些示例数据：

```py
>>> data = [('4', 6.1), ('1', 4.0), ('2', 8.3), ('2', 6.5), ... ('1', 4.6), ('2', 6.8), ('3', 9.3), ('2', 7.8), ('2', 9.2), ... ('4', 5.6), ('3', 10.5), ('1', 5.8), ('4', 3.8), ('3', 8.1), ... ('3', 8.0), ('1', 6.9), ('3', 6.9), ('4', 6.2), ('1', 5.4), ... ('4', 5.8)]

```

我们有一系列原始数据值，每个键和每个键的测量值。

从这些数据中产生可用的组的一种方法是构建一个将键映射到该组中成员列表的字典，如下所示：

```py
from collections import defaultdict
def partition(iterable, key=lambda x:x):
 **"""Sort not required."""
 **pd = defaultdict(list)
 **for row in iterable:
 **pd[key(row)].append(row)
 **for k in sorted(pd):
 **yield k, iter(pd[k])

```

这将把可迭代对象中的每个项目分成单独的组。`key()`函数用于从每个项目中提取一个键值。这个键用于将每个项目附加到`pd`字典中的列表中。这个函数的结果值与`itertools.groupby()`函数的结果相匹配：它是一个可迭代的`(group key, iterator)`对序列。

以下是使用`itertools.groupby()`函数完成的相同特性：

```py
def partition_s(iterable, key= lambda x:x):
 **"""Sort required"""
 **return groupby(iterable, key)

```

我们可以按如下方式总结分组数据：

```py
mean= lambda seq: sum(seq)/len(seq)
var= lambda mean, seq: sum( (x-mean)**2/mean for x in seq)
def summarize( key_iter ):
 **key, item_iter= key_iter
 **values= tuple((v for k,v in item_iter))
 **μ= mean(values)
 **return key, μ, var(μ, values)

```

`partition()`函数的结果将是一个`(key, iterator)`两个元组的序列。我们将键与项目迭代器分开。项目迭代器中的每个项目都是源数据中的原始对象之一；这些是`(key, value)`对；我们只需要值，因此我们使用了一个简单的生成器表达式来将源键与值分开。

我们还可以执行以下命令，从两个元组中选择第二个项目：

```py
map(snd, item_iter)

```

这需要`snd= lambda x: x[1]`方法。

我们可以使用以下命令将`summarize()`函数应用于每个分区：

```py
>>> partition1= partition(list(data), key=lambda x:x[0])
>>> groups= map(summarize, partition1)

```

替代命令如下：

```py
>>> partition2= partition_s(sorted(data), key=lambda x:x[0])
>>> groups= map(summarize, partition2)

```

两者都将为我们提供每个组的汇总值。生成的组统计如下：

```py
1 5.34 0.93
2 7.72 0.63
3 8.56 0.89
4 5.5 0.7

```

方差可以作为![使用 groupby()和 reduce()](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/fp-py/img/B03652_10_07.jpg)的一部分来测试数据的零假设是否成立。零假设断言没有什么可看的；数据中的方差基本上是随机的。我们还可以比较四个组之间的数据，看各种平均值是否与零假设一致，或者是否存在一些统计学上显著的变化。

# 摘要

在本章中，我们研究了`functools`模块中的许多函数。这个库模块提供了许多函数，帮助我们创建复杂的函数和类。

我们已经将`@lru_cache`函数视为一种提高某些类型的应用程序的方法，这些应用程序需要频繁重新计算相同值。这个装饰器对于那些接受`integer`或`string`参数值的某些类型的函数来说是非常有价值的。它可以通过简单地实现记忆化来减少处理。

我们将`@total_` `ordering`函数视为装饰器，以帮助我们构建支持丰富排序比较的对象。这在函数式编程的边缘，但在创建新类型的数字时非常有帮助。

`partial()`函数创建一个新函数，其中包含参数值的部分应用。作为替代，我们可以构建一个具有类似特性的`lambda`。这种用例是模棱两可的。

我们还研究了`reduce()`函数作为高阶函数。这概括了像`sum()`函数这样的缩减。我们将在后面的章节中的几个示例中使用这个函数。这与`filter()`和`map()`函数在逻辑上是一致的，是一个重要的高阶函数。

在接下来的章节中，我们将看看如何使用装饰器构建高阶函数。这些高阶函数可以导致稍微更简单和更清晰的语法。我们可以使用装饰器来定义我们需要合并到许多其他函数或类中的孤立方面。


# 第十一章：装饰器设计技术

Python 为我们提供了许多创建高阶函数的方法。在第五章中，*高阶函数*，我们探讨了两种技术：定义一个接受函数作为参数的函数，以及定义`Callable`的子类，该子类可以初始化为一个函数或者使用函数作为参数调用。

在本章中，我们将探讨使用装饰器基于另一个函数构建函数。我们还将研究`functools`模块中的两个函数`update_wrapper()`和`wraps()`，这些函数可以帮助我们构建装饰器。

装饰函数的好处之一是我们可以创建复合函数。这些是单个函数，包含来自多个来源的功能。复合函数，![装饰器设计技术](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/fp-py/img/B03652_11_01.jpg)，可能比![装饰器设计技术](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/fp-py/img/B03652_11_02.jpg)更能表达复杂算法。对于表达复杂处理，有多种语法替代方式通常是有帮助的。

# 装饰器作为高阶函数

装饰器的核心思想是将一些原始函数转换为另一种形式。装饰器创建了一种基于装饰器和被装饰的原始函数的复合函数。

装饰器函数可以用以下两种方式之一使用：

+   作为一个前缀，创建一个与基本函数同名的新函数，如下所示：

```py
@decorator
def original_function():
 **pass

```

+   作为一个显式操作，返回一个新的函数，可能有一个新的名称：

```py
def original_function():
 **pass
original_function= decorator(original_function)

```

这些是相同操作的两种不同语法。前缀表示法的优点是整洁和简洁。对于某些读者来说，前缀位置更加可见。后缀表示法是显式的，稍微更加灵活。虽然前缀表示法很常见，但使用后缀表示法的一个原因是：我们可能不希望结果函数替换原始函数。我们可能希望执行以下命令，允许我们同时使用装饰和未装饰的函数：

```py
new_function = decorator(original_function)

```

Python 函数是一等对象。接受函数作为参数并返回函数作为结果的函数显然是语言的内置特性。那么，我们如何更新或调整函数的内部代码结构呢？

答案是我们不需要。

与其在代码内部胡乱搞，不如定义一个包装原始函数的新函数更清晰。在定义装饰器时，我们涉及两个高阶函数层次：

+   装饰器函数将包装器应用于基本函数，并返回新的包装器。此函数可以作为构建装饰函数的一次性评估。

+   包装函数可以（通常会）评估基本函数。每次评估装饰函数时，都会评估此函数。

这是一个简单装饰器的例子：

```py
from functools import wraps
def nullable(function):
 **@wraps(function)
 **def null_wrapper(arg):
 **return None if arg is None else function(arg)
 **return null_wrapper

```

我们几乎总是希望使用`functools.wraps()`函数来确保装饰的函数保留原始函数的属性。例如，复制`__name__`和`__doc__`属性可以确保结果装饰的函数具有原始函数的名称和文档字符串。

所得到的复合函数，在装饰器的定义中称为`null_wrapper()`函数，也是一种高阶函数，它将原始函数`function()`函数与一个保留`None`值的表达式相结合。原始函数不是一个显式参数；它是一个自由变量，将从定义`wrapper()`函数的上下文中获取其值。

装饰器函数的返回值将返回新创建的函数。装饰器只返回函数，不会尝试处理任何数据。装饰器是元编程：创建代码的代码。然而，`wrapper()`函数将用于处理真实的数据。

我们可以应用我们的`@nullable`装饰器来创建一个复合函数，如下所示：

```py
nlog = nullable(math.log)

```

现在我们有了一个函数`nlog()`，它是`math.log()`函数的空值感知版本。我们可以使用我们的复合函数`nlog()`，如下所示：

```py
>>> some_data = [10, 100, None, 50, 60]
>>> scaled = map(nlog, some_data)** 
>>> list(scaled)
[2.302585092994046, 4.605170185988092, None, 3.912023005428146, 4.0943445622221]

```

我们已经将函数应用于一组数据值。`None`值礼貌地导致`None`结果。没有涉及异常处理。

### 注意

这个例子并不适合进行单元测试。我们需要对值进行四舍五入以进行测试。为此，我们还需要一个空值感知的`round()`函数。

以下是使用装饰符表示法创建空值感知舍入函数的方法：

```py
@nullable
def nround4(x):
 **return round(x,4)

```

这个函数是`round()`函数的部分应用，包装成空值感知。在某些方面，这是一种相对复杂的函数式编程，对 Python 程序员来说是很容易使用的。

我们还可以使用以下方法创建空值感知的四舍五入函数：

```py
nround4= nullable(lambda x: round(x,4))

```

这具有相同的效果，但在清晰度方面有一些成本。

我们可以使用`round4()`函数来创建一个更好的测试用例，用于我们的`nlog()`函数，如下所示：

```py
>>> some_data = [10, 100, None, 50, 60]
>>> scaled = map(nlog, some_data)
>>> [nround4(v) for v in scaled]
[2.3026, 4.6052, None, 3.912, 4.0943]

```

这个结果将独立于任何平台考虑。

这个装饰器假设被装饰的函数是一元的。我们需要重新审视这个设计，以创建一个更通用的空值感知装饰器，可以处理任意集合的参数。

在第十四章中，*PyMonad 库*，我们将看一种容忍`None`值的问题的替代方法。`PyMonad`库定义了一个`Maybe`对象类，它可能有一个适当的值，也可能是`None`值。

## 使用 functool 的 update_wrapper()函数

`@wraps`装饰器应用`update_wrapper()`函数以保留包装函数的一些属性。一般来说，这默认情况下就做了我们需要的一切。这个函数将一些特定的属性从原始函数复制到装饰器创建的结果函数中。具体的属性列表是什么？它由一个模块全局变量定义。

`update_wrapper()`函数依赖于一个模块全局变量来确定要保留哪些属性。`WRAPPER_ASSIGNMENTS`变量定义了默认情况下要复制的属性。默认值是要复制的属性列表：

```py
('__module__', '__name__', '__qualname__', '__doc__', '__annotations__')

```

对这个列表进行有意义的修改是困难的。为了复制额外的属性，我们必须确保我们的函数是用这些额外的属性定义的。这是具有挑战性的，因为`def`语句的内部不容易进行简单的修改或更改。

因为我们不能轻松地合并新的属性，所以很难找到修改或扩展包装函数工作方式的原因。将这个变量作为参考信息大多是有趣的。

如果我们要使用`callable`对象，那么我们可能会有一个类，它在定义中提供了一些额外的属性。然后我们可能会遇到这样一种情况，装饰器可能需要将这些额外的属性从原始的被包装的`callable`对象复制到正在创建的包装函数中。然而，似乎更简单的是在类定义本身中进行这些更改，而不是利用棘手的装饰器技术。

虽然有很多灵活性可用，但大部分对于普通应用程序开发并不有用。

# 横切关注点

装饰器背后的一个一般原则是允许我们从应用装饰器的原始函数和装饰器构建一个复合函数。这个想法是有一个常见装饰器库，可以为常见关注点提供实现。

我们经常称这些横切关注，因为它们适用于几个函数。这些是我们希望通过装饰器设计一次并在应用程序或框架中的相关类中应用的事物。

通常集中描述的关注点包括以下内容：

+   记录

+   审计

+   安全

+   处理不完整的数据

例如，`logging`装饰器可能会向应用程序的日志文件写入标准化消息。审计装饰器可能会写入围绕数据库更新的详细信息。安全装饰器可能会检查一些运行时上下文，以确保登录用户具有必要的权限。

我们的一个示例是对函数的*空值感知*包装器是一个横切关注。在这种情况下，我们希望有许多函数处理`None`值，而不是引发异常返回`None`值。在数据不完整的应用程序中，我们可能需要以简单、统一的方式处理行，而不必编写大量分散注意力的`if`语句来处理缺失值。

# 组合设计

复合函数的常见数学表示如下：

![组合设计](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/fp-py/img/B03652_11_03.jpg)

这个想法是我们可以定义一个新函数，![组合设计](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/fp-py/img/B03652_11_01.jpg)，它结合了另外两个函数，![组合设计](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/fp-py/img/B03652_11_04.jpg)和![组合设计](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/fp-py/img/B03652_11_05.jpg)。

Python 的多行定义形式如下：

```py
@f
def g(x):
 **something

```

这在某种程度上相当于![组合设计](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/fp-py/img/B03652_11_01.jpg)。等价性并不是非常精确，因为`@f`装饰器与组合![组合设计](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/fp-py/img/B03652_11_04.jpg)和![组合设计](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/fp-py/img/B03652_11_05.jpg)的数学抽象不同。在讨论函数组合的目的时，我们将忽略![组合设计](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/fp-py/img/B03652_11_04.jpg)的抽象和`@f`装饰器之间的实现断开连接。

因为装饰器包装另一个函数，Python 提供了一个稍微更一般化的组合。我们可以将 Python 设计思考如下：

![组合设计](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/fp-py/img/B03652_11_06.jpg)

装饰器应用于某些应用程序函数，![组合设计](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/fp-py/img/B03652_11_05.jpg)，将包括一个包装器函数。包装器的一部分，![组合设计](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/fp-py/img/B03652_11_07.jpg)，应用于包装函数之前，另一部分，![组合设计](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/fp-py/img/B03652_11_08.jpg)，应用于包装函数之后。

`Wrapper()`函数通常如下所示：

```py
@wraps(argument_function)
def something_wrapper(*args, **kw):
 **# The "before" part, w_α, applied to *args or **kw
 **result= argument_function(*args, **kw)
 **# the "after" part, w_β, applied to the result

```

细节会有所不同，而且差异很大。在这个一般框架内可以做很多聪明的事情。

大量的函数式编程归结为![组合设计](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/fp-py/img/B03652_11_02.jpg)种类的构造。我们经常拼写这些函数，因为将函数总结为一个组合，![组合设计](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/fp-py/img/B03652_11_01.jpg)，并没有真正的好处。然而，在某些情况下，我们可能希望使用一个高阶函数，比如`map()`、`filter()`或`reduce()`来使用一个复合函数。

我们总是可以使用`map(f, map(g, x))`方法。然而，使用`map(f_g, x)`方法来应用一个复合到一个集合可能更清晰。重要的是要注意，这两种技术都没有固有的性能优势。`map()`函数是惰性的：使用两个`map()`函数，一个项目将从`x`中取出，由`g()`函数处理，然后由`f()`函数处理。使用单个`map()`函数，一个项目将从`x`中取出，然后由`f_g()`复合函数处理。

在第十四章中，*PyMonad 库*，我们将看看从单独的柯里化函数创建复合函数的另一种方法。

## 预处理坏数据

在一些探索性数据分析应用中的一个横切关注点是如何处理丢失或无法解析的数值。我们经常有一些`float`、`int`和`Decimal`货币值的混合，我们希望以一定的一致性处理它们。

在其他情境中，我们有*不适用*或*不可用*的数据值，不应干扰计算的主线。允许`Not Applicable`值在不引发异常的情况下通过表达式通常很方便。我们将专注于三个坏数据转换函数：`bd_int()`、`bd_float()`和`bd_decimal()`。我们要添加的复合特性将在内置转换函数之前定义。

这是一个简单的坏数据装饰器：

```py
import decimal
def bad_data(function):
 **@wraps(function)
 **def wrap_bad_data(text, *args, **kw):
 **try:
 **return function(text, *args, **kw)
 **except (ValueError, decimal.InvalidOperation):
 **cleaned= text.replace(",", "")
 **return function(cleaned, *args, **kw)
 **return wrap_bad_data

```

这个函数包装了一个给定的转换函数，以尝试在第一次转换涉及坏数据时进行第二次转换。在保留`None`值作为`Not Applicable`代码的情况下，异常处理将简单地返回`None`值。

在这种情况下，我们提供了 Python 的`*args`和`**kw`参数。这确保了包装函数可以提供额外的参数值。

我们可以使用这个包装器如下：

```py
bd_int= bad_data(int)
bd_float= bad_data(float)
bd_decimal= bad_data(Decimal)

```

这将创建一套函数，可以对良好的数据进行转换，同时也可以进行有限的数据清洗，以处理特定类型的坏数据。

以下是使用`bd_int()`函数的一些示例：

```py
>>> bd_int("13")
13
>>> bd_int("1,371")
1371
>>> bd_int("1,371", base=16)
4977

```

我们已经将`bd_int()`函数应用于一个字符串，它转换得很整洁，还有一个带有特定类型标点符号的字符串，我们将容忍它。我们还表明我们可以为每个转换函数提供额外的参数。

我们可能希望有一个更灵活的装饰器。我们可能希望添加的一个功能是处理各种数据清洗的能力。简单的`,`移除并不总是我们需要的。我们可能还需要移除`$`或`°`符号。我们将在下一节中看到更复杂的、带参数的装饰器。

# 向装饰器添加参数

一个常见的要求是使用额外的参数自定义装饰器。我们不仅仅是创建一个复合的![向装饰器添加参数](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/fp-py/img/B03652_11_01.jpg)，我们做的事情要复杂一些。我们正在创建![向装饰器添加参数](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/fp-py/img/B03652_11_09.jpg)。我们应用了一个参数，*c*，作为创建包装器的一部分。这个参数化的复合物，![向装饰器添加参数](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/fp-py/img/B03652_11_10.jpg)，然后可以与实际数据*x*一起使用。

在 Python 语法中，我们可以写成如下形式：

```py
@deco(arg)
def func( ):
 **something

```

这将为基本函数定义提供一个参数化的`deco(arg)`函数。

效果如下：

```py
def func( ):
 **something
func= deco(arg)(func)

```

我们已经做了三件事，它们如下：

1.  定义一个函数`func.`

1.  将抽象装饰器`deco()`应用于其参数，以创建一个具体的装饰器`deco(arg).`

1.  将具体的装饰器`deco(arg)`应用于基本函数，以创建函数的装饰版本`deco(arg)(func).`

带有参数的装饰器涉及间接构建最终函数。我们似乎已经超越了仅仅是高阶函数，进入了更抽象的领域：创建高阶函数的高阶函数。

我们可以扩展我们的*bad-data*感知装饰器，以创建一个稍微更灵活的转换。我们将定义一个可以接受要移除的字符参数的装饰器。以下是一个带参数的装饰器：

```py
import decimal
def bad_char_remove(*char_list):
 **def cr_decorator(function):
 **@wraps(function)
 **def wrap_char_remove(text, *args, **kw):
 **try:
 **return function(text, *args, **kw)
 **except (ValueError, decimal.InvalidOperation):
 **cleaned= clean_list(text, char_list)
 **return function(cleaned, *args, **kw)
 **return wrap_char_remove
 **return cr_decorator

```

一个带参数的装饰器有三个部分，它们如下：

+   整体装饰器。这定义并返回抽象装饰器。在这种情况下，`cr_decorator`是一个抽象装饰器。它有一个自由变量`char_list`，来自初始装饰器。

+   抽象装饰器。在这种情况下，`cr_decorator` 装饰器将绑定其自由变量 `char_list`，以便可以应用到一个函数。

+   装饰包装器。在这个例子中，`wrap_char_remove` 函数将替换被包装的函数。由于 `@wraps` 装饰器，`__name__`（和其他属性）将被替换为被包装的函数的名称。

我们可以使用这个装饰器来创建转换函数，如下所示：

```py
@bad_char_remove("$", ",")
def currency(text, **kw):
 **return Decimal(text, **kw)

```

我们已经使用我们的装饰器来包装一个 `currency()` 函数。`currency()` 函数的基本特征是对 `decimal.Decimal` 构造函数的引用。

这个 `currency()` 函数现在将处理一些变体数据格式：

```py
>>> currency("13")
Decimal('13')
>>> currency("$3.14")
Decimal('3.14')
>>> currency("$1,701.00")
Decimal('1701.00')

```

我们现在可以使用相对简单的 `map(currency, row)` 方法来处理输入数据，将源数据从字符串转换为可用的 `Decimal` 值。`try:/except:` 错误处理已经被隔离到一个函数中，我们用它来构建一个复合转换函数。

我们可以使用类似的设计来创建空值容忍函数。这些函数将使用类似的 `try:/except:` 包装器，但只会返回 `None` 值。

# 实现更复杂的描述符

我们可以轻松地编写以下命令：

```py
@f_wrap
@g_wrap
def h(x):
 **something

```

Python 中没有任何阻止我们的东西。这有一些类似于 ![实现更复杂的描述符](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/fp-py/img/B03652_11_11.jpg)。然而，名称仅仅是 ![实现更复杂的描述符](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/fp-py/img/B03652_11_12.jpg)。因此，当创建涉及深度嵌套描述符的函数时，我们需要谨慎。如果我们的意图只是处理一些横切关注，那么每个装饰器可以处理一个关注而不会造成太多混乱。

另一方面，如果我们使用装饰来创建一个复合函数，那么使用以下命令可能更好：

```py
f_g_h= f_wrap(g_wrap(h))

```

这澄清了正在发生的事情。装饰器函数并不完全对应于函数被组合的数学抽象。装饰器函数实际上包含一个包装器函数，该包装器函数将包含被组合的函数。当尝试理解应用程序时，函数和创建函数组合的装饰器之间的区别可能会成为一个问题。

与函数式编程的其他方面一样，简洁和表达力是目标。具有表达力的装饰器是受欢迎的。编写一个可以在应用程序中完成所有事情的超级可调用函数，只需要进行轻微的定制，可能是简洁的，但很少是表达性的。

# 识别设计限制

在我们的数据清理的情况下，简单地去除杂散字符可能是不够的。在处理地理位置数据时，我们可能会有各种各样的输入格式，包括简单的度数（`37.549016197`），度和分钟（`37° 32.94097′`），以及度-分-秒（`37° 32′ 56.46″`）。当然，还可能存在更微妙的清理问题：一些设备会创建一个带有 Unicode U+00BA 字符 `º` 的输出，而不是类似的度字符 `°`，它是 U+00B0。

因此，通常需要提供一个单独的清理函数，与转换函数捆绑在一起。这个函数将处理输入格式非常不一致的输入所需的更复杂的转换，比如纬度和经度。

我们如何实现这个？我们有很多选择。简单的高阶函数是一个不错的选择。另一方面，装饰器并不是一个很好的选择。我们将看一个基于装饰器的设计，以了解装饰器的合理性有限制。

要求有两个正交设计考虑，它们如下：

1.  输出转换（`int`，`float`，`Decimal`）

1.  输入清理（清除杂散字符，重新格式化坐标）

理想情况下，其中一个方面是一个被包装的基本函数，另一个方面是通过包装器包含的内容。本质与包装的选择并不清晰。其中一个原因是我们之前的例子比简单的两部分组合要复杂一些。

在之前的例子中，我们实际上创建了一个三部分的组合：

+   输出转换（`int`，`float`，`Decimal`）

+   输入清洁——可以是简单的替换，也可以是更复杂的多字符替换

+   尝试转换的函数，作为对异常的响应进行清洁，并再次尝试转换

第三部分——尝试转换和重试——实际上是包装器，也是组合函数的一部分。正如我们之前提到的，包装器包含一个前阶段和一个后阶段，我们分别称之为![识别设计限制](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/fp-py/img/B03652_11_07.jpg)和![识别设计限制](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/fp-py/img/B03652_11_08.jpg)。

我们想要使用这个包装器来创建两个额外函数的组合。对于语法，我们有两种选择。我们可以将清洁函数作为装饰器的参数包含在转换中，如下所示：

```py
@cleanse_before(cleanser)
def convert(text):
 **something

```

或者，我们可以将转换函数作为清洁函数的装饰器的参数包含如下：

```py
@then_convert(converter)
def clean(text):
 **something

```

在这种情况下，我们可以选择`@then_convert(converter)`样式的装饰器，因为我们在很大程度上依赖于内置转换。我们的观点是要表明选择并不是非常清晰的。

装饰器如下所示：

```py
def then_convert(convert_function):
 **def clean_convert_decorator(clean_function):
 **@wraps(clean_function)
 **def cc_wrapper(text, *args, **kw):
 **try:
 **return convert_function(text, *args, **kw)
 **except (ValueError, decimal.InvalidOperation):
 **cleaned= clean_function(text)
 **return convert_function(cleaned, *args, **kw)
 **return cc_wrapper
 **return clean_convert_decorator

```

我们定义了一个三层装饰器。核心是`cc_wrapper()`函数，应用`convert_function`函数。如果失败，它会使用`clean_function`函数，然后再次尝试`convert_function`函数。这个函数被`then_convert_decorator()`具体装饰器函数包裹在`clean_function`函数周围。具体装饰器具有`convert_function`函数作为自由变量。具体装饰器由装饰器接口`then_convert()`创建，该接口由转换函数定制。

现在我们可以构建一个稍微更灵活的清洁和转换函数，如下所示：

```py
@then_convert(int)
def drop_punct(text):
 **return text.replace(",", "").replace("$", "")

```

整数转换是应用于给定清洁函数的装饰器。在这种情况下，清洁函数移除了`$`和`,`字符。整数转换包裹在这个清洁函数周围。

我们可以如下使用整数转换：

```py
>>> drop_punct("1,701")
1701
>>> drop_punct("97")
97

```

虽然这可以将一些复杂的清洁和转换封装成一个非常整洁的包，但结果可能令人困惑。函数的名称是核心清洁算法的名称；另一个函数对组合的贡献被忽略了。

作为替代，我们可以如下使用整数转换：

```py
def drop_punct(text):
 **return text.replace(",", "").replace("$", "")
drop_punct_int = then_convert(int)(drop_punct)

```

这将允许我们为装饰的清洁函数提供一个新的名称。这解决了命名问题，但是通过`then_convert(int)(drop_punct)`方法构建最终函数的过程相当不透明。

看起来我们已经触及了边界。装饰器模式并不适合这种设计。一般来说，当我们有一些相对简单和固定的方面要与给定的函数（或类）一起包含时，装饰器的效果很好。当这些额外的方面可以被看作是基础设施或支持，而不是应用代码含义的重要部分时，装饰器也很重要。

对于涉及多个正交维度的事物，我们可能希望使用各种插件策略对象的`Callables`函数。这可能提供更可接受的东西。我们可能需要仔细研究创建高阶函数。然后，我们可以为高阶函数的各种参数组合创建部分函数。

典型的日志记录或安全测试示例可以被视为与问题域无关的后台处理类型。当我们的处理与我们周围的空气一样普遍时，那么装饰器可能更合适。

# 总结

在本章中，我们看了两种类型的装饰器：没有参数的简单装饰器和带参数的装饰器。我们看到装饰器涉及函数之间的间接组合：装饰器将一个函数（在装饰器内部定义）包裹在另一个函数周围。

使用`functools.wraps()`装饰器可以确保我们的装饰器能够正确地从被包装的函数中复制属性。这应该是我们编写的每个装饰器的一部分。

在下一章中，我们将看一下可用于我们的多进程和多线程技术。这些包在函数式编程环境中特别有帮助。当我们消除复杂的共享状态并设计非严格处理时，我们可以利用并行性来提高性能。
