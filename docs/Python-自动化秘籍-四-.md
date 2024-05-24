# Python 自动化秘籍（四）

> 原文：[`zh.annas-archive.org/md5/de38d8b70825b858336fa5194110e245`](https://zh.annas-archive.org/md5/de38d8b70825b858336fa5194110e245)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：开发令人惊叹的图表

本章将涵盖以下示例：

+   绘制简单的销售图表

+   绘制堆叠条形图

+   绘制饼图

+   显示多条线。

+   绘制散点图

+   可视化地图

+   添加图例和注释

+   组合图表

+   保存图表

# 介绍

图表和图像是呈现复杂数据的绝妙方式，易于理解。在本章中，我们将利用强大的`matplotlib`库来学习如何创建各种图表。`matplotlib`是一个旨在以多种方式显示数据的库，它可以创建绝对令人惊叹的图表，有助于以最佳方式传输和显示信息。

我们将涵盖的图表将从简单的条形图到线图或饼图，并结合多个图表在同一图表中，注释它们，甚至绘制地理地图。

# 绘制简单的销售图表

在这个示例中，我们将看到如何通过绘制与不同时期销售成比例的条形来绘制销售图表。

# 准备工作

我们可以使用以下命令在我们的虚拟环境中安装`matplotlib`：

```py
$ echo "matplotlib==2.2.2" >> requirements.txt
$ pip install -r requirements.txt
```

在某些操作系统中，这可能需要我们安装额外的软件包；例如，在 Ubuntu 中可能需要我们运行`apt-get install python3-tk`。查看`matplolib`文档以获取详细信息。

如果您使用的是 macOS，可能会出现这样的错误—`RuntimeError: Python is not installed as a framework`。请参阅`matplolib`文档以了解如何解决：[`matplotlib.org/faq/osx_framework.html`](https://matplotlib.org/faq/osx_framework.html)。

# 如何做...

1.  导入`matplotlib`：

```py
>>> import matplotlib.pyplot as plt
```

1.  准备要在图表上显示的数据：

```py
>>> DATA = (
...    ('Q1 2017', 100),
...    ('Q2 2017', 150),
...    ('Q3 2017', 125),
...    ('Q4 2017', 175),
... )
```

1.  将数据拆分为图表可用的格式。这是一个准备步骤：

```py
>>> POS = list(range(len(DATA)))
>>> VALUES = [value for label, value in DATA]
>>> LABELS = [label for label, value in DATA]
```

1.  创建一个带有数据的条形图：

```py
>>> plt.bar(POS, VALUES)
>>> plt.xticks(POS, LABELS)
>>> plt.ylabel('Sales')
```

1.  显示图表：

```py
>>> plt.show()
```

1.  结果将在新窗口中显示如下：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-auto-cb/img/bd9e3f18-0570-48cd-8817-7a9d8dca9732.png)

# 它是如何工作的...

导入模块后，数据将以方便的方式呈现在第 2 步的*如何做*部分中，这很可能类似于数据最初的存储方式。

由于`matplotlib`的工作方式，它需要*X*组件以及*Y*组件。在这种情况下，我们的*X*组件只是一系列整数，与数据点一样多。我们在`POS`中创建了这个。在`VALUES`中，我们将销售的数值存储为一个序列，在`LABELS`中存储了每个数据点的相关标签。所有这些准备工作都在第 3 步完成。

第 4 步创建了条形图，使用了*X*（`POS`）和*Y*（`VALUES`）的序列。这些定义了我们的条形。为了指定它所指的时期，我们使用`.xticks`在*x*轴上为每个值放置标签。为了澄清含义，我们使用`.ylabel`添加标签。

要显示结果图表，第 5 步调用`.show`，它会打开一个新窗口显示结果。

调用`.show`会阻止程序的执行。当窗口关闭时，程序将恢复。

# 还有更多...

您可能希望更改值的呈现格式。在我们的示例中，也许数字代表数百万美元。为此，您可以向*y*轴添加格式化程序，以便在那里表示的值将应用于它们：

```py
>>> from matplotlib.ticker import FuncFormatter

>>> def value_format(value, position):
...    return '$ {}M'.format(int(value))

>>> axes = plt.gca()
>>> axes.yaxis.set_major_formatter(FuncFormatter(value_format))
```

`value_format`是一个根据数据的值和位置返回值的函数。在这里，它将返回值 100 作为`$ 100 M`。

值将以浮点数形式检索，需要将它们转换为整数进行显示。

要应用格式化程序，我们需要使用`.gca`（获取当前轴）检索`axis`对象。然后，`.yaxis`获取格式化程序。

条的颜色也可以使用`color`参数确定。颜色可以以多种格式指定，如[`matplotlib.org/api/colors_api.html`](https://matplotlib.org/api/colors_api.html)中所述，但我最喜欢的是遵循 XKCD 颜色调查，使用`xkcd:`前缀（冒号后没有空格）：

```py
>>> plt.bar(POS, VALUES, color='xkcd:moss green')
```

完整的调查可以在这里找到：[`xkcd.com/color/rgb/`](https://xkcd.com/color/rgb/)。

大多数常见的颜色，如蓝色或红色，也可以用于快速测试。但它们往往有点亮，不能用于漂亮的报告。

将颜色与格式化轴结合起来，得到以下结果：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-auto-cb/img/2487d3fa-1b81-4594-97ba-1b5dfafbd44e.png)

条形图不一定需要以时间顺序显示信息。正如我们所见，`matplotlib`要求我们指定每个条的*X*参数。这是一个生成各种图表的强大工具。

例如，可以安排条形以显示直方图，比如显示特定身高的人。条形将从较低的高度开始增加到平均大小，然后再降低。不要局限于电子表格图表！

完整的`matplotlib`文档可以在这里找到：[`matplotlib.org/`](https://matplotlib.org/)。

# 另请参阅

+   *绘制堆叠条形图*的方法

+   *添加图例和注释*的方法

+   *组合图表*的方法

# 绘制堆叠条形图

一种强大的显示不同类别的方法是将它们呈现为堆叠条形图，因此每个类别和总数都会显示出来。我们将在这个方法中看到如何做到这一点。

# 准备就绪

我们需要在虚拟环境中安装`matplotlib`：

```py
$ echo "matplotlib==2.2.2" >> requirements.txt
$ pip install -r requirements.txt
```

如果您使用的是 macOS，可能会出现这样的错误：`RuntimeError: Python is not installed as a framework`。请参阅`matplolib`文档以了解如何解决：[`matplotlib.org/faq/osx_framework.html`](https://matplotlib.org/faq/osx_framework.html)。

# 如何做...

1.  导入`matplotlib`：

```py
>>> import matplotlib.pyplot as plt
```

1.  准备数据。这代表了两种产品的销售，一个是已建立的，另一个是新产品：

```py
>>> DATA = (
...     ('Q1 2017', 100, 0),
...     ('Q2 2017', 105, 15),
...     ('Q3 2017', 125, 40),
...     ('Q4 2017', 115, 80),
... )
```

1.  处理数据以准备期望的格式：

```py
>>> POS = list(range(len(DATA)))
>>> VALUESA = [valueA for label, valueA, valueB in DATA]
>>> VALUESB = [valueB for label, valueA, valueB in DATA]
>>> LABELS = [label for label, value1, value2 in DATA]
```

1.  创建条形图。需要两个图：

```py
>>> plt.bar(POS, VALUESB)
>>> plt.bar(POS, VALUESA, bottom=VALUESB)
>>> plt.ylabel('Sales')
>>> plt.xticks(POS, LABELS)
```

1.  显示图表：

```py
>>> plt.show()
```

1.  结果将显示在一个新窗口中，如下所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-auto-cb/img/6d97abab-342a-4cee-b175-3786b4ae9dd5.png)

# 它是如何工作的...

导入模块后，在第 2 步以一种方便的方式呈现数据，这可能与数据最初存储的方式类似。

在第 3 步中，数据准备为三个序列，`VALUESA`，`VALUEB`和`LABELS`。添加了一个`POS`序列以正确定位条形。

第 4 步创建了条形图，使用了序列*X*（`POS`）和*Y*（`VALUESB`）。第二个条形序列`VALUESA`添加到前一个上面，使用`bottom`参数。这样就堆叠了条形。

请注意，我们首先堆叠第二个值`VALUESB`。第二个值代表市场上推出的新产品，而`VALUESA`更加稳定。这更好地显示了新产品的增长。

每个期间都在*X*轴上用`.xticks`标记。为了澄清含义，我们使用`.ylabel`添加标签。

要显示生成的图表，第 5 步调用`.show`，这将打开一个新窗口显示结果。

调用`.show`会阻止程序的执行。当窗口关闭时，程序将恢复。

# 还有更多...

呈现堆叠条形的另一种方法是将它们添加为百分比，这样总数不会改变，只是相对大小相互比较。

为了做到这一点，需要根据百分比计算`VALUESA`和`VALUEB`：

```py
>>> VALUESA = [100 * valueA / (valueA + valueB) for label, valueA, valueB in DATA]
>>> VALUESB = [100 * valueB / (valueA + valueB) for label, valueA, valueB in DATA]
```

这使得每个值都等于总数的百分比，总数始终加起来为`100`。这产生了以下图形：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-auto-cb/img/f1270a74-2f03-49e2-b731-c2a539e6a774.png)

条形不一定需要堆叠。有时，将条形相互对比呈现可能会更有趣。

为了做到这一点，我们需要移动第二个条形序列的位置。我们还需要设置更细的条形以留出空间：

```py
>>> WIDTH = 0.3
>>> plt.bar([p - WIDTH / 2 for p in POS], VALUESA, width=WIDTH)
>>> plt.bar([p + WIDTH / 2 for p in POS], VALUESB, width=WIDTH)
```

注意条的宽度设置为空间的三分之一，因为我们的参考空间在条之间是`1`。第一根条移到左边，第二根移到右边以使它们居中。已删除`bottom`参数，以不堆叠条形：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-auto-cb/img/7cd52074-9e8e-4407-ae9f-e751c8e64e3f.png)

完整的`matplotlib`文档可以在这里找到：[`matplotlib.org/`](https://matplotlib.org/)。

# 另请参阅

+   *绘制简单销售图表*食谱

+   *添加图例和注释*食谱

+   *组合图表*食谱

# 绘制饼图

饼图！商业 101 最喜欢的图表，也是呈现百分比的常见方式。在这个食谱中，我们将看到如何绘制一个饼图，不同的切片代表不同的比例。

# 准备工作

我们需要使用以下命令在虚拟环境中安装`matplotlib`：

```py
$ echo "matplotlib==2.2.2" >> requirements.txt
$ pip install -r requirements.txt
```

如果您使用的是 macOS，可能会出现这样的错误——`RuntimeError: Python is not installed as a framework`。请参阅`matplotlib`文档以了解如何解决此问题：[`matplotlib.org/faq/osx_framework.html`](https://matplotlib.org/faq/osx_framework.html)。

# 如何做...

1.  导入`matplotlib`：

```py
>>> import matplotlib.pyplot as plt
```

1.  准备数据。这代表了几条产品线：

```py
>>> DATA = (
...     ('Common', 100),
...     ('Premium', 75),
...     ('Luxurious', 50),
...     ('Extravagant', 20),
... )
```

1.  处理数据以准备预期格式：

```py
>>> VALUES = [value for label, value in DATA]
>>> LABELS = [label for label, value in DATA]
```

1.  创建饼图：

```py
>>> plt.pie(VALUES, labels=LABELS, autopct='%1.1f%%')
>>> plt.gca().axis('equal')
```

1.  显示图表：

```py
>>> plt.show()
```

1.  结果将显示在新窗口中，如下所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-auto-cb/img/d11a4172-49d1-4df0-a0a9-df33e6bb7c10.png)

# 工作原理...

在*如何做...*部分的第 1 步中导入了该模块，并在第 2 步中导入了要呈现的数据。在第 3 步中，数据被分成两个部分，一个是`VALUES`的列表，另一个是`LABELS`的列表。

图表的创建发生在第 4 步。饼图是通过添加`VALUES`和`LABELS`来创建的。`autopct`参数格式化值，以便将其显示为百分比到小数点后一位。

对`axis`的调用确保饼图看起来是圆形的，而不是有一点透视并呈现为椭圆。

要显示生成的图表，第 5 步调用`.show`，它会打开一个新窗口显示结果。

调用`.show`会阻塞程序的执行。当窗口关闭时，程序将恢复。

# 还有更多...

饼图在商业图表中有点过度使用。大多数情况下，使用带百分比或值的条形图会更好地可视化数据，特别是当显示两个或三个以上的选项时。尽量限制在报告和数据演示中使用饼图。

通过`startangle`参数可以旋转楔形的起始位置，使用`counterclock`来设置楔形的方向（默认为`True`）：

```py
>>> plt.pie(VALUES, labels=LABELS, startangle=90, counterclock=False)
```

标签内的格式可以通过函数设置。由于饼图内的值被定义为百分比，找到原始值可能有点棘手。以下代码片段创建了一个按整数百分比索引的字典，因此我们可以检索引用的值。请注意，这假设没有重复的百分比。如果有这种情况，标签可能会略有不正确。在这种情况下，我们可能需要使用更好的精度，最多使用小数点后一位：

```py
>>> from matplotlib.ticker import FuncFormatter

>>> total = sum(value for label, value in DATA)
>>> BY_VALUE = {int(100 * value / total): value for label, value in DATA}

>>> def value_format(percent, **kwargs):
...     value = BY_VALUE[int(percent)]
...     return '{}'.format(value)
```

一个或多个楔形也可以通过使用 explode 参数分开。这指定了楔形与中心的分离程度：

```py
>>> explode = (0, 0, 0.1, 0)
>>> plt.pie(VALUES, labels=LABELS, explode=explode, autopct=value_format,
            startangle=90, counterclock=False)
```

结合所有这些选项，我们得到以下结果：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-auto-cb/img/907bd5d6-c5cb-49cb-8f51-29aebf936ed1.png)

完整的`matplotlib`文档可以在这里找到：[`matplotlib.org/`](https://matplotlib.org/)。

# 另请参阅

+   *绘制简单销售图表*食谱

+   *绘制堆叠条形图*食谱

# 显示多条线

这个食谱将展示如何在图表中显示多条线。

# 准备工作

我们需要在虚拟环境中安装`matplotlib`：

```py
$ echo "matplotlib==2.2.2" >> requirements.txt
$ pip install -r requirements.txt
```

如果您使用的是 macOS，可能会出现这样的错误——`RuntimeError: Python is not installed as a framework`。请参阅`matplolib`文档以了解如何解决此问题：[`matplotlib.org/faq/osx_framework.html`](https://matplotlib.org/faq/osx_framework.html)。

# 如何做...

1.  导入`matplotlib`：

```py
>>> import matplotlib.pyplot as plt
```

1.  准备数据。这代表了两种产品的销售：

```py
>>> DATA = (
...     ('Q1 2017', 100, 5),
...     ('Q2 2017', 105, 15),
...     ('Q3 2017', 125, 40),
...     ('Q4 2017', 115, 80),
... )
```

1.  处理数据以准备预期格式：

```py
>>> POS = list(range(len(DATA)))
>>> VALUESA = [valueA for label, valueA, valueB in DATA]
>>> VALUESB = [valueB for label, valueA, valueB in DATA]
>>> LABELS = [label for label, value1, value2 in DATA]
```

1.  创建线图。需要两条线：

```py
>>> plt.plot(POS, VALUESA, 'o-')
>>> plt.plot(POS, VALUESB, 'o-')
>>> plt.ylabel('Sales')
>>> plt.xticks(POS, LABELS)
```

1.  显示图表：

```py
>>> plt.show()
```

1.  结果将显示在一个新窗口中：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-auto-cb/img/defcbfbe-a08d-4ed8-b19d-b03b82ef8552.png)

# 工作原理…

在*如何做…*部分，第 1 步导入模块，第 2 步以格式化的方式显示要绘制的数据。

在第 3 步中，数据准备好了三个序列`VALUESA`，`VALUEB`和`LABELS`。添加了一个`POS`序列来正确定位每个点。

第 4 步创建了图表，使用了序列*X*（`POS`）和*Y*（`VALUESA`），然后是`POS`和`VALUESB`。添加了值为`'o-'`，以在每个数据点上绘制一个圆圈，并在它们之间绘制一条实线。

默认情况下，图表将显示一条实线，每个点上没有标记。如果只使用标记（即`'o'`），就不会有线。

*X*轴上的每个周期都带有`.xticks`标签。为了澄清含义，我们使用`.ylabel`添加了一个标签。

要显示结果图表，第 5 步调用`.show`，它会打开一个新窗口显示结果。

调用`.show`会阻塞程序的执行。当窗口关闭时，程序将恢复。

# 还有更多…

带有线条的图表看起来简单，能够创建许多有趣的表示。在显示数学图表时，这可能是最方便的。例如，我们可以用几行代码显示 Moore 定律的图表。

摩尔定律是戈登·摩尔观察到的一个现象，即集成电路中的元件数量每两年翻一番。它首次在 1965 年被描述，然后在 1975 年得到修正。它似乎与过去 40 年的技术进步历史速度非常接近。

我们首先创建了一条描述理论线的线，数据点从 1970 年到 2013 年。从 1000 个晶体管开始，每两年翻一番，直到 2013 年：

```py
>>> POS = [year for year in range(1970, 2013)]
>>> MOORES = [1000 * (2 ** (i * 0.5)) for i in range(len(POS))]
>>> plt.plot(POS, MOORES)
```

根据一些文档，我们从这里提取了一些商用 CPU 的例子，它们的发布年份以及集成元件的数量：[`www.wagnercg.com/Portals/0/FunStuff/AHistoryofMicroprocessorTransistorCount.pdf`](http://www.wagnercg.com/Portals/0/FunStuff/AHistoryofMicroprocessorTransistorCount.pdf)。由于数字很大，我们将使用 Python 3 中的`1_000_000`表示一百万：

```py
>>> DATA = (
...    ('Intel 4004', 2_300, 1971),
...    ('Motorola 68000', 68_000, 1979),
...    ('Pentium', 3_100_000, 1993),
...    ('Core i7', 731_000_000, 2008),
... )
```

绘制一条带有标记的线，以在正确的位置显示这些点。`'v'`标记将显示一个三角形：

```py
>>> data_x = [x for label, y, x in DATA]
>>> data_y = [y for label, y, x in DATA]
>>> plt.plot(data_x, data_y, 'v')
```

对于每个数据点，将一个标签附加在正确的位置，标有 CPU 的名称：

```py
>>> for label, y, x in DATA:
>>>    plt.text(x, y, label)
```

最后，成长在线性图表中没有意义，因此我们将比例改为对数，这样指数增长看起来像一条直线。但为了保持尺度的意义，添加一个网格。调用`.show`显示图表：

```py
>>> plt.gca().grid()
>>> plt.yscale('log')
```

结果图将显示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-auto-cb/img/bc851b15-ef70-481c-b08e-51b3879cfb60.png)

完整的`matplotlib`文档可以在这里找到：[`matplotlib.org/`](https://matplotlib.org/)。特别是，可以在这里检查线条（实线、虚线、点线等）和标记（点、圆圈、三角形、星形等）的可用格式：[`matplotlib.org/api/_as_gen/matplotlib.pyplot.plot.html`](https://matplotlib.org/api/_as_gen/matplotlib.pyplot.plot.html)。

# 另请参阅

+   *添加图例和注释*配方

+   *组合图表*配方

# 绘制散点图

散点图是一种只显示为点的信息，具有*X*和*Y*值。当呈现样本并查看两个变量之间是否存在关系时，它们非常有用。在这个配方中，我们将显示一个图表，绘制在网站上花费的时间与花费的金钱，以查看是否可以看到一个模式。

# 准备就绪

我们需要在虚拟环境中安装`matplotlib`：

```py
$ echo "matplotlib==2.2.2" >> requirements.txt
$ pip install -r requirements.txt
```

如果您使用的是 macOS，可能会出现这样的错误——`RuntimeError: Python is not installed as a framework`。请参阅`matplolib`文档，了解如何解决此问题：[`matplotlib.org/faq/osx_framework.html`](https://matplotlib.org/faq/osx_framework.html)。

作为数据点，我们将使用`scatter.csv`文件来读取数据。此文件可在 GitHub 上找到：[`github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/Chapter07/scatter.csv`](https://github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/Chapter07/scatter.csv)。

# 如何做...

1.  导入`matplotlib`和`csv`。还导入`FuncFormatter`以稍后格式化轴：

```py
>>> import csv
>>> import matplotlib.pyplot as plt
>>> from matplotlib.ticker import FuncFormatter
```

1.  准备数据，使用`csv`模块从文件中读取：

```py
>>> with open('scatter.csv') as fp:
...    reader = csv.reader(fp)
...    data = list(reader)
```

1.  准备绘图数据，然后绘制：

```py
>>> data_x = [float(x) for x, y in data]
>>> data_y = [float(y) for x, y in data]
>>> plt.scatter(data_x, data_y)
```

1.  通过格式化轴来改善上下文：

```py
>>> def format_minutes(value, pos):
...     return '{}m'.format(int(value))
>>> def format_dollars(value, pos):
...     return '${}'.format(value)
>>> plt.gca().xaxis.set_major_formatter(FuncFormatter(format_minutes))
>>> plt.xlabel('Time in website')
>>> plt.gca().yaxis.set_major_formatter(FuncFormatter(format_dollars))
>>> plt.ylabel('Spending')
```

1.  显示图表：

```py
>>> plt.show()
```

1.  结果将显示在新窗口中：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-auto-cb/img/ced40fbf-6f2b-4eb1-b8b9-f5483b9f4989.png)

# 工作原理...

*如何做…*部分的步骤 1 和 2 导入了我们稍后将使用的模块并从 CSV 文件中读取数据。数据被转换为列表，以允许我们多次迭代，这在第 3 步中是必要的。

第 3 步将数据准备为两个数组，然后使用`.scatter`来绘制它们。与`matplotlib`的其他方法一样，`.scatter`的参数需要*X*和*Y*值的数组。它们都需要具有相同的大小。数据从文件格式转换为`float`，以确保数字格式。

第 4 步改进了数据在每个轴上的呈现方式。相同的操作被呈现两次——创建一个函数来定义该轴上的值应该如何显示（以美元或分钟）。该函数接受要显示的值和位置作为输入。通常，位置将被忽略。轴格式化程序将被覆盖为`.set_major_formatter`。请注意，两个轴都将使用`.gca`（获取当前轴）返回。

使用`.xlabel`和`.ylabel`向轴添加标签。

最后，第 5 步在新窗口中显示图表。分析结果，我们可以说似乎有两种用户，一些用户花费不到 10 分钟，从不花费超过 10 美元，还有一些用户花费更多时间，也更有可能花费高达 100 美元。

请注意，所呈现的数据是合成的，并且已经根据结果生成。现实生活中的数据可能看起来更分散。

# 还有更多...

散点图不仅可以显示二维空间中的点，还可以添加第三个（面积）甚至第四个维度（颜色）。

要添加这些元素，使用参数`s`表示*大小*，`c`表示*颜色*。

大小被定义为点的直径的平方。因此，对于直径为 10 的球，将使用 100。颜色可以使用`matplotlib`中颜色的任何常规定义，例如十六进制颜色、RGB 等。有关更多详细信息，请参阅文档：[`matplotlib.org/users/colors.html`](https://matplotlib.org/users/colors.html)。例如，我们可以使用以下方式生成一个随机图表的四个维度：

```py
>>> import matplotlib.pyplot as plt
>>> import random
>>> NUM_POINTS = 100
>>> COLOR_SCALE = ['#FF0000', '#FFFF00', '#FFFF00', '#7FFF00', '#00FF00']
>>> data_x = [random.random() for _ in range(NUM_POINTS)]
>>> data_y = [random.random() for _ in range(NUM_POINTS)]
>>> size = [(50 * random.random()) ** 2 for _ in range(NUM_POINTS)]
>>> color = [random.choice(COLOR_SCALE) for _ in range(NUM_POINTS)]
>>> plt.scatter(data_x, data_y, s=size, c=color, alpha=0.5)
>>> plt.show()
```

`COLOR_SCALE`从绿色到红色，每个点的大小将在`0`到`50`之间。结果应该是这样的：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-auto-cb/img/ab8e4b1e-6dfa-4367-8e57-47e7557c5f45.png)

请注意，这是随机的，因此每次都会生成不同的图表。

`alpha`值使每个点半透明，使我们能够看到它们重叠的位置。该值越高，点的透明度越低。此参数将影响显示的颜色，因为它将点与背景混合。

尽管可以在大小和颜色中显示两个独立的值，但它们也可以与任何其他值相关联。例如，使颜色依赖于大小将使所有相同大小的点具有相同的颜色，这可能有助于区分数据。请记住，图表的最终目标是使数据易于理解。尝试不同的方法来改进这一点。

完整的`matplotlib`文档可以在这里找到：[`matplotlib.org/`](https://matplotlib.org/)。

# 另请参阅

+   *显示多行*的方法

+   *添加图例和注释*的方法

# 可视化地图

要显示从区域到区域变化的信息，最好的方法是显示一张呈现信息的地图，同时为数据提供区域位置和位置的感觉。

在此示例中，我们将利用`fiona`模块导入 GIS 信息，以及`matplotlib`来显示信息。 我们将显示西欧的地图，并显示每个国家的人口与颜色等级。 颜色越深，人口越多。

# 准备工作

我们需要在虚拟环境中安装`matplotlib`和`fiona`：

```py
$ echo "matplotlib==2.2.2" >> requirements.txt
$ echo "Fiona==1.7.13" >> requirements.txt
$ pip install -r requirements.txt
```

如果您使用的是 macOS，可能会出现这样的错误-`RuntimeError: Python is not installed as a framework`。 请参阅`matplolib`文档以了解如何解决此问题：[`matplotlib.org/faq/osx_framework.html`](https://matplotlib.org/faq/osx_framework.html)。

需要下载地图数据。 幸运的是，有很多免费提供的地理信息数据。 在 Google 上搜索应该很快返回几乎您需要的所有内容，包括有关地区，县，河流或任何其他类型数据的详细信息。

来自许多公共组织的 GIS 信息以不同格式可用。 `fiona`能够理解大多数常见格式并以等效方式处理它们，但存在细微差异。 请阅读`fiona`文档以获取更多详细信息。

我们将在此示例中使用的数据，涵盖所有欧洲国家，可在 GitHub 的以下网址找到：[`github.com/leakyMirror/map-of-europe/blob/master/GeoJSON/europe.geojson`](https://github.com/leakyMirror/map-of-europe/blob/master/GeoJSON/europe.geojson)。 请注意，它是 GeoJSON 格式，这是一种易于使用的标准。

# 如何操作...

1.  导入稍后要使用的模块：

```py
>>> import matplotlib.pyplot as plt
>>> import matplotlib.cm as cm
>>> import fiona
```

1.  加载要显示的国家的人口。 人口已经是：

```py
>>> COUNTRIES_POPULATION = {
...     'Spain': 47.2,
...     'Portugal': 10.6,
...     'United Kingdom': 63.8,
...     'Ireland': 4.7,
...     'France': 64.9,
...     'Italy': 61.1,
...     'Germany': 82.6,
...     'Netherlands': 16.8,
...     'Belgium': 11.1,
...     'Denmark': 5.6,
...     'Slovenia': 2,
...     'Austria': 8.5,
...     'Luxembourg': 0.5,
...     'Andorra': 0.077,
...     'Switzerland': 8.2,
...     'Liechtenstein': 0.038,
... }
>>> MAX_POPULATION = max(COUNTRIES_POPULATION.values())
>>> MIN_POPULATION = min(COUNTRIES_POPULATION.values())
```

1.  准备`colormap`，它将确定每个国家显示在绿色阴影中的颜色。 计算每个国家对应的颜色：

```py
>>> colormap = cm.get_cmap('Greens')
>>> COUNTRY_COLOUR = {
...     country_name: colormap(
...         (population - MIN_POPULATION) / (MAX_POPULATION - MIN_POPULATION)
...     )
...     for country_name, population in COUNTRIES_POPULATION.items()
... }
```

1.  打开文件并读取数据，按照我们在第 1 步中定义的国家进行过滤：

```py
>>> with fiona.open('europe.geojson') as fd:
>>>     full_data = [data for data in full_data
...                  if data['properties']['NAME'] in COUNTRIES_POPULATION]
```

1.  以正确的颜色绘制每个国家：

```py
>>> for data in full_data:
...     country_name = data['properties']['NAME']
...     color = COUNTRY_COLOUR[country_name]
...     geo_type = data['geometry']['type']
...     if geo_type == 'Polygon':
...         data_x = [x for x, y in data['geometry']['coordinates'][0]]
...         data_y = [y for x, y in data['geometry']['coordinates'][0]]
...         plt.fill(data_x, data_y, c=color)
...     elif geo_type == 'MultiPolygon':
...         for coordinates in data['geometry']['coordinates']:
...             data_x = [x for x, y in coordinates[0]]
...             data_y = [y for x, y in coordinates[0]]
...             plt.fill(data_x, data_y, c=color)
```

1.  显示结果：

```py
>>> plt.show()
```

1.  结果将显示在新窗口中：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-auto-cb/img/d4a76e46-e98f-4763-8e14-5658dd95e0e6.png)

# 它是如何工作的...

在*如何操作...*部分的第 1 步中导入模块后，将在第 2 步中定义要显示的数据。 请注意，名称需要与 GEO 文件中的格式相同。 最小和最大人口将被计算以正确平衡范围。

人口已经舍入到一个显著数字，并以百万定义。 仅为此示例的目的定义了一些国家，但在 GIS 文件中还有更多可用的国家，并且地图可以向东扩展。

在第 3 步中描述了定义绿色阴影（`Greens`）范围的`colormap`。 这是`matplotlib`中的一个标准`colormap`，但可以使用文档中描述的其他`colormap`（[`matplotlib.org/examples/color/colormaps_reference.html`](https://matplotlib.org/examples/color/colormaps_reference.html)），例如橙色，红色或等离子体，以获得更冷到热的方法。

`COUNTRY_COLOUR`字典存储了由`colormap`为每个国家定义的颜色。 人口减少到从 0.0（最少人口）到 1.0（最多）的数字，并传递给`colormap`以检索其对应的比例的颜色。

然后在第 4 步中检索 GIS 信息。 使用`fiona`读取`europe.geojson`文件，并复制数据，以便在接下来的步骤中使用。 它还会过滤，只处理我们定义了人口的国家，因此不会绘制额外的国家。

步骤 5 中的循环逐个国家进行，然后我们使用`.fill`来绘制它，它绘制一个多边形。每个不同国家的几何形状都是一个单一的多边形（`Polygon`）或多个多边形（`MultiPolygon`）。在每种情况下，适当的多边形都以相同的颜色绘制。这意味着`MultiPolygon`会被绘制多次。

GIS 信息以描述纬度和经度的坐标点的形式存储。区域，如国家，有一系列坐标来描述其中的区域。一些地图更精确，有更多的点来定义区域。可能需要多个多边形来定义一个国家，因为一些部分可能相互分离，岛屿是最明显的情况，但也有飞地。

最后，通过调用`.show`来显示数据。

# 还有更多...

利用 GIS 文件中包含的信息，我们可以向地图添加额外的信息。`properties`对象包含有关国家名称的信息，还有 ISO 名称、FID 代码和中心位置的`LON`和`LAT`。我们可以使用这些信息来使用`.text`显示国家的名称：

```py
    long, lat = data['properties']['LON'], data['properties']['LAT']
    iso3 = data['properties']['ISO3']
    plt.text(long, lat, iso3, horizontalalignment='center')
```

这段代码将存在于*如何做*部分的步骤 6 中的循环中。

如果你分析这个文件，你会发现`properties`对象包含有关人口的信息，存储为 POP2005，所以你可以直接从地图上绘制人口信息。这留作练习。不同的地图文件将包含不同的信息，所以一定要尝试一下，释放所有可能性。

此外，你可能会注意到在某些情况下地图可能会变形。`matplotlib`会尝试将其呈现为一个正方形的框，如果地图不是大致正方形，这将是明显的。例如，尝试只显示西班牙、葡萄牙、爱尔兰和英国。我们可以强制图表以 1 点纬度与 1 点经度相同的空间来呈现，这是一个很好的方法，如果我们不是在靠近极地的地方绘制东西。这是通过在轴上调用`.set_aspect`来实现的。当前轴可以通过`.gca`（**获取当前轴**）获得。

```py
>>> axes = plt.gca()
>>> axes.set_aspect('equal', adjustable='box')
```

此外，为了改善地图的外观，我们可以设置一个背景颜色，以帮助区分背景和前景，并删除轴上的标签，因为打印纬度和经度可能会分散注意力。通过使用`.xticks`和`.yticks`设置空标签来实现在轴上删除标签。背景颜色由轴的前景颜色规定：

```py
>>> plt.xticks([])
>>> plt.yticks([])
>>> axes = plt.gca()
>>> axes.set_facecolor('xkcd:light blue')
```

最后，为了更好地区分不同的区域，可以添加一个包围每个区域的线。这可以通过在`.fill`之后用相同的数据绘制一条细线来实现。请注意，这段代码在步骤 2 中重复了两次。

```py
 plt.fill(data_x, data_y, c=color)
 plt.plot(data_x, data_y, c='black', linewidth=0.2)
```

将所有这些元素应用到地图上，现在看起来是这样的：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-auto-cb/img/a57d8513-6d08-4ba4-a29c-9f03641ec34f.png)

生成的代码可以在 GitHub 上找到：[`github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/Chapter07/visualising_maps.py`](https://github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/Chapter07/visualising_maps.py)。

正如我们所见，地图是以一般的多边形绘制的。不要害怕包括其他几何形状。你可以定义自己的多边形，并用`.fill`或一些额外的标签打印它们。例如，远离的地区可能需要被运输，以避免地图太大。或者，可以使用矩形在地图的部分上打印额外的信息。

完整的`fiona`文档可以在这里找到：[`toblerity.org/fiona/`](http://toblerity.org/fiona/)。完整的`matplotlib`文档可以在这里找到：[`matplotlib.org/`](https://matplotlib.org/)。

# 另请参阅

+   *添加图例和注释*配方

+   *组合图表*配方

# 添加图例和注释

在绘制具有密集信息的图表时，可能需要图例来确定特定颜色或更好地理解所呈现的数据。在`matplotlib`中，图例可以非常丰富，并且有多种呈现方式。注释也是吸引观众注意力的好方法，以便更好地传达信息。

在本示例中，我们将创建一个具有三个不同组件的图表，并显示一个包含信息的图例，以更好地理解它，并在图表上注释最有趣的点。

# 准备工作

我们需要在虚拟环境中安装`matplotlib`：

```py
$ echo "matplotlib==2.2.2" >> requirements.txt
$ pip install -r requirements.txt
```

如果您正在使用 macOS，可能会出现这样的错误——`RuntimeError: Python is not installed as a framework`。请参阅`matplolib`文档以了解如何解决：[`matplotlib.org/faq/osx_framework.html`](https://matplotlib.org/faq/osx_framework.html)。

# 操作步骤...

1.  导入`matplotlib`：

```py
>>> import matplotlib.pyplot as plt
```

1.  准备要在图表上显示的数据，以及应该显示的图例。每行由时间标签、`ProductA`的销售额、`ProductB`的销售额和`ProductC`的销售额组成：

```py
>>> LEGEND = ('ProductA', 'ProductB', 'ProductC')
>>> DATA = (
...     ('Q1 2017', 100, 30, 3),
...     ('Q2 2017', 105, 32, 15),
...     ('Q3 2017', 125, 29, 40),
...     ('Q4 2017', 115, 31, 80),
... )
```

1.  将数据拆分为图表可用的格式。这是一个准备步骤：

```py
>>> POS = list(range(len(DATA)))
>>> VALUESA = [valueA for label, valueA, valueB, valueC in DATA]
>>> VALUESB = [valueB for label, valueA, valueB, valueC in DATA]
>>> VALUESC = [valueC for label, valueA, valueB, valueC in DATA]
>>> LABELS = [label for label, valueA, valueB, valueC in DATA]
```

1.  创建带有数据的条形图：

```py
>>> WIDTH = 0.2
>>> plt.bar([p - WIDTH for p in POS], VALUESA, width=WIDTH)
>>> plt.bar([p for p in POS], VALUESB, width=WIDTH)
>>> plt.bar([p + WIDTH for p in POS], VALUESC, width=WIDTH)
>>> plt.ylabel('Sales')
>>> plt.xticks(POS, LABELS)
```

1.  添加一个注释，显示图表中的最大增长：

```py
>>> plt.annotate('400% growth', xy=(1.2, 18), xytext=(1.3, 40),
                 horizontalalignment='center',
                 arrowprops=dict(facecolor='black', shrink=0.05))
```

1.  添加`legend`：

```py
>>> plt.legend(LEGEND)
```

1.  显示图表：

```py
>>> plt.show()
```

1.  结果将显示在新窗口中：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-auto-cb/img/7284a61f-70fe-43e5-b151-152dd0086307.png)

# 它是如何工作的...

*操作步骤*的第 1 步和第 2 步准备了导入和将在条形图中显示的数据，格式类似于良好结构化的输入数据。在第 3 步中，数据被拆分成不同的数组，以准备在`matplotlib`中输入。基本上，每个数据序列都存储在不同的数组中。

第 4 步绘制数据。每个数据序列都会调用`.bar`，指定其位置和值。标签与`.xticks`相同。为了在标签周围分隔每个条形图，第一个条形图向左偏移，第三个向右偏移。

在第二季度的`ProductC`条形图上方添加了一个注释。请注意，注释包括`xy`中的点和`xytext`中的文本位置。

在第 6 步中，添加了图例。请注意，标签需要按照输入数据的顺序添加。图例会自动放置在不覆盖任何数据的区域。`arroprops`详细说明了指向数据的箭头。

最后，在第 7 步通过调用`.show`绘制图表。

调用`.show`会阻止程序的执行。当窗口关闭时，程序将恢复执行。

# 还有更多...

图例通常会自动显示，只需调用`.legend`即可。如果需要自定义它们的显示顺序，可以将每个标签指定给特定元素。例如，这种方式（注意它将`ProductA`称为`valueC`系列）

```py
>>> valueA = plt.bar([p - WIDTH for p in POS], VALUESA, width=WIDTH)
>>> valueB = plt.bar([p for p in POS], VALUESB, width=WIDTH)
>>> valueC = plt.bar([p + WIDTH for p in POS], VALUESC, width=WIDTH)
>>> plt.legend((valueC, valueB, valueA), LEGEND)
```

图例的位置也可以通过`loc`参数手动更改。默认情况下，它是`best`，它会在数据最少重叠的区域绘制图例（理想情况下没有）。但是可以使用诸如`right`、`upper left`等值，或者特定的`(X, Y)`元组。

另一种选择是在图表之外绘制图例，使用`bbox_to_anchor`选项。在这种情况下，图例附加到边界框的（*X*，*Y*）位置，其中`0`是图表的左下角，`1`是右上角。这可能导致图例被外部边框剪切，因此您可能需要通过`.subplots_adjust`调整图表的起始和结束位置：

```py
>>> plt.legend(LEGEND, title='Products', bbox_to_anchor=(1, 0.8))
>>> plt.subplots_adjust(right=0.80)
```

调整`bbox_to_anchor`参数和`.subplots_adjust`将需要一些试错，直到产生预期的结果。

`.subplots_adjust`引用了位置，作为将显示的轴的位置。这意味着`right=0.80`将在绘图的右侧留下 20%的屏幕空间，而左侧的默认值为 0.125，这意味着在绘图的左侧留下 12.5%的空间。有关更多详细信息，请参阅文档：[`matplotlib.org/api/_as_gen/matplotlib.pyplot.subplots_adjust.html`](https://matplotlib.org/api/_as_gen/matplotlib.pyplot.subplots_adjust.html)。

注释可以以不同的样式进行，并可以通过不同的选项进行调整，例如连接方式等。例如，这段代码将创建一个箭头，使用`fancy`样式连接一个曲线。结果显示在这里：

```py
plt.annotate('400% growth', xy=(1.2, 18), xytext=(1.3, 40),
             horizontalalignment='center',
             arrowprops={'facecolor': 'black',
                         'arrowstyle': "fancy",
                         'connectionstyle': "angle3",
                         })
```

在我们的方法中，我们没有精确地注释到条的末端（点（`1.2`，`15`）），而是略高于它，以留出一点空间。

调整注释的确切位置和文本的位置将需要进行一些测试。文本的位置也是通过寻找最佳位置来避免与条形图重叠而定位的。字体大小和颜色可以使用`.legend`和`.annotate`调用中的`fontsize`和`color`参数进行更改。

应用所有这些元素，图表可能看起来类似于这样。可以通过调用 GitHub 上的`legend_and_annotation.py`脚本来复制此图表：[`github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/Chapter07/adding_legend_and_annotations.py`](https://github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/Chapter07/adding_legend_and_annotations.py)：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-auto-cb/img/cbe93454-92bf-4133-a125-e94c0269ba18.png)

完整的`matplotlib`文档可以在这里找到：[`matplotlib.org/`](https://matplotlib.org/)。特别是图例的指南在这里：[`matplotlib.org/users/legend_guide.html#plotting-guide-legend`](https://matplotlib.org/users/legend_guide.html#plotting-guide-legend)，注释的指南在这里：[`matplotlib.org/users/annotations.html`](https://matplotlib.org/users/annotations.html)。

# 另请参阅

+   *绘制堆叠条形图*的方法

+   *组合图表*的方法

# 组合图表

可以在同一图表中组合多个图表。在这个方法中，我们将看到如何在同一图表上以两个不同的轴呈现数据，并如何在同一图表上添加更多的图表。

# 准备工作

我们需要在虚拟环境中安装`matplotlib`：

```py
$ echo "matplotlib==2.2.2" >> requirements.txt
$ pip install -r requirements.txt
```

如果您使用的是 macOS，可能会出现这样的错误——`RuntimeError: Python is not installed as a framework`。请参阅`matplolib`文档，了解如何解决此问题：[`matplotlib.org/faq/osx_framework.html`](https://matplotlib.org/faq/osx_framework.html)。

# 如何做…

1.  导入`matplotlib`：

```py
>>> import matplotlib.pyplot as plt
```

1.  准备数据以在图表上显示，并显示应该显示的图例。每条线由时间标签、`ProductA`的销售额和`ProductB`的销售额组成。请注意，`ProductB`的值远高于`A`：

```py
>>> DATA = (
...  ('Q1 2017', 100, 3000, 3),
...  ('Q2 2017', 105, 3200, 5),
...  ('Q3 2017', 125, 2900, 7),
...  ('Q4 2017', 115, 3100, 3),
... )
```

1.  准备独立数组中的数据：

```py
>>> POS = list(range(len(DATA)))
>>> VALUESA = [valueA for label, valueA, valueB, valueC in DATA]
>>> VALUESB = [valueB for label, valueA, valueB, valueC in DATA]
>>> VALUESC = [valueC for label, valueA, valueB, valueC in DATA]
>>> LABELS = [label for label, valueA, valueB, valueC in DATA]
```

请注意，这将扩展并为每个值创建一个列表。

这些值也可以通过`LABELS`、`VALUESA`、`VALUESB`、`VALUESC = ZIP(*DATA)`进行扩展。

1.  创建第一个子图：

```py
>>> plt.subplot(2, 1, 1)
```

1.  创建一个关于`VALUESA`的条形图：

```py
>>> valueA = plt.bar(POS, VALUESA)
>>> plt.ylabel('Sales A')
```

1.  创建一个不同的*Y*轴，并将`VALUESB`的信息添加为线图：

```py
>>> plt.twinx()
>>> valueB = plt.plot(POS, VALUESB, 'o-', color='red')
>>> plt.ylabel('Sales B')
>>> plt.xticks(POS, LABELS)
```

1.  创建另一个子图，并用`VALUESC`填充它：

```py
>>> plt.subplot(2, 1, 2)
>>> plt.plot(POS, VALUESC)
>>> plt.gca().set_ylim(ymin=0)
>>> plt.xticks(POS, LABELS)
```

1.  显示图表：

```py
>>> plt.show()
```

1.  结果将显示在一个新窗口中：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-auto-cb/img/ba4d0d65-86cb-462a-a017-9b5bc32a8d21.png)

# 它是如何工作的…

导入模块后，数据以一种方便的方式呈现在“如何做…”部分的第 2 步中，这很可能类似于数据最初的存储方式。第 3 步是一个准备步骤，将数据分割成不同的数组，以便进行下一步。

第 4 步创建一个新的`.subplot`。这将把整个图形分成两个元素。参数是行数、列数和所选的子图。因此，我们在一列中创建了两个子图，并在第一个子图中绘制。

第 5 步使用`VALUESA`数据在此子图中打印了一个`.bar`图，并使用`.ylabel`标记了*Y*轴为`Sales A`。

第 6 步使用`.twinx`创建一个新的*Y*轴，通过`.plot`绘制`VALUESB`为线图。标签使用`.ylabel`标记为`Sales B`。使用`.xticks`标记*X*轴。

`VALUESB`图形设置为红色，以避免两个图形具有相同的颜色。默认情况下，两种情况下的第一种颜色是相同的，这将导致混淆。数据点使用`'o'`选项标记。

在第 7 步中，我们使用`.subplot`切换到第二个子图。图形以线条形式打印`VALUESC`，然后使用`.xticker`在*X*轴上放置标签，并将*Y*轴的最小值设置为`0`。然后在第 8 步显示图形。

# 还有更多...

通常情况下，具有多个轴的图形很难阅读。只有在有充分理由这样做并且数据高度相关时才使用它们。

默认情况下，线图中的*Y*轴将尝试呈现*Y*值的最小值和最大值之间的信息。通常截断轴不是呈现信息的最佳方式，因为它可能扭曲感知的差异。例如，如果图形从 10 到 11，那么在 10 到 11 之间的值的变化可能看起来很重要，但这不到 10%。将*Y*轴最小值设置为`0`，使用`plt.gca().set_ylim(ymin=0)`是一个好主意，特别是在有两个不同的轴时。

选择子图的调用将首先按行，然后按列进行，因此`.subplot(2, 2, 3)`将选择第一列，第二行的子图。

分割的子图网格可以更改。首先调用`.subplot(2, 2, 1)`和`.subplot(2, 2, 2)`，然后调用`.subplot(2, 1, 2)`，将在第一行创建两个小图和第二行一个较宽的图的结构。返回将覆盖先前绘制的子图。

完整的`matplotlib`文档可以在这里找到：[`matplotlib.org/`](https://matplotlib.org/)。特别是，图例指南在这里：[`matplotlib.org/users/legend_guide.html#plotting-guide-legend`](https://matplotlib.org/users/legend_guide.html#plotting-guide-legend)。有关注释的信息在这里：[`matplotlib.org/users/annotations.html`](https://matplotlib.org/users/annotations.html)。

# 另请参阅

+   *绘制多条线*教程

+   *可视化地图*教程

# 保存图表

一旦图表准备好，我们可以将其存储在硬盘上，以便在其他文档中引用。在本教程中，我们将看到如何以不同的格式保存图表。

# 准备工作

我们需要在虚拟环境中安装`matplotlib`：

```py
$ echo "matplotlib==2.2.2" >> requirements.txt
$ pip install -r requirements.txt
```

如果您使用的是 macOS，可能会出现这样的错误——`RuntimeError: Python is not installed as a framework`。请参阅`matplolib`文档以了解如何解决此问题：[`matplotlib.org/faq/osx_framework.html`](https://matplotlib.org/faq/osx_framework.html)。

# 如何做…

1.  导入`matplotlib`：

```py
>>> import matplotlib.pyplot as plt
```

1.  准备要显示在图表上的数据，并将其拆分为不同的数组：

```py
>>> DATA = (
...    ('Q1 2017', 100),
...    ('Q2 2017', 150),
...    ('Q3 2017', 125),
...    ('Q4 2017', 175),
... )
>>> POS = list(range(len(DATA)))
>>> VALUES = [value for label, value in DATA]
>>> LABELS = [label for label, value in DATA]
```

1.  使用数据创建条形图：

```py
>>> plt.bar(POS, VALUES)
>>> plt.xticks(POS, LABELS)
>>> plt.ylabel('Sales')
```

1.  将图表保存到硬盘：

```py
>>> plt.savefig('data.png')
```

# 工作原理...

在*如何做…*部分的第 1 和第 2 步中导入和准备数据后，通过调用`.bar`在第 3 步生成图表。添加了一个`.ylabel`，并通过`.xticks`标记了*X*轴的适当时间描述。

第 4 步将文件保存到硬盘上，文件名为`data.png`。

# 还有更多...

图像的分辨率可以通过`dpi`参数确定。这将影响文件的大小。使用`72`到`300`之间的分辨率。较低的分辨率将难以阅读，较高的分辨率除非图形的大小巨大，否则没有意义：

```py
>>> plt.savefig('data.png', dpi=72)
```

`matplotlib`了解如何存储最常见的文件格式，如 JPEG、PDF 和 PNG。当文件名具有适当的扩展名时，它将自动使用。

除非您有特定要求，否则请使用 PNG。与其他格式相比，它在存储具有有限颜色的图形时非常高效。如果您需要找到所有支持的文件，可以调用`plt.gcf().canvas.get_supported_filetypes()`。

完整的`matplotlib`文档可以在这里找到：[`matplotlib.org/`](https://matplotlib.org/)。特别是图例指南在这里：[`matplotlib.org/users/legend_guide.html#plotting-guide-legend`](https://matplotlib.org/users/legend_guide.html#plotting-guide-legend)。有关注释的信息在这里：[`matplotlib.org/users/annotations.html`](https://matplotlib.org/users/annotations.html)。

# 另请参阅

+   *绘制简单销售图*配方

+   *添加图例和注释*配方


# 第八章：处理通信渠道

在本章中，我们将涵盖以下配方：

+   使用电子邮件模板

+   发送单个电子邮件

+   阅读电子邮件

+   将订阅者添加到电子邮件通讯中

+   通过电子邮件发送通知

+   生成短信

+   接收短信

+   创建一个 Telegram 机器人

# 介绍

处理通信渠道是自动化事务可以产生巨大收益的地方。在本配方中，我们将看到如何处理两种最常见的通信渠道——电子邮件，包括新闻通讯，以及通过电话发送和接收短信。

多年来，交付方法中存在相当多的滥用，如垃圾邮件或未经请求的营销信息，这使得与外部工具合作以避免消息被自动过滤器自动拒绝成为必要。我们将在适用的情况下提出适当的注意事项。所有工具都有很好的文档，所以不要害怕阅读它。它们还有很多功能，它们可能能够做一些正是你所寻找的东西。

# 使用电子邮件模板

要发送电子邮件，我们首先需要生成其内容。在本配方中，我们将看到如何生成适当的模板，既以纯文本样式又以 HTML 样式。

# 准备就绪

我们应该首先安装`mistune`模块，它将 Markdown 文档编译为 HTML。我们还将使用`jinja2`模块将 HTML 与我们的文本组合在一起。

```py
$ echo "mistune==0.8.3" >> requirements.txt
$ echo "jinja2==2.20" >> requirements.txt
$ pip install -r requirements.txt
```

在 GitHub 存储库中，有一些我们将使用的模板——`email_template.md`在[`github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/Chapter08/email_template.md`](https://github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/Chapter08/email_template.md)和一个用于样式的模板，`email_styling.html`在[`github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/Chapter08/email_styling.html`](https://github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/Chapter08/email_styling.html)。

# 如何做...

1.  导入模块：

```py
>>> import mistune
>>> import jinja2
```

1.  从磁盘读取两个模板：

```py
>>> with open('email_template.md') as md_file:
...     markdown = md_file.read()

>>> with open('email_styling.html') as styling_file:
...     styling = styling_file.read()
```

1.  定义要包含在模板中的`data`。模板非常简单，只接受一个参数：

```py
>>> data = {'name': 'Seamus'}
```

1.  呈现 Markdown 模板。这会产生`data`的纯文本版本：

```py
>>> text = markdown.format(**data)
```

1.  呈现 Markdown 并添加样式：

```py
>>> html_content = mistune.markdown(text)
>>> html = jinja2.Template(styling).render(content=html_content)
```

1.  将文本和 HTML 版本保存到磁盘以进行检查：

```py
>>> with open('text_version.txt', 'w') as fp:
...     fp.write(text)
>>> with open('html_version.html', 'w') as fp:
...     fp.write(html)
```

1.  检查文本版本：

```py
$ cat text_version.txt
Hi Seamus:

This is an email talking about **things**

### Very important info

1\. One thing
2\. Other thing
3\. Some extra detail

Best regards,

  *The email team*
```

1.  在浏览器中检查 HTML 版本：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-auto-cb/img/cc6cc1e0-aeaf-4e3a-911b-dacf333609ee.png)

# 它是如何工作的...

第 1 步获取稍后将使用的模块，第 2 步读取将呈现的两个模板。`email_template.md`是内容的基础，它是一个 Markdown 模板。`email_styling.html`是一个包含基本 HTML 环绕和 CSS 样式信息的 HTML 模板。

基本结构是以 Markdown 格式创建内容。这是一个可读的纯文本文件，可以作为电子邮件的一部分发送。然后可以将该内容转换为 HTML，并添加一些样式来创建 HTML 函数。`email_styling.html`有一个内容区域，用于放置从 Markdown 呈现的 HTML。

第 3 步定义了将在`email_template.md`中呈现的数据。这是一个非常简单的模板，只需要一个名为`name`的参数。

在第 4 步，Markdown 模板与`data`一起呈现。这会产生电子邮件的纯文本版本。

第 5 步呈现了`HTML`版本。使用`mistune`将纯文本版本呈现为`HTML`，然后使用`jinja2`模板将其包装在`email_styling.html`中。最终版本是一个独立的 HTML 文档。

最后，我们将两个版本，纯文本（作为`text`）和 HTML（作为`html`），保存到文件中的第 6 步。第 7 步和第 8 步检查存储的值。信息是相同的，但在`HTML`版本中，它是有样式的。

# 还有更多...

使用 Markdown 可以轻松生成包含文本和 HTML 的双重电子邮件。Markdown 在文本格式中非常易读，并且可以自然地呈现为 HTML。也就是说，可以生成完全不同的 HTML 版本，这将允许更多的自定义和利用 HTML 的特性。

完整的 Markdown 语法可以在[`daringfireball.net/projects/markdown/syntax`](https://daringfireball.net/projects/markdown/syntax)找到，最常用元素的好的速查表在[`beegit.com/markdown-cheat-sheet`](https://beegit.com/markdown-cheat-sheet)。

虽然制作电子邮件的纯文本版本并不是绝对必要的，但这是一个很好的做法，表明您关心谁阅读了电子邮件。大多数电子邮件客户端接受 HTML，但并非完全通用。

对于 HTML 电子邮件，请注意整个样式应该包含在电子邮件中。这意味着 CSS 需要嵌入到 HTML 中。避免进行可能导致电子邮件在某些电子邮件客户端中无法正确呈现，甚至被视为垃圾邮件的外部调用。

`email_styling.html`中的样式基于可以在[`markdowncss.github.io/`](http://markdowncss.github.io/)找到的`modest`样式。还有更多可以使用的 CSS 样式，可以在 Google 中搜索找到更多。请记住删除任何外部引用，如前面所讨论的。

可以通过以`base64`格式对图像进行编码，以便直接嵌入 HTML`img`标签中，而不是添加引用，将图像包含在 HTML 中。

```py
>>> import base64
>>> with open("image.png",'rb') as file:
... encoded_data = base64.b64encode(file) >>> print "<img src='data:image/png;base64,{data}'/>".format(data=encoded_data)
```

您可以在[`css-tricks.com/data-uris/`](https://css-tricks.com/data-uris/)的文章中找到有关此技术的更多信息。

`mistune`完整文档可在[`mistune.readthedocs.io/en/latest/`](http://mistune.readthedocs.io/en/latest/)找到，`jinja2`文档可在[`jinja.pocoo.org/docs/2.10/`](http://jinja.pocoo.org/docs/2.10/)找到。

# 另请参阅

+   第五章中的*在 Markdown 中格式化文本*食谱，*生成精彩的报告*

+   第五章中的*使用模板生成报告食谱*，*生成精彩的报告*

+   第五章中的*发送事务性电子邮件*食谱，*生成精彩的报告*

# 发送单个电子邮件

发送电子邮件的最基本方法是从电子邮件帐户发送单个电子邮件。这个选项只建议用于非常零星的使用，但对于简单的目的，比如每天向受控地址发送几封电子邮件，这可能足够了。

不要使用此方法向分发列表或具有未知电子邮件地址的客户批量发送电子邮件。您可能因反垃圾邮件规则而被服务提供商禁止。有关更多选项，请参阅本章中的其他食谱。

# 准备工作

对于这个示例，我们将需要一个带有服务提供商的电子邮件帐户。根据要使用的提供商有一些小的差异，但我们将使用 Gmail 帐户，因为它非常常见且免费访问。

由于 Gmail 的安全性，我们需要创建一个特定的应用程序密码，用于发送电子邮件。请按照这里的说明操作：[`support.google.com/accounts/answer/185833`](https://support.google.com/accounts/answer/185833)。这将有助于为此示例生成一个密码。记得为邮件访问创建它。您可以随后删除密码以将其删除。

我们将使用 Python 标准库中的`smtplib`模块。

# 如何做...

1.  导入`smtplib`和`email`模块：

```py
>>> import smtplib
>>> from email.mime.multipart import MIMEMultipart
>>> from email.mime.text import MIMEText
```

1.  设置凭据，用您自己的凭据替换这些。出于测试目的，我们将发送到相同的电子邮件，但请随意使用不同的地址：

```py
>>> USER = 'your.account@gmail.com'
>>> PASSWORD = 'YourPassword'
>>> sent_from = USER
>>> send_to = [USER]
```

1.  定义要发送的数据。注意两种选择，纯文本和 HTML：

```py
>>> text = "Hi!\nThis is the text version linking to https://www.packtpub.com/\nCheers!"
>>> html = """<html><head></head><body>
... <p>Hi!<br>
... This is the HTML version linking to <a href="https://www.packtpub.com/">Packt</a><br>
... </p>
... </body></html>
"""
```

1.  将消息组成为`MIME`多部分，包括`主题`，`收件人`和`发件人`：

```py
>>> msg = MIMEMultipart('alternative')
>>> msg['Subject'] = 'An interesting email'
>>> msg['From'] = sent_from
>>> msg['To'] = ', '.join(send_to)
```

1.  填写电子邮件的数据内容部分：

```py
>>> part_plain = MIMEText(text, 'plain')
>>> part_html = MIMEText(html, 'html')
>>> msg.attach(part_plain)
>>> msg.attach(part_html)
```

1.  使用`SMTP SSL`协议发送电子邮件：

```py
>>> with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
...     server.login(USER, PASSWORD)
...     server.sendmail(sent_from, send_to, msg.as_string())
```

1.  邮件已发送。检查您的电子邮件帐户是否收到了消息。检查*原始电子邮件*，您可以看到完整的原始电子邮件，其中包含 HTML 和纯文本元素。电子邮件已被编辑：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-auto-cb/img/eedfbdbd-64da-4f0e-abd9-7fa23bbaf20d.png)

# 工作原理...

在第 1 步之后，从`stmplib`和`email`进行相关导入，第 2 步定义了从 Gmail 获取的凭据。

第 3 步显示了将要发送的 HTML 和文本。它们是替代方案，因此它们应该呈现相同的信息，但以不同的格式呈现。

基本的消息信息在第 4 步中设置。它指定了电子邮件的主题，以及*from*和*to*。第 5 步添加了多个部分，每个部分都有适当的`MIMEText`类型。

最后添加的部分是首选的替代方案，根据`MIME`格式，因此我们最后添加了`HTML`部分。

第 6 步建立与服务器的连接，使用凭据登录并发送消息。它使用`with`上下文来获取连接。

如果凭据出现错误，它将引发一个异常，显示用户名和密码不被接受。

# 还有更多...

请注意，`sent_to`是一个地址列表。您可以将电子邮件发送给多个地址。唯一的注意事项在第 4 步，需要将其指定为所有地址的逗号分隔值列表。

尽管可以将`sent_from`标记为与发送电子邮件时使用的地址不同，但并不建议这样做。这可能被解释为试图伪造电子邮件的来源，并引发检测为垃圾邮件来源的迹象。

此处使用的服务器`smtp.gmail.com`*是 Gmail 指定的服务器，并且`SMTPS`（安全`SMTP`）的定义端口为`465`。Gmail 还接受端口`587`，这是标准端口，但需要您通过调用`.starttls`指定会话的类型，如下面的代码所示：

```py
 with smtplib.SMTP('smtp.gmail.com', 587) as server:
    server.starttls()
    server.login(USER, PASSWORD)
    server.sendmail(sent_from, send_to, msg.as_string())
```

如果您对这些差异和两种协议的更多细节感兴趣，可以在这篇文章中找到更多信息：[`www.fastmail.com/help/technical/ssltlsstarttls.html`](https://www.fastmail.com/help/technical/ssltlsstarttls.html)。

完整的`smtplib`文档可以在[`docs.python.org/3/library/smtplib.html`](https://docs.python.org/3/library/smtplib.html)找到，`email`模块中包含有关电子邮件不同格式的信息，包括`MIME`类型的示例，可以在这里找到：[`docs.python.org/3/library/email.html`](https://docs.python.org/3/library/email.html)。

# 另请参阅

+   *使用电子邮件模板*示例

+   *发送单个电子邮件*示例

# 阅读电子邮件

在本示例中，我们将看到如何从帐户中读取电子邮件。我们将使用`IMAP4`标准，这是最常用的用于阅读电子邮件的标准。

一旦读取，电子邮件可以被自动处理和分析，以生成智能自动响应、将电子邮件转发到不同的目标、聚合结果进行监控等操作。选项是无限的！

# 准备就绪

对于此示例，我们将需要一个带有服务提供商的电子邮件帐户。基于要使用的提供商的小差异，但我们将使用 Gmail 帐户，因为它非常常见且免费访问。

由于 Gmail 的安全性，我们需要创建一个特定的应用程序密码来发送电子邮件。请按照这里的说明操作：[`support.google.com/accounts/answer/185833`](https://support.google.com/accounts/answer/185833)。这将为此示例生成一个密码。记得为邮件创建它。您可以在之后删除密码以将其删除。

我们将使用 Python 标准库中的`imaplib`模块。

该示例将读取最后收到的电子邮件，因此您可以使用它更好地控制将要读取的内容。我们将发送一封看起来像是发送给支持的简短电子邮件。

# 如何做...

1.  导入`imaplib`和`email`模块：

```py
>>> import imaplib
>>> import email
>>> from email.parser import BytesParser, Parser
>>> from email.policy import default
```

1.  设置凭据，用您自己的凭据替换这些：

```py
>>> USER = 'your.account@gmail.com'
>>> PASSWORD = 'YourPassword'
```

1.  连接到电子邮件服务器：

```py
>>> mail = imaplib.IMAP4_SSL('imap.gmail.com')
>>> mail.login(USER, PASSWORD)
```

1.  选择收件箱文件夹：

```py
>>> mail.select('inbox')
```

1.  读取所有电子邮件 UID 并检索最新收到的电子邮件：

```py
>>> result, data = mail.uid('search', None, 'ALL')
>>> latest_email_uid = data[0].split()[-1]
>>> result, data = mail.uid('fetch', latest_email_uid, '(RFC822)')
>>> raw_email = data[0][1]
```

1.  将电子邮件解析为 Python 对象：

```py
>>> email_message = BytesParser(policy=default).parsebytes(raw_email)
```

1.  显示电子邮件的主题和发件人：

```py
>>> email_message['subject']
'[Ref ABCDEF] Subject: Product A'
>>> email.utils.parseaddr(email_message['From'])
('Sender name', 'sender@gmail.com')
```

1.  检索文本的有效载荷：

```py
>>> email_type = email_message.get_content_maintype()
>>> if email_type == 'multipart':
...     for part in email_message.get_payload():
...         if part.get_content_type() == 'text/plain':
...             payload = part.get_payload()
... elif email_type == 'text':
...     payload = email_message.get_payload()
>>> print(payload)
Hi:

  I'm having difficulties getting into my account. What was the URL, again?

  Thanks!
    A confuser customer
```

# 工作原理...

导入将要使用的模块并定义凭据后，我们在第 3 步连接到服务器。

第 4 步连接到`inbox`。这是 Gmail 中包含收件箱的默认文件夹，其中包含收到的电子邮件。

当然，您可能需要阅读不同的文件夹。您可以通过调用`mail.list()`来获取所有文件夹的列表。

在第 5 步，首先通过调用`.uid('search', None, "ALL")`检索收件箱中所有电子邮件的 UID 列表。然后通过`fetch`操作和`.uid('fetch', latest_email_uid, '(RFC822)')`再次从服务器检索最新收到的电子邮件。这将以 RFC822 格式检索电子邮件，这是标准格式。请注意，检索电子邮件会将其标记为已读。

`.uid`命令允许我们调用 IMAP4 命令，返回一个带有结果（`OK`或`NO`）和数据的元组。如果出现错误，它将引发适当的异常。

`BytesParser`模块用于将原始的`RFC822`电子邮件转换为 Python 对象。这是在第 6 步完成的。

元数据，包括主题、发件人和时间戳等详细信息，可以像字典一样访问，如第 7 步所示。地址可以从原始文本格式解析为带有`email.utils.parseaddr`的部分。

最后，内容可以展开和提取。如果电子邮件的类型是多部分的，可以通过迭代`.get_payload()`来提取每个部分。最容易处理的是`plain/text`，因此假设它存在，第 8 步中的代码将提取它。

电子邮件正文存储在`payload`变量中。

# 还有更多...

在第 5 步，我们正在检索收件箱中的所有电子邮件，但这并非必要。搜索可以进行过滤，例如只检索最近一天的电子邮件：

```py
import datetime
since = (datetime.date.today() - datetime.timedelta(days=1)).strftime("%d-%b-%Y")
result, data = mail.uid('search', None, f'(SENTSINCE {since})')
```

这将根据电子邮件的日期进行搜索。请注意，分辨率以天为单位。

还有更多可以通过`IMAP4`完成的操作。查看 RFC 3501  [`tools.ietf.org/html/rfc3501`](https://tools.ietf.org/html/rfc3501)和 RFC 6851 [`tools.ietf.org/html/rfc6851`](https://tools.ietf.org/html/rfc6851)以获取更多详细信息。

RFC 描述了 IMAP4 协议，可能有点枯燥。检查可能的操作将让您了解详细调查的可能性，可能通过 Google 搜索示例。

可以解析和处理电子邮件的主题和正文，以及日期、收件人、发件人等其他元数据。例如，本食谱中检索的主题可以按以下方式处理：

```py
>>> import re
>>> re.search(r'\[Ref (\w+)] Subject: (\w+)', '[Ref ABCDEF] Subject: Product A').groups()
('ABCDEF', 'Product') 
```

有关正则表达式和其他解析信息的更多信息，请参见第一章，*让我们开始自动化之旅*。

# 另请参阅

+   第一章中的*介绍正则表达式*食谱，*让我们开始自动化之旅*

# 向电子邮件通讯订阅者添加订阅者

常见的营销工具是电子邮件通讯。它们是向多个目标发送信息的便捷方式。一个好的通讯系统很难实现，推荐的方法是使用市场上可用的。一个著名的是 MailChimp ([`mailchimp.com/`](https://mailchimp.com/))。

MailChimp 有很多可能性，但与本书相关的有趣之一是其 API，可以编写脚本来自动化工具。这个 RESTful API 可以通过 Python 访问。在这个食谱中，我们将看到如何向现有列表添加更多的订阅者。

# 准备就绪

由于我们将使用 MailChimp，因此需要有一个可用的帐户。您可以在[`login.mailchimp.com/signup/`](https://login.mailchimp.com/signup/)上创建一个免费帐户。

创建帐户后，请确保至少有一个我们将向其添加订阅者的列表。作为注册的一部分，可能已经创建了。它将显示在列表下：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-auto-cb/img/05182753-f7ff-4002-8e63-40cdbcfe5e36.png)

列表将包含已订阅的用户。

对于 API，我们将需要一个 API 密钥。转到帐户|额外|API 密钥并创建一个新的：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-auto-cb/img/a2174005-2a85-4c91-880a-a14ec426ca66.png)

我们将使用`requests`模块来访问 API。将其添加到您的虚拟环境中：

```py
$ echo "requests==2.18.3" >> requirements.txt
$ pip install -r requirements.txt
```

MailChimp API 使用**DC**（数据中心）的概念，您的帐户使用它。这可以从您的 API 的最后几位数字中获得，或者从 MailChimp 管理站点的 URL 开头获得。例如，在所有先前的截图中，它是`us19`。

# 如何做...

1.  导入`requests`模块：

```py
>>> import requests
```

1.  定义身份验证和基本 URL。基本 URL 需要在开头加上您的`dc`（例如`us19`）：

```py
>>> API = 'your secret key'
>>> BASE = 'https://<dc>.api.mailchimp.com/3.0'
>>> auth = ('user', API)
```

1.  获取所有列表：

```py
>>> url = f'{BASE}/lists'
>>> response = requests.get(url, auth=auth)
>>> result = response.json()
```

1.  过滤列表以获取所需列表的`href`：

```py
>>> LIST_NAME = 'Your list name'
>>> this_list = [l for l in result['lists'] if l['name'] == LIST_NAME][0]
>>> list_url = [l['href'] for l in this_list['_links'] if l['rel'] == 'self'][0]
```

1.  使用列表 URL，您可以获取列表成员的 URL：

```py
>>> response = requests.get(list_url, auth=auth)
>>> result = response.json()
>>> result['stats']
{'member_count': 1, 'unsubscribe_count': 0, 'cleaned_count': 0, ...}
>>> members_url = [l['href'] for l in result['_links'] if l['rel'] == 'members'][0]
```

1.  可以通过向`members_url`发出`GET`请求来检索成员列表：

```py
>>> response = requests.get(members_url, json=new_member, auth=auth)
>>> result = response.json()
>>> len(result['members'])
1
```

1.  向列表添加新成员：

```py
>>> new_member = {
    'email_address': 'test@test.com',
    'status': 'subscribed',
}
>>> response = requests.post(members_url, json=new_member, auth=auth)
```

1.  使用`GET`获取用户列表会获取到所有用户：

```py
>>> response = requests.post(members_url, json=new_member, auth=auth)
>>> result = response.json()
>>> len(result['members'])
2
```

# 工作原理...

在第 1 步导入 requests 模块后，在第 2 步定义连接的基本值，即基本 URL 和凭据。请注意，对于身份验证，我们只需要 API 密钥作为密码，以及任何用户（如 MailChimp 文档所述：[`developer.mailchimp.com/documentation/mailchimp/guides/get-started-with-mailchimp-api-3/`](https://developer.mailchimp.com/documentation/mailchimp/guides/get-started-with-mailchimp-api-3/)）。

第 3 步检索所有列表，调用适当的 URL。结果以 JSON 格式返回。调用包括具有定义凭据的`auth`参数。所有后续调用都将使用该`auth`参数进行身份验证。

第 4 步显示了如何过滤返回的列表以获取感兴趣的特定列表的 URL。每个返回的调用都包括一系列与相关信息的`_links`列表，使得可以通过 API 进行遍历。

在第 5 步调用列表的 URL。这将返回列表的信息，包括基本统计信息。类似于第 4 步的过滤，我们检索成员的 URL。

由于尺寸限制和显示相关数据，未显示所有检索到的元素。请随时进行交互式分析并了解它们。数据构造良好，遵循 RESTful 的可发现性原则；再加上 Python 的内省能力，使其非常易读和易懂。

第 6 步检索成员列表，向`members_url`发出`GET`请求，可以将其视为单个用户。这可以在网页界面的*Getting Ready*部分中看到。

第 7 步创建一个新用户，并在`members_url`上发布`json`参数中传递的信息，以便将其转换为 JSON 格式。第 7 步检索更新后的数据，显示列表中有一个新用户。

# 还有更多...

完整的 MailChimp API 非常强大，可以执行大量任务。请查看完整的 MailChimp 文档以发现所有可能性：[`developer.mailchimp.com/`](https://developer.mailchimp.com/)。

简要说明一下，超出了本书的范围，请注意向自动列表添加订阅者的法律影响。垃圾邮件是一个严重的问题，有新的法规来保护客户的权利，如 GPDR。确保您有用户的许可才能给他们发送电子邮件。好消息是，MailChimp 自动实现了帮助解决这个问题的工具，如自动退订按钮。

一般的 MailChimp 文档也非常有趣，展示了许多可能性。MailChimp 能够管理通讯和一般的分发列表，但也可以定制生成流程，安排发送电子邮件，并根据参数（如生日）自动向您的受众发送消息。

# 另请参阅

+   *发送单个电子邮件*配方

+   *发送交易电子邮件*配方

# 通过电子邮件发送通知

在这个配方中，我们将介绍如何发送将发送给客户的电子邮件。作为对用户操作的响应发送的电子邮件，例如确认电子邮件或警报电子邮件，称为*交易电子邮件*。由于垃圾邮件保护和其他限制，最好使用外部工具来实现这种类型的电子邮件。

在这个配方中，我们将使用 Mailgun ([`www.mailgun.com`](https://www.mailgun.com))，它能够发送这种类型的电子邮件，并与之通信。

# 准备工作

我们需要在 Mailgun 中创建一个帐户。转到[`signup.mailgun.com`](https://signup.mailgun.com/new/signup)创建一个。请注意，信用卡信息是可选的。

注册后，转到域以查看是否有沙箱环境。我们可以使用它来测试功能，尽管它只会向注册的测试电子邮件帐户发送电子邮件。API 凭据将显示在那里：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-auto-cb/img/f287dcdc-a84e-4cd0-9df3-abae2afae51a.png)

我们需要注册帐户，以便我们将作为*授权收件人*收到电子邮件。您可以在此处添加：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-auto-cb/img/eacf6ffc-c628-4baf-8292-c4eec436fd98.png)

要验证帐户，请检查授权收件人的电子邮件并确认。电子邮件地址现在已准备好接收测试邮件：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-auto-cb/img/485590b4-1022-4f34-82ad-2859dac25be9.png)

我们将使用`requests`模块来连接 Mailgun API。在虚拟环境中安装它：

```py
$ echo "requests==2.18.3" >> requirements.txt
$ pip install -r requirements.txt
```

一切准备就绪，可以发送电子邮件，但请注意只发送给授权收件人。要能够在任何地方发送电子邮件，我们需要设置域。请参阅 Mailgun 文档：[`documentation.mailgun.com/en/latest/quickstart-sending.html#verify-your-domain`](https://documentation.mailgun.com/en/latest/quickstart-sending.html#verify-your-domain)。

# 如何做...

1.  导入`requests`模块：

```py
>>> import requests
```

1.  准备凭据，以及要发送和接收的电子邮件。请注意，我们正在使用模拟发件人：

```py
>>> KEY = 'YOUR-SECRET-KEY'
>>> DOMAIN = 'YOUR-DOMAIN.mailgun.org'
>>> TO = 'YOUR-AUTHORISED-RECEIVER'
```

```py

>>> FROM = f'sender@{DOMAIN}'
>>> auth = ('api', KEY)
```

1.  准备要发送的电子邮件。这里有 HTML 版本和备用纯文本版本：

```py
>>> text = "Hi!\nThis is the text version linking to https://www.packtpub.com/\nCheers!"
>>> html = '''<html><head></head><body>
...     <p>Hi!<br>
...        This is the HTML version linking to <a href="https://www.packtpub.com/">Packt</a><br>
...     </p>  
...   </body></html>'''
```

1.  设置要发送到 Mailgun 的数据：

```py
>>> data = {
...     'from': f'Sender <{FROM}>',
...     'to': f'Jaime Buelta <{TO}>',
...     'subject': 'An interesting email!',
...     'text': text,
...     'html': html,
... }
```

1.  调用 API：

```py
>>> response = requests.post(f"https://api.mailgun.net/v3/{DOMAIN}/messages", auth=auth, data=data)
>>> response.json()
{'id': '<YOUR-ID.mailgun.org>', 'message': 'Queued. Thank you.'}
```

1.  检索事件并检查电子邮件是否已发送：

```py
>>> response_events = requests.get(f'https://api.mailgun.net/v3/{DOMAIN}/events', auth=auth)
>>> response_events.json()['items'][0]['recipient'] == TO
True
>>> response_events.json()['items'][0]['event']
'delivered'
```

1.  邮件应该出现在您的收件箱中。由于它是通过沙箱环境发送的，请确保在直接显示时检查您的垃圾邮件文件夹。

# 它是如何工作的...

第 1 步导入`requests`模块以供以后使用。第 2 步定义了凭据和消息中的基本信息，并应从 Mailgun Web 界面中提取，如前所示。

第 3 步定义将要发送的电子邮件。第 4 步将信息结构化为 Mailgun 所期望的方式。请注意`html`和`text`字段。默认情况下，它将设置 HTML 为首选项，并将纯文本选项作为备选项。`TO`和`FROM`的格式应为`Name <address>`格式。您可以使用逗号将多个收件人分隔在`TO`中。

在第 5 步进行 API 调用。这是对消息端点的`POST`调用。数据以标准方式传输，并使用`auth`参数进行基本身份验证。请注意第 2 步中的定义。所有对 Mailgun 的调用都应包括此参数。它返回一条消息，通知您它已成功排队了消息。

在第 6 步，通过`GET`请求调用检索事件。这将显示最新执行的操作，其中最后一个将是最近的发送。还可以找到有关交付的信息。

# 还有更多...

要发送电子邮件，您需要设置用于发送电子邮件的域，而不是使用沙箱环境。您可以在这里找到说明：[`documentation.mailgun.com/en/latest/quickstart-sending.html#verify-your-domain`](https://documentation.mailgun.com/en/latest/quickstart-sending.html#verify-your-domain)。这需要您更改 DNS 记录以验证您是其合法所有者，并提高电子邮件的可交付性。

电子邮件可以以以下方式包含附件：

```py
attachments = [("attachment", ("attachment1.jpg", open("image.jpg","rb").read())),
               ("attachment", ("attachment2.txt", open("text.txt","rb").read()))]
response = requests.post(f"https://api.mailgun.net/v3/{DOMAIN}/messages",
                         auth=auth, files=attachments, data=data)
```

数据可以包括常规信息，如`cc`或`bcc`，但您还可以使用`o:deliverytime`参数将交付延迟最多三天：

```py
import datetime
import email.utils
delivery_time = datetime.datetime.now() + datetime.timedelta(days=1)
data = {
    ...
    'o:deliverytime': email.utils.format_datetime(delivery_time),
}
```

Mailgun 还可以用于接收电子邮件并在其到达时触发流程，例如，根据规则转发它们。查看 Mailgun 文档以获取更多信息。

完整的 Mailgun 文档可以在这里找到，[`documentation.mailgun.com/en/latest/quickstart.html`](https://documentation.mailgun.com/en/latest/quickstart.html)。一定要检查他们的*最佳实践*部分([`documentation.mailgun.com/en/latest/best_practices.html#email-best-practices`](https://documentation.mailgun.com/en/latest/best_practices.html#email-best-practices))，以了解发送电子邮件的世界以及如何避免被标记为垃圾邮件。

# 另请参阅

+   *使用电子邮件模板*配方

+   *发送单个电子邮件*配方

# 生成短信

最广泛使用的通信渠道之一是短信。短信非常方便用于分发信息。

短信可以用于营销目的，也可以用作警报或发送通知的方式，或者最近非常常见的是作为实施双因素身份验证系统的一种方式。

我们将使用 Twilio，这是一个提供 API 以轻松发送短信的服务。

# 准备就绪

我们需要在[`www.twilio.com/`](https://www.twilio.com/)为 Twilio 创建一个帐户。转到该页面并注册一个新帐户。

您需要按照说明设置一个电话号码来接收消息。您需要输入发送到此电话的代码或接听电话以验证此线路。

创建一个新项目并检查仪表板。从那里，您将能够创建第一个电话号码，能够接收和发送短信：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-auto-cb/img/93858574-0d63-4bac-b762-e8e0f5435059.png)

一旦号码配置完成，它将出现在所有产品和服务 | 电话号码*.*的活动号码部分。

在主仪表板上，检查`ACCOUNT SID`和`AUTH TOKEN`。稍后将使用它们。请注意，您需要显示身份验证令牌。

我们还需要安装`twilio`模块。将其添加到您的虚拟环境中：

```py
$ echo "twilio==6.16.1" >> requirements.txt
$ pip install -r requirements.txt
```

请注意，接收者电话号码只能是经过试用账户验证的号码。您可以验证多个号码；请参阅[`support.twilio.com/hc/en-us/articles/223180048-Adding-a-Verified-Phone-Number-or-Caller-ID-with-Twilio`](https://support.twilio.com/hc/en-us/articles/223180048-Adding-a-Verified-Phone-Number-or-Caller-ID-with-Twilio)上的文档。

# 如何做...

1.  从`twilio`模块导入`Client`：

```py
>>> from twilio.rest import Client
```

1.  在之前从仪表板获取的身份验证凭据。还要设置您的 Twilio 电话号码；例如，这里我们设置了`+353 12 345 6789`，一个虚假的爱尔兰号码。它将是您国家的本地号码：

```py
>>> ACCOUNT_SID = 'Your account SID'
>>> AUTH_TOKEN = 'Your secret token'
>>> FROM = '+353 12 345 6789'
```

1.  启动`client`以访问 API：

```py
>>> client = Client(ACCOUNT_SID, AUTH_TOKEN)
```

1.  向您授权的电话号码发送一条消息。请注意`from_`末尾的下划线：

```py
>>> message = client.messages.create(body='This is a test message from Python!', 
                                     from_=FROM, 
                                     to='+your authorised number')
```

1.  您将收到一条短信到您的手机：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-auto-cb/img/89dfa2a3-a312-4789-bbbe-74a394a84b48.png)

# 它是如何工作的...

使用 Twilio 客户端发送消息非常简单。

在第 1 步，我们导入`Client`，并准备在第 2 步配置的凭据和电话号码。

第 3 步使用适当的身份验证创建客户端，并在第 4 步发送消息。

请注意，`to`号码需要是试用帐户中经过身份验证的号码之一，否则将产生错误。您可以添加更多经过身份验证的号码；请查看 Twilio 文档。

从试用帐户发送的所有消息都将在短信中包含该详细信息，正如您在第 5 步中所看到的。

# 还有更多...

在某些地区（在撰写本文时为美国和加拿大），短信号码具有发送 MMS 消息（包括图像）的功能。要将图像附加到消息中，请添加`media_url`参数和要发送的图像的 URL：

```py
client.messages.create(body='An MMS message',
                       media_url='http://my.image.com/image.png', 
                       from_=FROM, 
                       to='+your authorised number')
```

客户端基于 RESTful API，并允许您执行多个操作，例如创建新的电话号码，或首先获取一个可用的号码，然后购买它：

```py
available_numbers = client.available_phone_numbers("IE").local.list()
number = available_numbers[0]
new_number = client.incoming_phone_numbers.create(phone_number=number.phone_number)
```

查看文档以获取更多可用操作，但大多数仪表板的点按操作都可以以编程方式执行。

Twilio 还能够执行其他电话服务，如电话呼叫和文本转语音。请在完整文档中查看。

完整的 Twilio 文档在此处可用：[`www.twilio.com/docs/`](https://www.twilio.com/docs/)。

# 另请参阅

+   *接收短信*配方

+   *创建 Telegram 机器人*配方

# 接收短信

短信也可以自动接收和处理。这使得可以提供按请求提供信息的服务（例如，发送 INFO GOALS 以接收足球联赛的结果），但也可以进行更复杂的流程，例如在机器人中，它可以与用户进行简单的对话，从而实现诸如远程配置恒温器之类的丰富服务。

每当 Twilio 接收到您注册的电话号码之一的短信时，它会执行对公开可用的 URL 的请求。这在服务中进行配置，这意味着它应该在您的控制之下。这会产生一个问题，即在互联网上有一个在您控制之下的 URL。这意味着仅仅您的本地计算机是行不通的，因为它是不可寻址的。我们将使用 Heroku（[`heroku.com`](http://heroku.com)）来提供一个可用的服务，但也有其他选择。Twilio 文档中有使用`grok`的示例，它允许通过在公共地址和您的本地开发环境之间创建隧道来进行本地开发。有关更多详细信息，请参见此处：[`www.twilio.com/blog/2013/10/test-your-webhooks-locally-with-ngrok.html`](https://www.twilio.com/blog/2013/10/test-your-webhooks-locally-with-ngrok.html)。

这种操作方式在通信 API 中很常见。值得注意的是，Twilio 有一个 WhatsApp 的 beta API，其工作方式类似。请查看文档以获取更多信息：[`www.twilio.com/docs/sms/whatsapp/quickstart/python`](https://www.twilio.com/docs/sms/whatsapp/quickstart/python)。

# 准备就绪

我们需要在[`www.twilio.com/`](https://www.twilio.com/)为 Twilio 创建一个帐户。有关详细说明，请参阅*准备就绪*部分中*生成短信*配方。

对于这个配方，我们还需要在 Heroku（[`www.heroku.com/`](https://www.heroku.com/)）中设置一个 Web 服务，以便能够创建一个能够接收发送给 Twilio 的短信的 Webhook。因为这个配方的主要目标是短信部分，所以在设置 Heroku 时我们将简洁一些，但您可以参考其出色的文档。它非常易于使用：

1.  在 Heroku 中创建一个帐户。

1.  您需要安装 Heroku 的命令行界面（所有平台的说明都在[`devcenter.heroku.com/articles/getting-started-with-python#set-up`](https://devcenter.heroku.com/articles/getting-started-with-python#set-up)），然后登录到命令行：

```py
$ heroku login
Enter your Heroku credentials.
Email: your.user@server.com
Password:
```

1.  从[`github.com/datademofun/heroku-basic-flask`](https://github.com/datademofun/heroku-basic-flask)下载一个基本的 Heroku 模板。我们将把它用作服务器的基础。

1.  将`twilio`客户端添加到`requirements.txt`文件中：

```py
$ echo "twilio" >> requirements.txt
```

1.  用 GitHub 中的`app.py`替换`app.py`：[`github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/Chapter08/app.py`](https://github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/Chapter08/app.py)。

您可以保留现有的`app.py`来检查模板示例和 Heroku 的工作原理。查看[`github.com/datademofun/heroku-basic-flask`](https://github.com/datademofun/heroku-basic-flask)中的 README。

1.  完成后，将更改提交到 Git：

```py
$ git add .
$ git commit -m 'first commit'
```

1.  在 Heroku 中创建一个新服务。它将随机生成一个新的服务名称（我们在这里使用`service-name-12345`）。此 URL 是可访问的：

```py
$ heroku create
Creating app... done, ⬢ SERVICE-NAME-12345
https://service-name-12345.herokuapp.com/ | https://git.heroku.com/service-name-12345.git
```

1.  部署服务。在 Heroku 中，部署服务会将代码推送到远程 Git 服务器：

```py
$ git push heroku master
...
remote: Verifying deploy... done.
To https://git.heroku.com/service-name-12345.git
 b6cd95a..367a994 master -> master
```

1.  检查 Webhook URL 的服务是否正在运行。请注意，它显示为上一步的输出。您也可以在浏览器中检查：

```py
$ curl https://service-name-12345.herokuapp.com/
All working!
```

# 如何做...

1.  转到 Twilio 并访问 PHONE NUMBER 部分。配置 Webhook URL。这将使 URL 在每次收到短信时被调用。转到 All Products and Services | Phone Numbers 中的 Active Numbers 部分，并填写 Webhook。请注意 Webhook 末尾的`/sms`。单击保存：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-auto-cb/img/278c3fc0-7ec7-4567-815a-060e27cd40f0.png)

1.  服务现在已经启动并可以使用。向您的 Twilio 电话号码发送短信，您应该会收到自动回复：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-auto-cb/img/9853424c-d223-4767-88b5-55a161028b3a.png)

请注意，模糊的部分应该用您的信息替换。

如果您有试用账户，您只能向您授权的电话号码之一发送消息，所以您需要从它们发送文本。

# 它是如何工作的...

第 1 步设置了 Webhook，因此 Twilio 在电话线上收到短信时调用您的 Heroku 应用程序。

让我们看看`app.py`中的代码，看看它是如何工作的。这里为了清晰起见对其进行了编辑；请在[`github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/Chapter08/app.py`](https://github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/Chapter08/app.py)中查看完整文件：

```py
...
@app.route('/')
def homepage():
    return 'All working!'

@app.route("/sms", methods=['GET', 'POST'])
def sms_reply():
    from_number = request.form['From']
    body = request.form['Body']
    resp = MessagingResponse()
    msg = (f'Awwwww! Thanks so much for your message {from_number}, '
           f'"{body}" to you too.')

    resp.message(msg)
    return str(resp)
...
```

`app.py`可以分为三个部分——文件开头的 Python 导入和 Flask 应用程序的启动，这只是设置 Flask（此处不显示）；调用`homepage`，用于测试服务器是否正常工作；和`sms_reply`，这是魔术发生的地方。

`sms_reply`函数从`request.form`字典中获取发送短信的电话号码以及消息的正文。然后，在`msg`中组成一个响应，将其附加到一个新的`MessagingResponse`，并返回它。

我们正在将用户的消息作为一个整体使用，但请记住第一章中提到的解析文本的所有技术，*让我们开始自动化之旅*。它们都适用于在此处检测预定义操作或任何其他文本处理。

返回的值将由 Twilio 发送回发送者，产生步骤 2 中看到的结果。

# 还有更多...

要能够生成自动对话，对话的状态应该被存储。对于高级状态，它可能应该被存储在数据库中，生成一个流程，但对于简单情况，将信息存储在`session`中可能足够了。会话能够在 cookies 中存储信息，这些信息在相同的来去电话号码组合之间是持久的，允许您在消息之间检索它。

例如，此修改将返回不仅发送正文，还有先前的正文。只包括相关部分：

```py
app = Flask(__name__)
app.secret_key = b'somethingreallysecret!!!!'
... 
@app.route("/sms", methods=['GET', 'POST'])
def sms_reply():
    from_number = request.form['From']
    last_message = session.get('MESSAGE', None)
    body = request.form['Body']
    resp = MessagingResponse()
    msg = (f'Awwwww! Thanks so much for your message {from_number}, '
           f'"{body}" to you too. ')
    if last_message:
        msg += f'Not so long ago you said "{last_message}" to me..'
    session['MESSAGE'] = body
    resp.message(msg)
    return str(resp)
```

上一个`body`存储在会话的`MESSAGE`键中，会话会被保留。注意使用会话数据需要秘密密钥的要求。阅读此处的信息：[`flask.pocoo.org/docs/1.0/quickstart/?highlight=session#sessions`](http://flask.pocoo.org/docs/1.0/quickstart/?highlight=session#sessions)。

要在 Heroku 中部署新版本，将新的`app.py`提交到 Git，然后执行`git push heroku master`。新版本将自动部署！

因为这个食谱的主要目标是演示如何回复，Heroku 和 Flask 没有详细描述，但它们都有很好的文档。Heroku 的完整文档可以在这里找到：[`devcenter.heroku.com/categories/reference`](https://devcenter.heroku.com/categories/reference)，Flask 的文档在这里：[`flask.pocoo.org/docs/`](http://flask.pocoo.org/docs/)。

请记住，使用 Heroku 和 Flask 只是为了方便这个食谱，因为它们是很好和易于使用的工具。有多种替代方案，只要您能够公开一个 URL，Twilio 就可以调用它。还要检查安全措施，以确保对此端点的请求来自 Twilio：[`www.twilio.com/docs/usage/security#validating-requests`](https://www.twilio.com/docs/usage/security#validating-requests)。

Twilio 的完整文档可以在这里找到：[`www.twilio.com/docs/`](https://www.twilio.com/docs/)。

# 另请参阅

+   *生成短信*食谱

+   *创建 Telegram 机器人*食谱

# 创建一个 Telegram 机器人

Telegram Messenger 是一个即时通讯应用程序，对创建机器人有很好的支持。机器人是旨在产生自动对话的小型应用程序。机器人的重要承诺是作为可以产生任何类型对话的机器，完全无法与人类对话区分开来，并通过*Turing 测试*，但这个目标对大部分来说是相当雄心勃勃且不现实的。

图灵测试是由艾伦·图灵于 1951 年提出的。两个参与者，一个人类和一个人工智能（机器或软件程序），通过文本（就像在即时通讯应用程序中）与一个人类评委进行交流，评委决定哪一个是人类，哪一个不是。如果评委只能猜对一半的时间，就无法轻易区分，因此人工智能通过了测试。这是对衡量人工智能的最早尝试之一。

但是，机器人也可以以更有限的方式非常有用，类似于需要按*2*来检查您的账户，按*3*来报告遗失的卡片的电话系统。在这个食谱中，我们将看到如何生成一个简单的机器人，用于显示公司的优惠和活动。

# 准备就绪

我们需要为 Telegram 创建一个新的机器人。这是通过一个名为**BotFather**的界面完成的，它是一个特殊的 Telegram 频道，允许我们创建一个新的机器人。您可以通过此链接访问该频道：[`telegram.me/botfather`](https://telegram.me/botfather)。通过您的 Telegram 帐户访问它。

运行`/start`以启动界面，然后使用`/newbot`创建一个新的机器人。界面会要求您输入机器人的名称和用户名，用户名应该是唯一的。

一旦设置好，它将给您以下内容：

+   您的机器人的 Telegram 频道-`https:/t.me/<yourusername>`。

+   允许访问机器人的令牌。复制它，因为稍后会用到。

如果丢失令牌，可以生成一个新的令牌。阅读 BotFather 的文档。

我们还需要安装 Python 模块`telepot`，它包装了 Telegram 的 RESTful 接口：

```py
$ echo "telepot==12.7" >> requirements.txt
$ pip install -r requirements.txt
```

从 GitHub 上下载`telegram_bot.py`脚本：[`github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/Chapter08/telegram_bot.py`](https://github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/Chapter08/telegram_bot.py)。

# 如何做...

1.  将生成的令牌设置到`telegram_bot.py`脚本的第 6 行的`TOKEN`常量中：

```py
TOKEN = '<YOUR TOKEN>'
```

1.  启动机器人：

```py
$ python telegram_bot.py
```

1.  使用 URL 在手机上打开 Telegram 频道并启动它。您可以使用`help`，`offers`和`events`命令：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-auto-cb/img/e8a122ba-dadf-4e78-9c32-d29e8d56449c.png)

# 工作原理...

第 1 步设置要用于您特定频道的令牌。在第 2 步中，我们在本地启动机器人。

让我们看看`telegram_bot.py`中的代码结构：

```py
IMPORTS

TOKEN

# Define the information to return per command
def get_help():
def get_offers():
def get_events():
COMMANDS = {
    'help': get_help,
    'offers': get_offers,
    'events': get_events,
}

class MarketingBot(telepot.helper.ChatHandler):
...

# Create and start the bot

```

`MarketingBot`类创建了一个与 Telegram 进行通信的接口：

+   当频道启动时，将调用`open`方法

+   当收到消息时，将调用`on_chat_message`方法

+   如果有一段时间没有回应，将调用`on_idle`

在每种情况下，`self.sender.sendMessage`方法用于向用户发送消息。大部分有趣的部分都发生在`on_chat_message`中：

```py
def on_chat_message(self, msg):
    # If the data sent is not test, return an error
    content_type, chat_type, chat_id = telepot.glance(msg)
    if content_type != 'text':
        self.sender.sendMessage("I don't understand you. "
                                "Please type 'help' for options")
        return

    # Make the commands case insensitive
    command = msg['text'].lower()
```

```py

    if command not in COMMANDS:
        self.sender.sendMessage("I don't understand you. "
                                "Please type 'help' for options")
        return

    message = COMMANDS[command]()
    self.sender.sendMessage(message)
```

首先，它检查接收到的消息是否为文本，如果不是，则返回错误消息。它分析接收到的文本，如果是定义的命令之一，则执行相应的函数以检索要返回的文本。

然后，将消息发送回用户。

第 3 步显示了从与机器人交互的用户的角度来看这是如何工作的。

# 还有更多...

您可以使用`BotFather`接口向您的 Telegram 频道添加更多信息，头像图片等。

为了简化我们的界面，我们可以创建一个自定义键盘来简化机器人。在定义命令之后创建它，在脚本的第 44 行左右：

```py
from telepot.namedtuple import ReplyKeyboardMarkup, KeyboardButton
keys = [[KeyboardButton(text=text)] for text in COMMANDS]
KEYBOARD = ReplyKeyboardMarkup(keyboard=keys)
```

请注意，它正在创建一个带有三行的键盘，每行都有一个命令。然后，在每个`sendMessage`调用中添加生成的`KEYBOARD`作为`reply_markup`，例如如下所示：

```py
 message = COMMANDS[command]()
 self.sender.sendMessage(message, reply_markup=KEYBOARD)
```

这将键盘替换为仅有定义的按钮，使界面非常明显：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-auto-cb/img/c7d4fc8c-6861-4cb5-b4e2-72ac8dd1108c.png)

这些更改可以在 GitHub 的`telegram_bot_custom_keyboard.py`文件中下载，链接在这里：[`github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/Chapter08/telegram_bot_custom_keyboard.py`](https://github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/Chapter08/telegram_bot_custom_keyboard.py)。

您可以创建其他类型的自定义界面，例如内联按钮，甚至是创建游戏的平台。查看 Telegram API 文档以获取更多信息。

与 Telegram 的交互也可以通过 webhook 完成，方式与*接收短信*配方中介绍的类似。在`telepot`文档中查看 Flask 的示例：[`github.com/nickoala/telepot/tree/master/examples/webhook`](https://github.com/nickoala/telepot/tree/master/examples/webhook)。

通过`telepot`可以设置 Telegram webhook。这要求您的服务位于 HTTPS 地址后，以确保通信是私密的。这可能对于简单的服务来说有点棘手。您可以在 Telegram 文档中查看有关设置 webhook 的文档：[`core.telegram.org/bots/api#setwebhook`](https://core.telegram.org/bots/api#setwebhook)。

电报机器人的完整 API 可以在这里找到：[`core.telegram.org/bots`](https://core.telegram.org/bots)。

`telepot`模块的文档可以在这里找到：[`telepot.readthedocs.io/en/latest/`](https://telepot.readthedocs.io/en/latest/)。

# 另请参阅

+   *生成短信*配方

+   *接收短信*配方
