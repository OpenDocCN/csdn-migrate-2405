# Python GUI 编程秘籍（二）

> 原文：[`zh.annas-archive.org/md5/de38d8b70825b858336fa5194110e245`](https://zh.annas-archive.org/md5/de38d8b70825b858336fa5194110e245)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：Matplotlib 图表

在这一章中，我们将使用 Python 3 和 Matplotlib 模块创建美丽的图表。

+   使用 Matplotlib 创建美丽的图表

+   Matplotlib - 使用 pip 下载模块

+   Matplotlib - 使用 whl 扩展名下载模块

+   创建我们的第一个图表

+   在图表上放置标签

+   如何给图表加上图例

+   调整图表的比例

+   动态调整图表的比例

# 介绍

在本章中，我们将创建美丽的图表，以直观地表示数据。根据数据源的格式，我们可以在同一图表中绘制一个或多个数据列。

我们将使用 Python Matplotlib 模块来创建我们的图表。

为了创建这些图形图表，我们需要下载额外的 Python 模块，有几种安装方法。

本章将解释如何下载 Matplotlib Python 模块，所有其他所需的 Python 模块，以及如何做到这一点的方法。

在安装所需的模块之后，我们将创建自己的 Python 图表。

# 使用 Matplotlib 创建美丽的图表

这个示例向我们介绍了 Matplotlib Python 模块，它使我们能够使用 Python 3 创建可视化图表。

以下 URL 是开始探索 Matplotlib 世界的好地方，并将教您如何创建本章中未提及的许多图表：

[`matplotlib.org/users/screenshots.html`](http://matplotlib.org/users/screenshots.html)

## 准备工作

为了使用 Matplotlib Python 模块，我们首先必须安装该模块，以及诸如 numpy 等其他相关的 Python 模块。

如果您使用的 Python 版本低于 3.4.3，我建议您升级 Python 版本，因为在本章中我们将使用 Python pip 模块来安装所需的 Python 模块，而 pip 是在 3.4.3 及以上版本中安装的。

### 注意

可以使用较早版本的 Python 3 安装 pip，但这个过程并不是很直观，因此最好升级到 3.4.3 或更高版本。

## 如何做...

以下图片是使用 Python 和 Matplotlib 模块创建的令人难以置信的图表的示例。

我从[`matplotlib.org/`](http://matplotlib.org/)网站复制了以下代码，它创建了这个令人难以置信的图表。该网站上有许多示例，我鼓励您尝试它们，直到找到您喜欢创建的图表类型。

以下是创建图表的代码，包括空格在内，不到 25 行的 Python 代码。

```py
from mpl_toolkits.mplot3d import Axes3D
from matplotlib import cm
from matplotlib.ticker import LinearLocator, FormatStrFormatter
import matplotlib.pyplot as plt
import numpy as np

fig = plt.figure()
ax = fig.gca(projection='3d')
X = np.arange(-5, 5, 0.25)
Y = np.arange(-5, 5, 0.25)
X, Y = np.meshgrid(X, Y)
R = np.sqrt(X**2 + Y**2)
Z = np.sin(R)
surf = ax.plot_surface(X, Y, Z, rstride=1, cstride=1, cmap=cm.coolwarm, linewidth=0, antialiased=False)

ax.set_zlim(-1.01, 1.01)

ax.zaxis.set_major_locator(LinearLocator(10))
ax.zaxis.set_major_formatter(FormatStrFormatter('%.02f'))

fig.colorbar(surf, shrink=0.5, aspect=5)

plt.show()
```

运行代码会创建以下图片中显示的图表：

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_05_01.jpg)

使用 Python 3.4 或更高版本与 Eclipse PyDev 插件运行代码可能会显示一些未解决的导入错误。这似乎是 PyDev 或 Java 中的一个错误。

如果您使用 Eclipse 进行开发，请忽略这些错误，因为代码将成功运行。

## 它是如何工作的...

为了创建如前面截图所示的美丽图表，我们需要下载其他几个 Python 模块。

以下示例将指导我们如何成功下载所有所需的模块，从而使我们能够创建自己的美丽图表。

# Matplotlib - 使用 pip 下载模块

下载额外的 Python 模块的常规方法是使用 pip。pip 模块预装在最新版本的 Python（3.4 及以上）中。

### 注意

如果您使用的是较旧版本的 Python，可能需要自己下载 pip 和 setuptools。

除了使用 Python 安装程序外，还有其他几个预编译的 Windows 可执行文件，可以让我们轻松安装 Matplotlib 等 Python 模块。

这个示例将展示如何通过 Windows 可执行文件成功安装 Matplotlib，以及使用 pip 安装 Matplotlib 库所需的其他模块。

## 准备工作

我们所需要做的就是在我们的 PC 上安装一个 Python 3.4（或更高版本）的发行版，以便下载所需的 Python 模块来使用 Matplotlib 模块。

## 如何做...

我们可以通过官方 Matplotlib 网站上的 Windows 可执行文件来安装 Matplotlib。

确保安装与您正在使用的 Python 版本匹配的 Matplotlib 版本。例如，如果您在 64 位操作系统（如 Microsoft Windows 7）上安装了 Python 3.4，则下载并安装`Matplotlib-1.4.3.win-amd64-py3.4.exe`。

### 注意

可执行文件名称中的"amd64"表示您正在安装 64 位版本。如果您使用 32 位 x86 系统，则安装 amd64 将不起作用。如果您安装了 32 位版本的 Python 并下载了 64 位 Python 模块，则可能会出现类似的问题。

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_05_02.jpg)

运行可执行文件将启动我们，并且看起来像这样：

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_05_03.jpg)

我们可以通过查看我们的 Python 安装目录来验证我们是否成功安装了 Matplotlib。

安装成功后，Matplotlib 文件夹将添加到 site-packages。在 Windows 上使用默认安装，site-packages 文件夹的完整路径是：

`C:\Python34\Lib\site-packages\matplotlib\`

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_05_04.jpg)

在官方 Matplotlib 网站上最简单的绘图示例需要使用 Python numpy 模块，所以让我们下载并安装这个模块。

### 注意

Numpy 是一个数学模块，它使 Matplotlib 图表的绘制成为可能，但远不止于 Matplotlib。如果您正在开发的软件需要大量的数学计算，您肯定会想要查看 numpy。

有一个优秀的网站，为我们提供了几乎所有 Python 模块的快速链接。它作为一个很好的时间节省者，指出了成功使用 Matplotlib 所需的其他 Python 模块，并给我们提供了下载这些模块的超链接，这使我们能够快速轻松地安装它们。

### 注意

这是链接：

[`www.lfd.uci.edu/~gohlke/pythonlibs/`](http://www.lfd.uci.edu/~gohlke/pythonlibs/)

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_05_05.jpg)

注意安装程序包的文件扩展名都以 whl 结尾。为了使用它们，我们必须安装 Python wheel 模块，我们使用 pip 来做到这一点。

### 注意

Wheels 是 Python 分发的新标准，旨在取代 eggs。

您可以在以下网站找到更多详细信息：

[`pythonwheels.com/`](http://pythonwheels.com/)

最好以管理员身份运行 Windows 命令处理器，以避免潜在的安装错误。

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_05_06.jpg)

## 它是如何工作的...

下载 Python 模块的常见方法是使用 pip，就像上面所示的那样。为了安装 Matplotlib 所需的所有模块，我们可以从主网站下载它们的下载格式已更改为使用 whl 格式。

下一个配方将解释如何使用 wheel 安装 Python 模块。

# Matplotlib - 使用 whl 扩展名下载模块

我们将使用几个 Matplotlib 需要的额外 Python 模块，在这个配方中，我们将使用 Python 的新模块分发标准 wheel 来下载它们。

### 注意

您可以在以下网址找到新的 wheel 标准的 Python 增强提案（PEP）：[`www.python.org/dev/peps/pep-0427/`](https://www.python.org/dev/peps/pep-0427/)

## 准备工作

为了下载带有 whl 扩展名的 Python 模块，必须首先安装 Python wheel 模块，这在前面的配方中已经解释过了。

## 如何做...

让我们从网上下载`numpy-1.9.2+mkl-cp34-none-win_amd64.whl`。安装了 wheel 模块后，我们可以使用 pip 来安装带有 whl 文件扩展名的软件包。

### 注意

Pip 随 Python 3.4.3 及以上版本一起提供。如果您使用的是较旧版本的 Python，我建议安装 pip，因为它可以让安装所有其他额外的 Python 模块变得更加容易。

一个更好的建议可能是将您的 Python 版本升级到最新的稳定版本。当您阅读本书时，最有可能的是 Python 3.5.0 或更高版本。

Python 是免费软件。升级对我们来说是没有成本的。

浏览到要安装的软件包所在的文件夹，并使用以下命令进行安装：

```py
**pip install numpy-1.9.2+mkl-cp34-none-win_amd64.whl**

```

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_05_07.jpg)

现在我们可以使用官方网站上最简单的示例应用程序创建我们的第一个 Matplotlib 图表。之后，我们将创建自己的图表。

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_05_08.jpg)

我们还没有准备好运行前面的代码，这表明我们需要下载更多的模块。虽然一开始需要下载更多的模块可能会有点烦人，但实际上这是一种代码重用的形式。

因此，让我们使用 pip 和 wheel 下载并安装 six 和所有其他所需的模块（如 dateutil、pyparsing 等），直到我们的代码能够工作并从只有几行 Python 代码中创建一个漂亮的图表。

我们可以从刚刚用来安装 numpy 的同一个网站下载所有所需的模块。这个网站甚至列出了我们正在安装的模块所依赖的所有其他模块，并提供了跳转到这个网站上的安装软件的超链接。

### 注意

如前所述，安装 Python 模块的 URL 是：[`www.lfd.uci.edu/~gohlke/pythonlibs/`](http://www.lfd.uci.edu/~gohlke/pythonlibs/)

## 它是如何工作的...

使我们能够从一个便利的地方下载许多 Python 模块的网站还提供其他 Python 模块。并非所有显示的依赖项都是必需的。这取决于您正在开发的内容。随着您使用 Matplotlib 库的旅程的推进，您可能需要下载和安装其他模块。

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_05_09.jpg)

# 创建我们的第一个图表

现在我们已经安装了所有所需的 Python 模块，我们可以使用 Matplotlib 创建自己的图表。

我们可以只用几行 Python 代码创建图表。

## 准备工作

使用前一个示例中的代码，我们现在可以创建一个看起来类似于下一个示例的图表。

## 如何做...

使用官方网站上提供的最少量的代码，我们可以创建我们的第一个图表。嗯，几乎。网站上显示的示例代码在导入`show`方法并调用它之前是无法工作的。

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_05_10.jpg)

我们可以简化代码，甚至通过使用官方 Matplotlib 网站提供的许多示例之一来改进它。

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_05_11.jpg)

## 它是如何工作的...

Python Matplotlib 模块，结合诸如 numpy 之类的附加组件，创建了一个非常丰富的编程环境，使我们能够轻松进行数学计算并在可视化图表中绘制它们。

Python numpy 方法`arange`并不打算安排任何事情。它的意思是创建“一个范围”，在 Python 中用于内置的“range”运算符。`linspace`方法可能会造成类似的混淆。谁是“lin”，在什么“空间”？

事实证明，该名称意味着“线性间隔向量”。

pyglet 函数`show`显示我们创建的图形。在成功创建第一个图形后，调用`show()`会产生一些副作用，当您尝试绘制另一个图形时。

# 在图表上放置标签

到目前为止，我们已经使用了默认的 Matplotlib GUI。现在我们将使用 Matplotlib 创建一些 tkinter GUI。

这将需要更多的 Python 代码行和导入更多的库，但这是值得的，因为我们正在通过画布控制我们的绘画。

我们将标签放在水平轴和垂直轴上，也就是*x*和*y*。

我们将通过创建一个 Matplotlib 图形来实现这一点。

我们还将学习如何使用子图，这将使我们能够在同一个窗口中绘制多个图形。

## 准备工作

安装必要的 Python 模块并知道在哪里找到官方在线文档和教程后，我们现在可以继续创建 Matplotlib 图表。

## 如何做...

虽然`plot`是创建 Matplotlib 图表的最简单方法，但是结合`Canvas`使用`Figure`创建一个更定制的图表，看起来更好，还可以让我们向其添加按钮和其他小部件。

```py
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import tkinter as tk
#--------------------------------------------------------------
fig = Figure(figsize=(12, 8), facecolor='white')
#--------------------------------------------------------------
# axis = fig.add_subplot(111)   # 1 row,  1 column, only graph
axis = fig.add_subplot(211)     # 2 rows, 1 column, Top graph
#--------------------------------------------------------------
xValues = [1,2,3,4]
yValues = [5,7,6,8]
axis.plot(xValues, yValues)

axis.set_xlabel('Horizontal Label')
axis.set_ylabel('Vertical Label')

# axis.grid()                   # default line style 
axis.grid(linestyle='-')        # solid grid lines
#--------------------------------------------------------------
def _destroyWindow():
    root.quit()
    root.destroy() 
#--------------------------------------------------------------
root = tk.Tk() 
root.withdraw()
root.protocol('WM_DELETE_WINDOW', _destroyWindow)   
#--------------------------------------------------------------
canvas = FigureCanvasTkAgg(fig, master=root)
canvas._tkcanvas.pack(side=tk.TOP, fill=tk.BOTH, expand=1)
#--------------------------------------------------------------
root.update()
root.deiconify()
root.mainloop()
```

运行上述代码会得到以下图表：

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_05_12.jpg)

在导入语句之后的第一行代码中，我们创建了一个`Figure`对象的实例。接下来，我们通过调用`add_subplot(211)`向这个图添加子图。211 中的第一个数字告诉图要添加多少个图，第二个数字确定列数，第三个数字告诉图以什么顺序显示图。

我们还添加了一个网格并更改了其默认线型。

尽管我们在图表中只显示一个图，但通过选择 2 作为子图的数量，我们将图向上移动，这导致图表底部出现额外的空白。这第一个图现在只占据屏幕的 50％，这会影响在显示时此图的网格线有多大。

### 注意

通过取消注释`axis =`和`axis.grid()`的代码来尝试该代码，以查看不同的效果。

我们可以通过将它们分配到第二个位置使用`add_subplot(212)`来添加更多的子图。

```py
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import tkinter as tk
#--------------------------------------------------------------
fig = Figure(figsize=(12, 8), facecolor='white')
#--------------------------------------------------------------
axis = fig.add_subplot(211)     # 2 rows, 1 column, Top graph
#--------------------------------------------------------------
xValues = [1,2,3,4]
yValues = [5,7,6,8]
axis.plot(xValues, yValues)

axis.set_xlabel('Horizontal Label')
axis.set_ylabel('Vertical Label')

axis.grid(linestyle='-')        # solid grid lines
#--------------------------------------------------------------
axis1 = fig.add_subplot(212)    # 2 rows, 1 column, Bottom graph
#--------------------------------------------------------------
xValues1 = [1,2,3,4]
yValues1 = [7,5,8,6]
axis1.plot(xValues1, yValues1)
axis1.grid()                    # default line style 
#--------------------------------------------------------------
def _destroyWindow():
    root.quit()
    root.destroy() 
#--------------------------------------------------------------
root = tk.Tk() 
root.withdraw()
root.protocol('WM_DELETE_WINDOW', _destroyWindow)   
#--------------------------------------------------------------
canvas = FigureCanvasTkAgg(fig, master=root)
canvas._tkcanvas.pack(side=tk.TOP, fill=tk.BOTH, expand=1)
#--------------------------------------------------------------
root.update()
root.deiconify()
root.mainloop()
```

现在运行略微修改的代码会将 axis1 添加到图表中。对于底部图的网格，我们将线型保留为默认值。

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_05_13.jpg)

## 工作原理...

我们导入了必要的 Matplotlib 模块来创建一个图和一个画布，用于在其上绘制图表。我们为*x*和*y*轴给出了一些值，并设置了很多配置选项中的一些。

我们创建了自己的 tkinter 窗口来显示图表并自定义了绘图的位置。

正如我们在前几章中看到的，为了创建一个 tkinter GUI，我们首先必须导入 tkinter 模块，然后创建`Tk`类的实例。我们将这个类实例分配给一个我们命名为`root`的变量，这是在示例中经常使用的名称。

我们的 tkinter GUI 直到我们启动主事件循环才会变得可见，为此，我们使用`root.mainloop()`。

避免在这里使用 Matplotlib 默认 GUI 并改为使用 tkinter 创建自己的 GUI 的一个重要原因是，我们想要改善默认 Matplotlib GUI 的外观，而使用 tkinter 可以很容易地实现这一点。

如果我们使用 tkinter 构建 GUI，就不会再出现那些过时的按钮出现在 Matplotlib GUI 底部。

同时，Matplotlib GUI 具有我们的 tkinter GUI 没有的功能，即当我们在图表内移动鼠标时，我们实际上可以看到 Matplotlib GUI 中的 x 和 y 坐标。 x 和 y 坐标位置显示在右下角。

# 如何给图表添加图例

一旦我们开始绘制多条数据点的线，事情可能会变得有点不清楚。通过向我们的图表添加图例，我们可以知道哪些数据是什么，它们实际代表什么。

我们不必选择不同的颜色来表示不同的数据。Matplotlib 会自动为每条数据点的线分配不同的颜色。

我们所要做的就是创建图表并向其添加图例。

## 准备工作

在这个示例中，我们将增强上一个示例中的图表。我们只会绘制一个图表。

## 如何做...

首先，我们将在同一图表中绘制更多的数据线，然后我们将向图表添加图例。

我们通过修改上一个示例中的代码来实现这一点。

```py
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import tkinter as tk
#--------------------------------------------------------------
fig = Figure(figsize=(12, 5), facecolor='white')
#--------------------------------------------------------------
axis  = fig.add_subplot(111)                  # 1 row, 1 column

xValues  = [1,2,3,4]

yValues0 = [6,7.5,8,7.5]
yValues1 = [5.5,6.5,8,6]
yValues2 = [6.5,7,8,7]

t0, = axis.plot(xValues, yValues0)
t1, = axis.plot(xValues, yValues1)
t2, = axis.plot(xValues, yValues2)

axis.set_ylabel('Vertical Label')
axis.set_xlabel('Horizontal Label')

axis.grid()

fig.legend((t0, t1, t2), ('First line', 'Second line', 'Third line'), 'upper right')

#--------------------------------------------------------------
def _destroyWindow():
    root.quit()
    root.destroy() 
#--------------------------------------------------------------
root = tk.Tk() 
root.withdraw()
root.protocol('WM_DELETE_WINDOW', _destroyWindow)
#--------------------------------------------------------------
canvas = FigureCanvasTkAgg(fig, master=root)
canvas._tkcanvas.pack(side=tk.TOP, fill=tk.BOTH, expand=1)
#--------------------------------------------------------------
root.update()
root.deiconify()
root.mainloop()
```

运行修改后的代码会创建以下图表，图例位于右上角：

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_05_14.jpg)

在这个示例中，我们只绘制了一个图表，我们通过更改`fig.add_subplot(111)`来实现这一点。我们还通过`figsize`属性略微修改了图表的大小。

接下来，我们创建了三个包含要绘制的值的 Python 列表。当我们绘制数据时，我们将图表的引用保存在本地变量中。

我们通过传入一个包含三个图表引用的元组，另一个包含随后在图例中显示的字符串的元组来创建图例，并在第三个参数中定位图例在图表中的位置。

Matplotlib 的默认设置为正在绘制的线条分配了一个颜色方案。

我们可以通过在绘制每个轴时设置属性来轻松地将这些默认颜色设置更改为我们喜欢的颜色。

我们通过使用颜色属性并为其分配一个可用的颜色值来实现这一点。

```py
t0, = axis.plot(xValues, yValues0, color = 'purple')
t1, = axis.plot(xValues, yValues1, color = 'red')
t2, = axis.plot(xValues, yValues2, color = 'blue')
```

请注意，t0、t1 和 t2 的变量赋值后面的逗号不是错误，而是为了创建图例而需要的。

在每个变量后面的逗号将列表转换为元组。如果我们省略这一点，我们的图例将不会显示。

代码仍将运行，只是没有预期的图例。

### 注意

当我们在 t0 =赋值后移除逗号时，我们会得到一个错误，第一行不再出现在图中。图表和图例仍然会被创建，但图例中不再出现第一行。

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_05_15.jpg)

## 它是如何工作的...

我们通过在同一图表中绘制三条数据线并为其添加图例来增强了我们的图表，以区分这三条线绘制的数据。

# 调整图表的比例

在以前的示例中，当我们创建我们的第一个图表并增强它们时，我们硬编码了这些值的视觉表示方式。

虽然这对我们使用的值很有帮助，但我们经常从非常大的数据库中绘制图表。

根据数据的范围，我们为垂直 y 维度的硬编码值可能并不总是最佳解决方案，这可能会使我们的图表中的线条难以看清。

## 准备工作

我们将改进我们在上一个示例中的代码。如果您没有输入所有以前示例中的代码，只需下载本章的代码，它将让您开始（然后您可以通过使用 Python 创建 GUI、图表等来玩得很开心）。

## 如何做...

将上一个示例中的`yValues1`代码行修改为使用 50 作为第三个值。

```py
axis  = fig.add_subplot(111)        # 1 row, 1 column

xValues  = [1,2,3,4]

yValues0 = [6,7.5,8,7.5]
yValues1 = [5.5,6.5,50,6]           # one very high value
yValues2 = [6.5,7,8,7]
```

与上一个示例中创建图表的代码唯一的区别是一个数据值。

通过更改一个与所有其他值的平均范围不接近的值，数据的视觉表示已经发生了戏剧性的变化，我们失去了关于整体数据的许多细节，现在主要看到一个高峰。

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_05_16.jpg)

到目前为止，我们的图表已根据它们所呈现的数据自动调整。

虽然这是 Matplotlib 的一个实用功能，但这并不总是我们想要的。我们可以通过限制垂直 y 维度来限制图表的比例。

```py
yValues0 = [6,7.5,8,7.5]
yValues1 = [5.5,6.5,50,6]           # one very high value (50)
yValues2 = [6.5,7,8,7]

axis.set_ylim(5, 8)                 # limit the vertical display
```

现在，`axis.set_ylim(5, 8)`这行代码限制了起始值为 5，垂直显示的结束值为 8。

现在，当我们创建图表时，高值峰值不再像以前那样有影响。

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_05_17.jpg)

## 它是如何工作的...

我们增加了数据中的一个值，这产生了戏剧性的效果。通过设置图表的垂直和水平显示限制，我们可以看到我们最感兴趣的数据。

像刚才显示的那样的尖峰也可能非常有趣。这一切取决于我们要寻找什么。数据的视觉表示具有很大的价值。

### 注意

一图胜千言。

# 动态调整图表的比例

在上一个示例中，我们学习了如何限制我们图表的缩放。在这个示例中，我们将进一步通过在表示数据之前动态调整缩放来设置限制并分析我们的数据。

## 准备工作

我们将通过动态读取数据、对其进行平均并调整我们的图表来增强上一个示例中的代码。

虽然我们通常会从外部来源读取数据，在这个示例中，我们使用 Python 列表创建我们要绘制的数据，如下面的代码所示。

## 如何做...

我们通过将数据分配给 xvalues 和 yvalues 变量来在我们的 Python 模块中创建自己的数据。

在许多图表中，x 和 y 坐标系的起始点通常是(0, 0)。这通常是一个好主意，所以让我们相应地调整我们的图表坐标代码。

让我们修改代码以限制 x 和 y 两个维度：

```py
xValues  = [1,2,3,4]

yValues0 = [6,7.5,8,7.5]
yValues1 = [5.5,6.5,50,6]           # one very high value (50)
yValues2 = [6.5,7,8,7]              

axis.set_ylim(0, 8)                 # lower limit (0)
axis.set_xlim(0, 8)                 # use same limits for x
```

现在我们已经为 x 和 y 设置了相同的限制，我们的图表可能看起来更加平衡。当我们运行修改后的代码时，我们得到了以下结果：

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_05_18.jpg)

也许从(0, 0)开始并不是一个好主意...

我们真正想做的是根据数据的范围动态调整我们的图表，同时限制过高或过低的值。

我们可以通过解析要在图表中表示的所有数据，同时设置一些明确的限制来实现这一点。

修改代码如下所示：

```py
xValues  = [1,2,3,4]

yValues0 = [6,7.5,8,7.5]
yValues1 = [5.5,6.5,50,6]              # one very high value (50)
yValues2 = [6.5,7,8,7]              
yAll = [yValues0, yValues1, yValues2]  # list of lists

# flatten list of lists retrieving minimum value
minY = min([y for yValues in yAll for y in yValues])

yUpperLimit = 20
# flatten list of lists retrieving max value within defined limit
maxY = max([y for yValues in yAll for y in yValues if y < yUpperLimit])

# dynamic limits
axis.set_ylim(minY, maxY)                 
axis.set_xlim(min(xValues), max(xValues))                

t0, = axis.plot(xValues, yValues0)
t1, = axis.plot(xValues, yValues1)
t2, = axis.plot(xValues, yValues2)
```

运行代码会得到以下图表。我们动态调整了它的 x 和 y 维度。请注意，现在 y 维度从 5.5 开始，而不是之前的 5.0。图表也不再从(0, 0)开始，这为我们提供了更有价值的关于我们的数据的信息。

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_05_19.jpg)

我们正在为 y 维度数据创建一个列表的列表，然后使用一个列表推导包装成对 Python 的`min()`和`max()`函数的调用。

如果列表推导似乎有点高级，它们基本上是一个非常压缩的循环。

它们还被设计为比常规编程循环更快。

在创建上述图表的 Python 代码中，我们创建了三个包含要绘制的 y 维度数据的列表。然后我们创建了另一个包含这三个列表的列表，从而创建了一个列表的列表。

就像这样：

```py
yValues0 = [6,7.5,8,7.5]
yValues1 = [5.5,6.5,50,6]              # one very high value (50)
yValues2 = [6.5,7,8,7]              
yAll = [yValues0, yValues1, yValues2]  # list of lists
```

我们对获取所有 y 维度数据的最小值以及包含在这三个列表中的最大值感兴趣。

我们可以通过 Python 列表推导来实现这一点。

```py
# flatten list of lists retrieving minimum value
minY = min([y for yValues in yAll for y in yValues])
```

在运行列表推导后，`minY`为 5.5。

上面的一行代码是列表推导，它遍历三个列表中包含的所有数据的所有值，并使用 Python 的`min`关键字找到最小值。

在同样的模式中，我们找到了我们希望绘制的数据中包含的最大值。这次，我们还在列表推导中设置了一个限制，忽略了所有超过我们指定限制的值，就像这样：

```py
yUpperLimit = 20
# flatten list of lists retrieving max value within defined limit
maxY = max([y for yValues in yAll for y in yValues if y < yUpperLimit])
```

在使用我们选择的限制条件运行上述代码后，`maxY`的值为 8（而不是 50）。

我们根据预定义条件选择 20 作为图表中显示的最大值，对最大值应用了限制。

对于 x 维度，我们只需在 Matplotlib 方法中调用`min()`和`max()`来动态调整图表的限制。

## 工作原理...

在这个示例中，我们创建了几个 Matplotlib 图表，并调整了其中一些可用属性。我们还使用核心 Python 动态控制了图表的缩放。


# 第六章：线程和网络

在本章中，我们将使用 Python 3 创建线程、队列和 TCP/IP 套接字。

+   如何创建多个线程

+   启动一个线程

+   停止一个线程

+   如何使用队列

+   在不同模块之间传递队列

+   使用对话框小部件将文件复制到您的网络

+   使用 TCP/IP 通过网络进行通信

+   使用 URLOpen 从网站读取数据

# 介绍

在本章中，我们将使用线程、队列和网络连接扩展我们的 Python GUI 的功能。

### 注意

tkinter GUI 是单线程的。每个涉及休眠或等待时间的函数都必须在单独的线程中调用，否则 tkinter GUI 会冻结。

当我们在 Windows 任务管理器中运行我们的 Python GUI 时，我们可以看到一个新的`python.exe`进程已经启动。

当我们给我们的 Python GUI 一个`.pyw`扩展名时，然后创建的进程将是`python.pyw`，可以在任务管理器中看到。

当创建一个进程时，该进程会自动创建一个主线程来运行我们的应用程序。这被称为单线程应用程序。

对于我们的 Python GUI，单线程应用程序将导致我们的 GUI 在调用较长时间的任务时变得冻结，比如点击一个有几秒钟休眠的按钮。

为了保持我们的 GUI 响应，我们必须使用多线程，这就是我们将在本章中学习的内容。

我们还可以通过创建多个 Python GUI 的实例来创建多个进程，可以在任务管理器中看到。

进程在设计上是相互隔离的，彼此不共享公共数据。为了在不同进程之间进行通信，我们必须使用**进程间通信**（**IPC**），这是一种高级技术。

另一方面，线程确实共享公共数据、代码和文件，这使得在同一进程内的线程之间的通信比使用 IPC 更容易。

### 注意

关于线程的很好的解释可以在这里找到：[`www.cs.uic.edu/~jbell/CourseNotes/OperatingSystems/4_Threads.html`](https://www.cs.uic.edu/~jbell/CourseNotes/OperatingSystems/4_Threads.html)

在本章中，我们将学习如何保持我们的 Python GUI 响应，并且不会冻结。

# 如何创建多个线程

我们将使用 Python 创建多个线程。这是为了保持我们的 GUI 响应而必要的。

### 注意

线程就像编织由纱线制成的织物，没有什么可害怕的。

## 准备就绪

多个线程在同一计算机进程内存空间内运行。不需要进程间通信（IPC），这会使我们的代码变得复杂。在本节中，我们将通过使用线程来避免 IPC。

## 如何做...

首先，我们将增加我们的`ScrolledText`小部件的大小，使其更大。让我们将`scrolW`增加到 40，`scrolH`增加到 10。

```py
# Using a scrolled Text control
scrolW  = 40; scrolH  =  10
self.scr = scrolledtext.ScrolledText(self.monty, width=scrolW, height=scrolH, wrap=tk.WORD)
self.scr.grid(column=0, row=3, sticky='WE', columnspan=3)
```

当我们现在运行结果的 GUI 时，`Spinbox`小部件相对于其上方的`Entry`小部件是居中对齐的，这看起来不好。我们将通过左对齐小部件来改变这一点。

在`grid`控件中添加`sticky='W'`，以左对齐`Spinbox`小部件。

```py
# Adding a Spinbox widget using a set of values
self.spin = Spinbox(self.monty, values=(1, 2, 4, 42, 100), width=5, bd=8, command=self._spin) 
self.spin.grid(column=0, row=2, sticky='W')
```

GUI 可能看起来还不错，所以下一步，我们将增加`Entry`小部件的大小，以获得更平衡的 GUI 布局。

将宽度增加到 24，如下所示：

```py
# Adding a Textbox Entry widget
self.name = tk.StringVar()
nameEntered = ttk.Entry(self.monty, width=24, textvariable=self.name)
nameEntered.grid(column=0, row=1, sticky='W')
```

让我们也稍微增加`Combobox`的宽度到 14。

```py
ttk.Label(self.monty, text="Choose a number:").grid(column=1, row=0)
number = tk.StringVar()
numberChosen = ttk.Combobox(self.monty, width=14, textvariable=number)
numberChosen['values'] = (1, 2, 4, 42, 100)
numberChosen.grid(column=1, row=1)
numberChosen.current(0)
```

运行修改和改进的代码会导致一个更大的 GUI，我们将在本节和下一节中使用它。

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_06_01.jpg)

为了在 Python 中创建和使用线程，我们必须从 threading 模块中导入`Thread`类。

```py
#======================
# imports
#======================
import tkinter as tk
from tkinter import ttk
from tkinter import scrolledtext
from tkinter import Menu  
from tkinter import Spinbox
import B04829_Ch06_ToolTip as tt

from threading import Thread

GLOBAL_CONST = 42
```

让我们在`OOP`类中添加一个在线程中创建的方法。

```py
class OOP():
    def methodInAThread(self):
        print('Hi, how are you?')
```

现在我们可以在代码中调用我们的线程方法，将实例保存在一个变量中。

```py
#======================
# Start GUI
#======================
oop = OOP()

# Running methods in Threads
runT = Thread(target=oop.methodInAThread)
oop.win.mainloop())
```

现在我们有一个线程化的方法，但当我们运行代码时，控制台上什么都没有打印出来！

我们必须先启动`Thread`，然后它才能运行，下一节将向我们展示如何做到这一点。

然而，在 GUI 主事件循环之后设置断点证明我们确实创建了一个`Thread`对象，这可以在 Eclipse IDE 调试器中看到。

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_06_02.jpg)

## 它是如何工作的...

在这个配方中，我们首先增加了 GUI 的大小，以便更好地看到打印到`ScrolledText`小部件中的结果，为了准备使用线程。

然后，我们从 Python 的`threading`模块中导入了`Thread`类。

之后，我们创建了一个在 GUI 内部从线程中调用的方法。

# 启动线程

这个配方将向我们展示如何启动一个线程。它还将演示为什么线程在长时间运行的任务期间保持我们的 GUI 响应是必要的。

## 准备工作

让我们首先看看当我们调用一个带有一些休眠的函数或方法时会发生什么，而不使用线程。

### 注意

我们在这里使用休眠来模拟一个现实世界的应用程序，该应用程序可能需要等待 Web 服务器或数据库响应，或者大文件传输或复杂计算完成其任务。

休眠是一个非常现实的占位符，并展示了涉及的原则。

在我们的按钮回调方法中添加一个循环和一些休眠时间会导致我们的 GUI 变得无响应，当我们尝试关闭 GUI 时，情况变得更糟。

```py
# Button callback
def clickMe(self):
  self.action.configure(text='Hello ' + self.name.get())
  # Non-threaded code with sleep freezes the GUI
  for idx in range(10):
    sleep(5)
    self.scr.insert(tk.INSERT, str(idx) + '\n')
```

![准备工作](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_06_03.jpg)

如果我们等待足够长的时间，方法最终会完成，但在此期间，我们的 GUI 小部件都不会响应点击事件。我们通过使用线程来解决这个问题。

### 注意

在之前的配方中，我们创建了一个要在线程中运行的方法，但到目前为止，线程还没有运行！

与常规的 Python 函数和方法不同，我们必须`start`一个将在自己的线程中运行的方法！

这是我们接下来要做的事情。

## 如何做...

首先，让我们将线程的创建移到它自己的方法中，然后从按钮回调方法中调用这个方法。

```py
# Running methods in Threads
def createThread(self):
  runT = Thread(target=self.methodInAThread)
  runT.start()
# Button callback
def clickMe(self):
  self.action.configure(text='Hello ' + self.name.get())
  self.createThread()
```

现在点击按钮会导致调用`createThread`方法，然后调用`methodInAThread`方法。

首先，我们创建一个线程并将其目标定位到一个方法。接下来，我们启动线程，该线程将在一个新线程中运行目标方法。

### 注意

GUI 本身运行在它自己的线程中，这是应用程序的主线程。

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_06_04.jpg)

我们可以打印出线程的实例。

```py
# Running methods in Threads
def createThread(self):
  runT = Thread(target=self.methodInAThread)
  runT.start()
  print(runT)
```

现在点击按钮会创建以下输出：

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_06_05.jpg)

当我们点击按钮多次时，我们可以看到每个线程都被分配了一个唯一的名称和 ID。

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_06_06.jpg)

现在让我们将带有`sleep`的循环代码移到`methodInAThread`方法中，以验证线程确实解决了我们的问题。

```py
def methodInAThread(self):
  print('Hi, how are you?')
  for idx in range(10):
    sleep(5)
    self.scr.insert(tk.INSERT, str(idx) + '\n')
```

当点击按钮时，数字被打印到`ScrolledText`小部件中，间隔五秒，我们可以在 GUI 的任何地方点击，切换标签等。我们的 GUI 再次变得响应，因为我们正在使用线程！

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_06_07.jpg)

## 它是如何工作的...

在这个配方中，我们在它们自己的线程中调用了 GUI 类的方法，并学会了我们必须启动这些线程。否则，线程会被创建，但只是坐在那里等待我们运行它的目标方法。

我们注意到每个线程都被分配了一个唯一的名称和 ID。

我们通过在代码中插入`sleep`语句来模拟长时间运行的任务，这向我们表明线程确实可以解决我们的问题。

# 停止线程

我们必须启动一个线程来通过调用`start()`方法实际让它做一些事情，因此，直觉上，我们会期望有一个匹配的`stop()`方法，但实际上并没有这样的方法。在这个配方中，我们将学习如何将线程作为后台任务运行，这被称为守护线程。当关闭主线程，也就是我们的 GUI 时，所有守护线程也将自动停止。

## 准备工作

当我们在线程中调用方法时，我们也可以向方法传递参数和关键字参数。我们首先通过这种方式开始这个示例。

## 如何做到...

通过在线程构造函数中添加`args=[8]`并修改目标方法以期望参数，我们可以向线程方法传递参数。`args`的参数必须是一个序列，所以我们将我们的数字包装在 Python 列表中。

```py
def methodInAThread(self, numOfLoops=10):
  for idx in range(numOfLoops):
    sleep(1)
    self.scr.insert(tk.INSERT, str(idx) + '\n')
```

在下面的代码中，`runT`是一个局部变量，我们只能在创建`runT`的方法的范围内访问它。

```py

# Running methods in Threads
def createThread(self):
  runT = Thread(target=self.methodInAThread, args=[8])
  runT.start()
```

通过将局部变量转换为成员变量，我们可以在另一个方法中调用`isAlive`来检查线程是否仍在运行。

```py
# Running methods in Threads
def createThread(self):
  self.runT = Thread(target=self.methodInAThread, args=[8])
  self.runT.start()
  print(self.runT)
  print('createThread():', self.runT.isAlive())
```

在前面的代码中，我们将我们的局部变量`runT`提升为我们类的成员。这样做的效果是使我们能够从我们类的任何方法中评估`self.runT`变量。

这是通过以下方式实现的：

```py
    def methodInAThread(self, numOfLoops=10):
        for idx in range(numOfLoops):
            sleep(1)
            self.scr.insert(tk.INSERT, str(idx) + '\n')
        sleep(1)
        print('methodInAThread():', self.runT.isAlive())
```

当我们单击按钮然后退出 GUI 时，我们可以看到`createThread`方法中的打印语句被打印出来，但我们看不到`methodInAThread`的第二个打印语句。

相反，我们会得到一个运行时错误。

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_06_08.jpg)

线程预期完成其分配的任务，因此当我们在线程尚未完成时关闭 GUI 时，Python 告诉我们我们启动的线程不在主事件循环中。

我们可以通过将线程转换为守护程序来解决这个问题，然后它将作为后台任务执行。

这给我们的是，一旦我们关闭我们的 GUI，也就是我们的主线程启动其他线程，守护线程将干净地退出。

我们可以通过在启动线程之前调用`setDaemon(True)`方法来实现这一点。

```py
# Running methods in Threads
def createThread(self):
  runT = Thread(target=self.methodInAThread)
  runT.setDaemon(True)
  runT.start()
  print(runT)
```

当我们现在单击按钮并在线程尚未完成其分配的任务时退出我们的 GUI 时，我们不再收到任何错误。

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_06_09.jpg)

## 它是如何工作的...

虽然有一个启动线程运行的方法，但令人惊讶的是，实际上并没有一个等效的停止方法。

在这个示例中，我们正在一个线程中运行一个方法，该方法将数字打印到我们的`ScrolledText`小部件中。

当我们退出 GUI 时，我们不再对曾经向我们的小部件打印的线程感兴趣，因此，通过将线程转换为后台守护程序，我们可以干净地退出 GUI。

# 如何使用队列

Python 队列是一种实现先进先出范例的数据结构，基本上就像一个管道一样工作。你把东西塞进管道的一端，它就从管道的另一端掉出来。

这种队列填充和填充泥浆到物理管道的主要区别在于，在 Python 队列中，事情不会混在一起。你放一个单位进去，那个单位就会从另一边出来。接下来，你放另一个单位进去（比如，例如，一个类的实例），整个单位将作为一个完整的整体从另一端出来。

它以我们插入代码到队列的确切顺序从另一端出来。

### 注意

队列不是一个我们推送和弹出数据的堆栈。堆栈是一个后进先出（LIFO）的数据结构。

队列是容器，用于保存从潜在不同数据源输入队列的数据。我们可以有不同的客户端在有数据可用时向队列提供数据。无论哪个客户端准备好向我们的队列发送数据，我们都可以显示这些数据在小部件中或将其转发到其他模块。

在队列中使用多个线程完成分配的任务在接收处理的最终结果并显示它们时非常有用。数据被插入到队列的一端，然后以有序的方式从另一端出来，先进先出（FIFO）。

我们的 GUI 可能有五个不同的按钮小部件，每个按钮小部件都会启动我们想要在小部件中显示的不同任务（例如，一个 ScrolledText 小部件）。

这五个不同的任务完成所需的时间不同。

每当一个任务完成时，我们立即需要知道这一点，并在我们的 GUI 中显示这些信息。

通过创建一个共享的 Python 队列，并让五个任务将它们的结果写入这个队列，我们可以使用 FIFO 方法立即显示已完成的任务的结果。

## 准备工作

随着我们的 GUI 在功能和实用性上不断增加，它开始与网络、进程和网站进行通信，并最终必须等待数据可用于 GUI 表示。

在 Python 中创建队列解决了等待数据在我们的 GUI 中显示的问题。

## 如何做...

为了在 Python 中创建队列，我们必须从`queue`模块导入`Queue`类。在我们的 GUI 模块的顶部添加以下语句：

```py
from threading import Thread
from time import sleep
from queue import Queue
```

这让我们开始了。

接下来，我们创建一个队列实例。

```py
def useQueues(self):
    guiQueue = Queue()     # create queue instance
```

### 注意

在前面的代码中，我们创建了一个本地的“队列”实例，只能在这个方法中访问。如果我们希望从其他地方访问这个队列，我们必须使用`self`关键字将其转换为我们的类的成员，这将本地变量绑定到整个类，使其可以在类中的任何其他方法中使用。在 Python 中，我们经常在`__init__(self)`方法中创建类实例变量，但 Python 非常实用，使我们能够在代码中的任何地方创建这些成员变量。

现在我们有了一个队列的实例。我们可以通过打印它来证明它有效。

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_06_10.jpg)

为了将数据放入队列，我们使用`put`命令。为了从队列中取出数据，我们使用`get`命令。

```py
# Create Queue instance  
def useQueues(self):
    guiQueue = Queue()
    print(guiQueue)
    guiQueue.put('Message from a queue')
    print(guiQueue.get())
```

运行修改后的代码会导致消息首先被放入“队列”，然后被从“队列”中取出，并打印到控制台。

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_06_11.jpg)

我们可以将许多消息放入队列。

```py
# Create Queue instance  
def useQueues(self):
    guiQueue = Queue()
    print(guiQueue)
    for idx in range(10):
        guiQueue.put('Message from a queue: ' + str(idx))
    print(guiQueue.get())
```

我们将 10 条消息放入了“队列”，但我们只取出了第一条。其他消息仍然在“队列”内，等待以 FIFO 方式取出。

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_06_12.jpg)

为了取出放入“队列”的所有消息，我们可以创建一个无限循环。

```py
# Create Queue instance
def useQueues(self):
    guiQueue = Queue()
    print(guiQueue)
    for idx in range(10):
        guiQueue.put('Message from a queue: ' + str(idx))

    while True: 
        print(guiQueue.get())
```

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_06_13.jpg)

虽然这段代码有效，但不幸的是它冻结了我们的 GUI。为了解决这个问题，我们必须在自己的线程中调用该方法，就像我们在之前的示例中所做的那样。

让我们在一个线程中运行我们的方法，并将其绑定到按钮事件：

```py
# Running methods in Threads
def createThread(self, num):
    self.runT = Thread(target=self.methodInAThread, args=[num])
    self.runT.setDaemon(True)
    self.runT.start()
    print(self.runT)
    print('createThread():', self.runT.isAlive())

    # textBoxes are the Consumers of Queue data
    writeT = Thread(target=self.useQueues, daemon=True)
    writeT.start()

# Create Queue instance  
def useQueues(self):
    guiQueue = Queue()
    print(guiQueue)
    for idx in range(10):
        guiQueue.put('Message from a queue: ' + str(idx))
    while True: 
        print(guiQueue.get())
```

当我们现在点击“按钮”时，我们不再会得到一个多余的弹出窗口，代码也能正常工作。

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_06_14.jpg)

## 它是如何工作的...

我们创建了一个“队列”，以 FIFO（先进先出）的方式将消息放入队列的一侧。我们从“队列”中取出消息，然后将其打印到控制台（stdout）。

我们意识到我们必须在自己的“线程”中调用该方法。

# 在不同模块之间传递队列

在这个示例中，我们将在不同的模块之间传递“队列”。随着我们的 GUI 代码变得越来越复杂，我们希望将 GUI 组件与业务逻辑分离，将它们分离到不同的模块中。

模块化使我们可以重用代码，并使代码更易读。

一旦要在我们的 GUI 中显示的数据来自不同的数据源，我们将面临延迟问题，这就是“队列”解决的问题。通过在不同的 Python 模块之间传递“队列”的实例，我们正在分离模块功能的不同关注点。

### 注意

GUI 代码理想情况下只关注创建和显示小部件。

业务逻辑模块的工作只是执行业务逻辑。

我们必须将这两个元素结合起来，理想情况下在不同模块之间尽可能少地使用关系，减少代码的相互依赖。

### 注意

避免不必要依赖的编码原则通常被称为“松耦合”。

为了理解松散耦合的重要性，我们可以在白板或纸上画一些框。一个框代表我们的 GUI 类和代码，而其他框代表业务逻辑、数据库等。

接下来，我们在框之间画线，绘制出这些框之间的相互依赖关系，这些框是我们的 Python 模块。

### 注意

我们在 Python 框之间的行数越少，我们的设计就越松散耦合。

## 准备工作

在上一个示例中，我们已经开始使用`Queues`。在这个示例中，我们将从我们的主 GUI 线程传递`Queue`的实例到其他 Python 模块，这将使我们能够从另一个模块向`ScrolledText`小部件写入内容，同时保持我们的 GUI 响应。

## 如何做...

首先，在我们的项目中创建一个新的 Python 模块。让我们称之为`Queues.py`。我们将在其中放置一个函数（暂时不需要 OOP），并将队列的一个实例传递给它。

我们还传递了创建 GUI 表单和小部件的类的自引用，这使我们能够从另一个 Python 模块中使用所有 GUI 方法。

我们在按钮回调中这样做。

### 注意

这就是面向对象编程的魔力。在类的中间，我们将自己传递给类内部调用的函数，使用`self`关键字。

现在代码看起来像这样。

```py
import B04829_Queues as bq

class OOP():
    # Button callback
    def clickMe(self):
      # Passing in the current class instance (self)
        print(self)
        bq.writeToScrol(self)
```

导入的模块包含我们正在调用的函数，

```py
def writeToScrol(inst):
    print('hi from Queue', inst)
    inst.createThread(6)

```

我们已经在按钮回调中注释掉了对`createThread`的调用，因为我们现在是从我们的新模块中调用它。

```py
# Threaded method does not freeze our GUI
# self.createThread()
```

通过从类实例向另一个模块中的函数传递自引用，我们现在可以从其他 Python 模块访问所有 GUI 元素。

运行代码会创建以下结果。

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_06_15.jpg)

接下来，我们将创建`Queue`作为我们类的成员，并将对它的引用放在类的`__init__`方法中。

```py
class OOP():
    def __init__(self):
        # Create a Queue
        self.guiQueue = Queue()
```

现在我们可以通过简单地使用传入的类引用将消息放入队列中。

```py
def writeToScrol(inst):
    print('hi from Queue', inst)
    for idx in range(10):
        inst.guiQueue.put('Message from a queue: ' + str(idx))
    inst.createThread(6)
```

我们 GUI 代码中的`createThread`方法现在只从队列中读取数据，这些数据是由我们新模块中的业务逻辑填充的，这样就将逻辑与我们的 GUI 模块分离开来了。

```py
def useQueues(self):
    # Now using a class member Queue
    while True:
        print(self.guiQueue.get())
```

运行我们修改后的代码会产生相同的结果。我们没有破坏任何东西（至少目前没有）！

## 它是如何工作的...

为了将 GUI 小部件与表达业务逻辑的功能分开，我们创建了一个类，将队列作为这个类的成员，并通过将类的实例传递到不同 Python 模块中的函数中，我们现在可以访问所有 GUI 小部件以及`Queue`。

这个示例是一个使用面向对象编程的合理情况的例子。

# 使用对话框小部件将文件复制到您的网络

这个示例向我们展示了如何将文件从本地硬盘复制到网络位置。

我们将使用 Python 的 tkinter 内置对话框之一，这使我们能够浏览我们的硬盘。然后我们可以选择要复制的文件。

这个示例还向我们展示了如何使`Entry`小部件只读，并将我们的`Entry`默认设置为指定位置，这样可以加快浏览我们的硬盘的速度。

## 准备工作

我们将扩展我们在之前示例中构建的 GUI 的**Tab 2**。

## 如何做...

将以下代码添加到我们的 GUI 中`def createWidgets(self)`方法中，放在我们创建 Tab Control 2 的底部。

新小部件框的父级是`tab2`，我们在`createWidgets()`方法的开头创建了它。只要您将下面显示的代码放在`tab2`的创建物理下方，它就会起作用。

```py
###########################################################
    def createWidgets(self):
        tabControl = ttk.Notebook(self.win)  # Create Tab  
        tab2 = ttk.Frame(tabControl)         # Add a second tab
        tabControl.add(tab2, text='Tab 2')

# Create Manage Files Frame 
mngFilesFrame = ttk.LabelFrame(tab2, text=' Manage Files: ')
mngFilesFrame.grid(column=0, row=1, sticky='WE', padx=10, pady=5)

# Button Callback
def getFileName():
    print('hello from getFileName')

# Add Widgets to Manage Files Frame
lb = ttk.Button(mngFilesFrame, text="Browse to File...", command=getFileName)
lb.grid(column=0, row=0, sticky=tk.W) 

file = tk.StringVar()
self.entryLen = scrolW
self.fileEntry = ttk.Entry(mngFilesFrame, width=self.entryLen, textvariable=file)
self.fileEntry.grid(column=1, row=0, sticky=tk.W)

logDir = tk.StringVar()
self.netwEntry = ttk.Entry(mngFilesFrame, width=self.entryLen, textvariable=logDir)
self.netwEntry.grid(column=1, row=1, sticky=tk.W) 
        def copyFile():
        import shutil   
        src  = self.fileEntry.get()
        file = src.split('/')[-1]  
        dst  = self.netwEntry.get() + '\\'+ file
        try:
            shutil.copy(src, dst)   
            mBox.showinfo('Copy File to Network', 'Success: File copied.')
        except FileNotFoundError as err:
            mBox.showerror('Copy File to Network', '*** Failed to copy file! ***\n\n' + str(err))
        except Exception as ex:
            mBox.showerror('Copy File to Network', '*** Failed to copy file! ***\n\n' + str(ex))

        cb = ttk.Button(mngFilesFrame, text="Copy File To :   ", command=copyFile)
        cb.grid(column=0, row=1, sticky=tk.E)

        # Add some space around each label
        for child in mngFilesFrame.winfo_children(): 
            child.grid_configure(padx=6, pady=6)
```

这将在我们的 GUI 的**Tab 2**中添加两个按钮和两个输入。

我们还没有实现按钮回调函数的功能。

运行代码会创建以下 GUI：

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_06_16.jpg)

点击**浏览文件...**按钮目前会在控制台上打印。

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_06_17.jpg)

我们可以使用 tkinter 的内置文件对话框，所以让我们在我们的 Python GUI 模块的顶部添加以下`import`语句。

```py
from tkinter import filedialog as fd
from os import path
```

现在我们可以在我们的代码中使用对话框。我们可以使用 Python 的 os 模块来查找 GUI 模块所在的完整路径，而不是硬编码路径。

```py
def getFileName():
    print('hello from getFileName')
    fDir  = path.dirname(__file__)
    fName = fd.askopenfilename(parent=self.win, initialdir=fDir)
```

单击浏览按钮现在会打开`askopenfilename`对话框。

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_06_18.jpg)

现在我们可以在这个目录中打开一个文件，或者浏览到另一个目录。在对话框中选择一个文件并单击**打开**按钮后，我们将保存文件的完整路径在`fName`本地变量中。

如果我们打开我们的 Python `askopenfilename`对话框小部件时，能够自动默认到一个目录，这将是很好的，这样我们就不必一直浏览到我们正在寻找的特定文件要打开的地方。

最好通过回到我们的 GUI **Tab 1**来演示如何做到这一点，这就是我们接下来要做的。

我们可以将默认值输入到 Entry 小部件中。回到我们的**Tab 1**，这非常容易。我们只需要在创建`Entry`小部件时添加以下两行代码即可。

```py
# Adding a Textbox Entry widget
self.name = tk.StringVar()
nameEntered = ttk.Entry(self.monty, width=24, textvariable=self.name)
nameEntered.grid(column=0, row=1, sticky='W')
nameEntered.delete(0, tk.END)
nameEntered.insert(0, '< default name >')
```

当我们现在运行 GUI 时，`nameEntered`输入框有一个默认值。

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_06_19.jpg)

我们可以使用以下 Python 语法获取我们正在使用的模块的完整路径，然后我们可以在其下创建一个新的子文件夹。我们可以将其作为模块级全局变量，或者我们可以在方法中创建子文件夹。

```py
# Module level GLOBALS
GLOBAL_CONST = 42
fDir   = path.dirname(__file__)
netDir = fDir + '\\Backup'

def __init__(self):
    self.createWidgets()       
    self.defaultFileEntries()

def defaultFileEntries(self):
    self.fileEntry.delete(0, tk.END)
    self.fileEntry.insert(0, fDir) 
    if len(fDir) > self.entryLen:
        self.fileEntry.config(width=len(fDir) + 3)
        self.fileEntry.config(state='readonly')

    self.netwEntry.delete(0, tk.END)
    self.netwEntry.insert(0, netDir) 
    if len(netDir) > self.entryLen:
        self.netwEntry.config(width=len(netDir) + 3)
```

我们为两个输入小部件设置默认值，并在设置它们后，将本地文件输入小部件设置为只读。

### 注意

这个顺序很重要。我们必须先填充输入框，然后再将其设置为只读。

在调用主事件循环之前，我们还选择**Tab 2**，不再将焦点设置到**Tab 1**的`Entry`中。在我们的 tkinter `notebook`上调用`select`是从零开始的，所以通过传入值 1，我们选择**Tab 2**...

```py
# Place cursor into name Entry
# nameEntered.focus()             
tabControl.select(1)
```

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_06_20.jpg)

由于我们不都在同一个网络上，这个示例将使用本地硬盘作为网络的示例。

UNC 路径是通用命名约定，这意味着我们可以通过双反斜杠访问网络服务器，而不是在访问 Windows PC 上的本地硬盘时使用典型的`C:\`。

### 注意

你只需要使用 UNC，并用`\\<server name> \<folder>\`替换`C:\`。

这个例子可以用来将我们的代码备份到一个备份目录，如果不存在，我们可以使用`os.makedirs`来创建它。

```py
# Module level GLOBALS
GLOBAL_CONST = 42

from os import makedirs
fDir   = path.dirname(__file__)
netDir = fDir + '\\Backup' 
if not path.exists(netDir):
    makedirs(netDir, exist_ok = True)
```

在选择要复制到其他地方的文件后，我们导入 Python 的`shutil`模块。我们需要文件源的完整路径，一个网络或本地目录路径，然后我们使用`shutil.copy`将文件名附加到我们将要复制的路径上。

### 注意

Shutil 是 shell utility 的简写。

我们还可以通过消息框向用户提供反馈，指示复制是否成功或失败。为了做到这一点，导入`messagebox`并将其重命名为`mBox`。

在下面的代码中，我们将混合两种不同的方法来放置我们的导入语句。在 Python 中，我们有一些其他语言不提供的灵活性。

我们通常将所有的导入语句放在每个 Python 模块的顶部，这样可以清楚地看出我们正在导入哪些模块。

同时，现代编码方法是将变量的创建放在首次使用它们的函数或方法附近。

在下面的代码中，我们在 Python 模块的顶部导入了消息框，然后在一个函数中也导入了 shutil Python 模块。

为什么我们要这样做呢？

这样做会起作用吗？

答案是，是的，它确实有效，我们将这个导入语句放在一个函数中，因为这是我们的代码中唯一需要这个模块的地方。

如果我们从不调用这个方法，那么我们将永远不会导入这个方法所需的模块。

在某种意义上，您可以将这种技术视为惰性初始化设计模式。

如果我们不需要它，我们就不会在 Python 代码中导入它，直到我们真正需要它。

这里的想法是，我们的整个代码可能需要，比如说，二十个不同的模块。在运行时，真正需要哪些模块取决于用户的交互。如果我们从未调用`copyFile()`函数，那么就没有必要导入`shutil`。

一旦我们点击调用`copyFile()`函数的按钮，在这个函数中，我们就导入了所需的模块。

```py
from tkinter import messagebox as mBox

def copyFile():
    import shutil   
    src = self.fileEntry.get()
    file = src.split('/')[-1]  
    dst = self.netwEntry.get() + '\\'+ file
    try:
      shutil.copy(src, dst)   
      mBox.showinfo('Copy File to Network', 'Success: File copied.')
    except FileNotFoundError as err:
      mBox.showerror('Copy File to Network', '*** Failed to copy file! ***\n\n' + str(err))
    except Exception as ex:
      mBox.showerror('Copy File to Network', '*** Failed to copy file! ***\n\n' + str(ex))
```

当我们现在运行我们的 GUI 并浏览到一个文件并点击复制时，文件将被复制到我们在`Entry`小部件中指定的位置。

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_06_21.jpg)

如果文件不存在，或者我们忘记浏览文件并尝试复制整个父文件夹，代码也会让我们知道，因为我们使用了 Python 的内置异常处理能力。

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_06_22.jpg)

## 它是如何工作的...

我们正在使用 Python shell 实用程序将文件从本地硬盘复制到网络。由于大多数人都没有连接到相同的局域网，我们通过将代码备份到不同的本地文件夹来模拟复制。

我们正在使用 tkinter 的对话框控件，并且通过默认目录路径，我们可以提高复制文件的效率。

# 使用 TCP/IP 通过网络进行通信

这个示例向您展示了如何使用套接字通过 TCP/IP 进行通信。为了实现这一点，我们需要 IP 地址和端口号。

为了保持简单并独立于不断变化的互联网 IP 地址，我们将创建自己的本地 TCP/IP 服务器，并作为客户端，学习如何连接到它并从 TCP/IP 连接中读取数据。

我们将通过使用我们在以前的示例中创建的队列，将这种网络功能集成到我们的 GUI 中。

## 准备工作

我们将创建一个新的 Python 模块，它将是 TCP 服务器。

## 如何做...

在 Python 中实现 TCP 服务器的一种方法是从`socketserver`模块继承。我们子类化`BaseRequestHandler`，然后覆盖继承的`handle`方法。在很少的 Python 代码行中，我们可以实现一个 TCP 服务器模块。

```py
from socketserver import BaseRequestHandler, TCPServer

class RequestHandler(BaseRequestHandler):
    # override base class handle method
    def handle(self):
        print('Server connected to: ', self.client_address)
        while True:
            rsp = self.request.recv(512)
            if not rsp: break
            self.request.send(b'Server received: ' + rsp)

def startServer():
    serv = TCPServer(('', 24000), RequestHandler)
    serv.serve_forever()
```

我们将我们的`RequestHandler`类传递给`TCPServer`初始化程序。空的单引号是传递本地主机的快捷方式，这是我们自己的 PC。这是 IP 地址 127.0.0.1 的 IP 地址。元组中的第二项是端口号。我们可以选择任何在本地 PC 上未使用的端口号。

我们只需要确保在 TCP 连接的客户端端口上使用相同的端口，否则我们将无法连接到服务器。当然，在客户端可以连接到服务器之前，我们必须先启动服务器。

我们将修改我们的`Queues.py`模块，使其成为 TCP 客户端。

```py
from socket import socket, AF_INET, SOCK_STREAM

def writeToScrol(inst):
    print('hi from Queue', inst)
    sock = socket(AF_INET, SOCK_STREAM)
    sock.connect(('localhost', 24000))
    for idx in range(10):
        sock.send(b'Message from a queue: ' + bytes(str(idx).encode()) )
        recv = sock.recv(8192).decode()
        inst.guiQueue.put(recv)      
    inst.createThread(6)
```

这是我们与 TCP 服务器通信所需的所有代码。在这个例子中，我们只是向服务器发送一些字节，服务器将它们发送回来，并在返回响应之前添加一些字符串。

### 注意

这显示了 TCP 通过网络进行通信的原理。

一旦我们知道如何通过 TCP/IP 连接到远程服务器，我们将使用由我们感兴趣的通信程序的协议设计的任何命令。第一步是在我们可以向驻留在服务器上的特定应用程序发送命令之前进行连接。

在`writeToScrol`函数中，我们将使用与以前相同的循环，但现在我们将把消息发送到 TCP 服务器。服务器修改接收到的消息，然后将其发送回给我们。接下来，我们将其放入 GUI 成员队列中，就像以前的示例一样，在其自己的`Thread`中运行。

### 注意

在 Python 3 中，我们必须以二进制格式通过套接字发送字符串。现在添加整数索引变得有点复杂，因为我们必须将其转换为字符串，对其进行编码，然后将编码后的字符串转换为字节！

```py
sock.send(b'Message from a queue: ' + bytes(str(idx).encode()) )
```

注意字符串前面的`b`，然后，嗯，所有其他所需的转换...

我们在 OOP 类的初始化程序中启动 TCP 服务器的线程。

```py
class OOP():
    def __init__(self):
    # Start TCP/IP server in its own thread
        svrT = Thread(target=startServer, daemon=True)
        svrT.start()
```

现在，在**Tab 1**上单击**Click Me!**按钮将在我们的`ScrolledText`小部件中创建以下输出，以及在控制台上，由于使用`Threads`，响应非常快。

![操作步骤...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_06_23.jpg)

## 它是如何工作的...

我们创建了一个 TCP 服务器来模拟连接到本地区域网络或互联网上的服务器。我们将我们的队列模块转换为 TCP 客户端。我们在它们自己的后台线程中运行队列和服务器，这样我们的 GUI 非常响应。

# 使用 URLOpen 从网站读取数据

这个示例展示了我们如何使用 Python 的内置模块轻松读取整个网页。我们将首先以原始格式显示网页数据，然后解码它，然后在我们的 GUI 中显示它。

## 准备工作

我们将从网页中读取数据，然后在我们的 GUI 的`ScrolledText`小部件中显示它。

## 如何做...

首先，我们创建一个新的 Python 模块并命名为`URL.py`。

然后，我们导入所需的功能来使用 Python 读取网页。

我们可以用很少的代码来做到这一点。

我们将我们的代码包装在一个类似于 Java 和 C#的`try…except`块中。这是 Python 支持的一种现代编码方法。

每当我们有可能不完整的代码时，我们可以尝试这段代码，如果成功，一切都很好。

如果`try…except`块中的代码块不起作用，Python 解释器将抛出几种可能的异常，然后我们可以捕获。一旦我们捕获了异常，我们就可以决定接下来要做什么。

Python 中有一系列的异常，我们还可以创建自己的类，继承并扩展 Python 异常类。

在下面显示的代码中，我们主要关注我们尝试打开的 URL 可能不可用，因此我们将我们的代码包装在`try…except`代码块中。

如果代码成功打开所请求的 URL，一切都很好。

如果失败，可能是因为我们的互联网连接断开了，我们就会进入代码的异常部分，并打印出发生异常的信息。

### 注意

您可以在[`docs.python.org/3.4/library/exceptions.html`](https://docs.python.org/3.4/library/exceptions.html)了解更多关于 Python 异常处理的信息。

```py
from urllib.request import urlopen
link = 'http://python.org/' 
try:
    f = urlopen(link)
    print(f)
    html = f.read()
    print(html)
    htmldecoded = html.decode()
    print(htmldecoded)

except Exception as ex:
    print('*** Failed to get Html! ***\n\n' + str(ex))
```

通过在官方 Python 网站上调用`urlopen`，我们得到整个数据作为一个长字符串。

第一个打印语句将这个长字符串打印到控制台上。

然后我们对结果调用`decode`，这次我们得到了一千多行的网页数据，包括一些空白。

我们还打印调用`urlopen`的类型，它是一个`http.client.HTTPResponse`对象。实际上，我们首先打印出来。

![操作步骤...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_06_24.jpg)

这是我们刚刚读取的官方 Python 网页。如果您是 Web 开发人员，您可能对如何处理解析数据有一些好主意。

![操作步骤...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_06_25.jpg)

接下来，我们在我们的 GUI 中的`ScrolledText`小部件中显示这些数据。为了这样做，我们必须将我们的新模块连接到我们的 GUI，从网页中读取数据。

为了做到这一点，我们需要一个对我们 GUI 的引用，而一种方法是通过将我们的新模块绑定到**Tab 1**按钮回调。

我们可以将从 Python 网页解码的 HTML 数据返回给`Button`小部件，然后将其放在`ScrolledText`控件中。

因此，让我们将我们的代码转换为一个函数，并将数据返回给调用代码。

```py
from urllib.request import urlopen
link = 'http://python.org/'
def getHtml():
    try:
        f = urlopen(link)
        #print(f)
        html = f.read()
        #print(html)
        htmldecoded = html.decode()
        #print(htmldecoded)     
    except Exception as ex:
        print('*** Failed to get Html! ***\n\n' + str(ex))
    else:
        return htmldecoded  
```

现在，我们可以通过首先导入新模块，然后将数据插入到小部件中，在我们的`button`回调方法中写入数据到`ScrolledText`控件。在调用`writeToScrol`之后，我们还给它一些休眠时间。

```py
import B04829_Ch06_URL as url

# Button callback
def clickMe(self):
  bq.writeToScrol(self)       
  sleep(2)
  htmlData = url.getHtml()
  print(htmlData)
  self.scr.insert(tk.INSERT, htmlData)
```

HTML 数据现在显示在我们的 GUI 小部件中。

![操作步骤...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_06_26.jpg)

## 它是如何工作的...

我们创建了一个新模块，将从网页获取数据的代码与我们的 GUI 代码分离。这总是一个好主意。我们读取网页数据，然后解码后返回给调用代码。然后我们使用按钮回调函数将返回的数据放入`ScrolledText`控件中。

本章向我们介绍了一些高级的 Python 编程概念，我们将它们结合起来，制作出一个功能性的 GUI 程序。


# 第七章：通过我们的 GUI 将数据存储在 MySQL 数据库中

在本章中，我们将通过连接到 MySQL 数据库来增强我们的 Python GUI。

+   从 Python 连接到 MySQL 数据库

+   配置 MySQL 连接

+   设计 Python GUI 数据库

+   使用 SQL INSERT 命令

+   使用 SQL UPDATE 命令

+   使用 SQL DELETE 命令

+   从我们的 MySQL 数据库中存储和检索数据

# 介绍

在我们可以连接到 MySQL 服务器之前，我们必须先访问 MySQL 服务器。本章的第一个步骤将向您展示如何安装免费的 MySQL 服务器社区版。

成功连接到我们的 MySQL 服务器运行实例后，我们将设计并创建一个数据库，该数据库将接受一本书的标题，这可能是我们自己的日记或者是我们在互联网上找到的引用。我们将需要书的页码，这可能为空白，然后我们将使用我们在 Python 3 中构建的 GUI 将我们喜欢的引用从一本书、日记、网站或朋友中`插入`到我们的 MySQL 数据库中。

我们将使用我们的 Python GUI 来插入、修改、删除和显示我们喜欢的引用，以发出这些 SQL 命令并显示数据。

### 注意

**CRUD**是您可能遇到的一个数据库术语，它缩写了四个基本的 SQL 命令，代表**创建**、**读取**、**更新**和**删除**。

# 从 Python 连接到 MySQL 数据库

在我们可以连接到 MySQL 数据库之前，我们必须先连接到 MySQL 服务器。

为了做到这一点，我们需要知道 MySQL 服务器的 IP 地址以及它所监听的端口。

我们还必须是一个注册用户，并且需要密码才能被 MySQL 服务器验证。

## 准备工作

您需要访问一个正在运行的 MySQL 服务器实例，并且您还需要具有管理员权限才能创建数据库和表。

在官方 MySQL 网站上有一个免费的 MySQL 社区版可用。您可以从以下网址在本地 PC 上下载并安装它：[`dev.mysql.com/downloads/`](http://dev.mysql.com/downloads/)

### 注意

在本章中，我们使用的是 MySQL 社区服务器（GPL）版本：5.6.26。

## 如何做...

为了连接到 MySQL，我们首先需要安装一个特殊的 Python 连接器驱动程序。这个驱动程序将使我们能够从 Python 与 MySQL 服务器通信。

该驱动程序可以在 MySQL 网站上免费获得，并附带一个非常好的在线教程。您可以从以下网址安装它：

[`dev.mysql.com/doc/connector-python/en/index.html`](http://dev.mysql.com/doc/connector-python/en/index.html)

### 注意

确保选择与您安装的 Python 版本匹配的安装程序。在本章中，我们使用 Python 3.4 的安装程序。

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_07_01.jpg)

在安装过程的最后，目前有一点小小的惊喜。当我们启动`.msi`安装程序时，我们会短暂地看到一个显示安装进度的 MessageBox，但然后它就消失了。我们没有收到安装是否成功的确认。

验证我们是否安装了正确的驱动程序，让 Python 能够与 MySQL 通信，一种方法是查看 Python site-packages 目录。

如果您的 site-packages 目录看起来类似于以下屏幕截图，并且您看到一些新文件的名称中带有`mysql_connector_python`，那么我们确实安装了一些东西...

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_07_02.jpg)

上述提到的官方 MySQL 网站附带一个教程，网址如下：

[`dev.mysql.com/doc/connector-python/en/connector-python-tutorials.html`](http://dev.mysql.com/doc/connector-python/en/connector-python-tutorials.html)

在线教程示例中关于验证安装 Connector/Python 驱动程序是否成功的部分有点误导，因为它试图连接到一个员工数据库，这个数据库在我的社区版中并没有自动创建。

验证我们的 Connector/Python 驱动程序是否真的安装了的方法是，只需连接到 MySQL 服务器而不指定特定的数据库，然后打印出连接对象。

### 注意

用你在 MySQL 安装中使用的真实凭据替换占位符括号名称`<adminUser>`和`<adminPwd>`。

如果您安装了 MySQL 社区版，您就是管理员，并且在 MySQL 安装过程中会选择用户名和密码。

```py
import mysql.connector as mysql

conn = mysql.connect(user=<adminUser>, password=<adminPwd>,
                     host='127.0.0.1')
print(conn)

conn.close()
```

如果运行上述代码导致以下输出打印到控制台，则表示正常。

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_07_03.jpg)

如果您无法连接到 MySQL 服务器，那么在安装过程中可能出了问题。如果是这种情况，请尝试卸载 MySQL，重新启动您的 PC，然后再次运行 MySQL 安装程序。仔细检查您下载的 MySQL 安装程序是否与您的 Python 版本匹配。如果您安装了多个版本的 Python，有时会导致混淆，因为您最后安装的版本会被添加到 Windows 路径环境变量中，并且一些安装程序只会使用在此位置找到的第一个 Python 版本。

当我安装了 Python 32 位版本并且我困惑为什么一些我下载的模块无法工作时，这种情况发生了。

安装程序下载了 32 位模块，这些模块与 64 位版本的 Python 不兼容。

## 它是如何工作的...

为了将我们的 GUI 连接到 MySQL 服务器，如果我们想创建自己的数据库，我们需要能够以管理员权限连接到服务器。

如果数据库已经存在，那么我们只需要连接、插入、更新和删除数据的授权权限。

在下一个教程中，我们将在 MySQL 服务器上创建一个新的数据库。

# 配置 MySQL 连接

在上一个教程中，我们使用了最短的方式通过将用于身份验证的凭据硬编码到`connection`方法中来连接到 MySQL 服务器。虽然这是早期开发的快速方法，但我们绝对不希望将我们的 MySQL 服务器凭据暴露给任何人，除非我们*授予*特定用户对数据库、表、视图和相关数据库命令的权限。

通过将凭据存储在配置文件中，通过 MySQL 服务器进行身份验证的一个更安全的方法是我们将在本教程中实现的。

我们将使用我们的配置文件连接到 MySQL 服务器，然后在 MySQL 服务器上创建我们自己的数据库。

### 注意

我们将在所有接下来的教程中使用这个数据库。

## 准备工作

需要具有管理员权限的运行中的 MySQL 服务器才能运行本教程中显示的代码。

### 注意

上一个教程展示了如何安装免费的 MySQL 服务器社区版。管理员权限将使您能够实现这个教程。

## 如何做...

首先，在`MySQL.py`代码的同一模块中创建一个字典。

```py
# create dictionary to hold connection info
dbConfig = {
    'user': <adminName>,      # use your admin name 
    'password': <adminPwd>,   # use your admin password
    'host': '127.0.0.1',      # IP address of localhost
    }
```

接下来，在连接方法中，我们解压字典的值。而不是写成，

```py
mysql.connect('user': <adminName>,  'password': <adminPwd>, 'host': '127.0.0.1') 
```

我们使用`(**dbConfig)`，这与上面的方法相同，但更简洁。

```py
import mysql.connector as mysql
# unpack dictionary credentials 
conn = mysql.connect(**dbConfig)
print(conn)
```

这将导致与 MySQL 服务器的相同成功连接，但不同之处在于连接方法不再暴露任何关键任务信息。

### 注意

数据库服务器对你的任务至关重要。一旦你丢失了宝贵的数据...并且找不到任何最近的备份时，你就会意识到这一点！

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_07_04.jpg)

现在，在同一个 Python 模块中将相同的用户名、密码、数据库等放入字典中并不能消除任何人浏览代码时看到凭据的风险。

为了增加数据库安全性，我们首先将字典移到自己的 Python 模块中。让我们称这个新的 Python 模块为`GuiDBConfig.py`。

然后我们导入这个模块并解压凭据，就像之前做的那样。

```py
import GuiDBConfig as guiConf
# unpack dictionary credentials 
conn = mysql.connect(**guiConf.dbConfig)
print(conn)
```

### 注意

一旦我们将这个模块放在一个安全的地方，与其余代码分开，我们就为我们的 MySQL 数据实现了更高级别的安全性。

现在我们知道如何连接到 MySQL 并具有管理员权限，我们可以通过发出以下命令来创建我们自己的数据库：

```py
GUIDB = 'GuiDB'

# unpack dictionary credentials 
conn = mysql.connect(**guiConf.dbConfig)

cursor = conn.cursor()

try:
    cursor.execute("CREATE DATABASE {} DEFAULT CHARACTER SET 'utf8'".format(GUIDB))

except mysql.Error as err:
    print("Failed to create DB: {}".format(err))

conn.close()
```

为了执行对 MySQL 的命令，我们从连接对象创建一个游标对象。

游标通常是数据库表中特定行的位置，我们可以在表中向上或向下移动，但在这里我们使用它来创建数据库本身。

我们将 Python 代码包装到`try...except`块中，并使用 MySQL 的内置错误代码告诉我们是否出现了任何问题。

我们可以通过执行创建数据库的代码两次来验证此块是否有效。第一次，它将在 MySQL 中创建一个新数据库，第二次将打印出一个错误消息，说明此数据库已经存在。

我们可以通过使用完全相同的游标对象语法执行以下 MySQL 命令来验证哪些数据库存在。

我们不是发出`CREATE DATABASE`命令，而是创建一个游标并使用它来执行`SHOW DATABASES`命令，然后获取并打印到控制台输出的结果。

```py
import mysql.connector as mysql
import GuiDBConfig as guiConf

# unpack dictionary credentials 
conn = mysql.connect(**guiConf.dbConfig)

cursor = conn.cursor()

cursor.execute("SHOW DATABASES")
print(cursor.fetchall())

conn.close()
```

### 注意

我们通过在游标对象上调用`fetchall`方法来检索结果。

运行此代码会显示我们的 MySQL 服务器实例中当前存在哪些数据库。从输出中可以看到，MySQL 附带了几个内置数据库，例如`information_schema`等。我们已成功创建了自己的`guidb`数据库，如输出所示。所有其他数据库都是 MySQL 附带的。

![如何操作...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_07_05.jpg)

请注意，尽管我们在创建时指定了数据库的混合大小写字母为 GuiDB，但`SHOW DATABASES`命令显示 MySQL 中所有现有数据库的小写形式，并将我们的数据库显示为`guidb`。

## 它是如何工作的...

为了将我们的 Python GUI 连接到 MySQL 数据库，我们首先必须知道如何连接到 MySQL 服务器。这需要建立一个连接，只有当我们能够提供所需的凭据时，MySQL 才会接受这个连接。

虽然将字符串放入一行 Python 代码很容易，但在处理数据库时，我们必须非常谨慎，因为今天的个人沙箱开发环境，明天很容易就可能变成全球网络上可以访问的环境。

您不希望危害数据库安全性，这个配方的第一部分展示了通过将 MySQL 服务器的连接凭据放入一个单独的文件，并将此文件放在外部世界无法访问的位置，来更安全地放置连接凭据的方法，我们的数据库系统将变得更加安全。

在真实的生产环境中，MySQL 服务器安装、连接凭据和 dbConfig 文件都将由 IT 系统管理员处理，他们将使您能够导入 dbConfig 文件以连接到 MySQL 服务器，而您不知道实际的凭据是什么。解压 dbConfig 不会像我们的代码那样暴露凭据。

第二部分在 MySQL 服务器实例中创建了我们自己的数据库，我们将在接下来的配方中扩展并使用这个数据库，将其与我们的 Python GUI 结合使用。

# 设计 Python GUI 数据库

在开始创建表并向其中插入数据之前，我们必须设计数据库。与更改本地 Python 变量名称不同，一旦创建并加载了数据的数据库模式就不那么容易更改。

在删除表之前，我们必须提取数据，然后`DROP`表，并以不同的名称重新创建它，最后重新导入原始数据。

你明白了...

设计我们的 GUI MySQL 数据库首先意味着考虑我们希望我们的 Python 应用程序如何使用它，然后选择与预期目的相匹配的表名。

## 准备工作

我们正在使用前一篇中创建的 MySQL 数据库。需要运行一个 MySQL 实例，前两篇文章介绍了如何安装 MySQL 和所有必要的附加驱动程序，以及如何创建本章中使用的数据库。

## 操作步骤…

首先，我们将在前几篇中创建的两个标签之间在我们的 Python GUI 中移动小部件，以便更好地组织我们的 Python GUI 以连接到 MySQL 数据库。

我们重命名了几个小部件，并将访问 MySQL 数据的代码分离到以前称为 Tab 1 的位置，我们将不相关的小部件移动到我们在早期配方中称为 Tab 2 的位置。

我们还调整了一些内部 Python 变量名，以便更好地理解我们的代码。

### 注意

代码可读性是一种编码美德，而不是浪费时间。

我们重构后的 Python GUI 现在看起来像下面的截图。我们将第一个标签重命名为 MySQL，并创建了两个 tkinter LabelFrame 小部件。我们将顶部的一个标记为 Python 数据库，它包含两个标签和六个 tkinter 输入小部件加上三个按钮，我们使用 tkinter 网格布局管理器将它们排列在四行三列中。

我们将书名和页数输入到输入小部件中，点击按钮将导致插入、检索或修改书籍引用。

底部的 LabelFrame 有一个**图书引用**的标签，这个框架中的 ScrolledText 小部件将显示我们的书籍和引用。

![操作步骤…](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_07_06.jpg)

我们将创建两个 SQL 表来保存我们的数据。第一个将保存书名和书页的数据。然后我们将与第二个表连接，第二个表将保存书籍引用。

我们将通过主键到外键关系将这两个表连接在一起。

所以，现在让我们创建第一个数据库表。

在这之前，让我们先验证一下我们的数据库确实没有表。根据在线 MySQL 文档，查看数据库中存在的表的命令如下。

### 注意

13.7.5.38 `SHOW` `TABLES` 语法：

```py
SHOW [FULL] TABLES [{FROM | IN} db_name]
    [LIKE 'pattern' | WHERE expr]
```

需要注意的是，在上述语法中，方括号中的参数（如`FULL`）是可选的，而花括号中的参数（如`FROM`）是`SHOW TABLES`命令描述中所需的。在`FROM`和`IN`之间的管道符号表示 MySQL 语法要求其中一个。

```py
# unpack dictionary credentials 
conn = mysql.connect(**guiConf.dbConfig)
# create cursor 
cursor = conn.cursor()
# execute command
cursor.execute("SHOW TABLES FROM guidb")
print(cursor.fetchall())

# close connection to MySQL
conn.close()
```

当我们在 Python 中执行 SQL 命令时，我们得到了预期的结果，即一个空列表，显示我们的数据库当前没有表。

![操作步骤…](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_07_07.jpg)

我们还可以通过执行`USE <DB>`命令首先选择数据库。现在，我们不必将其传递给`SHOW TABLES`命令，因为我们已经选择了要交谈的数据库。

以下代码创建了与之前相同的真实结果：

```py
cursor.execute("USE guidb")
cursor.execute("SHOW TABLES")
```

现在我们知道如何验证我们的数据库中是否有表，让我们创建一些表。创建了两个表之后，我们将使用与之前相同的命令验证它们是否真的进入了我们的数据库。

我们通过执行以下代码创建了第一个名为`Books`的表。

```py
# connect by unpacking dictionary credentials
conn = mysql.connect(**guiConf.dbConfig)

# create cursor 
cursor = conn.cursor()

# select DB
cursor.execute("USE guidb")

# create Table inside DB
cursor.execute("CREATE TABLE Books (       \
      Book_ID INT NOT NULL AUTO_INCREMENT, \
      Book_Title VARCHAR(25) NOT NULL,     \
      Book_Page INT NOT NULL,              \
      PRIMARY KEY (Book_ID)                \
    ) ENGINE=InnoDB")

# close connection to MySQL
conn.close()
```

我们可以通过执行以下命令验证表是否在我们的数据库中创建了。

![操作步骤…](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_07_08.jpg)

现在的结果不再是一个空列表，而是一个包含元组的列表，显示了我们刚刚创建的`books`表。

我们可以使用 MySQL 命令行客户端查看表中的列。为了做到这一点，我们必须以 root 用户身份登录。我们还必须在命令的末尾添加一个分号。

### 注意

在 Windows 上，您只需双击 MySQL 命令行客户端的快捷方式，这个快捷方式会在 MySQL 安装过程中自动安装。

如果您的桌面上没有快捷方式，您可以在典型默认安装的以下路径找到可执行文件：

`C:\Program Files\MySQL\MySQL Server 5.6\bin\mysql.exe`

如果没有运行 MySQL 客户端的快捷方式，您必须传递一些参数：

+   `C:\Program Files\MySQL\MySQL Server 5.6\bin\mysql.exe`

+   `--defaults-file=C:\ProgramData\MySQL\MySQL Server 5.6\my.ini`

+   `-uroot`

+   `-p`

双击快捷方式，或使用完整路径到可执行文件的命令行并传递所需的参数，将打开 MySQL 命令行客户端，提示您输入 root 用户的密码。

如果您记得在安装过程中为 root 用户分配的密码，那么可以运行`SHOW COLUMNS FROM books;`命令，如下所示。这将显示我们的`books`表的列从我们的 guidb。

### 注意

在 MySQL 客户端执行命令时，语法不是 Pythonic 的。

![如何做…](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_07_09.jpg)

接下来，我们将创建第二个表，用于存储书籍和期刊引用。我们将通过执行以下代码来创建它：

```py
# select DB
cursor.execute("USE guidb")

# create second Table inside DB
cursor.execute("CREATE TABLE Quotations ( \
        Quote_ID INT,                     \
        Quotation VARCHAR(250),           \
        Books_Book_ID INT,                \
        FOREIGN KEY (Books_Book_ID)       \
            REFERENCES Books(Book_ID)     \
            ON DELETE CASCADE             \
    ) ENGINE=InnoDB")
```

执行`SHOW TABLES`命令现在显示我们的数据库有两个表。

![如何做…](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_07_10.jpg)

我们可以通过使用 Python 执行 SQL 命令来查看列。

![如何做…](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_07_11.jpg)

使用 MySQL 客户端可能以更好的格式显示数据。我们还可以使用 Python 的漂亮打印（`pprint`）功能。

![如何做…](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_07_12.jpg)

MySQL 客户端仍然以更清晰的格式显示我们的列，当您运行此客户端时可以看到。

## 工作原理

我们设计了 Python GUI 数据库，并重构了我们的 GUI，以准备使用我们的新数据库。然后我们创建了一个 MySQL 数据库，并在其中创建了两个表。

我们通过 Python 和随 MySQL 服务器一起提供的 MySQL 客户端验证了表是否成功进入我们的数据库。

在下一个步骤中，我们将向我们的表中插入数据。

# 使用 SQL INSERT 命令

本步骤介绍了整个 Python 代码，向您展示如何创建和删除 MySQL 数据库和表，以及如何显示我们的 MySQL 实例中现有数据库、表、列和数据。

在创建数据库和表之后，我们将向本步骤中创建的两个表中插入数据。

### 注意

我们正在使用主键到外键的关系来连接两个表的数据。

我们将在接下来的两个步骤中详细介绍这是如何工作的，我们将修改和删除我们的 MySQL 数据库中的数据。

## 准备工作

本步骤基于我们在上一个步骤中创建的 MySQL 数据库，并向您展示如何删除和重新创建 GuiDB。

### 注意

删除数据库当然会删除数据库中表中的所有数据，因此我们还将向您展示如何重新插入这些数据。

## 如何做…

我们的`MySQL.py`模块的整个代码都在本章的代码文件夹中，可以从 Packt Publishing 的网站上下载。它创建数据库，向其中添加表，然后将数据插入我们创建的两个表中。

在这里，我们将概述代码，而不显示所有实现细节，以节省空间，因为显示整个代码需要太多页面。

```py
import mysql.connector as mysql
import GuiDBConfig as guiConf

class MySQL():
    # class variable
    GUIDB  = 'GuiDB'   

    #------------------------------------------------------
    def connect(self):
        # connect by unpacking dictionary credentials
        conn = mysql.connector.connect(**guiConf.dbConfig)

        # create cursor 
        cursor = conn.cursor()    

        return conn, cursor

    #------------------------------------------------------
    def close(self, cursor, conn):
        # close cursor

    #------------------------------------------------------
    def showDBs(self):
        # connect to MySQL

    #------------------------------------------------------
    def createGuiDB(self):
        # connect to MySQL

    #------------------------------------------------------
    def dropGuiDB(self):
        # connect to MySQL

    #------------------------------------------------------
    def useGuiDB(self, cursor):
        '''Expects open connection.'''
        # select DB

    #------------------------------------------------------
    def createTables(self):
        # connect to MySQL

        # create Table inside DB

    #------------------------------------------------------
    def dropTables(self):
        # connect to MySQL

    #------------------------------------------------------
    def showTables(self):
        # connect to MySQL

    #------------------------------------------------------
    def insertBooks(self, title, page, bookQuote):
        # connect to MySQL

        # insert data

    #------------------------------------------------------
    def insertBooksExample(self):
        # connect to MySQL

        # insert hard-coded data

    #------------------------------------------------------
    def showBooks(self):
        # connect to MySQL

    #------------------------------------------------------
    def showColumns(self):
        # connect to MySQL

    #------------------------------------------------------
    def showData(self):
        # connect to MySQL

#------------------------------------------------------
if __name__ == '__main__': 

    # Create class instance
    mySQL = MySQL()
```

运行上述代码会在我们创建的数据库中创建以下表和数据。

![如何做…](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_07_13.jpg)

## 工作原理

我们已经创建了一个 MySQL 数据库，建立了与之的连接，然后创建了两个表，用于存储喜爱的书籍或期刊引用的数据。

我们在两个表之间分配数据，因为引用往往相当大，而书名和书页码非常短。通过这样做，我们可以提高数据库的效率。

### 注意

在 SQL 数据库语言中，将数据分隔到单独的表中称为规范化。

# 使用 SQL UPDATE 命令

这个配方将使用前一个配方中的代码，对其进行更详细的解释，然后扩展代码以更新我们的数据。

为了更新我们之前插入到 MySQL 数据库表中的数据，我们使用 SQL `UPDATE`命令。

## 准备工作

这个配方是基于前一个配方的，所以请阅读和研究前一个配方，以便理解本配方中修改现有数据的编码。

## 如何做…

首先，我们将通过运行以下 Python 到 MySQL 命令来显示要修改的数据：

```py
import mysql.connector as mysql
import GuiDBConfig as guiConf

class MySQL():
    # class variable
    GUIDB  = 'GuiDB'
    #------------------------------------------------------
    def showData(self):
        # connect to MySQL
        conn, cursor = self.connect()   

        self.useGuiDB(cursor)      

        # execute command
        cursor.execute("SELECT * FROM books")
        print(cursor.fetchall())

        cursor.execute("SELECT * FROM quotations")
        print(cursor.fetchall())

        # close cursor and connection
        self.close(cursor, conn)
#==========================================================
if __name__ == '__main__': 
    # Create class instance
    mySQL = MySQL()
    mySQL.showData()
```

运行代码会产生以下结果：

![如何做…](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_07_14.jpg)

也许我们不同意“四人帮”的观点，所以让我们修改他们著名的编程引语。

### 注意

四人帮是创作了世界著名书籍《设计模式》的四位作者，这本书对整个软件行业产生了深远影响，使我们认识到、思考并使用软件设计模式进行编码。

我们将通过更新我们最喜爱的引语数据库来实现这一点。

首先，我们通过搜索书名来检索主键值，然后将该值传递到我们对引语的搜索中。

```py
    #------------------------------------------------------
    def updateGOF(self):
        # connect to MySQL
        conn, cursor = self.connect()   

        self.useGuiDB(cursor)      

        # execute command
        cursor.execute("SELECT Book_ID FROM books WHERE Book_Title = 'Design Patterns'")
        primKey = cursor.fetchall()[0][0]
        print(primKey)

        cursor.execute("SELECT * FROM quotations WHERE Books_Book_ID = (%s)", (primKey,))
        print(cursor.fetchall())

        # close cursor and connection
        self.close(cursor, conn) 
#==========================================================
if __name__ == '__main__': 
    # Create class instance
    mySQL = MySQL()
    mySQL.updateGOF()
```

这给我们带来了以下结果：

![如何做…](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_07_15.jpg)

现在我们知道了引语的主键，我们可以通过执行以下命令来更新引语。

```py
    #------------------------------------------------------
    def updateGOF(self):
        # connect to MySQL
        conn, cursor = self.connect()   

        self.useGuiDB(cursor)      

        # execute command
        cursor.execute("SELECT Book_ID FROM books WHERE Book_Title = 'Design Patterns'")
        primKey = cursor.fetchall()[0][0]
        print(primKey)

        cursor.execute("SELECT * FROM quotations WHERE Books_Book_ID = (%s)", (primKey,))
        print(cursor.fetchall())

        cursor.execute("UPDATE quotations SET Quotation = (%s) WHERE Books_Book_ID = (%s)", \
                       ("Pythonic Duck Typing: If it walks like a duck and talks like a duck it probably is a duck...", primKey))

        # commit transaction
        conn.commit ()

        cursor.execute("SELECT * FROM quotations WHERE Books_Book_ID = (%s)", (primKey,))
        print(cursor.fetchall())

        # close cursor and connection
        self.close(cursor, conn)
#==========================================================
if __name__ == '__main__': 
    # Create class instance
    mySQL = MySQL()
    #------------------------
    mySQL.updateGOF()
    book, quote = mySQL.showData()    
    print(book, quote)
```

通过运行上述代码，我们使这个经典的编程更加 Pythonic。

如下截图所示，在运行上述代码之前，我们的`Book_ID 1`标题通过主外键关系与引语表的`Books_Book_ID`列相关联。

这是《设计模式》书中的原始引语。

然后，我们通过 SQL `UPDATE`命令更新了与该 ID 相关的引语。

ID 都没有改变，但现在与`Book_ID 1`相关联的引语已经改变，如下所示在第二个 MySQL 客户端窗口中。

![如何做…](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_07_16.jpg)

## 工作原理…

在这个配方中，我们从数据库和之前配方中创建的数据库表中检索现有数据。我们向表中插入数据，并使用 SQL `UPDATE`命令更新我们的数据。

# 使用 SQL DELETE 命令

在这个配方中，我们将使用 SQL `DELETE`命令来删除我们在前面配方中创建的数据。

虽然删除数据乍一看似乎很简单，但一旦我们在生产中拥有一个相当大的数据库设计，事情可能就不那么容易了。

因为我们通过主外键关系设计了 GUI 数据库，当我们删除某些数据时，不会出现孤立记录，因为这种数据库设计会处理级联删除。

## 准备工作

这个配方使用了 MySQL 数据库、表以及本章前面配方中插入到这些表中的数据。为了展示如何创建孤立记录，我们将不得不改变其中一个数据库表的设计。

## 如何做…

我们通过只使用两个数据库表来保持我们的数据库设计简单。

虽然在删除数据时这样做是有效的，但总会有可能出现孤立记录。这意味着我们在一个表中删除数据，但在另一个 SQL 表中却没有删除相关数据。

如果我们创建`quotations`表时没有与`books`表建立外键关系，就可能出现孤立记录。

```py
        # create second Table inside DB -- 
        # No FOREIGN KEY relation to Books Table
        cursor.execute("CREATE TABLE Quotations ( \
                Quote_ID INT AUTO_INCREMENT,      \
                Quotation VARCHAR(250),           \
                Books_Book_ID INT,                \
                PRIMARY KEY (Quote_ID)            \
            ) ENGINE=InnoDB")  
```

在向`books`和`quotations`表中插入数据后，如果我们执行与之前相同的`delete`语句，我们只会删除`Book_ID 1`的书籍，而与之相关的引语`Books_Book_ID 1`则会被留下。

这是一个孤立的记录。不再存在`Book_ID`为`1`的书籍记录。

![如何做…](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_07_17.jpg)

这种情况可能会造成混乱，我们可以通过使用级联删除来避免这种情况。

我们在创建表时通过添加某些数据库约束来实现这一点。在之前的示例中，当我们创建包含引用的表时，我们使用外键约束创建了我们的“引用”表，明确引用了书籍表的主键，将两者联系起来。

```py
        # create second Table inside DB
        cursor.execute("CREATE TABLE Quotations ( \
                Quote_ID INT AUTO_INCREMENT,      \
                Quotation VARCHAR(250),           \
                Books_Book_ID INT,                \
                PRIMARY KEY (Quote_ID),           \
                FOREIGN KEY (Books_Book_ID)       \
                    REFERENCES Books(Book_ID)     \
                    ON DELETE CASCADE             \
            ) ENGINE=InnoDB")  
```

“外键”关系包括`ON DELETE CASCADE`属性，这基本上告诉我们的 MySQL 服务器，在删除与这些外键相关的记录时，删除这个表中的相关记录。

### 注意

在创建表时，如果不指定`ON DELETE CASCADE`属性，我们既不能删除也不能更新我们的数据，因为`UPDATE`是`DELETE`后跟`INSERT`。

由于这种设计，不会留下孤立的记录，这正是我们想要的。

### 注意

在 MySQL 中，我们必须指定`ENGINE=InnoDB`才能使用外键。

让我们显示我们数据库中的数据。

```py
#==========================================================
if __name__ == '__main__': 
    # Create class instance
    mySQL = MySQL()
      mySQL.showData()
```

这显示了我们数据库表中的以下数据：

![操作方法…](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_07_18.jpg)

这显示了我们有两条通过主键到外键关系相关的记录。

当我们现在删除“书籍”表中的记录时，我们期望“引用”表中的相关记录也将通过级联删除被删除。

让我们尝试通过在 Python 中执行以下 SQL 命令来执行此操作：

```py
import mysql.connector as mysql
import GuiDBConfig as guiConf

class MySQL():
    #------------------------------------------------------
    def deleteRecord(self):
        # connect to MySQL
        conn, cursor = self.connect()   

        self.useGuiDB(cursor)      

        # execute command
        cursor.execute("SELECT Book_ID FROM books WHERE Book_Title = 'Design Patterns'")
        primKey = cursor.fetchall()[0][0]
        # print(primKey)

        cursor.execute("DELETE FROM books WHERE Book_ID = (%s)", (primKey,))

        # commit transaction
        conn.commit ()

        # close cursor and connection
        self.close(cursor, conn)    
#==========================================================
if __name__ == '__main__': 
    # Create class instance
    mySQL = MySQL()
    #------------------------
    mySQL.deleteRecord()
    mySQL.showData()   
```

在执行前面的删除记录命令后，我们得到了以下新结果：

![操作方法…](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_07_19.jpg)

### 注意

著名的“设计模式”已经从我们喜爱的引用数据库中消失了…

## 工作原理…

通过通过主键到外键关系进行级联删除，通过设计我们的数据库，我们在这个示例中触发了级联删除。

这可以保持我们的数据完整和完整。

### 注意

在这个示例和示例代码中，我们有时引用相同的表名，有时以大写字母开头，有时全部使用小写字母。

这适用于 MySQL 的 Windows 默认安装，但在 Linux 上可能不起作用，除非我们更改设置。

这是官方 MySQL 文档的链接：[`dev.mysql.com/doc/refman/5.0/en/identifier-case-sensitivity.html`](http://dev.mysql.com/doc/refman/5.0/en/identifier-case-sensitivity.html)

在下一个示例中，我们将使用我们的 Python GUI 中的`MySQL.py`模块的代码。

# 从我们的 MySQL 数据库中存储和检索数据

我们将使用我们的 Python GUI 将数据插入到我们的 MySQL 数据库表中。我们已经重构了之前示例中构建的 GUI，以便连接和使用数据库。

我们将使用两个文本框输入小部件，可以在其中输入书名或期刊标题和页码。我们还将使用一个 ScrolledText 小部件来输入我们喜爱的书籍引用，然后将其存储在我们的 MySQL 数据库中。

## 准备工作

这个示例将建立在我们之前创建的 MySQL 数据库和表的基础上。

## 操作方法…

我们将使用我们的 Python GUI 来插入、检索和修改我们喜爱的引用。我们已经重构了我们 GUI 中的 MySQL 选项卡，为此做好了准备。

![操作方法…](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_07_20.jpg)

为了让按钮起作用，我们将把它们连接到回调函数，就像我们在之前的示例中所做的那样。

我们将在按钮下方的 ScrolledText 小部件中显示数据。

为了做到这一点，我们将像之前一样导入`MySQL.py`模块。所有与我们的 MySQL 服务器实例和数据库通信的代码都驻留在这个模块中，这是一种封装代码的形式，符合面向对象编程的精神。

我们将“插入引用”按钮连接到以下回调函数。

```py
        # Adding a Button
        self.action = ttk.Button(self.mySQL, text="Insert Quote", command=self.insertQuote)   
        self.action.grid(column=2, row=1)
    # Button callback
    def insertQuote(self):
        title = self.bookTitle.get()
        page = self.pageNumber.get()
        quote = self.quote.get(1.0, tk.END)
        print(title)
        print(quote)
        self.mySQL.insertBooks(title, page, quote)  
```

当我们现在运行我们的代码时，我们可以从我们的 Python GUI 中将数据插入到我们的 MySQL 数据库中。

![操作方法…](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_07_21.jpg)

输入书名和书页以及书籍或电影中的引用后，通过单击“插入引用”按钮将数据插入到我们的数据库中。

我们当前的设计允许标题、页面和引语。我们还可以插入我们最喜欢的电影引语。虽然电影没有页面，但我们可以使用页面列来插入引语在电影中发生的大致时间。

接下来，我们可以通过发出与之前使用的相同命令来验证所有这些数据是否已经进入了我们的数据库表。

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_07_22.jpg)

在插入数据之后，我们可以通过单击**获取引语**按钮来验证它是否已经进入了我们的两个 MySQL 表中，然后显示我们插入到两个 MySQL 数据库表中的数据，如上所示。

单击**获取引语**按钮会调用与按钮单击事件关联的回调方法。这给了我们在我们的 ScrolledText 小部件中显示的数据。

```py
# Adding a Button
        self.action1 = ttk.Button(self.mySQL, text="Get Quotes", command=self.getQuote)   
        self.action1.grid(column=2, row=2)
    # Button callback
    def getQuote(self):
        allBooks = self.mySQL.showBooks()  
        print(allBooks)
        self.quote.insert(tk.INSERT, allBooks)
```

我们使用`self.mySQL`类实例变量来调用`showBooks()`方法，这是我们导入的 MySQL 类的一部分。

```py
from B04829_Ch07_MySQL import MySQL
class OOP():
    def __init__(self):
        # create MySQL instance
        self.mySQL = MySQL()

class MySQL():
    #------------------------------------------------------
    def showBooks(self):
        # connect to MySQL
        conn, cursor = self.connect()    

        self.useGuiDB(cursor)    

        # print results
        cursor.execute("SELECT * FROM Books")
        allBooks = cursor.fetchall()
        print(allBooks)

        # close cursor and connection
        self.close(cursor, conn)   

        return allBooks  
```

## 它是如何工作的...

在这个示例中，我们导入了包含所有连接到我们的 MySQL 数据库并知道如何插入、更新、删除和显示数据的编码逻辑的 Python 模块。

我们现在已经将我们的 Python GUI 连接到了这个 SQL 逻辑。
