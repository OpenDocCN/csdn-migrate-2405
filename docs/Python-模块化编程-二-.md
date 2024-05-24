# Python 模块化编程（二）

> 原文：[`zh.annas-archive.org/md5/253F5AD072786A617BB26982B7C4733F`](https://zh.annas-archive.org/md5/253F5AD072786A617BB26982B7C4733F)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：使用模块进行现实世界编程

在本章中，我们将使用模块化编程技术来实现一个有用的现实世界系统。特别是，我们将：

+   设计和实现一个用于生成图表的 Python 包

+   看看不断变化的需求如何成为成功系统的崩溃

+   发现模块化编程技术如何帮助您以最佳方式处理不断变化的需求

+   了解不断变化的需求可能是好事，因为它们给您重新思考程序的机会，从而产生更健壮和设计良好的代码

让我们首先看一下我们将要实现的 Python 图表生成包，我们将其称为**Charter**。

# 介绍 Charter

Charter 将是一个用于生成图表的 Python 库。开发人员将能够使用 Charter 将原始数字转换为漂亮的折线图和条形图，然后将其保存为图像文件。以下是 Charter 库将能够生成的图表类型的示例：

![介绍 Charter](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mdl-prog-py/img/B05012_4_01.jpg)

Charter 库将支持折线图和条形图。虽然我们将通过仅支持两种类型的图表来保持 Charter 相对简单，但该包将被设计为您可以轻松添加更多的图表类型和其他图表选项。

# 设计 Charter

当您查看前一节中显示的图表时，您可以识别出所有类型的图表中使用的一些标准元素。这些元素包括标题、*x*轴和*y*轴，以及一个或多个数据系列：

![设计 Charter](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mdl-prog-py/img/B05012_4_02.jpg)

要使用 Charter 包，程序员将创建一个新图表并设置标题、*x*轴和*y*轴，以及要显示的数据系列。然后程序员将要求 Charter 生成图表，并将结果保存为磁盘上的图像文件。通过以这种方式组合和配置各种元素，程序员可以创建任何他们希望生成的图表。

### 注

更复杂的图表库将允许添加其他元素，例如右侧的*y*轴、轴标签、图例和多个重叠的数据系列。但是，对于 Charter，我们希望保持代码简单，因此我们将忽略这些更复杂的元素。

让我们更仔细地看看程序员如何与 Charter 库进行交互，然后开始思考如何实现它。

我们希望程序员能够通过导入`charter`包并调用各种函数来与 Charter 进行交互。例如：

```py
import charter
chart = charter.new_chart()
```

要为图表设置标题，程序员将调用`set_title()`函数：

```py
charter.set_title(chart, "Wild Parrot Deaths per Year")
```

### 提示

请注意，我们的 Charter 库不使用面向对象的编程技术。使用面向对象的技术，图表标题将使用类似`chart.set_title("每年野生鹦鹉死亡数量")`的语句进行设置。但是，面向对象的技术超出了本书的范围，因此我们将为 Charter 库使用更简单的过程式编程风格。

要为图表设置*x*和*y*轴，程序员必须提供足够的信息，以便 Charter 可以生成图表并显示这些轴。为了了解这可能是如何工作的，让我们想一想轴是什么样子。

对于某些图表，轴可能代表一系列数值：

![设计 Charter](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mdl-prog-py/img/B05012_4_03.jpg)

在这种情况下，通过计算数据点沿轴的位置来显示数据点。例如，具有*x = 35*的数据点将显示在该轴上**30**和**40**点之间的中间位置。

我们将把这种类型的轴称为**连续轴**。请注意，对于这种类型的轴，标签位于刻度线下方。将其与以下轴进行比较，该轴被分成多个离散的“桶”：

![设计 Charter](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mdl-prog-py/img/B05012_4_04.jpg)

在这种情况下，每个数据点对应一个单独的桶，标签将出现在刻度标记之间的空间中。这种类型的轴将被称为**离散轴**。

注意，对于连续轴，标签显示在刻度标记上，而对于离散轴，标签显示在刻度标记之间。此外，离散轴的值可以是任何值（在本例中是月份名称），而连续轴的值必须是数字。

对于 Charter 库，我们将使 *x* 轴成为离散轴，而 *y* 轴将是连续的。理论上，你可以为 *x* 和 *y* 轴使用任何类型的轴，但我们保持这样做是为了使库更容易实现。

知道这一点，我们现在可以看一下在创建图表时如何定义各种轴。

为了定义 x 轴，程序员将调用 `set_x_axis()` 函数，并提供用于离散轴中每个桶的标签列表：

```py
charter.set_x_axis(chart,
                   ["2009", "2010", "2011", "2012", "2013",
                    "2014", "2015"])
```

列表中的每个条目对应轴中的一个桶。

对于 *y* 轴，我们需要定义将显示的值的范围以及这些值将如何标记。为此，我们需要向 `set_y_axis()` 函数提供最小值、最大值和标签值：

```py
charter.set_y_axis(chart, minimum=0, maximum=700,
                   labels=[0, 100, 200, 300, 400, 500, 600, 700])
```

### 注意

为了保持简单，我们将假设 *y* 轴使用线性刻度。我们可能会支持其他类型的刻度，例如实现对数轴，但我们将忽略这一点，因为这会使 Charter 库变得更加复杂。

现在我们知道了轴将如何定义，我们可以看一下数据系列将如何指定。首先，我们需要程序员告诉 Charter 要显示什么类型的数据系列：

```py
charter.set_series_type(chart, "bar")
```

正如前面提到的，我们将支持线图和条形图。

然后程序员需要指定数据系列的内容。由于我们的 *x* 轴是离散的，而 *y* 轴是连续的，我们可以将数据系列定义为一个 *y* 轴值的列表，每个离散的 *x* 轴值对应一个 *y* 轴值：

```py
charter.set_series(chart, [250, 270, 510, 420, 680, 580, 450])
```

这完成了图表的定义。一旦定义好了，程序员就可以要求 Charter 库生成图表：

```py
charter.generate_chart(chart, "chart.png")
```

将所有这些放在一起，这是一个完整的程序，可以生成本章开头显示的条形图：

```py
import charter
chart = charter.new_chart()
charter.set_title(chart, "Wild Parrot Deaths per Year")
charter.set_x_axis(chart,
                   ["2009", "2010", "2011", "2012", "2013",
                    "2014", "2015"])
charter.set_y_axis(chart, minimum=0, maximum=700,
                   labels=[0, 100, 200, 300, 400, 500, 600, 700])
charter.set_series(chart, [250, 270, 510, 420, 680, 580, 450])
charter.set_series_type(chart, "bar")
charter.generate_chart(chart, "chart.png")
```

因为 Charter 是一个供程序员使用的库，这段代码为 Charter 库的 API 提供了一个相当完整的规范。从这个示例程序中很清楚地可以看出应该发生什么。现在让我们看看如何实现这一点。

# 实施图表

我们知道 Charter 库的公共接口将由许多在包级别访问的函数组成，例如 `charter.new_chart()`。然而，使用上一章介绍的技术，我们知道我们不必在包初始化文件中定义库的 API，以使这些函数在包级别可用。相反，我们可以在其他地方定义这些函数，并将它们导入到 `__init__.py` 文件中，以便其他人可以使用它们。

让我们从创建一个目录开始，用来保存我们的 `charter` 包。创建一个名为 `charter` 的新目录，在其中创建一个空的包初始化文件 `__init__.py`。这为我们提供了编写库的基本框架：

![实施图表](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mdl-prog-py/img/B05012_4_05.jpg)

根据我们的设计，我们知道生成图表的过程将涉及以下三个步骤：

1.  通过调用 `new_chart()` 函数创建一个新的图表。

1.  通过调用各种 `set_XXX()` 函数来定义图表的内容和外观。

1.  通过调用 `generate_chart()` 函数生成图表并将其保存为图像文件。

为了保持我们的代码组织良好，我们将分开生成图表的过程和创建和定义图表的过程。为此，我们将有一个名为`chart`的模块，负责图表的创建和定义，以及一个名为`generator`的单独模块，负责图表的生成。

继续创建这两个新的空模块，将它们放在`charter`包中：

![实现 Charter](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mdl-prog-py/img/B05012_4_06.jpg)

现在我们已经为我们的包建立了一个整体结构，让我们为我们知道我们将不得不实现的各种函数创建一些占位符。编辑`chart.py`模块，并在该文件中输入以下内容：

```py
def new_chart():
    pass

def set_title(chart, title):
    pass

def set_x_axis(chart, x_axis):
    pass

def set_y_axis(chart, minimum, maximum, labels):
    pass

def set_series_type(chart, series_type):
    pass

def set_series(chart, series):
    pass
```

同样，编辑`generator.py`模块，并在其中输入以下内容：

```py
def generate_chart(chart, filename):
    pass
```

这些是我们知道我们需要为 Charter 库实现的所有函数。但是，它们还没有放在正确的位置上——我们希望用户能够调用`charter.new_chart()`，而不是`charter.chart.new_chart()`。为了解决这个问题，编辑`__init__.py`文件，并在该文件中输入以下内容：

```py
from .chart     import *
from .generator import *
```

正如你所看到的，我们正在使用相对导入将所有这些模块中的函数加载到主`charter`包的命名空间中。

我们的 Charter 库开始成形了！现在让我们依次处理这两个模块。

## 实现 chart.py 模块

由于我们在 Charter 库的实现中避免使用面向对象的编程技术，我们不能使用对象来存储有关图表的信息。相反，`new_chart()`函数将返回一个图表值，各种`set_XXX()`函数将获取该图表并向其添加信息。

存储图表信息的最简单方法是使用 Python 字典。这使得我们的`new_chart()`函数的实现非常简单；编辑`chart.py`模块，并用以下内容替换`new_chart()`的占位符：

```py
def new_chart():
    return {}
```

一旦我们有一个将保存图表数据的字典，就很容易将我们想要的各种值存储到这个字典中。例如，编辑`set_title()`函数的定义，使其如下所示：

```py
def set_title(chart, title):
    chart['title'] = title
```

以类似的方式，我们可以实现`set_XXX()`函数的其余部分：

```py
def set_x_axis(chart, x_axis):
    chart['x_axis'] = x_axis

def set_y_axis(chart, minimum, maximum, labels):
    chart['y_min']    = minimum
    chart['y_max']    = maximum
    chart['y_labels'] = labels

def set_series_type(chart, series_type):
    chart['series_type'] = series_type

def set_series(chart, series):
    chart['series'] = series
```

这完成了我们的`chart.py`模块的实现。

## 实现 generator.py 模块

不幸的是，实现`generate_chart()`函数将更加困难，这就是为什么我们将这个函数移到了一个单独的模块中。生成图表的过程将涉及以下步骤：

1.  创建一个空图像来保存生成的图表。

1.  绘制图表的标题。

1.  绘制*x*轴。

1.  绘制*y*轴。

1.  绘制数据系列。

1.  将生成的图像文件保存到磁盘上。

因为生成图表的过程需要我们使用图像，所以我们需要找到一个允许我们生成图像文件的库。现在让我们来获取一个。

### Pillow 库

**Python Imaging Library**（**PIL**）是一个古老的用于生成图像的库。不幸的是，PIL 不再得到积极的开发。然而，有一个名为**Pillow**的更新版本的 PIL，它继续得到支持，并允许我们创建和保存图像文件。

Pillow 库的主要网站可以在[`python-pillow.org/`](http://python-pillow.org/)找到，文档可以在[`pillow.readthedocs.org/`](http://pillow.readthedocs.org/)找到。

让我们继续安装 Pillow。最简单的方法是使用`pip install pillow`，尽管安装指南([`pillow.readthedocs.org/en/3.0.x/installation.html`](http://pillow.readthedocs.org/en/3.0.x/installation.html))为您提供了各种选项，如果这种方法对您不起作用。

通过查看 Pillow 文档，我们发现可以使用以下代码创建一个空图像：

```py
from PIL import Image
image = Image.new("RGB", (CHART_WIDTH, CHART_HEIGHT), "#7f00ff")
```

这将创建一个新的 RGB（红色，绿色，蓝色）图像，宽度和高度由给定的颜色填充。

### 注意

`#7f00ff`是紫色的十六进制颜色代码。每对十六进制数字代表一个颜色值：`7f`代表红色，`00`代表绿色，`ff`代表蓝色。

为了绘制这个图像，我们将使用`ImageDraw`模块。例如：

```py
from PIL import ImageDraw
drawer = ImageDraw.Draw(image)
drawer.line(50, 50, 150, 200, fill="#ff8010", width=2)
```

图表绘制完成后，我们可以以以下方式将图像保存到磁盘上：

```py
image.save("image.png", format="png")
```

这个对 Pillow 库的简要介绍告诉我们如何实现我们之前描述的图表生成过程的第 1 步和第 6 步。它还告诉我们，对于第 2 到第 5 步，我们将使用`ImageDraw`模块来绘制各种图表元素。

### 渲染器

当我们绘制图表时，我们希望能够选择要绘制的元素。例如，我们可能根据用户想要显示的数据系列的类型在`"bar"`和`"line"`元素之间进行选择。一个非常简单的方法是将我们的绘图代码结构化如下：

```py
if chart['series_type'] == "bar":
    ...draw the data series using bars
elif chart['series_type'] == "line":
    ...draw the data series using lines
```

然而，这并不是很灵活，如果绘图逻辑变得复杂，或者我们向库中添加更多的图表选项，代码将很快变得难以阅读。为了使 Charter 库更加模块化，并支持今后的增强，我们将使用渲染器模块来实际进行绘制。

在计算机图形学中，**渲染器**是程序的一部分，用于绘制某些东西。其思想是你可以选择适当的渲染器，并要求它绘制你想要的元素，而不必担心该元素将如何被绘制的细节。

使用渲染器模块，我们的绘图逻辑看起来会像下面这样：

```py
from renderers import bar_series, line_series

if chart['series_type'] == "bar":
    bar_series.draw(chart, drawer)
elif chart['series_type'] == "line":
    line_series.draw(chart, drawer)
```

这意味着我们可以将每个元素的实际绘制细节留给渲染器模块本身，而不是在我们的`generate_chart()`函数中充斥着大量详细的绘制代码。

为了跟踪我们的渲染器模块，我们将创建一个名为`renderers`的子包，并将所有渲染器模块放在这个子包中。让我们现在创建这个子包。

在主`charter`目录中创建一个名为`renderers`的新目录，并在其中创建一个名为`__init__.py`的新文件，作为包初始化文件。这个文件可以为空，因为我们不需要做任何特殊的初始化来初始化这个子包。

我们将需要五个不同的渲染器模块来完成 Charter 库的工作：

+   `title.py`

+   `x_axis.py`

+   `y_axis.py`

+   `bar_series.py`

+   `line_series.py`

继续在`charter.renderers`目录中创建这五个文件，并在每个文件中输入以下占位文本：

```py
def draw(chart, drawer):
    pass
```

这给了我们渲染器模块的整体结构。现在让我们使用这些渲染器来实现我们的`generate_chart()`函数。

编辑`generate.py`模块，并用以下内容替换`generate_chart()`函数的占位符定义：

```py
def generate_chart(chart, filename):
    image  = Image.new("RGB", (CHART_WIDTH, CHART_HEIGHT),
                       "#ffffff")
    drawer = ImageDraw.Draw(image)

    title.draw(chart, drawer)
    x_axis.draw(chart, drawer)
    y_axis.draw(chart, drawer)
    if chart['series_type'] == "bar":
        bar_series.draw(chart, drawer)
    elif chart['series_type'] == "line":
        line_series.draw(chart, drawer)

    image.save(filename, format="png")
```

正如你所看到的，我们创建了一个`Image`对象来保存我们生成的图表，使用十六进制颜色代码`#ffffff`将其初始化为白色。然后我们使用`ImageDraw`模块来定义一个`drawer`对象来绘制图表，并调用各种渲染器模块来完成所有工作。最后，我们调用`image.save()`将图像文件保存到磁盘上。

为了使这个函数工作，我们需要在我们的`generator.py`模块的顶部添加一些`import`语句：

```py
from PIL import Image, ImageDraw
from .renderers import (title, x_axis, y_axis,
                        bar_series, line_series)
```

还有一件事我们还没有处理：当我们创建图像时，我们使用了两个常量，告诉 Pillow 要创建的图像的尺寸：

```py
    image = Image.new("RGB", (**CHART_WIDTH, CHART_HEIGHT**),
                       "#ffffff")
```

我们需要在某个地方定义这两个常量。

事实证明，我们需要定义更多的常量并在整个 Charter 库中使用它们。为此，我们将创建一个特殊的模块来保存我们的各种常量。

在顶层`charter`目录中创建一个名为`constants.py`的新文件。在这个模块中，添加以下值：

```py
CHART_WIDTH  = 600
CHART_HEIGHT = 400
```

然后，在你的`generator.py`模块中添加以下`import`语句：

```py
from .constants import *
```

### 测试代码

虽然我们还没有实现任何渲染器，但我们已经有足够的代码来开始测试。为此，创建一个名为`test_charter.py`的空文件，并将其放在包含`charter`包的目录中。然后，在此文件中输入以下内容：

```py
import charter
chart = charter.new_chart()
charter.set_title(chart, "Wild Parrot Deaths per Year")
charter.set_x_axis(chart,
                   ["2009", "2010", "2011", "2012", "2013",
                    "2014", "2015"])
charter.set_y_axis(chart, minimum=0, maximum=700,
                   labels=[0, 100, 200, 300, 400, 500, 600, 700])
charter.set_series(chart, [250, 270, 510, 420, 680, 580, 450])
charter.set_series_type(chart, "bar")
charter.generate_chart(chart, "chart.png")
```

这只是我们之前看到的示例代码的副本。这个脚本将允许您测试 Charter 库；打开一个终端或命令行窗口，`cd`到包含`test_charter.py`文件的目录，并输入以下内容：

```py
python test_charter.py

```

一切顺利的话，程序应该在没有任何错误的情况下完成。然后，您可以查看`chart.png`文件，这应该是一个填充有白色背景的空图像文件。

### 渲染标题

接下来，我们需要实现各种渲染器模块，从图表的标题开始。编辑`renderers/title.py`文件，并用以下内容替换`draw()`函数的占位符定义：

```py
def draw(chart, drawer):
    font = ImageFont.truetype("Helvetica", 24)
    text_width,text_height = font.getsize(chart['title'])

    left = CHART_WIDTH/2 - text_width/2
    top  = TITLE_HEIGHT/2 - text_height/2

    drawer.text((left, top), chart['title'], "#4040a0", font)
```

这个渲染器首先获取一个用于绘制标题的字体。然后计算标题文本的大小（以像素为单位）和用于标签的位置，以便它在图表上居中显示。请注意，我们使用一个名为`TITLE_HEIGHT`的常量来指定用于图表标题的空间量。

该函数的最后一行使用指定的位置和字体将标题绘制到图表上。字符串`#4040a0`是用于文本的十六进制颜色代码，这是一种深蓝色。

由于这个模块使用`ImageFont`模块加载字体，以及我们的`constants.py`模块中的一些常量，我们需要在我们的模块顶部添加以下`import`语句：

```py
from PIL import ImageFont
from ..constants import *
```

请注意，我们使用`..`从父包中导入`constants`模块。

最后，我们需要将`TITLE_HEIGHT`常量添加到我们的`constants.py`模块中：

```py
TITLE_HEIGHT = 50
```

如果现在运行您的`test_charter.py`脚本，您应该会看到生成的图像中出现图表的标题：

![渲染标题](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mdl-prog-py/img/B05012_4_07.jpg)

### 渲染 x 轴

如果您记得，* x *轴是一个离散轴，标签显示在每个刻度之间。为了绘制这个，我们将不得不计算轴上每个“桶”的宽度，然后绘制表示轴和刻度线的线，以及绘制每个“桶”的标签。

首先，编辑`renderers/x_axis.py`文件，并用以下内容替换您的占位符`draw()`函数：

```py
def draw(chart, drawer):
    font = ImageFont.truetype("Helvetica", 12)
    label_height = font.getsize("Test")[1]

    avail_width = CHART_WIDTH - Y_AXIS_WIDTH - MARGIN
    bucket_width = avail_width / len(chart['x_axis'])

    axis_top = CHART_HEIGHT - X_AXIS_HEIGHT
    drawer.line([(Y_AXIS_WIDTH, axis_top),
                 (CHART_WIDTH - MARGIN, axis_top)],
                "#4040a0", 2) # Draw main axis line.

    left = Y_AXIS_WIDTH
    for bucket_num in range(len(chart['x_axis'])):
        drawer.line([(left, axis_top),
                     (left, axis_top + TICKMARK_HEIGHT)],
                    "#4040a0", 1) # Draw tickmark.

        label_width = font.getsize(chart['x_axis'][bucket_num])[0]
        label_left = max(left,
                         left + bucket_width/2 - label_width/2)
        label_top  = axis_top + TICKMARK_HEIGHT + 4

        drawer.text((label_left, label_top),
                    chart['x_axis'][bucket_num], "#000000", font)

        left = left + bucket_width

    drawer.line([(left, axis_top),
                 (left, axis_top + TICKMARK_HEIGHT)],
                "#4040a0", 1) # Draw final tickmark.
```

您还需要在模块顶部添加以下`import`语句：

```py
from PIL import ImageFont
from ..constants import *
```

最后，您应该将以下定义添加到您的`constants.py`模块中：

```py
X_AXIS_HEIGHT   = 50
Y_AXIS_WIDTH    = 50
MARGIN          = 20
TICKMARK_HEIGHT = 8
```

这些定义了图表中固定元素的大小。

如果现在运行您的`test_charter.py`脚本，您应该会看到* x *轴显示在图表底部：

![渲染 x 轴](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mdl-prog-py/img/B05012_4_08.jpg)

### 剩下的渲染器

正如您所看到的，生成的图像开始看起来更像图表了。由于这个包的目的是展示如何构建代码结构，而不是这些模块是如何实现的细节，让我们跳过并添加剩下的渲染器而不再讨论。

首先，编辑您的`renderers/y_axis.py`文件，使其如下所示：

```py
from PIL import ImageFont

from ..constants import *

def draw(chart, drawer):
    font = ImageFont.truetype("Helvetica", 12)
    label_height = font.getsize("Test")[1]

    axis_top    = TITLE_HEIGHT
    axis_bottom = CHART_HEIGHT - X_AXIS_HEIGHT
    axis_height = axis_bottom - axis_top

    drawer.line([(Y_AXIS_WIDTH, axis_top),
                 (Y_AXIS_WIDTH, axis_bottom)],
                "#4040a0", 2) # Draw main axis line.

    for y_value in chart['y_labels']:
        y = ((y_value - chart['y_min']) /
             (chart['y_max']-chart['y_min']))

        y_pos = axis_top + (axis_height - int(y * axis_height))

        drawer.line([(Y_AXIS_WIDTH - TICKMARK_HEIGHT, y_pos),
                     (Y_AXIS_WIDTH, y_pos)],
                    "#4040a0", 1) # Draw tickmark.

        label_width,label_height = font.getsize(str(y_value))
        label_left = Y_AXIS_WIDTH-TICKMARK_HEIGHT-label_width-4
        label_top = y_pos - label_height / 2

        drawer.text((label_left, label_top), str(y_value),
                    "#000000", font)
```

接下来，编辑`renderers/bar_series.py`，使其如下所示：

```py
from PIL import ImageFont
from ..constants import *

def draw(chart, drawer):
    avail_width  = CHART_WIDTH - Y_AXIS_WIDTH - MARGIN
    bucket_width = avail_width / len(chart['x_axis'])

    max_top      = TITLE_HEIGHT
    bottom       = CHART_HEIGHT - X_AXIS_HEIGHT
    avail_height = bottom - max_top

    left = Y_AXIS_WIDTH
    for y_value in chart['series']:

        bar_left = left + MARGIN / 2
        bar_right = left + bucket_width - MARGIN / 2

        y = ((y_value - chart['y_min']) /
             (chart['y_max'] - chart['y_min']))

        bar_top = max_top + (avail_height - int(y * avail_height))

        drawer.rectangle([(bar_left, bar_top),
                          (bar_right + 1,
                           bottom)],
                         fill="#e8e8f4", outline="#4040a0")

        left = left + bucket_width
```

最后，编辑`renderers.line_series.py`，使其如下所示：

```py
from PIL import ImageFont
from ..constants import *

def draw(chart, drawer):
    avail_width  = CHART_WIDTH - Y_AXIS_WIDTH - MARGIN
    bucket_width = avail_width / len(chart['x_axis'])

    max_top      = TITLE_HEIGHT
    bottom       = CHART_HEIGHT - X_AXIS_HEIGHT
    avail_height = bottom - max_top

    left   = Y_AXIS_WIDTH
    prev_y = None
    for y_value in chart['series']:
        y = ((y_value - chart['y_min']) /
             (chart['y_max'] - chart['y_min']))

        cur_y = max_top + (avail_height - int(y * avail_height))

        if prev_y != None:
            drawer.line([(left - bucket_width / 2, prev_y),
                         (left + bucket_width / 2), cur_y],
                        fill="#4040a0", width=1)
        prev_y = cur_y
        left = left + bucket_width
```

这完成了我们对 Charter 库的实现。

### 测试 Charter

如果运行`test_charter.py`脚本，您应该会看到一个完整的条形图：

![测试 Charter](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mdl-prog-py/img/B05012_4_09.jpg)

显然，我们可以在 Charter 库中做更多的事情，但即使在当前状态下，它也运行良好。如果您愿意，您可以使用它为各种数据生成线条和条形图。对于我们的目的，我们可以声明 Charter 库已经完成，并开始将其作为我们生产系统的一部分使用。

# 变化的需求中的一块砂糖

当然，没有什么是真正完成的。假设你写了图书馆并且已经忙着扩展它好几个月，添加了更多的数据系列类型和大量的选项。该库正在公司的几个重大项目中使用，输出效果很棒，每个人似乎都对此很满意——直到有一天你的老板走进来说：“太模糊了。你能把模糊去掉吗？”

你问他是什么意思，他说他一直在一台高分辨率激光打印机上打印图表。结果对他来说还不够好，不能用在公司的报告中。他拿出一份打印件指着标题。仔细看，你明白了他的意思：

![瓶中之蝇——需求变更](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mdl-prog-py/img/B05012_4_10.jpg)

果然，文本是像素化的，即使线条在高分辨率打印时看起来也有点锯齿状。你尝试增加生成图表的大小，但仍然不够好——当你尝试将大小增加到公司高分辨率激光打印机的每英寸 1200 点时，你的程序崩溃了。

“但这个程序从来没有为此设计过，”你抱怨道。“我们编写它是为了在屏幕上显示图表。”

“我不在乎，”你的老板说。“我希望你生成矢量格式的输出。那样打印效果很好，一点都不模糊。”

### 注意

以防你以前没有遇到过，存储图像数据有两种根本不同的方式：位图图像，由像素组成；矢量图像，其中保存了单独的绘图指令（例如，“写一些文字”，“画一条线”，“填充一个矩形”等），然后每次显示图像时都会遵循这些指令。位图图像会出现像素化或“模糊”，而矢量图像即使放大或以高分辨率打印时看起来也很棒。

你进行了快速的谷歌搜索，并确认 Pillow 库无法保存矢量格式的图像；它只能处理位图数据。你的老板并不同情，“只需使其以矢量格式工作，同时保存为 PDF 和 PNG，以满足那些已经在使用它的人。”

心情沉重，你想知道自己怎么可能满足这些新的要求。整个 Charter 库都是从头开始构建的，用于生成位图 PNG 图像。难道你不得不从头开始重写整个东西吗？

# 重新设计图书馆

由于图书馆现在需要将图表保存为矢量格式的 PDF 文件，我们需要找到一个替代 Python Imaging Library 的支持写入 PDF 文件的库。其中一个明显的选择是**ReportLab**。

ReportLab 是一个商业 PDF 生成器，也以开源许可发布。你可以在[`www.reportlab.com/opensource/`](http://www.reportlab.com/opensource/)找到有关 ReportLab 工具包的更多信息。安装 ReportLab 的最简单方法是使用`pip install reportlab`。如果这对你不起作用，请查看[`bitbucket.org/rptlab/reportlab`](https://bitbucket.org/rptlab/reportlab)上的安装说明以获取更多详细信息。ReportLab 工具包的文档可以在[`www.reportlab.com/docs/reportlab-userguide.pdf`](http://www.reportlab.com/docs/reportlab-userguide.pdf)找到。

在许多方面，ReportLab 的工作方式与 Python Imaging Library 相同：你初始化一个文档（在 ReportLab 中称为**画布**），调用各种方法将元素绘制到画布上，然后使用`save()`方法将 PDF 文件保存到磁盘上。

然而，还有一个额外的步骤：因为 PDF 文件格式支持多页，你需要在保存文档之前调用`showPage()`函数来呈现当前页面。虽然我们不需要 Charter 库的多个页面，但我们可以通过在绘制每个页面后调用`showPage()`，然后在完成时调用`save()`来创建多页 PDF 文档并将文件保存到磁盘。

现在我们有了一个工具，可以生成 PDF 文件，让我们看看如何重新构建 Charter 包，以支持 PNG 或 PDF 文件格式的渲染。

`generate_chart()` 函数似乎是用户应该能够选择输出格式的逻辑点。实际上，我们可以根据文件名自动检测格式——如果 `filename` 参数以 `.pdf` 结尾，那么我们应该生成 PDF 格式的图表，而如果 `filename` 以 `.png` 结尾，那么我们应该生成 PNG 格式的文件。

更一般地说，我们的渲染器存在一个问题：它们都设计为与 Python Imaging Library 一起工作，并使用 `ImageDraw` 模块将每个图表绘制为位图图像。

由于这个原因，以及每个渲染器模块内部的代码复杂性，将这些渲染器保持不变，并编写使用 ReportLab 生成 PDF 格式图表元素的新渲染器是有意义的。为此，我们需要对我们的渲染代码进行**重构**。

在我们着手进行更改之前，让我们考虑一下我们想要实现什么。我们将需要每个渲染器的两个单独版本——一个用于生成 PNG 格式的元素，另一个用于生成相同的元素的 PDF 格式：

![重新设计 Charter](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mdl-prog-py/img/B05012_4_11.jpg)

由于所有这些模块都做同样的事情——在图表上绘制一个元素，因此最好有一个单独的函数，调用适当的渲染器模块的 `draw()` 函数以在所需的输出格式中绘制给定的图表元素。这样，我们的其余代码只需要调用一个函数，而不是根据所需的元素和格式选择十个不同的 `draw()` 函数。

为此，我们将在 `renderers` 包内添加一个名为 `renderer.py` 的新模块，并将调用各个渲染器的工作留给该模块。这将极大简化我们的设计。

最后，我们的 `generate_chart()` 函数将需要创建一个 ReportLab 画布以生成 PDF 格式的图表，然后在图表生成后保存这个画布，就像它现在为位图图像所做的那样。

这意味着，虽然我们需要做一些工作来实现我们的渲染器模块的新版本，创建一个新的 `renderer.py` 模块并更新 `generate_chart()` 函数，但系统的其余部分将保持完全相同。我们不需要从头开始重写一切，而我们的其余模块——特别是现有的渲染器——根本不需要改变。哇！

# 重构代码

我们将通过将现有的 PNG 渲染器移动到名为 `renderers.png` 的新子包中来开始我们的重构。在 `renderers` 目录中创建一个名为 `png` 的新目录，并将 `title.py`、`x_axis.py`、`y_axis.py`、`bar_series.py` 和 `line_series.py` 模块移动到该目录中。然后，在 `png` 目录内创建一个空的包初始化文件 `__init__.py`，以便 Python 可以识别它为一个包。

我们将不得不对现有的 PNG 渲染器进行一个小改动：因为每个渲染器模块使用相对导入导入 `constants.py` 模块，我们需要更新这些模块，以便它们仍然可以从新位置找到 `constants` 模块。为此，依次编辑每个 PNG 渲染器模块，并找到以下类似的行：

```py
from ..constants import *
```

在这些行的末尾添加一个额外的 `.`，使它们看起来像这样：

```py
from ...constants import *
```

我们的下一个任务是创建一个包来容纳我们的 PDF 格式渲染器。在 `renderers` 目录中创建一个名为 `pdf` 的子目录，并在该目录中创建一个空的包初始化文件，使其成为 Python 包。

接下来，我们要实现前面提到的`renderer.py`模块，以便我们的`generate_chart()`函数可以专注于绘制图表元素，而不必担心每个元素定义在哪个模块中。在`renderers`目录中创建一个名为`renderer.py`的新文件，并将以下代码添加到该文件中：

```py
from .png import title       as title_png
from .png import x_axis      as x_axis_png
from .png import y_axis      as y_axis_png
from .png import bar_series  as bar_series_png
from .png import line_series as line_series_png

renderers = {
    'png' : {
        'title'       : title_png,
        'x_axis'      : x_axis_png,
        'y_axis'      : y_axis_png,
        'bar_series'  : bar_series_png,
        'line_series' : line_series_png
    },
}

def draw(format, element, chart, output):
    renderers[format][element].draw(chart, output)
```

这个模块正在做一些棘手的事情，这可能是你以前没有遇到过的：在使用`import...as`导入每个 PNG 格式的渲染器模块之后，我们将导入的模块视为 Python 变量，将每个模块的引用存储在`renderers`字典中。然后，我们的`draw()`函数使用`renderers[format][element]`从该字典中选择适当的模块，并调用该模块内部的`draw()`函数来进行实际绘制。

这个 Python 技巧为我们节省了大量的编码工作——如果没有它，我们将不得不编写一整套基于所需元素和格式调用适当模块的`if...then`语句。以这种方式使用字典可以节省我们大量的输入，并使代码更容易阅读和调试。

### 注意

我们也可以使用 Python 标准库的`importlib`模块按名称加载渲染器模块。这将使我们的`renderer`模块更短，但会使代码更难理解。使用`import...as`和字典来选择所需的模块是复杂性和可理解性之间的良好折衷。

接下来，我们需要更新我们的`generate_report()`函数。如前一节所讨论的，我们希望根据正在生成的文件的文件扩展名选择输出格式。我们还需要更新此函数以使用我们的新`renderer.draw()`函数，而不是直接导入和调用渲染器模块。

编辑`generator.py`模块，并用以下代码替换该模块的内容：

```py
from PIL import Image, ImageDraw
from reportlab.pdfgen.canvas import Canvas

from .constants import *
from .renderers import renderer

def generate_chart(chart, filename):

    # Select the output format.

    if filename.lower().endswith(".pdf"):
        format = "pdf"
    elif filename.lower().endswith(".png"):
        format = "png"
    else:
        print("Unsupported file format: " + filename)
        return

    # Prepare the output file based on the file format.

    if format == "pdf":
        output = Canvas(filename)
    elif format == "png":
        image  = Image.new("RGB", (CHART_WIDTH, CHART_HEIGHT),
                           "#ffffff")
        output = ImageDraw.Draw(image)

    # Draw the various chart elements.

    renderer.draw(format, "title",  chart, output)
    renderer.draw(format, "x_axis", chart, output)
    renderer.draw(format, "y_axis", chart, output)
    if chart['series_type'] == "bar":
        renderer.draw(format, "bar_series", chart, output)
    elif chart['series_type'] == "line":
        renderer.draw(format, "line_series", chart, output)

    # Finally, save the output to disk.

    if format == "pdf":
        output.showPage()
        output.save()
    elif format == "png":
        image.save(filename, format="png")
```

这个模块中有很多代码，但注释应该有助于解释发生了什么。正如你所看到的，我们使用提供的文件名将`format`变量设置为`"pdf"`或`"png"`。然后，我们准备`output`变量来保存生成的图像或 PDF 文件。接下来，我们依次调用`renderer.draw()`来绘制每个图表元素，传入`format`和`output`变量，以便渲染器可以完成其工作。最后，我们将输出保存到磁盘，以便将图表保存到适当的 PDF 或 PNG 格式文件中。

有了这些更改，您应该能够使用更新后的 Charter 包来生成 PNG 格式文件。PDF 文件还不能工作，因为我们还没有编写 PDF 渲染器，但 PNG 格式输出应该可以工作。继续运行`test_charter.py`脚本进行测试，以确保您没有输入任何拼写错误。

现在我们已经完成了重构现有代码，让我们添加 PDF 渲染器。

## 实现 PDF 渲染器模块

我们将逐个处理各种渲染器模块。首先，在`pdf`目录中创建`titles.py`模块，并将以下代码输入到该文件中：

```py
from ...constants import *

def draw(chart, canvas):
    text_width  = canvas.stringWidth(chart['title'],
                                     "Helvetica", 24)
    text_height = 24 * 1.2

    left   = CHART_WIDTH/2 - text_width/2
    bottom = CHART_HEIGHT - TITLE_HEIGHT/2 + text_height/2

    canvas.setFont("Helvetica", 24)
    canvas.setFillColorRGB(0.25, 0.25, 0.625)
    canvas.drawString(left, bottom, chart['title'])
```

在某些方面，这段代码与该渲染器的 PNG 版本非常相似：我们计算文本的宽度和高度，并使用这些来计算标题应该绘制的图表位置。然后，我们使用 24 点的 Helvetica 字体以深蓝色绘制标题。

然而，也有一些重要的区别：

+   我们计算文本的宽度和高度的方式不同。对于宽度，我们调用画布的`stringWidth()`函数，而对于高度，我们将文本的字体大小乘以 1.2。默认情况下，ReportLab 在文本行之间留下字体大小的 20%的间隙，因此将字体大小乘以 1.2 是计算文本行高的准确方式。

+   用于计算页面上元素位置的单位不同。ReportLab 使用 **点** 而不是像素来测量所有位置和大小。一个点大约是一英寸的 1/72。幸运的是，一个点与典型计算机屏幕上的像素大小相当接近；这使我们可以忽略不同的测量系统，使得 PDF 输出看起来仍然很好。

+   PDF 文件使用与 PNG 文件不同的坐标系统。在 PNG 格式文件中，图像的顶部 *y* 值为零，而对于 PDF 文件，*y=0* 在图像底部。这意味着我们在页面上的所有位置都必须相对于页面底部计算，而不是像 PNG 渲染器中所做的那样相对于图像顶部计算。

+   颜色是使用 RGB 颜色值指定的，其中颜色的每个分量都表示为介于零和一之间的数字。例如，颜色值 `(0.25,0.25,0.625)` 相当于十六进制颜色代码 `#4040a0`。

话不多说，让我们实现剩下的 PDF 渲染模块。`x_axis.py` 模块应该如下所示：

```py
def draw(chart, canvas):
    label_height = 12 * 1.2

    avail_width  = CHART_WIDTH - Y_AXIS_WIDTH - MARGIN
    bucket_width = avail_width / len(chart['x_axis'])

    axis_top = X_AXIS_HEIGHT
    canvas.setStrokeColorRGB(0.25, 0.25, 0.625)
    canvas.setLineWidth(2)
    canvas.line(Y_AXIS_WIDTH, axis_top,
                CHART_WIDTH - MARGIN, axis_top)

    left = Y_AXIS_WIDTH
    for bucket_num in range(len(chart['x_axis'])):
        canvas.setLineWidth(1)
        canvas.line(left, axis_top,
                    left, axis_top - TICKMARK_HEIGHT)

        label_width  = canvas.stringWidth(
                               chart['x_axis'][bucket_num],
                               "Helvetica", 12)
        label_left   = max(left,
                           left + bucket_width/2 - label_width/2)
        label_bottom = axis_top - TICKMARK_HEIGHT-4-label_height

        canvas.setFont("Helvetica", 12)
        canvas.setFillColorRGB(0.0, 0.0, 0.0)
        canvas.drawString(label_left, label_bottom,
                          chart['x_axis'][bucket_num])

        left = left + bucket_width

    canvas.setStrokeColorRGB(0.25, 0.25, 0.625)
    canvas.setLineWidth(1)
    canvas.line(left, axis_top, left, axis_top - TICKMARK_HEIGHT)
```

同样，`y_axis.py` 模块应该实现如下：

```py
from ...constants import *

def draw(chart, canvas):
    label_height = 12 * 1.2

    axis_top    = CHART_HEIGHT - TITLE_HEIGHT
    axis_bottom = X_AXIS_HEIGHT
    axis_height = axis_top - axis_bottom

    canvas.setStrokeColorRGB(0.25, 0.25, 0.625)
    canvas.setLineWidth(2)
    canvas.line(Y_AXIS_WIDTH, axis_top, Y_AXIS_WIDTH, axis_bottom)

    for y_value in chart['y_labels']:
        y = ((y_value - chart['y_min']) /
             (chart['y_max'] - chart['y_min']))

        y_pos = axis_bottom + int(y * axis_height)

        canvas.setLineWidth(1)
        canvas.line(Y_AXIS_WIDTH - TICKMARK_HEIGHT, y_pos,
                    Y_AXIS_WIDTH, y_pos)

        label_width = canvas.stringWidth(str(y_value),
                                         "Helvetica", 12)
        label_left  = Y_AXIS_WIDTH - TICKMARK_HEIGHT-label_width-4
        label_bottom = y_pos - label_height/4

        canvas.setFont("Helvetica", 12)
        canvas.setFillColorRGB(0.0, 0.0, 0.0)
        canvas.drawString(label_left, label_bottom, str(y_value))
```

对于 `bar_series.py` 模块，输入以下内容：

```py
from ...constants import *

def draw(chart, canvas):
    avail_width  = CHART_WIDTH - Y_AXIS_WIDTH - MARGIN
    bucket_width = avail_width / len(chart['x_axis'])

    bottom       = X_AXIS_HEIGHT
    max_top      = CHART_HEIGHT - TITLE_HEIGHT
    avail_height = max_top - bottom

    left = Y_AXIS_WIDTH
    for y_value in chart['series']:
        bar_left  = left + MARGIN / 2
        bar_width = bucket_width - MARGIN

        y = ((y_value - chart['y_min']) /
             (chart['y_max'] - chart['y_min']))

        bar_height = int(y * avail_height)

        canvas.setStrokeColorRGB(0.25, 0.25, 0.625)
        canvas.setFillColorRGB(0.906, 0.906, 0.953)
        canvas.rect(bar_left, bottom, bar_width, bar_height,
                    stroke=True, fill=True)

        left = left + bucket_width
```

最后，`line_series.py` 模块应该如下所示：

```py
from ...constants import *

def draw(chart, canvas):
    avail_width  = CHART_WIDTH - Y_AXIS_WIDTH - MARGIN
    bucket_width = avail_width / len(chart['x_axis'])

    bottom       = X_AXIS_HEIGHT
    max_top      = CHART_HEIGHT - TITLE_HEIGHT
    avail_height = max_top - bottom

    left   = Y_AXIS_WIDTH
    prev_y = None
    for y_value in chart['series']:
        y = ((y_value - chart['y_min']) /
             (chart['y_max'] - chart['y_min']))

        cur_y = bottom + int(y * avail_height)

        if prev_y != None:
            canvas.setStrokeColorRGB(0.25, 0.25, 0.625)
            canvas.setLineWidth(1)
            canvas.line(left - bucket_width / 2, prev_y,
                        left + bucket_width / 2, cur_y)

        prev_y = cur_y
        left = left + bucket_width
```

正如你所看到的，这些模块看起来与它们的 PNG 版本非常相似。只要我们考虑到这两个库工作方式的差异，我们可以用 ReportLab 做任何 Python Imaging Library 能做的事情。

这使我们只需要做一个更改，就能完成对 Charter 库的新实现：我们需要更新 `renderer.py` 模块，以使这些新的 PDF 渲染模块可用。为此，将以下 `import` 语句添加到这个模块的顶部：

```py
from .pdf import title       as title_pdf
from .pdf import x_axis      as x_axis_pdf
from .pdf import y_axis      as y_axis_pdf
from .pdf import bar_series  as bar_series_pdf
from .pdf import line_series as line_series_pdf
```

然后，在这个模块的部分中，我们定义了 `renderers` 字典，通过向你的代码添加以下突出显示的行，为字典创建一个新的 `pdf` 条目：

```py
renderers = {
    ...
    **'pdf' : {
 **'title'       : title_pdf,
 **'x_axis'      : x_axis_pdf,
 **'y_axis'      : y_axis_pdf,
 **'bar_series'  : bar_series_pdf,
 **'line_series' : line_series_pdf
 **}
}
```

完成这些工作后，你已经完成了重构和重新实现 Charter 模块。假设你没有犯任何错误，你的库现在应该能够生成 PNG 和 PDF 格式的图表。

## 测试代码

为了确保你的程序正常工作，编辑你的 `test_charter.py` 程序，并将输出文件的名称从 `chart.png` 更改为 `chart.pdf`。然后运行这个程序，你应该会得到一个包含你的图表高质量版本的 PDF 文件：

![测试代码](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mdl-prog-py/img/B05012_4_12.jpg)

### 注意

注意图表出现在页面底部，而不是顶部。这是因为 PDF 文件将 `y=0` 位置放在页面底部。你可以通过计算页面的高度（以点为单位）并添加适当的偏移量，轻松地将图表移动到页面顶部。如果你愿意，可以实现这一点，但现在我们的任务已经完成。

如果你放大，你会发现图表的文本看起来仍然很好：

![测试代码](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mdl-prog-py/img/B05012_4_13.jpg)

这是因为我们现在生成的是矢量格式的 PDF 文件，而不是位图图像。这个文件可以在高质量激光打印机上打印，而不会出现像素化。更好的是，你库的现有用户仍然可以要求 PNG 版本的图表，他们不会注意到任何变化。

恭喜你——你做到了！

# 所得到的教训

虽然 Charter 库只是 Python 模块化编程的一个例子，你并没有一个坚持要求你生成 PDF 格式图表的老板，但这些例子被选中是因为问题一点也不简单，你需要做出的改变也非常具有挑战性。回顾我们所取得的成就，你可能会注意到几件事情：

+   面对需求的重大变化，我们的第一反应通常是消极的：“哦，不！我怎么可能做到？”，“这永远不会起作用”，等等。

+   与其着手开始修改代码，通常更好的做法是退后一步，思考现有代码库的结构以及为满足新需求可能需要做出的改变。

+   当新需求涉及到以前未使用过的库或工具时，值得花一些时间研究可能的选项，并可能编写一个简单的示例程序来检查库是否能够满足您的要求，然后再开始更新您的代码。

+   通过谨慎使用模块和包，对现有代码所需的更改可以保持在最低限度。在 Charter 中，我们可以利用所有现有的渲染器模块，只需对源代码进行轻微更改。我们只需要重写一个函数（`generate_chart()`函数），并添加一个新的`renderer`模块来简化对渲染器的访问，然后编写每个渲染器的新 PDF 版本。通过这种方式，模块化编程技术的使用有助于将更改隔离到程序的受影响部分。

+   通常情况下，最终的系统比我们开始时的系统更好。与其将我们的程序变成意大利面代码，支持 PDF 生成的需求导致了一个更模块化、更有结构的库。特别是，`renderer`模块处理了以各种格式渲染各种图表元素的复杂性，使得系统的其余部分只需调用`renderer.draw()`来完成工作，而无需直接导入和使用大量模块。由于这种改变，我们可以很容易地添加更多的图表元素或更多的输出格式，而对我们的代码进行最小的进一步更改。

总体教训很明显：与其抵制对需求的变化，不如接受它们。最终的结果是一个更好的系统——更健壮，更可扩展，通常也更有组织。当然，前提是你要做对。

# 总结

在这一章中，我们使用模块化编程技术来实现一个名为 Charter 的虚构图表生成包。我们看到图表由标准元素组成，以及如何将这种组织转化为程序代码。成功创建了一个能够将图表渲染为位图图像的工作图表生成库后，我们看到了需求上的根本变化起初似乎是一个问题，但实际上是重构和改进代码的机会。

通过这个虚构的例子，我们重构了 Charter 库以处理 PDF 格式的图表。在这样做的过程中，我们了解到使用模块化技术来应对需求的重大变化可以帮助隔离需要进行的更改，并且重构我们的代码通常会导致一个比起始状态更有组织、更可扩展和更健壮的系统。

在下一章中，我们将学习如何使用标准的模块化编程“模式”来处理各种编程挑战。


# 第五章：使用模块模式

在前几章中，我们详细讨论了 Python 模块和包的工作原理，并学习了如何在程序中使用它们。在使用模块化编程技术时，你会发现模块和包的使用方式往往遵循标准模式。在本章中，我们将研究使用模块和包处理各种编程挑战的一些常见模式。特别是，我们将：

+   了解分而治之技术如何帮助你解决编程问题

+   看看抽象原则如何帮助你将要做的事情与如何做它分开

+   了解封装如何允许你隐藏信息表示的细节

+   看到包装器是调用其他模块以简化或改变模块使用方式的模块

+   学习如何创建可扩展的模块

让我们从分而治之的原则开始。

# 分而治之

分而治之是将问题分解为较小部分的过程。你可能不知道如何解决一个特定的问题，但通过将其分解为较小的部分，然后依次解决每个部分，然后解决原始问题。

当然，这是一个非常普遍的技术，并不仅适用于模块和包的使用。然而，模块化编程有助于你通过分而治之的过程：当你分解问题时，你会发现你需要程序的一部分来执行特定的任务或一系列任务，而 Python 模块（和包）是组织这些任务的完美方式。

在本书中，我们已经做过几次这样的事情。例如，当面临创建图表生成库的挑战时，我们使用了分而治之的技术，提出了可以绘制单个图表元素的**渲染器**的概念。然后我们意识到我们需要几个不同的渲染器，这完美地转化为包含每个渲染器单独模块的`renderers`包。 

分而治之的方法不仅建议了代码的可能模块化结构，也可以反过来使用。当你考虑程序的设计时，你可能会想到一个与你要解决的问题相关的模块或包的概念。你甚至可能会规划出每个模块和包提供的各个函数。尽管你还不知道如何解决整个问题，但这种模块化设计有助于澄清你对问题的思考，从而使使用分而治之的方法更容易解决问题的其余部分。换句话说，模块和包帮助你在分而治之的过程中澄清你的思路。

# 抽象

抽象是另一个非常普遍的编程模式，适用于不仅仅是模块化编程。抽象本质上是隐藏复杂性的过程：将你想要做的事情与如何做它分开。

抽象对所有的计算机编程都是绝对基础的。例如，想象一下，你必须编写一个计算两个平均数然后找出两者之间差异的程序。这个程序的简单实现可能看起来像下面这样：

```py
values_1 = [...]
values_2 = [...]

total_1 = 0
for value in values_1:
    total = total + value
average_1 = total / len(values_1)

total_2 = 0
for value in values_2:
    total = total + value
average_2 = total / len(values_2)

difference = abs(total_1 - total-2)
print(difference)
```

正如你所看到的，计算列表平均数的代码重复了两次。这是低效的，所以你通常会写一个函数来避免重复。可以通过以下方式实现：

```py
values_1 = [...]
values_2 = [...]

def average(values):
    total = 0
    for value in values:
        total = total + value
    return = total / len(values)

average_1 = average(values_1)
average_2 = average(values_2)
difference = abs(total_1 - total-2)
print(difference)
```

当然，每次编程时你都在做这种事情，但实际上这是一个非常重要的过程。当你创建这样一个函数时，函数内部处理*如何*做某事，而调用该函数的代码只知道*要*做什么，以及函数会去做。换句话说，函数*隐藏了*任务执行的复杂性，使得程序的其他部分只需在需要执行该任务时调用该函数。

这种过程称为**抽象**。使用这种模式，你可以*抽象出*某事物的具体细节，这样你的程序的其他部分就不需要担心这些细节。

抽象不仅适用于编写函数。隐藏复杂性的一般原则也适用于函数组，而模块是将函数组合在一起的完美方式。例如，你的程序可能需要使用颜色，因此你编写了一个名为`colors`的模块，其中包含各种函数，允许你创建和使用颜色值。`colors`模块中的各种函数了解颜色值及如何使用它们，因此你的程序的其他部分不需要担心这些。使用这个模块，你可以做各种有趣的事情。例如：

```py
purple = colors.new_color(1.0, 0.0, 1.0)
yellow = colors.new_color(1.0, 1.0, 0.0)
dark_purple = colors.darken(purple, 0.3)
color_range = colors.blend(yellow, dark_purple, num_steps=20)
dimmed_yellow = colors.desaturate(yellow, 0.8)
```

在这个模块之外，你的代码可以专注于它想要做的事情，而不需要知道这些各种任务是如何执行的。通过这样做，你正在使用抽象模式将这些颜色计算的复杂性隐藏起来，使其不影响程序的其他部分。

抽象是设计和编写模块和包的基本技术。例如，我们在上一章中使用的 Pillow 库提供了各种模块，允许你加载、操作、创建和保存图像。我们可以使用这个库而不需要知道这些各种操作是如何执行的。例如，我们可以调用`drawer.line((x1, y1), (x2, y2), color, width)`而不必担心设置图像中的单个像素的细节。

应用抽象模式的一个伟大之处在于，当你开始实现代码时，通常并不知道某事物的复杂程度。例如，想象一下，你正在为酒店酒吧编写一个销售点系统。系统的一部分需要计算顾客点酒时应收取的价格。我们可以使用各种公式来计算这个价格，根据数量、使用的酒类等。但其中一个具有挑战性的特点是需要支持*欢乐时光*，即在此期间饮料将以折扣价提供。

起初，你被告知欢乐时光是每天晚上五点到六点之间。因此，使用良好的模块化技术，你在代码中添加了以下函数：

```py
def is_happy_hour():
    if datetime.datetime.now().hour == 17: # 5pm.
        return True
    else:
        return False
```

然后你可以使用这个函数来分离计算欢乐时光的方法和欢乐时光期间发生的事情。例如：

```py
if is_happy_hour():
    price = price * 0.5
```

到目前为止，这还相当简单，你可能会想要完全绕过创建`is_happy_hour()`函数。然而，当你发现欢乐时光不适用于星期日时，这个函数很快就变得更加复杂。因此，你必须修改`is_happy_hour()`函数以支持这一点：

```py
def is_happy_hour():
    if datetime.date.today().weekday() == 6: # Sunday.
        return False
    elif datetime.datetime.now().hour == 17: # 5pm.
        return True
    else:
        return False
```

但是你随后发现，欢乐时光不适用于圣诞节或耶稣受难日。虽然圣诞节很容易计算，但计算复活节在某一年的日期所使用的逻辑要复杂得多。如果你感兴趣，本章的示例代码包括`is_happy_hour()`函数的实现，其中包括对圣诞节和耶稣受难日的支持。不用说，这个实现相当复杂。

请注意，随着我们的`is_happy_hour()`函数的不断发展，它变得越来越复杂 - 起初我们以为它会很简单，但是添加的要求使它变得更加复杂。幸运的是，因为我们已经将计算快乐时光的细节从需要知道当前是否是快乐时光的代码中抽象出来，只需要更新一个函数来支持这种增加的复杂性。

# 封装

封装是另一种经常适用于模块和包的编程模式。使用封装，你有一个*东西* - 例如，颜色、客户或货币 - 你需要存储关于它的数据，但是你将这些数据的表示隐藏起来，不让系统的其他部分知道。而不是直接提供这个东西，你提供设置、检索和操作这个东西数据的函数。

为了看到这是如何工作的，让我们回顾一下我们在上一章中编写的一个模块。我们的`chart.py`模块允许用户定义一个图表并设置有关它的各种信息。这是我们为这个模块编写的代码的一个副本：

```py
def new_chart():
    return {}

def set_title(chart, title):
    chart['title'] = title

def set_x_axis(chart, x_axis):
    chart['x_axis'] = x_axis

def set_y_axis(chart, minimum, maximum, labels):
    chart['y_min']    = minimum
    chart['y_max']    = maximum
    chart['y_labels'] = labels

def set_series_type(chart, series_type):
    chart['series_type'] = series_type

def set_series(chart, series):
    chart['series'] = series
```

正如你所看到的，`new_chart()`函数创建了一个新的“图表”，而不清楚地告诉系统如何存储有关图表的信息 - 我们在这里使用了一个字典，但我们也可以使用一个对象、一个 base64 编码的字符串，或者其他任何东西。系统的其他部分并不关心，因为它只是调用`chart.py`模块中的各种函数来设置图表的各个值。

不幸的是，这并不是封装的一个完美的例子。我们的各种`set_XXX()`函数充当**设置器** - 它们让我们设置图表的各种值 - 但我们只是假设我们的图表生成函数可以直接从图表的字典中访问有关图表的信息。如果这将是封装的一个纯粹的例子，我们还将编写相应的**获取器**函数，例如：

```py
def get_title(chart):
    return chart['title']

def get_x_axis(chart):
    return chart['x_axis']

def get_y_axis(chart):
    return (chart['y_min'], chart['y_max'], chart['y_labels'])

def get_series_type(chart):
    return chart['series_type']

def get_series(chart):
    return chart['series']
```

通过将这些获取器函数添加到我们的模块中，我们现在有了一个完全封装的模块，可以存储和检索关于图表的信息。`charter`包的其他部分想要使用图表时，将调用获取器函数来检索该图表的数据，而不是直接访问它。

### 提示

在模块中编写设置器和获取器函数的这些示例有点牵强；封装通常是使用面向对象编程技术来完成的。然而，正如你所看到的，当编写只使用模块化编程技术的代码时，完全可以使用封装。

也许你会想知道为什么有人会想要使用封装。为什么不直接写`charts.get_title(chart)`，而不是简单地写`chart['title']`？第二个版本更短。它还避免了调用函数，因此速度会更快。为什么要使用封装呢？

在程序中使用封装有两个原因。首先，通过使用获取器和设置器函数，你隐藏了信息存储的细节。这使你能够更改内部表示而不影响程序的任何其他部分 - 并且在编写程序时你几乎可以肯定的一件事是，你将不断添加更多的信息和功能。这意味着你的数据的内部表示*将*发生变化。通过将存储的内容与存储方式分离，你的系统变得更加健壮，你可以进行更改而无需重写大量代码。这是一个良好模块化设计的标志。

使用封装的第二个主要原因是允许您的代码在用户设置特定值时执行某些操作。例如，如果用户更改订单的数量，您可以立即重新计算该订单的总价格。设置器经常做的另一件事是将更新后的值保存到磁盘或数据库中。您还可以在设置器中添加错误检查和其他逻辑，以便捕获可能很难跟踪的错误。

让我们详细看一下使用封装模式的 Python 模块。例如，假设我们正在编写一个用于存储食谱的程序。用户可以创建一个喜爱食谱的数据库，并在需要时显示这些食谱。

让我们创建一个 Python 模块来封装食谱的概念。在这个例子中，我们将食谱存储在内存中，以保持简单。对于每个食谱，我们将存储食谱的名称、食谱产生的份数、配料列表以及制作食谱时用户需要遵循的指令列表。

创建一个名为`recipes.py`的新 Python 源文件，并输入以下内容到此文件中：

```py
def new():
    return {'name'         : None,
            'num_servings' : 1,
            'instructions' : [],
            'ingredients'  : []}

def set_name(recipe, name):
    recipe['name'] = name

def get_name(recipe):
    return recipe['name']

def set_num_servings(recipe, num_servings):
    recipe['num_servings'] = num_servings

def get_num_servings(recipe):
    return recipe['num_servings']

def set_ingredients(recipe, ingredients):
    recipe['ingredients'] = ingredients

def get_ingredients(recipe):
    return recipe['ingredients']

def set_instructions(recipe, instructions):
    recipe['instructions'] = instructions

def get_instructions(recipe):
    return recipe['instructions']

def add_instruction(recipe, instruction):
    recipe['instructions'].append(instruction)

def add_ingredient(recipe, ingredient, amount, units):
    recipe['ingredients'].append({'ingredient' : ingredient,
                                  'amount'     : amount,
                                  'units'      : units})
```

正如您所见，我们再次使用 Python 字典来存储我们的信息。我们可以使用 Python 类或 Python 标准库中的`namedtuple`。或者，我们可以将信息存储在数据库中。但是，在这个例子中，我们希望尽可能简化我们的代码，字典是最简单的解决方案。

创建新食谱后，用户可以调用各种设置器和获取器函数来存储和检索有关食谱的信息。我们还有一些有用的函数，让我们一次添加一条指令和配料，这对我们正在编写的程序更方便。

请注意，当向食谱添加配料时，调用者需要提供三条信息：配料的名称、所需数量以及衡量此数量的单位。例如：

```py
recipes.add_ingredient(recipe, "Milk", 1, "cup")
```

到目前为止，我们已经封装了食谱的概念，允许我们存储所需的信息，并在需要时检索它。由于我们的模块遵循了封装原则，我们可以更改存储食谱的方式，向我们的模块添加更多信息和新行为，而不会影响程序的其余部分。

让我们再添加一个有用的函数到我们的食谱中：

```py
def to_string(recipe, num_servings):
    multiplier = num_servings / recipe['num_servings']
    s = []
    s.append("Recipe for {}, {} servings:".format(recipe['name'],
                                                  num_servings))
    s.append("")
    s.append("Ingredients:")
    s.append("")
    for ingredient in recipe['ingredients']:
        s.append("    {} - {} {}".format(
                     ingredient['ingredient'],
                     ingredient['amount'] * multiplier,
                     ingredient['units']))
    s.append("")
    s.append("Instructions:")
    s.append("")
    for i,instruction in enumerate(recipe['instructions']):
        s.append("{}. {}".format(i+1, instruction))

    return s
```

该函数返回一个字符串列表，可以打印出来以总结食谱。注意`num_servings`参数：这允许我们为不同的份数定制食谱。例如，如果用户创建了一个三份食谱并希望将其加倍，可以使用`to_string()`函数，并将`num_servings`值设为`6`，正确的数量将包含在返回的字符串列表中。

让我们看看这个模块是如何工作的。打开终端或命令行窗口，使用`cd`命令转到创建`recipes.py`文件的目录，并输入`python`启动 Python 解释器。然后，尝试输入以下内容以创建披萨面团的食谱：

```py
import recipes
recipe = recipes.new("Pizza Dough", num_servings=1)
recipes.add_ingredient(recipe, "Greek Yogurt", 1, "cup")
recipes.add_ingredient(recipe, "Self-Raising Flour", 1.5, "cups")
recipes.add_instruction(recipe, "Combine yogurt and 2/3 of the flour in a bowl and mix with a beater until combined")
recipes.add_instruction(recipe, "Slowly add additional flour until it forms a stiff dough")
recipes.add_instruction(recipe, "Turn out onto a floured surface and knead until dough is tacky")
recipes.add_instruction(recipe, "Roll out into a circle of the desired thickness and place on a greased and lined baking tray")

```

到目前为止一切顺利。现在让我们使用`to_string()`函数打印出食谱的详细信息，并将其加倍到两份：

```py
for s in recipes.to_string(recipe, num_servings=2):
 **print s

```

一切顺利的话，食谱应该已经打印出来了：

```py
Recipe for Pizza Dough, 2 servings:

Ingredients:

 **Greek Yogurt - 2 cup
 **Self-rising Flour - 3.0 cups

Instructions:

1\. Combine yogurt and 2/3 of the flour in a bowl and mix with a beater until combined
2\. Slowly add additional flour until it forms a stiff dough
3\. Turn out onto a floured surface and knead until dough is tacky
4\. Roll out into a circle of the desired thickness and place on a greased and lined baking tray

```

正如您所见，有一些次要的格式问题。例如，所需的希腊酸奶数量列为`2 cup`而不是`2 cups`。如果您愿意，您可以很容易地解决这个问题，但要注意的重要事情是`recipes.py`模块已经封装了食谱的概念，允许您（和您编写的其他程序）处理食谱而不必担心细节。

作为练习，你可以尝试修复`to_string()`函数中数量的显示。你也可以尝试编写一个新的函数，从食谱列表中创建一个购物清单，在两个或更多食谱使用相同的食材时自动合并数量。如果你完成了这些练习，你很快就会注意到实现可能会变得非常复杂，但通过将细节封装在一个模块中，你可以隐藏这些细节，使其对程序的其余部分不可见。

# 包装器

包装器本质上是一组调用其他函数来完成工作的函数：

![包装器](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mdl-prog-py/img/B05012_5_01.jpg)

包装器用于简化接口，使混乱或设计不良的 API 更易于使用，将数据格式转换为更方便的形式，并实现跨语言兼容性。包装器有时也用于向现有 API 添加测试和错误检查代码。

让我们看一个包装器模块的真实应用。想象一下，你在一家大型银行工作，并被要求编写一个程序来分析资金转账，以帮助识别可能的欺诈行为。你的程序实时接收有关每笔银行间资金转账的信息。对于每笔转账，你会得到：

+   转账金额

+   转账发生的分支的 ID

+   资金被发送到的银行的识别码

你的任务是分析随时间变化的转账，以识别异常的活动模式。为此，你需要计算过去八天的每个分支和目标银行的所有转账总值。然后，你可以将当天的总额与前七天的平均值进行比较，并标记任何日总额超过平均值 50%以上的情况。

你可以从决定如何表示一天的总转账开始。因为你需要跟踪每个分支和目标银行的转账总额，所以将这些总额存储在一个二维数组中是有意义的：

![包装器](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mdl-prog-py/img/B05012_5_02.jpg)

在 Python 中，这种二维数组的类型被表示为一个列表的列表：

```py
totals = [[0, 307512, 1612, 0, 43902, 5602918],
          [79400, 3416710, 75, 23508, 60912, 5806],
          ...
         ]
```

然后你可以保留一个单独的分支 ID 列表，每行一个，另一个列表保存每列的目标银行代码：

```py
branch_ids = [125000249, 125000252, 125000371, ...]
bank_codes = ["AMERUS33", "CERYUS33", "EQTYUS44", ...]
```

使用这些列表，你可以通过处理特定日期发生的转账来计算给定日期的总额：

```py
totals = []
for branch in branch_ids:
    branch_totals = []
    for bank in bank_codes:
        branch_totals.append(0)
    totals.append(branch_totals)

for transfer in transfers_for_day:
    branch_index = branch_ids.index(transfer['branch'])
    bank_index   = bank_codes.index(transfer['dest_bank'])
    totals[branch_index][bank_index] += transfer['amount']
```

到目前为止一切顺利。一旦你得到了每天的总额，你可以计算平均值，并将其与当天的总额进行比较，以识别高于平均值 150%的条目。

假设你已经编写了这个程序并设法让它工作。但当你开始使用它时，你立即发现了一个问题：你的银行有超过 5000 个分支，而你的银行可以向全球超过 15000 家银行转账，这总共需要为 7500 万种组合保留总额，因此，你的程序计算总额的时间太长了。

为了使你的程序更快，你需要找到一种更好的处理大量数字数组的方法。幸运的是，有一个专门设计来做这件事的库：**NumPy**。

NumPy 是一个出色的数组处理库。你可以创建巨大的数组，并使用一个函数调用对数组执行复杂的操作。不幸的是，NumPy 也是一个密集和晦涩的库。它是为数学深度理解的人设计和编写的。虽然有许多教程可用，你通常可以弄清楚如何使用它，但使用 NumPy 的代码通常很难理解。例如，要计算多个矩阵的平均值将涉及以下操作：

```py
daily_totals = []
for totals in totals_to_average:
    daily_totals.append(totals)
average = numpy.mean(numpy.array(daily_totals), axis=0)
```

弄清楚最后一行的作用需要查阅 NumPy 文档。由于使用 NumPy 的代码的复杂性，这是一个使用**包装模块**的完美例子：包装模块可以为 NumPy 提供一个更易于使用的接口，这样你的代码就可以使用它，而不会被复杂和令人困惑的函数调用所淹没。

为了通过这个例子，我们将从安装 NumPy 库开始。NumPy ([`www.numpy.org`](http://www.numpy.org)) 可以在 Mac OS X、Windows 和 Linux 机器上运行。你安装它取决于你使用的操作系统：

+   对于 Mac OS X，你可以从[`www.kyngchaos.com/software/python`](http://www.kyngchaos.com/software/python)下载安装程序。

+   对于 MS Windows，你可以从[`www.lfd.uci.edu/~gohlke/pythonlibs/#numpy`](http://www.lfd.uci.edu/~gohlke/pythonlibs/#numpy)下载 NumPy 的 Python“wheel”文件。选择与你的操作系统和所需的 Python 版本匹配的 NumPy 的预构建版本。要使用 wheel 文件，使用`pip install`命令，例如，`pip install numpy-1.10.4+mkl-cp34-none-win32.whl`。

### 注意

有关安装 Python wheel 的更多信息，请参阅[`pip.pypa.io/en/latest/user_guide/#installing-from-wheels`](https://pip.pypa.io/en/latest/user_guide/#installing-from-wheels)。

+   如果你的计算机运行 Linux，你可以使用你的 Linux 软件包管理器来安装 NumPy。或者，你可以下载并构建 NumPy 的源代码形式。

为了确保 NumPy 正常工作，启动你的 Python 解释器并输入以下内容：

```py
import numpy
a = numpy.array([[1, 2], [3, 4]])
print(a)
```

一切顺利的话，你应该看到一个 2 x 2 的矩阵显示出来：

```py
[[1 2]
 **[3 4]]

```

现在我们已经安装了 NumPy，让我们开始编写我们的包装模块。创建一个新的 Python 源文件，命名为`numpy_wrapper.py`，并输入以下内容到这个文件中：

```py
import numpy

```

就这些了；我们将根据需要向这个包装模块添加函数。

接下来，创建另一个 Python 源文件，命名为`detect_unusual_transfers.py`，并输入以下内容到这个文件中：

```py
import random
import numpy_wrapper as npw

BANK_CODES = ["AMERUS33", "CERYUS33", "EQTYUS44",
              "LOYDUS33", "SYNEUS44", "WFBIUS6S"]

BRANCH_IDS = ["125000249", "125000252", "125000371",
              "125000402", "125000596", "125001067"]
```

正如你所看到的，我们正在为我们的例子硬编码银行和分行代码；在一个真实的程序中，这些值将从某个地方加载，比如文件或数据库。由于我们没有可用的数据，我们将使用`random`模块来创建一些。我们还将更改`numpy_wrapper`模块的名称，以便更容易从我们的代码中访问。

现在让我们使用`random`模块创建一些要处理的资金转账数据：

```py
days = [1, 2, 3, 4, 5, 6, 7, 8]
transfers = []

for i in range(10000):
    day       = random.choice(days)
    bank_code = random.choice(BANK_CODES)
    branch_id = random.choice(BRANCH_IDS)
    amount    = random.randint(1000, 1000000)

    transfers.append((day, bank_code, branch_id, amount))
```

在这里，我们随机选择一天、一个银行代码、一个分行 ID 和一个金额，将这些值存储在`transfers`列表中。

我们的下一个任务是将这些信息整理成一系列数组。这样可以让我们计算每天的转账总额，按分行 ID 和目标银行分组。为此，我们将为每一天创建一个 NumPy 数组，其中每个数组中的行代表分行，列代表目标银行。然后我们将逐个处理转账列表中的转账。以下插图总结了我们如何依次处理每笔转账：

![Wrappers](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mdl-prog-py/img/B05012_5_03.jpg)

首先，我们选择发生转账的那一天的数组，然后根据目标银行和分行 ID 选择适当的行和列。最后，我们将转账金额添加到当天数组中的那个项目中。

现在让我们实现这个逻辑。我们的第一个任务是创建一系列 NumPy 数组，每天一个。在这里，我们立即遇到了一个障碍：NumPy 有许多不同的选项用于创建数组；在这种情况下，我们想要创建一个保存整数值并且其内容初始化为零的数组。如果我们直接使用 NumPy，我们的代码将如下所示：

```py
array = numpy.zeros((num_rows, num_cols), dtype=numpy.int32)
```

这并不是很容易理解，所以我们将这个逻辑移到我们的 NumPy 包装模块中。编辑`numpy_wrapper.py`文件，并在这个模块的末尾添加以下内容：

```py
def new(num_rows, num_cols):
    return numpy.zeros((num_rows, num_cols), dtype=numpy.int32)
```

现在，我们可以通过调用我们的包装函数（`npw.new()`）来创建一个新的数组，而不必担心 NumPy 的工作细节。我们已经简化了 NumPy 的特定方面的接口：

![包装器](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mdl-prog-py/img/B05012_5_04.jpg)

现在让我们使用我们的包装函数来创建我们需要的八个数组，每天一个。在`detect_unusual_transfers.py`文件的末尾添加以下内容：

```py
transfers_by_day = {}
for day in days:
    transfers_by_day[day] = npw.new(num_rows=len(BANK_CODES),
                                    num_cols=len(BRANCH_IDS))
```

现在我们有了 NumPy 数组，我们可以像使用嵌套的 Python 列表一样使用它们。例如：

```py
array[row][col] = array[row][col] + amount
```

我们只需要选择适当的数组，并计算要使用的行和列号。以下是必要的代码，你应该将其添加到你的`detect_unusual_transfers.py`脚本的末尾：

```py
for day,bank_code,branch_id,amount in transfers:
    array = transfers_by_day[day]
    row = BRANCH_IDS.index(branch_id)
    col = BANK_CODES.index(bank_code)
    array[row][col] = array[row][col] + amount
```

现在我们已经将转账整理成了八个 NumPy 数组，我们希望使用所有这些数据来检测任何不寻常的活动。对于每个分行 ID 和目标银行代码的组合，我们需要做以下工作：

1.  计算前七天活动的平均值。

1.  将计算出的平均值乘以 1.5。

1.  如果第八天的活动大于平均值乘以 1.5，那么我们认为这种活动是不寻常的。

当然，我们需要对我们的数组中的每一行和每一列都这样做，这将非常慢；这就是为什么我们使用 NumPy 的原因。因此，我们需要计算多个数字数组的平均值，然后将平均值数组乘以 1.5，最后，将乘以后的数组与第八天的数据数组进行比较。幸运的是，这些都是 NumPy 可以为我们做的事情。

我们将首先收集我们需要平均的七个数组，以及第八天的数组。为此，将以下内容添加到你的程序的末尾：

```py
latest_day = max(days)

transfers_to_average = []
for day in days:
    if day != latest_day:
        transfers_to_average.append(transfers_by_day[day])

current = transfers_by_day[latest_day]
```

要计算一组数组的平均值，NumPy 要求我们使用以下函数调用：

```py
average = numpy.mean(numpy.array(arrays_to_average), axis=0)
```

由于这很令人困惑，我们将把这个函数移到我们的包装器中。在`numpy_wrapper.py`模块的末尾添加以下代码：

```py
def average(arrays_to_average):
    return numpy.mean(numpy.array(arrays_to_average), axis=0)
```

这让我们可以使用一个调用我们的包装函数来计算七天活动的平均值。为此，将以下内容添加到你的`detect_unusual_transfers.py`脚本的末尾：

```py
average = npw.average(transfers_to_average)
```

正如你所看到的，使用包装器使我们的代码更容易理解。

我们的下一个任务是将计算出的平均值数组乘以 1.5，并将结果与当天的总数进行比较。幸运的是，NumPy 使这变得很容易：

```py
unusual_transfers = current > average * 1.5
```

因为这段代码如此清晰，所以为它创建一个包装器函数没有任何优势。结果数组`unusual_transfers`的大小与我们的`current`和`average`数组相同，数组中的每个条目都是`True`或`False`：

![包装器](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mdl-prog-py/img/B05012_5_05.jpg)

我们几乎完成了；我们的最后任务是识别数组中值为`True`的条目，并告诉用户有不寻常的活动。虽然我们可以扫描每一行和每一列来找到`True`条目，但使用 NumPy 会快得多。以下的 NumPy 代码将给我们一个包含数组中`True`条目的行和列号的列表：

```py
indices = numpy.transpose(array.nonzero())
```

不过，这段代码很难理解，所以它是另一个包装器函数的完美候选者。回到你的`numpy_wrapper.py`模块，并在文件末尾添加以下内容：

```py
def get_indices(array):
    return numpy.transpose(array.nonzero())
```

这个函数返回一个列表（实际上是一个数组），其中包含数组中所有`True`条目的`(行，列)`值。回到我们的`detect_unusual_activity.py`文件，我们可以使用这个函数快速识别不寻常的活动：

```py
    for row,col in npw.get_indices(unusual_transfers):
        branch_id   = BRANCH_IDS[row]
        bank_code   = BANK_CODES[col]
        average_amt = int(average[row][col])
        current_amt = current[row][col]

        print("Branch {} transferred ${:,d}".format(branch_id,
                                                    current_amt) +
              " to bank {}, average = ${:,d}".format(bank_code,
                                                     average_amt))
```

正如你所看到的，我们使用`BRANCH_IDS`和`BANK_CODES`列表来将行和列号转换回相关的分行 ID 和银行代码。我们还检索了可疑活动的平均值和当前金额。最后，我们打印出这些信息，警告用户有不寻常的活动。

如果你运行你的程序，你应该会看到类似这样的输出：

```py
Branch 125000371 transferred $24,729,847 to bank WFBIUS6S, average = $14,954,617
Branch 125000402 transferred $26,818,710 to bank CERYUS33, average = $16,338,043
Branch 125001067 transferred $27,081,511 to bank EQTYUS44, average = $17,763,644

```

因为我们在金融数据中使用随机数，所以输出也将是随机的。尝试运行程序几次；如果没有生成可疑的随机值，则可能根本没有输出。

当然，我们并不真正关心检测可疑的金融活动——这个例子只是一个借口，用来处理 NumPy。更有趣的是我们创建的包装模块，它隐藏了 NumPy 接口的复杂性，使得我们程序的其余部分可以集中精力完成工作。

如果我们继续开发我们的异常活动检测器，毫无疑问，我们会在`numpy_wrapper.py`模块中添加更多功能，因为我们发现了更多想要封装的 NumPy 函数。

这只是包装模块的一个例子。正如我们之前提到的，简化复杂和混乱的 API 只是包装模块的一个用途；它们还可以用于将数据从一种格式转换为另一种格式，向现有 API 添加测试和错误检查代码，并调用用其他语言编写的函数。

请注意，根据定义，包装器始终是*薄*的——虽然包装器中可能有代码（例如，将参数从对象转换为字典），但包装器函数最终总是调用另一个函数来执行实际工作。

# 可扩展模块

大多数情况下，模块提供的功能是预先知道的。模块的源代码实现了一组明确定义的行为，这就是模块的全部功能。然而，在某些情况下，您可能需要一个模块，在编写时模块的行为并不完全定义。系统的其他部分可以以各种方式*扩展*模块的行为。设计为可扩展的模块称为**可扩展模块**。

Python 的一个伟大之处在于它是一种*动态*语言。您不需要在运行之前定义和编译所有代码。这使得使用 Python 创建可扩展模块变得很容易。

在本节中，我们将看一下模块可以被扩展的三种不同方式：通过使用**动态导入**，编写**插件**，以及使用**钩子**。

## 动态导入

在上一章中，我们创建了一个名为`renderers.py`的模块，它选择了一个适当的渲染器模块，以使用给定的输出格式绘制图表元素。以下是该模块源代码的摘录：

```py
from .png import title  as title_png
from .png import x_axis as x_axis_png

from .pdf import title  as title_pdf
from .pdf import x_axis as x_axis_pdf

renderers = {
    'png' : {
        'title'  : title_png,
        'x_axis' : x_axis_png,
    },
    'pdf' : {
        'title'  : title_pdf,
        'x_axis' : x_axis_pdf,
    }
}

def draw(format, element, chart, output):
    renderers[format][element].draw(chart, output)
```

这个模块很有趣，因为它以有限的方式实现了可扩展性的概念。请注意，`renderer.draw()`函数调用另一个模块内的`draw()`函数来执行实际工作；使用哪个模块取决于所需的图表格式和要绘制的元素。

这个模块并不真正可扩展，因为可能的模块列表是由模块顶部的`import`语句确定的。然而，可以通过使用`importlib`将其转换为完全可扩展的模块。这是 Python 标准库中的一个模块，它使开发人员可以访问用于导入模块的内部机制；使用`importlib`，您可以动态导入模块。

要理解这是如何工作的，让我们看一个例子。创建一个新的目录来保存您的源代码，在这个目录中，创建一个名为`module_a.py`的新模块。将以下代码输入到这个模块中：

```py
def say_hello():
    print("Hello from module_a")
```

现在，创建一个名为`module_b.py`的此模块的副本，并编辑`say_hello()`函数以打印*Hello from module_b*。然后，重复这个过程来创建`module_c.py`。

我们现在有三个模块，它们都实现了一个名为`say_hello()`的函数。现在，在同一个目录中创建另一个 Python 源文件，并将其命名为`load_module.py`。然后，输入以下内容到这个文件中：

```py
import importlib

module_name = input("Load module: ")
if module_name != "":
    module = importlib.import_module(module_name)
    module.say_hello()
```

该程序提示用户使用`input()`语句输入一个字符串。然后，我们调用`importlib.import_module()`来导入具有该名称的模块，并调用该模块的`say_hello()`函数。

尝试运行这个程序，当提示时，输入`module_a`。你应该会看到以下消息显示：

```py
Hello from module_a

```

尝试用其他模块重复这个过程。如果输入一个不存在的模块名称，你会得到一个`ImportError`。

当然，`importlib`并不仅限于导入与当前模块相同目录中的模块；如果需要，你可以包括包名。例如：

```py
module = importlib.import_module("package.sub_package.module")

```

使用`importlib`，你可以动态地导入一个模块——在编写程序时不需要知道模块的名称。我们可以使用这个来重写上一章的`renderer.py`模块，使其完全可扩展：

```py
from importlib import import_module

def draw(format, element, chart, output):
    renderer = import_module("{}.{}.{}".format(__package__,
                                               format,
                                               element))
    renderer.draw(chart, output)
```

### 注意

注意到了特殊的`__package__`变量的使用。它保存了包含当前模块的包的名称；使用这个变量允许我们相对于`renderer.py`模块所属的包导入模块。

动态导入的好处是，在创建程序时不需要知道所有模块的名称。使用`renderer.py`的例子，你可以通过创建新的渲染器模块来添加新的图表格式或元素，系统将在请求时导入它们，而无需对`renderer.py`模块进行任何更改。

## 插件

插件是用户（或其他开发人员）编写并“插入”到你的程序中的模块。插件在许多大型系统中很受欢迎，如 WordPress、JQuery、Google Chrome 和 Adobe Photoshop。插件用于扩展现有程序的功能。

在 Python 中，使用我们在上一节讨论过的动态导入机制很容易实现插件。唯一的区别是，不是导入已经是程序源代码一部分的模块，而是设置一个单独的目录，用户可以将他们想要添加到程序中的插件放在其中。这可以简单地创建一个`plugins`目录在程序的顶层，或者你可以将插件存储在程序源代码之外的目录中，并修改`sys.path`以便 Python 解释器可以在该目录中找到模块。无论哪种方式，你的程序都将使用`importlib.import_module()`来加载所需的插件，然后像访问任何其他 Python 模块中的函数和其他定义一样访问插件中的函数和其他定义。

本章提供的示例代码包括一个简单的插件加载器，展示了这种机制的工作方式。

## 钩子

**钩子**是允许外部代码在程序的特定点被调用的一种方式。钩子通常是一个函数——你的程序会检查是否定义了一个钩子函数，如果是，就会在适当的时候调用这个函数。

让我们看一个具体的例子。假设你有一个程序，其中包括记录用户登录和退出的功能。你的程序的一部分可能包括以下模块，我们将其称为`login_module.py`：

```py
cur_user = None

def login(username, password):
    if is_password_correct(username, password):
        cur_user = username
        return True
    else:
        return False

def logout():
    cur_user = None
```

现在，想象一下，你想要添加一个钩子，每当用户登录时都会被调用。将这个功能添加到你的程序中将涉及对这个模块的以下更改：

```py
cur_user = None
login_hook = None

def set_login_hook(hook):
 **login_hook = hook

def login(username, password):
    if is_password_correct(username, password):
        cur_user = username
 **if login_hook != None:
 **login_hook(username)
        return True
    else:
        return False

def logout():
    cur_user = None
```

有了这段代码，系统的其他部分可以通过设置自己的登录钩子函数来连接到你的登录过程，这样每当用户登录时就会执行一些操作。例如：

```py
def my_login_hook(username):
    if user_has_messages(username):
        show_messages(username)

login_module.set_login_hook(my_login_hook)
```

通过实现这个登录钩子，你扩展了登录过程的行为，而不需要修改登录模块本身。

钩子有一些需要注意的事项：

+   根据你为其实现钩子的行为，钩子函数返回的值可能会被用来改变你的代码的行为。例如，如果登录钩子返回`False`，用户可能会被阻止登录。这并不适用于每个钩子，但这是一个让钩子函数对程序中发生的事情有更多控制的非常有用的方式。

+   在这个例子中，我们只允许为每个 hook 定义一个 hook 函数。另一种实现方式是拥有一个注册的 hook 函数列表，并让您的程序根据需要添加或删除 hook 函数。这样，您可以有几个 hook 函数，每当发生某些事情时依次调用它们。

Hooks 是向您的模块添加特定可扩展性点的绝佳方式。它们易于实现和使用，与动态导入和插件不同，它们不要求您将代码放入单独的模块中。这意味着 hooks 是以非常精细的方式扩展您的模块的理想方式。

# 总结

在本章中，我们看到模块和包的使用方式往往遵循标准模式。我们研究了分而治之的模式，这是将问题分解为较小部分的过程，并看到这种技术如何帮助构建程序结构并澄清您对要解决的问题的思考。

接下来，我们看了抽象模式，这是通过将您想要做的事情与如何做它分开来隐藏复杂性的过程。然后我们研究了封装的概念，即存储有关某些事物的数据，但隐藏该数据的表示方式的细节，使用 getter 和 setter 函数来访问该数据。

然后我们转向包装器的概念，并看到包装器如何用于简化复杂或令人困惑的 API 的接口，转换数据格式，实现跨语言兼容性，并向现有 API 添加测试和错误检查代码。

最后，我们了解了可扩展模块，并看到我们可以使用动态模块导入、插件和 hooks 的技术来创建一个模块，它可以做的不仅仅是您设计它要做的事情。我们看到 Python 的动态特性使其非常适合创建可扩展模块，其中您的模块的行为在编写时并不完全定义。

在下一章中，我们将学习如何设计和实现可以在其他程序中共享和重用的模块。


# 第六章：创建可重用模块

模块化编程不仅是一种为自己编写程序的好技术，也是一种为其他程序员编写的程序的绝佳方式。在本章中，我们将看看如何设计和实现可以在其他程序中共享和重用的模块和包。特别是，我们将：

+   看看模块和包如何被用作分享您编写的代码的一种方式

+   看看为重用编写模块与为作为一个程序的一部分使用编写模块有何不同

+   发现什么使一个模块适合重用

+   看一下成功可重用模块的例子

+   设计一个可重用的包

+   实现一个可重用的包

让我们首先看一下如何使用模块和包与其他人分享您的代码。

# 使用模块和包来分享你的代码

无论您编写的 Python 源代码是什么，您创建的代码都会执行某种任务。也许您的代码分析一些数据，将一些信息存储到文件中，或者提示用户从列表中选择一个项目。您的代码是什么并不重要——最终，您的代码会*做某事*。

通常，这是非常具体的。例如，您可能有一个计算复利、生成维恩图或向用户显示警告消息的函数。一旦您编写了这段代码，您就可以在自己的程序中随时使用它。这就是前一章中描述的简单抽象模式：您将*想要做什么*与*如何做*分开。

一旦您编写了函数，您就可以在需要执行该任务时调用它。例如，您可以在需要向用户显示警告时调用您的`display_warning()`函数，而不必担心警告是如何显示的细节。

然而，这个假设的`display_warning()`函数不仅在您当前编写的程序中有用。其他程序可能也想执行相同的任务——无论是您将来编写的程序还是其他人可能编写的程序。与其每次重新发明轮子，通常更有意义的是*重用*您的代码。

要重用您的代码，您必须分享它。有时，您可能会与自己分享代码，以便在不同的程序中使用它。在其他时候，您可能会与其他开发人员分享代码，以便他们在自己的程序中使用它。

当然，您不仅仅出于慈善目的与他人分享代码。在一个较大的组织中，您经常需要分享代码以提高同事的生产力。即使您是独自工作，通过使用其他人分享的代码，您也会受益，并且通过分享自己的代码，其他人可以帮助找到错误并解决您自己无法解决的问题。

无论您是与自己（在其他项目中）分享代码还是与他人（在您的组织或更广泛的开发社区中）分享代码，基本过程是相同的。有三种主要方式可以分享您的代码：

1.  您可以创建一个代码片段，然后将其复制并粘贴到新程序中。代码片段可以存储在一个名为“代码片段管理器”的应用程序中，也可以存储在一个文本文件夹中，甚至可以作为博客的一部分发布。

1.  您可以将要分享的代码放入一个模块或包中，然后将此模块或包导入新程序。该模块或包可以被物理复制到新程序的源代码中，可以放置在您的 Python 安装的`site-packages`目录中，或者您可以修改`sys.path`以包括可以找到模块或包的目录。

1.  或者，您可以将您的代码转换为一个独立的程序，然后使用`os.system()`从其他代码中调用这个程序。

虽然所有这些选项都可以工作，但并非所有选项都是理想的。让我们更仔细地看看每一个：

+   代码片段非常适合形成函数的代码的一部分。然而，它们非常糟糕，无法跟踪代码的最终位置。因为你已经将代码复制并粘贴到新程序的中间，所以很容易修改它，因为没有简单的方法可以区分粘贴的代码和你编写的程序的其余部分。此外，如果原始代码片段需要修改，例如修复错误，你将不得不找到在程序中使用代码片段的位置并更新以匹配。所有这些都相当混乱且容易出错。

+   导入模块或包的技术具有与较大代码块很好地配合的优势。你要分享的代码可以包括多个函数，甚至可以使用 Python 包将其拆分成多个源文件。由于源代码存储在单独的文件中，你也不太可能意外修改导入的模块。

如果你已经将源模块或包复制到新程序中，那么如果原始模块发生更改，你将需要手动更新它。这并不理想，但由于你替换了整个文件，这并不太困难。另一方面，如果你的新程序使用存储在其他位置的模块，那么就没有需要更新的内容——对原始模块所做的任何更改将立即应用于使用该模块的任何程序。

+   最后，将代码组织成独立的程序意味着你的新程序必须执行它。可以通过以下方式完成：

```py
status = os.system("python other_program.py <params>")
if status != 0:
    print("The other_program failed!")
```

正如你所看到的，可以运行另一个 Python 程序，等待其完成，然后检查返回的状态码，以确保程序成功运行。如果需要，还可以向运行的程序传递参数。但是，你可以传递给程序和接收的信息非常有限。例如，如果你有一个解析 XML 文件并将该文件的摘要保存到磁盘上的不同文件的程序，这种方法将起作用，但你不能直接传递 Python 数据结构给另一个程序进行处理，也不能再次接收 Python 数据结构。

### 注意

实际上，*可以*在运行的程序之间传输 Python 数据结构，但涉及的过程非常复杂，不值得考虑。

正如你所看到的，代码片段、模块/包导入和独立程序形成一种连续体：代码片段非常小且细粒度，模块和包导入支持更大的代码块，同时仍然易于使用和更新，独立程序很大，但在与其交互的方式上受到限制。

在这三种方法中，使用模块和包导入来共享代码似乎是最合适的：它们可以用于大量代码，易于使用和交互，并且在必要时非常容易更新。这使得模块和包成为共享 Python 源代码的理想机制——无论是与自己共享，用于将来的项目，还是与其他人共享。

# 什么使模块可重用？

为了使模块或包可重用，它必须满足以下要求：

+   它必须作为一个独立的单元运行

+   如果你的包意图作为另一个系统的源代码的一部分被包含，你必须使用相对导入来加载包内的其他模块。

+   任何外部依赖关系都必须明确说明

如果一个模块或包不满足这三个要求，要在其他程序中重用它将非常困难，甚至不可能。现在让我们依次更详细地看看这些要求。

## 作为独立单元运行

想象一下，你决定分享一个名为`encryption`的模块，它使用公钥/私钥对执行文本加密。然后，另一个程序员将此模块复制到他们的程序中。然而，当他们尝试使用它时，他们的程序崩溃，并显示以下错误消息：

```py
ImportError: No module named 'hash_utils'

```

`encryption`模块可能已经被共享，但它依赖于原始程序中的另一个模块(`hash_utils.py`)，而这个模块没有被共享，因此`encryption`模块本身是无用的。

解决这个问题的方法是将你想要共享的模块与它可能依赖的任何其他模块结合起来，将这些模块放在一个包中。然后共享这个包，而不是单独的模块。以下插图展示了如何做到这一点：

![作为独立单元运行](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mdl-prog-py/img/B05012_6_01.jpg)

在这个例子中，我们创建了一个名为`encryptionlib`的新包，并将`encryption.py`和`hash_utils.py`文件移动到了这个包中。当然，这需要你重构程序的其余部分，以适应这些模块的新位置，但这样做可以让你在其他程序中重用你的加密逻辑。

### 注意

虽然以这种方式重构你的程序可能有点麻烦，但结果几乎总是对原始程序的改进。将依赖模块放在一个包中有助于改善代码的整体组织。

## 使用相对导入

继续上一节的例子，想象一下你想要将你的新的`encryptionlib`包作为另一个程序的一部分，但不想将其作为单独的包公开。在这种情况下，你可以简单地将整个`encryptionlib`目录包含在你的新系统源代码中。然而，如果你的模块不使用相对导入，就会遇到问题。例如，如果你的`encryption`模块依赖于`hash_utils`模块，那么`encryption`模块将包含一个引用`hash_utils`模块的`import`语句。然而，如果`encryption`模块以以下任何一种方式导入`hash_utils`，则生成的包将无法重用：

```py
import hash_utils
from my_program.lib import hash_utils
from hash_utils import *
```

所有这些导入语句都会失败，因为它们假设`hash_utils.py`文件在程序源代码中的特定固定位置。对于依赖模块在程序源代码中位置的任何假设都会限制包的可重用性，因为你不能将包移动到不同的位置并期望它能够工作。考虑到新项目的要求，你经常需要将包和模块存储在与它们最初开发的位置不同的地方。例如，也许`encryptionlib`包需要安装在`thirdparty`包中，与所有其他重用的库一起。使用绝对导入，你的包将失败，因为其中的模块位置已经改变。

### 注意

如果你发布你的包然后将其安装到 Python 的`site-packages`目录中，这个规则就不适用了。然而，有许多情况下你不想将可重用的包安装到`site-packages`目录中，因此你需要小心相对导入。

为了解决这个问题，请确保包内的任何`import`语句引用同一包内的其他模块时始终使用相对导入。例如：

```py
from . import hash_utils
```

这将使你的包能够在 Python 源树的任何位置运行。

## 注意外部依赖

想象一下，我们的新的`encryptionlib`包利用了我们在上一章中遇到的`NumPy`库。也许`hash_utils`导入了一些来自 NumPy 的函数，并使用它们来快速计算数字列表的二进制哈希。即使 NumPy 作为原始程序的一部分安装了，你也不能假设新程序也是如此：如果你将`encryptionlib`包安装到一个新程序中并运行它，最终会出现以下错误：

```py
ImportError: No module named 'numpy'

```

为了防止发生这种情况，重要的是任何想要重用您的模块的人都知道对第三方模块的依赖，并且清楚地知道为了使您的模块或软件包正常运行需要安装什么。包含这些信息的理想位置是您共享的模块或软件包的`README`文件或其他文档。

### 注意

如果您使用诸如 setuptools 或 pip 之类的自动部署系统，这些工具有其自己的方式来识别您的软件包的要求。然而，将要求列在文档中仍然是一个好主意，这样您的用户在安装软件包之前就会意识到这些要求。

# 什么是一个好的可重用模块？

在前一节中，我们看了可重用模块的*最低*要求。现在让我们来看看可重用性的*理想*要求。一个完美的可重用模块会是什么样子？

优秀的可重用模块与糟糕的模块有三个区别：

+   它试图解决一个一般性问题（或一系列问题），而不仅仅是执行一个特定的任务

+   它遵循标准约定，使得在其他地方使用模块更容易

+   该模块有清晰的文档，以便其他人可以轻松理解和使用它

让我们更仔细地看看这些要点。

## 解决一个一般性问题

通常在编程时，您会发现自己需要执行特定的任务，因此编写一个函数来执行此任务。例如，考虑以下情况：

+   您需要将英寸转换为厘米，因此编写一个`inch_to_cm()`函数来执行此任务。

+   您需要从文本文件中读取地名列表，该文件使用垂直条字符（`|`）作为字段之间的分隔符：

```py
FEATURE_ID|FEATURE_NAME|FEATURE_CLASS|...
1397658|Ester|Populated Place|...
1397926|Afognak|Populated Place|...
```

为此，您创建一个`load_placenames()`函数，从该文件中读取数据。

+   您需要向用户显示客户数量：

```py
1 customer
8 customers
```

消息使用`customer`还是`customers`取决于提供的数量。为了处理这个问题，您创建一个`pluralize_customers()`函数，根据提供的数量返回相应的复数形式的消息。

在所有这些例子中，您都在解决一个具体的问题。很多时候，这样的函数最终会成为一个模块的一部分，您可能希望重用或与他人分享。然而，这三个函数`inch_to_cm()`、`load_placenames()`和`pluralize_customers()`都非常特定于您尝试解决的问题，因此对新程序的适用性有限。这三个函数都迫切需要更加通用化：

+   不要编写`inch_to_cm()`函数，而是编写一个将*任何*英制距离转换为公制的函数，然后创建另一个函数来执行相反的操作。

+   不要编写一个仅加载地名的函数，而是实现一个`load_delimited_text()`函数，该函数适用于任何类型的分隔文本文件，并且不假定特定的列名或分隔符是垂直条字符。

+   不要仅仅将客户名称变为复数形式，而是编写一个更通用的`pluralize()`函数，该函数将为程序中可能需要的所有名称变为复数形式。由于英语的种种变化，您不能仅仅假定所有名称都可以通过在末尾添加*s*来变为复数形式；您需要一个包含人/人们、轴/轴等的例外词典，以便该函数可以处理各种类型的名称。为了使这个函数更加有用，您可以选择接受名称的复数形式，如果它不知道您要变为复数的单位类型的话：

```py
def pluralize(n, singular_name, plural_name=None):
```

尽管这只是三个具体的例子，但您可以看到，通过将您共享的代码泛化，可以使其适用于更广泛的任务。通常，泛化函数所需的工作量很少，但结果将受到使用您创建的代码的人们的极大赞赏。

## 遵循标准约定

虽然你可以按照自己的喜好编写代码，但如果你想与他人分享你的代码，遵循标准的编码约定是有意义的。这样可以使其他人在不必记住你的库特定风格的情况下更容易使用你的代码。

举个实际的例子，考虑以下代码片段：

```py
shapefile = ogr.Open("...")
layer = shapefile.GetLayer(0)
for i in range(layer.GetFeatureCount()):
  feature = layer.GetFeature(i)
  shape = shapely.loads(feature.GetGeometryRef().ExportToWkt())
  if shape.contains(target_zone):
    ...
```

这段代码利用了两个库：Shapely 库，用于执行计算几何，以及 OGR 库，用于读写地理空间数据。Shapely 库遵循使用小写字母命名函数和方法的标准 Python 约定：

```py
shapely.loads(...)
shape.contains(...)
```

虽然这些库的细节相当复杂，但这些函数和方法的命名易于记忆和使用。然而，与之相比，OGR 库将每个函数和方法的第一个字母大写：

```py
ogr.Open(...)
layer.GetFeatureCount()
```

使用这两个库时，你必须不断地记住 OGR 将每个函数和方法的第一个字母大写，而 Shapely 则不会。这使得使用 OGR 比必要更加麻烦，并导致生成的代码中出现相当多的错误，需要进行修复。

如果 OGR 库简单地遵循了与 Shapely 相同的命名约定，所有这些问题都可以避免。

幸运的是，对于 Python 来说，有一份名为**Python 风格指南**（[`www.python.org/dev/peps/pep-0008/`](https://www.python.org/dev/peps/pep-0008/)）的文件，提供了一套清晰的建议，用于格式化和设计你的代码。函数和方法名称使用小写字母的惯例来自于这份指南，大多数 Python 代码也遵循这个指南。从如何命名变量到何时在括号周围放置空格，这份文件中都有描述。

虽然编码约定是个人偏好的问题，你当然不必盲目遵循 Python 风格指南中的指示，但这样做（至少在影响你的代码用户方面）将使其他人更容易使用你的可重用模块和包——就像 OGR 库的例子一样，你不希望用户在想要导入和使用你的代码时不断记住一个不寻常的命名风格。

## 清晰的文档

即使你编写了完美的模块，解决了一系列通用问题，并忠实地遵循了 Python 风格指南，如果没有人知道如何使用它，你的模块也是无用的。不幸的是，作为程序员，我们经常对我们的代码太过了解：我们很清楚我们的代码是如何工作的，所以我们陷入了假设其他人也应该很清楚的陷阱。此外，程序员通常*讨厌*编写文档——我们更愿意编写一千行精心编写的 Python 代码，而不是写一段描述它如何工作的话。因此，我们共享的代码的文档通常是勉强写的，甚至根本不写。

问题是，高质量的可重用模块或包将*始终*包括文档。这份文档将解释模块的功能和工作原理，并包括示例，以便读者可以立即看到如何在他们自己的程序中使用这个模块或包。

对于一个出色文档化的 Python 模块或包的例子，我们无需去看**Python 标准库**（[`docs.python.org/3/library/`](https://docs.python.org/3/library/)）之外的地方。每个模块都有清晰的文档，包括详细的信息和示例，以帮助程序员进行指导。例如，以下是`datetime.timedelta`类的文档的简化版本：

![清晰的文档](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mdl-prog-py/img/B05012_6_02.jpg)

每个模块、类、函数和方法都有清晰的文档，包括示例和详细的注释，以帮助这个模块的用户。

作为可重用模块的开发人员，您不必达到这些高度。Python 标准库是一个庞大的协作努力，没有一个人编写了所有这些文档。但这是您应该追求的文档类型的一个很好的例子：包含大量示例的全面文档。

虽然您可以在文字处理器中创建文档，或者使用类似 Sphinx 系统的复杂文档生成系统来构建 Python 文档，但有两种非常简单的方法可以在最少的麻烦下编写文档：创建 README 文件或使用文档字符串。

`README`文件只是一个文本文件，它与组成您的模块或包的各种源文件一起包含在内。它通常被命名为`README.txt`，它只是一个普通的文本文件。您可以使用用于编辑 Python 源代码的相同编辑器创建此文件。

README 文件可以是尽可能广泛或最小化的。通常有助于包括有关如何安装和使用模块的信息，任何许可问题，一些使用示例以及如果您的模块或包包含来自他人的代码，则包括致谢。

文档字符串是附加到模块或函数的 Python 字符串。这专门用于文档目的，有一个非常特殊的 Python 语法用于创建文档字符串：

```py
""" my_module.py

    This is the documentation for the my_module module.
"""
def my_function():
    """ This is the documentation for the my_function() function.

        As you can see, the documentation can span more than
        one line.
    """
    ...
```

在 Python 中，您可以使用三个引号字符标记跨越 Python 源文件的多行的字符串。这些三引号字符串可以用于各种地方，包括文档字符串。如果一个模块以三引号字符串开头，那么这个字符串将用作整个模块的文档。同样，如果任何函数以三引号字符串开头，那么这个字符串将用作该函数的文档。

### 注意

同样适用于 Python 中的其他定义，例如类、方法等。

文档字符串通常用于描述模块或函数的功能，所需的参数以及返回的信息。还应包括模块或函数的任何值得注意的方面，例如意外的副作用、使用示例等。

文档字符串（和 README 文件）不必非常广泛。您不希望花费数小时来撰写关于模块中只有三个人可能会使用的某个晦涩函数的文档。但是写得很好的文档字符串和 README 文件是出色且易于使用的模块或包的标志。

撰写文档是一种技能；像所有技能一样，通过实践可以变得更好。要创建可以共享的高质量模块和包，您应该养成创建文档字符串和 README 文件的习惯，以及遵循编码约定并尽可能地泛化您的代码，正如我们在本章的前几节中所描述的那样。如果您的目标是从一开始就产生高质量的可重用代码，您会发现这并不难。

# 可重用模块的示例

您不必走得很远才能找到可重用模块的示例；**Python 包索引**（[`pypi.python.org/pypi`](https://pypi.python.org/pypi)）提供了一个庞大的共享模块和包的存储库。您可以按名称或关键字搜索包，也可以按主题、许可证、预期受众、开发状态等浏览存储库。

Python 包索引非常庞大，但也非常有用：所有最成功的包和模块都包含在其中。让我们更仔细地看一些更受欢迎的可重用包。

## requests

`requests`库（[`docs.python-requests.org/en/master/`](http://docs.python-requests.org/en/master/)）是一个 Python 包，它可以轻松地向远程服务器发送 HTTP 请求并处理响应。虽然 Python 标准库中包含的`urllib2`包允许您发出 HTTP 请求，但往往难以使用并以意想不到的方式失败。`requests`包更容易使用和更可靠；因此，它变得非常受欢迎。

以下示例代码显示了`requests`库如何允许您发送复杂的 HTTP 请求并轻松处理响应：

```py
import requests

response = requests.post("http://server.com/api/login",
                         {'username' : username,
                          'password' : password})
if response.status_code == 200: # OK
    user = response.json()
    if user['logged_in']:
        ...
```

`requests`库会自动对要发送到服务器的参数进行编码，优雅地处理超时，并轻松检索 JSON 格式的响应。

`requests`库非常容易安装（在大多数情况下，您可以简单地使用 pip install requests）。它有很好的文档，包括用户指南、社区指南和详细的 API 文档，并且完全符合 Python 样式指南。它还提供了一套非常通用的功能，通过 HTTP 协议处理与外部网站和系统的各种通信。有了这些优点，难怪`requests`是整个 Python 包索引中第三受欢迎的包。

## python-dateutil

`dateutil`包（[`github.com/dateutil/dateutil`](https://github.com/dateutil/dateutil)）扩展了 Python 标准库中包含的`datetime`包，添加了对重复日期、时区、复杂相对日期等的支持。

以下示例代码计算复活节星期五的日期，比我们在上一章中用于*快乐时光*计算的形式要简单得多：

```py
from dateutil.easter import easter
easter_friday = easter(today.year) - datetime.timedelta(days=2)
```

`dateutil`提供了大量示例的优秀文档，使用`pip install python-dateutil`很容易安装，遵循 Python 样式指南，对解决各种与日期和时间相关的挑战非常有用。它是 Python 包索引中另一个成功和受欢迎的包的例子。

## lxml

`lxml`工具包（[`lxml.de`](http://lxml.de)）是一个非常成功的 Python 包的例子，它作为两个现有的 C 库的包装器。正如其写得很好的网站所说，`lxml`简化了读取和写入 XML 和 HTML 格式文档的过程。它是在 Python 标准库中现有库（`ElementTree`）的基础上建模的，但速度更快，功能更多，并且不会以意想不到的方式崩溃。

以下示例代码显示了如何使用`lxml`快速生成 XML 格式数据：

```py
from lxml import etree

movies = etree.Element("movie")
movie = etree.SubElement(movies, "movie")
movie.text = "The Wizard of Oz"
movie.set("year", "1939")

movie = etree.SubElement(movies, "movie")
movie.text = "Mary Poppins"
movie.set("year", "1964")

movie = etree.SubElement(movies, "movie")
movie.text = "Chinatown"
movie.set("year", "1974")

print(etree.tostring(movies, pretty_print=True))
```

这将打印出一个包含三部经典电影信息的 XML 格式文档：

```py
<movie>
 **<movie year="1939">The Wizard of Oz</movie>
 **<movie year="1964">Mary Poppins</movie>
 **<movie year="1974">Chinatown</movie>
</movie>

```

当然，`lxml`可以做的远不止这个简单的示例所展示的。它可以用于解析文档以及以编程方式生成庞大而复杂的 XML 文件。

`lxml`网站包括优秀的文档，包括教程、如何安装包以及完整的 API 参考。对于它解决的特定任务，`lxml`非常吸引人且易于使用。难怪这是 Python 包索引中非常受欢迎的包。

# 设计可重用的包

现在让我们将学到的知识应用到一个有用的 Python 包的设计和实现中。在上一章中，我们讨论了使用 Python 模块封装食谱的概念。每个食谱的一部分是成分的概念，它有三个部分：

+   成分的名称

+   成分所需的数量

+   成分的计量单位

如果我们想要处理成分，我们需要能够正确处理单位。例如，将 1.5 千克加上 750 克不仅仅是加上数字 1.5 和 750——您必须知道如何将这些值从一个单位转换为另一个单位。

在食谱的情况下，有一些相当不寻常的转换需要我们支持。例如，你知道三茶匙的糖等于一汤匙的糖吗？为了处理这些类型的转换，让我们编写一个单位转换库。

我们的单位转换器将需要了解烹饪中使用的所有标准单位。这些包括杯、汤匙、茶匙、克、盎司、磅等。我们的单位转换器将需要一种表示数量的方式，比如 1.5 千克，并且能够将数量从一种单位转换为另一种单位。

除了表示和转换数量，我们希望我们的图书馆能够显示数量，自动使用适当的单位名称的单数或复数形式，例如，**6 杯**，**1 加仑**，**150 克**等。

由于我们正在显示数量，如果我们的图书馆能够解析数量，将会很有帮助。这样，用户就可以输入像`3 汤匙`这样的值，我们的图书馆就会知道用户输入了三汤匙的数量。

我们越想这个图书馆，它似乎越像一个有用的工具。我们是在考虑我们的处理食谱程序时想到的这个，但似乎这可能是一个理想的可重用模块或包的候选者。

根据我们之前看过的指南，让我们考虑如何尽可能地概括我们的图书馆，使其在其他程序和其他程序员中更有用。

与其只考虑在食谱中可能找到的各种数量，不如改变我们的图书馆的范围，以处理*任何*类型的数量。它可以处理重量、长度、面积、体积，甚至可能处理时间、力量、速度等单位。

这样想，我们的图书馆不仅仅是一个单位转换器，而是一个处理**数量**的图书馆。数量是一个数字及其相关的单位，例如，150 毫米，1.5 盎司，或 5 英亩。我们将称之为 Quantities 的图书馆将是一个用于解析、显示和创建数量的工具，以及将数量从一种单位转换为另一种单位。正如你所看到的，我们对图书馆的最初概念现在只是图书馆将能够做的事情之一。

现在让我们更详细地设计我们的 Quantities 图书馆。我们希望我们的图书馆的用户能够很容易地创建一个新的数量。例如：

```py
q = quantities.new(5, "kilograms")
```

我们还希望能够将字符串解析为数量值，就像这样：

```py
q = quantities.parse("3 tbsp")
```

然后我们希望能够以以下方式显示数量：

```py
print(q)
```

我们还希望能够知道一个数量代表的是什么类型的值，例如：

```py
>>> print(quantities.kind(q))
weight

```

这将让我们知道一个数量代表重量、长度或距离等。

我们还可以获取数量的值和单位：

```py
>>> print(quantities.value(q))
3
>>> print(quantities.units(q))
tablespoon

```

我们还需要能够将一个数量转换为不同的单位。例如：

```py
>>> q = quantities.new(2.5, "cups")
>>> print(quantities.convert(q, "liter"))
0.59147059125 liters

```

最后，我们希望能够获得我们的图书馆支持的所有单位种类的列表以及每种单位的个体单位：

```py
>>> for kind in quantities.supported_kinds():
>>>     for unit in quantities.supported_units(kind):
>>>         print(kind, unit)
weight gram
weight kilogram
weight ounce
weight pound
length millimeter
...

```

我们的 Quantities 图书馆还需要支持一个最终功能：*本地化*单位和数量的能力。不幸的是，某些数量的转换值会根据你是在美国还是其他地方而有所不同。例如，在美国，一茶匙的体积约为 4.93 立方厘米，而在世界其他地方，一茶匙被认为有 5 立方厘米的体积。还有命名约定要处理：在美国，米制系统的基本长度单位被称为*米*，而在世界其他地方，同样的单位被拼写为*metre*。我们的单位将不得不处理不同的转换值和不同的命名约定。

为了做到这一点，我们需要支持**区域设置**的概念。当我们的图书馆被初始化时，调用者将指定我们的模块应该在哪个区域下运行：

```py
quantities.init("international")
```

这将影响库使用的转换值和拼写：

鉴于我们 Quantities 库的复杂性，试图把所有这些内容都挤入一个单独的模块是没有意义的。相反，我们将把我们的库分成三个单独的模块：一个`units`模块，定义我们支持的所有不同类型的单位，一个`interface`模块，实现我们包的各种公共函数，以及一个`quantity`模块，封装了数量作为值及其相关单位的概念。

这三个模块将合并为一个名为`quantities`的单个 Python 包。

### 注意

请注意，我们在设计时故意使用术语*库*来指代系统；这确保我们没有通过将其视为单个模块或包来预先设计。现在才清楚我们将要编写一个 Python 包。通常，你认为是模块的东西最终会变成一个包。偶尔也会发生相反的情况。对此要保持灵活。

现在我们对 Quantities 库有了一个很好的设计，知道它将做什么，以及我们想要如何构建它，让我们开始写一些代码。

# 实现可重用的包

### 提示

本节包含大量源代码。请记住，你不必手动输入所有内容；本章的示例代码中提供了`quantities`包的完整副本，可以下载。

首先创建一个名为`quantities`的目录来保存我们的新包。在这个目录中，创建一个名为`quantity.py`的新文件。这个模块将保存我们对数量的实现，即值和其相关单位。

虽然你不需要理解面向对象的编程技术来阅读本书，但这是我们需要使用面向对象编程的地方。这是因为我们希望用户能够直接打印一个数量，而在 Python 中唯一的方法就是使用对象。不过别担心，这段代码非常简单，我们会一步一步来。

在`quantity.py`模块中，输入以下 Python 代码：

```py
class Quantity(object):
    def __init__(self, value, units):
        self.value = value
        self.units = units
```

我们在这里做的是定义一个称为`Quantity`的新对象类型。第二行看起来非常像一个函数定义，只是我们正在定义一种特殊类型的函数，称为**方法**，并给它一个特殊的名称`__init__`。当创建新对象时，这个方法用于初始化新对象。`self`参数指的是正在创建的对象；正如你所看到的，我们的`__init__`函数接受两个额外的参数，命名为`value`和`units`，并将这两个值存储到`self.value`和`self.units`中。

有了我们定义的新`Quantity`对象，我们可以创建新对象并检索它们的值。例如：

```py
q = Quantity(1, "inch")
print(q.value, q.units)
```

第一行使用`Quantity`类创建一个新对象，为`value`参数传递`1`，为`units`参数传递`"inch"`。然后`__init__`方法将这些存储在对象的`value`和`units`属性中。正如你在第二行看到的，当我们需要时很容易检索这些属性。

我们几乎完成了`quantity.py`模块的实现。只剩最后一件事要做：为了能够打印`Quantity`值，我们需要向我们的`Quantity`类添加另一个方法；这个方法将被称为`__str__`，并且在我们需要打印数量时将被使用。为此，请在`quantity.py`模块的末尾添加以下 Python 代码：

```py
    def __str__(self):
        return "{} {}".format(self.value, self.units)
```

确保`def`语句的缩进与之前的`def __init__()`语句相同，这样它就是我们正在创建的类的一部分。这将允许我们做一些如下的事情：

```py
>>> q = Quantity(1, "inch")
>>> print(q)
1 inch

```

Python 的`print()`函数调用特别命名的`__str__`方法来获取要显示的数量的文本。我们的`__str__`方法返回值和单位，用一个空格分隔，这样可以得到一个格式良好的数量摘要。

这完成了我们的`quantity.py`模块。正如您所看到的，使用对象并不像看起来那么困难。

我们的下一个任务是收集关于我们的包将支持的各种单位的存储信息。因为这里有很多信息，我们将把它放入一个单独的模块中，我们将称之为`units.py`。

在您的`quantities`包中创建`units.py`模块，并首先输入以下内容到这个文件中：

```py
UNITS = {}
```

`UNITS`字典将把单位类型映射到该类型定义的单位列表。例如，所有长度单位将放入`UNITS['length']`列表中。

对于每个单位，我们将以字典的形式存储关于该单位的信息，具有以下条目：

| 字典条目 | 描述 |
| --- | --- |
| `name` | 此单位的名称，例如，`inch`。 |
| `abbreviation` | 此单位的官方缩写，例如，`in`。 |
| `plural` | 此单位的复数名称。当有多个此单位时使用的名称，例如，`inches`。 |
| `num_units` | 在这些单位和同类型的其他单位之间进行转换所需的单位数量。例如，如果`centimeter`单位的`num_units`值为`1`，那么`inch`单位的`num_units`值将为`2.54`，因为 1 英寸等于 2.54 厘米。 |

正如我们在前一节中讨论的，我们需要能够本地化我们的各种单位和数量。为此，所有这些字典条目都可以有单个值或将每个语言环境映射到一个值的字典。例如，`liter`单位可以使用以下 Python 字典来定义：

```py
{'name' : {'us'            : "liter",
           'international' : "litre"},
 'plural' : {'us'            : "liters",
             'international' : "litres"},
 'abbreviation' : "l",
 'num_units' : 1000}
```

这允许我们在不同的语言环境中拥有不同的`liter`拼写。其他单位可能会有不同数量的单位或不同的缩写，这取决于所选择的语言环境。

现在我们知道了如何存储各种单位定义，让我们实现`units.py`模块的下一部分。为了避免重复输入大量单位字典，我们将创建一些辅助函数。在您的模块末尾添加以下内容：

```py
def by_locale(value_for_us, value_for_international):
    return {"us"            : value_for_us,
            "international" : value_for_international}
```

此函数将返回一个将`us`和`international`语言环境映射到给定值的字典，使得创建一个特定语言环境的字典条目更容易。

接下来，在您的模块中添加以下函数：

```py
def unit(*args):
    if len(args) == 3:
        abbreviation = args[0]
        name         = args[1]

        if isinstance(name, dict):
            plural = {}
            for key,value in name.items():
                plural[key] = value + "s"
        else:
            plural = name + "s"

        num_units = args[2]
    elif len(args) == 4:
        abbreviation = args[0]
        name         = args[1]
        plural       = args[2]
        num_units    = args[3]
    else:
        raise RuntimeError("Bad arguments to unit(): {}".format(args))

    return {'abbreviation' : abbreviation,
            'name'         : name,
            'plural'       : plural,
            'num_units'    : num_units}
```

这个看起来复杂的函数为单个单位创建了字典条目。它使用特殊的`*args`参数形式来接受可变数量的参数；调用者可以提供缩写、名称和单位数量，或者提供缩写、名称、复数名称和单位数量。如果没有提供复数名称，它将通过在单位的单数名称末尾添加`s`来自动计算。

请注意，这里的逻辑允许名称可能是一个区域特定名称的字典；如果名称是本地化的，那么复数名称也将根据区域逐个地计算。

最后，我们定义一个简单的辅助函数，使一次性定义一个单位列表变得更容易：

```py
def units(kind, *units_to_add):
    if kind not in UNITS:
        UNITS[kind] = []

    for unit in units_to_add:
        UNITS[kind].append(unit)
```

有了所有这些辅助函数，我们很容易将各种单位添加到`UNITS`字典中。在您的模块末尾添加以下代码；这定义了我们的包将支持的各种基于重量的单位：

```py
units("weight",
      unit("g",  "gram",     1),
      unit("kg", "kilogram", 1000))
      unit("oz", "ounce",    28.349523125),
      unit("lb", "pound",    453.59237))
```

接下来，添加一些基于长度的单位：

```py
units("length",
      unit("cm", by_locale("centimeter", "centimetre"), 1),
      unit("m",  by_locale("meter",      "metre",       100),
      unit("in", "inch", "inches", 2.54)
      unit("ft", "foot", "feet", 30.48))
```

正如您所看到的，我们使用`by_locale()`函数基于用户当前的语言环境创建了单位名称和复数名称的不同版本。我们还为`inch`和`foot`单位提供了复数名称，因为这些名称不能通过在名称的单数版本后添加`s`来计算。

现在让我们添加一些基于面积的单位：

```py
units("area",
      unit("sq m", by_locale("square meter", "square metre"), 1),
      unit("ha",   "hectare", 10000),
      unit("a",    "acre",    4046.8564224))
```

最后，我们将定义一些基于体积的单位：

```py
units("volume",
      unit("l",  by_locale("liter", "litre"), 1000),
      unit("ml", by_locale("milliliter", "millilitre"), 1),
      unit("c",  "cup", localize(236.5882365, 250)))
```

对于`"cup"`单位，我们本地化的是单位的数量，而不是名称。这是因为在美国，一杯被认为是`236.588`毫升，而在世界其他地方，一杯被测量为 250 毫升。

### 注意

为了保持代码清单的合理大小，这些单位列表已经被缩写。本章示例代码中包含的`quantities`包版本具有更全面的单位列表。

这完成了我们的单位定义。为了使我们的代码能够使用这些各种单位，我们将在`units.py`模块的末尾添加两个额外的函数。首先是一个函数，用于选择单位字典中值的适当本地化版本：

```py
def localize(value, locale):
    if isinstance(value, dict):
        return value.get(locale)
    else:
        return value
```

如您所见，我们检查`value`是否为字典；如果是，则返回提供的`locale`的字典中的条目。否则，直接返回`value`。每当我们需要从单位的字典中检索名称、复数名称、缩写或值时，我们将使用此函数。

我们接下来需要的第二个函数是一个函数，用于搜索存储在`UNITS`全局变量中的各种单位。我们希望能够根据其单数或复数名称或缩写找到单位，允许拼写特定于当前区域。为此，在`units.py`模块的末尾添加以下代码：

```py
def find_unit(s, locale):
    s = s.lower()
    for kind in UNITS.keys():
        for unit in UNITS[kind]:
            if (s == localize(unit['abbreviation'],
                              locale).lower() or
                s == localize(unit['name'],
                              locale).lower() or
                s == localize(unit['plural'],
                              locale).lower()):
                # Success!
                return (kind, unit)

    return (None, None) # Not found.
```

请注意，我们在检查之前使用`s.lower()`将字符串转换为小写。这确保我们可以找到`inch`单位，例如，即使用户将其拼写为`Inch`或`INCH`。完成后，我们的`find_units()`函数将返回找到的单位的种类和单位字典，或者（`None，None`）如果找不到单位。

这完成了`units.py`模块。现在让我们创建`interface.py`模块，它将保存我们`quantities`包的公共接口。

### 提示

我们可以直接将所有这些代码放入包初始化文件`__init__.py`中，但这可能会有点令人困惑，因为许多程序员不希望在`__init__.py`文件中找到代码。相反，我们将在`interface.py`模块中定义所有公共函数，并将该模块的内容导入`__init__.py`中。

创建`interface.py`模块，将其放置到`units.py`和`quantities.py`旁边的`quantities`包目录中。然后，在该模块的顶部添加以下`import`语句：

```py
from .units import UNITS, localize, find_unit
from .quantity import Quantity
```

如您所见，我们使用相对导入语句从`units.py`模块加载`UNITS`全局变量以及`localize()`和`find_unit()`函数。然后，我们使用另一个相对导入来加载我们在`quantity.py`模块中定义的`Quantity`类。这使得这些重要的函数、类和变量可供我们的代码使用。

现在我们需要实现本章前面识别出的各种函数。我们将从`init()`开始，该函数初始化整个`quantities`包。将以下内容添加到您的`interface.py`模块的末尾：

```py
def init(locale):
    global _locale
    _locale = locale
```

调用者将提供区域的名称（应为包含`us`或`international`的字符串，因为这是我们支持的两个区域），我们将其存储到名为`_locale`的私有全局变量中。

我们要实现的下一个函数是`new()`。这允许用户通过提供值和所需单位的名称来定义新的数量。我们将使用`find_unit()`函数来确保单位存在，然后创建并返回一个新的带有提供的值和单位的`Quantity`对象：

```py
def new(value, units):
    global _locale
    kind,unit = find_unit(units, _locale)
    if kind == None:
        raise ValueError("Unknown unit: {}".format(units))

    return Quantity(value, localize(unit['name'], _locale))
```

因为单位的名称可能会根据区域而变化，我们使用`_locale`私有全局变量来帮助找到具有提供的名称、复数名称或缩写的单位。找到单位后，我们使用该单位的官方名称创建一个新的`Quantity`对象，然后将其返回给调用者。

除了通过提供值和单位来创建一个新的数量之外，我们还需要实现一个`parse()`函数，将一个字符串转换为`Quantity`对象。现在让我们来做这个：

```py
def parse(s):
    global _locale

    sValue,sUnits = s.split(" ", maxsplit=1)
    value = float(sValue)

    kind,unit = find_unit(sUnits, _locale)
    if kind == None:
        raise ValueError("Unknown unit: {}".format(sUnits))

    return Quantity(value, localize(unit['name'], _locale))
```

我们在第一个空格处拆分字符串，将第一部分转换为浮点数，并搜索一个名称或缩写等于字符串第二部分的单位。

接下来，我们需要编写一些函数来返回有关数量的信息。让我们通过在您的`interface.py`模块的末尾添加以下代码来实现这些函数：

```py
def kind(q):
    global _locale
    kind,unit = find_unit(q.units, _locale)
    return kind

def value(q):
    return q.value

def units(q):
    return q.units
```

这些函数允许我们的包的用户识别与给定数量相关的单位种类（例如长度、重量或体积），并检索数量的值和单位。

### 注意

请注意，用户也可以通过直接访问`Quantity`对象内的属性来检索这两个值，例如`print(q.value)`。我们无法阻止用户这样做，但是因为我们没有将其实现为面向对象的包，所以我们不想鼓励这样做。

我们已经快完成了。我们的下一个函数将把一个单位转换为另一个单位，如果转换不可能则返回`ValueError`。以下是执行此操作所需的代码：

```py
def convert(q, units):
    global _locale

    src_kind,src_units = find_unit(q.units, _locale)
    dst_kind,dst_units = find_unit(units, _locale)

    if src_kind == None:
        raise ValueError("Unknown units: {}".format(q.units))
    if dst_kind == None:
        raise ValueError("Unknown units: {}".format(units))

    if src_kind != dst_kind:
        raise ValueError(
                "It's impossible to convert {} into {}!".format(
                      localize(src_units['plural'], _locale),
                      localize(dst_units['plural'], _locale)))

    num_units = (q.value * src_units['num_units'] /
                 dst_units['num_units'])
    return Quantity(num_units, localize(dst_units['name'],
                                        _locale))
```

我们需要实现的最后两个函数返回我们支持的不同单位种类的列表和给定种类的各个单位的列表。以下是我们`interface.py`模块的最后两个函数：

```py
def supported_kinds():
    return list(UNITS.keys())

def supported_units(kind):
    global _locale

    units = []
    for unit in UNITS.get(kind, []):
        units.append(localize(unit['name'], _locale))
    return units
```

现在我们已经完成了`interface.py`模块的实现，只剩下最后一件事要做：为我们的`quantities`包创建包初始化文件`__init__.py`，并将以下内容输入到此文件中：

```py
from .interface import *
```

这使得我们在`interface.py`模块中定义的所有函数都可以供我们包的用户使用。

# 测试我们可重用的包

现在我们已经编写了代码（或者下载了代码），让我们来看看这个包是如何工作的。在终端窗口中，将当前目录设置为包含您的`quantities`包目录的文件夹，并键入`python`以启动 Python 解释器。然后，输入以下内容：

```py
>>> import quantities

```

如果您在输入源代码时没有犯任何错误，解释器应该会在没有任何错误的情况下返回。如果您有任何拼写错误，您需要在继续之前先修复它们。

接下来，我们必须通过提供我们想要使用的区域设置来初始化我们的`quantities`包：

```py
>>> quantities.init("international")

```

如果你在美国，可以随意将值`international`替换为`us`，这样你就可以获得本地化的拼写和单位。

让我们创建一个简单的数量，然后要求 Python 解释器显示它：

```py
>>> q = quantities.new(24, "km")
>>>> print(q)
24 kilometre

```

正如你所看到的，国际拼写单词`kilometer`会自动使用。

让我们尝试将这个单位转换成英寸：

```py
>>> print(quantities.convert(q, "inch"))
944881.8897637795 inch

```

还有其他函数我们还没有测试，但我们已经可以看到我们的`quantities`包解决了一个非常普遍的问题，符合 Python 风格指南，并且易于使用。它还不是一个完全理想的可重用模块，但已经很接近了。以下是我们可以做的一些事情来改进它：

+   重新构建我们的包以更符合面向对象的方式。例如，用户可以简单地说`q.convert("inch")`，而不是调用`quantities.convert(q, "inch")`。

+   改进`__str__()`函数的实现，以便在值大于 1 时将单位名称显示为复数。此外，更改代码以避免浮点舍入问题，这可能会在打印出某些数量值时产生奇怪的结果。

+   添加函数（或方法）来添加、减去、乘以和除以数量。

+   为我们的包源代码添加文档字符串，然后使用诸如**Sphinx**（[`www.sphinx-doc.org`](http://www.sphinx-doc.org)）之类的工具将文档字符串转换为我们包的 API 文档。

+   将`quantities`包的源代码上传到**GitHub**（[`github.com`](https://github.com)）以便更容易获取。

+   创建一个网站（可能是作为 GitHub 存储库中的简单 README 文件），以便人们可以了解更多关于这个包的信息。

+   将包提交到 PyPI，以便人们可以找到它。

如果你愿意，可以随意扩展`quantities`包并提交它；这只是本书的一个例子，但它确实有潜力成为一个通用（和流行的）可重用的 Python 包。

# 摘要

在本章中，我们讨论了可重用模块或包的概念。我们看到可重用的包和模块如何用于与其他人共享代码。我们了解到，可重用的模块或包需要作为一个独立的单元进行操作，最好使用相对导入，并应注意它可能具有的任何外部依赖关系。理想情况下，可重用的包或模块还将解决一个通用问题而不是特定问题，遵循标准的 Python 编码约定，并具有良好的文档。然后，我们看了一些好的可重用模块的例子，然后编写了我们自己的模块。

在下一章中，我们将看一些更高级的内容，涉及在 Python 中使用模块和包的工作。
