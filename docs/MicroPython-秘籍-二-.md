# MicroPython 秘籍（二）

> 原文：[`zh.annas-archive.org/md5/EE140280D367F2C84B38C2F3034D057C`](https://zh.annas-archive.org/md5/EE140280D367F2C84B38C2F3034D057C)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：读取传感器数据

本章将介绍您可以使用的方法，从 Adafruit Circuit Playground Express 上的多个传感器读取传感器数据。我们将涵盖温度和光传感器，以及运动传感器，您还将学习如何使板对传感器事件做出反应，例如板被摇动或光照水平发生变化。访问这些丰富的传感器数据可以使各种各样的项目成为可能。例如，您可以制作一个项目，如果检测到的温度超过了某个水平，就会发出警报声。通过学习如何读取和处理这些传感器数据，您可以使各种嵌入式项目成为现实。

在本章中，我们将涵盖以下主题：

+   Circuit Playground Express 传感器

+   读取温度读数

+   从光传感器中读取亮度级别

+   创建光度计

+   从运动传感器读取数据

+   检测单击或双击

+   检测摇晃

+   摇晃时发出哔哔声

# Circuit Playground Express 传感器

本章将使用三种不同的硬件传感器来从环境中获取传感器读数。以下照片是一个热敏电阻的照片，显示了温度传感器的位置：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mcpy-cb/img/d8b00dc3-8ddc-4693-b358-5fdd6aaffb50.png)

由 adafruit.com 提供

以下照片显示了设备上可用的光传感器：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mcpy-cb/img/67cbbbc0-96ae-4b86-b361-6a9c5aec0e37.png)

由 adafruit.com 提供

以下照片显示了加速度计，它可以用于检测运动，以及在板上敲击和双击：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mcpy-cb/img/6c2e0897-dcd6-4176-b9e7-f4a79f0ee32c.png)

由 adafruit.com 提供

现在让我们来检查我们的第一个教程。

# 读取温度读数

在本教程中，我们将学习如何创建一个循环，重复地从温度传感器中读取当前温度并将其打印出来。这将让我们对传感器进行实验，并查看它对温度变化的反应。本教程中的方法可以在您需要将温度读数纳入项目中时使用。

# 准备工作

你需要访问 Circuit Playground Express 上的 REPL 来运行本教程中提供的代码。

# 如何做...

按照以下步骤学习如何读取温度读数：

1.  在 REPL 中运行以下代码。输出显示室温约为 25°C：

```py
>>> from adafruit_circuitplayground.express import cpx
>>> import time
>>> cpx.temperature
25.7499
```

1.  现在，通过按压温度传感器来增加温度传感器读数，使用您的体温，同时在进行下一次读数时：

```py
>>> cpx.temperature
30.031
```

1.  温度应该已经升高了几度。如果运行以下代码，应返回一个浮点数：

```py
>>> start = time.monotonic()
>>> start
27.409
```

1.  在执行以下代码行之前等待几秒钟。它将计算自您将值分配给 start 变量以来的秒数：

```py
>>> time.monotonic() - start
11.37
```

1.  如果运行以下代码，应该会显示所有本地变量及其值的列表作为字典：

```py
>>> locals()
{'time': <module 'time'>, 'start': 60.659, '__name__': '__main__'}
>>> 
```

1.  以下代码应放入`main.py`文件中，当执行时，将重复打印当前经过的时间和当前温度读数：

```py
from adafruit_circuitplayground.express import cpx
import time

start = time.monotonic()
while True:
    elapsed = time.monotonic() - start
    temp = cpx.temperature
    print('{elapsed:.2f}\t{temp}'.format(**locals()))
    time.sleep(0.1)
```

# 它是如何工作的...

代码的前几行导入了 Circuit Playground Express 库和`time`模块。`cpx`对象公开了一个名为`temperature`的属性-每当访问该值时，该属性将以浮点数的形式返回热敏电阻的当前温度读数。

这个值是以摄氏温度标度表示的。记录开始时间，以便为每个温度读数计算经过的时间。然后脚本进入一个无限循环，计算经过的时间并获取每个循环迭代的温度读数。

经过的时间和温度以制表符分隔打印。在开始下一个循环迭代之前，会应用 0.1 秒的延迟。

# 还有更多...

该设备上的温度传感器是**负温度系数**（NTC）热敏电阻。该元件是一个随温度变化而改变电阻的电阻器。通过测量其电阻，我们可以得到温度读数。在 NTC 热敏电阻的情况下，电阻会随着温度的升高而减小。

在这个示例中，时间和温度数据以制表符分隔的格式输出。这种格式使得将数据移入其他应用程序进行分析变得很容易。以下图表是使用从本示例的主脚本输出的数据生成的：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mcpy-cb/img/8b264f44-a891-418e-9198-1b86fc7ff2a8.png)

脚本运行了 60 秒后，从 REPL 中获取输出，并将其复制粘贴到我们的电子表格程序 LibreOffice Calc 中。制表符默认将时间和温度数据分隔到各自的列中。然后，使用这个数据表，生成了*x*-*y*散点图。

像这样绘制传感器数据，可以很容易地可视化温度读数随时间的变化。在这个特定的数据集中（在脚本执行开始时），温度传感器读取环境室温约为 26°C。在脚本执行约 10 秒后，传感器被触摸加热到接近 30°C。

在前面的图表中可以看到温度的急剧上升，发生在 10 秒的标记处。放开传感器后，它开始缓慢冷却，直到在 40 秒的时间内冷却到 27°C 以下。

# 另请参阅

以下是关于本示例的一些参考资料：

+   温度属性的文档可以在[`circuitpython.readthedocs.io/projects/circuitplayground/en/latest/api.html#adafruit_circuitplayground.express.Express.temperature`](https://circuitpython.readthedocs.io/projects/circuitplayground/en/latest/api.html#adafruit_circuitplayground.express.Express.temperature)找到。

+   CircuitPython `time`模块的文档可以在[`circuitpython.readthedocs.io/en/3.x/shared-bindings/time/__init__.html`](https://circuitpython.readthedocs.io/en/3.x/shared-bindings/time/__init__.html)找到。

+   内置`locals`函数的文档可以在[`docs.python.org/3/library/functions.html#locals`](https://docs.python.org/3/library/functions.html#locals)找到。

+   关于热敏电阻工作原理的详细信息可以在[`www.omega.com/prodinfo/thermistor.html`](https://www.omega.com/prodinfo/thermistor.html)找到。

+   LibreOffice Calc 应用程序的项目页面和应用程序下载可以在[`www.libreoffice.org/`](https://www.libreoffice.org/)找到。

# 从光传感器读取亮度级别

在这个示例中，我们将学习如何创建一个循环，以重复从光传感器读取当前的光亮度。从传感器获取实时读数可以是一种有趣的方式，可以用不同的光源来测试传感器的灵敏度。

最终，本示例中的技术可以帮助您构建与环境交互的项目，取决于光的存在或缺失。

# 准备工作

您需要访问 Circuit Playground Express 上的 REPL 来运行本示例中提供的代码。

# 操作步骤...

按照以下步骤学习如何从光传感器读取亮度级别：

1.  在 REPL 中执行以下代码块：

```py
>>> from adafruit_circuitplayground.express import cpx
>>> cpx.light
5
```

1.  输出的数字是房间的光照水平。在正常光照条件下，这个数字应该很低。

1.  现在，在运行以下代码块时，用手电筒照射光传感器：

```py
>>> cpx.light
308
```

1.  您应该看到值飙升到一个更高的值。以下代码应该放入`main.py`文件中，并且在执行时，将重复打印从光传感器读取的当前光照水平：

```py
from adafruit_circuitplayground.express import cpx
import time

while True:
    print(cpx.light)
    time.sleep(0.1)
```

# 工作原理...

首先的代码行导入了 Circuit Playground Express 库和`time`模块。`cpx`对象公开了一个名为`light`的属性。这个属性将返回来自光传感器的当前光亮度读数。这个值使用勒克斯单位表示，这是一个用于测量照度的单位。

在这个脚本中，运行一个无限循环，打印当前的光亮度，然后在下一次迭代开始之前休眠 0.1 秒。

# 还有更多...

一个方便的方法来尝试光传感器是使用大多数智能手机上的手电筒。这个手电筒足够明亮，可以在 Circuit Playground Express 上创建光读数的显著差异。在运行本教程中的主要脚本时，观察当您将手电筒靠近或远离传感器时数值的变化。

该设备上的光传感器是光电晶体。这种设备是一种晶体管，当暴露在不同的光亮度下时，会导致电流流向其电路的差异。这些电气变化可以被读取，然后计算光亮度。

# 另请参阅

以下是关于这个教程的一些参考资料：

+   有关`light`属性的文档可以在[`circuitpython.readthedocs.io/projects/circuitplayground/en/latest/api.html#adafruit_circuitplayground.express.Express.light`](https://circuitpython.readthedocs.io/projects/circuitplayground/en/latest/api.html#adafruit_circuitplayground.express.Express.light)找到。

+   有关光电晶体工作原理的更多细节可以在[`www.elprocus.com/phototransistor-basics-circuit-diagram-advantages-applications/`](https://www.elprocus.com/phototransistor-basics-circuit-diagram-advantages-applications/)找到。

# 创建一个光度计

在这个教程中，我们将使用 10 个 NeoPixels 创建一个环，显示当前的光亮度。当光亮度增加和减少时，环会变得越来越小和越来越大。这个教程将向您展示一种可以使您的项目与光互动的方法。它还将展示将像素环转换为 10 级刻度的通用技术，您可以在各种项目中使用。

# 准备工作

您将需要访问 Circuit Playground Express 上的 REPL 来运行本教程中提供的代码。

# 如何做...

按照以下步骤学习如何创建光度计：

1.  使用 REPL 来运行以下代码行：

```py
>>> from adafruit_circuitplayground.express import cpx
>>> import time
>>> 
>>> BLACK = 0x000000
>>> BLUE = 0x0000FF
>>> MAX_LUX = 330
>>> cpx.pixels.brightness = 0.10
>>> 
>>> def gauge(level):
...     cpx.pixels[0:level] = [BLUE] * level
...     
...     
... 
>>> gauge(2)
```

1.  此时，您应该看到前两个像素变成蓝色。运行以下代码行，看到前五个像素变成蓝色：

```py
>>> gauge(5)
```

1.  以下代码应该放入`main.py`文件中，当执行时，它将创建一个光度计，随着光线变亮和变暗，它会变得越来越大和越来越小。

```py
from adafruit_circuitplayground.express import cpx
import time

BLACK = 0x000000
BLUE = 0x0000FF
MAX_LUX = 330
cpx.pixels.brightness = 0.10

def gauge(level):
    cpx.pixels[0:level] = [BLUE] * level

last = 0
while True:
    level = int((cpx.light / MAX_LUX) * 10)
    if level != last:
        cpx.pixels.fill(BLACK)
        gauge(level)
        last = level
    time.sleep(0.05)
```

# 它是如何工作的...

首先的代码行导入了 Circuit Playground Express 库和`time`模块。为蓝色和黑色定义了颜色代码。然后将亮度设置为舒适的水平。然后定义了`gauge`函数。这个函数接收一个整数参数，其值应在 0 到 10 之间。这个值将用于确定在像素环中有多少像素会变成蓝色。这个函数创建了一个类似于经典刻度表的可视显示，根据数值的级别显示一个较小或较大的环。

然后，初始化了`last`变量。这个变量用于跟踪刻度级别自上次循环以来是否发生了变化。这个额外的步骤是为了防止像素因不必要地在每个循环中关闭和打开而闪烁。刻度级别是通过获取当前光亮度并将其除以其最大可能值来计算的，这在这块板上恰好是 330。

然后将该值乘以 10，这是仪表中的级数。如果仪表级别发生了变化，所有像素将被关闭，然后显示正确的仪表级别。在每次无限循环的迭代过程中执行此过程，每个循环之间延迟 50 毫秒，以在与光传感器交互时产生响应的感觉。

# 还有更多...

在这个教程中，显示仪表的功能被故意保留在自己的函数中，以鼓励可重用性。它可以在其他项目中使用，或者保留在自己的模块中，可以在需要使用板上的像素显示信息作为仪表时导入并使用。

此教程的另一个方面是为了解决当您不必要地重复打开和关闭像素时出现的光闪烁问题而必须进行的额外工作。当您一次改变许多像素的状态时，如果您的实现不小心，可能会出现闪烁问题。这在功能上并不是一个主要问题；更多的是在人们使用光度计时创造更愉悦的视觉体验。

# 另请参阅

以下是有关此教程的一些参考资料：

+   可以在[`learn.adafruit.com/adafruit-circuit-playground-express/playground-sound-meter`](https://learn.adafruit.com/adafruit-circuit-playground-express/playground-sound-meter)找到使用 Circuit Playground Express 像素创建声音计的项目。

+   有关光度计及其用途的更多详细信息，请访问[`shuttermuse.com/glossary/light-meter/`](https://shuttermuse.com/glossary/light-meter/)。

# 从运动传感器读取数据

在这个教程中，我们将创建一个循环，不断从加速度计中读取数据，并打印*x*、*y*和*z*轴的数据。打印输出将帮助我们实验传感器对摇动板或以不同方向倾斜的反应。一旦您了解了传感器的工作原理，就可以开始将其纳入项目中，使板对倾斜或加速做出反应。

# 准备工作

您需要访问 Circuit Playground Express 上的 REPL 来运行此教程中提供的代码。

# 如何做...

按照以下步骤学习如何从运动传感器中读取数据：

1.  在将板放在水平表面并使按钮朝上的情况下，在 REPL 中运行以下代码行：

```py
>>> from adafruit_circuitplayground.express import cpx
>>> cpx.acceleration.z
9.46126
```

1.  在将板放置并使按钮朝下的情况下运行以下代码块：

```py
>>> cpx.acceleration.z
-9.30804
```

1.  以下代码应放入`main.py`文件中，并在执行时将不断打印加速度计的当前*x*、*y*和*z*轴数据：

```py
from adafruit_circuitplayground.express import cpx
import time

while True:
    x, y, z = cpx.acceleration
    print('x: {x:.2f} y: {y:.2f} z: {z:.2f}'.format(**locals()))
    time.sleep(0.1)
```

# 工作原理...

第一行代码导入了 Circuit Playground Express 库和`time`模块。启动了一个无限循环，每次循环都会从加速度计中获取读数。读数被解压缩为*x*、*y*和*z*变量。然后，在脚本进入休眠 0.1 秒之前，打印出每个轴的值，并开始下一次迭代。

# 还有更多...

在运行此脚本时，尝试以不同方向倾斜板。该传感器非常敏感，可以为您提供与板倾斜相关的相当准确的读数。除了检测板的方向外，它还可以用于检测三个轴上的加速度。在运行脚本的同时，还可以以不同方向摇动板，您应该看到与加速度相关的读数上升。根据您摇动板的方向，不同的轴应该相应地做出反应。

# 另请参阅

以下是有关此教程的一些参考资料：

+   有关`acceleration`属性的文档，请访问[`circuitpython.readthedocs.io/projects/circuitplayground/en/latest/api.html#adafruit_circuitplayground.express.Express.acceleration`](https://circuitpython.readthedocs.io/projects/circuitplayground/en/latest/api.html#adafruit_circuitplayground.express.Express.acceleration)。

+   有关 Circuit Playground Express 附带的加速度计的更多详细信息，请访问[`learn.adafruit.com/circuit-playground-lesson-number-0/accelerometer`](https://learn.adafruit.com/circuit-playground-lesson-number-0/accelerometer)。

# 检测单次或双次轻敲

在本教程中，我们将学习如何配置板以检测单次或双次轻敲。将使用来自加速度计的传感器数据来检测这些轻敲事件。本教程向您展示如何创建可以对人们敲击板做出反应的应用程序。

# 准备工作

您将需要访问 Circuit Playground Express 上的 REPL，以运行本教程中提供的代码。

# 如何做…

按照以下步骤学习如何检测单次或双次轻敲：

1.  在 REPL 中执行以下代码块：

```py
>>> from adafruit_circuitplayground.express import cpx
>>> cpx.detect_taps = 1
>>> cpx.tapped
False
```

1.  轻敲板一次，然后运行以下代码块。您应该会得到第一个值为`True`，表示检测到了轻敲，然后在下一次检查时得到一个`False`值，这表示自上次检查以来没有检测到新的轻敲：

```py
>>> cpx.tapped
True
>>> cpx.tapped
False
```

1.  以下代码应放入`main.py`文件中，当执行时，将不断打印自上次检查以来是否检测到了轻敲：

```py
from adafruit_circuitplayground.express import cpx
import time

cpx.detect_taps = 1
while True:
    print('tap detected:', cpx.tapped)
    time.sleep(0.1)
```

# 工作原理…

首先导入 Circuit Playground Express 库和`time`模块。将敲击检测算法配置为通过将`detect_taps`设置为`1`来检测单次轻敲。

开始一个无限循环，每次循环将检索`tapped`属性的值。此属性仅在自上次检查以来加速度计检测到单次轻敲时才返回`True`。然后调用`sleep`函数，使其在开始下一次迭代之前延迟 0.1 秒。

# 还有…

通过将`detect_taps`设置为`2`来修改脚本。再次运行它，尝试在板上执行一些单次轻敲。它不应该注册任何内容。

现在尝试执行一些双次轻敲。您应该会看到它们被检测到。尝试改变您用于轻敲板的力量的大小，看看在检测到轻敲之前需要什么级别的力量。

# 另请参阅

以下是有关本教程的一些参考资料：

+   有关`detect_taps`属性的文档，请访问[`circuitpython.readthedocs.io/projects/circuitplayground/en/latest/api.html#adafruit_circuitplayground.express.Express.detect_taps`](https://circuitpython.readthedocs.io/projects/circuitplayground/en/latest/api.html#adafruit_circuitplayground.express.Express.detect_taps)。

+   有关`tapped`属性的文档，请访问[`circuitpython.readthedocs.io/projects/circuitplayground/en/latest/api.html#adafruit_circuitplayground.express.Express.tapped`](https://circuitpython.readthedocs.io/projects/circuitplayground/en/latest/api.html#adafruit_circuitplayground.express.Express.tapped)。

+   有关板的轻敲检测功能的更多详细信息，请访问[`learn.adafruit.com/circuitpython-made-easy-on-circuit-playground-express/tap`](https://learn.adafruit.com/circuitpython-made-easy-on-circuit-playground-express/tap)。

# 检测摇晃

在本教程中，我们将学习如何轮询`shake`方法并在板被摇晃时打印它。创建可以响应设备被摇晃的项目可能非常有趣。还可以配置板，以便您可以指定在注册为摇晃之前需要轻或重摇晃。这可以开辟新的创造性方式，使人们与您的设备互动。

# 准备工作

您将需要访问 Circuit Playground Express 上的 REPL，以运行本教程中提供的代码。

# 如何做…

按照以下步骤学习如何检测摇晃：

1.  使用 REPL 运行以下代码行：

```py
>>> from adafruit_circuitplayground.express import cpx
>>> cpx.shake(20)
False
```

1.  在运行以下代码块时，反复摇晃板子：

```py
>>> cpx.shake(20)
True
```

1.  以下代码应放入`main.py`文件中，执行时，将不断打印板子当前是否在摇晃：

```py
from adafruit_circuitplayground.express import cpx
import time

while True:
    print('shake detected:', cpx.shake())
    time.sleep(0.1)
```

# 工作原理...

首先导入 Circuit Playground Express 库和`time`模块。启动一个无限循环，每次循环都会打印`shake`方法的结果。该方法将根据板子当前是否在摇晃而返回`True`或`False`。然后调用`sleep`函数，使下一次迭代之前延迟 0.1 秒。

# 还有更多...

修改脚本，并将`shake`函数的值作为第一个参数设置为`20`。现在，运行脚本并尝试摇晃它。您会发现需要更少的力量才能使板子注册摇晃事件。第一个参数`shake_threshold`的默认值为`30`，数值越低，板子对检测摇晃的敏感度就越高。不要将值设置为`10`或更低，否则它会变得过于敏感，并不断地认为它已经检测到了摇晃。

# 另请参阅

有关此方案的参考资料，请参阅：

+   有关`shake`方法的文档可以在[`circuitpython.readthedocs.io/projects/circuitplayground/en/latest/api.html#adafruit_circuitplayground.express.Express.shake`](https://circuitpython.readthedocs.io/projects/circuitplayground/en/latest/api.html#adafruit_circuitplayground.express.Express.shake)找到。

+   有关使用`shake`方法的示例，请参阅[`learn.adafruit.com/circuitpython-made-easy-on-circuit-playground-express/shake`](https://learn.adafruit.com/circuitpython-made-easy-on-circuit-playground-express/shake)。

# 摇晃时发出哔哔声

在这个方案中，我们将学习如何使板子在每次摇晃时发出哔哔声。这是一种有趣的方式，让板子对运动做出响应。相同的方法也可以用来使像素对摇晃做出响应，而不仅仅是发出哔哔声。

# 准备工作

您需要访问 Circuit Playground Express 上的 REPL，以运行本方案中提供的代码。

# 如何做...

按照以下步骤学习如何使板子在每次摇晃时发出哔哔声：

1.  在 REPL 中运行以下代码行；您应该听到一声哔哔声：

```py
>>> from adafruit_circuitplayground.express import cpx
>>> cpx.play_tone(900, 0.2)
```

1.  以下代码应放入`main.py`文件中，执行时，每次摇晃板子都会发出哔哔声：

```py
from adafruit_circuitplayground.express import cpx
import time

while True:
    if cpx.shake(20):
        cpx.play_tone(900, 0.2)
    time.sleep(0.1)
```

# 工作原理...

首先导入 Circuit Playground Express 库和`time`模块。启动一个无限循环，检查板子当前是否在摇晃。如果检测到摇晃事件，则会播放一个持续 0.2 秒的短暂哔哔声。之后，检查板子是否休眠 0.1 秒，然后再次开始该过程。

# 还有更多...

您可以将滑动开关纳入此方案中，以便人们可以根据滑动开关的位置选择高或低的摇晃阈值。这样，滑动开关可以用来使检测摇晃变得容易或困难。您可以创建一个游戏，其中每次摇晃都会增加一个计数器并播放一声哔哔声。

当计数器达到 10 时，您可以播放一段胜利的旋律。然后，谁先达到 10 次摇晃就赢了。使用摇晃而不是按按钮来与设备交互，可以是一种有趣的方式来改变人们与您的项目互动的方式。

# 另请参阅

有关此方案的参考资料，请参阅：

+   有关加速计工作原理的指南可以在[`www.dimensionengineering.com/info/accelerometers`](https://www.dimensionengineering.com/info/accelerometers)找到。

+   有关用于与板载加速计交互的 Python 库的文档可以在[`circuitpython.readthedocs.io/projects/lis3dh/en/latest/api.html`](https://circuitpython.readthedocs.io/projects/lis3dh/en/latest/api.html)找到。


# 第六章：按钮砸游戏

在本章中，我们将创建一个名为按钮砸的双人游戏，您可以直接在 Circuit Playground Express 上玩，无需计算机。每个玩家必须尽快按下他们的按钮。每次按下按钮都会将该玩家的分数增加一分。通过 NeoPixels 可以直观地显示玩家当前的分数。首先达到 20 分的玩家将赢得游戏。

为了创建这个游戏，我们将通过 NeoPixels 结合按钮输入和灯光输出，并通过内置扬声器进行音频输出。本章包含许多配方，每个配方展示游戏的不同部分，我们将所有这些部分组合在最后一个配方中，以制作完整的游戏。

在本章中，我们将涵盖以下主题：

+   创建一个类来检测按钮状态变化

+   创建自己的 Python 模块

+   将按钮交互添加到事件循环中

+   创建一个生成器来获取像素颜色

+   使用 ScoreBoard 类显示分数

+   使用 ScoreBoard 类检测获胜者

+   将 ScoreBoard 类添加到事件循环中

# 技术要求

本章的代码文件可以在 GitHub 存储库的`Chapter06`文件夹中找到，网址为[`github.com/PacktPublishing/MicroPython-Cookbook`](https://github.com/PacktPublishing/MicroPython-Cookbook)。

本章的许多配方需要将三个音频文件传输到 Circuit Playground Express 板上。这些文件分别为`start.wav`、`win1.wav`和`win2.wav`。它们都可以从 GitHub 存储库的`Chapter06`文件夹中下载。它们应该保存在与您的`main.py`文件的顶级文件夹中。

本章中的许多配方都使用了 Circuit Playground Express 库，通常会在脚本的第一行导入，代码的下一行是：

```py
from adafruit_circuitplayground.express import cpx
```

这个库将帮助我们与板子上的按钮、像素和扬声器进行交互。

# Circuit Playground Express 电源

本章将介绍的游戏可以直接在 Circuit Playground Express 上运行，无需连接计算机。这是一个很好的机会，介绍您在这种类型的板子上使项目便携的选项。该板可以从多种不同的便携式电源接收电源。

我们将探讨解决便携式电源问题的两种不同方法。每种方法都使用板子上的不同连接器。我们将首先看一下 Micro B USB 连接器，它出现在以下图片中：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mcpy-cb/img/f18560bf-0456-41b2-91fc-66d55b9e8615.png)

由 adafruit.com 提供

这个连接器可以用来将板子连接到计算机进行供电，并将您的代码和音频文件传输到板子上。一种方法是通过 USB 将便携式移动电源连接到板子上。以下照片显示了板子由其中一个移动电源供电：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mcpy-cb/img/d1980cd1-2afe-44a9-ae6a-77e12bf84353.png)

这种方法的好处在于，这些移动电源有各种不同的尺寸和容量，因此您有很多选择，可以选择最符合您需求的移动电源。它们是可充电的，可重复使用，并且可以很容易地在大多数电子零售商处购买。

我们将看一下的第二个连接器是 JST 电池输入，它出现在下一张照片中：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mcpy-cb/img/1718da72-4ee5-42a7-96c1-0a2f95daa7ae.png)

由 adafruit.com 提供

有许多便携式电池源可以连接到这个连接器。许多这些电池座价格相当便宜，它们通常支持流行的电池尺寸，如 AAA 电池。由于板子没有内置电池充电功能，您可以安全地使用常规电池或可充电电池。以下照片显示了一个带有开关的电池座：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mcpy-cb/img/3135dd49-5835-4e6a-8969-faed1ad4cfbc.png)

下一张照片显示了同一个支架，盖子打开，以便查看它使用的三节 AAA 电池：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mcpy-cb/img/1a4b85cd-4788-42e5-994e-9a3effd699f2.png)

在上一张照片中显示的电池盒可以在[`www.adafruit.com/product/727`](https://www.adafruit.com/product/727)购买到约 2 美元。

# 创建一个检测按钮状态变化的类

在本教程中，您将学习如何定义一个类，当实例化时，可以跟踪板上特定按钮的按钮按下事件。我们将在本章的后续教程中使用这个类，以便创建对象，用于跟踪按钮 A 和按钮 B 的按下事件。

您将学习如何将常见的代码块放入函数和类中，这将提高项目中的代码重用。它还可以帮助大型项目，以便将大量逻辑分解为更小、独立的函数和类的独立块。这个按钮事件类的实现将故意保持通用，以便它可以轻松地在不同的项目中重用。

# 准备工作

您将需要访问 Circuit Playground Express 上的 REPL，以运行本教程中将呈现的代码。

# 如何做...

让我们来看看本教程中需要的步骤：

1.  在 REPL 中运行以下代码行：

```py
>>> from adafruit_circuitplayground.express import cpx
>>> class ButtonEvent:
...     def __init__(self, name):
...         self.name = name
...         self.last = False
...         
...         
... 
>>> button = ButtonEvent('button_a')
```

1.  在这个阶段，我们已经定义了我们的类并给它一个构造函数。运行下一个代码块来创建这个类的第一个实例，并检查它的`name`属性：

```py
>>> button = ButtonEvent('button_a')
>>> button
<ButtonEvent object at 20003410>
>>> button.name
'button_a'
```

1.  以下代码块将访问`cpx`库中的属性，指示推按钮是否被按下：

```py
>>> pressed = getattr(cpx, button.name)
>>> pressed
False
```

1.  在按住按钮 A 的情况下运行以下代码块。它应该显示推按钮的状态为`pressed`：

```py
>>> pressed = getattr(cpx, button.name)
>>> pressed
True
```

1.  以下代码应该放入`main.py`文件中，当执行时，每当按下按钮 A 时，它将重复打印一条消息：

```py
from adafruit_circuitplayground.express import cpx

class ButtonEvent:
    def __init__(self, name):
        self.name = name
        self.last = False

    def is_pressed(self):
        pressed = getattr(cpx, self.name)
        changed = (pressed != self.last)
        self.last = pressed
        return (pressed and changed)

button = ButtonEvent('button_a')
while True:
    if button.is_pressed():
        print('button A pressed')
```

至此，编码部分就完成了；现在，让我们看看它是如何工作的。

# 工作原理...

`ButtonEvent`类被定义为帮助我们跟踪按钮 A 或按钮 B 的按下事件。当你实例化这个类时，它期望一个参数，指定我们要跟踪的按钮的名称。名称保存在实例的一个属性`name`中，然后最后一个变量被初始化为值`False`。每次我们检查新事件时，这个变量将跟踪按钮状态的上次已知值。

每次我们想要检查是否自上次检查以来发生了新的按钮按下事件时，都会调用`is_pressed`方法。它首先检索物理推按钮的当前状态，以找出它是否被按下。我们将检查该值与其上次已知值，以计算是否发生了变化；我们将这个结果保存在一个名为`changed`的变量中。然后我们保存当前值以供将来参考。该方法将在按钮状态发生变化且当前被按下时返回`True`值。

在类定义之后，我们创建了一个该类的实例，用于跟踪按钮 A 的按下事件。然后，启动一个无限循环，不断检查新的按钮按下事件，并在每次检测到其中一个时打印一条消息。

# 还有更多...

在本教程中，我们只使用了一次该类，以跟踪单个按钮的按下事件；但是因为我们没有在类定义中硬编码任何特定的按钮值，所以我们可以重用这段代码来跟踪许多不同的按钮。我们同样可以轻松地监视按钮 A 和按钮 B 的按下事件。许多 MicroPython 板可以连接许多额外的推按钮。在这些情况下，制作一个通用的观察按钮的类是非常有用的。

还涉及一些逻辑来跟踪先前的按钮状态，以便我们可以检测我们感兴趣的内容，即新的按钮按下事件。通过将所有这些代码放入一个包含的类中，我们可以使我们的代码更易读和更易管理。

# 另请参阅

以下是一些参考资料：

+   有关在 Python 中创建类的文档可以在[`docs.python.org/3/tutorial/classes.html`](https://docs.python.org/3/tutorial/classes.html)找到。

+   有关内置`getattr`函数的文档可以在[`docs.python.org/3/library/functions.html#getattr`](https://docs.python.org/3/library/functions.html#getattr)找到。

# 创建您自己的 Python 模块

在这个示例中，您将学习如何将您创建的代码放入自己的 Python 模块中。我们将从前面的示例中获取代码，该示例帮助我们跟踪按钮按下事件，并将其放入自己的专用模块中。

然后，我们将把这个新创建的模块导入到我们的主 Python 脚本中，并使用它的类定义来跟踪按钮按下事件。当您开始在大型项目上工作并希望将代码拆分为不同的模块时，这可能是一个非常有用的方法。当您发现一个有用的模块并希望将其纳入自己的项目时，这也可能会有所帮助。

# 准备工作

您需要访问 Circuit Playground Express 上的 REPL 才能运行本示例中提供的代码。

# 如何做...

让我们来看看这个食谱所需的步骤：

1.  以下代码应该放入一个名为`button.py`的新文件中；这将成为我们以后可以导入的 Python 模块：

```py
from adafruit_circuitplayground.express import cpx

class ButtonEvent:
    def __init__(self, name):
        self.name = name
        self.last = False

    def is_pressed(self):
        pressed = getattr(cpx, self.name)
        changed = (pressed != self.last)
        self.last = pressed
        return (pressed and changed)
```

1.  在 REPL 中运行以下代码行：

```py
>>> from button import ButtonEvent
>>> ButtonEvent
<class 'ButtonEvent'>
>>> 
```

1.  在这个阶段，我们已经能够从我们的新 Python 模块中导入一个类。下一行代码将创建一个新对象，我们可以用它来检测新的按钮按下事件：

```py
>>> button = ButtonEvent('button_a')
>>> button.is_pressed()
False
```

1.  在按住按钮 A 时运行以下代码块，它应该会检测到按钮按下事件：

```py
>>> button = ButtonEvent('button_a')
>>> button.is_pressed()
```

1.  以下代码应该放入`main.py`文件中，当执行时，每当按下按钮 A 时，它将重复打印一条消息：

```py
from button import ButtonEvent

button = ButtonEvent('button_a')
while True:
    if button.is_pressed():
        print('button A pressed')
```

# 它是如何工作的...

在我们之前的示例中，我们习惯于使用`main.py`文件。创建一个新的 Python 模块就像创建一个新文件并将我们的代码放入其中一样简单。我们已经将`ButtonEvent`类放入了自己的 Python 模块中，名为`button`。

现在，我们可以导入这个类并使用该类创建对象。代码的其余部分创建了一个对象来监视按钮按下事件，并在检测到事件时打印一条消息。

# 还有更多...

当您创建自己的自定义 Python 模块时，重要的是要注意您给模块的名称。任何 Python 模块的相同命名限制也适用于您的 MicroPython 代码。例如，您不能创建一个模块其中包含空格字符。您还应该确保不要将模块命名为现有的 MicroPython 或 CircuitPython 模块的相同名称。因此，您不应该将您的模块命名为`board`或`math`，因为这些名称已经被使用。

防止这种情况发生的最简单方法是在创建新模块之前进入 REPL，并尝试按该名称导入一个模块。如果出现`ImportError`，那么您就知道该名称尚未被使用。

# 另请参阅

以下是一些参考资料：

+   有关创建 Python 模块的文档可以在[`docs.python.org/3/tutorial/modules.html`](https://docs.python.org/3/tutorial/modules.html)找到。

+   关于使用 Python 模块的好处的讨论可以在[`realpython.com/python-modules-packages/`](https://realpython.com/python-modules-packages/)找到。

# 将按钮交互添加到事件循环

在这个食谱中，我们将开始构建我们的主事件循环。每个玩家将被分配一个单独的按键，在游戏中按下。玩家 1 将被分配按键 A，玩家 2 将被分配按键 B。事件循环将不断检查这些按钮，寻找新的按钮按下事件。当检测到新的按键按下事件时，它将打印一条消息。

这将在本章的下一个食谱中进一步扩展，以添加 Button Bash 游戏的其余功能。事件循环可以在许多类型的软件应用程序中找到。探索它们的使用可以帮助您在必须制作自己的事件循环时，或者在必须与内置事件循环交互时。

# 准备工作

您需要访问 Circuit Playground Express 上的 REPL 来运行本食谱中提供的代码。

# 如何做到...

让我们来看看这个食谱所需的步骤：

1.  在 REPL 中执行下一个代码块：

```py
>>> from button import ButtonEvent
>>> 
>>> buttons = {}
>>> buttons[1] = ButtonEvent('button_a')
>>> buttons[2] = ButtonEvent('button_b')
>>> buttons[1].is_pressed()
False
```

1.  在这个阶段，我们已经创建了两个对象来监视两个按键。在运行下一个代码块时，按住按键 A：

```py
>>> buttons[1].is_pressed()
True
```

1.  以下代码应放入`main.py`文件中，当执行时，每当按下按键 A 或按键 B 时，它将重复打印一条消息：

```py
from button import ButtonEvent

def main():
    buttons = {1: ButtonEvent('button_a'), 2: ButtonEvent('button_b')}
    while True:
        for player, button in buttons.items():
            if button.is_pressed():
                print('button pressed for player', player)

main()
```

# 它是如何工作的...

首先，从`button`模块导入`ButtonEvent`类。定义了一个名为`main`的函数，其中包含了我们主要事件循环的代码。代码的最后一行调用`main`函数来启动主事件循环的执行。主事件循环首先定义了一个字典，用于跟踪每个玩家的按钮。它定义了一个映射，玩家 1 将被分配按键 A，玩家 2 将被分配按键 B。

启动了一个无限循环，它将循环遍历每个`ButtonEvent`对象，并检查是否发生了按钮按下事件。如果检测到按钮按下事件，它将打印哪个玩家按下了按钮。

# 还有更多...

随着您的代码变得越来越大，将主要代码块放入自己的函数中，并调用它来启动执行是一个好主意。随着程序规模的增大，这将使跟踪变量变得更容易，因为它们都将在这个主函数的范围内，而不是驻留在全局命名空间中。这有助于减少一些可能出现在共享同一个大型全局命名空间的大块代码中的丑陋 bug。

本食谱中另一个要注意的事情是使用字典来维护玩家和他们的按钮的关联。字典数据结构是这种需求的一个非常自然的选择。如果我们使用的硬件有更多的按键，我们可以只需向我们的数据结构中为每个玩家添加一个项目。充分利用数据结构是一个很好的主意；它使调试和软件设计变得更加容易。

# 另请参阅

以下是一些参考资料：

+   可以在[`docs.python.org/3/library/tkinter.html#a-simple-hello-world-program`](https://docs.python.org/3/library/tkinter.html#a-simple-hello-world-program)找到使用事件循环响应按钮按下事件的`tkinter`库的文档。

+   关于`tkinter`的主事件循环的讨论可以在[`gordonlesti.com/use-tkinter-without-mainloop/`](https://gordonlesti.com/use-tkinter-without-mainloop/)找到。

# 创建一个生成器来获取像素颜色

在这个食谱中，我们将准备用于控制游戏中像素的代码。棋盘上有 10 个像素，所以每个玩家将获得 5 个像素，以表示他们目前获得了多少分。现在，每当玩家按下按钮时，他们都会获得一个点，游戏需要得分 20 分才能赢。因此，我们必须呈现 0 到 20 的分数，但只有 5 个像素。

我们将通过让每个像素的得分由四种颜色表示来实现这一点。因此，对于前四个点，第一个像素将经历黄色、深橙色、红色和品红色。然后，当你达到得分 5 时，第二个像素将点亮黄色并经历相同的循环。

将使用生成器获取与每个玩家每个得分相关的颜色和像素位置的列表。玩家 1 将使用按钮 A，并将拥有紧挨着该按钮的五个像素。这些是像素 0 到 4。玩家 2 将使用按钮 B，并将拥有紧挨着该按钮的五个像素。这些是像素 5 到 9。

两组像素将从 USB 连接器附近开始点亮，并向终点线赛跑，终点线将是 JST 电池输入。这使得玩家 1 的序列为 0 到 4，玩家 2 的序列为 9 到 5。这个示例将涵盖生成器的一个有趣用例，它在一些项目中可能会派上用场，当你需要基于一些复杂的逻辑生成一系列值时。

# 准备工作

您需要访问 Circuit Playground Express 上的 REPL 来运行本示例中提供的代码。

# 操作步骤

让我们来看看这个示例所需的步骤：

1.  使用 REPL 运行以下代码行：

```py
>>> from adafruit_circuitplayground.express import cpx
>>> BLACK = 0x000000
>>> SEQUENCE = [
...     0xFFFF00,   # Yellow
...     0xFF8C00,   # DarkOrange
...     0xFF0000,   # Red
...     0xFF00FF,   # Magenta
...     ]
>>> cpx.pixels.brightness = 0.02
>>> cpx.pixels[0] = SEQUENCE[0]
```

1.  在这个阶段，第一个像素应该点亮黄色。在下一段代码中，我们将定义生成器并调用它来为玩家 1 和玩家 2 生成位置和颜色的列表。列表中有 21 个项目。第一个项目代表得分 0，这是一个特殊情况，如果没有人得分，我们希望所有像素都关闭。剩下的 20 个项目代表得分 1 到 20：

```py
>>> PLAYER_PIXELS1 = [0, 1, 2, 3, 4]
>>> PLAYER_PIXELS2 = [9, 8, 7, 6, 5]
>>> 
>>> def generate_colors(positions):
...     yield 0, BLACK
...     for i in positions:
...         for color in SEQUENCE:
...             yield i, color
...             
...             
... 
>>> COLORS = dict()
>>> COLORS[1] = list(generate_colors(PLAYER_PIXELS1))
>>> COLORS[2] = list(generate_colors(PLAYER_PIXELS2))
>>> 
>>> COLORS[1]
[(0, 0), (0, 16776960), (0, 16747520), (0, 16711680), (0, 16711935), (1, 16776960), (1, 16747520), (1, 16711680), (1, 16711935), (2, 16776960), (2, 16747520), (2, 16711680), (2, 16711935), (3, 16776960), (3, 16747520), (3, 16711680), (3, 16711935), (4, 16776960), (4, 16747520), (4, 16711680), (4, 16711935)]
>>> len(COLORS[1])
21
```

1.  以下代码应放入`colors.py`文件中，然后可以在下一个示例中导入，以便访问游戏的颜色数据：

```py
BLACK = 0x000000
SEQUENCE = [
    0xFFFF00,   # Yellow
    0xFF8C00,   # DarkOrange
    0xFF0000,   # Red
    0xFF00FF,   # Magenta
]
PLAYER_PIXELS1 = [0, 1, 2, 3, 4]
PLAYER_PIXELS2 = [9, 8, 7, 6, 5]

def generate_colors(positions):
    yield 0, BLACK
    for i in positions:
        for color in SEQUENCE:
            yield i, color

COLORS = dict()
COLORS[1] = list(generate_colors(PLAYER_PIXELS1))
COLORS[2] = list(generate_colors(PLAYER_PIXELS2))
```

# 工作原理

首先，`SEQUENCE`列表表示将显示在每个像素上以表示玩家得分的四种颜色。然后定义了每个玩家将点亮的五个像素的位置和顺序。然后定义了`generate_colors`生成器。调用时，它将生成一系列元组，每个元组包含特定得分表示的位置和颜色。这将被转换为每个玩家的列表。

通过这种方式，我们可以立即查找任何得分的相关颜色和像素位置。每个玩家和每个得分的这些颜色和位置值存储在一个名为`COLORS`的字典中，可以用来通过玩家、数字和得分查找这些值。

# 还有更多...

Python 的**迭代器**是该语言的一个非常强大的特性。生成器是迭代器的一种类型，它让你以简洁的方式实现一些强大的解决方案。它们在这个示例中被用作一种辅助方式，用于构建一个具有特殊第一情况和两个嵌套级别的值的列表。

通过将所有这些逻辑放入一个生成器中，我们可以将其包含在一个地方，然后将其用作构建更复杂结构的构建块。在这个示例中，单个生成器被用来构建玩家 1 和玩家 2 的颜色查找数据。

# 另请参阅

以下是一些参考资料：

+   迭代器的文档可以在[`docs.python.org/3/tutorial/classes.html#iterators`](https://docs.python.org/3/tutorial/classes.html#iterators)找到。

+   生成器的文档可以在[`docs.python.org/3/tutorial/classes.html#generators`](https://docs.python.org/3/tutorial/classes.html#generators)找到。

# 使用 ScoreBoard 类显示得分

在这个示例中，我们将准备用于跟踪每个玩家得分并在像素上显示他们当前得分的代码。我们将创建一个名为`ScoreBoard`的新类，并将其放入一个名为`score`的新模块中。

这个配方将向您展示一种在基于 MicroPython 的游戏中实现记分牌功能的方法。这个配方将从开始游戏的初始逻辑开始，跟踪得分，然后在像素上显示得分。在接下来的配方中，我们将添加更多功能来处理得分的增加和检测玩家中的一个何时赢得比赛。

# 准备工作

您将需要访问 Circuit Playground Express 上的 REPL 来运行本配方中提供的代码。

# 如何做...

让我们来看看这个配方所需的步骤：

1.  在 REPL 中运行以下代码行：

```py
>>> from adafruit_circuitplayground.express import cpx
>>> from colors import COLORS
>>> 
>>> class ScoreBoard:
...     def __init__(self):
...         self.score = {1: 0, 2: 0}
...         cpx.pixels.brightness = 0.02
...         cpx.play_file('start.wav')
...         
...         
... 
>>> board = ScoreBoard()
>>> board.score[1]
0
```

1.  运行前面的代码后，您应该听到板子播放游戏启动音频，它说`1 2 3 Go!`。然后，您应该看到玩家 1 的当前得分为`0`。

1.  以下代码应该放入`score.py`文件中，然后我们可以在其他地方导入并使用它：

```py
from adafruit_circuitplayground.express import cpx
from colors import COLORS

class ScoreBoard:
    def __init__(self):
        self.score = {1: 0, 2: 0}
        cpx.pixels.brightness = 0.02
        cpx.play_file('start.wav')

    def show(self, player):
        score = self.score[player]
        pos, color = COLORS[player][score]
        cpx.pixels[pos] = color
```

1.  以下代码将从`score`模块导入`ScoreBoard`类，将第一个玩家的得分设置为`3`，然后在像素上显示这个得分。第一个像素应该变成红色：

```py
>>> from score import ScoreBoard
>>> 
>>> board = ScoreBoard()
>>> board.score[1] = 3
>>> board.show(1)
```

# 它是如何工作的...

`ScoreBoard`类在`score`模块中定义。当类首次实例化时，它准备好开始比赛。它将玩家 1 和 2 的分数初始化为 0。然后，它设置像素的亮度并播放音频剪辑，向玩家宣布比赛的开始。

`show`方法期望一个参数，这个参数将是要显示得分的玩家的编号。然后，它获取玩家得分的值，并将其与玩家编号一起使用，查找必须设置的像素的颜色和位置。然后，将该像素的颜色设置为正确的颜色。

# 还有更多...

我们已经开始构建逻辑，向玩家展示当前的记分牌。在竞争激烈的游戏中，重要的是要制作一个有趣和响应灵敏的记分牌，以保持两名玩家参与并努力互相击败。

更新记分牌的代码必须以执行良好的方式实现。如果对记分牌的每次更新都是一个迟钝的过程，玩家会感觉到并对不响应的应用感到沮丧。获取像素的颜色和位置的所有代码都以高效的方式实现，以确保其性能。

# 另请参阅

以下是一些参考资料：

+   可以在[`tinkercademy.com/tutorials/flappy-bird/`](https://tinkercademy.com/tutorials/flappy-bird/)找到一个 MicroPython 项目的示例，显示玩家在游戏中的得分。

+   可以在[`learn.adafruit.com/neopixel-coat-buttons`](https://learn.adafruit.com/neopixel-coat-buttons)找到一个使用电池操作的 MicroPython 项目的示例，用于控制 NeoPixels。

# 使用`ScoreBoard`类检测获胜者。

在这个配方中，我们将扩展`ScoreBoard`类，以便能够更新玩家得分并检测玩家何时赢得比赛。一旦玩家中的一个赢得了比赛，板子将通过播放带有宣布的音频剪辑来宣布哪个玩家赢得了比赛。

这个配方是完成`ScoreBoard`类中逻辑的最后一部分。一旦完成，我们就可以将其合并到主事件循环中，并在下一个配方中完成游戏。

# 准备工作

您将需要访问 Circuit Playground Express 上的 REPL 来运行本配方中提供的代码。

# 如何做...

让我们来看看这个配方所需的步骤：

1.  以下代码应该放入`score.py`文件中，然后我们可以在其他地方导入并使用它：

```py
from adafruit_circuitplayground.express import cpx
from colors import COLORS

class ScoreBoard:
    def __init__(self):
        self.score = {1: 0, 2: 0}
        cpx.pixels.brightness = 0.02
        cpx.play_file('start.wav')

    def scored(self, player):
        self.score[player] += 1
        self.show(player)
        if self.score[player] == 20:
            cpx.play_file('win%s.wav' % player)

    def show(self, player):
        score = self.score[player]
        pos, color = COLORS[player][score]
        cpx.pixels[pos] = color
```

1.  以下代码将从`score`模块导入`ScoreBoard`类，并打印出玩家的当前得分：

```py
>>> from score import ScoreBoard
>>> board = ScoreBoard()
>>> board.score
{2: 0, 1: 0}
```

1.  下一段代码将增加玩家 1 的得分，导致第一个像素点变成黄色，并打印出当前得分。得分应该显示玩家 1 得到 1 分：

```py
>>> board.scored(1)
>>> board.score
{2: 0, 1: 1}
```

# 它是如何工作的...

`ScoreBoard`类添加了一个额外的方法，当其中一个玩家得分时，它将在`score`数据结构中递增。`scored`方法接收一个参数，即玩家编号，并增加该玩家的得分。

然后它会更新像素以显示玩家的最新得分，然后检查玩家的得分是否已经达到 20 分。如果玩家已经达到 20 分，棋盘将播放一条宣布哪个玩家赢得了比赛的公告。

# 还有更多...

声音和光是与玩家在视频游戏中进行互动的好方法。在这个课程中，声音被有效地用来宣布游戏的开始和结束。在游戏过程中，光被用来激励每个玩家更快地按下按钮，以便他们能够第一个到达终点线。尽管在这个课程中发生了很多事情，但每种方法只有三到四行代码，这使得更容易看到每个部分所涉及的内容。这是将代码分解成较小块的一种方法，通过将不同的部分放入不同的方法中。

# 另请参阅

以下是一些参考资料：

+   可以在[`learn.adafruit.com/circuit-playground-express-ir-zombie-game/`](https://learn.adafruit.com/circuit-playground-express-ir-zombie-game/)找到使用 Circuit Playground Express 的多人游戏。

+   可以在[`learn.adafruit.com/circuit-playground-treasure-hunt/`](https://learn.adafruit.com/circuit-playground-treasure-hunt/)找到使用 CircuitPython 实现的游戏。

# 将 ScoreBoard 类添加到事件循环

本章的最后一个食谱将在本章中将所有先前的食谱结合起来，以创建最终的 Button Bash 游戏。我们将通过添加在上一个食谱中实现的`ScoreBoard`类来升级事件循环。这是谜题的最后一块。

最终结果是一个只有六行代码的主循环。我们能够通过将本章中创建的三个 Python 模块中的大部分游戏逻辑保留下来来实现这一结果。当您发现代码基础变得过大且集中在一个文件或一个函数中时，您可以在自己的项目中使用类似的方法。

# 准备工作

您将需要访问 Circuit Playground Express 上的 REPL 来运行本食谱中提供的代码。

# 如何做...

让我们来看看这个食谱所需的步骤：

1.  以下代码应该放入`main.py`文件中，然后您就可以开始玩 Button Bash 游戏了：

```py
from button import ButtonEvent
from score import ScoreBoard

def main():
    buttons = {1: ButtonEvent('button_a'), 2: ButtonEvent('button_b')}
    board = ScoreBoard()
    while True:
        for player, button in buttons.items():
            if button.is_pressed():
                board.scored(player)

main()
```

1.  如果您拥有本章开头提到的便携式电源供应之一，那么您可以将棋盘从计算机上断开，并连接该电源供应。

1.  现在您可以随身携带游戏，并在每个玩家之间进行回合。要开始下一场比赛，请按下棋盘中央的复位按钮，以开始新的一轮。

# 工作原理...

我们首先导入`ButtonEvent`和`ScoreBoard`对象；它们是我们需要实现事件循环的两个主要对象。在创建了我们的按钮字典之后，我们实例化了一个名为`board`的新`ScoreBoard`对象。

这将宣布游戏已经开始，然后我们将进入一个无限循环，该循环将不断检查按钮按下事件。一旦检测到这些事件中的一个，它将调用棋盘对象上的`scored`方法来增加特定玩家的分数。如果任何玩家已经达到最终得分，那么他们将被宣布为赢家。

# 还有更多...

现在我们已经有了游戏的基本版本，有许多方法可以改变它并增强它。我们可以创建两种可以通过滑动开关选择的游戏模式。可以有简单和困难模式，其中一个需要得分 10 分，另一个需要得分 20 分。当棋盘启动时，它会检查开关以加载颜色和最终得分的正确参数。

您可以制作一个三局两胜的模式，两名玩家必须反复进行三轮比赛，最终获得两局胜利的人获胜。要看游戏的实际操作，请查看下一张照片，看看两名玩家在 Button Bash 上激烈对抗。

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mcpy-cb/img/ff90c627-9968-4182-86ba-a0db4426b75f.png)

# 参见

以下是一些参考资料：

+   一个使用 NeoPixels 的电池供电便携式 CircuitPython 项目可以在[`learn.adafruit.com/ufo-circuit-playground-express`](https://learn.adafruit.com/ufo-circuit-playground-express)找到。

+   一个使用 NeoPixels 的篮球篮游戏可以在[`learn.adafruit.com/neopixel-mini-basketball-hoop`](https://learn.adafruit.com/neopixel-mini-basketball-hoop)找到。


# 第七章：水果曲调

在本章中，您将学习如何使用 Circuit Playground Express 和一些香蕉创建一个乐器。我们将把四根香蕉连接到板上的触摸板，这样您就可以触摸每根香蕉时播放特定的音乐声音。我们将通过点亮每个触摸板旁边的像素来为项目添加一些视觉反馈。这个项目将展示一个创造性、有趣的方式，让您的电容触摸项目生动起来。

通过在项目中使用意想不到的物体，如香蕉，您可以为平凡的 MicroPython 项目增添独特的风味。

在本章中，我们将介绍以下配方：

+   创建一个类来响应触摸事件

+   创建一个函数来启用扬声器输出

+   创建一个播放音频文件的函数

+   使用 NeoPixel 对象控制像素

+   创建一个触摸处理程序来播放声音

+   创建一个触摸处理程序来点亮像素

+   创建一个事件循环来处理所有触摸事件

# 技术要求

本章的代码文件可以在 GitHub 存储库的`Chapter07`文件夹中找到，网址为[`github.com/PacktPublishing/MicroPython-Cookbook`](https://github.com/PacktPublishing/MicroPython-Cookbook)。

本章中的许多配方需要将四个音频文件传输到 Circuit Playground Express 板上。它们都可以从 GitHub 存储库的`Chapter07`文件夹中下载。它们应该保存在与您的`main.py`文件同级的文件夹中。

# Circuit Playground Express 触摸板

Circuit Playground Express 带有七个电容触摸板。它们中的每一个都可以连接到任何可以导电的物体，触摸该物体将触发传感器。您可以使用良好的电导体，如金属，甚至较弱的导体，如香蕉。

水能导电，许多水果的表面含有足够的水分，可以被触摸板检测到触摸事件。许多水果，如香蕉、酸橙、橙子和苹果，都可以胜任。您可以使用鳄鱼夹将水果连接到触摸板。下一张照片显示了一捆鳄鱼夹：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mcpy-cb/img/a34c1b12-42b9-465a-8d1d-00e82740e562.png)

这些鳄鱼夹子有各种不同的颜色。最好为每个触摸板使用不同颜色的导线。这样会更容易追踪哪个水果连接到哪个触摸板。在这个项目中，我们将使用绿色、红色、黄色和白色的导线。我们将把每个触摸板旁边的像素颜色也设置为绿色、红色、黄色和白色。下一张照片显示了一个香蕉连接到一个触摸板：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mcpy-cb/img/3b3aa8f7-7cf8-4e04-b03e-4fabb1cb7126.png)

鳄鱼夹非常有效，因为它们不需要任何焊接，可以轻松连接到板和各种物体。鳄鱼夹的牙齿也会产生良好的抓地力，从而可以在板和香蕉之间建立良好的电连接。下一张照片更近距离地展示了连接到香蕉上的鳄鱼夹的牙齿：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mcpy-cb/img/155c7ec9-f0c3-49ef-bd49-97fc9e918997.png)

下一张照片显示了连接到触摸板的鳄鱼夹的更近距离视图：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mcpy-cb/img/52b29bc0-114d-40e6-8884-e58bc97b6eef.png)

在之前的章节中，我们使用 Circuit Playground Express 库与板上的不同组件进行交互。当您使用该库播放音频文件时，该库将阻塞您的代码，直到文件播放完成。在这个项目中，我们希望能够立即响应触摸事件，并在当前音频文件播放完成之前播放新的声音。

只有使用直接控制音频播放和触摸板的 CircuitPython 库才能实现这种程度的控制。因此，本章中的代码将不使用 Circuit Playground Express 库。通过采用这种方法，我们还将看到如何更精细地控制板上的组件。

# 创建一个用于响应触摸事件的类

在这个教程中，您将学习如何定义一个类，以帮助您处理特定触摸板上的触摸事件。当您创建这个类的实例时，您需要指定触摸板的名称和一个回调函数，每次触摸事件开始和结束时都会调用该函数。我们可以将这个类用作构建块，为将连接到香蕉的四个触摸板中的每一个调用一个回调。您可以在自己的项目中使用这种代码风格，每当您想要处理一系列事件时，都可以使用一组回调函数。

# 准备工作

您需要访问 Circuit Playground Express 上的 REPL 来运行本教程中提供的代码。

# 如何操作...

让我们来看看这个教程所需的步骤：

1.  在 REPL 中运行以下代码行：

```py
>>> from touchio import TouchIn
>>> import board
>>> 
>>> def handle(name, current):
...     print(name, current)
...     
...     
... 
>>> handle('A1', True)
A1 True
>>> handle('A1', False)
A1 False
>>> 
```

1.  在这个阶段，我们已经定义了一个函数，它将通过打印触摸板的名称以及触摸板是否被触摸来处理触摸事件。

1.  运行下一块代码以创建一个检查触摸事件的类。在定义类之后，它将创建一个实例，然后打印出触摸板的当前触摸状态：

```py
>>> class TouchEvent:
...     THRESHOLD_ADJUSTMENT = 400
...     
...     def __init__(self, name, onchange):
...         self.name = name
...         self.last = False
...         self.onchange = onchange
...         pin = getattr(board, name)
...         self.touch = TouchIn(pin)
...         self.touch.threshold += self.THRESHOLD_ADJUSTMENT
...         
...         
... 
>>> event = TouchEvent('A1', handle)
>>> event.touch.value
False
```

1.  按住触摸板 A1 上的手指，同时运行下一块代码：

```py
>>> event.touch.value
True
```

1.  运行下一块代码以创建一个具有处理触摸事件的方法的类：

```py
>>> class TouchEvent:
...     THRESHOLD_ADJUSTMENT = 400
...     
...     def __init__(self, name, onchange):
...         self.name = name
...         self.last = False
...         self.onchange = onchange
...         pin = getattr(board, name)
...         self.touch = TouchIn(pin)
...         self.touch.threshold += self.THRESHOLD_ADJUSTMENT
...         
...     def process(self):
...         current = self.touch.value
...         if current != self.last:
...             self.onchange(self.name, current)
...             self.last = current
...             
...             
... 
>>> event = TouchEvent('A1', handle)
```

1.  按住触摸板 A1 上的手指，同时运行下一块代码：

```py
>>> event.process()
A1 True
```

1.  以下代码应放入`main.py`文件中：

```py
from touchio import TouchIn
import board

class TouchEvent:
    THRESHOLD_ADJUSTMENT = 400

    def __init__(self, name, onchange):
        self.name = name
        self.last = False
        self.onchange = onchange
        pin = getattr(board, name)
        self.touch = TouchIn(pin)
        self.touch.threshold += self.THRESHOLD_ADJUSTMENT

    def process(self):
        current = self.touch.value
        if current != self.last:
            self.onchange(self.name, current)
            self.last = current

def handle(name, current):
    print(name, current)

event = TouchEvent('A1', handle)
while True:
    event.process()
```

当执行时，此脚本将在触摸板 A1 上触摸事件开始或结束时重复打印消息。

# 它是如何工作的...

`TouchEvent`类被定义为帮助我们跟踪触摸板的最后已知状态，并在其状态发生变化时调用指定的回调函数。定义了默认的触摸阈值为`400`，以便该类的子类可以覆盖该值。构造函数期望第一个参数是要监视的触摸板的名称，第二个参数是在检测到状态变化时将被调用的回调函数。

名称和回调函数将保存在实例的属性中。最后已知状态初始化为`False`值。然后，从`board` Python 模块中检索命名触摸板的引脚值。该引脚用于创建`TouchIn`实例，也保存为对象的属性。最后，在初始化过程中设置了该触摸板的阈值。

在类上定义的另一个方法将定期调用，以检查触摸板状态的任何变化，并通过调用定义的回调函数来处理这种状态变化。这是通过获取当前触摸状态并将其与最后已知值进行比较来完成的。如果它们不同，就会调用回调函数并保存该值以供将来参考。

定义了一个简单的函数来处理任何触摸事件，只需打印出发生状态变化的触摸板的名称和当前状态。

在这些类和函数定义之后，我们创建了这个类的一个实例，它将监视触摸板 A1。然后我们进入一个无限循环，不断检查状态变化，并在每次发生状态变化时打印出一条消息。

# 还有更多...

在触摸板上设置触摸阈值总是一个好主意。如果不这样做，当与触摸板交互时会出现很多误报。所选择的值`400`是适合将香蕉与鳄鱼夹连接的特定设置的值。最好连接实际用于项目的对象，然后将该值微调为合适的值。

在这个示例中，我们混合了函数和类的用法。这种方法在 Python 中是完全可以的，它让你同时拥有两种最好的方式。我们需要在每次调用`process`方法之间保持状态，这就是为什么我们选择了一个类来实现这个目的。回调函数不需要在调用之间保持任何状态，所以一个简单的函数就可以胜任。

# 另请参阅

以下是一些参考资料：

+   关于`TouchIn`类的文档可以在[`circuitpython.readthedocs.io/en/3.x/shared-bindings/touchio/TouchIn.html`](https://circuitpython.readthedocs.io/en/3.x/shared-bindings/touchio/TouchIn.html)找到。

+   关于`board` Python 模块的文档可以在[`circuitpython.readthedocs.io/en/3.x/shared-bindings/board/__init__.html#module-board`](https://circuitpython.readthedocs.io/en/3.x/shared-bindings/board/__init__.html#module-board)找到。

# 创建一个函数来启用扬声器输出

在这个示例中，您将学习如何创建一个函数，当调用时，将启用扬声器。如果在音频播放之前不启用扬声器，那么它将通过引脚 A0 播放，可以连接耳机。

这个项目将使用板子上的扬声器而不是耳机，所以我们需要在脚本开始时使用这个函数来启用扬声器。除了向您展示如何启用扬声器之外，这个示例还将向您介绍数字控制输入/输出引脚的方法。

# 准备工作

您需要访问 Circuit Playground Express 上的 REPL 来运行本示例中提供的代码。

# 如何做...

让我们来看看这个示例所需的步骤：

1.  在 REPL 中执行下一个代码块：

```py
>>> from digitalio import DigitalInOut
>>> import board
>>> 
>>> 
>>> speaker_control = DigitalInOut(board.SPEAKER_ENABLE)
>>> speaker_control
<DigitalInOut>
```

1.  在这个阶段，我们已经创建了一个连接到启用扬声器的引脚的对象。运行下一个代码块来启用扬声器：

```py
>>> speaker_control.switch_to_output(value=True)
```

1.  重新加载板子并再次进入 REPL。下一个代码块将定义启用扬声器的函数，并调用它：

```py
>>> from digitalio import DigitalInOut
>>> import board
>>> 
>>> def enable_speakers():
...     speaker_control = DigitalInOut(board.SPEAKER_ENABLE)
...     speaker_control.switch_to_output(value=True)
...     
...     
... 
>>> enable_speakers()
```

# 它是如何工作的...

首先定义了`enable_speakers`函数。它不接收任何参数，因为板子上只有一个扬声器需要启用，并且不返回任何东西，因为一旦扬声器启用，它的引脚就不需要再进行交互。`DigitalInOut`对象用于与启用扬声器的引脚进行交互。创建了这个对象后，调用`switch_to_output`方法来启用扬声器输出。在定义函数之后，调用它来启用扬声器。

# 还有更多...

在这个示例中使用的`DigitalInOut`对象可以用来与各种引脚进行交互。例如，在这块板子上，它可以用来连接读取来自按键 A 和按键 B 的输入的引脚。一旦正确连接和配置这些按键引脚，就可以开始轮询引脚的值，以检查按键是否被按下。

# 另请参阅

以下是一些参考资料：

+   `DigitalInOut`对象的示例用法可以在[`learn.adafruit.com/adafruit-circuit-playground-express/circuitpython-digital-in-out`](https://learn.adafruit.com/adafruit-circuit-playground-express/circuitpython-digital-in-out)找到。

+   关于`DigitalInOut`对象的文档可以在[`circuitpython.readthedocs.io/en/3.x/shared-bindings/digitalio/DigitalInOut.html`](https://circuitpython.readthedocs.io/en/3.x/shared-bindings/digitalio/DigitalInOut.html)找到。

# 创建一个函数来播放音频文件

在这个示例中，您将学习如何创建一个函数，当调用时，将在内置扬声器上播放特定的音频文件。这个示例将说明如何访问音频输出设备，以及如何读取`.wav`文件的内容，将其转换为音频流，并将该音频流馈送到板载音频播放设备。这个示例中展示的技术可以用于各种需要更精细控制音频文件播放方式的项目中。

# 准备工作

您需要访问 Circuit Playground Express 上的 REPL 来运行本教程中提供的代码。

# 如何做...

让我们来看看本教程所需的步骤：

1.  使用 REPL 运行以下代码行：

```py
>>> from digitalio import DigitalInOut
>>> from audioio import WaveFile, AudioOut
>>> import board
>>> import time
>>> 
>>> def enable_speakers():
...     speaker_control = DigitalInOut(board.SPEAKER_ENABLE)
...     speaker_control.switch_to_output(value=True)
...     
...     
... 
>>> enable_speakers()
>>> speaker = AudioOut(board.SPEAKER)
>>> speaker
<AudioOut>
>>> 
```

1.  在这个阶段，我们已经启用了扬声器，并创建了一个对象来向扬声器提供音频数据。当您运行下一块代码时，您应该听到扬声器上播放钢琴音符：

```py
>>> file = open('piano.wav', "rb")
>>> audio = WaveFile(file)
>>> speaker.play(audio)
>>> 
```

1.  运行下一块代码以再次听到相同的钢琴音符，但这次是通过函数调用播放：

```py
>>> def play_file(speaker, path):
...     file = open(path, "rb")
...     audio = WaveFile(file)
...     speaker.play(audio)
...     
...     
... 
>>> play_file(speaker, 'piano.wav')
```

1.  以下代码应放入`main.py`文件中，当执行时，它将在重新加载板时播放单个钢琴音符：

```py
from digitalio import DigitalInOut
from audioio import WaveFile, AudioOut
import board
import time

def play_file(speaker, path):
    file = open(path, "rb")
    audio = WaveFile(file)
    speaker.play(audio)

def enable_speakers():
    speaker_control = DigitalInOut(board.SPEAKER_ENABLE)
    speaker_control.switch_to_output(value=True)

enable_speakers()
speaker = AudioOut(board.SPEAKER)
play_file(speaker, 'piano.wav')
time.sleep(100)
```

# 工作原理...

首先，启用扬声器，以便我们可以在没有耳机的情况下听到音频播放。然后使用`AudioOut`类来访问音频输出设备。然后调用`play_file`函数，传递扬声器音频对象和将要播放的音频文件的路径。此函数以二进制模式打开文件。

然后使用此文件对象创建`WaveFile`对象，该对象将以音频流的形式返回数据。然后将此音频数据提供给`AudioOut`对象上的`play`方法以开始播放。此方法立即返回，并且不等待播放完成。这就是为什么之后调用`sleep`方法，以便在主脚本结束执行之前给板子一个播放音频流的机会。

如果您从文件中排除这行代码并重新加载代码，那么脚本将在板子有机会播放文件之前退出，您将听不到任何音频播放。

# 还有更多...

使用此函数，您可以通过仅传递音频输出对象和文件路径来播放任意数量的音频文件。您还可以将此教程用作进一步尝试与此板附带的音频播放库的起点。例如，有一种方法可以轮询和检查最后提供的流是否仍在播放，或者是否已完成播放。

# 另请参阅

以下是一些参考资料：

+   有关`AudioOut`对象的文档可以在[`circuitpython.readthedocs.io/en/3.x/shared-bindings/audioio/AudioOut.html`](https://circuitpython.readthedocs.io/en/3.x/shared-bindings/audioio/AudioOut.html)找到。

+   有关`WaveFile`对象的文档可以在[`circuitpython.readthedocs.io/en/3.x/shared-bindings/audioio/WaveFile.html`](https://circuitpython.readthedocs.io/en/3.x/shared-bindings/audioio/WaveFile.html)找到。

# 使用 NeoPixel 对象控制像素

在本教程中，您将学习如何使用 NeoPixel 对象控制板上的像素。我们在之前的章节中涵盖了这个对象中的许多方法，但这是我们第一次直接创建 NeoPixel 对象。直接使用 NeoPixel 对象的技能非常有用，而不是通过另一个对象访问它。如果您决定向项目添加额外的环或像素条，那么您将需要直接访问此对象来控制像素。

# 准备工作

您需要访问 Circuit Playground Express 上的 REPL 来运行本教程中提供的代码。

# 如何做...

让我们来看看本教程所需的步骤：

1.  在 REPL 中运行以下代码行：

```py
>>> from neopixel import NeoPixel
>>> import board
>>> 
>>> PIXEL_COUNT = 10
>>> pixels = NeoPixel(board.NEOPIXEL, PIXEL_COUNT)
>>> pixels.brightness = 0.05
>>> pixels[0] = 0xFF0000
```

1.  在运行上一个代码块之后，第一个像素应该变成红色。运行下一个代码块以使第二个像素变成绿色：

```py
>>> RGB = dict(
...     black=0x000000,
...     white=0xFFFFFF,
...     green=0x00FF00,
...     red=0xFF0000,
...     yellow=0xFFFF00,
... )
>>> pixels[1] = RGB['green']
```

1.  运行下一个代码块以关闭第一个像素：

```py
>>> pixels[0] = RGB['black']
```

1.  以下代码应放入`main.py`文件中，当执行时，它将使前两个像素变成红色和绿色：

```py
from neopixel import NeoPixel
import board

PIXEL_COUNT = 10
RGB = dict(
    black=0x000000,
    white=0xFFFFFF,
    green=0x00FF00,
    red=0xFF0000,
    yellow=0xFFFF00,
)

pixels = NeoPixel(board.NEOPIXEL, PIXEL_COUNT)
pixels.brightness = 0.05
pixels[0] = RGB['red']
pixels[1] = RGB['green']

while True:
    pass
```

# 工作原理...

`NeoPixel`类用于访问板上的像素数组。当我们创建此对象时，我们必须指定要连接到的板上的引脚以及连接到该引脚的像素数。

在 Circuit Playground Express 的情况下，板上有 10 个像素。我们将此值保存在全局常量中，以提高代码的可读性。然后将像素的亮度设置为 5%。

在项目中需要的五种不同颜色的名称和十六进制代码在全局字典中定义。白色、绿色、红色和黄色分别与附加电线的四种颜色相关。黑色用于关闭像素。然后，我们将第一个和第二个像素设置为红色和绿色。最后，我们运行一个无限循环，以便我们可以看到这些颜色并阻止脚本退出。

# 还有更多...

此代码具有与板载的任何 10 个像素进行交互所需的一切。您可以使用此基本代码开始尝试提供对象上可用的不同方法。使用这些不同的方法，您可以一次性更改所有像素的颜色。您还可以关闭默认的自动写入功能，然后直接控制您对颜色所做的更改何时应用。通过此库，可以完全控制像素的低级别控制。

# 另请参阅

以下是一些参考资料：

+   可以在[`circuitpython.readthedocs.io/projects/neopixel/en/latest/examples.html`](https://circuitpython.readthedocs.io/projects/neopixel/en/latest/examples.html)找到有关测试像素功能的文档。

+   可以在[`circuitpython.readthedocs.io/projects/neopixel/en/latest/`](https://circuitpython.readthedocs.io/projects/neopixel/en/latest/)找到 NeoPixel 驱动程序的概述。

# 创建触摸处理程序以播放声音

在本教程中，我们将创建我们的触摸处理程序的第一个版本。此第一个版本将在检测到触摸事件时播放特定的音频文件。然后，我们可以在以后的教程中使用此处理程序，以将每个触摸板映射到特定的音频文件。我们还将在以后的教程中扩展此处理程序的功能，以在触摸事件中添加光和声音。事件处理程序是许多软件系统的常见部分。本教程将帮助您了解如何在 MicroPython 项目中使用这种常见方法。

# 准备工作

您需要访问 Circuit Playground Express 上的 REPL 才能运行本教程中提供的代码。

# 如何做...

让我们来看看本教程所需的步骤：

1.  在 REPL 中执行下一块代码：

```py
>>> from touchio import TouchIn
>>> from digitalio import DigitalInOut
>>> from audioio import WaveFile, AudioOut
>>> import board
>>> def enable_speakers():
...     speaker_control = DigitalInOut(board.SPEAKER_ENABLE)
...     speaker_control.switch_to_output(value=True)
...     
...     
... 
>>> def play_file(speaker, path):
...     file = open(path, "rb")
...     audio = WaveFile(file)
...     speaker.play(audio)
...     
...     
... 
>>> enable_speakers()
>>> speaker = AudioOut(board.SPEAKER)
```

1.  此时，我们已经启用了扬声器，并设置了一个对象来在扬声器上播放音频文件。在下一块代码中，我们将定义一个`Handler`类，然后创建一个将使用我们的`speaker`对象的实例：

```py
>>> class Handler:
...     def __init__(self, speaker):
...         self.speaker = speaker
...         
...     def handle(self, name, state):
...         if state:
...             play_file(self.speaker, 'piano.wav')
... 
>>> handler = Handler(speaker)
```

1.  当您运行下一块代码时，您应该能听到扬声器上的钢琴声音：

```py
>>> handler.handle('A1', True)
```

1.  以下代码应放入`main.py`文件中，当执行时，每次触摸 A1 触摸板时都会播放钢琴声音：

```py
from touchio import TouchIn
from digitalio import DigitalInOut
from audioio import WaveFile, AudioOut
import board

def enable_speakers():
    speaker_control = DigitalInOut(board.SPEAKER_ENABLE)
    speaker_control.switch_to_output(value=True)

def play_file(speaker, path):
    file = open(path, "rb")
    audio = WaveFile(file)
    speaker.play(audio)

class Handler:
    def __init__(self, speaker):
        self.speaker = speaker

    def handle(self, name, state):
        if state:
            play_file(self.speaker, 'piano.wav')

class TouchEvent:
    THRESHOLD_ADJUSTMENT = 400

    def __init__(self, name, onchange):
        self.name = name
        self.last = False
        self.onchange = onchange
        pin = getattr(board, name)
        self.touch = TouchIn(pin)
        self.touch.threshold += self.THRESHOLD_ADJUSTMENT

    def process(self):
        current = self.touch.value
        if current != self.last:
            self.onchange(self.name, current)
            self.last = current

enable_speakers()
speaker = AudioOut(board.SPEAKER)
handler = Handler(speaker)
event = TouchEvent('A1', handler.handle)
while True:
    event.process()
```

# 工作原理...

所定义的`Handler`类将用于响应触摸事件。它在构造函数中期望一个参数，即将处理音频播放的`speaker`对象。此对象保存到对象实例的属性中。然后，该类定义了一个方法，每次发生触摸事件时都会调用该方法。该方法期望第一个参数是触摸板的名称，第二个参数是指示触摸板状态的布尔值。

当调用该方法时，它会检查触摸板是否被触摸；如果是，则调用`play_file`函数播放钢琴声音。本教程中的其余代码支持不断检查新触摸事件并调用已定义的处理程序的过程。

# 还有更多...

在这个例子中，配方只会在按下单个触摸板时播放一个声音。但是，它也为我们扩展提供了核心结构。您可以尝试使用这个配方并尝试两个触摸板，每个都播放不同的声音。您可以通过将多个定义的事件对象连接到不同的处理程序来实现这一点。在以后的配方中，您将看到单个事件类定义和单个处理程序类定义可以用于连接到四个不同的触摸板并播放四种不同的声音。

# 另见

以下是一些参考资料：

+   `AudioOut`类的源代码可以在[`github.com/adafruit/circuitpython/blob/3.x/shared-bindings/audioio/AudioOut.c`](https://github.com/adafruit/circuitpython/blob/3.x/shared-bindings/audioio/AudioOut.c)找到。

+   `WaveFile`类的源代码可以在[`github.com/adafruit/circuitpython/blob/3.x/shared-bindings/audioio/WaveFile.c`](https://github.com/adafruit/circuitpython/blob/3.x/shared-bindings/audioio/WaveFile.c)找到。

# 创建一个触摸处理程序来点亮像素

在这个配方中，我们将创建一个触摸处理程序，通过播放声音和点亮像素来对触摸事件做出反应。当触摸传感器被触发时，处理程序将播放声音并点亮特定的像素。当触摸传感器检测到您已经松开手指时，点亮的特定像素将关闭。

通过这种方式，您可以听到并看到板子对每个配置的触摸板的独特反应。这个配方展示了一种有用的方式，可以根据不同的触发输入创建不同类型的输出。当您添加一些独特的音频和视觉输出以对不同类型的人类输入做出反应时，许多项目可以变得生动起来。

# 准备好

您需要访问 Circuit Playground Express 上的 REPL 才能运行本配方中提供的代码。

# 如何做...

让我们来看看这个配方所需的步骤：

1.  使用 REPL 运行以下代码行。这将设置扬声器并创建一个与像素交互的对象：

```py
>>> from touchio import TouchIn
>>> from digitalio import DigitalInOut
>>> from audioio import WaveFile, AudioOut
>>> from neopixel import NeoPixel
>>> import board
>>> 
>>> PIXEL_COUNT = 10
>>> 
>>> def enable_speakers():
...     speaker_control = DigitalInOut(board.SPEAKER_ENABLE)
...     speaker_control.switch_to_output(value=True)
...     
...     
... 
>>> def play_file(speaker, path):
...     file = open(path, "rb")
...     audio = WaveFile(file)
...     speaker.play(audio)
... 
>>> 
>>> enable_speakers()
>>> speaker = AudioOut(board.SPEAKER)
>>> pixels = NeoPixel(board.NEOPIXEL, PIXEL_COUNT)
>>> pixels.brightness = 0.05
```

1.  在下一块代码中，我们将定义一个`Handler`类，然后创建一个实例，将对象传递给它来处理扬声器和像素：

```py
>>> class Handler:
...     def __init__(self, speaker, pixels):
...         self.speaker = speaker
...         self.pixels = pixels
...         
...     def handle(self, name, state):
...         if state:
...             play_file(self.speaker, 'piano.wav')
...             self.pixels[0] = 0xFF0000
...         else:
...             self.pixels[0] = 0x000000
...             
... 
>>> handler = Handler(speaker, pixels)
```

1.  当您运行下一块代码时，您应该听到扬声器上的钢琴声音，并且第一个像素应该变成红色：

```py
>>> handler.handle('A1', True)
```

1.  运行下一块代码，您应该看到第一个像素灯关闭：

```py
>>> handler.handle('A1', False)
```

1.  以下代码应放入`main.py`文件中：

```py
from touchio import TouchIn
from digitalio import DigitalInOut
from audioio import WaveFile, AudioOut
from neopixel import NeoPixel
import board

PIXEL_COUNT = 10

def enable_speakers():
    speaker_control = DigitalInOut(board.SPEAKER_ENABLE)
    speaker_control.switch_to_output(value=True)

def play_file(speaker, path):
    file = open(path, "rb")
    audio = WaveFile(file)
    speaker.play(audio)

class Handler:
    def __init__(self, speaker, pixels):
        self.speaker = speaker
        self.pixels = pixels

    def handle(self, name, state):
        if state:
            play_file(self.speaker, 'piano.wav')
            self.pixels[0] = 0xFF0000
        else:
            self.pixels[0] = 0x000000

class TouchEvent:
    THRESHOLD_ADJUSTMENT = 400

    def __init__(self, name, onchange):
        self.name = name
        self.last = False
        self.onchange = onchange
        pin = getattr(board, name)
        self.touch = TouchIn(pin)
        self.touch.threshold += self.THRESHOLD_ADJUSTMENT

    def process(self):
        current = self.touch.value
        if current != self.last:
            self.onchange(self.name, current)
            self.last = current

enable_speakers()
speaker = AudioOut(board.SPEAKER)
pixels = NeoPixel(board.NEOPIXEL, PIXEL_COUNT)
pixels.brightness = 0.05
handler = Handler(speaker, pixels)
event = TouchEvent('A1', handler.handle)
while True:
    event.process()
```

当执行脚本时，它将在触摸 A1 时播放钢琴声音并点亮一个像素。

# 它是如何工作的...

定义的`Handler`类将在检测到触摸事件时播放声音并点亮像素。这个类的构造函数接受扬声器和像素对象，并将它们保存到实例中以供以后使用。每次调用`handle`方法时，它都会检查触摸板当前是否被按下。

如果按下，一个像素会点亮并播放声音。如果释放垫子，同一个像素将关闭。脚本的其余部分负责初始化扬声器和像素，以便它们可以被处理程序使用，并创建一个无限循环，每次检测到事件时都会调用处理程序。

# 还有更多...

这个配方中的脚本每次都会点亮一个特定的像素。您可以扩展它，每次按下触摸板时使用随机颜色。有多种方法可以在按下触摸板的时间越长时点亮更多的像素。另一个有趣的实验是在每次事件发生时让板子播放随机声音。现在我们已经添加了声音和光，有更多的选择可以将创造力应用到这个项目中，并创建一个更独特的项目。

# 另见

以下是一些参考资料：

+   可以在[`learn.adafruit.com/circuit-playground-express-piano-in-the-key-of-lime/`](https://learn.adafruit.com/circuit-playground-express-piano-in-the-key-of-lime/)找到将酸橙连接到 Circuit Playground Express 的项目。

+   `TouchIn`类的源代码可以在[`github.com/adafruit/circuitpython/blob/3.x/shared-bindings/touchio/TouchIn.c`](https://github.com/adafruit/circuitpython/blob/3.x/shared-bindings/touchio/TouchIn.c)找到。

# 创建事件循环以处理所有触摸事件

本章的最后一个教程将本章中的所有先前教程结合起来，以完成香蕉音乐机。除了以前的教程之外，我们还需要创建一个事件循环，将所有这些逻辑结合到一个结构中，以处理所有四个触摸板及其相关的音频文件和像素。完成本教程后，您将能够创建通用的事件循环和处理程序，以满足您可能创建的嵌入式项目的不同需求。

# 准备工作

您需要访问 Circuit Playground Express 上的 REPL 才能运行本教程中提供的代码。

# 操作步骤...

让我们来看看完成本教程所需的步骤：

1.  在 REPL 中运行以下代码行：

```py
>>> from touchio import TouchIn
>>> from digitalio import DigitalInOut
>>> from audioio import WaveFile, AudioOut
>>> from neopixel import NeoPixel
>>> import board
>>> 
>>> PIXEL_COUNT = 10
>>> TOUCH_PADS = ['A1', 'A2', 'A5', 'A6']
>>> SOUND = dict(
...     A1='hit.wav',
...     A2='piano.wav',
...     A5='tin.wav',
...     A6='wood.wav',
... )
>>> RGB = dict(
...     black=0x000000,
...     white=0xFFFFFF,
...     green=0x00FF00,
...     red=0xFF0000,
...     yellow=0xFFFF00,
... )
>>> PIXELS = dict(
...     A1=(6, RGB['white']),
...     A2=(8, RGB['red']),
...     A5=(1, RGB['yellow']),
...     A6=(3, RGB['green']),
... )
```

1.  我们现在已经导入了我们脚本中所需的所有库，并创建了我们脚本中所需的主要数据结构。运行下一个代码块，扬声器应该会播放钢琴声音：

```py
>>> def play_file(speaker, path):
...     file = open(path, "rb")
...     audio = WaveFile(file)
...     speaker.play(audio)
...     
... 
>>> def enable_speakers():
...     speaker_control = DigitalInOut(board.SPEAKER_ENABLE)
...     speaker_control.switch_to_output(value=True)
...     
... 
>>> enable_speakers()
>>> speaker = AudioOut(board.SPEAKER)
>>> play_file(speaker, SOUND['A2'])
```

1.  运行下一个代码块以创建我们事件处理程序的实例：

```py
>>> class Handler:
...     def __init__(self, speaker, pixels):
...         self.speaker = speaker
...         self.pixels = pixels
...         
...     def handle(self, name, state):
...         pos, color = PIXELS[name]
...         if state:
...             play_file(self.speaker, SOUND[name])
...             self.pixels[pos] = color
...         else:
...             self.pixels[pos] = RGB['black']
...             
... 
>>> class TouchEvent:
...     THRESHOLD_ADJUSTMENT = 400
...     
...     def __init__(self, name, onchange):
...         self.name = name
...         self.last = False
...         self.onchange = onchange
...         pin = getattr(board, name)
...         self.touch = TouchIn(pin)
...         self.touch.threshold += self.THRESHOLD_ADJUSTMENT
...         
...     def process(self):
...         current = self.touch.value
...         if current != self.last:
...             self.onchange(self.name, current)
...             self.last = current
...             
... 
>>> pixels = NeoPixel(board.NEOPIXEL, PIXEL_COUNT)
>>> pixels.brightness = 0.05
>>> handler = Handler(speaker, pixels)
```

1.  运行下一个代码块以模拟在 2 号触摸板上的触摸事件。您应该听到钢琴声音，并看到一个像素变红：

```py
>>> handler.handle('A2', True)
```

1.  以下代码应放入`main.py`文件中，当执行时，每次按下四个配置的触摸板之一时，它将播放不同的声音并点亮不同的像素：

```py
from touchio import TouchIn
from digitalio import DigitalInOut
from audioio import WaveFile, AudioOut
from neopixel import NeoPixel
import board

PIXEL_COUNT = 10
TOUCH_PADS = ['A1', 'A2', 'A5', 'A6']
SOUND = dict(
    A1='hit.wav',
    A2='piano.wav',
    A5='tin.wav',
    A6='wood.wav',
)
RGB = dict(
    black=0x000000,
    white=0xFFFFFF,
    green=0x00FF00,
    red=0xFF0000,
    yellow=0xFFFF00,
)
PIXELS = dict(
    A1=(6, RGB['white']),
    A2=(8, RGB['red']),
    A5=(1, RGB['yellow']),
    A6=(3, RGB['green']),
)

def play_file(speaker, path):
    file = open(path, "rb")
    audio = WaveFile(file)
    speaker.play(audio)

def enable_speakers():
    speaker_control = DigitalInOut(board.SPEAKER_ENABLE)
    speaker_control.switch_to_output(value=True)

class Handler:
    def __init__(self, speaker, pixels):
        self.speaker = speaker
        self.pixels = pixels

    def handle(self, name, state):
        pos, color = PIXELS[name]
        if state:
            play_file(self.speaker, SOUND[name])
            self.pixels[pos] = color
        else:
            self.pixels[pos] = RGB['black']

class TouchEvent:
    THRESHOLD_ADJUSTMENT = 400

    def __init__(self, name, onchange):
        self.name = name
        self.last = False
        self.onchange = onchange
        pin = getattr(board, name)
        self.touch = TouchIn(pin)
        self.touch.threshold += self.THRESHOLD_ADJUSTMENT

    def process(self):
        current = self.touch.value
        if current != self.last:
            self.onchange(self.name, current)
            self.last = current

def main():
    enable_speakers()
    speaker = AudioOut(board.SPEAKER)
    pixels = NeoPixel(board.NEOPIXEL, PIXEL_COUNT)
    pixels.brightness = 0.05
    handler = Handler(speaker, pixels)
    events = [TouchEvent(i, handler.handle) for i in TOUCH_PADS]
    while True:
        for event in events:
            event.process()

main()
```

# 工作原理...

`main`函数包含我们的事件循环。该函数首先初始化扬声器和像素。然后，它创建一个单个处理程序实例。这个单个处理程序实例足够通用，可以用作所有四个触摸板的处理程序。

然后，创建一个事件列表，其中每个事件都连接到四个触摸板中的一个。启动一个无限循环，循环遍历每个事件对象，并调用其`process`方法，以便在检测到触摸板状态变化时调用事件处理程序。

脚本顶部的常量用于指定要使用的触摸板的名称，每个触摸板要播放的声音文件，以及按下触摸板时要设置的像素位置和颜色。

# 还有更多...

该脚本大量使用了多种数据结构，以便在函数和类定义中不需要硬编码值。使用字典作为自然结构，将每个触摸板名称映射到应该播放的音频文件名。使用数据结构列表定义将连接的触摸板的名称。最后，使用元组的字典将触摸板映射到其相关的像素位置和颜色。Python 具有丰富的数据结构集，有效利用时可以使代码更易读和易维护。

该项目将四根香蕉连接到板上，每根香蕉触摸时都会播放不同的声音。由于代码被构造为立即响应每次触摸，所以甚至可以让两个人同时玩。下一张照片显示了两个人，每人手持一对香蕉，创作音乐并控制板上的像素：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mcpy-cb/img/1f1a81c1-81e3-46f5-9b39-db853ae75ba1.png)

# 另请参阅

以下是一些参考资料：

+   有关使用 CircuitPython 提供音频输出的文档可以在[`learn.adafruit.com/adafruit-circuit-playground-express/circuitpython-audio-out`](https://learn.adafruit.com/adafruit-circuit-playground-express/circuitpython-audio-out)找到。

+   `NeoPixel`类的源代码可以在[`github.com/adafruit/Adafruit_CircuitPython_NeoPixel`](https://github.com/adafruit/Adafruit_CircuitPython_NeoPixel)找到。
