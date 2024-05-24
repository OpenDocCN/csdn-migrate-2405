# MicroPython 秘籍（五）

> 原文：[`zh.annas-archive.org/md5/EE140280D367F2C84B38C2F3034D057C`](https://zh.annas-archive.org/md5/EE140280D367F2C84B38C2F3034D057C)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十三章：与 Adafruit FeatherWing OLED 交互

本章将向您介绍 Adafruit FeatherWing 有机发光二极管（OLED）显示器。Adafruit Feather 是一个标准的板安排，允许将这些板升级插入到彼此之间。它们可以堆叠在一起或作为独立板运行。FeatherWings 是可以插入这些 Feather 板的附件。

在本章中，我们将把 Adafruit FeatherWing OLED 显示器插入 Adafruit Feather HUZZAH ESP8266 MicroPython 板中。这将创建一个功能强大的组合，即具有显示器的微控制器和互联网连接功能，可以输出文本图形，并使用显示器上的三个硬件按钮与用户交互。

本章的配方将帮助您构建一系列项目。您可以制作小型 MicroPython 板，显示一个菜单，您可以通过导航，选择的每个操作都可以将传感器数据发布到网络上的其他服务器或互联网上。您还可以使用它按命令从服务器获取数据并在屏幕上显示。本章将重点介绍显示器的所有主要功能，如显示文本、线条和矩形图形，以及与显示器配备的内置按钮进行交互。

本章将涵盖以下内容：

+   使用 GPIO 引脚检测按钮按下

+   连接到 SSD1306 显示器

+   填充和清除显示器

+   在显示器上设置像素

+   在显示器上绘制线条和矩形

+   在显示器上写文本

+   在显示器上反转颜色

# Adafruit FeatherWing OLED

FeatherWing OLED 显示器使用了一种 OLED，与其他显示技术相比有许多优点。例如，它的功耗比其他显示技术低得多。这使得它非常适用于嵌入式项目，其中需要尽可能降低功耗要求。

OLED 还具有比其他显示技术更高的对比度，使得显示的文本和图形更清晰。屏幕配备了三个用户按钮，并且在引脚和屏幕分辨率方面有许多不同的选项。以下照片显示了其中一个显示器连接到 Adafruit Feather HUZZAH ESP8266 板上：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mcpy-cb/img/71a2df18-6864-4813-a115-e48db0e6c628.png)

该板有一个配置，带有需要焊接的松散引脚，另一个版本带有组装好的引脚，无需焊接。在上一张照片中显示的板使用了组装好的引脚，可以直接插入 ESP8266 主板，无需焊接。

# 购买地址

本章使用了组装好的 Adafruit FeatherWing OLED - 128 x 32 OLED 附加板。这个 FeatherWing 可以直接从 Adafruit 购买([`www.adafruit.com/product/3045`](https://www.adafruit.com/product/3045))。

# 技术要求

本章的代码文件可以在以下 GitHub 存储库的`Chapter13`文件夹中找到：[`github.com/PacktPublishing/MicroPython-Cookbook`](https://github.com/PacktPublishing/MicroPython-Cookbook)。

本章使用了 Adafruit Feather HUZZAH ESP8266 板和组装好的 Adafruit FeatherWing OLED - 128 x 32 OLED 附加板。本章中的所有配方都使用了 CircuitPython 3.1.2。

本章需要 CircuitPython 库中的一些特定模块，它们将在每个配方的开头提到。有关下载和提取这些库的详细信息，您可以参考《使用 MicroPython 入门》中的*更新 CircuitPython 库*配方。本章中的所有配方都使用了 20190212 版本的 CircuitPython 库。

# 使用 GPIO 引脚检测按钮按下

这个食谱将演示如何检查 Adafruit FeatherWing OLED 附带的三个推按钮的状态。我们将轮询这三个按钮，并不断打印它们的状态，以便我们可以检测按钮被按下和释放的时刻。

这些推按钮中的每一个都连接到不同的 GPIO 引脚，因此我们将使用一个字典将按钮名称映射到它们关联的 GPIO 引脚。板上的物理按钮标有*A*、*B*和*C*。我们将使用相同的命名将按钮事件映射到脚本中的打印语句。

这个食谱很有用，因为它将使您的项目能够根据按下的按钮采取不同的操作。因为这个板上有三个按钮，所以您可以根据自己的应用设计有很多选择。例如，您可以将两个按钮作为上下菜单选项，而第三个按钮可以允许用户选择菜单选项。或者，您可以有一个按钮增加一个设置值，另一个按钮减少一个设置值。

# 准备工作

您需要访问 ESP8266 上的 REPL 来运行本食谱中提供的代码。

# 如何操作...

让我们执行以下步骤：

1.  在 REPL 中运行以下代码行：

```py
>>> from machine import Pin
>>> import time
>>> 
>>> PINS = dict(a=0, b=16, c=2)
```

1.  我们现在已经导入了必要的 Python 库，并设置了一个`PINS`字典，它将按钮名称映射到它们关联的 GPIO 引脚，如下所示：

```py
>>> def get_buttons():
...     return dict(
...         a=Pin(PINS['a'], Pin.IN, Pin.PULL_UP),
...         b=Pin(PINS['b']),
...         c=Pin(PINS['c'], Pin.IN, Pin.PULL_UP),
...     )
...     
...     
... 
>>> buttons = get_buttons()
```

1.  `get_buttons`函数将返回一个将每个按钮映射到其关联的`Pin`对象的字典。在这个板上，按钮 A 和 C 需要配置`PULL_UP`，而按钮 B 不需要。运行以下代码块，它将返回一个值`1`，表示按钮 A 没有被按下：

```py
>>> buttons['a'].value()
1
```

1.  在运行下一段代码块时按住按钮 A，`Pin`值将显示按钮正在被按下：

```py
>>> buttons['a'].value()
0
```

1.  下一段代码创建了`names`列表，其中包含按钮名称的排序列表。我们定义了一个名为`get_status`的函数，它将返回三个按钮的状态：

```py
>>> names = sorted(PINS.keys())
>>> 
>>> def get_status(names, buttons):
...     items = [format(i, buttons) for i in names]
...     return ' '.join(items)
...     
...     
... 
>>> 
```

1.  运行时，以下代码块调用`get_status`函数并返回推按钮的当前状态：

```py
>>> get_status(names, buttons)
'a: False b: False c: False'
```

1.  在运行下一段代码块时按住按钮 B，推按钮 B 的状态将显示为正在被按下：

```py
>>> get_status(names, buttons)
'a: False b: True c: False'
```

1.  以下代码应添加到`main.py`文件中：

```py
from machine import Pin
import time

PINS = dict(a=0, b=16, c=2)

def format(name, buttons):
    pressed = not buttons[name].value()
    return '{name}: {pressed}'.format(name=name, pressed=pressed)

def get_status(names, buttons):
    items = [format(i, buttons) for i in names]
    return ' '.join(items)

def get_buttons():
    return dict(
        a=Pin(PINS['a'], Pin.IN, Pin.PULL_UP),
        b=Pin(PINS['b']),
        c=Pin(PINS['c'], Pin.IN, Pin.PULL_UP),
    )

def main():
    names = sorted(PINS.keys())
    buttons = get_buttons()
    while True:
        status = get_status(names, buttons)
        print(status)
        time.sleep(0.1)

main()
```

当执行这个脚本时，它将不断打印出每个按钮的状态，每个循环之间延迟`0.1`秒。

# 工作原理...

这个食谱定义了一个名为`PINS`的数据结构，它将三个按钮分别映射到 ESP8266 上的正确 GPIO 引脚。`get_buttons`函数为这些按钮中的每一个创建了带有正确`PULL_UP`设置的`Pin`对象。`get_buttons`函数在`main`函数中被调用，并且返回的字典被保存在`buttons`变量中。

`names`变量只是按钮名称的排序列表。它被创建以确保状态更新总是按字母顺序呈现。`get_status`函数循环遍历每个按钮，并调用`format`函数生成状态行，每次检查状态时都会打印出来。主循环进入无限循环，在每次迭代中打印按钮状态，然后暂停`0.1`秒，然后继续下一个循环。

# 还有更多...

当使用 GPIO 引脚与推按钮交互时，它们需要被正确配置。需要使用正确的引脚，并且需要正确应用`PULL_UP`设置到每个引脚配置中。这些设置通常可以在板的文档中找到。

在这块板上，按钮 B 不需要设置`PULL_UP`的原因是按钮和硬件电平已经包含了 100k 的上拉值，因此解决了 ESP8266 在引脚 16 上没有内部上拉的问题。然而，其他两个按钮需要设置`PULL_UP`。

# 另请参阅

更多信息，请参考以下文档：

+   关于 FeatherWing OLED 引脚分配的更多文档可以在[`learn.adafruit.com/adafruit-oled-featherwing/pinouts`](https://learn.adafruit.com/adafruit-oled-featherwing/pinouts)找到。

+   关于`machine`模块中的`Pin`对象的更多文档可以在[`docs.micropython.org/en/latest/library/machine.Pin.html#machine.Pin`](https://docs.micropython.org/en/latest/library/machine.Pin.html#machine.Pin)找到。

# 连接到 SSD1306 显示器

本教程将向你展示如何使用`adafruit_ssd1306`库连接到 FeatherWing OLED 显示器。本教程将向你展示如何初始化连接到的**I2C**总线。然后，我们可以创建一个通过 I2C 总线连接到显示器的`SSD1306_I2C`对象。

这个教程将在很多方面帮助你；有一整套组件可以使用 I2C 连接，所以这个教程将让你接触到这项技术，以便在你自己的项目中需要使用它时，你会对它很熟悉。

你将了解如何使用可以与 MicroPython 一起工作的显示库，然后可以将其包含在任何你想要添加显示器的项目中。

# 准备工作

你需要访问 ESP8266 上的 REPL 来运行本教程中提供的代码。本教程使用的 CircuitPython 库版本是 20190212。

# 如何操作...

让我们执行以下步骤：

1.  下载 CircuitPython 库包。你需要`.mpy`和`.py`版本的库包。

1.  将这两个`.zip`文件解压到你的计算机上。

1.  在 ESP8266 上安装所有库包中的所有库是不必要的。

1.  连接到显示器需要三个特定的库。

1.  `adafruit_bus_device`和`adafruit_framebuf`库应该在 ESP8266 上安装它们的`.mpy`文件。这些库的文件应该被传输到 ESP8266 并放入`.lib`文件夹中。

1.  在 REPL 中执行以下代码以验证这两个库是否正确安装在板上：

```py
>>> import adafruit_bus_device
>>> import adafruit_framebuf
```

1.  `adafruit_ssd1306`库应该在库中有`adafruit_ssd1306.py`文件的`.py`版本。

1.  该库将尝试使用内置的`framebuf` MicroPython 库而不是`adafruit_framebuf`。如果使用`framebuf`库进行帧缓冲区操作，该库将无法连接到显示。为了解决这个问题，在与`adafruit_ssd1306.py`相同的目录中下载并运行`fix_framebuf_import.py`文件。你可以在书的 GitHub 存储库的`Chapter13`文件夹中找到这个脚本。

1.  将修复后的`adafruit_ssd1306.py`文件上传到板的根目录。

1.  运行以下代码块以验证`adafruit_ssd1306`库是否正确安装在板上：

```py
>>> import adafruit_ssd1306
>>> 
```

1.  在这个阶段，所有额外的库都已经成功安装和导入。运行以下代码块以导入初始化 I2C 总线所需的库：

```py
>>> import board
>>> import busio
```

1.  运行以下代码块以初始化 I2C 总线：

```py
>>> i2c = busio.I2C(board.SCL, board.SDA)
>>> 
```

1.  运行以下代码以创建一个`SSD1306_I2C`显示对象：

```py
>>> buttons['a'].value()
>>> oled = adafruit_ssd1306.SSD1306_I2C(128, 32, i2c)
>>>
```

1.  将以下代码添加到`main.py`文件中：

```py
import adafruit_ssd1306
import board
import busio

def main():
    print('initialize I2C bus')
    i2c = busio.I2C(board.SCL, board.SDA)
    print('create SSD1306_I2C object')
    oled = adafruit_ssd1306.SSD1306_I2C(128, 32, i2c)
    print('ALL DONE')

main()
```

当执行这个脚本时，它将初始化 I2C 总线并创建一个`SSD1306_I2C`对象。

# 工作原理...

与 FeatherWing OLED 交互所需的库不是 CircuitPython 固件的一部分，因此在使用之前需要进一步安装。需要安装三个库，它们分别是`adafruit_ssd1306`、`adafruit_bus_device`和`adafruit_framebuf`。

`adafruit_ssd1306`库是我们将要交互的主要库，它依赖于我们已安装的其他库才能正常工作。安装这些库后，我们可以开始导入它们并使用它们的代码连接到显示器。第一步是初始化 I2C 总线。通过创建一个 I2C 对象并将其引用传递给 SCL 和 SDA 引脚来完成此操作。然后将对象保存在`i2c`变量中。通过传递值`128`和`32`来创建一个`SSD1306_I2C`对象，这些值是指显示分辨率，因为我们使用的是 128 x 32 OLED。传递的另一个参数是`i2c`对象。

# 还有更多...

I2C 是一种非常流行的协议，适用于各种设备。 I2C 相对简单，易于连接和使用，这是它被广泛用于许多微控制器的原因之一。它只需要两根线连接，并且可以使用许多微控制器板上的通用 I/O 引脚。

单个连接可以控制多个设备，这增加了其灵活性。但是，与其他协议相比，这种协议的速度较慢是其缺点之一。这意味着我们可以用它来控制小型单色显示器，但是如果我们想要控制分辨率更高、颜色更多的显示器，那么它的速度就不够快了。

# 另请参阅

有关更多信息，您可以参考以下内容：

+   有关 I2C 协议的更多详细信息，请访问[`i2c.info/`](https://i2c.info/)。

+   有关安装 CircuitPython SSD1306 库的更多文档，请访问[`learn.adafruit.com/adafruit-oled-featherwing/circuitpython-and-python-setup`](https://learn.adafruit.com/adafruit-oled-featherwing/circuitpython-and-python-setup)。

# 填充和清除显示

本教程将向您展示如何使用`adafruit_ssd1306`库连接到 FeatherWing OLED 显示器。它将演示如何初始化连接到 OLED 显示器的 I2C 总线。然后，我们可以创建一个使用 I2C 总线连接到显示器的`SSD1306_I2C`对象。本教程将以多种方式帮助您。

有一整套组件可以使用 I2C 连接；本教程将使您了解这项技术，以便在自己的项目中需要使用它时熟悉它。本教程还将帮助您进行使用可以与 MicroPython 一起工作的显示库的第一步，然后可以将其包含在您可能想要添加显示器的任何项目中。

# 准备工作

您需要访问 ESP8266 上的 REPL 来运行本教程中提供的代码。

# 如何操作...

让我们执行以下步骤：

1.  使用 REPL 运行以下代码行：

```py
>>> import adafruit_ssd1306
>>> import board
>>> import busio
```

1.  所需的库现在都已导入。运行下一个代码块以创建`i2c`对象和名为`oled`的`SSD1306_I2C`对象：

```py
>>> i2c = busio.I2C(board.SCL, board.SDA)
>>> oled = adafruit_ssd1306.SSD1306_I2C(128, 32, i2c)
```

1.  使用以下代码块，将屏幕上的所有像素设置为白色，并通过调用`show`方法应用更改：

```py
>>> oled.fill(1)
>>> oled.show()
```

1.  现在，我们将使用以下代码块关闭屏幕上的所有像素：

```py
>>> oled.fill(0)
>>> oled.show()
```

1.  以下代码块将循环 10 次，并重复打开和关闭屏幕上的所有像素，创建闪烁屏幕的效果：

```py
>>> for i in range(10):
...     oled.fill(1)
...     oled.show()
...     oled.fill(0)
...     oled.show()
...     
...     
... 
>>>
```

1.  将以下代码添加到`main.py`文件中：

```py
import adafruit_ssd1306
import board
import busio

def main():
    i2c = busio.I2C(board.SCL, board.SDA)
    oled = adafruit_ssd1306.SSD1306_I2C(128, 32, i2c)
    for i in range(10):
        oled.fill(1)
        oled.show()
        oled.fill(0)
        oled.show()

main()
```

当执行此脚本时，屏幕将闪烁黑白 10 次。

# 它是如何工作的...

`main`函数首先设置了`i2c`对象，并将`SSD1306_I2C`对象保存为名为`oled`的变量。`oled`对象有两种方法，我们将在本教程中使用。`fill`方法接收一个参数，并将显示器上的所有像素填充为白色或黑色。如果提供`1`，则像素将变为白色，否则将变为黑色（或关闭）。

在每次更改后必须调用`show`方法，以使更改在显示器上生效。开始一个`for`循环，循环 10 次，在每次迭代期间将显示器变为全白，然后变为全黑。

# 还有更多...

`fill`和`show`方法是与显示器交互时的绝佳起点，因为它们相对容易使用。尽管它们看起来很简单，但它们在许多操作中都是必需的。

在后续的示例中，我们将探讨如何绘制线条、矩形和文本。在所有这些情况下，我们需要调用`show`来将更改呈现到屏幕上。我们还经常调用`fill`来清除屏幕上的内容，然后再在显示器上写入或绘制新内容。

# 另请参阅

有关更多信息，您可以参考以下内容：

+   可以在[`circuitpython.readthedocs.io/projects/ssd1306/en/latest/examples.html`](https://circuitpython.readthedocs.io/projects/ssd1306/en/latest/examples.html)找到使用`fill`和`show`的示例。

+   有关`SSD1306_I2C`对象的更多文档可以在[`circuitpython.readthedocs.io/projects/ssd1306/en/latest/api.html`](https://circuitpython.readthedocs.io/projects/ssd1306/en/latest/api.html)找到。

# 在显示器上设置像素

本示例将演示如何在屏幕上打开和关闭单个像素。该示例首先通过设置具有特定*x*和*y*坐标的像素来指示打开或关闭。然后，我们将创建一个简单的动画，重复在特定方向上绘制像素，从而创建一个不断增长长度的线条。我们将把这个简单的线条动画放入自己的函数中，以便我们可以多次调用它并创建一种锯齿线条动画。

当您开始控制显示器并希望控制单个像素时，您会发现这个示例非常有用。控制单个像素的操作成为生成更复杂图形的基本组件。

# 准备工作

您需要在 ESP8266 上访问 REPL 才能运行本示例中提供的代码。

# 操作步骤...

让我们执行以下步骤：

1.  在 REPL 中运行以下代码行：

```py
>>> import adafruit_ssd1306
>>> import board
>>> import busio
>>> 
>>> BLACK = 0
>>> WHITE = 1
>>> 
>>> i2c = busio.I2C(board.SCL, board.SDA)
>>> oled = adafruit_ssd1306.SSD1306_I2C(128, 32, i2c)
```

1.  定义`BLACK`和`WHITE`常量，它们代表两种可能的像素颜色值。然后设置`i2c`和`oled`对象。以下代码块将清除屏幕上的内容：

```py
>>> oled.fill(BLACK)
>>> oled.show()
```

1.  以下代码块将为白色绘制像素(*x*, *y*)，即位置(`0`, `0`)：

```py
>>> oled.pixel(0, 0, WHITE)
>>> oled.show()
```

1.  以下代码块将关闭位置(`0`, `0`)处的像素，将其颜色设置为黑色：

```py
>>> oled.pixel(0, 0, BLACK)
>>> oled.show()
```

1.  以下代码将把位置(`10`, `30`)处的像素颜色设置为白色：

```py
>>> oled.pixel(10, 30, WHITE)
>>> oled.show()
```

1.  以下代码块将清除屏幕，然后循环 10 次，逐个设置对角线上的像素，形成一个看起来像是不断增长的线条的动画：

```py
>>> oled.fill(BLACK)
>>> oled.show()
>>> 
>>> for i in range(10):
...     oled.pixel(i, i, WHITE)
...     oled.show()
...     
...     
... 
>>> 
```

1.  使用以下代码块，定义一个函数，该函数将从起始位置(`x`, `y`)开始执行线条动画，然后在*x*和*y*方向上移动一定的`count`次数：

```py
>>> def animate_pixel(oled, x, y, step_x, step_y, count):
...     for i in range(count):
...         x += step_x
...         y += step_y
...         oled.pixel(x, y, WHITE)
...         oled.show()
...         
...         
... 
>>> 
```

1.  以下代码块将清除屏幕并调用`animate_pixel`从位置(`0`, `0`)到(`30`, `30`)绘制由 30 个像素组成的线条：

```py
>>> oled.fill(BLACK)
>>> oled.show()
>>> animate_pixel(oled, x=0, y=0, step_x=1, step_y=1, count=30)
```

1.  然后，以下代码块将绘制从位置(`30`, `30`)到(`60`, `0`)的线条。该线条将在上一个动画完成的位置继续进行，但在不同的方向上移动：

```py
>>> animate_pixel(oled, x=30, y=30, step_x=1, step_y=-1, count=30)
```

1.  现在定义一个名为`zig_zag`的函数，它将绘制四个线条动画。每个动画将从上一个动画完成的位置继续进行，如下所示：

```py
>>> def zig_zag(oled):
...     animate_pixel(oled, x=0, y=0, step_x=1, step_y=1, count=30)
...     animate_pixel(oled, x=30, y=30, step_x=1, step_y=-1, 
...     count=30)
...     animate_pixel(oled, x=60, y=0, step_x=1, step_y=1, count=30)
...     animate_pixel(oled, x=90, y=30, step_x=1, step_y=-1, 
...     count=30)
...     
...     
... 
>>> 
```

1.  运行以下代码块以清除显示并运行`zig_zag`线条动画：

```py
>>> oled.fill(BLACK)
>>> oled.show()
>>> zig_zag(oled)
```

1.  将以下代码添加到`main.py`文件中：

```py
import adafruit_ssd1306
import board
import busio

BLACK = 0
WHITE = 1

def animate_pixel(oled, x, y, step_x, step_y, count):
    for i in range(count):
        x += step_x
        y += step_y
        oled.pixel(x, y, WHITE)
        oled.show()

def zig_zag(oled):
    animate_pixel(oled, x=0, y=0, step_x=1, step_y=1, count=30)
    animate_pixel(oled, x=30, y=30, step_x=1, step_y=-1, count=30)
    animate_pixel(oled, x=60, y=0, step_x=1, step_y=1, count=30)
    animate_pixel(oled, x=90, y=30, step_x=1, step_y=-1, count=30)

def main():
    i2c = busio.I2C(board.SCL, board.SDA)
    oled = adafruit_ssd1306.SSD1306_I2C(128, 32, i2c)
    zig_zag(oled)

main()
```

当执行此脚本时，它将以锯齿状模式绘制四个线条动画。

# 工作原理...

在`main`函数设置了`oled`对象之后，它调用`zig_zag`函数。`zig_zag`函数对`animate_pixel`函数进行了四次调用。每次调用都将线条移动到不同的对角方向。

每个新的线条动画都从上一个动画结束的地方开始，因此看起来像是从开始到结束的一个长动画。`animate_pixel`函数接受起始的*x*和*y*位置，并循环执行由`count`变量指定的次数。

在每次循环迭代中，*x*和*y*的值会根据指定的*x*和*y*步长值进行更改。一旦计算出新值，就会在该位置绘制一个像素，并调用`show`方法立即显示它。

# 还有更多...

这个教程从一些简单的设置像素开关和显示器上的不同位置的示例开始。然后，它扩展到进行简单的动画和更复杂的之字形动画。下面的照片展示了动画在显示器上完成后的样子：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mcpy-cb/img/dcdf610e-0164-4693-ac71-673c54ae39f0.png)

使用 MicroPython 附带的`math`模块可以创建许多不同类型的形状和动画。`sine`和`cosine`函数可用于绘制波形动画。我们还可以使用这些三角函数来绘制圆和椭圆。

# 另请参阅

有关更多信息，您可以参考以下内容：

+   有关在 FeatherWing OLED 上绘制像素的更多文档可以在[`learn.adafruit.com/adafruit-oled-featherwing/circuitpython-and-python-usage`](https://learn.adafruit.com/adafruit-oled-featherwing/circuitpython-and-python-usage)找到。

+   有关`math`模块中`sin`函数的更多文档可以在[`docs.micropython.org/en/latest/library/math.html#math.sin`](https://docs.micropython.org/en/latest/library/math.html#math.sin)找到。

# 在显示器上绘制线条和矩形

这个教程将演示如何使用`SSD1306_I2C`对象附带的方法，这将让我们绘制水平线、垂直线、正方形和矩形。现在我们可以超越设置单个像素，并探索使用`adafruit_ssd1306`显示库中的方法绘制更广泛范围的形状。

当您想要在显示器上绘制一些不同的形状时，您会发现这个教程很有用；例如，在显示器上构建一个简单的用户界面。显示器上有足够的分辨率来绘制代表用户界面不同部分的多个框和边框。

# 准备工作

您需要访问 ESP8266 上的 REPL 来运行本教程中提供的代码。

# 如何操作...

让我们执行以下步骤：

1.  在 REPL 中执行以下代码块：

```py
>>> import adafruit_ssd1306
>>> import board
>>> import busio
>>> 
>>> BLACK = 0
>>> WHITE = 1
>>> 
>>> i2c = busio.I2C(board.SCL, board.SDA)
>>> oled = adafruit_ssd1306.SSD1306_I2C(128, 32, i2c)
>>> oled.fill(BLACK)
>>> oled.show()
```

1.  导入必要的模块，创建`oled`，然后清除显示器。使用下面的代码块，绘制一条从坐标（`0`，`0`）开始，高度为 20 像素的垂直线：

```py
>>> oled.vline(x=0, y=0, height=20, color=WHITE)
>>> oled.show()
```

1.  类似地，使用 80 像素宽度从坐标（`0`，`0`）开始绘制一条水平线：

```py
>>> oled.hline(x=0, y=0, width=80, color=WHITE)
>>> oled.show()
```

1.  可以使用下一个代码块绘制一个位于（`0`，`0`）位置，宽度为 10 像素，高度为 20 像素的矩形：

```py
>>> oled.rect(x=0, y=0, width=10, height=20, color=WHITE)
>>> oled.show()
```

1.  以下函数将绘制`HI`文本。`H`字符将使用垂直线和一条水平线绘制。然后使用单个垂直线绘制`I`字符：

```py
>>> def draw_hi(oled):
...     print('drawing H')
...     oled.vline(x=50, y=0, height=30, color=WHITE)
...     oled.hline(x=50, y=15, width=30, color=WHITE)
...     oled.vline(x=80, y=0, height=30, color=WHITE)
...     oled.show()
...     print('drawing I')
...     oled.vline(x=100, y=0, height=30, color=WHITE)
...     oled.show()
...     
...     
... 
>>> 
```

1.  下面的代码块将清除屏幕并调用`draw_hi`函数在显示器上呈现消息`HI`：

```py
>>> oled.fill(BLACK)
>>> oled.show()
>>> draw_hi(oled)
drawing H
drawing I
>>> 
```

1.  使用下面的代码块，定义一个函数，该函数将执行涉及具有特定大小并且在每次迭代中通过步长*x*和*y*移动位置的方框动画：

```py
>>> def animate_boxes(oled, x, y, step_x, step_y, size, count):
...     for i in range(count):
...         oled.rect(x, y, width=size, height=size, color=WHITE)
...         oled.show()
...         x += step_x
...         y += step_y
...         
...         
... 
>>> 
```

1.  接下来，使用下面的代码块调用`animate_boxes`并绘制六个方框以对角线形式：

```py
>>> animate_boxes(oled, x=0, y=0, step_x=5, step_y=5, size=5, count=6)
```

1.  定义并调用`draw_x_boxes`函数，该函数在两条对角线上绘制一组方框，以创建由小方框组成的大字母`X`：

```py
>>> def draw_x_boxes(oled):
...     animate_boxes(oled, x=0, y=0, step_x=5, step_y=5, size=5, count=6)
...     animate_boxes(oled, x=0, y=25, step_x=5, step_y=-5, size=5, count=6)
...     
...     
... 
>>> 
>>> draw_x_boxes(oled)
```

1.  将以下代码添加到`main.py`文件中：

```py
import adafruit_ssd1306
import board
import busio

BLACK = 0
WHITE = 1

def draw_hi(oled):
    print('drawing H')
    oled.vline(x=50, y=0, height=30, color=WHITE)
    oled.hline(x=50, y=15, width=30, color=WHITE)
    oled.vline(x=80, y=0, height=30, color=WHITE)
    oled.show()
    print('drawing I')
    oled.vline(x=100, y=0, height=30, color=WHITE)
    oled.show()

def animate_boxes(oled, x, y, step_x, step_y, size, count):
    for i in range(count):
        oled.rect(x, y, width=size, height=size, color=WHITE)
        oled.show()
        x += step_x
        y += step_y

def draw_x_boxes(oled):
    animate_boxes(oled, x=0, y=0, step_x=5, step_y=5, size=5, count=6)
    animate_boxes(oled, x=0, y=25, step_x=5, step_y=-5, size=5, count=6)

def main():
    i2c = busio.I2C(board.SCL, board.SDA)
    oled = adafruit_ssd1306.SSD1306_I2C(128, 32, i2c)
    draw_x_boxes(oled)
    draw_hi(oled)

main()
```

当执行此脚本时，它将绘制一个由小方块组成的字母`X`，并绘制由垂直和水平线组成的`HI`文本。

# 它是如何工作的...

`draw_hi`函数使用`oled`对象上的`vline`和`hline`方法来绘制构成`H`的三条线。在绘制字母`H`之后，使用`vline`绘制垂直线来表示字母`I`。

调用`draw_x_boxes`函数将依次调用`animate_boxes`函数。对`animate_boxes`函数的第一次调用会沿对角线绘制六个方框，以形成`X`字符的第一部分。对`animate_boxes`的第二次调用也会绘制六个方框，但起始位置不同，并且方向也不同。第二次调用将穿过第一行以形成`X`字符。

# 还有更多...

线条绘制和矩形绘制方法可以以许多不同的方式组合，以创建各种形状和图纸。下面的照片显示了一旦在这个示例中运行`main.py`脚本，显示将会是什么样子：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mcpy-cb/img/b17657f1-6db0-40b9-a81b-501a016c42e2.png)

在下一个示例中，我们将学习如何在显示屏上绘制文本。将盒子和线条绘制结合起来，然后在显示屏的不同部分呈现文本非常有用。

# 另请参阅

有关更多信息，您可以参考以下内容：

+   有关 FeatherWing OLED 的主要功能的更多文档可以在[`learn.adafruit.com/adafruit-oled-featherwing/overview`](https://learn.adafruit.com/adafruit-oled-featherwing/overview)找到。

+   有关`busio`模块的更多文档可以在[`circuitpython.readthedocs.io/en/3.x/shared-bindings/busio/__init__.html`](https://circuitpython.readthedocs.io/en/3.x/shared-bindings/busio/__init__.html)找到。

# 在显示屏上写字

这个示例将演示如何将文本输出到 FeatherWing OLED。该示例将向您展示如何控制要显示的文本的位置和内容。将创建一个文本动画来执行显示倒计时，然后创建一个函数来同时显示所有小写字母、大写字母和数字字符。

这个示例将在您希望使用您的设备与人们交流一些信息时帮助您。因为显示可以显示三行文本，所以它为呈现各种信息提供了很大的空间。

# 准备工作

您需要访问 ESP8266 上的 REPL 来运行本示例中提供的代码。

# 如何做...

让我们执行以下步骤：

1.  下载 CircuitPython 库包。

1.  将`.zip`文件包解压到您的计算机上。

1.  复制位于 ESP8266 根文件夹包中的`font5x8.bin`字体文件。

1.  使用 REPL 运行以下代码行：

```py
>>> import adafruit_ssd1306
>>> import board
>>> import busio
>>> 
>>> BLACK = 0
>>> WHITE = 1
>>> 
>>> i2c = busio.I2C(board.SCL, board.SDA)
>>> oled = adafruit_ssd1306.SSD1306_I2C(128, 32, i2c)
>>> oled.fill(BLACK)
>>> oled.show()
```

1.  现在我们已经清除了显示屏，并准备在屏幕上显示一些文本。使用以下代码块，在颜色为白色的位置（`0`，`0`）上显示`'hello'`文本：

```py
>>> oled.text('hello', 0, 0, WHITE)
>>> oled.show()
```

1.  使用以下代码块清除屏幕并显示三行文本：

```py
>>> oled.fill(BLACK)
>>> oled.show()
>>> 
>>> oled.text('line 1', 0, 0, WHITE)
>>> oled.text('line 2', 0, 10, WHITE)
>>> oled.text('line 3', 0, 20, WHITE)
>>> oled.show()
```

1.  定义一个函数，然后调用它；这将在显示屏上从数字 10 倒数到 0：

```py
>>> def countdown(oled, start):
...     for i in range(start, -1, -1):
...         oled.fill(BLACK)
...         oled.text(str(i), 0, 0, WHITE)
...         oled.show()
...         
...         
... 
>>> 
>>> countdown(oled, 10)
```

1.  使用以下代码块，定义一个名为`ALPHA_NUMERIC`的常量。它包含所有小写字母、大写字母和数字字符，这些字符以适合显示的结构组织在一起：

```py
>>> ALPHA_NUMERIC = [
...     'abcdefghijklmnopqrstu',
...     'vwxyzABCDEFGHIJKLMNOP',
...     'QRSTUVWXYZ0123456789',
... ]
```

1.  使用以下代码块，定义并调用`show_alpha_numeric`函数，该函数循环遍历`ALPHA_NUMERIC`列表，并在单独的行上显示每个字符串：

```py
>>> def show_alpha_numeric(oled):
...     for i, text in enumerate(ALPHA_NUMERIC):
...         oled.text(text, 0, 10 * i, WHITE)
...         oled.show()
...         
...         
... 
>>> oled.fill(BLACK)
>>> show_alpha_numeric(oled)
```

1.  将以下代码添加到`main.py`文件中：

```py
import adafruit_ssd1306
import board
import busio

BLACK = 0
WHITE = 1
ALPHA_NUMERIC = [
    'abcdefghijklmnopqrstu',
    'vwxyzABCDEFGHIJKLMNOP',
    'QRSTUVWXYZ0123456789',
]

def countdown(oled, start):
    for i in range(start, -1, -1):
        oled.fill(BLACK)
        oled.text(str(i), 0, 0, WHITE)
        oled.show()

def show_alpha_numeric(oled):
    for i, text in enumerate(ALPHA_NUMERIC):
        oled.text(text, 0, 10 * i, WHITE)
        oled.show()

def main():
    i2c = busio.I2C(board.SCL, board.SDA)
    oled = adafruit_ssd1306.SSD1306_I2C(128, 32, i2c)
    oled.fill(BLACK)
    countdown(oled, 10)
    oled.fill(BLACK)
    show_alpha_numeric(oled)

main()
```

当执行此脚本时，它将执行一个倒计时动画，然后显示一些字母数字文本。

# 它是如何工作的...

`countdown`函数启动一个`for`循环，将从 10 倒数到 0。在每次迭代期间，屏幕被清除，然后当前数字被显示在屏幕上。`ALPHA_NUMERIC`变量以一种结构化的格式结合了小写字母、大写字母和数字字符，分布在三行上。显示器可以显示 3 行 21 列的文本。这些数据符合这些限制，以便所有字符都可以清晰地显示，而不会裁剪文本。`countdown`函数循环遍历每行文本，并在正确的位置显示它，以便屏幕上的 3 行文本被正确填充。

# 还有更多...

在使用文本输出时，您可以代表各种内容，无限可能。您显示的输出可以是从传感器读数到实时从互联网获取的最新新闻标题。下面的照片显示了在调用`show_alpha_numeric`函数后显示的屏幕：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mcpy-cb/img/efcd4925-a427-4cbe-939c-f805db778e89.png)

尽管屏幕在物理上相当小，但它具有良好的分辨率，并且 CircuitPython 库包中提供的字体已经很好地利用了有限的屏幕空间。这使得在非常小的显示器上显示三行文本成为可能。

# 另请参阅

有关更多信息，请参考以下内容：

+   可以在[`learn.adafruit.com/micropython-oled-watch`](https://learn.adafruit.com/micropython-oled-watch)找到有关创建 OLED 手表的 MicroPython 项目的更多文档。

+   可以在[`learn.sparkfun.com/tutorials/i2c/all`](https://learn.sparkfun.com/tutorials/i2c/all)找到有关 I2C 通信协议的更多文档。

# 在显示器上反转颜色

本教程将演示如何使用`invert`功能来翻转所有像素的颜色。当您在黑色背景上显示白色文本，然后希望颜色翻转，使屏幕显示白色背景上的黑色文本时，可以使用此功能。与清除屏幕等一些关键操作相比，`invert`等功能可能会慢得多。我们可以利用这些性能差异，当我们希望快速地向使用屏幕的人显示视觉反馈时使用`invert`。

本教程将帮助您在使用缓慢的微控制器创建项目并需要找到创造性方法使设备更具响应性以改善其可用性时使用。

# 准备工作

您需要访问 ESP8266 上的 REPL 来运行本教程中提供的代码。

# 如何操作...

让我们执行以下步骤：

1.  在 REPL 中运行以下代码行：

```py
>>> import adafruit_ssd1306
>>> import board
>>> import busio
>>> 
>>> BLACK = 0
>>> WHITE = 1
>>> 
>>> i2c = busio.I2C(board.SCL, board.SDA)
>>> oled = adafruit_ssd1306.SSD1306_I2C(128, 32, i2c)
>>> oled.fill(BLACK)
>>> oled.show()
```

1.  完成初始设置后，`oled`对象可用于开始反转屏幕。使用以下代码块在黑色背景上显示一些白色文本：

```py
>>> oled.invert(True)
```

1.  屏幕现在将显示白色背景上的黑色文本。要将颜色翻转回来，请运行以下代码：

```py
>>> oled.invert(False)
```

1.  `invert`功能比用于更新屏幕的其他一些方法快得多。使用以下函数来计算这种速度差异：

```py
>>> def measure_time(label, func, args=(), count=3):
...     for i in range(count):
...         start = time.monotonic()
...         func(*args)
...         total = (time.monotonic() - start) * 1000
...         print(label + ':', '%s ms' % total)
...         
...         
... 
>>> 
```

1.  使用以下代码块调用`measure_time`函数，并计算`fill`操作花费的时间（以毫秒为单位）：

```py
>>> measure_time('fill', oled.fill, [BLACK])
fill: 1047.85 ms
fill: 1049.07 ms
fill: 1046.14 ms
>>> 
```

1.  现在计时`show`方法，你会发现它比`fill`更快：

```py
>>> measure_time('show', oled.show, [])
show: 62.0117 ms
show: 62.0117 ms
show: 61.0352 ms
>>>
```

1.  使用以下代码检查`text`方法的速度：

```py
>>> measure_time('text', oled.text, ['hello', 0, 0, WHITE])
text: 74.9512 ms
text: 75.1953 ms
text: 80.0781 ms
>>> 
```

1.  最后，检查`invert`方法的速度如下：

```py
>>> measure_time('invert', oled.invert, [True])
invert: 0.976563 ms
invert: 1.95313 ms
invert: 0.976563 ms
>>> 
```

1.  将以下代码添加到`main.py`文件中：

```py
import adafruit_ssd1306
import board
import busio
import time

BLACK = 0
WHITE = 1

def measure_time(label, func, args=(), count=3):
    for i in range(count):
        start = time.monotonic()
        func(*args)
        total = (time.monotonic() - start) * 1000
        print(label + ':', '%s ms' % total)

def main():
    i2c = busio.I2C(board.SCL, board.SDA)
    oled = adafruit_ssd1306.SSD1306_I2C(128, 32, i2c)
    oled.fill(BLACK)
    oled.show()

    measure_time('fill', oled.fill, [BLACK])
    measure_time('show', oled.show, [])
    measure_time('text', oled.text, ['hello', 0, 0, WHITE])
    measure_time('invert', oled.invert, [True])

main()
```

当执行此脚本时，它会打印出与屏幕相关操作的性能结果。

# 工作原理

`measure_time`函数默认循环三轮。它将当前时间保存在`start`变量中，调用被测试的函数，然后计算函数调用的总执行时间。该值转换为毫秒，然后打印出结果。`main`函数调用`measure_time`四次。它调用它来测量`fill`，`show`，`text`和`invert`方法的执行时间。

# 还有更多...

从性能结果来看，有一些事情是非常明显的。好消息是结果非常一致。在这个示例中，我们对每个测量都进行了三次读数。在测量执行速度时，最好取多个样本。从样本中看，调用`fill`大约比调用`invert`慢 500 倍。为了使应用程序感觉灵敏，操作不应该超过 100 毫秒，否则它会显得迟钝或无响应。像`invert`，`text`和`show`这样的操作速度很快。但由于`fill`时间太长，我们可能希望在执行`fill`之前调用`invert`，以便用户得到我们的应用程序正在响应他们输入的迹象。

# 另请参阅

欲了解更多信息，请参阅以下内容：

+   有关使用 OLED 显示屏和 ESP8266 的 CircuitPython 项目的更多文档，请访问[`learn.adafruit.com/circuitpython-totp-otp-2fa-authy-authenticator-friend`](https://learn.adafruit.com/circuitpython-totp-otp-2fa-authy-authenticator-friend)。

+   有关 OLED 的更多详细信息，请访问[`www.oled-info.com/oled-introduction`](https://www.oled-info.com/oled-introduction)。


# 第十四章：构建物联网（IoT）天气机

在本章中，我们将创建一个连接到互联网的天气机，它将在按下按钮时告诉我们随机城市的天气。为了制作这个工作设备，我们将结合本书中涵盖的一些概念和技术。

我们将使用第十二章中展示的一些网络技术，以及第十三章中展示的显示逻辑，介绍如何与 FeatherWing OLED 交互。这些不同的技术将结合起来创建一个设备，通过触摸按钮事件获取实时天气数据，并在**有机发光二极管**（OLED）显示器上呈现。

本章可以成为一个有用的信息来源，帮助您使用 MicroPython 创建易于交互并提供丰富的视觉输出的物联网连接设备。

在本章中，我们将涵盖以下主题：

+   从互联网检索天气数据

+   创建一个获取城市天气的函数

+   随机选择城市

+   创建一个用于文本处理的屏幕对象

+   创建一个函数来显示城市的天气

+   在获取天气数据时提供视觉反馈

+   创建一个显示随机城市天气的函数

+   创建一个物联网按钮来显示全球各地的天气

# 技术要求

本章的代码文件可以在以下 GitHub 存储库的`Chapter14`文件夹中找到：[`github.com/PacktPublishing/MicroPython-Cookbook`](https://github.com/PacktPublishing/MicroPython-Cookbook)。

本章使用 Adafruit Feather HUZZAH ESP8266 和已组装的 Adafruit FeatherWing OLED 128x32 OLED 附加件。本章的所有教程都使用了 CircuitPython 3.1.2。您需要应用第十章中描述的*连接到现有 Wi-Fi 网络*教程中的配置，*控制 ESP8266*。本章还将使用第十二章中描述的*创建等待互联网连接的函数*教程中的`wait_for_networking`函数，*网络*。您还需要执行第十三章中描述的步骤，*与 Adafruit FeatherWing OLED 交互*。

本章的教程使用 Openweather 提供的天气 API 服务。该服务是免费使用的，但您必须注册并获取一个 API 密钥（APPID）才能使用该服务。API 密钥将需要在本章中运行代码。您可以访问[`openweathermap.org/appid`](https://openweathermap.org/appid)获取 API 密钥。

# 从互联网检索天气数据

本教程将向您展示如何使用 ESP8266 连接到互联网，并使用 RESTful Web 服务获取实时天气数据。我们将使用的服务为全球 10 万多个城市提供最新的天气信息。每个位置提供了大量的天气信息，因此本教程将展示如何筛选出对我们最感兴趣的项目。

本教程在您的项目中可能很有用，每当您需要向 RESTful 调用传递不同的参数，或者返回的结果非常庞大，您需要找到浏览这些大型数据集的方法。

# 准备工作

您需要访问 ESP8266 上的 REPL 来运行本教程中提供的代码。

# 如何做...

让我们按照本教程中所需的步骤进行操作：

1.  在 REPL 中运行以下代码行：

```py
>>> import urequests >>> >>> API_URL = 'http://api.openweathermap.org/data/2.5/weather' >>> 
```

1.  `API_URL`变量现在已经定义，我们将使用它来访问天气 API。在下一个代码块中，我们定义`APPID`和`city`以获取天气数据。确保用你实际的`APPID`值替换`APPID`值。现在我们将通过组合这些变量来构建 URL，然后我们可以访问：

```py
>>> APPID = 'put-your-API-key(APPID)-here'
>>> city = 'Berlin'
>>> url = API_URL + '?units=metric&APPID=' + APPID + '&q=' + city
```

1.  以下代码块将连接到天气 API 并检索天气数据：

```py
>>> response = urequests.get(url)
>>> response
<Response object at 3fff1b00>
```

1.  我们知道响应使用 JSON 格式，所以我们可以解析它并检查数据中有多少个顶级键：

```py
>>> data = response.json()
>>> len(data)
13
```

1.  下一个代码块检查了解析后的天气数据。由于有很多嵌套的数据，所以以当前形式很难理解：

```py
>>> data
{'cod': 200, 'rain': {'1h': 0.34}, 'dt': 1555227314, 'base': 'stations', 'weather': [{'id': 500, 'icon': '10d', 'main': 'Rain', 'description': 'light rain'}, {'id': 310, 'icon': '09d', 'main': 'Drizzle', 'description': 'light intensity drizzle rain'}], 'sys': {'message': 0.0052, 'country': 'DE', 'sunrise': 1555215098, 'sunset': 1555264894, 'id': 1275, 'type': 1}, 'name': 'Berlin', 'clouds': {'all': 75}, 'coord': {'lon': 13.39, 'lat': 52.52}, 'visibility': 7000, 'wind': {'speed': 3.6, 'deg': 40}, 'id': 2950159, 'main': {'pressure': 1025, 'humidity': 93, 'temp_min': 2.22, 'temp_max': 3.89, 'temp': 3.05}}
```

1.  MicroPython 没有`pprint`模块。我们将复制并粘贴数据的输出，并在计算机上的 Python REPL 上运行以下操作：

```py
>>> data = {'cod': 200, 'rain': {'1h': 0.34}, 'dt': 1555227314, 'base': 'stations', 'weather': [{'id': 500, 'icon': '10d', 'main': 'Rain', 'description': 'light rain'}, {'id': 310, 'icon': '09d', 'main': 'Drizzle', 'description': 'light intensity drizzle rain'}], 'sys': {'message': 0.0052, 'country': 'DE', 'sunrise': 1555215098, 'sunset': 1555264894, 'id': 1275, 'type': 1}, 'name': 'Berlin', 'clouds': {'all': 75}, 'coord': {'lon': 13.39, 'lat': 52.52}, 'visibility': 7000, 'wind': {'speed': 3.6, 'deg': 40}, 'id': 2950159, 'main': {'pressure': 1025, 'humidity': 93, 'temp_min': 2.22, 'temp_max': 3.89, 'temp': 3.05}}
```

1.  在计算机的 REPL 上运行下一个代码块，我们将得到数据的更结构化表示：

```py
>>> import pprint
>>> pprint.pprint(data)
{'base': 'stations',
 'clouds': {'all': 75},
 'cod': 200,
 'coord': {'lat': 52.52, 'lon': 13.39},
 'dt': 1555227314,
 'id': 2950159,
 'main': {'humidity': 93,
          'pressure': 1025,
          'temp': 3.05,
          'temp_max': 3.89,
          'temp_min': 2.22},
 'name': 'Berlin',
 'rain': {'1h': 0.34},
 'sys': {'country': 'DE',
         'id': 1275,
         'message': 0.0052,
         'sunrise': 1555215098,
         'sunset': 1555264894,
         'type': 1},
 'visibility': 7000,
 'weather': [{'description': 'light rain',
              'icon': '10d',
              'id': 500,
              'main': 'Rain'},
             {'description': 'light intensity drizzle rain',
              'icon': '09d',
              'id': 310,
              'main': 'Drizzle'}],
 'wind': {'deg': 40, 'speed': 3.6}}
>>> 
```

1.  现在我们可以返回到 MicroPython REPL 并运行以下代码来检查`main`键：

```py
>>> data['main']
{'pressure': 1025, 'humidity': 93, 'temp_min': 2.22, 'temp_max': 3.89, 'temp': 3.05}
```

1.  接下来的代码将让我们访问柏林的温度和湿度数值：

```py
>>> data['main']['temp']
3.05
>>> data['main']['humidity']
93
>>> 
```

1.  您可以使用以下代码访问数据的风部分：

```py
>>> data['wind']
{'speed': 3.6, 'deg': 40}
>>> data['wind']['speed']
3.6
```

通过这种方式，我们可以进一步深入，并获取所请求城市的风速值。

# 它是如何工作的...

导入`urequests`库后，我们定义了一些变量，以便我们可以继续准备 URL 来执行 API 调用。`API_URL`是一个固定的常量，在对网络服务进行调用时不会改变。然后，我们定义一个变量来存储 API 密钥和城市值。这些值被组合在一起，以制作最终的 URL，然后我们使用`urequests`库的`get`函数进行调用。

`return`响应被解析并显示输出。由于数据结构非常庞大，我们使用了一个技巧，将这些数据移动到计算机上的 REPL，这样我们就可以使用`pprint`函数，并获得返回数据的更清晰的输出格式。这样可以更容易地识别数据结构的不同部分，并开始访问嵌套数据结构中的不同数据元素。然后我们使用字典中的键来访问柏林市的湿度、温度和风速。

# 还有更多...

在网络服务的世界中，API 密钥的使用非常普遍。这个示例是一个很好的例子，说明了我们如何将这些密钥包含在我们的 API 调用中，以便它们可以成功处理。我们还展示了一个技巧，即将数据结构从 MicroPython REPL 复制到计算机上的 Python REPL。这样我们可以在这两个世界之间跳转，并访问一些在计算机上可用但在 MicroPython 上不可用的模块，比如`pprint`。

# 另请参阅

以下是一些进一步信息的参考资料：

+   `pprint`模块的文档可以在[`docs.python.org/3/library/pprint.html`](https://docs.python.org/3/library/pprint.html)找到。

+   有关通过城市名称访问天气数据的文档可以在[`openweathermap.org/current#name`](https://openweathermap.org/current#name)找到。

# 创建一个获取城市天气的函数

在这个示例中，我们将创建一个连接到天气 API 并获取特定城市天气数据的函数。我们不希望直接在源代码中硬编码诸如 API 密钥之类的值。因此，这个示例还将向您展示如何创建一个 JSON 格式的配置文件，可以存储不同的设置，比如 API 密钥。应用程序将在启动时从这个配置文件中读取值，并在调用天气网络服务时使用它们。

每当您想要将配置值与代码库分开保留时，无论是出于安全原因还是为了更轻松地调整这些设置而不更改应用程序的源代码，这个示例都会对您非常有用。这也可以帮助您在自己的项目中将 API 调用组织成可重用的函数。

# 准备工作

在 ESP8266 上运行此处方中提供的代码，您将需要访问 REPL。

# 如何做...

让我们按照这个食谱所需的步骤进行操作：

1.  在 REPL 中执行下一块代码：

```py
>>> from netcheck import wait_for_networking
>>> import urequests
>>> import json
>>> 
>>> CONF_PATH = 'conf.json'
>>> API_URL = 'http://api.openweathermap.org/data/2.5/weather'
```

1.  `CONF_PATH`变量定义了我们的 JSON 配置文件的位置。

1.  以下内容应放入板的根文件夹中的`conf.json`文件中。将`APPID`的值替换为您的实际`APPID`值：

```py
{"APPID": "put-your-API-key(APPID)-here"}
```

1.  下一块代码定义了一个函数，该函数将读取和解析配置文件中提供的设置。然后将这些设置的值返回给调用函数：

```py
>>> def get_conf():
...     content = open(CONF_PATH).read()
...     return json.loads(content)
...     
...     
... 
>>> 
```

1.  现在我们将调用`get_conf`函数并将其结果存储在名为`conf`的变量中。然后检索并保存`APPID`的值以供将来使用：

```py
>>> conf = get_conf()
>>> APPID = conf['APPID']
```

1.  下一块代码定义了一个函数，该函数接收一个城市名称并执行该城市的天气 API 调用，并返回解析后的天气数据：

```py
>>> def get_weather(APPID, city):
...     url = API_URL + '?units=metric&APPID=' + APPID + '&q=' 
...     + city
...     return urequests.get(url).json()
...     
...     
... 
>>> 
```

1.  下一块代码调用`get_weather`函数获取伦敦市的天气，并将结果存储在名为`data`的变量中。然后访问并打印出多个不同的数据字段：

```py
>>> data = get_weather(APPID, 'London')
>>> 
>>> print('temp:', data['main']['temp'])
temp: 7.87
>>> print('wind:', data['wind']['speed'])
wind: 3.1
>>> print('name:', data['name'])
name: London
>>> print('country:', data['sys']['country'])
country: GB
>>> 
```

1.  下一块代码应该放入`main.py`文件中。

```py
from netcheck import wait_for_networking
import urequests
import json

CONF_PATH = 'conf.json'
API_URL = 'http://api.openweathermap.org/data/2.5/weather'

def get_conf():
    content = open(CONF_PATH).read()
    return json.loads(content)

def get_weather(APPID, city):
    url = API_URL + '?units=metric&APPID=' + APPID + '&q=' + city
    return urequests.get(url).json()

def main():
    wait_for_networking()
    conf = get_conf()
    APPID = conf['APPID']
    data = get_weather(APPID, 'London')
    print('temp:', data['main']['temp'])
    print('wind:', data['wind']['speed'])
    print('name:', data['name'])
    print('country:', data['sys']['country'])

main()
```

当执行此脚本时，它将连接到天气 API 并打印出伦敦市检索到的多个数据元素。

# 它是如何工作的...

主脚本首先调用`wait_for_networking`来确保网络正常运行，然后调用`get_conf`来检索应用程序的配置数据，后者解析存储在配置文件中的 JSON 数据。

然后从配置设置中访问`APPID`的值。然后使用`get_weather`函数进行 API 调用。此函数接收`APPID`值和要获取信息的城市名称。有了这两个值，它就可以准备 URL 并进行 API 调用。

然后对结果进行解析并返回到`main`函数。然后访问数据结构以从返回的 API 调用中获取多个值，并打印出它们的相关标签。

# 还有更多...

这个食谱展示了一种通用的技术，用于将诸如 API 密钥之类的值存储在源代码之外。JSON 是一种有用的文件格式，特别适用于存储配置值，特别是在使用 MicroPython 时，因为它内置支持解析此文件格式。一些应用程序还使用流行的`.ini`文件格式进行配置文件，该文件格式在 Python 标准库中得到支持。这个 Python 模块不作为 MicroPython 的主要库的一部分提供，因此最好在您可以的时候避免在 MicroPython 项目中使用它。

# 另请参阅

以下是一些进一步信息的参考：

+   有关`json`模块的文档可以在[`docs.python.org/3/library/json.html`](https://docs.python.org/3/library/json.html)找到。

+   有关用于解析 INI 文件的`configparser`模块的文档可以在[`docs.python.org/3/library/configparser.html`](https://docs.python.org/3/library/configparser.html)找到。

# 随机选择城市

在这个食谱中，我们将使用`random`模块从固定的城市列表中随机选择城市。我们首先创建一个名为`CITIES`的全局变量来存储这些值。然后我们可以使用`random`模块中的特定函数，用于从值列表中选择随机项。

然后，该食谱将循环 10 次，从城市列表中进行随机选择，并输出所选城市的详细信息。每当您需要从固定值列表中随机选择某个选项的项目时，这个食谱将特别有用。例如，您可以创建一个骰子投掷 MicroPython 项目，每次投掷都应该从值 1 到 6 中选择一个值。

# 准备工作

在 ESP8266 上运行此处方中提供的代码，您将需要访问 REPL。

# 如何做...

让我们按照这个食谱所需的步骤进行操作：

1.  使用 REPL 来运行以下代码行：

```py
>>> import random
>>> 
>>> CITIES = ['Berlin', 'London', 'Paris', 'Tokyo', 'Rome', 'Oslo', 'Bangkok']
```

1.  我们现在已经定义了一个城市列表，我们可以从中随机选择。下一段代码展示了从`random` Python 模块中获取随机数据的最简单方法之一：

```py
>>> random.random()
0.0235046
>>> random.random()
0.830886
>>> random.random()
0.0738319
```

1.  对于我们的目的，我们可以使用`choice`函数，因为它会从列表中随机选择一个项目。以下代码块使用这种方法随机选择三个城市：

```py
>>> random.choice(CITIES)
'Rome'
>>> random.choice(CITIES)
'Berlin'
>>> 
>>> random.choice(CITIES)
'Oslo'
```

1.  以下代码块将循环 10 次，并在每次迭代中打印出一个随机选择的城市：

```py
>>> for i in range(10):
...     city = random.choice(CITIES)
...     print('random selection', i, city)
...     
...     
... 
random selection 0 London
random selection 1 Tokyo
random selection 2 Oslo
random selection 3 Berlin
random selection 4 Bangkok
random selection 5 Tokyo
random selection 6 London
random selection 7 Oslo
random selection 8 Oslo
random selection 9 London
>>> 
```

1.  下一段代码应该放入`main.py`文件中：

```py
import random

CITIES = ['Berlin', 'London', 'Paris', 'Tokyo', 'Rome', 'Oslo', 'Bangkok']

def main():
    for i in range(10):
        city = random.choice(CITIES)
        print('random selection', i, city)

main()
```

当执行此脚本时，它将打印出 10 个随机选择的城市。

# 工作原理...

我们首先导入将用于执行城市的随机选择的`random`模块。重复调用`random`函数以验证我们可以从模块中获取随机数。我们创建了一个名为`CITIES`的变量，这是我们想要从中进行随机选择的城市列表。然后使用`random`模块中的`choice`函数从这个列表中选择一个随机选择。`main`函数通过调用`choice`函数 10 次并打印出每次调用的结果来演示了这种逻辑。

# 还有更多...

本章只需要选择随机数来创建天气机器运行的不可预测性水平。因此，我们不需要担心生成的随机数的质量。然而，如果我们需要随机数用于某些加密操作的目的，那么我们需要更加小心地生成这些数字。我们还需要详细了解随机数生成器如何通过调用`seed`函数进行初始化。

# 另请参阅

以下是一些进一步信息的参考资料：

+   有关`choice`函数的文档可以在[`docs.python.org/3/library/random.html#random.choice`](https://docs.python.org/3/library/random.html#random.choice)找到。

+   有关`seed`函数的文档可以在[`docs.python.org/3/library/random.html#random.seed`](https://docs.python.org/3/library/random.html#random.seed)找到。

# 为文本处理创建一个 Screen 对象

在这个示例中，我们将创建一个`Screen`对象，它将更容易地将多行输出写入到 FeatherWing OLED 显示器中。我们正在构建的天气机器将希望利用 OLED 显示器的多行输出功能。

为了方便输出，这个示例将创建一个对象，接收多行文本，并将文本正确地定位在其关联的*x*和*y*坐标上。您会发现这个示例对于任何需要频繁向显示器写入文本内容并希望自动处理多行输出的项目非常有用。

# 准备就绪

您需要访问 ESP8266 上的 REPL 来运行本示例中提供的代码。

# 如何操作...

让我们按照这个示例中所需的步骤进行操作：

1.  在 REPL 中运行以下代码行：

```py
>>> import adafruit_ssd1306
>>> import board
>>> import busio
>>> 
>>> BLACK = 0
>>> WHITE = 1
>>> 
>>> MESSAGE = """\
... top line %s
... middle line
... last line
... """
>>> 
```

1.  我们已经导入了必要的模块，并创建了一个名为`MESSAGE`的变量，我们将用它来生成多行输出消息。下一段代码将创建`Screen`对象的基本结构，其中包含一个接收`oled`显示对象的构造函数：

```py
>>> class Screen:
...     def __init__(self, oled):
...         self.oled = oled
...         self.oled.fill(BLACK)
...         self.oled.show()
...         
...         
... 
>>> 
```

1.  在以下代码行中，我们创建一个与显示器交互的对象和`Screen`类的一个实例：

```py
>>> i2c = busio.I2C(board.SCL, board.SDA)
>>> oled = adafruit_ssd1306.SSD1306_I2C(128, 32, i2c)
>>> screen = Screen(oled)
```

1.  我们现在将在`Screen`对象中添加一个方法，负责将多行文本写入显示器：

```py
>>> class Screen:
...     def __init__(self, oled):
...         self.oled = oled
...         self.oled.fill(BLACK)
...         self.oled.show()
...         
...     def write(self, text):
...         self.oled.fill(BLACK)
...         lines = text.strip().split('\n')
...         for row, line in enumerate(lines):
...             self.oled.text(line, 0, 10 * row, WHITE)
...         self.oled.show()
...         
...         
... 
>>> 
```

1.  我们现在创建一个`Screen`对象并调用它的`write`方法。您应该会在显示器上看到`'hello'`文本出现：

```py
>>> screen = Screen(oled)
>>> screen.write('hello')
```

1.  下一段代码将在显示器上打印一个占据三行的多行消息：

```py
>>> screen.write('multi \n line \n output')
>>> 
```

1.  运行以下代码在显示器上显示 10 条不同的多行消息：

```py
>>> for i in range(10):
...     print(i)
...     screen.write(MESSAGE % i)
...     
...     
... 
0
1
2
3
4
5
6
7
8
9
>>> 
```

1.  以下代码应该放入`screen.py`文件中：

```py
import adafruit_ssd1306
import board
import busio

BLACK = 0
WHITE = 1

class Screen:
    def __init__(self, oled):
        self.oled = oled
        self.oled.fill(BLACK)
        self.oled.show()

    def write(self, text):
        self.oled.fill(BLACK)
        lines = text.strip().split('\n')
        for row, line in enumerate(lines):
            self.oled.text(line, 0, 10 * row, WHITE)
        self.oled.show()

def get_oled():
    i2c = busio.I2C(board.SCL, board.SDA)
    return adafruit_ssd1306.SSD1306_I2C(128, 32, i2c)
```

1.  下一段代码应该放入`main.py`文件中：

```py
from screen import Screen, get_oled

MESSAGE = """\
top line %s
middle line
last line
"""

def main():
    oled = get_oled()
    screen = Screen(oled)
    screen.write('hello')

    for i in range(10):
        print(i)
        screen.write(MESSAGE % i)

main()
```

当执行此脚本时，它将在 OLED 显示器上打印出 10 个多行文本块。

# 它是如何工作的...

`screen`对象将其构造函数的单个参数。这个参数是`oled`变量，它将让我们与显示器交互。保存了对这个对象的引用，然后清除了显示器上的所有像素。它还定义了一个名为`write`的方法。这个方法接收一个字符串，可以是单行或多行文本。

然后清除显示器，将文本分解为字符串列表，每个字符串代表一个输出行。这些行被循环处理，并分别写入其正确的行。一旦所有行都被处理，就会在显示器上调用`show`方法来呈现内容。这个配方中的`main`函数设置了`screen`对象，然后向显示器发送了一个简单的`hello`消息。然后循环 10 次并生成一组多行消息，这些消息将依次显示在屏幕上。

# 还有更多...

`Screen`对象的设计类似于 Python 中其他文件（如对象）的设计。例如，Python 模块`sys`有一个`stdout`对象，它有一个`write`方法，可以让您将文本输出到屏幕上。将复杂的交互（如文本放置的*x*，*y*位置）打包到一个单独的对象中，通常会使其余的代码更简单和更易读。

# 另请参阅

以下是一些进一步信息的参考：

+   有关`stdout`对象的文档可以在[`docs.python.org/3/library/sys.html#sys.stdout`](https://docs.python.org/3/library/sys.html#sys.stdout)找到。

+   可以在[`docs.python.org/3/glossary.html#term-file-object`](https://docs.python.org/3/glossary.html#term-file-object)找到公开`write`方法的文件对象的文档。

# 创建一个显示城市天气的函数

在本配方中，我们将创建一个函数，该函数接受城市的名称，查找其天气信息，然后在 OLED 显示器上显示部分信息。为了实现这一点，本配方中的函数将结合本章中涵盖的不同部分。

除了输出到 OLED，它还会将相同的信息打印到标准输出，以便进行调试。当您想要查看像天气机这样的项目如何被分解为结构化设计中互相调用的单独部分时，这个配方对您可能有用。

# 准备工作

您需要访问 ESP8266 上的 REPL 来运行本配方中提供的代码。

# 如何做...

让我们按照本配方中所需的步骤进行操作：

1.  在 REPL 中执行下一段代码：

```py
>>> from screen import Screen, get_oled
>>> from netcheck import wait_for_networking
>>> import urequests
>>> import json
>>> 
>>> CONF_PATH = 'conf.json'
>>> API_URL = 'http://api.openweathermap.org/data/2.5/weather'
>>> CITIES = ['Berlin', 'London', 'Paris', 'Tokyo', 'Rome', 'Oslo', 'Bangkok']
>>> WEATHER = """\
... City: {city}
... Temp: {temp}
... Wind: {wind}
... """
>>> 
```

1.  在导入所需的模块之后，我们创建了一个名为`WEATHER`的新变量，它存储了模板，我们将使用它来将天气信息输出到显示器上。运行下一段代码来设置屏幕对象并获取 API 调用的`APPID`值：

```py
>>> def get_conf():
...     content = open(CONF_PATH).read()
...     return json.loads(content)
...     
...     
... 
>>> def get_weather(APPID, city):
...     url = API_URL + '?units=metric&APPID=' + APPID + '&q=' + city
...     return urequests.get(url).json()
...     
...     
... 
>>> oled = get_oled()
>>> screen = Screen(oled)
>>> wait_for_networking()
address on network: 10.0.0.38
'10.0.0.38'
>>> conf = get_conf()
>>> APPID = conf['APPID']
>>> 
```

1.  在以下代码行中，我们定义了`show_weather`函数，该函数接受屏幕、`APPID`和城市名称，然后将获取并显示该城市的天气信息：

```py
>>> def show_weather(screen, APPID, city):
...     weather = get_weather(APPID, city)
...     data = {}
...     data['city'] = city
...     data['temp'] = weather['main']['temp']
...     data['wind'] = weather['wind']['speed']
...     text = WEATHER.format(**data)
...     print('-------- %s --------' % city)
...     print(text)
...     screen.write(text)
...     
...     
... 
>>> 
```

1.  运行下一段代码来调用`show_weather`函数以获取东京市的天气。您在标准输出上看到的文本也应该显示在 OLED 显示器上：

```py
>>> show_weather(screen, APPID, 'Tokyo')
-------- Tokyo --------
City: Tokyo
Temp: 13.67
Wind: 6.7

>>> 
```

1.  当我们执行以下代码块时，它将循环遍历所有城市，并在屏幕上显示它们的天气信息：

```py
>>> for city in CITIES:
...     show_weather(screen, APPID, city)
...     
...     
... 
-------- Berlin --------
City: Berlin
Temp: 10.03
Wind: 3.6

-------- London --------
City: London
Temp: 8.56
Wind: 8.7

-------- Paris --------
City: Paris
Temp: 9.11
Wind: 5.1

-------- Tokyo --------
City: Tokyo
Temp: 13.55
Wind: 6.7

-------- Rome --------
City: Rome
Temp: 11.69
Wind: 6.2

-------- Oslo --------
City: Oslo
Temp: 10.13
Wind: 2.1

-------- Bangkok --------
City: Bangkok
Temp: 30.66
Wind: 5.1

>>> 
```

1.  下一段代码应该放入`main.py`文件中：

```py
from screen import Screen, get_oled
from netcheck import wait_for_networking
import urequests
import json

CONF_PATH = 'conf.json'
API_URL = 'http://api.openweathermap.org/data/2.5/weather'
CITIES = ['Berlin', 'London', 'Paris', 'Tokyo', 'Rome', 'Oslo', 'Bangkok']
WEATHER = """\
City: {city}
Temp: {temp}
Wind: {wind}
"""

def get_conf():
    content = open(CONF_PATH).read()
    return json.loads(content)

def get_weather(APPID, city):
    url = API_URL + '?units=metric&APPID=' + APPID + '&q=' + city
    return urequests.get(url).json()

def show_weather(screen, APPID, city):
    weather = get_weather(APPID, city)
    data = {}
    data['city'] = city
    data['temp'] = weather['main']['temp']
    data['wind'] = weather['wind']['speed']
    text = WEATHER.format(**data)
    print('-------- %s --------' % city)
    print(text)
    screen.write(text)

def main():
    oled = get_oled()
    screen = Screen(oled)
    wait_for_networking()
    conf = get_conf()
    APPID = conf['APPID']
    for city in CITIES:
        show_weather(screen, APPID, city)

main()
```

当执行此脚本时，它将循环遍历所有城市名称，并在 OLED 显示器上显示它们的天气信息。

# 它是如何工作的...

`show_weather`函数在这个示例中承担了大部分的工作。当调用时，它首先通过调用`get_weather`函数收集天气数据。然后，它将这些信息填充到一个名为`data`的字典中，包括城市名称、温度和风速。

然后，这些值被填入`WEATHER`模板中，该模板用作控制如何在屏幕上呈现这些信息的模板。生成的文本既输出到标准输出显示器上，也显示在 OLED 显示器上。主函数将配置多个变量，以便可以进行 API 调用并更新屏幕。然后，它循环遍历城市列表，并为每个城市调用`show_weather`。

# 还有更多...

Python 在字符串模板方面提供了很多选项。在这个示例中使用的是内置于 Python 和 MicroPython 中的字符串格式化函数，这使它成为一个理想的选择。通常最好将模板保存在它们自己的变量中，就像在这个示例中所做的那样。这样可以更容易地更改标签并可视化预期结果的外观。

`show_weather`函数在标准输出和 OLED 显示器上输出相同的文本。处理文本输出的一个强大方面是可以在许多设备上复制相同的输出。您还可以进一步扩展这一点，并在文本日志文件中记录每次屏幕更新，以帮助调试。

# 另请参阅

以下是一些进一步信息的参考资料：

+   关于 Python 字符串格式化的文档可以在[`docs.python.org/3.4/library/string.html#string-formatting`](https://docs.python.org/3.4/library/string.html#string-formatting)找到。

+   关于`Template`对象的文档可以在[`docs.python.org/3.4/library/string.html#template-strings`](https://docs.python.org/3.4/library/string.html#template-strings)找到。

# 在获取数据时提供视觉反馈

在这个示例中，我们将增强上一个示例中的代码，以便在每次开始获取特定城市的天气数据时添加视觉反馈。这个示例的第一部分是进行一些测量，以找出`show_weather`函数有多慢。这将让我们了解函数是否足够慢，以至于用户可以看到。

然后，我们将使用显示器上的`invert`功能提供即时的视觉反馈，表明我们已经开始获取天气数据。这个示例将帮助您了解微控制器的硬件限制所面临的性能挑战，并且如何克服这些挑战，有时为应用程序的用户提供某种反馈。

# 准备工作

您将需要访问 ESP8266 上的 REPL 来运行本示例中呈现的代码。测量执行时间和反转颜色的方法是基于第十三章中*在显示器上反转颜色*一节中介绍的，*与 Adafruit FeatherWing* *OLED*交互。在继续本示例之前，最好先复习一下那个示例。

# 操作步骤

让我们按照这个示例中所需的步骤进行操作：

1.  使用 REPL 来运行以下代码行：

```py
>>> import time
>>> 
>>> def measure_time(label, func, args=(), count=3):
...     for i in range(count):
...         start = time.monotonic()
...         func(*args)
...         total = (time.monotonic() - start) * 1000
...         print(label + ':', '%s ms' % total)
...         
...         
... 
>>> 
```

1.  `measure_time`函数现在已经定义。在继续之前，请确保将上一个示例中`main.py`文件中的所有函数定义、模块导入和全局变量粘贴到 REPL 中。然后，运行以下代码块：

```py
>>> oled = get_oled()
>>> screen = Screen(oled)
>>> wait_for_networking()
address on network: 10.0.0.38
'10.0.0.38'
>>> conf = get_conf()
>>> APPID = conf['APPID']
>>> 
```

1.  我们现在已经有了测量`show_weather`函数执行时间所需的一切。运行下一个代码块来进行三次测量：

```py
>>> measure_time('show_weather', show_weather, [screen, APPID, 'Rome'])
-------- Rome --------
City: Rome
Temp: 9.34
Wind: 2.6

show_weather: 2047.0 ms
-------- Rome --------
City: Rome
Temp: 9.3
Wind: 2.6

show_weather: 1925.9 ms
-------- Rome --------
City: Rome
Temp: 9.36
Wind: 2.6

show_weather: 2019.04 ms
>>> 
```

1.  从这些测量中，我们可以看到每次调用大约需要 2 秒的执行时间。我们现在将在`show_weather`函数的开头和结尾添加对`invert`方法的调用，如下面的代码块所示：

```py
>>> def show_weather(screen, APPID, city):
...     screen.oled.invert(True)
...     weather = get_weather(APPID, city)
...     data = {}
...     data['city'] = city
...     data['temp'] = weather['main']['temp']
...     data['wind'] = weather['wind']['speed']
...     text = WEATHER.format(**data)
...     print('-------- %s --------' % city)
...     print(text)
...     screen.write(text)
...     screen.oled.invert(False)
...     
...     
... 
>>> 
```

1.  执行以下代码块时，将在`show_weather`函数执行的开始和结束提供视觉反馈：

```py
>>> show_weather(screen, APPID, 'Rome')
-------- Rome --------
City: Rome
Temp: 9.3
Wind: 2.6

>>> 
```

1.  下一段代码应该放在`main.py`文件中：

```py
from screen import Screen, get_oled
from netcheck import wait_for_networking
import urequests
import json
import time

CONF_PATH = 'conf.json'
API_URL = 'http://api.openweathermap.org/data/2.5/weather'
CITIES = ['Berlin', 'London', 'Paris', 'Tokyo', 'Rome', 'Oslo', 'Bangkok']
WEATHER = """\
City: {city}
Temp: {temp}
Wind: {wind}
"""

def get_conf():
    content = open(CONF_PATH).read()
    return json.loads(content)

def get_weather(APPID, city):
    url = API_URL + '?units=metric&APPID=' + APPID + '&q=' + city
    return urequests.get(url).json()

def show_weather(screen, APPID, city):
    screen.oled.invert(True)
    weather = get_weather(APPID, city)
    data = {}
    data['city'] = city
    data['temp'] = weather['main']['temp']
    data['wind'] = weather['wind']['speed']
    text = WEATHER.format(**data)
    print('-------- %s --------' % city)
    print(text)
    screen.write(text)
    screen.oled.invert(False)

def main():
    oled = get_oled()
    screen = Screen(oled)
    wait_for_networking()
    conf = get_conf()
    APPID = conf['APPID']
    for city in CITIES:
        show_weather(screen, APPID, city)
        time.sleep(1)

main()
```

当执行此脚本时，它将循环遍历每个城市，并使用新的反转颜色视觉反馈调用`show_weather`函数。

# 工作原理...

`measure_time`函数帮助我们测量了`show_weather`函数的执行时间。该函数正在从互联网获取数据，解析数据，然后执行一些屏幕操作来显示它。测得的执行时间大约为 2 秒。与台式电脑相比，微控制器的计算能力有限。在台式电脑上，类似这样的操作可能需要几百毫秒，但在微控制器上可能需要更长时间。由于这种明显的执行时间，我们通过在执行的开始处反转颜色来增强`show_weather`函数。这种颜色反转将在几毫秒内显示，并且会在任何其他处理之前显示。然后，在执行结束时，反转的颜色将恢复到正常状态，以指示函数已完成执行。

# 还有更多...

在以后的教程中，当我们将按钮连接到`show_weather`函数时，视觉反馈将变得非常重要。屏幕更新延迟 2 秒是非常明显的，用户需要某种视觉反馈来指示机器正在执行操作，而不是卡住了。本教程中展示的`invert`方法非常适合这个目的，并且不需要太多额外的代码来实现其结果。

# 另请参阅

以下是一些进一步信息的参考资料：

+   从可用性的角度来看，有关人类感知能力的详细信息可以在[`www.nngroup.com/articles/response-times-3-important-limits/`](https://www.nngroup.com/articles/response-times-3-important-limits/)找到。

+   有关软件可用性的文档可以在[`www.interaction-design.org/literature/topics/usability`](https://www.interaction-design.org/literature/topics/usability)找到。

# 创建一个函数来显示随机城市的天气

在这个教程中，我们将创建一个函数，每次调用时都会选择一个随机城市并在屏幕上显示其天气信息。该函数将使用`random`模块中的`choice`函数来选择一个随机城市，然后使用`show_weather`函数来显示该城市的天气信息。

在您想要向项目中添加一些随机性以使与该设备的交互更加不可预测的情况下，本教程可能对您有用。这可以在您的项目中创建一些意想不到的和令人惊讶的行为，使其更有趣。

# 准备工作

您需要访问 ESP8266 上的 REPL 来运行本教程中提供的代码。

# 如何操作...

让我们来看看这个教程需要哪些步骤：

1.  在 REPL 中运行以下代码行：

```py
>>> import random
>>> 
>>> def show_random_weather(screen, APPID):
...     city = random.choice(CITIES)
...     show_weather(screen, APPID, city)
...     
...     
... 
>>> 
```

1.  `show_random_weather`函数现在已经定义。在继续之前，请确保将上一个教程中的`main.py`文件中的所有函数定义，模块导入和全局变量粘贴到 REPL 中。然后，运行以下代码块：

```py
>>> oled = get_oled()
>>> screen = Screen(oled)
>>> wait_for_networking()
address on network: 10.0.0.38
'10.0.0.38'
>>> conf = get_conf()
>>> APPID = conf['APPID']
>>> 
```

1.  运行下一段代码，将显示随机城市的天气：

```py
>>> show_random_weather(screen, APPID)
-------- Bangkok --------
City: Bangkok
Temp: 30.01
Wind: 5.1

>>> 
```

1.  现在我们将循环三次并调用`show_random_weather`函数来测试其功能：

```py
>>> for i in range(3):
...     show_random_weather(screen, APPID)
...     
...     
... 
-------- Rome --------
City: Rome
Temp: 9.08
Wind: 2.6

-------- Berlin --------
City: Berlin
Temp: 8.1
Wind: 3.6

-------- London --------
City: London
Temp: 5.41
Wind: 6.2

>>> 
```

1.  下一段代码应该放在`main.py`文件中：

```py
from screen import Screen, get_oled
from netcheck import wait_for_networking
import urequests
import json
import time
import random

CONF_PATH = 'conf.json'
API_URL = 'http://api.openweathermap.org/data/2.5/weather'
CITIES = ['Berlin', 'London', 'Paris', 'Tokyo', 'Rome', 'Oslo', 'Bangkok']
WEATHER = """\
City: {city}
Temp: {temp}
Wind: {wind}
"""

def get_conf():
    content = open(CONF_PATH).read()
    return json.loads(content)

def get_weather(APPID, city):
    url = API_URL + '?units=metric&APPID=' + APPID + '&q=' + city
    return urequests.get(url).json()

def show_weather(screen, APPID, city):
    screen.oled.invert(True)
    weather = get_weather(APPID, city)
    data = {}
    data['city'] = city
    data['temp'] = weather['main']['temp']
    data['wind'] = weather['wind']['speed']
    text = WEATHER.format(**data)
    print('-------- %s --------' % city)
    print(text)
    screen.write(text)
    screen.oled.invert(False)

def show_random_weather(screen, APPID):
    city = random.choice(CITIES)
    show_weather(screen, APPID, city)

def main():
    oled = get_oled()
    screen = Screen(oled)
    wait_for_networking()
    conf = get_conf()
    APPID = conf['APPID']
    for i in range(3):
        show_random_weather(screen, APPID)

main()
```

当执行此脚本时，它将循环三次并在每次迭代中选择一个随机城市，然后显示其天气信息。

# 工作原理...

`show_random_weather`函数期望两个参数作为其输入。屏幕和`APPID`需要作为输入参数，以进行所需的 API 调用并更新屏幕内容。在`random`模块的`choice`函数上调用`CITIES`列表，以选择一个随机城市。一旦选择了这个城市，就可以使用`show_weather`函数获取并显示其天气。在这个示例中，`main`函数循环三次，并在每个`for`循环迭代中调用`show_random_weather`函数。

# 还有更多...

这个示例是互联网连接的天气机器的最后几个部分之一。我们已经构建和测试了应用程序的每个部分，以确认每个部分在构建上一层的附加逻辑之前都是正常的。这个示例的所有代码和逻辑都是自包含的，这提高了代码的可读性，也有助于故障排除。如果发生任何错误，通过确切地知道异常是在哪个函数中引发的，将更容易进行故障排除。

# 另请参阅

以下是一些进一步信息的参考资料：

+   与 MicroPython 交互显示的文档详细信息可以在[`learn.adafruit.com/micropython-displays-drawing-shapes`](https://learn.adafruit.com/micropython-displays-drawing-shapes)找到。

+   使用 Adafruit FeatherWing OLED 的微控制器项目的文档可以在[`learn.adafruit.com/digital-display-badge`](https://learn.adafruit.com/digital-display-badge)找到。

# 创建一个显示世界各地天气的物联网按钮

在这个示例中，我们将为我们的互联网连接的天气机器添加最后的修饰。我们将在本章中介绍的代码大部分，并在`main`函数中添加一个`事件`循环，以便我们可以通过显示世界各地随机城市的天气来响应按钮按下事件。这个示例将为您提供一个很好的例子，说明您如何向现有代码库添加`事件`循环，以创建用户交互性。

# 准备工作

您需要访问 ESP8266 上的 REPL 来运行本示例中提供的代码。

# 如何操作...

让我们按照这个示例中所需的步骤进行操作：

1.  在 REPL 中执行下一个代码块：

```py
>>> from machine import Pin
>>> 
>>> BUTTON_A_PIN = 0
>>> 
```

1.  现在导入`Pin`对象，以便我们可以与板载按钮进行交互。在继续之前，请确保将上一个示例中的`main.py`文件中的所有函数定义、模块导入和全局变量粘贴到 REPL 中。然后运行以下代码块：

```py
>>> button = Pin(BUTTON_A_PIN, Pin.IN, Pin.PULL_UP)
>>> 
```

1.  `button`变量现在可以读取按钮 A 的状态。运行下一个代码块来检测当前是否按下按钮 A：

```py
>>> not button.value()
False
>>> 
```

1.  在按下按钮 A 时，执行以下代码块：

```py
>>> not button.value()
True
>>> 
```

1.  运行下一个代码块来准备`screen`和`APPID`变量：

```py
>>> oled = get_oled()
>>> screen = Screen(oled)
>>> wait_for_networking()
address on network: 10.0.0.38
'10.0.0.38'
>>> conf = get_conf()
>>> APPID = conf['APPID']
>>> 
```

1.  以下代码块将启动一个`事件`循环。每次按下按钮 A 时，应显示一个随机城市的天气：

```py
>>> while True:
...     if not button.value():
...         show_random_weather(screen, APPID)
...         
...         
... 
-------- London --------
City: London
Temp: 6.62
Wind: 4.6

-------- Paris --------
City: Paris
Temp: 4.53
Wind: 2.6

-------- Rome --------
City: Rome
Temp: 10.39
Wind: 2.6
>>> 
```

1.  下一个代码块应放入`main.py`文件中：

```py
from screen import Screen, get_oled
from netcheck import wait_for_networking
from machine import Pin
import urequests
import json
import time
import random

BUTTON_A_PIN = 0
CONF_PATH = 'conf.json'
API_URL = 'http://api.openweathermap.org/data/2.5/weather'
CITIES = ['Berlin', 'London', 'Paris', 'Tokyo', 'Rome', 'Oslo', 'Bangkok']
WEATHER = """\
City: {city}
Temp: {temp}
Wind: {wind}
"""

def get_conf():
    content = open(CONF_PATH).read()
    return json.loads(content)

def get_weather(APPID, city):
    url = API_URL + '?units=metric&APPID=' + APPID + '&q=' + city
    return urequests.get(url).json()

def show_weather(screen, APPID, city):
    screen.oled.invert(True)
    weather = get_weather(APPID, city)
    data = {}
    data['city'] = city
    data['temp'] = weather['main']['temp']
    data['wind'] = weather['wind']['speed']
    text = WEATHER.format(**data)
    print('-------- %s --------' % city)
    print(text)
    screen.write(text)
    screen.oled.invert(False)

def show_random_weather(screen, APPID):
    city = random.choice(CITIES)
    show_weather(screen, APPID, city)

def main():
    oled = get_oled()
    screen = Screen(oled)
    wait_for_networking()
    conf = get_conf()
    APPID = conf['APPID']
    button = Pin(BUTTON_A_PIN, Pin.IN, Pin.PULL_UP)
    show_random_weather(screen, APPID)
    while True:
        if not button.value():
            show_random_weather(screen, APPID)

main()
```

当执行此脚本时，它将启动一个`事件`循环，每次按下按钮 A 时都会获取并显示一个随机城市的天气。

# 工作原理...

在这个示例中的`main`函数创建了一个名为`Button`的`Pin`对象，它将连接到按钮 A。我们可以使用这个`button`变量来轮询按钮的状态。然后，我们显示一个随机城市的天气，以便应用程序的起始状态是显示屏上显示的天气。然后，启动一个`无限`循环，这将是我们的`事件`循环，用于处理任何按钮事件。在每个循环中，我们检查按钮 A 是否被按下。如果是，则调用`show_random_weather`函数在屏幕上显示一个随机城市的天气。

# 还有更多...

此处的食谱对单个按钮的按下做出反应，显示随机天气。我们可以将按钮 B 和 C 连接到我们的主“事件”循环，并让它们产生其他功能。按下按钮 A 可能会更改城市，而 B 和 C 可以让您滚动并查看与当前选择的城市相关的更多天气信息。下一张照片显示了连接到互联网的天气机在显示东京市天气信息时的样子：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mcpy-cb/img/c0b499f3-126b-47ee-b061-1ca6896c55dc.png)

这个食谱也可以更改为从网络服务中获取和显示任何信息。您可以获取最新的新闻头条并显示它们，或者从 RESTful 笑话 API 中显示一个随机笑话。拥有多行文本显示和互联网连接，您可以做的事情是无限的。

# 另请参阅

以下是一些进一步信息的参考资料：

+   关于在 MicroPython 上使用`PULL_UP`设置与按钮的文档可以在[`learn.adafruit.com/micropython-hardware-digital-i-slash-o/digital-inputs`](https://learn.adafruit.com/micropython-hardware-digital-i-slash-o/digital-inputs)找到。

+   有关使用 RESTful 笑话 API 的文档可以在[`www.icndb.com/api/`](http://www.icndb.com/api/)找到。
