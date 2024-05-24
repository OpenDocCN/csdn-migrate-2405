# MicroPython 秘籍（一）

> 原文：[`zh.annas-archive.org/md5/EE140280D367F2C84B38C2F3034D057C`](https://zh.annas-archive.org/md5/EE140280D367F2C84B38C2F3034D057C)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

MicroPython 是 Python 3 编程语言的精简实现，能够在各种微控制器上运行。它为这些微控制器提供了 Python 编程语言的大部分功能，如函数、类、列表、字典、字符串、读写文件、列表推导和异常处理。

微控制器是通常包括 CPU、内存和输入/输出外围设备的微型计算机。尽管它们的资源相对于 PC 来说更有限，但它们可以制作成更小的尺寸，功耗更低，成本更低。这些优势使得它们可以在以前不可能的广泛应用中使用。

本书将涵盖 MicroPython 语言的许多不同特性，以及许多不同的微控制器板。最初的章节将提供简单易懂的配方，以使这些板与人们和他们的环境互动。主题涵盖从传感器读取温度、光线和运动数据到与按钮、滑动开关和触摸板互动。还将涵盖在这些板上产生音频播放和 LED 动画的主题。一旦打下了这个基础，我们将构建更多涉及的项目，如互动双人游戏、电子乐器和物联网天气机。您将能够将从这些配方中学到的技能直接应用于自己的嵌入式项目。

# 本书适合对象

这本书旨在帮助人们将 Python 语言的强大和易用性应用于微控制器的多功能性。预期读者具有 Python 的基础知识才能理解本书。

# 本书内容

第一章，*Getting Started with MicroPython*，介绍了 Adafruit Circuit Playground Express 微控制器，并教授了在此硬件上使用 MicroPython 的核心技能。

第二章，*Controlling LEDs*，涵盖了控制 NeoPixel LED、灯光颜色以及如何通过控制板上灯光变化的时间来创建动画灯光秀的方法。

第三章，*Creating Sound and Music*，讨论了如何在 Adafruit Circuit Playground Express 上制作声音和音乐的方法。将涵盖诸如使板在特定声音频率下发出蜂鸣声以及使用 WAV 文件格式和板载扬声器播放音乐文件等主题。

第四章，*Interacting with Buttons*，展示了与 Adafruit Circuit Playground Express 上的按钮和触摸板互动的方法。将讨论检测按钮何时被按下或未被按下的基础知识，以及高级主题，如微调电容触摸板的触摸阈值。

第五章，*Reading Sensor Data*，介绍了从各种不同类型的传感器（如温度、光线和运动传感器）读取传感器数据的方法。

第六章，*Button Bash Game*，指导我们创建一个名为*Button Bash*的双人游戏，您可以直接在 Circuit Playground Express 上使用按钮、NeoPixels 和内置扬声器进行游戏。

第七章，*Fruity Tunes*，解释了如何使用 Adafruit Circuit Playground Express 和一些香蕉创建一个乐器。触摸板将用于与香蕉互动，并在每次触摸不同的香蕉时播放不同的音乐声音。

第八章，“让我们动起来”，介绍了 Adafruit CRICKIT 硬件附加组件，它将帮助我们通过 Python 脚本控制电机和舵机；特别是它们的速度、旋转方向和角度将通过这些脚本进行控制。

第九章，“在 micro:bit 上编码”，涵盖了与 micro:bit 平台交互的方法。将讨论如何控制其 LED 网格显示并与板载按钮交互。

第十章，“控制 ESP8266”，介绍了 Adafruit Feather HUZZAH ESP8266 微控制器，并讨论了它与其他微控制器相比的特点和优势。将涵盖连接到 Wi-Fi 网络、使用 WebREPL 和通过 Wi-Fi 传输文件等主题。

第十一章，“与文件系统交互”，讨论了与操作系统（OS）相关的一些主题，如列出文件、删除文件、创建目录和计算磁盘使用量。

第十二章，“网络”，讨论了如何执行许多不同的网络操作，如 DNS 查找、实现 HTTP 客户端和 HTTP 服务器。

第十三章，“与 Adafruit FeatherWing OLED 交互”，介绍了 Adafruit FeatherWing OLED 硬件附加组件，它可以连接到 ESP8266，为互联网连接的微控制器添加显示，以显示文本图形并使用包含的三个硬件按钮与用户交互。

第十四章，“构建 IoT 天气机”，解释了如何创建一个 IoT 设备，该设备将在按下按钮时从 IoT 设备本身检索天气数据并向用户显示。

第十五章，“在 Adafruit HalloWing 上编码”，介绍了 Adafruit HalloWing 微控制器，它内置了一个 128x128 全彩薄膜晶体管（TFT）显示屏，可以在微控制器上显示丰富的图形图像。

# 为了充分利用本书

读者应具有 Python 编程语言的基本知识。读者最好具有基本的导入包和使用 REPL 的理解，以充分利用本书。

# 下载示例代码文件

您可以从[www.packtpub.com](http://www.packtpub.com/support)的帐户中下载本书的示例代码文件。如果您在其他地方购买了本书，您可以访问[www.packtpub.com/support](http://www.packtpub.com/support)并注册，以便文件直接通过电子邮件发送给您。

您可以按照以下步骤下载代码文件：

1.  在[www.packtpub.com](http://www.packtpub.com/support)上登录或注册。

1.  选择“支持”选项卡。

1.  点击“代码下载和勘误”。

1.  在搜索框中输入书名并按照屏幕上的说明操作。

下载示例代码文件后，请确保使用以下最新版本解压或提取文件夹：

+   Windows 的 WinRAR/7-Zip

+   Mac 的 Zipeg/iZip/UnRarX

+   Linux 的 7-Zip/PeaZip

该书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/MicroPython-Cookbook`](https://github.com/PacktPublishing/MicroPython-Cookbook)。我们还有来自丰富书籍和视频目录的其他代码包可供使用，网址为**[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)**。去看看吧！

# 下载彩色图片

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图像。您可以在这里下载：[`www.packtpub.com/sites/default/files/downloads/9781838649951_ColorImages.pdf`](https://www.packtpub.com/sites/default/files/downloads/9781838649951_ColorImages.pdf)。

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词，数据库表名，文件夹名，文件名，文件扩展名，路径名，虚拟 URL，用户输入和 Twitter 句柄。例如： "这个食谱需要在计算机上安装 Python 和`pip`。"

一个代码块设置如下：

```py
from adafruit_circuitplayground.express import cpx
import time

cpx.pixels[0] = (255, 0, 0) # set first NeoPixel to the color red
time.sleep(60)
```

当我们希望引起您对代码块的特定部分的注意时，相关的行或项目会以粗体显示：

```py
from adafruit_circuitplayground.express import cpx
import time

RAINBOW = [
 0xFF0000, # red 
 0xFFA500, # orange
```

任何命令行输入或输出都以如下形式书写：

```py
>>> 1+1
2
```

**粗体**：表示一个新术语，一个重要的词，或者您在屏幕上看到的词。例如，菜单或对话框中的单词会以这种形式出现在文本中。例如："单击工具栏上的串行按钮，以打开与设备的 REPL 会话。"

警告或重要说明会出现在这样的形式。提示和技巧会出现在这样的形式。

# 章节

在本书中，您会经常看到几个标题（*准备工作*，*如何做…*，*它是如何工作的…*，*还有更多…*，和*另请参阅*）。

为了清晰地说明如何完成一个食谱，使用以下章节：

# 准备工作

这一部分告诉您在食谱中可以期待什么，并描述如何设置食谱所需的任何软件或初步设置。

# 如何做…

这一部分包含了遵循食谱所需的步骤。

# 它是如何工作的…

这一部分通常包括对前一部分发生的事情的详细解释。

# 还有更多…

这一部分包括了有关食谱的额外信息，以使您对食谱更加了解。

# 另请参阅

这一部分提供了有用的链接，指向食谱的其他有用信息。


# 第一章：开始使用 MicroPython

现在是使用 MicroPython 等技术的激动人心的时刻。它们使得微小和廉价的硬件设备更容易访问，因为你可以使用高级语言如 Python 来编程。与其他微控制器语言相比，比如从 Web 服务中检索数据可以轻松地用几行代码完成，因为它们与 Python 相比操作的层级更低，需要更多的步骤。这非常有力量，因为你将能够更快地获得结果，并在更短的时间内迭代不同的设计和原型。

在本章中，我们将为您提供运行 MicroPython 所需的软件和硬件的基本技能。您将学习如何更新设备上的固件和库。还将介绍一些加载第一个程序并使用高级功能（如自动重新加载代码）的方法。最后，将介绍一些使用 REPL 的方法，这是一种快速与 MicroPython 设备上的可用组件进行交互和实验的强大方式。

在本章中，我们将涵盖以下内容：

+   刷新微控制器固件

+   执行你的第一个程序

+   使用屏幕访问 REPL

+   使用 Mu 访问 REPL

+   在 REPL 中执行命令

+   使用自动重新加载功能

+   更新 CircuitPython 库

# 什么是 MicroPython？

MicroPython 是澳大利亚程序员和物理学家 Damien George 的创造，他在 2013 年发起了一个 Kickstarter 活动，以支持该语言的开发和最初的微控制器硬件。在项目成功之后，越来越多的设备（具有不同制造商的各种芯片组）得到了 MicroPython 的支持，为使用 MicroPython 制作项目时提供了多种选择。

MicroPython 是 Python 3 编程语言的精简实现，能够在硬件资源非常有限的设备上运行，比如微控制器。MicroPython 已经实现了 Python 编程语言的大部分功能，比如函数、类、列表、字典、字符串、读写文件、列表推导和异常处理。

REPL 也已经实现，并且可以通过串行连接进行交互。提供了一系列核心 Python 库，可以实现各种应用。JSON 和`socket`库允许 Web 客户端和服务器的实现，使得基于 Python 的物联网（IoT）项目在微控制器上成为现实。

通过将最受欢迎和易于使用的编程语言之一引入到嵌入式计算的激动人心的世界中，MicroPython 为创客和企业家打开了新的大门，让他们的创意得以实现。本书将探索不同的方法来利用 MicroPython 语言与各种独特的微控制器设备，每种设备都带来了不同的功能。

在微控制器上运行 MicroPython 的独特和迷人之处之一是它不在操作系统（OS）上运行，而是直接在裸金属上运行。这些独特的特性以多种方式表现出来，比如在硬件上电的瞬间就能运行你的 Python 代码，因为不需要启动操作系统。

另一个方面是 Python 代码直接访问硬件并与之交互，创造了一些在典型 Python 应用程序上不可能实现的硬件可能性。

现在我们知道 MicroPython 可以在微控制器上运行，让我们看看微控制器到底是什么。

# 什么是微控制器？

微控制器是单芯片上的小型计算机。它们通常包括 CPU、内存和输入/输出外设。它们的计算资源比现代 PC 上可能找到的要有限。

然而，与 PC 相比，它们可以制作成更小的尺寸，可以嵌入各种电子和机械设备中。它们的功耗通常要小得多，因此可以提供数天的电池寿命。它们的单位成本要低得多，这就打开了在广泛地理区域收集传感器数据的数百个这样的设备的可能性，而且仍然是经济可行的。

传统上，在微控制器上创建应用程序是一个困难的过程，因为你必须编写非常低级的代码，这需要时间，而且很难调试。MicroPython 将 Python 的易用性带到了微控制器上。它能够提供与硬件的更轻松交互，同时在资源受限的环境中工作，并提供广泛的功能和高度的响应性。

# 什么是 CircuitPython？

CircuitPython 是 Adafruit Industries 创建的 MicroPython 分支，使得与微控制器的工作更简单。它通过 Python 库对许多传感器和 Adafruit 设备的组件提供了出色的支持。它还允许代码轻松加载和运行，而无需安装任何额外的软件应用程序，通过将微控制器的存储公开为磁盘驱动器。

一般来说，MicroPython 和 CircuitPython 之间的差异很小，在许多情况下，代码在两种实现上都会运行相同。

# 什么是 Circuit Playground Express？

Adafruit Circuit Playground Express 是一款价格便宜但功能丰富的微控制器，具有丰富的输入和输出设备，这些设备已经内置在设备中。以下是该设备中的一些主要硬件特性：

+   10 个迷你 NeoPixels，每个都能显示全色彩范围

+   作为运动传感器（带有敲击检测和自由落体检测的三轴加速度计）

+   一个温度传感器

+   一个光传感器

+   一个声音传感器

+   一个迷你扬声器

+   两个带有标签 A 和 B 的按钮

+   一个滑动开关

+   一个红外线接收器和发射器

+   八个鳄鱼夹友好的输入/输出引脚

+   支持 I2C 和 PWM 输出

+   七个电容触摸输入

+   一个红色 LED

+   一个复位按钮

+   一个运行在 3.3V 和 48MHz 的 ATSAMD21 ARM Cortex M0 处理器

+   2MB 的闪存存储

+   一个用于连接 PC 的微型 USB 端口

这些将是八章中唯一需要的设备。后面的章节将介绍一组不同的设备。

请参考[`learn.adafruit.com/welcome-to-circuitpython?view=all`](https://learn.adafruit.com/welcome-to-circuitpython?view=all)获取更多信息。

# 在哪里购买

Adafruit Circuit Playground Express 可以直接从 Adafruit（[`www.adafruit.com/product/3333`](https://www.adafruit.com/product/3333)）购买。它也可以从在线零售商购买，如亚马逊和 Pimoroni。

对于本书的目的，我们建议购买 Circuit Playground Express - 基础套件（[`www.adafruit.com/product/3517`](https://www.adafruit.com/product/3517)），还包括 USB 电缆和电池包，以便项目可以轻松地制作成便携式。

# 参考

以下是一些参考：

+   [`micropython.org`](http://micropython.org)上的 MicroPython 网页

+   [`www.kickstarter.com/projects/214379695/micro-python-python-for-microcontrollers`](https://www.kickstarter.com/projects/214379695/micro-python-python-for-microcontrollers)上的 Kickstarter 上的 MicroPython 项目

+   [`www.pcmag.com/encyclopedia/term/46924/microcontroller`](https://www.pcmag.com/encyclopedia/term/46924/microcontroller)上的 PC Mag 上的微控制器文章

+   CircuitPython 的 Adafruit 学习指南位于[`learn.adafruit.com/welcome-to-circuitpython/what-is-circuitpython`](https://learn.adafruit.com/welcome-to-circuitpython/what-is-circuitpython)

+   CircuitPython 官方文档位于[`circuitpython.readthedocs.io`](https://circuitpython.readthedocs.io)

# 刷新微控制器固件

在这个教程中，我们将展示如何使用最新的 CircuitPython 固件在 Circuit Playground Express 上刷新固件。在开始使用该设备之前，有两个原因需要这样做。首先，该设备还支持 Microsoft MakeCode 编程环境，并且使用 CircuitPython 固件刷新设备可以准备好使用 Python 语言。

其次，CircuitPython 语言正在不断发展，每隔几个月发布一次版本，因此定期更新固件以加载最新版本的语言到板上是个好主意。

# 准备工作

本章的介绍为我们提供了购买 Circuit Playground Express 的指导，这对本章中的所有教程都是必需的。还需要一个 USB micro B 电缆和运行 macOS、Windows 或 Linux 的计算机。

# 如何操作...

让我们看看以下步骤：

1.  下载最新的 CircuitPython Circuit Playground Express UF2 文件([`github.com/adafruit/circuitpython/releases/latest`](https://github.com/adafruit/circuitpython/releases/latest))。CircuitPython 3.1.2 版本的 UF2 文件名为`adafruit-circuitpython-circuitplayground_express-3.1.2.uf2`。对于每个 CircuitPython 版本，都有许多不同的支持的微控制器的`uf2`文件。确保下载适用于 Circuit Playground Express 设备的文件。

在本教程中，我们将使用最新的稳定版本的 CircuitPython，目前是 3.1.2。

1.  将 USB 电缆连接到 Circuit Playground Express 和计算机。

1.  双击位于板中心的复位按钮。如果一切顺利，您将看到所有 LED 变为绿色；否则，很可能是使用的 USB 电缆出现了问题。在某些情况下，如果双击不起作用，请尝试单击复位按钮。

1.  您将看到一个名为 CPLAYBOOT 的新磁盘出现：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mcpy-cb/img/8c4d1da7-3789-459e-a278-debe217f8335.png)

1.  将 UF2 文件复制到此驱动器中。

1.  一旦 UF2 文件完全写入设备，固件将被更新，一个新的驱动器将出现，名为 CIRCUITPY：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mcpy-cb/img/2ad4585f-ecc2-47fd-91db-8d7dce9cf589.png)

现在，我们的 Circuit Playground Express 可以使用了。

# 它是如何工作的...

传统上，需要安装和使用特殊软件来处理微控制器的刷新过程。微软开发了 UF2 方法，大大简化了该过程，不需要任何特殊软件或命令行执行来刷新微控制器。

一旦板子进入引导程序模式，它将期望保存一个 UF2 文件。当 UF2 文件复制到驱动器时，微控制器将检测到文件复制已完成，然后自动进行微控制器刷新并重新启动设备，此时设备将重新连接并准备好使用。

UF2 文件格式可以在[`github.com/Microsoft/uf2`](https://github.com/Microsoft/uf2)找到。

# 还有更多...

与以前的方法相比，UF2 方法使刷新微控制器固件的过程更加简单和快速。并非所有 MicroPython 板都支持 UF2 方法，因此需要更复杂的方法来安装特殊软件来进行固件刷新。不同的板和制造商之间所需的确切过程和软件各不相同。

当您使用这个闪存软件时，通常需要知道设备在计算机上显示为的串行设备的确切名称。这些设备的命名在 Windows、Linux 和 macOS 之间有所不同。这种类型的软件通常需要在终端中运行，因此您需要一些命令行知识来与之交互。出于所有这些原因，使用支持的设备（如 Circuit Playground Express）与 UF2 是开始使用 MicroPython 进行实验的首选方式。

# 另请参阅

关于本文描述的过程，Adafruit 和 Microsoft 网站上有许多资源。以下是一些参考资料：

+   有关更新 CircuitPython 的文档可以在[`learn.adafruit.com/adafruit-circuit-playground-express/circuitpython-quickstart`](https://learn.adafruit.com/adafruit-circuit-playground-express/circuitpython-quickstart)找到。

+   有关 UF2 过程的详细说明，请参阅[`makecode.com/blog/one-chip-to-flash-them-all`](https://makecode.com/blog/one-chip-to-flash-them-all)。[](https://makecode.com/blog/one-chip-to-flash-them-all)

# 执行您的第一个程序

在本文中，我们将向您展示如何在 Circuit Playground Express 上加载您的第一个程序，以及如何修改程序并重新加载它。然后，程序将点亮板上可用的十个 NeoPixel 中的一个。

# 准备工作

一旦 Circuit Playground Express 刷入了 CircuitPython 固件，您可以将 Python 脚本加载到板子上并运行它们。

# 如何做到...

让我们看看如何做到这一点：

1.  确保板子通过 USB 电缆连接到计算机，并且`CIRCUITPY`驱动器出现。

1.  在驱动器上保存一个文本文件，内容如下，并将其命名为`main.py`：

```py
from adafruit_circuitplayground.express import cpx
import time

cpx.pixels[0] = (255, 0, 0)  # set first NeoPixel to the color red
time.sleep(60)
```

1.  保存文件后，弹出驱动器，然后从计算机上断开并重新连接 USB 电缆。

1.  驱动器上的第一个 NeoPixel 应该点亮为红色。

1.  在您选择的文本编辑器中打开`main.py`文件，并将`cpx.pixels[0]`行更改为`cpx.pixels[1]`。保存文件。这个更改将使第二个 NeoPixel 点亮，而不是第一个。

1.  弹出驱动器，然后断开，重新连接 USB 电缆以使更改生效。

# 它是如何工作的...

当设备打开时，它会寻找某些文件，例如`code.py`或`main.py`，如果找到，将作为启动过程的一部分执行。通过这种方式，您可以指定在设备上电时要运行的代码。脚本首先导入`adafruit_circuitplayground.express`库，以便它可以控制 NeoPixels。通过给它一组适当的 RGB 值，将第一个 NeoPixel 设置为红色。

最后，脚本将休眠 60 秒，以便 LED 在脚本结束执行前保持点亮一分钟。

# 还有更多...

现在，板子已经加载了一个 Python 脚本，可以从计算机断开连接，并连接电池组。一旦电池组由脚本供电，它应该运行并点亮所选的 NeoPixel。

这是创建便携且廉价的项目的简单方法，可以直接从板上运行代码，无需连接 PC，并且可以通过三节 AAA 电池简单供电。

# 另请参阅

CircuitPython 在启动时寻找的一些文件的描述在[`learn.adafruit.com/welcome-to-circuitpython?view=all#naming-your-program-file-7-30`](https://learn.adafruit.com/welcome-to-circuitpython?view=all#naming-your-program-file-7-30)中有描述。

# 使用屏幕访问 REPL

Linux 和 macOS 有强大的终端仿真器，如`screen`，可以用于通过串行（USB）连接直接连接到设备的**读取-求值-打印循环**（**REPL**）。本文将展示如何连接到 REPL 并开始交互式地运行 Python 代码。

# 准备工作

此配方可以在 macOS 或 Linux 计算机上使用，并可能需要`screen`命令可用。在 macOS 上，Screen 应用程序是内置的，因此无需安装。在 Ubuntu 上，可以使用`apt install screen`命令安装 Linux Screen。

# 如何做...

让我们看看如何连接 REPL 并运行代码：

1.  打开计算机的终端应用程序。

1.  在 Linux 上运行`ls /dev/ttyACM*`或在 macOS 上运行`ls /dev/tty.*`来列出插入设备之前的设备名称。

1.  使用 USB 电缆将板连接到计算机。

1.  使用相同的命令再次列出设备名称，以发现板的设备名称。

1.  如果设备名称为`/dev/ttyACM0`，则`screen`命令将是`screen /dev/ttyACM0 115200`。

1.  在终端中输入命令并启动 Screen 应用程序。

1.  如果 Screen 能够成功连接，Python REPL 应该会出现在终端上，并显示类似以下文本的输出：

```py
Adafruit CircuitPython 3.1.2 on 2019-01-07; Adafruit CircuitPlayground Express with samd21g18 **>>>** 
```

1.  如果提示未出现，可以尝试按下*Ctrl* + *C*，然后按*Enter*，这将停止当前正在运行的 Python 脚本，并使用以下消息运行 REPL：

```py
Press any key to enter the REPL. Use CTRL-D to reload.
```

1.  一旦 REPL 提示出现，我们将必须通过评估`1+1`表达式来测试提示是否正常工作。它应该产生以下输出：

```py
>>> 1+1
2
```

# 它是如何工作的...

Circuit Playground Express 通过 USB 连接公开了串行设备，可以通过多种不同的终端仿真程序访问。除了`screen`之外，还有其他程序，如`picocom`和`minicom`，也可以使用。

在命令中设置的最后一个参数为 115,200，设置了连接的波特率，应该以该速度设置。一旦成功建立连接，就会开始一个交互式会话，允许直接在设备上评估表达式，并且输出直接显示在终端上。

# 还有更多...

书中的许多配方将介绍使用 REPL 的脚本的不同部分。这将使您有机会在运行每个代码片段时获得即时反馈。一旦您在 REPL 中输入了不同的片段，您还可以使用 REPL 功能来辅助您对代码进行实验。您可以使用*上*和*下*箭头键来浏览已在 REPL 中输入的命令历史记录。例如，如果您刚刚在 REPL 中执行了一行代码，打开了板上的特定像素，您可以按*上*键，通过编辑该行并再次按*Enter*来更改点亮的像素。

# 另请参阅

以下是一些参考资料：

+   有关在 CircuitPython 板上使用 REPL 的详细信息，请参阅[`learn.adafruit.com/welcome-to-circuitpython/the-repl`](https://learn.adafruit.com/welcome-to-circuitpython/the-repl)。

+   有关使用 REPL 访问 MicroPython 的详细信息，请访问[`learn.adafruit.com/micropython-basics-how-to-load-micropython-on-a-board/serial-terminal`](https://learn.adafruit.com/micropython-basics-how-to-load-micropython-on-a-board/serial-terminal)。

# 使用 Mu 访问 REPL

Mu 是一个易于使用的图形代码编辑器，用 Python 编写，可在 Windows、macOS、Linux 和树莓派上运行。在这个配方中，我们将学习如何安装 Mu 并使用它来访问 Circuit Playground Express 上的 REPL。

# 准备工作

此配方要求计算机上安装 Python 和`pip`。Mu 编辑器将使用`pip`命令安装，因此可以选择在`virtualenv`中运行此配方。

# 如何做...

让我们看看如何做到这一点：

1.  执行以下`pip3 install mu-editor`命令以安装 Mu 编辑器。

1.  运行`mu-editor`命令启动编辑器。

1.  第一次运行编辑器时，它将询问应以哪种模式运行。在下面的屏幕截图中，选择 Adafruit CircuitPython 模式：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mcpy-cb/img/7c502520-9416-4efa-93be-c1d8a5e59d3d.png)

1.  单击工具栏上的串行按钮以与设备打开 REPL 会话。

1.  在 Linux 系统上，如果出现“无法连接到设备”错误，则退出编辑器，并使用`sudo /full/path/to/mu-editor`命令重新启动编辑器，其中给出编辑器的绝对路径。

1.  一旦成功连接到设备，您可以通过评估`1+1`表达式来测试 REPL，这应该会产生如下屏幕截图所示的输出：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mcpy-cb/img/ce5e2439-ca20-4f8b-8c5e-3f29f4bf7ab1.png)

# 它是如何工作的...

当您在 Mu 编辑器中点击串行按钮时，它将尝试打开与板的串行连接。如果成功，它会捕获您的输入，将其发送到设备，并显示输出，就像典型的终端仿真器一样。

这个应用程序的美妙之处在于它适用于所有主要的桌面操作系统，并且可以自动找到正确的设备地址，无需手动指定，这是 Typical Terminal emulators 所必需的。它还具有非常简单和易于接近的布局，使得首次用户连接到微控制器变得容易使用。

# 还有更多...

Mu 编辑器是一个很棒的图形应用程序，当你第一次开始使用 MicroPython 时，它是一个很好的开始。它简单直观的设计使得你可以快速提高生产力，并且很有趣地探索其不同的功能。除了 REPL 功能之外，它还有主要部分的屏幕，可以用来编辑和保存 Python 脚本。它具有代码编辑功能，如代码完成，并将显示有关函数接受参数和函数功能的详细弹出窗口。

# 另请参阅

以下是一些参考资料：

+   该项目的 GitHub 存储库位于[`github.com/mu-editor/mu`](https://github.com/mu-editor/mu)。

+   项目主页位于[`codewith.mu/`](https://codewith.mu/)[.](https://github.com/mu-editor/mu)

# 在 REPL 中执行命令

以下配方展示了 REPL 的不同用法。

# 准备工作

可以从前面的两个配方中使用任一种方法来获取 REPL。

# 如何做...

1.  通过您喜欢的应用程序打开 REPL。

1.  与 CPython 中的 REPL 提供的许多相同功能在 MicroPython 实现中也可以使用。最后一个返回的值可以通过`_`访问：

```py
>>> 2 + 2
4
>>> _ + 2
6
```

1.  还支持连续行，这样可以通过 REPL 定义函数或`for`循环，如下面的输出所示：

```py
>>> def add(a, b):
...     return a + b
... 
... 
... 
>>> add(2, 2)
4
>>> 
```

1.  即使在受限的微控制器硬件上，也支持任意精度整数。以下代码显示了超出 64 位整数值限制的整数的算术运算：

```py
>>> 2**100 + 2**101
3802951800684688204490109616128
```

# 它是如何工作的...

REPL 实现具有我们在 CPython 实现中所熟悉和喜爱的大多数功能。MicroPython 实现必须处理严格的硬件约束，以便在微控制器上运行。但是，即使在这些约束下，两种实现中 REPL 的最终用户体验几乎是相同的，这使得对 Python 开发人员来说很容易过渡。

# 还有更多...

当您想要尝试某些 MicroPython 库或设备上的某些功能时，REPL 可以成为一个宝贵的工具。它让您可以轻松地导入不同的 Python 模块，并以更直接的方式调用这些库提供的函数，以发现它们实际上如何与硬件交互。这些微控制器上的许多组件可以根据不同的项目需求进行微调。REPL 经常成为进行这种微调的理想场所。

# 另请参阅

以下是一些参考资料：

+   MicroPython 交互式解释器模式（REPL）的文档位于[`docs.micropython.org/en/latest/reference/repl.html`](http://docs.micropython.org/en/latest/reference/repl.html)。

+   可以在[`docs.micropython.org/en/latest/genrst/builtin_types.html`](http://docs.micropython.org/en/latest/genrst/builtin_types.html)找到 MicroPython 内置类型的文档。

# 使用自动重新加载功能

以下配方显示了如何使用自动重载，以便编辑和运行代码的循环可以变得更快更有趣。

# 准备工作

在此之前使用的任何方法都可以用于获取 REPL。

# 如何做到...

让我们看看如何做到这一点：

1.  打开`main.py`文件，并保存文件中的`print('hi there')`语句。

1.  通过您喜欢的应用程序打开 REPL。打开 REPL 后，按下*Ctrl* + *D*。应出现以下输出：

```py
Adafruit CircuitPython 3.1.2 on 2019-01-07; Adafruit CircuitPlayground Express with samd21g18
>>> 
>>> 
soft reboot

Auto-reload is on. Simply save files over USB to run them or enter REPL to disable.
main.py output:
hi there

Press any key to enter the REPL. Use CTRL-D to reload.
```

1.  编辑`main.py`文件，并将内容更改为`print('hi there again')`。应自动显示以下输出：

```py
soft reboot

Auto-reload is on. Simply save files over USB to run them or enter REPL to disable.
main.py output:
hi there again

Press any key to enter the REPL. Use CTRL-D to reload.
```

# 它是如何工作的...

通过按下*Ctrl* + *D*，板子将进入自动重载模式。在这种模式下，您可以在您选择的文本编辑器中打开`main.py`文件，并且在保存文件的瞬间，板子会检测到发生了变化，并执行软重启。

软重启可以在屏幕输出中看到，然后执行新版本的代码，并立即显示其输出。

# 还有更多...

在脚本中开始使用一些基本的代码行来使脚本的初始部分运行是非常常见的。一旦您的第一个基本版本运行起来，您将经历许多迭代来微调和增强它，使其表现出您想要的方式。除了这些调整之外，不可避免的错误将出现在您的代码中，因为您在调试它时会出现。在这些密集的编码会话中，自动重载功能将成为您的好朋友，因为它将让您更快地获得结果，并以直观的方式。

# 另请参阅

以下是一些参考资料：

+   MicroPython 的软重置功能在[`docs.micropython.org/en/v1.8.6/wipy/wipy/tutorial/reset.html`](http://docs.micropython.org/en/v1.8.6/wipy/wipy/tutorial/reset.html)中有描述。

+   有关离开 REPL 的文档可以在[`learn.adafruit.com/welcome-to-circuitpython?view=all#returning-to-the-serial-console-10-24`](https://learn.adafruit.com/welcome-to-circuitpython?view=all#returning-to-the-serial-console-10-24)中找到。

# 更新 CircuitPython 库

除了更新固件外，还有一组名为 CircuitPython Library 的 Python 库，其中包含了最新支持的功能。

# 准备工作

在此之前使用的任何方法都可以用于获取 REPL。

# 如何做到...

让我们看看如何做到这一点：

1.  通过您喜欢的应用程序打开 REPL。

1.  下载最新的 CircuitPython Library Bundle 发布版([`github.com/adafruit/Adafruit_CircuitPython_Bundle/releases/latest`](https://github.com/adafruit/Adafruit_CircuitPython_Bundle/releases/latest))。捆绑文件的名称是`adafruit-circuitpython-bundle-3.x-mpy-20190212.zip`。由于我们的固件使用的是 3.x 版本，因此必须选择也适用于 3.x 版本的捆绑包。始终使用`mpy`版本，因为这样可以优化使用更少的磁盘空间，并减少内存使用。

在这个配方中，我们使用的是 CircuitPython Library Bundle 的最新自动发布版本，即 3.x 系列的 20190212 版本。

1.  将`.zip`文件提取到计算机上的一个位置。

1.  如果`CIRCUITPY`驱动器中不包含`lib`文件夹，则现在创建一个。

1.  将提取的`lib`文件夹的内容复制到设备上的`lib`文件夹中。

1.  通过按下*Ctrl* + *D*在 REPL 中执行软重启。

1.  在 REPL 中运行`import simpleio`。

1.  如果成功执行，则库已成功加载，因为`simpleio`模块不是固件的一部分，而是从库文件夹导入的。

# 它是如何工作的...

创建的`lib`路径是 CircuitPython 在导入 Python 包时查找的标准路径之一。通过将 Python 包添加到此文件夹，可以使其可以被设备上运行的任何脚本导入。

`mpy`文件是从原始源`py`文件构建的，并且全部打包在一起，以便更容易安装。

# 还有更多...

CircuitPython 库正在不断开发，因此重要的是要知道如何在板上更新库，以便获得最新的功能。当您尝试从互联网上找到的项目代码时，您可能偶尔会发现一些示例在您的板上无法运行，因为您正在运行过时的 CircuitPython 库版本。保持板子更新到最新版本，可以帮助防止这种情况发生。

# 另请参阅

以下是一些参考资料：

+   有关如何创建`mpy`文件的更多详细信息，请查看[`learn.adafruit.com/building-circuitpython/build-circuitpython`](https://learn.adafruit.com/building-circuitpython/build-circuitpython)中的`mpy-cross`命令。

+   有关安装 CircuitPython 库包的信息，请访问[`learn.adafruit.com/adafruit-circuit-playground-express?view=all#installing-the-circuitpython-library-bundle-12-5`](https://learn.adafruit.com/adafruit-circuit-playground-express?view=all#installing-the-circuitpython-library-bundle-12-5)。


# 第二章：控制 LED

在本章中，我们将介绍控制 Adafruit Circuit Playground Express 附带的一系列 NeoPixel LED 的几种方法。在这些示例中，我们将研究设置像素颜色的各种方法，每种方法都有其自己的权衡。

我们还将演示如何计时操作，以便创建淡入淡出和其他光动画效果。NeoPixels 是允许您的项目与丰富的视觉交互的强大方式。这些示例将为您提供必要的构建模块，以将这些视觉概念纳入您自己的项目中。

在本章中，我们将涵盖以下示例：

+   打开引脚 13 的 LED

+   设置 NeoPixel 的亮度

+   控制单个 NeoPixel 的颜色

+   使用 RGB 和十六进制代码显示 LED 颜色

+   使用颜色名称设置 LED 颜色

+   将所有 NeoPixels 设置为相同的颜色

+   将一系列 NeoPixels 设置为一种颜色

+   生成随机的 NeoPixel LED 颜色

+   使用随机颜色创建 LED 动画

+   使用彩虹颜色创建 LED 动画

# Adafruit Circuit Playground Express 布局

以下图表显示了本章中将使用的 LED 的位置：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mcpy-cb/img/7d6ba682-80e1-44fc-baee-79158532496b.png)

由 adafruit.com 提供

引脚 13 的 LED 是第一个示例中将使用的简单的单个红色 LED。板上共有 10 个 NeoPixels。每个 NeoPixel 由红色、绿色和蓝色 LED 组成。通过控制这些 LED 的各自亮度，您将能够将任何 NeoPixel 设置为特定颜色。

# 打开引脚 13 的 LED

在本示例中，我们将学习如何打开和关闭引脚 13 的 LED。这是板上最简单的 LED，因为它只有一种颜色，并且在 Python 中与之交互也非常简单。出于这些原因，引脚 13 的 LED 是一个很好的起点。

# 准备工作

您需要访问 Circuit Playground Express 上的 REPL 才能运行本示例中提供的代码。

# 如何做...

要做到这一点，请执行以下步骤：

1.  在 REPL 中运行以下代码行：

```py
>>> from adafruit_circuitplayground.express import cpx
>>> cpx.red_led = True
```

1.  此阶段应该看到引脚 13 的 LED 变红。

1.  使用以下代码检查 LED 的当前状态：

```py
>>> cpx.red_led
True
```

1.  要关闭 LED，请在 REPL 中运行以下代码：

```py
>>> cpx.red_led = False
```

1.  现在引脚 13 的 LED 灯将被关闭。

# 工作原理...

代码的第一行导入了 Circuit Playground Express 库。该库包含一个名为`express`的对象类，这是我们将用于与此板上的硬件进行交互的主要类。当导入库时，它会创建一个名为`cpx`的此类的实例。

`cpx`对象公开了一个名为`red_led`的属性。此属性可用于检索 LED 的当前值。如果 LED 打开，则返回`True`值；否则，如果 LED 关闭，则返回`False`值。设置此属性的值将打开或关闭 LED，具体取决于设置`True`或`False`值。

# 还有更多...

这是板上最简单的 LED 灯之一，因为它是通过将值设置为`True`或`False`来控制的。您无法控制此 LED 的颜色或亮度。本书中的其他示例将控制板上的 NeoPixel 灯，这些灯具有更丰富的功能范围，因此需要更复杂的 API 来控制它们。

# 另请参阅

您可以使用以下参考资料了解更多信息：

+   有关`red_led`属性的文档可以在[`circuitpython.readthedocs.io/projects/circuitplayground/en/latest/api.html#adafruit_circuitplayground.express.Express.red_led`](https://circuitpython.readthedocs.io/projects/circuitplayground/en/latest/api.html#adafruit_circuitplayground.express.Express.red_led)找到。

+   有关导入 `cpx` 变量的详细信息，请访问 [`circuitpython.readthedocs.io/projects/circuitplayground/en/latest/#usage-example`](https://circuitpython.readthedocs.io/projects/circuitplayground/en/latest/#usage-example)。

# 设置 NeoPixel 的亮度

控制像素的亮度将是本教程的主题。根据项目的需要设置像素的亮度非常重要。请注意，您必须将亮度更改为足够明亮的级别，以便像素清晰可见，但不要太亮以至于引起不适。

# 准备工作

您需要访问 Circuit Playground Express 上的 REPL，以运行本教程中提供的代码。

# 如何操作...

为了做到这一点，请执行以下步骤：

1.  在 REPL 中运行以下代码行：

```py
>>> from adafruit_circuitplayground.express import cpx
>>> cpx.pixels.brightness = 1.0
>>> cpx.pixels[0] = (255, 0, 0)
```

1.  此时，第一个像素应该是红色，并且亮度全开。运行以下代码行以将亮度级别设置为 50%：

```py
>>> cpx.pixels.brightness = 0.5
```

1.  亮度级别可以进一步降至 10%，仍然可以舒适地看到。您可以通过运行以下代码行来实现：

```py
>>> cpx.pixels.brightness = 0.10
```

# 它是如何工作的...

`brightness` 属性接受从 `0` 到 `1.0` 的值，从最暗到最亮。请注意，此板上的 NeoPixels 可能非常明亮，如果您直接看最高亮度级别的话，可能会对您的眼睛造成压力。

我建议您将亮度级别设置为 10%，因为这样可以更舒适地查看像素。然后，根据项目的需要，您可以调整亮度到最合适的级别。

有时像素将位于薄塑料覆盖物下，您将希望增加亮度级别。另一方面，有时您将直接看着它们，您将希望降低亮度级别。

# 还有更多...

重要的是要注意，亮度级别的实现方式意味着您只能一次更改所有的 NeoPixels。也就是说，使用亮度属性，您不能使一些像素变亮，一些像素变暗。因此，您设置的亮度值将应用于板上的所有像素。

当像素保持在最大亮度级别的 100% 时，它们具有非常明亮的能力。这种设置更适合的一个例子是当您将设备嵌入塑料容器中。以下照片是从一个 NeoPixel 项目中拍摄的，其中 Circuit Playground Express 板被放置在雪球的底座内部：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mcpy-cb/img/cddce960-db40-45aa-a407-294794c2a227.png)

在这个项目中，底座是由白色塑料制成的。因此，即使板不直接可见，像素也足够明亮，可以透过白色塑料照亮整个雪球。

本项目中展示的 DIY 雪球套件可以在 [`www.adafruit.com/product/3722`](https://www.adafruit.com/product/3722) 找到。

# 另请参阅

您可以使用以下参考资料了解更多信息：

+   亮度属性的文档位于 [`circuitpython.readthedocs.io/projects/NeoPixel/en/latest/api.html#NeoPixel.NeoPixel.brightness`](https://circuitpython.readthedocs.io/projects/neopixel/en/latest/api.html#neopixel.NeoPixel.brightness)。

+   有关更改亮度级别的示例，请访问 [`learn.adafruit.com/circuitpython-made-easy-on-circuit-playground-express/NeoPixels`](https://learn.adafruit.com/circuitpython-made-easy-on-circuit-playground-express/neopixels)。

# 控制单个 NeoPixel 的颜色

这个教程将向您展示如何将特定的 NeoPixel 设置为不同的颜色。然后它将向您展示如何更改板上附带的 10 个 NeoPixels 中的任何一个的颜色。这将是一个有用的教程，因此您可以开始释放这些板载像素的强大和灵活性。

# 准备工作

你需要在 Circuit Playground Express 上访问 REPL 来运行本教程中提供的代码。

# 如何做...

要做到这一点，执行以下步骤：

1.  在 REPL 中运行以下代码行：

```py
>>> from adafruit_circuitplayground.express import cpx
>>> cpx.pixels[0] = (255, 0, 0)
```

1.  现在，你应该看到第一个 NeoPixel 变成红色。

1.  当你运行以下代码时，你应该看到第一个 NeoPixel 变成绿色：

```py
>>> cpx.pixels[0] = (0, 255, 0)
```

1.  当你运行以下代码时，你应该看到第一个 NeoPixel 变成蓝色：

```py
>>> cpx.pixels[0] = (0, 0, 255)
```

1.  以下代码应该检索第一个 NeoPixel 的当前颜色值：

```py
>>> cpx.pixels[0]
(0, 0, 255)
```

1.  运行以下代码关闭第一个 NeoPixel：

```py
>>> cpx.pixels[0] = (0, 0, 0)
```

1.  运行以下代码，第二个 NeoPixel 应该变成红色：

```py
>>> cpx.pixels[1] = (255, 0, 0)
```

# 工作原理...

第一行代码导入了将用于控制 NeoPixels 的`cpx`对象。这个对象有一个名为`pixels`的属性，可以像列表一样访问。使用的索引表示要操作的 10 个 NeoPixels 中的哪一个。

在第一个代码片段中，我们将值设置为表示所需颜色的元组，它由红色、绿色和蓝色值组成。每个值应该表示为 0 到 255 之间的整数。通过将值设置为(255, 0, 0)，红色 LED 将达到最高值，绿色和蓝色 LED 将关闭。这将创建红色。

按照相同的方法，然后通过为每种颜色提供正确的值来将 NeoPixel 设置为绿色和蓝色。还可以通过简单地访问任何特定示例的值来轻松地检索特定像素的当前 RGB 值。

通过将所有 RGB 分量设置为 0，可以关闭像素，如本教程中的前面代码所示。最后一个前面的代码片段只是通过引用正确的索引值来将第二个像素设置为红色的示例。

# 还有更多...

在旧版本的库中，你可以将颜色提供为三个整数的列表，而不是三个整数的元组。最好避免这样做，而是坚持使用元组而不是列表。这是因为你的代码将在新版本和旧版本的库中都能工作。

每个 NeoPixel 由红色、绿色和蓝色 LED 组成。当你在这个教程中设置每种颜色的强度时，它直接改变了这些单独 LED 的亮度级别。可以使用消费者显微镜来查看组成每个 NeoPixel 的三个单独的 LED 灯。以下照片是从这些消费者级显微镜中拍摄的，放大倍数为 200 倍。正如你所看到的，单独的红色、绿色和蓝色 LED 清晰可见：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mcpy-cb/img/b25ccf3e-f210-4dab-b042-0457e92f2e5d.png)

# 另请参阅

你可以使用以下参考资料了解更多信息：

+   可以在[`circuitpython.readthedocs.io/projects/circuitplayground/en/latest/api.html#adafruit_circuitplayground.express.Express.pixels`](https://circuitpython.readthedocs.io/projects/circuitplayground/en/latest/api.html#adafruit_circuitplayground.express.Express.pixels)找到有关像素属性的文档。

+   有关 NeoPixel 的详细信息可以在[`learn.adafruit.com/adafruit-NeoPixel-uberguide/the-magic-of-NeoPixels`](https://learn.adafruit.com/adafruit-neopixel-uberguide/the-magic-of-neopixels)找到。

# 使用 RGB 和十六进制代码显示 LED 颜色

有一个常见的约定，可以使用十六进制代码来表示任何颜色，它通过表示颜色的红色、绿色和蓝色组件来工作。这个教程演示了如何使用这个十六进制代码约定来设置 NeoPixel 的颜色。当你想要从网络或桌面上的其他应用程序应用特定的颜色设置时，使用这样一个流行的约定将是有用的。

# 准备工作

你需要在 Circuit Playground Express 上访问 REPL 来运行本教程中提供的代码。

# 如何做...

要做到这一点，执行以下步骤：

1.  在 REPL 中运行以下代码行：

```py
>>> from adafruit_circuitplayground.express import cpx
>>> cpx.pixels[0] = 0xFF0000
```

1.  你应该看到第一个 NeoPixel 变成红色。运行以下代码来检索第一个 NeoPixel 的颜色值：

```py
>>> cpx.pixels[0]
(0, 0, 255)
```

1.  运行以下代码将接下来的两个像素设置为绿色和蓝色：

```py
>>> cpx.pixels[1] = 0x00FF00
>>> cpx.pixels[2] = 0x0000FF
```

1.  使用以下代码将第四个像素设置为黄色：

```py
>>> cpx.pixels[3] = 0xFFFF00
```

1.  使用以下代码显示颜色蓝的整数值，然后使用这个整数值将下一个像素设置为蓝色：

```py
>>> 0x0000FF
255
>>> cpx.pixels[4] = 255
```

# 工作原理...

第一个代码片段使用颜色的十六进制表示法将板上的第一个像素设置为红色。像素的接口接受颜色值，可以作为三个整数的元组或十六进制值给出，在 Python 中，这对应于一个整数值。

根据给定的值类型，库会提取颜色的红色、绿色和蓝色组件的正确值，并将像素设置为该颜色。第二个代码片段表明，当读取值时，它们将始终作为三个颜色组件的元组检索。

最后一个代码片段表明，正在使用的十六进制表示法是 Python 语言的一个标准特性，用于指定整数值的十六进制值。等效的整数值也可以用于设置颜色。

# 还有更多...

十六进制代码表示系统用于描述颜色的红色、绿色和蓝色组件，非常受欢迎。由于其受欢迎程度，很容易找到各种在线工具和桌面应用程序，提供颜色选择器和颜色轮，这些工具将颜色表示为十六进制代码。您可以在这些程序中简单地选择所需的颜色，然后将十六进制值复制并粘贴到您的脚本中。以下截图来自流行的开源图像编辑器 GIMP：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mcpy-cb/img/6918ea9c-b73f-4c25-9bd5-8456b961f999.png)

在上述截图中，您可以看到应用程序中提供的颜色轮。这个丰富的界面可以轻松地通过改变色调或饱和度找到您要找的颜色。一旦选择了您想要的颜色，您可以复制十六进制代码值，这在该应用程序中标记为**HTML 表示法**。然后，您可以使用相同的技术在您的脚本中使用这个值。

GIMP 可在 Linux、macOS 和 Windows 上使用，并可从[`www.gimp.org`](https://www.gimp.org)免费下载。

# 另请参阅

您可以使用以下参考资料了解更多信息：

+   有关 Python 语言中整数文字的文档可以在[`docs.python.org/3/reference/lexical_analysis.html#integer-literals`](https://docs.python.org/3/reference/lexical_analysis.html#integer-literals)找到。

+   可以在[`www.sessions.edu/color-calculator/`](https://www.sessions.edu/color-calculator/)找到交互式颜色轮。

# 使用颜色名称设置 LED 颜色

使用易读的颜色名称可以使您更容易跟踪应用程序中使用的颜色。本文演示了一种允许您使用常规颜色名称设置像素颜色的技术。通过一组标准的颜色名称引用颜色的功能在流行的语言中可用，包括 CSS。本文向您展示了如何将此功能引入到您的 MicroPython 脚本中。

# 准备工作

您需要访问 Circuit Playground Express 上的 REPL 才能运行本文中提供的代码。

# 如何操作...

要执行此操作，请执行以下步骤：

1.  在 REPL 中运行以下代码行：

```py
>>> from adafruit_circuitplayground.express import cpx
>>> RGB = dict(black=0x000000, blue=0x0000FF, green=0x00FF00, 
... cyan=0x00FFFF,
... red=0xFF0000, magenta=0xFF00FF, yellow=0xFFFF00, 
... white=0xFFFFFF)
>>> cpx.pixels[0] = RGB['red']
```

1.  您应该看到第一个 NeoPixel 变成红色。

1.  使用以下代码将前八个像素按字母顺序设置为命名颜色之一：

```py
>>> for i, name in enumerate(sorted(RGB)):
...     cpx.pixels[i] = RGB[name]
```

# 工作原理...

创建了一个名为 RGB 的全局变量；这是一个用于将颜色名称与它们的 RGB 颜色代码匹配的字典。这允许通过它们的名称检索颜色值，而不是每次需要使用时直接指定它们的十六进制代码。第一个片段使用 RGB 代码将第一个像素设置为红色。

第二个代码块按字母顺序循环遍历每个颜色名称，并将一个像素设置为该颜色。由于颜色查找字典中定义了八种颜色，前八个像素将设置它们的颜色，每个像素将从颜色列表中选择自己的颜色。

# 还有更多...

使用人类可读的颜色名称可以提高代码的可读性。然而，本教程中描述的技术需要您手动指定每个颜色名称及其相关的十六进制代码。如果只使用少量颜色，这是可以接受的，但如果要支持大量颜色，那么这将变得非常繁琐。另一个需要考虑的因素是，许多这些板子的内存容量有限，因此创建非常大的字典可能会导致板子内存不足。像本例中展示的小颜色查找表不应该引起这些问题。

当你在寻找颜色名称及其相关的十六进制代码时，有许多标准来源可供使用。一个流行的颜色名称列表是**万维网联盟**（**W3C**），它在 CSS 中使用。另一个标准颜色列表是开源文本编辑器 Vim 提供的。这个颜色名称列表存储在一个名为`rgb.txt`的文件中，它随每个 Vim 安装包提供。

使用这个颜色列表的好处在于它以一种机器可读的格式呈现，每一行代表一个颜色，颜色组件和名称以空格分隔。这使得解析和使用这些颜色名称变得相对简单。下面的截图显示了一个有用的 Vim 脚本的输出，该脚本解析了这个文件，并为每个颜色名称和其应用的颜色提供了便捷的选择：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mcpy-cb/img/6c942081-50b5-4340-a7e3-35462c0e0f18.png)

这个 Vim 颜色脚本可以在[`vim.fandom.com/wiki/View_all_colors_available_to_gvim`](https://vim.fandom.com/wiki/View_all_colors_available_to_gvim)找到。

# 另请参阅

您可以使用以下参考资料了解更多信息：

+   W3C 颜色名称可以在[`www.w3.org/TR/css-color-3/`](https://www.w3.org/TR/css-color-3/)找到。

+   关于加色法的解释可以在[`study.com/academy/lesson/additive-color-theory-definition.html`](https://study.com/academy/lesson/additive-color-theory-definition.html)找到。

# 将所有 NeoPixels 设置为相同颜色

本教程解释了如何通过一次调用将所有像素设置为一个颜色，而不是循环遍历所有 NeoPixels 并单独设置它们的颜色。您可以使用这种技术来创建一个很好的效果，将所有 10 个 NeoPixels 设置为相同的颜色。它们排列成一个完美的圆圈，所以当它们都设置为相同的颜色时，就会形成一个颜色的环。这也是一种一次性关闭所有 NeoPixels 的简单方法。

# 准备工作

你需要访问 Circuit Playground Express 上的 REPL 来运行本教程中提供的代码。

# 如何做...

要做到这一点，请执行以下步骤：

1.  在 REPL 中运行以下代码行：

```py
>>> from adafruit_circuitplayground.express import cpx
>>> cpx.pixels.fill(0x0000FF)
```

1.  你应该看到所有 10 个 NeoPixels 变成蓝色。

1.  使用以下代码关闭所有 10 个 NeoPixels：

```py
>>> cpx.pixels.fill(0x000000)
```

# 工作原理...

在第一个代码片段中，调用了`fill`方法，并提供了颜色值作为第一个参数。`fill`方法将循环遍历所有像素，并将它们设置为所需的颜色，这种情况下是蓝色。该方法接受十六进制颜色表示法和三个整数值的元组。

# 还有更多...

将所有像素设置为相同颜色的操作相对流行，该方法已经为您提供了便利。然而，重要的是要注意，这种方法的实现并不只是简单地循环并为每个像素设置颜色。相反，它使用了一个功能，可以在显示之前设置所有的颜色值。

这个功能的优点是您可以先设置所有颜色，然后一次性调用显示它们。这是设置像素的更好方法，而不是用简单的`for`循环，因此它提供了另一个使用`fill`方法的充分理由。

# 另请参阅

您可以使用以下参考资料找到更多信息：

+   可以在[`circuitpython.readthedocs.io/projects/neopixel/en/latest/api.html#neopixel.NeoPixel.fill`](https://circuitpython.readthedocs.io/projects/neopixel/en/latest/api.html#neopixel.NeoPixel.fill)找到关于`fill`方法的文档。

+   可以在[`www.adafruit.com/category/168`](https://www.adafruit.com/category/168)找到与 NeoPixel 库兼容的产品列表。

# 将一系列 NeoPixel 设置为一个颜色

本教程将探讨如何使用切片功能将特定范围的像素设置为特定颜色。当您想要将像素环转换为显示值从 1 到 10 的值的仪表时，这可能非常有用。基本上，它提供了一种更清晰和简单的方式来将一系列像素设置为特定颜色。

# 准备工作

您将需要访问 Circuit Playground Express 上的 REPL 来运行本教程中提供的代码。

# 如何做...

要做到这一点，请执行以下步骤：

1.  在 REPL 中运行以下代码行：

```py
>>> from adafruit_circuitplayground.express import cpx
>>> cpx.pixels[0:2] = [0xFF0000, 0xFF0000]
```

1.  您应该看到前两个 NeoPixels 点亮为红色。

1.  使用以下代码将接下来的三个像素变为绿色，最后五个像素变为蓝色：

```py
>>> cpx.pixels[2:5] = [0x00FF00] * 3 
>>> cpx.pixels[5:10] = [0x0000FF] * 5
```

# 工作原理...

`pixels`属性在使用`slice`方法设置值时会理解。但是，它期望如果您为两个像素设置颜色，那么您应该提供一个包含两个颜色值的列表，就像在第一个示例中所做的那样。

在 Python 中，我们可以通过取颜色值的列表并将其乘以所需数量的值来减少这种重复。这是用于将三个像素设置为绿色的方法。

# 还有更多...

在 Python 中使用的切片表示法简洁而强大。这是一种非常聪明的方式，可以在一行代码中改变一系列像素的颜色。这非常符合 Python 保持代码简短和简洁而不影响可读性的方法。

# 另请参阅

您可以使用以下参考资料找到更多信息：

+   使用`*`运算符在 Python 的列表中重复值的更多细节可以在[`interactivepython.org/runestone/static/CS152f17/Lists/ConcatenationandRepetition.html`](http://interactivepython.org/runestone/static/CS152f17/Lists/ConcatenationandRepetition.html)找到。

+   可以在[`docs.python.org/3/tutorial/introduction.html#lists`](https://docs.python.org/3/tutorial/introduction.html#lists)找到有关 Python 字符串切片的文档。

# 生成随机 NeoPixel LED 颜色

这个教程演示了一种可以无限生成随机颜色的技术。然后我们将在特定的 NeoPixel 上使用这些随机颜色。在颜色部分添加随机性可以使项目更有趣，因为您无法预测脚本执行时将出现的确切颜色序列。

# 准备工作

您将需要访问 Circuit Playground Express 上的 REPL 来运行本教程中提供的代码。

# 如何做...

要做到这一点，请执行以下步骤：

1.  在 REPL 中运行以下代码行：

```py
>>> from adafruit_circuitplayground.express import cpx
>>> from random import randint
>>> randint(0, 255)
186
>>> randint(0, 255)
84
```

1.  每次运行前面的代码行时，您应该得到一个介于 0 和 255 之间的随机整数。

1.  使用以下代码定义一个函数，然后调用该函数确认它是否正常工作：

```py
>>> def get_random_color():
...     return (randint(0, 255), randint(0, 255), randint(0, 255))
...     
...     
... 
>>> get_random_color()
(208, 161, 71)
>>> get_random_color()
(96, 126, 158)
```

1.  重复调用以下代码；每次调用时，第一个 NeoPixel 应更改为随机颜色：

```py
>>> cpx.pixels[0] = get_random_color()
```

1.  使用以下代码在每次调用时将所有像素设置为相同的随机颜色：

```py
>>> cpx.pixels.fill(get_random_color())
```

# 工作原理...

在这个配方中，我们使用了`random`模块，它是 Python 标准库和 CircuitPython 的一部分。调用`randint`并提供从 0 到 255 的范围将为每个颜色分量给我们一个随机整数。

然后我们定义`get_random_color`函数来随机选择三个颜色分量，因此产生一个随机颜色。现在我们有了这个函数，我们可以调用它来设置单个像素或所有像素的颜色，就像在这个配方的最后两个代码片段中演示的那样。

# 还有更多...

在 MicroPython 项目中使用`random`模块打开了一系列有趣的可能性，可以创建独特和不同的项目。这个配方涵盖了一个例子，结合随机库和代码来指定颜色，以便可以选择随机颜色。使用这种方法可能会随机选择超过 1600 万种不同的颜色。

# 另请参阅

您可以使用以下参考资料了解更多信息：

+   CircuitPython 随机库的文档可以在[`circuitpython.readthedocs.io/en/3.x/shared-bindings/random/__init__.html`](https://circuitpython.readthedocs.io/en/3.x/shared-bindings/random/__init__.html)找到。

+   使用`random`库和 Circuit Playground Express 创建电子骰子的项目可以在[`learn.adafruit.com/circuit-playground-d6-dice/`](https://learn.adafruit.com/circuit-playground-d6-dice/)找到。

# 使用随机颜色创建 LED 动画

这个配方将结合本章中以前配方的一些方面，使用随机选择的颜色创建动画。这个配方基于其他配方的技术来创建你的第一个动画。在板上有 10 个像素，有很多选项可以在板上创建引人入胜的视觉动画——这只是其中之一。

# 做好准备

您需要访问 Circuit Playground Express 上的 REPL 来运行本配方中提供的代码。

# 如何做...

要做到这一点，执行以下步骤：

1.  在 REPL 中运行以下代码行：

```py
>>> from adafruit_circuitplayground.express import cpx
>>> from random import randint
>>> import time
>>> def get_random_color():
...     return (randint(0, 255), randint(0, 255), randint(0, 255))
...          
... 
>>> get_random_color()
(10, 41, 10)
```

1.  运行以下代码块，板上的像素环周围应该出现一个持续 10 秒的颜色动画：

```py
>>> for i in range(10):
...     cpx.pixels[i] = get_random_color()
...     time.sleep(1)
...     
...     
... 
>>> 
```

1.  接下来，运行动画 30 秒，并循环三次所有像素，每次光变化之间延迟 1 秒：

```py
>>> cpx.pixels.fill(0x000000)
>>> for cycle in range(3):
...     for i in range(10):
...         cpx.pixels[i] = get_random_color()
...         time.sleep(1)
...         
...         
... 
>>> 
```

1.  对于最后一个动画，运行动画 5 秒，并在每秒更改所有像素颜色一次：

```py
>>> cpx.pixels.fill(0x000000)
>>> for i in range(5):
...     cpx.pixels.fill(get_random_color())
...     time.sleep(1)
...     
...     
... 
>>> 
```

# 它是如何工作的...

这个配方中介绍了三种不同的动画。在灯光动画方面，天空是极限。有很多不同的方法来控制颜色变化和时间，每种不同的方法都会产生略有不同的视觉效果。然而，所有动画的一个关键方面是时间；我们可以使用`sleep`调用来控制动画的节奏，这是`time`模块的一部分。通过这种方式，我们可以减慢或加快我们创建的动画的速度。

这个配方中的第一个动画是一个简单的`for`循环，它将每个像素的颜色设置为随机颜色，并在这些颜色变化之间暂停一秒。第二个动画在第一个动画的基础上进行了改进，通过一个外部循环循环 3 次，因此改变了像素 30 次。

最后，最后一个动画采用了不同的方法，将所有像素设置为相同的颜色，然后在每个循环期间一起改变它们。

# 还有更多...

这个配方中的动画可以进行调整，以创建各种不同的动画。例如，您可以改变动画的速度或动画循环像素的次数。前面的代码可以用在一个接收这两个参数作为参数的函数中。然后可以在一个更大的程序中使用它，该程序将调用该函数以使用不同的设置制作动画。

# 另请参阅

您可以使用以下参考资料了解更多信息：

+   CircuitPython 时间库的文档可以在[`circuitpython.readthedocs.io/en/3.x/shared-bindings/time/__init__.html`](https://circuitpython.readthedocs.io/en/3.x/shared-bindings/time/__init__.html)找到。

+   使用 Circuit Playground Express 创建动画自行车灯的项目可以在[`learn.adafruit.com/circuit-playground-bike-light`](https://learn.adafruit.com/circuit-playground-bike-light)找到。

# 使用彩虹颜色创建 LED 动画

这个方案将产生一个遵循彩虹中相同颜色顺序的颜色环。这些颜色将在一定的延迟后依次出现，产生彩虹动画效果。使用自然组合在一起的颜色序列，比如彩虹中找到的颜色，既令人愉悦又引人入胜。这个动画的优势在于学会如何控制正在动画中的确切颜色序列，无论是彩虹序列还是您选择的其他序列。

# 准备工作

您需要访问 Circuit Playground Express 上的 REPL 来运行本方案中提供的代码。

# 如何做...

要做到这一点，执行以下步骤：

1.  在 REPL 中运行以下代码行：

```py
>>> from adafruit_circuitplayground.express import cpx
>>> import time
```

1.  以下代码块定义了一个颜色值列表，其值和顺序与彩虹中的相同：

```py
>>> RAINBOW = [
... 0xFF0000,   # red
... 0xFFA500,   # orange
... 0xFFFF00,   # yellow
... 0x00FF00,   # green
... 0x0000FF,   # blue
... 0x4b0082,   # indigo
... 0xEE82EE,   # violet
... ]
>>> 
```

1.  然后，在开始动画之前，设置一个更舒适的亮度级别并关闭所有像素：

```py
>>> cpx.pixels.brightness = 0.10
>>> cpx.pixels.fill(0x000000)
>>> 
```

1.  使用以下代码块，循环遍历彩虹中的七种颜色，并将一个像素设置为每种颜色，每次灯光变化之间有短暂的`0.2`秒延迟：

```py
>>> for i, color in enumerate(RAINBOW):
...     cpx.pixels[i] = color
...     time.sleep(0.2)
...     
...     
... 
>>> 
```

1.  使用以下动画返回到每个像素，并以每次灯光变化的相同速度`0.2`秒关闭它：

```py
>>> for i in range(len(RAINBOW)):
...     cpx.pixels[i] = 0x000000
...     time.sleep(0.2)
...     
...     
... 
>>> 
```

1.  以下代码结合了描述的所有步骤，并将这些步骤包装成一个无限的`while`循环。将此代码部分添加到`main.py`文件中，然后创建一个连续的彩虹动画：

```py
from adafruit_circuitplayground.express import cpx import time RAINBOW = [ 0xFF0000, # red 
 0xFFA500, # orange 
 0xFFFF00, # yellow 
 0x00FF00, # green 
 0x0000FF, # blue 
 0x4b0082, # indigo 
 0xEE82EE, # violet
]

cpx.pixels.brightness = 0.10
cpx.pixels.fill(0x000000)
while True:
    for i, color in enumerate(RAINBOW):
        cpx.pixels[i] = color
        time.sleep(0.2)
    for i in range(len(RAINBOW)):
        cpx.pixels[i] = 0x000000
        time.sleep(0.2)
```

# 工作原理...

自然界中的彩虹由七种颜色组成：红色、橙色、黄色、绿色、蓝色、靛蓝色和紫罗兰色。我们将这些颜色的值以及它们在自然界中出现的正确顺序存储在一个列表中。设置亮度级别，然后调用`fill`方法关闭板上的所有像素。

启动一个包含两个循环的无限循环。第一个内部循环将循环遍历彩虹中的每种颜色，并将一个像素设置为每种颜色。然后，第二个内部循环将返回到被着色的七个像素，并关闭每一个。

# 还有更多...

以下照片显示了此处方案中的彩虹动画在 Circuit Playground Express 上运行：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mcpy-cb/img/a153e9c0-d041-4160-b6ae-a24207d78566.png)

有许多方法可以从这个彩虹动画中制作更多的衍生动画。例如，您可以添加更多不属于自然彩虹的颜色。我们定义了 7 种颜色，但板上有 10 个像素，所以您可以定义另外 3 种不同的颜色。您还可以使起始像素在每个循环中随机选择，这样动画在每个循环中都从不同的像素开始。

# 另请参阅

您可以使用以下参考资料了解更多信息：

+   彩虹的七种颜色的顺序和名称可以在[`sciencetrends.com/7-colors-rainbow-order/`](https://sciencetrends.com/7-colors-rainbow-order/)找到。

+   可以在[`learn.adafruit.com/adafruit-circuit-playground-express/circuitpython-neopixel`](https://learn.adafruit.com/adafruit-circuit-playground-express/circuitpython-neopixel)找到彩虹动画的另一种实现。


# 第三章：创建声音和音乐

本章将介绍使用 Adafruit Circuit Playground Express 上的硬件制作声音和播放音乐的方法。本章首先介绍了让板子以特定频率发出蜂鸣声的基础知识，然后将进一步介绍更高级的主题，如使用 WAV 文件格式和板载扬声器播放音乐文件。本章的技术可以直接用于您可能制作的各种 MicroPython 项目中。本章中产生音频输出的选项范围从产生简单的蜂鸣声到在嵌入式项目中播放歌曲。

在本章中，我们将介绍以下教程：

+   发出蜂鸣声

+   控制音调、频率和持续时间

+   播放音符

+   播放旋律

+   发出警报

+   播放 WAV 文件

+   将 MP3 文件转换为 WAV 文件

+   开始和停止音调

# Adafruit Circuit Playground Express 布局

以下照片显示了板子上内置扬声器的位置。本章涵盖的所有蜂鸣声和声音都将使用此扬声器进行播放：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mcpy-cb/img/7b610559-8dc7-4b1f-ba85-79f8b5c9f34c.png)

由 adafruit.com 提供

# 发出蜂鸣声

在本教程中，我们将学习如何使扬声器以特定的声音频率发出蜂鸣声，并持续一定的时间。音频输出是引起某人注意的好方法；您可以在到处都能找到它，从响铃电话到门铃。本教程将为您提供向嵌入式项目添加蜂鸣声所需的技能。

# 准备就绪

您需要访问 Circuit Playground Express 上的 REPL 来运行本教程中提供的代码。

# 如何做...

让我们执行以下步骤：

1.  在 REPL 中运行以下代码行。您应该听到以 900 赫兹的频率播放 0.2 秒的蜂鸣声：

```py
>>> from adafruit_circuitplayground.express import cpx
>>> cpx.play_tone(900, 0.2)
```

1.  执行以下代码，以便以较低频率的蜂鸣声播放更长时间：

```py
>>> cpx.play_tone(500, 0.4)
```

# 工作原理...

代码的第一行导入了 Circuit Playground Express 库。`cpx`对象公开了一个名为`play_tone`的方法。此方法接受两个参数：频率和持续时间。这些参数指定声音的频率（以赫兹为单位）以及声音将在多长时间内播放（以秒为单位）。

持续时间可以以浮点数给出。这意味着诸如`0.2`之类的值将对应于 200 毫秒。此方法调用是一个阻塞调用。因此，调用该方法将开始播放音频，并且在指定的时间到达之前不会返回任何内容。

# 还有更多...

本章介绍的技术是从板子上的扬声器生成蜂鸣声的一种非常直接的方法。但是，在幕后，发生了很多事情。当您指定声音的频率和持续时间时，它将以编程方式构建声波，然后将音频数据输入扬声器以播放声音。音频数据是通过在 Python 代码中构建正弦波来创建的。

构建此音频数据的代码是 Circuit Playground Express 库的一部分，该库已在本教程中导入。您可以下载代码并阅读以了解如何完成此操作。这是了解声波的数学和如何通过软件创建它们的绝佳方式。以下屏幕截图显示了计算机生成的以 500 赫兹播放的音调的外观：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mcpy-cb/img/ea2fd2f8-ab5a-4f62-a3c4-d012bbb0de11.png)

您可以清楚地从前面的屏幕截图中看到，这看起来就像正弦波形。当我们放大以查看单个声音周期时，我们拍摄了该屏幕截图。由于声音以 500 赫兹播放，我们期望一个周期为 1/500 秒长。在这里，我们可以看到第一个波结束的地方——确切地说是在 0.002 秒处。

# 另请参阅

您可以使用以下参考资料了解更多信息：

+   有关`play_tone`方法的文档可以在[`circuitpython.readthedocs.io/projects/circuitplayground/en/latest/api.html#adafruit_circuitplayground.express.Express.play_tone`](https://circuitpython.readthedocs.io/projects/circuitplayground/en/latest/api.html#adafruit_circuitplayground.express.Express.play_tone)找到。

+   有关人类可以听到的音频频谱的更多细节可以在[`www.teachmeaudio.com/mixing/techniques/audio-spectrum/`](https://www.teachmeaudio.com/mixing/techniques/audio-spectrum/)找到。

# 控制音调、频率和持续时间

在这个示例中，我们将学习如何以不同的频率和持续时间播放音调。通过重复播放不同频率的音调，每次持续时间都不同，我们可以学会如何超越单个蜂鸣声。这些步骤最终将使我们能够演奏旋律或不同音调，可以发出与警报相同的声音。

# 准备工作

您需要访问 Circuit Playground Express 上的 REPL 才能运行本示例中提供的代码。

# 如何做...

让我们执行以下步骤：

1.  在 REPL 中运行以下代码行。您应该听到五个单独的音调，每个音调都会播放 0.2 秒。声音将从较低的音调开始，逐渐变得更高。每次播放音调时，音调的频率将被打印到 REPL 中的输出中：

```py
>>> from adafruit_circuitplayground.express import cpx >>> for i in range(500, 1000, 100): ... print(i) ... cpx.play_tone(i, 0.2)
...     
...     
... 
500
600
700
800
900
>>> 
```

1.  使用以下代码播放三种不同的音调。音调将提高音高，并且播放时间也会增加：

```py
>>> from adafruit_circuitplayground.express import cpx
>>> for i in range(200, 500, 100):
...     print(i)
...     cpx.play_tone(i, i/1000)
...     
...     
... 
200
300
400
>>> 
```

# 工作原理…

在第一段代码中，`for`循环将迭代频率值，从 500 开始，每次增加 100，直到结束于 900。这个范围和这些步骤对人耳来说是很容易听到的。在每次迭代中，将打印要播放的频率，然后使用`play_tone`方法播放。每次迭代中只有声音的频率会改变；它们都会播放 200 毫秒。

在第二段代码中，`for`循环将迭代一个较低的音调，并且音调较少。对于每次迭代，音调的频率和持续时间都会增加。频率将是`i`变量的确切值，而持续时间将是以毫秒为单位的`i`的值。由于`play_tone`方法期望的值是以秒为单位的，所以我们必须将其除以 1,000。

# 还有更多...

本章介绍的两个`for`循环变化了在短暂的时间内播放音调的方式。在这两个示例中，音调在一秒钟内播放，但它们有三个或更多不同的音调。

这是一个很好的起点，可以尝试不同变化的循环。因为每个循环只需要一秒钟，所以你可以快速进行实验，立即听到结果。尝试通过改变音调或音调变化的速度来进行实验。

在两个循环中，音调随着每次迭代而增加。尝试并实验一个音调，使其随着每次迭代而降低。

# 另请参阅

您可以使用以下参考资料了解更多信息：

+   有关 Python range 函数的文档可以在[`docs.python.org/3/library/functions.html#func-range`](https://docs.python.org/3/library/functions.html#func-range)找到。

+   有关音调和频率的解释可以在[`www.le.ac.uk/se/centres/sci/selfstudy/snd5.htm`](https://www.le.ac.uk/se/centres/sci/selfstudy/snd5.htm)找到。

# 演奏一个音符

在这个示例中，我们将学习如何定义一些全局常量，每个常量代表一个特定的音符。然后，我们可以通过引用它们的常量来演奏这些不同的音符。音符是旋律的基本组成部分。这将是演奏旋律的第一步。一旦我们学会了如何演奏一个音符，我们就可以在以后的示例中将多个音符组合在一起演奏旋律。

# 准备工作

您需要访问 Circuit Playground Express 上的 REPL 来运行本食谱中提供的代码。

# 如何做...

让我们执行以下步骤：

1.  在 REPL 中运行以下代码行：

```py
>>> from adafruit_circuitplayground.express import cpx
>>> E5 = 659
>>> C5 = 523
>>> G5 = 784
>>> cpx.play_tone(E5, 0.15)
```

您应该听到音箱播放`E5`音符，持续 0.15 秒。

1.  使用以下代码播放`C5`和`G5`音符，持续 0.15 秒：

```py
cpx.play_tone(C5, 0.15)
cpx.play_tone(G5, 0.15)
```

# 它是如何工作的...

本食谱的第一行代码导入了 Circuit Playground Express 库。然后，定义了三个全局常量，并以它们关联的音符命名。本食谱使用**科学音高记谱法**（**SPN**）。这种记谱法通过将音符名称与指定音高的数字相结合来工作。在 E5 的情况下，音符将是 E，音高将是 5。在这里，每个音符都映射到特定的声音频率。

在第一段代码块中，通过在调用`play_tone`方法时引用`E5`全局常量来简单地播放`E5`音符。将持续时间设置为`0.15`允许每个音符播放 150 毫秒，这样可以为音乐创造一个舒适的节奏。减少或增加此值可以增加或减少音乐音调的播放速度。第二段代码以相同的速度播放其余两个音符。

本章中使用的频率遵循标准钢琴键频率。这相当于标准音乐音高和 12 平均律。

# 还有更多...

在本食谱中，我们使用了三个音符来演示定义音符然后播放每个音符的过程。当然，还可以定义许多其他音符。

一个很好的学习练习是找到其他流行音符的频率，并经历定义它们并播放它们的过程。尽管三个音符似乎太少，但足以演奏出一个可识别的旋律。在下一个食谱中，我们将看到这三个音符如何组合在一起演奏一首流行的旋律。

# 另请参阅

您可以使用以下参考资料了解更多信息：

+   八度记谱法的解释可以在[`www.flutopedia.com/octave_notation.html`](http://www.flutopedia.com/octave_notation.html)找到。

+   可以在[`mdoege.github.io/PySynth/`](https://mdoege.github.io/PySynth/)找到基于 Python 的软件合成器。

# 演奏旋律

在本食谱中，我们将学习如何通过播放一系列音符来演奏旋律。单独的音符本身相当无聊。真正的乐趣开始于您可以组合一系列音符并正确计时以演奏旋律。

通过遵循标准的音乐记谱法，将能够以一种 Circuit Playground Express 能够播放的方式在 Python 中指定流行的旋律。

# 准备工作

您需要访问 Circuit Playground Express 上的 REPL 来运行本食谱中提供的代码。

# 如何做...

让我们执行以下步骤：

1.  在 REPL 中运行以下代码行。您应该听到音箱播放`E5`音符，持续 0.15 秒：

```py
>>> import time
>>> from adafruit_circuitplayground.express import cpx
>>> 
>>> E5 = 659
>>> C5 = 523
>>> G5 = 784
>>> 
>>> def play_note(note, duration=0.15):
...     if note == 0:
...         time.sleep(duration)
...     else:
...         cpx.play_tone(note, duration)
... 
>>> play_note(E5)
```

1.  使用以下代码行以两倍速播放相同的音符，然后以一半的速度播放：

```py
>>> play_note(E5, 0.15 / 2)
>>> play_note(E5, 0.15 * 2)
```

1.  使用以下代码行播放空白，并使扬声器保持安静，持续时间与正常速度播放一个音符的时间相同：

```py
>>> play_note(0)
```

1.  使用以下代码行播放*超级马里奥兄弟*主题曲的开头部分：

```py
>>> MELODY = (E5, E5, 0, E5, 0, C5, E5, 0, G5)
>>> for note in MELODY:
...     play_note(note)
... 
>>> 
```

1.  接下来的代码将结合本食谱中显示的所有代码，以制作一个完整的程序。将其添加到`main.py`文件中，它将在重新加载代码时播放*超级马里奥兄弟*主题曲的开头部分：

```py
import time
from adafruit_circuitplayground.express import cpx

E5 = 659
C5 = 523
G5 = 784

MELODY = (E5, E5, 0, E5, 0, C5, E5, 0, G5)

def play_note(note, duration=0.15):
    if note == 0:
        time.sleep(duration)
    else:
        cpx.play_tone(note, duration)

for note in MELODY:
    play_note(note)
```

# 它是如何工作的...

初始的代码行导入必要的库并设置程序中其余代码所需的常量。`MELODY`常量包含构成歌曲的音符序列。在某些音符之间有静音暂停；这些暂停只需指定值为`0`，表示此时不应播放任何音符。`play_note`函数期望给出要播放的音符的频率，以及可选的音符播放时间。如果给出频率`0`，它将调用 sleep 函数保持静音；否则，它将播放音符作为音调。

最后，程序末尾的`for`循环简单地循环遍历旋律中定义的每个音符，并通过调用`play_note`函数来播放它。通过这种方式，您可以定义许多不同的旋律和歌曲，并根据用户与设备的交互方式播放不同的歌曲。

# 有更多...

这个配方是以通用方式编写的：您采用一首流行的旋律，提供音符序列和每个音符的相关频率，然后将旋律添加到您的项目中。这个配方中的旋律让每个音符以相同的持续时间播放。

然而，有许多旋律可能混合四分音符和八分音符。这些旋律将需要为每个音符定义不同的持续时间。可以扩展该配方，以便我们可以跟踪要播放的每个音符以及每个音符需要播放的持续时间。

# 另请参阅

您可以使用以下参考资料了解更多信息：

+   可以在[`www.princetronics.com/supermariothemesong/`](https://www.princetronics.com/supermariothemesong/)找到在 Arduino 设备上播放*超级马里奥兄弟*主题曲的示例。

+   有关 Circuit Playground 声音和音乐的讨论可在[`learn.adafruit.com/circuit-playground-music`](https://learn.adafruit.com/circuit-playground-music)找到。

+   在[`learn.adafruit.com/circuit-playground-hot-potato/caternuson-playing-a-melody`](https://learn.adafruit.com/circuit-playground-hot-potato/caternuson-playing-a-melody)找到 Circuit Playground 上演奏旋律的示例。

# 发出警报

在这个配方中，我们将学习如何播放低音和高音频率的声音，以创建警报声音。警报声音对于提醒人们引起他们的注意非常有用。这个配方演示了创建警报声音的一种非常简单但有效的方法，然后可以根据项目的需要进行调整。

# 准备工作

您需要访问 Circuit Playground Express 上的 REPL 来运行本配方中提供的代码。

# 如何做到...

让我们为这个配方执行以下步骤：

1.  在 REPL 中运行以下代码行。您应该听到高音的蜂鸣声持续 0.5 秒：

```py
>>> from adafruit_circuitplayground.express import cpx
>>> 
>>> BEEP_HIGH = 960
>>> BEEP_LOW = 800
>>> 
>>> cpx.play_tone(BEEP_HIGH, 0.5)
```

1.  使用以下代码播放低音的蜂鸣声 0.5 秒：

```py
>>> cpx.play_tone(BEEP_LOW, 0.5)
```

1.  使用以下代码播放警报器，通过三个周期从高音到低音，总共播放三秒：

```py
>>> for i in range(3):
...     cpx.play_tone(BEEP_HIGH, 0.5)
...     cpx.play_tone(BEEP_LOW, 0.5)
... 
>>> 
```

1.  接下来的代码将结合本配方中显示的所有代码，以制作一个完整的程序。将其添加到`main.py`文件中，每次重新加载代码时都会播放三秒的警报声音：

```py
from adafruit_circuitplayground.express import cpx

BEEP_HIGH = 960
BEEP_LOW = 800

for i in range(3):
    cpx.play_tone(BEEP_HIGH, 0.5)
    cpx.play_tone(BEEP_LOW, 0.5)
```

# 它是如何工作的...

初始的代码行导入必要的库并设置程序中其余代码所需的常量。然后，脚本循环三次，每次迭代都会播放一秒钟的声音。

在每次迭代中，将播放高音持续半秒，然后低音持续半秒。通过这种方式，创建了一个警报声音效果，类似于警报声音。

# 有更多...

此代码可以放入一个接收参数计数的函数中，该参数指定警报响响多少次或多少秒。然后，对于项目中的任何代码，您都可以调用该函数，使您的板播放 10 秒或 30 秒的警报。您还可以将此教程与书中的其他教程结合起来，使板上的像素以与警报相同的方式闪烁为红色。

# 另请参阅

您可以使用以下参考资料了解更多信息：

+   调用`play_tone`方法时更改频率的示例可以在[`learn.adafruit.com/circuitpython-made-easy-on-circuit-playground-express/play-tone`](https://learn.adafruit.com/circuitpython-made-easy-on-circuit-playground-express/play-tone)中找到。

+   可以在[`www.instructables.com/id/How-to-Make-a-Siren-Using-Arduino/`](https://www.instructables.com/id/How-to-Make-a-Siren-Using-Arduino/)找到制作警报声音的微控制器项目。

# 播放 WAV 文件

在本教程中，我们将学习如何使用扬声器播放您选择的 WAV 文件。Circuit Playground Express 上有大量存储空间，可以存储短音频片段，并可以在特定时间播放。

音调、蜂鸣、警报和旋律都很棒；但是，一旦您可以播放 WAV 文件，那么您就可以播放任何类型的声音。

# 准备工作

您需要访问 Circuit Playground Express 上的 REPL 来运行本教程中提供的代码。

# 操作步骤...

让我们执行以下步骤：

1.  将`hello.wav`文件复制到与`main.py`文件相同的文件夹中的设备上。然后，在 REPL 中运行以下代码行：

```py
>>> from adafruit_circuitplayground.express import cpx
>>> cpx.play_file('hello.wav')
```

1.  您应该听到板子播放音频文件时说“**你好**”。

# 工作原理...

代码的第一行导入了 Circuit Playground Express 库。`cpx`对象公开了一个名为`play_file`的属性方法。该方法接受一个参数，即`.wav`文件名，该文件将在板上的扬声器上播放。

音频文件应该是 WAV 文件格式；它应该具有 22,050 kHz 的采样率，16 位格式，并且具有单声道音频。此方法将打开音频文件并在扬声器上开始播放。它还将不断轮询音频设备，直到播放完成，并在音频播放完成后返回。

# 还有更多...

由于板上的硬件限制，您将无法播放诸如 MP3 这样的压缩音乐格式。文件需要以特定的未压缩文件格式，直接输入到板上的播放硬件中。

这样做的一个后果是，未压缩的声音流会更大，因此只能存储短音频片段在设备上。这仍然为播放声音效果或其他短音频片段提供了许多可能性。

# 另请参阅

您可以使用以下参考资料了解更多信息：

+   可以在[`circuitpython.readthedocs.io/projects/circuitplayground/en/latest/api.html#adafruit_circuitplayground.express.Express.play_file`](https://circuitpython.readthedocs.io/projects/circuitplayground/en/latest/api.html#adafruit_circuitplayground.express.Express.play_file)找到`play_file`方法的文档。

+   调用`play_file`方法的示例可以在[`learn.adafruit.com/circuitpython-made-easy-on-circuit-playground-express/play-file`](https://learn.adafruit.com/circuitpython-made-easy-on-circuit-playground-express/play-file)中找到。

# 将 MP3 文件转换为 WAV 文件

在本教程中，我们将学习如何将 MP3 文件转换为 WAV 文件，然后可以在 Circuit Playground Express 上播放。MP3 文件是最流行的声音文件格式之一。当您有一个要包含在嵌入式项目中的音频剪辑，但需要将其转换为正确的格式以便正确播放时，本教程非常有用。

# 准备工作

您需要下载并安装开源音频编辑软件 Audacity。它适用于 Windows、macOS 和 Linux。

Audacity 可以从官方网站[`www.audacityteam.org/`](https://www.audacityteam.org/)下载。

# 如何做...

让我们执行以下步骤：

1.  启动 Audacity 软件，然后选择文件|打开。然后，选择 MP3 文件并单击打开。

1.  应用程序中应该显示音频文件的详细信息，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mcpy-cb/img/2e53af75-4de3-4618-ac25-0808b3010fc0.png)

1.  选择轨道|重新采样，然后应该出现以下对话框：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mcpy-cb/img/ec025055-3467-4fd2-a993-26d6b45e3f27.png)

1.  将新的采样率设置为`22050`，然后单击确定。

1.  现在，选择轨道|立体声轨道转换为单声道。屏幕上应该只有一个单声道，而不是可见的立体声音频流：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mcpy-cb/img/a41bf509-b7ef-4be2-afa8-76a4c9ca5926.png)

音频数据现在已准备好导出为 WAV 格式。

1.  接下来，选择文件|导出音频。

1.  将文件格式下拉菜单设置为 WAV（Microsoft）签名 16 位 PCM 的值。

1.  单击保存按钮。

1.  现在，您可以将 WAV 文件复制到板上并在设备上播放它。

# 它是如何工作的...

Circuit Playground Express 板期望音频文件以 WAV 文件格式存在，并且采样率为 22,050 kHz，采用 16 位格式，并且具有音频数据的单声道。Audacity 是一款多功能音频编辑器，可以打开任意数量的音频格式，并执行必要的更改以将音频数据转换为正确的格式。

在这个教程中采取的步骤重新采样音频数据并将音频通道转换为单声道。完成后，音频数据可以导出到正确的 WAV 格式。重要的是要注意，WAV 文件不像其他音频格式那样被压缩，因此它们将占用更多的空间。这与该设备上的存储限制相结合，意味着只能使用短音频剪辑，以便它们可以适应该设备。

# 还有更多...

这个教程侧重于 MP3 文件格式作为输入格式。但是，Audacity 支持广泛的输入格式，因此您不仅限于该输入格式进行转换。当您想要从更大的音频流中准备一个短音频剪辑时，Audacity 还具有广泛的编辑功能，这将非常有用。

一个很好的例子是，当您有一首可能长达五分钟的歌曲，但您只想要一个短短的五秒钟的片段加载到您的板上。然后，您可以使用 Audacity 的编辑和转换功能来实现最终结果。

# 另请参阅

您可以使用以下参考资料了解更多信息：

+   有关 WAV PCM 音频文件格式的更多详细信息，请访问[`soundfile.sapp.org/doc/WaveFormat/`](http://soundfile.sapp.org/doc/WaveFormat/)。

+   有关在微控制器音频项目中使用 Audacity 的指南，请访问[`learn.adafruit.com/microcontroller-compatible-audio-file-conversion`](https://learn.adafruit.com/microcontroller-compatible-audio-file-conversion)。

# 开始和停止音调

在这个教程中，我们将学习如何使用`start_tone`和`stop_tone`调用在后台播放音调，并在播放声音时控制板上的其他组件。本教程中使用的技术基本上允许您在播放声音时做更多事情。

实施此项目的一个示例是当您想要播放警报声并同时闪烁灯光时。

# 准备工作

您将需要访问 Circuit Playground Express 上的 REPL，以运行本教程中提供的代码。

# 如何做...

让我们执行以下步骤：

1.  在 REPL 中运行以下代码行。您应该听到一个高音的尖叫声，持续 0.5 秒：

```py
>>> from adafruit_circuitplayground.express import cpx
>>> import time
>>> 
>>> BEEP_HIGH = 960
>>> BEEP_LOW = 800
>>> 
>>> cpx.pixels.brightness = 0.10
>>> cpx.start_tone(BEEP_HIGH)
>>> time.sleep(0.5)
>>> cpx.stop_tone()
```

1.  使用以下代码在后台播放蜂鸣声，同时以 0.1 秒的间隔将 10 个像素变红。然后在动画结束时蜂鸣声将停止：

```py
>>> cpx.start_tone(BEEP_HIGH)
>>> for i in range(10):
...     cpx.pixels[i] = 0xFF0000
...     time.sleep(0.1)
... 
>>> cpx.stop_tone()
>>> 
```

1.  使用以下代码块执行类似的操作，但音调较低。在这里，像素动画将逐个关闭每个像素，最终在动画结束时结束音调：

```py
>>> cpx.start_tone(BEEP_LOW)
>>> for i in range(10):
...     cpx.pixels[i] = 0x000000
...     time.sleep(0.1)
... 
>>> cpx.stop_tone()
>>> 
```

1.  接下来的代码将所有在本示例中显示的代码组合在一起，以制作一个完整的程序。将其添加到`main.py`文件中，它将播放警报声并以警报声开启和关闭像素动画。

```py
from adafruit_circuitplayground.express import cpx
import time

BEEP_HIGH = 960
BEEP_LOW = 800

cpx.pixels.brightness = 0.10

cpx.start_tone(BEEP_HIGH)
for i in range(10):
    cpx.pixels[i] = 0xFF0000
    time.sleep(0.1)
cpx.stop_tone()

cpx.start_tone(BEEP_LOW)
for i in range(10):
    cpx.pixels[i] = 0x000000
    time.sleep(0.1)
cpx.stop_tone()
```

# 工作原理...

初始代码行导入必要的库并设置程序中其余代码所需的常量。像素的亮度也设置为更舒适的水平。然后脚本开始在后台播放高音调的蜂鸣声。在循环遍历 10 个像素并在每个循环之间以 0.1 秒的延迟将每个像素变红。

动画完成后，音调播放停止并播放较低的音调。像素再次被循环遍历；然而，这一次，它们逐个关闭。最后，一旦循环结束，音调播放停止。

# 还有更多...

尽管使用`start_tone`和`stop_tone`需要比简单调用`play_tone`更多的代码行，但它们允许您做一些仅使用`play_tone`是不可能做到的事情。例如，您可以使用脚本在音频在后台播放时执行其他任务。

在这个示例中，灯光和声音输出一起改变。但是，您可以使用相同的技术来播放音调，直到有人按下某个按钮。或者，您可以根据按下不同的按钮来改变正在播放的音调。

# 另请参阅

您可以使用以下参考资料了解更多信息：

+   有关`start_tone`方法的文档可在[`circuitpython.readthedocs.io/projects/circuitplayground/en/latest/api.html#adafruit_circuitplayground.express.Express.start_tone`](https://circuitpython.readthedocs.io/projects/circuitplayground/en/latest/api.html#adafruit_circuitplayground.express.Express.start_tone)找到。

+   有关`stop_tone`方法的文档可在[`circuitpython.readthedocs.io/projects/circuitplayground/en/latest/api.html#adafruit_circuitplayground.express.Express.stop_tone`](https://circuitpython.readthedocs.io/projects/circuitplayground/en/latest/api.html#adafruit_circuitplayground.express.Express.stop_tone)找到。


# 第四章：与按钮交互

本章将介绍与 Adafruit Circuit Playground Express 配备的按钮和触摸板进行交互的方法。您将学习如何检测按钮是否被按下，并且还将探索更高级的主题，例如微调电容触摸板的灵敏度。

在本章中，我们将介绍以下配方：

+   检测按下按钮

+   使用按下按钮控制 LED

+   读取滑动开关

+   在按钮状态更改时调用函数

+   使用按下按钮移动活动 LED

+   按下按钮时播放蜂鸣声

+   检测触摸板上的触摸

+   监视触摸板的原始测量值

+   调整触摸阈值

# Adafruit Circuit Playground Express 布局

以下照片显示了标有 A 和 B 的两个按下按钮的位置：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mcpy-cb/img/218effcf-eb72-4d4b-9d79-22da608a3f65.png)

由 adafruit.com 提供

以下照片显示了设备上滑动开关的位置：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mcpy-cb/img/654587b7-181c-48c5-be45-6e3d7f9b9d2b.png)

由 adafruit.com 提供

以下照片显示了板上七个电容触摸板的位置：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mcpy-cb/img/1d427f3e-82fd-4e6f-b431-d853f833347e.png)

由 adafruit.com 提供

每个触摸板都包含可以导电的不同材料。鳄鱼夹可以用来连接这些材料到触摸板。此外，金属、水和水果都可以导电，足以用作连接器连接到触摸板。

现在，让我们看看如何检测按钮的按下。

# 检测按下按钮

在本配方中，我们将学习如何创建一个程序，当按下按钮时将打印一条消息。按下按钮是在设备上创建用户交互的好方法。该板配有两个按下按钮 A 和 B，因此您可以通过读取和响应按下按钮事件来创建各种不同的用户交互。

# 准备工作

您需要访问 Circuit Playground Express 上的 REPL 才能运行本配方中提供的代码。

# 如何做...

让我们执行以下步骤：

1.  首先，在 REPL 中运行以下代码行。这里`cpx.button_a`的值是`False`，因为按钮没有被按下：

```py
>>> from adafruit_circuitplayground.express import cpx
>>> cpx.button_a
False
```

1.  在运行以下代码块时，保持按下按钮 A。这将把值更改为`True`：

```py
>>> cpx.button_a
True
```

1.  然后，将以下代码添加到`main.py`文件中，这将在执行时重复打印按下按钮 A 的状态：

```py
from adafruit_circuitplayground.express import cpx
import time

while True:
    print(cpx.button_a)
    time.sleep(0.05)
```

# 它是如何工作的...

第一行代码导入了 Circuit Playground Express 库。`cpx`对象公开了一个名为`button_a`的属性。当按钮被按下时，此属性将返回`True`，当按钮未被按下时，它将返回`False`。

脚本循环运行，每个循环之间延迟 50 毫秒。按钮按下的状态不断打印。运行此程序时，按住并释放按钮，以查看打印输出的变化。

请注意，还有另一个名为`button_b`的属性，它具有相同的功能，但用于按下按钮 B。

# 还有更多...

在 Python 中与按下按钮交互的界面非常简单。基本上，它转换为一个布尔值，您可以在脚本执行期间的任何时间检查以检查按钮的当前状态。

在简单的情况下，反复检查按钮状态的轮询模型效果很好。然而，当您想要对每次按下按钮执行单个操作时，而不是持续按下按钮时，它会出现问题。这类似于您期望在桌面上与键盘交互的方式。在这种情况下，您期望一个物理按键按下将转换为一次应用的动作。另一方面，长时间按下的物理按键通常会产生重复的按键动作。

在大多数操作系统上，在释放按键之前会应用大约 500 毫秒的延迟，这被视为**重复按键操作**。当您尝试实现与按键自然和直观交互的代码时，牢记这些细节是很重要的。

# 另请参阅

您可以在这里找到更多信息：

+   有关`button_a`属性的更多文档可以在[`circuitpython.readthedocs.io/projects/circuitplayground/en/latest/api.html#adafruit_circuitplayground.express.Express.button_a`](https://circuitpython.readthedocs.io/projects/circuitplayground/en/latest/api.html#adafruit_circuitplayground.express.Express.button_a)找到。

+   可以在[`learn.adafruit.com/circuitpython-made-easy-on-circuit-playground-express/buttons`](https://learn.adafruit.com/circuitpython-made-easy-on-circuit-playground-express/buttons)找到与按键交互的示例。

# 使用按钮控制 LED

在这个示例中，我们将学习如何使用两个独立的按钮控制两个单独的 NeoPixels。这是一种有趣而简单的方式，可以使您的设备具有交互性。在这里，您将在按下每个按钮时立即从板上获得反馈，因为像素会做出响应而亮起。

# 准备工作

您需要访问 Circuit Playground Express 上的 REPL 才能运行本示例中提供的代码。

# 如何做...

让我们执行以下步骤：

1.  首先，在 REPL 中运行以下代码行：

```py
>>> from adafruit_circuitplayground.express import cpx
>>> 
>>> BLACK = 0x000000
>>> GREEN = 0x00FF00
>>> 
>>> cpx.pixels.brightness = 0.10
```

1.  在运行以下代码块时，保持按下按钮 A。您应该会看到紧挨着按钮的像素 2 变成绿色：

```py
>>> cpx.pixels[2] = GREEN if cpx.button_a else BLACK
```

1.  释放按钮 A 并运行以下代码块；现在应该看到像素 2 关闭：

```py
>>> cpx.pixels[2] = GREEN if cpx.button_a else BLACK
```

1.  将以下代码添加到`main.py`文件中，它将根据按下按钮 A 或按钮 B 来打开像素 2 和像素 7：

```py
from adafruit_circuitplayground.express import cpx

BLACK = 0x000000
GREEN = 0x00FF00

cpx.pixels.brightness = 0.10
while True:
    cpx.pixels[2] = GREEN if cpx.button_a else BLACK
    cpx.pixels[7] = GREEN if cpx.button_b else BLACK
```

# 工作原理...

代码的第一行导入了 Circuit Playground Express 库。定义了绿色和黑色的常量，并将像素亮度设置为舒适的水平。

然后，启动一个无限循环，每次迭代执行两行代码。如果按下按钮 A，则第一行将把像素 2 的颜色设置为绿色，否则将关闭像素。第二行将把像素 7 的颜色设置为绿色，如果按下按钮 B，则将关闭像素。

# 还有更多...

与本章第一个示例相比，在每次循环之间没有调用`sleep`函数来引起延迟。在这个特定的示例中，之所以不需要在轮询按钮状态之间设置延迟，是有原因的。如果其中一个按钮被按住，那么其中一个灯将打开并保持打开，而不会出现问题。

在第一个示例中，当按下按钮时将会出现大量的打印语句。仔细观察每种情况，以决定是否需要在每次轮询之间设置延迟。

# 另请参阅

您可以在这里找到更多信息：

+   有关条件表达式的更多文档可以在[`docs.python.org/3/reference/expressions.html#conditional-expressions`](https://docs.python.org/3/reference/expressions.html#conditional-expressions)找到。

+   有关按钮如何工作的更多详细信息，请访问[`sciencing.com/push-switches-work-electrical-circuit-5030234.html`](https://sciencing.com/push-switches-work-electrical-circuit-5030234.html)。

# 读取滑动开关

在这个示例中，我们将学习如何创建一个程序，该程序将重复打印滑动开关是打开还是关闭。滑动开关有其自身的优势，这个示例将演示如何将其纳入您的项目中。

# 准备工作

您需要访问 Circuit Playground Express 上的 REPL 才能运行本示例中提供的代码。

# 如何做...

让我们执行以下步骤：

1.  确保将滑动开关翻转到左侧。在 REPL 中运行以下代码行：

```py
>>> from adafruit_circuitplayground.express import cpx
>>> cpx.switch
True
```

1.  将滑动开关翻转到右侧。运行以下代码块：

```py
>>> cpx.switch
False
```

1.  将以下代码添加到`main.py`文件中，它将在执行时重复打印滑动开关的状态。将滑动开关向左和向右转动，观察输出的变化：

```py
from adafruit_circuitplayground.express import cpx
import time

while True:
    print(cpx.switch)
    time.sleep(0.05)
```

# 工作原理...

第一行代码导入了 Circuit Playground Express 库。`cpx`对象公开了一个名为`switch`的属性。当开关处于左侧位置时，此属性将返回`True`，当开关处于右侧位置时，将返回`False`。

该脚本将无限循环，每个循环之间有 50 毫秒的延迟。滑动开关的状态将不断打印。

# 还有更多...

按下按钮非常适合重复应用动作，或者当您希望注册单次按钮按下时。然而，滑动开关更适合当您希望人们能够在两种操作模式之间进行选择时。

例如，您可能有一个项目，其中有两种动画模式可以使用滑动开关进行选择。您可以使用滑动开关来启用或禁用项目中的警报声音。根据用户的操作，滑动开关或按钮可能更合适。

Circuit Playground Express 的好处在于两种选项都可用，因此您可以选择最适合您的选项。

# 另请参阅

您可以在这里找到更多信息：

+   有关开关属性的更多文档可以在[`circuitpython.readthedocs.io/projects/circuitplayground/en/latest/api.html#adafruit_circuitplayground.express.Express.switch`](https://circuitpython.readthedocs.io/projects/circuitplayground/en/latest/api.html#adafruit_circuitplayground.express.Express.switch)找到。

+   可以在[`learn.sparkfun.com/tutorials/switch-basics/all`](https://learn.sparkfun.com/tutorials/switch-basics/all)找到关于常见类型开关工作原理的解释。

# 在按钮状态改变时调用函数

在本文中，我们将学习如何在按钮状态发生变化时调用函数。通常要求仅在按钮状态发生变化时执行操作，而不是在按钮被按下时执行操作。本文演示了一种您可以在项目中实现此要求的技术。

# 准备工作

您需要访问 Circuit Playground Express 上的 REPL 来运行本文中提供的代码。

# 如何做...

让我们执行以下步骤：

1.  首先，在 REPL 中运行以下代码行：

```py
>>> from adafruit_circuitplayground.express import cpx
>>> def button_change(pressed):
...     print('pressed:', pressed)
... 
```

1.  这将定义`button_change`函数，每次按钮状态发生变化时都会调用该函数。运行以下代码，然后重复按下和释放按钮 A：

```py
>>> last = cpx.button_a
>>> while True:
...     if cpx.button_a != last:
...         button_change(cpx.button_a)
...         last = cpx.button_a
... 
pressed: True
pressed: False
pressed: True
pressed: False
pressed: True
pressed: False
```

1.  接下来的代码将结合本文中展示的所有代码，制作一个完整的程序。将其添加到`main.py`文件中；每次按下或释放按钮 A 时，它都会打印一条消息：

```py
from adafruit_circuitplayground.express import cpx

def button_change(pressed):
    print('pressed:', pressed)

last = cpx.button_a
while True:
    if cpx.button_a != last:
        button_change(cpx.button_a)
        last = cpx.button_a
```

# 工作原理...

定义了`button_change`函数，每次按钮状态改变时都会调用该函数。

`last`全局变量将用于跟踪按钮的上一个状态。然后，启动一个无限循环，它将检查按钮的当前状态是否与其上一个状态不同。如果检测到变化，它将调用`button_change`函数。

最后，每当按钮状态发生变化时，最新的按钮状态都将保存在`last`变量中。该脚本实际上实现了一个事件循环，用于检测按钮按下事件，并在检测到这些事件时调用`button_change`事件处理程序来处理这些事件。

# 还有更多...

偶尔，您可能希望将按钮按下注册为单个事件，而不管用户按下按钮的时间长短。这个方法通过跟踪按钮的先前状态并仅在按钮按下的结果时调用事件处理程序来实现这一目标。

尽管您需要跟踪按钮的最后状态这一额外步骤，但这种方法的好处在于您不必在轮询按键的延迟时间或重复键盘延迟的时间上纠缠。这个方法只是解决如何响应物理按钮交互的另一种可行方法。

# 另请参阅

您可以在这里找到更多信息：

+   可以在[`docs.python.org/3/library/cmd.html`](https://docs.python.org/3/library/cmd.html)找到事件循环和事件处理程序的很好的示例。

+   可以在[`learn.adafruit.com/sensor-plotting-with-mu-and-circuitpython/buttons-and-switch`](https://learn.adafruit.com/sensor-plotting-with-mu-and-circuitpython/buttons-and-switch)找到响应按钮按下的示例。

# 使用按钮移动活动 LED

在这个方法中，我们将学习如何根据按下左侧或右侧按钮来顺时针或逆时针移动活动的 NeoPixel。这个方法超越了以前方法中显示的更简单的按钮和 LED 交互。这是一个更复杂的方法，它将产生按钮按下正在使光在面板上以圆周运动的印象。

# 准备工作

您需要访问 Circuit Playground Express 上的 REPL 才能运行本方法中提供的代码。

# 如何做...

让我们执行以下步骤：

1.  在 REPL 中运行以下代码行：

```py
>>> from adafruit_circuitplayground.express import cpx
>>> import time
>>> 
>>> BLACK = 0x000000
>>> BLUE = 0x0000FF
>>> 
>>> cpx.pixels.brightness = 0.10
>>> i = 0
>>> direction = 1
>>> 
>>> 
```

1.  运行以下代码并按下按钮以查看其对像素的影响：

```py
>>> while True:
...     if cpx.button_a:
...         direction = 1
...     if cpx.button_b:
...         direction = -1
...     i += direction
...     i = i % 10
...     cpx.pixels.fill(BLACK)
...     cpx.pixels[i] = BLUE
...     time.sleep(0.05)
... 
```

1.  接下来的代码将结合本方法中显示的所有代码，以制作一个完整的程序。将此代码块添加到`main.py`文件中，它将在按下按钮 A 和按钮 B 时将点亮的像素的方向从顺时针改为逆时针：

```py
from adafruit_circuitplayground.express import cpx
import time

BLACK = 0x000000
BLUE = 0x0000FF

cpx.pixels.brightness = 0.10
i = 0
direction = 1
while True:
    if cpx.button_a:
        direction = 1
    if cpx.button_b:
        direction = -1
    i += direction
    i = i % 10
    cpx.pixels.fill(BLACK)
    cpx.pixels[i] = BLUE
    time.sleep(0.05)
```

# 它是如何工作的...

代码的第一行导入了 Circuit Playground Express 库和`time`库。然后设置了颜色常量和亮度级别。`i`变量将跟踪当前点亮的像素。`direction`变量将具有值`1`或`-1`，并将控制像素是顺时针移动还是逆时针移动。

在无限循环中，如果按下按钮 A 或按下按钮 B，则会更改方向。方向应用于位置，并应用模 10 运算，以便位置值在 0 和 10 之间旋转。

在每次迭代中，所有像素都会关闭，然后打开所选像素。通过调用使面板在每次循环迭代之间休眠 50 毫秒来控制灯光动画的速度。

# 还有更多...

这个方法结合了许多不同的技术，以产生最终的结果。它使用了一个动画效果，让看着面板的人认为光在面板上以圆圈的方式移动。

已实施动画效果以支持方向运动，使其看起来就像光在顺时针或逆时针方向移动。然后，按键与此动画结合在一起，以改变动画的方向。

您可以采用这个基本方法并将其适应不同的场景。例如，您可以用声音效果替换灯光秀，声音效果可以从安静到响亮，或者从响亮到安静，具体取决于按下哪个按钮。此外，您可以使用两个按键来增加或减少亮度级别。有两个按键可以打开许多选项，以便根据按下的按钮来增加或减少特定值。

# 另请参阅

您可以在这里找到更多信息：

+   可以在[`learn.adafruit.com/circuit-playground-simple-simon`](https://learn.adafruit.com/circuit-playground-simple-simon)找到使用按钮和像素的 Circuit Playground 项目的详细信息。

+   有关取模运算符的文档可以在[`docs.python.org/3.3/reference/expressions.html#binary-arithmetic-operations`](https://docs.python.org/3.3/reference/expressions.html#binary-arithmetic-operations)找到。

# 在按钮按下时播放蜂鸣声

在本教程中，我们将学习在按下按钮时播放蜂鸣声。之前的教程允许我们使用按钮与灯进行交互。本教程将向您展示如何在项目中引入按钮和声音交互。

# 准备工作

您需要访问 Circuit Playground Express 上的 REPL，以运行本教程中提供的代码。

# 如何做...

让我们执行以下步骤：

1.  在按住按钮 A 的同时在 REPL 中运行以下代码行：

```py
>>> from adafruit_circuitplayground.express import cpx
>>> if cpx.button_a:
...     cpx.play_tone(500, 0.2)
...     
...     
... 
>>>
```

1.  扬声器应该发出低音蜂鸣声。在按住按钮 B 的同时运行以下代码，您应该听到高音蜂鸣声：

```py
>>> if cpx.button_b:
...     cpx.play_tone(900, 0.2)
...     
...     
... 
>>> 
```

1.  接下来的代码将结合本教程中显示的所有代码，并向其中添加一个`while`循环，以使其成为一个完整的程序。将此添加到`main.py`文件中，当执行时，每次按下按钮 A 或按钮 B 时，它将产生高音或低音蜂鸣声：

```py
from adafruit_circuitplayground.express import cpx

while True:
    if cpx.button_a:
        cpx.play_tone(500, 0.2)
    if cpx.button_b:
        cpx.play_tone(900, 0.2)
```

# 它是如何工作的...

第一行代码导入了 Circuit Playground Express 库。然后进入一个无限循环，每次循环迭代都会检查按钮 A 或按钮 B 是否被按下，并在每种情况下播放不同音调的蜂鸣声，持续时间为 0.2 秒。

# 还有更多...

这个简单的教程演示了如何通过播放不同的音调使板对不同的按钮按下做出反应。另一种使脚本行为的方法是根据按下的按钮不同播放不同的音频`.wav`文件。滑动开关也可以并入到教程中，以设置两种不同的模式；一种模式可以播放低音调的音符，另一种可以播放高音调的音符。

# 另请参阅

您可以在这里找到更多信息：

+   有关 CircuitPython 如何读取按钮输入的示例可以在[`learn.adafruit.com/circuitpython-essentials/circuitpython-digital-in-out`](https://learn.adafruit.com/circuitpython-essentials/circuitpython-digital-in-out)找到。

+   可以在[`learn.adafruit.com/dear-diary-alarm`](https://learn.adafruit.com/dear-diary-alarm)找到对输入做出反应以播放不同音调的 Circuit Playground 项目的示例。

# 在触摸板上检测触摸

在本教程中，我们将学习如何检测触摸板何时被触摸，并在每次发生此事件时打印一条消息。Circuit Playground Express 配备了许多可以连接到各种对象的触摸板连接器。

基本上，任何可以导电的东西都可以用作与设备交互的方式。您可以使用导线、导电线、水果、水或铜箔与设备交互。

# 准备工作

您需要访问 Circuit Playground Express 上的 REPL，以运行本教程中提供的代码。

# 如何做...

让我们执行以下步骤：

1.  在 REPL 中运行以下代码行。`cpx.touch_A1`的值为`False`，因为未触摸触摸板 A1：

```py
>>> from adafruit_circuitplayground.express import cpx
>>> cpx.touch_A1
False
```

1.  在运行以下代码块时，保持手指触摸触摸板 A1：

```py
>>> cpx.touch_A1
True
```

1.  以下代码应添加到`main.py`文件中。每次按下触摸板 A1 时，这将打印一条消息：

```py
from adafruit_circuitplayground.express import cpx
import time

while True:
    if cpx.touch_A1:
        print('detected touch')
    time.sleep(0.05)
```

# 它是如何工作的...

前几行代码导入了 Circuit Playground Express 库和`time`库。然后脚本进入一个无限循环，在每次循环迭代中检查触摸板 A1 的状态。如果检测到触摸事件，则会打印一条消息。

# 还有更多...

本教程演示了与触摸板交互的简单方法。但是，当涉及到电容触摸传感器时，细节至关重要。取决于您连接到触摸板的材料的导电性，您可能会发现自己处于两个极端之一；也就是说，传感器可能根本不会检测到某些触摸事件，或者如果有很多环境噪音被错误地检测为多次触摸事件。

这些设备并不像机械按钮那样简单。然而，它们将让您创建可以使用香蕉和橙子与嵌入式设备进行交互的项目（因为它们具有电导性）。

# 另请参阅

您可以在这里找到更多信息：

+   有关`touch_A1`属性的更多文档可以在[`circuitpython.readthedocs.io/projects/circuitplayground/en/latest/api.html#adafruit_circuitplayground.express.Express.touch_A1`](https://circuitpython.readthedocs.io/projects/circuitplayground/en/latest/api.html#adafruit_circuitplayground.express.Express.touch_A1)找到。

+   可以在[`learn.adafruit.com/adafruit-circuit-playground-express/adafruit2-circuitpython-cap-touch`](https://learn.adafruit.com/adafruit-circuit-playground-express/adafruit2-circuitpython-cap-touch)找到与电容触摸传感器交互的示例。

# 监控触摸板的原始测量值

在这个教程中，我们将学习如何监控触摸板的原始测量值，这是验证触摸阈值应该如何调整的非常有用的方法。能够直接读取来自触摸传感器的原始传感器值非常重要。

当您想要正确设置触摸阈值或想要找出为什么触摸板的响应方式与您的预期不符时，这种详细级别是必要的。

# 准备工作

您需要访问 Circuit Playground Express 上的 REPL 才能运行本教程中提供的代码。

# 如何操作...

让我们执行以下步骤：

1.  在 REPL 中运行以下代码行。输出显示了从原始触摸测量中获取的值以及在创建对象时自动设置的初始阈值值：

```py
>>> import time
>>> import touchio
>>> import board
>>> a1 = touchio.TouchIn(board.A1)
>>> a1.raw_value
1933
>>> a1.threshold
2050
>>> 
```

1.  在运行下一段代码时，保持手指触摸触摸板 A1：

```py
>>> a1.raw_value
4065
```

1.  在运行下一段代码时，从触摸板 A1 上松开手指：

```py
>>> a1.raw_value
1839
```

1.  以下代码应添加到`main.py`文件中，然后运行。在执行此代码时，它将不断打印原始触摸测量值和当前阈值，并确定当前读数是否被视为触摸事件。此脚本可用于获取实时传感器读数：

```py
import time
import touchio
import board

a1 = touchio.TouchIn(board.A1)
while True:
    touch = a1.raw_value > a1.threshold
    print('raw:', a1.raw_value, 'threshold:', a1.threshold, 'touch:', touch)
    time.sleep(0.5)
```

# 工作原理...

前几行代码导入了与触摸板交互所需的不同低级库。创建了一个`TouchIn`对象并连接到 A1 接口。然后，运行一个无限循环，不断打印与传感器相关的多个值。它打印当前原始触摸测量值的阈值以及当前测量是否应被注册为触摸事件。

最后一个值只是`True`，但如果原始值超过阈值，那么它就是`False`。当`TouchIn`对象首次实例化时，阈值是通过取初始原始值并将其加 100 来设置的。

# 还有更多...

此脚本非常有用，可以验证从触摸传感器读取的实际值，并决定触摸阈值应设置多低或多高。这也是将不同材料连接到您的板上并查看它们在导电和检测触摸事件方面表现如何的好方法。如果没有这些原始值，您只能猜测实际发生了什么。

本章中其他地方使用的高级属性实际上在底层使用了许多在本配方中介绍的库。查看这些高级代码的源代码很有帮助，因为其中的大部分是用 Python 实现的。此外，它可以让您了解代码实际上是如何与硬件交互的。

# 另请参阅

您可以在这里找到更多信息：

+   有关`touchio`模块的更多文档可以在[`circuitpython.readthedocs.io/en/3.x/shared-bindings/touchio/__init__.html`](https://circuitpython.readthedocs.io/en/3.x/shared-bindings/touchio/__init__.html)找到。

+   有关`board`模块的更多文档可以在[`circuitpython.readthedocs.io/en/3.x/shared-bindings/board/__init__.html`](https://circuitpython.readthedocs.io/en/3.x/shared-bindings/board/__init__.html)找到。

+   有关 Circuit Playground 上电容触摸传感器的功能的讨论可以在[`learn.adafruit.com/circuit-playground-fruit-drums/hello-capacitive-touch`](https://learn.adafruit.com/circuit-playground-fruit-drums/hello-capacitive-touch)找到。

+   有关电容触摸传感器工作原理的解释可以在[`scienceline.org/2012/01/okay-but-how-do-touch-screens-actually-work/`](https://scienceline.org/2012/01/okay-but-how-do-touch-screens-actually-work/)找到。

# 调整触摸阈值

在本配方中，我们将学习如何通过更改阈值来调整触摸板的灵敏度。这用于决定信号是否将被视为触摸事件。这是一个重要的设置，需要进行微调并设置为正确的值。如果不这样做，那么您的触摸项目将无法正确运行。

# 准备工作

您需要访问 Circuit Playground Express 上的 REPL 才能运行本配方中提供的代码。

# 如何做...

让我们执行以下步骤：

1.  在 REPL 中运行以下代码行。此时，触摸阈值将增加`200`：

```py
>>> from adafruit_circuitplayground.express import cpx
>>> import time
>>> 
>>> cpx.adjust_touch_threshold(200)
```

1.  在运行下一块代码时，保持手指触摸触摸板 A1：

```py
>>> cpx.touch_A1
True
```

1.  应将以下代码添加到`main.py`文件并运行。该脚本将通过`200`增加触摸阈值，并在传感器检测到触摸事件时打印消息：

```py
from adafruit_circuitplayground.express import cpx
import time

cpx.adjust_touch_threshold(200)
while True:
    if cpx.touch_A1:
        print('detected touch')
    time.sleep(0.5)
```

# 工作原理...

第一行代码导入了 Circuit Playground Express 库。`cpx`对象公开了一个名为`adjust_touch_threshold`的方法。可以使用此方法来更改触摸板上的配置阈值。调用时，所有触摸板的阈值都将增加指定的量。

增加阈值会使触摸板变得不那么敏感，而减小此值将使传感器更敏感。如果阈值设置得太低，则许多传感器读数将被错误地检测为触摸事件。另一方面，如果阈值太高，则无法检测到真正的触摸事件。在每次循环迭代之间应用 500 毫秒的休眠函数，以便在每次迭代期间不会检测到大量的触摸事件。

# 还有更多...

通过实验来决定阈值的最佳值是最好的方法。在开始调整阈值之前，将所有实际导电材料连接到触摸板。然后，在本章中的*监视触摸板原始测量*配方中，获取传感器读数的实时视图。

您还可以重复触摸所讨论的材料，以查看触摸和释放时读数的变化。根据这些读数，您可以设置可靠读取触摸事件的理想阈值。每次更改材料时重启脚本很重要，因为每次首次运行代码时都会发生初始阈值自动配置。

# 另请参阅

您可以在这里找到更多信息：

+   有关`adjust_touch_threshold`方法的进一步文档可以在[`circuitpython.readthedocs.io/projects/circuitplayground/en/latest/api.html#adafruit_circuitplayground.express.Express.adjust_touch_threshold`](https://circuitpython.readthedocs.io/projects/circuitplayground/en/latest/api.html#adafruit_circuitplayground.express.Express.adjust_touch_threshold)找到。

+   调用`adjust_touch_threshold`方法的示例可以在[`learn.adafruit.com/make-it-sense/circuitpython-6`](https://learn.adafruit.com/make-it-sense/circuitpython-6)找到。
