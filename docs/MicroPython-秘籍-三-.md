# MicroPython 秘籍（三）

> 原文：[`zh.annas-archive.org/md5/EE140280D367F2C84B38C2F3034D057C`](https://zh.annas-archive.org/md5/EE140280D367F2C84B38C2F3034D057C)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：让我们动起来

在本章中，您将学习如何控制电机和舵机。使用直流电机将有助于需要控制车辆车轮的项目。舵机可以帮助您的项目控制机器人手臂的移动。这两种设备都将为我们提供创建机械运动的方式。根据您在项目中尝试创建的运动，您可能希望选择其中一种。它们各自的功能以及它们最适合的地方将在接下来的章节中介绍。

通过本章结束时，您将能够利用所学知识创建各种有趣的项目。这将为您能够构建的项目类型开辟全新的可能性。

在本章中，我们将涵盖以下主题：

+   调整舵机到正确的脉冲宽度

+   设置舵机的作用范围

+   设置舵机的角度

+   扫描舵机

+   使用按钮控制舵机

+   控制多个舵机

+   打开直流电机

+   设置直流电机的速度和方向

+   使用按钮控制直流电机

# 技术要求

本章的代码文件可以在 GitHub 存储库的`Chapter08`文件夹中找到[`github.com/PacktPublishing/MicroPython-Cookbook`](https://github.com/PacktPublishing/MicroPython-Cookbook)。

本章中的许多配方将使用 Circuit Playground Express 库，该库通常会在脚本的前几行导入，使用以下代码行：

```py
from adafruit_circuitplayground.express import cpx
```

这个库将帮助我们与板上的按钮和开关进行交互。还有另一个库将在本章的许多配方中导入，使用以下语句：

```py
from adafruit_crickit import crickit
```

这个库将帮助我们与 CRICKIT 板进行交互，以便我们可以控制舵机和直流电机。

本章中涉及舵机的配方期望两个舵机连接到舵机端口 1 和舵机端口 2。连接舵机电缆时，请确保黄色电线朝向板外。

本章中涉及直流电机的配方期望电机连接的驱动器 1 上连接电机。两根电线可以连接到两个连接器中的任何一个方向。无论如何连接电线，旋转方向都会翻转，取决于电线连接的方式。

# 直流电机

直流电机将直流电转换为旋转运动。通常是通过驱动运动的电磁体来实现的，因为它们的磁场发生变化。以下插图显示了这种类型电机的内部结构：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mcpy-cb/img/c7e20f54-d436-4531-935c-a447b0e69f25.png)

来源：https://commons.wikimedia.org/wiki/File:Ejs_Open_Source_Direct_Current_Electrical_Motor_Model_Java_Applet_(_DC_Motor_)_80_degree_split_ring.gif

直流电机在需要高速旋转运动的应用中表现出色。它们适用于操作遥控汽车上的风扇或车轮。

# 舵机

舵机比直流电机更复杂，更适合需要对连接到舵机的物体的确切位置进行更多控制的情况。舵机通常包含直流电机、齿轮、控制电路和传感器，用于检测舵机的确切位置。所有这些组件汇集在一起，形成一个设备，让您对舵机指向的确切角度有更精确的控制。

以下图像显示了一个拆卸的舵机，您可以看到其中的直流电机、齿轮和电路：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mcpy-cb/img/56c95a65-31f3-4d92-b461-fef2e17f8338.png)

来源：https://commons.wikimedia.org/wiki/File:Exploded_Servo.jpg

舵机在需要对某个部件的角度进行精确控制的应用中表现出色；例如，需要控制机器人手臂的角度或船舶舵的角度。

# Adafruit CRICKIT

Adafruit CRICKIT 是一个可以让您从各种硬件控制许多不同类型的电机的板。不同的 CRICKIT 型号支持树莓派和 FeatherWing 系列产品。 

在本章中，我们将使用 CRICKIT 来控制 Circuit Playground Express。以下图片显示了在连接 Circuit Playground Express 之前 CRICKIT 的样子：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mcpy-cb/img/85d7a456-6976-4701-87f7-9b2d93851462.png)

由 adafruit.com 提供

要将这两个设备连接在一起，您将需要 6 个六角黄铜支架，每个支架都将用 12 颗螺丝螺入两个设备。以下图片显示了这些支架和螺丝的样子：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mcpy-cb/img/2e653d71-9c57-45b1-8bb8-c6cd11104b30.png)

由 adafruit.com 提供

连接这些螺丝和支架后，您的两个板应该看起来像下图所示：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mcpy-cb/img/a01b9e38-edd4-4b3c-b7b4-00329a6e6fb8.png)

由 adafruit.com 提供

最多可以连接四个独立的舵机到板上。支持微型、迷你和标准舵机。舵机的三针连接器应连接到一个可用的舵机插槽，如下图所示：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mcpy-cb/img/0823559f-3f26-4a54-9ad8-6c5b24c87980.png)

由 adafruit.com 提供

最多可以连接两个直流电机到板上。每个电机将连接到两个引脚。每个电机连接的引脚对在下图中显示：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mcpy-cb/img/ec85cdb2-810f-47ab-a9e4-60f7cc8125cd.png)

由 adafruit.com 提供

连接两个设备后，您可以为每个设备供电，并使用 USB 电缆将 Circuit Playground Express 连接到计算机，方式与本书前几章相同。连接后，您需要使用支持 CRICKIT 硬件的固件刷新固件。

本章使用的 UF2 文件的版本是支持 CRICKIT 的 CircuitPython 3.1.2 版本，名为`adafruit-circuitpython-circuitplayground_express_crickit-3.1.2.uf2`。

有关如何使用此固件刷新板的详细信息，请参阅第一章，*使用 MicroPython 入门*中有关如何刷新微控制器固件的说明。

# 购买地址

本章使用了许多组件，所有这些组件都可以从 Adafruit 在线零售商处购买。

Adafruit CRICKIT for Circuit Playground Express 可以直接从 Adafruit 购买（[`www.adafruit.com/product/3093`](https://www.adafruit.com/product/3093)）。也可以从其他在线零售商购买，如 Pimoroni。

Circuit Playground Bolt-On Kit 可以直接从 Adafruit 购买（[`www.adafruit.com/product/3816`](https://www.adafruit.com/product/3816)）。该套件包括连接两个板所需的六个六角支架和 12 颗螺丝。本章使用的舵机可以直接从 Adafruit 购买（[`www.adafruit.com/product/169`](https://www.adafruit.com/product/169)）。

本章使用的直流电机可以直接从 Adafruit 购买（[`www.adafruit.com/product/3777`](https://www.adafruit.com/product/3777)）。Adafruit 还出售许多可选的轮子附件，但在本章的示例中并不需要。

CRICKIT 可以通过一个三节 AA 电池盒供电，可以直接从 Adafruit 购买（[`www.adafruit.com/product/3842`](https://www.adafruit.com/product/3842)）。与其他电源相比，这种电源的好处在于便携和低成本。

# 调整舵机到正确的脉冲宽度

舵机可以通过发送不同的电脉冲来旋转其臂到特定角度。臂移动到的角度将由电脉冲的宽度控制。在设置这些角度之前，每个舵机必须首先配置正确的最小和最大宽度设置。

本示例将向您展示如何做到这一点。每当您想在项目中使用舵机时，都需要进行此配置。

# 准备工作

您将需要访问 Circuit Playground Express 上的 REPL 来运行本示例中提供的代码。

# 如何做...

让我们重温一下本示例所需的步骤：

1.  在 REPL 中运行以下代码行：

```py
>>> from adafruit_circuitplayground.express import cpx
>>> from adafruit_crickit import crickit
>>> 
>>> MIN_PULSE=750 
>>> MAX_PULSE=2250
```

1.  在这个阶段，我们已经导入了必要的库，并定义了我们想要为这组特定舵机设置的最小和最大脉冲宽度值。以下代码块将使用这些设置配置连接到第一个端口的舵机：

```py
>>> crickit.servo_1.set_pulse_width_range(MIN_PULSE, MAX_PULSE)
```

1.  运行下一块代码将舵机移动到最低角度：

```py
>>> crickit.servo_1.angle = 0
```

1.  以下代码块将将臂移动到中间位置，即最低和最高值之间：

```py
>>> crickit.servo_1.angle = 90
```

1.  在运行下一块代码时，按住手指在触摸板 A1 上：

```py
>>> event.process()
A1 True
```

1.  以下代码应放入`main.py`文件中，当执行时，它将把舵机 1 移动到最低角度 3 秒，然后将其移动到中间范围角度 60 秒：

```py
import time
from adafruit_circuitplayground.express import cpx
from adafruit_crickit import crickit

MIN_PULSE = 750
MAX_PULSE = 2250

crickit.servo_1.set_pulse_width_range(MIN_PULSE, MAX_PULSE)
crickit.servo_1.angle = 0
time.sleep(3)
crickit.servo_1.angle = 90
time.sleep(60)
```

# 工作原理...

`crickit`对象将是我们与连接到电路板的所有舵机和直流电机进行交互的方式。每个舵机连接都有编号，因此您可以通过这个单一对象的属性来控制多个舵机。在将最小和最大脉冲宽度的值保存为常量后，我们通过调用`set_pulse_width_range`将这些设置应用于第一个舵机电机。

然后我们设置第一个舵机的角度属性的值，这将使舵机移动到角度 0。我们通过调用`sleep`方法暂停 3 秒，然后使用相同的角度属性将角度更改为 90。

# 还有更多...

来自不同制造商的舵机电机将期望不同的最小和最大脉冲宽度设置。您通常可以通过查看产品的数据表来找到特定舵机的正确设置。本示例中使用的设置特定于本章开头描述的舵机型号。如果您决定使用不同的舵机组，可以根据需要更改这些设置。用于控制舵机的 Python 库还允许您为每个舵机配置这些设置。这样，您可以通过分别配置每个舵机，同时连接具有不同设置的不同舵机。

脉冲宽度有时以毫秒提供，有时以微秒提供。只需将它们转换为微秒，因为这是这个 Python 模块所期望的单位。本示例中使用的舵机被描述为使用 0.75 毫秒到 2.25 毫秒的脉冲宽度，转换为微秒后变为 750 到 2,250。

# 另请参阅

以下是一些参考资料：

+   有关舵机中发现的组件的概述可在[`developer.wildernesslabs.co/Hardware/Reference/Peripherals/Servos/`](http://developer.wildernesslabs.co/Hardware/Reference/Peripherals/Servos/)找到。

+   有关舵机内部工作原理的解释可在[`www.pc-control.co.uk/servo_control.htm`](https://www.pc-control.co.uk/servo_control.htm)找到。

# 设置舵机的作用范围

舵机的臂在其运动范围上有所不同。对于角度，您在软件中发出请求以正确映射到舵机实际移动的角度；您需要使用其作用范围配置舵机。一旦配置完成，您将能够准确地将连接到舵机的臂移动到其正确位置。这是配置您计划在其中使用舵机的任何项目中的重要步骤。如果不这样做，您将面临一些奇怪的惊喜，其中舵机臂会不断移动到错误的位置。

# 准备工作

您将需要访问 Circuit Playground Express 上的 REPL 来运行本示例中提供的代码。

# 如何做...

让我们重温一下本示例所需的步骤：

1.  在 REPL 中执行下一块代码：

```py
>>> from adafruit_circuitplayground.express import cpx
>>> from adafruit_crickit import crickit
>>> 
>>> MIN_PULSE = 750
>>> MAX_PULSE = 2250
>>> 
>>> crickit.servo_1.set_pulse_width_range(MIN_PULSE, MAX_PULSE)
```

1.  现在已配置了伺服的脉冲宽度。执行以下代码块将伺服移动到最低位置：

```py
>>> crickit.servo_1.angle = 0
```

1.  在运行下一个代码块之前，请记下臂的当前位置。运行下一个代码块将伺服移动到最高角度：

```py
>>> crickit.servo_1.angle = 180
```

1.  测量这两个位置之间的角度。您应该发现角度为 160 度。运行下一个代码块将伺服返回到 0 度角并配置执行范围：

```py
>>> crickit.servo_1.angle = 0
>>> crickit.servo_1.actuation_range = 160
```

1.  运行下一个代码块，软件角度和实际角度应该都是 160 度：

```py
>>> crickit.servo_1.angle = 160
```

1.  以下代码应插入到`main.py`文件中：

```py
import time
from adafruit_circuitplayground.express import cpx
from adafruit_crickit import crickit

MIN_PULSE = 750
MAX_PULSE = 2250

crickit.servo_1.set_pulse_width_range(MIN_PULSE, MAX_PULSE)
crickit.servo_1.angle = 0
time.sleep(3)
crickit.servo_1.actuation_range = 160
crickit.servo_1.angle = 160
time.sleep(60)
```

执行此脚本时，将伺服 1 移动到最低角度 3 秒，然后将其移动到 160 度角度 60 秒。

# 工作原理...

前几行代码将配置伺服的脉冲宽度设置。在将执行范围配置为特定伺服的正确值（160 度）之前，角度将设置为 0，持续 3 秒。配置完成后，当软件中的角度设置为 160 度时，实际运动也应为 160 度。

# 还有更多...

就像脉冲宽度在伺服之间变化一样，运动范围也是如此。大多数伺服不会提供完整的 180 度运动。发现这些设置的一种方法是不配置执行范围，然后在软件中将伺服移动到 0 度和 180 度。

然后，您可以使用量角器来物理测量伺服移动的角度。测量了这个值后，您可以将这个角度作为执行范围的值。以下图片显示了使用量角器测量本章中伺服的最低角度：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mcpy-cb/img/1b83778d-0608-40c5-9646-16e51b8b2edc.png)

放置量角器后，将伺服移动到最高角度。以下图片显示量角器测量角度为 160 度：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mcpy-cb/img/5fd941b7-5863-4341-b671-6722501ab59f.png)

当您想在现实世界中进行准确的角度测量时，量角器是最佳选择。

# 另请参阅

以下是一些参考资料：

+   有关设置执行范围的一些详细信息，请参阅[`learn.adafruit.com/using-servos-with-circuitpython/circuitpython`](https://learn.adafruit.com/using-servos-with-circuitpython/circuitpython)。

+   有关伺服运动范围的讨论，请参阅[`learn.sparkfun.com/tutorials/hobby-servo-tutorial`](https://learn.sparkfun.com/tutorials/hobby-servo-tutorial)。

# 设置伺服的角度

一旦您正确配置了伺服，您将能够将伺服臂移动到精确的角度位置。本教程将移动伺服到多个角度，并展示当您尝试将伺服移动到超出其允许运动范围的角度时会发生什么。

一旦我们有能力将伺服移动到特定角度，我们就可以开始将它们纳入我们的项目中，以控制机械臂或将其他伺服附件移动到特定位置。

# 准备工作

您需要访问 Circuit Playground Express 上的 REPL 才能运行本教程中提供的代码。

# 如何操作...

让我们来看看这个教程所需的步骤：

1.  使用 REPL 运行以下代码行：

```py
>>> from adafruit_circuitplayground.express import cpx
>>> from adafruit_crickit import crickit
>>> 
>>> MIN_PULSE = 750
>>> MAX_PULSE = 2250
>>> 
>>> crickit.servo_1.set_pulse_width_range(MIN_PULSE, MAX_PULSE)
>>> crickit.servo_1.angle = 0
```

1.  现在伺服应该处于最低角度。执行以下代码块将伺服移动到最高位置：

```py
>>> crickit.servo_1.angle = 180
```

1.  运行以下代码以查看当您超出最大角度范围时会发生什么：

```py
>>> crickit.servo_1.angle = 190
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
  File "adafruit_motor/servo.py", line 111, in angle
ValueError: Angle out of range
```

1.  运行以下代码块将伺服返回到 0 度角并将执行范围配置为 160 度：

```py
>>> crickit.servo_1.angle = 0
>>> crickit.servo_1.actuation_range = 160
```

1.  运行以下代码块，查看 180 度现在被认为是伺服的范围之外的角度：

```py
>>> crickit.servo_1.angle = 180
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
  File "adafruit_motor/servo.py", line 111, in angle
ValueError: Angle out of range
```

1.  运行以下代码块，伺服应该移动到最高角度：

```py
>>> crickit.servo_1.angle = 160
```

1.  以下代码应放入`main.py`文件中，执行时将伺服移动到 0、45、90 和 160 度的角度，每次移动之间有 3 秒的延迟：

```py
import time
from adafruit_circuitplayground.express import cpx
from adafruit_crickit import crickit

MIN_PULSE = 750
MAX_PULSE = 2250

crickit.servo_1.set_pulse_width_range(MIN_PULSE, MAX_PULSE)
crickit.servo_1.angle = 0
crickit.servo_1.actuation_range = 160

crickit.servo_1.angle = 0
time.sleep(3)

crickit.servo_1.angle = 45
time.sleep(3)

crickit.servo_1.angle = 90
time.sleep(3)

crickit.servo_1.angle = 160
time.sleep(3)
```

# 工作原理...

代码的前几行将配置舵机的脉冲宽度设置和作用范围。然后，将在舵机上设置 4 个不同的角度。这些角度分别是 0、45、90 和 160 度。在设置每个角度之后，通过调用时间模块上的`sleep`函数应用 3 秒的延迟。

# 还有更多...

在这个示例中，我们试验了在配置作用范围之前和之后尝试设置舵机角度时会发生什么。作用范围的默认设置是 180 度。这就是为什么在所有情况下，190 度的值都会被拒绝。一旦我们将作用范围配置为 160，诸如 180 的值当然会被拒绝，因为它们超出了这个范围。

舵机库具有这些检查非常有帮助，因为如果不执行这些检查，设置舵机角度超出正确范围的软件应用程序中的错误可能会损坏您的舵机。此外，通过使用清晰的异常消息抛出`ValueError`异常，使得更容易调试这些错误的应用程序。

# 另请参阅

以下是一些参考资料：

+   可以在[`learn.adafruit.com/crickit-powered-owl-robot`](https://learn.adafruit.com/crickit-powered-owl-robot)找到使用 CRICKIT 控制舵机角度的项目。

+   有关使用舵机和 CircuitPython 创建运动的示例，请访问[`learn.adafruit.com/hello-world-of-robotics-with-crickit`](https://learn.adafruit.com/hello-world-of-robotics-with-crickit)。

# 扫描舵机

在这个示例中，您将学习如何创建一个脚本，不断地将舵机从最低角度移动到最高角度，然后再次返回，以扫描运动。在某些方面，这段代码类似于我们在前几章中看到的灯光动画，因为我们将改变板的输出，并在每次改变之间设置时间延迟，以创建动画视觉效果。

然而，在舵机的情况下，动画效果将出现在连接的臂上，呈扫描运动。本示例中使用的方法可以适应任何想要一些舵机附件不断从一个位置扫到另一个位置的项目。

# 准备工作

您将需要访问 Circuit Playground Express 上的 REPL 来运行本示例中提供的代码。

# 如何操作...

让我们来看看这个示例所需的步骤：

1.  在 REPL 中运行以下代码：

```py
>>> import time
>>> from adafruit_circuitplayground.express import cpx
>>> from adafruit_crickit import crickit
>>> 
>>> MIN_PULSE = 750
>>> MAX_PULSE = 2250
>>> MAX_ANGLE = 160
>>> STEP = 10
>>> DELAY = 0.1
```

1.  在这个阶段，应该导入所需的 Python 库，并将不同的设置定义为我们脚本的常量。执行以下代码块来初始化舵机并将其移动到最低位置：

```py
>>> def init(servo):
...     servo.set_pulse_width_range(MIN_PULSE, MAX_PULSE)
...     servo.angle = 0
...     servo.actuation_range = MAX_ANGLE
...     
...     
... 
>>> init(crickit.servo_1)
```

1.  运行以下代码，将舵机从角度`0`扫到`160`：

```py
>>> def sweep(servo, direction):
...     angle = int(servo.angle)
...     while 0 <= angle <= MAX_ANGLE:
...         print(angle)
...         servo.angle = angle
...         time.sleep(DELAY)
...         angle += STEP * direction
...         
... 
>>> sweep(crickit.servo_1, 1)
0
10
20
30
40
50
60
70
80
90
100
110
120
130
140
150
160
```

1.  运行以下代码，将舵机从角度`160`扫到`0`：

```py
>>> sweep(crickit.servo_1, -1)
160
150
140
130
120
110
100
90
80
70
60
50
40
30
20
10
0
```

1.  以下代码应该插入到`main.py`文件中，当执行时，它将不断地将电机从角度`0`扫到`160`，然后返回到`0`：

```py
import time
from adafruit_circuitplayground.express import cpx
from adafruit_crickit import crickit

MIN_PULSE = 750
MAX_PULSE = 2250
MAX_ANGLE = 160
STEP = 10
DELAY = 0.1

def init(servo):
    servo.set_pulse_width_range(MIN_PULSE, MAX_PULSE)
    servo.angle = 0
    servo.actuation_range = MAX_ANGLE

def sweep(servo, direction):
    angle = int(servo.angle)
    while 0 <= angle <= MAX_ANGLE:
        print(angle)
        servo.angle = angle
        time.sleep(DELAY)
        angle += STEP * direction

def main():
    init(crickit.servo_1)
    while True:
        sweep(crickit.servo_1, 1)
        sweep(crickit.servo_1, -1)

main()
```

# 工作原理...

首先，定义了一个名为`init`的函数，它期望将要初始化的舵机的名称作为其第一个参数。当调用此函数时，它将设置最小和最大脉冲宽度，将角度设置为 0，并设置作用范围。接下来，定义了一个名为`sweep`的函数。这个函数期望第一个参数是要控制的舵机，第二个参数是一个带有值`1`或`-1`的整数，表示扫描的方向。

值为`1`将使角度增加，而值为`-1`将使角度减少。sweep 函数的第一部分将检索舵机角度的当前值并将其强制转换为整数并存储在名为`angle`的变量中。然后启动一个循环，直到角度的值超出了 0 到 160 的允许范围。在循环的每次迭代中，都会打印当前角度，然后将角度应用于舵机，然后应用延迟；然后，角度将按照定义的步长值进行更改。

然后定义了`main`函数，当调用时，将初始化舵机并将其移动到角度 0。然后，启动一个无限循环，在每次循环迭代期间执行两个操作。首先调用`sweep`函数来增加角度从 0 到 160。然后再次调用`sweep`函数，但这次是将角度从 160 减少到 0。

# 还有更多...

在`init`和`sweep`函数中尽可能不要硬编码任何值。大多数值都作为可配置的常量设置在脚本顶部，或者作为函数调用时接收的参数。这将使得调整脚本以适应其他设置的舵机变得更加容易。您还可以通过增加和降低这些常量中的值来轻松改变每次`sweep`迭代中角度变化的量以及完成扫描的速度。

该程序还被分成了 3 个不同的函数，以提高可读性并鼓励将不同的代码块重用到其他项目中。Python 编程语言的一个有趣且相对独特的特性是能够链式比较操作，这在 MicroPython 和 CircuitPython 版本中得到了充分支持。这个特性在`sweep`函数中用于检查角度是否在 0 到 160 之间。

在其他语言中，您通常需要使用`and`运算符结合两个比较运算符来表达这一点。然而，在 Python 中，您可以简单地链式比较运算符以更简洁和可读的方式实现相同的结果。

# 另请参阅

以下是一些参考资料：

+   描述如何链式比较的文档可以在[`docs.python.org/3/reference/expressions.html#comparisons`](https://docs.python.org/3/reference/expressions.html#comparisons)找到。

+   CRICKIT 库的文档可以在[`circuitpython.readthedocs.io/projects/crickit/en/latest/`](https://circuitpython.readthedocs.io/projects/crickit/en/latest/)找到。

# 使用按钮控制舵机

在这个食谱中，您将学习如何使用 Circuit Playground Express 上的两个按钮来控制舵机的角度。本食谱中的脚本将在按下按钮 A 时增加舵机角度，并在按下按钮 B 时减少角度。每当您想要创建一个项目，让人们可以直接使用不同的输入控件（如按钮）来控制舵机时，这些类型的脚本都非常有用。

# 准备工作

您需要访问 Circuit Playground Express 上的 REPL 来运行本食谱中提供的代码。

# 操作步骤...

让我们来看看这个食谱所需的步骤：

1.  在 REPL 中执行以下代码块：

```py
>>> import time
>>> from adafruit_circuitplayground.express import cpx
>>> from adafruit_crickit import crickit
>>> 
>>> MIN_PULSE = 750
>>> MAX_PULSE = 2250
>>> MAX_ANGLE = 160
>>> STEP = 10
>>> DELAY = 0.1
```

1.  初始导入已完成，我们准备定义我们的函数。以下代码块将定义并调用一个初始化舵机的函数：

```py
>>> def init(servo):
...     servo.set_pulse_width_range(MIN_PULSE, MAX_PULSE)
...     servo.angle = 0
...     servo.actuation_range = MAX_ANGLE
...     
...     
... 
>>> init(crickit.servo_1)
```

1.  运行以下代码将舵机移动 10 度并检查角度的值：

```py
>>> def move(servo, angle, direction):
...     new = angle + STEP * direction
...     if 0 <= new <= MAX_ANGLE:
...         angle = new
...         print(angle)
...         servo.angle = angle
...     return angle
...     
... 
>>> angle = 0
>>> angle = move(crickit.servo_1, angle, 1)
10
>>> angle
10
```

1.  运行以下代码再次移动舵机，增加 10 度：

```py
>>> angle = move(crickit.servo_1, angle, 1)
20
```

1.  运行以下代码将减少舵机的角度 10 度：

```py
>>> angle = move(crickit.servo_1, angle, -1)
10
```

1.  以下代码应插入到`main.py`文件中：

```py
import time
from adafruit_circuitplayground.express import cpx
from adafruit_crickit import crickit

MIN_PULSE = 750
MAX_PULSE = 2250
MAX_ANGLE = 160
STEP = 10
DELAY = 0.1

def init(servo):
    servo.set_pulse_width_range(MIN_PULSE, MAX_PULSE)
    servo.angle = 0
    servo.actuation_range = MAX_ANGLE

def move(servo, angle, direction):
    new = angle + STEP * direction
    if 0 <= new <= MAX_ANGLE:
        angle = new
        print(angle)
        servo.angle = angle
    return angle

def main():
    init(crickit.servo_1)
    angle = 0
    while True:
        if cpx.button_a:
            angle = move(crickit.servo_1, angle, 1)
        if cpx.button_b:
            angle = move(crickit.servo_1, angle, -1)
        time.sleep(DELAY)

main()
```

一旦执行，该脚本将在按下按钮 A 和 B 时每次将舵机移动到较低或较高的角度。

# 工作原理...

在定义全局常量和舵机初始化函数之后，我们继续定义另外两个函数。`move`函数接受舵机、当前角度和移动方向作为其三个参数。然后根据当前角度步进量和移动方向计算预期的新角度。如果这个新角度在可接受的角度范围内，则打印其值并应用于`servo`和`angle`变量。最后，返回`angle`变量的值。

在脚本底部定义并调用的`main`函数实现了主事件循环。在初始化`servo`变量并将`angle`变量设置为`0`之后，开始了一个无限循环。在循环的每次迭代中，如果按下按钮 A，则将调用`move`函数来增加舵机角度。然后，检查按钮 B，如果按下，则调用`move`函数来减小舵机角度。最后，在此循环的每次迭代结束时应用`sleep`函数。

# 还有更多...

这个基本的事件循环允许我们通过将舵机移动到不同的方向来对用户输入做出反应。我们可以在许多方向上扩展此脚本的逻辑。例如，我们可以将步进角从 10 减少到 1，以便非常精细地控制舵机，并每次改变一个度的角度。我们还可以减少延迟以加快对每次按钮按下的反应运动。我们可以拿基本脚本并添加控制像素的代码，除了舵机角度，当您按下每个按钮时。

# 另请参阅

以下是一些参考资料：

+   可以在[`learn.adafruit.com/universal-marionette-with-crickit`](https://learn.adafruit.com/universal-marionette-with-crickit)找到使用按钮控制舵机的项目。

+   `servo`对象的源代码可以在[`github.com/adafruit/Adafruit_Circuitpython_Motor`](https://github.com/adafruit/Adafruit_Circuitpython_Motor)找到。

# 控制多个舵机

在这个食谱中，您将学习如何结合使用按钮和滑动开关来控制多个舵机。基本上，我们将使用按钮来控制特定舵机的角度。然后，我们将使用滑动开关来选择我们想要控制的两个连接舵机中的哪一个。

这个食谱建立在一些过去的食谱基础上，增加了额外的数据结构和控制，以管理控制多个舵机所需的额外逻辑。每当您需要找到控制多个舵机的方法时，这个食谱将非常有用。

# 准备工作

您需要访问 Circuit Playground Express 上的 REPL 来运行此食谱中呈现的代码。

# 如何做...

让我们来看看这个食谱所需的步骤：

1.  使用 REPL 运行以下代码行：

```py
>>> import time
>>> from adafruit_circuitplayground.express import cpx
>>> from adafruit_crickit import crickit
>>> 
>>> MIN_PULSE = 750
>>> MAX_PULSE = 2250
>>> MAX_ANGLE = 160
>>> STEP = 10
>>> DELAY = 0.1
>>> 
>>> def init(servo):
...     servo.set_pulse_width_range(MIN_PULSE, MAX_PULSE)
...     servo.angle = 0
...     servo.actuation_range = MAX_ANGLE
...     
...     
... 
>>> 
```

1.  初始导入已完成，并且我们已经定义了`init`函数来帮助初始化舵机。以下代码块将设置一些数据结构，用于跟踪我们的角度和舵机：

```py
>>> servos = [crickit.servo_1, crickit.servo_4]
>>> angles = [0, 0]
```

1.  以下代码块将初始化我们舵机列表中的所有舵机：

```py
>>> init(servos[0])
>>> init(servos[1])
```

1.  运行以下代码以根据滑动开关位置设置开关变量：

```py
>>> switch = int(cpx.switch)
>>> switch
0
```

1.  运行以下代码以将所选舵机移动 10 度：

```py
>>> def move(servo, angle, direction):
...     new = angle + STEP * direction
...     if 0 <= new <= MAX_ANGLE:
...         angle = new
...         print(angle)
...         servo.angle = angle
...     return angle
...     
...     
... 
>>> angles[switch] = move(servos[switch], angles[switch], 1)
10
```

1.  运行以下代码以检查调用`move`函数之前和之后的角度数据结构：

```py
>>> angle = move(crickit.servo_1, angle, 1)
>>> angles
[10, 0]
>>> angles[switch] = move(servos[switch], angles[switch], 1)
20
>>> angles
[20, 0]
```

1.  更改滑动开关位置并运行以下代码块以更新所选舵机：

```py
>>> switch = int(cpx.switch)
>>> switch
1
```

1.  运行以下代码块以查看调用`move`函数如何移动另一个舵机：

```py
>>> angles[switch] = move(servos[switch], angles[switch], 1)
10
>>> angles
[20, 10]
```

1.  以下代码应插入到`main.py`文件中：

```py
import time
from adafruit_circuitplayground.express import cpx
from adafruit_crickit import crickit

MIN_PULSE = 750
MAX_PULSE = 2250
MAX_ANGLE = 160
STEP = 10
DELAY = 0.1

def init(servo):
    servo.set_pulse_width_range(MIN_PULSE, MAX_PULSE)
    servo.angle = 0
    servo.actuation_range = MAX_ANGLE

def move(servo, angle, direction):
    new = angle + STEP * direction
    if 0 <= new <= MAX_ANGLE:
        angle = new
        print(angle)
        servo.angle = angle
    return angle

def main():
    servos = [crickit.servo_1, crickit.servo_4]
    angles = [0, 0]
    init(servos[0])
    init(servos[1])
    while True:
        switch = int(cpx.switch)
        if cpx.button_a:
            angles[switch] = move(servos[switch], angles[switch], 1)
        if cpx.button_b:
            angles[switch] = move(servos[switch], angles[switch], -1)
        time.sleep(DELAY)

main()
```

执行此脚本将移动不同的舵机，具体取决于滑动开关的位置和按钮的按压。

# 它是如何工作的...

在定义全局常量和舵机初始化函数之后，我们将继续定义另外两个函数。`move`函数遵循了您在上一个示例中看到的相同结构。但是，`main`函数已扩展为具有处理多个舵机和滑动开关的附加数据结构和逻辑。

在`main`函数中，创建了一个名为`servos`的列表，指向要控制的两个舵机。一个名为`angles`的列表将跟踪每个舵机的角度。然后初始化每个舵机，然后进入无限循环。

在每次循环迭代期间，开关的值将从布尔值转换为整数值 0 或 1。这将允许我们在两个舵机之间切换控制。然后，根据按下按钮 A 还是 B，将调用`move`函数，并提供正确的`servo`对象和角度。最后，在每个循环结束时应用`sleep`。

# 还有更多...

在这个示例中，我们已经以一种使与板交互成为自然过程的方式将三个输入控件和两个输出舵机组合在一起。部分原因是不同的物理输入控件适合映射到不同的逻辑控件。

滑动开关非常适合在两个选项之间切换，因此在选择两个舵机时使用滑动开关是合理的。当您希望通过重复按按钮来重复增加或减少值时，按钮可以很好地工作。

# 另请参阅

以下是一些参考资料：

+   可以在[`learn.adafruit.com/circuitpython-made-easy-on-circuit-playground-express/slide-switch`](https://learn.adafruit.com/circuitpython-made-easy-on-circuit-playground-express/slide-switch)找到与滑动开关交互的示例。

+   可以在[`www.adafruit.com/category/972`](https://www.adafruit.com/category/972)找到一些与 Adafruit CRICKIT 相关的组件。

# 打开直流电机

在这个示例中，您将学习如何使用 Circuit Playground Express 和 CRICKIT 板控制直流电机。与舵机相比，直流电机更容易交互，因为它们不需要任何初始配置。这个示例将为您提供打开和关闭直流电机所需的基本技能。

# 准备工作

您需要访问 Circuit Playground Express 上的 REPL 来运行本示例中提供的代码。

# 如何做...

让我们来看看完成此示例所需的步骤：

1.  在 REPL 中运行以下代码行：

```py
>>> from adafruit_crickit import crickit
>>> import time
>>> 
>>> crickit.dc_motor_1.throttle = 1
```

1.  连接到板上的直流电机现在应该以全速旋转。运行以下代码块以停止直流电机的旋转：

```py
>>> crickit.dc_motor_1.throttle = 0
```

1.  以下代码块将停止并启动电机，并延迟一秒：

```py
>>> while True:
...     crickit.dc_motor_1.throttle = 1
...     time.sleep(1)
...     crickit.dc_motor_1.throttle = 0
...     time.sleep(1)
...     
...     
... 
```

1.  以下代码应插入到`main.py`文件中：

```py
from adafruit_crickit import crickit
import time

while True:
    crickit.dc_motor_1.throttle = 1
    time.sleep(1)
    crickit.dc_motor_1.throttle = 0
    time.sleep(1)
```

当执行此脚本时，将启动一个无限循环，不断启动和停止电机。

# 它是如何工作的...

直流电机与舵机不同，因此，它们需要更少的代码和交互来使它们运动。在库导入之后，将启动一个无限循环。

在循环的第一行，访问了`crickit`对象上的`dc_motor_1`属性。这个对象将让我们与连接到板上第一个电机连接的任何直流电机进行交互。`dc_motor_1`公开了一个名为`throttle`的属性，我们可以用它来打开和关闭电机。如果我们将值设置为`1`，电机就会启动，值为`0`则关闭电机。

因此，首先将油门设置为`1`以打开电机；然后应用`1`秒的延迟，然后关闭电机，并再次应用`1`秒的延迟。然后循环重新开始，重复这个过程。

# 还有更多...

直流电机在许多方面与舵机不同，正如本教程所示。它们确实比舵机更容易入门，因为它们不需要任何初始配置。然而，相反，它们不提供对您想要将电机放置在的确切位置的精确控制。

当然，直流电机能够做到舵机无法做到的事情，比如完全 360 度的旋转运动。

# 另请参阅

以下是一些参考资料：

+   可以在[`learn.adafruit.com/adafruit-crickit-creative-robotic-interactive-construction-kit/circuitpython-dc-motors`](https://learn.adafruit.com/adafruit-crickit-creative-robotic-interactive-construction-kit/circuitpython-dc-motors)找到使用 CRICKIT 板与直流电机的文档。

+   可以在[`learn.adafruit.com/adafruit-crickit-creative-robotic-interactive-construction-kit/recommended-chassis`](https://learn.adafruit.com/adafruit-crickit-creative-robotic-interactive-construction-kit/recommended-chassis)找到可用于安装直流电机的底盘。

# 设置直流电机的速度和方向

在本教程中，您将学习如何控制特定直流电机的速度和旋转方向。您将看到，向油门提供正值或负值将让我们控制电机是顺时针还是逆时针旋转。我们还可以向油门提供小数值，以控制电机的运行功率。

当您使用直流电机控制 MicroPython 驱动的计算机控制车辆上的车轮时，本教程中的技术将非常有用。它们将让您加速或减速汽车。您还可以使用它们使汽车倒车或完全停止。

# 准备工作

您需要访问 Circuit Playground Express 上的 REPL，以运行本教程中提供的代码。

# 如何做....

让我们来看看这个教程所需的步骤：

1.  在 REPL 中执行以下代码块：

```py
>>> from adafruit_crickit import crickit
>>> import time
>>> DELAY = 0.1
>>> 
>>> crickit.dc_motor_1.throttle = 0.5
```

1.  直流电机现在将以其全速的 50%运行。以下代码将以其全速的四分之一运行电机：

```py
>>> crickit.dc_motor_1.throttle = 0.25
```

1.  以下代码块将以全速将电机移动到相反的方向：

```py
>>> crickit.dc_motor_1.throttle = -1
```

1.  运行以下代码块以停止电机：

```py
>>> crickit.dc_motor_1.throttle = 0
```

1.  执行以下代码块时，将定义并调用一个函数，该函数将改变电机的速度和方向，从一个方向到相反的方向：

```py
>>> from adafruit_crickit import crickit
>>> def change_throttle(motor, start, increment):
...     throttle = start
...     for i in range(21):
...         print(throttle)
...         motor.throttle = throttle
...         throttle += increment
...         throttle = round(throttle, 1)
...         time.sleep(DELAY)
...         
... 
>>> change_throttle(crickit.dc_motor_1, -1.0, 0.1)
-1.0
-0.9
-0.8
-0.7
-0.6
-0.5
-0.4
-0.3
-0.2
-0.1
0.0
0.1
0.2
0.3
0.4
0.5
0.6
0.7
0.8
0.9
1.0
>>> 
```

1.  以下代码应插入到`main.py`文件中：

```py
from adafruit_crickit import crickit
import time

DELAY = 0.1

def change_throttle(motor, start, increment):
    throttle = start
    for i in range(21):
        print(throttle)
        motor.throttle = throttle
        throttle += increment
        throttle = round(throttle, 1)
        time.sleep(DELAY)

def main():
    while True:
        change_throttle(crickit.dc_motor_1, -1.0, 0.1)
        change_throttle(crickit.dc_motor_1, 1.0, -0.1)

main()
```

执行此脚本将使电机一次又一次地从一个方向移动到另一个方向。

# 工作原理...

定义了`change_throttle`函数，它将在本教程中执行大部分工作。它期望接收要控制的电机、油门的起始值，最后是每次迭代期间油门应该改变的量。该函数将初始化`throttle`变量为指定的起始值。

然后，将启动一个`for`循环，该循环将从油门的最低值到最高值。它首先打印当前油门，然后将`throttle`变量的值应用于电机。然后将油门增加并四舍五入到小数点后一位。然后应用延迟，然后进行下一次迭代。

`main`函数将进入一个无限循环，每次迭代调用`change_throttle`函数两次。第一次调用将油门值从`-1.0`移动到`1.0`，以`0.1`的增量。第二次调用将油门值从`1.0`移动到`-1.0`，以`-0.1`的增量。

# 还有更多...

此教程可用于演示以不同速度和不同方向运行电机。它创建了一个几乎可视化的动画，您可以看到电机减速和加速。您可以看到它们以一个方向以最大速度运行，然后减速以在另一个方向以最大速度运行。

有各种各样的创意实验可以扩展这个功能。例如，你可以将两个车轮连接到直流电机上，使其像遥控汽车一样移动。你可以配置光传感器以对手电筒做出反应。

或者，你可以将其他东西连接到直流电机上，根据一定的时间表转动。你可以控制电机启动的时间，使用这个配方中使用的时间模块。

# 另请参阅

以下是一些参考资料：

+   可以在[`learn.adafruit.com/adafruit-crickit-creative-robotic-interactive-construction-kit/bubble-bot`](https://learn.adafruit.com/adafruit-crickit-creative-robotic-interactive-construction-kit/bubble-bot)找到一个使用 CRICKIT 板和舵机和直流电机的项目。

+   有关如何使用 CRICKIT 板连接和控制直流电机的详细信息，请访问[`learn.adafruit.com/make-it-move-with-crickit/use-a-continuous-dc-motor-now`](https://learn.adafruit.com/make-it-move-with-crickit/use-a-continuous-dc-motor-now)。

# 使用按钮控制直流电机

在这个配方中，我们将使用按钮来增加和减少直流电机的速度。我们可以使用相同的脚本来使用按钮改变旋转方向。基本上，一个按钮会使电机在一个方向上增加速度，另一个按钮会使电机在另一个方向上移动更多。这样，我们可以使用一对按钮来设置任一方向的一系列速度，并将电机完全停止。

当脚本运行时，当前速度和方向将打印到屏幕上。这个配方可以在任何需要将用户输入转换为运动的项目中有用。例如，你可以创建一个项目，将滑轮连接到直流电机上，并使用按钮来提升和降低滑轮。

# 准备工作

你需要访问 Circuit Playground Express 上的 REPL 来运行本配方中提供的代码。

# 如何操作...

让我们来看看这个配方所需的步骤：

1.  使用 REPL 运行以下代码行：

```py
>>> from adafruit_crickit import crickit
>>> from adafruit_circuitplayground.express import cpx
>>> import time
>>> 
>>> STEP = 0.1
>>> DELAY = 0.1
>>> MIN_THROTTLE = -1
>>> MAX_THROTTLE = 1
>>> 
>>> throttle = 0
>>> crickit.dc_motor_1.throttle = throttle
```

1.  直流电机速度设置为`0`油门。以下代码块将定义一个`move`函数，并调用它三次，参数是将速度增加到 30%强度：

```py
>>> def move(motor, throttle, direction):
...     new = throttle + STEP * direction
...     if MIN_THROTTLE <= new <= MAX_THROTTLE:
...         throttle = round(new, 1)
...         print(throttle)
...         motor.throttle = throttle
...     return throttle
...     
...     
... 
>>> throttle = move(crickit.dc_motor_1, throttle, 1)
0.1
>>> throttle = move(crickit.dc_motor_1, throttle, 1)
0.2
>>> throttle = move(crickit.dc_motor_1, throttle, 1)
0.3
```

1.  以下代码块将调用`move`函数三次，以减速直到电机完全停止：

```py
>>> throttle = move(crickit.dc_motor_1, throttle, -1)
0.2
>>> throttle = move(crickit.dc_motor_1, throttle, -1)
0.1
>>> throttle = move(crickit.dc_motor_1, throttle, -1)
0.0
```

1.  以下代码块将调用`move`函数三次，以负方向移动，将电机设置为 30%的强度，朝相反方向：

```py
>>> throttle = move(crickit.dc_motor_1, throttle, -1)
-0.1
>>> throttle = move(crickit.dc_motor_1, throttle, -1)
-0.2
>>> throttle = move(crickit.dc_motor_1, throttle, -1)
-0.3
```

1.  以下代码块将调用`move`函数三次，以一个方向将电机从相反方向减速到完全停止：

```py
>>> throttle = move(crickit.dc_motor_1, throttle, 1)
-0.2
>>> throttle = move(crickit.dc_motor_1, throttle, 1)
-0.1
>>> throttle = move(crickit.dc_motor_1, throttle, 1)
0.0
```

1.  以下代码应该插入到`main.py`文件中，当执行时，它将根据按下按钮的次数将电机从一个方向移动到另一个方向：

```py
from adafruit_crickit import crickit
from adafruit_circuitplayground.express import cpx
import time

STEP = 0.1
DELAY = 0.1
MIN_THROTTLE = -1
MAX_THROTTLE = 1

def move(motor, throttle, direction):
    new = throttle + STEP * direction
    if MIN_THROTTLE <= new <= MAX_THROTTLE:
        throttle = round(new, 1)
        print(throttle)
        motor.throttle = throttle
    return throttle

def main():
    throttle = 0
    while True:
        if cpx.button_a:
            throttle = move(crickit.dc_motor_1, throttle, 1)
        if cpx.button_b:
            throttle = move(crickit.dc_motor_1, throttle, -1)
        time.sleep(DELAY)

main()
```

# 工作原理...

`move`函数被定义为控制电机运动方向的变化。它可以被调用来增加或减少特定旋转方向上的运动。该函数接受电机对象、当前油门和期望的运动方向。新的油门值被计算出来，如果发现在电机的可接受范围内，该值将被打印并应用于电机。

然后返回油门的最新值，以便主事件循环可以跟踪它。`main`函数包含一个无限循环，充当主事件循环。在这个循环中，按下按钮 A 会增加电机在一个方向上的速度，按下按钮 B 会增加电机在另一个方向上的速度。

# 还有更多...

这个教程提供了使用直流电机接收用户输入并生成输出的基本构建模块。您可以以类似的方式扩展此教程，以便滑动开关可以让您使用相同的脚本控制多个直流电机。

您可以在脚本中更改步进值，以使电机更快地改变速度和方向。或者，也许您想减少步进值，以便更精细地控制速度，但需要额外的按钮按下成本。

# 另请参阅

以下是一些参考资料：

+   与本章中使用的直流电机兼容的电机滑轮可在[`www.adafruit.com/product/3789`](https://www.adafruit.com/product/3789)找到。

+   使用 CRICKIT 板和直流电机控制滑轮的项目可在[`learn.adafruit.com/adafruit-crickit-creative-robotic-interactive-construction-kit/marble-madness`](https://learn.adafruit.com/adafruit-crickit-creative-robotic-interactive-construction-kit/marble-madness)找到。


# 第九章：在 micro:bit 上编码

在本章中，我们将介绍 micro:bit 微控制器。我们将探索其特点及与其他微控制器相比的优势。到本章结束时，您将学会如何在这个微控制器上加载您的代码，控制其 LED 网格显示，并与板上的按钮进行交互。本章以一个不错的项目结束，让您可以使用这个硬件创建一个倒计时器。每个 MicroPython 板都有其自身的优势，了解目前市面上的产品是很有好处的，这样您就可以为您的项目选择合适的硬件。

在本章中，我们将涵盖以下主题：

+   使用 Mu 将代码闪存到 micro:bit

+   使用 Mu 在 micro:bit 上获取 REPL

+   在 LED 显示屏上显示单个字符

+   显示内置图像

+   显示滚动文本

+   显示已按下的按钮

+   创建倒计时器

# 技术要求

本章的代码文件可以在本书的 GitHub 存储库的`Chapter09`文件夹中找到，网址为[`github.com/PacktPublishing/MicroPython-Cookbook`](https://github.com/PacktPublishing/MicroPython-Cookbook)。

您将需要 BBC micro:bit 板和 Mu 文本编辑器来完成本章的示例。

# micro:bit

Micro Bit 是由**英国广播公司**（**BBC**）创建的一块可以用于英国教育目的的板子。它大约是信用卡的一半大小，并且内置了许多输入和输出传感器，考虑到其大小，这令人惊讶。它既有加速度计又有磁力计。它有两个按钮和一个复位按钮。有一个 5 x 5 的 LED 阵列，可以作为基本显示来显示不同的符号和字符。以下照片展示了这块板子的样子：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mcpy-cb/img/e9ef093d-41ba-417b-8baf-d900e073a2d8.png)

该板支持使用外部电池盒和 AAA 电池进行便携式电源供应。使用 USB 连接将板子连接到计算机，以便传输脚本并运行 REPL。

# 使用 Mu 将代码闪存到 micro:bit

本示例将向您展示如何将 Python 脚本闪存到 micro:bit。Mu 文本编辑器内置支持将代码闪存到这种类型的板子，本示例将带您完成这个过程。一旦我们理解了这一点，就可以用它来开发并加载我们需要的脚本到 micro:bit 板上。这是您想要创建项目并尝试 micro:bit 时的必要第一步。

# 准备工作

您需要安装 Mu 文本编辑器才能完成此操作。请按照第一章中关于安装 Mu 文本编辑器的说明进行操作，*使用 MicroPython 入门*。

# 操作步骤...

按照以下步骤学习如何使用 Mu 将代码闪存到 micro:bit：

1.  使用 USB 电缆将 micro:bit 连接到计算机。

1.  启动 Mu 文本编辑器应用程序。

1.  单击应用程序最左侧的 Mode 按钮，以打开以下对话框：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mcpy-cb/img/9feb119a-12eb-4f33-a864-3e3b2b95f9a5.png)

1.  选择 BBC micro:bit 选项，然后按 OK。

1.  将以下代码块放入主文本编辑器窗口：

```py
from microbit import display
display.show('x')
```

1.  按工具栏上的闪存按钮，将代码闪存到板子上。以下屏幕截图中已突出显示了闪存按钮以供参考：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mcpy-cb/img/81316c08-09e2-4b52-a12a-0aad1c6e484c.png)

1.  如果您查看板子上的 LED 网格，现在应该显示`x`字符。

# 工作原理...

与 Circuit Playground Express 相比，micro:bit 采用了不同的加载代码到板上的方法。该板需要您使用特定的软件来理解如何将您的 Python 脚本闪存到这些类型的板上。Mu 文本编辑器完全支持这个 MicroPython 板。最初的步骤是需要配置 Mu，以便它预期与连接的 micro:bit 板进行交互。创建的脚本是一个简单的脚本，它从 micro:bit Python 库中导入显示对象，并使用它在 LED 显示器上显示`x`字符。

# 还有更多...

在将代码闪存到 micro:bit 上时，最简单的程序是 Mu 文本编辑器。还有其他选项可用，比如一个名为 uFlash 的命令行程序。使用命令行方法的价值在于它可以让您灵活地使用您选择的文本编辑器，以便在准备使用 uFlash 实用程序时编辑代码并将其闪存。

# 参见

以下是有关此配方的一些参考资料：

+   有关 uFlash 命令的文档可以在[`uflash.readthedocs.io/en/latest/`](https://uflash.readthedocs.io/en/latest/)找到。

+   有关在将代码闪存到板上时使用的 HEX 文件格式的详细信息可以在[`tech.microbit.org/software/hex-format/`](https://tech.microbit.org/software/hex-format/)找到。

# 使用 Mu 在 micro:bit 上获取 REPL

此配方将建立在我们在上一个配方中介绍的方法之上。就像加载脚本到板上一样重要，当调试脚本时，REPL 也是必不可少的。REPL 将为您提供一个更丰富的界面，当您尝试使用板或尝试弄清楚代码有什么问题时。在 REPL 中，您可以获取回溯信息并查看打印语句的输出。

# 准备工作

您需要安装和配置 Mu 文本编辑器，并将您的 micro:bit 板连接到计算机上。

# 如何操作...

按照以下步骤学习如何使用 mu 在 micro:bit 上获取 REPL：

1.  启动 Mu 文本编辑器应用程序。

1.  单击工具栏中突出显示的 REPL 按钮，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mcpy-cb/img/ddea152f-5611-479c-b581-ac9a53ff6324.png)

1.  REPL 界面现在应该出现在屏幕的下半部分，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mcpy-cb/img/57f8e521-8bd4-450e-a57e-9cc6f0786d80.png)

1.  在 REPL 中运行以下代码行：

```py
>>> 1+1
2
```

1.  运行以下代码块：

```py
>>> import microbit
>>> microbit
<module 'microbit'>
```

`microbit`库现在已被导入。

# 工作原理...

Mu 文本编辑器为许多板提供了内置的 REPL 支持，包括 micro:bit。当您单击 REPL 按钮时，编辑器会尝试打开与板的串行连接。如果成功，它将在板上启动一个 REPL 会话。

在 REPL 中打印出的初始文本显示了板上正在使用的 MicroPython 解释器的版本。此时，您在 REPL 提示符中键入的任何命令都将通过串行连接发送到板上进行评估。然后，它们的输出将返回到计算机上显示在 REPL 屏幕上。

# 还有更多...

MicroPython REPL 带有许多有用的函数，帮助您探索板上可用的不同 Python 模块和对象。您可以在不同的模块和对象上调用`help`函数以获取有关它们的详细信息。当您探索特定对象并想要了解该对象上可用的属性和方法时，您可以使用`dir`函数在 REPL 会话中列出它们。

# 参见

以下是有关此配方的一些参考资料：

+   `help`函数的文档可以在[`docs.python.org/3/library/functions.html#help`](https://docs.python.org/3/library/functions.html#help)找到。

+   `dir`函数的文档可以在[`docs.python.org/3/library/functions.html#dir`](https://docs.python.org/3/library/functions.html#dir)找到。

# 在 LED 显示器上显示单个字符

这个食谱将向您展示如何使用板上的 5 x 5 LED 阵列来显示字符和数字。显示对象有一个`show`方法，可以将字符和数字映射到需要显示在 LED 上的位图图像。这些 LED 是该板上的主要输出形式之一，因此这个食谱将为您提供一个有价值的交互手段，以与您放在板上的脚本进行交互。

# 准备就绪

您需要安装和配置 Mu 文本编辑器，以及将您的 Micro Bit 板连接到计算机。

# 如何操作...

按照以下步骤学习如何在 LED 显示器上显示单个字符：

1.  在 REPL 中运行以下代码行：

```py
>>> from microbit import display
>>> display.show('a')
```

1.  显示现在应该显示字母`a`。运行以下代码块以显示数字`1`：

```py
>>> display.show('1')
```

1.  运行以下代码块后，将显示数字`2`：

```py
>>> display.show(2)
```

1.  运行以下代码块以关闭显示：

```py
>>> display.clear()
```

1.  以下代码应放入主文本编辑器窗口并刷新到板上：

```py
from microbit import display
import time

for i in range(3):
    display.show(i)
    time.sleep(1)
```

执行后，此代码将显示数字 0、1 和 2，每次更改之间间隔 1 秒。

# 它是如何工作的...

micro:bit Python 库中的显示对象具有一个`show`方法，可以用来在显示器上显示数字和字符。最初的两个示例调用了带有字符串数据类型的参数的方法。 

当显示数字`2`时，该值被给定为整数。当`show`接收其输入时，它可以接受字符串或整数。在食谱中首先导入必要的库，然后启动一个`for`循环，循环三次。在每次循环中，它显示从`0`开始的当前迭代次数，然后在再次循环之前休眠一秒。

# 还有更多...

处理 5 x 5 LED 网格的有限显示分辨率可能具有挑战性。幸运的是，micro:bit 附带的 Python 模块已经完成了在显示器上以可读方式显示所有字母和字符的工作。在这个食谱中，我们已经看到了如何提供字符串和整数作为数据来显示。在下一个食谱中，我们将看到相同的方法也可以接收其他对象，比如图像对象。

# 另请参阅

关于这个食谱的一些参考资料：

+   `show`方法的文档可以在[`microbit-micropython.readthedocs.io/en/latest/display.html#microbit.display.show`](https://microbit-micropython.readthedocs.io/en/latest/display.html#microbit.display.show)找到。

+   `clear`方法的文档可以在[`microbit-micropython.readthedocs.io/en/latest/display.html#microbit.display.clear`](https://microbit-micropython.readthedocs.io/en/latest/display.html#microbit.display.clear)找到。

# 显示内置图像

这个食谱将向您展示如何使用 5 x 5 LED 阵列来显示 micro:bit 库中提供的内置图像之一。有许多可用的图像，从面部表情到动物符号不等。它们非常像表情符号。

在这个食谱中，我们将看到如何在显示器上显示心形和笑脸图标。在 micro:bit 上创建项目时，显示超出文本和数字的符号可能是有用的，就像在这个食谱中所示的那样。如果您在 micro:bit 上制作了游戏，您可能希望在玩家输赢游戏时显示快乐或悲伤的表情。

# 准备就绪

您需要安装和配置 Mu 文本编辑器，以及将您的 micro:bit 板连接到计算机。

# 如何操作...

按照以下步骤学习如何显示内置图像：

1.  在 REPL 中执行以下代码块：

```py
>>> from microbit import display, Image
>>> import time
>>> 
>>> display.show(Image.HAPPY)
```

1.  显示应该显示一个笑脸。运行以下代码块以显示一个心形图标：

```py
>>> display.show(Image.HEART)
```

1.  以下代码块将显示一个指向 1 点钟的时钟表盘：

```py
>>> display.show(Image.CLOCK1)
```

1.  运行以下代码块以显示一个时钟表盘动画，将时钟表盘从 1 点钟移动到 12 点钟：

```py
>>> CLOCK = [getattr(Image, 'CLOCK%s' % i) for i in range(1, 13)]
>>> for image in CLOCK:
...     display.show(image)
...     time.sleep(0.1)
...     
...     
... 
>>>
```

1.  以下代码应该放入主文本编辑器窗口并刷入到板上：

```py
from microbit import display, Image
import time

CLOCK = [getattr(Image, 'CLOCK%s' % i) for i in range(1, 13)]
while True:
    for image in CLOCK:
        display.show(image)
        time.sleep(0.1)
```

一旦执行，此代码将不断地将时钟表盘从 1 点钟移动到 12 点钟，每次更改之间的延迟为`0.1`秒。

# 它是如何工作的...

`Image`对象是`microbit` Python 库的一部分，其中包含一系列内置图像，可以通过引用其属性名称来访问。show 方法接受这些图像对象，并在调用它们后在网格上显示它们。在 REPL 中的初始示例中，通过引用这些图像的名称，显示了一个笑脸、心形和时钟表盘。

然后创建一个列表，指向正确顺序的 12 个时钟表盘图像中的每一个。然后可以使用此列表创建一个时钟表盘动画。首先，启动一个无限循环。在无限循环的每次迭代期间，将启动一个`for`循环，该循环将遍历 12 个时钟表盘图像中的每一个，显示它们，然后在开始下一次迭代之前暂停 0.1 秒。通过这种方式，创建了一个时钟表盘动画，时钟表盘在时钟的 12 个位置之间移动。

# 还有更多...

有许多符号和图像，不仅仅是这个配方中显示的。您可以在 REPL 中通过引用文档或使用内置的`dir`函数列出它们的名称来探索它们。

该库还支持一种机制，您可以使用它来定义自己的自定义图像，然后可以将其保存在代码中，并在项目中重复使用。在这个配方中，我们向您展示了创建图像动画的一种方法，但`display`对象的`show`方法中也内置了对动画的支持，也可以使用。

# 另请参阅

以下是有关此配方的一些参考资料：

+   有关创建自己的图像的文档，请访问[`microbit-micropython.readthedocs.io/en/latest/tutorials/images.html#diy-images`](https://microbit-micropython.readthedocs.io/en/latest/tutorials/images.html#diy-images)。

+   有关使用内置支持创建动画的文档，请访问[`microbit-micropython.readthedocs.io/en/latest/tutorials/images.html#animation`](https://microbit-micropython.readthedocs.io/en/latest/tutorials/images.html#animation)。

# 显示滚动文本

这个配方将向您展示一种技术，您可以使用滚动文本功能来向用户显示文本，该功能在`microbit`库中可用。LED 网格仅能一次显示一个字符。通过使用滚动功能，您可以将消息显示为一系列在显示器上滚动的字符。

通过这种方式，您可以创建项目，向用户显示简短的消息，即使在板上可用的物理显示有限。这个配方还将向您展示如何控制动画的速度，以及如何使文本在显示器上无限循环。

# 准备工作

您需要安装和配置 Mu 文本编辑器，以及将您的 micro:bit 板连接到计算机。

# 如何做...

按照以下步骤学习如何显示滚动文本：

1.  使用 REPL 运行以下代码行：

```py
>>> from microbit import display
>>> display.scroll('hello')
```

1.  显示应该显示文本`'hello'`在显示器上滚动。默认延迟为 150 毫秒。以下代码块将以正常速度的两倍滚动文本：

```py
>>> display.scroll('hello', delay=75)
```

1.  以下代码块将以默认速度的一半显示相同的文本：

```py
>>> display.scroll('hello', delay=300)
```

1.  运行以下代码块以显示无限循环中的文本：

```py
>>> display.scroll('hello', loop=True)
```

1.  通过按下*Ctrl* + *C*来终止无限循环。您应该会看到以下消息：

```py
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
KeyboardInterrupt: 
>>> 
```

1.  以下代码应放入主文本编辑器窗口并刷入板：

```py
from microbit import display

TEXT = [
    ('slow', 300),
    ('normal', 150),
    ('fast', 75),

]

for text, delay in TEXT:
    display.scroll(text, delay=delay)
```

一旦执行，此代码将以三种不同的速度（慢速、正常速度和快速）滚动文本。

# 工作原理...

`scroll` 方法是 `display` 对象的一部分，并提供了我们在显示器上滚动文本所需的所有功能。只需要一个参数，即要显示的文本。一旦调用此方法，它将启动动画，并显示所提供文本中的每个字符，并将字符滚动到屏幕上，直到整个文本都显示出来。

可提供可选的 `delay` 参数以控制滚动动画的显示速度。延迟的较低值将创建更快的动画，而较高的值将减慢动画速度。主脚本定义了一个包含三条消息的列表，每条消息都有不同的滚动延迟设置。然后执行一个 `for` 循环，循环遍历每个值，并调用 `scroll` 方法来显示指定的文本，并为每条消息应用自定义滚动 `delay`。

# 还有更多...

`scroll` 方法提供了其他选项，这些选项可能会派上用场。此方法具有在后台运行 `scroll` 动画的能力。当您希望让消息出现而程序执行其他操作时，这可能很有用。您应该注意使用此食谱中介绍的循环选项。基本上，以这种方式调用 `show` 方法将使调用永远不会返回，因为它将在 `show` 方法中启动一个无限循环。

# 另请参阅

以下是有关此食谱的一些参考资料：

+   可以在[`microbit-micropython.readthedocs.io/en/latest/tutorials/hello.html`](https://microbit-micropython.readthedocs.io/en/latest/tutorials/hello.html)找到一些调用 `scroll` 方法的简单示例。

+   有关 `scroll` 方法的文档可以在[`microbit-micropython.readthedocs.io/en/latest/display.html#microbit.display.scroll`](https://microbit-micropython.readthedocs.io/en/latest/display.html#microbit.display.scroll)找到。

# 显示哪个按钮被按下

此食谱将向您展示如何通过在按下按钮时在显示器上显示被按下的按钮来响应板上的两个按钮之一。这将是本章中的第一个食谱，我们将看到如何创建一个可以通过显示内置 LED 网格的视觉输出来响应用户输入的交互式项目。

在创建自己的项目时，拥有两个按钮可以打开许多可能性，可以创建响应这些输入的交互式应用程序和游戏。此食谱将为您提供基本构建模块，以便您可以开始构建这些类型的项目。

# 准备工作

您需要安装和配置 Mu 文本编辑器，以及将 micro:bit 板连接到计算机。

# 如何做到...

按照以下步骤学习如何显示哪个按钮已被按下：

1.  在 REPL 中运行以下代码行：

```py
>>> from microbit import display, button_a, button_b
>>> 
>>> button_a.is_pressed()
False
```

1.  由于按钮 A 没有被按下，返回的值应为 `False`。在执行以下代码块时按住按钮 A：

```py
>>> button_a.is_pressed()
True
```

1.  在执行以下代码块时按住按钮 B：

```py
>>> button_b.is_pressed()
True
```

1.  以下代码应放入主文本编辑器窗口并刷入板：

```py
from microbit import display, button_a, button_b

while True:
    if button_a.is_pressed():
        display.show('a')
    elif button_b.is_pressed():
        display.show('b')
    else:
        display.clear()
```

一旦执行，此代码将显示字符 `a` 或 `b`，如果按下按钮 A 或 B。

# 工作原理...

在初始导入之后，主脚本进入无限循环。在每次迭代期间，将轮询两个按钮，以查看它们当前是否被按下。如果按下按钮 A 或 B 中的任何一个，则屏幕上将显示按下按钮的字符。循环的最后一部分是检查是否两个按钮都没有被按下，然后清除屏幕的内容。

# 还有更多...

该示例显示了一个事件循环的基本结构，该循环不断循环并检查输入传感器上的事件，并根据发生的事件采取行动。您可以采用这个基本示例，并以许多方式进行扩展。例如，您可以创建一个脚本，帮助用户在菜单选项列表之间导航和选择。

按下按钮 A 可以显示下一个菜单项。按下按钮 B 后，然后可以选择该菜单项。程序的整体结构在事件循环和在每次循环迭代期间检查每个按钮的状态方面将保持不变。

# 另请参阅

以下是有关此示例的一些参考资料：

+   有关与按键交互的示例，请访问[`microbit-micropython.readthedocs.io/en/latest/tutorials/buttons.html`](https://microbit-micropython.readthedocs.io/en/latest/tutorials/buttons.html)。

+   可以在[`microbit-micropython.readthedocs.io/en/latest/button.html`](https://microbit-micropython.readthedocs.io/en/latest/button.html)找到有关`Button`类及其方法的文档。

# 创建一个倒计时器

该示例将向您展示如何使用 micro:bit 板创建一个倒计时器。每次有人按下按钮 A 时，倒计时器就会启动。它会显示倒计时完成前剩余多少秒。它将从数字 9 开始倒数，直到计时器完成，然后清除屏幕。在考虑创建需要将经过的时间纳入脚本的项目时，查阅此类示例可能会很有用。

# 准备就绪

您需要安装和配置 Mu 文本编辑器，以及将您的 micro:bit 板连接到计算机。

# 如何做...

按照以下步骤学习如何创建倒计时器：

1.  在 REPL 中执行以下代码块：

```py
>>> from microbit import display, button_a
>>> import time
>>> 
>>> NUMBERS = list(range(9, 0, -1))
```

1.  用于倒计时的数字列表将存储在`NUMBERS`变量中。以下代码块将显示它们的值：

```py
>>> NUMBERS
[9, 8, 7, 6, 5, 4, 3, 2, 1]
```

1.  以下代码块将定义并调用`countdown`函数。您应该看到显示屏显示从 9 到 1 的倒计时，每次更改之间有一秒的延迟：

```py
>>> def countdown():
...     for i in NUMBERS:
...         display.show(i)
...         time.sleep(1)
...     display.clear()
...     
...     
... 
>>> 
>>> countdown()
```

1.  以下代码应放入主文本编辑窗口并刷新到板上：

```py
from microbit import display, button_a
import time

NUMBERS = list(range(9, 0, -1))

def countdown():
    for i in NUMBERS:
        display.show(i)
        time.sleep(1)
    display.clear()

while True:
    if button_a.is_pressed():
        countdown()
```

执行后，每次按下按钮 A 时，此代码将显示一个 9 秒的倒计时。

# 它是如何工作的...

在初始导入之后，主脚本进入一个无限循环，不断检查按钮 A 上的按钮按下事件。如果检测到按下按钮 A，则将调用倒计时函数开始倒计时。`countdown`函数循环遍历从 9 到 1 的数字列表。

在每次循环中，它将显示数字并暂停 1 秒，然后继续到下一个迭代。完成所有九次迭代后，它将清除屏幕以标记计时器的结束。

# 还有更多...

可以扩展此示例，以便按下按钮 B 时启动不同的计时器。也许按钮 B 会启动一个从 1 到 9 的计时器。您还可以使按钮 A 启动秒表，按钮 B 可以停止秒表并显示经过的时间。

# 另请参阅

以下是有关此示例的一些参考资料：

+   可以在[`microbit-micropython.readthedocs.io/en/latest/microbit.html#microbit.running_time`](https://microbit-micropython.readthedocs.io/en/latest/microbit.html#microbit.running_time)找到有关`running_time`函数的文档。

+   可以在[`microbit-micropython.readthedocs.io/en/latest/utime.html`](https://microbit-micropython.readthedocs.io/en/latest/utime.html)找到有关`utime`模块的文档，该模块可用于 micro:bit。


# 第十章：控制 ESP8266

在本章中，我们将介绍 Adafruit Feather HUZZAH ESP8266 微控制器。当您的嵌入式项目需要支持互联网连接时，ESP8266 是最受欢迎的 MicroPython 硬件选项之一。通过板上内置的 Wi-Fi 功能实现此连接。

本章将探讨获取板上 REPL 访问的两种主要方法：通过 USB 连接，以及通过 Wi-Fi 无线连接。我们还将介绍一些配方，涵盖与板上 Wi-Fi 功能的不同交互方面。

在本章结束时，您将学会所有必要的核心技能，以便可以高效地使用该板，并开始使用这种多功能且价格低廉的互联网连接硬件构建自己的嵌入式项目。

在本章中，我们将涵盖以下主题：

+   通过串行连接使用 REPL

+   扫描可用的 Wi-Fi 网络

+   配置 AP 模式的设置

+   连接到现有的 Wi-Fi 网络

+   通过 Wi-Fi 使用 WebREPL

+   使用 WebREPL CLI 传输文件

+   控制蓝色和红色 LED

# 技术要求

本章的代码文件可以在本书的 GitHub 存储库的`Chapter10`文件夹中找到，网址为[`github.com/PacktPublishing/MicroPython-Cookbook`](https://github.com/PacktPublishing/MicroPython-Cookbook)。

本章中的所有配方都使用了 CircuitPython 3.1.2。

# Adafruit Feather HUZZAH ESP8266

ESP8266 是由 Espressif Systems 制造的廉价微控制器。它可以运行 MicroPython，并支持完整的 TCP/IP 堆栈。其内置的 Wi-Fi 支持 802.11b/g/n。Adafruit Feather HUZZAH ESP8266 是一款开发板，具有用于电源和数据连接的 USB 支持。

该板上的处理器运行在 80 MHz，并配备了 4 MB 的闪存。该板配有九个 GPIO 引脚，可以连接到许多其他组件。该板有多个不同版本。以下照片显示了带有引脚选项的该板的外观：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mcpy-cb/img/829cc862-59b3-4010-8e2e-3a9d44794a1f.png)

该板还具有堆叠式引脚配置，可以在板的顶部插入其他组件，如 OLED 显示屏和按钮。这些升级可以直接插入，无需焊接或面包板。以下照片显示了具有堆叠式引脚的板的版本：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mcpy-cb/img/5467a9e0-0c89-4df8-a997-137d53bf4b15.png)

您还可以通过使用可充电锂聚合物电池为板载电源使您的项目具有便携性。这些电池可以使用其 JST 连接器连接到板上。以下照片显示了连接到锂聚合物电池的板：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mcpy-cb/img/9967247a-f240-4e06-856a-6713b3559ad4.png)

该板具有内置的 LiPoly 充电器，可以使用指示灯显示充电状态。只要板连接了 USB 电缆，电池就可以充电。

# 您可以在哪里购买这些？

本章使用 Adafruit Feather HUZZAH ESP8266 微控制器。我们建议购买带有堆叠式引脚的版本。Adafruit 已组装的 Feather HUZZAH ESP8266 Wi-Fi 微控制器带有堆叠式引脚，可以直接从 Adafruit 购买([`www.adafruit.com/product/3213`](https://www.adafruit.com/product/3213))。

# 通过串行连接使用 REPL

本配方将向您展示如何通过 USB 串行连接获取对 ESP8266 的 REPL 访问。尽管该板的真正功能和激动点来自于无线连接，但我们需要做的第一件事是通过简单的 USB 连接与其连接。设置好此连接后，您可以继续本章中的其余配方，设置无线设置，以便可以拔掉板并完全无线地与其交互。

这个配方将帮助您通过建立与板的初始连接来开始自己的无线嵌入式项目，以建立无线连接。当您的配置板面临连接问题并且您想要访问它以调试可能遇到的任何 Wi-Fi 问题时，它也是一个有价值的工具。

# 准备工作

此配方可以使用 macOS 或 Linux 计算机，并且需要可用的 screen 命令。在 macOS 上，screen 应用程序是内置的，因此无需安装。在 Ubuntu Linux 上，可以使用 apt `install screen`命令安装 screen 命令。

# 如何做...

按照以下步骤学习如何通过串行连接使用 REPL：

1.  使用 USB 电缆将 ESP8266 连接到计算机。

1.  打开终端应用程序。

1.  在大多数 Linux 系统上，设备的名称应该是`/dev/ttyUSB0`。通过在终端中运行以下命令来确认该设备是否存在：

```py
$ ls /dev/ttyUSB0
/dev/ttyUSB0
```

1.  如果 ESP8266 被操作系统成功检测到，上述命令应该成功运行。

1.  运行以下命令以启动与板的 REPL 会话：

```py
$ sudo screen /dev/ttyUSB0 115200
```

1.  上面的命令将启动`screen`命令，并以每秒 115,200 比特的波特率连接到名为`/dev/ttyUSB0`的设备。如果连接成功建立，您应该在终端中看到以下消息：

```py
Adafruit CircuitPython 3.1.2 on 2019-01-07; ESP module with ESP8266
>>> 
>>> 
```

1.  在 REPL 中执行以下代码：

```py
>>> import math
>>> math.pow(8,2)
64.0
>>> 8**2
64
```

上面的代码块将导入`math`库并计算 8 的平方。

# 工作原理...

ESP8266 通过 USB 连接公开了一个串行设备。然后可以使用类似`screen`的终端仿真器与该串行设备进行交互。连接到 screen 后，您可以访问 REPL 并开始在板上执行 Python 代码。每当在 REPL 中执行 Python 代码时，命令都会被发送到板上执行，然后命令的结果通过串行连接传输回终端仿真器。

# 还有更多...

所有主要操作系统上都有许多优秀的免费终端仿真器。`picocom`和`minicom`是 Unix 系统上 screen 的流行替代品。在 Windows 上，可以使用终端仿真器 PuTTY，而 macOS 有一个名为 CoolTerm 的应用程序可以用于此目的。

# 另请参阅

以下是关于这个配方的一些参考资料：

+   连接到 Adafruit Feather HUZZAH ESP8266 的文档可以在[`learn.adafruit.com/adafruit-feather-huzzah-esp8266`](https://learn.adafruit.com/adafruit-feather-huzzah-esp8266)找到。

+   有关`picocom`命令的详细信息可以在[`github.com/npat-efault/picocom`](https://github.com/npat-efault/picocom)找到。

# 扫描可用的 Wi-Fi 网络

这个配方将向您展示如何使用 ESP8266 列出所有可用的 Wi-Fi 网络，并且可以连接到这些网络。我们将介绍 MicroPython 网络库，并探讨如何使用它的对象来初始化板载 Wi-Fi 硬件。

设置好这些组件后，我们可以使用它们来扫描无线网络并将扫描结果存储以供进一步检查。这个配方可以为您提供有用的技术，以便您可以测试板的 Wi-Fi 功能。通常，在以后连接到它们之前，列出无线网络是需要的第一步。

# 准备工作

您需要访问 ESP8266 上的 REPL 才能运行本配方中提供的代码。

# 如何做...

按照以下步骤学习如何扫描可用的 Wi-Fi 网络：

1.  在 REPL 中运行以下代码行：

```py
>>> import network
>>> station = network.WLAN(network.STA_IF)
```

1.  网络库现在已经被导入，并且已经创建了一个 WLAN 对象，它将提供一个`station`接口。以下代码块将激活`station`接口：

```py
>>> station.active(True)
```

1.  以下代码块将扫描所有可用的无线网络并将结果存储在`networks`变量中：

```py
>>> networks = station.scan()
scandone
```

1.  以下代码块将输出`networks`变量的内容，并显示找到了多少个网络：

```py
>>> networks
[(b'My WiFi', b'\x80*\xa8\x84\xa6\xfa', 1, -72, 3, 0), (b'Why Fi', b'\xc8Q\x95\x92\xaa\xd0', 1, -92, 4, 0), (b'Wi Oh Wi', b'd\xd1T\x9a\xb3\xcd', 1, -90, 3, 0)]
>>> len(networks)
3
```

1.  运行以下代码行：

```py
>>> names = [i[0] for i in networks]
>>> names
[b'My WiFi', b'Why Fi', b'Wi Oh Wi']
```

执行后，代码将提取无线网络的名称并将它们存储在一个名为`names`的变量中，然后进行检查。

# 工作原理...

MicroPython 提供了一个名为`network`的模块，可以用来与 ESP8266 上的 Wi-Fi 硬件进行交互。 WLAN 对象被实例化，并提供了`network.STA_IF`作为其第一个参数。这将返回一个作为`station`接口创建的对象。

当您想要将板子连接到现有的 Wi-Fi 网络时，需要`station`接口。在执行扫描之前，必须通过调用`active`方法并传入`True`值来激活该接口。然后，可以在该接口上调用`scan`方法，该方法将扫描可用的网络。此方法返回一个元组列表，我们将其存储在`networks`变量中。

然后，我们可以使用`len`函数计算网络的数量，并循环遍历这个元组列表，提取每个网络的名称。每个网络的名称，或**服务集标识符**（**SSID**），将存储在元组的第一个值中。我们使用列表推导式从`networks`变量中的每个项目中检索此值，然后将其保存在`names`变量中。

# 还有更多...

本教程创建了一个 WLAN 对象作为`station`接口。在后续的教程中，我们将学习如何创建另一种类型的 WLAN 对象，该对象可用于将设备配置为 AP。除了使用`scan`方法获取无线网络的名称之外，还可以检查有关每个网络的其他详细信息，例如它使用的信道和接受的认证模式。

`scan`方法将其结果作为一个简单的数据结构返回，您可以在程序的其余部分中存储和处理。这使得可以创建定期扫描可用网络并将结果保存到日志文件中的项目成为可能。

# 另请参阅

以下是关于本教程的一些参考资料：

+   `scan`方法的文档可以在[`docs.micropython.org/en/latest/library/network.html#network.AbstractNIC.scan`](https://docs.micropython.org/en/latest/library/network.html#network.AbstractNIC.scan)找到。

+   `active`方法的文档可以在[`docs.micropython.org/en/latest/library/network.html#network.AbstractNIC.active`](https://docs.micropython.org/en/latest/library/network.html#network.AbstractNIC.active)找到。

# 配置 AP 模式的设置

本教程将向您展示如何在 ESP8266 上配置**接入点**（**AP**）模式。配置完成后，板子将成为一个 Wi-Fi AP，您可以直接使用标准 Wi-Fi 连接将笔记本电脑和手机连接到板子。

Wi-Fi 是如此普遍，以至于这个功能成为一种非常强大的提供连接的方式。您可以使用本教程中展示的技术将 Wi-Fi AP 功能合并到自己的项目中。这样，即使没有其他接入点可用，您也可以在板子和手机或笔记本电脑之间建立无线连接。

# 准备工作

您需要访问 ESP8266 上的 REPL 来运行本教程中提供的代码。

# 操作步骤...

按照以下步骤学习如何配置 AP 模式的设置：

1.  在 REPL 中执行以下代码块：

```py
>>> import network
>>> ap = network.WLAN(network.AP_IF)
```

1.  `network`库现在已被导入，并且已经为 AP 模式创建了一个 WLAN 对象。以下代码块将配置并激活 AP：

```py
>>> ap.config(essid='PyWifi', password='12345678')
bcn 0
del if1
pm open,type:2 0
add if1
pm close 7
#7 ets_task(4020f4c0, 29, 3fff96f8, 10)
dhcp server start:(ip:192.168.4.1,mask:255.255.255.0,gw:192.168.4.1)
bcn 100
>>> ap.active(True)
```

1.  使用手机或笔记本电脑搜索并加入名为`PyWifi`的 AP。应该在 REPL 中看到以下输出：

```py
>>> add 1
aid 1
station: b0:35:9f:2c:69:aa join, AID = 1

>>> 
```

1.  将另一台设备连接到相同的 AP。您应该在 REPL 输出中看到已连接设备的详细信息，如下面的代码块所示：

```py
>>> add 2
aid 2
station: 34:2d:0d:8c:40:bb join, AID = 2

>>> 
```

1.  板子还将报告从 AP 断开连接的设备。从 AP 中断开一个连接的设备，应该在 REPL 中出现以下输出：

```py
>>> station: 34:2d:0d:8c:40:bb leave, AID = 2
rm 2

>>> 
```

1.  在 REPL 中运行以下代码：

```py
>>> ap.ifconfig()
('192.168.4.1', '255.255.255.0', '192.168.4.1', '8.8.8.8')
>>> 
```

上述代码将获取有关 AP 的 IP 地址和子网掩码的详细信息。

# 工作原理...

MicroPython 固件提供了使用 ESP8266 创建 Wi-Fi 接入点的功能。要使用此功能，我们必须首先创建一个 WLAN 对象，并将`network.AP_IF`值作为其第一个参数传递。这将返回一个可以用于启用 AP 模式的对象。然后调用`config`方法，传递所需的 Wi-Fi 网络名称和设备连接到 AP 时将使用的密码。

最后，通过调用`active`方法并传入`True`值来激活 AP。然后，板子就准备好接收连接了。当设备加入和离开网络时，这些细节将自动打印为 REPL 会话的输出。

# 还有更多...

正如我们在本教程中看到的，多个设备可以同时连接到板子上。您可以将此教程作为实验此功能的起点。例如，您可以将笔记本电脑和手机连接到 AP，并尝试 ping Wi-Fi 网络上的不同设备。您甚至可以从笔记本电脑 ping 您的手机或 ESP8266 板。

在后续章节中，我们将学习如何在板子上运行 Web 服务器，然后您将能够超越 ping 并通过 Wi-Fi 使用您的 Web 浏览器与板子进行交互。

# 另请参阅

以下是有关本教程的一些参考资料：

+   `config`方法的文档可以在[`docs.micropython.org/en/latest/library/network.html#network.AbstractNIC.config`](https://docs.micropython.org/en/latest/library/network.html#network.AbstractNIC.config)找到。

+   `ifconfig`方法的文档可以在[`docs.micropython.org/en/latest/library/network.html#network.AbstractNIC.ifconfig`](https://docs.micropython.org/en/latest/library/network.html#network.AbstractNIC.ifconfig)找到。

# 连接到现有的 Wi-Fi 网络

本教程将向您展示如何将 ESP8266 连接到现有的 Wi-Fi 网络。加入现有的 Wi-Fi 网络有许多好处。这样做可以使不同设备在您的网络上无线访问板子成为可能。它还通过 Wi-Fi 网络的互联网连接为板子提供了互联网连接。您可以使用本教程中展示的方法将自己的嵌入式项目连接到不同的网络，并帮助这些项目实现互联网连接。

# 准备工作

您需要访问 ESP8266 上的 REPL 来运行本教程中提供的代码。

# 如何操作...

按照以下步骤学习如何连接到现有的 Wi-Fi 网络：

1.  使用 REPL 运行以下代码行：

```py
>>> import network
>>> station = network.WLAN(network.STA_IF)
>>> station.active(True)
```

1.  WLAN 对象现已创建并激活。使用以下代码块验证要连接的 AP 是否出现在可用网络列表中：

```py
>>> networks = station.scan()
scandone
>>> names = [i[0] for i in networks]
>>> names
[b'MyAmazingWiFi', b'Why Fi', b'Wi Oh Wi']
```

1.  以下代码行将连接到 Wi-Fi AP：

```py
>>> station.connect('MyAmazingWiFi', 'MyAmazingPassword')
ap_loss
scandone
state: 5 -> 0 (0)
rm 0
reconnect
>>> scandone
state: 0 -> 2 (b0)
state: 2 -> 3 (0)
state: 3 -> 5 (10)
add 0
aid 1
cnt 

connected with MyAmazingWiFi, channel 6
dhcp client start...
ip:192.168.43.110,mask:255.255.255.0,gw:192.168.43.1

>>> 
```

1.  以下代码块将返回一个布尔值，指示我们当前是否已连接到 AP：

```py
>>> station.isconnected()
True
```

1.  以下代码行将获取有关我们当前网络连接的详细信息，包括板的 IP 地址、子网掩码、网关和 DNS 服务器：

```py
>>> station.ifconfig()
('192.168.43.110', '255.255.255.0', '192.168.43.1', '192.168.43.1')
>>> 
```

1.  运行以下代码块：

```py
>>> station.active(False)
state: 5 -> 0 (0)
rm 0
del if0
mode : softAP(86:f3:eb:b2:9b:aa)
>>> 
```

运行此代码后，板将断开与 AP 的连接。

# 工作原理...

MicroPython 固件具有连接到现有 Wi-Fi 接入点的能力，使用 ESP8266。为此，您必须创建一个 WLAN 对象，并将`network.STA_IF`值作为其第一个参数传递。在本教程中，将此对象保存到名为`station`的变量中。然后，通过调用`active`方法并传入`True`值来激活`station`对象。一旦激活，就可以调用`connect`方法并传入要连接的 AP 的名称及其关联密码。一旦调用`connect`方法，连接过程中将打印出大量信息。

我们随时可以通过在站点对象上调用`isconnected`方法来检查我们是否连接。如果我们连接，它将返回`True`值，否则返回`False`值。然后，我们可以通过调用`ifconfig`方法来检索有关我们的 IP 地址和 DNS 服务器的网络详细信息。最后，可以调用`active`方法，并使用`False`参数使板断开网络连接。

# 还有更多...

本教程中包含了关于 WLAN 对象的多种不同方法，可以调用和使用。它向您展示了如何列出网络、连接到网络、轮询连接状态、获取有关当前网络的网络信息以及如何断开网络连接。

使用这些方法，您可以创建一个定期扫描附近网络以寻找特定网络的程序。每当找到它时，您可以自动连接到它。您还可以编写一个不同的脚本，不断轮询网络连接状态并更新状态 LED，以指示 Wi-Fi 已连接，并在断开连接时关闭。

# 另请参阅

以下是有关本教程的一些参考资料：

+   有关`connect`方法的文档可以在[`docs.micropython.org/en/latest/library/network.html#network.AbstractNIC.connect`](https://docs.micropython.org/en/latest/library/network.html#network.AbstractNIC.connect)找到。

+   有关`isconnected`方法的文档可以在[`docs.micropython.org/en/latest/library/network.html#network.AbstractNIC.isconnected`](https://docs.micropython.org/en/latest/library/network.html#network.AbstractNIC.isconnected)找到。

# 通过 Wi-Fi 使用 WebREPL

本教程将向您展示如何在 ESP8266 板上使用 MicroPython 提供的 WebREPL 功能。 WebREPL 是可以在板上启动的服务，它允许您的网络上的计算机通过网络浏览器无线访问 REPL。我们已经在本章的*使用串行连接*教程中看到了如何使用串行连接访问 REPL。

本教程将为您提供通过 Wi-Fi 获取 REPL 所需的技能，从而即使在没有直接物理连接的情况下，也可以远程调试和执行板上的代码。

# 准备就绪

您需要访问 ESP8266 上的 REPL 才能运行本教程中提供的代码。在完成本教程之前，您应该按照前一个教程*连接到现有 Wi-Fi 网络*，因为您将使用该教程将板连接到您的网络并获取其 IP 地址。

# 操作步骤...

按照以下步骤学习如何通过 Wi-Fi 使用 WebREPL：

1.  在 REPL 中运行以下代码行：

```py
>>> import webrepl_setup
```

1.  WebREPL 配置向导现在将开始，询问您一系列问题，以便配置服务。回答以下问题，使用字母`E`启用启动时的服务：

```py
WebREPL daemon auto-start status: disabled

Would you like to (E)nable or (D)isable it running on boot?
(Empty line to quit)
> E
```

1.  接下来的一系列问题将要求您输入和确认 WebREPL 密码：

```py
To enable WebREPL, you must set password for it
New password (4-9 chars): secret123
Confirm password: secret123
```

1.  对于下一个问题，回答`y`（是），以便可以重新启动板并应用更改：

```py
Changes will be activated after reboot
Would you like to reboot now? (y/n) y
Rebooting. Please manually reset if it hangs.
state: 5 -> 0 (0)
rm 0
del if0
bcn 0
del if1
usl
load 0x40100000, len 31012, room 16 
tail 4
chksum 0x61
load 0x3ffe8000, len 1100, room 4 
tail 8
chksum 0x4e
load 0x3ffe8450, len 3264, room 0 
tail 0
chksum 0x0f
csum 0x0f
boot.py output:
WebREPL daemon started on ws://192.168.4.1:8266
WebREPL daemon started on ws://0.0.0.0:8266
Started webrepl in normal mode
```

1.  您可以从前面的输出中看到，一旦板子启动，它将显示 WebREPL 服务已启动以及可用于访问该服务的 URL。

1.  通过单击克隆或下载按钮从[`github.com/micropython/webrepl`](https://github.com/micropython/webrepl)下载 WebREPL 软件。

1.  将下载的`.zip`文件解压缩到计算机上的任何文件夹中。

1.  在任何现代的网络浏览器中打开`webrepl.html`文件。您应该在网络浏览器中看到以下界面：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mcpy-cb/img/a36cc34c-8f7b-413d-a9fa-abcff78e24dd.png)

1.  在连接按钮旁边的文本框中输入设备的 WebREPL 服务的 URL。在上一个屏幕截图中，板的 IP 地址是`10.0.0.38`，因此给出了 URL`ws://10.0.0.38:8266`。

1.  现在，单击“连接”按钮，并在提示时输入 WebREPL 密码。以下屏幕截图显示了一个 WebREPL 会话，其中导入了`math`模块并显示了 pi 的值：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mcpy-cb/img/df9cdbce-06e5-4d30-b800-cbc427e40cfc.png)

1.  WebREPL 还具有上传文件到板上的功能。您可以使用此功能上传名为`main.py`的 Python 脚本到板上。

1.  单击“发送文件”下的“浏览...”按钮。

1.  选择您的`main.py`文件。

1.  单击“发送到设备”按钮。

1.  以下屏幕截图显示了上传文件到板上后出现的成功上传消息的示例：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mcpy-cb/img/8fc4762f-7697-48ce-a30f-36fb30f53a2e.png)

屏幕上的消息确认了文件已发送，并报告了传输的字节数。

# 工作原理...

MicroPython 固件带有内置的 WebREPL 服务器。一旦导入`webrepl_setup`模块，它将启动一个交互式向导，让您启用该服务。设置其密码并配置它在每次启动板时运行。一旦此服务运行，它将公开一个 WebSocket 服务，可以接收来自在浏览器中运行的 WebREPL 客户端的连接。

WebREPL 客户端不需要任何特殊的安装——它只是一个 HTML 文件，可以在本地提取到您的计算机，然后在网络浏览器中打开。通过此客户端，您现在可以指定要连接的板的地址，并与板建立连接。一旦连接，您将在网络浏览器中拥有一个交互式 REPL 会话，以及将文件上传到板的能力。

# 还有更多...

这个配方专注于 WebREPL 客户端之一。在这个配方中显示的客户端旨在在您的网络浏览器中运行，并使通过 Wi-Fi 与板卡一起工作的过程变得简单。还有一个 WebREPL 客户端，可以使用**命令行界面**（**CLI**）而不是网络浏览器来运行。

与网络浏览器客户端不同，CLI 版本完全由 Python 编写。这为您提供了一个很好的机会来探索 WebREPL 通过 Web 套接字传输文件的内部。下一个配方将更深入地探讨 CLI 版本。

# 另请参阅

以下是有关此配方的一些参考资料：

+   有关访问 WebREPL 的文档可以在[`docs.micropython.org/en/latest/esp8266/tutorial/repl.html#webrepl-a-prompt-over-wifi`](https://docs.micropython.org/en/latest/esp8266/tutorial/repl.html#webrepl-a-prompt-over-wifi)找到。

+   有关连接到 WebREPL 的指南可以在[`learn.adafruit.com/micropython-basics-esp8266-webrepl/`](https://learn.adafruit.com/micropython-basics-esp8266-webrepl/)找到。

# 使用 WebREPL CLI 传输文件

这个配方将向您展示如何使用 WebREPL CLI 通过 Wi-Fi 从计算机传输文件到 ESP8266。这是一个非常强大的将文件传输到板上的方法。每次您对 Python 代码进行更改并希望尝试最新更改时，都必须将文件上传到板上。一遍又一遍地用您的网络浏览器做这件事可能会变得乏味。

使用 CLI 界面的美妙之处在于，大多数终端会记住它们最后执行的命令，因此您可以用两个简单的按键重新运行上一个命令：只需按下*上*箭头键和*Enter*键。这将使您的代码、上传和运行循环更快，更高效。

# 准备工作

您需要访问 ESP8266 上的 REPL 才能运行本配方中提供的代码。在尝试本配方之前，应该先遵循上一个配方*通过 Wi-Fi 使用 WebREPL*，以确保 WebREPL 正常工作。

# 操作方法...

按照以下步骤学习如何使用 WebREPL CLI 传输文件：

1.  通过单击“克隆或下载”按钮从[`github.com/micropython/webrepl`](https://github.com/micropython/webrepl)下载 WebREPL 软件。

1.  将下载的`.zip`文件解压缩到计算机上的任何文件夹中。

1.  提取的文件将包含一个名为`webrepl_cli.py`的脚本。

1.  打开终端并将工作目录更改为`webrepl_cli.py`脚本的位置。

1.  在终端中执行以下命令以查看命令的选项：

```py
$ python webrepl_cli.py --help
webrepl_cli.py - Perform remote file operations using MicroPython WebREPL protocol
Arguments:
  [-p password] <host>:<remote_file> <local_file> - Copy remote file to local file
  [-p password] <local_file> <host>:<remote_file> - Copy local file to remote file
Examples:
  webrepl_cli.py script.py 192.168.4.1:/another_name.py
  webrepl_cli.py script.py 192.168.4.1:/app/
  webrepl_cli.py -p password 192.168.4.1:/app/script.py .
```

1.  运行以下命令将`main.py`脚本上传到板子上。在提示时，您需要输入 WebREPL 密码：

```py
$ python webrepl_cli.py  main.py 10.0.0.38:/
Password: 
op:put, host:10.0.0.38, port:8266, passwd:secret123.
main.py -> /main.py
Remote WebREPL version: (3, 1, 2)
Sent 73 of 73 bytes
```

1.  以下命令与前一个命令非常相似：

```py
$ python webrepl_cli.py -p secret123 main.py 10.0.0.38:/
op:put, host:10.0.0.38, port:8266, passwd:secret123.
main.py -> /main.py
Remote WebREPL version: (3, 1, 2)
Sent 73 of 73 bytes
```

主要区别在于密码是作为命令行选项在命令行中提供的。

# 工作原理...

本教程从简单的命令行调用`webrepl_cli.py`脚本开始，以显示有关命令行选项的详细信息。至少验证 Python 是否成功执行脚本并生成您期望的输出是一个好主意。

下次调用该命令时，它将用于将`main.py`脚本上传到板子上。这绝对是上传脚本的一种可行方式。但是，它的主要缺点是每次上传脚本时都必须输入密码。这可以像前面的例子一样解决，其中密码是在命令行上提供的。通过最后一个例子，可以只需按下几个按键重复运行该命令。

# 还有更多...

当您反复上传脚本到板子上时，这个命令可以节省真正的时间。您还可以将其与其他命令行软件结合起来，以监视特定文件夹中的更改。例如，您可以通过结合这两个软件，使该命令在每次文件更改时自动上传任何更改到`main.py`。

请注意，正如该命令的文档中所述，文件传输仍处于 alpha 阶段，并且存在一些已知问题。如果发现脚本在上传几次后卡住，最有效的解决方法是进行硬复位。可以通过运行以下代码块来完成：

```py
import machine
machine.reset()
```

这也可以通过按下板子上的复位按钮来完成。

# 另请参阅

以下是有关此教程的一些参考资料：

+   有关执行硬复位的文档可以在[`docs.micropython.org/en/v1.8.6/wipy/wipy/tutorial/reset.html`](http://docs.micropython.org/en/v1.8.6/wipy/wipy/tutorial/reset.html)找到

+   有关使用`webrepl_cli.py`文件上传文件的文档可以在[`micropython-on-esp8266-workshop.readthedocs.io/en/latest/basics.html#uploading-files`](https://micropython-on-esp8266-workshop.readthedocs.io/en/latest/basics.html#uploading-files)找到。

# 控制蓝色和红色 LED

ESP8266 配备了两个 LED：一个是红色的，另一个是蓝色的。这两个 LED 都可以从加载到板子上的脚本中进行控制。本教程将向您展示如何控制每个 LED，并以一个闪烁红色和蓝色灯的动画结束。

在您自己的项目中，每当您想要向用户发出某种状态信号时，都可以使用本教程中显示的技术。当您正在扫描 Wi-Fi 网络时，您可能希望有一个闪烁的蓝灯，或者在板子失去网络连接时点亮红灯。

# 准备工作

您需要访问 ESP8266 上的 REPL 才能运行本教程中提供的代码。

# 如何做...

按照以下步骤学习如何控制蓝色和红色 LED：

1.  在 REPL 中执行以下代码块：

```py
>>> from machine import Pin
>>> red = Pin(0, Pin.OUT)
>>> red.value(0)
```

1.  红色 LED 现在应该已经打开。运行以下代码块以关闭红色 LED：

```py
>>> red.value(1)
```

1.  以下代码块将打开蓝色 LED：

```py
>>> blue = Pin(2, Pin.OUT)
>>> blue.value(0)
```

1.  以下代码将关闭蓝色 LED：

```py
>>> blue.value(1)
```

1.  运行以下代码块：

```py
>>> import time
>>> 
>>> while True:
...     blue.value(0)
...     red.value(1)
...     time.sleep(1)
...     blue.value(1)
...     red.value(0)
...     time.sleep(1)
...     
...     
... 
```

前面的代码将创建一个灯光动画，每次变化之间有一秒的延迟，可以在红色和蓝色灯之间切换。

# 工作原理...

首先，从 machine 模块中导入`Pin`对象。这个对象将让我们直接连接到 ESP8266 板上的**通用输入/输出**（**GPIO**）引脚。红色 LED 连接在引脚 0 上。分配给`red`变量的`Pin`对象连接到红色 LED。一旦创建了这个对象，将其值设置为`0`会打开灯，将其值设置为 1 会关闭灯。

`blue`变量被定义为连接到 GPIO 引脚 2 的`Pin`对象，它映射到蓝色 LED。它可以以相同的方式打开和关闭。这个教程的最后部分是一个无限循环，首先打开蓝色 LED 并关闭红色 LED。

在蓝色 LED 关闭并打开红色 LED 之前应用了 1 秒的休眠延迟。在循环再次从头开始执行相同的操作之前，再次应用 1 秒的休眠延迟。

# 还有更多...

这个教程向你展示了如何控制板载的两个 LED 灯。额外的 LED 灯可以连接到其他可用的 GPIO 引脚，并且可以以类似的方式进行控制。该板载有 9 个可用的 GPIO 引脚。除了简单的单色 LED 灯外，相同的 GPIO 引脚也可以用于连接 NeoPixels，它们提供了全彩色范围，因为它们结合了不同级别的红色、绿色和蓝色 LED 灯。

# 另请参阅

以下是关于这个教程的一些参考资料：

+   可以在[`docs.micropython.org/en/latest/esp8266/quickref.html#pins-and-gpio`](https://docs.micropython.org/en/latest/esp8266/quickref.html#pins-and-gpio)找到与引脚和 GPIO 交互的文档。

+   在[`docs.micropython.org/en/latest/esp8266/tutorial/pins.html`](https://docs.micropython.org/en/latest/esp8266/tutorial/pins.html)可以找到与 GPIO 引脚交互的教程。
