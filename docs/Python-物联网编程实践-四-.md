# Python 物联网编程实践（四）

> 原文：[`zh.annas-archive.org/md5/7FABA31DD38F615362E1254C67CC152E`](https://zh.annas-archive.org/md5/7FABA31DD38F615362E1254C67CC152E)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十章：使用舵机、电机和步进电机进行运动

在上一章中，我们介绍了如何测量温度、湿度、光线和湿度。在本章中，我们将把注意力转向控制电机和舵机，这些是用于创建物理运动和动作的常见设备。本章中您将学习的核心概念、电路和代码将为您打开使用树莓派进行物理自动化和机器人技术的大门。

我们将学习如何使用**脉冲宽度调制**（**PWM**）来设置舵机的角度，以及如何使用 H 桥集成电路来控制直流电机的方向和速度。我们将研究步进电机以及如何控制它们进行精确的运动。

本章我们将涵盖以下内容：

+   使用 PWM 来旋转舵机

+   使用 H 桥集成电路控制电机

+   步进电机控制简介

# 技术要求

要执行本章的练习，您需要以下物品：

+   树莓派 4 型 B

+   Raspbian OS Buster（带桌面和推荐软件）

+   最低 Python 版本 3.5

这些要求是本书中代码示例的基础。可以合理地期望，只要您的 Python 版本为 3.5 或更高，代码示例应该可以在树莓派 3 型 B 或不同版本的 Raspbian OS 上无需修改即可运行。

你会在 GitHub 存储库的`chapter10`文件夹中找到本章的源代码，该存储库位于[`github.com/PacktPublishing/Practical-Python-Programming-for-IoT`](https://github.com/PacktPublishing/Practical-Python-Programming-for-IoT)。

您需要在终端中执行以下命令来设置虚拟环境并安装本章代码所需的 Python 库：

```py
$ cd chapter10              # Change into this chapter's folder
$ python3 -m venv venv      # Create Python Virtual Environment
$ source venv/bin/activate  # Activate Python Virtual Environment
(venv) $ pip install pip --upgrade        # Upgrade pip
(venv) $ pip install -r requirements.txt  # Install dependent packages
```

以下依赖项已从`requirements.txt`中安装：

+   **PiGPIO**：PiGPIO GPIO 库（[`pypi.org/project/pigpio`](https://pypi.org/project/pigpio)）

本章练习所需的电子元件如下：

+   1 x MG90S 业余舵机（或等效的 3 线 5 伏特业余舵机）。参考资料表：[`www.alldatasheet.com/datasheet-pdf/pdf/1132104/ETC2/MG90S.html`](https://www.alldatasheet.com/datasheet-pdf/pdf/1132104/ETC2/MG90S.html)

+   1 x L293D **集成电路**（**IC**）（确保它带有 D - 也就是 L293**D**，而不是 L293）。参考资料表：[`www.alldatasheet.com/datasheet-pdf/pdf/89353/TI/L293D.html`](https://www.alldatasheet.com/datasheet-pdf/pdf/89353/TI/L293D.html)

+   1 x 28BYJ-48 步进电机（5 伏特，64 步，1:64 齿轮）。注意：28BYJ-48 有 5 伏特和 12 伏特两种，不同的配置步数和齿轮。参考资料表：[`www.alldatasheet.com/datasheet-pdf/pdf/1132391/ETC1/28BYJ-48.html`](https://www.alldatasheet.com/datasheet-pdf/pdf/1132391/ETC1/28BYJ-48.html)

+   2 x 尺寸 130（R130）直流电机额定为 3-6 伏特（最好具有静态电流<800 毫安），或具有兼容电压和电流额定值的替代直流电机

+   外部电源 - 至少是 3.3V/5V 的面包板可安装电源

让我们开始学习如何在树莓派、Python 和 PiGPIO 中使用舵机。

# 使用 PWM 来旋转舵机

常见的舵机或舵机是内部齿轮电机，允许您将其轴精确旋转到 180 度弧度内的特定角度。它们是工业机器人和玩具的核心组件，我们都熟悉玩具中的舵机，如遥控汽车、飞机和无人机中的舵机。

在*图 10.1*中显示了一个全尺寸的业余风格舵机、一个微型舵机和一组排针，这些对于帮助将舵机连接到面包板非常有用，我们将在本节后面构建电路时需要用到：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/2de779f7-fcbb-40f5-830f-0182445471ba.png)

图 10.1 - 舵机

舵机的一个很好的特性是它们基本上是一种即插即用的设备——在我们将它们连接到电源后，我们只需要发送一个编码了我们想要舵机旋转到的角度的 PWM 信号，然后就完成了。没有集成电路、没有晶体管，也没有任何其他外部电路。更好的是，舵机控制是如此普遍，以至于许多 GPIO 库——包括 PiGPIO——都包括了方便的控制方法。

让我们通过连接一个舵机到我们的树莓派来开始我们的舵机探索。

## 连接舵机到你的树莓派

我们舵机示例的第一个任务是将其连接到电源和我们的树莓派。显示这种布线的原理图如下：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/e4baeb96-c9b1-447e-93e6-e6b9e0e9d56e.png)

图 10.2 – 舵机布线原理图

让我们开始使用面包板布线我们的舵机，如下所示：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/39734f78-1f47-465b-b1bb-b622f221f12c.png)

图 10.3 – 舵机面包板布局

在我们逐步介绍布线程序之前，我首先想简要讨论一下舵机出线的颜色。虽然舵机线的颜色有些是标准的，但在不同的制造商和舵机之间可能会有所不同。在连接你的舵机时，请使用以下提示在*步骤 4*、*5*和*6*。如果你的舵机有我没有列在下面列表中的颜色线，你需要查阅你舵机的数据表。

常见的舵机线颜色如下：

+   棕色或黑色的线连接到 GND

+   红色线连接到+5 伏

+   橙色、黄色、白色或蓝色的线是信号/PWM 输入线，连接到 GPIO 引脚

以下是创建面包板构建的步骤。步骤编号与*图 10.3*中的黑色圆圈中的数字相匹配：

1.  将左侧和右侧的负电源轨道连接在一起。

1.  将树莓派上的 GND 引脚连接到左侧的负电源轨道。

1.  将舵机连接到面包板。如前所述，并如*图 10.1*所示，你需要一组排针（或者，作为替代，公对公跳线）来将你的舵机连接到你的面包板。

1.  将舵机的黑色线（负/GND）连接到右侧电源轨道的负极。

1.  将舵机的红色线（5 伏电源）连接到右侧电源轨道的正极。

1.  将舵机的信号线连接到树莓派上的 GPIO 21。

1.  将外部 5 伏电源的正输出端连接到右侧电源轨道的正极。

1.  将电源供应的负输出端连接到右侧电源轨道的负极。

你需要使用外部的 5 伏电源(*步骤 7*和*8*)来为你的舵机供电。像 MG90S 这样的小型舵机在没有负载的情况下旋转时使用的电流约为 200 毫安，如果你在舵机上连接了重负载或者强行阻止旋转，最大电流为 400 毫安。直接从你的树莓派的 5 伏引脚中提取这个电流可能足以导致它重置。

许多廉价的类似汽车的玩具都有一个硬左/右模拟舵机用于他们的转向机构。它可能看起来像一个舵机，但实际上，它只是一个带有一些齿轮和弹簧的基本直流电机，用于创建硬左/右转向角度。当电机没有参与时，弹簧会将舵机返回到中心。如果你不能对角度进行精细控制，那它就不是一个真正的舵机。

在我们开始编写一些代码之前，让我们快速看一下 PWM 是如何用来控制舵机的。这将让你了解当我们到达代码时发生了什么。

## 如何使用 PWM 控制舵机

舵机通常需要大约 50 赫兹的 PWM 信号（50 赫兹左右的一些变化是可以的，但我们将坚持使用 50 赫兹作为常见参考点），以及在 1.0 毫秒和 2.0 毫秒之间的脉冲宽度来确定旋转角度。脉冲宽度、占空比和角度之间的关系在*图 10.4*中有所说明。如果你现在还没有完全理解，不要担心。当我们看到我们的舵机动作并在下一节中审查与舵机相关的代码时，这些应该会更清楚：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/ba7e9381-16b5-46d7-bda5-9ed6e7582115.png)

图 10.4 - 舵机的脉冲宽度、占空比和角度

我们之前没有涵盖脉冲宽度与我们之前对 PWM 的覆盖范围的关系；然而，这只是描述占空比的另一种方式。

这里有一个例子：

+   如果我们有一个 50 赫兹的 PWM 信号（即每秒 50 个周期），那么这意味着 1 个 PWM 周期需要*1 / 50 = 0.02*秒，或者 20 毫秒。

+   因此，以 1.5 毫秒的脉冲宽度表示的占空比为*1.5 毫秒/20 毫秒=0.075*，乘以 100 得到占空比为 7.5%。

往回推，我们有以下内容：

+   7.5%的占空比除以 100 是 0.075。然后，*0.075 x 20 毫秒=1.5 毫秒*，即 1.5 毫秒的脉冲宽度。

如果你更喜欢一个公式来描述*脉冲宽度*、*频率*和*占空比*的关系，这里有一个：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/5a2e6517-ec08-4b37-8577-1529da534f55.png)

要转换回来，我们有以下内容：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/2290e598-7bf5-4ddf-b717-e37eab32ec44.png)

好了，数学的部分就到此为止。让我们运行并查看 Python 代码来让我们的舵机移动。

## 运行和探索舵机代码

我们即将运行的代码可以在`chapter10/servo.py`文件中找到。我建议在继续之前先查看源代码，以便对文件的内容有一个整体的了解。

当你运行`chapter10/servo.py`文件中的代码时，你的舵机应该会左右旋转几次。

让我们从代码开始，首先是在第 1 行定义的一些脉冲宽度变量：

```py
LEFT_PULSE  = 1000   # Nano seconds          # (1)
RIGHT_PULSE = 2000
CENTER_PULSE = ((LEFT_PULSE - RIGHT_PULSE) // 2) + RIGHT_PULSE  # Eg 1500
```

这些脉冲宽度代表了我们舵机的极端左右旋转。

请注意，`LEFT_PULSE`和`RIGHT_PULSE`的值以纳秒为单位，因为这是 PiGPIO 舵机函数使用的单位。

`LEFT_PULSE = 1000`和`RIGHT_PULSE = 2000`这些值是你经常看到的完美世界值。实际上，你可能需要对这些变量进行轻微调整，以便使舵机完全旋转。例如，我的测试舵机需要`LEFT_PULSE = 600`和`RIGHT_PULSE = 2450`这些值才能实现完全旋转。如果你调整得太远，舵机在完全左转或右转时会保持连接并发出嘎吱嘎吱的声音。如果发生这种情况，立即断开电源以防止对舵机造成损坏，并重新调整数值。

如果你的舵机向后旋转 - 例如，当你期望它向右旋转时它向左旋转 - 交换`LEFT_PULSE`和`RIGHT_PULSE`的值。或者，只需将你的舵机倒置。

在第 2 行，我们定义了`MOVEMENT_DELAY_SECS= 0.5`变量，我们稍后需要在舵机移动之间添加延迟：

```py
  # Delay to give servo time to move
  MOVEMENT_DELAY_SECS = 0.5            # (2)
```

当你使用舵机并发送 PWM 旋转信号时，你会发现它们的行为是异步的。也就是说，代码不会阻塞，直到舵机完成旋转。如果我们打算进行许多快速的舵机移动，并希望它们完全完成，我们必须添加一个短暂的延迟，以确保舵机有时间完成旋转。我们很快将介绍的`sweep()`函数中就有一个例子。0.5 秒的延迟只是一个建议，所以可以随意尝试不同的数字。

从第 3 行开始，我们定义了三个基本函数来控制我们的舵机：

```py
 def left():                                               # (3)
       pi.set_servo_pulsewidth(SERVO_GPIO, LEFT_PULSE)

 def center():
       pi.set_servo_pulsewidth(SERVO_GPIO, CENTER_PULSE)

 def right():
       pi.set_servo_pulsewidth(SERVO_GPIO, RIGHT_PULSE)
```

`left()`函数只是使用 PiGPIO 的`set_servo_pulsewidth()`方法将 PWM 脉冲宽度设置为`LEFT_PULSE`在伺服的 GPIO 引脚上。这是 PiGPIO 提供的伺服控制的便利函数，作为使用我们在许多先前章节中看到的`set_PWM_dutycycle()`和`set_PWM_frequency()`方法的实际替代方案。在我们回顾了代码之后，我们将更多地谈论这些方法。

`center()`和`right()`函数执行与`left()`相应的等效操作。

如果您将伺服旋转到指定的角度并尝试用手移动齿轮，您会注意到伺服会抵抗变化。这是因为伺服持续以 50 赫兹的速率接收通过`set_servo_pulsewidth()`设置的最后一个脉冲，因此它会抵制任何试图改变其设置位置的尝试。

在前一节中，当我们将伺服连接到树莓派时，我们提到了伺服的最大电流约为~400+mA。前面的段落是一个例子，其中伺服吸取了这个最大电流。当伺服接收到脉冲宽度指令时，它会抵抗任何改变其位置的力，导致更多的电流使用。这与我们在第七章中讨论的直流电机的空载电流原理类似，*打开和关闭物品*。

如果您将伺服的脉冲宽度设置为零，就像我们在第 4 行的`idle()`函数中所做的那样，您现在会发现可以轻松地用手旋转伺服。当我的测试伺服处于空闲状态（或静止状态）时，它大约使用了 6.5 毫安：

```py
   def idle():                                      # (4)
      pi.set_servo_pulsewidth(SERVO_GPIO, 0)
```

到目前为止，我们已经看到了如何使伺服向左、中间和右边旋转，但是如果我们想将其旋转到特定的角度怎么办？很简单（有点），我们只需要一点数学，就像在第 5 行的`angle()`函数中所示：

```py
  def angle(to_angle):                                   # (5)
      # Restrict to -90..+90 degrees
      to_angle = int(min(max(to_angle, -90), 90))

      ratio = (to_angle + 90) / 180.0                    # (6)
      pulse_range = LEFT_PULSE - RIGHT_PULSE
      pulse = LEFT_PULSE - round(ratio * pulse_range)    # (7)

      pi.set_servo_pulsewidth(SERVO_GPIO, pulse)
```

`angle()`函数接受-90 到+90 度范围内的角度（0 度为中心），在第 6 行计算出我们输入角度相对于我们伺服 180 度范围的比率，然后在第 7 行推导出相应的脉冲宽度。然后将此脉冲宽度发送到伺服，它将相应地调整其角度。

最后，我们在第 10 行遇到了`sweep()`函数。这是在您运行此代码时提供了伺服左右扫描运动的函数：

```py
 def sweep(count=4):                        # (10)
      for i in range(count):
          right()
          sleep(MOVEMENT_DELAY_SECS)
          left()
          sleep(MOVEMENT_DELAY_SECS)
```

在这个函数中，我们看到了`sleep(MOVEMENT_DELAY_SECS)`的使用，这是必要的，以便给伺服完成每个旋转请求的时间，因为伺服的异步性质。如果您注释掉两个`sleep()`调用，您会发现伺服向左旋转并停止。这是因为当`for`循环迭代（没有`sleep()`）时，每个`left()`调用会覆盖先前的`right()`调用，依此类推，最后在循环完成之前调用的是`left()`。

我们刚刚看到了如何使用 PiGPIO 及其面向伺服的 PWM 函数`set_servo_pulsewidth()`来控制伺服。如果您对使用`set_PWM_frequency()`和`set_PWM_dutycycle()`函数实现伺服的实现感兴趣，您会在`chapter10`文件夹中找到一个名为`servo_alt.py`的文件。它在功能上等同于我们刚刚介绍的`servo.py`代码。

这样就结束了我们的伺服示例。您学到的知识以及代码示例将为您提供开始在自己的项目中使用伺服所需的一切！我们的重点是使用角度运动伺服；然而，您学到的核心内容也可以通过一些试验和实验（主要是确定正确的脉冲宽度）来适应*连续旋转伺服*，我将在下一节中简要提到。

让我们用一个简短的考虑来结束我们对伺服的讨论，讨论不同类型的伺服。

## 不同类型的伺服

我们的示例使用了常见的 3 线，180 度角舵机。虽然这是一种非常常见的舵机类型，但也有其他变体，包括连续旋转舵机，具有三根以上线的舵机和特殊用途舵机：

+   **连续旋转舵机**：有 3 根线，使用与 3 线角度舵机相同的 PWM 原理，只是 PWM 脉冲宽度确定了舵机的旋转*方向*（顺时针/逆时针）和*速度*。

由于它们的内部控制电路和齿轮装置，连续旋转舵机是直流电机和 H-Bridge 控制器的便捷低速/高扭矩替代品（我们将在下一节中介绍）。

+   **4 线舵机**：这些舵机有一组三根线和一根松散的第四根线。这第四根线是舵机的模拟输出，可用于检测角度。如果您需要在启动程序时知道舵机的静止角度，这将非常有用。

舵机使用嵌入电位器来跟踪它们的位置。第四根线连接到这样的电位器。

+   **特殊用途或重型工业用途舵机**：具有不同的接线配置和使用要求-例如，它们可能没有内部电路来解码 PWM 信号，并且需要用户提供和创建电路来执行此功能。

我们现在已经了解了常见的业余舵机的工作原理，并且还发现了如何使用 PWM 在 Python 中设置它们的旋转角度。在下一节中，我们将学习更多关于直流电机以及如何使用 H-Bridge 这种集成电路来控制它们。

# 使用 H-Bridge 集成电路来控制电机

在第七章中，*打开和关闭东西*，我们学习了如何使用晶体管打开和关闭直流电机，并且还看到了如何使用 PWM 控制电机的速度。我们单个晶体管电路的一个限制是电机只能单向旋转。在本节中，我们将探讨一种让我们能够让电机在前后两个方向旋转的方法-使用所谓的*H-Bridge*电路。

H-Bridge 中的 H 来自于基本 H-Bridge 电路原理图（由四个单独的晶体管创建）形成字母 H 的感知。

如果您在 eBay 等网站上搜索 H-Bridge 模块，您将会发现许多相同目的的现成模块，我们将在本节中介绍。我们将在面包板上构建一个复制模块。一旦您的面包板复制品运行并了解其工作原理，您就能够理解这些现成模块的构造。

我们可以通过几种方式创建 H-Bridge 来驱动我们的电机：

+   只需使用预制模块（模块和集成电路也可以称为电机驱动器或电机控制器）。这是最简单的方法。

+   使用离散元件创建 H-Bridge 电路-例如，四个晶体管，许多二极管，一些电阻和大量的导线连接它们。这是最困难的方法。

+   使用集成电路（内部组合了所有必要的离散部件）。

舵机，就像我们在上一节中使用的那样，由连接到 H-Bridge 样式电路的直流电机组成，该电路允许电机前后移动，以创建舵机的左右旋转。

我们将选择最后一种选择，并使用 L293D，这是一种常见且低成本的 H-Bridge 集成电路，我们可以用它来构建电机控制电路。

以下是从 L293D 的数据表中提取的基本规格：

+   连续电流为 600 毫安，峰值/脉冲为 1.2 安。作为提醒，我们在第七章中探讨了电机和电流的使用，*打开和关闭东西*。

+   它可以控制电压在 4.5 伏至 36 伏之间的电机。

+   它包括内部飞回二极管，因此我们不需要添加自己的。这就是 L293**D**中 D 的含义。如果您需要复习飞回二极管，请参阅第七章，*打开和关闭*。

+   它包括两个通道，因此可以同时驱动两个直流电机。

如果您想购买一个不同的电机驱动 IC 用于项目（例如，如果您需要一个更大电流的 IC），请记住要检查数据表，看看它是否嵌入了飞回二极管，否则您将需要自己提供。

让我们建立电路来控制我们的电机。

## 构建电机驱动电路

在本节中，我们将构建 H 桥电路，用于控制两个直流电机。以下原理图描述了我们将创建的电路。虽然这个电路看起来很繁忙，但我们的大部分工作将只是连接 L293D IC 的引脚到树莓派、电源和电机：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/655775d0-d70a-48ac-927a-ccd34687f67a.png)

图 10.5 - L293D 和电机原理图

由于有很多导线连接要完成，我们将在面包板上分四部分构建这个电路。

我们将在电路构建中使用一个 IC。许多 IC（包括 L293D）对静电放电（ESD）敏感，如果暴露于静电放电，它们可能会受到损坏。一般规则是，您应该避免用手指触摸 IC 的引脚/腿，以免您体内的任何静电荷被释放到 IC 上。

让我们从第一部分开始，如下图所示：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/de40640a-3ebe-4491-ac76-5062cc6c3766.png)

图 10.6 - L293D 面包板布局（第一部分，共 3 部分）

以下是我们开始面包板构建的步骤。步骤编号与*图 10.6*中黑色圆圈中的数字相匹配：

1.  首先将 L293D IC 放入面包板中，确保 IC 的引脚/腿朝向面包板顶部。IC 的引脚 1 通常由引脚旁边的小圆凹陷或点指示。在我们的插图中，为了方便查看，这个点是白色的；然而，它很可能与 IC 的外壳颜色相同。如果没有点，IC 的一端通常也有一个凹口部分。当您将 IC 的凹口朝向远离您时，引脚 1 是顶部左侧的引脚。

1.  将树莓派的 5V 引脚连接到左侧电源轨的正电源。

1.  将树莓派的 GND 引脚连接到左侧电源轨的负电源。

1.  将 GPIO 18 连接到 L293D 的引脚 1。

1.  将 GPIO 23 连接到 L293D 的引脚 2。

1.  将 GPIO 24 连接到 L293D 的引脚 7。

1.  将跳线引脚连接到 L293D 的引脚 3。此引脚的另一端（标有**Output 1Y**）目前未连接到任何东西。

1.  将跳线引脚连接到 L293D 的引脚 6。此引脚的另一端（标有**Output 2Y**）目前未连接到任何东西。

1.  使用跳线，将 L293D 的引脚 4 和引脚 5 连接在一起。

1.  最后，将 L293D 的引脚 4 和引脚 5 连接到左侧电源轨的负电源。

我们刚刚完成的大部分工作涉及 L293D 的*通道 1*的布线。作为提醒，L293D 有两个输出通道，这意味着我们可以控制两个直流电机。

如果您回顾*图 10.6*，您会注意到（放置在*步骤 7*和*8*处）的导线构成了通道 1 的输出。在本节的后面，我们将把电机连接到这些导线。此外，在图中，您会注意到 GPIO 18、23 和 24 被标记为通道 1 控制 GPIOs。我们将学习这些 GPIO 是如何用于控制通道 1 电机的，当我们讨论伴随这个电路的代码时。

接下来，我们构建的下一部分主要涉及布线 L293D 的通道 2。这更多或多是我们刚刚执行的布线的镜像：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/f520647e-b1bc-49df-b7d9-7ba16d839315.png)

图 10.7 - L293D 面包板布局（第二部分）

以下是完成我们面包板搭建的第二部分所需遵循的步骤。 步骤编号与*图 10.7*中黑色圆圈中的数字相匹配：

1.  将 L293D 的引脚 16 连接到左侧电源轨道的正轨道。 连接到引脚 16 的这个 5 伏电源为*IC 的内部电路*提供电源-它不是通道输出的电源（那是我们的电机）。 我们将在搭建的第三部分中将外部电源连接到 IC 以为通道的电机供电。

1.  将 GPIO 16 连接到 L293D 的引脚 9。

1.  将 GPIO 20 连接到 L293D 的引脚 10。

1.  将 GPIO 21 连接到 L293D 的引脚 15。

1.  将跳线引线连接到 L293D 的引脚 14。 此引线的另一端（标有**Output 4Y**）目前未连接到任何东西。

1.  将跳线引线连接到 L293D 的引脚 11。 此引线的另一端（标有**Output 3Y**）目前未连接到任何东西。

1.  使用跳线将 L293D 的引脚 12 和引脚 13 连接在一起。

1.  最后，将 L293D 的引脚 12 和引脚 13 连接到右侧电源轨道的负轨道。

现在我们已经连接了通道 2 的输出，我们的第三个任务是连接外部电源：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/ab5d7593-df76-4bdd-811b-04ce6417ee24.png)

图 10.8 - L293D 面包板布局（第三部分）

以下是完成我们面包板搭建的第三部分所需遵循的步骤。 步骤编号与*图 10.8*中黑色圆圈中的数字相匹配：

1.  将电源的正输出端连接到右侧电源轨道的正轨道。

1.  将电源的负输出端连接到右侧电源轨道的负轨道。

1.  将 L293D 的引脚 8 连接到右侧电源轨道的正轨道。 L293D 的引脚 8 提供了用于驱动输出通道的输入电源。

1.  最后，使用跳线将左侧和右侧电源轨道的负轨道连接起来。

这是我们的面包板布局完成。 但是，还有一个最后的任务，我们要连接我们的电机。 根据以下图表中的示例，您可以将一个电机连接到每个输出通道：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/04f2999e-7469-4e8a-9e33-336abaed04d8.png)

图 10.9 - L293D 电机连接

干得好！那是很多布线。 我想你现在面包板上的电线纠结看起来并不像插图那样优雅！ 请务必花时间仔细检查这个电路的布线，因为错误放置的电线会阻止电路按预期工作。

在我们的电路搭建中，在第三部分，*步骤 3*中，我们将外部 5 伏电源连接到 L293D 的引脚 8。 这是用于驱动每个输出通道和因此我们的电机的电源。 如果您希望使用需要与 5 伏不同电压的电机，您可以更改此供电电压以满足您的需求，但前提是 L293D 的电源电压必须在 4.5 伏至 36 伏的范围内。 还要记住（如本节开头提到的），您的电机不应该吸取超过 600 毫安的持续电流（全开）或 1.2 安的峰值电流（例如，当使用 PWM 时，我们将在编码时介绍）。

如果您阅读 L293D 的数据表，它可能被称为*四路半 H 驱动器*。 驱动器类型 IC 的数据表可能具有各种不同的标题和措辞。 这里的重要一点是，为了驱动我们的电机向前和向后，我们需要一个完整的 H-Bridge 电路，因此对于 L293D：Quad=4 和 half=0.5，因此*4 x 0.5 = 2 -*也就是说，2 个完整的 H-Bridge-因此，我们可以控制 2 个电机。

一旦您创建了面包板电路并连接了电机，我们将运行示例代码并讨论其工作原理。

## 运行示例 H-Bridge 代码以控制电机

现在您已经创建了 H 桥驱动器电路并连接了电机，让我们运行能让电机旋转的代码。

这一节有两个文件，它们可以在`chapter10/motor_class.py`和`chapter10/motor.py`中找到。运行`chapter10/motor.py`中的代码，您的电机将会转动，改变速度和方向。

在电机轴上贴一张胶带，以便更容易地看到它们旋转的方向。

当您确认您的电路可以与示例代码一起工作时，我们将继续讨论代码。由于 L293D 可以驱动两个电机，公共代码已经被抽象成了`motor_class.py`，它被`motor.py`导入并用于驱动我们的两个独立电机。

我们将从`motor.py`开始。 

### motor.py

从第 1 行开始，我们导入 PiGPIO 和`motor_class.py`文件中定义的`Motor`类，然后定义了几个变量，描述了我们如何将 L293D 连接到树莓派的 GPIO 引脚：

```py
import pigpio                    # (1)
from time import sleep
from motor_class import Motor

# Motor A
CHANNEL_1_ENABLE_GPIO = 18       # (2)
INPUT_1Y_GPIO = 23 
INPUT_2Y_GPIO = 24

# Motor B
CHANNEL_2_ENABLE_GPIO = 16       # (3)
INPUT_3Y_GPIO = 20
INPUT_4Y_GPIO = 21
```

回顾*图 10.3*和*图 10.4*，如果我们考虑电机 A（通道 1）电路的一侧，我们会看到逻辑引脚连接到第 2 行的 GPIO 23 和 24 - `INPUT_1Y_GPIO = 23` 和 `INPUT_2Y_GPIO = 24`。这些逻辑引脚（以及我们很快将介绍的使能引脚）用于设置电机的状态和旋转方向。这些状态的真值表如下所示。

这个表格是从 L293D 的数据表中获取的，并进行了重新格式化和补充，以匹配我们的代码和电路：

| **行号** | **使能 GPIO** | **逻辑 1 GPIO** | **逻辑 2 GPIO** | **电机功能** |
| --- | --- | --- | --- | --- |
| 1 | `HIGH` 或 > 0% 占空比 | 低 | 高 | 向右转 |
| 2 | `HIGH` 或 > 0% 占空比 | 高 | 低 | 向左转 |
| 3 | `HIGH` 或 > 0% 占空比 | 低 | 低 | 刹车 |
| 4 | `HIGH` 或 > 0% 占空比 | 高 | 高 | 刹车 |
| 5 | `LOW` 或 0% 占空比 | N/A | N/A | 关闭电机 |

L293D 有两个使能引脚 - 每个通道一个（即每个电机一个） - 例如，在前面的代码中的第 3 行，`CHANNEL_1_ENABLE_GPIO = 18`。使能引脚就像每个通道的主开关。当使能引脚设置为高时，它会打开相关的通道，从而给电机供电。或者，如果我们使用 PWM 脉冲使能引脚，我们可以控制电机的速度。当我们探索`motor_class.py`文件时，我们将很快看到处理逻辑和使能引脚的代码。

接下来，我们将创建`pigpio.pi()`的单个实例，如第 4 行所示，然后我们将创建两个`Motor`的实例来代表我们的两个物理电机：

```py
pi = pigpio.pi()                 # (4)
motor_A = Motor(pi, CHANNEL_1_ENABLE_GPIO, INPUT_1Y_GPIO, INPUT_2Y_GPIO)
motor_B = Motor(pi, CHANNEL_2_ENABLE_GPIO, INPUT_3Y_GPIO, INPUT_4Y_GPIO)
```

在我们创建了`motor_A`和`motor_B`类之后，我们使用这些类对电机进行了一些操作，如下面的代码所示，从第 5 行开始 - 这就是您在上一节运行代码时所见到的：

```py
 print("Motor A and B Speed 50, Right") 
 motor_A.set_speed(50)                                # (5)
 motor_A.right()
 motor_B.set_speed(50)
 motor_B.right() 
 sleep(2)

 #... truncated ... 

 print("Motor A Classic Brake, Motor B PWM Brake")
 motor_A.brake()                                      # (6) 
 motor_B.brake_pwm(brake_speed=100, delay_millisecs=50)
 sleep(2)
```

注意第 6 行的刹车，并观察电机。一个电机的刹车效果比另一个好吗？当我们在下一节的最后讨论两个刹车功能时，我们将进一步讨论这个问题。

让我们继续看`motor_class.py`。这是我们的树莓派与 L293D 集成的代码所在之处。

### motor_class.py

首先，我们看到`Motor`类的定义及其构造函数：

```py
class Motor:

  def __init__(self, pi, enable_gpio, logic_1_gpio, logic_2_gpio):

    self.pi = pi
    self.enable_gpio = enable_gpio
    self.logic_1_gpio = logic_1_gpio
    self.logic_2_gpio = logic_2_gpio

    pi.set_PWM_range(self.enable_gpio, 100) # speed is 0..100       # (1)

    # Set default state - motor not spinning and 
    # set for right direction.
    self.set_speed(0) # Motor off                                   # (2)
    self.right()
```

在第 1 行，我们定义了 PiGPIO PWM 使能引脚的占空比范围为`0..100`。这定义了我们可以在`set_speed()`函数中使用的最大范围值（即`100`）。

范围`0..100`表示我们有 101 个离散的整数 PWM 步骤，这方便地映射到 0%到 100%的占空比。如果您指定一个更高的数字，这并不意味着更多的占空比（或更高的电机速度）；它只是改变了步骤的粒度 - 例如，默认的 PWM 范围`0..255`给我们 256 个离散的步骤，其中 255 = 100%的占空比。

请记住，我们即将讨论的内容涵盖了 L293D IC 电路的一个通道（一个电机）。我们讨论的所有内容也适用于另一个通道 - 只是 GPIO 引脚和 IC 引脚会有所变化。

我们的构造函数通过将电机初始化为关闭（零速度），并将电机默认为右旋转方向来完成，如前面代码中的第 2 行所示。

接下来，我们遇到了几个函数，我们用它们来使我们的电机旋转。我们在第 3 行和第 4 行看到了`right()`和`left()`方法，它们根据前表中的第 1 行和第 2 行改变了 L293D 的逻辑引脚的高低状态。

```py
 def right(self, speed=None):           # (3)
     if speed is not None:
         self.set_speed(speed)

     self.pi.write(self.logic_1_gpio, pigpio.LOW)
     self.pi.write(self.logic_2_gpio, pigpio.HIGH)

 def left(self, speed=None):           # (4)
     if speed is not None:
         self.set_speed(speed)

     self.pi.write(self.logic_1_gpio, pigpio.HIGH)
     self.pi.write(self.logic_2_gpio, pigpio.LOW)
```

我们可以通过查询逻辑引脚的当前状态来检查我们的电机是否设置为左旋转或右旋转，就像在`is_right()`中所示的那样。请注意，`is_right()`中查询的 GPIO 状态与`right()`中设置的状态相匹配。

```py
   def is_right(self):                              # (5)
       return not self.pi.read(self.logic_1_gpio)   # LOW 
              and self.pi.read(self.logic_2_gpio)   # HIGH
```

我们在第 6 行的以下代码中看到了`set_speed()`方法中使用`set_PWM_dutycycle()`，在这里我们通过脉冲 L293D 的使能引脚来设置电机的速度。脉冲使能引脚的脉冲是使用我们在第七章中使用的相同基本原理进行的，*打开和关闭事物*，当我们脉冲一个晶体管来设置电机的速度时。

```py
    def set_speed(self, speed):                      # (6)
        assert 0<=speed<=100
        self.pi.set_PWM_dutycycle(self.enable_gpio, speed)
```

您可以通过将速度设置为`0`来停止电机，这实际上是切断电机的电源（0%占空比=引脚低电平）。

接下来，我们发现了两种方法，即`brake()`和`brake_pwm()`，它们可以用于*快速*停止电机。制动和通过切断电源（即`set_speed(0)`）来停止电机的区别在于，`set_speed(0)`允许电机逐渐减速 - 这是前表中第 5 行的状态：

```py
    def brake(self):                # (7)
        was_right = self.is_right() # To restore direction after braking

        self.set_speed(100)
        self.pi.write(self.logic_1_gpio, pigpio.LOW)
        self.pi.write(self.logic_2_gpio, pigpio.LOW)
        self.set_speed(0)

        if was_right:
            self.right()
        else:
            self.left()
```

当您在上一节中运行此代码，并且如果您自己尝试两种制动功能，我的猜测是您会发现`brake()`不起作用（或者根本不起作用），而`brake_pwm()`函数会起作用。

```py
    def brake_pwm(self, brake_speed=100, delay_millisecs=50):    # (8)
        was_right = None # To restore direction after braking
        if self.is_right(): 
            self.left(brake_speed)
            was_right = True
        else:
            self.right(brake_speed)
            was_right = False
        sleep(delay_millisecs / 1000)
        self.set_speed(0)
        if was_right:
            self.right()
        else:
            self.left()
```

让我们讨论为什么我们定义了两种不同的制动方法，以及为什么一种方法比另一种方法更有效。

`brake()`的实现是经典的电机制动实现方式，其中逻辑 GPIO 同时设置为高电平或低电平，就像前表中的第 3 行或第 4 行。然而，问题在于，这种逻辑的性能可能会因您使用的 IC（内部构造方式）、电机、电压和电流使用情况而有所不同。在我们的示例中，我们使用的是一个小电机（轴上没有负载）、小电压和电流，以及一个 L293D IC。所有这些的结果是，经典制动方法不起作用，或者效果不佳。

我们使用 L293D IC 是因为它很受欢迎、易得、成本低。它已经生产了很多年，您将毫无问题地找到基于这个 IC 的示例电路和代码，用于各种应用。然而，它并不是最有效的 IC。这是经典制动在某些情况下不起作用的一个因素。

`brake_pwm(reverse_speed, delay_secs)`的实现采用了一种不同且更可靠的制动方式，即向电机施加一个小的相反电压。您可以使用`brake_speed`和`delay_millisecs`参数来调整制动，如果需要的话 - 速度和延迟太小，制动将不起作用，太大则电机会反向。

您是否注意到在全速（即`set_speed(100)`）时，您的电机转速比直接连接到 5 伏特时要慢？L293D 中存在一个约 2 伏特的电压降。即使 V[cc1]（电机电源）连接到 5 伏特，电机也没有获得这个完整的 5 伏特（更像是约 3 伏特）。如果您使用的是可变电源（即不是 3.3V/5V 面包板电源），您可以将输入电压增加到 V[cc1]周围的 7 伏特。然后电机将获得约 5 伏特（您可以使用万用表来验证）。

恭喜！您刚刚学会了如何操作伺服并掌握了直流电机在速度和制动方向上的控制。您刚刚获得的电路、代码和技能可以适应许多需要创建运动和角运动的应用，例如机器人车或机械臂。您甚至可以使用这些技能来改装电动玩具和其他电动小工具，并使它们可以由您的树莓派控制。

如果您想进一步扩展您的知识，您可能想探索如何从单独的元件（如晶体管、电阻和二极管）创建 H 桥电路。虽然有各种方法可以完成这个电路，但我们在本章和我们在第七章中使用晶体管时，涵盖了概念和组件的核心基础，*打开和关闭东西*。

干得好！在本节中，我们学习了如何使用 L293D H 桥使直流电机旋转、改变方向和制动。在下一节中，我们将看看 L293D 的另一种用途，并了解如何使用它来控制步进电机。

# 步进电机控制简介

步进电机在精度和扭矩方面是一种独特的电机类型。与直流电机类似，步进电机可以在两个方向上连续旋转，同时它们可以像伺服一样被精确控制。

在下图中是一个 28BYJ-48 步进电机，以及可以用来将电机连接到面包板的引脚：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/e7d525e8-4b34-4f5b-acc9-555258724de3.png)

图 10.10 - 28BYJ-48 步进电机

步进电机的理论和实践可能会很快变得复杂！有不同形式和类型的步进电机，许多需要考虑的变量，如步距角和齿轮，以及各种布线和控制方式。我们不可能在这里涵盖所有这些参数，也不能深入了解步进电机的低级细节。

相反，我们将介绍一种常见且易得的步进电机 28BYJ-48 的实际操作。一旦您了解了适用于 28BYJ-48 的基本原理，您就可以扩展对步进电机的知识。

当您第一次开始使用步进电机时，控制步进电机可能会令人困惑和琐碎。与直流电机和伺服不同，您需要了解步进电机在机械和代码层面上的工作原理才能控制它们。

我们参考的 28BYJ-48 的基本规格如下：

+   5 伏特（确保您的步进电机是 5 伏特，因为 28BYJ-48 也有 12 伏特）。

+   64 的步距角，1:64 的齿轮比，每 360 度旋转*64 x 64 = 4,096*步。

使用步距角、齿轮比和序列，我们可以计算旋转我们的步进电机 360 度所需的逻辑步数：*64 x 64 / 8 = 512* *步*。

接下来，我们将把我们的步进电机连接到我们的树莓派。

## 将步进电机连接到 L293D 电路

为了将我们的步进电机连接到树莓派，我们将重复使用我们的 L293D 电路，如前一节中的*图 10.8*所示。我们需要做的是：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/6cac6ea0-8f96-4692-80ec-3fff638d1ff2.png)

图 10.11 - 28BYJ-48 步进电机接线连接

以下步骤与*图 10.11*中显示的编号相匹配。请记住，我们从您在*构建电机驱动器电路*部分完成的电路开始，并在*图 10.8*中显示：

在*步骤 2*到*5*中，我们将在我们的面包板电路中连接步进电机。建议使用引脚排针（如*图 10.10*中所示）将电机连接到面包板上的空行，然后将 L293D 的输出线连接到与步骤中提到的线颜色相匹配的适当行。

1.  如果您还没有这样做，请断开两个直流电机与现有电路的连接。

1.  将你的步进电机的橙线连接到*图 10.8.*中标有**Output 4Y**的线上。

1.  将你的步进电机的黄线连接到*图 10.8.*中标有**Output 3Y**的线上。

1.  将你的步进电机的粉红线连接到*图 10.8.*中标有**Output 2Y**的线上。

1.  将你的步进电机的蓝线连接到*图 10.8.*中标有**Output 1Y**的线上。

在我们的示例场景中，我们使用我们的 L293D H-Bridge 来驱动我们的步进电机作为*双极*步进电机。在步进电机方面，你会遇到*双极*和*单极*这两个术语。这些术语与电机的接线方式有关，这影响了你将如何控制它们。在学习的这个阶段，对双极和单极步进电机之间的区别进行简化的区分如下：

+   一个*双极*步进电机需要一个能够改变电流流向的驱动电路。

+   *单极*步进电机*不需要*一个能够改变电流流向的电路。

在我们的双极接线示例中，我们使用 H-Bridge 电路，因为它能够改变电流流向到线圈（例如，这就是我们在前一节中使直流电机改变方向的方法）。

ULN2003 IC 是一种流行的、低成本的达林顿晶体管阵列（带有内置飞回二极管）；你也可以使用它来驱动你的步进电机作为*单极*步进电机。在这种设置中，你将使用连接到+5 伏特的红线，因为 ULN2003 无法改变电流的方向。

连接好步进电机后，我们可以继续使用代码来控制它。

## 运行和探索步进电机代码

我们即将运行的代码可以在`chapter10/stepper.py`文件中找到。我建议在继续之前先查看源代码，以便对文件的内容有一个整体的了解。

当你运行`chapter10/stepper.py`文件中的代码时，你的步进电机应该在一个方向上旋转 360 度，然后再返回。

在你的步进电机轴上贴一块胶带，以便在旋转时更容易看到它的方向。

从源文件的顶部开始，我们定义了所有的 GPIO 变量，包括我们的使能引脚在第 1 行，以及从第 2 行开始与我们的步进电机线圈线有关的变量。这些线必须**正确识别和排序，因为线圈线的顺序很重要！**

```py
CHANNEL_1_ENABLE_GPIO = 18                                # (1)
CHANNEL_2_ENABLE_GPIO = 16

INPUT_1A_GPIO = 23 # Blue Coil 1 Connected to 1Y          # (2)
INPUT_2A_GPIO = 24 # Pink Coil 2 Connected to 2Y
INPUT_3A_GPIO = 20 # Yellow Coil 3 Connected to 3Y
INPUT_4A_GPIO = 21 # Orange Coil 4 Connected to 4Y

STEP_DELAY_SECS = 0.002                                   # (3)
```

我们将在代码中稍后看到使用`STEP_DELAY_SECS`在第 3 行，以在线圈步进之间增加一些延迟。更长的延迟会导致步进电机轴的旋转速度变慢；然而，如果数字太小，轴可能根本不会旋转，或者旋转会不稳定和抖动。随时尝试不同的延迟值以满足你的需求。

接下来，从第 4 行开始，我们将我们的线圈 GPIO 分组到一个 Python 列表（数组）中，并在第 5 行将这些 GPIO 初始化为输出。我们将 GPIO 存储在列表中，因为我们将在稍后使用`rotate()`函数时对这些 GPIO 进行迭代。我们还在第 6 行有`off()`函数，用于关闭所有线圈：

```py
coil_gpios = [                             # (4)
    INPUT_1A_GPIO,
    INPUT_2A_GPIO,
    INPUT_3A_GPIO,
    INPUT_4A_GPIO
]

# Initialise each coil GPIO as OUTPUT.
for gpio in coil_gpios:                    # (5)
    pi.set_mode(gpio, pigpio.OUTPUT)

def off():
    for gpio in coil_gpios:                # (6)
       pi.write(gpio, pigpio.LOW) # Coil off

off() # Start with stepper motor off.
```

在第 7 行，我们在代码中将两个使能 GPIO 引脚设置为`HIGH`，因为我们正在重用之前直流电机控制示例中的电路。另一种非代码方法是直接将 L293D EN1 和 EN2 引脚连接到+5 伏特（即手动将它们拉高）：

```py
# Enable Channels (always high)
pi.set_mode(CHANNEL_1_ENABLE_GPIO, pigpio.OUTPUT)      # (7)
pi.write(CHANNEL_1_ENABLE_GPIO, pigpio.HIGH)
pi.set_mode(CHANNEL_2_ENABLE_GPIO, pigpio.OUTPUT)
pi.write(CHANNEL_2_ENABLE_GPIO, pigpio.HIGH)
```

从第 8 行开始，我们在一个名为`COIL_HALF_SEQUENCE`和`COIL_FULL_SEQUENCE`的多维（2 x 2）数组中定义了两个步进序列，因此我们遇到了代码的部分，从这里开始，步进电机控制变得比直流电机或伺服控制更复杂！

步进序列定义了我们必须如何打开（通电）和关闭（不通电）步进电机中的每个线圈，以使其步进。序列中的每一行都有四个元素，每个元素都与一个线圈相关：

```py
COIL_HALF_SEQUENCE = [             # (8)
    [0, 1, 1, 1],
    [0, 0, 1, 1],   # (a)
    [1, 0, 1, 1],
    [1, 0, 0, 1],   # (b)
    [1, 1, 0, 1],
    [1, 1, 0, 0],   # (c)
    [1, 1, 1, 0],
    [0, 1, 1, 0] ]  # (d)

COIL_FULL_SEQUENCE = [
    [0, 0, 1, 1],   # (a)
    [1, 0, 0, 1],   # (b)
    [1, 1, 0, 0],   # (c)
    [0, 1, 1, 0] ]  # (d)
```

具有八个步骤的序列称为*半步*序列，而*全步*序列有四行，是半序列的子集（在前面的代码中匹配*(a)*、*(b)*、*(c)*和*(d)*行）。

半序列将为您提供更高的分辨率（例如，360 度革命的 4,096 步），而全步序列将提供一半的分辨率（2,048 步），但步进速度加倍。

步进电机的步进序列通常可以在其数据表中找到 - 但并非总是如此，正如我们在*技术要求*部分提到的 28BYJ-48 数据表所证明的那样，因此有时可能需要进行一些研究。

如果步进电机没有旋转，但发出声音和振动，这表明步进序列和线圈顺序不匹配。当您尝试盲目连接它们并希望它们工作时，这是步进电机的常见挫折。为了避免这种反复试验的方法，请花时间识别您的步进电机类型以及它的接线方式（例如，双极或单极），并找出线圈编号以及适合的线圈步进序列是什么样的。查阅您的步进电机的数据表是开始的最佳地方。

接下来，在第 9 行，我们定义了全局变量`sequence = COIL_HALF_SEQUENCE`，以在步进电机步进时使用半步序列。您可以将其更改为`sequence = COIL_FULL_SEQUENCE`以使用全步序列 - 所有其他代码保持不变：

```py
sequence = COIL_HALF_SEQUENCE       # (9)
#sequence = COIL_FULL_SEQUENCE
```

在第 10 行，我们有`rotate(steps)`方法，这是发生所有魔术的地方，可以这么说。检查和理解这个方法做了什么是理解如何控制我们的步进电机的关键。`steps`参数可以是正数或负数，以使步进电机向相反方向旋转：

```py
# For rotate() to keep track of the sequence row it is on.
sequence_row = 0 

def rotate(steps):                              # (10)
    global sequence_row
    direction = +1
    if steps < 0:
        direction = -1
```

`rotate()`函数的核心部分在两个`for`循环中，从第 11 行开始：

```py
# rotate(steps) continued...

    for step in range(abs(steps)):                # (11)
      coil_states = sequence[sequence_row]        # (12)
      for i in range(len(sequence[sequence_row])):
          gpio = coil_gpios[i]                    # (13)
          state = sequence[sequence_row][i]       # (14)
          pi.write(gpio, state)                   # (15)
          sleep(STEP_DELAY_SECS)
```

当代码循环进行`step`次迭代时，我们在第 12 行得到下一个线圈状态的形式，`sequence[sequence_row]`（例如，`[0, 1, 1, 1]`），然后在第 13 行循环获取相应的线圈 GPIO，并在第 14 行得到其`HIGH`/`LOW`状态。在第 15 行，我们使用`pi.write()`设置线圈的`HIGH`/`LOW`状态，这使我们的电机移动（即步进），然后休眠一小段时间。

接下来，从第 16 行开始，根据旋转方向（即`steps`参数是正数还是负数），更新`sequence_row`索引：

```py
# rotate(steps) continued...

      sequence_row += direction            # (16)
      if sequence_row < 0:
          sequence_row = len(sequence) - 1
      elif sequence_row >= len(sequence):
          sequence_row = 0
```

在这段代码块的末尾，如果还有更多的步骤要完成，代码将返回到第 11 行进行下一个`for steps in ...`迭代。

最后，在第 17 行，我们来到了使我们的步进电机在运行示例时旋转的代码部分。请记住，如果您将第 9 行切换为`sequence = COIL_FULL_SEQUENCE`，则步数将为`2048`：

```py
if __name__ == '__main__':
    try:                                                   #(17)
        steps = 4096 # Steps for HALF stepping sequence.
        print("{} steps for full 360 degree rotation.".format(steps))
        rotate(steps) # Rotate one direction
        rotate(-steps) # Rotate reverse direction

    finally:
        off() # Turn stepper coils off
        pi.stop() # PiGPIO Cleanup
```

恭喜！您刚刚完成了关于步进电机控制的速成课程。

我明白，如果您是步进电机的新手，需要进行一些多维思考，并且您已经接触到了许多概念和术语，我们无法详细介绍。步进电机需要时间来理解；然而，一旦您掌握了控制一个步进电机的基本过程，那么您就已经在更深入地理解更广泛的概念的道路上了。

互联网上有许多步进电机教程和示例。许多示例的目标只是让步进电机工作，但由于底层复杂性，这并不总是清楚地解释了如何实现这一点。当您阅读步进电机的资料并探索代码示例时，请记住，步长的定义可能会有很大的差异，这取决于它的使用环境。这就是为什么两个示例可能会针对同一个步进电机引用显著不同的步数的原因。

# 总结

在本章中，您学会了如何使用三种常见类型的电机来利用树莓派创建复杂的运动 - 使用舵机创建角动量，使用带 H 桥驱动器的直流电机创建方向运动和速度控制，以及使用步进电机进行精确运动。如果您掌握了这些类型电机的一般概念，那么您值得表扬！这是一个成就。虽然电机在原理上很简单，它们的运动在日常用品和玩具中是我们每天都习以为常的，但正如您发现的那样，背后有很多事情在发生，以使得运动发生。

本章学到的知识，加上示例电路和代码，为您提供了一个基础，您可以用它来开始构建自己的应用程序，其中需要运动和动作。一个简单有趣的项目可以是创建一个程序来控制一个机器人汽车或机械臂 - 您可以在 eBay 等网站上找到汽车和机械臂的 DIY 套件和零件。

在下一章中，我们将探讨如何使用树莓派、Python 和各种电子元件来测量距离和检测运动的方法。

# 问题

最后，这里有一些问题供您测试本章材料的知识。您将在书的“评估”部分找到答案：

1.  您的舵机无法完全向左或向右旋转。这是为什么，如何解决？

1.  您的舵机在极左/右位置发出嘎吱声。为什么？

1.  在控制直流电机时，H 桥相比单个晶体管有什么优势？

1.  您正在使用 L293D H 桥集成电路。您按照数据表上的说明操作，但无法使电机制动。为什么？

1.  为什么将 5 伏电机连接到使用 L293D 的 H 桥时会比直接连接到 5 伏电源时转速较慢？

1.  您有一个步进电机无法工作 - 它会震动，但不会转动。可能是什么问题？

1.  您能直接从四个树莓派的 GPIO 引脚驱动步进电机吗？


# 第十一章：测量距离和检测运动

欢迎来到我们的最后一个基于核心电子学的章节。在上一章中，我们学习了如何以复杂的方式控制三种不同形式的电机。在本章中，我们将把注意力集中在使用树莓派和电子设备检测运动和测量距离。

检测运动对于自动化项目非常有用，例如当您走进房间或建筑物时点亮灯光，警报系统，建筑物计数器或检测轴的旋转。我们将研究两种运动检测技术，包括使用**被动红外**（**PIR**）传感器来检测人（或动物）的存在的热检测，以及数字霍尔效应传感器，它可以检测磁场的存在（或者更宽泛地说，我们可以说霍尔效应传感器可以检测到磁铁移过它的时候）。

距离测量对于许多项目也很有用，从碰撞检测电路到测量水箱水位。我们将研究两种距离测量形式，包括使用超声波声音传感器，可以测量大约 2 厘米到 4 米的距离，以及可以测量磁场接近度的模拟霍尔效应传感器，可以测量到毫米级的磁场接近度。

以下是本章的内容：

+   使用 PIR 传感器检测运动

+   使用超声波传感器测量距离

+   使用霍尔效应传感器检测运动和距离

# 技术要求

要执行本章的练习，您需要以下内容：

+   树莓派 4 型 B

+   Raspbian OS Buster（带桌面和推荐软件）

+   最低 Python 版本 3.5

这些要求是本书中代码示例的基础。可以合理地期望代码示例应该可以在树莓派 3 型 B 或不同版本的 Raspbian OS 上无需修改即可工作，只要您的 Python 版本是 3.5 或更高。

您可以在 GitHub 存储库的`chapter11`文件夹中找到本章的源代码，网址为[`github.com/PacktPublishing/Practical-Python-Programming-for-IoT`](https://github.com/PacktPublishing/Practical-Python-Programming-for-IoT)。

您需要在终端中执行以下命令来设置虚拟环境并安装本章代码所需的 Python 库：

```py
$ cd chapter11              # Change into this chapter's folder
$ python3 -m venv venv      # Create Python Virtual Environment
$ source venv/bin/activate  # Activate Python Virtual Environment
(venv) $ pip install pip --upgrade        # Upgrade pip
(venv) $ pip install -r requirements.txt  # Install dependent packages
```

从`requirements.txt`安装以下依赖项：

+   **PiGPIO**：PiGPIO GPIO 库（[`pypi.org/project/pigpio`](https://pypi.org/project/pigpio)）

+   **ADS1X15**：ADS11x5 ADC 库（[`pypi.org/project/adafruit-circuitpython-ads1x15`](https://pypi.org/project/adafruit-circuitpython-ads1x15)）

本章练习所需的电子元件如下：

+   1 x 1kΩ电阻

+   1 x 2kΩ电阻

+   1 x HC-SR501 PIR 传感器（数据表：[`www.alldatasheet.com/datasheet-pdf/pdf/1131987/ETC2/HC-SR501.html`](https://www.alldatasheet.com/datasheet-pdf/pdf/1131987/ETC2/HC-SR501.html)）

+   1 x A3144 霍尔效应传感器（非锁存）（数据表：[`www.alldatasheet.com/datasheet-pdf/pdf/55092/ALLEGRO/A3144.html`](https://www.alldatasheet.com/datasheet-pdf/pdf/55092/ALLEGRO/A3144.html)）

+   1 x AH3503 霍尔效应传感器（比率式）（数据表：[`www.alldatasheet.com/datasheet-pdf/pdf/1132644/AHNJ/AH3503.html`](https://www.alldatasheet.com/datasheet-pdf/pdf/1132644/AHNJ/AH3503.html)）

+   1 x HC-SR04 或 HC-SR04P 超声波距离传感器（数据表：[`tinyurl.com/HCSR04DS`](https://tinyurl.com/HCSR04DS)）

+   用于霍尔效应传感器的小磁铁

HC-SR04 有两种变体可用。更常见的 HC-SR04，输出 5 伏逻辑和 HC-SR04**P**，可以在 3 伏至 5.5 伏之间工作。这两种模块都适用于本章的练习。

# 使用 PIR 传感器检测运动

PIR 传感器是一种可以检测到物体（例如人）发出的红外光（热量）的设备。我们在周围的应用中看到这些类型的传感器，如安全系统和对我们的存在做出反应的自动门和灯。PIR 中的“被动”意味着传感器只是检测运动。要检测*什么*移动和*如何*移动，你需要一个主动红外设备，比如热成像摄像头。

PIR 传感器有几种不同的形式和品种；然而，它们的基本用法是相同的——它们作为一个简单的数字开关。当它们没有检测到运动时，它们输出数字`LOW`，当检测到运动时，它们输出数字`HIGH`。

下图显示了我们将在示例中使用的 HC-SR501 PIR 传感器模块。图片中显示了模块的顶部、底部和 PIR 传感器的常见原理图符号：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/15a71ea4-9918-4be8-a0fc-27240f8add81.png)

图 11.1 - HC-SR501 PIR 传感器模块

一些 PIR 传感器，包括我们的 HC-SR501，上面有设置和校准调整。这些调整用于改变传感器的灵敏度范围和触发模式。在没有板载校准的情况下使用 PIR 设备意味着我们需要在代码中自行处理灵敏度调整。

关于 HC-SR501，它的端子如下：

+   **GND**：接地。

+   **Vcc**：连接到 5 伏至 20 伏的电源。

+   **数据**：我们连接到 GPIO 引脚的数字输出。当 PIR 检测到运动时，此引脚变为`HIGH`；否则，在没有运动的情况下保持`LOW`。HC-SR501 输出 3.3 伏信号，尽管它需要 5 至 20 伏的电源。接下来我们将看到，板载的*灵敏度调整*、*定时调整*、*触发模式*跳线会影响数据引脚在检测到运动时保持`HIGH`的方式、时间和持续时间。

HC-SR501 的板载设置如下：

+   **灵敏度调整**：改变有效的移动感应范围，从大约 3 米到大约 7 米。使用小螺丝刀旋转此设置的拨号。

+   **时间延迟调整**：在检测到运动后数据端口保持`HIGH`的时间。调整范围约为 5 秒至 300 秒。使用小螺丝刀旋转此设置的拨号。

+   **触发模式跳线**：在持续检测到运动的情况下，此跳线设置意味着在时间延迟到期后（由**时间延迟调整**设置），数据端口将执行以下操作：

+   保持`HIGH`。这是*可重复*触发设置，通过将跳线放置在**H**位置来设置。

+   恢复为`LOW`。这是*单次触发*设置，通过将跳线放置在**L**位置来设置。

你的 PIR 的最佳设置将取决于你打算如何使用它以及你部署传感器的环境。我的建议是，在完成电路搭建并运行后续部分的示例代码后，尝试调整设置，以了解如何改变设置会影响传感器的操作。记得查阅 HC-SR501 的数据表，以获取有关传感器及其板载设置的更多信息。

让我们把我们的 PIR 传感器接线并连接到我们的树莓派。

## 创建 PIR 传感器电路

在这一部分，我们将把我们的 PIR 传感器连接到我们的树莓派。以下是我们即将构建的电路的原理图。正如你所看到的，从 PIR 传感器的角度来看，它的布线相对简单：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/a71c4b1a-0925-4a7a-871b-16feb2158fa8.png)

图 11.2 - PIR 传感器模块电路

让我们按照下图所示将其连接到我们的树莓派：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/2ed19997-c875-442a-97a5-377aac349c70.png)

图 11.3 - PIR 传感器电路面包板布局

以下是创建面包板搭建的步骤。步骤编号与*图 11.3*中的黑色圆圈中的编号相匹配：

1.  将您的 PIR 传感器的每个端子连接到面包板上。您将需要三根公对公跳线。

1.  将树莓派上的 5 伏特引脚连接到 PIR 的 Vcc 端使用的面包板行。PIR 传感器只使用少量电流，因此将 5 伏特 Vcc 引脚直接连接到树莓派上是可以的。

1.  将树莓派上的 GND 引脚连接到 PIR 的 GND 端使用的面包板行。

1.  将树莓派上的 GPIO 21 引脚连接到 PIR 的数据端使用的面包板行。

**重要提示**：我们参考的 HC-SR501 PIR 传感器需要>4.5 伏特的电源（Vcc），并在其 Sig 输出引脚上输出 3.3 伏特。如果您使用的是不同的 PIR 传感器，请查阅其数据表并检查输出引脚电压。如果它大于 3.3 伏特，您将需要使用电压分压器或逻辑电平转换器。在下一节中，我们将涵盖这种确切的情况，当我们将电压分压器与 HC-SR04 传感器配对，将其 5 伏特输出转换为树莓派友好的 3.3 伏特。

创建电路后，我们将继续并运行我们的 PIR 示例代码，这将让我们检测运动。

## 运行和探索 PIR 传感器代码

我们的 PIR 电路代码可以在`chapter11/hc-sr501.py`文件中找到。在继续之前，请查看源代码，以对该文件的内容有一个广泛的了解。

HC-SR501 数据表规定，传感器在上电后需要大约 1 分钟的时间来初始化和稳定自身。如果在传感器变得稳定之前尝试使用传感器，可能会在启动程序时收到一些错误的触发。

在终端中运行`hc-sr501.py`文件。当 HC-SR501 检测到运动时，程序将在终端上打印`Triggered`，或者在未检测到运动时打印`Not Triggered`，如下所示：

```py
(venv) $ python hc-sr501.py 

PLEASE NOTE - The HC-SR501 Needs 1 minute after power on to initialize itself.

Monitoring environment...
Press Control + C to Exit
Triggered.
Not Triggered.
... truncated ...
```

如果您的程序没有按预期响应，请尝试调整我们之前在*使用 PIR 传感器检测运动*部分中讨论的**灵敏度调整**、**时间延迟调整**或**触发模式跳线**设置中的一个或多个。

您可以将 HC-SR501 视为基本开关。它要么是打开的（`HIGH`），要么是关闭的（`LOW`），就像普通的按钮开关一样。实际上，我们的代码类似于第二章中*使用 Python 和物联网入门*部分中介绍的 PiGPIO 按钮示例。我们只会在这里简要介绍核心代码部分；但是，如果您需要更深入的解释或复习，请重新查看第二章中的 PiGPIO 部分，*使用 Python 和物联网入门*。

让我们讨论示例代码。首先，我们在第 1 行开始设置我们的 GPIO 引脚为带有下拉使能的输入引脚，而在第 2 行，我们启用了去抖动。我们的 HC-SR501 模块实际上不需要在代码中激活下拉，也不需要去抖动；但是，我为了完整性而添加了它：

```py
# ... truncated ...
GPIO = 21

# Initialize GPIO
pi.set_mode(GPIO, pigpio.INPUT)                               # (1)
pi.set_pull_up_down(GPIO, pigpio.PUD_DOWN)
pi.set_glitch_filter(GPIO, 10000) # microseconds debounce     # (2)
```

接下来，在第 3 行，我们定义了`callback_handler()`函数，每当 GPIO 引脚改变其`HIGH`/`LOW`状态时都会被调用：

```py
def callback_handler(gpio, level, tick):                       # (3)
    """ Called whenever a level change occurs on GPIO Pin.
      Parameters defined by PiGPIO pi.callback() """
    global triggered

    if level == pigpio.HIGH:
        triggered = True
        print("Triggered")
    elif level == pigpio.LOW:
        triggered = False
        print("Not Triggered")
```

最后，在第 4 行，我们注册了回调函数。正是第二个参数`pigpio.EITHER_EDGE`导致`callback_handler()`在 GPIO 变为`HIGH`或`LOW`时被调用：

```py
# Register Callback
callback = pi.callback(GPIO, pigpio.EITHER_EDGE, callback_handler) # (4)
```

作为对比，在第二章中，*使用 Python 和物联网入门*，对于我们的按钮示例，此参数为`pigpio.FALLING_EDGE`，意味着只有在按下按钮时才会调用回调，而松开按钮时不会调用。

正如我们所见，PIR 传感器只能检测物体的接近 - 例如，有人靠近我们的传感器吗？ - 但它无法告诉我们物体的距离有多远或多近。

我们现在已经学会了如何创建和连接一个简单的 PIR 传感器电路到我们的树莓派，并且学会了如何在 Python 中使用它来检测运动。有了这些知识，你现在可以开始构建自己的运动检测项目，比如结合第七章中的示例，*打开和关闭东西*，或者作为你自己的警报和监控系统的重要部分。

接下来，我们将看一下能够估算距离的传感器。

# 用超声波传感器测量距离

在上一节中，我们学会了如何使用 PIR 传感器检测运动。正如我们发现的那样，我们的 PIR 传感器是一个数字设备，通过使其输出为数字`HIGH`来表示检测到运动。

现在是时候学习如何用树莓派测量距离了。有各种各样的传感器可以执行这项任务，它们通常要么使用声音，要么使用光。我们的示例将基于流行的 HC-SR04 超声波距离传感器（它使用声音），如下图所示：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/dde3ee8c-3469-4a0d-824d-8b6fa7984f25.png)

图 11.4 - HC-SR04 超声波距离传感器模块

你通常会在现代汽车保险杠上找到超声波距离传感器（它们通常是小圆圈，这是与前面图中的 HC-SR04 不同的形状）。这些传感器计算你的车和附近物体之间的距离，例如，当你越来越接近物体时，会让车内的蜂鸣器越来越快地响起。

另一个常见的应用是用于测量液体水平，比如水箱中的水位。在这种情况下，（防水）超声波传感器测量从水箱顶部到水位的距离（声音脉冲反射在水上）。然后可以将测得的距离转换为水箱的大致容量。

让我们更仔细地看一下我们的 HC-SR04 传感器。参考 HC-SR04 数据表中的核心规格如下：

+   电源电压 5 伏（HC-SR04）或 3 伏至 5.5 伏（HC-SR04P）

+   逻辑电压 5 伏（HC-SR04）或 3 伏至 5.5 伏（HC-SR04P）

+   工作电流 15 毫安，静态电流 2 毫安

+   有效测量范围为 2 厘米至 4 米，精度为+/- 0.3 厘米

+   10 微秒的触发脉冲宽度。我们将在标题为*HC-SR04 距离测量过程*的部分重新讨论这个脉冲宽度并进行更多讨论。

SC-SR04 有两个圆柱体。它们如下：

+   **T**或**TX**：产生超声波脉冲的发射器

+   **R**或**RX**：检测超声波脉冲的接收器

我们将在下一节讨论发射器和接收器如何一起工作来测量距离。

HC-SR04 有四个端子，它们如下：

+   **Vcc**：电源（树莓派 5 伏引脚将是可以的，考虑到最大电流为 15 毫安）。

+   **GND**：接地连接。

+   **TRIG**：触发*输入*端子 - 当`HIGH`时，传感器发送超声波脉冲。

+   **ECHO**：回声*输出*端子 - 当`TRIG`变为`HIGH`时，此引脚变为`HIGH`，然后在检测到超声脉冲时变为`LOW`。

我们将在标题为*HC-SR04 距离测量过程*的部分讨论`TRIG`和`ECHO`端子的使用。

现在我们了解了超声波距离传感器的基本用法和 HC-SR04 的基本特性和布局，让我们讨论一下它是如何工作的。

## 超声波距离传感器的工作原理

让我们看看发射器（TX）和接收器（RX）如何一起工作来测量距离。超声波传感器的基本工作原理如下图所示：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/04fb297a-ba3e-4828-bef7-85587791b615.png)

图 11.5 - 超声波距离传感器操作

以下是发生的事情：

1.  首先，传感器从发射器（TX）发送超声波脉冲。

1.  如果传感器前面有物体，这个脉冲会反弹到物体上并返回到传感器，并被接收器（RX）检测到。

1.  通过测量发送脉冲和接收脉冲之间的时间，我们可以计算传感器和物体之间的距离。

了解了传感器工作原理的高层次理解后，接下来，我们将深入讨论如何使用 HC-SR04 上的 TRIG 和 ECHO 端子一起估算距离的过程。

## HC-SR04 距离测量过程

在本节中，我们将介绍使用 HC-SR04 测量距离的过程。 如果这一点不立即明白，不要担心。 我在这里提供了详细信息作为背景材料，因为这是我们示例程序实现的逻辑过程，以使传感器工作。 您还会在传感器的数据表中找到这个过程的记录。

我们通过正确使用和监控 TRIG 和 ECHO 引脚来测量 HC-SR04 的距离。 过程如下：

1.  将 TRIG 引脚拉高 10 微秒。 拉高 TRIG 也会使 ECHO 引脚变高。

1.  启动计时器。

1.  等待以下任一情况发生：

+   ECHO 变为`LOW`

+   经过 38 毫秒（从数据表中，这是>4 米的时间）

1.  停止计时器。

如果经过了 38 毫秒，我们得出结论认为传感器前面没有物体（至少在有效范围内的 2 厘米到 4 米之间）。 否则，我们将经过的时间除以 2（因为我们想要传感器和物体之间的时间间隔，而不是传感器到物体再返回到传感器），然后使用基本物理学，使用以下公式计算传感器和物体之间的距离：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/8e34f8a8-c9d8-4330-ad69-d2bd3f0a2338.png)

在这里，我们有以下内容：

+   *d*是以米为单位的距离。

+   *v*是以米/秒为单位的速度，我们使用声速，大约为 20°C（68°F）时的 343 米/秒。

+   *t*是以秒为单位的时间。

HC-SR04 只会估算距离。 有几个参数会影响其准确性。 首先，正如之前暗示的，声速随温度变化而变化。 其次，传感器的分辨率为±0.3 厘米。 此外，被测物体的大小，物体相对于传感器的角度，甚至物体的材质都会影响 ECHO 的定时结果，从而影响计算出的距离。

通过对如何使用 HC-SR04 估算距离的基本理解，让我们构建我们的电路，将 HC-SR04 连接到我们的树莓派。

## 构建 HC-SR04 电路

是时候构建我们的 HC-SR04 电路了。 我们电路的原理图如下图所示。 这种布线适用于 HC-SR04 或 HC-SR04P 模块： 

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/03adb9b5-5121-4443-b68d-1260bd41e2f0.png)

图 11.6 - HC-SR04（5 伏逻辑 ECHO 引脚）电路

作为提醒，HC-SR04 模块（或像这样连接到 5 伏电源的 HC-SR04P）是一个 5 伏逻辑模块，因此您会注意到电路中由两个电阻器创建的电压分压器将 5 伏转换为 3.3 伏。 如果您需要关于电压分压器的复习，我们在第六章中详细介绍了它们，*软件工程师的电子学 101*。

让我们在面包板上构建这个电路：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/d7c2f5d8-4f07-4387-a2d7-ac26fbce53f5.png)

图 11.7 - HC-SR04 电路面包板布局（第一部分）

以下是创建面包板构建的第一部分的步骤。 步骤编号与*图 11.7*中的黑色圆圈中的数字相匹配：

1.  将 1kΩ电阻（R1）放入面包板中。

1.  将 2kΩ电阻（R2）放入面包板中。 第二个电阻的一个腿与第一个电阻的一个腿共用一行。 在插图中，这可以在右侧银行的第 21 行中看到。

1.  将左侧和右侧的负电源导轨连接在一起。

1.  将树莓派上的 GND 引脚连接到左侧电源轨的负电源。

1.  将第二条 2kΩ电阻（R2）连接到右侧电源轨的负电源。

1.  将 HC-SR04 传感器上的 GND 端子连接到右侧电源轨的负电源。

1.  将 HC-SR04 传感器上的 Vcc 端子连接到右侧电源轨的正电源。

确保 R1 和 R2 电阻的连接方式如前图所示 - 即 R1（1kΩ）连接到 HC-SR04 的 ECHO 引脚。由 R1 和 R2 创建的电压分压器将 ECHO 引脚的 5 伏特转换为~3.3 伏特。如果您将电阻安装反了，5 伏特将转换为~1.67 伏特，这不足以在树莓派上注册逻辑`HIGH`。

既然我们已经布置好了基本组件并进行了一些初步的接线连接，让我们完成我们的构建：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/e2285741-5fdb-4ed7-ad55-da4add757bc9.png)

图 11.8 - HC-SR04 电路面包板布局（第二部分）

以下是要遵循的步骤。步骤编号与*图 11.8*中黑色圆圈中的数字相匹配：

1.  将树莓派上的 GPIO 20 连接到 HC-SR04 传感器上的 Trig 端子。

1.  将树莓派上的 GPIO 21 连接到 1kΩ（R1）和 2kΩ（R2）电阻的交汇处。这个连接在 F21 孔上的插图中有显示。

1.  将 HC-SR04 传感器的 Echo 端子连接到 1kΩ电阻（R1）。这个连接在 J17 孔上有显示。

1.  将 5 伏特电源的正端连接到右侧电源轨的正电源。

1.  将 5 伏特电源的负端连接到右侧电源轨的负电源。

如前所述，我们的电路构建将适用于 HC-SR04 和 HC-SR04P 模块。如果您有 HC-SR04P 模块，可以选择更简单的接线选项。由于 HC-SR04P 将在 3.3 伏特下工作，因此您可以这样做：

+   将 Vcc 连接到 3.3 伏特电源或树莓派上的 3.3 伏特引脚。

+   将 ECHO 端子直接连接到 GPIO 21。

+   GND 仍然连接到 GND，TRIG 仍然直接连接到 GPIO 20。

由于此配置以 3.3 伏特供电，因此 ECHO 端子上的逻辑输出也是 3.3 伏特，因此可以安全地直接连接到树莓派的 GPIO 引脚。

太好了！现在我们的电路已经完成，接下来我们将运行我们的示例程序，并使用 HC-SR04 来测量距离，并了解使其发生的代码。

## 运行和探索 HC-SR04 示例代码

HC-SR04 的示例代码可以在`chapter11/hc-sr04.py`文件中找到。在继续之前，请查看源代码，以对该文件的内容有一个广泛的了解。

在 HC-SR04 前面放一个实物体（大约 10 厘米），并在终端中运行代码。当您将物体靠近或远离传感器时，终端中打印的距离将会改变，如下所示：

```py
(venv) python hc-sr04.py
Press Control + C to Exit
9.6898cm, 3.8149"
9.7755cm, 3.8486"
10.3342cm, 4.0686"
11.5532cm, 4.5485"
12.3422cm, 4.8591"
...
```

让我们来审查代码。

首先，在第 1 行定义了`TRIG_GPIO`和`ECHO_GPIO`引脚，在第 2 行定义了声速的`VELOCITY`常数。我们使用 343 米每秒。

我们的代码使用 343 米/秒作为声速，而数据表建议的值为 340 米/秒。您还会发现其他使用略有不同数值的 HC-SR04 示例和库。这些差异是不同代码示例和库可能会对相同的传感器到物体距离产生略有不同读数的原因之一。

在第 3 行，我们定义了`TIMEOUT_SECS = 0.1`。`0.1`的值大于 38 毫秒（来自数据表）。任何大于这个值的时间，我们都会得出结论，我们的 HC-SR04 传感器前面没有物体，并返回`SENSOR_TIMEOUT`值，而不是`get_distance_cms()`函数中的距离，我们马上就会讲到：

```py
TRIG_GPIO = 20                                       # (1)
ECHO_GPIO = 21

# Speed of Sound in meters per second
# at 20 degrees C (68 degrees F)
VELOCITY = 343                                       # (2)

# Sensor timeout and return value
TIMEOUT_SECS = 0.1 # based on max distance of 4m     # (3)
SENSOR_TIMEOUT  = -1
```

接下来，从第 4 行开始，我们找到了几个变量，用于帮助测量传感器超声脉冲的时间以及我们是否有一个成功的读数：

```py
# For timing our ultrasonic pulse
echo_callback = None                             # (4)
tick_start = -1
tick_end = -1
reading_success = False
```

`echo_callback`将包含一个 GPIO 回调引用，以供稍后进行清理，而`tick_start`和`tick_end`保存了用于计算超声脉冲回波的经过时间的开始和结束时间。术语`tick`用于与 PiGPIO 定时函数保持一致，我们将很快讨论这一点。只有在`TIMEOUT_SECS`过去之前我们有一个距离读数时，`reading_success`才为`True`。

我们使用第 5 行显示的`trigger()`函数来启动我们的距离测量。我们在第 6 行简单地应用了数据表中的流程 - 也就是说，我们使 TRIG 引脚在 10 微秒内变为`HIGH`：

```py
def trigger():                                   # (5)
    global reading_success
    reading_success = False

    # Start ultrasonic pulses
    pi.write(TRIG_GPIO, pigpio.HIGH)             # (6)
    sleep(1 / 1000000) # Pause 10 microseconds
    pi.write(TRIG_GPIO, pigpio.LOW)
```

在第 7 行显示的`get_distance_cms()`函数是我们的主要函数，它通过调用`trigger()`来启动距离测量过程，然后在第 8 行等待，直到我们有一个成功的读数（也就是`reading_success = True`），或者`TIMEOUT_SECS`过去，此时我们返回`SENSOR_TIMEOUT`。在等待期间，一个名为`echo_handler()`的回调处理程序在后台监视`ECHO_GPIO`引脚以获取成功的读数。我们将在本节后面讨论`echo_handler()`。

```py
def get_distance_cms()                           # (7)
    trigger()

    timeout = time() + TIMEOUT_SECS              # (8)
    while not reading_success:
      if time() > timeout:
          return SENSOR_TIMEOUT
      sleep(0.01)
```

当我们有一个成功的读数时，我们的函数继续。在第 9 行，我们取`tick_start`和`tick_end`变量（现在已经由回声回调处理程序设置了值）并计算经过的时间。记住，我们在第 9 行将经过的时间除以 2，因为我们想要从传感器到物体的时间，*而不是*从传感器到物体再返回传感器的完整超声脉冲往返时间：

```py
# ... get_distance_cms() continued

    # Elapsed time in microseconds.
    #Divide by 2 to get time from sensor to object.
    elapsed_microseconds = 
                pigpio.tickDiff(tick_start, tick_end) / 2   # (9)

    # Convert to seconds
    elapsed_seconds = elapsed_microseconds / 1000000

    # Calculate distance in meters (d = v * t)
    distance_in_meters = elapsed_seconds * VELOCITY         # (10)

    distance_in_centimeters = distance_in_meters * 100
    return distance_in_centimeters
```

在第 10 行，我们应用了我们之前讨论过的公式，*d* = *v* × *t*，来计算传感器和物体之间的距离。

接下来，在第 11 行，我们遇到了`echo_handler()`函数，它监视`ECHO_GPIO`引脚的状态变化：

```py
def echo_handler(gpio, level, tick):            # (11)
    global tick_start, tick_end, reading_success

    if level == pigpio.HIGH:
        tick_start = tick                       # (12)
    elif level == pigpio.LOW:
        tick_end = tick                         # (13)
        reading_success = True
```

根据数据表中的流程，我们捕获了在第 12 行发送脉冲时的时间，当`ECHO_GPIO`变为`HIGH`，并在第 13 行接收到脉冲回来时的时间，当`ECHO_GPIO`变为`LOW`。如果我们在超时之前（在第 8 行）检测到`ECHO_GPIO`为`LOW`，我们将`reading_success = True`，这样`get_distance_cms()`就知道我们有一个有效的读数。

最后，我们在第 14 行使用 PiGPIO 注册了`echo_handler()`回调函数。`pigpio.EITHER_EDGE`参数表示我们希望在`ECHO_GPIO`转换为`HIGH`或`LOW`状态时调用此回调函数：

```py
echo_callback = 
    pi.callback(ECHO_GPIO, pigpio.EITHER_EDGE, echo_handler) # (14)
```

干得好！你刚刚连接、测试和学习了如何使用 HC-SR04 传感器以及 PiGPIO 来估算距离。你刚刚学到的电路和代码示例可以被改编并用于测量水箱水位，甚至作为机器人的碰撞检测（这是 HC-SR04 在业余机器人中非常常见的应用），或者在任何其他需要距离的项目中。

接下来，我们将简要探讨霍尔效应传感器，并学习它们如何用于检测运动和相对距离。

# 使用霍尔效应传感器检测运动和距离

本章的最后一个实际示例将说明霍尔效应传感器的使用。霍尔效应传感器是简单的组件，用于检测磁场的存在（或不存在）。与 PIR 或距离传感器相比，您可以使用霍尔效应传感器与磁铁一起监测小范围甚至非常快速的运动。例如，您可以将一个小磁铁固定在直流电机的轴上，并使用霍尔效应传感器来确定电机的每分钟转数。

霍尔效应传感器的另一个常见应用是在手机和平板电脑中。一些手机和平板电脑的外壳和套子中有一个小磁铁。当您打开或关闭外壳时，您的设备会通过霍尔效应传感器检测到这个磁铁的存在或不存在，并自动为您打开或关闭显示屏。

霍尔效应传感器有三种类型，如下所述：

+   **非锁定开关类型（数字）**：它们在磁场存在时输出数字状态（即`高`或`低`），在磁场不存在时输出相反的数字状态。信号在磁场存在时是`高`还是`低`取决于传感器是主动`低`还是主动`高`（如果需要关于主动`低`和主动`高`概念的复习，请参考第六章，*软件工程师的电子学 101*）。

+   **锁定开关类型（数字）**：当检测到磁铁的一个极性（例如南极）时，它们输出（并锁定到）`低`（或`高`），当检测到另一个极性（例如北极）时返回到`高`（或`低）（解锁）。

+   **比率类型（模拟）**：它们根据它们离磁场有多近而输出不同的电压。

一些读者可能熟悉一种叫做*磁簧开关*的组件，它是一种磁控开关。乍一看，它们在基本原理和操作上似乎与非锁定霍尔效应传感器相似。以下是重要的区别 - 与经典的磁簧开关不同，霍尔效应传感器是固态设备（没有活动部件），它们可以非常非常快地切换/触发（每秒数千次），并且它们需要一个适当的电路来使它们工作。

我们的示例将使用 A3144（非锁定数字开关）和 AH3503（模拟比率）霍尔效应传感器。由于这些特定部件的可用性和低成本，我们选择了这些特定部件；但是，我们将讨论的一般原则也适用于其他霍尔效应传感器。

图中显示了 A3144 霍尔效应传感器和常见的原理图符号：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/6c43f66c-4239-47e0-8db7-0a951ebdb90e.png)

图 11.9 - 霍尔效应传感器和符号

您会注意到最右边的符号有四个突出的输出，因为一些霍尔效应传感器确实有四条腿。您可以期望该符号的输出在适用于所指的传感器的原理图中被注释。我们将坚持使用三条腿的传感器和相应的三个输出符号。

我们组件的腿如下：

+   **Vcc**：5 伏电源。

+   **GND**：接地连接。

+   **输出**：5 伏信号输出。请注意，A3144 是主动`低`的，这意味着在磁场存在时，**输出**腿变为`低`。

**输出**腿的行为将取决于霍尔效应传感器的类型：

+   **锁定和非锁定开关类型**：**输出**腿将输出数字`低`或数字`高`。

+   **比率类型**：输出将是变化的电压（即模拟输出）。请注意，变化电压的范围不会是 0 到 5 伏之间的全部范围，而更可能是几百分之几伏的范围。

现在我们了解了霍尔效应传感器的腿配置，让我们构建我们的电路。

## 创建霍尔效应传感器电路

我们将在面包板上构建以下电路。与我们的 HC-SR04 示例和*图 11.5*中的电路类似，由于我们的霍尔效应传感器输出 5 伏逻辑，我们需要使用电压分压器将其降至 3.3 伏：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/209e5779-2f47-45e4-a894-cd29d7db6ce6.png)

图 11.10 - 霍尔效应传感器电路

您会注意到该电路的输出是二元的，并且取决于您使用的传感器：

+   对于*非锁定开关*或*锁定开关*类型的霍尔效应传感器，您将直接将电路连接到 GPIO 21，因为传感器将输出数字`高`/`低`信号。

+   对于*比率*类型的霍尔效应传感器，您需要通过 ADS1115 模数转换器将传感器连接到您的树莓派，因为传感器输出变化的模拟电压。

我没有在*图 11.9*或以下的步进面包板布局中包括 ADS1115 的接线。我们已经在之前的章节中看到了如何使用 ADS1115 将模拟输出连接到树莓派 - 例如电路和代码，请参考第五章，*将您的树莓派连接到物理世界*，和/或第九章，*测量温度、湿度和光照水平*。

让我们在面包板上构建这个电路。这个布局是用于*开关型*霍尔效应传感器的：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/c0b6ae7e-1802-49ff-b1a3-9b1cff719d69.png)

图 11.11 - 霍尔效应传感器电路面包板布局

以下是完成面包板构建的步骤。步骤编号与*图 11.10*中的黑色圆圈中的数字相匹配：

1.  将您的 A3144 霍尔效应传感器放入面包板中，注意其腿部的方向。如果需要帮助识别元件的腿部，请参考*图 11.8*。

1.  将 1kΩ电阻（R1）放入面包板中。

1.  将 2kΩ电阻（R2）放入面包板中。这第二个电阻的一个腿与第一个电阻的一个腿共用一行。在插图中，这可以在左侧银行的第 17 行看到。

1.  将树莓派的 5V 引脚连接到左侧电源轨道的正极。

1.  将树莓派的 GND 引脚连接到左侧电源轨道的负极。

1.  将霍尔效应传感器的 Vcc 腿连接到正电源轨道。

1.  将霍尔效应传感器的 GND 腿连接到负电源轨道。

1.  将霍尔效应传感器的 Out 腿连接到 1kΩ电阻（R1）。在插图中，这显示在 E13 孔。

1.  将 1kΩ（R1）和 2kΩ（R2）电阻的交汇处连接到树莓派的 GPIO 21。

1.  将 2kΩ电阻（R2）的左侧连接到负电源轨道。

要在这个电路中使用 AH3503 比率型霍尔效应传感器，在*步骤 1*，*步骤 9*的电线将需要连接到 ADS1115 模块的输入端口（例如 A0）。

现在我们已经建立了霍尔效应传感器电路，准备好一个磁铁，因为我们准备运行示例代码，看看磁铁如何触发传感器。

## 运行和探索霍尔效应传感器代码

您可以在`chapter11/hall_effect_digital.py`文件中找到开关和锁定开关类型霍尔效应传感器的代码，以及`chapter11/hall_effect_analog.py`文件中找到比率型霍尔效应传感器的代码。

当您查看这两个文件时，您会发现以下内容：

+   `chapter11/hall_effect_digital.py`在功能上与我们在本章前面介绍的 PIR 代码示例相同，标题为*运行和探索 PIR 传感器代码*。PIR 和非锁定/锁定霍尔效应传感器都是数字开关。唯一的区别是我们的参考霍尔效应传感器是*活动*`LOW`。

+   `chapter11/hall_effect_analog.py`类似于我们在使用 ADS1115 ACD 的其他模拟到数字示例中看到的，包括来自第五章，*将您的树莓派连接到物理世界*的电路布线和代码。

AH3503 比率型霍尔效应传感器输出的变化电压范围，并通过电压分压器由您的 ADC 测量，可能在几百毫伏的范围内。

当您运行示例代码时，将磁铁移过霍尔效应传感器。磁铁需要靠近传感器的外壳；然而，它不需要实际接触传感器。有多*近*取决于您的磁铁的强度。

如果您无法使电路和代码正常工作，请尝试旋转磁铁以改变通过传感器的南/北极。还要注意，对于*闸锁*型霍尔效应传感器，一个磁铁极常常会*锁定*（触发）传感器，而另一个磁铁极则会*解锁*（取消触发）传感器。

由于代码相似性，我们不会在这里再次介绍代码。但是，我想说的是，现在在本书中，您已经可以连接并使用任何简单的模拟或数字元件的数字和模拟基础电路和代码。正如本章已经指出的那样，只需注意所需的电压和电流来为元件供电，特别是输出电压是多少，因为如果超过 3.3 伏，您将需要使用电压分压器或电平转换器。

# 总结

在本章中，我们探讨了如何使用树莓派检测运动并估计距离。我们学会了如何使用 PIR 传感器检测广泛的运动，以及如何使用开关型霍尔效应传感器来检测磁场的运动。我们还发现了如何使用超声波测距传感器在较大范围上估计绝对距离，以及如何使用比例型霍尔效应传感器在小范围上测量相对距离。

本章中所有的电路和示例都是*输入*为主 - 告诉我们的树莓派发生了某些事件，比如检测到有人移动或正在测量距离。

现在你已经处于一个很好的位置，可以将本章中涵盖的输入电路（还有第九章中的内容，*测量温度、湿度和光照*），与第七章中的输出电路和示例，*打开和关闭设备*，第八章，*灯光、指示灯和信息显示*，以及第十章，*使用舵机、电机和步进电机进行运动*，结合起来，创建可以控制和测量环境的端到端项目！

不要忘记我们在第二章中学到的内容，*使用 Python 和物联网入门*，第三章，*使用 Flask 进行 RESTful API 和 Web Sockets 网络*，以及第四章，*使用 MQTT、Python 和 Mosquitto MQTT Broker 进行网络*。这三章为您提供了创建网页界面和集成到外部系统的基础，可以控制和监测环境。

到目前为止，在本书中呈现的许多电子和代码示例都围绕着单个传感器或执行器发展。在下一章中，我们将探索几种基于 Python 的设计模式，这些模式在构建涉及多个需要相互通信的传感器和/或执行器的更复杂的自动化和物联网项目时非常有用。

# 问题

最后，这里有一些问题供您测试对本章材料的了解。您将在本书的*评估*部分找到答案：

1.  PIR 传感器能否检测物体移动的方向？

1.  有哪些因素会影响超声波距离传感器的测量精度？

1.  闸锁型或非闸锁型霍尔效应传感器的输出与比例霍尔效应传感器的输出有何不同？

1.  关于这个 PiGPIO 函数调用，`callback = pi.callback(GPIO, pigpio.EITHER_EDGE, callback_handler)`，`pigpio.EITHER_EDGE`参数是什么意思？

1.  在由 1kΩ和 2kΩ电阻组成的 5 伏到 3.3 伏基于电阻的电压分压器中，为什么在电路中连接两个电阻值的方式很重要？

1.  HC-SR04 超声波距离传感器和 HC-SR501 PIR 传感器都使用 5 伏电压连接到它们各自的 Vcc 引脚。为什么我们要使用电压分压器将 HC-SR04 的输出从 5 伏降到 3.3 伏，而不是 HC-SR501？


# 第十二章：高级 IoT 编程概念-线程、异步 IO 和事件循环

在上一章中，我们学习了如何使用 PIR 传感器检测运动，以及如何使用超声波传感器和霍尔效应传感器测量距离和检测运动。

在本章中，我们将讨论在处理电子传感器（输入设备）和执行器（输出设备）时，*构建*Python 程序的替代方式。我们将首先介绍经典的事件循环编程方法，然后转向更高级的方法，包括在 Python 中使用线程、发布者/订阅者模型，最后是使用 Python 进行异步 IO 编程。

我向您保证，互联网上有很多博客文章和教程涵盖了这些主题；然而，本章将专注于实际的电子接口。本章的方法将涉及创建一个简单的电路，其中包括一个按钮、一个电位计和两个 LED，我们将使它们以不同的速率闪烁，并提供四种不同的编码方法来使电路工作。

以下是本章将涵盖的内容：

+   构建和测试我们的电路

+   探索事件循环的方法

+   探索线程化方法

+   探索发布者-订阅者的替代方案

+   探索异步 IO 的方法

# 技术要求

为了完成本章的练习，您需要以下内容：

+   树莓派 4 型 B

+   Raspbian OS Buster（带桌面和推荐软件）

+   最低 Python 版本 3.5

这些要求是本书中代码示例的基础。可以合理地期望，只要您的 Python 版本是 3.5 或更高，本书中的代码示例应该可以在树莓派 3 型 B 或不同版本的 Raspbian OS 上无需修改即可运行。

您可以在 GitHub 存储库的`chapter12`文件夹中找到本章的源代码，该存储库位于[`github.com/PacktPublishing/Practical-Python-Programming-for-IoT`](https://github.com/PacktPublishing/Practical-Python-Programming-for-IoT)。

需要在终端中执行以下命令来设置虚拟环境并安装本章所需的 Python 库：

```py
$ cd chapter12              # Change into this chapter's folder
$ python3 -m venv venv      # Create Python Virtual Environment
$ source venv/bin/activate  # Activate Python Virtual Environment
(venv) $ pip install pip --upgrade        # Upgrade pip
(venv) $ pip install -r requirements.txt  # Install dependent packages
```

以下依赖项已从`requirements.txt`中安装：

+   **PiGPIO**：PiGPIO GPIO 库（[`pypi.org/project/pigpio`](https://pypi.org/project/pigpio)）

+   **ADS1X15**：ADS1x15 ADC 库（[`pypi.org/project/adafruit-circuitpython-ads1x15`](https://pypi.org/project/adafruit-circuitpython-ads1x15)）

+   **PyPubSub**：进程内消息和事件（[`pypi.org/project/PyPubSub`](https://pypi.org/project/PyPubSub)）

本章练习所需的电子元件如下：

+   2 x 红色 LED

+   2 x 200 Ω 电阻

+   1 x 按钮开关

+   1 x ADS1115 模块

+   1 x 10k Ω 电位计

为了最大限度地提高您在本章中的学习效果，对于预先存在的知识和经验做出了一些假设：

+   从电子接口的角度来看，我假设您已经阅读了本书前面的 11 章，并且对本书中始终出现的 PiGPIO 和 ADS1115 Python 库的工作感到满意。

+   从编程的角度来看，我假设您已经掌握了**面向对象编程**（**OOP**）技术以及它们在 Python 中的实现。

+   熟悉*事件循环*、*线程*、*发布者-订阅者*和*同步与异步*范式的概念也将是有利的。

如果前述任何主题对您来说是陌生的，您会发现有很多在线教程详细介绍了这些主题。请参阅本章末尾的*进一步阅读*部分以获取建议。

# 构建和测试我们的电路

我将以实际练习的形式呈现本章的电路和程序。让我们假设我们被要求设计和构建一个具有以下要求的*小玩意*：

+   它有两个 LED 灯在闪烁。

+   电位计用于调整 LED 的闪烁速率。

+   程序启动时，两个 LED 将以由电位计位置确定的相同速率闪烁。

+   0 秒的闪烁速率意味着 LED 关闭，而 5 秒的最大闪烁速率意味着 LED 打开 5 秒，然后关闭 5 秒，然后重复循环。

+   按下按钮用于选择调整闪烁速率的 LED，当调整电位计时。

+   当按下并保持按下按钮 0.5 秒时，所有 LED 将同步到相同的速率，由电位计的位置确定。

+   理想情况下，程序代码应该很容易扩展，以支持更多 LED，而编码工作量很小。

以下是一个说明使用这个小玩意的场景：

1.  应用电源后（程序启动），所有 LED 以 2.5 秒的速率开始闪烁，因为电位计的刻度在旋转的中点（50%）。

1.  用户调整电位计，使*第一个*LED 以 4 秒的速率闪烁。

1.  接下来，用户简短地按下并释放按钮，以便电位计改变*第二个*LED 的闪烁速率。

1.  现在，用户调整电位计，使*第二个*LED 以 0.5 秒的速率闪烁。

1.  最后，用户按下并保持按钮 0.5 秒，使*第一个*和*第二个*LED 以 0.5 秒的速率同步闪烁（由*步骤 4*中电位计设置的速率）。

现在是我提到的挑战 - 在我们进入本章的电路和代码之前，我挑战您停止阅读，尝试创建一个实现上述要求的电路并编写程序。

您可以在[`youtu.be/seKkF61OE8U`](https://youtu.be/seKkF61OE8U)上找到演示这些要求的短视频。

我预计您会遇到挑战，并对采取的最佳方法有疑问。没有最佳方法；然而，通过拥有自己的实现 - 无论是否有效 - 您将有东西可以与我在本章中将提出的四种解决方案进行比较和对比。我相信，如果您首先自己尝试一下，那么您将获得更深入的理解和更多的见解。也许您会创造出更好的解决方案！

如果您需要建议来帮助您入门，这里有一些建议：

+   我们在《使用 Python 和物联网入门》的[第二章]中首次介绍了 LED 和按钮。

+   我们首先在《将树莓派连接到物理世界》的[第五章]中介绍了电位计和模拟输入，使用了 ADS1115 模块。

当您准备好时，我们将看一个满足上述要求的电路。

## 构建参考电路

在*图 12.1*中是一个符合我们刚列出的要求的电路。它有一个按钮，一个电位计，以电压分压器的形式连接到 ADS1115 模数转换器，和两个通过限流电阻连接的 LED。添加额外的 LED 将像在 GND 和一个空闲的 GPIO 引脚之间布线更多的 LED 和电阻对一样简单：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/1ce6b28c-49d3-4bae-bfce-ee96b13a20ab.png)

图 12.1 - 参考电路原理图

如果您还没有在面包板上创建类似的电路，我们现在将在您的面包板上创建这个电路。我们将分三部分构建这个电路。让我们开始吧：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/e0af2da2-7c85-476e-97eb-25ad65088378.png)

图 12.2 - 参考电路（3 部分之一）

以下是创建我们的面包板构建的第一部分的步骤。步骤编号与*图 12.2*中黑色圆圈中的数字相匹配：

1.  将 ADS1115 模块放入面包板中。

1.  将电位计放入面包板中。

1.  将 LED 放入面包板中，注意 LED 的引脚方向如图所示。

1.  将第二个 LED 放入面包板中，注意 LED 的引脚方向如图所示。

1.  将一个 200Ω电阻（R1）放入您的面包板中。这个电阻的一端与*步骤 3*中放置的 LED 的阳极腿共用一行。

1.  将另一个 200Ω电阻（R2）放入您的面包板中。这个电阻的一端与*步骤 5*中放置的第二个 LED 的阳极腿共用一行。

1.  将按键放入您的面包板中。

现在我们已经将组件放入面包板中，让我们开始将它们连接起来：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/332b67b8-0242-43a3-a206-485f0325e118.png)

图 12.3 - 参考电路（2/3 部分）

以下是继续进行面包板组装的步骤。步骤编号与*图 12.3*中的黑色圆圈中的编号相匹配：

1.  将树莓派的 3.3 伏特引脚连接到左侧电源轨的正电源轨。

1.  将 ADS1115 的 Vdd 端连接到左侧电源轨的正电源轨。

1.  将 ADS1115 的 GND 端连接到左侧电源轨的负电源轨。

1.  将 ADS1115 的 SCL 端连接到树莓派的 SCL 引脚。

1.  将 ADS1115 的 SDA 端连接到树莓派的 SDA 引脚。

1.  将树莓派上的 GND 引脚连接到左侧电源轨的负电源轨。

1.  将电位器的外端连接到左侧电源轨的正电源轨。

1.  将电位器的另一个外端连接到左侧电源轨的负电源轨。

1.  将电位器的中间端口连接到 ADS1115 的 A0 端口。

您是否记得，这种配置中的电位器正在创建一个可变电压分压器？如果没有，您可能需要重新阅读第六章，*软件工程师的电子学 101*。此外，如果您想对 ADS1115 模块进行详细复习，请参阅第五章，*将树莓派连接到物理世界*。

让我们继续组装：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/2c48c450-5450-4f1e-b387-70c8aaf5848a.png)

图 12.4 - 参考电路（3/3 部分）

以下是继续进行面包板组装的最后部分的步骤。步骤编号与*图 12.4*中的黑色圆圈中的编号相匹配：

1.  将树莓派的 GPIO 26 连接到 200Ω电阻（R1）。

1.  将树莓派的 GPIO 19 连接到第二个 200Ω电阻（R2）。

1.  将树莓派的 GPIO 21 连接到按键的一腿。

1.  将两个 LED 的阴极腿连接在一起。

1.  将 LED 的阴极腿连接到左侧电源轨的负电源轨。

1.  将按键的第二腿连接到左侧电源轨的负电源轨。

现在我们已经完成了电路组装，我们准备运行示例代码使电路工作。

## 运行示例

本章提供了四个不同版本的代码，可以与*图 12.1*中先前显示的电路配合使用。您将在`chapter12`文件夹中按版本组织的代码：

+   `chapter12/version1_eventloop`是一个基于*事件循环*的示例。

+   `chapter12/version2_thread`是一个基于*线程和回调*的示例。

+   `chapter12/version3_pubsub`是一个基于*发布者-订阅者*的示例。

+   `chapter12/version4_asyncio`是一个**异步 IO**（***AsyncIO***)*-based 示例。

所有版本在功能上是等效的；但是它们在代码结构和设计上有所不同。在测试电路后，我们将更详细地讨论每个版本。

以下是运行每个版本（从版本 1 开始）并测试电路的步骤：

1.  切换到`version1_eventloop`文件夹。

1.  简要查看`main.py`源文件，以及文件夹中的任何其他 Python 文件，了解它们包含的内容以及程序的结构。

1.  在终端中运行`main.py`（记得先切换到本章的虚拟环境）。

此时，如果您收到关于 I2C 或 ADS11x5 的错误，请记住有一个`i2cdetect`工具，可以用来确认 I2C 设备（如 ADS1115）是否正确连接并对您的树莓派可见。有关更多信息，请参阅第五章，*将您的树莓派连接到物理世界*。

1.  转动电位器拨号并观察*第一个*LED 的闪烁速率变化。

1.  短按按钮。

1.  转动电位器拨号并观察*第二个*LED 的闪烁速率变化。

1.  按住按钮 0.5 秒，观察两个 LED 现在以相同速率同步闪烁。

以下是您将收到的终端输出示例：

```py
(venv) $ cd version1_eventloop
(venv) $ python main.py
INFO:Main:Version 1 - Event Loop Example. Press Control + C To Exit.
INFO:Main:Setting rate for all LEDs to 2.5
INFO:Main:Turning the Potentiometer dial will change the rate for LED #0
INFO:Main:Changing LED #0 rate to 2.6
INFO:Main:Changing LED #0 rate to 2.7 
INFO:Main:Turning the Potentiometer dial will change the rate for LED #1
INFO:Main:Changing LED #1 rate to 2.6
INFO:Main:Changing LED #1 rate to 2.5
# Truncated
INFO:Main:Changing LED #1 rate to 0.5
INFO:Main:Changing rate for all LEDs to 0.5
```

1.  在终端中按*Ctrl *+ *C*退出程序。

1.  对`version2_threads`、`version3_pubsub`和`version4_asyncio`重复*步骤 1*至*8*。

您刚刚测试并浏览了四种不同程序的源代码（也许五种，如果您挑战自己创建了自己的程序），它们都以不同的方式实现了完全相同的最终结果。

现在是时候了解这些程序是如何构建的了。让我们从程序的*事件循环*版本开始。

# 探索事件循环方法

我们将通过讨论基于事件循环的方法来开始我们的代码探索，以构建我们在上一节中测试过的示例小玩意。

基于事件循环的方法的代码可以在`chapter12/version1_eventloop`文件夹中找到。您会找到一个名为`main.py`的文件。现在请花时间停下来阅读`main.py`中的代码，以基本了解程序的结构和工作原理。或者，您可以在代码中添加断点或插入`print()`语句，然后再次运行它以了解其工作原理。

您的体验如何，您注意到了什么？如果您认为*呸*或者在循环、`if`语句和状态变量的网络中迷失了，那么干得好！这意味着您已经投入了时间来考虑这种方法以及代码的构造方式。

我所说的事件循环方法在代码中通过第 1 行的`while True:`循环进行了演示：

```py
# chapter12/version1_eventloop
#
# Setup and initialization code goes before while loop.
#

if __name__ == "__main__":
    # Start of "Event Loop"
    while True:                                # (1)
      #
      # ... Main body of logic and code is within the while loop...
      #
      sleep(SLEEP_DELAY)
```

当然，我可以使用函数甚至外部类来减少`while`循环中的代码数量（可能还可以增强可读性），但是，总体设计范式仍然是相同的-程序控制的主体部分处于永久循环中。

如果您熟悉 Arduino 编程，您将对这种编程方法非常熟悉。这就是为什么我将本节标题为*事件循环*，因为这种方法和术语的流行度相似。尽管如此，请注意*事件循环*这个术语在 Python 中有更广泛的上下文，当我们查看程序的 AsyncIO（版本 4）时会看到。

您可能已经意识到，本书中许多示例都使用了这种事件循环编程方法。以下是三个示例：

+   当我们需要定时事件，比如闪烁 LED 时（第二章，*使用 Python 和物联网入门*）

+   DHT 11 或 DHT 22 温度/湿度传感器的轮询（第九章，*测量温度、湿度和光照水平*）

+   轮询连接到**光敏电阻**（**LDR**）的 ADS1115 模拟数字转换器（也第九章，*测量温度、湿度和光照水平*）

在这种情况下，对于一个单一的专注示例，事件循环是有意义的。甚至在你进行试验和学习新的执行器或传感器时，它们也是纯粹为了方便而有意义的。然而，正如我们的`version1_eventloop/main.py`程序所示，一旦你添加了多个组件（比如电位计、两个 LED 和一个按钮）并且想要让它们为一个明确的目的一起工作，代码就会迅速变得复杂。

例如，考虑一下第 3 行的以下代码，它负责让所有 LED 闪烁，并记住这个代码块在每次循环迭代中被评估一次，负责让每个 LED 闪烁：

```py
    #
    # Blink the LEDs.
    #
    now = time()                                               # (3)
    for i in range(len(LED_GPIOS)):
        if led_rates[i] <= 0:
            pi.write(LED_GPIOS[i], pigpio.LOW) # LED Off.
        elif now >= led_toggle_at_time[i]:
            pi.write(LED_GPIOS[i], not pi.read(LED_GPIOS[i])) # Toggle LED
            led_toggle_at_time[i] = now + led_rates[i]
```

与纯粹的替代方案相比（类似于我们将在其他方法中看到的），一眼看去，它们显然更容易理解：

```py
   while True:
      pi.write(led_gpio, not pi.read(led_gpio)) # Toggle LED GPIO High/Low
      sleep(delay)
```

如果你再考虑一下从第 2 行开始的以下代码块，它负责检测按钮按下，那么你会发现在实际的`main.py`文件中有将近 40 行代码，只是为了检测按钮的操作：

```py
while True:
    button_pressed = pi.read(BUTTON_GPIO) == pigpio.LOW        # (2)

    if button_pressed and not button_held:
        # Button has been pressed.
        # ... Truncated ...
    elif not button_pressed:
        if was_pressed and not button_held:
            # Button has been released
            # ... Truncated ...
    if button_hold_timer >= BUTTON_HOLD_SECS and not button_held:
        # Button has been held down
        # ... Truncated ...

    # ... Truncated ...
```

你会发现有多个变量在起作用 - `button_pressed`、`button_held`、`was_pressed`和`button_hold_timer` - 它们在每次`while`循环迭代中都被评估，并且主要用于检测*按钮按住*事件。我相信你会理解，像这样编写和调试这样的代码可能会很乏味和容易出错。

我们本可以使用`PiGPIO` *回调*来处理`while`循环之外的按钮按下，或者使用 GPIO Zero 的`Button`类。这两种方法都有助于减少按钮处理逻辑的复杂性。同样，也许我们本可以混合使用 GPIO Zero 的`LED`类来处理 LED 的闪烁。然而，如果这样做，我们的示例就不会是一个纯粹基于事件循环的示例。

现在，我并不是说事件循环是一种不好或错误的方法。它们有它们的用途，是必需的，实际上，每当我们使用`while`循环或其他循环结构时，我们都会创建一个 - 所以基本理念无处不在，但这并不是构建复杂程序的理想方法，因为这种方法使它们更难理解、维护和调试。

每当你发现你的程序正在走这条事件循环的道路时，停下来反思一下，因为也许是时候考虑重构你的代码，采用不同的 - 更易维护的 - 方法，比如线程/回调方法，我们将在下面看到。

# 探索线程方法

现在我们已经探索了一个基于事件循环的方法来创建我们的程序，让我们考虑一种使用线程、回调和面向对象编程的替代方法，并看看这种方法如何改进了代码的可读性和可维护性，并促进了代码的重用。

基于*线程*的方法的代码可以在`chapter12/version2_threads`文件夹中找到。你会找到四个文件 - 主程序`main.py`和三个类定义：`LED.py`、`BUTTON.py`和`POT.py`。

现在请花点时间停下来阅读`main.py`中包含的代码，以基本了解程序的结构和工作原理。然后，继续查看`LED.py`、`BUTTON.py`和`POT.py`。

它是如何进行的，你注意到了什么？我猜想你会发现这个程序的版本（在阅读`main.py`时）更快更容易理解，并且注意到没有繁琐复杂的`while`循环，而是一个`pause()`调用，这是必要的，用于阻止我们的程序退出，如第 3 行总结的那样：

```py
# chapter12/version2_threads/main.py
if __name__ == "__main__":                                       # (3)
        # Initialize all LEDs
        # ... Truncated ...

        # No While loop!
        # It's our BUTTON, LED and POT classes and the 
        # registered callbacks doing all the work.
        pause()
```

在这个程序示例中，我们使用了面向对象的技术，并使用了三个类来组件化我们的程序：

+   一个按钮类（`BUTTON.py`），负责所有按钮逻辑

+   一个电位计类（`POT.py`），负责所有电位计和模拟数字转换逻辑

+   一个 LED 类（`LED.py`），负责让*单个*LED 闪烁

通过使用面向对象的方法，我们的`main.py`代码大大简化了。它的作用现在是创建和初始化类实例，并包含使我们的程序工作的回调处理程序和逻辑。

考虑一下我们的按钮的面向对象的方法：

```py
# chapter12/version2_threads/main.py
# Callback Handler when button is pressed, released or held down.
def button_handler(the_button, state):
    global led_index
    if state == BUTTON.PRESSED:                                 # (1)
        #... Truncated ...
    elif state == BUTTON.HOLD:                                  # (2)
        #... Truncated 

# Creating button Instance
button = BUTTON(gpio=BUTTON_GPIO,
               pi=pi,
               callback=button_handler)
```

与事件循环示例中的按钮处理代码相比，这大大简化了并且更易读——很明显这段代码在第 1 行响应按钮按下，第 2 行响应按钮保持。

让我们考虑一下`BUTTON`类，它在`BUTTON.py`文件中定义。这个类是一个增强的包装器，可以将按钮的 GPIO 引脚的`HIGH`/`LOW`状态转换为`PRESSED`、`RELEASED`和`HOLD`事件，如在`BUTTON.py`的第 1 行中总结的代码所示：

```py
# chapter12/version2_threads/BUTTON.py
def _callback_handler(self, gpio, level, tick): # PiGPIO Callback  # (1)

     if level == pigpio.LOW: # level is LOW -> Button is pressed
         if self.callback: self.callback(self, BUTTON.PRESSED)

         # While button is pressed start a timer to detect
         # if it remains pressed for self.hold_secs
         timer = 0                                                 # (2)
         while (timer < self.hold_secs) and not self.pi.read(self.gpio):
             sleep(0.01)
             timer += 0.01

         # Button is still pressed after self.hold_secs
         if not self.pi.read(self.gpio):                
             if self.callback: self.callback(self, BUTTON.HOLD)

     else: # level is HIGH -> Button released            
         if self.callback: self.callback(self, BUTTON.RELEASED)
```

与事件循环示例中的按钮处理代码相比，我们没有引入和审问多个状态变量来检测按钮保持事件，而是将这个逻辑简化为在第 2 行的简单线性方法。

接下来，当我们考虑`POT`类（在`POT.py`中定义）和`LED`类（在`LED.py`中定义）时，我们将看到线程进入我们的程序。

您知道即使在多线程的 Python 程序中，也只有一个线程在活动吗？虽然这似乎违反直觉，但这是 Python 语言最初创建时做出的一个称为**全局解释器锁**（**GIL**）的设计决定。如果您想了解更多关于 GIL 和使用 Python 实现并发的其他形式的信息，您可以在本章的*进一步阅读*部分找到相关资源。

以下是`POT`类的线程运行方法，可以在`POT.py`源文件中找到，从第 1 行开始说明了中间轮询 ADS1115 ADC 以确定电位器位置的方法。我们已经在本书中多次看到这个轮询示例，最早是在第五章中，*将您的树莓派连接到物理世界*，我们首次讨论模数转换、ADS1115 模块和电位器：

```py
    # chapter12/version2_threads/POT.py
    def run(self):   
        while self.is_polling:                              # (1)
            current_value = self.get_value()  
            if self.last_value != current_value:            # (2)
                if self.callback:
                    self.callback(self, current_value)      # (3)
                self.last_value = current_value

            timer = 0  
            while timer < self.poll_secs:  # Sleep for a while
                sleep(0.01)
                timer += 0.01

        # self.is_polling has become False and the Thread ends.
        self.__thread = None
```

我们这里的代码不同之处在于我们正在监视 ADC 上的电压变化（例如，当用户转动电位器时），并将其转换为回调（在第 3 行），您在审查该文件中的源代码`main.py`时会看到。

现在让我们讨论一下我们如何实现`version2` LED 相关的代码。正如您所知，闪烁 LED 的基本代码模式涉及`while`循环和`sleep`语句。这就是 LED 类中采用的方法，如`LED.py`中第 3 行的`run()`方法中所示：

```py
# chapter12/version2_threads/LED.py
 def run(self):                                                    # (3)
     """ Do the blinking (this is the run() method for our Thread) """
     while self.is_blinking:
         # Toggle LED On/Off
         self.pi.write(self.gpio, not self.pi.read(self.gpio))

         # Works, but LED responsiveness to rate chances can be sluggish.
         # sleep(self.blink_rate_secs)

         # Better approach - LED responds to changes in near real-time.
         timer = 0
         while timer < self.blink_rate_secs:
             sleep(0.01)
             timer += 0.01

     # self.is_blinking has become False and the Thread ends.
     self._thread = None
```

我相信您会同意这比我们在前一节讨论的事件循环方法更容易理解。然而，重要的是要记住，事件循环方法是在*单个*代码块中使用和改变*所有*LED 的闪烁速率，并在*单个*线程——程序的主线程中进行的。

请注意前面代码中显示的两种睡眠方法。虽然使用 `sleep(self.blink_rate_secs)` 的第一种方法很常见且诱人，但需要注意的是它会阻塞线程，使其在整个睡眠期间无法立即响应速率变化，当用户转动电位器时会感觉迟钝。第二种方法，称为 `#Better approach`，缓解了这个问题，使 LED 能够（近乎）实时地响应速率变化。

我们的`version2`程序示例使用 LED 类及其自己的内部线程，这意味着我们现在有多个线程——每个 LED 一个——都独立地使 LED 独立地闪烁。

你能想到这可能引入的任何潜在问题吗？好吧，如果你已经阅读了`version2`源文件，这可能是显而易见的——当按钮按下 0.5 秒时，同步所有 LED 以同样的速率同时闪烁！

通过引入多个线程，我们引入了多个定时器（即`sleep()`语句），因此每个线程都在自己独立的时间表上闪烁，而不是从一个共同的参考点开始闪烁。

这意味着，如果我们简单地在多个 LED 上调用`led.set_rate(n)`，虽然它们都会以速率*n*闪烁，但它们不一定会同步闪烁。

解决这个问题的一个简单方法是在开始以相同速率闪烁之前同步关闭所有 LED。也就是说，我们从一个共同的状态（即关闭）开始让它们一起闪烁。

这种方法在`LED.py`的第 1 行开始的以下代码片段中显示。同步的核心是在第 2 行的`led._thread.join()`语句中实现的：

```py
    # chapter12/version2_threads/LED.py
    @classmethod                                           # (1)
    def set_rate_all(cls, rate):
        for led in cls.instances: # Turn off all LEDs.
            led.set_rate(0)

        for led in cls.instances:                        
            if led._thread:
                led._thread.join()                         # (2)

        # We do not get to this point in code until all 
        # LED Threads are complete (and LEDS are all off)

        for led in cls.instances:  # Start LED's blinking
            led.set_rate(rate)
```

这是同步的一个很好的第一步，对于我们的情况来说，实际上效果很好。正如前面提到的，我们所做的就是确保我们的 LED 从关闭状态同时开始闪烁（嗯，非常非常接近同时，取决于 Python 迭代`for`循环所花费的时间）。

尝试将前面代码中第 2 行的`led._thread.join()`和包含的`for`循环注释掉，然后运行程序。让 LED 以不同的速率闪烁，然后尝试通过按住按钮来同步它们。它总是有效吗？

但必须指出的是，我们仍然在处理多个线程和独立的定时器来让我们的 LED 闪烁，因此存在时间漂移的可能性。如果这曾经成为一个实际问题，那么我们将需要探索替代技术来同步每个线程中的时间，或者我们可以创建并使用一个单一的类来管理多个 LED（基本上使用事件循环示例中的方法，只是将其重构为一个类和一个线程）。

关于线程的要点是，当您将线程引入应用程序时，您可能会引入*可能*可以设计或同步的时间问题。

如果你的原型或新程序的第一次尝试涉及基于事件循环的方法（就像我经常做的那样），那么当你将代码重构为类和线程时，始终要考虑可能出现的任何时间和同步问题。在测试期间意外发现与同步相关的错误（或更糟糕的是，在生产中）是令人沮丧的，因为它们很难可靠地复制，并且可能导致需要进行大量的重做。

我们刚刚看到了如何使用面向对象编程技术、线程和回调创建样本小工具程序。我们已经看到了这种方法导致了更容易阅读和维护的代码，同时也发现了需要同步线程代码的额外要求和工作。接下来，我们将看一下我们的程序的第三种变体，它是基于发布-订阅模型的。

# 探索发布-订阅的替代方法

现在我们已经看到了使用线程、回调和面向对象编程技术创建程序的方法，让我们考虑第三种方法，使用*发布-订阅*模型。

发布-订阅方法的代码可以在`chapter12/version3_pubsub`文件夹中找到。你会找到四个文件——主程序`main.py`和三个类定义：`LED.py`、`BUTTON.py`和`POT.py`。

现在请花时间停下来阅读`main.py`中包含的代码，以基本了解程序的结构和工作原理。然后，继续查看`LED.py`、`BUTTON.py`和`POT.py`。

你可能已经注意到，整体程序结构（特别是类文件）与我们在上一个标题中介绍的`version2`线程/回调示例非常相似。

你可能也意识到，这种方法在概念上与 MQTT 采用的发布者/订阅者方法非常相似，我们在第四章中详细讨论了 MQTT、Python 和 Mosquitto MQTT Broker 的网络。主要区别在于，在我们当前的`version3`示例中，我们的发布者-订阅者上下文仅限于我们的程序运行时环境，而不是网络分布式程序集，这是我们 MQTT 示例的情况。

我已经使用`PyPubSub` Python 库在`version3`中实现了发布-订阅层，该库可以从[pypi.org](https://pypi.org)获取，并使用`pip`安装。我们不会详细讨论这个库，因为这种类型的库的整体概念和使用应该已经很熟悉了，如果没有，我相信一旦你审查了`version3`源代码文件（如果你还没有这样做），你会立刻明白发生了什么。

Python 通过 PyPi.org 提供了其他可选的 PubSub 库。选择在这个例子中使用`PyPubSub`是因为它的文档质量和提供的示例。你会在本章开头的*技术要求*部分找到这个库的链接。

由于`version2`（线程方法）和`version3`（发布者-订阅者方法）示例的相似性，我们不会详细讨论每个代码文件，只是指出核心差异：

+   在`version2`（线程）中，这是我们的`led`、`button`和`pot`类实例之间的通信方式：

+   我们在`main.py`上注册了`button`和`pot`类实例的回调处理程序。

+   `button`和`pot`通过这种回调机制发送事件（例如按钮按下或电位器调整）。

+   我们直接使用`set_rate()`实例方法和`set_rate_all()`类方法与 LED 类实例进行交互。

+   在“version3”（发布者-订阅者）中，这是类内通信结构和设计：

+   每个类实例都是非常松散耦合的。

+   没有回调。

+   在类实例创建并注册到`PyPubSub`之后，我们不再直接与任何类实例进行交互。

+   所有类和线程之间的通信都是使用`PyPubSub`提供的消息层进行的。

现在，说实话，我们的小玩意程序并不从发布者-订阅者方法中受益。我个人偏好采用回调版本来处理这样一个小程序。然而，我提供了发布者-订阅者的替代实现作为参考，这样你就有这个选择来考虑你自己的需求。

发布者-订阅者方法在更复杂的程序中表现出色，其中有许多组件（这里指的是软件组件，不一定是电子组件）需要共享数据，并且可以以异步的发布者-订阅者方式进行。

我们在本章中以四个非常离散和专注的例子来展示编码和设计方法。然而，在实践中，当创建程序时，通常会将这些方法（以及其他设计模式）以混合的方式结合起来。记住，使用的方法或方法组合应该是对你所要实现的目标最有意义的。

正如我们刚刚讨论过的，你在审查`version3`代码时会看到，我们的小玩意程序的发布者-订阅者方法是线程和回调方法的一个简单变体，我们不再直接使用回调与类实例交互，而是将所有代码通信标准化到一个消息层。接下来，我们将看看我们编写小玩意程序的最终方法，这次采用 AsyncIO 方法。

# 探索 AsyncIO 方法

到目前为止，在本章中，我们已经看到了三种不同的编程方法来实现相同的最终目标。我们的第四种和最终方法将使用 Python 3 提供的 AsyncIO 库构建。正如我们将看到的，这种方法与我们以前的方法有相似之处和不同之处，并且还为我们的代码及其操作方式增加了一个额外的维度。

根据我的经验，第一次体验 Python 中的异步编程可能会感到复杂、繁琐和令人困惑。是的，异步编程有一个陡峭的学习曲线（在本节中我们只能勉强触及表面）。然而，当您学会掌握这些概念并获得实际经验时，您可能会开始发现这是一种优雅而优美的创建程序的方式！

如果您是 Python 中异步编程的新手，您将在*进一步阅读*部分找到精心策划的教程链接，以加深您的学习。在本节中，我打算为您提供一个专注于电子接口的简单工作的 AsyncIO 程序，您可以在学习更多关于这种编程风格时作为参考。

基于异步的方法的代码可以在`chapter12/version4_asyncio`文件夹中找到。您会找到四个文件 - 主程序`main.py`和三个类定义：`LED.py`，`BUTTON.py`和`POT.py`。

现在请花时间停下来阅读`main.py`中包含的代码，以基本了解程序的结构和工作原理。然后继续查看`LED.py`，`BUTTON.py`和`POT.py`。

如果您也是 JavaScript 开发人员 - 特别是 Node.js - 您可能已经知道 JavaScript 是一种异步编程语言；但是，它看起来和感觉起来与您在 Python 中看到的非常不同！我可以向您保证，原则是相同的。以下是它们感觉非常不同的一个关键原因 - JavaScript 是*默认异步*的。正如任何有经验的 Node.js 开发人员所知道的，我们经常不得不在代码中采取（通常是极端的）措施来使我们的代码部分表现出同步行为。对于 Python 来说，情况正好相反 - 它是*默认同步*的，我们需要额外的编程工作来使我们的代码部分表现出异步行为。

当您阅读源代码文件时，我希望您将我们的`version4` AsyncIO 程序视为同时具有`version1`基于事件循环的程序和`version2`线程/回调程序的元素。以下是关键差异和相似之处的摘要：

+   整体程序结构与`version2`线程/回调示例非常相似。

+   在`main.py`的末尾，我们有几行新的代码，在这本书中我们以前没有见过 - 例如，`loop = asyncio.get_event_loop()`。

+   像`version2`程序一样，我们使用了面向对象编程技术将组件分解为类，这些类也有一个`run()`方法 - 但请注意这些类中没有线程实例，也没有与启动线程相关的代码。

+   在类定义文件`LED.py`，`BUTTON.py`和`POT.py`中，我们在`run()`函数中使用了`async`和`await`关键字，并在`while`循环中延迟了 0 秒 - 也就是说，`asyncio.sleep(0)` - 因此我们实际上并没有睡觉！

+   在`BUTTON.py`中，我们不再使用 PiGPIO 回调来监视按钮被按下，而是在`while`循环中轮询按钮的 GPIO。

Python 3 的 AsyncIO 库随着时间的推移发生了显著的演变（并且仍在演变），具有新的 API 约定，更高级功能的添加和废弃的函数。由于这种演变，代码可能会很快地与最新的 API 约定过时，两个代码示例展示了相同的基本概念，但可能使用看似不同的 API。我强烈建议您浏览最新的 Python AsyncIO 库 API 文档，因为它将为您提供有关新旧 API 实践的提示和示例，这可能有助于您更好地解释代码示例。

我将通过以简化的方式引导您了解程序的高级程序流程来解释这个程序是如何工作的。当您能够掌握正在发生的一般情况时，您就已经在理解 Python 中的异步编程方面迈出了重要的一步。

您还会发现一个名为`chapter12/version4_asyncio/main_py37.py`的文件。这是我们程序的 Python 3.7+版本。它使用自 Python 3.7 以来可用的 API。如果您浏览这个文件，差异是清楚地被注释了。

在`main.py`文件的末尾，我们看到以下代码：

```py
if __name__ == "__main__":
       # .... truncated ....

        # Get (create) an event loop.
        loop = asyncio.get_event_loop()      # (1)

        # Register the LEDs.
        for led in LEDS:
            loop.create_task(led.run())      # (2)

        # Register Button and Pot
        loop.create_task(pot.run())          # (3)
        loop.create_task(button.run())       # (4)

        # Start the event loop.
        loop.run_forever()                   # (5)
```

Python 中的异步程序围绕着事件循环发展。我们在第 1 行创建了这个事件循环，并在第 5 行启动了它。我们将在稍后回到在第 2、3 和 4 行之间发生的注册。

这个异步事件循环的整体原则与我们的 version1 事件循环示例类似；但是，语义是不同的。两个版本都是单线程的，两组代码都会*在循环中运行*。在`version1`中，这是非常明确的，因为我们的主要代码体包含在外部的`while`循环中。在我们的异步`version4`中，这更加隐含，并且有一个核心的区别——如果编写正确，它是非阻塞的，并且很快我们会看到，这是类`run()`方法中`await asyncio.sleep()`调用的目的。

正如前面提到的，我们已经在第 2、3 和 4 行将我们的类`run()`方法注册到循环中。在第 5 行启动事件循环后，简化来看发生了以下情况：

1.  *第一个*LED 的`run()`函数（在下面的代码中显示）被调用：

```py
# version4_asyncio/LED.py
async def run(self):
    """ Do the blinking """
    while True:                                           # (1)
        if self.toggle_at > 0 and 
              (time() >= self.toggle_at):                 # (2)
            self.pi.write(self.gpio, not self.pi.read(self.gpio))
            self.toggle_at += self.blink_rate_secs

        await asyncio.sleep(0)                            # (3)
```

1.  它进入第 1 行的`while`循环，并根据闪烁速率从第 2 行切换 LED 的开关状态。

1.  接下来，它到达第 3 行，`await asyncio.sleep(0)`，并*让出*控制。在这一点上，`run()`方法实际上被暂停了，另一个`while`循环迭代不会开始。

1.  控制权转移到*第二个*LED 的`run()`函数，并且它通过它的`while`循环运行一次，直到达到`await asyncio.sleep(0)`。然后它让出控制。

1.  现在，pot 实例的`run()`方法（在下面的代码中显示）获得了运行的机会：

```py
async def run(self):
    """ Poll ADC for Voltage Changes """
    while True:
        # Check if the Potentiometer has been adjusted.
        current_value = self.get_value()
        if self.last_value != current_value:

            if self.callback:
                self.callback(self, current_value)

            self.last_value = current_value

        await asyncio.sleep(0)
```

1.  `run()`方法执行`while`循环的一个迭代，直到达到`await asyncio.sleep(0)`。然后它让出控制。

1.  控制权转移到`button`实例的`run()`方法（部分显示在下面的代码中），它有多个`await asyncio.sleep(0)`语句：

```py
async def run(self):
    while True:
        level = self.pi.read(self.gpio) # LOW(0) or HIGH(1)

        # Waiting for a GPIO level change.
        while level == self.__last_level:
            await asyncio.sleep(0)

            # ... truncated ...

            while (time() < hold_timeout_at) and \
                   not self.pi.read(self.gpio):
                await asyncio.sleep(0)

        # ... truncated ...
        await asyncio.sleep(0)
```

1.  一旦按钮的`run()`方法达到任何`await asyncio.sleep(0)`的实例，它就会让出控制。

1.  现在，我们所有注册的`run()`方法都有机会运行，所以*第一个*LED 的`run()`方法将再次控制并执行一个`while`循环迭代，直到达到`await asyncio.sleep(0)`。同样，在这一点上它*让出*控制，*第二个*LED 的`run()`方法再次获得运行的机会...这个过程一遍又一遍地继续进行，每个`run()`方法以轮流的方式获得运行的机会。

让我们解决一些可能会有问题的问题：

+   那么按钮的`run()`函数和它的许多`await asyncio.sleep(0)`语句呢？

当在任何`await asyncio.sleep(0)`语句处*让出*控制时，函数就在这一点上让出。下一次`run()`按钮获得控制时，代码将从`await asyncio.sleep(0)`语句下面的下一个语句继续执行。

+   为什么睡眠延迟为 0 秒？

等待零延迟睡眠是放弃控制的最简单方法（请注意，这是`asyncio`库的`sleep()`函数，而不是`time`库的`sleep()`函数）。然而，你可以`await`任何异步方法，但这超出了我们简单示例的范围。

我在这个例子中使用了零秒延迟，以简化解释程序的工作原理，但你也可以使用非零延迟。这只是意味着放弃控制的`run()`函数会在这段时间内休眠 - 直到这段时间过去，事件循环才会让它运行。

+   那么`async`和`await`关键字呢？我怎么知道在哪里使用它们？

这当然需要练习；然而，这里有一些基本的设计规则：

+   +   如果你要向事件循环注册一个函数（例如`run()`），那么这个函数必须以`async`关键字开头。

+   任何`async`函数必须包含至少一个`await`语句。

编写和学习异步程序需要练习和实验。你将面临的一个最初的设计挑战是知道在哪里放置`await`语句（以及有多少个），以及你应该放弃控制多长时间。我鼓励你玩一下`version4`代码库，添加你自己的调试`print()`或日志语句，然后进行实验和调试，直到你对它如何组合在一起有了感觉。在某个时候，你会有那个“啊哈”时刻，那时，你刚刚打开了进一步探索 Python AsyncIO 库提供的许多高级功能的大门。

现在我们已经看到了异步程序在运行时的结构和行为，我想给你一些可以进行实验和思考的东西。

## 异步实验

让我们试一试。也许你想知道为什么`version4`（AsyncIO）有点像我们的`version1`（事件循环）代码，只是它已经重构成类，就像`version2`（线程）代码一样。那么，我们是否可以将`version1 while`循环中的代码重构成类，创建并调用一个函数（例如`run()`）在`while`循环中，而不必理会所有的异步内容及其额外的库和语法？

让我们试试。你会在`chapter12/version5_eventloop2`文件夹中找到一个与此类似的版本。尝试运行这个版本，看看会发生什么。你会发现第一个 LED 会闪烁，第二个 LED 会一直亮着，按钮和电位器不起作用。

你能想出原因吗？

简单的答案是：在`main.py`中，一旦第一个 LED 的`run()`函数被调用，我们就会永远停留在它的`while`循环中！

调用`sleep()`（来自`time`库）不会放弃控制；它只是在下一个`while`循环迭代发生之前暂停 LED 的`run()`方法。

因此，这就是为什么我们说同步程序是阻塞的（不会放弃控制），而异步程序是非阻塞的（它们放弃控制并让其他代码有机会运行）的一个例子。

希望你喜欢我们探索了四种不同的构建电子接口程序的方法，以及我们不应该使用的方法。让我们通过回顾本章学到的内容来结束。

# 总结

在本章中，我们看了四种不同的 Python 程序与电子设备接口的结构方式。我们了解了一种基于事件循环的编程方法，两种基于线程的变体 - 回调和发布-订阅模型 - 最后看了一下异步编程的工作方式。

我们讨论的四个例子都在方法上非常具体和离散。虽然我们在讨论过程中简要讨论了每种方法的相对优势和缺点，但值得记住的是，在实践中，你的项目可能会使用这些方法的混合（可能还有其他方法），这取决于你试图实现的编程和接口目标。

在下一章中，我们将把注意力转向物联网平台，并讨论可用于构建物联网程序的各种选项和替代方案。

# 问题

最后，这里有一些问题供您测试本章内容的知识。您可以在书的“评估”部分找到答案：

1.  发布者-订阅者模型何时是一个好的设计方法？

1.  Python GIL 是什么，对于经典线程有什么影响？

1.  为什么纯事件循环通常不适合复杂的应用程序？

1.  事件循环方法是一个坏主意吗？为什么？

1.  `thread.join()`函数调用的目的是什么？

1.  您已经使用线程通过模拟数字转换器来轮询您的新模拟组件。然而，您发现您的代码对组件的变化反应迟缓。可能的问题是什么？

1.  在 Python 中设计物联网或电子接口应用的优越方法是什么——使用事件循环、线程/回调、发布者-订阅者模型还是基于 AsyncIO 的方法？

# 进一步阅读

[realpython.com](https://realpython.com)网站提供了一系列优秀的教程，涵盖了 Python 中的并发编程，包括以下内容：

+   Python GIL 是什么？[`realpython.com/python-gil`](https://realpython.com/python-gil)

+   通过并发加速您的 Python 程序：[`realpython.com/python-concurrency`](https://realpython.com/python-concurrency)

+   Python 中线程的介绍：[`realpython.com/intro-to-python-threading`](https://realpython.com/intro-to-python-threading)

+   Python 中的异步 IO：完整演练：[`realpython.com/async-io-python`](https://realpython.com/async-io-python)

以下是来自官方 Python（3.7）API 文档的相关链接：

+   线程：[`docs.python.org/3.7/library/threading.html`](https://docs.python.org/3.7/library/threading.html)

+   AsyncIO 库：[`docs.python.org/3.7/library/asyncio.htm`](https://docs.python.org/3.7/library/asyncio.htm)

+   使用 AsyncIO 进行开发：[`docs.python.org/3.7/library/asyncio-dev.html`](https://docs.python.org/3.7/library/asyncio-dev.html)

+   Python 中的并发编程：[`docs.python.org/3.7/library/concurrency.html`](https://docs.python.org/3.7/library/concurrency.html)
