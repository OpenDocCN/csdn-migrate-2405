# Python 物联网项目（四）

> 原文：[`zh.annas-archive.org/md5/34135f16ce1c2c69e5f81139e996b460`](https://zh.annas-archive.org/md5/34135f16ce1c2c69e5f81139e996b460)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十四章：使用 Python 控制机器人小车

在第十三章中，*介绍树莓派机器人小车*，我们建造了 T.A.R.A.S 机器人小车。在章节结束时，我们讨论了如何通过代码控制 T.A.R.A.S。在本章中，我们将开始编写代码来实现这一点。

我们将首先编写简单的 Python 代码，然后利用 GPIO Zero 库使车轮向前移动，移动携带摄像头的伺服电机，并点亮机器人小车后面的 LED 灯。

然后，我们将使用类组织我们的代码，然后进一步增强它，让 T.A.R.A.S 执行秘密安全任务。

本章将涵盖以下主题：

+   查看 Python 代码

+   修改机器人小车的 Python 代码

+   增强代码

# 完成本章所需的知识

如果您跳到本章而没有经历前几章的项目，让我概述一下您完成以下项目所需的技能。当然，我们必须知道如何在 Raspbian OS 中四处走动，以便找到我们的**集成开发环境**（**IDE**）。

在完成 T.A.R.A.S 的编程后，您可能会倾向于利用新技能与其他构建树莓派机器人的人竞争。Pi Wars ([`piwars.org/`](https://piwars.org/))就是这样一个地方。Pi Wars 是一个在英国剑桥举行的国际机器人竞赛。在一个周末内，最多有 76 支队伍参加基于挑战的机器人竞赛。尽管它被称为 Pi Wars，但您可以放心，您不会带着一箱破碎的零件回来，因为每场比赛都是非破坏性的挑战。查看[`piwars.org/`](https://piwars.org/)，或在 YouTube 上搜索 Pi Wars 视频以获取更多信息。

此外，需要对 Python 有一定的了解，因为本章的所有编码都将使用 Python 完成。由于我喜欢尽可能多地使用面向对象的方法，一些**面向对象编程**（**OOP**）的知识也将帮助您更好地从本章中受益。

# 项目概述

在本章中，我们将编程 T.A.R.A.S 在桌子周围跳舞并拍照。本章的项目应该需要几个小时才能完成。

# 入门

要完成这个项目，需要以下内容：

+   树莓派 3 型号（2015 年或更新型号）

+   USB 电源供应

+   计算机显示器

+   USB 键盘

+   USB 鼠标

+   已完成的 T.A.R.A.S 机器人小车套件（参见第十三章，*介绍树莓派机器人小车*）

# 查看 Python 代码

在某种程度上，我们的机器人小车项目就像是我们在前几章中所做的代码的概述。通过使用 Python 和令人惊叹的 GPIO Zero 库，我们能够从 GPIO 读取传感器数据，并通过向 GPIO 引脚写入数据来控制输出设备。在接下来的步骤中，我们将从非常简单的 Python 代码和 GPIO Zero 库开始。如果您已经完成了本书中的一些早期项目，那么这些代码对您来说将会非常熟悉。

# 控制机器人小车的驱动轮

让我们看看是否可以让 T.A.R.A.S 移动一点。我们将首先编写一些基本代码来让机器人小车前后移动：

1.  从应用程序菜单 | 编程 | Thonny Python IDE 中打开 Thonny

1.  单击新图标创建新文件

1.  将以下代码输入文件：

```py
from gpiozero import Robot
from time import sleep

robot = Robot(left=(5,6), right=(22,27))
robot.forward(0.2)
sleep(0.5)
robot.backward(0.2)
sleep(0.5)
robot.stop()
```

1.  将文件保存为`motor-test.py`

1.  运行代码

您应该看到机器人小车向前移动`0.5`秒，然后向后移动相同的时间。如果路上没有障碍物，机器人小车应该回到起始位置。代码相当简单明了；然而，我们现在将对其进行讨论。

我们首先导入我们需要的库：`Robot`和`sleep`。之后，我们实例化一个名为`robot`的`Robot`对象，并将其配置为左侧电机的`5`和`6`引脚，右侧电机的`22`和`27`引脚。之后，我们以`0.2`的速度将机器人向前移动。为了使机器人移动更快，我们增加这个值。稍作延迟后，我们使用`robot.backward(0.2)`命令将机器人返回到原始位置。

需要注意的一点是电机的旋转方式，它们会一直旋转，直到使用`robot.stop()`命令停止。

如果发现电机没有按预期移动，那是因为接线的问题。尝试尝试不同的接线和更改`Robot`对象的引脚号码（left=(5,6), right=(22,27)）。可能需要几次尝试才能搞定。

# 移动机器人车上的舵机

我们现在将测试舵机。为了做到这一点，我们将从右到左摆动机器人摄像头支架（机器人的头）：

1.  从应用程序菜单 | 编程 | Thonny Python IDE 打开 Thonny

1.  单击新图标创建一个新文件

1.  将以下代码输入文件：

```py
import Adafruit_PCA9685 from time import sleep pwm = Adafruit_PCA9685.PCA9685() servo_min = 150
servo_max = 600 while True:
    pwm.set_pwm(0, 0, servo_min)
    sleep(5)
    pwm.set_pwm(0, 0, servo_max)
    sleep(5) 
```

1.  将文件保存为`servo-test.py`

1.  运行代码

您应该看到机器人头部向右移动，等待`5`秒，然后向左移动。

在代码中，我们首先导入`Adafruit_PCA9685`库。在导入`sleep`函数后，我们创建一个名为`pwm`的`PCA9685`对象。当然，这是一个使用 Adafruit 代码构建的对象，用于支持 HAT。然后我们分别设置舵机可以移动的最小和最大值，分别为`servo_min`和`servo_max`。

如果您没有得到预期的结果，请尝试调整`servo_min`和`servo_max`的值。我们在第五章中稍微涉及了一些关于舵机的内容，*用 Python 控制舵机*。

# 拍照

您可能还记得在以前的章节中使用树莓派摄像头；特别是第九章，*构建家庭安全仪表板*，我们在那里使用它为我们的安全应用程序拍照。由于 T.A.R.A.S 将是我们可靠的安全代理，它有能力拍照是有意义的。让我们编写一些代码来测试一下我们的机器人车上的摄像头是否工作：

1.  从应用程序菜单 | 编程 | Thonny Python IDE 打开 Thonny

1.  单击新图标创建一个新文件

1.  输入以下代码：

```py
from picamera import PiCamera import time camera = PiCamera() camera.capture("/home/pi/image-" + time.ctime() + ".png")   
```

1.  将文件保存为`camera-test.py`

1.  运行代码

如果一切设置正确，您应该在`/home/pi`目录中看到一个图像文件，文件名为`image`，后跟今天的日期。

# 发出蜂鸣声

我们的安全代理受限于发出噪音以警示我们并吓跑潜在的入侵者。在这一部分，我们将测试安装在 T.A.R.A.S 上的有源蜂鸣器。

旧的英国警察口哨是过去警察官员必须自卫的最早和可信赖的装备之一。英国警察口哨以其独特的声音，允许警官之间进行交流。尽管警察口哨已不再使用，但它的遗产对社会产生了影响，以至于“吹哨人”这个术语至今仍用来指代揭露隐藏的不公正或腐败的人。

1.  从应用程序菜单 | 编程 | Thonny Python IDE 打开 Thonny

1.  单击新图标创建一个新文件

1.  将以下代码输入文件：

```py
from gpiozero import Buzzer
from time import sleep

buzzer = Buzzer(12)
buzzer.on()
sleep(5)
buzzer.off()
```

1.  将文件保存为`buzzer-test.py`

1.  运行代码

您应该听到蜂鸣器声音持续`5`秒，然后关闭。

# 让 LED 闪烁

在 T.A.R.A.S 的背面，我们安装了两个 LED（最好是一个红色和一个绿色）。我们以前使用简单的 GPIO Zero 库命令来闪烁 LED，所以这对我们来说不应该是一个挑战。让我们更进一步，创建可以用来封装 LED 闪烁模式的代码：

1.  从应用程序菜单中打开 Thonny | 编程 | Thonny Python IDE

1.  点击新图标创建一个新文件

1.  输入以下代码：

```py
from gpiozero import LEDBoard
from time import sleep

class TailLights:

    led_lights = LEDBoard(red=21, green=20)

    def __init__(self):
        self.led_lights.on()
        sleep(0.25)
        self.led_lights.off()
        sleep(0.25)

    def blink_red(self, num, duration):
        for x in range(num):
            self.led_lights.red.on()
            sleep(duration)
            self.led_lights.red.off()
            sleep(duration)

    def blink_green(self, num, duration):
        for x in range(num):
            self.led_lights.green.on()
            sleep(duration)
            self.led_lights.green.off()
            sleep(duration)

    def blink_alternating(self, num, duration):
        for x in range(num):
            self.led_lights.red.off()
            self.led_lights.green.on()
            sleep(duration)
            self.led_lights.red.on()
            self.led_lights.green.off()
            sleep(duration)
        self.led_lights.red.off()

    def blink_together(self, num, duration):
        for x in range(num):
            self.led_lights.on()
            sleep(duration)
            self.led_lights.off()
            sleep(duration)

    def alarm(self, num):
        for x in range(num):
            self.blink_alternating(2, 0.25)
            self.blink_together(2, 0.5)

if __name__=="__main__":

    tail_lights = TailLights()
    tail_lights.alarm(20) 
```

1.  将文件保存为`TailLights.py`

1.  运行代码

你应该看到 LED 显示器闪烁 20 秒。但值得注意的是我们的代码中使用了 GPIO Zero 库的`LEDBoard`类，如下所示：

```py
led_lights = LEDBoard(red=21, green=20)
```

在这段代码中，我们从`LEDBoard`类中实例化一个名为`led_lights`的对象，并使用`red`和`green`的值来配置它，分别指向`21`和`20`的 GPIO 引脚。通过使用`LEDBoard`，我们能够分别或作为一个单元来控制 LED。`blink_together`方法控制 LED 作为一个单元，如下所示：

```py
def blink_together(self, num, duration):
        for x in range(num):
            self.led_lights.on()
            sleep(duration)
            self.led_lights.off()
            sleep(duration)
```

我们的代码相当容易理解；然而，还有一些其他事情我们应该指出。当我们初始化`TailLights`对象时，我们让 LED 短暂闪烁以表示对象已被初始化。这样可以在以后进行故障排除；尽管，如果我们觉得代码是多余的，那么我们以后可以将其删除：

```py
def __init__(self):
        self.led_lights.on()
        sleep(0.25)
        self.led_lights.off()
        sleep(0.25)
```

保留初始化代码可能会很方便，尤其是当我们想要确保我们的 LED 没有断开连接时（毕竟，谁在尝试连接其他东西时没有断开过某些东西呢？）。要从 shell 中执行此操作，请输入以下代码：

```py
import TailLights
tail_lights = TailLights.TailLights()
```

你应该看到 LED 闪烁了半秒钟。

# 修改机器人车 Python 代码

现在我们已经测试了电机、舵机、摄像头和 LED，是时候将代码修改为类，以使其更加统一了。在本节中，我们将让 T.A.R.A.S 跳舞。

# 移动车轮

让我们从封装移动机器人车轮的代码开始：

1.  从应用程序菜单中打开 Thonny | 编程 | Thonny Python IDE

1.  点击新图标创建一个新文件

1.  将以下代码输入文件中：

```py
from gpiozero import Robot
from time import sleep

class RobotWheels:

    robot = Robot(left=(5, 6), right=(22, 27))

    def __init__(self):
        pass

    def move_forward(self):
        self.robot.forward(0.2)

    def move_backwards(self):
        self.robot.backward(0.2)

    def turn_right(self):
        self.robot.right(0.2)

    def turn_left(self):
        self.robot.left(0.2)

    def dance(self):
        self.move_forward()
        sleep(0.5)
        self.stop()
        self.move_backwards()
        sleep(0.5)
        self.stop()
        self.turn_right()
        sleep(0.5)
        self.stop()
        self.turn_left()
        sleep(0.5)
        self.stop()

    def stop(self):
        self.robot.stop()

if __name__=="__main__":

    robot_wheels = RobotWheels()
    robot_wheels.dance() 
```

1.  将文件保存为`RobotWheels.py`

1.  运行代码

你应该看到 T.A.R.A.S 在你面前跳了一小段舞。确保连接到 T.A.R.A.S 的电线松动，这样 T.A.R.A.S 就可以做自己的事情。谁说机器人不能跳舞呢？

这段代码相当容易理解。但值得注意的是我们如何从`dance`方法中调用`move_forward`、`move_backwards`、`turn_left`和`turn_right`函数。我们实际上可以参数化移动之间的时间，但这会使事情变得更加复杂。`0.5`秒的延迟（加上硬编码的速度`0.2`）似乎非常适合一个不会从桌子上掉下来的跳舞机器人。可以把 T.A.R.A.S 想象成在一个非常拥挤的舞池上，没有太多的移动空间。

但等等，还有更多。T.A.R.A.S 还可以移动头部、点亮灯光并发出一些声音。让我们开始添加这些动作。

# 移动头部

由于 T.A.R.A.S 上的摄像头连接到头部，因此将头部运动（摄像头支架舵机）与摄像头功能封装起来是有意义的：

1.  从应用程序菜单中打开 Thonny | 编程 | Thonny Python IDE

1.  点击新图标创建一个新文件

1.  将以下代码输入文件中：

```py
from time import sleep
from time import ctime
from picamera import PiCamera
import Adafruit_PCA9685

class RobotCamera:

    pan_min = 150
    pan_centre = 375
    pan_max = 600
    tilt_min = 150
    tilt_max = 200
    camera = PiCamera()
    pwm = Adafruit_PCA9685.PCA9685()

    def __init__(self):
        self.tilt_up()

    def pan_right(self):
        self.pwm.set_pwm(0, 0, self.pan_min)
        sleep(2)

    def pan_left(self):
        self.pwm.set_pwm(0, 0, self.pan_max)
        sleep(2)

    def pan_mid(self):
        self.pwm.set_pwm(0, 0, self.pan_centre)
        sleep(2)

    def tilt_down(self):
        self.pwm.set_pwm(1, 0, self.tilt_max)
        sleep(2)

    def tilt_up(self):
        self.pwm.set_pwm(1, 0, self.tilt_min)
        sleep(2)

    def take_picture(self):
        sleep(2)
        self.camera.capture("/home/pi/image-" + ctime() + ".png")

    def dance(self):
        self.pan_right()
        self.tilt_down()
        self.tilt_up()
        self.pan_left()
        self.pan_mid()

    def secret_dance(self):
        self.pan_right()
        self.tilt_down()
        self.tilt_up()
        self.pan_left()
        self.pan_mid()
        self.take_picture()

if __name__=="__main__":

    robot_camera = RobotCamera()
    robot_camera.dance()
```

1.  将文件保存为`RobotCamera.py`

1.  运行代码

你应该看到 T.A.R.A.S 把头向右转，然后向下，然后向上，然后全部向左，然后返回到中间并停止。

再次，我们尝试编写我们的代码，使其易于理解。当实例化`RobotCamera`对象时，`init`方法确保 T.A.R.A.S 在移动头部之前将头部抬起：

```py
def __init__(self):
    self.tilt_up()
```

通过调用`RobotCamera`类，我们将代码结构化为查看机器人车头部舵机和运动的一部分。尽管我们在示例中没有使用摄像头，但我们很快就会使用它。为舵机位置设置的最小和最大值是通过试验和错误确定的，如下所示：

```py
pan_min = 150
pan_centre = 375
pan_max = 600
tilt_min = 150
tilt_max = 200
```

尝试调整这些值以适应您的 T.A.R.A.S 机器人车的构建。

`dance`和`secret_dance`方法使用机器人车头执行一系列动作来模拟跳舞。它们基本上是相同的方法（除了`take_picture`在最后调用），`secret_dance`方法使用树莓派摄像头拍照，并以基于日期的名称存储在主目录中。

# 发出声音

现在 T.A.R.A.S 可以移动身体和头部了，是时候发出一些声音了：

1.  从应用程序菜单中打开 Thonny | 编程 | Thonny Python IDE

1.  单击新图标创建新文件

1.  将以下代码输入文件

```py
from gpiozero import Buzzer
from time import sleep

class RobotBeep:

    buzzer = Buzzer(12)
    notes = [[0.5,0.5],[0.5,1],[0.2,0.5],[0.5,0.5],[0.5,1],[0.2,0.5]]

    def __init__(self, play_init=False):

        if play_init:
            self.buzzer.on()
            sleep(0.1)
            self.buzzer.off()
            sleep(1)

    def play_song(self):

        for note in self.notes:
            self.buzzer.on()
            sleep(note[0])
            self.buzzer.off()
            sleep(note[1])

if __name__=="__main__":

    robot_beep = RobotBeep(True)
```

1.  将文件保存为`RobotBeep.py`

1.  运行代码

您应该听到 T.A.R.A.S 上的有源蜂鸣器发出短促的蜂鸣声。这似乎是为了做这个而写了很多代码，不是吗？啊，但是等到下一节，当我们充分利用`RobotBeep`类时。

`RobotBeep`的`init`函数允许我们打开和关闭类实例化时听到的初始蜂鸣声。这对于测试我们的蜂鸣器是否正常工作很有用，我们通过在创建`robot_beep`对象时向类传递`True`来进行测试：

```py
robot_beep = RobotBeep(True)
```

`notes`列表和`play_song`方法执行类的实际魔术。该列表实际上是一个列表的列表，因为每个值代表蜂鸣器播放或休息的时间：

```py
for note in self.notes:
    self.buzzer.on()
    sleep(note[0])
    self.buzzer.off()
    sleep(note[1])
```

循环遍历`notes`列表，查看`note`变量。我们使用第一个元素作为保持蜂鸣器开启的时间长度，第二个元素作为在再次打开蜂鸣器之前休息的时间量。换句话说，第一个元素确定音符的长度，第二个元素确定该音符与下一个音符之间的间隔。`notes`列表和`play_song`方法使 T.A.R.A.S 能够唱歌（尽管没有旋律）。

我们将在下一节中使用`play_song`方法。

# 增强代码

这是一个寒冷，黑暗和阴郁的十二月之夜。我们对我们的对手知之甚少，但我们知道他们喜欢跳舞。T.A.R.A.S 被指派到敌人领土深处的一个当地舞厅。在这个晚上，所有感兴趣的人都在那里。如果您选择接受的话，您的任务是编写一个程序，让 T.A.R.A.S 在舞厅拍摄秘密照片。但是，它不能看起来像 T.A.R.A.S 在拍照。T.A.R.A.S 必须跳舞！如果我们的对手发现 T.A.R.A.S 在拍照，那将是糟糕的。非常糟糕！想象一下帝国反击战中的 C3PO 糟糕。

# 将我们的代码连接起来

因此，我们有能力让 T.A.R.A.S 移动头部和身体，发出声音，发光和拍照。让我们把所有这些放在一起，以便完成任务：

1.  从应用程序菜单中打开 Thonny | 编程 | Thonny Python IDE

1.  单击新图标创建新文件

1.  将以下内容输入文件：

```py
from RobotWheels import RobotWheels
from RobotBeep import RobotBeep
from TailLights import TailLights
from RobotCamera import RobotCamera

class RobotDance:

    light_show = [2,1,4,5,3,1]

    def __init__(self):

        self.robot_wheels = RobotWheels()
        self.robot_beep = RobotBeep()
        self.tail_lights = TailLights()
        self.robot_camera = RobotCamera()

    def lets_dance_incognito(self):
        for tail_light_repetition in self.light_show:
            self.robot_wheels.dance()
            self.robot_beep.play_song()
            self.tail_lights.alarm(tail_light_repetition)
            self.robot_camera.secret_dance()

if __name__=="__main__":

    robot_dance = RobotDance()
    robot_dance.lets_dance_incognito()

```

1.  将文件保存为`RobotDance.py`

1.  运行代码

在秘密拍照之前，您应该看到 T.A.R.A.S 执行一系列动作。如果舞蹈结束后检查树莓派`home`文件夹，您应该会看到六张新照片。

我们代码中值得注意的是`light_show`列表的使用。我们以两种方式使用此列表。首先，将列表中存储的值传递给我们在`RobotDance`类中实例化的`TailLights`对象的`alarm`方法。我们在`lets_dance_incognito`方法中使用`tail_light_repetition`变量，如下所示：

```py
def lets_dance_incognito(self):
    for tail_light_repetition in self.light_show:
        self.robot_wheels.dance()
        self.robot_beep.play_song()
        self.tail_lights.alarm(tail_light_repetition)
        self.robot_camera.secret_dance()
```

如您在先前的代码中所看到的，`TailLights`类的变量`alarm`方法被命名为`tail_lights`。这将导致 LED 根据`tail_light_repetition`的值多次执行它们的序列。例如，当将值`2`传递给`alarm`方法（`light_show`列表中的第一个值）时，LED 序列将执行两次。

我们运行`lets_dance_incognito`方法六次。这基于`light_show`列表中的值的数量。这是我们使用`light_show`的第二种方式。为了增加或减少 T.A.R.A.S 执行舞蹈的次数，我们可以从`light_show`列表中添加或减去一些数字。

当我们在名为`robot_camera`的`RobotCamera`对象上调用`secret_dance`方法时，对于`light_show`列表中的每个值（在本例中为六），在舞蹈结束后，我们的家目录中应该有六张以日期命名的照片。

T.A.R.A.S 完成舞蹈后，请检查家目录中 T.A.R.A.S 在舞蹈期间拍摄的照片。任务完成！

# 总结

在本章结束时，您应该熟悉使用 Python 代码控制树莓派驱动的机器人。我们首先通过简单的代码使机器人车上的各种组件工作。在我们确信机器人车确实使用我们的 Python 命令移动后，我们将代码封装在类中，以便更容易使用。这导致了`RobotDance`类，其中包含对类的调用，这些类又封装了我们机器人的控制代码。这使我们能够使用`RobotDance`类作为黑匣子，将控制代码抽象化，并使我们能够专注于为 T.A.R.A.S 设计舞步的任务。

在第十五章中，*将机器人车的感应输入连接到网络*，我们将从 T.A.R.A.S（距离传感器值）中获取感官信息，并将其发布到网络上，然后将 T.A.R.A.S 从桌面上的电线中释放出来，让其自由行动。

# 问题

1.  真或假？`LEDBoard`对象允许我们同时控制许多 LED。

1.  真或假？`RobotCamera`对象上的笔记列表用于移动摄像机支架。

1.  真或假？我们虚构故事中的对手喜欢跳舞。

1.  `dance`和`secret_dance`方法之间有什么区别？

1.  机器人的`gpiozero`库的名称是什么？

1.  受老警察哨子启发，给出揭露犯罪行为的行为的术语是什么？

1.  真或假？封装控制代码是一个毫无意义和不必要的步骤。

1.  `TailLights`类的目的是什么？

1.  我们将使用哪个类和方法将机器人车转向右侧？

1.  `RobotCamera`类的目的是什么？

# 进一步阅读

学习 GPIO Zero 的最佳参考书之一是 GPIO Zero PDF 文档本身。搜索 GPIO Zero PDF，然后下载并阅读它。


# 第十五章：将机器人汽车的感应输入连接到网络

为了使我们的机器人汽车 T.A.R.A.S 成为真正的物联网**设备**，我们必须将 T.A.R.A.S 连接到互联网。在本章中，我们将通过将 T.A.R.A.S 的距离传感器连接到网络，开始将桌面机器人转变为互联网机器人。

本章将涵盖以下主题：

+   识别机器人汽车上的传感器

+   使用 Python 读取机器人汽车的感应数据

+   将机器人汽车的感应数据发布到云端

# 完成本章所需的知识

要完成本章，您应该已经按照第十三章中详细描述的方式构建了 T.A.R.A.S 机器人汽车。与本书中的其他章节一样，需要具备 Python 的工作知识，以及对面向对象编程的基本理解。

# 项目概述

本章的项目将涉及将 T.A.R.A.S 的感应距离数据发送到互联网。我们将使用 ThingsBoard 创建一个在线仪表板，该仪表板将在模拟表盘上显示这些距离信息。

这个项目应该需要几个小时来完成。

# 入门

要完成这个项目，需要以下设备：

+   一个树莓派 3 型号（2015 年或更新型号）

+   一个 USB 电源供应

+   一台电脑显示器

+   一个 USB 键盘

+   一个 USB 鼠标

+   一个完成的 T.A.R.A.S 机器人汽车套件（参见第十三章，*介绍树莓派机器人汽车*）

# 识别机器人汽车上的传感器

在整本书的过程中，我们使用了一些输入传感器。我们还将这些传感器的数据发布到了互联网上。T.A.R.A.S 使用距离传感器来检测附近的物体，如下图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/da4160be-5fd9-49fa-bc1a-6c249107c6e1.png)

第一次看到 T.A.R.A.S 时，您可能不知道距离传感器的位置在哪里。在 T.A.R.A.S 和许多其他机器人上，这个传感器位于眼睛位置。

以下是 HC-SR04 距离传感器的照片，即 T.A.R.A.S 上使用的传感器：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/c6bd91ef-c524-41cc-9ea8-6b1127b72892.png)

如果您在机器人上搜索 HC-SR04 的 Google 图片，您会看到很多使用这个传感器的机器人。由于其低成本和广泛可用性，以及其方便的眼睛外观，它是一个非常受欢迎的选择。

# 仔细观察 HC-SR04

如前所述，HC-SR04 是一个非常受欢迎的传感器。它易于编程，并且可以从[www.aliexpress.com](http://www.aliexpress.com)的多个供应商处获得。HC-SR04 提供从 2 厘米到 400 厘米的测量，并且精度在 3 毫米以内。

GPIO Zero 库使得从 HC-SR04 读取数据变得容易。以下图表是使用这个传感器与树莓派连接的接线图：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/9fffe200-03b5-4702-b041-d246fb7dad48.png)

正如你所看到的，HC-SR04 有四个引脚，其中两个用于信号输入和输出。接线图是我们在第十三章中用来连接 T.A.R.A.S 的子图，*介绍树莓派机器人汽车*。连接如下：

+   从 HC-SR04（距离传感器）的 Trig 到树莓派的 17 号引脚

+   从 HC-SR04 的 Echo（距离传感器）到面包板上 330 欧姆电阻的左侧

+   从 HC-SR04 的 VCC（距离传感器）到树莓派的 5V

+   从电压分压器输出到树莓派的 18 号引脚

+   从 HC-SR04 的 GND 到面包板上 470 欧姆电阻的右侧

触发器是 HC-SR04 的输入，可使用 5V 或 3.3V。回波引脚是输出，设计用于 5V。由于这对我们的树莓派来说有点太多了，我们使用电压分压电路将电压降低到 3.3V。

我们本可以向 T.A.R.A.S 添加更多传感器，使其更加先进，包括线路跟踪传感器、温度传感器、光传感器和 PID 传感器。线路跟踪传感器尤其有趣，因为一个简单的线路可以为 T.A.R.A.S 提供在其安全巡逻任务期间跟随的路线，这是一个非常有用的补充。由于设计已经足够复杂，如果您选择的话，我将留给您添加这个功能。

以下图表概述了线路跟踪传感器的工作原理：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/d0d5f0ff-d13f-4fbc-8061-5e8f133d8a90.png)

在图表中，您将看到机器人车前面有两个传感器。当机器人车偏离一侧时，其中一个传感器会检测到。在上一个示例中，位置为**B**的汽车已经向右偏离。左侧传感器会检测到这一点，并且程序通过将机器人车向左转动来进行校正，直到它返回到位置**A**。

# 使用 Python 读取机器人车的感知数据

虽然我们之前已经介绍过这个，但熟悉（或重新熟悉）HC-SR04 的编程是一个好主意：

1.  从应用程序菜单 | 编程 | Thonny Python IDE 中打开 Thonny。

1.  点击“新建”创建一个新文件。

1.  输入以下内容：

```py
from gpiozero import DistanceSensor
from time import sleep

distance_sensor = DistanceSensor(echo=18, trigger=17)

while True:
    print('Distance: ', distance_sensor.distance*100)
    sleep(1) 
```

1.  将文件保存为`distance-sensor-test.py`。

1.  运行代码。

1.  将手放在距离传感器前面。您应该在 shell 中看到以下内容（取决于您的手离距离传感器有多远）：

```py
Distance: 5.05452024001
```

1.  当您将手靠近或远离距离传感器时，数值会发生变化。这段代码相当容易理解。`distance_sensor = DistanceSensor(echo=18, trigger=17)`这一行设置了一个`DistanceSensor`类类型的`distance_sensor`对象，并设置了适当的引脚定义。每次调用`distance_sensor`的`distance`方法时，我们都会获取 HC-SR04 距离物体的距离。为了将值转换为厘米，我们将其乘以 100。

现在我们能够从距离传感器中检索值，让我们修改代码，使其更加面向对象友好：

1.  从应用程序菜单 | 编程 | Thonny Python IDE 中打开 Thonny

1.  点击“新建”创建一个新文件

1.  输入以下内容：

```py
from gpiozero import DistanceSensor
from time import sleep

class RobotEyes:

    distance_sensor = DistanceSensor(echo=18, trigger=17)

    def get_distance(self):
        return self.distance_sensor.distance*100

if __name__=="__main__":

    robot_eyes = RobotEyes()

    while True:
        print('Distance: ', robot_eyes.get_distance())
        sleep(1)
```

1.  将文件保存为`RobotEyes.py`

1.  运行代码

代码应该以完全相同的方式运行。我们所做的唯一的事情就是将它封装在一个类中，以便进行抽象。随着我们编写更多的代码，这将使事情变得更容易。我们不必记住 HC-SR04 连接到哪些引脚，实际上我们也不需要知道我们正在从中获取数据的是一个距离传感器。这段代码在视觉上比以前的代码更有意义。

# 将机器人车的感知数据发布到云端

在第十章中，*发布到 Web 服务*，我们设置了一个 ThingsBoard 账户来发布感知数据。如果您还没有这样做，请在[www.ThingsBoard.io](https://thingsboard.io/)上设置一个账户（参考第十章中的说明）。

# 创建一个 ThingsBoard 设备

要将我们的距离传感器数据发布到 ThingsBoard，我们首先需要创建一个 ThingsBoard 设备：

1.  登录到您的账户[`demo.thingsboard.io/login`](https://demo.thingsboard.io/login)

1.  点击“设备”，然后点击屏幕右下角的大橙色+号：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/49e26edc-5be8-4ee2-b56b-49dc553774c9.png)

1.  在“名称”中输入`RobotEyes`，将设备类型保留为“默认”，并在“描述”下输入有意义的描述

1.  点击“添加”

1.  点击`RobotEyes`以从右侧滑出菜单

1.  点击“复制访问令牌”将令牌复制到剪贴板上

1.  将令牌粘贴到一个文本文件中

对于我们的代码，我们将使用 MQTT 协议。如果 Paho MQTT 库尚未安装在您的树莓派上，请执行以下操作：

1.  从树莓派主工具栏中打开一个终端应用程序

1.  输入`sudo pip3 install pho-mqtt`

您应该看到库已安装。

现在是时候编写代码，将 T.A.R.A.S 的感知数据发布到网络上了。我们将修改我们的`RobotEyes`类：

1.  从应用程序菜单|编程|Thonny Python IDE 中打开 Thonny

1.  点击新建创建一个新文件

1.  输入以下内容：

```py
from gpiozero import DistanceSensor
from time import sleep
import paho.mqtt.client as mqtt
import json

class RobotEyes:

    distance_sensor = DistanceSensor(echo=18, trigger=17)
    host = 'demo.thingsboard.io'
    access_token='<<access token>>'

    def get_distance(self):
        return self.distance_sensor.distance*100

    def publish_distance(self):
        distance = self.get_distance()
        sensor_data = {'distance': 0}
        sensor_data['distance'] = distance
        client = mqtt.Client()
        client.username_pw_set(self.access_token)
        client.connect(self.host, 1883, 20)
        client.publish('v1/devices/me/telemetry',
             json.dumps(sensor_data), 1)
        client.disconnect()

if __name__=="__main__":

    robot_eyes = RobotEyes()   
    while True:
        print('Distance: ', robot_eyes.get_distance())
        robot_eyes.publish_distance()
        sleep(5) 
```

1.  确保将访问令牌从文本文件粘贴到`access_token`变量中

1.  将文件保存为`RobotEyesIOT.py`

1.  运行代码

您应该在 shell 中看到`distance`值，就像以前一样。但是，当您转到 ThingsBoard 并单击最新遥测时，您应该看到相同的值，如下所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/f43b0d47-2406-49cc-a3c7-b33bae6a940b.png)

我们在这里所取得的成就，就像第十章中一样，*发布到 Web 服务*，成功地将我们的距离传感器信息传输到了互联网。现在，我们可以从世界上任何地方看到物体离我们的机器人车有多近。在上一张屏幕截图中，我们可以看到有*某物*离我们 3.801 厘米远。

再次，我们尽可能地使代码自解释。但是，我们应该指出类的`publish_distance`方法：

```py
def publish_distance(self):
 distance = self.get_distance()
 sensor_data = {'distance': 0}
 sensor_data['distance'] = distance
 client = mqtt.Client()
 client.username_pw_set(self.access_token)
 client.connect(self.host, 1883, 20)
 client.publish('v1/devices/me/telemetry',
 json.dumps((sensor_data), 1)
 client.disconnect()
```

在这种方法中，我们首先创建了一个名为`distance`的变量，我们用我们的类`get_distance`方法中的实际距离信息填充它。创建了一个名为`sensor_data`的 Python 字典对象，并用它来存储`distance`值。然后，我们创建了一个名为`client`的 MQTT 客户端对象。我们将密码设置为我们从 ThingsBoard 复制的`access_token`，然后使用标准的 ThingsBoard 样板代码进行连接。

`client.publish`方法通过`json.dumps`方法将我们的`sensor_data`发送到 ThingsBoard。然后，我们断开`client`以关闭连接。

现在，让我们使用我们的距离传感数据创建一个仪表板小部件：

1.  在 ThingsBoard 中，单击最新遥测，并在列表中的`distance`值旁边选中复选框：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/12e05e33-6189-4eb6-8036-9ab7bfda79d1.png)

1.  点击在小部件上显示

1.  在当前包中，从下拉菜单中选择`模拟表`，如下所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/e77e038b-87ee-4f2c-bfe9-42eb23a9b346.png)

1.  选择最后一个小部件：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/e70c900d-55eb-4683-9354-4653ebf48dee.png)

1.  点击顶部的添加到仪表板

1.  创建名为`RobotEyes`的新仪表板，并选中打开仪表板框：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/9107f1c7-f6fd-46ee-973e-29e398d856d8.png)

1.  点击添加

1.  恭喜！我们现在已经为 T.A.R.A.S 的感知距离信息创建了一个物联网仪表板小部件。有了这个，我们可以全屏查看信息：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/5b607879-78ed-4afb-8320-f5a9b25d9a29.png)

# 摘要

在本章中，我们通过将距离数据发布到互联网，将 T.A.R.A.S 变成了一个真正的物联网物体。通过将我们的代码封装到一个名为`RobotEyes`的类中，我们可以忘记我们正在处理距离传感器，只需专注于 T.A.R.A.S 的眼睛表现得像声纳一样。

通过 ThingsBoard 中的演示平台，我们能够编写代码，将 T.A.R.A.S 的距离信息发送到仪表板小部件以供显示。如果我们真的想要创造性地做，我们可以通过舵机连接一个实际的模拟设备，并以这种方式显示距离信息（就像我们在第六章中所做的那样，*使用舵机控制代码来控制模拟设备*）。在第十六章中，*使用 Web 服务调用控制机器人车*，我们将更进一步，开始从互联网上控制 T.A.R.A.S。

# 问题

1.  连接 HC-SR04 到树莓派时，为什么要使用电压分压电路？

1.  正确还是错误？T.A.R.A.S 通过声纳来看。

1.  ThingsBoard 中的设备是什么？

1.  正确还是错误？我们的类`RobotEyes`封装了 T.A.R.A.S 上使用的树莓派摄像头模块。

1.  `RobotEyes.publish_distance`方法是做什么的？

1.  真的还是假的？我们需要使用 MQTT 的库在 Raspbian 上预先安装。

1.  为什么我们将类命名为`RobotEyes`而不是`RobotDistanceSensor`？

1.  真的还是假的？将样板代码封装在一个类中会使代码更难处理。

1.  真的还是假的？GPIO Zero 库不支持距离传感器。

1.  `RobotEyes.py`和`RobotEyesIOT.py`之间有什么区别？

# 进一步阅读

ThingsBoard 平台的一个很好的指导来源是它自己的网站。访问[www.thingsboard.io/docs/guides](https://thingsboard.io/docs/guides/)获取更多信息。


# 第十六章：使用 Web 服务调用控制机器人车

有一天，无人驾驶汽车将主导我们的街道和高速公路。尽管感应信息和控制算法将位于汽车本身，但我们将有能力（并且可能会成为立法要求）从其他地方控制汽车。控制无人驾驶汽车将需要将汽车的感应信息以速度、GPS 位置等形式发送到控制站。相反，控制站的信息将以交通和方向等形式发送到汽车。

在本章中，我们将探讨从 T.A.R.A.S 发送感应信息和接收 T.A.R.A.S 控制信息的两个方面。

本章将涵盖以下主题：

+   从云端读取机器人车的数据

+   使用 Python 程序通过云端控制机器人车

# 完成本章所需的知识

要完成本章，您应该有一个完整的 T.A.R.A.S 机器人车，详细描述在第十三章中，*介绍树莓派机器人车*。与本书中的其他章节一样，需要具备 Python 的工作知识，以及对面向对象编程的基本理解。

# 项目概述

本章的项目将涉及通过互联网与 T.A.R.A.S 进行通信。我们将深入研究在第十五章中创建的仪表板模拟表，然后在仪表板上创建控制 T.A.R.A.S 的开关。这些项目应该需要大约 2 小时才能完成。

# 技术要求

要完成此项目，需要以下内容：

+   一个树莓派 3 型号（2015 年或更新型号）

+   一个 USB 电源适配器

+   一台电脑显示器

+   一个 USB 键盘

+   一个 USB 鼠标

+   一个完整的 T.A.R.A.S 机器人车套件（参见第十三章，*介绍树莓派机器人车*）

# 从云端读取机器人车的数据

在第十五章中，*将机器人车的感应输入连接到网络*，我们能够使用网站[`thingsboard.io/`](https://thingsboard.io/)将距离感应数据发送到云端。最后，我们展示了一个显示距离数值的模拟仪表。在本节中，我们将深入研究模拟小部件并进行自定义。

# 改变距离表的外观

这是我们改变距离表外观的方法：

1.  登录您的 ThingsBoard 账户

1.  点击 DASHBOARDS

1.  点击 ROBOTEYES 标题

1.  单击屏幕右下角的橙色铅笔图标

1.  您会注意到距离模拟表已经改变（见下面的屏幕截图）

1.  首先，表盘右上角有三个新图标

1.  右下角的颜色也变成了浅灰色

1.  您可以通过将鼠标悬停在右下角来调整小部件的大小

1.  您也可以将小部件移动到仪表板上

1.  右上角的 X 允许您从仪表板中删除此小部件

1.  带有下划线箭头的图标允许您将小部件下载为`.json`文件。此文件可用于将小部件导入 ThingsBoard 上的另一个仪表板

1.  单击小部件上的铅笔图标会产生一个从右侧滑出的菜单：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/947e50b2-1c6b-43f3-8c1b-029d601c9124.png)

1.  如前面的屏幕截图所示，菜单选项为 DATA、SETTINGS、ADVANCED 和 ACTION。默认为 DATA

1.  点击 SETTINGS 选项卡

1.  在标题下，将名称更改为`RobotEyes`：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/67a0e9ed-a1df-4a5d-8e13-0909edd17784.png)

1.  点击显示标题复选框

1.  点击背景颜色下的白色圆圈：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/3fcf61fa-9959-41d4-99b6-cdb3aae1e365.png)

1.  您将看到颜色选择对话框：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/3045209d-d736-42a9-9e1e-00babfd775ff.png)

1.  将顶部更改为`rgb(50,87,126)`

1.  点击右上角的橙色复选框以接受更改

1.  您会注意到距离表有一些外观上的变化（请参见以下屏幕截图）：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/e12eee79-c197-47b5-afc4-fb904b89f9d1.png)

# 更改距离表上的范围

看着距离模拟表，很明显，对于我们的应用程序来说，有负数并没有太多意义。让我们将范围更改为`0`到`100`：

1.  点击小部件上的铅笔图标

1.  点击“高级”选项卡

1.  将最小值更改为`0`，将最大值更改为`100`：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/2292aa38-1f4e-4055-8dca-42262a44e8e5.png)

1.  点击右上角的橙色复选框以接受对小部件的更改

1.  关闭 ROBOTEYES 对话框

1.  点击右下角的橙色复选框以接受对仪表板的更改

1.  您会注意到距离模拟表现在显示范围为`0`到`100`：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/c8e1a9b6-5b28-423b-9cf2-dd21c16c35c7.png)

# 在您的帐户之外查看仪表板

对于我们的最后一个技巧，我们将在我们的帐户之外显示我们的仪表板（我们在第十章中也这样做，*发布到 Web 服务*）。这也允许我们将我们的仪表板发送给朋友。那么，为什么我们要在帐户之外查看我们的仪表板呢？物联网的核心概念是我们可以从一个地方获取信息并在其他地方显示，也许是在世界的另一边的某个地方。通过使我们的仪表板在我们的帐户之外可访问，我们允许在任何地方设置仪表板，而无需共享我们的帐户信息。想象一下世界上某个地方有一块大屏幕，屏幕的一小部分显示我们的仪表板。从 T.A.R.A.S 显示距离信息可能对许多人来说并不是很感兴趣，但重要的是概念。

要分享我们的仪表板，请执行以下操作：

1.  在 ThingsBoard 应用程序中，点击“仪表板”选项

1.  点击 RobotEyes 仪表板下的中间图标：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/2218b998-0b43-4bdd-af3e-69b5d68724f9.png)

1.  您将看到类似以下的对话框（URL 已部分模糊处理）：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/0368bece-b8e4-42b2-9dc1-4f059ad502e8.png)

1.  点击 URL 旁边的图标将 URL 复制到剪贴板

1.  要测试 URL，请将其粘贴到计算机上的完全不同的浏览器中（或将其发送给朋友并让他们打开）

1.  您应该能够看到我们的距离模拟表的仪表板

# 使用 Python 程序通过云控制机器人车

能够在仪表板中看到传感器数据是非常令人印象深刻的。但是，如果我们想要从我们的仪表板实际控制某些东西怎么办？在本节中，我们将做到这一点。我们将首先构建一个简单的开关来控制 T.A.R.A.S 上的 LED。然后，我们将扩展此功能，并让 T.A.R.A.S 通过互联网上的按钮按下来跳舞。

让我们首先将仪表板的名称从`RobotEyes`更改为`RobotControl`：

1.  在 ThingsBoard 应用程序中，点击“仪表板”选项

1.  点击 RobotEyes 仪表板下的铅笔图标：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/5d584ac7-e3ca-4193-adf0-9c86c0a719e3.png)

1.  点击橙色铅笔图标

1.  将瓷砖从`RobotEyes`更改为`RobotControl`：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/0c99f107-af76-44a2-b4c6-0ec5cb7863b5.png)

1.  点击橙色复选框以接受更改

1.  退出侧边对话框

现在让我们从 ThingsBoard 仪表板上控制 T.A.R.A.S 上的 LED。

# 向我们的仪表板添加一个开关

为了控制 LED，我们需要创建一个开关：

1.  点击 RobotControl 仪表板

1.  点击橙色铅笔图标

1.  点击+图标

1.  点击“创建新小部件”图标

1.  选择“控制小部件”并点击“切换控制”：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/a2a3f9d4-ab05-4e65-82a0-4581d1c2b6b6.png)

1.  在目标设备下，选择 RobotControl

1.  点击“设置”选项卡：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/ad038ebb-a391-4dc2-8d92-901d1b7f5870.png)

1.  将标题更改为`Green Tail Light`，然后点击显示标题

1.  点击高级选项卡

1.  将 RPC 设置值方法更改为`toggleGreenTailLight`：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/5b306916-8573-4478-922b-6930261347a0.png)

1.  点击橙色的勾号图标以接受对小部件的更改

1.  关闭侧边对话框

1.  点击橙色的勾号图标以接受对仪表板的更改

那么，我们刚刚做了什么？我们在我们的仪表板上添加了一个开关，它将发布一个名为`toggleGreenTailLight`的方法，该方法将返回一个值，要么是`true`，要么是`false`（默认返回值为`this is a switch`）。

既然我们有了开关，让我们在树莓派上编写一些代码来响应它。

# 控制 T.A.R.A.S 上的绿色 LED

要控制 T.A.R.A.S 上的绿色 LED，我们需要编写一些代码到 T.A.R.A.S 上的树莓派。我们需要我们仪表板的访问令牌（参见第十五章，*将机器人汽车的感应输入连接到网络*，关于如何获取）：

1.  从应用程序菜单中打开 Thonny | 编程 | Thonny Python IDE

1.  点击新建图标创建一个新文件

1.  输入以下内容：

```py
import paho.mqtt.client as mqtt
from gpiozero import LED
import json

THINGSBOARD_HOST = 'demo.thingsboard.io' ACCESS_TOKEN = '<<access token>>'
green_led=LED(21)

def on_connect(client, userdata, rc, *extra_params):
   print('Connected with result code ' + str(rc))
    client.subscribe('v1/devices/me/rpc/request/+')

def on_message(client, userdata, msg):
    data = json.loads(msg.payload.decode("utf-8")) 

    if data['method'] == 'toggleGreenTailLight':
        if data['params']:
            green_led.on()
        else:
            green_led.off()

client = mqtt.Client()
client.on_connect = on_connect
client.on_message = on_message
client.username_pw_set(ACCESS_TOKEN)
client.connect(THINGSBOARD_HOST, 1883, 60)

client.loop_forever()
```

1.  将文件保存为`control-green-led-mqtt.py`

1.  运行代码

1.  返回我们的 ThingsBoard 仪表板（如果您一直在 T.A.R.A.S 上的树莓派之外的计算机上使用，现在是一个好时机）

1.  点击开关以打开它

1.  您应该看到 T.A.R.A.S 上的绿色 LED 随开关的打开和关闭而打开和关闭

那么，我们刚刚做了什么？使用从 ThingsBoard 网站获取的样板代码，我们构建了一个**消息查询遥测传输**（**MQTT**）客户端，该客户端监听仪表板，并在接收到`toggleGreenTailLight`方法时做出响应。我们通过在`on_connect`方法中订阅`'v1/devices/me/rpc/request/+'`来实现这一点。我们在第十章中也使用了 MQTT，*发布到网络服务*。然而，由于这段代码几乎只是 MQTT 代码，让我们更仔细地研究一下。

MQTT 是一种基于`发布者`和`订阅者`方法的轻量级消息传递协议，非常适合在物联网中使用。理解发布者和订阅者的一个好方法是将它们与过去的报纸联系起来。发布者是制作报纸的实体；订阅者是购买和阅读报纸的人。发布者不知道，甚至不必知道，为了印刷报纸有多少订阅者（不考虑出版成本）。想象一下每天都会出版的巨大报纸，不知道有多少人会购买他们的报纸。因此，发布者可以有很多订阅者，反之亦然，订阅者可以订阅很多发布者，就像读者可以阅读很多不同的报纸一样。

我们首先导入我们代码所需的库：

```py
import paho.mqtt.client as mqtt
from gpiozero import LED
import json

THINGSBOARD_HOST = 'demo.thingsboard.io'
ACCESS_TOKEN = '<<access token>>'
green_led=LED(21)
```

这里需要注意的是`json`和`pho.mqtt.client`库，这些库是与 MQTT 服务器通信所需的。`THINGSBOARD_HOST`和`ACCESS_TOKEN`是连接到正确服务器和服务所需的标准变量。当然，还有`GPIO Zero LED`类，它将`green_led`变量设置为 GPIO 引脚`21`（这恰好是 T.A.R.A.S 上的绿色尾灯）。

`on_connect`方法打印出连接信息，然后订阅将我们连接到来自我们 ThingsBoard 仪表板的`rpc`方法的服务：

```py
def on_connect(client, userdata, rc, *extra_params):
    print('Connected with result code ' + str(rc))
    client.subscribe('v1/devices/me/rpc/request/+')
```

正是`on_message`方法使我们能够真正修改我们的代码以满足我们的目的：

```py
def on_message(client, userdata, msg):
    data = json.loads(msg.payload.decode("utf-8")) 

    if data['method'] == 'toggleGreenTailLight':
        if data['params']:
            green_led.on()
        else:
            green_led.off()
```

我们首先从我们的`msg`变量中收集`data`，然后使用`json.loads`方法将其转换为`json`文件。`method`声明`on_message(client, userdata, msg)`，再次是来自 ThingsBoard 网站的标准样板代码。我们真正关心的只是获取`msg`的值。

第一个`if`语句，`if data['method'] == 'toggleGreenTailLight'`，检查我们的`msg`是否包含我们在 ThingsBoard 仪表板上设置的`toggleGreenTailLight`方法。一旦我们知道`msg`包含这个方法，我们使用`if data['params']`提取`data`中的其他键值对，以检查是否有`True`值。换句话说，调用`on_message`方法返回的`json`文件看起来像`{'params': True, 'method': 'toggleGreenTailLight'}`。这基本上是一个包含两个键值对的 Python 字典。这可能看起来令人困惑，但最简单的想法是将其想象成一个`json`版本的方法（`toggleGreenTailLight`）和一个返回值（`True`）。

真正理解发生了什么的一种方法是在`on_message`方法中添加一个`print`语句来`print data`，就在`data = json.loads(msg.payload.decode("utf-8"))`之后。因此，该方法看起来像以下内容：

```py
def on_message(client, userdata, msg):
    data = json.loads(msg.payload.decode("utf-8")) 
    print(data)
    .
    .
    . 
```

当从`params`返回的值为`True`时，我们简单地使用标准的 GPIO Zero 代码打开 LED。当从`params`返回的值不是`True`（或`False`，因为只有两个可能的值）时，我们关闭 LED。

通过使用互联网看到 LED 开关是相当令人印象深刻的。然而，这还不够。让我们利用我们在之前章节中使用的一些代码，让 T.A.R.A.S 跳舞。这一次，我们将通过互联网让它跳舞。

# 使用互联网让 T.A.R.A.S 跳舞

要让 T.A.R.A.S 再次跳舞，我们需要确保第十四章中的代码*使用 Python 控制机器人车*与我们将要编写的代码在同一个目录中。

我们将从在我们的仪表板上创建一个跳舞开关开始：

1.  按照之前的步骤 1 到 9，在仪表板下添加一个开关来创建一个开关

1.  将标题更改为 Dance Switch 并点击显示标题

1.  点击高级选项卡

1.  将`RPC set value method`更改为`dance`

1.  点击橙色的勾号图标以接受对小部件的更改

1.  关闭侧边对话框

1.  点击橙色的勾号图标以接受对仪表板的更改

现在我们有了开关，让我们修改我们的代码：

1.  从应用程序菜单 | 编程 | Thonny Python IDE 打开 Thonny

1.  点击新图标创建一个新文件

1.  输入步骤 4 中的以下内容：

```py
import paho.mqtt.client as mqtt
import json
from RobotDance import RobotDance

THINGSBOARD_HOST = 'demo.thingsboard.io'
ACCESS_TOKEN = '<<access token>>'
robot_dance = RobotDance()

def on_connect(client, userdata, rc, *extra_params):
    print('Connected with result code ' + str(rc))
    client.subscribe('v1/devices/me/rpc/request/+')

def on_message(client, userdata, msg):
    data = json.loads(msg.payload.decode("utf-8")) 

    if data['method'] == 'dance':
        if data['params']:
            robot_dance.lets_dance_incognito()

client = mqtt.Client()
client.on_connect = on_connect
client.on_message = on_message
client.username_pw_set(ACCESS_TOKEN)
client.connect(THINGSBOARD_HOST, 1883, 60)

client.loop_forever()
```

1.  将文件保存为`internet-dance.py`

1.  运行代码

现在去仪表板上打开跳舞开关（不幸的是，它是一个开关而不是一个按钮）。T.A.R.A.S 应该开始跳舞，就像在第十四章中一样，*使用 Python 控制机器人车*。

那么，我们刚刚做了什么？嗯，我们拿了简单的代码，稍微修改了一下，通过面向对象编程的力量，我们能够让 T.A.R.A.S 跳舞，而无需更改甚至浏览我们旧的`RobotDance`代码（难道 OOP 不是自从你认为最好的东西以来最好的东西吗？）。

对于 MQTT 代码，我们所要做的就是在`RobotDance`类中添加`import`，去掉多余的 GPIO Zero 导入，去掉对 LED 的任何引用（因为这会引起冲突），然后修改我们的`on_message`方法以查找`dance`作为方法。

`RobotDance`类类型的`robot_dance`对象完成了所有工作。当我们在这个对象上调用`lets_dance_incognito`方法时，它会启动`RobotWheels`、`RobotBeep`、`TailLights`和`RobotCamera`类中用于移动的方法。最终结果是通过互联网上的开关让 T.A.R.A.S 跳舞的方法。

# 摘要

在本章中，我们进一步研究了我们用于距离传感信息的仪表盘模拟表。在更改范围并将其公开之前，我们对其进行了美学修改。然后，我们将注意力转向通过互联网控制 T.A.R.A.S。通过使用一个简单的程序，我们能够通过仪表盘开关打开 T.A.R.A.S 上的绿色 LED。我们利用这些知识修改了我们的代码，通过另一个仪表盘开关使 T.A.R.A.S 跳舞。

在第十七章 *构建 JavaScript 客户端*中，我们将继续编写一个 JavaScript 客户端，通过互联网控制 T.A.R.A.S。

# 问题

1.  无人驾驶汽车需要从中央站获取什么类型的信息？

1.  真/假？在 ThingsBoard 仪表盘中无法更改小部件的背景颜色。

1.  如何更改仪表盘模拟表的范围？

1.  真/假？从行`print(data)`返回的信息无法被人类阅读。

1.  我们从`RobotDance`类中调用哪个方法来使 T.A.R.A.S 跳舞？

1.  真/假？我们需要使用的处理`json`数据的库叫做`jason`。

1.  我们如何在仪表盘上创建一个开关？

1.  真/假？T.A.R.A.S 上的绿色 LED 连接到 GPIO 引脚 14。

1.  真/假？一个发布者只能有一个订阅者。

1.  使用`on_message`方法从`msg`返回多少个键值对？

# 进一步阅读

由于我们只是简单地涉及了 ThingsBoard，查看他们的文档是个好主意，网址是[`thingsboard.io/docs/guides/`](https://thingsboard.io/docs/guides/)。


# 第十七章：构建 JavaScript 客户端

让我们面对现实吧。如果没有互联网，我们真的不会有物联网。JavaScript，连同 HTML 和 CSS，是互联网的核心技术之一。物联网的核心是设备之间通信的协议 MQTT。

在这一章中，我们将把注意力从 Python 转移到使用 JavaScript 构建 JavaScript 客户端以订阅 MQTT 服务器上的主题。

本章将涵盖以下主题：

+   介绍 JavaScript 云库

+   使用 JavaScript 连接到云服务

# 项目概述

我们将从创建一个简单的 JavaScript 客户端开始这一章，该客户端连接到 MQTT Broker（服务器）。我们将向 MQTT Broker 发送一条测试消息，然后让该消息返回到我们创建 JavaScript 客户端的同一页。然后我们将从 Raspberry Pi 发布一条消息到我们的 MQTT Broker。

完成本章应该需要几个小时。

# 入门

要完成这个项目，需要以下内容：

+   Raspberry Pi 3 型号（2015 年或更新型号）

+   USB 电源适配器

+   计算机显示器

+   USB 键盘

+   USB 鼠标

+   用于编写和执行 JavaScript 客户端程序的单独计算机

# 介绍 JavaScript 云库

让我们首先介绍一下 JavaScript 云库的背景。JavaScript 自互联网诞生以来就存在（1995 年，举例而言）。它已经成为一种可以将 HTML 网页转变为完全功能的桌面等效应用程序的语言。就我个人而言，我发现 JavaScript 是最有用的编程语言之一（当然，除了 Python）。

JavaScript 于 1995 年发布，旨在与当时最流行的网络浏览器 Netscape Navigator 一起使用。它最初被称为 livescript，但由于在 Netscape Navigator 浏览器中使用和支持 Java，名称被更改为 JavaScript。尽管语法相似，但 Java 和 JavaScript 实际上与彼此无关——这是一个令人困惑的事实，直到今天仍然存在。

# 谷歌云

通过`google-api-javascript-client`，我们可以访问谷歌云服务。具体来说，我们可以访问谷歌计算引擎，这是谷歌云平台的一个组件。通过谷歌计算引擎，我们可以通过按需虚拟机访问运行 Gmail、YouTube、谷歌搜索引擎和其他谷歌服务的基础设施。如果这听起来像是能让你的朋友印象深刻的技术术语，你可能需要更深入地了解这个 JavaScript 库。您可以在这里了解更多关于`google-api-javascript-client`的信息：[`cloud.google.com/compute/docs/tutorials/javascript-guide`](https://cloud.google.com/compute/docs/tutorials/javascript-guide)。

# AWS SDK for JavaScript

AWS SDK for JavaScript in Node.js 提供了 AWS 服务的 JavaScript 对象。这些服务包括 Amazon S3、Amazon EC2、Amazon SWF 和 DynamoDB。此库使用 Node.js 运行时环境。您可以在这里了解更多关于这个库的信息：[`aws.amazon.com/sdk-for-node-js/`](https://aws.amazon.com/sdk-for-node-js/)。

Node.js 于 2009 年 5 月发布。最初的作者是 Ryan Dhal，目前由 Joyent 公司开发。Node.js 允许在浏览器之外执行 JavaScript 代码，从而使其成为一种 JavaScript 无处不在的技术。这使 JavaScript 可以在服务器端和客户端用于 Web 应用程序。

# Eclipse Paho JavaScript 客户端

Eclipse Paho JavaScript 客户端库是一个面向 JavaScript 客户端的 MQTT 基于浏览器的库。Paho 本身是用 JavaScript 编写的，可以轻松地插入到 Web 应用程序项目中。Eclipse Paho JavaScript 客户端库使用 Web 套接字连接到 MQTT Broker。我们将在本章的项目中使用这个库。

# 使用 JavaScript 连接到云服务

对于我们的项目，我们将构建一个 JavaScript 客户端并将其连接到 MQTT Broker。我们将**发布**和**订阅**名为**test**的**topic**。然后，我们将在树莓派上编写一个小的简单程序来发布到名为 test 的主题。这段代码将演示使用 MQTT 发送和接收消息是多么容易。

请查看以下图表，了解我们将通过此项目实现的内容：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/84267fcf-dc03-4879-a939-a007bd125ecb.png)

# 设置 CloudMQTT 帐户

第一步是设置 MQTT Broker。我们可以通过在本地安装 Mosquitto 平台（[www.mosquitto.org](http://www.mosquitto.org)）来完成此操作。相反，我们将使用网站[www.cloudmqtt.com](http://www.cloudmqtt.com)设置基于云的 MQTT Broker。

要设置帐户：

1.  在浏览器中，导航到[www.cloudmqtt.com.](http://www.cloudmqtt.com)

1.  在右上角点击登录。

1.  在创建帐户框中，输入您的电子邮件地址：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/f04e69e9-3f08-4ba7-a01f-2c681a01a8e3.png)

1.  您将收到一封发送到该电子邮件地址的电子邮件，要求您确认。您可以通过单击电子邮件中的确认电子邮件按钮来完成确认过程。

1.  然后您将进入一个页面，需要输入密码。选择密码，确认密码，然后按提交：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/4078ed85-99ff-471d-9ca8-90f36549b436.png)

1.  然后您将进入实例页面。这是我们将创建 MQTT Broker 实例以发送和发布 MQTT 消息的地方。

# 设置 MQTT Broker 实例

现在我们已经设置了 CloudMQTT 帐户，是时候创建一个用于我们应用程序的实例了：

1.  从实例页面，单击标有创建新实例的大绿色按钮。

1.  您将看到以下页面：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/01a45002-ed39-4088-981a-c57dfa9a50a1.png)

1.  在名称框中，输入`T.A.R.A.S`（我们将将 MQTT Broker 实例命名为此，因为我们将考虑此 Broker 是 T.A.R.A.S 机器人汽车的一部分）。

1.  在计划下拉菜单中，选择 Cute Cat（这是用于开发目的的免费选项）。

1.  点击绿色的选择区域按钮。

1.  根据您所在的世界位置，选择一个靠近您地理位置的区域。由于我位于加拿大，我将选择 US-East-1（北弗吉尼亚）：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/d41391c9-48ce-4cfb-8894-5732fe6f80e0.png)

1.  点击绿色的确认按钮。

1.  您将看到确认新实例页面。在点击绿色的确认实例按钮之前，请查看此信息：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/62dd7a70-3784-465c-a9ca-9143c8705e4c.png)

1.  您应该看到 T.A.R.A.S 实例在列表中的实例列表中：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/0e5c8309-381e-4d4a-8fbb-515b4ef2a5f9.png)

# 编写 JavaScript 客户端代码

这是我在我的帐户上设置的 T.A.R.A.S 实例的屏幕截图。请注意列表中的值。这些值来自我的实例，您的值将不同。我们将在编写 JavaScript 客户端时使用这些值：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/5519d33b-365e-40d2-8ef0-02657aef5ef6.png)

要编写我们的 JavaScript 客户端代码，我们应该使用 T.A.R.A.S 上的树莓派以外的计算机。您可以使用任何您喜欢的操作系统和 HTML 编辑器。我使用 macOS 和 Visual Studio Code 编写了我的 JavaScript 客户端代码。您还需要 Paho JavaScript 库：

1.  转到 Eclipse Paho 下载站点[`projects.eclipse.org/projects/technology.paho/downloads`](https://projects.eclipse.org/projects/technology.paho/downloads)。

1.  点击 JavaScript 客户端链接。它将以`JavaScript 客户端`的名称标记，后跟版本号。在撰写本文时，版本号为 1.03。

1.  JavaScript 客户端库将以`paho.javascript-1.0.3`的 ZIP 文件形式下载。解压文件。

1.  我们需要在计算机上创建一个用作项目文件夹的文件夹。在计算机上创建一个新文件夹，并将其命名为`MQTT HTML Client`。

1.  在`MQTT HTML Client`文件夹内创建一个名为`scripts`的子文件夹。

1.  将解压后的`paho.javascript-1.0.3`文件夹拖放到`MQTT HTML Client`文件夹中。

1.  `MQTT HTML Client`文件夹内的目录结构应如下所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/5e404183-5f7a-4f40-84e3-e31297a50130.png)

现在，是时候编写代码了。我们将尽可能简化我们的代码，以便更好地理解 MQTT 如何与 JavaScript 配合使用。我们的客户端代码将包括两个文件，一个 HTML 页面和一个`.js`（JavaScript）文件。让我们从创建 HTML 页面开始：

1.  使用您喜欢的 HTML 编辑器，创建一个名为`index.html`的文件并保存到项目根目录。

1.  您的`project`文件夹应该如下所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/6a9ccea0-16b5-4bd3-ac42-b289a09df395.png)

1.  在`index.html`文件中输入以下内容：

```py
<!DOCTYPE html>
<html>

<head>
 <title>MQTT Message Client</title>
 <script src="paho.javascript-1.0.3/paho-mqtt.js" type="text/javascript"></script>
 <script src="scripts/index.js" type='text/javascript'></script>
</head>

<body>

 <h2>MQTT Message Client</h2>
 <button onclick="sendTestData()">
 <h4>Send test message</h4>
 </button>

 <button onclick="subscribeTestData()">
 <h4>Subscribe to test</h4>
 </button>

 <div>
 <input type="text" id="messageTxt" value="Waiting for MQTT message" size=34 />
 </div>

</body>

</html>
```

1.  保存对`index.html`的更改。

1.  我们在这里做的是创建一个简单的 HTML 页面，并导入了两个 JavaScript 库，Paho JavaScript 库和一个名为`index.js`的文件，我们还没有创建：

```py
<script src="paho.javascript-1.0.3/paho-mqtt.js" type="text/javascript"></script>
<script src="scripts/index.js" type='text/javascript'></script>
```

1.  然后，我们需要创建两个按钮；在顶部按钮上，我们将`onclick`方法设置为`sendTestData`。在底部按钮上，我们将`onclick`方法设置为`subscribeTestData`。这些方法将在我们编写的 JavaScript 文件中创建。为简单起见，我们不给这些按钮分配 ID 名称，因为我们不会在我们的 JavaScript 代码中引用它们：

```py
<button onclick="sendTestData()">
        <h4>Send test Message</h4>
</button>
<button onclick="subscribeTestData()">
        <h4>Subscribe to test</h4>
</button>
```

1.  我们在`index.html`页面中将创建的最后一个元素是一个文本框。我们为文本框分配了一个`id`为`messageTxt`和一个值为`Waiting for MQTT message`：

```py
<div>
    <input type="text" id="messageTxt" value="Waiting for MQTT message" size=34 />
</div>
```

1.  如果我们将`index.html`加载到浏览器中，它将如下所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/d3b89900-edd2-4fb5-9e45-d39a24510d8f.png)

# 运行代码

在运行客户端代码之前，我们需要创建一个 JavaScript 文件，该文件将提供我们需要的功能：

1.  使用 HTML 编辑器，在我们的项目目录中的`scripts`文件夹中创建一个名为`index.js`的文件并保存。

1.  将以下代码添加到`index.js`并保存。用您的实例中的值替换`Server`、`User`、`Password`和`Websockets Port`（分别显示为`"m10.cloudmqtt.com"`、`38215`、`"vectydkb"`和`"ZpiPufitxnnT"`）：

```py
function sendTestData() {
 client = new Paho.MQTT.Client
 ("m10.cloudmqtt.com", 38215, "web_" + 
 parseInt(Math.random() * 100, 10));

 // set callback handlers
 client.onConnectionLost = onConnectionLost;

 var options = {
 useSSL: true,
 userName: "vectydkb",
 password: "ZpiPufitxnnT",
 onSuccess: sendTestDataMessage,
 onFailure: doFail
 }

 // connect the client
 client.connect(options);
}

// called when the client connects
function sendTestDataMessage() {
 message = new Paho.MQTT.Message("Hello from JavaScript 
 client");
 message.destinationName = "test";
 client.send(message);
}

function doFail() {
 alert("Error!");
}

// called when the client loses its connection
function onConnectionLost(responseObject) {
 if (responseObject.errorCode !== 0) {
 alert("onConnectionLost:" + responseObject.errorMessage);
 }
}

// called when a message arrives
function onMessageArrived(message) {
 document.getElementById('messageTxt').value = message.payloadString; 
}

function onsubsribeTestDataSuccess() {
 client.subscribe("test");
 alert("Subscribed to test");
}

function subscribeTestData() {
 client = new Paho.MQTT.Client
 ("m10.cloudmqtt.com", 38215, "web_" + 
 parseInt(Math.random() * 100, 10));

 // set callback handlers
 client.onConnectionLost = onConnectionLost;
 client.onMessageArrived = onMessageArrived;

 var options = {
 useSSL: true,
 userName: "vectydkb",
 password: "ZpiPufitxnnT",
 onSuccess: onsubsribeTestDataSuccess,
 onFailure: doFail
 }

 // connect the client
 client.connect(options);
}
```

1.  通过刷新加载了`index.html`的浏览器中运行代码。

1.  点击`Subscribe to test`按钮。您应该会收到一个弹出对话框，显示`Subscribed to test`消息。

1.  关闭弹出对话框。

1.  点击发送测试消息按钮。

1.  您应该在文本框中看到消息`Hello from JavaScript client`。

这是我们刚刚执行的某种魔术吗？在某种程度上是。我们刚刚成功订阅了 MQTT Broker 上的一个主题，然后发布到相同的主题，然后在同一个 JavaScript 客户端中接收到了一条消息。要从 MQTT Broker 中观察到这一点，请执行以下操作：

1.  登录到您的 CloudMQTT 帐户

1.  点击 T.A.R.A.S 实例

1.  点击 WEBSOCKET UI 菜单选项

1.  您应该会看到以下对话框，显示您已连接：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/a3d25e03-1fdd-4109-9f78-44479e68140a.png)

1.  在浏览器的另一个标签或窗口中，导航回 JavaScript 客户端`index.html`

1.  再次点击发送测试消息按钮

1.  返回 CloudMQTT 页面

1.  在接收到的消息列表下，您应该看到一条消息：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/50628610-fba2-47f4-a0db-e16acfd31ad2.png)

1.  点击发送测试消息按钮几次，您应该会在接收到的消息下看到相同消息的列表。

# 理解 JavaScript 代码

在为树莓派编写代码之前，让我们先看一下`index.js`中的 JavaScript 代码。

我们首先来看订阅代码。我们用来从我们的 MQTT Broker 订阅主题的两种方法是`subscribeTestData`和`onsubsribeTestDataSuccess`。`subscribeTestData`创建了一个名为`client`的 Paho MQTT 客户端对象。它使用`client`对象通过实例化对象与我们的 MQTT Broker 连接，并使用`Server`和`Websockets Port`值（为简单起见，我在代码中留下了我的帐户中的值）：

```py
function subscribeTestData() {
    client = new Paho.MQTT.Client
        ("m10.cloudmqtt.com", 38215, "web_" +     
                        parseInt(Math.random() * 100, 10));

    // set callback handlers
    client.onConnectionLost = onConnectionLost;
    client.onMessageArrived = onMessageArrived;

    var options = {
        useSSL: true,
        userName: "vectydkb",
        password: "ZpiPufitxnnT",
        onSuccess: onsubsribeTestDataSuccess,
        onFailure: doFail
    }

    // connect the client
    client.connect(options);
}
```

然后，我们使用`client.onConnectionLost`和`client.onMessageArrived`设置回调处理程序。回调处理程序将我们 JavaScript 代码中的函数与我们的`client`对象的事件相关联。在这种情况下，当与 MQTT 代理的连接丢失或从 MQTT 代理接收到消息时。 `options`变量将 SSL 的使用设置为`true`，设置`User`和`Password`设置，然后将成功连接的条件设置为`onsubsribeTestDataSuccess`方法，将连接尝试不成功的条件设置为`doFail`方法。然后，我们通过传递我们的`options`变量通过`client.connect`方法连接到我们的 MQTT 代理。

当成功连接到 MQTT 代理时，将调用`onsubsribeTestDataSuccess`方法。它设置`client`对象以订阅`test`主题。然后，它创建一个带有消息`Subscribed to test`的警报：

```py
function onsubsribeTestDataSuccess() {
    client.subscribe("test");
    alert("Subscribed to test");
}
```

如果与客户端的连接不成功，则调用`doFail`方法。它只是创建一个带有消息“错误！”的弹出警报：

```py
function doFail() {
    alert("Error!");
}
```

现在我们了解了订阅`test`主题的代码，让我们看一下发布到`test`主题的代码。

`sendTestData`函数与`subscribeTestData`函数非常相似：

```py
function sendTestData() {
    client = new Paho.MQTT.Client
        ("m10.cloudmqtt.com", 38215, "web_" + parseInt(Math.random() * 100, 10));

    // set callback handlers
    client.onConnectionLost = onConnectionLost;

    var options = {
        useSSL: true,
        userName: "vectydkb",
        password: "ZpiPufitxnnT",
        onSuccess: sendTestDataMessage,
        onFailure: doFail
    }

    // connect the client
    client.connect(options);
}
```

创建了一个名为`client`的 Paho MQTT 客户端对象，其参数与`subscribeTestData`函数中使用的参数相同。设置的唯一回调处理程序是`onConnectionLost`。我们没有设置`onMessageArrived`，因为我们正在发送消息而不是接收消息。将`options`变量设置为与`subscribeTestData`函数中使用的相同值，唯一的例外是将`onSuccess`分配给`sendTestDataMessage`函数。

`sendTestDataMessage`函数创建一个新的 Paho MQTT 消息对象，其值为`Hello from JavaScript client`，并将其命名为`message`。 `destinationName`是我们为其创建消息的主题，设置为`test`值。然后，我们使用`client.send`发送消息：

```py
function sendTestDataMessage() {
    message = new Paho.MQTT.Message("Hello from JavaScript client");
    message.destinationName = "test";
    client.send(message);
}
```

`onConnectionLost`函数用于订阅和发布，并简单地创建一个带有来自 JavaScript 响应对象的错误消息的警报弹出窗口：

```py
// called when the client loses its connection
function onConnectionLost(responseObject) {
    if (responseObject.errorCode !== 0) {
        alert("onConnectionLost:" + responseObject.errorMessage);
    }
}
```

既然我们的 JavaScript 客户端已经订阅并发布到我们的 MQTT 代理，让我们让树莓派也参与其中。

# 从我们的树莓派发布 MQTT 消息

让我们返回到我们的树莓派（如果您一直在使用另一台计算机），并编写一些代码与我们的 MQTT 代理进行通信：

1.  从应用程序菜单 | 编程 | Thonny Python IDE 打开 Thonny。

1.  单击“新建”图标创建一个新文件。

1.  在文件中输入以下内容：

```py
import paho.mqtt.client as mqtt
from time import sleep

mqttc = mqtt.Client()
mqttc.username_pw_set("vectydkb", "ZpiPufitxnnT")
mqttc.connect('m10.cloudmqtt.com', 18215)

while True:
    try:
        mqttc.publish("test", "Hello from Raspberry Pi")
    except:
        print("Could not send message!")
    sleep(10)

```

1.  将文件保存为`CloudMQTT-example.py`并运行它。

1.  返回到 CloudMQTT 页面。您应该看到来自树莓派的消息：

！[](assets/3e8afc3a-0e68-4a3f-a61c-120c53b71bc9.png)

1.  导航到我们的 JavaScript 客户端`index.html`。您应该在文本框中看到消息`Hello from the Raspberry Pi`（如果您没有看到消息，请刷新页面并再次单击“Subscribe to test”）：

！[](assets/3ce2d3c4-6320-486b-9e96-6c57db5fcb98.png)

树莓派 Python 代码故意保持简单，以便可以理解这些概念。我们通过导入所需的库来启动代码。然后，我们创建一个名为`mqttc`的 MQTT 客户端对象。使用`username_pw_set`方法设置用户名和密码。然后，我们使用`connect`方法连接到 MQTT 代理，通过传递`Server`和`Port`值（我们为 Python 客户端使用`Port`而不是`Websockets Port`）。在一个连续的循环内，我们通过传递主题`test`和消息`Hello from Raspberry Pi`来通过`publish`方法发布到 MQTT 代理。

# 摘要

在本章中，我们在使用 JavaScript 创建 MQTT 客户端之前探索了 JavaScript 库。我们设置了一个基于云的 MQTT 代理，并能够使用我们的 JavaScript 客户端和树莓派上的 Python 程序发布和订阅消息。

在第十八章中，*将所有内容放在一起*，我们将扩展本章学到的知识，并构建一个可以通过互联网控制 T.A.R.A.S 的 JavaScript 客户端。

# 问题

1.  我们可以使用哪个程序（平台）在本地安装 MQTT Broker？

1.  JavaScript 和 Java 是相同的技术，是真是假？

1.  我们可以使用 JavaScript 来创建一个 MQTT 客户端吗？

1.  我们可以使用`google-api-javascript-client`库来访问哪些谷歌服务？

1.  MQTT 是物联网中使用的协议，是真是假？

1.  JavaScript Node.js 技术允许您做什么？

1.  Python 可以用于开发 MQTT 客户端，是真是假？

1.  我们可以通过使用脚本标签将外部 JavaScript 库的功能添加到我们的网页中，是真是假？

1.  我们如何在 JavaScript 代码中为我们的 MQTT 客户端设置用户名和密码？

1.  我们可以在 Cloud MQTT 应用程序中查看我们发布的消息吗？

# 进一步阅读

有关使用基于云的 MQTT Broker 的更多信息，请参阅[`www.cloudmqtt.com/docs.html`](https://www.cloudmqtt.com/docs.html)。


# 第十八章：将所有内容放在一起

对于我们的最后一步，我们将让 T.A.R.A.S 响应使用 JavaScript 客户端发送的 MQTT 控制信号。我们将通过修改到目前为止编写的代码来实现这一点。如果您从头开始阅读本书，感谢您的毅力。这是一个漫长的旅程。我们终于做到了。在本章结束时，我们将完成构建物联网设备的终极目标，即一个可以通过互联网控制的机器人车。

系好安全带（双关语）-是时候将 T.A.R.A.S 提升到下一个级别了。

在本章中，我们将涵盖以下主题：

+   构建一个 JavaScript 客户端以连接到我们的树莓派

+   JavaScript 客户端以访问我们的机器人车的感知数据

+   增强我们的 JavaScript 客户端以控制我们的机器人车

# 项目概述

在本章中，我们将 T.A.R.A.S 连接到 MQTT 代理。通过 MQTT 消息，我们将控制 T.A.R.A.S 的移动，并从 T.A.R.A.S 的距离传感器中读取信息。以下是我们将要构建的图表：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/81f1811c-9a9e-42f9-b355-e13691cbb16d.png)

我们将首先编写 HTML JavaScript 客户端（在图表中显示为**HTML 客户端**），并使用它发送和接收 MQTT 消息。然后，我们将把注意力转向编写 T.A.R.A.S 上的代码，以从相同的 MQTT 代理接收和发送消息。我们将使用这些消息来使用浏览器控制 T.A.R.A.S。最后，我们还将使用浏览器从 T.A.R.A.S 实时传输视频。

完成此项目应该需要半天的时间。

# 入门

要完成此项目，需要以下内容：

+   一个树莓派 3 型（2015 年或更新型号）

+   一个 USB 电源适配器

+   一个计算机显示器

+   一个 USB 键盘

+   一个 USB 鼠标

+   一个 T.A.R.A.S 机器人车

# 构建一个 JavaScript 客户端以连接到我们的树莓派

以下是我们将构建的 HTML JavaScript 客户端的屏幕截图，用于通过网络控制 T.A.R.A.S。HTML JavaScript 客户端可能不会赢得任何设计奖，但它将作为一个优秀的学习平台，用于通过互联网发送机器人控制信息。

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/03b0f1b6-f68b-4d53-9ada-0d5ad736a6c1.png)

大紫色按钮用于向 T.A.R.A.S 发送“前进”和“后退”命令。较小的绿色按钮向 T.A.R.A.S 发送“左转”和“右转”控制信息。底部的小银色按钮允许我们使用 T.A.R.A.S 的摄像头拍照，触发 T.A.R.A.S 的警报，并让 T.A.R.A.S 跳舞。`跟踪距离`按钮将 HTML JavaScript 客户端连接到 T.A.R.A.S 传来的距离信息。

在我们为树莓派构建 Python MQTT 客户端之前，我们将使用 CloudMQTT 仪表板跟踪控制信息。

# 编写 HTML 代码

我们将首先为我们的 HTML JavaScript 客户端编写 HTML 代码。您可以使用树莓派以外的计算机：

1.  在您的计算机上创建一个名为`HTML JavaScript Client`的`project`文件夹

1.  从第十七章中复制 Paho JavaScript 库，*构建 JavaScript 客户端*，到`project`文件夹中

1.  使用您喜欢的 HTML 编辑器，创建一个名为`index.html`的文件，并将其保存在*步骤 1*中创建的文件夹中

1.  将以下内容输入到`index.html`中，然后再次保存：

```py
<html>
    <head>
        <title>T.A.R.A.S Robot Car Control</title>
        <script src="paho.javascript-1.0.3/paho-mqtt.js" 
                        type="text/javascript"></script>        
        <script src="scripts/index.js"        
                        type='text/javascript'></script>            

        <link rel="stylesheet" href="styles/styles.css">        
    </head>
    <body>
        <h2>T.A.R.A.S Robot Car Control</h2>
        <div>
            <button onclick="moveForward()" 
                            class="big_button">    
                <h4>Forward</h4>
            </button>
        </div>
        <div>
            <button onclick="turnLeft()" 
                            class="small_button">
                <h4>Turn Left</h4>
            </button>
            <button onclick="turnRight()" 
                            class="small_button">
                <h4>Turn Right</h4>
            </button>
        </div>
        <div>
            <button onclick="moveBackward()" 
                                class="big_button">        
                <h4>Backwards</h4>
            </button>
        </div>
        <div>
            <button onclick="takePicture()" 
                            class="distance_button">        
                <h4>Take Picture</h4>
            </button>
            <button onclick="TARASAlarm()" 
                            class="distance_button">        
                <h4>T.A.R.A.S Alarm</h4>
            </button>
            <button onclick="makeTARASDance()" 
                            class="distance_button">        
                <h4>T.A.R.A.S Dance</h4>
            </button>
            <button onclick="subscribeDistanceData()" 
                            class="distance_button">
                <h4>Track Distance</h4>
            </button>
            <input type="text" id="messageTxt" value="0" 
                            size=34 class="distance" />        
        </div>
    </body>
</html>
```

在我们可以在浏览器中查看`index.html`之前，我们必须为样式创建一个`.css`文件。我们还将为我们的 JavaScript 文件创建一个文件夹：

1.  在您的`project`文件夹中，创建一个新文件夹，并将其命名为`styles`

1.  在`project`文件夹中创建另一个文件夹，并将其命名为`scripts`

1.  您的`project`目录应该与以下内容相同：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/285b49bd-af91-4b65-a64a-2e12ece753d9.png)

1.  在`styles`文件夹中，使用 HTML 编辑器创建一个名为`styles.css`的文件

1.  将以下内容输入到`styles.css`文件中，然后保存：

```py
.big_button {
    background-color: rgb(86, 76, 175);
    border: none;
    color: white;
    padding: 15px 32px;
    text-align: center;
    text-decoration: none;
    display: inline-block;
    font-size: 16px;
    margin: 4px 2px;
    cursor: pointer;
    width: 400px;
}
.small_button {
    background-color: rgb(140, 175, 76);
    border: none;
    color: white;
    padding: 15px 32px;
    text-align: center;
    text-decoration: none;
    display: inline-block;
    font-size: 16px;
    margin: 4px 2px;
    cursor: pointer;
    width: 195px;
}
.distance_button {
    background-color: rgb(192, 192, 192);
    border: none;
    color: white;
    padding: 1px 1px;
    text-align: center;
    text-decoration: none;
    display: inline-block;
    font-size: 10px;
    margin: 2px 2px;
    cursor: pointer;
    width: 60px;
}
.distance {
    background-color: rgb(255, 255, 255);
    border: none;
    color: rgb(192,192,192);
    padding: 1px 1px;
    text-align: top;
    text-decoration: none;
    display: inline-block;
    font-size: 20px;
    margin: 2px 2px;
    cursor: pointer;
    width: 300px;
}
```

1.  打开浏览器，导航到`project`文件夹中的`index.html`文件

1.  您应该看到 T.A.R.A.S 机器人车控制仪表板

在添加 JavaScript 代码之前，让我们看一下我们刚刚写的内容。我们将从导入我们需要的资源开始。我们需要 Paho MQTT 库、一个`index.js`文件（我们还没有写），以及我们的`styles.css`文件。

```py
<script  src="paho.javascript-1.0.3/paho-mqtt.js"  type="text/javascript"></script> <script  src="scripts/index.js"  type='text/javascript'></script> <link  rel="stylesheet"  href="styles/styles.css"> 
```

然后，我们将创建一系列按钮，将这些按钮与我们即将编写的`index.js` JavaScript 文件中的函数绑定：

```py
<div>
 <button  onclick="moveForward()"  class="big_button"> <h4>Forward</h4> </button> </div>
```

由于我们的按钮几乎相似，我们只讨论第一个按钮。第一个按钮通过`onclick`属性绑定到我们 JavaScript 文件中的`moveForward`函数。按钮的样式通过将`class`分配给`big_button`来设置。我们使用第一个按钮来向前移动 T.A.R.A.S。

# 编写与我们的 MQTT 代理通信的 JavaScript 代码

现在我们有了 HTML 和 CSS 文件，让我们创建一个 JavaScript 文件，让 MQTT 的魔力发生：

1.  在`scripts`文件夹中，使用 HTML 编辑器创建一个名为`index.js`的文件。

1.  在`index.js`文件中输入以下内容并保存：

```py
function moveForward() {
    client = new Paho.MQTT.Client("m10.cloudmqtt.com", 38215, "web_" + parseInt(Math.random() * 100, 10));

    // set callback handlers
    client.onConnectionLost = onConnectionLost;
    var options = {
        useSSL: true,
        userName: "vectydkb",
        password: "ZpiPufitxnnT",
        onSuccess: sendMoveForwardMessage,
        onFailure: doFail
    }

    // connect the client
    client.connect(options);
}

// called when the client connects
function sendMoveForwardMessage() {
    message = new Paho.MQTT.Message("Forward");
    message.destinationName = "RobotControl";
    client.send(message);
}

function moveBackward() {
    client = new Paho.MQTT.Client("m10.cloudmqtt.com", 38215, "web_" + parseInt(Math.random() * 100, 10));

    // set callback handlers
    client.onConnectionLost = onConnectionLost;
    var options = {
        useSSL: true,
        userName: "vectydkb",
        password: "ZpiPufitxnnT",
        onSuccess: sendMoveBackwardMessage,
        onFailure: doFail
    }

    // connect the client
    client.connect(options);
}

// called when the client connects
function sendMoveBackwardMessage() {
    message = new Paho.MQTT.Message("Backward");
    message.destinationName = "RobotControl";
    client.send(message);
}

function turnLeft() {
    client = new Paho.MQTT.Client("m10.cloudmqtt.com", 38215, "web_" + parseInt(Math.random() * 100, 10));

    // set callback handlers
    client.onConnectionLost = onConnectionLost;
    var options = {
        useSSL: true,
        userName: "vectydkb",
        password: "ZpiPufitxnnT",
        onSuccess: sendTurnLeftMessage,
        onFailure: doFail
    }

    // connect the client
    client.connect(options);
}

// called when the client connects
function sendTurnLeftMessage() {
    message = new Paho.MQTT.Message("Left");
    message.destinationName = "RobotControl";
    client.send(message);
}

function turnRight() {
    client = new Paho.MQTT.Client("m10.cloudmqtt.com", 38215, "web_" + parseInt(Math.random() * 100, 10));

    // set callback handlers
    client.onConnectionLost = onConnectionLost;
    var options = {
        useSSL: true,
        userName: "vectydkb",
        password: "ZpiPufitxnnT",
        onSuccess: sendTurnRightMessage,
        onFailure: doFail
    }

    // connect the client
    client.connect(options);
}

// called when the client connects
function sendTurnRightMessage() {
    message = new Paho.MQTT.Message("Right");
    message.destinationName = "RobotControl";
    client.send(message);
}

function takePicture() {
    client = new Paho.MQTT.Client("m10.cloudmqtt.com", 38215, "web_" + parseInt(Math.random() * 100, 10));

    // set callback handlers
    client.onConnectionLost = onConnectionLost;
    var options = {
        useSSL: true,
        userName: "vectydkb",
        password: "ZpiPufitxnnT",
        onSuccess: sendTakePictureMessage,
        onFailure: doFail
    }

    // connect the client
    client.connect(options);
}

// called when the client connects
function sendTakePictureMessage() {
    message = new Paho.MQTT.Message("Picture");
    message.destinationName = "RobotControl";
    client.send(message);
}

function TARASAlarm() {
    client = new Paho.MQTT.Client("m10.cloudmqtt.com", 38215, "web_" + parseInt(Math.random() * 100, 10));

    // set callback handlers
    client.onConnectionLost = onConnectionLost;
    var options = {
        useSSL: true,
        userName: "vectydkb",
        password: "ZpiPufitxnnT",
        onSuccess: sendTARASAlarmMessage,
        onFailure: doFail
    }

    // connect the client
    client.connect(options);
}

// called when the client connects
function sendTARASAlarmMessage() {
    message = new Paho.MQTT.Message("Alarm");
    message.destinationName = "RobotControl";
    client.send(message);
}

function makeTARASDance() {
    client = new Paho.MQTT.Client("m10.cloudmqtt.com", 38215, "web_" + parseInt(Math.random() * 100, 10));

    // set callback handlers
    client.onConnectionLost = onConnectionLost;
    var options = {
        useSSL: true,
        userName: "vectydkb",
        password: "ZpiPufitxnnT",
        onSuccess: makeTARASDanceMessage,
        onFailure: doFail
    }

    // connect the client
    client.connect(options);
}

// called when the client connects
function makeTARASDanceMessage() {
    message = new Paho.MQTT.Message("Dance");
    message.destinationName = "RobotControl";
    client.send(message);
}

function doFail() {
    alert("Error!");
}

// called when the client loses its connection
function onConnectionLost(responseObject) {
    if (responseObject.errorCode !== 0) {
        alert("onConnectionLost:" + responseObject.errorMessage);
    }
}

// called when a message arrives
function onMessageArrived(message) {
    document.getElementById('messageTxt').value = message.payloadString; 
}

function onsubsribeDistanceDataSuccess() {
    client.subscribe("distance");
    alert("Subscribed to distance data");
}

function subscribeDistanceData() {
    client = new Paho.MQTT.Client("m10.cloudmqtt.com", 38215, "web_" + parseInt(Math.random() * 100, 10));

    // set callback handlers
    client.onConnectionLost = onConnectionLost;
    client.onMessageArrived = onMessageArrived;
    var options = {
        useSSL: true,
        userName: "vectydkb",
        password: "ZpiPufitxnnT",
        onSuccess: onsubsribeDistanceDataSuccess,
        onFailure: doFail
    }

    // connect the client
    client.connect(options);
}
```

1.  我已经在代码中留下了我的 CloudMQTT 实例的值。就像我们在第十七章中所做的那样，*构建 JavaScript 客户端*，用您实例的值（`服务器`、`Websockets 端口`、`用户名`、`密码`）替换这些值。

1.  在浏览器中导航回到`index.html`并刷新页面。

1.  现在我们已经有了我们的 HTML JavaScript 客户端。我们所做的实质上是修改了第十七章中的`index.js`代码，*构建 JavaScript 客户端*，以便我们可以向我们的 MQTT 代理发送控制消息，最终控制我们的机器人车：

```py
function moveForward() {
    client = new Paho.MQTT.Client("m10.cloudmqtt.com", 38215, "web_" + parseInt(Math.random() * 100, 10));

    // set callback handlers
    client.onConnectionLost = onConnectionLost;
    var options = {
        useSSL: true,
        userName: "vectydkb",
        password: "ZpiPufitxnnT",
        onSuccess: sendMoveForwardMessage,
        onFailure: doFail
    }

    // connect the client
    client.connect(options);
}

// called when the client connects
function sendMoveForwardMessage() {
    message = new Paho.MQTT.Message("Forward");
    message.destinationName = "RobotControl";
    client.send(message);
}
```

我们已经更改了上一个示例中的代码。`moveForward`函数创建了一个名为`client`的 Paho MQTT 客户端，其中包含从我们的 CloudMQTT 实例获取的`服务器`和`Websockets 端口`连接信息。设置了一个回调处理程序来处理连接丢失时的情况，该处理程序设置为`onConnectionLost`函数。使用从我们的 CloudMQTT 实例获取的`userName`和`password`信息创建了`options`变量。我们将成功连接到 MQTT 代理设置为`sendMoveForwardMessage`函数。然后通过传入`options`变量连接到我们的客户端。

`sendMoveForwardMessage`函数创建了一个名为`Forward`的新 Paho MQTT 消息。然后将此消息分配给`RobotControl`主题，并使用我们的 Paho MQTT 客户端对象`client`发送。

发送后退、右转、左转、拍照、触发警报和跳舞的消息的函数以类似的方式编写为`moveForward`函数。

现在我们已经为控制 T.A.R.A.S 在网络上构建了 HTML JavaScript 客户端，让我们使用 CloudMQTT 实例上的`WEBSOCKETS UI`页面进行测试：

1.  导航回到您的 CloudMQTT 帐户。

1.  选择您获取服务器、用户、密码和 Web 套接字端口连接信息的实例（在第十七章中，*构建 JavaScript 客户端*，我们创建了名为`T.A.R.A.S`的实例）。

1.  点击左侧的 WEBSOCKETS UI 菜单选项。您应该在右侧收到一个成功连接的通知。

1.  导航回到`index.html`并点击“前进”按钮。

1.  现在，导航回到您的 CloudMQTT 实例。您应该在“接收到的消息”列表中看到一条新消息：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/d27aef97-918d-4ec1-b8fa-ed685f711ea6.png)

恭喜！您刚刚连接了一个 HTML JavaScript 客户端到一个 MQTT 代理并发送了一条消息。现在我们将在另一台设备上使用完全不同的编程语言开发另一个客户端，然后使用该客户端订阅来自我们的 HTML JavaScript 客户端的消息。

# 创建一个 JavaScript 客户端来访问我们机器人车的感知数据

我们创建的`index.js`文件包含订阅我们的 HTML JavaScript 客户端到`distance`主题的函数：

```py
function subscribeDistanceData() {
    client = new Paho.MQTT.Client("m10.cloudmqtt.com", 38215, "web_" + parseInt(Math.random() * 100, 10));

    // set callback handlers
    client.onConnectionLost = onConnectionLost;
    client.onMessageArrived = onMessageArrived;
    var options = {
        useSSL: true,
        userName: "vectydkb",
        password: "ZpiPufitxnnT",
        onSuccess: onsubsribeDistanceDataSuccess,
        onFailure: doFail
    }

    // connect the client
    client.connect(options);
}

function onsubsribeDistanceDataSuccess() {
    client.subscribe("distance");
    alert("Subscribed to distance data");
}
```

类似于我们在第十七章中编写的代码，*构建 JavaScript 客户端*，`subscribeDistanceData`函数创建了一个 Paho MQTT 客户端，其中包含来自 CloudMQTT 实例的连接信息。成功连接后，将调用`onsubscribeDistanceDataSuccess`函数，该函数将`client`订阅到`distance`主题。

还创建了一个警报，告诉我们 HTML JavaScript 客户端现在已订阅了`distance`主题。

# 编写 T.A.R.A.S 的代码

现在我们将把注意力转回到我们的树莓派机器人车上，并编写 Python 代码来与我们的 MQTT 代理通信，最终与我们的 HTML JavaScript 客户端通信。以下代码应直接从 T.A.R.A.S 运行。如果您想要无线运行 T.A.R.A.S，请使用 USB 电源适配器为树莓派供电，并在运行以下程序后断开 HDMI 电缆：

1.  从应用程序菜单 | 编程 | Thonny Python IDE 中打开 Thonny。

1.  单击新图标创建一个新文件。

1.  将以下代码输入文件中：

```py
import paho.mqtt.client as mqtt
from time import sleep
from RobotDance import RobotDance
from RobotWheels import RobotWheels
from RobotBeep import RobotBeep
from RobotCamera import RobotCamera
from gpiozero import DistanceSensor

distance_sensor = DistanceSensor(echo=18, trigger=17)

def on_message(client, userdata, message):
    command = message.payload.decode("utf-8")

    if command == "Forward":
        move_forward()
    elif command == "Backward":
        move_backward()
    elif command == "Left":
        turn_left()
    elif command == "Right":
        turn_right()
    elif command == "Picture":
        take_picture()
    elif command == "Alarm":
        sound_alarm()
    elif command == "Dance":
        robot_dance()

def move_forward():
    robotWheels = RobotWheels()
    robotWheels.move_forward()
    sleep(1)
    print("Moved forward")
    robotWheels.stop()
    watchMode()

def move_backward():
    robotWheels = RobotWheels()
    robotWheels.move_backwards()
    sleep(1)
    print("Moved backwards")
    robotWheels.stop()
    watchMode()

def turn_left():
    robotWheels = RobotWheels()
    robotWheels.turn_left()
    sleep(1)
    print("Turned left")
    robotWheels.stop()
    watchMode()

def turn_right():
    robotWheels = RobotWheels()
    robotWheels.turn_right()
    print("Turned right")
    robotWheels.stop()
    watchMode()

def take_picture():
    robotCamera = RobotCamera()
    robotCamera.take_picture()
    watchMode()

def sound_alarm():
    robotBeep = RobotBeep()
    robotBeep.play_song()

def robot_dance():
    robotDance = RobotDance()
    robotDance.lets_dance_incognito()
    print("Finished dancing now back to work")
    watchMode()

def watchMode():
    print("Watching.....")
    mqttc = mqtt.Client()
    mqttc.username_pw_set("vectydkb", "ZpiPufitxnnT")
    mqttc.connect('m10.cloudmqtt.com', 18215)
    mqttc.on_message = on_message
    mqttc.subscribe("RobotControl")

    while True:
        distance = distance_sensor.distance*100
        mqttc.loop()
        mqttc.publish("distance", distance)
        sleep(2)

watchMode()
```

1.  将文件保存为`MQTT-RobotControl.py`。

1.  从 Thonny 运行代码。

1.  转到 HTML JavaScript 客户端，然后单击前进按钮：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/a3a9aa2f-9422-4ebf-9872-52f768cdc3d3.png)

1.  T.A.R.A.S 应该向前移动一秒，然后停止。

1.  底部的小灰色按钮允许您执行与 T.A.R.A.S 的各种任务：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/4c7e63b9-3ddf-430a-80ea-19c0822004f3.png)

1.  通过单击这些按钮来探索每个按钮的功能。`Take Picture`按钮将拍照并将其存储在文件系统中，`T.A.R.A.S Alarm`将在 T.A.R.A.S 上触发警报，`T.A.R.A.S Dance`将使 T.A.R.A.S 跳舞。

1.  要订阅来自 T.A.R.A.S 距离传感器的`distance`数据，请单击 Track Distance 按钮：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/2cc958d7-a0e0-4e21-bd37-36ea31d9c59e.png)

1.  单击 Track Distance 按钮后，您应该会看到一个弹出窗口，告诉您 HTML JavaScript 客户端现在已订阅了`distance`数据：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/415dfa7a-89b4-48ad-8513-e091c2aa3d0e.png)

1.  单击关闭以关闭弹出窗口。现在您应该看到 T.A.R.A.S 的距离数据信息显示在 Track Distance 按钮旁边。

1.  与迄今为止我们编写的所有代码一样，我们的目标是使其尽可能简单和易于理解。我们代码的核心是`watch_mode`方法：

```py
def watchMode():
    print("Watching.....")
    mqttc = mqtt.Client()
    mqttc.username_pw_set("vectydkb", "ZpiPufitxnnT")
    mqttc.connect('m10.cloudmqtt.com', 18215)
    mqttc.on_message = on_message
    mqttc.subscribe("RobotControl")

    while True:
        distance = distance_sensor.distance*100
        mqttc.loop()
        mqttc.publish("distance", distance)
        sleep(2)
```

`watch_mode`方法是我们代码的默认方法。它在代码运行后立即调用，并在另一个方法完成时调用。在`watch_mode`中，我们需要创建一个名为`mqttc`的 MQTT 客户端对象，然后使用它连接到我们的 CloudMQTT 实例。从那里，我们将`on_message`回调设置为`on_message`方法。然后我们订阅`RobotControl`主题。随后的 while 循环调用我们的 MQTT 客户端`mqttc`的`loop`方法。由于我们已经设置了`on_message`回调，因此每当从`RobotControl`主题接收到消息时，程序都会退出 while 循环，并执行我们代码的`on_message`方法。

在`watch_mode`中，每 2 秒将距离传感器信息发布到`distance`主题。由于我们的 HTML JavaScript 客户端已设置为订阅`distance`主题上的消息，因此我们的 HTML JavaScript 客户端将每两秒在页面上更新`distance`信息。

# 从 T.A.R.A.S 直播视频。

从网络上控制 T.A.R.A.S 是一件了不起的事情，但如果我们看不到我们在做什么，那就没什么用了。如果你在树莓派上安装 RPi-Cam-Web-Interface，就可以很简单地从树莓派上直播视频。现在让我们来做这个：

1.  如果您的树莓派上没有安装`git`，请在终端中使用`sudo apt-get install git`进行安装。

1.  使用终端，通过运行`git clone https://github.com/silvanmelchior/RPi_Cam_Web_Interface.git`命令获取安装文件。

1.  使用`cd RPi_Cam_Web_Interface`命令更改目录。

1.  使用`./install.sh`命令运行安装程序。

1.  您应该看到配置选项屏幕：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/721fe07d-1a6c-410b-9453-b884580c6170.png)

1.  通过在键盘上按*Tab*，接受所有默认设置，直到 OK 选项被突出显示。然后按*Enter*。

1.  在看到“现在启动摄像头系统”对话框时选择“是”：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/61bcc260-0ba5-4de2-90f1-5a8dd2685c95.png)

1.  现在，我们已经准备好从我们的树莓派（T.A.R.A.S）实时传输视频。在另一台计算机上，打开浏览器，输入地址`http://<<您的树莓派 IP 地址>>/html`（在您的树莓派上使用`ifconfig`来查找您的 IP 地址；在我的情况下，视频流的 URL 是`http://192.168.0.31/html`）。

1.  现在，您应该看到视频流播放器加载到您的浏览器中，并从您的树莓派实时播放视频。以下是我办公室 T.A.R.A.S 的直播截图，显示我的无人机：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/2c0a7d4a-e9e2-493f-b74b-0585dc0461dd.png)

RPi-Cam-Web-Interface 实用程序是一个令人惊叹的工具。花些时间尝试一下可用的各种选项和功能。

# 增强我们的 JavaScript 客户端以控制我们的机器人小车

正如我们已经提到的，我们的 HTML JavaScript 客户端是最具吸引力的界面。我设计它尽可能简单直接，以便解释各种概念。但是，如果我们想把它提升到另一个水平呢？以下是一些可能用于增强我们的 HTML JavaScript 客户端的 JavaScript 库的列表。

# Nipple.js

Nipple.js ([`www.bypeople.com/touch-screen-joystick/`](https://www.bypeople.com/touch-screen-joystick/))是一个 JavaScript 触摸屏操纵杆库，可用于控制机器人。Nipple.js 基本上是一种屏幕上的指向杆控制，类似于一些笔记本电脑上的控制。

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/279a34fc-8690-419e-a37f-3216132c51a3.png)

如果您要为触摸屏平板电脑或笔记本电脑创建 JavaScript 客户端，Nipple.js 可能是一个很好的构建技术。将 Nipple.js 等技术纳入我们的设计中，需要相当多的编码工作，以便将移动转换为 T.A.R.A.S 能理解的消息。简单的前进消息可能不够。消息可能是`Forward-1-Left-2.3`之类的，必须对其进行解析并提取信息，以确定转动电机的时间和移动哪些电机。

# HTML5 Gamepad API

您想连接物理操纵杆来控制我们的机器人小车吗？您可以使用 HTML5 Gamepad API ([`www.w3.org/TR/gamepad/`](https://www.w3.org/TR/gamepad/))。使用 HTML5 Gamepad API，您可以在构建的 Web 应用程序中使用标准游戏操纵杆。通过 HTML5 Gamepad API 控制您的机器人小车可能就像玩您最喜欢的视频游戏一样简单。

# Johnny-Five

Johnny-Five ([`johnny-five.io`](http://johnny-five.io))是一个 JavaScript 机器人和物联网平台。这是一个完全不同于我们为机器人小车开发的平台。现在我们已经从头开始构建了我们的机器人小车，并且已经手工编写了控制代码，我们可能有兴趣尝试一些新东西。Johnny-Five 可能是您决定成为专家的下一个技术。

# 摘要

我们做到了！我们已经完成了树莓派物联网之旅。在本章中，我们将所学知识整合在一起，并创建了自己的 HTML JavaScript 客户端，用于通过网页控制 T.A.R.A.S。我们使用类来控制 T.A.R.A.S，使得创建控制代码相对容易，因为我们只需要在类上调用方法，而不是从头开始创建控制代码。

我们简要介绍了如何轻松地从树莓派实时传输视频。尽管我们做所有这些是为了通过网络控制机器人小车，但不难想象我们可以利用所学知识来构建任意数量的不同物联网项目。

我们生活在一个非常激动人心的时代。我们中的任何一个人都可以仅凭我们的智慧和一些相对便宜的电子元件来构建下一个杀手级应用程序。如果可能的话，我希望我能激励您使用令人惊叹的树莓派计算机来构建您的下一个伟大项目。

对于那些质疑我们如何将这视为物联网项目的人，当我们只使用我们的本地网络时，请研究一下如何在路由器上打开端口以连接外部世界。然而，这不是一项应该轻率对待的任务，因为在这样做时必须解决安全问题。请注意，您的互联网服务提供商可能没有为您提供静态 IP 地址，因此您构建的任何用于从外部访问您的网络的东西都会在 IP 地址更改时中断（我曾经构建过一个定期检查我的 IP 地址的 PHP 页面，存储最新地址，并有外部客户端会访问该 PHP 获取地址，而不是将其硬编码）。

# 问题

1.  在我们的项目中，我们向哪个主题发布控制类型的消息？

1.  真或假？MQTT Broker 和 MQTT Server 是用来描述同一件事情的词语。

1.  真或假？T.A.R.A.S 在相同的 MQTT 主题上发布和订阅。

1.  我们的 HTML JavaScript 客户端中的大前进和后退按钮是什么颜色？

1.  真或假？使用 HTML JavaScript 客户端，我们能够远程使用 T.A.R.A.S 上的摄像头拍照。

1.  我们使用什么 MQTT 主题名称来订阅来自 T.A.R.A.S 的距离数据？

1.  真或假？我们的 HTML JavaScript 客户端采用了屡获殊荣的 UI 设计。

1.  真或假？使用我们的 CloudMQTT 账户，我们能够查看我们实例中发布的消息。

1.  我们使用什么技术来从 T.A.R.A.S 进行视频直播？

1.  真或假？Johnny-Five 是可口可乐公司推出的一种新果汁饮料。

# 进一步阅读

当我们在 T.A.R.A.S 上设置实时流时，我们简要地介绍了 RPi-Cam-Web-Interface 网页界面。这个网页界面非常惊人，对它的更深入了解只会增强我们对树莓派的所有可能性的理解。请访问[`elinux.org/RPi-Cam-Web-Interface`](https://elinux.org/RPi-Cam-Web-Interface)获取更多信息。
