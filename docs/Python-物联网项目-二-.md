# Python 物联网项目（二）

> 原文：[`zh.annas-archive.org/md5/34135f16ce1c2c69e5f81139e996b460`](https://zh.annas-archive.org/md5/34135f16ce1c2c69e5f81139e996b460)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：使用伺服控制代码控制模拟设备

继续我们的旅程，将模拟仪表的优雅与数字数据的准确性相结合，我们将看看我们在前两章中学到的内容，并构建一个带有模拟仪表显示的物联网天气仪表盘。

在开始本章之前，请确保已经连接了第五章中的电路，*使用 Python 控制伺服*。

这个仪表盘将根据室外温度和风速显示衣柜建议。我们还将在我们的仪表盘上使用 LED 指示是否需要带上雨伞。

本章将涵盖以下主题：

+   从云端访问天气数据

+   使用天气数据控制伺服

+   增强我们的项目

# 完成本章所需的知识

您应该具备 Python 编程语言的工作知识才能完成本章。还必须了解如何使用简单的面包板，以便连接组件。

在这个项目中可以使用乙烯基或手工切割机。了解如何使用切割机将是一个资产，这样你就可以完成这个项目。

# 项目概述

到本章结束时，我们应该有一个可以工作的物联网模拟天气仪表盘。我们将修改第四章和第五章中编写的代码，以向我们的仪表盘提供数据。将打印并剪切一个背景。这个背景将给我们的仪表盘一个卡通般的外观。

我们将使用第五章中的电路，*使用 Python 控制伺服*。以下是来自该电路的接线图：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/80b31448-fb1a-4e05-8f81-ccecbeb974e0.png)

这个项目应该需要一个下午的时间来完成。

# 入门

要完成这个项目，需要以下设备：

+   树莓派 3 型号（2015 年或更新型号）

+   一个 USB 电源适配器

+   一台电脑显示器

+   一个 USB 键盘

+   一个 USB 鼠标

+   一个小型伺服电机

+   一个 LED（任何颜色）

+   一个面包板

+   面包板的跳线线

+   一个彩色打印机

+   一个乙烯基或手工切割机（可选）

# 从云端访问天气数据

在第四章中，*订阅 Web 服务*，我们编写了一个 Python 程序，从 Yahoo!天气获取天气数据。该程序中的`CurrentWeather`类返回了根据类实例化时的`city`值返回的温度、天气状况和风速。

我们将重新访问该代码，并将类名更改为`WeatherData`。我们还将添加一个方法，返回一个值从`0`-`100`，以指示天气。在确定这个数字时，我们将考虑温度和风速，0 表示极端的冬季条件，`100`表示非常炎热的夏季极端条件。我们将使用这个数字来控制我们的伺服。我们还将检查是否下雨，并更新我们的 LED 以指示我们是否需要雨伞：

1.  从应用程序菜单 | 编程 | Thonny Python IDE 打开 Thonny

1.  单击新图标创建一个新文件

1.  在文件中输入以下内容：

```py
from weather import Weather, Unit

class WeatherData:

    temperature = 0
    weather_conditions = ''
    wind_speed = 0
    city = ''

    def __init__(self, city):
        self.city = city
        weather = Weather(unit = Unit.CELSIUS)
        lookup = weather.lookup_by_location(self.city)
        self.temperature = float(lookup.condition.temp)
        self.weather_conditions = lookup.condition.text
        self.wind_speed = float(lookup.wind.speed)

    def getServoValue(self):
        temp_factor = (self.temperature*100)/30
        wind_factor = (self.wind_speed*100)/20
        servo_value = temp_factor-(wind_factor/20)

        if(servo_value >= 100):
            return 100
        elif (servo_value <= 0):
            return 0
        else:
            return servo_value

    def getLEDValue(self): 
        if (self.weather_conditions=='Thunderstorm'):
            return 2;
        elif(self.weather_conditions=='Raining'):
            return 1
        else:
            return 0

if __name__=="__main__":

    weather = WeatherData('Paris')
    print(weather.getServoValue())
    print(weather.getLEDValue())
```

1.  将文件保存为`WeatherData.py`

我们的代码的核心在于`getServoValue()`和`getLEDValue()`方法：

```py
def getServoValue(self):
     temp_factor = (self.temperature*100)/30
     wind_factor = (self.wind_speed*100)/20
     servo_value = temp_factor-(wind_factor/20)

     if(servo_value >= 100):
         return 100
     elif (servo_value <= 0):
         return 0
     else:
         return servo_value
```

在`getServoValue`方法中，我们将`temp_factor`和`wind_factor`变量设置为基于最小值`0`和温度和风速的最大值`30`和`20`的百分比值。这些是任意的数字，因为我们将考虑`30`摄氏度为我们的极端高温，20 公里/小时的风速为我们的极端风速。伺服值通过从温度减去风速的 5%（除以`20`）来设置。当然，这也是任意的。随意调整所需的百分比。

为了进一步解释，考虑一下 10 摄氏度的温度和 5 公里/小时的风速。温度因子（temp_factor）将是 10 乘以 100，然后除以 30 或 33.33。风速因子（wind_factor）将是 5 乘以 100，然后除以 20 或 25。我们传递给舵机的值（servo_value）将是温度因子（33.33）减去风速因子（25）后除以`20`。`servo_value`的值为 32.08，或者大约是最大舵机值的 32%。

然后返回`servo_value`的值并将其用于控制我们的舵机。任何低于`0`和高于`100`的值都将超出我们的范围，并且无法与我们的舵机一起使用（因为我们将舵机在`0`和`100`之间移动）。我们在`getServoValue`方法中使用`if`语句来纠正这种情况。

`getLEDValue`方法只是检查天气条件并根据是否下雨返回代码。“雷暴”将返回值`2`，“雨”和“小雨”将返回值`1`，其他任何情况将返回值`0`。如果有雷暴，我们将使用这个值来在我们的仪表盘上闪烁 LED，如果只是下雨，我们将保持其亮起，并在其他所有情况下关闭它：

```py
def getLEDValue(self):
     if (self.weather_conditions=='Thunderstorm'):
         return 2;
     elif(self.weather_conditions=='Rain'):
         return 1
     elif(self.weather_conditions=='Light Rain'):
         return 1
     else:
         return 0
```

在撰写本书时，“雷暴”、“雨”和“小雨”是在搜索世界各大城市天气时返回的值。请随时更新`if`语句以包括其他极端降水的描述。作为一个额外的增强，你可以考虑在`if`语句中使用正则表达式。

在 Thonny 中运行代码。你应该会得到巴黎天气条件下舵机和 LED 的值。我在运行代码时得到了以下结果：

```py
73.075
0
```

# 使用天气数据控制舵机

我们即将构建我们的物联网天气仪表盘。最后的步骤涉及根据从 Yahoo! Weather 网络服务返回的天气数据来控制我们舵机的位置，并在物理上建立一个背景板来支撑我们的舵机指针。

# 校正舵机范围

正如你们中的一些人可能已经注意到的那样，你的舵机并不能从最小到最大移动 180 度。这是由于 GPIO Zero 中设置的最小和最大脉冲宽度为 1 毫秒和 2 毫秒。为了解决这个差异，我们在实例化`Servo`对象时必须相应地调整`min_pulse_width`和`max_pulse_width`属性。

以下代码就是这样做的。变量`servoCorrection`对`min_pulse_width`和`max_pulse_width`值进行加减。以下代码在`5`秒后将舵机移动到最小位置，然后移动到最大位置：

1.  从应用程序菜单 | 编程 | Thonny Python IDE 中打开 Thonny。

1.  单击“新建”图标创建新文件。

1.  在文件中键入以下内容：

```py
from gpiozero import Servo
from time import sleep
servoPin=17

servoCorrection=0.5
maxPW=(2.0+servoCorrection)/1000
minPW=(1.0-servoCorrection)/1000

servo=Servo(servoPin, min_pulse_width=minPW, max_pulse_width=maxPW)

servo.min()
sleep(5)
servo.max()
sleep(5)
servo.min()
sleep(5)
servo.max()
sleep(5)
servo.min()
sleep(5)
servo.max()
sleep(5)

servo.close()
```

1.  将文件保存为`servo_correction.py`。

1.  运行代码，看看`servoCorrection`的值是否修复了你的舵机在`servo.min`到`servo.max`之间不能转动 180 度的问题。

1.  调整`servoCorrection`，直到你的舵机在`servo.min`和`servo.max`之间移动了 180 度。我们将在天气仪表盘的代码中使用`servoCorrection`的值。

# 根据天气数据改变舵机的位置

我们现在已经准备好根据天气条件控制我们舵机的位置。我们将修改我们在第五章中创建的`WeatherDashboard`类，*用 Python 控制舵机*，执行以下步骤：

1.  从应用程序菜单 | 编程 | Thonny Python IDE 中打开 Thonny

1.  单击“新建”图标创建新文件

1.  在文件中键入以下内容：

```py
from gpiozero import Servo
from gpiozero import LED
from time import sleep
from WeatherData import WeatherData

class WeatherDashboard:

     servo_pin = 17
     led_pin = 14
     servoCorrection=0.5
     maxPW=(2.0+servoCorrection)/1000
     minPW=(1.0-servoCorrection)/1000

     def __init__(self, servo_position=0, led_status=0):
         self.servo = Servo(self.servo_pin, min_pulse_width=
                self.minPW, max_pulse_width=self.maxPW)
         self.led = LED(self.led_pin)

         self.move_servo(servo_position)
         self.set_led_status(led_status)

     def move_servo(self, servo_position=0): 
         self.servo.value = self.convert_percentage_to_integer(
                servo_position)

     def turnOffServo(self):
         sleep(5)
         self.servo.close()

     def set_led_status(self, led_status=0):
         if(led_status==0):
             self.led.off()
         elif (led_status==1):
             self.led.on()
         else:
             self.led.blink()

     def convert_percentage_to_integer(self, percentage_amount):
        #adjust for servos that turn counter clockwise by default
        adjusted_percentage_amount = 100 - percentage_amount
        return (adjusted_percentage_amount*0.02)-1

if __name__=="__main__":
     weather_data = WeatherData('Toronto')
     weather_dashboard = WeatherDashboard(
     weather_data.getServoValue(),
     weather_data.getLEDValue())
     weather_dashboard.turnOffServo()
```

1.  将文件保存为`WeatherDashboard.py`

1.  运行代码并观察舵机位置的变化

让我们来看看代码。

我们首先导入我们需要的资源：

```py
from time import sleep
from WeatherData import WeatherData
```

我们添加`time`到我们的项目中，因为我们将在关闭`Servo`对象之前使用它作为延迟。添加`WeatherData`以根据天气条件为我们的伺服和 LED 提供值。

`servoCorrection`，`maxPW`和`minPW`变量调整我们的伺服（如果需要），如前面的伺服校正代码所述：

```py
servoCorrection=0.5
maxPW=(2.0+servoCorrection)/1000
minPW=(1.0-servoCorrection)/1000
```

`turnOffServo`方法允许我们关闭与伺服的连接，停止可能发生的任何抖动运动：

```py
def turnOffServo(self):
    sleep(5)
    self.servo.close()
```

我们使用`sleep`函数延迟关闭伺服，以便在设置到位置之前不会关闭。

您可能还注意到了代码中`convert_percentage_to_integer`方法的更改第五章中的代码，*使用 Python 控制伺服*。为此项目测试的电机在右侧有一个最小位置。这与我们所需的相反，因此代码已更改为从 100 中减去`percentage_amount`，以扭转此行为并给出正确的伺服位置（有关此方法的更多信息，请参阅第五章，*使用 Python 控制伺服*，如有需要，请使用本章中的`convert_percentage_to_integer`）：

```py
def convert_percentage_to_integer(self, percentage_amount):
        #adjust for servos that turn counter clockwise by default
        adjusted_percentage_amount = 100 - percentage_amount
        return (adjusted_percentage_amount*0.02)-1
```

在 Thonny 中运行代码。您应该看到伺服电机根据多伦多，加拿大的天气条件移动到一个位置。LED 将根据多伦多的降雨情况闪烁、保持稳定或关闭。

现在，让我们通过为我们的伺服和 LED 建立一个物理背景来增强我们的项目。

# 增强我们的项目

现在我们的代码已经完成，现在是时候为我们的伺服添加一个物理背景了。通过这个背景，我们根据天气数据为我们的衣柜推荐穿什么。

# 打印主图形

以下是我们将在背景中使用的图形：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/6c3d81ed-cbcb-4f52-9d72-627d49d3fbfa.png)

使用彩色打印机，在可打印的乙烯基上打印图形（此图像文件可从我们的 GitHub 存储库中获取）。剪下伞下和主图形下的孔。

为了增加支撑，用刀或剪刀在硬纸板上切出背板：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/b712b994-07a0-423c-94ae-6e8940f87e8d.png)

将背景从可打印的乙烯基片上剥离并粘贴到背板上。使用孔将背景与背板对齐：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/caaa3b46-e584-45d2-a087-ee980b7fb01e.png)

# 添加指针和 LED

将 LED 插入伞下的孔中：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/1e7514b8-e796-4bd3-929b-a49cdc0e52dc.png)

将伺服电机的轴心插入另一个孔。如有必要，使用双面泡沫胶带将伺服固定在背板上：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/1b142b34-2431-4bdb-89b0-8cbf65488fee.png)

使用跳线线将 LED 和伺服连接到面包板上（请参阅本章开头的接线图）。组件应该稍微倾斜。在我们用新的显示运行`WeatherDashboard`代码之前，我们必须将指针安装到最小位置：

1.  从应用程序菜单中打开 Thonny | 编程 | Thonny Python IDE

1.  单击新图标创建一个新文件

1.  在文件中输入以下内容：

```py
from gpiozero import Servo
servoPin=17

servoCorrection=<<put in the correction you calculated>>
maxPW=(2.0+servoCorrection)/1000
minPW=(1.0-servoCorrection)/1000

servo=Servo(servoPin, min_pulse_width=minPW, max_pulse_width=maxPW)

servo.min()
```

1.  将文件保存为`servo_minimum.py`

1.  运行代码使伺服将自己定位到最小值

安装指针，使其指向左侧，如果伺服电机逆时针转到最小位置，使其指向右侧，如果伺服电机顺时针转到最小位置（一旦您开始实际使用伺服，这将更有意义）。

再次运行`WeatherDashboard`代码。伺服应该根据天气数据移动，指示衣柜选项。如果下雨，LED 应该亮起。雷暴会闪烁 LED。否则，LED 将保持关闭状态。

在下图中，仪表盘建议多伦多，加拿大穿短袖衬衫。外部天气条件不需要雨伞：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/f64e1685-26b7-4020-9ea4-91021073ff0e.png)

恭喜！你刚刚建立了一个 IoT 天气仪表盘。

# 摘要

在这个项目中，我们利用了树莓派的力量来创建了一个 IoT 模拟天气仪表盘。在这种情况下，这涉及到使用作为模拟仪表的互联网控制的伺服。我们很容易想象如何修改我们的代码来显示除天气数据之外的其他数据。想象一下，一个模拟仪表显示远程工厂的油箱水平，其中水平数据通过互联网通信。

模拟仪表的直观性使其非常适合需要一瞥数据的应用程序。将模拟仪表与来自互联网的数据结合起来，创造了全新的数据显示世界。

在第七章中，*设置树莓派 Web 服务器*，我们将迈出模拟世界的一步，探索如何使用树莓派作为 Web 服务器并构建基于 Web 的仪表盘。

# 问题

1.  真还是假？伺服可以用作 IoT 设备。

1.  真还是假？更改`Servo`对象上的最小和最大脉冲宽度值会修改伺服的范围。

1.  为什么在调用`Servo`对象的`close()`方法之前我们要添加延迟？

1.  真还是假？我们在`WeatherData`类中不需要`getTemperature()`方法。

1.  真还是假？我们仪表盘上闪烁的 LED 表示晴天和多云的天气。

1.  我们在仪表盘上使用一对短裤来表示什么？

1.  在我们的代码中，你会在哪里使用正则表达式？

1.  为什么我们在代码中导入时间？

1.  真还是假？IoT 启用的伺服只能用于指示天气数据。

# 进一步阅读

为了增强我们的代码，可以使用正则表达式。任何关于 Python 和正则表达式的文档都对发展强大的编码技能非常宝贵。


# 第七章：设置树莓派 Web 服务器

我们将通过学习如何使用 CherryPy web 服务器框架来开始创建 IoT 家庭安全仪表板的旅程。我们的章节将从介绍 CherryPy 开始。在我们创建一个修改版本的`CurrentWeather`类的 HTML 天气仪表板之前，我们将通过一些示例进行学习。

本章将涵盖以下主题：

+   介绍 CherryPy——一个极简的 Python Web 框架

+   使用 CherryPy 创建一个简单的网页

# 完成本章所需的知识

读者应该具有 Python 的工作知识才能完成本章。还需要基本了解 HTML，包括 CSS，才能完成本章的项目。

# 项目概述

在本章中，我们将使用 CherryPy 和 Bootstrap 框架构建 HTML 天气仪表板。不需要对这些框架有深入的了解就可以完成项目。

这个项目应该需要几个小时来完成。

# 入门

要完成此项目，需要以下内容：

+   Raspberry Pi Model 3（2015 年或更新型号）

+   一个 USB 电源适配器

+   一个计算机显示器

+   一个 USB 键盘

+   一个 USB 鼠标

# 介绍 CherryPy——一个极简的 Python Web 框架

对于我们的项目，我们将使用 CherryPy Python 库（请注意，它是带有"y"的 CherryPy，而不是带有"i"的 CherryPi）。

# 什么是 CherryPy？

根据他们的网站，CherryPy 是一个 Pythonic 的面向对象的 Web 框架。CherryPy 使开发人员能够构建 Web 应用程序，就像他们构建任何面向对象的 Python 程序一样。按照 Python 的风格，CherryPy 程序的代码更少，开发时间比其他 Web 框架短。

# 谁在使用 CherryPy？

一些使用 CherryPy 的公司包括以下内容：

+   Netflix：Netflix 通过 RESTful API 调用在其基础设施中使用 CherryPy。Netflix 使用的其他 Python 库包括 Bottle 和 SciPy。

+   Hulu：CherryPy 被用于 Hulu 的一些项目。

+   Indigo Domotics：Indigo Domotics 是一家使用 CherryPy 框架的家庭自动化公司。

# 安装 CherryPy

我们将使用 Python 的`pip3`软件包管理系统来安装 CherryPy。

软件包管理系统是一个帮助安装和配置应用程序的程序。它还可以进行升级和卸载。

要做到这一点，打开一个终端窗口，输入以下内容：

```py
sudo pip3 install cherrypy
```

按下*Enter*。您应该在终端中看到以下内容：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/2fe0a193-759c-49b0-9c82-57ce1f5766dc.png)

在 Thonny 中，转到工具|管理包。您应该看到 CherryPy 现在已安装，如下所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/7f7232a1-86e0-4f95-ab6b-c8c9c3cb45a2.png)

# 使用 CherryPy 创建一个简单的网页

让我们开始，让我们用 CherryPy 构建最基本的程序。我指的当然是无处不在的`Hello World`程序，我们将用它来说`Hello Raspberry Pi!`。在我们构建一个仪表板来显示天气数据之前，我们将通过一些示例进行学习，使用第四章中的`CurrentWeather`类的修改版本，*订阅 Web 服务*。

# Hello Raspberry Pi!

要构建`Hello Raspberry Pi!`网页，执行以下操作：

1.  从应用程序菜单|编程|Thonny Python IDE 中打开 Thonny。

1.  单击新图标创建一个新文件。

1.  输入以下内容：

```py
import cherrypy

class HelloWorld():

     @cherrypy.expose
     def index(self):
         return "Hello Raspberry Pi!"

cherrypy.quickstart(HelloWorld())

```

1.  确保行`cherrypy.quickstart(HelloWorld())`与`import`和`class`语句一致。

1.  将文件保存为`HelloRaspberryPi.py`。

1.  点击绿色的`Run current script`按钮运行文件。

1.  您应该看到 CherryPy web 服务器正在终端中启动：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/ecbc3a89-f763-46b3-bbde-b32f6e46aa04.png)

1.  从终端输出中，您应该能够观察到 CherryPy 正在运行的 IP 地址和端口，`http://127.0.0.1:8080`。您可能会认出 IP 地址是环回地址。CherryPy 使用端口`8080`。

1.  在树莓派上打开一个网络浏览器，并在地址栏中输入上一步的地址：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/8f293187-5738-4253-8d25-32b1172d5aac.png)

恭喜，您刚刚将您的谦卑的树莓派变成了一个网络服务器。

如果您和我一样，您可能没有想到一个网络服务器可以用如此少的代码创建。CherryPy 基本上专注于一个任务，那就是接收 HTTP 请求并将其转换为 Python 方法。

它是如何工作的呢？我们的`HelloWorld`类中的装饰器`@cherrypy.expose`公开了恰好对应于网络服务器根目录的`index`方法。当我们使用回环地址（`127.0.0.1`）和 CherryPy 正在运行的端口（`8080`）加载我们的网页时，`index`方法将作为页面提供。在我们的代码中，我们只是返回字符串`Hello Raspberry Pi!`，然后它就会显示为我们的网页。

回环地址是用作机器软件回环接口的 IP 号码。这个号码通常是`127.0.0.1`。这个地址并没有物理连接到网络，通常用于测试安装在同一台机器上的网络服务器。

# 向 myFriend 问好

那么，如果我们在 Python 代码中公开另一个方法会发生什么呢？我们可以通过在方法之前使用装饰器轻松地检查到这一点。让我们编写一些代码来做到这一点：

1.  从应用程序菜单 | 编程 | Thonny Python IDE 中打开 Thonny。

1.  单击新建图标创建一个新文件。

1.  输入以下内容：

```py
import cherrypy

class HelloWorld():

     @cherrypy.expose
     def index(self):
         return "Hello Raspberry Pi!"

     @cherrypy.expose
     def sayHello(self, myFriend=" my friend"):
         return "Hello " + myFriend

cherrypy.quickstart(HelloWorld())
```

1.  将文件保存为`SayHello.py`。

1.  通过单击中断/重置按钮，然后单击运行当前脚本按钮来停止和启动 CherryPy 服务器。

1.  现在，输入以下内容到您的浏览器的地址栏中，然后按*Enter*：`http://127.0.0.1:8080/sayHello`

1.  您应该看到以下内容：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/41a50c34-5bce-48d0-817a-40f6cfed119b.png)

这次我们做了什么不同的事情？首先，我们不只是访问了服务器的根目录。我们在 URL 中添加了`/sayHello`。通常，当我们在网络服务器上这样做时，我们会被引导到一个子文件夹。在这种情况下，我们被带到了我们的`HelloWorld`类中的`sayHello()`方法。

如果我们仔细看`sayHello()`方法，我们会发现它接受一个名为`myFriend`的参数：

```py
@cherrypy.expose
def sayHello(self, myFriend=" my friend"):
         return "Hello " + myFriend
```

我们可以看到`myFriend`参数的默认值是`my Friend`。因此，当我们运行 CherryPy 并导航到`http://127.0.0.1:8080/sayHello`的 URL 时，将调用`sayHello`方法，并返回`"Hello " + my friend`字符串。

现在，将以下内容输入到地址栏中，然后按*Enter*：`http://127.0.0.1:8080/sayHello?myFriend=Raspberry%20Pi`

在这个 URL 中，我们将`myFriend`的值设置为`Raspberry%20Pi`（使用`%20`代替空格）。我们应该得到与我们的第一个示例相同的结果。

正如我们所看到的，将 Python 方法连接到 HTML 输出非常容易。

# 静态页面呢？

静态页面曾经是互联网上随处可见的。静态页面之间的简单链接构成了当时被认为是一个网站的内容。然而，自那时以来发生了很多变化，但是能够提供一个简单的 HTML 页面仍然是网络服务器框架的基本要求。

那么，我们如何在 CherryPy 中做到这一点呢？实际上很简单。我们只需在一个方法中打开一个静态 HTML 页面并返回它。让我们通过以下方式让 CherryPy 提供一个静态页面：

1.  从应用程序菜单 | 编程 | Thonny Python IDE 中打开 Thonny。

1.  单击新建图标创建一个新文件。

1.  输入以下内容：

```py
<html>
    <body>
        This is a static HTML page.
    </body>
</html>
```

1.  将文件保存为`static.html`。

1.  在 Thonny 中点击新建图标，在与`static.html`相同的目录中创建一个新文件。

1.  输入以下内容：

```py
import cherrypy

class StaticPage():

     @cherrypy.expose
     def index(self):
         return open('static.html')

cherrypy.quickstart(StaticPage())
```

1.  将文件保存为`StaticPage.py`。

1.  如果 CherryPy 仍在运行，请单击红色按钮停止它。

1.  运行文件`StaticPage.py`以启动 CherryPy。

1.  您应该看到 CherryPy 正在启动，如终端中所示。

1.  要查看我们的新静态网页，请在树莓派上打开一个网络浏览器，并在地址栏中输入以下内容：`http://127.0.0.1:8080`

1.  您应该看到静态页面显示出来了：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/6418ac8e-b97b-49d3-9c72-7edc6d83348f.png)

那么我们在这里做了什么呢？我们修改了我们的`index`方法，使其返回一个打开的`static.html`文件，带有`return open('static.html')`这一行。这将在我们的浏览器中打开`static.html`作为我们的索引（或`http://127.0.0.1:8080/index`）。请注意，尝试在 url 中输入页面名称`static.html`（`http://127.0.0.1:8080/static.html`）将不起作用。CherryPy 根据方法名提供内容。在这种情况下，方法名是 index，这是默认值。

# HTML 天气仪表板

现在是时候添加我们从之前章节学到的知识了。让我们重新访问第四章中的`CurrentWeather`类，*订阅 Web 服务*。我们将把它重命名为`WeatherData`，因为这个名字更适合这个项目，并稍微修改一下。

1.  从应用程序菜单 | 编程 | Thonny Python IDE 中打开 Thonny

1.  单击新图标创建一个新文件

1.  输入以下内容：

```py
from weather import Weather, Unit
import time

class WeatherData:

    temperature = 0
    weather_conditions = ''
    wind_speed = 0
    city = ''

    def __init__(self, city):
        self.city = city
        weather = Weather(unit = Unit.CELSIUS)
        lookup = weather.lookup_by_location(self.city)
        self.temperature = lookup.condition.temp
        self.weather_conditions = lookup.condition.text
        self.wind_speed = lookup.wind.speed

    def getTemperature(self):
        return self.temperature + " C"

    def getWeatherConditions(self):
        return self.weather_conditions

    def getWindSpeed(self):
        return self.wind_speed + " kph"

    def getCity(self):
        return self.city

    def getTime(self):
        return time.ctime()

if __name__ == "__main__":

    current_weather = WeatherData('London')
    print(current_weather.getTemperature())
    print(current_weather.getWeatherConditions())
    print(current_weather.getTime())
```

1.  将文件保存为`WeatherData.py`

1.  运行代码

1.  您应该在以下 shell 中看到伦敦，英格兰的天气：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/88d68f15-1946-4c56-9a03-d4549b87e934.png)

让我们来看看代码。基本上`WeatherData.py`与第四章中的`CurrentWeather.py`完全相同，但多了一个名为`getTime`的额外方法：

```py
def getTime(self):
    return time.ctime()
```

我们使用这种方法返回调用天气 Web 服务时的时间，以便在我们的网页中使用。

我们现在将使用 CherryPy 和[Bootstrap](https://getbootstrap.com)框架来创建我们的仪表板。要做到这一点，请执行以下操作：

1.  从应用程序菜单 | 编程 | Thonny Python IDE 中打开 Thonny

1.  单击新图标创建一个新文件

1.  输入以下内容（特别注意引号）：

```py
import cherrypy
from WeatherData import WeatherData

class WeatherDashboardHTML:

    def __init__(self, currentWeather):
        self.currentWeather = currentWeather

    @cherrypy.expose
    def index(self):
        return """
               <!DOCTYPE html>
                <html lang="en">

                <head>
                    <title>Weather Dashboard</title>
                    <meta charset="utf-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1">
                    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.1.0/css/bootstrap.min.css">
                    <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.3.1/jquery.min.js"></script>
                    <script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.14.0/umd/popper.min.js"></script>
                    <script src="https://maxcdn.bootstrapcdn.com/bootstrap/4.1.0/js/bootstrap.min.js"></script>
                    <style>
                        .element-box {
                            border-radius: 10px;
                            border: 2px solid #C8C8C8;
                            padding: 20px;
                        }

                        .card {
                            width: 600px;
                        }

                        .col {
                            margin: 10px;
                        }
                    </style>
                </head>

                <body>
                    <div class="container">
                        <br/>
                        <div class="card">
                            <div class="card-header">
                                <h3>Weather Conditions for """ + self.currentWeather.getCity() + """
                                </h3></div>
                             <div class="card-body">
                                <div class="row">
                                    <div class="col element-box">
                                        <h5>Temperature</h5>
                                        <p>""" + self.currentWeather.getTemperature() + """</p>
                                    </div>
                                    <div class="col element-box">
                                        <h5>Conditions</h5>
                                        <p>""" + self.currentWeather.getWeatherConditions() + """</p>
                                    </div>
                                    <div class="col element-box">
                                        <h5>Wind Speed</h5>
                                        <p>""" + self.currentWeather.getWindSpeed() + """</p>
                                    </div>
                                </div>
                            </div>
                            <div class="card-footer"><p>""" + self.currentWeather.getTime() + """</p></div>
                        </div>
                    </div>
                </body>

                </html>
               """

if __name__=="__main__":
    currentWeather = WeatherData('Paris')
    cherrypy.quickstart(WeatherDashboardHTML(currentWeather))
```

1.  将文件保存为`WeatherDashboardHTML.py`

这可能看起来是一大堆代码 - 而且确实是。不过，如果我们把它分解一下，实际上并不是那么复杂。基本上，我们使用 CherryPy 返回一个 HTML 字符串，这个字符串将通过`index`方法在我们的 URL 根目录中提供。

在我们可以这样做之前，我们通过传入一个`WeatherData`对象来实例化`WeatherDashboardHTML`类。我们给这个`WeatherData`对象起名为`currentWeather`，就像`init`（类构造函数）方法中所示的那样：

```py
def __init__(self, currentWeather):
         self.currentWeather = currentWeather
```

CherryPy 通过打印一个 HTML 字符串来提供`index`方法，该字符串中包含来自我们`currentWeather`对象的参数。我们在我们的 HTML 代码中使用了 Bootstrap 组件库。我们通过合并标准的 Bootstrap 样板代码来添加它：

```py
<link rel="stylesheet"href="https://maxcdn.bootstrapcdn.com
        /bootstrap/4.1.0/css/bootstrap.min.css">

<script src="https://ajax.googleapis.com/ajax/libs/jquery/3.3.1/jquery.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.14.0/umd/popper.min.js"></script>
<script src="https://maxcdn.bootstrapcdn.com/bootstrap/4.1.0/js/bootstrap.min.js"></script>
```

我们使用 Bootstrap 的`card`组件作为我们的内容容器。`card`允许我们创建一个标题、正文和页脚：

```py
<div class="card">
    <div class="card-header">
        .
        .
        .
```

`card`组件的标题部分显示了城市的名称。我们使用我们的`currentWeather`对象的`getCity`方法来获取城市的名称。

```py
<div class="card-header">
    <h3>Weather Conditions for """ + self.currentWeather.getCity() + """</h3>
</div>
```

在`card`组件的正文部分，我们创建了一个具有三列的行。每列包含一个标题（`<h5>`），以及从我们的`WeatherData`对象`currentWeather`中提取的数据。您可以看到标题`Temperature`，以及从`currentWeather`方法`getTemperature`中提取的温度值：

```py
<div class="card-body">
    <div class="row">
        <div class="col element-box">
            <h5>Temperature</h5>
            <p>""" + self.currentWeather.getTemperature() + """</p>
        .
        .
        .
```

对于页脚，我们只需返回`currentWeather`对象的实例化时间。我们将这个时间作为我们的程序从中检查天气信息的时间。

```py
<div class="card-footer">
    <p>""" + self.currentWeather.getTime() + """</p>
</div>
```

我们在顶部的样式部分允许我们自定义我们的仪表板的外观。我们创建了一个 CSS 类，称为`element-box`，以便在我们的天气参数周围创建一个银色（`#C8C8C8`）的圆角框。我们还限制了卡片（因此也是仪表板）的宽度为`600px`。最后，我们在列周围放置了`10px`的边距，以便圆角框不会彼此接触：

```py
<style>
    .element-box {
        border-radius: 10px;
        border: 2px solid #C8C8C8;
        padding: 20px;
    }

    .card {
        width: 600px;
    }

    .col {
        margin: 10px;
    }

</style>
```

我们在底部的`main`方法中将`WeatherData`类实例化为一个名为`currentWeather`的对象。在我们的示例中，我们使用来自`Paris`城市的数据。然后我们的代码将`currentWeather`对象传递给`cherrypy.quickstart()`方法，如下所示：

```py
if __name__=="__main__":
     currentWeather = WeatherData('Paris')
     cherrypy.quickstart(WeatherDashboardHTML(currentWeather))
```

在`WeatherDashboardHTML.py`文件上停止和启动 CherryPy 服务器。如果您的代码没有任何错误，您应该会看到类似以下的内容：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/ce7db347-f9c2-4e2b-a938-903edd69a563.png)

# 摘要

在本章中，我们使用 CherryPy HTTP 框架将我们的树莓派变成了一个 Web 服务器。凭借其简约的架构，CherryPy 允许开发者在很短的时间内建立一个支持 Web 的 Python 程序。

我们在本章开始时在树莓派上安装了 CherryPy。经过几个简单的示例后，我们通过修改和利用我们在第四章中编写的 Web 服务代码，构建了一个 HTML 天气仪表盘。

在接下来的章节中，我们将利用本章学到的知识来构建一个物联网家庭安全仪表盘。

# 问题

1.  True 或 false？它是 CherryPi，而不是 CherryPy。

1.  True 或 false？Netflix 使用 CherryPy。

1.  我们如何告诉 CherryPy 我们想要公开一个方法？

1.  True 或 false？CherryPy 需要很多样板代码。

1.  我们为什么将我们的`CurrentWeather`类重命名为`WeatherData`？

1.  True 或 false？CherryPy 使用的默认端口是`8888`。

1.  我们为什么要向我们的`col` CSS 类添加边距？

1.  我们从`WeatherData`类中使用哪个方法来获取当前天气状况的图片 URL？

1.  我们使用哪个 Bootstrap 组件作为我们的内容容器？

1.  True 或 false？在我们的示例中，伦敦是晴天和炎热的。

# 更多阅读

在本章中，我们只是浅尝了一下 CherryPy 和 Bootstrap 框架。更多阅读材料可以在 CherryPy 网站上找到，网址为[www.cherrypy.org](http://www.cherrypy.org)，以及 Bootstrap 的网站，网址为[`getbootstrap.com`](https://getbootstrap.com)。建议开发者通过阅读来提高对这些强大框架的了解。


# 第八章：使用 Python 读取树莓派 GPIO 传感器数据

在第七章中，*设置树莓派 Web 服务器*，我们使用 GPIO Zero 库来控制舵机和 LED 灯。在本章中，我们将使用 GPIO Zero 来读取 GPIO 端口的输入。首先，我们将从一个简单的按钮开始，然后转向**被动红外**（**PIR**）运动传感器和蜂鸣器。

能够从 GPIO 读取传感器数据将使我们能够构建我们的物联网家庭安全仪表板。在本章结束时，我们应该对使用连接到 GPIO 的组件编程树莓派非常熟悉。

本章将涵盖以下主题：

+   读取按钮的状态

+   从红外运动传感器读取状态

+   使用红外传感器修改`Hello LED`

# 项目概述

在本章中，我们将创建两种不同类型的报警系统。我们将首先学习如何从按钮读取 GPIO 传感器数据。然后，我们将学习如何与 PIR 传感器和距离传感器交互。最后，我们将学习如何连接一个有源蜂鸣器。

本章应该需要大约 3 小时完成。

# 入门

要完成这个项目，需要以下材料：

+   树莓派 3 型（2015 年或更新型号）

+   一个 USB 电源供应

+   一台电脑显示器

+   一个 USB 键盘

+   一个 USB 鼠标

+   一个面包板

+   跳线

+   一个 PIR 传感器

+   一个距离传感器

+   一个有源蜂鸣器

+   一个 LED

+   一个按钮（瞬时）

+   一个按钮（锁定式）

+   一个键开关（可选）

# 读取按钮的状态

`Button`，来自`GPIO Zero`库，为我们提供了一种与连接到 GPIO 的典型按钮进行交互的简单方法。本节将涵盖以下内容：

+   使用 GPIO Zero 与按钮

+   使用 Sense HAT 模拟器和 GPIO Zero 按钮

+   使用长按按钮切换 LED

# 使用 GPIO Zero 与按钮

使用 GPIO 连接按钮相对容易。以下是显示连接过程的连接图：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/d70e80e0-3c45-4b64-acf3-417770f347c0.png)

将按钮连接，使一端使用跳线连接到地。将另一端连接到树莓派上的 GPIO 4。

在 Thonny 中，创建一个新文件并将其命名为`button_press.py`。然后，输入以下内容并运行：

```py
from gpiozero import Button
from time import sleep

button = Button(4)
while True:
    if button.is_pressed:
     print("The Button on GPIO 4 has been pressed")
     sleep(1)
```

当你按下按钮时，你现在应该在壳中看到消息`“GPIO 4 上的按钮已被按下”`。代码将持续运行，直到你点击重置按钮。

让我们来看看代码。我们首先从`GPIO Zero`导入`Button`，并从`time`库导入`sleep`：

```py
from gpiozero import Button
from time import sleep
```

然后，我们创建一个新的`button`对象，并使用以下代码将其分配给 GPIO 引脚`4`：

```py
button = Button(4)
```

我们的连续循环检查按钮当前是否被按下，并在壳中打印出一条语句：

```py
while True:
    if button.is_pressed:
     print("The Button on GPIO 4 has been pressed")
     sleep(1)
```

# 使用 Sense HAT 模拟器和 GPIO Zero 按钮

我们每天都使用按钮，无论是在电梯中选择楼层还是启动汽车。现代技术使我们能够将按钮与其控制的物理设备分离。换句话说，按下按钮可以引发许多与按钮无关的事件。我们可以使用我们的按钮和 Sense HAT 模拟器来模拟这种分离。

我可以想象你们中的一些人在想分离按钮与其控制对象实际意味着什么。为了帮助你们形象化，想象一下一个控制灯的锁定式按钮。当按钮被按下时，电路闭合，电流通过按钮上的引线流动。通过使用控制器和计算机，比如树莓派，按钮所需做的就是改变它的状态。控制器或计算机接收该状态并执行与按钮本身完全分离的操作。

从 Raspbian 的编程菜单中加载 Sense HAT 模拟器。在 Thonny 中创建一个名为`sense-button.py`的新的 Python 文件。输入以下代码到文件中，然后在完成后单击运行图标：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/38d82455-991a-4e29-8de5-31d33de635a7.png)

```py
from gpiozero import Button
from sense_emu import SenseHat
from time import sleep

button = Button(4)
sense = SenseHat()

def display_x_mark(rate=1):
    sense.clear()
    X = (255,0,0)
    O = (255,255,255)
    x_mark = [
              X,O,O,O,O,O,O,X,
              O,X,O,O,O,O,X,O,
              O,O,X,O,O,X,O,O,
              O,O,O,X,X,O,O,O,
              O,O,O,X,X,O,O,O,
              O,O,X,O,O,X,O,O,
              O,X,O,O,O,O,X,O,
              X,O,O,O,O,O,O,X
    ]
    sense.set_pixels(x_mark)

while True:
    if button.is_pressed:
        display_x_mark()
        sleep(1)
    else:
        sense.clear()
```

如果您的代码没有任何错误，当您按下按钮时，您应该会看到 Sense HAT 模拟器上的显示屏变成白色背景上的红色`X`：

让我们稍微解释一下上面的代码。我们首先导入我们代码所需的库：

```py
from gpiozero import Button
from sense_emu import SenseHat
from time import sleep
```

然后我们创建新的按钮和 Sense HAT 模拟器对象。我们的`button`再次连接到 GPIO 引脚`4`：

```py
button = Button(4)
sense = SenseHat()
```

`display_x_mark`方法通过使用`SenseHat`方法`set_pixels`在显示器上创建一个`X`：

```py
def display_x_mark(rate=1):
    sense.clear()
    X = (255,0,0)
    O = (255,255,255)
    x_mark = [
              X,O,O,O,O,O,O,X,
              O,X,O,O,O,O,X,O,
              O,O,X,O,O,X,O,O,
              O,O,O,X,X,O,O,O,
              O,O,O,X,X,O,O,O,
              O,O,X,O,O,X,O,O,
              O,X,O,O,O,O,X,O,
              X,O,O,O,O,O,O,X
    ]
    sense.set_pixels(x_mark)
```

`X`和`O`变量用于保存颜色代码，`(255,0,0)`表示红色，`(255,255,255)`表示白色。变量`x_mark`创建一个与 Sense HAT 模拟器屏幕分辨率匹配的 8 x 8 图案。`x_mark`被传递到`SenseHAT`对象的`set_pixels`方法中。

我们的连续循环检查按钮的`is_pressed`状态，并在状态返回`true`时调用`display_x_mark`方法。然后该方法会在白色背景上打印一个红色的`X`。

当按钮未处于按下状态时，使用`sense.clear()`清除显示：

```py
while True:
    if button.is_pressed:
        display_x_mark()
        sleep(1)
    else:
        sense.clear()
```

# 使用长按按钮切换 LED

使用`GPIO Zero`库，我们不仅可以检测按钮何时被按下，还可以检测按下多长时间。我们将使用`hold_time`属性和`when_held`方法来确定按钮是否被按下了一段时间。如果超过了这段时间，我们将打开和关闭 LED。

以下是我们程序的电路图。将按钮连接到 GPIO 引脚 4。使用 GPIO 引脚 17 来连接 LED，如图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/e895d707-f0b5-45aa-85f4-b08962d1569d.png)

在 Thonny 中创建一个名为`buttonheld-led.py`的新文件。输入以下内容并单击运行：

```py
from gpiozero import LED
from gpiozero import Button

led = LED(17)
button = Button(4)
button.hold_time=5

while True:
    button.when_held = lambda: led.toggle()
```

按下按钮保持`5`秒。您应该会看到 LED 切换开。现在再按下`5`秒。LED 应该会切换关闭。

我们已经在之前的示例中涵盖了代码的前四行。让我们看看按钮的保持时间是如何设置的：

```py
button.hold_time=5
```

这一行将按钮的保持时间设置为`5`秒。`when_held`方法在我们的连续循环中被调用：

```py
button.when_held = lambda: led.toggle()
```

使用 lambda，我们能够创建一个匿名函数，以便我们可以在`LED`对象`led`上调用`toggle()`。这会将 LED 打开和关闭。

# 从红外运动传感器中读取状态

使用运动传感器的报警系统是我们社会中无处不在的一部分。使用我们的树莓派，它们非常容易构建。我们将在本节中涵盖以下内容：

+   什么是 PIR 传感器？

+   使用`GPIO 蜂鸣器`类

+   构建一个基本的报警系统

# 什么是 PIR 传感器？

PIR 传感器是一种运动传感器，用于检测运动。 PIR 传感器的应用主要基于为安全系统检测运动。 PIR 代表被动红外线，PIR 传感器包含一个检测低级辐射的晶体。 PIR 传感器实际上是由两半构成的，因为两半之间的差异才能检测到运动。以下是一个廉价的 PIR 传感器的照片：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/80f92423-d6d9-4649-b969-40074ac2036a.png)在上面的照片中，我们可以看到正（**+**）、负（**-**）和信号（**S**）引脚。这个特定的 PIR 传感器很适合面包板上。

以下是我们 PIR 电路的接线图。正极引脚连接到树莓派的 5V DC 输出。负极引脚连接到地（GND），信号引脚连接到 GPIO 引脚 4：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/d056ccfc-b83f-47cb-b414-f5e204570fd2.png)

在 Thonny 中创建一个名为`motion-sensor.py`的新的 Python 文件。输入以下代码并运行：

```py
from gpiozero import MotionSensor
from time import sleep

motion_sensor = MotionSensor(4)

while True:
    if motion_sensor.motion_detected:
        print('Detected Motion!')
        sleep(2)
    else:
        print('No Motion Detected!')
        sleep(2)
```

当您靠近 PIR 传感器时，您应该看到一条消息，上面写着`检测到运动！`。尝试保持静止，看看是否可以在 shell 中显示消息`未检测到运动！`。

我们的代码开始时从`GPIO Zero`库中导入`MotionSensor`类：

```py
from gpiozero import MotionSensor
```

导入`sleep`类后，我们创建一个名为`motion_sensor`的新`MotionSensor`对象，附加了数字`4`，以便让我们的程序在 GPIO 引脚 4 上寻找信号：

```py
motion_sensor = MotionSensor(4)
```

在我们的循环中，我们使用以下代码检查`motion_sensor`是否有运动：

```py
if motion_sensor.motion_detected:
```

从这里开始，我们定义要打印到 shell 的消息。

# 使用 GPIO Zero 蜂鸣器类

通常，有两种类型的电子蜂鸣器：有源和无源。有源蜂鸣器具有内部振荡器，当直流（DC）施加到它时会发出声音。无源蜂鸣器需要交流（AC）才能发出声音。无源蜂鸣器基本上是小型电磁扬声器。区分它们的最简单方法是施加直流电源并听声音。对于我们的代码目的，我们将使用有源蜂鸣器，如下图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/9cabbcd7-9a5f-476a-a961-170e92323f84.png)

`GPIO Zero`库中有一个`buzzer`类。我们将使用这个类来生成有源蜂鸣器的刺耳警报声。按照以下图表配置电路。有源蜂鸣器的正极导线连接到 GPIO 引脚 17：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/c1e46b62-c411-4348-beb9-266ae3e17aba.png)

在 Thonny 中创建一个新的 Python 文件，并将其命名为`buzzer-test1.py`。输入以下代码并运行：

```py
from gpiozero import Buzzer
from time import sleep

buzzer = Buzzer(17)

while True:
    buzzer.on()
    sleep(2)
    buzzer.off()
    sleep(2)
```

根据您选择的有源蜂鸣器，您应该听到持续两秒的刺耳声音，然后是 2 秒的静音。以下一行打开了蜂鸣器：

```py
buzzer.on()
```

同样，前面代码中的这行关闭了蜂鸣器：

```py
buzzer.off()
```

可以使用`buzzer`对象上的`toggle`方法简化代码。在 Thonny 中创建一个新的 Python 文件。将其命名为`buzzer-test2.py`。输入以下内容并运行：

```py
from gpiozero import Buzzer
from time import sleep

buzzer = Buzzer(17)

while True:
    buzzer.toggle()
    sleep(2)
```

您应该得到相同的结果。执行相同操作的第三种方法是使用`buzzer`对象的`beep`方法。在 Thonny 中创建一个新的 Python 文件。将其命名为`buzzer-test3.py`。输入以下内容并运行：

```py
from gpiozero import Buzzer

buzzer = Buzzer(17)

while True:
    buzzer.beep(2,2,10,False)
```

`buzzer`应该在`2`秒内打开，然后关闭`2`秒，重复进行`10`次。`beep`方法接受以下四个参数：

+   `on_time`：这是声音开启的秒数。默认值为`1`秒。

+   `off_time`：这是声音关闭的秒数。默认值为`1`秒。

+   `n`：这是进程运行的次数。默认值为`None`，表示永远。

+   `background`：这确定是否启动后台线程来运行进程。`True`值在后台线程中运行进程并立即返回。当设置为`False`时，直到进程完成才返回（请注意，当`n`为`None`时，该方法永远不会返回）。

# 构建一个基本的报警系统

现在让我们围绕蜂鸣器构建一个基本的报警系统。将 PIR 传感器连接到 GPIO 引脚 4，并将一个锁定按钮连接到 GPIO 引脚 8。以下是我们系统的电路图：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/2227e962-05f3-42cd-8afd-f285c678cb38.png)

在 Thonny 中创建一个新文件，并将其命名为`basic-alarm-system.py`。输入以下内容，然后点击运行：

```py
from gpiozero import MotionSensor
from gpiozero import Buzzer
from gpiozero import Button
from time import sleep

buzzer = Buzzer(17)
motion_sensor = MotionSensor(4)
switch = Button(8)

while True:
    if switch.is_pressed:
        if motion_sensor.motion_detected:
            buzzer.beep(0.5,0.5, None, True)
            print('Intruder Alert')
            sleep(1)
        else:
            buzzer.off()
            print('Quiet')
            sleep(1)
    else:
        buzzer.off()
        sleep(1)
```

我们在这里所做的是使用我们的组件创建一个报警系统。我们使用一个锁定按钮来打开和关闭报警系统。我们可以很容易地用一个钥匙开关替换锁定按钮。以下图片显示了这个变化：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/7850b80f-1614-4439-91b0-8dd9269c8ade.png)

这个电路可以很容易地转移到项目盒中，用作报警系统。

# 使用红外传感器修改 Hello LED

我们将通过修改我们最初的`Hello LED`代码来继续探索传感器。在这个项目中，我们将距离传感器与我们的 PIR 传感器相结合，并根据这些传感器的值闪烁 LED。这个电路不仅会告诉我们有人靠近，还会告诉我们他们有多近。

我们将在本节中涵盖以下内容：

+   配置距离传感器

+   将`Hello LED`提升到另一个水平

# 配置距离传感器

我们将从配置距离传感器和运行一些代码开始。以下是我们距离传感器电路的电路图：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/b0566f96-1a30-491c-97be-90aff92585be.png)

需要进行以下连接：

+   来自运动传感器的 VCC 连接到树莓派的 5V 直流输出

+   树莓派的 GPIO 引脚 17 连接到距离传感器的 Trig

+   距离传感器上的回波连接到 330 欧姆电阻

+   距离传感器上的 GND 连接到树莓派上的 GND 和一个 470 欧姆电阻

+   来自距离传感器回波引脚的 330 欧姆电阻的另一端连接到 470 欧姆电阻（这两个电阻创建了一个电压分压电路）

+   来自树莓派的 GPIO 引脚 18 连接到电阻的交叉点

在这个电路中值得注意的是由两个电阻创建的电压分压器。我们使用这个分压器连接 GPIO 引脚 18。

在 Thonny 中创建一个新的 Python 文件，并将其命名为`distance-sensor-test.py`。输入以下代码并运行：

```py
from gpiozero import DistanceSensor
from time import sleep

distance_sensor = DistanceSensor(echo=18, trigger=17)
while True:
    print('Distance: ', distance_sensor.distance*100)
    sleep(1)
```

当您将手或其他物体放在距离传感器前时，Shell 中打印的值应该会发生变化，如下所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/998c5ae2-fac9-47bf-80e5-508593e35f36.png)确保将距离传感器放在稳固的、不动的表面上，比如面包板。

# 将“Hello LED”提升到另一个水平

我们最初的“Hello LED！”系统是一个简单的电路，涉及制作一个 LED，连接到 GPIO 端口，闪烁开关。自从创建该电路以来，我们已经涵盖了更多内容。我们将利用我们所学到的知识创建一个新的`Hello LED`电路。通过这个电路，我们将创建一个报警系统，LED 的闪烁频率表示报警距离。

以下是我们新的`Hello LED`系统的电路图：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/91600d51-e1a3-4ba4-8942-ac3b62b33e2e.png)

这可能看起来有点复杂，线路到处都是；然而，这是一个非常简单的电路。距离传感器部分与以前一样。对于其他组件，连接如下：

+   PIR 传感器的正极连接到面包板上的 5V 直流电源

+   PIR 传感器的负极连接到面包板上的 GND

+   PIR 传感器的信号引脚连接到 GPIO 引脚 4

+   LED 的正极通过 220 欧姆电阻连接到 GPIO 引脚 21

+   LED 的负极连接到面包板上的 GND

在 Thonny 中创建一个新的 Python 文件，并将其命名为`hello-led.py`。输入以下代码并运行：

```py
from gpiozero import DistanceSensor
from gpiozero import MotionSensor
from gpiozero import LED
from time import sleep

distance_sensor = DistanceSensor(echo=18, trigger=17)
motion_sensor = MotionSensor(4)
led = LED(21)

while True:  
    if(motion_sensor.motion_detected):
        blink_time=distance_sensor.distance
        led.blink(blink_time,blink_time,None,True)
    sleep(2)
```

LED 应该在检测到运动后立即开始闪烁。当您将手靠近距离传感器时，LED 的闪烁频率会加快。

# 总结

现在我们应该非常熟悉与传感器和树莓派的交互。这一章应该被视为使用我们的树莓派轻松创建感官电路的练习。

我们将在第九章中使用这些知识，*构建家庭安全仪表板*，在那里我们将创建一个物联网家庭安全仪表板。

# 问题

1.  主动蜂鸣器和被动蜂鸣器有什么区别？

1.  真或假？我们检查`button.is_pressed`参数来确认我们的按钮是否被按下。

1.  真或假？我们需要一个电压分压电路才能连接我们的 PIR 传感器。

1.  我们可以使用哪三种不同的方法让我们的主动蜂鸣器发出蜂鸣声？

1.  真或假？按键必须直接连接到电路才能发挥作用。

1.  我们使用哪个`DistanceSensor`参数来检查物体与距离传感器的距离？

1.  我们使用 Sense HAT 模拟器的哪个方法来将像素打印到屏幕上？

1.  我们如何设置我们的`MotionSensor`来从 GPIO 引脚 4 读取？

1.  真或假？基本的报警系统对于我们的树莓派来说太复杂了。

1.  真或假？Sense HAT 模拟器可以用来与连接到 GPIO 的外部传感器进行交互。

# 进一步阅读

请参阅 GPIO Zero 文档[`gpiozero.readthedocs.io/en/stable/`](https://gpiozero.readthedocs.io/en/stable/)，了解如何使用这个库的更多信息。


# 第九章：构建家庭安全仪表板

在第七章中，*设置树莓派 Web 服务器*，我们介绍了 web 框架 CherryPy。使用 CherryPy，我们可以将树莓派变成一个 Web 服务器。在第八章中，*使用 Python 读取树莓派 GPIO 传感器数据*，我们学会了如何从 GPIO 读取传感器数据。

在本章中，我们将从前两章学到的经验中创建一个家庭安全仪表板。

本章将涵盖以下主题：

+   使用 CherryPy 创建我们的仪表板

+   在我们的仪表板上显示传感器数据

# 完成本章所需的知识

读者需要对 Python 编程语言有一定的了解才能完成本章。还需要基本了解 HTML，包括 CSS。

# 项目概述

在本章中，我们将构建两个不同的家庭安全仪表板。第一个将涉及使用温度和湿度传感器，下一个将涉及使用有源蜂鸣器。

这个项目应该需要几个小时才能完成。

# 入门

要完成此项目，需要以下内容：

+   树莓派 3 型（2015 年型号或更新型号）

+   一个 USB 电源适配器

+   一个计算机显示器

+   一个 USB 键盘

+   USB 鼠标

+   一个面包板

+   DHT11 温度传感器

+   一个锁存按钮、开关或键开关

+   一个 PIR 传感器

+   一个有源蜂鸣器

+   树莓派摄像头模块

# 使用 CherryPy 创建我们的仪表板

为了创建我们的家庭安全仪表板，我们将修改我们在第七章中编写的代码，*设置树莓派 Web 服务器*。这些修改包括添加来自 GPIO 的传感器数据——这是我们在第八章结束时变得非常擅长的事情，*使用 Python 读取树莓派 GPIO 传感器数据*。

两个输入，温度和湿度传感器以及树莓派摄像头，将需要额外的步骤，以便我们可以将它们整合到我们的仪表板中。

# 使用 DHT11 查找温度和湿度

DHT11 温度和湿度传感器是一种低成本的业余级传感器，能够提供基本的测量。DHT11 有两种不同的版本，四针模型和三针模型。

我们将在我们的项目中使用三针模型（请参阅以下图片）：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/05c744f6-b954-47ce-9212-2af4eecdfbac.png)

我们将使用`Adafruit DHT`库来读取 DHT11 数据，该库在 Raspbian 上没有预安装（截至撰写时）。要安装它，我们将克隆库的 GitHub 项目并从源代码构建它。

打开终端窗口，输入以下命令使用`git`并下载源代码（撰写时，`git`已预装在 Raspbian 中）：

```py
git clone https://github.com/adafruit/Adafruit_Python_DHT.git
```

您应该看到代码下载的进度。现在，使用以下命令更改目录：

```py
cd Adafruit_Python_DHT
```

您将在`源代码`目录中。

使用以下命令构建项目：

```py
sudo python3 setup.py install
```

您应该在终端中看到显示的进度：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/d072cdb7-4d9b-434e-a8ff-140ffe801ade.png)

如果您没有收到任何错误，`Adafruit DHT`库现在应该已安装在您的树莓派上。要验证这一点，打开 Thonny 并检查包：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/f7b5c282-0a2d-4cbb-88a3-08fd18a698b0.png)

现在，让我们连接电路。将 DHT11 传感器连接到树莓派如下：

+   DHT11 的 GND 连接到树莓派的 GND

+   DHT11 的 VCC 连接到树莓派的 5V DC

+   DHT11 的信号连接到 GPIO 引脚 19

有关更多信息，请参阅以下 Fritzing 图表：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/6caf4ad6-d61c-44e0-8d83-812dadc76f80.png)

一旦 DHT11 连接好，就是写一些代码的时候了：

1.  从应用程序菜单 | 编程 | Thonny Python IDE 打开 Thonny

1.  点击“新建”创建一个新文件

1.  在文件中输入以下内容：

```py
import Adafruit_DHT

dht_sensor = Adafruit_DHT.DHT11
pin = 19
humidity, temperature = Adafruit_DHT.read_retry(dht_sensor, pin)

print(humidity)
print(temperature)
```

1.  将文件保存为`dht-test.py`

1.  运行代码

1.  您应该看到类似以下的内容：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/e261501e-b9b0-4a45-a941-c1d50a855082.png)

让我们看看代码。我们将从导入`Adafruit_DHT`库开始。然后我们创建一个新的`DHT11`对象，并将其命名为`dht_sensor`。`湿度`和`温度`是从`Adafruit_DHT`类的`read_retry`方法中设置的。

然后我们在 shell 中打印出`湿度`和`温度`的值。

# 使用 Pi 相机拍照

在第三章中，*使用 GPIO 连接到外部世界*，我们尝试了特殊的树莓派相机模块，并编写了代码来打开相机预览。是时候把相机投入使用了。

通过 CSI 相机端口将树莓派相机模块安装到树莓派上（如果尚未启用，请确保在树莓派配置屏幕中启用相机）。让我们写一些代码：

1.  从应用程序菜单中打开 Thonny | 编程 | Thonny Python IDE

1.  单击“新建”以创建新文件

1.  在文件中输入以下内容：

```py
from picamera import PiCamera
from time import sleep

pi_cam = PiCamera()

pi_cam.start_preview()
sleep(5)
pi_cam.capture('/home/pi/myimage.png')
pi_cam.stop
```

1.  将文件保存为`pi-camera-test.py`

1.  运行代码

该程序导入`PiCamera`并在创建一个名为`pi_cam`的新`PiCamera`对象之前休眠。`start_preview`方法向我们显示相机在全屏中看到的内容。

捕获方法创建一个名为`myimage.png`的新图像文件，并将其存储在默认目录`/home/pi`中。

我们有 5 秒的时间来调整相机的位置，然后拍照。

以下是使用树莓派相机拍摄的我的工作区的照片：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/501926f5-b41a-4fb4-bb94-da115688f2e9.png)

# 使用 CherryPy 创建我们的仪表板

在第七章中，*设置树莓派 Web 服务器*，我们使用 Bootstrap 框架和`WeatherDashboardHTML.py`文件创建了一个天气仪表板。我们将重新访问该代码，并修改为我们的家庭安全仪表板。

要创建我们的家庭安全仪表板，请执行以下操作：

1.  从应用程序菜单中打开 Thonny | 编程 | Thonny Python IDE

1.  单击“新建”以创建新文件

1.  在文件中输入以下内容：

```py
import cherrypy
from SecurityData import SecurityData

class SecurityDashboard:

    def __init__(self, securityData):
        self.securityData = securityData

    @cherrypy.expose
    def index(self):
        return """
               <!DOCTYPE html>
                <html lang="en">

                <head>
                    <title>Home Security Dashboard</title>
                    <meta charset="utf-8">
                    <meta name="viewport"
                        content="width=device-width,
                        initial-scale=1">

                    <meta http-equiv="refresh" content="30">

                    <link rel="stylesheet"         
                        href="https://maxcdn.bootstrapcdn.com
                        /bootstrap/4.1.0/css/bootstrap.min.css">

                    <link rel="stylesheet" href="led.css">

                    <script src="https://ajax.googleapis.com
                        /ajax/libs/jquery/3.3.1/jquery.min.js">                
                    </script>

                    <script src="https://cdnjs.cloudflare.com
                        /ajax/libs/popper.js/1.14.0
                        /umd/popper.min.js">
                    </script>

                    <script src="https://maxcdn.bootstrapcdn.com
                        /bootstrap/4.1.0/js/bootstrap.min.js">
                    </script>

                    <style>
                        .element-box {
                            border-radius: 10px;
                            border: 2px solid #C8C8C8;
                            padding: 20px;
                        }

                        .card {
                            width: 600px;
                        }

                        .col {
                            margin: 10px;
                        }
                    </style>
                </head>

                <body>
                    <div class="container">
                        <br/>
                        <div class="card">
                             <div class="card-header">
                                <h3>Home Security Dashboard</h3>
                             </div>
                             <div class="card-body">
                                <div class="row">
                                    <div class="col element-box">
                                        <h6>Armed</h6>
                                        <div class = """ +     
                                            self.securityData
                                            .getArmedStatus() + 
                                        """>
                                        </div>
                                    </div>
                                    <div class="col element-box">
                                        <h6>Temp / Humidity</h6>
                                        <p>""" + self.securityData
                                            .getRoomConditions() 
                                        + """</p>
                                    </div>
                                    <div class="col element-box">
                                        <h6>Last Check:</h6>
                                        <p>""" + self
                                            .securityData.getTime() 
                                         + """</p>
                                    </div>
                                </div>
                            </div>
                            <div class="card-footer" 
                                       align="center">

                                <img src=""" + self.securityData
                                    .getSecurityImage() + """/>
                                <p>""" + self.securityData
                                    .getDetectedMessage() + """</p>
                            </div>
                        </div>
                    </div>
                </body>

                </html>
               """

if __name__=="__main__":
    securityData = SecurityData()
    conf = {
        '/led.css':{
            'tools.staticfile.on': True,
            'tools.staticfile.filename': '/home/pi/styles/led.css'
            },
        '/intruder.png':{
            'tools.staticfile.on': True,
            'tools.staticfile.filename':                            
                '/home/pi/images/intruder.png'
            },
        '/all-clear.png':{
            'tools.staticfile.on': True,
            'tools.staticfile.filename': '/home/pi/images
                /all-clear.png'
            },
        '/not-armed.png':{
            'tools.staticfile.on': True,
            'tools.staticfile.filename': '/home/pi
                /images/not-armed.png'
            }
    }
    cherrypy.quickstart(SecurityDashboard(securityData),'/',conf)
```

1.  将文件保存为`security-dashboard.py`

尚未运行代码，因为我们还需要创建`SecurityData`类。

正如您所看到的，我们对`WeatherDashboardHTML.py`进行了一些更改，以创建`security-dashboard.py`。在运行代码之前，让我们指出一些更改。

最明显的变化是使用了`SecurityData`类。可以想象，这个类将用于获取我们仪表板的数据：

```py
from SecurityData import SecurityData
```

我们使用以下行来每 30 秒自动刷新我们的页面（我们没有自动刷新我们的天气仪表板，因为天气数据不经常变化）：

```py
<meta http-equiv="refresh" content="30">
```

对于我们的家庭安全仪表板，我们使用一些 CSS 魔术来表示闪烁的 LED。这是通过添加`led.css`文件来实现的：

```py
<link rel="stylesheet" href="led.css">
```

对于数据字段，我们将从我们的`SecurityData`对象中访问方法。我们将在接下来的部分详细介绍这些方法。对于我们的主要部分，我们将创建一个名为`conf`的字典：

```py
if __name__=="__main__":
    securityData = SecurityData()
    conf = {
        '/led.css':{
            'tools.staticfile.on': True,
            'tools.staticfile.filename': '/home/pi/styles/led.css'
            },
        '/intruder.png':{
            'tools.staticfile.on': True,
            'tools.staticfile.filename':                            
                '/home/pi/images/intruder.png'
            },
        '/all-clear.png':{
            'tools.staticfile.on': True,
            'tools.staticfile.filename': '/home/pi/images
                /all-clear.png'
            },
        '/not-armed.png':{
            'tools.staticfile.on': True,
            'tools.staticfile.filename': '/home/pi
                /images/not-armed.png'
            }
    }
    cherrypy.quickstart(SecurityDashboard(securityData),'/',conf)

```

我们使用`conf`字典将配置数据传递给`cherrypy quickstart`方法。此配置数据允许我们在 CherryPy 服务器中使用静态文件`led.css`，`intruder.png`，`all-clear.png`和`not-armed.png`。

先前提到了 CSS 文件`led.css`。其他三个文件是我们仪表板中使用的自描述图像。

为了在 CherryPy 中使用静态文件或目录，您必须创建并传递配置信息。配置信息必须包含绝对路径（而不是相对路径）。

配置信息说明 CSS 和图像文件分别位于名为`styles`和`images`的目录中。这些目录都位于`/home/pi`目录中。

以下是`images`目录中文件的屏幕截图（请确保将文件放在正确的目录中）：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/54f70c24-38f3-45dd-9eee-7db79364230f.png)

# 在我们的仪表板上显示传感器数据

为了提供我们的仪表板数据，我们将创建一个名为`SecurityData.py`的新 Python 文件，我们将在其中存储`SecurityData`类。在这之前，让我们先建立我们的电路。

# 带有温度传感器的家庭安全仪表板

我们将使用 DHT11 温湿度传感器、PIR 传感器和一个 latching 按钮（或钥匙开关）来构建家庭安全仪表板的第一个版本。以下是我们家庭安全仪表板的 Fritzing 图表：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/56fe1cf8-ea5b-4089-9019-42d61ca7b0b4.png)

电路连接如下：

+   DHT11 的 GND 连接到 GND

+   DHT11 的 VCC 连接到 5V 直流电源

+   DHT11 的信号连接到 GPIO 引脚 19

+   PIR 传感器的 GND 连接到 GND

+   PIR 传感器的 VCC 连接到 5V 直流电源

+   PIR 传感器的信号连接到 GPIO 引脚 4

+   拉 atching 按钮的一端连接到 GPIO 引脚 8

+   拉 atching 按钮的另一端接地

+   树莓派摄像头模块连接到 CSI 端口（未显示）

以下是我们电路的照片。需要注意的一点是我们为 DHT11 传感器使用了单独的面包板（更容易放在微型面包板上），以及钥匙开关代替 latching 按钮：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/04677e64-df43-436f-a745-76726f0485fb.png)

现在是时候编写代码了：

1.  从应用程序菜单中打开 Thonny | 编程 | Thonny Python IDE

1.  点击“新建”创建一个新文件

1.  将以下内容输入文件：

```py
from gpiozero import MotionSensor
from gpiozero import Button
from datetime import datetime
from picamera import PiCamera
import Adafruit_DHT

class SecurityData:
    humidity=''
    temperature=''
    detected_message=''

    dht_pin = 19
    dht_sensor = Adafruit_DHT.DHT11
    switch = Button(8)
    motion_sensor = MotionSensor(4)
    pi_cam = PiCamera()

    def getRoomConditions(self):
        humidity, temperature = Adafruit_DHT
            .read_retry(self.dht_sensor, self.dht_pin)

        return str(temperature) + 'C / ' + str(humidity) + '%'

    def getDetectedMessage(self):
        return self.detected_message

    def getArmedStatus(self):
        if self.switch.is_pressed:
            return "on"
        else:
            return "off"

    def getSecurityImage(self):

        if not(self.switch.is_pressed):
            self.detected_message = ''
            return "/not-armed.png"

        elif self.motion_sensor.motion_detected:
            self.pi_cam.resolution = (500, 375)
            self.pi_cam.capture("/home/pi/images/intruder.png")
            self.detected_message = "Detected at: " + 
                self.getTime()
            return "/intruder.png"

        else:
            self.detected_message = ''
            return "/all-clear.png"

    def getTime(self):
        return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

if __name__ == "__main__":

    while True:
        security_data = SecurityData()
        print(security_data.getRoomConditions())
        print(security_data.getArmedStatus())
        print(security_data.getTime())
```

1.  将文件保存为`SecurityData.py`

1.  运行代码

您应该在 shell 中得到一个输出，指示房间中的`温度`和`湿度`水平，一个表示开关位置的`on`或`off`，以及当前时间。尝试打开和关闭开关，看看输出是否发生变化。

在运行仪表板代码（`security-dashboard.py`）之前，让我们先回顾一下`SecurityData`类。正如我们所看到的，代码的第一部分是我们已经熟悉的标准样板代码。`getRoomConditions`和`getDetectedMessage`方法要么是不言自明的，要么是我们已经讨论过的内容。

我们的`getArmedStatus`方法做了一个小技巧，以保持我们的代码简单而紧凑：

```py
def getArmedStatus(self):
    if self.switch.is_pressed:
        return "on"
    else:
        return "off"
```

我们可以看到`getArmedStatus`返回的是`on`或`off`，而不是大多数具有二进制返回的方法返回的`True`或`False`。我们这样做是为了我们仪表板代码的武装部分。

以下是`SecurityDashboard`类的`index`方法生成的 HTML 代码：

```py
<div class="col element-box">
    <h6>Armed</h6>
    <div class = """ + self.securityData.getArmedStatus() + """>
    </div>
</div>
```

正如我们所看到的，`getArmedStatus`方法在构建 div 标签时被调用，以替代 CSS 类名。单词`on`和`off`指的是我们`led.css`文件中的 CSS 类。当返回`on`时，我们得到一个闪烁的红色 LED 类型图形。当返回`off`时，我们得到一个黑点。

因此，拉 atching 开关（或钥匙开关）的位置决定了 div 标签是否具有 CSS 类名`on`或 CSS 类名`off`，通过`SecurityData`类的`getArmedStatus`方法。

我们的代码在`getSecurityImage`方法中变得非常有趣：

```py
def getSecurityImage(self):

        if not(self.switch.is_pressed):
            self.detected_message = ''
            return "/not-armed.png"

        elif self.motion_sensor.motion_detected:
            self.pi_cam.resolution = (500, 375)
            self.pi_cam.capture("/home/pi/images/intruder.png")
            self.detected_message = "Detected at: " + 
                self.getTime()
            return "/intruder.png"

        else:
            self.detected_message = ''
            return "/all-clear.png"
```

我们的第一个条件语句检查电路是否处于武装状态（开关处于`on`位置）。如果没有武装，那么我们只需要将检测到的消息设置为空，并返回对`not-armed.png`文件的引用（`/not-armed.png`在我们在`security-dashboard.py`文件中设置的配置信息中定义）。

如果我们看一下`SecurityDashboard`类（`security-dashboard.py`文件）中的代码，我们可以看到`getSecurityImage`方法在生成的 HTML 代码的底部附近被调用：

```py
<div class="card-footer" align="center">
    <img src=""" + self.securityData.getSecurityImage() + """/>
    <p>""" + self.securityData.getDetectedMessage() + """</p>
</div>
```

如果电路中的开关没有打开，我们将在仪表板页脚看到以下内容，后面没有描述（空的`detected_message`值）：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/0a3c09bd-7a1f-4de6-b4c2-b55576a6eb85.png)

我们代码中的第二个条件语句是在开关处于`on`并且检测到运动时触发的。在这种情况下，我们设置我们树莓派摄像头的分辨率，然后拍照。

我们可能在类的实例化过程中设置了树莓派摄像头的分辨率，这可能更有意义。但是，将这行放在这里使得在完成代码之前调整分辨率更容易，因为这行存在于我们关注的方法中。

我们将文件命名为`intruder.png`，并将其存储在`security-dashboard.py`文件中的配置代码可以找到的位置。

我们还根据当前时间创建了一个`detected_message`值。这条消息将为我们从树莓派摄像头获取的图像提供时间戳。

最后的`else:`语句是我们返回`/all-clear.png`的地方。到达这一点时，我们知道开关是“开启”的，并且没有检测到任何运动。我们在仪表板页脚将看到以下图像：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/681072ff-ecb3-46a7-8081-eaf54ec7bddd.png)

与`NOT ARMED`消息一样，在`ALL CLEAR`后面不会有描述。只有当开关处于“开启”状态且 PIR 传感器没有检测到任何运动（`motion_detected`为`false`）时，我们才会看到这个图形。

现在，让我们运行仪表板代码。如果您还没有这样做，请点击红色按钮停止`SecurityData`程序。点击`security-dashboard.py`文件的选项卡，然后点击运行。等待几秒钟，以便让 CherryPy 运行起来。

打开一个网络浏览器，然后导航到以下地址：

```py
http://127.0.0.1:8080
```

将开关置于“关闭”位置，您应该看到以下仪表板屏幕：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/2747d648-0f9a-443a-b1c1-6b41b37f7b57.png)

正如我们所看到的，武装部分下的 LED 是黑色的，在页脚中会得到一个`NOT ARMED`消息。我们还可以看到`temperature`和`humidity`的显示，即使系统没有武装。

最后一个复选框显示了代码上次检查开关状态的时间。如果你等待 30 秒，你应该看到页面刷新并显示相同的信息。

现在，打开开关，站在一边，这样 PIR 传感器就不会检测到你。你应该看到一个类似于以下的屏幕：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/59607798-8731-417c-a215-12ee661d22f3.png)

您会注意到武装部分的 LED 现在变成了闪烁的红色，`temperature`和`humidity`读数要么相同，要么略有不同，上次检查已更新到当前时间，并且页脚中出现了`ALL CLEAR`消息。

让我们看看是否能抓住入侵者。将树莓派摄像头对准门口，等待 PIR 传感器触发：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/d3e9d7b6-cdec-4b3d-8562-6f73a6ccaf28.png)

看来我们已经抓到了入侵者！

# 具有快速响应的家庭安全仪表板

您可能已经注意到我们的页面刷新需要很长时间。当然，这是由于 30 秒的刷新时间，以及 DHT11 读取数值所需的长时间。

让我们改变我们的代码，使其更快，并给它一个蜂鸣器来吓跑入侵者。

用连接到 GPIO 引脚 17 的蜂鸣器替换 DHT11（对于这个简单的更改，我们不需要 Fritzing 图）。

我们将首先创建`SecurityDataQuick`数据类：

1.  从应用程序菜单中打开 Thonny | 编程 | Thonny Python IDE

1.  点击“新建”以创建一个新文件

1.  在文件中键入以下内容：

```py
from gpiozero import MotionSensor
from gpiozero import Button
from datetime import datetime
from picamera import PiCamera
from gpiozero import Buzzer
from time import sleep

class SecurityData:
    alarm_status=''
    detected_message=''

    switch = Button(8)
    motion_sensor = MotionSensor(4)
    pi_cam = PiCamera()
    buzzer = Buzzer(17)

    def sound_alarm(self):
        self.buzzer.beep(0.5,0.5, 5, True)
        sleep(1)

    def getAlarmStatus(self):

        if not(self.switch.is_pressed):
            self.alarm_status = 'not-armed'
            return "Not Armed"

        elif self.motion_sensor.motion_detected:
            self.alarm_status = 'motion-detected'
            self.sound_alarm()
            return "Motion Detected"

        else:
            self.alarm_status = 'all-clear'
            return "All Clear"

    def getDetectedMessage(self):
        return self.detected_message

    def getArmedStatus(self):
        if self.switch.is_pressed:
            return "on"
        else:
            return "off"

    def getSecurityImage(self):

        if self.alarm_status=='not-armed':
            self.detected_message = ''
            return "/not-armed.png"

        elif self.alarm_status=='motion-detected':
            self.pi_cam.resolution = (500, 375)
            self.pi_cam.capture("/home/pi/images/intruder.png")

            self.detected_message = "Detected at: " + 
                self.getTime()

            return "/intruder.png"

        else:
            self.detected_message = ''
            return "/all-clear.png"

    def getTime(self):
        return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

if __name__ == "__main__":

    while True:
        security_data = SecurityData()
        print(security_data.getArmedStatus())
        print(security_data.getTime())

```

1.  将文件保存为`SecurityDataQuick.py`

1.  运行代码

在我们的 shell 中，我们应该看到开关和当前时间的值。通过点击红色按钮停止程序。

正如我们所看到的，已经发生了一些变化。我们没有做的一个变化是更改类名。将其保持为`SecurityData`意味着以后对我们的仪表板代码的更改更少。

我们添加了`GPIO Zero`蜂鸣器的库，并删除了与 DHT11 传感器相关的任何代码。我们还创建了一个名为`sound_buzzer`的新方法，当检测到入侵者时我们将调用它。

添加了一个名为`alarm_status`的新变量，以及相应的`getAlarmStatus`方法。我们将类的核心逻辑移到了这个方法中（远离`getSecurityImage`），因为在这里我们检查开关和 PIR 传感器的状态。变量`alarm_status`在其他地方用于确定是否要拍照。如果检测到入侵者，我们还会在这个方法中发出警报。

通过添加新方法，我们更改了`getSecurityImage`。通过在`getSecurityImage`方法中使用`alarm_status`，我们无需检查传感器的状态。现在我们可以将`getSecurityImage`用于其预期用途——在检测到入侵者时拍照。

现在是时候更改仪表板代码了：

1.  从应用程序菜单|编程|Thonny Python IDE 打开 Thonny

1.  单击“新建”以创建新文件

1.  在文件中输入以下内容：

```py
import cherrypy
from SecurityDataQuick import SecurityData

class SecurityDashboard:

def __init__(self, securityData):
    self.securityData = securityData

@cherrypy.expose
def index(self):
    return """
        <!DOCTYPE html>
        <html lang="en">

        <head>
            <title>Home Security Dashboard</title>
            <meta charset="utf-8">

            <meta name="viewport" content="width=device-
        width, initial-scale=1">

            <meta http-equiv="refresh" content="2">

            <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com
        /bootstrap/4.1.0/css/bootstrap.min.css">

            <link rel="stylesheet" href="led.css">

            <script src="https://ajax.googleapis.com
        /ajax/libs/jquery/3.3.1/jquery.min.js">
            </script>

            <script src="https://cdnjs.cloudflare.com
        /ajax/libs/popper.js/1.14.0
        /umd/popper.min.js">
            </script>

            <script src="https://maxcdn.bootstrapcdn.com
        /bootstrap/4.1.0/js/bootstrap.min.js">
            </script>

            <style>
                .element-box {
                    border-radius: 10px;
                    border: 2px solid #C8C8C8;
                    padding: 20px;
                }

                .card {
                    width: 600px;
                }

                .col {
                    margin: 10px;
                }
            </style>
        </head>

        <body>
            <div class="container">
                <br />
                <div class="card">
                    <div class="card-header">
                        <h3>Home Security Dashboard</h3>
                    </div>
                    <div class="card-body">
                        <div class="row">
                            <div class="col element-box">
                                <h4>Armed</h4>

                                <div class=""" + self
        .securityData
        .getArmedStatus() 
        + """>
                                </div>
                            </div>

                            <div class="col element-box">
                                <h4>Status</h4>
                                <p>""" + self.securityData
                                    .getAlarmStatus()
                                    + """</p>
                            </div>

                            <div class="col element-box">
                                <h4>Last Check:</h4>

                                <p>""" + self.securityData
                                    .getTime() + """
                                </p>
                            </div>
                        </div>
                    </div>
                    <div class="card-footer" align="center">
                        <img src=""" + self.securityData
        .getSecurityImage() + """ />
                        <p>""" + self.securityData
                            .getDetectedMessage() + """</p>
                    </div>
                </div>
            </div>
        </body>

        </html>
    """

if __name__=="__main__":
    securityData = SecurityData()
    conf = {
        '/led.css':{
        'tools.staticfile.on': True,
        'tools.staticfile.filename': '/home/pi/styles/led.css'
        },
        '/intruder.png':{
        'tools.staticfile.on': True,
        'tools.staticfile.filename': '/home/pi
        /images/intruder.png'
        },
        '/all-clear.png':{
        'tools.staticfile.on': True,
        'tools.staticfile.filename': '/home/pi
        /images/all-clear.png'
        },
        '/not-armed.png':{
        'tools.staticfile.on': True,
        'tools.staticfile.filename': '/home/pi
        /images/not-armed.png'
        }
    }
    cherrypy.quickstart(SecurityDashboard(securityData),'/',conf)

```

1.  将文件保存为`SecurityDataQuick.py`

1.  运行代码

1.  返回到您的网络浏览器并刷新仪表板页面

我们的仪表板现在应该与以下截图匹配：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/57ba904c-a2b4-411b-bff3-8947fa32c3a3.png)

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/3990c950-4f8d-47fd-a2e8-f7c7526f3164.png)

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/01356c4e-7034-4ecf-8ad8-52a1258fc0dc.png)

我们的仪表板应该每两秒刷新一次，而不是 30 秒，当处于武装模式时检测到运动时应该发出蜂鸣器声音。

让我们看看代码。我们仪表板的更改相当容易理解。但值得注意的是我们仪表板上中间框的更改：

```py
<div class="col element-box">
    <h4>Status</h4>
    <p>""" + self.securityData.getAlarmStatus() + """</p>
</div>
```

我们通过`getAlarmStatus`方法将房间的`温度`和`湿度`替换为开关和 PIR 传感器的状态。通过这种更改，我们可以使用`getAlarmStatus`方法作为我们的`初始化`方法，其中我们设置`SecurityData`类变量`alarm_status`的状态。

如果我们真的想要一丝不苟，我们可以更改我们的代码，以便使用开关和 PIR 传感器的值来初始化`SecurityData`类。目前，`SecurityData`更像是一种实用类，其中必须先调用某些方法。我们暂且放过它。

# 摘要

正如我们所看到的，使用树莓派构建安全应用程序非常容易。尽管我们正在查看我们的仪表板并在同一台树莓派上托管我们的传感器，但将树莓派设置为向网络中的其他计算机（甚至是互联网）提供仪表板并不太困难。在第十章中，*发布到 Web 服务*，我们将与

将传感器数据进一步处理并发布到互联网。

# 问题

1.  真或假？DHT11 传感器是一种昂贵且高精度的温湿度传感器。

1.  真或假？DHT11 传感器可以检测到来自太阳的紫外线。

1.  真或假？运行 DHT11 所需的代码已预装在 Raspbian 中。

1.  如何设置 Pi 摄像头模块的分辨率？

1.  如何设置 CherryPy 以便可以访问本地静态文件？

1.  如何设置网页的自动刷新？

1.  真或假？通过使用 CSS，我们可以模拟闪烁的 LED。

1.  `SecurityData`类的目的是什么？

1.  我们找到了谁或什么作为我们的入侵者？

1.  如果我们想要一丝不苟，我们将如何更改我们的`SecurityData`类？

# 进一步阅读

我们代码中使用的刷新方法很有效，但有点笨拙。我们的仪表板可以通过使用 AJAX 代码进行改进，其中字段被更新但页面不更新。请查阅 CherryPy 文档以获取更多信息。
