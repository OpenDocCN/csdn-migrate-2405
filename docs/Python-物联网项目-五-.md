# Python 物联网项目（五）

> 原文：[`zh.annas-archive.org/md5/34135f16ce1c2c69e5f81139e996b460`](https://zh.annas-archive.org/md5/34135f16ce1c2c69e5f81139e996b460)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十九章：评估

# 第一章

1.  第一款树莓派是在哪一年推出的？

A. 2012

1.  树莓派 3 Model B+相对于上一个版本有哪些升级？

A. 处理器升级到 1.4 GHz，支持 5 GHz 无线局域网，蓝牙低功耗。

1.  NOOBS 代表什么？

A. 新开箱即用软件

1.  允许使用 Python 代码创建音乐的预安装应用程序的名称是什么？

A. Sonic Pi

1.  树莓派的操作系统存储在哪里？

A. 在 microSD 卡上

1.  为儿童设计的可视化编程环境的名称是什么，它们预装在 Raspbian 中？

A. Scratch 和 Scratch 2

1.  Mathematica 中使用的语言名称是什么？

A. Wolfram

1.  Raspbian 的默认用户名和密码是什么？

A. pi / raspberry

1.  GPIO 代表什么？

A. 通用输入输出

1.  RetroPie 是什么？

A. 复古游戏模拟器

1.  真/假？单击主栏上的两个文件夹图标会加载`home`文件夹。

A. True

1.  真/假？microSD 卡槽位于树莓派底部。

A. True

1.  真/假？要关闭树莓派，从“应用程序”菜单中选择“关闭”。

A. True

1.  真/假？只能使用 NOOBS 安装 Raspbian 操作系统。

A. False

1.  真/假？低功耗蓝牙是指吃太多蓝莓并且早上很难醒来的人。

A. False

# 第二章

1.  Thonny 适用于哪些操作系统？

A. Linux（Raspbian），macOS 和 Windows

1.  我们如何从终端命令行进入 Python 2？

A. 通过输入命令`python.`

1.  Thonny 中的哪个工具用于查看对象内部的内容？

A. 对象检查器

1.  在我们的天气示例代码中，为什么要使用对象？

A. 使代码清晰并为以后使用类做准备。

1.  向`CurrentWeather`类添加名为`getCity`的方法的优点是什么？

A. 我们能够使用更通用的名称创建类。

1.  IDLE 是用什么语言编写的？

A. Python

1.  为了打印当前日期和时间，需要采取哪两个步骤？

A. 从`datetime`导入`datetime`，打印`datetime.now()`。

1.  我们如何在代码中补偿只用一个字母表示的风速方向？

A. 通过使用`if`语句设置`wind_dir_str_len`。

1.  `if __name__ =="__main__"`语句是做什么的？

A. 允许测试类。

1.  IDLE 代表什么？

A. 集成开发和学习环境

# 第三章

1.  允许您访问树莓派摄像头模块的 Python 软件包的名称是什么？

A. picamera

1.  真/假？由学生编写的代码的树莓派被部署到国际空间站上。

A. True

1.  Sense HAT 包括哪些传感器？

A. 加速计、温度传感器、磁力计、气压传感器、湿度传感器、陀螺仪。

1.  真/假？我们不需要购买树莓派 Sense HAT 进行开发，因为 Raspbian 中存在该 HAT 的模拟器。

A. True

1.  GPIO 上有多少个接地引脚？

A. 8

1.  真/假？树莓派的 GPIO 引脚提供 5V 和 3.3V。

A. True

1.  Pibrella 是什么？

A. Pibrella 是一个相对便宜的树莓派 HAT，可使连接到 GPIO 变得容易。

1.  真/假？只能在早期的树莓派计算机上使用 Pibrella。

A. False

1.  BCM 模式是什么意思？

A. 用于通过 GPIO 编号访问 GPIO 引脚。

1.  真/假？BOARD 是 BCM 的替代品。

A. True

1.  `gpiozero`中的 Zero 指的是什么？

A. 零样板或设置代码。

1.  真/假？使用 Fritzing，我们可以为树莓派设计 GPIO 电路。

A. True

1.  `gpiozero` LED `blink`函数中的默认背景参数设置为什么？

A. False

1.  真/假？使用`gpiozero`库访问 GPIO 比使用`RPi.GPIO`库更容易。

A. True

1.  维多利亚时代的互联网是什么？

A. 19 世纪的电报和跨世界电报电缆。

# 第四章

1.  IBM Watson 是什么？

A. IBM Watson 是一个能够用自然语言回答问题的系统。

1.  正确/错误？ 亚马逊的物联网网络服务允许访问亚马逊的其他基于云的服务。

A. 真

1.  正确/错误？Watson 是游戏节目 Jeopardy 的冠军。

A. 真

1.  正确/错误？谷歌拥有自己的全球私人网络。

A. 真

1.  正确/错误？当我们引入网络服务数据时，我们需要更改我们的函数名称，比如`getTemperature`。

A. 假

1.  正确/错误？在您的类中使用测试代码以隔离其功能是个好主意。

A. 真

1.  `DisplayWeather`类在我们的代码中的目的是什么？

A. 在 Sense HAT 模拟器中显示天气信息。

1.  我们使用`SenseHat`对象的哪个方法将天气信息显示到 Sense HAT 模拟器上？

A. `show_message`

# 第五章

1.  正确/错误？步进电机是使用开环反馈系统控制的。

A. 真

1.  如果您正在建造电动汽车，您会使用哪种类型的电动机？

A. 直流电机

1.  正确/错误？伺服电机被认为是步进电机的高性能替代品。

A. 真

1.  控制伺服电机的角度是什么？

A. 伺服电机的角度由传递到伺服控制引脚的脉冲决定。

1.  正确/错误？直流电机的响应时间比步进电机短。

A. 真

1.  我们使用哪个 Python 包来控制我们的伺服？

A. gpiozero

1.  正确/错误？我们能够使用 Thonny 中的 Python shell 来控制伺服。

A. 真

1.  用于将伺服移动到其最大位置的命令是什么？

A. `servo.max()`

1.  正确/错误？我们只能将伺服移动到其最小、最大和中性位置。

A. 假

1.  我们如何将百分比值转换为我们的代码中的`servo`对象理解的相应值？

A. 我们将百分比值乘以 0.02，然后减去 1。

# 第六章

1.  正确/错误？伺服可以用作物联网设备。

A. 真

1.  正确/错误？更改`Servo`对象上的最小和最大脉冲宽度值会修改伺服的范围。

A. 真

1.  为什么我们在调用`Servo`对象的`close()`方法之前添加延迟？

A. 为了延迟关闭伺服，以便在设置到位置之前不会关闭。

1.  正确/错误？我们在我们的`WeatherData`类中不需要`getTemperature()`方法。

A. 真

1.  正确/错误？我们仪表板上闪烁的 LED 表示天气晴朗。

A. 假

1.  我们在我们的仪表板上使用一对短裤来表示什么？

A. 夏季天气

1.  我们在代码中的哪里使用正则表达式？

A. 在`getLEDValue`方法中。

1.  为什么我们在代码中导入`time`？

为了延迟关闭到伺服的连接

1.  正确/错误？物联网使能的伺服只能用于指示天气数据。

A. 假

# 第七章

1.  正确/错误？这是 CherryPi 而不是 CherryPy。

A. 假

1.  正确/错误？Netflix 使用 CherryPy。

A. 真

1.  我们如何告诉 CherryPy 我们要公开一个方法？

通过使用`@cherrypy.expose`装饰器

1.  正确/错误？CherryPy 需要许多样板代码。

A. 假

1.  正确/错误？CherryPy 使用的默认端口是`8888`。

A. 假

1.  为什么我们在我们的`col` CSS 类中添加边距？

为了使圆角框不互相接触

1.  我们使用哪个 Bootstrap 组件作为我们的内容容器？

A. 卡片

1.  正确/错误？在我们的例子中，伦敦是晴天和炎热的。

A. 假

# 第八章

1.  有源蜂鸣器和无源蜂鸣器之间有什么区别？

A. 有源蜂鸣器具有内部振荡器，当直流电流（或 DC）施加在上面时会发出声音。无源蜂鸣器需要交流电流（或 AC）才能发出声音。

1.  正确/错误？我们检查`button.is_pressed`参数以确认我们的按钮是否被按下。

A. 真

1.  正确/错误？我们需要一个电压分压电路才能连接我们的 PIR 传感器。

A. 假

1.  我们可以使用哪三种不同的方法让我们的有源蜂鸣器发出哔哔声？

`buzzer.on()`和`buzzer.off()`之间有一个延迟，`buzzer.toggle()`和`buzzer.beep()`

1.  真/假？按钮必须直接连接到电路才能发挥作用。

A. 假

1.  我们使用哪个`DistanceSensor`参数来检查物体与距离传感器的距离？

A. 距离参数

1.  我们从 Sense HAT 模拟器中使用哪个方法将像素打印到屏幕上？

A. `set_pixels`方法

1.  我们如何设置我们的`MotionSensor`来从 GPIO 引脚 4 读取？

A. 将正极引脚连接到 5 伏特，负极引脚连接到 GND，信号引脚连接到 GPIO 4

1.  真/假？基本的报警系统对于我们的树莓派来说太复杂了。

A. 假

1.  真/假？Sense HAT 模拟器可以用于与连接到 GPIO 的外部传感器进行交互。

A. 真

# 第九章

1.  真/假？DHT11 传感器是一种价格昂贵且高精度的温湿度传感器？

A. 假

1.  真/假？DHT11 传感器能够检测到来自太阳的紫外线？

A. 假

1.  真/假？在 Raspbian 中预先安装了运行 DHT11 所需的代码？

A. 假

1.  如何设置 Pi 摄像头模块的分辨率？

A. 通过`PiCamera`的`resolution`属性。

1.  如何设置 CherryPy 以便可以访问本地静态文件？

A. 通过配置。

1.  如何为网页设置自动刷新？

A. `<meta http-equiv="refresh" content="30">`

1.  真/假？通过使用 CSS，我们能够模拟闪烁的 LED？

A. 真

1.  `SecurityData`类的目的是什么？

A. 提供仪表板的数据。

1.  我们找到了谁或什么作为我们的入侵者？

A. 一只狗。

1.  如果我们想要一丝不苟，我们如何改变我们的`SecurityData`类？

A. 我们将使用开关和 PIR 传感器的值初始化`SecurityData`类。

# 第十章

1.  我们用来从树莓派发送短信的服务的名称是什么？

A. Twilio

1.  真/假？我们使用 PIR 传感器来读取温度和湿度值？

A. 假

1.  如何在 ThingsBoard 中创建仪表板？

A. 你可以从设备的遥测数据创建一个仪表板

1.  真/假？我们通过使用感官仪表板来构建我们的增强安全仪表板？

A. 真

1.  我们用来读取温度和湿度传感器数据的库的名称是什么？

A. `Adafruit_DHT`

1.  真/假？我们需要发送短信的库在 Raspbian 中预先安装了吗？

A. 假

1.  在我们的代码中命名类时，我们试图做什么？

A. 根据它们代表的内容命名它们

1.  真/假？为了将我们的环境从测试更改为增强的家庭安全仪表板，我们必须重新编写整个代码？

A. 假

1.  真/假？我们的 Twilio 帐户的`account_sid`号码在测试环境和实际环境中是相同的。

A. 真

1.  我们在哪里在我们的`SecurityDashboardDist.py`代码中创建了一个`SecurityDashboardDist`对象？

A. 在`if __name__=="__main__":`部分下

# 第十一章

1.  RGB LED 与普通 LED 有何不同？

A. RGB LED 基本上是一个单元中的三个 LED（红色、绿色、蓝色）。

1.  真/假？蓝点应用程序可以在 Google Play 商店中找到。

A. 真

1.  共阳极是什么？

A. 一些 RGB LED 具有共阳极的公共正极（+），因此被称为具有共阳极

1.  真/假？RGB LED 内的三种颜色是红色、绿色和黄色。

A. 假

1.  如何将蓝点应用程序与树莓派配对？

A. 通过从蓝牙下拉菜单中使用 Make Discoverable

1.  真/假？蓝牙是一种用于极远距离的通信技术。

A. 假

1.  `DoorbellAlarm`和`DoorbellAlarmAdvanced`之间有什么区别？

类属性延迟用于更改蜂鸣器响铃之间的延迟时间。

1.  真/假？GPIO Zero 库包含一个名为`RGBLED`的类。

A. 真

1.  真/假？蓝点应用程序可用于记录滑动手势。

A. 真

1.  `SimpleDoorbell`和`SecretDoorbell`类之间有什么区别？

A. `SecretDoorbell`利用蓝点应用程序中的滑动手势。

# 第十二章

1.  蓝点应用程序如何连接到我们的树莓派？

A. 通过蓝牙。

1.  真/假？ 通过 Twilio 测试环境运行消息会创建发送到您手机的短信。

A. 假

1.  我们用来发送短信的服务的名称是什么？

A. Twilio

1.  真/假？ 我们将我们的`SecretDoorbell`类创建为`Doorbell`类的子类。

A. 真

1.  我们在第二个应用程序中使用的四个蓝点手势是什么？

A. `swipe.up`，`swipe.down`，`swipe.left`和`swipe.right`。

1.  真/假？ 为类命名使编码更容易。

A. 真

1.  `Doorbell`和`SecretDoorbell`之间有什么区别？

A. `SecretDoorbell`允许使用秘密手势，以便我们知道谁在门口。

1.  真/假？ Josephine 的铃声模式包括一个长的蜂鸣器声音。

A. 真

1.  真/假？ 您需要使用 Android 手机才能从我们的应用程序接收短信。

A. 假

1.  康斯坦斯应该如何滑动蓝点，以便我们知道她在门口？

A. 康斯坦斯应该向右滑动蓝点。

# 第十三章

1.  真/假？ T.A.R.A.S 代表技术先进的机器人更优越？

A. 假

1.  主动蜂鸣器和被动蜂鸣器之间有什么区别？

A. 主动蜂鸣器在施加直流电压时发出声音。被动蜂鸣器需要交流电压。被动蜂鸣器需要更多的编码。被动蜂鸣器更像小音箱，因此您可以控制从中发出的声音。

1.  真/假？ T.A.R.A.S 有摄像头作为眼睛？

A. 假

1.  电机驱动板的作用是什么？

A. 控制电机

1.  Adafruit 伺服 HAT 的目的是什么？

A. 用于驱动摄像头支架的舵机。

1.  打印一个轮子支架需要多长时间？

A. 30 分钟

1.  机器人脸的目的是什么？

A. 机器人上的面孔用作人类的视觉线索。

1.  真/假？ 钩带是固定电池到底盘上的好方法。

A. 真

# 第十四章

1.  真/假？ `LEDBoard`对象允许我们同时控制许多 LED。

A. 真

1.  真/假？ `RobotCamera`对象上的`notes`列表用于移动摄像头支架。

A. 假

1.  真/假？ 我们虚构故事中的对手喜欢跳舞。

A. 真

1.  `dance`和`secret_dance`方法之间有什么区别？

A. `secret_dance`拍照

1.  机器人的`gpiozero`库的名称是什么？

A. 机器人

1.  揭露犯罪的警笛启发术语是什么？

A. 吹哨人

1.  真/假？ 封装控制代码是一个毫无意义和不必要的步骤。

A. 假

1.  `TailLights`类的目的是什么？

A. 封装 LED 闪烁模式

1.  我们会使用哪个类和方法来使机器人车向右转？

A. 机器人类和`right()`方法

1.  `RobotCamera`类的目的是什么？

A. 封装头部运动和摄像头功能

# 第十五章

1.  连接 HC-SR04 到树莓派时，为什么我们使用电压分压电路？

A. 5 伏特对于我们的树莓派来说是太高的电压

1.  真/假？ T.A.R.A.S 有通过声纳看到的眼睛？

A. 真

1.  在 ThingsBoard 中，设备是什么？

它是用于在 ThingsBoard 中发布 MQTT 数据的组件

1.  真/假？ 我们的`RobotEyes`类封装了 T.A.R.A.S 上使用的树莓派摄像头模块？

A. 假

1.  方法`RobotEyes.publish_distance`的作用是什么？

A. 这些方法将距离传感器数据发送到 ThingsBoard 仪表板。

1.  真/假？ 我们需要使用 MQTT 的库与 Raspbian 预装？

A. 假

1.  为什么我们将我们的类命名为`RobotEyes`而不是`RobotDistanceSensor`？

A. 我们不需要知道眼睛是由距离传感器组成的。这使我们能够更改类的内部工作方式，而无需更改类与之交互的代码。

1.  真/假？将样板代码封装在一个类中会使代码更难处理？

A. 假

1.  真/假？GPIO Zero 库不支持距离传感器。

A. 假

1.  `RobotEyes.py`和`RobotEyesIOT.py`之间有什么区别？

A. `RobotEyesIOT`将感官信息发布到互联网，而`RobotEyes`则不会。

# 第十六章

1.  一个无人驾驶汽车需要从中央站获得什么类型的信息？

A. 交通和道路状况

1.  真/假？在 ThingsBoard 仪表板中无法更改小部件的背景颜色？

A. 假

1.  你如何改变仪表板模拟表的范围？

A. 通过在高级选项卡下将最小值更改为`0`，最大值更改为`100`

1.  真/假？从`print(data)`行返回的信息无法被人类阅读？

A. 假

1.  我们从`RobotDance`类中调用哪个方法让 T.A.R.A.S 跳舞？

A. `lets_dance_incognito`方法

1.  真/假？我们需要使用的处理`json`数据的库叫做`jason`？

A. 假

1.  我们如何在仪表板上创建一个开关？

A. 点击`RobotControl`仪表板，点击橙色的铅笔图标，点击+图标，点击创建新小部件图标，选择控制小部件，然后点击开关控制。

1.  真/假？T.A.R.A.S 上的绿色 LED 连接到 GPIO 引脚 14。

A. 假

1.  真/假？一个发布者只能有一个订阅者。

A. 假

1.  `msg`的`on_message`方法返回多少个键值对？

A. 两个

# 第十七章

1.  我们可以使用哪个程序（平台）在本地安装 MQTT Broker？

A. Mosquitto

1.  真/假？JavaScript 和 Java 是相同的技术？

A. 假

1.  真/假？我们可以使用 JavaScript 创建一个 MQTT 客户端？

A. 真

1.  我们可以使用`google-api-javascript-client`库访问哪些谷歌服务？

A. 谷歌云服务

1.  真/假？MQTT 是物联网中使用的协议？

A. 真

1.  JavaScript Node.js 技术允许你做什么？

A. 允许在浏览器之外执行 JavaScript。

1.  真/假？Python 可以用来开发 MQTT 客户端？

A. 真

1.  真/假？我们可以通过使用脚本标签在我们的网页中添加外部 JavaScript 库的功能。

A. 真

1.  我们如何在 JavaScript 代码中为我们的 MQTT 客户端设置用户名和密码？

A. 通过实例化一个`Paho.MQTT.Client`。

1.  真/假？我们可以在 Cloud MQTT 应用程序中查看我们发布的消息？

A. 真

# 第十八章

1.  我们的项目中发布控制类型消息的主题是什么？

A. `RobotControl`

1.  真/假？MQTT Broker 和 MQTT Server 是用来描述同一件事情的词语？

A. 真

1.  真/假？T.A.R.A.S 在 MQTT 相同的主题上发布和订阅？

A. 假

1.  我们的 HTML JavaScript 客户端上大的前进和后退按钮的颜色是什么？

A. 紫色

1.  真/假？使用 HTML JavaScript 客户端，我们可以远程使用 T.A.R.A.S 相机拍照？

A. 真

1.  我们用来订阅来自 T.A.R.A.S 的`distance`数据的 MQTT 主题的名称是什么？

A. `RobotEyes`

1.  真/假？我们的 HTML JavaScript 客户端包含屡获殊荣的 UI 设计？

A. 假

1.  真/假？使用我们的 CloudMQTT 帐户，我们可以查看我们实例上发布的消息？

A. 真

1.  我们用来从 T.A.R.A.S 实时传输视频的技术的名称是什么？

A. RPi-Cam-Web-Interface

1.  真/假？Johnny-Five 是可口可乐公司推出的一种新果汁饮料的名称？

A. 在撰写本文时，答案是假。
