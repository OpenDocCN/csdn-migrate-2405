# Python 物联网项目（三）

> 原文：[`zh.annas-archive.org/md5/34135f16ce1c2c69e5f81139e996b460`](https://zh.annas-archive.org/md5/34135f16ce1c2c69e5f81139e996b460)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十章：发布到 Web 服务

在物联网的核心是允许与物理设备交互的 Web 服务。在本章中，我们将探讨使用 Web 服务来显示来自树莓派的传感器数据的用途。我们还将研究 Twilio，一个短信服务，以及我们如何使用此服务从树莓派发送短信给自己。

本章将涵盖以下主题：

+   将传感器数据发布到基于云的服务

+   为文本消息传输设置账户

# 项目概述

在本章中，我们将编写代码将我们的传感器数据显示到 IoT 仪表板上。此外，我们还将探索 Twilio，一个短信服务。然后，我们将把这两个概念结合起来，以增强我们在第九章中构建的家庭安全仪表板。

# 入门

要完成此项目，需要以下内容：

+   树莓派 3 型号（2015 年或更新型号）

+   一个 USB 电源适配器

+   一个计算机显示器

+   一个 USB 键盘

+   一个 USB 鼠标

+   一个面包板

+   跳线

+   一个 DHT-11 温度传感器

+   一个 PIR 传感器

+   一个按钮（锁定）

+   一个按键开关（可选）

# 将传感器数据发布到基于云的服务

在本节中，我们将使用 MQTT 协议将传感器数据发布到在线仪表板。这将涉及在 ThingsBoard 网站上设置一个账户，并使用`demo`环境。

# 安装 MQTT 库

我们将使用 MQTT 协议与 ThingsBoard 仪表板进行通信。要在树莓派上设置库，请执行以下操作：

1.  从主工具栏打开终端设备

1.  输入`**sudo pip3 install pho-mqtt**`

1.  您应该看到库已安装

# 设置一个账户并创建一个设备

首先，转到 ThingsBoard 网站[www.thingsboard.io](http://www.thingsboard.io)：

1.  点击屏幕顶部的 TRY IT NOW 按钮。向下滚动并在 Thing Board Community Edition 部分下点击 LIVE DEMO 按钮：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/99834e79-3ac3-46de-89c3-3c7b4db4d192.png)

1.  您将看到一个注册窗口。输入适当的信息设置一个账户。一旦您的账户成功设置，您将看到一个对话框显示以下内容：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/59f38928-a10e-466c-a456-09d642cd38a3.png)

1.  点击登录进入应用程序。之后，您应该在屏幕左侧看到一个菜单：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/ec514cbb-75e8-431b-92fa-02591dd5704c.png)

1.  点击 DEVICES。在屏幕右下角，找到一个带加号的圆形橙色图形，如下所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/9d87136a-700e-4000-b7d6-183d75e5d0cc.png)

1.  点击这个橙色圆圈添加一个新设备。在添加设备对话框中，输入`Room Conditions`作为名称*，并选择默认作为设备类型*。不要选择 Is gateway。点击 ADD：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/853a76a0-1f4c-456a-9f12-433668ea6a8f.png)

1.  您应该在您的设备下看到一个新的框，名称为 Room Conditions：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/18e9ccb0-00e3-4284-b5ce-fcadb263d16e.png)

1.  点击此框，然后会从右侧滑出一个菜单。点击 COPY ACCESS TOKEN 按钮将此令牌复制到剪贴板上：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/115adb70-987e-4e89-9eb4-f79a2aadefb8.png)

我们在这里做的是设置 ThingsBoard 账户和 ThingsBoard 内的新设备。我们将使用此设备从树莓派检索传感信息，并制作这些值的仪表板。

# 读取传感器数据并发布到 ThingsBoard

现在是时候创建我们的电路和代码了。使用 GPIO 引脚 19 安装 DHT-11 传感器（如果不确定如何将 DHT-11 传感器连接到树莓派，请参考第九章，*构建家庭安全仪表板*）：

1.  打开 Thonny 并创建一个名为`dht11-mqtt.py`的新文件。在文件中输入以下内容并运行。确保粘贴从剪贴板中复制的访问令牌：

```py
from time import sleep
import Adafruit_DHT
import paho.mqtt.client as mqtt
import json

host = 'demo.thingsboard.io'
access_token = '<<access token>>'
dht_sensor = Adafruit_DHT.DHT11
pin = 19

sensor_data = {'temperature': 0, 'humidity': 0}

client = mqtt.Client()
client.username_pw_set(access_token)

while True:
 humidity, temperature = Adafruit_DHT
 .read_retry(dht_sensor, pin)

 print(u"Temperature: {:g}\u00b0C, Humidity
 {:g}%".format(temperature, humidity))

 sensor_data['temperature'] = temperature
 sensor_data['humidity'] = humidity
 client.connect(host, 1883, 20)
 client.publish('v1/devices/me/telemetry', 
 json.dumps(sensor_data), 1)
 client.disconnect()
 sleep(10)
```

1.  您应该在 shell 中看到类似以下截图的输出：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/b8f64a58-60a6-4d41-967e-0e21c3778318.png)

1.  每 10 秒应该有一个新行。正如您所看到的，房间里又热又潮。

让我们更仔细地看一下前面的代码：

1.  我们的`import`语句让我们可以访问代码所需的模块：

```py
from time import sleep
import Adafruit_DHT
import paho.mqtt.client as mqtt
import json
```

我们已经熟悉了`sleep`，`Adafruit_DHT`和`json`。`Paho MQTT`库让我们可以访问`client`对象，我们将使用它来将我们的传感器数据发布到仪表板。

1.  代码中的接下来两行用于设置`demo`服务器的 URL 和我们之前从设备检索到的访问令牌的变量。我们需要这两个值才能连接到 MQTT 服务器并发布我们的传感器数据：

```py
host = 'demo.thingsboard.io'
access_token = '<<access token>>'
```

1.  我们将`dht_sensor`变量定义为`Adafruit`库中的`DHT11`对象。我们使用传感器的引脚`19`：

```py
dht_sensor = Adafruit_DHT.DHT11
pin = 19
```

1.  然后我们定义一个`dictionary`对象来存储将发布到 MQTT 服务器的传感器数据：

```py
sensor_data = {'temperature': 0, 'humidity': 0}
```

1.  然后我们创建一个`mqtt Client`类型的`client`对象。用户名和密码使用代码中先前定义的`access_token`设置：

```py
client = mqtt.Client()
client.username_pw_set(access_token)
```

1.  连续的`while`循环包含读取传感器数据的代码，然后将其发布到 MQTT 服务器。通过从`read_retry`方法读取湿度和温度，并将相应的`sensor_data`字典值设置如下：

```py
while True:
    humidity, temperature = Adafruit_DHT
                                .read_retry(dht_sensor, pin)

    print(u"Temperature: {:g}\u00b0C, Humidity
               {:g}%".format(temperature, humidity))

    sensor_data['temperature'] = temperature
    sensor_data['humidity'] = humidity
```

1.  以下`client`代码是负责将我们的传感器数据发布到 MQTT 服务器的代码。我们使用`client`对象的`connect`方法连接，传入主机值、端口（默认端口）和`20`秒的保持活动时间。与许多 MQTT 示例不同，我们不创建循环并寻找回调，因为我们只对发布传感器值感兴趣，而不是订阅主题。在这种情况下，我们要发布的主题是`v1/devices/me/telemetry`，如 ThingsBoard 文档示例代码所示。然后我们断开与`client`的连接：

```py
client.connect(host, 1883, 20)
client.publish('v1/devices/me/telemetry', 
            json.dumps(sensor_data), 1)
client.disconnect()
sleep(10)
```

我们现在将在 ThingsBoard 中创建一个仪表板，以显示从我们的代码发送的传感器值。

# 在 ThingsBoard 中创建仪表板

以下是将湿度值添加到仪表板的步骤：

1.  返回 ThingsBoard，单击“设备”，然后单击“ROOM CONDITIONS”。侧边菜单应该从右侧滑出：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/e4a0f8a8-5fb8-457e-89a9-d6db6d79d54a.png)

1.  单击“最新遥测”选项卡。

1.  您应该看到湿度和温度的值，以及上次更新这些值的时间。通过单击左侧的复选框选择湿度。现在，单击“在小部件上显示”：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/d9de168d-ad4f-4b08-b757-c5d7553a3fd2.png)

1.  选择当前捆绑到模拟表盘，并循环浏览表盘，直到找到湿度表盘小部件。单击“添加到仪表板”按钮：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/3d991f91-b3c7-4a34-b75c-a5aebe6bd90e.png)

1.  选择创建新仪表板，并输入`Room Conditions`作为名称：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/7f4d0b0c-8d41-4ba4-8d7e-eca154a676ba.png)

1.  不要选择“打开仪表板”复选框。单击“添加”按钮。

1.  重复上述步骤以添加温度值。选择温度小部件，并将小部件添加到“Room Conditions”仪表板。这次，在单击“添加”之前选择“打开仪表板”：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/fa7423ba-e6b0-4d5c-ac23-d2d2a348952b.png)

现在，您应该看到一个仪表板，其中显示了湿度和温度值，显示在模拟表盘上。

# 与朋友分享您的仪表板

如果您想要将此仪表板公开，以便其他人可以看到它，您需要执行以下操作：

1.  通过单击“DASHBOARDS”导航到仪表板屏幕：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/5ea867db-fe5f-48e6-aacd-5f3633c598de.png)

1.  单击“使仪表板公开”选项：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/bd1baa9b-615e-4340-8ed7-212823a62971.png)

1.  您将看到对话框显示“仪表板现在是公开的”，如下截图所示。您可以复制并粘贴 URL，或通过社交媒体分享：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/10b1a040-1240-4aee-8848-b2c98cb8eb13.png)

# 设置用于文本消息传输的账户

在本节中，我们将连接到一个文本消息传输服务，并从树莓派向我们的手机发送一条短信。我们将利用这些信息以及我们迄今为止关于发布感知信息的所学知识，来创建一个增强版的安全仪表板，位于第九章，“构建家庭安全仪表板”中。

# 设置 Twilio 账户

Twilio 是一个服务，它为软件开发人员提供通过其网络服务 API 来编程创建和接收文本和电话通话的能力。让我们从设置 Twilio 账户开始：

1.  在网页浏览器中，导航至 [www.twilio.com](http://www.twilio.com)

1.  点击页面右上角的红色注册按钮

1.  输入适当的个人信息和密码，然后选择短信、到达提醒和 Python 作为密码下面的字段：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/4dda7c52-477c-4c6e-b693-bcd26b0f1239.png)

1.  提供一个电话号码，以便通过短信接收授权码，如下所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/1ce5138e-b3f3-4c70-aaee-1e3368e4aa3d.png)

1.  输入您收到的授权码，如下所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/b4d3f813-f5e9-4206-808e-2cd1f811890a.png)

1.  下一步是为您将要使用的项目命名。我们将其命名为`Doorbell`。输入名称并点击“继续”：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/85292270-6310-40e4-ade5-646e203a0415.png)

1.  我们需要一个账户的电话号码才能与其进行交互。点击获取号码：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/b9cf840a-56b8-44a5-a41d-deb6258174a9.png)

1.  将向您呈现一个号码。如果这个号码适合您，请点击“选择此号码”：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/f0c888ec-7c2f-4a32-99a1-426eac78c2fb.png)

1.  您现在已经设置好并准备使用 Twilio：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/f8fcd1de-66d3-455f-8b87-d1f37e36f7bb.png)

Twilio 是一个付费服务。您将获得一个初始金额来使用。请在创建应用程序之前检查使用此服务的成本。

# 在我们的树莓派上安装 Twilio

要从 Python 访问 Twilio，我们需要安装`twilio`库。打开终端并输入以下内容：

```py
pip3 install twilio
```

您应该在终端中看到 Twilio 安装的进度。

# 通过 Twilio 发送短信

在发送短信之前，我们需要获取凭据。在您的 Twilio 账户中，点击“设置”|“常规”，然后滚动到“API 凭据”：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/287a1ff0-1d05-4954-a6ca-33d3d1cef52a.png)

我们将使用 LIVE 凭据和 TEST 凭据的值。打开 Thonny 并创建一个名为`twilio-test.py`的新文件。在文件中输入以下代码并运行。确保粘贴 LIVE 凭据（请注意，发送短信将收取您的账户费用）：

```py
from twilio.rest import Client

account_sid = '<<your account_sid>>'
auth_token = '<<your auth_token>>'
client = Client(account_sid, auth_token)

message = client.messages.create(
                              body='Twilio says hello!',
                              from_='<<your Twilio number>>',
                              to='<<your cell phone number>>'
                          )
print(message.sid)
```

您应该会在您的手机上收到一条消息“Twilio 问候！”的短信。

# 创建一个新的家庭安全仪表板

在第九章，“构建家庭安全仪表板”中，我们使用 CherryPy 创建了一个家庭安全仪表板。物联网的强大之处在于能够构建一个连接到世界各地设备的应用程序。我们将把这个想法应用到我们的家庭安全仪表板上。如果尚未组装，请使用第九章，“构建家庭安全仪表板”中的温度传感器来构建家庭安全仪表板：

1.  我们将通过将我们的感知数据封装在一个“类”容器中来开始我们的代码。打开 Thonny 并创建一个名为`SensoryData.py`的新文件：

```py
from gpiozero import MotionSensor
import Adafruit_DHT

class SensoryData:
    humidity=''
    temperature=''
    detected_motion=''

    dht_pin = 19
    dht_sensor = Adafruit_DHT.DHT11
    motion_sensor = MotionSensor(4)

    def __init__(self):
        self.humidity, self.temperature = Adafruit_DHT
                            .read_retry(self.dht_sensor, 
                            self.dht_pin)

        self.motion_detected = self.motion_sensor.motion_detected

    def getTemperature(self):
        return self.temperature

    def getHumidity(self):
        return self.humidity

    def getMotionDetected(self):
        return self.motion_detected

if __name__ == "__main__":

    while True:
        sensory_data = SensoryData()
        print(sensory_data.getTemperature())
        print(sensory_data.getHumidity())
        print(sensory_data.getMotionDetected())

```

1.  运行程序来测试我们的传感器。这里没有我们尚未涵盖的内容。基本上我们只是在测试我们的电路和传感器。您应该在 shell 中看到感知数据的打印。 

1.  现在，让我们创建我们的感知仪表板。打开 Thonny 并创建一个名为`SensoryDashboard.py`的新文件。代码如下：

```py
import paho.mqtt.client as mqtt
import json
from SensoryData import SensoryData
from time import sleep

class SensoryDashboard:

    host = 'demo.thingsboard.io'
    access_token = '<<your access_token>>'
    client = mqtt.Client()
    client.username_pw_set(access_token)
    sensory_data = ''

    def __init__(self, sensoryData):
        self.sensoryData = sensoryData

    def publishSensoryData(self):
        sensor_data = {'temperature': 0, 'humidity': 0,
                        'Motion Detected':False}

        sensor_data['temperature'] =  self.sensoryData
                                        .getTemperature()

        sensor_data['humidity'] = self.sensoryData.getHumidity()

        sensor_data['Motion Detected'] = self.sensoryData
                                        .getMotionDetected()

        self.client.connect(self.host, 1883, 20)
        self.client.publish('v1/devices/me/telemetry',         
                                json.dumps(sensor_data), 1)
        self.client.disconnect()

        return sensor_data['Motion Detected']

if __name__=="__main__":

    while True:
        sensoryData = SensoryData()
        sensory_dashboard = SensoryDashboard(sensoryData)

        print("Motion Detected: " +             
                str(sensory_dashboard.publishSensoryData()))

        sleep(10)
```

我们在这里所做的是将以前的代码中的`dht-mqtt.py`文件封装在一个`class`容器中。我们用一个`SensoryData`对象来实例化我们的对象，以便从传感器获取数据。`publishSensoryData()`方法将感官数据发送到我们的 MQTT 仪表板。注意它如何返回运动传感器的状态？我们在主循环中使用这个返回值来打印出运动传感器的值。然而，这个返回值在我们未来的代码中会更有用。

让我们将运动传感器添加到我们的 ThingsBoard 仪表板中：

1.  在浏览器中打开 ThingsBoard

1.  点击设备菜单

1.  点击房间条件设备

1.  选择最新的遥测

1.  选择检测到的运动值

1.  点击小部件上的显示

1.  在卡片下面，找到由一个大橙色方块组成的小部件，如下所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/6cfc62b4-a7ca-4364-8662-c59f77450cb0.png)

1.  点击添加到仪表板

1.  选择现有的房间条件仪表板

1.  选中打开仪表板

1.  点击添加

您应该看到新的小部件已添加到房间条件仪表板。通过点击页面右下角的橙色铅笔图标，您可以移动和调整小部件的大小。编辑小部件，使其看起来像以下的屏幕截图：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/f83cee48-8874-4e06-92e9-86ec54584e03.png)

我们在这里所做的是重新创建第九章中的家庭安全仪表板的第一个版本，*构建家庭安全仪表板*，并采用了更加分布式的架构。我们不再依赖于我们的树莓派通过 CherryPy 网页提供感官信息。我们能够将我们的树莓派的角色减少到感官信息的来源。正如您所能想象的，使用多个树莓派来使用相同的仪表板非常容易。

通过靠近 PIR 传感器来测试这个新的仪表板。看看能否使检测到运动的小部件变为`true`。

为了使我们的新家庭安全仪表板更加分布式，让我们添加在 PIR 运动传感器激活时发送文本消息的功能。打开 Thonny 并创建一个名为`SecurityDashboardDist.py`的新文件。以下是要插入文件的代码：

```py
from twilio.rest import Client
from SensoryData import SensoryData
from SensoryDashboard import SensoryDashboard
from gpiozero import Button
from time import time, sleep

class SecurityDashboardDist:
    account_sid = ''
    auth_token = ''
    time_sent = 0
    test_env = True 
    switch = Button(8)

    def __init__(self, test_env = True):
        self.test_env = self.setEnvironment(test_env)

    def setEnvironment(self, test_env):
        if test_env:
            self.account_sid = '<<your Twilio test account_sid>>'
            self.auth_token = '<<your Twilio test auth_token>>'
            return True
        else:
            self.account_sid = '<<your Twilio live account_sid>>'
            self.auth_token = '<<your Twilio live auth_token>>'
            return False

    def update_dashboard(self, sensoryDashboard):
        self.sensoryDashboard = sensoryDashboard

        motion_detected = self
                          .sensoryDashboard
                          .publishSensoryData()

        if motion_detected:
            return self.send_alert()
        else:
            return 'Alarm not triggered'

    def send_alert(self):
        if self.switch.is_pressed:
            return self.sendTextMessage()
        else:
            return "Alarm triggered but Not Armed"

    def sendTextMessage(self):
        message_interval = round(time() - self.time_sent)

        if message_interval > 600:
            twilio_client = Client(self.account_sid, 
                                   self.auth_token)

            if self.test_env:
                message = twilio_client.messages.create(
                            body='Intruder Alert',
                            from_= '+15005550006',
                            to='<<your cell number>>'
                          )
            else:
                message = twilio_client.messages.create(
                            body='Intruder Alert',
                            from_= '<<your Twilio number>>',
                            to='<<your cell number>>'
                          )

            self.time_sent=round(time())

            return 'Alarm triggered and text message sent - ' 
                    + message.sid
        else:
             return 'Alarm triggered and text 
                    message sent less than 10 minutes ago'   

if __name__=="__main__":  
    security_dashboard = SecurityDashboardDist()

    while True:
        sensory_data = SensoryData()
        sensory_dashboard = SensoryDashboard(sensory_data)
        print(security_dashboard.update_dashboard(
                sensory_dashboard))

        sleep(5)

```

利用第九章中的家庭安全仪表板电路的第一个版本，*构建家庭安全仪表板*，这段代码使用钥匙开关来激活发送文本消息的呼叫，如果运动传感器检测到运动。当钥匙开关处于关闭位置时，每当运动传感器检测到运动时，您将收到一条消息，内容为`警报触发但未激活`。

如果还没有打开，请打开钥匙开关以激活电路。通过四处移动来激活运动传感器。您应该会收到一条通知，说明已发送了一条文本消息。消息的 SID 也应该显示出来。您可能已经注意到，您实际上并没有收到一条文本消息。这是因为代码默认为 Twilio 测试环境。在我们打开实时环境之前，让我们先看一下代码。

我们首先导入我们代码所需的库：

```py
from twilio.rest import Client
from SensoryData import SensoryData
from SensoryDashboard import SensoryDashboard
from gpiozero import Button
from time import time, sleep
```

这里没有太多我们以前没有见过的东西；然而，请注意`SensoryData`和`SensoryDashboard`的导入。由于我们已经封装了读取感官数据的代码，现在我们可以把它看作一个黑匣子。我们知道我们需要安全仪表板的感官数据，但我们不关心如何获取这些数据以及它将在哪里显示。`SensoryData`为我们提供了我们需要的感官数据，`SensoryDashboard`将其发送到某个仪表板。在我们的`SecurityDashboardDist.py`代码中，我们不必关心这些细节。

我们为我们的分布式安全仪表板创建了一个名为`SecurityDashboardDist`的类。重要的是要通过它们的名称来区分我们的类，并选择描述`class`是什么的名称。

```py
class SecurityDashboardDist:
```

在声明了一些整个类都可以访问的类变量之后，我们来到了我们的类初始化方法：

```py
    account_sid = ''
    auth_token = ''
    time_sent = 0
    test_env = True 
    switch = Button(8)

    def __init__(self, test_env = True):
        self.test_env = self.setEnvironment(test_env)
```

在`initialization`方法中，我们设置了类范围的`test_env`变量（用于`test`环境）。默认值为`True`，这意味着我们必须有意地覆盖默认值才能运行实时仪表板。我们使用`setEnvironment()`方法来设置`test_env`：

```py
def setEnvironment(self, test_env):
        if test_env:
            self.account_sid = '<<your Twilio test account_sid>>'
            self.auth_token = '<<your Twilio test auth_token>>'
            return True
        else:
            self.account_sid = '<<your Twilio live account_sid>>'
```

```py
            self.auth_token = '<<your Twilio live auth_token>>'
            return False
```

`setEnvironment()`方法根据`test_env`的值设置类范围的`account_id`和`auth_token`值，以便设置测试环境或实际环境。基本上，我们只是通过`setEnvironment()`方法传回`test_env`的状态，同时设置我们需要启用测试或实际短信环境的变量。

`update_dashboard()`方法通过传入的`SensoryDashboard`对象调用传感器和感官仪表板。这里是我们采取的面向对象方法的美妙之处，因为我们不需要关心传感器是如何读取的或仪表板是如何更新的。我们只需要传入一个`SensoryDashboard`对象就可以完成这个任务。

```py
def update_dashboard(self, sensoryDashboard):
        self.sensoryDashboard = sensoryDashboard

        motion_detected = self
                          .sensoryDashboard
                          .publishSensoryData()

        if motion_detected:
            return self.send_alert()
        else:
            return 'Alarm not triggered'
```

`update_dashboard`方法还负责确定是否发送短信，通过检查运动传感器的状态。您还记得我们在调用`SensoryDashboard`类的`publishSensoryData()`方法时返回了运动传感器的状态吗？这就是它真正方便的地方。我们可以使用这个返回值来确定是否应该发送警报。我们根本不需要在我们的类中检查运动传感器的状态，因为它可以很容易地从`SensoryDashboard`类中获得。

`send_alert()`方法检查开关的状态，以确定是否发送短信：

```py
def send_alert(self):
        if self.switch.is_pressed:
            return self.sendTextMessage()
        else:
            return "Alarm triggered but Not Armed"
```

也许你会想知道为什么我们在这里检查传感器（在这种情况下是开关）的状态，而不是从`SensoryDashboard`类中检查。答案是？我们正在通过封装传感数据仪表板来构建家庭安全仪表板。`SensorDashboard`类中不需要开关，因为它不涉及从 GPIO 到 MQTT 仪表板的传感数据的读取和传输。开关是安全系统的领域；在这种情况下是`SecurityDashboardDist`类。

`SecurityDasboardDist`类的核心是`sendTextMessage()`方法，如下所述：

```py
def sendTextMessage(self):
        message_interval = round(time() - self.time_sent)

        if message_interval > 600:
            twilio_client = Client(self.account_sid, 
                                   self.auth_token)

            if self.test_env:
                message = twilio_client.messages.create(
                            body='Intruder Alert',
                            from_= '+15005550006',
                            to='<<your cell number>>'
                          )
            else:
                message = twilio_client.messages.create(
                            body='Intruder Alert',
                            from_= '<<your Twilio number>>',
                            to='<<your cell number>>'
                          )

            self.time_sent=round(time())

            return 'Alarm triggered and text message sent - ' 
                    + message.sid
        else:
             return 'Alarm triggered and text 
                    message sent less than 10 minutes ago'   
```

我们使用`message_interval`方法变量来设置短信之间的时间间隔。我们不希望每次运动传感器检测到运动时都发送短信。在我们的情况下，短信之间的最短时间为`600`秒，或`10`分钟。

如果这是第一次，或者距离上次发送短信已经超过 10 分钟，那么代码将在测试环境或实际环境中发送短信。请注意`15005550006`电话号码在测试环境中的使用。实际环境需要您的 Twilio 号码，并且您自己的电话号码用于`to`字段。对于测试和实际环境，都会返回`触发警报并发送短信`的消息，然后是消息的 SID。不同之处在于您实际上不会收到短信（尽管代码中有调用 Twilio）。

如果距上次发送短信不到 10 分钟，则消息将显示`触发警报并发送短信不到 10 分钟`。

在我们的主函数中，我们创建了一个`SecurityDashboardDist`对象，并将其命名为`security_dashboard`。通过不传入任何内容，我们允许默认情况下设置测试环境的仪表板：

```py
if __name__=="__main__":  
    security_dashboard = SecurityDashboardDist()

    while True:
        sensory_data = SensoryData()
        sensory_dashboard = SensoryDashboard(sensory_data)
        print(security_dashboard.update_dashboard(
                sensory_dashboard))

        sleep(5)
```

随后的连续循环每 5 秒创建一个`SensoryData`和`SensoryDashboard`对象。`SensoryData`对象（`sensory_data`）用于实例化`SensoryDashboard`对象（`sensory_dashboard`），因为前者提供当前的感官数据，后者创建感官仪表板。

通过根据它们的名称命名我们的类，以及根据它们的功能命名我们的方法，代码变得相当自解释。

然后我们将这个`SensoryDashboard`对象(`sensory_dashboard`)传递给`SecurityDashboard`(`security_dashboard`)的`update_dashboard`方法。由于`update_dashboard`方法返回一个字符串，我们可以用它来打印到我们的 shell，从而看到我们的仪表板每 5 秒打印一次状态。我们将`SecurityDashboardDist`对象的实例化放在循环之外，因为我们只需要设置环境一次。

现在我们了解了代码，是时候在实际的 Twilio 环境中运行它了。请注意，当我们切换到实际环境时，代码中唯一改变的部分是实际发送短信。要将我们的仪表板变成一个实时发送短信的机器，只需将主方法的第一行更改为以下内容：

```py
security_dashboard = SecurityDashboardDist(True)
```

# 摘要

完成本章后，我们应该非常熟悉将感应数据发布到物联网仪表板。我们还应该熟悉使用 Twilio 网络服务从树莓派发送短信。

我们将在第十一章中查看蓝牙库，*使用蓝牙创建门铃按钮*，然后将这些信息和我们在本章中获得的信息结合起来，制作一个物联网门铃。

# 问题

1.  我们用来从树莓派发送短信的服务的名称是什么？

1.  真或假？我们使用 PIR 传感器来读取温度和湿度值。

1.  如何在 ThingsBoard 中创建仪表板？

1.  真或假？我们通过使用感应仪表板来构建我们的增强安全仪表板。

1.  我们用来读取温度和湿度感应数据的库的名称是什么？

1.  真或假？我们需要预先安装用于发送短信的库与 Raspbian 一起。

1.  在我们的代码中命名类时，我们试图做什么？

1.  真或假？为了将我们的环境从测试切换到实际，我们是否需要重写增强家庭安全仪表板中的整个代码。

1.  真或假？我们 Twilio 账户的`account_sid`号码在实际环境和测试环境中是相同的。

1.  在我们的`SecurityDashboardDist.py`代码中，我们在哪里创建了`SecurityDashboardDist`对象？

# 进一步阅读

为了进一步了解 Twilio 和 ThingsBoard 背后的技术，请参考以下链接：

+   Twilio 文档：[`www.twilio.com/docs/quickstart`](https://www.twilio.com/docs/quickstart)

+   ThingsBoard 的文档：

[`thingsboard.io/docs/`](https://thingsboard.io/docs/)


# 第十一章：使用蓝牙创建门铃按钮

在本章中，我们将把重点转向蓝牙。蓝牙是一种无线技术，用于在短距离内交换数据。它在 2.4 到 2.485 GHz 频段运行，通常的范围为 10 米。

在本章的项目中，我们将使用安卓上的蓝点应用程序，首先构建一个简单的蓝牙门铃，然后构建一个接受秘密滑动手势的更高级的门铃。

本章将涵盖以下主题：

+   介绍蓝点

+   RGB LED 是什么？

+   使用蓝牙和 Python 读取我们的按钮状态

# 项目概述

在本章中，我们将使用树莓派和安卓手机或平板电脑构建一个蓝牙门铃。我们将使用安卓手机或平板电脑上的一个名为蓝点的应用程序，该应用程序专为树莓派项目设计。

我们将从 RGB LED 开始，编写一个小程序来循环显示这三种颜色。然后，我们将使用 RGB LED 和有源蜂鸣器创建一个警报。我们将使用 Python 代码测试警报。

我们将编写 Python 代码来从蓝点读取按钮信息。然后，我们将结合警报和蓝点的代码来创建一个蓝牙门铃系统。

本章的项目应该需要一个上午或下午的时间来完成。

# 入门

完成此项目需要以下内容：

+   树莓派 3 型号（2015 年或更新型号）

+   USB 电源适配器

+   计算机显示器

+   USB 键盘

+   USB 鼠标

+   面包板

+   跳线线

+   330 欧姆电阻器（3 个）

+   RGB LED

+   有源蜂鸣器

+   安卓手机或平板电脑

# 介绍蓝点

蓝点是一个安卓应用程序，可在 Google Play 商店中获得。它可以作为树莓派的蓝牙遥控器。加载到您的安卓手机或平板电脑后，它基本上是一个大蓝点，您按下它就会向树莓派发送信号。以下是一个加载到平板电脑上的蓝点应用程序的图片：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/cd63e306-d53d-4de9-b93e-d4dd48adb03e.png)

它可以作为一种蓝牙操纵杆，因为根据您如何与屏幕上的点交互，位置、滑块和旋转数据可以从应用程序发送到您的树莓派。我们将通过根据蓝点的按压方式创建自定义铃声，将一些功能添加到我们的门铃应用程序中。要在安卓手机或平板电脑上安装蓝点，请访问 Google Play 商店并搜索蓝点。

# 在树莓派上安装 bluedot 库

要在树莓派上安装`bluedot`库，请执行以下操作：

1.  打开终端应用程序

1.  在终端中输入以下内容：

```py
sudo pip3 install bluedot
```

1.  按*Enter*安装库

# 将蓝点与您的树莓派配对

为了使用蓝点应用程序，您必须将其与树莓派配对。要做到这一点，请按照以下步骤操作：

1.  从树莓派桌面客户端的右上角，点击蓝牙符号：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/ea7c6ad0-ba64-4e00-a079-5f13c8a6e92f.png)

1.  如果蓝牙未打开，请点击蓝牙图标，然后选择打开蓝牙

1.  从蓝牙下拉菜单中选择“使可发现”

1.  在您的安卓手机或平板电脑上，转到蓝牙设置（这可能在手机或平板电脑上的特定操作系统上有不同的位置）

1.  您应该能够在“可用设备”列表中看到树莓派

1.  点击它以将您的设备与树莓派配对

1.  您应该在树莓派上收到一条消息，内容类似于“设备'Galaxy Tab E'请求配对。您接受请求吗？”

1.  点击“确定”接受

1.  可能会收到“连接失败”消息。我能够忽略这条消息，仍然可以让蓝点应用程序与我的树莓派配对，所以不要太担心

1.  将蓝点应用加载到您的安卓手机或平板电脑上

1.  您应该看到一个列表，其中树莓派是其中的一项

1.  点击树莓派项目以连接蓝点应用程序到树莓派

要测试我们的连接，请执行以下操作：

1.  通过以下方式打开 Thonny：应用程序菜单 | 编程 | Thonny Python IDE

1.  单击“新建”图标创建一个新文件

1.  在文件中键入以下内容：

```py
from bluedot import BlueDot
bd = BlueDot()
bd.wait_for_press()
print("Thank you for pressing the Blue Dot!")
```

1.  将文件保存为`bluest-test.py`并运行它

1.  您应该在 Thonny shell 中收到一条消息，上面写着`服务器已启动`，然后是树莓派的蓝牙地址

1.  然后您会收到一条消息，上面写着`等待连接`

1.  如果您的蓝点应用从树莓派断开连接，请通过在列表中选择树莓派项目来重新连接

1.  一旦蓝点应用连接到树莓派，您将收到消息`客户端已连接`，然后是您手机或平板电脑的蓝牙地址

1.  按下大蓝点

1.  Thonny shell 现在应该打印以下消息：`感谢您按下蓝点！`

# 接线我们的电路

我们将使用有源蜂鸣器和 RGB LED 创建一个门铃电路。由于我们之前没有讨论过 RGB LED，我们将快速看一下这个令人惊叹的小电子元件。然后，我们使用树莓派编写一个简单的测试程序，点亮 RGB LED 并发出有源蜂鸣器的声音。

# 什么是 RGB LED？

RGB LED 实际上只是一个单元内的三个 LED：一个红色，一个绿色，一个蓝色。通过在输入引脚的选择上以不同的功率电流来实现几乎可以达到任何颜色。以下是这样一个 LED 的图示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/bab49a3e-0a0e-40e3-88f5-1ac80a3ed730.png)

您可以看到有红色、绿色和蓝色引脚，还有一个负极引脚（-）。当 RGB LED 有一个负极引脚（-）时，它被称为共阴极。一些 RGB LED 有一个共阳极引脚（+），因此被称为共阳极。对于我们的电路，我们将使用一个共阴极的 RGB LED。共阴极和共阳极都有 RGB LED 的最长引脚，并且通过这个特征来识别。

# 测试我们的 RGB LED

我们现在将建立一个电路，用它我们可以测试我们的 RGB LED。以下是我们电路的接线图：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/361e3f94-6df6-439c-8bd9-633b15fd5b39.png)

要按照图中所示的电路搭建，请执行以下操作：

1.  使用面包板，将 RGB LED 插入面包板，使得共阴极插入到左边第二个插槽中

1.  将 330 欧姆电阻器连接到面包板中央间隙上的红色、绿色和蓝色引脚

1.  从 GPIO 引脚 17 连接一根母对公跳线到面包板左侧的第一个插槽

1.  从 GPIO GND 连接一根母对公跳线到 RGB LED 的阴极引脚（从左边数第二个）

1.  从 GPIO 引脚 27 连接一根母对公跳线到面包板左侧的第三个插槽

1.  从 GPIO 引脚 22 连接一根母对公跳线到面包板左侧的第四个插槽

1.  从应用程序菜单 | 编程 | Thonny Python IDE 中打开 Thonny

1.  单击“新建”图标创建一个新文件

1.  在文件中键入以下内容：

```py
from gpiozero import RGBLED
from time import sleep

led = RGBLED(red=17, green=27, blue=22)

while True:
   led.color=(1,0,0)
    sleep(2)
    led.color=(0,1,0)
    sleep(2)
    led.color=(0,0,1)
    sleep(2)
    led.off()
    sleep(2)    
```

1.  将文件保存为`RGB-LED-test.py`并运行它

您应该看到 RGB LED 在红色亮起 2 秒钟。然后 RGB LED 应该在绿色亮起 2 秒钟，然后在蓝色亮起 2 秒钟。然后它将在 2 秒钟内关闭，然后再次开始序列。

在代码中，我们首先从 GPIO Zero 库导入`RGBLED`。然后，我们通过为 RGB LED 的红色、绿色和蓝色分配引脚号来设置一个名为`led`的变量。从那里，我们只需使用`led.color`属性打开每种颜色。很容易看出，将值`1, 0, 0`分配给`led.color`属性会打开红色 LED 并关闭绿色和蓝色 LED。`led.off`方法关闭 RGB LED。

尝试尝试不同的`led.color`值。您甚至可以输入小于`1`的值来改变颜色的强度（范围是`0`到`1`之间的任何值）。如果您仔细观察，您可能能够看到 RGB LED 内部不同的 LED 灯亮起。

# 完成我们的门铃电路

现在让我们向我们的电路中添加一个有源蜂鸣器，以完成我们门铃系统的构建。以下是我们门铃电路的图表：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/f9a0218c-a5dd-465a-8d20-96247a7807d6.png)

要构建电路，请按照以下步骤进行：

1.  使用我们现有的电路，在面包板的另一端插入一个有源蜂鸣器

1.  将母对公跳线从 GPIO 引脚 26 连接到有源蜂鸣器的正引脚

1.  将母对公跳线从 GPIO GND 连接到有源蜂鸣器的负引脚

1.  从应用程序菜单中打开 Thonny |编程| Thonny Python IDE

1.  单击新图标创建新文件

1.  在文件中键入以下内容：

```py
from gpiozero import RGBLED
from gpiozero import Buzzer
from time import sleep

class DoorbellAlarm:

    led = RGBLED(red=17, green=22, blue=27)
    buzzer = Buzzer(26)
    num_of_times = 0

    def __init__(self, num_of_times):
        self.num_of_times = num_of_times

    def play_sequence(self):
        num = 0
        while num < self.num_of_times:
            self.buzzer.on()
            self.light_show()
            sleep(0.5)
            self.buzzer.off()
            sleep(0.5)
            num += 1

    def light_show(self):
        self.led.color=(1,0,0)
        sleep(0.1)
        self.led.color=(0,1,0)
        sleep(0.1)
        self.led.color=(0,0,1)
        sleep(0.1)
        self.led.off()

if __name__=="__main__":

    doorbell_alarm = DoorbellAlarm(5)
    doorbell_alarm.play_sequence()   
```

1.  将文件保存为`DoorbellAlarm.py`并运行它

1.  您应该听到蜂鸣器响了五次，并且 RGB LED 也应该按相同的次数进行灯光序列

让我们来看看代码：

1.  我们首先通过导入所需的库来开始：

```py
from gpiozero import RGBLED
from gpiozero import Buzzer
from time import sleep
```

1.  之后，我们使用`DoorbellAlarm`类名创建我们的类，然后设置初始值：

```py
led = RGBLED(red=17, green=22, blue=27)
buzzer = Buzzer(26)
num_of_times = 0
```

1.  类初始化使用`num_of_times`类变量设置警报序列将播放的次数：

```py
def __init__(self, num_of_times):
    self.num_of_times = num_of_times
```

1.  `light_show`方法只是按顺序闪烁 RGB LED 中的每种颜色，持续`0.1`秒：

```py
def light_show(self):
    self.led.color=(1,0,0)
    sleep(0.1)
    self.led.color=(0,1,0)
    sleep(0.1)
    self.led.color=(0,0,1)
    sleep(0.1)
    self.led.off()
```

1.  `play_sequence`方法打开和关闭蜂鸣器的次数设置在初始化`DoorbellAlarm`类时。每次蜂鸣器响起时，它还会运行 RGB LED `light_show`函数：

```py
def play_sequence(self):
    num = 0
    while num < self.num_of_times:
        self.buzzer.on()
        self.light_show()
        sleep(0.5)
        self.buzzer.off()
        sleep(0.5)
        num += 1
```

1.  我们通过用值`5`实例化`DoorbellAlarm`类并将其分配给`doorbell_alarm`变量来测试我们的代码。然后通过调用`play_sequence`方法来播放序列：

```py
if __name__=="__main__":

    doorbell_alarm = DoorbellAlarm(5)
    doorbell_alarm.play_sequence()   
```

# 使用蓝牙和 Python 读取我们的按钮状态

如前所述，我们能够以更多方式与 Blue Dot 应用进行交互，而不仅仅是简单的按钮按下。Blue Dot 应用可以解释用户在按钮上按下的位置，以及检测双击和滑动。在以下代码中，我们将使用 Python 从 Blue Dot 应用中读取。

# 使用 Python 读取按钮信息

做以下事情：

1.  从应用程序菜单中打开 Thonny |编程| Thonny Python IDE

1.  单击新图标创建新文件

1.  在文件中键入以下内容：

```py
from bluedot import BlueDot
from signal import pause

class BlueDotButton:

    def swiped(swipe):

        if swipe.up:
            print("Blue Dot Swiped Up")
        elif swipe.down:
            print("Blue Dot Swiped Down")
        elif swipe.left:
            print("Blue Dot Swiped Left")
        elif swipe.right:
            print("Blue Dot Swiped Right")

    def pressed(pos):
        if pos.top:
            print("Blue Dot Pressed from Top")
        elif pos.bottom:
            print("Blue Dot Pressed from Bottom")
        elif pos.left:
            print("Blue Dot Pressed from Left")
        elif pos.right:
            print("Blue Dot Pressed from Right")
        elif pos.middle:
            print("Blue Dot Pressed from Middle")

    def double_pressed():
        print("Blue Dot Double Pressed")

    blue_dot = BlueDot()
    blue_dot.when_swiped = swiped
    blue_dot.when_pressed = pressed
    blue_dot.when_double_pressed = double_pressed

 if __name__=="__main__":

    blue_dot_button = BlueDotButton()
    pause()       
```

1.  将文件保存为`BlueDotButton.py`并运行它

每次运行此程序时，您可能需要将 Blue Dot 应用连接到您的 Raspberry Pi（只需从 Blue Dot 应用中的列表中选择它）。尝试在中间，顶部，左侧等处按下 Blue Dot。您应该在 shell 中看到告诉您按下的位置的消息。现在尝试滑动和双击。shell 中的消息也应指示这些手势。

那么，我们在这里做了什么？让我们来看看代码：

1.  我们首先通过导入所需的库来开始：

```py
from bluedot import BlueDot
from signal import pause
```

我们显然需要`BlueDot`，我们还需要`pause`。我们使用`pause`来暂停程序，并等待来自 Blue Dot 应用的信号。由于我们正在使用`when_pressed`，`when_swiped`和`when_double_swiped`事件，我们需要暂停和等待（而不是其他方法，如`wait_for_press`）。我相信使用`when`而不是`wait`类型的事件使代码更清晰。

1.  在我们的程序的核心是实例化`BlueDot`对象及其相关的回调定义：

```py
blue_dot = BlueDot()
blue_dot.when_swiped = swiped
blue_dot.when_pressed = pressed
blue_dot.when_double_pressed = double_pressed
```

请注意，这些回调定义必须放在它们所引用的方法之后，否则将会出错。

1.  方法本身非常简单。以下是`swiped`方法：

```py
def swiped(swipe):

    if swipe.up:
        print("Blue Dot Swiped Up")
    elif swipe.down:
        print("Blue Dot Swiped Down")
    elif swipe.left:
        print("Blue Dot Swiped Left")
    elif swipe.right:
        print("Blue Dot Swiped Right")
```

1.  我们使用方法定义了一个名为`swipe`的变量。请注意，在方法签名中我们不必使用`self`，因为我们在方法中没有使用类变量。

# 创建蓝牙门铃

现在我们知道如何从 Blue Dot 读取按钮信息，我们可以构建一个蓝牙门铃按钮。我们将重写我们的`DoorbellAlarm`类，并使用来自 Blue Dot 的简单按钮按下来激活警报，如下所示：

1.  从应用程序菜单中打开 Thonny | 编程 | Thonny Python IDE

1.  单击新图标创建新文件

1.  在文件中键入以下内容：

```py
from gpiozero import RGBLED
from gpiozero import Buzzer
from time import sleep

class DoorbellAlarmAdvanced:

    led = RGBLED(red=17, green=22, blue=27)
    buzzer = Buzzer(26)
    num_of_times = 0
    delay = 0

    def __init__(self, num_of_times, delay):
        self.num_of_times = num_of_times
        self.delay = delay

    def play_sequence(self):
        num = 0
        while num < self.num_of_times:
            self.buzzer.on()
            self.light_show()
            sleep(self.delay)
            self.buzzer.off()
            sleep(self.delay)
            num += 1

    def light_show(self):
        self.led.color=(1,0,0)
        sleep(0.1)
        self.led.color=(0,1,0)
        sleep(0.1)
        self.led.color=(0,0,1)
        sleep(0.1)
        self.led.off()

if __name__=="__main__":

    doorbell_alarm = DoorbellAlarmAdvanced(5,1)
    doorbell_alarm.play_sequence()
```

1.  将文件保存为`DoorbellAlarmAdvanced.py`

我们的新类`DoorbellAlarmAdvanced`是`DoorbellAlarm`类的修改版本。我们所做的基本上是添加了一个我们称之为`delay`的新类属性。这个类属性将用于改变蜂鸣器响铃之间的延迟时间。正如您在代码中看到的，为了进行这一更改而修改的两个方法是`__init__`和`play_sequence`**。**

现在我们已经对我们的警报进行了更改，让我们创建一个简单的门铃程序如下：

1.  从应用程序菜单中打开 Thonny | 编程 | Thonny Python IDE

1.  单击新图标创建新文件

1.  在文件中键入以下内容：

```py
from bluedot import BlueDot
from signal import pause
from DoorbellAlarmAdvanced import DoorbellAlarmAdvanced

class SimpleDoorbell:

 def pressed():
 doorbell_alarm = DoorbellAlarmAdvanced(5, 1)
 doorbell_alarm.play_sequence()

 blue_dot = BlueDot()
 blue_dot.when_pressed = pressed

if __name__=="__main__":

 doorbell_alarm = SimpleDoorbell()
 pause()
```

1.  将文件保存为`SimpleDoorbell.py`并运行

1.  将蓝点应用程序连接到树莓派，如果尚未连接

1.  按下大蓝点

您应该听到五声持续一秒钟的响铃，每隔一秒钟响一次。您还会看到 RGB LED 经历了一个短暂的灯光秀。正如您所看到的，代码非常简单。我们导入我们的新`DoorbellAlarmAdvanced`类，然后在`pressed`方法中使用`doorbell_alarm`变量初始化类后调用`play_sequence`方法。

我们在创建`DoorbellAlarmAdvanced`类时所做的更改被用于我们的代码，以允许我们设置响铃之间的延迟时间。

# 创建一个秘密蓝牙门铃

在我们回答门铃之前知道谁在门口会不会很好？我们可以利用蓝点应用程序的滑动功能。要创建一个秘密的蓝牙门铃（秘密是我们与门铃互动的方式，而不是门铃的秘密位置），请执行以下操作：

1.  从应用程序菜单中打开 Thonny | 编程 | Thonny Python IDE

1.  单击新图标创建新文件

1.  在文件中键入以下内容：

```py
from bluedot import BlueDot
from signal import pause
from DoorbellAlarmAdvanced import DoorbellAlarmAdvanced

class SecretDoorbell:

    def swiped(swipe):

        if swipe.up:
            doorbell_alarm = DoorbellAlarmAdvanced(5, 0.5)
            doorbell_alarm.play_sequence()
        elif swipe.down:
            doorbell_alarm = DoorbellAlarmAdvanced(3, 2)
            doorbell_alarm.play_sequence()
        elif swipe.left:
            doorbell_alarm = DoorbellAlarmAdvanced(1, 5)
            doorbell_alarm.play_sequence()
        elif swipe.right:
            doorbell_alarm = DoorbellAlarmAdvanced(1, 0.5)
            doorbell_alarm.play_sequence()

    blue_dot = BlueDot()
    blue_dot.when_swiped = swiped    

if __name__=="__main__":

    doorbell = SecretDoorbell()
    pause()
```

1.  将文件保存为`SecretDoorbell.py`并运行

1.  将蓝点应用程序连接到树莓派，如果尚未连接

1.  向上滑动蓝点

您应该听到五声短促的响铃，同时看到 RGB LED 的灯光秀。尝试向下、向左和向右滑动。每次您应该得到不同的响铃序列。

那么，我们在这里做了什么？基本上，我们将回调附加到`when_swiped`事件，并通过`if`语句，创建了具有不同初始值的新`DoorbellAlarmAdvanced`对象。

通过这个项目，我们现在可以知道谁在门口，因为我们可以为不同的朋友分配各种滑动手势。

# 摘要

在本章中，我们使用树莓派和蓝点安卓应用程序创建了一个蓝牙门铃应用程序。我们首先学习了一些关于 RGB LED 的知识，然后将其与主动蜂鸣器一起用于警报电路。

通过蓝点应用程序，我们学会了如何将蓝牙按钮连接到树莓派。我们还学会了如何使用一些蓝点手势，并创建了一个具有不同响铃持续时间的门铃应用程序。

在第十二章中，*增强我们的物联网门铃*，我们将扩展我们的门铃功能，并在有人按下按钮时发送文本消息。

# 问题

1.  RGB LED 与普通 LED 有什么不同？

1.  正确还是错误？蓝点应用程序可以在 Google Play 商店中找到。

1.  什么是共阳极？

1.  正确还是错误？RGB LED 内的三种颜色是红色、绿色和黄色。

1.  如何将蓝点应用程序与树莓派配对？

1.  正确还是错误？蓝牙是一种用于极长距离的通信技术。

1.  `DoorbellAlarm`和`DoorbellAlarmAdvanced`之间有什么区别？

1.  正确还是错误？GPIO Zero 库包含一个名为`RGBLED`的类。

1.  正确还是错误？蓝点应用程序可以用于记录滑动手势。

1.  `SimpleDoorbell`和`SecretDoorbell`类之间有什么区别？

# 进一步阅读

要了解更多关于 Blue Dot Android 应用程序的信息，请访问文档页面[`bluedot.readthedocs.io`](https://bluedot.readthedocs.io)。


# 第十二章：增强我们的物联网门铃

在第十章中，我们探索了网络服务。然后在第十一章中引入了蓝牙，并使用 Android 应用蓝点和我们的树莓派构建了蓝牙门铃。

在本章中，我们将通过添加在有人敲门时发送短信的功能来增强我们的蓝牙门铃。我们将运用所学知识，并使用我们在第十章中设置的 Twilio 账户，添加短信功能。

本章将涵盖以下主题：

+   有人敲门时发送短信

+   创建一个带有短信功能的秘密门铃应用

# 项目概述

在本章的两个项目中，我们将使用第十一章中的电路，同时还将使用 Android 设备上的蓝点应用，如第十一章中所述。以下是本章中我们将创建的应用的图表：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/48881639-1b37-4934-880b-12c34b044a47.png)

我们将创建这个应用的两个版本。我们的应用的第一个版本将是一个简单的蓝牙门铃，按下蓝点会触发蜂鸣器和 RGB LED 灯光秀。警报触发后，将使用 Twilio 云服务发送一条短信。

应用程序的修改版本将使用蓝点应用上的滑动手势来指示特定的访客。四位潜在的访客将各自拥有自己独特的蓝点滑动手势。在自定义蜂鸣器响铃和 RGB LED 灯光秀之后，将发送一条文本消息通知收件人门口有谁。Twilio 云也将用于此功能。

这两个项目应该需要一个上午或一个下午的时间来完成。

# 入门

完成此项目需要以下步骤：

+   树莓派 3 型（2015 年或更新型号）

+   USB 电源适配器

+   计算机显示器

+   USB 键盘

+   USB 鼠标

+   面包板

+   跳线线

+   330 欧姆电阻（3 个）

+   RGB LED

+   有源蜂鸣器

+   Android 设备（手机/平板）

# 有人敲门时发送短信

在第十章中，我们使用了一种叫做 Twilio 的技术来创建文本消息。在那个例子中，我们使用 Twilio 在检测到入侵者时发送文本消息。在第十一章中，我们使用了 Android 手机或平板上的蓝点应用创建了一个蓝牙门铃。门铃响起蜂鸣器，并在 RGB LED 上进行了一些灯光秀。

对于这个项目，我们将结合 Twilio 和蓝牙门铃，当有人按下蓝点门铃时，将发送一条短信（参考第十章和第十一章，熟悉这些技术）。

# 创建一个带有短信功能的简单门铃应用

要创建我们的简单门铃应用，请执行以下操作：

1.  从应用程序菜单 | 编程 | Thonny Python IDE 中打开 Thonny

1.  点击“新建”图标创建一个新文件

1.  输入以下内容：

```py
from twilio.rest import Client
from gpiozero import RGBLED
from gpiozero import Buzzer
from bluedot import BlueDot
from signal import pause
from time import sleep

class Doorbell:
    account_sid = ''
    auth_token = ''
    from_phonenumber=''
    test_env = True
    led = RGBLED(red=17, green=22, blue=27)
    buzzer = Buzzer(26)
    num_of_rings = 0
    ring_delay = 0
    msg = ''

    def __init__(self, 
                 num_of_rings = 1, 
                 ring_delay = 1, 
                 message = 'ring', 
                 test_env = True):
        self.num_of_rings = num_of_rings
        self.ring_delay = ring_delay
        self.message = message
        self.test_env = self.setEnvironment(test_env)

    def setEnvironment(self, test_env):
        if test_env:
            self.account_sid = '<<test account_sid>>'
            self.auth_token = '<<test auth_token>>'
            return True
        else:
            self.account_sid = '<<live account_sid>>'
            self.auth_token = '<<live auth_token>>'
            return False

    def doorbell_sequence(self):
        num = 0
        while num < self.num_of_rings:
            self.buzzer.on()
            self.light_show()
            sleep(self.ring_delay)
            self.buzzer.off()
            sleep(self.ring_delay)
            num += 1
        return self.sendTextMessage()

    def sendTextMessage(self):
        twilio_client = Client(self.account_sid, self.auth_token)
        if self.test_env:
            message = twilio_client.messages.create(
                        body=self.message,
                        from_= '+15005550006',
                        to='<<your phone number>>'
            )
        else:
            message = twilio_client.messages.create(
                        body=self.message,
                        from_= '<<your twilio number>>',
                        to='<<your phone number>>'
            ) 
        return 'Doorbell text message sent - ' + message.sid

    def light_show(self):
        self.led.color=(1,0,0)
        sleep(0.5)
        self.led.color=(0,1,0)
        sleep(0.5)
        self.led.color=(0,0,1)
        sleep(0.5)
        self.led.off()

def pressed():
    doorbell = Doorbell(2, 0.5, 'There is someone at the door')
    print(doorbell.doorbell_sequence())

blue_dot = BlueDot()
blue_dot.when_pressed = pressed

if __name__=="__main__":
    pause()

```

1.  将文件保存为`Doorbell.py`并运行

1.  在您的 Android 设备上打开蓝点应用

1.  连接到树莓派

1.  按下大蓝点

你应该听到铃声并看到灯光序列循环两次，两次之间有短暂的延迟。你应该在 shell 中得到类似以下的输出：

```py
Server started B8:27:EB:12:77:4F
Waiting for connection
Client connected F4:0E:22:EB:31:CA
Doorbell text message sent - SM5cf1125acad44016840a6b76f99b3624
```

前三行表示 Blue Dot 应用程序已通过我们的 Python 程序连接到我们的 Raspberry Pi。最后一行表示已发送了一条短信。由于我们使用的是测试环境，实际上没有发送短信，但是调用了 Twilio 服务。

让我们来看看代码。我们首先定义了我们的类，并给它命名为`Doorbell`。这是我们类的一个很好的名字，因为我们已经编写了我们的代码，使得一切与门铃有关的东西都包含在`Doorbell.py`文件中。这个文件包含了`Doorbell`类，用于提醒用户，以及 Blue Dot 代码，用于触发门铃。Blue Dot 代码实际上位于`Doorbell`类定义之外，因为我们认为它是 Blue Dot 应用的一部分，而不是门铃本身。我们当然可以设计我们的代码，使得`Doorbell`类包含触发警报的代码；然而，将警报与警报触发器分开使得在将来更容易重用`Doorbell`类作为警报机制。

选择类名可能有些棘手。然而，选择正确的类名非常重要，因为使用适合其预期用途的类名将更容易构建应用程序。类名通常是名词，类中的方法是动词。通常，最好让一个类代表一件事或一个想法。例如，我们将我们的类命名为`Doorbell`，因为我们已经设计它来封装门铃的功能：提醒用户有人在门口。考虑到这个想法，`Doorbell`类包含点亮 LED、发出蜂鸣器声音和发送短信的代码是有意义的，因为这三个动作都属于提醒用户的想法。

在我们定义了我们的类之后，我们创建了以下用于我们类的类变量：

```py
class Doorbell:
    account_sid = ''
    auth_token = ''
    from_phonenumber=''
    test_env = True
    led = RGBLED(red=17, green=22, blue=27)
    buzzer = Buzzer(26)
    num_of_rings = 0
    ring_delay = 0
    msg = ''
```

`init`和`setEnvironment`方法设置了我们在类中使用的变量。`test_env`变量确定我们在代码中使用 Twilio 测试环境还是实时环境。测试环境是默认使用的：

```py
def __init__(self, 
             num_of_rings = 1, 
             ring_delay = 1, 
             message = 'ring', 
             test_env = True):
     self.num_of_rings = num_of_rings
     self.ring_delay = ring_delay
     self.message = message
     self.test_env = self.setEnvironment(test_env)

 def setEnvironment(self, test_env):
     if test_env:
         self.account_sid = '<<test account sid>>'
         self.auth_token = '<<test auth token>>'
         return True
     else:
         self.account_sid = '<<live account sid>>'
         self.auth_token = '<<auth_token>>'
         return False
```

`doorbell_sequence`、`sendTextMessage`和`light_show`方法与本书先前介绍的方法类似。通过这三种方法，我们通知用户有人在门口。这里需要注意的是从`sendTextMessage`方法发送的返回值：`return 'Doorbell text message sent - ' + message.sid`。通过在代码中加入这一行，我们能够使用`sendTextMessage`方法在我们的 shell 中提供一个打印确认，即已发送了一条短信。

如前所述，我们的代码中的 Blue Dot 部分位于类定义之外：

```py
def pressed():
    doorbell = Doorbell(2, 0.5, 'There is someone at the door')
    print(doorbell.doorbell_sequence())

blue_dot = BlueDot()
blue_dot.when_pressed = pressed
```

前面的代码是我们以前见过的。我们定义了`pressed`方法，在这里我们实例化了一个新的`doorbell`对象，然后调用了`doorbell`的`doorbell_sequence`方法。`blue_dot`变量是一个`BlueDot`对象，我们只关心`when_pressed`事件。

这里需要注意的是包含`doorbell = Doorbell(2, 0.5, 'There is someone at the door')`语句的那一行。在这一行中，我们实例化了一个`Doorbell`对象，我们称之为`doorbell`，`num_of_rings`等于`2`；`ring_delay`（或持续时间）等于`0.5`；消息等于`门口有人`。我们没有传递`test_env`环境值。因此，默认设置为`True`，用于设置我们的`doorbell`对象使用 Twilio 测试环境，不发送短信。要更改为发送短信，将语句更改为：

```py
doorbell = Doorbell(2, 0.5, 'There is someone at the door', False)
```

确保您相应地设置了 Twilio 帐户参数。您应该收到一条短信，告诉您有人在门口。以下是我在 iPhone 上收到的消息：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/1d69e13e-94fe-4952-8dc1-998cca3258f9.png)

# 创建一个带有短信功能的秘密门铃应用程序

现在我们有能力在安卓设备上的大蓝色按钮被按下时发送文本消息，让我们把它变得更加复杂一些。我们将修改我们在第十一章中创建的`SecretDoorbell`类，*使用蓝牙创建门铃按钮*，并赋予它发送文本消息告诉我们谁在门口的能力。就像之前一样，我们将把所有的代码放在一个文件中以保持紧凑：

1.  从应用程序菜单中打开 Thonny | 编程 | Thonny Python IDE

1.  点击新建图标创建一个新文件

1.  输入以下内容：

```py
from twilio.rest import Client
from gpiozero import RGBLED
from gpiozero import Buzzer
from bluedot import BlueDot
from signal import pause
from time import sleep

class Doorbell:
    account_sid = ''
    auth_token = ''
    from_phonenumber=''
    test_env = True
    led = RGBLED(red=17, green=22, blue=27)
    buzzer = Buzzer(26)
    num_of_rings = 0
    ring_delay = 0
    msg = ''

    def __init__(self, 
                 num_of_rings = 1, 
                 ring_delay = 1, 
                 message = 'ring', 
                 test_env = True):
        self.num_of_rings = num_of_rings
        self.ring_delay = ring_delay
        self.message = message
        self.test_env = self.setEnvironment(test_env)

    def setEnvironment(self, test_env):
        if test_env:
            self.account_sid = '<<test account_sid>>'
            self.auth_token = '<<test auth_token>>'
            return True
        else:
            self.account_sid = '<<live account_sid>>'
            self.auth_token = '<<live auth_token>>'
            return False

    def doorbell_sequence(self):
        num = 0
        while num < self.num_of_rings:
            self.buzzer.on()
            self.light_show()
            sleep(self.ring_delay)
            self.buzzer.off()
            sleep(self.ring_delay)
            num += 1
        return self.sendTextMessage()

    def sendTextMessage(self):
        twilio_client = Client(self.account_sid, self.auth_token)
        if self.test_env:
            message = twilio_client.messages.create(
                        body=self.message,
                        from_= '+15005550006',
                        to='<<your phone number>>'
            )
        else:
            message = twilio_client.messages.create(
                        body=self.message,
                        from_= '<<your twilio number>>',
                        to='<<your phone number>>'
            ) 
        return 'Doorbell text message sent - ' + message.sid

    def light_show(self):
        self.led.color=(1,0,0)
        sleep(0.5)
        self.led.color=(0,1,0)
        sleep(0.5)
        self.led.color=(0,0,1)
        sleep(0.5)
        self.led.off()

class SecretDoorbell(Doorbell):
    names=[['Bob', 4, 0.5], 
           ['Josephine', 1, 3], 
           ['Ares', 6, 0.2], 
           ['Constance', 2, 1]]
    message = ' is at the door!'

    def __init__(self, person_num, test_env = True):
        Doorbell.__init__(self,
                          self.names[person_num][1],
                          self.names[person_num][2],
                          self.names[person_num][0] + self.message,
                          test_env)

def swiped(swipe):
    if swipe.up:
        doorbell = SecretDoorbell(0)
        print(doorbell.doorbell_sequence())
    elif swipe.down:
        doorbell = SecretDoorbell(1)
        print(doorbell.doorbell_sequence())
    elif swipe.left:
        doorbell = SecretDoorbell(2)
        print(doorbell.doorbell_sequence())
    elif swipe.right:
        doorbell = SecretDoorbell(3)
        print(doorbell.doorbell_sequence())

blue_dot = BlueDot()
blue_dot.when_swiped = swiped

if __name__=="__main__":
    pause()
```

1.  将文件保存为`SecretDoorbell.py`并运行它

1.  在您的安卓设备上打开蓝点应用

1.  连接到树莓派

1.  从顶部位置向下滑动蓝点

1.  您应该听到蜂鸣器响一次，大约持续三秒钟，并且看到 RGB LED 进行一次灯光表演。在 shell 底部将显示类似以下内容：

```py
Server started B8:27:EB:12:77:4F
Waiting for connection
Client connected F4:0E:22:EB:31:CA
Doorbell text message sent - SM62680586b32a42bdacaff4200e0fed78
```

1.  和之前的项目一样，我们将会收到一条文本消息已发送的消息，但实际上我们不会收到文本消息，因为我们处于 Twilio 测试环境中

在让我们的应用程序根据他们的滑动给我们发送一条告诉我们门口有谁的短信之前，让我们看一下代码。

我们的`SecretDoorbell.py`文件与我们的`Doorbell.py`文件完全相同，除了以下代码：

```py
class SecretDoorbell(Doorbell):
    names=[['Bob', 4, 0.5], 
           ['Josephine', 1, 3], 
           ['Ares', 6, 0.2], 
           ['Constance', 2, 1]]
    message = ' is at the door!'

    def __init__(self, person_num, test_env = True):
        Doorbell.__init__(self,
                          self.names[person_num][1],
                          self.names[person_num][2],
                          self.names[person_num][0] + self.message,
                          test_env)

def swiped(swipe):
    if swipe.up:
        doorbell = SecretDoorbell(0)
        print(doorbell.doorbell_sequence())
    elif swipe.down:
        doorbell = SecretDoorbell(1)
        print(doorbell.doorbell_sequence())
    elif swipe.left:
        doorbell = SecretDoorbell(2)
        print(doorbell.doorbell_sequence())
    elif swipe.right:
        doorbell = SecretDoorbell(3)
        print(doorbell.doorbell_sequence())

blue_dot = BlueDot()
blue_dot.when_swiped = swiped
```

`SecretDoorbell`类被创建为`Doorbell`的子类，从而继承了`Doorbell`的方法。我们创建的`names`数组存储了数组中的名称和与名称相关的铃声属性。例如，第一个元素的名称是`Bob`，`num_of_rings`值为`4`，`ring_delay`（持续时间）值为`0.5`。当这条记录在 Twilio 实时环境中使用时，您应该听到蜂鸣器响四次，并看到 RGB LED 灯光表演循环，之间有短暂的延迟。`SecretDoorbell`的`init`方法收集`person_num`（或者基本上是`names`数组中的位置信息），并用它来实例化`Doorbell`父类。`test_env`值默认为`True`，这意味着我们只能通过明确覆盖这个值来打开 Twilio 实时环境。这样可以防止我们在准备好部署应用程序之前意外使用完 Twilio 账户余额。

我们文件中的蓝点代码位于`SecretDoorbell`类定义之外。和之前的项目一样，这样做可以让我们将门铃功能与门铃触发器（我们安卓设备上的蓝点应用）分开。

在我们的蓝点代码中，我们实例化一个名为`blue_dot`的`BlueDot`对象，然后将`when_swiped`事件赋给`swiped`。在`swiped`中，我们实例化一个`SecretDoorbell`对象，为`swipe.up`手势赋值`0`，为`swipe.down`赋值`1`，为`swipe.left`赋值`2`，为`swipe.right`赋值`3`。这些值对应于`SecretDoorbell`类的`names`数组中的位置。我们在为任何手势实例化`SecretDoorbell`对象时不传递`test_env`的值，因此不会发送文本消息。就像之前的项目一样，我们在 shell 中打印`doorbell_sequence`方法运行成功的结果。

要发送文本消息，我们只需要用`False`值覆盖默认的`test_env`值。我们在`swiped`方法中为我们的滑动手势实例化`SecretDoorbell`对象时这样做。我们的代码设计成这样的方式，我们可以为一个或多个手势发送文本消息。修改`swiped`中的以下`elif`语句：

```py
elif swipe.down:
    doorbell = SecretDoorbell(1, False)
    print(doorbell.doorbell_sequence())
```

我们在这里所做的是通过覆盖`test_env`变量，为`swipe.down`手势打开了 Twilio 实时环境。我们为`SecretDoorbell`对象实例化时使用的`1`值对应于`SecretDoorbell`中`names`数组中的第二个元素。

因此，当你运行应用程序并在蓝点上从上向下滑动时，你应该收到来自 Twilio 的一条短信，内容是 Josephine 在门口，如下所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/fa0067b8-c184-4ae2-9be1-281df3a40d2f.png)

# 摘要

在本章中，我们学习了如何将短信功能添加到我们的门铃应用程序中。这使得门铃适应了物联网时代。很容易看出物联网蓝牙门铃的概念可以被扩展——想象一下当有人按门铃时打开门廊灯。

我们还可以看到蓝点应用程序也可以以其他方式被利用。我们可以使用蓝点应用程序编程特定的滑动序列，也许是为了解锁门。想象一下不必随身携带钥匙！

这是我们介绍我们的机器人车之前的最后一章。在接下来的章节中，我们将把我们迄今为止学到的概念应用到我们通过互联网控制的机器人上。

# 问题

1.  蓝点应用程序如何连接到我们的树莓派？

1.  正确还是错误？通过 Twilio 测试环境运行消息会创建一条发送到你手机的短信。

1.  我们用来发送短信的服务的名称是什么？

1.  正确还是错误？我们将我们的`SecretDoorbell`类创建为`Doorbell`类的子类。

1.  我们在第二个应用程序中使用的四个蓝点手势是什么？

1.  正确还是错误？以描述其功能的方式命名一个类会使编码变得更容易。

1.  `Doorbell`和`SecretDoorbell`之间有什么区别？

1.  正确还是错误？Josephine 的铃声模式包括一个长的蜂鸣声。

1.  正确还是错误？为了从我们的应用程序接收短信，你需要使用安卓手机。

1.  康斯坦斯应该如何滑动蓝点，这样我们就知道是她在门口？

# 进一步阅读

我们稍微涉及了 Twilio 服务。然而，还有更多需要学习的地方——访问[`www.twilio.com/docs/tutorials`](https://www.twilio.com/docs/tutorials)获取更多信息。


# 第十三章：介绍树莓派机器人车

我想向您介绍 T.A.R.A.S，这辆机器人车。T.A.R.A.S 实际上是一个回文缩略词；我从一个帮助我起步的商业导师那里得到了这个名字。在绞尽脑汁之后，我终于想出了如何将我的朋友 Taras 变成 T.A.R.A.S，这个令人惊叹的树莓派自动安全代理。从名字上您可能能够猜到，T.A.R.A.S 将为我们监视事物并充当自动安全警卫。

T.A.R.A.S 将使用树莓派作为大脑和电机驱动板，以控制摄像机云台和车轮的运动。T.A.R.A.S 还将具有感应输入以及 LED 和蜂鸣器输出。T.A.R.A.S 将是我们在本书中所学技能的集合。

我们将在本章中组装 T.A.R.A.S 并编写控制代码。

本章将涵盖以下主题：

+   机器人车的零件

+   构建机器人车

# 机器人车的零件

我设计 T.A.R.A.S 尽可能简单地组装。T.A.R.A.S 由激光切割的硬纸板底盘、3D 打印的车轮和摄像头支架部件组成（也有使用激光切割车轮支架的选项）。为了您能够组装 T.A.R.A.S，我提供了底盘的 SVG 文件和 3D 打印部件的 STL 文件。所有其他零件可以在线购买。以下是 T.A.R.A.S 组装前的照片：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/1a8a2578-d9ac-4388-9038-cfa92762062f.png)

1.  伺服摄像头支架（已组装）—在[www.aliexpress.com](http://www.aliexpress.com)搜索防抖动摄像头支架

1.  3D 打印支架（摄像头支架）

1.  车轮用直流电机（带有电机线和延长线）—在[www.aliexpress.com](http://www.aliexpress.com)搜索智能车机器人塑料轮胎轮

1.  车轮支架（3D 打印）

1.  LED 灯

1.  LED 灯座—在[www.aliexpress.com](http://www.aliexpress.com)搜索灯 LED 灯座黑色夹子

1.  摄像头支架支撑（激光切割）

1.  有源蜂鸣器—在[www.aliexpress.com](http://www.aliexpress.com)搜索 5V 有源蜂鸣器

1.  距离传感器（HC-SR04）—在[www.aliexpress.com](http://www.aliexpress.com)搜索 HC-SR04

1.  替代车轮支架（激光切割）

1.  树莓派摄像头（长焦镜头版本，不带电缆）—在[www.aliexpress.com](http://www.aliexpress.com)搜索

1.  电机驱动板（激光切割）

1.  车轮—在[www.aliexpress.com](http://www.aliexpress.com)搜索智能车机器人塑料轮胎轮

1.  机器人车底盘（激光切割）

1.  电机驱动板—在[www.aliexpress.com](http://www.aliexpress.com)搜索 L298N 电机驱动板模块

1.  DC 插孔（带有连接的电线）—[www.aliexpress.com](http://www.aliexpress.com)

1.  Adafruit 16 通道 PWM/舵机 HAT—[`www.adafruit.com/product/2327`](https://www.adafruit.com/product/2327)

1.  树莓派

1.  40 针单排公针排连接器条（未显示）—[www.aliexpress.com](http://www.aliexpress.com)

1.  各种松散的电线和面包板跳线（未显示）—购买许多不同的电线和面包板跳线是个好主意；您可以在[www.aliexpress.com](http://www.aliexpress.com)搜索面包板跳线

1.  热缩管（未显示）

1.  带 DC 插头的 7.4V 可充电电池（未显示）—在[www.aliexpress.com](http://www.aliexpress.com)搜索 7.4V 18650 锂离子可充电电池组（确保选择与 16 号 DC 插孔匹配的电池）

1.  与零件 22 相比，您可以使用 AA 号电池存储盒来替代零件 16 和 22—[www.aliexpress.com](http://www.aliexpress.com)

1.  迷你面包板（未显示）—在[www.aliexpress.com](http://www.aliexpress.com)搜索 SYB-170 迷你无焊点原型实验测试面包板

1.  各种支架（未显示）-它应该能够具有至少 40 毫米的支架高度；最好尽可能多地使用支架，因为它们似乎总是派上用场，您可以在[www.aliexpress.com](http://www.aliexpress.com)上搜索电子支架

1.  330 和 470 欧姆电阻器（未显示）-购买许多电阻器是个好主意；在[www.aliexpress.com](http://www.aliexpress.com)上搜索电阻器包

1.  便携式 USB 电源包（未显示）-这种类型用于在外出时给手机充电；我们将使用此电源包为树莓派供电

# 组装机器人汽车

以下是构建 T.A.R.A.S，我们的机器人汽车的步骤。您的 T.A.R.A.S 版本可能与本书中使用的版本相似，也可以根据需要进行修改。首先，我使用了带有较长镜头的树莓派相机模块（夜视模型带有较长的镜头）。我还使用 Adafruit 16 通道 PWM /伺服 HAT 来驱动相机支架的伺服。您可以选择使用另一个板，或者放弃伺服，将相机安装在固定位置。

我最喜欢的机器人缩写词之一是来自 1980 年迪士尼电影《黑洞》的 Vincent。 Vincent，或更准确地说，V.I.N.CENT，代表着必要的集中信息。如果您知道这部电影，您将知道 V.I.N.CENT 非常聪明和非常有礼貌。 V.I.N.CENT 也有点自以为是，有时可能有点烦人。

我提供了两种不同的安装轮毂电机的方法：使用 3D 打印的轮毂支架或使用激光切割的轮毂支架。我更喜欢 3D 打印的支架，因为它可以使螺丝嵌入，从而在底盘和轮毂之间提供更多空间。

如果您自己 3D 打印轮毂支架和相机支架，可以使用任何您喜欢的固体丝材类型。就我个人而言，我使用 PETG，因为我喜欢它的弯曲性而不易断裂。 PLA 也可以。请确保将轮毂支架侧向打印，以便它们打印宽而不是高。这将导致打印可能在孔周围有点凌乱（至少对于 PETG 来说），但它将是一个更坚固的零件。我设法在 30 分钟内打印了一个轮毂支架，相机支架大约 90 分钟。

组装机器人汽车应该花费您一下午的时间。

# 第 1 步 - 用于树莓派的 Adafruit 16 通道 PWM /伺服 HAT

如果您还没有听说过，纽约市有一家名为 Adafruit 的令人惊叹的公司，为全球的电子爱好者提供服务。 Adafruit 为树莓派创建了许多**HATs**（**Hardware Added on Top**），包括我们将用于机器人的 Adafruit 16 通道 PWM /伺服 HAT。

使用此 HAT，用于控制伺服的重复时间脉冲从树莓派卸载到 HAT 上。使用此 HAT，您可以控制多达 16 个伺服。

以下是 HAT 和随附的引脚的照片：

！[](assets/ef44e937-759e-4d95-b942-8d35b5e04834.png)

为了我们的目的，我们需要在板上焊接引脚：

1.  由于我们只使用了两个伺服，因此需要将两个**3 引脚伺服引脚**焊接到板上。

1.  焊接**2 X 20 引脚引脚**。在焊接时，固定板和引脚的一个好方法是使用一些橡皮泥！（确保在焊接时不要让热焊铁太靠近橡皮泥！）：

！[](assets/274703ea-3d65-4fac-a024-5e0fede76158.png)

1.  由于我们将使用来自电机板的电线来为伺服板供电，因此需要将电源引脚焊接到板上。

1.  我们需要从树莓派访问 GPIO 引脚，因此必须添加另一排引脚。从 40 针引脚排连接器中断开 25 根引脚。将引脚焊接到板上：

！[](assets/f578020c-805e-435f-94a1-393d2b501af3.png)

# 第 2 步 - 接线电机

我们需要将电机接线，以便两个电机始终同时且在同一方向旋转：

1.  切割八根相等长度的电线，并剥离所有电线的两端的一些绝缘：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/11481a24-5dca-4873-936d-de7e12c8a928.png)

1.  将每个电机的端子焊接在一起：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/c3081fa8-76c7-434b-97ce-f1b490d32dd6.png)

1.  在端子上应用热缩管以绝缘：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/50e0c531-01fd-4a60-91e7-0e3c9d9fac51.png)

1.  将每个电机的电线分组并连接起来，使得一个电机顶部的电线连接到另一个电机底部的电线（请参考照片以了解清晰情况）：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/249bbb07-2500-4f65-ad99-5c26bab1f08e.png)

1.  为了增加强度和保护，您可以使用热缩管将电线固定在一起（在上一张照片中，使用了黄色热缩管）。

1.  可以在末端添加延长线（我选择为我的组装添加了延长线，因为电线长度有点短）。稍后添加到末端的蓝色标签胶带将有助于将电机连接到电机驱动器板：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/56bc16f2-2da7-41e4-a6ba-2a66d18f54a3.png)

# 第 3 步 - 组装伺服摄像机支架

有了我们的伺服摄像机支架，T.A.R.A.S 有能力左右摇头和上下运动。这对我们在第十四章中的项目非常有用，即*使用 Python 控制机器人车*。当您将伺服摄像机支架的零件倒在桌子上时，可能会感到有点令人生畏，不知道如何将其组装成有用的东西。

以下是伺服摄像机支架零件的照片。与其试图命名零件，我会把字母放下来，并参考这些字母进行组装：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/c0b0a161-8760-4f1a-a995-b24a37ca20bd.png)

要组装伺服摄像机支架，请按以下步骤进行：

1.  将零件**E**放入零件**A**中，使得零件**E**的突出圆柱朝上：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/ee0163cd-7696-4b42-8b25-3032cd731a5e.png)

1.  翻转并使用包装中最小的螺丝将零件**E**螺丝固定到零件**A**上：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/05d60291-48b3-4962-bb76-d95629bfa5cb.png)

1.  使用小螺丝将伺服螺丝固定在零件**D**上（请参见下一张照片）：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/56361793-a726-4c89-9ea4-4990fe63dde9.png)

1.  将零件**B**放在伺服上，并将零件**F**插入为其制作的凹槽中。将零件**F**螺丝固定在位。伺服应能够在连接到零件**B**和**F**的同时自由上下移动：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/fc2f337b-1d27-4b11-a7da-0756e63cbb1a.png)

1.  翻转组装好的零件并将另一个伺服插入零件**B**中：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/596a4f93-7534-4aef-a120-1ed776b46e64.png)

1.  将零件**C**放在伺服上。您可能需要稍微弯曲零件**D**以使零件**C**适合：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/40c91b14-9ee6-447d-aba8-b8aa5d5296c2.png)

1.  翻转组装好的零件并将零件**B**和**C**螺丝固定在一起：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/43f9b60d-e642-4861-86a8-cf20f0037b7a.png)

1.  将组装好的零件插入零件**E**中：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/745d14a3-4613-4369-9438-a361241f02f5.png)

1.  将零件**A**螺丝固定在组装好的零件底部：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/23bb8986-9f34-4c57-8251-3bb3dfc15b39.png)

# 第 4 步 - 附加头部

让我们面对现实吧。除非有某种面孔（向 R2D2 道歉），否则机器人就不是机器人。在这一步中，我们将连接零件以构建 T.A.R.A.S 的头部和面部。

根据 Rethink Robotics 创始人 Rodney Brooks 的说法，机器人并不是为了让它们看起来友好才有脸。机器人的脸被用作人类的视觉线索。例如，如果机器人朝某个方向移动头部，我们可以安全地假设机器人正在分析那个方向的东西。当我们移动 T.A.R.A.S 的头部时，我们向周围的人发出信号，告诉他们 T.A.R.A.S 正在朝那个方向看。

以下是完成头部所需的零件的照片：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/15c557ce-1c73-4395-813b-8619a0770596.png)

现在我们将组装 T.A.R.A.S 的头部。以下是零件清单：

+   **A**：树莓派摄像头模块

+   **B**：摄像机支架支撑

+   **C**：带伺服的组装摄像机支架

+   **D**：3D 打印支架

+   **E**：距离传感器

+   **F**：螺丝

要组装头部，请按以下步骤进行：

1.  在树莓派摄像头模块和距离传感器上贴上双面泡沫胶带的小块：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/ba566c64-a12f-4435-9c5b-f978f980068c.png)

1.  将树莓派摄像头模块和距离传感器粘贴到 3D 打印支架的适当位置（请参考以下照片以获得澄清）：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/2db37d5e-c365-4453-9a65-748ab09d07b3.png)

1.  将组件滑入已组装的摄像头支架上并将其固定在位（请参考以下照片以获得澄清）：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/ac938a4b-5a96-4efd-94e8-fce25cf85af5.png)

1.  在距离传感器的引脚上加上母对母跳线。在这里，我使用了一个四针连接器连接到 4 个单独的引脚。您也可以使用单独的跳线：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/5a76c2d7-ff97-40ec-8bcd-17ec77c3d6f1.png)

1.  将组装好的部件转过来，贴上牙齿的贴纸：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/011f8ceb-3127-447a-b352-03e0498f3c54.png)

# 步骤 5 - 组装直流电机板

直流电机板位于 T.A.R.A.S 的后部，安装有驱动轮的直流电机驱动器。直流插孔和尾灯 LED 也安装在直流电机板上。我们将从创建尾灯 LED 开始这一步。

以下照片显示了制作尾灯 LED 所需的零件：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/3bf3391b-fd10-451b-9a8e-f87b2e4c5c59.png)

以下是零件清单：

+   **A**：红色跳线（一端必须是女头）

+   **B**：棕色跳线（一端必须是女头）

+   **C**：红色 LED

+   **D**：绿色 LED

+   **E**：330 欧姆电阻

+   **F**：热缩管

以下是创建 LED 尾灯的步骤：

1.  将 330 欧姆电阻焊接到 LED 的阳极（长腿）。

1.  在连接处加上热缩管以提供强度和绝缘。

1.  剥开一根红色跳线（确保另一端是女头），并将其焊接到电阻的末端。这是组件的正端：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/90fb2cdb-e6f4-45c9-85de-732f8938f539.png)

1.  在整个电阻上加上热缩管：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/4659ec3e-a64c-4481-be31-14f1d03bf841.png)

1.  将棕色线焊接到阴极并加上热缩管（在这张照片中，我们展示了一个带有延长棕色线的红色 LED）。这是组件的负端：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/cc7440c0-7751-4ed8-8035-83d94a75cee4.png)

1.  现在我们已经完成了两个尾灯的组装，让我们把直流电机板组装起来。以下是我们需要组装直流电机板的零件的照片：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/9277defa-8ea8-4dd4-87a1-2de3937a3fd3.png)

以下是零件清单：

+   **A**：红色尾灯

+   **B**：绿色尾灯

+   **C**：短电源线

+   **D**：电机驱动板

+   **E**：直流电机板（激光切割）

+   **F**：LED 支架

+   **G**：直流插孔

+   **H**：40mm 支架

+   八颗 M3X10 螺栓（未显示）

+   四颗 M3 螺母（未显示）

+   拉链扎带（未显示）

让我们开始组装它：

1.  用四颗 10mm M3 螺栓将 40mm 支架（**H**）固定到**E**上。请参考以下照片以获得正确的方向：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/239e3c1c-63b2-43e1-acba-5829f74284a1.png)

1.  用四颗 10mm M3 螺栓和螺母将电机驱动板（**D**）固定到**E**上。请参考以下照片以获得正确的方向：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/60030ea6-e7e6-4eca-af03-6571d7c8beba.png)

这是侧视图：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/973a1d78-3237-4bf6-892e-38b1a6364122.png)

1.  将电线**C**连接到直流插孔（**G**）端口。确保红线连接到正极，黑线连接到负极。将电线**C**的另一端连接到电机驱动板（**D**）。确保红线连接到 VCC，黑线连接到 GND。用拉链扎带将直流插孔（**G**）固定到直流电机板（**E**）上。请参考以下照片以获得澄清：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/a705ff16-c7c6-4fe4-b4cf-3de6501d3438.png)

这是接线图：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/e4bfee31-dc2f-435d-87e2-0e76a59b343a.png)

1.  或者，您可以使用 AA 电池四组供电。确保使用相同的布线，红线连接到 VCC，黑线连接到 GND：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/0ef07af9-254e-42cb-8d80-09ee55760833.png)

1.  将尾灯（**B**）穿过 LED 孔并穿过 LED 支架（**F**）：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/d76c25ca-ffcf-47bd-b669-9ecaab88062e.png)

1.  将 LED 支架（**F**）推入位。如果孔太紧，使用小锉将孔稍微放大一点（LED 支架应该安装得很紧）。重复操作以安装红色尾灯：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/38e3629f-3b4b-43d2-a5a7-fda32c26e074.png)

# 第 6 步 - 安装电机和轮子

在这一步中，我们将开始将零件固定到底盘上。我们将首先固定轮子支架，然后是电机。我们将在这一步中使用 3D 打印的轮子支架。

此步骤所需的零件如下图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/5f890aae-169b-4f3e-9bb2-02b5be256ff2.png)

以下是零件清单：

+   **A**：轮子

+   **B**：电机

+   **C**：备用轮子支架（激光切割）

+   **D**：轮子支架（3D 打印）

+   **E**：机器人车底盘（激光切割）

+   八颗 M3 10 毫米螺栓（未显示）

+   八颗 M3 30 毫米螺栓（未显示）

+   16 颗 M3 螺母（未显示）

让我们开始组装它：

1.  使用 10 毫米 M3 螺栓和螺母，将每个轮子支架（**D**）固定到底盘（**E**）上，使螺栓的头部平躺在轮子支架（**D**）中。参考以下照片以便澄清：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/d8593bd5-ee03-4dd5-ad13-c7e8781d71c8.png)

1.  使用 30 毫米 M3 螺栓和 M3 螺母，通过使用轮子支架（**D**）将电机（**B**）安装到底盘（**E**）上。确保螺栓的头部平躺。参考以下照片以便澄清：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/d7114241-77a4-4119-ac53-e90921cdc459.png)

1.  或者，您可以使用零件**C**代替零件**D**来安装轮子。参考以下照片以便澄清：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/755bec60-4da7-45c5-89c6-34fe0c3ce9e4.png)

1.  将轮子（**A**）安装到电机（**B**）上：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/de1d6e9d-4ab8-4576-8698-1c3406982398.png)

# 第 7 步 - 连接电机的电线

接下来，我们将安装电机驱动板组件并连接轮子电机的电线：

1.  首先，使用四颗 M3 10 毫米螺栓将第 5 步中的直流电机板组件固定在底盘顶部。确保将轮子电机的电线穿过中央孔。尾灯 LED 应该安装在机器人车的后部。参考以下照片以便澄清：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/711e93ff-8aea-4af9-b220-4611a869bf80.png)

1.  将轮子电机的电线安装到电机驱动板的 OUT1、OUT2、OUT3 和 OUT4 端子块中。右侧电线应连接到 OUT1 和 OUT2，左侧电线应连接到 OUT3 和 OUT4。在这一点上，右侧电线连接到 OUT1 或 OUT2（或左侧电线连接到 OUT3 或 OUT4）并不重要。参考以下照片以便澄清：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/2de9f44c-65e1-4aa4-bf57-dd7926e5270a.png)

# 第 8 步 - 安装摄像头支架、树莓派和 Adafruit 伺服板

机器人车开始看起来像一辆机器人车。在这一步中，我们将安装摄像头支架（或 T.A.R.A.S 的头部）和树莓派。

我们将从树莓派开始。这是我们必须在如何将树莓派和 Adafruit 伺服板安装到底盘上稍微有些创意的地方。Adafruit 伺服板是一个很棒的小板，但是套件缺少支架，无法防止板的一部分接触树莓派。我发现很难将 M3 螺栓穿过板上的安装孔。我的解决方案是使用 30 毫米的母对公支架将树莓派固定到底盘上，并使用 10 毫米的母对母支架将树莓派与 Adafruit 伺服板分开。

以下是带有一些我收集的支架的树莓派的照片：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/2cb70178-957b-470f-ae89-85e59daf2dd9.png)

以下是上图中的组件：

+   **A**：15 毫米母对公尼龙支架

+   **B**：10 毫米母对母尼龙支架

+   **C**：树莓派

要创建这个电路，请按照以下步骤进行：

1.  通过将**A**的一端螺丝拧入另一个端口，创建四个 30 毫米的母对公支架。通过树莓派将**B**支架螺丝拧入**A**支架（请参考以下照片以便理解）：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/93c4d596-eaf6-4ab9-aaf4-71ae304f83d8.png)

1.  使用四个 10 毫米 M3 螺栓将树莓派固定到底盘上：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/322079c1-7928-4f04-a05c-da1660fa0cfb.png)

现在，让我们安装摄像头支架，连接摄像头，并安装 Adafruit 舵机板：

1.  使用四个 10 毫米 M3 螺丝和 M3 螺母将摄像头支架安装到底盘的前部（请参考以下照片以便理解）：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/86ac58d3-1cee-4450-ab02-51a4fdfafbb9.png)

1.  通过摄像头模块的排线插入适当的开口到 Adafruit 舵机板（请参考以下照片以便理解）：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/39566e38-0af6-4300-b297-977550b357a4.png)

1.  将 Adafruit 舵机板固定到树莓派上：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/c55672a9-c12e-463e-bb57-b6bf73c896f2.png)

# 第 9 步 - 安装蜂鸣器和电压分压器

安装在底盘上的最终组件是蜂鸣器和电压分压器。我们需要电压分压器，以便我们可以从距离传感器的回波引脚向树莓派提供 3.3V。对于蜂鸣器，我们使用的是有源蜂鸣器。

有源蜂鸣器在施加直流电压时发出声音。被动蜂鸣器需要交流电压。被动蜂鸣器需要更多的编码。被动蜂鸣器更像是小音箱，因此您可以控制它们发出的声音。

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/0eb0829c-0678-4a30-8051-cdde32de77da.png)

以下是完成此步骤所需的组件：

+   **A**：迷你面包板

+   **B**：棕色母对母跳线

+   **C**：红色母对母跳线

+   **D**：470 欧姆电阻

+   **E**：330 欧姆电阻

+   **F**：有源蜂鸣器

按照以下步骤完成电路：

1.  为了创建电压分压器，在面包板（**A**）上将 330 欧姆（**E**）和 470 欧姆（**D**）电阻串联：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/8cf75624-efcb-480b-86bc-8aa674a3697a.png)

1.  将红色跳线（**C**）连接到蜂鸣器的正极，棕色跳线（**B**）连接到另一端：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/47b068ea-37a5-4de1-91b5-35967c2f7122.png)

1.  将蜂鸣器（**F**）安装在底盘上的适当孔中。使用双面泡沫胶带，将迷你面包板（**A**）粘贴到底盘的前部（请参考以下照片以便理解）：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/7c9e8d6d-393d-44c9-8efc-144dca4c80dd.png)

# 第 10 步 - 连接 T.A.R.A.S

现在是你一直在等待的部分：连接所有的电线！好吧，也许整理一堆电线并理清它们并不是你的好时光。然而，稍微耐心一点，这一步骤会在你知道之前结束的。

参考以下接线图，将所有电线连接到相应的位置。我们的接线图中不包括电源和电机连接到电机驱动板，因为我们在第 7 步中已经处理了电机的接线。我已经注意到了根据它们的用途分组的电线颜色。请注意，接线图不是按比例绘制的：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/a5bb3926-7d5d-4659-8245-6c8bb35c1d92.png)

要连接 T.A.R.A.S 的电线，执行以下连接：

+   从 Servo HAT 的引脚五到 L298N（电机板）的 In1

+   从 Servo HAT 的引脚六到 L298N（电机板）的 In2

+   从 Servo HAT 的引脚 27 到 L298N（电机板）的 In3

+   从 Servo HAT 的引脚 22 到 L298N（电机板）的 In4

+   从 HC-SR04（距离传感器）的 Trig 到 Servo HAT 上的引脚 17

+   从 HC-SR04（距离传感器）的回波到迷你面包板上 330 欧姆电阻的左侧

+   从 HC-SR04（距离传感器）的 VCC 到 Servo HAT 上的 5 伏特

+   从电压分压器的输出到 Servo HAT 上的引脚 18

+   从 HC-SR04 的 GND 到迷你面包板上 470 欧姆电阻的右侧

+   从迷你面包板的 GND 到 Servo HAT 上的 GND

+   从 Servo HAT 电源端子（HAT 左侧）的+5V 到电机驱动板的+5V（使用更粗的电线）

+   舵机 HAT 电源端子（HAT 左侧）的 GND 连接到电机驱动板上的 GND（使用更粗的电线）

+   从摄像头支架（水平）底部的舵机到舵机 HAT 上的零号舵机

+   从摄像头支架（倾斜）中间的舵机到舵机 HAT 上的一号舵机

+   绿色尾灯上的红线连接到舵机 HAT 上的 20 号引脚

+   绿色尾灯上的棕色线连接到舵机 HAT 上的 GND

+   红色尾灯上的红线连接到舵机 HAT 上的 21 号引脚

+   棕色线连接到舵机 HAT 上的红色尾灯接地

+   主动蜂鸣器上的红线连接到舵机 HAT 上的 12 号引脚

+   主动蜂鸣器上的棕色线连接到舵机 HAT 上的 GND

为了启动 T.A.R.A.S，我们将使用两个便携式电源。对于树莓派，我们将使用标准的 USB 便携式电源包。对于电机驱动板和舵机 HAT，我们将使用可充电的 7.4V 电池。安装电池，按照以下步骤进行：

1.  以下是我们将用于我们的机器人车的两个电池。左边的是用于树莓派的，使用 USB 到 Micro-USB 连接器。右边的是电机驱动板，使用标准的 DC 插头：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/c380fe13-1eb8-4068-86b0-3bfef697dbfa.png)

1.  将剥离式粘扣条贴在两个电池和底盘上，并将电池放置在底盘上：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/15fb0978-cab4-4754-89e6-6fd3b99ece93.png)

1.  经过一番必要的整理（清理电线），T.A.R.A.S 已经准备就绪：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/aad6712d-7d7c-4eec-8074-0cae03d5e2dd.png)

# 学习如何控制机器人车

在第十四章中，*使用 Python 控制机器人车*，我们将开始编写代码来控制 T.A.R.A.S。在我们开始编写代码之前，看一下如何设置树莓派以访问所需的接口是个好主意。我们应该安装我们需要使用的库来创建控制代码。

# 配置我们的树莓派

为了确保我们已经启用了机器人车所需的推理，按照以下步骤进行：

1.  导航到应用程序菜单|首选项|树莓派配置

1.  单击“接口”选项卡

1.  启用摄像头、SSH 和 I2C。您可能需要重新启动树莓派：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/2960257c-6d2e-4ecd-84d8-9e109d85b58a.png)

如果您尚未更改`pi`用户的默认密码，则在启用 SSH 后可能会收到有关此警告。最好更改默认密码。您可以在树莓派配置工具的系统选项卡下更改它。

# Adafruit 舵机 HAT 的 Python 库

为了访问 Adafruit 舵机 HAT，您必须下载并安装库：

1.  `git`用于从互联网下载 Adafruit 舵机 HAT 库。在 Raspbian 中打开终端并输入以下内容：

```py
sudo apt-get install -y git build-essential python-dev
```

1.  如果`git`已安装，您将收到相应的消息。否则，请继续安装`git`。

1.  在终端中输入以下内容以下载库：

```py
git clone https://github.com/adafruit/Adafruit_Python_PCA9685.git
```

1.  输入以下内容更改目录：

```py
cd Adafruit_Python_PCA9685
```

1.  使用以下命令安装库：

```py
sudo python3 setup.py install
```

1.  库已成功安装到 Thonny 的工具|管理包中。您应该能看到它在列表中：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/7f1d3d07-ab79-461f-b682-777f4db5a4a8.png)

# 摘要

在本章中，我们建造了我们的机器人车 T.A.R.A.S。我们首先概述了零件，然后继续将它们组装在一起。如果您以前从未组装过机器人，那么恭喜！您已正式进入了机器人领域。接下来的路由取决于您。

在本书的其余部分，我们将编程 T.A.R.A.S 执行任务。在第十四章中，*使用 Python 控制机器人车*，T.A.R.A.S 将被要求参与秘密任务。

# 问题

1.  正确还是错误？T.A.R.A.S 代表 Technically Advanced Robots Are Superior。

1.  主动蜂鸣器和被动蜂鸣器有什么区别？

1.  正确还是错误？T.A.R.A.S 有摄像头作为眼睛。

1.  电机驱动板的作用是什么？

1.  Adafruit 舵机 HAT 的目的是什么？

1.  3D 打印一个轮子支架需要多长时间？

1.  机器人脸的目的是什么？

1.  Velcro strips are a great way to secure batteries onto the chassis.
