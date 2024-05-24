# Python 物联网编程实践（五）

> 原文：[`zh.annas-archive.org/md5/7FABA31DD38F615362E1254C67CC152E`](https://zh.annas-archive.org/md5/7FABA31DD38F615362E1254C67CC152E)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十三章：物联网可视化和自动化平台

在上一章中，我们探讨了与电子设备接口的 Python 程序结构的替代方法。这包括事件循环方法，两种基于线程的方法，显示回调和发布-订阅模型的使用，以及异步 I/O 方法。

在本章中，我们将讨论您可以与树莓派一起使用的物联网和自动化平台。术语*物联网平台*和*自动化平台*是非常广泛的概念，因此在本章中，我所指的是任何软件服务-基于云或本地安装-为您提供一个现成的生态系统，以创建强大，灵活和有趣的物联网项目。

我们的主要重点将放在**If-This-Then-That**（**IFTTT**）自动化平台上，我怀疑你们中的许多人对此都有一些了解，并且 ThingSpeak 平台用于数据可视化。我选择了这两个服务，因为它们都提供免费的定价层，并且允许我们创建和探索简单的演示和示例，您可以在此基础上构建。但是，除此之外，我还将讨论一些我有经验的其他物联网和自动化平台，这些平台将使您能够构建更强大的物联网解决方案。

本章将涵盖以下主题：

+   从树莓派触发 IFTTT Applet

+   从 IFTTT Applet 操作您的树莓派

+   使用 ThingSpeak 平台可视化数据

+   其他物联网和自动化平台供进一步探索

让我们开始吧！

# 技术要求

要执行本章的练习，您将需要以下物品：

+   树莓派 4 型 B

+   Raspbian OS Buster（带桌面和推荐软件）

+   Python 版本至少为 3.5

这些要求是本书中代码示例的基础。可以合理地期望代码示例应该可以在树莓派 3 型 B 或不同版本的 Raspbian OS 上无需修改即可工作，只要您的 Python 版本是 3.5 或更高。

您将在本书的 GitHub 存储库的`chapter13`文件夹中找到本章的源代码，该存储库位于此处：[`github.com/PacktPublishing/Practical-Python-Programming-for-IoT`](https://github.com/PacktPublishing/Practical-Python-Programming-for-IoT)。

您需要在终端中执行以下命令来设置虚拟环境并安装本章代码所需的 Python 库：

```py
$ cd chapter13              # Change into this chapter's folder
$ python3 -m venv venv      # Create Python Virtual Environment
$ source venv/bin/activate  # Activate Python Virtual Environment
(venv) $ pip install pip --upgrade        # Upgrade pip
(venv) $ pip install -r requirements.txt  # Install dependent packages
```

以下依赖项将从`requirements.txt`中安装：

+   **PiGPIO**：PiGPIO GPIO 库（[`pypi.org/project/pigpio`](https://pypi.org/project/pigpio)）

+   **Paho MQTT 库**：[`pypi.org/project/paho-mqtt`](https://pypi.org/project/paho-mqtt)

+   **Requests HTTP 库**：[`pypi.org/project/requests`](https://pypi.org/project/requests)

+   **基于 PiGPIO 的 DHT 库**：[`pypi.org/project/pigpio-dht`](https://pypi.org/project/pigpio-dht)

本章练习所需的电子元件如下：

+   1 x DHT11（较低精度）或 DHT22（较高精度）温湿度传感器

+   1 x 红色 LED

+   电阻：

+   1 x 200Ω 电阻

+   1 x 10kΩ 电阻（可选）

# 从树莓派触发 IFTTT Applet

你们中的许多人可能已经熟悉**If-This-Than-That**（**IFTTT**）网络服务（[ifttt.com](https://ifttt.com)），在那里您可以创建称为*Applets*的简单工作流自动化链。Applet 响应一个网络服务的更改（*This*），然后触发另一个网络服务的操作（*That*）。

以下是一些 Applet 配置（称为*Recipes）的常见示例：

+   每当特定的 Twitter 标签发布时，向自己发送电子邮件。

+   在一天的特定时间打开或关闭智能灯泡。

+   当您接近您的房子时，使用手机的 GPS 打开您的联网车库门。

+   在电子表格中记录您在办公室的时间。

+   ...以及成千上万的其他示例！

正如我们将在本节和下一节中学到的那样，我们的 Raspberry Pi 可以承担*This*或*That*的角色，以触发 Applet 或响应触发的 Applet 执行操作。

以下是我们将在本节中涵盖的内容的可视化表示；即，使我们的 Raspberry Pi 承担 IFTTT 工作流程中*This*角色：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/4303aaf0-acc8-4520-89a8-3d9784ccfd72.png)

图 13.1 - Raspberry Pi 在 IFTTT Applet 工作流程中承担*This*角色

我们即将介绍的 Python 示例将监视当前温度（*This*），并在特定温度时请求特殊的 IFTTT Webhook URL。此 URL 请求将触发我们的 Applet，然后发送电子邮件（*That*）。在构建我们的第一个 IFTTT Applet 时，我们将很快更详细地讨论 Webhooks。

首先，我们需要创建和测试我们的示例电路，接下来我们将这样做。

## 创建温度监测电路

在本示例中，我们将重用我们在第九章中创建的 DHT11/DHT22 温度电路，*测量温度、湿度和光照水平*。

我们需要做的是：

1.  构建*图 9.2*中所示的电路。

1.  将数据引脚连接到 GPIO 24（在第九章中，*测量温度、湿度和光照水平*，我们使用了 GPIO 21，但我们将在本章后面使用 GPIO 21 来控制 LED）。

一旦您建立了电路，我们就可以继续并构建我们的第一个 IFTTT Applet。

## 创建和配置 IFTTT Applet

要创建我们的 IFTTT Applet，我们需要遵循许多步骤。这些步骤中的许多步骤都很简单和通用，无论您创建的 Applet 类型如何。虽然我们将逐步介绍这些通用步骤，但我们不会详细介绍它们，因为我相信您完全能够理解在过程中发生了什么。相反，我们将专注于与集成我们的 Raspberry Pi 相关的 IFTTT 的独特步骤和部分。

请注意，[`ifttt.com/`](https://ifttt.com/)免费定价层限制了您可以同时拥有的 Applet 数量。在撰写本文时，最大值为三个活动 Applet。在本章和下一章中，我们将创建四个 Applet，因此您需要在进行下一章时至少将一个 Applet 存档到 IFTTT 上，以保持在 IFTTT 免费定价层上。

以下是我们需要遵循的步骤：

1.  登录或创建您的 IFTTT 帐户。如果您还没有 IFTTT 帐户，请访问[ifttt.com/join](https://ifttt.com/join)并按照屏幕上的说明操作。

我们在 IFTTT 网站[ifttt.com](https://ifttt.com)上执行这些步骤。IFTTT 手机和平板应用程序的操作流程将不同。

1.  登录到 IFTTT 后，点击您的个人资料头像图标（在下图中用方框标出）以显示菜单：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/aca6a0a4-f02a-409d-9068-981bfae1cdec.png)

图 13.2 - 个人资料头像图标

1.  接下来，点击个人资料菜单中的创建选项，如下所示：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/18671e75-d293-46b0-a70a-75bd2ce5ee9a.png)

图 13.3 - 个人资料菜单

1.  接下来您将看到的页面是创建您自己的页面。在这里，点击*If*和*This*之间的+图标：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/cce74029-b626-47db-8ec3-84e62a9d75d7.png)

图 13.4 - 创建您自己的页面 - 第一部分

1.  现在，您将被要求选择一个服务。我们需要选择的服务与我们的 Raspberry Pi 集成的服务称为 WebHook 服务，如下所示：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/f1863ed6-d765-4f21-a827-94f71cfc1e2e.png)

图 13.5 - 选择服务页面

1.  找到并识别 Webhook 服务后，点击 Webhooks 图标继续。

1.  接下来您将看到的页面是选择触发器页面，如下截图所示。在这里，点击接收 Web 请求选项：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/e029b47f-c7ee-4e05-afc5-88ad678d28d1.png)

图 13.6 - 选择触发器页面

1.  接下来，您将看到完成触发字段页面，如下所示：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/a291b7c9-1176-4712-ae9a-7c7afdea76a2.png)

图 13.7 - 完成触发字段页面

事件名称对于我们的树莓派集成非常重要。在我们即将介绍的 Python 代码中，我们必须确保代码中使用的事件名称与我们在此页面中输入的名称匹配。在我们的示例中，我们将事件命名为 RPITemperature。

1.  在“事件名称”框中输入 RPITemperature，然后点击“创建触发器”按钮继续。

Webhook 的事件名称是其唯一标识符（用于您的 IFTTT 帐户）。如果您创建了许多 Webhooks，则需要使用不同的事件名称来区分它们。

1.  接下来，您将再次看到“创建您自己”的页面。这一次，您会发现*This*现在是 Webhook 图标：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/07bdc6ca-6d2d-41d5-9e1b-4b8994cd02c1.png)

图 13.8 - 创建您自己的页面 - 第二部分

我们现在已经完成了配置 IFTTT Applet 的一半。现在我们已经配置了 Webhook 触发器，我们需要配置我们的动作，即发送电子邮件。创建电子邮件动作后，我们将重新访问 Webhook 触发器，并发现用于触发此 Webhook 事件的 URL 和参数。

1.  接下来，在“然后”和“那个”之间点击“+”图标。您将看到选择动作服务页面。在此页面上，搜索电子邮件并点击电子邮件图标：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/14538a8c-4390-4199-b5dd-9f73f088bd69.png)

图 13.9 - 选择动作服务页面

1.  当您看到下图所示的选择动作页面时，请选择“发送电子邮件”选项：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/799fbea2-585f-403b-a4a5-2cda1e63da1a.png)

图 13.10 - 选择动作页面

1.  接下来，您将看到完成动作字段页面。请填写主题和正文文本字段，如下截图所示。您将在本章后面找到此动作生成的示例电子邮件：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/57b62fb0-15af-476e-8523-0fa8d854dd08.png)

图 13.11 - 完成动作字段页面

在前面的屏幕截图中，您会注意到一些文本被灰色框包围；例如，“Value1”和“OccuredAt”。这些被称为*ingredients*，在触发 Applet 时会动态替换。正如我们很快将在代码中看到的那样，我们将用当前温度、湿度和消息分别替换 Value1、Value2 和 Value3。

1.  填写主题和正文文本字段后，点击“创建动作”按钮。

1.  最后，在审查和完成页面上点击“完成”按钮，如下所示：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/602b06fa-867c-4d9f-a717-da370163fbf1.png)

图 13.12 - 审查和完成页面

恭喜！您刚刚创建了一个 IFTTT Applet，当我们使用树莓派触发它时，它会发送一封电子邮件。但是我们如何做到的呢？这就是我们将在下一节中了解的内容。

## 触发 IFTTT Webhook

现在我们已经创建了我们的 IFTTT Applet，我们需要采取一些步骤来学习如何触发我们的 Webhook。这些步骤归结为知道在 IFTTT 中导航到哪里以发现您的唯一 Webhook URL。

以下是我们需要遵循的步骤：

1.  首先，我们需要导航到 Webhooks 页面。我们可以通过几种方式来做到这一点，我会让您自行决定采取哪种方式：

+   +   将您的网络浏览器导航到 Webhook 服务 URL；即[ifttt.com/maker_webhook](https://ifttt.com/maker_webhooks)。

+   或者，导航到此网页的步骤如下：

1.  点击个人资料头像图标（如*图 13.2*中所示）。

1.  在出现的菜单中，选择“My Services”项目（参见*图 13.3*）。

1.  在出现的页面上，找到并点击“Webhooks”项目。

无论您选择哪条路径，您将看到下图所示的页面：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/390f2005-f5f8-47c4-aaa7-b1482c3c38a1.png)

图 13.13 - Webhooks 页面

1.  单击页面右上角的 Documentation 按钮。您将看到这里显示的 Webhook 文档页面：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/92fa1db0-2d3f-4e77-b4cf-0c0649f71b8c.png)

图 13.14 - Webhook 文档页面请注意，在前面的示例页面中，我已经填写了{Event}和 JSON Body 字段，以便在我们的讨论中引用它们。您的字段将最初为空。

这个页面包含了我们需要的关键信息，以便将这个 Webhook 触发与我们的 Raspberry Pi 集成。这个页面的关键部分如下：

+   **您的密钥**：这是您的帐户的 Webhook API 密钥，并且是您独特的 Webhook URL 的一部分。

+   **GET 或 POST 请求 URL**：您独特的 Webhook URL。您的 API 密钥和事件名称的独特组合是将 URL 与可触发的 IFTTT 事件关联起来的。要与我们的 Raspberry Pi 集成，这是我们需要构建和请求的 URL。我们将很快在代码中介绍这一点。

+   **事件名称**：您想触发的事件的名称。

+   **JSON 主体**：每个可触发的 Webhook 可以包含最多三个以 JSON 格式呈现的数据参数，它们必须命名为 value1、value2 和 value3。

+   **cURL 命令行示例**：在终端中运行此示例以触发 RPITemperature 事件（您将收到一封电子邮件）。

+   **测试按钮**：单击此按钮将触发 RPITemperature 事件（您将收到一封电子邮件）。

现在我们已经创建了 IFTTT Applet，并发现了在哪里找到 Webhook URL 以及它是如何构建的，我们现在可以深入研究将触发我们的 IFTTT Applet 的 Python 代码。

## 在 Python 中触发 IFTTT Applet

我们将要探索一个简单的应用程序，基于我们在第九章中首次看到的 DHT 11/DHT 22 电路和代码，*测量温度、湿度和光照水平*。您可以在`chapter13/ifttt_dht_trigger_email.py`文件中找到这段代码。

这段代码将使用 DHT 11 或 DHT 22 传感器监视温度，如果违反了预先配置的高温或低温阈值，代码将调用您的 IFTTT Webhook URL，然后会像下面的截图中显示的那样给您发送一封电子邮件。这对应于您在*步骤 13*中配置的电子邮件主题和正文文本：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/fb5055c7-3127-4f1a-87a2-3a4b5b73c826.png)

图 13.15 - 示例 IFTTT 电子邮件

在我们运行示例应用程序代码之前，我们需要执行一些配置步骤。让我们来看一下：

1.  打开`chapter13/ifttt_dht_trigger_email.py`文件进行编辑。

1.  找到由第（1）和（2）行表示的以下代码段。确认您的 DHT 传感器连接到适当的 GPIO 引脚，并且根据您拥有的传感器使用正确的 DHT11 或 DHT22 实例：

```py
# DHT Temperature/Humidity Sensor GPIO. GPIO = 24                                                     # (1)   # Configure DHT sensor - Uncomment appropriate line 
# based on the sensor you have. dht = DHT11(GPIO, use_internal_pullup=True, timeout_secs=0.5) # (2) 
#dht = DHT22(GPIO, use_internal_pullup=True, timeout_secs=0.5)
```

1.  现在，找到以下代码段，由行（3）、（4）和（5）表示，并将`USE_DEGREES_CELSIUS`，`HIGH_TEMP_TRIGGER`和`LOW_TEMP_TRIGGER`变量更新为在您的位置有意义的值：

```py
USE_DEGREES_CELSIUS = True # False to use Fahrenheit   # (3)
HIGH_TEMP_TRIGGER   = 20 # Degrees                     # (4)
LOW_TEMP_TRIGGER    = 19 # Degrees                     # (5)
```

当温度达到`HIGH_TEMP_TRIGGER`度或降至`LOW_TEMP_TRIGGER`度时，您的 IFTTT Applet 将被触发并发送电子邮件。设置高温和低温触发的原因是为了创建一个小的温度缓冲区，以防止代码在温度在单个值以上下波动时触发多封电子邮件。

1.  接下来，找到从第 6 行开始的以下代码部分，并更新显示的详细信息 - 特别是您在上一节中识别的 IFTTT API 密钥，在*步骤 2*中：

```py
EVENT = "RPITemperature"                    # (6)
API_KEY = "<ADD YOUR IFTTT API KEY HERE>"
```

这就是我们所有的配置。您会注意到第 7 行，这是我们使用我们的 API 密钥和事件名称构建 IFTTT Webhook URL 的地方：

```py
URL = "https://maker.ifttt.com/trigger/{}/with/key/{}".format(EVENT, API_KEY) # (7)
```

文件中的其余代码轮询 DHT11 或 DHT22 传感器，将读数与`HIGH_TEMP_TRIGGER`和`HIGH_TEMP_TRIGGER`值进行比较，如果温度已超过，构造一个`requests`对象并调用 IFTTT Webhook URL 来触发您的 Applet。我们不会在这里涵盖该代码，因为根据您之前使用 DHT11/DHT22 传感器和 Python `requests`库的经验，这应该是不言自明的。

配置好我们的代码后，是时候在终端中运行程序了。您将收到类似以下的输出：

```py
(venv) $ python ifttt_dht_trigger_email.py
INFO:root:Press Control + C To Exit.
INFO:root:Sensor result {'temp_c': 19.6, 'temp_f': 67.3, 'humidity': 43.7, 'valid': True}
INFO:root:Sensor result {'temp_c': 20.7, 'temp_f': 69.3, 'humidity': 42.9, 'valid': True}
INFO:root:Temperature 20.7 is >= 20, triggering event RPITemperature
INFO:root:Response Congratulations! You've fired the RPITemperature event
INFO:root:Successful Request.
```

我们的示例还显示了当温度超过 20 度时触发 IFTTT Applet。

现在，我们使用我们的树莓派在*This*角色中触发 IFTTT Applet 完成了我们的 IFTTT 示例。我们所涵盖的基本流程说明了实现这一点有多容易！我们发送了一封电子邮件，但您可以按照相同的整体流程创建其他触发其他操作的 IFTTT 配方，例如打开智能灯和电器，向 Google 电子表格添加行，以及创建 Facebook 帖子。您可能想要查看[`ifttt.com/discover`](https://ifttt.com/discover)以获取各种想法和可能性。请记住，从我们的角度和我们的学习来看，这是一个*Webhook*触发器，我们可以从我们的树莓派中使用它来实现这些想法。玩得开心！

接下来，我们将看看相反的情况，看看我们如何操作我们的树莓派。

# 从 IFTTT Applet 中操作您的树莓派

上一节教会了我们如何从我们的树莓派触发 IFTTT Applet。在本节中，我们将学习如何从 IFTTT Applet 中操作我们的树莓派。

对于我们的示例，我们将创建一个 IFTTT Applet，当收到电子邮件时将触发该 Applet。我们将使用此电子邮件的主题来控制连接到 GPIO 引脚的 LED。

我们将使用 IFTTT Webhook 服务，就像以前一样，只是这次 Webhook 服务将安装在我们 Applet 的*That*一侧，并且将请求我们指定的 URL。这个基本想法在下图中有所说明：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/518422de-c428-4537-a648-6b1f34f80280.png)

图 13.16 - 树莓派在 IFTTT Applet 中扮演*That*角色

让我们看看我们可以使用的两种可能的方法，通过 IFTTT Webhook 服务请求一个 URL，然后可以被我们的树莓派的 Python 代码看到。

## **方法 1 - 使用 dweet.io 服务作为中介**

将 IFTTT 与我们的树莓派集成的一种方法是使用 dweet.io 服务。我们在第二章中介绍了 dweet.io 以及 Python 示例，*使用 Python 和物联网入门*。

简而言之，我们将如何在 IFTTT Webhook 中使用 dweet.io 以及我们的 Python 代码：

1.  在我们的 IFTTT Webhook 中，我们将使用 dweet.io URL 发布一个 dweet（包含打开、关闭或使 LED 闪烁的指令）。

1.  我们的树莓派将运行 Python 代码来检索 IFTTT Webhook 发布的 dweet。

1.  然后，我们的代码将根据 dweet 中指定的命令控制 LED。

这是我们示例中将要使用的方法。这种方法的优势在于我们无需担心在路由器上配置防火墙和端口转发规则。此外，这意味着我们可以在工作环境等环境中运行示例，而在这些环境中，路由器配置可能不切实际甚至不可能。

我们将在`chapter13/dweet_led.py`文件中使用此基于 dweet.io 的集成的代码，该文件是第二章中`chapter02/dweet_led.py`文件的精确副本，*使用 Python 和物联网入门*。

## **方法 2 - 创建 Flask-RESTful 服务**

要使用这种方法，我们需要创建一个类似于我们在第三章中所做的 RESTful 服务，*使用 Flask 进行 RESTful API 和 Web 套接字服务*（`chapter02/flask_api_server.py`中的代码，它改变 LED 的亮度（而不是设置为开/关/闪烁），将是一个很好的起点）。

我们还需要将我们的树莓派暴露到公共互联网，这将需要我们在本地防火墙或路由器中打开一个端口并创建一个端口转发规则。然后，连同我们的公共 IP（或域名），我们可以构建一个 URL，并直接将其与 IFTTT Webhook 服务一起使用。

对于原型设计和创建演示，一个简单的替代方法是使用本地隧道（[localtunnel.github.io/www](https://localtunnel.github.io/www/)）或 ngrok（[ngrok.com](https://ngrok.com/)）这样的服务，而不是打开防火墙和创建端口转发规则，这些服务可以帮助您将设备暴露到互联网上。

由于这种方法需要您进行配置和设置，这超出了我们作为本章的一部分可以实际完成的范围，因此我们将坚持使用前一节中显示的 dweet.io 方法。

接下来，我们将创建一个电路，我们可以在第二个 IFTTT Applet 中使用，我们将很快构建它。

## 创建 LED 电路

我们即将介绍的示例将需要一个 LED，以及连接到 GPIO 引脚（对于我们的示例是 GPIO 21）的一系列电阻。我相信，考虑到我们在本书中已经多次构建了 LED 电路，你可以毫无问题地自己完成这个连接！（如果你需要提醒，请参见第二章中的*图 2.7*，*使用 Python 和物联网入门*）

保留您为我们第一个 IFTTT Applet 示例创建的 DHT 11/DHT 22 电路，因为我们将在本章后面再次重用此电路。

当您的电路准备好后，我们将继续并运行我们的示例程序。

## 运行 IFTTT 和 LED Python 程序

在本节中，我们将运行我们的程序，并获取用于 dweet.io 服务的唯一物名称和 URL。

以下是要遵循的步骤：

1.  在终端中运行`chapter13/dweet_led.py`文件中的代码。您将收到类似以下内容的输出（您的*物名称*和因此您的 URL 将不同）：

```py
(venv) $ python dweet_led.py
INFO:main:Created new thing name 749b5e60
LED Control URLs - Try them in your web browser:
  On : https://dweet.io/dweet/for/749b5e60?state=on
  Off : https://dweet.io/dweet/for/749b5e60?state=off
  Blink : https://dweet.io/dweet/for/749b5e60?state=blink
```

正如我们之前提到的，`chapter13/dweet_led.py`是我们在第二章中讨论的相同程序的精确副本，*使用 Python 和物联网入门*。如果您需要更多关于这个程序如何工作的上下文，请重新阅读那一章和其中包含的代码讨论。

1.  保持终端打开并运行程序，因为我们将需要在下一节中复制其中一个 URL。我们还需要运行程序来测试我们即将进行的集成。

接下来，我们将创建另一个 IFTTT Applet，通过 dweet.io 与该程序集成。

## 创建 IFTTT Applet

我们即将创建另一个 IFTTT Applet。整个过程与我们之前创建的 Applet 非常相似，只是我们的树莓派（通过 Webhook 集成）将位于 Applet 的*That*端，如*图 13.16*所示。

以下是我们需要遵循的步骤来创建我们的下一个 Applet。由于它们与我们之前创建的 IFTTT Applet 过程非常相似，这次我省略了许多常见的屏幕截图：

1.  登录到 IFTTT 后，点击个人资料头像图标，然后从下拉菜单中选择创建。

1.  在 If + This Then Than 页面上，点击+图标。

1.  在“选择服务”页面上，搜索并选择“电子邮件”服务。

1.  在选择触发器页面上，选择发送带标签的 IFTTT 电子邮件（确保选项中包含这个词*tagged)。

1.  在下一页中，输入 LED 作为标签输入，然后点击创建触发器按钮：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/9872195c-9014-4066-82d4-be7c02ba6851.png)

图 13.17 - 完成触发字段页面

1.  在 If <email icon> This Then + Than 页面上，点击+图标。

1.  在选择操作服务页面上，搜索并选择 Webhooks 服务。

1.  接下来，在选择操作页面上，选择进行网络请求。

1.  接下来你会遇到的页面叫做“完成操作字段”。这是我们将使用上一节中程序打印到终端的 dweet URL 的地方：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/25679560-23f0-4fd6-a3ac-186c87fd8f50.png)

图 13.18 - 完成操作字段页面

以下是您需要遵循的子步骤，以完成此页面上的字段：

1.  1.  从终端复制 On URL（例如，`https://dweet.io/dweet/for/749b5e60?state=on` - 注意您的*thing name*将不同）。

1.  将此 URL 粘贴到 IFTTT URL 字段中。

1.  在 URL 字段中，删除单词 on（所以 URL 现在是 https://dweet.io/dweet/for/749b5e60?state=）。

1.  点击添加成分按钮（在 URL 字段下），选择主题（使 URL 现在为 https://dweet.io/dweet/for/749b5e60?state={{Subject}}）。

1.  其他字段可以保留为默认值。

1.  点击创建操作按钮：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/6c62931d-4dd8-4985-b603-25fccede7dfe.png)

图 13.19 - 完成操作字段页面

1.  最后，在“审查和完成”页面上，点击“完成”按钮。

干得好！我们现在创建了第二个 Applet。接下来，我们将使用这个 Applet 通过发送电子邮件来控制我们的 LED，指示 LED 打开、关闭或闪烁。

## 从电子邮件控制 LED

现在我们已经创建了一个 Applet 来通过电子邮件控制 LED，是时候测试集成了。

以下是创建电子邮件的步骤：

1.  确保`chapter13/dweet_led.py`文件中的程序仍在终端中运行。

1.  打开您喜欢的电子邮件程序并创建新邮件。

1.  使用`trigger@applet.ifttt.com`作为电子邮件的收件人地址。

当向 IFTTT 发送触发电子邮件时，它必须来自您在 IFTTT 中使用的相同电子邮件地址（您可以访问[`ifttt.com/settings`](https://ifttt.com/settings)来检查您的电子邮件地址）。

1.  作为主题，使用以下内容之一来控制 LED：

+   `#LED On`

+   `#LED Off`

+   `#LED Blink`

IFTTT 会去掉#LED 标签，因此我们的`dweet_led.py`程序只会收到打开、关闭或闪烁的文本。在我们的 Python 代码中，前导空格被去掉。

以下截图显示了一个使 LED 闪烁的示例电子邮件：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/052d8aed-d735-4e38-8e56-1d389ac4afd4.png)

13.20 - 触发电子邮件示例

1.  发送电子邮件。

1.  等一会儿，LED 将改变状态。

现在我们已经学会了如何通过电子邮件使用 IFTTT 来控制我们的 LED，让我们快速介绍一些故障排除技巧。

## IFTTT 故障排除

如果您的 IFTTT Applets 似乎没有触发和执行操作，这里有一些故障排除途径供您探索和尝试：

+   在`dweet_led.py`中，尝试以下操作：

+   打开调试日志记录；例如，`logger.setLevel(logging.DEBUG)`。

+   更改源文件末尾附近的 dweet 检索方法。如果您正在使用`stream_dweets_forever()`，请尝试改用`poll_dweets_forever()`，因为它对瞬时连接问题更具弹性。

+   在 IFTTT 网站上，您可以通过以下方式检查任何 Applet 的活动日志：

1.  导航到个人资料菜单下的我的服务选项

1.  选择一个服务（例如，Webhooks）

1.  选择要检查的 Applet

1.  点击设置按钮

1.  点击查看活动按钮和/或尝试立即检查按钮

+   您还可以查看以下 IFTTT 资源：

+   *常见错误和故障排除提示*，请访问[`help.ifttt.com/hc/en-us/articles/115010194547-Common-errors-and-troubleshooting-tips`](https://help.ifttt.com/hc/en-us/articles/115010194547-Common-errors-and-troubleshooting-tips)

+   *故障排除 Applets & Services*，请访问[`help.ifttt.com/hc/en-us/categories/115001569887-Troubleshooting-Applets-Services`](https://help.ifttt.com/hc/en-us/categories/115001569887-Troubleshooting-Applets-Services)。

IFTTT 还有一个*最佳实践*页面，您可以在[`help.ifttt.com/hc/en-us/categories/115001569787-Best-Practices`](https://help.ifttt.com/hc/en-us/categories/115001569787-Best-Practices)上了解更多关于该平台的信息。

在我们讨论了*从树莓派触发 IFTTT Applet*部分之后，对于 IFTTT *触发器*，您可以采用我们刚刚介绍的相同的整体流程来执行您的树莓派，以便从任何 IFTTT 配方中采取行动。再次查看[`ifttt.com/discover`](https://ifttt.com/discover)以获取一些想法，这一次，请记住，从我们的角度来看，我们在 IFTTT 配方中使用*Webhook*操作来控制我们的树莓派。这里有一个例子-使用 Google 助手语音控制您的树莓派！哦，等一下-我们将在下一章第十四章中做到这一点-将所有内容联系在一起-物联网圣诞树！

我们已经探讨了如何以两种方式将我们的树莓派与 IFTTT 集成-作为*This*角色来触发 Applet，以及在*That*角色中，我们可以从触发的 Applet 中执行我们的树莓派。接下来，我们将看一种方法来创建一个物联网仪表板，我们可以用来可视化数据。

# 使用 ThingSpeak 平台可视化数据

我们刚刚学习了如何使用 IFTTT 平台创建简单的自动化。在本节中，我们将与 ThingSpeak 平台集成，以可视化显示我们将使用 DHT 11 或 DHT 22 传感器收集的温度和湿度数据。我们将使用我们在本章前面创建的 DHT 11/DHT 22 电路。

ThingSpeak([thingspeak.com](https://thingspeak.com))是一个数据可视化、聚合和分析平台。我们将专注于数据可视化方面，特别是如何将我们的树莓派集成到该平台中。

我选择在本节中以 ThingSpeak 为例的原因有几个-它简单易用，并且对于我们将要做的简单数据可视化来说，它是免费的。还有许多其他可用的可视化平台，它们都有自己独特的功能、定价结构和复杂性。我在*其他物联网和自动化平台供进一步探索*部分中包含了一些建议供您探索。

如果您希望更深入地探索聚合和分析功能，您可以通过搜索 ThingSpeak 找到许多优质的示例、教程和文档。作为建议，从[`au.mathworks.com/help/thingspeak`](https://au.mathworks.com/help/thingspeak)开始您的调查。

我们将在下面的屏幕截图中看到我们将要创建的仪表板的一个示例。请注意标签栏中显示的通道设置和 API 密钥项目-我们将很快提到这些标签：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/305142c2-ad8f-41e8-862f-11f3a9a9361f.png)

图 13.21-ThingSpeak 通道仪表板

在我们可以集成我们的树莓派并将数据发送到 ThingSpeak 之前，我们的第一站是为我们的集成配置平台。

## 配置 ThinkSpeak 平台

配置 ThinkSpeak 相对简单-事实上，这是我遇到的同类平台中最简单的之一。以下是我们需要遵循的步骤：

1.  首先，您需要为自己创建一个 ThingSpeak 账户。访问他们的网站[thingspeak.com](https://thingspeak.com)，然后点击“注册”按钮。

1.  一旦您创建了 ThinkSpeak 账户并登录到平台，您应该会登陆到“我的通道”页面；也就是[`thingspeak.com/channels`](https://thingspeak.com/channels)。

在 ThingSpeak 生态系统中，*通道*是我们存储数据、仪表板和可视化的虚拟位置。这类似于一个工作区。

1.  接下来，我们需要点击“新通道”按钮创建一个新通道：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/d34b6031-bbfc-4569-bcbb-f8f95f37d3ba.png)

图 13.22-ThingSpeak 通道配置

在新通道页面上，输入以下详细信息：

+   +   名称：`环境数据`（或您选择的任何名称）

+   字段 1：`温度`

+   字段 2：`湿度`

您可以将所有其他字段保留为默认值。

如果以后需要查看或更改通道设置，可以在通道设置选项卡中找到，如*图 13.19.*中所示。

1.  填写完字段后，滚动到页面底部，然后单击“保存通道”按钮。您将看到一个类似于*图 13.19*的页面，只是没有数据，是空白的。

要在*图 13.19*中看到的两个表中添加两个表，请执行以下操作：

1.  1.  按“添加小部件”按钮。

1.  选择“仪表”图标，然后按“下一步”。

1.  在“配置小部件参数”对话框中，输入仪表的名称（例如`温度`），并选择适当的字段编号（温度为 Field1，湿度为 Field2）。

1.  您可以根据需要调整和实验其他参数，以设置仪表的最大/最小范围、颜色和其他显示属性。

1.  为第二个表重复该过程。

如果仪表（或图表）显示“字段值不可用”，不要担心。这是正确的，因为我们还没有向 ThingSpeak 发送任何温度或湿度数据。

1.  现在，是时候获取 API 密钥和通道 ID 了，我们需要这些信息来配置即将到来的 Python 代码。点击 API 密钥选项卡：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/71b5fdb4-937a-4b6a-8dc4-fc7b4f0bf64e.png)

图 13.21 - API 密钥选项卡

这是我们的 Python 程序需要收集的信息：

+   +   写 API 密钥（因为我们将向平台*写入*数据）

+   通道 ID（这在所有 ThinkSpeak 页面上都有，靠近顶部）

现在我们已经创建并配置了一个简单的 ThinkSpeak 通道，并收集了我们的 API 密钥和通道 ID，我们可以继续进行 Python 代码。

## 配置和运行 ThinkSpeak Python 程序

我们提供了两个样本程序，可以与 ThinkSpeak 集成。它们如下：

+   `chapter13/thingspeak_dht_mqtt.py`：一个使用 MQTT 将数据发送到 ThinkSpeak 通道的示例。

+   `chapter13/thingspeak_dht_http.py`：一个使用 Python 请求库进行 RESTful API 调用，将数据发送到 ThinkSpeak 通道的示例。

这两个程序的核心概念在早期章节中已经讨论过。供您参考，它们如下：

+   **MQTT**：我们在第四章中讨论了 Paho-MQTT 库，*使用 MQTT、Python 和 Mosquitto MQTT 代理进行网络通信*。本章的一个关键区别是，我们使用 Paho-MQTT *简化客户端包装器*来发布 MQTT 消息，而不是完整的生命周期示例。

+   我们在第二章中介绍了 RESTful API 和请求库，*Python 和物联网入门*。

+   有关 DHT 11/DHT 22 温湿度传感器的代码在第九章中已经涵盖了，*测量温度、湿度和光照水平*。

让我们配置这些程序，运行它们，并在 ThingSpeak 中看到数据。我们将演示`chapter13/thingspeak_dht_mqtt.py`中提供的示例代码；但是，对于`chapter13/thingspeak_dht_http.py`，整个过程都是相同的：

1.  打开`chapter13/thingspeak_dht_mqtt.py`文件进行编辑。

1.  在文件顶部附近，找到以下代码，从第（1）行开始，并确认您的 DHT 传感器连接到正确的 GPIO 引脚，并且正确的传感器实例在代码中启用：

```py
# DHT Temperature/Humidity Sensor
GPIO = 24                                                   # (1)
#dht = DHT11(GPIO, use_internal_pullup=True, timeout_secs=0.5)
dht = DHT22(GPIO, use_internal_pullup=True, timeout_secs=0.5)
```

1.  接下来，找到以下代码段，从第（2）行开始，并使用您的 ThingSpeak 写 API 密钥、通道 ID 和时区进行更新。请注意，`CHANNEL_ID`仅在 MQTT 集成中使用（因此它不会出现在`thingspeak_dht_http.py`文件中）：

```py
# ThingSpeak Configuration
WRITE_API_KEY = "" # <<<< ADD YOUR WRITE API KEY HERE   # (2)
CHANNEL_ID = ""    # <<<< ADD YOUR CHANNEL ID HERE

# See for values https://au.mathworks.com/help/thingspeak/time-zones-reference.html
TIME_ZONE = "Australia/Melbourne"
```

1.  保存文件并运行程序。您应该会收到类似以下内容的输出：

```py
(venv) $ python thing_speak_dht_mqtt.py
INFO:root:Collecting Data and Sending to ThingSpeak every 600 seconds. Press Control + C to Exit
INFO:root:Sensor result {'temp_c': 25.3, 'temp_f': 77.5, 'humidity': 43.9, 'valid': True}
INFO:root:Published to mqtt.thingspeak.com
```

1.  几秒钟后，您应该会在 ThingSpeak 仪表板上看到您的数据出现！

恭喜！通过这样，你已经创建了一个 ThingSpeak 仪表板来可视化树莓派收集的数据。对于许多监控物联网项目来说，可视化数据是一个经常的需求，无论是简单的指示器显示，比如表盘，还是生成历史图表来可视化趋势。你如何处理数据的可视化完全取决于你的需求；然而，所有这些需求共同的一点是，有许多现成的服务，如 ThingSpeak，可以帮助你实现这一点，而不是自己定制编码仪表板和可视化应用。

现在，我将用一个简短的讨论来结束这一章，讨论一些其他流行的物联网平台，你可能会喜欢在未来的项目中探索和使用。

# 其他物联网和自动化平台供进一步探索

到目前为止，在本章中，我们已经看到了 IFTTT 和 ThingSpeak 的运作方式，以及如何将它们与我们的树莓派集成。我们看到了如何使用 IFTTT 创建简单的工作流程，以及如何使用 ThingSpeak 可视化数据——两个非常不同的想法，但它们都是物联网平台。

这两个平台都非常强大，并提供了广泛的功能和可能性，超出了我们在一个章节中所能涵盖的范围，所以我鼓励你查阅它们的文档和示例，以提升你的学习。

还有许多其他可用的物联网平台、应用程序和框架。本节将根据我的经验提供一个简短的策划清单。它们都与本书的 Python 和树莓派主题很好地契合。

## **Zapier**

我们已经看到了 IFTTT 的运作方式。在支持的服务方面，IFTTT 更加面向消费者，而且正如我们所见，我们受限于单个 *This* 触发器和单个 *That* 动作。

Zappier 在原则上与 IFTTT 非常相似，但更加注重商业，包括一系列服务和集成，这些在 IFTTT 中不可用（IFTTT 也有独特的服务和集成）。此外，Zapier 还能够触发事件和动作的更复杂工作流程。

你会发现重新实现本章中我们的两个 IFTTT 示例在 Zappier 中相对简单。

网站：[`zapier.com`](https://zapier.com)。

## **IFTTT 平台**

在本章中，我们使用 IFTTT 作为最终用户，并使用 Webhooks 进行集成。如果你是一家希望创建作为一流 IFTTT 服务公开的小工具的企业，那么你应该了解一下 IFTTT 平台。

网站：[`platform.ifttt.com`](https://platform.ifttt.com)。

## **ThingsBoard 物联网平台**

ThingsBoard 是一个开源的物联网平台，你可以在树莓派上下载和托管。从表面上看，它将允许你构建仪表板和数据可视化，就像我们在 ThingSpeak 中所做的那样。与 ThingSpeak 相比，你会发现 ThingsBoard 在创建你的第一个仪表板时有一个更陡的学习曲线；然而，你也会发现它提供了更广泛的小部件和自定义选项。此外，与只能消耗数据的 ThingSpeak 不同，ThingsBoard 允许你将控件嵌入到仪表板中，让你使用 MQTT 与你的树莓派进行交互。

根据经验，如果你想学习如何使用这个平台，那么你必须仔细阅读 ThingsBoard 的文档和教程（许多都是视频），因为在你第一次访问其用户界面时，不会立即明显你需要做什么。

以下是他们网站上的一些具体资源：

+   树莓派安装说明：[`thingsboard.io/docs/user-guide/install/rpi`](https://thingsboard.io/docs/user-guide/install/rpi)（不用担心它说的是树莓派 3；它在 4 上也能运行）

+   入门指南：[`thingsboard.io/docs/getting-started-guides/helloworld`](https://thingsboard.io/docs/getting-started-guides/helloworld)

在入门指南中没有 Python 特定的示例，但有 Mosquito MQTT 示例和 cURL 示例，演示了 RESTful API。建议使用本章中提供的两个 ThingSpeak 代码示例作为起点，并采用它们来使用 ThingBoard 特定的 MQTT 和/或 RESTful API。

网站：[`thingsboard.io`](https://thingsboard.io)。

## **Home Assistant**

Home Assistant 是一个纯 Python 家庭自动化套件。Home Assistant 可以与各种互联网设备连接，如灯、门、冰箱和咖啡机 - 仅举几例。

Home Assistant 在这里得到提及，不仅因为它是用 Python 构建的，而且因为它允许我们直接与主机树莓派的 GPIO 引脚集成，以及使用 PiGPIO 的远程 GPIO 功能与远程树莓派的 GPIO 引脚集成。此外，还有 MQTT 和 RESTful API 集成选项。

虽然在概念和最终用户操作上很简单，但是在配置 Home Assistant 时存在较高的学习曲线（需要相当多的实验），因为大多数集成是通过直接编辑**YAML Ain't Markup Language**（**YAML**）文件来完成的。

关于 GPIO 集成，我从他们的网站上选择了一些资源来帮助您入门。我建议先阅读术语表，因为这将帮助您更好地理解 Home Assistant 的术语，从而帮助您更好地理解文档的其他部分：

+   安装：Home Assistant 可以以多种方式安装。为了测试平台并构建 GPIO 集成，我建议选择“虚拟环境”选项，文档位于[`www.home-assistant.io/docs/installation/virtualenv`](https://www.home-assistant.io/docs/installation/virtualenv)。

+   术语表：[`www.home-assistant.io/docs/glossary`](https://www.home-assistant.io/docs/glossary)。

+   可用的树莓派集成：[`www.home-assistant.io/integrations/#search/Raspberry%20Pi`](https://www.home-assistant.io/integrations/#search/Raspberry%20Pi)。

网站：[`www.home-assistant.io`](https://www.home-assistant.io)。

## **亚马逊网络服务（AWS）**

另一个建议是亚马逊网络服务，具体来说是两项服务 - IoT Core 和 Elastic Beanstalk。这些选项将为您提供巨大的灵活性和几乎无穷无尽的选择，当涉及到创建物联网应用程序时。IoT Core 是亚马逊的物联网平台，您可以在其中创建仪表板、工作流和集成，而 Elastic Beanstalk 是他们的云平台，您可以在其中托管自己的程序 - 包括 Python - 在云中。

亚马逊网络服务是一个先进的开发平台，因此您需要投入几周的时间来学习它的工作原理，以及如何使用它构建和部署应用程序，但我可以向您保证，在这个过程中您会学到很多！此外，他们的文档和教程质量非常高。

亚马逊物联网核心：[`aws.amazon.com/iot-core`](https://aws.amazon.com/iot-core)。

亚马逊弹性 Beanstalk：[`aws.amazon.com/elasticbeanstalk`](https://aws.amazon.com/elasticbeanstalk)。

## **Microsoft Azure、IBM Watson 和 Google Cloud**

最后，我想提一下其他 IT 巨头，他们都提供自己的云和物联网平台。我之所以建议 AWS，纯粹是因为我对这个平台有更深入的经验。微软、IBM 和谷歌提供的比较平台也是高质量的，并且有着优秀的文档和教程支持，因此如果您个人偏好于这些提供商中的一个，您仍然是安全的。

# 摘要

在本章中，我们探讨并学习了如何将我们的 Raspberry Pi 与 IFTTT 和 ThinkSpeak IoT 平台一起使用。我们创建了两个 IFTTT 示例，其中我们的 Raspberry Pi 在 IFTTT Applet 中执行了*This*角色，以启动 IFTTT 工作流程。我们还看到了如何将我们的 Raspberry Pi 用作*That*角色，以便它可以被 IFTTT Applet 执行。接下来，我们介绍了如何与 ThinkSpeak IoT 平台集成，以可视化由我们的 Raspberry Pi 收集的温度和湿度数据的示例。最后，我们讨论了您可能希望调查和实验的其他 IoT 平台选项。

在本章中，我们确实只涵盖了可视化和自动化平台可能性的基础知识。我鼓励你寻找更多的 IFTTT 示例和你可以尝试的想法，并探索我们提到的其他平台。请记住，虽然每个平台都会有所不同并且有自己的集成考虑，但通常接受的实现集成的标准是 RESTful API 和 MQTT，这两者你现在都有经验了！

在下一章中，我们将涵盖一个全面的端到端示例，汇集了本书中涵盖的许多概念和示例。

# 问题

随着我们结束本章，这里有一些问题供你测试对本章材料的了解。你将在*附录*的*评估*部分找到答案：

1.  在我们的第一个 IFTTT Applet 中，我们监测温度时为什么使用了不同的高温和低温值来触发我们的 Applet 并发送电子邮件？

1.  使用像 dweet.io 这样的中介服务与我们的 IFTTT Webhook 服务有什么优势？

1.  IFTTT 和 Zapier 之间的一些核心区别是什么？

1.  你能从 ThingSpeak 仪表板控制你的 Raspberry Pi 吗？

1.  关于数据，当 IFTTT Webhook 服务用作动作（即 applet 的*That*一侧）时有什么限制？

1.  你想要原型化基于 Raspberry Pi 的 GPIO 引脚状态来开关柜台智能灯泡。你可以使用哪些平台？


# 第十四章：将所有内容联系在一起-物联网圣诞树

欢迎来到我们的最后一章！我们将通过整合前几章的各种主题和想法来完成本书，以构建一个多方面的物联网程序。具体来说，我们将构建一个可以通过互联网控制的圣诞树，一个*IoTree*，如果你不介意的话！

本章中我们的方法是重用前几章的两个电路，以创建圣诞树灯光（使用 APA102 LED 灯带）和一个摇摆机制来使树摇晃（我们将使用舵机）和发出叮当声（好吧，如果你用铃铛装饰树，它会在摇晃时发出叮当声！）。然后我们将重新审视和调整我们关于 RESTful API 和 MQTT 的学习，以创建两种方式来通过网络或互联网控制灯光和舵机。然后我们将重新审视 dweet.io 和**If-This-Then-That**（**IFTTT**）并构建 IFTTT Applets 来通过电子邮件和您的声音使用 Google 助手来控制树！

以下是本章将涵盖的内容：

+   物联网圣诞树概述

+   构建 IoTree 电路

+   配置、运行和使用 Tree API 服务

+   配置、运行和使用 Tree MQTT 服务

+   将 IoTree 与 dweet.io 集成

+   与电子邮件和 Google 助手通过 IFTTT 集成

+   扩展您的 IoTree 的想法和建议

# 技术要求

要执行本章的练习，您需要以下内容：

+   树莓派 4 Model B

+   Raspbian OS Buster（带桌面和推荐软件）

+   最低 Python 版本 3.5

这些要求是本书中代码示例的基础。可以合理地期望，只要您的 Python 版本是 3.5 或更高，代码示例应该可以在树莓派 3 Model B 或不同版本的 Raspbian OS 上无需修改地工作。

要完成标题为*与 Google 助手集成*的部分，至少需要以下先决条件：

+   一个 Google 账户（如果您有 Gmail 邮箱账户，那就是您需要的全部）

+   安卓手机或 iOS 的*Google 助手*应用

您将在 GitHub 存储库的`chapter14`文件夹中找到本章的源代码，链接在这里：[`github.com/PacktPublishing/Practical-Python-Programming-for-IoT`](https://github.com/PacktPublishing/Practical-Python-Programming-for-IoT)。

您需要在终端中执行以下命令来设置虚拟环境并安装本章代码所需的 Python 库：

```py
$ cd chapter14              # Change into this chapter's folder
$ python3 -m venv venv      # Create Python Virtual Environment
$ source venv/bin/activate  # Activate Python Virtual Environment
(venv) $ pip install pip --upgrade        # Upgrade pip
(venv) $ pip install -r requirements.txt  # Install dependent packages
```

以下依赖项从`requirements.txt`中安装：

+   **PiGPIO**：PiGPIO GPIO 库（[`pypi.org/project/pigpio`](https://pypi.org/project/pigpio)）

+   **Flask-RESTful**：用于创建 RESTful API 服务的 Flask 扩展（[`pypi.org/project/Flask-RESTful`](https://pypi.org/project/Flask-RESTful)）

+   **Paho MQTT** **客户端**：[`pypi.org/project/paho-mqtt`](https://pypi.org/project/paho-mqtt)

+   **Pillow**：**Python Imaging Library**（**PIL**）（[`pypi.org/project/Pillow`](https://pypi.org/project/Pillow)）

+   **Luma LED Matrix 库**：[`pypi.org/project/luma.led_matrix`](https://pypi.org/project/luma.led_matrix)

+   **Requests**：用于发出 HTTP 请求的高级 Python 库（[`pypi.org/project/requests`](https://pypi.org/project/requests)）

+   **PyPubSub**：进程内消息传递和事件（[`pypi.org/project/PyPubSub`](https://pypi.org/project/PyPubSub)）

本章练习所需的电子元件如下：

+   1 x MG90S 爱好舵机（或等效的 3 线、5 伏特爱好舵机）

+   1 x APA102 RGB LED 灯带

+   1 x 逻辑电平转换模块

+   外部电源供应（至少是 3.3V/5V 面包板可安装的电源供应）

视频展示了这棵树的运作情况，网址是[`youtu.be/15Xfuf_99Io`](https://youtu.be/15Xfuf_99Io)。请注意，这棵树使用 RGB LED 和交替闪烁的灯光动画。在本章中，我们将使用 APA102 LED 灯带，它能够创建更多的动画效果。演示树还可以演奏曲调，但我们在本章不会涉及（尽管您可以轻松地通过采用第八章中的 RTTTL 示例来添加该功能）。

# IoT 圣诞树概述

在我们通过构建电路和查看代码来开始本章之前，让我们花一点时间了解一下我们的 IoTree 将会做什么以及我们将如何构建它。*图 14.1*中的树代表了您在完成本章后可能创建的东西：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/2af4c674-ab83-40e1-9837-9b9aae3983d3.png)

图 14.1 - IoTree 示例

现在，我需要提前告诉您，我们只会涵盖 IoTree 的电子和编程部分。您需要发挥自己的主动性，并发挥您的制造技能来建造这棵树并让它活起来。我建议使用一棵小桌面圣诞树，因为我们的构建部分涉及使用伺服机来*摇晃*树。我们的业余级伺服机足够强大，可以摇动一棵小树；但是，它不太可能能够摇动一棵全尺寸的圣诞树（如果您希望将我们的构建升级到更大的树，请研究并获得更强大的伺服机，并且如果您这样做，请给我发一张照片！）。

我们的基本树将包括以下电子组件：

+   用于树灯的 APA102 LED 灯带（我们在第八章中介绍了 APA102 LED 灯带，*灯光、指示灯和信息显示*）。

+   一个伺服机使树*摇晃*和*叮当作响* - 为此，您需要在树上放一些铃铛装饰品，当树摇晃时它们会*叮当作响*（我们在第十章中介绍了伺服机，*使用伺服机、电机和步进电机进行运动*）。

在程序和结构上，我们的树程序将借鉴我们学到的以下概念：

+   **dweet.io 服务**：首次介绍于第二章，*Python 和 IoT 入门*，并在第十三章，*IoT 可视化和自动化平台*中重新讨论

+   **使用 Flask-RESTful 的 RESTful API**：来自第三章，*使用 Flask 进行 RESTful API 和 Web 套接字进行网络连接*

+   **消息队列遥测传输（MQTT）**：在第四章中介绍，*使用 MQTT、Python 和 Mosquitto MQTT 代理进行网络连接*。

+   **IoT 程序的线程和发布-订阅（PubSub）方法**：在第十二章中介绍，*高级 IoT 编程概念-线程、AsyncIO 和事件循环*

+   **IFTTT IoT 平台**：在第十三章中介绍，*IoT 可视化和自动化平台*

在我们继续本章之前，我们将假设您已经理解了前述每一章的概念，并且已经完成了每一章中提出的练习，包括构建电路和理解使电路工作的电路和代码级概念。

我们的第一个任务将是构建 IoTree 所需的电路，接下来我们将进行。

# 构建 IoTree 电路

是时候开始建设了！请构建*图 14.2*中所示的电路：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/9ee79d65-a7e4-46a2-9fbd-6d89308d52be.png)

图 14.2 - IoTree 电路原理图

这个电路应该看起来很熟悉。它是我们之前见过的两个电路的组合：

+   来自*图 8.4*的 APA102（带逻辑电平转换器）电路，位于第八章中，*灯光、指示灯和信息显示*

+   来自*图 10.2*的舵机电路，位于第十章中，*使用舵机、电机和步进电机进行运动*

如果您需要逐步构建面包板上的电路的说明，请参阅相应的章节。

请记住，您需要使用外部电源来为 APA102 和舵机供电，因为它们会吸取太多的电流，无法使用树莓派的 5 伏引脚。

当您完成电路构建后，接下来让我们简要讨论三个可以用来控制此电路的程序。

## 三个 IoTree 服务程序

有三个单独的程序来配合我们的 IoTree，每个程序都采用了稍微不同的方法来处理我们的灯光和舵机。这些程序如下：

+   **Tree API 服务**（位于`chapter14/tree_api_service`文件夹中）：此程序提供了一个使用 Flask-RESTful 创建的 RESTful API，用于控制灯光和舵机。它还包括一个使用 API 的基本 HTML 和 JavaScript Web 应用程序。我们将在标题为*配置、运行和使用 Tree API 服务*的部分进一步讨论 Tree API 服务。

+   **Tree MQTT 服务**（位于`chapter14/tree_mqtt_service`文件夹中）：此程序将允许我们通过发布 MQTT 消息来控制灯光和舵机。我们将在标题为*配置、运行和使用 Tree MQTT 服务*的部分进一步讨论 Tree MQTT 服务。

+   **dweet 集成服务**（位于`chapter14/dweet_integration_service`文件夹中）：此程序接收 dweets 并将它们重新发布为 MQTT 消息。我们可以将此程序与*Tree MQTT 服务*程序一起使用，以使用 dweet.io 来控制我们的灯光和舵机，从而为我们提供了一种将 IoTree 与 IFTTT 等服务集成的简单方法。我们将在标题为*将 IoTree 与 dweet.io 集成*的部分进一步讨论 dweet 集成服务。

现在我们已经简要讨论了构成本章示例的程序，让我们配置和运行我们的 Tree API 服务，并使用它来使灯光和舵机工作。

# 配置、运行和使用 Tree API 服务

Tree API 服务程序为控制我们的 IoTree 的 APA102 LED 灯带和舵机提供了一个 RESTful API 服务。您可以在`chapter14/tree_api_service`文件夹中找到 Tree API 服务程序。它包含以下文件：

+   `README.md`：Tree API 服务程序的完整 API 文档，包括示例。

+   `main.py`：这是程序的主要入口点。

+   `config.py`：程序配置。

+   `apa102.py`：与 APA102 LED 灯带集成的 Python 类。这段代码的核心与我们在第八章中探讨的 APA102 Python 代码非常相似，只是现在它被构造为 Python 类，使用线程来运行灯光动画，还有一些其他小的添加，比如让 LED 闪烁的代码。

+   `apa102_api.py`：提供 APA102 API 的 Flask-RESTful 资源类。它借鉴了第三章中 Flask-RESTful 代码和示例，*使用 Flask 进行 RESTful API 和 Web 套接字的网络*

+   `servo.py`：用于控制舵机的 Python 类。它借鉴了我们在第十章中介绍的舵机代码。

+   `servo_api.py`：提供舵机 API 的 Flask-RESTful 资源类。

+   `模板`：此文件夹包含示例 Web 应用程序的`index.html`文件。

+   `static`：此文件夹包含 Web 应用程序使用的静态 JavaScript 库和图像。

图 14.3 显示了 Tree API 服务程序架构的图表：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/2ad54f4a-949b-4ead-a32f-55220cd18170.png)

图 14.3 - Tree API 服务架构块图

这是 Tree API 服务的高级操作，用于前面图表中显示的 API 请求：

1.  外部客户端向#1 处的`/lights/colors`端点发出 POST 请求。

1.  请求由 Flask 框架/服务器在#2 处处理。（Flask 和 Flask-RESTful 的设置可以在`main.py`中找到。）

1.  `/lights/*`端点被路由到适当的 Flask-RESTful 资源#3（APA102 - 也就是*light* - 资源在`apa102_api.py`中定义）。端点设置和资源注册在`main.py`中找到。

1.  在#4 处，调用适当的资源（在本例中，将是`ColorControl.post()`），然后解析和验证查询字符串参数（即`colors=red%20blue&pattern=yes`）。

1.  最后，在#5 处，`ColorControl.post()`调用 APA102 的实例中的适当方法（在`apa102.py`中定义，并在`main.py`中设置），直接与物理 APA102 LED 灯带接口并更新重复的红色和蓝色模式。

现在我们了解了我们的 Tree API 服务的工作原理，在运行 Tree API 服务之前，首先需要检查它的配置。我们接下来会做这个。

## 配置 Tree API 服务

Tree API 服务配置在`chapter14/tree_api_service/config.py`文件中。在这个文件中有许多配置选项，它们大多与 APA102（在第八章中讨论）和舵机（在第十章中讨论）的配置有关。你会发现这个文件和配置选项都有很好的注释。

默认配置足以在树莓派上本地运行示例；但是，你应该检查的一个配置参数是`APA102_NUM_LEDS = 60`。如果你的 APA102 LED 灯带包含不同数量的 LED，那么请相应地更新此配置。

让我们运行 Tree API 服务程序并创建一些灯光（和移动）！

## 运行 Tree API 服务

现在是时候运行 Tree API 服务程序并发送 RESTful API 请求使其工作了。以下是运行和测试我们的 Tree API 服务的步骤：

1.  切换到`chapter14/tree_api_service`文件夹并启动`main.py`脚本，如下所示：

```py
# Terminal 1
(venv) $ cd tree_api_service
(venv) $ python main.py
* Serving Flask app "main" (lazy loading)
... truncated ...
INFO:werkzeug: * Running on http://0.0.0.0:5000/ (Press CTRL+C to quit)
```

1.  接下来，打开第二个终端并运行以下`curl`命令，将重复的灯光模式序列设置为`红色，蓝色，黑色`：

```py
# Terminal 2
$ curl -X POST "http://localhost:5000/lights/color?colors=red,blue,black&pattern=yes"
```

1.  同样在*终端 2*中，运行下一个命令开始让灯光动画起来：

```py
# Terminal 2
$ curl -X POST "http://localhost:5000/lights/animation?mode=left&speed=5"
```

除了`left`，你还可以在`mode`参数中使用其他动画模式，包括`right`，`blink`，`rainbow`和`stop`。`speed`参数接受`1`到`10`之间的值。

1.  要清除或重置 LED 灯带，再次在*终端 2*中运行以下命令：

```py
# Terminal 2
$ curl -X POST "http://localhost:5000/lights/clear"
```

1.  要使舵机扫动（也就是使树摇晃），在*终端 2*中运行以下命令：

```py
# Terminal 2
$ curl -X POST "http://localhost:5000/servo/sweep"
```

舵机应该来回扫动几次。如果你想让舵机扫动更多次或需要增加其运动范围，那么你可以在`chapter14/tree_api_service/config.py`文件中调整`SERVO_SWEEP_COUNT`和`SERVO_SWEEP_DEGREES`配置参数。

如果发现当你移动舵机时 LED 变暗、闪烁或者表现不稳定，或者当你改变 APA102 LED 时舵机抽搐，很可能是你的外部电源无法提供足够的电流来同时运行 LED 和舵机。作为临时措施，如果你没有另一个电源，可以尝试减少 LED 的数量（`config.py`中的`APA102_NUM_LEDS`）和/或减少 LED 对比度（`config.py`中的`APA102_DEFAULT_CONTRAST`）。这将降低 LED 灯带的电流需求。

1.  最后，让我们运行 Web 应用程序，并通过在树莓派桌面上打开 Web 浏览器并导航到 URL `http://localhost:5000`来控制我们的 IoTree。您应该看到一个类似于这里图片的网页：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/a29059b1-831e-42cb-ae1f-fce5a7279e80.png)

图 14.4 - 示例 IoTree Web 应用程序

尝试以下操作：

+   点击颜色栏中的颜色，观察该颜色被推送到 APA102 LED 灯带。

+   点击*Pattern Fill*按钮填充 APA102 LED 灯带的选定颜色。

+   点击左侧开始动画。

此 Web 应用程序背后的 JavaScript（在`chapter14/tree_api_service/templates/index.html`中找到）只是调用我们的 IoTree API，类似于我们已经使用`curl`做的事情，只是它使用 jQuery 来做。 jQuery 和 JavaScript 超出了本书的范围；但是，在第三章中简要介绍了它们，*使用 Flask 进行 RESTful API 和 Web Sockets 的网络*。

您将在`chapter14/tree_api_service/README.md`文件中找到 IoTree 的完整 API 文档集，其中包含`curl`示例。

我们的 RESTful API 实现提供了本章所需的基本 API 端点；但是，我非常有信心您将能够扩展和调整此示例以适应您自己的项目，或者向您的 IoTree 添加新功能。我将在本章末尾的*扩展您的 IoTree 的想法和建议*部分提供关于如何根据本书学到的知识扩展您的 IoTree 的建议。

现在我们已经运行并看到如何使用 RESTful API 控制我们的 IoTree 的灯和舵机，接下来我们将看一种替代服务实现，它将允许我们使用 MQTT 控制我们的 IoTree。

# 配置、运行和使用 Tree MQTT 服务

Tree MQTT 服务程序提供了一个 MQTT 接口，用于通过发布 MQTT 消息到 MQTT 主题来控制树的 APA102 LED 灯带和舵机。您可以在`chapter14/tree_mqtt_service`文件夹中找到 Tree MQTT 服务程序，并包含以下文件：

+   `README.md`：控制您的 IoTree 的 MQTT 主题和消息格式的完整列表。

+   `main.py`：这是程序的主要入口点。

+   `config.py`：程序配置。

+   `apa102.py`：这是`chapter14/tree_api_service/apa102.py`的精确副本。文件

+   `servo.py`：这是`chapter14/tree_api_service/servo.py`文件的精确副本。

+   `mqtt_listener_client.py`：这是一个连接到 MQTT 代理并订阅将接收消息以控制 APA102 和舵机的主题的类。当接收到 MQTT 消息时，它们被转换为 PubSub 消息并使用`PyPubSub`库发布，我们在第十二章中讨论过，*高级 IoT 编程概念-线程、AsyncIO 和事件循环*。

+   `apa102_controller.py`：此代码接收由`mqtt_listener_client.py`发送的 PubSub 消息，并根据需要更新 APA102 LED 灯带。

+   `servo_controller.py`：此代码接收由`mqtt_listener_client.py`发送的 PubSub 消息并控制舵机。

显示了 Tree MQTT 服务程序架构的图表如*图 14.5*所示：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/0cdf056b-bfbe-4b53-96f9-a8882011c8ba.png)

图 14.5 - Tree MQTT 服务架构块图

以下是 Tree MQTT 服务的高级操作，用虚线表示在前面的图表中发布的 MQTT 发布：

1.  `red blue`消息发布到`tree/lights/pattern`主题上＃1。

1.  消息由 Paho-MQTT 客户端在＃2 处接收。主题和消息在`mqtt_listener_client.py`中的`on_message()`方法中进行解析，并使用`config.py`中的`MQTT_TO_PUBSUB_TOPIC_MAPPINGS`映射字典映射到本地 PubSub 主题*pattern*。

1.  映射的消息和解析的数据使用`PyPubSub`库在＃3 处分发。

1.  `apa102_controller.py`中的`PyPubSub`订阅接收*pattern*主题及其负载数据在#4 处

1.  `apa102_controller.py`处理#5 处的消息和数据，并在 APA102 实例（在`apa102.py`中定义）上调用适当的方法，直接与重复的红色和蓝色模式的物理 APA102 LED 灯带进行接口和更新。

如果你在想，使用`PyPubSub`并在`mqtt_listener_client.py`中重新分发 MQTT 消息是基于我个人偏好的设计决定，目的是将 MQTT 相关的代码和硬件控制相关的代码解耦，以使应用程序更易于阅读和维护。另一种同样有效的方法是在直接响应接收到的 MQTT 消息时在`mqtt_listener_client.py`中使用`apa102.py`和`servo.py`。

现在我们已经了解了我们的 Tree MQTT 服务是如何工作的，在运行我们的 Tree MQTT 服务之前，首先我们需要检查它的配置。我们将在下一步进行。

## 配置 Tree MQTT 服务

Tree MQTT 服务配置位于`chapter14/tree_mqtt_service/config.py`文件中。与 Tree API 服务类似，它们主要涉及 APA102 和伺服器的配置。您还会发现这个文件及其配置选项都有很好的注释。

默认配置将足以在树莓派上本地运行示例；但是，就像我们为 Tree API 服务配置所做的那样，请检查并更新`APA102_NUM_LEDS = 60`参数。

如果您在运行 Tree API 示例时还需要更改`APA102_DEFAULT_CONTRAST`、`SERVO_SWEEP_COUNT`或`SERVO_SWEEP_DEGREES`参数中的任何一个，请现在也更新这些值以供 MQTT 示例使用。

一旦您对配置进行了任何必要的更改，我们将继续运行我们的 Tree MQTT 服务程序并发布 MQTT 消息以使我们的 IoTree 工作。

## 运行 Tree MQTT 服务程序

现在是时候运行 Tree MQTT 服务程序并发布 MQTT 消息来控制我们的 IoTree 了。以下是运行和测试我们的 Tree MQTT 服务的步骤：

1.  我们必须在树莓派上安装并运行 Mosquitto MQTT 代理服务以及 Mosquitto MQTT 客户端工具。如果您需要检查您的安装，请参阅第四章，*使用 MQTT、Python 和 Mosquitto MQTT 代理进行网络连接*。

1.  切换到`chapter14/tree_mqtt_service`文件夹并启动`main.py`脚本，如下所示：

```py
# Terminal 1
(venv) $ cd tree_mqtt_service
(venv) $ python main.py
INFO:root:Connecting to MQTT Broker localhost:1883
INFO:MQTTListener:Connected to MQTT Broker
```

1.  接下来，打开第二个终端并使用以下命令发送 MQTT 消息：

```py
# Terminal 2
$ mosquitto_pub -h "localhost" -t "tree/lights/pattern" -m "red blue black"
```

LED 灯带将以重复的颜色模式（红色、蓝色、黑色（黑色表示 LED 关闭））点亮。

尝试使用`--retain`或`-r`保留消息选项来实验`mosquirro_pub`。如果您发布了一个保留消息，当它连接到 MQTT 代理并订阅`tree/#`主题时，它将被重新传递到您的 Tree MQTT 服务，这为您的 IoTree 在重新启动之间恢复其上次状态提供了一种方式。

1.  现在，在*终端 2*中运行以下命令使 LED 灯带动画起来：

```py
# Terminal 2
$ mosquitto_pub -h "localhost" -t "tree/lights/animation" -m "left"
```

1.  要清除或重置 LED 灯带，请在*终端 2*中再次运行以下命令：

```py
# Terminal 2
$ mosquitto_pub -h "localhost" -t "tree/lights/clear" -m ""
```

在这个例子（以及*步骤 6*中的下一个例子）中，我们没有任何消息内容；但是，我们仍然需要传递一个空消息，使用`-m ""`选项（或者，`-n`）；否则，`mosquitto_pub`将中止。

1.  最后，尝试以下命令来扫描伺服器：

```py
# Terminal 2
$ mosquitto_pub -h "localhost" -t "tree/servo/sweep" -m ""
```

伺服器将根据`chapter14/tree_mqtt_service/config.py`中`SERVO_SWEEP_COUNT`或`SERVO_SWEEP_DEGREES`设置来来回扫动。

您将在`chapter14/tree_mqtt_service/README.md`文件中找到 Tree MQTT 服务识别的完整 MQTT 主题和消息格式的完整集合，包括`mosquitto_pub`示例。

与我们的 RESTful API 示例类似，我们的 MQTT 示例提供了本章所需的最小功能，但提供了一个基本框架，您可以在自己的未来项目中扩展，或者如果您扩展了 IoTree 的功能。

现在我们已经运行并看到如何使用 MQTT 控制 IoTree 的灯和伺服，让我们看看我们可以使用的集成服务，将我们的 Tree MQTT 服务与 dweet.io 耦合。

# 将 IoTree 与 dweet.io 集成

*dweet 集成服务*，位于`chatper14/dweet_integration_service`文件夹中，是一个基于 Python 的集成服务，它接收 dweets 并将它们重新发布为消息到 MQTT 主题。此服务为我们提供了一种简单的方法，将诸如 IFTTT 之类的服务与我们的 Tree MQTT 服务程序集成。

dweet 集成服务由以下文件组成：

+   `main.py`：主程序入口点。

+   `config.py`：配置参数。

+   `thing_name.txt`：保存您的物体名称的地方。当您第一次启动程序时，将创建此文件。

+   `dweet_listener.py`：核心程序代码。

我们的 dweet 服务的核心部分位于`dweet_listener.py`文件中。如果您检查此文件，您会注意到它几乎与第二章中涵盖的`dweet_led.py`文件以及*第十三章*，IoT 可视化和自动化平台中涵盖的文件几乎相同（除了现在它作为 Python 类包装）。

核心区别在于`process_dweet()`方法，在下面的代码中显示为（1）行，这里我们不是直接控制 LED，而是拦截 dweet，然后重新发布到 MQTT 主题：

```py
def process_dweet(self, dweet):        # (1)

   # ...Truncated...
   # command is "<action> <data1> <data2> ... <dataN>"
   command = dweet['command'].strip()
   # ...Truncated...

   # elements (List) <action>,<data1>,<data2>,...,<dataN>
   elements = command.split(" ")
   action = elements[0].lower()
   data = " ".join(elements[1:])

   self.publish_mqtt(action, data)     # (2)
```

`publish_mqtt()`方法，在前面的代码中显示为（2）行，在下面的代码中显示为（3）行，然后根据`chapter14/dweet_mqtt_service/config.py`中的`ACTION_TOPIC_MAPPINGS`设置，将我们解析的命令字符串转换为基于 MQTT 主题的消息并发布：

```py
    def publish_mqtt(self, action, data):                       # (3)
        if action in self.action_topic_mappings:
            # Map Action into MQTT Topic
            # (Eg mode --> tree/lights/mode). 
            # See config.py for mappings.

            topic = self.action_topic_mappings[action]
            retain = topic in self.mqtt_topic_retain_message    # (4)
            # ... truncated ...
            publish.single(topic, data, qos=0,                  # (5)
                          client_id=self.mqtt_client_id, 
                          retain=retain, hostname=self.mqtt_host, 
                          port=self.mqtt_port)
    # ... truncated ...

```

请注意，在（5）行，我们使用了 Paho-MQTT 的`publish.single()`便利方法，而不是我们在第四章中使用的完整的 MQTT 客户端方法，*使用 MQTT、Python 和 Mosquitto MQTT 代理进行网络连接*（并且在 Tree MQTT 服务程序中也使用）。

目前，我只想指出（4）行，我们在那里设置了`retain`变量（还注意到它在`publish.single()`中的使用）。在接下来的部分中，当我们讨论服务配置文件时，我们将更多地讨论此消息保留。

图 14.6 显示了树服务程序架构的图表：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/53f844ed-a48c-4006-a903-92e84dff021f.png)

图 14.6 - dweet 集成服务架构块图

这是 dweet 集成服务的高级操作，由前面图中蓝色虚线所示的请求：

1.  在#1 处创建了一个 dweet。

1.  `dweet_listener.py`在#2 处接收 dweet 并解析`command`参数中包含的数据。命令中包含的操作使用`config.py`中找到的`ACTION_TOPIC_MAPPINGS`映射字典映射为 MQTT 主题。

1.  消息被发布到 MQTT 代理到映射的 MQTT 主题#3。根据`config.py`中找到的`TOPIC_RETAIN_MESSAGE`映射字典，设置消息的*保留*标志。

发布 MQTT 消息后，如果您的 Tree MQTT 服务正在运行并连接到相同的 MQTT 代理，它将接收 MQTT 消息并相应地更新您的 IoTree。

现在我们了解了我们的 dweet 集成服务的工作原理，然后我们可以运行我们的 dweet 集成服务之前，首先需要检查其配置。我们接下来会做这个。

## 配置 Tree MQTT 服务

dweet 集成服务的配置位于`chapter14/dweet_integration_service/config.py`文件中。有许多与服务工作方式相关的配置选项，默认配置将足以在您的 Raspberry Pi 上本地运行此服务，同时您还在那里运行您的 Mosquitto MQTT 代理。这个文件中的配置参数有很好的注释；但是，我将提到`ACTION_TOPIC_MAPPINGS`和`TOPIC_RETAIN_MESSAGE`参数：

```py
ACTION_TOPIC_MAPPINGS = {
    "clear": "tree/lights/clear",
    "push": "tree/lights/push",
    ... truncated ...
}
```

dweet 集成服务将*dweeted 命令*映射到*MQTT 主题*。决定如何将命令映射到 MQTT 主题的是`ACTION_TOPIC_MAPPINGS`配置参数。我们将在下一节讨论这个*命令*的概念。

由 dweet 集成服务映射和使用的 MQTT 主题必须与 Tree MQTT 服务使用的主题相匹配。每个服务的默认配置都使用相同的主题。

以下代码中显示的`TOPIC_RETAIN_MESSAGE`配置确定了哪些 MQTT 主题将设置其消息的*保留*标志。正如我们在上一节中指出的那样，这个配置（`True`或`False`）用于在`single.publish()`上设置`retained`参数：

```py
TOPIC_RETAIN_MESSAGE = {
    "tree/lights/clear": False,
    "tree/lights/animation": True,
    ... truncated ...
}
```

现在我们已经讨论了配置文件，让我们启动我们的 dweet 集成服务，并发送 dweets 来控制我们的 IoTree。

## 运行 dweet 集成服务程序

我们的 dweet 集成服务通过按照我们在上一节中讨论的配置参数将预定义格式的 dweets 转换为 MQTT 主题和消息来工作。当我们运行和测试 dweet 集成服务时，我们将很快讨论这个 dweet 格式。以下是我们需要遵循的步骤：

1.  首先，请确保您在终端上运行了上一节中的*Tree MQTT 服务*程序。正是 Tree MQTT 服务将接收并处理 dweet 集成服务发布的 MQTT 消息。

1.  接下来，在新的终端中导航到`chapter14/dweet_integration_service`文件夹，并启动`main.py`程序，如下所示（请记住您的物体名称将不同）：

```py
(venv) $ cd dweet_service
(venv) $ python main.py
INFO:DweetListener:Created new thing name ab5f2504
INFO:DweetListener:Dweet Listener initialized. Publish command dweets to 'https://dweet.io/dweet/for/ab5f2504?command=...'
```

1.  将以下 URL 复制并粘贴到 Web 浏览器中以控制您的 IoTree。使用您输出中显示的物体名称替换`<thing_name>`文本：

+   +   dweet.io/dweet/for/<thing_name>?command=pattern%20red%20blue%20black

+   dweet.io/dweet/for/<thing_name>?command=animation%20left

+   dweet.io/dweet/for/<thing_name>?command=speed%2010

+   dweet.io/dweet/for/<thing_name>?command=clear

+   dweet.io/dweet/for/<thing_name>?command=sweep

在调用这些 URL 之间可能需要一些时间，然后它将被您的 dweet 集成服务接收。

正如您在前面的 URL 中的`command`参数中所看到的，我们的 dweet 的格式是`<action> <data1> <data2> <dataN>`。

在`config.py`文件中，您将找到默认配置中识别的完整的 dweet 命令字符串集，包括示例 URL，在`chapter14/dweet_integration_service/README.md`文件中。

干得好！我们刚刚使用 dweet.io 和 MQTT 创建了一个简单的集成服务，并学会了一种简单且非侵入式的方法，可以让我们在互联网上控制我们的 tree，而无需进行任何网络或防火墙配置。

在设计物联网项目并考虑数据在互联网和网络中的传输方式时，通常会发现您需要设计和构建某种集成形式，以桥接建立在不同传输机制上的系统。本节中的示例说明了一个场景，我们在其中将 MQTT 服务（我们的 IoTree MQTT 服务）与基于轮询的 RESTful API 服务（dweet.io）进行了桥接。虽然每个集成都有自己的要求，但希望这个示例为您提供了一个大致的路线图和方法，以便在将来遇到这些情况时进行调整和构建。

现在我们的 dweet 集成服务正在运行，并且已经测试过它正在工作，让我们看看如何将其与 IFTTT 平台一起使用。

# 通过电子邮件和 Google 助手与 IFTTT 集成

现在是真正有趣的部分——让我们使我们的树可以通过互联网进行控制。作为一个剧透，我不会在这个集成中手把手地指导您，因为在第十三章中详细解释了使用 dweet.io 和 IFTTT 的核心概念，*IoT 可视化和自动化平台*。特别是，我们学会了如何将我们的树莓派与 IFTTT 和电子邮件集成，以控制 LED。

然而，我将给您我的 IFTTT 配置的截图，以便您可以验证您设置的内容。另外，作为一个额外的奖励，我还将给您一个关于如何与 Google 助手集成的提示和截图，以便您可以语音控制您的 IoTree！

在撰写本文时，IFTTT 有一个 Google 助手服务，可以接受任意口头输入（在 IFTTT 术语中称为*成分*）。我确实尝试了 Alexa 集成，但不幸的是，Alexa IFTTT 服务无法接受任意输入，因此与我们的示例不兼容。

首先，我们将看一下如何将我们的 IoTree 与电子邮件集成。

## 与电子邮件的集成

与电子邮件或 Twitter 集成的过程与我们在第十三章*IoT 可视化和自动化平台*中介绍的内容相同，只是有以下更改：

1.  不要使用`LED`作为标签（在 IFTTT 的**完成触发器字段页面**步骤中），使用`TREE`。这样，您的电子邮件主题可以是`#TREE 模式红蓝`或`#TREE 动画闪烁`之类的内容。

1.  在配置 That webhook 服务时，您需要使用之前在终端上运行 dweet 集成服务时打印的 dweet URL。我的配置示例如下图所示。请记住，您 URL 中的*thing name*将是不同的：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/5e11ac9b-937c-47a4-8a18-90f29e95f3c5.png)

图 14.7 – Webhook 配置

1.  完成设置 IFTTT Applet 后，尝试发送电子邮件至`trigger@applet.ifttt.com`，主题如下：

+   +   `#TREE 模式红蓝黑色`

+   `#TREE 动画向左`

发送电子邮件或推文`#TREE 模式红蓝黑色`命令后的几分钟内，您的树灯将以这些颜色进行重复变换。同样，发送电子邮件或推文`#TREE 动画向左`后的几分钟内，您的树灯将开始动画。

请记住，为了使此示例工作，您需要在终端上同时运行 Tree MQTT 服务和 dweet 集成服务。在发送电子邮件或发布推文后，您的 IoTree 更改可能需要一些时间。

一旦您能够通过电子邮件控制您的 IoTree，接下来我们将看一下添加使用 Google 助手进行语音控制所需的步骤。

## 与 Google 助手的集成

让我们使用 Google 助手使我们的 IoTree 可以通过语音控制。

*Google 助手*有许多其他形式，包括 Google Home、Google Nest 和 Google Mini。只要它们登录到与 IFTTT 使用的相同的 Google 帐户，这些产品也将与 IFTTT Google 助手集成和您的 IoTree 一起使用。

要创建我们的集成，我们需要将您的 Google 帐户与 IFTTT Google 助手服务链接，并在接收命令时调用 dweet.io URL。以下是要遵循的高级步骤：

1.  登录到您的 IFTTT 帐户。

1.  创建一个新的 Applet。

1.  对于 Applet 的这一部分，请使用 Google 助手服务。

1.  接下来，您将被要求连接并允许 IFTTT 使用您的 Google 帐户。按照屏幕上的说明连接 IFTTT 和您的 Google 帐户。

1.  现在是选择 Google 助手触发器的时候了。选择“说一个带有文本成分的短语”。示例触发器配置如*图 14.8*所示：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/5df6808b-bafd-4740-9c73-09ba7a5e7273.png)

图 14.8 - Google 助手触发器示例

在前面的屏幕截图中显示的 Tree $中的$符号被转换为我们将与我们的 webhook 服务一起使用的 IFTTT 成分（我们将在后面的步骤中看到）。

有了这个触发器配置，你可以说出像以下这样的命令来控制你的 IoTree：

+   +   "Tree pattern red blue black"

+   "Set tree animation blink"

+   "Tree clear"

1.  现在是配置 IFTTT Applet 的那部分的时间。搜索并选择 WebHook。

1.  webhook 服务的配置与我们在*步骤 2*中之前介绍的*与电子邮件集成*标题下的过程相同，并且如*图 14.7.*所示。

1.  继续并完成创建你的 IFTTT Applet。

1.  询问你的 Google 助手以下命令：

+   +   "Tree pattern red blue black"

+   "Tree animation blink"

+   "Tree clear"

+   "Tree sweep"（或“tree jingle”）

+   或者`chapter14/dweet_integration_service/README.md`文件中记录的任何其他命令

记住，Google 助手承认你的请求后，你的 IoTree 可能需要一会儿才能开始改变。

这是我在 iPhone 上的 Google 助手对话框的屏幕截图：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/prac-py-prog-iot/img/67a87536-2224-4688-9c18-4d3ef28ecff6.png)

图 14.9 - 用于控制 IoTree 的 Google 助手对话框

如果集成工作正常，Google 助手将回复“好的，正在更新树”（或者你在*步骤 5*中使用的任何文本），然后几分钟后，你的 IoTree 将做出响应。

重要的是要记住，我们必须准确地说出命令，就像它们被 dweet 集成服务解释的那样 - 例如，它们会出现在 dweet URL 的命令参数中，如`https://dweet.io/dweet/for/<thing_name>?command=pattern red blue black`。

记得在它们之前加上“Tree”（或“Set Tree”）这个词。这个文本是触发你的 IFTTT Applet 的。只说一个命令本身不会触发你的 Applet。

如果你使用安卓手机或 iOS 的 Google 助手应用程序，你将能够看到你说出的话是如何转换为文本命令的，这可以帮助你排除不起作用或被误解的命令。

你刚刚学会了如何创建三个 IFTTT 集成，以使用电子邮件和语音控制你的 IoTree，并且你可以轻松地将相同的基本思想和流程适应于控制和自动化本书中所见的其他电子电路。

此外，正如我们在第十三章中讨论的那样，*物联网可视化和自动化平台*，IFTTT 提供了许多*触发器*和*操作*，你可以组合起来构建自动化工作流*Applets*。在本章和上一章之间，你现在已经创建了几个 Applets，所以我完全相信你将能够探索 IFTTT 生态系统，并创建各种有趣的 Applets，这些 Applets 可以与你的树莓派一起工作。

在我们结束本章（和本书！）之前，我想给你留下一些想法和实验，以进一步扩展你的 IoTree 的功能。

# 扩展你的 IoTree 的想法和建议

我们在本章中使用的代码和电子设备为我们提供了一个基础，我们可以在此基础上构建。这可能是扩展你的 IoTree，也可能是其他物联网项目的基础。

以下是一些建议，你可以尝试：

+   添加并集成一个 PIR 传感器，每当有人走过你的 IoTree 时，它就会播放一个 RTTTL 曲调。毕竟，如果不一遍又一遍地播放曲调，什么电子圣诞小工具才算完整呢...

+   将 RGB LED 添加并集成到树的顶部（也许在透明的星星内），或者在 APA102 LED 条的位置使用 RGB LED 或与之一起使用。

+   构建多个 IoTree。如果你使用 MQTT，它们将同步！

+   尝试构建 WebSocket 集成和相应的 Web 应用程序。

+   当前的 dweet Google 助手集成要求您精确发出命令。您能否创建一个更模糊的升级-也就是说，可以解析口头文本并找出口头命令是什么？

+   在我们的 IFTTT 示例中，我们使用了 dweet.io（与 MQTT 一起），因此我们不必担心防火墙配置。您可能希望调查在您的位置打开防火墙端口或调查诸如 LocalTunnels（https://localtunnel.github.io/www）或 ngrok（https://ngrok.com）之类的服务。这些方法将允许您使用 IFTTT Webhooks 直接与您的 IoTree 的 RESTful API 进行通信。但是，请记住，我们的 RESTful API 示例没有得到保护-它们没有使用 HTTPS，也没有身份验证机制，例如用户名和密码来限制对 API 的访问，因此您可能还希望研究如何保护基于 Flask 的 API 并首先执行这些升级。

显然，这些只是我的一些建议。在我们的旅程中，我们涵盖了许多电路，所以发挥你的想象力，看看你能想出什么-并且要玩得开心！

# 总结

恭喜！我们现在已经到达了本章和整本书的结尾！

在本章中，我们运行了电子设备并测试了控制这些电子设备的程序，这些程序构成了物联网圣诞树的基础。我们看到了一个可以控制我们 IoTree 的灯和伺服的 RESTful API，以及一个类似的 MQTT 实现。我们还研究了一个 dweet.io 到 MQTT 的集成服务，我们将其与 IFTTT 配对，以提供一种使用电子邮件和 Google 助手来控制我们 IoTree 的机制。

在本书中的旅程中，我们涵盖了许多概念和技术，包括各种网络技术，电子和接口基础知识，以及使用传感器和执行器与树莓派的一系列实际示例。我们还研究了自动化和可视化平台，并在本章中完成了一个将我们的学习结合在一起的示例。

当我写这本书时，我有一些核心意图。我的一个意图是分享和解释我们如何将传感器和执行器连接到树莓派的原因，以及为什么我们要使用额外的组件，如电阻器来创建电压分压器。我的第二个核心意图是为您提供适用于物联网项目的各种网络技术和选项。

我相信，我们在旅程中学到的软件和硬件基础知识，以及实际示例，将为您提供许多技能和见解，不仅可以帮助您设计和构建自己的复杂物联网项目，还可以在软件、网络和电子方面在基本水平上理解现有的物联网项目是如何工作的。

我真诚地希望你喜欢这本书，学到了很多，并且在阅读过程中获得了许多实用的技巧！祝你在物联网之旅中一切顺利，希望你能创造一些了不起的东西！

# 问题

最后，这里是一些问题供您测试对本章材料的了解。您将在附录的评估部分中找到答案：

1.  在我们的 MQTT 服务示例中，为什么我们使用`PyPubSub`重新分发 MQTT 消息？

1.  在与或调试 IFTTT Google 助手 Applet 集成时，为什么在手机（或平板电脑）上使用 Google 助手应用程序很有用？

1.  您正在处理一个现有的天气监测项目，该项目使用 MQTT 作为其网络传输层，以连接许多分布式设备。有人要求您将应用程序与 IFTTT 服务集成。您该如何做？

1.  您想要构建多个 IoTree 并使它们一起协同工作。您可以采取哪两种方法来实现这一目标？

1.  为什么在本章中我们使用了免费的[dweet.io](http://dweet.io)服务？您会在商业物联网项目中使用这种方法吗？

1.  我们想要从命令行测试一个 RESTful API 服务。我们可以使用什么命令行工具？

1.  您可以使用 MQTT 的哪个特性来在树莓派上电或重新启动时自动初始化 IoTrees？

1.  关于*问题 7*，在设置和部署 Mosquitto MQTT 代理以实现这一目标时，您需要考虑哪些因素？


# 第十五章：评估

# 第一章

1.  将项目特定的 Python 软件包和依赖项与其他项目和系统级 Python 软件包隔离开来。

1.  不。您可以随时重新生成虚拟环境并重新安装软件包。

1.  保持 Python 项目依赖的所有 Python 软件包（和版本）的列表。拥有一个维护良好的`requirements.txt`文件可以让您通过`pip install -r requirements.txt`命令轻松重新安装所有软件包。

1.  确保您使用的是虚拟环境的`bin`文件夹中的 Python 解释器的绝对路径。

1.  它激活了一个虚拟环境，以便 Python 和 pip 的所有用户都被隔离到虚拟环境中。

1.  `deactivate`。如果您输入`exit`（我们有时都会这样做！），它会退出终端窗口或关闭远程 SSH 会话！Grrrrr。

1.  是的，只需切换到`projects`文件夹并激活虚拟环境。

1.  Python IDLE，但请记住，您需要在虚拟环境中使用`python -m idlelib.idle [filename] &`。

1.  检查在 Raspbian 中是否已启用了 I2C 接口。

# 第二章

1.  按照答案编号排序，这样您就不会损坏其他组件或电阻器...除非您了解不同值将如何影响电子电路并且这样做是安全的。

1.  错误。GPIO Zero 是其他 GPIO 库的封装。它旨在通过隐藏较低级别的 GPIO 接口细节，使初学者易于使用。

1.  错误。在许多情况下，最好使用成熟的高级软件包，因为它们将有助于加快开发速度。Python API 文档也推荐这种方法。

1.  不。LED 具有正（阳极）和负（阴极）端子（腿），必须正确连接。

1.  有可能设备的时区处理存在不匹配。

1.  `signal.pause()`

# 第三章

1.  我们可以创建和配置一个`RequestParser`的实例。我们在我们的控制器处理程序方法中使用这个实例，比如`.get()`或`.post()`来验证客户端的请求。

1.  WebSockets - 使用 Web Sockets 构建的客户端和服务器可以在任何方向上相互发起请求。这与 RESTful API 服务形成对比，后者只有客户端可以向服务器发起请求。

1.  Flask-SocketIO 不包括像 Flask-RESTful 那样的内置验证类。您必须手动执行输入验证。或者，您也可以从 PyPi.org 找到一个合适的第三方 Python 模块来使用。

1.  `templates`文件夹是 Flask 框架查找模板文件的默认位置。在这个位置，我们存储我们的 HTML 页面和模板。

1.  我们应该在文档准备好的函数中初始化事件侦听器和网页内容，这个函数在网页完全加载后调用。

1.  命令是`curl`。它默认安装在大多数基于 Unix 的操作系统上。

1.  更改`value`属性会改变 LED 的 PWM 占空比。我们将这视为改变 LED 的亮度。

# 第四章

1.  **MQTT**，或**消息队列遥测协议**，是在分布式物联网网络中经常使用的轻量级消息协议。

1.  检查 QoS 级别，确保它们是 1 级或 2 级。

1.  如果客户端突然断开与代理的连接而没有干净地关闭连接，将代表客户端发布`Will`消息。

1.  发布的消息和订阅的客户端都必须至少使用 QoS 级别 1，这可以确保消息被传递一次或多次。

1.  理想情况下，除了可能需要更改代理主机和端口之外，您的 Python 代码不应该需要任何更改，因为 MQTT 是一个开放标准。前提是新代理配置与被替换的代理类似 - 例如，两个代理都配置类似以为客户端提供消息保留或持久连接功能。

1.  你应该在成功连接类型的处理程序中订阅主题。这样，如果客户端失去了与代理的连接，它可以在重新连接时自动重新建立主题订阅。

# 第五章

1.  **SPI**（串行外围接口电路）。LED 灯带和矩阵是常见的例子。

1.  你可以参考设备的官方数据表，或使用列出所有连接的 I2C 设备地址的命令行工具 i2cdetect。

1.  确保你使用的是库期望的正确引脚编号方案，并/或者确保你已经配置了库以使用你喜欢的方案，如果库提供了这个选项。

1.  驱动程序库不是建立在 PiGPIO 之上的，因此不支持远程 GPIO。

1.  错误。所有的 GPIO 引脚额定电压为 3.3 伏特。连接任何高于这个电压的电压都可能损坏你的树莓派。

1.  你使用来驱动舵机的库很可能是使用软件 PWM 来生成舵机的 PWM 信号。当树莓派的 CPU 变得繁忙时，软件 PWM 信号可能会失真。

1.  如果你从树莓派的 5 伏特引脚为舵机供电，这将表明你正在吸取过多的电力，实际上是从树莓派中夺取电力。理想情况下，舵机应该由外部电源供电。

# 第六章

1.  一般来说，是的。尝试是安全的，因为电阻越高，电路中的电流就越低（欧姆定律），而 330Ω相对接近期望的 200Ω电阻。

1.  更高的电阻导致了更少的电流，以至于电路没有足够的电流来可靠地工作。

1.  电阻要耗散的功率超过了电阻的功率额定值。除了使用欧姆定律来确定电阻值之外，你还需要计算电阻的预期功率耗散，并确保电阻的功率额定值（以瓦特为单位）超过你计算出的值。

1.  1（一）。连接到+3.3 伏特的输入 GPIO 引脚是逻辑高。

1.  GPIO 21 是浮动的。它没有通过物理电阻或者通过代码使用函数调用（例如`pi.set_pull_up_down(21, pigpio.PUD_UP)）`拉高到+3.3 伏特。

1.  你必须使用逻辑电平转换器。这可以是一个简单的基于电阻的电压分压器，一个专用的逻辑电平转换器 IC 或模块，或者任何其他可以适当将 5 伏特转换为 3.3 伏特的形式。

1.  错误。电阻分压器只能降低电压。但是，请记住，只要 5 伏特设备将 3.3 伏特注册为逻辑高，可能可以使用 3.3 伏特来驱动 5 伏特逻辑设备。

# 第七章

1.  MOSFET 是电压控制元件，而 BJT 是电流控制元件。

1.  你在 MOSFET 的栅极上没有下拉电阻，所以它是悬空的。MOSFET 放电缓慢，这反映在电机减速。使用下拉电阻可以确保 MOSFET 迅速放电并关闭。

1.  （a）确保 G、S 和 D 腿正确连接，因为不同的封装样式（例如 T092 与 TP220）它们的腿的顺序是不同的。

（b）你还要确保 MOSFET 是逻辑电平兼容的，这样它就可以使用 3.3 伏特的电压源进行控制。

（c）确保在下拉电阻和限流电阻之间创建的电压分压器允许>〜3 伏特进入 MOSFET 的栅极腿。

1.  光耦和继电器在电路的输入和输出端之间进行电气隔离。晶体管是在电路中的，虽然它们允许低电流设备控制更大的电流设备，但两个设备仍然都是电气连接的（例如，你会看到一个公共地连接）。

1.  主动低是指使 GPIO 低电平以打开或激活连接的电路。主动高则相反，我们使 GPIO 引脚高电平以激活连接的电路。

1.  代码激活的下拉仅在运行代码时变为下拉，因此 MOSFET 门基本上是悬浮的，直到运行代码。

1.  堵转电流是电机在其轴被强行停止旋转时使用的电流。这是电机将吸取的最大电流。

1.  没有区别-它们是两个可互换使用的术语，用来描述电机在轴上没有负载的情况下自由旋转时所使用的电流。

# 第八章

1.  检查您的电源是否能够提供足够的电流（和电压）给 LED 灯带。电流需求随您想要点亮的 LED 数量以及它们设置的颜色和亮度而成比例增加。电流不足可能意味着内部的红/绿/蓝 LED 没有正确点亮，因此颜色不如您期望的那样。

1.  缺少从选择或客户端启用引脚意味着 APA102 完全控制 SPI 接口。这意味着您不能将多个 SPI 从设备连接到一个 SPI 引脚（除非您使用额外的电子设备）。

1.  首先，检查您的逻辑电平转换器是否连接正确。其次，可能逻辑电平转换器无法快速转换逻辑电平以跟上 SPI 接口。尝试降低 SPI 总线速度。

1.  我们使用**PIL**（**Python Imaging Library**）创建一个内存中的图像，代表我们想要显示的内容。然后将此图像发送到 OLED 显示器进行渲染。

1.  **RTTTL**意味着**Ring Tone Text Transfer Language**，这是由诺基亚创建的一个铃声音乐格式。

# 第九章

1.  DHT22 是一种更精确的传感器，它能够感知更广泛的温度和湿度范围。

1.  外部上拉电阻是可选的，因为我们的树莓派可以使用其内部嵌入的上拉电阻。

1.  LDR 是一种光敏电阻。当作为电压分压电路的一部分使用时，我们将变化的电阻转换为变化的电压。然后，这个电压可以被模拟到数字转换器（如连接到您的树莓派的 ADS1115）检测到。

1.  尝试改变电压分压电路中固定电阻的电阻值。尝试更高阻值的电阻以使 LDR 在较暗的条件下更敏感。尝试更低的电阻值以使 LDR 对更明亮的条件更敏感。

1.  当涉及到它们测量的电阻时，没有两个 LDR 是相同的。如果在电路中更换 LDR，请重新校准代码以确保。

1.  水传导电。它在两个探针线之间充当电阻。这种电阻通过电压分压器转换为电压，ADS1115 ADC 可以检测到这种电压。

# 第十章

1.  我们通常发现默认的参考脉冲宽度为 1 毫秒用于左，2 毫秒用于右的舵机。实际上，舵机可能需要略微调整的脉冲宽度才能达到其极限旋转位置。

1.  您正在应用尝试将舵机旋转到其物理极限之外的脉冲宽度。

1.  H 桥还允许我们改变电机的旋转并快速制动以停止电机旋转。

1.  许多因素影响制动的可靠性，包括 IC 和您的电机。您可以采用 PWM 式制动作为替代制动技术。

1.  振动但不转动通常是线圈通电顺序和线圈步进序列不匹配的症状。您需要确定并确保步进电机的线圈连接正确并匹配步进序列。查阅您的步进电机的数据表是开始的最佳地点。

1.  L293D 的电压降约为 2 伏，因此您的电机只能获得约 3 伏。为了补偿这种电压降，您需要一个 7 伏的电源。

1.  不。GPIO 引脚只提供 3.3 伏。虽然这可能刚好足够旋转 5 伏的步进电机，但是步进电机的电流要求将超出树莓派 GPIO 引脚的安全限制。

# 第十一章

1.  不。**被动红外**（PIR）传感器只能检测抽象的运动。您将需要一种主动型红外传感器或类似热成像相机的设备（以及更复杂的代码）来提取更丰富的运动信息。

1.  超声波传感器测量超声脉冲的往返时间，然后用于计算距离。影响超声脉冲时间或所用的声速常数的因素因此会影响计算出的距离。一些例子包括温度，因为这会影响声速，被检测物体的材料（例如，它是否吸收声音？），物体的大小以及其相对于传感器的角度。

1.  锁定和非锁定霍尔效应传感器都输出数字信号-它们的输出引脚要么是高电平要么是低电平。相比之下，比例霍尔效应传感器输出与它们离磁场有多近的模拟信号（变化的电压）。

1.  `callback_handler`函数将在 GPIO 转换为高电平或低电平时调用。

1.  因此，位于 5 伏特源和电压分压器输出（两个电阻之间）之间的电阻器上的相对电压降为 3.3 伏特，即 5 伏特*2kΩ/(1kΩ+2kΩ) = ~3.3 伏特。如果您在电路中颠倒了电阻值，电压分压器输出将为~1.7 伏特，即 5 伏特*1kΩ/(1kΩ+2kΩ) = ~1.7 伏特。

1.  在查阅 HC-SR501 PIR 传感器的数据表后，我们了解到它的输出引脚始终在 3.3 伏特工作，即使它是由 5 伏特供电的，因此我们不需要电压分压器。（请注意，在实践中，我们最好也通过我们的测量来确认这一点。）

# 第十二章

1.  发布-订阅方法促进了高度解耦的编程方法。当您有许多组件（例如传感器）发布数据，只需要在程序的其他地方消耗数据时，这可能是有益的。

1.  GIL 代表全局解释器锁。这是 Python 编程语言的一个设计方面，意味着一次只有一个线程可以访问 Python 解释器。

1.  纯事件循环（例如，一个长的 while 循环）在程序增长时可能会变得复杂。对许多状态变量和非平凡的和干预的条件测试（例如，if 语句）的需求可能会使程序逻辑难以理解和调试。

1.  不。每种方法都有其目的。事件循环在小而专注时是可以的。只有当它们变得庞大并执行多个操作时，它们才会变得复杂。

1.  当您使用线程进行编程时，调用`join()`另一个线程会将该线程加入到当前线程。然后，您的当前线程将阻塞，直到所有加入的线程运行方法完成。这是同步多个线程完成的简单方法。

1.  也许您正在使用`sleep`语句（来自`time`库），例如`sleep(duration)`，它会阻塞整个持续时间。尝试使用以下示例中的方法，这将使您的程序保持对`duration`值的更改的响应性：

```py
duration = 1   # 1 second
timer = 0
while timer < duration:
    timer += 0.01
    sleep(0.01)
```

1.  没有一种方法是优越的。在 Python 中，达到编程目标的方法总是不止一种。最佳方法或方法的组合完全取决于您的项目以及您想要实现的目标。最佳方法也可能是根据您的个人偏好和首选编程风格而为您最佳的方法。

# 第十三章

1.  我们使用不同的温度创建一个缓冲区，这样我们就不会在温度围绕单个温度值徘徊时生成多个触发器（和多个电子邮件）。

1.  使用中介者意味着我们不需要担心防火墙、端口转发和其他必要的配置，以将您的树莓派暴露给公共互联网。

1.  IFTTT 更加面向消费者，而 Zapper 在提供集成方面更加面向企业。Zapper 还允许您创建更复杂的工作流程、触发器和操作场景。

1.  不，ThingSpeak 只消耗数据以在仪表板上显示。一些平台，如 ThingBoard，将允许您将数据发送回设备，以控制该设备。

1.  最多可以使用三个 JSON 属性`– Value1`、`Value2`和`Value3`。

1.  从开发的便捷性和速度的角度来看，IFTTT 或 Zapper 都是不错的选择，但您当然也可以使用 AWS 或其他主要的物联网平台，甚至是 Home Assistant。

# 第十四章

1.  使用 PyPubSub 是一个设计决策，旨在将与 MQTT 相关的代码和逻辑与硬件控制代码和逻辑分离，以使代码更清晰、更易于维护。

1.  使用 Google 助手应用程序时说的命令会显示在您的设备上，因此很容易看到 Google 助手是如何听到您说的命令，以及发送给您的 IFTTT Applet 的文本命令。

1.  您需要构建一个集成服务，用于在 MQTT 和 RESTful API 之间传输数据（或者，也可以找到一个第三方服务来做到这一点，例如，可以查看[`io.adafruit.com`](https://io.adafruit.com)和他们的 IFTTT 服务）。IFTTT 提供 RESTful webhooks 作为构建自定义集成的选项，但它不提供 MQTT 选项。

1.  一种选择是使用 MQTT，就像我们在本章中介绍的示例一样。如果您使用 MQTT 将多个 IoTree 连接到中央 MQTT 代理，它们将一起接收指令。第二个选择可能是构建基于 WebSockets 的服务和应用程序（我们在第三章中介绍了这种方法，*使用 Flask 进行 RESTful API 和 Web Sockets 的网络连接*）。

1.  我们使用免费的[dweet.io](http://dweet.io)服务，因为这样做非常方便，这样我们就不必担心防火墙、端口转发和路由器配置（以防您没有相关经验）。免费的[dweet.io](http://dweet.io)服务不提供安全性或隐私性，因此对许多项目来说并不理想。如果您喜欢[dweet.io](http://dweet.io)的想法，还有[dweetpro.io](https://dweetpro.io)，这是一个付费的替代方案，提供了免费版本中不可用的安全性和许多其他功能。

1.  `CURL`是一种常用的命令行工具，可用于测试 RESTful API。Postman ([getpostman.com](https://getpostman.com))是一种常用的 GUI 工具，也可以用于相同的目的。

1.  如果您使用 MQTT 代理的保留消息功能，每个 IoTree 在连接时都会收到最后一条消息（例如，要显示什么颜色模式），因此可以初始化自己。我们在《使用 MQTT、Python 和 Mosquitto MQTT 代理进行网络连接》第四章中介绍了保留消息。

1.  如果您的 MQTT 代理运行在与 IoTree 相同的树莓派上，并且重新启动了这个树莓派，除非 Mosquitto MQTT 代理在其配置中启用了持久性，否则所有保留的消息都将丢失。（我们在第四章中的配置，*使用 MQTT、Python 和 Mosquitto MQTT 代理进行网络连接*，确保了持久性已启用）。
