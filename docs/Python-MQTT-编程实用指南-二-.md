# Python MQTT 编程实用指南（二）

> 原文：[`zh.annas-archive.org/md5/948E1F407C9BFCC597B979028EF5EE22`](https://zh.annas-archive.org/md5/948E1F407C9BFCC597B979028EF5EE22)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：使用 Python 和 MQTT 消息编写控制车辆的代码

在本章中，我们将编写 Python 3.x 代码，以通过加密连接（TLS 1.2）传递 MQTT 消息来控制车辆。我们将编写能够在不同流行的物联网平台上运行的代码，例如 Raspberry Pi 3 板。我们将了解如何利用我们对 MQTT 协议的了解来构建基于要求的解决方案。我们将学习如何使用最新版本的 Eclipse Paho MQTT Python 客户端库。我们将深入研究以下内容：

+   理解使用 MQTT 控制车辆的要求

+   定义主题和命令

+   学习使用 Python 的好处

+   使用 Python 3.x 和 PEP 405 创建虚拟环境

+   理解虚拟环境的目录结构

+   激活虚拟环境

+   停用虚拟环境

+   为 Python 安装 paho-mqtt

+   使用 paho-mqtt 将客户端连接到安全的 MQTT 服务器

+   理解回调

+   使用 Python 订阅主题

+   为将作为客户端工作的物联网板配置证书

+   创建代表车辆的类

+   在 Python 中接收消息

+   使用多次调用循环方法

# 理解使用 MQTT 控制车辆的要求

在前三章中，我们详细了解了 MQTT 的工作原理。我们了解了如何在 MQTT 客户端和 MQTT 服务器之间建立连接。我们了解了当我们订阅主题过滤器时以及当发布者向特定主题发送消息时会发生什么。我们安装了 Mosquitto 服务器，然后对其进行了安全设置。

现在，我们将使用 Python 作为我们的主要编程语言，生成将充当发布者和订阅者的 MQTT 客户端。我们将连接 Python MQTT 客户端到 MQTT 服务器，并处理命令以通过 MQTT 消息控制小型车辆。这辆小车复制了现实道路车辆中发现的许多功能。

我们将使用 TLS 加密和 TLS 认证，因为我们不希望任何 MQTT 客户端能够向我们的车辆发送命令。我们希望我们的 Python 3.x 代码能够在许多平台上运行，因为我们将使用相同的代码库来控制使用以下物联网板的车辆：

+   Raspberry Pi 3 Model B+

+   高通龙板 410c

+   BeagleBone Black

+   MinnowBoard Turbot Quad-Core

+   LattePanda 2G

+   UP Core 4GB

+   UP Squared

根据平台的不同，每辆车将提供额外的功能，因为一些板比其他板更强大。但是，我们将专注于基本功能，以保持我们的示例简单，并集中在 MQTT 上。然后，我们将能够将此项目用作其他需要我们在运行 Python 3.x 代码的物联网板上运行代码，连接到 MQTT 服务器并处理命令的解决方案的基线。

驱动车辆的板上运行的代码必须能够处理在特定主题的消息中接收到的命令。我们将在有效载荷中使用 JSON 字符串。

另外，还必须使用 Python 编写的客户端应用程序能够控制一个或多个车辆。我们还将使用 Python 编写客户端应用程序，并且它将向每辆车的主题发布带有 JSON 字符串的 MQTT 消息。客户端应用程序必顶要显示执行每个命令的结果。每辆车在成功执行命令时必须向特定主题发布消息。

# 定义主题和命令

我们将使用以下主题名称发布车辆的命令：`vehicles/vehiclename/commands`，其中`vehiclename`必须替换为分配给车辆的唯一名称。例如，如果我们将`vehiclepi01`分配为由 Raspberry Pi 3 Model B+板驱动的车辆的名称，我们将不得不向`vehicles/vehiclepi01/commands`主题发布命令。在该板上运行的 Python 代码将订阅此主题，以接收带有命令的消息并对其做出反应。

我们将使用以下主题名称使车辆发布有关成功执行命令的详细信息：`vehicles/vehiclename/executedcommands`，其中`vehiclename`必须替换为分配给车辆的唯一名称。例如，如果我们将`vehiclebeagle03`分配为由 BeagleBone Black 板提供动力的车辆的名称，那么想要接收有关成功处理命令的信息的客户端必须订阅`vehicles/vehiclebeagle03/executedcommands`主题。

命令将以 JSON 字符串的形式发送，其中包含键值对。键必须等于 CMD，值必须指定以下任何有效命令之一。当命令需要额外参数时，参数名称必须包含在下一个键中，而此参数的值必须包含在此键的值中：

+   启动车辆的发动机。

+   关闭车辆的发动机。

+   锁上车门。

+   解锁并打开车门。

+   停车：停车。

+   在为车辆配置的安全位置停车。

+   打开车辆的前灯。

+   关闭车辆的前灯。

+   打开车辆的停车灯，也称为侧灯。

+   关闭车辆的停车灯，也称为侧灯。

+   加速：加速车辆，即踩油门。

+   刹车：刹车车辆，即踩刹车踏板。

+   向右旋转：使车辆向右旋转。我们必须在 DEGREES 键的值中指定我们希望车辆向右旋转多少度。

+   向左旋转：使车辆向左旋转。我们必须在 DEGREES 键的值中指定我们希望车辆向左旋转多少度。

+   设置我们允许车辆的最高速度。我们必须在 MPH 键的值中指定所需的最高速度（以每小时英里为单位）。

+   设置我们允许车辆的最低速度。我们必须在 MPH 键的值中指定所需的最低速度（以每小时英里为单位）。

以下一行显示了将车辆的发动机打开的命令的有效负载示例：

```py
{"CMD": "TURN_ON_ENGINE"}
```

以下一行显示了将车辆的最高速度设置为每小时五英里的命令的有效负载示例：

```py
{"CMD": "SET_MAX_SPEED", "MPH": 5}
```

我们已经准备好开始使用 Python 编码所需的所有细节。

# 使用 Python 3.6.x 和 PEP 405 创建虚拟环境

在接下来的章节中，我们将编写不同的 Python 代码片段，这些代码片段将订阅主题，并且还将向主题发布消息。每当我们想要隔离需要额外软件包的环境时，最好使用 Python 虚拟环境。Python 3.3 引入了轻量级虚拟环境，并在 Python 3.4 中进行了改进。我们将使用这些虚拟环境，因此，您需要 Python 3.4 或更高版本。您可以在此处阅读有关 PEP 405 Python 虚拟环境的更多信息，该文档介绍了 venv 模块：[`www.python.org/dev/peps/pep-0405`](https://www.python.org/dev/peps/pep-0405)。

本书的所有示例都在 macOS 和 Linux 上的 Python 3.6.2 上进行了测试。这些示例还在本书中提到的物联网板上进行了测试，以及它们最流行的操作系统。例如，所有示例都在 Raspbian 上进行了测试。 Raspbian 基于 Debian Linux，因此，所有 Linux 的说明都适用于 Raspbian。

如果您决定使用流行的`virtualenv`（[`pypi.python.org/pypi/virtualenv`](https://pypi.python.org/pypi/virtualenv)）第三方虚拟环境构建器或您的 Python IDE 提供的虚拟环境选项，您只需确保在必要时激活您的虚拟环境，而不是按照使用 Python 中集成的`venv`模块生成的虚拟环境的步骤来激活它。

我们使用`venv`创建的每个虚拟环境都是一个隔离的环境，并且它将在其站点目录（文件夹）中具有其自己独立安装的 Python 软件包集。在 Python 3.4 及更高版本中，使用`venv`创建虚拟环境时，`pip`已包含在新的虚拟环境中。在 Python 3.3 中，需要在创建虚拟环境后手动安装`pip`。请注意，所提供的说明与 Python 3.4 或更高版本兼容，包括 Python 3.6.x。以下命令假定您在 Linux、macOS 或 Windows 上已安装了 Python 3.5.x 或更高版本。

首先，我们必须选择我们轻量级虚拟环境的目标文件夹或目录。以下是我们在 Linux 和 macOS 示例中将使用的路径。虚拟环境的目标文件夹将是我们的主目录中的`HillarMQTT/01`文件夹。例如，如果我们在 macOS 或 Linux 中的主目录是`/Users/gaston`，则虚拟环境将在`/Users/gaston/HillarMQTT/01`中创建。您可以在每个命令中用您想要的路径替换指定的路径：

```py
~/HillarMQTT/01
```

以下是我们在 Windows 示例中将使用的路径。虚拟环境的目标文件夹将是用户个人资料文件夹中的`HillarMQTT\01`文件夹。例如，如果我们的用户个人资料文件夹是`C:\Users\gaston`，则虚拟环境将在`C:\Users\gaston\HillarMQTT\01`中创建。您可以在每个命令中用您想要的路径替换指定的路径：

```py
%USERPROFILE%\HillarMQTT\01
```

在 Windows PowerShell 中，上一个路径将是：

```py
$env:userprofile\HillarMQTT\01
```

现在，我们必须使用`-m`选项，后跟`venv`模块名称和所需的路径，使 Python 运行此模块作为脚本，并在指定的路径中创建虚拟环境。根据我们创建虚拟环境的平台，指令是不同的。

在 Linux 或 macOS 中打开终端并执行以下命令创建虚拟环境：

```py
python3 -m venv ~/HillarMQTT/01
```

在 Windows 的命令提示符中，执行以下命令创建虚拟环境：

```py
python -m venv %USERPROFILE%\HillarMQTT\01
```

如果要在 Windows PowerShell 中工作，请执行以下命令创建虚拟环境：

```py
python -m venv $env:userprofile\HillarMQTT\01
```

上述任何命令都不会产生任何输出。脚本通过调用`ensurepip`安装了`pip`，因为我们没有指定`--without-pip`选项。

# 了解虚拟环境的目录结构

指定的目标文件夹具有一个新的目录树，其中包含 Python 可执行文件和其他文件，表明它是一个 PEP405 虚拟环境。

在虚拟环境的根目录中，`pyenv.cfg`配置文件指定了虚拟环境的不同选项，其存在表明我们处于虚拟环境的根文件夹中。在 Linux 和 macOS 中，该文件夹将具有以下主要子文件夹：`bin`、`include`、`lib`、`lib/python3.6`和`lib/python3.6/site-packages`。请注意，文件夹名称可能根据具体的 Python 版本而有所不同。在 Windows 中，该文件夹将具有以下主要子文件夹：`Include`、`Lib`、`Lib\site-packages`和`Scripts`。每个平台上的虚拟环境的目录树与这些平台上 Python 安装的布局相同。

以下屏幕截图显示了在 macOS 和 Linux 平台上为`01`虚拟环境生成的目录树中的文件夹和文件：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-mqtt-prog-py/img/89de4379-d681-4d7d-bfe2-e816e637fa68.png)

下面的屏幕截图显示了在 Windows 为虚拟环境生成的目录树中的主要文件夹：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-mqtt-prog-py/img/e5e90a3e-c514-4f2a-be55-350e276a53e6.png)

激活虚拟环境后，我们将在虚拟环境中安装第三方软件包，模块将位于`lib/python3.6/site-packages`或`Lib\site-packages`文件夹中，根据平台和特定的 Python 版本。可执行文件将被复制到`bin`或`Scripts`文件夹中，根据平台而定。我们安装的软件包不会对其他虚拟环境或我们的基本 Python 环境进行更改。

# 激活虚拟环境

现在我们已经创建了一个虚拟环境，我们将运行一个特定于平台的脚本来激活它。激活虚拟环境后，我们将安装软件包，这些软件包只能在此虚拟环境中使用。这样，我们将使用一个隔离的环境，在这个环境中，我们安装的所有软件包都不会影响我们的主 Python 环境。

在 Linux 或 macOS 的终端中运行以下命令。请注意，如果您在终端会话中没有启动与默认 shell 不同的其他 shell，此命令的结果将是准确的。如果您有疑问，请检查您的终端配置和首选项：

```py
echo $SHELL
```

该命令将显示您在终端中使用的 shell 的名称。在 macOS 中，默认值为`/bin/bash`，这意味着您正在使用 bash shell。根据 shell 的不同，您必须在 Linux 或 macOS 中运行不同的命令来激活虚拟环境。

如果您的终端配置为在 Linux 或 macOS 中使用 bash shell，请运行以下命令来激活虚拟环境。该命令也适用于`zsh` shell：

```py
source ~/HillarMQTT/01/bin/activate
```

如果您的终端配置为使用`csh`或`tcsh` shell，请运行以下命令来激活虚拟环境：

```py
source ~/HillarMQTT/01/bin/activate.csh
```

如果您的终端配置为使用`fish` shell，请运行以下命令来激活虚拟环境：

```py
source ~/HillarMQTT/01/bin/activate.fish
```

激活虚拟环境后，命令提示符将显示虚拟环境根文件夹名称括在括号中作为默认提示的前缀，以提醒我们正在虚拟环境中工作。在这种情况下，我们将看到**(01)**作为命令提示符的前缀，因为激活的虚拟环境的根文件夹是`01`。

下面的屏幕截图显示在 macOS High Sierra 终端中使用`bash` shell 激活的虚拟环境，在执行先前显示的命令后：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-mqtt-prog-py/img/42c36ca7-12a9-421e-a366-c41041a57ec5.png)

从先前的屏幕截图中可以看出，在激活虚拟环境后，提示从`Gastons-MacBook-Pro:~ gaston$`变为`(01) Gastons-MacBook-Pro:~ gaston$`。

在 Windows 中，您可以在命令提示符中运行批处理文件或 Windows PowerShell 脚本来激活虚拟环境。

如果您喜欢使用命令提示符，请在 Windows 命令行中运行以下命令来激活虚拟环境：

```py
%USERPROFILE%\HillarMQTT\01\Scripts\activate.bat
```

下面的屏幕截图显示在 Windows 10 命令提示符中激活的虚拟环境，在执行先前显示的命令后：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-mqtt-prog-py/img/d93be1d1-aa98-40a6-94f6-e84f628a5ea3.png)

从先前的屏幕截图中可以看出，在激活虚拟环境后，提示从`C:\Users\gaston`变为`(01) C:\Users\gaston`。

如果您喜欢使用 Windows PowerShell，请启动它并运行以下命令来激活虚拟环境。请注意，您必须在 Windows PowerShell 中启用脚本执行才能运行该脚本：

```py
cd $env:USERPROFILE
.\HillarMQTT\01\Scripts\Activate.ps1
```

如果您收到类似以下错误的错误，这意味着您没有启用脚本执行：

```py
C:\Users\gaston\HillarMQTT\01\Scripts\Activate.ps1 : File C:\Users\gaston\HillarMQTT\01\Scripts\Activate.ps1 cannot be loaded because running scripts is disabled on this system. For more information, see about_Execution_Policies at
http://go.microsoft.com/fwlink/?LinkID=135170.
At line:1 char:1
+ C:\Users\gaston\HillarMQTT\01\Scripts\Activate.ps1
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 + CategoryInfo : SecurityError: (:) [], PSSecurityException
 + FullyQualifiedErrorId : UnauthorizedAccess
```

Windows PowerShell 的默认执行策略是`Restricted`。此策略允许执行单个命令，但不运行脚本。因此，如果要使用 Windows PowerShell，必须更改策略以允许执行脚本。非常重要的是确保您了解允许运行未签名脚本的 Windows PowerShell 执行策略的风险。有关不同策略的更多信息，请查看以下网页：[`docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies?view=powershell-6`](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies?view=powershell-6)。

以下屏幕截图显示了在 Windows 10 PowerShell 中激活的虚拟环境，执行了先前显示的命令：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-mqtt-prog-py/img/14730ab3-23c5-456b-a559-bacda570a93a.png)

# 取消激活虚拟环境

使用先前解释的过程生成的虚拟环境非常容易取消激活。取消激活将删除环境变量中的所有更改，并将提示更改回其默认消息。取消激活虚拟环境后，您将返回到默认的 Python 环境。

在 macOS 或 Linux 中，只需键入`deactivate`并按*Enter*。

在命令提示符中，您必须运行`Scripts`文件夹中包含的`deactivate.bat`批处理文件。在我们的示例中，此文件的完整路径为`%USERPROFILE%\HillarMQTT\01\Scripts\deactivate.bat`。

在 Windows PowerShell 中，您必须在`Scripts`文件夹中运行`Deactivate.ps1`脚本。在我们的示例中，此文件的完整路径为`$env:userprofile\HillarMQTT\01\Scripts\Deactivate.ps1`。请记住，必须在 Windows PowerShell 中启用脚本执行，才能运行该脚本。

下一节的说明假定我们创建的虚拟环境已激活。

# 安装 Python 的 paho-mqtt

Eclipse Paho 项目提供了 MQTT 的开源客户端实现。该项目包括 Python 客户端，也称为 Paho Python 客户端或 Eclipse Paho MQTT Python 客户端库。此 Python 客户端是从 Mosquitto 项目贡献的，最初被称为 Mosquitto Python 客户端。以下是 Eclipse Paho 项目的网页：[`www.eclipse.org/paho`](http://www.eclipse.org/paho)。以下是 Eclipse Paho MQTT Python 客户端库版本 1.3.1 的网页，即`paho-mqtt`模块版本 1.3.1：[`pypi.python.org/pypi/paho-mqtt/1.3.1`](https://pypi.python.org/pypi/paho-mqtt/1.3.1)。

我们可以在许多支持 Python 3.x 或更高版本的现代物联网板上使用`paho-mqtt`。我们只需要确保安装了`pip`，以便更容易安装`paho-mqtt`。您可以使用开发计算机来运行示例，也可以使用前面提到的任何一个物联网板。

确保在继续下一步之前，我们在上一步中创建的虚拟环境已激活。

如果要使用物联网板运行示例，请确保在 SSH 终端或运行在板子上的终端窗口中运行所有命令。如果使用开发计算机，请在 macOS 或 Linux 中的终端或 Windows 中的命令提示符中运行命令。

现在，我们将使用`pip`安装程序安装`paho-mqtt` 1.3.1。我们只需要在 SSH 终端或我们与板子一起使用的本地终端窗口中运行以下命令，或者在用于安装软件包的计算机上运行：

```py
pip install paho-mqtt==1.3.1
```

一些物联网板具有需要您在运行上述命令之前安装`pip`的操作系统。在带有 Raspbian 的 Raspberry Pi 3 板上，`pip`已经安装。如果您使用计算机，则 Python 安装通常包括`pip`。

如果您在 Windows 的默认文件夹中安装了 Python，并且没有使用 Python 虚拟环境，您将不得不在管理员命令提示符中运行上一个命令。如果您在 Raspbian 中没有使用 Python 虚拟环境，您将不得不在前面加上`sudo`前缀运行上一个命令：`sudo pip install paho-mqtt`。然而，如前所述，强烈建议使用虚拟环境。

输出的最后几行将指示`paho-mqtt`包版本 1.3.1 已成功安装。输出将类似于以下行，但不完全相同，因为它将根据您运行命令的平台而变化：

```py
Collecting paho-mqtt==1.3.1
 Downloading paho-mqtt-1.3.1.tar.gz (80kB)
 100% |################################| 81kB 1.2MB/s 
Installing collected packages: paho-mqtt
 Running setup.py install for paho-mqtt ... done
Successfully installed paho-mqtt-1.3.1
```

# 使用 paho-mqtt 将客户端连接到安全的 MQTT 服务器

首先，我们将使用`paho-mqtt`创建一个连接到 Mosquitto MQTT 服务器的 MQTT 客户端。我们将编写几行 Python 代码来建立一个安全连接并订阅一个主题。

在第三章中，*保护 MQTT 3.1.1 Mosquitto 服务器*，我们保护了我们的 Mosquitto 服务器，因此，我们将使用我们创建的数字证书来对客户端进行身份验证。大多数情况下，我们将使用 TLS 的 MQTT 服务器，因此，学习如何建立 TLS 和 TLS 身份验证连接是一个好主意。建立与 MQTT 服务器的非安全连接更容易，但在开发与 MQTT 配合工作的应用程序时，这不会是我们面临的最常见情况。

首先，我们需要复制以下文件，这些文件是我们在[第三章](https://cdp.packtpub.com/hands_on_mqtt_programming_with_python/wp-admin/post.php?post=107&action=edit#post_26)中创建的，*保护 MQTT 3.1.1 Mosquitto 服务器*，到计算机或设备上的目录，我们将用它来运行 Python 脚本。我们将文件保存在一个名为`mqtt_certificates`的目录中。在您将用作 MQTT 客户端的计算机或板上创建一个名为`board_certificates`的新目录。将以下三个文件复制到这个新目录中：

+   `ca.crt`：证书颁发机构证书文件

+   `board001.crt`：客户端证书文件

+   `board001.key`：客户端密钥

现在，我们将在主虚拟环境文件夹中创建一个名为`config.py`的新的 Python 文件。以下几行显示了该文件的代码，该代码定义了许多配置值，这些值将用于与 Mosquitto MQTT 服务器建立连接。这样，所有配置值都包含在一个特定的 Python 脚本中。您必须将`certificates_path`字符串中的`/Users/gaston/board_certificates`值替换为您创建的`board_certificates`目录的路径。此外，用 Mosquitto 服务器或任何其他您决定使用的 MQTT 服务器的 IP 地址或主机名替换`mqtt_server_host`的值。示例的代码文件包含在`mqtt_python_gaston_hillar_04_01`文件夹中的`config.py`文件中：

```py
import os.path

# Replace /Users/gaston/python_certificates with the path
# in which you saved the certificate authority file,
# the client certificate file and the client key
certificates_path = "/Users/gaston/python_certificates"
ca_certificate = os.path.join(certificates_path, "ca.crt")
client_certificate = os.path.join(certificates_path, "board001.crt")
client_key = os.path.join(certificates_path, "board001.key")
# Replace 192.168.1.101 with the IP or hostname for the Mosquitto
# or other MQTT server
# Make sure the IP or hostname matches the value 
# you used for Common Name
mqtt_server_host = "192.168.1.101"
mqtt_server_port = 8883
mqtt_keepalive = 60
```

该代码声明了`certificates_path`变量，该变量初始化为一个字符串，指定了您保存证书颁发机构文件、客户端证书文件和客户端密钥（`ca.crt`、`board001.crt`和`board001.key`）的路径。然后，该代码声明了以下字符串变量，这些变量包含了我们需要配置 TLS 和 TLS 客户端身份验证的证书和密钥文件的完整路径：`ca_certificate`、`client_certificate`和`client_key`。

调用`os.path.join`使得将`certificates_path`变量中指定的路径与文件名连接并生成完整路径变得容易。`os.path.join`函数适用于任何平台，因此我们不必担心是使用斜杠(`/`)还是反斜杠(`\`)来将路径与文件名连接。有时，我们可以在 Windows 中开发和测试，然后在可以使用不同 Unix 或 Linux 版本的 IoT 板上运行代码，例如 Raspbian 或 Ubuntu。在我们在不同平台之间切换的情况下，使用`os.path.join`使得我们的工作更加容易。

`mqtt_server_host`、`mqtt_server_port`和`mqtt_keepalive`变量指定了 MQTT 服务器（Mosquitto 服务器）的 IP 地址（`192.168.1.101`），我们要使用的端口（`8883`），以及保持连接的秒数。非常重要的是要用 MQTT 服务器的 IP 地址替换`192.168.1.101`。我们将`mqtt_server_port`指定为`8883`，因为我们使用 TLS，这是 MQTT over TLS 的默认端口，正如我们在[第三章](https://cdp.packtpub.com/hands_on_mqtt_programming_with_python/wp-admin/post.php?post=107&action=edit#post_26)中学到的，*Securing an MQTT 3.1.1 Mosquitto Server*。

现在，我们将在主虚拟环境文件夹中创建一个名为`subscribe_with_paho.py`的新 Python 文件。以下行显示了该文件的代码，该代码与我们的 Mosquitto MQTT 服务器建立连接，订阅`vehicles/vehiclepi01/tests`主题过滤器，并打印出订阅主题过滤器中接收到的所有消息。示例的代码文件包含在`mqtt_python_gaston_hillar_04_01`文件夹中的`subscribe_with_paho.py`文件中。

```py
from config import *
import paho.mqtt.client as mqtt

def on_connect(client, userdata, flags, rc):
    print("Result from connect: {}".format(
        mqtt.connack_string(rc)))
    # Subscribe to the vehicles/vehiclepi01/tests topic filter
    client.subscribe("vehicles/vehiclepi01/tests", qos=2)

def on_subscribe(client, userdata, mid, granted_qos):
    print("I've subscribed with QoS: {}".format(
        granted_qos[0]))

def on_message(client, userdata, msg):
    print("Message received. Topic: {}. Payload: {}".format(
        msg.topic, 
        str(msg.payload)))

if __name__ == "__main__":
    client = mqtt.Client(protocol=mqtt.MQTTv311)
    client.on_connect = on_connect
    client.on_subscribe = on_subscribe
    client.on_message = on_message
    client.tls_set(ca_certs = ca_certificate,
        certfile=client_certificate,
        keyfile=client_key)
    client.connect(host=mqtt_server_host,
        port=mqtt_server_port,
        keepalive=mqtt_keepalive)
    client.loop_forever()

```

请注意，该代码与`paho-mqtt`版本 1.3.1 兼容。早期版本的`paho-mqtt`与该代码不兼容。因此，请确保按照先前解释的步骤安装`paho-mqtt`版本 1.3.1。

# 理解回调

前面的代码使用了最近安装的`paho-mqtt`版本 1.3.1 模块与 MQTT 服务器建立加密连接，订阅`vehicles/vehiclepi01/tests`主题过滤器，并在接收到主题中的消息时运行代码。我们将使用这段代码来了解`paho-mqtt`的基础知识。该代码是一个非常简单的 MQTT 客户端版本，订阅了一个主题过滤器，我们将在接下来的部分中对其进行改进。

第一行导入了我们在先前编写的`config.py`文件中声明的变量。第二行将`paho.mqtt.client`导入为`mqtt`。这样，每当我们使用`mqtt`别名时，我们将引用`paho.mqtt.client`。

当我们声明一个函数时，我们将此函数作为参数传递给另一个函数或方法，或者将此函数分配给一个属性，然后一些代码在某个时候调用此函数；这种机制被称为**回调**。之所以称之为回调，是因为代码在某个时候回调函数。`paho-mqtt`版本 1.3.1 包要求我们使用许多回调，因此了解它们的工作原理非常重要。

该代码声明了以下三个我们稍后指定为回调的函数：

+   `on_connect`：当 MQTT 客户端从 MQTT 服务器接收到`CONNACK`响应时，即成功与 MQTT 服务器建立连接时，将调用此函数。

+   `on_subscribe`：当 MQTT 客户端从 MQTT 服务器接收到`SUBACK`响应时，即成功完成订阅时，将调用此函数。

+   `on_message`：当 MQTT 客户端从 MQTT 服务器接收到`PUBLISH`消息时，将调用此函数。每当 MQTT 服务器基于客户端的订阅发布消息时，将调用此函数。

下表总结了基于从 MQTT 服务器接收到的响应调用的函数：

| **来自 MQTT 服务器的响应** | **将被调用的函数** |
| --- | --- |
| `CONNACK` | `on_connnect` |
| `SUBACK` | `on_subscribe` |
| `PUBLISH` | `on_message` |

主要代码块创建了代表 MQTT 客户端的`mqtt.Client`类（`paho.mqtt.client.Client`）的实例。我们使用这个实例与我们的 MQTT 服务器 Mosquitto 进行通信。如果我们使用默认参数创建新实例，我们将使用 MQTT 版本 3.1。我们想要使用 MQTT 版本 3.11，因此我们将`mqtt.MQTTv311`指定为协议参数的值。

然后，代码将函数分配给属性。以下表总结了这些分配：

| **属性** | **分配的函数** |
| --- | --- |
| `client.on_connect` | `on_connect` |
| `client.on_message` | `on_message` |
| `client.on_subscribe` | `on_subscribe` |

调用`client.tls_set`方法配置加密和认证选项非常重要，在运行`client.connect`方法之前调用此方法。我们在`ca_certs`、`certfile`和`keyfile`参数中指定证书颁发机构证书文件、客户端证书和客户端密钥的完整字符串路径。`ca_certs`参数名称有点令人困惑，但我们只需要指定证书颁发机构证书文件的字符串路径，而不是多个证书。

最后，主要代码块调用`client.connect`方法，并指定`host`、`port`和`keepalive`参数的值。这样，代码要求 MQTT 客户端与指定的 MQTT 服务器建立连接。

`connect`方法以异步执行方式运行，因此它是一个非阻塞调用。

成功与 MQTT 服务器建立连接后，将执行`client.on_connect`属性中指定的回调，即`on_connect`函数。此函数在 client 参数中接收与 MQTT 服务器建立连接的`mqtt.Client`实例。

如果要与不使用 TLS 的 MQTT 服务器建立连接，则无需调用`client.tls_set`方法。此外，您需要使用适当的端口，而不是在使用 TLS 时指定的`8883`端口。请记住，当不使用 TLS 时，默认端口是`1883`。

# 使用 Python 订阅主题

代码调用`client.subscribe`方法，参数为`"vehicles/vehiclepi01/tests"`，以订阅这个特定的单个主题，并将`qos`参数设置为`2`，以请求 QoS 级别为 2。

在这种情况下，我们只订阅一个主题。但是，非常重要的是要知道，我们不限于订阅单个主题过滤器；我们可以通过一次调用`subscribe`方法订阅许多主题过滤器。

在 MQTT 服务器确认成功订阅指定主题过滤器并返回`SUBACK`响应后，将执行`client.on_subscribe`属性中指定的回调，即`on_subscribe`函数。此函数在`granted_qos`参数中接收一个整数列表，提供 MQTT 服务器为每个主题过滤器订阅请求授予的 QoS 级别。`on_subscribe`函数中的代码显示了 MQTT 服务器为我们指定的主题过滤器授予的 QoS 级别。在这种情况下，我们只订阅了一个单一的主题过滤器，因此代码从接收到的`granted_qos`数组中获取第一个值。

每当收到与我们订阅的主题过滤器匹配的新消息时，将执行`client.on_messsage`属性中指定的回调，即`on_message`函数。此函数在 client 参数中接收与 MQTT 服务器建立连接的`mqtt.Client`实例，并在`msg`参数中接收一个`mqtt.MQTTMessage`实例。`mqtt.MQTTMessage`类描述了一条传入消息。

在这种情况下，每当执行`on_message`函数时，`msg.topic`中的值将始终匹配`"vehicles/vehiclepi01/tests"`，因为我们刚刚订阅了一个主题，没有其他主题名称与主题过滤器匹配。但是，如果我们订阅了一个或多个主题过滤器，其中可能有多个主题匹配，那么始终需要检查`msg.topic`属性的值来确定消息是发送到哪个主题。

`on_message`函数中的代码打印已接收消息的主题`msg.topic`和消息的有效负载的字符串表示形式，即`msg.payload`属性。

最后，主块调用`client.loop_forever`方法，该方法以无限阻塞循环为我们调用`loop`方法。在这一点上，我们只想在我们的程序中运行 MQTT 客户端循环。我们将接收与我们订阅的主题匹配的消息。

`loop`方法负责处理网络事件，即确保与 MQTT 服务器的通信进行。您可以将`loop`方法视为将电子邮件客户端同步以接收传入消息并发送发件箱中的消息的等效方法。

确保 Mosquitto 服务器或您可能要用于此示例的任何其他 MQTT 服务器正在运行。然后，在要用作 MQTT 客户端并使用 Linux 或 macOS 的任何计算机或设备上执行以下行以启动示例：

```py
python3 subscribe_with_paho.py
```

在 Windows 中，您必须执行以下行：

```py
python subscribe_with_paho.py
```

如果您看到类似以下行的`SSLError`的回溯，这意味着 MQTT 服务器的主机名或 IP 与生成名为`server.crt`的服务器证书文件时指定的`Common Name`属性的值不匹配。确保检查 MQTT 服务器（Mosquitto 服务器）的 IP 地址，并使用指定为`Common Name`的适当 IP 地址或主机名再次生成服务器证书文件和密钥，如[第三章](https://cdp.packtpub.com/hands_on_mqtt_programming_with_python/wp-admin/post.php?post=107&action=edit#post_26)中所述，*Securing an MQTT 3.1.1 Mosquitto Server*，如果您正在使用我们生成的自签名证书。如果您正在使用自签名证书、IP 地址和 DHCP 服务器，请还要检查 DHCP 服务器是否更改了 Mosquitto 服务器的 IP 地址：

```py
Traceback (most recent call last):
 File "<stdin>", line 1, in <module>
 File "/Users/gaston/HillarMQTT/01/lib/python3.6/site-packages/paho/mqtt/client.py", line 612, in connect
 return self.reconnect()
 File "/Users/gaston/HillarMQTT/01/lib/python3.6/site-packages/paho/mqtt/client.py", line 751, in reconnect
 self._tls_match_hostname()
 File "/Users/gaston/HillarMQTT/01/lib/python3.6/site-packages/paho/mqtt/client.py", line 2331, in _tls_match_hostname
 raise ssl.SSLError('Certificate subject does not match remote hostname.')
```

现在，按照以下步骤使用 MQTT.fx GUI 实用程序向`vehicles/vehiclepi01/tests`主题发布两条消息：

1.  启动 MQTT.fx，并按照我们在[第三章](https://cdp.packtpub.com/hands_on_mqtt_programming_with_python/wp-admin/post.php?post=107&action=edit#post_26)中学到的步骤与 MQTT 服务器建立连接，*Securing an MQTT 3.1.1 Mosquitto Server*。

1.  单击 Publish 并在 Publish 按钮左侧的下拉菜单中输入`vehicles/vehiclepi01/tests`。

1.  单击 Publish 按钮右侧的 QoS 2。

1.  在 Publish 按钮下的文本框中输入以下文本：`{"CMD": " UNLOCK_DOORS"}`。然后，单击 Publish 按钮。MQTT.fx 将输入的文本发布到指定的主题。

1.  在 Publish 按钮下的文本框中输入以下文本：`{"CMD": "TURN_ON_HEADLIGHTS"}`。然后，单击 Publish 按钮。MQTT.fx 将输入的文本发布到指定的主题。

如果您不想使用 MQTT.fx 实用程序，可以运行两个`mosquitto_pub`命令来生成发布消息到主题的 MQTT 客户端。您只需要在 macOS 或 Linux 中打开另一个终端，或者在 Windows 中打开另一个命令提示符，转到 Mosquitto 安装的目录，并运行以下命令。在这种情况下，不需要指定`-d`选项。将`192.168.1.101`替换为 MQTT 服务器的 IP 或主机名。记得将`ca.crt`、`board001.crt`和`board001.key`替换为在`board_certificates`目录中创建的这些文件的完整路径。示例的代码文件包含在`mqtt_python_gaston_hillar_04_01`文件夹中的`script_01.txt`文件中：

```py
mosquitto_pub -h 192.168.1.101 -V mqttv311 -p 8883 --cafile ca.crt --cert board001.crt --key board001.key -t vehicles/vehiclepi01/tests -m '{"CMD": "UNLOCK_DOORS"}' -q 2 --tls-version tlsv1.2

mosquitto_pub -h 192.168.1.101 -V mqttv311 -p 8883 --cafile ca.crt --cert board001.crt --key board001.key -t vehicles/vehiclepi01/tests -m '{"CMD": "TURN_ON_HEADLIGHTS"}' -q 2 --tls-version tlsv1.2
```

转到您执行 Python 脚本的设备和窗口。您将看到以下输出：

```py
Result from connect: Connection Accepted.
I've subscribed with QoS: 2
Message received. Topic: vehicles/vehiclepi01/tests. Payload: b'{"CMD": "UNLOCK_DOORS"}'
Message received. Topic: vehicles/vehiclepi01/tests. Payload: b'{"CMD": "TURN_ON_HEADLIGHTS"}'
```

Python 程序成功地与 MQTT 服务器建立了安全加密的连接，并成为了`vehicles/vehiclepi01/tests`主题的订阅者，授予了 QoS 级别 2。该程序显示了它在`vehicles/vehiclepi01/tests`主题中接收到的两条消息。

按下*Ctrl* + *C*停止程序的执行。生成的 MQTT 客户端将关闭与 MQTT 服务器的连接。您将看到类似以下输出的错误消息，因为循环执行被中断：

```py
Traceback (most recent call last):
 File "subscribe_with_paho.py", line 33, in <module>
 client.loop_forever()
 File "/Users/gaston/HillarMQTT/01/lib/python3.6/site-packages/paho/mqtt/client.py", line 1481, in loop_forever
 rc = self.loop(timeout, max_packets)
 File "/Users/gaston/HillarMQTT/01/lib/python3.6/site-packages/paho/mqtt/client.py", line 988, in loop
 socklist = select.select(rlist, wlist, [], timeout)
KeyboardInterrupt
```

# 为将作为客户端工作的物联网板配置证书

现在，我们将编写 Python 代码，该代码将准备在不同的物联网板上运行。当然，您可以在单个开发计算机或开发板上工作。无需在不同设备上运行代码。我们只是想确保我们可以编写能够在不同设备上运行的代码。

记得将我们在上一章中创建的文件复制到代表控制车辆的板的计算机或设备上，并且我们将用它来运行 Python 脚本。如果您将继续使用到目前为止一直在使用的同一台计算机或设备，您无需遵循下一步。

我们将文件保存在一个名为`mqtt_certificates`的目录中。在您将用作此示例的 MQTT 客户端的计算机或板上创建一个`board_certificates`目录。将以下三个文件复制到这个新目录中：

+   `ca.crt`：证书颁发机构证书文件

+   `board001.crt`：客户端证书文件

+   `board001.key`：客户端密钥

# 创建一个代表车辆的类

我们将创建以下两个类：

+   `Vehicle`：这个类将代表一个车辆，并提供在处理命令时将被调用的方法。为了保持示例简单，我们的方法将在每次调用后将车辆执行的操作打印到控制台输出。代表车辆的真实类将在每次调用每个方法时与发动机、灯、执行器、传感器和车辆的其他不同组件进行交互。

+   `VehicleCommandProcessor`：这个类将代表一个命令处理器，它将与 MQTT 服务器建立连接，订阅一个主题，其中 MQTT 客户端将接收带有命令的消息，分析传入的消息，并将命令的执行委托给`Vehicle`类的相关实例。`VehicleCommandProcessor`类将声明许多静态方法，我们将指定为 MQTT 客户端的回调。

在主虚拟环境文件夹中创建一个名为`vehicle_commands.py`的新 Python 文件。以下行声明了许多变量，这些变量具有标识车辆支持的每个命令的值。此外，代码还声明了许多变量，这些变量具有我们将用于指定命令的关键字符串以及我们将用于指定成功执行的命令的关键字符串。所有这些变量都以全大写字母定义，因为我们将把它们用作常量。示例的代码文件包含在`mqtt_python_gaston_hillar_04_01`文件夹中的`vehicle_commands.py`文件中。

```py
# Key strings
COMMAND_KEY = "CMD"
SUCCESFULLY_PROCESSED_COMMAND_KEY = "SUCCESSFULLY_PROCESSED_COMMAND"
# Command strings
# Turn on the vehicle's engine.
CMD_TURN_ON_ENGINE = "TURN_ON_ENGINE"
# Turn off the vehicle's engine
CMD_TURN_OFF_ENGINE = "TURN_OFF_ENGINE"
# Close and lock the vehicle's doors
CMD_LOCK_DOORS = "LOCK_DOORS"
# Unlock and open the vehicle's doors
CMD_UNLOCK_DOORS = "UNLOCK_DOORS"
# Park the vehicle
CMD_PARK = "PARK"
# Park the vehicle in a safe place that is configured for the vehicle
CMD_PARK_IN_SAFE_PLACE = "PARK_IN_SAFE_PLACE"
# Turn on the vehicle's headlights
CMD_TURN_ON_HEADLIGHTS = "TURN_ON_HEADLIGHTS"
# Turn off the vehicle's headlights
CMD_TURN_OFF_HEADLIGHTS = "TURN_OFF_HEADLIGHTS"
# Turn on the vehicle's parking lights, also known as sidelights
CMD_TURN_ON_PARKING_LIGHTS = "TURN_ON_PARKING_LIGHTS"
# Turn off the vehicle's parking lights, also known as sidelights
CMD_TURN_OFF_PARKING_LIGHTS = "TURN_OFF_PARKING_LIGHTS"
# Accelerate the vehicle, that is, press the gas pedal
CMD_ACCELERATE = "ACCELERATE"
# Brake the vehicle, that is, press the brake pedal
CMD_BRAKE = "BRAKE"
# Make the vehicle rotate to the right. We must specify the degrees 
# we want the vehicle to rotate right in the value for the DEGREES key
CMD_ROTATE_RIGHT = "ROTATE_RIGHT"
# Make the vehicle rotate to the left. We must specify the degrees 
# we want the vehicle to rotate left in the value for the DEGREES key
CMD_ROTATE_LEFT = "ROTATE_LEFT"
# Set the maximum speed that we allow to the vehicle. We must specify 
# the desired maximum speed in miles per hour in the value for the MPH key
CMD_SET_MAX_SPEED = "SET_MAX_SPEED"
# Set the minimum speed that we allow to the vehicle. We must specify 
# the desired minimum speed in miles per hour in the value for the MPH key
CMD_SET_MIN_SPEED = "SET_MIN_SPEED"
# Degrees key
KEY_DEGREES = "DEGREES"
# Miles per hour key
KEY_MPH = "MPH"
```

`COMMAND_KEY`变量定义了一个关键字符串，该字符串定义了代码将理解为命令。每当我们接收包含指定关键字符串的消息时，我们知道字典中与此关键相关联的值将指示消息希望代码在板上运行的命令被处理。MQTT 客户端不会接收消息作为字典，因此，当它们不仅仅是一个字符串时，有必要将它们从字符串转换为字典。

`SUCCESSFULLY_PROCESSED_COMMAND_KEY`变量定义了一个关键字符串，该字符串定义了代码将在发布到适当主题的响应消息中用作成功处理的命令键。每当我们发布包含指定关键字符串的消息时，我们知道字典中与此关键相关联的值将指示板成功处理的命令。

在主虚拟环境文件夹中创建一个名为`vehicle_mqtt_client.py`的新 Python 文件。以下行声明了必要的导入和与前面示例中使用的相同变量，以建立与 MQTT 服务器的连接。然后，这些行声明了`Vehicle`类。示例的代码文件包含在`mqtt_python_gaston_hillar_04_01`文件夹中的`vehicle_mqtt_client.py`文件中。

```py
class Vehicle:
    def __init__(self, name):
        self.name = name
        self.min_speed_mph = 0
        self.max_speed_mph = 10

    def print_action_with_name_prefix(self, action):
        print("{}: {}".format(self.name, action))

    def turn_on_engine(self):
        self.print_action_with_name_prefix("Turning on the engine")

    def turn_off_engine(self):
        self.print_action_with_name_prefix("Turning off the engine")

    def lock_doors(self):
        self.print_action_with_name_prefix("Locking doors")

    def unlock_doors(self):
        self.print_action_with_name_prefix("Unlocking doors")

    def park(self):
        self.print_action_with_name_prefix("Parking")

    def park_in_safe_place(self):
        self.print_action_with_name_prefix("Parking in safe place")

    def turn_on_headlights(self):
        self.print_action_with_name_prefix("Turning on headlights")

    def turn_off_headlights(self):
        self.print_action_with_name_prefix("Turning off headlights")

    def turn_on_parking_lights(self):
        self.print_action_with_name_prefix("Turning on parking lights")

    def turn_off_parking_lights(self):
        self.print_action_with_name_prefix("Turning off parking 
         lights")

    def accelerate(self):
        self.print_action_with_name_prefix("Accelerating")

    def brake(self):
        self.print_action_with_name_prefix("Braking")

    def rotate_right(self, degrees):
        self.print_action_with_name_prefix("Rotating right {} 
          degrees".format(degrees))

    def rotate_left(self, degrees):
        self.print_action_with_name_prefix("Rotating left {} 
           degrees".format(degrees))

    def set_max_speed(self, mph):
        self.max_speed_mph = mph
        self.print_action_with_name_prefix("Setting maximum speed to {} 
        MPH".format(mph))

    def set_min_speed(self, mph):
        self.min_speed_mph = mph
        self.print_action_with_name_prefix("Setting minimum speed to {} 
        MPH".format(mph))
```

与前面的示例一样，用于与 Mosquitto MQTT 服务器建立连接的所有配置值都在名为`config.py`的 Python 文件中定义在主虚拟环境文件夹中。如果要在不同的设备上运行此示例，您将不得不创建一个新的`config.py`文件，并更改导入`config`模块的行，以使用新的配置文件。不要忘记将`certificates_path`字符串中的值`/Users/gaston/board_certificates`替换为您创建的`board_certificates`目录的路径。此外，将`mqtt_server_host`的值替换为 Mosquitto 服务器或其他您决定使用的 MQTT 服务器的 IP 地址或主机名。

我们必须在所需的名称参数中指定车辆的名称。构造函数，即`__init__`方法，将接收的名称保存在具有相同名称的属性中。然后，构造函数为两个属性设置了初始值：`min_speed_mph`和`max_speed_mph`。这些属性确定了车辆的最小和最大速度值，以英里每小时表示。

`Vehicle`类声明了`print_action_with_name_prefix`方法，该方法接收一个包含正在执行的动作的字符串，并将其与保存在`name`属性中的值一起作为前缀打印出来。此类中定义的其他方法调用`print_action_with_name_prefix`方法，以打印指示车辆正在执行的动作的消息，并以车辆的名称作为前缀。

# 在 Python 中接收消息

我们将使用最近安装的`paho-mqtt`版本 1.3.1 模块订阅特定主题，并在接收到主题消息时运行代码。我们将在同一个 Python 文件中创建一个名为`vehicle_mqtt_client.py`的`VehicleCommandProcessor`类，该文件位于主虚拟环境文件夹中。这个类将代表一个与先前编码的`Vehicle`类实例相关联的命令处理器，配置 MQTT 客户端和订阅客户端，并声明当与 MQTT 相关的某些事件被触发时将要执行的回调代码。

我们将`VehicleCommandProcessor`类的代码拆分成许多代码片段，以便更容易理解每个代码部分。您必须将下面的代码添加到现有的`vehicle_mqtt_client.py` Python 文件中。以下代码声明了`VehicleCommandProcessor`类及其构造函数，即`__init__`方法。示例的代码文件包含在`mqtt_python_gaston_hillar_04_01`文件夹中的`vehicle_mqtt_client.py`文件中：

```py
class VehicleCommandProcessor:
    commands_topic = ""
    processed_commands_topic = ""
    active_instance = None

    def __init__(self, name, vehicle):
        self.name = name
        self.vehicle = vehicle
        VehicleCommandProcessor.commands_topic = \
            "vehicles/{}/commands".format(self.name)
        VehicleCommandProcessor.processed_commands_topic = \
            "vehicles/{}/executedcommands".format(self.name)
        self.client = mqtt.Client(protocol=mqtt.MQTTv311)
        VehicleCommandProcessor.active_instance = self
        self.client.on_connect = VehicleCommandProcessor.on_connect
        self.client.on_subscribe = VehicleCommandProcessor.on_subscribe
        self.client.on_message = VehicleCommandProcessor.on_message
        self.client.tls_set(ca_certs = ca_certificate,
            certfile=client_certificate,
            keyfile=client_key)
        self.client.connect(host=mqtt_server_host,
                            port=mqtt_server_port,
                            keepalive=mqtt_keepalive)
```

我们必须为命令处理器和命令处理器将控制的`Vehicle`实例指定一个名称，分别在`name`和`vehicle`参数中。构造函数，即`__init__`方法，将接收到的`name`和`vehicle`保存在同名的属性中。然后，构造函数设置了`commands_topic`和`processed_commands_topic`类属性的值。构造函数使用接收到的`name`来确定命令和成功处理的命令的主题名称，根据我们之前讨论的规范。MQTT 客户端将在`command_topic`类属性中保存的主题名称接收消息，并将消息发布到`processed_commands_topic`类属性中保存的主题名称。

然后，构造函数创建了一个`mqtt.Client`类的实例（`paho.mqtt.client.Client`），表示一个 MQTT 客户端，我们将使用它与 MQTT 服务器进行通信。代码将此实例分配给`client`属性（`self.client`）。与我们之前的示例一样，我们希望使用 MQTT 版本 3.11，因此我们将`mqtt.MQTTv311`指定为协议参数的值。

代码还将此实例的引用保存在`active_instance`类属性中，因为我们必须在构造函数指定为 MQTT 客户端触发的不同事件的回调中访问该实例。我们希望将与车辆命令处理器相关的所有方法都放在`VehicleCommandProcessor`类中。

然后，代码将静态方法分配给`self.client`实例的属性。以下表总结了这些分配：

| **属性** | **分配的静态方法** |
| --- | --- |
| `client.on_connect` | `VehicleCommandProcessor.on_connect` |
| `client.on_message` | `VehicleCommandProcessor.on_message` |
| `client.on_subscribe` | `VehicleCommandProcessor.on_subscribe` |

静态方法不接收`self`或`cls`作为第一个参数，因此我们可以将它们用作具有所需数量参数的回调。请注意，我们将在下一段编码和分析这些静态方法。

`self.client.tls_set`方法的调用配置了加密和认证选项。最后，构造函数调用`client.connect`方法，并指定`host`、`port`和`keepalive`参数的值。这样，代码要求 MQTT 客户端与指定的 MQTT 服务器建立连接。请记住，`connect`方法以异步执行方式运行，因此它是一个非阻塞调用。

如果要与未使用 TLS 的 MQTT 服务器建立连接，则需要删除对`self.client.tls_set`方法的调用。此外，您需要使用适当的端口，而不是在使用 TLS 时指定的`8883`端口。请记住，当您不使用 TLS 时，默认端口是`1883`。

以下行声明了`on_connect`静态方法，该方法是`VehicleCommandProcessor`类的一部分。您需要将这些行添加到现有的`vehicle_mqtt_client.py` Python 文件中。示例的代码文件包含在`mqtt_python_gaston_hillar_04_01`文件夹中的`vehicle_mqtt_client.py`文件中：

```py
    @staticmethod
    def on_connect(client, userdata, flags, rc):
        print("Result from connect: {}".format(
            mqtt.connack_string(rc)))
        # Check whether the result form connect is the CONNACK_ACCEPTED  
          connack code
        if rc == mqtt.CONNACK_ACCEPTED:
            # Subscribe to the commands topic filter
            client.subscribe(
                VehicleCommandProcessor.commands_topic, 
                qos=2)
```

成功与 MQTT 服务器建立连接后，将执行`self.client.on_connect`属性中指定的回调，即`on_connect`静态方法（使用`@staticmethod`装饰器标记）。此静态方法接收了与 MQTT 服务器建立连接的`mqtt.Client`实例作为 client 参数。

该代码检查`rc`参数的值，该参数提供了 MQTT 服务器返回的`CONNACK`代码。如果此值与`mqtt.CONNACK_ACCEPTED`匹配，则意味着 MQTT 服务器接受了连接请求，因此，代码调用`client.subscribe`方法，并将`VehicleCommandProcessor.commands_topic`作为参数订阅到`commands_topic`类属性中指定的主题，并为订阅指定了 QoS 级别为 2。

以下行声明了`on_subscribe`静态方法，该方法是`VehicleCommandProcessor`类的一部分。您需要将这些行添加到现有的`vehicle_mqtt_client.py` Python 文件中。示例的代码文件包含在`mqtt_python_gaston_hillar_04_01`文件夹中的`vehicle_mqtt_client.py`文件中：

```py
    @staticmethod
    def on_subscribe(client, userdata, mid, granted_qos):
        print("I've subscribed with QoS: {}".format(
            granted_qos[0]))
```

`on_subscribe`静态方法显示了 MQTT 服务器为我们指定的主题过滤器授予的 QoS 级别。在这种情况下，我们只订阅了一个单一主题过滤器，因此，代码从接收的`granted_qos`数组中获取第一个值。

以下行声明了`on_message`静态方法，该方法是`VehicleCommandProcessor`类的一部分。您需要将这些行添加到现有的`vehicle_mqtt_client.py` Python 文件中。示例的代码文件包含在`mqtt_python_gaston_hillar_04_01`文件夹中的`vehicle_mqtt_client.py`文件中：

```py
    @staticmethod
    def on_message(client, userdata, msg):
        if msg.topic == VehicleCommandProcessor.commands_topic:
            print("Received message payload: 
            {0}".format(str(msg.payload)))
            try:
                message_dictionary = json.loads(msg.payload)
                if COMMAND_KEY in message_dictionary:
                    command = message_dictionary[COMMAND_KEY]
                    vehicle = 
                    VehicleCommandProcessor.active_instance.vehicle
                    is_command_executed = False
                    if KEY_MPH in message_dictionary:
                        mph = message_dictionary[KEY_MPH]
                    else:
                        mph = 0
                    if KEY_DEGREES in message_dictionary:
                        degrees = message_dictionary[KEY_DEGREES]
                    else:
                        degrees = 0
                    command_methods_dictionary = {
                        CMD_TURN_ON_ENGINE: lambda: 
                        vehicle.turn_on_engine(),
                        CMD_TURN_OFF_ENGINE: lambda: 
                        vehicle.turn_off_engine(),
                        CMD_LOCK_DOORS: lambda: vehicle.lock_doors(),
                        CMD_UNLOCK_DOORS: lambda: 
                        vehicle.unlock_doors(),
                        CMD_PARK: lambda: vehicle.park(),
                        CMD_PARK_IN_SAFE_PLACE: lambda: 
                        vehicle.park_in_safe_place(),
                        CMD_TURN_ON_HEADLIGHTS: lambda: 
                        vehicle.turn_on_headlights(),
                        CMD_TURN_OFF_HEADLIGHTS: lambda: 
                        vehicle.turn_off_headlights(),
                        CMD_TURN_ON_PARKING_LIGHTS: lambda: 
                        vehicle.turn_on_parking_lights(),
                        CMD_TURN_OFF_PARKING_LIGHTS: lambda: 
                        vehicle.turn_off_parking_lights(),
                        CMD_ACCELERATE: lambda: vehicle.accelerate(),
                        CMD_BRAKE: lambda: vehicle.brake(),
                        CMD_ROTATE_RIGHT: lambda: 
                        vehicle.rotate_right(degrees),
                        CMD_ROTATE_LEFT: lambda: 
                        vehicle.rotate_left(degrees),
                        CMD_SET_MIN_SPEED: lambda: 
                        vehicle.set_min_speed(mph),
                        CMD_SET_MAX_SPEED: lambda: 
                        vehicle.set_max_speed(mph),
                    }
                    if command in command_methods_dictionary:
                        method = command_methods_dictionary[command]
                        # Call the method
                        method()
                        is_command_executed = True
                    if is_command_executed:

           VehicleCommandProcessor.active_instance.
            publish_executed_command_message(message_dictionary)
                    else:
                        print("I've received a message with an   
                          unsupported command.")
            except ValueError:
                # msg is not a dictionary
                # No JSON object could be decoded
                print("I've received an invalid message.")
```

每当在我们订阅的`commands_topic`类属性中保存的主题中收到新消息时，将执行`self.client.on_messsage`属性中指定的回调，即先前编码的`on_message`静态方法（使用`@staticmethod`装饰器标记）。此静态方法接收了与 MQTT 服务器建立连接的`mqtt.Client`实例作为 client 参数，并在`msg`参数中接收了一个`mqtt.MQTTMessage`实例。

`mqtt.MQTTMessage`类描述了传入的消息。

`msg.topic`属性指示接收消息的主题。因此，静态方法检查`msg.topic`属性是否与`commands_topic`类属性中的值匹配。在这种情况下，每当执行`on_message`方法时，`msg.topic`中的值将始终与主题类属性中的值匹配，因为我们只订阅了一个主题。但是，如果我们订阅了多个主题，则始终需要检查消息发送的主题以及我们接收消息的主题。因此，我们包含了代码以清楚地了解如何检查接收消息的`topic`。

代码打印了已接收消息的 payload，即`msg.payload`属性。然后，代码将`json.loads`函数的结果分配给`msg.payload`以将其反序列化为 Python 对象，并将结果分配给`message_dictionary`本地变量。如果`msg.payload`的内容不是 JSON，则会捕获`ValueError`异常，代码将打印一条消息，指示消息不包含有效命令，并且不会执行更多代码。如果`msg.payload`的内容是 JSON，则`message_dictionary`本地变量中将有一个字典。

然后，代码检查`COMMAND_KEY`字符串中保存的值是否包含在`message_dictionary`字典中。如果表达式求值为`True`，则意味着将 JSON 消息转换为字典后包含我们必须处理的命令。但是，在我们处理命令之前，我们必须检查是哪个命令，因此需要检索与与`COMMAND_KEY`字符串中保存的值相等的键关联的值。当值是我们分析为要求的命令之一时，代码能够运行特定的代码。

代码使用`active_instance`类属性，该属性引用了活动的`VehicleCommandProcessor`实例，以调用基于必须处理的命令的相关车辆的必要方法。我们必须将回调声明为静态方法，因此我们使用此类属性来访问活动实例。一旦命令成功处理，代码将`is_command_executed`标志设置为`True`。最后，代码检查此标志的值，如果等于`True`，则代码将为`active_instance`类属性中保存的`VehicleCommandProcessor`实例调用`publish_executed_command_message`。

当然，在实际示例中，我们应该添加更多的验证。前面的代码被简化，以便我们可以将注意力集中在 MQTT 上。

以下行声明了`publish_executed_command_message`方法，该方法是`VehicleCommandProcessor`类的一部分。您需要将这些行添加到现有的`vehicle_mqtt_client.py` Python 文件中。示例的代码文件包含在`mqtt_python_gaston_hillar_04_01`文件夹中的`vehicle_mqtt_client.py`文件中：

```py
    def publish_executed_command_message(self, message):
        response_message = json.dumps({
            SUCCESFULLY_PROCESSED_COMMAND_KEY:
                message[COMMAND_KEY]})
        result = self.client.publish(
            topic=self.__class__.processed_commands_topic,
            payload=response_message)
        return result
```

`publish_executed_command_message`方法接收了带有消息参数的命令的消息字典。该方法调用`json.dumps`函数将字典序列化为 JSON 格式的字符串，其中包含指示命令已成功处理的响应消息。最后，代码调用`client.publish`方法，将`processed_commands_topic`变量作为主题参数，并将 JSON 格式的字符串（`response_message`）作为`payload`参数。

在这种情况下，我们不评估从`publish`方法接收到的响应。此外，我们使用了`qos`参数的默认值，该参数指定所需的服务质量。因此，我们将以 QoS 级别等于 0 发布此消息。在第五章中，《在 Python 中测试和改进我们的车辆控制解决方案》，我们将处理更高级的场景，在这些场景中，我们将添加代码来检查方法的结果，并且我们将添加代码到`on_publish`回调中，该回调在成功发布消息时触发，就像我们在之前的示例中所做的那样。在这种情况下，我们仅对接收到的带有命令的消息使用 QoS 级别 2。

# 使用多次调用循环方法

以下行声明了`process_incoming_commands`方法，该方法是`VehicleCommandProcessor`类的一部分。 您必须将这些行添加到现有的`vehicle_mqtt_client.py` Python 文件中。 示例的代码文件包含在`mqtt_python_gaston_hillar_04_01`文件夹中的`vehicle_mqtt_client.py`文件中：

```py
    def process_incoming_commands(self):
        self.client.loop()
```

`process_incoming_commands`方法调用 MQTT 客户端的`loop`方法，并确保与 MQTT 服务器的通信已完成。 将调用`loop`方法视为同步您的邮箱。 将发送要发布的任何未决消息，任何传入消息将到达收件箱，并且我们先前分析过的事件将被触发。 这样，车辆命令处理器将接收消息并处理命令。

最后，以下行声明了代码的主要块。 您必须将这些行添加到现有的`vehicle_mqtt_client.py` Python 文件中。 示例的代码文件包含在`mqtt_python_gaston_hillar_04_01`文件夹中的`vehicle_mqtt_client.py`文件中：

```py
if __name__ == "__main__":
    vehicle = Vehicle("vehiclepi01")
    vehicle_command_processor = VehicleCommandProcessor("vehiclepi01", 
      vehicle)
    while True:
        # Process messages and the commands every 1 second
        vehicle_command_processor.process_incoming_commands()
        time.sleep(1)
```

`__main__`方法创建了`Vehicle`类的一个实例，命名为 vehicle，名称参数的值为`"vehiclepi01"`。 下一行创建了`VehicleCommandProcessor`类的一个实例，命名为`vehicle_command_processor`，名称参数的值为`"vehiclepi01"`，先前创建的`Vehicle`实例*X*的值为`vehicle`参数。 这样，`vehicle_command_processor`将把命令的执行委托给`vehicle`中的实例方法。

`VehicleCommandProcessor`类的构造函数将订阅 MQTT 服务器上的`vehicles/vehiclepi01/commands`主题，因此，我们必须发布消息到此主题，以便发送代码将处理的命令。 每当成功处理命令时，将发布新消息到`vehicles/vehiclepi01/executedcommands`主题。 因此，我们必须订阅此主题以检查车辆执行的命令。

while 循环调用`vehicle_command_processor.process_commands`方法并休眠一秒钟。 `process_commands`方法调用 MQTT 客户端的循环方法，并确保与 MQTT 服务器的通信已完成。

还有一个线程化的接口，我们可以通过调用 MQTT 客户端的`loop_start`方法来运行。 这样，我们可以避免多次调用循环方法。 但是，我们调用循环方法使得调试代码和理解底层工作变得更容易。 我们将在[第五章](https://cdp.packtpub.com/hands_on_mqtt_programming_with_python/wp-admin/post.php?post=107&action=edit#post_129)中使用线程化接口，*在 Python 中测试和改进我们的车辆控制解决方案*。

# 测试你的知识

让我们看看你是否能正确回答以下问题：

1.  以下哪个 Python 模块是 Paho Python 客户端？

1.  `paho-mqtt`

1.  `paho-client-pip`

1.  `paho-python-client`

1.  要与使用 TLS 的 MQTT 服务器建立连接，必须在调用`connect`之前为`paho.mqtt.client.Client`实例调用哪个方法？

1.  `connect_with_tls`

1.  `tls_set`

1.  `configure_tls`

1.  在`paho.mqtt.client.Client`实例与 MQTT 服务器建立连接后，将调用分配给以下哪个属性的回调函数？

1.  `on_connection`

1.  `on_connect`

1.  `connect_callback`

1.  在`paho.mqtt.client.Client`实例从其订阅的主题过滤器之一接收到消息后，将调用分配给以下哪个属性的回调函数？

1.  `on_message_arrived`

1.  `on_message`

1.  `message_arrived_callback`

1.  `paho.mqtt.client.Client`实例的以下哪个方法会以无限阻塞循环为我们调用循环方法？

1.  `infinite_loop`

1.  `loop_while_true`

1.  `loop_forever`

正确答案包含在附录中，*解决方案*。

# 摘要

在本章中，我们分析了使用 MQTT 消息控制车辆的要求。我们定义了要使用的主题以及消息有效载荷中将成为控制车辆一部分的命令。然后，我们使用 Paho Python 客户端编写了 Python 代码，将 MQTT 客户端连接到 MQTT 服务器。

我们了解了 Paho Python 客户端需要调用的方法及其参数。我们分析了回调函数的工作原理，并编写了代码来订阅主题过滤器，以及接收和处理消息。

我们编写了使用 Python 处理车辆命令的代码。该代码能够在不同的物联网平台上运行，包括树莓派 3 系列板，高通 DragonBoard，BeagleBone Black，MinnowBoard Turbot，LattePanda，UP squared，以及任何能够执行 Python 3.6.x 代码的计算机。我们还使用了 Python 中的 MQTT 客户端的网络循环。

现在我们已经了解了使用 Python 与 MQTT 一起工作的基础知识，我们将使用并改进我们的车辆控制解决方案，使用 MQTT 消息和 Python 代码，并利用其他 MQTT 功能，这些功能将在[第五章](https://cdp.packtpub.com/hands_on_mqtt_programming_with_python/wp-admin/post.php?post=107&action=edit#post_129)中讨论，*在 Python 中测试和改进我们的车辆控制解决方案*。


# 第五章：测试和改进我们的 Python 车辆控制解决方案

在本章中，我们将使用我们的车辆控制解决方案与 MQTT 消息和 Python 代码。我们将学习如何使用 Python 代码处理接收到的 MQTT 消息中的命令。我们将编写 Python 代码来组成和发送带有命令的 MQTT 消息。我们将使用阻塞和线程化的网络循环，并理解它们的区别。最后，我们将利用遗嘱功能。我们将深入研究以下内容：

+   使用 Python 处理命令

+   使用 Python 发送消息

+   使用 Python 处理网络循环

+   使用 Python 处理遗嘱和遗嘱消息

+   使用保留的遗嘱消息

+   理解阻塞和非阻塞代码

+   使用线程化客户端接口

# 使用 Python 处理命令

在第四章中，*使用 Python 和 MQTT 消息编写控制车辆的代码*，我们编写了一个能够使用 Python 代码处理作为 MQTT 消息接收的车辆命令的解决方案。现在，我们想让车辆处理多条命令，以检查所有部件如何协同工作。我们想执行以下命令：

```py
{"CMD": "LOCK_DOORS"} 
{"CMD": "TURN_OFF_PARKING_LIGHTS"} 
{"CMD": "SET_MAX_SPEED", "MPH": 10} 
{"CMD": "SET_MIN_SPEED", "MPH": 1} 
{"CMD": "TURN_ON_ENGINE"} 
{"CMD": "TURN_ON_HEADLIGHTS"} 
{"CMD": "ACCELERATE"} 
{"CMD": "ROTATE_RIGHT", "DEGREES": 45} 
{"CMD": "ACCELERATE"} 
{"CMD": "TURN_ON_PARKING_LIGHTS"} 
{"CMD": "BRAKE"} 
{"CMD": "TURN_OFF_ENGINE"} 
```

确保 Mosquitto 服务器，或者您可能想要用于此示例的任何其他 MQTT 服务器正在运行。

启动 MQTT.fx 并按照[第四章](https://cdp.packtpub.com/hands_on_mqtt_programming_with_python/wp-admin/post.php?post=129&action=edit#post_107)中解释的所有步骤，*使用 Python 和 MQTT 消息编写控制车辆的代码*，配置 TLS 和 TLS 身份验证的连接，如果您之前没有使用 MQTT.fx 与 MQTT 服务器建立安全连接。然后，点击连接按钮。

点击订阅并在订阅按钮左侧的下拉菜单中输入`vehicles/vehiclepi01/executedcommands`。然后，点击订阅按钮。MQTT.fx 将在左侧显示一个新面板，其中包含我们已订阅的主题过滤器，QoS 级别为 0。

然后，在任何您想要用作使用 Linux 或 macOS 的 MQTT 客户端的计算机或设备上执行以下命令以启动车辆控制器示例：

```py
    python3 subscribe_with_paho.py 
```

在 Windows 中，您必须执行以下命令：

```py
    python subscribe_with_paho.py
```

保持代码在您选择用作此示例的车辆控制器的本地计算机或 IoT 板上运行。

在 MQTT.fx 中，点击发布并在发布按钮左侧的下拉菜单中输入`vehicles/vehiclepi01/commands`。点击 QoS 2，因为我们想使用 QoS 级别 2。

在发布按钮下方的文本框中输入以下文本：`{"CMD": "LOCK_DOORS"}`

然后，点击发布按钮。MQTT.fx 将以 QoS 级别 2 将输入的文本发布到指定主题。

转到您可以看到由接收消息并控制车辆的 Python 代码生成的输出的窗口。如果您在 IoT 板上运行代码，您可能正在使用 SSH 终端或连接到 IoT 板的屏幕。如果您在本地计算机上运行代码，请转到终端或命令提示符，根据您使用的操作系统。您将看到以下输出：

```py
    Result from connect: Connection Accepted.
    Received message payload: b'{"CMD": "LOCK_DOORS"}'
    vehiclepi01: Locking doors
```

代码已收到带有命令的消息，`Vehicle`实例执行了`lock_doors`方法，并且输出显示了执行此代码的结果。

返回到 MQTT.fx，点击订阅，您将看到`vehicles/vehiclepi01/executedcommands`主题中已经有一条新消息到达，其有效载荷如下：`{"SUCCESSFULLY_PROCESSED_COMMAND": "LOCK_DOORS"}`。以下屏幕截图显示了在 MQTT.fx 中接收到的消息：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-mqtt-prog-py/img/ca44b769-efda-4736-b925-9e45b6ca3c91.png)

现在，对先前显示的列表中包含的每个命令重复以下过程。我们希望我们的车辆控制应用程序处理通过 MQTT 消息接收的每个命令，QoS 级别为 2。删除现有文本，然后在发布按钮下的文本框中输入 JSON 字符串的文本，然后单击发布按钮。MQTT.fx 将以 QoS 级别 2 将输入的文本发布到指定主题：

```py
{"CMD": "TURN_OFF_PARKING_LIGHTS"} 

{"CMD": "SET_MAX_SPEED", "MPH": 10} 

{"CMD": "SET_MIN_SPEED", "MPH": 1} 

{"CMD": "TURN_ON_ENGINE"} 

{"CMD": "TURN_ON_HEADLIGHTS"} 

{"CMD": "ACCELERATE"} 

{"CMD": "ROTATE_RIGHT", "DEGREES": 45} 

{"CMD": "ACCELERATE"} 

{"CMD": "TURN_ON_PARKING_LIGHTS"} 

{"CMD": "BRAKE"} 

{"CMD": "TURN_OFF_ENGINE"} 

```

转到您可以看到由接收消息并控制车辆的 Python 代码生成的输出的窗口。您将看到以下输出，指示所有命令已被接收和处理：

```py
    Result from connect: Connection Accepted.
    Received message payload: b'{"CMD": "LOCK_DOORS"}'
    vehiclepi01: Locking doors
    Received message payload: b'{"CMD": "TURN_OFF_PARKING_LIGHTS"}'
    vehiclepi01: Turning off parking lights
    Received message payload: b'{"CMD": "SET_MAX_SPEED", "MPH": 10}'
    vehiclepi01: Setting maximum speed to 10 MPH
    Received message payload: b'{"CMD": "SET_MIN_SPEED", "MPH": 1}'
    vehiclepi01: Setting minimum speed to 1 MPH
    Received message payload: b'{"CMD": "TURN_ON_ENGINE"}'
    vehiclepi01: Turning on the engine
    Received message payload: b'{"CMD": "TURN_ON_HEADLIGHTS"}'
    vehiclepi01: Turning on headlights
    Received message payload: b'{"CMD": "ACCELERATE"}'
    vehiclepi01: Accelerating
    Received message payload: b'{"CMD": "ROTATE_RIGHT", "DEGREES": 45}'
    vehiclepi01: Rotating right 45 degrees
    Received message payload: b'{"CMD": "ACCELERATE"}'
    vehiclepi01: Accelerating
    Received message payload: b'{"CMD": "TURN_ON_PARKING_LIGHTS"}'
    vehiclepi01: Turning on parking lights
    Received message payload: b'{"CMD": "BRAKE"}'
    vehiclepi01: Braking
    Received message payload: b'{"CMD": "TURN_OFF_ENGINE"}'
    vehiclepi01: Turning off the engine
```

返回到 MQTT.fx，单击订阅，您将看到已到达`vehicles/vehiclepi01/executedcommands`主题的共计 12 条消息。您可以通过单击窗口右侧代表每条消息的面板来轻松检查每条接收消息的有效负载的内容。以下屏幕截图显示了 MQTT.fx 中收到的最后一条消息：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-mqtt-prog-py/img/92978bdf-384b-4340-b6d1-c49b8db655f5.png)

现在，我们将使用 Mosquitto 命令行实用程序订阅`vehicles/vehiclepi01/executedcommands`主题，并发布许多带有命令的 JSON 字符串的 MQTT 消息到`vehicles/vehiclepi01/commands`主题。这次，我们将发布以下命令：

```py
{"CMD": "UNLOCK_DOORS"} 
{"CMD": "LOCK_DOORS"} 
{"CMD": "SET_MAX_SPEED", "MPH": 20} 
{"CMD": "SET_MIN_SPEED", "MPH": 5} 
{"CMD": "TURN_ON_ENGINE"} 
{"CMD": "ACCELERATE"} 
{"CMD": "ROTATE_LEFT", "DEGREES": 15} 
{"CMD": "ROTATE_LEFT", "DEGREES": 20} 
{"CMD": "BRAKE"} 
{"CMD": "TURN_OFF_ENGINE"} 
```

在 macOS 或 Linux 中打开另一个终端，或者在 Windows 中打开另一个命令提示符，转到 Mosquitto 安装的目录，并运行以下命令。将`192.168.1.1`替换为 MQTT 服务器的 IP 或主机名。记得将`ca.crt`、`board001.crt`和`board001.key`替换为在`board_certificates`目录中创建的这些文件的完整路径。保持窗口打开，实用程序将显示在`vehicles/vehiclepi01/executedcommands`主题中接收的所有消息。示例的代码文件包含在`mqtt_python_gaston_hillar_05_01`文件夹中的`script_01.txt`文件中：

```py
    mosquitto_sub -h 192.168.1.1 -V mqttv311 -p 8883 --cafile ca.crt --
    cert device001.crt --key device001.key -t 
    vehicles/vehiclepi01/executedcommands --tls-version tlsv1.2

```

在 macOS 或 Linux 中打开另一个终端，或者在 Windows 中打开另一个命令提示符，转到 Mosquitto 安装的目录，并运行以下命令以使用 QoS 级别 2 发布带有命令的消息到`vehicles/vehiclepi01/commands`主题。对于`mosquitto_sub`命令，进行与之前解释的相同替换。示例的代码文件包含在`mqtt_python_gaston_hillar_05_01`文件夹中的`script_02.txt`文件中：

```py
    mosquitto_pub -h 192.168.1.1 -V mqttv311 -p 8883 --cafile ca.crt --
cert board001.crt --key board001.key -t vehicles/vehiclepi01/commands -m '{"CMD": "UNLOCK_DOORS"}' -q 2 --tls-version tlsv1.2

    mosquitto_pub -h 192.168.1.1 -V mqttv311 -p 8883 --cafile ca.crt --cert board001.crt --key board001.key -t vehicles/vehiclepi01/commands -m '{"CMD": "LOCK_DOORS"}' -q 2 --tls-version tlsv1.2

    mosquitto_pub -h 192.168.1.1 -V mqttv311 -p 8883 --cafile ca.crt --cert board001.crt --key board001.key -t vehicles/vehiclepi01/commands -m '{"CMD": "SET_MAX_SPEED", "MPH": 20}' -q 2 --tls-version tlsv1.2

    mosquitto_pub -h 192.168.1.1 -V mqttv311 -p 8883 --cafile ca.crt --cert board001.crt --key board001.key -t vehicles/vehiclepi01/commands -m '{"CMD": "SET_MIN_SPEED", "MPH": 5}' -q 2 --tls-version tlsv1.2

    mosquitto_pub -h 192.168.1.1 -V mqttv311 -p 8883 --cafile ca.crt --cert board001.crt --key board001.key -t vehicles/vehiclepi01/commands -m '{"CMD": "TURN_ON_ENGINE"}' -q 2 --tls-version tlsv1.2

    mosquitto_pub -h 192.168.1.1 -V mqttv311 -p 8883 --cafile ca.crt --cert board001.crt --key board001.key -t vehicles/vehiclepi01/commands -m '{"CMD": "ACCELERATE"}' -q 2 --tls-version tlsv1.2

    mosquitto_pub -h 192.168.1.1 -V mqttv311 -p 8883 --cafile ca.crt --cert board001.crt --key board001.key -t vehicles/vehiclepi01/commands -m '{"CMD": "ROTATE_LEFT", "DEGREES": 15}' -q 2 --tls-version tlsv1.2

    mosquitto_pub -h 192.168.1.1 -V mqttv311 -p 8883 --cafile ca.crt --cert board001.crt --key board001.key -t vehicles/vehiclepi01/commands -m '{"CMD": "ROTATE_LEFT", "DEGREES": 20}' -q 2 --tls-version tlsv1.2

    mosquitto_pub -h 192.168.1.1 -V mqttv311 -p 8883 --cafile ca.crt --cert board001.crt --key board001.key -t vehicles/vehiclepi01/commands -m '{"CMD": "BRAKE"}' -q 2 --tls-version tlsv1.2

    mosquitto_pub -h 192.168.1.1 -V mqttv311 -p 8883 --cafile ca.crt --cert board001.crt --key board001.key -t vehicles/vehiclepi01/commands -m '{"CMD": "TURN_OFF_ENGINE"}' -q 2 --tls-version tlsv1.2

```

运行上述命令后，`VehicleCommandProcessor`类将接收这些命令并处理它们。几秒钟后，您将在执行`mosquitto_sub`实用程序的窗口中看到以下输出：

```py
    {"SUCCESSFULLY_PROCESSED_COMMAND": "UNLOCK_DOORS"}
    {"SUCCESSFULLY_PROCESSED_COMMAND": "LOCK_DOORS"}
    {"SUCCESSFULLY_PROCESSED_COMMAND": "SET_MAX_SPEED"}
    {"SUCCESSFULLY_PROCESSED_COMMAND": "SET_MIN_SPEED"}
    {"SUCCESSFULLY_PROCESSED_COMMAND": "TURN_ON_ENGINE"}
    {"SUCCESSFULLY_PROCESSED_COMMAND": "ACCELERATE"}
    {"SUCCESSFULLY_PROCESSED_COMMAND": "ROTATE_LEFT"}
    {"SUCCESSFULLY_PROCESSED_COMMAND": "ROTATE_LEFT"}
    {"SUCCESSFULLY_PROCESSED_COMMAND": "BRAKE"}
    {"SUCCESSFULLY_PROCESSED_COMMAND": "TURN_OFF_ENGINE"}

```

请注意，MQTT.fx 实用程序也将接收消息，因为它保持订阅`vehicles/vehiclepi01/executedcommands`主题。

转到您可以看到由接收消息并控制车辆的 Python 代码生成的输出的窗口。您将看到以下输出，指示所有命令已被接收和处理：

```py
    Result from connect: Connection Accepted.
    Received message payload: b'{"CMD": "UNLOCK_DOORS"}'
    vehiclepi01: Unlocking doors
    Received message payload: b'{"CMD": "LOCK_DOORS"}'
    vehiclepi01: Locking doors
    Received message payload: b'{"CMD": "SET_MAX_SPEED", "MPH": 20}'
    vehiclepi01: Setting maximum speed to 20 MPH
    Received message payload: b'{"CMD": "SET_MIN_SPEED", "MPH": 5}'
    vehiclepi01: Setting minimum speed to 5 MPH
    Received message payload: b'{"CMD": "TURN_ON_ENGINE"}'
    vehiclepi01: Turning on the engine
    Received message payload: b'{"CMD": "ACCELERATE"}'
    vehiclepi01: Accelerating
    Received message payload: b'{"CMD": "ROTATE_LEFT", "DEGREES": 15}'
    vehiclepi01: Rotating left 15 degrees
    Received message payload: b'{"CMD": "ROTATE_LEFT", "DEGREES": 20}'
    vehiclepi01: Rotating left 20 degrees
    Received message payload: b'{"CMD": "BRAKE"}'
    vehiclepi01: Braking
    Received message payload: b'{"CMD": "TURN_OFF_ENGINE"}'
    vehiclepi01: Turning off the engine

```

# 使用 Python 发送消息

到目前为止，我们一直在使用 GUI 和命令行工具发布 MQTT 消息来控制车辆。现在，我们将编写 Python 代码来发布控制每辆车的命令，并检查执行这些命令的结果。当然，GUI 实用程序，如 MQTT.fx 和 Mosquitto 命令行实用程序，非常有用。但是，一旦我们知道事情正在按我们的期望进行，我们可以编写必要的代码以在与我们用于在 IoT 板上运行代码的相同编程语言中执行测试。

现在，我们将编写一个 Python 客户端，它将发布消息到`vehicles/vehiclepi01/commands`主题，并订阅到`vehicles/vehiclepi01/executedcommands`主题。我们将编写发布者和订阅者。这样，我们将能够设计能够通过 Python 代码与 MQTT 消息通信的应用程序，Python 将作为客户端应用程序的编程语言。具体来说，这些应用程序将能够通过 MQTT 服务器与所有发布者和订阅者设备中的 Python 代码进行通信。

我们可以在任何其他能够执行 Python 3.x 的计算机或物联网板上运行 Python 客户端。

在第四章中，*使用 Python 和 MQTT 消息编写控制车辆的代码*，我们在主虚拟环境文件夹中创建了一个名为`config.py`的 Python 文件。在这个文件中，我们定义了许多配置值，用于与 Mosquitto MQTT 服务器建立连接。这样，所有配置值都包含在一个特定的 Python 脚本中。如果您需要更改此文件以配置将组成并发送 MQTT 消息以控制车辆的应用程序，请确保您查看了第四章中包含的说明。

现在，我们将在主虚拟环境文件夹中创建一个名为`vehicle_mqtt_remote_control.py`的新的 Python 文件。我们将创建许多函数，并将它们分配为 MQTT 客户端中事件的回调函数。此外，我们将声明变量、一个辅助类和一个辅助函数，以便轻松地发布带有命令和所需值的消息。以下行显示了定义变量、辅助类和函数的代码。示例的代码文件包含在`mqtt_python_gaston_hillar_05_01`文件夹中的`vehicle_mqtt_remote_control.py`文件中：

```py
from config import * 
from vehicle_commands import * 
import paho.mqtt.client as mqtt 
import time 
import json 

vehicle_name = "vehiclepi01" 
commands_topic = "vehicles/{}/commands".format(vehicle_name) 
processed_commands_topic = "vehicles/{}/executedcommands".format(vehicle_name) 

class LoopControl: 
    is_last_command_processed = False 

def on_connect(client, userdata, flags, rc): 
    print("Result from connect: {}".format( 
        mqtt.connack_string(rc))) 
    # Check whether the result form connect is the CONNACK_ACCEPTED 
      connack code 
    if rc == mqtt.CONNACK_ACCEPTED: 
        # Subscribe to the commands topic filter 
        client.subscribe( 
            processed_commands_topic,  
            qos=2) 

def on_message(client, userdata, msg): 
    if msg.topic == processed_commands_topic: 
        print(str(msg.payload)) 
        if str(msg.payload).count(CMD_TURN_OFF_ENGINE) > 0: 
            LoopControl.is_last_command_processed = True 

def on_subscribe(client, userdata, mid, granted_qos): 
    print("Subscribed with QoS: {}".format(granted_qos[0])) 

def build_command_message(command_name, key="", value=""): 
    if key: 
        # The command requires a key 
        command_message = json.dumps({ 
            COMMAND_KEY: command_name, 
            key: value}) 
    else: 
        # The command doesn't require a key 
        command_message = json.dumps({ 
            COMMAND_KEY: command_name}) 
    return command_message 

def publish_command(client, command_name, key="", value=""):
    command_message = build_command_message(
        command_name, key, value)
    result = client.publish(topic=commands_topic, payload=command_message, qos=2)
client.loop()
time.sleep(1)
return result
```

第一行导入了我们在著名的`config.py`文件中声明的变量。代码声明了`vehicle_name`变量，保存了一个字符串`"vehiclepi01"`，我们可以轻松地用要控制的车辆的名称替换它。我们的主要目标是构建并发布命令消息到`commands_topic`变量中指定的主题。我们将订阅到`processed_commands_topic`变量中指定的主题。

`LoopControl`类声明了一个名为`is_last_command_processed`的类属性，初始化为`False`。我们将使用这个类属性作为控制网络循环的标志。

`on_connect`函数是一旦与 MQTT 服务器建立了成功的连接就会执行的回调函数。代码检查`rc`参数的值，该参数提供 MQTT 服务器返回的`CONNACK`代码。如果此值与`mqtt.CONNACK_ACCEPTED`匹配，则表示 MQTT 服务器接受了连接请求，因此，代码调用`client.subscribe`方法，为`client`参数中接收到的 MQTT 客户端订阅了保存在`processed_commands_topic`中的主题名称，QoS 级别为 0。

`on_message`函数将在每次新消息到达我们订阅的主题时执行。该函数只是打印接收到的消息的有效负载的原始字符串。如果有效负载包含在`CMD_TURN_OFF_ENGINE`常量中保存的字符串，则我们假定上一个命令已成功执行，并且代码将`LoopControl.is_last_command_processed`设置为`True`。这样，我们将根据车辆通过 MQTT 消息指示的已处理命令来控制网络循环。

`on_subscribe`函数将在订阅成功完成时调用。

下表总结了将根据从 MQTT 服务器接收到的响应调用的函数：

| **来自 MQTT 服务器的响应** | **将被调用的函数** |
| --- | --- |
| `CONNACK` | `on_connnect` |
| `SUBACK` | `on_subscribe` |
| `PUBLISH` | `on_message` |

`build_command_message`函数接收命令名称、键和值，提供构建包含命令的 JSON 键值对字符串所需的信息。请注意，最后两个参数是可选的，它们的默认值是空字符串。该函数创建一个字典，并将字典序列化为 JSON 格式的字符串保存在`command_message`局部变量中。`COMMAND_KEY`常量是字典的第一个键，`command_name`作为参数接收，是组成第一个键值对的值。最后，函数返回`command_message`字符串。

`publish_command`函数接收 MQTT 客户端、命令名称、键和值，提供执行命令所需的信息。与`build_command_message`函数一样，键和值参数是可选的，它们的默认值是空字符串。该函数使用接收到的`command_name`、`key`和`value`参数调用先前解释的`build_command_message`函数，并将结果保存在`command_message`局部变量中。然后，代码调用`client.publish`方法，将`command_message` JSON 格式的字符串发布到`commands_topic`变量中保存的主题名称，QoS 级别为 2。

接下来的一行调用`client.loop`方法，以确保与 MQTT 服务器的通信进行，并休眠一秒。这样，消息将被发布，应用程序将等待一秒。

# 使用 Python 处理网络循环

现在，我们将在`__main__`方法中使用之前编写的`functions`，该方法将发布包含在 MQTT 消息中的许多命令，以便控制车辆的代码将处理这些命令。您必须将下面的代码添加到现有的`vehicle_mqtt_remote_control.py` Python 文件中。以下代码显示了`__main__`方法的代码块。示例的代码文件包含在`mqtt_python_gaston_hillar_05_01`文件夹中的`vehicle_mqtt_remote_control.py`文件中：

```py
if __name__ == "__main__": 
    client = mqtt.Client(protocol=mqtt.MQTTv311) 
    client.on_connect = on_connect 
    client.on_subscribe = on_subscribe 
    client.on_message = on_message 
    client.tls_set(ca_certs = ca_certificate, 
        certfile=client_certificate, 
        keyfile=client_key) 
    client.connect(host=mqtt_server_host, 
        port=mqtt_server_port, 
        keepalive=mqtt_keepalive) 
    publish_command(client, CMD_SET_MAX_SPEED, KEY_MPH, 30) 
    publish_command(client, CMD_SET_MIN_SPEED, KEY_MPH, 8) 
    publish_command(client, CMD_LOCK_DOORS) 
    publish_command(client, CMD_TURN_ON_ENGINE) 
    publish_command(client, CMD_ROTATE_RIGHT, KEY_DEGREES, 15) 
    publish_command(client, CMD_ACCELERATE) 
    publish_command(client, CMD_ROTATE_RIGHT, KEY_DEGREES, 25) 
    publish_command(client, CMD_ACCELERATE) 
    publish_command(client, CMD_ROTATE_LEFT, KEY_DEGREES, 15) 
    publish_command(client, CMD_ACCELERATE) 
    publish_command(client, CMD_TURN_OFF_ENGINE) 
    while LoopControl.is_last_command_processed == False: 
        # Process messages and the commands every 500 milliseconds 
        client.loop() 
        time.sleep(0.5) 
    client.disconnect() 
    client.loop() 
```

代码的前几行与我们编写的第一个 Python 示例类似。调用`client.connect`方法后，代码多次调用`publish_command`命令来构建并发布带有命令的消息。

`while`循环调用`client.loop`方法，以确保与 MQTT 服务器的通信进行，并休眠 500 毫秒，即 0.5 秒。在最后一个命令被处理后，`LoopControl.is_last_command_processed`类变量被设置为`True`，`while`循环结束执行。当这发生时，代码调用`client.disconnect`方法，最后调用`client.loop`方法，以确保断开连接请求被处理。

如果在调用`client.disconnect`后不调用`client.loop`方法，程序可能会在不向 MQTT 服务器发送断开连接请求的情况下结束执行。在接下来的章节中，我们将使用遗嘱功能，并注意客户端断开连接的方式对该功能的使用产生重要影响。

在这种情况下，我们不希望循环永远运行，因为我们有一个特定的目标，即组合并发送一组命令。一旦我们确信最后一个命令已被处理，我们就会关闭与 MQTT 服务器的连接。

确保控制`vehiclepi01`的代码正在运行，也就是说，我们在第四章中编写的`vehicle_mqtt_client.py` Python 脚本正在运行。

然后，在任何您想要用作 MQTT 客户端并且使用 Linux 或 macOS 的计算机或设备上执行以下命令来启动车辆远程控制示例：

```py
    python3 vehicle_mqtt_remote_control.py
```

在 Windows 中，您必须执行以下命令：

```py
    python vehicle_mqtt_remote_control.py
```

保持代码在您选择用作此示例车辆远程控制的本地计算机或 IoT 板上运行。

转到执行先前的 Python 脚本`vehicle_mqtt_remote_control.py`的设备和窗口。您将看到以下输出。Python 代码将显示在`vehicles/vehiclepi01/executedcommands`主题中接收到的所有消息。在车辆成功处理`TURN_OFF_ENGINE`命令后，程序将结束执行：

```py
    Result from connect: Connection Accepted.
    Subscribed with QoS: 2
    b'{"SUCCESSFULLY_PROCESSED_COMMAND": "SET_MAX_SPEED"}'
    b'{"SUCCESSFULLY_PROCESSED_COMMAND": "SET_MIN_SPEED"}'
    b'{"SUCCESSFULLY_PROCESSED_COMMAND": "LOCK_DOORS"}'
    b'{"SUCCESSFULLY_PROCESSED_COMMAND": "TURN_ON_ENGINE"}'
    b'{"SUCCESSFULLY_PROCESSED_COMMAND": "ROTATE_RIGHT"}'
    b'{"SUCCESSFULLY_PROCESSED_COMMAND": "ACCELERATE"}'
    b'{"SUCCESSFULLY_PROCESSED_COMMAND": "ROTATE_RIGHT"}'
    b'{"SUCCESSFULLY_PROCESSED_COMMAND": "ACCELERATE"}'
    b'{"SUCCESSFULLY_PROCESSED_COMMAND": "ROTATE_LEFT"}'
    b'{"SUCCESSFULLY_PROCESSED_COMMAND": "ACCELERATE"}'
    b'{"SUCCESSFULLY_PROCESSED_COMMAND": "TURN_OFF_ENGINE"}'

```

转到执行控制车辆并处理接收到的命令的 Python 脚本`vehicle_mqtt_client.py`的设备和窗口。您将看到以下输出：

```py
    Received message payload: b'{"CMD": "SET_MAX_SPEED", "MPH": 30}'
    vehiclepi01: Setting maximum speed to 30 MPH
    Received message payload: b'{"CMD": "SET_MIN_SPEED", "MPH": 8}'
    vehiclepi01: Setting minimum speed to 8 MPH
    Received message payload: b'{"CMD": "LOCK_DOORS"}'
    vehiclepi01: Locking doors
    Received message payload: b'{"CMD": "TURN_ON_ENGINE"}'
    vehiclepi01: Turning on the engine
    Received message payload: b'{"CMD": "ROTATE_RIGHT", "DEGREES": 15}'
    vehiclepi01: Rotating right 15 degrees
    Received message payload: b'{"CMD": "ACCELERATE"}'
    vehiclepi01: Accelerating
    Received message payload: b'{"CMD": "ROTATE_RIGHT", "DEGREES": 25}'
    vehiclepi01: Rotating right 25 degrees
    Received message payload: b'{"CMD": "ACCELERATE"}'
    vehiclepi01: Accelerating
    Received message payload: b'{"CMD": "ROTATE_LEFT", "DEGREES": 15}'
    vehiclepi01: Rotating left 15 degrees
    Received message payload: b'{"CMD": "ACCELERATE"}'
    vehiclepi01: Accelerating
    Received message payload: b'{"CMD": "TURN_OFF_ENGINE"}'
    vehiclepi01: Turning off the engine
```

以下屏幕截图显示了在 macOS 计算机上运行的两个终端窗口。左侧的终端显示了由发布命令并作为车辆远程控制器的 Python 客户端显示的消息，即`vehicle_mqtt_remote_control.py`脚本。右侧的终端显示了控制车辆并处理接收到的命令的 Python 客户端代码的结果，即`vehicle_mqtt_client.py`脚本：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-mqtt-prog-py/img/7335cf47-4c8d-487d-bca1-88ece1b7c706.png)

# 使用 Python 处理遗嘱

现在，我们将检查如果代表我们的车辆远程控制应用程序的 MQTT 客户端意外断开与我们迄今为止编写的代码所连接的 MQTT 服务器会发生什么。请注意所有步骤，因为我们将手动中断车辆远程控制程序的执行，以了解我们将利用遗嘱功能解决的特定问题。

在任何您想要用作 MQTT 客户端并且使用 Linux 或 macOS 的计算机或设备上执行以下命令来启动车辆远程控制示例：

```py
    python3 vehicle_mqtt_remote_control.py
```

在 Windows 中，您必须执行以下命令：

```py
    python vehicle_mqtt_remote_control.py
```

转到执行先前的 Python 脚本`vehicle_mqtt_remote_control.py`的设备和窗口。在看到以下输出后，按下*Ctrl* + *C*中断脚本的执行，直到所有命令都被处理：

```py
    Result from connect: Connection Accepted.
    Subscribed with QoS: 2
    b'{"SUCCESSFULLY_PROCESSED_COMMAND": "SET_MAX_SPEED"}'
    b'{"SUCCESSFULLY_PROCESSED_COMMAND": "SET_MIN_SPEED"}'
    b'{"SUCCESSFULLY_PROCESSED_COMMAND": "LOCK_DOORS"}'
    b'{"SUCCESSFULLY_PROCESSED_COMMAND": "TURN_ON_ENGINE"}'
    b'{"SUCCESSFULLY_PROCESSED_COMMAND": "ROTATE_RIGHT"}'

```

按下*Ctrl* + *C*后，您将看到类似以下行的回溯输出：

```py
    ^CTraceback (most recent call last):
      File "vehicle_mqtt_remote_control.py", line 86, in <module>
        publish_command(client, CMD_ACCELERATE)
      File "vehicle_mqtt_remote_control.py", line 57, in 
        publish_command
        time.sleep(1)
      KeyboardInterrupt

```

我们中断了作为车辆远程控制器的 MQTT 客户端与 MQTT 服务器之间的连接。我们没有等待所有命令被发布，而是意外地将 MQTT 客户端与 MQTT 服务器断开连接。车辆不知道远程控制应用程序已中断。

在这种情况下，我们使用了一个键盘快捷键来中断 Python 程序的执行。然而，网络故障可能是 MQTT 客户端意外与 MQTT 服务器断开连接的另一个原因。

当然，我们不希望网络故障使我们的车辆失去控制，因此，我们希望确保如果远程控制应用程序与 MQTT 服务器失去连接，车辆将停放在一个安全的地方。在这种情况下，我们希望确保车辆接收到一条指示车辆必须停放在为车辆配置的安全地点的命令的消息。

在第一章*，安装 MQTT 3.1.1 Mosquitto 服务器*中，我们分析了组成 MQTT 客户端发送到 MQTT 服务器以建立连接的`CONNECT`控制数据包的有效载荷的字段和标志。现在，我们将使用`paho-mqtt`中提供的适当方法来配置`Will`、`WillQoS`、`WillRetain`、`WillTopic`和`WillMessage`标志和字段的值，以使我们的 MQTT 客户端利用 MQTT 的遗嘱功能。

打开现有的`vehicle_mqtt_remote_control.py` Python 文件，并用以下代码替换定义`__main__`方法的行，以配置我们希望 MQTT 服务器在发生意外断开连接时发送给车辆的遗嘱消息。添加的行已经突出显示。示例的代码文件包含在`mqtt_python_gaston_hillar_05_02`文件夹中的`vehicle_mqtt_remote_control.py`文件中。

```py
if __name__ == "__main__": 
    client = mqtt.Client(protocol=mqtt.MQTTv311) 
    client.on_connect = on_connect 
    client.on_subscribe = on_subscribe 
    client.on_message = on_message 
    client.tls_set(ca_certs = ca_certificate, 
        certfile=client_certificate, 
        keyfile=client_key) 
    # Set a will to be sent to the MQTT server in case the client 
    # disconnects unexpectedly 
    last_will_payload = build_command_message(CMD_PARK_IN_SAFE_PLACE) 
    client.will_set(topic=commands_topic,  
        payload=last_will_payload,  
        qos=2) 
    client.connect(host=mqtt_server_host, 
        port=mqtt_server_port, 
        keepalive=mqtt_keepalive) 
    publish_command(client, CMD_SET_MAX_SPEED, KEY_MPH, 30) 
    publish_command(client, CMD_SET_MIN_SPEED, KEY_MPH, 8) 
    publish_command(client, CMD_LOCK_DOORS) 
    publish_command(client, CMD_TURN_ON_ENGINE) 
    publish_command(client, CMD_ROTATE_RIGHT, KEY_DEGREES, 15) 
    publish_command(client, CMD_ACCELERATE) 
    publish_command(client, CMD_ROTATE_RIGHT, KEY_DEGREES, 25) 
    publish_command(client, CMD_ACCELERATE) 
    publish_command(client, CMD_ROTATE_LEFT, KEY_DEGREES, 15) 
    publish_command(client, CMD_ACCELERATE) 
    publish_command(client, CMD_TURN_OFF_ENGINE) 
    while LoopControl.is_last_command_processed == False: 
        # Process messages and the commands every 500 milliseconds 
        client.loop() 
        time.sleep(0.5) 
    client.disconnect() 
    client.loop() 
```

在代码调用`client.connect`方法之前，我们添加了两行代码，即在向 MQTT 服务器发送连接请求之前。第一行调用`build_command_message`函数，并将`CMD_PARK_IN_SAFE_PLACE`作为参数，以构建使车辆停放在安全地方的命令的 JSON 字符串，并将其存储在`last_will_payload`变量中。

下一行代码调用`client.will_set`方法，允许我们配置`Will`、`WillQoS`、`WillRetain`、`WillTopic`和`WillMessage`标志和字段的期望值，并将其用于 CONNECT 控制数据包。该代码使用`commands_topic`、`last_will_payload`和`2`作为主题、有效载荷和 qos 参数的值来调用此方法。由于我们没有为`retain`参数指定值，该方法将使用其默认值`False`，这指定了遗嘱消息不会是保留消息。这样，当下一行代码调用`client.connect`方法请求 MQTT 客户端与 MQTT 服务器建立连接时，`CONNECT`控制数据包将包括用于配置遗嘱消息的字段和标志的适当值，QoS 级别为 2，`commands_topic`作为消息将被发布的主题，`last_will_payload`作为消息的有效载荷。

现在，在任何您想要用作 MQTT 客户端并使用 Linux 或 macOS 的计算机或设备上执行以下行以启动车辆远程控制示例：

```py
    python3 vehicle_mqtt_remote_control.py
```

在 Windows 中，您必须执行以下行：

```py
    python vehicle_mqtt_remote_control.py
```

转到您执行之前的 Python 脚本`vehicle_mqtt_remote_control.py`的设备和窗口。在看到以下输出后，按*Ctrl* + *C*中断脚本的执行，然后再处理所有命令：

```py
    Result from connect: Connection Accepted.
    Subscribed with QoS: 2
    b'{"SUCCESSFULLY_PROCESSED_COMMAND": "SET_MAX_SPEED"}'
    b'{"SUCCESSFULLY_PROCESSED_COMMAND": "SET_MIN_SPEED"}'
    b'{"SUCCESSFULLY_PROCESSED_COMMAND": "LOCK_DOORS"}'
    b'{"SUCCESSFULLY_PROCESSED_COMMAND": "TURN_ON_ENGINE"}'

```

按下*Ctrl* + *C*后，您将看到类似以下行的输出：

```py
^CTraceback (most recent call last):
 File "vehicle_mqtt_remote_control.py", line 87, in <module>
 publish_command(client, CMD_ROTATE_LEFT, KEY_DEGREES, 15)
 File "vehicle_mqtt_remote_control.py", line 57, in publish_command
 time.sleep(1)
 KeyboardInterrupt
```

我们中断了作为车辆远程控制器的 MQTT 客户端与 MQTT 服务器之间的连接。我们没有等待所有命令被发布，而是意外地从 MQTT 服务器断开了 MQTT 客户端的连接。因此，MQTT 服务器会发布配置的遗嘱消息，即当远程控制车辆的 MQTT 客户端与 MQTT 服务器建立连接时配置的遗嘱消息。这样，当远程控制应用程序与 MQTT 服务器之间的连接丢失时，车辆会收到一个命令，要求它停放在一个安全的地方。

转到您执行控制车辆并处理接收到的命令的 Python 脚本`vehicle_mqtt_client.py`的设备和窗口。您将看到类似以下行的输出。请注意，最后接收到的消息指示车辆停放在一个安全的地方。这个最后接收到的消息是我们在名为`vehicle_mqtt_remote_control.py`的 Python 脚本中添加的代码行配置的遗嘱消息。

```py
Received message payload: b'{"CMD": "SET_MAX_SPEED", "MPH": 30}'
vehiclepi01: Setting maximum speed to 30 MPH
Received message payload: b'{"CMD": "SET_MIN_SPEED", "MPH": 8}'
vehiclepi01: Setting minimum speed to 8 MPH
Received message payload: b'{"CMD": "LOCK_DOORS"}'
vehiclepi01: Locking doors
Received message payload: b'{"CMD": "TURN_ON_ENGINE"}'
vehiclepi01: Turning on the engine
Received message payload: b'{"CMD": "ROTATE_RIGHT", "DEGREES": 15}'
vehiclepi01: Rotating right 15 degrees
Received message payload: b'{"CMD": "ACCELERATE"}'
vehiclepi01: Accelerating
Received message payload: b'{"CMD": "ROTATE_RIGHT", "DEGREES": 25}'
vehiclepi01: Rotating right 25 degrees
Received message payload: b'{"CMD": "ACCELERATE"}'
vehiclepi01: Accelerating
Received message payload: b'{"CMD": "PARK_IN_SAFE_PLACE"}'
vehiclepi01: Parking in safe place
```

以下屏幕截图显示了在 macOS 计算机上运行的两个终端窗口。左侧的终端显示了由发布命令并作为车辆远程控制器工作的 Python 客户端显示的消息，即`vehicle_mqtt_remote_control.py`脚本。右侧的终端显示了控制车辆并处理接收到的命令的 Python 客户端代码的结果，即`vehicle_mqtt_client.py`脚本。连接中断导致 MQTT 服务器发布了配置的最后遗嘱消息：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-mqtt-prog-py/img/05a40b9f-167a-48f5-829b-fcbca43e357a.png)您可以利用最后遗嘱功能来指示感兴趣的客户端，特定的板、设备或传感器已离线。

现在，在任何您想要用作 MQTT 客户端并使用 Linux 或 macOS 的计算机或设备上执行以下命令以启动车辆远程控制示例：

```py
    python3 vehicle_mqtt_remote_control.py

```

在 Windows 中，您必须执行以下命令：

```py
    python vehicle_mqtt_remote_control.py

```

转到执行先前 Python 脚本的设备和窗口，名称为`vehicle_mqtt_remote_control.py`。

这次，在您选择用作此示例车辆远程控制的本地计算机或 IoT 板上保持代码运行。

转到执行控制车辆并处理接收到的命令的 Python 脚本的设备和窗口，即`vehicle_mqtt_client.py`。您将在输出中看到以下最后几行：

```py
    Received message payload: b'{"CMD": "ROTATE_LEFT", "DEGREES": 15}'
    vehiclepi01: Rotating left 15 degrees
    Received message payload: b'{"CMD": "ACCELERATE"}'
    vehiclepi01: Accelerating
    Received message payload: b'{"CMD": "TURN_OFF_ENGINE"}'
    vehiclepi01: Turning off the engine
```

在这种情况下，代码调用了`client.disconnect`方法，然后调用了`client.loop`方法。 MQTT 客户端以正常方式从 MQTT 服务器断开连接，因此，带有将车辆停放在安全位置的命令的最后遗嘱消息没有被发布。

非常重要的是要理解，当 MQTT 客户端通过调用`client.disconnect`方法断开与 MQTT 的连接并确保网络事件被处理时，配置的最后遗嘱消息不会被发布。如果我们希望在使用`client.disconnect`方法执行正常断开连接之前发布一条消息，我们必须在调用此方法之前编写必要的代码来执行此操作。此外，我们必须确保网络事件被处理。

# 使用保留的最后遗嘱消息

现在，我们将检查当控制车辆的 MQTT 客户端意外地与 MQTT 服务器断开连接时以及我们的车辆远程控制应用程序也意外断开连接时会发生什么。请注意所有步骤，因为我们将手动中断两个程序的执行，以了解我们将利用最后遗嘱功能结合保留标志值来解决的特定问题。

您必须迅速执行接下来的步骤。因此，请确保您阅读所有步骤，然后执行它们。

在任何您想要用作 MQTT 客户端并使用 Linux 或 macOS 的计算机或设备上执行以下命令以启动车辆远程控制示例：

```py
    python3 vehicle_mqtt_remote_control.py

```

在 Windows 中，您必须执行以下命令：

```py
    python vehicle_mqtt_remote_control.py

```

转到执行控制车辆并处理接收到的命令的 Python 脚本的设备和窗口，即`vehicle_mqtt_client.py`。在看到以下输出后，按*Ctrl* + *C*中断脚本的执行，然后再接收到所有命令之前：

```py
    Received message payload: b'{"CMD": "PARK_IN_SAFE_PLACE"}'
    vehiclepi01: Parking in safe place
    Received message payload: b'{"CMD": "SET_MAX_SPEED", "MPH": 30}'
    vehiclepi01: Setting maximum speed to 30 MPH
```

按下*Ctrl* + *C*后，您将看到类似以下行的输出：

```py
    ^CTraceback (most recent call last):
      File "vehicle_mqtt_client.py", line 198, in <module>
        time.sleep(1)
        KeyboardInterrupt
```

我们中断了控制车辆并处理接收到的命令的 MQTT 客户端与 MQTT 服务器之间的连接。我们没有等待所有命令被接收，而是意外地将 MQTT 客户端与 MQTT 服务器断开连接。车辆遥控应用程序不知道遥控应用程序已中断，它会等待直到它发送的最后一个命令被处理。

转到您执行先前的 Python 脚本`vehicle_mqtt_remote_control.py`的设备和窗口。按下*Ctrl* + *C*中断脚本的执行。按下*Ctrl* + *C*后，您将看到类似以下行的回溯输出：

```py
    ^CTraceback (most recent call last):
      File "vehicle_mqtt_remote_control.py", line 93, in <module>
        client.loop()
      File "/Users/gaston/HillarMQTT/01/lib/python3.6/site-
        packages/paho/mqtt/client.py", line 988, in loop
        socklist = select.select(rlist, wlist, [], timeout)
        KeyboardInterrupt

```

返回到您执行控制车辆并处理接收到的命令的 Python 脚本的设备和窗口，即`vehicle_mqtt_client.py`。在任何您想要用作 MQTT 客户端并且使用 Linux 或 macOS 的计算机或设备上执行以下行以重新启动此脚本：

```py
    python3 vehicle_mqtt_client.py 
```

在 Windows 中，您必须执行以下行：

```py
    python vehicle_mqtt_client.py 
```

等待几秒钟，您将只看到以下指示已接受与 MQTT 服务器的连接的输出。没有接收到任何命令：

```py
Result from connect: Connection Accepted.
```

以下屏幕截图显示了在 macOS 计算机上运行的两个终端窗口。左侧的终端显示了由发布命令并作为车辆遥控的 Python 客户端显示的消息，即`vehicle_mqtt_remote_control.py`脚本。右侧的终端显示了控制车辆并处理接收到的命令的 Python 客户端代码的运行结果，即先前解释的中断后的`vehicle_mqtt_client.py`脚本：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-mqtt-prog-py/img/f4771d68-6c0b-4a1d-a201-b17583b5f3a5.png)

当我们启动`vehicle_mqtt_client.py`脚本时，代码生成了一个新的 MQTT 客户端，并与 MQTT 服务器建立了连接，并订阅了`vehicles/vehiclepi01/commands`。当我们中断`vehicle_mqtt_remote_control.py`脚本的执行时，发布到此主题的最后遗嘱消息已经设置为`False`，因此，消息没有被 MQTT 服务器保留，并且任何新的订阅匹配发送到保留的最后遗嘱消息的主题的主题过滤器的订阅都不会收到它。

打开现有的`vehicle_mqtt_remote_control.py` Python 文件，并用以下代码替换`__main__`方法中调用`client.will_set`方法的行。示例的代码文件包含在`mqtt_python_gaston_hillar_05_03`文件夹中的`vehicle_mqtt_remote_control.py`文件中：

```py
    client.will_set(topic=commands_topic,  
        payload=last_will_payload,  
        qos=2, 
        retain=True) 
```

我们为`retain`参数指定了`True`值，而在代码的先前版本中使用了默认的`False`值。这样，最后遗嘱消息将成为保留消息。

在任何您想要用作 MQTT 客户端并且使用 Linux 或 macOS 的计算机或设备上执行以下行以启动车辆遥控示例：

```py
    python3 vehicle_mqtt_remote_control.py
```

在 Windows 中，您必须执行以下行：

```py
    python vehicle_mqtt_remote_control.py
```

转到您执行控制车辆并处理接收到的命令的 Python 脚本的设备和窗口，即`vehicle_mqtt_client.py`。在看到以下输出后，按下*Ctrl* + *C*中断脚本的执行，直到所有命令都被接收之前：

```py
    Received message payload: b'{"CMD": "PARK_IN_SAFE_PLACE"}'
    vehiclepi01: Parking in safe place  
```

按下*Ctrl* + *C*后，您将看到类似以下行的回溯输出：

```py
^CTraceback (most recent call last):
 File "vehicle_mqtt_client.py", line 198, in <module>
 time.sleep(1)
 KeyboardInterrupt
```

我们中断了控制车辆并处理接收到的命令的 MQTT 客户端与 MQTT 服务器之间的连接。我们没有等待所有命令被接收，而是突然断开了 MQTT 客户端与 MQTT 服务器的连接。车辆遥控应用程序不知道遥控应用程序已被中断，它会等到发送的最后一个命令被处理。

转到您执行先前的 Python 脚本`vehicle_mqtt_remote_control.py`的设备和窗口。按下*Ctrl* + *C*中断脚本的执行。按下*Ctrl* + *C*后，您将看到类似以下行的回溯输出：

```py
    ^CTraceback (most recent call last):
      File "vehicle_mqtt_remote_control.py", line 93, in <module>
        client.loop()
      File "/Users/gaston/HillarMQTT/01/lib/python3.6/site-   
      packages/paho/mqtt/client.py", line 988, in loop
        socklist = select.select(rlist, wlist, [], timeout)
         KeyboardInterrupt
```

回到执行控制车辆并处理接收到的命令的 Python 脚本`vehicle_mqtt_client.py`的设备和窗口。在任何您想要用作 MQTT 客户端并且使用 Linux 或 macOS 的计算机或设备上再次执行以下命令来启动此脚本：

```py
    python3 vehicle_mqtt_client.py
```

在 Windows 中，您必须执行以下命令：

```py
    python vehicle_mqtt_client.py 
```

等待几秒钟，您将只会看到指示已接受与 MQTT 服务器的连接的输出，并且已接收和处理了指示车辆停放在安全位置的保留的遗嘱消息的输出。因此，车辆将停放在一个安全的地方：

```py
Result from connect: Connection Accepted.
Received message payload: b'{"CMD": "PARK_IN_SAFE_PLACE"}'
vehiclepi01: Parking in safe place
```

以下屏幕截图显示了在 macOS 计算机上运行的两个终端窗口。左侧的终端显示了由发布命令并作为车辆远程控制器工作的 Python 客户端显示的消息，即`vehicle_mqtt_remote_control.py`脚本。右侧的终端显示了运行控制车辆并处理接收到的命令的 Python 客户端代码的结果，即在先前解释的中断之后的`vehicle_mqtt_client.py`脚本：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-mqtt-prog-py/img/ae4b5d8c-cdd0-41f9-8101-75804c384227.png)

使用新代码时，当我们启动`vehicle_mqtt_client.py`脚本时，代码生成了一个新的 MQTT 客户端，与 MQTT 服务器建立了连接，并订阅了`vehicles/vehiclepi01/commands`。当我们中断`vehicle_mqtt_remote_control.py`脚本的执行时，最后一个遗嘱消息以`Retained`标志设置为`True`发布到此主题，因此，消息被 MQTT 服务器保留，并且任何新订阅与保留的遗嘱消息匹配的主题过滤器的连接都会接收到它。保留的遗嘱消息允许我们确保消息在新连接到 MQTT 服务器并订阅匹配主题时作为第一条消息到达。

在这种情况下，我们始终希望确保如果`vehicle_mqtt_client.py`脚本中创建的 MQTT 客户端与 MQTT 服务器失去连接，然后建立新连接，车辆会收到遗嘱消息。

# 理解阻塞和非阻塞代码

到目前为止，我们一直在处理与 MQTT 相关的网络流量和分发回调的阻塞调用。在以前的示例中，每当我们调用`client.loop`方法时，该方法都会使用两个可选参数的默认值：`timeout`为`1`，`max_packets`为`1`。该方法最多阻塞一秒钟，即`timeout`参数的值，以处理传入或传出的数据。该方法以同步执行，因此，在此方法返回之前，下一行代码不会被执行。我们在主线程中调用了`client.loop`方法，因此，在`client.loop`方法阻塞时，此线程中无法执行其他代码。

在我们的第一个示例中，使用 Python 代码创建了一个 MQTT 客户端，我们调用了`client.loop_forever`方法。此方法会阻塞，直到客户端调用`disconnect`方法。该方法以同步执行，因此，在客户端调用`disconnect`方法之前，下一行代码不会被执行。我们还在主线程中调用了`client.loop_forever`，因此，在`client.loop_forever`方法阻塞时，此线程中无法执行其他代码。

循环方法和`loop_forever`方法之间的一个重要区别是，当我们使用循环方法时，需要手动处理重新连接。`loop_forever`方法会自动处理与 MQTT 服务器的重新连接。

`paho-mqtt`库为我们提供了一个用于网络循环的线程化客户端接口，启动另一个线程自动调用`loop`方法。这样，就可以释放主线程来运行其他代码。线程化接口是非阻塞的，我们不必担心重复调用`loop`方法。此外，线程化接口还会自动处理与 MQTT 服务器的重新连接。

# 使用线程化的客户端接口

现在，我们将编写车辆远程控制应用的新版本，以使用线程化接口，也称为线程循环。打开现有的`vehicle_mqtt_remote_control.py` Python 文件，并用以下行替换定义`publish_command`函数的行。示例的代码文件包含在`mqtt_python_gaston_hillar_05_04`文件夹中的`vehicle_mqtt_remote_control.py`文件中：

```py
def publish_command(client, command_name, key="", value=""): 
    command_message = build_command_message( 
        command_name, key, value) 
    result = client.publish(topic=commands_topic, 
    payload=command_message, qos=2) 
    time.sleep(1) 
    return result 
```

在调用`time.sleep(1)`之前，我们移除了以下行：

```py
    client.loop() 
```

线程循环将在另一个线程中自动调用`client.loop`，因此，我们不再需要在`publish_command`方法中包含对`client.loop`的调用。

打开现有的`vehicle_mqtt_remote_control.py` Python 文件，并用以下代码替换定义`__main__`方法的行，以使用线程循环。添加的行已经突出显示。示例的代码文件包含在`mqtt_python_gaston_hillar_05_04`文件夹中的`vehicle_mqtt_remote_control.py`文件中：

```py
if __name__ == "__main__": 
    client = mqtt.Client(protocol=mqtt.MQTTv311) 
    client.on_connect = on_connect 
    client.on_subscribe = on_subscribe 
    client.on_message = on_message 
    client.tls_set(ca_certs = ca_certificate, 
         certfile=client_certificate, 
         keyfile=client_key) 
    # Set a will to be sent to the MQTT server in case the client 
    # disconnects unexpectedly 
    last_will_payload = build_command_message(CMD_PARK_IN_SAFE_PLACE) 
    client.will_set(topic=commands_topic,  
        payload=last_will_payload,  
        qos=2, 
        retain=True) 
    client.connect(host=mqtt_server_host, 
        port=mqtt_server_port, 
        keepalive=mqtt_keepalive) 
    client.loop_start() 
    publish_command(client, CMD_SET_MAX_SPEED, KEY_MPH, 30) 
    publish_command(client, CMD_SET_MIN_SPEED, KEY_MPH, 8) 
    publish_command(client, CMD_LOCK_DOORS) 
    publish_command(client, CMD_TURN_ON_ENGINE) 
    publish_command(client, CMD_ROTATE_RIGHT, KEY_DEGREES, 15) 
    publish_command(client, CMD_ACCELERATE) 
    publish_command(client, CMD_ROTATE_RIGHT, KEY_DEGREES, 25) 
    publish_command(client, CMD_ACCELERATE) 
    publish_command(client, CMD_ROTATE_LEFT, KEY_DEGREES, 15) 
    publish_command(client, CMD_ACCELERATE) 
    publish_command(client, CMD_TURN_OFF_ENGINE) 
    while LoopControl.is_last_command_processed == False: 
        # Check whether the last command has been processed or not  
        # every 500 milliseconds 
        time.sleep(0.5) 
       client.disconnect() 
       client.loop_stop() 
```

调用`client.connect`方法后，代码调用`client.loop_start`方法。该方法会启动一个新线程来处理 MQTT 网络流量，并释放主线程。

然后，编辑后的`publish_command`函数的调用不再调用`client.loop`，因为我们使用`client.loop_start`启动的线程化客户端接口将自动调用循环来处理传出消息。

每 500 毫秒检查最后一条命令是否已经被处理的`while`循环不再调用`client.loop`。现在，有另一个线程在为我们调用`client.loop`。

当最后一条命令被处理时，代码调用`client.disconnect`方法，最后调用`client.loop_stop`方法来停止运行线程化客户端接口的线程。该方法将在线程完成时返回。

在任何您想要用作 MQTT 客户端并且使用 Linux 或 macOS 的计算机或设备上，执行以下行以启动车辆远程控制示例的新版本：

```py
    python3 vehicle_mqtt_remote_control.py
```

在 Windows 中，您必须执行以下行：

```py
    python vehicle_mqtt_remote_control.py 
```

您会注意到发送命令和处理命令之间的时间更清晰，因为新版本中处理网络事件的时间更准确。

# 测试您的知识

让我们看看您是否能正确回答以下问题：

1.  `paho.mqtt.client.Client`实例的以下哪种方法会阻塞执行并确保与 MQTT 服务器的通信进行？

1.  `loop`

1.  `loop_start`

1.  阻塞循环

1.  `paho.mqtt.client.Client`实例的以下哪种方法会启动一个新线程，并确保与 MQTT 服务器的通信进行？

1.  `loop`

1.  `loop_start`

1.  `non_blocking_loop`

1.  `paho.mqtt.client.Client`实例的以下哪种方法配置了一个遗嘱消息，以便在客户端意外断开连接时发送到 MQTT 服务器？

1.  `last_will_publish`

1.  `last_will_message`

1.  `will_set`

1.  `paho.mqtt.client.Client`实例的以下哪种方法停止运行线程化客户端接口的线程？

1.  `loop_end`

1.  `non_blocking_loop_stop`

1.  `loop_stop`

1.  以下哪种方法是非阻塞的？

1.  `loop_start`

1.  `non_blocking_loop`

1.  `loop_forever`

正确答案包含在附录中，*解决方案*。

# 摘要

在本章中，我们使用 Python 代码处理接收的 JSON 字符串作为 MQTT 消息中的命令。然后，我们编写了一个 Python 客户端，用于组合和发布带有命令的消息，以作为车辆控制器的远程控制应用程序。

我们使用了阻塞网络循环，然后将应用程序转换为使用线程化的客户端接口，以避免阻塞主线程。我们利用了遗嘱功能，以确保在连接丢失时受控车辆停在安全位置。然后，我们处理了保留的遗嘱消息。

现在我们了解了如何使用 Python 来处理利用高级功能的多个 MQTT 应用程序，我们将使用基于云的实时 MQTT 提供程序来监视冲浪比赛，我们需要从多个传感器接收和处理数据，这就是我们将在第六章中讨论的内容，《使用基于云的实时 MQTT 提供程序和 Python 监视冲浪比赛》。


# 第六章：使用基于云的实时 MQTT 提供程序和 Python 监控冲浪比赛

在本章中，我们将编写 Python 代码，使用 PubNub 基于云的实时 MQTT 提供程序与 Mosquitto MQTT 服务器结合，监控冲浪比赛。我们将通过分析需求从头构建解决方案，并编写 Python 代码，该代码将在连接到冲浪板中的多个传感器的防水 IoT 板上运行。我们将定义主题和命令，并与基于云的 MQTT 服务器以及在先前章节中使用的 Mosquitto MQTT 服务器一起工作。我们将涵盖以下内容：

+   理解要求

+   定义主题和有效载荷

+   编写冲浪板传感器仿真器

+   配置 PubNub MQTT 接口

+   将从传感器检索的数据发布到基于云的 MQTT 服务器

+   使用多个 MQTT 服务器

+   使用 freeboard 构建基于 Web 的仪表板

# 理解要求

许多为冲浪比赛训练的冲浪者希望我们构建一个实时基于 Web 的仪表板，该仪表板使用连接到冲浪板中的多个传感器的 IoT 板提供的数据。每个 IoT 板将提供以下数据：

+   **状态**：每个冲浪者的潜水服中嵌入了许多可穿戴无线传感器，冲浪板中还包括其他传感器，它们将提供数据，而 IoT 板将进行实时分析以指示冲浪者的状态

+   **速度**：传感器将以**每小时英里**（**mph**）测量冲浪板的速度

+   **海拔**：传感器将以英尺测量冲浪板的海拔

+   **水温**：位于冲浪板鳍中的传感器将以华氏度测量水温

第三方软件正在 IoT 板上运行，我们无法更改发布不同主题数据的代码。我们可以提供必要的证书来配置与我们的 Mosquitto MQTT 服务器的安全连接，并指定其主机名和协议。此外，我们可以配置一个标识冲浪板并确定数据将被发布的主题的名称。

# 定义主题和有效载荷

IoT 板使用以下主题名称发布有关特定冲浪板的数据，其中`sufboardname`必须替换为分配给冲浪板的唯一名称：

| **变量** | **主题名称** |
| --- | --- |
| 状态 | `surfboards/surfboardname/status` |
| 速度（mph） | `surfboards/surfboardname/speedmph` |
| 海拔（英尺） | `surfboards/surfboardname/altitudefeet` |
| 水温（华氏度） | `surfboards/surfboardname/temperaturef` |

例如，如果我们将`sufboard01`指定为冲浪板的名称，那么想要接收冲浪板实际速度的客户端必须订阅`sufboards/surfboard01/speedmph`主题。

IoT 板及其连接的传感器能够区分冲浪者及其冲浪板的以下五种可能状态：

| **状态键** | **含义** |
| --- | --- |
| `0` | 空闲 |
| `1` | 划水 |
| `2` | 骑行 |
| `3` | 骑行结束 |
| `4` | 摔倒 |

IoT 板发布指定在状态键列中的整数值，指示冲浪者及其冲浪板的当前状态。例如，当冲浪者在冲浪时，板将在`sufboards/surfboard01/status`主题中发布`2`。

该板将在先前解释的主题中发布速度、海拔和水温的浮点值。在这种情况下，IoT 板将只发布整数或浮点值作为 MQTT 消息的有效载荷。有效载荷不会是 JSON，就像我们之前的例子一样。有效载荷不会包含有关测量单位的任何其他信息。此信息包含在主题名称中。

IoT 板将在先前解释的主题中每秒发布数据。

在之前的例子中，我们是从零开始设计我们的解决方案。在这种情况下，我们必须与已经运行我们无法更改代码的物联网板进行交互。想象一下，我们必须在没有物联网板的情况下开始解决方案的工作；因此，我们将在 Python 中开发一个冲浪板传感器模拟器，以便为我们提供数据，以便我们可以接收发布的数据并开发所需的仪表板。在现实项目中，这是一个非常常见的情况。

正如我们在之前的章节中学到的，MQTT 已经成为物联网项目中非常流行的协议，其中许多传感器必须发布数据。由于其日益增长的流行度，许多基于云的消息基础设施已经包含了 MQTT 接口或桥接。例如，PubNub 数据流网络提供了可扩展的 MQTT 接口。我们可以利用到目前为止我们所学到的关于 MQTT 的一切来使用这个基于云的数据流网络。您可以在其网页上了解更多关于 PubNub 的信息：[`www.pubnub.com`](http://www.pubnub.com)。

一个 Python 程序将通过订阅四个主题来收集物联网板发布的数据，并且代码将每秒构建一个完整的冲浪者及其冲浪板状态。然后，代码将构建一个包含状态、速度、海拔和水温的 JSON 消息，并将其发布到 MQTT PubNub 接口的一个主题。

在我们的例子中，我们将利用 PubNub 及其 MQTT 接口提供的免费服务。我们不会使用一些可能增强我们的物联网项目连接需求的高级功能和附加服务，但这些功能也需要付费订阅。

我们将利用 freeboard.io 来可视化从传感器收集的数据，并在 PubNub MQTT 接口中发布，以多个表盘的形式呈现，并且可以在全球范围内的不同计算机和设备上使用。freeboard.io 允许我们通过选择数据源并拖放可定制的小部件来构建仪表板。freeboard.io 定义自己为一个允许我们可视化物联网的基于云的服务。您可以在其网页上了解更多关于 freeboard.io 的信息：[`freeboard.io`](http://freeboard.io)。

在我们的例子中，我们将利用 freeboard.io 提供的免费服务，并且我们不会使用一些提供我们仪表板隐私的高级功能，但这些功能也需要付费订阅。我们的仪表板将对任何拥有其唯一 URL 的人可用，因为我们不使用私人仪表板。

以下是提供冲浪者及其冲浪板状态的消息负载的示例。

```py
{ 
    "Status": "Riding",  
    "Speed MPH": 15.0,  
    "Altitude Feet": 3.0,  
    "Water Temperature F": 56.0 
}
```

Freeboard.io 允许我们轻松地选择 PubNub MQTT 接口中接收的 JSON 消息的每个键作为仪表板的数据源。这样，我们将轻松地构建一个基于 Web 的仪表板，以提供给我们状态、速度、海拔和水温数值的表盘。

总之，我们的解决方案将由以下两个 Python 程序组成：

+   **冲浪板传感器模拟器**：该程序将与我们的 Mosquitto MQTT 服务器建立安全连接，并且将从**CSV**（逗号分隔值）文件中读取的状态、速度、海拔和水温数值发布到适当的主题。该程序将工作得就像我们有一个穿着潜水服和冲浪板传感器的真实冲浪者在冲浪并发布数据一样。

+   **冲浪板监视器**：该程序将与我们的 Mosquitto MQTT 服务器建立安全连接，并订阅冲浪板传感器模拟器发布的状态、速度、海拔和水温数值的主题。冲浪板监视器程序还将与 PubNub MQTT 接口建立连接。该程序将每秒向 PubNub MQTT 接口发布一个包含决定冲浪者及其冲浪板状态的键值对的单个消息。

# 编写冲浪板传感器模拟器

首先，我们将创建一个 CSV 文件，其中包含许多状态、速度（以英里/小时为单位）、海拔（以英尺为单位）和温度（以华氏度为单位）的值，这些值用逗号分隔。文件中的每一行将代表冲浪板传感器模拟器将发布到相应主题的一组值。在这种情况下，使用随机值并不方便，因为我们希望模拟冲浪者和他的冲浪板的真实场景。

现在，我们将在主虚拟环境文件夹中创建一个名为`surfboard_sensors_data.csv`的新文件。以下行显示了定义从冲浪者和他们的冲浪板中检索到的数据的代码。

从左到右用逗号分隔的值依次是：速度（以英里/小时为单位）、海拔（以英尺为单位）和温度（以华氏度为单位）。首先，冲浪者处于空闲状态，当划桨时增加速度，当冲浪时达到速度最大值，最后在状态设置为冲浪结束时减速。示例的代码文件包含在`mqtt_python_gaston_hillar_06_01`文件夹中的`surfboard_sensors_data.csv`文件中：

```py
0, 1, 2, 58 
0, 1.1, 2, 58 
1, 2, 3, 57 
1, 3, 3, 57 
1, 3, 3, 57 
1, 3, 3, 57 
1, 4, 4, 57 
1, 5, 5, 57 
2, 8, 5, 57 
2, 10, 4, 57 
2, 12, 4, 56 
2, 15, 3, 56 
2, 15, 3, 56 
2, 15, 3, 56 
2, 15, 3, 56 
2, 15, 3, 56 
2, 12, 3, 56 
3, 3, 3, 55 
3, 2, 3, 55 
3, 1, 3, 55 
3, 0, 3, 55 
```

现在，我们将在主虚拟环境文件夹中创建一个名为`surfboard_config.py`的新 Python 文件。以下行显示了此文件的代码，它定义了许多配置值，这些值将用于配置冲浪板传感器模拟器将发布从传感器检索到的值的主题。冲浪板监视器也将需要这些主题来订阅它们，因此将所有配置值包含在一个特定的 Python 脚本中是方便的。示例的代码文件包含在`mqtt_python_gaston_hillar_06_01`文件夹中的`surfboard_config.py`文件中：

```py
surfboard_name = "surfboard01" 
topic_format = "surfboards/{}/{}" 
status_topic = topic_format.format( 
    surfboard_name,  
    "status") 
speed_mph_topic = topic_format.format( 
    surfboard_name,  
    "speedmph") 
altitude_feet_topic = topic_format.format( 
    surfboard_name,  
    "altitudefeet") 
water_temperature_f_topic = topic_format.format( 
    surfboard_name,  
    "temperaturef")
```

该代码定义了冲浪板名称并将其存储在`surfboard_name`变量中。`topic_format`变量包含一个字符串，使得易于构建具有共同前缀的不同主题。以下表总结了四个变量的字符串值，这些变量定义了每个传感器的主题名称，基于一个名为`surfboard01`的定义的冲浪板：

| **变量** | **值** |
| --- | --- |
| `status_topic` | `surfboards/surfboard01/status` |
| `speed_mph_topic` | `surfboards/surfboard01/speedmph` |
| `altitude_feet_topic` | `surfboards/surfboard01/altitudefeet` |
| `temperature_f_topic` | `surfboards/surfboard01/temperaturef` |

现在，我们将在主虚拟环境文件夹中创建一个名为`surfboard_sensors_emulator.py`的新 Python 文件。以下行显示了此文件的代码，它与我们的 Mosquitto MQTT 服务器建立连接，读取先前创建的`surfboard_sensors_data.csv` CSV 文件，并持续发布从该文件中读取的值到先前枚举的主题。示例的代码文件包含在`mqtt_python_gaston_hillar_06_01`文件夹中的`surfboard_sensors_emulator.py`文件中：

```py
from config import * 
from surfboard_config import * 
import paho.mqtt.client as mqtt 
import time 
import csv 

def on_connect(client, userdata, flags, rc): 
    print("Result from connect: {}".format( 
        mqtt.connack_string(rc))) 
    # Check whether the result form connect is the CONNACK_ACCEPTED connack code 
    if rc != mqtt.CONNACK_ACCEPTED: 
        raise IOError("I couldn't establish a connection with the MQTT server") 

def publish_value(client, topic, value): 
    result = client.publish(topic=topic, 
        payload=value, 
        qos=0) 
    return result 

if __name__ == "__main__": 
    client = mqtt.Client(protocol=mqtt.MQTTv311) 
    client.on_connect = on_connect 
    client.tls_set(ca_certs = ca_certificate, 
        certfile=client_certificate, 
        keyfile=client_key) 
    client.connect(host=mqtt_server_host, 
        port=mqtt_server_port, 
        keepalive=mqtt_keepalive) 
    client.loop_start() 
    publish_debug_message = "{}: {}" 
    try: 
        while True: 
            with open('surfboard_sensors_data.csv') as csvfile: 
                reader=csv.reader(csvfile) 
                for row in reader: 
                    status_value = int(row[0]) 
                    speed_mph_value = float(row[1]) 
                    altitude_feet_value = float(row[2]) 
                    water_temperature_f_value = float(row[3]) 
                    print(publish_debug_message.format( 
                        status_topic, 
                        status_value)) 
                    print(publish_debug_message.format( 
                        speed_mph_topic,  
                        speed_mph_value)) 
                    print(publish_debug_message.format( 
                        altitude_feet_topic,  
                        altitude_feet_value)) 
                    print(publish_debug_message.format( 
                        water_temperature_f_topic,  
                        water_temperature_f_value)) 
                    publish_value(client,  
                        status_topic,  
                        status_value) 
                    publish_value(client,  
                        speed_mph_topic,  
                        speed_mph_value) 
                    publish_value(client,  
                        altitude_feet_topic,  
                        altitude_feet_value) 
                    publish_value(client, 
                        water_temperature_f_topic,  
                        water_temperature_f_value)                    time.sleep(1) 
    except KeyboardInterrupt: 
        print("I'll disconnect from the MQTT server") 
        client.disconnect() 
        client.loop_stop() 
```

在第四章中，*使用 Python 和 MQTT 消息编写控制车辆的代码*，我们在主虚拟环境文件夹中创建了一个名为`config.py`的 Python 文件。在这个文件中，我们定义了许多配置值，用于与 Mosquitto MQTT 服务器建立连接。这样，所有配置值都包含在一个特定的 Python 脚本中。如果您需要更改此文件以配置冲浪板模拟器和未来的冲浪板监视器，请确保您查看该章节中包含的解释。

首先导入了我们在`config.py`文件和先前编码的`surfboard_config.py`文件中声明的变量。在这种情况下，我们还导入了`csv`模块，以便我们可以轻松地从包含模拟传感器值的 CSV 文件中读取。`on_connect`函数的代码与我们在先前的示例中使用的代码非常相似。

`publish_value`函数接收 MQTT 客户端、主题名称和我们要在`client`、`topic`和`value`参数中发布的值。该函数调用`client.publish`方法，将接收到的值作为有效载荷发布到`topic`参数中接收到的主题名称，QoS 级别为 0。

主要代码块使用我们非常熟悉的代码与 Mosquitto MQTT 服务器建立连接。调用`client.connect`方法后，代码调用`client.loop_start`方法启动一个处理 MQTT 网络流量并释放主线程的新线程。

然后，代码进入一个连续循环，打开`surfboard_sensors_data.csv` CSV 文件，并创建一个`csv.reader`来将逗号分隔的值的每一行读入`row`数组。代码检索`row[0]`中的字符串，该字符串代表状态值；将其转换为整数值；并将该值保存在`status_value`本地变量中。接下来的行检索`row[1]`、`row[2`和`row[3]`中的速度、海拔和水温的字符串。代码将这三个值转换为浮点数，并将它们保存在`speed_mph_value`、`altitude_feet_value`和`water_temperature_f_value`本地变量中。

接下来的行会打印调试消息，显示从 CSV 文件中读取的每个模拟传感器的值，并为每个值调用先前解释的`publish_value`函数。每次调用`publish_value`函数都会使用在`surfboard_config.py`文件中配置的主题名称的适当变量，因为每个值都会发布到不同的主题。

在代码发布了四个模拟传感器的值后，它会休眠一秒钟，然后重复 CSV 文件中下一行的过程。在读取了最后一行后，代码会再次开始循环，直到用户按下*Ctrl* + *C*并引发`KeyboardInterrupt`异常被捕获。在这种情况下，我们捕获此异常并调用`client.disconnect`和`client.loop_stop`方法，以适当地从 Mosquitto MQTT 服务器断开连接。在以前的示例中，我们并不关心这个异常。

# 配置 PubNub MQTT 接口

在使用 PubNub 的免费服务之前，PubNub 要求我们注册并创建一个带有有效电子邮件和密码的帐户，以便在 PubNub 中创建应用程序，包括设备的 PubNub MQTT 接口。我们不需要输入任何信用卡或付款信息。如果您已经在 PubNub 上有帐户，可以跳过下一步。

创建账户后，PubNub 将重定向您到列出 PubNub 应用程序的管理门户。为了在网络上发送和接收消息，需要生成 PubNub 的发布和订阅密钥。点击 CREATE NEW APP+，输入`MQTT`作为应用名称，然后点击 CREATE。

在管理门户中，一个新的窗格将代表应用程序。以下截图显示了 PubNub 管理门户中的 MQTT 应用程序窗格：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-mqtt-prog-py/img/9688a166-7994-4df1-93c5-9405719dbb2b.png)

点击 MQTT 窗格，PubNub 将显示自动生成的 Demo Keyset 窗格。点击此窗格，PubNub 将显示 Publish Key、Subscribe Key 和 Secret key。我们必须复制并粘贴这些密钥，以便在使用 PubNub MQTT 接口发布消息和订阅这些消息的 freeboard.io 基于 Web 的仪表板的代码中使用。以下截图显示了密钥的前缀。请注意，图像中的其余字符已被删除：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-mqtt-prog-py/img/1bd7d1cf-d2e7-4029-8689-cae606953d28.png)

为了复制 Secret key，您必须点击 Secret key 右侧的眼睛图标，PubNub 将使所有字符可见。

# 从传感器检索的数据发布到基于云的 MQTT 服务器

如果我们用数字显示冲浪者和他的冲浪板的状态，那么理解真实状态将会很困难。因此，我们必须将表示状态的整数映射到解释状态的字符串。

现在，我们将在主虚拟环境文件夹中创建一个名为`surfboard_status.py`的新 Python 文件。以下行显示了此文件的代码，其中定义了不同状态数字的常量和将这些常量与整数映射到状态描述字符串的字典。示例的代码文件包含在`mqtt_python_gaston_hillar_06_01`文件夹中的`surfboard_status.py`文件中：

```py
SURFBOARD_STATUS_IDLE = 0 
SURFBOARD_STATUS_PADDLING = 1 
SURFBOARD_STATUS_RIDING = 2 
SURFBOARD_STATUS_RIDE_FINISHED = 3 
SURFBOARD_STATUS_WIPED_OUT = 4 

SURFBOARD_STATUS_DICTIONARY = { 
    SURFBOARD_STATUS_IDLE: 'Idle', 
    SURFBOARD_STATUS_PADDLING: 'Paddling', 
    SURFBOARD_STATUS_RIDING: 'Riding', 
    SURFBOARD_STATUS_RIDE_FINISHED: 'Ride finished', 
    SURFBOARD_STATUS_WIPED_OUT: 'Wiped out', 
    } 
```

现在，我们将编写冲浪板监视器的代码。我们将把代码分成许多代码片段，以便更容易理解每个代码部分。在主虚拟环境文件夹中创建一个名为`surfboard_monitor.py`的新 Python 文件。以下行声明了所有必要的导入和我们将用来与 PubNub MQTT 接口建立连接的变量。不要忘记用从先前解释的 PubNub 密钥生成过程中检索到的值替换分配给`pubnub_publish_key`和`pubnub_subscribe_key`变量的字符串。示例的代码文件包含在`mqtt_python_gaston_hillar_06_01`文件夹中的`surfboard_monitor.py`文件中：

```py
from config import * 
from surfboard_status import * 
from surfboard_config import * 
import paho.mqtt.client as mqtt 
import time 
import json 

# Publish key is the one that usually starts with the "pub-c-" prefix 
# Do not forget to replace the string with your publish key 
pubnub_publish_key = "pub-c-xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" 
# Subscribe key is the one that usually starts with the "sub-c" prefix 
# Do not forget to replace the string with your subscribe key 
pubnub_subscribe_key = "sub-c-xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" 
pubnub_mqtt_server_host = "mqtt.pndsn.com" 
pubnub_mqtt_server_port = 1883 
pubnub_mqtt_keepalive = 60 
device_id = surfboard_name 
pubnub_topic = surfboard_name 
```

首先导入了我们在`config.py`文件中声明的变量以及之前编写的`surfboard_config.py`和`surfboard_status.py`文件中的变量。然后，代码声明了以下变量，我们将使用这些变量与 PubNub MQTT 接口建立连接：

+   `pubnub_publish_key`：此字符串指定了 PubNub 发布密钥。

+   `pubnub_subscribe_key`：此字符串指定了 PubNub 订阅密钥。

+   `pubnub_mqtt_server_host`：此字符串指定了 PubNub MQTT 服务器地址。为了使用 PubNub MQTT 接口，我们必须始终与`mqtt.pndsn.com`主机建立连接。

+   `pubnub_mqtt_server_port`：此数字指定了 PubNub MQTT 服务器端口。在这种情况下，我们将与 PubNub MQTT 服务器建立一个不安全的连接，因此我们将使用端口号`1883`。我们希望保持 PubNub MQTT 接口配置简单，因此在此示例中不使用 TLS。

+   `pubnub_mqtt_keepalive`：此数字指定了与 PubNub MQTT 接口的连接的保持活动间隔配置。

+   `device_id`：此字符串指定了我们在创建`Surfboard`类的实例时要使用的设备标识符。代码分配了从`surfboard_config.py`文件导入的`surfboard_name`值。我们稍后将分析此类的代码。

+   `Pubnub_topic`：此字符串指定了冲浪板监视器将向其发布 JSON 有效载荷的主题，该有效载荷包含指定冲浪者和他们的冲浪板状态的键值对。代码分配了从`surfboard_config.py`文件导入的`surfboard_name`值。

冲浪板监视器将在端口`1883`上与`mqtt.pndsn.com`主机建立连接。因此，我们必须确保我们的防火墙配置具有适当的入站和出站规则配置，以允许在指定端口上建立连接。

将以下行添加到主虚拟环境文件夹中现有的`surfboard_monitor.py`中。以下行声明了`Surfboard`类。示例的代码文件包含在`mqtt_python_gaston_hillar_06_01`文件夹中的`surfboard_monitor.py`文件中：

```py
class Surfboard: 
    active_instance = None 
    def __init__(self, device_id, status,  
        speed_mph, altitude_feet, water_temperature_f): 
        self.device_id = device_id 
        self.status = status 
        self.speed_mph = speed_mph 
        self.altitude_feet = altitude_feet 
        self.water_temperature_f = water_temperature_f 
        self.is_pubnub_connected = False 
        Surfboard.active_instance = self 

    def build_json_message(self): 
        # Build a message with the status for the surfboard 
        message = { 
            "Status": SURFBOARD_STATUS_DICTIONARY[self.status], 
            "Speed MPH": self.speed_mph, 
            "Altitude Feet": self.altitude_feet, 
            "Water Temperature F": self.water_temperature_f,  
        } 
        json_message = json.dumps(message) 
        return json_message
```

我们必须为传感器提供的数据的`device_id`、`status`、`speed_mph`、`altitude_feet`和`water_temperature_f`参数指定一个`device_id`和初始值。构造函数，即`__init__`方法，将接收到的值保存在同名的属性中。

该代码还将引用保存在`active_instance`类属性中，因为我们必须在许多函数中访问该实例，这些函数将被指定为两个 MQTT 客户端触发的不同事件的回调：PubNub MQTT 客户端和 Mosquitto MQTT 客户端。在代码创建`Surfboard`实例后，我们将使用`Surfboard.active_instance`类属性访问活动实例。

该类声明了`build_json_message`方法，该方法构建了一个包含冲浪板状态的消息，并返回了由组成状态消息的键值对组成的 JSON 字符串。该代码使用`SURFBOARD_STATUS_DICTIONARY`在`surfboard_status.py`文件中声明的内容，将存储在`status`属性中的数字映射为解释状态的字符串。代码使用`speed_mph`，`altitude_feet`和`water_temperature_f`属性为其他键提供值。

在主虚拟环境文件夹中的现有`surfboard_monitor.py`中添加以下行。以下行声明了我们将用作回调的函数以及将由这些回调调用的其他函数。示例的代码文件包含在`mqtt_python_gaston_hillar_06_01`文件夹中的`surfboard_monitor.py`文件中：

```py
def on_connect_mosquitto(client, userdata, flags, rc): 
    print("Result from Mosquitto connect: {}".format( 
        mqtt.connack_string(rc))) 
    # Check whether the result form connect is the CONNACK_ACCEPTED connack code 
    if rc == mqtt.CONNACK_ACCEPTED: 
        # Subscribe to a topic filter that provides all the sensors 
        sensors_topic_filter = topic_format.format( 
            surfboard_name, 
            "+") 
        client.subscribe(sensors_topic_filter, qos=0) 

def on_subscribe_mosquitto(client, userdata, mid, granted_qos): 
    print("I've subscribed with QoS: {}".format( 
        granted_qos[0])) 

def print_received_message_mosquitto(msg): 
    print("Message received. Topic: {}. Payload: {}".format( 
        msg.topic,  
        str(msg.payload))) 

def on_status_message_mosquitto(client, userdata, msg): 
    print_received_message_mosquitto(msg) 
    Surfboard.active_instance.status = int(msg.payload) 

def on_speed_mph_message_mosquitto(client, userdata, msg): 
    print_received_message_mosquitto(msg) 
    Surfboard.active_instance.speed_mph = float(msg.payload) 

def on_altitude_feet_message_mosquitto(client, userdata, msg): 
    print_received_message_mosquitto(msg) 
    Surfboard.active_instance.altitude_feet = float(msg.payload) 

def on_water_temperature_f_message_mosquitto(client, userdata, msg): 
    print_received_message_mosquitto(msg) 
    Surfboard.active_instance.water_temperature_f = float(msg.payload) 

def on_connect_pubnub(client, userdata, flags, rc): 
    print("Result from PubNub connect: {}".format( 
        mqtt.connack_string(rc))) 
    # Check whether the result form connect is the CONNACK_ACCEPTED connack code 
    if rc == mqtt.CONNACK_ACCEPTED: 
        Surfboard.active_instance.is_pubnub_connected = True 

def on_disconnect_pubnub(client, userdata, rc): 
    Surfboard.active_instance.is_pubnub_connected = False 
    print("Disconnected from PubNub")
```

该代码声明了以下以`mosquitto`前缀结尾的函数：

+   `on_connect_mosquitto`：这个函数是一旦与 Mosquitto MQTT 服务器建立了成功的连接，就会执行的回调。代码检查`rc`参数的值，该参数提供 Mosquitto MQTT 服务器返回的`CONNACK`代码。如果此值匹配`mqtt.CONNACK_ACCEPTED`，则意味着 Mosquitto MQTT 服务器接受了连接请求，因此代码调用`client.subscribe`方法，为`client`参数中接收的 MQTT 客户端订阅`surfboards/surfboard01/+`主题过滤器，QoS 级别为 0。这样，MQTT 客户端将接收从不同传感器检索的值发送到`surfboards/surfboard01/status`，`surfboards/surfboard01/speedmph`，`surfboards/surfboard01/altitudefeet`和`surfboards/surfboard01/temperaturef`主题的消息。

+   `on_subscribe_mosquitto`：当成功完成对`surfboards/surfboard01/+`主题过滤器的订阅时，将调用此函数。与之前的示例一样，该函数打印一条消息，指示订阅所授予的 QoS 级别。

+   `print_received_message_mosquitto`：此函数在`msg`参数中接收一个`mqtt.MQTTMessage`实例，并打印此消息的主题和负载，以帮助我们理解应用程序中发生的情况。

+   `on_status_message_mosquitto`：当来自 Mosquitto MQTT 服务器的消息到达`surfboards/surfboard01/status`主题时，将调用此函数。该函数使用接收到的`mqtt.MQTTMessage`实例作为参数调用`print_received_message_mosquitto`函数，并将`Surfboard`活动实例的`status`属性值设置为接收到的消息负载转换为`int`的值。

+   `on_speed_mph_message_mosquitto`：当来自 Mosquitto MQTT 服务器的消息到达`surfboards/surfboard01/speedmph`主题时，将调用此函数。该函数使用接收到的`mqtt.MQTTMessage`实例作为参数调用`print_received_message_mosquitto`函数，并将`Surfboard`活动实例的`speed_mph`属性值设置为接收到的消息负载转换为`float`的值。

+   `on_altitude_feet_message_mosquitto`：当从 Mosquitto MQTT 服务器接收到`surfboards/surfboard01/altitudefeet`主题的消息时，将调用此函数。 该函数使用接收到的`mqtt.MQTTMessage`实例作为参数调用`print_received_message_mosquitto`函数，并将`Surfboard`活动实例的`altitude_feet`属性值设置为接收到的消息负载的整数转换。

+   `on_water_temperature_f_message_mosquitto`：当从 Mosquitto MQTT 服务器接收到`surfboards/surfboard01/watertemperaturef`主题的消息时，将调用此函数。 该函数使用接收到的`mqtt.MQTTMessage`实例作为参数调用`print_received_message_mosquitto`函数，并将`Surfboard`活动实例的`water_temperature_f`属性值设置为接收到的消息负载的整数转换。

在这种情况下，我们没有一个单独的函数作为回调来处理来自 Mosquitto MQTT 服务器的所有传入消息。 我们为每个特定主题使用一个回调。 这样，我们就不必检查消息的主题以确定我们必须运行的代码。

代码声明了以下以`pubnub`前缀结尾的函数：

+   `on_connect_pubnub`：一旦与 PubNub MQTT 服务器建立成功连接，将执行此回调函数。 该代码检查提供 PubNub MQTT 服务器返回的`CONNACK`代码的`rc`参数的值。 如果此值与`mqtt.CONNACK_ACCEPTED`匹配，则表示 PubNub MQTT 服务器接受了连接请求，因此代码将 Surfboard 活动实例的`is_pubnub_connected`属性值设置为`True`。

+   `on_disconnect_pubnub`：如果连接到 PubNub MQTT 服务器的客户端失去连接，将执行此回调函数。 该代码将 Surfboard 活动实例的`is_pubnub_connected`属性值设置为`False`，并打印一条消息。

# 使用多个 MQTT 服务器

在主虚拟环境文件夹中的现有`surfboard_monitor.py`中添加以下行。 以下行声明了主要块。 示例的代码文件包含在`mqtt_python_gaston_hillar_06_01`文件夹中的`surfboard_monitor.py`文件中：

```py
if __name__ == "__main__": 
    surfboard = Surfboard(device_id=device_id, 
        status=SURFBOARD_STATUS_IDLE, 
        speed_mph=0,  
        altitude_feet=0,  
        water_temperature_f=0) 
    pubnub_client_id = "{}/{}/{}".format( 
        pubnub_publish_key, 
        pubnub_subscribe_key, 
        device_id) 
    pubnub_client = mqtt.Client(client_id=pubnub_client_id, 
        protocol=mqtt.MQTTv311) 
    pubnub_client.on_connect = on_connect_pubnub 
    pubnub_client.on_disconnect = on_disconnect_pubnub 
    pubnub_client.connect(host=pubnub_mqtt_server_host, 
        port=pubnub_mqtt_server_port, 
        keepalive=pubnub_mqtt_keepalive) 
    pubnub_client.loop_start() 
    mosquitto_client = mqtt.Client(protocol=mqtt.MQTTv311) 
    mosquitto_client.on_connect = on_connect_mosquitto 
    mosquitto_client.on_subscribe = on_subscribe_mosquitto 
    mosquitto_client.message_callback_add( 
        status_topic, 
        on_status_message_mosquitto) 
    mosquitto_client.message_callback_add( 
        speed_mph_topic, 
        on_speed_mph_message_mosquitto) 
    mosquitto_client.message_callback_add( 
        altitude_feet_topic, 
        on_altitude_feet_message_mosquitto) 
    mosquitto_client.message_callback_add( 
        water_temperature_f_topic, 
        on_water_temperature_f_message_mosquitto) 
    mosquitto_client.tls_set(ca_certs = ca_certificate, 
        certfile=client_certificate, 
        keyfile=client_key) 
    mosquitto_client.connect(host=mqtt_server_host, 
        port=mqtt_server_port, 
        keepalive=mqtt_keepalive) 
    mosquitto_client.loop_start() 
    try: 
        while True: 
            if Surfboard.active_instance.is_pubnub_connected: 
                payload = Surfboard.active_instance.build_json_message() 
                result = pubnub_client.publish(topic=pubnub_topic, 
                    payload=payload, 
                    qos=0) 
                print("Publishing: {}".format(payload)) 
            else: 
                print("Not connected") 
            time.sleep(1) 
    except KeyboardInterrupt: 
        print("I'll disconnect from both Mosquitto and PubNub") 
        pubnub_client.disconnect() 
        pubnub_client.loop_stop() 
        mosquitto_client.disconnect() 
        mosquitto_client.loop_stop() 
```

首先，主要块创建了`Surfboard`类的实例，并将其保存在`surfboard`本地变量中。 然后，代码生成了与 PubNub MQTT 接口建立连接所需的客户端 ID 字符串，并将其保存在`pubnub_client_id`本地变量中。 PubNub MQTT 接口要求我们使用以下组成的客户端 ID：

```py
publish_key/subscribe_key/device_id 
```

代码使用`pubnub_publish_key`，`pubnub_subscribe_key`和`device_id`变量的值构建了一个符合 PubNub MQTT 接口要求的客户端 ID。 然后，代码创建了一个名为`pubnub_client`的`mqtt.Client`类（`paho.mqtt.client.Client`）的实例，该实例表示 PubNub MQTT 接口客户端。 我们使用此实例与 PubNub MQTT 服务器进行通信。

然后，代码将函数分配给属性。 以下表总结了这些分配：

| **属性** | **分配的函数** |
| --- | --- |
| `pubnub_client.on_connect` | `on_connect_pubnub` |
| `pubnub_client.on_disconnect` | `on_disconnect_pubnub` |

然后，代码调用`pubnub_client.connect`方法，并指定`host`，`port`和`keepalive`参数的值。 这样，代码要求 MQTT 客户端与指定的 PubNub MQTT 服务器建立连接。 调用`pubnub_client.connect`方法后，代码调用`pubnub_client.loop_start`方法。 此方法启动一个处理与 PubNub MQTT 接口相关的 MQTT 网络流量的新线程，并释放主线程。

然后，主要块创建了`mqtt.Client`类（`paho.mqtt.client.Client`）的另一个实例`mosquitto_client`，代表 Mosquitto MQTT 服务器客户端。我们使用此实例与本地 Mosquitto MQTT 服务器进行通信。

然后，代码将函数分配给属性。以下表总结了这些分配：

| **属性** | **分配的函数** |
| --- | --- |
| `mosquitto_client.on_connect` | `on_connect_mosquitto` |
| `mosquitto_client.on_subscribe` | `on_subscribe_mosquitto` |

请注意，在这种情况下，代码没有将函数分配给`mosquitto_client.on_message`。接下来的行调用`mosquitto_client.message_callback_add`方法，以指定客户端在特定主题接收到消息时必须调用的回调函数。以下表总结了根据定义消息到达的主题的变量调用的函数：

| **主题变量** | **分配的函数** |
| --- | --- |
| `status_topic` | `on_status_message_mosquitto` |
| `speed_mph_topic` | `on_speed_mph_message_mosquitto` |
| `altitude_feet_topic` | `on_altitude_feet_message_mosquitto` |
| `water_temperature_f_topic` | `on_water_temperature_f_message_mosquitto` |

每当客户端从任何传感器接收到消息时，它将更新`Surfboard`活动实例的适当属性。这些分配的函数负责更新`Surfboard`活动实例的状态。

然后，代码调用了众所周知的`mosquitto_client.tls_set`和`mosquitto_client.connect`方法。这样，代码要求 MQTT 客户端与指定的 Mosquitto MQTT 服务器建立连接。调用`mosquitto_client.connect`方法后，代码调用`mosquitto_client.loop_start`方法。此方法启动一个处理与 Mosquitto MQTT 服务器相关的 MQTT 网络流量的新线程，并释放主线程。

请注意，我们对`loop_start`进行了两次调用，因此我们将有两个线程处理 MQTT 网络流量：一个用于 PubNub MQTT 服务器，另一个用于 Mosquitto MQTT 服务器。

接下来的行声明了一个`while`循环，该循环将一直运行，直到发生`KeyboardInterrupt`异常。循环检查`Surfboard.active_instance.is_pubnub_connected`属性的值，以确保与 PubNub MQTT 服务器的连接没有中断。如果连接是活动的，代码将调用`Surfboard.active_instance.build_json_message`方法，根据`Surfboard`属性的当前值构建 JSON 字符串，这些值在传感器传来具有新值的消息时被更新。

代码将 JSON 字符串保存在`payload`本地变量中，并调用`pubnub_client.publish`方法将`payload` JSON 格式的字符串发布到`pubnub_topic`变量中保存的主题名称，QoS 级别为 0。这样，负责处理 PubNub MQTT 客户端的 MQTT 网络事件的线程将发布消息，并使用 PubNub MQTT 服务器作为数据源的基于 Web 的仪表板将被更新。下一行打印了正在发布到 PubNub MQTT 服务器的负载的消息。

# 运行多个客户端

现在，我们将运行最近编写的冲浪板传感器模拟器和冲浪板监视器。确保在运行这些 Python 程序之前，您已经按照必要的步骤激活了我们一直在其中工作的虚拟环境。

在任何您想要用作冲浪板传感器模拟器并使用 Linux 或 macOS 的 MQTT 客户端的计算机或设备上执行以下行以启动冲浪板传感器模拟器示例：

```py
    python3 surfboard_sensors_emulator.py  
```

在 Windows 中，您必须执行以下行：

```py
    python surfboard_sensors_emulator.py
```

几秒钟后，您将看到下面显示的输出：

```py
 Result from connect: Connection Accepted.
    surfboards/surfboard01/status: 0
    surfboards/surfboard01/speedmph: 1.0
    surfboards/surfboard01/altitudefeet: 2.0
    surfboards/surfboard01/temperaturef: 58.0
    surfboards/surfboard01/status: 0
    surfboards/surfboard01/speedmph: 1.1
    surfboards/surfboard01/altitudefeet: 2.0
    surfboards/surfboard01/temperaturef: 58.0
    surfboards/surfboard01/status: 1
    surfboards/surfboard01/speedmph: 2.0
    surfboards/surfboard01/altitudefeet: 3.0
    surfboards/surfboard01/temperaturef: 57.0
```

程序将继续为主题发布消息到 Mosquitto MQTT 服务器。保持代码在您的本地计算机上运行，或者在您选择用作本示例冲浪板传感器模拟器的物联网板上运行。

然后，在任何您想要用作 MQTT 客户端的计算机或设备上执行以下命令，该客户端接收来自 Mosquitto MQTT 服务器的消息并发布消息到 PubNub MQTT 服务器，并使用 Linux 或 macOS：

```py
    python3 surfboard_monitor.py  
```

在 Windows 中，您必须执行以下命令：

```py
    python surfboard_monitor.py
```

几秒钟后，您将看到类似下面几行的消息输出。请注意，值将不同，因为您开始运行程序的时间将使值变化：

```py
    Not connected
    Result from Mosquitto connect: Connection Accepted.
    I've subscribed with QoS: 0
    Result from PubNub connect: Connection Accepted.
    Message received. Topic: surfboards/surfboard01/status. Payload: 
    b'3'
    Message received. Topic: surfboards/surfboard01/speedmph. Payload: 
    b'0.0'
    Message received. Topic: surfboards/surfboard01/altitudefeet. 
    Payload: b'3.0'
    Message received. Topic: surfboards/surfboard01/temperaturef. 
    Payload: b'55.0'
    Publishing: {"Status": "Ride finished", "Speed MPH": 0.0, "Altitude 
    Feet": 3.0, "Water Temperature F": 55.0}
    Message received. Topic: surfboards/surfboard01/status. Payload: 
    b'0'
    Message received. Topic: surfboards/surfboard01/speedmph. Payload: 
    b'1.0'
    Message received. Topic: surfboards/surfboard01/altitudefeet. 
    Payload: b'2.0'
    Message received. Topic: surfboards/surfboard01/temperaturef. 
    Payload: b'58.0'
    Publishing: {"Status": "Idle", "Speed MPH": 1.0, "Altitude Feet": 
    2.0, "Water Temperature F": 58.0}
    Message received. Topic: surfboards/surfboard01/status. Payload: 
    b'0'
    Message received. Topic: surfboards/surfboard01/speedmph. Payload: 
    b'1.1'
    Message received. Topic: surfboards/surfboard01/altitudefeet. 
    Payload: b'2.0'
    Message received. Topic: surfboards/surfboard01/temperaturef. 
    Payload: b'58.0'
    Publishing: {"Status": "Idle", "Speed MPH": 1.1, "Altitude Feet": 
    2.0, "Water Temperature F": 58.0}

```

程序将继续接收来自冲浪板传感器模拟器的消息，并将消息发布到 PubNub MQTT 服务器。保持代码在您的本地计算机上运行，或者在您选择用作本示例冲浪板监视器的物联网板上运行。

下面的屏幕截图显示了在 macOS 计算机上运行的两个终端窗口。左侧的终端显示了作为冲浪板传感器模拟器的 Python 客户端显示的消息，即`surfboard_sensors_emulator.py`脚本。右侧的终端显示了作为冲浪板监视器的 Python 客户端运行代码的结果，即`surfboard_monitor.py`脚本：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-mqtt-prog-py/img/611ee552-ee5c-42ed-8915-edf10b548519.png)

# 使用 freeboard 构建基于网络的仪表板

现在，我们准备使用 PubNub MQTT 服务器作为数据源来构建实时的基于网络的仪表板。如前所述，我们将利用 freeboard.io 来在许多表盘中可视化冲浪者和冲浪板的数据。

freeboard.io 要求我们注册并创建一个带有有效电子邮件和密码的账户，然后我们才能构建基于网络的仪表板。我们不需要输入任何信用卡或付款信息。如果您已经在 freeboard.io 上有账户，可以跳过下一步。

在您的网络浏览器中转到[`freeboard.io`](http://freeboard.io)，然后点击立即开始。您也可以直接转到[`freeboard.io/signup`](https://freeboard.io/signup)。在选择用户名中输入您想要的用户名，在输入您的电子邮件中输入您的电子邮件，在创建密码中输入所需的密码。填写完所有字段后，点击创建我的账户。

创建完账户后，您可以在您的网络浏览器中转到[`freeboard.io`](http://freeboard.io)，然后点击登录。您也可以通过访问[`freeboard.io/login`](https://freeboard.io/login)来实现相同的目标。然后，输入您的用户名或电子邮件和密码，然后点击登录。freeboard 将显示您的 freeboard，也称为仪表板。

在创建新按钮的左侧的输入名称文本框中输入`Surfboard01`，然后单击此按钮。freeboard.io 将显示一个空的仪表板，其中有许多按钮，可以让我们添加窗格和数据源等。下面的屏幕截图显示了空的仪表板：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-mqtt-prog-py/img/d7089651-6c62-4937-830d-7ecb05c946ba.png)

点击数据源下方的添加，网站将打开数据源对话框。在类型下拉菜单中选择 PubNub，对话框将显示定义 PubNub 数据源所需的字段。

请注意，也可以使用 MQTT 作为 freeboard.io 的数据源。但是，这将要求我们将我们的 Mosquitto MQTT 服务器公开可用。相反，我们利用 PubNub MQTT 接口，它允许我们轻松地在 PubNub 网络上提供消息。但是，在需要 freeboard.io 提供所需功能的项目中，您绝对可以使用 MQTT 服务器作为数据源来工作。

在名称中输入`surfboard01`。

输入你从 PubNub 设置中复制的订阅密钥。请记住，订阅密钥通常以`sub-c`前缀开头。

在频道中输入`surfboard01`。

如果之前的任何数值名称错误，数据源将无法获得适当的数据。下面的截图显示了 PubNub 数据源的配置，订阅仅显示`sub-c`前缀：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-mqtt-prog-py/img/57fab197-993c-4ad3-b989-ef126e8dd77e.png)

点击保存，数据源将显示在数据源下方。由于冲浪板传感器模拟器和冲浪板监视器正在运行，所以下方的“最后更新”时间将每秒变化一次。如果时间没有每秒变化，这意味着数据源配置错误，或者 Python 程序中的任何一个未按预期运行。

点击“添加窗格”以在仪表板上添加一个新的空窗格。然后，点击新空窗格右上角的加号（+），freeboard 将显示小部件对话框。

在类型下拉菜单中选择文本，并且对话框将显示添加文本小部件到仪表板窗格所需的字段。在标题中输入`Status`。

在值文本框的右侧点击+数据源，选择 surfboard01，然后选择状态。做出选择后，值文本框中将出现以下文本：`datasources ["surfboard01"] ["Status"]`，如下一截图所示：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-mqtt-prog-py/img/4d75a58e-0dbd-4025-ae1d-eba3a29f2c02.png)

然后，点击保存，freeboard 将关闭对话框，并将新的仪表添加到仪表板中之前创建的窗格中。表盘将显示冲浪板监视器最后一次发布到 PubNub MQTT 接口的状态的最新数值，即代码上次发布的 JSON 数据中`Status`键的数值。下面的截图显示了 surfboard01 数据源显示的最后更新时间，以及仪表显示了状态的最新数值。

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-mqtt-prog-py/img/f0a8e9fe-1230-4721-b40d-ef49df3aa008.png)

点击“添加窗格”以在仪表板上添加另一个新的空窗格。然后，点击新空窗格右上角的加号（+），freeboard 将显示小部件对话框。

在类型下拉菜单中选择仪表，并且对话框将显示添加仪表小部件到仪表板窗格所需的字段。在标题中输入`Speed`。

在值文本框的右侧点击+数据源，选择 surfboard01，然后选择速度 MPH。做出选择后，值文本框中将出现以下文本：`datasources ["surfboard01"] ["Speed MPH"]`。

在单位中输入`MPH`，最小值为`0`，最大值为`40`。然后，点击保存，freeboard 将关闭对话框，并将新的表盘添加到仪表板上之前创建的窗格中。表盘将显示冲浪板监视器最后一次发布到 PubNub MQTT 接口的速度的最新数值，即代码上次发布的 JSON 数据中`Speed MPH`键的数值。

下面的截图显示了 surfboard01 数据源显示的最后更新时间，以及添加的仪表显示了 mph 速度的最新数值。

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-mqtt-prog-py/img/cacc5fe5-54e2-4cb2-8277-5692d568dd92.png)

点击“添加窗格”以在仪表板上添加另一个新的空窗格。然后，点击新空窗格右上角的加号（+），freeboard 将显示小部件对话框。

在类型下拉菜单中选择仪表，并且对话框将显示添加仪表小部件到仪表板窗格所需的字段。在标题中输入`Altitude`。

在值文本框的右侧点击+数据源，选择 surfboard01，然后选择海拔英尺。做出选择后，值文本框中将出现以下文本：`datasources ["surfboard01"] ["Altitude Feet"]`。

在单位中输入“英尺”，在最小值中输入`0`，在最大值中输入`30`。然后，单击“保存”，freeboard 将关闭对话框，并将新的仪表添加到仪表板上以前创建的窗格中。仪表将显示冲浪板监视器最后一次发布到 PubNub MQTT 接口的海拔值，即代码为`Altitude Feet`键发布的 JSON 数据的最新值。

现在，我们将添加最后一个窗格。单击“添加窗格”以在仪表板上添加另一个新的空窗格。然后，单击新空窗格右上角的加号（+），freeboard 将显示小部件对话框。

在类型下拉菜单中选择仪表，对话框将显示添加仪表小部件到仪表板上的窗格所需的字段。在标题中输入“水温”。

在值文本框的右侧点击+数据源，选择 surfboard01，然后选择 Water Temperature F。在进行选择后，值文本框中将显示以下文本：`datasources ["surfboard01"] ["Water Temperature F"]`。

在单位中输入“ºF”，在最小值中输入`0`，在最大值中输入`80`。然后，单击“保存”，freeboard 将关闭对话框，并将新的仪表添加到仪表板上以前创建的窗格中。仪表将显示冲浪板监视器最后一次发布到 PubNub MQTT 接口的水温，即代码为`Water Temperature F`键发布的 JSON 数据的最新值。

拖放窗格以找到布局中显示的窗格。屏幕截图显示了我们使用四个窗格和三个仪表构建的仪表板，当我们的冲浪板监视器向 PubNub MQTT 接口发布数据时，这些仪表会每秒自动刷新数据。

我们可以通过输入 Web 浏览器在我们使用仪表板时显示的 URL 来访问最近构建的仪表板。该 URL 由`https://freeboard.io/board/`前缀后跟字母和数字组成。例如，如果 URL 是`https://freeboard.io/board/EXAMPLE`，我们只需在任何连接到互联网的设备或计算机上的任何 Web 浏览器中输入它，我们就可以观看仪表，并且当新数据从我们的冲浪板监视器发布时，它们将被刷新。

将 PubNub 作为我们的数据源，将 freeboard.io 作为我们的基于 Web 的仪表板，使我们能够轻松监视从冲浪者潜水服和冲浪板传感器检索的数据。我们可以在任何提供 Web 浏览器的设备上监视数据。这两个基于云的 IoT 服务的组合只是我们如何可以轻松地将不同的服务与 MQTT 结合在我们的解决方案中的一个例子。

# 测试你的知识

让我们看看你是否能正确回答以下问题：

1.  PubNub MQTT 接口要求我们使用以下格式组成的客户端 ID：

1.  `publish_key/subscribe_key/device_id`

1.  `device_id/publish_key/subscribe_key`

1.  `publish_key/device_id`

1.  当我们向 PubNub MQTT 接口发布消息时：

1.  它仅在 PubNub MQTT 子网络上可用

1.  它在 PubNub 网络上可用

1.  需要特定的有效负载前缀才能在 PubNub 网络上使用

1.  以下`paho.mqtt.client.Client`实例的哪种方法允许我们指定客户端在特定主题接收消息时必须调用的回调函数：

1.  `message_callback_add`

1.  `message_arrived_to_topic_callback`

1.  `message_on_topic`

# 摘要

在本章中，我们将前几章学到的知识结合起来，使用 freeboard 构建了一个基于 Web 的仪表板，每秒显示仪表中的数据。我们从头开始构建了解决方案。首先，我们分析了要求，了解了嵌入在冲浪板中的 IoT 板将如何为我们提供必要的数据。

我们编写了一个冲浪板传感器模拟器，以与物联网板相同的方式工作。然后，我们配置了 PubNub MQTT 接口，并编写了一个冲浪板监视器，收集来自冲浪板传感器模拟器的数据，并将数据发布到基于云的 PubNub MQTT 接口。我们编写了一个 Python 程序，与两个 MQTT 客户端一起使用两个线程循环接口。

最后，我们可以利用这样一个事实：发布到 PubNub MQTT 接口的消息也可以在 PubNub 网络上轻松构建一个基于 web 的仪表板，使用 freeboard。

我们能够创建能够在最流行和强大的物联网板上运行的代码。我们准备在各种项目中使用 MQTT，使用最流行和多功能的编程语言之一：Python 3。
