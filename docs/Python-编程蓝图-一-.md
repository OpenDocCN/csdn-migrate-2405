# Python 编程蓝图（一）

> 原文：[`zh.annas-archive.org/md5/86404db5905a76ae5db4e50dd816784e`](https://zh.annas-archive.org/md5/86404db5905a76ae5db4e50dd816784e)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

如果你在过去 20 年里一直在软件开发行业中，那么你肯定听说过一种名为 Python 的编程语言。Python 由 Guido van Rossum 创建，于 1991 年首次亮相，并自那时起就一直受到全球许多软件开发人员的喜爱。

然而，一个已经有 20 多年历史的语言为何仍然存在，并且每天都在变得越来越受欢迎呢？

嗯，这个问题的答案很简单。Python 对于一切（或几乎一切）都很棒。Python 是一种通用编程语言，这意味着你可以创建简单的终端应用程序、Web 应用程序、微服务、游戏，以及复杂的科学应用程序。尽管可以用 Python 来实现不同的目的，但 Python 是一种以易学著称的语言，非常适合初学者以及没有计算机科学背景的人。

Python 是一种“电池包含”的编程语言，这意味着大多数时候在开发项目时你不需要使用任何外部依赖。Python 的标准库功能丰富，大多数时候包含了你创建程序所需的一切，而且即使你需要标准库中没有的东西，PyPI（Python 包索引）目前也包含了 117,652 个包。

Python 社区是一个欢迎、乐于助人、多元化且对这门语言非常热情的社区，社区中的每个人都乐意互相帮助。

如果你还不相信，知名网站 StackOverflow 发布了今年关于编程语言受欢迎程度的统计数据，基于用户在网站上提出的问题数量，Python 是排名前列的语言，仅次于 JavaScript、Java、C#和 PHP。

现在是成为 Python 开发者的完美时机，所以让我们开始吧！

# 本书适合对象

这本书适用于熟悉 Python 并希望通过网络和软件开发项目获得实践经验的软件开发人员。需要有 Python 编程的基础知识。

# 本书内容包括

第一章，*实现天气应用程序*，将指导你开发一个终端应用程序，显示特定地区的当前天气和未来 5 天的预报。本章将介绍 Python 编程的基本概念。你将学习如何解析命令行参数以增加程序的交互性，并最终学会如何使用流行的 Beautiful Soup 框架从网站上抓取数据。

第二章，*使用 Spotify 创建远程控制应用程序*，将教你如何使用 OAuth 对 Spotify API 进行身份验证。我们将使用 curses 库使应用程序更有趣和用户友好。

第三章，*在 Twitter 上投票*，将教你如何使用 Tkinter 库使用 Python 创建美观的用户界面。我们将使用 Python 的 Reactive Extensions 来检测后端的投票情况，然后在用户界面中发布更改。

第四章，*汇率和货币转换工具*，将使你能够实现一个货币转换器，它将实时从不同来源获取外汇汇率，并使用数据进行货币转换。我们将开发一个包含辅助函数来执行转换的 API。首先，我们将使用开源外汇汇率和货币转换 API（[`fixer.io/`](http://fixer.io/)）。

本章的第二部分将教你如何创建一个命令行应用程序，利用我们的 API 从数据源获取数据，并使用一些参数获取货币转换结果。

第五章《使用微服务构建 Web Messenger》将教您如何使用 Nameko，这是 Python 的微服务框架。您还将学习如何为外部资源（如 Redis）创建依赖项提供程序。本章还将涉及对 Nameko 服务进行集成测试以及对 API 的基本 AJAX 请求。

第六章《使用用户认证微服务扩展 TempMessenger》将在第五章《使用微服务构建 Web Messenger》的基础上构建您的应用程序。您将创建一个用户认证微服务，将用户存储在 Postgres 数据库中。使用 Bcrypt，您还将学习如何安全地将密码存储在数据库中。本章还涵盖了创建 Flask Web 界面以及如何利用 cookie 存储 Web 会话数据。通过这些章节的学习，您将能够创建可扩展和协调的微服务。

第七章《使用 Django 创建在线视频游戏商店》将使您能够创建一个在线视频游戏商店。它将包含浏览不同类别的视频游戏、使用不同标准进行搜索、查看每个游戏的详细信息，最后将游戏添加到购物车并下订单等功能。在这里，您将学习 Django 2.0、管理 UI、Django 数据模型等内容。

第八章《订单微服务》将帮助您构建一个负责接收来自我们在上一章中开发的 Web 应用程序的订单的微服务。订单微服务还提供其他功能，如更新订单状态和使用不同标准提供订单信息。

第九章《通知无服务器应用》将教您有关无服务器函数架构以及如何使用 Flask 构建通知服务，并使用伟大的项目 Zappa 将最终应用部署到 AWS Lambda。您还将学习如何将在第七章《使用 Django 创建在线视频游戏商店》中开发的 Web 应用程序和在第八章《订单微服务》中开发的订单微服务与无服务器通知应用集成。

# 为了充分利用本书

为了在本地计算机上执行本书中的代码，您需要以下内容：

+   互联网连接

+   Virtualenv

+   Python 3.6

+   MongoDB 3.2.11

+   pgAdmin（参考官方文档[`url.marcuspen.com/pgadmin`](http://url.marcuspen.com/pgadmin)进行安装）

+   Docker（参考官方文档[`url.marcuspen.com/docker-install`](http://url.marcuspen.com/docker-install)进行安装）

随着我们逐步学习，所有其他要求都将被安装。

本章中的所有说明都针对 macOS 或 Debian/Ubuntu 系统；但是，作者已经注意只使用跨平台依赖项。

# 下载示例代码文件

您可以从[www.packtpub.com](http://www.packtpub.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了本书，您可以访问[www.packtpub.com/support](http://www.packtpub.com/support)并注册，以便直接通过电子邮件接收文件。

您可以按照以下步骤下载代码文件：

1.  登录或注册[www.packtpub.com](http://www.packtpub.com/support)。

1.  选择“SUPPORT”选项卡。

1.  单击“代码下载和勘误”。

1.  在搜索框中输入书名并按照屏幕上的说明进行操作。

下载文件后，请确保使用以下最新版本解压或提取文件夹：

+   Windows 的 WinRAR/7-Zip

+   Mac 的 Zipeg/iZip/UnRarX

+   7-Zip/PeaZip for Linux

本书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Python-Programming-Blueprints`](https://github.com/PacktPublishing/Python-Programming-Blueprints)。我们还有来自丰富书籍和视频目录的其他代码包，可在**[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)**上找到。去看看吧！

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。这是一个例子：“这个方法将调用`Runner`的`exec`方法来执行执行请求 Twitter API 的函数。”

代码块设置如下：

```py
def set_header(self):
    title = Label(self,
                  text='Voting for hasthags',
                  font=("Helvetica", 24),
                  height=4)
    title.pack()
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```py
def start_app(args):
    root = Tk()
    app = Application(hashtags=args.hashtags, master=root)
    app.master.title("Twitter votes")
    app.master.geometry("400x700+100+100")
    app.mainloop()
```

任何命令行输入或输出都以以下方式编写：

```py
python app.py --hashtags debian ubuntu arch
```

**粗体**：表示新术语、重要单词或屏幕上看到的单词。例如，菜单或对话框中的单词会以这种方式出现在文本中。这是一个例子：“它说，以您的用户名登录，然后在其后有一个注销链接。试一试，点击链接注销。”

警告或重要说明会显示为这样。提示和技巧会显示为这样。


# 第一章：实现天气应用程序

本书中的第一个应用程序将是一个网络爬虫应用程序，它将从[`weather.com`](https://weather.com)爬取天气预报信息并在终端中呈现。我们将添加一些选项，可以将其作为应用程序的参数传递，例如：

+   温度单位（摄氏度或华氏度）

+   您可以获取天气预报的地区

+   用户可以在我们的应用程序中选择当前预报、五天预报、十天预报和周末的输出选项

+   补充输出的方式，例如风和湿度等额外信息

除了上述参数之外，此应用程序将被设计为可扩展的，这意味着我们可以为不同的网站创建解析器来获取天气预报，并且这些解析器将作为参数选项可用。

在本章中，您将学习如何：

+   在 Python 应用程序中使用面向对象编程概念

+   使用`BeautifulSoup`包从网站上爬取数据

+   接收命令行参数

+   利用`inspect`模块

+   动态加载 Python 模块

+   使用 Python 推导

+   使用`Selenium`请求网页并检查其 DOM 元素

在开始之前，重要的是要说，当开发网络爬虫应用程序时，您应该牢记这些类型的应用程序容易受到更改的影响。如果您从中获取数据的网站的开发人员更改了 CSS 类名或 HTML DOM 的结构，应用程序将停止工作。此外，如果我们获取数据的网站的 URL 更改，应用程序将无法发送请求。

# 设置环境

在我们开始编写第一个示例之前，我们需要设置一个环境来工作并安装项目可能具有的任何依赖项。幸运的是，Python 有一个非常好的工具系统来处理虚拟环境。

Python 中的虚拟环境是一个广泛的主题，超出了本书的范围。但是，如果您不熟悉虚拟环境，知道虚拟环境是一个与全局 Python 安装隔离的 Python 环境即可。这种隔离允许开发人员轻松地使用不同版本的 Python，在环境中安装软件包，并管理项目依赖项，而不会干扰 Python 的全局安装。

Python 的安装包含一个名为`venv`的模块，您可以使用它来创建虚拟环境；语法非常简单。我们将要创建的应用程序称为`weatherterm`（天气终端），因此我们可以创建一个同名的虚拟环境，以使其简单。

要创建一个新的虚拟环境，请打开终端并运行以下命令：

```py
$ python3 -m venv weatherterm
```

如果一切顺利，您应该在当前目录中看到一个名为`weatherterm`的目录。现在我们有了虚拟环境，我们只需要使用以下命令激活它：

```py
$ . weatherterm/bin/activate
```

我建议安装并使用`virtualenvwrapper`，这是`virtualenv`工具的扩展。这使得管理、创建和删除虚拟环境以及快速在它们之间切换变得非常简单。如果您希望进一步了解，请访问：[`virtualenvwrapper.readthedocs.io/en/latest/#`](https://virtualenvwrapper.readthedocs.io/en/latest/#)。

现在，我们需要创建一个目录，我们将在其中创建我们的应用程序。不要在创建虚拟环境的同一目录中创建此目录；相反，创建一个项目目录，并在其中创建应用程序目录。我建议您简单地使用与虚拟环境相同的名称命名它。

我正在设置环境并在安装了 Debian 9.2 的机器上运行所有示例，并且在撰写本文时，我正在运行最新的 Python 版本（3.6.2）。如果您是 Mac 用户，情况可能不会有太大差异；但是，如果您使用 Windows，步骤可能略有不同，但是很容易找到有关如何在其中设置虚拟环境的信息。现在，Windows 上的 Python 3 安装效果很好。

进入刚创建的项目目录并创建一个名为`requirements.txt`的文件，内容如下：

```py
beautifulsoup4==4.6.0
selenium==3.6.0
```

这些都是我们这个项目所需的所有依赖项：

+   `BeautifulSoup`**：**这是一个用于解析 HTML 和 XML 文件的包。我们将使用它来解析从天气网站获取的 HTML，并在终端上获取所需的天气数据。它非常简单易用，并且有在线上有很好的文档：[`beautiful-soup-4.readthedocs.io/en/latest/`](http://beautiful-soup-4.readthedocs.io/en/latest/)。

+   `selenium`**：**这是一个用于测试的知名工具集。有许多应用程序，但它主要用于自动测试 Web 应用程序。

要在我们的虚拟环境中安装所需的软件包，可以运行以下命令：

```py
pip install -r requirements.txt
```

始终使用 GIT 或 Mercurial 等版本控制工具是一个好主意。它非常有助于控制更改，检查历史记录，回滚更改等。如果您对这些工具不熟悉，互联网上有很多教程。您可以通过查看 GIT 的文档来开始：[`git-scm.com/book/en/v1/Getting-Started`](https://git-scm.com/book/en/v1/Getting-Started)。

我们需要安装的最后一个工具是 PhantomJS；您可以从以下网址下载：[`phantomjs.org/download.html`](http://phantomjs.org/download.html)

下载后，提取`weatherterm`目录中的内容，并将文件夹重命名为`phantomjs`。

在设置好我们的虚拟环境并安装了 PhantomJS 后，我们准备开始编码！

# 核心功能

首先，创建一个模块的目录。在项目的根目录内，创建一个名为`weatherterm`的子目录。`weatherterm`子目录是我们模块的所在地。模块目录需要两个子目录-`core`和`parsers`。项目的目录结构应该如下所示：

```py
weatherterm
├── phantomjs
└── weatherterm
    ├── core
    ├── parsers   
```

# 动态加载解析器

这个应用程序旨在灵活，并允许开发人员为不同的天气网站创建不同的解析器。我们将创建一个解析器加载器，它将动态发现`parsers`目录中的文件，加载它们，并使它们可供应用程序使用，而无需更改代码的其他部分。在实现新解析器时，我们的加载器将需要遵循以下规则：

+   创建一个实现获取当前天气预报以及五天、十天和周末天气预报方法的类文件

+   文件名必须以`parser`结尾，例如`weather_com_parser.py`

+   文件名不能以双下划线开头

说到这里，让我们继续创建解析器加载器。在`weatherterm/core`目录中创建一个名为`parser_loader.py`的文件，并添加以下内容：

```py
import os
import re
import inspect

def _get_parser_list(dirname):
    files = [f.replace('.py', '')
             for f in os.listdir(dirname)
             if not f.startswith('__')]

    return files

def _import_parsers(parserfiles):

    m = re.compile('.+parser$', re.I)

    _modules = __import__('weatherterm.parsers',
                          globals(),
                          locals(),
                          parserfiles,
                          0)

    _parsers = [(k, v) for k, v in inspect.getmembers(_modules)
                if inspect.ismodule(v) and m.match(k)]

    _classes = dict()

    for k, v in _parsers:
        _classes.update({k: v for k, v in inspect.getmembers(v)
                         if inspect.isclass(v) and m.match(k)})

    return _classes

def load(dirname):
    parserfiles = _get_parser_list(dirname)
    return _import_parsers(parserfiles)
```

首先，执行`_get_parser_list`函数并返回位于`weatherterm/parsers`中的所有文件的列表；它将根据先前描述的解析器规则过滤文件。返回文件列表后，就可以导入模块了。这是由`_import_parsers`函数完成的，它首先导入`weatherterm.parsers`模块，并利用标准库中的 inspect 包来查找模块中的解析器类。

`inspect.getmembers`函数返回一个元组列表，其中第一项是表示模块中的属性的键，第二项是值，可以是任何类型。在我们的情况下，我们对以`parser`结尾的键和类型为类的值感兴趣。

假设我们已经在`weatherterm/parsers`目录中放置了一个解析器，`inspect.getmembers(_modules)`返回的值将看起来像这样：

```py
[('WeatherComParser',
  <class 'weatherterm.parsers.weather_com_parser.WeatherComParser'>),
  ...]
```

`inspect.getmembers(_module)`返回了更多的项目，但它们已被省略，因为在这一点上展示它们并不相关。

最后，我们循环遍历模块中的项目，并提取解析器类，返回一个包含类名和稍后用于创建解析器实例的类对象的字典。

# 创建应用程序的模型

让我们开始创建将代表我们的应用程序从天气网站上爬取的所有信息的模型。我们要添加的第一项是一个枚举，用于表示我们应用程序的用户将提供的天气预报选项。在`weatherterm/core`目录中创建一个名为`forecast_type.py`的文件，内容如下：

```py
from enum import Enum, unique

@unique
class ForecastType(Enum):
    TODAY = 'today'
    FIVEDAYS = '5day'
    TENDAYS = '10day'
    WEEKEND = 'weekend'
```

枚举自 Python 3.4 版本以来一直存在于 Python 标准库中，可以使用创建类的语法来创建。只需创建一个从`enum.Enum`继承的类，其中包含一组设置为常量值的唯一属性。在这里，我们为应用程序提供的四种类型的预报设置了值，可以访问`ForecastType.TODAY`、`ForecastType.WEEKEND`等值。

请注意，我们正在分配与枚举的属性项不同的常量值，原因是以后这些值将用于构建请求天气网站的 URL。

应用程序需要另一个枚举来表示用户在命令行中可以选择的温度单位。这个枚举将包含摄氏度和华氏度项目。

首先，让我们包含一个基本枚举。在`weatherterm/core`目录中创建一个名为`base_enum.py`的文件，内容如下：

```py
from enum import Enum

class BaseEnum(Enum):
    def _generate_next_value_(name, start, count, last_value):
        return name
```

`BaseEnum`是一个非常简单的类，继承自`Enum`。我们在这里想要做的唯一一件事是覆盖`_generate_next_value_`方法，以便从`BaseEnum`继承的每个枚举和具有值设置为`auto()`的属性将自动获得与属性名称相同的值。

现在，我们可以为温度单位创建一个枚举。在`weatherterm/core`目录中创建一个名为`unit.py`的文件，内容如下：

```py
from enum import auto, unique

from .base_enum import BaseEnum

@unique
class Unit(BaseEnum):
    CELSIUS = auto()
    FAHRENHEIT = auto()
```

这个类继承自我们刚刚创建的`BaseEnum`，每个属性都设置为`auto()`，这意味着枚举中每个项目的值将自动设置。由于`Unit`类继承自`BaseEnum`，每次调用`auto()`时，`BaseEnum`上的`_generate_next_value_`方法将被调用，并返回属性本身的名称。

在我们尝试这个之前，让我们在`weatherterm/core`目录中创建一个名为`__init__.py`的文件，并导入我们刚刚创建的枚举，如下所示：

```py
from .unit import Unit
```

如果我们在 Python REPL 中加载这个类并检查值，将会发生以下情况：

```py
Python 3.6.2 (default, Sep 11 2017, 22:31:28) 
[GCC 6.3.0 20170516] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> from weatherterm.core import Unit
>>> [value for key, value in Unit.__members__.items()]
[<Unit.CELSIUS: 'CELSIUS'>, <Unit.FAHRENHEIT: 'FAHRENHEIT'>]
```

我们还想要添加到我们应用程序的核心模块的另一项内容是一个类，用于表示解析器返回的天气预报数据。让我们继续在`weatherterm/core`目录中创建一个名为`forecast.py`的文件，内容如下：

```py
from datetime import date

from .forecast_type import ForecastType

class Forecast:
    def __init__(
            self,
            current_temp,
            humidity,
            wind,
            high_temp=None,
            low_temp=None,
            description='',
            forecast_date=None,
            forecast_type=ForecastType.TODAY):
        self._current_temp = current_temp
        self._high_temp = high_temp
        self._low_temp = low_temp
        self._humidity = humidity
        self._wind = wind
        self._description = description
        self._forecast_type = forecast_type

        if forecast_date is None:
            self.forecast_date = date.today()
        else:
            self._forecast_date = forecast_date

    @property
    def forecast_date(self):
        return self._forecast_date

    @forecast_date.setter
    def forecast_date(self, forecast_date):
        self._forecast_date = forecast_date.strftime("%a %b %d")

    @property
    def current_temp(self):
        return self._current_temp

    @property
    def humidity(self):
        return self._humidity

    @property
    def wind(self):
        return self._wind

    @property
    def description(self):
        return self._description

    def __str__(self):
        temperature = None
        offset = ' ' * 4

        if self._forecast_type == ForecastType.TODAY:
            temperature = (f'{offset}{self._current_temp}\xb0\n'
                           f'{offset}High {self._high_temp}\xb0 / '
                           f'Low {self._low_temp}\xb0 ')
        else:
            temperature = (f'{offset}High {self._high_temp}\xb0 / '
                           f'Low {self._low_temp}\xb0 ')

        return(f'>> {self.forecast_date}\n'
               f'{temperature}'
               f'({self._description})\n'
               f'{offset}Wind: '
               f'{self._wind} / Humidity: {self._humidity}\n')
```

在 Forecast 类中，我们将定义我们将要解析的所有数据的属性：

| `current_temp` | 表示当前温度。仅在获取今天的天气预报时才可用。 |
| --- | --- |
| `humidity` | 一天中的湿度百分比。 |
| `wind` | 有关今天当前风级的信息。 |
| `high_temp` | 一天中的最高温度。 |
| `low_temp` | 一天中的最低温度。 |
| `description` | 天气条件的描述，例如*部分多云*。 |
| `forecast_date` | 预测日期；如果未提供，将设置为当前日期。 |
| `forecast_type` | 枚举`ForecastType`中的任何值（`TODAY`，`FIVEDAYS`，`TENDAYS`或`WEEKEND`）。 |

我们还可以实现两个名为`forecast_date`的方法，使用`@property`和`@forecast_date.setter`装饰器。`@property`装饰器将方法转换为`Forecast`类的`_forecast_date`属性的 getter，而`@forecast_date.setter`将方法转换为 setter。之所以在这里定义 setter，是因为每次需要在`Forecast`的实例中设置日期时，我们都需要确保它将被相应地格式化。在 setter 中，我们调用`strftime`方法，传递格式代码`%a`（缩写的星期几名称），`%b`（缩写的月份名称）和`%d`（月份的第几天）。

格式代码`%a`和`%b`将使用在运行代码的机器上配置的区域设置。

最后，我们重写`__str__`方法，以便在使用`print`，`format`和`str`函数时以我们希望的方式格式化输出。

默认情况下，`weather.com`使用的温度单位是`华氏度`，我们希望我们的应用程序用户可以选择使用摄氏度。因此，让我们继续在`weatherterm/core`目录中创建一个名为`unit_converter.py`的文件，内容如下：

```py
from .unit import Unit

class UnitConverter:
    def __init__(self, parser_default_unit, dest_unit=None):
        self._parser_default_unit = parser_default_unit
        self.dest_unit = dest_unit

        self._convert_functions = {
            Unit.CELSIUS: self._to_celsius,
            Unit.FAHRENHEIT: self._to_fahrenheit,
        }

    @property
    def dest_unit(self):
        return self._dest_unit

    @dest_unit.setter
    def dest_unit(self, dest_unit):
        self._dest_unit = dest_unit

    def convert(self, temp):

        try:
            temperature = float(temp)
        except ValueError:
            return 0

        if (self.dest_unit == self._parser_default_unit or
                self.dest_unit is None):
            return self._format_results(temperature)

        func = self._convert_functions[self.dest_unit]
        result = func(temperature)

        return self._format_results(result)

    def _format_results(self, value):
        return int(value) if value.is_integer() else f'{value:.1f}'

    def _to_celsius(self, fahrenheit_temp):
        result = (fahrenheit_temp - 32) * 5/9
        return result

    def _to_fahrenheit(self, celsius_temp):
        result = (celsius_temp * 9/5) + 32
        return result
```

这个类将负责将摄氏度转换为华氏度，反之亦然。这个类的初始化器有两个参数；解析器使用的默认单位和目标单位。在初始化器中，我们将定义一个包含用于温度单位转换的函数的字典。

`convert`方法只接受一个参数，即温度。在这里，温度是一个字符串，因此我们需要尝试将其转换为浮点值；如果失败，它将立即返回零值。

您还可以验证目标单位是否与解析器的默认单位相同。在这种情况下，我们不需要继续执行任何转换；我们只需格式化值并返回它。

如果需要执行转换，我们可以查找`_convert_functions`字典，找到需要运行的`conversion`函数。如果找到我们正在寻找的函数，我们调用它并返回格式化的值。

下面的代码片段显示了`_format_results`方法，这是一个实用方法，将为我们格式化温度值：

```py
return int(value) if value.is_integer() else f'{value:.1f}'
```

`_format_results`方法检查数字是否为整数；如果`value.is_integer()`返回`True`，则表示数字是整数，例如 10.0。如果为`True`，我们将使用`int`函数将值转换为 10；否则，该值将作为具有精度为 1 的定点数返回。Python 中的默认精度为 6。最后，有两个实用方法执行温度转换，`_to_celsius`和`_to_fahrenheit`。

现在，我们只需要编辑`weatherterm/core`目录中的`__init__.py`文件，并包含以下导入语句：

```py
from .base_enum import BaseEnum
from .unit_converter import UnitConverter
from .forecast_type import ForecastType
from .forecast import Forecast
```

# 从天气网站获取数据

我们将添加一个名为`Request`的类，负责从天气网站获取数据。让我们在`weatherterm/core`目录中添加一个名为`request.py`的文件，内容如下：

```py
import os
from selenium import webdriver

class Request:
    def __init__(self, base_url):
        self._phantomjs_path = os.path.join(os.curdir,
                                          'phantomjs/bin/phantomjs')
        self._base_url = base_url
        self._driver = webdriver.PhantomJS(self._phantomjs_path)

    def fetch_data(self, forecast, area):
        url = self._base_url.format(forecast=forecast, area=area)
        self._driver.get(url)

        if self._driver.title == '404 Not Found':
            error_message = ('Could not find the area that you '
                             'searching for')
            raise Exception(error_message)

        return self._driver.page_source
```

这个类非常简单；初始化程序定义了基本 URL 并创建了一个 PhantomJS 驱动程序，使用 PhantomJS 安装的路径。`fetch_data`方法格式化 URL，添加预测选项和区域。之后，`webdriver`执行请求并返回页面源代码。如果返回的标记标题是`404 Not Found`，它将引发异常。不幸的是，`Selenium`没有提供获取 HTTP 状态代码的正确方法；这比比较字符串要好得多。

您可能会注意到，我在一些类属性前面加了下划线符号。我通常这样做是为了表明底层属性是私有的，不应该在类外部设置。在 Python 中，没有必要这样做，因为没有办法设置私有或公共属性；但是，我喜欢这样做，因为我可以清楚地表明我的意图。

现在，我们可以在`weatherterm/core`目录中的`__init__.py`文件中导入它：

```py
from .request import Request
```

现在我们有一个解析器加载器，可以加载我们放入`weatherterm/parsers`目录中的任何解析器，我们有一个表示预测模型的类，以及一个枚举`ForecastType`，因此我们可以指定要解析的预测类型。该枚举表示温度单位和实用函数，用于将温度从`华氏度`转换为`摄氏度`和从`摄氏度`转换为`华氏度`。因此，现在，我们应该准备好创建应用程序的入口点，以接收用户传递的所有参数，运行解析器，并在终端上呈现数据。

# 使用 ArgumentParser 获取用户输入

在我们第一次运行应用程序之前，我们需要添加应用程序的入口点。入口点是在执行应用程序时将首先运行的代码。

我们希望为我们的应用程序的用户提供尽可能好的用户体验，因此我们需要添加的第一个功能是能够接收和解析命令行参数，执行参数验证，根据需要设置参数，最后但并非最不重要的是，显示一个有组织且信息丰富的帮助系统，以便用户可以查看可以使用哪些参数以及如何使用应用程序。

听起来很繁琐，对吧？

幸运的是，Python 自带了很多功能，标准库中包含一个很棒的模块，可以让我们以非常简单的方式实现这一点；该模块称为`argparse`。

另一个很好的功能是让我们的应用程序易于分发给用户。一种方法是在`weatherterm`模块目录中创建一个`__main__.py`文件，然后可以像运行常规脚本一样运行模块。Python 将自动运行`__main__.py`文件，如下所示：

```py
$ python -m weatherterm
```

另一个选项是压缩整个应用程序目录并执行 Python，传递 ZIP 文件的名称。这是一种简单、快速、简单的分发 Python 程序的方法。

还有许多其他分发程序的方法，但这超出了本书的范围；我只是想给你一些使用`__main__.py`文件的例子。

有了这个说法，让我们在`weatherterm`目录中创建一个`__main__.py`文件，内容如下：

```py
import sys
from argparse import ArgumentParser

from weatherterm.core import parser_loader
from weatherterm.core import ForecastType
from weatherterm.core import Unit

def _validate_forecast_args(args):
    if args.forecast_option is None:
        err_msg = ('One of these arguments must be used: '
                   '-td/--today, -5d/--fivedays, -10d/--tendays, -
                    w/--weekend')
        print(f'{argparser.prog}: error: {err_msg}', 
        file=sys.stderr)
        sys.exit()

parsers = parser_loader.load('./weatherterm/parsers')

argparser = ArgumentParser(
    prog='weatherterm',
    description='Weather info from weather.com on your terminal')

required = argparser.add_argument_group('required arguments')

required.add_argument('-p', '--parser',
                      choices=parsers.keys(),
                      required=True,
                      dest='parser',
                      help=('Specify which parser is going to be  
                       used to '
                            'scrape weather information.'))

unit_values = [name.title() for name, value in Unit.__members__.items()]

argparser.add_argument('-u', '--unit',
                       choices=unit_values,
                       required=False,
                       dest='unit',
                       help=('Specify the unit that will be used to 
                       display '
                             'the temperatures.'))

required.add_argument('-a', '--areacode',
                      required=True,
                      dest='area_code',
                      help=('The code area to get the weather 
                       broadcast from. '
                            'It can be obtained at 
                              https://weather.com'))

argparser.add_argument('-v', '--version',
                       action='version',
                       version='%(prog)s 1.0')

argparser.add_argument('-td', '--today',
                       dest='forecast_option',
                       action='store_const',
                       const=ForecastType.TODAY,
                       help='Show the weather forecast for the 
                       current day')

args = argparser.parse_args()

_validate_forecast_args(args)

cls = parsers[args.parser]

parser = cls()
results = parser.run(args)

for result in results:
    print(results)
```

我们的应用程序将接受的天气预报选项（今天、五天、十天和周末预报）不是必需的；但是，至少必须在命令行中提供一个选项，因此我们创建了一个名为`_validate_forecast_args`的简单函数来执行此验证。此函数将显示帮助消息并退出应用程序。

首先，我们获取`weatherterm/parsers`目录中可用的所有解析器。解析器列表将用作解析器参数的有效值。

`ArgumentParser`对象负责定义参数、解析值和显示帮助，因此我们创建一个`ArgumentParser`的实例，并创建一个必需参数的参数组。这将使帮助输出看起来更加美观和有组织。

为了使参数和帮助输出更有组织，我们将在`ArgumentParser`对象中创建一个组。此组将包含我们的应用程序需要的所有必需参数。这样，我们的应用程序的用户可以轻松地看到哪些参数是必需的，哪些是不必需的。

我们通过以下语句实现了这一点：

```py
required = argparser.add_argument_group('required arguments')
```

在为必需参数创建参数组之后，我们获取枚举`Unit`的所有成员的列表，并使用`title()`函数使只有第一个字母是大写字母。

现在，我们可以开始添加我们的应用程序能够在命令行接收的参数。大多数参数定义使用相同的一组关键字参数，因此我不会覆盖所有参数。

我们将创建的第一个参数是`--parser`或`-p`：

```py
required.add_argument('-p', '--parser',
                      choices=parsers.keys(),
                      required=True,
                      dest='parser',
                      help=('Specify which parser is going to be 
                       used to '
                            'scrape weather information.'))
```

让我们分解创建解析器标志时使用的`add_argument`的每个参数：

+   前两个参数是标志。在这种情况下，用户可以使用`-p`或`--parser`在命令行中传递值给此参数，例如`--parser WeatherComParser`。

+   `choices`参数指定我们正在创建的参数的有效值列表。在这里，我们使用`parsers.keys()`，它将返回一个解析器名称的列表。这种实现的优势是，如果我们添加一个新的解析器，它将自动添加到此列表中，而且不需要对此文件进行任何更改。

+   `required`参数，顾名思义，指定参数是否为必需的。

+   `dest`参数指定要添加到解析器参数的结果对象中的属性的名称。`parser_args()`返回的对象将包含一个名为`parser`的属性，其值是我们在命令行中传递给此参数的值。

+   最后，`help`参数是参数的帮助文本，在使用`-h`或`--help`标志时显示。

转到`--today`参数：

```py
argparser.add_argument('-td', '--today',
                       dest='forecast_option',
                       action='store_const',
                       const=ForecastType.TODAY,
                       help='Show the weather forecast for the 
                       current day')
```

这里有两个我们以前没有见过的关键字参数，`action`和`const`。

行动可以绑定到我们创建的参数，并且它们可以执行许多操作。`argparse`模块包含一组很棒的操作，但如果您需要执行特定操作，可以创建自己的操作来满足您的需求。`argparse`模块中定义的大多数操作都是将值存储在解析结果对象属性中的操作。

在前面的代码片段中，我们使用了`store_const`操作，它将一个常量值存储到`parse_args()`返回的对象中的属性中。

我们还使用了关键字参数`const`，它指定在命令行中使用标志时的常量默认值。

记住我提到过可以创建自定义操作吗？参数 unit 是自定义操作的一个很好的用例。`choices`参数只是一个字符串列表，因此我们使用此推导式获取`Unit`枚举中每个项目的名称列表，如下所示：

```py
unit_values = [name.title() for name, value in Unit.__members__.items()]

required.add_argument('-u', '--unit',
                      choices=unit_values,
                      required=False,
                      dest='unit',
                      help=('Specify the unit that will be used to 
                       display '
                            'the temperatures.'))
```

`parse_args()`返回的对象将包含一个名为 unit 的属性，其值为字符串（`Celsius`或`Fahrenheit`），但这并不是我们想要的。我们可以通过创建自定义操作来更改此行为。

首先，在`weatherterm/core`目录中添加一个名为`set_unit_action.py`的新文件，内容如下：

```py
from argparse import Action

from weatherterm.core import Unit

class SetUnitAction(Action):

    def __call__(self, parser, namespace, values,    
     option_string=None):
        unit = Unit[values.upper()]
        setattr(namespace, self.dest, unit)
```

这个操作类非常简单；它只是继承自`argparse.Action`并覆盖`__call__`方法，当解析参数值时将调用该方法。这将设置为目标属性。

`parser`参数将是`ArgumentParser`的一个实例。命名空间是`argparser.Namespace`的一个实例，它只是一个简单的类，包含`ArgumentParser`对象中定义的所有属性。如果您使用调试器检查此参数，您将看到类似于这样的东西：

```py
Namespace(area_code=None, fields=None, forecast_option=None, parser=None, unit=None)
```

`values`参数是用户在命令行上传递的值；在我们的情况下，它可以是摄氏度或华氏度。最后，`option_string`参数是为参数定义的标志。对于单位参数，`option_string`的值将是`-u`。

幸运的是，Python 中的枚举允许我们使用项目访问它们的成员和属性：

```py
Unit[values.upper()]
```

在 Python REPL 中验证这一点，我们有：

```py
>>> from weatherterm.core import Unit
>>> Unit['CELSIUS']
<Unit.CELSIUS: 'CELSIUS'>
>>> Unit['FAHRENHEIT']
<Unit.FAHRENHEIT: 'FAHRENHEIT'>
```

在获取正确的枚举成员之后，我们设置了命名空间对象中`self.dest`指定的属性的值。这样更清晰，我们不需要处理魔术字符串。

有了自定义操作，我们需要在`weatherterm/core`目录中的`__init__.py`文件中添加导入语句：

```py
from .set_unit_action import SetUnitAction
```

只需在文件末尾包含上面的行。然后，我们需要将其导入到`__main__.py`文件中，就像这样：

```py
from weatherterm.core import SetUnitAction
```

然后，我们将在单位参数的定义中添加`action`关键字参数，并将其设置为`SetUnitAction`，就像这样：

```py
required.add_argument('-u', '--unit',
                      choices=unit_values,
                      required=False,
                      action=SetUnitAction,
                      dest='unit',
                      help=('Specify the unit that will be used to 
                       display '
                            'the temperatures.'))
```

所以，当我们的应用程序的用户使用摄氏度标志`-u`时，`parse_args()`函数返回的对象的属性单位的值将是：

`<Unit.CELSIUS: 'CELSIUS'>`

代码的其余部分非常简单；我们调用`parse_args`函数来解析参数并将结果设置在`args`变量中。然后，我们使用`args.parser`的值（所选解析器的名称）并访问解析器字典中的项。请记住，值是类类型，所以我们创建解析器的实例，最后调用 run 方法，这将启动网站抓取。

# 创建解析器

为了第一次运行我们的代码，我们需要创建一个解析器。我们可以快速创建一个解析器来运行我们的代码，并检查数值是否被正确解析。

让我们继续，在`weatherterm/parsers`目录中创建一个名为`weather_com_parser.py`的文件。为了简单起见，我们只会创建必要的方法，当这些方法被调用时，我们唯一要做的就是引发`NotImplementedError`：

```py
from weatherterm.core import ForecastType

class WeatherComParser:

    def __init__(self):
        self._forecast = {
            ForecastType.TODAY: self._today_forecast,
            ForecastType.FIVEDAYS: self._five_and_ten_days_forecast,
            ForecastType.TENDAYS: self._five_and_ten_days_forecast,
            ForecastType.WEEKEND: self._weekend_forecast,
            }

    def _today_forecast(self, args):
        raise NotImplementedError()

    def _five_and_ten_days_forecast(self, args):
        raise NotImplementedError()

    def _weekend_forecast(self, args):
        raise NotImplementedError()

    def run(self, args):
        self._forecast_type = args.forecast_option
        forecast_function = self._forecast[args.forecast_option]
        return forecast_function(args)
```

在初始化器中，我们创建了一个字典，其中键是`ForecasType`枚举的成员，值是绑定到任何这些选项的方法。我们的应用程序将能够呈现今天的、五天的、十天的和周末的预报，所以我们实现了所有四种方法。

`run`方法只做两件事；它使用我们在命令行中传递的`forecast_option`查找需要执行的函数，并执行该函数返回其值。

现在，如果你在命令行中运行命令，应用程序终于准备好第一次执行了：

```py
$ python -m weatherterm --help
```

应该看到应用程序的帮助选项：

```py
usage: weatherterm [-h] -p {WeatherComParser} [-u {Celsius,Fahrenheit}] -a AREA_CODE [-v] [-td] [-5d] [-10d] [-w]

Weather info from weather.com on your terminal

optional arguments:
 -h, --help show this help message and exit
 -u {Celsius,Fahrenheit}, --unit {Celsius,Fahrenheit}
 Specify the unit that will be used to display 
 the temperatures.
 -v, --version show program's version number and exit
 -td, --today Show the weather forecast for the current day

require arguments:
 -p {WeatherComParser}, --parser {WeatherComParser}
 Specify which parser is going to be used to scrape
 weather information.
 -a AREA_CODE, --areacode AREA_CODE
 The code area to get the weather broadcast from. It
 can be obtained at https://weather.com
```

正如你所看到的，`ArgumentParse`模块已经提供了开箱即用的帮助输出。你可以按照自己的需求自定义输出的方式，但我觉得默认布局非常好。

注意，`-p`参数已经给了你选择`WeatherComParser`的选项。因为解析器加载器已经为我们完成了所有工作，所以不需要在任何地方硬编码它。`-u`（`--unit`）标志也包含了枚举`Unit`的项。如果有一天你想扩展这个应用程序并添加新的单位，你唯一需要做的就是在这里添加新的枚举项，它将自动被捡起并包含为`-u`标志的选项。

现在，如果你再次运行应用程序并传递一些参数：

```py
$ python -m weatherterm -u Celsius -a SWXX2372:1:SW -p WeatherComParser -td
```

你会得到类似于这样的异常：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-prog-bp/img/c2b594fc-7ad7-4b4f-877a-3476564ec7f6.png)

不用担心——这正是我们想要的！如果您跟踪堆栈跟踪，您会看到一切都按预期工作。当我们运行我们的代码时，我们在`__main__.py`文件中选择了所选解析器上的`run`方法，然后选择与预报选项相关联的方法，例如`_today_forecast`，最后将结果存储在`forecast_function`变量中。

当执行存储在`forecast_function`变量中的函数时，引发了`NotImplementedError`异常。到目前为止一切顺利；代码完美运行，现在我们可以开始为这些方法中的每一个添加实现。

# 获取今天的天气预报

核心功能已经就位，应用程序的入口点和参数解析器将为我们的应用程序的用户带来更好的体验。现在，终于到了我们一直在等待的时间，开始实现解析器的时间。我们将开始实现获取今天的天气预报的方法。

由于我在瑞典，我将使用区号`SWXX2372:1:SW`（瑞典斯德哥尔摩）；但是，您可以使用任何您想要的区号。要获取您选择的区号，请转到[`weather.com`](https://weather.com)并搜索您想要的区域。选择区域后，将显示当天的天气预报。请注意，URL 会更改，例如，搜索瑞典斯德哥尔摩时，URL 会更改为：

[`weather.com/weather/today/l/SWXX2372:1:SW`](https://weather.com/weather/today/l/SWXX2372:1:SW)

对于巴西圣保罗，将是：

[`weather.com/weather/today/l/BRXX0232:1:BR`](https://weather.com/weather/today/l/BRXX0232:1:BR)

请注意，URL 只有一个部分会更改，这就是我们要作为参数传递给我们的应用程序的区号。

# 添加辅助方法

首先，我们需要导入一些包：

```py
import re

from weatherterm.core import Forecast
from weatherterm.core import Request
from weatherterm.core import Unit
from weatherterm.core import UnitConverter
```

在初始化程序中，我们将添加以下代码：

```py
self._base_url = 'http://weather.com/weather/{forecast}/l/{area}'
self._request = Request(self._base_url)

self._temp_regex = re.compile('([0-9]+)\D{,2}([0-9]+)')
self._only_digits_regex = re.compile('[0-9]+')

self._unit_converter = UnitConverter(Unit.FAHRENHEIT)
```

在初始化程序中，我们定义了要使用的 URL 模板，以执行对天气网站的请求；然后，我们创建了一个`Request`对象。这是将代表我们执行请求的对象。

只有在解析今天的天气预报温度时才使用正则表达式。

我们还定义了一个`UnitConverter`对象，并将默认单位设置为`华氏度`。

现在，我们准备开始添加两个方法，这两个方法将负责实际搜索某个类中的 HTML 元素并返回其内容。第一个方法称为`_get_data`：

```py
def _get_data(self, container, search_items):
    scraped_data = {}

    for key, value in search_items.items():
        result = container.find(value, class_=key)

        data = None if result is None else result.get_text()

        if data is not None:
            scraped_data[key] = data

    return scraped_data
```

这种方法的想法是在匹配某些条件的容器中搜索项目。`container`只是 HTML 中的 DOM 元素，而`search_items`是一个字典，其中键是 CSS 类，值是 HTML 元素的类型。它可以是 DIV、SPAN 或您希望获取值的任何内容。

它开始循环遍历`search_items.items()`，并使用 find 方法在容器中查找元素。如果找到该项，我们使用`get_text`提取 DOM 元素的文本，并将其添加到一个字典中，当没有更多项目可搜索时将返回该字典。

我们将实现的第二个方法是`_parser`方法。这将使用我们刚刚实现的`_get_data`：

```py
def _parse(self, container, criteria):
    results = [self._get_data(item, criteria)
               for item in container.children]

    return [result for result in results if result]
```

在这里，我们还会得到一个`container`和`criteria`，就像`_get_data`方法一样。容器是一个 DOM 元素，标准是我们要查找的节点的字典。第一个推导式获取所有容器的子元素，并将它们传递给刚刚实现的`_get_data`方法。

结果将是一个包含所有已找到项目的字典列表，我们只会返回不为空的字典。

我们还需要实现另外两个辅助方法，以便获取今天的天气预报。让我们实现一个名为`_clear_str_number`的方法：

```py
def _clear_str_number(self, str_number):
    result = self._only_digits_regex.match(str_number)
    return '--' if result is None else result.group()
```

这种方法将使用正则表达式确保只返回数字。

还需要实现的最后一个方法是 `_get_additional_info` 方法：

```py
def _get_additional_info(self, content):
    data = tuple(item.td.span.get_text()
                 for item in content.table.tbody.children)
    return data[:2]
```

这个方法循环遍历表格行，获取每个单元格的文本。这个推导式将返回有关天气的大量信息，但我们只对前 `2` 个感兴趣，即风和湿度。

# 实施今天的天气预报

现在是时候开始添加 `_today_forecast` 方法的实现了，但首先，我们需要导入 `BeautifulSoup`。在文件顶部添加以下导入语句：

```py
from bs4 import BeautifulSoup
```

现在，我们可以开始添加 `_today_forecast` 方法：

```py
def _today_forecast(self, args):
    criteria = {
        'today_nowcard-temp': 'div',
        'today_nowcard-phrase': 'div',
        'today_nowcard-hilo': 'div',
        }

    content = self._request.fetch_data(args.forecast_option.value,
                                       args.area_code)

    bs = BeautifulSoup(content, 'html.parser')

    container = bs.find('section', class_='today_nowcard-container')

    weather_conditions = self._parse(container, criteria)

    if len(weather_conditions) < 1:
        raise Exception('Could not parse weather foreecast for 
        today.')

    weatherinfo = weather_conditions[0]

    temp_regex = re.compile(('H\s+(\d+|\-{,2}).+'
                             'L\s+(\d+|\-{,2})'))
    temp_info = temp_regex.search(weatherinfo['today_nowcard-hilo'])
    high_temp, low_temp = temp_info.groups()

    side = container.find('div', class_='today_nowcard-sidecar')
    humidity, wind = self._get_additional_info(side)

    curr_temp = self._clear_str_number(weatherinfo['today_nowcard- 
    temp'])

    self._unit_converter.dest_unit = args.unit

    td_forecast = Forecast(self._unit_converter.convert(curr_temp),
                           humidity,
                           wind,
                           high_temp=self._unit_converter.convert(
                               high_temp),
                           low_temp=self._unit_converter.convert(
                               low_temp),
                           description=weatherinfo['today_nowcard-
                            phrase'])

    return [td_forecast]
```

这是在命令行上使用`-td` 或`--today` 标志时将被调用的函数。让我们分解这段代码，以便我们可以轻松理解它的作用。理解这个方法很重要，因为这些方法解析了与此非常相似的其他天气预报选项（五天、十天和周末）的数据。

这个方法的签名非常简单；它只获取`args`，这是在`__main__` 方法中创建的`Argument` 对象。在这个方法中，我们首先创建一个包含我们想要在标记中找到的所有 DOM 元素的`criteria` 字典：

```py
criteria = {
    'today_nowcard-temp': 'div',
    'today_nowcard-phrase': 'div',
    'today_nowcard-hilo': 'div',
}
```

如前所述，`criteria` 字典的关键是 DOM 元素的 CSS 类的名称，值是 HTML 元素的类型：

+   `today_nowcard-temp` 类是包含当前温度的 DOM 元素的 CSS 类

+   `today_nowcard-phrase` 类是包含天气条件文本（多云，晴天等）的 DOM 元素的 CSS 类

+   `today_nowcard-hilo` 类是包含最高和最低温度的 DOM 元素的 CSS 类

接下来，我们将获取、创建和使用`BeautifulSoup` 来解析 DOM：

```py
content = self._request.fetch_data(args.forecast_option.value, 
                                   args.area_code)

bs = BeautifulSoup(content, 'html.parser')

container = bs.find('section', class_='today_nowcard-container')

weather_conditions = self._parse(container, criteria)

if len(weather_conditions) < 1:
    raise Exception('Could not parse weather forecast for today.')

weatherinfo = weather_conditions[0]
```

首先，我们利用我们在核心模块上创建的`Request` 类的`fetch_data` 方法，并传递两个参数；第一个是预报选项，第二个参数是我们在命令行上传递的地区代码。

获取数据后，我们创建一个`BeautifulSoup` 对象，传递`content`和一个`parser`。因为我们得到的是 HTML，所以我们使用`html.parser`。

现在是开始寻找我们感兴趣的 HTML 元素的时候了。记住，我们需要找到一个容器元素，`_parser` 函数将搜索子元素并尝试找到我们在字典条件中定义的项目。对于今天的天气预报，包含我们需要的所有数据的元素是一个带有 `today_nowcard-container` CSS 类的`section` 元素。

`BeautifulSoup` 包含了 `find` 方法，我们可以使用它来查找具有特定条件的 HTML DOM 中的元素。请注意，关键字参数称为`class_` 而不是`class`，因为`class` 在 Python 中是一个保留字。

现在我们有了容器元素，我们可以将其传递给`_parse` 方法，它将返回一个列表。我们检查结果列表是否至少包含一个元素，并在为空时引发异常。如果不为空，我们只需获取第一个元素并将其分配给`weatherinfo` 变量。`weatherinfo` 变量现在包含了我们正在寻找的所有项目的字典。

下一步是分割最高和最低温度：

```py
temp_regex = re.compile(('H\s+(\d+|\-{,2}).+'
                         'L\s+(\d+|\-{,2})'))
temp_info = temp_regex.search(weatherinfo['today_nowcard-hilo'])
high_temp, low_temp = temp_info.groups()
```

我们想解析从带有 `today_nowcard-hilo` CSS 类的 DOM 元素中提取的文本，文本应该看起来像 `H 50 L 60`，`H -- L 60` 等。提取我们想要的文本的一种简单方法是使用正则表达式：

`H\s+(\d+|\-{,2}).L\s+(\d+|\-{,2})`

我们可以将这个正则表达式分成两部分。首先，我们想要得到最高温度—`H\s+(\d+|\-{,2})`；这意味着它将匹配一个`H`后面跟着一些空格，然后它将分组一个匹配数字或最多两个破折号的值。之后，它将匹配任何字符。最后，第二部分基本上做了相同的事情；不过，它开始匹配一个`L`。

执行搜索方法后，调用`groups()`函数返回了正则表达式组，这种情况下将返回两个组，一个是最高温度，另一个是最低温度。

我们想要向用户提供的其他信息是关于风和湿度的信息。包含这些信息的容器元素具有一个名为`today_nowcard-sidecar`的 CSS 类：

```py
side = container.find('div', class_='today_nowcard-sidecar')
wind, humidity = self._get_additional_info(side)
```

我们只需找到容器并将其传递给`_get_additional_info`方法，该方法将循环遍历容器的子元素，提取文本，最后为我们返回结果。

最后，这个方法的最后一部分：

```py
curr_temp = self._clear_str_number(weatherinfo['today_nowcard-temp'])

self._unit_converter.dest_unit = args.unit

td_forecast = Forecast(self._unit_converter.convert(curr_temp),
                       humidity,
                       wind,
                       high_temp=self._unit_converter.convert(
                           high_temp),
                       low_temp=self._unit_converter.convert(
                           low_temp),
                       description=weatherinfo['today_nowcard- 
                        phrase'])

return [td_forecast]
```

由于当前温度包含一个我们此时不想要的特殊字符（度数符号），我们使用`_clr_str_number`方法将`weatherinfo`字典的`today_nowcard-temp`项传递给它。

现在我们有了所有需要的信息，我们构建`Forecast`对象并返回它。请注意，我们在这里返回一个数组；这是因为我们将要实现的所有其他选项（五天、十天和周末天气预报）都将返回一个列表，为了使其一致；也为了在终端上显示这些信息时更方便，我们也返回一个列表。

还要注意的一点是，我们正在使用`UnitConverter`的转换方法将所有温度转换为命令行中选择的单位。

再次运行命令时：

```py
$ python -m weatherterm -u Fahrenheit -a SWXX2372:1:SW -p WeatherComParser -td
```

你应该看到类似于这样的输出：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-prog-bp/img/1f2ea039-104c-4786-a400-ae107a248609.png)

恭喜！你已经实现了你的第一个网络爬虫应用。接下来，让我们添加其他的预报选项。

# 获取五天和十天的天气预报

我们目前正在从([weather.com](https://weather.com/en-IN/))这个网站上爬取天气预报，它也提供了风和湿度的天气预报。

五天和十天，所以在这一部分，我们将实现解析这些预报选项的方法。

呈现五天和十天数据的页面的标记非常相似；它们具有相同的 DOM 结构和共享相同的 CSS 类，这使得我们可以实现只适用于这两个选项的方法。让我们继续并向`wheater_com_parser.py`文件添加一个新的方法，内容如下：

```py
def _parse_list_forecast(self, content, args):
    criteria = {
        'date-time': 'span',
        'day-detail': 'span',
        'description': 'td',
        'temp': 'td',
        'wind': 'td',
        'humidity': 'td',
    }

    bs = BeautifulSoup(content, 'html.parser')

    forecast_data = bs.find('table', class_='twc-table')
    container = forecast_data.tbody

    return self._parse(container, criteria)
```

正如我之前提到的，五天和十天的天气预报的 DOM 结构非常相似，因此我们创建了`_parse_list_forecast`方法，可以用于这两个选项。首先，我们定义了标准：

+   `date-time`是一个`span`元素，包含代表星期几的字符串

+   `day-detail`是一个`span`元素，包含一个日期的字符串，例如，`SEP 29`

+   `description`是一个`TD`元素，包含天气状况，例如，``Cloudy``

+   `temp`是一个`TD`元素，包含高低温度等温度信息

+   `wind`是一个`TD`元素，包含风力信息

+   `humidity`是一个`TD`元素，包含湿度信息

现在我们有了标准，我们创建一个`BeatufulSoup`对象，传递内容和`html.parser`。我们想要获取的所有数据都在一个名为`twc-table`的 CSS 类的表格中。我们找到表格并将`tbody`元素定义为容器。

最后，我们运行`_parse`方法，传递`container`和我们定义的`criteria`。这个函数的返回将看起来像这样：

```py
[{'date-time': 'Today',
  'day-detail': 'SEP 28',
  'description': 'Partly Cloudy',
  'humidity': '78%',
  'temp': '60°50°',
  'wind': 'ESE 10 mph '},
 {'date-time': 'Fri',
  'day-detail': 'SEP 29',
  'description': 'Partly Cloudy',
  'humidity': '79%',
  'temp': '57°48°',
  'wind': 'ESE 10 mph '},
 {'date-time': 'Sat',
  'day-detail': 'SEP 30',
  'description': 'Partly Cloudy',
  'humidity': '77%',
  'temp': '57°49°',
  'wind': 'SE 10 mph '},
 {'date-time': 'Sun',
  'day-detail': 'OCT 1',
  'description': 'Cloudy',
  'humidity': '74%',
  'temp': '55°51°',
  'wind': 'SE 14 mph '},
 {'date-time': 'Mon',
  'day-detail': 'OCT 2',
  'description': 'Rain',
  'humidity': '87%',
  'temp': '55°48°',
  'wind': 'SSE 18 mph '}]
```

我们需要创建的另一个方法是一个为我们准备数据的方法，例如，解析和转换温度值，并创建一个`Forecast`对象。添加一个名为`_prepare_data`的新方法，内容如下：

```py
def _prepare_data(self, results, args):
    forecast_result = []

    self._unit_converter.dest_unit = args.unit

    for item in results:
        match = self._temp_regex.search(item['temp'])
        if match is not None:
            high_temp, low_temp = match.groups()

        try:
            dateinfo = item['weather-cell']
            date_time, day_detail = dateinfo[:3], dateinfo[3:]
            item['date-time'] = date_time
            item['day-detail'] = day_detail
        except KeyError:
            pass

        day_forecast = Forecast(
            self._unit_converter.convert(item['temp']),
            item['humidity'],
            item['wind'],
            high_temp=self._unit_converter.convert(high_temp),
            low_temp=self._unit_converter.convert(low_temp),
            description=item['description'].strip(),
            forecast_date=f'{item["date-time"]} {item["day-
             detail"]}',
            forecast_type=self._forecast_type)
        forecast_result.append(day_forecast)

    return forecast_result
```

这个方法非常简单。首先，循环遍历结果，并应用我们创建的正则表达式来分割存储在`item['temp']`中的高温和低温。如果匹配成功，它将获取组并将值分配给`high_temp`和`low_temp`。

之后，我们创建一个`Forecast`对象，并将其附加到稍后将返回的列表中。

最后，我们添加一个在使用`-5d`或`-10d`标志时将被调用的方法。创建另一个名为`_five_and_ten_days_forecast`的方法，内容如下：

```py
def _five_and_ten_days_forecast(self, args):
    content = self._request.fetch_data(args.forecast_option.value, 
    args.area_code)
    results = self._parse_list_forecast(content, args)
    return self._prepare_data(results)
```

这个方法只获取页面的内容，传递`forecast_option`值和区域代码，因此可以构建 URL 来执行请求。当数据返回时，我们将其传递给`_parse_list_forecast`，它将返回一个`Forecast`对象的列表（每天一个）；最后，我们使用`_prepare_data`方法准备要返回的数据。

在运行命令之前，我们需要在我们实现的命令行工具中启用此选项；转到`__main__.py`文件，并在`-td`标志的定义之后，添加以下代码：

```py
argparser.add_argument('-5d', '--fivedays',
                       dest='forecast_option',
                       action='store_const',
                       const=ForecastType.FIVEDAYS,
                       help='Shows the weather forecast for the next         
                       5 days')
```

现在，再次运行应用程序，但这次使用`-5d`或`--fivedays`标志：

```py
$ python -m weatherterm -u Fahrenheit -a SWXX2372:1:SW -p WeatherComParser -5d
```

它将产生以下输出：

```py
>> [Today SEP 28]
 High 60° / Low 50° (Partly Cloudy)
 Wind: ESE 10 mph / Humidity: 78%

>> [Fri SEP 29]
 High 57° / Low 48° (Partly Cloudy)
 Wind: ESE 10 mph / Humidity: 79%

>> [Sat SEP 30]
 High 57° / Low 49° (Partly Cloudy)
 Wind: SE 10 mph / Humidity: 77%

>> [Sun OCT 1]
 High 55° / Low 51° (Cloudy)
 Wind: SE 14 mph / Humidity: 74%

>> [Mon OCT 2]
 High 55° / Low 48° (Rain)
 Wind: SSE 18 mph / Humidity: 87%
```

为了结束本节，让我们在`__main__.py`文件中添加一个选项，以便获取未来十天的天气预报，就在`-5d`标志定义的下面。添加以下代码：

```py
argparser.add_argument('-10d', '--tendays',
                       dest='forecast_option',
                       action='store_const',
                       const=ForecastType.TENDAYS,
                       help='Shows the weather forecast for the next  
                       10 days')
```

如果您运行与获取五天预报相同的命令，但将`-5d`标志替换为`-10d`，如下所示：

```py
$ python -m weatherterm -u Fahrenheit -a SWXX2372:1:SW -p WeatherComParser -10d
```

您应该看到十天的天气预报输出：

```py
>> [Today SEP 28]
 High 60° / Low 50° (Partly Cloudy)
 Wind: ESE 10 mph / Humidity: 78%

>> [Fri SEP 29]
 High 57° / Low 48° (Partly Cloudy)
 Wind: ESE 10 mph / Humidity: 79%

>> [Sat SEP 30]
 High 57° / Low 49° (Partly Cloudy)
 Wind: SE 10 mph / Humidity: 77%

>> [Sun OCT 1]
 High 55° / Low 51° (Cloudy)
 Wind: SE 14 mph / Humidity: 74%

>> [Mon OCT 2]
 High 55° / Low 48° (Rain)
 Wind: SSE 18 mph / Humidity: 87%

>> [Tue OCT 3]
 High 56° / Low 46° (AM Clouds/PM Sun)
 Wind: S 10 mph / Humidity: 84%

>> [Wed OCT 4]
 High 58° / Low 47° (Partly Cloudy)
 Wind: SE 9 mph / Humidity: 80%

>> [Thu OCT 5]
 High 57° / Low 46° (Showers)
 Wind: SSW 8 mph / Humidity: 81%

>> [Fri OCT 6]
 High 57° / Low 46° (Partly Cloudy)
 Wind: SW 8 mph / Humidity: 76%

>> [Sat OCT 7]
 High 56° / Low 44° (Mostly Sunny)
 Wind: W 7 mph / Humidity: 80%

>> [Sun OCT 8]
 High 56° / Low 44° (Partly Cloudy)
 Wind: NNE 7 mph / Humidity: 78%

>> [Mon OCT 9]
 High 56° / Low 43° (AM Showers)
 Wind: SSW 9 mph / Humidity: 79%

>> [Tue OCT 10]
 High 55° / Low 44° (AM Showers)
 Wind: W 8 mph / Humidity: 79%

>> [Wed OCT 11]
 High 55° / Low 42° (AM Showers)
 Wind: SE 7 mph / Humidity: 79%

>> [Thu OCT 12]
 High 53° / Low 43° (AM Showers)
 Wind: NNW 8 mph / Humidity: 87%
```

如您所见，我在瑞典写这本书时天气并不是很好。

# 获取周末天气预报

我们将在我们的应用程序中实现的最后一个天气预报选项是获取即将到来的周末天气预报的选项。这个实现与其他实现有些不同，因为周末天气返回的数据与今天、五天和十天的天气预报略有不同。

DOM 结构不同，一些 CSS 类名也不同。如果您还记得我们之前实现的方法，我们总是使用`_parser`方法，该方法为我们提供容器 DOM 和带有搜索条件的字典作为参数。该方法的返回值也是一个字典，其中键是我们正在搜索的 DOM 的类名，值是该 DOM 元素中的文本。

由于周末页面的 CSS 类名不同，我们需要实现一些代码来获取结果数组并重命名所有键，以便`_prepare_data`函数可以正确使用抓取的结果。

说到这一点，让我们继续在`weatherterm/core`目录中创建一个名为`mapper.py`的新文件，内容如下：

```py
class Mapper:

    def __init__(self):
        self._mapping = {}

    def _add(self, source, dest):
        self._mapping[source] = dest

    def remap_key(self, source, dest):
        self._add(source, dest)

    def remap(self, itemslist):
        return [self._exec(item) for item in itemslist]

    def _exec(self, src_dict):
        dest = dict()

        if not src_dict:
            raise AttributeError('The source dictionary cannot be  
            empty or None')

        for key, value in src_dict.items():
            try:
                new_key = self._mapping[key]
                dest[new_key] = value
            except KeyError:
                dest[key] = value
        return dest
```

`Mapper`类获取一个包含字典的列表，并重命名我们想要重命名的特定键。这里的重要方法是`remap_key`和`remap`。`remap_key`接收两个参数，`source`和`dest`。`source`是我们希望重命名的键，`dest`是该键的新名称。`remap_key`方法将其添加到一个名为`_mapping`的内部字典中，以便以后查找新的键名。

`remap`方法只是获取包含字典的列表，并对该列表中的每个项目调用`_exec`方法，该方法首先创建一个全新的字典，然后检查字典是否为空。在这种情况下，它会引发`AttributeError`。

如果字典有键，我们循环遍历其项，搜索当前项的键是否在映射字典中具有新名称。如果找到新的键名，将创建一个具有新键名的新项；否则，我们只保留旧名称。循环结束后，返回包含所有具有新名称键的字典的列表。

现在，我们只需要将其添加到`weatherterm/core`目录中的`__init__.py`文件中：

```py
from .mapper import Mapper
```

而且，在`weatherterm/parsers`目录中的`weather_com_parser.py`文件中，我们需要导入`Mapper`：

```py
from weatherterm.core import Mapper
```

有了映射器，我们可以继续在`weather_com_parser.py`文件中创建`_weekend_forecast`方法，如下所示：

```py
def _weekend_forecast(self, args):
    criteria = {
        'weather-cell': 'header',
        'temp': 'p',
        'weather-phrase': 'h3',
        'wind-conditions': 'p',
        'humidity': 'p',
    }

    mapper = Mapper()
    mapper.remap_key('wind-conditions', 'wind')
    mapper.remap_key('weather-phrase', 'description')

    content = self._request.fetch_data(args.forecast_option.value,
                                       args.area_code)

    bs = BeautifulSoup(content, 'html.parser')

    forecast_data = bs.find('article', class_='ls-mod')
    container = forecast_data.div.div

    partial_results = self._parse(container, criteria)
    results = mapper.remap(partial_results)

    return self._prepare_data(results, args)
```

该方法首先通过以与其他方法完全相同的方式定义标准来开始；但是，DOM 结构略有不同，一些 CSS 名称也不同：

+   `weather-cell`：包含预报日期：`FriSEP 29`

+   `temp`：包含温度（高和低）：`57°F48°F`

+   `weather-phrase`：包含天气条件：`多云`

+   `wind-conditions`：风信息

+   `humidity`：湿度百分比

正如你所看到的，为了使其与`_prepare_data`方法很好地配合，我们需要重命名结果集中字典中的一些键——`wind-conditions`应该是`wind`，`weather-phrase`应该是`description`。

幸运的是，我们引入了`Mapper`类来帮助我们：

```py
mapper = Mapper()
mapper.remap_key('wind-conditions', 'wind')
mapper.remap_key('weather-phrase', 'description')
```

我们创建一个`Mapper`对象并说，将`wind-conditions`重新映射为`wind`，将`weather-phrase`重新映射为`description`：

```py
content = self._request.fetch_data(args.forecast_option.value,
                                   args.area_code)

bs = BeautifulSoup(content, 'html.parser')

forecast_data = bs.find('article', class_='ls-mod')
container = forecast_data.div.div

partial_results = self._parse(container, criteria)
```

我们获取所有数据，使用`html.parser`创建一个`BeautifulSoup`对象，并找到包含我们感兴趣的子元素的容器元素。对于周末预报，我们有兴趣获取具有名为`ls-mod`的 CSS 类的`article`元素，并在`article`中向下移动到第一个子元素，这是一个 DIV，并获取其第一个子元素，这也是一个 DIV 元素。

HTML 应该看起来像这样：

```py
<article class='ls-mod'>
  <div>
    <div>
      <!-- this DIV will be our container element -->
    </div>
  </div>
</article>
```

这就是我们首先找到文章，将其分配给`forecast_data`，然后使用`forecast_data.div.div`，这样我们就可以得到我们想要的 DIV 元素。

在定义容器之后，我们将其与容器元素一起传递给`_parse`方法；当我们收到结果时，我们只需要运行`Mapper`实例的`remap`方法，它将在我们调用`_prepare_data`之前为我们规范化数据。

现在，在运行应用程序并获取周末天气预报之前的最后一个细节是，我们需要将`--w`和`--weekend`标志包含到`ArgumentParser`中。打开`weatherterm`目录中的`__main__.py`文件，并在`--tenday`标志的下方添加以下代码：

```py
argparser.add_argument('-w', '--weekend',
                       dest='forecast_option',
                       action='store_const',
                       const=ForecastType.WEEKEND,
                       help=('Shows the weather forecast for the 
                             next or '
                             'current weekend'))
```

太好了！现在，使用`-w`或`--weekend`标志运行应用程序：

```py
>> [Fri SEP 29]
 High 13.9° / Low 8.9° (Partly Cloudy)
 Wind: ESE 10 mph / Humidity: 79%

>> [Sat SEP 30]
 High 13.9° / Low 9.4° (Partly Cloudy)
 Wind: SE 10 mph / Humidity: 77%

>> [Sun OCT 1]
 High 12.8° / Low 10.6° (Cloudy)
 Wind: SE 14 mph / Humidity: 74%
```

请注意，这次我使用了`-u`标志来选择摄氏度。输出中的所有温度都以摄氏度表示，而不是华氏度。

# 总结

在本章中，您学习了 Python 中面向对象编程的基础知识；我们介绍了如何创建类，使用继承，并使用`@property`装饰器创建 getter 和 setter。

我们介绍了如何使用 inspect 模块来获取有关模块、类和函数的更多信息。最后但并非最不重要的是，我们利用了强大的`Beautifulsoup`包来解析 HTML 和`Selenium`来向天气网站发出请求。

我们还学习了如何使用 Python 标准库中的`argparse`模块实现命令行工具，这使我们能够提供更易于使用且具有非常有用的文档的工具。

接下来，我们将开发一个小包装器，围绕 Spotify Rest API，并使用它来创建一个远程控制终端。


# 第二章：使用 Spotify 创建远程控制应用程序

Spotify 是一家总部位于瑞典斯德哥尔摩的音乐流媒体服务。第一个版本于 2008 年发布，如今它不仅提供音乐，还提供视频和播客。Spotify 从瑞典的初创公司迅速发展成为世界上最大的音乐服务，其应用程序在视频游戏机和手机上运行，并与许多社交网络集成。

该公司确实改变了我们消费音乐的方式，也使得不仅是知名艺术家，而且小型独立艺术家也能与世界分享他们的音乐。

幸运的是，Spotify 也是开发人员的绝佳平台，并提供了一个非常好的和有文档的 REST API，可以通过艺术家、专辑、歌曲名称进行搜索，还可以创建和分享播放列表。

在本书的第二个应用程序中，我们将开发一个终端应用程序，其中我们可以：

+   搜索艺术家

+   搜索专辑

+   搜索曲目

+   播放音乐

除了所有这些功能之外，我们将实现一些函数，以便通过终端控制 Spotify 应用程序。

首先，我们将经历在 Spotify 上创建新应用程序的过程；然后，将是开发一个小框架的时间，该框架将包装 Spotify 的 REST API 的某些部分。我们还将致力于实现 Spotify 支持的不同类型的身份验证，以便消耗其 REST API。

当所有这些核心功能都就位后，我们将使用 Python 附带的`curses`软件包来开发终端用户界面。

在本章中，您将学习：

+   如何创建`Spotify`应用程序

+   如何使用`OAuth`

+   面向对象的编程概念

+   使用流行的`Requests`软件包来消耗 REST API

+   使用 curses 设计终端用户界面的方法

我不知道你们，但我真的很想写代码并听一些好听的音乐，所以让我们开始吧！

# 设置环境

让我们继续配置我们的开发环境。我们需要做的第一件事是创建一个新的虚拟环境，这样我们就可以工作并安装我们需要的软件包，而不会干扰全局 Python 安装。

我们的应用程序将被称为`musicterminal`，因此我们可以创建一个同名的虚拟环境。

要创建一个新的虚拟环境，请运行以下命令：

```py
$ python3 -m venv musicterminal
```

确保您使用的是 Python 3.6 或更高版本，否则本书中的应用程序可能无法正常工作。

要激活虚拟环境，可以运行以下命令：

```py
$ . musicterminal/bin/activate
```

太好了！现在我们已经设置好了虚拟环境，我们可以创建项目的目录结构。它应该具有以下结构：

```py
musicterminal
├── client
├── pytify
│   ├── auth
│   └── core
└── templates
```

与第一章中的应用程序一样，我们创建一个项目目录（这里称为`musicterminal`）和一个名为`pytify`的子目录，其中将包含包装 Spotify 的 REST API 的框架。

在框架目录中，我们将`auth`拆分为两个模块，这两个模块将包含 Spotify 支持的两种身份验证流程的实现——授权代码和客户端凭据。最后，`core`模块将包含从 REST API 获取数据的所有方法。

客户端目录将包含与我们将构建的客户端应用程序相关的所有脚本。

最后，`templates`目录将包含一些 HTML 文件，这些文件将在我们构建一个小的 Flask 应用程序来执行 Spotify 身份验证时使用。

现在，让我们在`musicterminal`目录中创建一个`requirements.txt`文件，内容如下：

```py
requests==2.18.4
PyYAML==3.12
```

要安装依赖项，只需运行以下命令：

```py
$ pip install -r requirements.txt
```

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-prog-bp/img/c51878ae-cdd2-4c1c-aba5-a1fb2df3386e.png)

如您在输出中所见，其他软件包已安装在我们的虚拟环境中。这是因为我们项目所需的软件包也需要其他软件包，因此它们也将被安装。

Requests 是由 Kenneth Reitz 创建的[`www.kennethreitz.org/`](https://www.kennethreitz.org/)，它是 Python 生态系统中使用最广泛且备受喜爱的软件包之一。它被微软、谷歌、Mozilla、Spotify、Twitter 和索尼等大公司使用，它是 Pythonic 且非常直观易用的。

查看 Kenneth 的其他项目，尤其是`pipenv`项目，这是一个很棒的 Python 打包工具。

我们将使用的另一个模块是 curses。curses 模块只是 curses C 函数的包装器，相对于在 C 中编程，它相对简单。如果您之前使用过 curses C 库，那么 Python 中的 curses 模块应该是熟悉且易于学习的。

需要注意的一点是，Python 在 Linux 和 Mac 上包含 curses 模块；但是，在 Windows 上，默认情况下不包含它。如果您使用 Windows，curses 文档在[`docs.python.org/3/howto/curses.html`](https://docs.python.org/3/howto/curses.html)上推荐由 Fredrik Lundh 开发的 UniCurses 包。

在我们开始编码之前，还有一件事。在尝试导入 curses 时，您可能会遇到问题；最常见的原因是您的系统中未安装`libncurses`。在安装 Python 之前，请确保您的系统上已安装`libncurses`和`libncurses-dev`。

如果您使用 Linux，您很可能会在我们首选发行版的软件包存储库中找到`libncurses`。在 Debian/Ubuntu 中，您可以使用以下命令安装它：

```py
$ sudo apt-get install libncurses5 libncurses5-dev
```

太好了！现在，我们已经准备好开始实施我们的应用程序了。

# 创建 Spotify 应用程序

我们需要做的第一件事是创建一个 Spotify 应用程序；之后，我们将获取访问密钥，以便我们可以进行身份验证并使用 REST API。

前往[`beta.developer.spotify.com/dashboard/`](https://beta.developer.spotify.com/dashboard/)，在页面下方您可以找到登录按钮，如果您没有帐户，可以创建一个新帐户。

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-prog-bp/img/1557b618-e930-456a-bf79-f539bf015194.png)在撰写本文时，Spotify 开始更改其开发者网站，并且目前处于测试阶段，因此登录地址和一些截图可能会有所不同。

如果您没有 Spotify 帐户，您首先需要创建一个。如果您注册免费帐户，应该能够创建应用程序，但我建议您注册高级帐户，因为它是一个拥有丰富音乐目录的优秀服务。

当您登录 Spotify 开发者网站时，您将看到类似以下页面：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-prog-bp/img/d051e689-8f73-40a9-b6bf-7e005dc6fd66.png)

目前，我们还没有创建任何应用程序（除非您已经创建了一个），所以继续点击“CREATE AN APP”按钮。将显示一个对话框屏幕来创建应用程序：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-prog-bp/img/50e3e47c-e7b5-484f-8617-203af23e550a.png)

在这里，我们有三个必填字段：应用程序名称、描述，以及一些复选框，您需要告诉 Spotify 您正在构建什么。名称应该是`pytify`，在描述中，您可以随意填写，但让我们添加类似“用于从终端控制 Spotify 客户端的应用程序”的内容。我们正在构建的应用程序类型将是网站。

完成后，点击对话框屏幕底部的“NEXT”按钮。

应用程序创建过程的第二步是告知 Spotify 您是否正在创建商业集成。对于本书的目的，我们将选择**NO**；但是，如果您要创建一个将实现货币化的应用程序，您应该选择**YES**。

在下一步中，将显示以下对话框：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-prog-bp/img/0f932dc3-70ea-4696-91e7-7ddc19dd3cef.png)

如果您同意所有条件，只需选择所有复选框，然后点击“SUBMIT”按钮。

如果应用程序已成功创建，您将被重定向到应用程序的页面，如下所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-prog-bp/img/ed9c9c57-1548-4c53-8414-9a973dc370df.png)

单击“显示客户端密钥”链接，并复制客户端 ID 和客户端密钥的值。我们将需要这些密钥来使用 Spotify 的 REST API。

# 应用程序的配置

为了使应用程序更灵活且易于配置，我们将创建一个配置文件。这样，我们就不需要硬编码 URL 和访问密钥；而且，如果需要更改这些设置，也不需要更改源代码。

我们将创建一个 YAML 格式的配置文件，用于存储我们的应用程序用于认证、向 Spotify RESP API 端点发出请求等的信息。

# 创建配置文件

让我们继续在`musicterminal`目录中创建一个名为`config.yaml`的文件，内容如下：

```py
client_id: '<your client ID>'
client_secret: '<your client secret>'
access_token_url: 'https://accounts.spotify.com/api/token'
auth_url: 'http://accounts.spotify.com/authorize'
api_version: 'v1'
api_url: 'https://api.spotify.com'
auth_method: 'AUTHORIZATION_CODE'
```

`client_id`和`client_secret`是我们创建 Spotify 应用程序时为我们创建的密钥。这些密钥将用于获取访问令牌，每次我们需要向 Spotify 的 REST API 发送新请求时都必须获取访问令牌。只需用您自己的密钥替换`<your client ID>`和`<your client secret>`。

请记住，这些密钥必须保存在安全的地方。不要与任何人分享密钥，如果您在 GitHub 等网站上有项目，请确保不要提交带有您的秘密密钥的配置文件。我通常会将配置文件添加到我的`.gitignore`文件中，这样它就不会被源代码控制；否则，您可以像我一样提交文件，使用占位符而不是实际密钥。这样，就很容易记住您需要在哪里添加密钥。

在`client_id`和`client_secret`键之后，我们有`access_token_url`。这是我们必须执行请求的 API 端点的 URL，以便获取访问令牌。

`auth_url`是 Spotify 的账户服务的端点；当我们需要获取或刷新授权令牌时，我们将使用它。

`api_version`，顾名思义，指定了 Spotify 的 REST API 版本。在执行请求时，这将附加到 URL 上。

最后，我们有`api_url`，这是 Spotify 的 REST API 端点的基本 URL。

# 实现配置文件读取器

在实现读取器之前，我们将添加一个枚举，表示 Spotify 提供给我们的两种认证流程。让我们继续在`musicterminal/pytify/auth`目录中创建一个名为`auth_method.py`的文件，内容如下：

```py
from enum import Enum, auto

class AuthMethod(Enum):
    CLIENT_CREDENTIALS = auto()
    AUTHORIZATION_CODE = auto()
```

这将定义一个枚举，具有`CLIENT_CREDENTIALS`和`AUTHORIZATION_CODE`属性。现在，我们可以在配置文件中使用这些值。我们还需要做的另一件事是在`musicterminal/pytify/auth`目录中创建一个名为`__init__.py`的文件，并导入我们刚刚创建的枚举：

```py
from .auth_method import AuthMethod
```

现在，我们可以继续创建将为我们读取配置的函数。在`musicterminal/pytify/core`目录中创建一个名为`config.py`的文件，然后让我们开始添加一些导入语句：

```py
import os
import yaml
from collections import namedtuple

from pytify.auth import AuthMethod
```

首先，我们导入`os`模块，这样我们就可以访问一些函数，这些函数将帮助我们构建 YAML 配置文件所在的路径。我们还导入`yaml`包来读取配置文件，最后，我们从 collections 模块导入`namedtuple`。稍后我们将更详细地讨论`namedtuple`的作用。

我们最后导入的是我们刚刚在`pytify.auth`模块中创建的`AuthMethod`枚举。

现在，我们需要一个表示配置文件的模型，因此我们创建一个名为`Config`的命名元组，如下所示：

```py
Config = namedtuple('Config', ['client_id',
                               'client_secret',
                               'access_token_url',
                               'auth_url',
                               'api_version',
                               'api_url',
                               'base_url',
                               'auth_method', ])
```

`namedtuple`不是 Python 中的新功能，自 2.6 版本以来一直存在。`namedtuple`是类似元组的对象，具有名称，并且可以通过属性查找访问字段。可以以两种不同的方式创建`namedtuple`；让我们开始 Python REPL 并尝试一下：

```py
>>> from collections import namedtuple
>>> User = namedtuple('User', ['firstname', 'lastname', 'email'])
>>> u = User('Daniel','Furtado', 'myemail@test.com')
User(firstname='Daniel', lastname='Furtado', email='myemail@test.com')
>>>
```

此结构有两个参数；第一个参数是`namedtuple`的名称，第二个是表示`namedtuple`中每个字段的`str`元素数组。还可以通过传递一个由空格分隔的每个字段名的字符串来指定`namedtuple`的字段，例如：

```py
>>> from collections import namedtuple
>>> User = namedtuple('User', 'firstname lastname email')
>>> u = User('Daniel', 'Furtado', 'myemail@test.com')
>>> print(u)
User(firstname='Daniel', lastname='Furtado', email='myemail@test.com')
```

`namedtuple`构造函数还有两个关键字参数：

`Verbose`，当设置为`True`时，在终端上显示定义`namedtuple`的类。在幕后，`namedtuple`是类，`verbose`关键字参数让我们一睹`namedtuple`类的构造方式。让我们在 REPL 上实践一下：

```py
>>> from collections import namedtuple
>>> User = namedtuple('User', 'firstname lastname email', verbose=True)
from builtins import property as _property, tuple as _tuple
from operator import itemgetter as _itemgetter
from collections import OrderedDict

class User(tuple):
    'User(firstname, lastname, email)'

    __slots__ = ()

    _fields = ('firstname', 'lastname', 'email')

    def __new__(_cls, firstname, lastname, email):
        'Create new instance of User(firstname, lastname, email)'
        return _tuple.__new__(_cls, (firstname, lastname, email))

    @classmethod
    def _make(cls, iterable, new=tuple.__new__, len=len):
        'Make a new User object from a sequence or iterable'
        result = new(cls, iterable)
        if len(result) != 3:
            raise TypeError('Expected 3 arguments, got %d' % 
            len(result))
        return result

    def _replace(_self, **kwds):
        'Return a new User object replacing specified fields with  
         new values'
        result = _self._make(map(kwds.pop, ('firstname', 'lastname',  
                             'email'), _self))
        if kwds:
            raise ValueError('Got unexpected field names: %r' %  
                              list(kwds))
        return result

    def __repr__(self):
        'Return a nicely formatted representation string'
        return self.__class__.__name__ + '(firstname=%r,  
                                           lastname=%r, email=%r)' 
        % self

    def _asdict(self):
        'Return a new OrderedDict which maps field names to their  
          values.'
        return OrderedDict(zip(self._fields, self))

    def __getnewargs__(self):
        'Return self as a plain tuple. Used by copy and pickle.'
        return tuple(self)

    firstname = _property(_itemgetter(0), doc='Alias for field  
                          number 0')

    lastname = _property(_itemgetter(1), doc='Alias for field number  
                         1')

    email = _property(_itemgetter(2), doc='Alias for field number  
                      2')
```

另一个关键字参数是`rename`，它将重命名`namedtuple`中具有不正确命名的每个属性，例如：

```py
>>> from collections import namedtuple
>>> User = namedtuple('User', 'firstname lastname email 23445', rename=True)
>>> User._fields
('firstname', 'lastname', 'email', '_3')
```

如您所见，字段`23445`已自动重命名为`_3`，这是字段位置。

要访问`namedtuple`字段，可以使用与访问类中的属性相同的语法，使用`namedtuple`——`User`，如前面的示例所示。如果我们想要访问`lastname`属性，只需写`u.lastname`。

现在我们有了代表我们配置文件的`namedtuple`，是时候添加执行加载 YAML 文件并返回`namedtuple`——`Config`的工作的函数了。在同一个文件中，让我们实现`read_config`函数如下：

```py
def read_config():
    current_dir = os.path.abspath(os.curdir)
    file_path = os.path.join(current_dir, 'config.yaml')

    try:
        with open(file_path, mode='r', encoding='UTF-8') as file:
            config = yaml.load(file)

            config['base_url'] = 
 f'{config["api_url"]}/{config["api_version"]}'    auth_method = config['auth_method']
            config['auth_method'] = 
            AuthMethod.__members__.get(auth_method)

            return Config(**config)

    except IOError as e:
        print(""" Error: couldn''t file the configuration file 
        `config.yaml`
 'on your current directory.   Default format is:',   client_id: 'your_client_id' client_secret: 'you_client_secret' access_token_url: 'https://accounts.spotify.com/api/token' auth_url: 'http://accounts.spotify.com/authorize' api_version: 'v1' api_url: 'http//api.spotify.com' auth_method: 'authentication method'   * auth_method can be CLIENT_CREDENTIALS or  
          AUTHORIZATION_CODE""")
        raise   
```

`read_config`函数首先使用`os.path.abspath`函数获取当前目录的绝对路径，并将其赋给`current_dir`变量。然后，我们将存储在`current_dir`变量上的路径与文件名结合起来，即 YAML 配置文件。

在`try`语句中，我们尝试以只读方式打开文件，并将编码设置为 UTF-8。如果失败，将向用户打印帮助消息，说明无法打开文件，并显示描述 YAML 配置文件结构的帮助。

如果配置文件可以成功读取，我们调用`yaml`模块中的 load 函数来加载和解析文件，并将结果赋给`config`变量。我们还在配置中包含了一个额外的项目`base_url`，它只是一个辅助值，包含了`api_url`和`api_version`的连接值。

`base_url`的值将如下所示：[`api.spotify.com/v1.`](https://api.spotify.com/v1)

最后，我们创建了一个`Config`的实例。请注意我们如何在构造函数中展开值；这是可能的，因为`namedtuple`——`Config`具有与`yaml.load()`返回的对象相同的字段。这与执行以下操作完全相同：

```py
return Config(
    client_id=config['client_id'],
    client_secret=config['client_secret'],
    access_token_url=config['access_token_url'],
    auth_url=config['auth_url'],
    api_version=config['api_version'],
    api_url=config['api_url'],
    base_url=config['base_url'],
    auth_method=config['auth_method'])
```

最后一步是在`pytify/core`目录中创建一个`__init__.py`文件，并导入我们刚刚创建的`read_config`函数：

```py
from .config import read_config
```

# 使用 Spotify 的 Web API 进行身份验证

现在我们已经有了加载配置文件的代码，我们将开始编写框架的认证部分。Spotify 目前支持三种认证方式：授权码、客户端凭据和隐式授权。在本章中，我们将实现授权码和客户端凭据，首先实现客户端凭据流程，这是最容易开始的。

客户端凭据流程与授权码流程相比有一些缺点，因为该流程不包括授权，也无法访问用户的私人数据以及控制播放。我们现在将实现并使用此流程，但在开始实现终端播放器时，我们将改为授权码。

首先，我们将在`musicterminal/pytify/auth`目录中创建一个名为`authorization.py`的文件，内容如下：

```py
from collections import namedtuple

Authorization = namedtuple('Authorization', [
    'access_token',
    'token_type',
    'expires_in',
    'scope',
    'refresh_token',
])
```

这将是认证模型，它将包含我们在请求访问令牌后获得的数据。在下面的列表中，您可以看到每个属性的描述：

+   `access_token`：必须与每个对 Web API 的请求一起发送的令牌

+   `token_type`：令牌的类型，通常为`Bearer`

+   `expires_in`：`access_token`的过期时间，为 3600 秒（1 小时）

+   `scope`：范围基本上是 Spotify 用户授予我们应用程序的权限

+   `refresh_token`：在过期后可以用来刷新`access_token`的令牌

最后一步是在`musicterminal/pytify/auth`目录中创建一个`__init__.py`文件，并导入`Authorization`，这是一个`namedtuple`：

```py
from .authorization import Authorization
```

# 实施客户端凭据流

客户端凭据流非常简单。让我们分解一下直到获得`access_token`的所有步骤：

1.  我们的应用程序将从 Spotify 帐户服务请求访问令牌；请记住，在我们的配置文件中，有`api_access_token`。这是我们需要发送请求以获取访问令牌的 URL。我们需要发送请求的三件事是客户端 ID、客户端密钥和授权类型，在这种情况下是`client_credentials`。

1.  Spotify 帐户服务将验证该请求，检查密钥是否与我们在开发者网站注册的应用程序的密钥匹配，并返回一个访问令牌。

1.  现在，我们的应用程序必须使用此访问令牌才能从 REST API 中获取数据。

1.  Spotify REST API 将返回我们请求的数据。

在开始实现将进行身份验证并获取访问令牌的函数之前，我们可以添加一个自定义异常，如果从 Spotify 帐户服务获得了错误请求（HTTP `400`）时，我们将抛出该异常。

让我们在`musicterminal/pytify/core`目录中创建一个名为`exceptions.py`的文件，内容如下：

```py
class BadRequestError(Exception):
    pass
```

这个类并没有做太多事情；我们只是继承自`Exception`。我们本可以只抛出一个通用异常，但是在开发其他开发人员将使用的框架和库时，最好创建自己的自定义异常，并使用良好的名称和描述。

因此，不要像这样抛出异常：

`raise Exception('some message')`

我们可以更明确地抛出`BadRequestError`，如下所示：

`raise BadRequestError('some message')`

现在，使用此代码的开发人员可以在其代码中正确处理此类异常。

打开`musicterminal/pytify/core`目录中的`__init__.py`文件，并添加以下导入语句：

```py
from .exceptions import BadRequestError
```

太好了！现在是时候在`musicterminal/pytify/auth`目录中添加一个名为`auth.py`的新文件了，我们要添加到此文件的第一件事是一些导入：

```py
import requests
import base64
import json

from .authorization import Authorization
from pytify.core import BadRequestError
```

我通常首先放置来自标准库模块的所有导入，然后是来自我的应用程序文件的函数导入。这不是必需的，但我认为这样可以使代码更清晰、更有组织。这样，我可以轻松地看出哪些是标准库项目，哪些不是。

现在，我们可以开始添加将发送请求到`Spotify`帐户服务并返回访问令牌的函数。我们要添加的第一个函数称为`get_auth_key`：

```py
def get_auth_key(client_id, client_secret):
    byte_keys = bytes(f'{client_id}:{client_secret}', 'utf-8')
    encoded_key = base64.b64encode(byte_keys)
    return encoded_key.decode('utf-8')
```

客户端凭据流要求我们发送`client_id`和`client_secret`，它必须是 base 64 编码的。首先，我们将字符串转换为`client_id:client_secret`格式的字节。然后，我们使用 base 64 对其进行编码，然后解码它，返回该编码数据的字符串表示，以便我们可以将其与请求有效负载一起发送。

我们要在同一文件中实现的另一个函数称为`_client_credentials`：

```py
def _client_credentials(conf):

    auth_key = get_auth_key(conf.client_id, conf.client_secret)

    headers = {'Authorization': f'Basic {auth_key}', }

    options = {
        'grant_type': 'client_credentials',
        'json': True,
        }

    response = requests.post(
        'https://accounts.spotify.com/api/token',
        headers=headers,
        data=options
    )

    content = json.loads(response.content.decode('utf-8'))

    if response.status_code == 400:
        error_description = content.get('error_description','')
        raise BadRequestError(error_description)

    access_token = content.get('access_token', None)
    token_type = content.get('token_type', None)
    expires_in = content.get('expires_in', None)
    scope = content.get('scope', None)    

    return Authorization(access_token, token_type, expires_in, 
    scope, None)
```

这个函数接收配置作为参数，并使用`get_auth_key`函数传递`client_id`和`client_secret`来构建一个 base 64 编码的`auth_key`。这将被发送到 Spotify 的账户服务以请求`access_token`。

现在，是时候准备请求了。首先，我们在请求头中设置`Authorization`，值将是`Basic`字符串后跟`auth_key`。这个请求的载荷将是`grant_type`，在这种情况下是`client_credentials`，`json`将设置为`True`，告诉 API 我们希望以 JSON 格式获取响应。

我们使用 requests 包向 Spotify 的账户服务发出请求，传递我们配置的头部和数据。

当我们收到响应时，我们首先解码并将 JSON 数据加载到变量 content 中。

如果 HTTP 状态码是`400 (BAD_REQUEST)`，我们会引发一个`BadRequestError`；否则，我们会获取`access_token`、`token_type`、`expires_in`和`scope`的值，最后创建一个`Authorization`元组并返回它。

请注意，当创建一个`Authentication`的`namedtuple`时，我们将最后一个参数设置为`None`。这样做的原因是，当身份验证类型为`CLIENT_CREDENTIALS`时，Spotify 的账户服务不会返回`refresh_token`。

到目前为止，我们创建的所有函数都是私有的，所以我们要添加的最后一个函数是`authenticate`函数。这是开发人员将调用以开始身份验证过程的函数：

```py
def authenticate(conf):
    return _client_credentials(conf)
```

这个函数非常直接；函数接收一个`Config`的实例作为参数，`namedtuple`，其中包含了从配置文件中读取的所有数据。然后我们将配置传递给`_client_credentials`函数，该函数将使用客户端凭据流获取`access_token`。

让我们在`musicterminal/pytify/auth`目录中打开`__init__.py`文件，并导入`authenticate`和`get_auth_key`函数：

```py
from .auth import authenticate
from .auth import get_auth_key
```

很好！让我们在 Python REPL 中尝试一下：

```py
Python 3.6.2 (default, Oct 15 2017, 01:15:28)
[GCC 6.3.0 20170516] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> from pytify.core import read_config
>>> from pytify.auth import authenticate
>>> config = read_config()
>>> auth = authenticate(config)
>>> auth
Authorization(access_token='BQDM_DC2HcP9kq5iszgDwhgDvq7zm1TzvzXXyJQwFD7trl0Q48DqoZirCMrMHn2uUml2YnKdHOszAviSFGtE6w', token_type='Bearer', expires_in=3600, scope=None, refresh_token=None)
>>>
```

正是我们所期望的！下一步是开始创建将消耗 Spotify 的 REST API 的函数。

# 实现授权码流程

在这一部分，我们将实现授权码流程，这是我们将在客户端中使用的流程。我们需要使用这种身份验证流程，因为我们需要从用户那里获得特殊的访问权限，以便使用我们的应用程序执行某些操作。例如，我们的应用程序将能够向 Spotify 的 Web API 发送请求，在用户的活动设备上播放某个曲目。为了做到这一点，我们需要请求`user-modify-playback-state`。

以下是授权码流程中涉及的步骤：

1.  我们的应用程序将请求授权以访问数据，并将用户重定向到 Spotify 网页上的登录页面。在那里，用户可以看到应用程序需要的所有访问权限。

1.  如果用户批准，Spotify 账户服务将向回调 URI 发送一个请求，发送一个代码和状态。

1.  当我们获得了代码后，我们发送一个新的请求，传递`client_id`、`client_secret`、`grant_type`和`code`来获取`access_token`。这一次，它将与客户端凭据流不同；我们将获得`scope`和`refresh_token`。

1.  现在，我们可以正常地向 Web API 发送请求，如果访问令牌已过期，我们可以发送另一个请求来刷新访问令牌并继续执行请求。

说到这里，在`musicterminal/pytify/auth`目录中打开`auth.py`文件，让我们添加一些更多的函数。首先，我们将添加一个名为`_refresh_access_token`的函数；你可以在`get_auth_key`函数之后添加这个函数：

```py
def _refresh_access_token(auth_key, refresh_token):

    headers = {'Authorization': f'Basic {auth_key}', }

    options = {
        'refresh_token': refresh_token,
        'grant_type': 'refresh_token',
        }

    response = requests.post(
        'https://accounts.spotify.com/api/token',
        headers=headers,
        data=options
    )

    content = json.loads(response.content.decode('utf-8'))

    if not response.ok:
        error_description = content.get('error_description', None)
        raise BadRequestError(error_description)

    access_token = content.get('access_token', None)
    token_type = content.get('token_type', None)
    scope = content.get('scope', None)
    expires_in = content.get('expires_in', None)

    return Authorization(access_token, token_type, expires_in, 
    scope, None)
```

它基本上与处理客户端凭据流的函数做同样的事情，但这次我们发送`refresh_token`和`grant_type`。我们从响应对象中获取数据并创建一个`Authorization`，`namedtuple`。

我们接下来要实现的下一个函数将利用标准库的`os`模块，因此在开始实现之前，我们需要在`auth.py`文件的顶部添加以下导入语句：

```py
import os
```

现在，我们可以继续添加一个名为`_authorization_code`的函数。您可以在`get_auth_key`函数之后添加此函数，并包含以下内容：

```py
def _authorization_code(conf):

    current_dir = os.path.abspath(os.curdir)
    file_path = os.path.join(current_dir, '.pytify')

    auth_key = get_auth_key(conf.client_id, conf.client_secret)

    try:
        with open(file_path, mode='r', encoding='UTF-8') as file:
            refresh_token = file.readline()

            if refresh_token:
                return _refresh_access_token(auth_key, 
                 refresh_token)

    except IOError:
        raise IOError(('It seems you have not authorize the 
                       application '
                       'yet. The file .pytify was not found.'))
```

在这里，我们尝试在`musicterminal`目录中打开一个名为`.pytify`的文件。这个文件将包含我们将用来刷新`access_token`的`refresh_token`。

从文件中获取`refresh_token`后，我们将其与`auth_key`一起传递给`_refresh_access_token`函数。如果由于某种原因我们无法打开文件或文件不存在于`musicterminal`目录中，将引发异常。

我们现在需要做的最后修改是在同一文件中的`authenticate`函数中。我们将为两种身份验证方法添加支持；它应该是这样的：

```py
def authenticate(conf):
    if conf.auth_method == AuthMethod.CLIENT_CREDENTIALS:
        return _client_credentials(conf)

    return _authorization_code(conf)
```

现在，我们将根据配置文件中的指定开始不同的身份验证方法。

由于身份验证函数引用了`AuthMethod`，我们需要导入它：

```py
from .auth_method import AuthMethod
```

在我们尝试这种类型的身份验证之前，我们需要创建一个小型的 Web 应用程序，它将为我们授权我们的应用程序。我们将在下一节中进行这方面的工作。

# 使用授权码流授权我们的应用程序

为了使我们的 Spotify 终端客户端正常工作，我们需要特殊的访问权限来操作用户的播放。我们通过使用授权码来做到这一点，我们需要专门请求`user-modify-playback-state`访问权限。

如果您打算为此应用程序添加更多功能，最好从一开始就添加一些其他访问权限；例如，如果您想要能够操作用户的私人和公共播放列表，您可能希望添加`playlist-modify-private`和`playlist-modify-public`范围。

您可能还希望在客户端应用程序上显示用户关注的艺术家列表，因此您还需要将`user-follow-read`包含在范围内。

对于我们将在客户端应用程序中实现的功能，请求`user-modify-playback-state`访问权限将足够。

我们的想法是使用授权码流授权我们的应用程序。我们将使用 Flask 框架创建一个简单的 Web 应用程序，该应用程序将定义两个路由。`/`根将只呈现一个简单的页面，其中包含一个链接，该链接将重定向我们到 Spotify 认证页面。

第二个根将是`/callback`，这是 Spotify 在我们的应用程序用户授权我们的应用程序访问其 Spotify 数据后将调用的端点。

让我们看看这是如何实现的，但首先，我们需要安装 Flask。打开终端并输入以下命令：

```py
pip install flask
```

安装后，您甚至可以将其包含在`requirements.txt`文件中，如下所示：

```py
$ pip freeze | grep Flask >> requirements.txt
```

命令`pip freeze`将以 requirements 格式打印所有已安装的软件包。输出将返回更多项目，因为它还将包含我们已安装的软件包的所有依赖项，这就是为什么我们使用 grep `Flask`并将其附加到`requirements.txt`文件中。

下次您要设置虚拟环境来处理这个项目时，只需运行：

```py
pip install -r requirements.txt
```

太棒了！现在，我们可以开始创建 Web 应用程序。创建一个名为`spotify_auth.py`的文件。

首先，我们添加所有必要的导入：

```py
from urllib.parse import urlencode

import requests
import json

from flask import Flask
from flask import render_template
from flask import request

from pytify.core import read_config
from pytify.core import BadRequestError
from pytify.auth import Authorization
from pytify.auth import get_auth_key
```

我们将使用`urllib.parse`模块中的`urlencode`函数来对要附加到授权 URL 的参数进行编码。我们还将使用 requests 来发送请求，以在用户授权我们的应用程序后获取`access_token`，并使用`json`包来解析响应。

然后，我们将导入与 Flask 相关的内容，以便创建一个 Flask 应用程序，`render_template`，以便将渲染的 HTML 模板返回给用户，最后是请求，以便我们可以访问 Spotify 授权服务返回给我们的数据。

我们还将导入一些我们在`pytify`模块的核心和 auth 子模块中包含的函数：`read_config`用于加载和读取 YAML 配置文件，以及`_authorization_code_request`。后者将在稍后详细解释。

我们将创建一个 Flask 应用程序和根路由：

```py
app = Flask(__name__)

@app.route("/")
def home():
    config = read_config()

    params = {
        'client_id': config.client_id,
        'response_type': 'code',
        'redirect_uri': 'http://localhost:3000/callback',
        'scope': 'user-read-private user-modify-playback-state',
    }

    enc_params = urlencode(params)
    url = f'{config.auth_url}?{enc_params}'

    return render_template('index.html', link=url)
```

太棒了！从头开始，我们读取配置文件，以便获取我们的`client_id`，还有 Spotify 授权服务的 URL。我们使用`client_id`构建参数字典；授权代码流的响应类型需要设置为`code`；`redirect_uri`是回调 URI，Spotify 授权服务将用它来将授权代码发送回给我们。最后，由于我们将向 REST API 发送指令来播放用户活动设备中的曲目，应用程序需要具有`user-modify-playback-state`权限。

现在，我们对所有参数进行编码并构建 URL。

返回值将是一个渲染的 HTML。在这里，我们将使用`render_template`函数，将模板作为第一个参数传递。默认情况下，Flask 将在一个名为`templates`的目录中搜索这个模板。这个函数的第二个参数是模型。我们传递了一个名为`link`的属性，并设置了变量 URL 的值。这样，我们可以在 HTML 模板中渲染链接，比如：`{{link}}`。

接下来，我们将添加一个函数，以在从 Spotify 的帐户服务获取授权代码后为我们获取`access_token`和`refresh_token`。创建一个名为`_authorization_code_request`的函数，内容如下：

```py
def _authorization_code_request(auth_code):
    config = read_config()

    auth_key = get_auth_key(config.client_id, config.client_secret)

    headers = {'Authorization': f'Basic {auth_key}', }

    options = {
        'code': auth_code,
        'redirect_uri': 'http://localhost:3000/callback',
        'grant_type': 'authorization_code',
        'json': True
    }

    response = requests.post(
        config.access_token_url,
        headers=headers,
        data=options
    )

    content = json.loads(response.content.decode('utf-8'))

    if response.status_code == 400:
        error_description = content.get('error_description', '')
        raise BadRequestError(error_description)

    access_token = content.get('access_token', None)
    token_type = content.get('token_type', None)
    expires_in = content.get('expires_in', None)
    scope = content.get('scope', None)
    refresh_token = content.get('refresh_token', None)

    return Authorization(access_token, token_type, expires_in, 
    scope, refresh_token)
```

这个函数与我们之前在`auth.py`文件中实现的`_refresh_access_token`函数基本相同。这里唯一需要注意的是，在选项中，我们传递了授权代码，`grant_type`设置为`authorization_code`：

```py
@app.route('/callback')
def callback():
    config = read_config()
    code = request.args.get('code', '')
    response = _authorization_code_request(config, code)

    file = open('.pytify', mode='w', encoding='utf-8')
    file.write(response.refresh_token)
    file.close()

    return 'All set! You can close the browser window and stop the 
    server.'
```

在这里，我们定义了将由 Spotify 授权服务调用以发送授权代码的路由。

我们首先读取配置，解析请求数据中的代码，并调用`_authorization_code_request`，传递我们刚刚获取的代码。

这个函数将使用这个代码发送另一个请求，并获取一个我们可以用来发送请求的访问令牌，以及一个将存储在`musicterminal`目录中名为`.pytify`的文件中的刷新令牌。

我们获取的用于向 Spotify REST API 发出请求的访问令牌有效期为 3,600 秒，或 1 小时，这意味着在一个小时内，我们可以使用相同的访问令牌发出请求。之后，我们需要刷新访问令牌。我们可以通过使用存储在`.pytify`文件中的刷新令牌来实现。

最后，我们向浏览器发送一个成功消息。

现在，为了完成我们的 Flask 应用程序，我们需要添加以下代码：

```py
if __name__ == '__main__':
    app.run(host='localhost', port=3000)
```

这告诉 Flask 在本地主机上运行服务器，并使用端口`3000`。

我们的 Flash 应用程序的`home`函数将作为响应返回一个名为 index.html 的模板化 HTML 文件。我们还没有创建该文件，所以让我们继续创建一个名为`musicterminal/templates`的文件夹，并在新创建的目录中添加一个名为`index.html`的文件，内容如下：

```py
<html>
    <head>
    </head>
    <body>
       <a href={{link}}> Click here to authorize </a>
    </body>
</html>
```

这里没有太多解释的地方，但请注意我们正在引用链接属性，这是我们在 Flask 应用程序的主页函数中传递给`render_template`函数的。我们将锚元素的`href`属性设置为链接的值。

太好了！在我们尝试这个并查看一切是否正常工作之前，还有一件事情。我们需要更改 Spotify 应用程序的设置；更具体地说，我们需要配置应用程序的回调函数，以便我们可以接收授权码。

说到这一点，前往[`beta.developer.spotify.com/dashboard/`](https://beta.developer.spotify.com/dashboard/)网站，并使用你的凭据登录。仪表板将显示我们在本章开头创建的`pytify`应用程序。点击应用程序名称，然后点击页面右上角的`EDIT SETTINGS`按钮。

向下滚动直到找到重定向 URI，在文本框中输入 http://localhost:3000/callback，然后点击添加按钮。你的配置应该如下所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-prog-bp/img/bc6aecdc-cc8d-41c2-b322-0e5104dee0e5.png)

太好了！滚动到对话框底部，点击保存按钮。

现在，我们需要运行我们刚刚创建的 Flask 应用程序。在终端中，进入项目的根目录，输入以下命令：

```py
python spotify_auth.py
```

你应该会看到类似于这样的输出：

```py
* Running on http://localhost:3000/ (Press CTRL+C to quit)
```

打开你选择的浏览器，转到`http://localhost:3000`；你将看到一个简单的页面，上面有我们创建的链接：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-prog-bp/img/6bc6cdd8-da51-453f-a117-5ac4fe18ee67.png)

点击链接，你将被发送到 Spotify 的授权服务页面。

一个对话框将显示，要求将`Pytify`应用程序连接到我们的账户。一旦你授权了它，你将被重定向回`http://localhost:3000/callback`。如果一切顺利，你应该在页面上看到`All set! You can close the browser window and stop the server`的消息。

现在，只需关闭浏览器，你就可以停止 Flask 应用程序了。

请注意，现在在`musicterminal`目录中有一个名为`.pytify`的文件。如果你查看内容，你会看到一个类似于这样的加密密钥：

```py
AQB2jJxziOvuj1VW_DOBeJh-uYWUYaR03nWEJncKdRsgZC6ql2vaUsVpo21afco09yM4tjwgt6Kkb_XnVC50CR0SdjWrrbMnr01zdemN0vVVHmrcr_6iMxCQSk-JM5yTjg4
```

现在，我们准备开始编写播放器。

接下来，我们将添加一些函数，用于向 Spotify 的 Web API 发送请求，搜索艺术家，获取艺术家专辑的列表和专辑中的曲目列表，并播放所选的曲目。

# 查询 Spotify 的 Web API

到目前为止，我们只是准备了地形，现在事情开始变得更有趣了。在这一部分，我们将创建基本函数来向 Spotify 的 Web API 发送请求；更具体地说，我们想要能够搜索艺术家，获取艺术家专辑的列表，获取该专辑中的曲目列表，最后我们想要发送一个请求来实际播放 Spotify 客户端中当前活动的曲目。可以是浏览器、手机、Spotify 客户端，甚至是视频游戏主机。所以，让我们马上开始吧！

首先，我们将在`musicterminal/pytify/core`目录中创建一个名为`request_type.py`的文件，内容如下：

```py
from enum import Enum, auto

class RequestType(Enum):
    GET = auto()
    PUT = auto()
```

我们之前已经讨论过枚举，所以我们不会详细讨论。可以说我们创建了一个包含`GET`和`PUT`属性的枚举。这将用于通知为我们执行请求的函数，我们想要进行`GET`请求还是`PUT`请求。

然后，我们可以在相同的`musicterminal/pytify/core`目录中创建另一个名为`request.py`的文件，并开始添加一些导入语句，并定义一个名为`execute_request`的函数：

```py
import requests
import json

from .exceptions import BadRequestError
from .config import read_config
from .request_type import RequestType

def execute_request(
        url_template,
        auth,
        params,
        request_type=RequestType.GET,
        payload=()):

```

这个函数有一些参数：

+   `url_template`：这是将用于构建执行请求的 URL 的模板；它将使用另一个名为`params`的参数来构建 URL

+   `auth`：是`Authorization`对象

+   `params`：这是一个包含我们将放入我们将要执行请求的 URL 中的所有参数的`dict`

+   `request`：这是请求类型；可以是`GET`或`PUT`

+   `payload`：这是可能与请求一起发送的数据

随着我们继续实现相同的功能，我们可以添加：

```py
conf = read_config()

params['base_url'] = conf.base_url

url = url_template.format(**params)

headers = {
    'Authorization': f'Bearer {auth.access_token}'
}
```

我们读取配置并将基本 URL 添加到参数中，以便在`url_template`字符串中替换它。我们在请求标头中添加`Authorization`，以及认证访问令牌：

```py
if request_type is RequestType.GET:
    response = requests.get(url, headers=headers)
else:
    response = requests.put(url, headers=headers, data=json.dumps(payload))

    if not response.text:
        return response.text

result = json.loads(response.text)
```

在这里，我们检查请求类型是否为`GET`。如果是，我们执行来自 requests 的`get`函数；否则，我们执行`put`函数。函数调用非常相似；这里唯一不同的是数据参数。如果返回的响应为空，我们只返回空字符串；否则，我们将 JSON 数据解析为`result`变量：

```py
if not response.ok:
    error = result['error']
    raise BadRequestError(
        f'{error["message"]} (HTTP {error["status"]})')

return result
```

解析 JSON 结果后，我们测试请求的状态是否不是`200`（OK）；在这种情况下，我们引发`BadRequestError`。如果是成功的响应，我们返回结果。

我们还需要一些函数来帮助我们准备要传递给 Web API 端点的参数。让我们继续在`musicterminal/pytify/core`文件夹中创建一个名为`parameter.py`的文件，内容如下：

```py
from urllib.parse import urlencode

def validate_params(params, required=None):

    if required is None:
        return

    partial = {x: x in params.keys() for x in required}
    not_supplied = [x for x in partial.keys() if not partial[x]]

    if not_supplied:
        msg = f'The parameter(s) `{", ".join(not_supplied)}` are 
        required'
        raise AttributeError(msg)

def prepare_params(params, required=None):

    if params is None and required is not None:
        msg = f'The parameter(s) `{", ".join(required)}` are 
        required'
        raise ValueErrorAttributeError(msg)
    elif params is None and required is None:
        return ''
    else:
        validate_params(params, required)

    query = urlencode(
        '&'.join([f'{key}={value}' for key, value in 
         params.items()])
    )

    return f'?{query}'
```

这里有两个函数，`prepare_params`和`validate_params`。`validate_params`函数用于识别是否有参数需要进行某种操作，但它们尚未提供。`prepare_params`函数首先调用`validate_params`，以确保所有参数都已提供，并将所有参数连接在一起，以便它们可以轻松附加到 URL 查询字符串中。

现在，让我们添加一个枚举，列出可以执行的搜索类型。在`musicterminal/pytify/core`目录中创建一个名为`search_type.py`的文件，内容如下：

```py
from enum import Enum

class SearchType(Enum):
    ARTIST = 1
    ALBUM = 2
    PLAYLIST = 3
    TRACK = 4
```

这只是一个简单的枚举，列出了四个搜索选项。

现在，我们准备创建执行搜索的函数。在`musicterminal/pytify/core`目录中创建一个名为`search.py`的文件：

```py
import requests
import json
from urllib.parse import urlencode

from .search_type import SearchType
from pytify.core import read_config

def _search(criteria, auth, search_type):

    conf = read_config()

    if not criteria:
        raise AttributeError('Parameter `criteria` is required.')

    q_type = search_type.name.lower()
    url = urlencode(f'{conf.base_url}/search?q={criteria}&type=
    {q_type}')

    headers = {'Authorization': f'Bearer {auth.access_token}'}
    response = requests.get(url, headers=headers)

    return json.loads(response.text)

def search_artist(criteria, auth):
    return _search(criteria, auth, SearchType.ARTIST)

def search_album(criteria, auth):
    return _search(criteria, auth, SearchType.ALBUM)

def search_playlist(criteria, auth):
    return _search(criteria, auth, SearchType.PLAYLIST)

def search_track(criteria, auth):
    return _search(criteria, auth, SearchType.TRACK)
```

我们首先解释`_search`函数。这个函数获取三个标准参数（我们要搜索的内容），`Authorization`对象，最后是搜索类型，这是我们刚刚创建的枚举中的一个值。

这个函数非常简单；我们首先验证参数，然后构建 URL 以进行请求，我们使用我们的访问令牌设置`Authorization`头，最后，我们执行请求并返回解析后的响应。

其他功能`search_artist`，`search_album`，`search_playlist`和`search_track`只是获取相同的参数，标准和`Authorization`对象，并将其传递给`_search`函数，但它们传递不同的搜索类型。

现在我们可以搜索艺术家，我们必须获取专辑列表。在`musicterminal/pytify/core`目录中添加一个名为`artist.py`的文件，内容如下：

```py
from .parameter import prepare_params
from .request import execute_request

def get_artist_albums(artist_id, auth, params=None):

    if artist_id is None or artist_id is "":
        raise AttributeError(
            'Parameter `artist_id` cannot be `None` or empty.')

    url_template = '{base_url}/{area}/{artistid}/{postfix}{query}'
    url_params = {
        'query': prepare_params(params),
        'area': 'artists',
        'artistid': artist_id,
        'postfix': 'albums',
        }

    return execute_request(url_template, auth, url_params)
```

因此，给定一个`artist_id`，我们只需定义 URL 模板和我们要发出请求的参数，并运行`execute_request`函数，它将负责为我们构建 URL，获取和解析结果。

现在，我们想要获取给定专辑的曲目列表。在`musicterminal/pytify/core`目录中添加一个名为`album.py`的文件，内容如下：

```py
from .parameters import prepare_params
from .request import execute_request

def get_album_tracks(album_id, auth, params=None):

    if album_id is None or album_id is '':
        raise AttributeError(
            'Parameter `album_id` cannot be `None` or empty.')

    url_template = '{base_url}/{area}/{albumid}/{postfix}{query}'
    url_params = {
        'query': prepare_params(params),
        'area': 'albums',
        'albumid': album_id,
        'postfix': 'tracks',
        }

    return execute_request(url_template, auth, url_params)
```

`get_album_tracks`函数与我们刚刚实现的`get_artist_albums`函数非常相似。

最后，我们希望能够向 Spotify 的 Web API 发送指令，告诉它播放我们选择的曲目。在`musicterminal/pytify/core`目录中添加一个名为`player.py`的文件，并添加以下内容：

```py
from .parameter import prepare_params
from .request import execute_request

from .request_type import RequestType

def play(track_uri, auth, params=None):

    if track_uri is None or track_uri is '':
        raise AttributeError(
            'Parameter `track_uri` cannot be `None` or empty.')

    url_template = '{base_url}/{area}/{postfix}'
    url_params = {
        'query': prepare_params(params),
        'area': 'me',
        'postfix': 'player/play',
        }

    payload = {
        'uris': [track_uri],
        'offset': {'uri': track_uri}
    }

    return execute_request(url_template,
                           auth,
                           url_params,
                           request_type=RequestType.PUT,
                           payload=payload)
```

这个函数与之前的函数（`get_artist_albums`和`get_album_tracks`）非常相似，只是它定义了一个有效负载。有效负载是一个包含两个项目的字典：`uris`，是应该添加到播放队列的曲目列表，和`offset`，其中包含另一个包含应该首先播放的曲目的 URI 的字典。由于我们只对一次播放一首歌感兴趣，`uris`和`offset`将包含相同的`track_uri`。

这里的最后一步是导入我们实现的新函数。在`musicterminal/pytify/core`目录下的`__init__.py`文件中，添加以下代码：

```py
from .search_type import SearchType

from .search import search_album
from .search import search_artist
from .search import search_playlist
from .search import search_track

from .artist import get_artist_albums
from .album import get_album_tracks
from .player import play
```

让我们尝试在 python REPL 中搜索艺术家的函数，以检查一切是否正常工作：

```py
Python 3.6.2 (default, Dec 22 2017, 15:38:46)
[GCC 6.3.0 20170516] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> from pytify.core import search_artist
>>> from pytify.core import read_config
>>> from pytify.auth import authenticate
>>> from pprint import pprint as pp
>>>
>>> config = read_config()
>>> auth = authenticate(config)
>>> results = search_artist('hot water music', auth)
>>> pp(results)
{'artists': {'href': 'https://api.spotify.com/v1/search?query=hot+water+music&type=artist&market=SE&offset=0&limit=20',
 'items': {'external_urls': {'spotify': 'https://open.spotify.com/artist/4dmaYARGTCpChLhHBdr3ff'},
 'followers': {'href': None, 'total': 56497},
 'genres': ['alternative emo',
 'emo',
 'emo punk', 
```

其余输出已被省略，因为太长了，但现在我们可以看到一切都正如预期地工作。

现在，我们准备开始构建终端播放器。

# 创建播放器

现在我们已经拥有了认证和使用 Spotify Rest API 所需的一切，我们将创建一个小型终端客户端，可以在其中搜索艺术家，浏览他/她的专辑，并选择要在 Spotify 客户端中播放的曲目。请注意，要使用客户端，我们将不得不从高级账户中发出访问令牌，并且我们需要在这里使用的认证流程是`AUTHENTICATION_CODE`。

我们还需要从我们应用程序的用户那里要求`user-modify-playback-state`范围，这将允许我们控制播放。说到这里，让我们开始吧！

首先，我们需要创建一个新目录，将所有客户端相关的文件保存在其中，所以继续创建一个名为`musicterminal/client`的目录。

我们的客户端只有三个视图。在第一个视图中，我们将获取用户输入并搜索艺术家。当艺术家搜索完成后，我们将切换到第二个视图，在这个视图中，将呈现所选艺术家的专辑列表。在这个视图中，用户将能够使用键盘的*上*和*下*箭头键选择列表上的专辑，并通过按*Enter*键选择专辑。

最后，当选择了一个专辑后，我们将切换到我们应用程序的第三个和最后一个视图，用户将看到所选专辑的曲目列表。与之前的视图一样，用户还可以使用键盘的*上*和*下*箭头键选择曲目；按*Enter*将向 Spotify API 发送请求，在用户可用设备上播放所选曲目。

一种方法是使用`curses.panel`。面板是一种窗口，非常灵活，允许我们堆叠、隐藏和显示、切换面板，返回到面板堆栈的顶部等等，非常适合我们的目的。

因此，让我们在`musicterminal/client`目录下创建一个名为`panel.py`的文件，内容如下：

```py
import curses
import curses.panel
from uuid import uuid1

class Panel:

    def __init__(self, title, dimensions):
        height, width, y, x = dimensions

        self._win = curses.newwin(height, width, y, x)
        self._win.box()
        self._panel = curses.panel.new_panel(self._win)
        self.title = title
        self._id = uuid1()

        self._set_title()

        self.hide()
```

我们所做的就是导入我们需要的模块和函数，并创建一个名为`Panel`的类。我们还导入`uuid`模块，以便为每个新面板创建一个 GUID。

面板的初始化器有两个参数：`title`，是窗口的标题，和`dimensions`。`dimensions`参数是一个元组，遵循 curses 的约定。它由`height`、`width`和面板应该开始绘制的位置`y`和`x`组成。

我们解包`dimensions`元组的值，以便更容易处理，然后我们使用`newwin`函数创建一个新窗口；它将具有我们在类初始化器中传递的相同尺寸。接下来，我们调用 box 函数在终端的四个边上绘制线条。

现在我们已经创建了窗口，是时候为我们刚刚创建的窗口创建面板了，调用`curses.panel.new_panel`并传递窗口。我们还设置窗口标题并创建一个 GUID。

最后，我们将面板的状态设置为隐藏。继续在这个类上工作，让我们添加一个名为`hide`的新方法：

```py
def hide(self):
    self._panel.hide()
```

这个方法非常简单；它所做的唯一的事情就是调用我们面板中的`hide`方法。

我们在初始化器中调用的另一个方法是`_set_title`；现在让我们创建它：

```py
def _set_title(self):
    formatted_title = f' {self._title} '
    self._win.addstr(0, 2, formatted_title, curses.A_REVERSE)
```

在`_set_title`中，我们通过在标题字符串的两侧添加一些额外的填充来格式化标题，然后我们调用窗口的`addstr`方法在零行、二列打印标题，并使用常量`A_REVERSE`，它将颠倒字符串的颜色，就像这样：

![

我们有一个隐藏面板的方法；现在，我们需要一个显示面板的方法。让我们添加`show`方法：

```py
def show(self):
    self._win.clear()
    self._win.box()
    self._set_title()
    curses.curs_set(0)
    self._panel.show()
```

`show`方法首先清除窗口并用`box`方法绘制其周围的边框。然后，我们再次设置`title`。`cursers.curs_set(0)`调用将禁用光标；我们在这里这样做是因为当我们在列表中选择项目时，我们不希望光标可见。最后，我们在面板中调用`show`方法。

也很好有一种方法来知道当前面板是否可见。因此，让我们添加一个名为`is_visible`的方法：

```py
def is_visible(self):
    return not self._panel.hidden()
```

在这里，我们可以在面板上使用`hidden`方法，如果面板隐藏则返回`true`，如果面板可见则返回`false`。

在这个类中的最后一步是添加比较面板的可能性。我们可以通过覆盖一些特殊方法来实现这一点；在这种情况下，我们想要覆盖`__eq__`方法，每当使用`==`运算符时都会调用它。记住我们为每个面板创建了一个`id`吗？我们现在可以使用那个`id`来测试相等性：

```py
def __eq__(self, other):
    return self._id == other._id
```

太好了！现在我们有了`Panel`基类，我们准备创建一个特殊的面板实现，其中将包含选择项目的菜单。

# 为专辑和曲目选择添加菜单

现在，我们将在`musicterminal/client/`目录中创建一个名为`menu_item.py`的文件，并且我们将从中导入一些我们需要的函数开始：

```py
from uuid import uuid1
```

我们只需要从`uuid`模块中导入`uuid1`函数，因为和面板一样，我们将为列表中的每个菜单项创建一个`id（GUID）`。

让我们首先添加类和构造函数：

```py
class MenuItem:
    def __init__(self, label, data, selected=False):
        self.id = str(uuid1())
        self.data = data
        self.label = label

        def return_id():
            return self.data['id'], self.data['uri']

        self.action = return_id
        self.selected = selected
```

`MenuItem`初始化器有三个参数，`label`项，`data`将包含 Spotify REST API 返回的原始数据，以及一个指示项目当前是否被选中的标志。

我们首先为项目创建一个 id，然后使用传递给类初始化器的参数值设置数据和标签属性的值。

列表中的每个项目都将有一个在选择列表项时执行的操作，因此我们创建一个名为`return_id`的函数，它返回一个包含项目 id 的元组（不同于我们刚刚创建的 id）。这是 Spotify 上项目的 id，URI 是 Spotify 上项目的 URI。当我们选择并播放一首歌时，后者将会很有用。

现在，我们将实现一些特殊方法，这些方法在执行项目比较和打印项目时将对我们很有用。我们要实现的第一个方法是`__eq__`：

```py
def __eq__(self, other):
    return self.id == other.id
```

这将允许我们使用`index`函数在`MenuItem`对象列表中找到特定的`MenuItem`。

我们要实现的另一个特殊方法是`__len__`方法：

```py
def __len__(self):
    return len(self.label)
```

它返回`MenuItem`标签的长度，当测量列表中菜单项标签的长度时将会用到。稍后，当我们构建菜单时，我们将使用`max`函数来获取具有最长标签的菜单项，并基于此，我们将为其他项目添加额外的填充，以便列表中的所有项目看起来对齐。

我们要实现的最后一个方法是`__str__`方法：

```py
def __str__(self):
    return self.label
```

这只是在打印菜单项时的便利性；我们可以直接调用`print(menuitem)`而不是`print(menuitem.label)`，它将调用`__str__`，返回`MenuItem`标签的值。

# 实现菜单面板

现在，我们将实现菜单面板，它将是一个容器类，容纳所有菜单项，处理事件，并在终端屏幕上执行呈现。

在我们开始实现菜单面板之前，让我们添加一个枚举，表示不同的项目对齐选项，这样我们就可以更灵活地显示菜单中的菜单项。

在`musicterminal/client`目录中创建一个名为`alignment.py`的文件，内容如下：

```py
from enum import Enum, auto

class Alignment(Enum):
    LEFT = auto()
    RIGHT = auto()
```

如果您在第一章中跟随代码，您应该是一个枚举专家。这里没有什么复杂的；我们定义了一个从 Enum 继承的`Alignment`类，并定义了两个属性，`LEFT`和`RIGHT`，它们的值都设置为`auto()`，这意味着值将自动设置为`1`和`2`。

现在，我们准备创建菜单。让我们继续在`musicterminal/client`目录中创建一个名为`menu.py`的最终类。

让我们添加一些导入和构造函数：

```py
import curses
import curses.panel

from .alignment import Alignment
from .panel import Panel

class Menu(Panel):

    def __init__(self, title, dimensions, align=Alignment.LEFT, 
                 items=[]):
        super().__init__(title, dimensions)
        self._align = align
        self.items = items
```

`Menu`类继承自我们刚刚创建的`Panel`基类，类初始化器接收一些参数：`title`，`dimensions`（包含`height`，`width`，`y`和`x`值的元组），默认为`LEFT`的`alignment`设置，以及`items`。items 参数是一个`MenuItems`对象的列表。这是可选的，如果没有指定值，它将设置为空列表。

在类初始化器中的第一件事是调用基类的`__init__`方法。我们可以使用`super`函数来做到这一点。如果您记得，`Panel`类上的`__init__`方法有两个参数，`title`和`dimension`，所以我们将它传递给基类初始化器。

接下来，我们为属性`align`和`items`赋值。

我们还需要一个方法，返回菜单项列表中当前选定的项目：

```py
def get_selected(self):
    items = [x for x in self.items if x.selected]
    return None if not items else items[0]
```

这个方法非常简单；推导返回一个选定项目的列表，如果没有选定项目，则返回`None`；否则，返回列表中的第一个项目。

现在，我们可以实现处理项目选择的方法。让我们添加另一个名为`_select`的方法：

```py
def _select(self, expr):
    current = self.get_selected()
    index = self.items.index(current)
    new_index = expr(index)

    if new_index < 0:
        return

    if new_index > index and new_index >= len(self.items):
        return

    self.items[index].selected = False
    self.items[new_index].selected = True
```

在这里，我们开始获取当前选定的项目，然后立即使用数组中的索引方法获取菜单项列表中项目的索引。这是因为我们在`Panel`类中实现了`__eq__`方法。

然后，我们开始运行作为参数传递的函数`expr`，传递当前选定项目索引的值。

`expr`将确定下一个当前项目索引。如果新索引小于`0`，这意味着我们已经到达菜单项列表的顶部，因此我们不采取任何行动。

如果新索引大于当前索引，并且新索引大于或等于列表中菜单项的数量，则我们已经到达列表底部，因此此时不需要采取任何操作，我们可以继续选择相同的项目。

但是，如果我们还没有到达列表的顶部或底部，我们需要交换选定的项目。为此，我们将当前项目的 selected 属性设置为`False`，并将下一个项目的 selected 属性设置为`True`。

`_select`方法是一个`private`方法，不打算在外部调用，因此我们定义了两个方法——`next`和`previous`：

```py
def next(self):
    self._select(lambda index: index + 1)

def previous(self):
    self._select(lambda index: index - 1)
```

下一个方法将调用`_select`方法，并传递一个 lambda 表达式，该表达式将接收一个索引并将其加一，而上一个方法将执行相同的操作，但是不是增加索引`1`，而是减去。因此，在`_select`方法中，当我们调用：

```py
new_index = expr(index)
```

我们要么调用`lambda index: index + 1`，要么调用`lambda index: index + 1`。

太好了！现在，我们将添加一个负责在屏幕上呈现菜单项之前格式化菜单项的方法。创建一个名为`_initialize_items`的方法，如下所示：

```py
def _initialize_items(self):
    longest_label_item = max(self.items, key=len)

    for item in self.items:
        if item != longest_label_item:
            padding = (len(longest_label_item) - len(item)) * ' '
            item.label = (f'{item}{padding}'
                          if self._align == Alignment.LEFT
                          else f'{padding}{item}')

        if not self.get_selected():
            self.items[0].selected = True
```

首先，我们获取具有最大标签的菜单项；我们可以通过使用内置函数`max`并传递`items`，以及作为键的另一个内置函数`len`来实现这一点。这将起作用，因为我们在菜单项中实现了特殊方法`__len__`。

在发现具有最大标签的菜单项之后，我们循环遍历列表的项目，在`LEFT`或`RIGHT`上添加填充，具体取决于对齐选项。最后，如果列表中没有被选中标志设置为`True`的菜单项，我们将选择第一个项目作为选定项目。

我们还想提供一个名为`init`的方法，它将为我们初始化列表上的项目：

```py
def init(self):
    self._initialize_items()
```

我们还需要处理键盘事件，这样当用户特别按下*上*和*下*箭头键以及*Enter*键时，我们就可以执行一些操作。

首先，我们需要在文件顶部定义一些常量。您可以在导入和类定义之间添加这些常量：

```py
NEW_LINE = 10 CARRIAGE_RETURN = 13
```

让我们继续包括一个名为`handle_events`的方法：

```py
    def handle_events(self, key):
        if key == curses.KEY_UP:
            self.previous()
        elif key == curses.KEY_DOWN:
            self.next()
        elif key == curses.KEY_ENTER or key == NEW_LINE or key == 
         CARRIAGE_RETURN:
            selected_item = self.get_selected()
            return selected_item.action
```

这个方法非常简单；它获取一个`key`参数，如果键等于`curses.KEY_UP`，那么我们调用`previous`方法。如果键等于`curses.KEY_DOWN`，那么我们调用`next`方法。现在，如果键是`ENTER`，那么我们获取选定的项目并返回其操作。操作是一个将执行另一个函数的函数；在我们的情况下，我们可能会在列表上选择艺术家或歌曲，或执行一个将播放音乐曲目的函数。

除了测试`key`是否为`curses.KEY_ENTER`之外，我们还需要检查键是否为换行符`\n`或回车符`\r`。这是必要的，因为*Enter*键的代码可能会根据应用程序运行的终端的配置而有所不同。

我们将实现`__iter__`方法，这将使我们的`Menu`类表现得像一个可迭代的对象：

```py
    def __iter__(self):
        return iter(self.items)
```

这个类的最后一个方法是`update`方法。这个方法将实际工作渲染菜单项并刷新窗口屏幕：

```py
def update(self):
    pos_x = 2
    pos_y = 2

    for item in self.items:
        self._win.addstr(
                pos_y,
                pos_x,
                item.label,
                curses.A_REVERSE if item.selected else 
                curses.A_NORMAL)
        pos_y += 1

    self._win.refresh()
```

首先，我们将`x`和`y`坐标设置为`2`，这样窗口上的菜单将从第`2`行和第`2`列开始。我们循环遍历菜单项，并调用`addstr`方法在屏幕上打印项目。

`addstr`方法获取`y`位置，`x`位置，将在屏幕上写入的字符串，在我们的例子中是`item.label`，最后一个参数是`style`。如果项目被选中，我们希望以突出显示的方式显示它；否则，它将以正常颜色显示。以下截图说明了渲染列表的样子：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-prog-bp/img/270dbea3-ceb9-4922-8216-c30ab85c7688.png)

# 创建 DataManager 类

我们已经实现了身份验证和从 Spotify REST API 获取数据的基本功能，但现在我们需要创建一个类，利用这些功能，以便获取我们需要在客户端中显示的信息。

我们的 Spotify 终端客户端将执行以下操作：

+   按名称搜索艺术家

+   列出艺术家的专辑

+   列出专辑的曲目

+   请求播放一首曲目

我们要添加的第一件事是一个自定义异常，我们可以引发，而且没有从 Spotify REST API 返回结果。在`musicterminal/client`目录中创建一个名为`empty_results_error.py`的新文件，内容如下：

```py
class EmptyResultsError(Exception):
    pass
```

为了让我们更容易，让我们创建一个称为`DataManager`的类，它将为我们封装所有这些功能。在`musicterminal/client`目录中创建一个名为`data_manager.py`的文件：

```py
from .menu_item import MenuItem

from pytify.core import search_artist
from pytify.core import get_artist_albums
from pytify.core import get_album_tracks
from pytify.core import play

from .empty_results_error import EmptyResultsError

from pytify.auth import authenticate
from pytify.core import read_config

class DataManager():

    def __init__(self):
        self._conf = read_config()
        self._auth = authenticate(self._conf)
```

首先，我们导入`MenuItem`，这样我们就可以返回带有请求结果的`MenuItem`对象。之后，我们从`pytify`模块导入函数来搜索艺术家，获取专辑，列出专辑曲目，并播放曲目。此外，在`pytify`模块中，我们导入`read_config`函数并对其进行身份验证。

最后，我们导入刚刚创建的自定义异常`EmptyResultsError`。

`DataManager`类的初始化器开始读取配置并执行身份验证。身份验证信息将存储在`_auth`属性中。

接下来，我们将添加一个搜索艺术家的方法：

```py
def search_artist(self, criteria):
    results = search_artist(criteria, self._auth)
    items = results['artists']['items']

    if not items:
        raise EmptyResultsError(f'Could not find the artist: 
        {criteria}')

    return items[0]
```

`_search_artist`方法将`criteria`作为参数，并调用`python.core`模块中的`search_artist`函数。如果没有返回项目，它将引发一个`EmptyResultsError`；否则，它将返回第一个匹配项。

在我们继续创建将获取专辑和音轨的方法之前，我们需要两个实用方法来格式化`MenuItem`对象的标签。

第一个方法将格式化艺术家标签：

```py
def _format_artist_label(self, item):
    return f'{item["name"]} ({item["type"]})'
```

在这里，标签将是项目的名称和类型，可以是专辑、单曲、EP 等。

第二个方法格式化音轨的名称：

```py
def _format_track_label(self, item):

    time = int(item['duration_ms'])
    minutes = int((time / 60000) % 60)
    seconds = int((time / 1000) % 60)

    track_name = item['name']

    return f'{track_name} - [{minutes}:{seconds}]'
```

在这里，我们提取音轨的持续时间（以毫秒为单位），将其转换为`分钟：秒`的格式，并使用音轨的名称和持续时间在方括号之间格式化标签。

之后，让我们创建一个获取艺术家专辑的方法：

```py
def get_artist_albums(self, artist_id, max_items=20):

     albums = get_artist_albums(artist_id, self._auth)['items']

     if not albums:
         raise EmptyResultsError(('Could not find any albums for'
                                  f'the artist_id: {artist_id}'))

     return [MenuItem(self._format_artist_label(album), album)
             for album in albums[:max_items]]
```

`get_artist_albums`方法接受两个参数，`artist_id`和`max_item`，它是该方法返回的专辑最大数量。默认情况下，它设置为`20`。

我们在这里首先使用`pytify.core`模块中的`get_artist_albums`方法，传递`artist_id`和`authentication`对象，并从结果中获取项目的属性，将其分配给变量专辑。如果`albums`变量为空，它将引发一个`EmptyResultsError`；否则，它将为每个专辑创建一个`MenuItem`对象的列表。

我们还可以为音轨添加另一个方法：

```py
def get_album_tracklist(self, album_id):

    results = get_album_tracks(album_id, self._auth)

    if not results:
        raise EmptyResultsError('Could not find the tracks for this 
        album')

    tracks = results['items']

    return [MenuItem(self._format_track_label(track), track)
            for track in tracks]
```

`get_album_tracklist`方法以`album_id`作为参数，我们首先使用`pytify.core`模块中的`get_album_tracks`函数获取该专辑的音轨。如果没有返回结果，我们会引发一个`EmptyResultsError`；否则，我们会构建一个`MenuItem`对象的列表。

最后一个方法实际上是将命令发送到 Spotify REST API 播放音轨的方法：

```py
def play(self, track_uri):
    play(track_uri, self._auth)
```

非常直接。在这里，我们只是将`track_uri`作为参数，并将其传递给`pytify.core`模块中的`play`函数，以及`authentication`对象。这将使音轨开始在可用设备上播放；可以是手机、您计算机上的 Spotify 客户端、Spotify 网络播放器，甚至您的游戏机。

接下来，让我们把我们建立的一切放在一起，并运行 Spotify 播放器终端。

# 是时候听音乐了！

现在，我们拥有了开始构建终端播放器所需的所有部件。我们有`pytify`模块，它提供了 Spotify RESP API 的包装器，并允许我们搜索艺术家、专辑、音轨，甚至控制运行在手机或计算机上的 Spotify 客户端。

`pytify`模块还提供了两种不同类型的身份验证——客户端凭据和授权代码——在之前的部分中，我们实现了构建使用 curses 的应用程序所需的所有基础设施。因此，让我们将所有部分粘合在一起，听一些好音乐。

在`musicterminal`目录中，创建一个名为`app.py`的文件；这将是我们应用程序的入口点。我们首先添加导入语句：

```py
import curses
import curses.panel
from curses import wrapper
from curses.textpad import Textbox
from curses.textpad import rectangle

from client import Menu
from client import DataManager
```

我们当然需要导入`curses`和`curses.panel`，这次我们还导入了`wrapper`。这用于调试目的。在开发 curses 应用程序时，它们极其难以调试，当出现问题并抛出异常时，终端将无法返回到其原始状态。

包装器接受一个`callable`，当`callable`函数返回时，它将返回终端的原始状态。

包装器将在 try-catch 块中运行可调用项，并在出现问题时恢复终端。在开发应用程序时非常有用。让我们使用包装器，这样我们就可以看到可能发生的任何问题。

我们将导入两个新函数，`Textbox`和`rectangle`。我们将使用它们创建一个搜索框，用户可以在其中搜索他们喜欢的艺术家。

最后，我们导入在前几节中实现的`Menu`类和`DataManager`。

让我们开始实现一些辅助函数；第一个是`show_search_screen`：

```py
def show_search_screen(stdscr):
    curses.curs_set(1)
    stdscr.addstr(1, 2, "Artist name: (Ctrl-G to search)")

    editwin = curses.newwin(1, 40, 3, 3)
    rectangle(stdscr, 2, 2, 4, 44)
    stdscr.refresh()

    box = Textbox(editwin)
    box.edit()

    criteria = box.gather()
    return criteria
```

它以窗口实例作为参数，这样我们就可以在屏幕上打印文本并添加我们的文本框。

`curses.curs_set`函数用于打开和关闭光标；当设置为`1`时，光标将在屏幕上可见。我们希望在搜索屏幕上这样做，以便用户知道可以从哪里开始输入搜索条件。然后，我们打印帮助文本，以便用户知道应输入艺术家的名称；最后，他们可以按*Ctrl* + *G*或*Enter*执行搜索。

创建文本框时，我们创建一个新的小窗口，高度为`1`，宽度为`40`，并且它从终端屏幕的第`3`行，第`3`列开始。之后，我们使用`rectangle`函数在新窗口周围绘制一个矩形，并刷新屏幕以使我们所做的更改生效。

然后，我们创建`Textbox`对象，传递我们刚刚创建的窗口，并调用`edit`方法，它将设置框为文本框并进入编辑模式。这将`停止`应用程序，并允许用户在文本框中输入一些文本；当用户点击*Ctrl* + *G*或*Enter*时，它将退出。

当用户完成编辑文本后，我们调用`gather`方法，它将收集用户输入的数据并将其分配给`criteria`变量，最后返回`criteria`。

我们还需要一个函数来轻松清理屏幕，让我们创建另一个名为`clean_screen`的函数：

```py
def clear_screen(stdscr):
    stdscr.clear()
    stdscr.refresh()
```

太好了！现在，我们可以开始应用程序的主入口，并创建一个名为 main 的函数，内容如下：

```py
def main(stdscr):

    curses.cbreak()
    curses.noecho()
    stdscr.keypad(True)

    _data_manager = DataManager()

    criteria = show_search_screen(stdscr)

    height, width = stdscr.getmaxyx()

    albums_panel = Menu('List of albums for the selected artist',
                        (height, width, 0, 0))

    tracks_panel = Menu('List of tracks for the selected album',
                        (height, width, 0, 0))

    artist = _data_manager.search_artist(criteria)

    albums = _data_manager.get_artist_albums(artist['id'])

    clear_screen(stdscr)

    albums_panel.items = albums
    albums_panel.init()
    albums_panel.update()
    albums_panel.show()

    current_panel = albums_panel

    is_running = True

    while is_running:
        curses.doupdate()
        curses.panel.update_panels()

        key = stdscr.getch()

        action = current_panel.handle_events(key)

        if action is not None:
            action_result = action()
            if current_panel == albums_panel and action_result is 
            not None:
                _id, uri = action_result
                tracks = _data_manager.get_album_tracklist(_id)
                current_panel.hide()
                current_panel = tracks_panel
                current_panel.items = tracks
                current_panel.init()
                current_panel.show()
            elif current_panel == tracks_panel and action_result is  
            not None:
                _id, uri = action_result
                _data_manager.play(uri)

        if key == curses.KEY_F2:
            current_panel.hide()
            criteria = show_search_screen(stdscr)
            artist = _data_manager.search_artist(criteria)
            albums = _data_manager.get_artist_albums(artist['id'])

            clear_screen(stdscr)
            current_panel = albums_panel
            current_panel.items = albums
            current_panel.init()
            current_panel.show()

        if key == ord('q') or key == ord('Q'):
            is_running = False

        current_panel.update()

try:
    wrapper(main)
except KeyboardInterrupt:
    print('Thanks for using this app, bye!')
```

让我们将其分解为其组成部分：

```py
curses.cbreak()
curses.noecho()
stdscr.keypad(True)
```

在这里，我们进行一些初始化。通常，curses 不会立即注册按键。当按键被输入时，这称为缓冲模式；用户必须输入一些内容，然后按*Enter*。在我们的应用程序中，我们不希望出现这种行为；我们希望按键在用户输入后立即注册。这就是`cbreak`的作用；它关闭 curses 的缓冲模式。

我们还使用`noecho`函数来读取按键并控制何时在屏幕上显示它们。

我们做的最后一个 curses 设置是打开键盘，这样 curses 将负责读取和处理按键，并返回表示已按下的键的常量值。这比尝试自己处理并测试键码数字要干净得多，更易于阅读。

我们创建`DataManager`类的实例，以便获取我们需要在菜单上显示的数据并执行身份验证：

```py
_data_manager = DataManager()
```

现在，我们创建搜索对话框：

```py
criteria = show_search_screen(stdscr)
```

我们调用`show_search_screen`函数，传递窗口的实例；它将在屏幕上呈现搜索字段并将结果返回给我们。当用户输入完成时，用户输入将存储在`criteria`变量中。

在获取条件后，我们调用`get_artist_albums`，它将首先搜索艺术家，然后获取艺术家专辑列表并返回`MenuItem`对象的列表。

当专辑列表返回时，我们可以创建其他带有菜单的面板：

```py
height, width = stdscr.getmaxyx()

albums_panel = Menu('List of albums for the selected artist',
                    (height, width, 0, 0))

tracks_panel = Menu('List of tracks for the selected album',
                    (height, width, 0, 0))

artist = _data_manager.search_artist(criteria)

albums = _data_manager.get_artist_albums(artist['id'])

clear_screen(stdscr)
```

在这里，我们获取主窗口的高度和宽度，以便我们可以创建具有相同尺寸的面板。`albums_panel`将显示专辑，`tracks_panel`将显示曲目；如前所述，它将具有与主窗口相同的尺寸，并且两个面板将从第`0`行，第`0`列开始。

之后，我们调用`clear_screen`准备窗口以渲染带有专辑的菜单窗口：

```py
albums_panel.items = albums
albums_panel.init()
albums_panel.update()
albums_panel.show()

current_panel = albums_panel

is_running = True
```

我们首先使用专辑搜索结果设置项目的属性。我们还在面板上调用`init`，这将在内部运行`_initialize_items`，格式化标签并设置当前选定的项目。我们还调用`update`方法，这将实际打印窗口中的菜单项；最后，我们展示如何将面板设置为可见。

我们还定义了`current_panel`变量，它将保存当前在终端上显示的面板的实例。

`is_running`标志设置为`True`，并将在应用程序的主循环中使用。当我们想要停止应用程序的执行时，我们将其设置为`False`。

现在，我们进入应用程序的主循环：

```py
while is_running:
    curses.doupdate()
    curses.panel.update_panels()

    key = stdscr.getch()

    action = current_panel.handle_events(key)
```

首先，我们调用`doupdate`和`update_panels`：

+   `doupdate`：Curses 保留两个表示物理屏幕（在终端屏幕上看到的屏幕）和虚拟屏幕（保持下一个更新的屏幕）的数据结构。`doupdate`更新物理屏幕，使其与虚拟屏幕匹配。

+   `update_panels`：在面板堆栈中的更改后更新虚拟屏幕，例如隐藏、显示面板等。

更新屏幕后，我们使用`getch`函数等待按键按下，并将按下的键值分配给`key`变量。然后将`key`变量传递给当前面板的`handle_events`方法。

如果您还记得`Menu`类中`handle_events`的实现，它看起来像这样：

```py
def handle_events(self, key):
    if key == curses.KEY_UP:
        self.previous()
    elif key == curses.KEY_DOWN:
        self.next()
    elif key == curses.KEY_ENTER or key == NEW_LINE or key ==  
    CARRIAGE_RETURN:
    selected_item = self.get_selected()
    return selected_item.action
```

它处理`KEY_DOWN`，`KEY_UP`和`KEY_ENTER`。如果键是`KEY_UP`或`KEY_DOWN`，它将只更新菜单中的位置并设置新选择的项目，这将在下一个循环交互中更新在屏幕上。如果键是`KEY_ENTER`，我们获取所选项目并返回其操作函数。

请记住，对于两个面板，它将返回一个函数，当执行时，将返回包含项目 ID 和项目 URI 的元组。

接下来，我们处理返回的操作：

```py
if action is not None:
    action_result = action()
    if current_panel == albums_panel and action_result is not None:
        _id, uri = action_result
        tracks = _data_manager.get_album_tracklist(_id)
        current_panel.hide()
        current_panel = tracks_panel
        current_panel.items = tracks
        current_panel.init()
        current_panel.show()
    elif current_panel == tracks_panel and action_result is not 
    None:
        _id, uri = action_result
        _data_manager.play(uri)
```

如果当前面板的`handle_events`方法返回一个可调用的`action`，我们执行它并获取结果。然后，我们检查活动面板是否是第一个面板（带有专辑）。在这种情况下，我们需要获取所选专辑的曲目列表，因此我们在`DataManager`实例中调用`get_album_tracklist`。

我们隐藏`current_panel`，将当前面板切换到第二个面板（曲目面板），使用曲目列表设置项目属性，调用 init 方法使项目正确格式化并设置列表中的第一个项目为选定项目，最后我们调用`show`以便曲目面板可见。

在当前面板是`tracks_panel`的情况下，我们获取操作结果并在`DataManager`上调用 play，传递曲目 URI。它将请求在 Spotify 上活跃的设备上播放所选的曲目。

现在，我们希望有一种方法返回到搜索屏幕。当用户按下*F12*功能键时，我们这样做：

```py
if key == curses.KEY_F2:
    current_panel.hide()
    criteria = show_search_screen(stdscr)
    artist = _data_manager.search_by_artist_name(criteria)
    albums = _data_manager.get_artist_albums(artist['id'])

    clear_screen(stdscr)
    current_panel = albums_panel
    current_panel.items = albums
    current_panel.init()
    current_panel.show()
```

对于上面的`if`语句，测试用户是否按下了*F12*功能键；在这种情况下，我们希望返回到搜索屏幕，以便用户可以搜索新的艺术家。当按下*F12*键时，我们隐藏当前面板。然后，我们调用`show_search_screen`函数，以便呈现搜索屏幕，并且文本框将进入编辑模式，等待用户的输入。

当用户输入完成并按下*Ctrl*+ *G*或*Enter*时，我们搜索艺术家。然后，我们获取艺术家的专辑，并显示带有专辑列表的面板。

我们想要处理的最后一个事件是用户按下`q`或`Q`键，将`is_running`变量设置为`False`，应用程序关闭：

```py
if key == ord('q') or key == ord('Q'):
    is_running = False
```

最后，我们在当前面板上调用`update`，以便重新绘制项目以反映屏幕上的更改：

```py
current_panel.update()
```

在主函数之外，我们有代码片段，其中我们实际执行`main`函数：

```py
try:
    wrapper(main)
except KeyboardInterrupt:
    print('Thanks for using this app, bye!')
```

我们用`try` catch 包围它，所以如果用户按下*Ctrl* + *C*，将会引发`KeyboardInterrupt`异常，我们只需优雅地完成应用程序，而不会在屏幕上抛出异常。

我们都完成了！让我们试试吧！

打开终端并输入命令—`python app.py`。

您将看到的第一个屏幕是搜索屏幕：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-prog-bp/img/526e4ad4-49d1-401d-8c0c-d58064a728fd.png)

让我搜索一下我最喜欢的艺术家：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-prog-bp/img/fdc3a925-18ee-43ea-b8e1-65fe12d2ae54.png)

按下*Enter*或*Ctrl* + *G*后，您应该会看到专辑列表：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-prog-bp/img/131e336d-88eb-4ca7-a629-e2670ede056f.png)

在这里，您可以使用箭头键（*上*和*下*）来浏览专辑，并按*Enter*来选择一个专辑。然后，您将看到屏幕显示所选专辑的所有曲目：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-prog-bp/img/71f792f1-dc7c-4300-a96e-3983f7576669.png)

如果这个屏幕是一样的，您可以使用箭头键（*上*和*下*）来选择曲目，*Enter*将发送请求在您的 Spotify 活动设备上播放这首歌曲。

# 总结

在本章中，我们涵盖了很多内容；我们首先在 Spotify 上创建了一个应用程序，并学习了其开发者网站的使用方法。然后，我们学习了如何实现 Spotify 支持的两种认证流程：客户端凭据流程和授权流程。

在本章中，我们还实现了一个完整的模块包装器，其中包含了一些来自 Spotify 的 REST API 的功能。

然后，我们实现了一个简单的终端客户端，用户可以在其中搜索艺术家，浏览艺术家的专辑和曲目，最后在用户的活动设备上播放一首歌曲，这可以是计算机、手机，甚至是视频游戏主机。

在下一章中，我们将创建一个桌面应用程序，显示通过 Twitter 标签的投票数。
