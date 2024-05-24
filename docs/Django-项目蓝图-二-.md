# Django 项目蓝图（二）

> 原文：[`zh.annas-archive.org/md5/9264A540D01362E1B15A5AC7EC06D652`](https://zh.annas-archive.org/md5/9264A540D01362E1B15A5AC7EC06D652)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第三章：Djagios - Django 中的 Nagios 克隆

在本章中，我们将创建一个类似于**Nagios**的服务器状态监控解决方案。如果您从未听说过 Nagios，那是可以理解的，因为它不是在 Web 开发人员的日常对话中经常出现的东西。简而言之，Nagios 可以在一个屏幕上告诉您服务器的状态（可以达到数千台）。您可以根据条件配置警报，例如，如果某个关键服务器变得无响应，这样您就可以在用户开始注意到任何服务降级之前解决问题。Nagios 是一个令人惊叹的软件，被全球数百万组织使用。

本章的目标是创建一个类似的东西，尽管非常简单。我们的 Nagios 克隆品，创意地命名为**Djagios**，将允许用户设置监视其服务器的简单统计信息。我们将允许监视以下内容：

+   系统负载

+   磁盘使用情况

我们还将开发一个网页，用户可以在其中以漂亮的表格格式查看这些数据。用户还将看到他们的服务器的概述，以及这些系统上是否有任何活动警报。

以下是本章我们将要研究的一些内容：

+   Django 管理命令以及如何创建自定义命令

+   使用 Django shell 快速测试代码的小片段

+   Django 模型字段的复杂验证

+   内置通用视图的稍微复杂的用法

+   创建一个 API 端点以接受来自外部来源的数据

+   使用简单的共享密钥保护这些 API 端点

+   使用简单工具测试 API 端点

# 代码包

本章的代码包已经设置了一个基本的 Django 应用程序，并配置了一个 SQLite 数据库。但是，代码包中没有太多代码，因为本章不需要用户帐户或任何其他预先存在的设置。您可以解压缩代码包，创建一个新的虚拟环境，激活它，并从代码文件夹中运行以下命令以启动和运行：

```py
> pip install django
> python manage.py migrate

```

# 要求

在我们开始编写代码之前，让我们谈谈我们对最终产品的期望。如前所述，我们希望创建一个服务器监控解决方案。它将具体做什么？我们如何实现所需的功能？

由于我们对 Djagios 的灵感来自 Nagios，让我们看看 Nagios 是如何工作的。虽然 Nagios 是一个庞大的应用程序，具有可以理解的复杂编程，但它最终是一个客户端-服务器应用程序。服务器，也就是另一台计算机，包含 Nagios 安装。客户端，也就是您想要监视的系统，运行小型插件脚本来收集数据并将其推送到服务器。服务器接收这些数据点，并根据其配置情况发送警报（如果需要）。它还存储这些数据点，并可以以简单的表格布局显示它们，让您立即了解基础架构中所有计算机系统的概况。

我们将创建类似的东西。我们的服务器将是一个 Django 应用程序，将使用 HTTP 端点接受数据点。该应用程序还将包括一个网页，其中所有这些数据点将显示在客户端旁边。我们的客户端将是简单的 shell 脚本，用于将数据上传到我们的服务器。

### 注意

在本章的其余部分，我将把 Django 应用程序称为**服务器**，将您想要监视的系统称为**节点**。这些是您在编程生涯中会遇到的许多其他项目中常用的术语，它们在这些其他项目中通常意味着类似的东西。

与其一次性开发所有这些东西，我们将采取渐进式的方法。我们首先创建模型来存储我们的数据点。接下来，我们不会直接转向创建 HTTP 端点来接受数据点和客户端插件脚本，而是采取更简单的方法，想出一种方法来生成一些虚假数据进行测试。最后，我们将创建网页来向用户显示客户端节点的最新状态和触发的警报。

通过使用虚假数据进行测试，我们可以确信我们的状态页面和警报系统正常工作。然后我们可以继续下一步，即创建 HTTP 端点以从客户端和客户端插件脚本收集数据点。

在现实世界的项目中，逐步构建软件系统通常是完成项目的最佳方式。创建简单的功能并对其进行广泛测试，以确保其正常工作。一旦您对其正确性有信心，就添加更多功能并重复测试阶段。这种方式类似于建造高楼。如果您确信基础牢固，您可以一次建造一层，而不必担心整个建筑会倒在您头上。

# 模型

我们记录数据点需要记录什么信息？我们肯定需要记录发送数据的节点的名称。我们还需要记录获取数据点的时间，以便我们可以找出节点的最新状态。当然，我们需要知道数据点的类型和值。数据点的类型只是我们正在测量的数量的名称，例如 CPU 使用率，内存使用率，正常运行时间等。

目前，我认为这些是我们需要测量的所有东西：

+   节点名称

+   日期和时间

+   类型

+   价值

在考虑我们模型中需要哪些字段时，我想到了另一种方法。它涉及为每种数据点类型创建不同的模型，因此我们可以有名为`SystemLoad`，`MemoryUsage`，`DiskUsage`，`Uptime`等的 Django 模型。然而，一旦我进一步考虑了一下，我发现这样做将非常限制，因为现在每当我们想要测量新的东西时，我们都需要定义一个新的模型。在我们的模型中添加数据点的类型作为另一个字段，可以在记录新类型的信息方面给我们很大的灵活性。

后面您将看到这两种方法的利弊。

让我们在项目中开始一个新的 Django 应用程序。在命令行中，输入以下内容，确保您的虚拟环境已激活，并且您在项目文件夹中：

```py
> python manage.py startapp data_collector

```

将这个新应用程序添加到`djagios/settings.py`中的`INSTALLED_APPS`列表中，然后将我们的数据点模型添加到`data_collector/models.py`中：

```py
class DataPoint(models.Model):
    node_name = models.CharField(max_length=250)
    datetime = models.DateTimeField(auto_now_add=True)

    data_type = models.CharField(max_length=100)
    data_value = models.FloatField()
```

保存文件，然后运行迁移以将其添加到我们的数据库中：

```py
> python manage.py makemigrations data_collector
> python manage.py migrate

```

虽然模型非常简单，但有一件事情你应该知道。为了保持简单，我决定仅存储数字值；因此，`data_value`字段是`FloatField`类型。如果这是一个现实世界的项目，您可能会有一系列要求，这些要求将决定您是否可以做出相同的妥协。例如，您可能还必须记录文本值，例如，您可能正在运行的某些服务的状态。对于 Djagios，我们只接受数字值，因为我们想要测量的所有统计数据都只是数字。

# 虚假数据生成

在进行下一步，即创建状态页面之前，我们应该想出一种方法来生成一些虚假数据。这将在创建状态页面并在途中调试任何问题时帮助我们。没有任何数据，我们可能会花时间创建完美的状态页面，只是后来发现当我们添加数据时，其中的某些方面，如设计或数据布局方案，不起作用。

## Django 管理命令

Django 有一个非常有用的功能，叫做管理命令。它允许我们创建可以与我们编写的 Django 应用程序代码以及我们的模型进行交互的 Python 脚本。

我们不能只编写一个简单的 Python 脚本来导入我们的模型，原因是 Django，像所有的 Web 框架一样，有许多依赖项，并且需要进行复杂的设置，以确保在使用其功能之前一切都配置正确。例如，访问数据库取决于 Django 知道设置文件在哪里，因为它包含数据库的配置。不知道如何读取数据库，就无法查询模型。

让我们进行一个小测试。确保您的虚拟环境已激活，并且您在项目目录中。接下来，通过输入以下内容启动 Python shell：

```py
> python

```

这将启动一个新的 Python 交互式 shell，在这里您可以输入 Python 语句并立即执行它们。您会知道您在 Python shell 中，因为您的提示符将更改为`>>>`。现在，让我们尝试在这个 shell 中导入我们的`DataPoint`模型：

```py
>>> from data_collector.models import DataPoint

```

按下*Enter*，您可能会对打印的巨大错误消息感到惊讶。不用担心，您不需要阅读所有内容。最重要的部分是最后一行。它将类似于这样（尽管可能会在不同的 Django 版本之间略有变化）：

```py
django.core.exceptions.ImproperlyConfigured: Requested setting DEFAULT_INDEX_TABLESPACE, but settings are not configured. You must either define the environment variable DJANGO_SETTINGS_MODULE or call settings.configure() before accessing settings.
```

看起来令人生畏，但让我们分部分来看。冒号`:`之前的第一部分是异常名称。在这里，Django 引发了`ImproperlyConfigured`异常。然后有一句话告诉您请求了某个设置，但设置尚未配置。最后一句是关于如何解决此问题的有用消息。

虽然您可以按照错误消息中列出的步骤并使您的脚本在 Django 之外运行，但使用管理命令几乎总是最佳选择。使用管理命令，您无需手动设置 Django。在运行脚本之前，它会自动为您完成，并且您可以避免担心设置环境变量，如`DJANGO_SETTINGS_MODULE`或调用`settings.configure()`。

要创建一个新的管理命令，我们首先必须创建两个新的 Python 模块来保存我们的命令脚本。从项目根目录的命令行中输入以下内容：

```py
> mkdir -p data_collector/management/commands
> touch data_collector/management/__init__.py
> touch data_collector/management/commands/__init__.py

```

这些命令的作用是在`data_collector`模块文件夹下创建一个名为`management`的模块，然后在`management`模块中创建另一个名为`commands`的模块。我们首先创建模块的文件夹，然后创建空的`__init__.py`文件，以便 Python 将这些文件夹识别为模块。

接下来，让我们尝试创建一个简单的管理命令，只需打印出我们数据库中目前为止的数据点列表。创建一个新的`data_collector/management/commands/sample_data.py`文件，并给它以下内容：

```py
from django.core.management import BaseCommand

from data_collector.models import DataPoint

class Command(BaseCommand):
    def handle(self, *args, **options):
        print('All data points:')
        print(DataPoint.objects.all())
```

保存此文件，然后返回到命令提示符。然后运行以下命令：

```py
> python manage.py sample_data

```

您应该看到以下输出：

```py
All data points:
[]
```

就是这样。这就是创建 Django 管理命令的全部内容。正如您所看到的，我们能够在命令行上运行脚本时使用我们的`DataPoint`模型的方法，而不是作为 HTTP 响应视图的一部分运行。关于 Django 管理命令的一些注意事项如下：

+   您的命令与包含命令的文件的名称相同。

+   为了成为有效的管理命令，源文件应始终定义一个`Command`类，它将是`BaseCommand`的基类。

+   Django 将调用您的`Command`类的`handle`方法。这个方法是您想要从脚本提供的任何功能的起点。

接下来，当我们修改`sample_data.py`命令以实际添加示例数据时，我们将看一下`*args`和`**options`参数。如果您想进一步了解 Django 管理命令的信息，您应该查看[`docs.djangoproject.com/en/stable/howto/custom-management-commands/`](https://docs.djangoproject.com/en/stable/howto/custom-management-commands/)上的文档。

让我们修改我们的命令类来添加虚假数据。这是修改后的`Command`类代码：

```py
class Command(BaseCommand):
    def add_arguments(self, parser):
        parser.add_argument('node_name', type=str)
        parser.add_argument('data_type', type=str)
        parser.add_argument('data_value', type=float)

    def handle(self, *args, **options):
        node_name = options['node_name']
        data_type = options['data_type']
        data_value = options['data_value']

        new_data_point = DataPoint(node_name=node_name, data_type=data_type, data_value=data_value)
        new_data_point.save()

        print('All data points:')
        print(DataPoint.objects.all())
```

这里有一些新东西。让我们首先看一下`add_arguments`方法。大多数管理命令需要参数才能做一些有用的事情。由于我们正在向数据库添加示例数据，我们的命令将需要添加的值。这些值以参数的形式提供给命令行。如果你没有太多使用命令行的经验，参数就是在命令名称后面输入的所有东西。例如，让我们看一下我们用来在项目中创建新的 Django 应用程序的命令：

```py
> python manage.py startapp APP_NAME

```

在这里，我们使用了`startapp` Django 管理命令，这是一个内置命令，而应用程序名称是应用程序的参数。

我们希望我们的自定义命令接受三个参数：节点名称、数据类型和数据点的值。在`add_arguments`方法中，我们告诉 Django 为这个命令需要和解析三个参数。

`handle`方法的`options`参数是一个字典，保存了用户定义并传递给命令的所有参数。在`handle`方法中，我们只是将每个选项的值分配给一个变量。如果用户在调用命令时漏掉或添加了额外的参数，Django 将打印出一个错误消息，并告诉他们需要的参数是什么。例如，如果我现在调用命令而没有任何参数，会发生什么：

```py
> python manage.py sample_data
usage: manage.py sample_data [-h] [--version] [-v {0,1,2,3}]
                             [--settings SETTINGS] [--pythonpath PYTHONPATH]
                             [--traceback] [--no-color]
                             node_name data_type data_value
manage.py sample_data: error: the following arguments are required: node_name, data_type, data_value
```

如果用户忘记了如何使用管理命令，这是有用的信息。

现在我们有了变量中的参数值，我们创建一个新的数据点并保存它。最后，我们打印出数据库中所有的数据点。让我们现在尝试运行我们的命令，看看我们得到什么输出：

```py
> python manage.py sample_data web01 load 5
All data points:
[<DataPoint: DataPoint object>]
```

虽然命令成功创建了一个新的数据点，但输出并不是很有用。我们不知道这个数据点包含什么信息。让我们来修复这个问题。

## 更好的模型表示

每当 Django 打印出一个模型实例时，它首先尝试查看模型类是否定义了`__str__`方法。如果找到这个方法，它就使用它的输出；否则，它会退回到一个默认实现，只打印类名，就像我们在这里看到的那样。为了让 Django 打印出一个更有用的数据点模型表示，将这个`__str__`方法添加到我们的`DataPoint`模型类中：

```py
def __str__(self):
    return 'DataPoint for {}. {} = {}'.format(self.node_name, self.data_type, self.data_value)
```

让我们现在再次运行我们的`sample_data`命令，看看它的输出如何改变了：

```py
> python manage.py sample_data web01 load 1.0
All data points:
[<DataPoint: DataPoint for web01\. load = 5.0>, <DataPoint: DataPoint for web01\. load = 1.0]
```

好了。现在我们看到我们添加的数据点已经正确保存到数据库中。继续创建更多的数据点。使用尽可能多的不同节点名称，但尝试将数据类型限制为**load**或**disk_usage**中的一个，因为我们稍后将创建特定于这些数据类型的代码。这是我为参考添加到数据库的示例数据：

| 节点名称 | 数据类型 | 数据值 |
| --- | --- | --- |
| `web01` | `load` | `5.0` |
| `web01` | `load` | `1.0` |
| `web01` | `load` | `1.5` |
| `web01` | `disk_usage` | `0.5` |
| `web02` | `load` | `7.0` |
| `web02` | `load` | `9.0` |
| `web02` | `disk_usage` | `0.85` |
| `dbmaster` | `disk_usage` | `0.8` |
| `dbmaster` | `disk_usage` | `0.95` |

现在我们有了一种添加示例数据并将其添加到数据库中的方法，让我们创建一个状态页面，向用户展示所有这些数据。

# 状态页面

我们的状态页面需要以一种视图显示用户完整基础设施的状态。为此，表感觉像是一个合适的设计组件。由于对用户最重要的信息将是他们服务器的最新状态，我们的状态页面将需要仅显示每个节点的一行表，并且仅列出我们在数据库中为该节点拥有的每种不同数据类型的最新值。

对于我添加到数据库中的示例数据，我们理想情况下希望状态页面上有一个类似这样的表：

![状态页面](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj-pj-bp/img/00698_03_01.jpg)

正如你所看到的，我们只提到每个节点一次，并且将不同的数据类型分组，这样所有关于节点的信息都显示在一个地方，用户不必在表中搜索他们要找的内容。作为一个奖励，我们还以一种好看的方式显示最后更新的时间，而不仅仅是显示最新数据点的时间。

如果你认为像这样以一种好看和整合的方式显示我们的数据点不会简单，恐怕你是对的。我们可以使用`DataPoint.objects.all()`从数据库中获取所有数据点，然后在我们的 Python 代码中对它们进行分组，但一旦我们数据库中的数据点数量增加，这种方法就会变得低效。对于服务器监控解决方案，拥有几百万数据点并不罕见。我们不能每次用户想要查看状态页面时都去获取和分组所有百万数据点。这将使加载页面变得难以忍受缓慢。

幸运的是，SQL——用于从数据库查询数据的语言——为我们提供了一些非常强大的结构，我们可以使用它们来获取我们想要的信息，而不必遍历我们数据点表中可能有的所有数据行。让我们想想我们需要什么。

首先，我们想知道我们数据库中的不同节点名称。对于每个节点名称，我们还需要知道可用的数据类型。在我们的示例中，虽然**web01**和**web02**都有**load**和**disk_usage**数据类型可用，但**dbmaster**节点只有**disk_usage**数据类型（或指标）的数据。对于这样的情况，SQL 语言为我们提供了一个`DISTINCT`查询子句。在我们的查询中添加`DISTINCT`指示数据库仅返回唯一行。也就是说，所有重复行只返回一次。这样，我们就可以获取我们数据库中所有不同节点和数据类型的列表，而无需遍历每条记录。

我们需要进行一些实验，以找出如何将 SQL 查询转换为我们可以在 Django ORM 中使用的内容。我们可以编写我们的视图代码，然后不断更改它以找出获取我们想要的数据的正确方法，但这非常麻烦。相反，Django 为我们提供了一个非常方便的 shell 来进行这些实验。

如果你还记得，本章的开头，我向你展示了为什么你不能只启动一个 Python shell 并导入模型。Django 抱怨在使用之前没有被正确设置。相反，Django 有自己的启动 Python shell 的方式，确保在开始使用 shell 之前满足了设置 Django 的所有依赖关系。要启动这个 shell，输入以下内容：

```py
> python manage.py shell

```

像之前一样，这会让你进入一个 Python shell，你可以通过改变的提示来告诉。现在，让我们尝试导入我们的`DataPoint`模型：

```py
>>> from data_collector.models import DataPoint

```

这次你不应该会得到任何错误。现在输入以下内容：

```py
>>
> DataPoint.objects.all()
[<DataPoint: DataPoint for web01\. load = 5.0>, <DataPoint: DataPoint for web01\. load = 1.0>, <DataPoint: DataPoint for web01\. load = 1.5>, <DataPoint: DataPoint for web02\. load = 7.0>, <DataPoint: DataPoint for web02\. load = 9.0>, <DataPoint: DataPoint for dbmaster. disk_usage = 0.8>, <DataPoint: DataPoint for dbmaster. disk_usage = 0.95>, <DataPoint: DataPoint for web01\. disk_usage = 0.5>, <DataPoint: DataPoint for web02\. disk_usage = 0.85>]

```

正如你所看到的，你可以查询模型并立即看到查询的输出。Django shell 是 Django 中最有用的组件之一，你经常会发现自己在 shell 中进行实验，以找出在编写最终代码之前正确的做法。

所以，回到我们从数据库中获取不同节点名称和数据类型的问题。如果你在 Django 文档中搜索**distinct**关键字，你应该会在结果中看到这个链接：

[`docs.djangoproject.com/en/stable/ref/models/querysets/#distinct`](https://docs.djangoproject.com/en/stable/ref/models/querysets/#distinct)。

如果您阅读文档中的内容，您应该会发现这正是我们需要使用`DISTINCT`子句的原因。但是我们如何使用它呢？让我们在 shell 中尝试一下：

```py
>>> DataPoint.objects.all().distinct()
[<DataPoint: DataPoint for web01\. load = 5.0>, <DataPoint: DataPoint for web01\. load = 1.0>, <DataPoint: DataPoint for web01\. load = 1.5>, <DataPoint: DataPoint for web02\. load = 7.0>, <DataPoint: DataPoint for web02\. load = 9.0>, <DataPoint: DataPoint for dbmaster. disk_usage = 0.8>, <DataPoint: DataPoint for dbmaster. disk_usage = 0.95>, <DataPoint: DataPoint for web01\. disk_usage = 0.5>, <DataPoint: DataPoint for web02\. disk_usage = 0.85>]

```

嗯？这没有改变任何东西。为什么？让我们想想这里发生了什么。我们要求 Django 查询数据库中的所有数据点，然后仅返回每个重复数据的一行。如果您熟悉 SQL，不同的子句通过比较您选择的数据行中的每个字段来工作。但是，由于默认情况下，Django 在查询模型时会选择数据库表中的所有行，因此 SQL 查询看到的数据也包括主键，这根据定义对于每一行都是唯一的。这就是为什么我们看到所有数据，即使我们使用了不同的子句。

为了使用不同的子句，我们需要限制我们要求数据库返回给我们的数据中的字段。对于我们特定的用例，我们只需要知道节点名称和数据类型的唯一对。Django ORM 提供了另一个方法`values`，我们可以使用它来限制 Django 选择的字段。让我们首先尝试一下没有不同子句，看看返回什么数据：

```py
>>> DataPoint.objects.all().values('node_name', 'data_type')
[{'data_type': u'load', 'node_name': u'web01'}, {'data_type': u'load', 'node_name': u'web01'}, {'data_type': u'load', 'node_name': u'web01'}, {'data_type': u'load', 'node_name': u'web02'}, {'data_type': u'load', 'node_name': u'web02'}, {'data_type': u'disk_usage', 'node_name': u'dbmaster'}, {'data_type': u'disk_usage', 'node_name': u'dbmaster'}, {'data_type': u'disk_usage', 'node_name': u'web01'}, {'data_type': u'disk_usage', 'node_name': u'web02'}]

```

这似乎起了作用。现在我们的数据只包括我们想要运行不同查询的两个字段。让我们也添加不同的子句，看看我们得到了什么：

```py
>>> DataPoint.objects.all().values('node_name', 'data_type').distinct()
[{'data_type': u'load', 'node_name': u'web01'}, {'data_type': u'load', 'node_name': u'web02'}, {'data_type': u'disk_usage', 'node_name': u'dbmaster'}, {'data_type': u'disk_usage', 'node_name': u'web01'}, {'data_type': u'disk_usage', 'node_name': u'web02'}]

```

哇！这似乎起了作用。现在我们的 Django ORM 查询只返回唯一的节点名称和数据类型对，这正是我们需要的。

重要的一点要注意的是，当我们在 ORM 查询中添加了`values`方法后，返回的数据不再是我们的`DataPoint`模型类。相反，它是只包含我们要求的字段值的字典。因此，您在模型上定义的任何函数都无法在这些字典上访问。如果您仔细想想，这是显而易见的，因为没有完整的字段，Django 无法填充模型对象。即使您在`values`方法参数中列出了所有模型字段，它仍然只会返回字典，而不是模型对象。

现在我们已经弄清楚了如何以我们想要的格式获取数据，而无需循环遍历我们数据库中的每一行数据，让我们为我们的状态页面创建模板、视图和 URL 配置。从视图代码开始，将`data_collector/views.py`更改为以下内容：

```py
from django.views.generic import TemplateView

from data_collector.models import DataPoint

class StatusView(TemplateView):
    template_name = 'status.html'

    def get_context_data(self, **kwargs):
        ctx = super(StatusView, self).get_context_data(**kwargs)

        nodes_and_data_types = DataPoint.objects.all().values('node_name', 'data_type').distinct()

        status_data_dict = dict()
        for node_and_data_type_pair in nodes_and_data_types:
            node_name = node_and_data_type_pair['node_name']
            data_type = node_and_data_type_pair['data_type']

            data_point_map = status_data_dict.setdefault(node_name, dict())
            data_point_map[data_type] = DataPoint.objects.filter(
                node_name=node_name, data_type=data_type
            ).latest('datetime')

        ctx['status_data_dict'] = status_data_dict

        return ctx
```

这有点复杂，所以让我们分成几部分。首先，我们使用之前想出的查询获取节点名称和数据类型对的列表。我们将查询的结果存储在`nodes_and_data_types`中，类似于以下内容：

```py
[{'data_type': u'load', 'node_name': u'web01'}, {'data_type': u'load', 'node_name': u'web02'}, {'data_type': u'disk_usage', 'node_name': u'dbmaster'}, {
'data_type': u'disk_usage', 'node_name': u'web01'}, {'data_type': u'disk_usage', 'node_name': u'web02'}]
```

正如我们之前看到的，这是我们数据库中所有唯一的节点名称和数据类型对的列表。因此，由于我们的**dbmaster**节点没有任何**load**数据类型的数据，您在此列表中找不到该对。稍后我会解释为什么运行不同的查询有助于我们减少对数据库的负载。

接下来，我们循环遍历每对；这是您在代码中看到的 for 循环。对于每个节点名称和数据类型对，我们运行一个查询，以获取最新的数据点。首先，我们筛选出我们感兴趣的数据点，即与我们指定的节点名称和数据类型匹配的数据点。然后，我们调用`latest`方法并获取最近更新的数据点。

`latest`方法接受一个字段的名称，使用该字段对查询进行排序，然后根据该排序返回数据的最后一行。应该注意的是，`latest`可以与任何可以排序的字段类型一起使用，包括数字，而不仅仅是日期时间字段。

我想指出这里使用了`setdefault`。在字典上调用`setdefault`可以确保如果提供的键在字典中不存在，那么第二个参数传递的值将被设置为该键的值。这是一个非常有用的模式，我和很多 Python 程序员在创建字典时使用，其中所有的键都需要具有相同类型的值-在这种情况下是一个字典。

这使我们可以忽略键以前不存在于字典中的情况。如果不使用`setdefault`，我们首先必须检查键是否存在。如果存在，我们将修改它。如果不存在，我们将创建一个新的字典，修改它，然后将其分配给`status_data_dict`。

`setdefault`方法也返回给定键的值，无论它是否必须将其设置为默认值。我们在代码中将其保存在`data_point_map`变量中。

最后，我们将`status_data_dict`字典添加到上下文中并返回它。我们将在我们的模板中看到如何处理这些数据并向用户显示它。我之前说过我会解释不同的查询是如何帮助我们减少数据库负载的。让我们看一个例子。假设我们的基础设施中有相同的三个节点，我们在样本数据中看到了：**web01**，**web02**和**dbmaster**。假设我们已经运行了一整天的监控，每分钟收集所有三个节点的负载和磁盘使用情况的统计数据。做一下计算，我们应该有以下结果：

节点数 x 数据类型数 x 小时数 x60：

```py
3 x 2 x 24 x 60 = 8640

```

因此，我们的数据库有 8,640 个数据点对象。现在，有了我们在视图中的代码，我们只需要从数据库中检索六个数据点对象，就可以向用户显示一个更新的状态页面，再加上一个不同的查询。如果我们必须获取所有数据点，我们将不得不从数据库中传输所有这些 8,640 个数据点的数据，然后只使用其中的六个。

对于模板，创建一个名为`templates`的文件夹在`data_collector`目录中。然后，在模板文件夹中创建一个名为`status.html`的文件，并给它以下内容：

```py
{% extends "base.html" %}

{% load humanize %}

{% block content %}
<h1>Status</h1>

<table>
    <tbody>
        <tr>
            <th>Node Name</th>
            <th>Metric</th>
            <th>Value</th>
            <th>Last Updated</th>
        </tr>

        {% for node_name, data_type_to_data_point_map in status_data_dict.items %}
            {% for data_type, data_point in data_type_to_data_point_map.items %}
            <tr>
                <td>{% if forloop.first %}{{ node_name }}{% endif %}</td>
                <td>{{ data_type }}</td>
                <td>{{ data_point.data_value }}</td>
                <td>{{ data_point.datetime|naturaltime }}</td>
            </tr>
            {% endfor %}
        {% endfor %}
    </tbody>
</table>
{% endblock %}
```

这里不应该有太多意外。忽略`load humanize`行，我们的模板只是使用我们在视图中生成的数据字典创建一个表。两个嵌套的`for`循环可能看起来有点复杂，但看一下我们正在循环的数据应该会让事情变得清晰：

```py
{u'dbmaster': {u'disk_usage': <DataPoint: DataPoint for dbmaster. disk_usage = 0.95>},
 u'web01': {u'disk_usage': <DataPoint: DataPoint for web01\. disk_usage = 0.5>,
            u'load': <DataPoint: DataPoint for web01\. load = 1.5>},
 u'web02': {u'disk_usage': <DataPoint: DataPoint for web02\. disk_usage = 0.85>,
            u'load': <DataPoint: DataPoint for web02\. load = 9.0>}}
```

第一个 for 循环获取节点名称和将数据类型映射到最新数据点的字典。然后内部 for 循环遍历数据类型和该类型的最新数据点，并生成表行。我们使用`forloop.first`标志仅在内部循环第一次运行时打印节点名称。Django 在模板中提供了一些与 for 循环相关的其他有用的标志。查看文档[`docs.djangoproject.com/en/stable/ref/templates/builtins/#for`](https://docs.djangoproject.com/en/stable/ref/templates/builtins/#for)。

当我们打印数据点的`datetime`字段时，我们使用`naturaltime`过滤器。这个过滤器是 Django 提供的 humanize 模板标签的一部分，这就是为什么我们需要在模板的开头使用`load humanize`行。`naturaltime`模板过滤器以易于人类理解的格式输出日期时间值，例如，两秒前，一小时前，20 分钟前等等。在你加载`humanize`模板标签之前，你需要将`django.contrib.humanize`添加到`djagios/settings.py`的`INSTALLED_APPS`列表中。

完成我们的状态页面的最后一步是将其添加到 URL 配置中。由于状态页面是用户最常想要从监控系统中看到的页面，让我们把它作为主页。让`djagios/urls.py`中的 URL 配置文件包含以下内容：

```py
from django.conf.urls import url

from data_collector.views import StatusView

urlpatterns = [
    url(r'^$', StatusView.as_view(), name='status'),
]
```

就是这样。运行开发服务器：

```py
> python manage.py runserver

```

访问`http://127.0.0.1:8000`上的状态页面。如果您迄今为止已经按照步骤进行操作，您应该会看到一个类似以下页面的状态页面。当然，您的页面将显示来自您的数据库的数据：

![状态页面](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj-pj-bp/img/00698_03_02.jpg)

# 警报

现在我们已经有了一个基本的状态页面，让我们谈谈允许用户配置一些警报条件。目前，我们将通过在状态页面上以红色显示该节点的信息来通知用户任何警报条件。

首先，我们需要弄清楚我们希望用户设置什么样的警报。从那里，我们可以弄清楚技术细节。所以，让我们考虑一下。鉴于我们记录的所有数据类型都具有数值数值，用户应该能够设置阈值是有意义的。例如，他们可以设置警报，如果任何节点的系统负载超过 1.0，或者如果节点的磁盘使用率超过 80%。

此外，也许我们的用户不希望为每个节点设置相同的警报条件。数据库节点预计会处理大量的系统负载，因此也许我们的用户希望为数据库节点设置单独的警报条件。最后，如果他们正在对一些节点进行维护，他们可能希望停止一些警报的触发。

从所有这些来看，似乎我们的警报需要具有以下字段：

+   触发的数据类型

+   触发的最大值

+   触发的最小值

+   触发的节点名称

+   如果警报当前处于活动状态

其中，数据类型和活动状态是必填字段，不应为空。节点名称可以是空字符串，在这种情况下，将检查每个节点的警报条件。如果节点名称不是空字符串，则将检查名称与提供的字符串完全匹配的节点。

至于最大值和最小值，其中一个是必需的。这样用户可以仅设置最大值的警报，而不必关心数据点的最小值。这将需要在模型中进行手动验证。

## 模型

让我们看看模型。为了保持简单，我们将使用`data_collector`应用程序，而不是为警报创建一个新的应用程序。以下是我们的`Alert`模型的代码。将其放在`data_collector/models.py`中的`DataPoint`模型代码之后：

```py
class Alert(models.Model):
    data_type = models.CharField(max_length=100)
    min_value = models.FloatField(null=True, blank=True)
    max_value = models.FloatField(null=True, blank=True)
    node_name = models.CharField(max_length=250, blank=True)

    is_active = models.BooleanField(default=True)

    def save(self, *args, **kwargs):
        if self.min_value is None and self.max_value is None:
            raise models.exceptions.ValidationError('Both min and max value can not be empty for an alert')

        super(Alert, self).save(*args, **kwargs)
```

由于我们对最小和最大字段的特殊要求，我们不得不重写`save`方法。您可能已经注意到，我们的自定义`save`方法如果未设置最小和最大值，则会引发错误。由于没有办法使用正常的 Django 字段配置表达这种条件，我们不得不重写`save`方法并在这里添加我们的自定义逻辑。如果您有一些依赖于多个字段的自定义验证要求，这在 Django 中是一种非常常见的做法。

还有一件事要注意，那就是对最小和最大`FloatField`的`blank=True`参数。这是必需的，以便从该模型构建的任何模型表单（稍后我们将用于`create`和`update`视图）允许这些字段的空值。

创建并运行迁移以将其添加到您的数据库中。

```py
> python manage.py makemigrations data_collector
> python manage.py migrate data_collector

```

## 管理视图

用户将需要一些视图来管理警报。他们将需要页面来查看系统中定义的所有警报，创建新警报和编辑现有警报的页面，以及删除不再需要的警报的某种方式。所有这些都可以使用 Django 提供的通用视图和一些模板来实现。让我们开始吧！

首先，让我们先看看列表视图。将其添加到`data_collector/views.py`中：

```py
class AlertListView(ListView):
    template_name = 'alerts_list.html'
    model = Alert
```

记得从`django.views.generic`中导入`ListView`和从`data_collector.models`中导入`Alert`。接下来，在`data_collector/templates`中创建`alerts_list.html`模板文件，并给它以下内容：

```py
{% extends "base.html" %}

{% block content %}
<h1>Defined Alerts</h1>

{% if object_list %}
<table>
    <tr>
        <th>Data Type</th>
        <th>Min Value</th>
        <th>Max Value</th>
        <th>Node Name</th>
        <th>Is Active</th>
    </tr>

    {% for alert in object_list %}
    <tr>
        <td>{{ alert.data_type }}</td>
        <td>{{ alert.min_value }}</td>
        <td>{{ alert.max_value }}</td>
        <td>{{ alert.node_name }}</td>
        <td>{{ alert.is_active }}</td>
    </tr>
    {% endfor %}
</table>
{% else %}
<i>No alerts defined</i>
{% endif %}
{% endblock %}
```

最后，编辑`djagios/urls.py`。导入新视图，然后将其添加到 URL 模式中：

```py
url(r'^alerts/$', AlertListView.as_view(), name='alerts-list'),
```

要测试它，打开`http://127.0.0.1:8000/alerts/`。你应该会看到**没有定义警报**的消息。列表视图非常基本。`ListVew`通用视图使用指定模型的所有对象渲染模板，提供`object_list`模板上下文变量中的对象列表。接下来，让我们看看创建新警报的视图。

在`data_collector/view.py`文件中，首先导入以下内容：

```py
from django.core.urlresolvers import reverse
from django.views.generic import CreateView
```

然后添加这个视图类：

```py
class NewAlertView(CreateView):
    template_name = 'create_or_update_alert.html'
    model = Alert
    fields = [
        'data_type', 'min_value', 'max_value', 'node_name', 'is_active'
    ]

    def get_success_url(self):
        return reverse('alerts-list')
```

在视图代码中没有新内容。模板代码也非常简单。将这段代码放入`data_collector/templates/create_or_update_alert.html`中：

```py
{% extends "base.html" %}

{% block content %}
{% if object %}
<h1>Update Alert</h1>
{% else %}
<h1>New Alert</h1>
{% endif %}

<form action="" method="post">{% csrf_token %}
    {{ form.as_p }}
    <input type="submit" value="{% if object %}Update{% else %}Create{% endif %}" />
    <a href="{% url 'alerts-list' %}">Cancel</a>
</form>
{% endblock %}
```

和以前的章节一样，我们使用`object`上下文变量来决定这个模板是从`CreateView`还是`UpdateView`中使用的，并根据此更改一些元素。否则，它非常直接了当。让我们也看看`UpdateView`的代码：

```py
class EditAlertView(UpdateView):
    template_name = 'create_or_update_alert.html'
    model = Alert
    fields = [
        'data_type', 'min_value', 'max_value', 'node_name', 'is_active'
    ]

    def get_success_url(self):
        return reverse('alerts-list')
```

这几乎是前一个创建视图的完全相同的副本。确保你已经导入了`UpdateView`通用视图。我们仍然需要将这两个视图添加到我们的 URL 配置中。在`djagios/urls.py`文件中，导入`NewAlertView`和`EditAlertView`，并添加这些模式：

```py
url(r'^alerts/new/$', NewAlertView.as_view(), name='alerts-new'),
url(r'^alerts/(?P<pk>\d+)/edit/$', EditAlertView.as_view(), name='alerts-edit'),
```

在我们测试这些视图之前，我们应该添加链接，让用户可以到达这些视图。修改`alerts_list.html`模板以匹配这段代码：

```py
{% extends "base.html" %}

{% block content %}
<h1>Defined Alerts</h1>

{% if object_list %}
<table>
    <tr>
        <th>Data Type</th>
        <th>Min Value</th>
        <th>Max Value</th>
        <th>Node Name</th>
        <th>Is Active</th>
    </tr>

    {% for alert in object_list %}
    <tr>
        <td>{{ alert.data_type }}</td>
        <td>{{ alert.min_value }}</td>
        <td>{{ alert.max_value }}</td>
        <td>{{ alert.node_name }}</td>
        <td>{{ alert.is_active }}</td>
        <td><a href="{% url 'alerts-edit' pk=alert.pk %}">Edit</a></td>
    </tr>
    {% endfor %}
</table>
{% else %}
<i>No alerts defined</i>
{% endif %}
<p><a href="{% url 'alerts-new' %}">Add New Alert</a></p>
{% endblock %}
```

已添加了两行新的高亮显示的行。现在，让我们看看我们的警报列表页面是什么样子的。和以前一样，在浏览器中打开`http://127.0.0.1:8000/alerts/`。你应该会看到以下页面：

![管理视图](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj-pj-bp/img/00698_03_03.jpg)

点击**添加新警报**链接，你应该会看到创建警报的表单。填写一些示例数据，然后点击**创建**按钮。如果你的表单没有任何错误，你应该会回到警报列表视图，并且你的屏幕现在应该列出新的警报，如下面的截图所示：

![管理视图](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj-pj-bp/img/00698_03_04.jpg)

现在剩下的就是允许用户删除他们的警报的选项。为此，创建一个从通用`DeleteView`继承的视图，记得首先从`django.views.generic`中导入`DeleteView`。以下是你应该放入`data_collector/view.py`中的代码：

```py
class DeleteAlertView(DeleteView):
    template_name = 'delete_alert.html'
    model = Alert

    def get_success_url(self):
        return reverse('alerts-list')
```

创建一个新的`data_collector/templates/delete_alert.html`模板：

```py
{% extends "base.html" %}

{% block content %}
<h1>Delete alert?</h1>
<p>Are you sure you want to delete this alert?</p>
<form action="" method="post">{% csrf_token %}
    {{ form.as_p }}
    <input type="submit" value="Delete" />
    <a href="{% url 'alerts-list' %}">Cancel</a>
</form>
{% endblock %}
```

接下来，在`djagios/urls.py`中导入`DeleteAlertView`，并添加这个新的模式：

```py
url(r'^alerts/(?P<pk>\d+)/delete/$', DeleteAlertView.as_view(), name='alerts-delete'),
```

最后，让我们从警报列表页面添加一个链接到删除视图。编辑`alerts_list.html`模板，在**编辑**链接后面添加这一行：

```py
<td><a href="{% url 'alerts-delete' pk=alert.pk %}">Delete</a></td>
```

现在当你打开警报列表视图时，你应该会看到一个**删除**链接。你的屏幕应该看起来类似于以下截图：

![管理视图](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj-pj-bp/img/00698_03_05.jpg)

如果你点击**删除**链接，你应该会看到一个确认页面。如果你确认删除，你会发现你的警报将从列表页面消失。这些是我们需要管理警报的所有视图。让我们继续检测警报条件并在状态页面显示它们。

# 在状态页面显示触发的警报

正如我之前所说，我们希望我们的用户在状态页面上看到任何触发警报的节点都被突出显示。假设他们定义了一个警报，当任何节点的磁盘使用率超过`0.85`时触发，而我们对**dbmaster**磁盘使用率的最新数据点的值为`0.9`。当用户访问状态页面时，我们希望显示**dbmaster**节点的磁盘使用情况的行以红色突出显示，以便用户立即意识到警报并能够采取措施纠正这一情况。

将`data_collector/view.py`中的`StatusView`更改为匹配以下代码。更改的部分已经高亮显示：

```py
class StatusView(TemplateView):
    template_name = 'status.html'

    def get_context_data(self, **kwargs):
        ctx = super(StatusView, self).get_context_data(**kwargs)

        alerts = Alert.objects.filter(is_active=True)

        nodes_and_data_types = DataPoint.objects.all().values('node_name', 'data_type').distinct()

        status_data_dict = dict()
        for node_and_data_type_pair in nodes_and_data_types:
            node_name = node_and_data_type_pair['node_name']
            data_type = node_and_data_type_pair['data_type']

            latest_data_point = DataPoint.objects.filter(node_name=node_name, data_type=data_type).latest('datetime')
 latest_data_point.has_alert = self.does_have_alert(latest_data_point, alerts)

            data_point_map = status_data_dict.setdefault(node_name, dict())
            data_point_map[data_type] = latest_data_point

        ctx['status_data_dict'] = status_data_dict

        return ctx

    def does_have_alert(self, data_point, alerts):
 for alert in alerts:
 if alert.node_name and data_point.node_name != alert.node_name:
 continue

 if alert.data_type != data_point.data_type:
 continue

 if alert.min_value is not None and data_point.data_value < alert.min_value:
 return True
 if alert.max_value is not None and data_point.data_value > alert.max_value:
 return True

 return False

```

我们在这里所做的是，对于我们检索到的每个数据点，检查它是否触发了任何警报。我们通过比较每个警报中的最小值和最大值与数据点值来做到这一点，但只有当数据点数据类型和节点名称与警报中的匹配时。如果数据点值超出了警报范围，我们将标记数据点为触发了警报。

这是我在许多项目中经常使用的另一种技术。由于模型只是 Python 对象，你可以在运行时向它们附加额外的信息。不需要在`DataPoint`类上定义`has_alert`。只需在需要时将其添加到对象中。不过要小心。这样做并不是一个好的编程实践，因为试图理解`DataPoint`类的人将不知道`has_alert`属性甚至存在，除非他们查看视图类的代码。由于我们只在视图和模板中使用这个属性，对我们来说是可以的。但是，如果我们传递`DataPoint`对象并且更多的代码开始使用这个属性，最好还是在类本身上定义它，这样查看类代码的人就会知道它的存在。

我们还需要修改`status.html`模板，以利用我们已经添加到数据点的`has_alert`属性。将其更改为以下代码。与之前一样，修改的部分已经被突出显示：

```py
{% extends "base.html" %}

{% load humanize %}

{% block content %}
<h1>Status</h1>

<table>
    <tbody>
        <tr>
            <th>Node Name</th>
            <th>Metric</th>
            <th>Value</th>
            <th>Last Updated</th>
        </tr>

        {% for node_name, data_type_to_data_point_map in status_data_dict.items %}
            {% for data_type, data_point in data_type_to_data_point_map.items %}
            <tr {% if data_point.has_alert %}class="has-alert"{% endif %}>
                <td>{% if forloop.first %}{{ node_name }}{% endif %}</td>
                <td>{{ data_type }}</td>
                <td>{{ data_point.data_value }}</td>
                <td>{{ data_point.datetime|naturaltime }}</td>
            </tr>
            {% endfor %}
        {% endfor %}
    </tbody>
</table>

<style type="text/css" media="all">
 tr.has-alert td:not(:first-child) {
 color: red;
 }
</style>
{% endblock %}
```

就是这样。为了测试它，你需要创建一些在你的数据库中由`DataPoints`触发的`Alert`对象。对于我使用的示例数据，我创建了一个数据类型为**disk_usage**，最大值为 0.5 的`Alert`对象。创建警报后，我的状态屏幕突出显示了触发警报的节点。你的屏幕会显示类似的内容：

![在状态页面上显示触发的警报](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj-pj-bp/img/00698_03_06.jpg)

为了测试我们的突出显示代码是否正确工作，我添加了另一个**dbmaster**磁盘使用率指标的数据点，使用以下命令：

```py
> python manage.py sample_data dbmaster disk_usage 0.2

```

刷新状态页面后，**dbmaster**节点的警报条件消失了。你应该进行类似的测试来亲自看看。

就是这样！虽然很辛苦，但我们的监控工具现在开始成形了。我们有一个显示最新节点状态的状态页面，突出显示任何有警报的节点。一旦警报条件解决，突出显示就会消失。我们也有一个页面来管理我们的警报。总的来说，我们可以说应用程序的用户界面部分几乎已经完成了。一个相当有帮助的东西是一个导航栏。在`templates/base.html`的`body`标签开始后添加这个：

```py
<ul>
    <li><a href="{% url 'status' %}">Home</a></li>
    <li><a href="{% url 'alerts-list' %}">Alerts</a></li>
</ul>
```

刷新状态页面，你应该会看到页面顶部有一个简单的导航菜单。

# 接受来自远程系统的数据

现在用户可以看到他们基础设施的状态并管理警报了，是时候继续下一步了：从真实来源获取数据，而不是使用 Django 管理命令输入示例数据。

为此，我们将创建一个接受来自远程系统的 API 端点。API 端点只是一个不需要渲染模板的 Django 视图的花哨名称。API 端点的响应通常要么只是一个 200 OK 状态，要么是一个 JSON 响应。API 端点不是为人类用户使用的。相反，它们是为不同的软件系统连接在一起并共享信息而设计的。

我们需要创建的 API 端点将是一个简单的视图，接受一个带有创建新`DataPoint`对象所需信息的 POST 请求。为了确保恶意用户不能用随机数据垃圾邮件式地填充我们的数据库，我们还将在 API 端点中添加一个简单的身份验证机制，以便它只接受来自授权来源的数据。

要创建一个 API 端点，我们将使用`django.view.generic.View`类，只实现 POST 处理程序。为了解析请求数据，我们将动态创建一个模型表单。编辑`data_collector/views.py`并添加以下代码：

```py
from django.forms.models import modelform_factory
from django.http.response import HttpResponse
from django.http.response import HttpResponseBadRequest
from django.http.response import HttpResponseForbidden
from django.views.generic import View

class RecordDataApiView(View):
    def post(self, request, *args, **kwargs):
        # Check if the secret key matches
        if request.META.get('HTTP_AUTH_SECRET') != 'supersecretkey':
            return HttpResponseForbidden('Auth key incorrect')

        form_class = modelform_factory(DataPoint, fields=['node_name', 'data_type', 'data_value'])
        form = form_class(request.POST)
        if form.is_valid():
            form.save()
            return HttpResponse()
        else:
            return HttpResponseBadRequest()
```

这里有一些新的东西需要我们注意。首先，我们使用了请求对象的`META`属性来访问请求。如果您了解 HTTP 协议的工作原理，您应该熟悉头部。如果不了解，可以在[`www.jmarshall.com/easy/http/`](https://www.jmarshall.com/easy/http/)找到一个很好的解释。详细解释头部超出了本书的范围，但简单地说，头部是客户端在 HTTP 请求中添加的额外信息。在下一节中，当我们测试 API 视图时，我们将看到如何添加它们。

Django 会自动规范化所有头部名称并将它们添加到`META`字典中。在这里，我们使用自定义头部**Auth-Secret**来确保只有拥有我们秘钥的客户端才能使用这个视图。

### 注意

有关 META 字典中的内容以及其构造方式的更多信息，请参阅 Django 文档[`docs.djangoproject.com/en/stable/ref/request-response/#django.http.HttpRequest.META`](https://docs.djangoproject.com/en/stable/ref/request-response/#django.http.HttpRequest.META)。

接下来，我们需要看的是`modelform_factory`函数。这是 Django 提供的一个很好的小函数，它返回给定模型的`ModelForm`子类。您可以使用此函数的参数对模型表单进行一定程度的自定义。在这里，我们限制了可以编辑的字段数量。为什么首先使用模型表单呢？

我们从 API 端点中想要的是创建新的`DataPoint`模型的方法。模型表单正好提供了我们需要做到这一点的功能，而且它们还为我们处理了数据验证。我们本可以在`forms.py`文件中创建一个单独的模型表单类，然后像以前一样在视图中使用它，但我们没有这样做的两个原因。

首先，这是我们的代码中唯一使用模型表单的地方，用于`DataPoint`方法。如果我们需要在其他地方也使用它，那么在单个地方定义模型表单将是最佳的编程实践。然而，由于我们不需要，在需要时动态定义模型表单就可以了。

其次，我们不需要对模型表单类进行任何自定义。如果我们想要，比如，像之前所做的那样覆盖`save`方法，我们将被迫定义类而不是使用`modelform_factory`方法。

获取模型表单类之后，我们可以像使用任何模型表单类一样使用它，要么创建新的数据点，要么返回指示数据验证失败的响应。要使我们的新端点通过 URL 可用，请在`djagios/urls.py`中导入以下内容：

```py
from django.views.decorators.csrf import csrf_exempt
from data_collector.views import RecordDataApiView
```

然后，添加此 URL 模式：

```py
url(r'^record/$', csrf_exempt(RecordDataApiView.as_view()), name='record-data'),
```

使用`csrf_exempt`装饰器是因为默认情况下，Django 对 POST 请求使用 CSRF 保护。然而，这通常用于 Web 表单，而不是 API 端点。因此，我们必须禁用它，否则 Django 不会允许我们的 POST 请求成功。现在，让我们看看如何测试我们的新视图。

### 提示

您可以在[`docs.djangoproject.com/en/stable/ref/csrf/`](https://docs.djangoproject.com/en/stable/ref/csrf/)获取有关 Django 提供的 CSRF 保护的更多信息。

## 测试 API 端点

您不能简单地在浏览器中测试此 API 端点，因为它是一个 POST 请求，而且没有模板可以在浏览器中呈现一个表单。但是，有很多很好的工具可用于进行手动的 POST 请求。我建议您使用的是 Postman。它是一个 Google Chrome 应用，因此您不需要安装任何依赖项。只要您的计算机上安装了 Google Chrome，您就可以从[`www.getpostman.com/`](https://www.getpostman.com/)获取 Postman。安装后，启动它，您应该看到一个类似以下屏幕的界面。如果您的 Postman 界面不完全相同，不要担心。可能是您下载的版本更新了。Postman 的主要部分应该是相同的。

![测试 API 端点](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj-pj-bp/img/00698_03_07.jpg)

使用 Postman 很简单。我将逐步为您讲解整个过程，包括每个步骤的图像，以便清楚地说明我的意思。在这个过程结束时，我们应该能够使用我们的 API 端点生成一个新的数据点。

顺便说一句，如果您使用的是 Linux 或 Unix 操作系统，如 Ubuntu 或 Mac OS X，并且更习惯使用命令行，您可以使用`curl`实用程序来进行 POST 请求。对于更简单的请求，它通常更快。要使用`curl`进行与我在 Postman 中演示的相同请求，请在命令提示符上键入以下内容：

```py
> c
url http://127.0.0.1:8000/record/ -H 'Auth-Secret: supersecretkey' -d node_name=web01 -d data_type=disk_usage -d data_value=0.2

```

要使用 Postman 进行此请求，请执行以下步骤：

1.  选择请求类型。我们要进行 POST 请求，因此从下拉菜单中选择 POST：![测试 API 端点](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj-pj-bp/img/00698_03_08.jpg)

1.  输入您要发出请求的 URL。在我们的情况下，它是`http://127.0.0.1:8000/record/`：![测试 API 端点](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj-pj-bp/img/00698_03_09.jpg)

1.  添加我们的自定义身份验证标头。打开**标头**选项卡，并添加值为**supersecretkey**的**Auth-Secret**标头：![测试 API 端点](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj-pj-bp/img/00698_03_10.jpg)

1.  最后，将我们的 POST 参数添加到**Body**部分。我使用的示例数据如下：

+   node_name: `web01`

+   data_type: `disk_usage`

+   data_value: `0.72`

![测试 API 端点](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj-pj-bp/img/00698_03_11.jpg)

就是这样。我们的请求现在已经设置好了。单击 URL 文本框旁边的**发送**按钮，您应该在参数体下方看到一个空的响应。要确认请求是否正常工作，请查看响应的状态代码。它应该是**200 OK**：

![测试 API 端点](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj-pj-bp/img/00698_03_12.jpg)

打开我们应用程序的状态页面`http://127.0.0.1:8000/`，您应该看到最新的数据点值显示在那里。就是这样，我们完成了！

### 注意

正如本节开头所解释的那样，您还可以使用诸如`curl`之类的命令行工具来上传数据到 API。使用这样的工具，您可以编写 shell 脚本，自动从计算机系统更新 Web 应用程序的真实数据。这也是 Nagios 和许多数据监控工具的运行方式。服务器有 API 端点来监听数据，然后简单的脚本从客户节点收集并上传数据到服务器。

# 摘要

这是一个相当苛刻的章节，你学到了很多新信息。

首先，我们看了 Django 管理命令。它们是 Django 的一个重要特性。您运行的所有 Django 命令，例如`python manage.py startapp`，也是管理命令，因此您应该已经知道它们可以有多么强大。在更大的项目中，您几乎总是有一些管理命令来自动化您的任务。

我们还看了 Django 如何使用我们模型类上的`__str__`方法创建模型的字符串表示。它不仅在控制台打印时使用。每当您尝试将模型对象用作字符串时，甚至在模板中，Django 都会使用这个表示，因此拥有一个可以立即为您提供有关对象的所有重要信息的良好格式非常重要。

本章还介绍了高级查询方法，特别是`distinct`和`values`方法，允许您发出更复杂的 SQL 查询，以从数据库中获取您想要的数据格式。然而，这只是个开始。在以后的章节中，我们可能需要使用更复杂的查询方法。您可能需要查看 Django 文档中关于`queryset`方法的更多信息，网址为[`docs.djangoproject.com/en/stable/ref/models/querysets/`](https://docs.djangoproject.com/en/stable/ref/models/querysets/)。

除了以我们想要的格式从数据库中获取数据之外，我们还研究了如何准备一个相当复杂的数据结构，以便将所有必需的信息传递给模板，然后看到如何在我们的模板中使用该数据结构。

通常，您需要确保通过复杂的数据验证规则才能将数据保存到数据库。在本章中，我们看到了如何通过覆盖模型类的`save`方法来实现这一点。

最后，您学会了如何创建简单的 API 端点以及如何使用`curl`或 Postman 对其进行测试。总的来说，这是一个介绍了许多新概念的重要章节，这些概念将在以后的章节中使用。


# 第四章：汽车租赁应用程序

对于本章，我们的假想客户是一家汽车租赁公司。他们希望我们创建一个网站，供他们的客户访问，查看可用的汽车库存，并最终预订其中一辆汽车。客户还希望有一个管理面板，他们可以在其中管理库存和预订请求。

我们将在（鼓声）Django 中创建这个 Web 应用程序！您现在应该对 Django 有足够的信心，以至于 Web 应用程序的前端对我们来说不是挑战。本章的重点将放在定制 Django 内置的**admin**应用程序上，以满足我们客户的要求。大多数情况下，当您需要为创建的 Web 应用程序创建管理面板时，您可以通过定制 Django admin 来做几乎您需要的一切。有时候，要求足够复杂，您需要创建一个自定义管理面板，但这很少见。因此，我们在这里获得的知识将对您的 Web 开发职业非常有用。

本章的主要要点如下：

+   定制 Django admin 模型表单

+   向管理对象列表页面添加自定义过滤器

+   覆盖和定制 Django admin 模板

# 代码包

正如我所提到的，到目前为止，您应该已经牢牢掌握了创建基本 Web 应用程序的组件，包括视图、模板、模型和 URL 配置，因此我们在本章不会讨论 Web 应用程序的这些部分。因此，本章的代码包比以前的要大得多。我已经创建了所有的模型和一些视图、模板和 URL。我们将主要关注如何驯服 Django admin 应用程序以满足我们的需求。

我想不出一个花哨的名字来为这个项目命名，所以我只是把项目称为*carrental*。像往常一样，创建一个新的虚拟环境，在这个环境中安装 Django，并运行迁移命令来初始化数据库。对于这个项目，我们需要安装另一个 Python 包，Pillow，这是一个用于 Python 的图像处理库。要安装它，请在虚拟环境激活时运行以下命令：

```py
> pip install Pillow

```

这可能需要一两分钟，因为可能需要进行一些编译。安装 Pillow 要复杂一些，因为它依赖于第三方库。如果安装命令对您失败了，请查看[`pillow.readthedocs.org/en/3.0.x/installation.html`](https://pillow.readthedocs.org/en/3.0.x/installation.html)上有关安装 Pillow 的文档。该页面有每个操作系统的逐步指南，按照那里的指南，您应该能够轻松安装 Pillow。只需记住，您需要该库来运行和处理汽车租赁应用程序。

安装了 Pillow 后，使用`runserver`命令运行开发服务器，并在`http://127.0.0.1:8000`上打开 Web 应用程序。您应该会看到以下页面：

![代码包](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj-pj-bp/img/00698_04_01.jpg)

# 固定装置

我们的数据库是空的，但现在我们没有任何视图来向我们的数据库添加对象。我们可以像上一章那样创建一个管理命令，但有一个更简单的方法。我已经向数据库添加了三个`Car`对象，然后创建了这些数据的转储，您可以加载。这样的数据转储称为固定装置。我们将稍后讨论固定装置；现在让我们看看如何使用它们来加载我们的数据库中的数据。

在命令行上，在虚拟环境激活的情况下，在项目根目录中运行此命令：

```py
> python manage.py loaddata frontend/fixtures/initial.json
Installed 3 object(s) from 1 fixture(s)

```

刷新网页，现在您应该看到一个类似于这样的网页：

![固定装置](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj-pj-bp/img/00698_04_02.jpg)

现在我们的数据库中有三辆汽车。您应该玩一会儿这个应用程序。它为每辆汽车都有一个详细页面，并允许您从详细页面提交预订请求。

### 注意

如果您尝试使用预订表单，请注意开始和结束日期需要采用 YYYY-MM-DD 格式。例如，2016-12-22 是表单接受的有效日期格式。

要了解更多关于固定装置的信息，请查看 Django 文档[`docs.djangoproject.com/en/stable/howto/initial-data/`](https://docs.djangoproject.com/en/stable/howto/initial-data/)。固定装置是 Django 的一个功能，它允许你使用多种格式将数据库中的数据转储到简单的文本文件中。最常用的格式是 JSON。一旦你有了一个固定装置文件，你就可以使用它来填充你的数据库，就像我们在这里使用`loaddata`命令一样。

在我们继续进行管理定制之前，我想谈谈我在这个应用程序的模型中使用的一些新东西。你应该看一下`frontend/models.py`，看看我们的模型是如何配置的，然后阅读下面的信息，解释了这些新概念。

# 图片和文件字段

我想花一分钟介绍一下`ImageField`模型字段。这是我们第一次看到它，使用它与其他模型字段有些不同。这是我们使用这个字段的`Car`模型：

```py
class Car(models.Model):
    name = models.CharField(max_length=100)
    image = models.ImageField(upload_to='car_images')
    description = models.TextField()
    daily_rent = models.IntegerField()

    is_available = models.BooleanField()

    def get_absolute_url(self):
        return reverse('car-details', kwargs={'pk': self.pk})
```

### 注意

这一部分关于`ImageField`的所有信息也适用于`FileField`。

`ImageField`与我们查看过的所有其他数据库模型字段都有一些特殊之处。首先，它需要 Pillow 图像处理库才能工作，这就是为什么我们在本章的开头安装它的原因。如果我们在没有安装 Pillow 的情况下尝试运行我们的应用程序，Django 会抱怨并且不会启动开发服务器。

其次，`ImageField`是少数几个依赖于在使用之前进行一些设置的 Django 数据库模型字段之一。如果你看一下`carrental/settings.py`文件的末尾，你会看到我已经设置了`MEDIA_ROOT`和`MEDIA_URL`变量。

最后，你可以看到我们传递了一个`upload_to`参数给`ImageField`并将其设置为`car_images`。`FileField`和`ImageField`数据库模型字段都需要这个参数。这个参数是相对于配置的`MEDIA_ROOT`的文件夹名称，任何通过 Image/File 字段上传到你的应用程序的文件都将被保存在这里。这是一个我花了一些时间才弄明白的概念，所以我会进一步解释一下。

你应该看到我已经将`MEDIA_ROOT`设置为项目根目录中的`media`文件夹。如果你看一下`media`文件夹，你应该会看到另一个名为`car_images`的文件夹。这与我们传递给`upload_to`参数的名称相同。这就是我说`upload_to`参数是相对于配置的媒体根目录的文件夹名称时的意思。

### 提示

当我开始使用 Django 时，我有一些困难理解`MEDIA_ROOT`和`STATIC_ROOT`之间的区别。简而言之，`MEDIA_ROOT`是站点用户上传的所有文件所在的位置。这些文件是使用表单和 Image/File 字段上传的。

`STATIC_ROOT`是你放置与你的 Web 应用程序相关的静态文件的位置。这些包括 CSS 文件、JavaScript 文件和任何其他作为静态文件提供的文件。这与你的 Web 应用程序的 Django 部分无关；这些文件是原样提供给用户的，通常通过诸如 nginx 之类的 Web 服务器。

现在你已经配置好了一切，那么如何使用`ImageField`上传文件呢？嗯，Django 支持几种不同的方法来做这个。在我们的代码中，我们将使用`ModelForm`，它会为我们处理所有的细节。还有其他方法。如果你想了解更多细节，你应该查看处理文件上传的 Django 文档。它非常全面，列出了处理文件上传的所有不同方式。你可以在[`docs.djangoproject.com/en/stable/topics/http/file-uploads/`](https://docs.djangoproject.com/en/stable/topics/http/file-uploads/)上查看。

# 获取绝对 URL

我们在`Car`模型中第一次看到的另一件事是`get_absolute_url`。实现上没有什么特别之处。它只是一个返回 URL 的类方法，它使用`reverse`函数和对象的主键构建 URL。这并不是什么新鲜事。自第一章以来，我们一直在为详细页面创建这样的 URL。这里有趣的是 Django 对模型类上的`get_absolute_url`方法赋予了特殊意义。Django 有许多地方会自动使用`get_absolute_url`方法的返回值，如果该方法存在于模型对象上。例如，`CreateView`通用方法会使用它。如果您没有在视图类上提供`success_url`属性和自定义的`get_success_url`方法，Django 将尝试从新创建的对象上的`get_absolute_url`方法获取重定向的 URL，如果该方法在模型类中定义了。

Django 还在管理员应用程序中使用此方法，我们稍后会看到。如果您感兴趣，可以查看其文档：

[`docs.djangoproject.com/en/stable/ref/models/instances/#get-absolute-url/`](https://docs.djangoproject.com/en/stable/ref/models/instances/#get-absolute-url/)。

# Django 管理员应用程序

现在我们已经看了代码包中使用的新功能，让我们继续讨论本章的主题——Django**管理员**应用程序。管理员应用程序很可能是 Django 比其他类似的 Web 框架更受欢迎的主要原因之一。它体现了 Django“电池包含”的本质。通过最小的配置，管理员应用程序提供了一个功能齐全且非常定制的 CMS，足以与 WordPress 和 Drupal 等大型名称媲美。

在本章中，您将学习如何轻松配置和自定义管理员，以获得您在 Web 应用程序的管理员面板中所需的大部分功能。让我们首先解决我们虚构客户的最紧迫问题，即汽车租赁业主的能力来添加和编辑汽车详情。

当您启动一个新应用程序时，Django 默认会在应用程序文件夹中创建一个`admin.py`文件。更改我们项目中的`frontend/admin.py`文件以匹配此内容：

```py
from django.contrib import admin
from frontend.models import Car
admin.site.register(Car)
```

就是这样。真的！总共只有三行代码，您就可以编辑和添加`Car`对象到您的数据库中。这就是 Django 的强大之处，就在这三行代码中。让我们来测试一下。在浏览器中，访问`http://127.0.0.1:8000/admin`，您应该会看到类似以下页面：

![Django 管理员应用程序](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj-pj-bp/img/00698_04_03.jpg)

### 提示

如果您的管理员看起来略有不同，不要担心。Django 偶尔会更新管理员的主题，取决于您使用的 Django 版本，您的管理员可能看起来略有不同。但是，所有功能都会在那里，几乎总是具有相同的界面布局。

哎呀，有一件事我们忘了。我们没有创建一个可以登录的用户。这很容易解决。在命令行中，激活虚拟环境后运行以下命令：

```py
> python manage.py createsuperuser

```

跟着提示创建一个新用户。创建用户后，使用该用户登录到管理员。登录后，您应该会看到类似于以下内容：

![Django 管理员应用程序](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj-pj-bp/img/00698_04_04.jpg)

在这个屏幕上需要注意的几件事。首先，Django 默认会添加链接来管理**组**和**用户**。其次，我们配置在管理员中显示的任何模型都会按其应用程序名称进行分组。因此，管理**Cars**的链接显示在定义模型的应用程序标签**Frontend**下。

### 提示

如果您仔细观察，您可能会注意到管理员列出了我们`Car`模型的复数名称。它是如何知道复数名称的呢？嗯，它只是在我们模型名称的前面添加了一个's'。在很多情况下，这并不适用，例如，如果我们有一个名为`Bus`的模型。对于这种情况，Django 允许我们配置模型的复数名称。

让我们尝试编辑我们数据库中的一辆汽车。单击**Cars**链接，您应该会看到类似以下的屏幕：

![Django 管理员应用程序](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj-pj-bp/img/00698_04_05.jpg)

列表看起来并不是很有用。我们不知道哪个汽车对象是哪个。我们稍后会解决这个问题。现在，只需单击列表中的顶部汽车对象，您应该会看到一个页面，您可以在该页面上编辑该对象的详细信息：

![Django 管理员应用程序](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj-pj-bp/img/00698_04_06.jpg)

### 注意

Django 管理员文档将此列表称为更改列表。在本章中，我将称其为列表视图。

让我们更改汽车的名称。我将**Dodge Charger**更改为**My New Car Name**。更改名称后，滚动到页面底部，然后单击保存。为了确保我们的更改确实已保存，打开我们应用程序的主页`http://127.0.0.1:8000/`，您会看到您编辑的汽车将显示新名称。

让我们尝试更复杂的事情——添加一辆新汽车！单击屏幕右侧的**ADD CAR**按钮，然后根据需要填写详细信息。只需确保选择`is_available`复选框；否则，新汽车将不会显示在主页上。我填写了如下截图所示的表单：

![Django 管理员应用程序](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj-pj-bp/img/00698_04_07.jpg)

我还从 Google Images 下载了一辆汽车的图片，并将其选中为**Image**字段。单击保存按钮，然后再次访问主页。您添加的新汽车应该会显示在列表的末尾：

![Django 管理员应用程序](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj-pj-bp/img/00698_04_08.jpg)

正如我在本节开始时提到的，Django 管理员的强大是 Django 流行的主要原因之一。到目前为止，您应该明白为什么了。在三行代码中，我们有了一个完整且可用的内容管理系统，尽管不太美观，但客户可以用它来编辑和添加汽车到他们的网站。

然而，在其当前形式下，管理员看起来像是一个快速的黑客工作。客户可能不会对此感到满意。他们甚至在打开编辑页面之前都看不到他们即将编辑的汽车是哪辆。让我们首先解决这个问题。稍后我们会回到刚刚为管理员编写的代码。

# 显示汽车名称

在上一章中，我们看到了模型类上的`__str__`方法。我还说过，Django 在需要显示模型的字符串表示时会使用这个方法。嗯，这正是 Django 管理员在`Car`模型的列表视图中所做的：它显示了它的字符串表示。让我们通过将字符串表示更改为用户可以理解的内容来使列表更加用户友好。在`frontend/models.py`文件中，向`Car`模型类添加这个`__str__`方法：

```py
def __str__(self):
    return self.name
```

让我们看看现在`Car`对象的列表是什么样子的：

![显示汽车名称](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj-pj-bp/img/00698_04_09.jpg)

这是一个更好的用户体验，因为用户现在可以看到他们即将编辑的汽车是哪一辆。

# 预订管理

让我们暂时保持汽车管理员部分不变，转而进入`Booking`模型的管理员。每当网站访问者通过汽车详情页面上的**立即预订**表单提交时，我们都会创建一个新的`Booking`模型记录。我们需要一种方法来允许客户查看这些预订询问，根据一些标准对其进行筛选，并接受或拒绝它们。让我们看看如何做到这一点。首先，让我们确保我们的`Booking`模型显示为管理员面板中的一个项目。为此，请在`frontend/admin.py`文件中添加以下两行：

```py
from frontend.models import Booking
admin.site.register(Booking)
```

如果你现在查看 URL 为`http://127.0.0.1:8000/admin/`的管理员面板，你应该会看到`Booking`模型已经被添加为一个链接。打开链接，你应该会看到一个类似于我们之前看到的`Car`模型的列表页面。如果你提交了任何预订请求，它们应该会显示在列表中。这不够美观，但至少它能用。让我们把它做得更好。首先，我们需要给管理员更多关于每个预订询问的信息。如果我们能显示客户的姓名、预订开始和结束日期，以及预订是否已经被批准，那就太好了。

虽然我们可以再次使用`__str__`方法来创建一个包含所有这些信息的字符串，但是在一个列中显示这么多信息并不美观。此外，我们将错过 Django 管理员为每个模型列表页面提供的排序功能。

让我们看看如何在列表视图中显示我们模型的多个字段。在此过程中，你还将更多地了解管理员内部是如何工作的。

## 幕后一瞥

如果你花一分钟思考一下，我们只用几行代码就能实现的成就，你可能会对 Django 管理员的强大感到惊讶。这种力量是如何实现的呢？嗯，这个问题的答案非常复杂。即使我自己还没有完全理解管理员应用是如何工作的。这是一个非常复杂的编程部分。

### 注意

尽管管理员应用非常复杂，但它仍然是 Python 代码。如果你感到有冒险精神，或者只是某一天感到无聊，试着查看管理员应用的源代码。它在`VIRTUAL_ENV/lib/python3.5/site-packages/django/contrib/admin`文件夹中。用你为项目创建的虚拟环境的文件夹替换`VIRTUAL_ENV`。

管理员系统的主要组件之一是`ModelAdmin`类。就像`models.Model`类允许我们使用非常简单的类定义来定义复杂的数据库模型一样，`ModelAdmin`类允许我们非常详细地定制模型的管理员界面。让我们看看如何使用它来向我们的预订询问列表添加额外的字段。修改`frontend/admin.py`文件以匹配以下内容：

```py
from django.contrib import admin

from frontend.models import Car
from frontend.models import Booking

class BookingModelAdmin(admin.ModelAdmin):
    list_display = ['customer_name', 'booking_start_date', 'booking_end_date', 'is_approved']

admin.site.register(Car)
admin.site.register(Booking, BookingModelAdmin)
```

现在，如果你打开`Booking`模型的管理员列表页面，你应该会看到类似于这样的东西，所有重要的字段都显示出来：

![幕后一瞥](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj-pj-bp/img/00698_04_11.jpg)

这为用户提供了一个非常好的表格视图。客户现在可以看到所有相关的细节，并且可以根据自己的需求对表格进行排序。Django 还很贴心地以一种好看的格式显示日期值。让我们看看我们在这里做了什么。

我们首先创建了一个名为`BookingModelAdmin`的`ModelAdmin`子类。然后，我们使用`list_display`属性配置我们想在列表页面显示的字段。最后，我们需要将我们的`ModelAdmin`类与`Booking`模型类关联起来，以便管理员可以根据我们的要求自定义自己。我们使用以下方法来做到这一点：

```py
admin.site.register(Booking, BookingModelAdmin)
```

如果你看一下我们如何注册`Car`模型，它看起来与`Booking`模型类似：

```py
admin.site.register(Car)
```

这是因为它是同样的东西。如果你没有提供自定义的`ModelAdmin`子类，Django 会使用默认选项，这就是我们在`Car`模型中看到的。

# 改善用户体验

虽然我们通过在列表页面上显示相关字段来改进了基本的管理员界面，但我们可以做得更多。让我们看看管理员可能想要为网站收到的预订询问采取的一些操作：

+   只查看已批准的预订询问或尚未批准的预订询问

+   通过客户姓名搜索预订

+   快速批准或不批准预订询问

+   选择多个预订询问对象，并向客户发送关于他们批准/不批准的电子邮件

## 过滤对象

对于我们的第一个功能，我们希望允许用户对显示的对象进行筛选。页面上应该有一个筛选器，允许他们只查看已批准或未批准的预订。为此，Django 管理在`ModelAdmin`子类上提供了`list_filter`属性。`list_filter`属性包含一个可以进行筛选的字段列表。在我们的`BookingModelAdmin`类中，添加以下`list_filter`属性：

```py
list_filter = ['is_approved']
```

就是这样。一旦您将这行添加到`BookingModelAdmin`中，打开预订列表页面；在右侧，您应该看到一个新的侧边栏，您可以选择要查看的预订——只有已批准的或未批准的，或两者都有。它应该看起来类似于以下的屏幕截图：

![过滤对象](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj-pj-bp/img/00698_04_12.jpg)

## 搜索对象

就像 Django 管理内置了对过滤器的支持一样，它还提供了一种易于使用的添加搜索的方法。我们希望客户能够通过客户名称字段搜索预订。为此，请将`search_fields`属性添加到`BookingModelAdmin`类中：

```py
search_fields = ['customer_name']
```

就是这样。一旦您添加了这个属性，您应该在预订对象列表的顶部看到一个搜索框。输入一些示例查询，看看它是如何工作的。如果您有多个要进行搜索的字段，也可以将其添加到`search_fields`列表中。

如果列表中有多个字段名称，Django 将进行 OR 搜索。这只是意味着对于给定的搜索，具有至少一个匹配字段值的所有记录都将显示。

## 快速编辑

我们列表中的第三个功能是允许管理员快速标记预订为批准/未批准。Django 管理提供了另一个内置功能，我们可以配置以获得我们需要的功能。在您的`BookingModelAdmin`类中，添加`list_editable`属性：

```py
list_editable = ['is_approved']
```

如果您现在打开预订列表页面，您会注意到在以前的`is_approved`列中显示的图标已经被替换为复选框和**保存**按钮添加到列表的末尾。您可以选择要批准的预订的复选框，并取消选择要不批准的预订，并单击**保存**。然后 Django 将一次保存您对多个对象的更改。

到目前为止，我们的预订列表页面看起来类似于以下的屏幕截图：

![快速编辑](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj-pj-bp/img/00698_04_13.jpg)

## 管理操作

我们功能列表中的最后一项是允许用户选择多个预订查询对象，并向每个包含预订批准状态的`Booking`对象的`customer_email`发送电子邮件。目前，我们将只是在控制台上打印出电子邮件来测试这个功能。我们将在后面的章节中查看如何从 Django 发送电子邮件。

到目前为止，我们在 Django 管理中所做的大部分编辑都是基于每个对象的。您选择一个对象，编辑它，然后保存它，然后重新开始。除了最后一个功能（快速编辑）之外，我们一直在逐个编辑对象。然而，有时您希望能够对多个对象执行常见操作，就像我们在电子邮件功能中所需的那样。为了实现这样的功能，Django 管理提供了**管理操作**。

管理操作是`ModelAdmin`类上的方法，它们接收用户选择的对象列表。然后，这些方法可以对这些对象执行一些操作，然后将用户返回到更改列表页面。

### 注意

实际上，我稍微简化了一下。管理操作不需要是`ModelAdmin`上的方法。它们也可以是独立的函数。然而，通常最好的编程实践是在使用它们的`ModelAdmin`中声明它们，所以我们将在这里这样做。您可以在[`docs.djangoproject.com/en/stable/ref/contrib/admin/actions/`](https://docs.djangoproject.com/en/stable/ref/contrib/admin/actions/)的管理操作文档中找到更多详细信息。

Django 管理员默认提供了一个操作：删除。如果你打开预订列表顶部的**操作**下拉菜单，你应该会看到这个菜单：

![管理员操作](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj-pj-bp/img/00698_04_14.jpg)

要定义管理员操作，首先需要在`ModelAdmin`类上创建一个方法，然后将方法的名称添加到类的`actions`属性中。`actions`属性是一个列表，就像我们到目前为止看到的所有其他属性一样。修改`BookingModelAdmin`以匹配以下代码：

```py
class BookingModelAdmin(admin.ModelAdmin):
    list_display = ['customer_name', 'booking_start_date', 'booking_end_date', 'is_approved']
    list_filter = ['is_approved']
    list_editable = ['is_approved']
    search_fields = ['customer_name']

    actions = ['email_customers']

    def email_customers(self, request, queryset):
        for booking in queryset:
            if booking.is_approved:
                email_body = """Dear {},
    We are pleased to inform you that your booking has been approved.
Thanks
""".format(booking.customer_name)
            else:
                email_body = """Dear {},
    Unfortunately we do not have the capacity right now to accept your booking.
Thanks
""".format(booking.customer_name)

            print(email_body)
```

让我们在查看代码功能之前先试一下。刷新 Booking 模型的`changelist`页面，查看**操作**下拉菜单。应该会有一个新选项，**给顾客发送邮件**：

![管理员操作](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj-pj-bp/img/00698_04_15.jpg)

要测试它，从列表中选择一些预订对象，从下拉菜单中选择**给顾客发送邮件**操作，然后单击下拉菜单旁边的**Go**按钮。页面加载后，查看控制台。你应该会看到类似于这里显示的内容：

```py
Dear Jibran,
    We are pleased to inform you that your booking has been approved.
Thanks

[18/Jan/2016 09:58:05] "POST /admin/frontend/booking/ HTTP/1.1" 302 0
```

让我们看看我们在这里做了什么。正如我之前所说，管理员操作只是`ModelAdmin`类上的一个方法，接受`request`对象和`queryset`作为参数，然后对`queryset`执行所需的操作。在这里，我们为每个预订对象创建了一个电子邮件正文，并将其打印到控制台。

## UX 改进

虽然系统现在已经足够好让我们的客户使用，但肯定还有改进的空间。首先，用户没有得到任何关于**给顾客发送邮件**操作是否执行的反馈。让我们先解决这个问题。在`email_customers`方法的末尾添加这一行：

```py
self.message_user(request, 'Emails were send successfully')
```

再次尝试使用电子邮件操作。现在页面重新加载后，你会看到一个很好的成功消息，向用户保证他们想要的操作已经完成。在用户体验方面的小改进在帮助用户导航和成功使用产品方面可以走很长的路。

其次，让我们来看看如何命名这个操作。对于这个操作，Django 提供了一个相当不错的名称——**给顾客发送邮件**。这个名称简单明了。然而，它并不像应该的那样清晰。它没有向用户传达正在发送的电子邮件是什么。在一个更大的系统中，客户可能会发送多种类型的电子邮件，我们的操作名称应该清楚地说明我们在谈论哪一封电子邮件。

为了改变管理员操作的名称，我们需要给方法添加一个名为`short_description`的属性。由于在 Python 中方法也是对象，所以这很容易实现。修改`BookingModelAdmin`类以匹配以下代码。需要添加的新行已经标出：

```py
class BookingModelAdmin(admin.ModelAdmin):
    list_display = ['customer_name', 'booking_start_date', 'booking_end_date', 'is_approved']
    list_filter = ['is_approved']
    list_editable = ['is_approved']
    search_fields = ['customer_name']

    actions = ['email_customers']

    def email_customers(self, request, queryset):
        for booking in queryset:
            if booking.is_approved:
                email_body = """Dear {},
    We are pleased to inform you that your booking has been approved.
Thanks
""".format(booking.customer_name)
            else:
                email_body = """Dear {},
    Unfortunately we do not have the capacity right now to accept your booking.
Thanks
""".format(booking.customer_name)

            print(email_body)

        self.message_user(request, 'Emails were send successfully')
    email_customers.short_description = 'Send email about booking status to customers'

```

请注意，新的行（最后一行）不是函数体的一部分。它与函数定义的缩进级别相同，实际上是类的一部分，而不是函数的一部分。刷新列表页面，再次查看操作下拉菜单：

![UX 改进](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj-pj-bp/img/00698_04_16.jpg)

# 总结

这一章可能是本书中编写的代码最少的一章。然而，我们在这里构建的功能可能比大多数章节中构建的功能更复杂。我在本章的开头说过，Django 框架受欢迎的原因之一是管理员应用程序。我希望到现在为止你同意我的观点。

不到 20 行代码，我们就能够创建一个与大多数 CMS 系统相媲美的系统，而且仍然更符合我们客户的需求。与大多数 CMS 系统不同，我们不将`Car`和`Booking`对象视为页面或节点。在我们的系统中，它们是一流的对象，每个对象都有自己的字段和独特的功能。然而，就客户而言，管理员的工作方式与大多数 CMS 一样，可能更容易，因为没有像大多数 CMS 解决方案中那样有额外的字段。

我们几乎只是开始了解定制管理员的表面。管理员提供了许多功能，适用于管理面板所需的大多数场景。通过在`ModelAdmin`上更改一些设置，所有这些功能都很容易使用。在我开发的所有 Django 应用程序中，我只需要创建定制的管理面板一次。Django 管理员是如此可定制，您只需配置它以满足您的需求。

我强烈建议您查看 Django 管理员的文档[https://docs.djangoproject.com/en/stable/ref/contrib/admin/]。如果您需要为您的 Web 应用程序创建管理项目，请检查管理员是否提供您想要的功能。往往情况是如此，并且可以节省大量精力。


# 第五章：多语言电影数据库

互联网可能是世界上增长最快的现象。廉价的互联网手机进一步加速了这种增长，据一些估计，今天世界上有 40%的人口可以接入互联网。我们开发的任何网络应用都可以真正成为全球性的。然而，英语用户只占互联网用户的大约 30%。如果你的网站只有英文，你就错过了一个巨大的受众。

为了解决这个问题，近年来已经做出了许多努力，使网站也能够为非英语用户提供访问。Django 本身包括可靠的方法，将网站内容翻译成多种语言。

然而，翻译内容只是过程的第一部分。语言并不是世界各地不同之间唯一的不同之处。货币代码、时区和数字格式只是一些例子。将这些适应到用户所在地的过程称为**本地化**。你经常会看到这个缩写为**l10n**。这是本地化的第一个`l`，然后是一个数字`10`，后面是最后一个`n`。`10`指的是两者之间的字符数！你可能也会遇到国际化（**i18n**）这个术语。国际化是确保你的应用在多个地区都能正常运行，不会出现错误。例如，确保你从用户那里接受的任何输入可以是多种语言，而不仅仅是你开发应用的那种语言。

在本章中，我们将制作一个受到非常有用的**IMDB**（**互联网电影数据库**）网站启发的应用程序。如果你从未听说过它，它是一个提供有关电影的大量信息的网络应用程序，无论是新的还是旧的。我们将创建一个类似于 IMDB 的应用程序，提供一些非常基本的功能。由于我们的应用程序是多语言的（顺便说一句，IMDB 也是），我将把它称为**多语言电影数据库**（**MMDB**）。

本章的代码包含了一个工作的非本地化应用程序副本。我们的工作是为法国用户添加本地化和国际化，以便其能够正常使用。

# 要求

让我们来看看本章结束时我们想要实现的目标：

+   了解 Django 提供的所有功能，以允许本地化

+   将网站内容翻译成法语

+   给用户选择他们想要在网站中使用的语言的能力

+   在多次访问中保持用户的语言偏好

+   翻译模型的内容

在我们开始之前，有一件事我想提一下。由于我们是第一次学习这些东西，我们将从一个已经存在的 Django 应用程序开始。然而，与大多数真实项目相比，我们的应用程序非常小。对于更大的应用程序，在完成项目后添加本地化通常更加困难。

在开始项目时考虑本地化需求并在首次开发应用程序时将这些功能纳入其中总是一个好主意，而不是在应用程序开发后的后期阶段这样做。

# 启动项目

和往常一样，一旦你下载了代码包，解压它。然后，为这个项目创建一个新的虚拟环境并安装 Django。最后，激活它并在项目根目录中运行迁移命令。这应该为项目设置数据库，并让你可以启动应用程序。现在你需要创建一个新的超级用户，这样你就可以添加一些测试数据。在项目根目录中（虚拟环境处于活动状态），运行以下命令：

```py
> python manage.py createsuperuser

```

回答问题，您将获得一个新用户。现在，使用`runserver`命令运行应用程序，然后访问`http://127.0.0.1:8000/admin/`，并向数据库添加一些电影详细对象。一旦您添加了一些测试数据，访问应用程序的主页，您应该看到类似以下屏幕截图的内容：

![启动项目](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj-pj-bp/img/00698_05_01.jpg)

您应该花一些时间来探索这个应用程序。您可以在页面上查看特定电影的详细信息，如下面的屏幕截图所示：

![启动项目](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj-pj-bp/img/00698_05_02.jpg)

最后，您可以点击**提交新评论**链接，转到下一页，并为电影创建一个新的评论，如下面的屏幕截图所示：

![启动项目](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj-pj-bp/img/00698_05_03.jpg)

这就是我们整个应用程序。在本章的其余部分，我们将探讨如何向这个项目添加 l10n 和 i18n。我们对核心产品功能几乎没有或没有做任何更改。

# 翻译我们的静态内容

我们想要做的第一件事是翻译网站上的所有静态内容。这包括在前面三个屏幕中看到的所有标题、链接和表单标签。为了翻译模板中使用的字符串，Django 为我们提供了一个`trans`模板标签。让我们先看看如何在简单的上下文中使用它，然后我会详细介绍它的工作原理。这是一个稍微长一点的部分，因为我们将在这里做很多构成 Django 翻译功能基础的事情。

### 提示

如果您不理解某些内容，请不要惊慌。只需按照说明进行。我将深入介绍每一步，但首先我想向您展示翻译是如何完成的。

打开`main/templates/movies_list.html`，并将`h2`标签中的`Movies List`替换为以下内容：

```py
{% trans "Movies List" %}
```

在文件的第二行后面的`extends`标签之后，添加以下`load`标签：

```py
{% load i18n %}
```

这是我们现在需要对模板进行的所有更改。我将在稍后解释这两行的作用，但首先我想完成整个翻译过程，这样您就可以看到整个过程而不仅仅是一小部分。

接下来，让我们从项目根目录运行以下命令：

```py
> python manage.py makemessages -l fr
CommandError: Unable to find a locale path to store translations for file main/__init__.py

```

如果您运行这个命令，您也应该看到与我一样的错误，即找不到区域设置路径。我们会在演示结束后解释区域设置路径是什么。现在，在`main`文件夹中创建一个名为`locale`的新文件夹，然后再次运行该命令：

```py
>mkdir main/locale
> python manage.py makemessages -l fr
processing locale fr

```

这次命令成功了。如果您查看您创建的`locale`文件夹，您会看到它下面创建了一个全新的文件夹层次结构。`makemessages`命令所做的是在`main/locale/fr/LC_MESSAGES/django.po`文件中创建了一个`django.po`文件。如果您打开这个文件，您应该能够了解一些关于它的目的。文件的最后三行应该如下所示：

```py
#: main/templates/movies_list.html:5
msgid "Movies List"
msgstr ""
```

加上这个文件的路径(`locale/fr/LC_MESSAGES/django.po`)和这三行，您应该能够理解这个文件将包含我们之前用`trans`标签标记的字符串的法语翻译。在`msgstr`旁边放在引号中的任何内容都将替换网站的法语翻译中的原始字符串。

我使用 Google 翻译来翻译`Movies List`字符串，它给了我翻译为 Liste des films。将这个翻译放在`msgstr`旁边的引号中。现在，`django.po`文件的最后三行应该与以下内容匹配：

```py
#: main/templates/movies_list.html:5
msgid "Movies List"
msgstr "Liste des films"
```

接下来，从项目根目录运行以下命令：

```py
> python manage.py compilemessages -l fr
processing file django.po in /Users/asadjb/Programming/Personal/DjangoBluePrints/mmdb/mmdb/main/locale/fr/LC_MESSAGES

```

如果您现在查看`LC_MESSAGES`文件夹，您会看到一个新的`django.mo`文件已经被创建。这是我们的`django.po`文件的编译版本，我们将翻译的字符串放入其中。出于性能考虑，Django 翻译需要将文件编译成二进制格式，然后才能获取字符串的翻译。

接下来，打开`mmdb/settings.py`并找到`MIDDLEWARE_CLASSES`列表。编辑它，使得`django.middleware.locale.LocaleMiddleware`字符串出现在已安装的`SessionMiddleware`和`CommonMiddleware`之间。位置很重要。列表现在应该如下所示：

```py
MIDDLEWARE_CLASSES = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
 'django.middleware.locale.LocaleMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.auth.middleware.SessionAuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]
```

接下来，在设置文件中添加一个`LANGUAGES`变量，并给它以下值：

```py
LANGUAGES = (
    ('en', 'English'),
    ('fr', 'French')
)
```

默认情况下，Django 支持更多的语言列表。对于我们的项目，我们希望将用户限制在这两个选项中。这就是`LANGUAGES`列表的作用。

最后一步是修改`mmdb/urls.py`文件。首先，从`django.conf.urls.i18n`导入`i18n_patterns`。接下来，更改`urlpatterns`变量，以便`i18n_patterns`函数包装所有我们的 URL 定义，如下面的代码所示：

```py
urlpatterns = i18n_patterns(
url(r'^$', MoviesListView.as_view(), name='movies-list'),
url(r'^movie/(?P<pk>\d+)/$', MovieDetailsView.as_view(), name='movie-details'),
url(r'^movie/(?P<movie_pk>\d+)/review/$', NewReviewView.as_view(), name='new-review'),

url(r'^admin/', admin.site.urls),
)
```

完成这些后，让我们测试一下，看看我们的辛勤工作得到了什么。首先，打开`http://127.0.0.1:8000`。您应该会看到与之前相同的主页，但是如果您注意地址栏，您会注意到浏览器位于`http://127.0.0.1:8000/en/`而不是我们输入的内容。我们将在下一步详细了解为什么会发生这种情况，但简而言之，我们打开了主页而没有指定语言，Django 将我们重定向到了站点的默认语言，我们之前指定为英语。

将 URL 更改为`http://127.0.0.1:8000/fr/`，您应该会再次看到相同的主页，但是这次，`Movies List`文本应该被我们说的法语翻译所替换，如下面的截图所示：

![翻译我们的静态内容](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj-pj-bp/img/00698_05_04.jpg)

虽然这一切可能看起来像是为了翻译一个句子而做了很多工作，但请记住，您只需要做一次。既然基础已经建立，让我们看看现在翻译其他内容有多容易。让我们将单词`Stars`翻译成法语，`Etoiles`。打开`main/templates/movies_list.html`，并将单词`Stars`替换为以下内容：

```py
{% trans "Stars" %}
```

接下来，运行`makemessages`命令：

```py
> python manage.py makemessages -l fr

```

打开`main/locale/fr/LC_MESSAGES/django.po`文件。您应该会看到一个新的部分，用于我们标记为翻译的`Stars`字符串。添加翻译（`Étoile`）并保存文件。最后，运行`compilemessages`命令：

```py
> python manage.py compilemessages

```

再次访问`http://127.0.0.1:8000/fr/`，打开法语语言主页。您会看到单词`Stars`已被其法语翻译所替换。所需的工作量很小。您刚刚遵循的工作流程：标记一个或多个字符串进行翻译，制作消息，翻译新字符串，最后运行`compilemessages`，是大多数 Django 开发人员在翻译项目时遵循的工作流程。准备网站翻译所涉及的大部分工作都是我们之前所做的。让我们更仔细地看看我们到底做了什么来使我们的 Web 应用程序可翻译。

# 所有这些是如何工作的？

就像我在上一节开始时所承诺的那样，在看到 Django 翻译实际操作后，我们现在将更深入地了解我们所遵循的所有步骤以及每个步骤所做的事情。

我们做的第一件事是加载 i18n 模板标签库，它为我们提供了各种模板标签来翻译模板中的内容。最重要的，也可能是您最常使用的，是`trans`标签。`trans`标签接受一个字符串参数，并根据活动的语言输出该字符串的正确翻译。如果找不到翻译，将输出原始字符串。

您在模板中编写的几乎任何字符串最终都将被`trans`标签包装，然后在您的 Web 应用程序可用的各种语言中进行翻译。有某些情况下`trans`标签无法使用。例如，如果您必须将某些上下文变量的值添加到已翻译的字符串中，则`trans`标签无法做到这一点。对于这些情况，我们需要使用块翻译标签`blocktrans`。我们的应用程序不需要它，但您可以在 Django 文档中了解有关它的信息[`docs.djangoproject.com/es/stable/topics/i18n/translation/#blocktrans-template-tag`](https://docs.djangoproject.com/es/stable/topics/i18n/translation/#blocktrans-template-tag)。

我们的下一步是运行`make messages`命令。我们的第一次尝试没有成功，所以我们不得不在我们的`application`文件夹中创建一个`locale`目录。做完这些后，我们运行了该命令，并创建了一个带有`.po`扩展名的消息文件。该命令的作用是遍历项目中的每个文件，并提取您标记为翻译的字符串。标记字符串的一种方法是使用`trans`标签进行包装。还有其他方法，我们稍后会看到。

`make messages`命令提取字符串后，需要创建文件并将提取的字符串存储在这些文件中。Django 在确定每个提取的字符串应放入哪个文件时遵循一组规则。对于从应用程序文件中提取的字符串，Django 首先尝试在该应用程序的文件夹中找到`locale`目录。如果找到该文件夹，它将在其中创建适当的层次结构（`fr/LC_MESSAGES`目录）并将消息文件放在那里。

如果未找到`locale`文件夹，Django 将查看`LOCALE_PATHS`设置变量的值。这应该是一个目录位置列表。Django 从此路径列表中选择第一个目录，并将消息文件放在那里。在我们的情况下，我们没有设置`LOCALE_PATHS`，这就是为什么 Django 会引发错误，找不到我们主要应用程序文件夹中的 locale 目录。

让我们稍微谈谈消息文件的格式。这是我们当前消息文件的样子：

```py
# SOME DESCRIPTIVE TITLE.
# Copyright (C) YEAR THE PACKAGE'S COPYRIGHT HOLDER
# This file is distributed under the same license as the PACKAGE package.
# FIRST AUTHOR <EMAIL@ADDRESS>, YEAR.
#
#, fuzzy
msgid ""
msgstr ""
"Project-Id-Version: PACKAGE VERSION\n"
"Report-Msgid-Bugs-To: \n"
"POT-Creation-Date: 2016-02-15 21:25+0000\n"
"PO-Revision-Date: YEAR-MO-DA HO:MI+ZONE\n"
"Last-Translator: FULL NAME <EMAIL@ADDRESS>\n"
"Language-Team: LANGUAGE <LL@li.org>\n"
"Language: \n"
"MIME-Version: 1.0\n"
"Content-Type: text/plain; charset=UTF-8\n"
"Content-Transfer-Encoding: 8bit\n"
"Plural-Forms: nplurals=2; plural=(n > 1);\n"

#: main/templates/movies_list.html:6
msgid "Movies List"
msgstr "Liste des films"

#: main/templates/movies_list.html:10
msgid "Stars"
msgstr "Étoile"
```

以`#`开头的行是注释。然后是一对空的`msgid`和`msgstr`。然后是关于此消息文件的一些元数据。之后，我们得到了主要部分。消息文件，忽略元数据和第一对（在模糊注释之前的那一对），只是一系列`msgid`和`msgstr`对。`msgid`对是您标记为翻译的字符串，`msgstr`是该字符串的翻译。翻译应用程序的常规方法是首先标记所有字符串以进行翻译，然后生成消息文件，最后将其提供给翻译人员。然后翻译人员将带有填充翻译的文件返回给您。使用简单文本文件的好处是，翻译人员不需要使用任何特殊软件。如果他可以访问简单的文本编辑器，他就可以翻译消息文件。

一旦我们翻译了消息文件中的字符串，我们需要在 Django 能够使用这些翻译之前运行编译消息命令。如前所述，编译命令将文本消息文件转换为二进制文件。二进制文件格式对 Django 来说读取速度更快，在具有数百或数千个可翻译字符串的项目中，这些性能优势会非常快速地累积起来。编译消息文件的输出是一个`.mo`文件，与`.po`文件在同一个文件夹中。

一旦我们完成并编译了翻译，我们需要设置一些 Django 配置。我们首先要做的是将`LocaleMiddleware`添加到应用程序使用的中间件列表中。`LocaleMiddleware`的工作是允许用户根据一些请求参数选择站点的语言。您可以在文档中阅读有关语言确定方式的详细信息[`docs.djangoproject.com/es/stable/topics/i18n/translation/#how-django-discovers-language-preference`](https://docs.djangoproject.com/es/stable/topics/i18n/translation/#how-django-discovers-language-preference)。我们稍后会回到这个问题，讨论它如何通过示例确定语言。

然后我们需要定义两个设置变量，`LANGUAGES`和`LANGUAGE`。`LANGUAGE`已经在代码包中定义了，所以我们只设置了`LANGUAGES`变量。`LANGUAGES`是 Django 可以为站点提供翻译的语言选择列表。默认情况下，这是一个包含 Django 可以翻译的所有语言的巨大列表。然而，对于大多数项目，您希望用户仅限于使用站点的少数语言。通过为`LANGUAGES`列表提供我们自己的值，我们确保 Django 不会为除定义的语言之外的任何语言提供页面。

`LANGAUGE`变量定义了要使用的默认语言。如果您记得，当我们打开主页时没有任何语言代码（`http://127.0.0.1:8000/`），**英语**语言会被默认选择。`LANGUAGE`变量决定了站点的默认语言是什么。

使应用程序可翻译的下一步是修改`url.py`文件。我们将 URL 配置的简单列表替换为`i18n_patterns`函数。这个函数允许我们匹配在 URL 前面加上语言代码的 URL。对于每个进来的请求，这个函数会尝试匹配我们在其中包装的模式，然后从 URL 路径中移除语言代码。这有点复杂，所以让我们看一个例子。

假设我们有以下的 URL 模式：

```py
url(r'^example/$', View.as_view(), name='example')
```

这将匹配`DOMAIN.COM/example/`，但如果我们尝试`DOMAIN.com/en/example/`，模式将不会匹配，因为`/en/`部分不是正则表达式的一部分。然而，一旦我们将其包装在`i18n_patterns`中，它将匹配第二个示例。这是因为`i18n_patterns`函数会移除语言代码，然后尝试匹配我们在其中包装的模式。

在一些应用程序中，您不希望所有的 URL 都匹配语言前缀。一些 URL，比如 API 端点，不会根据语言而改变。在这种情况下，您可以将`i18n_patterns`和普通的 URL 模式列表结合在一起：

```py
urlpatterns = i18n_patterns(url(r'^example/$', ExampleView.as_view(), name='example')) + [url(r'^api/$', ApiView.as_view(), name='api')]
```

这样，您可以创建一些混合了翻译和非翻译视图的应用程序。

添加了`i18n_urlpatterns`后，我们已经完成了 Django 需要的基本国际化配置，我们可以访问我们用法语编写的页面并查看翻译版本。

我要解释的最后一件事是`LocaleMiddleware`。区域设置中间件是 Django 的一部分，允许用户使用 URL 中的语言代码来决定使用哪种语言。因此，即使是`i18n_patterns`根据语言代码匹配模式，中间件也会为每个请求激活正确的语言。除了在 URL 路径中使用语言前缀之外，`LocaleMiddleware`还提供了其他几种选择语言的方式：

+   一个会话变量

+   一个 cookie 值

+   用户浏览器发送的`Accept-Language`头

+   如果一切都失败了，就会使用`LANGUAGE`设置变量的默认语言

这是我们如何使我们的应用程序适应可翻译的概述。然而，我们还没有完成。

# 让用户决定使用哪种语言

虽然这不是 Django 的一部分，但几乎所有国际化的项目都使用这种模式；因此我认为您了解这一点很重要。大多数具有多种语言选项的网站都会向用户提供一个菜单，让他们选择要以哪种语言查看网站。让我们创建一个。修改`templates/base.html`模板以匹配以下内容：

```py
{% load i18n %}

<html>
<head>
<meta http-equiv="content-type" content="text/html; charset=utf-8" />

<title>MMDB</title>
</head>
<body>
<h1>MMDB</h1>
<div>
<span>Select Language</span>
<ul>
 {% get_available_languages as available_languages %}
 {% for lang_code, lang_name in available_languages %}
 {% language lang_code %}<li><a href="{% url "movies-list" %}">{{ lang_name }}</a></li>{% endlanguage %}
 {% endfor %}
</ul>
</div>
    {% block content %}
    {% endblock %}
</body>
</html>
```

新部分已经突出显示。我们首先导入 i18n 模板库。然后，我们创建一个新的`div`元素来保存我们的语言选择列表。接下来，为了将语言选择作为模板的一部分，我们使用`get_available_languages`模板标签，并将选择分配给`available_languages`变量。

接下来，我们根据语言选择创建一个链接列表。`get_available_languages`的返回值是我们在`LANGUAGES`变量的设置文件中设置的元组。

在我们的链接列表中，我们需要一种方法来获取每种语言的 URL。Django 在这方面表现出色，它与国际化功能和框架的其他部分深度集成。如果您启用了国际化并反转 URL，它会自动获取正确的语言前缀。

然而，我们不能在这里对 URL 进行反转，因为那样会创建当前活动语言的 URL。因此，我们的语言切换链接列表实际上只会指向当前语言。相反，我们必须暂时切换到我们想要创建链接的语言，然后生成 URL。我们使用`language`标签来实现这一点。在`language`标签之间，我们传递的语言参数会被激活。因此，我们反转的 URL 正好符合我们的要求。

最后要注意的是我们反转的 URL。对于我们的应用程序，`movies-list` URL 是主页，因此我们反转它。对于大多数应用程序，您将做同样的事情，并反转主页 URL，以便切换语言时将用户带到指定语言的主页。

### 提示

有一种高级的方法可以让用户保持在当前页面并切换语言。一种方法是在每个页面上生成链接，而不是在`base.html`中，就像我们在这里做的一样。这样，由于您知道模板将呈现的 URL，您可以反转适当的 URL。然而，这样做的缺点是需要重复很多次。您可以在 Google 上搜索`Django reverse current URL in another language`，并获得一些其他建议。我还没有找到一个好的方法来使用，但您可以决定是否认为其中一个建议的选项符合您的需求。

一旦您进行了更改，通过访问`http://127.0.0.1:8000/en/`再次打开电影列表页面，您现在应该在顶部看到语言切换链接。参考以下截图：

![让用户决定使用哪种语言](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj-pj-bp/img/00698_05_05.jpg)

您可以尝试切换语言，看到页面上的字符串立即反映出变化。

# 保持用户选择

让我们尝试一个实验。将语言切换为法语，然后关闭浏览器窗口。再次打开浏览器并访问`http://127.0.0.1:8000/`。注意 URL 中没有语言前缀。您将被重定向到该网站的英语版本。如果一旦您选择了要使用的语言，它能够在访问时保持不变，那不是很好吗？

Django 提供了这样一个功能，您只需添加一些代码来使用它。如果您记得`LocaleMiddleware`确定当前请求的语言所采取的步骤列表，那么在查看 URL 前缀之后的第二步是查看会话。如果我们可以将语言选择放入会话字典中，Django 将在随后的访问中自动为用户选择正确的语言。

在哪里放置更新会话字典的代码是正确的位置？如果您考虑一下，每当用户更改其语言选择时，我们都会将其重定向到主页。因为他们在语言偏好更改时总是访问主页，让我们把我们的代码放在那里。修改`MoviesListView`以匹配以下代码：

```py
class MoviesListView(ListView):
    model = MovieDetails
    template_name = 'movies_list.html'

    def get(self, request, *args, **kwargs):
        current_language = get_language()
        request.session[LANGUAGE_SESSION_KEY] = current_language

        return super(MoviesListView, self).get(request, *args, **kwargs)
```

您还需要导入`get_language`和`LANGUAGE_SESSION_KEY`。将其放在`main/views.py`的顶部：

```py
from django.utils.translation import LANGUAGE_SESSION_KEY
from django.utils.translation import get_language
```

现在，再次访问网站并将语言更改为法语。接下来，关闭浏览器窗口，然后再次打开。打开`http://127.0.0.1:8000/`，并注意不要在 URL 中添加语言前缀，您应该被重定向到法语页面。

让我们看看这里发生了什么。在 URL 中没有语言代码的情况下，`LocaleMiddleware`会查看会话，看看保存语言选择的键是否有任何值。如果有，中间件会将其设置为请求的语言。我们通过首先使用`get_language`方法获取当前活动的语言，然后将其放入会话中，将用户的语言选择放入会话中。中间件使用的键名称存储在`LANGUAGE_SESSION_KEY`常量中，因此我们使用它来设置语言选择。

正确设置会话后，用户下次访问网站时，如果没有语言前缀，中间件会在会话中找到他们的选择并使用它。

# 翻译我们的模型

我们要看的最后一件事是如何翻译我们的模型数据。打开网站并切换到法语。您的主页应该类似于以下截图：

![翻译我们的模型](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj-pj-bp/img/00698_05_06.jpg)

您会注意到，即使静态内容——我们自己放在模板中的内容——已被翻译，电影的动态名称却没有被翻译。虽然这对一些网站来说是可以接受的，但您的模型数据也应该被翻译，以便真正国际化。Django 默认没有任何内置方法来实现这一点，但这很容易。

### 提示

我将要向您展示的是 Django `modeltranslation`库已经提供的内容。我在一个大型项目中使用过它，效果非常好，所以如果您想跳过这一部分，可以直接使用该库。但是，了解如何在没有任何外部帮助的情况下实现它也是很好的。

您可以在[`github.com/deschler/django-modeltranslation`](https://github.com/deschler/django-modeltranslation)找到该库。

我们需要的是一种方法来为我们模型中的每个文本字段存储多种语言。您可以想出一种方案，在其中使用某种分隔符将字符串的英文和法文翻译存储在同一个字段中，然后在显示模型时将两者分开。

另一种实现相同结果的方法是为每种语言添加一个额外的字段。对于我们当前的示例，这意味着为每个要翻译的字段添加一个额外的字段。

这两种方法都有其利弊。第一种方法难以维护；随着需要翻译的语言不止一种，数据格式变得难以维护。

第二种方法添加了数据库字段，这可能并非总是可能的。此外，它需要根本性地改变数据访问方式。但是，如果您有选择，我总是建议选择结果更清晰易懂的代码，这种情况下意味着为每种语言添加额外字段。

对于我们的`MovieDetails`模型，这意味着为标题和描述字段各添加一个额外的字段来存储法语翻译。编辑您的`main/models.py`文件，使`MovieDetails`模型与以下代码匹配：

```py
class MovieDetails(models.Model):
    title = models.CharField(max_length=500)
    title_fr = models.CharField(max_length=500)

    description = models.TextField()
    description_fr = models.TextField()

    stars = models.PositiveSmallIntegerField()

    def __str__(self):
        return self.title
```

接下来，创建并运行迁移以将这些新字段添加到数据库中：

```py
> python manage.py makemigrations
You are trying to add a non-nullable field 'description_fr' to moviedetails without a default; we can't do that (the database needs something to populate existing rows).
Please select a fix:
 1) Provide a one-off default now (will be set on all existing rows)
 2) Quit, and let me add a default in models.py
Select an option: 1
Please enter the default value now, as valid Python
The datetime and django.utils.timezone modules are available, so you can do e.g. timezone.now()
>>> ''
You are trying to add a non-nullable field 'title_fr' to moviedetails without a default; we can't do that (the database needs something to populate existing rows).
Please select a fix:
 1) Provide a one-off default now (will be set on all existing rows)
 2) Quit, and let me add a default in models.py
Select an option: 1
Please enter the default value now, as valid Python
The datetime and django.utils.timezone modules are available, so you can do e.g. timezone.now()
>>> ''
Migrations for 'main':
 0002_auto_20160216_2300.py:
 - Add field description_fr to moviedetails
 - Add field title_fr to moviedetails
 - Alter field movie on moviereview

```

如你在前面的 CLI 会话中所看到的，当我创建迁移时，我被要求为新字段提供默认值。我只输入了空字符串。我们可以稍后从管理员中修复这个值。

最后，运行新的迁移：

```py
> python manage.py migrate
Operations to perform:
 Apply all migrations: admin, contenttypes, main, auth, sessions
Running migrations:
 Rendering model states... DONE
 Applying main.0002_auto_20160216_2300... OK

```

完成后，打开管理员，查看数据库中一个对象的编辑页面。它应该看起来类似于以下截图：

![翻译我们的模型](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj-pj-bp/img/00698_05_07.jpg)

在前面的截图中，你可以看到管理员添加了两个新字段。我使用 Google 翻译翻译了这些字段的英文值，并填写了法语语言字段的值。点击**保存**。现在，我们的模型在英语值旁边有了法语语言数据；但如何显示它们呢？

你可以在模板代码中放置一些 `if/else` 条件来决定使用哪种语言字段。然而，这很快就会变得混乱。现在，我们的模型只有两个被翻译的字段，但想象一下一个有 10 个这样字段的模型。你会有多少条件？我们只讨论支持一种语言。最后，我们只需要修改两个模板，列表视图和详细视图。在一个真实的、更复杂的应用程序中，你的模型可能会被用在一百个不同的地方。`if/else` 方法很快就变得难以维护。

相反，我们将给我们的模型方法，以智能地返回正确的字段值，取决于当前的语言。让我们再次修改我们的 `main/models.py` 文件。首先，在顶部导入 `get_language` 方法：

```py
from django.utils.translation import get_language
```

接下来，再次修改 `MovieDetails` 模型，并添加这三个新方法（在代码中突出显示）：

```py
class MovieDetails(models.Model):
    title = models.CharField(max_length=500)
    title_fr = models.CharField(max_length=500)

    description = models.TextField()
    description_fr = models.TextField()

    stars = models.PositiveSmallIntegerField()

 def get_title(self):
 return self._get_translated_field('title')

 def get_description(self):
 return self._get_translated_field('description')

 def _get_translated_field(self, field_name):
 original_field_name = field_name

 lang_code = get_language()

 if lang_code != 'en':
 field_name = '{}_{}'.format(field_name, lang_code)
 field_value = getattr(self, field_name)

 if field_value:
 return field_value
 else:
 return getattr(self, original_field_name)

    def __str__(self):
        return self.title
```

新方法中没有任何 Django 特定的内容。主要的工作是 `_get_translated_field` 方法。给定一个字段名，它查看当前的语言，如果语言不是英语，就将语言代码附加到字段名。然后从对象中获取新字段名的值。如果值为空，因为我们没有翻译该字段，它遵循 Django 的约定，只返回原始未翻译字段的值。

现在，修改 `main/templates/movies_list.html` 来使用这些新方法：

```py
{% extends "base.html" %}
{% load i18n %}

{% block content %}
<h2>{% trans "Movies List" %}</h2>

<ul>
    {% for movie in object_list %}
<li><a href="{% url 'movie-details' pk=movie.pk %}">{{ movie.get_title }}</a> | {{ movie.stars }} {% trans "Stars" %}</li>
    {% endfor %}
</ul>
{% endblock %}
```

唯一的改变是，现在不再直接使用 `movie.title` 的值，而是使用 `movie.get_title`。这是这种方法的一个主要缺点。现在在你的项目中，无论何处你需要 `title` 或 `description` 的值，你都必须使用 `get_title` 和 `get_description` 方法，而不是直接使用字段值。

### 注意

保存字段也是一样的。你必须弄清楚要写入哪个字段名，这取决于激活的语言。虽然这两者都不复杂，但它们确实给整个过程增加了一些不便。然而，这就是你为这种功能付出的代价。

我之前提到的 `django-modeltranslation` 包对这个问题有一个很好的解决方案。它使用模型中的代码来自动决定每当你访问任何字段时应该返回哪种语言。所以，你不再使用 `obj.get_title()`，而是直接写 `obj.title`，就可以得到当前激活语言的正确字段。对于你的项目，你可能需要研究一下这个。我在本章中没有使用这个，因为我想给你一个使用基本的 Django 的方法，并向你展示一种自己处理事情的可能方式，而不是依赖第三方库。

再次打开网站的法语版本，你会看到我们翻译的一个对象应该有标题的翻译版本，而其他的则只显示未翻译的版本：

![翻译我们的模型](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj-pj-bp/img/00698_05_08.jpg)

对于详情模板做同样的事情应该很简单，留给你来完成！

# 总结

虽然这是一个相对较小的章节，但我们看到的信息将在您的网络开发职业生涯中派上用场。虽然并非您开发的所有网站都需要被翻译成多种语言，但一些最重要的网站会需要。当您有机会参与这样的项目时，您将拥有如何创建一个真正国际化的网络应用程序的信息。

我们只是初步了解了 Django 国际化和本地化的可能性。当您开始一个需要这些功能的项目时，请务必查阅文档。

我们现在已经完成了简单的仅使用 Django 的应用程序。在学习了 Django 的基础知识之后，下一章将让我们开始开发一个更复杂的网络应用程序——一个涉及使用强大的 Elasticsearch 进行搜索的应用程序！


# 第六章：戴恩特里 - 电子商务网站

在前几章中，我们创建了一些稳健的网络应用。它们很简单，但具有足够的功能，可以在真实项目中使用。通过一些前端工作，我们的应用很可能可以部署在互联网上，并解决真实问题。现在是时候看一些更复杂的东西了。

我相信你已经使用过，或者至少听说过，电子商务领域的一些大名鼎鼎的公司，比如亚马逊和阿里巴巴。虽然这些网站非常复杂，但在内部，一个基本的电子商务网站是相当简单的。电子商务网站也是许多客户想要创建的东西，因此了解如何制作一个好的电子商务网站对你的职业生涯将非常有用。

一个基本的电子商务网站有一个主要目的：帮助用户从在线商店找到并购买产品。Django 可以单独用于快速构建电子商务网站，使用数据库查询来允许跨产品范围进行搜索，但这并不适合扩展。数据库被设计为快速保存和检索数据行，但它们并不是为了跨整个数据集（或子集）进行搜索而进行优化的。一旦您的网站流量开始增加，您会发现搜索速度会迅速下降。除此之外，还有一些很难用数据库构建的功能。

相反，我们将使用**搜索服务器**。搜索服务器非常类似于数据库。您可以给它一些数据来存储，然后以后可以检索它。它还具有专门为帮助您向应用程序添加搜索而构建的功能。您可能会想，如果搜索服务器可以像数据库一样存储我们的数据，那么我们不是可以摆脱数据库吗？我们可以，但通常不建议这样做。为什么？因为搜索服务器是为不同的用例而设计的。虽然它可以存储您的数据，但数据库提供了许多关于存储的保证，搜索服务器通常不提供。例如，一个好的数据库（如 MySQL 或 PostgreSQL）会保证，如果您尝试保存某些内容并且数据库返回成功的响应，那么在发生崩溃、停电或其他问题时，您的数据不会丢失。这被称为耐久性。搜索服务器不提供此保证，因为这不是它们的设计目的。通常最好将我们的数据保存在数据库中，并使用搜索服务器来搜索我们的数据。

在本章中，我们将使用**Elasticsearch**，这是最受欢迎、可能也是最易于使用的搜索服务器之一。它也是开源的，可以免费使用。所以让我们开始吧。这将是一个令人兴奋的章节！

# 代码包

本章的代码包含了一个基本的网络应用程序，其中包含了一个简单电子商务网站的模型和视图。现在还没有搜索，只有一个列出所有可用产品的页面。我还提供了一个数据转储，其中包含大约 1,000 个产品，这样我们的数据库就有一些可以玩耍的数据。与往常一样，下载代码包，创建一个新的虚拟环境，安装 Django，运行迁移命令，然后发出`run server`命令来启动开发服务器。你现在应该已经掌握了如何在没有任何指导的情况下做这些事情。

要加载测试数据，请在迁移命令之后运行以下命令：

```py
> python manage.py loaddata main/fixtures/initial.json

```

这应该会用一千个样品产品填满你的数据库，并为我们提供足够的数据来玩耍。

# 探索 Elasticsearch

在我们将 Elasticsearch 与 Django 应用程序集成之前，让我们花点时间来探索 Elasticsearch。我们将研究如何将数据导入其中，并使用搜索功能来获取我们想要的结果。我们不会详细讨论搜索，因为我们将在构建应用程序的搜索页面时再进行研究，但我们将对 Elasticsearch 的工作原理和它对我们有用的地方进行基本概述。

首先，从[`www.elastic.co/downloads/elasticsearch`](https://www.elastic.co/downloads/elasticsearch)下载最新版本的 Elasticsearch。你需要在系统上安装 Java 才能运行 Elasticsearch，所以如果你还没有安装，就去安装吧。你可以从[`java.com/en/download/`](https://java.com/en/download/)获取 Java。下载完 Elasticsearch 后，将压缩存档中的文件提取到一个文件夹中，打开一个新的终端会话，并`cd`到这个文件夹。接下来，`cd`进入`bin`文件夹，并运行以下命令：

```py
> ./elasticsearch
.
.
.
[2016-03-06 17:53:53,091][INFO ][http                     ] [Marvin Flumm] publish_address {127.0.0.1:9200}, bound_addresses {[fe80::1]:9200}, {[::1]:9200}, {127.0.0.1:9200}
[2016-03-06 17:53:53,092][INFO ][node                     ] [Marvin Flumm] started
[2016-03-06 17:53:53,121][INFO ][gateway                  ] [Marvin Flumm] recovered [0] indices into cluster_state
```

运行 Elasticsearch 二进制文件应该会产生大量的输出，它会与我粘贴的内容不同。然而，你应该仍然能看到输出的最后出现两条消息**started**和**recovered [0] indices into cluster_state**。这意味着 Elasticsearch 现在正在你的系统上运行。这并不难！当然，在生产环境中运行 Elasticsearch 会有些不同，Elasticsearch 文档提供了大量关于如何为几种不同的用例部署它的信息。

在本章中，我们只涵盖了 Elasticsearch 的基础知识，因为我们的重点是查看 Django 和 Elasticsearch 之间的集成，但如果你发现自己陷入困境或需要解答一些问题，可以查看文档——它真的非常广泛和详尽。你可以在[`www.elastic.co/guide/en/elasticsearch/reference/current/index.html`](https://www.elastic.co/guide/en/elasticsearch/reference/current/index.html)找到它。如果你真的想花时间学习 Elasticsearch，还有一本书式指南可供参考，地址是[`www.elastic.co/guide/en/elasticsearch/guide/current/index.html`](https://www.elastic.co/guide/en/elasticsearch/guide/current/index.html)。

## Elasticsearch 的第一步

既然我们已经运行了 Elasticsearch，我们可以用它做些什么呢？首先，你需要知道 Elasticsearch 通过一个简单的 HTTP API 公开其功能。因此，你不需要任何特殊的库来与其通信。大多数编程语言，包括 Python，都包含了进行 HTTP 请求的手段。然而，有一些库提供了另一层对 HTTP 的抽象，并使得与 Elasticsearch 的工作更加容易。我们稍后会详细介绍这些。

现在，让我们在浏览器中打开这个 URL：

```py
http://localhost:9200/?pretty
```

这应该会给你一个类似于这样的输出：

```py
{
  "name" : "Marvin Flumm",
  "cluster_name" : "elasticsearch",
  "version" : {
    "number" : "2.2.0",
    "build_hash" : "8ff36d139e16f8720f2947ef62c8167a888992fe",
    "build_timestamp" : "2016-01-27T13:32:39Z",
    "build_snapshot" : false,
    "lucene_version" : "5.4.1"
  },
  "tagline" : "You Know, for Search"
}
```

虽然大部分值都会不同，但响应的结构应该大致相同。这个简单的测试让我们知道 Elasticsearch 在我们的系统上正常工作。

现在我们将快速浏览一下，我们将插入、检索和搜索一些产品。我不会详细介绍，但如果你感兴趣，你应该查看我之前提到的 Elasticsearch 文档。

### 注意

在本节中，你需要在你的机器上安装一个工作的 curl 命令行实用程序的副本才能执行这些步骤。它应该默认在 Linux 和 Unix 平台上，包括 Mac OS X 上可用。如果你在 Windows 上，你可以从[`curl.haxx.se/download.html`](https://curl.haxx.se/download.html)获取一个副本。

打开一个新的终端窗口，因为我们当前的窗口中已经运行了 Elasticsearch。接下来，输入以下内容：

```py
> curl -XPUT http://localhost:9200/daintree/products/1 -d '{"name": "Django Blueprints", "category": "Book", "price": 50, "tags": ["django", "python", "web applications"]}'
{"_index":"daintree","_type":"products","_id":"1","_version":1,"_shards":{"total":2,"successful":1,"failed":0},"created":true}      
                                                > curl -XPUT http://localhost:9200/daintree/products/2 -d '{"name": "Elasticsearch Guide", "category": "Book", "price": 100, "tags": ["elasticsearch", "java", "search"]}'
{"_index":"daintree","_type":"products","_id":"2","_version":1,"_shards":{"total":2,"successful":1,"failed":0},"created":true}
```

大多数 Elasticsearch API 接受 JSON 对象。在这里，我们要求 Elasticsearch 将两个文档，id 为 1 和 2，放入其存储中。这可能看起来很复杂，但让我解释一下这里发生了什么。

在数据库服务器中，你有数据库、表和行。你的数据库就像一个命名空间，所有的表都驻留在其中。表定义了你想要存储的数据的整体形状，每一行都是这些数据的一个单元。Elasticsearch 有一种稍微不同的处理数据的方式。

在数据库的位置，Elasticsearch 有一个索引。表被称为文档类型，并且存在于索引内。最后，行，或者正如 Elasticsearch 所称的那样，文档存储在文档类型内。在我们之前的例子中，我们告诉 Elasticsearch 在**daintree**索引中的**products**文档类型中`PUT`一个 Id 为**1**的文档。我们在这里没有做的一件事是定义文档结构。这是因为 Elasticsearch 不需要固定的结构。它会动态更新表的结构（文档类型），当你插入新的文档时。

让我们尝试检索我们插入的第一个文档。运行这个命令：

```py
> curl -XGET 'http://localhost:9200/daintree/products/1?pretty=true'
{
  "_index" : "daintree",
  "_type" : "products",
  "_id" : "1",
  "_version" : 1,
  "found" : true,
  "_source" : {
    "name" : "Django Blueprints",
    "category" : "Book",
    "price" : 50,
    "tags" : [ "django", "python", "web applications" ]
  }
}
```

正如你可能猜到的那样，Elasticsearch 的 API 非常简单和直观。当我们想要插入一个文档时，我们使用`PUT` HTTP 请求。当我们想要检索一个文档时，我们使用`GET` HTTP 请求类型，并且我们给出了与插入文档时相同的路径。我们得到的信息比我们插入的要多一些。我们的文档在`_source`字段中，其余字段是 Elasticsearch 与每个文档存储的元数据。

现在我们来看看搜索的主角——搜索！让我们看看如何对标题中包含 Django 的书进行简单搜索。运行以下命令：

```py
> curl -XGET 'http://localhost:9200/daintree/products/_search?q=name:Django&pretty'
{
  "took" : 4,
  "timed_out" : false,
  "_shards" : {
    "total" : 5,
    "successful" : 5,
    "failed" : 0
  },
  "hits" : {
    "total" : 1,
    "max_score" : 0.19178301,
    "hits" : [ {
      "_index" : "daintree",
      "_type" : "products",
      "_id" : "1",
      "_score" : 0.19178301,
      "_source" : {
        "name" : "Django Blueprints",
        "category" : "Book",
        "price" : 50,
        "tags" : [ "django", "python", "web applications" ]
      }
    } ]
  }
}
```

结果是你对这次搜索的预期。Elasticsearch 只返回了一个包含 Django 一词的文档，并跳过了其他的。这被称为 lite 搜索或查询字符串搜索，因为我们的查询作为查询字符串参数的一部分发送。然而，对于具有多个参数的复杂查询，这种方法很快变得难以使用。对于这些查询，Elasticsearch 提供了完整的查询 DSL，它使用 JSON 来指定查询。让我们看看如何使用查询 DSL 进行相同的搜索：

```py
> curl -XGET 'http://localhost:9200/daintree/products/_search?pretty' -d '{"query": {"match": {"name": "Django"}}}'
{
  "took" : 3,
  "timed_out" : false,
  "_shards" : {
    "total" : 5,
    "successful" : 5,
    "failed" : 0
  },
  "hits" : {
    "total" : 1,
    "max_score" : 0.19178301,
    "hits" : [ {
      "_index" : "daintree",
      "_type" : "products",
      "_id" : "1",
      "_score" : 0.19178301,
      "_source" : {
        "name" : "Django Blueprints",
        "category" : "Book",
        "price" : 50,
        "tags" : [ "django", "python", "web applications" ]
      }
    } ]
  }
}
```

这一次，我们不再传递查询参数，而是发送一个带有 GET 请求的主体。主体是我们希望执行的 JSON 查询。我不会解释查询 DSL，因为它有很多功能，非常强大，需要另一本书来正确解释它。事实上，已经有几本书完全解释了 DSL。然而，对于像这样的简单用法，你可以很容易地猜到发生了什么。如果你想了解更多细节，我再次建议查看 Elasticsearch 文档。

# 从 Python 中搜索

现在我们已经基本了解了如何使用 Elasticsearch 来插入和搜索我们的文档，让我们看看如何从 Python 中做同样的事情。我们可以使用 Python 中的 Elasticsearch 的 HTTP API 并查询文档，但有更好的方法。有许多库提供了对 Elasticsearch 的 HTTP API 的抽象。在底层，它们只是简单地使用 HTTP API，但它们提供的抽象使我们更容易与 Elasticsearch 通信。我们将在这里使用的库是`elasticsearch_dsl`。确保你的虚拟环境已激活，并使用`pip`安装它：

```py
> pip install elasticsearch_dsl

```

接下来，让我们启动一个 Django shell，这样我们就可以玩耍并弄清楚如何使用它：

```py
> python manage.py shell
> from elasticsearch_dsl import Search
> from elasticsearch_dsl.connections import connections
> connections.create_connection(hosts=['localhost:9200'])
<Elasticsearch([{u'host': u'localhost', u'port': 9200}])>
> Search(index='daintree').query('match', name='django').execute().to_dict()
{u'_shards': {u'failed': 0, u'successful': 5, u'total': 5},
 u'hits': {u'hits': [{u'_id': u'1',
    u'_index': u'daintree',
    u'_score': 0.19178301,
    u'_source': {u'category': u'Book',
     u'name': u'Django Blueprints',
     u'price': 50,
     u'tags': [u'django', u'python', u'web applications']},
    u'_type': u'products'}],
  u'max_score': 0.19178301,
  u'total': 1},
 u'timed_out': False,
 u'took': 2}
```

让我们来看看每一行。前两行只是导入库。第三行很重要。它使用`create_connection`方法来定义一个默认连接。这是每当我们尝试使用这个库进行搜索时使用的连接，使用默认设置。

接下来，我们执行搜索并打印结果。这是重要的部分。这一行代码做了几件事情，让我们来分解一下。首先，我们构建了一个`Search`对象，传入了我们之前创建的`daintree`索引的索引名称。由于我们没有传入自定义的 Elasticsearch 连接，它使用了我们之前定义的默认连接。

接下来，我们在`Search`对象上使用`query`方法。这种语法很简单。第一个参数是我们想要使用的查询类型的名称。就像我们使用`curl`一样，我们使用`match`查询类型。查询方法的所有其他参数都需要是关键字参数，这些参数将是查询的元素。在这里，这生成了与我们之前使用`curl`示例相同的查询：

```py
{
    "query": {
        "match": {
            "name": "django"
        }
    }
}
```

在`Search`对象中添加查询后，我们需要显式执行它。这是通过`execute`方法完成的。最后，为了查看响应，我们使用响应的辅助`to_dict`方法，该方法打印出 Elasticsearch 对我们的搜索做出的响应；在这种情况下，它类似于我们之前使用`curl`时得到的内容。

现在我们已经看到了如何搜索，下一步将是看看如何向我们的 Elasticsearch 索引添加数据。在我们这样做之前，我们需要了解 Elasticsearch 映射。

# 映射

我之前提到过，Elasticsearch 不需要为文档类型定义数据结构。但是，Elasticsearch 在内部会弄清楚我们插入的数据的结构。我们有能力手动定义这个结构，但不一定需要这样做。当 Elasticsearch 使用自己猜测的数据结构时，它被称为使用文档类型的动态映射。让我们看看 Elasticsearch 为我们的`product`文档类型猜测了什么。使用命令行，使用 curl 发出以下请求：

```py
> curl 'http://localhost:9200/daintree/products/_mapping?pretty'
{
  "daintree" : {
    "mappings" : {
      "products" : {
        "properties" : {
          "category" : {
            "type" : "string"
          },
          "name" : {
            "type" : "string"
          },
          "price" : {
            "type" : "long"
          },
          "tags" : {
            "type" : "string"
          }
        }
      }
    }
  }
}
```

Elasticsearch 已经相当准确地猜测了我们的文档结构。正如您所看到的，它正确猜测了所有字段的类型。但是，如果您注意到 tags 字段的类型，您会发现它是一个字符串。如果您查看我们之前检索到的文档，您会发现 tags 字段是一个字符串数组。这是怎么回事？

嗯，在 Elasticsearch 中，数组没有任何特殊的映射。每个字段可以有一个或多个值；因此，每个字段都可以是一个数组，而无需将其映射为这样。这种情况的一个重要含义是，Elasticsearch 中的数组只能具有一种数据类型。因此，您不能有一个同时包含日期值和字符串的数组。如果您尝试插入这样的内容，Elasticsearch 将只是将日期存储为字符串。

您可能会想知道，如果 Elasticsearch 足够智能，可以弄清楚我们的数据结构，那么为什么我们要关心映射呢？嗯，我们使用的用于与`Elasticsearch`一起工作的库`elasticsearch_dsl`需要定义自定义映射才能将文档插入索引。

在将数据插入索引时，明确指定要插入的数据类型也是一个好主意。您可以在设置自定义映射时设置许多选项，例如定义字段为整数。这样，即使您插入值“123”，Elasticsearch 也会在插入文档之前将其转换为整数，并在无法转换时引发错误。这提供了数据验证。有某些类型的数据，例如日期格式与 Elasticsearch 默认使用的格式不同，只有在设置了自定义映射时才能正确索引。

## 定义映射

要使用`elasticsearch_dsl`定义映射，我们创建一个`DocType`子类。这类似于定义 Django 数据库模型的方式。创建一个新的`main/es_docs.py`文件，并键入以下代码：

```py
from elasticsearch_dsl import DocType
from elasticsearch_dsl import Long
from elasticsearch_dsl import String

class ESProduct(DocType):
    name = String(required=True)
    description = String()
    price = Long(required=True)

    category = String(required=True)
    tags = String(multi=True)

    class Meta:
        doc_type = 'products'
```

这里不应该有任何意外，因为语法非常简单易懂。我喜欢在我的文档类型类的开头添加 ES，以区分 ES 文档类型类和同名的 Django 模型。请注意，我们明确指定了文档类型名称。如果我们没有这样做，`elasticsearch_dsl`将根据类名自动提出一个名称——`ESProduct`。但是，由于我们只是想为现有的文档类型定义映射，因此我们在`Meta`类中设置了`doc_type`属性。

注意我们的数据类型与我们之前在询问 Elasticsearch 关于映射时看到的数据类型是一样的。这是有原因的。您不能更改现有字段的数据类型。否则，现有文档将具有错误的数据类型，搜索将返回不一致的结果。虽然这个映射已经存在于我们的 Elasticsearch 中，让我们看看如何使用这个类来定义一个新的文档类型映射。再次打开 Django shell，输入以下内容：

```py
> python manage.py shell
> from elasticsearch_dsl.connections import connections
> from main.es_docs import ESProduct
> connections.create_connection()
<Elasticsearch([{}])>
> ESProduct.init(index='daintree')
```

我们使用`ESProduct.init(index='daintree')`方法在 Elasticsearch 中创建映射。由于我们的映射已经存在并且完全相同，这个函数没有改变任何东西。但是，如果我们正在创建一个新的映射，这个函数将配置 Elasticsearch 与新的文档类型。

请注意，这次我们没有向`connections.create_connection()`方法传递任何参数，这意味着它使用了默认的主机列表，假设默认端口 9200 上运行的本地实例 Elasticsearch。由于我们的 Elasticsearch 在同一端口上本地运行，我们可以跳过`create_connection()`方法的主机参数。

# 从 Python 将文档插入 Elasticsearch

现在我们有了一个`DocType`子类，并且已经看到了如何创建映射，剩下的就是插入文档到 Elasticsearch。本节假设您已经加载了我提供的代码片段的 fixtures 数据。

再次打开 Django shell 并输入以下命令：

```py
> python manage.py shell
> from elasticsearch_dsl.connections import connections
> from main.es_docs import ESProduct
> from main.models import Product
> connections.create_connection()
<Elasticsearch([{}])>
> p = Product.objects.get(pk=200)
> esp = ESProduct(meta={'id':p.pk}, name=p.name, description=p.description, price=p.price, category=p.category.name)
> for tag in p.tags.all():
>     esp.tags.append(tag.name)
>
> esp.save(index='daintree')
True
```

### 注意

注意在 for 循环体之后的空行。在 shell 中，这个空行是必需的，告诉交互式 shell 循环体已经结束，可以继续执行循环。

直到我们从数据库中获取 ID 为`200`的产品为止，一切都应该很正常。我只是随机选择了一个 ID，因为我知道在加载我提供的 fixtures 后，您的数据库中将存在 ID 为`200`的产品。

接下来，我们创建一个新的`ESProduct`实例，并从我们的 Django 模型中分配值。ID 字段需要使用特殊的 meta 关键字参数分配一个值，因为它是 Elasticsearch 文档的元数据，而不是文档主体的一部分。如果我们没有提供 ID，Elasticsearch 将自动生成一个随机的 ID。我们明确指定它，以便我们可以将我们的数据库模型与我们的 Elasticsearch 文档联系起来。

接下来，我们循环遍历我们的`Product`对象中的所有标签，并将其附加到我们的`ESProduct`对象中的`tags`字段。我们不需要将`tags`字段的值设置为空数组。当我们定义`tags`字段时，我们向构造函数传递了`multi=True`参数。对于`elasticsearch_dsl`字段，多字段具有默认的空值，即一个空列表。因此，在我们的循环中，我们确信`esp.tags`是一个我们可以附加的列表。

在我们使用正确的值设置了`ESProduct`模型实例之后，我们调用 save 方法，传递要插入的索引名称。一旦保存调用返回，Elasticsearch 将保存我们的新数据。我们可以使用`curl`来检索这个新文档：

```py
> curl 'http://localhost:9200/daintree/products/_search?pretty'

```

在这个命令的输出中，您现在应该看到三个产品，而不是我们最初插入的两个。

## 将所有数据导入 Elasticsearch

我们不能一直从控制台向 Elasticsearch 插入数据。我们需要一种自动化的方法。正如我们之前所看到的，Django 管理命令是创建一个脚本的完美方式。创建将保存我们命令文件的文件夹，`main/management/commands`，在`main/management`和`main/management/commands`中创建一个空的`__init__.py`文件，并将以下代码添加到`main/management/commands/index_all_data.py`中：

```py
import elasticsearch_dsl
import elasticsearch_dsl.connections

from django.core.management import BaseCommand

from main.models import Product
from main.es_docs import ESProduct

class Command(BaseCommand):
    help = "Index all data to Elasticsearch"

    def handle(self, *args, **options):
        elasticsearch_dsl.connections.connections.create_connection()

        for product in Product.objects.all():
            esp = ESProduct(meta={'id': product.pk}, name=product.name, description=product.description,
                            price=product.price, category=product.category.name)
            for tag in product.tags.all():
                esp.tags.append(tag.name)

            esp.save(index='daintree')
```

这里没有什么新的。我们只是循环遍历数据库中的所有产品对象，并将它们添加到 Elasticsearch 中。运行如下：

```py
> python manage.py index_all_data
```

它将成功运行而不输出任何内容，现在您应该在 Elasticsearch 中拥有所有文档。为了确认这一点，我们可以从 Elasticsearch 获取我们的`daintree`索引的统计信息。从您的 shell 运行以下命令：

```py
> curl 'localhost:9200/daintree/_stats?pretty=1'
```

这应该输出有关`daintree`索引的大量数据。您需要向上滚动，您会找到总文档数。它应该类似于这样：

```py
.
.
.
"total" : {
        "docs" : {
          "count" : 1000,
          "deleted" : 0
        },
.
.
.
```

如您所见，我们的所有数据现在都已被索引。接下来，我们将使用 Elasticsearch 在我们的主页上添加搜索。

# 添加搜索

如果您现在查看我们的主页，它应该是从我们的数据库中随机选择的 50 个产品的列表。您可以在`http://127.0.0.1:8000`打开它，它应该看起来类似于这样：

![添加搜索](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj-pj-bp/img/00698_06_01.jpg)

我们想要做的是在这个页面上添加一个基本的搜索表单。表单将只是一个接受搜索词的字段和执行搜索的按钮。搜索词将在我们产品列表的名称字段上执行搜索。

让我们创建一个简单的 Django 表单并将其添加到我们的页面上。创建一个新的`main/forms.py`文件，并添加以下代码：

```py
from django import forms

class SearchForm(forms.Form):
    name = forms.CharField(required=False)
```

接下来，我们需要在主页上显示我们的搜索表单。在`home.html`模板中添加以下内容，就在`content`块的开头标签之后：

```py
<h2>Search</h2>
<form action="" method="get">
    {{ form.as_p }}
    <input type="submit" value="Search" />
</form>
```

最后，我们需要修改我们的`HomeView`，以便它使用用户的查询来生成结果列表，而不是从数据库中获取 50 个随机的结果。更改`main/view.py`以匹配以下代码：

```py
import random

from django.shortcuts import render
from django.template.response import RequestContext
from django.views.generic import View

from elasticsearch_dsl import Search
from elasticsearch_dsl.connections import connections

from main.forms import SearchForm

class HomeView(View):
    def get(self, request):
        form = SearchForm(request.GET)

        ctx = {
            "form": form
        }

        if form.is_valid():
            connections.create_connection()

            name_query = form.cleaned_data["name"]
            s = Search(index="daintree").query("match", name=name_query)
            result = s.execute()

            ctx["products"] = result.hits

        return render(request, "home.html", ctx)
```

首先让我们测试一下，然后我会解释这段代码的作用。在字段中输入搜索词并点击**搜索**按钮。由于我们的示例数据在所有字段中都有通常的`Lorem Ipsum`文本，因此搜索一个词如`lorem`。您应该会看到类似于这样的东西：

![添加搜索](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj-pj-bp/img/00698_06_02.jpg)

尝试使用一些不同的搜索词来玩耍，看看它的反应。如果您输入的内容在我们的产品列表中找不到，您应该会看到一个空页面。我们将更改它，以便用户看到一条消息，告诉他们他们的搜索查询没有结果。此外，类别名称已经消失了。这是因为`product.category.name`模板中使用的属性名称与我们的 Elasticsearch 文档包含的内容不同。虽然我们的 Elasticsearch 文档中大多数字段名称与我们的 Django 模型中的字段名称相同，但类别名称需要以不同的方式访问，因为它不再是外键，而是一个简单的字符串。在`main/templates/home.html`中，请注意以下行：

```py
<i>Category: {{ product.category.name }}</i> <br />
```

将其更改为以下内容：

```py
<i>Category: {{ product.category }}</i> <br />
```

我们的产品的类别名称将重新出现。

如果您进行了一些实验，您会注意到如果您将字段留空并单击**搜索**按钮，您将不会收到任何结果。这是因为如果您给匹配查询一个空字符串进行匹配，它会返回零结果。我们可以通过查询用户是否指定了搜索词来解决这个问题。从视图代码中删除这行：

```py
s = Search(index="daintree").query("match", name=name_query)
```

将其替换为以下条件：

```py
if name_query:
    s = Search(index="daintree").query("match", name=name_query)
else:
    s = Search(index="daintree")
```

这样，如果用户没有输入任何查询，我们要求 Elasticsearch 进行没有指定查询的搜索，Elasticsearch 只返回它拥有的前十个文档。这类似于如果我们使用数据库，执行`Product.objects.all()[:10]`。

现在，让我们更改我们的模板，以便如果没有结果，用户会看到一个漂亮的消息来解释，而不是一个空页面，用户可能会认为这是我们应用程序中的一个错误。更改我们的`main/templates/home.html`模板中的`{% for product in products %}`循环，并将其替换为以下内容：

```py
{% if products %}                                             
    {% for product in products %}
    <li>
        Name: <b>{{ product.name }}</b> <br />
        <i>Category: {{ product.category.name }}</i> <br />
        {% if product.tags.all %}
            Tags: (
            {% for tag in product.tags.all %}
                {{ tag.name }}
                {% if not forloop.last %}
                ,
                {% endif %}
            {% endfor %}
            )
        {% endif %}
    </li>
    {% endfor %}
{% else %}
    No results found. Please try another search term
{% endif %}
```

现在，如果您输入一个没有结果的搜索词，您应该会看到一条消息，而不是一个空页面。

现在，表单和模板代码应该很容易让您理解。最有趣的是视图代码。让我们看看发生魔术的`get`方法：

```py
def get(self, request):
        form = SearchForm(request.GET)

        ctx = {
            "form": form
        }

        if form.is_valid():
            connections.create_connection()

            name_query = form.cleaned_data.get("name")
            if name_query:
                s = Search(index="daintree").query("match", name=name_query)
            else:
                s = Search(index="daintree")
            result = s.execute()

            ctx["products"] = result.hits

        return render(request, "home.html", ctx)
```

首几行只是用请求中的 GET 参数实例化表单。我们还将它添加到稍后传递给模板的上下文字典中。然后，我们检查表单是否有效。如果有效，我们首先使用`elasticsearch_dsl`库中的`create_connection()`方法。我们需要在这里这样做，因为如果没有这样做，我们以后将无法进行搜索。

### 注意

你们中的一些人可能会说，在我们的视图代码中配置 Elasticsearch 连接的方法感觉像是糟糕的代码。我同意！以后，我们会解决这个问题，不用担心。

设置好 Elasticsearch 连接后，我们检查用户是否实际输入了一些搜索词。如果他们输入了，我们就创建`Search`对象并将我们的查询添加到其中。我们指定我们需要`match`查询类型，并且我们希望获取`name`字段中包含用户输入的查询词的文档。如果用户没有输入任何搜索查询，我们需要将我们的搜索对象`s`设置为默认搜索。如前所述，我们这样做是因为如果查询词为空，Elasticsearch 会返回一个空的结果列表。

最后，我们执行搜索并将结果存储在`result`变量中。然后，我们从`result`变量的`hits`参数中提取结果，并将其分配给上下文字典中的`products`键。

最后，我们只需使用我们准备好的上下文字典来呈现模板。正如你所看到的，使用 Elasticsearch 与 Django 并不是非常复杂的事情。`elasticsearch_dsl`库特别使这变得非常简单。

## 配置管理

在前面的代码中，我们在视图代码中使用`connections.create_connection()`方法来设置我们的 Elasticsearch 连接。由于几个原因，这是一个不好的做法。首先，你必须记住在每个想要使用 Search 对象的视图中初始化连接。我们的示例只有一个视图，所以我们没有遇到这个问题。但是，想象一下，如果你有三个使用 Elasticsearch 的视图。现在你的`create_connection()`方法调用必须在这三个视图中都有，因为你永远不知道用户会以什么顺序访问网站，哪个视图会首先运行。

其次，更重要的是，如果你需要改变连接配置的方式——也许是改变 Elasticsearch 服务器的地址或设置其他连接参数——你需要在所有初始化连接的地方进行更改。

由于这些原因，将初始化外部连接的代码放在一个地方总是一个好主意。Django 为我们提供了一个很好的方法来使用`AppConfig`对象来做到这一点。

当 Django 启动时，它将导入`settings.INSTALLED_APPS`列表中列出的所有应用程序。对于每个应用程序，它将检查应用程序的`__init__.py`是否定义了`default_app_config`变量。这个变量需要是一个字符串，其中包含指向`AppConfig`类的子类的 Python 路径。

如果定义了`default_app_config`变量，Django 将使用指向的子类作为该应用程序的配置选项。如果没有，Django 将创建一个通用的`AppConfig`对象并使用它。

`AppConfig`子类有一些有趣的用途，比如为应用程序设置详细名称和获取应用程序中定义的模型。对于我们的情况，`AppConfig`子类可以定义一个`ready()`方法，Django 在首次导入应用程序时将调用该方法一次。我们可以在这里设置我们的 Elasticsearch 连接，然后只需在整个应用程序中使用`Search`对象，而不需要关心连接是否已配置。现在让我们来做这个。

首先，编辑`main/apps.py`文件并更改代码以匹配以下内容：

```py
from __future__ import unicode_literals

from django.apps import AppConfig

from elasticsearch_dsl.connections import connections

class MainConfig(AppConfig):
    name = 'main'

    def ready(self):
        connections.create_connection()
```

接下来，打开`main/__init__.py`并添加以下行：

```py
default_app_config = "main.apps.MainConfig"
```

最后，从`main/views.py`中删除导入：

```py
from elasticsearch_dsl.connections import connections
```

从`HomeView`的`get`方法中删除`connections.create_connection()`方法调用。

再次打开主页并进行几次搜索。您会发现即使在我们的视图中没有`create_connection()`方法调用，搜索也能正常工作。如果您想了解有关`AppConfig`的更多信息，我建议您查看 Django 文档[`docs.djangoproject.com/en/stable/ref/applications/`](https://docs.djangoproject.com/en/stable/ref/applications/)。

## 更多搜索选项

虽然我们的基本搜索很有用，但我们的用户肯定也需要一些按价格范围搜索的方法。让我们看看如何将其添加到我们的搜索表单中。我们将使用`range` Elasticsearch 查询类型来添加此功能。首先，让我们更改`main/forms.py`以添加我们需要的两个字段-最低价格和最高价格：

```py
from django import forms

class SearchForm(forms.Form):
    name = forms.CharField(required=False)
    min_price = forms.IntegerField(required=False, label="Minimum Price")
    max_price = forms.IntegerField(required=False, label="Maximum Price")
```

接下来，更改`HomeView`代码以接受并使用我们搜索查询中的这些新字段：

```py
class HomeView(View):
    def get(self, request):
        form = SearchForm(request.GET)

        ctx = {
            "form": form
        }

        if form.is_valid():
            name_query = form.cleaned_data.get("name")
            if name_query:
                s = Search(index="daintree").query("match", name=name_query)
            else:
                s = Search(index="daintree")

            min_price = form.cleaned_data.get("min_price")
            max_price = form.cleaned_data.get("max_price")
            if min_price is not None or max_price is not None:
                price_query = dict()

                if min_price is not None:
                    price_query["gte"] = min_price

                if max_price is not None:
                    price_query["lte"] = max_price

                s = s.query("range", price=price_query)

            result = s.execute()

            ctx["products"] = result.hits

        return render(request, "home.html", ctx)
```

在视图中，我们首先检查用户是否为最低价格或最高价格提供了值。如果用户没有为任何字段输入任何值，那么添加空查询就没有意义。

如果用户为两个价格范围字段中的任何一个输入了值，我们首先实例化一个空字典（稍后我们将看到为什么需要字典）。然后，根据用户在两个价格范围字段中输入数据的情况，我们向字典添加大于或等于和小于或等于子句。最后，我们添加一个范围查询，将我们创建的字典作为字段名称关键字参数的值传递，`price`在我们的情况下。以下是相关的代码行：

```py
s = s.query("range", price=price_query)
```

我们在这里需要一个字典而不是在上一个示例中需要的原因是因为一些 Elasticsearch 查询不仅仅有一个选项。在范围查询的情况下，Elasticsearch 支持`gte`和`lte`选项。但是，我们正在使用的库`elasticsearch_dsl`只能接受任何查询类型的一个参数，并且此参数需要作为字段名称的关键参数传递，我们的情况下是`price`。因此，我们创建一个字典，然后将其传递给我们的范围查询。

现在您应该在我们的主页上看到这两个字段，并且能够使用它们进行查询。您会注意到我们没有向用户提供有关产品价格的任何反馈。它没有显示在任何地方。因此，我们无法确认搜索是否实际起作用。让我们现在添加它。更改`main/templates/home.html`以在我们显示产品类别的下方添加这行：

```py
<i>Price: {{ product.price }}</i> <br />
```

现在，如果您查看主页，它将为您显示每个产品的价格，并且您会感到它提供了更好的用户体验。此外，您现在还可以测试最低和最高价格搜索代码。到目前为止，我们的主页看起来是这样的：

![更多搜索选项](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj-pj-bp/img/00698_06_03.jpg)

到目前为止，我们在 Elasticsearch 中还没有做任何数据库无法轻松完成的事情。我们可以使用 Django ORM 构建所有这些查询，并且它将起到相同的作用。也许我们获得了一些性能优势，但在我们的应用程序操作的小规模中，这些收益几乎可以忽略不计。接下来，我们将添加一个使用仅仅数据库很难创建的功能，并且我们将看到 Elasticsearch 如何使它变得更容易。

# 聚合和过滤器

如果您曾经使用过亚马逊（或任何其他大型电子商务网站），您可能会记得在搜索结果的左侧，这些网站提供了一个用户可以轻松选择和浏览搜索结果的过滤器列表。这些过滤器是根据显示的结果动态生成的，选择一个过滤器会进一步缩小搜索结果。通过截图更容易理解我的意思。在亚马逊上，如果您进行搜索，您会在屏幕左侧看到类似于以下内容：

![聚合和过滤器](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj-pj-bp/img/00698_06_04.jpg)

如果您选择这里列出的任何选项，您将进一步细化您的搜索，并只看到与该选项相关的结果。它们还为用户提供了即时反馈，让他们一目了然地知道如果他们选择其中一个可用选项，他们可以期望看到多少结果。

我们想在我们的应用程序中实现类似的功能。Elasticsearch 提供了一个名为聚合的功能来帮助我们做到这一点。让我们先看看什么是聚合。

聚合提供了一种获取有关我们搜索结果的统计信息的方法。有两种类型的聚合可用于获取有关搜索结果的两种不同类型的数据：bucket 聚合和度量聚合。

Bucket 聚合类似于`GROUP BY SQL`查询。它们根据某些维度将文档聚合到组或桶中，并为这些组中的每个计算一些指标。最简单的聚合是`terms`聚合。您给它一个字段名，对于该字段的每个唯一值，Elasticsearch 返回包含该值的字段的文档计数。

例如，假设您的索引中有五个文档：

```py
{"name": "Book 1", "category": "web"}
{"name": "Book 2", "category": "django"}
{"name": "Book 3", "category": "java"}
{"name": "Book 4", "category": "web"}
{"name": "Book 5", "category": "django"}
```

如果我们根据类别字段对这些数据运行 terms 聚合，我们将得到返回结果，这些结果给出了每个类别中书籍的数量：web 中有两本，Django 中有两本，Java 中有一本。

首先，我们将为产品列表中的类别添加聚合，并允许用户根据这些类别筛选他们的搜索。

## 类别聚合

第一步是向我们的搜索对象添加一个聚合，并将来自此聚合的结果传递给我们的模板。更改`main/views.py`中的`HomeView`以匹配以下代码：

```py
class HomeView(View):
    def get(self, request):
        form = SearchForm(request.GET)

        ctx = {
            "form": form
        }

        if form.is_valid():
            name_query = form.cleaned_data.get("name")
            if name_query:
                s = Search(index="daintree").query("match", name=name_query)
            else:
                s = Search(index="daintree")

            min_price = form.cleaned_data.get("min_price")
            max_price = form.cleaned_data.get("max_price")
            if min_price is not None or max_price is not None:
                price_query = dict()

                if min_price is not None:
                    price_query["gte"] = min_price

                if max_price is not None:
                    price_query["lte"] = max_price

                s = s.query("range", price=price_query)

            # Add aggregations
 s.aggs.bucket("categories", "terms", field="category")

            result = s.execute()

            ctx["products"] = result.hits
 ctx["aggregations"] = result.aggregations

        return render(request, "home.html", ctx)
```

我已经突出显示了新代码，只有两行。第一行如下：

```py
s.aggs.bucket("categories", "terms", field="category")
```

这一行向我们的搜索对象添加了一个 bucket 类型的聚合。在 Elasticsearch 中，每个聚合都需要一个名称，并且聚合结果与响应中的此名称相关联。我们给我们的聚合起名为`categories`。方法的下一个参数是我们想要的聚合类型。因为我们想要计算每个不同类别术语的文档数量，所以我们使用`terms`聚合。正如我们将在后面看到的，Elasticsearch 有许多不同的聚合类型，几乎可以满足您能想到的所有用例。在第二个参数之后，所有关键字参数都是聚合定义的一部分。每种类型的聚合需要不同的参数。`terms`聚合只需要要聚合的字段的名称，这在我们的文档中是`category`。

下一行如下：

```py
ctx["aggregations"] = result.aggregations
```

这一行将我们的聚合结果添加到我们的模板上下文中，我们将在模板中使用它进行渲染。聚合结果的格式类似于这样：

```py
{
    "categories": {
        "buckets": [
            {
                "key": "CATEGORY 1",
                "doc_count": 10
            },

            {
                "key": "CATEGORY 2",
                "doc_count": 50
            },

            .
            .
            .
        ]
    }
}
```

顶层字典包含我们添加的每个聚合的键，与我们添加的名称相同。在我们的情况下，名称是`categories`。每个键的值是该聚合的结果。对于 bucket 聚合，就像我们使用的`terms`一样，结果是一个桶的列表。每个桶都有一个键，这是一个不同的类别名称，以及具有该类别的文档数量。

让我们首先在模板中显示这些数据。更改`main/templates/home.html`以匹配以下代码：

```py
{% extends "base.html" %}

{% block content %}
<h2>Search</h2>
<form action="" method="get">
    {{ form.as_p }}
    <input type="submit" value="Search" />
</form>

{% if aggregations.categories.buckets %}
<h2>Categories</h2>
<ul>
{% for bucket in aggregations.categories.buckets %}
 <li>{{ bucket.key }} ({{ bucket.doc_count }})</li>
{% endfor %}
</ul>
{% endif %}

<ul>
    {% if products %}
        {% for product in products %}
        <li>
            Name: <b>{{ product.name }}</b> <br />
            <i>Category: {{ product.category }}</i> <br />
            <i>Price: {{ product.price }}</i> <br />
            {% if product.tags.all %}
                Tags: (
                {% for tag in product.tags.all %}
                    {{ tag.name }}
                    {% if not forloop.last %}
                    ,
                    {% endif %}
                {% endfor %}
                )
            {% endif %}
        </li>
        {% endfor %}
    {% else %}
        No results found. Please try another search term
    {% endif %}
</ul>
{% endblock %}
```

再次，我已经突出显示了新代码。看到了前面输出的格式，这个新代码对你来说应该很简单。我们只是循环遍历每个桶项，并在这里显示类别的名称和具有该类别的文档数量。

让我们来看看结果。在浏览器中打开主页并进行搜索；您应该会看到类似于这样的结果：

![类别聚合](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj-pj-bp/img/00698_06_05.jpg)

现在我们有一个显示的类别列表。但等等，这是什么？如果你仔细看，你会发现没有一个类别名称是有意义的（除了它们是拉丁文）。我们看到的类别都不符合我们的产品类别。为什么呢？

这里发生的是 Elasticsearch 获取了我们的类别列表，将它们分解成单个单词，然后进行了聚合。例如，如果三个产品的类别是*web development*、*django development*和*web applications*，这个聚合将给我们以下结果：

+   网络（2）

+   开发（2）

+   django（1）

+   应用程序（1）

然而，这对我们的用例没有用。我们的类别名称应该被视为一个单位，而不是分解成单个单词。此外，当我们索引数据时，我们从未要求 Elasticsearch 做任何这样的事情。那么发生了什么？要理解这一点，我们需要了解 Elasticsearch 如何处理文本数据。

## 全文搜索和分析

Elasticsearch 基于 Lucene，这是一个非常强大的库，用于创建全文搜索应用程序。全文搜索有点像在自己的文档上使用 Google。您一生中可能已经使用过类似 Microsoft Word 这样的文字处理器中的查找功能，或者在网页上几次。这种搜索方法称为精确匹配。例如，您有一段文本，就像从《一千零一夜故事》的序言中摘取的这段：

> *《一千零一夜故事》中的女主人公沙赫拉萨德（Scheherazadè）与世界上伟大的讲故事者一样，就像佩内洛普（Penelope）与织工一样。拖延是她艺术的基础；尽管她完成的任务是辉煌而令人难忘的，但她的发明量远远超过了质量——在长时间的表演中，本来可以更简短地完成的任务——这使她成为戏剧性兴趣的人物。*

如果您使用精确匹配搜索术语`memorable quantity`，它将不会显示任何结果。这是因为在这段文本中没有找到确切的术语`memorable quantity`。

然而，全文搜索会返回这段文本，因为即使确切术语`memorable quantity`在文本中没有出现，但`memorable`和`quantity`这两个词确实出现在文本中。即使搜索`memorable Django`，这段文本仍然会返回，因为`memorable`这个词仍然出现在文本中，即使`Django`没有。这就是大多数用户期望在网络上进行搜索的方式，特别是在电子商务网站上。

如果您在我们的网站上搜索`Django web development`图书，但我们没有确切标题的书，但我们有一本名为`Django Blueprints`的书，用户会期望在搜索结果中看到它。

这就是当您使用全文搜索时 Elasticsearch 所做的。它会将您的搜索词分解成单词，然后使用这些单词来查找包含这些词的搜索结果。但是，为了做到这一点，Elasticsearch 还需要在索引文档时分解您的文档，以便以后可以更快地进行搜索。这个过程称为分析文档，并且默认情况下对所有字符串字段在索引时间进行。

这就是为什么当我们为我们的类别字段获取聚合时，我们得到的是单个单词，而不是结果中完整的类别名称。虽然全文搜索在大多数搜索情况下非常有用，例如我们拥有的名称查询搜索，但在类别名称等情况下，它实际上给我们带来了意想不到的结果。

正如我之前提到的，导致 Elasticsearch 分解（这个技术术语称为标记化）的分析过程是在索引时间完成的。为了确保我们的类别名称不被分析，我们需要更改我们的`ESProduct DocType`子类并重新索引所有数据。

首先，让我们在`main/es_docs.py`中更改我们的`ESProduct`类。注意以下行：

```py
category = String(required=True)
```

将其更改如下：

```py
category = String(required=True, index="not_analyzed")
```

然而，如果我们现在尝试更新映射，我们将遇到问题。Elasticsearch 只能为字段创建映射，而不能更新它们。这是因为如果允许在索引中有一些数据之后更改字段的映射，旧数据可能再也不符合新的映射了。

要删除我们现有的 Elasticsearch 索引，请在命令行中运行以下命令：

```py
> curl -XDELETE 'localhost:9200/daintree'
{"acknowledged":true}
```

接下来，我们想要创建我们的新索引并添加`ESProduct`映射。我们可以像以前一样从 Python shell 中创建索引。相反，让我们修改我们的`index_all_data`命令，在运行时自动创建索引。更改`main/management/commands/index_all_data.py`中的代码以匹配以下内容：

```py
import elasticsearch_dsl
import elasticsearch_dsl.connections

from django.core.management import BaseCommand

from main.models import Product
from main.es_docs import ESProduct

class Command(BaseCommand):
    help = "Index all data to Elasticsearch"

    def handle(self, *args, **options):
        elasticsearch_dsl.connections.connections.create_connection()
        ESProduct.init(index='daintree')

        for product in Product.objects.all():
            esp = ESProduct(meta={'id': product.pk}, name=product.name, description=product.description,
                            price=product.price, category=product.category.name)
            for tag in product.tags.all():
                esp.tags.append(tag.name)

            esp.save(index='daintree')
```

我已经突出显示了更改，只是添加了一行调用`ESProduct.init`方法。最后，让我们运行我们的命令：

```py
> python manage.py index_all_data

```

运行命令后，让我们确保我们的新映射被正确插入。让我们通过在命令行中运行以下命令来查看 Elasticsearch 现在有什么映射：

```py
> curl "localhost:9200/_mapping?pretty=1"
{
  "daintree" : {
    "mappings" : {
      "products" : {
        "properties" : {
          "category" : {
            "type" : "string",
            "index" : "not_analyzed"
          },
          "description" : {
            "type" : "string"
          },
          "name" : {
            "type" : "string"
          },
          "price" : {
            "type" : "long"
          },
          "tags" : {
            "type" : "string"
          }
        }
      }
    }
  }
}
```

如果您查看`category`字段的映射，现在它不再被分析。让我们再试一次最后的搜索，看看这是否解决了我们的类别聚合问题。现在你应该看到类似于这样的东西：

![全文搜索和分析](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj-pj-bp/img/00698_06_06.jpg)

如您所见，我们不再将我们的类别名称拆分为单独的单词。相反，我们得到了一个唯一类别名称的列表，这正是我们从一开始想要的。现在让我们让我们的用户能够选择其中一个类别，将他们的搜索限制为所选的类别。

# 使用聚合进行搜索

我们希望用户交互是这样的：用户打开搜索页面或进行搜索并看到类别链接列表。然后用户点击其中一个链接，只看到来自这些类别的产品，并应用用户之前的搜索。因此，如果用户搜索价格在 100 到 200 之间的产品，然后点击一个类别链接，新的搜索应该只显示来自该类别的产品，同时仍然应用价格过滤。

为了实现这一点，我们需要一种方法来创建类别链接，以便保留当前搜索。我们可以将类别作为另一个 GET 参数传递给`HomeView`。因此，我们需要获取当前的 GET 参数（构成当前搜索）并将我们的类别名称添加到其末尾作为另一个参数。

不幸的是，Django 没有内置的方法来实现这一点。有许多解决方案。您可以构建一个自定义模板标签，将参数添加到当前 URL 的末尾，或者您可以在模板中使用一些 if 条件将类别名称添加到 URL 的末尾。还有另一种方法，我更喜欢，因为它更清晰。我们将在 Python 代码中生成 URL，而不是在模板中生成 URL，我们有很多实用程序来处理 URL GET 参数，只需将类别列表与 URL 一起传递到模板中显示。

让我们更改`main/views.py`的代码以匹配以下内容：

```py
import random

from django.core.urlresolvers import reverse
from django.shortcuts import render
from django.template.response import RequestContext
from django.views.generic import View
from elasticsearch_dsl import Search
from elasticsearch_dsl.connections import connections

from main.forms import SearchForm

class HomeView(View):
    def get(self, request):
        form = SearchForm(request.GET)

        ctx = {
            "form": form
        }

        if form.is_valid():
            name_query = form.cleaned_data.get("name")
            if name_query:
                s = Search(index="daintree").query("match", name=name_query)
            else:
                s = Search(index="daintree")

            min_price = form.cleaned_data.get("min_price")
            max_price = form.cleaned_data.get("max_price")
            if min_price is not None or max_price is not None:
                price_query = dict()

                if min_price is not None:
                    price_query["gte"] = min_price

                if max_price is not None:
                    price_query["lte"] = max_price

                s = s.query("range", price=price_query)

            # Add aggregations
            s.aggs.bucket("categories", "terms", field="category")

            if request.GET.get("category"):
 s = s.query("match", category=request.GET["category"])

            result = s.execute()

            ctx["products"] = result.hits

            category_aggregations = list()
 for bucket in result.aggregations.categories.buckets:
 category_name = bucket.key
 doc_count = bucket.doc_count

 category_url_params = request.GET.copy()
 category_url_params["category"] = category_name
 category_url = "{}?{}".format(reverse("home"), category_url_params.urlencode())

 category_aggregations.append({
 "name": category_name,
 "doc_count": doc_count,
 "url": category_url
 })

 ctx["category_aggs"] = category_aggregations

        return render(request, "home.html", ctx)
```

我已经突出显示了我们添加的新代码。首先，我们从 Django 导入了`reverse`方法。接下来，在进行搜索查询时，我们检查用户是否选择了一个类别（通过查看类别查询参数）。如果用户确实选择了某些内容，我们将其添加到我们的搜索中作为对类别字段的`match`查询。

更重要的部分接下来，我们要为类别链接构建 URL。我们循环遍历聚合结果中的每个桶。对于每个桶，我们提取类别名称和文档计数。然后，我们复制请求的 GET 参数。我们复制是因为我们想要通过添加我们的类别名称来修改参数，但`request.GET dict`是不可变的，不能被改变。如果你尝试改变`request.GET`中的内容，你会得到一个异常。所以我们复制一份，并在其中添加当前桶的类别名称。

接下来，我们为使用该类别进行搜索创建一个 URL。首先，我们要反转主页的 URL，然后添加查询参数——我们通过复制当前请求参数并添加我们的类别名称而得到的参数。

最后，我们将所有这些信息添加到一个列表中，然后传递给模板。我们的模板也需要改变以适应这种新的数据格式。以下是`main/templates/home.html`的新代码：

```py
{% extends "base.html" %}

{% block content %}
<h2>Search</h2>
<form action="" method="get">
    {{ form.as_p }}
    <input type="submit" value="Search" />
</form>

{% if category_aggs %}
<h2>Categories</h2>
<ul>
{% for agg in category_aggs %}
 <li>
 <a href="{{ agg.url }}">{{ agg.name }}</a> ({{ agg.doc_count }})
 </li>
{% endfor %}
</ul>
{% endif %}

<h2>Results</h2>
<ul>
    {% if products %}
        {% for product in products %}
        <li>
            Name: <b>{{ product.name }}</b> <br />
            <i>Category: {{ product.category }}</i> <br />
            <i>Price: {{ product.price }}</i> <br />
            {% if product.tags.all %}
                Tags: (
                {% for tag in product.tags.all %}
                    {{ tag.name }}
                    {% if not forloop.last %}
                    ,
                    {% endif %}
                {% endfor %}
                )
            {% endif %}
        </li>
        {% endfor %}
    {% else %}
        No results found. Please try another search term
    {% endif %}
</ul>
{% endblock %}
```

我已经突出显示了代码更改。鉴于我们现在已经格式化了我们的类别过滤器，我们所做的应该是清楚的。一个不相关的小改变是添加了`<h2>` `Results </h2>`。那是因为我之前忘记添加它，后来才意识到聚合过滤器和结果之间没有分隔符。所以我在这里添加了它。

你应该尝试玩一下类别过滤器。选择其中一个显示的类别，你应该只能看到该类别的产品。你的屏幕应该看起来类似于这样：

![使用聚合进行搜索](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj-pj-bp/img/00698_06_06.jpg)

我想要添加的最后一个功能是取消类别过滤器的方法。如果你仔细想想，我们只需要删除类别查询参数来取消类别过滤器，这样我们就会得到只包括搜索表单参数的原始查询。这样做非常简单，让我们来看一下。

在`main/views.py`中，在`get() HomeView`方法的`render()`调用之前，添加以下代码：

```py
if "category" in request.GET:
    remove_category_search_params = request.GET.copy()
    del remove_category_search_params["category"]
    remove_category_url = "{}?{}".format(reverse("home"), remove_category_search_params.urlencode())
    ctx["remove_category_url"] = remove_category_url
```

在`main/templates/home.html`中，在类别`ul`标签结束后添加以下内容：

```py
{% if remove_category_url %}
<a href="{{ remove_category_url }}">Remove Category Filter</a>
{% endif %}
```

就是这样。现在尝试使用搜索，选择一个类别。你应该会看到一个**删除类别过滤器**链接，你可以用它来删除任何类别搜索条件。它应该看起来类似于这样：

![使用聚合进行搜索](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj-pj-bp/img/00698_06_08.jpg)

你可能已经注意到的一件事是，当选择了任何类别后，我们就不再看到其他类别了。这是因为 Elasticsearch 的聚合默认是限定于主查询的。因此，任何术语聚合只会计算已经存在于主查询结果中的文档。当搜索包括类别查询时，我们拥有的类别聚合只能找到所选类别中的文档。要改变这种行为并显示所有类别，无论用户选择了什么，超出了本书的范围。然而，我会指引你正确的方向，通过一些工作，你应该能够自己实现这一点。看一下[`www.elastic.co/guide/en/elasticsearch/guide/current/_scoping_aggregations.html`](https://www.elastic.co/guide/en/elasticsearch/guide/current/_scoping_aggregations.html)。

# 摘要

哇！这是一个相当深奥的章节。我们看了很多东西，获得了很多知识。特别是在涉及到 Elasticsearch 的时候，我们很快地从 0 到 60，在前 10 页内就设置好并运行了搜索。

然而，我相信到现在你应该能够轻松掌握复杂的概念。我们首先看了如何在本地系统上启动 Elasticsearch。然后我们看了如何使用它的 HTTP API 轻松地与 Elasticsearch 进行交互。我们了解了 Elasticsearch 的基本概念，然后向我们的第一个索引插入了一些文档。

然后我们使用 HTTP API 来搜索这些文档并获取结果。一旦我们了解了 Elasticsearch 是什么以及它是如何工作的，我们就开始将其与我们的 Django 应用程序集成。

我们再次看到了使用 Django shell 快速测试库并找出如何处理各种任务的能力，就像我们在使用`elasticsearch_dsl`库对文档进行索引和搜索时所做的那样。然后我们创建了一个 Django 命令，基本上只是复制了我们之前在 Django shell 中所做的事情。

然后我们真正开始处理我们的搜索视图。我们将主页更改为使用 Elasticsearch 而不是数据库来显示我们的产品，并添加了对名称字段的基本搜索。接下来，我们看了如何从一个中央位置`AppConfig`管理我们应用的配置选项。我们还学习了如何使用`elasticsearch_dsl`来执行更复杂的查询，比如范围查询。

最后，我们了解了 Elasticsearch 聚合是什么，以及我们如何将它们整合到我们的应用程序中，为用户提供出色的搜索体验。总的来说，这是一个复杂的章节，完成后，你现在应该有信心去处理更大型和功能丰富的应用程序。
