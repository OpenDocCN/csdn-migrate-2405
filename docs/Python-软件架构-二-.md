# Python 软件架构（二）

> 原文：[`zh.annas-archive.org/md5/E8EC0BA674FAF6D2B8F974FE76F20D30`](https://zh.annas-archive.org/md5/E8EC0BA674FAF6D2B8F974FE76F20D30)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第三章：可测试性 - 编写可测试代码

在上一章中，我们涵盖了软件的一个非常重要的架构属性，即可修改性及其相关方面。在本章中，我们将讨论软件的一个与之密切相关的质量属性——软件的可测试性。

在本书的第一章中，我们简要介绍了可测试性，了解了可测试性是什么，以及它与代码复杂性的关系。在本章中，我们将详细探讨软件可测试性的不同方面。

软件测试本身已经发展成一个拥有自己标准和独特工具和流程的大领域。本章的重点不是涵盖软件测试的正式方面。相反，我们在这里将努力从架构的角度理解软件测试，了解它与其他质量属性的关系，并在本章的后半部分讨论与我们在 Python 中使用软件测试相关的 Python 工具和库。

# 理解可测试性

可测试性可以定义如下：

> *“软件系统通过基于执行的测试轻松暴露其故障的程度”*

具有高可测试性的软件系统通过测试提供了其故障的高度暴露，从而使开发人员更容易访问系统的问题，并允许他们更快地找到和修复错误。另一方面，可测试性较低的系统会使开发人员难以找出其中的问题，并且往往会导致生产中的意外故障。

因此，可测试性是确保软件系统在生产中的质量、稳定性和可预测性的重要方面。

## 软件的可测试性和相关属性

如果软件系统能够很容易地向测试人员暴露其故障，那么它就是可测试的。而且，系统应该以可预测的方式对测试人员进行有用的测试。一个不可预测的系统会在不同的时间给出不同的输出，因此是不可测试的（或者说没有用！）。

与不可预测性一样，复杂或混乱的系统也不太适合测试。例如，一个在负载下行为迥异的系统并不适合进行负载测试。因此，确定性行为对于确保系统的可测试性也是重要的。

另一个方面是测试人员对系统子结构的控制程度。为了设计有意义的测试，系统应该很容易地被识别为具有明确定义的 API 的子系统，可以为其编写测试。一个复杂的软件系统，如果不能轻松访问其子系统，从定义上来说，比那些可以访问的系统要难以测试得多。

这意味着结构上更复杂的系统比那些不复杂的系统更难测试。

让我们把这些列在一个易于阅读的表格中。

| 确定性 | 复杂性 | 可测试性 |
| --- | --- | --- |
| 高 | 低 | 高 |
| 低 | 高 | 低 |

## 可测试性 - 架构方面

软件测试通常意味着正在评估被测试的软件产品的功能。然而，在实际的软件测试中，功能只是可能失败的方面之一。测试意味着评估软件的其他质量属性，如性能、安全性、健壮性等。

由于测试的不同方面，软件的可测试性通常被分为不同的级别。我们将从软件架构的角度来看这些方面。

以下是通常属于软件测试的不同方面的简要列表：

+   功能测试：这涉及测试软件以验证其功能。如果软件单元按照其开发规范的预期行为，它通过了功能测试。功能测试通常有两种类型：

+   白盒测试：这些通常是由开发人员实施的测试，他们可以看到软件代码。这里测试的单元是组成软件的个别函数、方法、类或模块，而不是最终用户功能。白盒测试的最基本形式是单元测试。其他类型包括集成测试和系统测试。

+   黑盒测试：这种类型的测试通常由开发团队之外的人员执行。测试对软件代码没有可见性，将整个系统视为黑盒。黑盒测试测试系统的最终用户功能，而不关心其内部细节。这些测试通常由专门的测试或 QA 工程师执行。然而，如今，许多基于 Web 的应用程序的黑盒测试可以通过使用 Selenium 等测试框架进行自动化。

除了功能测试之外，还有许多测试方法，用于评估系统的各种架构质量属性。我们将在下面讨论这些。

+   性能测试：衡量软件在高负载下的响应性和鲁棒性（稳定性）的测试属于这一类别。性能测试通常分为以下几种：

+   负载测试：评估系统在特定负载下的性能，无论是并发用户数量、输入数据还是事务。

+   压力测试：当某些输入突然或高速增长并达到极限时，测试系统的鲁棒性和响应。压力测试通常倾向于在规定的设计极限之外轻微测试系统。压力测试的变体是在一定的负载下长时间运行系统，并测量其响应性和稳定性。

+   可扩展性测试：衡量系统在负载增加时能够扩展或扩大多少。例如，如果系统配置为使用云服务，这可以测试水平可扩展性——即系统在负载增加时如何自动扩展到一定数量的节点，或垂直可扩展性——即系统 CPU 核心和/或 RAM 的利用程度。

+   安全测试：验证系统安全性的测试属于这一类别。对于基于 Web 的应用程序，这通常涉及通过检查给定的登录或角色只能执行指定的一组操作而不多（或更少）来验证角色的授权。属于安全性的其他测试包括验证对数据或静态文件的适当访问，以确保应用程序的所有敏感数据都受到适当的登录授权保护。

+   可用性测试：可用性测试涉及测试系统的用户界面对其最终用户是否易于使用、直观和可理解。可用性测试通常通过包括符合预期受众或系统最终用户定义的选定人员的目标群体来进行。

+   安装测试：对于运送到客户位置并在那里安装的软件，安装测试很重要。这测试并验证了在客户端构建和/或安装软件的所有步骤是否按预期工作。如果开发硬件与客户的不同，那么测试还涉及验证最终用户硬件中的步骤和组件。除了常规软件安装外，当交付软件更新、部分升级等时，安装测试也很重要。

+   **可访问性测试**：从软件角度来看，可访问性指的是软件系统对残障用户的可用性和包容性程度。通常通过在系统中加入对可访问性工具的支持，并使用可访问性设计原则设计用户界面来实现。多年来已经制定了许多标准和指南，允许组织开发软件以使其对这样的受众具有可访问性。例如，W3C 的**Web 内容可访问性指南**（**WCAG**）、美国政府的第五百零八部分等。

可访问性测试旨在根据这些标准评估软件的可访问性，适用时。

还有各种其他类型的软件测试，涉及不同的方法，并在软件开发的各个阶段调用，例如回归测试、验收测试、Alpha 或 Beta 测试等。

然而，由于我们讨论的重点是软件测试的架构方面，我们将把注意力限制在前面列表中提到的主题上。

## 可测试性 - 策略

我们在前面的部分中看到，测试性根据正在测试的软件系统的复杂性和确定性而变化。

能够隔离和控制正在测试的工件对软件测试至关重要。在测试系统的关注点分离中，即能够独立测试组件并且不过多地依赖外部是关键。

让我们看看软件架构师可以采用的策略，以确保他正在测试的组件提供可预测和确定的行为，从而提供有效和有用的测试结果。

### 减少系统复杂性

如前所述，复杂系统的可测试性较低。系统复杂性可以通过将系统拆分为子系统、为系统提供明确定义的 API 以进行测试等技术来减少。以下是这些技术的一些详细列表：

**减少耦合**：隔离组件，以减少系统中的耦合。组件间的依赖关系应该被明确定义，并且如果可能的话，应该被记录下来。

**增加内聚性**：增加模块的内聚性，即确保特定模块或类只执行一组明确定义的功能。

**提供明确定义的接口**：尝试为获取/设置组件和类的状态提供明确定义的接口。例如，getter 和 setter 允许提供用于获取和设置类属性值的特定方法。重置方法允许将对象的内部状态设置为其创建时的状态。在 Python 中，可以通过定义属性来实现这一点。

**减少类的复杂性**：减少一个类派生的类的数量。一个称为**类响应**（**RFC**）的度量是类 C 的一组方法，以及类 C 的方法调用的其他类的方法。建议将类的 RFC 保持在可管理的限制范围内，通常对于小到中等规模的系统，不超过 50。

### 提高可预测性

我们看到，具有确定性行为对设计提供可预测结果的测试非常重要，因此可以用于构建可重复测试的测试工具。以下是一些改善被测试代码可预测性的策略：

+   **正确的异常处理**：缺少或编写不当的异常处理程序是软件系统中错误和不可预测行为的主要原因之一。重要的是找出代码中可能发生异常的地方，然后处理错误。大多数情况下，异常发生在代码与外部资源交互时，例如执行数据库查询、获取 URL、等待共享互斥锁等。

+   无限循环和/或阻塞等待：当编写依赖于特定条件的循环时，比如外部资源的可用性，或者从共享资源（如共享互斥锁或队列）获取句柄或数据时，重要的是要确保代码中始终提供安全的退出或中断条件。否则，代码可能会陷入永远不会中断的无限循环，或者在资源上永远阻塞等待，导致难以排查和修复的错误。

+   时间相关的逻辑：在实现依赖于一天中特定时间（小时或特定工作日）的逻辑时，确保代码以可预测的方式工作。在测试这样的代码时，通常需要使用模拟或存根来隔离这些依赖关系。

+   并发：在编写使用并发方法（如多线程和/或进程）的代码时，重要的是确保系统逻辑不依赖于线程或进程以任何特定顺序启动。系统状态应该通过定义良好的函数或方法以一种干净和可重复的方式初始化，从而使系统行为可重复，因此可测试。

+   内存管理：软件错误和不可预测性的一个非常常见的原因是内存的错误使用和管理不当。在具有动态内存管理的现代运行时环境中，如 Python、Java 或 Ruby，这不再是一个问题。然而，内存泄漏和未释放的内存导致软件膨胀仍然是现代软件系统中非常真实的问题。

重要的是要分析并能够预测软件系统的最大内存使用量，以便为其分配足够的内存，并在正确的硬件上运行。此外，软件应定期进行内存泄漏和更好的内存管理的评估和测试，并且应该解决和修复任何主要问题。

### 控制和隔离外部依赖

测试通常具有某种外部依赖。例如，一个测试可能需要从数据库中加载/保存数据。另一个可能依赖于一天中特定的时间运行测试。第三个可能需要从 Web 上的 URL 获取数据。

然而，具有外部依赖通常会使测试场景变得更加复杂。这是因为外部依赖通常不在测试设计者的控制范围内。在上述情况下，数据库可能位于另一个数据中心，或者连接可能失败，或者网站可能在配置的时间内不响应，或者出现 50X 错误。

在设计和编写可重复的测试时，隔离这些外部依赖非常重要。以下是一些相同的技术：

+   数据源：大多数真实的测试都需要某种形式的数据。往往情况下，数据是从数据库中读取的。然而，数据库作为外部依赖，不能被依赖。以下是一些控制数据源依赖的技术：

+   使用本地文件而不是数据库：经常可以使用预填充数据的测试文件，而不是查询数据库。这些文件可以是文本、JSON、CSV 或 YAML 文件。通常，这些文件与模拟或存根对象一起使用。

+   使用内存数据库：与连接到真实数据库不同，可以使用一个小型的内存数据库。一个很好的例子是 SQLite DB，它是一个基于文件或内存的数据库，实现了一个良好但是最小的 SQL 子集。

+   使用测试数据库：如果测试确实需要数据库，操作可以使用一个使用事务的测试数据库。数据库在测试用例的`setUp()`方法中设置，并在`tearDown()`方法中回滚，以便在操作结束时不留下真实数据。

+   **资源虚拟化**: 为了控制系统外部资源的行为，可以对它们进行虚拟化，即构建这些资源的版本，模仿它们的 API，但不是内部实现。一些常见的资源虚拟化技术如下：

+   **存根**: 存根为测试期间进行的函数调用提供标准（预定义）响应。`Stub()`函数替换了它替代的函数的细节，只返回所需的响应。

例如，这是一个根据给定 URL 返回`data`的函数：

```py
import hashlib
import requests

def get_url_data(url):
    """ Return data for a URL """

    # Return data while saving the data in a file 
    # which is a hash of the URL
    data = requests.get(url).content
    # Save it in a filename
    filename = hashlib.md5(url).hexdigest()
    open(filename, 'w').write(data)
    return data
```

以下是替代它的存根，它内部化了 URL 的外部依赖：

```py
import os

def get_url_data_stub(url):
    """ Stub function replacing get_url_data """

    # No actual web request is made, instead 
    # the file is opened and data returned
    filename = hashlib.md5(url).hexdigest()
    if os.path.isfile(filename):
        return open(filename).read()
```

编写这样一个函数的更常见的方法是将原始请求和文件缓存合并到同一代码中。URL 只被请求一次——在第一次调用函数时——在后续请求中，从文件缓存返回数据。

```py
def get_url_data(url):
    """ Return data for a URL """

    # First check for cached file - if so return its
    # contents. Note that we are not checking for
    # age of the file - so content may be stale.
    filename = hashlib.md5(url).hexdigest()
    if os.path.isfile(filename):
        return open(filename).read()

    # First time - so fetch the URL and write to the
    # file. In subsequent calls, the file contents will
    # be returned.
    data = requests.get(url).content
    open(filename, 'w').write(data)

    return data
```

+   **模拟**: 模拟对象是对它们替代的真实世界对象的 API 进行伪装。一个程序可以通过设置期望来直接在测试中模拟对象——期望函数将期望的参数类型和顺序以及它们将返回的响应。稍后，可以选择性地在验证步骤中验证这些期望。

### 注意

模拟和存根之间的主要区别在于存根只实现了足够的行为，使得被测试对象能够执行测试。模拟通常会超出范围，还会验证被测试对象是否按预期调用模拟——例如，参数的数量和顺序。

使用模拟对象时，测试的一部分涉及验证模拟是否被正确使用。换句话说，模拟和存根都回答了问题，“结果是什么？”，但模拟还回答了问题，“结果是如何实现的？”

我们将在后面看到使用 Python 进行模拟的单元测试的示例。

+   **伪造**: `Fake`对象具有工作实现，但由于存在一些限制，不足以用于生产。`Fake`对象提供了一个非常轻量级的实现，不仅仅是存根对象。

例如，这是一个实现非常简单的日志记录的`Fake`对象，模仿了 Python 的日志记录模块的`Logger`对象的 API：

```py
import logging

class FakeLogger(object):
    """ A class that fakes the interface of the 
    logging.Logger object in a minimalistic fashion """

    def __init__(self):
        self.lvl = logging.INFO

    def setLevel(self, level):
        """ Set the logging level """
        self.lvl = level

    def _log(self, msg, *args):
        """ Perform the actual logging """

        # Since this is a fake object - no actual logging is 
        # done.
        # Instead the message is simply printed to standard 
        # output.

        print (msg, end=' ')
        for arg in args:
            print(arg, end=' ')
        print()

    def info(self, msg, *args):
        """ Log at info level """
        if self.lvl<=logging.INFO: return self._log(msg, *args)

    def debug(self, msg, *args):
        """ Log at debug level """
        if self.lvl<=logging.DEBUG: return self._log(msg, *args)

    def warning(self, msg, *args):
        """ Log at warning level """
        if self.lvl<=logging.WARNING: return self._log(msg, *args)          

    def error(self, msg, *args):
        """ Log at error level """
        if self.lvl<=logging.ERROR: return self._log(msg, *args)    

    def critical(self, msg, *args):
        """ Log at critical level """
        if self.lvl<=logging.CRITICAL: return self._log(msg, *args)
```

前面代码中的`FakeLogger`类实现了`logging.Logger`类的一些主要方法，它试图伪装。

它作为替换`Logger`对象来实现测试的伪造对象是理想的。

# 白盒测试原则

从软件架构的角度来看，测试的一个最重要的步骤是在软件开发时进行。软件的行为或功能，只对最终用户可见，是软件实现细节的产物。

因此，一个早期进行测试并经常进行测试的系统更有可能产生一个可测试和健壮的系统，以满意的方式为最终用户提供所需的功能。

因此，实施测试原则的最佳方式是从源头开始，也就是软件编写的地方，由开发人员来实施。由于源代码对开发人员可见，这种测试通常被称为白盒测试。

那么，我们如何确保我们可以遵循正确的测试原则，并在软件开发过程中进行尽职调查呢？让我们来看看在软件最终呈现给客户之前，在开发阶段涉及的不同类型的测试。

## 单元测试

单元测试是开发人员执行的最基本的测试类型。单元测试通过使用可执行的断言来应用软件代码的最基本单元——通常是函数或类方法——来检查被测试单元的输出与预期结果是否一致。

在 Python 中，通过标准库中的`unittest`模块提供对单元测试的支持。

单元测试模块提供以下高级对象。

+   **测试用例**：`unittest`模块提供了`TestCase`类，它提供了对测试用例的支持。可以通过继承这个类并设置测试方法来设置一个新的测试用例类。每个测试方法将通过检查响应与预期结果是否匹配来实现单元测试。

+   **测试固件**：测试固件代表一个或多个测试所需的任何设置或准备工作，然后是任何清理操作。例如，这可能涉及创建临时或内存数据库，启动服务器，创建目录树等。在`unittest`模块中，通过`TestCase`类的`setUp()`和`tearDown()`方法以及`TestSuite`类的相关类和模块方法提供了对固件的支持。

+   **测试套件**：测试套件是相关测试用例的聚合。测试套件还可以包含其他测试套件。测试套件允许将在软件系统上执行功能相似的测试的测试用例分组，并且其结果应该一起阅读或分析。`unittest`模块通过`TestSuite`类提供了对测试套件的支持。

+   **测试运行器**：测试运行器是一个管理和运行测试用例，并向测试人员提供结果的对象。测试运行器可以使用文本界面或图形界面。

+   **测试结果**：测试结果类管理向测试人员显示的测试结果输出。测试结果总结了成功、失败和出错的测试用例数量。在`unittest`模块中，这是通过`TestResult`类实现的，具体的默认实现是`TextTestResult`类。

在 Python 中提供支持单元测试的其他模块包括 nose（nose2）和**py.test**。我们将在接下来的部分简要讨论每一个。

## 单元测试实例

让我们来做一个具体的单元测试任务，然后尝试构建一些测试用例和测试套件。由于`unittest`模块是最流行的，并且在 Python 标准库中默认可用，我们将首先从它开始。

为了我们的测试目的，我们将创建一个具有一些用于日期/时间转换的方法的类。

以下代码显示了我们的类：

```py
""" Module datetime helper - Contains the class DateTimeHelper providing some helpful methods for working with date and datetime objects """

import datetime
class DateTimeHelper(object):
    """ A class which provides some convenient date/time
    conversion and utility methods """

    def today(self):
        """ Return today's datetime """
        return datetime.datetime.now()

    def date(self):
        """ Return today's date in the form of DD/MM/YYYY """
        return self.today().strftime("%d/%m/%Y")

    def weekday(self):
        """ Return the full week day for today """
        return self.today().strftime("%A")

    def us_to_indian(self, date):
        """ Convert a U.S style date i.e mm/dd/yy to Indian style dd/mm/yyyy """

        # Split it
        mm,dd,yy = date.split('/')
        yy = int(yy)
        # Check if year is >16, else add 2000 to it
        if yy<=16: yy += 2000
        # Create a date object from it
        date_obj = datetime.date(year=yy, month=int(mm), day=int(dd))
        # Retur it in correct format
        return date_obj.strftime("%d/%m/%Y")
```

我们的`DateTimeHelper`类有一些方法，如下所示：

+   `date`：以 dd/mm/yyyy 格式返回当天的时间戳

+   `weekday`：返回当天的星期几，例如，星期日，星期一等等

+   `us_to_indian`：将美国日期格式（mm/dd/yy(yy)）转换为印度格式（dd/mm/yyyy）

这是一个`unittest TestCase`类，它实现了对最后一个方法的测试：

```py
""" Module test_datetimehelper -  Unit test module for testing datetimehelper module """

import unittest
import datetimehelper

class DateTimeHelperTestCase(unittest.TestCase):
     """ Unit-test testcase class for DateTimeHelper class """

    def setUp(self):
        print("Setting up...")
        self.obj = datetimehelper.DateTimeHelper()

    def test_us_india_conversion(self):
        """ Test us=>india date format conversion """

        # Test a few dates
        d1 = '08/12/16'
        d2 = '07/11/2014'
        d3 = '04/29/00'
        self.assertEqual(self.obj.us_to_indian(d1), '12/08/2016')
        self.assertEqual(self.obj.us_to_indian(d2), '11/07/2014')
        self.assertEqual(self.obj.us_to_indian(d3), '29/04/2000')

if __name__ == "__main__":
    unittest.main()
```

请注意，在测试用例代码的主要部分中，我们只是调用了`unittest.main()`。这会自动找出模块中的测试用例，并执行它们。以下图片显示了测试运行的输出：

![单元测试实例](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00386.jpeg)

`datetimehelper`模块的单元测试案例输出 - 版本#1

从输出中可以看出，这个简单的测试用例通过了。

### 扩展我们的单元测试用例

您可能已经注意到`datetimehelper`模块的第一个版本的单元测试用例只包含了一个方法的测试，即将美国日期格式转换为印度日期格式的方法。

但是，其他两种方法呢？难道我们也不应该为它们编写单元测试吗？

其他两种方法的问题在于它们获取来自今天日期的数据。换句话说，输出取决于代码运行的确切日期。因此，无法通过输入日期值并期望结果与预期结果匹配来为它们编写特定的测试用例，因为代码是时间相关的。我们需要一种方法来控制这种外部依赖。

这里是 Mocking 来拯救我们。记住我们曾讨论过 Mock 对象作为控制外部依赖的一种方式。我们可以使用`unittest.mock`库的修补支持，并修补返回今天日期的方法，以返回我们控制的日期。这样，我们就能够测试依赖于它的方法。

以下是修改后的测试用例，使用了这种技术来支持两种方法：

```py
""" Module test_datetimehelper -  Unit test module for testing datetimehelper module """

import unittest
import datetime
import datetimehelper
from unittest.mock import patch

class DateTimeHelperTestCase(unittest.TestCase):
    """ Unit-test testcase class for DateTimeHelper class """

    def setUp(self):
        self.obj = datetimehelper.DateTimeHelper()

    def test_date(self):
        """ Test date() method """

        # Put a specific date to test
        my_date = datetime.datetime(year=2016, month=8, day=16)

        # Patch the 'today' method with a specific return value
        with patch.object(self.obj, 'today', return_value=my_date):
            response = self.obj.date()
            self.assertEqual(response, '16/08/2016')

    def test_weekday(self):
        """ Test weekday() method """

        # Put a specific date to test
        my_date = datetime.datetime(year=2016, month=8, day=21)

        # Patch the 'today' method with a specific return value
        with patch.object(self.obj, 'today', return_value=my_date):
            response = self.obj.weekday()
            self.assertEqual(response, 'Sunday')            

    def test_us_india_conversion(self):
        """ Test us=>india date format conversion """

        # Test a few dates
        d1 = '08/12/16'
        d2 = '07/11/2014'
        d3 = '04/29/00'
        self.assertEqual(self.obj.us_to_indian(d1), '12/08/2016')
        self.assertEqual(self.obj.us_to_indian(d2), '11/07/2014')
        self.assertEqual(self.obj.us_to_indian(d3), '29/04/2000')

if __name__ == "__main__":
    unittest.main()
```

正如你所看到的，我们已经对`today`方法进行了修补，使其在两个测试方法中返回特定日期。这使我们能够控制该方法的输出，并将结果与特定结果进行比较。

以下是测试用例的新输出：

![扩展我们的单元测试用例](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00387.jpeg)

单元测试用例的输出，用于 datetimehelper 模块，增加了两个测试 - 版本＃2

### 提示

注意：`unittest.main`是`unittest`模块上的一个便利函数，它可以轻松地从一个模块中自动加载一组测试用例并运行它们。

要了解测试运行时发生了什么的更多细节，我们可以通过增加冗长度来让测试运行器显示更多信息。可以通过将`verbosity`参数传递给`unittest.main`，或者通过在命令行上传递`-v`选项来实现。

![扩展我们的单元测试用例](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00388.jpeg)

通过传递`-v`参数来从单元测试用例中生成冗长输出

## 用 nose2 四处嗅探

Python 中还有其他单元测试模块，它们不是标准库的一部分，但作为第三方包可用。我们将看一下第一个名为`nose`的模块。最新版本（写作时）是版本 2，该库已更名为 nose2。

可以使用 Python 包安装程序 pip 来安装 nose2 包。

```py
$ pip install nose2
```

运行 nose2 非常简单。它会自动检测要从中运行的 Python 测试用例所在的文件夹，方法是查找从`unittest.TestCase`派生的类，以及以`test`开头的函数。

在我们的 datetimehelper 测试用例中，nose2 会自动捡起它。只需从包含模块的文件夹中运行它。以下是测试输出：

![用 nose2 四处嗅探](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00389.jpeg)

使用 nose2 运行单元测试

然而，前面的输出并没有报告任何内容，因为默认情况下，nose2 会静默运行。我们可以通过使用冗长选项（`-v`）来打开一些测试报告。

![用 nose2 四处嗅探](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00390.jpeg)

使用 nose2 运行单元测试，带有冗长输出

nose2 还支持使用插件来报告代码覆盖。我们将在后面的部分看到代码覆盖。

## 使用 py.test 进行测试

py.test 包，通常称为 pytest，是 Python 的一个功能齐全、成熟的测试框架。与 nose2 一样，py.test 也支持通过查找以特定模式开头的文件来发现测试。

py.test 也可以使用 pip 安装。

```py
$ pip install pytest

```

像 nose2 一样，使用 py.test 进行测试也很容易。只需在包含测试用例的文件夹中运行可执行文件 pytest。

![使用 py.test 进行测试](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00391.jpeg)

使用 py.test 进行测试发现和执行

像 nose2 一样，pytest 也具有自己的插件支持，其中最有用的是代码覆盖插件。我们将在后面的部分看到示例。

需要注意的是，pytest 不要求测试用例正式派生自`unittest.TestCase`模块。Py.test 会自动从包含以`Test`为前缀的类或以`test_`为前缀的函数的模块中发现测试。

例如，这里有一个新的测试用例，没有依赖于`unittest`模块，但测试用例类是从 Python 中最基本的类型 object 派生的。新模块名为`test_datetimehelper_object`。

```py
""" Module test_datetimehelper_object - Simple test case with test class derived from object """ 

import datetimehelper

class TestDateTimeHelper(object):

    def test_us_india_conversion(self):
        """ Test us=>india date format conversion """

        obj = datetimehelper.DateTimeHelper()
        assert obj.us_to_indian('1/1/1') == '01/01/2001'
```

请注意，这个类与`unittest`模块没有任何依赖关系，并且没有定义任何固定装置。以下是现在在文件夹中运行 pytest 的输出：

![使用 py.test 进行测试](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00392.jpeg)

使用 py.test 进行测试用例发现和执行，而不使用 unittest 模块支持

pytest 已经捕捉到了这个模块中的测试用例，并自动执行了它，正如输出所示。

nose2 也具有类似的功能来捕捉这样的测试用例。下一张图片显示了 nose2 对新测试用例的输出。

![使用 py.test 进行测试](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00393.jpeg)

使用 nose2 进行测试用例发现和执行，而不使用 unittest 模块支持

上述输出显示了新测试已被捕捉并执行。

`unittest`模块、nose2 和 py.test 包提供了大量支持，以非常灵活和可定制的方式开发和实现测试用例、固定装置和测试套件。讨论这些工具的多种选项超出了本章的范围，因为我们的重点是了解这些工具，以理解我们如何使用它们来满足测试性的架构质量属性。

因此，我们将继续讨论单元测试的下一个重要主题，即**代码覆盖率**。我们将看看这三个工具，即`unittest`、nose2 和 py.test，以及它们如何允许架构师帮助他的开发人员和测试人员找到有关他们单元测试中代码覆盖率的信息。

## 代码覆盖率

代码覆盖率是衡量被测试的源代码被特定测试套件覆盖的程度。理想情况下，测试套件应该追求更高的代码覆盖率，因为这将使更大比例的源代码暴露给测试，并有助于发现错误。

代码覆盖率指标通常报告为**代码行数**（**LOC**）的百分比，或者测试套件覆盖的子程序（函数）的百分比。

现在让我们看看不同工具对于测量代码覆盖率的支持。我们将继续使用我们的测试示例（`datetimehelper`）进行这些说明。

### 使用 coverage.py 进行覆盖率测量

Coverage.py 是一个第三方的 Python 模块，它与使用`unittest`模块编写的测试套件和测试用例一起工作，并报告它们的代码覆盖率。

Coverage.py 可以像其他工具一样使用 pip 进行安装。

```py
$ pip install coverage

```

这个最后的命令安装了 coverage 应用程序，用于运行和报告代码覆盖率。

Coverage.py 有两个阶段：首先，它运行一段源代码，并收集覆盖信息，然后报告覆盖数据。

要运行 coverage.py，请使用以下语法：

```py
 **$ coverage run <source file1> <source file 2> …

```

运行完成后，使用此命令报告覆盖率：

```py
 **$ coverage report -m

```

例如，这是我们测试模块的输出：

![使用 coverage.py 进行覆盖率测量](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00394.jpeg)

使用 coverage.py 对 datetimehelper 模块进行测试覆盖率报告

Coverage.py 报告称我们的测试覆盖了`datetimehelper`模块中`93%`的代码，这是相当不错的代码覆盖率。（您可以忽略关于测试模块本身的报告。）

### 使用 nose2 进行覆盖率测量

nose2 包带有用于代码覆盖率的插件支持。这不是默认安装的。要为 nose2 安装代码覆盖插件，请使用此命令：

```py
$ pip install cov-core

```

现在，nose2 可以使用代码覆盖选项运行测试用例，并一次性报告覆盖率。可以这样做：

```py
$ nose2 -v -C

```

### 注意

注意：在幕后，cov-core 利用 coverage.py 来完成其工作，因此 coverage.py 和 nose2 的覆盖度度量报告是相同的。

以下是使用 nose2 运行测试覆盖率的输出：

![使用 nose2 进行覆盖率测量](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00395.jpeg)

使用 nose2 对 datetimehelper 模块进行测试覆盖率报告

默认情况下，覆盖率报告会被写入控制台。要生成其他形式的输出，可以使用`–coverage-report`选项。例如，`--coverage-report html`将以 HTML 格式将覆盖率报告写入名为`htmlcov`的子文件夹。

![使用 nose2 进行覆盖率测量](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00396.jpeg)

使用 nose2 生成 HTML 覆盖率输出

以下是浏览器中的 HTML 输出效果：

![使用 nose2 测量覆盖率](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00397.jpeg)

在浏览器中查看的 HTML 覆盖报告

### 使用 py.test 测量覆盖率

Pytest 还配备了自己的覆盖插件，用于报告代码覆盖。与 nose2 一样，它在后台利用 coverage.py 来完成工作。

为了为 py.test 提供代码覆盖支持，需要安装`pytest-cov`包，如下所示：

```py
$ pip install pytest-cov

```

要报告当前文件夹中测试用例的代码覆盖率，请使用以下命令：

```py
$ pytest –cov

```

以下是 pytest 代码覆盖的示例输出：

![使用 py.test 测量覆盖率](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00398.jpeg)

使用 py.test 运行当前文件夹的代码覆盖

## 模拟事物

我们在之前的测试示例中看到了使用`unittest.mock`的 patch 支持的示例。然而，`unittest`提供的 Mock 支持甚至比这个更强大，所以让我们看一个更多的例子来理解它的强大和适用性在编写单元测试中。

为了说明这一点，我们将考虑一个在大型数据集上执行关键字搜索并按权重排序返回结果的类，并假设数据集存储在数据库中，并且结果作为（句子、相关性）元组列表返回，其中句子是具有关键字匹配的原始字符串，相关性是其在结果集中的命中权重。

以下是代码：

```py
"""
Module textsearcher - Contains class TextSearcher for performing search on a database and returning results
"""

import operator

class TextSearcher(object):
    """ A class which performs a text search and returns results """

    def __init__(self, db):
        """ Initializer - keyword and database object """

        self.cache = False
        self.cache_dict = {}
        self.db = db
        self.db.connect()

    def setup(self, cache=False, max_items=500):
        """ Setup parameters such as caching """

        self.cache = cache
        # Call configure on the db
        self.db.configure(max_items=max_items)

    def get_results(self, keyword, num=10):
        """ Query keyword on db and get results for given keyword """

        # If results in cache return from there
        if keyword in self.cache_dict:
            print ('From cache')
            return self.cache_dict[keyword]

        results = self.db.query(keyword)
        # Results are list of (string, weightage) tuples
        results = sorted(results, key=operator.itemgetter(1), reverse=True)[:num]
        # Cache it
        if self.cache:
            self.cache_dict[keyword] = results

        return results
```

该类有以下三种方法：

+   `__init__`：初始化器，它接受一个充当数据源（数据库）句柄的对象；还初始化了一些属性，并连接到数据库

+   `setup`：它设置搜索器，并配置数据库对象

+   `get_results`：它使用数据源（数据库）执行搜索，并返回给定关键字的结果

我们现在想要为这个搜索器实现一个单元测试用例。由于数据库是一个外部依赖，我们将通过模拟来虚拟化数据库对象。我们将仅测试搜索器的逻辑、可调用签名和返回数据。

我们将逐步开发这个程序，以便每个模拟步骤对您来说都是清晰的。我们将使用 Python 交互式解释器会话来进行相同的操作。

首先，是必要的导入。

```py
>>> from unittest.mock import Mock, MagicMock
>>> import textsearcher
>>> import operator
```

由于我们想要模拟数据库，第一步就是确切地做到这一点。

```py
>>> db = Mock()
```

现在让我们创建`searcher`对象。我们不打算模拟这个，因为我们需要测试其方法的调用签名和返回值。

```py
>>> searcher = textsearcher.TextSearcher(db)
```

此时，数据库对象已被传递给`searcher`的`__init__`方法，并且已经在其上调用了`connect`。让我们验证这个期望。

```py
>>> db.connect.assert_called_with()
```

没有问题，所以断言成功了！现在让我们设置`searcher`。

```py
>>> searcher.setup(cache=True, max_items=100)
```

查看`TextSearcher`类的代码，我们意识到前面的调用应该调用数据库对象上的`configure`方法，并将参数`max_items`设置为值`100`。让我们验证一下。

```py
>>> searcher.db.configure.assert_called_with(max_items=100)
<Mock name='mock.configure_assert_called_with()' id='139637252379648'>
```

太棒了！

最后，让我们尝试并测试`get_results`方法的逻辑。由于我们的数据库是一个模拟对象，它将无法执行任何实际查询，因此我们将一些预先准备好的结果传递给它的`query`方法，有效地模拟它。

```py
>>> canned_results = [('Python is wonderful', 0.4),
...                       ('I like Python',0.8),
...                       ('Python is easy', 0.5),
...                       ('Python can be learnt in an afternoon!', 0.3)]
>>> db.query = MagicMock(return_value=canned_results)
```

现在我们设置关键字和结果的数量，并使用这些参数调用`get_results`。

```py
>>> keyword, num = 'python', 3
>>> data = searcher.get_results(python, num=num)
```

让我们检查数据。

```py
>>> data
[('I like Python', 0.8), ('Python is easy', 0.5), ('Python is wonderful', 0.4)]
```

看起来不错！

在下一步中，我们验证`get_results`确实使用给定的关键字调用了`query`。

```py
>>> searcher.db.query.assert_called_with(keyword)
```

最后，我们验证返回的数据是否已正确排序并截断到我们传递的结果数（`num`）值。

```py
>>> results = sorted(canned_results, key=operator.itemgetter(1), reverse=True)[:num]
>>> assert data == results
True
```

一切正常！

该示例显示了如何使用`unittest`模块中的 Mock 支持来模拟外部依赖项并有效地虚拟化它，同时测试程序的逻辑、控制流、可调用参数和返回值。

这是一个测试模块，将所有这些测试组合成一个单独的测试模块，并在其上运行 nose2 的输出。

```py
"""
Module test_textsearch - Unittest case with mocks for textsearch module
"""

from unittest.mock import Mock, MagicMock
import textsearcher
import operator

def test_search():
    """ Test search via a mock """

    # Mock the database object
    db = Mock()
    searcher = textsearcher.TextSearcher(db)
    # Verify connect has been called with no arguments
    db.connect.assert_called_with()
    # Setup searcher
    searcher.setup(cache=True, max_items=100)
    # Verify configure called on db with correct parameter
    searcher.db.configure.assert_called_with(max_items=100)

    canned_results = [('Python is wonderful', 0.4),
                      ('I like Python',0.8),
                      ('Python is easy', 0.5),
                      ('Python can be learnt in an afternoon!', 0.3)]
    db.query = MagicMock(return_value=canned_results)

    # Mock the results data
    keyword, num = 'python', 3
    data = searcher.get_results(keyword,num=num)
    searcher.db.query.assert_called_with(keyword)

    # Verify data 
    results = sorted(canned_results, key=operator.itemgetter(1), reverse=True)[:num]
    assert data == results
```

这是 nose2 在这个测试用例上的输出：

![模拟事物](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00399.jpeg)

使用 nose2 运行 testsearcher 测试用例

为了保险起见，让我们也看一下我们的模拟测试示例`test_textsearch`模块的覆盖率，使用 py.test 覆盖率插件。

![模拟事物](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00400.jpeg)

通过使用 py.test 测试文本搜索测试用例来测量 textsearcher 模块的覆盖率

所以我们的模拟测试覆盖率为*90%*，只有*20*个语句中的两个没有覆盖到。还不错！

## 文档中的内联测试 - doctests

Python 对另一种内联代码测试有独特的支持，通常称为**doctests**。这些是函数、类或模块文档中的内联单元测试，通过将代码和测试结合在一个地方，无需开发或维护单独的测试套件，从而增加了很多价值。

doctest 模块通过查找代码文档中看起来像 Python 字符串的文本片段来工作，并执行这些会话以验证它们确实与找到的一样工作。任何测试失败都会在控制台上报告。

让我们看一个代码示例来看看它是如何运作的。以下代码实现了简单的阶乘函数，采用了迭代方法：

```py
"""
Module factorial - Demonstrating an example of writing doctests
"""

import functools
import operator

def factorial(n):
    """ Factorial of a number.

    >>> factorial(0)
    1    
    >>> factorial(1)
    1
    >>> factorial(5)
    120
    >>> factorial(10)
    3628800

    """

    return functools.reduce(operator.mul, range(1,n+1))

if __name__ == "__main__":
    import doctest
    doctest.testmod(verbose=True)
```

让我们来看一下执行这个模块的输出。

![文档中的内联测试 - doctests](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00401.jpeg)

阶乘模块的 doctest 输出

Doctest 报告说四个测试中有一个失败了。

快速扫描输出告诉我们，我们忘记编写计算零的阶乘的特殊情况。错误是因为代码尝试计算 range(1, 1)，这会导致`reduce`引发异常。

代码可以很容易地重写以解决这个问题。以下是修改后的代码：

```py
"""
Module factorial - Demonstrating an example of writing doctests
"""

import functools
import operator

def factorial(n):
    """ Factorial of a number.

    >>> factorial(0)
    1    
    >>> factorial(1)
    1
    >>> factorial(5)
    120
    >>> factorial(10)
    3628800
    """

    # Handle 0 as a special case
    if n == 0:
        return 1

    return functools.reduce(operator.mul, range(1,n+1))

if __name__ == "__main__":
    import doctest
    doctest.testmod(verbose=True)
```

下一张图片显示了现在执行模块的新输出：

![文档中的内联测试 - doctests](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00402.jpeg)

修复后阶乘模块的 doctest 输出

现在所有的测试都通过了。

### 注意

注意：在这个例子中，我们打开了 doctest 模块的`testmod`函数的详细选项，以显示测试的详细信息。如果没有这个选项，如果所有测试都通过，doctest 将保持沉默，不产生任何输出。

doctest 模块非常灵活。它不仅可以加载 Python 代码，还可以从文本文件等来源加载 Python 交互会话，并将它们作为测试执行。

Doctest 检查所有文档字符串，包括函数、类和模块文档字符串，以搜索 Python 交互会话。

### 注意

注意：pytest 包内置支持 doctests。要允许 pytest 发现并运行当前文件夹中的 doctests，请使用以下命令：

```py
$ pytest –doctest-modules
```

## 集成测试

单元测试虽然在软件开发生命周期早期的白盒测试中非常有用，可以发现和修复错误，但单靠它们是不够的。只有当不同组件按预期方式协同工作，以向最终用户提供所需的功能并满足预定义的架构质量属性时，软件系统才能完全正常运行。这就是集成测试的重要性所在。

集成测试的目的是验证软件系统的不同功能子系统的功能、性能和其他质量要求，这些子系统作为一个逻辑单元提供某些功能。这些子系统通过它们各自单元的累积行动来提供一些功能。虽然每个组件可能已经定义了自己的单元测试，但通过编写集成测试来验证系统的组合功能也是很重要的。

集成测试通常是在单元测试完成之后，验证测试之前编写的。

在这一点上，列出集成测试提供的优势将是有益的，因为这对于任何在设计和实现了不同组件的单元测试的软件架构师来说都是有用的。

+   **测试组件的互操作性**：功能子系统中的每个单元可能由不同的程序员编写。尽管每个程序员都知道他的组件应该如何执行，并可能已经为其编写了单元测试，但整个系统可能在协同工作方面存在问题，因为组件之间的集成点可能存在错误或误解。集成测试将揭示这样的错误。

+   **测试系统需求修改**：需求可能在实施期间发生了变化。这些更新的需求可能没有经过单元测试，因此，集成测试非常有用，可以揭示问题。此外，系统的某些部分可能没有正确实现需求，这也可以通过适当的集成测试来揭示。

+   **测试外部依赖和 API**：当今软件组件使用大量第三方 API，这些 API 通常在单元测试期间被模拟或存根。只有集成测试才能揭示这些 API 的性能，并暴露调用约定、响应数据或性能方面的任何问题。

+   **调试硬件问题**：集成测试有助于获取有关任何硬件问题的信息，调试这些测试可以为开发人员提供有关是否需要更新或更改硬件配置的数据。

+   **揭示代码路径中的异常**：集成测试还可以帮助开发人员找出他们在代码中可能没有处理的异常，因为单元测试不会执行引发此类错误的路径或条件。更高的代码覆盖率可以识别和修复许多此类问题。然而，一个良好的集成测试结合每个功能的已知代码路径和高覆盖率是确保在使用过程中可能发生的大多数潜在错误都被发现并在测试期间执行的良好公式。

编写集成测试有三种方法。它们如下：

+   自下而上：在这种方法中，首先测试低层组件，然后使用这些测试结果来集成链中更高级组件的测试。该过程重复进行，直到达到与控制流相关的组件层次结构的顶部。在这种方法中，层次结构顶部的关键模块可能得到不充分的测试。

如果顶层组件正在开发中，可能需要使用驱动程序来模拟它们。

![集成测试](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00403.jpeg)

自下而上的集成测试策略

+   **自上而下**：测试开发和测试按照软件系统中的工作流程自上而下进行。因此，首先测试层次结构顶部的组件，最后测试低级模块。在这种方法中，首要测试关键模块，因此我们可以首先识别主要的设计或开发缺陷并加以修复。然而，低级模块可能得到不充分的测试。

低级模块可以被模拟其功能的存根所替代。在这种方法中，早期原型是可能的，因为低级模块逻辑可以被存根化。

![集成测试](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00404.jpeg)

自上而下的集成测试策略

+   **大爆炸**：这种方法是在开发的最后阶段集成和测试所有组件。由于集成测试是在最后进行的，这种方法节省了开发时间。然而，这可能不会给予足够的时间来测试关键模块，因为可能没有足够的时间平等地花在所有组件上。

没有特定的软件用于一般集成测试。某些类别的应用程序，如 Web 框架，定义了自己特定的集成测试框架。例如，一些 Web 框架如 Django、Pyramid 和 Flask 都有一些由其自己社区开发的特定测试框架。

另一个例子是流行的`webtest`框架，它对 Python WSGI 应用程序的自动化测试很有用。这些框架的详细讨论超出了本章和本书的范围。

## 测试自动化

互联网上有许多有用的工具，用于自动化软件应用程序的集成测试。我们将在这里快速看一些流行的工具。

### 使用 Selenium Web Driver 进行测试自动化

Selenium 一直是自动化集成、回归和验证测试的热门选择，适用于许多软件应用程序。Selenium 是免费开源的，并支持大多数流行的 Web 浏览器引擎。

在 Selenium 中，主要对象是**web driver**，它是客户端上的一个有状态的对象，代表一个浏览器。Web driver 可以被编程访问 URL，执行操作（如点击、填写表单和提交表单），有效地替换通常手动执行这些步骤的人类测试对象。

Selenium 为大多数流行的编程语言和运行时提供客户端驱动程序支持。

要在 Python 中安装 Selenium Web Driver，请使用以下命令：

```py
$ pip install selenium

```

我们将看一个小例子，使用 Selenium 和 pytest 来实现一个小的自动化测试，测试 Python 网站（[`www.python.org`](http://www.python.org)）的一些简单测试用例。

这是我们的测试代码。模块名为`selenium_testcase.py`。

```py
"""
Module selenium_testcase - Example of implementing an automated UI test using selenium framework
"""

from selenium import webdriver
import pytest
import contextlib

@contextlib.contextmanager
@pytest.fixture(scope='session')
def setup():
    driver = webdriver.Firefox()    
    yield driver
    driver.quit()

def test_python_dotorg():
    """ Test details of python.org website URLs """

    with setup() as driver:
        driver.get('http://www.python.org')
        # Some tests
        assert driver.title == 'Welcome to Python.org'
        # Find out the 'Community' link
        comm_elem = driver.find_elements_by_link_text('Community')[0]
        # Get the URL
        comm_url = comm_elem.get_attribute('href')
        # Visit it
        print ('Community URL=>',comm_url)
        driver.get(comm_url)
        # Assert its title
        assert driver.title == 'Our Community | Python.org'
        assert comm_url == 'https://www.python.org/community/'
```

在运行上述示例并显示输出之前，让我们稍微检查一下函数。

+   函数`setUp`是一个测试装置，它为我们的测试设置了主要对象，即 Firefox 的 Selenium Web driver。我们通过在`contextlib`模块中使用`contextmanager`装饰器将`setUp`函数转换为上下文管理器。在`setUp`函数的末尾，驱动程序退出，因为调用了它的`quit`方法。

+   在测试函数`test_python_dot_org`中，我们设置了一个相当简单的、人为的测试，用于访问主 Python 网站 URL，并通过断言检查其标题。然后我们通过在主页上找到它来加载 Python 社区的 URL，然后访问这个 URL。最后在结束测试之前断言其标题和 URL。

让我们看看程序的运行情况。我们将明确要求 pytest 只加载这个模块，并运行它。这个命令行如下：

```py
$ pytest -s selenium_testcase.py** 

```

Selenium 驱动程序将启动浏览器（Firefox），并自动打开一个窗口，访问 Python 网站 URL，同时运行测试。测试的控制台输出如下图所示：

![使用 Selenium Web Driver 进行测试自动化](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00405.jpeg)

简单的 Selenium 测试用例在 Python 编程语言网站上的控制台输出

Selenium 可以用于更复杂的测试用例，因为它提供了许多方法来检查页面的 HTML，定位元素并与之交互。还有一些 Selenium 的插件，可以执行页面的 JavaScript 内容，以通过 JavaScript 执行复杂的交互（如 AJAX 请求）。

Selenium 也可以在服务器上运行。它通过远程驱动程序支持提供对远程客户端的支持。浏览器在服务器上实例化（通常使用虚拟 X 会话），而测试可以通过网络从客户端机器运行和控制。

## 测试驱动开发

**测试驱动开发**（**TDD**）是一种敏捷软件开发实践，使用非常短的开发周期，编写代码以满足增量测试用例。

在 TDD 中，将功能需求映射到特定的测试用例。编写代码以通过第一个测试用例。任何新需求都被添加为一个新的测试用例。代码被重构以支持新的测试用例。这个过程一直持续到代码能够支持整个用户功能的范围。

TDD 的步骤如下：

1.  定义一些起始测试用例作为程序的规范。

1.  编写代码使早期测试用例通过。

1.  添加一个定义新功能的新测试用例。

1.  运行所有测试，看看新测试是失败还是通过。

1.  如果新测试失败，请编写一些代码使测试通过。

1.  再次运行测试。

1.  重复步骤 4 到 6，直到新测试通过。

1.  重复步骤 3 到 7，通过测试用例添加新功能。

在 TDD 中，重点是保持一切简单，包括单元测试用例和为支持测试用例而添加的新代码。TDD 的实践者认为，提前编写测试允许开发人员更好地理解产品需求，从开发生命周期的最开始就专注于软件质量。

在 TDD 中，通常在系统中添加了许多测试之后，还会进行最终的重构步骤，以确保不会引入编码异味或反模式，并保持代码的可读性和可维护性。

TDD 没有特定的软件，而是一种软件开发的方法和过程。大多数情况下，TDD 使用单元测试，因此，工具链支持主要是`unittest`模块和本章讨论过的相关软件包。

## 回文的 TDD

让我们像之前讨论的那样，通过一个简单的示例来理解 TDD，开发一个检查输入字符串是否为回文的 Python 程序。

### 注意

回文是一个在两个方向上都读取相同的字符串。例如，*bob*，*rotator*和*Malayalam*都是回文。当你去掉标点符号时，句子*Madam, I'm Adam*也是回文。

让我们遵循 TDD 的步骤。最初，我们需要一个定义程序基本规范的测试用例。我们的测试代码的第一个版本看起来像这样：

```py
"""
Module test_palindrome - TDD for palindrome module
"""

import palindrome

def test_basic():
    """ Basic test for palindrome """

    # True positives
    for test in ('Rotator','bob','madam','mAlAyAlam', '1'):
        assert palindrome.is_palindrome(test)==True

    # True negatives
    for test in ('xyz','elephant', 'Country'):
        assert palindrome.is_palindrome(test)==False        
```

注意，上述代码不仅在早期功能方面为我们提供了程序的规范，还给出了函数名称和签名——包括参数和返回值。我们可以通过查看测试来列出第一个版本的要求。

+   该函数名为`_palindrome`。它应该接受一个字符串，如果是回文则返回 True，否则返回 False。该函数位于`palindrome`模块中。

+   该函数应将字符串视为不区分大小写。

有了这些规范，这是我们的`palindrome`模块的第一个版本：

```py
def is_palindrome(in_string):
    """ Returns True whether in_string is palindrome, False otherwise """

    # Case insensitive
    in_string = in_string.lower()
    # Check if string is same as in reverse
    return in_string == in_string[-1::-1]
```

让我们检查一下这是否通过了我们的测试。我们将在测试模块上运行 py.test 来验证这一点。

![回文的 TDD](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00406.jpeg)

test_palindrome.py 版本＃1 的测试输出

正如你在最后一张图片中看到的，基本测试通过了；所以，我们得到了一个`palindrome`模块的第一个版本，它可以工作并通过测试。

现在按照 TDD 步骤，让我们进行第三步，添加一个新的测试用例。这增加了对带有空格的回文字符串进行测试的检查。以下是带有这个额外测试的新测试模块：

```py
"""
Module test_palindrome - TDD for palindrome module
"""

import palindrome

def test_basic():
    """ Basic test for palindrome """

    # True positives
    for test in ('Rotator','bob','madam','mAlAyAlam', '1'):
        assert palindrome.is_palindrome(test)==True

    # True negatives
    for test in ('xyz','elephant', 'Country'):
        assert palindrome.is_palindrome(test)==False        

def test_with_spaces():
    """ Testing palindrome strings with extra spaces """

    # True positives
    for test in ('Able was I ere I saw Elba',
                 'Madam Im Adam',
                 'Step on no pets',
                 'Top spot'):
        assert palindrome.is_palindrome(test)==True

    # True negatives
    for test in ('Top post','Wonderful fool','Wild Imagination'):
        assert palindrome.is_palindrome(test)==False        
```

让我们运行更新后的测试并查看结果。

![回文的 TDD](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00407.jpeg)

test_palindrome.py 版本＃2 的测试输出

测试失败，因为代码无法处理带有空格的回文字符串。所以让我们按照 TDD 步骤（5）的说法，编写一些代码使这个测试通过。

由于明显需要忽略空格，一个快速的解决方法是从输入字符串中清除所有空格。以下是带有这个简单修复的修改后的回文模块：

```py
"""
Module palindrome - Returns whether an input string is palindrome or not
"""

import re

def is_palindrome(in_string):
    """ Returns True whether in_string is palindrome, False otherwise """

    # Case insensitive
    in_string = in_string.lower()
    # Purge spaces
    in_string = re.sub('\s+','', in_string)
    # Check if string is same as in reverse
    return in_string == in_string[-1::-1]
```

现在让我们重复 TDD 的第四步，看看更新后的代码是否使测试通过。

![回文的 TDD](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00408.jpeg)

代码更新后的 test_palindrome.py 版本＃2 的控制台输出

当然，现在代码通过了测试！

我们刚刚看到的是 TDD 的一个实例，用于在 Python 中实现一个模块的更新周期，该模块检查字符串是否为回文。以类似的方式，可以不断添加测试，并根据 TDD 的第 8 步不断更新代码，从而在维护更新的测试的过程中添加新功能。

我们用检查最终版本的回文测试用例结束了本节，其中添加了一个检查带有额外标点符号的字符串的测试用例。

```py
"""
Module test_palindrome - TDD for palindrome module
"""

import palindrome

def test_basic():
    """ Basic test for palindrome """

    # True positives
    for test in ('Rotator','bob','madam','mAlAyAlam', '1'):
        assert palindrome.is_palindrome(test)==True

    # True negatives
    for test in ('xyz','elephant', 'Country'):
        assert palindrome.is_palindrome(test)==False        

def test_with_spaces():
    """ Testing palindrome strings with extra spaces """

    # True positives
    for test in ('Able was I ere I saw Elba',
                 'Madam Im Adam',
                 'Step on no pets',
                 'Top spot'):
        assert palindrome.is_palindrome(test)==True

    # True negatives
    for test in ('Top post','Wonderful fool','Wild Imagination'):
        assert palindrome.is_palindrome(test)==False        

def test_with_punctuations():
    """ Testing palindrome strings with extra punctuations """

    # True positives
    for test in ('Able was I, ere I saw Elba',
                 "Madam I'm Adam",
                 'Step on no pets.',
                 'Top spot!'):
        assert palindrome.is_palindrome(test)==True

    # True negatives
    for test in ('Top . post','Wonderful-fool','Wild Imagination!!'):
        assert palindrome.is_palindrome(test)==False            
```

以下是更新后的回文模块，使得这个测试通过：

```py
"""
Module palindrome - Returns whether an input string is palindrome or not
"""

import re
from string import punctuation

def is_palindrome(in_string):
    """ Returns True whether in_string is palindrome, False otherwise """

    # Case insensitive
    in_string = in_string.lower()
    # Purge spaces
    in_string = re.sub('\s+','', in_string)
    # Purge all punctuations
    in_string = re.sub('[' + re.escape(punctuation) + ']+', '', in_string)
    # Check if string is same as in reverse
    return in_string == in_string[-1::-1]
```

让我们检查一下控制台上`_palindrome`模块的最终输出。

![回文的 TDD](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00409.jpeg)

test_palindrome.py 版本＃3 的控制台输出，带有匹配的代码更新

## 总结

在本章中，我们重新审视了可测试性的定义及其相关的架构质量方面，如复杂性和确定性。我们研究了被测试的不同架构方面，并了解了软件测试过程通常执行的测试类型。

然后，我们讨论了改进软件可测试性的各种策略，并研究了减少系统复杂性、提高可预测性以及控制和管理外部依赖的技术。在这个过程中，我们学习了不同的虚拟化和管理外部依赖的方法，例如伪装、模拟和存根，通过示例进行了说明。

然后，我们从 Python `unittest`模块的角度主要讨论了单元测试及其各个方面。我们通过使用一个 datetime 辅助类的示例，解释了如何编写有效的单元测试——先是一个简单的例子，然后是使用`unittest`的 Mock 库对函数进行打补丁的有趣的例子。

接下来，我们介绍并学习了 Python 中另外两个著名的测试框架，即 nose2 和 py.test。接下来我们讨论了代码覆盖率的非常重要的方面，并看到了使用 coverage.py 包直接测量代码覆盖率的示例，以及通过 nose2 和 pytest 的插件使用它的示例。

在下一节中，我们勾勒了一个使用高级模拟对象的 textsearch 类的示例，我们对其外部依赖进行了模拟，并编写了一个单元测试用例。我们继续讨论了 Python doctest 支持，通过 doctest 模块在类、模块、方法和函数的文档中嵌入测试的示例。

下一个话题是集成测试，我们讨论了集成测试的不同方面和优势，并看了一下测试可以在软件组织中集成的三种不同方式。接下来讨论了通过 Selenium 进行测试自动化，以及使用 Selenium 和 py.test 在 Python 语言网站上自动化一些测试的示例。

我们以对 TDD 的快速概述结束了本章，并讨论了使用 TDD 原则编写 Python 中检测回文的程序的示例，我们以逐步的方式使用测试开发了这个程序。

在下一章中，我们将讨论在开发软件时架构的一个最关键的质量属性，即性能。


# 第四章：良好的性能是有回报的！

性能是现代软件应用的基石之一。每天我们以多种不同的方式与高性能计算系统进行交互，作为我们工作和休闲的一部分。

当你在网上的旅行网站之一预订航班时，你正在与一个高性能系统交互，该系统在特定时间内执行数百个此类交易。当你向某人转账或通过互联网银行交易支付信用卡账单时，你正在与一个高性能和高吞吐量的交易系统交互。同样，当你在手机上玩在线游戏并与其他玩家互动时，又有一个网络服务器系统专为高并发和低延迟而建，它接收你和成千上万其他玩家的输入，进行后台计算并向你发送数据 - 所有这些都以合理而安静的效率进行。

现代网络应用程序可以同时为数百万用户提供服务，这是因为高速互联网的出现以及硬件价格/性能比的大幅下降。性能仍然是现代软件架构的关键质量属性，编写高性能和可扩展软件仍然是一门艰难的艺术。你可能编写了一个功能和其他质量属性都符合要求的应用程序，但如果它未通过性能测试，那么它就不能投入生产。

在本章和下一章中，我们将重点关注写高吞吐量软件的两个方面 - 即性能和可扩展性。在本章中，重点是性能，以及它的各个方面，如何衡量它，各种数据结构的性能，以及在何时选择什么 - 重点放在 Python 上。

本章我们将讨论的主题大致包括以下几个部分：

+   定义性能

+   软件性能工程

+   性能测试工具的类型

+   性能复杂性和大 O 符号：

+   性能测量

+   使用图表找到性能复杂性

+   提高性能

+   性能分析：

+   确定性分析

+   `cProfile` 和 `profile`

+   第三方性能分析工具

+   其他工具：

+   Objgraph

+   Pympler

+   为性能编程 - 数据结构：

+   列表

+   字典

+   集合

+   元组

+   高性能容器 - collections 模块：

+   `deque`

+   `defaultdict`

+   `OrderedDict`

+   `Counter`

+   `ChainMap`

+   `namedtuple`

+   概率数据结构 - 布隆过滤器

# 什么是性能？

软件系统的性能可以广义地定义为：

> “系统能够满足其吞吐量和/或延迟要求的程度，以每秒事务数或单个事务所需时间来衡量。”

我们已经在介绍章节中概述了性能测量。性能可以用响应时间/延迟或吞吐量来衡量。前者是应用程序完成请求/响应循环的平均时间。后者是系统以每分钟成功完成的请求或交易数量来处理其输入的速率。

系统的性能是其软件和硬件能力的函数。一个糟糕编写的软件仍然可以通过扩展硬件（例如 RAM 的数量）来提高性能。

同样，通过增加性能（例如，通过重写例程或函数以在时间或内存方面更有效，或通过修改架构），可以使现有硬件上的软件更好地运行。

然而，正确的性能工程是软件以最佳方式针对硬件进行调整，使得软件相对于可用硬件的线性扩展或更好。

# 软件性能工程

软件性能工程包括软件工程和分析的所有活动，应用于**软件开发生命周期**（**SDLC**），旨在满足性能要求。

在传统的软件工程中，性能测试和反馈通常是在 SDLC 的最后阶段进行的。这种方法纯粹基于测量，并等待系统开发完成后再应用测试和诊断，并根据结果调整系统。

另一个更正式的模型名为**软件性能工程**（**SPE**）本身，在 SDLC 的早期开发性能模型，并使用模型的结果来修改软件设计和架构，以满足多次迭代中的性能要求。

在这种方法中，性能作为非功能性需求和软件开发满足其功能性需求并行进行。有一个特定的**性能工程生命周期**（**PELC**），与 SDLC 中的步骤相对应。从设计和架构一直到部署的每一步，都利用两个生命周期之间的反馈来迭代地提高软件质量：

![软件性能工程](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00410.jpeg)

SPE - 性能工程生命周期反映软件开发生命周期

在这两种方法中，性能测试和诊断都很重要，随后根据所获得的结果调整设计/架构或代码。因此，性能测试和测量工具在这一步中起着重要作用。

# 性能测试和测量工具

这些工具分为两大类 - 用于性能测试和诊断的工具，以及用于收集性能指标和仪器的工具。

性能测试和诊断工具可以进一步分类如下：

+   **压力测试工具**：这些工具用于向被测试系统提供工作负载，模拟生产中的高峰工作负载。这些工具可以配置为向应用程序发送连续的输入流，以模拟高压力，或者定期发送一大批非常高的流量 - 远远超过甚至高峰压力 - 以测试系统的稳健性。这些工具也被称为**负载生成器**。用于 Web 应用程序测试的常见压力测试工具的示例包括**httpperf**、**ApacheBench**、**LoadRunner**、**Apache JMeter**和**Locust**。另一类工具涉及实际记录真实用户流量，然后通过网络重放以模拟真实用户负载。例如，流行的网络数据包捕获和监视工具**Wireshark**及其控制台表亲程序`tcpdump`可以用于此目的。我们不会在本章讨论这些工具，因为它们是通用工具，可以在网络上找到大量的使用示例。

+   **监控工具**：这些工具与应用程序代码一起生成性能指标，例如函数执行所需的时间和内存，每个请求-响应循环中进行的函数调用次数，每个函数花费的平均和峰值时间等。

+   **仪器工具**：仪器工具跟踪指标，例如每个计算步骤所需的时间和内存，并跟踪事件，例如代码中的异常，涵盖诸如发生异常的模块/函数/行号、事件的时间戳以及应用程序的环境（环境变量、应用程序配置参数、用户信息、系统信息等）的详细信息。现代 Web 应用程序编程系统通常使用外部仪器工具来捕获和详细分析此类数据。

+   **代码或应用程序分析工具**：这些工具生成关于函数的统计信息，它们的调用频率和持续时间，以及每个函数调用所花费的时间。这是一种动态程序分析。它允许程序员找到代码中花费最多时间的关键部分，从而优化这些部分。不建议在没有进行分析的情况下进行优化，因为程序员可能最终会优化错误的代码，从而无法实现预期的应用程序效益。

大多数编程语言都配备了自己的一套工具和性能分析工具。在 Python 中，标准库中的一组工具（如`profile`和`cProfile`模块）可以做到这一点 - 这得益于丰富的第三方工具生态系统。我们将在接下来的部分讨论这些工具。

# 性能复杂度

在我们跳入 Python 中的代码示例并讨论测量和优化性能的工具之前，花点时间讨论一下我们所说的代码的性能复杂度是什么意思会很有帮助。

例程或函数的性能复杂度是根据它们对输入大小的变化的响应来定义的，通常是根据执行代码所花费的时间来定义的。

这通常由所谓的大 O 符号表示，它属于一类称为**巴赫曼-兰道符号或渐近**符号的符号。

字母 O 用作函数相对于输入大小的增长速度 - 也称为函数的**顺序**。

常用的大 O 符号或函数顺序按照增加复杂度的顺序显示在以下表中：

| # | 顺序 | 复杂度 | 例子 |
| --- | --- | --- | --- |
| 1 | *O(1)* | 常数 | 在常数查找表中查找键，例如 Python 中的 HashMap 或字典 |
| 2 | *O(log (n))* | 对数 | 在排序数组中使用二分搜索查找项目。Python 中对 heapq 的所有操作 |
| 3 | *O(n)* | 线性 | 通过遍历数组（Python 中的列表）来搜索项目 |
| 4 | *O(n*k)* | 线性 | 基数排序的最坏情况复杂度 |
| 5 | *O(n * log (n))* | n 对数星 n | 归并排序或堆排序算法的最坏情况复杂度 |
| 6 | *O(n²)* | 二次 | 简单的排序算法，如冒泡排序，插入排序和选择排序。某些排序算法的最坏情况复杂度，如快速排序，希尔排序等 |
| 7 | *O(2^n)* | 指数 | 尝试使用暴力破解破解大小为 n 的密码，使用动态规划解决旅行推销员问题 |
| 8 | *O(n!)* | 阶乘 | 生成集合的所有分区 |

表 1：关于输入大小“n”的函数顺序的常见大 O 符号

当实现一个接受特定大小输入*n*的例程或算法时，程序员理想情况下应该目标是将其实现在前五个顺序中。任何*O(n)或 O(n * log(n))*或更低顺序的东西都表明合理到良好的性能。

具有*O(n²)*顺序的算法通常可以优化为更低的顺序。我们将在以下图表中的部分中看到一些例子。

以下图表显示了这些顺序随着*n*的增长而增长的方式：

![性能复杂度](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00411.jpeg)

每个复杂度顺序的增长率图（y 轴）相对于输入大小（x 轴）的增长率图。

# 性能测量

既然我们已经概述了性能复杂度是什么，也了解了性能测试和测量工具，让我们实际看看用 Python 测量性能复杂度的各种方法。

最简单的时间测量之一是使用 POSIX/Linux 系统的`time`命令。

通过使用以下命令行完成：

```py
$ time <command>

```

例如，这是从 Web 获取一个非常流行页面所需时间的截图：

![性能测量](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00412.jpeg)

通过 wget 从互联网获取网页的时间命令输出

请注意，它显示了三种时间输出，即`real`、`user`和`sys`。重要的是要知道这三者之间的区别，让我们简要地看一下它们：

+   `real`：实际时间是操作所经历的实际挂钟时间。这是操作从开始到结束的时间。它将包括进程休眠或阻塞的任何时间，例如 I/O 完成所花费的时间。

+   `User`：用户时间是进程在用户模式（在内核之外）内实际花费的 CPU 时间。任何休眠时间或在等待中花费的时间，如 I/O，不会增加用户时间。

+   `Sys`：系统时间是程序内核中执行系统调用所花费的 CPU 时间。这仅计算在内核空间中执行的函数，如特权系统调用。它不计算在用户空间中执行的任何系统调用（这在`User`中计算）。

一个进程所花费的总 CPU 时间是`user` + `sys`时间。真实或挂钟时间是由简单的时间计数器大多数测量的时间。

## 使用上下文管理器测量时间

在 Python 中，编写一个简单的函数作为代码块的上下文管理器，用于测量其执行时间并不是很困难。

但首先我们需要一个可以测量性能的程序。

请看以下步骤，了解如何使用上下文管理器来测量时间：

1.  让我们编写一个计算两个序列之间共同元素的程序作为测试程序。以下是代码：

```py
def common_items(seq1, seq2):
    """ Find common items between two sequences """

    common = []
    for item in seq1:
        if item in seq2:
            common.append(item)

    return common
```

1.  让我们编写一个简单的上下文管理器计时器来计时这段代码。为了计时，我们将使用`time`模块的`perf_counter`，它可以给出最精确的时间分辨率：

```py
from time import perf_counter as timer_func
from contextlib import contextmanager

@contextmanager
def timer():
    """ A simple timing function for routines """

    try:
        start = timer_func()
        yield
    except Exception as e:
        print(e)
        raise
    finally:
        end = timer_func()
        print ('Time spent=>',1000.0*(end – start),'ms.')
```

1.  让我们为一些简单的输入数据计时函数。为此，一个`test`函数很有用，它可以生成随机数据，给定一个输入大小：

```py
def test(n):
    """ Generate test data for numerical lists given input size """

    a1=random.sample(range(0, 2*n), n)
    a2=random.sample(range(0, 2*n), n)

    return a1, a2
```

以下是在 Python 交互解释器上对`test`函数的`timer`方法的输出：

```py
>>> with timer() as t:
... common = common_items(*test(100))
... Time spent=> 2.0268699999999864 ms.
```

1.  实际上，测试数据生成和测试可以结合在同一个函数中，以便轻松地测试和生成一系列输入大小的数据：

```py
def test(n, func):
    """ Generate test data and perform test on a given function """

    a1=random.sample(range(0, 2*n), n)
    a2=random.sample(range(0, 2*n), n)

    with timer() as t:
        result = func(a1, a2)
```

1.  现在让我们在 Python 交互控制台中测量不同范围的输入大小所花费的时间：

```py
>>> test(100, common_items)
    Time spent=> 0.6799279999999963 ms.
>>> test(200, common_items)
    Time spent=> 2.7455590000000085 ms.
>>> test(400, common_items)
    Time spent=> 11.440810000000024 ms.
>>> test(500, common_items)
    Time spent=> 16.83928100000001 ms.
>>> test(800, common_items)
    Time spent=> 21.15130400000004 ms.
>>> test(1000, common_items)
    Time spent=> 13.200749999999983 ms.
```

哎呀，`1000`个项目所花费的时间比`800`的时间少！这怎么可能？让我们再试一次：

```py
>>> test(800, common_items)
    Time spent=> 8.328282999999992 ms.
>>> test(1000, common_items)
    Time spent=> 34.85899500000001 ms.
```

现在，`800`个项目所花费的时间似乎比`400`和`500`的时间少。而`1000`个项目所花费的时间增加到了之前的两倍以上。

原因是我们的输入数据是随机的，这意味着它有时会有很多共同的项目-这需要更多的时间-有时会少得多。因此，在后续调用中，所花费的时间可能会显示一系列值。

换句话说，我们的计时函数对于获得一个大致的图片是有用的，但是当涉及到获取程序执行所花费的真实统计度量时，它并不是非常有用，这更为重要。

1.  为此，我们需要多次运行计时器并取平均值。这与算法的**摊销**分析有些类似，它考虑了执行算法所花费的时间的下限和上限，并给程序员一个实际的平均时间估计。

Python 自带了这样一个模块，它可以帮助在其标准库中执行这样的计时分析，即`timeit`模块。让我们在下一节中看看这个模块。

## 使用`timeit`模块计时代码

Python 标准库中的`timeit`模块允许程序员测量执行小代码片段所花费的时间。代码片段可以是 Python 语句、表达式或函数。

使用`timeit`模块的最简单方法是在 Python 命令行中将其作为模块执行。

例如，以下是一些简单的 Python 内联代码的计时数据，用于测量在范围内计算数字平方的列表推导的性能：

```py
$ python3 -m timeit '[x*x for x in range(100)]'
100000 loops, best of 3: 5.5 usec per loop

$ python3 -m timeit '[x*x for x in range(1000)]'
10000 loops, best of 3: 56.5 usec per loop

$ python3 -m timeit '[x*x for x in range(10000)]'
1000 loops, best of 3: 623 usec per loop

```

结果显示了执行代码片段所花费的时间。在命令行上运行时，`timeit`模块会自动确定运行代码的循环次数，并计算单次执行的平均时间。

### 注意

结果显示，我们正在执行的语句是线性的或 O(n)，因为大小为 100 的范围需要 5.5 微秒，而 1000 的范围需要 56.5 微秒，大约是其时间的 10 倍。微秒是秒的百万分之一，即 1*10-6 秒。

使用 Python 解释器中的`timeit`模块的方法如下：

```py
>>> 1000000.0*timeit.timeit('[x*x for x in range(100)]', number=100000)/100000.0
6.007622049946804

>>> 1000000.0*timeit.timeit('[x*x for x in range(1000)]', number=10000)/10000.0
58.761584300373215
```

### 注意

请注意，以这种方式使用时，程序员必须将正确的迭代次数作为`number`参数传递，并且为了求平均值，必须除以相同的数字。乘以`1000000`是为了将时间转换为微秒（usec）。

`timeit`模块在后台使用`Timer`类。该类也可以直接使用，以及进行更精细的控制。

使用此类时，`timeit`成为类的实例的方法，循环次数作为参数传递。

`Timer`类构造函数还接受一个可选的`setup`参数，用于设置`Timer`类的代码。这可以包含用于导入包含函数的模块、设置全局变量等的语句。它接受用分号分隔的多个语句。

### 使用 timeit 测量我们代码的性能

让我们重写我们的`test`函数，以测试两个序列之间的共同项目。现在我们将使用`timeit`模块，可以从代码中删除上下文管理器计时器。我们还将在函数中硬编码调用`common_items`。

### 注意

我们还需要在测试函数之外创建随机输入，否则它所花费的时间将增加到测试函数的时间中，从而破坏我们的结果。

因此，我们需要将变量作为全局变量移到模块中，并编写一个`setup`函数，作为第一步为我们生成数据。

我们重写的`test`函数如下：

```py
def test():
    """ Testing the common_items function """

    common = common_items(a1, a2)
```

具有全局变量的`setup`函数如下：

```py
# Global lists for storing test data
a1, a2 = [], []

def setup(n):
    """ Setup data for test function """

    global a1, a2
    a1=random.sample(range(0, 2*n), n)
    a2=random.sample(range(0, 2*n), n)
```

假设包含`test`和`common_items`函数的模块名为`common_items.py`。

现在可以运行计时器测试如下：

```py
>>> t=timeit.Timer('test()', 'from common_items import test,setup; setup(100)')
>>> 1000000.0*t.timeit(number=10000)/10000
116.58759460115107
```

因此，100 个数字的范围平均需要 117 微秒（0.12 微秒）。

现在对其他输入大小的几个范围进行执行，得到以下输出：

```py
>>> t=timeit.Timer('test()','from common_items import test,setup; setup(200)')
>>> 1000000.0*t.timeit(number=10000)/10000
482.8089299000567

>>> t=timeit.Timer('test()','from common_items import test,setup; setup(400)')
>>> 1000000.0*t.timeit(number=10000)/10000
1919.577144399227

>>> t=timeit.Timer('test()','from common_items import test,setup; setup(800)')
>>> 1000000.0*t.timeit(number=1000)/1000
7822.607815993251

>>> t=timeit.Timer('test()','from common_items import test,setup; setup(1000)')
>>> 1000000.0*t.timeit(number=1000)/1000
12394.932234004957
```

因此，此测试运行的最长时间为 1000 个项目的输入大小需要 12.4 微秒。

## 找出时间复杂度-图表

从这些结果中是否可以找出我们函数的时间性能复杂度？让我们尝试在图表中绘制它并查看结果。

`matplotlib`库在 Python 中绘制任何类型的输入数据的图表非常有用。我们只需要以下简单的代码即可实现：

```py
import matplotlib.pyplot as plt

def plot(xdata, ydata):
    """ Plot a range of ydata (on y-axis) against xdata (on x-axis) """

    plt.plot(xdata, ydata)
    plt.show()
```

上述代码给出了以下输出：

```py
This is our x data.
>>> xdata = [100, 200, 400, 800, 1000]
This is the corresponding y data.
>>> ydata = [117,483,1920,7823,12395]
>>> plot(xdata, ydata)
```

看一下下面的图表：

![找出时间复杂度-图表](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00413.jpeg)

输入范围与 common_items 函数所花费时间的图表

显然这不是线性的，当然也不是二次的（与大 O 符号的图形相比）。让我们尝试绘制一个 O(n*log(n))的图表叠加在当前图表上，看看是否匹配。

由于我们现在需要两个`ydata`系列，我们需要另一个略微修改的函数：

```py
def plot_many(xdata, ydatas):
    """ Plot a sequence of ydatas (on y-axis) against xdata (on x-axis) """

    for ydata in ydatas:
        plt.plot(xdata, ydata)
    plt.show()
```

上述代码给出了以下输出：

```py
>>> ydata2=map(lambda x: x*math.log(x, 2), input)

>>> plot_many(xdata, [ydata2, ydata])
```

你会得到以下图表：

![找出时间复杂度-图表](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00414.jpeg)

common_items 的时间复杂度图表叠加在 y=x*log(x)的图表上

叠加的图表显示，该函数与 n*log(n)阶数非常匹配，如果不是完全相同的话。因此，我们当前实现的复杂度似乎大致为 O(n*log(n))。

现在我们已经完成了性能分析，让我们看看是否可以重写我们的例程以获得更好的性能。

以下是当前的代码：

```py
def common_items(seq1, seq2):
    """ Find common items between two sequences """

    common = []
    for item in seq1:
        if item in seq2:
            common.append(item)

    return common
```

例程首先对外部的`for`循环（大小为`n`）进行一次遍历，并在一个序列（同样大小为`n`）中检查该项。现在第二次搜索的平均时间复杂度也是`n`。

然而，有些项会立即被找到，有些项会花费线性时间(k)，其中 1 < k < n。平均而言，分布会在两者之间，这就是为什么代码的平均复杂度接近 O(n*log(n))。

快速分析会告诉你，通过将外部序列转换为字典并将值设置为 1，可以避免内部搜索。内部搜索将被在第二个序列上的循环替代，该循环将值递增 1。

最后，所有共同项在新字典中的值都将大于 1。

新代码如下：

```py
def common_items(seq1, seq2):
    """ Find common items between two sequences, version 2.0 """

    seq_dict1 = {item:1 for item in seq1}

    for item in seq2:
        try:
            seq_dict1[item] += 1
        except KeyError:
            pass

    # Common items will have value > 1
    return [item[0] for item in seq_dict1.items() if item[1]>1]
```

通过这个改变，计时器给出了以下更新后的结果：

```py
>>> t=timeit.Timer('test()','from common_items import test,setup; setup(100)')
>>> 1000000.0*t.timeit(number=10000)/10000
35.777671200048644

>>> t=timeit.Timer('test()','from common_items import test,setup; setup(200)')
>>> 1000000.0*t.timeit(number=10000)/10000
65.20369809877593

>>> t=timeit.Timer('test()','from common_items import test,setup; setup(400)')
>>> 1000000.0*t.timeit(number=10000)/10000
139.67061050061602

>>> t=timeit.Timer('test()','from common_items import test,setup; setup(800)')
>>> 1000000.0*t.timeit(number=10000)/10000
287.0645995993982

>>> t=timeit.Timer('test()','from common_items import test,setup; setup(1000)')
>>> 1000000.0*t.timeit(number=10000)/10000
357.764518300246
```

让我们绘制这个图并叠加在 O(n)图上：

```py
>>> input=[100,200,400,800,1000]
>>> ydata=[36,65,140,287,358]

# Note that ydata2 is same as input as we are superimposing with y = x 
# graph
>>> ydata2=input
>>> plot.plot_many(xdata, [ydata, ydata2])
```

让我们来看一下下面的图表：

![找出时间复杂度-图表](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00415.jpeg)

common_items 函数（v2）所花费的时间的图与 y = x 图

上面的绿线是参考**y** = **x**图，下面的蓝线是我们新函数所花费的时间的图。很明显，时间复杂度现在是线性的或者 O(n)。

然而，这里似乎有一个常数因子，因为两条线的斜率不同。通过快速计算，可以大致计算出这个因子约为`0.35`。

应用这个改变后，你会得到以下输出：

```py
>>> input=[100,200,400,800,1000]
>>> ydata=[36,65,140,287,358]

# Adjust ydata2 with the constant factor
>>> ydata2=map(lambda x: 0.35*x, input)
>>> plot.plot_many(xdata, [ydata, ydata2])
```

![找出时间复杂度-图表](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00416.jpeg)

common_items 函数（v2）所花费的时间的图与 y = 0.35*x 图

你可以看到这些图几乎完全叠加在一起。因此我们的函数现在的性能是 O(c*n)，其中 c 约等于 0.35。

### 注意

`common_items`函数的另一个实现是将两个序列都转换为集合并返回它们的交集。读者可以尝试进行这种改变，计时并绘制图表以确定时间复杂度。

## 使用 timeit 测量 CPU 时间

`Timer`模块默认使用时间模块的`perf_counter`函数作为默认的`timer`函数。正如前面提到的，这个函数返回小时间段的最大精度的墙钟时间，因此它将包括任何睡眠时间、I/O 时间等。

通过向我们的测试函数添加一点睡眠时间，可以澄清这一点：

```py
def test():
    """ Testing the common_items function using a given input size """

    sleep(0.01)
    common = common_items(a1, a2)
```

上述代码将给出以下输出：

```py
>>> t=timeit.Timer('test()','from common_items import test,setup; setup(100)')
>>> 1000000.0*t.timeit(number=100)/100
10545.260819926625
```

由于我们在每次调用时睡眠了`0.01`秒（10 毫秒），所以时间增加了 300 倍，因此代码实际消耗的时间现在几乎完全由睡眠时间决定，因为结果显示为`10545.260819926625`微秒（大约 10 毫秒）。

有时候你可能会有这样的睡眠时间和其他阻塞/等待时间，但你只想测量函数实际消耗的 CPU 时间。为了使用这个功能，可以使用时间模块的`process_time`函数作为`timer`函数来创建`Timer`对象。

当你创建`Timer`对象时，可以通过传入一个`timer`参数来实现：

```py
>>> from time import process_time
>>> t=timeit.Timer('test()','from common_items import test,setup;setup(100)', timer=process_time)
>>> 1000000.0*t.timeit(number=100)/100
345.22438
```

如果你现在将睡眠时间增加 10 倍，测试时间也会增加相应的倍数，但计时器的返回值仍然保持不变。

例如，当睡眠 1 秒时，结果如下。输出大约在 100 秒后出现（因为我们迭代了`100`次），但请注意返回值（每次调用所花费的时间）并没有改变：

```py
>>> t=timeit.Timer('test()','from common_items import test,setup;setup(100)', timer=process_time)
>>> 1000000.0*t.timeit(number=100)/100
369.8039100000002

```

让我们接下来进行分析。

# 分析

在本节中，我们将讨论分析器，并深入研究 Python 标准库中提供的支持确定性分析的模块。我们还将研究提供分析支持的第三方库，如`line_profiler`和`memory_profiler`。

## 确定性分析

确定性性能分析意味着监视所有函数调用、函数返回和异常事件，并对这些事件之间的时间间隔进行精确计时。另一种类型的性能分析，即**统计性能分析**，会随机抽样指令指针，并推断时间花费在哪里-但这可能不是非常准确。

作为一种解释性语言，Python 在元数据方面已经有一定的开销。大多数确定性性能分析工具利用了这些信息，因此对于大多数应用程序来说，只会增加很少的额外处理开销。因此，在 Python 中进行确定性性能分析并不是一项非常昂贵的操作。

## 使用 cProfile 和 profile

`profile`和`cProfile`模块在 Python 标准库中提供了确定性性能分析的支持。`profile`模块纯粹由 Python 编写。`cProfile`模块是一个 C 扩展，模仿了`profile`模块的接口，但与`profile`相比，它的开销更小。

这两个模块都报告统计数据，使用`pstats`模块将其转换为可报告的结果。

我们将使用以下代码，这是一个质数迭代器，以展示我们使用`profile`模块的示例：

```py
class Prime(object):
    """ A prime number iterator for first 'n' primes """

    def __init__(self, n):
        self.n = n
        self.count = 0
        self.value = 0

    def __iter__(self):
        return self

    def __next__(self):
        """ Return next item in iterator """

        if self.count == self.n:
            raise StopIteration("end of iteration")
        return self.compute()

    def is_prime(self):
        """ Whether current value is prime ? """

        vroot = int(self.value ** 0.5) + 1
        for i in range(3, vroot):
            if self.value % i == 0:
                return False
        return True

    def compute(self):
        """ Compute next prime """

        # Second time, reset value
        if self.count == 1:
            self.value = 1

        while True:
            self.value += 2

            if self.is_prime():
                self.count += 1
                break

        return self.value
```

给定值`n`，质数迭代器生成前`n`个质数：

```py
>>> for p in Prime(5):
... print(p)
...
2
3
5
7
11
```

要对此代码进行性能分析，我们只需要将要执行的代码作为字符串传递给`profile`或`cProfile`模块的`run`方法。在以下示例中，我们将使用`cProfile`模块：

![使用 cProfile 和 profile 进行性能分析](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00417.jpeg)

对前 100 个质数的质数迭代器函数的性能分析输出

看看性能分析器如何报告其输出。输出按以下六列排序：

+   `ncalls`：每个函数的调用次数

+   `tottime`：调用中花费的总时间

+   `percall`：`percall`时间（`tottime`/`ncalls`的商）

+   `cumtime`：此函数及任何子函数中的累积时间

+   `percall`：另一个`percall`列（`cumtime`/原始调用次数的商）

+   `filename: lineno(function)`：函数调用的文件名和行号

在这种情况下，我们的函数完成需要`4`微秒，其中大部分时间（`3`微秒）花在`is_prime`方法内部，这也占据了 271 次调用中的大部分。

以下是`n = 1000`和`10000`的性能分析输出：

![使用 cProfile 和 profile 进行性能分析](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00418.jpeg)

对前 1,000 个质数的质数迭代器函数的性能分析输出

看一下以下额外输出：

![使用 cProfile 和 profile 进行性能分析](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00419.jpeg)

对前 10,000 个质数的质数迭代器函数的性能分析输出

如您所见，在`n`=`1000`时，大约需要`0.043`秒（43 微秒），而在`n`=`10000`时，需要`0.458`秒（458 微秒）。我们的`Prime`迭代器似乎以接近 O(n)的顺序执行。

像往常一样，大部分时间都花在`is_primes`上。有没有办法减少这段时间？

在这一点上，让我们分析一下代码。

### 质数迭代器类-性能调整

对代码的快速分析告诉我们，在`is_prime`内部，我们将值除以从`3`到值的平方根的后继数的范围内的每个数。

这包含许多偶数-我们正在进行不必要的计算，我们可以通过仅除以奇数来避免这种情况。

修改后的`is_prime`方法如下：

```py
    def is_prime(self):
        """ Whether current value is prime ? """

        vroot = int(self.value ** 0.5) + 1
        for i in range(3, vroot, 2):
            if self.value % i == 0:
                return False
        return True
```

因此，`n`=`1000`和`n`=`10000`的性能分析如下。

以下是`n = 1000`的性能分析输出。

![质数迭代器类-性能调整](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00420.jpeg)

对前 1,000 个质数的质数迭代器函数的性能分析输出，使用了调整后的代码

以下是`n`=`10000`时的性能分析输出：

![质数迭代器类-性能调整](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00421.jpeg)

对调整后的代码进行前 10000 个质数的 Prime 迭代器函数的分析输出

您可以看到，在`1000`时，时间有所下降（从 43 微秒到 38 微秒），但在`10000`时，几乎有 50%的下降，从 458 微秒到 232 微秒。此时，该函数的性能优于 O(n)。

## 分析-收集和报告统计信息

我们之前在示例中使用 cProfile 的方式是直接运行并报告统计数据。使用该模块的另一种方式是将`filename`参数传递给它，它会将统计数据写入文件，稍后可以由`pstats`模块加载和解释。

我们修改代码如下：

```py
>>> cProfile.run("list(primes.Prime(100))", filename='prime.stats')
```

通过这样做，统计数据不会被打印出来，而是保存到名为`prime.stats`的文件中。

以下是如何使用`pstats`模块解析统计数据并按调用次数排序打印结果：

![分析-收集和报告统计信息](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00422.jpeg)

使用 pstats 模块解析和打印保存的配置文件结果

`pstats`模块允许按照多个标题对配置文件结果进行排序，例如总时间（`tottime`）、原始调用次数（`pcalls`）、累积时间（`cumtime`）等等。您可以从 pstats 的输出中再次看到，大部分处理都是在 is_prime 方法中进行的，因为我们按照'ncalls'或函数调用次数对输出进行排序。

`pstats`模块的`Stats`类在每次操作后都会返回对自身的引用。这是一些 Python 类的非常有用的特性，它允许我们通过链接方法调用来编写紧凑的一行代码。

`Stats`对象的另一个有用方法是找出被调用者/调用者的关系。这可以通过使用`print_callers`方法而不是`print_stats`来实现。以下是我们当前统计数据的输出：

![分析-收集和报告统计信息](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00423.jpeg)

使用 pstats 模块按原始调用次数排序打印被调用者/调用者关系

## 第三方分析器

Python 生态系统提供了大量用于解决大多数问题的第三方模块。在分析器的情况下也是如此。在本节中，我们将快速浏览一下 Python 社区开发人员贡献的一些流行的第三方分析器应用程序。

### 行分析器

行分析器是由 Robert Kern 开发的一款应用程序，用于对 Python 应用程序进行逐行分析。它是用 Cython 编写的，Cython 是 Python 的优化静态编译器，可以减少分析的开销。

可以通过以下方式使用 pip 安装行分析器：

```py
$ pip3 install line_profiler

```

与 Python 中的分析模块相反，它们分析函数，行分析器能够逐行分析代码，从而提供更详细的统计信息。

行分析器附带一个名为`kernprof.py`的脚本，它使得使用行分析器对代码进行分析变得容易。当使用`kernprof`时，只需使用`@profile`装饰器装饰需要进行分析的函数。

例如，我们意识到我们的质数迭代器中大部分时间都花在了`is_prime`方法上。然而，行分析器允许我们更详细地查找这些函数中哪些行花费了最多的时间。

要做到这一点，只需使用`@profile`装饰器装饰该方法：

```py
    @profile
    def is_prime(self):
        """ Whether current value is prime ? """

        vroot = int(self.value ** 0.5) + 1
        for i in range(3, vroot, 2):
            if self.value % i == 0:
                return False
        return True
```

由于`kernprof`接受脚本作为参数，我们需要添加一些代码来调用质数迭代器。为此，我们可以在`primes.py`模块的末尾添加以下内容：

```py
# Invoke the code.
if __name__ == "__main__":
    l=list(Prime(1000))
```

现在，使用行分析器运行它：

```py
$ kernprof -l -v primes.py

```

通过向`kernprof`脚本传递`-v`，我们告诉它显示分析结果，而不仅仅是保存它们。

以下是输出：

![行分析器](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00424.jpeg)

使用 n = 1000 对 is_prime 方法进行分析的行分析器结果

行分析器告诉我们，大部分时间-接近总时间的 90%都花在了方法的前两行上：for 循环和余数检查。

这告诉我们，如果我们想要优化这种方法，我们需要集中在这两个方面。

### 内存分析器

内存分析器类似于行分析器，它逐行分析 Python 代码。但是，它不是分析代码每行所花费的时间，而是通过内存消耗逐行分析代码。

内存分析器可以像行分析器一样安装：

```py
$ pip3 install memory_profiler

```

安装后，可以通过将函数装饰为`@profile`装饰器来打印行的内存，类似于行分析器。

这是一个简单的例子：

```py
# mem_profile_example.py
@profile
def squares(n):
    return [x*x for x in range(1, n+1)]

squares(1000)
```

以下是如何运行的：

![内存分析器](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00425.jpeg)

内存分析器对前 1000 个数字的平方的列表推导式进行分析

内存分析器逐行显示内存增量。在这种情况下，包含平方数（列表推导式）的行几乎没有增量，因为数字相当小。总内存使用量保持在开始时的水平：约 32 MB。

如果我们将`n`的值更改为一百万会发生什么？可以通过将代码的最后一行改写为以下内容来实现：

```py
squares(100000)
```

![内存分析器](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00426.jpeg)

内存分析器对前 100 万个数字的平方的列表推导式进行分析

现在您可以看到，计算平方的列表推导式的内存增加约为 39 MB，最终总内存使用量约为 70 MB。

为了展示内存分析器的真正用处，让我们看另一个例子。

这涉及查找序列中作为另一个序列中任何字符串的子序列的字符串，通常包含较大的字符串。

### 子字符串（子序列）问题

假设您有一个包含以下字符串的序列：

```py
>>> seq1 = ["capital","wisdom","material","category","wonder"]
```

假设还有另一个序列如下：

```py
>>> seq2 = ["cap","mat","go","won","to","man"]
```

问题是要找到`seq2`中作为`seq1`中任何字符串中连续出现的子字符串：

在这种情况下，答案如下：

```py
>>> sub=["cap","mat","go","won"]
```

这可以通过蛮力搜索来解决-逐个检查每个字符串是否在父字符串中，如下所示：

```py
def sub_string_brute(seq1, seq2):
    """ Sub-string by brute force """

    subs = []
    for item in seq2:
        for parent in seq1:
            if item in parent:
                subs.append(item)

    return subs
```

然而，快速分析会告诉您，该函数的时间复杂度随着序列大小的增加而变得非常糟糕。由于每个步骤都需要迭代两个序列，然后在第一个序列的每个字符串中进行搜索，平均性能将是 O(n1*n2)，其中 n1，n2 分别是序列的大小。

以下是对此函数进行一些测试的结果，输入大小为随机字符串的长度 2 到 10 的两个序列的大小相同：

| 输入大小 | 花费时间 |
| --- | --- |
| 100 | 450 微秒 |
| 1000 | 52 微秒 |
| 10000 | 5.4 秒 |

结果表明性能几乎完全是 O(n²)。

有没有办法重写函数以提高性能？这种方法体现在以下`sub_string`函数中：

```py
def slices(s, n):
    return map(''.join, zip(*(s[i:] for i in range(n))))

def sub_string(seq1, seq2):
    """ Return sub-strings from seq2 which are part of strings in seq1 """

    # Create all slices of lengths in a given range
    min_l, max_l = min(map(len, seq2)), max(map(len, seq2))
    sequences = {}

    for i in range(min_l, max_l+1):
        for string in seq1:
	      # Create all sub sequences of given length i
         sequences.update({}.fromkeys(slices(string, i)))

    subs = []
    for item in seq2:
        if item in sequences:
            subs.append(item)

    return subs
```

在这种方法中，我们预先计算`seq1`中字符串的大小范围的所有子字符串，并将其存储在字典中。然后只需遍历`seq2`中的字符串，并检查它们是否在此字典中，如果是，则将它们添加到列表中。

为了优化计算，我们只计算大小在`seq2`字符串的最小和最大长度范围内的字符串。

与几乎所有解决性能问题的解决方案一样，这种方法以时间换空间。通过预先计算所有子字符串，我们在内存中消耗了更多的空间，但这简化了计算时间。

测试代码如下：

```py
import random
import string

seq1, seq2 = [], []

def random_strings(n, N):
     """ Create N random strings in range of 4..n and append
     to global sequences seq1, seq2 """

    global seq1, seq2
    for i in range(N):
        seq1.append(''.join(random.sample(string.ascii_lowercase,
                             random.randrange(4, n))))

    for i in range(N):
        seq2.append(''.join(random.sample(string.ascii_lowercase,
                             random.randrange(2, n/2))))  

def test(N):
    random_strings(10, N)
    subs=sub_string(seq1, seq2)

def test2():
    # random_strings has to be called before this
    subs=sub_string(seq1, seq2)
```

以下是使用`timeit`模块运行此函数的时间结果：

```py
>>> t=timeit.Timer('test2()',setup='from sub_string import test2, random_
strings;random_strings(10, 100)')
>>> 1000000*t.timeit(number=10000)/10000.0
1081.6103347984608
>>> t=timeit.Timer('test2()',setup='from sub_string import test2, random_
strings;random_strings(10, 1000)')
>>> 1000000*t.timeit(number=1000)/1000.0
11974.320339999394
>>> t=timeit.Timer('test2()',setup='from sub_string import test2, random_
strings;random_strings(10, 10000)')
>>> 1000000*t.timeit(number=100)/100.0124718.30968977883
124718.30968977883
>>> t=timeit.Timer('test2()',setup='from sub_string import test2, random_
strings;random_strings(10, 100000)')
>>> 1000000*t.timeit(number=100)/100.0
1261111.164370086
```

以下是此测试的总结结果：

| 输入大小 | 花费时间 |
| --- | --- |
| 100 | 1.08 微秒 |
| 1000 | 11.97 微秒 |
| 10000 | 0.12 微秒 |
| 100000 | 1.26 秒 |

表 2：通过蛮力解决方案的输入大小与花费时间

快速计算告诉我们，该算法现在的性能为 O(n)。非常好！

但这是以预先计算的字符串的内存为代价。我们可以通过调用内存分析器来估计这一点。

这是用于执行此操作的装饰函数：

```py
@profile
def sub_string(seq1, seq2):
    """ Return sub-strings from seq2 which are part of strings in seq1 """

    # Create all slices of lengths in a given range
    min_l, max_l = min(map(len, seq2)), max(map(len, seq2))
    sequences = {}

    for i in range(min_l, max_l+1):
        for string in seq1:
            sequences.update({}.fromkeys(slices(string, i)))

    subs = []
    for item in seq2:
        if item in sequences:
            subs.append(item)
```

现在测试函数如下：

```py
def test(N):
    random_strings(10, N)
    subs = sub_string(seq1, seq2)
```

让我们分别测试大小为 1,000 和 10,000 的序列。

以下是输入大小为 1,000 时的结果：

![子串（子序列）问题](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00427.jpeg)

测试大小为 1,000 的序列的内存分析器结果

以下是输入大小为 10,000 时的结果：

![子串（子序列）问题](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00428.jpeg)

测试大小为 10,000 的序列的内存分析器结果

对于大小为 1,000 的序列，内存使用量增加了微不足道的 1.4 MB。对于大小为 10,000 的序列，它增加了 6.2 MB。显然，这些数字并不是非常显著的。

因此，使用内存分析器进行测试清楚地表明，尽管我们的算法在时间性能上效率高，但也具有高效的内存利用率。

# 其他工具

在本节中，我们将讨论一些其他工具，这些工具将帮助程序员调试内存泄漏，并使其能够可视化其对象及其关系。

## Objgraph

Objgraph（**对象图**）是一个 Python 对象可视化工具，它利用`graphviz`包绘制对象引用图。

它不是一个分析或检测工具，但可以与此类工具一起使用，以可视化复杂程序中的对象树和引用，同时寻找难以捉摸的内存泄漏。它允许您查找对象的引用，以找出是什么引用使对象保持活动状态。

与 Python 世界中的几乎所有内容一样，它可以通过`pip`安装：

```py
$ pip3 install objgraph

```

然而，objgraph 只有在能够生成图形时才真正有用。因此，我们需要安装`graphviz`包和`xdot`工具。

在 Debian/Ubuntu 系统中，您可以按照以下步骤安装：

```py
$ sudo apt install graphviz xdot -y

```

让我们看一个使用`objgraph`查找隐藏引用的简单示例：

```py
import objgraph

class MyRefClass(object):
    pass

ref=MyRefClass()
class C(object):pass

c_objects=[]
for i in range(100):
    c=C()
    c.ref=ref
    c_objects.append(c)

import pdb; pdb.set_trace()
```

我们有一个名为`MyRefClass`的类，其中有一个单一实例`ref`，由`for`循环中创建的 100 个`C`类的实例引用。这些是可能导致内存泄漏的引用。让我们看看`objgraph`如何帮助我们识别它们。

当执行这段代码时，它会停在调试器（`pdb`）处：

```py
$ python3 objgraph_example.py
--Return--
[0] > /home/user/programs/chap4/objgraph_example.py(15)<module>()->None
-> import pdb; pdb.set_trace()
(Pdb++) objgraph.show_backrefs(ref, max_depth=2, too_many=2, filename='refs.png')
Graph written to /tmp/objgraph-xxhaqwxl.dot (6 nodes)
Image generated as refs.png

```

### 注意

图像的左侧已被裁剪，只显示相关部分。

接下来是 objgraph 生成的图表：

![Objgraph](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00429.jpeg)

Objgraph 对象引用的可视化

前面图表中的红色框显示**99 个更多的引用**，这意味着它显示了一个**C**类的实例，并告诉我们还有 99 个类似的实例 - 总共有 100 个 C 类的实例，引用了单个对象**ref**。

在一个复杂的程序中，我们无法跟踪导致内存泄漏的对象引用，程序员可以利用这样的引用图。

## Pympler

Pympler 是一个用于监视和测量 Python 应用程序中对象内存使用情况的工具。它适用于 Python 2.x 和 3.x。可以使用`pip`安装如下：

```py
$ pip3 install pympler

```

Pympler 的文档相当缺乏。但是，它的众所周知的用途是通过其`asizeof`模块跟踪对象并打印其实际内存使用情况。

以下是我们修改后用于打印序列字典（其中存储了所有生成的子串）的内存使用情况的`sub_string`函数：

```py
from pympler import asizeof

def sub_string(seq1, seq2):
    """ Return sub-strings from seq2 which are part of strings in seq1 """

    # Create all slices of lengths in a given range
    min_l, max_l = min(map(len, seq2)), max(map(len, seq2))
    sequences = {}

    for i in range(min_l, max_l+1):
        for string in seq1:
            sequences.update({}.fromkeys(slices(string, i)))

    subs = []
    for item in seq2:
        if item in sequences:
            subs.append(item)
    print('Memory usage',asizeof.asized(sequences).format())

    return subs
```

当对大小为 10,000 的序列运行时：

```py
$ python3 sub_string.py
Memory usage {'awg': None, 'qlbo': None, 'gvap': No....te':** 
 **None, 'luwr':
 **None, 'ipat': None}** 
size=5874384** 
flat=3145824

```

`5870408`字节（约 5.6 MB）的内存大小与内存分析器报告的一致（约 6 MB）

Pympler 还带有一个名为`muppy`的包，允许跟踪程序中的所有对象。这可以通过`summary`包总结应用程序中所有对象（根据其类型分类）的内存使用情况。

这是我们使用 n =10,000 运行的`sub_string`模块的报告。为此，执行部分必须修改如下：

```py
if __name__ == "__main__":
    from pympler import summary
    from pympler import muppy
    test(10000)
    all_objects = muppy.get_objects()
    sum1 = summary.summarize(all_objects)
    summary.print_(sum1)
```

以下显示了`pympler`在程序结束时总结的输出：

![Pympler](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00430.jpeg)

由 pympler 按对象类型分类的内存使用摘要

# 为性能编程——数据结构

我们已经看过了性能的定义、性能复杂度的测量以及测量程序性能的不同工具。我们还通过对代码进行统计、内存使用等进行了性能分析。

我们还看到了一些程序优化的例子，以改善代码的时间性能。

在本节中，我们将看一下常见的 Python 数据结构，并讨论它们的最佳和最差性能场景，还将讨论它们适合的理想情况以及它们可能不是最佳选择的一些情况。

## 可变容器——列表、字典和集合

列表、字典和集合是 Python 中最受欢迎和有用的可变容器。

列表适用于通过已知索引访问对象。字典为具有已知键的对象提供接近常数时间的查找。集合可用于保留项目组，同时丢弃重复项，并在接近线性时间内找到它们的差异、交集、并集等。

让我们依次看看每个。

### 列表

列表为以下操作提供了接近常数时间 O(1)的顺序：

+   通过`[]`运算符的`get(index)`

+   通过`.append`方法的`append(item)`

但是，在以下情况下，列表的性能表现不佳（O(n)）：

+   通过`in`运算符寻找项目

+   通过`.insert`方法在索引处插入

在以下情况下，列表是理想的选择：

+   如果您需要一个可变存储来保存不同类型或类的项目（异构）。

+   如果您的对象搜索涉及通过已知索引获取项目。

+   如果您不需要通过搜索列表进行大量查找（**item in list**）。

+   如果您的任何元素是不可哈希的。字典和集合要求它们的条目是可哈希的。因此，在这种情况下，您几乎默认使用列表。

如果您有一个庞大的列表——比如超过 100,000 个项目——并且您发现自己通过`in`运算符搜索元素，您应该将其替换为字典。

同样，如果您发现自己大部分时间都在向列表插入而不是附加，您可以考虑使用`collections`模块中的`deque`替换列表。

### 字典

字典为以下情况提供了常数时间顺序：

+   通过键设置项目

+   通过键获取项目

+   通过键删除项目

然而，与列表相比，字典占用的内存略多。字典在以下情况下很有用：

+   您不关心元素的插入顺序

+   在键方面没有重复的元素

字典也非常适合在应用程序开始时从源（数据库或磁盘）加载大量通过键唯一索引的数据，并且需要快速访问它们——换句话说，大量随机读取而不是较少的写入或更新。

### 集合

集合的使用场景介于列表和字典之间。在 Python 中，集合的实现更接近于字典——因为它们是无序的，不支持重复元素，并且通过键提供接近 O(1)的时间访问项目。它们在某种程度上类似于列表，因为它们支持弹出操作（即使它们不允许索引访问！）。

在 Python 中，集合通常用作处理其他容器的中间数据结构——用于删除重复项、查找两个容器之间的共同项等操作。

由于集合操作的顺序与字典完全相同，您可以在大多数需要使用字典的情况下使用它们，只是没有值与键相关联。

示例包括：

+   在丢弃重复项的同时，保留来自另一个集合的异构、无序数据

+   在应用程序中为特定目的处理中间数据-例如查找公共元素，组合多个容器中的唯一元素，删除重复项等

## 不可变容器-元组

元组是 Python 中列表的不可变版本。由于它们在创建后无法更改，因此不支持列表修改的任何方法，例如插入、附加等。

元组与使用索引和搜索（通过**item in tuple**）时的时间复杂度相同。但是，与列表相比，它们占用的内存开销要少得多；解释器对它们进行了更多优化，因为它们是不可变的。

因此，只要存在读取、返回或创建不会更改但需要迭代的数据容器的用例，就可以使用元组。以下是一些示例：

+   从数据存储加载的逐行数据，将仅具有读取访问权限。例如，来自 DB 查询的结果，从读取 CSV 文件的处理行等。

+   需要反复迭代的一组常量值。例如，从配置文件加载的配置参数列表。

+   从函数返回多个值。在这种情况下，除非显式返回列表，否则 Python 始终默认返回元组。

+   当可变容器需要成为字典键时。例如，当需要将列表或集合与字典键关联时，快速方法是将其转换为元组。

## 高性能容器-集合模块

集合模块提供了 Python 内置默认容器类型的高性能替代品，即`list`、`set`、`dict`和`tuple`。

我们将简要介绍集合模块中的以下容器类型：

+   `deque`：列表容器的替代品，支持快速插入和弹出

+   `defaultdict`：为提供缺失值的类型提供工厂函数的`dict`的子类

+   `OrderedDict`：记住插入键的顺序的`dict`的子类

+   `Counter`：用于保持可散列类型的计数和统计信息的字典子类

+   `Chainmap`：具有类似字典的接口的类，用于跟踪多个映射

+   `namedtuple`：用于创建具有命名字段的类似元组的类型

### 双端队列

双端队列或*双端队列*类似于列表，但支持几乎恒定的（O(1)）时间附加和弹出，而不是列表，列表在左侧弹出和插入的成本为 O(n)。

双端队列还支持旋转等操作，用于将`k`个元素从后面移动到前面，并且具有 O(k)的平均性能。这通常比列表中的类似操作稍快，列表涉及切片和附加：

```py
def rotate_seq1(seq1, n):
    """ Rotate a list left by n """
    # E.g: rotate([1,2,3,4,5], 2) => [4,5,1,2,3]

    k = len(seq1) - n
    return seq1[k:] + seq1[:k]

def rotate_seq2(seq1, n):
    """ Rotate a list left by n using deque """

    d = deque(seq1)
    d.rotate(n)
    return d
```

通过简单的`timeit`测量，您应该发现双端队列在性能上略优于列表（约 10-15%），在上面的示例中。

### defaultdict

默认字典是使用类型工厂提供默认值以提供字典键的字典子类。

在 Python 中遇到的一个常见问题是，当循环遍历项目列表并尝试增加字典计数时，可能不存在该项的现有条目。

例如，如果要计算文本中单词出现的次数：

```py
counts = {}
for word in text.split():
    word = word.lower().strip()
    try:
        counts[word] += 1
    except KeyError:
        counts[word] = 1
```

我们被迫编写前面的代码或其变体。

另一个例子是根据特定条件将对象分组到字典中，例如，尝试将所有长度相同的字符串分组到字典中：

```py
cities = ['Jakarta','Delhi','Newyork','Bonn','Kolkata','Bangalore','Seoul']
cities_len = {}
for city in cities:
  clen = len(city)
  # First create entry
  if clen not in cities_len:
    cities_len[clen] = []
  cities_len[clen].append(city)
```

`defaultdict`容器通过定义类型工厂来解决这些问题，以为尚未存在于字典中的任何键提供默认参数。默认工厂类型支持任何默认类型，并默认为`None`。

对于每种类型，其空值是默认值。这意味着：

```py
0 → default value for integers
[] → default value for lists
'' → default value for strings
{} → default value for dictionaries
```

然后可以将单词计数代码重写如下：

```py
counts = defautldict(int)
for word in text.split():
    word = word.lower().strip()
    # Value is set to 0 and incremented by 1 in one go
    counts[word] += 1
```

同样，对于按其长度分组字符串的代码，我们可以这样写：

```py
cities = ['Jakarta','Delhi','Newyork','Bonn','Kolkata','Bangalore','Seoul']
cities_len = defaultdict(list)
for city in cities:
    # Empty list is created as value and appended to in one go
    cities_len[len(city)].append(city)
```

### 有序字典

OrderedDict 是 dict 的子类，它记住条目插入的顺序。它有点像字典和列表的混合体。它的行为类似于映射类型，但也具有列表般的行为，可以记住插入顺序，并支持诸如`popitem`之类的方法来移除最后或第一个条目。

这里有一个例子：

```py
>>> cities = ['Jakarta','Delhi','Newyork','Bonn','Kolkata','Bangalore','Seoul']
>>> cities_dict = dict.fromkeys(cities)
>>> cities_dict
{'Kolkata': None, 'Newyork': None, 'Seoul': None, 'Jakarta': None, 'Delhi': None, 'Bonn': None, 'Bangalore': None}

# Ordered dictionary
>>> cities_odict = OrderedDict.fromkeys(cities)
>>> cities_odict
OrderedDict([('Jakarta', None), ('Delhi', None), ('Newyork', None), ('Bonn', None), ('Kolkata', None), ('Bangalore', None), ('Seoul', None)])
>>> cities_odict.popitem()
('Seoul', None)
>>> cities_odict.popitem(last=False)
('Jakarta', None)
```

你可以比较和对比字典如何改变顺序以及`OrdredDict`容器如何保持原始顺序。

这允许使用`OrderedDict`容器的一些配方。

#### 在不丢失顺序的情况下从容器中删除重复项

让我们修改城市列表以包括重复项：

```py
>>> cities = ['Jakarta','Delhi','Newyork','Bonn','Kolkata','Bangalore','Bonn','Seoul','Delhi','Jakarta','Mumbai']
>>> cities_odict = OrderedDict.fromkeys(cities)
>>> print(cities_odict.keys())
odict_keys(['Jakarta', 'Delhi', 'Newyork', 'Bonn', 'Kolkata', 'Bangalore', 'Seoul', 'Mumbai'])
```

看看重复项是如何被删除但顺序被保留的。

#### 实现最近最少使用（LRU）缓存字典

LRU 缓存优先考虑最近使用（访问）的条目，并丢弃最少使用的条目。这是 HTTP 缓存服务器（如 Squid）中常用的缓存算法，以及需要保持有限大小容器的地方，优先保留最近访问的项目。

在这里，我们利用了`OrderedDict`的行为：当现有键被移除并重新添加时，它会被添加到末尾（右侧）：

```py
class LRU(OrderedDict):
    """ Least recently used cache dictionary """

    def __init__(self, size=10):
        self.size = size

    def set(self, key):
        # If key is there delete and reinsert so
        # it moves to end.
        if key in self:
            del self[key]

        self[key] = 1
        if len(self)>self.size:
            # Pop from left
            self.popitem(last=False)
```

这里有一个演示。

```py
>>> d=LRU(size=5)
>>> d.set('bangalore')
>>> d.set('chennai')
>>> d.set('mumbai')
>>> d.set('bangalore')
>>> d.set('kolkata')
>>> d.set('delhi')
>>> d.set('chennai')

>>> len(d)
5
>>> d.set('kochi')
>>> d
LRU([('bangalore', 1), ('chennai', 1), ('kolkata', 1), ('delhi', 1), ('kochi', 1)])
```

由于键`mumbai`首先设置并且再也没有设置过，它成为了最左边的一个，并被删除了。

### 注意

注意下一个要删除的候选者是`bangalore`，接着是`chennai`。这是因为在`bangalore`设置后又设置了`chennai`。

### 计数器

计数器是字典的子类，用于保持可散列对象的计数。元素存储为字典键，它们的计数存储为值。`Counter`类是 C++等语言中多重集合的并行体，或者是 Smalltalk 等语言中的 Bag。

计数器是在处理任何容器时保持项目频率的自然选择。例如，可以使用计数器在解析文本时保持单词的频率或在解析单词时保持字符的频率。

例如，以下两个代码片段执行相同的操作，但计数器的代码更简洁紧凑。

它们都从在线古腾堡版本的著名福尔摩斯小说《巴斯克维尔的猎犬》的文本中返回最常见的 10 个单词。

+   在以下代码中使用`defaultdict`容器：

```py
import requests, operator
    text=requests.get('https://www.gutenberg.org/files/2852/2852-0.txt').text
    freq=defaultdict(int)
    for word in text.split():
        if len(word.strip())==0: continue
        freq[word.lower()] += 1
        print(sorted(freq.items(), key=operator.itemgetter(1), reverse=True) [:10])
```

+   在以下代码中使用`Counter`类：

```py
import requests
text = requests.get('https://www.gutenberg.org/files/2852/2852-0.txt').text
freq = Counter(filter(None, map(lambda x:x.lower().strip(), text.split())))
print(freq.most_common(10))
```

### ChainMap

`ChainMap`是一个类似字典的类，它将多个字典或类似的映射数据结构组合在一起，创建一个可更新的单一视图。

所有通常的字典方法都受支持。查找会搜索连续的映射，直到找到一个键。

`ChainMap`类是 Python 中较新的添加内容，它是在 Python 3.3 中添加的。

当你有一个场景，需要一遍又一遍地从源字典更新键到目标字典时，`ChainMap`类可以在性能方面对你有利，特别是如果更新次数很大。

以下是`ChainMap`的一些实际用途：

+   程序员可以将 web 框架的`GET`和`POST`参数保持在单独的字典中，并通过单个`ChainMap`更新配置。

+   在应用程序中保持多层配置覆盖。

+   当没有重叠的键时，可以将多个字典作为视图进行迭代。

+   `ChainMap`类在其 maps 属性中保留了先前的映射。然而，当你使用另一个字典的映射更新一个字典时，原始字典状态就会丢失。这里有一个简单的演示：

```py
>>> d1={i:i for i in range(100)}
>>> d2={i:i*i for i in range(100) if i%2}
>>> c=ChainMap(d1,d2)
# Older value accessible via chainmap
>>> c[5]
5
>>> c.maps[0][5]
5
# Update d1
>>> d1.update(d2)
# Older values also got updated
>>> c[5]
25
>>> c.maps[0][5]
25
```

### namedtuple

命名元组类似于具有固定字段的类。字段可以通过属性查找访问，就像普通类一样，但也可以通过索引访问。整个命名元组也可以像容器一样进行迭代。换句话说，命名元组行为类似于类和元组的结合体：

```py
>>> Employee = namedtuple('Employee', 'name, age, gender, title, department')
>>> Employee
<class '__main__.Employee'>
```

让我们创建一个 Employee 的实例：

```py
>>> jack = Employee('Jack',25,'M','Programmer','Engineering')
>>> print(jack)
Employee(name='Jack', age=25, gender='M', title='Programmer', department='Engineering')
```

我们可以遍历实例的字段，就好像它是一个迭代器：

```py
>>> for field in jack:
... print(field)
...
Jack
25
M
Programmer
Engineering
```

创建后，`namedtuple`实例就像元组一样是只读的：

```py
>>> jack.age=32
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
AttributeError: can't set attribute
```

要更新值，可以使用`_replace`方法。它返回一个具有指定关键字参数替换为新值的新实例：

```py
>>> jack._replace(age=32)
Employee(name='Jack', age=32, gender='M', title='Programmer', department='Engineering')
```

与具有相同字段的类相比，命名元组在内存效率上要高得多。因此，在以下情况下，命名元组非常有用：

+   需要将大量数据作为只读加载，从存储中获取键和值。例如，通过 DB 查询加载列和值，或者从大型 CSV 文件加载数据。

+   当需要创建大量类的实例，但属性上并不需要进行许多写入或设置操作时，可以创建`namedtuple`实例以节省内存，而不是创建类实例。

+   可以使用`_make`方法加载现有的可迭代对象，以相同顺序返回一个`namedtuple`实例。例如，如果有一个`employees.csv`文件，其中列名、年龄、性别、职称和部门按顺序排列，我们可以使用以下命令将它们全部加载到`namedtuples`的容器中：

```py
employees = map(Employee._make, csv.reader(open('employees.csv'))
```

## 概率数据结构 - 布隆过滤器

在我们结束对 Python 中容器数据类型的讨论之前，让我们来看看一个重要的概率数据结构，名为**布隆过滤器**。Python 中的布隆过滤器实现类似于容器，但它们具有概率性质。

布隆过滤器是一种稀疏的数据结构，允许我们测试集合中元素的存在性。但是，我们只能确定元素在集合中不存在 - 也就是说，我们只能断言真负。当布隆过滤器告诉我们元素在集合中时，它可能在那里 - 换句话说，元素实际上可能丢失的概率不为零。

布隆过滤器通常实现为位向量。它们的工作方式类似于 Python 字典，因为它们使用哈希函数。但是，与字典不同，布隆过滤器不存储实际的元素本身。此外，一旦添加元素，就无法从布隆过滤器中删除。

当源数据的数量意味着如果我们存储所有数据而没有哈希冲突，就会占用非常大的内存时，就会使用布隆过滤器。

在 Python 中，`pybloom`包提供了一个简单的布隆过滤器实现（但是在撰写本文时，它不支持 Python 3.x，因此这里的示例是在 Python 2.7.x 中显示的）：

```py
$ pip install pybloom

```

让我们编写一个程序，从《巴斯克维尔的猎犬》文本中读取并索引单词，这是我们在讨论计数器数据结构时使用的示例，但这次使用布隆过滤器：

```py
# bloom_example.py
from pybloom import BloomFilter
import requests

f=BloomFilter(capacity=100000, error_rate=0.01)
text=requests.get('https://www.gutenberg.org/files/2852/2852-0.txt').text

for word in text.split():
    word = word.lower().strip()
    f.add(word)

print len(f)
print len(text.split())
for w in ('holmes','watson','hound','moor','queen'):
    print 'Found',w,w in f
```

执行此操作，我们得到以下输出：

```py
$ python bloomtest.py
9403
62154
Found holmes True
Found watson True
Found moor True
Found queen False

```

### 注意

在《巴斯克维尔的猎犬》故事中，`holmes`、`watson`、`hound`和`moor`是最常见的单词，因此布隆过滤器能够找到这些单词是令人放心的。另一方面，`queen`这个词在文本中从未出现，因此布隆过滤器在这一点上是正确的（真负）。文本中单词的长度为 62,154，其中只有 9,403 个被索引到过滤器中。

让我们尝试测量布隆过滤器的内存使用情况，与计数器相比。为此，我们将依赖于内存分析器。

对于这个测试，我们将使用`Counter`类重写代码如下：

```py
# counter_hound.py
import requests
from collections import Counter

@profile
def hound():
    text=requests.get('https://www.gutenberg.org/files/2852/2852-0.txt').text
    c = Counter()
    words = [word.lower().strip() for word in text.split()]
    c.update(words)

if __name__ == "__main__":
    hound()
```

使用布隆过滤器的情况如下：

```py
# bloom_hound.py
from pybloom import BloomFilter
import requests

@profile
def hound():
    f=BloomFilter(capacity=100000, error_rate=0.01)
    text=requests.get('https://www.gutenberg.org/files/2852/2852-0.txt').text

    for word in text.split():
        word = word.lower().strip()
        f.add(word)

if __name__ == "__main__":
    hound()
```

以下是运行内存分析器的第一个输出：

![概率数据结构 - 布隆过滤器](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00431.jpeg)

解析《巴斯克维尔的猎犬》文本时计数器对象的内存使用情况

第二个的结果如下：

![概率数据结构 - 布隆过滤器](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/sw-arch-py/img/image00432.jpeg)

布隆过滤器用于解析《巴斯克维尔的猎犬》文本的内存使用情况

最终的内存使用量大约相同，每个约为 50 MB。在 Counter 的情况下，当 Counter 类被创建时几乎不使用内存，但在向计数器添加单词时使用了接近 0.7 MB。

然而，这两种数据结构之间的内存增长模式存在明显的差异。

在布隆过滤器的情况下，在创建时为其分配了 0.16 MB 的初始内存。添加单词似乎几乎不会给过滤器或程序增加内存。

那么，什么时候应该使用布隆过滤器，而不是在 Python 中使用字典或集合？以下是一些一般原则和现实世界使用场景：

+   当您对不存储实际元素本身，而只对元素的存在（或不存在）感兴趣时。换句话说，您的应用用例更依赖于检查数据的缺失而不是其存在。

+   当您的输入数据量非常大，以至于在内存中存储每个项目（如字典或哈希表）是不可行的时。布隆过滤器在内存中占用的数据要少得多，而不是确定性数据结构。

+   当您对数据集的*假阳性*具有一定的明确定义的错误率满意时 - 比如说在 100 万条数据中有 5% - 您可以为特定的错误率配置一个布隆过滤器，并获得满足您要求的数据命中率。

一些使用布隆过滤器的现实世界例子如下：

+   **安全测试**：在浏览器中存储恶意 URL 的数据，例如

+   **生物信息学**：测试基因组中某种模式（k-mer）的存在

+   为了避免在分布式网络缓存基础设施中存储只有一个命中的 URL

# 总结

本章主要讨论了性能。在本章开始时，我们讨论了性能和 SPE。我们看了性能测试和诊断工具的两类 - 即压力测试工具和分析/仪器工具。

然后我们讨论了性能复杂性在大 O 符号中的真正含义，并简要讨论了函数的常见时间顺序。我们看了函数执行所花费的时间，并学习了 POSIX 系统中的三种时间使用方式 - 即`real`，`user`和`sys`。

我们在下一节中转向了性能和时间的测量 - 从简单的上下文管理器计时器开始，然后使用`timeit`模块进行更准确的测量。我们测量了一系列输入大小的某些算法所花费的时间。通过将所花费的时间与输入大小进行绘图，并将其叠加在标准时间复杂性图上，我们能够直观地了解函数的性能复杂性。我们将常见的项目问题从 O(n*log(n))性能优化到 O(n)，并绘制了时间使用的图表来证实这一点。

然后我们开始讨论代码的性能分析，并看到了使用`cProfile`模块进行性能分析的一些示例。我们选择的示例是一个返回前`n`个质数的质数迭代器，其性能为 O(n)。使用分析数据，我们对代码进行了一些优化，使其性能优于 O(n)。我们简要讨论了`pstats`模块，并使用其`Stats`类来读取分析数据并生成按可用数据字段数量排序的自定义报告。我们讨论了另外两个第三方分析器 - `liner_profiler`和`memory_profiler`，它们逐行分析代码 - 并讨论了在两个字符串序列中查找子序列的问题，编写了它们的优化版本，并使用这些分析器测量了其时间和内存使用情况。

在其他工具中，我们讨论了 objgraph 和 pympler - 前者作为一种可视化工具，用于查找对象之间的关系和引用，帮助探索内存泄漏，后者作为一种监视和报告代码中对象内存使用情况并提供摘要的工具。

在上一节关于 Python 容器的部分中，我们看了标准 Python 容器（如列表、字典、集合和元组）的最佳和最差的使用情况。然后我们研究了 collections 模块中的高性能容器类，包括`deque`、`defaultdict`、`OrderedDict`、`Counter`、`Chainmap`和`namedtuple`，并提供了每个容器的示例和用法。具体来说，我们看到了如何使用`OrderedDict`非常自然地创建 LRU 缓存。

在本章的最后，我们讨论了一种特殊的数据结构，称为布隆过滤器，它作为一种概率数据结构非常有用，可以确定地报告真负例，并在预定义的错误率内报告真正例。

在下一章中，我们将讨论性能的近亲扩展性，我们将探讨编写可扩展应用程序的技术，以及在 Python 中编写可扩展和并发程序的细节。
