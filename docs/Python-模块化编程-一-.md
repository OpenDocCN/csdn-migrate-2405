# Python 模块化编程（一）

> 原文：[`zh.annas-archive.org/md5/253F5AD072786A617BB26982B7C4733F`](https://zh.annas-archive.org/md5/253F5AD072786A617BB26982B7C4733F)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

模块化编程是一种组织程序源代码的方式。通过将代码组织成模块（Python 源文件）和包（模块集合），然后将这些模块和包导入到程序中，您可以保持程序的逻辑组织，并将潜在问题降至最低。

随着程序的增长和变化，您经常需要重写或扩展代码的某些部分。模块化编程技术有助于管理这些变化，最小化副作用，并控制代码。

当您使用模块化编程技术时，您将学习一些常见的使用模块和包的模式，包括编程的分而治之方法，抽象和封装的使用，以及编写可扩展模块的概念。

模块化编程技术也是共享代码的好方法，可以通过使其可供他人使用或在另一个程序中重用您的代码。使用流行工具如 GitHub 和 Python 包索引，您将学习如何发布您的代码，以及使用其他人编写的代码。

将所有这些技术结合起来，您将学习如何应用“模块化思维”来创建更好的程序。您将看到模块如何用于处理大型程序中的复杂性和变化，以及模块化编程实际上是良好编程技术的基础。

在本书结束时，您将对 Python 中的模块和包的工作原理有很好的理解，并且知道如何使用它们来创建高质量和健壮的软件，可以与他人共享。

# 本书涵盖内容

第一章，“介绍模块化编程”，探讨了您可以使用 Python 模块和包来帮助组织程序的方式，为什么使用模块化技术很重要，以及模块化编程如何帮助您处理持续的编程过程。

第二章，“编写您的第一个模块化程序”，介绍了编程的“分而治之”方法，并将此技术应用于基于模块化编程原则构建库存控制系统的过程。

第三章，“使用模块和包”，涵盖了使用 Python 进行模块化编程的基础知识，包括嵌套包，包和模块初始化技术，相对导入，选择导入内容，以及如何处理循环引用。

第四章，“将模块用于实际编程”，使用图表生成库的实现来展示模块化技术如何以最佳方式处理不断变化的需求。

第五章，“使用模块模式”，探讨了一些与模块和包一起使用的标准模式，包括分而治之技术，抽象，封装，包装器，以及如何使用动态导入，插件和钩子编写可扩展模块。

第六章，“创建可重用模块”，展示了如何设计和创建旨在与其他人共享的模块和包。

第七章，“高级模块技术”，探讨了 Python 中模块化编程的一些更独特的方面，包括可选和本地导入，调整模块搜索路径，“要注意的事项”，如何使用模块和包进行快速应用程序开发，处理包全局变量，包配置和包数据文件。

第八章，“测试和部署模块”探讨了单元测试的概念，如何准备您的模块和包以供发布，如何上传和发布您的工作，以及如何使用其他人编写的模块和包。

第九章，“作为良好编程技术基础的模块化编程”展示了模块化技术如何帮助处理编程的持续过程，如何处理变化和管理复杂性，以及模块化编程技术如何帮助您成为更有效的程序员。

# 您需要什么来阅读本书

在本书中跟随示例所需的只是运行任何最新版本的 Python 的计算机。虽然所有示例都使用 Python 3，但它们可以很容易地适应 Python 2，只需进行少量更改。

# 本书适合对象

本书面向初学者到中级水平的 Python 程序员，希望使用模块化编程技术创建高质量和组织良好的程序。读者必须了解 Python 的基础知识，但不需要先前的模块化编程知识。

# 约定

在这本书中，您会发现一些文本样式，用于区分不同类型的信息。以下是这些样式的一些示例以及它们的含义解释。

文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下：“这个一行程序将被保存在磁盘上的一个文件中，通常命名为`hello.py`”

代码块设置如下：

```py
def init():
    global _stats
    _stats = {}
```

当我们希望引起您对代码块的特定部分的注意时，相关的行或项目会以粗体显示：

```py
[default]
exten => s,1,Dial(Zap/1|30)
exten => s,2,Voicemail(u100)
exten => s,102,Voicemail(b100)
exten => i,1,Voicemail(s0)
```

任何命令行输入或输出都以以下方式编写：

```py
# cp /usr/src/asterisk-addons/configs/cdr_mysql.conf.sample
 **/etc/asterisk/cdr_mysql.conf

```

**新术语**和**重要单词**以粗体显示。您在屏幕上看到的单词，例如菜单或对话框中的单词，会以这种方式出现在文本中：“单击**下一步**按钮会将您移至下一个屏幕。”

### 注意

警告或重要说明显示在这样的框中。

### 提示

提示和技巧会以这种方式出现。


# 第一章：介绍模块化编程

模块化编程是现代开发人员的必备工具。过去那种随便拼凑然后希望它能工作的日子已经一去不复返。要构建持久的健壮系统，您需要了解如何组织程序，使其能够随着时间的推移而增长和发展。*意大利面编程*不是一个选择。模块化编程技术，特别是使用 Python 模块和包，将为您提供成功的工具，使您能够成为快速变化的编程领域的专业人士。

在这一章中，我们将：

+   查看模块化编程的基本方面

+   看看 Python 模块和包如何被用来组织您的代码

+   了解当不使用模块化编程技术时会发生什么

+   了解模块化编程如何帮助您掌握开发过程

+   以 Python 标准库为例，看看模块化编程是如何使用的

+   创建一个简单的程序，使用模块化技术构建，以了解它在实践中是如何工作的

让我们开始学习模块和它们的工作原理。

# 介绍 Python 模块

对于大多数初学者程序员来说，他们的第一个 Python 程序是著名的*Hello World*程序的某个版本。这个程序可能看起来像这样：

```py
print("Hello World!")
```

这个一行程序将保存在磁盘上的一个文件中，通常命名为`hello.py`，并且通过在终端或命令行窗口中输入以下命令来执行：

```py
python hello.py

```

然后 Python 解释器将忠实地打印出您要求它打印的消息：

```py
Hello World!

```

这个`hello.py`文件被称为**Python 源文件**。当您刚开始时，将所有程序代码放入单个源文件是组织程序的好方法。您可以定义函数和类，并在底部放置指令，当您使用 Python 解释器运行程序时，它会启动您的程序。将程序代码存储在 Python 源文件中可以避免每次想要告诉 Python 解释器该做什么时都需要重新输入它。

然而，随着您的程序变得更加复杂，您会发现越来越难以跟踪您定义的所有各种函数和类。您会忘记放置特定代码的位置，并且发现越来越难记住所有各种部分是如何组合在一起的。

模块化编程是一种组织程序的方式，随着程序变得更加复杂。您可以创建一个 Python **模块**，一个包含 Python 源代码以执行某些有用功能的源文件，然后将此模块**导入**到您的程序中，以便您可以使用它。例如，您的程序可能需要跟踪程序运行时发生的各种事件的各种统计信息。最后，您可能想知道每种类型的事件发生了多少次。为了实现这一点，您可以创建一个名为`stats.py`的 Python 源文件，其中包含以下 Python 代码：

```py
def init():
    global _stats
    _stats = {}

def event_occurred(event):
    global _stats
    try:
        _stats[event] = _stats[event] + 1
    except KeyError:
        _stats[event] = 1

def get_stats():
    global _stats
    return sorted(_stats.items())
```

`stats.py` Python 源文件定义了一个名为`stats`的模块—正如您所看到的，模块的名称只是源文件的名称，不包括`.py`后缀。您的主程序可以通过导入它并在需要时调用您定义的各种函数来使用这个模块。以下是一个无聊的例子，展示了如何使用`stats`模块来收集和显示有关事件的统计信息：

```py
import stats

stats.init()
stats.event_occurred("meal_eaten")
stats.event_occurred("snack_eaten")
stats.event_occurred("meal_eaten")
stats.event_occurred("snack_eaten")
stats.event_occurred("meal_eaten")
stats.event_occurred("diet_started")
stats.event_occurred("meal_eaten")
stats.event_occurred("meal_eaten")
stats.event_occurred("meal_eaten")
stats.event_occurred("diet_abandoned")
stats.event_occurred("snack_eaten")

for event,num_times in stats.get_stats():
    print("{} occurred {} times".format(event, num_times))
```

当然，我们对记录餐点不感兴趣—这只是一个例子—但这里需要注意的重要事情是`stats`模块如何被导入，以及`stats.py`文件中定义的各种函数如何被使用。例如，考虑以下代码行：

```py
stats.event_occurred("snack_eaten")
```

因为`event_occurred()`函数是在`stats`模块中定义的，所以每当您引用这个函数时，都需要包括模块的名称。

### 注意

有多种方法可以导入模块，这样你就不需要每次都包含模块的名称。我们将在第三章 *使用模块和包* 中看到这一点，当我们更详细地了解命名空间和`import`命令的工作方式时。

正如您所看到的，`import`语句用于加载一个模块，每当您看到模块名称后跟着一个句点，您就可以知道程序正在引用该模块中定义的某个东西（例如函数或类）。

# 介绍 Python 包

就像 Python 模块允许您将函数和类组织到单独的 Python 源文件中一样，Python **包**允许您将多个模块组合在一起。

Python 包是具有特定特征的目录。例如，考虑以下 Python 源文件目录：

![介绍 Python 包](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mdl-prog-py/img/B05012_1_01.jpg)

这个 Python 包叫做`animals`，包含五个 Python 模块：`cat`、`cow`、`dog`、`horse`和`sheep`。还有一个名为`__init__.py`的特殊文件。这个文件被称为**包初始化文件**；这个文件的存在告诉 Python 系统这个目录包含一个包。包初始化文件还可以用于初始化包（因此得名），也可以用于使导入包变得更容易。

### 注意

从 Python 3.3 版本开始，包不总是需要包含初始化文件。然而，没有初始化文件的包（称为**命名空间包**）仍然相当罕见，只在非常特定的情况下使用。为了保持简单，我们将在本书中始终使用常规包（带有`__init__.py`文件）。

就像我们在调用模块内的函数时使用模块名称一样，当引用包内的模块时，我们使用包名称。例如，考虑以下代码：

```py
import animals.cow
animals.cow.speak()
```

在此示例中，`speak()`函数是在`cow.py`模块中定义的，它本身是`animals`包的一部分。

包是组织更复杂的 Python 程序的一种很好的方式。您可以使用它们将相关的模块分组在一起，甚至可以在包内定义包（称为*嵌套包*）以保持程序的超级组织。

请注意，`import`语句（以及相关的`from...import`语句）可以以各种方式用于加载包和模块到您的程序中。我们在这里只是浅尝辄止，向您展示了 Python 中模块和包的样子，以便您在程序中看到它们时能够识别出来。我们将在第三章 *使用模块和包* 中更深入地研究模块和包的定义和导入方式。

### 提示

**下载示例代码**

本书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Modular-Programming-with-Python`](https://github.com/PacktPublishing/Modular-Programming-with-Python)。我们还有来自丰富书籍和视频目录的其他代码包，可在[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)上找到。快去看看吧！

# 使用模块和包来组织程序

模块和包不仅仅是用来将 Python 代码分布在多个源文件和目录中的，它们还允许您*组织*您的代码以反映程序试图做什么的逻辑结构。例如，想象一下，您被要求创建一个 Web 应用程序来存储和报告大学考试成绩。考虑到您得到的业务需求，您为应用程序提出了以下整体结构：

![使用模块和包来组织程序](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mdl-prog-py/img/B05012_1_02.jpg)

该程序分为两个主要部分：一个**网络界面**，用于与用户交互（以及通过 API 与其他计算机程序交互），以及一个**后端**，用于处理将信息存储在数据库中的内部逻辑、生成报告和向学生发送电子邮件的逻辑。正如您所看到的，网络界面本身已被分解为四个部分：

+   一个用户认证部分，处理用户注册、登录和退出

+   一个用于查看和输入考试结果的网络界面

+   一个用于生成报告的网络界面

+   一个 API，允许其他系统根据请求检索考试结果

在考虑应用程序的每个逻辑组件（即上图中的每个框）时，您也开始考虑每个组件将提供的功能。在这样做时，您已经在模块化方面进行思考。实际上，应用程序的每个逻辑组件都可以直接实现为 Python 模块或包。例如，您可以选择将程序分为两个主要包，命名为`web`和`backend`，其中：

+   `web`包中有名为`authentication`、`results`、`reports`和`api`的模块

+   `backend`包中有名为`database`、`reportgenerator`和`emailer`的模块

正如您所看到的，上图中的每个阴影框都成为了一个 Python 模块，每个框的分组都成为了一个 Python 包。

一旦您决定要定义的包和模块集合，您就可以开始通过在每个模块中编写适当的函数集来实现每个组件。例如，`backend.database`模块可能有一个名为`get_students_results()`的函数，它返回给定科目和年份的单个学生的考试结果。

### 注意

在实际的 Web 应用程序中，您的模块化结构可能实际上会有所不同。这是因为您通常使用诸如 Django 之类的 Web 应用程序框架来创建 Web 应用程序，该框架会对您的程序施加自己的结构。但是，在这个例子中，我们将模块化结构保持得尽可能简单，以展示业务功能如何直接转化为包和模块。

显然，这个例子是虚构的，但它展示了您如何以模块化的方式思考复杂的程序，将其分解为单独的组件，然后依次使用 Python 模块和包来实现这些组件中的每一个。

# 为什么要使用模块化编程技术？

使用模块化设计技术的一大好处是，它们迫使您考虑程序应该如何结构化，并允许您定义一个随着程序发展而增长的结构。您的程序将是健壮的，易于理解，易于在程序范围扩大时重新构造，也易于其他人一起使用。

木匠有一句座右铭同样适用于模块化编程：每样东西都有其位置，每样东西都应该在其位置上。这是高质量代码的标志之一，就像是一个组织良好的木匠车间的标志一样。

要了解为什么模块化编程是如此重要的技能，请想象一下，如果在编写程序时没有应用模块化技术会发生什么。如果您将所有的 Python 代码放入单个源文件中，不尝试逻辑地排列您的函数和类，并且只是随机地将新代码添加到文件的末尾，您最终会得到一堆难以理解的糟糕代码。以下是一个没有任何模块化组织的程序的示例：

```py
import configparser

def load_config():
    config = configparser.ConfigParser()
    config.read("config.ini")
    return config['config']

def get_data_from_user():
    config = load_config()
    data = []
    for n in range(config.getint('num_data_points')):
        value = input("Data point {}: ".format(n+1))
        data.append(value)
    return data

def print_results(results):
    for value,num_times in results:
        print("{} = {}".format(value, num_times))

def analyze_data():
    data = get_data_from_user()
    results = {}
    config = load_config()
    for value in data:
        if config.getboolean('allow_duplicates'):
            try:
                results[value] = results[value] + 1
            except KeyError:
                results[value] = 1
        else:
            results[value] = 1
    return results

def sort_results(results):
    sorted_results = []
    for value in results.keys():
        sorted_results.append((value, results[value]))
    sorted_results.sort()
    return sorted_results

if __name__ == "__main__":
    results = analyze_data()
    sorted_results = sort_results(results)
    print_results(sorted_results)
```

这个程序旨在提示用户输入多个数据点并计算每个数据点出现的次数。它确实有效，并且函数和变量名称确实有助于解释程序的每个部分的功能——但它仍然是一团糟。仅仅看源代码，就很难弄清楚这个程序做什么。函数只是在文件的末尾添加，因为作者决定实现它们，即使对于一个相对较小的程序，也很难跟踪各个部分。想象一下，如果一个有 1 万行代码的程序像这样，试图调试或维护它会有多困难！

这个程序是*意大利面编程*的一个例子——编程中所有东西都混在一起，源代码没有整体组织。不幸的是，意大利面编程经常与其他使程序更难理解的编程习惯结合在一起。一些更常见的问题包括：

+   选择不当的变量和函数名称，不能暗示每个变量或函数的用途。一个典型的例子是一个程序使用诸如`a`、`b`、`c`和`d`这样的变量名。

+   完全没有任何解释代码应该做什么的文档。

+   具有意外副作用的函数。例如，想象一下，如果我们示例程序中的`print_results()`函数在打印时修改了`results`数组。如果你想要两次打印结果或在打印后使用结果，你的程序将以一种最神秘的方式失败。

虽然模块化编程不能治愈所有这些问题，但它迫使你考虑程序的逻辑组织，这将帮助你避免它们。将代码组织成逻辑片段将有助于你构建程序，以便你知道每个部分应该放在哪里。考虑包和模块，以及每个模块包含什么，将鼓励你为程序的各个部分选择清晰和适当的名称。使用模块和包还使得在编写过程中自然地包含**文档字符串**来解释程序的每个部分的功能。最后，使用逻辑结构鼓励程序的每个部分执行一个特定的任务，减少了代码中副作用的可能性。

当然，像任何编程技术一样，模块化编程也可能被滥用，但如果使用得当，它将大大提高你编写的程序的质量。

# 作为一个过程的编程

想象一下，你正在编写一个计算海外购买价格的程序。你的公司位于英格兰，你需要计算以美元购买的物品的当地价格。其他人已经编写了一个 Python 模块，用于下载汇率，所以你的程序开始看起来像下面这样：

```py
def calc_local_price(us_dollar_amount):
    exchange_rate = get_exchange_rate("USD", "EUR")
    local_amount = us_dollar_amount * exchange_rate
    return local_amount
```

到目前为止一切都很好。你的程序包含在公司的在线订购系统中，代码投入生产。然而，两个月后，你的公司开始不仅从美国订购产品，还从中国、德国和澳大利亚订购产品。你匆忙更新你的程序以支持这些替代货币，并写下了以下内容：

```py
def calc_local_price(foreign_amount, from_country):
    if from_country == "United States":
        exchange_rate = get_exchange_rate("USD", "EUR")
    elif from_country == "China":
        exchange_rate = get_exchange_rate("CHN", "EUR")
    elif from_country == "Germany":
        exchange_rate = get_exchange_rate("EUR", "EUR")
    elif from_country = "Australia":
        exchange_rate = get_exchange_rate("AUS", "EUR")
    else:
        raise RuntimeError("Unsupported country: " + from_country)
    local_amount = us_dollar_amount * exchange_rate
    return local_amount
```

这个程序再次投入生产。六个月后，又添加了另外 14 个国家，并且项目经理还决定添加一个新功能，用户可以看到产品价格随时间的变化。作为负责这段代码的程序员，你现在必须为这 14 个国家添加支持，并且还要添加支持历史汇率的功能。

当然，这只是一个刻意构造的例子，但它确实展示了程序通常是如何演变的。程序代码不是您写一次然后永远留下的东西。您的程序在不断地变化和发展，以响应新的需求、新发现的错误和意想不到的后果。有时，一个看似简单的变更可能并非如此。例如，考虑一下在我们之前的例子中编写`get_exchange_rate()`函数的可怜程序员。这个函数现在不仅需要支持任意货币对的当前汇率，还需要返回到任意所需时间点的历史汇率。如果这个函数是从一个不支持历史汇率的来源获取信息，那么整个函数可能需要从头开始重写以支持替代数据来源。

有时，程序员和 IT 经理试图抑制变更，例如通过编写详细的规范，然后逐步实现程序的一部分（所谓的*瀑布*编程方法）。但变更是编程的一个组成部分，试图抑制它就像试图阻止风吹一样——最好的办法是接受您的程序*将*发生变更，并学会尽可能好地管理这个过程。

模块化技术是管理程序变更的一种绝佳方式。例如，随着程序的增长和发展，您可能会发现某个变更需要向程序添加一个新模块：

![编程作为一个过程](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mdl-prog-py/img/B05012_1_03.jpg)

然后，您可以在程序的其他部分导入和使用该模块，以便使用这个新功能。

或者，您可能会发现一个新功能只需要您更改一个模块的内容：

![编程作为一个过程](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mdl-prog-py/img/B05012_1_04.jpg)

这是模块化编程的主要好处之一——因为特定功能的实现细节在一个模块内部，您通常可以改变模块的内部实现而不影响程序的其他部分。您的程序的其余部分继续像以前一样导入和使用模块——只有模块的内部实现发生了变化。

最后，您可能会发现需要**重构**您的程序。这是您必须改变代码的模块化组织以改进程序运行方式的地方：

![编程作为一个过程](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mdl-prog-py/img/B05012_1_05.jpg)

重构可能涉及将代码从一个模块移动到另一个模块，以及创建新模块、删除旧模块和更改模块的工作方式。实质上，重构是重新思考程序，使其运行得更好的过程。

在所有这些变更中，使用模块和包可以帮助您管理所做的变更。因为各个模块和包都执行着明确定义的任务，您确切地知道程序的哪些部分需要被改变，并且可以将变更的影响限制在受影响的模块和使用它们的系统部分之内。

模块化编程不会让变更消失，但它将帮助您处理变更——以及编程的持续过程——以最佳方式。

# Python 标准库

用来描述 Python 的一个流行词是它是一种“电池包含”的语言，也就是说，它带有丰富的内置模块和包的集合，称为**Python 标准库**。如果您编写了任何非平凡的 Python 程序，几乎肯定会使用 Python 标准库中的模块。要了解 Python 标准库有多么庞大，以下是该库中的一些示例模块：

| 模块 | 描述 |
| --- | --- |
| `datetime` | 定义用于存储和计算日期和时间值的类 |
| `tempfile` | 定义一系列函数来处理临时文件和目录 |
| `csv` | 支持读写 CSV 格式文件 |
| `hashlib` | 实现了密码安全哈希 |
| `logging` | 允许你编写日志消息和管理日志文件 |
| `threading` | 支持多线程编程 |
| `html` | 一组用于解析和生成 HTML 文档的模块（即包） |
| `unittest` | 用于创建和运行单元测试的框架 |
| `urllib` | 一组用于从 URL 读取数据的模块 |

这些只是 Python 标准库中可用的 300 多个模块中的一小部分。正如你所看到的，提供了广泛的功能，所有这些都内置在每个 Python 发行版中。

由于提供的功能范围非常广泛，Python 标准库是模块化编程的一个很好的例子。例如，`math` 标准库模块提供了一系列数学函数，使得更容易处理整数和浮点数。如果你查看这个模块的文档（[`docs.python.org/3/library/math.html`](http://docs.python.org/3/library/math.html)），你会发现一个大量的函数和常量，都在 `math` 模块中定义，执行几乎任何你能想象到的数学运算。在这个例子中，各种函数和常量都在一个单独的模块中定义，这样在需要时很容易引用它们。

相比之下，`xmlrpc` 包允许你进行使用 XML 协议发送和接收数据的远程过程调用。`xmlrpc` 包由两个模块组成：`xmlrpc.server` 和 `xmlrpc.client`，其中 `server` 模块允许你创建 XML-RPC 服务器，而 `client` 模块包括访问和使用 XML-RPC 服务器的代码。这是一个使用模块层次结构来逻辑地将相关功能组合在一起的例子（在这种情况下，在 `xmlrpc` 包中），同时使用子模块来分离包的特定部分。

如果你还没有这样做，值得花一些时间查看 Python 标准库的文档。可以在 [`docs.python.org/3/library/`](https://docs.python.org/3/library/) 找到。值得研究这些文档，看看 Python 是如何将如此庞大的功能集合组织成模块和包的。

Python 标准库并不完美，但随着时间的推移得到了改进，如今的库是模块化编程技术应用到了一个全面的库中，涵盖了广泛的功能和函数的一个很好的例子。

# 创建你的第一个模块

既然我们已经看到了模块是什么以及它们如何被使用，让我们实现我们的第一个真正的 Python 模块。虽然这个模块很简单，但你可能会发现它是你编写的程序的一个有用的补充。

## 缓存

在计算机编程中，**缓存**是一种存储先前计算结果的方式，以便可以更快地检索它们。例如，想象一下，你的程序必须根据三个参数计算运费：

+   已订购商品的重量

+   已订购商品的尺寸

+   客户的位置

根据客户的位置计算运费可能会非常复杂。例如，你可能对本市内的送货收取固定费用，但对于外地订单，根据客户的距离收取溢价。你甚至可能需要向货运公司的 API 发送查询，看看运送给定物品会收取多少费用。

由于计算运费的过程可能非常复杂和耗时，使用缓存来存储先前计算的结果是有意义的。这允许你使用先前计算的结果，而不是每次都重新计算运费。为此，你需要将你的 `calc_shipping_cost()` 函数结构化为以下内容：

```py
def calc_shipping_cost(params):
    if params in cache:
        shipping_cost = cache[params]
    else:
        ...calculate the shipping cost.
        cache[params] = shipping_cost
    return shipping_cost
```

正如你所看到的，我们接受提供的参数（在这种情况下是重量、尺寸和客户位置），并检查是否已经有一个缓存条目与这些参数匹配。如果是，我们从缓存中检索先前计算的运费。否则，我们将经历可能耗时的过程来计算运费，使用提供的参数将其存储在缓存中，然后将运费返回给调用者。

请注意，前面伪代码中的`cache`变量看起来非常像 Python 字典——你可以根据给定的键在字典中存储条目，然后使用该键检索条目。然而，字典和缓存之间有一个关键区别：缓存通常对其包含的条目数量有一个*限制*，而字典没有这样的限制。这意味着字典将继续无限增长，可能会占用计算机的所有内存，而缓存永远不会占用太多内存，因为条目数量是有限的。

一旦缓存达到最大尺寸，每次添加新条目时都必须删除一个现有条目，以防缓存继续增长：

![缓存](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mdl-prog-py/img/B05012_1_06.jpg)

虽然有各种各样的选择要删除的条目的方法，但最常见的方法是删除最近未使用的条目，也就是最长时间未使用的条目。

缓存在计算机程序中非常常见。事实上，即使你在编写程序时还没有使用缓存，你几乎肯定以前遇到过它们。有人曾经建议你*清除浏览器缓存*来解决浏览器问题吗？是的，浏览器使用缓存来保存先前下载的图像和网页，这样它们就不必再次检索，清除浏览器缓存的内容是修复浏览器问题的常见方法。

## 编写一个缓存模块

现在让我们编写自己的 Python 模块来实现一个缓存。在写之前，让我们考虑一下我们的缓存模块将需要的功能：

+   我们将限制我们的缓存大小为 100 个条目。

+   我们将需要一个`init()`函数来初始化缓存。

+   我们将有一个`set(key, value)`函数来在缓存中存储一个条目。

+   `get(key)`函数将从缓存中检索条目。如果没有该键的条目，此函数应返回`None`。

+   我们还需要一个`contains(key)`函数来检查给定的条目是否在缓存中。

+   最后，我们将实现一个`size()`函数，它返回缓存中的条目数。

### 注意

我们故意保持这个模块的实现相当简单。一个真正的缓存会使用`Cache`类来允许您同时使用多个缓存。它还将允许根据需要配置缓存的大小。然而，为了保持简单，我们将直接在一个模块中实现这些函数，因为我们想专注于模块化编程，而不是将其与面向对象编程和其他技术结合在一起。

继续创建一个名为`cache.py`的新 Python 源文件。这个文件将保存我们新模块的 Python 源代码。在这个模块的顶部，输入以下 Python 代码：

```py
import datetime

MAX_CACHE_SIZE = 100
```

我们将使用`datetime`标准库模块来计算缓存中最近未使用的条目。第二个语句定义了`MAX_CACHE_SIZE`，设置了我们缓存的最大尺寸。

### 提示

请注意，我们遵循了使用大写字母定义常量的标准 Python 约定。这样可以使它们在源代码中更容易看到。

现在我们要为我们的缓存实现`init()`函数。为此，在模块的末尾添加以下内容：

```py
def init():
    global _cache
    _cache = {} # Maps key to (datetime, value) tuple.
```

如你所见，我们创建了一个名为`init()`的新函数。这个函数的第一条语句`global _cache`定义了一个名为`_cache`的新变量。`global`语句使得这个变量作为*模块级全局变量*可用，也就是说，这个变量可以被`cache.py`模块的所有部分共享。

注意变量名开头的下划线字符。在 Python 中，前导下划线是指示名称为私有的约定。换句话说，`_cache`全局变量旨在作为`cache.py`模块的内部部分使用——下划线告诉你，你不应该在`cache.py`模块之外使用这个变量。

`init()`函数中的第二条语句将`_cache`全局设置为空字典。注意我们添加了一个解释说明字典将如何被使用的注释；向你的代码中添加这样的注释是一个好习惯，这样其他人（以及你，在长时间处理其他事情后再看这段代码时）可以轻松地看到这个变量的用途。

总之，调用`init()`函数的效果是在模块内创建一个私有的`_cache`变量，并将其设置为空字典。现在让我们编写`set()`函数，它将使用这个变量来存储缓存条目。

将以下内容添加到模块的末尾：

```py
def set(key, value):
    global _cache
    if key not in _cache and len(_cache) >= MAX_CACHE_SIZE:
        _remove_oldest_entry()
    _cache[key] = [datetime.datetime.now(), value]
```

一次又一次，`set()`函数以`global _cache`语句开始。这使得`_cache`模块级全局变量可供函数使用。

`if`语句检查缓存是否将超过允许的最大大小。如果是，我们调用一个名为`_remove_oldest_entry()`的新函数，从缓存中删除最旧的条目。注意这个函数名也以下划线开头——再次说明这个函数是私有的，只应该被模块内部的代码使用。

最后，我们将条目存储在`_cache`字典中。注意我们存储了当前日期和时间以及缓存中的值；这将让我们知道缓存条目上次被使用的时间，这在我们必须删除最旧的条目时很重要。

现在实现`get()`函数。将以下内容添加到模块的末尾：

```py
def get(key):
    global _cache
    if key in _cache:
        _cache[key][0] = datetime.datetime.now()
        return _cache[key][1]
    else:
        return None
```

你应该能够弄清楚这段代码的作用。唯一有趣的部分是在返回相关值之前更新缓存条目的日期和时间。这样我们就知道缓存条目上次被使用的时间。

有了这些函数的实现，剩下的两个函数也应该很容易理解。将以下内容添加到模块的末尾：

```py
def contains(key):
    global _cache
    return key in _cache

def size():
    global _cache
    return len(_cache)
```

这里不应该有任何意外。

只剩下一个函数需要实现：我们的私有`_remove_oldest_entry()`函数。将以下内容添加到模块的末尾：

```py
def _remove_oldest_entry():
    global _cache
    oldest = None
    for key in _cache.keys():
        if oldest == None:
            oldest = key
        elif _cache[key][0] < _cache[oldest][0]:
            oldest = key
    if oldest != None:
        del _cache[oldest]
```

这完成了我们`cache.py`模块本身的实现，包括我们之前描述的五个主要函数，以及一个私有函数和一个私有全局变量，它们在内部用于帮助实现我们的公共函数。

## 使用缓存

现在让我们编写一个简单的测试程序来使用这个`cache`模块，并验证它是否正常工作。创建一个新的 Python 源文件，我们将其称为`test_cache.py`，并将以下内容添加到该文件中：

```py
import random
import string
import cache

def random_string(length):
    s = ''
    for i in range(length):
        s = s + random.choice(string.ascii_letters)
    return s

cache.init()

for n in range(1000):
    while True:
        key = random_string(20)
        if cache.contains(key):
            continue
        else:
            break
    value = random_string(20)
    cache.set(key, value)
    print("After {} iterations, cache has {} entries".format(n+1, cache.size()))
```

这个程序首先导入了三个模块：两个来自 Python 标准库，以及我们刚刚编写的`cache`模块。然后我们定义了一个名为`random_string()`的实用函数，它生成给定长度的随机字母字符串。之后，我们通过调用`cache.init()`来初始化缓存，然后生成 1,000 个随机条目添加到缓存中。在添加每个缓存条目后，我们打印出我们添加的条目数以及当前的缓存大小。

如果你运行这个程序，你会发现它按预期工作：

```py
$ python test_cache.py
After 1 iterations, cache has 1 entries
After 2 iterations, cache has 2 entries
After 3 iterations, cache has 3 entries
...
After 98 iterations, cache has 98 entries
After 99 iterations, cache has 99 entries
After 100 iterations, cache has
 **100 entries
After 101 iterations, cache has 100 entries
After 102 iterations, cache has 100 entries
...
After 998 iterations, cache has 100 entries
After 999 iterations, cache has 100 entries
After 1000 iterations, cache has 100 entries

```

缓存会不断增长，直到达到 100 个条目，此时最旧的条目将被移除以为新条目腾出空间。这确保了缓存保持相同的大小，无论添加了多少新条目。

虽然我们可以在`cache.py`模块中做更多的事情，但这已足以演示如何创建一个有用的 Python 模块，然后在另一个程序中使用它。当然，你不仅仅局限于在主程序中导入模块，模块也可以相互导入。

# 总结

在本章中，我们介绍了 Python 模块的概念，看到 Python 模块只是 Python 源文件，可以被另一个源文件导入和使用。然后我们看了 Python 包，发现这些是由一个名为`__init__.py`的包初始化文件标识的模块集合。

我们探讨了模块和包如何用于组织程序的源代码，以及为什么使用这些模块化技术对于大型系统的开发非常重要。我们还探讨了意大利面条式代码的样子，发现如果不对程序进行模块化，可能会出现一些其他陷阱。

接下来，我们将编程视为不断变化和发展的过程，以及模块化编程如何帮助以最佳方式处理不断变化的代码库。然后我们了解到 Python 标准库是大量模块和包的绝佳示例，并通过创建自己的简单 Python 模块来展示有效的模块化编程技术。在实现这个模块时，我们学会了模块如何使用前导下划线来标记变量和函数名称为模块的*私有*，同时使其余函数和其他定义可供系统的其他部分使用。

在下一章中，我们将应用模块化技术来开发一个更复杂的程序，由几个模块共同解决一个更复杂的编程问题。


# 第二章：编写您的第一个模块化程序

在本章中，我们将使用模块化编程技术来实现一个非平凡的程序。在此过程中，我们将：

+   了解程序设计的“分而治之”方法

+   检查我们的程序需要执行的任务

+   查看我们的程序需要存储的信息

+   应用模块化技术，将我们的程序分解为各个部分

+   弄清楚每个部分如何可以作为单独的 Python 模块实现

+   查看各个模块如何协同工作以实现我们程序的功能

+   按照这个过程实现一个简单但完整的库存控制系统

+   了解模块化技术如何允许您向程序添加功能，同时最小化需要进行的更改

# 库存控制系统

假设您被要求编写一个程序，允许用户跟踪公司的库存，即公司可供销售的各种物品。对于每个库存物品，您被要求跟踪产品代码和物品当前的位置。新物品将在收到时添加，已售出的物品将在售出后移除。您的程序还需要生成两种类型的报告：列出公司当前库存的报告，包括每种物品在每个位置的数量，以及用于在物品售出后重新订购库存物品的报告。

查看这些要求，很明显我们需要存储三种不同类型的信息：

1.  公司出售的不同类型的产品清单。对于每种产品类型，我们需要知道产品代码（有时称为 SKU 编号）、描述以及公司应该在库存中拥有的该产品类型的所需数量。

1.  库存物品可以存放的位置清单。这些位置可能是单独的商店、仓库或储藏室。或者，位置可能标识商店内的特定货架或过道。对于每个位置，我们需要有位置代码和标识该位置的描述。

1.  最后，公司当前持有的库存物品清单。每个库存物品都有产品代码和位置代码；这些标识产品类型以及物品当前所在的位置。

运行程序时，最终用户应能执行以下操作：

+   向库存中添加新物品

+   从库存中移除物品

+   生成当前库存物品的报告

+   生成需要重新订购的库存物品的报告

+   退出程序

虽然这个程序并不太复杂，但这里有足够的功能可以从模块化设计中受益，同时保持我们的讨论相对简洁。既然我们已经看了我们的程序需要做什么以及我们需要存储的信息，让我们开始应用模块化编程技术来设计我们的系统。

# 设计库存控制系统

如果您退后一步，审查我们的库存控制程序的功能，您会发现这个程序需要支持三种基本类型的活动：

+   存储信息

+   与用户交互

+   生成报告

虽然这很笼统，但这种分解很有帮助，因为它提出了组织程序代码的可能方式。例如，负责存储信息的系统部分可以存储产品、位置和库存物品的列表，并在需要时提供这些信息。同样，负责与用户交互的系统部分可以提示用户选择要执行的操作，要求他们选择产品代码等。最后，负责生成报告的系统部分将能够生成所需类型的报告。

以这种方式思考系统，很明显，系统的这三个*部分*可以分别实现为单独的模块：

+   负责存储信息的系统部分可以称为**数据存储**模块

+   负责与用户交互的系统部分可以称为**用户界面**模块

+   负责生成报告的系统部分可以称为**报告生成器**模块

正如名称所示，每个模块都有特定的目的。除了这些专用模块，我们还需要系统的另一个部分：一个 Python 源文件，用户执行以启动和运行库存控制系统。因为这是用户实际运行的部分，我们将称其为**主程序**，通常存储在名为`main.py`的 Python 源文件中。

现在我们的系统有四个部分：三个模块加上一个主程序。每个部分都将有特定的工作要做，各个部分通常会相互交互以执行特定的功能。例如，报告生成器模块将需要从数据存储模块获取可用产品代码的列表。这些各种交互在下图中用箭头表示：

![设计库存控制系统](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mdl-prog-py/img/B05012_2_01.jpg)

现在我们对程序的整体结构有了一个概念，让我们更仔细地看看这四个部分中的每一个是如何工作的。

## 数据存储模块

这个模块将负责存储我们程序的所有数据。我们已经知道我们需要存储三种类型的信息：**产品**列表，**位置**列表和**库存项目**列表。

为了使我们的程序尽可能简单，我们将就数据存储模块做出两个重要的设计决定：

+   产品和位置列表将被硬编码到我们的程序中

+   我们将在内存中保存库存项目列表，并在列表更改时将其保存到磁盘上

我们的库存控制系统的更复杂的实现会将这些信息存储在数据库中，并允许用户查看和编辑产品代码和位置列表。然而，在我们的情况下，我们更关心程序的整体结构，所以我们希望尽可能简单地实现。

虽然产品代码列表将被硬编码，但我们不一定希望将此列表构建到数据存储模块本身中。数据存储模块负责存储和检索信息，而不是定义产品代码列表的工作。因此，我们需要在数据存储模块中添加一个函数，用于设置产品代码列表。此函数将如下所示：

```py
def set_products(products):
    ...
```

我们已经决定，对于每种产品，我们希望存储**产品代码**，**描述**和用户希望保留的**物品数量**。为了支持这一点，我们将定义产品列表（作为我们`set_products()`函数中的`products`参数提供）为`(code, description, desired_number)`元组的列表。例如，我们的产品列表可能如下所示：

```py
[("CODE01", "Product 1", 10),
 ("CODE02", "Product 2", 200), ...
]
```

一旦产品列表被定义，我们可以提供一个函数根据需要返回此列表：

```py
def products():
    ...
```

这将简单地返回产品列表，允许您的代码根据需要使用此列表。例如，您可以使用以下 Python 代码扫描产品列表：

```py
for code,description,desired_number in products():
    ...
```

这两个函数允许我们定义（硬编码）产品列表，并在需要时检索此列表。现在让我们为位置列表定义相应的两个函数。

首先，我们需要一个函数来设置硬编码的位置列表：

```py
def set_locations(locations):
    ...
```

`locations`列表中的每个项目将是一个`(code, description)`元组，其中`code`是位置的代码，`description`是描述位置的字符串，以便用户知道它在哪里。

然后我们需要一个函数根据需要检索位置列表：

```py
def locations():
    ...
```

再次返回位置列表，允许我们根据需要处理这些位置。

现在我们需要决定数据存储模块将如何允许用户存储和检索库存项目列表。库存项目被定义为产品代码加上位置代码。换句话说，库存项目是特定类型的产品在特定位置。

为了检索库存项目列表，我们将使用以下函数：

```py
def items():
    ...
```

遵循我们为`products()`和`locations()`函数使用的设计，`items()`函数将返回一个库存项目列表，其中每个库存项目都是一个`(product_code, location_code)`元组。

与产品和位置列表不同，库存项目列表不会被硬编码：用户可以添加和删除库存项目。为了支持这一点，我们需要两个额外的函数：

```py
def add_item(product_code, location_code):
    ...

def remove_item(product_code, location_code):
    ...
```

我们需要设计数据存储模块的最后一个部分：因为我们将在内存中存储库存项目列表，并根据需要将它们保存到磁盘，所以当程序启动时，我们需要一种方式将库存项目从磁盘加载到内存中。为了支持这一点，我们将为我们的模块定义一个**初始化函数**：

```py
def init():
    ...
```

我们现在已经决定了数据存储模块的总共八个函数。这八个函数构成了我们模块的**公共接口**。换句话说，系统的其他部分将*只能*使用这八个函数与我们的模块进行交互：

![数据存储模块](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mdl-prog-py/img/B05012_2_02.jpg)

注意我们在这里经历的过程：我们首先看了我们的模块需要做什么（在这种情况下，存储和检索信息），然后根据这些要求设计了模块的公共接口。对于前七个函数，我们使用业务需求来帮助我们设计接口，而对于最后一个函数`init()`，我们使用了我们对模块内部工作方式的知识来改变接口，以便模块能够完成其工作。这是一种常见的工作方式：业务需求和技术需求都将帮助塑造模块的接口以及它如何与系统的其他部分交互。

现在我们已经设计了我们的数据存储模块，让我们为系统中的其他模块重复这个过程。

## 用户界面模块

用户界面模块将负责与用户进行交互。这包括向用户询问信息，以及在屏幕上显示信息。为了保持简单，我们将为我们的库存控制系统使用一个简单的基于文本的界面，使用`print()`语句来显示信息，使用`input()`来要求用户输入内容。

我们的库存控制系统的更复杂的实现将使用带有窗口、菜单和对话框的图形用户界面。这样做会使库存控制系统变得更加复杂，远远超出了我们在这里尝试实现的范围。然而，由于系统的模块化设计，如果我们重新编写用户界面以使用菜单、窗口等，我们只需要更改这一个模块，而系统的其他部分将不受影响。

### 注意

这实际上是一个轻微的过度简化。用 GUI 替换基于文本的界面需要对系统进行许多更改，并且可能需要我们稍微更改模块的公共函数，就像我们不得不向数据存储模块添加`init()`函数以允许其内部工作方式一样。但是，由于我们正在设计系统的模块化方式，如果我们重写用户界面模块以使用 GUI，其他模块将不受影响。

让我们从用户与系统交互的角度来考虑库存控制系统需要执行的各种任务：

1.  用户需要能够选择要执行的操作。

1.  当用户想要添加新的库存项目时，我们需要提示用户输入新项目的详细信息。

1.  当用户想要移除库存项目时，我们需要提示用户输入要移除的库存项目的详细信息。

1.  当用户希望生成报告时，我们需要能够向用户显示报告的内容。

让我们逐个解决这些交互：

1.  要选择要执行的操作，我们将有一个`prompt_for_action()`函数，它返回一个标识用户希望执行的操作的字符串。让我们定义此函数可以返回的代码，以执行用户可以执行的各种操作：

| 操作 | 操作代码 |
| --- | --- |
| 添加库存项目 | `ADD` |
| 移除库存项目 | `REMOVE` |
| 生成当前库存项目的报告 | `INVENTORY_REPORT` |
| 生成需要重新订购的库存项目报告 | `REORDER_REPORT` |
| 退出程序 | `QUIT` |

1.  要添加库存项目，用户需要提示输入新项目的详细信息。因为库存项目被定义为给定位置的给定产品，实际上我们需要提示用户选择新项目的产品和位置。为了提示用户选择产品，我们将使用以下函数：

```py
def prompt_for_product():
    ...
```

用户将看到可用产品的列表，然后从列表中选择一个项目。如果他们取消，`prompt_for_product()`将返回`None`。否则，它将返回所选产品的产品代码。

同样，为了提示用户选择位置，我们将定义以下函数： 

```py
def prompt_for_location():
    ...
```

再次，这显示了可用位置的列表，用户可以从列表中选择一个位置。如果他们取消，我们返回`None`。否则，我们返回所选位置的位置代码。

使用这两个函数，我们可以要求用户标识新的库存项目，然后我们使用数据存储模块的`add_item()`函数将其添加到列表中。

1.  因为我们正在实现这个简单的基于文本的系统，删除库存项目的过程几乎与添加项目的过程相同：用户将被提示输入产品和位置，然后将删除该位置的库存项目。因此，我们不需要任何额外的函数来实现这个功能。

1.  要生成报告，我们将简单地调用报告生成器模块来完成工作，然后将生成的报告显示给用户。为了保持简单，我们的报告不会带任何参数，并且生成的报告将以纯文本格式显示。因此，我们唯一需要的用户界面函数是一个函数，用于显示报告的纯文本内容：

```py
def show_report(report):
    ...
```

`report`参数将简单地是一个包含生成报告的字符串的列表。`show_report()`函数需要做的就是逐个打印这些字符串，以向用户显示报告的内容。

这完成了我们对用户界面模块的设计。我们需要为此模块实现四个公共函数。

## 报告生成器模块

报告生成器模块负责生成报告。由于我们需要能够生成两种类型的报告，所以我们只需在报告生成器模块中有两个公共函数，每种报告一个：

```py
def generate_inventory_report():
    ...

def generate_reorder_report():
    ...
```

这些函数中的每一个都将生成给定类型的报告，将报告内容作为字符串列表返回。请注意，这些函数没有参数；因为我们尽可能保持简单，报告不会使用任何参数来控制它们的生成方式。

## 主程序

主程序不是一个模块。相反，它是一个标准的 Python 源文件，用户运行以启动系统。主程序将导入它需要的各种模块，并调用我们定义的函数来完成所有工作。在某种意义上，我们的主程序是将系统的所有其他部分粘合在一起的胶水。

在 Python 中，当一个源文件打算被运行（而不是被其他模块导入和使用，或者从 Python 命令行使用）时，通常使用以下结构的源文件：

```py
def main():
    ...

if __name__ == "__main__":
    main()
```

所有程序逻辑都写在`main()`函数内部，然后由文件中的最后两行调用。`if __name__ == "__main__"`行是 Python 的一个魔术，基本上意味着*如果正在运行这个程序*。换句话说，如果用户正在运行这个程序，调用`main()`函数来完成所有工作。

### 注意

我们可以将所有程序逻辑放在`if __name__ == "__main__"`语句下面，但将程序逻辑放在一个单独的函数中有一些优点。通过使用单独的函数，我们可以在想要退出时简单地从这个函数返回。这也使得错误处理更容易，代码组织得更好，因为我们的主程序代码与检查我们是否实际运行程序的代码是分开的。

我们将使用这个设计作为我们的主程序，将所有实际功能放在一个名为`main()`的函数中。

我们的`main()`函数将执行以下操作：

1.  调用需要初始化的各个模块的`init()`函数。

1.  提供产品和位置的硬连线列表。

1.  要求用户界面模块提示用户输入命令。

1.  响应用户输入的命令。

步骤 3 和 4 将无限重复，直到用户退出。

# 实施库存控制系统

现在我们对系统的整体结构有了一个很好的想法，我们的各种模块将是什么，它们将提供什么功能，是时候开始实施系统了。让我们从数据存储模块开始。

## 实施数据存储模块

在一个方便的地方创建一个目录，可以在其中存储库存控制系统的源代码。您可能想将此目录命名为`inventoryControl`或类似的名称。

在这个目录中，我们将放置各种模块和文件。首先创建一个名为`datastorage.py`的新的空 Python 源文件。这个 Python 源文件将保存我们的数据存储模块。

### 注意

在为我们的模块选择名称时，我们遵循 Python 使用所有小写字母的惯例。起初你可能会觉得有点笨拙，但很快就会变得容易阅读。有关这些命名约定的更多信息，请参阅[`www.python.org/dev/peps/pep-0008/#package-and-module-names`](https://www.python.org/dev/peps/pep-0008/#package-and-module-names)。

我们已经知道我们将需要八个不同的函数来构成这个模块的公共接口，所以继续添加以下 Python 代码到这个模块中：

```py
def init():
    pass

def items():
    pass

def products():
    pass

def locations():
    pass

def add_item(product_code, location_code):
    pass

def remove_item(product_code, location_code):
    pass

def set_products(products):
    pass

def set_locations(locations):
    pass
```

`pass`语句允许我们将函数留空-这些只是我们将要编写的代码的占位符。

现在让我们实现`init()`函数。这在系统运行时初始化数据存储模块。因为我们将库存物品列表保存在内存中，并在更改时将其保存到磁盘上，我们的`init()`函数将需要从磁盘上的文件中加载库存物品到内存中，以便在需要时可用。为此，我们将定义一个名为`_load_items()`的私有函数，并从我们的`init()`函数中调用它。

### 提示

请记住，前导下划线表示某些内容是私有的。这意味着`_load_items()`函数不会成为我们模块的公共接口的一部分。

将`init()`函数的定义更改为以下内容：

```py
def init():
    _load_items()
```

`_load_items()`函数将从磁盘上的文件加载库存物品列表到一个名为`_items`的私有全局变量中。让我们继续实现这个函数，通过将以下内容添加到模块的末尾：

```py
def _load_items():
    global _items
    if os.path.exists("items.json"):
        f = open("items.json", "r")
        _items = json.loads(f.read())
        f.close()
    else:
        _items = []
```

请注意，我们将库存物品列表存储在名为`items.json`的文件中，并且我们正在使用`json`模块将`_items`列表从文本文件转换为 Python 列表。

### 提示

JSON 是保存和加载 Python 数据结构的绝佳方式，生成的文本文件易于阅读。由于`json`模块内置在 Python 标准库中，我们不妨利用它。

因为我们现在正在使用 Python 标准库中的一些模块，您需要将以下`import`语句添加到模块的顶部：

```py
import json
import os.path
```

趁热打铁，让我们编写一个函数将库存物品列表保存到磁盘上。将以下内容添加到模块的末尾：

```py
def _save_items():
    global _items
    f = open("items.json", "w")
    f.write(json.dumps(_items))
    f.close()
```

由于我们已将库存物品列表加载到名为`_items`的私有全局变量中，我们现在可以实现`items()`函数以使这些数据可用。编辑`items()`函数的定义，使其看起来像下面这样：

```py
def items():
    global _items
    return _items
```

现在让我们实现`add_item()`和`remove_item()`函数，让系统的其余部分操作我们的库存物品列表。编辑这些函数，使其看起来像下面这样：

```py
def add_item(product_code, location_code):
    global _items
    _items.append((product_code, location_code))
    _save_items()

def remove_item(product_code, location_code):
    global _items
    for i in range(len(_items)):
        prod_code,loc_code = _items[i]
        if prod_code == product_code and loc_code == location_code:
            del _items[i]
            _save_items()
            return True
    return False
```

请注意，`remove_item()`函数如果成功移除该物品则返回`True`，否则返回`False`；这告诉系统的其余部分尝试移除库存物品是否成功。

我们现在已经实现了`datastorage`模块中与库存物品相关的所有函数。接下来，我们将实现与产品相关的函数。

由于我们知道我们将硬编码产品列表，`set_products()`函数将是微不足道的：

```py
def set_products(products):
    global _products
    _products = products
```

我们只需将产品列表存储在名为`_products`的私有全局变量中。然后，我们可以通过`products()`函数使这个列表可用：

```py
def products():
    global _products
    return _products
```

同样，我们现在可以实现`set_locations()`函数来设置硬编码的位置列表：

```py
def set_locations(locations):
    global _locations
    _locations = locations
```

最后，我们可以实现`locations()`函数以使这些信息可用：

```py
def locations():
    global _locations
    return _locations
```

这完成了我们对`datastorage`模块的实现。

## 实现用户界面模块

如前所述，用户界面模块将尽可能保持简单，使用`print()`和`input()`语句与用户交互。在这个系统的更全面的实现中，我们将使用图形用户界面（GUI）来显示并询问用户信息，但我们希望尽可能保持我们的代码简单。

有了这个想法，让我们继续实现我们的用户界面模块函数中的第一个。创建一个名为`userinterface.py`的新 Python 源文件来保存我们的用户界面模块，并将以下内容添加到此文件中：

```py
def prompt_for_action():
    while True:
        print()
        print("What would you like to do?")
        print()
        print("  A = add an item to the inventory.")
        print("  R = remove an item from the inventory.")
        print("  C = generate a report of the current inventory levels.")
        print("  O = generate a report of the inventory items to re-order.")
        print("  Q = quit.")
        print()
        action = input("> ").strip().upper()
        if   action == "A": return "ADD"
        elif action == "R": return "REMOVE"
        elif action == "C": return "INVENTORY_REPORT"
        elif action == "O": return "REORDER_REPORT"
        elif action == "Q": return "QUIT"
        else:
            print("Unknown action!")
```

正如您所看到的，我们提示用户输入与每个操作对应的字母，显示可用操作列表，并返回一个标识用户选择的操作的字符串。这不是实现用户界面的好方法，但它有效。

我们接下来要实现的函数是`prompt_for_product()`，它要求用户从可用产品代码列表中选择一个产品。为此，我们将不得不要求数据存储模块提供产品列表。将以下代码添加到你的`userinterface.py`模块的末尾：

```py
def prompt_for_product():
    while True:
        print()
        print("Select a product:")
        print()
        n = 1
        for code,description,desired_number in datastorage.products():
            print("  {}. {} - {}".format(n, code, description))
            n = n + 1

        s = input("> ").strip()
        if s == "": return None

        try:
            n = int(s)
        except ValueError:
            n = -1

        if n < 1 or n > len(datastorage.products()):
            print("Invalid option: {}".format(s))
            continue

        product_code = datastorage.products()[n-1][0]
        return product_code
```

在这个函数中，我们显示产品列表，并在每个产品旁边显示一个数字。然后用户输入所需产品的数字，我们将产品代码返回给调用者。如果用户没有输入任何内容，我们返回`None`——这样用户可以在不想继续的情况下按下*Enter*键而不输入任何内容。

趁热打铁，让我们实现一个相应的函数，要求用户确定一个位置：

```py
def prompt_for_location():
    while True:
        print()
        print("Select a location:")
        print()
        n = 1
        for code,description in datastorage.locations():
            print("  {}. {} - {}".format(n, code, description))
            n = n + 1

        s = input("> ").strip()
        if s == "": return None

        try:
            n = int(s)
        except ValueError:
            n = -1

        if n < 1 or n > len(datastorage.locations()):
            print("Invalid option: {}".format(s))
            continue

        location_code = datastorage.locations()[n-1][0]
        return location_code
```

再次，这个函数显示每个位置旁边的数字，并要求用户输入所需位置的数字。然后我们返回所选位置的位置代码，如果用户取消，则返回`None`。

由于这两个函数使用了数据存储模块，我们需要在我们的模块顶部添加以下`import`语句：

```py
import datastorage
```

我们只需要实现一个函数：`show_report()`函数。让我们现在这样做：

```py
def show_report(report):
    print()
    for line in report:
        print(line)
    print()
```

由于我们使用文本界面来实现这个功能，这个函数几乎是荒谬地简单。不过它确实有一个重要的目的：通过将显示报告的过程作为一个单独的函数来实现，我们可以重新实现这个函数，以更有用的方式显示报告（例如，在 GUI 中的窗口中显示），而不会影响系统的其余部分。

## 实现报告生成器模块

报告生成器模块将有两个公共函数，一个用于生成每种类型的报告。话不多说，让我们实现这个模块，我们将把它存储在一个名为`reportgenerator.py`的 Python 源文件中。创建这个文件，并输入以下内容：

```py
import datastorage

def generate_inventory_report():
    product_names = {}
    for product_code,name,desired_number in datastorage.products():
        product_names[product_code] = name

    location_names = {}
    for location_code,name in datastorage.locations():
        location_names[location_code] = name

    grouped_items = {}
    for product_code,location_code in datastorage.items():
        if product_code not in grouped_items:
            grouped_items[product_code] = {}

        if location_code not in grouped_items[product_code]:
            grouped_items[product_code][location_code] = 1
        else:
            grouped_items[product_code][location_code] += 1

    report = []
    report.append("INVENTORY REPORT")
    report.append("")

    for product_code in sorted(grouped_items.keys()):
        product_name = product_names[product_code]
        report.append("Inventory for product: {} - {}"
                      .format(product_code, product_name))
        report.append("")

        for location_code in sorted(grouped_items[product_code].keys()):
            location_name = location_names[location_code]
            num_items = grouped_items[product_code][location_code]
            report.append("  {} at {} - {}"
                          .format(num_items,
                                  location_code,
                                  location_name))
        report.append("")

    return report

def generate_reorder_report():
    product_names   = {}
    desired_numbers = {}

    for product_code,name,desired_number in datastorage.products():
        product_names[product_code] = name
        desired_numbers[product_code] = desired_number

    num_in_inventory = {}
    for product_code,location_code in datastorage.items():
        if product_code in num_in_inventory:
            num_in_inventory[product_code] += 1
        else:
            num_in_inventory[product_code] = 1

    report = []
    report.append("RE-ORDER REPORT")
    report.append("")

    for product_code in sorted(product_names.keys()):
        desired_number = desired_numbers[product_code]
        current_number = num_in_inventory.get(product_code, 0)
        if current_number < desired_number:
            product_name = product_names[product_code]
            num_to_reorder = desired_number - current_number
            report.append("  Re-order {} of {} - {}"
                          .format(num_to_reorder,
                                  product_code,
                                  product_name))
    report.append("")

    return report
```

不要太担心这些函数的细节。正如你所看到的，我们从数据存储模块获取库存项目列表、产品列表和位置列表，并根据这些列表的内容生成一个简单的基于文本的报告。

## 实现主程序

我们需要实现的系统的最后一部分是我们的主程序。创建另一个名为`main.py`的 Python 源文件，并将以下内容输入到这个文件中：

```py
import datastorage
import userinterface
import reportgenerator

def main():
    pass

if __name__ == "__main__":
    main()
```

这只是我们主程序的总体模板：我们导入我们创建的各种模块，定义一个`main()`函数，所有的工作都将在这里完成，并在程序运行时调用它。现在我们需要编写我们的`main()`函数。

我们的第一个任务是初始化其他模块并定义产品和位置的硬编码列表。让我们现在这样做，通过重写我们的`main()`函数，使其看起来像下面这样：

```py
def main():
    datastorage.init()

    datastorage.set_products([
        ("SKU123", "4 mm flat-head wood screw",        50),
        ("SKU145", "6 mm flat-head wood screw",        50),
        ("SKU167", "4 mm countersunk head wood screw", 10),
        ("SKU169", "6 mm countersunk head wood screw", 10),
        ("SKU172", "4 mm metal self-tapping screw",    20),
        ("SKU185", "8 mm metal self-tapping screw",    20),
    ])

    datastorage.set_locations([
        ("S1A1", "Shelf 1, Aisle 1"),
        ("S2A1", "Shelf 2, Aisle 1"),
        ("S3A1", "Shelf 3, Aisle 1"),
        ("S1A2", "Shelf 1, Aisle 2"),
        ("S2A2", "Shelf 2, Aisle 2"),
        ("S3A2", "Shelf 3, Aisle 2"),
        ("BIN1", "Storage Bin 1"),
        ("BIN2", "Storage Bin 2"),
    ])
```

接下来，我们需要询问用户他们希望执行的操作，然后做出适当的响应。我们将从询问用户操作开始，使用`while`语句，以便可以重复执行这个操作：

```py
    while True:
        action = userinterface.prompt_for_action()
```

接下来，我们需要响应用户选择的操作。显然，我们需要针对每种可能的操作进行这样的操作。让我们从“退出”操作开始：

`break`语句将退出`while True`语句，这样就会离开`main()`函数并关闭程序。

接下来，我们要实现“添加”操作：

```py
        if action == "QUIT":
            break
        elif action == "ADD":
            product = userinterface.prompt_for_product()
            if product != None:
                location = userinterface.prompt_for_location()
                if location != None:
                    datastorage.add_item(product, location)
```

请注意，我们调用用户界面函数提示用户输入产品，然后输入位置代码，只有在函数没有返回`None`的情况下才继续。这意味着我们只有在用户没有取消的情况下才提示位置或添加项目。

现在我们可以实现“删除”操作的等效函数了：

```py
        elif action == "REMOVE":
            product = userinterface.prompt_for_product()
            if product != None:
                location = userinterface.prompt_for_location()
                if location != None:
                    if not datastorage.remove_item(product,
                                                   location):
                        pass # What to do?
```

这几乎与添加项目的逻辑完全相同，只有一个例外：`datastorage.remove_item()`函数可能会失败（返回`False`），如果该产品和位置代码没有库存项目。正如`pass`语句旁边的注释所建议的那样，当这种情况发生时，我们将不得不做一些事情。

我们现在已经达到了模块化编程过程中非常常见的一个点：我们设计了所有我们认为需要的功能，但后来发现漏掉了一些东西。当用户尝试移除一个不存在的库存项目时，我们希望显示一个错误消息，以便用户知道出了什么问题。因为所有用户交互都发生在`userinterface.py`模块中，我们希望将这个功能添加到该模块中。

现在让我们这样做。回到编辑`userinterface.py`模块，并在末尾添加以下函数：

```py
def show_error(err_msg):
    print()
    print(err_msg)
    print()
```

再次强调，这是一个令人尴尬的简单函数，但它让我们可以将所有用户交互保持在`userinterface`模块中（并且允许以后重写我们的程序以使用 GUI）。现在让我们用适当的错误处理代码替换`main.py`程序中的`pass`语句：

```py
                    ...
                    if not datastorage.remove_item(product,
                                                   location):
 **userinterface.show_error(
 **"There is no product with " +
 **"that code at that location!")

```

不得不回去更改模块的功能是非常常见的。幸运的是，模块化编程使这个过程更加自包含，因此在这样做时，您不太可能出现副作用和其他错误。

现在用户可以添加和移除库存项目，我们只需要实现另外两个操作：`INVENTORY_REPORT`操作和`REORDER_REPORT`操作。对于这两个操作，我们只需要调用适当的报告生成器函数来生成报告，然后调用用户界面模块的`show_report()`函数来显示结果。现在让我们通过将以下代码添加到我们的`main()`函数的末尾来实现这一点：

```py
        elif action == "INVENTORY_REPORT":
            report = reportgenerator.generate_inventory_report()
            userinterface.show_report(report)
        elif action == "REORDER_REPORT":
            report = reportgenerator.generate_reorder_report()
            userinterface.show_report(report)
```

这完成了我们`main()`函数的实现，实际上也完成了我们整个库存控制系统的实现。继续运行它。尝试输入一些库存项目，移除一两个库存项目，并生成两种类型的报告。如果您按照本书中提供的代码输入或下载了本章的示例代码，程序应该可以正常工作，为您提供一个简单但完整的库存控制系统，更重要的是，向您展示如何使用模块化编程技术实现程序。

# 总结

在本章中，我们设计并实现了一个非平凡的程序来跟踪公司的库存。使用分而治之的方法，我们将程序分成单独的模块，然后查看每个模块需要提供的功能。这使我们更详细地设计了每个模块内的函数，并且我们随后能够一步一步地实现整个系统。我们发现一些功能被忽视了，需要在设计完成后添加，并且看到模块化编程如何使这些类型的更改不太可能破坏您的系统。最后，我们快速测试了库存控制系统，确保它可以正常工作。

在下一章中，我们将更多地了解 Python 中模块和包的工作原理。


# 第三章：使用模块和包

要能够在 Python 程序中使用模块和包，您需要了解它们的工作原理。在本章中，我们将研究模块和包在 Python 中是如何定义和使用的。特别是，我们将：

+   回顾 Python 模块和包的定义

+   查看如何在其他包中创建包

+   发现模块和包如何初始化

+   了解更多关于导入过程

+   探索相对导入的概念

+   学习如何控制导入的内容

+   了解如何处理循环依赖

+   查看模块如何可以直接从命令行运行，以及为什么这很有用

# 模块和包

到目前为止，您应该已经相当熟悉如何将您的 Python 代码组织成模块，然后在其他模块和程序中导入和使用这些模块。然而，这只是一个小小的尝试。在深入了解它们如何工作之前，让我们简要回顾一下 Python 模块和包是什么。

正如我们所看到的，**模块**只是一个 Python 源文件。您可以使用`import`语句导入模块：

```py
import my_module
```

完成此操作后，您可以通过在项目名称前面添加模块名称来引用模块中的任何函数、类、变量和其他定义，例如：

```py
my_module.do_something()
print(my_module.variable)
```

在第一章中，*介绍模块化编程*，我们了解到 Python 的**包**是一个包含名为`__init__.py`的特殊文件的目录。这被称为**包初始化文件**，并将目录标识为 Python 包。该包通常还包含一个或多个 Python 模块，例如：

![模块和包](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mdl-prog-py/img/B05012_3_01.jpg)

要导入此包中的模块，您需要在模块名称的开头添加包名称。例如：

```py
import my_package.my_module
my_package.my_module.do_something()
```

您还可以使用`import`语句的另一种版本来使您的代码更易于阅读：

```py
from my_package import my_module
my_module.do_something()
```

### 注意

我们将在本章后面的*如何导入任何内容*部分中查看您可以使用`import`语句的各种方式。

# 包含包的包

就像您可以在目录中有子目录一样，您也可以在其他包中有包。例如，想象一下，我们的`my_package`目录包含另一个名为`my_sub_package`的目录，它本身有一个`__init__.py`文件：

![包含包的包](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mdl-prog-py/img/B05012_3_02.jpg)

正如您所期望的那样，您可以通过在包含它的包的名称前面添加来导入子包中的模块：

```py
from my_package.my_sub_package import my_module
my_module.do_something()
```

您可以无限嵌套包，但实际上，如果包含太多级别的包中包，它会变得有些难以管理。更有趣的是，各种包和子包形成了一个**树状结构**，这使您可以组织甚至最复杂的程序。例如，一个复杂的商业系统可能会被安排成这样：

![包含包的包](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mdl-prog-py/img/B05012_3_03.jpg)

正如您所看到的，这被称为树状结构，因为包中的包看起来像树的扩展分支。这样的树状结构使您可以将程序的逻辑相关部分组合在一起，同时确保在需要时可以找到所有内容。例如，使用前面插图描述的结构，您将使用`program.logic.data.customers`包访问客户数据，并且程序中的各种菜单将由`program.gui.widgets.menus`包定义。

显然，这是一个极端的例子。大多数程序——甚至非常复杂的程序——都不会这么复杂。但是您可以看到 Python 包如何使您能够保持程序的良好组织，无论它变得多么庞大和复杂。

# 初始化模块

当一个模块被导入时，该模块中的任何顶层代码都会被执行。这会使你在模块中定义的各种函数、变量和类对调用者可用。为了看看这是如何工作的，创建一个名为`test_module.py`的新 Python 源文件，并输入以下代码到这个模块中：

```py
def foo():
    print("in foo")

def bar():
    print("in bar")

my_var = 0

print("importing test module")
```

现在，打开一个终端窗口，`cd`到存储`test_module.py`文件的目录，并输入`python`启动 Python 解释器。然后尝试输入以下内容：

```py
% import test_module
```

当你这样做时，Python 解释器会打印以下消息：

```py
importing test module
```

这是因为模块中的所有顶层 Python 语句——包括`def`语句和我们的`print`语句——在模块被导入时都会被执行。然后你可以通过在名称前加上`my_module`来调用`foo`和`bar`函数，并访问`my_var`全局变量：

```py
% my_module.foo()
in foo
% my_module.bar()
in bar
% print(my_module.my_var)
0
% my_module.my_var = 1
% print(my_module.my_var)
1
```

因为模块被导入时会执行所有顶层的 Python 语句，所以你可以通过直接在模块中包含初始化语句来初始化一个模块，就像我们测试模块中设置`my_var`为零的语句一样。这意味着当模块被导入时，模块将自动初始化。

### 注意

请注意，一个模块只会被导入一次。如果两个模块导入了同一个模块，第二个`import`语句将简单地返回对已经导入的模块的引用，因此你不会导入（和初始化）两次相同的模块。

## 初始化函数

这种隐式初始化是有效的，但不一定是一个好的实践。Python 语言设计者提倡的指导方针之一是*显式优于隐式*。换句话说，让一个模块自动初始化并不总是一个好的编码实践，因为从代码中并不总是清楚哪些内容被初始化了，哪些没有。

为了避免这种混乱，并且为了遵循 Python 的指导方针，明确地初始化你的模块通常是一个好主意。按照惯例，这是通过定义一个名为`init()`的顶层函数来完成模块的所有初始化。例如，在我们的`test_module`中，我们可以用以下代码替换`my_var = 0`语句：

```py
def init():
    global my_var
    my_var = 0
```

这会显得有点啰嗦，但它使初始化变得明确。当然，你还必须记得在使用模块之前调用`test_module.init()`，通常是在主程序中调用。

显式模块初始化的主要优势之一是你可以控制各个模块初始化的顺序。例如，如果模块 A 的初始化包括调用模块 B 中的函数，并且这个函数需要模块 B 已经被初始化，如果两个模块的导入顺序错误，程序将崩溃。当模块导入其他模块时，情况会变得特别困难，因为模块导入的顺序可能会非常令人困惑。为了避免这种情况，最好使用显式模块初始化，并让你的主程序在调用`A.init()`之前调用`B.init()`。这是一个很好的例子，说明为什么通常最好为你的模块使用显式初始化函数。

# 初始化一个包

要初始化一个包，你需要将 Python 代码放在包的`__init__.py`文件中。这段代码将在包被导入时执行。例如，假设你有一个名为`test_package`的包，其中包含一个`__init__.py`文件和一个名为`test_module.py`的模块：

![初始化一个包](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mdl-prog-py/img/B05012_3_04.jpg)

你可以在`__init__.py`文件中放置任何你喜欢的代码，当包（或包内的模块）第一次被导入时，该代码将被执行。

你可能想知道为什么要这样做。初始化一个模块是有道理的，因为一个模块包含了可能需要在使用之前初始化的各种函数（例如，通过将全局变量设置为初始值）。但为什么要初始化一个包，而不仅仅是包内的一个模块？

答案在于当你导入一个包时发生了什么。当你这样做时，你在包的`__init__.py`文件中定义的任何东西都可以在包级别使用。例如，想象一下，你的`__init__.py`文件包含了以下 Python 代码：

```py
def say_hello():
    print("hello")
```

然后你可以通过以下方式从主程序中访问这个函数：

```py
import my_package
my_package.say_hello()
```

你不需要在包内的模块中定义`say_hello()`函数，它就可以很容易地被访问。

作为一个一般原则，向`__init__.py`文件添加代码并不是一个好主意。它可以工作，但是查看包源代码的人会期望包的代码被定义在模块内，而不是在包初始化文件中。另外，整个包只有一个`__init__.py`文件，这使得在包内组织代码变得更加困难。

更好的使用包初始化文件的方法是在包内的模块中编写代码，然后使用`__init__.py`文件导入这些代码，以便在包级别使用。例如，你可以在`test_module`模块中实现`say_hello()`函数，然后在包的`__init__.py`文件中包含以下内容：

```py
from test_package.test_module import say_hello
```

使用你的包的程序仍然可以以完全相同的方式调用`say_hello()`函数。唯一的区别是，这个函数现在作为`test_module`模块的一部分实现，而不是被整个包的`__init__.py`文件包含在一起。

这是一个非常有用的技术，特别是当你的包变得更加复杂，你有很多函数、类和其他定义想要提供。通过向包初始化文件添加`import`语句，你可以在任何模块中编写包的部分，然后选择哪些函数、类等在包级别可用。

使用`__init__.py`文件的一个好处是，各种`import`语句告诉包的用户他们应该使用哪些函数和类；如果你没有在包初始化文件中包含一个模块或函数，那么它可能被排除是有原因的。

在包初始化文件中使用`import`语句还告诉包的用户复杂包的各个部分的位置——`__init__.py`文件充当了包源代码的一种索引。

总之，虽然你可以在包的`__init__.py`文件中包含任何你喜欢的 Python 代码，但最好限制自己只使用`import`语句，并将真正的包代码放在其他地方。

# 如何导入任何东西

到目前为止，我们已经使用了`import`语句的两种不同版本：

+   导入一个模块，然后使用模块名来访问在该模块中定义的东西。例如：

```py
import math
print(math.pi)
```

+   从模块中导入某些东西，然后直接使用那个东西。例如：

```py
from math import pi
print(pi)
```

然而，`import`语句非常强大，我们可以用它做各种有趣的事情。在本节中，我们将看看你可以使用`import`语句以及它们的内容将模块和包导入到你的程序中的不同方式。

## 导入语句实际上是做什么？

每当你创建一个全局变量或函数时，Python 解释器都会将该变量或函数的名称添加到所谓的**全局命名空间**中。全局命名空间包含了你在全局级别定义的所有名称。要查看这是如何工作的，输入以下命令到 Python 解释器中：

```py
>>> print(globals())

```

`globals()`内置函数返回一个带有全局命名空间当前内容的字典：

```py
{'__package__': None, '__doc__': None, '__name__': '__main__', '__builtins__': <module 'builtins' (built-in)>, '__loader__': <class '_frozen_importlib.BuiltinImporter'>}

```

### 提示

不要担心各种奇怪命名的全局变量，例如`__package__`；这些是 Python 解释器内部使用的。

现在，让我们定义一个新的顶级函数：

```py
>>> def test():
...     print("Hello")
...
>>>

```

如果我们现在打印全局名称的字典，我们的`test()`函数将被包括在内：

```py
>>> print(globals())
{...'test': <function test at 0x1028225f0>...}

```

### 注意

`globals()`字典中还有其他几个条目，但从现在开始，我们只会显示我们感兴趣的项目，以便这些示例不会太令人困惑。

如您所见，名称`test`已添加到我们的全局命名空间中。

### 提示

再次，不要担心与`test`名称关联的值；这是 Python 存储您定义的函数的内部方式。

当某物在全局命名空间中时，您可以通过程序中的任何位置的名称访问它：

```py
>>> test()
Hello

```

### 注意

请注意，还有第二个命名空间，称为**局部命名空间**，其中保存了当前函数中定义的变量和其他内容。虽然局部命名空间在变量范围方面很重要，但我们将忽略它，因为它通常不涉及导入模块。

现在，当您使用`import`语句时，您正在向全局命名空间添加条目：

```py
>>> import string
>>> print(globals())
{...'string': <module 'string' from '/Library/Frameworks/Python.framework/Versions/3.3/lib/python3.3/string.py'>...}

```

正如您所看到的，您导入的模块已添加到全局命名空间中，允许您通过名称访问该模块，例如像这样：

```py
>>> print(string.capwords("this is a test"))
This Is A Test

```

同样，如果您使用`import`语句的`from...import`版本，您导入的项目将直接添加到全局命名空间中：

```py
>>> from string import capwords
>>> print(globals())
{...'capwords': <function capwords at 0x1020fb7a0>...}

```

现在您知道`import`语句的作用：它将您要导入的内容添加到全局命名空间，以便您可以访问它。

## 使用导入语句

既然我们已经看到了`import`语句的作用，让我们来看看 Python 提供的`import`语句的不同版本。

我们已经看到了`import`语句的两种最常见形式：

+   `import <something>`

+   `from <somewhere> import <something>`

使用第一种形式时，您不限于一次导入一个模块。如果愿意，您可以一次导入多个模块，就像这样：

```py
import string, math, datetime, random
```

同样，您可以一次从模块或包中导入多个项目：

```py
from math import pi, radians, sin
```

如果要导入的项目比一行所能容纳的要多，您可以使用行继续字符（`\`）将导入扩展到多行，或者用括号括起要导入的项目列表。例如：

```py
from math import pi, degrees, radians, sin, cos, \
                 tan, hypot, asin, acos, atan, atan2

from math import (pi, degrees, radians, sin, cos, 
                  tan, hypot, asin, acos, atan, atan2)
```

当您导入某物时，您还可以更改所导入项目的名称：

```py
import math as math_ops
```

在这种情况下，您正在将`math`模块导入为名称`math_ops`。`math`模块将使用名称`math_ops`添加到全局命名空间中，您可以使用`math_ops`名称访问`math`模块的内容：

```py
print(math_ops.pi)
```

有两个原因可能要使用`import...as`语句来更改导入时的名称：

1.  为了使长名称或难以处理的名称更容易输入。

1.  为了避免命名冲突。例如，如果您使用了两个都定义了名为`utils`的模块的包，您可能希望使用`import...as`语句，以便名称不同。例如：

```py
from package1 import utils as utils1
from package2 import utils as utils2
```

### 注意

请注意，您可能应该谨慎使用`import...as`语句。每次更改某物的名称时，您（以及任何阅读您代码的人）都必须记住`X`是`Y`的另一个名称，这增加了复杂性，并意味着您在编写程序时需要记住更多的事情。`import...as`语句当然有合法的用途，但不要过度使用它。

当然，您可以将`from...import`语句与`import...as`结合使用：

```py
from reports import customers as customer_report
from database import customers as customer_data
```

最后，您可以使用**通配符导入**一次性从模块或包中导入所有内容：

```py
from math import *
```

这将所有在`math`模块中定义的项目添加到当前全局命名空间。如果您从包中导入，则将导入包的`__init__.py`文件中定义的所有项目。

默认情况下，模块（或包）中以下划线字符开头的所有内容都将被通配符导入。这确保了私有变量和函数不会被导入。然而，如果你愿意，你可以通过使用`__all__`变量来改变通配符导入中包含的内容；这将在本章后面的*控制导入内容*部分中讨论。

## 相对导入

到目前为止，每当我们导入东西时，我们都使用了要从中导入的模块或包的完整名称。对于简单的导入，比如`from math import pi`，这是足够的。然而，有时这种类型的导入可能会相当繁琐。

例如，考虑我们在本章前面的*包内包*部分中看到的复杂包树。假设我们想要从`program.gui.widgets.editor`包内导入名为`slider.py`的模块：

![相对导入](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mdl-prog-py/img/B05012_3_06.jpg)

你可以使用以下 Python 语句导入这个模块：

```py
from program.gui.widgets.editor import slider
```

`import`语句中的`program.gui.widgets.editor`部分标识了`slider`模块所在的包。

虽然这样可以工作，但它可能会相当笨拙，特别是如果你需要导入许多模块，或者如果包的某个部分需要从同一个包内导入多个其他模块。

为了处理这种情况，Python 支持**相对导入**的概念。使用相对导入，你可以确定相对于包树中当前模块位置的位置导入你想要的内容。例如，假设`slider`模块想要从`program.gui.widgets.editor`包内导入另一个模块：

![相对导入](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mdl-prog-py/img/B05012_3_07.jpg)

为此，你用`.`字符替换包名：

```py
from . import slider
```

`.`字符是*当前包*的简写。

类似地，假设你有一个在`program.gui.widgets`包内的模块想要从`editor`子包内导入`slider`模块：

![相对导入](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mdl-prog-py/img/B05012_3_08.jpg)

在这种情况下，你的`import`语句将如下所示：

```py
from .editor import slider
```

`.`字符仍然指的是当前位置，`editor`是相对于当前位置的包的名称。换句话说，你告诉 Python 在当前位置查找名为`editor`的包，然后导入该包内的名为`slider`的模块。

让我们考虑相反的情况。假设`slider`模块想要从`widgets`目录中导入一个模块：

![相对导入](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mdl-prog-py/img/B05012_3_09.jpg)

在这种情况下，你可以使用两个`.`字符来表示*向上移动一个级别*：

```py
from .. import controls
```

正如你所想象的那样，你可以使用三个`.`字符来表示*向上移动两个级别*，依此类推。你也可以结合这些技术以任何你喜欢的方式在包层次结构中移动。例如，假设`slider`模块想要从`gui.dialogs.errors`包内导入名为`errDialog`的模块：

![相对导入](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/mdl-prog-py/img/B05012_3_10.jpg)

使用相对导入，`slider`模块可以以以下方式导入`errDialog`模块：

```py
from ...dialogs.errors import errDialog
```

如你所见，你可以使用这些技术来选择树状包结构中任何位置的模块或包。

使用相对导入有两个主要原因：

1.  它们是使你的`import`语句更短、更易读的好方法。在`slider`模块中，你不必再输入`from` `program.gui.widgets.editor import utils`，而是可以简单地输入`from . import utils`。

1.  当你为他人编写一个包时，你可以让包内的不同模块相互引用，而不必担心用户安装包的位置。例如，我可能会拿到你写的一个包并将其放入另一个包中；使用相对导入，你的包将继续工作，而无需更改所有`import`语句以反映新的包结构。

就像任何东西一样，相对导入可能会被滥用。因为`import`语句的含义取决于当前模块的位置，相对导入往往违反了“显式优于隐式”的原则。如果你尝试从命令行运行一个模块，也会遇到麻烦，这在本章后面的“从命令行运行模块”部分有描述。因此，除非有充分的理由，你应该谨慎使用相对导入，并坚持在`import`语句中完整列出整个包层次结构。

# 控制导入的内容

当你导入一个模块或包，或者使用通配符导入，比如`from my_module import *`，Python 解释器会将给定模块或包的内容加载到你的全局命名空间中。如果你从一个模块导入，所有顶层函数、常量、类和其他定义都会被导入。当从一个包导入时，包的`__init__.py`文件中定义的所有顶层函数、常量等都会被导入。

默认情况下，这些导入会从给定的模块或包中加载*所有*内容。唯一的例外是通配符导入会自动跳过任何以下划线开头的函数、常量、类或其他定义——这会导致通配符导入排除私有定义。

虽然这种默认行为通常运行良好，但有时你可能希望更多地控制导入的内容。为此，你可以使用一个名为`__all__`的特殊变量。

为了看看`__all__`变量是如何工作的，让我们看一下以下模块：

```py
A = 1
B = 2
C = 3
__all__ = ["A", "B"]
```

如果你导入这个模块，只有`A`和`B`会被导入。虽然模块定义了变量`C`，但这个定义会被跳过，因为它没有包含在`__all__`列表中。

在一个包内，`__all__`变量的行为方式相同，但有一个重要的区别：你还可以包括你希望在导入包时包含的模块和子包的名称。例如，一个包的`__init__.py`文件可能只包含以下内容：

```py
__all__ = ["module_1", "module_2", "sub_package"]
```

在这种情况下，`__all__`变量控制要包含的模块和包；当你导入这个包时，这两个模块和子包将被自动导入。

### 注意

注意，前面的`__init.py__`文件等同于以下内容：

```py
import module1
import module2
import sub_package
```

`__init__.py`文件的两个版本都会导致包中包含这两个模块和子包。

虽然你不一定需要使用它，`__all__`变量可以完全控制你的导入。`__all__`变量也可以是向模块和包的用户指示他们应该使用你代码的哪些部分的有用方式：如果某些东西没有包含在`__all__`列表中，那么它就不打算被外部代码使用。

# 循环依赖

在使用模块时，你可能会遇到的一个令人讨厌的问题是所谓的循环依赖。要理解这些是什么，考虑以下两个模块：

```py
# module_1.py

from module_2 import calc_markup

def calc_total(items):
    total = 0
    for item in items:
        total = total + item['price']
    total = total + calc_markup(total)
    return total

# module_2.py

from module_1 import calc_total

def calc_markup(total):
    return total * 0.1

def make_sale(items):
    total_price = calc_total(items)
    ...
```

虽然这是一个假设的例子，你可以看到`module_1`从`module_2`导入了一些东西，而`module_2`又从`module_1`导入了一些东西。如果你尝试运行包含这两个模块的程序，当导入`module_1`时，你会看到以下错误：

```py
ImportError: cannot import name calc_total

```

如果你尝试导入`module_2`，你会得到类似的错误。以这种方式组织代码，你就陷入了困境：你无法导入任何一个模块，因为它们都相互依赖。

为了解决这个问题，你需要重新构建你的模块，使它们不再相互依赖。在这个例子中，你可以创建一个名为`module_3`的第三个模块，并将`calc_markup()`函数移动到该模块中。这将使`module_1`依赖于`module_3`，而不是`module_2`，从而打破了循环依赖。

### 提示

还有其他一些技巧可以避免循环依赖错误，例如将`import`语句放在一个函数内部。然而，一般来说，循环依赖意味着你的代码设计有问题，你应该重构你的代码以完全消除循环依赖。

# 从命令行运行模块

在第二章*编写你的第一个模块化程序*中，我们看到你系统的主程序通常被命名为`main.py`，并且通常具有以下结构：

```py
def main():
    ...

if __name__ == "__main__":
    main()
```

当用户运行你的程序时，Python 解释器会将`__name__`全局变量设置为值`"__main__"`。这会在程序运行时调用你的`main()`函数。

`main.py`程序并没有什么特别之处；它只是另一个 Python 源文件。你可以利用这一点，使你的 Python 模块能够从命令行运行。

例如，考虑以下模块，我们将其称为`double.py`：

```py
def double(n):
    return n * 2

if __name__ == "__main__":
    print("double(3) =", double(3))
```

这个模块定义了一些功能，比如一个名为`double()`的函数，然后使用`if __name__ == "__main__"`的技巧来演示和测试模块在从命令行运行时的功能。让我们尝试运行这个模块，看看它是如何工作的：

```py
% python double.py** 
double(3) = 6

```

可运行模块的另一个常见用途是允许最终用户直接从命令行访问模块的功能。要了解这是如何工作的，创建一个名为`funkycase.py`的新模块，并输入以下内容到这个文件中：

```py
def funky_case(s):
    letters = []
    capitalize = False
    for letter in s:
        if capitalize:
            letters.append(letter.upper())
        else:
            letters.append(letter.lower())
        capitalize = not capitalize
    return "".join(letters)
```

`funky_case()` 函数接受一个字符串，并将每第二个字母大写。如果你愿意，你可以导入这个模块，然后在你的程序中访问这个函数：

```py
from funkycase import funky_case
s = funky_case("Test String")
```

虽然这很有用，但我们也希望让用户直接运行`funkycase.py`模块作为一个独立的程序，直接将提供的字符串转换为 funky-case 并打印出来给用户看。为了做到这一点，我们可以使用`if __name__ == "__main__"`的技巧以及`sys.argv`来提取用户提供的字符串。然后我们可以调用`funky_case()`函数来将这个字符串转换为 funky-case 并打印出来。为此，将以下代码添加到你的`funkycase.py`模块的末尾：

```py
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("You must supply exactly one string!")
    else:
        s = sys.argv[1]
        print(funky_case(s))
```

另外，将以下内容添加到你的模块顶部：

```py
import sys
```

现在你可以直接运行这个模块，就像它是一个独立的程序一样：

```py
% python funkycase.py "The quick brown fox"
tHe qUiCk bRoWn fOx

```

通过这种方式，`funkycase.py` 充当了一种*变色龙模块*。对于其他的 Python 源文件，它看起来就像是可以导入和使用的另一个模块，而对于最终用户来说，它看起来像是一个可以从命令行运行的独立程序。

### 提示

请注意，如果你想让一个模块能够从命令行运行，你不仅仅可以使用`sys.argv`来接受和处理用户提供的参数。Python 标准库中的优秀`argparse`模块允许你编写接受用户各种输入和选项的 Python 程序（和模块）。如果你以前没有使用过这个模块，一定要试试。

当你创建一个可以从命令行运行的模块时，有一个需要注意的问题：如果你的模块使用相对导入，当你直接使用 Python 解释器运行时，你的导入将会失败，并出现*尝试相对导入非包*的错误。这个错误是因为当模块从命令行运行时，它会忘记它在包层次结构中的位置。只要你的模块不使用任何命令行参数，你可以通过使用 Python 的`-m`命令行选项来解决这个问题，就像这样：

```py
python -m my_module.py

```

然而，如果您的模块确实接受命令行参数，那么您将需要替换相对导入，以避免出现这个问题。虽然有解决方法，但它们很笨拙，不建议一般使用。

# 总结

在本章中，我们深入了解了 Python 模块和包的工作原理。我们看到模块只是使用`import`语句导入的 Python 源文件，而包是由名为`__init__.py`的包初始化文件标识的 Python 源文件目录。我们了解到包可以定义在其他包内，形成嵌套包的树状结构。我们看了模块和包如何初始化，以及`import`语句如何以各种方式导入模块和包及其内容到您的程序中。

然后，我们看到了相对导入如何用于相对于包层次结构中的当前位置导入模块，以及`__all__`变量如何用于控制导入的内容。

然后，我们了解了循环依赖以及如何避免它们，最后学习了变色龙模块，它可以作为可导入的模块，也可以作为可以从命令行运行的独立程序。

在下一章中，我们将应用所学知识来设计和实现一个更复杂的程序，我们将看到对这些技术的深入理解将使我们能够构建一个健壮的系统，并能够根据不断变化的需求进行更新。
