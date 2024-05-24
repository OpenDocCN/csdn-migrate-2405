# Python GUI 编程（二）

> 原文：[`zh.annas-archive.org/md5/9d5f7126bd532a80dd6a9dce44175aaa`](https://zh.annas-archive.org/md5/9d5f7126bd532a80dd6a9dce44175aaa)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：规划我们应用程序的扩展

这个应用程序真的很受欢迎！经过一些初步测试和定位，数据录入人员现在已经使用您的新表单几个星期了。错误和数据输入时间的减少是显著的，人们对这个程序可能解决的其他问题充满了兴奋的讨论。即使主管也加入了头脑风暴，你强烈怀疑你很快就会被要求添加一些新功能。然而，有一个问题；这个应用程序已经是几百行的脚本了，你担心随着它的增长，它的可管理性。你需要花一些时间来组织你的代码库，为未来的扩展做准备。

在本章中，我们将学习以下主题：

+   如何使用**模型-视图-控制器**模式来分离应用程序的关注点

+   如何将代码组织成 Python 包

+   为您的包结构创建基本文件和目录

+   如何使用 Git 版本控制系统跟踪您的更改

# 分离关注点

适当的建筑设计对于任何需要扩展的项目都是至关重要的。任何人都可以支撑起一些支柱，建造一个花园棚屋，但是建造一座房子或摩天大楼需要仔细的规划和工程。软件也是一样的；简单的脚本可以通过一些快捷方式，比如全局变量或直接操作类属性来解决，但随着程序的增长，我们的代码需要以一种限制我们需要在任何给定时刻理解的复杂度的方式来隔离和封装不同的功能。

我们称之为**关注点的分离**，通过使用描述不同应用程序组件及其交互方式的架构模式来实现。

# MVC 模式

这些模式中最持久的可能是 MVC 模式，它是在 20 世纪 70 年代引入的。尽管这种模式多年来已经发展并衍生出各种变体，但基本的要点仍然是：将数据、数据的呈现和应用程序逻辑保持在独立的组件中。

让我们更深入地了解这些组件，并在我们的应用程序的上下文中理解它们。

# 什么是模型？

MVC 中的**模型**代表数据。这包括数据的存储，以及数据可以被查询或操作的各种方式。理想情况下，模型不关心或受到数据如何呈现或授予什么 UI 控件的影响，而是提供一个高级接口，只在最小程度上关注其他组件的内部工作。理论上，如果您决定完全更改程序的 UI（比如，从 Tkinter 应用程序到 Web 应用程序），模型应该完全不受影响。

模型中包含的功能或信息的一些示例包括以下内容：

+   准备并将程序数据写入持久介质（数据文件、数据库等）

+   从文件或数据库中检索数据并将其转换为程序有用的格式

+   一组数据中字段的权威列表，以及它们的数据类型和限制

+   根据定义的数据类型和限制验证数据

+   对存储的数据进行计算

我们的应用程序目前没有模型类；数据布局是在表单类中定义的，到目前为止，`Application.on_save()`方法是唯一关心数据持久性的代码。我们需要将这个逻辑拆分成一个单独的对象，该对象将定义数据布局并处理所有 CSV 操作。

# 什么是视图？

**视图**是向用户呈现数据和控件的接口。应用程序可能有许多视图，通常是在相同的数据上。视图不直接与模型交互，并且理想情况下只包含足够的逻辑来呈现 UI 并将用户操作传递回控制器。

在视图中找到的一些代码示例包括以下内容：

+   GUI 布局和小部件定义

+   表单自动化，例如字段的自动完成，小部件的动态切换，或错误对话框的显示

+   原始数据的格式化呈现

我们的`DataRecordForm`类是我们的主视图：它包含了我们应用程序用户界面的大部分代码。它还当前定义了我们数据记录的结构。这个逻辑可以留在视图中，因为视图确实需要一种在将数据临时传递给模型之前存储数据的方式，但从现在开始它不会再定义我们的数据记录。

随着我们继续前进，我们将向我们的应用程序添加更多视图。

# 什么是控制器？

**控制器**是应用程序的大中央车站。它处理用户的请求，并负责在视图和模型之间路由数据。MVC 的大多数变体都会改变控制器的角色（有时甚至是名称），但重要的是它充当视图和模型之间的中介。我们的控制器对象将需要保存应用程序使用的视图和模型的引用，并负责管理它们之间的交互。

在控制器中找到的代码示例包括以下内容：

+   应用程序的启动和关闭逻辑

+   用户界面事件的回调

+   模型和视图实例的创建

我们的`Application`对象目前充当着应用程序的控制器，尽管它也包含一些视图和模型逻辑。随着应用程序的发展，我们将把更多的展示逻辑移到视图中，将更多的数据逻辑移到模型中，留下的主要是连接代码在我们的`Application`对象中。

# 为什么要复杂化我们的设计？

最初，以这种方式拆分应用程序似乎会增加很多不必要的开销。我们将不得不在不同对象之间传输数据，并最终编写更多的代码来完成完全相同的事情。为什么我们要这样做呢？

简而言之，我们这样做是为了使扩展可管理。随着应用程序的增长，复杂性也会增加。将我们的组件相互隔离限制了任何一个组件需要管理的复杂性的数量；例如，当我们重新构造表单视图的布局时，我们不应该担心模型将如何在输出文件中结构化数据。程序的这两个方面应该彼此独立。

这也有助于我们在放置某些类型的逻辑时保持一致。例如，拥有一个独立的模型对象有助于我们避免在 UI 代码中散布临时数据查询或文件访问尝试。

最重要的是，如果没有一些指导性的架构策略，我们的程序很可能会变成一团无法解开的逻辑混乱。即使不遵循严格的 MVC 设计定义，始终遵循松散的 MVC 模式也会在应用程序变得更加复杂时节省很多麻烦。

# 构建我们的应用程序目录结构

将程序逻辑上分解为单独的关注点有助于我们管理每个组件的逻辑复杂性，将代码物理上分解为多个文件有助于我们保持每个文件的复杂性可管理。这也加强了组件之间的隔离；例如，您不能共享全局变量，如果您的模型文件导入了`tkinter`，那么您就知道您做错了什么。

# 基本目录结构

Python 应用程序目录布局没有官方标准，但有一些常见的约定可以帮助我们保持整洁，并且以后更容易打包我们的软件。让我们按照以下方式设置我们的目录结构：

1.  首先，创建一个名为`ABQ_Data_Entry`的目录。这是我们应用程序的**根目录**，所以每当我们提到**应用程序根目录**时，就是它。

1.  在应用程序根目录下，创建另一个名为`abq_data_entry`的目录。注意它是小写的。这将是一个 Python 包，其中将包含应用程序的所有代码；它应该始终被赋予一个相当独特的名称，以免与现有的 Python 包混淆。通常情况下，应用程序根目录和主模块之间不会有不同的大小写，但这也不会有任何问题；我们在这里这样做是为了避免混淆。

Python 模块的命名应始终使用全部小写的名称和下划线。这个约定在 PEP 8 中有详细说明，PEP 8 是 Python 的官方风格指南。有关 PEP 8 的更多信息，请参见[`www.python.org/dev/peps/pep-0008`](https://www.python.org/dev/peps/pep-0008)。

1.  接下来，在应用程序根目录下创建一个名为`docs`的文件夹。这个文件夹将用于存放关于应用程序的文档文件。

1.  最后，在应用程序根目录中创建两个空文件：`README.rst`和`abq_data_entry.py`。你的目录结构应该如下所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/830b3415-2492-4ad3-a86e-1e17b65c7a9b.png)

# abq_data_entry.py 文件

就像以前一样，`abq_data_entry.py`是执行程序的主文件。不过，与以前不同的是，它不会包含大部分的程序。实际上，这个文件应该尽可能地简化。

打开文件并输入以下代码：

```py
from abq_data_entry.application import Application

app = Application()
app.mainloop()
```

保存并关闭文件。这个文件的唯一目的是导入我们的`Application`类，创建一个实例，并运行它。其余的工作将在`abq_data_entry`包内进行。我们还没有创建这个包，所以这个文件暂时无法运行；在我们处理文档之前，让我们先处理一下文档。

# README.rst 文件

自上世纪 70 年代以来，程序一直包含一个名为`README`的简短文本文件，其中包含程序文档的简要摘要。对于小型程序，它可能是唯一的文档；对于大型程序，它通常包含用户或管理员的基本预先飞行指令。

`README`文件没有规定的内容集，但作为基本指南，考虑以下部分：

+   **描述**：程序及其功能的简要描述。我们可以重用规格说明中的描述，或类似的描述。这可能还包含主要功能的简要列表。

+   **作者信息**：作者的姓名和版权日期。如果你计划分享你的软件，这一点尤为重要，但即使对于公司内部的软件，让未来的维护者知道谁创建了软件以及何时创建也是有用的。

+   **要求**：软件和硬件要求的列表，如果有的话。

+   **安装**：安装软件、先决条件、依赖项和基本设置的说明。

+   **配置**：如何配置应用程序以及有哪些选项可用。这通常针对命令行或配置文件选项，而不是在程序中交互设置的选项。

+   **用法**：启动应用程序的描述，命令行参数和用户需要了解的其他注意事项。

+   **一般注意事项**：用户应该知道的注意事项或关键信息。

+   **错误**：应用程序中已知的错误或限制的列表。

并不是所有这些部分都适用于每个程序；例如，ABQ 数据输入目前没有任何配置选项，所以没有理由有一个配置部分。根据情况，你可能会添加其他部分；例如，公开分发的软件可能会有一个常见问题解答部分，或者开源软件可能会有一个包含如何提交补丁的贡献部分。

`README`文件以纯 ASCII 或 Unicode 文本编写，可以是自由格式的，也可以使用标记语言。由于我们正在进行一个 Python 项目，我们将使用 reStructuredText，这是 Python 文档的官方标记语言（这就是为什么我们的文件使用`rst`文件扩展名）。

# ReStructuredText

reStructuredText 标记语言是 Python `docutils`项目的一部分，完整的参考资料可以在 Docutils 网站找到：[`docutils.sourceforge.net`](http://docutils.sourceforge.net)。`docutils`项目还提供了将 RST 转换为 PDF、ODT、HTML 和 LaTeX 等格式的实用程序。

基础知识可以很快掌握，所以让我们来看看它们：

+   段落是通过在文本块之间留下一个空行来创建的。

+   标题通过用非字母数字符号下划线单行文本来创建。确切的符号并不重要；你首先使用的符号将被视为文档其余部分的一级标题，你其次使用的符号将被视为二级标题，依此类推。按照惯例，`=`通常用于一级，`-`用于二级，`~`用于三级，`+`用于四级。

+   标题和副标题的创建方式与标题相似，只是在上下都有一行符号。

+   项目列表是通过在行首加上`*`、`-`或`+`和一个空格来创建的。切换符号将创建子列表，多行点由将后续行缩进到文本从第一个项目符号开始的位置来创建。

+   编号列表的创建方式与项目列表相似，但使用数字（不需要正确排序）或`#`符号作为项目符号。

+   代码示例可以通过用双反引号字符括起来来指定内联(`` ` ``)，或者在一个代码块中，用双冒号结束一个引入行，并缩进代码块。
+   表格可以通过用 `=` 符号包围文本列，并用空格分隔表示列断点，或者通过使用 `|`、`-` 和 `+` 构建 ASCII 表格来创建。在纯文本编辑器中创建表格可能会很繁琐，但一些编程工具有插件可以生成 RST 表格。

我们已经在第二章中使用了 RST，*用 Tkinter 设计 GUI 应用程序*，来创建我们的程序规范；在那里，您看到了标题、头部、项目符号和表格的使用。让我们逐步创建我们的 `README.rst` 文件：

1.  打开文件并以以下方式开始标题和描述：

```py
============================
 ABQ Data Entry Application
============================

Description
===========

This program provides a data entry form for ABQ Agrilabs laboratory data.

Features
--------

* Provides a validated entry form to ensure correct data
* Stores data to ABQ-format CSV files
* Auto-fills form fields whenever possible

```

1.  接下来，我们将通过添加以下代码来列出作者：

```py
Authors
=======

Alan D Moore, 2018

```

当然要添加自己。最终，其他人可能会在您的应用程序上工作；他们应该在这里加上他们的名字以及他们工作的日期。现在，添加以下要求：

```py

Requirements
============

* Python 3
* Tkinter

```

目前，我们只需要 Python 3 和 Tkinter，但随着我们的应用程序的增长，我们可能会扩展这个列表。我们的应用程序实际上不需要被安装，并且没有配置选项，所以现在我们可以跳过这些部分。相反，我们将跳到 `使用方法` 如下：

```py

Usage
=====

To start the application, run::

  python3 ABQ_Data_Entry/abq_data_entry.py

```

除了这个命令之外，关于运行程序没有太多需要了解的东西；没有命令行开关或参数。我们不知道任何错误，所以我们将在末尾留下一些一般的说明，如下所示：

```py
General Notes
=============

The CSV file will be saved to your current directory in the format "abq_data_record_CURRENTDATE.csv", where CURRENTDATE is today's date in ISO format.

This program only appends to the CSV file.  You should have a spreadsheet program installed in case you need to edit or check the file.


```

现在告诉用户文件将被保存在哪里以及它将被命名为什么，因为这是硬编码到程序中的。此外，我们应该提到用户应该有某种电子表格，因为程序无法编辑或查看数据。这就完成了 `README.rst` 文件。保存它，然后我们继续到 `docs` 文件夹。

# 填充文档文件夹

`docs` 文件夹是用于存放文档的地方。这可以是任何类型的文档：用户手册、程序规范、API 参考、图表等等。

现在，您可以复制我们在前几章中编写的程序规范、您的界面模型和技术人员使用的表单的副本。

在某个时候，您可能需要编写一个用户手册，但是现在程序足够简单，不需要它。

# 制作一个 Python 包

创建自己的 Python 包其实非常简单。一个 Python 包由以下三个部分组成：

+   一个目录

+   那个目录中的一个或多个 Python 文件

+   目录中的一个名为 `__init__.py` 的文件

一旦完成这一步，您可以整体或部分地导入您的包，就像导入标准库包一样，只要您的脚本与包目录在同一个父目录中。

注意，模块中的 `__init__.py` 有点类似于类中的 `self.__init__()`。其中的代码将在包被导入时运行。Python 社区一般不鼓励在这个文件中放置太多代码，而且由于实际上不需要任何代码，我们将保持此文件为空。

让我们开始构建我们应用程序的包。在`abq_data_entry`下创建以下六个空文件：

+   `__init__.py`

+   `widgets.py`

+   `views.py`

+   `models.py`

+   `application.py`

+   `constants.py`

这些 Python 文件中的每一个都被称为一个**模块**。模块只是一个包目录中的 Python 文件。您的目录结构现在应该是这样的：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/06efc903-784c-426e-be9b-ddeb66de7849.png)

此时，您已经有了一个工作的包，尽管里面没有实际的代码。要测试这个，请打开一个终端/命令行窗口，切换到您的`ABQ_Data_Entry`目录，并启动一个 Python shell。

现在，输入以下命令：

```py

from abq_data_entry import application

```

这应该可以正常工作。当然，它什么也不做，但我们接下来会解决这个问题。

不要将此处的“包”一词与实际的可分发的 Python 包混淆，比如使用`pip`下载的那些。

# 将我们的应用程序拆分成多个文件

现在我们的目录结构已经就绪，我们需要开始解剖我们的应用程序脚本，并将其分割成我们的模块文件。我们还需要创建我们的模型类。打开您从第四章*减少用户错误：验证和自动化*中的`abq_data_entry.py`文件，让我们开始吧！

# 创建模型模块

当您的应用程序完全关注数据时，最好从模型开始。记住，模型的工作是管理我们应用程序数据的存储、检索和处理，通常是关于其持久存储格式的（在本例中是 CSV）。为了实现这一点，我们的模型应该包含关于我们数据的所有知识。

目前，我们的应用程序没有类似模型的东西；关于应用程序数据的知识散布在表单字段中，而`Application`对象只是在请求保存操作时获取表单包含的任何数据，并直接将其塞入 CSV 文件中。由于我们还没有检索或更新信息，所以我们的应用程序对 CSV 文件中的内容一无所知。

为了将我们的应用程序转移到 MVC 架构，我们需要创建一个模型类，它既管理数据存储和检索，又代表我们数据的权威来源。换句话说，我们必须在这里编码我们数据字典中包含的知识。我们真的不知道我们将如何使用这些知识，但它们应该在这里。

我们可以以几种方式存储这些数据，例如创建一个自定义字段类或一个`namedtuple`对象，但现在我们将保持简单，只使用一个字典，将字段名称映射到字段元数据。

字段元数据将同样被存储为关于字段的属性字典，其中将包括：

+   字段是否必填

+   字段中存储的数据类型

+   可能值的列表（如果适用）

+   值的最小、最大和增量（如果适用）

要为每个字段存储数据类型，让我们定义一些数据类型。打开`constants.py`文件并添加以下代码：

```py

class FieldTypes:
    string = 1
    string_list = 2
    iso_date_string = 3
    long_string = 4
    decimal = 5
    integer = 6
    boolean = 7

```

我们创建了一个名为`FieldTypes`的类，它简单地存储一些命名的整数值，这些值将描述我们将要存储的不同类型的数据。我们可以在这里只使用 Python 类型，但是区分一些可能是相同 Python 类型的数据类型是有用的（例如`long`、`short`和`date`字符串）。请注意，这里的整数值基本上是无意义的；它们只需要彼此不同。

Python 3 有一个`Enum`类，我们可以在这里使用它，但在这种情况下它添加的功能非常少。如果您正在创建大量常量，比如我们的`FieldTypes`类，并且需要额外的功能，可以研究一下这个类。

现在打开`models.py`，我们将导入`FieldTypes`并创建我们的模型类和字段定义如下：

```py

import csv
import os
from .constants import FieldTypes as FT

class CSVModel:
    """CSV file storage"""
    fields = {
        "Date": {'req': True, 'type': FT.iso_date_string},
        "Time": {'req': True, 'type': FT.string_list,
                 'values': ['8:00', '12:00', '16:00', '20:00']},
        "Technician": {'req': True, 'type':  FT.string},
        "Lab": {'req': True, 'type': FT.string_list,
                'values': ['A', 'B', 'C', 'D', 'E']},
        "Plot": {'req': True, 'type': FT.string_list,
                 'values': [str(x) for x in range(1, 21)]},
        "Seed sample":  {'req': True, 'type': FT.string},
        "Humidity": {'req': True, 'type': FT.decimal,
                     'min': 0.5, 'max': 52.0, 'inc': .01},
        "Light": {'req': True, 'type': FT.decimal,
                  'min': 0, 'max': 100.0, 'inc': .01},
        "Temperature": {'req': True, 'type': FT.decimal,
                        'min': 4, 'max': 40, 'inc': .01},
        "Equipment Fault": {'req': False, 'type': FT.boolean},
        "Plants": {'req': True, 'type': FT.integer,
                   'min': 0, 'max': 20},
        "Blossoms": {'req': True, 'type': FT.integer,
                     'min': 0, 'max': 1000},
        "Fruit": {'req': True, 'type': FT.integer,
                  'min': 0, 'max': 1000},
        "Min Height": {'req': True, 'type': FT.decimal,
                       'min': 0, 'max': 1000, 'inc': .01},
        "Max Height": {'req': True, 'type': FT.decimal,
                       'min': 0, 'max': 1000, 'inc': .01},
        "Median Height": {'req': True, 'type': FT.decimal,
                          'min': 0, 'max': 1000, 'inc': .01},
        "Notes": {'req': False, 'type': FT.long_string}
    }
```

注意我们导入`FieldTypes`的方式：`from .constants import FieldTypes`。点号在`constants`前面使其成为**相对导入**。相对导入可在 Python 包内部用于定位同一包中的其他模块。在这种情况下，我们位于`models`模块中，需要访问`abq_data_entry`包内的`constants`模块。单个点号表示我们当前的父模块（`abq_data_entry`），因此`.constants`表示`abq_data_entry`包的`constants`模块。

相对导入还可以区分我们的自定义模块与`PYTHONPATH`中的模块。因此，我们不必担心任何第三方或标准库包与我们的模块名称冲突。

除了字段属性之外，我们还在这里记录字段的顺序。在 Python 3.6 及更高版本中，字典会保留它们定义的顺序；如果您使用的是较旧版本的 Python 3，则需要使用`collections`标准库模块中的`OrderedDict`类来保留字段顺序。

现在我们有了一个了解哪些字段需要存储的类，我们需要将保存逻辑从应用程序类迁移到模型中。

我们当前脚本中的代码如下：

```py

datestring = datetime.today().strftime("%Y-%m-%d")
filename = "abq_data_record_{}.csv".format(datestring)
newfile = not os.path.exists(filename)

data = self.recordform.get()

with open(filename, 'a') as fh:
    csvwriter = csv.DictWriter(fh, fieldnames=data.keys())
    if newfile:
        csvwriter.writeheader()
    csvwriter.writerow(data)
```

让我们通过这段代码确定什么属于模型，什么属于控制器（即`Application`类）：

+   前两行定义了我们要使用的文件名。这可以放在模型中，但是提前思考，似乎用户可能希望能够打开任意文件或手动定义文件名。这意味着应用程序需要能够告诉模型要使用哪个文件名，因此最好将确定名称的逻辑留在控制器中。

+   `newfile`行确定文件是否存在。作为数据存储介质的实现细节，这显然是模型的问题，而不是应用程序的问题。

+   `data = self.recordform.get()`从表单中提取数据。由于我们的模型不知道表单的存在，这需要留在控制器中。

+   最后一块打开文件，创建一个`csv.DictWriter`对象，并追加数据。这明显是模型的关注点。

现在，让我们开始将代码移入`CSVModel`类：

1.  要开始这个过程，让我们为`CSVModel`创建一个允许我们传入文件名的构造函数：

```py
    def __init__(self, filename):
        self.filename = filename
```

构造函数非常简单；它只接受一个`filename`参数并将其存储为一个属性。现在，我们将迁移保存逻辑如下：

```py

    def save_record(self, data):
        """Save a dict of data to the CSV file"""

        newfile = not os.path.exists(self.filename)

        with open(self.filename, 'a') as fh:
            csvwriter = csv.DictWriter(fh, 
                fieldnames=self.fields.keys())
            if newfile:
                csvwriter.writeheader()
            csvwriter.writerow(data)
```

这本质上是我们选择从`Application.on_save()`中复制的逻辑，但有一个区别；在对`csv.DictWriter()`的调用中，`fieldnames` 参数由模型的`fields`列表而不是`data`字典的键定义。这允许我们的模型管理 CSV 文件本身的格式，并不依赖于表单提供的内容。

1.  在我们完成之前，我们需要处理我们的模块导入。`save_record()`方法使用`os`和`csv`库，所以我们需要导入它们。将此添加到文件顶部如下：

```py

import csv
import os

```

模型就位后，让我们开始处理我们的视图组件。

# 移动小部件

虽然我们可以将所有与 UI 相关的代码放在一个`views`文件中，但我们有很多小部件类，实际上应该将它们放在自己的文件中，以限制`views`文件的复杂性。

因此，我们将所有小部件类的代码移动到`widgets.py`文件中。小部件包括实现可重用 GUI 组件的所有类，包括`LabelInput`等复合小部件。随着我们开发更多的这些，我们将把它们添加到这个文件中。

打开`widgets.py`并复制`ValidatedMixin`、`DateInput`、`RequiredEntry`、`ValidatedCombobox`、`ValidatedSpinbox`和`LabelInput`的所有代码。这些是我们的小部件。

`widgets.py` 文件需要导入被复制代码使用的任何模块依赖项。我们需要查看我们的代码，并找出我们使用的库并将它们导入。显然，我们需要`tkinter`和`ttk`，所以在顶部添加它们如下：

```py
import tkinter as tk
from tkinter import ttk
```

我们的`DateInput` 类使用`datetime`库中的`datetime`类，因此也要导入它，如下所示：

```py

from datetime import datetime

```

最后，我们的`ValidatedSpinbox` 类使用`decimal`库中的`Decimal`类和`InvalidOperation`异常，如下所示：

```py

from decimal import Decimal, InvalidOperation

```

这是现在我们在`widgets.py`中需要的全部，但是当我们重构我们的视图逻辑时，我们会再次访问这个文件。

# 移动视图

接下来，我们需要创建`views.py`文件。视图是较大的 GUI 组件，如我们的`DataRecordForm`类。目前它是我们唯一的视图，但我们将在后面的章节中创建更多的视图，并将它们添加到这里。

打开`views.py`文件，复制`DataRecordForm`类，然后返回顶部处理模块导入。同样，我们需要`tkinter`和`ttk`，我们的文件保存逻辑依赖于`datetime`以获得文件名。

将它们添加到文件顶部如下：

```py

import tkinter as tk
from tkinter import ttk
from datetime import datetime

```

不过，我们还没有完成；我们实际的小部件还没有，我们需要导入它们。由于我们将在文件之间进行大量对象导入，让我们暂停一下，考虑一下处理这些导入的最佳方法。

我们可以导入对象的三种方式：

+   使用通配符导入从`widgets.py`中导入所有类

+   使用`from ... import ...`格式明确地从`widgets.py`中导入所有所需的类

+   导入`widgets`并将我们的小部件保留在它们自己的命名空间中

让我们考虑一下这些方法的相对优点：

+   第一个选项是迄今为止最简单的，但随着应用程序的扩展，它可能会给我们带来麻烦。通配符导入将会导入模块内在全局范围内定义的每个名称。这不仅包括我们定义的类，还包括任何导入的模块、别名和定义的变量或函数。随着应用程序在复杂性上的扩展，这可能会导致意想不到的后果和微妙的错误。

+   第二个选项更清晰，但意味着我们将需要维护导入列表，因为我们添加新类并在不同文件中使用它们，这导致了一个长而丑陋的导入部分，难以让人理解。

+   第三种选项是目前为止最好的，因为它将所有名称保留在命名空间内，并保持代码优雅简单。唯一的缺点是我们需要更新我们的代码，以便所有对小部件类的引用都包含模块名称。为了避免这变得笨拙，让我们将`widgets`模块别名为一个简短的名字，比如`w`。

将以下代码添加到你的导入中：

```py

from . import widgets as w

```

现在，我们只需要遍历代码，并在所有`LabelInput`、`RequiredEntry`、`DateEntry`、`ValidatedCombobox`和`ValidatedSpinbox`的实例之前添加`w.`。这应该很容易在 IDLE 或任何其他文本编辑器中使用一系列搜索和替换操作来完成。

例如，表单的`line 1`如下所示：

```py

# line 1
self.inputs['Date'] = w.LabelInput(
    recordinfo, "Date",
    input_class=w.DateEntry,
    input_var=tk.StringVar()
)
self.inputs['Date'].grid(row=0, column=0)
self.inputs['Time'] = w.LabelInput(
    recordinfo, "Time",
    input_class=w.ValidatedCombobox,
    input_var=tk.StringVar(),
    input_args={"values": ["8:00", "12:00", "16:00", "20:00"]}
)
self.inputs['Time'].grid(row=0, column=1)
self.inputs['Technician'] = w.LabelInput(
    recordinfo, "Technician",
    input_class=w.RequiredEntry,
    input_var=tk.StringVar()
)
self.inputs['Technician'].grid(row=0, column=2)
```

在你到处更改之前，让我们停下来，花一点时间重构这段代码中的一些冗余。

# 在我们的视图逻辑中消除冗余

查看视图逻辑中的字段定义：它们包含了很多与我们的模型中的信息相同的信息。最小值、最大值、增量和可能值在这里和我们的模型代码中都有定义。甚至输入小部件的类型直接与存储的数据类型相关。理想情况下，这应该只在一个地方定义，而且那个地方应该是模型。如果我们因为某种原因需要更新模型，我们的表单将不同步。

我们需要做的是将字段规范从我们的模型传递到视图类，并让小部件的详细信息从该规范中定义。

由于我们的小部件实例是在`LabelInput`类内部定义的，我们将增强该类的功能，以自动从我们模型的字段规范格式中计算出`input`类和参数。打开`widgets.py`文件，并像在`model.py`中一样导入`FieldTypes`类。

现在，找到`LabelInput`类，并在`__init__()`方法之前添加以下代码：

```py

    field_types = {
        FT.string: (RequiredEntry, tk.StringVar),
        FT.string_list: (ValidatedCombobox, tk.StringVar),
        FT.iso_date_string: (DateEntry, tk.StringVar),
        FT.long_string: (tk.Text, lambda: None),
        FT.decimal: (ValidatedSpinbox, tk.DoubleVar),
        FT.integer: (ValidatedSpinbox, tk.IntVar),
        FT.boolean: (ttk.Checkbutton, tk.BooleanVar)
    }

```

这段代码充当了将我们模型的字段类型转换为适合字段类型的小部件类型和变量类型的关键。

现在，我们需要更新`__init__()`，接受一个`field_spec`参数，并在给定时使用它来定义输入小部件，如下所示：

```py

    def __init__(self, parent, label='', input_class=None,
         input_var=None, input_args=None, label_args=None,
         field_spec=None, **kwargs):
        super().__init__(parent, **kwargs)
        input_args = input_args or {}
        label_args = label_args or {}
        if field_spec:
            field_type = field_spec.get('type', FT.string)
            input_class = input_class or 
            self.field_types.get(field_type)[0]
            var_type = self.field_types.get(field_type)[1]
            self.variable = input_var if input_var else var_type()
            # min, max, increment
            if 'min' in field_spec and 'from_' not in input_args:
                input_args['from_'] = field_spec.get('min')
            if 'max' in field_spec and 'to' not in input_args:
                input_args['to'] = field_spec.get('max')
            if 'inc' in field_spec and 'increment' not in input_args:
                input_args['increment'] = field_spec.get('inc')
            # values
            if 'values' in field_spec and 'values' not in input_args:
                input_args['values'] = field_spec.get('values')
        else:
            self.variable = input_var
        if input_class in (ttk.Checkbutton, ttk.Button, ttk.Radiobutton):
            input_args["text"] = label
            input_args["variable"] = self.variable
        else:
            self.label = ttk.Label(self, text=label, **label_args)
            self.label.grid(row=0, column=0, sticky=(tk.W + tk.E))
            input_args["textvariable"] = self.variable
        # ... Remainder of __init__() is the same
```

让我们逐步解析这些更改：

1.  首先，我们将`field_spec`添加为一个关键字参数，并将`None`作为默认值。我们可能会在没有字段规范的情况下使用这个类，所以我们保持这个参数是可选的。

1.  如果给出了`field_spec`，我们将执行以下操作：

    +   我们将获取`type`值，并将其与我们类的字段键一起使用以获取`input_class`。如果我们想要覆盖这个值，显式传递的`input_class`将覆盖检测到的值。

    +   我们将以相同的方式确定适当的变量类型。再次，如果显式传递了`input_var`，我们将优先使用它，否则我们将使用从字段类型确定的那个。我们将以任何方式创建一个实例，并将其存储在`self.variable`中。

    +   对于`min`、`max`、`inc`和`values`，如果字段规范中存在键，并且相应的`from_`、`to`、`increment`或`values`参数没有显式传递进来，我们将使用`field_spec`值设置`input_args`变量。

1.  如果没有传入`field_spec`，我们需要将`self.variable`从`input_var`参数中赋值。

1.  现在我们使用`self.variable`而不是`input_var`来分配输入的变量，因为这些值可能不再是相同的，而`self.variable`将包含正确的引用。

现在，我们可以更新我们的视图代码以利用这种新的能力。我们的`DataRecordForm`类将需要访问模型的`fields`字典，然后可以使用它将字段规范发送到`LabelInput`类。

回到`views.py`文件，在方法签名中编辑，以便我们可以传入字段规范的字典：

```py

def __init__(self, parent, fields, *args, **kwargs):

```

有了对`fields`字典的访问权限，我们只需从中获取字段规范，并将其传递到`LabelInput`类中，而不是指定输入类、输入变量和输入参数。

现在，第一行看起来是这样的：

```py

        self.inputs['Date'] = w.LabelInput(
            recordinfo, "Date",
            field_spec=fields['Date'])
        self.inputs['Date'].grid(row=0, column=0)
        self.inputs['Time'] = w.LabelInput(
            recordinfo, "Time",
            field_spec=fields['Time'])
        self.inputs['Time'].grid(row=0, column=1)
        self.inputs['Technician'] = w.LabelInput(
            recordinfo, "Technician",
            field_spec=fields['Technician'])
        self.inputs['Technician'].grid(row=0, column=2)
```

继续以相同的方式更新其余的小部件，用`field_spec`替换`input_class`、`input_var`和`input_args`。请注意，当您到达高度字段时，您将需要保留定义`min_var`、`max_var`和`focus_update_var`的`input_args`部分。

例如，以下是`Min Height`输入的定义：

```py

        self.inputs['Min Height'] = w.LabelInput(
            plantinfo, "Min Height (cm)",
            field_spec=fields['Min Height'],
            input_args={"max_var": max_height_var,
                        "focus_update_var": min_height_var})
```

就这样。现在，我们对字段规范的任何更改都可以仅在模型中进行，并且表单将简单地执行正确的操作。

# 创建应用程序文件

最后，让我们按照以下步骤创建我们的控制器类`Application`：

1.  打开`application.py`文件，并将脚本中的`Application`类定义复制进去。

1.  首先，我们要修复的是我们的导入项。在文件顶部添加以下代码：

```py

import tkinter as tk
from tkinter import ttk
from datetime import datetime
from . import views as v
from . import models as m
```

当然，我们需要`tkinter`和`ttk`，以及`datetime`来定义我们的文件名。虽然我们只需要从`views`和`models`中各自选择一个类，但我们还是要将它们保留在各自的命名空间中。随着应用程序的扩展，我们可能会有更多的视图，可能还会有更多的模型。

1.  我们需要更新在新命名空间中`__init__()`中对`DataRecordForm`的调用，并确保我们传递所需的字段规范字典，如下所示：

```py

self.recordform = v.DataRecordForm(self, m.CSVModel.fields)

```

1.  最后，我们需要更新`Application.on_save()`以使用模型，如下所示：

```py

    def on_save(self):
        """Handles save button clicks"""

        errors = self.recordform.get_errors()
        if errors:
            self.status.set(
                "Cannot save, error in fields: {}"
                .format(', '.join(errors.keys())))
            return False

        # For now, we save to a hardcoded filename 
        with a datestring.
        datestring = datetime.today().strftime("%Y-%m-%d")
        filename = "abq_data_record_{}.csv".format(datestring)
        model = m.CSVModel(filename)
        data = self.recordform.get()
        model.save_record(data)
        self.records_saved += 1
        self.status.set(
            "{} records saved this session".
            format(self.records_saved)
        )
        self.recordform.reset()
```

正如您所看到的，使用我们的模型非常简单；我们只需通过传递文件名创建了一个`CSVModel`类，然后将表单的数据传递给`save_record()`。

# 运行应用程序

应用程序现在完全迁移到了新的数据格式。要测试它，请导航到应用程序根文件夹`ABQ_Data_Entry`，然后执行以下命令：

```py

python3 abq_data_entry.py

```

它应该看起来和行为就像第四章中的单个脚本*通过验证和自动化减少用户错误*一样，并且在下面的截图中运行无错误：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/4151fc4d-d11b-4bf1-a5a3-df5ab3971dca.png)

成功！

# 使用版本控制软件

我们的代码结构良好，可以扩展，但是还有一个非常关键的问题我们应该解决：**版本控制**。您可能已经熟悉了**版本控制系统**（**VCS**），有时也称为**修订控制**或**源代码管理**，但如果不了解，它是处理大型和不断变化的代码库的不可或缺的工具。

在开发应用程序时，我们有时会认为自己知道需要更改什么，但事实证明我们错了。有时我们不完全知道如何编写某些代码，需要多次尝试才能找到正确的方法。有时我们需要恢复到很久之前更改过的代码。有时我们有多个人在同一段代码上工作，需要将他们的更改合并在一起。版本控制系统就是为了解决这些问题以及更多其他问题而创建的。

有数十种不同的版本控制系统，但它们大多数本质上都是相同的：

+   您有一个可用于进行更改的代码副本

+   您定期选择要提交回主副本的更改

+   您可以随时查看代码的旧版本，然后恢复到主副本

+   您可以创建代码分支来尝试不同的方法、新功能或大型重构

+   您随后可以将这些分支合并回主副本

VCS 提供了一个安全网，让您可以自由更改代码，而无需担心您会彻底毁坏它：返回到已知的工作状态只需几个快速的命令即可。它还帮助我们记录代码的更改，并在机会出现时与他人合作。

有数十种 VC 系统可供选择，但迄今为止，远远最流行的是**Git**。

# 使用 Git 的超快速指南

Git 是由 Linus Torvalds 创建的，用于 Linux 内核项目的版本控制软件，并且已经发展成为世界上最流行的 VC 软件。它被源代码共享网站如 GitHub、Bitbucket、SourceForge 和 GitLab 使用。Git 非常强大，掌握它可能需要几个月或几年；幸运的是，基础知识可以在几分钟内掌握。

首先，您需要安装 Git；访问[`git-scm.com/downloads`](https://git-scm.com/downloads)获取有关如何在 macOS、Windows、Linux 或其他 Unix 操作系统上安装 Git 的说明。

# 初始化和配置 Git 仓库

安装完 Git 后，我们需要通过以下步骤初始化和配置我们的项目目录为一个 Git 仓库：

1.  在应用程序的根目录（`ABQ_Data_Entry`）中运行以下命令：

```py

git init

```

此命令在我们项目根目录下创建一个名为`.git`的隐藏目录，并使用构成仓库的基本文件对其进行初始化。`.git`目录将包含关于我们保存的修订的所有数据和元数据。

1.  在我们添加任何文件到仓库之前，我们需要告诉 Git 忽略某些类型的文件。例如，Python 在执行文件时会创建字节码（`.pyc`）文件，我们不希望将这些文件保存为我们代码的一部分。为此，请在您的项目根目录中创建一个名为`.gitignore`的文件，并在其中放入以下行：

```py

*.pyc
__pycache__/

```

# 添加和提交代码

现在我们的仓库已经初始化，我们可以使用以下命令向我们的 Git 仓库添加文件和目录：

```py

git add abq_data_entry
git add abq_data_entry.py
git add docs
git add README.rst

```

此时，我们的文件已经准备就绪，但尚未提交到仓库。您可以随时输入`git status`来检查仓库及其中的文件的状态。

你应该得到以下输出：

```py

On branch master

No commits yet

Changes to be committed:
  (use "git rm --cached <file>..." to unstage)

    new file:   README.rst
    new file:   abq_data_entry.py
    new file:   abq_data_entry/__init__.py
    new file:   abq_data_entry/application.py
    new file:   abq_data_entry/models.py
    new file:   abq_data_entry/views.py
    new file:   abq_data_entry/widgets.py
    new file:   docs/Application_layout.png
    new file:   docs/abq_data_entry_spec.rst
    new file:   docs/lab-tech-paper-form.png

Untracked files:
  (use "git add <file>..." to include in what will be committed)

    .gitignore
```

这向您展示了`abq_data_entry`和`docs`下的所有文件以及您直接指定的文件都已经准备好提交到仓库中。

让我们继续提交更改，如下所示：

```py

git commit -m "Initial commit"

```

这里的`-m`标志传入了一个提交消息，该消息将与提交一起存储。每次向仓库提交代码时，您都需要编写一条消息。您应该尽可能使这些消息有意义，详细说明您所做的更改以及背后的原因。

# 查看和使用我们的提交

要查看仓库的历史记录，请运行以下`git log`命令：

```py

alanm@alanm-laptop:~/ABQ_Data_Entry$ git log
commit df48707422875ff545dc30f4395f82ad2d25f103 (HEAD -> master)
Author: Alan Moore <alan@example.com>
Date:   Thu Dec 21 18:12:17 2017 -0600

    Initial commit


```

正如您所看到的，我们上次提交的`作者`、`日期`和`提交`消息都显示出来。如果我们有更多的提交，它们也会在这里列出，从最新到最旧。您在输出的第一行中看到的长十六进制值是**提交哈希**，这是一个唯一的值，用于标识提交。这个值可以用来在其他操作中引用提交。

例如，我们可以使用它将我们的存储库重置到过去的状态，如下所示：

1.  删除`README.rst`文件，并验证它已完全消失。

1.  现在，输入命令`git reset --hard df48707`，将`df48707`替换为您提交哈希的前七个字符。

1.  再次检查您的文件清单：`README.rst`文件已经回来了。

这里发生的是我们改变了我们的存储库，然后告诉 Git 将存储库的状态硬重置到我们的第一个提交。如果您不想重置您的存储库，您也可以暂时检出一个旧的提交，或者使用特定的提交作为基础创建一个分支。正如您已经看到的，这为我们提供了一个强大的实验安全网；无论您如何调整代码，任何提交都只是一个命令的距离！

Git 有许多更多的功能超出了本书的范围。如果您想了解更多信息，Git 项目在[`git-scm.com/book`](https://git-scm.com/book)提供了免费的在线手册，您可以在那里了解分支和设置远程存储库等高级功能。目前，重要的是在进行更改时提交更改，以便保持您的安全网并记录更改的历史。

# 总结

在本章中，您学会了为您的简单脚本做一些严肃的扩展准备。您学会了如何将应用程序的职责领域划分为单独的组件，以及如何将代码分割成单独的模块。您学会了如何使用 reStructuredText 记录代码并使用版本控制跟踪所有更改。

在下一章中，我们将通过实现一些新功能来测试我们的新项目布局。您将学习如何使用 Tkinter 的应用程序菜单小部件，如何实现文件打开和保存，以及如何使用消息弹出窗口来警告用户或确认操作。

# 第六章：使用 Menu 和 Tkinter 对话框创建菜单

随着应用程序的增长，组织对其功能的访问变得越来越重要。传统上，应用程序通过**菜单系统**来解决这个问题，通常位于应用程序窗口的顶部或（在某些平台上）全局桌面菜单中。虽然这些菜单是特定于应用程序的，但已经制定了一些组织惯例，我们应该遵循以使我们的软件更加用户友好。

在本章中，我们将涵盖以下主题：

+   分析一些报告的问题并决定解决方案

+   探索一些 Tkinter 的对话框类，并使用它们来实现常见菜单功能

+   学习如何使用 Tkinter 的 Menu 小部件，并使用它为我们的应用程序创建菜单

+   为我们的应用程序创建一些选项并将它们保存到磁盘

# 解决我们应用程序中的问题

您的老板给您带来了需要在您的应用程序中解决的第一组问题。首先，在无法在第二天之前输入当天最后的报告的情况下，文件名中的硬编码日期字符串是一个问题。数据输入人员需要一种手动选择要追加的文件的方法。

此外，数据输入人员对表单中的自动填充功能有不同的看法。有些人觉得这非常有帮助，但其他人真的希望看到它被禁用。您需要一种允许用户打开和关闭此功能的方法。

最后，一些用户很难注意到底部状态栏的文本，并希望应用程序在由于错误而无法保存数据时更加显眼。

# 决定如何解决这些问题

很明显，您需要实现一种选择文件和切换表单自动填充功能的方法。首先，您考虑只向主应用程序添加这两个控件，并进行快速的模拟：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/b7aaf697-23dc-40a6-8c42-0e8c13ba42d7.png)

您很快就会意识到这不是一个很好的设计，当然也不是一个能够适应增长的设计。您的用户不想盲目地在框中输入文件路径和文件名，也不想让很多额外的字段混乱 UI。

幸运的是，Tkinter 提供了一些工具，可以帮助我们解决这些问题：

+   **文件对话框**：Tkinter 的`filedialog`库将帮助简化文件选择

+   **错误对话框**：Tkinter 的`messagebox`库将让我们更加显眼地显示错误消息

+   **主菜单**：Tkinter 的`Menu`类可以帮助我们组织常见功能，以便轻松访问

# 实现简单的 Tkinter 对话框

状态栏适用于不应中断用户工作流程的偶发信息，但对于阻止工作按预期继续的错误，用户应该以更有力的方式受到警告。一个中断程序直到通过鼠标点击确认的**错误对话框**是相当有力的，似乎是解决用户看不到错误的问题的好方法。为了实现这些，您需要了解 Tkinter 的`messagebox`库。

# Tkinter messagebox

在 Tkinter 中显示简单对话框的最佳方法是使用`tkinter.messagebox`库，其中包含几个方便的函数，允许您快速创建常见的对话框类型。每个函数显示一个预设的图标和一组按钮，带有您指定的消息和详细文本，并根据用户点击的按钮返回一个值。

以下表格显示了一些`messagebox`函数及其图标和返回值：

| **函数** | **图标** | **按钮** / **返回值** |
| --- | --- | --- |
| `askokcancel` | 问题 | 确定 (`True`), 取消 (`False`) |
| `askretrycancel` | 警告 | 重试 (`True`), 取消 (`False`) |
| `askyesno` | 问题 | 是 (`True`), 否 (`False`) |
| `askyesnocancel` | 问题 | 是 (`True`), 否 (`False`), 取消 (`None`) |
| `showerror` | 错误 | 确定 (`ok`) |
| `showinfo` | 信息 | 确定（`ok`） |
| `showwarning` | 警告 | 确定（`ok`） |

我们可以将以下三个文本参数传递给任何`messagebox`函数：

+   `title`：此参数设置窗口的标题，在您的桌面环境中显示在标题栏和/或任务栏中。

+   `message`：此参数设置对话框的主要消息。通常使用标题字体，应保持相当简短。

+   `detail`：此参数设置对话框的正文文本，通常显示在标准窗口字体中。

这是对`showinfo()`的基本调用：

```py
messagebox.showinfo(
    title='This is the title',
    message="This is the message",
    detail='This is the detail')
```

在 Windows 10 中，它会导致一个对话框（在其他平台上可能看起来有点不同），如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/3ae47462-cc7e-4428-bee7-9a8e23f15ea4.png)

Tkinter 的`messagebox`对话框是**模态**的，这意味着程序执行会暂停，而 UI 的其余部分在对话框打开时无响应。没有办法改变这一点，所以只能在程序暂停执行时使用它们。

让我们创建一个小例子来展示`messagebox`函数的使用：

```py
import tkinter as tk
from tkinter import messagebox
```

要使用`messagebox`，我们需要从 Tkinter 导入它；你不能简单地使用`tk.messagebox`，因为它是一个子模块，必须显式导入。

让我们创建一个是-否消息框，如下所示：

```py
see_more = messagebox.askyesno(title='See more?',
    message='Would you like to see another box?',
    detail='Click NO to quit')
if not see_more:
    exit()
```

这将创建一个带有是和否按钮的对话框；如果点击是，函数返回`True`。如果点击否，函数返回`False`，应用程序退出。

如果我们的用户想要看到更多的框，让我们显示一个信息框：

```py
messagebox.showinfo(title='You got it',
    message="Ok, here's another dialog.",
    detail='Hope you like it!')
```

注意`message`和`detail`在您的平台上显示方式的不同。在某些平台上，没有区别；在其他平台上，`message`是大而粗体的，这对于短文本是合适的。对于跨平台软件，最好使用`detail`进行扩展输出。

# 显示错误对话框

现在您了解了如何使用`messagebox`，错误对话框应该很容易实现。`Application.on_save()`方法已经在状态栏中显示错误；我们只需要通过以下步骤使此错误显示在错误消息框中：

1.  首先，我们需要在`application.py`中导入它，如下所示：

```py
from tkinter import messagebox
```

1.  现在，在`on_save()`方法中检查错误后，我们将设置错误对话框的消息。我们将通过使用`"\n *"`将错误字段制作成项目符号列表。不幸的是，`messagebox`不支持任何标记，因此需要使用常规字符手动构建类似项目符号列表的结构，如下所示：

```py
        message = "Cannot save record"
        detail = "The following fields have errors: \n  * {}".format(
            '\n  * '.join(errors.keys()))
```

1.  现在，我们可以在`status()`调用之后调用`showerror()`，如下所示：

```py
        messagebox.showerror(title='Error', message=message, detail=detail)
```

1.  现在，打开程序并点击保存；您将看到一个对话框，提示应用程序中的错误，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/b7f981fb-dc26-4abf-9ff9-b839d434646d.png)

这个错误应该对任何人来说都很难错过！

`messagebox`对话框的一个缺点是它们不会滚动；长错误消息将创建一个可能填满（或超出）屏幕的对话框。如果这是一个潜在的问题，您将需要创建一个包含可滚动小部件的自定义对话框。

# 设计我们的菜单

大多数应用程序将功能组织成一个分层的**菜单系统**，通常显示在应用程序或屏幕的顶部（取决于操作系统）。虽然这个菜单的组织在操作系统之间有所不同，但某些项目在各个平台上都是相当常见的。

在这些常见项目中，我们的应用程序将需要以下内容：

+   包含文件操作（如打开/保存/导出）的文件菜单，通常还有退出应用程序的选项。我们的用户将需要此菜单来选择文件并退出程序。

+   一个选项、首选项或设置菜单，用户可以在其中配置应用程序。我们将需要此菜单来进行切换设置；暂时我们将其称为选项。

+   帮助菜单，其中包含指向帮助文档的链接，或者至少包含一个关于应用程序的基本信息的消息。我们将为关于对话框实现这个菜单。

苹果、微软和 Gnome 项目分别发布了 macOS、Windows 和 Gnome 桌面（在 Linux 和 BSD 上使用）的指南；每套指南都涉及特定平台的菜单布局。

在我们实现菜单之前，我们需要了解 Tkinter 中菜单的工作原理。

# 在 Tkinter 中创建菜单

`tkinter.Menu`小部件用于在 Tkinter 应用程序中实现菜单；它是一个相当简单的小部件，作为任意数量的菜单项的容器。

菜单项可以是以下五种类型之一：

+   `command`：这些项目是带有标签的按钮，当单击时运行回调。

+   `checkbutton`：这些项目就像我们表单中的`Checkbutton`一样，可以用来切换`BooleanVar`。

+   `radiobutton`：这些项目类似于`Checkbutton`，但可以用来在几个互斥选项之间切换任何类型的 Tkinter 变量。

+   `separator`：这些项目用于将菜单分成几个部分。

+   `cascade`：这些项目允许您向菜单添加子菜单。子菜单只是另一个`tkinter.Menu`对象。

让我们编写以下小程序来演示 Tkinter 菜单的使用：

```py
import tkinter as tk

root = tk.Tk()
main_text = tk.StringVar(value='Hi')
label = tk.Label(root, textvariable=main_text)
label.pack()

root.mainloop()
```

该应用程序设置了一个标签，其文本由字符串变量`main_text`控制。如果您运行此应用程序，您将看到一个简单的窗口，上面写着 Hi。让我们开始添加菜单组件。

在`root.mainloop()`的正上方，添加以下代码：

```py
main_menu = tk.Menu(root)
root.config(menu=main_menu)
```

这将创建一个主菜单，然后将其设置为我们应用程序的主菜单。

目前，该菜单是空的，所以让我们通过添加以下代码来添加一个项目：

```py
main_menu.add('command', label='Quit', command=root.quit)
```

我们已经添加了一个退出应用程序的命令。`add`方法允许我们指定一个项目类型和任意数量的属性来创建一个新的菜单项。对于命令，我们至少需要有一个`label`参数来指定菜单中显示的文本，以及一个指向 Python 回调的`command`参数。

一些平台，如 macOS，不允许在顶级菜单中使用命令。

让我们尝试创建一个子菜单，如下所示：

```py
text_menu = tk.Menu(main_menu, tearoff=False)
```

创建子菜单就像创建菜单一样，只是我们将`parent`菜单指定为小部件的`parent`。注意`tearoff`参数；在 Tkinter 中，默认情况下子菜单是可撕下的，这意味着它们可以被拆下并作为独立窗口移动。您不必禁用此选项，但这是一个相当古老的 UI 功能，在现代平台上很少使用。用户可能会觉得困惑，最好在创建子菜单时禁用它。

添加一些命令到菜单中，如下所示：

```py
text_menu.add_command(label='Set to "Hi"',
              command=lambda: main_text.set('Hi'))
text_menu.add_command(label='Set to "There"',
              command=lambda: main_text.set('There'))
```

我们在这里使用`lambda`函数是为了方便，但您可以传递任何 Python 可调用的函数。这里使用的`add_command`方法只是`add('command')`的快捷方式。添加其他项目的方法也是类似的（级联，分隔符等）。

让我们使用`add_cascade`方法将我们的菜单添加回其`parent`小部件，如下所示：

```py
main_menu.add_cascade(label="Text", menu=text_menu)
```

在将子菜单添加到其`parent`菜单时，我们只需提供菜单的标签和菜单本身。

我们也可以将`Checkbutton`和`Radiobutton`小部件添加到菜单中。为了演示这一点，让我们创建另一个子菜单来改变标签的外观。

首先，我们需要以下设置代码：

```py
font_bold = tk.BooleanVar()
font_size = tk.IntVar()

def set_font(*args):
    font_spec = 'TkDefaultFont {size} {bold}'.format(
        size=font_size.get(),
        bold='bold' if font_bold.get() else '')
    label.config(font=font_spec)

font_bold.trace('w', set_font)
font_size.trace('w', set_font)
```

在这里，我们只是创建变量来存储粗体选项和字体大小的状态，然后创建一个回调方法，当调用时实际上从这些变量设置标签的字体。然后，我们在两个变量上设置了一个跟踪，以便在它们的值发生变化时调用回调。

现在，我们只需要通过添加以下代码来创建菜单选项来改变变量：

```py
# appearance menu
appearance_menu = tk.Menu(main_menu, tearoff=False)
main_menu.add_cascade(label="Appearance", menu=appearance_menu)

# bold text button
appearance_menu.add_checkbutton(label="Bold", variable=font_bold)
```

像普通的`Checkbutton`小部件一样，`add_checkbutton`方法接受`BooleanVar`，它被传递给`variable`参数，该参数将绑定到其选中状态。与普通的`Checkbutton`小部件不同，使用`label`参数而不是`text`参数来分配标签文本。

为了演示单选按钮，让我们向我们的子菜单添加一个子菜单，如下所示：

```py
size_menu = tk.Menu(appearance_menu, tearoff=False)
appearance_menu.add_cascade(label='Font size', menu=size_menu)
for size in range(8, 24, 2):
    size_menu.add_radiobutton(label="{} px".format(size),
        value=size, variable=font_size)
```

就像我们在主菜单中添加了一个子菜单一样，我们也可以在子菜单中添加子菜单。理论上，你可以无限嵌套子菜单，但大多数 UI 指南不鼓励超过两个级别。为了创建我们的大小菜单项，我们只需迭代一个在 8 和 24 之间生成的偶数列表；对于每一个，我们都添加一个值等于该大小的`radiobutton`项。就像普通的`Radiobutton`小部件一样，`variable`参数中给定的变量在按钮被选中时将被更新为`value`参数中给定的值。

启动应用程序并尝试一下，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/18dd3562-6645-4d90-84e7-3fd42afc8a8f.png)

现在你了解了`Menu`小部件，让我们在我们的应用程序中添加一个。

# 实现我们的应用程序菜单

作为 GUI 的一个重要组件，我们的菜单显然是一个视图，并且应该在`views.py`文件中实现。但是，它还需要设置影响其他视图的选项（例如我们现在正在实现的表单选项）并运行影响应用程序的函数（如退出）。我们需要以这样一种方式实现它，即我们将控制器函数保留在`Application`类中，但仍将 UI 代码保留在`views.py`中。让我们看看以下步骤：

1.  让我们首先打开`views.py`并创建一个继承了`tkinter.Menu`的`MainMenu`类：

```py
class MainMenu(tk.Menu):
"""The Application's main menu"""
```

我们重写的`__init__()`方法将使用两个字典，`settings`字典和`callbacks`字典，如下所示：

```py
    def __init__(self, parent, settings, callbacks, **kwargs):
        super().__init__(parent, **kwargs)
```

我们将使用这些字典与控制器进行通信：`settings`将包含可以绑定到我们菜单控件的 Tkinter 变量，`callbacks`将是我们可以绑定到菜单命令的控制器方法。当然，我们需要确保在我们的`Application`对象中使用预期的变量和可调用对象来填充这些字典。

1.  现在，让我们开始创建我们的子菜单，首先是文件菜单如下：

```py
        file_menu = tk.Menu(self, tearoff=False)
        file_menu.add_command(
            label="Select file…",
            command=callbacks['file->open'])
```

我们文件菜单中的第一个命令是“选择文件...”。注意标签中的省略号：这向用户表明该选项将打开另一个需要进一步输入的窗口。我们将`command`设置为从我们的`callbacks`字典中使用`file->open`键的引用。这个函数还不存在；我们将很快实现它。让我们添加我们的下一个文件菜单命令，`file->quit`：

```py
        file_menu.add_separator()
        file_menu.add_command(label="Quit",
                command=callbacks['file->quit'])
```

再次，我们将这个命令指向了一个尚未定义的函数，它在我们的`callbacks`字典中。我们还添加了一个分隔符；由于退出程序与选择目标文件是一种根本不同的操作，将它们分开是有意义的，你会在大多数应用程序菜单中看到这一点。

1.  这完成了文件菜单，所以我们需要将它添加到主`menu`对象中，如下所示：

```py
        self.add_cascade(label='File', menu=file_menu)
```

1.  我们需要创建的下一个子菜单是我们的“选项”菜单。由于我们只有两个菜单选项，我们将直接将它们添加到子菜单中作为`Checkbutton`。选项菜单如下所示：

```py
    options_menu = tk.Menu(self, tearoff=False)
    options_menu.add_checkbutton(label='Autofill Date',
        variable=settings['autofill date'])
    options_menu.add_checkbutton(label='Autofill Sheet data',
        variable=settings['autofill sheet data'])
    self.add_cascade(label='Options', menu=options_menu)
```

绑定到这些`Checkbutton`小部件的变量在`settings`字典中，因此我们的`Application`类将用两个`BooleanVar`变量填充`settings`：`autofill date`和`autofill sheet data`。

1.  最后，我们将创建一个“帮助”菜单，其中包含一个显示“关于”对话框的选项：

```py
        help_menu = tk.Menu(self, tearoff=False)
        help_menu.add_command(label='About…', command=self.show_about)
        self.add_cascade(label='Help', menu=help_menu)
```

我们的“关于”命令指向一个名为`show_about`的内部`MainMenu`方法，我们将在下面实现。关于对话框将是纯 UI 代码，没有实际的应用程序功能，因此我们可以完全在视图中实现它。

# 显示关于对话框

我们已经看到如何使用`messagebox`来创建错误对话框。现在，我们可以应用这些知识来创建我们的`About`框，具体步骤如下：

1.  在`__init__()`之后开始一个新的方法定义：

```py
    def show_about(self):
        """Show the about dialog"""
```

1.  `About`对话框可以显示您认为相关的任何信息，包括您的联系信息、支持信息、版本信息，甚至整个`README`文件。在我们的情况下，我们会保持它相当简短。让我们指定`message`标题文本和`detail`正文文本：

```py
        about_message = 'ABQ Data Entry'
        about_detail = ('by Alan D Moore\n'
            'For assistance please contact the author.')
```

我们只是在标题中使用应用程序名称，然后在详细信息中简要介绍我们的姓名以及联系支持的方式。请随意在您的`About`框中放入任何文本。

在 Python 代码中，有几种处理长的多行字符串的方法；这里使用的方法是在括号之间放置多个字符串，它们之间只有空格。Python 会自动连接只有空格分隔的字符串，因此对 Python 来说，这看起来像是一组括号内的单个长字符串。与其他方法相比，例如三引号，这允许您保持清晰的缩进并明确控制换行。

1.  最后，我们需要显示我们的`About`框如下：

```py
        messagebox.showinfo(title='About', message=about_message,  
            detail=about_detail)
```

在上述代码中，`showinfo()`函数显然是最合适的，因为我们实际上是在显示信息。这完成了我们的`show_about()`方法和我们的`MainMenu`类。接下来，我们需要对`Application`进行必要的修改以使其正常工作。

# 在控制器中添加菜单功能

现在我们的菜单类已经定义，我们的`Application`对象需要创建一个实例并将其添加到主窗口中。在我们这样做之前，我们需要定义一些`MainMenu`类需要的东西。

从上一节中记住以下事项：

+   我们需要一个包含我们两个设置选项的 Tkinter 变量的`settings`字典

+   我们需要一个指向`file->select`和`file->quit`回调的`callbacks`字典

+   我们需要实际实现文件选择和退出的函数

让我们定义一些`MainMenu`类需要的东西。

打开`application.py`，让我们在创建`self.recordform`之前开始添加代码：

```py
    self.settings = {
        'autofill date': tk.BooleanVar(),
        'autofill sheet data': tk.BooleanVar()
    }
```

这将是我们的全局设置字典，用于存储两个配置选项的布尔变量。接下来，我们将创建`callbacks`字典：

```py
    self.callbacks = {
        'file->select': self.on_file_select,
        'file->quit': self.quit
    }
```

在这里，我们将我们的两个回调指向`Application`类的方法，这些方法将实现功能。对我们来说，幸运的是，Tkinter 已经实现了`self.quit`，它确实做了您期望它做的事情，因此我们只需要自己实现`on_file_select`。我们将通过创建我们的`menu`对象并将其添加到应用程序来完成这里：

```py
    menu = v.MainMenu(self, self.settings, self.callbacks)
    self.config(menu=menu)
```

# 处理文件选择

当用户需要输入文件或目录路径时，首选的方法是显示一个包含迷你文件浏览器的对话框，通常称为文件对话框。与大多数工具包一样，Tkinter 为我们提供了用于打开文件、保存文件和选择目录的对话框。这些都是`filedialog`模块的一部分。

就像`messagebox`一样，`filedialog`是一个 Tkinter 子模块，需要显式导入才能使用。与`messagebox`一样，它包含一组方便的函数，用于创建适合不同场景的文件对话框。

以下表格列出了函数、它们的返回值和它们的 UI 特性：

| **功能** | **返回值** | **特点** |
| --- | --- | --- |
| `askdirectory` | 目录路径字符串 | 仅显示目录，不显示文件 |
| `askopenfile` | 文件句柄对象 | 仅允许选择现有文件 |
| `askopenfilename` | 文件路径字符串 | 仅允许选择现有文件 |
| `askopenfilenames` | 字符串列表的文件路径 | 类似于`askopenfilename`，但允许多个选择 |
| `askopenfiles` | 文件句柄对象列表 | 类似于`askopenfile`，但允许多个选择 |
| `asksaveasfile` | 文件句柄对象 | 允许创建新文件，在现有文件上进行确认提示 |
| `asksaveasfilename` | 文件路径字符串 | 允许创建新文件，在现有文件上进行确认提示 |

正如您所看到的，每个文件选择对话框都有两个版本：一个返回路径作为字符串，另一个返回打开的文件对象。

每个函数都可以使用以下常见参数：

+   `title`：此参数指定对话框窗口标题。

+   `parent`：此参数指定（可选的）`parent`小部件。文件对话框将出现在此小部件上方。

+   `initialdir`：此参数是文件浏览器应该开始的目录。

+   `filetypes`：此参数是一个元组列表，每个元组都有一个标签和匹配模式，用于创建过滤下拉类型的文件，通常在文件名输入框下方看到。这用于将可见文件过滤为仅由应用程序支持的文件。

`asksaveasfile`和`asksaveasfilename`方法还接受以下两个附加选项：

+   `initialfile`：此选项是要选择的默认文件路径

+   `defaultextension`：此选项是一个文件扩展名字符串，如果用户没有这样做，它将自动附加到文件名

最后，返回文件对象的方法接受一个指定文件打开模式的`mode`参数；这些是 Python 的`open`内置函数使用的相同的一到两个字符字符串。

我们的应用程序需要使用哪个对话框？让我们考虑一下我们的需求：

+   我们需要一个对话框，允许我们选择一个现有文件

+   我们还需要能够创建一个新文件

+   由于打开文件是模型的责任，我们只想获得一个文件名传递给模型

这些要求清楚地指向了`asksaveasfilename`函数。让我们看看以下步骤：

1.  在`Application`对象上启动一个新方法：

```py
    def on_file_select(self):
    """Handle the file->select action from the menu"""

    filename = filedialog.asksaveasfilename(
        title='Select the target file for saving records',
        defaultextension='.csv',
        filetypes=[('Comma-Separated Values', '*.csv *.CSV')])
```

该方法首先要求用户选择一个具有`.csv`扩展名的文件；使用`filetypes`参数，现有文件的选择将被限制为以`.csv`或 CSV 结尾的文件。对话框退出时，函数将将所选文件的路径作为字符串返回给`filename`。不知何故，我们必须将此路径传递给我们的模型。

1.  目前，文件名是在`Application`对象的`on_save`方法中生成并传递到模型中。我们需要将`filename`移动到`Application`对象的属性中，以便我们可以从我们的`on_file_select()`方法中覆盖它。

1.  回到`__init__()`方法，在`settings`和`callbacks`定义之前添加以下代码行：

```py
        self.filename = tk.StringVar()
```

1.  `self.filename`属性将跟踪当前选择的保存文件。以前，我们在`on_save()`方法中设置了我们的硬编码文件名；没有理由每次调用`on_save()`时都这样做，特别是因为我们只在用户没有选择文件的情况下使用它。相反，将这些行从`on_save()`移到`self.filename`定义的上方：

```py
    datestring = datetime.today().strftime("%Y-%m-%d")
    default_filename = "abq_data_record_{}.csv".
    format(datestring)
    self.filename = tk.StringVar(value=default_filename)
```

1.  定义了默认文件名后，我们可以将其作为`StringVar`的默认值提供。每当用户选择文件名时，`on_file_select()`将更新该值。这是通过`on_file_select()`末尾的以下行完成的：

```py
    if filename:
        self.filename.set(filename)
```

1.  `if`语句的原因是，我们只想在用户实际选择了文件时才设置一个值。请记住，如果用户取消操作，文件对话框将返回`None`；在这种情况下，用户希望当前设置的文件名仍然是目标。

1.  最后，当设置了这个值时，我们需要让我们的`on_save()`方法使用它，而不是硬编码的默认值。

1.  在`on_save()`方法中，找到定义`filename`的行，并将其更改为以下行：

```py
    filename = self.filename.get()
```

1.  这完成了代码更改，使文件名选择起作用。此时，您应该能够运行应用程序并测试文件选择功能。保存几条记录并注意它们确实保存到您选择的文件中。

# 使我们的设置生效

虽然文件保存起作用，但设置却没有。`settings`菜单项应该按预期工作，保持选中或取消选中，但它们尚未改变数据输入表单的行为。让我们让它起作用。

请记住，`DataRecordForm`类的`reset()`方法中实现了两个自动填充功能。为了使用我们的新设置，我们需要通过以下步骤让我们的表单访问`settings`字典：

1.  打开`views.py`并更新`DataRecordForm.__init__()`方法如下：

```py
    def __init__(self, parent, fields, settings, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        self.settings = settings
```

1.  我们添加了一个额外的位置参数`settings`，然后将其设置为`self.settings`，以便类中的所有方法都可以访问它。现在，看一下`reset()`方法；目前，日期自动填充代码如下：

```py
        current_date = datetime.today().strftime('%Y-%m-%d')
        self.inputs['Date'].set(current_date)
        self.inputs['Time'].input.focus()
```

1.  我们只需要确保这仅在`settings['autofill date']`为`True`时发生：

```py
 if self.settings['autofill date'].get():
        current_date = datetime.today().strftime('%Y-%m-%d')
        self.inputs['Date'].set(current_date)
        self.inputs['Time'].input.focus()
```

表格数据的自动填充已经在条件语句下，如下所示：

```py
    if plot not in ('', plot_values[-1]):
        self.inputs['Lab'].set(lab)
        self.inputs['Time'].set(time)
       ...
```

1.  为了使设置生效，我们只需要在`if`语句中添加另一个条件：

```py
    if (self.settings['autofill sheet data'].get() and
        plot not in ('', plot_values[-1])):
        ...
```

最后一部分的难题是确保我们在创建`DataRecordForm`时将我们的`settings`字典发送到`DataRecordForm`。

1.  回到`Application`代码，更新我们对`DataRecordForm()`的调用，包括`self.settings`如下：

```py
        self.recordform = v.DataRecordForm(self, 
            m.CSVModel.fields, self.settings)
```

1.  现在，如果运行程序，您应该会发现设置得到了尊重；尝试勾选和取消勾选它们，然后保存记录后查看发生了什么。

# 持久化设置

我们的设置有效，但有一个主要的烦恼：它们在会话之间不持久。关闭应用程序并重新启动，您会发现设置恢复为默认值。这不是一个主要问题，但这是一个我们不应该留给用户的粗糙边缘。

Python 为我们提供了各种将数据持久保存在文件中的方法。我们已经体验过 CSV，它是为表格数据设计的；还有其他设计用于不同功能的格式。

以下表格仅显示了 Python 标准库中可用的存储数据选项中的一些选项：

| **库** | **数据类型** | **适用** | **优点** | **缺点** |
| --- | --- | --- | --- | --- |
| `pickle` | 二进制 | 任何类型的对象 | 快速、简单、文件小 | 不安全，文件不易读，必须读取整个文件 |
| `configparser` | 文本 | `key->value`对 | 快速、简单、易读的文件 | 无法处理序列或复杂对象，层次有限 |
| `json` | 文本 | 简单值和序列 | 广泛使用，易读的文件 | 无法序列化复杂对象而不经修改 |
| `xml` | 文本 | 任何类型的 Python 对象 | 强大、灵活、大部分易读的文件 | 不安全，使用复杂，文件语法冗长 |
| `sqlite` | 二进制 | 关系数据 | 快速而强大的文件 | 需要 SQL 知识，对象必须转换为表 |

如果这还不够，第三方库中甚至还有更多选项可用。几乎任何一个都适合存储一些布尔值，那么我们该如何选择呢？

+   SQL 和 XML 功能强大，但对于我们这里的简单需求来说太复杂了。

+   我们希望坚持使用文本格式，以防需要调试损坏的设置文件，因此`pickle`不适用。

+   `configparser`现在可以工作了，但它无法处理列表、元组和字典，这在将来可能会有限制。

+   这留下了`json`，这是一个不错的选择。虽然它不能处理每种类型的 Python 对象，但它可以处理字符串、数字和布尔值，以及列表和字典。这应该可以很好地满足我们的配置需求。

当我们说一个库是“不安全”时，这意味着什么？一些数据格式设计有强大的功能，比如可扩展性、链接或别名，解析库必须实现这些功能。不幸的是，这些功能可能被用于恶意目的。例如，十亿次笑 XML 漏洞结合了三个 XML 功能，制作了一个文件，当解析时，会扩展到一个巨大的大小（通常导致程序或者在某些情况下，系统崩溃）。

# 为设置持久性构建模型

与任何数据持久化一样，我们需要先实现一个模型。与我们的`CSVModel`类一样，设置模型需要保存和加载数据，以及定义设置数据的布局。

在`models.py`文件中，让我们按照以下方式开始一个新的类：

```py
class SettingsModel:
    """A model for saving settings"""
```

就像我们的`CSVModel`类一样，我们需要定义我们模型的模式：

```py
    variables = {
        'autofill date': {'type': 'bool', 'value': True},
        'autofill sheet data': {'type': 'bool', 'value': True}
     }
```

`variables`字典将存储每个项目的模式和值。每个设置都有一个列出数据类型和默认值的字典（如果需要，我们可以在这里列出其他属性，比如最小值、最大值或可能的值）。`variables`字典将是我们保存到磁盘并从磁盘加载以持久化程序设置的数据结构。

模型还需要一个位置来保存配置文件，因此我们的构造函数将以文件名和路径作为参数。现在，我们只提供并使用合理的默认值，但在将来我们可能会想要更改这些值。

然而，我们不能只提供一个单一的文件路径；我们在同一台计算机上有不同的用户，他们会想要保存不同的设置。我们需要确保设置保存在各个用户的主目录中，而不是一个单一的公共位置。

因此，我们的`__init__()`方法如下：

```py
    def __init__(self, filename='abq_settings.json', path='~'):
        # determine the file path
        self.filepath = os.path.join(
            os.path.expanduser(path), filename)
```

作为 Linux 或 macOS 终端的用户会知道，`~`符号是 Unix 的快捷方式，指向用户的主目录。Python 的`os.path.expanduser()`函数将这个字符转换为绝对路径（即使在 Windows 上也是如此），这样文件将被保存在运行程序的用户的主目录中。`os.path.join()`将文件名附加到扩展路径上，给我们一个完整的路径到用户特定的配置文件。

一旦模型被创建，我们就希望从磁盘加载用户保存的选项。从磁盘加载数据是一个非常基本的模型操作，我们应该能够在类外部控制，所以我们将这个方法设为公共方法。

我们将称这个方法为`load()`，并在这里调用它：

```py
        self.load()
```

`load()`将期望找到一个包含与`variables`字典相同格式的字典的 JSON 文件。它将需要从文件中加载数据，并用文件副本替换自己的`variables`副本。

一个简单的实现如下：

```py
    def load(self):
        """Load the settings from the file"""

        with open(self.filepath, 'r') as fh:
            self.variables = json.loads(fh.read())
```

`json.loads()`函数读取 JSON 字符串并将其转换为 Python 对象，我们直接保存到我们的`variables`字典中。当然，这种方法也存在一些问题。首先，如果设置文件不存在会发生什么？在这种情况下，`open`会抛出一个异常，程序会崩溃。不好！

因此，在我们尝试打开文件之前，让我们测试一下它是否存在，如下所示：

```py
        # if the file doesn't exist, return
        if not os.path.exists(self.filepath):
            return
```

如果文件不存在，该方法将简单地返回并不执行任何操作。文件不存在是完全合理的，特别是如果用户从未运行过程序或编辑过任何设置。在这种情况下，该方法将保持`self.variables`不变，用户将最终使用默认值。

第二个问题是我们的设置文件可能存在，但不包含任何数据或无效数据（比如`variables`字典中不存在的键），导致程序崩溃。为了防止这种情况，我们将 JSON 数据拉到一个本地变量中；然后通过询问`raw_values`只获取那些存在于`variables`中的键来更新`variables`，如果它们不存在，则提供一个默认值。

新的、更安全的代码如下：

```py
        # open the file and read in the raw values
        with open(self.filepath, 'r') as fh:
            raw_values = json.loads(fh.read())

        # don't implicitly trust the raw values, 
        # but only get known keys
        for key in self.variables:
            if key in raw_values and 'value' in raw_values[key]:
                raw_value = raw_values[key]['value']
                self.variables[key]['value'] = raw_value
```

由于`variables`已经使用默认值创建，如果`raw_values`没有给定键，或者该键中的字典不包含`values`项，我们只需要忽略`raw_values`。

现在`load()`已经编写好了，让我们编写一个`save()`方法将我们的值写入文件：

```py
    def save(self, settings=None):
        json_string = json.dumps(self.variables)
        with open(self.filepath, 'w') as fh:
            fh.write(json_string)
```

`json.dumps()`函数是`loads()`的反函数：它接受一个 Python 对象并返回一个 JSON 字符串。保存我们的`settings`数据就像将`variables`字典转换为字符串并将其写入指定的文本文件一样简单。

我们的模型需要的最后一个方法是让外部代码设置值的方法；他们可以直接操作`variables`，但为了保护我们的数据完整性，我们将通过方法调用来实现。遵循 Tkinter 的惯例，我们将称这个方法为`set()`。

`set()`方法的基本实现如下：

```py
    def set(self, key, value):
        self.variables[key]['value'] = value
```

这个简单的方法只是接受一个键和值，并将它们写入`variables`字典。不过，这又带来了一些潜在的问题；如果提供的值对于数据类型来说不是有效的怎么办？如果键不在我们的`variables`字典中怎么办？这可能会导致难以调试的情况，因此我们的`set()`方法应该防范这种情况。

将代码更改如下：

```py
    if (
        key in self.variables and
        type(value).__name__ == self.variables[key]['type']
    ):
        self.variables[key]['value'] = value
```

通过使用与实际 Python 类型名称相对应的`type`字符串，我们可以使用`type(value).__name__`将其与值的类型名称进行匹配（我们本可以在我们的`variables`字典中使用实际的类型对象，但这些对象无法序列化为 JSON）。现在，尝试写入未知键或不正确的变量类型将会失败。

然而，我们不应该让它悄悄失败；我们应该立即引发`ValueError`来提醒我们存在问题，如下所示：

```py
    else:
        raise ValueError("Bad key or wrong variable type")
```

为什么要引发异常？如果测试失败，这只能意味着调用代码中存在错误。通过异常，我们将立即知道调用代码是否向我们的模型发送了错误的请求。如果没有异常，请求将悄悄失败，留下难以发现的错误。

故意引发异常的想法对于初学者来说通常似乎很奇怪；毕竟，我们正在尽量避免异常，对吧？对于主要是使用现有模块的小脚本来说，这是正确的；然而，当编写自己的模块时，异常是模块与使用它的代码交流问题的正确方式。试图处理或更糟糕的是消除外部调用代码的不良行为，最好会破坏模块化；在最坏的情况下，它会产生难以追踪的微妙错误。

# 在我们的应用程序中使用设置模型

我们的应用程序在启动时需要加载设置，然后在更改设置时自动保存。目前，应用程序的`settings`字典是手动创建的，但是我们的模型应该真正告诉它创建什么样的变量。让我们按照以下步骤在我们的应用程序中使用`settings`模型：

1.  用以下代码替换定义`Application.settings`的代码：

```py
        self.settings_model = m.SettingsModel()
        self.load_settings()
```

首先，我们创建一个`settings`模型并将其保存到我们的`Application`对象中。然后，我们将运行一个`load_settings()`方法。这个方法将负责根据`settings_model`设置`Application.settings`字典。

1.  现在，让我们创建`Application.load_settings()`：

```py
    def load_settings(self):
        """Load settings into our self.settings dict."""
```

1.  我们的模型存储了每个变量的类型和值，但我们的应用程序需要 Tkinter 变量。我们需要一种方法将模型对数据的表示转换为`Application`可以使用的结构。一个字典提供了一个方便的方法来做到这一点，如下所示：

```py
      vartypes = {
          'bool': tk.BooleanVar,
          'str': tk.StringVar,
          'int': tk.IntVar,
         'float': tk.DoubleVar
      }
```

注意，每个名称都与 Python 内置函数的类型名称匹配。我们可以在这里添加更多条目，但这应该涵盖我们未来的大部分需求。现在，我们可以将这个字典与模型的`variables`字典结合起来构建`settings`字典：

```py
        self.settings = {}
        for key, data in self.settings_model.variables.items():
            vartype = vartypes.get(data['type'], tk.StringVar)
            self.settings[key] = vartype(value=data['value'])
```

1.  在这里使用 Tkinter 变量的主要原因是，我们可以追踪用户通过 UI 对值所做的任何更改并立即做出响应。具体来说，我们希望在用户进行更改时立即保存我们的设置，如下所示：

```py
        for var in self.settings.values():
            var.trace('w', self.save_settings)
```

1.  当然，这意味着我们需要编写一个名为`Application.save_settings()`的方法，每当值发生更改时都会运行。`Application.load_settings()`已经完成，所以让我们接着做这个：

```py
    def save_settings(self, *args):
        """Save the current settings to a preferences file"""
```

1.  `save_settings()`方法只需要从`Application.settings`中获取数据并保存到模型中：

```py
        for key, variable in self.settings.items():
            self.settings_model.set(key, variable.get())
        self.settings_model.save()
```

这很简单，只需要循环遍历`self.settings`，并调用我们模型的`set()`方法逐个获取值。然后，我们调用模型的`save()`方法。

1.  现在，你应该能够运行程序并观察到设置被保存了，即使你关闭并重新打开应用程序。你还会在你的主目录中找到一个名为`abq_settings.json`的文件。

# 总结

在这一章中，我们简单的表单迈出了成为一个完全成熟的应用程序的重要一步。我们实现了一个主菜单，选项设置在执行之间是持久的，并且有一个“关于”对话框。我们增加了选择保存记录的文件的能力，并通过错误对话框改善了表单错误的可见性。在这个过程中，你学到了关于 Tkinter 菜单、文件对话框和消息框，以及标准库中持久化数据的各种选项。

在下一章中，我们将被要求让程序读取和写入。我们将学习关于 Tkinter 的树部件，如何在主视图之间切换，以及如何使我们的`CSVModel`和`DataRecordForm`类能够读取和更新现有数据。


# 第七章：使用 Treeview 导航记录

您收到了应用程序中的另一个功能请求。现在，您的用户可以打开任意文件，他们希望能够查看这些文件中的内容，并使用他们已经习惯的数据输入表单来更正旧记录，而不必切换到电子表格。简而言之，现在终于是时候在我们的应用程序中实现读取和更新功能了。

在本章中，我们将涵盖以下主题：

+   修改我们的 CSV 模型以实现读取和更新功能

+   发现 ttk`Treeview`小部件，并使用它构建记录列表

+   在我们的数据记录表单中实现记录加载和更新

+   重新设计菜单和应用程序，考虑到读取和更新

# 在模型中实现读取和更新

到目前为止，我们的整个设计都是围绕着一个只能向文件追加数据的表单；添加读取和更新功能是一个根本性的改变，几乎会触及应用程序的每个部分。这可能看起来是一项艰巨的任务，但通过逐个组件地进行，我们会发现这些变化并不那么令人难以承受。

我们应该做的第一件事是更新我们的文档，从`Requirements`部分开始：

```py
The program must:

* Provide a UI for reading, updating, and appending data to the CSV file
* ...
```

当然，还要更新后面不需要的部分：

```py
The program does not need to:

* Allow deletion of data.
```

现在，只需让代码与文档匹配即可。

# 将读取和更新添加到我们的模型中

打开`models.py`并考虑`CSVModel`类中缺少的内容：

+   我们需要一种方法，可以检索文件中的所有记录，以便我们可以显示它们。我们将其称为`get_all_records()`。

+   我们需要一种方法来按行号从文件中获取单个记录。我们可以称之为`get_record()`。

+   我们需要以一种既能追加新记录又能更新现有记录的方式保存记录。我们可以更新我们的`save_record()`方法来适应这一点。

# 实现`get_all_records()`

开始一个名为`get_all_records()`的新方法：

```py
    def get_all_records(self):
        if not os.path.exists(self.filename):
            return []
```

我们所做的第一件事是检查模型的文件是否已经存在。请记住，当我们的应用程序启动时，它会生成一个默认文件名，指向一个可能尚不存在的文件，因此`get_all_records()`将需要优雅地处理这种情况。在这种情况下返回一个空列表是有道理的，因为如果文件不存在，就没有数据。

如果文件存在，让我们以只读模式打开它并获取所有记录：

```py
        with open(self.filename, 'r') as fh:
            csvreader = csv.DictReader(fh)
            records = list(csvreader)
```

虽然不是非常高效，但在我们的情况下，将整个文件加载到内存中并将其转换为列表是可以接受的，因为我们知道我们的最大文件应该限制在仅 401 行：20 个图形乘以 5 个实验室加上标题行。然而，这段代码有点太信任了。我们至少应该进行一些合理性检查，以确保用户实际上已经打开了包含正确字段的 CSV 文件，而不是其他任意文件。

让我们检查文件是否具有正确的字段结构：

```py
        csvreader = csv.DictReader(fh)
        missing_fields = (set(self.fields.keys()) -    
                          set(csvreader.fieldnames))
        if len(missing_fields) > 0:
            raise Exception(
                "File is missing fields: {}"
                .format(', '.join(missing_fields))
            )
        else:
            records = list(csvreader)
```

在这里，我们首先通过将我们的`fields`字典`keys`的列表和 CSV 文件的`fieldnames`转换为 Python`set`对象来找到任何缺失的字段。我们可以从`keys`中减去`fieldnames`集合，并确定文件中缺少的字段。如果有任何字段缺失，我们将引发异常；否则，我们将 CSV 数据转换为`list`。

Python 的`set`对象非常有用，可以比较`list`、`tuple`和其他序列对象的内容。它们提供了一种简单的方法来获取诸如差异（`x`中的项目不在`y`中）或交集（`x`和`y`中的项目）之类的信息，或者允许您比较不考虑顺序的序列。

在我们可以返回`records`列表之前，我们需要纠正一个问题；CSV 文件中的所有数据都存储为文本，并由 Python 作为字符串读取。这大多数情况下不是问题，因为 Tkinter 会负责根据需要将字符串转换为`float`或`int`，但是`bool`值在 CSV 文件中存储为字符串`True`和`False`，直接将这些值强制转换回`bool`是行不通的。`False`是一个非空字符串，在 Python 中所有非空字符串都会被视为`True`。

为了解决这个问题，让我们首先定义一个应被解释为`True`的字符串列表：

```py
        trues = ('true', 'yes', '1')
```

不在此列表中的任何值都将被视为`False`。我们将进行不区分大小写的比较，因此我们的列表中只有小写值。

接下来，我们使用列表推导式创建一个包含`boolean`字段的字段列表，如下所示：

```py
        bool_fields = [
            key for key, meta
            in self.fields.items()
            if meta['type'] == FT.boolean]
```

我们知道`Equipment Fault`是我们唯一的布尔字段，因此从技术上讲，我们可以在这里硬编码它，但是最好设计您的模型，以便对模式的任何更改都将自动适当地处理逻辑部分。

现在，让我们通过添加以下代码来检查每行中的布尔字段：

```py
        for record in records:
            for key in bool_fields:
                record[key] = record[key].lower() in trues
```

对于每条记录，我们遍历我们的布尔字段列表，并根据我们的真值字符串列表检查其值，相应地设置该项的值。

修复布尔值后，我们可以将我们的`records`列表返回如下：

```py
        return records
```

# 实现`get_record()`

我们的`get_record()`方法需要接受行号并返回包含该行数据的单个字典。

如果我们利用我们的`get_all_records()`方法，这就非常简单了，如下所示：

```py
    def get_record(self, rownum):
        return self.get_all_records()[rownum]
```

由于我们的文件很小，拉取所有记录的开销很小，我们可以简单地这样做，然后取消引用我们需要的记录。

请记住，可能会传递不存在于我们记录列表中的`rownum`；在这种情况下，我们会得到`IndexError`；我们的调用代码将需要捕获此错误并适当处理。

# 将更新添加到`save_record()`

将我们的`save_record()`方法转换为可以更新记录的方法，我们首先需要做的是提供传入要更新的行号的能力。默认值将是`None`，表示数据是应追加的新行。

新的方法签名如下：

```py
    def save_record(self, data, rownum=None):
        """Save a dict of data to the CSV file"""
```

我们现有的逻辑不需要更改，但只有在`rownum`为`None`时才应运行。

因此，在该方法中要做的第一件事是检查`rownum`：

```py
        if rownum is not None:
            # This is an update, new code here
        else:
            # Old code goes here, indented one more level
```

对于相对较小的文件，更新单行的最简单方法是将整个文件加载到列表中，更改列表中的行，然后将整个列表写回到一个干净的文件中。

在`if`块下，我们将添加以下代码：

```py
            records = self.get_all_records()
            records[rownum] = data
            with open(self.filename, 'w') as fh:
                csvwriter = csv.DictWriter(fh,
                    fieldnames=self.fields.keys())
                csvwriter.writeheader()
                csvwriter.writerows(records)
```

再次利用我们的`get_all_records()`方法将 CSV 文件的内容提取到列表中。然后，我们用提供的`data`字典替换请求行中的字典。最后，我们以写模式（`w`）打开文件，这将清除其内容并用我们写入文件的内容替换它，并将标题和所有记录写回文件。

我们采取的方法使得两个用户同时在保存 CSV 文件中工作是不安全的。创建允许多个用户编辑单个文件的软件是非常困难的，许多程序选择使用锁文件或其他保护机制来防止这种情况。

这个方法已经完成了，这就是我们需要在模型中进行的所有更改，以实现更新和查看。现在，是时候向我们的 GUI 添加必要的功能了。

# 实现记录列表视图

记录列表视图将允许我们的用户浏览文件的内容，并打开记录进行查看或编辑。我们的用户习惯于在电子表格中看到这些数据，以表格格式呈现，因此设计我们的视图以类似的方式是有意义的。由于我们的视图主要存在于查找和选择单个记录，我们不需要显示所有信息；只需要足够让用户区分一个记录和另一个记录。

快速分析表明我们需要 CSV 行号、`Date`、`Time`、`Lab`和`Plot`。 

对于构建具有可选择行的类似表格的视图，Tkinter 为我们提供了 ttk `Treeview`小部件。为了构建我们的记录列表视图，我们需要了解`Treeview`。

# ttk Treeview

`Treeview`是一个 ttk 小部件，设计用于以分层结构显示数据的列。

也许这种数据的最好例子是文件系统树：

+   每一行可以代表一个文件或目录

+   每个目录可以包含额外的文件或目录

+   每一行都可以有额外的数据属性，比如权限、大小或所有权信息

为了探索`Treeview`的工作原理，我们将借助`pathlib`创建一个简单的文件浏览器。

在之前的章节中，我们使用`os.path`来处理文件路径。`pathlib`是 Python 3 标准库的一个新添加，它提供了更面向对象的路径处理方法。

打开一个名为`treeview_demo.py`的新文件，并从这个模板开始：

```py
import tkinter as tk
from tkinter import ttk
from pathlib import Path

root = tk.Tk()
# Code will go here

root.mainloop()
```

我们将首先获取当前工作目录下所有文件路径的列表。`Path`有一个名为`glob`的方法，将给我们提供这样的列表，如下所示：

```py
paths = Path('.').glob('**/*')
```

`glob()`会对文件系统树扩展通配符字符，比如`*`和`?`。这个名称可以追溯到一个非常早期的 Unix 命令，尽管现在相同的通配符语法在大多数现代操作系统中都被使用。

`Path('.')` 创建一个引用当前工作目录的路径对象，`**/*` 是一个特殊的通配符语法，递归地抓取路径下的所有对象。结果是一个包含当前目录下每个目录和文件的`Path`对象列表。

完成后，我们可以通过执行以下代码来创建和配置我们的`Treeview`小部件：

```py
tv = ttk.Treeview(root, columns=['size', 'modified'], 
                  selectmode='None')
```

与任何 Tkinter 小部件一样，`Treeview`的第一个参数是它的`parent`小部件。`Treeview`小部件中的每一列都被赋予一个标识字符串；默认情况下，总是有一个名为`"#0"`的列。这一列代表树中每个项目的基本标识信息，比如名称或 ID 号。要添加更多列，我们使用`columns`参数来指定它们。这个列表包含任意数量的字符串，用于标识随后的列。

最后，我们设置`selectmode`，确定用户如何在树中选择项目。

以下表格显示了`selectmode`的选项：

| **Value** | **Behavior** |
| --- | --- |
| `selectmode` | 可以进行选择 |
| `none`（作为字符串，而不是`None`对象） | 不能进行选择 |
| `browse` | 用户只能选择一个项目 |
| `extended` | 用户可以选择多个项目 |

在这种情况下，我们正在阻止选择，所以将其设置为`none`。

为了展示我们如何使用列名，我们将为列设置一些标题：

```py
tv.heading('#0', text='Name')
tv.heading('size', text='Size', anchor='center')
tv.heading('modified', text='Modified', anchor='e')
```

`Treeview` heading 方法用于操作列`heading`小部件；它接受列名，然后是要分配给列`heading`小部件的任意数量的属性。

这些属性可以包括：

+   `text`：标题显示的文本。默认情况下为空。

+   `anchor`：文本的对齐方式；可以是八个基本方向之一或`center`，指定为字符串或 Tkinter 常量。

+   `command`：单击标题时要运行的命令。这可能用于按该列对行进行排序，或选择该列中的所有值，例如。

+   `image`：要在标题中显示的图像。

最后，我们将列打包到`root`小部件中，并扩展它以填充小部件： 

```py
tv.pack(expand=True, fill='both')
```

除了配置标题之外，我们还可以使用`Treeview.column`方法配置列本身的一些属性。

例如，我们可以添加以下代码：

```py
tv.column('#0', stretch=True)
tv.column('size', width=200)
```

在此示例中，我们已将第一列中的`stretch`设置为`True`，这将导致它扩展以填充可用空间；我们还将`size`列上的`width`值设置为`200`像素。

可以设置的列参数包括：

+   `stretch`：是否将此列扩展以填充可用空间。

+   `width`：列的宽度，以像素为单位。

+   `minwidth`：列可以调整的最小宽度，以像素为单位。

+   `anchor`：列中文本的对齐方式。可以是八个基本方向或中心，指定为字符串或 Tkinter 常量。

树视图配置完成后，现在需要填充数据。使用`insert`方法逐行填充`Treeview`的数据。

`insert`方法如下所示：

```py
mytreeview.insert(parent, 'end', iid='item1',
          text='My Item 1', values=['12', '42'])
```

第一个参数指定插入行的`parent`项目。这不是`parent`小部件，而是层次结构中插入行所属的`parent`行。该值是一个字符串，指的是`parent`项目的`iid`。对于顶级项目，该值应为空字符串。

下一个参数指定应将项目插入的位置。它可以是数字索引或`end`，将项目放在列表末尾。

之后，我们可以指定关键字参数，包括：

+   `text`：这是要显示在第一列中的值。

+   `values`：这是剩余列的值列表。

+   `image`：这是要显示在列最左侧的图像对象。

+   `iid`：项目 ID 字符串。如果不指定，将自动分配。

+   `open`：行在开始时是否打开（显示子项）。

+   `tags`：标签字符串列表。

要将我们的路径插入`Treeview`，让我们按如下方式遍历我们的`paths`列表：

```py
for path in paths:
    meta = path.stat()
    parent = str(path.parent)
    if parent == '.':
        parent = ''
```

在调用`insert`之前，我们需要从路径对象中提取和准备一些数据。`path.stat()`将给我们一个包含各种文件信息的对象。`path.parent`提供了包含路径；但是，我们需要将`root`路径的名称（当前为单个点）更改为一个空字符串，这是`Treeview`表示`root`节点的方式。

现在，我们按如下方式添加`insert`调用：

```py
    tv.insert(parent, 'end', iid=str(path),
        text=str(path.name), values=[meta.st_size, meta.st_mtime])
```

通过使用路径字符串作为项目 ID，我们可以将其指定为其子对象的父级。我们仅使用对象的`name`（不包含路径）作为我们的显示值，然后使用`st_size`和`st_mtime`来填充大小和修改时间列。

运行此脚本，您应该会看到一个简单的文件树浏览器，类似于这样：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/1ceeffaf-50a0-4c9e-97d3-525c1026367f.png)

`Treeview`小部件默认不提供任何排序功能，但我们可以相当容易地添加它。

首先，让我们通过添加以下代码创建一个排序函数：

```py
def sort(tv, col):
    itemlist = list(tv.get_children(''))
    itemlist.sort(key=lambda x: tv.set(x, col))
    for index, iid in enumerate(itemlist):
        tv.move(iid, tv.parent(iid), index)
```

在上述代码片段中，`sort`函数接受一个`Treeview`小部件和我们将对其进行排序的列的 ID。它首先使用`Treeview`的`get_children()`方法获取所有`iid`值的列表。接下来，它使用`col`的值作为键对各种`iid`值进行排序；令人困惑的是，`Treeview`的`set()`方法用于检索列的值（没有`get()`方法）。最后，我们遍历列表，并使用`move()`方法将每个项目移动到其父级下的新索引（使用`parent()`方法检索）。

为了使我们的列可排序，使用`command`参数将此函数作为回调添加到标题中，如下所示：

```py
tv.heading('#0', text='Name', command=lambda: sort(tv, '#0'))
tv.heading('size', text='Size', anchor='center',
           command=lambda: sort(tv, 'size'))
tv.heading('modified', text='Modified', anchor='e',
           command=lambda: sort(tv, 'modified'))
```

# 使用`Treeview`实现我们的记录列表

现在我们了解了如何使用`Treeview`小部件，让我们开始构建我们的记录列表小部件。

我们将首先通过子类化`tkinter.Frame`来开始，就像我们在记录表单中所做的那样。

```py
class RecordList(tk.Frame):
    """Display for CSV file contents"""
```

为了节省一些重复的代码，我们将在类常量中定义我们的列属性和默认值。这也使得更容易调整它们以满足我们的需求。

使用以下属性开始你的类：

```py
    column_defs = {
        '#0': {'label': 'Row', 'anchor': tk.W},
        'Date': {'label': 'Date', 'width': 150, 'stretch': True},
        'Time': {'label': 'Time'},
        'Lab': {'label': 'Lab', 'width': 40},
        'Plot': {'label': 'Plot', 'width': 80}
        }
    default_width = 100
    default_minwidth = 10
    default_anchor = tk.CENTER
```

请记住，我们将显示`Date`，`Time`，`Lab`和`Plot`。对于第一个默认列，我们将显示 CSV 行号。我们还为一些列设置了`width`和`anchor`值，并配置了`Date`字段以进行拉伸。我们将在`__init__()`中配置`Treeview`小部件时使用这些值。

让我们从以下方式开始定义我们的`__init__()`：

```py
    def __init__(self, parent, callbacks, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        self.callbacks = callbacks
```

与其他视图一样，我们将从`Application`对象接受回调方法的字典，并将其保存为实例属性。

# 配置 Treeview 小部件

现在，通过执行以下代码片段来创建我们的`Treeview`小部件：

```py
        self.treeview = ttk.Treeview(self,
            columns=list(self.column_defs.keys())[1:],
            selectmode='browse')
```

请注意，我们正在从我们的`columns`列表中排除`＃0`列；它不应在这里指定，因为它会自动创建。我们还选择了`browse`选择模式，这样用户就可以选择 CSV 文件的单独行。

让我们继续将我们的`Treeview`小部件添加到`RecordList`并使其填充小部件：

```py
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)
        self.treeview.grid(row=0, column=0, sticky='NSEW')
```

现在，通过迭代`column_defs`字典来配置`Treeview`的列和标题：

```py
        for name, definition in self.column_defs.items():
```

对于每组项目，让我们按如下方式提取我们需要的配置值：

```py
            label = definition.get('label', '')
            anchor = definition.get('anchor', self.default_anchor)
            minwidth = definition.get(
                'minwidth', self.default_minwidth)
            width = definition.get('width', self.default_width)
            stretch = definition.get('stretch', False)
```

最后，我们将使用这些值来配置标题和列：

```py
            self.treeview.heading(name, text=label, anchor=anchor)
            self.treeview.column(name, anchor=anchor,
                minwidth=minwidth, width=width, stretch=stretch)
```

# 添加滚动条

ttk 的`Treeview`默认没有滚动条；它*可以*使用键盘或鼠标滚轮控件进行滚动，但用户合理地期望在可滚动区域上有滚动条，以帮助他们可视化列表的大小和当前位置。

幸运的是，ttk 为我们提供了一个可以连接到我们的`Treeview`小部件的`Scrollbar`对象：

```py
        self.scrollbar = ttk.Scrollbar(self,
            orient=tk.VERTICAL, command=self.treeview.yview)
```

在这里，`Scrollbar`接受以下两个重要参数：

+   `orient`：此参数确定是水平滚动还是垂直滚动

+   `command`：此参数为滚动条移动事件提供回调

在这种情况下，我们将回调设置为树视图的`yview`方法，该方法用于使`Treeview`上下滚动。另一个选项是`xview`，它将用于水平滚动。

我们还需要将我们的`Treeview`连接回滚动条：

```py
        self.treeview.configure(yscrollcommand=self.scrollbar.set)
```

如果我们不这样做，我们的`Scrollbar`将不知道我们已经滚动了多远或列表有多长，并且无法适当地设置滚动条小部件的大小或位置。

配置了我们的`Scrollbar`后，我们需要将其放置在小部件上——通常是在要滚动的小部件的右侧。

我们可以使用我们的`grid`布局管理器来实现这一点：

```py
        self.scrollbar.grid(row=0, column=1, sticky='NSW')
```

请注意，我们将`sticky`设置为 north、south 和 west。north 和 south 确保滚动条拉伸到小部件的整个高度，west 确保它紧贴着`Treeview`小部件的左侧。

# 填充 Treeview

现在我们有了`Treeview`小部件，我们将创建一个`populate()`方法来填充它的数据：

```py
    def populate(self, rows):
        """Clear the treeview & write the supplied data rows to it."""
```

`rows`参数将接受`dict`数据类型的列表，例如从`model`返回的类型。其想法是控制器将从模型中获取一个列表，然后将其传递给此方法。

在重新填充`Treeview`之前，我们需要清空它：

```py
        for row in self.treeview.get_children():
            self.treeview.delete(row)
```

`Treeview`的`get_children()`方法返回每行的`iid`列表。我们正在迭代此列表，将每个`iid`传递给`Treeview.delete()`方法，正如您所期望的那样，删除该行。

清除`Treeview`后，我们可以遍历`rows`列表并填充表格：

```py
        valuekeys = list(self.column_defs.keys())[1:]
        for rownum, rowdata in enumerate(rows):
            values = [rowdata[key] for key in valuekeys]
            self.treeview.insert('', 'end', iid=str(rownum),
                                 text=str(rownum), values=values)
```

我们在这里要做的第一件事是创建一个我们实际想要从每一行获取的所有键的列表；这只是从`self.column_defs`减去`＃0`列的键列表。

接下来，我们使用 `enumerate()` 函数迭代行以生成行号。对于每一行，我们将使用列表推导创建正确顺序的值列表，然后使用 `insert()` 方法将列表插入到 `Treeview` 小部件的末尾。请注意，我们只是将行号（转换为字符串）用作行的 `iid` 和 `text`。

在这个函数中我们需要做的最后一件事是进行一些小的可用性调整。为了使我们的 `Treeview` 对键盘友好，我们需要将焦点放在第一项上，这样键盘用户就可以立即开始使用箭头键进行导航。

在 `Treeview` 小部件中实际上需要三个方法调用，如下所示：

```py
        if len(rows) > 0:
            self.treeview.focus_set()
            self.treeview.selection_set(0)
            self.treeview.focus('0')
```

首先，`focus_set` 将焦点移动到 `Treeview`。接下来，`selection_set(0)` 选择列表中的第一条记录。最后，`focus('0')` 将焦点放在 `iid` 为 `0` 的行上。当然，我们只在有任何行的情况下才这样做。

# 响应记录选择

这个小部件的目的是让用户选择和打开记录；因此，我们需要一种方法来做到这一点。最好能够从双击或键盘选择等事件触发这一点。

`Treeview` 小部件有三个特殊事件，我们可以使用它们来触发回调，如下表所示：

| **事件字符串** | **触发时** |
| --- | --- |
| `<<TreeviewSelect>>` | 选择行，例如通过鼠标点击 |
| `<<TreeviewOpen>>` | 通过双击或选择并按 *Enter* 打开行 |
| `<<TreeviewClose>>` | 关闭打开的行 |

`<<TreeviewOpen>>` 听起来像我们想要的事件；即使我们没有使用分层列表，用户仍然在概念上打开记录，并且触发动作（双击）似乎很直观。我们将将此事件绑定到一个方法，该方法将打开所选记录。

将此代码添加到 `__init__()` 的末尾：

```py
        self.treeview.bind('<<TreeviewOpen>>', self.on_open_record)
```

`on_open_record()` 方法非常简单；将此代码添加到类中：

```py
    def on_open_record(self, *args):
        selected_id = self.treeview.selection()[0]
        self.callbacks'on_open_record'
```

只需从 `Treeview` 中检索所选 ID，然后使用控制器中的 `callbacks` 字典提供的函数调用所选 ID。这将由控制器来做一些适当的事情。

`RecordList` 类现在已经完成，但是我们的其他视图类需要注意。

# 修改记录表单以进行读取和更新

只要我们在编辑视图，我们就需要查看我们的 `DataRecordForm` 视图，并调整它以使其能够更新记录。

花点时间考虑一下我们需要进行的以下更改：

+   表单将需要一种方式来加载控制器提供的记录。

+   表单将需要跟踪它正在编辑的记录，或者是否是新记录。

+   我们的用户需要一些视觉指示来指示正在编辑的记录。

+   我们的保存按钮当前在应用程序中。它在表单之外没有任何意义，因此它可能应该是表单的一部分。

+   这意味着我们的表单将需要一个在单击保存按钮时调用的回调。我们需要像我们的其他视图一样为它提供一个 `callbacks` 字典。

# 更新 `__init__()`

让我们从我们的 `__init__()` 方法开始逐步进行这些工作：

```py
    def __init__(self, parent, fields, 
                 settings, callbacks, *args, **kwargs):
        self.callbacks = callbacks
```

我们正在添加一个新的参数 `callbacks`，并将其存储为实例属性。这将为控制器提供一种方法来提供视图调用的方法。

接下来，我们的 `__init__()` 方法应该设置一个变量来存储当前记录：

```py
        self.current_record = None
```

我们将使用 `None` 来指示没有加载记录，表单正在用于创建新记录。否则，这个值将是一个引用 CSV 数据中行的整数。

我们可以在这里使用一个 Tkinter 变量，但在这种情况下没有真正的优势，而且我们将无法使用 `None` 作为值。

在表单顶部，在第一个表单字段之前，让我们添加一个标签，用于跟踪我们正在编辑的记录：

```py
        self.record_label = ttk.Label()
        self.record_label.grid(row=0, column=0)
```

我们将其放在第`0`行，第`0`列，但第一个`LabelFrame`也在那个位置。您需要逐个检查每个`LabelFrame`，并在其对`grid`的调用中递增`row`值。

我们将确保每当记录加载到表单中时，此标签都会得到更新。

在小部件的最后，`Notes`字段之后，让我们添加我们的新保存按钮如下：

```py
        self.savebutton = ttk.Button(self,
            text="Save", command=self.callbacks["on_save"])
        self.savebutton.grid(sticky="e", row=5, padx=10)
```

当点击按钮时，按钮将调用`callbacks`字典中的`on_save()`方法。在`Application`中创建`DataRecordForm`时，我们需要确保提供这个方法。

# 添加`load_record()`方法

在我们的视图中添加的最后一件事是加载新记录的方法。这个方法需要使用控制器中给定的行号和数据字典设置我们的表单。

让我们将其命名为`load_record()`如下：

```py
    def load_record(self, rownum, data=None):
```

我们应该首先从提供的`rownum`设置表单的`current_record`值：

```py
        self.current_record = rownum
```

回想一下，`rownum`可能是`None`，表示这是一个新记录。

让我们通过执行以下代码来检查：

```py
        if rownum is None:
            self.reset()
            self.record_label.config(text='New Record')
```

如果我们要插入新记录，我们只需重置表单，然后将标签设置为指示这是新记录。

请注意，这里的`if`条件专门检查`rownum`是否为`None`；我们不能只检查`rownum`的真值，因为`0`是一个有效的用于更新的`rownum`！

如果我们有一个有效的`rownum`，我们需要让它表现得不同：

```py
        else:
            self.record_label.config(text='Record #{}'.format(rownum))
            for key, widget in self.inputs.items():
                self.inputs[key].set(data.get(key, ''))
                try:
                    widget.input.trigger_focusout_validation()
                except AttributeError:
                    pass
```

在这个块中，我们首先使用正在编辑的行号适当地设置标签。

然后，我们循环遍历`inputs`字典的键和小部件，并从`data`字典中提取匹配的值。我们还尝试在每个小部件的输入上调用`trigger_focusout_validation()`方法，因为 CSV 文件可能包含无效数据。如果输入没有这样的方法（也就是说，如果我们使用的是常规的 Tkinter 小部件而不是我们的自定义小部件之一，比如`Checkbutton`），我们就什么也不做。

# 更新应用程序的其余部分

在我们对表单进行更改生效之前，我们需要更新应用程序的其余部分以实现新功能。我们的主菜单需要一些导航项，以便用户可以在记录列表和表单之间切换，并且需要在`Application`中创建或更新控制器方法，以整合我们的新模型和视图功能。

# 主菜单更改

由于我们已经在`views.py`文件中，让我们首先通过一些命令来在我们的主菜单视图中切换记录列表和记录表单。我们将在我们的菜单中添加一个`Go`菜单，其中包含两个选项，允许在记录列表和空白记录表单之间切换。

在`Options`和`Help`菜单之间添加以下行：

```py
        go_menu = tk.Menu(self, tearoff=False)
        go_menu.add_command(label="Record List",
                         command=callbacks['show_recordlist'])
        go_menu.add_command(label="New Record",
                         command=callbacks['new_record'])
        self.add_cascade(label='Go', menu=go_menu)
```

与以前一样，我们将这些菜单命令绑定到`callbacks`字典中的函数，我们需要在`Application`类中添加这些函数。

# 在应用程序中连接各部分

让我们快速盘点一下我们需要在`Application`类中进行的以下更改：

+   我们需要添加一个`RecordList`视图的实例

+   我们需要更新我们对`CSVModel`的使用，以便可以从中访问数据

+   我们需要实现或重构视图使用的几个回调方法

# 添加`RecordList`视图

我们将在`__init__()`中创建`RecordList`对象，就在`DataRecordForm`之后，通过执行以下代码片段：

```py
        self.recordlist = v.RecordList(self, self.callbacks)
        self.recordlist.grid(row=1, padx=10, sticky='NSEW')
```

请注意，当我们调用`grid()`时，我们将`RecordList`视图添加到已经包含`DataRecordForm`的网格单元中。**这是有意的**。当我们这样做时，Tkinter 会将第二个小部件堆叠在第一个小部件上，就像将一张纸放在另一张纸上一样；我们将在稍后添加代码来控制哪个视图可见，通过将其中一个提升到堆栈的顶部。请注意，我们还将小部件粘贴到单元格的所有边缘。如果没有这段代码，一个小部件的一部分可能会在另一个小部件的后面可见。

类似地，我们需要更新记录表单的`grid`调用如下：

```py
        self.recordform.grid(row=1, padx=10, sticky='NSEW')
```

# 移动模型

目前，我们的数据模型对象仅在`on_save()`方法中创建，并且每次用户保存时都会重新创建。我们将要编写的其他一些回调函数也需要访问模型，因此我们将在`Application`类启动或选择新文件时创建一个可以由所有方法共享的单个数据模型实例。让我们看看以下步骤：

1.  首先，在创建`default_filename`后编辑`Application.__init__()`方法：

```py
        self.filename = tk.StringVar(value=default_filename)
        self.data_model = m.CSVModel(filename=self.filename.get())
```

1.  接下来，每当文件名更改时，`on_file_select()`方法需要重新创建`data_model`对象。

1.  将`on_file_select()`的结尾更改为以下代码：

```py
        if filename:
            self.filename.set(filename)
            self.data_model = m.CSVModel(filename=self.filename.get())
```

现在，`self.data_model`将始终指向当前数据模型，我们的所有方法都可以使用它来保存或读取数据。

# 填充记录列表

`Treeview`小部件已添加到我们的应用程序中，但我们需要一种方法来用数据填充它。

我们将通过执行以下代码创建一个名为`populate_recordlist()`的方法：

```py
    def populate_recordlist(self):
```

逻辑很简单：只需从模型中获取所有行并将它们发送到记录列表的`populate()`方法。

我们可以简单地写成这样：

```py
        rows = self.data_model.get_all_records()
        self.recordlist.populate(rows)
```

但要记住，如果文件出现问题，`get_all_records()`将引发一个`Exception`；我们需要捕获该异常并让用户知道出了问题。

使用以下代码更新代码：

```py
        try:
            rows = self.data_model.get_all_records()
        except Exception as e:
            messagebox.showerror(title='Error',
                message='Problem reading file',
                detail=str(e))
        else:
            self.recordlist.populate(rows)
```

在这种情况下，如果我们从`get_all_records()`获得异常，我们将显示一个显示`Exception`文本的错误对话框。

`RecordList`视图应在创建新模型时重新填充；目前，这在`Application.__init__()`和`Application.on_file_select()`中发生。

在创建记录列表后立即更新`__init__()`：

```py
        self.recordlist = v.RecordList(self, self.callbacks)
        self.recordlist.grid(row=1, padx=10, sticky='NSEW')
        self.populate_recordlist()
```

在`if filename:`块的最后，更新`on_file_select()`如下：

```py
        if filename:
            self.filename.set(filename)
            self.data_model = m.CSVModel(filename=self.filename.get())
            self.populate_recordlist()
```

# 添加新的回调函数

检查我们的视图代码，以下回调函数需要添加到我们的`callbacks`字典中：

+   `show_recordlist()`：当用户点击菜单中的记录列表选项时调用此函数，它应该导致记录列表可见

+   `new_record()`：当用户点击菜单中的新记录时调用此函数，它应该显示一个重置的`DataRecordForm`

+   `on_open_record()`：当打开记录列表项时调用此函数，它应该显示填充有记录 ID 和数据的`DataRecordForm`

+   `on_save()`：当点击保存按钮（现在是`DataRecordForm`的一部分）时调用此函数，它应该导致记录表单中的数据被更新或插入模型。

我们将从`show_recordlist()`开始：

```py
    def show_recordlist(self):
        """Show the recordform"""
        self.recordlist.tkraise()
```

记住，当我们布置主应用程序时，我们将`recordlist`叠放在数据输入表单上，以便一个遮挡另一个。`tkraise()`方法可以在任何 Tkinter 小部件上调用，将其提升到小部件堆栈的顶部。在这里调用它将使我们的`RecordList`小部件升至顶部并遮挡数据输入表单。

不要忘记将以下内容添加到`callbacks`字典中：

```py
        self.callbacks = {
             'show_recordlist': self.show_recordlist,
             ...
```

`new_record()`和`on_open_record()`回调都会导致`recordform`被显示；一个在没有行号的情况下调用，另一个在有行号的情况下调用。我们可以在一个方法中轻松地回答这两个问题。

让我们称这个方法为`open_record()`：

```py
    def open_record(self, rownum=None):
```

记住我们的`DataRecordForm.load_record()`方法需要一个行号和一个`data`字典，如果行号是`None`，它会重置表单以进行新记录。所以，我们只需要设置行号和记录，然后将它们传递给`load_record()`方法。

首先，我们将处理`rownum`为`None`的情况：

```py
        if rownum is None:
            record = None
```

没有行号，就没有记录。很简单。

现在，如果有行号，我们需要尝试从模型中获取该行并将其用于`record`：

```py
        else:
            rownum = int(rownum)
            record = self.data_model.get_record(rownum)
```

请注意，Tkinter 可能会将`rownum`作为字符串传递，因为`Treeview`的`iid`值是字符串。我们将进行安全转换为`int`，因为这是我们的模型所期望的。

记住，如果在读取文件时出现问题，模型会抛出`Exception`，所以我们应该捕获这个异常。

将`get_record()`的调用放在`try`块中：

```py
        try:
            record = self.data_model.get_record(rownum)
        except Exception as e:
            messagebox.showerror(title='Error',
                message='Problem reading file',
                detail=str(e))
            return
```

在出现`Exception`的情况下，我们将显示一个错误对话框，并在不改变任何内容的情况下从函数中返回。

有了正确设置的`rownum`和`record`，现在我们可以将它们传递给`DataRecordForm`：

```py
        self.recordform.load_record(rownum, record)
```

最后，我们需要提升`form`小部件，使其位于记录列表的顶部：

```py
        self.recordform.tkraise()
```

现在，我们可以更新我们的`callbacks`字典，将这些键指向新的方法：

```py
        self.callbacks = {
            'new_record': self.open_record,
            'on_open_record': self.open_record,
            ...
```

你可以说我们不应该在这里有相同的方法，而只是让我们的视图拉取相同的键；然而，让视图在语义上引用回调是有意义的——也就是说，根据它们打算实现的目标，而不是它是如何实现的——然后让控制器确定哪段代码最符合这个语义需求。如果在某个时候，我们需要将这些分成两个方法，我们只需要在`Application`中做这个操作。

我们已经有了一个`on_save()`方法，所以将其添加到我们的回调中就足够简单了：

```py
        self.callbacks = {
            ...
            'on_save': self.on_save
        }
```

然而，我们当前的`on_save()`方法只处理插入新记录。我们需要修复这个问题。

首先，我们可以删除获取文件名和创建模型的两行，因为我们可以直接使用`Application`对象的`data_model`属性。

现在，用以下内容替换下面的两行：

```py
        data = self.recordform.get()
        rownum = self.recordform.current_record
        try:
            self.data_model.save_record(data, rownum)
```

我们只需要从`DataRecordForm`中获取数据和当前记录，然后将它们传递给模型的`save_record()`方法。记住，如果我们发送`None`的`rownum`，模型将插入一个新记录；否则，它将更新该行号的记录。

因为`save_record()`可能会抛出几种不同的异常，所以它在这里是在一个`try`块下面。

首先，如果我们尝试更新一个不存在的行号，我们会得到`IndexError`，所以让我们捕获它：

```py
        except IndexError as e:
            messagebox.showerror(title='Error',
                message='Invalid row specified', detail=str(e))
            self.status.set('Tried to update invalid row')
```

在出现问题的情况下，我们将显示一个错误对话框并更新状态文本。

`save_record()`方法也可能会抛出一个通用的`Exception`，因为它调用了模型的`get_all_records()`方法。

我们也会捕获这个异常，并显示一个适当的错误：

```py
        except Exception as e:
            messagebox.showerror(title='Error',
                message='Problem saving record', detail=str(e))
            self.status.set('Problem saving record')
```

这个方法中剩下的代码只有在没有抛出异常时才应该运行，所以将它移动到一个`else`块下面：

```py
    else:
        self.records_saved += 1
        self.status.set(
            "{} records saved this session".format(self.records_saved)
        )
        self.recordform.reset()
```

由于插入或更新记录通常会导致记录列表的更改，所以在成功保存文件后，我们还应该重新填充记录列表。

在`if`块下面添加以下行：

```py
            self.populate_recordlist()
```

最后，我们只想在插入新文件时重置记录表单；如果不是，我们应该什么都不做。

将对`recordform.reset()`的调用放在一个`if`块下面：

```py
            if self.recordform.current_record is None:
                self.recordform.reset()
```

# 清理

在退出`application.py`之前，确保删除保存按钮的代码，因为我们已经将该 UI 部分移动到`DataRecordForm`中。

在`__init__()`中查找这些行并删除它们：

```py
        self.savebutton = ttk.Button(self, text="Save",
                                     command=self.on_save)
        self.savebutton.grid(sticky="e", row=2, padx=10)
```

你还可以将`statusbar`的位置上移一行：

```py
        self.statusbar.grid(sticky="we", row=2, padx=10)
```

# 测试我们的程序

此时，您应该能够运行应用程序并加载一个示例 CSV 文件，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/3b8b74a3-4a1c-4b7d-b269-4110be95eabf.png)

确保尝试打开记录，编辑和保存它，以及插入新记录和打开不同的文件。

你还应该测试以下错误条件：

+   尝试打开一个不是 CSV 文件的文件，或者一个带有不正确字段的 CSV 文件。会发生什么？

+   打开一个有效的 CSV 文件，选择一个记录进行编辑，然后在点击保存之前，选择一个不同的或空文件。会发生什么？

+   打开两个程序的副本，并将它们指向保存的 CSV 文件。尝试在程序之间交替编辑或更新操作。注意发生了什么。

# 摘要

我们已经将我们的程序从仅追加的形式改变为能够从现有文件加载、查看和更新数据的应用程序。您学会了如何制作读写模型，如何使用 ttk `Treeview`，以及如何修改现有的视图和控制器来读取和更新记录。

在我们的下一章中，我们将学习如何修改应用程序的外观和感觉。我们将学习如何使用小部件属性、样式和主题，以及如何使用位图图形。
