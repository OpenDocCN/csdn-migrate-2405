# Django 1.1 测试和调试教程（一）

> 原文：[`zh.annas-archive.org/md5/ECB5EEA8F49C43CEEB591D269760F77D`](https://zh.annas-archive.org/md5/ECB5EEA8F49C43CEEB591D269760F77D)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

在软件开发过程中，错误是一个耗时的负担。Django 的内置测试框架和调试支持有助于减轻这一负担。本书将教你使用 Django 和 Python 工具快速高效地消除错误，并确保 Django 应用程序正常运行。

本书将逐步引导你开发一个完整的样本 Django 应用程序。你将学习如何最好地测试和调试模型、视图、URL 配置、模板和模板标签。本书将帮助你集成并利用 Python 和 Django 应用程序丰富的外部测试和调试工具环境。

本书从基本的测试概述开始。它将强调测试时需要注意的地方。你将了解到不同类型的测试，每种测试的优缺点，以及 Django 提供的测试扩展的细节，这些扩展简化了测试 Django 应用程序的任务。你将看到外部工具如何集成到 Django 的框架中，提供更复杂的测试功能。

在调试方面，本书说明了如何解释 Django 调试错误页面提供的大量调试信息，以及如何利用日志记录和其他外部工具来了解代码的运行情况。

这本书是一个逐步指南，教你如何使用 Django 的测试支持，并充分利用 Django 和 Python 调试工具。

# 本书内容

在第一章，“Django 测试概述”中，我们开始开发一个样本 Django 调查应用程序。描述并运行了 Django 自动生成的示例测试。介绍了运行测试的所有选项。

在第二章，“这段代码有效吗？深入了解 doctests”中，开发了样本应用程序使用的模型。通过示例说明了使用 doctests 来测试模型。讨论了 doctests 的优缺点。介绍了在 Django 应用程序中使用 doctests 的特定注意事项。

在第三章，“测试 1, 2, 3：基本单元测试”中，上一章实施的 doctests 被重新实施为单元测试，并根据上一章讨论的 doctests 的优缺点和注意事项进行评估。开发了需要使用测试数据的其他测试。演示了使用 fixture 文件加载此类数据。此外，还开发了一些不适合使用 fixture 文件的测试数据的测试。

在第四章，“变得更加花哨：Django 单元测试扩展”中，我们开始编写为应用程序提供网页的视图。测试的数量开始变得显著，因此本章首先展示了如何用一个 tests 目录替换单个`tests.py`文件，以便更好地组织测试。然后，开发了用于视图的测试，演示了 Django 提供的单元测试扩展如何简化测试 Web 应用程序的任务。通过开发本章中进行的管理自定义的测试，演示了测试表单行为。

第五章，“填空：集成 Django 和其他测试工具”，展示了 Django 如何支持将其他测试工具集成到其框架中。书中介绍了两个例子。第一个例子说明了如何使用附加应用程序来生成测试覆盖信息，而第二个例子演示了如何将`twill`测试工具（允许更轻松地测试表单行为）集成到 Django 应用程序测试中。

第六章，“Django 调试概述”，介绍了调试 Django 应用程序的主题。描述了所有与调试相关的设置。介绍了调试错误页面。描述了在调试打开时 Django 维护的数据库查询历史，以及开发服务器的功能，有助于调试。最后，详细介绍了在生产过程中（调试关闭时）发生的错误处理，并提到了确保捕获并发送有关此类错误信息的所有必要设置。

在第七章，“当车轮脱落时：理解 Django 调试页面”，继续开发示例应用程序，在这个过程中犯了一些典型的错误。这些错误导致了 Django 调试页面。描述了这些页面上提供的所有信息，并给出了在什么情况下最有帮助的部分的指导。深入讨论了几种不同类型的调试页面。

第八章，“当问题隐藏时：获取更多信息”，着重介绍了在问题不会导致调试错误页面的情况下如何获取有关代码行为的更多信息。它演示了开发模板标签以在呈现页面中嵌入视图的查询历史的过程，然后展示了如何使用 Django 调试工具栏来获取相同的信息，以及更多信息。最后，开发了一些日志记录工具。

第九章，“当您甚至不知道要记录什么时：使用调试器”，通过示例演示了如何使用 Python 调试器（pdb）来跟踪在没有调试页面出现甚至日志也无法帮助的情况下出现问题。通过示例演示了所有最有用的 pdb 命令。此外，我们还看到了如何使用 pdb 来确保对于受多进程竞争条件影响的代码的正确行为。

第十章，“当一切都失败时：寻求外部帮助”，描述了当迄今为止的技术都未能解决问题时该怎么办。可能是外部代码中的错误：提供了如何搜索以查看其他人是否有相同经历以及是否有任何修复的提示。可能是我们代码中的错误或对某些工作原理的误解；包括了提问的途径和写好问题的提示。

在第十一章，“当是时候上线了：转向生产”，我们将示例应用程序移入生产环境，使用 Apache 和`mod_wsgi`代替开发服务器。涵盖了在此步骤中遇到的几种常见问题。此外，还讨论了在开发过程中使用 Apache 与`mod_wsgi`的选项。

# 本书需要以下内容：

您需要一台运行 Django 1.1 版本的计算机——建议使用最新的 1.1.X 版本。您还需要一个编辑器来编辑代码文件和一个网络浏览器。您可以选择使用您最熟悉的操作系统、编辑和浏览工具，只要选择一个可以运行 Django 的操作系统。有关 Django 要求的更多信息，请参阅[`docs.djangoproject.com/en/1.1/intro/install/`](http://docs.djangoproject.com/en/1.1/intro/install/)。

供您参考，本书中的示例控制台输出和屏幕截图都来自一台运行以下内容的计算机：

+   Ubuntu 8.10

+   Python 2.5.2

+   Django 1.1（书中早期）和 1.1.1（书中后期）

+   Firefox 3.5.7

您可以使用 Django 支持的任何数据库。为了说明的目的，在本书的不同部分使用了不同的数据库（SQLite、MySQL、PostgreSQL）。您可能更愿意选择一个数据库来贯穿使用。

本书在特定的点使用了额外的软件。每当引入一个软件包时，都会包括有关在哪里获取它以进行安装的说明。供您参考，以下是本书中使用的额外软件包及其版本的列表：

+   第五章 *填补空白：集成 Django 和其他测试工具* 使用：

+   coverage 3.2

+   django_coverage 1.0.1

+   twill 0.9（和最新的开发级别）

+   第八章 *当问题隐藏时：获取更多信息* 使用：

+   django-debug-toolbar 0.8.0

+   第九章 *当你甚至不知道要记录什么：使用调试器* 使用：

+   pygooglechart 0.2.0

+   matplotlib 0.98.3

+   第十一章 *当是时候上线了：转向生产* 使用：

+   Apache 2.2

+   mod_wsgi 2.3

+   siege 2.6.6

请注意，当您开始阅读本书时，您不需要安装这些额外的软件包中的任何一个，它们可以在您想要开始使用它们的特定点上添加。列出的版本是书中显示的输出所使用的版本；预计稍后的版本也将起作用，尽管如果您使用更新的版本，产生的输出可能会略有不同。

# 本书的受众

如果您是一名 Django 应用程序开发人员，希望快速创建稳健的应用程序，并且长期易于维护，那么本书适合您。如果您希望聪明地学习如何充分利用 Django 丰富的测试和调试支持，并使开发变得轻松，那么本书是您的不二选择。

假定您具有 Python、Django 和基于数据库的 Web 应用程序的整体结构的基本知识。但是，代码示例已经得到充分解释，以便即使是对这个领域新手的初学者也可以从本书中学到很多知识。如果您是 Django 的新手，建议您在开始阅读本书之前先完成在线 Django 教程。

# 约定

在本书中，您将找到一些文本样式，用于区分不同类型的信息。以下是一些这些样式的示例，以及它们的含义解释。

文本中的代码词如下所示：“现在我们有了 Django 项目和应用的基本骨架：一个`settings.py`文件，一个`urls.py`文件，`manage.py`实用程序，以及一个包含模型、视图和测试的`.py`文件的`survey`目录。”

代码块设置如下：

```py
__test__ = {"doctest": """
Another way to test that 1 + 1 is equal to 2.

>>> 1 + 1 == 2
True
"""}
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```py
urlpatterns = patterns('', 
    # Example: 
    # (r'^marketr/', include('marketr.foo.urls')), 

    # Uncomment the admin/doc line below and add # 'django.contrib.admindocs' 
    # to INSTALLED_APPS to enable admin documentation: 
    # (r'^admin/doc/', include('django.contrib.admindocs.urls')), 

    # Uncomment the next line to enable the admin: 
    (r'^admin/', include(admin.site.urls)), 
 (r'', include('survey.urls')), 
) 
```

任何命令行输入或输出都以以下方式编写：

```py
kmt@lbox:/dj_projects$ django-admin.py startproject marketr

```

**新术语**和**重要单词**以粗体显示。您在屏幕上看到的单词，例如菜单或对话框中的单词，会以这样的方式出现在文本中：“此下拉框包含我们可以搜索的所有票据属性的完整列表，例如**报告人**、**所有者**、**状态**和**组件**。”

### 注意

警告或重要说明会以这样的方式出现在框中。

### 提示

提示和技巧会以这样的方式出现。


# 第一章：Django 测试概述

您如何知道您编写的代码是否按预期工作？好吧，您测试它。但是如何测试？对于 Web 应用程序，您可以通过手动在 Web 浏览器中打开应用程序的页面并验证它们是否正确来测试代码。这不仅涉及快速浏览以查看它们是否具有正确的内容，还必须确保例如所有链接都有效，任何表单都能正常工作等。正如您可以想象的那样，这种手动测试很快就会在应用程序增长到几个简单页面以上时变得不可靠。对于任何非平凡的应用程序，自动化测试是必不可少的。

Django 应用程序的自动化测试利用了 Python 语言内置的基本测试支持：doctests 和单元测试。当您使用`manage.py startapp`创建一个新的 Django 应用程序时，生成的文件之一包含一个样本 doctest 和单元测试，旨在加速您自己的测试编写。在本章中，我们将开始学习测试 Django 应用程序。具体来说，我们将：

+   详细检查样本`tests.py`文件的内容，同时回顾 Python 测试支持的基本知识

+   查看如何使用 Django 实用程序来运行`tests.py`中包含的测试

+   学习如何解释测试的输出，无论测试成功还是失败

+   审查可以在测试时使用的各种命令行选项的影响

# 入门：创建一个新应用程序

让我们开始创建一个新的 Django 项目和应用程序。为了在整本书中有一致的工作内容，让我们假设我们打算创建一个新的市场调研类型的网站。在这一点上，我们不需要对这个网站做出太多决定，只需要为 Django 项目和至少一个将包含的应用程序取一些名称。由于`market_research`有点长，让我们将其缩短为`marketr`作为项目名称。我们可以使用`django-admin.py`来创建一个新的 Django 项目：

```py
kmt@lbox:/dj_projects$ django-admin.py startproject marketr

```

然后，从新的`marketr`目录中，我们可以使用`manage.py`实用程序创建一个新的 Django 应用程序。我们市场调研项目的核心应用程序之一将是一个调查应用程序，因此我们将从创建它开始：

```py
kmt@lbox:/dj_projects/marketr$ python manage.py startapp survey

```

现在我们有了 Django 项目和应用程序的基本框架：`settings.py`文件，`urls.py`文件，`manage.py`实用程序，以及一个包含模型、视图和测试的`survey`目录。自动生成的模型和视图文件中没有实质性内容，但在`tests.py`文件中有两个样本测试：一个单元测试和一个 doctest。接下来我们将详细检查每个测试。

# 理解样本单元测试

单元测试是`tests.py`中包含的第一个测试，它开始于：

```py
""" 
This file demonstrates two different styles of tests (one doctest and one unittest). These will both pass when you run "manage.py test". 

Replace these with more appropriate tests for your application. 
"""

from django.test import TestCase 

class SimpleTest(TestCase): 
    def test_basic_addition(self): 
        """ 
        Tests that 1 + 1 always equals 2\. 
        """ 
        self.failUnlessEqual(1 + 1, 2) 
```

单元测试从`django.test`中导入`TestCase`开始。`django.test.TestCase`类基于 Python 的`unittest.TestCase`，因此它提供了来自基础 Python`unittest.TestCase`的一切，以及对测试 Django 应用程序有用的功能。这些对`unittest.TestCase`的 Django 扩展将在第三章和第四章中详细介绍。这里的样本单元测试实际上并不需要任何支持，但是将样本测试用例基于 Django 类也没有坏处。

然后，样本单元测试声明了一个基于 Django 的`TestCase`的`SimpleTest`类，并在该类中定义了一个名为`test_basic_addition`的测试方法。该方法包含一条语句：

```py
self.failUnlessEqual(1 + 1, 2)
```

正如你所期望的那样，该语句将导致测试用例报告失败，除非两个提供的参数相等。按照编码的方式，我们期望该测试会成功。我们将在本章稍后验证这一点，当我们实际运行测试时。但首先，让我们更仔细地看一下示例 doctest。

# 理解示例 doctest

示例`tests.py`的 doctest 部分是：

```py
__test__ = {"doctest": """
Another way to test that 1 + 1 is equal to 2.

>>> 1 + 1 == 2
True
"""}
```

这看起来比单元测试部分更神秘。对于示例 doctest，声明了一个特殊变量`__test__`。这个变量被设置为包含一个键`doctest`的字典。这个键被设置为一个类似于包含注释后面的字符串值的 docstring，后面跟着一个看起来像是交互式 Python shell 会话的片段。

看起来像交互式 Python shell 会话的部分就是 doctest 的组成部分。也就是说，以`>>>`开头的行将在测试期间执行（减去`>>>`前缀），并且实际产生的输出将与 doctest 中以`>>>`开头的行下面找到的预期输出进行比较。如果任何实际输出与预期输出不匹配，则测试失败。对于这个示例测试，我们期望在交互式 Python shell 会话中输入`1 + 1 == 2`会导致解释器产生输出`True`，所以看起来这个示例测试应该通过。

请注意，doctests 不必通过使用特殊的`__test__`字典来定义。实际上，Python 的 doctest 测试运行器会查找文件中所有文档字符串中的 doctests。在 Python 中，文档字符串是模块、函数、类或方法定义中的第一条语句。鉴于此，你会期望在`tests.py`文件顶部的注释中找到的交互式 Python shell 会话片段也会作为 doctest 运行。这是我们开始运行这些测试后可以尝试的另一件事情。

# 运行示例测试

示例`tests.py`文件顶部的注释说明了两个测试：`当你运行"manage.py test"时都会通过`。所以让我们看看如果我们尝试那样会发生什么：

```py
kmt@lbox:/dj_projects/marketr$ python manage.py test 
Creating test database... 
Traceback (most recent call last): 
 File "manage.py", line 11, in <module> 
 execute_manager(settings) 
 File "/usr/lib/python2.5/site-packages/django/core/management/__init__.py", line 362, in execute_manager 
 utility.execute() 
 File "/usr/lib/python2.5/site-packages/django/core/management/__init__.py", line 303, in execute 
 self.fetch_command(subcommand).run_from_argv(self.argv) 
 File "/usr/lib/python2.5/site-packages/django/core/management/base.py", line 195, in run_from_argv 
 self.execute(*args, **options.__dict__) 
 File "/usr/lib/python2.5/site-packages/django/core/management/base.py", line 222, in execute 
 output = self.handle(*args, **options) 
 File "/usr/lib/python2.5/site-packages/django/core/management/commands/test.py", line 23, in handle 
 failures = test_runner(test_labels, verbosity=verbosity, interactive=interactive) 
 File "/usr/lib/python2.5/site-packages/django/test/simple.py", line 191, in run_tests 
 connection.creation.create_test_db(verbosity, autoclobber=not interactive) 
 File "/usr/lib/python2.5/site-packages/django/db/backends/creation.py", line 327, in create_test_db 
 test_database_name = self._create_test_db(verbosity, autoclobber) 
 File "/usr/lib/python2.5/site-packages/django/db/backends/creation.py", line 363, in _create_test_db 
 cursor = self.connection.cursor() 
 File "/usr/lib/python2.5/site-packages/django/db/backends/dummy/base.py", line 15, in complain 
 raise ImproperlyConfigured, "You haven't set the DATABASE_ENGINE setting yet." 
django.core.exceptions.ImproperlyConfigured: You haven't set the DATABASE_ENGINE setting yet.

```

哎呀，我们似乎有点超前了。我们创建了新的 Django 项目和应用程序，但从未编辑设置文件以指定任何数据库信息。显然，我们需要这样做才能运行测试。

但测试是否会使用我们在`settings.py`中指定的生产数据库？这可能令人担忧，因为我们可能在某个时候在我们的测试中编写了一些我们不希望对我们的生产数据执行的操作。幸运的是，这不是问题。Django 测试运行器为运行测试创建了一个全新的数据库，使用它来运行测试，并在测试运行结束时删除它。这个数据库的名称是`test_`后跟`settings.py`中指定的`DATABASE_NAME`。因此，运行测试不会干扰生产数据。

为了运行示例`tests.py`文件，我们需要首先为`DATABASE_ENGINE`、`DATABASE_NAME`和`settings.py`中使用的数据库所需的其他任何内容设置适当的值。现在也是一个好时机将我们的`survey`应用程序和`django.contrib.admin`添加到`INSTALLED_APPS`中，因为我们在继续进行时会需要这两个。一旦这些更改已经在`settings.py`中进行了，`manage.py test`就能更好地工作：

```py
kmt@lbox:/dj_projects/marketr$ python manage.py test 
Creating test database... 
Creating table auth_permission 
Creating table auth_group 
Creating table auth_user 
Creating table auth_message 
Creating table django_content_type 
Creating table django_session 
Creating table django_site 
Creating table django_admin_log 
Installing index for auth.Permission model 
Installing index for auth.Message model 
Installing index for admin.LogEntry model 
................................... 
---------------------------------------------------------------------- 
Ran 35 tests in 2.012s 

OK 
Destroying test database...

```

看起来不错。但到底测试了什么？在最后，它说`Ran 35 tests`，所以肯定运行了比我们简单的`tests.py`文件中的两个测试更多的测试。其他 33 个测试来自`settings.py`中默认列出的其他应用程序：auth、content types、sessions 和 sites。这些 Django“contrib”应用程序附带了它们自己的测试，并且默认情况下，`manage.py test`会运行`INSTALLED_APPS`中列出的所有应用程序的测试。

### 注意

请注意，如果您没有将`django.contrib.admin`添加到`settings.py`中的`INSTALLED_APPS`列表中，则`manage.py test`可能会报告一些测试失败。对于 Django 1.1，`django.contrib.auth`的一些测试依赖于`django.contrib.admin`也包含在`INSTALLED_APPS`中，以便测试通过。这种相互依赖关系可能会在将来得到修复，但是现在最简单的方法是从一开始就将`django.contrib.admin`包含在`INTALLED_APPS`中，以避免可能的错误。无论如何，我们很快就会想要使用它。

可以仅运行特定应用程序的测试。要做到这一点，在命令行上指定应用程序名称。例如，仅运行`survey`应用程序的测试：

```py
kmt@lbox:/dj_projects/marketr$ python manage.py test survey 
Creating test database... 
Creating table auth_permission 
Creating table auth_group 
Creating table auth_user 
Creating table auth_message 
Creating table django_content_type 
Creating table django_session 
Creating table django_site 
Creating table django_admin_log 
Installing index for auth.Permission model 
Installing index for auth.Message model 
Installing index for admin.LogEntry model 
.. 
---------------------------------------------------------------------- 
Ran 2 tests in 0.039s 

OK 
Destroying test database... 

```

在这里——`Ran 2 tests`看起来适合我们的样本`tests.py`文件。但是关于创建表和安装索引的所有这些消息呢？为什么这些应用程序的表在不进行测试时被创建？这是因为测试运行程序不知道将要测试的应用程序与`INSTALLED_APPS`中列出的其他不打算进行测试的应用程序之间可能存在的依赖关系。

例如，我们的调查应用程序可能具有一个模型，其中包含对`django.contrib.auth User`模型的`ForeignKey`，并且调查应用程序的测试可能依赖于能够添加和查询`User`条目。如果测试运行程序忽略了对不进行测试的应用程序创建表，这将无法工作。因此，测试运行程序为`INSTALLED_APPS`中列出的所有应用程序创建表，即使不打算运行测试的应用程序也是如此。

我们现在知道如何运行测试，如何将测试限制在我们感兴趣的应用程序上，以及成功的测试运行是什么样子。但是，测试失败呢？在实际工作中，我们可能会遇到相当多的失败，因此确保我们了解测试输出在发生时的情况是很重要的。因此，在下一节中，我们将引入一些故意的破坏，以便我们可以探索失败的样子，并确保当我们遇到真正的失败时，我们将知道如何正确解释测试运行的报告。

# 故意破坏事物

让我们首先引入一个单一的简单失败。更改单元测试，期望将`1 + 1`加上`3`而不是`2`。也就是说，更改单元测试中的单个语句为：`self.failUnlessEqual(1 + 1, 3)`。

现在当我们运行测试时，我们会得到一个失败：

```py
kmt@lbox:/dj_projects/marketr$ python manage.py test
Creating test database... 
Creating table auth_permission 
Creating table auth_group 
Creating table auth_user 
Creating table auth_message 
Creating table django_content_type 
Creating table django_session 
Creating table django_site 
Creating table django_admin_log 
Installing index for auth.Permission model
Installing index for auth.Message model 
Installing index for admin.LogEntry model 
...........................F.......
====================================================================== 
FAIL: test_basic_addition (survey.tests.SimpleTest) 
---------------------------------------------------------------------- 
Traceback (most recent call last): 
 File "/dj_projects/marketr/survey/tests.py", line 15, in test_basic_addition 
 self.failUnlessEqual(1 + 1, 3) 
AssertionError: 2 != 3 

---------------------------------------------------------------------- 
Ran 35 tests in 2.759s 

FAILED (failures=1) 
Destroying test database...

```

看起来相当简单。失败产生了一块以等号开头的输出，然后是失败的测试的具体内容。失败的方法被识别出来，以及包含它的类。有一个`Traceback`显示了生成失败的确切代码行，`AssertionError`显示了失败原因的细节。

注意等号上面的那一行——它包含一堆点和一个`F`。这是什么意思？这是我们在早期测试输出列表中忽略的一行。如果你现在回去看一下，你会发现在最后一个`Installing index`消息之后一直有一行点的数量。这行是在运行测试时生成的，打印的内容取决于测试结果。`F`表示测试失败，点表示测试通过。当有足够多的测试需要一段时间来运行时，这种实时进度更新可以帮助我们在运行过程中了解运行的情况。

最后，在测试输出的末尾，我们看到`FAILED (failures=1)`而不是之前看到的`OK`。任何测试失败都会使整体测试运行的结果变成失败，而不是成功。

接下来，让我们看看一个失败的 doctest 是什么样子。如果我们将单元测试恢复到其原始形式，并将 doctest 更改为期望 Python 解释器对`1 + 1 == 3`作出`True`的回应，那么运行测试（这次只限制在`survey`应用程序中进行测试）将产生以下输出：

```py
kmt@lbox:/dj_projects/marketr$ python manage.py test survey 
Creating test database... 
Creating table auth_permission 
Creating table auth_group 
Creating table auth_user 
Creating table auth_message 
Creating table django_content_type 
Creating table django_session 
Creating table django_site 
Creating table django_admin_log 
Installing index for auth.Permission model 
Installing index for auth.Message model 
Installing index for admin.LogEntry model 
.F 
====================================================================== 
FAIL: Doctest: survey.tests.__test__.doctest 
---------------------------------------------------------------------- 
Traceback (most recent call last): 
 File "/usr/lib/python2.5/site-packages/django/test/_doctest.py", line 2180, in runTest 
 raise self.failureException(self.format_failure(new.getvalue())) 
AssertionError: Failed doctest test for survey.tests.__test__.doctest 
 File "/dj_projects/marketr/survey/tests.py", line unknown line number, in doctest 

---------------------------------------------------------------------- 
File "/dj_projects/marketr/survey/tests.py", line ?, in survey.tests.__test__.doctest 
Failed example: 
 1 + 1 == 3 
Expected: 
 True 
Got: 
 False 

---------------------------------------------------------------------- 
Ran 2 tests in 0.054s 

FAILED (failures=1) 
Destroying test database... 

```

失败的 doctest 的输出比单元测试失败的输出稍微冗长，解释起来也没有那么直接。失败的 doctest 被标识为`survey.tests.__test__.doctest`——这意味着在`survey/tests.py`文件中定义的`__test__`字典中的`doctest`键。输出的`Traceback`部分不像在单元测试案例中那样有用，因为`AssertionError`只是指出 doctest 失败了。幸运的是，随后提供了导致失败的原因的详细信息，您可以看到导致失败的行的内容，期望的输出以及执行失败行产生的实际输出。

请注意，测试运行器没有准确定位`tests.py`中发生失败的行号。它报告了不同部分的`未知行号`和`第?行`。这是 doctest 的一般问题还是这个特定 doctest 的定义方式的结果，作为`__test__`字典的一部分？我们可以通过在`tests.py`顶部的文档字符串中放置一个测试来回答这个问题。让我们将示例 doctest 恢复到其原始状态，并将文件顶部更改为如下所示：

```py
""" 
This file demonstrates two different styles of tests (one doctest and one unittest). These will both pass when you run "manage.py test". 

Replace these with more appropriate tests for your application. 

>>> 1 + 1 == 3 
True
""" 
```

然后当我们运行测试时，我们得到：

```py
kmt@lbox:/dj_projects/marketr$ python manage.py test survey 
Creating test database... 
Creating table auth_permission 
Creating table auth_group 
Creating table auth_user 
Creating table auth_message 
Creating table django_content_type 
Creating table django_session 
Creating table django_site 
Creating table django_admin_log 
Installing index for auth.Permission model 
Installing index for auth.Message model 
Installing index for admin.LogEntry model 
.F. 
====================================================================== 
FAIL: Doctest: survey.tests 
---------------------------------------------------------------------- 
Traceback (most recent call last): 
 File "/usr/lib/python2.5/site-packages/django/test/_doctest.py", line 2180, in runTest 
 raise self.failureException(self.format_failure(new.getvalue())) 
AssertionError: Failed doctest test for survey.tests 
 File "/dj_projects/marketr/survey/tests.py", line 0, in tests 

---------------------------------------------------------------------- 
File "/dj_projects/marketr/survey/tests.py", line 7, in survey.tests 
Failed example: 
 1 + 1 == 3 
Expected: 
 True 
Got: 
 False 

---------------------------------------------------------------------- 
Ran 3 tests in 0.052s 

FAILED (failures=1) 
Destroying test database... 

```

这里提供了行号。`Traceback`部分显然标识了包含失败测试行的文档字符串开始的行的上面一行（文档字符串从`第 1 行`开始，而回溯报告`第 0 行`）。详细的失败输出标识了导致失败的文件中的实际行，本例中为`第 7 行`。

无法准确定位行号因此是在`__test__`字典中定义 doctest 的副作用。虽然在我们简单的测试中很容易看出哪一行导致了问题，但在编写更实质性的 doctest 放置在`__test__`字典中时，这是需要牢记的事情。如果测试中的多行是相同的，并且其中一行导致失败，可能很难确定导致问题的确切行号，因为失败输出不会标识发生失败的具体行号。

到目前为止，我们在样本测试中引入的所有错误都涉及预期输出与实际结果不匹配。这些被报告为测试失败。除了测试失败，有时我们可能会遇到测试错误。接下来描述这些。

# 测试错误与测试失败

看看测试错误是什么样子，让我们删除上一节介绍的失败的 doctest，并在我们的样本单元测试中引入一种不同类型的错误。假设我们想要测试`1 + 1`是否等于文字`2`，而是想要测试它是否等于一个函数`sum_args`的结果，该函数应该返回其参数的总和。但我们会犯一个错误，忘记导入该函数。所以将`self.failUnlessEqual`改为：

```py
self.failUnlessEqual(1 + 1, sum_args(1, 1))
```

现在当运行测试时，我们看到：

```py
kmt@lbox:/dj_projects/marketr$ python manage.py test survey 
Creating test database... 
Creating table auth_permission 
Creating table auth_group 
Creating table auth_user 
Creating table auth_message 
Creating table django_content_type 
Creating table django_session 
Creating table django_site 
Creating table django_admin_log 
Installing index for auth.Permission model 
Installing index for auth.Message model 
Installing index for admin.LogEntry model 
E. 
====================================================================== 
ERROR: test_basic_addition (survey.tests.SimpleTest) 
---------------------------------------------------------------------- 
Traceback (most recent call last): 
 File "/dj_projects/marketr/survey/tests.py", line 15, in test_basic_addition 
 self.failUnlessEqual(1 + 1, sum_args(1, 1)) 
NameError: global name 'sum_args' is not defined 

---------------------------------------------------------------------- 
Ran 2 tests in 0.041s 

FAILED (errors=1) 
Destroying test database... 

```

测试运行器在甚至比较`1 + 1`和`sum_args`的返回值之前就遇到了异常，因为`sum_args`没有被导入。在这种情况下，错误在于测试本身，但如果`sum_args`中的代码引起问题，它仍然会被报告为错误，而不是失败。失败意味着实际结果与预期结果不匹配，而错误意味着在测试运行期间遇到了一些其他问题（异常）。错误可能暗示测试本身存在错误，但不一定必须意味着如此。

请注意，在 doctest 中发生的类似错误会报告为失败，而不是错误。例如，我们可以将 doctest 的`1 + 1`行更改为：

```py
>>> 1 + 1 == sum_args(1, 1) 
```

然后运行测试，输出将是：

```py
kmt@lbox:/dj_projects/marketr$ python manage.py test survey 
Creating test database... 
Creating table auth_permission 
Creating table auth_group 
Creating table auth_user 
Creating table auth_message 
Creating table django_content_type 
Creating table django_session 
Creating table django_site 
Creating table django_admin_log 
Installing index for auth.Permission model 
Installing index for auth.Message model 
Installing index for admin.LogEntry model 
EF 
====================================================================== 
ERROR: test_basic_addition (survey.tests.SimpleTest) 
---------------------------------------------------------------------- 
Traceback (most recent call last): 
 File "/dj_projects/marketr/survey/tests.py", line 15, in test_basic_addition 
 self.failUnlessEqual(1 + 1, sum_args(1, 1)) 
NameError: global name 'sum_args' is not defined 

====================================================================== 
FAIL: Doctest: survey.tests.__test__.doctest 
---------------------------------------------------------------------- 
Traceback (most recent call last): 
 File "/usr/lib/python2.5/site-packages/django/test/_doctest.py", line 2180, in runTest 
 raise self.failureException(self.format_failure(new.getvalue())) 
AssertionError: Failed doctest test for survey.tests.__test__.doctest 
 File "/dj_projects/marketr/survey/tests.py", line unknown line number, in doctest 

---------------------------------------------------------------------- 
File "/dj_projects/marketr/survey/tests.py", line ?, in survey.tests.__test__.doctest 
Failed example: 
 1 + 1 == sum_args(1, 1) 
Exception raised: 
 Traceback (most recent call last): 
 File "/usr/lib/python2.5/site-packages/django/test/_doctest.py", line 1267, in __run 
 compileflags, 1) in test.globs 
 File "<doctest survey.tests.__test__.doctest[0]>", line 1, in <module> 
 1 + 1 == sum_args(1, 1) 
 NameError: name 'sum_args' is not defined 

---------------------------------------------------------------------- 
Ran 2 tests in 0.044s 

FAILED (failures=1, errors=1) 
Destroying test database... 

```

因此，对于单元测试所做的错误与失败的区分并不一定适用于 doctests。因此，如果您的测试包括 doctests，则在最后打印的失败和错误计数摘要并不一定反映出产生意外结果的测试数量（单元测试失败计数）或出现其他错误的测试数量（单元测试错误计数）。但是，在任何情况下，都不希望出现失败或错误。最终目标是两者都为零，因此如果它们之间的差异有时有点模糊，那也没什么大不了的。不过，了解在什么情况下报告一个而不是另一个可能是有用的。

我们现在已经了解了如何运行测试，以及整体成功和一些失败和错误的结果是什么样子。接下来，我们将研究`manage.py test`命令支持的各种命令行选项。

# 运行测试的命令行选项

除了在命令行上指定要测试的确切应用程序之外，还有哪些控制`manage.py` test 行为的选项？找出的最简单方法是尝试使用`--help`选项运行命令：

```py
kmt@lbox:/dj_projects/marketr$ python manage.py test --help
Usage: manage.py test [options] [appname ...]

Runs the test suite for the specified applications, or the entire site if no apps are specified.

Options:
 -v VERBOSITY, --verbosity=VERBOSITY
 Verbosity level; 0=minimal output, 1=normal output,
 2=all output
 --settings=SETTINGS   The Python path to a settings module, e.g.
 "myproject.settings.main". If this isn't provided, the
 DJANGO_SETTINGS_MODULE environment variable will 
 be used.
 --pythonpath=PYTHONPATH
 A directory to add to the Python path, e.g.
 "/home/djangoprojects/myproject".
 --traceback           Print traceback on exception
 --noinput             Tells Django to NOT prompt the user for input of 
 any kind.
 --version             show program's version number and exit
 -h, --help            show this help message and exit

```

让我们依次考虑每个（除了`help`，因为我们已经看到它的作用）：

## 冗长度

冗长度是一个介于`0`和`2`之间的数字值。它控制测试产生多少输出。默认值为`1`，因此到目前为止我们看到的输出对应于指定`-v 1`或`--verbosity=1`。将冗长度设置为`0`会抑制有关创建测试数据库和表的所有消息，但不包括摘要、失败或错误信息。如果我们纠正上一节引入的最后一个 doctest 失败，并重新运行指定`-v0`的测试，我们将看到：

```py
kmt@lbox:/dj_projects/marketr$ python manage.py test survey -v0 
====================================================================== 
ERROR: test_basic_addition (survey.tests.SimpleTest) 
---------------------------------------------------------------------- 
Traceback (most recent call last): 
 File "/dj_projects/marketr/survey/tests.py", line 15, in test_basic_addition 
 self.failUnlessEqual(1 + 1, sum_args(1, 1)) 
NameError: global name 'sum_args' is not defined 

---------------------------------------------------------------------- 
Ran 2 tests in 0.008s 

FAILED (errors=1) 

```

将冗长度设置为`2`会产生更多的输出。如果我们修复这个剩下的错误，并将冗长度设置为最高级别运行测试，我们将看到：

```py
kmt@lbox:/dj_projects/marketr$ python manage.py test survey --verbosity=2 
Creating test database... 
Processing auth.Permission model 
Creating table auth_permission 
Processing auth.Group model 
Creating table auth_group 
 **[...more snipped...]**

**Creating many-to-many tables for auth.Group model** 
**Creating many-to-many tables for auth.User model** 
**Running post-sync handlers for application auth** 
**Adding permission 'auth | permission | Can add permission'** 
**Adding permission 'auth | permission | Can change permission'** 
 ****[...more snipped...]**

**No custom SQL for auth.Permission model** 
**No custom SQL for auth.Group model** 

**[...more snipped...]**
 ****Installing index for auth.Permission model** 
**Installing index for auth.Message model** 
**Installing index for admin.LogEntry model** 
**Loading 'initial_data' fixtures...** 
**Checking '/usr/lib/python2.5/site-packages/django/contrib/auth/fixtures' for fixtures...** 
**Trying '/usr/lib/python2.5/site-packages/django/contrib/auth/fixtures' for initial_data.xml fixture 'initial_data'...** 
**No xml fixture 'initial_data' in '/usr/lib/python2.5/site-packages/django/contrib/auth/fixtures'.** 

**[....much more snipped...]**
**No fixtures found.** 
**test_basic_addition (survey.tests.SimpleTest) ... ok** 
**Doctest: survey.tests.__test__.doctest ... ok** 

**----------------------------------------------------------------------** 
**Ran 2 tests in 0.004s** 

**OK** 
**Destroying test database...****** 
```

正如您所看到的，以这种详细程度，该命令报告了设置测试数据库所做的一切细节。除了我们之前看到的创建数据库表和索引之外，我们现在看到数据库设置阶段包括：

1.  运行`post-syncdb`信号处理程序。例如，`django.contrib.auth`应用程序使用此信号在安装每个应用程序时自动添加模型的权限。因此，您会看到有关在为`INSTALLED_APPS`中列出的每个应用程序发送`post-syncdb`信号时创建权限的消息。

1.  为数据库中已创建的每个模型运行自定义 SQL。根据输出，似乎`INSTALLED_APPS`中的任何应用程序都没有使用自定义 SQL。

1.  加载`initial_data` fixtures。初始数据 fixtures 是一种自动预先填充数据库的常量数据的方法。我们在`INSTALLED_APPS`中列出的任何应用程序都没有使用此功能，但是测试运行程序会产生大量输出，因为它寻找初始数据 fixtures，这些 fixtures 可以在几种不同的名称下找到。对于每个被检查的可能文件以及是否找到任何内容，都会有消息。如果测试运行程序找到初始数据 fixtures 时遇到问题，这些输出可能会在某个时候派上用场（我们将在第三章中详细介绍 fixtures），但是目前这些输出并不是很有趣。

****一旦测试运行程序完成初始化数据库，它就会开始运行测试。在`2`的冗长级别下，我们之前看到的点、Fs 和 Es 的行会被每个测试的更详细的报告所取代。测试的名称被打印出来，然后是三个点，然后是测试结果，可能是`ok`、`ERROR`或`FAIL`。如果有任何错误或失败，它们发生的详细信息将在测试运行结束时打印出来。因此，当您观看冗长的测试运行时，设置冗长级别为`2`，您将能够看到哪些测试遇到了问题，但直到运行完成，您才能得到它们发生原因的详细信息。

## ****设置****

****您可以将设置选项传递给`test`命令，以指定要使用的设置文件，而不是项目默认的设置文件。例如，如果要使用与通常使用的数据库不同的数据库运行测试（无论是为了加快测试速度还是验证代码在不同数据库上是否正确运行），则可以派上用场。

****请注意，此选项的帮助文本说明`DJANGO_SETTINGS_MODULE`环境变量将用于定位设置文件，如果未在命令行上指定设置选项。当使用`django-admin.py`实用程序运行`test`命令时，这才是准确的。当使用`manage.py test`时，`manage.py`实用程序负责设置此环境变量以指定当前目录中的`settings.py`文件。

## ****Pythonpath****

****此选项允许您在测试运行期间将附加目录追加到 Python 路径中。当使用`django-admin.py`时，通常需要将项目路径添加到标准 Python 路径中。`manage.py`实用程序负责将项目路径添加到 Python 路径中，因此在使用`manage.py test`时通常不需要此选项。

## ****Traceback****

****实际上，`test`命令并不使用此选项。它作为所有`django-admin.py`（和`manage.py`）命令支持的默认选项之一而被继承，但`test`命令从不检查它。因此，您可以指定它，但它不会产生任何效果。

## ****Noinput****

****此选项导致测试运行程序不会提示用户输入，这引发了一个问题：测试运行程序何时需要用户输入？到目前为止，我们还没有遇到过。测试运行程序在测试数据库创建期间会提示用户输入，如果测试数据库名称已经存在。例如，如果在测试运行期间按下*Ctrl* + *C*，则测试数据库可能不会被销毁，下次尝试运行测试时可能会遇到类似以下消息：

```py
****kmt@lbox:/dj_projects/marketr$ python manage.py test** 
**Creating test database...** 
**Got an error creating the test database: (1007, "Can't create database 'test_marketr'; database exists")** 
**Type 'yes' if you would like to try deleting the test database 'test_marketr', or 'no' to cancel:**** 
```

****如果在命令行上传递了`--noinput`，则不会打印提示，并且测试运行程序将继续进行，就好像用户已经输入了'yes'一样。如果要从无人值守脚本运行测试，并确保脚本不会在等待永远不会输入的用户输入时挂起，这将非常有用。

## ****版本****

此选项报告正在使用的 Django 版本，然后退出。因此，当使用`--version`与`manage.py`或`django-admin.py`一起使用时，实际上不需要指定`test`等子命令。实际上，由于 Django 处理命令选项的方式存在错误，在撰写本书时，如果同时指定`--version`和子命令，版本将被打印两次。这可能会在某个时候得到修复。

****# 摘要

Django 测试的概述现在已经完成。在本章中，我们：

+   详细查看了在创建新的 Django 应用程序时生成的样本`tests.py`文件

+   学习如何运行提供的样本测试

+   尝试在测试中引入故意的错误，以查看和理解测试失败或遇到错误时提供的信息

+   最后，我们检查了所有可能与`manage.py test`一起使用的命令行选项。

我们将在下一章继续建立这些知识，重点关注深入的 doctests。


# 第二章：这段代码有效吗？深入了解文档测试

在第一章中，我们学习了如何运行`manage.py startapp`创建的示例测试。虽然我们使用了 Django 实用程序来运行测试，但是示例测试本身与 Django 无关。在本章中，我们将开始详细介绍如何为 Django 应用程序编写测试。我们将：

+   通过开发一些基本模型来开始编写第一章创建的市场调研项目

+   尝试向其中一个模型添加文档测试

+   开始学习哪些测试是有用的，哪些只会给代码增加混乱

+   发现文档测试的一些优缺点

上一章提到了文档测试和单元测试，而本章的重点将专门放在文档测试上。开发 Django 应用程序的单元测试将是第三章和第四章的重点。

# 调查应用程序模型

开始开发新的 Django 应用程序的常见地方是从模型开始：这些数据的基本构建块将由应用程序进行操作和存储。我们示例市场调研`survey`应用程序的基石模型将是`Survey`模型。

`Survey`将类似于 Django 教程`Poll`模型，只是：

+   教程`Poll`只包含一个问题，而`Survey`将有多个问题。

+   `Survey`将有一个标题用于参考目的。对于教程`Poll`，可以使用一个单一的问题。

+   `Survey`只会在有限的时间内（取决于`Survey`实例）开放回应。虽然`Poll`模型有一个`pub_date`字段，但它除了在索引页面上对`Polls`进行排序之外没有用。因此，`Survey`将需要两个日期字段，而`Poll`只有一个，`Survey`的日期字段将比`Poll pub_date`字段更常用。

只需这些简单的要求，我们就可以开始为`Survey`开发 Django 模型。具体来说，我们可以通过将以下内容添加到我们`survey`应用程序的自动生成的`models.py`文件中的代码来捕捉这些要求：

```py
class Survey(models.Model): 
    title = models.CharField(max_length=60) 
    opens = models.DateField() 
    closes = models.DateField() 
```

请注意，由于`Survey`可能有多个问题，它没有一个问题字段。相反，有一个单独的模型`Question`，用于保存与其相关的调查实例的问题：

```py
class Question(models.Model): 
    question = models.CharField(max_length=200) 
    survey = models.ForeignKey(Survey) 
```

我们需要的最终模型（至少是开始时）是一个用于保存每个问题的可能答案，并跟踪调查受访者选择每个答案的次数。这个模型`Answer`与教程`Choice`模型非常相似，只是它与`Question`相关联，而不是与`Poll`相关联：

```py
class Answer(models.Model): 
    answer = models.CharField(max_length=200) 
    question = models.ForeignKey(Question) 
    votes = models.IntegerField(default=0) 
```

# 测试调查模型

如果你和我一样，在这一点上你可能想要开始验证到目前为止是否正确。的确，现在还没有太多的代码，但特别是在项目刚开始的时候，我喜欢确保我到目前为止的东西是有效的。那么，我们如何开始测试？首先，我们可以通过运行`manage.py syncdb`来验证我们没有语法错误，这也会让我们在 Python shell 中开始尝试这些模型。让我们来做吧。由于这是我们为这个项目第一次运行`syncdb`，我们将收到关于为`INSTALLED_APPS`中列出的其他应用程序创建表的消息，并且我们将被问及是否要创建超级用户，我们也可以继续做。

## 测试调查模型创建

现在，我们可以用这些模型做些什么来在 Python shell 中测试它们？实际上，除了创建每个模型之外，我们并没有太多可做的事情，也许可以验证一下，如果我们没有指定其中一个字段，我们会得到一个错误，或者正确的默认值被分配，并验证我们是否可以遍历模型之间的关系。如果我们首先关注`Survey`模型以及为了测试其创建而可能做的事情，那么 Python shell 会话可能看起来像这样：

```py
kmt@lbox:/dj_projects/marketr$ python manage.py shell 
Python 2.5.2 (r252:60911, Oct  5 2008, 19:24:49) 
[GCC 4.3.2] on linux2 
Type "help", "copyright", "credits" or "license" for more information. 
(InteractiveConsole) 
>>> from survey.models import Survey 
>>> import datetime 
>>> t = 'First!'
>>> d = datetime.date.today()
>>> s = Survey.objects.create(title=t, opens=d, closes=d) 
>>>

```

在这里，我们首先导入了我们的`Survey`模型和 Python 的`datetime`模块，然后创建了一个变量`t`来保存一个标题字符串和一个变量`d`来保存一个日期值，并使用这些值创建了一个`Survey`实例。没有报告错误，所以看起来很好。

如果我们想验证一下，如果我们尝试创建一个没有关闭日期的`Survey`，我们会得到一个错误吗，我们将继续进行：

```py
>>> s = Survey.objects.create(title=t, opens=d, closes=None) 
 File "<console>", line 1, in <module> 
 File "/usr/lib/python2.5/site-packages/django/db/models/manager.py", line 126, in create 
 return self.get_query_set().create(**kwargs) 
 File "/usr/lib/python2.5/site-packages/django/db/models/query.py", line 315, in create 
 obj.save(force_insert=True) 
 File "/usr/lib/python2.5/site-packages/django/db/models/base.py", line 410, in save 
 self.save_base(force_insert=force_insert, force_update=force_update) 
 File "/usr/lib/python2.5/site-packages/django/db/models/base.py", line 495, in save_base 
 result = manager._insert(values, return_id=update_pk) 
 File "/usr/lib/python2.5/site-packages/django/db/models/manager.py", line 177, in _insert 
 return insert_query(self.model, values, **kwargs) 
 File "/usr/lib/python2.5/site-packages/django/db/models/query.py", line 1087, in insert_query 
 return query.execute_sql(return_id) 
 File "/usr/lib/python2.5/site-packages/django/db/models/sql/subqueries.py", line 320, in execute_sql 
 cursor = super(InsertQuery, self).execute_sql(None) 
 File "/usr/lib/python2.5/site-packages/django/db/models/sql/query.py", line 2369, in execute_sql 
 cursor.execute(sql, params) 
 File "/usr/lib/python2.5/site-packages/django/db/backends/util.py", line 19, in execute 
 return self.cursor.execute(sql, params) 
 File "/usr/lib/python2.5/site-packages/django/db/backends/sqlite3/base.py", line 193, in execute 
 return Database.Cursor.execute(self, query, params) 
IntegrityError: survey_survey.closes may not be NULL 

```

在这里，我们尝试创建`Survey`实例的唯一不同之处是为`closes`值指定了`None`，而不是传入我们的日期变量`d`。结果是一个以`IntegrityError`结尾的错误消息，因为调查表的关闭列不能为 null。这证实了我们对应该发生的预期，所以到目前为止一切都很好。然后我们可以对其他字段执行类似的测试，并看到相同的回溯报告了其他列的`IntegrityError`。

如果我们想的话，我们可以通过直接从 shell 会话中剪切和粘贴它们到我们的`survey/models.py`文件中，将这些测试变成我们模型定义的永久部分，就像这样：

```py
import datetime
from django.db import models 

class Survey(models.Model): 
    """ 
    >>> t = 'First!' 
    >>> d = datetime.date.today() 
    >>> s = Survey.objects.create(title=t, opens=d, closes=d) 
    >>> s = Survey.objects.create(title=t, opens=d, closes=None) 
    Traceback (most recent call last): 
    ... 
    IntegrityError: survey_survey.closes may not be NULL 
    >>> s = Survey.objects.create(title=t, opens=None, closes=d) 
    Traceback (most recent call last): 
    ... 
    IntegrityError: survey_survey.opens may not be NULL 
    >>> s = Survey.objects.create(title=None, opens=d, closes=d) 
    Traceback (most recent call last): 
    ... 
    IntegrityError: survey_survey.title may not be NULL 
    """ 
    title = models.CharField(max_length=60) 
    opens = models.DateField() 
    closes = models.DateField()
```

您可能已经注意到，所显示的结果并不是直接从 shell 会话中剪切和粘贴的。差异包括：

+   `import datetime`被移出了 doctest，并成为`models.py`文件中的代码的一部分。这并不是严格必要的——如果作为 doctest 的一部分，它也可以正常工作，但是如果导入在主代码中，那么在 doctest 中就不是必要的。由于`models.py`中的代码可能需要稍后使用`datetime`函数，因此现在将导入放在主代码中可以减少稍后的重复和混乱，当主代码需要导入时。

+   回溯的调用堆栈部分，也就是除了第一行和最后一行之外的所有内容，都被删除并替换为包含三个点的行。这也并不是严格必要的，只是为了去除杂乱，并突出结果的重要部分。doctest 运行器在决定测试成功或失败时会忽略调用堆栈的内容（如果预期输出中存在）。因此，如果调用堆栈具有一些解释价值，可以将其保留在测试中。然而，大部分情况下，最好删除调用堆栈，因为它们会产生大量杂乱，而提供的有用信息并不多。

如果我们现在运行`manage.py test survey -v2`，输出的最后部分将是：

```py
No fixtures found. 
test_basic_addition (survey.tests.SimpleTest) ... ok 
Doctest: survey.models.Survey ... ok 
Doctest: survey.tests.__test__.doctest ... ok 

---------------------------------------------------------------------- 
Ran 3 tests in 0.030s 

OK 
Destroying test database... 

```

我们仍然在`tests.py`中运行我们的样本测试，现在我们还可以看到我们的`survey.models.Survey` doctest 被列为正在运行并通过。

## 那个测试有用吗？

但等等；我们刚刚添加的测试有用吗？它实际上在测试什么？实际上并没有什么，除了验证基本的 Django 函数是否按照广告那样工作。它测试我们是否可以创建我们定义的模型的实例，并且我们在模型定义中指定为必需的字段实际上在关联的数据库表中是必需的。看起来这个测试更像是在测试 Django 的底层代码，而不是我们的应用程序。在我们的应用程序中测试 Django 本身并不是必要的：Django 有自己的测试套件，我们可以运行它进行测试（尽管可以相当安全地假设基本功能在任何发布版本的 Django 中都能正确工作）。

可以说，这个测试验证了模型中每个字段是否已经指定了正确和预期的选项，因此这是对应用程序而不仅仅是底层 Django 函数的测试。然而，测试那些通过检查就很明显的事情（对于任何具有基本 Django 知识的人来说）让我觉得有点过分。这不是我通常会在自己写的项目中包含的测试。

这并不是说我在开发过程中不会在 Python shell 中尝试类似的事情：我会的，而且我也会。但是在开发过程中在 shell 中尝试的并不是所有东西都需要成为应用程序中的永久测试。您想要包含在应用程序中的测试类型是那些对应用程序独特行为进行测试的测试。因此，让我们开始开发一些调查应用程序代码，并在 Python shell 中进行测试。当我们的代码工作正常时，我们可以评估哪些来自 shell 会话的测试是有用的。

## 开发自定义调查保存方法

要开始编写一些特定于应用程序的代码，请考虑对于调查模型，如果在创建模型实例时没有指定`closes`，我们可能希望允许`closes`字段假定默认值为`opens`后的一周。我们不能使用 Django 模型字段默认选项，因为我们想要分配的值取决于模型中的另一个字段。因此，我们通常会通过覆盖模型的保存方法来实现这一点。首次尝试实现这一点可能是：

```py
import datetime
from django.db import models  

class Survey(models.Model): 
    title = models.CharField(max_length=60) 
    opens = models.DateField() 
    closes = models.DateField() 

    def save(self, **kwargs): 
        if not self.pk and not self.closes: 
            self.closes = self.opens + datetime.timedelta(7) 
        super(Survey, self).save(**kwargs) 
```

也就是说，在调用`save`并且模型实例尚未分配主键（因此这是对数据库的第一次保存），并且没有指定`closes`的情况下，我们在调用超类`save`方法之前将`closes`赋予一个比`opens`晚一周的值。然后我们可以通过在 Python shell 中进行实验来测试这是否正常工作：

```py
kmt@lbox:/dj_projects/marketr$ python manage.py shell 
Python 2.5.2 (r252:60911, Oct  5 2008, 19:24:49) 
[GCC 4.3.2] on linux2 
Type "help", "copyright", "credits" or "license" for more information. 
(InteractiveConsole) 
>>> from survey.models import Survey 
>>> import datetime 
>>> t = "New Year's Resolutions" 
>>> sd = datetime.date(2009, 12, 28) 
>>> s = Survey.objects.create(title=t, opens=sd) 
>>> s.closes 
datetime.date(2010, 1, 4) 
>>> 

```

这与我们之前的测试非常相似，只是我们选择了一个特定的日期来分配给`opens`，而不是使用今天的日期，并且在创建`Survey`实例时没有指定`closes`的值，我们检查了分配给它的值。显示的值比`opens`晚一周，所以看起来很好。

请注意，故意选择`opens`日期，其中一周后的值将在下个月和年份是一个明智的选择。测试边界值总是一个好主意，也是一个好习惯，即使（就像这里一样）我们正在编写的代码中没有任何东西负责为边界情况得到正确的答案。

接下来，我们可能希望确保如果我们指定了`closes`的值，它会被尊重，而不会被默认的一周后的日期覆盖：

```py
>>> s = Survey.objects.create(title=t, opens=sd, closes=sd)
>>> s.opens 
datetime.date(2009, 12, 28) 
>>> s.closes 
datetime.date(2009, 12, 28) 
>>> 

```

所有看起来都很好，`opens`和`closes`显示为具有相同的值，就像我们在`create`调用中指定的那样。我们还可以验证，如果我们在模型已经保存后将`closes`重置为`None`，然后尝试再次保存，我们会得到一个错误。在现有模型实例上将`closes`重置为`None`将是代码中的错误。因此，我们在这里测试的是我们的`save`方法重写不会通过悄悄地重新分配一个值给`closes`来隐藏该错误。在我们的 shell 会话中，我们可以这样继续并查看：

```py
>>> s.closes = None 
>>> s.save() 
Traceback (most recent call last): 
 File "<console>", line 1, in <module> 
 File "/dj_projects/marketr/survey/models.py", line 12, in save 
 super(Survey, self).save(**kwargs) 
 File "/usr/lib/python2.5/site-packages/django/db/models/base.py", line 410, in save 
 self.save_base(force_insert=force_insert, force_update=force_update) 
 File "/usr/lib/python2.5/site-packages/django/db/models/base.py", line 474, in save_base 
 rows = manager.filter(pk=pk_val)._update(values) 
 File "/usr/lib/python2.5/site-packages/django/db/models/query.py", line 444, in _update 
 return query.execute_sql(None) 
 File "/usr/lib/python2.5/site-packages/django/db/models/sql/subqueries.py", line 120, in execute_sql 
 cursor = super(UpdateQuery, self).execute_sql(result_type) 
 File "/usr/lib/python2.5/site-packages/django/db/models/sql/query.py", line 2369, in execute_sql 
 cursor.execute(sql, params) 
 File "/usr/lib/python2.5/site-packages/django/db/backends/util.py", line 19, in execute 
 return self.cursor.execute(sql, params) 
 File "/usr/lib/python2.5/site-packages/django/db/backends/sqlite3/base.py", line 193, in execute 
 return Database.Cursor.execute(self, query, params) 
IntegrityError: survey_survey.closes may not be NULL 
>>> 

```

同样，这看起来很好，因为这是我们期望的结果。最后，由于我们已经将一些自己的代码插入到基本模型保存处理中，我们应该验证我们没有在`create`上没有指定`title`或`opens`字段的其他预期失败情况中出现问题。如果我们这样做，我们会发现没有指定`title`的情况下工作正常（我们在数据库标题列上得到了预期的`IntegrityError`），但如果`opens`和`closes`都没有指定，我们会得到一个意外的错误：

```py
>>> s = Survey.objects.create(title=t) 
Traceback (most recent call last): 
 File "<console>", line 1, in <module> 
 File "/usr/lib/python2.5/site-packages/django/db/models/manager.py", line 126, in create 
 return self.get_query_set().create(**kwargs) 
 File "/usr/lib/python2.5/site-packages/django/db/models/query.py", line 315, in create 
 obj.save(force_insert=True) 
 File "/dj_projects/marketr/survey/models.py", line 11, in save 
 self.closes = self.opens + datetime.timedelta(7) 
TypeError: unsupported operand type(s) for +: 'NoneType' and 'datetime.timedelta' 
>>> 

```

在这里，我们用一个相当晦涩的消息来报告我们留下了一个必需的值未指定的错误，而不是一个相当清晰的错误消息。问题是我们在尝试在`save`方法重写中使用`opens`之前没有检查它是否有值。为了获得这种情况下的正确（更清晰）错误，我们的`save`方法应该修改为如下所示：

```py
    def save(self, **kwargs): 
        if not self.pk and self.opens and not self.closes: 
            self.closes = self.opens + datetime.timedelta(7) 
        super(Survey, self).save(**kwargs) 
```

也就是说，如果`opens`没有被指定，我们不应该尝试设置`closes`。在这种情况下，我们直接将`save`调用转发到超类，并让正常的错误路径报告问题。然后，当我们尝试创建一个没有指定`opens`或`closes`值的`Survey`时，我们会看到：

```py
>>> s = Survey.objects.create(title=t) 
Traceback (most recent call last): 
 File "<console>", line 1, in <module> 
 File "/usr/lib/python2.5/site-packages/django/db/models/manager.py", line 126, in create 
 return self.get_query_set().create(**kwargs) 
 File "/usr/lib/python2.5/site-packages/django/db/models/query.py", line 315, in create 
 obj.save(force_insert=True) 
 File "/dj_projects/marketr/survey/models.py", line 12, in save 
 super(Survey, self).save(**kwargs) 
 File "/usr/lib/python2.5/site-packages/django/db/models/base.py", line 410, in save 
 self.save_base(force_insert=force_insert, force_update=force_update) 
 File "/usr/lib/python2.5/site-packages/django/db/models/base.py", line 495, in save_base 
 result = manager._insert(values, return_id=update_pk) 
 File "/usr/lib/python2.5/site-packages/django/db/models/manager.py", line 177, in _insert 
 return insert_query(self.model, values, **kwargs) 
 File "/usr/lib/python2.5/site-packages/django/db/models/query.py", line 1087, in insert_query 
 return query.execute_sql(return_id) 
 File "/usr/lib/python2.5/site-packages/django/db/models/sql/subqueries.py", line 320, in execute_sql 
 cursor = super(InsertQuery, self).execute_sql(None) 
 File "/usr/lib/python2.5/site-packages/django/db/models/sql/query.py", line 2369, in execute_sql 
 cursor.execute(sql, params) 
 File "/usr/lib/python2.5/site-packages/django/db/backends/util.py", line 19, in execute 
 return self.cursor.execute(sql, params) 
 File "/usr/lib/python2.5/site-packages/django/db/backends/sqlite3/base.py", line 193, in execute 
 return Database.Cursor.execute(self, query, params) 
IntegrityError: survey_survey.opens may not be NULL 
>>> 

```

这样会好得多，因为报告的错误直接指出了问题所在。

## 决定测试什么

在这一点上，我们相当确定我们的`save`重写正在按我们的意图工作。在我们为验证目的在 Python shell 中运行的所有测试中，哪些测试有意义地包含在代码中？这个问题的答案涉及判断，并且不同的人可能会有不同的答案。就我个人而言，我倾向于包括：

+   受代码直接影响的参数的所有测试

+   在对代码进行初始测试时遇到的任何测试，这些测试在我编写的原始代码版本中没有起作用

因此，我的`save`重写函数，包括带有注释的 doctests，可能看起来像这样：

```py
    def save(self, **kwargs): 
        """ 
        save override to allow for Survey instances to be created without explicitly specifying a closes date. If not specified, closes will be set to 7 days after opens. 
        >>> t = "New Year's Resolutions" 
        >>> sd = datetime.date(2009, 12, 28) 
        >>> s = Survey.objects.create(title=t, opens=sd) 
        >>> s.closes 
        datetime.date(2010, 1, 4) 

        If closes is specified, it will be honored and not auto-set. 

        >>> s = Survey.objects.create(title=t, opens=sd, closes=sd) 
        >>> s.closes 
        datetime.date(2009, 12, 28) 

        Any changes to closes after initial creation need to be explicit. Changing closes to None on an existing instance will not result in closes being reset to 7 days after opens. 

        >>> s.closes = None 
        >>> s.save() 
        Traceback (most recent call last): 
          ... 
        IntegrityError: survey_survey.closes may not be NULL 

        Making the mistake of specifying neither opens nor closes results in the expected IntegrityError for opens, not any exception in the code here. 

        >>> s = Survey.objects.create(title=t) 
        Traceback (most recent call last): 
          ... 
        IntegrityError: survey_survey.opens may not be NULL 
        """ 
        if not self.pk and self.opens and not self.closes: 
            self.closes = self.opens + datetime.timedelta(7) 
        super(Survey, self).save(**kwargs) 
```

## 到目前为止，doctests 的一些优缺点

即使只是通过研究这一个例子方法的经验，我们也可以开始看到 doctests 的一些优缺点。显然，可以很容易地重用在 Python shell 会话中完成的工作（这些工作很可能已经作为编码的一部分而被完成）用于永久测试目的。这使得更有可能为代码编写测试，并且测试本身不需要被调试。这是 doctests 的两个很好的优点。

第三个是 doctests 提供了代码预期行为的明确文档。散文描述可能模糊不清，而以测试形式的代码示例是不可能被误解的。此外，测试作为文档字符串的一部分，使它们可以被所有使用文档字符串自动生成帮助和文档的 Python 工具访问。

在这里包括测试有助于使文档完整。例如，将`closes`重置为`None`后的行为可能不明显，一个同样有效的设计是在`save`期间将`closes`重置为一周后的日期。在编写文档时很容易忽略这种细节。因此，在 doctest 中详细说明预期的行为是有帮助的，因为它会自动记录下来。

然而，这种测试兼作文档的特性也有一个缺点：您可能希望包括的一些测试实际上可能并不适合作为文档，并且您可能会得到一个对相当简单的代码而言文档过多的情况。考虑我们开发的`save`重写案例。它有四行代码和超过 30 行的文档字符串。这种比例对于一些具有许多参数或参数以非明显方式相互作用的复杂函数可能是合适的，但是对于这种简单的方法来说，文档比代码多近十倍似乎过多了。

让我们考虑`save`中的各个测试，重点是它们作为文档的有用性：

+   第一个测试显示了使用`title`和`opens`创建`Survey`，但没有`closes`，并验证了在创建后将正确值分配给`closes`，这是`save`重写允许调用者执行的示例。这是通过添加的代码启用的特定调用模式，并且因此作为文档是有用的，即使它在很大程度上重复了散文描述。

+   第二个测试显示了如果指定了`closes`，它将被遵守，这并不特别适合作为文档。任何程序员都会期望，如果指定了`closes`，它应该被遵守。这种行为可能适合测试，但不需要记录。

+   第三个测试展示了在现有的`Survey`实例上将`closes`重置为`None`后`save`的预期行为，出于前面提到的原因，这对于文档来说是有用的。

+   第四个和最后一个测试说明了添加的代码不会在未指定`opens`或`closes`的错误情况下引发意外异常。这是另一个需要测试但不需要记录的例子，因为正确的行为是显而易见的。

将我们的文档字符串的一半分类为不适合文档目的是不好的。当人们遇到明显的、冗余的或无用的信息时，他们往往会停止阅读。我们可以通过将这些测试从文档字符串方法移到我们的`tests.py`文件中来解决这个问题，而不放弃 doctests 的一些优势。如果我们采取这种方法，我们可能会改变`tests.py`中的`__test__`字典，使其看起来像这样：

```py
__test__ = {"survey_save": """ 

Tests for the Survey save override method. 

>>> import datetime 
>>> from survey.models import Survey 
>>> t = "New Year's Resolutions" 
>>> sd = datetime.date(2009, 12, 28) 

If closes is specified, it will be honored and not auto-set. 

>>> s = Survey.objects.create(title=t, opens=sd, closes=sd) 
>>> s.closes 
datetime.date(2009, 12, 28) 

Making the mistake of specifying neither opens nor closes results 
in the expected IntegrityError for opens, not any exception in the 
save override code itself. 

>>> s = Survey.objects.create(title=t) 
Traceback (most recent call last): 
  ... 
IntegrityError: survey_survey.opens may not be NULL 
"""} 
```

在这里，我们将测试的关键字从通用的`doctest`改为`survey_save`，这样任何测试输出中报告的测试名称都会给出被测试的提示。然后我们将“非文档”测试（以及现在需要在两个地方都设置的一些变量设置代码）从我们的`save`覆盖文档字符串中移到这里的键值中，并在顶部添加一般注释，说明测试的目的。

`save`方法本身的文档字符串中剩下的测试确实具有一定的文档价值：

```py
    def save(self, **kwargs): 
        """ 
        save override to allow for Survey instances to be created without explicitly specifying a closes date. If not specified, closes will be set to 7 days after opens. 
        >>> t = "New Year's Resolutions" 
        >>> sd = datetime.date(2009, 12, 28) 
        >>> s = Survey.objects.create(title=t, opens=sd) 
        >>> s.closes 
        datetime.date(2010, 1, 4) 

        Any changes to closes after initial creation need to be explicit. Changing closes to None on an existing instance will not result in closes being reset to 7 days after opens. 

        >>> s.closes = None 
        >>> s.save() 
        Traceback (most recent call last): 
          ... 
        IntegrityError: survey_survey.closes may not be NULL 

        """ 
        if not self.pk and self.opens and not self.closes: 
            self.closes = self.opens + datetime.timedelta(7) 
        super(Survey, self).save(**kwargs) 
```

这对于函数的文档字符串来说肯定更容易管理，不太可能会让在 Python shell 中键入`help(Survey.save)`的人感到不知所措。

这种方法也有其不利之处。代码的测试不再集中在一个地方，很难知道或轻松确定代码被完全测试了多少。如果有人在`tests.py`中遇到测试，却不知道方法的文档字符串中还有额外的测试，很可能会想知道为什么只测试了这两个边缘情况，为什么忽略了基本功能的直接测试。

此外，当添加测试时，可能不清楚（特别是对于新加入项目的程序员）新测试应该放在哪里。因此，即使项目一开始在文档字符串测试中有一个很好的清晰分割，“适合文档的测试”和“必要但不适合文档的测试”在`tests.py`文件中，随着时间的推移，这种区别可能很容易变得模糊。

因此，测试选择和放置涉及权衡。并不是每个项目都有“正确”的答案。然而，采用一致的方法是最好的。在选择这种方法时，每个项目团队都应该考虑诸如以下问题的答案：

+   **自动生成的基于文档字符串的文档的预期受众是谁？**

如果存在其他文档（或正在编写），预期它们将成为代码“使用者”的主要来源，那么具有不太好的文档功能的 doctests 可能并不是问题。

+   **可能会有多少人在代码上工作？**

如果人数相对较少且稳定，让每个人记住测试分散在两个地方可能不是什么大问题。对于一个较大的项目或者如果开发人员流动性较高，教育开发人员关于这种分割可能会成为更大的问题，而且可能更难维护一致的代码。

# 附加的 doctest 注意事项

Doctests 还有一些我们可能还没有遇到或注意到的额外缺点。其中一些只是我们需要注意的事项，如果我们想确保我们的 doctests 在各种环境中能正常工作，并且在我们的代码周围的代码发生变化时。其他更严重的问题最容易通过切换到单元测试而不是 doctests 来解决，至少对受影响的测试来说是这样。在本节中，我们将列出许多需要注意的额外 doctest 问题，并提供关于如何避免或克服这些问题的指导。

## 注意环境依赖

doctests 很容易无意中依赖于实际被测试的代码以外的代码的实现细节。我们在`save`覆盖测试中已经有了一些这样的情况，尽管我们还没有被这个问题绊倒。我们现在所面临的依赖实际上是一种非常特定的环境依赖——数据库依赖。由于数据库依赖本身就是一个相当大的问题，它将在下一节中详细讨论。然而，我们首先将介绍一些其他可能会遇到的次要环境依赖，并看看如何避免将它们包含在我们的测试中。

一种极其常见的环境依赖形式是依赖于对象的打印表示。例如，`__unicode__`方法是首先在模型类中实现的常见方法。它在之前的`Survey`模型讨论中被省略，因为那时并不需要，但实际上我们可能会在`save`覆盖之前实现`__unicode__`。对于`Survey`的第一次尝试`__unicode__`方法可能看起来像这样：

```py
    def __unicode__(self): 
        return u'%s (Opens %s, closes %s)' % (self.title, self.opens, self.closes) 
```

在这里，我们决定`Survey`实例的打印表示将由标题值后跟括号中的有关此调查何时开放和关闭的注释组成。鉴于该方法的定义，我们在测试创建实例时正确设置`closes`时的 shell 会话可能看起来像这样：

```py
>>> from survey.models import Survey 
>>> import datetime 
>>> sd = datetime.date(2009, 12, 28) 
>>> t = "New Year's Resolutions" 
>>> s = Survey.objects.create(title=t, opens=sd) 
>>> s 
<Survey: New Year's Resolutions (Opens 2009-12-28, closes 2010-01-04)> 
>>> 

```

也就是说，我们可能不是专门检查`closes`分配的值，而是显示已创建实例的打印表示，因为它包括`closes`的值。在 shell 会话中进行实验时，自然而然地会以这种方式进行检查，而不是直接询问相关属性。首先，这样做更短（`s`比`s.closes`更容易输入）。此外，它通常显示的信息比我们可能正在测试的特定部分更多，这在我们进行实验时是有帮助的。

然而，如果我们直接从 shell 会话中复制并粘贴到我们的`save`覆盖 doctest 中，我们就会使该 doctest 依赖于`__unicode__`的实现细节。随后，我们可能会决定不想在`Survey`的可打印表示中包含所有这些信息，甚至只是认为如果“Opens”中的“o”不大写会看起来更好。因此，我们对`__unicode__`方法的实现进行了微小的更改，突然间一个与其他方法无关的 doctest 开始失败了。

```py
====================================================================== 
FAIL: Doctest: survey.models.Survey.save 
---------------------------------------------------------------------- 
Traceback (most recent call last): 
 File "/usr/lib/python2.5/site-packages/django/test/_doctest.py", line 2189, in runTest 
 raise self.failureException(self.format_failure(new.getvalue())) 
AssertionError: Failed doctest test for survey.models.Survey.save 
 File "/dj_projects/marketr/survey/models.py", line 9, in save 

---------------------------------------------------------------------- 
File "/dj_projects/marketr/survey/models.py", line 32, in survey.models.Survey.save 
Failed example: 
 s 
Expected: 
 <Survey: New Year's Resolutions (Opens 2009-12-28, closes 2010-01-04)> 
Got: 
 <Survey: New Year's Resolutions (opens 2009-12-28, closes 2010-01-04)> 

---------------------------------------------------------------------- 
Ran 3 tests in 0.076s 

FAILED (failures=1) 
Destroying test database... 

```

因此，在从 shell 会话创建 doctests 时，需要仔细考虑会话是否依赖于被测试的代码以外的任何代码的实现细节，并相应地进行调整以消除这种依赖。在这种情况下，使用`s.closes`来测试`closes`被赋予了什么值，消除了对`Survey`模型`__unicode__`方法实现方式的依赖。

在 doctests 中可能会出现许多其他环境依赖的情况，包括：

+   任何依赖于文件路径打印表示的测试都可能会遇到问题，因为在基于 Unix 的操作系统上，路径组件由正斜杠分隔，而 Windows 使用反斜杠。如果需要包含依赖于文件路径值的 doctests，可能需要使用实用函数来规范不同操作系统上的文件路径表示。

+   任何依赖于字典键以特定顺序打印的测试都可能会遇到一个问题，即这个顺序在不同操作系统或 Python 实现中可能是不同的。因此，为了使这些测试在不同平台上更加健壮，可能需要专门查询字典键值，而不仅仅是打印整个字典内容，或者使用一个实用函数，为打印表示应用一致的顺序到键上。

关于这些在 doctests 中经常出现的环境依赖问题，没有什么特别与 Django 相关的内容。然而，在 Django 应用程序中特别容易出现一种环境依赖：数据库依赖。接下来将讨论这个问题。

## 警惕数据库依赖

Django 的**对象关系管理器**（**ORM**）非常费力地屏蔽应用程序代码与底层数据库的差异。但是，让所有不同的支持的数据库在所有情况下看起来完全相同对 Django 来说是不可行的。因此，在应用程序级别可能观察到特定于数据库的差异。这些差异可能很容易进入 doctests，使得测试依赖于特定的数据库后端才能通过。

这种依赖已经存在于本章早期开发的`save`覆盖测试中。因为 SQLite 是最容易使用的数据库（因为它不需要安装或配置），所以到目前为止，示例代码和测试都是使用`settings.py`中的`DATABASE_ENGINE = 'sqlite3'`设置开发的。如果我们切换到使用 MySQL（`DATABASE_ENGINE = 'mysql'`）作为数据库，并尝试运行我们的`survey`应用程序测试，我们将看到失败。有两个失败，但我们首先只关注测试输出中的最后一个：

```py
====================================================================== 
FAIL: Doctest: survey.tests.__test__.survey_save 
---------------------------------------------------------------------- 
Traceback (most recent call last): 
 File "/usr/lib/python2.5/site-packages/django/test/_doctest.py", line 2189, in runTest 
 raise self.failureException(self.format_failure(new.getvalue())) 
AssertionError: Failed doctest test for survey.tests.__test__.survey_save 
 File "/dj_projects/marketr/survey/tests.py", line unknown line number, in survey_save 

---------------------------------------------------------------------- 
File "/dj_projects/marketr/survey/tests.py", line ?, in survey.tests.__test__.survey_save 
Failed example: 
 s = Survey.objects.create(title=t) 
Expected: 
 Traceback (most recent call last): 
 ... 
 IntegrityError: survey_survey.opens may not be NULL 
Got: 
 Traceback (most recent call last): 
 File "/usr/lib/python2.5/site-packages/django/test/_doctest.py", line 1274, in __run 
 compileflags, 1) in test.globs 
 File "<doctest survey.tests.__test__.survey_save[6]>", line 1, in <module> 
 s = Survey.objects.create(title=t) 
 File "/usr/lib/python2.5/site-packages/django/db/models/manager.py", line 126, in create 
 return self.get_query_set().create(**kwargs) 
 File "/usr/lib/python2.5/site-packages/django/db/models/query.py", line 315, in create 
 obj.save(force_insert=True) 
 File "/dj_projects/marketr/survey/models.py", line 34, in save 
 super(Survey, self).save(**kwargs) 
 File "/usr/lib/python2.5/site-packages/django/db/models/base.py", line 410, in save 
 self.save_base(force_insert=force_insert, force_update=force_update) 
 File "/usr/lib/python2.5/site-packages/django/db/models/base.py", line 495, in save_base 
 result = manager._insert(values, return_id=update_pk) 
 File "/usr/lib/python2.5/site-packages/django/db/models/manager.py", line 177, in _insert 
 return insert_query(self.model, values, **kwargs) 
 File "/usr/lib/python2.5/site-packages/django/db/models/query.py", line 1087, in insert_query 
 return query.execute_sql(return_id) 
 File "/usr/lib/python2.5/site-packages/django/db/models/sql/subqueries.py", line 320, in execute_sql 
 cursor = super(InsertQuery, self).execute_sql(None) 
 File "/usr/lib/python2.5/site-packages/django/db/models/sql/query.py", line 2369, in execute_sql 
 cursor.execute(sql, params) 
 File "/usr/lib/python2.5/site-packages/django/db/backends/mysql/base.py", line 89, in execute 
 raise Database.IntegrityError(tuple(e)) 
 IntegrityError: (1048, "Column 'opens' cannot be null") 

---------------------------------------------------------------------- 
Ran 3 tests in 0.434s 

FAILED (failures=2) 
Destroying test database... 

```

这里的问题是什么？在`tests.py`中的 doctest 中的`save`调用中没有为`opens`指定值，预期会出现`IntegrityError`，而确实出现了`IntegrityError`，但`IntegrityError`消息的细节是不同的。SQLite 数据库返回：

```py
 IntegrityError: survey_survey.opens may not be NULL 

```

MySQL 以稍微不同的方式表达了同样的观点：

```py
 IntegrityError: (1048, "Column 'opens' cannot be null") 

```

有两种简单的方法可以解决这个问题。一种是在失败的测试上使用 doctest 指令`IGNORE_EXCEPTION_DETAIL`。使用此选项，doctest 运行程序在确定预期结果是否与实际结果匹配时，只会考虑异常的类型（在本例中为`IntegrityError`）。因此，不同数据库产生的确切异常消息的差异不会导致测试失败。

通过在包含测试的行上将 doctest 指令指定为单个测试来指定。注释以`doctest：`开头，后面跟着一个或多个指令名称，前面是`+`表示打开选项，`-`表示关闭选项。因此，在这种情况下，我们将更改`tests.py`中失败的测试行为（请注意，尽管此行在此页面上换行到第二行，但在测试中需要保持在一行上）：

```py
>>> s = Survey.objects.create(title=t) # doctest: +IGNORE_EXCEPTION_DETAIL 
```

另一种修复方法是用省略号替换测试中预期输出的详细消息部分，省略号是一个省略标记。也就是说，将测试更改为：

```py
>>> s = Survey.objects.create(title=t) 
Traceback (most recent call last): 
  ... 
IntegrityError: ... 
```

这是告诉 doctest 运行器忽略异常消息的具体方法。它依赖于 doctest 选项`ELLIPSIS`在 doctest 运行时被启用。虽然这个选项在 Python 中默认情况下是不启用的，但是 Django 使用的 doctest 运行器启用了它，所以你不需要在你的测试代码中做任何事情来启用期望输出中的省略号标记。还要注意，`ELLIPSIS`不仅仅适用于异常消息的细节；它是一种更一般的方法，让你指示 doctest 输出的部分可能因运行而异，而不会导致测试失败。

### 注意

如果你阅读了`ELLIPSIS`的 Python 文档，你可能会注意到它是在 Python 2.4 中引入的。因此，如果你正在运行 Python 2.3（这仍然是 Django 1.1 支持的），你可能会期望在你的 Django 应用程序的 doctests 中无法使用省略号标记技术。然而，Django 1.0 和 1.1 附带了一个定制的 doctest 运行器，当你运行你的应用程序的 doctests 时会使用它。这个定制的运行器是基于 Python 2.4 附带的 doctest 模块的。因此，即使你运行的是早期的 Python 版本，你也可以使用 Python 2.4 中的 doctest 选项，比如`ELLIPSIS`。

注意，尽管 Django 使用自己定制的 doctest 运行器的另一面是：如果你运行的 Python 版本比 2.4 更新，你不能在应用程序的 doctests 中使用比 2.4 更晚添加的 doctest 选项。例如，Python 在 Python 2.5 中添加了`SKIP`选项。在 Django 更新其定制的 doctest 模块的版本之前，你将无法在 Django 应用程序的 doctests 中使用这个新选项。

回想一下，有两次测试失败，我们只看了其中一个的输出（另一个很可能滚动得太快，无法阅读）。然而，考虑到我们检查过的一个失败，我们可能期望另一个也是一样的，因为在`models.py`的 doctest 中，我们对`IntegrityError`有一个非常相似的测试：

```py
        >>> s.closes = None 
        >>> s.save() 
        Traceback (most recent call last): 
          ... 
        IntegrityError: survey_survey.closes may not be NULL 
```

这肯定也需要被修复以忽略异常细节，所以我们可能会同时做这两件事，并且可能会纠正两个测试失败。事实上，当我们在将两个预期的`IntegrityErrors`都更改为包含省略号标记而不是具体错误消息后再次运行测试时，所有的测试都通过了。

### 注意

请注意，对于某些 MySQL 的配置，忽略异常细节将无法纠正第二个测试失败。具体来说，如果 MySQL 服务器配置为以“非严格”模式运行，尝试将行更新为包含`NULL`值的列声明为`NOT NULL`不会引发错误。相反，该值将设置为列类型的隐式默认值，并发出警告。

很可能，如果你正在使用 MySQL，你会想要配置它以在“严格模式”下运行。然而，如果由于某种原因你不能这样做，并且你需要在你的应用程序中有这样一个测试，并且你需要测试在多个数据库上通过，你将不得不考虑在你的测试中考虑数据库行为的差异。这是可以做到的，但在单元测试中更容易完成，而不是在 doctest 中，所以我们不会讨论如何修复这种情况的 doctest。

现在我们已经让我们的测试在两个不同的数据库后端上通过了，我们可能会认为我们已经准备好了，并且可能会在 Django 支持的所有数据库上获得一个干净的测试运行。我们错了，当我们尝试使用 PostgreSQL 作为数据库运行相同的测试时，我们会发现数据库的差异，这突出了在编写 doctests 时需要注意的下一项内容，并在下一节中进行了介绍。

## 注意测试之间的相互依赖

如果我们现在尝试使用 PostgreSQL 作为数据库运行我们的测试（在`settings.py`中指定`DATABASE_ENGINE = 'postgresql_psycopg2'`），我们会得到一个非常奇怪的结果。从`manage.py test survey -v2`的输出的末尾，我们看到：

```py
No fixtures found. 
test_basic_addition (survey.tests.SimpleTest) ... ok 
Doctest: survey.models.Survey.save ... ok 
Doctest: survey.tests.__test__.survey_save ... FAIL 

```

我们仍然在`tests.py`中有一个样本单元测试运行并通过，然后`models.py`中的 doctest 也通过了，但我们添加到`tests.py`中的 doctest 失败了。失败的细节是：

```py
====================================================================== 
FAIL: Doctest: survey.tests.__test__.survey_save 
---------------------------------------------------------------------- 
Traceback (most recent call last): 
 File "/usr/lib/python2.5/site-packages/django/test/_doctest.py", line 2189, in runTest 
 raise self.failureException(self.format_failure(new.getvalue())) 
AssertionError: Failed doctest test for survey.tests.__test__.survey_save 
 File "/dj_projects/marketr/survey/tests.py", line unknown line number, in survey_save 

---------------------------------------------------------------------- 
File "/dj_projects/marketr/survey/tests.py", line ?, in survey.tests.__test__.survey_save 
Failed example: 
 s = Survey.objects.create(title=t, opens=sd, closes=sd) 
Exception raised: 
 Traceback (most recent call last): 
 File "/usr/lib/python2.5/site-packages/django/test/_doctest.py", line 1274, in __run 
 compileflags, 1) in test.globs 
 File "<doctest survey.tests.__test__.survey_save[4]>", line 1, in <module> 
 s = Survey.objects.create(title=t, opens=sd, closes=sd) 
 File "/usr/lib/python2.5/site-packages/django/db/models/manager.py", line 126, in create 
 return self.get_query_set().create(**kwargs) 
 File "/usr/lib/python2.5/site-packages/django/db/models/query.py", line 315, in create 
 obj.save(force_insert=True) 
 File "/dj_projects/marketr/survey/models.py", line 34, in save 
 super(Survey, self).save(**kwargs)
 File "/usr/lib/python2.5/site-packages/django/db/models/base.py", line 410, in save 
 self.save_base(force_insert=force_insert, force_update=force_update) 
 File "/usr/lib/python2.5/site-packages/django/db/models/base.py", line 495, in save_base 
 result = manager._insert(values, return_id=update_pk) 
 File "/usr/lib/python2.5/site-packages/django/db/models/manager.py", line 177, in _insert 
 return insert_query(self.model, values, **kwargs) 
 File "/usr/lib/python2.5/site-packages/django/db/models/query.py", line 1087, in insert_query 
 return query.execute_sql(return_id) 
 File "/usr/lib/python2.5/site-packages/django/db/models/sql/subqueries.py", line 320, in execute_sql 
 cursor = super(InsertQuery, self).execute_sql(None) 
 File "/usr/lib/python2.5/site-packages/django/db/models/sql/query.py", line 2369, in execute_sql 
 cursor.execute(sql, params) 
 InternalError: current transaction is aborted, commands ignored until end of transaction block 

---------------------------------------------------------------------- 
File "/dj_projects/marketr/survey/tests.py", line ?, in survey.tests.__test__.survey_save 
Failed example: 
 s.closes 
Exception raised: 
 Traceback (most recent call last): 
 File "/usr/lib/python2.5/site-packages/django/test/_doctest.py", line 1274, in __run 
 compileflags, 1) in test.globs 
 File "<doctest survey.tests.__test__.survey_save[5]>", line 1, in <module> 
 s.closes 
 NameError: name 's' is not defined 
 ****----------------------------------------------------------------------** 
**Ran 3 tests in 0.807s** 
 ****FAILED (failures=1)** 
**Destroying test database...****** 
```

这次我们需要按顺序检查报告的错误，因为第二个错误是由第一个错误导致的。这种错误的链接是常见的，因此要记住，虽然从测试运行结束时最容易看到的最后一个失败开始可能很诱人，但这可能不是最有效的方法。如果不立即明显导致最后一个失败的原因，通常最好从头开始，找出导致第一个失败的原因。随后的失败原因可能会变得明显。供参考，正在失败的测试的开头是：

```py
**>>> import datetime 
>>> from survey.models import Survey 
>>> t = "New Year's Resolutions" 
>>> sd = datetime.date(2009, 12, 28) 

If closes is specified, it will be honored and not auto-set. 

>>> s = Survey.objects.create(title=t, opens=sd, closes=sd) 
>>> s.closes 
datetime.date(2009, 12, 28)** 
```

因此，根据测试输出，这个测试中对数据库的第一次访问——也就是尝试创建`Survey`实例——导致了错误。

```py
****InternalError: current transaction is aborted, commands ignored until end of transaction block****
```

然后，测试的下一行也会导致错误，因为它使用了应该在上一行中分配的变量`s`。然而，那一行没有完成执行，所以当测试尝试使用它时，变量`s`没有被定义。因此，第二个错误是有道理的，考虑到第一个错误，但为什么这个测试中的第一个数据库访问会导致错误呢？

为了理解这一点的解释，我们必须回顾一下紧接在这个测试之前运行的测试。从测试输出中我们可以看到，紧接在这个测试之前的测试是`models.py`中的 doctest。该测试的结尾是：

```py
 **>>> s.closes = None 
        >>> s.save() 
        Traceback (most recent call last): 
          ... 
        IntegrityError: ... 
        """** 
```

测试的最后一件事是预期引发数据库错误的事情。在 PostgreSQL 上的一个副作用是，数据库连接进入了一个状态，只允许结束事务块的命令。因此，这个测试结束时，数据库连接处于一个破碎的状态，当下一个 doctest 开始运行时，它仍然处于破碎状态，导致下一个 doctest 在尝试任何数据库访问时立即失败。

这个问题说明了 doctests 之间没有数据库隔离。一个 doctest 对数据库的操作可以被后续运行的 doctest 观察到。这包括在数据库表中创建、更新或删除行的问题，以及在这里看到的问题。这个特定的问题可以通过在故意引起数据库错误的代码后添加一个回滚当前事务的调用来解决。

```py
 **>>> s.closes = None 
        >>> s.save() 
        Traceback (most recent call last): 
          ... 
        IntegrityError: ... 
        >>> from django.db import transaction 
        >>> transaction.rollback() 
        """** 
```

这将允许测试在 PostgreSQL 上通过，并且在其他数据库后端上是无害的。因此，处理 doctests 中没有数据库隔离的一种方法是编写代码，使它们在自己之后进行清理。这可能是一个可以接受的方法，但如果测试已经在数据库中添加、修改或删除了对象，可能很难将一切恢复到最初的状态。

第二种方法是在每个 doctest 进入时将数据库重置为已知状态。Django 不会为您执行此操作，但您可以通过调用管理命令来手动执行。我通常不建议这种方法，因为随着应用程序的增长，它变得非常耗时。

第三种方法是使 doctests 在数据库状态上相对宽容，这样它们可能会在其他测试是否运行过的情况下正常运行。在这里使用的技术包括：

+   在测试本身创建测试所需的所有对象。也就是说，不要依赖于任何先前运行的测试创建的对象的存在，因为该测试可能会更改，或被删除，或测试运行的顺序可能会在某个时候更改。

+   在创建对象时，要防止与其他测试可能创建的相似对象发生冲突。例如，如果一个测试需要创建一个`is_superuser`字段设置为`True`的`User`实例，以便测试具有该属性的用户的某些行为，那么给`User`实例一个`username`为"superuser"可能是很自然的。然而，如果两个 doctest 都这样做了，那么不幸的是第二个运行的测试会遇到错误，因为`User`模型的`username`字段被声明为唯一，所以第二次尝试使用这个`username`创建`User`会失败。因此，最好使用在共享模型中不太可能被其他测试使用的唯一字段的值。

所有这些方法和技术都有其缺点。对于这个特定问题，单元测试是一个更好的解决方案，因为它们可以自动提供数据库隔离，而不会产生重置数据库的性能成本（只要在支持事务的数据库上运行）。因此，如果你开始遇到很多 doctest 的测试相互依赖的问题，我强烈建议考虑单元测试作为解决方案，而不是依赖于这里列出的任何方法。

## 谨防 Unicode

我们将在 doctest 注意事项中涵盖的最后一个问题是 Unicode。如果你在 Django（甚至只是 Python）中使用了比英语更广泛的字符集的数据，你可能已经遇到过`UnicodeDecodeError`或`UnicodeEncodeError`一两次。因此，你可能已经养成了在测试中包含一些非 ASCII 字符的习惯，以确保一切都能正常工作，不仅仅是英语。这是一个好习惯，但不幸的是，在 doctest 中使用 Unicode 值进行测试会出现一些意想不到的故障，需要克服。

先前提到的`Survey`的`__unicode__`方法可能是我们希望在面对非 ASCII 字符时测试其行为是否正确的一个地方。对此进行测试的第一步可能是：

```py
 **def __unicode__(self): 
        """ 
        >>> t = u'¿Como está usted?' 
        >>> sd = datetime.date(2009, 12, 28) 
        >>> s = Survey.objects.create(title=t, opens=sd) 
        >>> print s 
        ¿Como está usted? (opens 2009-12-28, closes 2010-01-04) 
        """ 
        return u'%s (opens %s, closes %s)' % (self.title, self.opens, self.closes)** 
```

这个测试与许多保存覆盖测试类似，因为它首先创建了一个`Survey`实例。在这种情况下，重要的参数是标题，它被指定为 Unicode 文字字符串，并包含非 ASCII 字符。创建了`Survey`实例后，调用打印它以验证非 ASCII 字符在实例的打印表示中是否正确显示，并且没有引发 Unicode 异常。

这个测试效果如何？不太好。在添加了那段代码后，尝试运行调查测试会导致错误：

```py
****kmt@lbox:/dj_projects/marketr$ python manage.py test survey** 
**Traceback (most recent call last):** 
 **File "manage.py", line 11, in <module>** 
 **execute_manager(settings)** 
 **File "/usr/lib/python2.5/site-packages/django/core/management/__init__.py", line 362, in execute_manager** 
 **utility.execute()** 
 **File "/usr/lib/python2.5/site-packages/django/core/management/__init__.py", line 303, in execute** 
 **self.fetch_command(subcommand).run_from_argv(self.argv)** 
 **File "/usr/lib/python2.5/site-packages/django/core/management/base.py", line 195, in run_from_argv** 
 **self.execute(*args, **options.__dict__)** 
 **File "/usr/lib/python2.5/site-packages/django/core/management/base.py", line 222, in execute** 
 **output = self.handle(*args, **options)** 
 **File "/usr/lib/python2.5/site-packages/django/core/management/commands/test.py", line 23, in handle** 
 **failures = test_runner(test_labels, verbosity=verbosity, interactive=interactive)** 
 **File "/usr/lib/python2.5/site-packages/django/test/simple.py", line 178, in run_tests** 
 **app = get_app(label)** 
 **File "/usr/lib/python2.5/site-packages/django/db/models/loading.py", line 114, in get_app** 
 **self._populate()** 
 **File "/usr/lib/python2.5/site-packages/django/db/models/loading.py", line 58, in _populate** 
 **self.load_app(app_name, True)** 
 **File "/usr/lib/python2.5/site-packages/django/db/models/loading.py", line 74, in load_app** 
 **models = import_module('.models', app_name)** 
 **File "/usr/lib/python2.5/site-packages/django/utils/importlib.py", line 35, in import_module** 
 **__import__(name)** 
 **File "/dj_projects/marketr/survey/models.py", line 40** 
**SyntaxError: Non-ASCII character '\xc2' in file /dj_projects/marketr/survey/models.py on line 41, but no encoding declared; see http://www.python.org/peps/pep-0263.html for details**** 
```

这个很容易解决；我们只是忘记了声明 Python 源文件的编码。为了做到这一点，我们需要在文件顶部添加一个注释行，指定文件使用的编码。假设我们使用 UTF-8 编码，所以我们应该将以下内容添加为我们的`models.py`文件的第一行：

```py
**# -*- encoding: utf-8 -*-** 
```

现在新的测试会起作用吗？还没有，我们仍然失败了：

```py
****======================================================================** 
**FAIL: Doctest: survey.models.Survey.__unicode__** 
**----------------------------------------------------------------------** 
**Traceback (most recent call last):** 
 **File "/usr/lib/python2.5/site-packages/django/test/_doctest.py", line 2180, in runTest** 
 **raise self.failureException(self.format_failure(new.getvalue()))** 
**AssertionError: Failed doctest test for survey.models.Survey.__unicode__** 
 **File "/dj_projects/marketr/survey/models.py", line 39, in __unicode__** 

**----------------------------------------------------------------------** 
**File "/dj_projects/marketr/survey/models.py", line 44, in survey.models.Survey.__unicode__** 
**Failed example:** 
 **print s** 
**Expected:** 
 **¿Como está usted? (opens 2009-12-28, closes 2010-01-04)** 
**Got:** 
 **Â¿Como estÃ¡ usted? (opens 2009-12-28, closes 2010-01-04)** 

**----------------------------------------------------------------------** 
**Ran 4 tests in 0.084s** 

**FAILED (failures=1)** 
**Destroying test database...**** 
```

这个有点令人费解。虽然我们在测试中将标题指定为 Unicode 文字字符串`u'¿Como está usted?'`，但打印出来时显然是**Â¿Como estÃ¡ usted?**。这种数据损坏是错误地使用了错误的编码将字节字符串转换为 Unicode 字符串的明显迹象。事实上，这里的损坏特性，即原始字符串中的每个非 ASCII 字符在损坏版本中被两个（或更多）字符替换，是实际上以 UTF-8 编码的字符串被解释为如果它是以 ISO-8859-1（也称为 Latin-1）编码的特征。但是这里怎么会发生这种情况，因为我们指定了 UTF-8 作为我们的 Python 文件编码声明？为什么这个字符串会使用其他编码来解释？

此时，我们可能会去仔细阅读我们收到的第一个错误消息中引用的网页，并了解到我们添加的编码声明只影响 Python 解释器从源文件构造 Unicode 文字字符串的方式。然后我们可能会注意到，尽管我们的标题是一个 Unicode 文字字符串，但包含 doctest 的文档字符串却不是。因此，也许这个奇怪的结果是因为我们忽略了将包含 doctest 的文档字符串作为 Unicode 文字字符串。因此，我们下一个版本的测试可能是将整个文档字符串指定为 Unicode 文字字符串。

不幸的是，这也将是不成功的，因为存在 Unicode 文字文档字符串的问题。首先，doctest 运行器无法正确比较预期输出（现在是 Unicode，因为文档字符串本身是 Unicode 文字）和包含非 ASCII 字符的字节串的实际输出。这样的字节串必须转换为 Unicode 以进行比较。当必要时，Python 将自动执行此转换，但问题在于它不知道正在转换的字节串的实际编码。因此，它假定为 ASCII，并且如果字节串包含任何非 ASCII 字符，则无法执行转换。

这种转换失败将导致涉及字节串的比较被假定为失败，进而导致测试被报告为失败。即使预期和接收到的输出是相同的，如果只假定了字节串的正确编码，也没有办法使正确的编码被使用，因此测试将失败。对于`Survey`模型`__unicode__` doctest，这个问题将导致在尝试比较`print s`的实际输出（这将是一个 UTF-8 编码的字节串）和预期输出时测试失败。

Unicode 文字文档字符串的第二个问题涉及包含非 ASCII 字符的输出的报告，例如在`Survey`模型`__unicode__` doctest 中将发生的失败。doctest 运行器将尝试显示一个消息，显示预期和接收到的输出。然而，当它尝试将预期和接收到的输出合并成一个用于显示的单个消息时，它将遇到与比较期间遇到的相同问题。因此，与其生成一个至少能够显示测试遇到问题的消息，doctest 运行器本身会生成`UnicodeDecodeError`。

Python 的 bug 跟踪器中有一个未解决的 Python 问题报告了这些问题：[`bugs.python.org/issue1293741`](http://bugs.python.org/issue1293741)。在它被修复之前，最好避免在 doctests 中使用 Unicode 文字文档字符串。

那么，有没有办法在 doctests 中包含一些非 ASCII 数据的测试？是的，这是可能的。使这样的测试起作用的关键是避免在文档字符串中使用 Unicode 文字。而是显式将字符串解码为 Unicode 对象。例如：

```py
 **def __unicode__(self): 
        """ 
        >>> t = '¿Como está usted?'.decode('utf-8') 
        >>> sd = datetime.date(2009, 12, 28) 
        >>> s = Survey.objects.create(title=t, opens=sd) 
        >>> print s 
        ¿Como está usted? (opens 2009-12-28, closes 2010-01-04) 
        """ 
        return u'%s (opens %s, closes %s)' % (self.title, self.opens, self.closes)** 
```

也就是说，用一个明确使用 UTF-8 解码的字节串替换 Unicode 文字标题字符串，以创建一个 Unicode 字符串。

这样做有用吗？现在运行`manage.py test survey -v2`，我们在输出的最后看到以下内容：

```py
****No fixtures found.** 
**test_basic_addition (survey.tests.SimpleTest) ... ok** 
**Doctest: survey.models.Survey.__unicode__ ... ok** 
**Doctest: survey.models.Survey.save ... ok** 
**Doctest: survey.tests.__test__.survey_save ... ok** 

**----------------------------------------------------------------------** 
**Ran 4 tests in 0.046s** 

**OK** 
**Destroying test database...**** 
```

成功！因此，在 doctests 中正确测试非 ASCII 数据是可能的。只需注意避免遇到使用 Unicode 文字文档字符串或在 doctest 中嵌入 Unicode 文字字符串相关的现有问题。

# 总结

我们对 Django 应用程序的 doctests 的探索现在已经完成。在本章中，我们：

+   开始为我们的 Django`survey`应用程序开发一些模型

+   尝试向其中一个模型添加 doctests——`Survey`模型

+   了解了哪些类型的 doctests 是有用的，哪些只是为代码添加了混乱

+   体验了 doctests 的一些优势，即轻松重用 Python shell 会话工作和方便地将 doctests 用作文档

+   遇到了许多 doctests 的缺点，并学会了如何避免或克服它们

在下一章中，我们将开始探索单元测试。虽然单元测试可能不提供一些 doctests 的轻松重用功能，但它们也不会受到许多 doctests 的缺点的影响。此外，整体的单元测试框架允许 Django 提供特别适用于 Web 应用程序的便利支持，这将在第四章中详细介绍。


# 第三章：测试 1, 2, 3：基本单元测试

在上一章中，我们开始通过为`Survey`模型编写一些 doctests 来学习测试 Django 应用程序。在这个过程中，我们体验了 doctests 的一些优点和缺点。在讨论一些缺点时，提到了单元测试作为避免一些 doctest 陷阱的替代测试方法。在本章中，我们将开始详细学习单元测试。具体来说，我们将：

+   将`Survey`的 doctests 重新实现为单元测试

+   评估等效的单元测试版本在实现的便利性和对上一章讨论的 doctest 注意事项的敏感性方面与 doctests 相比如何

+   在扩展现有测试以覆盖其他功能时，开始学习单元测试的一些附加功能

# `Survey`保存覆盖方法的单元测试

回想在上一章中，我们最终实现了对`Survey`保存覆盖功能的四个单独测试：

+   对添加的功能进行直接测试，验证如果在创建`Survey`时未指定`closes`，则自动设置为`opens`之后的一周

+   验证如果在创建时明确指定了`closes`，则不会执行此自动设置操作的测试

+   验证只有在初始创建时其值缺失时，才会自动设置`closes`的测试

+   验证`save`覆盖功能在创建时既未指定`opens`也未指定`closes`的错误情况下不会引入意外异常的测试

要将这些实现为单元测试而不是 doctests，请在`suvery/tests.py`文件中创建一个`TestCase`，替换示例`SimpleTest`。在新的`TestCase`类中，将每个单独的测试定义为该`TestCase`中的单独测试方法，如下所示：

```py
import datetime
from django.test import TestCase 
from django.db import IntegrityError 
from survey.models import Survey 

class SurveySaveTest(TestCase): 
    t = "New Year's Resolutions" 
    sd = datetime.date(2009, 12, 28) 

    def testClosesAutoset(self): 
        s = Survey.objects.create(title=self.t, opens=self.sd) 
        self.assertEqual(s.closes, datetime.date(2010, 1, 4))

    def testClosesHonored(self):
        s = Survey.objects.create(title=self.t, opens=self.sd, closes=self.sd) 
        self.assertEqual(s.closes, self.sd) 

    def testClosesReset(self): 
        s = Survey.objects.create(title=self.t, opens=self.sd) 
        s.closes = None 
        self.assertRaises(IntegrityError, s.save) 

    def testTitleOnly(self): 
        self.assertRaises(IntegrityError, Survey.objects.create, title=self.t) 
```

这比 doctest 版本更难实现，不是吗？无法直接从 shell 会话中剪切和粘贴，需要添加大量代码开销——在 shell 会话中没有出现的代码。我们仍然可以从 shell 会话中剪切和粘贴作为起点，但是我们必须在粘贴后编辑代码，以将粘贴的代码转换为适当的单元测试。虽然不难，但可能会很乏味。

大部分额外工作包括选择各个测试方法的名称，对剪切和粘贴的代码进行微小编辑以正确引用类变量，如`t`和`sd`，以及创建适当的测试断言来验证预期结果。其中第一个需要最多的脑力（选择好的名称可能很难），第二个是微不足道的，第三个是相当机械的。例如，在我们的 shell 会话中：

```py
>>> s.closes 
datetime.date(2010, 1, 4) 
>>> 

```

在单元测试中，我们有一个`assertEqual`：

```py
self.assertEqual(s.closes, datetime.date(2010, 1, 4))
```

预期的异常类似，但使用`assertRaises`。例如，在 shell 会话中，我们有：

```py
>>> s = Survey.objects.create(title=t) 
Traceback (most recent call last): 
 [ traceback details snipped ]
IntegrityError: survey_survey.opens may not be NULL 
>>> 

```

在单元测试中，这是：

```py
self.assertRaises(IntegrityError, Survey.objects.create, title=self.t)
```

请注意，我们实际上没有在我们的单元测试代码中调用`create`例程，而是将其留给`assertRaises`内的代码。传递给`assertRaises`的第一个参数是预期的异常，后跟可预期引发异常的可调用对象，后跟在调用它时需要传递给可调用对象的任何参数。

## 单元测试版本的优点

从这项额外工作中我们得到了什么？当以最高详细级别运行时，我们从测试运行器中获得了更多反馈。对于 doctest 版本，`manage.py test survey -v2`的输出只是：

```py
Doctest: survey.models.Survey.save ... ok 
```

在单元测试中，我们为每个测试方法报告单独的结果：

```py
testClosesAutoset (survey.tests.SurveySaveTest) ... ok 
testClosesHonored (survey.tests.SurveySaveTest) ... ok 
testClosesReset (survey.tests.SurveySaveTest) ... ok 
testTitleOnly (survey.tests.SurveySaveTest) ... ok 

```

如果我们再付出一点努力，并为我们的测试方法提供单行文档字符串，我们甚至可以从测试运行器中获得更详细的结果。例如，如果我们这样添加文档字符串：

```py
class SurveySaveTest(TestCase): 
    """Tests for the Survey save override method""" 
    t = "New Year's Resolutions" 
    sd = datetime.date(2009, 12, 28) 

    def testClosesAutoset(self): 
        """Verify closes is autoset correctly""" 
        s = Survey.objects.create(title=self.t, opens=self.sd) 
        self.assertEqual(s.closes, datetime.date(2010, 1, 4)) 

    def testClosesHonored(self): 
        """Verify closes is honored if specified""" 
        s = Survey.objects.create(title=self.t, opens=self.sd, closes=self.sd) 
        self.assertEqual(s.closes, self.sd)

    def testClosesReset(self): 
        """Verify closes is only autoset during initial create""" 
        s = Survey.objects.create(title=self.t, opens=self.sd) 
        s.closes = None 
        self.assertRaises(IntegrityError, s.save) 

    def testTitleOnly(self): 
        """Verify correct exception is raised in error case""" 
        self.assertRaises(IntegrityError, Survey.objects.create, title=self.t) 
```

然后，此测试的测试运行器输出将是：

```py
Verify closes is autoset correctly ... ok 
Verify closes is honored if specified ... ok 
Verify closes is only autoset during initial create ... ok 
Verify correct exception is raised in error case ... ok 

```

这种额外的描述性细节在所有测试通过时可能并不那么重要，但当测试失败时，它可能非常有助于作为测试试图实现的线索。

例如，假设我们已经破坏了`save`覆盖方法，忽略了向`opens`添加七天，因此如果未指定`closes`，它将自动设置为与`opens`相同的值。使用测试的 doctest 版本，失败将被报告为：

```py
====================================================================== 
FAIL: Doctest: survey.models.Survey.save 
---------------------------------------------------------------------- 
Traceback (most recent call last): 
 File "/usr/lib/python2.5/site-packages/django/test/_doctest.py", line 2180, in runTest 
 raise self.failureException(self.format_failure(new.getvalue())) 
AssertionError: Failed doctest test for survey.models.Survey.save 
 File "/dj_projects/marketr/survey/models.py", line 10, in save 

---------------------------------------------------------------------- 
File "/dj_projects/marketr/survey/models.py", line 19, in survey.models.Survey.save 
Failed example: 
 s.closes 
Expected: 
 datetime.date(2010, 1, 4) 
Got: 
 datetime.date(2009, 12, 28) 

```

这并没有提供有关出了什么问题的详细信息，您真的必须阅读完整的测试代码才能看到正在测试什么。与单元测试报告的相同失败更具描述性，因为`FAIL`标题包括测试文档字符串，因此我们立即知道问题与`closes`的自动设置有关：

```py
====================================================================== 
FAIL: Verify closes is autoset correctly 
---------------------------------------------------------------------- 
Traceback (most recent call last): 
 File "/dj_projects/marketr/survey/tests.py", line 20, in testClosesAutoset 
 self.assertEqual(s.closes, datetime.date(2010, 1, 4)) 
AssertionError: datetime.date(2009, 12, 28) != datetime.date(2010, 1, 4) 

```

我们可以进一步迈出一步，通过在调用`assertEqual`时指定自己的错误消息，使错误消息更友好：

```py
    def testClosesAutoset(self):
        """Verify closes is autoset correctly"""
        s = Survey.objects.create(title=self.t, opens=self.sd)
        self.assertEqual(s.closes, datetime.date(2010, 1, 4), 
            "closes not autoset to 7 days after opens, expected %s, ""actually %s" % 
            (datetime.date(2010, 1, 4), s.closes))
```

然后报告的失败将是：

```py
====================================================================== 
FAIL: Verify closes is autoset correctly 
---------------------------------------------------------------------- 
Traceback (most recent call last): 
 File "/dj_projects/marketr/survey/tests.py", line 22, in testClosesAutoset 
 (datetime.date(2010, 1, 4), s.closes)) 
AssertionError: closes not autoset to 7 days after opens, expected 2010-01-04, actually 2009-12-28 

```

在这种情况下，自定义错误消息可能并不比默认消息更有用，因为这里`save`覆盖应该做的事情非常简单。然而，对于更复杂的测试断言，这样的自定义错误消息可能是有价值的，以帮助解释正在测试的内容以及预期结果背后的“为什么”。

单元测试的另一个好处是，它们允许比 doctests 更有选择性地执行测试。在`manage.py test`命令行上，可以通过`TestCase`名称标识要执行的一个或多个单元测试。甚至可以指定只运行`TestCase`中的特定方法。例如：

```py
python manage.py test survey.SurveySaveTest.testClosesAutoset 
```

在这里，我们指示只想在`survey`应用程序中找到的`SurveySaveTest`单元测试中运行`testClosesAutoset`测试方法。在开发测试时，能够仅运行单个方法或单个测试用例是非常方便的时间节省器。

## 单元测试版本的缺点

切换到单元测试是否有所损失？有一点。首先，已经提到的实施便利性：单元测试需要比 doctests 更多的工作来实施。虽然通常不是困难的工作，但可能会很乏味。这也是可能出现错误的工作，导致需要调试测试代码。这种增加的实施负担可能会阻止编写全面的测试。

我们还失去了将测试与代码放在一起的好处。在上一章中提到，这是将一些 doctests 从文档字符串移出并放入`tests.py`中的`__test__`字典的一个负面影响。由于单元测试通常保存在与被测试的代码分开的文件中，因此通常看不到靠近代码的测试，这可能会阻止编写测试。使用单元测试时，除非采用测试驱动开发等方法，否则“视而不见”效应很容易导致编写测试成为事后想法。

最后，我们失去了 doctest 版本的内置文档。这不仅仅是来自文档字符串的自动生成文档的潜力。Doctests 通常比单元测试更易读，其中只是测试开销的多余代码可能会掩盖测试的意图。但请注意，使用单元测试并不意味着您必须放弃 doctests；在应用程序中同时使用这两种测试是完全可以的。每种测试都有其优势，因此对于许多项目来说，最好是在所有测试中使用一种类型，而不是依赖单一类型。

# 重新审视 doctest 的注意事项

在上一章中，我们列出了编写文档测试时需要注意的事项。在讨论这些事项时，有时会提到单元测试作为一个不会遇到相同问题的替代方法。但是单元测试是否真的免疫于这些问题，还是只是使问题更容易避免或解决？在本节中，我们重新审视文档测试的警告，并考虑单元测试对相同或类似问题的敏感程度。

## 环境依赖

讨论的第一个文档测试警告是环境依赖：依赖于实际被测试的代码以外的代码的实现细节。尽管单元测试也可能出现这种依赖，但发生的可能性较小。这是因为这种依赖的非常常见的方式是依赖于对象的打印表示，因为它们在 Python shell 会话中显示。单元测试与 Python shell 相去甚远。在单元测试中需要一些编码工作才能获得对象的打印表示，因此这种形式的环境依赖很少会出现在单元测试中。

第二章中提到的一种常见的环境依赖形式也影响到了单元测试，涉及文件路径名。单元测试和文档测试一样，需要注意跨操作系统的文件路径名约定差异，以防在不同于最初编写测试的操作系统上运行测试时导致虚假的测试失败。因此，尽管单元测试不太容易出现环境依赖问题，但它们并非完全免疫。

## 数据库依赖

数据库依赖是 Django 应用程序特别常见的一种环境依赖形式。在文档测试中，我们看到测试的初始实现依赖于伴随`IntegrityError`的消息的具体内容。为了使文档测试在多个不同的数据库上通过，我们需要修改初始测试以忽略此消息的细节。

我们在单元测试版本中没有这个问题。用于检查预期异常的`assertRaises`已经不考虑异常消息的细节。例如：

```py
self.assertRaises(IntegrityError, s.save)
```

那里没有包含具体的消息，所以我们不需要做任何事情来忽略来自不同数据库实现的消息差异。

此外，单元测试使处理比消息细节更广泛的差异变得更容易。在上一章中指出，对于 MySQL 的某些配置，忽略消息细节不足以使所有测试通过。在这里出现问题的测试是确保`closes`仅在初始模型创建期间自动设置的测试。这个测试的单元测试版本是：

```py
def testClosesReset(self): 
    """Verify closes is only autoset during initial create""" 
    s = Survey.objects.create(title=self.t, opens=self.sd) 
    s.closes = None 
    self.assertRaises(IntegrityError, s.save) 
```

如果在运行在非严格模式下的 MySQL 服务器上运行此测试，则此测试将失败。在此模式下，MySQL 在尝试将行更新为包含在声明为`NOT NULL`的列中包含`NULL`值时不会引发`IntegrityError`。相反，该值将设置为隐式默认值，并发出警告。因此，当我们在配置为在非严格模式下运行的 MySQL 服务器上运行此测试时，我们会看到测试错误：

```py
====================================================================== 
ERROR: Verify closes is only autoset during initial create 
---------------------------------------------------------------------- 
Traceback (most recent call last): 
 File "/dj_projects/marketr/survey/tests.py", line 35, in testClosesReset 
 self.assertRaises(IntegrityError, s.save) 
 File "/usr/lib/python2.5/unittest.py", line 320, in failUnlessRaises 
 callableObj(*args, **kwargs) 
 File "/dj_projects/marketr/survey/models.py", line 38, in save 
 super(Survey, self).save(**kwargs) 
 File "/usr/lib/python2.5/site-packages/django/db/models/base.py", line 410, in save 
 self.save_base(force_insert=force_insert, force_update=force_update) 
 File "/usr/lib/python2.5/site-packages/django/db/models/base.py", line 474, in save_base 
 rows = manager.filter(pk=pk_val)._update(values) 
 File "/usr/lib/python2.5/site-packages/django/db/models/query.py", line 444, in _update 
 return query.execute_sql(None) 
 File "/usr/lib/python2.5/site-packages/django/db/models/sql/subqueries.py", line 120, in execute_sql 
 cursor = super(UpdateQuery, self).execute_sql(result_type) 
 File "/usr/lib/python2.5/site-packages/django/db/models/sql/query.py", line 2369, in execute_sql 
 cursor.execute(sql, params) 
 File "/usr/lib/python2.5/site-packages/django/db/backends/mysql/base.py", line 84, in execute 
 return self.cursor.execute(query, args) 
 File "/var/lib/python-support/python2.5/MySQLdb/cursors.py", line 168, in execute 
 if not self._defer_warnings: self._warning_check() 
 File "/var/lib/python-support/python2.5/MySQLdb/cursors.py", line 82, in _warning_check 
 warn(w[-1], self.Warning, 3) 
 File "/usr/lib/python2.5/warnings.py", line 62, in warn 
 globals) 
 File "/usr/lib/python2.5/warnings.py", line 102, in warn_explicit 
 raise message 
Warning: Column 'closes' cannot be null 

```

在这里，我们看到 MySQL 发出的警告导致引发了一个简单的`Exception`，而不是`IntegrityError`，因此测试报告了一个错误。

这里还有一个额外的问题需要考虑：当 MySQL 发出警告时引发`Exception`的行为取决于 Django 的`DEBUG`设置。只有在`DEBUG`为`True`时（就像先前运行的测试一样），MySQL 警告才会转换为引发的`Exception`。如果我们在`settings.py`中将`DEBUG`设置为`False`，我们会看到另一种形式的测试失败：

```py
====================================================================== 
FAIL: Verify closes is only autoset during initial create 
---------------------------------------------------------------------- 
Traceback (most recent call last): 
 File "/dj_projects/marketr/survey/tests.py", line 35, in testClosesReset 
 self.assertRaises(IntegrityError, s.save) 
AssertionError: IntegrityError not raised 

```

在这种情况下，MySQL 允许保存，由于 Django 没有打开`DEBUG`，因此没有将 MySQL 发出的警告转换为`Exception`，因此保存工作正常进行。

在这一点上，我们可能会认真质疑是否值得在所有这些不同的情况下让这个测试正常运行，考虑到观察到的行为差异很大。也许我们应该要求，如果代码在 MySQL 上运行，服务器必须配置为严格模式。然后测试就会很好，因为以前的失败都会发出服务器配置问题的信号。但是，让我们假设我们确实需要支持在 MySQL 上运行，但我们不能对 MySQL 施加任何特定的配置要求，我们仍然需要验证我们的代码是否对这个测试行为正常。我们该怎么做呢？

请注意，我们试图在这个测试中验证的是，如果在初始创建后将`closes`重置为`None`，我们的代码不会自动将其设置为某个值。起初，似乎只需检查尝试保存时是否出现`IntegrityError`就可以轻松完成这个任务。然而，我们发现了一个数据库配置，我们在那里没有得到`IntegrityError`。此外，根据`DEBUG`设置，即使我们的代码行为正确并在尝试保存期间将`closes`保持为`None`，我们也可能不会报告任何错误。我们能写一个测试来报告正确的结果吗？也就是说，我们的代码在所有这些情况下是否表现正常？

答案是肯定的，只要我们能在我们的测试代码中确定正在使用的数据库，它是如何配置的，以及`DEBUG`设置是什么。然后，我们只需要根据测试运行的环境改变预期的结果。实际上，我们可以通过一些工作测试所有这些事情：

```py
    def testClosesReset(self): 
        """Verify closes is only autoset during initial create""" 
        s = Survey.objects.create(title=self.t, opens=self.sd) 
        s.closes = None 

        strict = True 
        debug = False
        from django.conf import settings 
        if settings.DATABASE_ENGINE == 'mysql': 
            from django.db import connection 
            c = connection.cursor() 
            c.execute('SELECT @@SESSION.sql_mode') 
            mode = c.fetchone()[0] 
            if 'STRICT' not in mode: 
                strict = False; 
                from django.utils import importlib
                debug = importlib.import_module(settings.SETTINGS_MODULE).DEBUG

        if strict: 
            self.assertRaises(IntegrityError, s.save) 
        elif debug: 
            self.assertRaises(Exception, s.save) 
        else: 
            s.save() 
            self.assertEqual(s.closes, None) 
```

测试代码首先假设我们正在运行在严格模式下操作的数据库，并将本地变量`strict`设置为`True`。我们还假设`DEBUG`是`False`并设置一个本地变量来反映这一点。然后，如果正在使用的数据库是 MySQL（通过检查`settings.DATABASE_ENGINE`的值确定），我们需要进行进一步的检查以查看它是如何配置的。查阅 MySQL 文档显示，这样做的方法是`SELECT`会话的`sql_mode`变量。如果返回的值包含字符串`STRICT`，那么 MySQL 正在严格模式下运行，否则不是。我们发出这个查询并使用 Django 支持将原始 SQL 发送到数据库来获取结果。如果我们确定 MySQL 没有配置为运行在严格模式下，我们将更新我们的本地变量`strict`为`False`。

如果我们到达将`strict`设置为`False`的地步，那也是`settings`中的`DEBUG`值变得重要的时候，因为在这种情况下，MySQL 将发出警告而不是为我们在这里测试的情况引发`IntegrityError`。如果`settings`文件中的`DEBUG`是`True`，那么 MySQL 的警告将被 Django 的 MySQL 后端转换为`Exceptions`。这是通过后端使用 Python 的`warnings`模块完成的。当后端加载时，如果`DEBUG`是`True`，那么将发出`warnings.filterwarnings`调用，以强制所有数据库警告转换为`Exceptions`。

不幸的是，在数据库后端加载后，测试代码运行之前的某个时刻，测试运行程序将更改内存设置，以便将`DEBUG`设置为`False`。这样做是为了使测试代码的行为尽可能接近在生产中发生的情况。但是，这意味着我们不能仅仅在测试期间测试`settings.DEBUG`的值，以查看在加载数据库后端时`DEBUG`是否为`True`。相反，我们必须重新加载设置模块并检查新加载版本中的值。我们使用`django.utils.importlib`的`import_module`函数来实现这一点（这是 Python 2.7 的一个函数，已经被回溯使用 Django 1.1）。

最后，我们知道在运行我们的测试代码时要寻找什么。如果我们已经确定我们正在运行严格模式的数据库，我们断言尝试使用`closes`设置为`None`保存我们的模型实例应该引发`IntegrityError`。否则，如果我们在非严格模式下运行，但在设置文件中`DEBUG`为`True`，那么尝试保存应该导致引发`Exception`。否则保存应该成功，并且我们通过确保即使在模型实例保存后`closes`仍然设置为`None`来测试我们代码的正确行为。

所有这些可能看起来是为了一个相当次要的测试而经历的相当大麻烦，但它说明了如何编写单元测试以适应不同环境中预期行为的显着差异。对于 doctest 版本来说，做同样的事情并不那么简单。因此，虽然单元测试显然不能消除在测试中处理数据库依赖的问题，但它们使得编写能够解决这些差异的测试变得更容易。

## 测试相互依赖

上一章遇到的下一个 doctest 警告是测试相互依赖。当在 PostgreSQL 上运行 doctests 时，在故意触发数据库错误的第一个测试之后遇到了一个错误，因为该错误导致数据库连接进入一个状态，它不会接受除终止事务之外的任何进一步命令。解决这个问题的方法是记住在故意触发错误后“清理”，在导致这种错误的任何测试步骤之后包括一个事务回滚。

Django 单元测试不会受到这个问题的影响。Django 测试用例类`django.test.TestCase`确保在调用每个测试方法之前将数据库重置为干净状态。因此，即使`testClosesReset`方法以尝试触发`IntegrityError`的模型保存结束，下一个运行的测试方法也不会看到任何错误，因为在此期间，数据库连接被`django.test.TestCase`代码重置。不仅清理了这种错误情况，任何被测试用例方法添加、删除或修改的数据库行在下一个方法运行之前都会被重置为它们的原始状态。（请注意，在大多数数据库上，测试运行程序可以使用事务回滚调用来非常有效地完成这个任务。）因此，Django 单元测试方法完全与之前运行的测试可能执行的任何数据库更改隔离开来。

## Unicode

上一章讨论的最后一个 doctest 警告涉及在 doctests 中使用 Unicode 文字。由于 Python 中与 Unicode docstrings 和 docstrings 中的 Unicode 文字相关的基础问题，这些被观察到无法正常工作。

单元测试没有这个问题。对`Survey`模型`__unicode__`方法行为的直接单元测试可以工作。

```py
class SurveyUnicodeTest(TestCase): 
    def testUnicode(self): 
        t = u'¿Como está usted?' 
        sd = datetime.date(2009, 12, 28) 
        s = Survey.objects.create(title=t, opens=sd) 
        self.assertEqual(unicode(s), u'¿Como está usted? (opens 2009-12-28, closes 2010-01-04)') 
```

请注意，必须像我们在上一章中为`survey/models.py`做的那样，在`survey/tests.py`的顶部添加编码声明，但不需要对字节字符串文字进行任何手动解码以构造所需的 Unicode 对象，这在 doctest 版本中是必需的。我们只需要像通常一样设置我们的变量，创建`Survey`实例，并断言调用该实例的`unicode`方法的结果是否产生我们期望的字符串。因此，使用单元测试进行非 ASCII 数据的测试比使用 doctests 要简单得多。

# 为单元测试提供数据

除了不受 doctests 一些缺点的影响外，单元测试为 Django 应用程序提供了一些额外的有用功能。其中之一是在测试运行之前加载测试数据到数据库中。有几种不同的方法可以做到这一点；每种方法在以下各节中都有详细讨论。

## 在测试装置中提供数据

为单元测试提供测试数据的第一种方法是从文件中加载它们，称为固定装置。我们将首先通过开发一个可以从预加载的测试数据中受益的示例测试来介绍这种方法，然后展示如何创建一个固定装置文件，最后描述如何确保固定装置文件作为测试的一部分被加载。

### 需要测试数据的示例测试

在深入讨论如何为测试提供预加载数据的细节之前，有一个可以使用这个功能的测试的例子将会有所帮助。到目前为止，我们的简单测试通过在进行时创建它们所需的数据来轻松进行。然而，当我们开始测试更高级的功能时，很快就会遇到情况，测试本身需要为一个良好的测试创建所有需要的数据将变得繁琐。

例如，考虑`Question`模型：

```py
 class Question(models.Model): 
    question = models.CharField(max_length=200) 
    survey = models.ForeignKey(Survey) 

    def __unicode__(self): 
        return u'%s: %s' % (self.survey, self.question) 
```

（请注意，我们已经为这个模型添加了一个`__unicode__`方法。当我们开始使用管理界面创建一些调查应用程序数据时，这将会很方便。）

回想一下，给定`Question`实例的允许答案存储在一个单独的模型`Answer`中，它使用`ForeignKey`与`Question`关联：

```py
class Answer(models.Model): 
    answer = models.CharField(max_length=200) 
    question = models.ForeignKey(Question) 
    votes = models.IntegerField(default=0) 
```

这个`Answer`模型还跟踪了每个答案被选择的次数，在它的`votes`字段中。（我们还没有为这个模型添加`__unicode__`方法，因为根据我们稍后在本章中将如何配置管理界面，它还不是必需的。）

现在，在分析调查结果时，我们想要了解一个给定的`Question`的`Answers`中哪个被选择得最多。也就是说，`Question`模型需要支持的一个功能是返回该`Question`的“获胜答案”。如果我们仔细考虑一下，我们会意识到可能没有一个单一的获胜答案。可能会有多个答案获得相同数量的票数而并列。因此，这个获胜答案的方法应该足够灵活，可以返回多个答案。同样，如果没有人回答这个问题，最好返回没有获胜答案，而不是整套允许的答案，其中没有一个被选择。由于这个方法（让我们称之为`winning_answers`）可能返回零个、一个或多个结果，为了保持一致性，最好总是返回类似列表的东西。

甚至在开始实现这个函数之前，我们就已经对它需要处理的不同情况有了一定的了解，以及在开发函数本身和对其进行测试时需要放置哪种类型的测试数据。这个例程的一个很好的测试将需要至少三个不同的问题，每个问题都有一组答案：

+   一个问题的答案中有一个明显的获胜者，也就是说一个答案的票数比其他所有答案都多，这样`winning_answers`返回一个单一的答案

+   一个问题的答案中有平局，所以`winning_answers`返回多个答案

+   一个问题根本没有得到任何回答，因此`winning_answers`不返回任何答案

此外，我们应该测试一个没有与之关联的答案的`Question`。这显然是一个边缘情况，但我们应该确保`winning_answers`函数在看起来数据还没有完全准备好分析哪个答案最受欢迎时也能正常运行。因此，实际上测试数据中应该有四个问题，其中三个有一组答案，一个没有答案。

### 使用管理应用程序创建测试数据

在一个 shell 会话或者甚至一个程序中创建四个问题，其中三个有几个答案，是相当乏味的，所以让我们使用 Django 管理应用程序来代替。在第一章中，我们包含了`django.contrib.admin`在`INSTALLED_APPS`中，所以它已经加载了。此外，当我们运行`manage.py syncdb`时，为管理所需的表已经创建。然而，我们仍然需要取消注释`urls.py`文件中与管理相关的行。当我们这样做时，`urls.py`应该看起来像这样：

```py
from django.conf.urls.defaults import * 

# Uncomment the next two lines to enable the admin: 
from django.contrib import admin 
admin.autodiscover() 

urlpatterns = patterns('', 
    # Example: 
    # (r'^marketr/', include('marketr.foo.urls')), 

    # Uncomment the admin/doc line below and add # 'django.contrib.admindocs' 
    # to INSTALLED_APPS to enable admin documentation: 
    # (r'^admin/doc/', include('django.contrib.admindocs.urls')), 

    # Uncomment the next line to enable the admin: 
    (r'^admin/', include(admin.site.urls)), 
) 
```

最后，我们需要为我们的调查应用程序模型提供一些管理定义，并将它们注册到管理应用程序中，以便我们可以在管理中编辑我们的模型。因此，我们需要创建一个类似于这样的`survey/admin.py`文件：

```py
from django.contrib import admin 
from survey.models import Survey, Question, Answer 

class QuestionsInline(admin.TabularInline): 
    model = Question 
    extra = 4

class AnswersInline(admin.TabularInline): 
    model = Answer 

class SurveyAdmin(admin.ModelAdmin): 
    inlines = [QuestionsInline] 

class QuestionAdmin(admin.ModelAdmin): 
    inlines = [AnswersInline] 

admin.site.register(Survey, SurveyAdmin) 
admin.site.register(Question, QuestionAdmin) 
```

在这里，我们大部分使用了管理默认值，除了我们定义和指定了一些管理内联类，以便更容易在单个页面上编辑多个内容。我们在这里设置内联的方式允许我们在`Survey`所属的同一页上编辑`Questions`，并在与其相关联的`Answers`的同一页上编辑`Answers`。我们还指定了当它们内联出现时，我们希望有四个额外的空`Questions`。这个值的默认值是三，但我们知道我们想要设置四个问题，我们也可能设置一次性添加所有四个问题。

现在，我们可以通过在命令提示符中运行`python manage.py runserver`来启动开发服务器，并通过在同一台机器上的浏览器中导航到`http://localhost:8000/admin/`来访问管理应用程序。登录为我们在第一章创建的超级用户后，我们将会看到管理主页面。从那里，我们可以点击链接添加一个`Survey`。**添加调查**页面将允许我们创建一个包含四个`Questions`的调查：

![使用管理应用程序创建测试数据](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj11-test-dbg/img/7566_03_01.jpg)

在这里，我们为我们的`Question`实例分配了`question`值，这些值不是问题，而是我们将用来测试每个问题的指示。请注意，此页面还反映了对`Survey`模型所做的轻微更改：在`closes`字段规范中添加了`blank=True`。没有这个改变，管理将要求在这里为`closes`指定一个值。有了这个改变，管理应用程序允许字段留空，以便可以使用保存覆盖方法自动分配的值。

一旦我们保存了这份调查，我们可以导航到第一个问题的更改页面，**明确的赢家**，并添加一些答案：

![使用管理应用程序创建测试数据](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj11-test-dbg/img/7566_03_02.jpg)

因此，我们设置了**明确的赢家**问题有一个答案（**最大票数**）比其他所有答案都多。同样，我们可以设置**2-Way Tie**问题有两个答案获得相同数量的票数：

![使用管理应用程序创建测试数据](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj11-test-dbg/img/7566_03_03.jpg)

最后，我们设置了**无回应**的答案，这样我们就可以测试没有任何答案收到任何投票的情况：

![使用管理应用程序创建测试数据](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj11-test-dbg/img/7566_03_04.jpg)

我们不需要进一步处理**无回应**问题，因为这个问题将用于测试问题的答案集为空的情况，就像它刚创建时一样。

## 编写函数本身

现在我们的数据库已经设置了测试数据，我们可以在 shell 中尝试实现`winning_answers`函数的最佳方法。因此，我们可能会得出类似以下的结果：

```py
from django.db.models import Max

class Question(models.Model): 
    question = models.CharField(max_length=200) 
    survey = models.ForeignKey(Survey) 
    def winning_answers(self): 
       rv = [] 
       max_votes = self.answer_set.aggregate(Max('votes')).values()[0] 
       if max_votes and max_votes > 0: 
           rv = self.answer_set.filter(votes=max_votes) 
       return rv 
```

该方法首先通过将本地变量`rv`（返回值）初始化为空列表。然后，它使用聚合`Max`函数来检索与此`Question`实例关联的`Answer`实例集中存在的`votes`的最大值。这一行代码在几个方面做了一些事情，为了得出答案，可能需要更多的解释。要了解它是如何工作的，请在 shell 会话中查看每个部分依次返回的内容：

```py
>>> from survey.models import Question 
>>> q = Question.objects.get(question='Clear Winner') 
>>> from django.db.models import Max 
>>> q.answer_set.aggregate(Max('votes')) 
{'votes__max': 8} 

```

在这里，我们看到将聚合函数`Max`应用于给定`Question`关联的`answer_set`的`votes`字段会返回一个包含单个键值对的字典。我们只对值感兴趣，因此我们使用`.values()`从字典中检索值。

```py
>>> q.answer_set.aggregate(Max('votes')).values() 
[8] 

```

但是，`values()` 返回一个列表，我们想要列表中的单个项目，因此我们通过请求列表中索引为零的项目来检索它：

```py
>>> q.answer_set.aggregate(Max('votes')).values()[0] 
8 

```

接下来，代码测试 `max_votes` 是否存在，以及它是否大于零（至少有一个答案至少被选择了一次）。如果是，`rv` 将被重置为答案集，只包含那些获得最大投票数的答案。

但是，`max_votes` 何时不存在呢，因为它刚刚在上一行中设置了？这可能发生在没有答案链接到问题的边缘情况中。在这种情况下，聚合 `Max` 函数将返回最大投票值的 `None`，而不是零：

```py
>>> q = Question.objects.get(question='No Answers') 
>>> q.answer_set.aggregate(Max('votes')) 
{'votes__max': None} 

```

因此，在这种边缘情况下，`max_votes` 可能被设置为 `None`，所以最好测试一下，避免尝试将 `None` 与 `0` 进行比较。虽然在 Python 2.x 中，这种比较实际上可以工作并返回一个看似合理的答案（`None` 不大于 `0`），但在 Python 3.0 开始，尝试的比较将返回 `TypeError`。现在最好避免这样的比较，以限制在需要将代码移植到 Python 3 下运行时可能出现的问题。

最后，该函数返回 `rv`，此时希望已经设置为正确的值。（是的，这个函数中有一个 bug。偶尔编写能捕捉到 bug 的测试更有趣。）

### 编写使用测试数据的测试

现在我们已经有了 `winning_answers` 的实现，以及用于测试的数据，我们可以开始编写 `winning_answers` 方法的测试。我们可以从 `tests.py` 中添加以下测试开始，测试有一个明显的获胜者的情况：

```py
from survey.models import Question
class QuestionWinningAnswersTest(TestCase): 
    def testClearWinner(self): 
        q = Question.objects.get(question='Clear Winner') 
        wa_qs = q.winning_answers() 
        self.assertEqual(wa_qs.count(), 1) 
        winner = wa_qs[0] 
        self.assertEqual(winner.answer, 'Max Votes') 
```

测试从具有其 `question` 值设置为 `'Clear Winner'` 的 `Question` 中开始。然后，它调用 `winning_answers` 在该 `Question` 实例上，以检索获得最多投票的问题的答案的查询集。由于这个问题应该有一个单一的获胜者，测试断言返回的查询集中有一个元素。然后它通过检索获胜答案本身并验证其答案值是否为 `'Max Votes'` 来进行进一步的检查。如果所有这些都成功，我们可以相当肯定 `winning_answers` 在答案中有一个单一的“获胜者”的情况下返回了正确的结果。

### 从数据库中提取测试数据

那么，我们如何对我们通过管理员应用加载到数据库中的测试数据运行该测试呢？当我们运行测试时，它们不会使用我们的生产数据库，而是创建并使用一个最初为空的测试数据库。这就是 fixture 的用武之地。Fixture 只是包含可以加载到数据库中的数据的文件。

因此，第一项任务是将我们加载到生产数据库中的测试数据提取到一个 fixture 文件中。我们可以使用 `manage.py dumpdata` 命令来做到这一点：

```py
python manage.py dumpdata survey --indent 4 >test_winning_answers.json

```

除了 `dumpdata` 命令本身外，那里指定的各种内容是：

+   `survey`：这将限制转储的数据到调查应用程序。默认情况下，`dumpdata` 将输出所有已安装应用程序的数据，但是获胜答案测试不需要来自调查以外的任何应用程序的数据，因此我们可以将 fixture 文件限制为只包含调查应用程序的数据。

+   `--indent 4`：这使得数据输出更容易阅读和编辑。默认情况下，`dumpdata` 将把数据输出到一行，如果你需要检查或编辑结果，这将很难处理。指定 `indent 4` 使 `dumpdata` 格式化数据为多行，四个空格缩进使结构的层次清晰。 （你可以为缩进值指定任何你喜欢的数字，不一定是 `4`。）

+   `>test_winning_answers.json`：这将命令的输出重定向到一个文件。`dumpdata` 的默认输出格式是 JSON，所以我们使用 `.json` 作为文件扩展名，这样当加载 fixture 时，它的格式将被正确解释。

当`dumpdata`完成时，我们将会有一个`test_winning_answers.json`文件，其中包含我们测试数据的序列化版本。除了将其作为我们测试的一部分加载（下面将介绍），我们还可以对此或任何装置文件做些什么呢？

首先，我们可以使用`manage.py loaddata`命令加载装置。因此，`dumpdata`和`loaddata`一起提供了一种将数据从一个数据库移动到另一个数据库的方法。其次，我们可能有或编写处理序列化数据的程序：有时在包含在平面文件中的数据上执行分析可能比在数据库中执行分析更容易。最后，`manage.py testserver`命令支持将装置（在命令行上指定）加载到测试数据库中，然后运行开发服务器。在您想要尝试使用这些测试数据来实验真实服务器的行为时，这可能会很方便，而不仅仅是限于使用数据编写的测试的结果。

### 在测试运行期间加载测试数据

回到我们手头的任务：当运行测试时，我们如何加载刚刚创建的这个装置？一个简单的方法是将其重命名为`initial_data.json`并将其放在我们调查应用程序目录的`fixtures`子目录中。如果我们这样做并运行测试，我们将看到装置文件被加载，并且我们的测试清晰获胜的情况运行成功：

```py
kmt@lbox:/dj_projects/marketr$ python manage.py test survey 
Creating test database... 
Creating table auth_permission 
Creating table auth_group 
Creating table auth_user 
Creating table auth_message 
Creating table django_content_type 
Creating table django_session 
Creating table django_site 
Creating table django_admin_log 
Creating table survey_survey 
Creating table survey_question 
Creating table survey_answer 
Installing index for auth.Permission model 
Installing index for auth.Message model 
Installing index for admin.LogEntry model 
Installing index for survey.Question model 
Installing index for survey.Answer model 
Installing json fixture 'initial_data' from '/dj_projects/marketr/survey/fixtures'. 
Installed 13 object(s) from 1 fixture(s) 
......... 
---------------------------------------------------------------------- 
Ran 9 tests in 0.079s 

OK 
Destroying test database... 

```

然而，这并不是真正正确的方法来加载特定的装置数据。初始数据装置是用于应用程序中应始终存在的常量应用程序数据，而这些数据并不属于这一类别。相反，它是特定于这个特定测试的，并且只需要为这个测试加载。为了做到这一点，将其放在`survey/fixtures`目录中，使用原始名称`test_winning_answers.json`。然后，更新测试用例代码，通过在测试用例的`fixtures`类属性中包含文件名来指定应该为这个测试加载这个装置：

```py
class QuestionWinningAnswersTest(TestCase): 

    fixtures = ['test_winning_answers.json'] 

    def testClearWinner(self): 
        q = Question.objects.get(question='Clear Winner') 
        wa_qs = q.winning_answers() 
        self.assertEqual(wa_qs.count(), 1) 
        winner = wa_qs[0] 
        self.assertEqual(winner.answer, 'Max Votes') 
```

请注意，`manage.py test`，至少在 Django 1.1 版本中，对于以这种方式指定的测试装置的加载并没有提供与加载初始数据装置相同的反馈。在先前的测试输出中，当装置被加载为初始数据时，会有关于加载初始数据装置和安装了 13 个对象的消息。当装置作为`TestCase`的一部分加载时，就没有这样的消息了。

此外，如果您在`TestCase fixtures`值中犯了错误并指定了错误的文件名，将不会有错误指示。例如，如果您错误地将`test_winning_answers`的结尾`s`省略了，那么唯一的问题指示将是测试用例失败：

```py
kmt@lbox:/dj_projects/marketr$ python manage.py test survey 
Creating test database... 
Creating table auth_permission 
Creating table auth_group 
Creating table auth_user 
Creating table auth_message 
Creating table django_content_type 
Creating table django_session 
Creating table django_site 
Creating table django_admin_log 
Creating table survey_survey 
Creating table survey_question 
Creating table survey_answer 
Installing index for auth.Permission model 
Installing index for auth.Message model 
Installing index for admin.LogEntry model 
Installing index for survey.Question model 
Installing index for survey.Answer model 
E........ 
====================================================================== 
ERROR: testClearWinner (survey.tests.QuestionWinningAnswersTest) 
---------------------------------------------------------------------- 
Traceback (most recent call last): 
 File "/dj_projects/marketr/survey/tests.py", line 67, in testClearWinner 
 q = Question.objects.get(question='Clear Winner') 
 File "/usr/lib/python2.5/site-packages/django/db/models/manager.py", line 120, in get 
 return self.get_query_set().get(*args, **kwargs) 
 File "/usr/lib/python2.5/site-packages/django/db/models/query.py", line 305, in get 
 % self.model._meta.object_name) 
DoesNotExist: Question matching query does not exist. 

---------------------------------------------------------------------- 
Ran 9 tests in 0.066s 

FAILED (errors=1) 
Destroying test database... 

```

可能将来对于这种错误情况提供的诊断可能会得到改进，但与此同时最好记住，像上面的`DoesNotExist`这样的神秘错误很可能是由于没有加载正确的测试装置而不是测试代码或被测试代码中的某些错误。

现在我们已经加载了测试装置并且第一个测试方法正常工作，我们可以为另外三种情况添加测试：其中一种是答案之间存在两种平局的情况，另一种是没有收到问题的回答，还有一种是没有答案与问题相关联的情况。这些测试可以编写得非常类似于测试清晰获胜情况的现有方法：

```py
    def testTwoWayTie(self): 
        q = Question.objects.get(question='2-Way Tie') 
        wa_qs = q.winning_answers() 
        self.assertEqual(wa_qs.count(), 2) 
        for winner in wa_qs: 
            self.assert_(winner.answer.startswith('Max Votes')) 

    def testNoResponses(self): 
        q = Question.objects.get(question='No Responses') 
        wa_qs = q.winning_answers() 
        self.assertEqual(wa_qs.count(), 0) 

    def testNoAnswers(self): 
        q = Question.objects.get(question='No Answers') 
        wa_qs = q.winning_answers() 
        self.assertEqual(wa_qs.count(), 0) 
```

区别在于从数据库中检索到的`Questions`的名称，以及如何测试具体的结果。在`2-Way Tie`的情况下，测试验证`winning_answers`返回两个答案，并且两者的`answer`值都以`'Max Votes'`开头。在没有回应和没有答案的情况下，所有测试只需要验证`winning_answers`返回的查询集中没有项目。

如果我们现在运行测试，我们会发现之前提到的错误，因为我们最后两个测试失败了：

```py
====================================================================== 
ERROR: testNoAnswers (survey.tests.QuestionWinningAnswersTest) 
---------------------------------------------------------------------- 
Traceback (most recent call last): 
 File "/dj_projects/marketr/survey/tests.py", line 88, in testNoAnswers 
 self.assertEqual(wa_qs.count(), 0) 
TypeError: count() takes exactly one argument (0 given) 

====================================================================== 
ERROR: testNoResponses (survey.tests.QuestionWinningAnswersTest) 
---------------------------------------------------------------------- 
Traceback (most recent call last): 
 File "/dj_projects/marketr/survey/tests.py", line 83, in testNoResponses 
 self.assertEqual(wa_qs.count(), 0) 
TypeError: count() takes exactly one argument (0 given) 

```

这里的问题是`winning_answers`在返回时不一致：

```py
def winning_answers(self): 
    rv = [] 
    max_votes = self.answer_set.aggregate(Max('votes')).values()[0] 
    if max_votes and max_votes > 0: 
        rv = self.answer_set.filter(votes=max_votes) 
    return rv 
```

`rv`的返回值在函数的第一行初始化为一个列表，但当它在有答案收到投票的情况下被设置时，它被设置为来自`filter`调用的返回值，它返回一个`QuerySet`，而不是一个列表。测试方法，因为它们在`winning_answers`的返回值上使用没有参数的`count()`，所以期望一个`QuerySet`。

对于`winning_answers`来说，返回列表还是`QuerySet`更合适？可能是`QuerySet`。调用者可能只对集合中答案的计数感兴趣，而不是具体的答案，因此可能不需要从数据库中检索实际的答案。如果`winning_answers`始终返回一个列表，它将不得不强制从数据库中读取答案以将它们放入列表中。因此，始终返回`QuerySet`并让调用者的要求决定最终需要从数据库中读取什么可能更有效。 （考虑到我们期望在这个集合中的项目数量很少，可能在这里几乎没有效率可言，但在设计接口时考虑这些事情仍然是一个好习惯。）

将`winning_answers`修复为始终返回`QuerySet`的一种方法是使用应用于`answer_set`的`none()`方法，它将返回一个空的`QuerySet`：

```py
def winning_answers(self):
    max_votes = self.answer_set.aggregate(Max('votes')).values()[0] 
    if max_votes and max_votes > 0:
        rv = self.answer_set.filter(votes=max_votes)
    else:
        rv = self.answer_set.none()
    return rv
```

进行这一更改后，`QuestionWinningAnswersTest TestCase`将成功运行。

## 在测试设置期间创建数据

虽然测试装置非常方便，但有时并不是适合所有工作的正确工具。具体来说，由于装置文件包含所有模型数据的固定、硬编码值，因此装置有时对于所有测试来说并不够灵活。

举个例子，让我们回到“调查”模型，并考虑一些我们可能希望它支持的方法。请记住，调查既有“开放”日期，也有“关闭”日期，因此在任何时间点，特定的“调查”实例可能被认为是“已完成”，“活跃”或“即将到来”，这取决于当前日期与调查的“开放”和“关闭”日期的关系。有易于访问这些不同类别的调查将是有用的。在 Django 中支持这一点的典型方法是为`Survey`创建一个特殊的模型`Manager`，该`Manager`实现了返回适当过滤的查询集的方法。这样的`Manager`可能如下所示：

```py
import datetime 
from django.db import models 

class SurveyManager(models.Manager): 
    def completed(self): 
        return self.filter(closes__lt=datetime.date.today()) 
    def active(self): 
        return self.filter(opens__lte=datetime.date.today()).\filter(closes__gte=datetime.date.today()) 
    def upcoming(self): 
        return self.filter(opens__gt=datetime.date.today()) 
```

这个管理器实现了三种方法：

+   `completed`：这将返回一个经过筛选的`Survey`的`QuerySet`，只包括那些`closes`值早于今天的调查。这些是关闭对任何更多回应的调查。

+   `active`：这将返回一个经过筛选的`Survey`的`QuerySet`，只包括那些`opens`值早于或等于今天，并且`closes`晚于或等于今天的调查。这些是可以接收回应的调查。

+   `upcoming`：这将返回一个经过筛选的`Survey`的`QuerySet`，只包括那些`opens`值晚于今天的调查。这些是尚未开放回应的调查。

要使这个自定义管理器成为`Survey`模型的默认管理器，将其实例分配给`Survey objects`属性的值：

```py
 class Survey(models.Model):
    title = models.CharField(max_length=60)
    opens = models.DateField()
    closes = models.DateField(blank=True)

    objects = SurveyManager()
```

为什么我们可能会在使用装置数据测试这些方法时遇到困难？问题出在这些方法依赖于今天日期的移动目标。对于测试`completed`来说，这并不是问题，因为我们可以为具有过去`closes`日期的调查设置测试数据，而这些`closes`日期将继续保持在过去，无论我们向前移动多少时间。

然而，`active`和`upcoming`是一个问题，因为最终，即使我们选择将“关闭”（对于`upcoming`，“打开”）日期设定在遥远的未来，今天的日期也会（除非发生普遍灾难）在某个时候赶上那些遥远的未来日期。当发生这种情况时，测试将开始失败。现在，我们可能期望我们的软件不会在那个遥远的时间仍在运行。（或者我们可能只是希望到那时我们不再负责维护它。）但这并不是一个好的方法。最好使用一种不会在测试中产生定时炸弹的技术。

如果我们不想使用一个带有硬编码日期的测试装置文件来测试这些例程，那么有什么替代方法呢？我们可以做的与之前的工作非常相似：在测试用例中动态创建数据。正如前面所述，这可能有点乏味，但请注意我们不必为每个测试方法重新创建数据。单元测试提供了一个钩子方法`setUp`，我们可以使用它来实现任何常见的测试前初始化。测试机制将确保我们的`setUp`例程在每个测试方法之前运行。因此，`setUp`是一个很好的地方，用于放置为我们的测试动态创建类似装置的数据的代码。

在对自定义“调查”管理器进行测试时，我们可能会有一个类似于以下的`setUp`例程：

```py
class SurveyManagerTest(TestCase): 
    def setUp(self): 
        today = datetime.date.today() 
        oneday = datetime.timedelta(1) 
        yesterday = today - oneday 
        tomorrow = today + oneday
        Survey.objects.all().delete()
        Survey.objects.create(title="Yesterday", opens=yesterday, closes=yesterday) 
        Survey.objects.create(title="Today", opens=today, closes=today) 
        Survey.objects.create(title="Tomorrow", opens=tomorrow, closes=tomorrow) 
```

这种方法创建了三个“调查”：一个昨天打开和关闭的，一个今天打开和关闭的，一个明天打开和关闭的。在创建这些之前，它会删除数据库中的所有“调查”对象。因此，`SurveyManagerTest`中的每个测试方法都可以依赖于数据库中确切地有三个“调查”，每个处于三种状态之一。

为什么测试首先删除所有“调查”对象？数据库中应该还没有任何“调查”，对吧？那个调用只是为了以防将来调查应用程序获取包含一个或多个“调查”的初始数据装置。如果存在这样的装置，它将在测试初始化期间加载，并且会破坏这些依赖数据库中确切地有三个“调查”的测试。因此，在这里`setUp`最安全的做法是确保数据库中唯一的“调查”是它创建的。

然后可能会有一个`Survey`管理器`completed`函数的测试：

```py
    def testCompleted(self): 
        self.assertEqual(Survey.objects.completed().count(), 1) 
        completed_survey = Survey.objects.get(title="Yesterday") 
        self.assertEqual(Survey.objects.completed()[0], completed_survey) 

        today = datetime.date.today() 
        completed_survey.closes = today 
        completed_survey.save() 
        self.assertEqual(Survey.objects.completed().count(), 0) 
```

测试首先断言进入时数据库中有一个已完成的“调查”。然后验证`completed`函数返回的一个“调查”实际上是它期望完成的实际调查，即标题设置为“昨天”的调查。然后测试进一步修改了已完成的“调查”，使其“关闭”日期不再使其符合已完成的资格，并将该更改保存到数据库。完成后，测试断言数据库中现在有零个已完成的“调查”。

通过该例程进行测试可以验证测试是否有效，因此，对于活动调查的类似测试可能会被写成：

```py
    def testActive(self):
        self.assertEqual(Survey.objects.active().count(), 1)
        active_survey = Survey.objects.get(title="Today")
        self.assertEqual(Survey.objects.active()[0], active_survey)
        yesterday = datetime.date.today() - datetime.timedelta(1)
        active_survey.opens = active_survey.closes = yesterday
        active_survey.save()
        self.assertEqual(Survey.objects.active().count(), 0)
```

这与“已完成”测试非常相似。它断言进入时有一个活动的“调查”，检索活动的“调查”并验证它是否是预期的活动的“调查”，修改它以使其不再符合活动的资格（使其符合关闭的资格），保存修改，最后验证“活动”然后返回没有活动的“调查”。

类似地，一个关于即将到来的调查的测试可能是：

```py
    def testUpcoming(self):
        self.assertEqual(Survey.objects.upcoming().count(), 1)
        upcoming_survey = Survey.objects.get(title="Tomorrow")
        self.assertEqual(Survey.objects.upcoming()[0], upcoming_survey)
        yesterday = datetime.date.today() - datetime.timedelta(1)
        upcoming_survey.opens = yesterday
        upcoming_survey.save()
        self.assertEqual(Survey.objects.upcoming().count(), 0)
```

但是，所有这些测试不会相互干扰吗？例如，`completed`的测试使“昨天”的调查似乎是活动的，`active`的测试使“今天”的调查似乎是关闭的。似乎无论哪个先运行，都会进行更改，从而干扰其他测试的正确操作。

实际上，这些测试并不会相互干扰，因为在运行每个测试方法之前，数据库会被重置，并且测试用例的 `setUp` 方法会被重新运行。因此 `setUp` 不是每个 `TestCase` 运行一次，而是每个 `TestCase` 中的测试方法运行一次。运行这些测试显示，尽管每个测试都会更新数据库，以一种可能会干扰其他测试的方式，但所有这些测试都通过了，如果其他测试看到了它所做的更改，就会相互干扰：

```py
testActive (survey.tests.SurveyManagerTest) ... ok
testCompleted (survey.tests.SurveyManagerTest) ... ok
testUpcoming (survey.tests.SurveyManagerTest) ... ok
```

`setUp` 有一个伴随方法，叫做 `tearDown`，可以用来在测试方法之后执行任何清理工作。在这种情况下，这并不是必要的，因为 Django 默认的操作会在测试方法执行之间重置数据库，从而撤消测试方法所做的数据库更改。`tearDown` 例程对于清理任何非数据库更改（例如临时文件创建）可能会被测试所做的更改非常有用。

# 总结

我们现在已经掌握了对 Django 应用程序进行单元测试的基础知识。在本章中，我们：

+   将先前编写的 `Survey` 模型的 doctests 转换为单元测试，这使我们能够直接比较每种测试方法的优缺点

+   重新审视了上一章的 doctest 注意事项，并检查了单元测试在多大程度上容易受到相同问题的影响

+   开始学习一些单元测试的附加功能；特别是与加载测试数据相关的功能。

在下一章中，我们将开始研究更多可用于 Django 单元测试的高级功能。
