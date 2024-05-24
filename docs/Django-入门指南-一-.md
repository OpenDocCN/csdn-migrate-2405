# Django 入门指南（一）

> 原文：[`zh.annas-archive.org/md5/2CE5925D7287B88DF1D43517EEF98569`](https://zh.annas-archive.org/md5/2CE5925D7287B88DF1D43517EEF98569)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

多年来，Web 开发已经通过框架得到了发展。Web 开发变得更加高效，质量也得到了提高。Django 是一个非常复杂和流行的框架。框架是一组旨在简化和标准化开发的工具。它允许开发人员从非常实用的工具中受益，以最小化开发时间。然而，使用框架进行开发需要了解框架及其正确的使用方法。本书使用逐步教学法帮助初学者开发人员学习如何轻松应对 Django 框架。本书中的示例解释了一个简单 Web 工具的开发：基于文本的任务管理器。

# 本书涵盖内容

第一章，“Django 在 Web 上的位置”，简要介绍了 Web 的历史和发展。它解释了框架和 MVC 模式是什么。最后介绍了 Django。

第二章，“创建 Django 项目”，涉及安装使用 Django 所需的软件。在本章结束时，您将拥有一个准备好编码的开发环境。

第三章，“使用 Django 的 Hello World!”，描述了在提醒正则表达式后的 Django 路由。最后以一个简单的控制器示例结束，该控制器在用户的浏览器上显示“Hello world!”。

第四章，“使用模板”，解释了 Django 模板的工作原理。它涵盖了模板语言的基础知识以及架构模板和 URL 创建的最佳实践。

第五章，“使用模型”，描述了在 Django 中构建模型。它还解释了如何生成数据库以及如何使用 South 工具进行维护。本章还向您展示了如何通过管理模块设置管理界面。

第六章，“使用 Querysets 获取模型数据”，解释了如何通过模型对数据库执行查询。使用示例来测试不同类型的查询。

第七章，“使用 Django 表单”，讨论了 Django 表单。它解释了如何使用 Django 创建表单以及如何处理它们。

第八章，“使用 CBV 提高生产力”，专注于 Django 的一个独特方面：基于类的视图。本章解释了如何在几秒钟内创建 CRUD 界面。

第九章，“使用会话”，解释了如何使用 Django 会话。不同的实际示例展示了会话变量的使用以及如何充分利用它们。

第十章，“认证模块”，解释了如何使用 Django 认证模块。它涵盖了注册、登录以及对某些页面的访问限制。

第十一章，“使用 Django 进行 AJAX”，描述了 jQuery 库的基础知识。然后，它展示了使用 Django 进行 AJAX 的实际示例，并解释了这些页面的特点。

第十二章，“使用 Django 进行生产”，解释了如何使用 Django Web 服务器（如 Nginx）和 PostgreSQL Web 系统数据库部署网站。

附录，“速查表”，是对 Django 开发人员有用的常见方法或属性的快速参考。

# 本书所需内容

Django 开发所需的软件如下：

+   Python 3

+   PIP 1.5

+   Django 1.6

# 本书适合对象

本书适用于希望学习如何使用高质量框架创建网站的 Python 开发人员。本书也适用于使用其他语言（如 PHP）的 Web 开发人员，他们希望提高网站的质量和可维护性。本书适用于具有 Python 基础和 Web 基础知识的任何人，他们希望在当今最先进的框架之一上工作。

# 惯例

在本书中，您会发现一些文本样式，用于区分不同类型的信息。以下是一些这些样式的例子，以及它们的含义解释。

文本中的代码单词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 用户名会显示如下：“我们可以通过使用`settings.py`指令来包含其他上下文。”

代码块设置如下：

```py
from django.conf.urls import patterns, include, url
from django.contrib import admin
admin.autodiscover()
urlpatterns = patterns('',
# Examples:
# url(r'^$', 'Work_msanager.views.home', name='home'),
# url(r'^blog/', include('blog.urls')),
url(r'^admin/', include(admin.site.urls)),
)
```

任何命令行输入或输出都以以下方式书写：

```py
root@debian: wget https://raw.github.com/pypa/pip/master/contrib
/get-pip.py
root@debian:python3 get-pip.py

```

**新术语**和**重要单词**以粗体显示。例如，屏幕上看到的单词，菜单或对话框中的单词会以这种方式出现在文本中：“点击**高级系统设置**。”

### 注意

警告或重要提示会以这样的框出现。

### 提示

提示和技巧会以这种方式出现。


# 第一章：Django 在网络上的位置

近年来，Web 开发发生了重大变化，特别是出现了 Web 框架。我们将学习如何使用 Django 框架创建一个完整的网站。

在本章中，我们将讨论以下内容：

+   网络的变化

+   Django 的介绍

+   MVC 开发模式

# 从 Web 1.0 到 Web 2.0

今天你看到的网络并不总是像今天这样。事实上，许多技术，如 CSS，AJAX 或新的 HTML 5 版本都改进了网络。

## 网络 1.0

25 年前，由于不断增长的新技术，网络诞生了。其中两个非常决定性：

+   HTML 语言是一种显示语言。它允许您使用嵌套标签组织信息。

+   HTTP 协议是一种通信网络协议，允许客户端和服务器进行通信。客户端通常是 Firefox 或 Google Chrome 等浏览器，服务器往往是 Nginx，Apache 或 Microsoft IIS 等 Web 服务器。

起初，开发人员使用`<table>`标签来组织页面的各种元素，如菜单，标题或内容。网页上显示的图像分辨率较低，以避免使页面变得沉重。用户唯一能够执行的操作是点击超文本链接以导航到其他页面。

这些超文本链接使用户能够通过发送一种类型的数据（页面的 URL）从一个页面导航到另一个页面。**统一资源定位符**（**URL**）定义了获取资源（如 HTML 页面，图片或 PDF 文件）的唯一链接。用户发送的数据除了 URL 之外没有其他数据。

## Web 2.0

Web 2.0 这个术语是由 Dale Dougherty，O'Reilly Media 公司创造的，并在 2004 年 10 月由 Tim O'Reilly 在第一次 Web 2.0 会议上传播。

这个新的网络变得互动和可达到初学者。它成为了许多技术的礼物，包括以下内容：

+   服务器端语言，如 PHP，**Java 服务器页面**（**JSP**）或 ASP。这些语言允许您与数据库通信以提供动态内容。这也允许用户通过 HTML 表单发送数据以便使用 Web 服务器处理数据。

+   数据库存储了大量信息。这些信息可以用来验证用户或显示从较旧到最近的条目列表。

+   客户端脚本，如 JavaScript，使用户能够在不刷新页面的情况下执行简单的任务。**异步 JavaScript 和 XML**（**AJAX**）为当前网络带来了一个重要的功能：客户端和服务器之间的异步交换。由于这一点，无需刷新页面即可享受网站。

如今，Web 2.0 无处不在，它已成为我们日常生活的一部分。Facebook 是 Web 2.0 网站的一个完美例子，用户之间完全互动，并在其数据库中存储了大量信息。Web 应用程序已经被普及，如网络邮件或 Google 网络应用程序。

正是在这种哲学中，Django 出现了。

# 什么是 Django？

Django 诞生于 2003 年堪萨斯州劳伦斯的一家新闻机构。它是一个使用 Python 创建网站的 Web 框架。它的目标是编写非常快速的动态网站。2005 年，该机构决定以 BSD 许可证发布 Django 源代码。2008 年，Django 软件基金会成立以支持和推进 Django。几个月后发布了框架的 1.00 版本。

！[什么是 Django？]（img/00002.jpeg）

### 注意

**Django 的口号**

完美主义者与截止日期的网络框架。

Django 的口号很明确。这个框架是为了加速网站开发阶段而创建的，但并不是唯一的。事实上，这个框架使用了 MVC 模式，这使我们能够拥有一个一致的架构，正如我们将在下一章中看到的那样。

直到 2013 年，Django 只兼容 Python 2.x 版本，但 2013 年 2 月 26 日发布的 Django 1.5 版本标志着 Python 3 兼容性的开始。

如今，像 Instagram 移动网站、Mozilla.org 和 Openstack.org 这样的大型组织正在使用 Django。

## Django - 一个 Web 框架

框架是一组软件，它组织了应用程序的架构，并使开发人员的工作更加轻松。框架可以适应不同的用途。它还提供了实用工具，使程序员的工作更快。因此，一些在网站上经常使用的功能可以被自动化，比如数据库管理和用户管理。

一旦程序员掌握了一个框架，它会极大地提高他们的生产力和代码质量。

# MVC 框架

在 MVC 框架存在之前，Web 编程混合了数据库访问代码和页面的主要代码。这将 HTML 页面返回给用户。即使我们将 CSS 和 JavaScript 文件存储在外部文件中，服务器端语言代码仍然存储在至少三种语言之间共享的一个文件中：Python、SQL 和 HTML。

MVC 模式是为了将逻辑与表示分离，并拥有更加具体和真实的内部架构而创建的。**模型-视图-控制器**（**MVC**）代表了该范式推荐的三个应用程序层：

+   **模型**：这些代表数据库中的数据组织。简单地说，我们可以说每个模型定义了数据库中的一个表以及其他模型之间的关系。多亏了它们，每一点数据都存储在数据库中。

+   **视图**：这些包含将发送给客户端的所有信息。它们生成最终的 HTML 文档。我们可以将 HTML 代码与视图关联起来。

+   **控制器**：这些包含服务器执行的所有操作，对客户端不可见。控制器检查用户是否经过身份验证，或者可以从模板生成 HTML 代码。

![MVC 框架](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/gtst-dj/img/00003.jpeg)

在具有 MVC 模式的应用程序中遵循以下步骤：

1.  客户端向服务器发送请求，要求显示一个页面。

1.  控制器通过模型使用数据库。它可以创建、读取、更新或删除任何记录，或对检索到的数据应用任何逻辑。

1.  模型从数据库发送数据；例如，如果我们有一个在线商店，它会发送产品列表。

1.  控制器将数据注入视图以生成它。

1.  视图根据控制器提供的数据返回其内容。

1.  控制器将 HTML 内容返回给客户端。

MVC 模式使我们能够为每个项目的工作者获得一致性。在一个有网页设计师和开发人员的网络代理公司中，网页设计师是视图的负责人。鉴于视图只包含 HTML 代码，网页设计师不会被开发人员的代码打扰。开发人员编辑他们的模型和控制器。

特别是 Django 使用了 MVT 模式。在这种模式中，视图被模板替换，控制器被视图替换。在本书的其余部分，我们将使用 MVT 模式。因此，我们的 HTML 代码将是模板，我们的 Python 代码将是视图和模型。

# 为什么使用 Django？

以下是使用 Django 的优势的非尽事例清单：

+   Django 是根据 BSD 许可发布的，这确保了 Web 应用程序可以自由使用和修改，而不会出现任何问题；它也是免费的。

+   Django 是完全可定制的。开发人员可以通过创建模块或覆盖框架方法来轻松地适应它。

+   这种模块化增加了其他优势。有很多 Django 模块可以集成到 Django 中。你可以得到一些帮助，因为你经常会找到你可能需要的高质量模块。

+   在这个框架中使用 Python 可以让你享受所有 Python 库的好处，并确保非常好的可读性。

+   Django 是一个旨在完美的框架。它专门为那些希望为他们的应用程序编写清晰代码和良好架构的人而设计。它完全遵循“不要重复自己”（DRY）的理念，这意味着在多个地方保持代码简洁，而不必复制/粘贴相同的部分。

+   关于质量，Django 集成了许多有效的方法来执行单元测试。

+   Django 得到了一个良好的社区支持。这是一个非常重要的资产，因为它可以让您快速解决问题和修复错误。多亏了社区，我们还可以找到展示最佳实践的代码示例。

Django 也有一些缺点。当开发人员开始使用一个框架时，他/她会开始一个学习阶段。这个阶段的持续时间取决于框架和开发人员。如果开发人员了解 Python 和面向对象编程，那么 Django 的学习阶段相对较短。

还可能出现一个新版本的框架发布，修改了一些语法。例如，Django 1.5 版本改变了模板中 URL 的语法。（更多细节，请访问[`docs.djangoproject.com/en/1.5/ref/templates/builtins/#url`](https://docs.djangoproject.com/en/1.5/ref/templates/builtins/#url)。）尽管如此，文档提供了每个 Django 更新的详细信息。

# 总结

在本章中，我们研究了使 Web 进化为 Web 2.0 的变化。我们还研究了将逻辑与表示分离的 MVC 的运作方式。最后，我们介绍了 Django 框架。

在下一章中，我们将使用 Python、PIP 和 Django 建立我们的开发环境。


# 第二章：创建 Django 项目

在本章结束时，您将拥有开始使用 Django 进行编程所需的所有必要元素。使用 Django 开发的网站是包含一个或多个应用程序的项目。实际上，当一个网站变得更加重要时，将其在逻辑上分成几个模块变得必要。然后，这些模块被放置在对应于网站的项目中。在本书中，我们不需要创建许多应用程序，但在某些情况下它们可能非常有用。实际上，如果有一天您创建了一个应用程序，并且希望在另一个项目中使用它，您将需要将该应用程序复制并调整以适应新项目。

要能够使用 Django，您需要安装以下软件：

+   Python 3，享受第三版的创新。

+   setuptools 是一个简化外部 Python 模块安装的模块。但是，它无法管理卸载模块。

+   PIP 通过删除软件包、使用更简单的语法和提供其他好处来扩展 setuptools 的可能性。

+   Django，我们将通过 PIP 安装。

这些安装将与 Windows、Linux 和 Mac OS X 兼容。

# 安装 Python 3

要使用到目前为止我们谈到的所有工具，我们首先需要安装 Python 3。以下部分描述了如何在不同的操作系统上安装 Python。

## 为 Windows 安装 Python 3

要下载 Python 可执行文件，请访问[`www.python.org/download/`](http://www.python.org/download/)并下载**Python MSI**文件。请确保您选择与您的平台相关的正确版本。Python 安装可能需要管理员帐户。

对于 Python 安装的所有阶段，您可以将所有设置保留为默认值。如果安装正确完成，您应该看到以下对话框窗口打开：

![为 Windows 安装 Python 3](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/gtst-dj/img/00004.jpeg)

## 为 Linux 安装 Python 3

要在 Linux 上设置 Python 3，我们可以使用以下命令的包管理器 APT：

```py
root@debian:apt-get install python3

```

### 提示

**下载示例代码**

您可以从您在[`www.packtpub.com`](http://www.packtpub.com)的帐户中为您购买的所有 Packt 图书下载示例代码文件。如果您在其他地方购买了本书，您可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册，以便直接通过电子邮件接收文件。

我们需要确认 APT 提出的修改。

## 为 Mac OS 安装 Python 3

最新版本的 Mac OS 已经安装了 Python 的一个版本。但是，安装了 Python 的第 2 版，我们想要安装第 3 版。为此，请访问[`www.python.org/download/`](https://www.python.org/download/)并下载正确的版本。然后，打开扩展名为`.dmp`的文件。最后，运行扩展名为`.mpkg`的文件。如果出现诸如`Python 无法打开，因为它来自未知开发者`的错误，请执行以下步骤：

1.  在**Finder**中，找到 Python 安装位置。

1.  按下*ctrl*键，然后单击应用程序图标。

1.  从快捷菜单中选择**打开**。

1.  单击**打开**。

# 安装 setuptools

PIP 是 setuptools 的一个依赖项。我们需要安装 setuptools 才能使用 PIP。以下部分描述了如何在不同的操作系统上安装 setuptools。

## 为 Windows 安装 setuptools

要下载 setuptools 可执行文件，您必须转到 PyPI 网站[`pypi.python.org/pypi/setuptools`](https://pypi.python.org/pypi/setuptools)。然后，我们需要单击**下载**并选择正确的版本。在本书中，我们使用 1.1 版本，如下面的屏幕截图所示：

![为 Windows 安装 setuptools](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/gtst-dj/img/00005.jpeg)

## 为 Linux 安装 setuptools

使用 APT 时，我们不需要安装 setuptools。实际上，APT 将在安装 PIP 之前自动安装它。

## 为 Mac OS 安装 setuptools

当我们使用`get-pip.py`文件安装 PIP 时，setuptools 将直接安装。因此，我们暂时不需要安装它。

# 安装 PIP

PIP 在 Python 用户中非常受欢迎，并且使用 PIP 是 Django 社区的最佳实践。它处理包安装，执行更新，并删除所有 Python 包扩展。由于这个，我们可以安装所有 Python 所需的包。

如果您安装了 Python 3.4 或更高版本，PIP 已包含在 Python 中。

## 在 Windows 上安装 PIP

要安装 PIP，首先从[`pypi.python.org/pypi/pip/1.5.4`](https://pypi.python.org/pypi/pip/1.5.4)下载它。

然后，我们需要从可执行文件安装 PIP，但不要忘记定义正确的 Python 安装文件夹，如下面的屏幕截图所示：

![为 Windows 安装 PIP](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/gtst-dj/img/00006.jpeg)

对于下一组步骤，请使用默认选项并完成安装。有了 PIP，我们将安装所有所需的 Python 包。

## 在 Linux 上安装 PIP

要在 Linux 上安装 PIP 和包括 setuptools 在内的所有组件，您必须使用以下命令使用`get-pip.py`文件：

```py
root@debian: wget https://raw.github.com/pypa/pip/master/contrib/get-pip.py
root@debian:python3 get-pip.py

```

## 在 Mac OS 上安装 PIP

要在 Mac OS 上安装 PIP，我们必须以以下方式使用`get-pip.py`文件：

```py
curl -O https://raw.github.com/pypa/pip/master/contrib/get-pip.py sudo python3 get-pip.py

```

# 安装 Django

然后，我们将安装我们将要使用的框架。以下部分描述了如何在不同的操作系统上安装 Django。

## 在 Windows 上安装 Django

要使用 PIP 安装 Django，您必须打开命令提示符并转到`Python`文件夹中可以找到的`Scripts`目录。您可以使用以下命令安装 Django：

```py
C:\Python33\Scripts\pip.exe install django=="X.X"

```

PIP 将在 Python 的`site-packages`存储库中下载并安装 Django 包。

## 在 Linux 上安装 Django

为了方便我们刚刚安装的 PIP 的使用，我们必须查找系统上安装的版本并定义一个别名来引用已安装的 PIP 版本。不要忘记以 root 身份执行以下命令：

```py
root@debian:compgen -c | grep pip
root@debian:alias pip=pip-3.2
root@debian:pip install django=="1.6"

```

第一个命令查找包含单词`pip`的可用命令。您肯定会找到一行，比如`pip-3.2`。我们将在这个命令上使用第二个命令定义一个别名。

第三个命令安装 Django 的 1.6 版本。

## 在 Mac OS 上安装 Django

如果您想更轻松地使用 PIP，可以使用以下命令创建符号链接：

```py
cd /usr/local/binln -s ../../../Library/Frameworks/Python.framework/Version/3.3/bin/pip3 pip

```

然后，我们可以使用以下命令安装 Django：

```py
pip install django=="1.6"

```

# 使用 Django 启动您的项目

在开始使用 Django 之前，您需要为您的应用程序创建一个环境。我们将创建一个 Django 项目。然后，这个项目将包含我们的应用程序。

要创建我们的应用程序的项目，我们需要使用`django-admin.py`文件运行以下命令（您可以在`Python33\Scripts`文件夹中找到它）：

```py
django-admin.py startproject Work_manager

```

为了方便使用 Django 命令，我们可以设置 Windows 的环境变量。为此，您必须执行以下步骤：

1.  在桌面上右键单击**我的电脑**。

1.  点击**高级系统设置**。

1.  接下来，点击**环境变量**。

1.  添加或更新`PATH`变量：

+   如果不存在，创建`PATH`变量并将其值设置为`C:\Python33/Scripts`

+   如果存在，将`;C:\Python33\Scripts`追加到现有值

1.  现在，您可以使用之前的命令，而无需进入`Python33/Scripts`文件夹。

### 注意

有不同的方法来执行前面的命令：

+   以下命令将在所有情况下执行：

```py
C:\Python33\python.exe C:\Python33\Scripts\django-admin.py startproject Work_manager

```

+   如果我们在`PATH`变量中定义了`C:\Python33\Scripts`，则将执行以下命令：

```py
C:\Python33\python.exe django-admin.py startproject Work_manager

```

+   如果我们在`PATH`变量中定义了`C:\Python33\Scripts`并且`.py`扩展文件被定义为与 Python 一起运行，则将执行以下命令：

```py
django-admin.py startproject Work_manager

```

这个命令在您运行命令的文件夹中创建一个`Work_manager`文件夹。我们将在该文件夹中找到一个文件夹和一个文件：

+   `manage.py`文件将用于在项目上执行操作，比如启动开发服务器或将数据库与模型同步。

+   `Work_manager`文件夹代表我们项目的一个应用程序。默认情况下，`startproject`命令会创建一个新的应用程序。

`Work_manager`文件夹包含两个非常重要的文件：

+   `settings.py`文件包含我们项目的参数。这个文件对我们所有的应用程序都是通用的。我们用它来定义调试模式，配置数据库，或者定义我们将使用的 Django 包。`settings.py`文件允许我们做更多的事情，但我们的使用将局限于之前描述的内容。

+   `urls.py`文件包含我们所有的 URL。通过这个文件，我们在 Django 中进行路由。我们将在下一章中介绍这个。

# 创建一个应用程序

我们不会在`Work_manager`文件夹中编写我们的应用程序，因为我们想要创建我们自己的`Task_manager`应用程序。

为此，请使用`startproject`命令创建的`manage.py`文件运行以下命令。您必须在包含`manage.py`文件的`Work_manager`文件夹中运行以下命令：

```py
Manage.py startapp TasksManager

```

这个命令在我们项目的文件夹中创建了一个`TasksManager`文件夹。这个文件夹包含五个文件：

+   `__init__.py`文件定义了一个包。Python 需要它来区分标准文件夹和包。

+   `admin.py`文件目前没有用。它包含需要并入管理模块的模型。

+   `models.py`文件包含我们应用程序的所有模型。我们在应用程序的开发中经常使用它。模型允许我们创建数据库并存储信息。我们将在第五章中讨论这一点，*使用模型*。

+   `tests.py`文件包含我们应用程序的单元测试。

+   `views.py`文件可以包含视图。这个文件将包含在将 HTML 页面发送给客户端之前执行的所有操作。

既然我们知道了 Django 最重要的文件，我们可以配置我们的项目了。

# 配置应用程序

要配置我们的项目或应用程序，我们需要编辑项目文件夹中的`settings.py`文件。

这个文件包含变量。这些变量是 Django 在初始化 Web 应用程序时读取的设置。以下是其中的一些变量：

+   `DEBUG`：在开发过程中，此参数必须设置为`True`，因为它可以显示错误。当将项目投入生产时，不要忘记将其设置为`False`，因为错误会提供有关站点安全性的非常敏感的信息。

+   `TIME_ZONE`：此参数设置了必须计算日期和时间的区域。默认值是`UTC`。

+   `DEFAULT_CHARSET`：这设置了所使用的字符编码。在`task_manager`应用程序中，我们使用 UTF-8 编码来简化国际化。为此，您必须添加以下行：

```py
DEFAULT_CHARSET = 'utf-8'
```

+   `LANGUAGE_CODE`：这设置了网站上要使用的语言。这是国际化的主要有用参数。

+   `MIDDLEWARE_CLASSES`：这定义了所使用的不同中间件。

中间件是在请求过程中执行的类和方法，包括在参数中执行的方法。为了简化开发的开始，我们将从该参数中删除一个中间件。这需要您在行前添加`#`来注释掉该行：

```py
# 'django.middleware.csrf.CsrfViewMiddleware',
```

我们将在后面的章节中讨论这个中间件，以解释它的操作和重要性。

既然我们已经了解了 Django 的一般设置，我们可以开始开发我们的应用程序了。

# 总结

在本章中，我们已经安装了使用 Django 所需的所有软件。我们学会了如何创建 Django 项目和应用程序。我们还学会了如何配置应用程序。

在下一章中，我们将以一个包含文本`Hello World!`的网页示例开始 Django 开发。


# 第三章：使用 Django 的 Hello World！

在本章中，我们实际上不会开始开发阶段。相反，我们将学习网站的基础知识，以了解 Django，即项目和应用程序的创建。在本章中，我们还将：

+   学习如何使用正则表达式

+   创建你的第一个 URL

+   创建你的第一个视图

+   测试你的应用程序

在本章结束时，我们将创建我们的第一个网页，显示`Hello World!`。

# Django 中的路由

在上一章中，我们编辑了`settings.py`文件来配置我们的 Django 项目。我们将再次编辑`settings.py`以添加一个新参数。以下行必须存在于`settings.py`中：

```py
ROOT_URLCONF = 'Work_manager.urls'
```

此参数将定义包含我们网站所有 URL 的 Python 文件。我们已经谈到了之前的文件，因为它在`Work_manager`文件夹中。用于定义`ROOT_URLCONF`变量的语法意味着 Django 将`Workmanager`包中的`urls.py`文件中的 URLs 带到项目的根目录。

我们的应用程序的路由将基于此文件。路由定义了基于发送的 URL 将如何处理客户端请求。

实际上，当控制器接收到客户端请求时，它将进入`urls.py`文件，并检查 URL 是否是客户端的请求，并使用相应的视图。

例如，在以下 URL 中，Django 将在`urls.py`中查找`search`字符串，以了解要采取什么操作：`http://localhost/search`。

这是`urls.py`文件的样子，它是 Django 创建项目时创建的：

```py
from django.conf.urls import patterns, include, url
from django.contrib import admin
admin.autodiscover()
urlpatterns = patterns('',
    # Examples:
    # url(r'^$', 'Work_msanager.views.home', name='home'),
    # url(r'^blog/', include('blog.urls')),
    url(r'^admin/', include(admin.site.urls)),
)
```

我们将详细介绍此文件的组件：

+   第一行导入了在 URL 管理中常用的函数。

+   下面两行对管理模块很有用。我们将通过在行首添加`#`来进行注释。这些行将在后面的章节中解释。

+   其余的行定义了`urlpatterns`变量中的 URL。我们还将审查以`url (r '^ admin`开头的 URL。

在从 Web 客户端接收到请求后，控制器会线性地遍历 URL 列表，并检查 URL 是否符合正则表达式。如果不符合，控制器将继续检查列表的其余部分。如果符合，控制器将通过在 URL 中发送参数来调用相应视图的方法。如果您想编写 URL，您必须首先了解正则表达式的基础知识。

# 正则表达式

正则表达式就像一个小语言本身。尽管它们复杂且难以理解，但它们可以以极大的灵活性操纵字符串。它们由一系列字符组成，用于定义模式。

我们不会在本书中探讨所有正则表达式的概念，因为这将需要几章，并使我们偏离本书的主要目标。在编写您的第一个 URL 之前，练习您的正则表达式；许多网站可以帮助您在正则表达式上进行训练。搜索“在线正则表达式匹配器”，您将找到通过 JavaScript 检查您的正则表达式的页面。您还可以通过 Félix López 撰写的书籍*Mastering Regular Expressions Python*，*Packt Publishing*进一步探索正则表达式。有一个实用工具可以可视化正则表达式。这个工具叫做**Regexper**，由 Jeff Avallone 创建。我们将使用它来表示正则表达式的图表。

以下部分探讨了使用的模式、函数和示例，以帮助您更好地理解正则表达式。

## 未解释的字符

未解释的字符，如字母和数字，在正则表达式中意味着它们存在于字符串中，并且必须按照完全相同的顺序放置。

例如，正则表达式`test01`将验证`test01`、`dktest01`和`test0145g`字符串，但不会验证`test10`或`tste01`。

正则表达式`test-reg`将验证`a test-regex`，但不会验证`test-aregex`或`testregex:`

![未解释的字符](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/gtst-dj/img/00007.jpeg)

`test01`正则表达式的可视化表示

## 行的开头和结尾

要检查字符串是否必须出现在行的开头或结尾，你必须使用`^`和`$`字符。如果`^`出现在字符串的开头，验证将在字符串的开头进行。对于`$`在结尾的情况也是一样。

以下是一些示例：

+   `^test`正则表达式将验证`test`和`test01l`，但不会验证`dktest`或`ttest01`：![行的开头和结尾](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/gtst-dj/img/00008.jpeg)

+   正则表达式`test$`将验证`test`和`01test`，但不会验证`test01`：![行的开头和结尾](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/gtst-dj/img/00009.jpeg)

+   正则表达式`^test$`只验证`test`：![行的开头和结尾](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/gtst-dj/img/00010.jpeg)

## 任意字符的正则表达式

在正则表达式中，句点（`.`）表示“任意字符”。因此，当你验证无法推断的字符时，会使用句点。如果你尝试在你的语音中验证句点，使用转义字符`\`。

以下是示例：

+   `^te.t`验证`test`或`tept`：![任意字符的正则表达式](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/gtst-dj/img/00011.jpeg)

+   `^test\.me$`只验证`test.me`：![任意字符的正则表达式](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/gtst-dj/img/00012.jpeg)

## 字符类

要验证字符，你可以使用字符类。字符类用方括号括起来，包含所有允许的字符。要验证位置中的所有数字和字母，你必须使用`[0123456789a]`。例如，`^tes[t0e]$`只验证三个字符串：`test`、`tes0`和`tese`。

你也可以使用以下预定义类：

+   `[0-9]`等同于`[0123456789]`

+   `[a-z]`匹配所有字母，`[abcdefghijklmnopqrstuvwxyz]`

+   `[A-Z]`匹配所有大写字母

+   `[a-zA-Z]`匹配所有字母

以下是快捷方式：

+   `\d`等同于`[0-9]`

+   `\w`等同于`[a-zA-Z0-9_]`

+   `[0-9]`等同于`[0123456789]`

## 验证字符的数量

到目前为止，我们学习的一切都是定义一个且仅一个字符的元素。要验证一个字符出现一次或多次，必须使用大括号`{x, y}`，其中`x`定义了最小出现次数，`y`是最大出现次数。如果其中一个未指定，将会有一个未定义的值。例如，如果你忘记在`{2,}`中包含一个元素，这意味着该字符必须至少出现两次。

以下是一些示例：

+   `^test{2, 3}$`只验证`testt`和`testtt`：![验证字符的数量](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/gtst-dj/img/00013.jpeg)

+   `^tests{0,1}$`只验证`test`和`tests`![验证字符的数量](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/gtst-dj/img/00014.jpeg)

+   `. ^ {1} $`验证除一个之外的所有通道：空字符串

以下是快捷方式：

+   `*`等同于`{0}`

+   `?`等同于`{0, 1}`

+   `+`等同于`{1}`

正则表达式非常强大，即使在 Django 编程之外也会非常有用。

# 创建我们的第一个 URL

Django 的一个有趣特性之一是包含了一个开发服务器。事实上，在网站开发阶段，开发人员不需要设置 Web 服务器。然而，当你将网站投入生产时，你将需要安装一个真正的 Web 服务器，因为它不适用于生产环境。

事实上，Django 服务器并不安全，几乎无法承受大量负载。这并不意味着你的网站会变得缓慢且充满缺陷；它只是意味着你必须在生产中使用一个真正的 Web 服务器。

要使用开发服务器，我们需要使用`manage.py` runserver 命令文件。我们必须启动命令提示符并进入项目根目录（使用`cd`命令浏览文件夹）来执行命令：

```py
manage.py runserver 127.0.0.1:8000

```

这个命令启动了 Django 开发服务器。让我们逐步解释控制：

+   `runserver`参数启动开发服务器。

+   `127.0.0.1`是我们网络适配器的内部 IP 地址。这意味着我们的服务器只会监听和响应在其上启动的计算机。如果我们在一个局域网中，并且希望使我们的网站在除我们之外的计算机上可用，我们将输入我们的本地 IP 地址而不是`127.0.0.1`。值`127.0.0.1`是参数的默认值。

+   `8000`定义了服务器的监听端口。这个设置对于在一台计算机上运行多个 web 服务器非常有用。

如果命令执行正确，窗口应该显示`0 errors found`的消息，如下面的截图所示：

![创建我们的第一个 URL](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/gtst-dj/img/00015.jpeg)

要查看结果，我们必须打开浏览器并输入以下 URL：`http://localhost:8000`。

Django 通过显示以下消息确认我们的开发环境是正常的：

![创建我们的第一个 URL](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/gtst-dj/img/00016.jpeg)

这个消息也意味着我们没有指定的 URL。我们将向我们的文件添加两个 URL：

```py
url (r'^$', 'TasksManager.views.index.page), 
url (r'^index$', 'TasksManager.views.index.page') 

```

### 提示

你应该始终了解 Django 中的错误，特别是在 Django 的 GitHub 页面上：[`github.com/django`](https://github.com/django)。

在我们输入的 URL 中，我们定义了第一个参数（正则表达式），它将验证 URL。我们将在下一章讨论第二个参数。

让我们回到浏览器，用*F5*键刷新页面。Django 将显示一个`ViewDoesNotExist at /`的错误。

这意味着我们的模块不存在。你必须研究你的错误；在这个例子中，我们有一个错误。有了这个错误，我们将直接修复不起作用的部分。

我们经常遇到的另一个问题是`404 页面未找到`错误。我们可以通过在浏览器中输入`http://localhost:8000/test404`来生成它。这个错误意味着没有 URL 验证`test404`字符串。

我们必须注意错误，因为看到并解决它们可以节省我们很多时间。

# 创建我们的第一个视图

现在我们已经创建了我们的 URL 并由路由系统解释，我们必须确保一个视图（在 MVC 模式中是一个控制器）满足客户的需求。

这是`urls.py`中存在的第二个参数的功能。这个参数将定义扮演视图角色的方法。例如，我们的第一个 URL：

```py
url (r'^$', 'TasksManager.views.index.page'), 
```

首先，正如我们在学习正则表达式时所看到的，这个 URL 只有在浏览`http://localhost:8000` URL 时才有效。URL 中的第二个参数意味着在`index.py`文件中有一个名为`page`的方法将处理请求。`index.py`文件位于`TasksManager`应用程序根目录下的`views`包中。

当我们希望 Python 识别一个文件夹为包时，我们需要创建一个包含`__init__.py`文件的文件夹，我们可以将其留空。

你可以选择另一种结构来存储你的视图。你必须选择最适合你的项目的结构。从第一行代码开始，对你的项目有一个长期的愿景，以定义高质量的架构。

在我们的`index.py`文件中，我们将创建一个名为`page()`的方法。这个方法将向客户端返回一个 HTML 页面。页面是通过 HTTP 协议返回的，所以我们将使用`HttpResponse()`函数及其导入。这个`HttpResponse()`函数的参数返回我们将返回给浏览器的 HTML 内容。为了简化阅读这个例子，我们没有使用正确的 HTML 结构，因为我们只是向客户端返回`Hello world!`，如下面的代码所示：

```py
# - * - Coding: utf -8 - * -
from django.http import HttpResponse
# View for index page.
def page (request) :
 return HttpResponse ("Hello world!" )
```

在前面的例子中，我们在`page()`方法之前添加了一个注释。注释非常重要。它们帮助你快速理解你的代码。

我们还设置了 UTF-8 字符的编码。这将提高我们的应用与其他语言的兼容性。我们不一定在书中后面指出它，但建议使用它。

# 测试我们的应用程序

要测试我们的第一个页面，我们将不得不使用`runserver`命令，这是我们在本章中早些时候看到的。为了做到这一点，您必须运行命令并在浏览器中刷新您的页面，`http://localhost:8000`。

如果您在浏览器中看到`Hello World!`而没有错误出现，这意味着您已经按照之前的步骤进行了操作。如果您忘记了某些东西，请不要犹豫在互联网上找到您的错误；其他人可能也经历过同样的情况。

然而，我们必须改善我们的观点，因为目前我们并不尊重 MVC 模型。我们将创建一个模板来分离 Python 代码的 HTML，并且具有更多的灵活性。

# 总结

在本章中，我们学习了正则表达式的基础知识。这是一个强大的工具，用于操作字符串。我们学会了如何操作系统路由 URL。我们还创建了我们的第一个视图，将一个字符串返回给客户端。在下一章中，我们将学习如何使用 Django 创建可维护的模板。


# 第四章：使用模板

正如我们在第一章中所看到的，我们解释了 MVC 和 MVT 模型，模板是允许我们生成返回给客户端的 HTML 代码的文件。在我们的视图中，HTML 代码不与 Python 代码混合。

Django 自带其自己的模板系统。然而，由于 Django 是模块化的，可以使用不同的模板系统。这个系统由一个语言组成，将用于制作我们的动态模板。

在本章中，我们将学习如何做以下事情：

+   将数据发送到模板

+   在模板中显示数据

+   在模板中显示对象列表

+   在 Django 中使用过滤器处理链

+   有效使用 URL

+   创建基础模板以扩展其他模板

+   在我们的模板中插入静态文件

# 在模板中显示 Hello world！

我们将创建我们应用程序的第一个模板。为此，我们必须首先编辑`settings.py`文件，以定义将包含我们模板的文件夹。我们将首先将项目文件夹定义为`PROJECT_ROOT`，以简化迁移到另一个系统：

```py
PROJECT_ROOT = os.path.abspath(os.path.dirname(__file__))
TEMPLATE_DIRS = (os.path.join(PROJECT_ROOT, '../TasksManager/templates')
  # Put strings here, like "/home/html/django_templates" or "C:/www/django/templates".
  # Always use forward slashes, even on Windows.
  # Don't forget to use absolute paths, not relative paths.
)
```

现在 Django 知道在哪里查找模板，我们将创建应用程序的第一个模板。为此，请使用文件浏览器，并在`TasksManager/templates/en/public/`文件夹中添加`index.html`文件。我们不需要创建`__init__.py`文件，因为这些文件不包含任何 Python 文件。

以下是`index.html`文件的内容：

```py
<html>
  <head>
    <title>
      Hello World Title
    </title>
  </head>
  <body>
    <h1>
      Hello World Django
    </h1>
    <article>
      Hello world !
    </article>
  </body>
</html>
```

尽管模板是正确的，但我们需要更改视图以指示其使用。我们将使用以下内容修改`index.py`文件：

```py
from django.shortcuts import render
# View for index page. 
def page(request):
  return render(request, 'en/public/index.html')
```

如果我们测试这个页面，我们会注意到模板已经被视图考虑进去了。

# 从视图向模板注入数据

在改进我们的模板之前，我们必须将变量发送到模板。数据的注入是基于这些变量，因为模板将执行某些操作。事实上，正如我们在 MVC 模式的解释中所看到的，控制器必须将变量发送到模板以便显示它们。

有几个函数可以将变量发送到模板。两个主要函数是`render()`和`render_to_response()`。`render()`函数与`render_to_response()`非常相似。主要区别在于，如果我们使用`render`，我们不需要指定`context_instance = RequestContext(request)`以发送当前上下文。这是稍后在本书中使用 CSRF 中间件的上下文。

我们将改变我们的视图，以在我们的模板中注入变量。这些变量将对使用模板语言非常有用。以下是我们修改后的视图：

```py
from django.shortcuts import render
"""
View for index page. 
"""

def page(request):
  my_variable = "Hello World !"
  years_old = 15
  array_city_capitale = [ "Paris", "London", "Washington" ]
  return render(request, 'en/public/index.html', { "my_var":my_variable, "years":years_old, "array_city":array_city_capitale })
```

# 创建动态模板

Django 自带完整的模板语言。这意味着我们将使用模板标签，这将允许我们在模板中具有更多的灵活性，并显示变量，执行循环，并设置过滤器。

HTML 和模板语言在模板中混合在一起；然而，模板语言非常简单，与 HTML 代码相比只是少数。网页设计师可以轻松修改模板文件。

# 在模板中集成变量

在我们的控制器中，我们发送了一个名为`my_var`的变量。我们可以以以下方式在`<span>`标签中显示它。在我们的模板标签的`<article>`标签中添加以下行：

```py
<span> {{my_var}} </ span> 
```

因此，因为我们的变量包含`string = "Hello World!"`，将生成以下 HTML 代码：

```py
<span> Hello World! </span>
```

我们将学习如何为变量或函数创建条件，以便在以下示例中过滤变量中的数据。

## 条件语句

语言模板还允许条件结构。请注意，对于显示变量，使用双大括号`{{}}`，但一旦我们有一个作为条件或循环的操作，我们将使用`{%%}`。

我们的控制器发送一个可以定义年龄的`years`变量。条件结构的一个示例是，当您可以更改控制器中变量的值以观察更改时。在我们的`<article>`标签中添加以下代码：

```py
<span>
  {% if years <10 %}
    You are a children
  {% elif years < 18 %}
    You are a teenager
  {% else %}
    You are an adult!
  {% endif %}
</span>
```

在我们的情况下，当我们将值`15`发送到生成的模板时，使用的代码如下：

```py
<span> You are a teenager </span>
```

## 在模板中循环

循环允许您阅读表或数据字典的元素。在我们的控制器中，我们发送了一个名为`array_city`的数据表，其中包含城市的名称。要以列表形式查看所有这些城市的名称，我们可以在模板中编写以下内容：

```py
<ul>
  {% for city in array_city %}
    <li>
      {{ city }}
    </li>
  {% endfor %}
</ul>
```

此循环将遍历`array_city`表，并将每个元素放入我们在`<li>`标签中显示的`city`变量中。使用我们的示例数据，此代码将生成以下 HTML 代码：

```py
<ul>
  <li>Paris</li>
  <li>London</li>
  <li>Washington</li>
</ul>
```

# 使用过滤器

过滤器是在将数据发送到模板之前修改数据的有效方法。我们将在以下部分中查看一些过滤器的示例，以更好地理解它们。

## 大写和小写过滤器

小写过滤器将转换为小写字母，而大写过滤器将转换为大写字母。在接下来的部分中给出的示例中包含`my_hello`变量，其值为`Hello World!`

### 小写过滤器

小写过滤器的代码如下：

```py
<span> {{ my_hello | lower }} </span>
```

此代码生成以下 HTML 代码：

```py
<span> hello </span>
```

### 大写过滤器

大写过滤器的代码如下：

```py
<span> {{ my_hello | upper }} </span>
```

此代码生成以下 HTML 代码：

```py
<span> HELLO </span>
```

## capfirst 过滤器

capfirst 过滤器将第一个字母转换为大写。具有`myvar = "hello"`变量的示例如下：

```py
<span>{{ my_hello | capfirst }}</span>
```

此代码生成以下 HTML 代码：

```py
<span> Hello </span>
```

## 复数过滤器

复数过滤器可以轻松处理复数形式。通常，开发人员由于时间不足而选择简单的解决方案。解决方案是显示频道：*您的购物车中有 2 个产品*。

Django 简化了这种类型的字符串。如果变量表示复数值，复数过滤器将在单词末尾添加后缀，如下所示：

```py
You have {{ product }} nb_products {{ nb_products | pluralize }} in our cart.
```

如果`nb_products`为`1`和`2`，则此频道将显示以下三个频道：

```py
You have 1 product in our cart.
You have 2 products in our cart.
I received {{ nb_diaries }} {{ nb_diaries|pluralize : "y , ies "}}.
```

如果`nb_diaries`为`1`和`2`，则上述代码将显示以下两个链：

```py
I received one diary.
I received two diaries.
```

在上一个示例中，我们首次使用了带参数的过滤器。要为过滤器设置参数，必须使用以下语法：

```py
{{ variable | filter:"parameters" }}
```

此过滤器有助于提高您网站的质量。当网站显示正确的句子时，它看起来更专业。

## 转义和安全以避免 XSS 过滤器

XSS 过滤器用于转义 HTML 字符。此过滤器有助于防止 XSS 攻击。这些攻击是基于黑客注入客户端脚本的。以下是 XSS 攻击的逐步描述：

+   攻击者找到一个表单，以便内容将显示在另一个页面上，例如商业网站的评论字段。

+   黑客编写 JavaScript 代码以使用此表单中的标记进行黑客攻击。提交表单后，JavaScript 代码将存储在数据库中。

+   受害者查看页面评论，JavaScript 运行。

风险比简单的`alert()`方法更重要，以显示消息。使用这种类型的漏洞，黑客可以窃取会话 ID，将用户重定向到伪造的网站，编辑页面等。

更具体地说，过滤器更改以下字符：

+   `<` 被转换为 `&lt;`

+   `>` 被转换为 `&gt;`

+   `'` 被转换为 `'`

+   `"` 被转换为 `&quot;`

+   `&` 被转换为 `&amp;`

我们可以使用`{% autoescape %} tag`自动转义块的内容，该标签带有 on 或 off 参数。默认情况下，autoescape 是启用的，但请注意，在较旧版本的 Django 中，autoescape 未启用。

当启用 autoescape 时，如果我们想将一个变量定义为可信任的变量，我们可以使用 safe 过滤器对其进行过滤。以下示例显示了不同的可能场景：

```py
<div>
  {% autoescape on %}
  <div>
    <p>{{ variable1 }}</p>
    <p>
      <span>
        {{ variable2|safe }}
      </span>
      {% endautoescape %}
      {% autoescape off %}
    </p>
  </div>
    <span>{{ variable3 }}</span>
    <span>{{ variable4|escape }}</span>
  {% endautoescape %}
  <span>{{ variable5 }}</span>
</div>
```

在这个例子中：

+   `variable1`被`autoescape`转义

+   `variable2`没有被转义，因为它被过滤为安全的

+   `variable3`没有被转义，因为`autoescape`被定义为关闭

+   `variable4`被转义，因为它已经使用转义过滤器进行了过滤

+   `variable5`被转义，因为`autoescape`是关闭的

## linebreaks 过滤器

linebreaks 过滤器允许您将换行符转换为 HTML 标记。一个单独的换行符被转换为`<br />`标记。一个换行符后跟一个空格将变成一个段落分隔，`</p>`：

```py
<span>{{ text|linebreaks }}</span>
```

## truncatechars 过滤器

truncatechars 过滤器允许您从一定长度截断字符串。如果超过这个数字，字符串将被截断，Django 会添加字符串“`...`”。

包含“欢迎来到 Django”的变量的示例如下：

```py
{{ text|truncatechars:14 }}
```

这段代码输出如下：

```py
"Welcome in ..."
```

# 创建 DRY URL

在学习什么是 DRY 链接之前，我们首先会提醒您 HTML 链接是什么。每天，当我们上网时，我们通过点击链接来改变页面或网站。这些链接被重定向到 URL。以下是一个指向[google.com](http://google.com)的示例链接：

```py
<a href="http://www.google.com">Google link !</a>
```

我们将在我们的应用程序中创建第二个页面，以创建第一个有效的链接。在`urls.py`文件中添加以下行：

```py
url(r'^connection$', 'TasksManager.views.connection.page'),
```

然后，创建一个对应于前面 URL 的视图：

```py
from django.shortcuts import render
# View for connection page. 
def page(request):
  return render(request, 'en/public/connection.html')
```

我们将为新视图创建第二个模板。让我们复制第一个模板，并将副本命名为`connection.html`，并修改`Connection`中的`Hello world`。我们可以注意到这个模板不符合 DRY 哲学。这是正常的；我们将在下一节学习如何在不同模板之间共享代码。

我们将在我们的第一个`index.html`模板中创建一个 HTML 链接。这个链接将引导用户到我们的第二个视图。我们的`<article>`标签变成了：

```py
<article>
  Hello world !
  <br />
  <a href="connection">Connection</a>
</article>
```

现在，让我们用开发服务器测试我们的网站，并打开浏览器到我们网站的 URL。通过测试网站，我们可以检查链接是否正常工作。这是一个好事，因为现在你能够用 Django 制作一个静态网站，而且这个框架包含一个方便的工具来管理 URL。

Django 永远不会在`href`属性中写入链接。事实上，通过正确地填写我们的`urls.py`文件，我们可以引用 URL 的名称和地址。

为了做到这一点，我们需要改变包含以下 URL 的`urls.py`文件：

```py
url(r'^$', 'TasksManager.views.index.page', name="public_index"),
url(r'^connection/$', 'TasksManager.views.connection.page', name="public_connection"),
```

给我们的每个 URL 添加 name 属性可以让我们使用 URL 的名称来创建链接。修改您的`index.html`模板以创建 DRY 链接：

```py
<a href="{% url 'public_connection' %}">Connection</a>
```

再次测试新网站；请注意，链接仍然有效。但是目前，这个功能对我们来说是没有用的。如果 Google 决定改进以网站名称结尾的 URL 的索引，您将不得不更改所有的 URL。要在 Django 中做到这一点，您只需要更改第二个 URL 如下：

```py
url(r'^connection-TasksManager$', 'TasksManager.views.connection.page', name="public_connection"),
```

如果我们再次测试我们的网站，我们可以看到更改已经正确完成，并且`urls.py`文件中的更改对网站的所有页面都有效。当您需要使用参数化 URL 时，您必须使用以下语法将参数集成到 URL 中：

```py
{% url "url_name" param %}
{% url "url_name" param1, param2 %}
```

# 扩展模板

模板的传承允许您定义一个超级模板和一个从超级模板继承的子模板。在超级模板中，可以定义子模板可以填充的块。这种方法允许我们通过在超级模板中应用通用代码到多个模板来遵循 DRY 哲学。我们将使用一个例子，`index.html`模板将扩展`base.html`模板。

以下是我们必须在`template`文件夹中创建的`base.html`模板代码：

```py
<html>
  <head>
    <title>
      % block title_html %}{% endblock %}
    </title>
  </head>
  <body>
    <h1>
      Tasks Manager - {% block h1 %}{% endblock %}
    </h1>
    <article>
      {% block article_content %}{% endblock %}
    </article>
  </body>
</html>
```

在前面的代码中，我们定义了子模板可以覆盖的三个区域：`title_html`、`h1`和`article_content`。以下是`index.html`模板代码：

```py
{% extends "base.html" %}
{% block title_html %}
  Hello World Title
{% endblock %}
{% block h1 %}
  {{ bloc.super }}Hello World Django
{% endblock %}
{% block article_content %}
  Hello world !
{% endblock %}
```

在这个模板中，我们首先使用了 extends 标签，它扩展了`base.html`模板。然后，block 和 endblock 标签允许我们重新定义`base.html`模板中的内容。我们可以以相同的方式更改我们的`connection.html`模板，这样`base.html`的更改就可以在两个模板上进行。

可以定义尽可能多的块。我们还可以创建超级模板，以创建更复杂的架构。

# 在模板中使用静态文件

诸如 JavaScript 文件、CSS 或图像之类的静态文件对于获得人体工程学网站至关重要。这些文件通常存储在一个文件夹中，但在开发或生产中修改此文件夹可能会很有用。

根据 URL，Django 允许我们定义一个包含静态文件的文件夹，并在需要时轻松修改其位置。

要设置 Django 查找静态文件的路径，我们必须通过添加或更改以下行来更改我们的`settings.py`文件：

```py
STATIC_URL = '/static/'
STATICFILES_DIRS = (
    os.path.join(PROJECT_ROOT, '../TasksManager/static/'),
)
```

我们将为我们未来的静态文件定义一个合适的架构。选择早期一致的架构非常重要，因为它使应用程序支持以及包括其他开发人员变得更容易。我们的静态文件架构如下：

```py
static/
  images/
  javascript/
    lib/
  css/
  pdf/
```

我们为每种静态文件创建一个文件夹，并为 JavaScript 库定义一个`lib`文件夹，如 jQuery，我们将在本书中使用。例如，我们更改了我们的`base.html`文件。我们将添加一个 CSS 文件来管理我们页面的样式。为了做到这一点，我们必须在`</title>`和`</head>`之间添加以下行：

```py
<link href="{% static "css/style.css" %}" rel="stylesheet" type="text/css" />
```

在我们的静态模板中使用标签，我们还必须通过在使用静态标签之前放置以下行来加载系统：

```py
{% load staticfiles %}
```

我们将在`/static/css`文件夹中创建`style.css`文件。这样，浏览器在开发过程中不会生成错误。

# 摘要

在本章中，我们学习了如何创建模板并将数据发送到模板，以及如何在模板中使用条件、循环和过滤器。我们还讨论了如何为灵活的 URL 结构创建 DRY URLs，扩展模板以满足 DRY 哲学，以及如何使用静态文件。

在下一章中，我们将学习如何结构化我们的数据以保存在数据库中。


# 第五章：使用模型

我们刚刚创建的网站只包含静态数据；但是，我们想要存储数据以自动化所有任务。这就是为什么有模型；它们将在我们的视图和数据库之间建立联系。

像许多框架一样，Django 提出了使用抽象层进行数据库访问。这个抽象层称为**对象关系映射**（**ORM**）。这允许您使用 Python 实现对象来访问数据，而不必担心使用数据库。使用这个 ORM，我们不需要为简单和稍微复杂的操作使用 SQL 查询。这个 ORM 属于 Django，但还有其他的，比如**SQLAlchemy**，它是一个质量很高的 ORM，特别是在 Python TurboGears 框架中使用。

模型是从`Model`类继承的对象。`Model`类是一个专门设计用于数据持久性的 Django 类。

我们在模型中定义字段。这些属性允许我们在模型内组织数据。要在数据库和 SQL 之间建立连接，我们可以说一个模型在数据库中由一个表表示，而模型属性在表中由一个字段表示。

在本章中，我们将解释：

+   如何设置对数据库的访问

+   如何安装 South 进行数据库迁移

+   如何创建简单的模型

+   如何在模型之间创建关系

+   如何扩展我们的模型

+   如何使用管理模块

# 数据库和 Django

Django 可以与许多数据库进行接口。但是，在我们的应用程序开发过程中，我们使用了 Django 中包含的 SQLite 库。

我们将修改`settings.py`以设置与数据库的连接：

```py
DATABASES = {
  'default': {
    'ENGINE': 'django.db.backends.sqlite3', 
    'NAME': os.path.join(PROJECT_ROOT, 'database.db'), 
    'USER': '',                     
    'PASSWORD': '',                 
    'HOST': '',                     
    'PORT': '',                     
  }
}
```

以下是前面代码中提到的属性的描述：

+   `ENGINE`属性指定要使用的数据库类型。

+   `NAME`属性定义了 SQLite 数据库的路径和最终名称。我们在我们的代码中使用`os.path.join`的语法，并且它与所有操作系统兼容。数据库文件将包含在项目目录中。

+   其他属性在使用数据库服务器时很有用，但由于我们将使用 SQLite，因此不需要定义它们。

# 使用 South 进行迁移

**South**是 Django 的一个非常有用的扩展。它在更改字段时简化了数据库的迁移。它还保留了数据库结构更改的历史记录。

我们现在谈论它是因为必须在创建数据库之前安装它才能正常工作。

Django 1.7 集成了迁移系统。您将不再需要使用 South 来进行 Django 应用的迁移。您可以在[`docs.djangoproject.com/en/dev/topics/migrations/`](https://docs.djangoproject.com/en/dev/topics/migrations/)找到有关集成到 Django 1.7 中的迁移系统的更多信息。

## 安装 South

要安装 South，我们使用`pip`命令。我们已经用它来安装 Django。要做到这一点，请运行以下命令：

```py
pip install South

```

在实际使用 South 之前，我们必须更改`settings.py`文件，以便 South 能够在 Django 中良好集成。为此，您必须转到`INSTALLED_APPS`并添加以下行（根据版本的不同，安装 South 可能已经添加了这行）：

```py
'south',
'TasksManager',
```

## 使用 South 扩展

在我们进行第一次迁移和生成数据库之前，我们还必须创建模式迁移。为此，我们必须运行以下命令：

```py
manage.py schemamigration TasksManager --initial 

```

然后，我们必须执行初始迁移：

```py
manage.py syncdb --migrate 

```

Django 要求我们首先创建一个帐户。这个帐户将是超级用户。记住您输入的登录名和密码；您以后会需要这些信息。

South 现在已经完全可用。每次我们需要修改模型时，我们都会进行迁移。但是，为了正确进行迁移，您必须牢记以下事项：

+   永远不要执行 Django 的`syncdb`命令。第一次运行`syncdb --migrate`后，永远不要再次运行它。之后使用`migrate`。

+   始终在新字段中放置默认值；否则，我们将被要求分配一个值。

+   每次我们完成编辑我们的模型时，我们必须按正确的顺序执行以下两个命令：

```py
manage.py schemamigration TasksManager –auto
manage.py migrate TasksManager

```

# 创建简单模型

要创建模型，我们必须已经深入研究了应用程序。模型是任何应用程序的基础，因为它们将存储所有数据。因此，我们必须仔细准备它们。

关于我们的`Tasksmanager`应用程序，我们需要一个用户来保存在项目上执行的任务。我们将创建两个模型：`User`_`django`和`Project`。

我们需要将我们的模型存储在`models.py`文件中。我们将编辑`TasksManager`文件夹中的`models.py`文件。我们不需要修改配置文件，因为当您需要模型时，我们将不得不导入它。

文件已经存在并且有一行。以下一行允许您导入 Django 的基本模型：

```py
from django.db import models
```

## 用户资料模型

要创建`UserProfile`模型，我们要问自己一个问题，即“*我们需要保存关于用户的哪些数据？*”。我们需要以下数据：

+   用户的真实姓名

+   一个将标识每个用户的昵称

+   一个对用户身份验证有用的密码

+   电话号码

+   出生日期（这不是必要的，但我们必须研究日期！）

+   用户上次连接的日期和时间

+   电子邮件地址

+   年龄（以年为单位）

+   用户帐户的创建日期

+   专业化，如果是主管

+   用户类型

+   如果您是开发人员，那么您就是主管

所需的模型如下：

```py
class UserProfile(models.Model):
  name = models.CharField(max_length=50, verbose_name="Name")
  login = models.CharField(max_length=25, verbose_name="Login")
  password = models.CharField(max_length=100, verbose_name="Password")
  phone = models.CharField(max_length=20, verbose_name="Phone number" , null=True, default=None, blank=True)
  born_date = models.DateField(verbose_name="Born date" , null=True, default=None, blank=True)
  last_connection = models.DateTimeField(verbose_name="Date of last connection" , null=True, default=None, blank=True)
  email = models.EmailField(verbose_name="Email")
  years_seniority = models.IntegerField(verbose_name="Seniority", default=0)
  date_created = models.DateField(verbose_name="Date of Birthday", auto_now_add=True)
```

我们还没有定义专业化、用户类型和主管，因为这些点将在下一部分中看到。

在前面的代码中，我们可以看到`Django_user`继承自`Model`类。这个`Model`类有我们需要操作模型的所有方法。我们也可以重写这些方法来定制模型的使用。

在这个类中，我们通过添加一个属性来添加我们的字段，并指定值。例如，名字字段是一个字符字符串类型，最大长度为 50 个字符。`verbose_name`属性将是我们在表单中定义字段的标签。以下是常用的字段类型列表：

+   `CharField`：这是一个具有有限字符数的字符字符串

+   `TextField`：这是一个具有无限字符的字符字符串

+   `IntegerField`：这是一个整数字段

+   `DateField`：这是一个日期字段

+   `DateTimeField`：这个字段包括日期以及小时、分钟和秒的时间

+   `DecimalField`：这是一个可以精确定义的小数

### 提示

Django 自动保存一个自动递增的`id`字段。因此，我们不需要定义主键。

## 项目模型

为了保存我们的项目，我们需要以下数据：

+   标题

+   描述

+   客户名称

这些因素使我们能够定义以下模型：

```py
class Project(models.Model):
  title = models.CharField(max_length=50, verbose_name="Title")
  description = models.CharField(max_length=1000, verbose_name="Description")
  client_name = models.CharField(max_length=1000, verbose_name="Client name")
```

为了遵守良好的实践，我们本来不需要为客户定义一个文本字段，而是定义一个与客户表的关系。为了简化我们的第一个模型，我们为客户名称定义一个文本字段。

# 模型之间的关系

关系是连接我们的模型的元素。例如，在这个应用程序的情况下，一个任务与一个项目相关联。实际上，开发人员为特定项目执行任务，除非它是一个更一般的任务，但这超出了我们项目的范围。我们定义一对多类型的关系，以表示一个任务总是涉及一个单一项目，但一个项目可以与许多任务相关联。

还有两种其他类型的关系：

+   一对一关系将模型分为两部分。生成的数据库将创建两个通过关系链接的表。我们将在身份验证模块的章节中看到一个例子。

+   多对多关系定义与同一类型的任何模型连接的关系。例如，一个作者可以出版多本书，一本书可能有几个作者。

## 创建具有关系的任务模型

对于任务模型，我们需要以下元素：

+   用几个词定义任务的一种方式

+   有关任务的更多详细描述

+   过去的生活

+   它的重要性

+   它所附属的项目

+   创建它的开发人员

这使我们能够编写以下模型：

```py
class Task(models.Model):
  title = models.CharField(max_length=50, verbose_name="Title")
  description = models.CharField(max_length=1000, verbose_name="Description")
  time_elapsed = models.IntegerField(verbose_name="Elapsed time" , null=True, default=None, blank=True)
  importance = models.IntegerField(verbose_name="Importance")
  project = models.ForeignKey(Project, verbose_name="Project" , null=True, default=None, blank=True)
  app_user = models.ForeignKey(UserProfile, verbose_name="User")
```

在这个模型中，我们定义了两种外键字段类型：`project`和`app_user`。在数据库中，这些字段包含它们所附属的记录的登录详细信息在另一个表中。

定义与`Project`模型的关系的`project`字段有两个额外的属性：

+   `Null`：这决定了元素是否可以定义为空。`project`字段中存在此属性的事实意味着任务不一定与项目相关联。

+   `Default`：这设置字段将具有的默认值。也就是说，如果我们在保存模型之前没有指定项目的值，任务将不会与域相关联。

# 扩展模型

继承模型允许为两个不同的模型使用共同的字段。例如，在我们的`App_user`模型中，我们无法确定随机记录是开发人员还是监督员。

一个解决方案是创建两个不同的模型，但我们将不得不复制所有共同的字段，如名称、用户名和密码，如下所示：

```py
class Supervisor(models.Model):
  # Duplicated common fields
  specialisation = models.CharField(max_length=50, verbose_name="Specialisation")

class Developer(models.Model):
  # Duplicated common fields
  supervisor = models.ForeignKey(Supervisor, verbose_name="Supervisor")
```

复制代码是一件遗憾的事，但这是 Django 和 DRY 必须遵循的原则。这就是为什么有一个继承模型的原因。

实际上，遗留模型用于定义一个主模型（或超级模型），其中包含多个模型的共同字段。子模型会自动继承超级模型的字段。

没有比一个例子更明确的了；我们将修改我们的`Developer`和`Supervisor`类，使它们继承`App_user`：

```py
class Supervisor(UserProfile):
  specialisation = models.CharField(max_length=50, verbose_name="Specialisation")

class Developer(UserProfile):
  supervisor = models.ForeignKey(Supervisor, verbose_name="Supervisor")
```

遗留数据库的结果允许我们创建三个表：

+   `App_user`模型的表，包含模型属性的字段

+   `Supervisor`模型的表，包含一个专业的文本字段和一个与`App_user`表有外键关系的字段

+   一个`Developer`表，有两个字段：一个与`Supervisor`表关联的字段，一个与`App_user`表关联的字段

现在我们已经分开了两种类型的用户，我们将修改与`App_user`的关系，因为只有开发人员会记录他们的任务。在`Tasks`模型中，我们有以下行：

```py
app_user = models.ForeignKey(App_user, verbose_name="User")
```

这段代码转换如下：

```py
developer = models.ForeignKey(Developer, verbose_name="User")
```

为了使数据库命令生成工作，我们必须按正确的顺序放置模型。实际上，如果我们定义与尚未定义的模型的关系，Python 将引发异常。目前，模型需要按照描述的顺序定义。稍后，我们将看到如何解决这个限制。

在下一章中，我们将对模型执行查询。这需要数据库与模型同步。在开始下一章之前，我们必须先迁移 South。

要执行迁移，我们必须使用本章开头看到的命令。为了简化迁移，我们还可以在 Python 文件夹中创建一个批处理文件，其中我们将放入以下行：

```py
manage.py schemamigration TasksManager --auto
manage.py migrate
pause

```

以下是一个 bash 脚本，您可以在`Work_manager`文件夹中创建，可以在 Debian Linux 上执行相同的操作：

```py
#!/bin/bash
manage.py runserver 127.0.0.1:8000

```

这样，当您迁移 South 时，它将执行此文件。`pause`命令允许您在不关闭窗口的情况下查看结果或显示的错误。

# 管理员模块

管理模块非常方便，并且在 Django 中默认包含。这是一个可以轻松维护数据库内容的模块。这不是一个数据库管理器，因为它无法维护数据库的结构。

您可能会问的一个问题是，“*除了管理工具数据库之外还有什么？*”答案是管理模块完全集成了 Django 并使用这些模型。

以下是它的优点：

+   它管理模型之间的关系。这意味着如果我们想保存一个新的开发人员，该模块将提出所有主管的列表。这样，它就不会创建一个不存在的关系。

+   它管理 Django 权限。您可以根据模型和 CRUD 操作为用户设置权限。

+   它很快就建立起来了。

基于 Django 模型而不是数据库，这个模块允许用户编辑记录的数据。

## 安装模块

要实现管理模块，请编辑`settings.py`文件。在`INSTALLED_APPS`设置中，您需要添加或取消注释以下行：

```py
'django.contrib.admin'
```

您还必须通过添加或取消注释以下行来编辑`urls.py`文件：

```py
from django.contrib import admin
admin.autodiscover()
url (r'^admin', include(admin.site.urls)),
```

导入管理模块的行必须在文件的开头与其他导入一起。运行`autodiscover()`方法的行必须在导入之后并在`urlpatterns`定义之前找到。最后，最后一行是一个应该在`urlpatterns`中的 URL。

我们还必须在`TasksManager`文件夹中创建一个`admin.py`文件，在其中我们将定义要集成到管理模块中的样式：

```py
from django.contrib import admin
from TasksManager.models import UserProfile, Project, Task , Supervisor , Developer
admin.site.register(UserProfile)
admin.site.register(Project)
admin.site.register(Task)
admin.site.register(Supervisor)
admin.site.register(Developer)
```

现在我们已经配置了管理模块，我们可以轻松地管理我们的数据。

## 使用模块

要使用管理模块，我们必须连接到刚刚定义的 URL：`http://localhost:8000/admin/`。

我们必须在创建数据库时连接定义的登录：

1.  一旦我们连接，模型列表就会出现。

1.  如果我们点击**Supervisor**模型链接，我们会到达一个页面，我们可以通过窗口右上角的按钮添加一个主管：![使用模块](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/gtst-dj/img/00017.jpeg)

1.  通过点击这个按钮，我们加载一个由表单组成的页面。这个表单自动提供了管理日期和时间的实用工具：![使用模块](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/gtst-dj/img/00018.jpeg)

让我们添加一个新的主管，然后添加一个开发人员。当您想选择主管时，您可以在下拉框中看到我们刚刚创建的主管。右侧的绿色十字架允许您快速创建一个主管。

在接下来的章节中，我们将为我们的模型定义`str`方法。这将改进管理模块中对象的显示列表。

# 模型的高级用法

我们学习了允许我们创建简单应用程序的模型的基础知识。有时，需要定义更复杂的结构。

## 为同一模型使用两个关系

有时，将两个（或更多）外键存储在单个模型中是有用的。例如，如果我们希望两个开发人员并行工作在同一任务上，我们必须在我们的模型中使用`related_name`属性。例如，我们的`Task`模型包含以下行的两个关系：

```py
developer1 = models.ForeignKey (Developer , verbose_name = "User" , related_name = "dev1" )
developer2 = models.ForeignKey (Developer , verbose_name = "User" , related_name = "dev2" )
```

在本书的后续部分，我们将不使用这两个关系。为了有效地遵循本书，我们必须返回到我们之前定义的`Task`模型。

### 注意

在这里，我们定义了同一任务上的两个开发人员。最佳实践建议我们在`Task`模型中创建一个多对多的关系。详细参数允许您指定一个中间表来存储附加数据。这是一个可选步骤。这种关系的示例如下：

```py
#Relationship to add to the Task model
developers = models.ManyToManyField(Developer , through="DeveloperWorkTask")
class DeveloperWorkTask(models.Model):
  developer = models.ForeignKey(Developer)
  task = models.ForeignKey(Task)
  time_elapsed_dev = models.IntegerField(verbose_name="Time elapsed", null=True, default=None, blank=True)
```

## 定义 str 方法

如在管理模块使用部分中已经提到的，`__str__()`方法将允许更好地查看我们的模型。这个方法将设置用于显示我们的模型实例的字符串。当 Django 与 Python 3 不兼容时，这个方法被`__unicode__()`方法替换。

例如，当我们添加了一个开发者时，定义主管的下拉列表显示了“主管对象”行。显示主管的姓名会更有帮助。为了做到这一点，改变我们的`App_user`类并添加`str()`方法：

```py
class UserProfile ( models.Model ) :
# Fields...
def __str__ (self):
  return self.name
```

这个方法将返回主管的姓名以便显示，并允许您轻松管理管理：

![定义 str 方法](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/gtst-dj/img/00019.jpeg)

# 总结

在本章中，我们学习了使用 South 进行迁移。我们还学习了如何创建简单的模型和模型之间的关系。此外，我们还学习了如何安装和使用管理模块。在下一章中，我们将学习如何操作我们的数据。我们将学习如何对数据进行四种主要操作：添加、读取（和研究）、修改和删除。


# 第六章：使用 Querysets 获取模型的数据

**Querysets** 用于数据检索，而不是直接构建 SQL 查询。它们是 Django 使用的 ORM 的一部分。ORM 用于通过抽象层将视图和控制器连接起来。开发人员可以使用对象模型类型，而无需编写 SQL 查询。我们将使用 querysets 来检索我们通过模型存储在数据库中的数据。这四个操作通常被 **CRUD** (**创建**，**读取**，**更新** 和 **删除**) 所总结。

本章中讨论的示例旨在向您展示查询集的工作原理。下一章将向您展示如何使用表单，以及如何将来自客户端的数据保存在模型中。

在本章结束时，我们将知道如何：

+   在数据库中保存数据

+   从数据库中检索数据

+   更新数据库中的数据

# 在数据库上持久化模型的数据

使用 Django 进行数据存储很简单。我们只需要在模型中填充数据，并使用方法将它们存储在数据库中。Django 处理所有的 SQL 查询；开发人员不需要编写任何查询。

## 填充模型并将其保存在数据库中

在将模型实例的数据保存到数据库之前，我们需要定义模型所需字段的所有值。我们可以在我们的视图索引中显示示例。

以下示例显示了如何保存模型：

```py
from TasksManager.models import Project # line 1
from django.shortcuts import render
def page(request):
  new_project = Project(title="Tasks Manager with Django", description="Django project to getting start with Django easily.", client_name="Me") # line 2
  new_project.save() # line 3
  return render(request, 'en/public/index.html', {'action':'Save datas of model'})
```

我们将解释我们视图的新行：

+   我们导入我们的 `models.py` 文件；这是我们将在视图中使用的模型

+   然后，我们创建我们的 `Project` 模型的一个实例，并用数据填充它

+   最后，我们执行 `save()` 方法，将当前数据保存在实例中

我们将通过启动开发服务器（或 runserver）来测试此代码，然后转到我们的 URL。在 `render()` 方法中，我们定义的 `action` 变量的值将被显示。要检查查询是否执行，我们可以使用管理模块。还有用于管理数据库的软件。

我们需要通过更改 `line 2` 中的值来添加更多记录。要了解如何做到这一点，我们需要阅读本章。

# 从数据库中获取数据

在使用 Django 从数据库中检索数据之前，我们使用 SQL 查询来检索包含结果的对象。使用 Django，根据我们是要获取一个记录还是多个记录，有两种检索记录的方式。

## 获取多条记录

要从模型中检索记录，我们必须首先将模型导入视图，就像我们之前保存数据到模型中一样。

我们可以按以下方式检索和显示 `Project` 模型中的所有记录：

```py
from TasksManager.models import Project
from django.shortcuts import render
def page(request):
  all_projects = Project.objects.all()
  return render(request, 'en/public/index.html', {'action': "Display all project", 'all_projects': all_projects})
```

显示项目的代码模板如下：

```py
{% extends "base.html" %}
{% block title_html %}
  Projects list
{% endblock %}
{% block h1 %}
  Projects list
{% endblock %}
{% block article_content %}
  <h3>{{ action }}</h3>
  {% if all_projects|length > 0 %}
  <table>
    <thead>
      <tr>
        <td>ID</td>
        <td>Title</td>
      </tr>
    </thead>
    <tbody>
    {% for project in all_projects %}
      <tr>
        <td>{{ project.id }}</td>
        <td>{{ project.title }}</td>
      </tr>
    {% endfor %}
    </tbody>
  </table>
  {% else %}
  <span>No project.</span>
  {% endif %}
{% endblock %}
```

`all()` 方法可以链接到 SQL `SELECT * FROM` 查询。现在，我们将使用 `filter()` 方法来过滤我们的结果，并进行等效于 `SELECT * FROM Project WHERE field = value` 查询。

以下是筛选模型记录的代码：

```py
from TasksManager.models import Project
from django.shortcuts import render
def page(request):
  action='Display project with client name = "Me"'
  projects_to_me = Project.objects.filter(client_name="Me")
  return render(request, 'en/public/index.html', locals())
```

我们使用了一种新的语法将变量发送到模板。`locals()` 函数将所有本地变量发送到模板，这简化了渲染行。

### 提示

最佳实践建议您逐个传递变量，并且只发送必要的变量。

`filter()` 方法中的每个参数都定义了查询的过滤器。实际上，如果我们想要进行两个过滤，我们将编写以下代码行：

```py
projects_to_me = Project.objects.filter(client_name="Me", title="Project test")
```

这行代码等同于以下内容：

```py
projects_to_me = Project.objects.filter(client_name="Me")
projects_to_me = projects_to_me.filter(title="Project test") 
```

第一行可以分成两行，因为 querysets 是可链接的。可链接方法是返回查询集的方法，因此可以使用其他查询集方法。

使用 `all()` 和 `filter()` 方法获得的响应是查询集类型。查询集是可以迭代的模型实例集合。

## 仅获取一条记录

我们将在本章中看到的方法返回 `Model` 类型的对象，这些对象将用于记录关系或修改恢复的模型实例。

要使用查询集检索单个记录，我们应该像下面这行代码一样使用`get()`方法：

```py
first_project = Project.objects.get(id="1")
```

`get()`方法在作为`filter()`方法使用时接受过滤参数。但是，设置检索单个记录的过滤器时要小心。

如果`get()`的参数是`client_name = "Me"`，如果我们有超过两条记录与`client_name`对应，它将生成错误。

## 从查询集实例中获取模型实例

我们说过只有`get()`方法才能检索模型的实例。这是正确的，但有时从查询集中检索模型的实例也是有用的。

例如，如果我们想要获取客户`Me`的第一条记录，我们将写：

```py
queryset_project = Project.objects.filter(client_name="Me").order_by("id")
# This line returns a queryset in which there are as many elements as there are projects for the Me customer

first_item_queryset = queryset_project[:1]
# This line sends us only the first element of this queryset, but this element is not an instance of a model

project = first_item_queryset.get()
# This line retrieves the instance of the model that corresponds to the first element of queryset
```

这些方法是可链接的，所以我们可以写下面的一行代码，而不是前面的三行代码：

```py
project = Project.objects.filter(client_name="Me").order_by("id")[:1].get()
```

# 使用 get 参数

现在我们已经学会了如何检索记录，也知道如何使用 URL，我们将创建一个页面，用于显示项目的记录。为此，我们将看到一个新的 URL 语法：

```py
url(r'^project-detail-(?P<pk>\d+)$', 'TasksManager.views.project_detail.page', name="project_detail"),
```

这个 URL 包含一个新的字符串，`(?P<pk>\d+)`。它允许具有十进制参数的 URL 是有效的，因为它以`\d`结尾。结尾处的`+`字符表示参数不是可选的。`<pk>`字符串表示参数的名称是`pk`。

Django 的系统路由将直接将此参数发送到我们的视图。要使用它，只需将其添加到我们的`page()`函数的参数中。我们的视图变成了以下内容：

```py
from TasksManager.models import Project
from django.shortcuts import render
def page(request, pk):
  project = Project.objects.get(id=pk)
  return render(request, 'en/public/project_detail.html', {'project' : project})
```

然后，我们将创建我们的`en/public/project_detail.html`模板，从`base.html`扩展，并在`article_content`块中添加以下代码：

```py
<h3>{{ project.title }}</h3>
<h4>Client : {{ project.client_name }}</h4>
<p>
  {{ project.description }}
</p>
```

我们刚刚编写了我们的第一个包含参数的 URL。我们以后会用到这个，特别是在关于基于类的视图的章节中。

# 保存外键

我们已经从模型中记录了数据，但到目前为止，我们从未在关系数据库中记录过。以下是一个我们将在本章后面解释的关系记录的例子：

```py
from TasksManager.models import Project, Task, Supervisor, Developer
from django.shortcuts import render
from django.utils import timezone
def page(request):
  # Saving a new supervisor
  new_supervisor = Supervisor(name="Guido van Rossum", login="python", password="password", last_connection=timezone.now(), email="python@python.com", specialisation="Python") # line 1
  new_supervisor.save()
  # Saving a new developer
  new_developer = Developer(name="Me", login="me", password="pass", last_connection=timezone.now(), email="me@python.com", supervisor=new_supervisor)
  new_developer.save()
  # Saving a new task
  project_to_link = Project.objects.get(id = 1) # line 2
  new_task = Task(title="Adding relation", description="Example of adding relation and save it", time_elapsed=2, importance=0, project=project_to_link, developer=new_developer) # line 3
  new_task.save()
  return render(request, 'en/public/index.html', {'action' : 'Save relationship'})
```

在这个例子中，我们加载了四个模型。这四个模型用于创建我们的第一个任务。实际上，一个职位与一个项目和开发人员相关联。开发人员附属于监督者。

根据这种架构，我们必须首先创建一个监督者来添加一个开发人员。以下列表解释了这一点：

+   我们创建了一个新的监督者。请注意，扩展模型无需额外的步骤来记录。在`Supervisor`模型中，我们定义了`App_user`模型的字段，没有任何困难。在这里，我们使用`timezone`来记录当天的日期。

+   我们寻找第一个记录的项目。这行代码的结果将在`project_to_link`变量中记录`Model`类实例的遗留。只有`get()`方法才能给出模型的实例。因此，我们不应该使用`filter()`方法。

+   我们创建了一个新的任务，并将其分配给代码开头创建的项目和刚刚记录的开发人员。

这个例子非常全面，结合了我们从一开始学习的许多元素。我们必须理解它，才能继续在 Django 中编程。

# 更新数据库中的记录

Django 中有两种机制可以更新数据。实际上，有一种机制可以更新一条记录，另一种机制可以更新多条记录。

## 更新模型实例

更新现有数据非常简单。我们已经看到了如何做到这一点。以下是一个修改第一个任务的例子：

```py
from TasksManager.models import Project, Task
from django.shortcuts import render
def page(request):
  new_project = Project(title = "Other project", description="Try to update models.", client_name="People")
  new_project.save()
  task = Task.objects.get(id = 1)
  task.description = "New description"
  task.project = new_project
  task.save()
  return render(request, 'en/public/index.html', {'action' : 'Update model'})
```

在这个例子中，我们创建了一个新项目并保存了它。我们搜索了我们的任务，找到了`id = 1`。我们修改了描述和项目，使其与任务相关联。最后，我们保存了这个任务。

## 更新多条记录

要一次编辑多条记录，必须使用带有查询集对象类型的`update()`方法。例如，我们的`People`客户被名为`Nobody`的公司购买，因此我们需要更改所有`client_name`属性等于`People`的项目：

```py
from TasksManager.models import Project
from django.shortcuts import render
def page(request):
  task = Project.objects.filter(client_name = "people").update(client_name="Nobody")
  return render(request, 'en/public/index.html', {'action' : 'Update for many model'})
```

查询集的`update()`方法可以更改与该查询集相关的所有记录。这个方法不能用于模型的实例。

# 删除记录

要删除数据库中的记录，我们必须使用`delete()`方法。删除项目比更改项目更容易，因为该方法对查询集和模型实例都是相同的。一个例子如下：

```py
from TasksManager.models import Task
from django.shortcuts import render
def page(request):
  one_task = Task.objects.get(id = 1)
  one_task.delete() # line 1
  all_tasks = Task.objects.all()
  all_tasks.delete() # line 2
  return render(request, 'en/public/index.html', {'action' : 'Delete tasks'})
```

在这个例子中，`第 1 行`删除了`id = 1`的污渍。然后，`第 2 行`删除了数据库中所有现有的任务。

要小心，因为即使我们使用了一个 Web 框架，我们仍然掌握着数据。在这个例子中不需要确认，也没有进行备份。默认情况下，具有`ForeignKey`的模型删除规则是`CASCADE`值。这个规则意味着如果我们删除一个模板实例，那么对这个模型有外键的记录也将被删除。

# 获取关联记录

我们现在知道如何在数据库中创建、读取、更新和删除当前记录，但我们还没有恢复相关的对象。在我们的`TasksManager`应用程序中，检索项目中的所有任务将是有趣的。例如，由于我们刚刚删除了数据库中所有现有的任务，我们需要创建其他任务。我们特别需要在本章的其余部分为项目数据库创建任务。

使用 Python 及其面向对象模型的全面实现，访问相关模型是直观的。例如，当`login = 1`时，我们将检索所有项目任务：

```py
from TasksManager.models import Task, Project
from django.shortcuts import render
def page(request):
  project = Project.objects.get(id = 1)
  tasks = Task.objects.filter(project = project)
  return render(request, 'en/public/index.html', {'action' : 'Tasks for project', 'tasks':tasks})
```

现在我们将查找`id = 1`时的项目任务：

```py
from TasksManager.models import Task, Project
from django.shortcuts import render
def page(request):
  task = Task.objects.get(id = 1)
  project = task.project
  return render(request, 'en/public/index.html', {'action' : 'Project for task', 'project':project})
```

现在我们将使用关系来访问项目任务。

# 查询集的高级用法

我们学习了允许您与数据交互的查询集的基础知识。在特定情况下，需要对数据执行更复杂的操作。

## 在查询集中使用 OR 运算符

在查询集过滤器中，我们使用逗号来分隔过滤器。这一点隐含地意味着逻辑运算符`AND`。当应用`OR`运算符时，我们被迫使用`Q`对象。

这个`Q`对象允许您在模型上设置复杂的查询。例如，要选择客户`Me`和`Nobody`的项目，我们必须在视图中添加以下行：

```py
from TasksManager.models import Task, Project
from django.shortcuts import render
from django.db.models import Q
def page(request):
  projects_list = Project.objects.filter(Q(client_name="Me") | Q(client_name="Nobody"))
  return render(request, 'en/public/index.html', {'action' : 'Project with OR operator', 'projects_list':projects_list})
```

## 使用小于和大于的查找

使用 Django 查询集，我们不能使用`<`和`>`运算符来检查一个参数是否大于或小于另一个参数。

您必须使用以下字段查找：

+   `__gte`：这相当于 SQL 的大于或等于运算符，`>=`

+   `__gt`：这相当于 SQL 的大于运算符，`>`

+   `__lt`：这相当于 SQL 的小于运算符，`<`

+   `__lte`：这相当于 SQL 的小于或等于运算符，`<=`

例如，我们将编写一个查询集，可以返回持续时间大于或等于四小时的所有任务：

```py
tasks_list = Task.objects.filter(time_elapsed__gte=4)
```

## 执行排除查询

在网站的上下文中，排除查询可能很有用。例如，我们想要获取持续时间不超过四小时的项目列表：

```py
from TasksManager.models import Task, Project
from django.shortcuts import renderdef page(request):
  tasks_list = Task.objects.filter(time_elapsed__gt=4)
  array_projects = tasks_list.values_list('project', flat=True).distinct()
  projects_list = Project.objects.all()
  projects_list_lt4 = projects_list.exclude(id__in=array_projects)
  return render(request, 'en/public/index.html', {'action' : 'NOT IN SQL equivalent', 'projects_list_lt4':projects_list_lt4})
```

```py
In the first queryset, we first retrieve the list of all the tasks for which `time_elapsed` is greater than `4`In the second queryset, we got the list of all the related projects in these tasksIn the third queryset, we got all the projectsIn the fourth queryset, we excluded all the projects with tasks that last for more than `4` hours
```

## 进行原始 SQL 查询

有时，开发人员可能需要执行原始的 SQL 查询。为此，我们可以使用`raw()`方法，将 SQL 查询定义为参数。以下是一个检索第一个任务的示例：

```py
first_task = Project.objects.raw("SELECT * FROM TasksManager_project")[0]
```

要访问第一个任务的名称，只需使用以下语法：

```py
first_task.title
```

# 总结

在本章中，我们学习了如何通过 Django ORM 处理数据库。确实，借助 ORM，开发人员不需要编写 SQL 查询。在下一章中，我们将学习如何使用 Django 创建表单。
