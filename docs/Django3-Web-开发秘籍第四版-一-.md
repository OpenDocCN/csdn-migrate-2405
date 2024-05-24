# Django3 Web 开发秘籍第四版（一）

> 原文：[`zh.annas-archive.org/md5/49CC5D4E5506D0966D8746F9F4B56200`](https://zh.annas-archive.org/md5/49CC5D4E5506D0966D8746F9F4B56200)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

Django 框架专门设计用于帮助开发人员快速高效地构建强大的 Web 应用程序。它大大减少了繁琐的工作和重复的过程，解决了项目结构、数据库对象关系映射、模板化、表单验证、会话、身份验证、安全、cookie 管理、国际化、基本管理和从脚本访问数据的接口等问题。Django 是建立在 Python 编程语言之上的，Python 本身强制执行清晰易读的代码。除了核心框架，Django 还被设计为使开发人员能够创建可与自己的应用程序一起使用的第三方模块。Django 拥有一个成熟和充满活力的社区，您可以在其中找到源代码、获得帮助并做出贡献。

*Django 3 Web Development Cookbook, Fourth Edition*，将指导您使用 Django 3.0 框架完成 Web 开发过程的每个阶段。我们从项目的配置和结构开始。然后，您将学习如何使用可重用组件定义数据库结构，并在项目的整个生命周期中进行管理。本书将继续介绍用于输入和列出数据的表单和视图。我们将继续使用响应式模板和 JavaScript 来增强用户体验。然后，我们将通过自定义过滤器和标签增强 Django 的模板系统，以便更灵活地进行前端开发。之后，您将调整管理界面，以简化内容编辑者的工作流程。接下来，我们将关注项目的稳定性和健壮性，帮助您保护和优化应用程序。接下来，我们将探讨如何高效地存储和操作分层结构。然后，我们将演示从不同来源收集数据并以各种格式提供您自己的数据比您想象的简单。然后，我们将向您介绍一些用于编程和调试 Django 项目代码的技巧。我们将继续介绍一些可用于测试代码的选项。在本书结束之前，我们将向您展示如何将项目部署到生产环境。最后，我们将通过设置常见的维护实践来完成开发周期。

与许多其他 Django 书籍相比，这些书籍只关注框架本身，而本书涵盖了几个重要的第三方模块，这些模块将为您提供完成网站开发所需的工具。此外，我们提供了使用 Bootstrap 前端框架和 jQuery JavaScript 库的示例，这两者都简化了高级和复杂用户界面的创建。

# 本书适合人群

如果您有 Django 经验并希望提高技能，这本书适合您。我们设计了中级和专业 Django 开发人员的内容，他们的目标是构建多语言、安全、响应迅速且能够随时间推移扩展的强大项目。

# 本书内容包括

第一章，*开始使用 Django 3.0*，说明了任何 Django 项目所需的基本设置和配置步骤。我们涵盖了虚拟环境、Docker 以及跨环境和数据库的项目设置。

第二章，*模型和数据库结构*，解释了如何编写可重用的代码，用于构建模型。新应用程序的首要事项是定义数据模型，这构成了任何项目的支柱。您将学习如何在数据库中保存多语言数据。此外，您还将学习如何使用 Django 迁移管理数据库模式更改和数据操作。

第三章，*表单和视图*，展示了构建用于数据显示和编辑的视图和表单的方法。您将学习如何使用微格式和其他协议，使您的页面对机器更易读，以便在搜索结果和社交网络中表示。您还将学习如何生成 PDF 文档并实现多语言搜索。

第四章，*模板和 JavaScript*，涵盖了一起使用模板和 JavaScript 的实际示例。我们将这些方面结合起来：渲染的模板向用户呈现信息，而 JavaScript 为现代网站提供了关键的增强功能，以实现丰富的用户体验。

第五章，*自定义模板过滤器和标签*，介绍了如何创建和使用自己的模板过滤器和标签。正如您将看到的，默认的 Django 模板系统可以扩展以满足模板开发人员的需求。

第六章，*模型管理*，探讨了默认的 Django 管理界面，并指导您如何通过自己的功能扩展它。

第七章，*安全性和性能*，深入探讨了 Django 内在和外部的几种方式，以确保和优化您的项目。

第八章，*分层结构*，探讨了在 Django 中创建和操作类似树的结构，以及将`django-mptt`或`treebeard`库纳入此类工作流程的好处。本章向您展示了如何同时用于层次结构的显示和管理。

第九章，*导入和导出数据*，演示了数据在不同格式之间的传输，以及在各种来源之间的提供。在本章中，使用自定义管理命令进行数据导入，并利用站点地图、RSS 和 REST API 进行数据导出。

第十章，*花里胡哨*，展示了在日常网页开发和调试中有用的一些额外片段和技巧。

第十一章，*测试*，介绍了不同类型的测试，并提供了一些特征示例，说明如何测试项目代码。

第十二章，*部署*，涉及将第三方应用程序部署到 Python 软件包索引以及将 Django 项目部署到专用服务器。

第十三章，*维护*，解释了如何创建数据库备份，为常规任务设置 cron 作业，并记录事件以供进一步检查。

# 为了充分利用本书

要使用本书中的示例开发 Django 3.0，您需要以下内容：

+   Python 3.6 或更高版本

+   用于图像处理的**Pillow**库

+   要么使用 MySQL 数据库和`mysqlclient`绑定库，要么使用带有`psycopg2-binary`绑定库的 PostgreSQL 数据库

+   Docker Desktop 或 Docker Toolbox 用于完整的系统虚拟化，或者内置虚拟环境以保持每个项目的 Python 模块分开

+   用于版本控制的 Git

| **书中涵盖的软件/硬件** | **操作系统建议** |
| --- | --- |

| Python 3.6 或更高版本 Django 3.0.X

PostgreSQL 11.4 或更高版本/MySQL 5.6 或更高版本|任何最近的基于 Unix 的操作系统，如 macOS 或 Linux（尽管也可以在 Windows 上开发）

所有其他特定要求都将在每个配方中单独提到。

**如果您使用的是本书的数字版本，我们建议您自己输入代码或通过 GitHub 存储库访问代码（链接在下一节中提供）。这样做将有助于避免与复制/粘贴代码或不正确缩进相关的任何潜在错误。**

对于编辑项目文件，您可以使用任何代码编辑器，但我们建议使用**PyCharm**（[`www.jetbrains.com/pycharm/`](https://www.jetbrains.com/pycharm/)）或**Visual Studio Code**（[`code.visualstudio.com/`](https://code.visualstudio.com/)）。

如果您成功发布了 Django 项目，我会非常高兴，如果您能通过电子邮件与我分享您的结果、经验和成果，我的电子邮件是 aidas@bendoraitis.lt。

所有代码示例都经过了 Django 3 的测试。但是，它们也应该适用于将来的版本发布。

# 下载示例代码文件

您可以从 [www.packt.com](http://www.packt.com) 的帐户中下载本书的示例代码文件。如果您在其他地方购买了本书，您可以访问 [www.packtpub.com/support](https://www.packtpub.com/support) 并注册，以便直接通过电子邮件接收文件。

您可以按照以下步骤下载代码文件：

1.  在 [www.packt.com](http://www.packt.com) 上登录或注册。

1.  选择 Support 选项卡。

1.  点击 Code Downloads。

1.  在 Search 框中输入书名，然后按照屏幕上的说明进行操作。

一旦文件下载完成，请确保使用最新版本的解压缩或提取文件夹：

+   WinRAR/7-Zip for Windows

+   Zipeg/iZip/UnRarX for Mac

+   7-Zip/PeaZip for Linux

该书的代码包也托管在 GitHub 上，网址为 [`github.com/PacktPublishing/Django-3-Web-Development-Cookbook-Fourth-Edition`](https://github.com/PacktPublishing/Django-3-Web-Development-Cookbook-Fourth-Edition)。如果代码有更新，将在现有的 GitHub 存储库上进行更新。

我们还有其他代码包来自我们丰富的图书和视频目录，可在 **[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)** 上找到。请查看！

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。例如："为了使这个配方起作用，您需要安装 `contenttypes` 应用程序。"

代码块设置如下：

```py
# requirements/dev.txt
-r _base.txt
coverage
django-debug-toolbar
selenium
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```py
class Idea(CreationModificationDateBase, MetaTagsBase, UrlBase):
    title = models.CharField(
        _("Title"),
        max_length=200,
    )
    content = models.TextField(
        _("Content"),
    )
```

任何命令行输入或输出都以以下方式编写：

```py
(env)$ pip install -r requirements/dev.txt
```

**粗体**：表示新术语、重要单词或屏幕上看到的单词。例如，菜单或对话框中的单词会以这种方式出现在文本中。例如："我们可以看到这里与上传相关的操作按钮也被替换为了一个 Remove 按钮。"

警告或重要说明会以这种方式出现。

技巧和窍门会以这种方式出现。

# 章节

在本书中，您会经常看到几个标题（*准备工作*、*如何做...*、*它是如何工作的...*、*还有更多...* 和 *另请参阅*）。

为了清晰地说明如何完成一个配方，使用以下各节：

# 准备工作

本节告诉您应该期望在配方中发生什么，并描述了为配方设置任何软件或任何必需的预设置所需的步骤。

# 如何做...

本节包含了遵循配方所需的步骤。

# 它是如何工作的...

本节通常包括对前一节中发生的事情的详细解释。

# 还有更多...

本节包括有关配方的其他信息，以增加您对其的了解。

# 另请参阅

本节提供了有关配方的其他有用信息的链接。


# 第一章：开始使用 Django 3.0

在本章中，我们将涵盖以下主题：

+   使用虚拟环境

+   创建项目文件结构

+   使用 pip 处理项目依赖关系

+   为开发、测试、暂存和生产环境配置设置

+   在设置中定义相对路径

+   处理敏感设置

+   在项目中包含外部依赖项

+   动态设置`STATIC_URL`

+   将 UTF-8 设置为 MySQL 配置的默认编码

+   创建 Git 的`ignore`文件

+   删除 Python 编译文件

+   遵守 Python 文件中的导入顺序

+   创建应用程序配置

+   定义可覆盖的应用程序设置

+   使用 Docker 容器处理 Django、Gunicorn、Nginx 和 PostgreSQL

# 介绍

在本章中，我们将看到一些有价值的实践，用于使用 Python 3 在 Django 3.0 中启动新项目时遵循。我们选择了处理可扩展项目布局、设置和配置的最有用的方法，无论是使用 virtualenv 还是 Docker 来管理您的项目。

我们假设您已经熟悉 Django、Git 版本控制、MySQL 以及 PostgreSQL 数据库和命令行使用的基础知识。我们还假设您使用的是基于 Unix 的操作系统，如 macOS 或 Linux。在 Unix-based 平台上开发 Django 更有意义，因为 Django 网站很可能会发布在 Linux 服务器上，这意味着您可以建立在开发或部署时都能工作的例行程序。如果您在 Windows 上本地使用 Django，例行程序是类似的；但是它们并不总是相同的。

无论您的本地平台如何，使用 Docker 作为开发环境都可以通过部署改善应用程序的可移植性，因为 Docker 容器内的环境可以精确匹配部署服务器的环境。我们还应该提到，在本章的配方中，我们假设您已经在本地机器上安装了适当的版本控制系统和数据库服务器，无论您是否使用 Docker 进行开发。

# 技术要求

要使用本书的代码，您将需要最新稳定版本的 Python，可以从[`www.python.org/downloads/`](https://www.python.org/downloads/)下载。在撰写本文时，最新版本为 3.8.X。您还需要 MySQL 或 PostgreSQL 数据库。您可以从[`dev.mysql.com/downloads/`](https://dev.mysql.com/downloads/)下载 MySQL 数据库服务器。PostgreSQL 数据库服务器可以从[`www.postgresql.org/download/`](https://www.postgresql.org/download/)下载。其他要求将在特定的配方中提出。

您可以在 GitHub 存储库的`ch01`目录中找到本章的所有代码，网址为[`github.com/PacktPublishing/Django-3-Web-Development-Cookbook-Fourth-Edition`](https://github.com/PacktPublishing/Django-3-Web-Development-Cookbook-Fourth-Edition)。

# 使用虚拟环境

很可能您会在计算机上开发多个 Django 项目。某些模块，如 virtualenv、setuptools、wheel 或 Ansible，可以安装一次，然后为所有项目共享。其他模块，如 Django、第三方 Python 库和 Django 应用程序，需要保持彼此隔离。virtualenv 工具是一个实用程序，它将所有 Python 项目分开，并将它们保留在自己的领域中。在本配方中，我们将看到如何使用它。

# 准备工作

要管理 Python 包，您将需要 pip。如果您使用的是 Python 3.4+，则它将包含在您的 Python 安装中。如果您使用的是其他版本的 Python，可以通过执行[http:/​/​pip.​readthedocs.​org/​en/​stable/installing/](https://pip.pypa.io/en/stable/installing/)的安装说明来安装 pip。让我们升级共享的 Python 模块、pip、setuptools 和 wheel：

```py
$ sudo pip3 install --upgrade pip setuptools wheel
```

虚拟环境已经内置到 Python 3.3 版本以来。

# 如何做...

安装完先决条件后，创建一个目录，其中将存储所有 Django 项目，例如，在您的主目录下创建`projects`。创建目录后，请按以下步骤进行：

1.  转到新创建的目录并创建一个使用共享系统站点包的虚拟环境：

```py
$ cd ~/projects
$ mkdir myproject_website
$ cd myproject_website
$ python3 -m venv env
```

1.  要使用您新创建的虚拟环境，您需要在当前 shell 中执行激活脚本。可以使用以下命令完成：

```py
$ source env/bin/activate
```

1.  根据您使用的 shell，`source`命令可能不可用。另一种使用以下命令来源文件的方法是具有相同结果的（注意点和`env`之间的空格）：

```py
$ . env/bin/activate
```

1.  您将看到命令行工具的提示前缀为项目名称，如下所示：

```py
(env)$
```

1.  要退出虚拟环境，请输入以下命令：

```py
(env)$ deactivate
```

# 它是如何工作的...

创建虚拟环境时，会创建一些特定目录（`bin`、`include`和`lib`），以存储 Python 安装的副本，并定义一些共享的 Python 路径。激活虚拟环境后，您使用`pip`或`easy_install`安装的任何内容都将放在虚拟环境的站点包中，并且不会放在 Python 安装的全局站点包中。

要在虚拟环境中安装最新的 Django 3.0.x，请输入以下命令：

```py
(env)$ pip install "Django~=3.0.0"
```

# 另请参阅

+   *创建项目文件结构*食谱

+   第十二章中的*使用 Docker 容器进行 Django、Gunicorn、Nginx 和 PostgreSQL 部署*食谱

+   第十二章中的*使用 mod_wsgi 在 Apache 上部署分段环境*食谱，*部署*

+   第十二章*, 部署*中的*使用 Apache 和 mod_wsgi 部署生产环境*食谱

+   第十二章*, 部署*中的*在 Nginx 和 Gunicorn 上部署分段环境*食谱

+   第十二章*, 部署*中的*在 Nginx 和 Gunicorn 上部署生产环境*食谱

# 创建项目文件结构

为您的项目保持一致的文件结构可以使您更有条理、更高效。当您定义了基本工作流程后，您可以更快地进入业务逻辑并创建出色的项目。

# 准备工作

如果还没有，请创建一个`~/projects`目录，您将在其中保存所有 Django 项目（您可以在*使用虚拟环境*食谱中了解更多信息）。

然后，为您的特定项目创建一个目录，例如`myproject_website`。在那里的`env`目录中启动虚拟环境。激活它并在其中安装 Django，如前面的食谱中所述。我们建议添加一个`commands`目录，用于与项目相关的本地 shell 脚本，一个用于数据库转储的`db_backups`目录，一个用于网站设计文件的`mockups`目录，最重要的是一个用于您的 Django 项目的`src`目录。

# 如何做...

按照以下步骤为您的项目创建文件结构：

1.  激活虚拟环境后，转到`src`目录并启动一个新的 Django 项目，如下所示：

```py
(env)$ django-admin.py startproject myproject
```

执行的命令将创建一个名为`myproject`的目录，其中包含项目文件。该目录将包含一个名为`myproject`的 Python 模块。为了清晰和方便起见，我们将顶级目录重命名为`django-myproject`。这是您将放入版本控制的目录，因此它将有一个`.git`或类似命名的子目录。

1.  在`django-myproject`目录中，创建一个`README.md`文件，以向新的开发者描述您的项目。

1.  `django-myproject`目录还将包含以下内容：

+   您项目的 Python 包名为`myproject`。

+   您的项目的 pip 要求与 Django 框架和其他外部依赖项（在*使用 pip 处理项目依赖*食谱中了解更多）。

+   `LICENSE`文件中的项目许可证。如果您的项目是开源的，可以从[`choosealicense.com`](https://choosealicense.com)中选择最受欢迎的许可证之一。

1.  在您的项目的根目录`django-myproject`中，创建以下内容：

+   用于项目上传的`media`目录

+   用于收集静态文件的`static`目录

+   用于项目翻译的`locale`目录

+   用于无法使用 pip 要求的项目中包含的外部依赖的`externals`目录

1.  `myproject`目录应包含以下目录和文件：

+   `apps`目录，您将在其中放置项目的所有内部 Django 应用程序。建议您有一个名为`core`或`utils`的应用程序，用于项目的共享功能。

+   用于项目设置的`settings`目录（在*配置开发、测试、暂存和生产环境的设置*食谱中了解更多）。

+   用于特定项目的静态文件的`site_static`目录。

+   项目的 HTML 模板的`templates`目录。

+   项目的 URL 配置的`urls.py`文件。

+   项目的 Web 服务器配置的`wsgi.py`文件。

1.  在您的`site_static`目录中，创建`site`目录作为站点特定静态文件的命名空间。然后，我们将在其中的分类子目录之间划分静态文件。例如，参见以下内容：

+   Sass 文件的`scss`（可选）

+   用于生成压缩的**层叠样式表**（**CSS**）的`css`

+   用于样式图像、网站图标和标志的`img`

+   项目的 JavaScript 的`js`

+   `vendor`用于任何第三方模块，结合所有类型的文件，例如 TinyMCE 富文本编辑器

1.  除了`site`目录，`site_static`目录还可能包含第三方应用程序的覆盖静态目录，例如，它可能包含`cms`，它会覆盖 Django CMS 的静态文件。要从 Sass 生成 CSS 文件并压缩 JavaScript 文件，您可以使用带有图形用户界面的 CodeKit ([`codekitapp.com/`](https://codekitapp.com/))或 Prepros ([`prepros.io/`](https://prepros.io/))应用程序。

1.  将按应用程序分隔的模板放在您的`templates`目录中。如果模板文件表示页面（例如，`change_item.html`或`item_list.html`），则直接将其放在应用程序的模板目录中。如果模板包含在另一个模板中（例如，`similar_items.html`），则将其放在`includes`子目录中。此外，您的模板目录可以包含一个名为`utils`的目录，用于全局可重用的片段，例如分页和语言选择器。

# 它是如何工作的...

完整项目的整个文件结构将类似于以下内容：

```py
myproject_website/
├── commands/
├── db_backups/
├── mockups/
├── src/
│   └── django-myproject/
│       ├── externals/
│       │   ├── apps/
│       │   │   └── README.md
│       │   └── libs/
│       │       └── README.md
│       ├── locale/
│       ├── media/
│       ├── myproject/
│       │   ├── apps/
│       │   │   ├── core/
│       │   │   │   ├── __init__.py
│       │   │   │   └── versioning.py
│       │   │   └── __init__.py
│       │   ├── settings/
│       │   │   ├── __init__.py
│       │   │   ├── _base.py
│       │   │   ├── dev.py
│       │   │   ├── production.py
│       │   │   ├── sample_secrets.json
│       │   │   ├── secrets.json
│       │   │   ├── staging.py
│       │   │   └── test.py
│       │   ├── site_static/
│       │   │   └── site/
│       │   │  django-admin.py startproject myproject     ├── css/
│       │   │       │   └── style.css
│       │   │       ├── img/
│       │   │       │   ├── favicon-16x16.png
│       │   │       │   ├── favicon-32x32.png
│       │   │       │   └── favicon.ico
│       │   │       ├── js/
│       │   │       │   └── main.js
│       │   │       └── scss/
│       │   │           └── style.scss
│       │   ├── templates/
│       │   │   ├── base.html
│       │   │   └── index.html
│       │   ├── __init__.py
│       │   ├── urls.py
│       │   └── wsgi.py
│       ├── requirements/
│       │   ├── _base.txt
│       │   ├── dev.txt
│       │   ├── production.txt
│       │   ├── staging.txt
│       │   └── test.txt
│       ├── static/
│       ├── LICENSE
│       └── manage.py
└── env/
```

# 还有更多...

为了加快按照我们刚刚描述的方式创建项目的速度，您可以使用来自[`github.com/archatas/django-myproject`](https://github.com/archatas/django-myproject)的项目样板。下载代码后，执行全局搜索并替换`myproject`为您的项目的有意义的名称，然后您就可以开始了。

# 另请参阅

+   使用 pip 处理项目依赖的食谱

+   在项目中包含外部依赖的食谱

+   配置开发、测试、暂存和生产环境的设置

+   第十二章**部署**中的*在 Apache 上使用 mod_wsgi 部署暂存环境*食谱

+   第十二章*部署*中的*在 Apache 上使用 mod_wsgi 部署生产环境*食谱

+   第十二章*部署*中的*在 Nginx 和 Gunicorn 上部署暂存环境*食谱

+   在第十二章*，部署*中的*在 Nginx 和 Gunicorn 上部署生产环境*配方

# 使用 pip 处理项目依赖关系

安装和管理 Python 包的最方便的工具是 pip。与逐个安装包不同，可以将要安装的包的列表定义为文本文件的内容。我们可以将文本文件传递给 pip 工具，然后 pip 工具将自动处理列表中所有包的安装。采用这种方法的一个附加好处是，包列表可以存储在版本控制中。

一般来说，拥有一个与您的生产环境直接匹配的单个要求文件是理想的，通常也足够了。您可以在开发机器上更改版本或添加和删除依赖项，然后通过版本控制进行管理。这样，从一个依赖项集（和相关的代码更改）到另一个依赖项集的转换可以像切换分支一样简单。

在某些情况下，环境的差异足够大，您将需要至少两个不同的项目实例：

+   在这里创建新功能的开发环境

+   通常称为托管服务器中的生产环境的公共网站环境

可能有其他开发人员的开发环境，或者在开发过程中需要的特殊工具，但在生产中是不必要的。您可能还需要测试和暂存环境，以便在本地测试项目和在类似公共网站的设置中进行测试。

为了良好的可维护性，您应该能够为开发、测试、暂存和生产环境安装所需的 Python 模块。其中一些模块将是共享的，而另一些将特定于一部分环境。在本配方中，我们将学习如何为多个环境组织项目依赖项，并使用 pip 进行管理。

# 准备工作

在使用此配方之前，您需要准备好一个已安装 pip 并激活了虚拟环境的 Django 项目。有关如何执行此操作的更多信息，请阅读*使用虚拟环境*配方。

# 如何做...

逐步执行以下步骤，为您的虚拟环境 Django 项目准备 pip 要求：

1.  让我们进入您正在版本控制下的 Django 项目，并创建一个包含以下文本文件的 `requirements` 目录：

+   `_base.txt` 用于共享模块

+   `dev.txt` 用于开发环境

+   `test.txt` 用于测试环境

+   `staging.txt` 用于暂存环境

+   `production.txt` 用于生产环境

1.  编辑 `_base.txt` 并逐行添加在所有环境中共享的 Python 模块：

```py
# requirements/_base.txt
Django~=3.0.4
djangorestframework
-e git://github.com/omab/python-social-auth.git@6b1e301c79#egg=python-social-auth
```

1.  如果特定环境的要求与 `_base.txt` 中的要求相同，请在该环境的要求文件中添加包括 `_base.txt` 的行，如下例所示：

```py
# requirements/production.txt
-r _base.txt
```

1.  如果环境有特定要求，请在 `_base.txt` 包含之后添加它们，如下面的代码所示：

```py
# requirements/dev.txt
-r _base.txt
coverage
django-debug-toolbar
selenium
```

1.  您可以在虚拟环境中运行以下命令，以安装开发环境所需的所有依赖项（或其他环境的类似命令），如下所示：

```py
(env)$ pip install -r requirements/dev.txt
```

# 它是如何工作的...

前面的 `pip install` 命令，无论是在虚拟环境中显式执行还是在全局级别执行，都会从 `requirements/_base.txt` 和 `requirements/dev.txt` 下载并安装所有项目依赖项。如您所见，您可以指定您需要的 Django 框架的模块版本，甚至可以直接从 Git 存储库的特定提交中安装，就像我们的示例中对 `python-social-auth` 所做的那样。

在项目中有很多依赖项时，最好坚持使用 Python 模块发布版本的狭窄范围。然后，您可以更有信心地确保项目的完整性不会因依赖项的更新而受到破坏，这可能会导致冲突或向后不兼容。当部署项目或将其移交给新开发人员时，这一点尤为重要。

如果您已经手动逐个使用 pip 安装了项目要求，您可以在虚拟环境中使用以下命令生成`requirements/_base.txt`文件：

```py
(env)$ pip freeze > requirements/_base.txt
```

# 还有更多...

如果您想保持简单，并确信对于所有环境，您将使用相同的依赖项，您可以使用名为`requirements.txt`的一个文件来定义生成要求，如下所示：

```py
(env)$ pip freeze > requirements.txt
```

要在新的虚拟环境中安装模块，只需使用以下命令：

```py
(env)$ pip install -r requirements.txt
```

如果您需要从另一个版本控制系统或本地路径安装 Python 库，则可以从官方文档[`pip.pypa.io/en/stable/user_guide/`](https://pip.pypa.io/en/stable/user_guide)了解有关 pip 的更多信息。

另一种越来越受欢迎的管理 Python 依赖项的方法是 Pipenv。您可以在[`github.com/pypa/pipenv`](https://github.com/pypa/pipenv)获取并了解它。

# 另请参阅

+   *使用虚拟环境* 教程

+   *Django，Gunicorn，Nginx 和 PostgreSQL 的 Docker 容器工作* 教程

+   *在项目中包含外部依赖项* 教程

+   *配置开发、测试、暂存和生产环境的设置* 教程

# 配置开发、测试、暂存和生产环境的设置

如前所述，您将在开发环境中创建新功能，在测试环境中测试它们，然后将网站放到暂存服务器上，让其他人尝试新功能。然后，网站将部署到生产服务器供公众访问。每个环境都可以有特定的设置，您将在本教程中学习如何组织它们。

# 准备工作

在 Django 项目中，我们将为每个环境创建设置：开发、测试、暂存和生产。

# 如何做到...

按照以下步骤配置项目设置：

1.  在`myproject`目录中，创建一个`settings` Python 模块，并包含以下文件：

+   `__init__.py` 使设置目录成为 Python 模块。

+   `_base.py` 用于共享设置

+   `dev.py` 用于开发设置

+   `test.py` 用于测试设置

+   `staging.py` 用于暂存设置

+   `production.py` 用于生产设置

1.  将自动在启动新的 Django 项目时创建的`settings.py`的内容复制到`settings/_base.py`。然后，删除`settings.py`。

1.  将`settings/_base.py`中的`BASE_DIR`更改为指向上一级。它应该首先如下所示：

```py
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
```

更改后，它应如下所示：

```py
BASE_DIR = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
```

1.  如果一个环境的设置与共享设置相同，那么只需

从`_base.py`中导入所有内容，如下所示：

```py
# myproject/settings/production.py
from ._base import *
```

1.  在其他文件中应用您想要附加或覆盖的特定环境的设置，例如，开发环境设置应该放在`dev.py`中，如下面的代码片段所示：

```py
# myproject/settings/dev.py
from ._base import *
EMAIL_BACKEND = "django.core.mail.backends.console.EmailBackend"
```

1.  修改`manage.py`和`myproject/wsgi.py`文件，以默认使用其中一个环境设置，方法是更改以下行：

```py
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'myproject.settings')
```

1.  您应该将此行更改为以下内容：

```py
os.environ.setdefault('DJANGO_SETTINGS_MODULE',  'myproject.settings.production')
```

# 它是如何工作的...

默认情况下，Django 管理命令使用`myproject/settings.py`中的设置。使用此食谱中定义的方法，我们可以将所有环境中所需的非敏感设置保留在`config`目录中，并将`settings.py`文件本身忽略在版本控制中，它只包含当前开发、测试、暂存或生产环境所需的设置。

对于每个环境，建议您单独设置`DJANGO_SETTINGS_MODULE`环境变量，可以在 PyCharm 设置中、`env/bin/activate`脚本中或`.bash_profile`中设置。

# 另请参阅

+   *为 Django、Gunicorn、Nginx 和 PostgreSQL 工作的 Docker 容器*食谱

+   *处理敏感设置*食谱

+   *在设置中定义相对路径*食谱

+   *创建 Git 忽略文件*食谱

# 在设置中定义相对路径

Django 要求您在设置中定义不同的文件路径，例如媒体的根目录、静态文件的根目录、模板的路径和翻译文件的路径。对于项目的每个开发者，路径可能会有所不同，因为虚拟环境可以设置在任何地方，用户可能在 macOS、Linux 或 Windows 上工作。即使您的项目包装在 Docker 容器中，定义绝对路径会降低可维护性和可移植性。无论如何，有一种方法可以动态定义这些路径，使它们相对于您的 Django 项目目录。

# 准备工作

已经启动了一个 Django 项目并打开了`settings/_base.py`。

# 如何做...

相应地修改您的与路径相关的设置，而不是将路径硬编码到本地目录中，如下所示：

```py
# settings/_base.py
import os
BASE_DIR = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
# ...
TEMPLATES = [{
    # ...
    DIRS: [
       os.path.join(BASE_DIR, 'myproject', 'templates'),
    ],
    # ...
}]
# ...
LOCALE_PATHS = [
    os.path.join(BASE_DIR, 'locale'),
]
# ...
STATICFILES_DIRS = [
    os.path.join(BASE_DIR, 'myproject', 'site_static'),
]
STATIC_ROOT = os.path.join(BASE_DIR, 'static')
MEDIA_ROOT = os.path.join(BASE_DIR, 'media')
```

# 它是如何工作的...

默认情况下，Django 设置包括`BASE_DIR`值，这是一个绝对路径，指向包含`manage.py`的目录（通常比`settings.py`文件高一级，或比`settings/_base.py`高两级）。然后，我们使用`os.path.join()`函数将所有路径设置为相对于`BASE_DIR`。

根据我们在*创建项目文件结构*食谱中设置的目录布局，我们将在一些先前的示例中插入`'myproject'`作为中间路径段，因为相关文件夹是在其中创建的。

# 另请参阅

+   *创建项目文件结构*食谱

+   *为 Django、Gunicorn、Nginx 和 PostgreSQL 工作的 Docker 容器*食谱

+   *在项目中包含外部依赖项*食谱

# 处理敏感设置

在配置 Django 项目时，您肯定会处理一些敏感信息，例如密码和 API 密钥。不建议将这些信息放在版本控制下。存储这些信息的主要方式有两种：在环境变量中和在单独的未跟踪文件中。在这个食谱中，我们将探讨这两种情况。

# 准备工作

项目的大多数设置将在所有环境中共享并保存在版本控制中。这些可以直接在设置文件中定义；但是，将有一些设置是特定于项目实例的环境或敏感的，并且需要额外的安全性，例如数据库或电子邮件设置。我们将使用环境变量来公开这些设置。

# 如何做...

从环境变量中读取敏感设置，执行以下步骤：

1.  在`settings/_base.py`的开头，定义`get_secret()`函数如下：

```py
# settings/_base.py
import os
from django.core.exceptions import ImproperlyConfigured

def get_secret(setting):
    """Get the secret variable or return explicit exception."""
    try:
        return os.environ[setting]
    except KeyError:
        error_msg = f'Set the {setting} environment variable'
        raise ImproperlyConfigured(error_msg)
```

1.  然后，每当您需要定义敏感值时，使用`get_secret()`函数，如下例所示：

```py
SECRET_KEY = get_secret('DJANGO_SECRET_KEY')

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql_psycopg2',
        'NAME': get_secret('DATABASE_NAME'),
        'USER': get_secret('DATABASE_USER'),
        'PASSWORD': get_secret('DATABASE_PASSWORD'),
        'HOST': 'db',
        'PORT': '5432',
    }
}
```

# 它是如何工作的...

如果在没有设置环境变量的情况下运行 Django 管理命令，您将看到一个错误消息，例如设置`DJANGO_SECRET_KEY`环境变量。

您可以在 PyCharm 配置、远程服务器配置控制台、`env/bin/activate`脚本、`.bash_profile`或直接在终端中设置环境变量，如下所示：

```py
$ export DJANGO_SECRET_KEY="change-this-to-50-characters-long-random-
  string"
$ export DATABASE_NAME="myproject"
$ export DATABASE_USER="myproject"
$ export DATABASE_PASSWORD="change-this-to-database-password"
```

请注意，您应该在 Django 项目配置中使用`get_secret()`函数来获取所有密码、API 密钥和任何其他敏感信息。

# 还有更多...

您还可以使用包含敏感信息的文本文件，这些文件不会被版本控制跟踪，而不是环境变量。它们可以是 YAML、INI、CSV 或 JSON 文件，放置在硬盘的某个位置。例如，对于 JSON 文件，您可以有`get_secret()`函数，如下所示：

```py
# settings/_base.py
import os
import json

with open(os.path.join(os.path.dirname(__file__), 'secrets.json'), 'r') 
 as f:
    secrets = json.loads(f.read())

def get_secret(setting):
    """Get the secret variable or return explicit exception."""
    try:
        return secrets[setting]
    except KeyError:
        error_msg = f'Set the {setting} secret variable'
        raise ImproperlyConfigured(error_msg)
```

这将从设置目录中的`secrets.json`文件中读取，并期望它至少具有以下结构：

```py
{
    "DATABASE_NAME": "myproject",
    "DATABASE_USER": "myproject",
    "DATABASE_PASSWORD": "change-this-to-database-password",
    "DJANGO_SECRET_KEY": "change-this-to-50-characters-long-random-string"
}
```

确保`secrets.json`文件被版本控制忽略，但为了方便起见，您可以创建带有空值的`sample_secrets.json`并将其放在版本控制下：

```py
{
    "DATABASE_NAME": "",
    "DATABASE_USER": "",
    "DATABASE_PASSWORD": "",
    "DJANGO_SECRET_KEY": "change-this-to-50-characters-long-random-string"
}
```

# 另请参阅

+   *创建项目文件结构*配方

+   *Docker 容器中的 Django、Gunicorn、Nginx 和 PostgreSQL*配方

# 在项目中包含外部依赖项

有时，您无法使用 pip 安装外部依赖项，必须直接将其包含在项目中，例如以下情况：

+   当您有一个修补过的第三方应用程序，您自己修复了一个错误或添加了一个未被项目所有者接受的功能时

+   当您需要使用无法在**Python 软件包索引**（**PyPI**）或公共版本控制存储库中访问的私有应用程序时

+   当您需要使用 PyPI 中不再可用的依赖项的旧版本时

*在项目中包含外部依赖项*可以确保每当开发人员升级依赖模块时，所有其他开发人员都将在版本控制系统的下一个更新中收到升级后的版本。

# 准备工作

您应该从虚拟环境下的 Django 项目开始。

# 如何做...

逐步执行以下步骤，针对虚拟环境项目：

1.  如果尚未这样做，请在 Django 项目目录`django-myproject`下创建一个`externals`目录。

1.  然后，在其中创建`libs`和`apps`目录。`libs`目录用于项目所需的 Python 模块，例如 Boto、Requests、Twython 和 Whoosh。`apps`目录用于第三方 Django 应用程序，例如 Django CMS、Django Haystack 和 django-storages。

我们强烈建议您在`libs`和`apps`目录中创建`README.md`文件，其中提到每个模块的用途、使用的版本或修订版本以及它来自哪里。

1.  目录结构应该类似于以下内容：

```py
externals/
 ├── apps/
 │   ├── cms/
 │   ├── haystack/
 │   ├── storages/
 │   └── README.md
 └── libs/
     ├── boto/
     ├── requests/
     ├── twython/
     └── README.md
```

1.  下一步是将外部库和应用程序放在 Python 路径下，以便它们被识别为已安装。这可以通过在设置中添加以下代码来完成：

```py
# settings/_base.py
import os
import sys
BASE_DIR = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
EXTERNAL_BASE = os.path.join(BASE_DIR, "externals")
EXTERNAL_LIBS_PATH = os.path.join(EXTERNAL_BASE, "libs")
EXTERNAL_APPS_PATH = os.path.join(EXTERNAL_BASE, "apps")
sys.path = ["", EXTERNAL_LIBS_PATH, EXTERNAL_APPS_PATH] + sys.path
```

# 工作原理...

如果您可以运行 Python 并导入该模块，则模块应该位于 Python 路径下。将模块放在 Python 路径下的一种方法是在导入位于不寻常位置的模块之前修改`sys.path`变量。根据设置文件指定的`sys.path`的值是一个目录列表，以空字符串开头表示当前目录，然后是项目中的目录，最后是 Python 安装的全局共享目录。您可以在 Python shell 中看到`sys.path`的值，如下所示：

```py
(env)$ python manage.py shell
>>> import sys
>>> sys.path
```

尝试导入模块时，Python 会在此列表中搜索模块，并返回找到的第一个结果。

因此，我们首先定义`BASE_DIR`变量，它是`django-myproject`的绝对路径，或者比`myproject/settings/_base.py`高三级。然后，我们定义`EXTERNAL_LIBS_PATH`和`EXTERNAL_APPS_PATH`变量，它们是相对于`BASE_DIR`的。最后，我们修改`sys.path`属性，将新路径添加到列表的开头。请注意，我们还将空字符串添加为第一个搜索路径，这意味着始终应首先检查任何模块的当前目录，然后再检查其他 Python 路径。

这种包含外部库的方式无法跨平台使用具有 C 语言绑定的 Python 软件包，例如`lxml`。对于这样的依赖关系，我们建议使用在*使用 pip 处理项目依赖关系*配方中介绍的 pip 要求。

# 参见

+   *创建项目文件结构*配方

+   *使用 Docker 容器处理 Django、Gunicorn、Nginx 和 PostgreSQL*配方

+   *使用 pip 处理项目依赖关系*配方

+   *在设置中定义相对路径*配方

+   *在[第十章](http://bells)*中的*Django shell*配方，铃声和口哨*

# 动态设置 STATIC_URL

如果将`STATIC_URL`设置为静态值，则每次更新 CSS 文件、JavaScript 文件或图像时，您和您的网站访问者都需要清除浏览器缓存才能看到更改。有一个绕过清除浏览器缓存的技巧，就是在`STATIC_URL`中显示最新更改的时间戳。每当代码更新时，访问者的浏览器将强制加载所有新的静态文件。

在这个配方中，我们将看到如何在`STATIC_URL`中放置 Git 用户的时间戳。

# 准备工作

确保您的项目处于 Git 版本控制下，并且在设置中定义了`BASE_DIR`，如*在设置中定义相对路径*配方中所示。

# 如何做...

将 Git 时间戳放入`STATIC_URL`设置的过程包括以下两个步骤：

1.  如果尚未这样做，请在 Django 项目中创建`myproject.apps.core`应用。您还应该在那里创建一个`versioning.py`文件：

```py
# versioning.py
import subprocess
from datetime import datetime

def get_git_changeset_timestamp(absolute_path):
    repo_dir = absolute_path
    git_log = subprocess.Popen(
        "git log --pretty=format:%ct --quiet -1 HEAD",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=True,
        cwd=repo_dir,
        universal_newlines=True,
    )

    timestamp = git_log.communicate()[0]
    try:
        timestamp = datetime.utcfromtimestamp(int(timestamp))
    except ValueError:
        # Fallback to current timestamp
        return datetime.now().strftime('%Y%m%d%H%M%S')
    changeset_timestamp = timestamp.strftime('%Y%m%d%H%M%S')
    return changeset_timestamp
```

1.  在设置中导入新创建的`get_git_changeset_timestamp()`函数，并将其用于`STATIC_URL`路径，如下所示：

```py
# settings/_base.py
from myproject.apps.core.versioning import get_git_changeset_timestamp
# ...
timestamp = get_git_changeset_timestamp(BASE_DIR)
STATIC_URL = f'/static/{timestamp}/'
```

# 它是如何工作的...

`get_git_changeset_timestamp()`函数以`absolute_path`目录作为参数，并调用`git log` shell 命令，参数是显示目录中 HEAD 修订的 Unix 时间戳。我们将`BASE_DIR`传递给函数，因为我们确信它处于版本控制之下。时间戳被解析，转换为由年、月、日、小时、分钟和秒组成的字符串，然后包含在`STATIC_URL`的定义中。

# 还有更多...

这种方法仅在您的每个环境中包含项目的完整 Git 存储库时才有效——在某些情况下，例如当您使用 Heroku 或 Docker 进行部署时，您无法访问远程服务器中的 Git 存储库和`git log`命令。为了使`STATIC_URL`具有动态片段，您必须从文本文件中读取时间戳，例如`myproject/settings/last-modified.txt`，并且应该在每次提交时更新该文件。

在这种情况下，您的设置将包含以下行：

```py
# settings/_base.py
with open(os.path.join(BASE_DIR, 'myproject', 'settings', 'last-update.txt'), 'r') as f:
    timestamp = f.readline().strip()

STATIC_URL = f'/static/{timestamp}/'
```

您可以通过预提交挂钩使 Git 存储库更新`last-modified.txt`。这是一个可执行的 bash 脚本，应该被称为`pre-commit`，并放置在`django-myproject/.git/hooks/`下：

```py
# django-myproject/.git/hooks/pre-commit
#!/usr/bin/env python
from subprocess import check_output, CalledProcessError
import os
from datetime import datetime

def root():
    ''' returns the absolute path of the repository root '''
    try:
        base = check_output(['git', 'rev-parse', '--show-toplevel'])
    except CalledProcessError:
        raise IOError('Current working directory is not a git repository')
    return base.decode('utf-8').strip()

def abspath(relpath):
    ''' returns the absolute path for a path given relative to the root of
        the git repository
    '''
    return os.path.join(root(), relpath)

def add_to_git(file_path):
    ''' adds a file to git '''
    try:
        base = check_output(['git', 'add', file_path])
    except CalledProcessError:
        raise IOError('Current working directory is not a git repository')
    return base.decode('utf-8').strip()

def main():
    file_path = abspath("myproject/settings/last-update.txt")

    with open(file_path, 'w') as f:
        f.write(datetime.now().strftime("%Y%m%d%H%M%S"))

    add_to_git(file_path)

if __name__ == '__main__':
    main()
```

每当您提交到 Git 存储库时，此脚本将更新`last-modified.txt`并将该文件添加到 Git 索引中。

# 参见

+   *创建 Git 忽略文件*配方

# 将 UTF-8 设置为 MySQL 配置的默认编码

MySQL 自称是最流行的开源数据库。在这个食谱中，我们将告诉你如何将 UTF-8 设置为它的默认编码。请注意，如果你不在数据库配置中设置这个编码，你可能会遇到这样的情况，即默认情况下使用 LATIN1 编码你的 UTF-8 编码数据。这将导致数据库错误，每当使用€等符号时。这个食谱还将帮助你免于在将数据库数据从 LATIN1 转换为 UTF-8 时遇到困难，特别是当你有一些表以 LATIN1 编码，另一些表以 UTF-8 编码时。

# 准备工作

确保 MySQL 数据库管理系统和**mysqlclient** Python 模块已安装，并且在项目设置中使用了 MySQL 引擎。

# 操作步骤...

在你喜欢的编辑器中打开`/etc/mysql/my.cnf` MySQL 配置文件，并确保以下设置在`[client]`、`[mysql]`和`[mysqld]`部分中设置如下：

```py
# /etc/mysql/my.cnf
[client]
default-character-set = utf8

[mysql]
default-character-set = utf8

[mysqld]
collation-server = utf8_unicode_ci
init-connect = 'SET NAMES utf8'
character-set-server = utf8
```

如果任何部分不存在，就在文件中创建它们。如果部分已经存在，就将这些设置添加到现有的配置中，然后在命令行工具中重新启动 MySQL，如下所示：

```py
$ /etc/init.d/mysql restart
```

# 它是如何工作的...

现在，每当你创建一个新的 MySQL 数据库时，数据库和所有的表都将默认设置为 UTF-8 编码。不要忘记在开发或发布项目的所有计算机上设置这一点。

# 还有更多...

在 PostgreSQL 中，默认的服务器编码已经是 UTF-8，但如果你想显式地创建一个带有 UTF-8 编码的 PostgreSQL 数据库，那么你可以使用以下命令来实现：

```py
$ createdb --encoding=UTF8 --locale=en_US.UTF-8 --template=template0 myproject
```

# 另请参阅

+   *创建项目文件结构*食谱

+   *使用 Docker 容器进行 Django、Gunicorn、Nginx 和 PostgreSQL 开发*食谱

# 创建 Git 忽略文件

Git 是最流行的分布式版本控制系统，你可能已经在你的 Django 项目中使用它。尽管你正在跟踪大部分文件的更改，但建议你将一些特定的文件和文件夹排除在版本控制之外。通常情况下，缓存、编译代码、日志文件和隐藏系统文件不应该在 Git 仓库中被跟踪。

# 准备工作

确保你的 Django 项目在 Git 版本控制下。

# 操作步骤...

使用你喜欢的文本编辑器，在你的 Django 项目的根目录创建一个`.gitignore`文件，并将以下文件和目录放在其中：

```py
# .gitignore ### Python template
# Byte-compiled / optimized / DLL files
__pycache__/
*.py[cod]
*$py.class

# Installer logs
pip-log.txt
pip-delete-this-directory.txt

# Unit test / coverage reports
htmlcov/
.tox/
.nox/
.coverage
.coverage.*
.cache
nosetests.xml
coverage.xml
*.cover
.hypothesis/
.pytest_cache/

# Translations
*.mo
*.pot

# Django stuff:
*.log
db.sqlite3

# Sphinx documentation
docs/_build/

# IPython
profile_default/
ipython_config.py

# Environments
env/

# Media and Static directories
/media/
!/media/.gitkeep

/static/
!/static/.gitkeep

# Secrets
secrets.json
```

# 它是如何工作的...

`.gitignore`文件指定了应该被 Git 版本控制系统有意忽略的模式。我们在这个食谱中创建的`.gitignore`文件将忽略 Python 编译文件、本地设置、收集的静态文件和上传文件的媒体目录。

请注意，我们对媒体和静态文件有特殊的叹号语法：

```py
/media/
!/media/.gitkeep
```

这告诉 Git 忽略`/media/`目录，但保持`/media/.gitkeep`文件在版本控制下被跟踪。由于 Git 版本控制跟踪文件，而不是目录，我们使用`.gitkeep`来确保`media`目录将在每个环境中被创建，但不被跟踪。

# 另请参阅

+   *创建项目文件结构*食谱

+   *使用 Docker 容器进行 Django、Gunicorn、Nginx 和 PostgreSQL 开发*食谱

# 删除 Python 编译文件

当你第一次运行项目时，Python 会将所有的`*.py`代码编译成字节编译文件`*.pyc`，以便后续执行。通常情况下，当你改变`*.py`文件时，`*.pyc`会被重新编译；然而，有时当你切换分支或移动目录时，你需要手动清理编译文件。

# 准备工作

使用你喜欢的编辑器，在你的主目录中编辑或创建一个`.bash_profile`文件。

# 操作步骤...

1.  在`.bash_profile`的末尾添加这个别名，如下所示：

```py
# ~/.bash_profile alias delpyc='
find . -name "*.py[co]" -delete
find . -type d -name "__pycache__" -delete'
```

1.  现在，要清理 Python 编译文件，进入你的项目目录，在命令行上输入以下命令：

```py
(env)$ delpyc
```

# 它是如何工作的...

首先，我们创建一个 Unix 别名，用于搜索当前目录及其子目录中的`*.pyc`和`*.pyo`文件和`__pycache__`目录，并将其删除。当您在命令行工具中启动新会话时，将执行`.bash_profile`文件。

# 还有更多...

如果您想完全避免创建 Python 编译文件，可以在`.bash_profile`、`env/bin/activate`脚本或 PyCharm 配置中设置环境变量`PYTHONDONTWRITEBYTECODE=1`。

# 另请参阅

+   创建 Git 忽略文件的方法

# 尊重 Python 文件中的导入顺序

在创建 Python 模块时，保持与文件结构一致是一个良好的做法。这样可以使您和其他开发人员更容易阅读代码。本方法将向您展示如何构建导入结构。

# 准备就绪

创建虚拟环境并在其中创建 Django 项目。

# 如何做...

对于您正在创建的每个 Python 文件，请使用以下结构。将导入分类为以下几个部分：

```py
# System libraries
import os
import re
from datetime import datetime

# Third-party libraries
import boto
from PIL import Image

# Django modules
from django.db import models
from django.conf import settings

# Django apps
from cms.models import Page

# Current-app modules
from .models import NewsArticle
from . import app_settings
```

# 它是如何工作的...

我们有五个主要的导入类别，如下所示：

+   系统库用于 Python 默认安装的软件包

+   第三方库用于额外安装的 Python 包

+   Django 模块用于 Django 框架中的不同模块

+   Django 应用程序用于第三方和本地应用程序

+   当前应用程序模块用于从当前应用程序进行相对导入

# 还有更多...

在 Python 和 Django 中编码时，请使用 Python 代码的官方样式指南 PEP 8。您可以在[https:/​/​www.​python.​org/​dev/​peps/​pep-​0008/](https://www.python.org/dev/peps/pep-0008/)找到它。

# 另请参阅

+   使用 pip 处理项目依赖的方法

+   在项目中包含外部依赖的方法

# 创建应用程序配置

Django 项目由称为应用程序（或更常见的应用程序）的多个 Python 模块组成，这些模块结合了不同的模块化功能。每个应用程序都可以有模型、视图、表单、URL 配置、管理命令、迁移、信号、测试、上下文处理器、中间件等。Django 框架有一个应用程序注册表，其中收集了所有应用程序和模型，稍后用于配置和内省。自 Django 1.7 以来，有关应用程序的元信息可以保存在每个应用程序的`AppConfig`实例中。让我们创建一个名为`magazine`的示例应用程序，看看如何在那里使用应用程序配置。

# 准备就绪

您可以通过调用`startapp`管理命令或手动创建应用程序模块来创建 Django 应用程序：

```py
(env)$ cd myproject/apps/
(env)$ django-admin.py startapp magazine
```

创建`magazine`应用程序后，在`models.py`中添加`NewsArticle`模型，在`admin.py`中为模型创建管理，并在设置中的`INSTALLED_APPS`中放入`"myproject.apps.magazine"`。如果您还不熟悉这些任务，请学习官方的 Django 教程[`docs.djangoproject.com/en/3.0/intro/tutorial01/`](https://docs.djangoproject.com/en/3.0/intro/tutorial01/)。

# 如何做...

按照以下步骤创建和使用应用程序配置：

1.  修改`apps.py`文件并插入以下内容：

```py
# myproject/apps/magazine/apps.py
from django.apps import AppConfig
from django.utils.translation import gettext_lazy as _

class MagazineAppConfig(AppConfig):
    name = "myproject.apps.magazine"
    verbose_name = _("Magazine")

    def ready(self):
        from . import signals
```

1.  编辑`magazine`模块中的`__init__.py`文件，包含以下内容：

```py
# myproject/apps/magazine/__init__.py
default_app_config = "myproject.apps.magazine.apps.MagazineAppConfig"
```

1.  让我们创建一个`signals.py`文件并在其中添加一些信号处理程序：

```py
# myproject/apps/magazine/signals.py
from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from django.conf import settings

from .models import NewsArticle

@receiver(post_save, sender=NewsArticle)
def news_save_handler(sender, **kwargs):
    if settings.DEBUG:
        print(f"{kwargs['instance']} saved.")

@receiver(post_delete, sender=NewsArticle)
def news_delete_handler(sender, **kwargs):
    if settings.DEBUG:
        print(f"{kwargs['instance']} deleted.")
```

# 它是如何工作的...

当您运行 HTTP 服务器或调用管理命令时，会调用`django.setup()`。它加载设置，设置日志记录，并准备应用程序注册表。此注册表分为三个步骤初始化。Django 首先从设置中的`INSTALLED_APPS`导入每个项目的配置。这些项目可以直接指向应用程序名称或配置，例如`"myproject.apps.magazine"`或`"myproject.apps.magazine.apps.MagazineAppConfig"`。

然后 Django 尝试从`INSTALLED_APPS`中的每个应用程序导入`models.py`并收集所有模型。

最后，Django 运行 `ready()` 方法以进行每个应用程序配置。如果有的话，此方法在开发过程中是注册信号处理程序的好时机。`ready()` 方法是可选的。

在我们的示例中，`MagazineAppConfig` 类设置了 `magazine` 应用程序的配置。`name` 参数定义了当前应用程序的模块。`verbose_name` 参数定义了在 Django 模型管理中使用的人类名称，其中模型按应用程序进行呈现和分组。`ready()` 方法导入并激活信号处理程序，当处于 DEBUG 模式时，它会在终端中打印出 `NewsArticle` 对象已保存或已删除的消息。

# 还有更多...

在调用 `django.setup()` 后，您可以按如下方式从注册表中加载应用程序配置和模型：

```py
>>> from django.apps import apps as django_apps
>>> magazine_app_config = django_apps.get_app_config("magazine")
>>> magazine_app_config
<MagazineAppConfig: magazine>
>>> magazine_app_config.models_module
<module 'magazine.models' from '/path/to/myproject/apps/magazine/models.py'>
>>> NewsArticle = django_apps.get_model("magazine", "NewsArticle")
>>> NewsArticle
<class 'magazine.models.NewsArticle'>
```

您可以在官方 Django 文档中阅读有关应用程序配置的更多信息

[`docs.djangoproject.com/en/2.2/ref/applications/`](https://docs.djangoproject.com/en/2.2/ref/applications/)​。

# 另请参阅

+   *使用虚拟环境* 配方

+   *使用 Docker 容器进行 Django、Gunicorn、Nginx 和 PostgreSQL* 配方

+   *定义可覆盖的应用程序设置* 配方

+   第六章*，模型管理*

# 定义可覆盖的应用程序设置

此配方将向您展示如何定义应用程序的设置，然后可以在项目的设置文件中进行覆盖。这对于可重用的应用程序特别有用，您可以通过添加配置来自定义它们。

# 准备工作

按照*准备工作*中*创建应用程序配置* 配方中的步骤来创建您的 Django 应用程序。

# 如何做...

1.  如果只有一两个设置，可以在 `models.py` 中使用 `getattr()` 模式定义应用程序设置，或者如果设置很多并且想要更好地组织它们，可以在 `app_settings.py` 文件中定义：

```py
# myproject/apps/magazine/app_settings.py
from django.conf import settings
from django.utils.translation import gettext_lazy as _

# Example:
SETTING_1 = getattr(settings, "MAGAZINE_SETTING_1", "default value")

MEANING_OF_LIFE = getattr(settings, "MAGAZINE_MEANING_OF_LIFE", 42)

ARTICLE_THEME_CHOICES = getattr(
    settings,
    "MAGAZINE_ARTICLE_THEME_CHOICES",
    [
        ('futurism', _("Futurism")),
        ('nostalgia', _("Nostalgia")),
        ('sustainability', _("Sustainability")),
        ('wonder', _("Wonder")),
    ]
)
```

1.  `models.py` 将包含以下 `NewsArticle` 模型：

```py
# myproject/apps/magazine/models.py
from django.db import models
from django.utils.translation import gettext_lazy as _

class NewsArticle(models.Model):
    created_at = models.DateTimeField(_("Created at"),  
     auto_now_add=True)
    title = models.CharField(_("Title"), max_length=255)
    body = models.TextField(_("Body"))
    theme = models.CharField(_("Theme"), max_length=20)

    class Meta:
        verbose_name = _("News Article")
        verbose_name_plural = _("News Articles")

    def __str__(self):
        return self.title
```

1.  接下来，在 `admin.py` 中，我们将从 `app_settings.py` 导入并使用设置，如下所示：

```py
# myproject/apps/magazine/admin.py
from django import forms
from django.contrib import admin

from .models import NewsArticle

from .app_settings import ARTICLE_THEME_CHOICES

class NewsArticleModelForm(forms.ModelForm):
    theme = forms.ChoiceField(
        label=NewsArticle._meta.get_field("theme").verbose_name,
        choices=ARTICLE_THEME_CHOICES,
        required=not NewsArticle._meta.get_field("theme").blank,
    )
    class Meta:
        fields = "__all__"

@admin.register(NewsArticle)
class NewsArticleAdmin(admin.ModelAdmin):
 form = NewsArticleModelForm
```

1.  如果要覆盖给定项目的 `ARTICLE_THEME_CHOICES` 设置，应在项目设置中添加 `MAGAZINE_ARTICLE_THEME_CHOICES`：

```py
# myproject/settings/_base.py
from django.utils.translation import gettext_lazy as _
# ...
MAGAZINE_ARTICLE_THEME_CHOICES = [
    ('futurism', _("Futurism")),
    ('nostalgia', _("Nostalgia")),
    ('sustainability', _("Sustainability")),
    ('wonder', _("Wonder")),
    ('positivity', _("Positivity")),
    ('solutions', _("Solutions")),
    ('science', _("Science")),
]
```

# 它是如何工作的...

`getattr(object, attribute_name[, default_value])` Python 函数尝试从 `object` 获取 `attribute_name` 属性，并在找不到时返回 `default_value`。我们尝试从 Django 项目设置模块中读取不同的设置，如果在那里找不到，则使用默认值。

请注意，我们本可以在 `models.py` 中为 `theme` 字段定义 `choices`，但我们改为在管理中创建自定义 `ModelForm` 并在那里设置 `choices`。这样做是为了避免在更改 `ARTICLE_THEME_CHOICES` 时创建新的数据库迁移。

# 另请参阅

+   *创建应用程序配置* 配方

+   第六章，*模型管理*

# 使用 Docker 容器进行 Django、Gunicorn、Nginx 和 PostgreSQL

Django 项目不仅依赖于 Python 要求，还依赖于许多系统要求，如 Web 服务器、数据库、服务器缓存和邮件服务器。在开发 Django 项目时，您需要确保所有环境和所有开发人员都安装了相同的要求。保持这些依赖项同步的一种方法是使用 Docker。使用 Docker，您可以为每个项目单独拥有数据库、Web 或其他服务器的不同版本。

Docker 是用于创建配置、定制的虚拟机的系统，称为容器。它允许我们精确复制任何生产环境的设置。Docker 容器是从所谓的 Docker 镜像创建的。镜像由层（或指令）组成，用于构建容器。可以有一个用于 PostgreSQL 的镜像，一个用于 Redis 的镜像，一个用于 Memcached 的镜像，以及一个用于您的 Django 项目的自定义镜像，所有这些镜像都可以与 Docker Compose 结合成相应的容器。

在这个示例中，我们将使用项目模板来设置一个 Django 项目，其中包括一个由 Nginx 和 Gunicorn 提供的 PostgreSQL 数据库，并使用 Docker Compose 来管理它们。

# 准备工作

首先，您需要安装 Docker Engine，按照[`www.docker.com/get-started`](https://www.docker.com/get-started)上的说明进行操作。这通常包括 Compose 工具，它可以管理需要多个容器的系统，非常适合完全隔离的 Django 项目。如果需要单独安装，Compose 的安装详细信息可在[`docs.docker.com/compose/install/`](https://docs.docker.com/compose/install/)上找到。

# 如何做...

让我们来探索 Django 和 Docker 模板：

1.  例如，从[`github.com/archatas/django_docker`](https://github.com/archatas/django_docker)下载代码到您的计算机的`~/projects/django_docker`目录。

如果您选择另一个目录，例如`myproject_docker`，那么您将需要全局搜索和替换`django_docker`为`myproject_docker`。

1.  打开`docker-compose.yml`文件。需要创建三个容器：`nginx`，`gunicorn`和`db`。如果看起来很复杂，不用担心；我们稍后会详细描述它：

```py
# docker-compose.yml
version: "3.7"

services:
  nginx:
    image: nginx:latest
    ports:
      - "80:80"
    volumes:
      - ./config/nginx/conf.d:/etc/nginx/conf.d
      - static_volume:/home/myproject/static
      - media_volume:/home/myproject/media
    depends_on:
      - gunicorn

  gunicorn:
    build:
      context: .
      args:
        PIP_REQUIREMENTS: "${PIP_REQUIREMENTS}"
    command: bash -c "/home/myproject/env/bin/gunicorn --workers 3 
    --bind 0.0.0.0:8000 myproject.wsgi:application"
    depends_on:
      - db
    volumes:
      - static_volume:/home/myproject/static
      - media_volume:/home/myproject/media
    expose:
      - "8000"
    environment:
      DJANGO_SETTINGS_MODULE: "${DJANGO_SETTINGS_MODULE}"
      DJANGO_SECRET_KEY: "${DJANGO_SECRET_KEY}"
      DATABASE_NAME: "${DATABASE_NAME}"
      DATABASE_USER: "${DATABASE_USER}"
      DATABASE_PASSWORD: "${DATABASE_PASSWORD}"
      EMAIL_HOST: "${EMAIL_HOST}"
      EMAIL_PORT: "${EMAIL_PORT}"
      EMAIL_HOST_USER: "${EMAIL_HOST_USER}"
      EMAIL_HOST_PASSWORD: "${EMAIL_HOST_PASSWORD}"

  db:
    image: postgres:latest
    restart: always
    environment:
      POSTGRES_DB: "${DATABASE_NAME}"
      POSTGRES_USER: "${DATABASE_USER}"
      POSTGRES_PASSWORD: "${DATABASE_PASSWORD}"
    ports:
      - 5432
    volumes:
      - postgres_data:/var/lib/postgresql/data/

volumes:
  postgres_data:
  static_volume:
  media_volume:

```

1.  打开并阅读`Dockerfile`文件。这些是创建`gunicorn`容器所需的层（或指令）：

```py
# Dockerfile
# pull official base image
FROM python:3.8

# accept arguments
ARG PIP_REQUIREMENTS=production.txt

# set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# install dependencies
RUN pip install --upgrade pip setuptools

# create user for the Django project
RUN useradd -ms /bin/bash myproject

# set current user
USER myproject

# set work directory
WORKDIR /home/myproject

# create and activate virtual environment
RUN python3 -m venv env

# copy and install pip requirements
COPY --chown=myproject ./src/myproject/requirements /home/myproject/requirements/
RUN ./env/bin/pip3 install -r /home/myproject/requirements/${PIP_REQUIREMENTS}

# copy Django project files
COPY --chown=myproject ./src/myproject /home/myproject/

```

1.  将`build_dev_example.sh`脚本复制到`build_dev.sh`并编辑其内容。这些是要传递给`docker-compose`脚本的环境变量：

```py
# build_dev.sh
#!/usr/bin/env bash
DJANGO_SETTINGS_MODULE=myproject.settings.dev \
DJANGO_SECRET_KEY="change-this-to-50-characters-long-
 random-string" \
DATABASE_NAME=myproject \
DATABASE_USER=myproject \
DATABASE_PASSWORD="change-this-too" \
PIP_REQUIREMENTS=dev.txt \
docker-compose up --detach --build
```

1.  在命令行工具中，为`build_dev.sh`添加执行权限并运行它以构建容器：

```py
$ chmod +x build_dev.sh
$ ./build_dev.sh
```

1.  如果您现在转到`http://0.0.0.0/en/`，您应该会在那里看到一个 Hello, World!页面。

导航到`http://0.0.0.0/en/admin/`时，您应该会看到以下内容：

```py
OperationalError at /en/admin/
 FATAL: role "myproject" does not exist
```

这意味着你必须在 Docker 容器中创建数据库用户和数据库。

1.  让我们 SSH 到`db`容器中，在 Docker 容器中创建数据库用户、密码和数据库本身：

```py
$ docker exec -it django_docker_db_1 bash
/# su - postgres
/$ createuser --createdb --password myproject
/$ createdb --username myproject myproject
```

当询问时，输入与`build_dev.sh`脚本中数据库相同的密码。

按下[*Ctrl* + *D*]两次以注销 PostgreSQL 用户和 Docker 容器。

如果您现在转到`http://0.0.0.0/en/admin/`，您应该会看到以下内容：

```py
ProgrammingError at /en/admin/ relation "django_session" does not exist LINE 1: ...ession_data", "django_session"."expire_date" FROM "django_se...
```

这意味着您必须运行迁移以创建数据库架构。

1.  SSH 到`gunicorn`容器中并运行必要的 Django 管理命令：

```py
$ docker exec -it django_docker_gunicorn_1 bash
$ source env/bin/activate
(env)$ python manage.py migrate
(env)$ python manage.py collectstatic
(env)$ python manage.py createsuperuser
```

回答管理命令提出的所有问题。

按下[*Ctrl* + *D*]两次以退出 Docker 容器。

如果您现在导航到`[`0.0.0.0/en/admin/`](http://0.0.0.0/en/admin/)`，您应该会看到 Django 管理界面，您可以使用刚刚创建的超级用户凭据登录。

1.  创建类似的脚本`build_test.sh`，`build_staging.sh`和`build_production.sh`，只有环境变量不同。

# 它是如何工作的...

模板中的代码结构类似于虚拟环境中的代码结构。项目源文件位于`src`目录中。我们有`git-hooks`目录用于预提交挂钩，用于跟踪最后修改日期和`config`目录用于容器中使用的服务的配置：

```py
django_docker
├── config/
│   └── nginx/
│       └── conf.d/
│           └── myproject.conf
├── git-hooks/
│   ├── install_hooks.sh
│   └── pre-commit
├── src/
│   └── myproject/
│       ├── locale/
│       ├── media/
│       ├── myproject/
│       │   ├── apps/
│       │   │   └── __init__.py
│       │   ├── settings/
│       │   │   ├── __init__.py
│       │   │   ├── _base.py
│       │   │   ├── dev.py
│       │   │   ├── last-update.txt
│       │   │   ├── production.py
│       │   │   ├── staging.py
│       │   │   └── test.py
│       │   ├── site_static/
│       │   │   └── site/
│       │   │       ├── css/
│       │   │       ├── img/
│       │   │       ├── js/
│       │   │       └── scss/
│       │   ├── templates/
│       │   │   ├── base.html
│       │   │   └── index.html
│       │   ├── __init__.py
│       │   ├── urls.py
│       │   └── wsgi.py
│       ├── requirements/
│       │   ├── _base.txt
│       │   ├── dev.txt
│       │   ├── production.txt
│       │   ├── staging.txt
│       │   └── test.txt
│       ├── static/
│       └── manage.py
├── Dockerfile
├── LICENSE
├── README.md
├── build_dev.sh
├── build_dev_example.sh
└── docker-compose.yml
```

主要的与 Docker 相关的配置位于`docker-compose.yml`和`Dockerfile`。Docker Compose 是 Docker 命令行 API 的包装器。`build_dev.sh`脚本构建并在端口`8000`下运行 Django 项目下的 Gunicorn WSGI HTTP 服务器，端口`80`下的 Nginx（提供静态和媒体文件并代理其他请求到 Gunicorn），以及端口`5432`下的 PostgreSQL 数据库。

在`docker-compose.yml`文件中，请求创建三个 Docker 容器：

+   `nginx`用于 Nginx Web 服务器

+   `gunicorn`用于 Django 项目的 Gunicorn Web 服务器

+   `db`用于 PostgreSQL 数据库

`nginx`和`db`容器将从位于[`hub.docker.com`](https://hub.docker.com)的官方镜像创建。它们具有特定的配置参数，例如它们运行的端口，环境变量，对其他容器的依赖以及卷。

Docker 卷是在重新构建 Docker 容器时保持不变的特定目录。需要为数据库数据文件，媒体，静态文件等定义卷。

`gunicorn`容器将根据`Dockerfile`中的指令构建，该指令由`docker-compose.yml`文件中的构建上下文定义。让我们检查每个层（或指令）：

+   `gunicorn`容器将基于`python:3.7`镜像

+   它将从`docker-compose.yml`文件中获取`PIP_REQUIREMENTS`作为参数

+   它将为容器设置环境变量

+   它将安装并升级 pip，setuptools 和 virtualenv

+   它将为 Django 项目创建一个名为`myproject`的系统用户

+   它将把`myproject`设置为当前用户

+   它将把`myproject`用户的主目录设置为当前工作目录

+   它将在那里创建一个虚拟环境

+   它将从基础计算机复制 pip 要求到 Docker 容器

+   它将安装当前环境的 pip 要求，由`PIP_REQUIREMENTS`变量定义

+   它将复制整个 Django 项目的源代码

`config/nginx/conf.d/myproject.conf`的内容将保存在`nginx`容器中的`/etc/nginx/conf.d/`下。这是 Nginx Web 服务器的配置，告诉它监听端口`80`（默认的 HTTP 端口）并将请求转发到端口`8000`上的 Gunicorn 服务器，除了请求静态或媒体内容：

```py
#/etc/nginx/conf.d/myproject.conf
upstream myproject {
    server django_docker_gunicorn_1:8000;
}

server {
    listen 80;

    location / {
        proxy_pass http://myproject;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Host $host;
        proxy_redirect off;
    }

    rewrite "/static/\d+/(.*)" /static/$1 last;

    location /static/ {
        alias /home/myproject/static/;
    }

    location /media/ {
        alias /home/myproject/media/;
    }
}
```

您可以在第十二章*，部署*中的*在 Nginx 和 Gunicorn 上部署暂存环境*和*在 Nginx 和 Gunicorn 上部署生产环境*配方中了解更多关于 Nginx 和 Gunicorn 配置的信息。

# 还有更多...

您可以使用`docker-compose down`命令销毁 Docker 容器，并使用构建脚本重新构建它们：

```py
$ docker-compose down
$ ./build_dev.sh
```

如果某些内容不符合预期，您可以使用`docker-compose logs`命令检查日志：

```py
$ docker-compose logs nginx
$ docker-compose logs gunicorn $ docker-compose logs db

```

要通过 SSH 连接到任何容器，您应该使用以下之一：

```py
$ docker exec -it django_docker_gunicorn_1 bash
$ docker exec -it django_docker_nginx_1 bash
$ docker exec -it django_docker_db_1 bash
```

您可以使用`docker cp`命令将文件和目录复制到 Docker 容器上的卷中，并从中复制出来：

```py
$ docker cp ~/avatar.png django_docker_gunicorn_1:/home/myproject/media/ $ docker cp django_docker_gunicorn_1:/home/myproject/media ~/Desktop/

```

如果您想更好地了解 Docker 和 Docker Compose，请查看官方文档[`docs.docker.com/`](https://docs.docker.com/)，特别是[`docs.docker.com/compose/`](https://docs.docker.com/compose/)。

# 另请参阅

+   *创建项目文件结构*配方

+   *在 Apache 上使用 mod_wsgi 部署暂存环境*配方在第十二章*，部署*

+   *在 Apache 上使用 mod_wsgi 部署生产环境*配方在第十二章*，部署*

+   *在 Nginx 和 Gunicorn 上部署暂存环境*配方在第十二章*，部署*

+   *在 Nginx 和 Gunicorn 上部署生产环境*配方在第十二章*，部署*


# 第二章：模型和数据库结构

在本章中，我们将涵盖以下主题：

+   使用模型 mixin

+   创建一个具有 URL 相关方法的模型 mixin

+   创建一个模型 mixin 来处理创建和修改日期

+   创建一个处理元标签的模型 mixin

+   创建一个处理通用关系的模型 mixin

+   处理多语言字段

+   使用模型翻译表

+   避免循环依赖

+   添加数据库约束

+   使用迁移

+   将外键更改为多对多字段

# 介绍

当您开始一个新的应用程序时，您要做的第一件事是创建代表您的数据库结构的模型。我们假设您已经创建了 Django 应用程序，或者至少已经阅读并理解了官方的 Django 教程。在本章中，您将看到一些有趣的技术，这些技术将使您的数据库结构在项目中的不同应用程序中保持一致。然后，您将学习如何处理数据库中数据的国际化。之后，您将学习如何避免模型中的循环依赖以及如何设置数据库约束。在本章的最后，您将学习如何使用迁移来在开发过程中更改数据库结构。

# 技术要求

要使用本书中的代码，您需要最新稳定版本的 Python、MySQL 或 PostgreSQL 数据库以及一个带有虚拟环境的 Django 项目。

您可以在 GitHub 存储库的`ch02`目录中找到本章的所有代码：[`github.com/PacktPublishing/Django-3-Web-Development-Cookbook-Fourth-Edition`](https://github.com/PacktPublishing/Django-3-Web-Development-Cookbook-Fourth-Edition)。

# 使用模型 mixin

在面向对象的语言中，比如 Python，一个 mixin 类可以被视为一个带有实现特性的接口。当一个模型扩展一个 mixin 时，它实现了接口并包含了所有的字段、属性、属性和方法。Django 模型中的 mixin 可以在您想要多次在不同模型中重用通用功能时使用。Django 中的模型 mixin 是抽象基本模型类。我们将在接下来的几个示例中探讨它们。

# 准备工作

首先，您需要创建可重用的 mixin。将模型 mixin 保存在`myproject.apps.core`应用程序中是一个很好的地方。如果您创建了一个可重用的应用程序，将模型 mixin 保存在可重用的应用程序本身中，可能是在一个`base.py`文件中。

# 如何做...

打开任何您想要在其中使用 mixin 的 Django 应用程序的`models.py`文件，并键入以下代码：

```py
# myproject/apps/ideas/models.py
from django.db import models
from django.urls import reverse
from django.utils.translation import gettext_lazy as _

from myproject.apps.core.models import (
    CreationModificationDateBase,
    MetaTagsBase,
    UrlBase,
)

class Idea(CreationModificationDateBase, MetaTagsBase, UrlBase):
    title = models.CharField(
        _("Title"),
        max_length=200,
    )
    content = models.TextField(
        _("Content"),
    )
    # other fields…

    class Meta:
        verbose_name = _("Idea")
        verbose_name_plural = _("Ideas")

    def __str__(self):
        return self.title

    def get_url_path(self):
        return reverse("idea_details", kwargs={
            "idea_id": str(self.pk),
        })
```

# 它是如何工作的...

Django 的模型继承支持三种类型的继承：抽象基类、多表继承和代理模型。模型 mixin 是抽象模型类，我们通过使用一个指定字段、属性和方法的抽象`Meta`类来定义它们。当您创建一个模型，比如在前面的示例中所示的`Idea`，它继承了`CreationModificationDateMixin`、`MetaTagsMixin`和`UrlMixin`的所有特性。这些抽象类的所有字段都保存在与扩展模型的字段相同的数据库表中。在接下来的示例中，您将学习如何定义您自己的模型 mixin。

# 还有更多...

在普通的 Python 类继承中，如果有多个基类，并且它们都实现了一个特定的方法，并且您在子类的实例上调用该方法，只有第一个父类的方法会被调用，就像下面的例子一样：

```py
>>> class A(object):
... def test(self):
...     print("A.test() called")
... 

>>> class B(object):
... def test(self):
...     print("B.test() called")
... 

>>> class C(object):
... def test(self):
...     print("C.test() called")
... 

>>> class D(A, B, C):
... def test(self):
...     super().test()
...     print("D.test() called")

>>> d = D()
>>> d.test()
A.test() called
D.test() called
```

这与 Django 模型基类相同；然而，有一个特殊的例外。

Django 框架对元类进行了一些魔术，调用了每个基类的`save()`和`delete()`方法。

这意味着您可以自信地对特定字段进行预保存、后保存、预删除和后删除操作，这些字段是通过覆盖 mixin 中的`save()`和`delete()`方法来定义的。

要了解更多关于不同类型的模型继承，请参阅官方 Django 文档，网址为[`docs.djangoproject.com/en/2.2/topics/db/models/#model-inheritance`](https://docs.djangoproject.com/en/2.2/topics/db/models/#model-inheritance)。

# 另请参阅

+   *创建一个具有与 URL 相关方法的模型 mixin*配方

+   *创建一个模型 mixin 来处理创建和修改日期*配方

+   *创建一个模型 mixin 来处理 meta 标签*配方

# 创建一个具有与 URL 相关方法的模型 mixin

对于每个具有自己独特详细页面的模型，定义`get_absolute_url()`方法是一个良好的做法。这个方法可以在模板中使用，也可以在 Django 管理站点中用于预览保存的对象。但是，`get_absolute_url()`是模棱两可的，因为它返回 URL 路径而不是完整的 URL。

在这个配方中，我们将看看如何创建一个模型 mixin，为模型特定的 URL 提供简化的支持。这个 mixin 将使您能够做到以下几点：

+   允许您在模型中定义 URL 路径或完整 URL

+   根据您定义的路径自动生成其他 URL

+   在幕后定义`get_absolute_url()`方法

# 准备工作

如果尚未这样做，请创建`myproject.apps.core`应用程序，您将在其中存储您的模型 mixin。然后，在 core 包中创建一个`models.py`文件。或者，如果您创建了一个可重用的应用程序，请将 mixin 放在该应用程序的`base.py`文件中。

# 如何做...

逐步执行以下步骤：

1.  将以下内容添加到`core`应用程序的`models.py`文件中：

```py
# myproject/apps/core/models.py from urllib.parse import urlparse, urlunparse
from django.conf import settings
from django.db import models

class UrlBase(models.Model):
    """
    A replacement for get_absolute_url()
    Models extending this mixin should have either get_url or 
     get_url_path implemented.
    """
    class Meta:
        abstract = True

    def get_url(self):
        if hasattr(self.get_url_path, "dont_recurse"):
            raise NotImplementedError
        try:
            path = self.get_url_path()
        except NotImplementedError:
            raise
        return settings.WEBSITE_URL + path
    get_url.dont_recurse = True

    def get_url_path(self):
        if hasattr(self.get_url, "dont_recurse"):
            raise NotImplementedError
        try:
            url = self.get_url()
        except NotImplementedError:
            raise
        bits = urlparse(url)
        return urlunparse(("", "") + bits[2:])
    get_url_path.dont_recurse = True

    def get_absolute_url(self):
        return self.get_url()
```

1.  将`WEBSITE_URL`设置添加到`dev`、`test`、`staging`和`production`设置中，不带斜杠。例如，对于开发环境，如下所示：

```py
# myproject/settings/dev.py
from ._base import *

DEBUG = True
WEBSITE_URL = "http://127.0.0.1:8000"  # without trailing slash
```

1.  要在您的应用程序中使用 mixin，从`core`应用程序导入 mixin，在您的模型类中继承 mixin，并定义`get_url_path()`方法，如下所示：

```py
# myproject/apps/ideas/models.py
from django.db import models
from django.urls import reverse
from django.utils.translation import gettext_lazy as _

from myproject.apps.core.models import UrlBase

class Idea(UrlBase):
    # fields, attributes, properties and methods…

    def get_url_path(self):
        return reverse("idea_details", kwargs={
            "idea_id": str(self.pk),
        })
```

# 它是如何工作的...

`UrlBase`类是一个抽象模型，具有三种方法，如下所示：

+   `get_url()`检索对象的完整 URL。

+   `get_url_path()`检索对象的绝对路径。

+   `get_absolute_url()`模仿`get_url_path()`方法。

`get_url()`和`get_url_path()`方法预计会在扩展模型类中被覆盖，例如`Idea`。您可以定义`get_url()`，`get_url_path()`将会将其剥离为路径。或者，您可以定义`get_url_path()`，`get_url()`将在路径的开头添加网站 URL。

一个经验法则是始终覆盖`get_url_path()`方法。

在模板中，当您需要链接到同一网站上的对象时，请使用`get_url_path()`，如下所示：

```py
<a href="{{ idea.get_url_path }}">{{ idea.title }}</a>
```

在外部通信中使用`get_url()`进行链接，例如在电子邮件、RSS 订阅或 API 中；例如如下：

```py
<a href="{{  idea.get_url }}">{{ idea.title }}</a>
```

默认的`get_absolute_url()`方法将在 Django 模型管理中用于“查看网站”功能，并且也可能被一些第三方 Django 应用程序使用。

# 还有更多...

一般来说，不要在 URL 中使用递增的主键，因为将它们暴露给最终用户是不安全的：项目的总数将可见，并且只需更改 URL 路径就可以轻松浏览不同的项目。

只有当它们是**通用唯一标识符**（**UUIDs**）或生成的随机字符串时，您才可以在详细页面的 URL 中使用主键。否则，请创建并使用 slug 字段，如下所示：

```py
class Idea(UrlBase):
    slug = models.SlugField(_("Slug for URLs"), max_length=50)
```

# 另请参阅

+   *使用模型 mixin*配方

+   *创建一个模型 mixin 来处理创建和修改日期*配方

+   *创建一个模型 mixin 来处理 meta 标签*配方

+   *创建一个模型 mixin 来处理通用关系*配方

+   *为开发、测试、暂存和生产环境配置设置*配方，在第一章*，使用 Django 3.0 入门*

# 创建一个模型 mixin 来处理创建和修改日期

在您的模型中包含创建和修改模型实例的时间戳是很常见的。在这个示例中，您将学习如何创建一个简单的模型 mixin，为您的模型保存创建和修改的日期和时间。使用这样的 mixin 将确保所有模型使用相同的时间戳字段名称，并具有相同的行为。

# 准备工作

如果还没有这样做，请创建`myproject.apps.core`包来保存您的 mixin。然后，在核心包中创建`models.py`文件。

# 如何做...

打开`myprojects.apps.core`包中的`models.py`文件，并在其中插入以下内容：

```py
# myproject/apps/core/models.py
from django.db import models
from django.utils.translation import gettext_lazy as _

class CreationModificationDateBase(models.Model):
    """
    Abstract base class with a creation and modification date and time
    """

    created = models.DateTimeField(
        _("Creation Date and Time"),
        auto_now_add=True,
    )

    modified = models.DateTimeField(
        _("Modification Date and Time"),
        auto_now=True,
    )

    class Meta:
        abstract = True
```

# 它是如何工作的...

`CreationModificationDateMixin`类是一个抽象模型，这意味着扩展模型类将在同一个数据库表中创建所有字段，也就是说，不会有使表更复杂的一对一关系。

这个 mixin 有两个日期时间字段，`created`和`modified`。使用`auto_now_add`和`auto_now`属性，时间戳将在保存模型实例时自动保存。字段将自动获得`editable=False`属性，因此在管理表单中将被隐藏。如果在设置中将`USE_TZ`设置为`True`（这是默认和推荐的），将使用时区感知的时间戳。否则，将使用时区无关的时间戳。时区感知的时间戳保存在数据库中的**协调世界时**（**UTC**）时区，并在读取或写入时将其转换为项目的默认时区。时区无关的时间戳保存在数据库中项目的本地时区；一般来说，它们不实用，因为它们使得时区之间的时间管理更加复杂。

要使用这个 mixin，我们只需要导入它并扩展我们的模型，如下所示：

```py
# myproject/apps/ideas/models.py
from django.db import models

from myproject.apps.core.models import CreationModificationDateBase

class Idea(CreationModificationDateBase):
    # other fields, attributes, properties, and methods…
```

# 另请参阅

+   *使用模型 mixin*示例

+   *创建一个处理 meta 标签的模型 mixin*示例

+   *创建一个处理通用关系的模型 mixin*示例

# 创建一个处理 meta 标签的模型 mixin

当您为搜索引擎优化您的网站时，不仅需要为每个页面使用语义标记，还需要包含适当的 meta 标签。为了最大的灵活性，有必要定义特定于在您的网站上拥有自己详细页面的对象的常见 meta 标签的内容。在这个示例中，我们将看看如何为与关键字、描述、作者和版权 meta 标签相关的字段和方法创建模型 mixin。

# 准备工作

如前面的示例中所述，确保您的 mixin 中有`myproject.apps.core`包。另外，在该包下创建一个目录结构`templates/utils/includes/`，并在其中创建一个`meta.html`文件来存储基本的 meta 标签标记。

# 如何做...

让我们创建我们的模型 mixin：

1.  确保在设置中将`"myproject.apps.core"`添加到`INSTALLED_APPS`中，因为我们希望为此模块考虑`templates`目录。

1.  将以下基本的 meta 标签标记添加到`meta_field.html`中：

```py
{# templates/core/includes/meta_field.html #}
<meta name="{{ name }}" content="{{ content }}" />
```

1.  打开您喜欢的编辑器中的核心包中的`models.py`文件，并添加以下内容：

```py
# myproject/apps/core/models.py from django.conf import settings
from django.db import models
from django.utils.translation import gettext_lazy as _
from django.utils.safestring import mark_safe
from django.template.loader import render_to_string

class MetaTagsBase(models.Model):
    """
    Abstract base class for generating meta tags
    """
    meta_keywords = models.CharField(
        _("Keywords"),
        max_length=255,
        blank=True,
        help_text=_("Separate keywords with commas."),
    )
    meta_description = models.CharField(
        _("Description"),
        max_length=255,
        blank=True,
    )
    meta_author = models.CharField(
        _("Author"),
        max_length=255,
        blank=True,
    )
    meta_copyright = models.CharField(
        _("Copyright"),
        max_length=255,
        blank=True,
    )

    class Meta:
        abstract = True

    def get_meta_field(self, name, content):
        tag = ""
        if name and content:
            tag = render_to_string("core/includes/meta_field.html", 
            {
                "name": name,
                "content": content,
            })
        return mark_safe(tag)

    def get_meta_keywords(self):
        return self.get_meta_field("keywords", self.meta_keywords)

    def get_meta_description(self):
        return self.get_meta_field("description", 
         self.meta_description)

    def get_meta_author(self):
        return self.get_meta_field("author", self.meta_author)

    def get_meta_copyright(self):
        return self.get_meta_field("copyright", 
         self.meta_copyright)

    def get_meta_tags(self):
        return mark_safe("\n".join((
            self.get_meta_keywords(),
            self.get_meta_description(),
            self.get_meta_author(),
            self.get_meta_copyright(),
        )))
```

# 它是如何工作...

这个 mixin 为扩展自它的模型添加了四个字段：`meta_keywords`，`meta_description`，`meta_author`和`meta_copyright`。还添加了相应的`get_*()`方法，用于呈现相关的 meta 标签。其中每个方法都将名称和适当的字段内容传递给核心的`get_meta_field()`方法，该方法使用此输入返回基于`meta_field.html`模板的呈现标记。最后，提供了一个快捷的`get_meta_tags()`方法，用于一次生成所有可用元数据的组合标记。

如果您在模型中使用这个 mixin，比如在本章开头的*使用模型 mixin*配方中展示的`Idea`中，您可以将以下内容放在`detail`页面模板的`HEAD`部分，以一次性渲染所有的元标记：

```py
{% block meta_tags %}
{{ block.super }}
{{ idea.get_meta_tags }}
{% endblock %}
```

在这里，一个`meta_tags`块已经在父模板中定义，这个片段展示了子模板如何重新定义块，首先将父模板的内容作为`block.super`，然后用`idea`对象的附加标签扩展它。您也可以通过类似以下的方式只渲染特定的元标记：`{{ idea.get_meta_description }}`。

从`models.py`代码中，您可能已经注意到，渲染的元标记被标记为安全-也就是说，它们没有被转义，我们不需要使用`safe`模板过滤器。只有来自数据库的值被转义，以确保最终的 HTML 格式正确。当我们为`meta_field.html`模板调用`render_to_string()`时，`meta_keywords`和其他字段中的数据库数据将自动转义，因为该模板在其内容中没有指定`{% autoescape off %}`。

# 另请参阅

+   *使用模型 mixin*配方

+   *创建一个处理创建和修改日期的模型 mixin*配方

+   *创建处理通用关系的模型 mixin*配方

+   在第四章*，模板和 JavaScript*中*安排 base.html 模板*配方

# 创建一个处理通用关系的模型 mixin

除了常规的数据库关系，比如外键关系或多对多关系，Django 还有一种将模型与任何其他模型的实例相关联的机制。这个概念被称为通用关系。对于每个通用关系，我们保存相关模型的内容类型以及该模型实例的 ID。

在这个配方中，我们将看看如何在模型 mixin 中抽象通用关系的创建。

# 准备工作

为了使这个配方工作，您需要安装`contenttypes`应用程序。它应该默认在设置中的`INSTALLED_APPS`列表中，如下所示：

```py
# myproject/settings/_base.py

INSTALLED_APPS = [
    # contributed
    "django.contrib.admin",
    "django.contrib.auth",
 "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    # third-party
    # ...
    # local
    "myproject.apps.core",
    "myproject.apps.categories",
    "myproject.apps.ideas",
]
```

再次确保您已经为模型 mixin 创建了`myproject.apps.core`应用程序。

# 如何做...

要创建和使用通用关系的 mixin，请按照以下步骤进行：

1.  在文本编辑器中打开核心包中的`models.py`文件，并在那里插入以下内容：

```py
# myproject/apps/core/models.py from django.db import models
from django.utils.translation import gettext_lazy as _
from django.contrib.contenttypes.models import ContentType
from django.contrib.contenttypes.fields import GenericForeignKey
from django.core.exceptions import FieldError

def object_relation_base_factory(
        prefix=None,
        prefix_verbose=None,
        add_related_name=False,
        limit_content_type_choices_to=None,
        is_required=False):
    """
    Returns a mixin class for generic foreign keys using
    "Content type - object ID" with dynamic field names.
    This function is just a class generator.

    Parameters:
    prefix:           a prefix, which is added in front of
                      the fields
    prefix_verbose:   a verbose name of the prefix, used to
                      generate a title for the field column
                      of the content object in the Admin
    add_related_name: a boolean value indicating, that a
                      related name for the generated content
                      type foreign key should be added. This
                      value should be true, if you use more
                      than one ObjectRelationBase in your
                      model.

    The model fields are created using this naming scheme:
        <<prefix>>_content_type
        <<prefix>>_object_id
        <<prefix>>_content_object
    """
    p = ""
    if prefix:
        p = f"{prefix}_"

    prefix_verbose = prefix_verbose or _("Related object")
    limit_content_type_choices_to = limit_content_type_choices_to 
     or {}

    content_type_field = f"{p}content_type"
    object_id_field = f"{p}object_id"
    content_object_field = f"{p}content_object"

    class TheClass(models.Model):
 class Meta:
 abstract = True

    if add_related_name:
        if not prefix:
            raise FieldError("if add_related_name is set to "
                             "True, a prefix must be given")
        related_name = prefix
    else:
        related_name = None

    optional = not is_required

    ct_verbose_name = _(f"{prefix_verbose}'s type (model)")

    content_type = models.ForeignKey(
        ContentType,
        verbose_name=ct_verbose_name,
        related_name=related_name,
        blank=optional,
        null=optional,
        help_text=_("Please select the type (model) "
                    "for the relation, you want to build."),
        limit_choices_to=limit_content_type_choices_to,
        on_delete=models.CASCADE)

    fk_verbose_name = prefix_verbose

    object_id = models.CharField(
        fk_verbose_name,
        blank=optional,
        null=False,
        help_text=_("Please enter the ID of the related object."),
        max_length=255,
        default="")  # for migrations

    content_object = GenericForeignKey(
        ct_field=content_type_field,
        fk_field=object_id_field)

    TheClass.add_to_class(content_type_field, content_type)
    TheClass.add_to_class(object_id_field, object_id)
    TheClass.add_to_class(content_object_field, content_object)

    return TheClass
```

1.  以下代码片段是如何在您的应用中使用两个通用关系的示例（将此代码放在`ideas/models.py`中）：

```py
# myproject/apps/ideas/models.py from django.db import models
from django.utils.translation import gettext_lazy as _

from myproject.apps.core.models import (
    object_relation_base_factory as generic_relation,
)

FavoriteObjectBase = generic_relation(
    is_required=True,
)

OwnerBase = generic_relation(
    prefix="owner",
    prefix_verbose=_("Owner"),
    is_required=True,
    add_related_name=True,
    limit_content_type_choices_to={
        "model__in": (
            "user",
            "group",
        )
    }
)

class Like(FavoriteObjectBase, OwnerBase):
    class Meta:
        verbose_name = _("Like")
        verbose_name_plural = _("Likes")

    def __str__(self):
        return _("{owner} likes {object}").format(
            owner=self.owner_content_object,
            object=self.content_object
        )
```

# 它是如何工作的...

正如您所看到的，这个片段比之前的更复杂。

`object_relation_base_factory`函数，我们已经给它起了别名`generic_relation`，在我们的导入中，它本身不是一个 mixin；它是一个生成模型 mixin 的函数-也就是说，一个抽象模型类来扩展。动态创建的 mixin 添加了`content_type`和`object_id`字段以及指向相关实例的`content_object`通用外键。

为什么我们不能只定义一个具有这三个属性的简单模型 mixin？动态生成的抽象类允许我们为每个字段名称添加前缀；因此，我们可以在同一个模型中拥有多个通用关系。例如，之前展示的`Like`模型将为喜欢的对象添加`content_type`、`object_id`和`content_object`字段，以及为喜欢对象的用户或组添加`owner_content_type`、`owner_object_id`和`owner_content_object`。

`object_relation_base_factory`函数，我们已经给它起了别名

对于`generic_relation`的简称，通过`limit_content_type_choices_to`参数添加了限制内容类型选择的可能性。前面的示例将`owner_content_type`的选择限制为`User`和`Group`模型的内容类型。

# 另请参阅

+   *创建一个具有 URL 相关方法的模型 mixin*配方

+   处理创建和修改日期的模型混合的配方

+   处理处理元标签的模型混合的配方

+   在第四章的*实现“喜欢”小部件*配方中，模板和 JavaScript

# 处理多语言字段

Django 使用国际化机制来翻译代码和模板中的冗长字符串。但是开发人员可以决定如何在模型中实现多语言内容。我们将向您展示如何直接在项目中实现多语言模型的几种方法。第一种方法是在模型中使用特定语言字段。

这种方法具有以下特点：

+   在模型中定义多语言字段很简单。

+   在数据库查询中使用多语言字段很简单。

+   您可以使用贡献的管理来编辑具有多语言字段的模型，无需额外修改。

+   如果需要，您可以轻松地在同一模板中显示对象的所有翻译。

+   在设置中更改语言数量后，您需要为所有多语言模型创建和运行迁移。

# 准备工作

您是否已经创建了本章前面配方中使用的`myproject.apps.core`包？现在，您需要在`core`应用程序中创建一个新的`model_fields.py`文件，用于自定义模型字段。

# 如何做...

执行以下步骤来定义多语言字符字段和多语言文本字段：

1.  打开`model_fields.py`文件，并创建基本多语言字段，如下所示：

```py
# myproject/apps/core/model_fields.py from django.conf import settings
from django.db import models
from django.utils.translation import get_language
from django.utils import translation

class MultilingualField(models.Field):
    SUPPORTED_FIELD_TYPES = [models.CharField, models.TextField]

    def __init__(self, verbose_name=None, **kwargs):
        self.localized_field_model = None
        for model in MultilingualField.SUPPORTED_FIELD_TYPES:
            if issubclass(self.__class__, model):
                self.localized_field_model = model
        self._blank = kwargs.get("blank", False)
        self._editable = kwargs.get("editable", True)
        super().__init__(verbose_name, **kwargs)

    @staticmethod
    def localized_field_name(name, lang_code):
        lang_code_safe = lang_code.replace("-", "_")
        return f"{name}_{lang_code_safe}"

    def get_localized_field(self, lang_code, lang_name):
        _blank = (self._blank
                  if lang_code == settings.LANGUAGE_CODE
                  else True)
        localized_field = self.localized_field_model(
            f"{self.verbose_name} ({lang_name})",
            name=self.name,
            primary_key=self.primary_key,
            max_length=self.max_length,
            unique=self.unique,
            blank=_blank,
            null=False, # we ignore the null argument!
            db_index=self.db_index,
            default=self.default or "",
            editable=self._editable,
            serialize=self.serialize,
            choices=self.choices,
            help_text=self.help_text,
            db_column=None,
            db_tablespace=self.db_tablespace)
        return localized_field

    def contribute_to_class(self, cls, name,
                            private_only=False,
                            virtual_only=False):
        def translated_value(self):
            language = get_language()
            val = self.__dict__.get(
                MultilingualField.localized_field_name(
                        name, language))
            if not val:
                val = self.__dict__.get(
                    MultilingualField.localized_field_name(
                            name, settings.LANGUAGE_CODE))
            return val

        # generate language-specific fields dynamically
        if not cls._meta.abstract:
            if self.localized_field_model:
                for lang_code, lang_name in settings.LANGUAGES:
                    localized_field = self.get_localized_field(
                        lang_code, lang_name)
                    localized_field.contribute_to_class(
                            cls,
                            MultilingualField.localized_field_name(
                                    name, lang_code))

                setattr(cls, name, property(translated_value))
            else:
                super().contribute_to_class(
                    cls, name, private_only, virtual_only)
```

1.  在同一文件中，为字符和文本字段表单子类化基本字段，如下所示：

```py
class MultilingualCharField(models.CharField, MultilingualField):
    pass

class MultilingualTextField(models.TextField, MultilingualField):
    pass
```

1.  在核心应用中创建一个`admin.py`文件，并添加以下内容：

```py
# myproject/apps/core/admin.py
from django.conf import settings

def get_multilingual_field_names(field_name):
    lang_code_underscored = settings.LANGUAGE_CODE.replace("-", 
     "_")
    field_names = [f"{field_name}_{lang_code_underscored}"]
    for lang_code, lang_name in settings.LANGUAGES:
        if lang_code != settings.LANGUAGE_CODE:
            lang_code_underscored = lang_code.replace("-", "_")
            field_names.append(
                f"{field_name}_{lang_code_underscored}"
            )
    return field_names
```

现在，我们将考虑如何在应用程序中使用多语言字段的示例，如下所示：

1.  首先，在项目的设置中设置多种语言。假设我们的网站将支持欧盟所有官方语言，英语是默认语言：

```py
# myproject/settings/_base.py LANGUAGE_CODE = "en"

# All official languages of European Union
LANGUAGES = [
    ("bg", "Bulgarian"),    ("hr", "Croatian"),
    ("cs", "Czech"),        ("da", "Danish"),
    ("nl", "Dutch"),        ("en", "English"),
    ("et", "Estonian"),     ("fi", "Finnish"),
    ("fr", "French"),       ("de", "German"),
    ("el", "Greek"),        ("hu", "Hungarian"),
    ("ga", "Irish"),        ("it", "Italian"),
    ("lv", "Latvian"),      ("lt", "Lithuanian"),
    ("mt", "Maltese"),      ("pl", "Polish"),
    ("pt", "Portuguese"),   ("ro", "Romanian"),
    ("sk", "Slovak"),       ("sl", "Slovene"),
    ("es", "Spanish"),      ("sv", "Swedish"),
]
```

1.  然后，打开`myproject.apps.ideas`应用的`models.py`文件，并为`Idea`模型创建多语言字段，如下所示：

```py
# myproject/apps/ideas/models.py
from django.db import models
from django.utils.translation import gettext_lazy as _

from myproject.apps.core.model_fields import (
    MultilingualCharField,
    MultilingualTextField,
)

class Idea(models.Model):
    title = MultilingualCharField(
        _("Title"),
        max_length=200,
    )
    content = MultilingualTextField(
        _("Content"),
    )

    class Meta:
        verbose_name = _("Idea")
        verbose_name_plural = _("Ideas")

    def __str__(self):
        return self.title
```

1.  为`ideas`应用创建一个`admin.py`文件：

```py
# myproject/apps/ideas/admin.py
from django.contrib import admin
from django.utils.translation import gettext_lazy as _

from myproject.apps.core.admin import get_multilingual_field_names

from .models import Idea

@admin.register(Idea)
class IdeaAdmin(admin.ModelAdmin):
    fieldsets = [
        (_("Title and Content"), {
            "fields": get_multilingual_field_names("title") +
                      get_multilingual_field_names("content")
        }),
    ]
```

# 它是如何工作的...

`Idea`的示例将生成一个类似以下的模型：

```py
class Idea(models.Model):
    title_bg = models.CharField(
        _("Title (Bulgarian)"),
        max_length=200,
    )
    title_hr = models.CharField(
        _("Title (Croatian)"),
        max_length=200,
    )
    # titles for other languages…
    title_sv = models.CharField(
        _("Title (Swedish)"),
        max_length=200,
    )

    content_bg = MultilingualTextField(
        _("Content (Bulgarian)"),
    )
    content_hr = MultilingualTextField(
        _("Content (Croatian)"),
    )
    # content for other languages…
    content_sv = MultilingualTextField(
        _("Content (Swedish)"),
    )

    class Meta:
        verbose_name = _("Idea")
        verbose_name_plural = _("Ideas")

    def __str__(self):
        return self.title
```

如果有带有破折号的语言代码，比如瑞士德语的“de-ch”，那么这些语言的字段将被下划线替换，比如`title_de_ch`和`content_de_ch`。

除了生成的特定语言字段之外，还将有两个属性 - `title` 和 `content` - 它们将返回当前活动语言中对应的字段。如果没有可用的本地化字段内容，它们将回退到默认语言。

`MultilingualCharField`和`MultilingualTextField`字段将根据您的`LANGUAGES`设置动态地处理模型字段。它们将覆盖`contribute_to_class()`方法，该方法在 Django 框架创建模型类时使用。多语言字段动态地为项目的每种语言添加字符或文本字段。您需要创建数据库迁移以在数据库中添加适当的字段。此外，创建属性以返回当前活动语言的翻译值或默认情况下的主语言。

在管理中，`get_multilingual_field_names()` 将返回一个特定语言字段名称的列表，从`LANGUAGES`设置中的一个默认语言开始，然后继续使用其他语言。

以下是您可能在模板和视图中使用多语言字段的几个示例。

如果在模板中有以下代码，它将显示当前活动语言的文本，比如立陶宛语，如果翻译不存在，将回退到英语：

```py
<h1>{{ idea.title }}</h1>
<div>{{ idea.content|urlize|linebreaks }}</div>
```

如果您希望将您的`QuerySet`按翻译后的标题排序，可以定义如下：

```py
>>> lang_code = input("Enter language code: ")
>>> lang_code_underscored = lang_code.replace("-", "_")
>>> qs = Idea.objects.order_by(f"title_{lang_code_underscored}")
```

# 另请参阅

+   *使用模型翻译表*配方

+   *使用迁移*配方

+   第六章，模型管理

# 使用模型翻译表

在处理数据库中的多语言内容时，第二种方法涉及为每个多语言模型使用模型翻译表。

这种方法的特点如下：

+   您可以使用贡献的管理来编辑翻译，就像内联一样。

+   更改设置中的语言数量后，不需要进行迁移或其他进一步的操作。

+   您可以轻松地在模板中显示当前语言的翻译，但在同一页上显示特定语言的多个翻译会更困难。

+   您必须了解并使用本配方中描述的特定模式来创建模型翻译。

+   使用这种方法进行数据库查询并不那么简单，但是，正如您将看到的，这仍然是可能的。

# 准备工作

我们将从`myprojects.apps.core`应用程序开始。

# 如何做...

执行以下步骤来准备多语言模型：

1.  在`core`应用程序中，创建带有以下内容的`model_fields.py`：

```py
# myproject/apps/core/model_fields.py
from django.conf import settings
from django.utils.translation import get_language
from django.utils import translation

class TranslatedField(object):
    def __init__(self, field_name):
        self.field_name = field_name

    def __get__(self, instance, owner):
        lang_code = translation.get_language()
        if lang_code == settings.LANGUAGE_CODE:
            # The fields of the default language are in the main
               model
            return getattr(instance, self.field_name)
        else:
            # The fields of the other languages are in the
               translation
            # model, but falls back to the main model
            translations = instance.translations.filter(
                language=lang_code,
            ).first() or instance
            return getattr(translations, self.field_name)
```

1.  将以下内容添加到`core`应用程序的`admin.py`文件中：

```py
# myproject/apps/core/admin.py
from django import forms
from django.conf import settings
from django.utils.translation import gettext_lazy as _

class LanguageChoicesForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        LANGUAGES_EXCEPT_THE_DEFAULT = [
            (lang_code, lang_name)
            for lang_code, lang_name in settings.LANGUAGES
            if lang_code != settings.LANGUAGE_CODE
        ]
        super().__init__(*args, **kwargs)
        self.fields["language"] = forms.ChoiceField(
            label=_("Language"),
            choices=LANGUAGES_EXCEPT_THE_DEFAULT, 
            required=True,
        )
```

现在让我们实现多语言模型：

1.  首先，在项目的设置中设置多种语言。假设我们的网站将支持欧盟所有官方语言，英语是默认语言：

```py
# myproject/settings/_base.py
LANGUAGE_CODE = "en"

# All official languages of European Union
LANGUAGES = [
    ("bg", "Bulgarian"),    ("hr", "Croatian"),
    ("cs", "Czech"),        ("da", "Danish"),
    ("nl", "Dutch"),        ("en", "English"),
    ("et", "Estonian"),     ("fi", "Finnish"),
    ("fr", "French"),       ("de", "German"),
    ("el", "Greek"),        ("hu", "Hungarian"),
    ("ga", "Irish"),        ("it", "Italian"),
    ("lv", "Latvian"),      ("lt", "Lithuanian"),
    ("mt", "Maltese"),      ("pl", "Polish"),
    ("pt", "Portuguese"),   ("ro", "Romanian"),
    ("sk", "Slovak"),       ("sl", "Slovene"),
    ("es", "Spanish"),      ("sv", "Swedish"),
]
```

1.  然后，让我们创建`Idea`和`IdeaTranslations`模型：

```py
# myproject/apps/ideas/models.py
from django.db import models
from django.conf import settings
from django.utils.translation import gettext_lazy as _

from myproject.apps.core.model_fields import TranslatedField

class Idea(models.Model):
    title = models.CharField(
        _("Title"),
        max_length=200,
    )
    content = models.TextField(
        _("Content"),
    )
    translated_title = TranslatedField("title")
    translated_content = TranslatedField("content")

    class Meta:
        verbose_name = _("Idea")
        verbose_name_plural = _("Ideas")

    def __str__(self):
        return self.title

class IdeaTranslations(models.Model):
    idea = models.ForeignKey(
        Idea,
        verbose_name=_("Idea"),
        on_delete=models.CASCADE,
        related_name="translations",
    )
    language = models.CharField(_("Language"), max_length=7)

    title = models.CharField(
        _("Title"),
        max_length=200,
    )
    content = models.TextField(
        _("Content"),
    )

    class Meta:
        verbose_name = _("Idea Translations")
        verbose_name_plural = _("Idea Translations")
        ordering = ["language"]
        unique_together = [["idea", "language"]]

    def __str__(self):
        return self.title
```

1.  最后，创建`ideas`应用程序的`admin.py`如下：

```py
# myproject/apps/ideas/admin.py
from django.contrib import admin
from django.utils.translation import gettext_lazy as _

from myproject.apps.core.admin import LanguageChoicesForm

from .models import Idea, IdeaTranslations

class IdeaTranslationsForm(LanguageChoicesForm):
    class Meta:
        model = IdeaTranslations
        fields = "__all__"

class IdeaTranslationsInline(admin.StackedInline):
    form = IdeaTranslationsForm
    model = IdeaTranslations
    extra = 0

@admin.register(Idea)
class IdeaAdmin(admin.ModelAdmin):
    inlines = [IdeaTranslationsInline]

    fieldsets = [
        (_("Title and Content"), {
            "fields": ["title", "content"]
        }),
    ]
```

# 工作原理...

我们将默认语言的特定于语言的字段保留在`Idea`模型本身中。每种语言的翻译都在`IdeaTranslations`模型中，该模型将作为内联翻译列在管理中列出。`IdeaTranslations`模型没有模型的语言选择，这是有原因的——我们不希望每次添加新语言或删除某种语言时都创建迁移。相反，语言选择设置在管理表单中，还要确保默认语言被跳过或在列表中不可选择。语言选择使用`LanguageChoicesForm`类进行限制。

要获取当前语言中的特定字段，您将使用定义为`TranslatedField`的字段。在模板中，看起来像这样：

```py
<h1>{{ idea.translated_title }}</h1>
<div>{{ idea.translated_content|urlize|linebreaks }}</div>
```

要按特定语言的翻译标题对项目进行排序，您将使用`annotate()`方法如下：

```py
>>> from django.conf import settings
>>> from django.db import models
>>> lang_code = input("Enter language code: ")

>>> if lang_code == settings.LANGUAGE_CODE:
...     qs = Idea.objects.annotate(
...         title_translation=models.F("title"),
...         content_translation=models.F("content"),
...     )
... else:
...     qs = Idea.objects.filter(
...         translations__language=lang_code,
...     ).annotate(
...         title_translation=models.F("translations__title"),
...         content_translation=models.F("translations__content"),
...     )

>>> qs = qs.order_by("title_translation")

>>> for idea in qs:
...     print(idea.title_translation)
```

在这个例子中，我们在 Django shell 中提示输入语言代码。如果语言是默认语言，我们将`title`和`content`存储为`Idea`模型的`title_translation`和`content_translation`。如果选择了其他语言，我们将从选择的语言中读取`title`和`content`作为`IdeaTranslations`模型的`title_translation`和`content_translation`。

之后，我们可以通过`title_translation`或`content_translation`筛选或排序`QuerySet`。

# 另请参阅

+   *处理多语言字段*配方

+   第六章，模型管理

# 避免循环依赖

在开发 Django 模型时，非常重要的是要避免循环依赖，特别是在`models.py`文件中。循环依赖是指不同 Python 模块之间的相互导入。您不应该从不同的`models.py`文件中交叉导入，因为这会导致严重的稳定性问题。相反，如果存在相互依赖，您应该使用本配方中描述的操作。

# 准备工作

让我们使用`categories`和`ideas`应用程序来说明如何处理交叉依赖。

# 如何做...

在处理使用其他应用程序模型的模型时，请遵循以下实践：

1.  对于来自其他应用程序的模型的外键和多对多关系，请使用`"<app_label>.<model>"`声明，而不是导入模型。在 Django 中，这适用于`ForeignKey`，`OneToOneField`和`ManyToManyField`，例如：

```py
# myproject/apps/ideas/models.py from django.db import models
from django.conf import settings
from django.utils.translation import gettext_lazy as _

class Idea(models.Model):
    author = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        verbose_name=_("Author"),
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
    )
    category = models.ForeignKey(
        "categories.Category",
        verbose_name=_("Category"),
        blank=True,
        null=True,
        on_delete=models.SET_NULL,
    )
    # other fields, attributes, properties and methods…
```

这里，`settings.AUTH_USER_MODEL`是一个具有值如`"auth.User"`的设置：

1.  如果您需要在方法中访问另一个应用程序的模型，请在方法内部导入该模型，而不是在模块级别导入，例如：

```py
# myproject/apps/categories/models.py
from django.db import models
from django.utils.translation import gettext_lazy as _

class Category(models.Model):
    # fields, attributes, properties, and methods…

    def get_ideas_without_this_category(self):
        from myproject.apps.ideas.models import Idea
        return Idea.objects.exclude(category=self)
```

1.  如果您使用模型继承，例如用于模型混合，将基类保留在单独的应用程序中，并将它们放在`INSTALLED_APPS`中将使用它们的其他应用程序之前，如下所示：

```py
# myproject/settings/_base.py

INSTALLED_APPS = [
    # contributed
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    # third-party
    # ...
    # local
    "myproject.apps.core",
    "myproject.apps.categories",
    "myproject.apps.ideas",
]
```

在这里，`ideas`应用程序将如下使用`core`应用程序的模型混合：

```py
# myproject/apps/ideas/models.py
from django.db import models
from django.conf import settings
from django.utils.translation import gettext_lazy as _

from myproject.apps.core.models import (
 CreationModificationDateBase,
 MetaTagsBase,
 UrlBase,
)

class Idea(CreationModificationDateBase, MetaTagsBase, UrlBase):
    # fields, attributes, properties, and methods…
```

# 另请参阅

+   第一章*中的*为开发、测试、暂存和生产环境配置设置*示例，Django 3.0 入门

+   第一章**中的*尊重 Python 文件的导入顺序*示例，Django 3.0 入门**

+   *使用模型混合*示例

+   *将外键更改为多对多字段*示例

# 添加数据库约束

为了更好地保证数据库的完整性，通常会定义数据库约束，告诉某些字段绑定到其他数据库表的字段，使某些字段唯一或非空。对于高级数据库约束，例如使字段在满足条件时唯一或为某些字段的值设置特定条件，Django 有特殊的类：`UniqueConstraint`和`CheckConstraint`。在这个示例中，您将看到如何使用它们的实际示例。

# 准备工作

让我们从`ideas`应用程序和将至少具有`title`和`author`字段的`Idea`模型开始。

# 如何做...

在`Idea`模型的`Meta`类中设置数据库约束如下：

```py
# myproject/apps/ideas/models.py
from django.db import models
from django.utils.translation import gettext_lazy as _

class Idea(models.Model):
    author = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        verbose_name=_("Author"),
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        related_name="authored_ideas",
    )
    title = models.CharField(
        _("Title"),
        max_length=200,
    )

    class Meta:
        verbose_name = _("Idea")
        verbose_name_plural = _("Ideas")
        constraints = [
 models.UniqueConstraint(
 fields=["title"],
 condition=~models.Q(author=None),
 name="unique_titles_for_each_author",
 ),
 models.CheckConstraint(
 check=models.Q(
 title__iregex=r"^\S.*\S$"
 # starts with non-whitespace,
 # ends with non-whitespace,
 # anything in the middle
 ),
 name="title_has_no_leading_and_trailing_whitespaces",
 )
 ]
```

# 它是如何工作的...

我们在数据库中定义了两个约束。

第一个`UniqueConstraint`告诉标题对于每个作者是唯一的。如果作者未设置，则标题可以重复。要检查作者是否已设置，我们使用否定查找：`~models.Q(author=None)`。请注意，在 Django 中，查找的`~`运算符等同于 QuerySet 的`exclude()`方法，因此这些 QuerySets 是等价的：

```py
ideas_with_authors = Idea.objects.exclude(author=None)
ideas_with_authors2 = Idea.objects.filter(~models.Q(author=None))
```

第二个约束条件`CheckConstraint`检查标题是否不以空格开头和结尾。为此，我们使用正则表达式查找。

# 还有更多...

数据库约束不会影响表单验证。如果保存条目到数据库时任何数据不符合其条件，它们只会引发`django.db.utils.IntegrityError`。

如果您希望在表单中验证数据，您必须自己实现验证，例如在模型的`clean()`方法中。对于`Idea`模型，这将如下所示：

```py
# myproject/apps/ideas/models.py from django.db import models
from django.conf import settings
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

class Idea(models.Model):
    author = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        verbose_name=_("Author"),
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        related_name="authored_ideas2",
    )
    title = models.CharField(
        _("Title"),
        max_length=200,
    )

    # other fields and attributes…

    class Meta:
        verbose_name = _("Idea")
        verbose_name_plural = _("Ideas")
        constraints = [
            models.UniqueConstraint(
                fields=["title"],
                condition=~models.Q(author=None),
                name="unique_titles_for_each_author2",
            ),
            models.CheckConstraint(
                check=models.Q(
                    title__iregex=r"^\S.*\S$"
                    # starts with non-whitespace,
                    # ends with non-whitespace,
                    # anything in the middle
                ),
                name="title_has_no_leading_and_trailing_whitespaces2",
            )
        ]

 def clean(self):
 import re
 if self.author and Idea.objects.exclude(pk=self.pk).filter(
 author=self.author,
 title=self.title,
 ).exists():
 raise ValidationError(
 _("Each idea of the same user should have a unique title.")
 )
 if not re.match(r"^\S.*\S$", self.title):
 raise ValidationError(
 _("The title cannot start or end with a whitespace.")
 )

    # other properties and methods…
```

# 另请参阅

+   第三章*中的*表单和视图*

+   第十章*中的*使用数据库查询表达式*示例，花里胡哨

# 使用迁移

在敏捷软件开发中，项目的要求会随着时间的推移而不断更新和更新。随着开发的进行，您将不得不沿途执行数据库架构更改。使用 Django 迁移，您不必手动更改数据库表和字段，因为大部分工作都是自动完成的，使用命令行界面。

# 准备工作

在命令行工具中激活您的虚拟环境，并将活动目录更改为您的项目目录。

# 如何做...

要创建数据库迁移，请查看以下步骤：

1.  当您在新的`categories`或`ideas`应用程序中创建模型时，您必须创建一个初始迁移，该迁移将为您的应用程序创建数据库表。这可以通过使用以下命令来完成：

```py
(env)$ python manage.py makemigrations ideas
```

1.  第一次要为项目创建所有表时，请运行以下命令：

```py
(env)$ python manage.py migrate
```

当您想要执行所有应用程序的新迁移时，请运行此命令。

1.  如果要执行特定应用程序的迁移，请运行以下命令：

```py
(env)$ python manage.py migrate ideas
```

1.  如果对数据库模式进行了一些更改，则必须为该模式创建一个迁移。例如，如果我们向 idea 模型添加一个新的 subtitle 字段，可以使用以下命令创建迁移：

```py
(env)$ python manage.py makemigrations --name=subtitle_added ideas
```

然而，`--name=subtitle_added`字段可以被跳过，因为在大多数情况下，Django 会生成相当自解释的默认名称。

1.  有时，您可能需要批量添加或更改现有模式中的数据，这可以通过数据迁移而不是模式迁移来完成。要创建修改数据库表中数据的数据迁移，可以使用以下命令：

```py
(env)$ python manage.py makemigrations --name=populate_subtitle \
> --empty ideas
```

`--empty`参数告诉 Django 创建一个骨架数据迁移，您必须在应用之前修改它以执行必要的数据操作。对于数据迁移，建议设置名称。

1.  要列出所有可用的已应用和未应用的迁移，请运行以下命令：

```py
(env)$ python manage.py showmigrations
```

已应用的迁移将以[X]前缀列出。未应用的迁移将以[ ]前缀列出。

1.  要列出特定应用程序的所有可用迁移，请运行相同的命令，但传递应用程序名称，如下所示：

```py
(env)$ python manage.py showmigrations ideas
```

# 它是如何工作的...

Django 迁移是数据库迁移机制的指令文件。这些指令文件告诉我们要创建或删除哪些数据库表，要添加或删除哪些字段，以及要插入、更新或删除哪些数据。它们还定义了哪些迁移依赖于其他迁移。

Django 有两种类型的迁移。一种是模式迁移，另一种是数据迁移。当您添加新模型、添加或删除字段时，应创建模式迁移。当您想要向数据库填充一些值或大量删除数据库中的值时，应使用数据迁移。数据迁移应该通过命令行工具中的命令创建，然后在迁移文件中编码。

每个应用程序的迁移都保存在它们的`migrations`目录中。第一个迁移通常称为`0001_initial.py`，在我们的示例应用程序中，其他迁移将被称为`0002_subtitle_added.py`和`0003_populate_subtitle.py`。每个迁移都有一个自动递增的数字前缀。对于执行的每个迁移，都会在`django_migrations`数据库表中保存一个条目。

可以通过指定要迁移的迁移编号来来回迁移，如下命令所示：

```py
(env)$ python manage.py migrate ideas 0002

```

要取消应用程序的所有迁移，包括初始迁移，请运行以下命令：

```py
(env)$ python manage.py migrate ideas zero
```

取消迁移需要每个迁移都有前向和后向操作。理想情况下，后向操作应该恢复前向操作所做的更改。然而，在某些情况下，这样的更改是无法恢复的，例如当前向操作从模式中删除了一个列时，因为它将破坏数据。在这种情况下，后向操作可能会恢复模式，但数据将永远丢失，或者根本没有后向操作。

在测试了前向和后向迁移过程并确保它们在其他开发和公共网站环境中能够正常工作之前，不要将您的迁移提交到版本控制中。

# 还有更多...

在官方的*How To*指南中了解更多关于编写数据库迁移的信息，网址为[`docs.djangoproject.com/en/2.2/howto/writing-migrations/`](https://docs.djangoproject.com/en/2.2/howto/writing-migrations/)​。

# 另请参阅

+   第一章*中的*使用虚拟环境*配方

+   在第一章*中的*使用 Django、Gunicorn、Nginx 和 PostgreSQL 的 Docker 容器*食谱，使用 Django 3.0 入门

+   在第一章*中的*使用 pip 处理项目依赖关系*食谱，使用 Django 3.0 入门

+   在第一章*中的*在您的项目中包含外部依赖项*食谱，使用 Django 3.0 入门

+   *将外键更改为多对多字段*食谱

# 将外键更改为多对多字段

这个食谱是如何将多对一关系更改为多对多关系的实际示例，同时保留已经存在的数据。在这种情况下，我们将同时使用模式迁移和数据迁移。

# 准备就绪

假设您有`Idea`模型，其中有一个指向`Category`模型的外键。

1.  让我们在`categories`应用程序中定义`Category`模型，如下所示：

```py
# myproject/apps/categories/models.py
from django.db import models
from django.utils.translation import gettext_lazy as _

from myproject.apps.core.model_fields import MultilingualCharField

class Category(models.Model):
    title = MultilingualCharField(
        _("Title"),
        max_length=200,
    )

    class Meta:
        verbose_name = _("Category")
        verbose_name_plural = _("Categories")

    def __str__(self):
        return self.title
```

1.  让我们在`ideas`应用程序中定义`Idea`模型，如下所示：

```py
# myproject/apps/ideas/models.py from django.db import models
from django.conf import settings
from django.utils.translation import gettext_lazy as _

from myproject.apps.core.model_fields import (
    MultilingualCharField,
    MultilingualTextField,
)

class Idea(models.Model):
    title = MultilingualCharField(
        _("Title"),
        max_length=200,
    )
    content = MultilingualTextField(
        _("Content"),
    )
 category = models.ForeignKey(
        "categories.Category",
        verbose_name=_("Category"),
        blank=True,
        null=True,
        on_delete=models.SET_NULL,
        related_name="category_ideas",
    ) 
    class Meta:
        verbose_name = _("Idea")
        verbose_name_plural = _("Ideas")

    def __str__(self):
        return self.title
```

1.  通过使用以下命令创建和执行初始迁移：

```py
(env)$ python manage.py makemigrations categories
(env)$ python manage.py makemigrations ideas
(env)$ python manage.py migrate
```

# 如何做...

以下步骤将向您展示如何从外键关系切换到多对多关系，同时保留已经存在的数据：

1.  添加一个名为`categories`的新多对多字段，如下所示：

```py
# myproject/apps/ideas/models.py from django.db import models
from django.conf import settings
from django.utils.translation import gettext_lazy as _

from myproject.apps.core.model_fields import (
    MultilingualCharField,
    MultilingualTextField,
)

class Idea(models.Model):
    title = MultilingualCharField(
        _("Title"),
        max_length=200,
    )
    content = MultilingualTextField(
        _("Content"),
    )
    category = models.ForeignKey(
        "categories.Category",
        verbose_name=_("Category"),
        blank=True,
        null=True,
        on_delete=models.SET_NULL,
        related_name="category_ideas",
    )
    categories = models.ManyToManyField(
 "categories.Category",
 verbose_name=_("Categories"),
 blank=True,
 related_name="ideas",
 )

    class Meta:
        verbose_name = _("Idea")
        verbose_name_plural = _("Ideas")

    def __str__(self):
        return self.title
```

1.  创建并运行模式迁移，以向数据库添加新的关系，如下面的代码片段所示：

```py
(env)$ python manage.py makemigrations ideas
(env)$ python manage.py migrate ideas
```

1.  创建一个数据迁移，将类别从外键复制到多对多字段，如下所示：

```py
(env)$ python manage.py makemigrations --empty \
> --name=copy_categories ideas
```

1.  打开新创建的迁移文件（`0003_copy_categories.py`），并定义前向迁移指令，如下面的代码片段所示：

```py
# myproject/apps/ideas/migrations/0003_copy_categories.py from django.db import migrations

def copy_categories(apps, schema_editor):
 Idea = apps.get_model("ideas", "Idea")
 for idea in Idea.objects.all():
 if idea.category:
 idea.categories.add(idea.category)

class Migration(migrations.Migration):

    dependencies = [
        ('ideas', '0002_idea_categories'),
    ]

    operations = [
        migrations.RunPython(copy_categories),
    ]
```

1.  运行新的数据迁移，如下所示：

```py
(env)$ python manage.py migrate ideas
```

1.  在`models.py`文件中删除外键`category`字段，只留下新的`categories`多对多字段，如下所示：

```py
# myproject/apps/ideas/models.py from django.db import models
from django.conf import settings
from django.utils.translation import gettext_lazy as _

from myproject.apps.core.model_fields import (
    MultilingualCharField,
    MultilingualTextField,
)

class Idea(models.Model):
    title = MultilingualCharField(
        _("Title"),
        max_length=200,
    )
    content = MultilingualTextField(
        _("Content"),
    )

    categories = models.ManyToManyField(
 "categories.Category",
 verbose_name=_("Categories"),
 blank=True,
 related_name="ideas",
 )

    class Meta:
        verbose_name = _("Idea")
        verbose_name_plural = _("Ideas")

    def __str__(self):
        return self.title
```

1.  创建并运行模式迁移，以从数据库表中删除`Categories`字段，如下所示：

```py
(env)$ python manage.py makemigrations ideas
(env)$ python manage.py migrate ideas
```

# 它是如何工作的...

首先，我们向`Idea`模型添加一个新的多对多字段，并生成一个迁移以相应地更新数据库。然后，我们创建一个数据迁移，将现有关系从外键`category`复制到新的多对多`categories`。最后，我们从模型中删除外键字段，并再次更新数据库。

# 还有更多...

我们的数据迁移目前只包括前向操作，将外键中的类别复制到多对多字段中

将类别键作为新类别关系中的第一个相关项目。虽然我们在这里没有详细说明，在实际情况下最好也包括反向操作。这可以通过将第一个相关项目复制回`category`外键来实现。不幸的是，任何具有多个类别的`Idea`对象都将丢失额外数据。

# 另请参阅

+   *使用迁移*食谱

+   *处理多语言字段*食谱

+   *使用模型翻译表*食谱

+   *避免循环依赖*食谱
