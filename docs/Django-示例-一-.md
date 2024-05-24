# Django 示例（一）

> 译者：[夜夜月](https://www.jianshu.com/u/390b6edb26a8)
> 
> 来源：<https://www.jianshu.com/p/05810d38f93a>

# 第一章：创建一个博客应用

在本书中，你将学习如何创建完整的，可用于生产环境的 Django 项目。如果你还没有安装 Django，你将在本章的第一部分学习如何安装。本章将会涉及如何使用 Django 创建一个简单的博客应用。本章的目的是对框架如何工作有一个基本概念，理解不同组件之间如何交互，并教你使用基本功能创建 Django 项目。本章会引导你创建一个完整项目，但不会阐述所有细节。不同框架组件的细节会在本书接下来的章节中介绍。

本章将会涉及以下知识点：

- 安装 Django，并创建第一个项目
- 设计模型（model），并生成模型迁移（model migration）
- 为模型创建一个管理站点
- 使用`QuerySet`和管理器（manager）
- 创建视图（view），模板（template）和 URL
- 为列表视图中添加分页
- 使用基于类的视图

## 1.1 安装 Django

如果你已经安装了 Django，可以略过本节，直接跳到`创建第一个项目`。Django 是一个 Python 包，可以在任何 Python 环境中安装。如果你还没有安装 Django，这是为本地开发安装 Django 的快速指南。

Django 可以在 Python 2.7 或 3 版本中工作。本书的例子中，我们使用 Python 3。如果你使用 Linux 或 Mac OS X，你可能已经安装了 Python。如果不确定是否安装，你可以在终端里输入`python`。如果看到类似下面的输出，表示已经安装了 Python：

```py
Python 3.5.2 (v3.5.2:4def2a2901a5, Jun 26 2016, 10:47:25)
[GCC 4.2.1 (Apple Inc. build 5666) (dot 3)] on darwin
Type "help", "copyright", "credits" or "license" for more information.
>>>
```

如果你安装的 Python 版本低于 3，或者没有安装，请从[官方网站](http://www.python.org/download/)下载并安装。

> **译者注：**如果你的电脑上同时安装了 Python 2 和 Python 3，需要输入`python3`，而不是`python`。

因为将会使用 Python 3，所以不需要安装数据库。该 Python 版本内置了 SQLite 数据库。SQLite 是一个轻量级数据库，可以在 Django 开发中使用。如果计划在生产环境部署应用，应该使用更高级的数据库，比如 PostgreSQL，MySQL，或者 Oracle。在[这里](https://docs.djangoproject.com/en/1.11/topics/install/#database-installation)获取更多关于如何在 Django 中使用数据库的信息。

### 1.1.1 创建独立的 Python 环境

推荐你使用`virtualenv`创建独立的 Python 环境，这样就可以为不同项目使用不同的包版本，比在系统范围内安装 Python 包更实用。使用`virtualenv`的另一个好处是，安装 Python 包时不需要管理员权限。在终端运行下面的命令来安装`virtualenv`：

```py
pip install virtualenv
```

> **译者注**：如果电脑上同时安装了 Python 2 和 Python 3，需要使用`pip3`。

安装`virtualenv`后，使用下面的命令创建一个独立的 Python 环境：

```py
virtualenv my_env
```

这将会创建一个包括 Python 环境的`my_env/`目录。当虚拟环境激活时，安装的所有 Python 库都会在`my_env/lib/python3.5/site-packages`目录中。

如果电脑上同时安装了 Python 2 和 Python 3，你需要告诉`virtualenv`使用后者。使用以下命令定位 Python 3 的安装路径，然后使用该路径创建虚拟环境：

```py
zenx$ which python3
/Library/Frameworks/Python.framework/Versions/3.5/bin/python3
zenx$ virtualenv my_env -p
/Library/Frameworks/Python.framework/Versions/3.5/bin/python3
```

运行下面的命令激活虚拟环境：

```py
source my_env/bin/activate
```

终端的提示中，括号内是激活的虚拟环境的名称，比如：

```py
(my_env)laptop:~ zenx$
```

你可以使用`deactive`命令随时停用虚拟环境。

你可以在[这里](https://virtualenv.pypa.io/en/latest/)找到更多关于`virtualenv`的信息。

在`virtualenv`之上，你可以使用`virtualenvwrapper`。该工具进行了一些封装，更容易创建和管理虚拟环境。你可以在[这里](http://virtualenvwrapper.readthedocs.io/en/latest/)下载。

### 1.1.2 使用 pip 安装 Django

推荐使用`pip`安装 Django。Python 3.5 中已经安装了`pip`。在终端运行以下命令安装 Django：

```py
pip install Django
```

Django 将会安装在虚拟环境的`site-packages`目录中。

检查一下 Django 是否安装成功。在终端中运行`python`，然后导入 Django，检查版本：

```py
>>> import django
>>> django.VERSION
(1, 11, 0, 'final', 1)
```

如果得到类似以上的输出，表示 Django 已经安装成功。

有多种方式可以安装 Django，访问[这里](https://docs.djangoproject.com/en/1.11/topics/install/)查看完成的安装指南。

## 1.2 创建第一个项目

我们的第一个 Django 项目是一个完整的博客网站。Django 提供了一个命令，可以很容易创建一个初始的项目文件结构。在终端运行以下命令：

```py
django-admin startproject mysite
```

这会创建一个名为`mysite`的 Django 项目。

让我们看一下生成的项目结构：

```py
mysite/
  manage.py
  mysite/
    __init__.py
    settings.py
    urls.py
    wsgi.py
```

以下是这些文件的基本介绍：

- `manage.py`：用于与项目交互的命令行工具。它对`django-admin.py`工具进行了简单的封装。你不需要编辑该文件。
- `mysite/`：你的项目目录，由以下文件组成：
 * `__init__.py`：一个空文件，告诉 Python，把`mysite`目录当做一个 Python 模块。
 * `settings.py`：用于设置和配置你的项目。包括初始的默认设置。
 * `urls.py`：放置 URL 模式（pattern）的地方。这里定义的每个 URL 对应一个视图。
 * `wsgi.py`：配置你的项目，让它作为一个 WSGI 应用运行。

生成的`settings.py`文件中包括：使用 SQLite 数据库的基本配置，以及默认添加到项目中的 Django 应用。我们需要为这些初始应用在数据库中创建表。

打开终端，运行以下命令：

```py
cd mysite
python manage.py migrate
```

你会看到以类似这样结尾的输出：

```py
Running migrations:
  Applying contenttypes.0001_initial... OK
  Applying auth.0001_initial... OK
  Applying admin.0001_initial... OK
  Applying admin.0002_logentry_remove_auto_add... OK
  Applying contenttypes.0002_remove_content_type_name... OK
  Applying auth.0002_alter_permission_name_max_length... OK
  Applying auth.0003_alter_user_email_max_length... OK
  Applying auth.0004_alter_user_username_opts... OK
  Applying auth.0005_alter_user_last_login_null... OK
  Applying auth.0006_require_contenttypes_0002... OK
  Applying auth.0007_alter_validators_add_error_messages... OK
  Applying auth.0008_alter_user_username_max_length... OK
  Applying sessions.0001_initial... OK
```

初始应用的数据库表已经创建成功。一会你会学习`migrate`管理命令。

### 1.2.1 运行开发服务器

Django 自带一个轻量级的 web 服务器，可以快速运行你的代码，不需要花时间配置生产服务器。当你运行 Django 的开发服务器时，它会一直监测代码的变化，自动重新载入，不需要修改代码后，手动重启服务器。但是，有些操作它可能无法监测，比如在项目中添加新文件，这种情况下，你需要手动重启服务器。

从项目的根目录下输入以下命令，启动开发服务器：

```py
python manage.py runserver
```

你会看到类似这样的输出：

```py
Performing system checks...

System check identified no issues (0 silenced).
April 21, 2017 - 08:01:00
Django version 1.11, using settings 'kaoshao.settings'
Starting development server at http://127.0.0.1:8000/
Quit the server with CONTROL-C.

```

在浏览器中打开`http://127.0.0.1:8000/`。你应该可以看到一个页面，告诉你项目已经成功运行，如下图所示：

![](http://ooyedgh9k.bkt.clouddn.com/%E5%9B%BE1.1.png) 

你可以让 Django 在自定义的 host 和端口运行开发服务器，或者载入另一个配置文件来运行项目。例如，你可以这样运行`manage.py`命令：

```py
python manage.py runserver 127.0.0.1:8001 --settings=mysite.settings
```

这可以用来处理多个环境需要不同的配置。记住，该服务器只能用于开发，不适合生产环境使用。要在生产环境发布 Django，你需要使用真正的 web 服务器（比如 Apache，Gunicorn，或者 uWSGI）作为 Web Server Gateway Interface（WSGI）。你可以在[这里](https://docs.djangoproject.com/en/1.11/howto/deployment/wsgi/)找到更多关于如何使用不同的 web 服务器发布 Django 的信息。

### 1.2.2 项目设置

让我们打开`settings.py`文件，看下项目的配置。该文件中有很多 Django 的配置，但这只是所有 Django 配置中的一部分。你可以在[这里](https://docs.djangoproject.com/en/1.11/ref/settings/)查看所有配置和它们的默认值。

以下配置非常值得一看：

- `DEBUG`：一个布尔值，用于开启或关闭项目的调试模式。如果设置为`True`，当应用抛出一个未捕获的异常时，Django 会显示详细的错误页面。当你部署到生产环境时，记得设置为`False`。在生产环境部署站点时，永远不要启用`DEBUG`，否则会暴露项目的敏感数据。
- `ALLOWED_HOSTS`：当开启调试模式，或者运行测试时，它不会起作用。一旦你准备把站点部署到生产环境，并设置`DEBUG`为`False`，就需要将你的域或 host 添加到该设置中，以便它可以提供该 Django 站点。
- `INSTALLED_APPS`：你需要在所有项目中编辑该设置。该设置告诉 Django，该站点激活了哪些应用。默认情况下，Django 包括以下应用：
 * `django.contrib.admin`：管理站点。
 * `django.contrib.auth`：权限框架。
 * `django.contrib.contenttypes`：内容类型的框架。
 * `django.contrib.sessions`：会话框架。
 * `django.contrib.messages`：消息框架。
 * `django.contrib.staticfiles`：管理静态文件的框架。
- `MIDDLEWARE`：一个包括被执行的中间件的元组。
- `ROOT_URLCONF`：指明哪个 Python 模块定义了应用的根 URL 模式。
- `DATABASES`：一个字典，其中包括了所有在项目中使用的数据库的设置。必须有一个`default`数据库。默认使用 SQLite3 数据库。
- `LANGUAGE_CODE`：定义该 Django 站点的默认语言编码。

> **译者注：**Django 1.9 和之前的版本是`MIDDLEWARE`，之后的版本修改为`MIDDLEWARE`。

不用担心现在不能理解这些配置的意思。在以后的章节中你会逐渐熟悉 Django 配置。

### 1.2.3 项目和应用

在本书中，你会一次次看到术语项目（project）和应用（application）。在 Django 中，一个项目认为是一个具有一些设置的 Django 安装；一个应用是一组模型，视图，模板和 URLs。应用与框架交互，提供一些特定的功能，而且可能在多个项目中复用。你可以认为项目是你的站点，其中包括多个应用，比如博客，wiki，或者论坛，它们可以在其它项目中使用。

### 1.2.4 创建一个应用

现在，让我们创建第一个 Django 应用。我们会从头开始创建一个博客应用。在项目的根目录下，执行以下命令：

```py
python manage.py startapp blog
```

这将会创建应用的基本架构，如下所示：

```py
blog/
	__init__.py
   admin.py
   apps.py
   migrations/
       __init__.py
   models.py
   tests.py
   views.py
```

以下是这些文件：

- `admin.py`：用于注册模型，把它们包括进 Django 管理站点。是否使用 Django 管理站点是可选的。
- `apps.py`：用于放置应用配置（application configuration），可以配置应用的某些属性。
- `migrations`：该目录会包含应用的数据库迁移。迁移允许 Django 追踪模型的变化，并同步数据库。
- `models.py`：应用的数据模型。所有 Django 应用必须有一个`models.py`文件，但该文件可以为空。
- `tests.py`：用于添加应用的测试。
- `views.py`：用于存放应用的逻辑。每个视图接收一个 HTTP 请求，然后处理请求，并返回响应。

> **译者注：**从 Django 1.9 开始，`startapp`命令会创建`apps.py`文件。

## 1.3 设计博客的数据架构

我们将会开始定义博客的初始数据模型。一个模型是一个 Python 类，并继承自`django.db.models.Model`，其中每个属性表示数据库的一个字段。Django 会为`models.py`中定义的每个模型创建一张数据库表。创建模型后，Django 会提供一个实用的 API 进行数据库查询。

首先，我们定义一个`Post`模型，在`blog`应用的`models.py`文件中添加以下代码：

```py
from django.db import models
from django.utils import timezone
from django.contrib.auth.models import User

class Post(models.Model):
    STATUS_CHOICES = (
        ('draft', 'Draft'),
        ('published', 'Published'),
    )

    title = models.CharField(max_length=250)
    slug = models.SlugField(max_length=250, 
                            unique_for_date='publish')
    author = models.ForeignKey(User, 
                               related_name='blog_posts')
    body = models.TextField()
    publish = models.DateTimeField(default=timezone.now)
    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)
    status = models.CharField(max_length=10,
                              choices=STATUS_CHOICES,
                              default='draft')

    class Meta:
        ordering = ('-publish',)

    def __str__(self):
        return self.title
```

这是博客帖子的基础模型。让我们看看该模型定义的字段：

- `title`：这个字段是帖子的标题。该字段的类型是`CharField`，在 SQL 数据库中会转换为`VARCHAR`。
- `slug`：这个字段会在 URLs 中使用。一个别名（slug）是一个短标签，只包括字母，数字，下划线或连字符。我们将使用`slug`字段为 blog 的帖子创建漂亮的，搜索引擎友好的 URLs。我们为该字段添加了`unique_for_date`参数，所以我们可以使用帖子的日期和别名来构造帖子的 URLs。Django 不允许多个帖子有相同的别名和日期。
- `author`：这个字段是一个`ForeignKey`。该字段定义了多对一的关系。我们告诉 Django，一篇帖子由一个用户编写，一个用户可以编写多篇帖子。对于该字段，Django 使用关联模型的主键，在数据库中创建一个外键。在这里，我们关联了 Django 权限系统的`User`模型。我们使用`related_name`属性，指定了从`User`到`Post`的反向关系名。之后我们会学习更多这方面的内容。
- `body`：帖子的正文。该字段是`TextField`，在 SQL 数据中会转换为`TEXT`。
	 `publish`：帖子发布的时间。	我们使用 Django 中`timezone`的`now`方法作为默认值。这只是一个时区感知的`datetime.now`。（**译者注：**根据不同时区，返回该时区的当前时间）
- `created`：帖子创建的时间。我们使用`auto_now_add`，因此创建对象时，时间会自动保存。
- `updated`：帖子最后被修改的时间。我们使用`auto_now`，因此保存对象时，时间会自动更新。
- `status`：该字段表示帖子的状态。我们使用`choices`参数，因此该字段的值只能是给定选项中的一个。

正如你所看到的，Django 内置了很多不同类型的字段，可以用来定义你的模型。你可以在[这里](https://docs.djangoproject.com/en/1.11/ref/models/fields/)找到所有字段类型。

模型中的`Meta`类包含元数据。我们告诉 Django，查询数据库时，默认排序是`publish`字段的降序排列。我们使用负号前缀表示降序排列。

`__str__()`方法是对象的默认可读表示。Django 会在很多地方（比如管理站点）使用它。

> 如果你是从 Python 2.X 中迁移过来的，请注意在 Python 3 中所有字符串天生就是 Unicode 编码，因此我们只使用`__str__()`方法。`__unicode__()`方法被废弃了。

因为我们要处理时间，所以将会安装`pytz`模块。该模块为 Python 提供了时区定义，同时 SQLite 也需要它操作时间。打开终端，使用以下命令安装`pytz`。

```py
pip install pytz
```

Django 内置支持时区感知。在项目的`settings.py`文件中，通过`USE_TZ`设置，启用或禁用时区支持。使用`startproject`管理命令创建新项目时，该设置为`True`。

### 1.3.1 激活应用

为了让 Django 保持追踪应用，并且可以为它的模型创建数据库，我们需要激活应用。编辑`settings.py`文件，在`INSTALLED_APPS`设置中添加`blog`。如下所示：

```py
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'blog',
]
```

现在，Django 知道在该项目中，我们的应用已经激活，并且可以自省（instrospect）它的模型。

### 1.3.2 创建并应用数据库迁移

让我们在数据库中创建模型的数据库表。Django 自带一个迁移系统，可以追踪模型变化，并同步到数据库中。`migrate`命令会应用迁移到`INSTALLED_APPS`中列出的所有应用；它根据当前模型和迁移来同步数据库。

首先，我们需要为刚创建的新模型创建一个数据库迁移。在项目的根目录下输入以下命令：

```py
python manage.py makemigrations blog
```

你会得到类似以下的输出：

```py
Migrations for 'blog':
  0001_initial.py:
    - Create model Post
```

Django 在`blog`应用的`migrations`目录中创建了`0001_initial.py`文件。你可以打开该文件，查看数据库迁移生成的内容。

让我们看看 SQL 代码，Django 会在数据库中执行它们，为我们的模型创建数据库表。`sqlmigrate`命令接收一个数据库迁移名称，并返回 SQL 语句，但不会执行。运行以下命令检查数据：

```py
python manage.py sqlmigrate blog 0001
```

输入看起来是这样：

```py
BEGIN;
CREATE TABLE "blog_post" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "title" varchar(250) NOT NULL, "slug" varchar(250) NOT NULL, "body" text NOT NULL, "publish" datetime NOT NULL, "created" datetime NOT NULL, "updated" datetime NOT NULL, "status" varchar(10) NOT NULL, "author_id" integer NOT NULL REFERENCES "auth_user" ("id"));
CREATE INDEX "blog_post_slug_b95473f2" ON "blog_post" ("slug");
CREATE INDEX "blog_post_author_id_dd7a8485" ON "blog_post" ("author_id");
COMMIT;
```

使用不同的数据库，输出会有不同。上面是为 SQLite 生成的输出。正如你所看见的，Django 通过组合应用名和模型名的小写字母生成表名（blog_post），但你可以在模型的`Meta`类中使用`db_table`属性指定表明。Django 会自动为每个模型创建一个主键，但你同样可以在某个模型字段中指定`primary_key=True`，来指定主键。

让我们使用新模型同步数据库。运行以下命令，应用已经存在的数据库迁移：

```py
python manage.py migrate
```

你会得到以下面这行结尾的输出：

```py
  Applying blog.0001_initial... OK
```

我们刚才为`INSTALLED_APPS`中列出的所有应用（包括`blog`应用）进行了数据库迁移。应用了迁移后，数据库会反应模型的当前状态。

如果添加，移除或修改了已存在模型的字段，或者添加了新模型，你需要使用`makemigrations`命令创建一个新的数据库迁移。数据库迁移将会允许 Django 保持追踪模型的变化。然后，你需要使用`migrate`命令应用该迁移，保持数据库与模型同步。

## 1.4 为模型创建管理站点

现在，我们已经定义了`Post`模型，我们将会创建一个简单的管理站点，来管理博客帖子。Django 内置了管理界面，非常适合编辑内容。Django 管理站点通过读取模型的元数据，并为编辑内容提供可用于生产环境的界面，进行动态构建。你可以开箱即用，或者配置如何显示模型。

记住，`django.contrib.admin`已经包括在我们项目的`INSTALLED_APPS`设置中，所以我们不需要再添加。

### 1.4.1 创建超级用户

首先，我们需要创建一个用户来管理这个站点。运行以下命令：

```py
python manage.py createsuperuser
```

你会看到以下输出。输入你的用户名，e-mail 和密码：

```py
Username (leave blank to use 'admin'): admin
Email address: admin@admin.com
Password: ********
Password (again): ********
Superuser created successfully.
```

### 1.4.2 Django 管理站点

现在，使用`python manage.py runserver`命令启动开发服务器，并在浏览器中打开`http://127.0.0.1:8000/admin/`。你会看到如下所示的管理员登录界面：

![](http://ooyedgh9k.bkt.clouddn.com/%E5%9B%BE1.2.png)

使用上一步创建的超级用户登录。你会看到管理站点的首页，如下图所示：

![](http://ooyedgh9k.bkt.clouddn.com/%E5%9B%BE1.3.png)

这里的`Group`和`User`模型是 Django 权限框架的一部分，位于`django.contrib.auth`中。如果你点击`Users`，会看到你之前创建的用户。你的`blog`应用的`Post`模型与`User`模型关联在一起。记住，这种关系由`author`字段定义。

### 1.4.3 添加模型到管理站点

让我们添加 blog 模型到管理站点。编辑`blog`应用的`admin.py`文件，如下所示：

```py
from django.contrib import admin
from .models import Post

admin.site.register(Post)
```

现在，在浏览器中重新载入管理站点。你会看到`Post`模型，如下图所示：

![](http://ooyedgh9k.bkt.clouddn.com/%E5%9B%BE1.4.png)

这很容易吧？当你在 Django 管理站点注册模型时，你会得到一个用户友好的界面，该界面通过内省你的模型产生，允许你非常方便的排列，编辑，创建和删除对象。

点击`Post`右边的`Add`链接来添加一篇新的帖子。你会看到 Django 为模型动态生成的表单，如下图所示：

![](http://ooyedgh9k.bkt.clouddn.com/%E5%9B%BE1.5.png)

Django 为每种字段类型使用不同的表单控件。即使是复杂的字段（比如`DateTimeField`），也会使用类似`JavaScript`的日期选择器显示一个简单的界面。

填写表单后，点击`Save`按钮。你会被重定向到帖子列表页面，其中显示一条成功消息和刚刚创建的帖子，如下图所示：

![](http://ooyedgh9k.bkt.clouddn.com/%E5%9B%BE1.6.png)

### 1.4.4 自定义模型显示方式

现在，我们看下如何自定义管理站点。编辑`blog`应用的`admin.py`文件，修改为：

```py
from django.contrib import admin
from .models import Post

class PostAdmin(admin.ModelAdmin):
    list_display = ('title', 'slug', 'author', 'publish', 'status')

admin.site.register(Post, PostAdmin)
```

我们告诉 Django 管理站点，使用从`ModelAdmin`继承的自定义类注册模型到管理站点。在这个类中，我们可以包括如何在管理站点中显示模型的信息，以及如何与它们交互。`list_display`属性允许你设置想在管理对象列表页中显示的模型字段。

让我们使用更多选项自定义管理模型，如下所示：

```py
class PostAdmin(admin.ModelAdmin):
    list_display = ('title', 'slug', 'author', 'publish', 'status')
    list_filter = ('status', 'created', 'publish', 'author')
    search_fields = ('title', 'body')
    prepopulated_fields = {'slug': ('title', )}
    raw_id_fields = ('author', )
    date_hierarchy = 'publish'
    ordering = ['status', 'publish']
```

回到浏览器，重新载入帖子类别页，如下图所示：

![](http://ooyedgh9k.bkt.clouddn.com/%E5%9B%BE1.7.png)

你可以看到，帖子列表页中显示的字段就是在`list_display`属性中指定的字段。现在，帖子列表页包括一个右边栏，可以通过`list_filter`属性中包括的字段来过滤结果。页面上出现了一个搜索栏。这是因为我们使用`search_fields`属性定义了可搜索的字段列表。在搜索栏下面，有一个通过日期进行快速导航的栏。这是通过定义`date_hierarchy`属性定义的。你还可以看到，帖子默认按`Status`和`Publish`列排序。这是因为使用`ordering`属性指定了默认排序。

现在点击`Add post`链接，你会看到有些不同了。当你为新帖子输入标题时，会自动填写`slug`字段。我们通过`prepopulated_fields`属性已经告诉了 Django，用`title`字段的输入预填充`slug`字段。同样，`author`字段显示为搜索控件，当你有成千上万的用户时，比下拉框更人性化，如下图所示：

![](http://ooyedgh9k.bkt.clouddn.com/%E5%9B%BE1.8.png)

通过几行代码，我们已经在管理站点中自定义了模型的显示方式。还有很多自定义和扩展 Django 管理站点的方式。本书后面的章节会涉及这个特性。

## 1.5 使用 QuerySet 和管理器

现在，你已经有了一个功能完整的管理站点来管理博客的内容，是时候学习如何从数据库中检索对象，并与之交互了。Django 自带一个强大的数据库抽象 API，可以很容易的创建，检索，更新和删除对象。Django 的 ORM（Object-relational Mapper）兼容 MySQL，PostgreSQL，SQLite 和 Oracle。记住，你可以在项目的`settings.py`文件中编辑`DATABASES`设置，来定义项目的数据库。Django 可以同时使用多个数据库，你可以用任何你喜欢的方式，甚至编写数据库路由来处理数据。

一旦创建了数据模型，Django 就提供了一个自由的 API 来与之交互。你可以在[这里](https://docs.djangoproject.com/en/1.11/ref/models/)找到数据模型的官方文档。

### 1.5.1 创建对象

打开终端，运行以下命令来打开 Python 终端：

```py
python manage.py shell
```

然后输入以下行：

```py
>>> from django.contrib.auth.models import User
>>> from blog.models import Post
>>> user = User.objects.get(username='admin')
>>> post = Post(title='One more post',
                slug='one-more-post',
                body='Post body.',
                author=user)
>>> post.save()
```

> **译者注：**书中的代码不是创建一个`Post`实例，而是直接使用`create()`在数据库中创建对象。这个地方应该是作者的笔误。

让我们分析这段代码做了什么。首先，我们检索`username`为`admin`的用户对象：

```py
user = User.objects.get(username='admin')
```

`get()`方法允许你冲数据库中检索单个对象。注意，该方法期望一个匹配查询的结果。如果数据库没有返回结果，该方法会抛出`DoesNotExist`异常；如果数据库返回多个结果，将会抛出`MultipleObjectsReturned`异常。这两个异常都是执行查询的模型类的属性。

然后，我们使用`title`，`slug`和`body`创建了一个`Post`实例，并设置之前返回的`user`作为帖子的作者：

```py
post = Post(title='Another post', slug='another-post', body='Post body.', author=user)
```

> 该对象在内存中，而不会存储在数据库中。

最后，我们使用`save()`方法保存`Post`对象到数据库中：

```py
post.save()

```

这个操作会在底层执行一个`INSERT`语句。我们已经知道如何先在内存创建一个对象，然后存储到数据库中，但也可以使用`create()`方法直接在数据库中创建对象：

```py
Post.objects.create(title='One more post', 
                    slug='one-more-post',
                    body='Post body.', 
                    author=user)
```

### 1.5.2 更新对象

现在，修改帖子的标题，并再次保存对象：

```py
>>> post.title = 'New title'
>>> post.save()
```

此时，`save()`方法会执行`UPDATE`语句。

> 直到调用`save()`方法，你对对象的修改才会存到数据库中。

### 1.5.3 检索对象

Django 的 ORM 是基于`QuerySet`的。一个`QuerySet`是来自数据库的对象集合，它可以有数个过滤器来限制结果。你已经知道如何使用`get()`方法从数据库检索单个对象。正如你所看到的，我们使用`Post.objects.get()`访问该方法。每个 Django 模型最少有一个管理器（manager），默认管理器叫做`objects`。你通过使用模型管理器获得一个`QuerySet`对象。要从表中检索所有对象，只需要在默认的`objects`管理器上使用`all()`方法，比如：

```py
>>> all_posts = Post.objects.all()
```

这是如何创建一个返回数据库中所有对象的`QuerySet`。注意，该`QuerySet`还没有执行。Django 的`QuerySet`是懒惰的；只有当强制它们执行时才会执行。这种行为让`QuerySet`变得很高效。如果没有没有把`QuerySet`赋值给变量，而是直接在 Python 终端输写，`QuerySet`的 SQL 语句会执行，因为我们强制它输出结果：

```py
>>> Post.objects.all()
```

#### 1.5.3.1 使用`filter()`方法

你可以使用管理器的`filter()`方法过滤一个`QuerySet`。例如，我们使用下面的`QuerySet`检索所有 2015 年发布的帖子：

```py
Post.objects.filter(publish__year=2015)
```

你也可以过滤多个字段。例如，我们可以检索 2015 年发布的，作者的`username`是`amdin`的帖子：

```py
Post.objects.filter(publish__year=2015, author__username='admin')
```

这等价于链接多个过滤器，来创建`QuerySet`：

```py
Post.objects.filter(publish__year=2015)\
            .filter(author__username='admin')
```

> 通过两个下划线（publish\_\_year)，我们使用字段查找方法构造了查询，但我们也可以使用两个下划线访问相关模型的字段（author\_\_username）。

#### 1.5.3.2 使用`exclude()`

你可以使用管理器的`exclude()`方法从`QuerySet`中排除某些结果。例如，我们可以检索所有 2017 年发布的，标题不是以`Why`开头的帖子：

```py
Post.objects.filter(publish__year=2017)\
            .exclude(title__startswith='Why')
```

#### 1.5.3.3 使用`order_by()`

你可以使用管理器的`order_by()`方法对不同字段进行排序。例如，你可以检索所有对象，根据它们的标题排序：

```py
Post.objects.order_by('title')
```

默认是升序排列。通过负号前缀指定降序排列，比如：

```py
Post.objects.order_by('-title')
```

### 1.5.4 删除对象

如果想要删除对象，可以这样操作：

```py
post = Post.objects.get(id=1)
post.delete()
```

> 注意，删除对象会删除所有依赖关系。

### 1.5.5 什么时候执行 QuerySet

你可以连接任意多个过滤器到`QuerySet`，在`QuerySet`执行之前，不会涉及到数据库。`QuerySet`只在以下几种情况被执行：

- 你第一次迭代它们
- 当你对它们进行切片操作。比如：`Post.objects.all()[:3]`
- 当你对它们进行`pickle`或缓存
- 当你对它们调用`repr()`或`len()`
- 当你显示对它们调用`list()`
- 当你在语句中测试，比如`bool()`，`or`，`and`或者`if`

### 1.5.6 创建模型管理器

正如我们之前提到的，`objects`是每个模型的默认管理器，它检索数据库中的所有对象。但我们也可以为模型自定义管理器。接下来，我们会创建一个自定义管理器，用于检索所有状态为`published`的帖子。

为模型添加管理器有两种方式：添加额外的管理器方法或者修改初始的管理器`QuerySet`。前者类似`Post.objects.my_manager()`，后者类似`Post.my_manager.all()`。我们的管理器允许我们使用`Post.published`来检索帖子。

编辑`blog`应用中的`models.py`文件，添加自定义管理器：

```py
class PublishedManager(models.Manager):
    def get_queryset(self):
        return super().get_queryset()\
                      .filter(status='published')


class Post(models.Model):
    # ...
    objects = models.Manager()
    published = PublishedManager()
```

`get_queryset()`是返回被执行的`QuerySet`的方法。我们使用它在最终的`QuerySet`中包含了自定义的过滤器。我们已经自定义了管理器，并添加到`Post`模型中；现在可以用它来执行查询。例如，我们可以检索所有标题以`Who`开头，并且已经发布的帖子：

```py
Post.published.filter(title__startswith='Who')
```

> **译者注：**这里修改了`models.py`文件，因此需要在终端再次导入`Post`：`from blog.models import Post`。

## 1.6 构建列表和详情视图

现在，你已经了解了如何使用 ORM，可以随时构建博客应用的视图了。一个 Django 视图就是一个 Python 函数，它接收一个 web 请求，并返回一个 web 响应。视图中的所有逻辑返回期望的响应。

首先，我们会创建应用视图，然后定义每个视图的 URL 模式，最后创建 HTML 模板渲染视图产生的数据。每个视图渲染一个的模板，同时把变量传递给模板，并返回一个具有渲染输出的 HTTP 响应。

### 1.6.1 创建列表和详情视图

让我们从创建显示所有帖子的列表视图开始。编辑`blog`应用的`views.py`文件，如下所示：

```py
from django.shortcuts import render, get_object_or_404
from .models import Post

def post_list(request):
    posts = Post.published.all()
    return render(request,
                  'blog/post/list.html',
                  {'posts': posts})
```

你刚创建了第一个 Django 视图。`post_list`视图接收`request`对象作为唯一的参数。记住，该参数是所有视图都必需的。在这个视图中，我们使用之前创建的`published`管理器检索所有状态为`published`的帖子。

最后，我们使用 Django 提供的快捷方法`render()`，渲染指定模板的帖子列表。该函数接收`request`对象作为参数，通过模板路径和变量来渲染指定的模板。它返回一个带有渲染后文本（通常是 HTML 代码）的`HttpResponse`对象。`render()`快捷方法考虑了请求上下文，因此由模板上下文处理器（template context processor）设置的任何变量都可以由给定的模板访问。模板上下文处理器是可调用的，它们把变量设置到上下文中。你将会在第三章中学习如何使用它们。

让我们创建第二个视图，用于显示单个帖子。添加以下函数到`views.py`文件中：

```py
def post_detail(request, year, month, day, post):
    post = get_object_or_404(Post, slug=post,
                                   status='published',
                                   publish__year=year,
                                   publish__month=month,
                                   publish__day=day)
    return render(request,
                  'blog/post/detail.html',
                  {'post': post})
```

这是帖子的详情视图。该视图接收`year`，`month`，`day`和`post`作为参数，用于检索指定别名和日期的已发布的帖子。注意，当我们创建`Post`模型时，添加了`unique_for_date`参数到`slug`字段。这就确保了指定日期和别名时，只会检索到一个帖子。在详情视图中，我们使用`get_object_or_404()`快捷方法检索期望的帖子。该函数检索匹配给定参数的对象，如果没有找到对象，就会引发 HTTP 404（Not found）异常。最后，我们使用模板，调用`render()`快捷方法渲染检索出来的帖子。

### 1.6.2 为视图添加 URL 模式

一个 URL 模式由一个 Python 正则表达式，一个视图和一个项目范围内的名字组成。Django 遍历每个 URL 模式，并在匹配到第一个请求的 URL 时停止。然后，Django 导入匹配 URL 模式的视图，传递`HttpRequest`类实例和关键字或位置参数，并执行视图。

如果你以前没有使用过正则表达式，可以在[这里](https://docs.python.org/3/howto/regex.html )了解。

在`blog`应用的目录下新建一个`urls.py`文件，添加以下代码：

```py
from django.conf.urls import url
from . import views

urlpatterns = [
    url(r'^$', views.post_list, name='post_list'),
    url(r'^(?P<year>\d{4})/(?P<month>\d{2})/(?P<day>\d{2})/'\
        r'(?P<post>[-\w]+)/$',
        views.post_detail,
        name='post_detail'),
]
```

第一个 URL 模式不带任何参数，映射到`post_list`视图。第二个模式带以下四个参数，映射到`post_detail`视图。让我们看看 URL 模式的正则表达式：

- year：需要四个数字
- month：需要两个数字，在前面补零。
- day：需要两个数字，在前面补零。
- post：可以由单词和连字符组成。

> 最好为每个应用创建一个`urls.py`文件，这可以让应用在其它项目中复用。

现在你需要在项目的主 URL 模式中包含`blog`应用的 URL 模式。编辑项目目录中的`urls.py`文件，如下所示：

```py
from django.conf.urls import url, include
from django.contrib import admin

urlpatterns = [
    url(r'^admin/', admin.site.urls),
    url(r'^blog/', include('blog.urls',
                           namespace='blog',
                           app_name='blog'))
]
```

这样你就可以让 Django 包括 URL 模式，该模式在`blog/`路径下的`urls.py`文件中定义。你指定它们的命名空间为`blog`，这样你可以很容易的引用该 URLs 组。

### 1.6.3 模型的标准 URLs

你可以使用上一节定义的`post_detail` URL，为`Post`对象构建标准的 URL。Django 的惯例是在模型中添加`get_absolute_url()`方法，该方法返回对象的标准 URL。对于这个方法，我们会使用`reverse()`方法，它允许你通过它们的名字，以及传递参数构造 URLs。编辑`models.py`文件，添加以下代码：

```py
from django.core.urlresolvers import reverse
   Class Post(models.Model):
       # ...
       def get_absolute_url(self):
           return reverse('blog:post_detail',
                          args=[self.publish.year,
                                self.publish.strftime('%m'),
                                self.publish.strftime('%d'),
                                self.slug])

```

注意，我们使用`strftime()`函数构造使用零开头的月份和日期。我们将会在模板中使用`get_absolute_url()`方法。

## 1.7 为视图创建模板

我们已经为应用创建了视图和 URL 模式。现在该添加模板来显示用户界面友好的帖子了。

在你的`blog`应用目录中创建以下目录和文件：

```py
templates/
    blog/
        base.html
        post/
            list.html
            detail.html
```

这就是模板的文件结构。`base.html`文件将会包括网站的主 HTML 结构，它把内容分为主内容区域和一个侧边栏。`list.html`和`detail.html`文件继承自`base.html`文件，分别用于渲染帖子列表视图和详情视图。

Django 有一个强大的模板语言，允许你指定如何显示数据。它基于模板标签——`{% tag %}`，模板变量——`{{ variable }}`，和可作用于变量的模板过滤器——`{{ variable|filter }}`。你可以在[这里](https://docs.djangoproject.com/en/1.11/ref/templates/builtins/)查看所有内置模板标签和过滤器。

让我们编辑`base.html`文件，添加以下代码：

```py
{% load staticfiles %}
<!DOCTYPE html>
<html>
<head>
	<title>{% block title %}{% endblock %}</title>
   <link href="{% static "css/blog.css" %}" rel="stylesheet">
</head>
<body>
	<div id="content">
		{% block content %}
		{% endblock %}
	</div>
	<div id="sidebar">
		<h2>My blog</h2>
		<p>This is my blog.</p>
	</div>
</body>
</html>
```

`{% load staticfiles %}`告诉 Django 加载`staticfiles`模板标签，它是`django.contrib.staticfiles`应用提供的。加载之后，你可以在该模板中使用`{% static %}`模板过滤器。通过该模板过滤器，你可以包括静态文件（比如`blog.css`，在 blog 应用的`static/`目录下可以找到这个例子的代码）。拷贝这个目录到你项目的相同位置，来使用这些静态文件。

你可以看到，有两个`{% block %}`标签。它们告诉 Django，我们希望在这个区域定义一个块。从这个模板继承的模板，可以用内容填充这些块。我们定义了一个`title`块和一个`content`块。

让我们编辑`post/list.html`文件，如下所示：

```py
{% extends "blog/base.html" %}

{% block title %}My Blog{% endblock %}

{% block content %}
	<h1>My Blog</h1>
	{% for post in posts %}
		<h2>
			<a href="{{ post.get_absolute_url }}">
				{{ post.title }}
			</a>
		</h2>
		<p class="date">
			Published {{ post.publish }} by {{ post.author }}
		</p>
		{{ post.body|truncatewords:30|linebreaks }}
	{% endfor %}
{% endblock %}
```

使用`{% extends %}`模板标签告诉 Django 从`blog/base.html`模板继承。接着，我们填充基类模板的`title`和`content`块。我们迭代帖子，并显示它们的标题，日期，作者和正文，其中包括一个标题链接到帖子的标准 URL。在帖子的正文中，我们使用了两个模板过滤器：`truncatewords`从内容中截取指定的单词数，`linebreaks`把输出转换为 HTML 换行符。你可以连接任意多个模板过滤器；每个过滤器作用于上一个过滤器产生的输出。

打开终端，执行`python manage.py runserver`启动开发服务器。在浏览器打开`http://127.0.0.1:8000/blog/`，就能看到运行结果。注意，你需要一些状态为`Published`的帖子才能看到。如下图所示：

![](http://ooyedgh9k.bkt.clouddn.com/%E5%9B%BE1.9.png)

接着，让我们编辑`post/detail.html`文件，添加以下代码：

```py
{% extends "blog/base.html" %}

{% block title %}{{ post.title }}{% endblock %}

{% block content %}
	<h1>{{ post.title }}</h1>
	<p class="date">
		Published {{ post.publish }} by {{ post.author }}
	</p>
	{{ post.body|linebreaks }}
{% endblock %}
```

返回浏览器，点击某条帖子的标题跳转到详情视图，如下图所示：

![](http://ooyedgh9k.bkt.clouddn.com/%E5%9B%BE1.10.png)

观察一下 URL，类似这样：`/blog/2017/04/25/who-was-django-reinhardt/`。我们为帖子创建了一个对搜索引擎友好的 URL。

## 1.8 添加分页

当你开始往博客中添加内容，你会发现需要把帖子分页。Django 内置了一个分页类，可以很容易的管理分页内容。

编辑`blog`应用的`views.py`文件，导入分页类，并修改`post_list`视图：

```py
from django.core.paginator import Paginator, EmptyPage,\
                                  PageNotAnInteger
                                  
def post_list(request):
	object_list = Post.published.all()
	paginator = Paginator(object_list, 3) # 3 posts in each page
	page = request.GET.get('page')
	try:
		posts = paginator.page(page)
	except PageNotAnInteger:
		# If page is not an integer deliver the first page
		posts = paginator.page(1)
	except EmptyPage:
		# If page is out of range deliver last page of results
       posts = paginator.page(paginator.num_pages)
   return render(request,
                 'blog/post/list.html',
					{'page': page, 'posts': posts})
```

分页是这样工作的：

1. 用每页想要显示的对象数量初始化`Paginator`类。
2. 获得`GET`中的`page`参数，表示当前页码。
3. 调用`Paginator`类的`page()`方法，获得想要显示页的对象。
4. 如果`page`参数不是整数，则检索第一页的结果。如果这个参数大于最大页码，则检索最后一页。
5. 把页码和检索出的对象传递给模板。

现在，我们需要创建显示页码的模板，让它可以在任何使用分页的模板中使用。在`blog`应用的`templates`目录中，创建`pagination.html`文件，并添加以下代码：

```py
<div class="pagination">
	<span class="step-links">
		{% if page.has_previous %}
			<a href="?page={{ page.previous_page_number }}">Previous</a>
		{% endif %}
		<span class="current">
			Page {{ page.number }} of {{ page.paginator.num_pages }}.
		</span>
		{% if page.has_next %}
			<a href="?page={{ page.next_page_number }}">Next</a>
			{% endif %}
	</span>
</div>
```

这个分页模板需要一个`Page`对象，用于渲染上一个和下一个链接，并显示当前页和总页数。让我们回到`blog/post/list.html`模板，将`pagination.html`模板包括在`{% content %}`块的底部，如下所示：

```py
{% block content %}
	...
	{% include "pagination.html" with page=posts %}
{% endblock %}
```

因为我们传递给模板的`Page`对象叫做`posts`，所以我们把分页模板包含在帖子列表模板中，并指定参数进行正确的渲染。通过这种方法，你可以在不同模型的分页视图中重用分页模板。

在浏览器中打开`http://127.0.0.1:8000/blog/`，你会在帖子列表底部看到分页，并且可以通过页码导航：

![](http://ooyedgh9k.bkt.clouddn.com/%E5%9B%BE1.11.png)

## 1.9 使用基于类的视图

视图接收一个 web 请求，返回一个 web 响应，并且可以被调用，所以可以把视图定义为类方法。Django 为此提供了基础视图类。它们都是继承自`View`类，可以处理 HTTP 方法调度和其它功能。这是创建视图的一个替代方法。

我们使用 Django 提供的通用`ListView`，把`post_list`视图修改为基于类的视图。这个基础视图允许你列出任何类型的对象。

编辑`blog`应用的`views.py`文件，添加以下代码：

```py
from django.views.generic import ListView

class PostListView(ListView):
	queryset = Post.published.all()
	context_object_name = 'posts'
	paginate_by = 3
	template_name = 'blog/post/list.html'
```

这个基于类的视图与之前的`post_list`视图类似，它做了以下操作：

- 使用特定的`QuerySet`代替检索所有对象。我们可以指定`model=Post`，然后 Django 会为我们创建通用的`Post.objects.all()`这个`QuerySet`，来代替定义一个`queryset`属性。
- 为查询结果使用上下文变量`posts`。如果不指定`context_object_name`，默认变量是`object_list`。
- 对结果进行分页，每页显示三个对象。
- 使用自定义模板渲染页面。如果没有设置默认模板，`ListView`会使用`blog/post_list.html`。

打开`blog`应用的`urls.py`文件，注释之前的`post_list` URL 模式，使用`PostListView`类添加新的 URL 模式：

```py
urlpatterns = [
	# post views
	# url(r'^$', views.post_list, name='post_list'),
	url(r'^$', views.PostListView.as_view(), name='post_list'),
	url(r'^(?P<year>\d{4})/(?P<month>\d{2})/(?P<day>\d{2})/'\
	    r'(?P<post>[-\w]+)/$',
	    views.post_detail,
	    name='post_detail'),
]
```

为了保证分页正常工作，我们需要传递正确的`page`对象给模板。Django 的`ListView`使用`page_obj`变量传递选中页，因此你需要编辑`list.html`模板，使用正确的变量包括页码：

```py
{% include "pagination.html" with page=page_obj %}
```

在浏览器打开`http://127.0.0.1:8000/blog/`，检查是不是跟之前使用的`post_list`视图一致。这是一个基于类视图的简单示例，使用了 Django 提供的通过类。你会在第十章和后续章节学习更多基于类的视图。

## 1.10 总结

在这章中，通过创建一个基本的博客应用，我们学习了 Django 框架的基础知识。你设计了数据模型，并进行了数据库迁移。你创建了视图，模板和博客的 URLs，以及对象分页。

在下一章，你将会学习如何完善博客应用，包括评论系统，标签功能，并且允许用户通过 e-mail 分享帖子。

# 第二章：为博客添加高级功能

上一章中，你创建了一个基础的博客应用。现在，利用一些高级特性，你要把它打造成一个功能完整的博客，比如通过邮件分享帖子，添加评论，为帖子打上标签，以及通过相似度检索帖子。在这一章中，你会学习以下主题：

- 使用 Django 发送邮件
- 在视图中创建和处理表单
- 通过模型创建表单
- 集成第三方应用
- 构造复杂的`QuerySet`。

## 2.1 通过邮件分享帖子

首先，我们将会允许用户通过邮件分享帖子。花一点时间想想，通过上一章学到的知识，你会如何使用视图，URL 和模板来完成这个功能。现在核对一下，允许用户通过邮件发送帖子需要完成哪些操作：

- 为用户创建一个填写名字，邮箱，收件人和评论（可选的）的表单
- 在`views.py`中创建一个视图，用于处理`post`数据和发送邮件
- 在`blog`应用的`urls.py`文件中，为新视图添加 URL 模式
- 创建一个显示表单的模板

### 2.1.1 使用 Django 创建表单

让我们从创建分享帖子的表单开始。Django 有一个内置的表单框架，让你很容易的创建表单。表单框架允许你定义表单的字段，指定它们的显示方式，以及如何验证输入的数据。Django 的表单框架还提供了一种灵活的方式，来渲染表单和处理数据。

Django 有两个创建表单的基础类：

- `Form`：允许你创建标准的表单
- `ModelForm`：允许你通过创建表单来创建或更新模型实例

首先，在`blog`应用目录中创建`forms.py`文件，添加以下代码：

```py
from django import forms

class EmailPostForm(forms.Form):
	name = forms.CharField(max_length=25)
	email = forms.EmailField()
	to = forms.EmailField()
	comments = forms.CharField(required=False, 
	                           widget=forms.Textarea)
```

这是你的第一个 Django 表单。这段代码通过继承基类`Form`创建了一个表单。我们使用不同的字段类型，Django 可以相应的验证字段。

> 表单可以放在 Django 项目的任何地方，但惯例是放在每个应用的`forms.py`文件中。

`name`字段是一个`CharField`。这种字段的类型渲染为`<input type="text">` HTML 元素。每种字段类型都有一个默认组件，决定了该字段如何在 HTML 中显示。可以使用`widget`属性覆盖默认组件。在`comments`字段中，我们使用`Textarea`组件显示为`<textarea>` HTML 元素，而不是默认的`<input>`元素。

字段的验证也依赖于字段类型。例如，`email`和`to`字段是`EmailField`。这两个字段都要求一个有效的邮箱地址，否则字段验证会抛出`forms.ValidationError`异常，导致表单无效。表单验证时，还会考虑其它参数：我们定义`name`字段的最大长度为 25 个字符，并使用`required=False`让`comments`字段是可选的。字段验证时，这些所有因素都会考虑进去。这个表单中使用的字段类型只是 Django 表单字段的一部分。在[这里](https://docs.djangoproject.com/en/1.11/ref/forms/fields/)查看所有可用的表单字段列表。

### 2.1.2 在视图中处理表单

你需要创建一个新视图，用于处理表单，以及提交成功后发送一封邮件。编辑`blog`应用的`views.py`文件，添加以下代码：

```py
from .forms import EmailPostForm

def post_share(request, post_id):
	# Retrieve post by id
	post = get_object_or_404(Post, id=post_id, status='published')
	
	if request.method == 'POST':
		# Form was submitted
		form = EmailPostForm(request.POST)
		if form.is_valid():
			# Form fields passed validation
			cd = form.cleaned_data
			# ... send email
	else:
		form = EmailPostForm()
	return render(request, 
					'blog/post/share.html', 
					{'post': post, 'form': form})
```

该视图是这样工作的：

- 我们定义了`post_share`视图，接收`request`对象和`post_id`作为参数。
- 我们通过 ID，使用`get_object_or_404()`快捷方法检索状态为`published`的帖子。
- 我们使用同一个视图=显示初始表单和处理提交的数据。根据`request.method`区分表单是否提交。我们将使用`POST`提交表单。如果我们获得一个`GET`请求，需要显示一个空的表单；如果获得一个`POST`请求，表单会被提交，并且需要处理它。因此，我们使用`request.method == 'POST'`来区分这两种场景。

以下是显示和处理表单的过程：

1. 当使用`GET`请求初始加载视图时，我们创建了一个新的表单实例，用于在模板中显示空表单。

 `form = EmailPostForm()`

2. 用户填写表单，并通过`POST`提交。接着，我们使用提交的数据创建一个表单实例，提交的数据包括在`request.POST`中：
 ```py
 if request.POST == 'POST':
     # Form was submitted
     form = EmailPostForm(request.POST)
 ```

3. 接着，我们使用表单的`is_valid()`方法验证提交的数据。该方法会验证表单中的数据，如果所有字段都是有效数据，则返回`True`。如果任何字段包含无效数据，则返回`False`。你可以访问`form.errors`查看验证错误列表。
4. 如果表单无效，我们使用提交的数据在模板中再次渲染表单。我们将会在模板中显示验证错误。
5. 如果表单有效，我们访问`form.cleaned_data`获得有效的数据。该属性是表单字段和值的字典。

> 如果你的表单数据无效，`cleaned_data`只会包括有效的字段。

现在，你需要学习如何使用 Django 发送邮件，把所有功能串起来。

### 2.1.3 使用 Django 发送邮件

使用 Django 发送邮件非常简单。首先，你需要一个本地 SMTP 服务，或者在项目的`settings.py`文件中添加以下设置，定义一个外部 SMTP 服务的配置：

- `EMAIL_HOST`：SMTP 服务器地址。默认是`localhost`。
- `EMAIL_PORT`：SMTP 服务器端口，默认 25。
- `EMAIL_HOST_USER`：SMTP 服务器的用户名。
- `EMAIL_HOST_PASSWORD`：SMTP 服务器的密码。
- `EMAIL_USE_TLS`：是否使用 TLS 加密连接。
- `EMAIL_USE_SSL`：是否使用隐式 TLS 加密连接。

如果你没有本地 SMTP 服务，可以使用你的邮箱提供商的 SMTP 服务。下面这个例子中的配置使用 Google 账户发送邮件：

```py
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_HOST_USER = 'your_account@gmail.com'
EMAIL_HOST_PASSWORD = 'your_password'
EMAIL_PORT = 587
EMAIL_USE_TLS = True
```

运行`python manage.py shell`命令打开 Python 终端，如下发送邮件：

```py
>>> from django.core.mail import send_mail
>>> send_mail('Django mail', 'This e-mail was sent with Django',
'your_account@gmail.com', ['your_account@gmail.com'], 
fail_silently=False)
```

`send_mail()`的必填参数有：主题，内容，发送人，以及接收人列表。通过设置可选参数`fail_silently=False`，如果邮件不能正确发送，就会抛出异常。如果看到输出`1`，则表示邮件发送成功。如果你使用前面配置的 Gmail 发送邮件，你可能需要在[这里](https://www.google.com/settings/security/lesssecureapps)启用低安全级别应用访问权限。

现在，我们把它添加到视图中。编辑`blog`应用中`views.py`文件的`post_share`视图，如下所示：

```py
from django.core.mail import send_mail

def post_share(request, post_id):
	# Retrieve post by id
	post = get_object_or_404(Post, id=post_id, status='published')
	sent = False
	
	if request.method == 'POST':
		# Form was submitted
		form = EmailPostForm(request.POST)
		if form.is_valid():
			# Form fields passed validation
			cd = form.cleaned_data
			post_url = request.build_absolute_uri(post.get_absolute_url())
			subject = '{} ({}) recommends you reading "{}"'.format(cd['name'], cd['email'], post.title)
			message = 'Read "{}" at {}\n\n{}\'s comments: {}'.format(post.title, post_url, cd['name'], cd['comments'])
			send_mail(subject, message, 'admin@blog.com', [cd['to']])
			sent = True
	else:
		form = EmailPostForm()
	return render(request, 
		           'blog/post/share.html', 
		           {'post': post, 'form': form, 'sent': sent}) 
```

注意，我们声明了一个`sent`变量，当帖子发送后，设置为`True`。当表单提交成功后，我们用该变量在模板中显示一条成功的消息。因为我们需要在邮件中包含帖子的链接，所以使用了`get_absolute_url()`方法检索帖子的绝对路径。我们把这个路径作为`request.build_absolute_uri()`的输入，构造一个包括 HTTP 模式（schema）和主机名的完整 URL。我们使用验证后的表单数据构造邮件的主题和内容，最后发送邮件到表单`to`字段中的邮件地址。

现在，视图的开发工作已经完成，记得为它添加新的 URL 模式。打开`blog`应用的`urls.py`文件，添加`post_share`的 URL 模式：

```py
urlpatterns = [
	# ...
	url(r'^(?P<post_id>\d+)/share/$', views.post_share, name='post_share'),
]
```

### 2.1.4 在模板中渲染表单

完成创建表单，编写视图和添加 URL 模式后，我们只缺少该视图的模板了。在`blog/templates/blog/post/`目录中创建`share.html`文件，添加以下代码：

```py
{% extends "blog/base.html" %}

{% block title %}Share a post{% endblock %}

{% block content %}
	{% if sent %}
		<h1>E-mail successfully sent</h1>
		<p>
			"{{ post.title }}" was successfully sent to {{ cd.to }}.
		</p>
	{% else %}
		<h1>Share "{{ post.title }}" by e-mail</h1>
		<form action="." method="post">
			{{ form.as_p }}
			{% csrf_token %}
			<input type="submit" value="Send e-mail">
		</form>
	{% endif %}
{% endblock %}
```

这个模板用于显示表单，或者表单发送后的一条成功消息。正如你所看到的，我们创建了一个 HTML 表单元素，指定它需要使用`POST`方法提交：

```py
<form action="." method="post">
```

然后，我们包括了实际的表单实例。我们告诉 Django 使用`as_p`方法，在 HTML 的`<p>`元素中渲染表单的字段。我们也可以使用`as_ul`把表单渲染为一个无序列表，或者使用`as_table`渲染为 HTML 表格。如果你想渲染每一个字段，我们可以这样迭代字段：

```py
{% for field in form %}
	<div>
		{{ field.errors }}
		{{ field.label_tag }} {{ field }}
	</div>
{% endfor %}
```

模板标签`{% csrf_token %}`使用自动生成的令牌引入一个隐藏字段，以避免跨站点请求伪造（CSRF）的攻击。这些攻击包含恶意网站或程序，对你网站上的用户执行恶意操作。你可以在[这里](https://en.wikipedia.org/wiki/Cross-site_request_forgery)找到更多相关的信息。

上述标签生成一个类似这样的隐藏字段：

```py
<input type="hidden" name="csrfmiddlewaretoken" value="26JjKo2lcEtYkGoV9z4XmJIEHLXN5LDR" />
```

> 默认情况下，Django 会检查所有`POST`请求中的 CSRF 令牌。记得在所有通过`POST`提交的表单中包括`csrf_token`标签。

编辑`blog/post/detail.html`模板，在`{{ post.body|linebreaks }}`变量之后添加链接，用于分享帖子的 URL：

```py
<p>
	<a href="{% url "blog:post_share" post.id %}">
		Share this post
	</a>
</p>
```

记住，我们使用 Django 提供的`{% url %}`模板标签，动态生成 URL。我们使用名为`blog`命名空间和名为`post_share`的 URL，并传递帖子 ID 作为参数来构造绝对路径的 URL。

现在，使用`python manage.py runserver`命令启动开发服务器，并在浏览器中打开`http://127.0.0.1:8000/blog/`。点击任何一篇帖子的标题，打开详情页面。在帖子正文下面，你会看到我们刚添加的链接，如下图所示：

![](http://ooyedgh9k.bkt.clouddn.com/%E5%9B%BE2.1.png)

点击`Share this post`，你会看到一个包含表单的页面，该页面可以通过邮件分享帖子。如下图所示：

![](http://ooyedgh9k.bkt.clouddn.com/%E5%9B%BE2.2.png)

该表单的 CSS 样式在`static/css/blog.css`文件中。当你点击`Send e-mail`按钮时，该表单会被提交和验证。如果所有字段都是有效数据，你会看到一条成功消息，如下图所示：

![](http://ooyedgh9k.bkt.clouddn.com/%E5%9B%BE2.3.png)

如果你输入了无效数据，会再次渲染表单，其中包括了所有验证错误：

![](http://ooyedgh9k.bkt.clouddn.com/%E5%9B%BE2.4.png)

> **译者注：**不知道是因为浏览器不同，还是 Django 的版本不同，这里显示的验证错误跟原书中不一样。我用的是 Chrome 浏览器。

## 2.2 创建评论系统

现在，我们开始为博客构建评论系统，让用户可以评论帖子。要构建评论系统，你需要完成以下工作：

- 创建一个保存评论的模型
- 创建一个提交表单和验证输入数据的表单
- 添加一个视图，处理表单和保存新评论到数据库中
- 编辑帖子详情模板，显示评论列表和添加新评论的表单

首先，我们创建一个模型存储评论。打开`blog`应用的`models.py`文件，添加以下代码：

```py
class Comment(models.Model):
	post = models.ForeignKey(Post, related_name='comments')
	name = models.CharField(max_length=80)
	email = models.EmailField()
	body = models.TextField()
	created = models.DateTimeField(auto_now_add=True)
	updated = models.DateTimeField(auto_now=True)
	active = models.BooleanField(default=True)
	
	class Meta:
		ordering = ('created', )
		
	def __str__(self):
		return 'Comment by {} on {}'.format(self.name, self.post)
```

这就是我们的`Comment`模型。它包含一个外键，把评论与单篇帖子关联在一起。这个多对一的关系在`Comment`模型中定义，因为每条评论对应一篇帖子，而每篇帖子可能有多条评论。从关联对象反向到该对象的关系由`related_name`属性命名。定义这个属性后，我们可以使用`comment.post`检索评论对象的帖子，使用`post.comments.all()`检索帖子的所有评论。如果你没有定义`related_name`属性，Django 会使用模型名加`_set`（即`comment_set`）命名关联对象反向到该对象的管理器。

你可以在[这里](https://docs.djangoproject.com/en/1.11/topics/db/examples/many_to_one/)学习更多关于多对一的关系。

我们使用了`active`布尔字段，用于手动禁用不合适的评论。我们使用`created`字段排序评论，默认按时间排序。

刚创建的`Comment`模型还没有同步到数据库。运行以下命令，生成一个新的数据库迁移，反射创建的新模型：

```py
python manage.py makemigrations blog
```

你会看到以下输出：

```py
Migrations for 'blog'
  0002_comment.py:
    - Create model Comment
```

Django 在`blog`应用的`migrations/`目录中生成了`0002_comment.py`文件。现在，你需要创建一个相关的数据库架构，并把这些改变应用到数据库中。运行以下命令，让已存在的数据库迁移生效：

```py
python manage.py migrate
```

你会得到一个包括下面这一行的输出：

```py
Apply blog.0002_comment... OK
```

我们刚创建的数据库迁移已经生效，数据库中已经存在一张新的`blog_comment`表。

现在我们可以添加新的模型到管理站点，以便通过简单的界面管理评论。打开`blog`应用的`admin.py`文件，导入`Comment`模型，并增加`CommentAdmin`类：

```py
from .models import Post, Comment

class CommentAdmin(admin.ModelAdmin):
	list_display = ('name', 'email', 'post', 'created', 'active')
	list_filter = ('active', 'created', 'updated')
	search_fields = ('name', 'email', 'body')
admin.site.register(Comment, CommentAdmin)
```

使用`python manage.py runserver`命令启动开发服务器，并在浏览器中打开`http://127.0.0.1:8000/admin/`。你会在`Blog`中看到新的模型，如下图所示：

![](http://ooyedgh9k.bkt.clouddn.com/%E5%9B%BE2.5.png)

我们的模型已经在管理站点注册，并且可以使用简单的界面管理`Comment`实例。

### 2.2.1 通过模型创建表单

我们仍然需要创建一个表单，让用户可以评论博客的帖子。记住，Django 有两个基础类用来创建表单：`Form`和`ModelForm`。之前你使用了第一个，让用户可以通过邮件分享帖子。在这里，你需要使用`ModelForm`，因为你需要从`Comment`模型中动态的创建表单。编辑`blog`应用的`forms.py`文件，添加以下代码：

```py
from .models import Comment

class CommentForm(forms.ModelForm):
	class Meta:
		model = Comment
		fields = ('name', 'email', 'body')
```

要通过模型创建表单，我们只需要在表单的`Meta`类中指定，使用哪个模型构造表单。Django 自省模型，并动态的为我们创建表单。每种模型字段类型都有相应的默认表单字段类型。我们定义模型字段的方式考虑了表单的验证。默认情况下，Django 为模型中的每个字段创建一个表单字段。但是，你可以使用`fields`列表明确告诉框架，你想在表单中包含哪些字段，或者使用`exclude`列表定义你想排除哪些字段。对应`CommentForm`，我们只使用`name`，`email`，和`body`字段，因为用户只可能填写这些字段。

### 2.2.2 在视图中处理 ModelForm

为了简单，我们将会使用帖子详情页面实例化表单，并处理它。编辑`views.py`文件，导入`Comment`模型和`CommentForm`表单，并修改`post_detail`视图，如下所示：

> **译者注：**原书中是编辑`models.py`文件，应该是作者的笔误。

```py
from .models import Post, Comment
from .forms import EmailPostForm, CommentForm

def post_detail(request, year, month, day, post):
	post = get_object_or_404(Post, slug=post,
										 status='published',
										 publish__year=year,
										 publish__month=month,
										 publish__day=day)
	# List of active comments for this post
	comments = post.comments.filter(active=True)
	new_comment = None
	
	if request.method == 'POST':
		# A comment was posted
		comment_form = CommentForm(data=request.POST)
		if comment_form.is_valid():
			# Create Comment object but don't save to database yet
			new_comment = comment_form.save(commit=False)
			# Assign the current post to comment
			new_comment.post = post
			# Save the comment to the database
			new_comment.save()
	else:
		comment_form = CommentForm()
	return render(request, 
					 'blog/post/detail.html',
					 {'post': post,
					  'comments': comments,
					  'new_comment': new_comment,
					  'comment_form': comment_form})
```

让我们回顾一下，我们往视图里添加了什么。我们使用`post_detail`视图显示帖子和它的评论。我们添加了一个`QuerySet`，用于检索该帖子所有有效的评论：

```py
comments = post.comments.filter(active=True)
```

我们从`post`对象开始创建这个`QuerySet`。我们在`Comment`模型中使用`related_name`属性，定义了关联对象的管理器为`comments`。这里使用了这个管理器。

同时，我们使用同一个视图让用户添加新评论。因此，如果视图通过`GET`调用，我们使用`comment_form = CommentForm()`创建一个表单实例。如果是`POST`请求，我们使用提交的数据实例化表单，并使用`is_valid()`方法验证。如果表单无效，我们渲染带有验证错误的模板。如果表单有效，我们完成以下操作：

1. 通过调用表单的`save()`方法，我们创建一个新的`Comment`对象：

 `new_comment = comment_form.save(commit=False)`

 `save()`方法创建了一个链接到表单模型的实例，并把它存到数据库中。如果使用`commit=False`调用，则只会创建模型实例，而不会存到数据库中。当你想在存储之前修改对象的时候，会非常方便，之后我们就是这么做的。`save()`只对`ModelForm`实例有效，对`Form`实例无效，因为它们没有链接到任何模型。

2. 我们把当前的帖子赋值给刚创建的评论：

 `new_comment.post = post `

 通过这个步骤，我们指定新评论属于给定的帖子。

3. 最后，使用下面的代码，把新评论存到数据库中：

 `new_comment.save()`

现在，我们的视图已经准备好了，可以显示和处理新评论了。

### 2.2.3 在帖子详情模板中添加评论

我们已经为帖子创建了管理评论的功能。现在我们需要修改`blog/post/detail.html`模板，完成以下工作：

- 为帖子显示评论总数
- 显示评论列表
- 显示一个表单，用户增加评论

首先，我们会添加总评论数。打开`detail.html`模板，在`content`块中添加以下代码：

```py
{% with comments.count as total_comments %}
	<h2>
		{{ total_comments }} comment{{ total_comments|pluralize }}
	</h2>
{% endwith %}
```

我们在模板中使用 Django ORM 执行`comments.count()`这个`QuerySet`。注意，Django 模板语言调用方法时不带括号。`{% with %}`标签允许我们把值赋给一个变量，我们可以在`{% endwith %}`标签之前一直使用它。

> `{% with %}`模板标签非常有用，它可以避免直接操作数据库，或者多次调用昂贵的方法。

我们使用了`pluralize`模板过滤器，根据`total_comments`的值决定是否显示单词`comment`的复数形式。模板过滤器把它们起作用变量的值作为输入，并返回一个计算后的值。我们会在第三章讨论模板过滤器。

如果值不是 1，`pluralize`模板过滤器会显示一个“s”。上面的文本会渲染为`0 comments`，`1 comment`，或者`N comments`。Django 包括大量的模板标签和过滤器，可以帮助你以希望的方式显示信息。

现在，让我们添加评论列表。在上面代码后面添加以下代码：

```py
{% for comment in comments %}
	<div class="comment">
		<p class="info">
			Comment {{ forloop.counter }} by {{ comment.name }}
			{{ comment.created }}
		</p>
		{{ comment.body|linebreaks }}
	</div>
{% empty %}
	<p>There are no comments yet.</p>
{% endfor %}
```

我们使用`{% for %}`模板标签循环所有评论。如果`comments`列表为空，显示一个默认消息，告诉用户该帖子还没有评论。我们使用`{{ forloop.counter }}`变量枚举评论，它包括每次迭代中循环的次数。然后我们显示提交评论的用户名，日期和评论的内容。

最后，当表单成功提交后，我们需要渲染表单，或者显示一条成功消息。在上面的代码之后添加以下代码：

```py
{% if new_comment %}
	<h2>Your comment has been added.</h2>
{% else %}
	<h2>Add a new comment</h2>
	<form action="." method="post">
		{{ comment_form.as_p }}
		{% csrf_token %}
		<p><input type="submit" value="Add comment"></p>
	</form>
{% endif %}
```

代码非常简单：如果`new_comment`对象存在，则显示一条成功消息，因为已经创建评论成功。否则渲染表单，每个字段使用一个`<p>`元素，以及`POST`请求必需的 CSRF 令牌。在浏览器中打开`http://127.0.0.1:8000/blog/`，点击一条帖子标题，打开详情页面，如下图所示：

![](http://ooyedgh9k.bkt.clouddn.com/%E5%9B%BE2.6.png)

使用表单添加两条评论，它们会按时间顺序显示在帖子下方，如下图所示：

![](http://ooyedgh9k.bkt.clouddn.com/%E5%9B%BE2.7.png)

在浏览器中打开`http://127.0.0.1:8000/admin/blog/comment/`，你会看到带有刚创建的评论列表的管理页面。点击某一条编辑，不选中`Active`选择框，然后点击`Save`按钮。你会再次被重定向到评论列表，该评论的`Active`列会显示一个禁用图标。类似下图的第一条评论：

![](http://ooyedgh9k.bkt.clouddn.com/%E5%9B%BE2.8.png)

如果你回到帖子详情页面，会发现被删除的评论没有显示；同时也没有算在评论总数中。多亏了`active`字段，你可以禁用不合适的评论，避免它们在帖子中显示。

## 2.3 增加标签功能

实现评论系统之后，我们准备为帖子添加标签。我们通过在项目中集成一个第三方的 Django 标签应用，来实现这个功能。`django-taggit`是一个可复用的应用，主要提供了一个`Tag`模型和一个管理器，可以很容易的为任何模型添加标签。你可以在[这里](https://github.com/alex/django-taggit)查看它的源码。

首先，你需要通过`pip`安装`django-taggit`，运行以下命令：

```py
pip install django-taggit
```

然后打开`mysite`项目的`settings.py`文件，添加`taggit`到`INSTALLED_APPS`设置中：

```py
INSTALLED_APPS = (
	# ...
	'blog',
	'taggit',
)
```

打开`blog`应用的`models.py`文件，添加`django-taggit`提供的`TaggableManager`管理器到`Post`模型：

```py
from taggit.managers import TaggableManager

class Post(models.Model):
	# ...
	tags = TaggableManager()
```

`tags`管理器允许你从`Post`对象中添加，检索和移除标签。

运行以下命令，为模型改变创建一个数据库迁移：

```py
python manage.py makemigrations blog
```

你会看下以下输出：

```py
Migrations for 'blog'
  0003_post_tags.py:
    - Add field tags to post
```

现在，运行以下命令创建`django-taggit`模型需要的数据库表，并同步模型的变化：

```py
python manage.py migrate
```

你会看到迁移数据库生效的输入，如下所示：

```py
Applying taggit.0001_initial... OK
Applying taggit.0002_auto_20150616_2121... OK
Applying blog.0003_post_tags... OK
```

你的数据库已经为使用`django-taggit`模型做好准备了。使用`python manage.py shell`打开终端，学习如何使用`tags`管理器。

首先，我检索其中一个帖子（ID 为 3 的帖子）：

```py
>>> from blog.models import Post
>>> post = Post.objects.get(id=3)
```

接着给它添加标签，并检索它的标签，检查是否添加成功：

```py
>>> post.tags.add('music', 'jazz', 'django')
>>> post.tags.all()
[<Tag: jazz>, <Tag: django>, <Tag: music>]
```

最后，移除一个标签，并再次检查标签列表：

```py
>>> post.tags.remove('django')
>>> post.tags.all()
[<Tag: jazz>, <Tag: music>]
```

这很容易，对吧？运行`python manage.py runserver`，再次启动开发服务器，并在浏览器中打开`http://127.0.0.1:8000/admin/taggit/tag/`。你会看到`taggit`应用管理站点，其中包括`Tag`对象的列表：

![](http://ooyedgh9k.bkt.clouddn.com/%E5%9B%BE2.9.png)

导航到`http://127.0.0.1:8000/admin/blog/post/`，点击一条帖子编辑。你会看到，现在帖子包括一个新的`Tags`字段，如下图所示，你可以很方便的编辑标签：

![](http://ooyedgh9k.bkt.clouddn.com/%E5%9B%BE2.10.png)

现在，我们将会编辑博客帖子，来显示标签。打开`blog/post/list.html`模板，在帖子标题下面添加以下代码：

```py
<p class="tags">Tags: {{ post.tags.all|join:", " }}</p>
```

模板过滤器`join`与 Python 字符串的`join()`方法类似，用指定的字符串连接元素。在浏览器中打开`http://127.0.0.1:8000/blog/`。你会看到每篇帖子标题下方有标签列表：

![](http://ooyedgh9k.bkt.clouddn.com/%E5%9B%BE2.11.png)

现在，我们将要编辑`post_list`视图，为用户列出具有指定标签的所有帖子。打开`blog`应用的`views.py`文件，从`django-taggit`导入`Tag`模型，并修改`post_list`视图，可选的通过标签过滤帖子：

```py
from taggit.models import Tag

def post_list(request, tag_slug=None):
	object_list = Post.published.all()
	tag = None
	
	if tag_slug:
		tag = get_object_or_404(Tag, slug=tag_slug)
		object_list = object_list.filter(tags__in=[tag])
		# ...
```

该视图是这样工作的：

1. 该视图接收一个默认值为`None`的可选参数`tag_slug`。该参数会在 URL 中。
2. 在视图中，我们创建了初始的`QuerySet`，检索所有已发布的帖子，如果给定了标签别名，我们使用`get_object_or_404()`快捷方法获得给定别名的`Tag`对象。
3. 然后，我们过滤包括给定标签的帖子列表。因为这是一个多对多的关系，所以我们需要把过滤的标签放在指定列表中，在这个例子中只包含一个元素。

记住，`QeurySet`是懒惰的。这个`QuerySet`只有在渲染模板时，循环帖子列表时才会计算。

最后，修改视图底部的`render()`函数，传递`tag`变量到模板中。视图最终是这样的：

```py
def post_list(request, tag_slug=None):
	object_list = Post.published.all()
	tag = None
	
	if tag_slug:
		tag = get_object_or_404(Tag, slug=tag_slug)
		object_list = object_list.filter(tags__in=[tag])
		
	paginator = Paginator(object_list, 3)
	page = request.GET.get('page')
	try:
		posts = paginator.page(page)
	except PageNotAnInteger:
		posts = paginator.page(1)
	excpet EmptyPage:
		posts = paginator.page(paginator.num_pages)
	return render(request,
					 'blog/post/list.html',
					 {'page': page,
					  'posts': posts,
					  'tag': tag})
```

打开`blog`应用的`urls.py`文件，注释掉基于类`PostListView`的 URL 模式，取消`post_list`视图的注释：

```py
url(r'^$', views.post_list, name='post_list'),
# url(r'^$', views.PostListView.as_view(), name='post_list'),
```

添加以下 URL 模式，通过标签列出帖子：

```py
url(r'^tag/(?P<tag_slug>[-\w]+)/$', views.post_list,
    name='post_list_by_tag'),
```

正如你所看到的，两个模式指向同一个视图，但是名称不一样。第一个模式不带任何可选参数调用`post_list`视图，第二个模式使用`tag_slug`参数调用视图。

因为我们使用的是`post_list`视图，所以需要编辑`blog/post/list.hmlt`模板，修改`pagination`使用`posts`参数：

```py
{% include "pagination.html" with page=posts %}
```

在`{% for %}`循环上面添加以下代码：

```py
{% if tag %}
	<h2>Posts tagged with "{{ tag.name }}"</h2>
{% endif %}
```

如果用户正在访问博客，他会看到所有帖子列表。如果他通过指定标签过滤帖子，就会看到这个信息。现在，修改标签的显示方式：

```py
<p class="tag">
	Tags:
	{% for tag in post.tags.all %}
		<a href="{% url "blog:post_list_by_tag" tag.slug %}">
			{{ tag.name }}
		</a>
	{% if not forloop.last %}, {% endif %}
	{% endfor %}
</p>
```

现在，我们循环一篇帖子的所有标签，显示一个自定义链接到 URL，以便使用该便签过滤帖子。我们用`{% url "blog:post_list_by_tag" tag.slug %}`构造 URL，把 URL 名和标签的别名作为参数。我们用逗号分隔标签。

在浏览器中打开`http://127.0.0.1:8000/blog/`，点击某一个标签链接。你会看到由该标签过滤的帖子列表：

![](http://ooyedgh9k.bkt.clouddn.com/%E5%9B%BE2.12.png)

## 2.4 通过相似度检索帖子

现在，我们已经为博客帖子添加了标签，我们还可以用标签做更多有趣的事。通过便签，我们可以很好的把帖子分类。主题类似的帖子会有几个共同的标签。我们准备增加一个功能：通过帖子共享的标签数量来显示类似的帖子。在这种情况下，当用户阅读一篇帖子的时候，我们可以建议他阅读其它相关帖子。

为某个帖子检索相似的帖子，我们需要：

- 检索当前帖子的所有标签。
- 获得所有带这些便签中任何一个的帖子。
- 从列表中排除当前帖子，避免推荐同一篇帖子。
- 通过和当前帖子共享的标签数量来排序结果。
- 如果两篇或以上的帖子有相同的标签数量，推荐最近发布的帖子。
- 限制我们想要推荐的帖子数量。

这些步骤转换为一个复杂的`QuerySet`，我们需要在`post_detail`视图中包含它。打开`blog`应用的`views.py`文件，在顶部添加以下导入：

```py
from django.db.models import Count
```

这是 Django ORM 的`Count`汇总函数。此函数允许我们执行汇总计数。然后在`post_detail`视图的`render()`函数之前添加以下代码：

```py
# List of similar posts
post_tags_ids = post.tags.values_list('id', flat=True)
similar_posts = Post.published.filter(tags__in=post_tags_ids)\
									.exclude(id=post.id)
similar_posts = similar_posts.annotate(same_tags=Count('tags'))\
                             .order_by('-same_tags', '-publish')[:4]
```

这段代码完成以下操作：

1. 我们获得一个包含当前帖子所有标签的 ID 列表。`values_list()`这个`QuerySet`返回指定字段值的元组。我们传递`flat=True`给它，获得一个`[1, 2, 3, ...]`的列表。
2. 我们获得包含这些标签中任何一个的所有帖子，除了当前帖子本身。
3. 我们使用`Count`汇总函数生成一个计算后的字段`same_tags`，它包含与所有查询标签共享的标签数量。
4. 我们通过共享的标签数量排序结果（降序），共享的标签数量相等时，用`publish`优先显示最近发布的帖子。我们对结果进行切片，只获取前四篇帖子。

为`render()`函数添加`similar_posts`对象到上下文字典中：

```py
return render(request,
              'blog/post/detail.html',
              {'post': post,
               'comments': comments,
               'new_comment':new_comment,
               'comment_form': comment_form,
               'similar_posts': similar_posts})
```

现在，编辑`blog/post/detail.html`模板，在帖子的评论列表前添加以下代码：

```py
<h2>Similar posts</h2>
{% for post in similar_posts %}
	<p>
		<a href="{{ post.get_absolute_url }}">{{ post.title }}</a>
	</p>
{% empty %}
	There are no similar post yet.
{% endfor %}
```

推荐你在帖子详情模板中也添加标签列表，就跟我们在帖子列表模板中所做的那样。现在，你的帖子详情页面应该看起来是这样的：

![](http://ooyedgh9k.bkt.clouddn.com/%E5%9B%BE2.13.png)

> **译者注：**需要给其它帖子添加标签，才能看到上图所示的相似的帖子。

你已经成功的推荐了相似的帖子给用户。`django-taggit`也包含一个`similar_objects()`管理器，可以用来检索共享的标签。你可以在[这里](http://django-taggit.readthedocs.org/en/latest/api.html)查看所有`django-taggit`管理器。
    
## 2.5 总结

在这一章中，你学习了如何使用 Django 表单和模型表单。你创建了一个可以通过邮件分享网站内容的系统，还为博客创建了评论系统。你为帖子添加了标签，集成了一个可复用的应用，并创建了一个复杂的`QuerySet`，通过相似度检索对象。

下一章中，你会学习如何创建自定义模板标签和过滤器。你还会构建一个自定义的站点地图和帖子的 RSS 源，并在应用中集成一个高级的搜索引擎。

























# 第三章：扩展你的博客应用

上一章介绍了标签的基础知识，你学会了如何在项目中集成第三方应用。本章将会涉及以下知识点：

- 创建自定义模板标签和过滤器
- 添加站点地图和帖子订阅
- 使用 Solr 和 Haystack 构建搜索引擎

## 3.1 创建自定义模板标签和过滤器

Django 提供了大量内置的模板标签，比如`{% if %}`，`{% block %}`。你已经在模板中使用过几个了。你可以在[这里](https://docs.djangoproject.com/en/1.11/ref/templates/builtins/)找到所有内置的模板标签和过滤器。

当然，Django 也允许你创建自定义模板标签来执行操作。当你需要在模板中添加功能，而 Django 模板标签不满足需求时，自定义模板标签会非常方便。

### 3.1.1 创建自定义模板标签

Django 提供了以下帮助函数，让你很容易的创建自定义模板标签：

- `simple_tag`：处理数据，并返回一个字符串。
- `inclusion_tag`：处理数据，并返回一个渲染后的模板。
- `assignment_tag`：处理数据，并在上下文中设置一个变量。

模板标签必须存在 Django 应用中。

在`blog`应用目录中，创建`templatetags`目录，并在其中添加一个空的`__init__.py`文件和一个`blog_tags.py`文件。博客应用的目录看起来是这样的：

```py
blog/
	__init__.py
	models.py
	...
	templatetags/
		__init__.py
		blog_tags.py
```

文件名非常重要。你将会在模板中使用该模块名来加载你的标签。

我们从创建一个`simple_tag`标签开始，该标签检索博客中已发布的帖子总数。编辑刚创建的`blog_tags.py`文件，添加以下代码：

```py
from django import template

register = template.Library()

from ..models import Post

@register.simple_tag
def total_posts():
	return Post.published.count()
```

我们创建了一个简单的模板标签，它返回已发布的帖子数量。每一个模板标签模块想要作为一个有效的标签库，都需要包含一个名为`register`的变量。该变量是一个`template.Library`的实例，用于注册你自己的模板标签和过滤器。然后我们使用 Python 函数定义了一个名为`total_posts`的标签，并使用`@register.simple_tag`定义该函数为一个`simple_tag`，并注册它。Django 将会使用函数名作为标签名。如果你想注册为另外一个名字，可以通过`name`属性指定，比如`@register.simple_tag(name='my_tag')`。

> 添加新模板标签模块之后，你需要重启开发服务器，才能使用新的模板标签和过滤器。

使用自定义模板标签之前，你必须使用`{% load %}`标签让它们在模板中生效。像之前提到的，你需要使用包含模板标签和过滤器的 Python 模块名。打开`blog/base.html`模板，在顶部添加`{% load blog_tags %}`，来加载你的模板标签模块。然后使用创建的标签显示帖子总数。只需要在模板中添加`{% total_posts %}`。最终，该模板看起来是这样的：

```py
{% load blog_tags %}
{% load staticfiles %}
<!DOCTYPE html>
<html>
<head>
    <title>{% block title %}{% endblock %}</title>
    <link href="{% static "css/blog.css" %}" rel="stylesheet">
</head>
<body>
    <div id="content">
        {% block content %}
        {% endblock %}
    </div>
    <div id="sidebar">
        <h2>My blog</h2>
        <p>This is my blog. I've written {% total_posts %} posts so far.</p>
    </div>
</body>
</html>
```

因为在项目中添加了新文件，所以需要重启开发服务器。运行`python manage.py runserver`启动开发服务器。在浏览器中打开`http://127.0.0.1:8000/blog/`。你会在侧边栏中看到帖子的总数量，如下图所示：

![](http://ooyedgh9k.bkt.clouddn.com/%E5%9B%BE3.1.png)

自定义模板标签的强大之处在于，你可以处理任意数据，并把它添加到任意模板中，不用管视图如何执行。你可以执行`QuerySet`或处理任意数据，并在模板中显示结果。

现在，我们准备创建另一个标签，在博客侧边栏中显示最近发布的帖子。这次我们使用`inclusion_tag`标签。使用该标签，可以利用你的模板标签返回的上下文变量渲染模板。编辑`blog_tags.py`文件，添加以下代码：

```py
@register.inclusion_tag('blog/post/latest_posts.html')
def show_latest_posts(count=5):
	latest_posts = Post.published.order_by('-publish')[:count]
	return {'latest_posts': latest_posts}
```

在这段代码中，我们使用`@register.inclusion_tag`注册模板标签，并用该模板标签的返回值渲染`blog/post/latest_posts.html`模板。我们的模板标签接收一个默认值为 5 的可选参数`count`，用于指定想要显示的帖子数量。我们用该变量限制`Post.published.order_by('-publish')[:count]`查询返回的结果。注意，该函数返回一个字典变量，而不是一个简单的值。`Inclusion`标签必须返回一个字典值作为上下文变量，来渲染指定的模板。`Inclusion`标签返回一个字典。我们刚创建的模板标签可以传递一个显示帖子数量的可选参数，比如`{% show_latest_posts 3 %}`。

现在，在`blog/post/`目录下新建一个`latest_posts.html`文件，添加以下代码：

```py
<ul>
{% for post in latest_posts %}
	<li>
		<a href="{{ post.get_absolute_url }}">{{ post.title }}</a>
	</li>
{% endfor %}
</ul>
```

在这里，我们用模板标签返回的`latest_posts`变量显示一个帖子的无序列表。现在，编辑`blog/base.html`模板，添加新的模板标签，显示最近 3 篇帖子，如下所示：

```py
<div id="sidebar">
	<h2>My blog</h2>
	<p>This is my blog. I've written {% total_posts %} posts so far.</p>
	<h3>Latest posts</h3>
	{% show_latest_posts 3 %}
</div>
```

通过传递显示的帖子数量调用模板标签，并用给定的上下文在原地渲染模板。

现在回到浏览器，并刷新页面。侧边栏现在看起来是这样的：

![](http://ooyedgh9k.bkt.clouddn.com/%E5%9B%BE3.2.png)

最后，我们准备创建一个`assignment`标签。`Assignment`标签跟`simple`标签很像，它们把结果存在指定的变量中。我们会创建一个`assignment`标签，用于显示评论最多的帖子。编辑`blog_tags.py`文件，添加以下导入和模板标签：

```py
from django.db.models import Count

@register.assignment_tag
def get_most_commented_posts(count=5):
	return Post.published.annotate(total_comments=Count('comments')).order_by('-total_comments')[:count]
```

这个`QuerySet`使用了`annotate()`函数，调用`Count`汇总函数进行汇总查询。我们构造了一个`QuerySet`，在`totaol_comments`字段中汇总每篇帖子的评论数，并用该字段对`QeurySet`排序。我们还提供了一个可选变量`count`，限制返回的对象数量。

除了`Count`，Django 还提供了`Avg`，`Max`，`Min`，`Sum`汇总函数。你可以在[这里](https://docs.djangoproject.com/en/1.11/topics/db/aggregation/)阅读更多关于汇总函数的信息。

编辑`blog/base.html`模板，在侧边栏的`<div>`元素中添加以下代码：

```py
<h3>Most commented posts</h3>
{% get_most_commented_posts as most_commented_posts %}
<ul>
{% for post in most_commented_posts %}
	<li>
		<a href="{{ post.get_absolute_url }}">{{ post.title }}</a>
	</li>
{% endfor %}
</ul>
```

`Assignment`模板标签的语法是`{% template_tag as variable %}`。对于我们这个模板标签，我们使用`{% get_most_commented_posts as most_commented_posts %}`。这样，我们就在名为`most_commented_posts`的变量中存储了模板标签的结果。接着，我们用无序列表显示返回的帖子。

现在，打开浏览器，并刷新页面查看最终的结果，如下所示：

![](http://ooyedgh9k.bkt.clouddn.com/%E5%9B%BE3.3.png)

你可以在[这里](https://docs.djangoproject.com/en/1.11/howto/custom-template-tags/)阅读更多关于自定义模板标签的信息。

### 3.1.2 创建自定义模板过滤器

Django 内置了各种模板过滤器，可以在模板中修改变量。过滤器就是接收一个或两个参数的 Python 函数——一个是它要应用的变量的值，以及一个可选参数。它们返回的值可用于显示，或者被另一个过滤器处理。一个过滤器看起来是这样的：`{{ variable|my_filter }}`，或者传递一个参数：`{{ variable|my_filter:"foo" }}`。你可以在一个变量上应用任意多个过滤器：`{{ variable|filter1|filter2 }}`，每个过滤器作用于前一个过滤器产生的输出。

我们将创建一个自定义过滤器，可以在博客帖子中使用`markdown`语法，然后在模板中把帖子内容转换为 HTML。`Markdown`是一种纯文本格式化语法，使用起来非常简单，并且可以转换为 HTML。你可以在[这里](http://daringfireball.net/projects/markdown/basics)学习该格式的基本语法。

首先，使用下面的命令安装 Python 的`markdown`模块：

```py
pip install Markdown
```

接着，编辑`blog_tags.py`文件，添加以下代码：

```py
from django.utils.safestring import mark_safe
import markdown

@register.filter(name='markdown')
def markdown_format(text):
	return mark_safe(markdown.markdown(text))
```

我们用与模板标签同样的方式注册模板过滤器。为了避免函数名和`markdown`模块名的冲突，我们将函数命名为`markdown_format`，把过滤器命名为`markdown`，在模板中这样使用：`{{ variable|markdown }}`。Django 会把过滤器生成的 HTML 代码转义。我们使用 Django 提供的`mark_safe`函数，把要在模板中渲染的结果标记为安全的 HTML 代码。默认情况下，Django 不会信任任何 HTML 代码，并且会在输出结果之前进行转义。唯一的例外是标记为安全的转义变量。这种行为可以阻止 Django 输出有潜在危险的 HTML 代码；同时，当你知道返回的是安全的 HTML 代码时，允许这种例外情况发生。

现在，在帖子列表和详情模板中加载你的模板标签。在`post/list.html`和`post/detail.html`模板的`{% extends %}`标签之后添加下面这行代码：

```py
{% load blog_tags %}
```

在`post/detail.html`模板中，把这一行：

```py
{{ post.body|linebreaks }}
```

替换为：

```py
{{ post.body|markdown }}
```

接着，在`post/list.html`模板中，把这一行：

```py
{{ post.body|truncatewords:30|linebreaks }}
```

替换为：

```py
{{ post.body|markdown|truncatewords_html:30 }}
```

过滤器`truncatewords_html`会在指定数量的单词之后截断字符串，并避免没有闭合的 HTML 标签。

现在，在浏览器中打开`http://127.0.0.1:8000/admin/blog/post/add/`，并用下面的正文添加一篇帖子：

```py
This is a post formatted with markdown
--------------------------------------

*This is emphasized* and **this is more emphasized**.

Here is a list:

* One
* Two
* Three

And a [link to the Django website](https://www.djangoproject.com/)
```

打开浏览器，看看帖子是如何渲染的，如下图所示：

![](http://ooyedgh9k.bkt.clouddn.com/%E5%9B%BE3.4.png)

正如你所看到的，自定义模板过滤器对自定义格式非常有用。你可以在[这里](https://docs.djangoproject.com/en/1.11/howto/custom-template-tags/#writing-custom-template-filters)查看更多自定义过滤器的信息。

## 3.2 为站点添加站点地图

Django 自带一个站点地图框架，可以为站点动态生成站点地图。站点地图是一个 XML 文件，告诉搜索引擎你的网站有哪些页面，它们之间的关联性，以及更新频率。使用站点地图，可以帮助网络爬虫索引网站的内容。

Django 的站点地图框架依赖`django.contrib.sites`，它允许你将对象关联到在项目中运行的指定网站。当你用单个 Django 项目运行多个站点时，会变得非常方便。要安装站点地图框架，我们需要在项目中启用`sites`和`sitemap`两个应用。编辑项目的`settings.py`文件，并在`INSTALLED_APPS`设置中添加`django.contrib.sites`和`django.contrib.sitemaps`。同时为站点 ID 定义一个新的设置，如下所示：

```py
SITE_ID = 1

INSTALLED_APPS = [
	# ...
	'django.contrib.sites',
	'django.contrib.sitemaps',
]
```

现在，运行以下命令，在数据库中创建`sites`应用的数据库表：

```py
python manage.py migrate
```

你会看到包含这一行的输出：

```py
Applying sites.0001_initial... OK
```

现在，`sites`应用与数据库同步了。在`blog`应用目录中创建`sitemaps.py`文件，添加以下代码：

```py
from django.contrib.sitemaps import Sitemap
from .models import Post

class PostSitemap(Sitemap):
	changefreq = 'weekly'
	priority = 0.9
	
	def items(self):
		return Post.published.all()
		
	def lastmod(self, obj):
		return obj.publish
```

我们创建了一个自定义的站点地图，它继承自`sitemaps`模块的`Sitemap`类。`changefreq`和`priority`属性表示帖子页面的更新频率和它们在网站中的关联性（最大值为 1）。`items()`方法返回这个站点地图中包括的对象的`QuerySet`。默认情况下，Django 调用每个对象的`get_absolute_url()`方法获得它的 URL。记住，我们在第一章创建了该方法，用于获得帖子的标准 URL。如果你希望为每个对象指定 URL，可以在站点地图类中添加`location`方法。`lastmod`方法接收`items()`返回的每个对象，并返回该对象的最后修改时间。`changefreq`和`priority`既可以是方法，也可以是属性。你可以在[官方文档](https://docs.djangoproject.com/en/1.11/ref/contrib/sitemaps/)中查看完整的站点地图参考。

最后，我们只需要添加站点地图的 URL。编辑项目的`urls.py`文件，添加站点地图：

```py
from django.conf.urls import include, url
from django.contrib import admin
from django.contrib.sitemaps.views import sitemap 
from blog.sitemaps import PostSitemap

sitemaps = {
	'posts': PostSitemap,
}

urlpatterns = [
	url(r'^admin/', include(admin.site.urls)),
	url(r'^blog/', 
		include('blog.urls'namespace='blog', app_name='blog')),
	url(r'^sitemap\.xml$', sitemap, {'sitemaps': sitemaps},
		name='django.contrib.sitemaps.views.sitemap'),
]
```

我们在这里包括了必需的导入，并定义了一个站点地图的字典。我们定义了一个匹配`sitemap.xml`的 URL 模式，并使用`sitemap`视图。把`sitemaps`字典传递给`sitemap`视图。在浏览器中打开`http://127.0.0.1:8000/sitemap.xml`，你会看到类似这样的 XML 代码：

```py
<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
	<url>
		<loc>http://example.com/blog/2017/04/28/markdown-post/</loc>
		<lastmod>2017-04-28</lastmod>
		<changefreq>weekly</changefreq>
		<priority>0.9</priority>
	</url>
	<url>
		<loc>http://example.com/blog/2017/04/25/one-more-again/</loc>
		<lastmod>2017-04-25</lastmod>
		<changefreq>weekly</changefreq>
		<priority>0.9</priority>
	</url>
	...
</urlset>
```

通过调用`get_absolute_url()`方法，为每篇帖子构造了 URL。我们在站点地图中指定了，`lastmod`属性对应帖子的`publish`字段，`changefreq`和`priority`属性也是从`PostSitemap`中带过来的。你可以看到，用于构造 URL 的域名是`example.com`。该域名来自数据库中的`Site`对象。这个默认对象是在我们同步`sites`框架数据库时创建的。在浏览器中打开`http://127.0.0.1/8000/admin/sites/site/`，如下图所示：

![](http://ooyedgh9k.bkt.clouddn.com/%E5%9B%BE3.5.png)

这是`sites`框架的管理视图显示的列表。你可以在这里设置`sites`框架使用的域名或主机，以及依赖它的应用。为了生成存在本机环境中的 URL，需要把域名修改为`127.0.0.1:8000`，如下图所示：

![](http://ooyedgh9k.bkt.clouddn.com/%E5%9B%BE3.6.png)

为了方便开发，我们指向了本机。在生产环境中，你需要为`sites`框架使用自己的域名。

## 3.3 为博客帖子创建订阅

Django 内置一个聚合订阅（syndication feed）框架，可以用来动态生成 RSS 或 Atom 订阅，与用`sites`框架创建站点地图的方式类似。

在`blog`应用目录下创建一个`feeds.py`文件，添加以下代码：

```py
from django.contrib.syndication.views import Feed
from django.template.defaultfilters import truncatewords
from .models import Post

class LatestPostsFeed(Feed):
	title = 'My blog'
	link = '/blog/'
	description = 'New posts of my blog.'
	
	def items(self):
		return Post.published.all()[:5]
		
	def item_title(self, item):
		return item.title
		
	def item_description(self, item):
		return truncatewords(item.body, 30)
```

首先，我们从`syndication`框架的`Feed`类继承。`title`，`link`，`description`属性分别对应 RSS 的`<title>`，`<link>`，`<description>`元素。

`items()`方法获得包括在订阅中的对象。我们只检索最近发布的五篇帖子。`item_title()`和`item_description()`方法接收`items()`返回的每一个对象，并返回每一项的标题和描述。我们用内置的`truncatewords`模板过滤器截取前 30 个单词，用于构造博客帖子的描述。

现在编辑`blog`应用的`urls.py`文件，导入刚创建的`LatestPostsFeed`，并在新的 URL 模式中实例化：

```py
from .feeds import LatestPostsFeed

urlpatterns = [
	# ...
	url(r'^feed/$', LatestPostsFeed(), name='post_feed'),
]
```

在浏览器中打开`http://127.0.0.1:8000/blog/feed/`，你会看到 RSS 订阅包括了最近五篇博客帖子：

```py
<?xml version="1.0" encoding="utf-8"?>
<rss xmlns:atom="http://www.w3.org/2005/Atom" version="2.0">
	<channel>
		<title>My blog</title>
		<link>http://127.0.0.1:8000/blog/</link>
		<description>New posts of my blog</description>
		<atom:link href="http://127.0.0.1:8000/blog/feed/" rel="self"></atom:link>
		<language>en-us</language>
		<lastBuildDate>Fri, 28 Apr 2017 05:44:43 +0000</lastBuildDate>
		<item>
			<title>One More Again</title>
			<link>http://127.0.0.1:8000/blog/2017/04/25/one-more-again/</link>
			<description>Post body.</description>
			<guid>http://127.0.0.1:8000/blog/2017/04/25/one-more-again/</guid>
		</item>
		<item>
			<title>Another Post More</title>
			<link>http://127.0.0.1:8000/blog/2017/04/25/another-post-more/</link>
			<description>Post body.</description>
			<guid>http://127.0.0.1:8000/blog/2017/04/25/another-post-more/</guid>
		</item>
		...
	</channel>
</rss>
```

如果你在 RSS 客户端中打开这个 URL，你会看到一个用户界面友好的订阅。

最后一步是在博客的侧边栏添加一个订阅链接。打开`blog/base.html`模板，在侧边栏`<div>`的帖子总数后面添加这一行代码：

```py
<p><a href="{% url "blog:post_feed" %}">Subscribe to my RSS feed</a></p>
```

现在，在浏览器中打开`http://127.0.0.1:8000/blog/`，你会看到如下图所示的侧边栏：

![](http://ooyedgh9k.bkt.clouddn.com/%E5%9B%BE3.7.png)

## 3.4 使用 Solr 和 Haystack 添加搜索引擎

> **译者注：**暂时跳过这一节的翻译，对于一般的博客，实在是用不上搜索引擎。

## 3.5 总结

在这一章中，你学习了如何创建自定义 Django 模板标签和过滤器，为模板提供自定义的功能。你还创建了站点地图，便于搜索引擎爬取你的网站，以及一个 RSS 订阅，便于用户订阅。同时，你在项目中使用 Haystack 集成了 Solr，为博客构建了一个搜索引擎。

在下一章，你会学习如何使用 Django 的`authentication`构建社交网站，创建自定义的用户资料，以及社交认证。



























