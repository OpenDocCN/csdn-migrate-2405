# 精通 Django（五）

> 原文：[`zh.annas-archive.org/md5/0D7AA9BDBF4A402F69CD832FB5D17FA6`](https://zh.annas-archive.org/md5/0D7AA9BDBF4A402F69CD832FB5D17FA6)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十三章：部署 Django

本章涵盖了构建 Django 应用程序的最后一个基本步骤：将其部署到生产服务器。

如果您一直在跟着我们的示例，您可能一直在使用 `runserver`，这使得事情变得非常容易-使用 `runserver`，您不必担心 web 服务器的设置。但是 `runserver` 仅适用于在本地机器上进行开发，而不适用于在公共网络上暴露。

要部署您的 Django 应用程序，您需要将其连接到像 Apache 这样的工业级 Web 服务器。在本章中，我们将向您展示如何做到这一点-但首先，我们将为您提供一个在您上线之前在您的代码库中要做的事情的清单。

# 为生产准备您的代码库

## 部署清单

互联网是一个敌对的环境。在部署 Django 项目之前，您应该花些时间审查您的设置，考虑安全性、性能和操作。

Django 包含许多安全功能。有些是内置的并且始终启用。其他是可选的，因为它们并不总是合适的，或者因为它们对开发来说不方便。例如，强制使用 HTTPS 可能不适用于所有网站，并且对于本地开发来说是不切实际的。

性能优化是另一类便利性的权衡。例如，在生产中缓存很有用，但在本地开发中不那么有用。错误报告的需求也是非常不同的。以下清单包括以下设置：

+   必须正确设置才能让 Django 提供预期的安全级别，

+   在每个环境中都有所不同，

+   启用可选的安全功能，

+   启用性能优化；和，

+   提供错误报告。

许多这些设置是敏感的，应该被视为机密。如果您发布项目的源代码，一个常见的做法是发布适合开发的设置，并为生产使用私有设置模块。可以使用所描述的检查来自动化以下检查

`-deploy` 选项的 `check` 命令。务必根据选项的文档描述运行它针对您的生产设置文件。

# 关键设置

## SECRET_KEY

**秘钥必须是一个大的随机值，并且必须保密。**

确保在生产中使用的密钥没有在其他任何地方使用，并且避免将其提交到源代码控制。这减少了攻击者可能获取密钥的向量数量。考虑从环境变量中加载秘密密钥，而不是在设置模块中将秘密密钥硬编码：

```py
import os
SECRET_KEY = os.environ['SECRET_KEY']
```

或者从一个文件：

```py
with open('/etc/secret_key.txt') as f:
SECRET_KEY = f.read().strip()
```

## 调试

**您绝对不能在生产中启用调试。**

当我们在第一章 *Django 简介* *和入门*中创建项目时，`django-admin startproject` 命令创建了一个带有 `DEBUG` 设置为 `True` 的 `settings.py` 文件。Django 的许多内部部分都会检查此设置，并在 `DEBUG` 模式开启时改变它们的行为。

例如，如果 `DEBUG` 设置为 `True`，那么：

+   所有数据库查询将被保存在内存中作为对象 `django.db.connection.queries`。你可以想象，这会消耗内存！

+   任何 404 错误都将由 Django 的特殊 404 错误页面（在第三章中介绍，*模板*）呈现，而不是返回正确的 404 响应。这个页面包含潜在的敏感信息，不应该暴露在公共互联网上。

+   您的 Django 应用程序中的任何未捕获异常-从基本的 Python 语法错误到数据库错误和模板语法错误-都将由您可能已经了解和喜爱的 Django 漂亮错误页面呈现。这个页面包含的敏感信息甚至比 404 页面还要多，绝不能暴露给公众。

简而言之，将`DEBUG`设置为`True`告诉 Django 假设只有可信任的开发人员在使用您的网站。互联网上充满了不可信任的流氓，当您准备部署应用程序时，第一件事就是将`DEBUG`设置为`False`。

# 特定于环境的设置

## ALLOWED_HOSTS

当`DEBUG = False`时，Django 在没有适当的`ALLOWED_HOSTS`值的情况下根本无法工作。这个设置是必需的，以保护您的网站免受一些 CSRF 攻击。如果您使用通配符，您必须执行自己的`Host` HTTP 头的验证，或者确保您不容易受到这类攻击的影响。

## 缓存

如果您使用缓存，连接参数在开发和生产中可能不同。缓存服务器通常具有弱身份验证。确保它们只接受来自应用服务器的连接。如果您使用**Memcached**，考虑使用缓存会话以提高性能。

## 数据库

开发和生产中的数据库连接参数可能不同。数据库密码非常敏感。您应该像保护`SECRET_KEY`一样保护它们。为了最大的安全性，请确保数据库服务器只接受来自应用服务器的连接。如果您还没有为数据库设置备份，请立即进行设置！

## EMAIL_BACKEND 和相关设置

如果您的网站发送电子邮件，这些值需要正确设置。

## STATIC_ROOT 和 STATIC_URL

静态文件由开发服务器自动提供。在生产中，您必须定义一个`STATIC_ROOT`目录，`collectstatic`将在其中复制它们。

## MEDIA_ROOT 和 MEDIA_URL

媒体文件是由您的用户上传的。它们是不受信任的！确保您的 Web 服务器永远不会尝试解释它们。例如，如果用户上传了一个`.php`文件，Web 服务器不应该执行它。现在是检查这些文件的备份策略的好时机。

# HTTPS

任何允许用户登录的网站都应强制执行全站 HTTPS，以避免在明文中传输访问令牌。在 Django 中，访问令牌包括登录/密码、会话 cookie 和密码重置令牌。（如果通过电子邮件发送它们，你无法保护密码重置令牌。）

保护敏感区域，如用户帐户或管理员是不够的，因为相同的会话 cookie 用于 HTTP 和 HTTPS。您的 Web 服务器必须将所有 HTTP 流量重定向到 HTTPS，并且只将 HTTPS 请求传输到 Django。设置 HTTPS 后，启用以下设置。

## CSRF_COOKIE_SECURE

将其设置为`True`，以避免意外通过 HTTP 传输 CSRF cookie。

## SESSION_COOKIE_SECURE

将其设置为`True`，以避免意外通过 HTTP 传输会话 cookie。

# 性能优化

将`DEBUG = False`设置为禁用一些仅在开发中有用的功能。此外，您可以调整以下设置。

## CONN_MAX_AGE

启用持久数据库连接可以在连接到数据库占请求处理时间的重要部分时获得良好的加速。这在网络性能有限的虚拟化主机上非常有帮助。

## 模板

启用缓存模板加载器通常会大大提高性能，因为它避免了每次需要呈现模板时都要编译模板。有关更多信息，请参阅模板加载器文档。

# 错误报告

当您将代码推送到生产环境时，希望它是健壮的，但您不能排除意外错误。幸运的是，Django 可以捕获错误并相应地通知您。

## 日志记录

在将网站投入生产之前，请检查您的日志配置，并在收到一些流量后立即检查它是否按预期工作。

## ADMINS 和 MANAGERS

`ADMINS`将通过电子邮件收到 500 错误的通知。`MANAGERS`将收到 404 错误的通知。`IGNORABLE_404_URLS`可以帮助过滤掉虚假报告。

通过电子邮件进行错误报告并不是很有效。在您的收件箱被报告淹没之前，考虑使用 Sentry 等错误监控系统（有关更多信息，请访问 [`sentry.readthedocs.org/en/latest/`](http://sentry.readthedocs.org/en/latest/)）。Sentry 还可以聚合日志。

## 自定义默认错误视图

Django 包括了几个 HTTP 错误代码的默认视图和模板。您可能希望通过在根模板目录中创建以下模板来覆盖默认模板：`404.html`、`500.html`、`403.html` 和 `400.html`。默认视图应该适用于 99% 的 Web 应用程序，但如果您希望自定义它们，请参阅这些指令（[`docs.djangoproject.com/en/1.8/topics/http/views/#customizing-error-views`](https://docs.djangoproject.com/en/1.8/topics/http/views/#customizing-error-views)），其中还包含有关默认模板的详细信息：

+   `http_not_found_view`

+   `http_internal_server_error_view`

+   `http_forbidden_view`

+   `http_bad_request_view`

# 使用虚拟环境

如果您在虚拟环境中安装了项目的 Python 依赖项（有关更多信息，请访问 [`www.virtualenv.org/`](http://www.virtualenv.org/)），您还需要将此虚拟环境的 `site-packages` 目录的路径添加到您的 Python 路径中。为此，添加一个额外的路径到您的 `WSGIPythonPath` 指令，如果使用类 UNIX 系统，则使用冒号（`:`）分隔多个路径，如果使用 Windows，则使用分号（`;`）分隔。如果目录路径的任何部分包含空格字符，则必须引用完整的参数字符串：

```py
WSGIPythonPath /path/to/mysite.com:/path/to/your/venv/lib/python3.X/site-packages 

```

确保您提供正确的虚拟环境路径，并用正确的 Python 版本（例如 `python3.4`）替换 `python3.X`。

# 在生产中使用不同的设置

到目前为止，在本书中，我们只处理了一个设置文件：由 `django-admin startproject` 生成的 `settings.py`。但是当您准备部署时，您可能会发现自己需要多个设置文件，以保持开发环境与生产环境隔离。（例如，您可能不希望在本地机器上测试代码更改时将 `DEBUG` 从 `False` 更改为 `True`。）Django 通过允许您使用多个设置文件来使这一切变得非常容易。如果您希望将设置文件组织成生产和开发设置，您可以通过以下三种方式之一来实现：

+   设置两个完全独立的设置文件。

+   设置一个基本设置文件（比如开发），以及一个第二个（比如生产）设置文件，它只是从第一个文件中导入，并定义任何需要定义的覆盖。

+   只使用一个具有 Python 逻辑的设置文件来根据上下文更改设置。

我们将逐个来看这些。首先，最基本的方法是定义两个单独的设置文件。如果您在跟着做，您已经有了 `settings.py`。现在，只需复制它，命名为 `settings_production.py`。（我们随便取的名字；您可以随意命名。）在这个新文件中，更改 `DEBUG` 等。第二种方法类似，但减少了冗余。不是拥有两个内容大部分相似的设置文件，您可以将一个作为基本文件，并创建另一个文件从中导入。例如：

```py
# settings.py 

DEBUG = True 
TEMPLATE_DEBUG = DEBUG 

DATABASE_ENGINE = 'postgresql_psycopg2' 
DATABASE_NAME = 'devdb' 
DATABASE_USER = '' 
DATABASE_PASSWORD = '' 
DATABASE_PORT = '' 

# ... 

# settings_production.py 

from settings import * 

DEBUG = TEMPLATE_DEBUG = False 
DATABASE_NAME = 'production' 
DATABASE_USER = 'app' 
DATABASE_PASSWORD = 'letmein' 

```

在这里，`settings_production.py` 从 `settings.py` 导入所有内容，并重新定义了特定于生产的设置。在这种情况下，`DEBUG` 设置为 `False`，但我们还为生产设置了不同的数据库访问参数。（后者表明您可以重新定义任何设置，而不仅仅是基本的设置，比如 `DEBUG`。）最后，实现两个设置环境最简洁的方法是使用一个设置文件，根据环境进行分支。其中一种方法是检查当前的主机名。例如：

```py
# settings.py 

import socket 

if socket.gethostname() == 'my-laptop': 
    DEBUG = TEMPLATE_DEBUG = True 
else: 
    DEBUG = TEMPLATE_DEBUG = False 

# ... 

```

在这里，我们从 Python 的标准库中导入`socket`模块，并使用它来检查当前系统的主机名。我们可以检查主机名来确定代码是否在生产服务器上运行。这里的一个核心教训是，设置文件只是*Python 代码*。它们可以从其他文件导入，可以执行任意逻辑，等等。只要确保，如果您选择这条路，设置文件中的 Python 代码是无懈可击的。如果它引发任何异常，Django 可能会严重崩溃。

随意将您的`settings.py`重命名为`settings_dev.py`或`settings/dev.py`或`foobar.py`-Django 不在乎，只要告诉它您正在使用哪个设置文件即可。

但是，如果您重命名了`django-admin startproject`生成的`settings.py`文件，您会发现`manage.py`会给出一个错误消息，说它找不到设置。这是因为它尝试导入一个名为`settings`的模块。您可以通过编辑`manage.py`将`settings`更改为您的模块的名称来解决此问题，或者使用`django-admin`而不是`manage.py`。在后一种情况下，您需要将`DJANGO_SETTINGS_MODULE`环境变量设置为您的设置文件的 Python 路径（例如，`'mysite.settings'`）。

# 将 Django 部署到生产服务器

### 注意

无需头痛的部署

如果您真的想要部署一个实时网站，真的只有一个明智的选择-找到一个明确支持 Django 的主机。

不仅会得到一个独立的媒体服务器（通常是 Nginx），而且他们还会照顾一些小事情，比如正确设置 Apache 并设置一个定期重启 Python 进程的 cron 作业（以防止您的网站挂起）。对于更好的主机，您还可能会得到某种形式的一键部署。

省点心，花几块钱每月找一个懂 Django 的主机。

# 使用 Apache 和 mod_wsgi 部署 Django

使用 Apache（[`httpd.apache.org/`](http://httpd.apache.org/)）和`mod_wsgi`（[`code.google.com/p/modwsgi`](http://code.google.com/p/modwsgi)）部署 Django 是一个经过验证的将 Django 投入生产的方法。`mod_wsgi`是一个可以托管任何 Python WSGI 应用程序（包括 Django）的 Apache 模块。Django 将与支持`mod_wsgi`的任何版本的 Apache 一起工作。官方的`mod_wsgi`文档非常棒；这是您获取有关如何使用`mod_wsgi`的所有细节的来源。您可能希望从安装和配置文档开始。

## 基本配置

一旦安装并激活了`mod_wsgi`，编辑 Apache 服务器的`httpd.conf`文件并添加以下内容。请注意，如果您使用的是早于 2.4 版本的 Apache，将`Require all granted`替换为`Allow from all`，并在其前面添加`Order deny,allow`行。

```py
WSGIScriptAlias / /path/to/mysite.com/mysite/wsgi.py 
WSGIPythonPath /path/to/mysite.com 

<Directory /path/to/mysite.com/mysite> 
<Files wsgi.py> 
Require all granted 
</Files> 
</Directory> 

```

`WSGIScriptAlias`行中的第一部分是您希望在其上提供应用程序的基本 URL 路径（`/`表示根 URL），第二部分是系统上 WSGI 文件的位置，通常在您的项目包内（例如此示例中的`mysite`）。这告诉 Apache 使用在该文件中定义的 WSGI 应用程序来提供任何遵循给定 URL 的请求。

`WSGIPythonPath`行确保您的项目包可以在 Python 路径上导入；换句话说，`import mysite`有效。`<Directory>`部分只是确保 Apache 可以访问您的`wsgi.py`文件。

接下来，我们需要确保存在带有 WSGI 应用程序对象的`wsgi.py`。从 Django 版本 1.4 开始，`startproject`会为您创建一个；否则，您需要自己创建。

查看 WSGI 概述，了解您应该在此文件中放置的默认内容，以及您可以添加的其他内容。

### 注意

如果在单个`mod_wsgi`进程中运行多个 Django 站点，则所有这些站点都将使用首先运行的站点的设置。这可以通过更改`wsgi.py`中的`os.environ.setdefault("DJANGO_SETTINGS_MODULE", "{{ project_name }}.settings")`来解决，例如：`os.environ["DJANGO_SETTINGS_MODULE"] = "{{ project_name }}.settings"`或者使用`mod_wsgi`守护程序模式，并确保每个站点在其自己的守护进程中运行。

## 使用 mod_wsgi 守护程序模式

守护程序模式是在非 Windows 平台上运行`mod_wsgi`的推荐模式。要创建所需的守护进程组并委托 Django 实例在其中运行，您需要添加适当的`WSGIDaemonProcess`和`WSGIProcessGroup`指令。

如果使用守护程序模式，则对上述配置需要进一步更改，即不能使用`WSGIPythonPath`；相反，您应该使用`WSGIDaemonProcess`的`python-path`选项，例如：

```py
WSGIDaemonProcess example.com python-path=/path/to/mysite.com:/path/to/venv/lib/python2.7/site-packages 
WSGIProcessGroup example.com 

```

有关设置守护程序模式的详细信息，请参阅官方`mod_wsgi`文档。

## 提供文件

Django 本身不提供文件服务；它将这项工作留给您选择的任何 Web 服务器。我们建议使用单独的 Web 服务器（即不运行 Django 的服务器）来提供媒体。以下是一些不错的选择：

+   Nginx（有关更多信息，请访问[`code.google.com/p/modwsgi`](http://code.google.com/p/modwsgi)）

+   Apache 的精简版本

然而，如果您别无选择，只能在与 Django 相同的 Apache `VirtualHost`上提供媒体文件，您可以设置 Apache 以将某些 URL 作为静态媒体提供，然后使用`mod_wsgi`接口将其他 URL 用于 Django。

此示例在站点根目录设置 Django，但显式提供`robots.txt`，`favicon.ico`，任何 CSS 文件以及`/static/`和`/media/` URL 空间中的任何内容作为静态文件。所有其他 URL 将使用`mod_wsgi`进行提供：

```py
Alias /robots.txt /path/to/mysite.com/static/robots.txt 
Alias /favicon.ico /path/to/mysite.com/static/favicon.ico 

Alias /media/ /path/to/mysite.com/media/ 
Alias /static/ /path/to/mysite.com/static/ 

<Directory /path/to/mysite.com/static> 
Require all granted 
</Directory> 

<Directory /path/to/mysite.com/media> 
Require all granted 
</Directory> 

WSGIScriptAlias / /path/to/mysite.com/mysite/wsgi.py 

<Directory /path/to/mysite.com/mysite> 
<Files wsgi.py> 
Require all granted 
</Files> 
</Directory> 

```

如果您使用的是早于 2.4 的 Apache 版本，请用`Allow from all`替换`Require all granted`，并在其前面添加`Order deny,allow`行。

## 提供管理文件

当`django.contrib.staticfiles`在`INSTALLED_APPS`中时，Django 开发服务器会自动提供管理应用程序（以及任何其他已安装的应用程序）的静态文件。但是，当您使用其他服务器安排时，情况并非如此。您需要负责设置 Apache 或您正在使用的任何其他 Web 服务器以提供管理文件。

管理文件位于 Django 分发的(`django/contrib/admin/static/admin`)中。我们建议使用`django.contrib.staticfiles`来处理管理文件（以及在前一节中概述的 Web 服务器一起使用；这意味着使用`collectstatic`管理命令在`STATIC_ROOT`中收集静态文件，然后配置您的 Web 服务器以在`STATIC_URL`处提供`STATIC_ROOT`），但这里有其他三种方法：

1.  从您的文档根目录创建到管理静态文件的符号链接（这可能需要在 Apache 配置中使用`+FollowSymLinks`）。

1.  使用`Alias`指令，如前一段所示，将适当的 URL（可能是`STATIC_URL` + `admin/`）别名为管理文件的实际位置。

1.  复制管理静态文件，使其位于 Apache 文档根目录中。

## 如果遇到 UnicodeEncodeError

如果您正在利用 Django 的国际化功能，并且打算允许用户上传文件，您必须确保用于启动 Apache 的环境已配置为接受非 ASCII 文件名。如果您的环境配置不正确，当调用`os.path`中包含非 ASCII 字符的文件名时，将触发`UnicodeEncodeError`异常。

为了避免这些问题，用于启动 Apache 的环境应包含类似以下设置的环境：

```py
export LANG='en_US.UTF-8' 
export LC_ALL='en_US.UTF-8' 

```

请查阅操作系统的文档，了解适当的语法和放置这些配置项的位置；在 Unix 平台上，`/etc/apache2/envvars`是一个常见的位置。添加了这些语句到您的环境后，重新启动 Apache。

# 在生产环境中提供静态文件

将静态文件放入生产环境的基本概述很简单：当静态文件更改时运行`collectstatic`命令，然后安排将收集的静态文件目录（`STATIC_ROOT`）移动到静态文件服务器并提供服务。

根据`STATICFILES_STORAGE`，文件可能需要手动移动到新位置，或者`Storage`类的`post_process`方法可能会处理这个问题。

当然，与所有部署任务一样，魔鬼在细节中。每个生产设置都会有所不同，因此您需要根据自己的需求调整基本概述。

以下是一些可能有所帮助的常见模式。

## 从同一服务器提供站点和静态文件

如果您希望从已经提供站点的同一服务器提供静态文件，则该过程可能看起来像这样：

+   将您的代码推送到部署服务器。

+   在服务器上，运行`collectstatic`将所有静态文件复制到`STATIC_ROOT`中。

+   配置您的 Web 服务器，以便在`STATIC_ROOT`下的 URL`STATIC_URL`中提供文件。

您可能希望自动化这个过程，特别是如果您有多个 Web 服务器。有许多种方法可以进行这种自动化，但许多 Django 开发人员喜欢的一个选择是 Fabric（[`fabfile.org/`](http://fabfile.org/)）。

接下来，在接下来的几节中，我们将展示一些示例**fabfiles**（即 Fabric 脚本），这些脚本可以自动化这些文件部署选项。fabfile 的语法相当简单，但这里不会涉及到; 请参阅 Fabric 的文档，了解语法的完整解释。因此，一个用于将静态文件部署到一对 Web 服务器的 fabfile 可能看起来像这样：

```py
from fabric.api import * 

# Hosts to deploy onto 
env.hosts = ['www1.example.com', 'www2.example.com'] 

# Where your project code lives on the server 
env.project_root = '/home/www/myproject' 

def deploy_static(): 
    with cd(env.project_root): 
        run('./manage.py collectstatic -v0 -noinput') 

```

## 从专用服务器提供静态文件

大多数较大的 Django 站点使用单独的 Web 服务器-即不运行 Django 的服务器-用于提供静态文件。这个服务器通常运行不同类型的 Web 服务器-速度更快但功能不那么全面。一些常见的选择是：

+   Nginx

+   Apache 的简化版本

配置这些服务器不在本文档的范围之内; 请查看每个服务器的相应文档以获取说明。由于您的静态文件服务器不会运行 Django，因此您需要修改部署策略，看起来像这样：

1.  当您的静态文件更改时，在本地运行`collectstatic`。

1.  将本地的`STATIC_ROOT`推送到静态文件服务器中正在提供服务的目录。`rsync`（[`rsync.samba.org/`](https://rsync.samba.org/)）是这一步的常见选择，因为它只需要传输已更改的静态文件位。

以下是 fabfile 中的示例：

```py
from fabric.api import * 
from fabric.contrib import project 

# Where the static files get collected locally. Your STATIC_ROOT setting. 
env.local_static_root = '/tmp/static' 

# Where the static files should go remotely 
env.remote_static_root = '/home/www/static.example.com' 

@roles('static') 
def deploy_static(): 
    local('./manage.py collectstatic') 
    project.rsync_project( 
        remote_dir = env.remote_static_root, 
        local_dir = env.local_static_root, 
        delete = True 
    ) 

```

## 从云服务或 CDN 提供静态文件

另一种常见的策略是从云存储提供商（如 Amazon 的 S3）和/或 CDN（内容传送网络）提供静态文件。这样可以忽略提供静态文件的问题，并且通常可以使网页加载更快（特别是在使用 CDN 时）。

在使用这些服务时，基本工作流程看起来可能与前面的段落有些不同，只是不是使用`rsync`将静态文件传输到服务器，而是需要将静态文件传输到存储提供商或 CDN。您可能有许多种方法可以做到这一点，但如果提供商有 API，自定义文件存储后端将使这个过程变得非常简单。

如果您已经编写或正在使用第三方自定义存储后端，可以通过将`STATICFILES_STORAGE`设置为存储引擎来告诉`collectstatic`使用它。例如，如果您在`myproject.storage.S3Storage`中编写了一个 S3 存储后端，您可以使用它：

```py
STATICFILES_STORAGE = 'myproject.storage.S3Storage'
```

完成后，您只需运行`collectstatic`，您的静态文件将通过存储包推送到 S3。如果以后需要切换到不同的存储提供程序，只需更改`STATICFILES_STORAGE`设置即可。有第三方应用程序可提供许多常见文件存储 API 的存储后端。一个很好的起点是`djangopackages.com`上的概述。

# 扩展

现在您知道如何在单个服务器上运行 Django，让我们看看如何扩展 Django 安装。本节将介绍网站如何从单个服务器扩展到一个可以每小时服务数百万次点击的大规模集群。然而，需要注意的是，几乎每个大型网站在不同方面都很大，因此扩展绝非一刀切的操作。

以下覆盖应该足以展示一般原则，并且在可能的情况下，我们将尝试指出可以做出不同选择的地方。首先，我们将做出一个相当大的假设，并且专门讨论 Apache 和`mod_python`下的扩展。虽然我们知道有许多成功的中到大型规模的 FastCGI 部署，但我们对 Apache 更为熟悉。

## 在单个服务器上运行

大多数网站最初在单个服务器上运行，其架构看起来有点像*图 13.1*。然而，随着流量的增加，您很快会发现不同软件之间存在*资源争用*的问题。

数据库服务器和 Web 服务器喜欢拥有整个服务器，因此当它们在同一台服务器上运行时，它们经常会争夺它们更愿意垄断的相同资源（RAM 和 CPU）。将数据库服务器移至第二台机器很容易解决这个问题。

![在单个服务器上运行](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/ms-dj/img/image_13_001.jpg)

图 13.1：单服务器 Django 设置。

## 分离数据库服务器

就 Django 而言，分离数据库服务器的过程非常简单：您只需要将`DATABASE_HOST`设置更改为数据库服务器的 IP 或 DNS 名称。如果可能的话，最好使用 IP，因为不建议依赖 DNS 来连接您的 Web 服务器和数据库服务器。有了单独的数据库服务器，我们的架构现在看起来像*图 13.2*。

在这里，我们开始进入通常称为**n 层**架构的领域。不要被这个流行词吓到-它只是指 Web 堆栈的不同层被分离到不同的物理机器上。

在这一点上，如果您预计将来需要超出单个数据库服务器，最好开始考虑连接池和/或数据库复制。不幸的是，在本书中没有足够的空间来充分讨论这些主题，因此您需要咨询数据库的文档和/或社区以获取更多信息。

![分离数据库服务器](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/ms-dj/img/image_13_002.jpg)

图 13.2：将数据库移至专用服务器。

## 运行单独的媒体服务器

我们仍然有一个大问题留在单服务器设置中：从处理动态内容的同一台机器上提供媒体。这两个活动在不同情况下表现最佳，将它们合并在同一台机器上会导致它们都表现不佳。

因此，下一步是将媒体-即任何不是由 Django 视图生成的东西-分离到专用服务器上（见*图 13.3*）。

理想情况下，这个媒体服务器应该运行一个针对静态媒体传递进行优化的精简 Web 服务器。Nginx 是首选选项，尽管**lighttpd**是另一个选项，或者一个经过大幅简化的 Apache 也可以工作。对于静态内容丰富的网站（照片、视频等），将其移至单独的媒体服务器至关重要，很可能是扩展的第一步。

然而，这一步可能有点棘手。如果您的应用涉及文件上传，Django 需要能够将上传的媒体写入媒体服务器。如果媒体存储在另一台服务器上，您需要安排一种方式让该写入通过网络进行。

![运行一个独立的媒体服务器](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/ms-dj/img/image_13_003.jpg)

图 13.3：分离媒体服务器。

## 实现负载平衡和冗余

在这一点上，我们已经尽可能地将事情分解了。这种三台服务器的设置应该可以处理非常大量的流量-我们从这种结构中每天提供了大约 1000 万次点击-因此，如果您进一步增长，您将需要开始添加冗余。

实际上，这是一件好事。仅看一眼*图 13.3*就会告诉你，即使你的三台服务器中的一台失败，你也会使整个站点崩溃。因此，随着添加冗余服务器，不仅可以增加容量，还可以增加可靠性。为了这个例子，让我们假设 Web 服务器首先达到容量。

在不同的硬件上运行多个 Django 站点的副本相对容易-只需将所有代码复制到多台机器上，并在所有机器上启动 Apache。然而，您需要另一种软件来在多台服务器上分发流量：*负载均衡器*。

您可以购买昂贵的专有硬件负载均衡器，但也有一些高质量的开源软件负载均衡器。Apache 的`mod_proxy`是一个选择，但我们发现 Perlbal（[`www.djangoproject.com/r/perlbal/`](http://www.djangoproject.com/r/perlbal/)）非常棒。它是一个由编写`memcached`的同一批人编写的负载均衡器和反向代理（参见第十六章，“Django 的缓存框架”）。

现在，随着 Web 服务器的集群化，我们不断发展的架构开始变得更加复杂，如*图 13.4*所示。

![实现负载均衡和冗余](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/ms-dj/img/image_13_004.jpg)

图 13.4：一个负载平衡、冗余的服务器设置。

请注意，在图中，Web 服务器被称为集群，表示服务器的数量基本上是可变的。一旦您在前面放置了负载均衡器，您就可以轻松地添加和删除后端 Web 服务器，而不会有一秒钟的停机时间。

## 扩大规模

在这一点上，接下来的几个步骤基本上是上一个步骤的衍生：

+   当您需要更多的数据库性能时，您可能希望添加复制的数据库服务器。MySQL 包含内置的复制功能；PostgreSQL 用户应该研究 Slony（[`www.djangoproject.com/r/slony/`](http://www.djangoproject.com/r/slony/)）和 pgpool（[`www.djangoproject.com/r/pgpool/`](http://www.djangoproject.com/r/pgpool/)）用于复制和连接池。

+   如果单个负载均衡器不够，您可以在前面添加更多负载均衡器机器，并使用轮询 DNS 进行分发。

+   如果单个媒体服务器不够，您可以添加更多媒体服务器，并使用负载平衡集群分发负载。

+   如果您需要更多的缓存存储，您可以添加专用的缓存服务器。

+   在任何阶段，如果集群性能不佳，您可以向集群添加更多服务器。

经过几次迭代后，一个大规模的架构可能看起来像*图 13.5*。

![扩大规模](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/ms-dj/img/image_13_005.jpg)

图 13.5：一个大规模 Django 设置的示例。

尽管我们在每个级别只显示了两到三台服务器，但你可以添加的服务器数量并没有根本限制。

# 性能调优

如果你有大量的资金，你可以不断地投入硬件来解决扩展问题。然而，对于我们其他人来说，性能调优是必不可少的。

### 注意

顺便说一句，如果有人拥有大量资金正在阅读这本书，请考虑向 Django 基金会进行大额捐赠。他们也接受未加工的钻石和金锭。

不幸的是，性能调优更多地是一门艺术而不是一门科学，而且比扩展更难写。如果你真的想部署一个大规模的 Django 应用程序，你应该花大量时间学习如何调优你的每个部分。

接下来的章节介绍了多年来我们发现的一些 Django 特定的调优技巧。

## 没有太多的 RAM 这种事

即使是非常昂贵的 RAM 在今天也相对实惠。尽可能多地购买 RAM，然后再多买一点。更快的处理器不会显著提高性能；大多数 Web 服务器花费高达 90%的时间在等待磁盘 I/O。一旦开始交换，性能就会急剧下降。更快的磁盘可能会稍微有所帮助，但它们比 RAM 要贵得多，以至于并不重要。

如果你有多台服务器，将 RAM 放在数据库服务器是首选。如果你有能力，获得足够的 RAM 来容纳整个数据库到内存中。这并不难；我们开发了一个拥有超过 50 万篇报纸文章的网站，只需要不到 2GB 的空间。

接下来，充分利用 Web 服务器上的 RAM。理想情况是服务器从不交换。如果你达到了这一点，你应该能够承受大部分正常的流量。

## 关闭保持活动状态

保持活动状态是 HTTP 的一个特性，允许多个 HTTP 请求通过单个 TCP 连接提供，避免了 TCP 建立/拆除的开销。乍一看，这看起来不错，但它可能会影响 Django 网站的性能。如果你从一个单独的服务器正确地提供媒体，每个浏览你网站的用户大约每十秒钟只会从你的 Django 服务器请求一个页面。这会让 HTTP 服务器等待下一个保持活动状态的请求，而空闲的 HTTP 服务器只会消耗应该被活跃服务器使用的内存。

## 使用 Memcached

尽管 Django 支持许多不同的缓存后端，但没有一个能够像 Memcached 一样快。如果你有一个高流量的网站，甚至不要考虑其他后端，直接使用 Memcached。

## 经常使用 Memcached

当然，如果你实际上不使用 Memcached，选择 Memcached 对你没有好处。第十六章，*Django 的缓存框架*，是你的好朋友：学习如何使用 Django 的缓存框架，并在可能的地方使用它。积极的、预防性的缓存通常是唯一能够在大流量下保持网站稳定的方法。

## 加入讨论

Django 的每个部分-从 Linux 到 Apache 再到 PostgreSQL 或 MySQL-都有一个强大的社区支持。如果你真的想从你的服务器中获得最后 1%，加入你软件背后的开源社区并寻求帮助。大多数自由软件社区成员都会乐意帮助。还要确保加入 Django 社区-一个活跃、不断增长的 Django 开发者群体。我们的社区有大量的集体经验可以提供。

# 接下来是什么？

剩下的章节关注其他 Django 功能，这取决于你的应用是否需要。随意按照你选择的任何顺序阅读它们。


# 第十四章：生成非 HTML 内容

通常，当我们谈论开发网站时，我们谈论的是生成 HTML。当然，网页不仅仅是 HTML；我们使用网页以各种格式分发数据：RSS、PDF、图像等等。

到目前为止，我们专注于 HTML 生成的常见情况，但在本章中，我们将走一条弯路，看看如何使用 Django 生成其他类型的内容。Django 有方便的内置工具，可以用来生成一些常见的非 HTML 内容：

+   逗号分隔（CSV）文件，用于导入到电子表格应用程序中。

+   PDF 文件。

+   RSS/Atom 订阅源。

+   站点地图（最初由谷歌开发的 XML 格式，为搜索引擎提供提示）。

我们稍后会详细讨论这些工具，但首先我们将介绍基本原则。

# 基础知识：视图和 MIME 类型

从第二章中回忆，*视图和 URLconfs*，视图函数只是一个接受 Web 请求并返回 Web 响应的 Python 函数。这个响应可以是网页的 HTML 内容，或者重定向，或者 404 错误，或者 XML 文档，或者图像...或者任何东西。更正式地说，Django 视图函数必须*：*

1.  接受一个`HttpRequest`实例作为其第一个参数；和

1.  返回一个`HttpResponse`实例。

从视图返回非 HTML 内容的关键在于`HttpResponse`类，特别是`content_type`参数。默认情况下，Django 将`content_type`设置为 text/html。但是，您可以将`content_type`设置为 IANA 管理的任何官方互联网媒体类型（MIME 类型）（有关更多信息，请访问[`www.iana.org/assignments/media-types/media-types.xhtml`](http://www.iana.org/assignments/media-types/media-types.xhtml)）。

通过调整 MIME 类型，我们可以告诉浏览器我们返回了不同格式的响应。例如，让我们看一个返回 PNG 图像的视图。为了保持简单，我们只需从磁盘上读取文件：

```py
from django.http import HttpResponse 

def my_image(request): 
    image_data = open("/path/to/my/image.png", "rb").read() 
    return HttpResponse(image_data, content_type="image/png") 

```

就是这样！如果您用`open()`调用中的图像路径替换为真实图像的路径，您可以使用这个非常简单的视图来提供图像，浏览器将正确显示它。

另一个重要的事情是`HttpResponse`对象实现了 Python 的标准文件类对象 API。这意味着您可以在任何需要文件的地方使用`HttpResponse`实例，包括 Python（或第三方库）。让我们看一下如何使用 Django 生成 CSV 的示例。

# 生成 CSV

Python 自带一个 CSV 库，`csv`。使用它与 Django 的关键在于`csv`模块的 CSV 创建功能作用于类似文件的对象，而 Django 的`HttpResponse`对象是类似文件的对象。下面是一个例子：

```py
import csv 
from django.http import HttpResponse 

def some_view(request): 
    # Create the HttpResponse object with the appropriate CSV header. 
    response = HttpResponse(content_type='text/csv') 
    response['Content-Disposition'] = 'attachment; 
      filename="somefilename.csv"' 

    writer = csv.writer(response) 
    writer.writerow(['First row', 'Foo', 'Bar', 'Baz']) 
    writer.writerow(['Second row', 'A', 'B', 'C', '"Testing"']) 

    return response 

```

代码和注释应该是不言自明的，但有几件事值得一提：

+   响应获得了特殊的 MIME 类型`text/csv`。这告诉浏览器该文档是 CSV 文件，而不是 HTML 文件。如果不这样做，浏览器可能会将输出解释为 HTML，这将导致浏览器窗口中出现丑陋、可怕的胡言乱语。

+   响应获得了额外的`Content-Disposition`头，其中包含 CSV 文件的名称。这个文件名是任意的；随便取什么名字。它将被浏览器用于“另存为...”对话框等。

+   连接到 CSV 生成 API 很容易：只需将`response`作为`csv.writer`的第一个参数。`csv.writer`函数期望一个类似文件的对象，而`HttpResponse`对象符合要求。

+   对于 CSV 文件中的每一行，调用`writer.writerow`，将其传递给一个可迭代对象，如列表或元组。

+   CSV 模块会为您处理引用，因此您不必担心用引号或逗号转义字符串。只需将`writerow()`传递给您的原始字符串，它就会做正确的事情。

## 流式传输大型 CSV 文件

处理生成非常大响应的视图时，您可能希望考虑改用 Django 的`StreamingHttpResponse`。例如，通过流式传输需要很长时间生成的文件，您可以避免负载均衡器在服务器生成响应时可能会超时而断开连接。在这个例子中，我们充分利用 Python 生成器来高效地处理大型 CSV 文件的组装和传输：

```py
import csv 

from django.utils.six.moves import range 
from django.http import StreamingHttpResponse 

class Echo(object): 
    """An object that implements just the write method of the file-like 
    interface. 
    """ 
    def write(self, value): 
        """Write the value by returning it, instead of storing in a buffer.""" 
        return value 

def some_streaming_csv_view(request): 
    """A view that streams a large CSV file.""" 
    # Generate a sequence of rows. The range is based on the maximum number of 
    # rows that can be handled by a single sheet in most spreadsheet 
    # applications. 
    rows = (["Row {}".format(idx), str(idx)] for idx in range(65536)) 
    pseudo_buffer = Echo() 
    writer = csv.writer(pseudo_buffer) 
    response = StreamingHttpResponse((writer.writerow(row)  
      for row in rows), content_type="text/csv") 
    response['Content-Disposition'] = 'attachment;    
      filename="somefilename.csv"' 
    return response 

```

# 使用模板系统

或者，您可以使用 Django 模板系统来生成 CSV。这比使用方便的 Python `csv`模块更低级，但是这里提供了一个完整的解决方案。这里的想法是将一个项目列表传递给您的模板，并让模板在`for`循环中输出逗号。以下是一个示例，它生成与上面相同的 CSV 文件：

```py
from django.http import HttpResponse 
from django.template import loader, Context 

def some_view(request): 
    # Create the HttpResponse object with the appropriate CSV header. 
    response = HttpResponse(content_type='text/csv') 
    response['Content-Disposition'] = 'attachment;    
      filename="somefilename.csv"' 

    # The data is hard-coded here, but you could load it  
    # from a database or some other source. 
    csv_data = ( 
        ('First row', 'Foo', 'Bar', 'Baz'), 
        ('Second row', 'A', 'B', 'C', '"Testing"', "Here's a quote"), 
    ) 

    t = loader.get_template('my_template_name.txt') 
    c = Context({'data': csv_data,}) 
    response.write(t.render(c)) 
    return response 

```

这个例子和之前的例子唯一的区别是这个例子使用模板加载而不是 CSV 模块。其余的代码，比如`content_type='text/csv'`，都是一样的。然后，创建模板`my_template_name.txt`，其中包含以下模板代码：

```py
{% for row in data %} 
            "{{ row.0|addslashes }}", 
            "{{ row.1|addslashes }}", 
            "{{ row.2|addslashes }}", 
            "{{ row.3|addslashes }}", 
            "{{ row.4|addslashes }}" 
{% endfor %} 

```

这个模板非常基础。它只是遍历给定的数据，并为每一行显示一个 CSV 行。它使用`addslashes`模板过滤器来确保引号没有问题。

# 其他基于文本的格式

请注意，这里与 CSV 相关的内容并不多，只是特定的输出格式。您可以使用这些技术中的任何一种来输出您梦想中的任何基于文本的格式。您还可以使用类似的技术来生成任意二进制数据；例如，生成 PDF 文件。

# 生成 PDF

Django 能够使用视图动态输出 PDF 文件。这得益于出色的开源 ReportLab（有关更多信息，请访问[`www.reportlab.com/opensource/`](http://www.reportlab.com/opensource/)）Python PDF 库。动态生成 PDF 文件的优势在于，您可以为不同目的创建定制的 PDF 文件，比如为不同用户或不同内容创建。

# 安装 ReportLab

**ReportLab**库可在 PyPI 上获得。还可以下载用户指南（不巧的是，是一个 PDF 文件）。您可以使用`pip`安装 ReportLab：

```py
$ pip install reportlab 

```

通过在 Python 交互解释器中导入它来测试您的安装：

```py
>>> import reportlab 

```

如果该命令没有引发任何错误，则安装成功。

# 编写您的视图

使用 Django 动态生成 PDF 的关键是 ReportLab API，就像`csv`库一样，它作用于文件样对象，比如 Django 的`HttpResponse`。以下是一个 Hello World 示例：

```py
from reportlab.pdfgen import canvas 
from django.http import HttpResponse 

def some_view(request): 
    # Create the HttpResponse object with the appropriate PDF headers. 
    response = HttpResponse(content_type='application/pdf') 
    response['Content-Disposition'] = 'attachment;    
      filename="somefilename.pdf"' 

    # Create the PDF object, using the response object as its "file." 
    p = canvas.Canvas(response) 

    # Draw things on the PDF. Here's where the PDF generation happens. 
    # See the ReportLab documentation for the full list of functionality. 
    p.drawString(100, 100, "Hello world.") 

    # Close the PDF object cleanly, and we're done. 
    p.showPage() 
    p.save() 
    return response 

```

代码和注释应该是不言自明的，但有几点值得一提：

+   响应获得了特殊的 MIME 类型，`application/pdf`。这告诉浏览器该文档是一个 PDF 文件，而不是 HTML 文件。

+   响应获得了额外的`Content-Disposition`头部，其中包含 PDF 文件的名称。这个文件名是任意的：随便取什么名字都可以。浏览器将在“另存为...”对话框中使用它，等等。

+   在这个例子中，`Content-Disposition`头部以`'attachment; '`开头。这会强制 Web 浏览器弹出一个对话框，提示/确认如何处理文档，即使在计算机上设置了默认值。如果省略`'attachment;'`，浏览器将使用为 PDF 配置的任何程序/插件来处理 PDF。以下是该代码的样子：

```py
        response['Content-Disposition'] = 'filename="somefilename.pdf"'
```

+   连接到 ReportLab API 很容易：只需将`response`作为`canvas.Canvas`的第一个参数传递。`Canvas`类需要一个文件样对象，而`HttpResponse`对象正合适。

+   请注意，所有后续的 PDF 生成方法都是在 PDF 对象（在本例中是`p`）上调用的，而不是在`response`上调用的。

+   最后，重要的是在 PDF 文件上调用`showPage()`和`save()`。

# 复杂的 PDF

如果你正在使用 ReportLab 创建复杂的 PDF 文档，考虑使用`io`库作为 PDF 文件的临时存储位置。这个库提供了一个特别高效的类文件对象接口。以下是上面的 Hello World 示例重写，使用`io`：

```py
from io import BytesIO 
from reportlab.pdfgen import canvas 
from django.http import HttpResponse 

def some_view(request): 
    # Create the HttpResponse object with the appropriate PDF headers. 
    response = HttpResponse(content_type='application/pdf') 
    response['Content-Disposition'] = 'attachment;   
      filename="somefilename.pdf"' 

    buffer = BytesIO() 

    # Create the PDF object, using the BytesIO object as its "file." 
    p = canvas.Canvas(buffer) 

    # Draw things on the PDF. Here's where the PDF generation happens. 
    # See the ReportLab documentation for the full list of functionality. 
    p.drawString(100, 100, "Hello world.") 

    # Close the PDF object cleanly. 
    p.showPage() 
    p.save() 

    # Get the value of the BytesIO buffer and write it to the response. 
    pdf = buffer.getvalue() 
    buffer.close() 
    response.write(pdf) 
    return response 

```

# 更多资源

+   PDFlib ([`www.pdflib.org/`](http://www.pdflib.org/))是另一个具有 Python 绑定的 PDF 生成库。要在 Django 中使用它，只需使用本文中解释的相同概念。

+   Pisa XHTML2PDF ([`www.xhtml2pdf.com/`](http://www.xhtml2pdf.com/)) 是另一个 PDF 生成库。Pisa 附带了如何将 Pisa 与 Django 集成的示例。

+   HTMLdoc ([`www.htmldoc.org/`](http://www.htmldoc.org/))是一个可以将 HTML 转换为 PDF 的命令行脚本。它没有 Python 接口，但你可以使用`system`或`popen`跳出到 shell，并在 Python 中检索输出。

# 其他可能性

在 Python 中，你可以生成许多其他类型的内容。以下是一些更多的想法和一些指向你可以用来实现它们的库的指针：

+   **ZIP 文件**：Python 的标准库配备了`zipfile`模块，可以读取和写入压缩的 ZIP 文件。你可以使用它提供一堆文件的按需存档，或者在请求时压缩大型文档。你也可以使用标准库的`tarfile`模块类似地生成 TAR 文件。

+   **动态图片**：**Python Imaging Library**（**PIL**）([`www.pythonware.com/products/pil/`](http://www.pythonware.com/products/pil/))是一个用于生成图片（PNG、JPEG、GIF 等）的绝妙工具包。你可以使用它自动缩小图片为缩略图，将多个图片合成单个框架，甚至进行基于网络的图像处理。

+   **图表和图表**：有许多强大的 Python 绘图和图表库，你可以使用它们生成按需地图、图表、绘图和图表。我们不可能列出它们所有，所以这里是一些亮点：

+   `matplotlib` ([`matplotlib.sourceforge.net/`](http://matplotlib.sourceforge.net/))可用于生成通常使用 MatLab 或 Mathematica 生成的高质量图表。

+   `pygraphviz` ([`networkx.lanl.gov/pygraphviz/`](http://networkx.lanl.gov/pygraphviz/))，一个与 Graphviz 图形布局工具包的接口，可用于生成图和网络的结构化图表。

一般来说，任何能够写入文件的 Python 库都可以连接到 Django。可能性是巨大的。现在我们已经了解了生成非 HTML 内容的基础知识，让我们提高一个抽象级别。Django 配备了一些非常巧妙的内置工具，用于生成一些常见类型的非 HTML 内容。

# 联合供稿框架

Django 配备了一个高级别的联合供稿生成框架，可以轻松创建 RSS 和 Atom 供稿。RSS 和 Atom 都是基于 XML 的格式，你可以用它们提供站点内容的自动更新供稿。在这里阅读更多关于 RSS 的信息([`www.whatisrss.com/`](http://www.whatisrss.com/))，并在这里获取有关 Atom 的信息([`www.atomenabled.org/`](http://www.atomenabled.org/))。

创建任何联合供稿，你所要做的就是编写一个简短的 Python 类。你可以创建任意数量的供稿。Django 还配备了一个低级别的供稿生成 API。如果你想在网页上下文之外或以其他低级别方式生成供稿，可以使用这个 API。

# 高级别框架

## 概述

高级别的供稿生成框架由`Feed`类提供。要创建一个供稿，编写一个`Feed`类，并在你的 URLconf 中指向它的一个实例。

## 供稿类

`Feed`类是表示订阅源的 Python 类。订阅源可以是简单的（例如，站点新闻订阅，或者显示博客最新条目的基本订阅源）或更复杂的（例如，显示特定类别中的所有博客条目的订阅源，其中类别是可变的）。Feed 类是`django.contrib.syndication.views.Feed`的子类。它们可以存在于代码库的任何位置。`Feed`类的实例是视图，可以在您的 URLconf 中使用。

## 一个简单的例子

这个简单的例子，取自一个假设的警察打击新闻网站，描述了最新的五条新闻项目的订阅：

```py
from django.contrib.syndication.views import Feed 
from django.core.urlresolvers import reverse 
from policebeat.models import NewsItem 

class LatestEntriesFeed(Feed): 
    title = "Police beat site news" 
    link = "/sitenews/" 
    description = "Updates on changes and additions to police beat central." 

    def items(self): 
        return NewsItem.objects.order_by('-pub_date')[:5] 

    def item_title(self, item): 
        return item.title 

    def item_description(self, item): 
        return item.description 

    # item_link is only needed if NewsItem has no get_absolute_url method. 
    def item_link(self, item): 
        return reverse('news-item', args=[item.pk]) 

```

要将 URL 连接到此订阅源，请在您的 URLconf 中放置`Feed`对象的实例。例如：

```py
from django.conf.urls import url 
from myproject.feeds import LatestEntriesFeed 

urlpatterns = [ 
    # ... 
    url(r'^latest/feed/$', LatestEntriesFeed()), 
    # ... 
] 

```

**注意：**

+   Feed 类是`django.contrib.syndication.views.Feed`的子类。

+   `title`，`link`和`description`分别对应于标准的 RSS`<title>`，`<link>`和`<description>`元素。

+   `items()`只是一个返回应包含在订阅源中的对象列表的方法。尽管此示例使用 Django 的对象关系映射器返回`NewsItem`对象，但不必返回模型实例。尽管使用 Django 模型可以免费获得一些功能，但`items()`可以返回任何类型的对象。

+   如果您要创建 Atom 订阅源，而不是 RSS 订阅源，请设置`subtitle`属性，而不是`description`属性。有关示例，请参见本章后面的同时发布 Atom 和 RSS 订阅源。

还有一件事要做。在 RSS 订阅源中，每个`<item>`都有一个`<title>`，`<link>`和`<description>`。我们需要告诉框架将哪些数据放入这些元素中。

对于`<title>`和`<description>`的内容，Django 尝试在`Feed`类上调用`item_title()`和`item_description()`方法。它们传递了一个参数`item`，即对象本身。这些是可选的；默认情况下，对象的 unicode 表示用于两者。

如果您想对标题或描述进行任何特殊格式化，可以使用 Django 模板。它们的路径可以在`Feed`类的`title_template`和`description_template`属性中指定。模板为每个项目呈现，并传递了两个模板上下文变量：

+   `{{ obj }}`-：当前对象（您在`items()`中返回的任何对象之一）。

+   `{{ site }}`-：表示当前站点的 Django`site`对象。这对于`{{ site.domain }}`或`{{ site.name }}`非常有用。

请参阅下面使用描述模板的*一个复杂的例子*。

如果您需要提供比之前提到的两个变量更多的信息，还有一种方法可以将标题和描述模板传递给您。您可以在`Feed`子类中提供`get_context_data`方法的实现。例如：

```py
from mysite.models import Article 
from django.contrib.syndication.views import Feed 

class ArticlesFeed(Feed): 
    title = "My articles" 
    description_template = "feeds/articles.html" 

    def items(self): 
        return Article.objects.order_by('-pub_date')[:5] 

    def get_context_data(self, **kwargs): 
        context = super(ArticlesFeed, self).get_context_data(**kwargs) 
        context['foo'] = 'bar' 
        return context 

```

和模板：

```py
Something about {{ foo }}: {{ obj.description }} 

```

此方法将针对`items()`返回的列表中的每个项目调用一次，并带有以下关键字参数：

+   `item`：当前项目。出于向后兼容的原因，此上下文变量的名称为`{{ obj }}`。

+   `obj`：由`get_object()`返回的对象。默认情况下，这不会暴露给模板，以避免与`{{ obj }}`（见上文）混淆，但您可以在`get_context_data()`的实现中使用它。

+   `site`：如上所述的当前站点。

+   `request`：当前请求。

`get_context_data()`的行为模仿了通用视图的行为-您应该调用`super()`来从父类检索上下文数据，添加您的数据并返回修改后的字典。

要指定`<link>`的内容，您有两个选项。对于`items()`中的每个项目，Django 首先尝试在`Feed`类上调用`item_link()`方法。类似于标题和描述，它传递了一个参数-`item`。如果该方法不存在，Django 尝试在该对象上执行`get_absolute_url()`方法。

`get_absolute_url()`和`item_link()`都应返回项目的 URL 作为普通的 Python 字符串。与`get_absolute_url()`一样，`item_link()`的结果将直接包含在 URL 中，因此您负责在方法本身内部执行所有必要的 URL 引用和转换为 ASCII。

## 一个复杂的例子

该框架还通过参数支持更复杂的源。例如，网站可以为城市中每个警察拍摄提供最新犯罪的 RSS 源。为每个警察拍摄创建单独的`Feed`类是愚蠢的；这将违反 DRY 原则，并将数据耦合到编程逻辑中。

相反，辛迪加框架允许您访问从 URLconf 传递的参数，因此源可以根据源 URL 中的信息输出项目。警察拍摄源可以通过以下 URL 访问：

+   `/beats/613/rss/`-：返回 613 拍摄的最新犯罪。

+   `/beats/1424/rss/`-：返回 1424 拍摄的最新犯罪。

这些可以与 URLconf 行匹配，例如：

```py
url(r'^beats/(?P[0-9]+)/rss/$', BeatFeed()), 

```

与视图一样，URL 中的参数将与请求对象一起传递到`get_object()`方法。以下是这些特定于拍摄的源的代码：

```py
from django.contrib.syndication.views import FeedDoesNotExist 
from django.shortcuts import get_object_or_404 

class BeatFeed(Feed): 
    description_template = 'feeds/beat_description.html' 

    def get_object(self, request, beat_id): 
        return get_object_or_404(Beat, pk=beat_id) 

    def title(self, obj): 
        return "Police beat central: Crimes for beat %s" % obj.beat 

    def link(self, obj): 
        return obj.get_absolute_url() 

    def description(self, obj): 
        return "Crimes recently reported in police beat %s" % obj.beat 

    def items(self, obj): 
        return Crime.objects.filter(beat=obj).order_by(  
          '-crime_date')[:30] 

```

为了生成源的`<title>`，`<link>`和`<description>`，Django 使用`title()`，`link()`和`description()`方法。

在上一个示例中，它们是简单的字符串类属性，但是此示例说明它们可以是字符串*或*方法。对于`title`，`link`和`description`，Django 遵循此算法：

+   首先，它尝试调用一个方法，传递`obj`参数，其中`obj`是`get_object()`返回的对象。

+   如果失败，它将尝试调用一个没有参数的方法。

+   如果失败，它将使用 class 属性。

还要注意，`items()`也遵循相同的算法-首先尝试`items(obj)`，然后尝试`items()`，最后尝试`items`类属性（应该是一个列表）。我们正在使用模板来描述项目。它可以非常简单：

```py
{{ obj.description }} 

```

但是，您可以根据需要自由添加格式。下面的`ExampleFeed`类完整记录了`Feed`类的方法和属性。

## 指定源的类型

默认情况下，此框架生成的源使用 RSS 2.0。要更改此设置，请向您的`Feed`类添加`feed_type`属性，如下所示：

```py
from django.utils.feedgenerator import Atom1Feed 

class MyFeed(Feed): 
    feed_type = Atom1Feed 

```

请注意，将`feed_type`设置为类对象，而不是实例。当前可用的源类型有：

+   `django.utils.feedgenerator.Rss201rev2Feed`（RSS 2.01。默认）。

+   `django.utils.feedgenerator.RssUserland091Feed`（RSS 0.91）。

+   `django.utils.feedgenerator.Atom1Feed`（Atom 1.0）。

## 附件

要指定附件，例如在创建播客源时使用的附件，请使用`item_enclosure_url`，`item_enclosure_length`和`item_enclosure_mime_type`挂钩。有关用法示例，请参阅下面的`ExampleFeed`类。

## 语言

使用辛迪加框架创建的源自动包括适当的`<language>`标签（RSS 2.0）或`xml:lang`属性（Atom）。这直接来自您的`LANGUAGE_CODE`设置。

## URL

`link`方法/属性可以返回绝对路径（例如，`/blog/`）或具有完全合格的域和协议的 URL（例如，`http://www.example.com/blog/`）。如果`link`不返回域，辛迪加框架将根据您的`SITE_ID`设置插入当前站点的域。Atom 源需要定义源的当前位置的`<link rel="self">`。辛迪加框架会自动填充这一点，使用当前站点的域，根据`SITE_ID`设置。

## 同时发布 Atom 和 RSS 源

一些开发人员喜欢提供其源的 Atom 和 RSS 版本。在 Django 中很容易做到：只需创建`Feed`类的子类，并将`feed_type`设置为不同的内容。然后更新您的 URLconf 以添加额外的版本。以下是一个完整的示例：

```py
from django.contrib.syndication.views import Feed 
from policebeat.models import NewsItem 
from django.utils.feedgenerator import Atom1Feed 

class RssSiteNewsFeed(Feed): 
    title = "Police beat site news" 
    link = "/sitenews/" 
    description = "Updates on changes and additions to police beat central." 

    def items(self): 
        return NewsItem.objects.order_by('-pub_date')[:5] 

class AtomSiteNewsFeed(RssSiteNewsFeed): 
    feed_type = Atom1Feed 
    subtitle = RssSiteNewsFeed.description 

```

### 注意

在这个例子中，RSS feed 使用 `description`，而 Atom feed 使用 `subtitle`。这是因为 Atom feed 不提供 feed 级别的描述，但它们提供了一个副标题。如果您在 `Feed` 类中提供了 `description`，Django 将不会自动将其放入 `subtitle` 元素中，因为副标题和描述不一定是相同的。相反，您应该定义一个 `subtitle` 属性。

在上面的示例中，我们将 Atom feed 的 `subtitle` 设置为 RSS feed 的 `description`，因为它已经相当短了。并且相应的 URLconf：

```py
from django.conf.urls import url 
from myproject.feeds import RssSiteNewsFeed, AtomSiteNewsFeed 

urlpatterns = [ 
    # ... 
    url(r'^sitenews/rss/$', RssSiteNewsFeed()), 
    url(r'^sitenews/atom/$', AtomSiteNewsFeed()), 
    # ... 
] 

```

### 注意

有关 `Feed` 类的所有可能属性和方法的示例，请参见：`https://docs.djangoproject.com/en/1.8/ref/contrib/syndication/#feed-class-reference`

# 低级别框架

在幕后，高级 RSS 框架使用较低级别的框架来生成 feed 的 XML。这个框架存在于一个单独的模块中：`django/utils/feedgenerator.py`。您可以自己使用这个框架进行较低级别的 feed 生成。您还可以创建自定义 feed 生成器子类，以便与 `feed_type` `Feed` 选项一起使用。

## SyndicationFeed 类

`feedgenerator` 模块包含一个基类：

+   `django.utils.feedgenerator.SyndicationFeed`

和几个子类：

+   `django.utils.feedgenerator.RssUserland091Feed`

+   `django.utils.feedgenerator.Rss201rev2Feed`

+   `django.utils.feedgenerator.Atom1Feed`

这三个类都知道如何将某种类型的 feed 渲染为 XML。它们共享这个接口：

### SyndicationFeed.__init__()

使用给定的元数据字典初始化 feed，该元数据适用于整个 feed。必需的关键字参数是：

+   `标题`

+   `链接`

+   `描述`

还有一堆其他可选关键字：

+   `语言`

+   `作者电子邮件`

+   `作者名称`

+   `作者链接`

+   `副标题`

+   `类别`

+   `feed_url`

+   `feed_copyright`

+   `feed_guid`

+   `ttl`

您传递给 `__init__` 的任何额外关键字参数都将存储在 `self.feed` 中，以便与自定义 feed 生成器一起使用。

所有参数都应该是 Unicode 对象，除了 `categories`，它应该是 Unicode 对象的序列。

### SyndicationFeed.add_item()

使用给定参数向 feed 添加一个项目。

必需的关键字参数是：

+   `标题`

+   `链接`

+   `描述`

可选关键字参数是：

+   `作者电子邮件`

+   `作者名称`

+   `作者链接`

+   `pubdate`

+   `评论`

+   `unique_id`

+   `enclosure`

+   `类别`

+   `item_copyright`

+   `ttl`

+   `updateddate`

额外的关键字参数将被存储以供自定义 feed 生成器使用。所有参数，如果给定，都应该是 Unicode 对象，除了：

+   `pubdate` 应该是 Python `datetime` 对象。

+   `updateddate` 应该是 Python `datetime` 对象。

+   `enclosure` 应该是 `django.utils.feedgenerator.Enclosure` 的一个实例。

+   `categories` 应该是 Unicode 对象的序列。

### SyndicationFeed.write()

将 feed 以给定编码输出到 outfile，这是一个类似文件的对象。

### SyndicationFeed.writeString()

以给定编码的字符串形式返回 feed。例如，要创建 Atom 1.0 feed 并将其打印到标准输出：

```py
>>> from django.utils import feedgenerator 
>>> from datetime import datetime 
>>> f = feedgenerator.Atom1Feed( 
...     , 
...     link="http://www.example.com/", 
...     description="In which I write about what I ate today.", 
...     language="en", 
...     author_name="Myself", 
...     feed_url="http://example.com/atom.xml") 
>>> f.add_item(, 
...     link="http://www.example.com/entries/1/", 
...     pubdate=datetime.now(), 
...     description="<p>Today I had a Vienna Beef hot dog. It was pink, plump and perfect.</p>") 
>>> print(f.writeString('UTF-8')) 
<?xml version="1.0" encoding="UTF-8"?> 
<feed  xml:lang="en"> 
... 
</feed> 

```

## 自定义 feed 生成器

如果您需要生成自定义 feed 格式，您有几个选择。如果 feed 格式完全自定义，您将需要对 `SyndicationFeed` 进行子类化，并完全替换 `write()` 和 `writeString()` 方法。但是，如果 feed 格式是 RSS 或 Atom 的一个衍生格式（即 GeoRSS，（链接到网站 [`georss.org/`](http://georss.org/)），苹果的 iTunes podcast 格式（链接到网站 [`www.apple.com/itunes/podcasts/specs.html`](http://www.apple.com/itunes/podcasts/specs.html)）等），您有更好的选择。

这些类型的 feed 通常会向底层格式添加额外的元素和/或属性，并且有一组方法，`SyndicationFeed` 调用这些额外的属性。因此，您可以对适当的 feed 生成器类（`Atom1Feed` 或 `Rss201rev2Feed`）进行子类化，并扩展这些回调。它们是：

### SyndicationFeed.root_attributes(self, )

返回要添加到根源元素（`feed`/`channel`）的属性字典。

### SyndicationFeed.add_root_elements(self, handler)

回调以在根源元素（`feed`/`channel`）内添加元素。`handler`是 Python 内置 SAX 库中的`XMLGenerator`；您将在其上调用方法以添加到正在处理的 XML 文档中。

### SyndicationFeed.item_attributes(self, item)

返回要添加到每个条目（`item`/`entry`）元素的属性字典。参数`item`是传递给`SyndicationFeed.add_item()`的所有数据的字典。

### SyndicationFeed.add_item_elements(self, handler, item)

回调以向每个条目（`item`/`entry`）元素添加元素。`handler`和`item`与上述相同。

### 注意

如果您覆盖了这些方法中的任何一个，请确保调用超类方法，因为它们会为每个 feed 格式添加所需的元素。

例如，您可以开始实现一个 iTunes RSS feed 生成器，如下所示：

```py
class iTunesFeed(Rss201rev2Feed): 
    def root_attributes(self): 
        attrs = super(iTunesFeed, self).root_attributes() 
        attrs['xmlns:itunes'] =  
          'http://www.itunes.com/dtds/podcast-1.0.dtd' 
        return attrs 

    def add_root_elements(self, handler): 
        super(iTunesFeed, self).add_root_elements(handler) 
        handler.addQuickElement('itunes:explicit', 'clean') 

```

显然，要创建一个完整的自定义 feed 类还有很多工作要做，但上面的例子应该演示了基本思想。

# 站点地图框架

**站点地图**是您网站上的一个 XML 文件，告诉搜索引擎索引器您的页面更改的频率以及与站点上其他页面的重要性。这些信息有助于搜索引擎索引您的站点。有关站点地图的更多信息，请参阅 sitemaps.org 网站。

Django 站点地图框架通过让您在 Python 代码中表达此信息来自动创建此 XML 文件。它的工作方式与 Django 的 Syndication 框架类似。要创建站点地图，只需编写一个`Sitemap`类并在 URLconf 中指向它。

## 安装

要安装站点地图应用，请按照以下步骤进行：

+   将`"django.contrib.sitemaps"`添加到您的`INSTALLED_APPS`设置中。

+   确保您的`TEMPLATES`设置包含一个`DjangoTemplates`后端，其`APP_DIRS`选项设置为 True。默认情况下就在那里，所以只有在更改了该设置时才需要更改这一点。

+   确保您已安装了站点框架。

## 初始化

要在 Django 站点上激活站点地图生成，请将此行添加到您的 URLconf 中：

```py
from django.contrib.sitemaps.views import sitemap 

url(r'^sitemap\.xml$', sitemap, {'sitemaps': sitemaps}, 
    name='django.contrib.sitemaps.views.sitemap') 

```

这告诉 Django 在客户端访问`/sitemap.xml`时构建站点地图。站点地图文件的名称并不重要，但位置很重要。搜索引擎只会索引站点地图中当前 URL 级别及以下的链接。例如，如果`sitemap.xml`位于根目录中，它可以引用站点中的任何 URL。但是，如果您的站点地图位于`/content/sitemap.xml`，它只能引用以`/content/`开头的 URL。

站点地图视图需要一个额外的必需参数：`{'sitemaps': sitemaps}`。`sitemaps`应该是一个将短部分标签（例如`blog`或`news`）映射到其`Sitemap`类（例如`BlogSitemap`或`NewsSitemap`）的字典。它也可以映射到`Sitemap`类的实例（例如`BlogSitemap(some_var)`）。

## 站点地图类

`Sitemap`类是一个简单的 Python 类，表示站点地图中的条目部分。例如，一个`Sitemap`类可以表示您博客的所有条目，而另一个可以表示您事件日历中的所有事件。

在最简单的情况下，所有这些部分都被合并到一个`sitemap.xml`中，但也可以使用框架生成引用各个站点地图文件的站点地图索引，每个部分一个文件。（请参阅下面的创建站点地图索引。）

`Sitemap`类必须是`django.contrib.sitemaps.Sitemap`的子类。它们可以存在于代码库中的任何位置。

## 一个简单的例子

假设您有一个博客系统，其中有一个`Entry`模型，并且您希望您的站点地图包括到您个人博客条目的所有链接。以下是您的站点地图类可能如何看起来：

```py
from django.contrib.sitemaps import Sitemap 
from blog.models import Entry 

class BlogSitemap(Sitemap): 
    changefreq = "never" 
    priority = 0.5 

    def items(self): 
        return Entry.objects.filter(is_draft=False) 

    def lastmod(self, obj): 
        return obj.pub_date 

```

**注意：**

+   `changefreq`和`priority`是对应于`<changefreq>`和`<priority>`元素的类属性。它们可以作为函数调用，就像上面的`lastmod`一样。

+   `items()`只是返回对象列表的方法。返回的对象将传递给与站点地图属性（`location`，`lastmod`，`changefreq`和`priority`）对应的任何可调用方法。

+   `lastmod`应返回 Python `datetime`对象。

+   在此示例中没有`location`方法，但您可以提供它以指定对象的 URL。默认情况下，`location()`调用每个对象上的`get_absolute_url()`并返回结果。

## 站点地图类参考

`Sitemap`类可以定义以下方法/属性：

### items

**必需。**返回对象列表的方法。框架不关心它们是什么*类型*的对象；重要的是这些对象传递给`location()`，`lastmod()`，`changefreq()`和`priority()`方法。

### 位置

**可选。**可以是方法或属性。如果是方法，它应该返回`items()`返回的给定对象的绝对路径。如果是属性，其值应该是表示`items()`返回的每个对象使用的绝对路径的字符串。

在这两种情况下，绝对路径表示不包括协议或域的 URL。示例：

+   好的：`'/foo/bar/'`

+   不好：`'example.com/foo/bar/'`

+   不好：`'http://example.com/foo/bar/'`

如果未提供`location`，框架将调用`items()`返回的每个对象上的`get_absolute_url()`方法。要指定除`http`之外的协议，请使用`protocol`。

### lastmod

**可选。**可以是方法或属性。如果是方法，它应该接受一个参数-`items()`返回的对象-并返回该对象的最后修改日期/时间，作为 Python `datetime.datetime`对象。

如果它是一个属性，其值应该是一个 Python `datetime.datetime`对象，表示`items()`返回的*每个*对象的最后修改日期/时间。如果站点地图中的所有项目都有`lastmod`，则`views.sitemap()`生成的站点地图将具有等于最新`lastmod`的`Last-Modified`标头。

您可以激活`ConditionalGetMiddleware`，使 Django 对具有`If-Modified-Since`标头的请求做出适当响应，这将防止在站点地图未更改时发送站点地图。

### changefreq

**可选。**可以是方法或属性。如果是方法，它应该接受一个参数-`items()`返回的对象-并返回该对象的更改频率，作为 Python 字符串。如果是属性，其值应该是表示`items()`返回的每个对象的更改频率的字符串。无论您使用方法还是属性，`changefreq`的可能值是：

+   `'always'`

+   `'hourly'`

+   `'daily'`

+   `'weekly'`

+   `'monthly'`

+   `'yearly'`

+   `'never'`

### priority

**可选。**可以是方法或属性。如果是方法，它应该接受一个参数-`items()`返回的对象-并返回该对象的优先级，作为字符串或浮点数。

如果它是一个属性，其值应该是一个字符串或浮点数，表示`items()`返回的每个对象的优先级。`priority`的示例值：`0.4`，`1.0`。页面的默认优先级为`0.5`。有关更多信息，请参阅 sitemaps.org 文档。

### 协议

**可选。**此属性定义站点地图中 URL 的协议（`http`或`https`）。如果未设置，将使用请求站点地图的协议。如果站点地图是在请求的上下文之外构建的，则默认值为`http`。

### i18n

**可选。**一个布尔属性，定义此站点地图的 URL 是否应使用所有`LANGUAGES`生成。默认值为`False`。

## 快捷方式

网站地图框架为常见情况提供了一个方便的类-`django.contrib.syndication.GenericSitemap`

`django.contrib.sitemaps.GenericSitemap`类允许您通过向其传递至少包含`queryset`条目的字典来创建站点地图。此查询集将用于生成站点地图的项目。它还可以具有指定从`queryset`检索的对象的日期字段的`date_field`条目。

这将用于生成的站点地图中的`lastmod`属性。您还可以将`priority`和`changefreq`关键字参数传递给`GenericSitemap`构造函数，以指定所有 URL 的这些属性。

### 例子

以下是使用`GenericSitemap`的 URLconf 示例：

```py
from django.conf.urls import url 
from django.contrib.sitemaps import GenericSitemap 
from django.contrib.sitemaps.views import sitemap 
from blog.models import Entry 

info_dict = { 
    'queryset': Entry.objects.all(), 
    'date_field': 'pub_date', 
} 

urlpatterns = [ 
    # some generic view using info_dict 
    # ... 

    # the sitemap 
    url(r'^sitemap\.xml$', sitemap, 
        {'sitemaps': {'blog': GenericSitemap(info_dict, priority=0.6)}},  
        name='django.contrib.sitemaps.views.sitemap'), 
] 

```

## 静态视图的站点地图

通常，您希望搜索引擎爬虫索引既不是对象详细页面也不是平面页面的视图。解决方案是在`sitemap`的`items`中显式列出这些视图的 URL 名称，并在`sitemap`的`location`方法中调用`reverse()`。例如：

```py
# sitemaps.py 
from django.contrib import sitemaps 
from django.core.urlresolvers import reverse 

class StaticViewSitemap(sitemaps.Sitemap): 
    priority = 0.5 
    changefreq = 'daily' 

    def items(self): 
        return ['main', 'about', 'license'] 

    def location(self, item): 
        return reverse(item) 

# urls.py 
from django.conf.urls import url 
from django.contrib.sitemaps.views import sitemap 

from .sitemaps import StaticViewSitemap 
from . import views 

sitemaps = { 
    'static': StaticViewSitemap, 
} 

urlpatterns = [ 
    url(r'^$', views.main, name='main'), 
    url(r'^about/$', views.about, name='about'), 
    url(r'^license/$', views.license, name='license'), 
    # ... 
    url(r'^sitemap\.xml$', sitemap, {'sitemaps': sitemaps}, 
        name='django.contrib.sitemaps.views.sitemap') 
] 

```

## 创建站点地图索引

站点地图框架还具有创建引用各自`sitemaps`字典中定义的每个部分的单独站点地图文件的站点地图索引的功能。使用的唯一区别是：

+   您在 URLconf 中使用了两个视图：`django.contrib.sitemaps.views.index()`和`django.contrib.sitemaps.views.sitemap()`。

+   `django.contrib.sitemaps.views.sitemap()`视图应该接受一个`section`关键字参数。

以下是上述示例的相关 URLconf 行的样子：

```py
from django.contrib.sitemaps import views 

urlpatterns = [ 
    url(r'^sitemap\.xml$', views.index, {'sitemaps': sitemaps}), 
    url(r'^sitemap-(?P<section>.+)\.xml$', views.sitemap,  
        {'sitemaps': sitemaps}), 
] 

```

这将自动生成一个`sitemap.xml`文件，其中引用了`sitemap-flatpages.xml`和`sitemap-blog.xml`。`Sitemap`类和`sitemaps`字典完全不会改变。

如果您的站点地图中有超过 50,000 个 URL，则应创建一个索引文件。在这种情况下，Django 将自动对站点地图进行分页，并且索引将反映这一点。如果您没有使用原始站点地图视图-例如，如果它被缓存装饰器包装-您必须为您的站点地图视图命名，并将`sitemap_url_name`传递给索引视图：

```py
from django.contrib.sitemaps import views as sitemaps_views 
from django.views.decorators.cache import cache_page 

urlpatterns = [ 
    url(r'^sitemap\.xml$', 
        cache_page(86400)(sitemaps_views.index), 
        {'sitemaps': sitemaps, 'sitemap_url_name': 'sitemaps'}), 
    url(r'^sitemap-(?P<section>.+)\.xml$', 
        cache_page(86400)(sitemaps_views.sitemap), 
        {'sitemaps': sitemaps}, name='sitemaps'), 
] 

```

## 模板自定义

如果您希望在站点上可用的每个站点地图或站点地图索引使用不同的模板，您可以通过在 URLconf 中向`sitemap`和`index`视图传递`template_name`参数来指定它：

```py
from django.contrib.sitemaps import views 

urlpatterns = [ 
    url(r'^custom-sitemap\.xml$', views.index, { 
        'sitemaps': sitemaps, 
        'template_name': 'custom_sitemap.html' 
    }), 
    url(r'^custom-sitemap-(?P<section>.+)\.xml$', views.sitemap, { 
    'sitemaps': sitemaps, 
    'template_name': 'custom_sitemap.html' 
}), 
] 

```

## 上下文变量

在自定义`index()`和`sitemap()`视图的模板时，您可以依赖以下上下文变量。

### 索引

变量`sitemaps`是每个站点地图的绝对 URL 的列表。

### 站点地图

变量`urlset`是应该出现在站点地图中的 URL 列表。每个 URL 都公开了`Sitemap`类中定义的属性：

+   `changefreq`

+   `item`

+   `lastmod`

+   `位置`

+   `priority`

已为每个 URL 添加了`item`属性，以允许对模板进行更灵活的自定义，例如 Google 新闻站点地图。假设 Sitemap 的`items()`将返回一个具有`publication_data`和`tags`字段的项目列表，类似这样将生成一个与 Google 兼容的站点地图：

```py
{% spaceless %} 
{% for url in urlset %} 
    {{ url.location }} 
    {% if url.lastmod %}{{ url.lastmod|date:"Y-m-d" }}{% endif %} 
    {% if url.changefreq %}{{ url.changefreq }}{% endif %} 
    {% if url.priority %}{{ url.priority }}{% endif %} 

      {% if url.item.publication_date %}{{ url.item.publication_date|date:"Y-m-d" }}{% endif %} 
      {% if url.item.tags %}{{ url.item.tags }}{% endif %} 

{% endfor %} 
{% endspaceless %} 

```

## ping google

当您的站点地图发生更改时，您可能希望向 Google 发送 ping，以便让它知道重新索引您的站点。站点地图框架提供了一个函数来实现这一点：

### django.contrib.syndication.ping_google()

`ping_google()`接受一个可选参数`sitemap_url`，它应该是站点地图的绝对路径（例如`'/sitemap.xml'`）。如果未提供此参数，`ping_google()`将尝试通过在 URLconf 中执行反向查找来确定您的站点地图。如果无法确定您的站点地图 URL，`ping_google()`会引发异常`django.contrib.sitemaps.SitemapNotFound`。

从模型的`save()`方法中调用`ping_google()`的一个有用的方法是：

```py
from django.contrib.sitemaps import ping_google 

class Entry(models.Model): 
    # ... 
    def save(self, force_insert=False, force_update=False): 
        super(Entry, self).save(force_insert, force_update) 
        try: 
            ping_google() 
        except Exception: 
            # Bare 'except' because we could get a variety 
            # of HTTP-related exceptions. 
            pass 

```

然而，更有效的解决方案是从 cron 脚本或其他计划任务中调用`ping_google()`。该函数会向 Google 的服务器发出 HTTP 请求，因此您可能不希望在每次调用`save()`时引入网络开销。

### 通过 manage.py 向 Google 发送 ping

一旦站点地图应用程序添加到您的项目中，您还可以使用`ping_google`管理命令来 ping Google：

```py
python manage.py ping_google [/sitemap.xml] 

```

### 注意

**首先向 Google 注册！**只有在您已经在 Google 网站管理员工具中注册了您的站点时，`ping_google()`命令才能起作用。

# 接下来是什么？

接下来，我们将继续深入研究 Django 提供的内置工具，通过更仔细地查看 Django 会话框架。


# 第十五章：Django 会话

想象一下，如果您每次导航到另一个页面都必须重新登录到网站，或者您最喜欢的网站忘记了所有的设置，您每次访问时都必须重新输入？

现代网站如果没有一种方式来记住您是谁以及您在网站上的先前活动，就无法提供我们习惯的可用性和便利性。HTTP 是*无状态*的设计-在一次请求和下一次请求之间没有持久性，服务器无法判断连续的请求是否来自同一个人。

这种状态的缺乏是通过*会话*来管理的，这是您的浏览器和 Web 服务器之间的一种半永久的双向通信。当您访问现代网站时，在大多数情况下，Web 服务器将使用*匿名会话*来跟踪与您的访问相关的数据。会话被称为匿名，因为 Web 服务器只能记录您的操作，而不能记录您是谁。

我们都经历过这种情况，当我们在以后返回到电子商务网站时，发现我们放在购物车中的物品仍然在那里，尽管没有提供任何个人信息。会话通常使用经常受到诟病但很少被理解的*cookie*来持久化。与所有其他 Web 框架一样，Django 也使用 cookie，但以更聪明和安全的方式，您将看到。

Django 完全支持匿名会话。会话框架允许您在每个站点访问者的基础上存储和检索任意数据。它在服务器端存储数据并抽象了发送和接收 cookie。Cookie 包含会话 ID-而不是数据本身（除非您使用基于 cookie 的后端）；这是一种比其他框架更安全的实现 cookie 的方式。

# 启用会话

会话是通过中间件实现的。要启用会话功能，请编辑`MIDDLEWARE_CLASSES`设置，并确保其中包含`'django.contrib.sessions.middleware.SessionMiddleware'`。由`django-admin startproject`创建的默认`settings.py`已激活`SessionMiddleware`。

如果您不想使用会话，您也可以从`MIDDLEWARE_CLASSES`中删除`SessionMiddleware`行，并从`INSTALLED_APPS`中删除`'django.contrib.sessions'`。这将节省一点开销。

# 配置会话引擎

默认情况下，Django 将会话存储在数据库中（使用模型`django.contrib.sessions.models.Session`）。虽然这很方便，但在某些设置中，将会话数据存储在其他地方可能更快，因此可以配置 Django 将会话数据存储在文件系统或缓存中。

## 使用基于数据库的会话

如果您想使用基于数据库的会话，您需要将`'django.contrib.sessions'`添加到您的`INSTALLED_APPS`设置中。一旦配置了安装，运行`manage.py migrate`来安装存储会话数据的单个数据库表。

## 使用缓存会话

为了获得更好的性能，您可能希望使用基于缓存的会话后端。要使用 Django 的缓存系统存储会话数据，您首先需要确保已配置了缓存；有关详细信息，请参阅缓存文档。

### 注意

只有在使用 Memcached 缓存后端时，才应该使用基于缓存的会话。本地内存缓存后端不会保留数据足够长时间，因此直接使用文件或数据库会话而不是通过文件或数据库缓存后端发送所有内容将更快。此外，本地内存缓存后端不是多进程安全的，因此在生产环境中可能不是一个好选择。

如果在`CACHES`中定义了多个缓存，Django 将使用默认缓存。要使用另一个缓存，将`SESSION_CACHE_ALIAS`设置为该缓存的名称。配置好缓存后，您有两种选择来存储缓存中的数据：

+   将`SESSION_ENGINE`设置为`"django.contrib.sessions.backends.cache"`以使用简单的缓存会话存储。会话数据将直接存储在缓存中。但是，会话数据可能不是持久的：如果缓存填满或缓存服务器重新启动，缓存数据可能会被驱逐。

+   对于持久的缓存数据，将`SESSION_ENGINE`设置为`"django.contrib.sessions.backends.cached_db"`。这使用了一个写入缓存-每次写入缓存时也会写入数据库。会话读取仅在数据不在缓存中时才使用数据库。

这两种会话存储都非常快，但简单缓存更快，因为它忽略了持久性。在大多数情况下，`cached_db`后端将足够快，但如果您需要最后一点性能，并且愿意让会话数据不时被清除，那么`cache`后端适合您。如果您使用`cached_db`会话后端，还需要遵循使用基于数据库的会话的配置说明。

## 使用基于文件的会话

要使用基于文件的会话，请将`SESSION_ENGINE`设置为`"django.contrib.sessions.backends.file"`。您可能还想设置`SESSION_FILE_PATH`设置（默认为`tempfile.gettempdir()`的输出，很可能是`/tmp`）以控制 Django 存储会话文件的位置。请确保您的 Web 服务器有权限读取和写入此位置。

## 使用基于 cookie 的会话

要使用基于 cookie 的会话，请将`SESSION_ENGINE`设置为`"django.contrib.sessions.backends.signed_cookies"`。会话数据将使用 Django 的加密签名工具和`SECRET_KEY`设置进行存储。

建议将`SESSION_COOKIE_HTTPONLY`设置为`True`，以防止 JavaScript 访问存储的数据。

### 注意

**如果`SECRET_KEY`不保密，并且您使用`PickleSerializer`，这可能导致任意远程代码执行。**

拥有`SECRET_KEY`的攻击者不仅可以生成被您的站点信任的伪造会话数据，还可以远程执行任意代码，因为数据使用 pickle 进行序列化。如果您使用基于 cookie 的会话，请特别注意始终保持您的秘钥完全保密，以防止任何可能远程访问的系统。

### 注意

**会话数据已签名但未加密**

在使用 cookie 后端时，会话数据可以被客户端读取。使用 MAC（消息认证码）来保护数据免受客户端的更改，因此当被篡改时会使会话数据无效。如果存储 cookie 的客户端（例如，您的用户浏览器）无法存储所有会话 cookie 并丢弃数据，也会发生相同的无效。即使 Django 压缩了数据，仍然完全有可能超过每个 cookie 的常见限制 4096 字节。

### 注意

**没有新鲜度保证**

还要注意，虽然 MAC 可以保证数据的真实性（即它是由您的站点生成的，而不是其他人），以及数据的完整性（即它是否完整且正确），但它无法保证新鲜度，也就是说，您被发送回客户端的是您最后发送的内容。这意味着对于某些会话数据的使用，cookie 后端可能会使您容易受到重放攻击。与其他会话后端不同，其他会话后端会在用户注销时保留每个会话的服务器端记录并使其无效，而基于 cookie 的会话在用户注销时不会被无效。因此，如果攻击者窃取了用户的 cookie，他们可以使用该 cookie 以该用户的身份登录，即使用户已注销。只有当 cookie 的年龄大于您的`SESSION_COOKIE_AGE`时，才会检测到 cookie 已过期。

最后，假设上述警告没有阻止您使用基于 cookie 的会话：cookie 的大小也会影响站点的速度。

# 在视图中使用会话

当激活`SessionMiddleware`时，每个`HttpRequest`对象-任何 Django 视图函数的第一个参数-都将有一个`session`属性，这是一个类似字典的对象。您可以在视图的任何时候读取它并写入`request.session`。您可以多次编辑它。

所有会话对象都继承自基类`backends.base.SessionBase`。它具有以下标准字典方法：

+   `__getitem__(key)`

+   `__setitem__(key, value)`

+   `__delitem__(key)`

+   `__contains__(key)`

+   `get(key, default=None)`

+   `pop(key)`

+   `keys()`

+   `items()`

+   `setdefault()`

+   `clear()`

它还具有这些方法：

## flush()

从会话中删除当前会话数据并删除会话 cookie。如果您希望确保无法再次从用户的浏览器访问以前的会话数据（例如，`django.contrib.auth.logout()`函数调用它）。

## set_test_cookie()

设置一个测试 cookie 以确定用户的浏览器是否支持 cookie。由于 cookie 的工作方式，您将无法在用户的下一个页面请求之前测试这一点。有关更多信息，请参见下面的*设置测试 cookie*。

## test_cookie_worked()

返回`True`或`False`，取决于用户的浏览器是否接受了测试 cookie。由于 cookie 的工作方式，您将不得不在先前的单独页面请求上调用`set_test_cookie()`。有关更多信息，请参见下面的*设置测试 cookie*。

## delete_test_cookie()

删除测试 cookie。使用此方法进行清理。

## set_expiry(value)

设置会话的过期时间。您可以传递许多不同的值：

+   如果`value`是一个整数，会话将在多少秒的不活动后过期。例如，调用`request.session.set_expiry(300)`会使会话在 5 分钟后过期。

+   如果`value`是`datetime`或`timedelta`对象，则会话将在特定日期/时间过期。请注意，只有在使用`PickleSerializer`时，`datetime`和`timedelta`值才能被序列化。

+   如果`value`是`0`，用户的会话 cookie 将在用户的 Web 浏览器关闭时过期。

+   如果`value`是`None`，会话将恢复使用全局会话过期策略。

阅读会话不被视为过期目的的活动。会话的过期是根据会话上次修改的时间计算的。

## get_expiry_age()

返回直到此会话过期的秒数。对于没有自定义过期时间（或者设置为在浏览器关闭时过期）的会话，这将等于`SESSION_COOKIE_AGE`。此函数接受两个可选的关键字参数：

+   `modification`：会话的最后修改，作为`datetime`对象。默认为当前时间

+   `expiry`：会话的过期信息，作为`datetime`对象，一个`int`（以秒为单位），或`None`。默认为通过`set_expiry()`存储在会话中的值，如果有的话，或`None`

## get_expiry_date()

返回此会话将过期的日期。对于没有自定义过期时间（或者设置为在浏览器关闭时过期）的会话，这将等于从现在开始`SESSION_COOKIE_AGE`秒的日期。此函数接受与`get_expiry_age()`相同的关键字参数。

## get_expire_at_browser_close()

返回`True`或`False`，取决于用户的会话 cookie 是否在用户的 Web 浏览器关闭时过期。

## clear_expired()

从会话存储中删除过期的会话。这个类方法由`clearsessions`调用。

## cycle_key()

在保留当前会话数据的同时创建一个新的会话密钥。`django.contrib.auth.login()`调用此方法以减轻会话固定。

# 会话对象指南

+   在`request.session`上使用普通的 Python 字符串作为字典键。这更多是一种约定而不是一条硬性规定。

+   以下划线开头的会话字典键是由 Django 内部使用的保留字。

不要用新对象覆盖`request.session`，也不要访问或设置其属性。像使用 Python 字典一样使用它。

# 会话序列化

在 1.6 版本之前，Django 默认使用`pickle`对会话数据进行序列化后存储在后端。如果您使用签名的 cookie 会话后端并且`SECRET_KEY`被攻击者知晓（Django 本身没有固有的漏洞会导致泄漏），攻击者可以在其会话中插入一个字符串，该字符串在反序列化时在服务器上执行任意代码。这种技术简单易行，并且在互联网上很容易获得。

尽管 cookie 会话存储对 cookie 存储的数据进行签名以防篡改，但`SECRET_KEY`泄漏会立即升级为远程代码执行漏洞。可以通过使用 JSON 而不是`pickle`对会话数据进行序列化来减轻此攻击。为了方便这一点，Django 1.5.3 引入了一个新的设置`SESSION_SERIALIZER`，用于自定义会话序列化格式。为了向后兼容，Django 1.5.x 中此设置默认使用`django.contrib.sessions.serializers.PickleSerializer`，但为了加强安全性，从 Django 1.6 开始默认使用`django.contrib.sessions.serializers.JSONSerializer`。

即使在自定义序列化器中描述的注意事项中，我们强烈建议坚持使用 JSON 序列化*特别是如果您使用 cookie 后端*。

## 捆绑的序列化器

### 序列化器.JSONSerializer

从`django.core.signing`的 JSON 序列化器周围的包装器。只能序列化基本数据类型。此外，由于 JSON 仅支持字符串键，请注意在`request.session`中使用非字符串键将无法按预期工作：

```py
>>> # initial assignment 
>>> request.session[0] = 'bar' 
>>> # subsequent requests following serialization & deserialization 
>>> # of session data 
>>> request.session[0]  # KeyError 
>>> request.session['0'] 
'bar' 

```

请参阅自定义序列化器部分，了解 JSON 序列化的限制详情。

### 序列化器.PickleSerializer

支持任意 Python 对象，但如上所述，如果`SECRET_KEY`被攻击者知晓，可能会导致远程代码执行漏洞。

## 编写自己的序列化器

请注意，与`PickleSerializer`不同，`JSONSerializer`无法处理任意 Python 数据类型。通常情况下，方便性和安全性之间存在权衡。如果您希望在 JSON 支持的会话中存储更高级的数据类型，包括`datetime`和`Decimal`，则需要编写自定义序列化器（或在将这些值存储在`request.session`之前将其转换为 JSON 可序列化对象）。

虽然序列化这些值相当简单（`django.core.serializers.json.DateTimeAwareJSONEncoder`可能会有所帮助），但编写一个可靠地获取与输入相同内容的解码器更加脆弱。例如，您可能会冒返回实际上是字符串的`datetime`的风险，只是碰巧与`datetime`选择的相同格式相匹配）。

您的序列化器类必须实现两个方法，`dumps(self, obj)`和`loads(self, data)`，分别用于序列化和反序列化会话数据字典。

# 设置测试 cookie

作为便利，Django 提供了一种简单的方法来测试用户的浏览器是否接受 cookie。只需在视图中调用`request.session`的`set_test_cookie()`方法，并在随后的视图中调用`test_cookie_worked()`，而不是在同一视图调用中。

`set_test_cookie()`和`test_cookie_worked()`之间的这种尴尬分离是由于 cookie 的工作方式。当您设置一个 cookie 时，实际上无法确定浏览器是否接受它，直到浏览器的下一个请求。在验证测试 cookie 有效后，请使用`delete_test_cookie()`进行清理是一个良好的做法。

以下是典型的用法示例：

```py
def login(request): 
    if request.method == 'POST': 
        if request.session.test_cookie_worked(): 
            request.session.delete_test_cookie() 
            return HttpResponse("You're logged in.") 
        else: 
            return HttpResponse("Please enable cookies and try again.") 
    request.session.set_test_cookie() 
    return render_to_response('foo/login_form.html') 

```

# 在视图之外使用会话

本节中的示例直接从`django.contrib.sessions.backends.db`后端导入`SessionStore`对象。在您自己的代码中，您应该考虑从`SESSION_ENGINE`指定的会话引擎中导入`SessionStore`，如下所示：

```py
>>> from importlib import import_module 
>>> from django.conf import settings 
>>> SessionStore = import_module(settings.SESSION_ENGINE).SessionStore 

```

API 可用于在视图之外操作会话数据：

```py
>>> from django.contrib.sessions.backends.db import SessionStore 
>>> s = SessionStore() 
>>> # stored as seconds since epoch since datetimes are not serializable in JSON. 
>>> s['last_login'] = 1376587691 
>>> s.save() 
>>> s.session_key 
'2b1189a188b44ad18c35e113ac6ceead' 

>>> s = SessionStore(session_key='2b1189a188b44ad18c35e113ac6ceead') 
>>> s['last_login'] 
1376587691 

```

为了减轻会话固定攻击，不存在的会话密钥将被重新生成：

```py
>>> from django.contrib.sessions.backends.db import SessionStore 
>>> s = SessionStore(session_key='no-such-session-here') 
>>> s.save() 
>>> s.session_key 
'ff882814010ccbc3c870523934fee5a2' 

```

如果您使用`django.contrib.sessions.backends.db`后端，每个会话只是一个普通的 Django 模型。`Session`模型在`django/contrib/sessions/models.py`中定义。因为它是一个普通模型，您可以使用普通的 Django 数据库 API 访问会话：

```py
>>> from django.contrib.sessions.models import Session 
>>> s = Session.objects.get(pk='2b1189a188b44ad18c35e113ac6ceead') 
>>> s.expire_date 
datetime.datetime(2005, 8, 20, 13, 35, 12) 
Note that you'll need to call get_decoded() to get the session dictionary. This is necessary because the dictionary is stored in an encoded format: 
>>> s.session_data 
'KGRwMQpTJ19hdXRoX3VzZXJfaWQnCnAyCkkxCnMuMTExY2ZjODI2Yj...' 
>>> s.get_decoded() 
{'user_id': 42} 

```

# 会话保存时

默认情况下，只有在会话已被修改时（即其字典值已被分配或删除）Django 才会保存到会话数据库：

```py
# Session is modified. 
request.session['foo'] = 'bar' 

# Session is modified. 
del request.session['foo'] 

# Session is modified. 
request.session['foo'] = {} 

# Gotcha: Session is NOT modified, because this alters 
# request.session['foo'] instead of request.session. 
request.session['foo']['bar'] = 'baz' 

```

在上面示例的最后一种情况中，我们可以通过在会话对象上设置`modified`属性来明确告诉会话对象已被修改：

```py
request.session.modified = True 

```

要更改此默认行为，请将`SESSION_SAVE_EVERY_REQUEST`设置为`True`。当设置为`True`时，Django 将在每个请求上将会话保存到数据库。请注意，只有在创建或修改会话时才会发送会话 cookie。如果`SESSION_SAVE_EVERY_REQUEST`为`True`，则会在每个请求上发送会话 cookie。类似地，会话 cookie 的`expires`部分在每次发送会话 cookie 时都会更新。如果响应的状态码为 500，则不会保存会话。

# 浏览器长度会话与持久会话

您可以通过`SESSION_EXPIRE_AT_BROWSER_CLOSE`设置来控制会话框架是使用浏览器长度会话还是持久会话。默认情况下，`SESSION_EXPIRE_AT_BROWSER_CLOSE`设置为`False`，这意味着会话 cookie 将在用户的浏览器中存储，直到`SESSION_COOKIE_AGE`。如果您不希望用户每次打开浏览器时都需要登录，请使用此设置。

如果`SESSION_EXPIRE_AT_BROWSER_CLOSE`设置为`True`，Django 将使用浏览器长度的 cookie-即当用户关闭浏览器时立即过期的 cookie。

### 注意

一些浏览器（例如 Chrome）提供设置，允许用户在关闭和重新打开浏览器后继续浏览会话。在某些情况下，这可能会干扰`SESSION_EXPIRE_AT_BROWSER_CLOSE`设置，并阻止会话在关闭浏览器时过期。请在测试启用了`SESSION_EXPIRE_AT_BROWSER_CLOSE`设置的 Django 应用程序时注意这一点。

# 清除会话存储

当用户在您的网站上创建新会话时，会话数据可能会在会话存储中累积。Django 不提供自动清除过期会话。因此，您需要定期清除过期会话。Django 为此提供了一个清理管理命令：`clearsessions`。建议定期调用此命令，例如作为每日 cron 作业。

请注意，缓存后端不会受到此问题的影响，因为缓存会自动删除过时数据。Cookie 后端也不会受到影响，因为会话数据是由用户的浏览器存储的。

# 接下来是什么

接下来，我们将继续研究更高级的 Django 主题，通过检查 Django 的缓存后端。


# 第十六章：Django 的缓存框架

动态网站的一个基本权衡是，它们是动态的。每当用户请求一个页面时，Web 服务器都会进行各种计算，从数据库查询到模板渲染到业务逻辑再到创建用户所看到的页面。从处理开销的角度来看，这比标准的从文件系统中读取文件的服务器安排要昂贵得多。

对于大多数 Web 应用程序来说，这种开销并不是什么大问题。大多数 Web 应用程序不是 www.washingtonpost.com 或 www.slashdot.org；它们只是一些流量一般的中小型站点。但对于中高流量的站点来说，尽量减少开销是至关重要的。

这就是缓存的作用。缓存某些东西就是保存昂贵计算的结果，这样你就不必在下一次执行计算。下面是一些伪代码，解释了这在动态生成的网页上是如何工作的：

```py
given a URL, try finding that page in the cache 
if the page is in the cache: 
    return the cached page 
else: 
    generate the page 
    save the generated page in the cache (for next time) 
    return the generated page 

```

Django 自带一个强大的缓存系统，可以让你保存动态页面，这样它们就不必为每个请求重新计算。为了方便起见，Django 提供了不同级别的缓存粒度：你可以缓存特定视图的输出，也可以只缓存难以生成的部分，或者缓存整个站点。

Django 也可以很好地与下游缓存（如 Squid，更多信息请访问 [`www.squid-cache.org/`](http://www.squid-cache.org/)）和基于浏览器的缓存一起使用。这些是你无法直接控制的缓存类型，但你可以通过 HTTP 头提供关于你的站点应该缓存哪些部分以及如何缓存的提示。

# 设置缓存

缓存系统需要进行一些设置。主要是告诉它你的缓存数据应该存放在哪里；是在数据库中、在文件系统中还是直接在内存中。这是一个影响缓存性能的重要决定。

你的缓存偏好设置在设置文件的 `CACHES` 设置中。

## Memcached

Django 原生支持的最快、最高效的缓存类型是 Memcached（更多信息请访问 [`memcached.org/`](http://memcached.org/)），它是一个完全基于内存的缓存服务器，最初是为了处理 LiveJournal.com 上的高负载而开发的，并且后来由 Danga Interactive 开源。它被 Facebook 和 Wikipedia 等网站使用，以减少数据库访问并显著提高站点性能。

Memcached 作为守护进程运行，并被分配了指定的内存量。它所做的就是提供一个快速的接口，用于在缓存中添加、检索和删除数据。所有数据都直接存储在内存中，因此没有数据库或文件系统使用的开销。

安装完 Memcached 本身后，你需要安装一个 Memcached 绑定。有几个 Python Memcached 绑定可用；最常见的两个是 python-memcached（ftp://ftp.tummy.com/pub/python-memcached/）和 pylibmc（[`sendapatch.se/projects/pylibmc/`](http://sendapatch.se/projects/pylibmc/)）。要在 Django 中使用 Memcached：

+   将 `BACKEND` 设置为 `django.core.cache.backends.memcached.MemcachedCache` 或 `django.core.cache.backends.memcached.PyLibMCCache`（取决于你选择的 memcached 绑定）

+   将 `LOCATION` 设置为 `ip:port` 值，其中 `ip` 是 Memcached 守护进程的 IP 地址，`port` 是 Memcached 运行的端口，或者设置为 `unix:path` 值，其中 `path` 是 Memcached Unix socket 文件的路径。

在这个例子中，Memcached 在本地主机（`127.0.0.1`）的端口 11211 上运行，使用 `python-memcached` 绑定：

```py
CACHES = { 
    'default': { 
        'BACKEND': 'django.core.cache.backends.memcached.MemcachedCache', 
        'LOCATION': '127.0.0.1:11211', 
    } 
} 

```

在这个例子中，Memcached 可以通过本地的 Unix socket 文件 `/tmp/memcached.sock` 使用 `python-memcached` 绑定来访问：

```py
CACHES = { 
    'default': { 
        'BACKEND': 'django.core.cache.backends.memcached.MemcachedCache', 
        'LOCATION': 'unix:/tmp/memcached.sock', 
    } 
} 

```

Memcached 的一个优秀特性是它能够在多台服务器上共享缓存。这意味着您可以在多台机器上运行 Memcached 守护程序，并且程序将把这组机器视为*单个*缓存，而无需在每台机器上复制缓存值。要利用这个特性，在`LOCATION`中包含所有服务器地址，可以用分号分隔或作为列表。

在这个例子中，缓存是在 IP 地址`172.19.26.240`和`172.19.26.242`上运行的 Memcached 实例之间共享的，端口都是 11211：

```py
CACHES = { 
    'default': { 
        'BACKEND': 'django.core.cache.backends.memcached.MemcachedCache', 
        'LOCATION': [ 
            '172.19.26.240:11211', 
            '172.19.26.242:11211', 
        ] 
    } 
} 

```

在下面的例子中，缓存是在 IP 地址`172.19.26.240`（端口 11211）、`172.19.26.242`（端口 11212）和`172.19.26.244`（端口 11213）上运行的 Memcached 实例之间共享的：

```py
CACHES = { 
    'default': { 
        'BACKEND': 'django.core.cache.backends.memcached.MemcachedCache', 
        'LOCATION': [ 
            '172.19.26.240:11211', 
            '172.19.26.242:11212', 
            '172.19.26.244:11213', 
        ] 
    } 
} 

```

关于 Memcached 的最后一点是，基于内存的缓存有一个缺点：因为缓存数据存储在内存中，如果服务器崩溃，数据将丢失。

显然，内存并不适用于永久数据存储，因此不要仅依赖基于内存的缓存作为您唯一的数据存储。毫无疑问，Django 缓存后端都不应该用于永久存储-它们都是用于缓存而不是存储的解决方案-但我们在这里指出这一点是因为基于内存的缓存特别是临时的。

## 数据库缓存

Django 可以将其缓存数据存储在您的数据库中。如果您有一个快速、索引良好的数据库服务器，这将效果最佳。要将数据库表用作缓存后端：

+   将`BACKEND`设置为`django.core.cache.backends.db.DatabaseCache`

+   将`LOCATION`设置为`tablename`，即数据库表的名称。这个名称可以是任何你想要的，只要它是一个有效的表名，而且在你的数据库中还没有被使用。

在这个例子中，缓存表的名称是`my_cache_table`：

```py
CACHES = { 
    'default': { 
        'BACKEND': 'django.core.cache.backends.db.DatabaseCache', 
        'LOCATION': 'my_cache_table', 
    } 
} 

```

### 创建缓存表

在使用数据库缓存之前，您必须使用这个命令创建缓存表：

```py
python manage.py createcachetable 

```

这将在您的数据库中创建一个符合 Django 数据库缓存系统期望的正确格式的表。表的名称取自`LOCATION`。如果您使用多个数据库缓存，`createcachetable`会为每个缓存创建一个表。如果您使用多个数据库，`createcachetable`会观察数据库路由器的`allow_migrate()`方法（见下文）。与`migrate`一样，`createcachetable`不会触及现有表。它只会创建缺失的表。

### 多个数据库

如果您在使用多个数据库进行数据库缓存，还需要为数据库缓存表设置路由指令。对于路由的目的，数据库缓存表显示为一个名为`CacheEntry`的模型，在名为`django_cache`的应用程序中。这个模型不会出现在模型缓存中，但模型的详细信息可以用于路由目的。

例如，以下路由器将所有缓存读取操作定向到`cache_replica`，并将所有写操作定向到`cache_primary`。缓存表只会同步到`cache_primary`：

```py
class CacheRouter(object): 
    """A router to control all database cache operations""" 

    def db_for_read(self, model, **hints): 
        # All cache read operations go to the replica 
        if model._meta.app_label in ('django_cache',): 
            return 'cache_replica' 
        return None 

    def db_for_write(self, model, **hints): 
        # All cache write operations go to primary 
        if model._meta.app_label in ('django_cache',): 
            return 'cache_primary' 
        return None 

    def allow_migrate(self, db, model): 
        # Only install the cache model on primary 
        if model._meta.app_label in ('django_cache',): 
            return db == 'cache_primary' 
        return None 

```

如果您没有为数据库缓存模型指定路由指令，缓存后端将使用`default`数据库。当然，如果您不使用数据库缓存后端，您就不需要担心为数据库缓存模型提供路由指令。

## 文件系统缓存

基于文件的后端将每个缓存值序列化并存储为单独的文件。要使用此后端，将`BACKEND`设置为`'django.core.cache.backends.filebased.FileBasedCache'`，并将`LOCATION`设置为适当的目录。

例如，要将缓存数据存储在`/var/tmp/django_cache`中，使用以下设置：

```py
CACHES = { 
    'default': { 
        'BACKEND': 'django.core.cache.backends.filebased.FileBasedCache', 
        'LOCATION': '/var/tmp/django_cache', 
    } 
} 

```

如果您在 Windows 上，将驱动器号放在路径的开头，就像这样：

```py
CACHES = { 
    'default': { 
        'BACKEND': 'django.core.cache.backends.filebased.FileBasedCache', 
        'LOCATION': 'c:/foo/bar', 
    } 
} 

```

目录路径应该是绝对的-也就是说，它应该从文件系统的根目录开始。设置末尾是否加斜杠并不重要。确保此设置指向的目录存在，并且可以被运行您的网页服务器的系统用户读取和写入。继续上面的例子，如果您的服务器以用户`apache`运行，请确保目录`/var/tmp/django_cache`存在，并且可以被用户`apache`读取和写入。

## 本地内存缓存

如果在设置文件中未指定其他缓存，则这是默认缓存。如果您想要内存缓存的速度优势，但又没有运行 Memcached 的能力，请考虑使用本地内存缓存后端。要使用它，请将`BACKEND`设置为`django.core.cache.backends.locmem.LocMemCache`。例如：

```py
CACHES = { 
    'default': { 
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache', 
        'LOCATION': 'unique-snowflake' 
    } 
} 

```

缓存`LOCATION`用于标识单个内存存储。如果您只有一个`locmem`缓存，可以省略`LOCATION`；但是，如果您有多个本地内存缓存，您将需要为其中至少一个分配一个名称，以便将它们分开。

请注意，每个进程将拥有自己的私有缓存实例，这意味着不可能进行跨进程缓存。这显然也意味着本地内存缓存不是特别内存高效，因此在生产环境中可能不是一个好选择。但对于开发来说是不错的选择。

## 虚拟缓存（用于开发）

最后，Django 附带了一个虚拟缓存，它实际上不缓存-它只是实现了缓存接口而不执行任何操作。如果您的生产站点在各个地方都使用了重度缓存，但在开发/测试环境中不想缓存并且不想改变代码以特殊处理后者，这将非常有用。要激活虚拟缓存，请将`BACKEND`设置如下：

```py
CACHES = { 
    'default': { 
        'BACKEND': 'django.core.cache.backends.dummy.DummyCache', 
    } 
} 

```

## 使用自定义缓存后端

尽管 Django 默认支持多种缓存后端，但有时您可能希望使用自定义的缓存后端。要在 Django 中使用外部缓存后端，请将 Python 导入路径作为`CACHES`设置的`BACKEND`，如下所示：

```py
CACHES = { 
    'default': { 
        'BACKEND': 'path.to.backend', 
    } 
} 

```

如果您正在构建自己的后端，可以使用标准缓存后端作为参考实现。您可以在 Django 源代码的`django/core/cache/backends/`目录中找到这些代码。

### 注意

除非有一个真正令人信服的理由，比如不支持它们的主机，否则您应该坚持使用 Django 提供的缓存后端。它们经过了充分测试，易于使用。

## 缓存参数

每个缓存后端都可以提供额外的参数来控制缓存行为。这些参数作为`CACHES`设置中的额外键提供。有效参数如下：

+   `TIMEOUT`：用于缓存的默认超时时间（以秒为单位）。此参数默认为 300 秒（5 分钟）。您可以将`TIMEOUT`设置为`None`，以便默认情况下缓存键永不过期。值为`0`会导致键立即过期（实际上不缓存）。

+   `OPTIONS`：应传递给缓存后端的任何选项。有效选项的列表将随着每个后端的不同而变化，并且由第三方库支持的缓存后端将直接将它们的选项传递给底层缓存库。

+   实现自己的清除策略的缓存后端（即`locmem`，`filesystem`和`database`后端）将遵守以下选项：

+   `MAX_ENTRIES`：在旧值被删除之前缓存中允许的最大条目数。此参数默认为`300`。

+   `CULL_FREQUENCY`：当达到`MAX_ENTRIES`时被删除的条目比例。实际比例是`1 / CULL_FREQUENCY`，因此将`CULL_FREQUENCY`设置为`2`，以在达到`MAX_ENTRIES`时删除一半的条目。此参数应为整数，默认为`3`。

+   `CULL_FREQUENCY`的值为`0`意味着当达到`MAX_ENTRIES`时整个缓存将被清除。在某些后端（特别是`database`）上，这样做会使清除*更*快，但会增加缓存未命中的次数。

+   `KEY_PREFIX`：一个字符串，将自动包含（默认情况下是前置）到 Django 服务器使用的所有缓存键中。

+   `VERSION`：Django 服务器生成的缓存键的默认版本号。

+   `KEY_FUNCTION`：包含一个点路径到一个函数的字符串，该函数定义如何将前缀、版本和键组合成最终的缓存键。

在这个例子中，文件系统后端被配置为超时 60 秒，并且最大容量为 1000 个项目：

```py
CACHES = { 
    'default': { 
        'BACKEND': 'django.core.cache.backends.filebased.FileBasedCache', 
        'LOCATION': '/var/tmp/django_cache', 
        'TIMEOUT': 60, 
        'OPTIONS': {'MAX_ENTRIES': 1000} 
    } 
} 

```

# 每个站点的缓存

设置缓存后，使用缓存的最简单方法是缓存整个站点。您需要将`'django.middleware.cache.UpdateCacheMiddleware'`和`'django.middleware.cache.FetchFromCacheMiddleware'`添加到您的`MIDDLEWARE_CLASSES`设置中，就像这个例子中一样：

```py
MIDDLEWARE_CLASSES = [ 
    'django.middleware.cache.UpdateCacheMiddleware', 
    'django.middleware.common.CommonMiddleware', 
    'django.middleware.cache.FetchFromCacheMiddleware', 
] 

```

### 注意

不，这不是一个打字错误：更新中间件必须在列表中首先出现，获取中间件必须在最后出现。细节有点模糊，但是如果您想要完整的故事，请参阅下一章中的 MIDDLEWARE_CLASSES 顺序。

然后，将以下必需的设置添加到您的 Django 设置文件中：

+   `CACHE_MIDDLEWARE_ALIAS`：用于存储的缓存别名。

+   `CACHE_MIDDLEWARE_SECONDS`：每个页面应该被缓存的秒数。

+   `CACHE_MIDDLEWARE_KEY_PREFIX`-：如果缓存跨多个使用相同 Django 安装的站点共享，则将其设置为站点的名称，或者是对此 Django 实例唯一的其他字符串，以防止键冲突。如果您不在乎，可以使用空字符串。

`FetchFromCacheMiddleware`使用`status 200`缓存`GET`和`HEAD`响应，其中请求和响应头允许。对于具有不同查询参数的相同 URL 的请求的响应被认为是唯一的页面，并且被单独缓存。此中间件期望`HEAD`请求以与相应的`GET`请求相同的响应头进行响应；在这种情况下，它可以为`HEAD`请求返回缓存的`GET`响应。此外，`UpdateCacheMiddleware`自动在每个`HttpResponse`中设置一些头：

+   将`Last-Modified`头设置为请求新的（未缓存）页面时的当前日期/时间。

+   将`Expires`头设置为当前日期/时间加上定义的`CACHE_MIDDLEWARE_SECONDS`。

+   将`Cache-Control`头设置为页面的最大年龄-同样，从`CACHE_MIDDLEWARE_SECONDS`设置。

如果视图设置了自己的缓存到期时间（即它在其`max-age`部分中有一个），则页面将被缓存直到到期时间，而不是`CACHE_MIDDLEWARE_SECONDS`。 

`Cache-Control`头）那么页面将被缓存直到到期时间，而不是`CACHE_MIDDLEWARE_SECONDS`。使用`django.views.decorators.cache`中的装饰器，您可以轻松地设置视图的到期时间（使用`cache_control`装饰器）或禁用视图的缓存（使用`never_cache`装饰器）。有关这些装饰器的更多信息，请参阅使用其他标头部分。

如果`USE_I18N`设置为`True`，则生成的缓存键将包括活动语言的名称。这样，您可以轻松地缓存多语言站点，而无需自己创建缓存键。

当`USE_L10N`设置为`True`时，缓存键还包括活动语言，当`USE_TZ`设置为`True`时，还包括当前时区。

# 每个视图的缓存

使用缓存框架的更细粒度的方法是通过缓存单个视图的输出。`django.views.decorators.cache`定义了一个`cache_page`装饰器，它将自动为您缓存视图的响应。使用起来很容易：

```py
from django.views.decorators.cache import cache_page 

@cache_page(60 * 15) 
def my_view(request): 
    ... 

```

`cache_page`接受一个参数：缓存超时时间，以秒为单位。在上面的例子中，`my_view()`视图的结果将被缓存 15 分钟。（请注意，我已经将其写成`60 * 15`，以便阅读。`60 * 15`将被计算为`900`-也就是说，15 分钟乘以 60 秒每分钟。）

每个视图的缓存，就像每个站点的缓存一样，是基于 URL 的。如果多个 URL 指向同一个视图，每个 URL 将被单独缓存。继续`my_view`的例子，如果您的 URLconf 如下所示：

```py
urlpatterns = [ 
    url(r'^foo/([0-9]{1,2})/$', my_view), 
] 

```

然后对`/foo/1/`和`/foo/23/`的请求将被分别缓存，正如你可能期望的那样。但一旦请求了特定的 URL（例如`/foo/23/`），随后对该 URL 的请求将使用缓存。

`cache_page`还可以接受一个可选的关键字参数`cache`，它指示装饰器在缓存视图结果时使用特定的缓存（来自你的`CACHES`设置）。

默认情况下，将使用`default`缓存，但你可以指定任何你想要的缓存：

```py
@cache_page(60 * 15, cache="special_cache") 
def my_view(request): 
    ... 

```

你也可以在每个视图的基础上覆盖缓存前缀。`cache_page`接受一个可选的关键字参数`key_prefix`，它的工作方式与中间件的`CACHE_MIDDLEWARE_KEY_PREFIX`设置相同。可以像这样使用：

```py
@cache_page(60 * 15, key_prefix="site1") 
def my_view(request): 
    ... 

```

`key_prefix`和`cache`参数可以一起指定。`key_prefix`参数和在`CACHES`下指定的`KEY_PREFIX`将被连接起来。

## 在 URLconf 中指定每个视图的缓存

前一节中的示例已经硬编码了视图被缓存的事实，因为`cache_page`会直接修改`my_view`函数。这种方法将你的视图与缓存系统耦合在一起，这对于几个原因来说都不理想。例如，你可能希望在另一个没有缓存的站点上重用视图函数，或者你可能希望将视图分发给可能希望在没有被缓存的情况下使用它们的人。

解决这些问题的方法是在 URLconf 中指定每个视图的缓存，而不是在视图函数旁边。这样做很容易：只需在 URLconf 中引用视图函数时用`cache_page`包装视图函数即可。

这是之前的旧 URLconf：

```py
urlpatterns = [ 
    url(r'^foo/([0-9]{1,2})/$', my_view), 
] 

```

这里是相同的内容，`my_view`被包裹在`cache_page`中：

```py
from django.views.decorators.cache import cache_page 

urlpatterns = [ 
    url(r'^foo/([0-9]{1,2})/$', cache_page(60 * 15)(my_view)), 
] 

```

# 模板片段缓存

如果你想要更多的控制，你也可以使用`cache`模板标签来缓存模板片段。为了让你的模板可以访问这个标签，放置

在模板顶部附近使用`{% load cache %}`。`{% cache %}`模板标签会缓存给定时间内的块内容。

它至少需要两个参数：缓存超时（以秒为单位）和要给缓存片段的名称。名称将被直接使用，不要使用变量。

例如：

```py
{% load cache %} 
{% cache 500 sidebar %} 
    .. sidebar .. 
{% endcache %} 

```

有时你可能希望根据片段内部出现的一些动态数据来缓存多个副本的片段。

例如，你可能希望为站点的每个用户使用前面示例中使用的侧边栏的单独缓存副本。通过向`{% cache %}`模板标签传递额外的参数来唯一标识缓存片段来实现这一点：

```py
{% load cache %} 
{% cache 500 sidebar request.user.username %} 
    .. sidebar for logged in user .. 
{% endcache %} 

```

指定多个参数来标识片段是完全可以的。只需向`{% cache %}`传递所需的参数即可。如果`USE_I18N`设置为`True`，则每个站点的中间件缓存将遵循活动语言。

对于`cache`模板标签，你可以使用模板中可用的翻译特定变量之一来实现相同的结果：

```py
{% load i18n %} 
{% load cache %} 

{% get_current_language as LANGUAGE_CODE %} 

{% cache 600 welcome LANGUAGE_CODE %} 
    {% trans "Welcome to example.com" %} 
{% endcache %} 

```

缓存超时可以是一个模板变量，只要模板变量解析为整数值即可。

例如，如果模板变量`my_timeout`设置为值`600`，那么以下两个示例是等价的：

```py
{% cache 600 sidebar %} ... {% endcache %} 
{% cache my_timeout sidebar %} ... {% endcache %} 

```

这个功能在模板中避免重复很有用。你可以在一个地方设置超时，然后只需重用该值。默认情况下，缓存标签将尝试使用名为`template_fragments`的缓存。如果没有这样的缓存存在，它将退回到使用默认缓存。你可以选择一个备用的缓存后端来与`using`关键字参数一起使用，这必须是标签的最后一个参数。

```py
{% cache 300 local-thing ...  using="localcache" %} 

```

指定未配置的缓存名称被认为是一个错误。

如果你想获取用于缓存片段的缓存键，你可以使用`make_template_fragment_key`。`fragment_name`与`cache`模板标签的第二个参数相同；`vary_on`是传递给标签的所有额外参数的列表。这个函数对于使缓存项无效或覆盖缓存项可能很有用，例如：

```py
>>> from django.core.cache import cache 
>>> from django.core.cache.utils import make_template_fragment_key 
# cache key for {% cache 500 sidebar username %} 
>>> key = make_template_fragment_key('sidebar', [username]) 
>>> cache.delete(key) # invalidates cached template fragment 

```

# 低级别缓存 API

有时，缓存整个渲染页面并不会带来太多好处，实际上，这种方式过度。例如，您的站点可能包括一个视图，其结果取决于几个昂贵的查询，这些查询的结果在不同的时间间隔内发生变化。在这种情况下，使用每个站点或每个视图缓存策略提供的全页缓存并不理想，因为您不希望缓存整个结果（因为某些数据经常更改），但仍然希望缓存很少更改的结果。

对于这样的情况，Django 公开了一个简单的低级缓存 API。您可以使用此 API 以任何您喜欢的粒度存储对象。您可以缓存任何可以安全进行 pickle 的 Python 对象：字符串，字典，模型对象列表等（大多数常见的 Python 对象都可以进行 pickle；有关 pickling 的更多信息，请参阅 Python 文档）。

## 访问缓存

您可以通过类似字典的对象`django.core.cache.caches`访问`CACHES`设置中配置的缓存。在同一线程中对同一别名的重复请求将返回相同的对象。

```py
>>> from django.core.cache import caches 
>>> cache1 = caches['myalias'] 
>>> cache2 = caches['myalias'] 
>>> cache1 is cache2 
True 

```

如果命名键不存在，则将引发`InvalidCacheBackendError`。为了提供线程安全性，将为每个线程返回缓存后端的不同实例。

作为快捷方式，默认缓存可用为`django.core.cache.cache`：

```py
>>> from django.core.cache import cache 

```

此对象等同于`caches['default']`。

## 基本用法

基本接口是`set（key，value，timeout）`和`get（key）`：

```py
>>> cache.set('my_key', 'hello, world!', 30) 
>>> cache.get('my_key') 
'hello, world!' 

```

`timeout`参数是可选的，默认为`CACHES`设置中适当后端的`timeout`参数（如上所述）。这是值应在缓存中存储的秒数。将`None`传递给`timeout`将永远缓存该值。`timeout`为`0`将不会缓存该值。如果对象在缓存中不存在，则`cache.get（）`将返回`None`：

```py
# Wait 30 seconds for 'my_key' to expire... 

>>> cache.get('my_key') 
None 

```

我们建议不要将文字值`None`存储在缓存中，因为您无法区分存储的`None`值和由返回值`None`表示的缓存未命中。`cache.get（）`可以接受`default`参数。这指定如果对象在缓存中不存在时要返回的值：

```py
>>> cache.get('my_key', 'has expired') 
'has expired' 

```

要仅在键不存在时添加键，请使用`add（）`方法。它接受与`set（）`相同的参数，但如果指定的键已经存在，则不会尝试更新缓存：

```py
>>> cache.set('add_key', 'Initial value') 
>>> cache.add('add_key', 'New value') 
>>> cache.get('add_key') 
'Initial value' 

```

如果您需要知道`add（）`是否将值存储在缓存中，可以检查返回值。如果存储了该值，则返回`True`，否则返回`False`。还有一个`get_many（）`接口，只会命中一次缓存。`get_many（）`返回一个包含实际存在于缓存中的所有您请求的键的字典（并且尚未过期）：

```py
>>> cache.set('a', 1) 
>>> cache.set('b', 2) 
>>> cache.set('c', 3) 
>>> cache.get_many(['a', 'b', 'c']) 
{'a': 1, 'b': 2, 'c': 3} 

```

要更有效地设置多个值，请使用`set_many（）`传递键值对的字典：

```py
>>> cache.set_many({'a': 1, 'b': 2, 'c': 3}) 
>>> cache.get_many(['a', 'b', 'c']) 
{'a': 1, 'b': 2, 'c': 3} 

```

与`cache.set（）`类似，`set_many（）`接受一个可选的`timeout`参数。您可以使用`delete（）`显式删除键。这是清除特定对象的缓存的简单方法：

```py
>>> cache.delete('a') 

```

如果要一次清除一堆键，`delete_many（）`可以接受要清除的键的列表：

```py
>>> cache.delete_many(['a', 'b', 'c']) 

```

最后，如果要删除缓存中的所有键，请使用`cache.clear（）`。请注意；`clear（）`将从缓存中删除所有内容，而不仅仅是应用程序设置的键。

```py
>>> cache.clear() 

```

您还可以使用`incr（）`或`decr（）`方法来增加或减少已经存在的键。默认情况下，现有的缓存值将增加或减少 1。可以通过向增量/减量调用提供参数来指定其他增量/减量值。

如果您尝试增加或减少不存在的缓存键，则会引发`ValueError`。

```py
>>> cache.set('num', 1) 
>>> cache.incr('num') 
2 
>>> cache.incr('num', 10) 
12 
>>> cache.decr('num') 
11 
>>> cache.decr('num', 5) 
6 

```

如果缓存后端实现了`close（）`，则可以使用`close（）`关闭与缓存的连接。

```py
>>> cache.close() 

```

请注意，对于不实现`close`方法的缓存，`close（）`是一个空操作。

## 缓存键前缀

如果您在服务器之间共享缓存实例，或在生产和开发环境之间共享缓存实例，那么一个服务器缓存的数据可能会被另一个服务器使用。如果缓存数据在服务器之间的格式不同，这可能会导致一些非常难以诊断的问题。

为了防止这种情况发生，Django 提供了为服务器中使用的所有缓存键添加前缀的功能。当保存或检索特定缓存键时，Django 将自动使用`KEY_PREFIX`缓存设置的值作为缓存键的前缀。通过确保每个 Django 实例具有不同的`KEY_PREFIX`，您可以确保缓存值不会发生冲突。

## 缓存版本

当您更改使用缓存值的运行代码时，您可能需要清除任何现有的缓存值。这样做的最简单方法是刷新整个缓存，但这可能会导致仍然有效和有用的缓存值的丢失。Django 提供了一种更好的方法来定位单个缓存值。

Django 的缓存框架具有系统范围的版本标识符，使用`VERSION`缓存设置指定。此设置的值将自动与缓存前缀和用户提供的缓存键结合，以获取最终的缓存键。

默认情况下，任何键请求都将自动包括站点默认的缓存键版本。但是，原始缓存函数都包括一个`version`参数，因此您可以指定要设置或获取的特定缓存键版本。例如：

```py
# Set version 2 of a cache key 
>>> cache.set('my_key', 'hello world!', version=2) 
# Get the default version (assuming version=1) 
>>> cache.get('my_key') 
None 
# Get version 2 of the same key 
>>> cache.get('my_key', version=2) 
'hello world!' 

```

特定键的版本可以使用`incr_version()`和`decr_version()`方法进行增加和减少。这使得特定键可以升级到新版本，而不影响其他键。继续我们之前的例子：

```py
# Increment the version of 'my_key' 
>>> cache.incr_version('my_key') 
# The default version still isn't available 
>>> cache.get('my_key') 
None 
# Version 2 isn't available, either 
>>> cache.get('my_key', version=2) 
None 
# But version 3 *is* available 
>>> cache.get('my_key', version=3) 
'hello world!' 

```

## 缓存键转换

如前两节所述，用户提供的缓存键不会直接使用-它与缓存前缀和键版本结合以提供最终的缓存键。默认情况下，这三个部分使用冒号连接以生成最终字符串：

```py
def make_key(key, key_prefix, version): 
    return ':'.join([key_prefix, str(version), key]) 

```

如果您想以不同的方式组合部分，或对最终键应用其他处理（例如，对键部分进行哈希摘要），可以提供自定义键函数。`KEY_FUNCTION`缓存设置指定了与上面`make_key()`原型匹配的函数的点路径。如果提供了此自定义键函数，它将被用于替代默认的键组合函数。

## 缓存键警告

Memcached，最常用的生产缓存后端，不允许缓存键超过 250 个字符或包含空格或控制字符，使用这样的键将导致异常。为了鼓励可移植的缓存代码并最小化不愉快的惊喜，其他内置缓存后端在使用可能导致在 memcached 上出错的键时会发出警告（`django.core.cache.backends.base.CacheKeyWarning`）。

如果您正在使用可以接受更广泛键范围的生产后端（自定义后端或非 memcached 内置后端之一），并且希望在没有警告的情况下使用此更广泛范围，您可以在一个`INSTALLED_APPS`的`management`模块中使用以下代码来消除`CacheKeyWarning`：

```py
import warnings 

from django.core.cache import CacheKeyWarning 

warnings.simplefilter("ignore", CacheKeyWarning) 

```

如果您想为内置后端之一提供自定义键验证逻辑，可以对其进行子类化，仅覆盖`validate_key`方法，并按照使用自定义缓存后端的说明进行操作。

例如，要为`locmem`后端执行此操作，请将此代码放入一个模块中：

```py
from django.core.cache.backends.locmem import LocMemCache 

class CustomLocMemCache(LocMemCache): 
    def validate_key(self, key): 
        # Custom validation, raising exceptions or warnings as needed. 
        # ... 

```

...并在`CACHES`设置的`BACKEND`部分使用此类的点 Python 路径。

# 下游缓存

到目前为止，本章重点介绍了缓存自己的数据。但是，与 Web 开发相关的另一种缓存也很重要：下游缓存执行的缓存。这些是在请求到达您的网站之前就为用户缓存页面的系统。以下是一些下游缓存的示例：

+   您的 ISP 可能会缓存某些页面，因此，如果您从`http://example.com/`请求页面，则您的 ISP 将向您发送页面，而无需直接访问`example.com`。`example.com`的维护者对此缓存一无所知；ISP 位于`example.com`和您的 Web 浏览器之间，透明地处理所有缓存。

+   您的 Django 网站可能位于*代理缓存*之后，例如 Squid Web 代理缓存（有关更多信息，请访问[`www.squid-cache.org/`](http://www.squid-cache.org/)），该缓存可提高页面性能。在这种情况下，每个请求首先将由代理处理，只有在需要时才会传递给您的应用程序。

+   您的 Web 浏览器也会缓存页面。如果网页发送适当的头，则您的浏览器将对该页面的后续请求使用本地缓存副本，而无需再次联系网页以查看其是否已更改。

下游缓存是一个不错的效率提升，但也存在危险：许多网页的内容基于认证和一系列其他变量而异，盲目保存页面的缓存系统可能向随后访问这些页面的访问者公开不正确或敏感的数据。

例如，假设您运营一个 Web 电子邮件系统，收件箱页面的内容显然取决于哪个用户已登录。如果 ISP 盲目缓存您的站点，那么通过该 ISP 首次登录的用户将使其特定于用户的收件箱页面缓存供站点的后续访问者使用。这不好。

幸运的是，HTTP 提供了解决这个问题的方法。存在许多 HTTP 头，用于指示下游缓存根据指定的变量延迟其缓存内容，并告诉缓存机制不要缓存特定页面。我们将在接下来的部分中查看其中一些头。

# 使用 vary 头

`Vary`头定义了缓存机制在构建其缓存键时应考虑哪些请求头。例如，如果网页的内容取决于用户的语言首选项，则称该页面取决于语言。默认情况下，Django 的缓存系统使用请求的完全限定 URL 创建其缓存键，例如`http://www.example.com/stories/2005/?order_by=author`。

这意味着对该 URL 的每个请求都将使用相同的缓存版本，而不考虑用户代理的差异，例如 cookie 或语言首选项。但是，如果此页面根据请求头的某些差异（例如 cookie、语言或用户代理）生成不同的内容，则需要使用`Vary`头来告诉缓存机制页面输出取决于这些内容。

要在 Django 中执行此操作，请使用方便的`django.views.decorators.vary.vary_on_headers()`视图装饰器，如下所示：

```py
from django.views.decorators.vary import vary_on_headers 

@vary_on_headers('User-Agent') 
def my_view(request): 
    # ... 

```

在这种情况下，缓存机制（例如 Django 自己的缓存中间件）将为每个唯一的用户代理缓存页面的单独版本。使用`vary_on_headers`装饰器而不是手动设置`Vary`头（使用类似`response['Vary'] = 'user-agent'`的东西）的优势在于，装饰器会添加到`Vary`头（如果已经存在），而不是从头开始设置它，并可能覆盖已经存在的任何内容。您可以将多个头传递给`vary_on_headers()`：

```py
@vary_on_headers('User-Agent', 'Cookie') 
def my_view(request): 
    # ... 

```

这告诉下游缓存在两者上变化，这意味着每个用户代理和 cookie 的组合都将获得自己的缓存值。例如，具有用户代理`Mozilla`和 cookie 值`foo=bar`的请求将被视为与具有用户代理`Mozilla`和 cookie 值`foo=ham`的请求不同。因为在 cookie 上变化是如此常见，所以有一个`django.views.decorators.vary.vary_on_cookie()`装饰器。这两个视图是等效的。

```py
@vary_on_cookie 
def my_view(request): 
    # ... 

@vary_on_headers('Cookie') 
def my_view(request): 
    # ... 

```

您传递给`vary_on_headers`的标头不区分大小写；`User-Agent`与`user-agent`是相同的。您还可以直接使用辅助函数`django.utils.cache.patch_vary_headers()`。此函数设置或添加到`Vary`标头。例如：

```py
from django.utils.cache import patch_vary_headers 

def my_view(request): 
    # ... 
    response = render_to_response('template_name', context) 
    patch_vary_headers(response, ['Cookie']) 
    return response 

```

`patch_vary_headers`将`HttpResponse`实例作为其第一个参数，并将不区分大小写的标头名称列表/元组作为其第二个参数。有关`Vary`标头的更多信息，请参阅官方 Vary 规范（有关更多信息，请访问[`www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.44`](http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.44)）。

# 控制缓存：使用其他标头

缓存的其他问题是数据的隐私和数据应该存储在缓存级联中的哪个位置的问题。用户通常面临两种缓存：自己的浏览器缓存（私有缓存）和其提供者的缓存（公共缓存）。

公共缓存由多个用户使用，并由其他人控制。这会带来敏感数据的问题-您不希望您的银行账号存储在公共缓存中。因此，Web 应用程序需要一种告诉缓存哪些数据是私有的，哪些是公共的方法。

解决方案是指示页面的缓存应该是私有的。在 Django 中，使用`cache_control`视图装饰器。例如：

```py
from django.views.decorators.cache import cache_control 

@cache_control(private=True) 
def my_view(request): 
    # ... 

```

此装饰器负责在后台发送适当的 HTTP 标头。请注意，缓存控制设置`private`和`public`是互斥的。装饰器确保如果应该设置`private`，则删除公共指令（反之亦然）。

两个指令的一个示例用法是提供公共和私有条目的博客网站。公共条目可以在任何共享缓存上缓存。以下代码使用`django.utils.cache.patch_cache_control()`，手动修改缓存控制标头的方法（它由`cache_control`装饰器内部调用）：

```py
from django.views.decorators.cache import patch_cache_control 
from django.views.decorators.vary import vary_on_cookie 

@vary_on_cookie 
def list_blog_entries_view(request): 
    if request.user.is_anonymous(): 
        response = render_only_public_entries() 
        patch_cache_control(response, public=True) 
    else: 
        response = render_private_and_public_entries(request.user) 
        patch_cache_control(response, private=True) 

    return response 

```

还有其他控制缓存参数的方法。例如，HTTP 允许应用程序执行以下操作：

+   定义页面应缓存的最长时间。

+   指定缓存是否应该始终检查更新版本，仅在没有更改时提供缓存内容。（某些缓存可能会在服务器页面更改时提供缓存内容，仅因为缓存副本尚未过期。）

在 Django 中，使用`cache_control`视图装饰器来指定这些缓存参数。在此示例中，`cache_control`告诉缓存在每次访问时重新验证缓存，并将缓存版本存储最多 3600 秒：

```py
from django.views.decorators.cache import cache_control 

@cache_control(must_revalidate=True, max_age=3600) 
def my_view(request): 
    # ... 

```

`cache_control()`中的任何有效的`Cache-Control` HTTP 指令在`cache_control()`中都是有效的。以下是完整列表：

+   `public=True`

+   `private=True`

+   `no_cache=True`

+   `no_transform=True`

+   `must_revalidate=True`

+   `proxy_revalidate=True`

+   `max_age=num_seconds`

+   `s_maxage=num_seconds`

有关 Cache-Control HTTP 指令的解释，请参阅 Cache-Control 规范（有关更多信息，请访问[`www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.9`](http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.9)）。 （请注意，缓存中间件已经使用`CACHE_MIDDLEWARE_SECONDS`设置的值设置了缓存标头的`max-age`。如果您在`cache_control`装饰器中使用自定义的`max_age`，装饰器将优先，并且标头值将被正确合并。）

如果要使用标头完全禁用缓存，`django.views.decorators.cache.never_cache`是一个视图装饰器，它添加标头以确保响应不会被浏览器或其他缓存缓存。例如：

```py
from django.views.decorators.cache import never_cache 

@never_cache 
def myview(request): 
    # ... 

```

# 接下来是什么？

在下一章中，我们将看一下 Django 的中间件。
