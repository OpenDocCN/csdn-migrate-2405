# 精通 Django（七）

> 原文：[`zh.annas-archive.org/md5/0D7AA9BDBF4A402F69CD832FB5D17FA6`](https://zh.annas-archive.org/md5/0D7AA9BDBF4A402F69CD832FB5D17FA6)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第二十章：更多关于安装 Django 的信息

本章涵盖了与安装和维护 Django 相关的一些常见附加选项和场景。首先，我们将看看除了 SQLite 之外使用其他数据库的安装配置，然后我们将介绍如何升级 Django 以及如何手动安装 Django。最后，我们将介绍如何安装 Django 的开发版本，以防您想要尝试 Django 开发的最前沿。

# 运行其他数据库

如果您计划使用 Django 的数据库 API 功能，则需要确保数据库服务器正在运行。Django 支持许多不同的数据库服务器，并且官方支持 PostgreSQL、MySQL、Oracle 和 SQLite。

第二十一章，*高级数据库管理*，包含了连接 Django 到这些数据库的额外信息，但是，本书的范围不包括向您展示如何安装它们；请参考每个项目网站上的数据库文档。

如果您正在开发一个简单的项目或者您不打算在生产环境中部署，SQLite 通常是最简单的选择，因为它不需要运行单独的服务器。但是，SQLite 与其他数据库有许多不同之处，因此，如果您正在开发一些实质性的东西，建议使用与生产环境中计划使用的相同数据库进行开发。

除了数据库后端，您还需要确保安装了 Python 数据库绑定。

+   如果您使用 PostgreSQL，则需要`postgresql_psycopg2`（[`initd.org/psycopg/`](http://initd.org/psycopg/)）包。您可能需要参考 PostgreSQL 的注意事项，以获取有关此数据库的进一步技术细节。如果您使用 Windows，请查看非官方编译的 Windows 版本（[`stickpeople.com/projects/python/win-psycopg/`](http://stickpeople.com/projects/python/win-psycopg/)）。

+   如果您正在使用 MySQL，则需要`MySQL-python`包，版本为 1.2.1p2 或更高版本。您还需要阅读 MySQL 后端的特定于数据库的注意事项。

+   如果您使用 SQLite，您可能需要阅读 SQLite 后端的注意事项。

+   如果您使用 Oracle，则需要`cx_Oracle`的副本（[`cx-oracle.sourceforge.net/`](http://cx-oracle.sourceforge.net/)），但请阅读有关 Oracle 后端的特定于数据库的注意事项，以获取有关 Oracle 和`cx_Oracle`支持版本的重要信息。

+   如果您使用非官方的第三方后端，请查阅所提供的文档以获取任何额外要求。

如果您计划使用 Django 的`manage.py migrate`命令自动为模型创建数据库表（在安装 Django 并创建项目后），您需要确保 Django 有权限在您使用的数据库中创建和更改表；如果您计划手动创建表，您可以简单地授予 Django`SELECT`、`INSERT`、`UPDATE`和`DELETE`权限。在创建具有这些权限的数据库用户后，您将在项目的设置文件中指定详细信息，请参阅`DATABASES`以获取详细信息。

如果您使用 Django 的测试框架来测试数据库查询，Django 将需要权限来创建测试数据库。

# 手动安装 Django

1.  从 Django 项目下载页面下载最新版本的发布版（[`www.djangoproject.com/download/`](https://www.djangoproject.com/download/)）。

1.  解压下载的文件（例如，`tar xzvf Django-X.Y.tar.gz`，其中`X.Y`是最新发布版的版本号）。如果您使用 Windows，您可以下载命令行工具`bsdtar`来执行此操作，或者您可以使用基于 GUI 的工具，如 7-zip（[`www.7-zip.org/`](http://www.7-zip.org/)）。

1.  切换到步骤 2 中创建的目录（例如，`cd Django-X.Y`）。

1.  如果您使用 Linux、Mac OS X 或其他 Unix 变种，请在 shell 提示符下输入`sudo python setup.py install`命令。如果您使用 Windows，请以管理员权限启动命令 shell，并运行`python setup.py install`命令。这将在 Python 安装的`site-packages`目录中安装 Django。

### 注意

**删除旧版本**

如果您使用此安装技术，特别重要的是首先删除任何现有的 Django 安装（请参见下文）。否则，您可能会得到一个包含自 Django 已删除的以前版本的文件的损坏安装。

# 升级 Django

## 删除任何旧版本的 Django

如果您正在从以前的版本升级 Django 安装，您需要在安装新版本之前卸载旧的 Django 版本。

如果以前使用`pip`或`easy_install`安装了 Django，则再次使用`pip`或`easy_install`安装将自动处理旧版本，因此您无需自己操作。

如果您以前手动安装了 Django，卸载就像删除 Python `site-packages`中的`django`目录一样简单。要找到需要删除的目录，您可以在 shell 提示符（而不是交互式 Python 提示符）下运行以下命令：

`python -c "import sys; sys.path = sys.path[1:]; import django; print(django.__path__)"`

# 安装特定于发行版的软件包

检查特定于发行版的说明，看看您的平台/发行版是否提供官方的 Django 软件包/安装程序。发行版提供的软件包通常允许自动安装依赖项和简单的升级路径；但是，这些软件包很少包含 Django 的最新版本。

# 安装开发版本

如果您决定使用 Django 的最新开发版本，您需要密切关注开发时间表，并且需要关注即将发布的版本的发布说明。这将帮助您了解您可能想要使用的任何新功能，以及在更新 Django 副本时需要进行的任何更改。（对于稳定版本，任何必要的更改都在发布说明中记录。）

如果您希望偶尔能够使用最新的错误修复和改进更新 Django 代码，请按照以下说明操作：

1.  确保已安装 Git，并且可以从 shell 运行其命令。（在 shell 提示符处输入`git help`来测试这一点。）

1.  像这样查看 Django 的主要开发分支（*trunk*或*master*）：

```py
 git clone 
      git://github.com/django/django.git django-trunk

```

1.  这将在当前目录中创建一个名为`django-trunk`的目录。

1.  确保 Python 解释器可以加载 Django 的代码。最方便的方法是通过 pip。运行以下命令：

```py
 sudo pip install -e django-trunk/

```

1.  （如果使用`virtualenv`，或者运行 Windows，可以省略`sudo`。）

这将使 Django 的代码可导入，并且还将使`django-admin`实用程序命令可用。换句话说，您已经准备好了！

### 注意

不要运行`sudo python setup.py install`，因为您已经在第 3 步中执行了相应的操作。

当您想要更新 Django 源代码的副本时，只需在`django-trunk`目录中运行`git pull`命令。这样做时，Git 将自动下载任何更改。

# 接下来是什么？

在下一章中，我们将介绍有关在特定数据库上运行 Django 的附加信息


# 第二十一章：高级数据库管理

本章提供了有关 Django 中支持的每个关系数据库的额外信息，以及连接到传统数据库的注意事项和技巧。

# 一般注意事项

Django 尝试在所有数据库后端上支持尽可能多的功能。然而，并非所有的数据库后端都是一样的，Django 开发人员必须对支持哪些功能和可以安全假设的内容做出设计决策。

本文件描述了一些可能与 Django 使用相关的特性。当然，它并不打算替代特定服务器的文档或参考手册。

## 持久连接

持久连接避免了在每个请求中重新建立与数据库的连接的开销。它们由`CONN_MAX_AGE`参数控制，该参数定义了连接的最大生存期。它可以独立设置每个数据库。默认值为 0，保留了在每个请求结束时关闭数据库连接的历史行为。要启用持久连接，请将`CONN_MAX_AGE`设置为正数秒数。要获得无限的持久连接，请将其设置为`None`。

### 连接管理

Django 在首次进行数据库查询时会打开与数据库的连接。它会保持这个连接打开，并在后续请求中重用它。一旦连接超过`CONN_MAX_AGE`定义的最大寿命，或者不再可用，Django 会关闭连接。

具体来说，Django 在需要连接数据库时会自动打开一个连接，如果没有已经存在的连接，要么是因为这是第一个连接，要么是因为上一个连接已经关闭。

在每个请求开始时，如果连接已经达到最大寿命，Django 会关闭连接。如果您的数据库在一段时间后终止空闲连接，您应该将`CONN_MAX_AGE`设置为较低的值，这样 Django 就不会尝试使用已被数据库服务器终止的连接。（这个问题可能只影响非常低流量的站点。）

在每个请求结束时，如果连接已经达到最大寿命或处于不可恢复的错误状态，Django 会关闭连接。如果在处理请求时发生了任何数据库错误，Django 会检查连接是否仍然有效，如果无效则关闭连接。因此，数据库错误最多影响一个请求；如果连接变得无法使用，下一个请求将获得一个新的连接。

### 注意事项

由于每个线程都维护自己的连接，因此您的数据库必须支持至少与您的工作线程一样多的同时连接。

有时，数据库不会被大多数视图访问，例如，因为它是外部系统的数据库，或者由于缓存。在这种情况下，您应该将`CONN_MAX_AGE`设置为较低的值，甚至为`0`，因为维护一个不太可能被重用的连接是没有意义的。这将有助于保持对该数据库的同时连接数较小。

开发服务器为每个处理的请求创建一个新的线程，从而抵消了持久连接的效果。在开发过程中不要启用它们。

当 Django 建立与数据库的连接时，它会根据所使用的后端设置适当的参数。如果启用了持久连接，这个设置就不会在每个请求中重复。如果您修改了连接的隔离级别或时区等参数，您应该在每个请求结束时恢复 Django 的默认设置，或者在每个请求开始时强制设置适当的值，或者禁用持久连接。

## 编码

Django 假设所有数据库都使用 UTF-8 编码。使用其他编码可能会导致意外行为，例如数据库对 Django 中有效的数据产生值过长的错误。有关如何正确设置数据库的信息，请参阅以下特定数据库的注意事项。

# postgreSQL 注意事项

Django 支持 PostgreSQL 9.0 及更高版本。它需要使用 Psycopg2 2.0.9 或更高版本。

## 优化 postgreSQL 的配置

Django 需要其数据库连接的以下参数：

+   `client_encoding`: `'UTF8'`,

+   `default_transaction_isolation`: 默认为`'read committed'`，或者连接选项中设置的值（见此处），

+   `timezone`: 当`USE_TZ`为`True`时为`'UTC'`，否则为`TIME_ZONE`的值。

如果这些参数已经具有正确的值，Django 不会为每个新连接设置它们，这会稍微提高性能。您可以直接在`postgresql.conf`中配置它们，或者更方便地通过`ALTER ROLE`为每个数据库用户配置它们。

Django 在没有进行此优化的情况下也可以正常工作，但每个新连接都会执行一些额外的查询来设置这些参数。

## 隔离级别

与 PostgreSQL 本身一样，Django 默认使用`READ COMMITTED`隔离级别。如果需要更高的隔离级别，如`REPEATABLE READ`或`SERIALIZABLE`，请在`DATABASES`中的数据库配置的`OPTIONS`部分中设置它：

```py
import psycopg2.extensions 

DATABASES = { 
    # ... 
    'OPTIONS': { 
        'isolation_level': psycopg2.extensions.ISOLATION_LEVEL_SERIALIZABLE, 
    }, 
} 

```

在更高的隔禅级别下，您的应用程序应该准备好处理由于序列化失败而引发的异常。此选项设计用于高级用途。

## varchar 和 text 列的索引

在模型字段上指定`db_index=True`时，Django 通常会输出一个`CREATE INDEX`语句。但是，如果字段的数据库类型为`varchar`或`text`（例如，由`CharField`，`FileField`和`TextField`使用），那么 Django 将创建一个使用适当的 PostgreSQL 操作符类的额外索引。额外的索引是必要的，以正确执行使用`LIKE`操作符的查找，这在它们的 SQL 中使用`contains`和`startswith`查找类型时会发生。

# MySQL 注意事项

## 版本支持

Django 支持 MySQL 5.5 及更高版本。

Django 的`inspectdb`功能使用包含所有数据库模式详细数据的`information_schema`数据库。

Django 期望数据库支持 Unicode（UTF-8 编码）并委托给它执行事务和引用完整性的任务。重要的是要意识到，当使用 MyISAM 存储引擎时，MySQL 实际上并不执行这两个任务，详见下一节。

## 存储引擎

MySQL 有几种存储引擎。您可以在服务器配置中更改默认存储引擎。

直到 MySQL 5.5.4，默认引擎是 MyISAM。MyISAM 的主要缺点是它不支持事务或强制外键约束。另一方面，直到 MySQL 5.6.4，它是唯一支持全文索引和搜索的引擎。

自 MySQL 5.5.5 以来，默认存储引擎是 InnoDB。该引擎完全支持事务，并支持外键引用。这可能是目前最好的选择。但是，请注意，InnoDB 自增计数器在 MySQL 重新启动时会丢失，因为它不记住`AUTO_INCREMENT`值，而是将其重新创建为`max(id)+1`。这可能导致`AutoField`值的意外重用。

如果您将现有项目升级到 MySQL 5.5.5，然后添加一些表，请确保您的表使用相同的存储引擎（即 MyISAM vs. InnoDB）。特别是，如果在它们之间具有`ForeignKey`的表使用不同的存储引擎，那么在运行`migrate`时可能会看到以下错误：

```py
_mysql_exceptions.OperationalError: ( 
    1005, "Can't create table '\\db_name\\.#sql-4a8_ab' (errno: 150)" 
) 

```

## MySQL DB API 驱动程序

Python 数据库 API 在 PEP 249 中有描述。MySQL 有三个实现此 API 的知名驱动程序：

+   MySQLdb（[`pypi.python.org/pypi/MySQL-python/1.2.4`](https://pypi.python.org/pypi/MySQL-python/1.2.4)）是由 Andy Dustman 开发和支持了十多年的本地驱动程序。

+   mySQLclient ([`pypi.python.org/pypi/mysqlclient`](https://pypi.python.org/pypi/mysqlclient))是`MySQLdb`的一个分支，特别支持 Python 3，并且可以作为 MySQLdb 的替代品。在撰写本文时，这是使用 Django 与 MySQL 的推荐选择。

+   MySQL Connector/Python ([`dev.mysql.com/downloads/connector/python`](http://dev.mysql.com/downloads/connector/python))是来自 Oracle 的纯 Python 驱动程序，不需要 MySQL 客户端库或标准库之外的任何 Python 模块。

所有这些驱动程序都是线程安全的，并提供连接池。`MySQLdb`是目前唯一不支持 Python 3 的驱动程序。

除了 DB API 驱动程序，Django 还需要一个适配器来访问其 ORM 中的数据库驱动程序。Django 为 MySQLdb/mysqlclient 提供了一个适配器，而 MySQL Connector/Python 则包含了自己的适配器。

### mySQLdb

Django 需要 MySQLdb 版本 1.2.1p2 或更高版本。

如果在尝试使用 Django 时看到`ImportError: cannot import name ImmutableSet`，则您的 MySQLdb 安装可能包含一个过时的`sets.py`文件，与 Python 2.4 及更高版本中同名的内置模块发生冲突。要解决此问题，请验证您是否安装了 MySQLdb 版本 1.2.1p2 或更新版本，然后删除 MySQLdb 目录中由早期版本留下的`sets.py`文件。

MySQLdb 将日期字符串转换为 datetime 对象时存在已知问题。具体来说，值为`0000-00-00`的日期字符串对于 MySQL 是有效的，但在 MySQLdb 中会被转换为`None`。

这意味着在使用可能具有`0000-00-00`值的行的 loaddata/dumpdata 时，您应该小心，因为它们将被转换为`None`。

在撰写本文时，最新版本的 MySQLdb（1.2.4）不支持 Python 3。要在 Python 3 下使用 MySQLdb，您需要安装`mysqlclient`。

### mySQLclient

Django 需要 mysqlclient 1.3.3 或更高版本。请注意，不支持 Python 3.2。除了 Python 3.3+支持外，mysqlclient 应该与 MySQLdb 大致相同。

### mySQL connector/python

MySQL Connector/Python 可从下载页面获取。Django 适配器可在 1.1.X 及更高版本中获取。它可能不支持最新版本的 Django。

## 时区定义

如果您打算使用 Django 的时区支持，请使用`mysql_tzinfo_to_sql`将时区表加载到 MySQL 数据库中。这只需要针对您的 MySQL 服务器执行一次，而不是每个数据库。

## 创建您的数据库

您可以使用命令行工具和以下 SQL 创建您的数据库：

```py
CREATE DATABASE <dbname> CHARACTER SET utf8; 

```

这可以确保所有表和列默认使用 UTF-8。

### 校对设置

列的校对设置控制数据排序的顺序以及哪些字符串比较相等。它可以在数据库范围内设置，也可以在每个表和每个列上设置。这在 MySQL 文档中有详细说明。在所有情况下，您都可以通过直接操作数据库表来设置校对；Django 不提供在模型定义中设置这一点的方法。

默认情况下，对于 UTF-8 数据库，MySQL 将使用`utf8_general_ci`校对。这导致所有字符串相等比较以*不区分大小写*的方式进行。也就是说，"`Fred`"和"`freD`"在数据库级别被视为相等。如果在字段上有唯一约束，尝试将"`aa`"和"`AA`"插入同一列将是非法的，因为它们比较为相等（因此不唯一）。

在许多情况下，这个默认值不会有问题。但是，如果您真的想在特定列或表上进行区分大小写的比较，您将更改列或表以使用`utf8_bin`排序规则。在这种情况下要注意的主要事情是，如果您使用的是 MySQLdb 1.2.2，则 Django 中的数据库后端将为从数据库接收到的任何字符字段返回字节串（而不是 Unicode 字符串）。这与 Django *始终*返回 Unicode 字符串的正常做法有很大的不同。

由您作为开发人员来处理这样一个事实，即如果您配置表使用`utf8_bin`排序规则，您将收到字节串。Django 本身应该大部分可以顺利地处理这样的列（除了这里描述的`contrib.sessions``Session`和`contrib.admin``LogEntry`表），但是您的代码必须准备在必要时调用“django.utils.encoding.smart_text（）”，如果它真的想要处理一致的数据-Django 不会为您做这个（数据库后端层和模型填充层在内部是分开的，因此数据库层不知道它需要在这一个特定情况下进行这种转换）。

如果您使用的是 MySQLdb 1.2.1p2，Django 的标准`CharField`类将即使使用`utf8_bin`排序规则也返回 Unicode 字符串。但是，`TextField`字段将作为`array.array`实例（来自 Python 的标准`array`模块）返回。Django 对此无能为力，因为再次，当数据从数据库中读取时，所需的信息不可用。这个问题在 MySQLdb 1.2.2 中得到了解决，因此，如果您想要在`utf8_bin`排序规则下使用`TextField`，则升级到 1.2.2 版本，然后按照之前描述的处理字节串（这不应该太困难）是推荐的解决方案。

如果您决定在 MySQLdb 1.2.1p2 或 1.2.2 中使用`utf8_bin`排序规则来处理一些表，您仍应该为`django.contrib.sessions.models.Session`表（通常称为`django_session`）和`django.contrib.admin.models.LogEntry`表（通常称为`django_admin_log`）使用`utf8_general_ci`（默认值）排序规则。请注意，根据 MySQL Unicode 字符集，`utf8_general_ci`排序规则的比较速度更快，但比`utf8_unicode_ci`排序规则稍微不正确。如果这对您的应用程序是可以接受的，您应该使用`utf8_general_ci`，因为它更快。如果这是不可接受的（例如，如果您需要德语字典顺序），请使用`utf8_unicode_ci`，因为它更准确。

### 注意

模型表单集以区分大小写的方式验证唯一字段。因此，在使用不区分大小写的排序规则时，具有仅大小写不同的唯一字段值的表单集将通过验证，但在调用“save（）”时，将引发`IntegrityError`。

## 连接到数据库

连接设置按以下顺序使用：

+   `OPTIONS`

+   `NAME`，`USER`，`PASSWORD`，`HOST`，`PORT`

+   MySQL 选项文件

换句话说，如果在`OPTIONS`中设置了数据库的名称，这将优先于`NAME`，这将覆盖 MySQL 选项文件中的任何内容。以下是一个使用 MySQL 选项文件的示例配置：

```py
# settings.py 
DATABASES = { 
    'default': { 
        'ENGINE': 'django.db.backends.mysql', 
        'OPTIONS': {'read_default_file': '/path/to/my.cnf',}, 
    } 
} 

# my.cnf 
[client] 
database = NAME 
user = USER 
password = PASSWORD 
default-character-set = utf8 

```

其他一些 MySQLdb 连接选项可能会有用，例如`ssl`，`init_command`和`sql_mode`。请参阅 MySQLdb 文档以获取更多详细信息。

## 创建您的表

当 Django 生成模式时，它不指定存储引擎，因此表将使用数据库服务器配置的默认存储引擎创建。

最简单的解决方案是将数据库服务器的默认存储引擎设置为所需的引擎。

如果您使用托管服务并且无法更改服务器的默认存储引擎，则有几种选择。

+   创建表后，执行`ALTER TABLE`语句将表转换为新的存储引擎（例如 InnoDB）：

```py
        ALTER TABLE <tablename> ENGINE=INNODB; 

```

+   如果您有很多表，这可能会很麻烦。

+   另一个选项是在创建表之前使用 MySQLdb 的`init_command`选项：

```py
        'OPTIONS': { 
           'init_command': 'SET storage_engine=INNODB', 
        } 

```

这将在连接到数据库时设置默认存储引擎。创建表后，应删除此选项，因为它会向每个数据库连接添加一个仅在表创建期间需要的查询。

## 表名

即使在最新版本的 MySQL 中，也存在已知问题，可能会在特定条件下执行某些 SQL 语句时更改表名的情况。建议您尽可能使用小写表名，以避免可能由此行为引起的任何问题。Django 在自动生成模型的表名时使用小写表名，因此，如果您通过`db_table`参数覆盖表名，则主要考虑这一点。

## 保存点

Django ORM 和 MySQL（使用 InnoDB 存储引擎时）都支持数据库保存点。

如果使用 MyISAM 存储引擎，请注意，如果尝试使用事务 API 的保存点相关方法，您将收到数据库生成的错误。原因是检测 MySQL 数据库/表的存储引擎是一项昂贵的操作，因此决定不值得根据此类检测结果动态转换这些方法为无操作。

## 特定字段的注意事项

### 字符字段

如果您对字段使用`unique=True`，则存储为`VARCHAR`列类型的任何字段的`max_length`将限制为 255 个字符。这会影响`CharField`，`SlugField`和`CommaSeparatedIntegerField`。

### 时间和日期时间字段的分数秒支持

MySQL 5.6.4 及更高版本可以存储分数秒，前提是列定义包括分数指示（例如，`DATETIME(6)`）。早期版本根本不支持它们。此外，早于 1.2.5 的 MySQLdb 版本存在一个错误，也会阻止与 MySQL 一起使用分数秒。

如果数据库服务器支持，Django 不会将现有列升级以包括分数秒。如果要在现有数据库上启用它们，您需要手动更新目标数据库上的列，例如执行以下命令：

```py
ALTER TABLE `your_table` MODIFY `your_datetime_column` DATETIME(6) 

```

或在`数据迁移`中使用`RunSQL`操作。

默认情况下，使用 mysqlclient 或 MySQLdb 1.2.5 或更高版本在 MySQL 5.6.4 或更高版本上创建新的`DateTimeField`或`TimeField`列时现在支持分数秒。

### 时间戳列

如果您使用包含`TIMESTAMP`列的旧数据库，则必须将`USE_TZ = False`设置为避免数据损坏。`inspectdb`将这些列映射到`DateTimeField`，如果启用时区支持，则 MySQL 和 Django 都将尝试将值从 UTC 转换为本地时间。

### 使用 Queryset.Select_For_Update()进行行锁定

MySQL 不支持`SELECT ... FOR UPDATE`语句的`NOWAIT`选项。如果使用`select_for_update()`并且`nowait=True`，则会引发`DatabaseError`。

### 自动类型转换可能导致意外结果

在对字符串类型执行查询时，但具有整数值时，MySQL 将在执行比较之前将表中所有值的类型强制转换为整数。如果您的表包含值"`abc`"，"`def`"，并且您查询`WHERE mycolumn=0`，则两行都将匹配。同样，`WHERE mycolumn=1`将匹配值"`abc1`"。因此，在 Django 中包含的字符串类型字段在使用它进行查询之前将始终将该值转换为字符串。

如果您实现了直接继承自`Field`的自定义模型字段，正在覆盖`get_prep_value()`，或使用`extra()`或`raw()`，则应确保执行适当的类型转换。

# SQLite 注意事项

SQLite 为主要是只读或需要较小安装占用空间的应用程序提供了一个优秀的开发替代方案。然而，与所有数据库服务器一样，SQLite 具有一些特定于 SQLite 的差异，您应该注意。

## 子字符串匹配和区分大小写

对于所有 SQLite 版本，在尝试匹配某些类型的字符串时，会出现一些略微反直觉的行为。这些行为在 Querysets 中使用`iexact`或`contains`过滤器时会触发。行为分为两种情况：

1.  对于子字符串匹配，所有匹配都是不区分大小写的。也就是说，过滤器`filter（name__contains="aa"）`将匹配名称为“Aabb”的名称。

1.  对于包含 ASCII 范围之外字符的字符串，所有精确的字符串匹配都是区分大小写的，即使在查询中传递了不区分大小写的选项。因此，在这些情况下，`iexact`过滤器的行为将与精确过滤器完全相同。

这些问题的一些可能的解决方法在 sqlite.org 上有记录，但默认的 Django SQLite 后端没有使用它们，因为将它们整合起来可能会相当困难。因此，Django 暴露了默认的 SQLite 行为，您在进行不区分大小写或子字符串过滤时应该注意这一点。

## 旧的 SQLite 和 CASE 表达式

SQLite 3.6.23.1 及更早版本在处理包含`ELSE`和算术的`CASE`表达式中的查询参数时存在一个错误。

SQLite 3.6.23.1 于 2010 年 3 月发布，大多数不同平台的当前二进制发行版都包含了更新版本的 SQLite，但值得注意的是 Python 2.7 的 Windows 安装程序除外。

截至目前，Windows-Python 2.7.10 的最新版本包括 SQLite 3.6.21。您可以安装`pysqlite2`或将`sqlite3.dll`（默认安装在`C:\Python27\DLLs`中）替换为来自 sqlite.org 的更新版本以解决此问题。

## 使用更新版本的 SQLite DB-API 2.0 驱动程序

如果发现可用的话，Django 将优先使用`pysqlite2`模块而不是 Python 标准库中附带的`sqlite3`。

如果需要，这提供了升级 DB-API 2.0 接口或 SQLite 3 本身到比特定 Python 二进制发行版中包含的版本更新的能力。

## 数据库被锁定的错误

SQLite 旨在成为一个轻量级的数据库，因此无法支持高并发。`OperationalError: database is locked`错误表明您的应用程序正在经历比`sqlite`默认配置中可以处理的并发更多的情况。这个错误意味着一个线程或进程在数据库连接上有一个独占锁，另一个线程在等待锁被释放时超时了。

Python 的 SQLite 包装器具有默认的超时值，确定第二个线程在锁上等待多长时间才会超时并引发`OperationalError: database is locked`错误。

如果您遇到此错误，您可以通过以下方法解决：

+   切换到另一个数据库后端。在某一点上，SQLite 对于真实世界的应用程序来说变得太轻，这些并发错误表明您已经达到了这一点。

+   重写您的代码以减少并发并确保数据库事务的持续时间较短。

+   通过设置`timeout`数据库选项来增加默认超时值：

```py
        'OPTIONS': { # ... 'timeout': 20, # ... } 

```

这只会使 SQLite 在抛出数据库被锁定错误之前等待更长的时间；它实际上并不会真正解决这些问题。

### queryset.Select_For_Update()不支持

SQLite 不支持`SELECT ... FOR UPDATE`语法。调用它不会产生任何效果。

### 原始查询中不支持 pyformat 参数样式

对于大多数后端，原始查询（`Manager.raw()`或`cursor.execute()`）可以使用 pyformat 参数样式，其中查询中的占位符为`'%(name)s'`，参数作为字典而不是列表传递。SQLite 不支持这一点。

### 连接.queries 中未引用的参数

`sqlite3`不提供在引用和替换参数后检索 SQL 的方法。相反，在`connection.queries`中的 SQL 将使用简单的字符串插值重新构建。这可能是不正确的。在将查询复制到 SQLite shell 之前，请确保在必要的地方添加引号。

# Oracle 注意事项

Django 支持 Oracle 数据库服务器版本 11.1 及更高版本。需要版本 4.3.1 或更高版本的`cx_Oracle`（[`cx-oracle.sourceforge.net/`](http://cx-oracle.sourceforge.net/)）Python 驱动程序，尽管我们建议使用版本 5.1.3 或更高版本，因为这些版本支持 Python 3。

请注意，由于`cx_Oracle` 5.0 中存在 Unicode 损坏错误，因此不应该使用该驱动程序的该版本与 Django 一起使用；`cx_Oracle` 5.0.1 解决了此问题，因此如果您想使用更新的`cx_Oracle`，请使用版本 5.0.1。

`cx_Oracle` 5.0.1 或更高版本可以选择使用`WITH_UNICODE`环境变量进行编译。这是推荐的，但不是必需的。

为了使`python manage.py migrate`命令工作，您的 Oracle 数据库用户必须具有运行以下命令的权限：

+   `CREATE TABLE`

+   `CREATE SEQUENCE`

+   `CREATE PROCEDURE`

+   `CREATE TRIGGER`

要运行项目的测试套件，用户通常需要这些*额外*权限：

+   `CREATE USER`

+   `DROP USER`

+   `CREATE TABLESPACE`

+   `DROP TABLESPACE`

+   `CREATE SESSION WITH ADMIN OPTION`

+   `CREATE TABLE WITH ADMIN OPTION`

+   `CREATE SEQUENCE WITH ADMIN OPTION`

+   `CREATE PROCEDURE WITH ADMIN OPTION`

+   `CREATE TRIGGER WITH ADMIN OPTION`

请注意，虽然`RESOURCE`角色具有所需的`CREATE TABLE`、`CREATE SEQUENCE`、`CREATE PROCEDURE`和`CREATE TRIGGER`权限，而且授予`RESOURCE WITH ADMIN OPTION`的用户可以授予`RESOURCE`，但这样的用户不能授予单个权限（例如`CREATE TABLE`），因此`RESOURCE WITH ADMIN OPTION`通常不足以运行测试。

一些测试套件还会创建视图；要运行这些视图，用户还需要`CREATE VIEW WITH ADMIN OPTION`权限。特别是 Django 自己的测试套件需要这个权限。

所有这些权限都包含在 DBA 角色中，这适用于在私人开发人员的数据库上使用。

Oracle 数据库后端使用`SYS.DBMS_LOB`包，因此您的用户将需要对其具有执行权限。通常情况下，默认情况下所有用户都可以访问它，但如果不行，您将需要授予权限，如下所示：

```py
GRANT EXECUTE ON SYS.DBMS_LOB TO user; 

```

## 连接到数据库

要使用 Oracle 数据库的服务名称进行连接，您的`settings.py`文件应该如下所示：

```py
DATABASES = { 
    'default': { 
        'ENGINE': 'django.db.backends.oracle', 
        'NAME': 'xe', 
        'USER': 'a_user', 
        'PASSWORD': 'a_password', 
        'HOST': '', 
        'PORT': '', 
    } 
} 

```

在这种情况下，您应该将`HOST`和`PORT`都留空。但是，如果您不使用`tnsnames.ora`文件或类似的命名方法，并且希望使用 SID（在此示例中为`xe`）进行连接，那么请填写`HOST`和`PORT`如下：

```py
DATABASES = { 
    'default': { 
        'ENGINE': 'django.db.backends.oracle', 
        'NAME': 'xe', 
        'USER': 'a_user', 
        'PASSWORD': 'a_password', 
        'HOST': 'dbprod01ned.mycompany.com', 
        'PORT': '1540', 
    } 
} 

```

您应该同时提供`HOST`和`PORT`，或者将两者都留空。Django 将根据选择使用不同的连接描述符。

## 线程选项

如果您计划在多线程环境中运行 Django（例如，在任何现代操作系统上使用默认 MPM 模块的 Apache），那么您**必须**将 Oracle 数据库配置的`threaded`选项设置为 True：

```py
'OPTIONS': { 
    'threaded': True, 
}, 

```

未能这样做可能会导致崩溃和其他奇怪的行为。

## INSERT ... RETURNING INTO

默认情况下，Oracle 后端使用`RETURNING INTO`子句来高效地检索`AutoField`的值，当插入新行时。这种行为可能会导致某些不寻常的设置中出现`DatabaseError`，例如在远程表中插入，或者在具有`INSTEAD OF`触发器的视图中插入。

`RETURNING INTO`子句可以通过将数据库配置的`use_returning_into`选项设置为 False 来禁用：

```py
'OPTIONS': { 
    'use_returning_into': False, 
}, 

```

在这种情况下，Oracle 后端将使用单独的`SELECT`查询来检索`AutoField`值。

## 命名问题

Oracle 对名称长度有 30 个字符的限制。

为了适应这一点，后端将数据库标识符截断以适应，用可重复的 MD5 哈希值替换截断名称的最后四个字符。此外，后端将数据库标识符转换为全大写。

为了防止这些转换（通常仅在处理传统数据库或访问属于其他用户的表时才需要），请使用带引号的名称作为`db_table`的值：

```py
class LegacyModel(models.Model): 
    class Meta: 
        db_table = '"name_left_in_lowercase"' 

class ForeignModel(models.Model): 
    class Meta: 
        db_table = '"OTHER_USER"."NAME_ONLY_SEEMS_OVER_30"' 

```

带引号的名称也可以与 Django 的其他支持的数据库后端一起使用；但是，除了 Oracle 之外，引号没有任何效果。

在运行`migrate`时，如果将某些 Oracle 关键字用作模型字段的名称或`db_column`选项的值，则可能会遇到`ORA-06552`错误。 Django 引用所有在查询中使用的标识符，以防止大多数此类问题，但是当 Oracle 数据类型用作列名时，仍然可能发生此错误。特别要注意避免使用名称`date`，`timestamp`，`number`或`float`作为字段名称。

## NULL 和空字符串

Django 通常更喜欢使用空字符串（''“）而不是`NULL`，但是 Oracle 将两者视为相同。为了解决这个问题，Oracle 后端会忽略对具有空字符串作为可能值的字段的显式`null`选项，并生成 DDL，就好像`null=True`一样。在从数据库中获取数据时，假定这些字段中的`NULL`值实际上意味着空字符串，并且数据会被默默地转换以反映这一假设。

## Textfield 的限制

Oracle 后端将`TextField`存储为`NCLOB`列。 Oracle 对此类 LOB 列的使用施加了一些限制：

+   LOB 列不能用作主键。

+   LOB 列不能用于索引。

+   LOB 列不能在`SELECT DISTINCT`列表中使用。这意味着在包含`TextField`列的模型上尝试使用`QuerySet.distinct`方法将导致针对 Oracle 运行时出错。作为解决方法，使用`QuerySet.defer`方法与`distinct()`结合使用，以防止`TextField`列被包括在`SELECT DISTINCT`列表中。

# 使用第三方数据库后端

除了官方支持的数据库外，还有第三方提供的后端，允许您使用其他数据库与 Django 一起使用：

+   SAP SQL Anywhere

+   IBM DB2

+   Microsoft SQL Server

+   Firebird

+   ODBC

+   ADSDB

这些非官方后端支持的 Django 版本和 ORM 功能差异很大。关于这些非官方后端的具体功能以及任何支持查询，应该直接向每个第三方项目提供的支持渠道提出。

# 将 Django 与传统数据库集成

虽然 Django 最适合开发新应用程序，但完全可以将其集成到传统数据库中。Django 包括一些实用程序，以尽可能自动化这个过程。

设置好 Django 后，您将按照以下一般流程与现有数据库集成。

## 给 Django 提供您的数据库参数

您需要告诉 Django 您的数据库连接参数是什么，数据库的名称是什么。通过编辑`DATABASES`设置并为`'default'`连接分配值来完成这一点：

+   `NAME`

+   `ENGINE <DATABASE-ENGINE>`

+   `USER`

+   `PASSWORD`

+   `HOST`

+   `PORT`

## 自动生成模型

Django 带有一个名为`inspectdb`的实用程序，可以通过内省现有数据库来创建模型。您可以通过运行此命令查看输出：

```py
python manage.py inspectdb 

```

使用标准的 Unix 输出重定向将此保存为文件：

```py
python manage.py inspectdb > models.py 

```

此功能旨在作为快捷方式，而不是最终的模型生成。有关更多信息，请参阅`inspectdb`的文档。

清理模型后，将文件命名为`models.py`并将其放在包含您的应用程序的 Python 包中。然后将该应用程序添加到您的`INSTALLED_APPS`设置中。

默认情况下，`inspectdb`创建的是不受管理的模型。也就是说，在模型的`Meta`类中的`managed = False`告诉 Django 不要管理每个表的创建、修改和删除：

```py
class Person(models.Model): 
    id = models.IntegerField(primary_key=True) 
    first_name = models.CharField(max_length=70) 
    class Meta: 
       managed = False 
       db_table = 'CENSUS_PERSONS' 

```

如果你确实希望 Django 管理表的生命周期，你需要将前面的`managed`选项更改为`True`（或者简单地删除它，因为`True`是它的默认值）。

## 安装核心 Django 表

接下来，运行`migrate`命令来安装任何额外需要的数据库记录，比如管理员权限和内容类型：

```py
python manage.py migrate 

```

## 清理生成的模型

正如你所期望的那样，数据库内省并不完美，你需要对生成的模型代码进行一些轻微的清理。以下是处理生成模型的一些建议：

+   每个数据库表都转换为一个模型类（也就是说，数据库表和模型类之间是一对一的映射）。这意味着你需要将许多对多连接表的模型重构为`ManyToManyField`对象。

+   每个生成的模型都有一个属性对应每个字段，包括 id 主键字段。然而，要记住，如果一个模型没有主键，Django 会自动添加一个 id 主键字段。因此，你需要删除任何看起来像这样的行：

```py
        id = models.IntegerField(primary_key=True) 

```

+   这些行不仅是多余的，而且如果你的应用程序将向这些表中添加*新*记录，它们还会引起问题。

+   每个字段的类型（例如`CharField`、`DateField`）是通过查看数据库列类型（例如`VARCHAR`、`DATE`）来确定的。如果`inspectdb`无法将列的类型映射到模型字段类型，它将使用`TextField`，并在生成的模型中在字段旁边插入 Python 注释`'This field type is a guess.'`。留意这一点，如果需要，相应地更改字段类型。

+   如果数据库中的字段没有良好的 Django 等效项，你可以放心地将其删除。Django 模型层并不要求包含表中的每个字段。

+   如果数据库列名是 Python 保留字（比如`pass`、`class`或`for`），`inspectdb`会在属性名后面添加"`_field`"，并将`db_column`属性设置为真实字段名（例如`pass`、`class`或`for`）。

+   例如，如果一个表有一个名为`for`的`INT`列，生成的模型将有一个类似这样的字段：

```py
        for_field = models.IntegerField(db_column='for') 

```

+   `inspectdb`会在字段旁边插入 Python 注释`'Field renamed because it was a Python reserved word.'`。

+   如果你的数据库包含引用其他表的表（大多数数据库都是这样），你可能需要重新排列生成的模型的顺序，以便引用其他模型的模型被正确排序。例如，如果模型`Book`有一个指向模型`Author`的`ForeignKey`，模型`Author`应该在模型`Book`之前定义。如果需要在尚未定义的模型上创建关系，你可以使用包含模型名称的字符串，而不是模型对象本身。

+   `inspectdb`检测 PostgreSQL、MySQL 和 SQLite 的主键。也就是说，它会在适当的地方插入`primary_key=True`。对于其他数据库，你需要在每个模型中至少插入一个`primary_key=True`字段，因为 Django 模型需要有一个`primary_key=True`字段。

+   外键检测只适用于 PostgreSQL 和某些类型的 MySQL 表。在其他情况下，外键字段将被生成为`IntegerField`，假设外键列是一个`INT`列。

## 测试和调整

这些是基本步骤-从这里开始，你需要调整 Django 生成的模型，直到它们按照你的意愿工作。尝试通过 Django 数据库 API 访问数据，并尝试通过 Django 的管理站点编辑对象，并相应地编辑模型文件。

# 接下来是什么？

就是这样！

希望您喜欢阅读《精通 Django：核心》，并从这本书中学到了很多。虽然这本书将为您提供 Django 的完整参考，但没有什么能替代老实的实践-所以开始编码，祝您在 Django 职业生涯中一切顺利！

剩下的章节纯粹供您参考。它们包括附录和所有 Django 函数和字段的快速参考。


# 附录 A.模型定义参考

第四章中的*模型*解释了定义模型的基础知识，并且我们在本书的其余部分中使用它们。然而，还有大量的模型选项可用，其他地方没有涵盖。本附录解释了每个可能的模型定义选项。

# 字段

模型最重要的部分-也是模型的唯一必需部分-是它定义的数据库字段列表。

## 字段名称限制

Django 对模型字段名称只有两个限制：

1.  字段名称不能是 Python 保留字，因为那将导致 Python 语法错误。例如：

```py
        class Example(models.Model): 
        pass = models.IntegerField() # 'pass' is a reserved word! 

```

1.  由于 Django 的查询查找语法的工作方式，字段名称不能连续包含多个下划线。例如：

```py
        class Example(models.Model): 
            # 'foo__bar' has two underscores! 
            foo__bar = models.IntegerField()  

```

您模型中的每个字段都应该是适当`Field`类的实例。Django 使用字段类类型来确定一些事情：

+   数据库列类型（例如，`INTEGER`，`VARCHAR`）

+   在 Django 的表单和管理站点中使用的小部件，如果您愿意使用它（例如，`<input type="text">`，`<select>`）

+   最小的验证要求，这些要求在 Django 的管理界面和表单中使用

每个字段类都可以传递一系列选项参数，例如当我们在第四章中构建书籍模型时，我们的`num_pages`字段如下所示：

```py
num_pages = models.IntegerField(blank=True, null=True) 

```

在这种情况下，我们为字段类设置了`blank`和`null`选项。*表 A.2*列出了 Django 中的所有字段选项。

许多字段还定义了特定于该类的其他选项，例如`CharField`类具有一个必需选项`max_length`，默认为`None`。例如：

```py
title = models.CharField(max_length=100) 

```

在这种情况下，我们将`max_length`字段选项设置为 100，以将我们的书名限制为 100 个字符。

字段类的完整列表按字母顺序排列在*表 A.1*中。

| **字段** | **默认小部件** | **描述** |
| --- | --- | --- |
| `AutoField` | N/A | 根据可用 ID 自动递增的`IntegerField`。 |
| `BigIntegerField` | `NumberInput` | 64 位整数，类似于`IntegerField`，只是它保证适合从`-9223372036854775808`到`9223372036854775807`的数字 |
| `BinaryField` | N/A | 用于存储原始二进制数据的字段。它只支持`bytes`赋值。请注意，此字段功能有限。 |
| `BooleanField` | `CheckboxInput` | 真/假字段。如果需要接受`null`值，则使用`NullBooleanField`。 |
| `CharField` | `TextInput` | 用于小到大的字符串的字符串字段。对于大量的文本，请使用`TextField`。`CharField`有一个额外的必需参数：`max_length`。字段的最大长度（以字符为单位）。 |
| `DateField` | `DateInput` | 日期，在 Python 中由`datetime.date`实例表示。有两个额外的可选参数：`auto_now`，每次保存对象时自动将字段设置为现在，`auto_now_add`，在对象首次创建时自动将字段设置为现在。 |
| `DateTimeField` | `DateTimeInput` | 日期和时间，在 Python 中由`datetime.datetime`实例表示。接受与`DateField`相同的额外参数。 |
| `DecimalField` | `TextInput` | 固定精度的十进制数，在 Python 中由`Decimal`实例表示。有两个必需的参数：`max_digits`和`decimal_places`。 |
| `DurationField` | `TextInput` | 用于存储时间段的字段-在 Python 中由`timedelta`建模。 |
| `EmailField` | `TextInput` | 使用`EmailValidator`验证输入的`CharField`。`max_length`默认为`254`。 |
| `FileField` | `ClearableFileInput` | 文件上传字段。有关`FileField`的更多信息，请参见下一节。 |
| `FilePathField` | `Select` | `CharField`，其选择限于文件系统上某个目录中的文件名。 |
| `FloatField` | `NumberInput` | 由 Python 中的`float`实例表示的浮点数。注意，当`field.localize`为`False`时，默认小部件是`TextInput` |
| `ImageField` | `ClearableFileInput` | 继承自`FileField`的所有属性和方法，但也验证上传的对象是否是有效的图像。额外的`height`和`width`属性。需要在 http://pillow.readthedocs.org/en/latest/上可用的 Pillow 库。 |
| `IntegerField` | `NumberInput` | 一个整数。在 Django 支持的所有数据库中，从`-2147483648`到`2147483647`的值都是安全的。 |
| `GenericIPAddressField` | `TextInput` | 一个 IPv4 或 IPv6 地址，以字符串格式表示（例如，`192.0.2.30`或`2a02:42fe::4`）。 |
| `NullBooleanField` | `NullBooleanSelect` | 像`BooleanField`，但允许`NULL`作为其中一个选项。 |
| `PositiveIntegerField` | `NumberInput` | 一个整数。在 Django 支持的所有数据库中，从`0`到`2147483647`的值都是安全的。 |
| `SlugField` | `TextInput` | Slug 是一个报纸术语。Slug 是某物的一个简短标签，只包含字母、数字、下划线或连字符。 |
| `SmallIntegerField` | `NumberInput` | 像`IntegerField`，但只允许在某个点以下的值。在 Django 支持的所有数据库中，从`-32768`到`32767`的值都是安全的。 |
| `TextField` | `Textarea` | 一个大文本字段。如果指定了`max_length`属性，它将反映在自动生成的表单字段的`Textarea`小部件中。 |
| `TimeField` | `TextInput` | 一个时间，由 Python 中的`datetime.time`实例表示。 |
| `URLField` | `URLInput` | 用于 URL 的`CharField`。可选的`max_length`参数。 |
| `UUIDField` | `TextInput` | 用于存储通用唯一标识符的字段。使用 Python 的`UUID`类。 |

表 A.1：Django 模型字段参考

## FileField 注意事项

不支持`primary_key`和`unique`参数，如果使用将会引发`TypeError`。

+   有两个可选参数：FileField.upload_to

+   `FileField.storage`

### FileField FileField.upload_to

一个本地文件系统路径，将被附加到您的`MEDIA_ROOT`设置，以确定`url`属性的值。这个路径可能包含`strftime()`格式，它将被文件上传的日期/时间替换（这样上传的文件不会填满给定的目录）。这也可以是一个可调用的，比如一个函数，它将被调用来获取上传路径，包括文件名。这个可调用必须能够接受两个参数，并返回一个 Unix 风格的路径（带有正斜杠），以便传递给存储系统。

将传递的两个参数是：

+   **实例：**模型的一个实例，其中定义了 FileField。更具体地说，这是当前文件被附加的特定实例。在大多数情况下，这个对象还没有保存到数据库中，所以如果它使用默认的`AutoField`，它可能还没有主键字段的值。

+   **文件名：**最初给定的文件名。在确定最终目标路径时可能会考虑这个文件名。

### FileField.storage

一个存储对象，用于处理文件的存储和检索。这个字段的默认表单小部件是`ClearableFileInput`。在模型中使用`FileField`或`ImageField`（见下文）需要几个步骤：

+   在您的设置文件中，您需要将`MEDIA_ROOT`定义为一个目录的完整路径，您希望 Django 存储上传的文件在其中。（出于性能考虑，这些文件不存储在数据库中。）将`MEDIA_URL`定义为该目录的基本公共 URL。确保这个目录对 Web 服务器的用户帐户是可写的。

+   将`FileField`或`ImageField`添加到您的模型中，定义`upload_to`选项以指定`MEDIA_ROOT`的子目录，用于上传文件。

+   在数据库中存储的只是文件的路径（相对于 `MEDIA_ROOT`）。您很可能会想要使用 Django 提供的便捷的 `url` 属性。例如，如果您的 `ImageField` 名为 `mug_shot`，您可以在模板中使用 `{{ object.mug_shot.url }}` 获取图像的绝对路径。

请注意，每当处理上传的文件时，都应该密切关注您上传文件的位置和文件类型，以避免安全漏洞。验证所有上传的文件，以确保文件是您认为的文件。例如，如果您盲目地让某人上传文件，而没有进行验证，到您的 Web 服务器文档根目录中，那么某人可能会上传一个 CGI 或 PHP 脚本，并通过访问其 URL 在您的网站上执行该脚本。不要允许这种情况发生。

还要注意，即使是上传的 HTML 文件，由于浏览器可以执行它（尽管服务器不能），可能会带来等同于 XSS 或 CSRF 攻击的安全威胁。`FileField` 实例在数据库中以 `varchar` 列的形式创建，具有默认的最大长度为 100 个字符。与其他字段一样，您可以使用 `max_length` 参数更改最大长度。

### FileField 和 FieldFile

当您在模型上访问 `FileField` 时，会得到一个 `FieldFile` 的实例，作为访问底层文件的代理。除了从 `django.core.files.File` 继承的功能外，此类还具有几个属性和方法，可用于与文件数据交互：

#### FieldFile.url

通过调用底层 `Storage` 类的 `url()` 方法来访问文件的相对 URL 的只读属性。

#### FieldFile.open(mode='rb')

行为类似于标准的 Python `open()` 方法，并以 `mode` 指定的模式打开与此实例关联的文件。

#### FieldFile.close()

行为类似于标准的 Python `file.close()` 方法，并关闭与此实例关联的文件。

#### FieldFile.save(name, content, save=True)

此方法接受文件名和文件内容，并将它们传递给字段的存储类，然后将存储的文件与模型字段关联起来。如果您想手动将文件数据与模型上的 `FileField` 实例关联起来，可以使用 `save()` 方法来持久化该文件数据。

需要两个必需参数：`name` 是文件的名称，`content` 是包含文件内容的对象。可选的 `save` 参数控制在更改与此字段关联的文件后是否保存模型实例。默认为 `True`。

请注意，`content` 参数应该是 `django.core.files.File` 的实例，而不是 Python 的内置文件对象。您可以像这样从现有的 Python 文件对象构造一个 `File`：

```py
from django.core.files import File 
# Open an existing file using Python's built-in open() 
f = open('/tmp/hello.world') 
myfile = File(f) 

```

或者您可以像这样从 Python 字符串构造一个：

```py
from django.core.files.base import ContentFile 
myfile = ContentFile("hello world") 

```

#### FieldFile.delete(save=True)

删除与此实例关联的文件并清除字段上的所有属性。如果在调用 `delete()` 时文件处于打开状态，此方法将关闭文件。

可选的 `save` 参数控制在删除与此字段关联的文件后是否保存模型实例。默认为 `True`。

请注意，当模型被删除时，相关文件不会被删除。如果您需要清理孤立的文件，您需要自行处理（例如，使用自定义的管理命令，可以手动运行或通过例如 `cron` 定期运行）。

# 通用字段选项

*表 A.2* 列出了 Django 中所有字段类型的所有可选字段参数。

| 选项 | 描述 |
| --- | --- |
| `null` | 如果为 `True`，Django 将在数据库中将空值存储为 `NULL`。默认为 `False`。避免在诸如 `CharField` 和 `TextField` 等基于字符串的字段上使用 `null`，因为空字符串值将始终被存储为空字符串，而不是 `NULL`。对于基于字符串和非基于字符串的字段，如果希望在表单中允许空值，还需要设置 `blank=True`。如果要接受带有 `BooleanField` 的 `null` 值，请改用 `NullBooleanField`。 |
| `blank` | 如果为 `True`，则允许该字段为空。默认为 `False`。请注意，这与 `null` 是不同的。`null` 纯粹是与数据库相关的，而 `blank` 是与验证相关的。 |
| `choices` | 一个可迭代对象（例如列表或元组），其中包含正好两个项的可迭代对象（例如 `[(A, B), (A, B) ...]`），用作此字段的选择。如果给出了这个选项，默认的表单小部件将是一个带有这些选择的选择框，而不是标准文本字段。每个元组中的第一个元素是要在模型上设置的实际值，第二个元素是人类可读的名称。 |
| `db_column` | 用于此字段的数据库列的名称。如果没有给出，Django 将使用字段的名称。 |
| `db_index` | 如果为 `True`，将为此字段创建数据库索引。 |
| `db_tablespace` | 用于此字段索引的数据库表空间的名称，如果此字段已被索引。默认值是项目的 `DEFAULT_INDEX_TABLESPACE` 设置（如果设置了），或者模型的 `db_tablespace`（如果有）。如果后端不支持索引的表空间，则将忽略此选项。 |
| `default` | 该字段的默认值。这可以是一个值或一个可调用对象。如果是可调用的，它将在创建新对象时每次被调用。默认值不能是可变对象（模型实例、列表、集合等），因为在所有新模型实例中将使用对该对象的相同实例的引用作为默认值。 |
| `editable` | 如果为 `False`，该字段将不会显示在管理界面或任何其他 `ModelForm` 中。它们也会在模型验证期间被跳过。默认为 `True`。 |
| `error_messages` | `error_messages` 参数允许您覆盖字段将引发的默认消息。传入一个字典，其中键与您想要覆盖的错误消息相匹配。错误消息键包括 `null`、`blank`、`invalid`、`invalid_choice`、`unique` 和 `unique_for_date`。 |
| `help_text` | 要与表单小部件一起显示的额外帮助文本。即使您的字段在表单上没有使用，这也是有用的文档。请注意，此值在自动生成的表单中 *不* 是 HTML 转义的。这样，如果您愿意，可以在 `help_text` 中包含 HTML。 |
| `primary_key` | 如果为 `True`，则该字段是模型的主键。如果您没有为模型中的任何字段指定 `primary_key=True`，Django 将自动添加一个 `AutoField` 来保存主键，因此您不需要在任何字段上设置 `primary_key=True`，除非您想要覆盖默认的主键行为。主键字段是只读的。 |
| `unique` | 如果为 `True`，则此字段必须在整个表中是唯一的。这是在数据库级别和模型验证期间强制执行的。此选项对除 `ManyToManyField`、`OneToOneField` 和 `FileField` 之外的所有字段类型都有效。 |
| `unique_for_date` | 将其设置为 `DateField` 或 `DateTimeField` 的名称，以要求此字段对于日期字段的值是唯一的。例如，如果有一个字段 `title`，其 `unique_for_date="pub_date"`，那么 Django 将不允许输入具有相同 `title` 和 `pub_date` 的两条记录。这是在模型验证期间由 `Model.validate_unique()` 强制执行的，但不是在数据库级别上。 |
| `unique_for_month` | 类似于 `unique_for_date`，但要求该字段相对于月份是唯一的。 |
| `unique_for_year` | 类似于 `unique_for_date`，但要求该字段相对于年份是唯一的。 |
| `verbose_name` | 字段的可读名称。如果未给出详细名称，Django 将使用字段的属性名称自动创建它，将下划线转换为空格。 |
| `validators` | 一个要为此字段运行的验证器列表。 |

表 A.2：Django 通用字段选项

# 字段属性引用

每个`Field`实例都包含几个属性，允许内省其行为。在需要编写依赖于字段功能的代码时，请使用这些属性，而不是`isinstance`检查。这些属性可以与`Model._meta` API 一起使用，以缩小对特定字段类型的搜索。自定义模型字段应实现这些标志。

## 字段属性

### Field.auto_created

布尔标志，指示字段是否自动创建，例如模型继承中使用的`OneToOneField`。

### Field.concrete

布尔标志，指示字段是否与数据库列关联。

### Field.hidden

布尔标志，指示字段是否用于支持另一个非隐藏字段的功能（例如，构成`GenericForeignKey`的`content_type`和`object_id`字段）。`hidden`标志用于区分模型上的字段的公共子集与模型上的所有字段。

### Field.is_relation

布尔标志，指示字段是否包含对一个或多个其他模型的引用，以实现其功能（例如，`ForeignKey`，`ManyToManyField`，`OneToOneField`等）。

### Field.model

返回定义字段的模型。如果字段在模型的超类上定义，则`model`将引用超类，而不是实例的类。

## 具有关系的字段属性

这些属性用于查询关系的基数和其他细节。这些属性存在于所有字段上；但是，只有在字段是关系类型（`Field.is_relation=True`）时，它们才会有有意义的值。

### Field.many_to_many

布尔标志，如果字段具有多对多关系，则为`True`；否则为`False`。Django 中唯一包含此标志为`True`的字段是`ManyToManyField`。

### Field.many_to_one

布尔标志，如果字段具有多对一关系（例如`ForeignKey`），则为`True`；否则为`False`。

### Field.one_to_many

布尔标志，如果字段具有一对多关系（例如`GenericRelation`或`ForeignKey`的反向关系），则为`True`；否则为`False`。

### Field.one_to_one

布尔标志，如果字段具有一对一关系（例如`OneToOneField`），则为`True`；否则为`False`。

### Field.related_model

指向字段相关的模型。例如，在`ForeignKey(Author)`中的`Author`。如果字段具有通用关系（例如`GenericForeignKey`或`GenericRelation`），则`related_model`将为`None`。

# 关系

Django 还定义了一组表示关系的字段。

## ForeignKey

多对一关系。需要一个位置参数：模型相关的类。要创建递归关系（与自身具有多对一关系的对象），请使用`models.ForeignKey('self')`。

如果需要在尚未定义的模型上创建关系，可以使用模型的名称，而不是模型对象本身：

```py
from django.db import models 

class Car(models.Model): 
    manufacturer = models.ForeignKey('Manufacturer') 
    # ... 

class Manufacturer(models.Model): 
    # ... 
    pass 

```

要引用另一个应用程序中定义的模型，可以明确指定具有完整应用程序标签的模型。例如，如果上面的`Manufacturer`模型在另一个名为`production`的应用程序中定义，则需要使用：

```py
class Car(models.Model): 
    manufacturer = models.ForeignKey('production.Manufacturer') 

```

在两个应用程序之间解析循环导入依赖关系时，这种引用可能很有用。在`ForeignKey`上自动创建数据库索引。您可以通过将`db_index`设置为`False`来禁用此功能。

如果您创建外键以确保一致性而不是连接，或者如果您将创建替代索引（如部分索引或多列索引），则可能希望避免索引的开销。

### 数据库表示

在幕后，Django 将`字段名`附加`"_id"`以创建其数据库列名。在上面的示例中，`Car`模型的数据库表将具有`manufacturer_id`列。

您可以通过指定`db_column`来明确更改这一点，但是，除非编写自定义 SQL，否则您的代码不应该处理数据库列名。您将始终处理模型对象的字段名称。

### 参数

`ForeignKey`接受一组额外的参数-全部是可选的-用于定义关系的详细信息。

#### limit_choices_to

设置此字段的可用选择的限制，当使用`ModelForm`或管理员渲染此字段时（默认情况下，查询集中的所有对象都可供选择）。可以使用字典、`Q`对象或返回字典或`Q`对象的可调用对象。例如：

```py
staff_member = models.ForeignKey(User, limit_choices_to={'is_staff': True}) 

```

导致`ModelForm`上的相应字段仅列出`is_staff=True`的`Users`。这在 Django 管理员中可能会有所帮助。可调用形式可能会有所帮助，例如，当与 Python `datetime`模块一起使用以限制日期范围的选择时。例如：

```py
def limit_pub_date_choices(): 
    return {'pub_date__lte': datetime.date.utcnow()} 
limit_choices_to = limit_pub_date_choices 

```

如果`limit_choices_to`是或返回`Q 对象`，对于复杂查询很有用，那么它只会影响在模型的`ModelAdmin`中未列出`raw_id_fields`时管理员中可用的选择。

#### related_name

用于从相关对象返回到此对象的关系的名称。这也是`related_query_name`的默认值（从目标模型返回的反向过滤器名称）。有关完整说明和示例，请参阅相关对象文档。请注意，在定义抽象模型上的关系时，必须设置此值；在这样做时，一些特殊的语法是可用的。如果您希望 Django 不创建反向关系，请将`related_name`设置为`'+'`或以`'+'`结尾。例如，这将确保`User`模型不会有到此模型的反向关系：

```py
user = models.ForeignKey(User, related_name='+') 

```

#### related_query_name

用于从目标模型返回的反向过滤器名称的名称。如果设置了`related_name`，则默认为`related_name`的值，否则默认为模型的名称：

```py
# Declare the ForeignKey with related_query_name 
class Tag(models.Model): 
    article = models.ForeignKey(Article, related_name="tags",
      related_query_name="tag") 
    name = models.CharField(max_length=255) 

# That's now the name of the reverse filter 
Article.objects.filter(tag__name="important") 

```

#### to_field

关系对象上的字段。默认情况下，Django 使用相关对象的主键。

#### db_constraint

控制是否应为此外键在数据库中创建约束。默认值为`True`，这几乎肯定是您想要的；将其设置为`False`可能对数据完整性非常不利。也就是说，有一些情况下您可能希望这样做：

+   您有无效的旧数据。

+   您正在对数据库进行分片。

如果设置为`False`，访问不存在的相关对象将引发其`DoesNotExist`异常。

#### 删除时

当被`ForeignKey`引用的对象被删除时，Django 默认会模拟 SQL 约束`ON DELETE CASCADE`的行为，并删除包含`ForeignKey`的对象。可以通过指定`on_delete`参数来覆盖此行为。例如，如果您有一个可空的`ForeignKey`，并且希望在删除引用对象时将其设置为 null：

```py
user = models.ForeignKey(User, blank=True, null=True, on_delete=models.SET_NULL) 

```

`on_delete`的可能值可以在`django.db.models`中找到：

+   `CASCADE`：级联删除；默认值

+   `PROTECT`：通过引发`ProtectedError`（`django.db.IntegrityError`的子类）来防止删除引用对象

+   `SET_NULL`：将`ForeignKey`设置为 null；只有在`null`为`True`时才可能

+   `SET_DEFAULT`：将`ForeignKey`设置为其默认值；必须设置`ForeignKey`的默认值

#### 可交换

控制迁移框架对指向可交换模型的此`ForeignKey`的反应。如果为`True`-默认值-那么如果`ForeignKey`指向与当前`settings.AUTH_USER_MODEL`的值（或其他可交换模型设置）匹配的模型，则关系将在迁移中使用对设置的引用而不是直接对模型进行存储。

只有在确定模型应始终指向替换模型时才要将其覆盖为`False`，例如，如果它是专门为自定义用户模型设计的配置文件模型。将其设置为`False`并不意味着即使替换了模型，也可以引用可交换模型-`False`只是意味着使用此`ForeignKey`进行的迁移将始终引用您指定的确切模型（例如，如果用户尝试使用您不支持的用户模型，则会严重失败）。如果有疑问，请将其保留为默认值`True`。

## ManyToManyField

多对多关系。需要一个位置参数：模型相关的类，其工作方式与`ForeignKey`完全相同，包括递归和延迟关系。可以使用字段的`RelatedManager`添加、删除或创建相关对象。

### 数据库表示

在幕后，Django 创建一个中间连接表来表示多对多关系。默认情况下，此表名是使用多对多字段的名称和包含它的模型的表名生成的。

由于某些数据库不支持超过一定长度的表名，这些表名将自动截断为 64 个字符，并使用唯一性哈希。这意味着您可能会看到表名如`author_books_9cdf4`；这是完全正常的。您可以使用`db_table`选项手动提供连接表的名称。

### 参数

`ManyToManyField`接受一组额外的参数-全部是可选的-用于控制关系的功能。

#### related_name

与`ForeignKey.related_name`相同。

#### related_query_name

与`ForeignKey.related_query_name`相同。

#### limit_choices_to

与`ForeignKey.limit_choices_to`相同。当在使用`through`参数指定自定义中间表的`ManyToManyField`上使用`limit_choices_to`时，`limit_choices_to`没有效果。

#### 对称的

仅在自身的 ManyToManyFields 的定义中使用。考虑以下模型：

```py
from django.db import models 

class Person(models.Model): 
    friends = models.ManyToManyField("self") 

```

当 Django 处理此模型时，它会识别出它在自身上有一个`ManyToManyField`，因此它不会向`Person`类添加`person_set`属性。相反，假定`ManyToManyField`是对称的-也就是说，如果我是你的朋友，那么你也是我的朋友。

如果不希望在`self`的多对多关系中具有对称性，请将`symmetrical`设置为`False`。这将强制 Django 添加反向关系的描述符，从而允许`ManyToManyField`关系不对称。

#### 通过

Django 将自动生成一个表来管理多对多关系。但是，如果要手动指定中间表，可以使用`through`选项来指定表示要使用的中间表的 Django 模型。

此选项的最常见用法是当您想要将额外数据与多对多关系关联时。如果不指定显式的`through`模型，则仍然有一个隐式的`through`模型类，您可以使用它直接访问创建以保存关联的表。它有三个字段：

+   `id`：关系的主键

+   `<containing_model>_id`：声明`ManyToManyField`的模型的`id`

+   `<other_model>_id`：`ManyToManyField`指向的模型的`id`

此类可用于像普通模型一样查询给定模型实例的关联记录。

#### through_fields

仅在指定自定义中介模型时使用。Django 通常会确定中介模型的哪些字段以自动建立多对多关系。

#### db_table

用于存储多对多数据的表的名称。如果未提供此名称，Django 将基于定义关系的模型的表的名称和字段本身的名称假定默认名称。

#### db_constraint

控制是否应在中介表的外键在数据库中创建约束。默认值为`True`，这几乎肯定是您想要的；将其设置为`False`可能对数据完整性非常不利。

也就是说，以下是一些可能需要这样做的情况：

+   您有不合法的遗留数据

+   您正在对数据库进行分片

传递`db_constraint`和`through`是错误的。

#### swappable

如果此`ManyToManyField`指向可交换模型，则控制迁移框架的反应。如果为`True`-默认值-如果`ManyToManyField`指向与`settings.AUTH_USER_MODEL`（或其他可交换模型设置）的当前值匹配的模型，则关系将存储在迁移中，使用对设置的引用，而不是直接对模型。

只有在确定模型应始终指向替换模型的情况下，才希望将其覆盖为`False`-例如，如果它是专门为自定义用户模型设计的配置文件模型。如果有疑问，请将其保留为默认值`True`。`ManyToManyField`不支持`validators`。`null`没有影响，因为没有办法在数据库级别要求关系。

## OneToOneField

一对一关系。在概念上，这类似于具有`unique=True`的`ForeignKey`，但关系的反向侧将直接返回单个对象。这在作为模型的主键时最有用，该模型以某种方式扩展另一个模型；通过向子模型添加从子模型到父模型的隐式一对一关系来实现多表继承，例如。

需要一个位置参数：将与之相关的类。这与`ForeignKey`的工作方式完全相同，包括递归和延迟关系的所有选项。如果未为`OneToOneField`指定`related_name`参数，Django 将使用当前模型的小写名称作为默认值。使用以下示例：

```py
from django.conf import settings 
from django.db import models 

class MySpecialUser(models.Model): 
    user = models.OneToOneField(settings.AUTH_USER_MODEL) 
    supervisor = models.OneToOneField(settings.AUTH_USER_MODEL, 
      related_name='supervisor_of') 

```

您的生成的`User`模型将具有以下属性：

```py
>>> user = User.objects.get(pk=1)
>>> hasattr(user, 'myspecialuser')
True
>>> hasattr(user, 'supervisor_of')
True

```

当访问相关表中的条目不存在时，将引发`DoesNotExist`异常。例如，如果用户没有由`MySpecialUser`指定的主管：

```py
>>> user.supervisor_of
Traceback (most recent call last):
 ...
DoesNotExist: User matching query does not exist.

```

此外，`OneToOneField`接受`ForeignKey`接受的所有额外参数，以及一个额外参数：

### parent_link

当在继承自另一个具体模型的模型中使用时，`True`表示应使用此字段作为返回到父类的链接，而不是通常通过子类隐式创建的额外`OneToOneField`。有关`OneToOneField`的用法示例，请参见下一章中的*一对一关系*。

# 模型元数据选项

*表 A.3*是您可以在其内部`class Meta`中为模型提供的完整模型元选项列表。有关每个元选项的更多详细信息以及示例，请参阅 Django 文档[`docs.djangoproject.com/en/1.8/ref/models/options/`](https://docs.djangoproject.com/en/1.8/ref/models/options/)。

| **选项** | **说明** |
| --- | --- |
| `abstract` | 如果`abstract = True`，此模型将是一个抽象基类。 |
| `app_label` | 如果模型在`INSTALLED_APPS`之外定义，它必须声明属于哪个应用程序。 |
| `db_table` | 用于模型的数据库表的名称。 |
| - `db_tablespace` | 用于此模型的数据库表空间的名称。如果设置了项目的 `DEFAULT_TABLESPACE` 设置，则默认为该设置。如果后端不支持表空间，则忽略此选项。 |
| - `default_related_name` | 从相关对象返回到此对象的关系的默认名称。默认为 `<model_name>_set`。 |
| - `get_latest_by` | 模型中可排序字段的名称，通常为 `DateField`、`DateTimeField` 或 `IntegerField`。 |
| - `managed` | 默认为 `True`，意味着 Django 将在`migrate`或作为迁移的一部分中创建适当的数据库表，并在`flush`管理命令的一部分中删除它们。 |
| - `order_with_respect_to` | 标记此对象相对于给定字段是可排序的。 |
| - `ordering` | 对象的默认排序，用于获取对象列表时使用。 |
| - `permissions` | 创建此对象时要输入权限表的额外权限。 |
| - `default_permissions` | 默认为 `('add', 'change', 'delete')`。 |
| - `proxy` | 如果 `proxy = True`，则子类化另一个模型的模型将被视为代理模型。 |
| - `select_on_save` | 确定 Django 是否使用 pre-1.6 `django.db.models.Model.save()` 算法。 |
| - `unique_together` | 一起使用的字段集，必须是唯一的。 |
| - `index_together` | 一起使用的字段集，被索引。 |
| - `verbose_name` | 对象的可读名称，单数形式。 |
| - `verbose_name_plural` | 对象的复数名称。 |

表 A.3：模型元数据选项


# 附录 B.数据库 API 参考

Django 的数据库 API 是附录 A 中讨论的模型 API 的另一半。一旦定义了模型，您将在需要访问数据库时使用此 API。您已经在整本书中看到了此 API 的使用示例；本附录详细解释了各种选项。

在本附录中，我将引用以下模型，这些模型组成了一个 Weblog 应用程序：

```py
from django.db import models 

class Blog(models.Model): 
    name = models.CharField(max_length=100) 
    tagline = models.TextField() 

    def __str__(self): 
        return self.name 

class Author(models.Model): 
    name = models.CharField(max_length=50) 
    email = models.EmailField() 

    def __str__(self): 
        return self.name 

class Entry(models.Model): 
    blog = models.ForeignKey(Blog) 
    headline = models.CharField(max_length=255) 
    body_text = models.TextField() 
    pub_date = models.DateField() 
    mod_date = models.DateField() 
    authors = models.ManyToManyField(Author) 
    n_comments = models.IntegerField() 
    n_pingbacks = models.IntegerField() 
    rating = models.IntegerField() 

    def __str__(self):        
        return self.headline 

```

# 创建对象

为了在 Python 对象中表示数据库表数据，Django 使用了一个直观的系统：模型类表示数据库表，该类的实例表示数据库表中的特定记录。

要创建对象，请使用模型类的关键字参数进行实例化，然后调用`save()`将其保存到数据库中。

假设模型位于文件`mysite/blog/models.py`中，这是一个示例：

```py
>>> from blog.models import Blog
>>> b = Blog(name='Beatles Blog', tagline='All the latest Beatles news.')
>>> b.save()

```

这在幕后执行`INSERT` SQL 语句。直到您明确调用`save()`之前，Django 不会访问数据库。

`save()`方法没有返回值。

要在单个步骤中创建和保存对象，请使用`create()`方法。

# 保存对象的更改

要保存已经在数据库中的对象的更改，请使用`save()`。

假设已经将`Blog`实例`b5`保存到数据库中，此示例更改其名称并更新数据库中的记录：

```py
>>> b5.name = 'New name'
>>> b5.save()

```

这在幕后执行`UPDATE` SQL 语句。Django 直到您明确调用`save()`之前才会访问数据库。

## 保存 ForeignKey 和 ManyToManyField 字段

更新`ForeignKey`字段的方式与保存普通字段的方式完全相同-只需将正确类型的对象分配给相关字段。此示例更新了`Entry`实例`entry`的`blog`属性，假设已经适当保存了`Entry`和`Blog`的实例到数据库中（因此我们可以在下面检索它们）：

```py
>>> from blog.models import Entry
>>> entry = Entry.objects.get(pk=1)
>>> cheese_blog = Blog.objects.get(name="Cheddar Talk")
>>> entry.blog = cheese_blog
>>> entry.save()

```

更新`ManyToManyField`的方式略有不同-使用字段上的`add()`方法将记录添加到关系中。此示例将`Author`实例`joe`添加到`entry`对象中：

```py
>>> from blog.models import Author
>>> joe = Author.objects.create(name="Joe")
>>> entry.authors.add(joe)

```

要一次向`ManyToManyField`添加多条记录，请在调用`add()`时包含多个参数，如下所示：

```py
>>> john = Author.objects.create(name="John")
>>> paul = Author.objects.create(name="Paul")
>>> george = Author.objects.create(name="George")
>>> ringo = Author.objects.create(name="Ringo")
>>> entry.authors.add(john, paul, george, ringo)

```

如果尝试分配或添加错误类型的对象，Django 会发出警告。

# 检索对象

要从数据库中检索对象，请通过模型类上的`Manager`构建`QuerySet`。

`QuerySet`表示来自数据库的对象集合。它可以有零个、一个或多个过滤器。过滤器根据给定的参数缩小查询结果。在 SQL 术语中，`QuerySet`等同于`SELECT`语句，而过滤器是诸如`WHERE`或`LIMIT`的限制子句。

通过使用模型的`Manager`来获取`QuerySet`。每个模型至少有一个`Manager`，默认情况下称为`objects`。直接通过模型类访问它，就像这样：

```py
>>> Blog.objects
<django.db.models.manager.Manager object at ...>
>>> b = Blog(name='Foo', tagline='Bar')
>>> b.objects
Traceback:
 ...
AttributeError: "Manager isn't accessible via Blog instances."

```

## 检索所有对象

从表中检索对象的最简单方法是获取所有对象。要做到这一点，使用`Manager`上的`all()`方法：

```py
>>> all_entries = Entry.objects.all()

```

`all()`方法返回数据库中所有对象的`QuerySet`。

## 使用过滤器检索特定对象

`all()`返回的`QuerySet`描述了数据库表中的所有对象。通常，您需要选择完整对象集的子集。

要创建这样的子集，您需要细化初始的`QuerySet`，添加过滤条件。细化`QuerySet`的两种最常见的方法是：

+   `filter(**kwargs)`。返回一个包含匹配给定查找参数的对象的新`QuerySet`。

+   `exclude(**kwargs)`。返回一个包含不匹配给定查找参数的对象的新`QuerySet`。

查找参数（上述函数定义中的`**kwargs`）应该以本章后面描述的*字段查找*格式。

### 链接过滤器

细化`QuerySet`的结果本身是一个`QuerySet`，因此可以将细化链接在一起。例如：

```py
>>> Entry.objects.filter(
...     headline__startswith='What'
... ).exclude(
...     pub_date__gte=datetime.date.today()
... ).filter(pub_date__gte=datetime(2005, 1, 30)
... )

```

这需要数据库中所有条目的初始`QuerySet`，添加一个过滤器，然后一个排除，然后另一个过滤器。最终结果是一个包含所有以`What`开头的标题的条目，发布日期在 2005 年 1 月 30 日和当天之间的`QuerySet`。

## 过滤的查询集是唯一的

每次细化`QuerySet`，您都会得到一个全新的`QuerySet`，它与以前的`QuerySet`没有任何关联。每次细化都会创建一个单独且独特的`QuerySet`，可以存储、使用和重复使用。

例子：

```py
>>> q1 = Entry.objects.filter(headline__startswith="What")
>>> q2 = q1.exclude(pub_date__gte=datetime.date.today())
>>> q3 = q1.filter(pub_date__gte=datetime.date.today())

```

这三个`QuerySets`是独立的。第一个是一个基本的`QuerySet`，包含所有以 What 开头的标题的条目。第二个是第一个的子集，增加了一个额外的条件，排除了`pub_date`是今天或将来的记录。第三个是第一个的子集，增加了一个额外的条件，只选择`pub_date`是今天或将来的记录。初始的`QuerySet`（`q1`）不受细化过程的影响。

### QuerySets 是惰性的

`QuerySets`是惰性的-创建`QuerySet`的行为不涉及任何数据库活动。您可以整天堆叠过滤器，Django 实际上不会运行查询，直到`QuerySet`被*评估*。看看这个例子：

```py
>>> q = Entry.objects.filter(headline__startswith="What")
>>> q = q.filter(pub_date__lte=datetime.date.today())
>>> q = q.exclude(body_text__icontains="food")
>>> print(q)

```

尽管看起来像是三次数据库访问，实际上只有一次，在最后一行（`print(q)`）访问数据库。通常情况下，只有在要求时，`QuerySet`的结果才会从数据库中获取。当您这样做时，通过访问数据库来*评估*`QuerySet`。

## 使用 get 检索单个对象

`filter()`总是会给你一个`QuerySet`，即使只有一个对象匹配查询-在这种情况下，它将是包含单个元素的`QuerySet`。

如果您知道只有一个对象与您的查询匹配，您可以在`Manager`上使用`get()`方法直接返回对象：

```py
>>> one_entry = Entry.objects.get(pk=1)

```

您可以像使用`filter()`一样使用`get()`的任何查询表达式-再次参见本章的下一节中的*字段查找*。

请注意，使用`get()`和使用`filter()`与`[0]`的切片之间存在差异。如果没有结果与查询匹配，`get()`将引发`DoesNotExist`异常。此异常是正在执行查询的模型类的属性-因此在上面的代码中，如果没有主键为 1 的`Entry`对象，Django 将引发`Entry.DoesNotExist`。

类似地，如果`get()`查询匹配多个项目，Django 将抱怨。在这种情况下，它将引发`MultipleObjectsReturned`，这也是模型类本身的属性。

## 其他查询集方法

大多数情况下，当您需要从数据库中查找对象时，您将使用`all()`、`get()`、`filter()`和`exclude()`。但这远非全部；请参阅[`docs.djangoproject.com/en/1.8/ref/models/querysets/`](https://docs.djangoproject.com/en/1.8/ref/models/querysets/)上的 QuerySet API 参考，了解所有各种`QuerySet`方法的完整列表。

## 限制查询集

使用 Python 的数组切片语法的子集来限制您的`QuerySet`到一定数量的结果。这相当于 SQL 的`LIMIT`和`OFFSET`子句。

例如，这将返回前 5 个对象（`LIMIT 5`）：

```py
>>> Entry.objects.all()[:5]

```

这将返回第六到第十个对象（`OFFSET 5 LIMIT 5`）：

```py
>>> Entry.objects.all()[5:10]

```

不支持负索引（即`Entry.objects.all()[-1]`）。

通常，对`QuerySet`进行切片会返回一个新的`QuerySet`-它不会评估查询。一个例外是如果您使用 Python 切片语法的步长参数。例如，这实际上会执行查询，以返回前 10 个对象中每*第二个*对象的列表：

```py
>>> Entry.objects.all()[:10:2]

```

要检索*单个*对象而不是列表（例如，`SELECT foo FROM bar LIMIT 1`），请使用简单的索引而不是切片。

例如，这将按标题字母顺序返回数据库中的第一个`Entry`：

```py
>>> Entry.objects.order_by('headline')[0]

```

这大致相当于：

```py
>>> Entry.objects.order_by('headline')[0:1].get()

```

但是请注意，如果没有对象符合给定的条件，第一个将引发`IndexError`，而第二个将引发`DoesNotExist`。有关更多详细信息，请参见`get()`。

## 字段查找

字段查找是指定 SQL `WHERE`子句的主要方式。它们被指定为`QuerySet`方法`filter()`、`exclude()`和`get()`的关键字参数。（这是一个双下划线）。例如：

```py
>>> Entry.objects.filter(pub_date__lte='2006-01-01')

```

翻译（大致）成以下 SQL：

```py
SELECT * FROM blog_entry WHERE pub_date <= '2006-01-01';

```

查找中指定的字段必须是模型字段的名称。不过有一个例外，在`ForeignKey`的情况下，可以指定带有`_id`后缀的字段名。在这种情况下，值参数预期包含外键模型主键的原始值。例如：

```py
>>> Entry.objects.filter(blog_id=4)

```

如果传递了无效的关键字参数，查找函数将引发`TypeError`。

字段查找的完整列表如下：

+   `精确的`

+   `忽略大小写的精确的`

+   `包含`

+   `包含`

+   `在…中`

+   `大于`

+   `大于或等于`

+   `小于`

+   `小于或等于`

+   `以…开头`

+   `以…开头`

+   `以…结尾`

+   `以…结尾`

+   `范围`

+   `年`

+   `月`

+   `天`

+   `星期几`

+   `小时`

+   `分钟`

+   `秒`

+   `为空`

+   `搜索`

+   `正则表达式`

+   `iregex`

可以在字段查找参考中找到每个字段查找的完整参考和示例[`docs.djangoproject.com/en/1.8/ref/models/querysets/#field-lookups`](https://docs.djangoproject.com/en/1.8/ref/models/querysets/#field-lookups)。

## 跨关系的查找

Django 提供了一种强大且直观的方式来在查找中跟踪关系，自动在幕后为您处理 SQL `JOIN`。要跨越关系，只需使用跨模型的相关字段的字段名称，用双下划线分隔，直到您找到想要的字段。

这个例子检索所有`name`为`'Beatles Blog'`的`Blog`对象的`Entry`对象：

```py
>>> Entry.objects.filter(blog__name='Beatles Blog')

```

这种跨度可以深入到您想要的程度。

它也可以反向操作。要引用反向关系，只需使用模型的小写名称。

这个例子检索所有至少有一个`Entry`的`headline`包含`'Lennon'`的`Blog`对象：

```py
>>> Blog.objects.filter(entry__headline__contains='Lennon')

```

如果您在多个关系中进行过滤，并且中间模型之一没有满足过滤条件的值，Django 将把它视为一个空（所有值都为`NULL`），但有效的对象。这只意味着不会引发错误。例如，在这个过滤器中：

```py
Blog.objects.filter(entry__authors__name='Lennon') 

```

（如果有一个相关的`Author`模型），如果一个条目没有与作者相关联，它将被视为没有附加名称，而不是因为缺少作者而引发错误。通常这正是您希望发生的。唯一可能令人困惑的情况是如果您使用`isnull`。因此：

```py
Blog.objects.filter(entry__authors__name__isnull=True) 

```

将返回在`author`上有一个空的`name`的`Blog`对象，以及在`entry`上有一个空的`author`的`Blog`对象。如果您不想要后者的对象，您可以这样写：

```py
Blog.objects.filter(entry__authors__isnull=False, 
        entry__authors__name__isnull=True) 

```

### 跨多值关系

当您基于`ManyToManyField`或反向`ForeignKey`对对象进行过滤时，可能会对两种不同类型的过滤感兴趣。考虑`Blog`/`Entry`关系（`Blog`到`Entry`是一对多关系）。我们可能对找到有一个条目既在标题中有`Lennon`又在 2008 年发布的博客感兴趣。

或者我们可能想要找到博客中有一个标题中带有`Lennon`的条目以及一个在 2008 年发布的条目。由于一个`Blog`关联多个条目，这两个查询都是可能的，并且在某些情况下是有意义的。

与`ManyToManyField`相同类型的情况也会出现。例如，如果`Entry`有一个名为`tags`的`ManyToManyField`，我们可能想要找到链接到名称为`music`和`bands`的标签的条目，或者我们可能想要一个包含名称为`music`和状态为`public`的标签的条目。

为了处理这两种情况，Django 有一种一致的处理`filter()`和`exclude()`调用的方式。单个`filter()`调用中的所有内容同时应用于过滤掉符合所有这些要求的项目。

连续的`filter()`调用进一步限制对象集，但对于多值关系，它们适用于与主要模型链接的任何对象，不一定是由先前的`filter()`调用选择的对象。

这可能听起来有点混乱，所以希望通过一个例子来澄清。要选择包含标题中都有`Lennon`并且在 2008 年发布的条目的所有博客（同时满足这两个条件的相同条目），我们将写：

```py
Blog.objects.filter(entry__headline__contains='Lennon',
        entry__pub_date__year=2008) 

```

要选择包含标题中有`Lennon`的条目以及 2008 年发布的条目的所有博客，我们将写：

```py
Blog.objects.filter(entry__headline__contains='Lennon').filter(
        entry__pub_date__year=2008) 

```

假设只有一个博客既包含`Lennon`的条目，又包含 2008 年的条目，但 2008 年的条目中没有包含`Lennon`。第一个查询将不会返回任何博客，但第二个查询将返回那一个博客。

在第二个例子中，第一个过滤器将查询集限制为所有链接到标题中有`Lennon`的条目的博客。第二个过滤器将进一步将博客集限制为那些还链接到 2008 年发布的条目的博客。

第二个过滤器选择的条目可能与第一个过滤器中的条目相同，也可能不同。我们正在使用每个过滤器语句过滤`Blog`项，而不是`Entry`项。

所有这些行为也适用于`exclude()`：单个`exclude()`语句中的所有条件都适用于单个实例（如果这些条件涉及相同的多值关系）。后续`filter()`或`exclude()`调用中涉及相同关系的条件可能最终会过滤不同的链接对象。

## 过滤器可以引用模型上的字段

到目前为止给出的例子中，我们已经构建了比较模型字段值与常量的过滤器。但是，如果您想要比较模型字段的值与同一模型上的另一个字段呢？

Django 提供了`F 表达式`来允许这样的比较。`F()`的实例充当查询中模型字段的引用。然后可以在查询过滤器中使用这些引用来比较同一模型实例上两个不同字段的值。

例如，要查找所有博客条目中评论比 pingbacks 多的条目列表，我们构建一个`F()`对象来引用 pingback 计数，并在查询中使用该`F()`对象：

```py
>>> from django.db.models import F
>>> Entry.objects.filter(n_comments__gt=F('n_pingbacks'))

```

Django 支持使用`F()`对象进行加法、减法、乘法、除法、取模和幂运算，既可以与常量一起使用，也可以与其他`F()`对象一起使用。要查找所有评论比 pingbacks 多*两倍*的博客条目，我们修改查询：

```py
>>> Entry.objects.filter(n_comments__gt=F('n_pingbacks') * 2)

```

要查找所有评分小于 pingback 计数和评论计数之和的条目，我们将发出查询：

```py
>>> Entry.objects.filter(rating__lt=F('n_comments') + F('n_pingbacks'))

```

您还可以使用双下划线符号来跨越`F()`对象中的关系。带有双下划线的`F()`对象将引入访问相关对象所需的任何连接。

例如，要检索所有作者名称与博客名称相同的条目，我们可以发出查询：

```py
>>> Entry.objects.filter(authors__name=F('blog__name'))

```

对于日期和日期/时间字段，您可以添加或减去一个`timedelta`对象。以下将返回所有在发布后 3 天以上修改的条目：

```py
>>> from datetime import timedelta
>>> Entry.objects.filter(mod_date__gt=F('pub_date') + timedelta(days=3))

```

`F()`对象支持按位操作，通过`.bitand()`和`.bitor()`，例如：

```py
>>> F('somefield').bitand(16)

```

## pk 查找快捷方式

为了方便起见，Django 提供了一个`pk`查找快捷方式，代表主键。

在示例`Blog`模型中，主键是`id`字段，因此这三个语句是等价的：

```py
>>> Blog.objects.get(id__exact=14) # Explicit form
>>> Blog.objects.get(id=14) # __exact is implied
>>> Blog.objects.get(pk=14) # pk implies id__exact

```

`pk`的使用不限于`__exact`查询-任何查询条件都可以与`pk`组合，以对模型的主键执行查询：

```py
# Get blogs entries with id 1, 4 and 7
>>> Blog.objects.filter(pk__in=[1,4,7])
# Get all blog entries with id > 14
>>> Blog.objects.filter(pk__gt=14)

```

`pk`查找也适用于连接。例如，这三个语句是等价的：

```py
>>> Entry.objects.filter(blog__id__exact=3) # Explicit form
>>> Entry.objects.filter(blog__id=3)        # __exact is implied
>>> Entry.objects.filter(blog__pk=3)        # __pk implies __id__exact

```

## 在 LIKE 语句中转义百分号和下划线

等同于`LIKE` SQL 语句的字段查找（`iexact`，`contains`，`icontains`，`startswith`，`istartswith`，`endswith`和`iendswith`）将自动转义`LIKE`语句中使用的两个特殊字符-百分号和下划线。（在`LIKE`语句中，百分号表示多字符通配符，下划线表示单字符通配符。）

这意味着事情应该直观地工作，所以抽象不会泄漏。例如，要检索包含百分号的所有条目，只需像对待其他字符一样使用百分号：

```py
>>> Entry.objects.filter(headline__contains='%')

```

Django 会为您处理引用；生成的 SQL 将类似于这样：

```py
SELECT ... WHERE headline LIKE '%\%%';

```

下划线也是一样。百分号和下划线都会被透明地处理。

## 缓存和查询集

每个`QuerySet`都包含一个缓存，以最小化数据库访问。了解它的工作原理将使您能够编写最有效的代码。

在新创建的`QuerySet`中，缓存是空的。第一次评估`QuerySet`时-因此，数据库查询发生时-Django 会将查询结果保存在`QuerySet`类的缓存中，并返回已经明确请求的结果（例如，如果正在迭代`QuerySet`，则返回下一个元素）。后续的`QuerySet`评估将重用缓存的结果。

请记住这种缓存行为，因为如果您没有正确使用您的`QuerySet`，它可能会给您带来麻烦。例如，以下操作将创建两个`QuerySet`，对它们进行评估，然后丢弃它们：

```py
>>> print([e.headline for e in Entry.objects.all()])
>>> print([e.pub_date for e in Entry.objects.all()])

```

这意味着相同的数据库查询将被执行两次，有效地增加了数据库负载。此外，两个列表可能不包括相同的数据库记录，因为在两个请求之间的瞬间，可能已经添加或删除了`Entry`。

为了避免这个问题，只需保存`QuerySet`并重复使用它：

```py
>>> queryset = Entry.objects.all()
>>> print([p.headline for p in queryset]) # Evaluate the query set.
>>> print([p.pub_date for p in queryset]) # Re-use the cache from the evaluation.

```

### 当查询集没有被缓存时

查询集并不总是缓存它们的结果。当仅评估查询集的*部分*时，会检查缓存，但如果它没有被填充，那么后续查询返回的项目将不会被缓存。具体来说，这意味着使用数组切片或索引限制查询集将不会填充缓存。

例如，重复获取查询集对象中的某个索引将每次查询数据库：

```py
>>> queryset = Entry.objects.all()
>>> print queryset[5] # Queries the database
>>> print queryset[5] # Queries the database again

```

然而，如果整个查询集已经被评估，那么将检查缓存：

```py
>>> queryset = Entry.objects.all()
>>> [entry for entry in queryset] # Queries the database
>>> print queryset[5] # Uses cache
>>> print queryset[5] # Uses cache

```

以下是一些其他操作的例子，这些操作将导致整个查询集被评估，因此填充缓存：

```py
>>> [entry for entry in queryset]
>>> bool(queryset)
>>> entry in queryset
>>> list(queryset)

```

# 使用 Q 对象进行复杂的查找

关键字参数查询-在`filter()`和其他地方-会被 AND 在一起。如果您需要执行更复杂的查询（例如带有`OR`语句的查询），您可以使用`Q 对象`。

`Q 对象`（`django.db.models.Q`）是一个用于封装一组关键字参数的对象。这些关键字参数如上面的字段查找中所指定的那样。

例如，这个`Q`对象封装了一个单一的`LIKE`查询：

```py
from django.db.models import Q 
Q(question__startswith='What') 

```

`Q`对象可以使用`&`和`|`运算符进行组合。当两个`Q`对象上使用运算符时，它会产生一个新的`Q`对象。

例如，这个语句产生一个代表两个`"question__startswith"`查询的 OR 的单个`Q`对象：

```py
Q(question__startswith='Who') | Q(question__startswith='What') 

```

这等同于以下 SQL `WHERE`子句：

```py
WHERE question LIKE 'Who%' OR question LIKE 'What%'

```

您可以通过使用`&`和`|`运算符组合`Q`对象并使用括号分组来组成任意复杂的语句。此外，`Q`对象可以使用`~`运算符进行否定，从而允许组合查找结合了正常查询和否定（`NOT`）查询：

```py
Q(question__startswith='Who') | ~Q(pub_date__year=2005) 

```

每个接受关键字参数的查找函数（例如`filter()`、`exclude()`、`get()`）也可以作为位置（非命名）参数传递一个或多个`Q`对象。如果向查找函数提供多个`Q`对象参数，则这些参数将被 AND 在一起。例如：

```py
Poll.objects.get( 
    Q(question__startswith='Who'), 
    Q(pub_date=date(2005, 5, 2)) | Q(pub_date=date(2005, 5, 6)) 
) 

```

...大致翻译成 SQL：

```py
SELECT * from polls WHERE question LIKE 'Who%'
 AND (pub_date = '2005-05-02' OR pub_date = '2005-05-06')

```

查找函数可以混合使用`Q`对象和关键字参数。提供给查找函数的所有参数（无论是关键字参数还是`Q`对象）都会被 AND 在一起。但是，如果提供了`Q`对象，它必须在任何关键字参数的定义之前。例如：

```py
Poll.objects.get( 
    Q(pub_date=date(2005, 5, 2)) | Q(pub_date=date(2005, 5, 6)), 
    question__startswith='Who') 

```

...将是一个有效的查询，等同于前面的示例；但是：

```py
# INVALID QUERY 
Poll.objects.get( 
    question__startswith='Who', 
    Q(pub_date=date(2005, 5, 2)) | Q(pub_date=date(2005, 5, 6))) 

```

...将无效。

# 比较对象

要比较两个模型实例，只需使用标准的 Python 比较运算符，双等号：`==`。在幕后，这比较了两个模型的主键值。

使用上面的`Entry`示例，以下两个语句是等价的：

```py
>>> some_entry == other_entry
>>> some_entry.id == other_entry.id

```

如果模型的主键不叫`id`，没问题。比较将始终使用主键，无论它叫什么。例如，如果模型的主键字段叫`name`，这两个语句是等价的：

```py
>>> some_obj == other_obj
>>> some_obj.name == other_obj.name

```

# 删除对象

方便地，删除方法被命名为`delete()`。此方法立即删除对象，并且没有返回值。例如：

```py
e.delete() 

```

您还可以批量删除对象。每个`QuerySet`都有一个`delete()`方法，用于删除该`QuerySet`的所有成员。

例如，这将删除所有`pub_date`年份为 2005 的`Entry`对象：

```py
Entry.objects.filter(pub_date__year=2005).delete() 

```

请记住，这将在可能的情况下纯粹在 SQL 中执行，因此在过程中不一定会调用单个对象实例的`delete()`方法。如果您在模型类上提供了自定义的`delete()`方法，并希望确保它被调用，您将需要手动删除该模型的实例（例如，通过迭代`QuerySet`并在每个对象上调用`delete()`）而不是使用`QuerySet`的批量`delete()`方法。

当 Django 删除一个对象时，默认情况下会模拟 SQL 约束`ON DELETE CASCADE`的行为-换句话说，任何具有指向要删除的对象的外键的对象都将与其一起被删除。例如：

```py
b = Blog.objects.get(pk=1) 
# This will delete the Blog and all of its Entry objects. 
b.delete() 

```

此级联行为可以通过`ForeignKey`的`on_delete`参数进行自定义。

请注意，`delete()`是唯一不在`Manager`本身上公开的`QuerySet`方法。这是一个安全机制，可以防止您意外请求`Entry.objects.delete()`，并删除*所有*条目。如果*确实*要删除所有对象，则必须显式请求完整的查询集：

```py
Entry.objects.all().delete() 

```

# 复制模型实例

虽然没有内置的方法来复制模型实例，但可以轻松地创建具有所有字段值的新实例。在最简单的情况下，您可以将`pk`设置为`None`。使用我们的博客示例：

```py
blog = Blog(name='My blog', tagline='Blogging is easy') 
blog.save() # blog.pk == 1 

blog.pk = None 
blog.save() # blog.pk == 2 

```

如果使用继承，情况会变得更加复杂。考虑`Blog`的子类：

```py
class ThemeBlog(Blog): 
    theme = models.CharField(max_length=200) 

django_blog = ThemeBlog(name='Django', tagline='Django is easy',
  theme='python') 
django_blog.save() # django_blog.pk == 3 

```

由于继承的工作原理，您必须将`pk`和`id`都设置为 None：

```py
django_blog.pk = None 
django_blog.id = None 
django_blog.save() # django_blog.pk == 4 

```

此过程不会复制相关对象。如果要复制关系，您需要编写更多的代码。在我们的示例中，`Entry`有一个到`Author`的多对多字段：

```py
entry = Entry.objects.all()[0] # some previous entry 
old_authors = entry.authors.all() 
entry.pk = None 
entry.save() 
entry.authors = old_authors # saves new many2many relations 

```

# 一次更新多个对象

有时，您希望为`QuerySet`中的所有对象设置一个特定的值。您可以使用`update()`方法来实现这一点。例如：

```py
# Update all the headlines with pub_date in 2007.
Entry.objects.filter(pub_date__year=2007).update(headline='Everything is the same')

```

您只能使用此方法设置非关系字段和`ForeignKey`字段。要更新非关系字段，请将新值提供为常量。要更新`ForeignKey`字段，请将新值设置为要指向的新模型实例。例如：

```py
>>> b = Blog.objects.get(pk=1)
# Change every Entry so that it belongs to this Blog.
>>> Entry.objects.all().update(blog=b)

```

`update()`方法会立即应用，并返回查询匹配的行数（如果某些行已经具有新值，则可能不等于更新的行数）。

更新的`QuerySet`的唯一限制是它只能访问一个数据库表，即模型的主表。您可以基于相关字段进行过滤，但只能更新模型主表中的列。例如：

```py
>>> b = Blog.objects.get(pk=1)
# Update all the headlines belonging to this Blog.
>>> Entry.objects.select_related().filter(blog=b).update
(headline='Everything is the same')

```

请注意，`update()`方法会直接转换为 SQL 语句。这是一个用于直接更新的批量操作。它不会运行任何模型的`save()`方法，也不会发出`pre_save`或`post_save`信号（这是调用`save()`的结果），也不会遵守`auto_now`字段选项。如果您想保存`QuerySet`中的每个项目，并确保在每个实例上调用`save()`方法，您不需要任何特殊的函数来处理。只需循环遍历它们并调用`save()`：

```py
for item in my_queryset: 
    item.save() 

```

对更新的调用也可以使用`F 表达式`来根据模型中另一个字段的值更新一个字段。这对于根据其当前值递增计数器特别有用。例如，要为博客中的每个条目递增 pingback 计数：

```py
>>> Entry.objects.all().update(n_pingbacks=F('n_pingbacks') + 1)

```

但是，与在过滤和排除子句中使用`F()`对象不同，当您在更新中使用`F()`对象时，您不能引入连接-您只能引用要更新的模型本地字段。如果尝试使用`F()`对象引入连接，将引发`FieldError`：

```py
# THIS WILL RAISE A FieldError
>>> Entry.objects.update(headline=F('blog__name'))

```

# 相关对象

当您在模型中定义关系（即`ForeignKey`、`OneToOneField`或`ManyToManyField`）时，该模型的实例将具有便捷的 API 来访问相关对象。

使用本页顶部的模型，例如，`Entry`对象`e`可以通过访问`blog`属性获取其关联的`Blog`对象：`e.blog`。

（在幕后，这个功能是由 Python 描述符实现的。这对您来说并不重要，但我在这里指出它是为了满足好奇心。）

Django 还为关系的另一侧创建了 API 访问器-从相关模型到定义关系的模型的链接。例如，`Blog`对象`b`通过`entry_set`属性可以访问所有相关的`Entry`对象的列表：`b.entry_set.all()`。

本节中的所有示例都使用本页顶部定义的示例`Blog`、`Author`和`Entry`模型。

## 一对多关系

### 前向

如果模型具有`ForeignKey`，则该模型的实例将可以通过模型的简单属性访问相关（外键）对象。例如：

```py
>>> e = Entry.objects.get(id=2)
>>> e.blog # Returns the related Blog object.

```

您可以通过外键属性进行获取和设置。正如您可能期望的那样，对外键的更改直到调用`save()`之前都不会保存到数据库。例如：

```py
>>> e = Entry.objects.get(id=2)
>>> e.blog = some_blog
>>> e.save()

```

如果`ForeignKey`字段设置了`null=True`（即允许`NULL`值），则可以分配`None`来删除关系。例如：

```py
>>> e = Entry.objects.get(id=2)
>>> e.blog = None
>>> e.save() # "UPDATE blog_entry SET blog_id = NULL ...;"

```

第一次访问相关对象时，可以缓存对一对多关系的前向访问。对同一对象实例上的外键的后续访问将被缓存。例如：

```py
>>> e = Entry.objects.get(id=2)
>>> print(e.blog)  # Hits the database to retrieve the associated Blog.
>>> print(e.blog)  # Doesn't hit the database; uses cached version.

```

请注意，`select_related()` `QuerySet` 方法会预先递归填充所有一对多关系的缓存。例如：

```py
>>> e = Entry.objects.select_related().get(id=2)
>>> print(e.blog)  # Doesn't hit the database; uses cached version.
>>> print(e.blog)  # Doesn't hit the database; uses cached version.

```

### 向后跟踪关系

如果模型具有`ForeignKey`，则外键模型的实例将可以访问返回第一个模型的所有实例的`Manager`。默认情况下，此`Manager`命名为`foo_set`，其中`foo`是源模型名称的小写形式。此`Manager`返回`QuerySets`，可以像上面的检索对象部分中描述的那样进行过滤和操作。

例如：

```py
>>> b = Blog.objects.get(id=1)
>>> b.entry_set.all() # Returns all Entry objects related to Blog.
# b.entry_set is a Manager that returns QuerySets.
>>> b.entry_set.filter(headline__contains='Lennon')
>>> b.entry_set.count()

```

您可以通过在`ForeignKey`定义中设置`related_name`参数来覆盖`foo_set`名称。例如，如果`Entry`模型被修改为`blog = ForeignKey(Blog, related_name='entries')`，上面的示例代码将如下所示：

```py
>>> b = Blog.objects.get(id=1)
>>> b.entries.all() # Returns all Entry objects related to Blog.
# b.entries is a Manager that returns QuerySets.
>>> b.entries.filter(headline__contains='Lennon')
>>> b.entries.count()

```

### 使用自定义反向管理器

默认情况下，用于反向关系的`RelatedManager`是该模型的默认管理器的子类。如果您想为给定查询指定不同的管理器，可以使用以下语法：

```py
from django.db import models 

class Entry(models.Model): 
    #... 
    objects = models.Manager()  # Default Manager 
    entries = EntryManager()    # Custom Manager 

b = Blog.objects.get(id=1) 
b.entry_set(manager='entries').all() 

```

如果`EntryManager`在其`get_queryset()`方法中执行默认过滤，则该过滤将应用于`all()`调用。

当然，指定自定义的反向管理器也使您能够调用其自定义方法：

```py
b.entry_set(manager='entries').is_published() 

```

### 处理相关对象的附加方法

除了之前*检索对象*中定义的`QuerySet`方法之外，`ForeignKey` `Manager`还有其他用于处理相关对象集合的方法。每个方法的概要如下（完整详情可以在相关对象参考中找到[`docs.djangoproject.com/en/1.8/ref/models/relations/#related-objects-reference`](https://docs.djangoproject.com/en/1.8/ref/models/relations/#related-objects-reference)）：

+   `add(obj1, obj2, ...)` 将指定的模型对象添加到相关对象集合

+   `create(**kwargs)` 创建一个新对象，保存它并将其放入相关对象集合中。返回新创建的对象

+   `remove(obj1, obj2, ...)` 从相关对象集合中删除指定的模型对象

+   `clear()` 从相关对象集合中删除所有对象

+   `set(objs)` 替换相关对象的集合

要一次性分配相关集合的成员，只需从任何可迭代对象中分配给它。可迭代对象可以包含对象实例，也可以只是主键值的列表。例如：

```py
b = Blog.objects.get(id=1) 
b.entry_set = [e1, e2] 

```

在这个例子中，`e1`和`e2`可以是完整的 Entry 实例，也可以是整数主键值。

如果`clear()`方法可用，那么在将可迭代对象（在本例中是一个列表）中的所有对象添加到集合之前，`entry_set`中的任何现有对象都将被移除。如果`clear()`方法*不*可用，则将添加可迭代对象中的所有对象，而不会移除任何现有元素。

本节中描述的每个反向操作都会立即对数据库产生影响。每次添加、创建和删除都会立即自动保存到数据库中。

## 多对多关系

多对多关系的两端都自动获得对另一端的 API 访问权限。API 的工作方式与上面的反向一对多关系完全相同。

唯一的区别在于属性命名：定义`ManyToManyField`的模型使用该字段本身的属性名称，而反向模型使用原始模型的小写模型名称，再加上`'_set'`（就像反向一对多关系一样）。

一个例子可以更容易理解：

```py
e = Entry.objects.get(id=3) 
e.authors.all() # Returns all Author objects for this Entry. 
e.authors.count() 
e.authors.filter(name__contains='John') 

a = Author.objects.get(id=5) 
a.entry_set.all() # Returns all Entry objects for this Author. 

```

与`ForeignKey`一样，`ManyToManyField`可以指定`related_name`。在上面的例子中，如果`Entry`中的`ManyToManyField`指定了`related_name='entries'`，那么每个`Author`实例将具有一个`entries`属性，而不是`entry_set`。

## 一对一关系

一对一关系与多对一关系非常相似。如果在模型上定义了`OneToOneField`，那么该模型的实例将通过模型的简单属性访问相关对象。

例如：

```py
class EntryDetail(models.Model): 
    entry = models.OneToOneField(Entry) 
    details = models.TextField() 

ed = EntryDetail.objects.get(id=2) 
ed.entry # Returns the related Entry object. 

```

不同之处在于反向查询。一对一关系中的相关模型也可以访问`Manager`对象，但该`Manager`代表单个对象，而不是一组对象：

```py
e = Entry.objects.get(id=2) 
e.entrydetail # returns the related EntryDetail object 

```

如果没有对象分配给这个关系，Django 将引发`DoesNotExist`异常。

实例可以被分配到反向关系，就像你分配正向关系一样：

```py
e.entrydetail = ed 

```

## 涉及相关对象的查询

涉及相关对象的查询遵循涉及正常值字段的查询相同的规则。在指定要匹配的查询值时，您可以使用对象实例本身，也可以使用对象的主键值。

例如，如果您有一个`id=5`的 Blog 对象`b`，那么以下三个查询将是相同的：

```py
Entry.objects.filter(blog=b) # Query using object instance 
Entry.objects.filter(blog=b.id) # Query using id from instance 
Entry.objects.filter(blog=5) # Query using id directly 

```

# 回退到原始 SQL

如果你发现自己需要编写一个对 Django 的数据库映射器处理过于复杂的 SQL 查询，你可以回退到手动编写 SQL。

最后，重要的是要注意，Django 数据库层只是与您的数据库交互的接口。您可以通过其他工具、编程语言或数据库框架访问您的数据库；您的数据库与 Django 无关。
