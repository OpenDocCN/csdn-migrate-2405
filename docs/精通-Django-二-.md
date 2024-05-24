# 精通 Django（二）

> 原文：[`zh.annas-archive.org/md5/0D7AA9BDBF4A402F69CD832FB5D17FA6`](https://zh.annas-archive.org/md5/0D7AA9BDBF4A402F69CD832FB5D17FA6)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：模型

在第二章*视图和 URLconfs*中，我们介绍了使用 Django 构建动态网站的基础知识：设置视图和 URLconfs。正如我们所解释的，视图负责执行一些任意逻辑，然后返回一个响应。在其中一个示例中，我们的任意逻辑是计算当前日期和时间。

在现代 Web 应用程序中，任意逻辑通常涉及与数据库的交互。在幕后，一个数据库驱动的网站连接到数据库服务器，从中检索一些数据，并在网页上显示这些数据。该网站还可能提供访问者自行填充数据库的方式。

许多复杂的网站提供了这两种方式的组合。例如，[www.amazon.com](http://www.amazon.com)就是一个数据库驱动的网站的绝佳例子。每个产品页面本质上都是对亚马逊产品数据库的查询，格式化为 HTML，当您发布客户评论时，它会被插入到评论数据库中。

Django 非常适合制作数据库驱动的网站，因为它提供了使用 Python 执行数据库查询的简单而强大的工具。本章解释了这个功能：Django 的数据库层。

### 注意

虽然不是必须要了解基本的关系数据库理论和 SQL 才能使用 Django 的数据库层，但强烈建议这样做。这本书不涉及这些概念的介绍，但即使你是数据库新手，继续阅读也是有可能跟上并理解基于上下文的概念。

# 在视图中进行数据库查询的“愚蠢”方法

正如第二章*视图和 URLconfs*中详细介绍了在视图中生成输出的“愚蠢”方法（通过在视图中直接硬编码文本），在视图中从数据库中检索数据也有一个“愚蠢”的方法。很简单：只需使用任何现有的 Python 库来执行 SQL 查询并对结果进行处理。在这个示例视图中，我们使用`MySQLdb`库连接到 MySQL 数据库，检索一些记录，并将它们传递给模板以在网页上显示：

```py
from django.shortcuts import render 
import MySQLdb 

def book_list(request): 
    db = MySQLdb.connect(user='me', db='mydb',  passwd='secret', host='localhost') 
    cursor = db.cursor() 
    cursor.execute('SELECT name FROM books ORDER BY name') 
    names = [row[0] for row in cursor.fetchall()] 
    db.close() 
    return render(request, 'book_list.html', {'names': names}) 

```

这种方法可以工作，但是一些问题应该立即引起您的注意：

+   我们在硬编码数据库连接参数。理想情况下，这些参数应该存储在 Django 配置中。

+   我们不得不写相当多的样板代码：创建连接，创建游标，执行语句，关闭连接。理想情况下，我们只需要指定我们想要的结果。

+   它将我们与 MySQL 绑定。如果将来我们从 MySQL 切换到 PostgreSQL，我们很可能需要重写大量代码。理想情况下，我们使用的数据库服务器应该被抽象化，这样数据库服务器的更改可以在一个地方进行。 （如果您正在构建一个希望尽可能多的人使用的开源 Django 应用程序，这个功能尤其重要。）

正如您所期望的，Django 的数据库层解决了这些问题。

# 配置数据库

考虑到所有这些理念，让我们开始探索 Django 的数据库层。首先，让我们探索在创建应用程序时添加到`settings.py`的初始配置。

```py
# Database 
#  
DATABASES = { 
    'default': { 
        'ENGINE': 'django.db.backends.sqlite3', 
        'NAME': os.path.join(BASE_DIR, 'db.sqlite3'), 
    } 
} 

```

默认设置非常简单。以下是每个设置的概述。

+   `ENGINE`：它告诉 Django 使用哪个数据库引擎。在本书的示例中，我们使用 SQLite，所以将其保留为默认的`django.db.backends.sqlite3`。

+   `NAME`：它告诉 Django 你的数据库的名称。例如：`'NAME': 'mydb',`。

由于我们使用的是 SQLite，`startproject`为我们创建了数据库文件的完整文件系统路径。

这就是默认设置-你不需要改变任何东西来运行本书中的代码，我包含这个只是为了让你了解在 Django 中配置数据库是多么简单。有关如何设置 Django 支持的各种数据库的详细描述，请参见第二十一章, *高级数据库管理*。

# 你的第一个应用程序

现在你已经验证了连接是否正常工作，是时候创建一个**Django 应用程序**了-一个包含模型和视图的 Django 代码包，它们一起存在于一个单独的 Python 包中，代表一个完整的 Django 应用程序。这里值得解释一下术语，因为这往往会让初学者困惑。我们已经在第一章中创建了一个项目，*Django 简介和入门*，那么**项目**和**应用程序**之间有什么区别呢？区别在于配置和代码：

+   项目是一组 Django 应用程序的实例，以及这些应用程序的配置。从技术上讲，项目的唯一要求是提供一个设置文件，其中定义了数据库连接信息、已安装应用程序的列表、`DIRS`等。

+   应用程序是一组可移植的 Django 功能，通常包括模型和视图，它们一起存在于一个单独的 Python 包中。

例如，Django 自带了许多应用程序，比如自动管理界面。关于这些应用程序的一个关键点是它们是可移植的，可以在多个项目中重复使用。

关于如何将 Django 代码适应这个方案，几乎没有硬性规定。如果你正在构建一个简单的网站，可能只使用一个应用程序。如果你正在构建一个包括电子商务系统和留言板等多个不相关部分的复杂网站，你可能希望将它们拆分成单独的应用程序，以便将来可以单独重用它们。

事实上，你并不一定需要创建应用程序，正如我们在本书中迄今为止创建的示例视图函数所证明的那样。在这些情况下，我们只需创建一个名为`views.py`的文件，填充它以视图函数，并将我们的 URLconf 指向这些函数。不需要应用程序。

然而，关于应用程序约定有一个要求：如果你正在使用 Django 的数据库层（模型），你必须创建一个 Django 应用程序。模型必须存在于应用程序中。因此，为了开始编写我们的模型，我们需要创建一个新的应用程序。

在`mysite`项目目录中（这是你的`manage.py`文件所在的目录，而不是`mysite`应用程序目录），输入以下命令来创建一个`books`应用程序：

```py
python manage.py startapp books

```

这个命令不会产生任何输出，但它会在`mysite`目录中创建一个`books`目录。让我们看看该目录的内容：

```py
books/ 
    /migrations 
    __init__.py 
    admin.py 
    models.py 
    tests.py 
    views.py 

```

这些文件将包含此应用程序的模型和视图。在你喜欢的文本编辑器中查看`models.py`和`views.py`。这两个文件都是空的，除了注释和`models.py`中的导入。这是你的 Django 应用程序的空白板。

# 在 Python 中定义模型

正如我们在第一章中讨论的那样，MTV 中的 M 代表模型。Django 模型是对数据库中数据的描述，表示为 Python 代码。它是你的数据布局-相当于你的 SQL `CREATE TABLE`语句-只不过它是用 Python 而不是 SQL 编写的，并且包括的不仅仅是数据库列定义。

Django 使用模型在后台执行 SQL 代码，并返回表示数据库表中行的方便的 Python 数据结构。Django 还使用模型来表示 SQL 不能必然处理的更高级概念。

如果你熟悉数据库，你可能会立刻想到，“在 Python 中定义数据模型而不是在 SQL 中定义，这不是多余的吗？” Django 之所以采用这种方式有几个原因：

+   内省需要额外开销，而且并不完美。为了提供方便的数据访问 API，Django 需要以某种方式了解数据库布局，有两种方法可以实现这一点。第一种方法是在 Python 中明确描述数据，第二种方法是在运行时内省数据库以确定数据模型。

+   这第二种方法看起来更干净，因为关于你的表的元数据只存在一个地方，但它引入了一些问题。首先，在运行时内省数据库显然需要开销。如果框架每次处理请求时，甚至只在 Web 服务器初始化时都需要内省数据库，这将产生无法接受的开销。（虽然有些人认为这种开销是可以接受的，但 Django 的开发人员的目标是尽量减少框架的开销。）其次，一些数据库，特别是较旧版本的 MySQL，没有存储足够的元数据来进行准确和完整的内省。

+   编写 Python 很有趣，而且将所有东西都放在 Python 中可以减少你的大脑进行“上下文切换”的次数。如果你尽可能长时间地保持在一个编程环境/思维方式中，这有助于提高生产率。不得不先写 SQL，然后写 Python，再写 SQL 是会打断思维的。

+   将数据模型存储为代码而不是在数据库中，可以更容易地将模型纳入版本控制。这样，你可以轻松跟踪对数据布局的更改。

+   SQL 只允许对数据布局进行一定级别的元数据。例如，大多数数据库系统并没有提供专门的数据类型来表示电子邮件地址或 URL。但 Django 模型有。更高级别的数据类型的优势在于更高的生产率和更可重用的代码。

+   SQL 在不同的数据库平台上是不一致的。例如，如果你要分发一个网络应用程序，更实际的做法是分发一个描述数据布局的 Python 模块，而不是针对 MySQL、PostgreSQL 和 SQLite 分别创建`CREATE TABLE`语句的集合。

然而，这种方法的一个缺点是，Python 代码可能与实际数据库中的内容不同步。如果你对 Django 模型进行更改，你需要在数据库内做相同的更改，以保持数据库与模型一致。在本章后面讨论迁移时，我将向你展示如何处理这个问题。

最后，你应该注意到 Django 包括一个实用程序，可以通过内省现有数据库来生成模型。这对于快速启动和运行遗留数据非常有用。我们将在第二十一章中介绍这个内容，*高级数据库管理*。

## 你的第一个模型

作为本章和下一章的一个持续的例子，我将专注于一个基本的书籍/作者/出版商数据布局。我选择这个作为例子，因为书籍、作者和出版商之间的概念关系是众所周知的，这是初级 SQL 教科书中常用的数据布局。你也正在阅读一本由作者撰写并由出版商出版的书籍！

我假设以下概念、字段和关系：

+   作者有名字、姓氏和电子邮件地址。

+   出版商有一个名称、街道地址、城市、州/省、国家和网站。

+   一本书有一个标题和出版日期。它还有一个或多个作者（与作者之间是多对多的关系）和一个出版商（一对多的关系，也就是外键到出版商）。

在 Django 中使用这个数据库布局的第一步是将其表达为 Python 代码。在由`startapp`命令创建的`models.py`文件中输入以下内容：

```py
from django.db import models 

class Publisher(models.Model): 
    name = models.CharField(max_length=30) 
    address = models.CharField(max_length=50) 
    city = models.CharField(max_length=60) 
    state_province = models.CharField(max_length=30) 
    country = models.CharField(max_length=50) 
    website = models.URLField() 

class Author(models.Model): 
    first_name = models.CharField(max_length=30) 
    last_name = models.CharField(max_length=40) 
    email = models.EmailField() 

class Book(models.Model): 
    title = models.CharField(max_length=100) 
    authors = models.ManyToManyField(Author) 
    publisher = models.ForeignKey(Publisher) 
    publication_date = models.DateField() 

```

让我们快速检查这段代码，以涵盖基础知识。首先要注意的是，每个模型都由一个 Python 类表示，该类是`django.db.models.Model`的子类。父类`Model`包含使这些对象能够与数据库交互所需的所有机制，这样我们的模型就只负责以一种简洁而紧凑的语法定义它们的字段。

信不信由你，这就是我们需要编写的所有代码，就可以使用 Django 进行基本的数据访问。每个模型通常对应一个单独的数据库表，模型上的每个属性通常对应该数据库表中的一列。属性名称对应于列的名称，字段类型（例如，`CharField`）对应于数据库列类型（例如，`varchar`）。例如，`Publisher`模型等效于以下表（假设使用 PostgreSQL 的`CREATE TABLE`语法）：

```py
CREATE TABLE "books_publisher" ( 
    "id" serial NOT NULL PRIMARY KEY, 
    "name" varchar(30) NOT NULL, 
    "address" varchar(50) NOT NULL, 
    "city" varchar(60) NOT NULL, 
    "state_province" varchar(30) NOT NULL, 
    "country" varchar(50) NOT NULL, 
    "website" varchar(200) NOT NULL 
); 

```

事实上，Django 可以自动生成`CREATE TABLE`语句，我们将在下一刻向您展示。一个类对应一个数据库表的唯一规则的例外是多对多关系的情况。在我们的示例模型中，`Book`有一个名为`authors`的`ManyToManyField`。这表示一本书有一个或多个作者，但`Book`数据库表不会得到一个`authors`列。相反，Django 会创建一个额外的表-一个多对多的*连接表*-来处理书籍到作者的映射。

对于字段类型和模型语法选项的完整列表，请参见附录 B, *数据库 API 参考*。最后，请注意，我们没有在任何这些模型中明确定义主键。除非您另有指示，否则 Django 会自动为每个模型提供一个自增的整数主键字段，称为`id`。每个 Django 模型都需要有一个单列主键。

## 安装模型

我们已经编写了代码；现在让我们在数据库中创建表。为了做到这一点，第一步是在我们的 Django 项目中激活这些模型。我们通过将`books`应用程序添加到设置文件中的已安装应用程序列表中来实现这一点。再次编辑`settings.py`文件，并查找`INSTALLED_APPS`设置。`INSTALLED_APPS`告诉 Django 为给定项目激活了哪些应用程序。默认情况下，它看起来像这样：

```py
INSTALLED_APPS = ( 
'django.contrib.admin', 
'django.contrib.auth', 
'django.contrib.contenttypes', 
'django.contrib.sessions', 
'django.contrib.messages', 
'django.contrib.staticfiles', 
) 

```

要注册我们的`books`应用程序，请将`'books'`添加到`INSTALLED_APPS`中，以便设置最终看起来像这样（`'books'`指的是我们正在使用的`books`应用程序）：

```py
INSTALLED_APPS = ( 
'django.contrib.admin', 
'django.contrib.auth', 
'django.contrib.contenttypes', 
'django.contrib.sessions', 
'django.contrib.messages', 
'django.contrib.staticfiles', 
'books', 
) 

```

`INSTALLED_APPS`中的每个应用程序都由其完整的 Python 路径表示-即，由点分隔的导致应用程序包的路径。现在 Django 应用程序已在设置文件中激活，我们可以在数据库中创建数据库表。首先，让我们通过运行此命令来验证模型：

```py
python manage.py check

```

`check`命令运行 Django 系统检查框架-一组用于验证 Django 项目的静态检查。如果一切正常，您将看到消息`System check identified no issues (0 silenced)`。如果没有，请确保您正确输入了模型代码。错误输出应该为您提供有关代码错误的有用信息。每当您认为模型存在问题时，请运行`python manage.py check`。它往往会捕捉到所有常见的模型问题。

如果您的模型有效，请运行以下命令告诉 Django 您对模型进行了一些更改（在本例中，您创建了一个新模型）：

```py
python manage.py makemigrations books 

```

您应该看到类似以下内容的东西：

```py
Migrations for 'books': 
  0001_initial.py: 
   -Create model Author 
   -Create model Book 
   -Create model Publisher 
   -Add field publisher to book 

```

迁移是 Django 存储对模型的更改（因此是数据库模式）的方式-它们只是磁盘上的文件。在这种情况下，您将在`books`应用程序的`migrations`文件夹中找到名为`0001_initial.py`的文件。`migrate`命令将获取您的最新迁移文件并自动更新您的数据库模式，但首先让我们看看该迁移将运行的 SQL。`sqlmigrate`命令获取迁移名称并返回它们的 SQL：

```py
python manage.py sqlmigrate books 0001

```

你应该看到类似以下的内容（为了可读性重新格式化）：

```py
BEGIN; 

CREATE TABLE "books_author" ( 
    "id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, 
    "first_name" varchar(30) NOT NULL, 
    "last_name" varchar(40) NOT NULL, 
    "email" varchar(254) NOT NULL 
); 
CREATE TABLE "books_book" ( 
    "id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, 
    "title" varchar(100) NOT NULL, 
    "publication_date" date NOT NULL 
); 
CREATE TABLE "books_book_authors" ( 
    "id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, 
    "book_id" integer NOT NULL REFERENCES "books_book" ("id"), 
    "author_id" integer NOT NULL REFERENCES "books_author" ("id"), 
    UNIQUE ("book_id", "author_id") 
); 
CREATE TABLE "books_publisher" ( 
    "id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, 
    "name" varchar(30) NOT NULL, 
    "address" varchar(50) NOT NULL, 
    "city" varchar(60) NOT NULL, 
    "state_province" varchar(30) NOT NULL, 
    "country" varchar(50) NOT NULL, 
    "website" varchar(200) NOT NULL 
); 
CREATE TABLE "books_book__new" ( 
    "id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, 
    "title" varchar(100) NOT NULL, 
    "publication_date" date NOT NULL, 
    "publisher_id" integer NOT NULL REFERENCES 
    "books_publisher" ("id") 
); 

INSERT INTO "books_book__new" ("id", "publisher_id", "title", 
"publication_date") SELECT "id", NULL, "title", "publication_date" FROM 
"books_book"; 

DROP TABLE "books_book"; 

ALTER TABLE "books_book__new" RENAME TO "books_book"; 

CREATE INDEX "books_book_2604cbea" ON "books_book" ("publisher_id"); 

COMMIT; 

```

请注意以下内容：

+   表名是通过组合应用程序的名称（`books`）和模型的小写名称（`publisher`，`book`和`author`）自动生成的。你可以覆盖这种行为，详细信息请参见附录 B，*数据库 API 参考*。

+   正如我们之前提到的，Django 会自动为每个表添加一个主键-`id`字段。你也可以覆盖这一点。按照惯例，Django 会将`"_id"`附加到外键字段名称。你可能已经猜到，你也可以覆盖这种行为。

+   外键关系通过`REFERENCES`语句明确表示。

这些`CREATE TABLE`语句是针对你正在使用的数据库定制的，因此数据库特定的字段类型，如`auto_increment`（MySQL），`serial`（PostgreSQL）或`integer primary key`（SQLite）都会自动处理。列名的引用也是一样的（例如，使用双引号或单引号）。这个示例输出是以 PostgreSQL 语法为例。

`sqlmigrate`命令实际上并不会创建表或者对数据库进行任何操作，它只是在屏幕上打印输出，这样你就可以看到如果要求 Django 执行的 SQL 是什么。如果你愿意，你可以将这些 SQL 复制粘贴到你的数据库客户端中，然而，Django 提供了一个更简单的方法将 SQL 提交到数据库：`migrate`命令：

```py
python manage.py migrate

```

运行该命令，你会看到类似以下的内容：

```py
Operations to perform:
 Apply all migrations: books
Running migrations:
 Rendering model states... DONE
 # ...
 Applying books.0001_initial... OK
 # ...

```

如果你想知道所有这些额外的内容是什么（在上面被注释掉的），第一次运行 migrate 时，Django 还会创建 Django 内置应用所需的所有系统表。迁移是 Django 传播你对模型所做更改（添加字段、删除模型等）到数据库模式的方式。它们被设计为大部分是自动的，但是也有一些注意事项。有关迁移的更多信息，请参见第二十一章，*高级数据库管理*。

# 基本数据访问

一旦你创建了一个模型，Django 会自动为这些模型提供一个高级别的 Python API。通过运行`python manage.py shell`并输入以下内容来尝试一下：

```py
>>> from books.models import Publisher 
>>> p1 = Publisher(name='Apress', address='2855 Telegraph Avenue', 
...     city='Berkeley', state_province='CA', country='U.S.A.', 
...     website='http://www.apress.com/') 
>>> p1.save() 
>>> p2 = Publisher(name="O'Reilly", address='10 Fawcett St.', 
...     city='Cambridge', state_province='MA', country='U.S.A.', 
...     website='http://www.oreilly.com/') 
>>> p2.save() 
>>> publisher_list = Publisher.objects.all() 
>>> publisher_list 
[<Publisher: Publisher object>, <Publisher: Publisher object>] 

```

这几行代码完成了很多事情。以下是重点：

+   首先，我们导入我们的`Publisher`模型类。这让我们可以与包含出版商的数据库表进行交互。

+   我们通过为每个字段实例化一个`Publisher`对象来创建一个`Publisher`对象-`name`，`address`等等。

+   要将对象保存到数据库中，请调用其`save()`方法。在幕后，Django 在这里执行了一个 SQL `INSERT`语句。

+   要从数据库中检索出出版商，使用属性`Publisher.objects`，你可以将其视为所有出版商的集合。使用语句`Publisher.objects.all()`获取数据库中所有`Publisher`对象的列表。在幕后，Django 在这里执行了一个 SQL `SELECT`语句。

有一件事值得一提，以防这个例子没有清楚地表明。当你使用 Django 模型 API 创建对象时，Django 不会将对象保存到数据库，直到你调用`save()`方法：

```py
p1 = Publisher(...) 
# At this point, p1 is not saved to the database yet! 
p1.save() 
# Now it is. 

```

如果你想要在一步中创建一个对象并将其保存到数据库中，可以使用`objects.create()`方法。这个例子等同于上面的例子：

```py
>>> p1 = Publisher.objects.create(name='Apress', 
...     address='2855 Telegraph Avenue', 
...     city='Berkeley', state_province='CA', country='U.S.A.', 
...     website='http://www.apress.com/') 
>>> p2 = Publisher.objects.create(name="O'Reilly", 
...     address='10 Fawcett St.', city='Cambridge', 
...     state_province='MA', country='U.S.A.', 
...     website='http://www.oreilly.com/') 
>>> publisher_list = Publisher.objects.all() 
>>> publisher_list 
[<Publisher: Publisher object>, <Publisher: Publisher object>] 

```

当然，你可以使用 Django 数据库 API 做很多事情，但首先，让我们解决一个小烦恼。

## 添加模型字符串表示

当我们打印出出版商列表时，我们得到的只是这种不太有用的显示，这使得很难区分`Publisher`对象：

```py
[<Publisher: Publisher object>, <Publisher: Publisher object>] 

```

我们可以通过在`Publisher`类中添加一个名为`__str__()`的方法来轻松解决这个问题。`__str__()`方法告诉 Python 如何显示对象的可读表示。通过为这三个模型添加`__str__()`方法，你可以看到它的作用。

```py
from django.db import models 

class Publisher(models.Model): 
    name = models.CharField(max_length=30) 
    address = models.CharField(max_length=50) 
    city = models.CharField(max_length=60) 
    state_province = models.CharField(max_length=30) 
    country = models.CharField(max_length=50) 
    website = models.URLField() 

 def __str__(self): 
 return self.name 

class Author(models.Model): 
    first_name = models.CharField(max_length=30) 
    last_name = models.CharField(max_length=40) 
    email = models.EmailField() 

 def __str__(self):
 return u'%s %s' % 
                                (self.first_name, self.last_name) 

class Book(models.Model): 
    title = models.CharField(max_length=100) 
    authors = models.ManyToManyField(Author) 
    publisher = models.ForeignKey(Publisher) 
    publication_date = models.DateField() 

 def __str__(self):
 return self.title

```

如您所见，`__str__()`方法可以根据需要执行任何操作，以返回对象的表示。在这里，`Publisher`和`Book`的`__str__()`方法分别返回对象的名称和标题，但`Author`的`__str__()`方法稍微复杂一些-它将`first_name`和`last_name`字段拼接在一起，用空格分隔。`__str__()`的唯一要求是返回一个字符串对象。如果`__str__()`没有返回一个字符串对象-如果它返回了一个整数-那么 Python 将引发一个类似于以下的`TypeError`消息：

```py
TypeError: __str__ returned non-string (type int). 

```

要使`__str__()`的更改生效，请退出 Python shell，然后使用`python manage.py shell`再次进入。 （这是使代码更改生效的最简单方法。）现在`Publisher`对象的列表更容易理解了：

```py
>>> from books.models import Publisher 
>>> publisher_list = Publisher.objects.all() 
>>> publisher_list 
[<Publisher: Apress>, <Publisher: O'Reilly>] 

```

确保您定义的任何模型都有一个`__str__()`方法-不仅是为了在使用交互式解释器时方便您自己，而且还因为 Django 在需要显示对象时使用`__str__()`的输出。最后，请注意，`__str__()`是向模型添加行为的一个很好的例子。Django 模型描述了对象的数据库表布局，还描述了对象知道如何执行的任何功能。`__str__()`就是这种功能的一个例子-模型知道如何显示自己。

## 插入和更新数据

您已经看到了这个操作：要向数据库插入一行数据，首先使用关键字参数创建模型的实例，如下所示：

```py
>>> p = Publisher(name='Apress', 
...         address='2855 Telegraph Ave.', 
...         city='Berkeley', 
...         state_province='CA', 
...         country='U.S.A.', 
...         website='http://www.apress.com/') 

```

正如我们上面所指出的，实例化模型类的行为并不会触及数据库。直到您调用`save()`，记录才会保存到数据库中，就像这样：

```py
>>> p.save() 

```

在 SQL 中，这大致可以翻译为以下内容：

```py
INSERT INTO books_publisher 
    (name, address, city, state_province, country, website) 
VALUES 
    ('Apress', '2855 Telegraph Ave.', 'Berkeley', 'CA', 
     'U.S.A.', 'http://www.apress.com/'); 

```

因为`Publisher`模型使用自增主键`id`，对`save()`的初始调用还做了一件事：它计算了记录的主键值，并将其设置为实例的`id`属性：

```py
>>> p.id 
52    # this will differ based on your own data 

```

对`save()`的后续调用将在原地保存记录，而不是创建新记录（即执行 SQL 的`UPDATE`语句而不是`INSERT`）：

```py
>>> p.name = 'Apress Publishing' 
>>> p.save() 

```

前面的`save()`语句将导致大致以下的 SQL：

```py
UPDATE books_publisher SET 
    name = 'Apress Publishing', 
    address = '2855 Telegraph Ave.', 
    city = 'Berkeley', 
    state_province = 'CA', 
    country = 'U.S.A.', 
    website = 'http://www.apress.com' 
WHERE id = 52; 

```

是的，请注意，所有字段都将被更新，而不仅仅是已更改的字段。根据您的应用程序，这可能会导致竞争条件。请参阅下面的*在一条语句中更新多个对象*，了解如何执行这个（略有不同）查询：

```py
UPDATE books_publisher SET 
    name = 'Apress Publishing' 
WHERE id=52; 

```

## 选择对象

了解如何创建和更新数据库记录是至关重要的，但很有可能您构建的 Web 应用程序将更多地查询现有对象，而不是创建新对象。我们已经看到了检索给定模型的每条记录的方法：

```py
>>> Publisher.objects.all() 
[<Publisher: Apress>, <Publisher: O'Reilly>] 

```

这大致对应于以下 SQL：

```py
SELECT id, name, address, city, state_province, country, website 
FROM books_publisher; 

```

### 注意

请注意，Django 在查找数据时不使用`SELECT *`，而是明确列出所有字段。这是有意设计的：在某些情况下，`SELECT *`可能会更慢，并且（更重要的是）列出字段更贴近 Python 之禅的一个原则：*明确胜于隐晦*。有关 Python 之禅的更多信息，请尝试在 Python 提示符下输入`import this`。

让我们仔细看看`Publisher.objects.all()`这行的每个部分：

+   首先，我们有我们定义的模型`Publisher`。这里没有什么意外：当您想要查找数据时，您使用该数据的模型。

+   接下来，我们有`objects`属性。这被称为**管理器**。管理器在第九章*高级模型*中有详细讨论。现在，您需要知道的是，管理器负责处理数据的所有*表级*操作，包括最重要的数据查找。所有模型都会自动获得一个`objects`管理器；每当您想要查找模型实例时，都会使用它。

+   最后，我们有`all()`。这是`objects`管理器上的一个方法，它返回数据库中的所有行。虽然这个对象看起来像一个列表，但它实际上是一个**QuerySet**-一个表示数据库中特定一组行的对象。附录 C，*通用视图参考*，详细介绍了 QuerySets。在本章的其余部分，我们将把它们当作它们模拟的列表来处理。

任何数据库查找都会遵循这个一般模式-我们将在我们想要查询的模型上调用附加的管理器的方法。

## 过滤数据

自然地，很少有人希望一次从数据库中选择所有内容；在大多数情况下，您将希望处理您数据的一个子集。在 Django API 中，您可以使用`filter()`方法过滤您的数据：

```py
>>> Publisher.objects.filter(name='Apress') 
[<Publisher: Apress>] 

```

`filter()`接受关键字参数，这些参数被转换为适当的 SQL `WHERE`子句。前面的例子将被转换为类似于这样的东西：

```py
SELECT id, name, address, city, state_province, country, website 
FROM books_publisher 
WHERE name = 'Apress'; 

```

您可以将多个参数传递给`filter()`以进一步缩小范围：

```py
>>> Publisher.objects.filter(country="U.S.A.", state_province="CA") 
[<Publisher: Apress>] 

```

这些多个参数被转换为 SQL `AND`子句。因此，代码片段中的示例被转换为以下内容：

```py
SELECT id, name, address, city, state_province, country, website 
FROM books_publisher 
WHERE country = 'U.S.A.' 
AND state_province = 'CA'; 

```

请注意，默认情况下，查找使用 SQL `=`运算符进行精确匹配查找。其他查找类型也是可用的：

```py
>>> Publisher.objects.filter(name__contains="press") 
[<Publisher: Apress>] 

```

在`name`和`contains`之间有一个双下划线。像 Python 本身一样，Django 使用双下划线来表示发生了一些魔术-这里，`__contains`部分被 Django 转换为 SQL `LIKE`语句：

```py
SELECT id, name, address, city, state_province, country, website 
FROM books_publisher 
WHERE name LIKE '%press%'; 

```

还有许多其他类型的查找可用，包括`icontains`（不区分大小写的`LIKE`）、`startswith`和`endswith`，以及`range`（SQL `BETWEEN`查询）。附录 C，*通用视图参考*，详细描述了所有这些查找类型。

## 检索单个对象

上面的所有`filter()`示例都返回了一个`QuerySet`，您可以像对待列表一样对待它。有时，只获取单个对象比获取列表更方便。这就是`get()`方法的用途：

```py
>>> Publisher.objects.get(name="Apress") 
<Publisher: Apress> 

```

而不是返回一个列表（`QuerySet`），只返回一个单一对象。因此，导致多个对象的查询将引发异常：

```py
>>> Publisher.objects.get(country="U.S.A.") 
Traceback (most recent call last): 
    ... 
MultipleObjectsReturned: get() returned more than one Publisher -- it returned 2! Lookup parameters were {'country': 'U.S.A.'} 

```

返回没有对象的查询也会引发异常：

```py
>>> Publisher.objects.get(name="Penguin") 
Traceback (most recent call last): 
    ... 
DoesNotExist: Publisher matching query does not exist. 

```

`DoesNotExist`异常是模型类`Publisher.DoesNotExist`的属性。在您的应用程序中，您将希望捕获这些异常，就像这样：

```py
try: 
    p = Publisher.objects.get(name='Apress') 
except Publisher.DoesNotExist: 
    print ("Apress isn't in the database yet.") 
else: 
    print ("Apress is in the database.") 

```

## 排序数据

当您尝试之前的示例时，您可能会发现对象以看似随机的顺序返回。您没有想象的事情；到目前为止，我们还没有告诉数据库如何对其结果进行排序，因此我们只是以数据库选择的某种任意顺序返回数据。在您的 Django 应用程序中，您可能希望根据某个值-比如按字母顺序-对结果进行排序。要做到这一点，请使用`order_by()`方法：

```py
>>> Publisher.objects.order_by("name") 
[<Publisher: Apress>, <Publisher: O'Reilly>] 

```

这看起来与之前的`all()`示例没有太大不同，但是现在的 SQL 包括了特定的排序：

```py
SELECT id, name, address, city, state_province, country, website 
FROM books_publisher 
ORDER BY name; 

```

您可以按任何您喜欢的字段排序：

```py
>>> Publisher.objects.order_by("address") 
 [<Publisher: O'Reilly>, <Publisher: Apress>] 

>>> Publisher.objects.order_by("state_province") 
 [<Publisher: Apress>, <Publisher: O'Reilly>] 

```

要按多个字段排序（其中第二个字段用于消除第一个字段相同时的排序），请使用多个参数：

```py
>>> Publisher.objects.order_by("state_province", "address") 
 [<Publisher: Apress>, <Publisher: O'Reilly>] 

```

您还可以通过在字段名前加上“-”（减号）来指定反向排序：

```py
>>> Publisher.objects.order_by("-name") 
[<Publisher: O'Reilly>, <Publisher: Apress>] 

```

虽然这种灵活性很有用，但是一直使用`order_by()`可能会相当重复。大多数情况下，您通常会有一个特定的字段，您希望按照它进行排序。在这些情况下，Django 允许您在模型中指定默认排序：

```py
class Publisher(models.Model): 
    name = models.CharField(max_length=30) 
    address = models.CharField(max_length=50) 
    city = models.CharField(max_length=60) 
    state_province = models.CharField(max_length=30) 
    country = models.CharField(max_length=50) 
    website = models.URLField() 

    def __str__(self): 
        return self.name 

    class Meta:
 ordering = ['name']

```

在这里，我们介绍了一个新概念：`class Meta`，它是嵌入在`Publisher`类定义中的类（也就是说，它是缩进在`class Publisher`内部的）。您可以在任何模型上使用这个`Meta`类来指定各种特定于模型的选项。`Meta`选项的完整参考可在附录 B 中找到，但现在我们关注的是排序选项。如果您指定了这个选项，它告诉 Django，除非使用`order_by()`明确给出排序，否则所有`Publisher`对象在使用 Django 数据库 API 检索时都应该按`name`字段排序。

## 链接查找

您已经看到了如何过滤数据，也看到了如何对其进行排序。当然，通常情况下，您需要同时做这两件事。在这些情况下，您只需将查找链接在一起：

```py
>>> Publisher.objects.filter(country="U.S.A.").order_by("-name") 
[<Publisher: O'Reilly>, <Publisher: Apress>] 

```

正如您所期望的，这会转换为一个同时具有`WHERE`和`ORDER BY`的 SQL 查询：

```py
SELECT id, name, address, city, state_province, country, website 
FROM books_publisher 
WHERE country = 'U.S.A' 
ORDER BY name DESC; 

```

## 切片数据

另一个常见的需求是仅查找固定数量的行。想象一下，您的数据库中有成千上万的出版商，但您只想显示第一个。您可以使用 Python 的标准列表切片语法来实现：

```py
>>> Publisher.objects.order_by('name')[0] 
<Publisher: Apress> 

```

这大致对应于：

```py
SELECT id, name, address, city, state_province, country, website 
FROM books_publisher 
ORDER BY name 
LIMIT 1; 

```

类似地，您可以使用 Python 的范围切片语法检索特定的数据子集：

```py
>>> Publisher.objects.order_by('name')[0:2] 

```

这返回两个对象，大致翻译为：

```py
SELECT id, name, address, city, state_province, country, website 
FROM books_publisher 
ORDER BY name 
OFFSET 0 LIMIT 2; 

```

请注意，不支持负切片：

```py
>>> Publisher.objects.order_by('name')[-1] 
Traceback (most recent call last): 
  ... 
AssertionError: Negative indexing is not supported. 

```

不过，这很容易解决。只需更改`order_by()`语句，就像这样：

```py
>>> Publisher.objects.order_by('-name')[0] 

```

## 在一个语句中更新多个对象

我们在*插入和更新数据*部分指出，模型`save()`方法会更新行中的所有列。根据您的应用程序，您可能只想更新部分列。例如，假设我们要更新 Apress `Publisher`将名称从`'Apress'`更改为`'Apress Publishing'`。使用`save()`，它看起来会像这样：

```py
>>> p = Publisher.objects.get(name='Apress') 
>>> p.name = 'Apress Publishing' 
>>> p.save() 

```

这大致对应以下 SQL：

```py
SELECT id, name, address, city, state_province, country, website 
FROM books_publisher 
WHERE name = 'Apress'; 

UPDATE books_publisher SET 
    name = 'Apress Publishing', 
    address = '2855 Telegraph Ave.', 
    city = 'Berkeley', 
    state_province = 'CA', 
    country = 'U.S.A.', 
    website = 'http://www.apress.com' 
WHERE id = 52; 

```

（请注意，此示例假定 Apress 的出版商 ID 为`52`。）您可以在此示例中看到，Django 的`save()`方法设置了所有列的值，而不仅仅是`name`列。如果您处于其他列可能由于其他进程而发生变化的环境中，最好只更改您需要更改的列。要做到这一点，请在`QuerySet`对象上使用`update()`方法。以下是一个例子：

```py
>>> Publisher.objects.filter(id=52).update(name='Apress Publishing') 

```

这里的 SQL 转换效率更高，没有竞争条件的机会：

```py
UPDATE books_publisher 
SET name = 'Apress Publishing' 
WHERE id = 52; 

```

`update()`方法适用于任何`QuerySet`，这意味着您可以批量编辑多条记录。以下是您可能如何更改每个`Publisher`记录中的`country`从`'U.S.A.'`更改为`USA`：

```py
>>> Publisher.objects.all().update(country='USA') 
2 

```

`update()`方法有一个返回值-表示更改了多少条记录的整数。在上面的例子中，我们得到了`2`。

## 删除对象

要从数据库中删除对象，只需调用对象的`delete()`方法：

```py
>>> p = Publisher.objects.get(name="O'Reilly") 
>>> p.delete() 
>>> Publisher.objects.all() 
[<Publisher: Apress Publishing>] 

```

您还可以通过在任何`QuerySet`的结果上调用`delete()`来批量删除对象。这类似于我们在上一节中展示的`update()`方法：

```py
>>> Publisher.objects.filter(country='USA').delete() 
>>> Publisher.objects.all().delete() 
>>> Publisher.objects.all() 
[] 

```

小心删除您的数据！为了防止删除特定表中的所有数据，Django 要求您明确使用`all()`，如果要删除表中的所有内容。例如，这样是行不通的：

```py
>>> Publisher.objects.delete() 
Traceback (most recent call last): 
  File "", line 1, in  
AttributeError: 'Manager' object has no attribute 'delete' 

```

但如果添加`all()`方法，它将起作用：

```py
>>> Publisher.objects.all().delete() 

```

如果您只是删除数据的一个子集，您不需要包括`all()`。重复之前的例子：

```py
>>> Publisher.objects.filter(country='USA').delete() 

```

# 接下来是什么？

阅读完本章后，您已经掌握了足够的 Django 模型知识，可以编写基本的数据库应用程序。第九章，“高级模型”，将提供有关 Django 数据库层更高级用法的一些信息。一旦您定义了模型，下一步就是向数据库填充数据。您可能有遗留数据，这种情况下第二十一章，“高级数据库管理”，将为您提供有关与遗留数据库集成的建议。您可能依赖站点用户提供数据，这种情况下第六章，“表单”，将教您如何处理用户提交的表单数据。但在某些情况下，您或您的团队可能需要手动输入数据，这种情况下拥有一个基于 Web 的界面来输入和管理数据将非常有帮助。下一章将介绍 Django 的管理界面，它正是为了这个目的而存在的。


# 第五章：Django 管理站点

对于大多数现代网站，**管理界面**是基础设施的一个重要部分。这是一个基于 web 的界面，仅限于受信任的站点管理员，它使得可以添加、编辑和删除站点内容。一些常见的例子：你用来发布博客的界面，后端站点管理员用来审核用户生成的评论的界面，你的客户用来更新你为他们建立的网站上的新闻稿的工具。

不过，管理界面存在一个问题：构建它们很无聊。当你开发面向公众的功能时，web 开发是很有趣的，但构建管理界面总是一样的。你必须验证用户、显示和处理表单、验证输入等等。这很无聊，也很重复。

那么 Django 对于这些无聊、重复的任务的处理方式是什么呢？它会为你处理一切。

使用 Django，构建管理界面是一个已解决的问题。在本章中，我们将探索 Django 的自动管理界面：看看它如何为我们的模型提供方便的界面，以及我们可以用它做的一些其他有用的事情。

# 使用管理站点

当你在第一章中运行了`django-admin startproject mysite`时，Django 为你创建并配置了默认的管理站点。你所需要做的就是创建一个管理用户（超级用户），然后你就可以登录管理站点了。

### 注意

如果你使用的是 Visual Studio，你不需要在命令行中完成下一步，你可以直接在 Visual Studio 的**项目**菜单选项卡中添加一个超级用户。

要创建一个管理用户，运行以下命令：

```py
python manage.py createsuperuser

```

输入你想要的用户名并按回车。

```py
Username: admin

```

然后你将被提示输入你想要的电子邮件地址：

```py
Email address: admin@example.com

```

最后一步是输入密码。你将被要求两次输入密码，第二次是对第一次的确认。

```py
Password: **********
Password (again): *********
Superuser created successfully.

```

## 启动开发服务器

在 Django 1.8 中，默认情况下激活了 django 管理站点。让我们启动开发服务器并进行探索。回想一下之前的章节，你可以这样启动开发服务器：

```py
python manage.py runserver

```

现在，打开一个网页浏览器，转到本地域的`/admin/`，例如，`http://127.0.0.1:8000/admin/`。你应该会看到管理员的登录界面（*图 5.1*）。

由于默认情况下已经启用了翻译，登录界面可能会显示为你自己的语言，这取决于你的浏览器设置以及 Django 是否为这种语言提供了翻译。

## 进入管理站点

现在，尝试使用你在上一步中创建的超级用户账户登录。你应该会看到**Django 管理员**首页（*图 5.2*）。

你应该会看到两种可编辑的内容：组和用户。它们由`django.contrib.auth`提供，这是 Django 提供的身份验证框架。管理站点旨在供非技术用户使用，因此它应该相当容易理解。尽管如此，我们还是会快速介绍一下基本功能。

![进入管理站点](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/ms-dj/img/image_05_001.jpg)

图 5.1：**Django 管理员**登录界面

![进入管理站点](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/ms-dj/img/image_05_002.jpg)

图 5.2：**Django 管理员**首页

Django 管理站点中的每种数据都有一个更改列表和一个编辑表单。更改列表会显示数据库中所有可用的对象，而编辑表单则允许你添加、更改或删除数据库中的特定记录。点击**用户**行中的**更改**链接，加载用户的更改列表页面（*图 5.3*）。

![进入管理站点](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/ms-dj/img/image_05_003.jpg)

图 5.3：用户更改列表页面

这个页面显示了数据库中的所有用户；您可以将其视为`SELECT * FROM auth_user;` SQL 查询的网页版本。如果您正在跟随我们的示例，假设您只看到一个用户，那么一旦您有了更多的用户，您可能会发现过滤、排序和搜索选项很有用。

过滤选项在右侧，点击列标题可进行排序，顶部的搜索框可让您按用户名搜索。点击您创建的用户的用户名，您将看到该用户的编辑表单（*图 5.4*）。

这个页面允许您更改用户的属性，比如名字和各种权限。请注意，要更改用户的密码，您应该点击密码字段下的**更改密码表单**，而不是编辑哈希代码。

另一个需要注意的是，不同类型的字段会得到不同的小部件-例如，日期/时间字段有日历控件，布尔字段有复选框，字符字段有简单的文本输入字段。

![进入管理站点](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/ms-dj/img/image_05_004.jpg)

图 5.4：用户编辑表单

您可以通过在其编辑表单的左下角点击删除按钮来删除记录。这将带您到一个确认页面，在某些情况下，它将显示将被删除的任何相关对象（例如，如果您删除一个出版商，那么任何与该出版商有关的书籍也将被删除！）

您可以通过在管理主页的适当列中点击**添加**来添加记录。这将为您提供一个空白版本的编辑页面，准备让您填写。

您还会注意到，管理界面还为您处理输入验证。尝试将必填字段留空或在日期字段中输入无效日期，当您尝试保存时，您将看到这些错误，就像*图 5.5*中显示的那样。

当您编辑现有对象时，您会注意到窗口右上角有一个“历史”链接。通过管理界面进行的每一次更改都会被记录下来，您可以通过单击“历史”链接来查看这个日志（见*图 5.6*）。

![进入管理站点](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/ms-dj/img/image_05_005.jpg)

图 5.5：显示错误的编辑表单

![进入管理站点](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/ms-dj/img/image_05_006.jpg)

图 5.6：对象历史页面

### 注意

**管理站点的工作原理**

在幕后，管理站点是如何工作的？这相当简单。当 Django 在服务器启动时加载时，它会运行`admin.autodiscover()`函数。在 Django 的早期版本中，您需要从`urls.py`中调用这个函数，但现在 Django 会自动运行它。这个函数会遍历您的`INSTALLED_APPS`设置，并在每个已安装的应用程序中查找名为`admin.py`的文件。如果给定的应用程序中存在`admin.py`，它将执行该文件中的代码。

在我们的`books`应用程序的`admin.py`中，每次调用`admin.site.register()`都会简单地向管理站点注册给定的模型。管理站点只会为已经明确注册的模型显示编辑/更改界面。应用程序`django.contrib.auth`包括自己的`admin.py`，这就是为什么用户和组自动显示在管理中的原因。其他`django.contrib`应用程序，比如`django.contrib.redirects`，也会将自己添加到管理中，许多您从网上下载的第三方 Django 应用程序也会这样做。

除此之外，Django 管理站点只是一个 Django 应用程序，有自己的模型、模板、视图和 URLpatterns。您可以通过将其连接到您的 URLconf 来将其添加到您的应用程序中，就像您连接自己的视图一样。您可以在 Django 代码库的`django/contrib/admin`中查看其模板、视图和 URLpatterns，但不要尝试直接更改其中的任何内容，因为有很多钩子可以让您自定义管理站点的工作方式。

如果您决定在 Django 管理应用程序中进行探索，请记住，它在读取有关模型的元数据时会执行一些相当复杂的操作，因此可能需要大量时间来阅读和理解代码。

# 将您的模型添加到管理站点

有一个至关重要的部分我们还没有做。让我们将我们自己的模型添加到管理站点，这样我们就可以使用这个不错的界面向我们的自定义数据库表中添加、更改和删除对象。我们将继续第四章 *模型*中的`books`示例，我们在其中定义了三个模型：出版商、作者和书籍。在`books`目录（`mysite/books`）中，如果`startapp`没有创建一个名为`admin.py`的文件，那么您可以自己创建一个，并输入以下代码：

```py
from django.contrib import admin 
from .models import Publisher, Author, Book 

admin.site.register(Publisher) 
admin.site.register(Author) 
admin.site.register(Book) 

```

这段代码告诉 Django 管理站点为每个模型提供界面。完成后，转到您的网页浏览器中的管理主页（`http://127.0.0.1:8000/admin/`），您应该会看到一个**Books**部分，其中包含有关作者、书籍和出版商的链接。（您可能需要停止并重新启动开发服务器以使更改生效。）现在，您已经为这三个模型中的每一个拥有了一个完全功能的管理界面。这很容易！

花一些时间添加和更改记录，用一些数据填充您的数据库。如果您遵循第四章 *模型*，创建`Publisher`对象的示例（并且您没有删除它们），您已经可以在出版商更改列表页面上看到这些记录了。

这里值得一提的一个功能是管理站点对外键和多对多关系的处理，这两者都出现在`Book`模型中。作为提醒，这是`Book`模型的样子：

```py
class Book(models.Model): 
    title = models.CharField(max_length=100) 
    authors = models.ManyToManyField(Author) 
    publisher = models.ForeignKey(Publisher) 
    publication_date = models.DateField() 

    def __str__(self): 
        return self.title 

```

在 Django 管理站点的**添加书籍**页面（`http://127.0.0.1:8000/admin/books/book/add/`）

出版商（`ForeignKey`）由一个下拉框表示，作者字段（`ManyToManyField`）由一个多选框表示。这两个字段旁边有一个绿色加号图标，让您可以添加相关类型的记录。

例如，如果您点击**出版商**字段旁边的绿色加号，您将会得到一个弹出窗口，让您可以添加一个出版商。在弹出窗口中成功创建出版商后，**添加书籍**表单将会更新，显示新创建的出版商。很棒。

# 使字段变为可选

在管理站点玩一段时间后，您可能会注意到一个限制-编辑表单要求填写每个字段，而在许多情况下，您可能希望某些字段是可选的。例如，我们希望`Author`模型的`email`字段是可选的-也就是说，允许空字符串。在现实世界中，您可能并不为每个作者都有电子邮件地址。

要指定`email`字段是可选的，请编辑`Author`模型（正如您从第四章 *模型*中记得的那样，它位于`mysite/books/models.py`中）。只需向`email`字段添加`blank=True`，如下所示：

```py
class Author(models.Model): 
    first_name = models.CharField(max_length=30) 
    last_name = models.CharField(max_length=40) 
    email = models.EmailField(blank=True)

```

这段代码告诉 Django 空值确实允许作者的电子邮件地址。默认情况下，所有字段都具有`blank=False`，这意味着不允许空值。

这里发生了一些有趣的事情。到目前为止，除了`__str__()`方法之外，我们的模型一直作为数据库表的定义-基本上是 SQL `CREATE TABLE`语句的 Python 表达式。通过添加`blank=True`，我们已经开始扩展我们的模型，超出了对数据库表的简单定义。

现在，我们的模型类开始成为关于`Author`对象是什么以及它们能做什么的更丰富的知识集合。`email`字段不仅在数据库中表示为`VARCHAR`列；在诸如 Django 管理站点之类的上下文中，它也是一个可选字段。

一旦添加了`blank=True`，重新加载**添加作者**编辑表单（`http://127.0.0.1:8000/admin/books/author/add/`），您会注意到字段的标签-**电子邮件**-不再是粗体。这表示它不是必填字段。现在您可以添加作者而无需提供电子邮件地址；如果字段提交为空，您将不再收到响亮的红色**此字段是必填的**消息。

## 使日期和数字字段变为可选

与`blank=True`相关的一个常见陷阱与日期和数字字段有关，但它需要相当多的背景解释。SQL 有自己指定空值的方式-一个称为`NULL`的特殊值。`NULL`可能意味着“未知”、“无效”或其他一些特定于应用程序的含义。在 SQL 中，`NULL`的值与空字符串不同，就像特殊的 Python 对象`None`与空的 Python 字符串（`""`）不同。

这意味着特定字符字段（例如`VARCHAR`列）可以包含`NULL`值和空字符串值。这可能会导致不必要的歧义和混淆：为什么这条记录有一个`NULL`，而另一条记录有一个空字符串？有区别吗，还是数据只是不一致地输入了？以及：我如何获取所有具有空值的记录-我应该查找`NULL`记录和空字符串，还是只选择具有空字符串的记录？

为了避免这种歧义，Django 自动生成的`CREATE TABLE`语句（在第四章中介绍过，*模型*）为每个列定义添加了显式的`NOT NULL`。例如，这是我们的`Author`模型的生成语句，来自第四章，*模型*：

```py
CREATE TABLE "books_author" ( 
    "id" serial NOT NULL PRIMARY KEY, 
    "first_name" varchar(30) NOT NULL, 
    "last_name" varchar(40) NOT NULL, 
    "email" varchar(75) NOT NULL 
); 

```

在大多数情况下，这种默认行为对于您的应用程序来说是最佳的，并且会避免数据不一致的问题。它与 Django 的其余部分很好地配合，比如 Django 管理站点，在您留空字符字段时会插入一个空字符串（而不是`NULL`值）。

但是，对于不接受空字符串作为有效值的数据库列类型，例如日期、时间和数字，有一个例外。如果您尝试将空字符串插入日期或整数列，根据您使用的数据库，您可能会收到数据库错误（PostgreSQL 是严格的，在这里会引发异常；MySQL 可能会接受它，也可能不会，这取决于您使用的版本、时间和月相）。

在这种情况下，`NULL`是指定空值的唯一方法。在 Django 模型中，您可以通过向字段添加`null=True`来指定允许`NULL`。这就是说：如果您想在日期字段（例如`DateField`、`TimeField`、`DateTimeField`）或数字字段（例如`IntegerField`、`DecimalField`、`FloatField`）中允许空值，您将需要同时使用`null=True`和`blank=True`。

举例来说，让我们将我们的`Book`模型更改为允许空白的`publication_date`。以下是修改后的代码：

```py
class Book(models.Model): 
    title = models.CharField(max_length=100) 
    authors = models.ManyToManyField(Author) 
    publisher = models.ForeignKey(Publisher) 
    publication_date = models.DateField(blank=True, null=True)

```

添加`null=True`比添加`blank=True`更复杂，因为`null=True`会改变数据库的语义-也就是说，它会从`publication_date`字段的`CREATE TABLE`语句中删除`NOT NULL`。要完成此更改，我们需要更新数据库。出于许多原因，Django 不尝试自动更改数据库模式，因此您需要在对模型进行此类更改时执行`python manage.py migrate`命令。回到管理站点，现在**添加书籍**编辑表单应该允许空的出版日期值。

# 自定义字段标签

在管理站点的编辑表单上，每个字段的标签都是从其模型字段名称生成的。算法很简单：Django 只是用空格替换下划线，并将第一个字符大写，因此，例如，`Book`模型的`publication_date`字段的标签是**出版日期**。

然而，字段名称并不总是适合作为管理员字段标签，因此在某些情况下，您可能希望自定义标签。您可以通过在适当的模型字段中指定`verbose_name`来实现这一点。例如，这是我们如何将`Author.email`字段的标签更改为**e-mail**，并加上连字符：

```py
class Author(models.Model): 
    first_name = models.CharField(max_length=30) 
    last_name = models.CharField(max_length=40) 
 email = models.EmailField(blank=True, verbose_name ='e-mail')

```

进行这些更改并重新加载服务器，您应该在作者编辑表单上看到字段的新标签。请注意，除非始终应该大写（例如`"USA state"`），否则不要大写`verbose_name`的第一个字母。Django 将在需要时自动将其大写，并且在不需要大写的其他地方使用确切的`verbose_name`值。

# 自定义模型管理员类

到目前为止我们所做的更改-`blank=True`，`null=True`和`verbose_name`-实际上是模型级别的更改，而不是管理员级别的更改。也就是说，这些更改基本上是模型的一部分，只是碰巧被管理员站点使用；它们与管理员无关。

除此之外，Django 管理员站点提供了丰富的选项，让您可以自定义管理员站点如何为特定模型工作。这些选项存在于**ModelAdmin 类**中，这些类包含了特定模型在特定管理员站点实例中的配置。

## 自定义更改列表

让我们通过指定在我们的`Author`模型的更改列表上显示的字段来深入研究管理员自定义。默认情况下，更改列表显示每个对象的`__str__()`的结果。在第四章*模型*中，我们为`Author`对象定义了`__str__()`方法，以显示名字和姓氏：

```py
class Author(models.Model): 
    first_name = models.CharField(max_length=30) 
    last_name = models.CharField(max_length=40) 
    email = models.EmailField(blank=True, verbose_name ='e-mail') 

    def __str__(self): 
        return u'%s %s' % (self.first_name, self.last_name) 

```

结果是，`Author`对象的更改列表显示了每个人的名字和姓氏，就像*图 5.7*中所示的那样。

![自定义更改列表](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/ms-dj/img/image_05_007.jpg)

图 5.7：作者更改列表页面

我们可以通过向更改列表显示添加一些其他字段来改进这种默认行为。例如，在此列表中看到每个作者的电子邮件地址会很方便，而且能够按名字和姓氏排序也很好。为了实现这一点，我们将为`Author`模型定义一个`ModelAdmin`类。这个类是自定义管理员的关键，它让您可以做的最基本的事情之一就是指定要在更改列表页面上显示的字段列表。编辑`admin.py`以进行这些更改：

```py
from django.contrib import admin 
from mysite.books.models import Publisher, Author, Book 

class AuthorAdmin(admin.ModelAdmin):
 list_display = ('first_name', 'last_name', 'email') 

admin.site.register(Publisher) 
admin.site.register(Author, AuthorAdmin) 
admin.site.register(Book) 

```

我们所做的是：

+   我们创建了`AuthorAdmin`类。这个类是`django.contrib.admin.ModelAdmin`的子类，保存了特定管理员模型的自定义配置。我们只指定了一个自定义选项-`list_display`，它设置为要在更改列表页面上显示的字段名称的元组。当然，这些字段名称必须存在于模型中。

+   我们修改了`admin.site.register()`调用，将`AuthorAdmin`添加到`Author`之后。您可以这样理解：使用`AuthorAdmin`选项注册`Author`模型。

+   `admin.site.register()`函数接受`ModelAdmin`子类作为可选的第二个参数。如果不指定第二个参数（就像`Publisher`和`Book`的情况一样），Django 将使用该模型的默认管理员选项。

进行了这些调整后，重新加载作者更改列表页面，您会看到现在显示了三列-名字、姓氏和电子邮件地址。此外，每列都可以通过单击列标题进行排序。（见*图 5.8*。）

![自定义更改列表](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/ms-dj/img/image_05_008.jpg)

图 5.8：添加`list_display`后的作者更改列表页面

接下来，让我们添加一个简单的搜索栏。像这样在`AuthorAdmin`中添加`search_fields`：

```py
class AuthorAdmin(admin.ModelAdmin): 
    list_display = ('first_name', 'last_name', 'email') 
 search_fields = ('first_name', 'last_name')

```

在浏览器中重新加载页面，您应该会看到顶部有一个搜索栏（见 *图 5.9*）。我们刚刚告诉管理员更改列表页面包括一个搜索栏，可以搜索 `first_name` 和 `last_name` 字段。正如用户所期望的那样，这是不区分大小写的，并且搜索两个字段，因此搜索字符串 `bar` 将找到名为 Barney 的作者和姓为 Hobarson 的作者。

![自定义更改列表](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/ms-dj/img/image_05_009.jpg)

图 5.9：`search_fields` 添加后的作者更改列表页面

接下来，让我们在我们的 `Book` 模型的更改列表页面上添加一些日期过滤器：

```py
from django.contrib import admin 
from mysite.books.models import Publisher, Author, Book 

class AuthorAdmin(admin.ModelAdmin): 
    list_display = ('first_name', 'last_name', 'email') 
    search_fields = ('first_name', 'last_name') 

class BookAdmin(admin.ModelAdmin):
 list_display = ('title', 'publisher', 'publication_date')
 list_filter = ('publication_date',) 

admin.site.register(Publisher) 
admin.site.register(Author, AuthorAdmin) 
admin.site.register(Book, BookAdmin)

```

在这里，因为我们正在处理不同的选项集，我们创建了一个单独的 `ModelAdmin` 类-`BookAdmin`。首先，我们定义了一个 `list_display`，只是为了让更改列表看起来更好一些。然后，我们使用了 `list_filter`，它设置为一个字段元组，用于在更改列表页面的右侧创建过滤器。对于日期字段，Django 提供了快捷方式来过滤列表，包括**今天**、**过去 7 天**、**本月**和**今年**-这些是 Django 开发人员发现的常见日期过滤情况的快捷方式。*图 5.10* 显示了它的样子。

![自定义更改列表](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/ms-dj/img/image_05_010.jpg)

图 5.10：`list_filter` 后的书籍更改列表页面

`list_filter` 也适用于其他类型的字段，不仅仅是 `DateField`。（例如，尝试使用 `BooleanField` 和 `ForeignKey` 字段。）只要有至少两个可选择的值，过滤器就会显示出来。另一种提供日期过滤器的方法是使用 `date_hierarchy` 管理选项，就像这样：

```py
class BookAdmin(admin.ModelAdmin): 
    list_display = ('title', 'publisher','publication_date') 
    list_filter = ('publication_date',) 
 date_hierarchy = 'publication_date'

```

有了这个设置，更改列表页面顶部会出现一个日期钻取导航栏，如 *图 5.11* 所示。它从可用年份列表开始，然后进入月份和具体日期。

![自定义更改列表](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/ms-dj/img/image_05_011.jpg)

图 5.11：`date_hierarchy` 后的书籍更改列表页面

请注意，`date_hierarchy` 接受一个字符串，而不是元组，因为只能使用一个日期字段来创建层次结构。最后，让我们更改默认排序，使得更改列表页面上的书籍总是按照它们的出版日期降序排序。默认情况下，更改列表根据其模型的 `class Meta` 中的 `ordering` 对象进行排序（我们在第四章中介绍过，*模型*）-但如果您没有指定这个 `ordering` 值，那么排序是未定义的。

```py
class BookAdmin(admin.ModelAdmin): 
    list_display = ('title', 'publisher','publication_date') 
    list_filter = ('publication_date',) 
    date_hierarchy = 'publication_date' 
 ordering = ('-publication_date',)

```

这个管理员 `ordering` 选项与模型的 `class Meta` 中的 `ordering` 完全相同，只是它只使用列表中的第一个字段名。只需传递一个字段名的列表或元组，并在字段前加上减号以使用降序排序。重新加载书籍更改列表，以查看它的效果。请注意，**出版日期** 标头现在包含一个小箭头，指示记录的排序方式（见 *图 5.12*）。

![自定义更改列表](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/ms-dj/img/image_05_012.jpg)

图 5.12：排序后的书籍更改列表页面

我们在这里介绍了主要的更改列表选项。使用这些选项，您可以只用几行代码就可以创建一个非常强大的、适用于生产的数据编辑界面。

## 自定义编辑表单

就像更改列表可以自定义一样，编辑表单也可以以多种方式自定义。首先，让我们自定义字段的排序方式。默认情况下，编辑表单中字段的顺序与模型中定义的顺序相对应。我们可以使用我们的 `ModelAdmin` 子类中的 `fields` 选项来更改这一点：

```py
class BookAdmin(admin.ModelAdmin): 
    list_display = ('title', 'publisher', 'publication_date') 
    list_filter = ('publication_date',) 
    date_hierarchy = 'publication_date' 
    ordering = ('-publication_date',) 
 fields = ('title', 'authors', 'publisher', publication_date')

```

在这个更改之后，书籍的编辑表单将使用给定的字段排序。将作者放在书名后面会更自然一些。当然，字段顺序应该取决于您的数据输入工作流程。每个表单都是不同的。

`fields`选项让你可以做的另一件有用的事情是完全排除某些字段的编辑。只需省略你想要排除的字段。如果你的管理员用户只被信任编辑数据的某个部分，或者你的某些字段是由外部自动化流程改变的，你可能会用到这个功能。

例如，在我们的书籍数据库中，我们可以隐藏`publication_date`字段，使其不可编辑：

```py
class BookAdmin(admin.ModelAdmin): 
    list_display = ('title', 'publisher','publication_date') 
    list_filter = ('publication_date',) 
    date_hierarchy = 'publication_date' 
    ordering = ('-publication_date',) 
 fields = ('title', 'authors', 'publisher')

```

因此，书籍的编辑表单没有提供指定出版日期的方法。这可能很有用，比如，如果你是一个编辑，你希望作者不要推迟出版日期。（当然，这只是一个假设的例子。）当用户使用这个不完整的表单添加新书时，Django 将简单地将`publication_date`设置为`None`-所以确保该字段具有`null=True`。

另一个常用的编辑表单定制与多对多字段有关。正如我们在书籍的编辑表单上看到的，管理员站点将每个`ManyToManyField`表示为多选框，这是最合乎逻辑的 HTML 输入小部件使用方式，但多选框可能难以使用。如果你想选择多个项目，你必须按住控制键，或者在 Mac 上按住命令键。

管理员站点贴心地插入了一些解释这一点的文本，但是当你的字段包含数百个选项时，它仍然变得笨拙。管理员站点的解决方案是`filter_horizontal`。让我们将其添加到`BookAdmin`中，看看它的作用。

```py
class BookAdmin(admin.ModelAdmin): 
    list_display = ('title', 'publisher','publication_date') 
    list_filter = ('publication_date',) 
    date_hierarchy = 'publication_date' 
    ordering = ('-publication_date',) 
 filter_horizontal = ('authors',)

```

（如果你在跟着做，注意我们也已经移除了`fields`选项来显示编辑表单中的所有字段。）重新加载书籍的编辑表单，你会看到**作者**部分现在使用了一个花哨的 JavaScript 过滤界面，让你可以动态搜索选项并将特定作者从**可用作者**移动到**已选作者**框中，反之亦然。

![自定义编辑表单](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/ms-dj/img/image_05_013.jpg)

图 5.13：添加 filter_horizontal 后的书籍编辑表单

我强烈建议对于有超过十个项目的`ManyToManyField`使用`filter_horizontal`。它比简单的多选小部件更容易使用。另外，请注意你可以对多个字段使用`filter_horizontal`-只需在元组中指定每个名称。

`ModelAdmin`类也支持`filter_vertical`选项。这与`filter_horizontal`的工作方式完全相同，但是生成的 JavaScript 界面将两个框垂直堆叠而不是水平堆叠。这是个人品味的问题。

`filter_horizontal`和`filter_vertical`只对`ManyToManyField`字段起作用，而不对`ForeignKey`字段起作用。默认情况下，管理员站点对`ForeignKey`字段使用简单的`<select>`框，但是，就像对于`ManyToManyField`一样，有时你不想承担选择所有相关对象以在下拉框中显示的开销。

例如，如果我们的书籍数据库增长到包括成千上万的出版商，**添加书籍**表单可能需要一段时间才能加载，因为它需要加载每个出版商以在`<select>`框中显示。

修复这个问题的方法是使用一个叫做`raw_id_fields`的选项：

```py
class BookAdmin(admin.ModelAdmin): 
    list_display = ('title', 'publisher','publication_date') 
    list_filter = ('publication_date',) 
    date_hierarchy = 'publication_date' 
    ordering = ('-publication_date',) 
    filter_horizontal = ('authors',) 
 raw_id_fields = ('publisher',)

```

将其设置为`ForeignKey`字段名称的元组，这些字段将在管理员中显示为一个简单的文本输入框(`<input type="text">`)，而不是一个`<select>`。见*图 5.14*。

![自定义编辑表单](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/ms-dj/img/image_05_014.jpg)

图 5.14：添加`raw_id_fields`后的书籍编辑表单

你在这个输入框中输入什么？出版商的数据库 ID。鉴于人类通常不会记住数据库 ID，还有一个放大镜图标，你可以点击它弹出一个窗口，从中选择要添加的出版商。

# 用户、组和权限

因为您以超级用户身份登录，您可以访问创建、编辑和删除任何对象。不同的环境需要不同的权限系统-并非每个人都可以或应该成为超级用户。Django 的管理员站点使用了一个权限系统，您可以使用它来仅给特定用户访问他们需要的界面部分。这些用户帐户的设计是足够通用，可以在管理员界面之外使用，但我们现在将它们视为管理员用户帐户。

在第十一章，“Django 中的用户认证”中，我们将介绍如何使用 Django 的认证系统在整个站点上管理用户（即不仅仅是管理员站点）。您可以像编辑任何其他对象一样，通过管理员界面编辑用户和权限。我们在本章的前面看到了这一点，当时我们在管理员的用户和组部分玩耍。

用户对象具有标准的用户名、密码、电子邮件和真实姓名字段，以及一组定义用户在管理员界面中允许做什么的字段。首先，有一组三个布尔标志：

+   active 标志控制用户是否活跃。如果这个标志关闭，用户尝试登录时，即使有有效密码，也不会被允许登录。

+   staff 标志控制用户是否被允许登录到管理员界面（也就是说，该用户是否被认为是您组织中的工作人员）。由于这个相同的用户系统可以用来控制对公共（即非管理员）站点的访问（参见第十一章，“Django 中的用户认证”），这个标志区分了公共用户和管理员。

+   超级用户标志给予用户在管理员界面中添加、创建和删除任何项目的完全访问权限。如果用户设置了这个标志，那么所有常规权限（或缺乏权限）对该用户都将被忽略。

普通管理员用户-也就是活跃的、非超级用户的工作人员-通过分配的权限获得管理员访问权限。通过管理员界面可编辑的每个对象（例如书籍、作者、出版商）都有三个权限：创建权限、编辑权限和删除权限。将权限分配给用户将授予用户执行这些权限描述的操作的访问权限。当您创建用户时，该用户没有任何权限，您需要为用户分配特定的权限。

例如，您可以给用户添加和更改出版商的权限，但不给予删除的权限。请注意，这些权限是针对模型定义的，而不是针对对象定义的-因此它们让您说“约翰可以对任何书进行更改”，但不让您说“约翰可以对 Apress 出版的任何书进行更改”。后者的功能，即对象级权限，有点复杂，超出了本书的范围，但在 Django 文档中有介绍。

### 注意

警告！

对编辑用户和权限的访问也受到这个权限系统的控制。如果您给某人编辑用户的权限，他们将能够编辑自己的权限，这可能不是您想要的！给用户编辑用户的权限实质上是将用户变成超级用户。

您还可以将用户分配到组。组只是一组权限，适用于该组的所有成员。组对于授予一部分用户相同的权限非常有用。

# 何时以及为什么使用管理员界面，以及何时不要使用

通过本章的学习，您应该对如何使用 Django 的管理员站点有一个很好的了解。但我想强调一下何时以及为什么您可能想要使用它，以及何时不要使用它。

当非技术用户需要输入数据时，Django 的管理站点尤其突出；毕竟，这就是该功能的目的。在 Django 首次开发的报纸上，开发典型的在线功能（比如市政供水水质特别报告）的开发过程大致如下：

+   负责项目的记者与其中一名开发人员会面，并描述可用的数据。

+   开发人员设计 Django 模型以适应这些数据，然后向记者打开管理站点。

+   记者检查管理站点以指出任何缺失或多余的字段-现在指出比以后好。开发人员迭代更改模型。

+   当模型达成一致后，记者开始使用管理站点输入数据。与此同时，程序员可以专注于开发公开可访问的视图/模板（这是有趣的部分！）。

换句话说，Django 的管理界面的存在意义是促进内容生产者和程序员的同时工作。然而，除了这些明显的数据输入任务之外，管理站点在一些其他情况下也很有用：

+   **检查数据模型**：一旦定义了一些模型，通过在管理界面中调用它们并输入一些虚拟数据，这可能会揭示数据建模错误或模型的其他问题。

+   **管理获取的数据**：对于依赖来自外部来源的数据的应用程序（例如用户或网络爬虫），管理站点为您提供了一种轻松的方式来检查或编辑这些数据。您可以将其视为数据库命令行实用程序的功能较弱但更方便的版本。

+   **快速而简单的数据管理应用程序**：您可以使用管理站点来构建一个非常轻量级的数据管理应用程序，比如用于跟踪开支。如果您只是为自己的需求构建某些东西，而不是为公众消费，管理站点可以帮助您走得更远。在这种意义上，您可以将其视为增强版的关系型电子表格。

然而，管理站点并不是万能的。它不打算成为数据的公共接口，也不打算允许对数据进行复杂的排序和搜索。正如本章早期所说，它是为受信任的站点管理员而设计的。牢记这一甜蜜点是有效使用管理站点的关键。

# 接下来呢？

到目前为止，我们已经创建了一些模型，并配置了一个一流的界面来编辑数据。在下一章中，我们将继续进行真正的网页开发：表单创建和处理。


# 第六章：表单

HTML 表单是交互式网站的支柱，从谷歌的单个搜索框的简单性到无处不在的博客评论提交表单到复杂的自定义数据输入界面。

本章涵盖了如何使用 Django 访问用户提交的表单数据，对其进行验证并执行某些操作。在此过程中，我们将涵盖`HttpRequest`和`Form`对象。

# 从请求对象获取数据

我在第二章中介绍了`HttpRequest`对象，*视图和 URLconfs*，当时我们首次涵盖了视图函数，但那时我对它们没有太多可说的。回想一下，每个视图函数都以`HttpRequest`对象作为其第一个参数，就像我们的`hello()`视图一样：

```py
from django.http import HttpResponse 

def hello(request): 
    return HttpResponse("Hello world") 

```

`HttpRequest`对象，比如这里的变量`request`，有许多有趣的属性和方法，您应该熟悉它们，以便了解可能发生的情况。您可以使用这些属性来获取有关当前请求的信息（即加载 Django 站点上当前页面的用户/网络浏览器）在执行视图函数时。

## 关于 URL 的信息

`HttpRequest`对象包含有关当前请求的 URL 的几个信息（*表 6.1*）。

| 属性/方法 | 描述 | 示例 |
| --- | --- | --- |
| `request.path` | 完整路径，不包括域名，但包括前导斜杠。 | `"/hello/"` |
| `request.get_host()` | 主机（即俗称的“域名”）。 | `"127.0.0.1:8000"`或`"www.example.com"` |
| `request.get_full_path()` | `path`，加上查询字符串（如果有的话）。 | `"/hello/?print=true"` |
| `request.is_secure()` | 如果请求是通过 HTTPS 进行的，则为`True`。否则为`False`。 | `True`或`False` |

表 6.1：HttpRequest 方法和属性

始终使用这些属性/方法，而不是在视图中硬编码 URL。这样可以使代码更灵活，可以在其他地方重用。一个简单的例子：

```py
# BAD! 
def current_url_view_bad(request): 
    return HttpResponse("Welcome to the page at /current/") 

# GOOD 
def current_url_view_good(request): 
    return HttpResponse("Welcome to the page at %s" % request.path) 

```

## 请求对象的其他信息

`request.META`是一个 Python 字典，包含给定请求的所有可用 HTTP 标头-包括用户的 IP 地址和用户代理（通常是 Web 浏览器的名称和版本）。请注意，可用标头的完整列表取决于用户发送了哪些标头以及您的 Web 服务器设置了哪些标头。该字典中一些常用的键是：

+   `HTTP_REFERER`：引用的 URL，如果有的话。（请注意`REFERER`的拼写错误）。

+   `HTTP_USER_AGENT`：用户的浏览器的用户代理字符串，如果有的话。它看起来像这样：`"Mozilla/5.0 (X11; U; Linux i686; fr-FR; rv:1.8.1.17) Gecko/20080829 Firefox/2.0.0.17"`。

+   `REMOTE_ADDR`：客户端的 IP 地址，例如`"12.345.67.89"`。（如果请求通过任何代理，则这可能是一个逗号分隔的 IP 地址列表，例如`"12.345.67.89,23.456.78.90"`）。

请注意，因为`request.META`只是一个基本的 Python 字典，如果您尝试访问一个不存在的键，您将得到一个`KeyError`异常。（因为 HTTP 标头是外部数据-即它们是由您的用户的浏览器提交的-所以不应该信任它们，您应该始终设计您的应用程序，以便在特定标头为空或不存在时优雅地失败。）您应该使用`try`/`except`子句或`get()`方法来处理未定义键的情况：

```py
# BAD! 
def ua_display_bad(request): 
    ua = request.META['HTTP_USER_AGENT']  # Might raise KeyError! 
    return HttpResponse("Your browser is %s" % ua) 

# GOOD (VERSION 1) 
def ua_display_good1(request): 
    try: 
        ua = request.META['HTTP_USER_AGENT'] 
    except KeyError: 
        ua = 'unknown' 
    return HttpResponse("Your browser is %s" % ua) 

# GOOD (VERSION 2) 
def ua_display_good2(request): 
    ua = request.META.get('HTTP_USER_AGENT', 'unknown') 
    return HttpResponse("Your browser is %s" % ua) 

```

我鼓励您编写一个小视图，显示所有`request.META`数据，以便了解其中的内容。以下是该视图的样子：

```py
def display_meta(request): 
    values = request.META.items() 
    values.sort() 
    html = [] 
    for k, v in values: 
      html.append('<tr><td>%s</td><td>%s</td></tr>' % (k, v)) 
    return HttpResponse('<table>%s</table>' % '\n'.join(html)) 

```

查看请求对象包含的信息的另一种好方法是仔细查看 Django 错误页面，当您使系统崩溃时-那里有大量有用的信息，包括所有 HTTP 标头和其他请求对象（例如`request.path`）。

## 有关提交数据的信息

关于请求的基本元数据之外，`HttpRequest`对象有两个属性，包含用户提交的信息：`request.GET`和`request.POST`。这两个都是类似字典的对象，可以访问`GET`和`POST`数据。

`POST`数据通常是从 HTML `<form>`提交的，而`GET`数据可以来自页面 URL 中的`<form>`或查询字符串。

### 注意

**类似字典的对象**

当我们说`request.GET`和`request.POST`是*类似字典*的对象时，我们的意思是它们的行为类似于标准的 Python 字典，但在技术上并不是字典。例如，`request.GET`和`request.POST`都有`get()`、`keys()`和`values()`方法，您可以通过`for key in request.GET`来遍历键。那么为什么要区分呢？因为`request.GET`和`request.POST`都有标准字典没有的额外方法。我们将在短时间内介绍这些方法。您可能遇到过类似的术语*类似文件*的对象-具有一些基本方法（如`read()`）的 Python 对象，让它们可以充当"真实"文件对象的替代品。

# 一个简单的表单处理示例

继续图书、作者和出版商的示例，让我们创建一个简单的视图，让用户通过标题搜索我们的图书数据库。通常，开发表单有两个部分：HTML 用户界面和处理提交数据的后端视图代码。第一部分很容易；让我们设置一个显示搜索表单的视图：

```py

from django.shortcuts import render 

def search_form(request): 
    return render(request, 'search_form.html') 

```

正如您在第三章中学到的，这个视图可以存在于 Python 路径的任何位置。为了论证，将其放在`books/views.py`中。相应的模板`search_form.html`可能如下所示：

```py
<html> 
<head> 
    <title>Search</title> 
</head> 
<body> 
    <form action="/search/" method="get"> 
        <input type="text" name="q"> 
        <input type="submit" value="Search"> 
    </form> 
</body> 
</html> 

```

将此文件保存到您在第三章中创建的`mysite/templates`目录中，*模板*，或者您可以创建一个新的文件夹`books/templates`。只需确保您的设置文件中的`'APP_DIRS'`设置为`True`。`urls.py`中的 URL 模式可能如下所示：

```py
from books import views 

urlpatterns = [ 
    # ... 
    url(r'^search-form/$', views.search_form), 
    # ... 
] 

```

（请注意，我们直接导入`views`模块，而不是像`from mysite.views import search_form`这样的方式，因为前者更简洁。我们将在第七章中更详细地介绍这种导入方法，*高级视图和 URLconfs*）。现在，如果您运行开发服务器并访问`http://127.0.0.1:8000/search-form/`，您将看到搜索界面。足够简单。不过，尝试提交表单，您将收到 Django 404 错误。表单指向 URL`/search/`，但尚未实现。让我们用第二个视图函数来修复这个问题：

```py
# urls.py 

urlpatterns = [ 
    # ... 
    url(r'^search-form/$', views.search_form), 
    url(r'^search/$', views.search), 
    # ... 
] 

# books/views.py 

from django.http import HttpResponse 

# ... 

def search(request): 
    if 'q' in request.GET: 
        message = 'You searched for: %r' % request.GET['q'] 
    else: 
        message = 'You submitted an empty form.' 
    return HttpResponse(message) 

```

目前，这只是显示用户的搜索词，这样我们可以确保数据被正确提交到 Django，并且您可以感受搜索词是如何在系统中流动的。简而言之：

+   HTML `<form>`定义了一个变量`q`。当提交时，`q`的值通过`GET`（`method="get"`）发送到 URL`/search/`。

+   处理 URL`/search/`（`search()`）的 Django 视图可以访问`request.GET`中的`q`值。

这里要指出的一个重要事情是，我们明确检查`request.GET`中是否存在`'q'`。正如我在前面的`request.META`部分中指出的，您不应信任用户提交的任何内容，甚至不应假设他们首先提交了任何内容。如果我们没有添加这个检查，任何空表单的提交都会在视图中引发`KeyError`：

```py
# BAD! 
def bad_search(request): 
    # The following line will raise KeyError if 'q' hasn't 
    # been submitted! 
    message = 'You searched for: %r' % request.GET['q'] 
    return HttpResponse(message) 

```

## 查询字符串参数

因为`GET`数据是通过查询字符串传递的（例如，`/search/?q=django`），您可以使用`request.GET`来访问查询字符串变量。在第二章中，*视图和 URLconfs*，介绍了 Django 的 URLconf 系统，我将 Django 的美观 URL 与更传统的 PHP/Java URL 进行了比较，例如`/time/plus?hours=3`，并说我会在第六章中向您展示如何做后者。现在您知道如何在视图中访问查询字符串参数（例如在这个示例中的`hours=3`）-使用`request.GET`。

`POST`数据的工作方式与`GET`数据相同-只需使用`request.POST`而不是`request.GET`。`GET`和`POST`之间有什么区别？当提交表单的行为只是获取数据时使用`GET`。当提交表单的行为会产生一些副作用-更改数据、发送电子邮件或其他超出简单数据*显示*的操作时使用`POST`。在我们的图书搜索示例中，我们使用`GET`，因为查询不会改变服务器上的任何数据。（如果您想了解更多关于`GET`和`POST`的信息，请参阅 http://www.w3.org/2001/tag/doc/whenToUseGet.html 网站。）现在我们已经验证了`request.GET`是否被正确传递，让我们将用户的搜索查询连接到我们的图书数据库中（同样是在`views.py`中）：

```py
from django.http import HttpResponse 
from django.shortcuts import render 
from books.models import Book 

def search(request): 
    if 'q' in request.GET and request.GET['q']: 
        q = request.GET['q'] 
        books = Book.objects.filter(title__icontains=q) 
        return render(request, 'search_results.html', 
                      {'books': books, 'query': q}) 
    else: 
        return HttpResponse('Please submit a search term.') 

```

关于我们在这里所做的一些说明：

+   除了检查`'q'`是否存在于`request.GET`中，我们还确保在将其传递给数据库查询之前，`request.GET['q']`是一个非空值。

+   我们使用`Book.objects.filter(title__icontains=q)`来查询我们的图书表，找到标题包含给定提交的所有书籍。`icontains`是一种查找类型（如第四章和附录 B 中所解释的那样），该语句可以粗略地翻译为“获取标题包含`q`的书籍，而不区分大小写。”

+   这是一个非常简单的图书搜索方法。我们不建议在大型生产数据库上使用简单的`icontains`查询，因为它可能会很慢。（在现实世界中，您可能希望使用某种自定义搜索系统。搜索网络以获取*开源全文搜索*的可能性。）

+   我们将`books`，一个`Book`对象的列表，传递给模板。`search_results.html`文件可能包括类似以下内容：

```py
         <html> 
          <head> 
              <title>Book Search</title> 
          </head> 
          <body> 
            <p>You searched for: <strong>{{ query }}</strong></p> 

            {% if books %} 
                <p>Found {{ books|length }}
                    book{{ books|pluralize }}.</p> 
                <ul> 
                    {% for book in books %} 
                    <li>{{ book.title }}</li> 
                    {% endfor %} 
                </ul> 
            {% else %} 
                <p>No books matched your search criteria.</p> 
            {% endif %} 

          </body> 
        </html> 

```

注意使用`pluralize`模板过滤器，根据找到的书籍数量输出“s”。

# 改进我们简单的表单处理示例

与以前的章节一样，我向您展示了可能起作用的最简单的方法。现在我将指出一些问题，并向您展示如何改进它。首先，我们的`search()`视图对空查询的处理很差-我们只显示一个**请提交搜索词。**消息，要求用户点击浏览器的返回按钮。

这是可怕的，不专业的，如果您真的在实际中实现了这样的东西，您的 Django 权限将被撤销。更好的方法是重新显示表单，并在其前面显示一个错误，这样用户可以立即重试。最简单的方法是再次渲染模板，就像这样：

```py
from django.http import HttpResponse 
from django.shortcuts import render 
from books.models import Book 

def search_form(request): 
    return render(request, 'search_form.html') 

def search(request): 
    if 'q' in request.GET and request.GET['q']: 
        q = request.GET['q'] 
        books = Book.objects.filter(title__icontains=q) 
        return render(request, 'search_results.html', 
                      {'books': books, 'query': q}) 
    else: 
 return render
           (request, 'search_form.html', {'error': True})

```

（请注意，我在这里包括了`search_form()`，这样您就可以在一个地方看到两个视图。）在这里，我们改进了`search()`，如果查询为空，就重新渲染`search_form.html`模板。因为我们需要在该模板中显示错误消息，所以我们传递了一个模板变量。现在我们可以编辑`search_form.html`来检查`error`变量：

```py
<html> 
<head> 
    <title>Search</title> 
</head> 
<body> 
 {% if error %} 
 <p style="color: red;">Please submit a search term.</p> 
 {% endif %} 
    <form action="/search/" method="get"> 
        <input type="text" name="q"> 
        <input type="submit" value="Search"> 
    </form> 
</body> 
</html> 

```

我们仍然可以从我们原始的视图`search_form()`中使用这个模板，因为`search_form()`不会将`error`传递给模板，所以在这种情况下不会显示错误消息。有了这个改变，这是一个更好的应用程序，但现在问题是：是否真的需要一个专门的`search_form()`视图？

目前，对 URL`/search/`（没有任何`GET`参数）的请求将显示空表单（但带有错误）。只要我们在没有`GET`参数的情况下访问`/search/`，就可以删除`search_form()`视图及其相关的 URLpattern，同时将`search()`更改为在有人访问`/search/`时隐藏错误消息：

```py
def search(request): 
    error = False 
    if 'q' in request.GET: 
        q = request.GET['q'] 
if not q: 
 error = True 
 else: 
            books = Book.objects.filter(title__icontains=q) 
            return render(request, 'search_results.html', 
                          {'books': books, 'query': q}) 
 return render(request, 'search_form.html', 
 {'error': error})

```

在这个更新的视图中，如果用户在没有`GET`参数的情况下访问`/search/`，他们将看到没有错误消息的搜索表单。如果用户提交了一个空值的`'q'`，他们将看到带有错误消息的搜索表单。最后，如果用户提交了一个非空值的`'q'`，他们将看到搜索结果。

我们可以对此应用进行最后一次改进，以消除一些冗余。现在我们已经将两个视图和 URL 合并为一个，并且`/search/`处理搜索表单显示和结果显示，`search_form.html`中的 HTML`<form>`不必硬编码 URL。而不是这样：

```py
<form action="/search/" method="get"> 

```

可以更改为这样：

```py
<form action="" method="get"> 

```

`action=""` 表示*将表单提交到与当前页面相同的 URL*。有了这个改变，如果您将`search()`视图连接到另一个 URL，您就不必记得更改`action`。

# 简单验证

我们的搜索示例仍然相当简单，特别是在数据验证方面；我们只是检查确保搜索查询不为空。许多 HTML 表单包括比确保值非空更复杂的验证级别。我们都在网站上看到过错误消息：

+   *请输入一个有效的电子邮件地址。'foo'不是一个电子邮件地址。*

+   *请输入一个有效的五位数字的美国邮政编码。'123'不是一个邮政编码。*

+   *请输入格式为 YYYY-MM-DD 的有效日期。*

+   *请输入至少 8 个字符长且至少包含一个数字的密码。*

让我们调整我们的`search()`视图，以验证搜索词是否少于或等于 20 个字符长。（举个例子，假设超过这个长度可能会使查询变得太慢。）我们该如何做到这一点？

最简单的方法是直接在视图中嵌入逻辑，如下所示：

```py
def search(request): 
    error = False 
    if 'q' in request.GET: 
        q = request.GET['q'] 
        if not q: 
            error = True 
 elif len(q) > 20: 
 error = True 
        else: 
            books = Book.objects.filter(title__icontains=q) 
            return render(request, 'search_results.html', 
                          {'books': books, 'query': q}) 
    return render(request, 'search_form.html', 
        {'error': error}) 

```

现在，如果您尝试提交一个超过 20 个字符长的搜索查询，它将不允许您进行搜索；您将收到一个错误消息。但是`search_form.html`中的错误消息目前说：“请提交搜索词”。-所以我们必须更改它以适应两种情况：

```py
<html> 
<head> 
    <title>Search</title> 
</head> 
<body> 
    {% if error %} 
 <p style="color: red;"> 
 Please submit a search term 20 characters or shorter. 
 </p> 
    {% endif %} 

    <form action="/search/" method="get"> 
        <input type="text" name="q"> 
        <input type="submit" value="Search"> 
    </form> 
</body> 
</html> 

```

这里有一些不好的地方。我们的一刀切错误消息可能会令人困惑。为什么空表单提交的错误消息要提及 20 个字符的限制？

错误消息应该是具体的、明确的，不应该令人困惑。问题在于我们使用了一个简单的布尔值`error`，而我们应该使用一个错误消息字符串列表。以下是我们可能如何修复它：

```py
def search(request): 
    errors = [] 
    if 'q' in request.GET: 
        q = request.GET['q'] 
        if not q: 
 errors.append('Enter a search term.') 
        elif len(q) > 20: 
 errors.append('Please enter at most 20 characters.') 
        else: 
            books = Book.objects.filter(title__icontains=q) 
            return render(request, 'search_results.html', 
                          {'books': books, 'query': q}) 
    return render(request, 'search_form.html', 
                  {'errors': errors}) 

```

然后，我们需要对`search_form.html`模板进行小的调整，以反映它现在传递了一个`errors`列表，而不是一个`error`布尔值：

```py
<html> 
<head> 
    <title>Search</title> 
</head> 
<body> 
    {% if errors %} 
 <ul> 
 {% for error in errors %} 
 <li>{{ error }}</li> 
 {% endfor %} 
 </ul> 
    {% endif %} 
    <form action="/search/" method="get"> 
        <input type="text" name="q"> 
        <input type="submit" value="Search"> 
    </form> 
</body> 
</html> 

```

# 创建联系表单

尽管我们多次迭代了图书搜索表单示例并对其进行了良好的改进，但它仍然基本上很简单：只有一个字段`'q'`。随着表单变得更加复杂，我们必须一遍又一遍地重复前面的步骤，为我们使用的每个表单字段重复这些步骤。这引入了很多废料和很多人为错误的机会。幸运的是，Django 的开发人员考虑到了这一点，并在 Django 中构建了一个处理表单和验证相关任务的更高级别库。

## 您的第一个表单类

Django 带有一个表单库，称为`django.forms`，它处理了本章中我们探讨的许多问题-从 HTML 表单显示到验证。让我们深入研究并使用 Django 表单框架重新设计我们的联系表单应用程序。

使用表单框架的主要方法是为您处理的每个 HTML `<form>`定义一个`Form`类。在我们的情况下，我们只有一个`<form>`，所以我们将有一个`Form`类。这个类可以放在任何您想要的地方，包括直接放在您的`views.py`文件中，但社区约定是将`Form`类放在一个名为`forms.py`的单独文件中。

在与您的`mysite/views.py`相同的目录中创建此文件，并输入以下内容：

```py
from django import forms 

class ContactForm(forms.Form): 
    subject = forms.CharField() 
    email = forms.EmailField(required=False) 
    message = forms.CharField() 

```

这是非常直观的，类似于 Django 的模型语法。表单中的每个字段都由`Field`类的一种类型表示-这里只使用`CharField`和`EmailField`作为`Form`类的属性。默认情况下，每个字段都是必需的，因此要使`email`可选，我们指定`required=False`。让我们进入 Python 交互解释器，看看这个类能做什么。它能做的第一件事是将自己显示为 HTML：

```py
>>> from mysite.forms import ContactForm 
>>> f = ContactForm() 
>>> print(f) 
<tr><th><label for="id_subject">Subject:</label></th><td><input type="text" name="subject" id="id_subject" /></td></tr> 
<tr><th><label for="id_email">Email:</label></th><td><input type="text" name="email" id="id_email" /></td></tr> 
<tr><th><label for="id_message">Message:</label></th><td><input type="text" name="message" id="id_message" /></td></tr> 

```

Django 为每个字段添加了标签，以及用于辅助功能的`<label>`标签。其目的是使默认行为尽可能优化。此默认输出采用 HTML `<table>`格式，但还有其他几种内置输出：

```py
>>> print(f.as_ul()) 
<li><label for="id_subject">Subject:</label> <input type="text" name="subject" id="id_subject" /></li> 
<li><label for="id_email">Email:</label> <input type="text" name="email" id="id_email" /></li> 
<li><label for="id_message">Message:</label> <input type="text" name="message" id="id_message" /></li> 

>>> print(f.as_p()) 
<p><label for="id_subject">Subject:</label> <input type="text" name="subject" id="id_subject" /></p> 
<p><label for="id_email">Email:</label> <input type="text" name="email" id="id_email" /></p> 
<p><label for="id_message">Message:</label> <input type="text" name="message" id="id_message" /></p> 

```

请注意，输出中不包括开放和关闭的`<table>`、`<ul>`和`<form>`标签，因此您可以根据需要添加任何额外的行和自定义。这些方法只是常见情况下的快捷方式，即“显示整个表单”。您还可以显示特定字段的 HTML：

```py
>>> print(f['subject']) 
<input id="id_subject" name="subject" type="text" /> 
>>> print f['message'] 
<input id="id_message" name="message" type="text" /> 

```

`Form`对象的第二个功能是验证数据。要验证数据，请创建一个新的`Form`对象，并将数据字典传递给它，将字段名称映射到数据：

```py
>>> f = ContactForm({'subject': 'Hello', 'email': 'adrian@example.com', 'message': 'Nice site!'}) 

```

一旦您将数据与`Form`实例关联起来，就创建了一个**绑定**表单：

```py
>>> f.is_bound 
True 

```

对任何绑定的`Form`调用`is_valid()`方法，以了解其数据是否有效。我们已为每个字段传递了有效值，因此整个`Form`都是有效的：

```py
>>> f.is_valid() 
True 

```

如果我们不传递`email`字段，它仍然有效，因为我们已经为该字段指定了`required=False`：

```py
>>> f = ContactForm({'subject': 'Hello', 'message': 'Nice site!'}) 
>>> f.is_valid() 
True 

```

但是，如果我们省略`subject`或`message`中的任何一个，`Form`将不再有效：

```py
>>> f = ContactForm({'subject': 'Hello'}) 
>>> f.is_valid() 
False 
>>> f = ContactForm({'subject': 'Hello', 'message': ''}) 
>>> f.is_valid() 
False 

```

您可以深入了解特定字段的错误消息：

```py
>>> f = ContactForm({'subject': 'Hello', 'message': ''}) 
>>> f['message'].errors 
['This field is required.'] 
>>> f['subject'].errors 
[] 
>>> f['email'].errors 
[] 

```

每个绑定的`Form`实例都有一个`errors`属性，该属性为您提供了一个将字段名称映射到错误消息列表的字典：

```py
>>> f = ContactForm({'subject': 'Hello', 'message': ''}) 
>>> f.errors 
{'message': ['This field is required.']} 

```

最后，对于数据已被发现有效的`Form`实例，将提供`cleaned_data`属性。这是提交的数据的“清理”。Django 的表单框架不仅验证数据；它通过将值转换为适当的 Python 类型来清理数据：

```py
>>> f = ContactForm({'subject': 'Hello', 'email': 'adrian@example.com', 
'message': 'Nice site!'}) 
>>> f.is_valid() True 
>>> f.cleaned_data 
{'message': 'Nice site!', 'email': 'adrian@example.com', 'subject': 
'Hello'} 

```

我们的联系表单只处理字符串，这些字符串被“清理”为字符串对象-但是，如果我们使用`IntegerField`或`DateField`，表单框架将确保`cleaned_data`使用适当的 Python 整数或`datetime.date`对象来表示给定字段。

# 将表单对象与视图绑定

除非我们有一种方法将其显示给用户，否则我们的联系表单对我们来说没有太大用处。为此，我们首先需要更新我们的`mysite/views`：

```py
# views.py 

from django.shortcuts import render 
from mysite.forms import ContactForm 
from django.http import HttpResponseRedirect 
from django.core.mail import send_mail 

# ... 

def contact(request): 
    if request.method == 'POST': 
        form = ContactForm(request.POST) 
        if form.is_valid(): 
            cd = form.cleaned_data 
            send_mail( 
                cd['subject'], 
                cd['message'], 
                cd.get('email', 'noreply@example.com'), 
                ['siteowner@example.com'], 
            ) 
            return HttpResponseRedirect('/contact/thanks/') 
    else: 
        form = ContactForm() 
    return render(request, 'contact_form.html', {'form': form}) 

```

接下来，我们必须创建我们的联系表单（保存到`mysite/templates`）：

```py
# contact_form.html 

<html> 
<head> 
    <title>Contact us</title> 
</head> 
<body> 
    <h1>Contact us</h1> 

    {% if form.errors %} 
        <p style="color: red;"> 
            Please correct the error{{ form.errors|pluralize }} below. 
        </p> 
    {% endif %} 

    <form action="" method="post"> 
        <table> 
            {{ form.as_table }} 
        </table> 
        {% csrf_token %} 
        <input type="submit" value="Submit"> 
    </form> 
</body> 
</html> 

```

最后，我们需要更改我们的`urls.py`，以便在`/contact/`处显示我们的联系表单：

```py
 # ... 
from mysite.views import hello, current_datetime, hours_ahead, contact 

 urlpatterns = [ 

     # ... 

     url(r'^contact/$', contact), 
] 

```

由于我们正在创建一个`POST`表单（可能会导致修改数据的效果），我们需要担心跨站点请求伪造。幸运的是，您不必太担心，因为 Django 带有一个非常易于使用的系统来防止它。简而言之，所有针对内部 URL 的`POST`表单都应使用`{% csrf_token %}`模板标记。更多细节

`{% csrf_token %}`可以在第十九章*Django 中的安全性*中找到。

尝试在本地运行此代码。加载表单，提交表单时没有填写任何字段，使用无效的电子邮件地址提交表单，最后使用有效数据提交表单。（当调用`send_mail()`时，除非您配置了邮件服务器，否则会收到`ConnectionRefusedError`。）

# 更改字段呈现方式

当您在本地呈现此表单时，您可能首先注意到的是`message`字段显示为`<input type="text">`，而应该是`<textarea>`。我们可以通过设置字段的小部件来解决这个问题：

```py
from django import forms 

class ContactForm(forms.Form): 
    subject = forms.CharField() 
    email = forms.EmailField(required=False) 
    message = forms.CharField(widget=forms.Textarea)

```

表单框架将每个字段的呈现逻辑分离为一组小部件。每种字段类型都有一个默认小部件，但您可以轻松地覆盖默认值，或者提供自定义小部件。将`Field`类视为**验证逻辑**，而小部件表示**呈现逻辑**。

# 设置最大长度

最常见的验证需求之一是检查字段的大小。为了好玩，我们应该改进我们的`ContactForm`以将`subject`限制为 100 个字符。要做到这一点，只需向`CharField`提供`max_length`，如下所示：

```py
from django import forms 

class ContactForm(forms.Form): 
    subject = forms.CharField(max_length=100) 
    email = forms.EmailField(required=False) 
    message = forms.CharField(widget=forms.Textarea) 

```

还可以使用可选的`min_length`参数。

# 设置初始值

作为对这个表单的改进，让我们为`subject`字段添加一个初始值：`I love your site!`（一点点建议的力量不会有害）。为此，我们可以在创建`Form`实例时使用`initial`参数：

```py
def contact(request): 
    if request.method == 'POST': 
        form = ContactForm(request.POST) 
        if form.is_valid(): 
            cd = form.cleaned_data 
            send_mail( 
                cd['subject'], 
                cd['message'], 
                cd.get('email', 'noreply@example.com'), 
['siteowner@example.com'], 
            ) 
            return HttpResponseRedirect('/contact/thanks/') 
    else: 
        form = ContactForm( 
            initial={'subject': 'I love your site!'} 
        ) 
    return render(request, 'contact_form.html', {'form':form}) 

```

现在，`subject`字段将显示为预填充了这种陈述。请注意，传递初始数据和绑定表单的数据之间存在差异。最大的区别在于，如果你只是传递初始数据，那么表单将是未绑定的，这意味着它不会有任何错误消息。

# 自定义验证规则

想象一下，我们已经推出了我们的反馈表单，电子邮件已经开始涌入。只有一个问题：一些提交的消息只有一两个单词，这对我们来说不够长。我们决定采用一个新的验证策略：请至少四个单词。

有许多方法可以将自定义验证集成到 Django 表单中。如果我们的规则是我们将一遍又一遍地重用的，我们可以创建一个自定义字段类型。大多数自定义验证都是一次性的事务，可以直接绑定到`Form`类。我们想要在`message`字段上进行额外的验证，因此我们在`Form`类中添加了一个`clean_message()`方法：

```py
from django import forms 

class ContactForm(forms.Form): 
    subject = forms.CharField(max_length=100) 
    email = forms.EmailField(required=False) 
    message = forms.CharField(widget=forms.Textarea) 

    def clean_message(self): 
 message = self.cleaned_data['message'] 
 num_words = len(message.split()) 
 if num_words < 4: 
 raise forms.ValidationError("Not enough words!") 
 return message

```

Django 的表单系统会自动查找任何以`clean_`开头并以字段名称结尾的方法。如果存在这样的方法，它将在验证期间被调用。具体来说，`clean_message()`方法将在给定字段的默认验证逻辑之后被调用（在本例中，是必需的`CharField`的验证逻辑）。

因为字段数据已经部分处理，我们从`self.cleaned_data`中提取它。此外，我们不必担心检查该值是否存在且非空；这是默认验证器完成的。我们天真地使用`len()`和`split()`的组合来计算单词的数量。如果用户输入的单词太少，我们会引发一个`forms.ValidationError`。

附加到此异常的字符串将显示为错误列表中的一项。重要的是我们明确地在方法的最后返回字段的清理值。这允许我们在自定义验证方法中修改值（或将其转换为不同的 Python 类型）。如果我们忘记了返回语句，那么将返回`None`，并且原始值将丢失。

# 指定标签

默认情况下，Django 自动生成的表单 HTML 上的标签是通过用空格替换下划线并大写第一个字母来创建的-因此`email`字段的标签是"`Email`"。（听起来熟悉吗？这是 Django 模型用于计算字段默认`verbose_name`值的相同简单算法。我们在第四章中介绍过这一点，*模型*）。但是，与 Django 的模型一样，我们可以自定义给定字段的标签。只需使用`label`，如下所示：

```py
class ContactForm(forms.Form): 
    subject = forms.CharField(max_length=100) 
 email = forms.EmailField(required=False,
        label='Your e-mail address') 
    message = forms.CharField(widget=forms.Textarea)
```

# 自定义表单设计

我们的`contact_form.html`模板使用`{{ form.as_table }}`来显示表单，但我们可以以其他方式显示表单，以便更精细地控制显示。自定义表单的呈现方式最快的方法是使用 CSS。

错误列表，特别是可以通过一些视觉增强，并且自动生成的错误列表使用`<ul class="errorlist">`，这样你就可以用 CSS 来定位它们。以下 CSS 确实让我们的错误更加突出：

```py
<style type="text/css"> 
    ul.errorlist { 
        margin: 0; 
        padding: 0; 
    } 
    .errorlist li { 
        background-color: red; 
        color: white; 
        display: block; 
        font-size: 10px; 
        margin: 0 0 3px; 
        padding: 4px 5px; 
    } 
</style> 

```

虽然为我们生成表单的 HTML 很方便，但在许多情况下，您可能希望覆盖默认的呈现方式。`{{ form.as_table }}`和其他方法在开发应用程序时是有用的快捷方式，但表单的显示方式可以被覆盖，主要是在模板本身内部，您可能会发现自己这样做。

每个字段的小部件（`<input type="text">`，`<select>`，`<textarea>`等）可以通过在模板中访问`{{ form.fieldname }}`来单独呈现，并且与字段相关的任何错误都可以作为`{{ form.fieldname.errors }}`获得。

考虑到这一点，我们可以使用以下模板代码为我们的联系表单构建一个自定义模板：

```py
<html> 
<head> 
    <title>Contact us</title> 
</head> 
<body> 
    <h1>Contact us</h1> 

    {% if form.errors %} 
        <p style="color: red;"> 
            Please correct the error{{ form.errors|pluralize }} below. 
        </p> 
    {% endif %} 

    <form action="" method="post"> 
        <div class="field"> 
            {{ form.subject.errors }} 
            <label for="id_subject">Subject:</label> 
            {{ form.subject }} 
        </div> 
        <div class="field"> 
            {{ form.email.errors }} 
            <label for="id_email">Your e-mail address:</label> 
            {{ form.email }} 
        </div> 
        <div class="field"> 
            {{ form.message.errors }} 
            <label for="id_message">Message:</label> 
            {{ form.message }} 
        </div> 
        {% csrf_token %} 
        <input type="submit" value="Submit"> 
    </form> 
</body> 
</html> 

```

如果存在错误，`{{ form.message.errors }}`会显示一个`<ul class="errorlist">`，如果字段有效（或表单未绑定），则显示一个空字符串。我们还可以将`form.message.errors`视为布尔值，甚至可以将其作为列表进行迭代。例如：

```py
<div class="field{% if form.message.errors %} errors{% endif %}"> 
    {% if form.message.errors %} 
        <ul> 
        {% for error in form.message.errors %} 
            <li><strong>{{ error }}</strong></li> 
        {% endfor %} 
        </ul> 
    {% endif %} 
    <label for="id_message">Message:</label> 
    {{ form.message }} 
</div> 

```

在验证错误的情况下，这将在包含的`<div>`中添加一个“errors”类，并在无序列表中显示错误列表。

# 接下来呢？

本章结束了本书的介绍性材料-所谓的*核心课程* 本书的下一部分，第七章，*高级视图和 URLconfs*，到第十三章，*部署 Django*，将更详细地介绍高级 Django 用法，包括如何部署 Django 应用程序（第十三章，*部署 Django*）。在这七章之后，你应该已经了解足够的知识来开始编写自己的 Django 项目。本书中的其余材料将帮助您填补需要的空白。我们将从第七章开始，*高级视图和 URLconfs*，通过回顾并更仔细地查看视图和 URLconfs（首次介绍于第二章，*视图和 URLconfs*）。
