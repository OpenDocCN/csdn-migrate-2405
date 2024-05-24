# PHP Doctrine ORM 持久化（一）

> 原文：[`zh.annas-archive.org/md5/b34bd0528134548b9e95e991c08297b5`](https://zh.annas-archive.org/md5/b34bd0528134548b9e95e991c08297b5)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

Doctrine 2 已成为 PHP 最流行的现代持久化系统。它与 Symfony2 框架的标准版一起分发，可以独立在任何 PHP 项目中使用，并与 Zend Framework 2，CodeIgniter 或 Laravel 集成得非常好。它高效，自动抽象出流行的数据库管理系统，支持 PHP 5.3 功能（包括命名空间），可以通过 Composer 安装，并且具有经过广泛测试的高质量代码库。

Doctrine 的 ORM 库允许轻松持久化和检索 PHP 对象图，而无需手动编写任何 SQL 查询。它还提供了一个强大的面向对象的类似 SQL 的查询语言称为 DQL，一个数据库模式生成工具，一个事件系统等等。

为了发现这个必不可少的库，我们将一起构建一个典型的小型博客引擎。

# 本书涵盖的内容

第一章，“开始使用 Doctrine 2”，解释了如何通过 Composer 安装 Common，DBAL 和 ORM 库，获取我们的第一个实体管理器，并在介绍了我们在整本书中构建的项目之后配置命令行工具（Doctrine 的架构和开发环境的配置）。

第二章，“实体和映射信息”，介绍了 Doctrine 实体的概念。我们将创建第一个实体，使用注释将其映射到数据库，生成数据库模式，创建数据夹具，并最终奠定博客用户界面的基础。

第三章，“关联”，解释了如何处理 PHP 对象和 ORM 之间的关联。我们将创建新实体，详细说明一对一，一对多和多对多的关联，生成底层数据库模式，创建数据夹具，并在用户界面中使用关联。

第四章，“构建查询”，创建实体存储库，并帮助理解如何使用查询构建器生成 DQL 查询和检索实体。我们还将看一下聚合函数。

第五章，“更进一步”，将介绍 Doctrine 的高级功能。我们将看到 Doctrine 管理对象继承的不同方式，玩转实体生命周期事件，并创建本机 SQL 查询。

# 本书所需的内容

要执行本书的示例，您只需要 PHP 5.4+文本编辑器或 PHP IDE 以及您喜欢的浏览器。 

# 本书适合的读者

读者应该对面向对象编程，PHP（包括 PHP 5.3 和 5.4 中引入的功能）和一般数据库概念有很好的了解。

# 约定

在本书中，您会发现一些文本样式，用于区分不同类型的信息。以下是一些这些样式的示例，以及它们的含义解释。

文本中的代码词，数据库表名，文件夹名，文件名，文件扩展名，路径名，虚拟 URL 和用户输入显示如下：“`NativeQuery`类允许您执行本机 SQL 查询并将其结果作为 Doctrine 实体获取。”

代码块设置如下：

```php
    /**
     * Adds comment
     *
     * @param  Comment $comment
     * @return Post
     */
    public function addComment(Comment $comment)
    {
        $this->comments[] = $comment;
        $comment->setPost($this);

        return $this;
    }
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```php
    /**
     * Adds comment
     *
     * @param  Comment $comment
     * @return Post
     */
    public function addComment(Comment $comment)
    {
        $this->comments[] = $comment;
 **$comment->setPost($this);**

        return $this;
    }
```

任何命令行输入或输出都以以下方式编写：

```php
**# php bin/load-fixtures.php**

```

**新术语**和**重要单词**以粗体显示。例如，屏幕上显示的单词，例如菜单或对话框中的单词，会以这样的方式出现在文本中：“以下文本必须在终端中打印：**注意：此操作不应在生产环境中执行**。”

### 注意

警告或重要说明会出现在这样的框中。

### 提示

提示和技巧会以这样的方式出现。


# 第一章：开始使用 Doctrine 2

Doctrine 项目是一组库，提供了在 PHP 应用程序中轻松实现数据持久性的实用程序。它使得可以在很短的时间内创建与流行的 DBMS 兼容的复杂模型层，包括 SQLite、MySQL 和 PostgreSQL。为了发现和理解 Doctrine，我们将在本书中从头开始创建一个小型博客，主要使用以下 Doctrine 组件：

+   **Common**提供了 PHP 标准库中没有的实用程序，包括类自动加载器、注解解析器、集合结构和缓存系统。

+   **数据库抽象层**（**DBAL**）公开了一个独特的接口，用于访问流行的 DBMS。其 API 类似于 PDO（在可能的情况下使用 PDO）。DBAL 组件还能够通过内部重写查询来使用特定构造和模拟缺失功能，在不同的 DBMS 上执行相同的 SQL 查询。

+   **对象关系映射器**（**ORM**）允许通过面向对象的 API 访问和管理关系数据库表和行。借助它，我们将直接操作 PHP 对象，并且它将透明地生成 SQL 查询来填充、持久化、更新和删除它们。它是建立在 DBAL 之上的，并且将是本书的主要主题。

### 注意

有关 PHP 数据对象和 PHP 提供的数据访问抽象层的更多信息，请参考以下链接：[`php.net/manual/en/book.pdo.php`](http://php.net/manual/en/book.pdo.php)

为了学习 Doctrine，我们将一起构建一个具有以下高级功能的微型博客引擎：

+   帖子列表、创建、编辑和删除

+   评论

+   标签过滤

+   帖子和评论作者的配置文件

+   统计

+   数据夹具

以下是博客的屏幕截图：

![开始使用 Doctrine 2](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/prst-php-dct-orm/img/4104OS_01_01.jpg)

在本章中，我们将学习以下主题：

+   理解 Doctrine 背后的概念

+   创建项目的结构

+   安装 Composer

+   通过 Compose 安装 Doctrine ORM、DBAL 和 Common

+   引导应用程序

+   使用 Doctrine 的实体管理器

+   配置 Doctrine 命令行工具

# 先决条件

为了跟随本教程，我们需要正确安装 PHP 5.4 或更高版本的 CLI。我们还将使用`curl`命令来下载 Composer 存档和 SQLite 3 客户端。

### 注意

有关 PHP CLI、curl 和 SQLite 的更多信息，请参考以下链接：[`www.php.net/manual/en/features.commandline.php, http://curl.haxx.se`](http://www.php.net/manual/en/features.commandline.php, http://curl.haxx.se)和[`www.sqlite.org`](http://www.sqlite.org)

在示例中，我们将使用 PHP 内置的 Web 服务器和 SQLite 作为 DBMS。Doctrine 是一个纯 PHP 库。它与支持 PHP 的任何 Web 服务器兼容，但不限于 Apache 和 Nginx。当然，它也可以用于不打算在 Web 服务器上运行的应用程序，例如命令行工具。在数据库方面，官方支持 SQLite、MySQL、PostgreSQL、Oracle 和 Microsoft SQL Server。

由于 DBAL 组件，我们的博客应该可以在所有这些 DBMS 上正常工作。它已经在 SQLite 和 MySQL 上进行了测试。

Doctrine 项目还为 NoSQL 数据库（包括 MongoDB、CouchDB、PHPCR 和 OrientDB）提供了**对象文档映射器**（**ODM**）。这些主题不在本书中涵盖。

### 注意

在阅读本书时，请随时查阅以下链接中指定的 Doctrine 文档：[`www.doctrine-project.org`](http://www.doctrine-project.org)

# 理解 Doctrine 背后的概念

Doctrine ORM 实现了**数据映射器**和**工作单元**设计模式。

数据映射器是一个设计用来同步数据库中存储的数据与其领域层相关对象的层。换句话说，它执行以下操作：

+   从对象属性中插入和更新数据库中的行

+   当相关实体标记为删除时，删除数据库中的行

+   使用从数据库检索的数据来**水合**内存中的对象

### 注意

有关数据映射器和工作单元设计模式的更多信息，您可以参考以下链接：[`martinfowler.com/eaaCatalog/dataMapper.html`](http://martinfowler.com/eaaCatalog/dataMapper.html)和[`martinfowler.com/eaaCatalog/unitOfWork.html`](http://martinfowler.com/eaaCatalog/unitOfWork.html)

在 Doctrine 术语中，数据映射器称为**实体管理器**。实体是领域层的普通旧 PHP 对象。

由于实体管理器，它们不必知道它们将存储在数据库中。实际上，他们不需要知道实体管理器本身的存在。这种设计模式允许重用实体类，而不受持久性系统的影响。

出于性能和数据一致性的考虑，实体管理器不会在每次修改实体时将实体与数据库同步。工作单元设计模式用于保持数据映射器管理的对象的状态。只有在通过调用实体管理器的`flush()`方法请求时，数据库同步才会发生，并且在事务中进行（如果在将实体同步到数据库时出现问题，则数据库将回滚到同步尝试之前的状态）。

想象一个具有公共`$name`属性的实体。想象执行以下代码：

```php
  $myEntity->name = 'My name';
  $myEntity->name = 'Kévin';
  $entityManager->flush($myEntity);
```

由于工作单元设计模式的实现，Doctrine 只会发出类似以下的一个 SQL 查询：

```php
 **UPDATE MyEntity SET name='Kévin' WHERE id=1312;**

```

### 注意

出于性能原因，Doctrine 使用预处理语句，因此查询是相似的。

我们将以简要概述实体管理器方法及其相关实体状态来完成理论部分。

以下是表示实体及其实体管理器的类图的摘录：

![理解 Doctrine 背后的概念](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/prst-php-dct-orm/img/4104OS_01_02.jpg)

+   `find()`方法**水合**并返回第一个参数中**传递**的类型的实体，其第二个参数作为**标识符**。数据通过`SELECT`查询从数据库中检索。返回实体的状态为**受控**。这意味着在调用`flush()`方法时，对其进行的更改将同步到数据库。`find()`方法是一个方便的方法，它在内部使用**实体存储库**从数据库中检索数据并水合实体。受控实体的状态可以通过调用`detach()`方法更改为**分离**。对分离实体所做的修改将不会同步到数据库（即使调用`flush()`方法时也是如此），直到通过调用`merge()`方法将其状态设置回**受控**为止。

### 注意

第三章*关联*的开始将专门用于实体存储库。

+   `persist()`方法告诉 Doctrine 将传递的实体状态设置为受控。这仅对尚未至少一次同步到数据库的实体有用（新创建对象的默认状态为**new**），因为从现有数据中水合的实体自动具有受控状态。

+   `remove()`方法将传入实体的状态设置为**已删除**。与此实体相关的数据将在下次调用`flush()`方法时通过`DELETE` SQL 查询有效地从数据库中删除。

+   `flush()`方法将实体的数据与**受控**和**已删除**状态同步到数据库。Doctrine 将为同步发出`INSERT`，`UPDATE`和`DELETE` SQL 查询。在调用该方法之前，所有更改都仅在内存中，并且从未同步到数据库。

### 注意

Doctrine 的实体管理器有很多其他有用的方法，这些方法在 Doctrine 网站上有文档，[`www.doctrine-project.org/api/orm/2.4/class-Doctrine.ORM.EntityManager.html`](http://www.doctrine-project.org/api/orm/2.4/class-Doctrine.ORM.EntityManager.html)。

目前这是抽象的，但是我们将通过本书中的许多示例更好地理解实体管理器的工作原理。

# 创建项目结构

以下是我们应用程序的文件夹结构：

+   `blog/`：之前创建的应用根目录

+   `bin/`：我们博客应用程序的特定命令行工具

+   `config/`：我们应用程序的配置文件

+   `data/`：SQLite 数据库将存储在这里

+   `src/`：我们编写的所有 PHP 类将在这里

+   `vendor/`：这是**Composer**（见下一节）存储所有已下载依赖项的地方，包括 Doctrine 的源代码

+   `bin/`：这是由 Composer 安装的依赖项提供的命令行工具

+   `web/`：这是包含 PHP 页面和资产（如图像、CSS 和 JavaScript 文件）的公共目录

我们必须创建所有这些目录，除了`vendor/`，它将在以后自动生成。

# 安装 Composer

与大多数现代 PHP 库一样，Doctrine 可以通过 Composer 获得，这是一个强大的依赖管理器。还有一个 PEAR 频道可用。

### 注意

有关 Composer 和 Pear 软件包的更多信息，请参考以下链接：[`getcomposer.org`](http://getcomposer.org) 和 [`pear.doctrine-project.org`](http://pear.doctrine-project.org)

安装 Composer 应执行以下步骤：

1.  安装 Doctrine ORM 的第一步是获取最新版本的 Composer。

1.  打开您喜欢的终端，转到`blog/`目录（我们项目的根目录），并输入以下命令来安装 Composer：

```php
 **curl -sS https://getcomposer.org/installer | php**

```

一个名为`composer.phar`的新文件已经在目录中下载。这是 Composer 的一个自包含存档。

1.  现在输入以下命令：

```php
 **php composer.phar**

```

如果一切正常，将列出所有可用的命令。您的 Composer 安装已经准备就绪！

# 安装 Doctrine

安装 Doctrine 应执行以下步骤：

1.  要安装 Doctrine，我们需要在新的`blog`目录中创建一个名为`composer.json`的文件。它列出了我们项目的依赖项，如下面的代码所示：

```php
{
    "name": "myname/blog",
    "type": "project",
    "description": "My small blog to play with Doctrine",

    "require": {
 **"doctrine/orm": "2.4.*"**
    },

    "autoload": {
 **"psr-0": { "": "src/" }**
    }
} 
```

Composer 将解析这个标准的 JSON 文件，以下载和安装所有指定的依赖项。一旦安装完成，Composer 将自动加载这些库的所有类。

`name`、`type`和`description`属性是可选的，但最好总是填写它们。它们提供了关于我们正在开发的项目的一般信息。

这个`composer.json`文件更有趣的部分是`require`字段。为了让 Composer 安装它，我们应用程序使用的所有库都必须在这里列出。许多 PHP 库都可以在**Packagist**上找到，这是默认的 Composer 包存储库。当然，Doctrine 项目也是如此。

### 注意

有关 Packagist 的更多信息，请访问以下链接：[`packagist.org/`](https://packagist.org/)

我们指定需要 Doctrine ORM 2.4 分支的最新次要版本。您可以在这里设置主要或次要版本，甚至更复杂的东西。

### 注意

有关软件包版本的更多信息，请参考以下链接：[`getcomposer.org/doc/01-basic-usage.md#package-versions`](http://getcomposer.org/doc/01-basic-usage.md#package-versions)

`autoload`字段在这里告诉 Composer 自动加载我们应用程序的类。我们将把我们的特定代码放在一个名为`src/`的目录中。我们的文件和类将遵循`PSR-0`命名空间和文件命名标准。

### 注意

PHP 规范请求是为了改进 PHP 应用程序和库的互操作性而尝试的。它们可以在[`www.php-fig.org/`](http://www.php-fig.org/)找到。

1.  现在是使用 Composer 来安装 ORM 的时候了。运行以下命令：

```php
 **php composer.phar install**

```

`vendor/`目录中出现了新文件。Doctrine ORM 已经安装，Composer 足够智能，可以获取所有它的依赖，包括 Doctrine DBAL 和 Doctrine Common。

还创建了一个`composer.lock`文件。它包含已安装库的确切版本。这对于部署应用程序很有用。有了这个文件，运行`install`命令时，Composer 将能够检索与开发中使用的相同版本。

Doctrine 现在已经正确安装。很容易，不是吗？

1.  要在 2.4 分支中有新版本发布时更新库，我们只需要输入以下命令：

```php
 **php composer.phar update**

```

# 引导应用程序

需要执行以下步骤来引导应用程序：

1.  创建一个名为`config/config.php`的新文件，其中包含我们应用程序的配置参数，如下所示：

```php
  <?php

  // App configuration
  $dbParams = [
    'driver' => 'pdo_sqlite',
    'path' => __DIR__.'/../data/blog.db'
  ];

  // Dev mode?
  $dev = true;
```

Doctrine 的配置参数存储在`$dbParams`数组中。我们将使用一个名为`blog.db`的 SQLite 数据库，存储在`data/`目录中。如果你想使用 MySQL 或任何其他 DBMS，你将在这里配置要使用的驱动程序、数据库名称和访问凭据。

### 注意

以下是使用 MySQL 而不是 SQLite 的示例配置：

```php
$dbParams = [
    'driver' => 'pdo_mysql',
    'host' => '127.0.0.1',
    'dbname' => 'blog',
    'user' => 'root',
    'password' => ''
];
```

配置键是不言自明的。

如果`$dev`变量为`true`，一些优化将被禁用以便于调试。禁用`dev`模式允许 Doctrine 将大量数据（如元数据）放入强大的缓存中，以提高应用程序的整体性能。

### 注意

它需要缓存驱动程序的安装和额外的配置，可在[`docs.doctrine-project.org/en/latest/reference/caching.html`](http://docs.doctrine-project.org/en/latest/reference/caching.html)找到。

1.  接下来，我们需要一种方法来引导我们的应用程序。在`src/`目录中创建一个名为`bootstrap.php`的文件。这个文件将加载我们需要的一切，如下面的代码所示：

```php
  <?php

  require_once __DIR__.'/../vendor/autoload.php';
  require_once __DIR__.'/../config/config.php';
```

第一行需要 Composer 自动加载程序。它允许您自动加载 Doctrine 的类、项目的类（将在`src/`目录中），以及使用 Composer 安装的任何库的类。

第二行导入了应用程序的配置文件。项目结构已创建，应用程序的初始化过程已完成。我们准备开始使用 Doctrine。

# 使用 Doctrine 的实体管理器

ORM 的原则是通过面向对象的 API 管理存储在关系数据库中的数据。我们在本章的前面已经了解了它的基本概念。

每个实体类都映射到相关的数据库表。实体类的属性映射到表的列。

因此，数据库表的行在 PHP 应用程序中由一组实体表示。

Doctrine ORM 能够从数据库中检索数据并用它们填充实体。这个过程称为水合。

### 注意

Doctrine 可以以不同的方式填充 PHP 数组（使用对象图、使用矩形结果集等）。还可以通过参考以下链接创建自定义水合器：[`docs.doctrine-project.org/en/latest/reference/dql-doctrine-query-language.html#hydration-modes`](http://docs.doctrine-project.org/en/latest/reference/dql-doctrine-query-language.html#hydration-modes)

正如我们在数据映射器设计模式中学到的，它也做了相反的工作：将实体持有的数据持久化到数据库中。

我们以后会大量使用实体。

Doctrine 附带以下文件来将实体映射到表：

+   注释块中的注解直接嵌入实体

+   XML 配置文件

+   YAML 配置文件

+   纯 PHP 文件

注释在 PHP 世界中是相当新的（它们在 Java 中很受欢迎），但它们已经被 Doctrine 和 Symfony 社区广泛使用。这种方法的优势在于代码旁边的映射信息，使得代码易读且易于维护。但是，在某些情况下，直接将映射信息放入代码中也可能是一个缺点，特别是对于使用多个持久性系统的大型项目。

在本书中，我们将使用注释方法，但 Doctrine 文档中还描述了其他方法。我们将在第二章中返回它们，*实体和映射信息*。

在下一章，第二章中，*实体和映射信息*，我们将发现 Doctrine 足够智能，可以使用映射信息自动创建相关的数据库模式。

现在，我们将专注于检索实体管理器。因为实体是通过它检索、持久化、更新和删除的，这是 Doctrine ORM 的入口点。

编辑`src/bootstrap.php`文件以检索 Doctrine 的实体管理器。在文件末尾添加以下代码：

```php
  $entitiesPath = array(__DIR__.'/Blog/Entity');
  $config = **Setup::createAnnotationMetadataConfiguration**    **($entitiesPath, $dev);**
  $entityManager = **EntityManager::create**($dbParams, $config);
```

### 提示

**下载示例代码**

您可以从您在[`www.packtpub.com`](http://www.packtpub.com)购买的所有 Packt 图书的帐户中下载示例代码文件。如果您在其他地方购买了本书，您可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)注册并直接通过电子邮件接收文件。

`$entitiesPath`属性包含存储实体类的目录路径列表。我们已经提到我们的应用程序将遵循`PSR-0`命名空间约定。`\Blog`文件夹将是根命名空间，实体类将在`\Blog\Entity`文件夹中。

创建了一个 Doctrine 配置，用于使用注释进行映射信息，并能够定位我们将创建的博客实体。

创建并配置了一个新的`EntityManager`，以使用我们的数据库和 Doctrine 设置。

为简单起见，我们创建了一个在整个应用程序中将被使用的唯一实体管理器。对于真实世界的应用程序，您应该查看依赖注入设计模式。

### 注意

在以下链接找到有关依赖注入模式的更多信息：[`en.wikipedia.org/wiki/Dependency_injection`](http://en.wikipedia.org/wiki/Dependency_injection)

# 配置 Doctrine 命令行工具

Doctrine 库捆绑了一些有用的命令行工具。它们提供了许多有用的功能，包括但不限于根据实体映射创建数据库模式的能力。

Composer 已经在`vendor/bin/`目录中安装了 Doctrine 的命令行工具。但是，在能够使用它们之前，必须进行一些配置。命令行工具内部使用实体管理器。我们需要告诉它们如何检索它。

在这里，我们只需要在`config/`目录中创建一个名为`cli-config.php`的文件，如下所示：

```php
  <?php

// Doctrine CLI configuration file

use Doctrine\ORM\Tools\Console\ConsoleRunner;

require_once __DIR__.'/../src/bootstrap.php';

return ConsoleRunner::createHelperSet($entityManager);
```

由于 Doctrine 的约定，该文件将被自动检测并被 Doctrine CLI 使用。

### 注意

命令行工具将在当前目录和`config/`目录中查找名为`cli-config.php`的文件。

该文件只是使用我们之前创建的实用类获取一个新的实体管理器，并配置 Doctrine CLI 以使用它。

键入以下命令以获取可用的 Doctrine 命令列表：

```php
 **php vendor/bin/doctrine.php**

```

# 总结

在本章中，我们了解了 Doctrine 的基础知识。我们现在知道了实体和实体管理器是什么，我们已经使用 Composer 依赖管理器安装了 Doctrine，创建了博客应用程序的框架，并成功运行了命令行工具。

在下一章中，我们将创建我们的第一个实体类，发现许多注解来将其映射到数据库，生成数据库架构，并开始处理实体。到下一章结束时，我们博客的发布系统将会运作！


# 第二章：实体和映射信息

在上一章中，我们了解了 Doctrine 背后的概念，学习了如何使用 Composer 进行安装，设置了 Doctrine 命令行工具，并深入了解了实体管理器。

在本章中，我们将涵盖以下主题：

+   创建我们的第一个实体类

+   使用注释将其映射到相关的数据库表和列

+   使用 Doctrine 提供的命令助手自动生成数据库模式

+   创建一些固定数据，并处理实体管理器以在 Web 用户界面中显示我们的数据

因为我们正在构建一个博客，我们的主要实体类将被称为`Post`，如下图所示：

![实体和映射信息](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/prst-php-dct-orm/img/4104OS_02_01.jpg)

我们的`Post`实体类具有以下四个属性：

+   `id`：跨数据库表（和博客）的帖子的唯一标识符

+   `title`：帖子的标题

+   `body`：帖子的正文

+   `publicationDate`：帖子的发布日期

# 创建实体类

如第一章*开始使用 Doctrine 2*中所述，Doctrine 实体只是将保存在数据库中的 PHP 对象。Doctrine 注释添加在实体类属性的 PHP `DocBlock`注释中。Doctrine 使用注释将对象映射到相关的数据库表和属性到列。

### 注意

**DocBlocks**的最初目的是将技术文档直接集成到源代码中。解析 DocBlocks 的最流行的文档生成器是**phpDocumentator**，可以在此网站上找到：[`www.phpdoc.org`](http://www.phpdoc.org)。

每个实体一旦通过 Doctrine 持久化，将与数据库表的一行相关联。

在`src/Blog/Entity/`位置创建一个名为`Post.php`的新文件，其中包含以下代码的实体类：

```php
  <?php

  namespace Blog\Entity;

  use Doctrine\ORM\Mapping\Entity;
  use Doctrine\ORM\Mapping\Table;
  use Doctrine\ORM\Mapping\Index;
  use Doctrine\ORM\Mapping\Id;
  use Doctrine\ORM\Mapping\GeneratedValue;
  use Doctrine\ORM\Mapping\Column;

  /**
   * Blog Post entity
   *
   * **@Entity**
   * **@Table(indexes={**
   * **@Index(name="publication_date_idx",**    **columns="publicationDate")**
   * })
   */
  class Post
  {
    /**
     * @var int
     *
     * **@Id**
     * **@GeneratedValue**
     * **@Column(type="integer")**
     */
    protected $id;
    /**
     * @var string
     *
     * **@Column(type="string")**
     */
    protected $title;
    /**
     * @var string
     *
     * **@Column(type="text")**
     */
    protected $body;
    /**
     * @var \DateTime
     *
     * **@Column(type="datetime")**
     */
    protected $publicationDate;
  }
```

# 生成 getter 和 setter

我们在第一章*开始使用 Doctrine 2*中配置的 Doctrine 命令行工具包括一个有用的命令，用于为我们生成实体类的 getter 和 setter 方法。我们将使用它来避免编写`Post`类的 getter 和 setter 方法。

运行以下命令，生成应用程序所有实体类的 getter 和 setter：

```php
 **php vendor/bin/doctrine.php orm:generate:entities src/**

```

### 注意

如果您有多个实体，不想为所有实体生成 getter 和 setter，请使用`orm:generate:entities`命令的`filter`选项。

# 使用 Doctrine 注释进行映射

`Post`是一个简单的类，有四个属性。`$id`的 setter 实际上并没有被生成。Doctrine 在实体解析阶段直接填充`$id`实例变量。我们稍后会看到如何将 ID 生成委托给 DBMS。

Doctrine 注释从`\Doctrine\ORM\Mapping`命名空间导入，使用`use`语句。它们用于在 DocBlocks 中为类及其属性添加映射信息。DocBlocks 只是以`/**`开头的一种特殊的注释。

## 了解`@Entity`注释

`@Entity`注释用于类级别的 DocBlock 中，指定此类是实体类。

此注释的最重要属性是`repositoryClass`。它允许指定自定义实体存储库类。我们将在第四章*构建查询*中学习有关实体存储库的知识，包括如何制作自定义存储库。

## 理解`@Table`、`@Index`和`@UniqueConstraint`注释

`@Table`注释是可选的。它可用于向与实体类相关的表添加一些映射信息。

相关的数据库表名默认为实体类名。在这里，它是`Post`。可以使用注释的`name`属性进行更改。让 Doctrine 自动生成表和列名称是一个好习惯，但更改它们以匹配现有模式可能会很有用。

正如您所看到的，我们使用`@Table`注释在底层表上创建索引。为此，我们使用一个名为`indexes`的属性，其中包含索引列表。每个索引由`@Index`注释定义。每个`@Index`必须包含以下两个属性：

+   `name`：索引的名称

+   `columns`：索引列的列表

对于`Post`实体类，我们在`publicationDate`列上创建一个名为`publication_date_idx`的索引。

`@Table`注释的最后一个可选属性是`uniqueConstraints`（此处未使用）。它允许在列和列组上创建 SQL 级别的唯一约束。其语法类似于`@Index：name`来命名约束和`columns`来指定应用约束的列。

此属性仅由模式生成器使用。即使使用了`uniqueConstraints`属性，Doctrine 也不会自动检查值在整个表中是否唯一。底层的 DBMS 将会执行此操作，但可能会导致 DBMS 级别的 SQL 错误。如果我们想要强制数据的唯一性，我们应该在保存新数据之前执行检查。

## 深入了解@Column 注释

每个属性都通过`@Column`注释映射到数据库列。

映射的数据库列的名称默认为属性名称，但可以使用`name`参数进行更改。与表名一样，最好让 Doctrine 自动生成名称。

### 注意

与表名的情况一样，列名将默认为实体类属性名（如果正确遵循 PSR 样式，则为驼峰命名法）。

Doctrine 还提供了下划线命名策略（例如，与名为`MyEntity`的类相关的数据库表将是`my_entity`），并且可以编写自定义策略。

在 Doctrine 文档中了解更多信息：[`docs.doctrine-project.org/en/latest/reference/namingstrategy.html`](http://docs.doctrine-project.org/en/latest/reference/namingstrategy.html)

如果属性没有标记为`@Column`注释，Doctrine 将忽略它。

其`type`属性指示列的 Doctrine 映射类型（请参阅下一节）。这是此注释的唯一必需属性。

此注释支持一些更多的属性。与其他注释一样，支持的属性的完整列表可在 Doctrine 文档中找到。最重要的属性如下：

+   `unique`：如果为`true`，则此列的值必须在相关数据库表中是唯一的

+   `nullable`：如果为`false`，则值可以是`NULL`。默认情况下，列不能是`NULL`。

+   `length`：`string`类型的列的长度

+   `scale`：`decimal`类型的列的比例

+   `precision`：`decimal`类型的列的精度

与`@Table`一样，Doctrine 不使用`@Column`注释的属性来验证数据。这些属性仅用于映射和生成数据库模式。没有其他用途。出于安全和用户体验的原因，您必须验证用户提供的每一条数据。本书不涵盖此主题。如果您不想手动处理数据验证，请尝试来自[`symfony.com/components/Validator`](http://symfony.com/components/Validator)的 Symfony 验证器组件。

### 注意

也可以使用生命周期事件（参见第五章，“进一步”）来处理数据验证：[`docs.doctrine-project.org/projects/doctrine-orm/en/latest/cookbook/validation-of-entities.html`](http://docs.doctrine-project.org/projects/doctrine-orm/en/latest/cookbook/validation-of-entities.html)

## 了解@Id 和@GeneratedValue 注释

`$id`属性有点特殊。这是一个映射到整数的列，但这主要是我们对象的唯一标识符。

通过`@Id`注释，此列将被用作表的主键。

默认情况下，开发人员负责确保此属性的值在整个表中是唯一的。几乎所有的 DBMS 都提供了在插入新行时自动递增标识符的机制。`@GeneratedValue`注释利用了这一点。当属性标记为`@GeneratedValue`时，Doctrine 将把标识符的生成委托给底层的 DBMS。

### 注意

其他 ID 生成策略可在[`docs.doctrine-project.org/en/latest/reference/basic-mapping.html#identifier-generation-strategies`](http://docs.doctrine-project.org/en/latest/reference/basic-mapping.html#identifier-generation-strategies)找到。

Doctrine 还支持复合主键。只需在复合主键的所有列上添加`@Id`注释。

我们将在第三章中学习另一个例子，使用唯一字符串作为标识符，*关联*。

## 使用其他注释

存在许多 Doctrine 映射注释。我们将在第三章中使用一些新的注释，*关联*，以创建实体之间的关系。

可在 Doctrine 文档中找到所有可用注释的完整列表，网址为[`docs.doctrine-project.org/projects/doctrine-orm/en/latest/reference/annotations-reference.html`](http://docs.doctrine-project.org/projects/doctrine-orm/en/latest/reference/annotations-reference.html)。

# 了解 Doctrine 映射类型

在`@Column`注释中使用的 Doctrine 映射类型既不是 SQL 类型也不是 PHP 类型，但它们都被映射到。例如，Doctrine 的`text`类型将被转换为实体中的`string` PHP 类型，并存储在具有`CLOB`类型的数据库列中。

以下是 Doctrine 映射类型的 PHP 类型和 SQL 类型的对应表：

| Doctrine 映射类型 | PHP 类型 | SQL 类型 |
| --- | --- | --- |
| `string` | `string` | `VARCHAR` |
| `integer` | `integer` | `INT` |
| `smallint` | `integer` | `SMALLINT` |
| `bigint` | `string` | `BIGINT` |
| `boolean` | `boolean` | `BOOLEAN` |
| `decimal` | `double` | `DECIMAL` |
| `date` | `\DateTime` | `DATETIME` |
| `time` | `\DateTime` | `TIME` |
| `datetime` | `\DateTime` | `DATETIME`或`TIMESTAMP` |
| `text` | `string` | `CLOB` |
| `object` | 使用`serialize()`和`unserialize()`方法的对象 | `CLOB` |
| `array` | 使用`serialize()`和`unserialize()`方法的`array` | `CLOB` |
| `float` | `double` | `FLOAT`（双精度） |
| `simple_array` | 使用`implode()`和`explode()`的`array`，值不能包含逗号 | `CLOB` |
| `json_array` | 使用`json_encode()`和`json_decode()`方法的`object` | `CLOB` |
| `guid` | `string` | 如果 DBMS 支持`GUID`或`UUID`，则为`GUID`，否则为`VARCHAR` |
| `blob` | `resource stream`（参见[`www.php.net/manual/en/language.types.resource.php`](http://www.php.net/manual/en/language.types.resource.php)） | `BLOB` |

### 注意

请记住，我们可以创建自定义类型。要了解更多信息，请参阅：[`docs.doctrine-project.org/en/latest/cookbook/custom-mapping-types.html`](http://docs.doctrine-project.org/en/latest/cookbook/custom-mapping-types.html)

# 创建数据库模式

Doctrine 足够智能，可以生成与实体映射信息相对应的数据库模式。

### 注意

在设计相关数据库模式之前，首先设计实体是一个很好的做法。

为此，我们将再次使用第一章安装的命令行工具。在项目的根目录中键入以下命令：

```php
 **php vendor/bin/doctrine.php orm:schema-tool:create**

```

以下文本必须在终端中打印：

**注意：此操作不应在生产环境中执行。**

**创建数据库模式...**

**数据库模式创建成功！**

数据库中创建了一个名为`Post`的新表。您可以使用 SQLite 客户端来显示生成的表的结构：

```php
 **sqlite3 data/blog.db ".schema Post"**

```

它应该返回以下查询：

```php
  CREATE TABLE Post (id INTEGER NOT NULL, title VARCHAR(255) NOT NULL, body CLOB NOT NULL, publicationDate DATETIME NOT NULL, PRIMARY KEY(id));
  CREATE INDEX publication_date_idx ON Post (publicationDate);
```

以下屏幕截图是表 Post 的结构：

![创建数据库模式](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/prst-php-dct-orm/img/4104OS_02_02.jpg)

Doctrine 也能够为 MySQL 和其他支持的 DBMS 生成模式。如果我们配置我们的应用程序使用 MySQL 服务器作为 DBMS，并运行相同的命令，生成的表将类似于以下屏幕截图：

![创建数据库模式](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/prst-php-dct-orm/img/4104OS_02_03.jpg)

# 安装数据 fixtures

**Fixtures**是允许在每次安装后无需手动创建数据就可以测试应用程序的虚假数据。它们对自动化测试过程很有用，并且使新开发人员更容易开始在我们的项目上工作。

### 注意

任何应用程序都应该有自动化测试。我们正在构建的博客应用程序由 Behat（[`behat.org/`](http://behat.org/)）测试覆盖。它们可以在 Packt 网站提供的下载中找到。

Doctrine 有一个名为 Data Fixtures 的扩展，可以简化 fixtures 的创建。我们将安装它并使用它来创建一些虚假的博客帖子。

在项目的根目录中键入以下命令，通过 Composer 安装 Doctrine Data Fixtures：

```php
  php composer.phar require doctrine/data-fixtures:1.0.*
```

使用 Doctrine Data Fixtures 的第一步是创建一个 fixture 类。在`src/Blog/DataFixtures`目录中创建一个名为`LoadPostData.php`的文件，如下面的代码所示：

```php
  <?php

  namespace Blog\DataFixtures;

  use Blog\Entity\Post;
  use Doctrine\Common\DataFixtures\FixtureInterface;
  use Doctrine\Common\Persistence\ObjectManager;

  /**
   * Post fixtures
   */
  class LoadPostData implements **FixtureInterface**
  {
    /**
     * Number of posts to add
     */
    const NUMBER_OF_POSTS = 10;

    /**
     * {@inheritDoc}
     */
    public function **load(ObjectManager $manager)**
    {
        for ($i = 1; $i <= self::NUMBER_OF_POSTS; $i++) {
            $post = **new Post()**;
            $post
                **setTitle**(sprintf('Blog post number %d', $i))
                **setBody**(<<<EOTLorem ipsum dolor sit amet, consectetur adipiscing elit.EOT
                )
                **setPublicationDate**(**new \DateTime**(sprintf('-%d days', self::NUMBER_OF_POSTS - $i)))
            ;

            **$manager->persist($post);**
        }

        **$manager->flush();**
    }
}
```

这个`LoadPostData`类包含创建虚假数据的逻辑。它创建了十篇博客帖子，其中包括生成的标题、发布日期和正文。

`LoadPostData`类实现了`\Doctrine\Common\DataFixtures\FixtureInterface`目录中定义的`load()`方法。这个方法接受一个`EntityManager`实例的参数：

+   第一章的一些提醒，*使用 Doctrine 2 入门*：调用`EntityManager::persist()`将每个新实体的状态设置为已管理

+   在过程结束时，调用`flush()`方法将使 Doctrine 执行`INSERT`查询，有效地保存数据到数据库中

我们仍然需要为我们的 fixtures 类创建一个加载器。在项目的`bin/`目录中创建一个名为`load-fixtures.php`的文件，并使用以下代码：

```php
  <?php

  require_once __DIR__.'/../src/bootstrap.php';

  use Doctrine\Common\DataFixtures\Loader;
  use Doctrine\Common\DataFixtures\Purger\ORMPurger;
  use Doctrine\Common\DataFixtures\Executor\ORMExecutor;

 **$loader = new Loader();**
 **$loader->loadFromDirectory(__DIR__.'/../src/Blog/DataFixtures');**

 **$purger = new ORMPurger();**
 **$executor = new ORMExecutor($entityManager, $purger);**
  $executor->execute($loader->getFixtures());
```

在这个实用程序中，我们初始化我们的应用程序并按照第一章中的说明获取实体管理器，*使用 Doctrine 2 入门*。然后，我们实例化了 Doctrine Data Fixtures 提供的 fixtures 加载器，并告诉它在哪里找到我们的 fixtures 文件。

目前我们只有`LoadPostData`类，但我们将在接下来的章节中创建额外的 fixtures。

`ORMExecutor`方法被实例化并执行。它使用`ORMPurger`从数据库中删除现有数据。然后它用我们的 fixtures 填充数据库。

在我们项目的根目录中运行以下命令来加载我们的 fixtures：

```php
 **php bin/load-fixtures.php**

```

我们的 fixtures 已经插入到数据库中。请注意，每次运行此命令时，数据库中的所有数据都将被永久删除。

检查我们的数据库是否已经用以下命令填充：

```php
 **sqlite3 data/blog.db "SELECT * FROM Post;"**

```

您应该看到十行类似于以下内容的行：

**1|博客帖子编号 1|Lorem ipsum dolor sit amet，consectetur adipiscing elit。|2013-11-08 20:01:13**

**2|博客帖子编号 2|Lorem ipsum dolor sit amet，consectetur adipiscing elit。|2013-11-09 20:01:13**

# 创建一个简单的 UI

我们将创建一个简单的 UI 来处理我们的帖子。这个界面将让我们创建、检索、更新和删除博客帖子。你可能已经猜到我们将使用实体管理器来做到这一点。

为了简洁并专注于 Doctrine 部分，这个 UI 将有很多缺点。*它不应该在任何生产或公共服务器上使用*。主要问题如下：

+   **一点也不安全**：每个人都可以访问一切，因为没有认证系统，没有数据验证，也没有 CSRF 保护

+   **设计不良**：没有关注点分离，没有使用类似 MVC 的模式，没有 REST 架构，没有面向对象的代码等等。

当然，这将是…图形上极简主义的！

+   跨站点请求伪造（CSRF）：[`en.wikipedia.org/wiki/Cross-site_request_forgery`](http://en.wikipedia.org/wiki/Cross-site_request_forgery)

+   关注点分离：[`en.wikipedia.org/wiki/Separation_of_concerns`](http://en.wikipedia.org/wiki/Separation_of_concerns)

+   模型-视图-控制器（MVC）元模式：[`en.wikipedia.org/wiki/Model-view-controller`](http://en.wikipedia.org/wiki/Model-view-controller)

+   表述状态转移（REST）：[`en.wikipedia.org/wiki/Representational_state_transfer`](http://en.wikipedia.org/wiki/Representational_state_transfer)

对于真实世界的应用程序，您应该看一下 Symfony，这是一个强大的框架，包括 Doctrine 和大量功能（已经介绍了验证组件，表单框架，模板引擎，国际化系统等）：[`symfony.com/`](http://symfony.com/)

## 列出帖子

话虽如此，在`web/index.php`文件中创建列出帖子的页面，代码如下：

```php
  <?php

  /**
   * Lists all blog posts
   */

  require_once __DIR__.'/../src/bootstrap.php';

  /** @var $posts \Blog\Entity\Post[] Retrieve the list of all blog posts */
  **$posts = $entityManager->getRepository('Blog\Entity\Post')-**    **>findAll();**
  ?>

  <!DOCTYPE html>
  <html>
  <head>
    <meta charset="utf-8">
    <title>My blog</title>
  </head>
  <body>
  <h1>My blog</h1>

 **<?php foreach ($posts as $post): ?>**
    <article>
        <h1>
            <?=htmlspecialchars(**$post->getTitle()**)?>
        </h1>
        Date of publication: <?=**$post->getPublicationDate()->format('Y-m-d H:i:s')**?>

        <p>
            <?=nl2br(htmlspecialchars(**$post->getBody()**))?>
        </p>

        <ul>
            <li>
                <a href="edit-post.php?id=<?=**$post->getId()**?>">Edit this post</a>
            </li>
            <li>
                <a href="delete-post.php?id=<?=**$post->getId()**?>">Delete this post</a>
            </li>
        </ul>
    </article>
  <?php endforeach ?>
  <?php if (empty($posts)): ?>
    <p>
        No post, for now!
    </p>
  <?php endif ?>

  <a href="edit-post.php">
    Create a new post
  </a>
  </html>
```

这个第一个文件是博客的主页面。它列出所有帖子，并显示链接到创建、更新或删除帖子的页面。

在应用程序初始化之后，我们使用我们在第一章中编写的代码来获取`EntityManager`以配置命令行工具。

我们使用这个`EntityManager`来检索我们的`\Blog\Entity\Post`实体的存储库。目前，我们使用 Doctrine 提供的默认实体存储库。我们将在第四章中了解更多关于它们的信息，*构建查询*。这个默认存储库提供了一个`findAll()`方法，用于检索从数据库中获取的所有实体的集合。

### 注意

`Collection`接口类似于常规的 PHP 数组（带有一些增强功能）。这个类是 Doctrine Common 的一部分：[`www.doctrine-project.org/api/common/2.4/class-Doctrine.Common.Collections.Collection.html`](http://www.doctrine-project.org/api/common/2.4/class-Doctrine.Common.Collections.Collection.html)

调用它时，Doctrine 将查询数据库以查找`Post`表的所有行，并使用检索到的数据填充`\Blog\Entity\Post`对象的集合。这个集合被分配给`$posts`变量。

要浏览此页面，请在项目的根目录中运行以下命令：

```php
  php -S localhost:8000 -t web/
```

这将运行内置的 PHP Web 服务器。在您喜欢的 Web 浏览器中转到`http://localhost:8000`，您将看到我们的十个虚假帖子。

### 注意

如果不起作用，请确保您的 PHP 版本至少为 5.4。

## 创建和编辑帖子

是时候创建一个页面来添加新的博客帖子了。将其放在`web/edit-post.php`文件中，如下面的代码所示：

```php
  <?php

  /**
   * Creates or edits a blog post
   */

  use Blog\Entity\Post;

  require_once __DIR__.'/../src/bootstrap.php';

  // Retrieve the blog post if an id parameter exists
  if (isset ($_GET['id'])) {
    /** @var Post $post The post to edit */
    **$post = $entityManager->find('Blog\Entity\Post', $_GET['id']);**

    if (!$post) {
        throw new \Exception('Post not found');
    }
}

  // Create or update the blog post
  if ('POST' === $_SERVER['REQUEST_METHOD']) {
    // Create a new post if a post has not been retrieved and set its date of publication
    if (!isset ($post)) {
 **$post = new Post();**
        // Manage the entity
 **$entityManager->persist($post);**

 **$post->setPublicationDate(new \DateTime());**
    }

 **$post**
 **->setTitle($_POST['title'])**
 **->setBody($_POST['body'])**
 **;**

    // Flush changes to the database
 **$entityManager->flush();**

    // Redirect to the index
    header('Location: index.php');
    exit;
}

  /** @var string Page title */
  $pageTitle = isset ($post) ? sprintf('Edit post #%d', $post->getId()) : 'Create a new post';
  ?>

  <!DOCTYPE html>
  <html>
  <head>
    <meta charset="utf-8">
    <title><?=$pageTitle?> - My blog</title>
  </head>
  <body>
  <h1>
    <?=$pageTitle?>
  </h1>

  <form method="POST">
    <label>
        Title
        <input type="text" name="title" value="<?=isset ($post) ? htmlspecialchars($post->getTitle()) : ''?>" maxlength="255" required>
    </label><br>

    <label>
        Body
        <textarea name="body" cols="20" rows="10" required><?=isset ($post) ? htmlspecialchars($post->getBody()) : ''?></textarea>
    </label><br>

    <input type="submit">
  </form>

  <a href="index.php">Back to the index</a>
```

这个页面有点棘手：

+   在 URL 中带有`id`参数时，它会处理具有给定 ID 的`Post`实体

### 注意

最佳实践是使用 slug 而不是标识符。它们隐藏了应用程序的内部，可以被人类记住，并且对于搜索引擎优化更好：[`en.wikipedia.org/wiki/Slug_(publishing)`](http://en.wikipedia.org/wiki/Slug_(publishing))。

+   没有`id`参数时，它会实例化一个新的`Post`实体

+   当使用`GET` HTTP 方法调用时，它会显示一个填充有当前`Post`数据的表单，以进行编辑

+   当使用`Post` HTTP 方法（当表单被提交时）时，它会创建或更新`Post`实体，然后重定向到博客的主页

如果通过 URL 提供了 ID，则实体管理器的`find()`方法用于检索存储在数据库中的具有此 ID 的实体。Doctrine 查询数据库并为我们填充实体。

如果找不到具有此 ID 的`Post`，则将`NULL`值分配给`$post`变量，而不是`\Blog\Entity\Post`的实例。为了避免进一步的错误，如果是这种情况，我们会抛出一个异常。要了解更多关于 PHP 异常的信息，请参考网站[`php.net/manual/en/language.exceptions.php`](http://php.net/manual/en/language.exceptions.php)。

然后，我们使用我们的新实体作为参数调用实体管理器的`persist()`方法。如第一章*使用 Doctrine 2 入门*中所述，对`persist()`方法的调用将实体的状态设置为受管理状态。这仅对新实体是必要的，因为通过 Doctrine 检索的实体已经具有受管理状态。

接下来，我们设置我们新创建对象的发布日期。多亏了 Doctrine 映射系统，我们只需要将`\DateTime`实例传递给`setPublicationDate()`方法，ORM 将为我们将其转换为 DBMS 所需的格式（参考类型对应表）。

我们还使用先前生成的 getter 和 setter 的流畅接口设置了`$title`和`$body`属性。

### 注意

如果您不了解流畅接口，请阅读以下文章：[`martinfowler.com/bliki/FluentInterface.html`](http://martinfowler.com/bliki/FluentInterface.html)

当调用`flush()`方法时，实体管理器告诉 Doctrine 将所有受管理的实体与数据库同步。在这种情况下，只有我们的`Post`实体是受管理的。如果它是一个新实体，将生成一个`INSERT` SQL 语句。如果它是一个现有实体，将向 DBMS 发送一个`UPDATE`语句。

默认情况下，Doctrine 在调用`EntityManager::flush()`方法时自动将所有操作包装在事务中。如果发生错误，数据库状态将恢复到刷新调用之前的状态（回滚）。

这通常是最好的选择，但如果您有特定的需求，可以停用此自动提交模式。可以在[`docs.doctrine-project.org/en/latest/reference/transactions-and-concurrency.html`](http://docs.doctrine-project.org/en/latest/reference/transactions-and-concurrency.html)中找到相关信息。

## 删除帖子

让我们在`web/delete-post.php`文件中创建一个删除帖子的页面。

```php
  <?php

  /**
   * Deletes a blog post
   */

  require_once __DIR__.'/../src/bootstrap.php';

  /** @var Post The post to delete */
 **$post = $entityManager->find('Blog\Entity\Post', $_GET['id']);**
  if (!$post) {
    throw new \Exception('Post not found');
  }

  // Delete the entity and flush
 **$entityManager->remove($post);**
 **$entityManager->flush();**

  // Redirects to the index
  header('Location: index.php');
  exit;
```

我们使用 URL 中的 ID 参数检索要删除的帖子。我们告诉 Doctrine 安排删除它，调用`EntityManager::remove()`方法。在此调用之后，实体的状态被移除。当调用`flush()`方法时，Doctrine 执行`DELETE` SQL 查询以从数据库中删除数据。

### 注意

请注意，在调用`flush()`方法并从数据库中删除后，实体仍然存在于内存中。

# 总结

现在我们有一个最小但可用的博客应用程序！多亏了 Doctrine，将数据持久化、检索和删除到数据库中从未如此简单。

我们已经学会了如何使用注释将实体类映射到数据库表和行，我们生成了数据库模式而不需要输入一行 SQL，我们创建了固定装置，并且我们使用实体管理器将数据与数据库同步。

在下一章中，我们将学习如何在实体之间映射和管理一对一、一对多/多对一和多对多的关联。


# 第三章：关联

在上一章中，我们学习了如何使用 Doctrine 注释向实体类添加映射信息。我们使用了 Doctrine 命令行工具提供的代码和数据库模式生成器，并创建了一个使用`EntityManager`类来创建、更新、删除和显示博客文章的极简主义博客软件。

在第三章中，我们将学习如何通过以下主题处理实体之间的关联：

+   开始使用 Doctrine 关联

+   理解注释系统中的@ManyToOne 和@OneToMany 注释

+   理解标签的@ManyToMany 注释

# 开始使用 Doctrine 关联

我们将使用注释指定 Doctrine 关联，以及其他映射信息（还支持其他方法，如 XML 和 YAML 配置文件。请参阅第二章，*实体和映射信息*）。Doctrine 支持以下关联类型：

+   **一对一**：一个实体与一个实体相关联

+   **多对一**：多个实体与一个实体相关联（仅适用于双向关联，始终是一对多关联的反向方）

+   **一对多**：一个实体与多个实体相关联

+   **多对多**：多个实体与多个实体相关联

关联可以是单向的或双向的。单向关联只有一个拥有方，而双向关联既有拥有方又有反向方。换句话说，它们可以解释如下：

+   单向关联只能以一种方式使用：相关实体可以从主实体中检索。例如，用户有关联地址。地址可以从用户中检索，但用户无法从地址中检索。

+   双向关联可以以两种方式使用：相关实体可以从主实体中检索，主实体可以从相关实体中检索。例如，用户有关联订单。订单可以从用户中检索，用户也可以从订单中检索。

Doctrine 只管理关联的拥有方。这意味着您始终需要设置拥有方；否则，如果您只设置关联的反向方，它将不会由`EntityManager`类持久化。

有一种简单的方法来识别双向关联的方向。拥有方必须具有`inversedBy`属性，而反向方必须具有`mappedBy`属性。这些属性指的是相关的实体类。

默认情况下，一对一和多对一关联在 SQL 级别上使用存储相关 ID 和外键的列进行持久化。多对多关联始终使用关联表。

Doctrine 会自动生成列和表的名称（如果适用）。可以使用`@JoinColumn`注释更改名称，并使用`@JoinTable`注释强制使用关联表。

# 理解注释系统中的@ManyToOne 和@OneToMany 注释

让我们从评论开始。我们博客的访问者应该能够对我们的帖子做出反应。我们必须创建一个新的`Comment` Doctrine 实体类型，存储读者的评论。`Comment`实体将与一个`Post`实体相关联。一个帖子可以有多条评论，一条评论与一个帖子相关联。

以下 E-R 图表示将使用映射信息生成的 MySQL 模式：

![理解注释系统中的@ManyToOne 和@OneToMany 注释](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/prst-php-dct-orm/img/4104_03_01.jpg)

## 创建评论实体类（拥有方）

`Comment`实体具有以下四个属性：

+   `id`：这是评论的唯一标识符

+   `body`：这代表评论的文本

+   `publicationDate`：这是评论发布的日期

+   `post_id`：这代表与评论相关的帖子

这是`Comment`实体的第一个代码片段，包含有注释的属性。它必须放在`Comment.php`文件中，位于`src/Blog/Entity/`位置。

```php
<?php

namespace Blog\Entity;

use Doctrine\ORM\Mapping\Entity;
use Doctrine\ORM\Mapping\Id;
use Doctrine\ORM\Mapping\GeneratedValue;
use Doctrine\ORM\Mapping\Column;
use Doctrine\ORM\Mapping\ManyToOne;

/**
 * Comment entity
 *
 * @Entity
 */
class Comment
{
    /**
     * @var int
     *
     * @Id
     * @GeneratedValue
     * @Column(type="integer")
     */
    protected $id;
    /**
     * @var string
     *
     * @Column(type="text")
     */
    protected $body;
    /**
     * @var \DateTime
     *
     * @Column(type="datetime")
     */
    protected $publicationDate;
    /**
     * @var Post
     *
     * @ManyToOne(targetEntity="Post", inversedBy="comments")
     */
    protected $post;
}
```

这个实体类类似于第二章中创建的`Post`实体类，*实体和映射信息*。我们使用`@ManyToOne`注释在`Comment`和`Post`实体之间创建多对一关联。使用`targetEntity`属性指定相关实体类是必需的。

为了能够直接从`Post`实体中检索评论，这个关联必须是双向的。`inversedBy`属性将此关联标记为双向，并指示`Post`实体类拥有这个关联的反向端的属性。在这里，这是`Post`的`$comments`属性。

### 注意

对于每个具有`private`或`protected`属性的实体类，`Comment`类必须公开 getter 和 setter 来访问它们。我们将在本章后面为我们应用程序的每个实体类生成 getter 和 setter。

## 为`Post`实体类添加反向端

现在，我们需要修改`Post`实体类以添加这个关联的反向端。需要执行以下步骤：

1.  打开`src/Blog/Entity/`位置的`Post.php`文件，并从前一个代码片段中添加 use 语句：

```php
  use Doctrine\ORM\Mapping\OneToMany;
  use Doctrine\Common\Collections\ArrayCollection;
```

1.  按照以下代码片段中所示添加`$comments`属性：

```php
    /**
     * @var Comment[]
     *
     * @OneToMany(targetEntity="Comment", mappedBy="post")
     */
    protected $comments;
```

1.  将其初始化代码添加到构造函数中，如下一个代码片段所示：

```php
    /**
     * Initializes collections
     */
    public function __construct()
    {
        $this->comments = new ArrayCollection();
    }
```

1.  使用 Doctrine 命令行工具提供的实体生成器为我们刚刚添加到`Comment`和`Post`类的属性创建 getter 和 setter：

```php
**php vendor/bin/doctrine.php orm:generate:entities src/**

```

1.  在生成的`addComment()`方法中，添加以下代码片段中的突出显示行以自动设置关联的拥有端：

```php
    public function addComment(\Blog\Entity\Comment$comments)
    {
        $this->comments[] = $comments;
        $comments->setPost($this);

        return $this;
    }
```

`$comments`属性保存与`Post`实体相关联的评论集合。我们使用`@OneToMany`注释将此属性标记为关联的反向端，之前在`Comment`的`$post`属性中定义。我们已经解释了`targetEntity`属性。`mappedBy`属性是关联的反向端的`inversedBy`属性的等价物。它指示相关实体类的属性拥有关联的另一端。

为了让 Doctrine 正确管理元素的集合，必须使用 Doctrine Common 组件提供的特殊类。`Post`实体的`$comments`属性在构造函数中初始化为`Doctrine\Common\Collections\ArrayCollection`的实例。`ArrayCollection`实现了`Doctrine\Common\Collections\Collection`接口。这将使 Doctrine 能够填充和管理集合。

Doctrine `Collection`类实现了`Countable`、`IteratorAggregate`和`ArrayAccess`接口（这些接口在 PHP 或 SPL 中预定义）。因此，Doctrine 集合可以像标准的 PHP 数组一样使用，并且可以在 foreach 循环中透明地迭代。

### 注意

有关预定义接口和标准 PHP 库（SPL）提供的接口的更多信息，请参阅以下 PHP 手册：

[`php.net/manual/en/reserved.interfaces.php`](http://php.net/manual/en/reserved.interfaces.php)和[`php.net/manual/en/spl.interfaces.php`](http://php.net/manual/en/spl.interfaces.php)

Doctrine 命令行工具生成的`addComment()`和`removeComment()`方法演示了如何使用 Doctrine `Collection`类的方法来添加和删除项目。

### 注意

可用方法的完整列表在 Doctrine 网站上有文档，如下所示：

[`docs.doctrine-project.org/en/latest/reference/working-with-associations.html`](http://docs.doctrine-project.org/en/latest/reference/working-with-associations.html)

另一个重要的事情，正如已经解释的那样，Doctrine 只管理关联的拥有方。这就是为什么我们在`addComment()`方法中调用`Comment`实体的`setPost()`方法。这允许从反向方面进行关联的持久化。

### 注意

这仅在实体的更改跟踪策略是延迟隐式时才有效（这是默认情况）。延迟隐式策略是最方便的使用方式，但可能对性能产生负面影响。

再次参考 Doctrine 文档，了解更多可以使用的不同更改跟踪策略：

[`docs.doctrine-project.org/en/latest/reference/change-tracking-policies.html`](http://docs.doctrine-project.org/en/latest/reference/change-tracking-policies.html)

接下来，我们将更新我们的 UI 以添加评论功能。首先必须更新数据库模式。

## 更新数据库模式

与其他注释一样，Doctrine 能够自动创建在 SQL 层存储关联所需的列和外键。再次运行`orm:schema-tool:update`命令，与命令行工具捆绑在一起，如下所示：

```php
**php vendor/bin/doctrine.php orm:schema-tool:update --force**

```

Doctrine 将自动检测对映的更改，并相应地更新 SQL 模式。可以添加`--force`标志来有效执行查询。

### 注意

`orm:schema-tool:update`命令不应该在生产中使用。它可能会永久删除数据（例如，当删除列时）。相反，应该使用 Doctrine Migrations 库来正确处理复杂的迁移。即使这个库还没有被认为是稳定的，它非常方便。我们可以在以下网站找到这个库：

[`docs.doctrine-project.org/projects/doctrine-migrations/en/latest/reference/introduction.html`](http://docs.doctrine-project.org/projects/doctrine-migrations/en/latest/reference/introduction.html)

## 为评论添加装置

至于帖子，我们将为评论创建一些装置。在`src/Blog/DataFixtures/`位置创建一个名为`LoadCommentData.php`的新文件。下一个代码片段用于此目的：

```php
<?php

namespace Blog\DataFixtures;

use Blog\Entity\Comment;
use Doctrine\Common\DataFixtures\DependentFixtureInterface;
use Doctrine\Common\DataFixtures\Doctrine;
use Doctrine\Common\DataFixtures\FixtureInterface;
use Doctrine\Common\Persistence\ObjectManager;

/**
 * Comment fixtures
 */
class LoadCommentData implements FixtureInterface,DependentFixtureInterface
{
    /**
     * Number of comments to add by post
     */
    const NUMBER_OF_COMMENTS_BY_POST = 5;

    /**
     * {@inheritDoc}
     */
    public function load(ObjectManager $manager)
    {
        $posts = $manager->getRepository('Blog\Entity\Post')->findAll();

        foreach ($posts as $post) {
            for ($i = 1; $i <= self::NUMBER_OF_COMMENTS_BY_POST;$i++) {
                $comment = new Comment();
                $comment
                    ->setBody(<<<EOTLorem ipsum dolor sit amet, consectetur adipiscing elit.EOT
                    )
                    ->setPublicationDate(new \DateTime(sprintf('-%ddays', self::NUMBER_OF_COMMENTS_BY_POST - $i)))
                    ->setPost($post)
                ;

                $manager->persist($comment);
            }
        }

        $manager->flush();
    }

    /**
     * {@inheritDoc}
     */
    public function getDependencies()
    {
        return ['Blog\DataFixtures\LoadPostData'];
    }
}
```

我们使用`EntityManager`类来检索`Post`实体存储库，然后我们使用这个存储库来检索所有的帖子。我们为每个帖子添加了五条评论。这个数据装置类实现了`Doctrine\Common\DataFixtures\DependentFixtureInterface`接口（`getDependencies()`方法）。它告诉数据加载器首先加载`LoadPostData`，因为这个数据装置类依赖于它。

## 列出和创建评论

是时候更新 UI 了。在`web/`位置创建一个名为`view-post.php`的文件。这个页面显示一个帖子和它的所有评论，还有一个添加新评论的表单，并处理评论的创建。

用于检索帖子和处理评论创建的代码如下：

```php
<?php

/**
 * View a blog post
 */

use Blog\Entity\Comment;

require_once __DIR__ . '/../src/bootstrap.php';
/** @var \Blog\Entity\Post $post The post to edit */
$post = $entityManager->find('Blog\Entity\Post', $_GET['id']);

if (!$post) {
    throw new \Exception('Post not found');
}

// Add a comment
if ('POST' === $_SERVER['REQUEST_METHOD']) {
    $comment = new Comment();
    $comment
        ->setBody($_POST['body'])
        ->setPublicationDate(new \DateTime())
        ->setPost($post)
    ;

    $entityManager->persist($comment);
    $entityManager->flush();

    header(sprintf('Location: view-post.php?id=%d', $post->getId()));
    exit;
}
?>
```

正如你所看到的，使用 Doctrine 管理简单的关联是很容易的。设置关系就像调用一个带有实体链接的 setter 一样简单。使用 getter 可以访问相关实体。用于显示帖子的详细信息、相关评论和发布新评论的表单的代码（将其放在同一个文件的底部）如下：

```php
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title><?=htmlspecialchars($post->getTitle())?> - My blog</title>
</head>
<body>

<article>
    <h1>
        <?=htmlspecialchars($post->getTitle())?>
    </h1>
    Date of publication: <?=$post->getPublicationDate()->format('Y-m-d H:i:s')?>
    <p>
        <?=nl2br(htmlspecialchars($post->getBody()))?>
    </p>
    <?php if (count($post->getComments())): ?>
        <h2>Comments</h2>

        <?php foreach ($post->getComments() as $comment): ?>
            <article>
                <?=$comment->getPublicationDate()->format('Y-m-dH:i:s')?>

                <p><?=htmlspecialchars($comment->getBody())?></p>

                <a href="delete-comment.php?id=<?=$comment->getId()?>">Delete this comment</a>
            </article>
        <?php endforeach ?>
    <?php endif ?>

    <form method="POST">
        <h2>Post a comment</h2>

        <label>
            Comment
            <textarea name="body"></textarea>
        </label><br>

        <input type="submit">
    </form>
</article>

<a href="index.php">Back to the index</a>
```

默认情况下，Doctrine 会延迟加载关联的实体。这意味着，在我们的例子中，当调用`getComments()`时，Doctrine 首先向 DBMS 发送一个查询来检索帖子，然后再发送另一个查询来检索关联的评论。好处是，如果不调用`getComments()`方法，检索关联评论的查询将永远不会执行。但是当关联评论总是被获取时，这是一个无用的开销。

### 注意

为了使延迟加载功能起作用，Doctrine 在内部将实体包装成代理类。代理类负责在请求时获取尚未从数据库加载的关联实体的数据。关于这方面的一些细节可以在以下网址找到：

[`docs.doctrine-project.org/en/latest/reference/working-with-objects.html#entity-object-graph-traversal`](http://docs.doctrine-project.org/en/latest/reference/working-with-objects.html#entity-object-graph-traversal)

我们可以通过在关联注释上设置`fetch`属性来更改这种行为。该属性可以采用以下值：

+   `EAGER`：通常在第一个查询中使用 SQL 连接获取相关实体。

+   `懒加载`：相关实体只有在使用另一个 SQL 查询请求时才会被获取。这是默认值。

+   `EXTRA_LAZY`：这允许在不加载整个集合到内存中的情况下执行一些操作，例如计数。要了解更多信息，请参阅以下教程：

[`docs.doctrine-project.org/en/latest/tutorials/extra-lazy-associations.html`](http://docs.doctrine-project.org/en/latest/tutorials/extra-lazy-associations.html)

另一种急切加载相关实体的方法是使用 Doctrine 查询构建器来自定义生成的请求。我们将在第四章中展示查询构建器的强大功能。

通过在`view-post.php`页面中删除评论，我们创建了一个允许删除评论的链接。要使此功能正常工作，需要在`web/`位置的`delete-comment.php`文件中放入以下代码：

```php
<?php

/**
 * Deletes a comment
 */

require_once __DIR__ . '/../src/bootstrap.php';
/** @var Comment $comment The comment to delete */
$comment = $entityManager->find('Blog\Entity\Comment', $_GET['id']);

if (!$comment) {
    throw new \Exception('Comment not found');
}

// Delete the entity and flush
$entityManager->remove($comment);
$entityManager->flush();

// Redirect to the blog post
header(sprintf('Location: view-post.php?id=%d', $comment->getPost()->getId()));
exit;
```

这个文件与第一章中在`web/`位置创建的`delete-post.php`文件非常相似，*开始使用 Doctrine 2*。它通过`EntityManager`类检索存储库，使用它检索要删除的评论，调用`remove()`，并使用`flush()`将更改持久化到 DBMS。

## 更新索引

更新`web/`位置的`index.php`文件，创建一个链接到新的详细帖子视图，如下所示：

```php
        <h1>
            <?=htmlspecialchars($post->getTitle())?>
        </h1>
```

为了使我们的评论功能准备就绪，请使用以下代码替换前面的代码：

```php
        <h1>
            <a href="view-post.php?id=<?=$post->getId()?>">
                <?=htmlspecialchars($post->getTitle())?>
            </a>
        </h1>
```

# 理解标签的@ManyToMany 注释

标签按主题对帖子进行分组。一个标签包含多个帖子，一个帖子有多个标签。这是一个多对多双向关联。Doctrine 在 SQL 级别上透明地管理存储多对多关系所需的关联表。将生成的 MySQL 模式显示在以下截图中：

![理解标签的@ManyToMany 注释](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/prst-php-dct-orm/img/4104_03_02.jpg)

## 创建`Tag`实体类（反向端）

`Tag`实体类只有两个属性：

+   `name`：这是标签的名称，它是唯一的，并且是实体的标识符

+   `posts`：这是与此标签关联的帖子集合

以下是创建`Tag`实体类的步骤：

1.  在`src/Blog/Entity/`位置创建一个`Tag.php`文件，其中包含使用以下代码片段的实体类：

```php
<?php

namespace Blog\Entity;

use Doctrine\Common\Collections\ArrayCollection;
use Doctrine\ORM\Mapping\Entity;
use Doctrine\ORM\Mapping\Column;
use Doctrine\ORM\Mapping\Id;
use Doctrine\ORM\Mapping\ManyToMany;

/**
 * Tag entity
 *
 * @Entity
 */
class Tag
{
    /**
     * @var string
     *
     * @Id
     * @Column(type="string")
     */
    protected $name;
    /**
     * @var Post[]
     *
     * @ManyToMany(targetEntity="Post", mappedBy="tags")
     */
    protected $posts;

    /**
     * Initializes collection
     */
    public function __construct()
    {
        $this->posts = new ArrayCollection();
    }

    /**
     * String representation
     *
     * @return string
     */
    public function __toString()
    {
        return $this->getName();
    }
}
```

1.  使用以下命令生成 getter 和 setter：

```php
**php vendor/bin/doctrine.php orm:generate:entities src/**

```

1.  在`addPost()`方法中的`$this->posts[] = $posts;`之后添加以下代码行以设置关联的拥有端：

```php
$posts->addTag($this);
```

`$name`属性是`Tag`实体的标识符。与`Post`和`Comment`实体不同，它的值不是由 DBMS 自动生成的；它是标签的名称。这就是为什么这里不使用`@GeneratedValue`注释。标签的名称必须是唯一的，并且必须由应用程序设置。

`@ManyToMany`注释用于标记关联。`targetEntity`和`mappedBy`属性的含义与`@OneToMany`注释相同。`@ManyToMany`注释接受`mappedBy`属性作为反向端，`inversedBy`作为拥有端。这个关联的拥有端在`Post`实体上。与任何 Doctrine 集合一样，`$posts`属性在构造函数中被初始化。我们还创建一个`__toString()`方法，返回标签的名称，以便能够将`Tag`的实例转换为字符串。

### 注意

`__toString()`魔术方法允许我们将对象转换为字符串。有关更多详细信息，我们可以参考以下链接：

[`www.php.net/manual/en/language.oop5.magic.php#object.tostring`](http://www.php.net/manual/en/language.oop5.magic.php#object.tostring)

## 更新 Post 实体类（拥有方）

修改`src/Blog/Entity/`位置的`Post.php`文件，以添加关联的拥有方使用以下步骤：

1.  添加以下`use`语句：

```php
use Doctrine\ORM\Mapping\ManyToMany;
use Doctrine\ORM\Mapping\JoinTable;
use Doctrine\ORM\Mapping\JoinColumn;
```

1.  使用以下代码片段添加`mapped`属性：

```php
    /**
     * @var Tag[]
     *
     * @ManyToMany(targetEntity="Tag", inversedBy="posts",fetch="EAGER", cascade={"persist"}, orphanRemoval=true)
     * @JoinTable(
     *      inverseJoinColumns={@JoinColumn(name="tag_name",referencedColumnName="name")}
     * )
     */
    protected $tags;
```

1.  按照以下代码片段中所示的方式在构造函数中初始化属性：

```php
    public function __construct()
    {
        // …
        $this->tags = new ArrayCollection();
    }
```

1.  要生成 getter 和 setter，可以使用以下命令：

```php
**php vendor/bin/doctrine.php orm:generate:entities src/**

```

这里介绍了`@ManyToMany`注释的两个新属性，即`cascade`和`orphanRemoval`。

默认情况下，当设置主实体时，关联实体不会自动设置为托管状态。这必须通过对每个关联实体的`EntityManager`类的`persist()`方法进行手动调用来完成。如果`cascade`属性与`persist`一起使用，相关实体将在持久化主实体时自动持久化。

在这里，当持久化`Post`实体时，相关标签将一起持久化。`cascade`属性可以采用其他值，其中最有用的是`remove`。使用`remove`时，当删除主实体时，相关实体将被删除。

**对象关系映射器（ORM）**在内存中处理`CASCADE`操作。它们不等同于 SQL 的`DELETE CASCADE`操作，并且可能使用大量内存。应该谨慎使用以保持应用程序的性能。

可以通过`@JoinColumn`注释的`onDelete`属性添加 SQL`DELETE CASCADE`操作。

将`orphanRemoval`属性设置为`true`，Doctrine 将自动删除不再与主实体关联的实体。如果从`Post`实体的`$tags`集合中删除`Tag`实体，并且这个`Post`实体是唯一与`Tag`实体关联的实体，那么`Tag`实体将被永久删除。

`fetch`属性已在本章中进行了解释。使用`EAGER`值，它告诉 Doctrine 在检索帖子时自动使用`JOIN`查询检索相关标签。在我们的应用程序环境中，这是有用的，因为`Post`实体的标签在每次显示帖子时都会显示。

由于`Tag`的标识符没有标记`@GeneratedValue`注释，Doctrine 将无法猜测它。`@JoinTable`和`@JoinColumn`注释在这里用于覆盖默认行为。

我们使用`@JoinColumn`为关联方（反向方）设置自定义`JOIN`列，通过`@JoinTable`的`inverseJoinColumns`属性。`@JoinColumn`的`referencedColumnName`属性告诉 Doctrine 在 SQL 级联表中查找`Tag`的标识符的`$name`属性（默认情况下是`$id`）。`name`属性将`Tag`的标识符的列名称设置为`tag_name`（默认情况下是`tag_id`）。

## 再次更新模式

现在是时候再次更新 SQL 模式以匹配我们的更改。我们在命令行上使用以下命令：

```php
**php vendor/bin/doctrine.php orm:schema-tool:update --force**

```

## 创建标签固定装置

在`src/Blog/DataFixtures/`创建一个`LoadTagData.php`文件，其中包含使用以下代码片段的标签固定装置：

```php
<?php

namespace Blog\DataFixtures;

use Blog\Entity\Tag;
use Doctrine\Common\DataFixtures\DependentFixtureInterface;
use Doctrine\Common\DataFixtures\Doctrine;
use Doctrine\Common\DataFixtures\FixtureInterface;
use Doctrine\Common\Persistence\ObjectManager;

/**
 * Tag fixtures
 */
class LoadTagData implements FixtureInterface,DependentFixtureInterface
{
    /**
     * Number of comments to add by post
     */
    const NUMBER_OF_TAGS = 5;
    /**
     * {@inheritDoc}
     */
    public function load(ObjectManager $manager)
    {
        $tags = [];
        for ($i = 1; $i <= self::NUMBER_OF_TAGS; $i++) {
            $tag = new Tag();
            $tag->setName(sprintf("tag%d", $i));

            $tags[] = $tag;
        }

        $posts = $manager->getRepository('Blog\Entity\Post')->findAll();

        $tagsToAdd = 1;
        foreach ($posts as $post) {
            for ($j = 0; $j < $tagsToAdd; $j++) {
                $post->addTag($tags[$j]);
            }

            $tagsToAdd = $tagsToAdd % 5 + 1;
        }

        $manager->flush();
    }

    /**
     * {@inheritDoc}
     */
    public function getDependencies()
    {
        return ['Blog\DataFixtures\LoadPostData'];
    }
}
```

由于`persist`属性，我们可以在不手动持久化的情况下向帖子添加标签。

固定装置后，我们必须更新 UI。

## 管理帖子的标签

编辑`web/`位置的`edit-post.php`文件，并按以下步骤添加代码来管理标签：

1.  在文件顶部添加以下`use`语句：

```php
use Blog\Entity\Tag;
```

1.  找到以下代码片段：

```php
    $post
        ->setTitle($_POST['title'])
        ->setBody($_POST['body'])
    ;
```

1.  在`to extract`和管理提交的标签后添加此代码：

```php
    $newTags = [];
    foreach (explode(',', $_POST['tags']) as $tagName) {
        $trimmedTagName = trim($tagName);
        $tag = $entityManager->find('Blog\Entity\Tag',$trimmedTagName);
        if (!$tag) {
            $tag = new Tag();
            $tag->setName($trimmedTagName);
        }

        $newTags[] = $tag;
    }

    // Removes unused tags
    foreach (array_diff($post->getTags()->toArray(),$newTags) as $tag) {
        $post->removeTag($tag);
    }

    // Adds new tags
    foreach (array_diff($newTags, $post->getTags()->toArray()) as $tag) {
        $post->addTag($tag);
    }
```

1.  找到以下代码片段：

```php
    <label>
        Body
        <textarea name="body" cols="20" rows="10"required><?=isset ($post) ? htmlspecialchars($post-
        >getBody()) : ''?></textarea>
    </label><br>
```

1.  在`to display`后添加以下表单部件以更新标签：

```php
    <label>
        Tags
        <input type="text" name="tags" value="<?=isset($post) ? htmlspecialchars(implode(', ', $post->getTags()->toArray())) : ''?>" required>
    </label><br>
```

从提交的字符串中提取每个标签名称。从存储库中检索相应的`Tag`实体，如果找不到则创建。

由于它的`toArray()`方法，`Post`对象的`tag`集合被转换为标准的 PHP 数组。

标准的`array_diff()`函数用于识别已删除和已添加的`Tag`对象。`array_diff()`的参数必须是可以转换为字符串的对象数组。这里可以使用，因为我们的`Tag`类实现了`__toString()`魔术方法。

已删除的标签通过`Post::removeTag()`函数移除，新标签通过`Post::addTag()`添加。

感谢在`Post`实体类中定义的`CASCADE`属性，我们不需要针对每个新标签单独持久化。

在模板中，标签列表按照“tagname1，tagname2，tagname3”的模式转换为字符串。

# 总结

在本章中，我们学习了如何管理 Doctrine ORM 支持的所有类型的关联。我们学习了单向和双向关联以及拥有方和反向方的概念。我们还运用了我们在之前章节学到的知识，特别是`EntityManager`类、装置加载器和生成器。

在下一章中，我们将学习如何使用 DQL 和 Query Builder 创建复杂的查询。

由于它们，我们将创建按标签分组的帖子列表。我们还将研究聚合函数。


# 第四章：构建查询

在上一章中，我们为我们的博客软件添加了评论和标记支持。虽然它运行良好，但一些功能可以得到增强。

在本章中，我们将利用 Doctrine 的一些非常重要的部分：**Doctrine 查询语言**（**DQL**）、实体存储库和查询构建器。我们将在本章中涵盖以下方面：

+   优化评论功能

+   创建一个页面来通过标签过滤帖子

+   在主页上显示帖子的评论数量

# 理解 DQL

DQL 是 Doctrine 查询语言的缩写。它是一种特定领域的语言，非常类似于 SQL，但不是 SQL。DQL 不是用于查询数据库表和行，而是设计用于查询对象模型的实体和映射属性。

DQL 受 Hibernate 的查询语言 HQL 的启发和类似，Hibernate 是 Java 的流行 ORM 的查询语言。有关更多详细信息，您可以访问此网站：[`www.hibernate.org/`](http://www.hibernate.org/)。

### 注

在以下网站了解更多关于特定领域语言的信息：

[`en.wikipedia.org/wiki/Domain-specific_language`](http://en.wikipedia.org/wiki/Domain-specific_language)

为了更好地理解其含义，让我们运行我们的第一个 DQL 查询。

Doctrine 命令行工具就像瑞士军刀一样实用。它们包括一个名为`orm:run-dql`的命令，用于运行 DQL 查询并显示结果。使用它来检索带有`1`作为标识符的帖子的`title`和所有评论：

```php
php vendor/bin/doctrine.php orm:run-dql "SELECT p.title, c.bodyFROM Blog\Entity\Post p JOIN p.comments c WHERE p.id=1"
```

它看起来像一个 SQL 查询，但绝对不是 SQL 查询。检查`FROM`和`JOIN`子句；它们包含以下方面：

+   在`FROM`子句中使用完全限定的实体类名作为查询的根

+   所有与所选“帖子”实体相关联的“评论”实体都被连接在一起，这要归功于“帖子”实体类中的“评论”属性在`JOIN`子句中的存在

正如您所看到的，可以以面向对象的方式请求与主实体相关联的实体的数据。持有关联的属性（在拥有方或反向方）可以在`JOIN`子句中使用。

尽管存在一些限制（特别是在子查询领域），我们将看到如何绕过第五章中的限制，*进一步*，DQL 是一种强大而灵活的语言，用于检索对象图。在内部，Doctrine 解析 DQL 查询，通过**数据库抽象层（DBAL）**生成和执行它们对应的 SQL 查询，并使用结果填充数据结构。

### 注

到目前为止，我们只使用 Doctrine 来检索 PHP 对象。Doctrine 能够填充其他类型的数据结构，特别是数组和基本类型。还可以编写自定义水合器来填充任何数据结构。

如果您仔细观察上一次调用`orm:run-dql`的返回，您会发现它是一个数组，而不是一个对象图，已经被填充。

与本书中涵盖的所有主题一样，有关内置水合模式和自定义水合器的更多信息可在以下网站的 Doctrine 文档中找到：

[`docs.doctrine-project.org/en/latest/reference/dql-doctrine-query-language.html#hydration-modes`](http://docs.doctrine-project.org/en/latest/reference/dql-doctrine-query-language.html#hydration-modes)

# 使用实体存储库

实体存储库是负责访问和管理实体的类。就像实体与数据库行相关联一样，实体存储库与数据库表相关联。

我们已经在前几章中使用了 Doctrine 提供的默认实体存储库来检索实体。所有的 DQL 查询都应该写在与它们检索的实体类型相关的实体存储库中。它将 ORM 隐藏在应用程序的其他组件中，并使其更容易重用、重构和优化查询。

### 注

Doctrine 实体存储库是表数据网关设计模式的一种实现。有关更多详细信息，请访问以下网站：

[`martinfowler.com/eaaCatalog/tableDataGateway.html`](http://martinfowler.com/eaaCatalog/tableDataGateway.html)

为每个实体提供的基本存储库提供了管理实体的有用方法，如下所示：

+   `find($id)`: 返回具有`$id`作为标识符的实体，或`null`

### 注意

它在实体管理器的`find()`方法内部使用。我们在前面的章节中多次使用了这个快捷方式。

+   `findAll()`: 检索包含此存储库中所有实体的数组

+   `findBy(['property1' => 'value', 'property2' => 1], ['property3' => 'DESC', 'property4' => 'ASC'])`: 检索包含第一个参数中传递的所有条件匹配的实体的数组，并按照第二个参数排序

+   `findOneBy(['property1' => 'value', 'property2' => 1])`: 类似于`findBy()`，但只检索第一个实体，如果没有实体与条件匹配，则返回`null`

### 注意

实体存储库还提供了快捷方法，允许单个属性过滤实体。它们遵循这种模式：`findBy*()`和`findOneBy*()`。

例如，调用`findByTitle('My title')`等同于调用`findBy(['title' => 'My title'])`。

此功能使用了神奇的`__call()` PHP 方法。有关更多详细信息，请访问以下网站：

[`php.net/manual/en/language.oop5.overloading.php#object.call`](http://php.net/manual/en/language.oop5.overloading.php#object.call)

如第三章，“关联”中所述，这些快捷方法不会连接相关实体，除非我们在实体类的关联注释中添加了`fetch="EAGER"`属性。如果（且仅当）通过方法调用请求了相关实体（或实体集合），则会发出另一个 SQL 查询。

在我们的博客应用中，我们希望在详细的帖子视图中显示评论，但不需要从帖子列表中获取它们。通过`fetch`属性的急切加载不适合列表，而延迟加载会减慢详细视图的速度。

解决这个问题的方法是创建一个具有额外方法来执行我们自己的查询的自定义存储库。我们将编写一个在详细视图中整理评论的自定义方法。

## 创建自定义实体存储库

自定义实体存储库是扩展了 Doctrine 提供的基本实体存储库类的类。它们旨在接收运行 DQL 查询的自定义方法。

像往常一样，我们将使用映射信息告诉 Doctrine 使用自定义存储库类。这是`@Entity`注释的`repositoryClass`属性的作用。

请执行以下步骤创建自定义实体存储库：

1.  重新打开`Post.php`文件，位于`src/Blog/Entity/`位置，并在现有的`@Entity`注释中添加一个`repositoryClass`属性，就像下面的代码行一样：

```php
@Entity(repositoryClass="PostRepository")
```

1.  Doctrine 命令行工具还提供了实体存储库生成器。输入以下命令来使用它：

```php
**php vendor/bin/doctrine.php orm:generate:repositories src/**

```

1.  打开这个新的空自定义存储库，我们刚刚在`src/Blog/Entity/`位置生成的`PostRepository.php`文件。添加以下方法来检索帖子和评论：

```php
   /**
     * Finds a post with its comments
     *
     * @param  int  $id
     * @return Post
     */
    public function findWithComments($id)
    {
        return $this
            ->createQueryBuilder('p')
            ->addSelect('c')
            ->leftJoin('p.comments', 'c')
            ->where('p.id = :id')
            ->orderBy('c.publicationDate', 'ASC')
            ->setParameter('id', $id)
            ->getQuery()
            ->getOneOrNullResult()
        ;
    }
```

我们的自定义存储库扩展了 Doctrine 提供的默认实体存储库。前面章节中描述的标准方法仍然可用。

# 开始使用查询构建器

`QueryBuilder`是一个旨在通过 PHP API 和流畅的接口帮助构建 DQL 查询的对象（要了解更多关于流畅接口的信息，请参见第二章，“实体和映射信息”）。它允许我们通过`getDql()`方法检索生成的 DQL 查询（用于调试）或直接使用`Query`对象（由 Doctrine 提供）。

### 注意

为了提高性能，`QueryBuilder`缓存生成的 DQL 查询并管理内部状态。

DQL 查询的完整 API 和状态在以下网站上有文档：

[`docs.doctrine-project.org/projects/doctrine-orm/en/latest/reference/query-builder.html`](http://docs.doctrine-project.org/projects/doctrine-orm/en/latest/reference/query-builder.html)

我们将对我们在`PostRepository`类中创建的`findWithComments()`方法进行深入解释。

首先，使用从基本实体存储库继承的`createQueryBuilder()`方法创建一个`QueryBuilder`实例。`QueryBuilder`实例以字符串作为参数。此字符串将用作主实体类的别名。默认情况下，选择主实体类的所有字段，并且除了`SELECT`和`FROM`之外没有其他子句。

`leftJoin()`调用创建一个`JOIN`子句，用于检索与帖子相关联的评论。它的第一个参数是要加入的属性，第二个是别名；这些将在查询中用于加入的实体类（这里，字母`c`将用作`Comment`类的别名）。

### 注意

除非使用 SQL `JOIN`子句，否则 DQL 查询将自动获取与主实体相关联的实体。不需要像`ON`或`USING`这样的关键字。Doctrine 会自动知道是使用连接表还是外键列。

`addSelect()`调用将注释数据附加到`SELECT`子句。实体类的别名用于检索所有字段（这类似于 SQL 中的`*`运算符）。与本章的第一个 DQL 查询一样，可以使用表示法`alias.propertyName`检索特定字段。

你猜对了，对`where()`方法的调用设置了查询的`WHERE`部分。

在幕后，Doctrine 使用准备好的 SQL 语句。它们比标准 SQL 查询更有效。

`id`参数将由`setParameter()`调用设置的值填充。

再次感谢准备好的语句和这个`setParameter()`方法，自动避免了 SQL 注入攻击。

### 注意

SQL 注入攻击是使用未转义的用户输入执行恶意 SQL 查询的一种方法。让我们来看一个检查用户是否具有特定角色的糟糕 DQL 查询的例子：

```php
$query = $entityManager->createQuery('SELECT ur FROMUserRole ur WHERE ur.username = "' . $username . '" ANDur.role = "' . $role . '"');
$hasRole = count($query->getResult());
```

这个 DQL 查询将由 Doctrine 翻译成 SQL。如果有人输入以下用户名：

`" OR "a"="a`

字符串中包含的 SQL 代码将被注入，查询将始终返回一些结果。攻击者现在已经获得了对私人区域的访问权限。

正确的方法应该是使用以下代码：

```php
$query = $entityManager->createQuery("SELECT ur FROMUserRole WHERE username = :username and role = :role");
$query->setParameters([
    'username' => $username,
    'role' => $role
]);
$hasRole = count($query->getResult());
```

由于准备好的语句，用户名中包含的特殊字符（如引号）并不危险，这段代码将按预期工作。

`orderBy()`调用生成一个`ORDER BY`子句，按评论的发布日期对结果进行排序，先是较早的。

### 提示

大多数 SQL 指令在 DQL 中也有一个面向对象的等价物。最常见的连接类型可以使用 DQL 进行；它们通常具有相同的名称。

`getQuery()`调用告诉查询构建器生成 DQL 查询（如果需要，它将尽可能从缓存中获取查询），实例化 Doctrine `Query`对象，并用生成的 DQL 查询填充它。

这个生成的 DQL 查询将如下所示：

```php
SELECT p, c FROM Blog\Entity\Post p LEFT JOIN p.comments c WHEREp.id = :id ORDER BY c.publicationDate ASC
```

`Query`对象还公开了另一个用于调试的有用方法：`getSql()`。顾名思义，`getSql()`返回与 DQL 查询对应的 SQL 查询，Doctrine 将在 DBMS 上运行。对于我们的 DQL 查询，底层 SQL 查询如下：

```php
SELECT p0_.id AS id0, p0_.title AS title1, p0_.body AS body2,p0_.publicationDate AS publicationDate3, c1_.id AS id4, c1_.bodyAS body5, c1_.publicationDate AS publicationDate6, c1_.post_id ASpost_id7 FROM Post p0_ LEFT JOIN Comment c1_ ON p0_.id =c1_.post_id WHERE p0_.id = ? ORDER BY c1_.publicationDate ASC
```

`getOneOrNullResult()`方法执行它，检索第一个结果，并将其作为`Post`实体实例返回（如果找不到结果，则此方法返回`null`）。

### 注意

与`QueryBuilder`对象一样，`Query`对象管理内部状态，仅在必要时生成底层 SQL 查询。

在使用 Doctrine 时，性能是需要非常小心的。当设置为生产模式时（参见第一章，*使用 Doctrine 2 入门*），ORM 能够缓存生成的查询（DQL 通过`QueryBuilder`对象，SQL 通过`Query`对象）和查询的结果。

ORM 必须配置为使用以下网站显示的其中一个快速支持系统（APC，Memcache，XCache 或 Redis）：

[`docs.doctrine-project.org/en/latest/reference/caching.html`](http://docs.doctrine-project.org/en/latest/reference/caching.html)

我们仍然需要更新视图层来处理我们的新的`findWithComments()`方法。

打开`web/`位置的`view-post.php`文件，在那里你会找到以下代码片段：

```php
$post = $entityManager->getRepository('Blog\Entity\Post')->find($_GET['id']);
```

用以下代码片段替换前面的代码行：

```php
$post = $entityManager->getRepository('Blog\Entity\Post')->findWithComments($_GET['id']);
```

# 按标签过滤

为了发现更高级的 QueryBuilder 和 DQL 的用法，我们将创建一个具有一个或多个标签的帖子列表。

标签过滤对于搜索引擎优化很有用，并且允许读者轻松找到他们感兴趣的内容。我们将构建一个能够列出具有多个共同标签的帖子的系统；例如，所有标记有 Doctrine 和 Symfony 的帖子。

要使用标签过滤我们的帖子，请执行以下步骤：

1.  在我们的自定义`PostRepository`类（`src/Blog/Entity/PostRepository.php`）中添加另一个方法，使用以下代码：

```php
    /**
     * Finds posts having tags
     *
     * @param string[] $tagNames
     * @return Post[]
     */
    public function findHavingTags(array $tagNames)
    {
        return $queryBuilder = $this
            ->createQueryBuilder('p')
                  ->addSelect('t')
            ->join('p.tags', 't')
            ->where('t.name IN (:tagNames)')
            ->groupBy('p.id')
            ->having('COUNT(t.name) >= :numberOfTags')
            ->setParameter('tagNames', $tagNames)
            ->setParameter('numberOfTags',count($tagNames))
            ->getQuery()
            ->getResult()
        ;
    }
```

这个方法有点复杂。它以标签名称数组的参数形式接受参数，并返回具有所有这些标签的帖子数组。

查询值得一些解释，如下所示：

+   主实体类（由继承的`createQueryBuilder()`方法自动设置）是`Post`，其别名是字母`p`。

+   我们通过`JOIN`子句连接相关标签；`Tag`类由`t`别名。

+   由于调用了`where()`，我们只检索通过参数传递的标签之一标记的帖子。我们使用 Doctrine 的一个很棒的功能，允许我们直接使用数组作为查询参数。

+   `where()`的结果通过调用`groupBy()`按`id`分组。

+   我们在`HAVING`子句中使用聚合函数`COUNT()`来过滤由`$tagNames`数组的一些标签标记的帖子，但不是所有的。

1.  编辑`web/`中的`index.php`文件以使用我们的新方法。在这里，你会找到以下代码：

```php
/** @var $posts \Blog\Entity\Post[] Retrieve the list ofall blog posts */
$posts = $entityManager->getRepository('Blog\Entity\Post')->findAll();
```

并用下一个代码片段替换前面的代码：

```php
$repository = $entityManager->getRepository('Blog\Entity\Post');
/** @var $posts \Blog\Entity\Post[] Retrieve the list ofall blog posts */
$posts = isset($_GET['tags']) ? $repository->findHavingTags($_GET['tags']) : $repository->findAll();
```

现在，当 URL 中存在名为`tags`的`GET`参数时，它将用于过滤帖子。更好的是，如果传入了多个逗号分隔的标签，只会显示具有所有这些标签的帖子。

1.  在您喜欢的浏览器中键入`http://localhost:8000/index.php?tags=tag4,tag5`。由于我们在上一章中创建的固定装置，应该列出帖子 5 和 10。

1.  在同一个文件中，找到以下代码：

```php
        <p>
            <?=nl2br(htmlspecialchars($post->getBody()))?>
        </p>
```

并按以下方式添加标签列表：

```php
        <ul>
        <?php foreach ($post->getTags() as $tag): ?>
            <li>
                <a href="index.php?tags=<?=urlencode($tag)?>"><?=htmlspecialchars($tag)?></a>
            </li>
        <?php endforeach ?>
        </ul>
```

显示带有指向标签页面的链接的智能标签列表。您可以复制此代码，然后将其粘贴到`web/`位置的`view-post.php`文件中；或者更好的是，*不要重复自己*：创建一个小的辅助函数来显示标签。

# 计数评论

我们仍然需要进行一些外观上的改变。评论很多的帖子吸引了很多读者。如果每篇帖子的评论数量可以直接从列表页面获得会更好。Doctrine 可以将包含对`aggregate`函数调用的结果的数组作为第一行，并将实体作为第二行。

添加以下方法，用于检索具有相关评论的帖子，到`PostRepository`类：

```php
    /**
     * Finds posts with comment count
     *
     * @return array
     */
    public function findWithCommentCount()
    {
        return $this
            ->createQueryBuilder('p')
            ->leftJoin('p.comments', 'c')
            ->addSelect('COUNT(c.id)')
            ->groupBy('p.id')
            ->getQuery()
            ->getResult()
        ;
    }
```

由于`GROUP BY`子句和调用`addSelect()`，此方法将返回一个二维数组，而不是`Post`实体的数组。返回的数组中包含两个值，如下所示：

+   我们的`Post`实体在第一个索引处

+   DQL 的`COUNT()`函数的结果（评论数量）在第二个索引处

在`web/`位置的`index.php`文件中，找到以下代码：

```php
    $posts = $repository->findHavingTags(explode(',',$_GET['tags']));
} else {
    $posts = $repository->findAll();
}
```

并用以下代码替换前面的代码以使用我们的新方法：

```php
    $results = $repository->findHavingTags(explode(',',$_GET['tags']));
} else {
    $results = $repository->findWithCommentCount();
} 
```

为了匹配`findWithCommentCount()`返回的新结构，找到以下代码：

```php
<?php foreach ($posts as $post): ?>
```

并用下一个代码片段替换前面的代码：

```php
<?php
    foreach ($results as $result):
        $post = $result[0];
        $commentCount = $result[1];
?>
```

### 注意

如前所述，在处理这种情况时使用自定义水合器是一个更好的做法。

您还应该查看以下网站上显示的自定义 AST Walker：

[`docs.doctrine-project.org/en/latest/cookbook/dql-custom-walkers.html`](http://docs.doctrine-project.org/en/latest/cookbook/dql-custom-walkers.html)

找到以下代码片段：

```php
<?php if (empty($posts)): ?>
```

并用下一个代码片段替换前面的代码：

```php
<?php if (empty($results)): ?>
```

是时候显示评论数量了。在标签列表后插入以下代码：

```php
        <?php if ($commentCount == 0): ?>
            Be the first to comment this post.
        <?php elseif ($commentCount == 1): ?>
            One comment
        <?php else: ?>
            <?= $commentCount ?> comments
        <?php endif ?>
```

由于`web/`位置的`index.php`文件还使用`findHavingTags()`方法来显示标记文章的列表，我们也需要更新这个方法。使用以下代码完成：

```php
            // …
            ->addSelect('t')
            ->addSelect('COUNT(c.id)')
            ->leftJoin('p.comments', 'c')
            // …
```

# 总结

在本章中，我们学习了 DQL，它与 SQL 的区别，以及它的查询构建器。我们还学习了实体存储库的概念以及如何创建自定义存储库。

即使从这些主题和 Doctrine 中还有很多东西可以学习，我们的知识应该足够开始使用 Doctrine 作为持久系统开发完整和复杂的应用程序。

在第五章，“进一步”，这本书的最后一章，我们将进一步讨论一些更高级的主题，包括如何处理继承，如何进行本地 SQL 查询以及事件系统的基础知识。
