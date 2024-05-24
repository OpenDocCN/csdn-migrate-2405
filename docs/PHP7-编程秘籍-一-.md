# PHP7 编程秘籍（一）

> 原文：[`zh.annas-archive.org/md5/2ddf943a2c311275def462dcde4895fb`](https://zh.annas-archive.org/md5/2ddf943a2c311275def462dcde4895fb)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

PHP 7 已经席卷了开源社区，打破了速度记录，这在比喻上引起了人们的关注。从最基本的意义上讲，核心工程团队对语言进行了重大改写，但仍然成功地保持了很高程度的向后兼容性。这些内部变化的影响在速度上表现出来，速度几乎增加了 200%，内存使用也有了显著的节省。从开发的角度来看，命令解析方式的改变以及统一的变量语法引入了在早期版本的 PHP 中根本不可能的编写代码的新方法。同样，任何不了解 PHP 7 中命令解释方式的开发人员可能会陷入看不见的陷阱，导致代码出现故障。因此，本书的任务是阐明编写代码的新方法，并指出与以前版本的 PHP 不兼容的任何领域。还需要注意的是，本书涵盖了 PHP 7.0 和 7.1。

# 本书内容包括

第一章，*打下基础*，帮助您开始设置和配置 PHP 7 开发环境。我们还将介绍一些强有力的初始示例，展示 PHP 7 的新功能。

第二章，*使用 PHP 7 高性能功能*，深入探讨了语言的新功能。您将了解抽象语法树和统一变量语法等概念，以及这些如何影响日常编程。接着是利用 PHP 7 性能改进的示例，包括`foreach()`循环处理中的重大新变化。

第三章，*使用 PHP 函数式编程*，强调 PHP 一直具有使用程序员定义的函数库而不是类的能力，PHP 7 也不例外。在本章中，我们将更仔细地研究函数处理的改进，包括提供涉及基本数据类型（如整数、浮点数、布尔值和字符串）的“类型提示”，用于输入和输出。我们还将广泛介绍标准 PHP 库中的迭代器，以及如何利用生成器的改进处理编写自己的迭代器。

第四章，*使用 PHP 面向对象编程*，探讨了 PHP 面向对象编程的基础知识。迅速超越基础知识，您将学习如何使用 PHP 命名空间和特征。还将涵盖架构考虑因素，包括如何最好地使用接口。最后，将讨论一个令人兴奋的新功能 PHP 7，即匿名类，并提供其实际用例。

第五章，*与数据库交互*，探讨了应用程序从数据库中读取和写入数据的能力，这是任何现代网站的关键部分。然而，广泛误解的是正确使用 PHP 数据对象（PDO）扩展。本章将全面介绍 PDO，从而使您的应用程序能够与大多数主要数据库交互，包括 MySQL、Oracle、PostgreSQL、IBM DB2 和 Microsoft SQL Server，而无需学习任何其他一套命令。此外，我们还将涵盖高级技术，如使用领域模型实体、执行嵌入式次要查找以及使用 PHP 7 实现 jQuery DataTable 查找。

第六章，*构建可扩展的网站*，深入探讨了 PHP 开发人员在构建交互式网站时面临的经典问题之一——硬编码 HTML 表单，然后需要进行维护。本章介绍了一种简洁高效的面向对象方法，只需很少的代码，就可以生成整个 HTML 表单，并且可以在初始配置中轻松更改。另一个同样棘手的问题是如何过滤和验证从表单提交的数据。在本章中，您将学习如何开发一个易于配置的过滤和验证工厂，然后可以应用于任何传入的提交数据。

第七章，*访问 Web 服务*，涵盖了对 Web 开发越来越重要的内容——发布或消费 Web 服务的能力。本章涵盖了两种关键方法：SOAP 和 REST。您将学习如何实现 SOAP 和 REST 服务器和客户端。此外，所呈现的示例使用了适配器设计模式，这允许相当大程度的定制，这意味着您不会被锁定在特定的设计范式中。

第八章，*处理日期/时间和国际化方面*，帮助您应对由于万维网（WWW）的增长而导致的激烈竞争，从而导致越来越多的客户希望将业务拓展到国际市场。本章将使您了解国际化的各个方面，包括使用表情符号、复杂字符和翻译。此外，您将学习如何获取和处理区域信息，包括语言设置、数字和货币格式化，以及日期和时间。此外，我们还将介绍如何创建国际化日历的配方，这些日历可以处理重复事件。

第九章，*开发中间件*，涉及了当前开源社区中最热门的话题——中间件。顾名思义，中间件是可以“插入”到现有应用程序中，为该应用程序增加价值而无需修改该应用程序源代码的软件。在本章中，您将看到一系列配方，实现为符合 PSR-7 标准的中间件（有关更多详细信息，请参见附录，*定义 PSR-7 类*），执行身份验证、访问控制、缓存和路由。

第十章，*深入了解高级算法*，帮助您了解作为开发人员，鉴于大量的程序员和公司竞争同一业务，掌握关键的高级算法非常重要。在本章中，您将使用 PHP 7 学习获取器和设置器、链表、冒泡排序、栈和二分查找的理论和应用。此外，本章还探讨了如何使用这些技术来实现搜索引擎，以及如何处理多维数组。

第十一章，*实现软件设计模式*，涉及面向对象编程的一个重要方面，即理解关键的软件设计模式。如果没有这些知识，在申请新职位或吸引新客户时，作为开发人员，您将处于严重劣势。本章涵盖了几个非常重要的模式，包括 Hydration、Strategy、Mapper、Object Relational Mapping 和 Pub/Sub。

第十二章，*提高 Web 安全性*，解决了当今互联网的普遍性带来的问题。我们看到网络攻击的频率越来越高，往往造成严重的财务和个人损失。在本章中，我们将提供实用的实用食谱，如果实施，将大大提高您的网站的安全性。涵盖的主题包括过滤和验证、会话保护、安全表单提交、安全密码生成以及使用 CAPTCHA。此外，还介绍了一种食谱，将向您展示如何在不使用 PHP mcrypt 扩展的情况下加密和解密数据，该扩展在 PHP 7.1 中已被弃用（最终将从语言中删除）。

第十三章，*最佳实践、测试和调试*，涵盖了编写良好的代码以使其正常工作的最佳实践和调试。在本章中，您还将学习如何设置和创建单元测试，处理意外错误和异常以及生成测试数据。介绍了几个新的 PHP 7 功能，包括 PHP 7 如何“抛出”错误。重要的是要注意，*最佳实践*在整本书中都有提到，不仅仅是在本章中！

附录，*定义 PSR-7 类*，介绍了最近接受的 PHP 标准建议 7，该标准定义了与中间件一起使用的接口。在本附录中，您将看到 PSR-7 类的实际实现，其中包括 URI、正文和文件上传等值对象，以及请求和响应对象。

# 本书所需的内容

要成功实施本书中提出的食谱，您需要一台计算机、额外 100MB 的磁盘空间以及一个文本或代码编辑器（而不是文字处理软件！）。第一章将介绍如何设置 PHP 7 开发环境。拥有 Web 服务器是可选的，因为 PHP 7 包含开发 Web 服务器。不需要互联网连接，但可能有用以下载代码（例如 PSR-7 接口集），并查看 PHP 7.x 文档。

# 本书适合谁

本书适用于软件架构师、技术经理、中级到高级开发人员，或者只是好奇的人。您需要对 PHP 编程有基本的了解，特别是面向对象编程。

# 章节

在本书中，您将找到一些经常出现的标题（准备工作、如何做、它是如何工作的、还有更多以及另请参阅）。

为了清晰地说明如何完成食谱，我们使用以下各节：

## 准备工作

本节告诉您可以在食谱中期待什么，并描述了如何设置食谱所需的任何软件或任何初步设置。

## 如何做...

本节包含了遵循食谱所需的步骤。

## 它是如何工作的...

本节通常包括对上一节中发生的事情的详细解释。

## 还有更多...

本节包括有关食谱的其他信息，以使读者更加了解食谱。

## 另请参阅

本节提供了有关该食谱的其他有用信息的链接。

# 约定

在本书中，您将找到一些文本样式，用于区分不同类型的信息。以下是这些样式的一些示例以及它们的含义解释。

文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下：“最后，取出第三个项目中定义的`LotsProps`类，并将其放入一个单独的文件中，`chap_10_oop_using_getters_and_setters_magic_call.php`。”

代码块设置如下：

```php
protected static function loadFile($file)
{
    if (file_exists($file)) {
        require_once $file;
        return TRUE;
    }
    return FALSE;
}
```

当我们希望引起您对代码块的特定部分的注意时，相关的行或项目会以粗体显示：

```php
$params = [
  'db'   => __DIR__ . '/../data/db/php7cookbook.db.sqlite'
];
$dsn  = sprintf(**'sqlite:' . $params['db']**);
```

任何命令行输入或输出都是这样写的：

```php
**cd /path/to/recipes**
**php -S localhost:8080**

```

**新术语**和**重要单词**以粗体显示。屏幕上看到的单词，例如菜单或对话框中的单词，会在文本中以这种方式出现：“当点击**购买**按钮时，初始购买信息会出现。”

### 注意

警告或重要说明会出现在这样的框中。

### 提示

提示和技巧看起来像这样。


# 第一章：打下基础

在本章中，我们将涵盖以下主题：

+   PHP 7 安装注意事项

+   使用内置的 PHP Web 服务器

+   定义一个测试 MySQL 数据库

+   安装 PHPUnit

+   实现类自动加载

+   悬停在网站上

+   构建深网扫描器

+   创建一个 PHP 5 到 PHP 7 代码转换器

# 介绍

本章旨在作为一个*快速入门*，让您立即开始在 PHP 7 上运行并实施配方。本书的基本假设是您已经对 PHP 和编程有很好的了解。虽然本书不会详细介绍 PHP 的实际安装，但考虑到 PHP 7 相对较新，我们将尽力指出您在 PHP 7 安装过程中可能遇到的怪癖和*陷阱*。

# PHP 7 安装注意事项

有三种主要获取 PHP 7 的方法：

+   直接从源代码下载和安装

+   安装*预编译*二进制文件

+   安装*AMP 包（即 XAMPP，WAMP，LAMP，MAMP 等）

## 如何做...

这三种方法按难度顺序列出。然而，第一种方法虽然繁琐，但可以让您对扩展和选项有最精细的控制。

### 直接从源代码安装

为了使用这种方法，您需要有一个 C 编译器。如果您使用 Windows，**MinGW**是一个广受欢迎的免费编译器。它基于**GNU**项目提供的**GNU Compiler Collection**（**GCC**）编译器。非免费的编译器包括 Borland 的经典**Turbo C**编译器，当然，Windows 开发人员首选的编译器是**Visual Studio**。然而，后者主要设计用于 C++开发，因此在编译 PHP 时，您需要指定 C 模式。

在苹果 Mac 上工作时，最好的解决方案是安装**Apple Developer Tools**。您可以使用**Xcode IDE**编译 PHP 7，或者从终端窗口运行`gcc`。在 Linux 环境中，从终端窗口运行`gcc`。

在终端窗口或命令行编译时，正常的程序如下：

+   `configure`

+   `制作`

+   `make test`

+   `make install`

有关配置选项（即运行`configure`时）的信息，请使用`help`选项：

```php
**configure --help**

```

在配置阶段可能遇到的错误在下表中提到：

| 错误 | 修复 |
| --- | --- |
| `configure: error: xml2-config not found. Please check your libxml2 installation` | 您只需要安装`libxml2`。有关此错误，请参阅以下链接：[`superuser.com/questions/740399/how-to-fix-php-installation-when-xml2-config-is-missing`](http://superuser.com/questions/740399/how-to-fix-php-installation-when-xml2-config-is-missing) |
| `configure: error: Please reinstall readline - I cannot find readline.h` | 安装`libreadline-dev` |
| `configure: WARNING: unrecognized options: --enable-spl, --enable-reflection, --with-libxml` | 没关系。这些选项是默认的，不需要包含在内。有关更多详细信息，请参阅以下链接：[`jcutrer.com/howto/linux/how-to-compile-php7-on-ubuntu-14-04`](http://jcutrer.com/howto/linux/how-to-compile-php7-on-ubuntu-14-04) |

### 从预编译的二进制文件安装 PHP 7

正如标题所示，**预编译**二进制文件是一组由他人从 PHP 7 源代码编译而成并提供的二进制文件。

在 Windows 的情况下，转到[`windows.php.net/`](http://windows.php.net/)。您将在左栏找到一些关于选择哪个版本、**线程安全**与**非线程安全**等的提示。然后您可以点击**Downloads**并查找适用于您环境的 ZIP 文件。下载 ZIP 文件后，将文件解压到您选择的文件夹中，将`php.exe`添加到您的路径，并使用`php.ini`文件配置 PHP 7。

要在 Mac OS X 系统上安装预编译的二进制文件，最好使用包管理系统。PHP 推荐的包括以下内容：

+   MacPorts

+   Liip

+   Fink

+   Homebrew

在 Linux 的情况下，使用的打包系统取决于您使用的 Linux 发行版。以下表格按 Linux 发行版组织，总结了查找 PHP 7 包的位置。

| 分发 | PHP 7 在哪里找到 | 注释 |
| --- | --- | --- |

| Debian | `packages.debian.org/stable/php``repos-source.zend.com/zend-server/early-access/php7/php-7*DEB*` | 使用此命令：

```php
**sudo apt-get install php7**

```

或者，您可以使用图形包管理工具，如**Synaptic**。确保选择**php7**（而不是 php5）。 |

| Ubuntu | `packages.ubuntu.com``repos-source.zend.com/zend-server/early-access/php7/php-7*DEB*` | 使用此命令：`sudo apt-get install php7`确保选择正确的 Ubuntu 版本。或者，您可以使用图形包管理工具，如**Synaptic**。 |
| --- | --- | --- |

| Fedora / Red Hat | `admin.fedoraproject.org/pkgdb/packages``repos-source.zend.com/zend-server/early-access/php7/php-7*RHEL*` | 确保您是 root 用户：

```php
**su**

```

使用此命令：**dnf install php7**或者，您可以使用图形包管理工具，如 GNOME 包管理器。 |

| OpenSUSE | `software.opensuse.org/package/php7` | 使用此命令：

```php
**yast -i php7**

```

或者，您可以运行`zypper`，或者使用**YaST**作为图形工具。 |

### 安装*AMP 包

**AMP**指的是**Apache**，**MySQL**和**PHP**（还包括**Perl**和**Python**）。*****指的是 Linux、Windows、Mac 等（即 LAMP、WAMP 和 MAMP）。这种方法通常是最简单的，但是您对初始 PHP 安装的控制较少。另一方面，您可以随时修改`php.ini`文件并安装其他扩展来自定义您的安装。以下表格总结了一些流行的*AMP 包：

| Package | 找到它在哪里 | 免费？ | 支持* |
| --- | --- | --- | --- |
| `XAMPP` | [www.apachefriends.org/download.html](http://www.apachefriends.org/download.html) | Y | WML |
| `AMPPS` | [www.ampps.com/downloads](http://www.ampps.com/downloads) | Y | WML |
| `MAMP` | [www.mamp.info/en](http://www.mamp.info/en) | Y | WM |
| `WampServer` | [sourceforge.net/projects/wampserver](http://sourceforge.net/projects/wampserver) | Y | W |
| `EasyPHP` | [www.easyphp.org](http://www.easyphp.org) | Y | W |
| `Zend Server` | [www.zend.com/en/products/zend_server](http://www.zend.com/en/products/zend_server) | N | WML |

在上表中，我们列出了**W**替换为**W**的*AMP 包，**M**替换为 Mac OS X，**L**替换为 Linux。

## 还有更多...

当您从软件包安装预编译的二进制文件时，只安装了`core`扩展。非核心 PHP 扩展必须单独安装。

值得注意的是，云计算平台上的 PHP 7 安装通常会遵循预编译二进制文件的安装过程。了解您的云环境是否使用 Linux、Mac 或 Windows 虚拟机，然后按照本文中提到的适当过程进行操作。

可能 PHP 7 尚未到达您喜欢的预编译二进制文件存储库。您可以始终从源代码安装，或者考虑安装其中一个*AMP 包（请参阅下一节）。对于基于 Linux 的系统，另一种选择是使用**个人软件包存档**（**PPA**）方法。但是，由于 PPA 尚未经过严格的筛选过程，安全性可能是一个问题。有关 PPA 安全考虑的良好讨论可在[`askubuntu.com/questions/35629/are-ppas-safe-to-add-to-my-system-and-what-are-some-red-flags-to-watch-out-fo`](http://askubuntu.com/questions/35629/are-ppas-safe-to-add-to-my-system-and-what-are-some-red-flags-to-watch-out-fo)找到。

## 另请参阅

可以在[`php.net/manual/en/install.general.php`](http://php.net/manual/en/install.general.php)找到一般安装注意事项，以及针对三个主要操作系统平台（Windows、Mac OS X 和 Linux）的说明。

MinGW 的网站是[`www.mingw.org/`](http://www.mingw.org/)。

有关如何使用 Visual Studio 编译 C 程序的说明，请访问[`msdn.microsoft.com/en-us/library/bb384838`](https://msdn.microsoft.com/en-us/library/bb384838)。

测试 PHP 7 的另一种可能的方法是使用虚拟机。以下是一些工具及其链接，可能会有用：

+   **Vagrant**：[`github.com/rlerdorf/php7dev`](https://github.com/rlerdorf/php7dev)（php7dev 是一个预先配置用于测试 PHP 应用程序和在许多 PHP 版本上开发扩展的 Debian 8 Vagrant 映像）

+   **Docker**：[`hub.docker.com/r/coderstephen/php7/`](https://hub.docker.com/r/coderstephen/php7/)（其中包含一个 PHP7 Docker 容器）

# 使用内置的 PHP Web 服务器

除了单元测试和直接从命令行运行 PHP 之外，测试应用程序的明显方法是使用 Web 服务器。对于长期项目，为了开发与客户使用的 Web 服务器最接近的虚拟主机定义将是有益的。为各种 Web 服务器（如 Apache、NGINX 等）创建这样的定义超出了本书的范围。另一个快速且易于使用的替代方法（我们在这里有讨论的空间）是使用内置的 PHP 7 Web 服务器。

## 如何做...

1.  要激活 PHP Web 服务器，首先切换到将用作代码基础的目录。

1.  然后，您需要提供主机名或 IP 地址，以及可选的端口。以下是您可以使用来运行本书提供的示例的示例：

```php
cd /path/to/recipes
php -S localhost:8080
```

您将在屏幕上看到类似以下内容的输出：

![如何做...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_01_01.jpg)

1.  随着内置的 Web 服务器继续服务请求，您还将看到访问信息、HTTP 状态代码和请求信息。

1.  如果您需要将 Web 服务器文档根目录设置为当前目录以外的目录，可以使用`-t`标志。然后，该标志必须跟随有效的目录路径。内置的 Web 服务器将把这个目录视为 Web 文档根目录，这对安全原因很有用。出于安全原因，一些框架（如 Zend Framework）要求 Web 文档根目录与实际源代码所在的位置不同。

以下是使用`-t`标志的示例：

```php
**php -S localhost:8080 -t source/chapter01**

```

以下是输出的示例：

![如何做...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_01_02.jpg)

# 定义一个测试 MySQL 数据库

为了测试目的，除了本书的源代码，我们还提供了一个带有示例数据的 SQL 文件，位于[`github.com/dbierer/php7cookbook`](https://github.com/dbierer/php7cookbook)。本书中用于示例的数据库名称是`php7cookbook`。

## 如何做...

1.  定义一个 MySQL 数据库，`php7cookbook`。还将新数据库的权限分配给名为`cook`的用户，密码为`book`。以下表总结了这些设置：

| 项目 | 注释 |
| --- | --- |
| 数据库名称 | `php7cookbook` |
| 数据库用户 | `cook` |
| 数据库用户密码 | `book` |

1.  以下是创建数据库所需的 SQL 示例：

```php
CREATE DATABASE IF NOT EXISTS dbname DEFAULT CHARACTER SET utf8 COLLATE utf8_general_ci;
CREATE USER 'user'@'%' IDENTIFIED WITH mysql_native_password;
SET PASSWORD FOR 'user'@'%' = PASSWORD('userPassword');
GRANT ALL PRIVILEGES ON dbname.* to 'user'@'%';
GRANT ALL PRIVILEGES ON dbname.* to 'user'@'localhost';
FLUSH PRIVILEGES;
```

1.  将示例值导入新数据库。导入文件`php7cookbook.sql`位于[`github.com/dbierer/php7cookbook/blob/master/php7cookbook.sql`](https://github.com/dbierer/php7cookbook/blob/master/php7cookbook.sql)。

# 安装 PHPUnit

单元测试可以说是测试 PHP 代码的最流行方式。大多数开发人员都会同意，一个完善的测试套件是任何正确开发项目的必备条件。但是很少有开发人员实际编写这些测试。幸运的是，有一些独立的测试组为他们编写测试！然而，经过数月与测试组的战斗后，幸运的人往往会抱怨和抱怨。无论如何，任何一本关于 PHP 的书都不会完整，如果没有至少对测试的一点点提及。

找到**PHPUnit**的最新版本的地方是[`phpunit.de/`](https://phpunit.de/)。PHPUnit5.1 及以上版本支持 PHP 7。单击所需版本的链接，然后下载`phpunit.phar`文件。然后可以使用存档执行命令，如下所示：

```php
**php phpunit.phar <command>**

```

### 提示

`phar`命令代表**PHP Archive**。这项技术基于`tar`，`tar`本身是在 UNIX 中使用的。`phar`文件是一组 PHP 文件，它们被打包到一个单个文件中以方便使用。

# 实现类自动加载

在使用**面向对象编程**（**OOP**）方法开发 PHP 时，建议将每个类放在自己的文件中。遵循这个建议的好处是长期维护和提高可读性的便利。缺点是每个类定义文件必须被包含（即使用`include`或其变体）。为了解决这个问题，PHP 语言内置了一个机制，可以*自动加载*任何尚未被特别包含的类。

## 准备工作

PHP 自动加载的最低要求是定义一个全局的`__autoload()`函数。这是一个*魔术*函数，当 PHP 引擎自动调用时，会请求一个类，但该类尚未被包含。请求的类的名称将在调用`__autoload()`时作为参数出现（假设您已经定义了它！）。如果您使用 PHP 命名空间，将传递类的完整命名空间名称。因为`__autoload()`是一个*函数*，它必须在全局命名空间中；但是，对其使用有限制。因此，在本篇中，我们将使用`spl_autoload_register()`函数，这给了我们更多的灵活性。

## 操作方法...

1.  我们将在本篇中介绍的类是`Application\Autoload\Loader`。为了利用 PHP 命名空间和自动加载之间的关系，我们将文件命名为`Loader.php`，并将其放置在`/path/to/cookbook/files/Application/Autoload`文件夹中。

1.  我们将介绍的第一种方法是简单地加载一个文件。我们使用`file_exists()`在运行`require_once()`之前进行检查。这样做的原因是，如果文件未找到，`require_once()`将生成一个无法使用 PHP 7 的新错误处理功能捕获的致命错误：

```php
protected static function loadFile($file)
{
    if (file_exists($file)) {
        require_once $file;
        return TRUE;
    }
    return FALSE;
}
```

1.  然后我们可以在调用程序中测试`loadFile()`的返回值，并在无法加载文件时抛出`Exception`之前循环遍历备用目录列表。

### 提示

您会注意到这个类中的方法和属性都是静态的。这使我们在注册自动加载方法时更加灵活，并且还可以将`Loader`类视为**单例**。

1.  接下来，我们定义调用`loadFile()`并实际执行基于命名空间类名定位文件的逻辑的方法。该方法通过将 PHP 命名空间分隔符`\`转换为适合该服务器的目录分隔符并附加`.php`来派生文件名：

```php
public static function autoLoad($class)
{
    $success = FALSE;
    $fn = str_replace('\\', DIRECTORY_SEPARATOR, $class) 
          . '.php';
    foreach (self::$dirs as $start) {
        $file = $start . DIRECTORY_SEPARATOR . $fn;
        if (self::loadFile($file)) {
            $success = TRUE;
            break;
        }
    }
    if (!$success) {
        if (!self::loadFile(__DIR__ 
            . DIRECTORY_SEPARATOR . $fn)) {
            throw new \Exception(
                self::UNABLE_TO_LOAD . ' ' . $class);
        }
    }
    return $success;
}
```

1.  接下来，该方法循环遍历我们称之为`self::$dirs`的目录数组，使用每个目录作为派生文件名的起点。如果不成功，作为最后的手段，该方法尝试从当前目录加载文件。如果甚至这样也不成功，就会抛出一个`Exception`。

1.  接下来，我们需要一个可以将更多目录添加到我们要测试的目录列表中的方法。请注意，如果提供的值是一个数组，则使用`array_merge()`。否则，我们只需将目录字符串添加到`self::$dirs`数组中：

```php
public static function addDirs($dirs)
{
    if (is_array($dirs)) {
        self::$dirs = array_merge(self::$dirs, $dirs);
    } else {
        self::$dirs[] = $dirs;
    }
}  
```

1.  然后，我们来到最重要的部分；我们需要将我们的`autoload()`方法注册为**标准 PHP 库**（**SPL**）自动加载程序。这是使用`spl_autoload_register()`和`init()`方法来实现的：

```php
public static function init($dirs = array())
{
    if ($dirs) {
        self::addDirs($dirs);
    }
    if (self::$registered == 0) {
        spl_autoload_register(__CLASS__ . '::autoload');
        self::$registered++;
    }
}
```

1.  此时，我们可以定义`__construct()`，它调用`self::init($dirs)`。这使我们也可以创建`Loader`的实例（如果需要的话）。

```php
public function __construct($dirs = array())
{
    self::init($dirs);
}
```

## 它是如何工作的...

为了使用我们刚刚定义的自动加载程序类，您需要`require Loader.php`。如果您的命名空间文件位于当前目录之外的目录中，您还应该运行`Loader::init()`并提供额外的目录路径。

为了确保自动加载程序正常工作，我们还需要一个测试类。这是`/path/to/cookbook/files/Application/Test/TestClass.php`的定义：

```php
<?php
namespace Application\Test;
class TestClass
{
    public function getTest()
    {
        return __METHOD__;
    }
}
```

现在创建一个样本`chap_01_autoload_test.php`代码文件来测试自动加载程序：

```php
<?php
require __DIR__ . '/../Application/Autoload/Loader.php';
Application\Autoload\Loader::init(__DIR__ . '/..');
```

接下来，获取一个尚未加载的类的实例：

```php
$test = new Application\Test\TestClass();
echo $test->getTest();
```

最后，尝试获取一个不存在的`fake`类。请注意，这将引发错误：

```php
$fake = new Application\Test\FakeClass();
echo $fake->getTest();
```

# 清理网站

经常有兴趣扫描网站并从特定标签中提取信息。这种基本机制可以用来在网络中搜索有用的信息。有时需要获取`<IMG>`标签和`SRC`属性的列表，或者`<A>`标签和相应的`HREF`属性。可能性是无限的。

## 如何做...

1.  首先，我们需要获取目标网站的内容。乍一看，似乎我们应该发出 cURL 请求，或者简单地使用`file_get_contents()`。这些方法的问题是，我们最终将不得不进行大量的字符串操作，很可能不得不大量使用可怕的正则表达式。为了避免所有这些，我们将简单地利用已经存在的 PHP 7 类`DOMDocument`。因此，我们创建一个`DOMDocument`实例，将其设置为**UTF-8**。我们不关心空格，并使用方便的`loadHTMLFile()`方法将网站的内容加载到对象中：

```php
public function getContent($url)
{
    if (!$this->content) {
        if (stripos($url, 'http') !== 0) {
            $url = 'http://' . $url;
        }
        $this->content = new DOMDocument('1.0', 'utf-8');
        $this->content->preserveWhiteSpace = FALSE;
        // @ used to suppress warnings generated from // improperly configured web pages
        @$this->content->loadHTMLFile($url);
    }
    return $this->content;
}
```

### 提示

请注意，在调用`loadHTMLFile()`方法之前，我们在其前面加上了`@`。这不是为了掩盖糟糕的编码（`!`），这在 PHP 5 中经常发生！相反，`@`抑制了解析器在遇到编写不良的 HTML 时生成的通知。据推测，我们可以捕获通知并记录它们，可能还给我们的`Hoover`类提供诊断能力。

1.  接下来，我们需要提取感兴趣的标签。我们使用`getElementsByTagName()`方法来实现这个目的。如果我们希望提取*所有*标签，我们可以提供`*`作为参数：

```php
public function getTags($url, $tag)
{
    $count    = 0;
    $result   = array();
    $elements = $this->getContent($url)
                     ->getElementsByTagName($tag);
    foreach ($elements as $node) {
        $result[$count]['value'] = trim(preg_replace('/\s+/', ' ', $node->nodeValue));
        if ($node->hasAttributes()) {
            foreach ($node->attributes as $name => $attr) 
            {
                $result[$count]['attributes'][$name] = 
                    $attr->value;
            }
        }
        $count++;
    }
    return $result;
}
```

1.  提取特定属性而不是标签可能也是有趣的。因此，我们为此定义另一个方法。在这种情况下，我们需要遍历所有标签并使用`getAttribute()`。您会注意到有一个用于 DNS 域的参数。我们添加了这个参数，以便在同一个域内保持扫描（例如，如果您正在构建一个网页树）：

```php
public function getAttribute($url, $attr, $domain = NULL)
{
    $result   = array();
    $elements = $this->getContent($url)
                     ->getElementsByTagName('*');
    foreach ($elements as $node) {
        if ($node->hasAttribute($attr)) {
            $value = $node->getAttribute($attr);
            if ($domain) {
                if (stripos($value, $domain) !== FALSE) {
                    $result[] = trim($value);
                }
            } else {
                $result[] = trim($value);
            }
        }
    }
    return $result;
}
```

## 它是如何工作的...

为了使用新的`Hoover`类，初始化自动加载程序（如前所述）并创建`Hoover`类的实例。然后可以运行`Hoover::getTags()`方法，以产生您指定为参数的 URL 的标签数组。

这是来自`chap_01_vacuuming_website.php`的一段代码，它使用`Hoover`类来扫描 O'Reilly 网站的`<A>`标签：

```php
<?php
// modify as needed
define('DEFAULT_URL', 'http://oreilly.com/');
define('DEFAULT_TAG', 'a');

require __DIR__ . '/../Application/Autoload/Loader.php';
Application\Autoload\Loader::init(__DIR__ . '/..');

// get "vacuum" class
$vac = new Application\Web\Hoover();

// NOTE: the PHP 7 null coalesce operator is used
$url = strip_tags($_GET['url'] ?? DEFAULT_URL);
$tag = strip_tags($_GET['tag'] ?? DEFAULT_TAG);

echo 'Dump of Tags: ' . PHP_EOL;
var_dump($vac->getTags($url, $tag));
```

输出将看起来像这样：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_01_03.jpg)

## 另请参阅

有关 DOM 的更多信息，请参阅 PHP 参考页面[`php.net/manual/en/class.domdocument.php`](http://php.net/manual/en/class.domdocument.php)。

# 构建深层网络扫描器

有时您需要扫描一个网站，但要深入一级。例如，您想要构建一个网站的 Web 树图。这可以通过查找所有`<A>`标签并跟踪`HREF`属性到下一个网页来实现。一旦您获得了子页面，您可以继续扫描以完成树。

## 如何做...

1.  深层网络扫描仪的核心组件是一个基本的`Hoover`类，如前所述。本配方中介绍的基本过程是扫描目标网站并清理所有`HREF`属性。为此，我们定义了一个`Application\Web\Deep`类。我们添加一个表示 DNS 域的属性：

```php
namespace Application\Web;
class Deep
{
    protected $domain;
```

1.  接下来，我们定义一个方法，将为扫描列表中表示的每个网站的标签进行清理。为了防止扫描器在整个**万维网**（**WWW**）上进行搜索，我们将扫描限制在目标域上。添加`yield from`的原因是因为我们需要产生`Hoover::getTags()`生成的整个数组。`yield from`语法允许我们将数组视为子生成器：

```php
public function scan($url, $tag)
{
    $vac    = new Hoover();
    $scan   = $vac->getAttribute($url, 'href', 
       $this->getDomain($url));
    $result = array();
    foreach ($scan as $subSite) {
        yield from $vac->getTags($subSite, $tag);
    }
    return count($scan);
}
```

### 注意

使用`yield from`将`scan()`方法转换为 PHP 7 委托生成器。通常，您会倾向于将扫描结果存储在数组中。然而，在这种情况下，检索到的信息量可能会非常庞大。因此，最好立即产生结果，以节省内存并产生即时结果。否则，将会有一个漫长的等待，可能会导致内存不足错误。

1.  为了保持在同一个域中，我们需要一个方法，将从 URL 中返回域。我们使用方便的`parse_url()`函数来实现这个目的：

```php
public function getDomain($url)
{
    if (!$this->domain) {
        $this->domain = parse_url($url, PHP_URL_HOST);
    }
    return $this->domain;
}
```

## 它是如何工作的...

首先，继续定义之前定义的`Application\Web\Deep`类，以及前一个配方中定义的`Application\Web\Hoover`类。

接下来，定义一个代码块，来自`chap_01_deep_scan_website.php`，设置自动加载（如本章前面描述的）：

```php
<?php
// modify as needed
define('DEFAULT_URL', unlikelysource.com');
define('DEFAULT_TAG', 'img');

require __DIR__ . '/../../Application/Autoload/Loader.php';
Application\Autoload\Loader::init(__DIR__ . '/../..');
```

接下来，获取我们新类的一个实例：

```php
$deep = new Application\Web\Deep();
```

在这一点上，您可以从 URL 参数中检索 URL 和标签信息。PHP 7 的`null coalesce`运算符对于建立回退值非常有用：

```php
$url = strip_tags($_GET['url'] ?? DEFAULT_URL);
$tag = strip_tags($_GET['tag'] ?? DEFAULT_TAG);
```

一些简单的 HTML 将显示结果：

```php
foreach ($deep->scan($url, $tag) as $item) {
    $src = $item['attributes']['src'] ?? NULL;
    if ($src && (stripos($src, 'png') || stripos($src, 'jpg'))) {
        printf('<br><img src="%s"/>', $src);
    }
}
```

## 另请参阅

有关生成器和`yield from`的更多信息，请参阅[`php.net/manual/en/language.generators.syntax.php`](http://php.net/manual/en/language.generators.syntax.php)上的文章。

# 创建一个 PHP 5 到 PHP 7 代码转换器

在大多数情况下，PHP 5.x 代码可以在 PHP 7 上不经修改地运行。然而，有一些更改被归类为*向后不兼容*。这意味着，如果您的 PHP 5 代码以某种方式编写，或者使用了已删除的函数，您的代码将会出错，您将会遇到一个令人讨厌的错误。

## 准备工作

*PHP 5 到 PHP 7 代码转换器*执行两项任务：

+   扫描您的代码文件，并将已删除的 PHP 5 功能转换为 PHP 7 中的等效功能

+   在更改语言使用的地方添加了`//` `WARNING`注释，但不可能进行重写

### 注意

请注意，在运行转换器之后，不能保证您的代码在 PHP 7 中能够正常工作。您仍然需要查看添加的`//` `WARNING`标签。至少，这个方法将为您提供一个很好的起点，将您的 PHP 5 代码转换为在 PHP 7 中运行。

这个方法的核心是新的 PHP 7 `preg_replace_callback_array()`函数。这个神奇的函数允许您将一系列正则表达式作为键呈现，并将值表示为独立的回调。然后，您可以通过一系列转换来传递字符串。不仅如此，回调数组的主题本身也可以是一个数组。

## 如何做...

1.  在一个新的类`Application\Parse\Convert`中，我们从一个`scan()`方法开始，该方法接受一个文件名作为参数。它检查文件是否存在。如果存在，它调用 PHP 的`file()`函数，该函数将文件加载到一个数组中，其中每个数组元素代表一行：

```php
public function scan($filename)
{
    if (!file_exists($filename)) {
        throw new Exception(
            self::EXCEPTION_FILE_NOT_EXISTS);
    }
    $contents = file($filename);
    echo 'Processing: ' . $filename . PHP_EOL;

    $result = preg_replace_callback_array( [
```

1.  接下来，我们开始传递一系列键/值对。键是一个正则表达式，它针对字符串进行处理。任何匹配项都会传递给回调函数，该回调函数表示为键/值对的值部分。我们检查已从 PHP 7 中删除的开放和关闭标签：

```php
    // replace no-longer-supported opening tags
    '!^\<\%(\n| )!' =>
        function ($match) {
            return '<?php' . $match[1];
        },

    // replace no-longer-supported opening tags
    '!^\<\%=(\n| )!' =>
        function ($match) {
            return '<?php echo ' . $match[1];
        },

    // replace no-longer-supported closing tag
    '!\%\>!' =>
        function ($match) {
            return '?>';
        },
```

1.  接下来是一系列警告，当检测到某些操作并且在 PHP 5 与 PHP 7 中处理它们之间存在潜在的代码中断时。在所有这些情况下，代码都不会被重写。而是添加了一个带有`WARNING`单词的内联注释：

```php
    // changes in how $$xxx interpretation is handled
    '!(.*?)\$\$!' =>
        function ($match) {
            return '// WARNING: variable interpolation 
                   . ' now occurs left-to-right' . PHP_EOL
                   . '// see: http://php.net/manual/en/'
                   . '// migration70.incompatible.php'
                   . $match[0];
        },

    // changes in how the list() operator is handled
    '!(.*?)list(\s*?)?\(!' =>
        function ($match) {
            return '// WARNING: changes have been made '
                   . 'in list() operator handling.'
                   . 'See: http://php.net/manual/en/'
                   . 'migration70.incompatible.php'
                   . $match[0];
        },

    // instances of \u{
    '!(.*?)\\\u\{!' =>
        function ($match) {
        return '// WARNING: \\u{xxx} is now considered '
               . 'unicode escape syntax' . PHP_EOL
               . '// see: http://php.net/manual/en/'
               . 'migration70.new-features.php'
               . '#migration70.new-features.unicode-'
               . 'codepoint-escape-syntax' . PHP_EOL
               . $match[0];
    },

    // relying upon set_error_handler()
    '!(.*?)set_error_handler(\s*?)?.*\(!' =>
        function ($match) {
            return '// WARNING: might not '
                   . 'catch all errors'
                   . '// see: http://php.net/manual/en/'
                   . '// language.errors.php7.php'
                   . $match[0];
        },

    // session_set_save_handler(xxx)
    '!(.*?)session_set_save_handler(\s*?)?\((.*?)\)!' =>
        function ($match) {
            if (isset($match[3])) {
                return '// WARNING: a bug introduced in'
                       . 'PHP 5.4 which '
                       . 'affects the handler assigned by '
                       . 'session_set_save_handler() and '
                       . 'where ignore_user_abort() is TRUE 
                       . 'has been fixed in PHP 7.'
                       . 'This could potentially break '
                       . 'your code under '
                       . 'certain circumstances.' . PHP_EOL
                       . 'See: http://php.net/manual/en/'
                       . 'migration70.incompatible.php'
                       . $match[0];
            } else {
                return $match[0];
            }
        },
```

1.  任何尝试使用`<<`或`>>`与负操作符或超过 64 的操作都会被包裹在`try { xxx } catch() { xxx }`块中，寻找`ArithmeticError`的抛出：

```php
    // wraps bit shift operations in try / catch
    '!^(.*?)(\d+\s*(\<\<|\>\>)\s*-?\d+)(.*?)$!' =>
        function ($match) {
            return '// WARNING: negative and '
                   . 'out-of-range bitwise '
                   . 'shift operations will now 
                   . 'throw an ArithmeticError' . PHP_EOL
                   . 'See: http://php.net/manual/en/'
                   . 'migration70.incompatible.php'
                   . 'try {' . PHP_EOL
                   . "\t" . $match[0] . PHP_EOL
                   . '} catch (\\ArithmeticError $e) {'
                   . "\t" . 'error_log("File:" 
                   . $e->getFile() 
                   . " Message:" . $e->getMessage());'
                   . '}' . PHP_EOL;
        },
```

### 注意

PHP 7 已更改了错误处理方式。在某些情况下，错误被移动到与异常类似的分类中，并且可以被捕获！`Error`类和`Exception`类都实现了`Throwable`接口。如果要捕获`Error`或`Exception`，请捕获`Throwable`。

1.  接下来，转换器会重写任何使用`call_user_method*()`的用法，这在 PHP 7 中已被移除。这些将被替换为使用`call_user_func*()`的等效用法：

```php
    // replaces "call_user_method()" with
    // "call_user_func()"
    '!call_user_method\((.*?),(.*?)(,.*?)\)(\b|;)!' =>
        function ($match) {
            $params = $match[3] ?? '';
            return '// WARNING: call_user_method() has '
                      . 'been removed from PHP 7' . PHP_EOL
                      . 'call_user_func(['. trim($match[2]) . ',' 
                      . trim($match[1]) . ']' . $params . ');';
        },

    // replaces "call_user_method_array()" 
    // with "call_user_func_array()"
    '!call_user_method_array\((.*?),(.*?),(.*?)\)(\b|;)!' =>
        function ($match) {
            return '// WARNING: call_user_method_array()'
                   . 'has been removed from PHP 7'
                   . PHP_EOL
                   . 'call_user_func_array([' 
                   . trim($match[2]) . ',' 
                   . trim($match[1]) . '], ' 
                   . $match[3] . ');';
        },
```

1.  最后，任何尝试使用带有`/e`修饰符的`preg_replace()`都会被重写为使用`preg_replace_callback()`：

```php
     '!^(.*?)preg_replace.*?/e(.*?)$!' =>
    function ($match) {
        $last = strrchr($match[2], ',');
        $arg2 = substr($match[2], 2, -1 * (strlen($last)));
        $arg1 = substr($match[0], 
                       strlen($match[1]) + 12, 
                       -1 * (strlen($arg2) + strlen($last)));
         $arg1 = trim($arg1, '(');
         $arg1 = str_replace('/e', '/', $arg1);
         $arg3 = '// WARNING: preg_replace() "/e" modifier 
                   . 'has been removed from PHP 7'
                   . PHP_EOL
                   . $match[1]
                   . 'preg_replace_callback('
                   . $arg1
                   . 'function ($m) { return ' 
                   .    str_replace('$1','$m', $match[1]) 
                   .      trim($arg2, '"\'') . '; }, '
                   .      trim($last, ',');
         return str_replace('$1', '$m', $arg3);
    },

        // end array
        ],

        // this is the target of the transformations
        $contents
    );
    // return the result as a string
    return implode('', $result);
}
```

## 工作原理...

要使用转换器，请从命令行运行以下代码。您需要提供要作为参数扫描的 PHP 5 代码的文件名。

这段代码块`chap_01_php5_to_php7_code_converter.php`，从命令行运行，调用转换器：

```php
<?php
// get filename to scan from command line
$filename = $argv[1] ?? '';

if (!$filename) {
    echo 'No filename provided' . PHP_EOL;
    echo 'Usage: ' . PHP_EOL;
    echo __FILE__ . ' <filename>' . PHP_EOL;
    exit;
}

// setup class autoloading
require __DIR__ . '/../Application/Autoload/Loader.php';

// add current directory to the path
Application\Autoload\Loader::init(__DIR__ . '/..');

// get "deep scan" class
$convert = new Application\Parse\Convert();
echo $convert->scan($filename);
echo PHP_EOL;
```

## 另请参阅

有关不兼容的更多信息，请参考[`php.net/manual/en/migration70.incompatible.php`](http://php.net/manual/en/migration70.incompatible.php)。


# 第二章：使用 PHP 7 高性能特性

在本章中，我们将讨论并了解 PHP 5 和 PHP 7 之间的语法差异，包括以下内容：

+   理解抽象语法树

+   理解解析中的差异

+   理解`foreach()`处理中的差异

+   使用 PHP 7 增强功能提高性能

+   遍历大型文件

+   将电子表格上传到数据库

+   递归目录迭代器

# 介绍

在本章中，我们将直接进入 PHP 7，介绍利用新的高性能特性的配方。然而，我们将首先介绍一系列较小的配方，以说明 PHP 7 处理参数解析、语法、`foreach()`循环和其他增强功能的差异。在深入探讨本章内容之前，让我们讨论一些 PHP 5 和 PHP 7 之间的基本差异。

PHP 7 引入了一个新的层，称为**抽象语法树**（**AST**），它有效地将解析过程与伪编译过程分离。尽管新层对性能几乎没有影响，但它赋予了语言一种新的语法统一性，这在以前是不可能的。

AST 的另一个好处是*取消引用*的过程。取消引用简单地指的是立即从对象中获取属性或运行方法，立即访问数组元素，并立即执行回调的能力。在 PHP 5 中，这种支持是不一致和不完整的。例如，要执行回调，通常需要先将回调或匿名函数赋值给一个变量，然后执行它。在 PHP 7 中，你可以立即执行它。

# 理解抽象语法树

作为开发人员，你可能会对摆脱 PHP 5 及更早版本中施加的某些语法限制感兴趣。除了之前提到的语法的统一性外，你将看到语法最大的改进是能够调用任何返回值，只需在后面添加一组额外的括号。此外，当返回值是数组时，你将能够直接访问任何数组元素。

## 如何做...

1.  任何返回回调的函数或方法都可以通过简单地添加括号`()`（带或不带参数）立即执行。任何返回数组的函数或方法都可以通过使用方括号`[]`指示元素来立即取消引用。在下面显示的简短（但琐碎）示例中，函数`test()`返回一个数组。数组包含六个匿名函数。`$a`的值为`$t`。`$$a`被解释为`$test`：

```php
function test()
{
    return [
        1 => function () { return [
            1 => function ($a) { return 'Level 1/1:' . ++$a; },
            2 => function ($a) { return 'Level 1/2:' . ++$a; },
        ];},
        2 => function () { return [
            1 => function ($a) { return 'Level 2/1:' . ++$a; },
            2 => function ($a) { return 'Level 2/2:' . ++$a; },
        ];}
    ];
}

$a = 't';
$t = 'test';
echo $$a()[1]()2;
```

1.  AST 允许我们发出`echo $$a()[1]()2`命令。这是从左到右解析的，执行如下：

+   `$$a()`被解释为`test()`，返回一个数组

+   `[1]`取消引用数组元素`1`，返回一个回调

+   `()`执行此回调，返回一个包含两个元素的数组

+   `[2]`取消引用数组元素`2`，返回一个回调

+   `(100)`执行此回调，提供值`100`，返回`Level 1/2:101`

### 提示

在 PHP 5 中不可能有这样的语句：会返回解析错误。

1.  以下是一个更加实质性的例子，利用 AST 语法来定义数据过滤和验证类。首先，我们定义`Application\Web\Securityclass`。在构造函数中，我们构建并定义了两个数组。第一个数组由过滤回调组成。第二个数组有验证回调：

```php
public function __construct()
  {
    $this->filter = [
      'striptags' => function ($a) { return strip_tags($a); },
      'digits'    => function ($a) { return preg_replace(
      '/[⁰-9]/', '', $a); },
      'alpha'     => function ($a) { return preg_replace(
      '/[^A-Z]/i', '', $a); }
    ];
    $this->validate = [
      'alnum'  => function ($a) { return ctype_alnum($a); },
      'digits' => function ($a) { return ctype_digit($a); },
      'alpha'  => function ($a) { return ctype_alpha($a); }
    ];
  }
```

1.  我们希望能以*开发人员友好*的方式调用此功能。因此，如果我们想要过滤数字，那么运行这样的命令将是理想的：

```php
$security->filterDigits($item));
```

1.  为了实现这一点，我们定义了魔术方法`__call()`，它使我们能够访问不存在的方法：

```php
public function __call($method, $params)
{

  preg_match('/^(filter|validate)(.*?)$/i', $method, $matches);
  $prefix   = $matches[1] ?? '';
  $function = strtolower($matches[2] ?? '');
  if ($prefix && $function) {
    return $this->$prefix$function;
  }
  return $value;
}
```

我们使用`preg_match()`来匹配`$method`参数与`filter`或`validate`。然后，第二个子匹配将被转换为`$this->filter`或`$this->validate`中的数组键。如果两个子模式都产生子匹配，我们将第一个子匹配分配给`$prefix`，将第二个子匹配分配给`$function`。这些最终成为执行适当回调时的变量参数。

### 提示

**不要对这些东西太疯狂！**

当您沉浸在 AST 所带来的新的表达自由中时，请务必记住，您最终编写的代码可能会变得极其晦涩。这最终将导致长期的维护问题。

## 它是如何工作的...

首先，我们创建一个示例文件，`chap_02_web_filtering_ast_example.php`，以利用第一章中定义的自动加载类，*构建基础*，以获得`Application\Web\Security`的实例：

```php
require __DIR__ . '/../Application/Autoload/Loader.php';
Application\Autoload\Loader::init(__DIR__ . '/..');
$security = new Application\Web\Security();
```

接下来，我们定义一个测试数据块：

```php
$data = [
    '<ul><li>Lots</li><li>of</li><li>Tags</li></ul>',
    12345,
    'This is a string',
    'String with number 12345',
];
```

最后，我们为每个测试数据项调用每个过滤器和验证器：

```php
foreach ($data as $item) {
  echo 'ORIGINAL: ' . $item . PHP_EOL;
  echo 'FILTERING' . PHP_EOL;
  printf('%12s : %s' . PHP_EOL,'Strip Tags', $security->filterStripTags($item));
  printf('%12s : %s' . PHP_EOL, 'Digits', $security->filterDigits($item));
  printf('%12s : %s' . PHP_EOL, 'Alpha', $security->filterAlpha($item));

  echo 'VALIDATORS' . PHP_EOL;
  printf('%12s : %s' . PHP_EOL, 'Alnum',  
  ($security->validateAlnum($item))  ? 'T' : 'F');
  printf('%12s : %s' . PHP_EOL, 'Digits', 
  ($security->validateDigits($item)) ? 'T' : 'F');
  printf('%12s : %s' . PHP_EOL, 'Alpha',  
  ($security->validateAlpha($item))  ? 'T' : 'F');
}
```

以下是一些输入字符串的输出：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_02_01.jpg)

## 另请参阅

有关 AST 的更多信息，请参阅涉及**抽象语法树**的 RFC，可以在[`wiki.php.net/rfc/abstract_syntax_tree`](https://wiki.php.net/rfc/abstract_syntax_tree)上查看。

# 了解解析的差异

在 PHP 5 中，赋值操作的右侧表达式是从*右到左*解析的。在 PHP 7 中，解析是一致的*从左到右*。

## 如何做...

1.  变量变量是间接引用值的一种方式。在下面的例子中，首先`$$foo`被解释为`${$bar}`。因此最终的返回值是`$bar`的值，而不是`$foo`的直接值（应该是`bar`）：

```php
$foo = 'bar';
$bar = 'baz';
echo $$foo; // returns  'baz'; 
```

1.  在下一个例子中，我们有一个变量变量`$$foo`，它引用一个具有`bar 键`和`baz 子键`的多维数组：

```php
$foo = 'bar';
$bar = ['bar' => ['baz' => 'bat']];
// returns 'bat'
echo $$foo['bar']['baz'];
```

1.  在 PHP 5 中，解析是从右到左进行的，这意味着 PHP 引擎将寻找一个`$foo 数组`，其中包含一个`bar 键`和一个`baz 子键`。然后，元素的返回值将被解释以获得最终值`${$foo['bar']['baz']}`。

1.  然而，在 PHP 7 中，解析是一致的，从左到右进行，这意味着首先解释`($$foo)['bar']['baz']`。

1.  在下一个示例中，您可以看到在 PHP 5 中`$foo->$bar['bada']`的解释与 PHP 7 相比有很大不同。在下面的例子中，PHP 5 首先会解释`$bar['bada']`，并将此返回值与`$foo 对象实例`进行引用。另一方面，在 PHP 7 中，解析是一致的，从左到右进行，这意味着首先解释`$foo->$bar`，并期望一个具有`bada 元素`的数组。顺便说一句，这个例子还使用了 PHP 7 的*匿名类*特性：

```php
// PHP 5: $foo->{$bar['bada']}
// PHP 7: ($foo->$bar)['bada']
$bar = 'baz';
// $foo = new class 
{ 
    public $baz = ['bada' => 'boom']; 
};
// returns 'boom'
echo $foo->$bar['bada'];
```

1.  最后一个示例与上面的示例相同，只是期望的返回值是一个回调，然后立即执行如下：

```php
// PHP 5: $foo->{$bar['bada']}()
// PHP 7: ($foo->$bar)['bada']()
$bar = 'baz';
// NOTE: this example uses the new PHP 7 anonymous class feature
$foo = new class 
{ 
     public function __construct() 
    { 
        $this->baz = ['bada' => function () { return 'boom'; }]; 
    } 
};
// returns 'boom'
echo $foo->$bar['bada']();
```

## 它是如何工作的...

将 1 和 2 中的代码示例放入一个单独的 PHP 文件中，您可以将其命名为`chap_02_understanding_diffs_in_parsing.php`。首先使用 PHP 5 执行该脚本，您将注意到会产生一系列错误，如下所示：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_02_05.jpg)

错误的原因是 PHP 5 解析不一致，并且对所请求的变量变量的状态得出了错误的结论（如前所述）。现在，您可以继续添加剩余的示例，如步骤 5 和 6 所示。然后，如果您在 PHP 7 中运行此脚本，将会出现所描述的结果，如下所示：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_02_06.jpg)

## 另请参阅

有关解析的更多信息，请参阅涉及**统一** **变量语法**的 RFC，可以在[`wiki.php.net/rfc/uniform_variable_syntax`](https://wiki.php.net/rfc/uniform_variable_syntax)上查看。

# 理解 foreach（）处理中的差异

在某些相对晦涩的情况下，`foreach（）`循环内部代码的行为在 PHP 5 和 PHP 7 之间会有所不同。首先，有了大量的内部改进，这意味着在`foreach（）`循环内部的处理在 PHP 7 下的速度会比在 PHP 5 下快得多。在 PHP 5 中注意到的问题包括在`foreach（）`循环内部使用`current（）`和`unset（）`对数组的操作。其他问题涉及通过引用传递值同时操作数组本身。

## 如何做...

1.  考虑以下代码块：

```php
$a = [1, 2, 3];
foreach ($a as $v) {
  printf("%2d\n", $v);
  unset($a[1]);
}
```

1.  在 PHP 5 和 7 中，输出如下：

```php
 1
 2
 3
```

1.  然而，在循环之前添加一个赋值，行为会改变：

```php
$a = [1, 2, 3];
$b = &$a;
foreach ($a as $v) {
  printf("%2d\n", $v);
  unset($a[1]);
}
```

1.  比较 PHP 5 和 7 的输出：

| PHP 5 | PHP 7 |
| --- | --- |
| **1****3** | **1****2****3** |

1.  处理引用内部数组指针的函数在 PHP 5 中也导致不一致的行为。看下面的代码示例：

```php
$a = [1,2,3];
foreach($a as &$v) {
    printf("%2d - %2d\n", $v, current($a));
}
```

### 提示

每个数组都有一个指向其“当前”元素的内部指针，从`1`开始，“current（）”返回数组中的当前元素。

1.  请注意，在 PHP 7 中运行的输出是规范化和一致的：

| PHP 5 | PHP 7 |
| --- | --- |
| **1 - 2****2 - 3****3 - 0** | **1 - 1****2 - 1****3 - 1** |

1.  在`foreach（）`循环中添加一个新元素，一旦引用数组迭代完成，也在 PHP 5 中存在问题。这种行为在 PHP 7 中已经变得一致。以下代码示例演示了这一点：

```php
$a = [1];
foreach($a as &$v) {
    printf("%2d -\n", $v);
    $a[1]=2;
}
```

1.  我们将观察到以下输出：

| PHP 5 | PHP 7 |
| --- | --- |
| **1 -** | **1 -****2-** |

1.  在 PHP 5 中解决的 PHP 7 中的另一个不良行为示例是通过引用遍历数组时，使用修改数组的函数，如`array_push（）`，`array_pop（）`，`array_shift（）`和`array_unshift（）`。

看看这个例子：

```php
$a=[1,2,3,4];
foreach($a as &$v) {
    echo "$v\n";
    array_pop($a);
}
```

1.  您将观察到以下输出：

| PHP 5 | PHP 7 |
| --- | --- |
| **1****2****1****1** | **1****2** |

1.  最后，我们有一个情况，您正在通过引用遍历数组，并且有一个嵌套的`foreach（）`循环，它本身也通过引用在相同的数组上进行迭代。在 PHP 5 中，这种结构根本不起作用。在 PHP 7 中，这个问题已经解决。以下代码块演示了这种行为：

```php
$a = [0, 1, 2, 3];
foreach ($a as &$x) {
       foreach ($a as &$y) {
         echo "$x - $y\n";
         if ($x == 0 && $y == 1) {
           unset($a[1]);
           unset($a[2]);
         }
       }
}
```

1.  以下是输出：

| PHP 5 | PHP 7 |
| --- | --- |
| **0 - 0****0 - 1****0 - 3** | **0 - 0****0 - 1****0 - 3****3 - 0****3 -3** |

## 它是如何工作的...

将这些代码示例添加到一个名为`chap_02_foreach.php`的单个 PHP 文件中。从命令行下在 PHP 5 下运行脚本。预期输出如下：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_02_07.jpg)

在 PHP 7 下运行相同的脚本并注意差异：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_02_08.jpg)

## 另请参阅

有关更多信息，请参阅解决此问题的 RFC，该 RFC 已被接受。可以在以下网址找到有关此 RFC 的介绍：[`wiki.php.net/rfc/php7_foreach`](https://wiki.php.net/rfc/php7_foreach)。

# 使用 PHP 7 增强性能

开发人员正在利用的一个趋势是使用**匿名函数**。处理匿名函数时的一个经典问题是以这样的方式编写它们，以便任何对象都可以绑定到`$this`，并且函数仍然可以工作。PHP 5 代码中使用的方法是使用`bindTo（）`。在 PHP 7 中，添加了一个新方法`call（）`，它提供了类似的功能，但性能大大提高。

## 如何做...

为了利用`call（）`，在一个漫长的循环中执行一个匿名函数。在这个例子中，我们将演示一个匿名函数，它通过扫描日志文件，识别按出现频率排序的 IP 地址：

1.  首先，我们定义一个`Application\Web\Access`类。在构造函数中，我们接受一个文件名作为参数。日志文件被打开为`SplFileObject`并分配给`$this->log`：

```php
Namespace Application\Web;

use Exception;
use SplFileObject;
class Access
{
  const ERROR_UNABLE = 'ERROR: unable to open file';
  protected $log;
  public $frequency = array();
  public function __construct($filename)
  {
    if (!file_exists($filename)) {
      $message = __METHOD__ . ' : ' . self::ERROR_UNABLE . PHP_EOL;
      $message .= strip_tags($filename) . PHP_EOL;
      throw new Exception($message);
    }
    $this->log = new SplFileObject($filename, 'r');
  }
```

1.  接下来，我们定义一个遍历文件的生成器，逐行进行迭代：

```php
public function fileIteratorByLine()
{
  $count = 0;
  while (!$this->log->eof()) {
    yield $this->log->fgets();
    $count++;
  }
  return $count;
}
```

1.  最后，我们定义一个方法，查找并提取 IP 地址作为子匹配：

```php
public function getIp($line)
{
  preg_match('/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/', $line, $match);
  return $match[1] ?? '';
  }
}
```

## 它是如何工作的...

首先，我们定义一个调用程序`chap_02_performance_using_php7_enchancement_call.php`，利用第一章中定义的自动加载类，*建立基础*，来获取`Application\Web\Access`的实例：

```php
define('LOG_FILES', '/var/log/apache2/*access*.log');
require __DIR__ . '/../Application/Autoload/Loader.php';
Application\Autoload\Loader::init(__DIR__ . '/..');
```

接下来我们定义匿名函数，它处理日志文件中的一行。如果检测到 IP 地址，它将成为`$frequency 数组`中的一个键，并且增加这个键的当前值。

```php
// define functions
$freq = function ($line) {
  $ip = $this->getIp($line);
  if ($ip) {
    echo '.';
    $this->frequency[$ip] = 
    (isset($this->frequency[$ip])) ? $this->frequency[$ip] + 1 : 1;
  }
};
```

然后我们循环遍历每个找到的日志文件中的行迭代，处理 IP 地址：

```php
foreach (glob(LOG_FILES) as $filename) {
  echo PHP_EOL . $filename . PHP_EOL;
  // access class
  $access = new Application\Web\Access($filename);
  foreach ($access->fileIteratorByLine() as $line) {
    $freq->call($access, $line);
  }
}
```

### 提示

实际上你也可以在 PHP 5 中做同样的事情。但是需要两行代码：

```php
$func = $freq->bindTo($access);
$func($line);
```

在 PHP 7 中，使用`call()`的性能比较使用`call()`慢 20%到 50%。

最后，我们对数组进行逆向排序，但保持键。输出是在一个简单的`foreach()`循环中产生的：

```php
arsort($access->frequency);
foreach ($access->frequency as $key => $value) {
  printf('%16s : %6d' . PHP_EOL, $key, $value);
}
```

输出将根据你处理的`access.log`文件而有所不同。这里是一个示例：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_02_02.jpg)

## 还有更多...

许多 PHP 7 性能改进与新功能和函数无关。相反，它们采取了内部改进的形式，直到你开始运行程序之前都是*不可见*的。以下是属于这一类别的改进的简短列表：

| 功能 | 更多信息： | 注释 |
| --- | --- | --- |
| 快速参数解析 | [`wiki.php.net/rfc/fast_zpp`](https://wiki.php.net/rfc/fast_zpp) | 在 PHP 5 中，提供给函数的参数必须为每个函数调用进行解析。参数以字符串形式传递，并以类似于`scanf()`函数的方式进行解析。在 PHP 7 中，这个过程已经被优化，变得更加高效，导致了显著的性能提升。这种改进很难衡量，但似乎在 6%左右。 |
| PHP NG | [`wiki.php.net/rfc/phpng`](https://wiki.php.net/rfc/phpng) | PHP **NG**（**Next Generation**）计划代表了对大部分 PHP 语言的重写。它保留了现有功能，但涉及了所有可能的时间节省和效率措施。数据结构已经被压缩，内存利用更加高效。例如，只有一个改变影响了数组处理，导致了显著的性能提升，同时大大减少了内存使用。 |
| 去除死板 | [`wiki.php.net/rfc/removal_of_dead_sapis_and_exts`](https://wiki.php.net/rfc/removal_of_dead_sapis_and_exts) | 大约有二十多个扩展属于以下类别之一：已弃用、不再维护、未维护的依赖项，或者未移植到 PHP 7。核心开发人员组的投票决定移除“短列表”上约 2/3 的扩展。这将减少开销，并加快 PHP 语言的未来整体发展速度。 |

# 迭代处理大文件

诸如`file_get_contents()`和`file()`之类的函数使用起来快速简单，但由于内存限制，它们在处理大文件时很快会出现问题。`php.ini`中`memory_limit`设置的默认值为 128 兆字节。因此，任何大于这个值的文件都不会被加载。

在解析大文件时的另一个考虑是，你的函数或类方法产生输出的速度有多快？例如，在产生用户输出时，尽管一开始累积输出到一个数组中似乎更好。然后一次性输出以提高效率。不幸的是，这可能会对用户体验产生不利影响。也许更好的方法是创建一个**生成器**，并使用`yield 关键字`产生即时结果。

## 如何做...

如前所述，`file*`函数（即`file_get_contents()`）不适用于大文件。简单的原因是这些函数在某一点上会将整个文件内容表示在内存中。因此，本示例的重点将放在`f*`函数（即`fopen()`）上。

然而，有点不同的是，我们不直接使用`f*`函数，而是使用**SPL**（**标准 PHP 库**）中包含的`SplFileObject`类：

1.  首先，我们定义了一个`Application\Iterator\LargeFile`类，具有适当的属性和常量：

```php
namespace Application\Iterator;

use Exception;
use InvalidArgumentException;
use SplFileObject;
use NoRewindIterator;

class LargeFile
{
  const ERROR_UNABLE = 'ERROR: Unable to open file';
  const ERROR_TYPE   = 'ERROR: Type must be "ByLength", "ByLine" or "Csv"';     
  protected $file;
  protected $allowedTypes = ['ByLine', 'ByLength', 'Csv'];
```

1.  然后我们定义了一个`__construct()`方法，接受文件名作为参数，并用`SplFileObject`实例填充`$file`属性。如果文件不存在，这也是抛出异常的好地方：

```php
public function __construct($filename, $mode = 'r')
{
  if (!file_exists($filename)) {
    $message = __METHOD__ . ' : ' . self::ERROR_UNABLE . PHP_EOL;
    $message .= strip_tags($filename) . PHP_EOL;
    throw new Exception($message);
  }
  $this->file = new SplFileObject($filename, $mode);
}
```

1.  接下来我们定义了一个`fileIteratorByLine()method`方法，该方法使用`fgets()`逐行读取文件。创建一个类似的`fileIteratorByLength()`方法，但使用`fread()`来实现也是个不错的主意。使用`fgets()`的方法适用于包含换行符的文本文件。另一个方法可以用于解析大型二进制文件：

```php
protected function fileIteratorByLine()
{
  $count = 0;
  while (!$this->file->eof()) {
    yield $this->file->fgets();
    $count++;
  }
  return $count;
}

protected function fileIteratorByLength($numBytes = 1024)
{
  $count = 0;
  while (!$this->file->eof()) {
    yield $this->file->fread($numBytes);
    $count++;
  }
  return $count; 
}
```

1.  最后，我们定义了一个`getIterator()`方法，返回一个`NoRewindIterator()`实例。该方法接受`ByLine`或`ByLength`作为参数，这两个参数是指前一步骤中定义的两种方法。该方法还需要接受`$numBytes`，以防调用`ByLength`。我们需要一个`NoRewindIterator()`实例的原因是强制在这个例子中只能单向读取文件：

```php
public function getIterator($type = 'ByLine', $numBytes = NULL)
{
  if(!in_array($type, $this->allowedTypes)) {
    $message = __METHOD__ . ' : ' . self::ERROR_TYPE . PHP_EOL;
    throw new InvalidArgumentException($message);
  }
  $iterator = 'fileIterator' . $type;
  return new NoRewindIterator($this->$iterator($numBytes));
}
```

## 它是如何工作的...

首先，我们利用第一章中定义的自动加载类，在调用程序`chap_02_iterating_through_a_massive_file.php`中获取`Application\Iterator\LargeFile`的实例：

```php
define('MASSIVE_FILE', '/../data/files/war_and_peace.txt');
require __DIR__ . '/../Application/Autoload/Loader.php';
Application\Autoload\Loader::init(__DIR__ . '/..');
```

接下来，在`try {...} catch () {...}`块中，我们获取一个`ByLine`迭代器的实例：

```php
try {
  $largeFile = new Application\Iterator\LargeFile(__DIR__ . MASSIVE_FILE);
  $iterator = $largeFile->getIterator('ByLine');
```

然后我们提供了一个有用的示例，即定义每行的平均单词数：

```php
$words = 0;
foreach ($iterator as $line) {
  echo $line;
  $words += str_word_count($line);
}
echo str_repeat('-', 52) . PHP_EOL;
printf("%-40s : %8d\n", 'Total Words', $words);
printf("%-40s : %8d\n", 'Average Words Per Line', 
($words / $iterator->getReturn()));
echo str_repeat('-', 52) . PHP_EOL;
```

然后我们结束`catch`块：

```php
} catch (Throwable $e) {
  echo $e->getMessage();
}
```

预期输出（太大无法在此显示！）显示了《战争与和平》古腾堡版本中有 566,095 个单词。此外，我们发现每行的平均单词数为八个。

# 将电子表格上传到数据库

虽然 PHP 没有直接读取特定电子表格格式（如 XLSX、ODS 等）的能力，但它可以读取**（CSV 逗号分隔值**）文件。因此，为了处理客户的电子表格，您需要要求他们以 CSV 格式提供文件，或者您需要自行进行转换。

## 准备就绪...

将电子表格（即 CSV 文件）上传到数据库时，有三个主要考虑因素：

+   遍历（可能）庞大的文件

+   将每个电子表格行提取为 PHP 数组

+   将 PHP 数组插入数据库

庞大文件的迭代将使用前面的方法处理。我们将使用`fgetcsv()`函数将 CSV 行转换为 PHP 数组。最后，我们将使用**（PDO PHP 数据对象**）类建立数据库连接并执行插入操作。

## 如何做...

1.  首先，我们定义了一个`Application\Database\Connection`类，该类根据构造函数提供的一组参数创建一个 PDO 实例：

```php
<?php
  namespace Application\Database;

  use Exception;
  use PDO;

  class Connection
  { 
    const ERROR_UNABLE = 'ERROR: Unable to create database connection';    
    public $pdo;

    public function __construct(array $config)
    {
      if (!isset($config['driver'])) {
        $message = __METHOD__ . ' : ' . self::ERROR_UNABLE . PHP_EOL;
        throw new Exception($message);
    }
    $dsn = $config['driver'] 
    . ':host=' . $config['host'] 
    . ';dbname=' . $config['dbname'];
    try {
      $this->pdo = new PDO($dsn, 
      $config['user'], 
      $config['password'], 
      [PDO::ATTR_ERRMODE => $config['errmode']]);
    } catch (PDOException $e) {
      error_log($e->getMessage());
    }
  }

}
```

1.  然后我们加入了一个`Application\Iterator\LargeFile`的实例。我们为这个类添加了一个新的方法，用于遍历 CSV 文件：

```php
protected function fileIteratorCsv()
{
  $count = 0;
  while (!$this->file->eof()) {
    yield $this->file->fgetcsv();
    $count++;
  }
  return $count;        
}    
```

1.  我们还需要将`Csv`添加到允许的迭代器方法列表中：

```php
  const ERROR_UNABLE = 'ERROR: Unable to open file';
  const ERROR_TYPE   = 'ERROR: Type must be "ByLength", "ByLine" or "Csv"';

  protected $file;
  protected $allowedTypes = ['ByLine', 'ByLength', 'Csv'];
```

## 它是如何工作的...

首先我们定义一个配置文件，`/path/to/source/config/db.config.php`，其中包含数据库连接参数：

```php
<?php
return [
  'driver'   => 'mysql',
  'host'     => 'localhost',
  'dbname'   => 'php7cookbook',
  'user'     => 'cook',
  'password' => 'book',
  'errmode'  => PDO::ERRMODE_EXCEPTION,
];
```

接下来，我们利用第一章中定义的自动加载类，*建立基础*，来获得`Application\Database\Connection`和`Application\Iterator\LargeFile`的实例，定义一个调用程序`chap_02_uploading_csv_to_database.php`：

```php
define('DB_CONFIG_FILE', '/../data/config/db.config.php');
define('CSV_FILE', '/../data/files/prospects.csv');
require __DIR__ . '/../../Application/Autoload/Loader.php';
Application\Autoload\Loader::init(__DIR__ . '/..');
```

之后，我们设置了一个`try {...} catch () {...}`块，其中捕获了`Throwable`。这使我们能够同时捕获异常和错误：

```php
try {
  // code goes here  
} catch (Throwable $e) {
  echo $e->getMessage();
}
```

在`try {...} catch () {...}`块中，我们获得连接和大文件迭代器类的实例：

```php
$connection = new Application\Database\Connection(
include __DIR__ . DB_CONFIG_FILE);
$iterator  = (new Application\Iterator\LargeFile(__DIR__ . CSV_FILE))
->getIterator('Csv');
```

然后我们利用 PDO 准备/执行功能。准备好的语句的 SQL 使用`?`来表示在循环中提供的值：

```php
$sql = 'INSERT INTO `prospects` '
  . '(`id`,`first_name`,`last_name`,`address`,`city`,`state_province`,'
  . '`postal_code`,`phone`,`country`,`email`,`status`,`budget`,`last_updated`) '
  . ' VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)';
$statement = $connection->pdo->prepare($sql);
```

然后我们使用`foreach()`来循环遍历文件迭代器。每个`yield`语句产生一个值数组，表示数据库中的一行。然后我们可以使用这些值与`PDOStatement::execute()`一起使用，将这些值的行插入到数据库中执行准备好的语句：

```php
foreach ($iterator as $row) {
  echo implode(',', $row) . PHP_EOL;
  $statement->execute($row);
}
```

然后您可以检查数据库，以验证数据是否已成功插入。

# 递归目录迭代器

获取目录中文件的列表非常容易。传统上，开发人员使用`glob()`函数来实现这个目的。要从目录树中的特定点递归获取所有文件和目录的列表则更加棘手。这个方法利用了一个**（SPL 标准 PHP 库）**类`RecursiveDirectoryIterator`，它将非常好地实现这个目的。

这个类的作用是解析目录树，找到第一个子目录，然后沿着分支继续，直到没有更多的子目录，然后停止！不幸的是，这不是我们想要的。我们需要以某种方式让`RecursiveDirectoryIterator`继续解析每棵树和分支，从给定的起点开始，直到没有更多的文件或目录。碰巧有一个奇妙的类`RecursiveIteratorIterator`，它正好可以做到这一点。通过将`RecursiveDirectoryIterator`包装在`RecursiveIteratorIterator`中，我们可以完成对任何目录树的完整遍历。

### 提示

**警告！**

非常小心地选择文件系统遍历的起点。如果您从根目录开始，您可能会导致服务器崩溃，因为递归过程将一直持续，直到找到所有文件和目录！

## 如何做...

1.  首先，我们定义了一个`Application\Iterator\Directory`类，该类定义了适当的属性和常量，并使用外部类：

```php
namespace Application\Iterator;

use Exception;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use RecursiveRegexIterator;
use RegexIterator;

class Directory
{

  const ERROR_UNABLE = 'ERROR: Unable to read directory';

  protected $path;
  protected $rdi;
  // recursive directory iterator
```

1.  构造函数基于目录路径创建了一个`RecursiveDirectoryIterator`实例，该实例位于`RecursiveIteratorIterator`内部：

```php
public function __construct($path)
{
  try {
    $this->rdi = new RecursiveIteratorIterator(
      new RecursiveDirectoryIterator($path),
      RecursiveIteratorIterator::SELF_FIRST);
  } catch (\Throwable $e) {
    $message = __METHOD__ . ' : ' . self::ERROR_UNABLE . PHP_EOL;
    $message .= strip_tags($path) . PHP_EOL;
    echo $message;
    exit;
  }
}
```

1.  接下来，我们决定如何处理迭代。一种可能性是模仿 Linux 的`ls -l -R`命令的输出。请注意，我们使用了`yield`关键字，有效地将此方法转换为**生成器**，然后可以从外部调用。目录迭代产生的每个对象都是一个 SPL `FileInfo`对象，它可以为我们提供有关文件的有用信息。这个方法可能是这样的：

```php
public function ls($pattern = NULL)
{
  $outerIterator = ($pattern) 
  ? $this->regex($this->rdi, $pattern) 
  : $this->rdi;
  foreach($outerIterator as $obj){
    if ($obj->isDir()) {
      if ($obj->getFileName() == '..') {
        continue;
      }
      $line = $obj->getPath() . PHP_EOL;
    } else {
      $line = sprintf('%4s %1d %4s %4s %10d %12s %-40s' . PHP_EOL,
      substr(sprintf('%o', $obj->getPerms()), -4),
      ($obj->getType() == 'file') ? 1 : 2,
      $obj->getOwner(),
      $obj->getGroup(),
      $obj->getSize(),
      date('M d Y H:i', $obj->getATime()),
      $obj->getFileName());
    }
    yield $line;
  }
}
```

1.  您可能已经注意到，方法调用包括文件模式。我们需要一种方法来过滤递归，只包括匹配的文件。SPL 中还有另一个迭代器完全适合这个需求：`RegexIterator`类：

```php
protected function regex($iterator, $pattern)
{
  $pattern = '!^.' . str_replace('.', '\\.', $pattern) . '$!';
  return new RegexIterator($iterator, $pattern);
}
```

1.  最后，这是另一种方法，但这次我们将模仿`dir /s`命令：

```php
public function dir($pattern = NULL)
{
  $outerIterator = ($pattern) 
  ? $this->regex($this->rdi, $pattern) 
  : $this->rdi;
  foreach($outerIterator as $name => $obj){
      yield $name . PHP_EOL;
    }        
  }
}
```

## 工作原理...

首先，我们利用第一章中定义的自动加载类，*建立基础*，来获得`Application\Iterator\Directory`的实例，定义一个调用程序`chap_02_recursive_directory_iterator.php`：

```php
define('EXAMPLE_PATH', realpath(__DIR__ . '/../'));
require __DIR__ . '/../Application/Autoload/Loader.php';
Application\Autoload\Loader::init(__DIR__ . '/..');
$directory = new Application\Iterator\Directory(EXAMPLE_PATH);
```

然后，在`try {...} catch () {...}`块中，我们调用了我们的两个方法，使用一个示例目录路径：

```php
try {
  echo 'Mimics "ls -l -R" ' . PHP_EOL;
  foreach ($directory->ls('*.php') as $info) {
    echo $info;
  }

  echo 'Mimics "dir /s" ' . PHP_EOL;
  foreach ($directory->dir('*.php') as $info) {
    echo $info;
  }

} catch (Throwable $e) {
  echo $e->getMessage();
}
```

`ls()`的输出将如下所示：

![工作原理...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_02_03.jpg)

`dir()`的输出将如下所示：

![工作原理...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_02_04.jpg)


# 第三章：使用 PHP 函数式编程

在本章中，我们将涵盖以下主题：

+   开发函数

+   数据类型提示

+   使用返回值数据类型

+   使用迭代器

+   使用生成器编写自己的迭代器

# 介绍

在本章中，我们将考虑利用 PHP 的**函数式编程**能力的方法。函数式或**过程式**编程是在 PHP 版本 4 引入**面向对象编程**（**OOP**）之前编写 PHP 代码的传统方式。函数式编程是将程序逻辑封装到一系列离散的**函数**中，这些函数通常存储在单独的 PHP 文件中。然后可以在任何未来的脚本中包含此文件，从而允许随意调用定义的函数。

# 开发函数

最困难的部分是决定如何将编程逻辑分解为函数。另一方面，在 PHP 中开发函数的机制非常简单。只需使用`function`关键字，给它一个名称，然后跟着括号。

## 如何做...

1.  代码本身放在大括号中，如下所示：

```php
function someName ($parameter)
{ 
  $result = 'INIT';
  // one or more statements which do something
  // to affect $result
  $result .= ' and also ' . $parameter;
  return $result; 
}
```

1.  您可以定义一个或多个**参数**。要使其中一个参数变为可选，只需分配一个默认值。如果不确定要分配什么默认值，请使用`NULL`：

```php
function someOtherName ($requiredParam, $optionalParam = NULL)
  { 
    $result = 0;
    $result += $requiredParam;
    $result += $optionalParam ?? 0;
    return $result; 
  }
```

### 注意

您不能重新定义函数。唯一的例外是在不同的命名空间中定义重复的函数。这个定义会生成一个错误：

```php
function someTest()
{
  return 'TEST';
}
function someTest($a)
{
  return 'TEST:' . $a;
}
```

1.  如果不知道将向函数提供多少参数，或者想要允许无限数量的参数，请使用`...`后跟一个变量名。提供的所有参数将出现在变量中的数组中：

```php
function someInfinite(...$params)
{
  // any params passed go into an array $params
  return var_export($params, TRUE);
}
```

1.  函数可以调用自身。这被称为**递归**。以下函数执行递归目录扫描：

```php
function someDirScan($dir)
{
  // uses "static" to retain value of $list
  static $list = array();
  // get a list of files and directories for this path
  $list = glob($dir . DIRECTORY_SEPARATOR . '*');
  // loop through
  foreach ($list as $item) {
    if (is_dir($item)) {
      $list = array_merge($list, someDirScan($item));
    }
  }
  return $list;
}
```

### 注意

在函数内使用`static`关键字已经有 12 年以上的历史了。`static`的作用是在函数调用之间保留变量的值。

如果需要在 HTTP 请求之间保留变量的值，请确保已启动 PHP 会话并将值存储在`$_SESSION`中。

1.  在 PHP **命名空间**中定义函数时受到限制。这个特性可以用来为函数库之间提供额外的逻辑分离。为了*锚定*命名空间，您需要添加`use`关键字。以下示例放置在单独的命名空间中。请注意，即使函数名称相同，它们也不会发生冲突，因为它们彼此之间不可见。

1.  我们在命名空间`Alpha`中定义了`someFunction()`。我们将其保存到一个单独的 PHP 文件`chap_03_developing_functions_namespace_alpha.php`中：

```php
<?php
namespace Alpha;

function someFunction()
{
  echo __NAMESPACE__ . ':' . __FUNCTION__ . PHP_EOL;
}
```

1.  然后我们在命名空间`Beta`中定义了`someFunction()`。我们将其保存到一个单独的 PHP 文件`chap_03_developing_functions_namespace_beta.php`中：

```php
<?php
namespace Beta;

function someFunction()
{
  echo __NAMESPACE__ . ':' . __FUNCTION__ . PHP_EOL;
}
```

1.  然后我们可以通过在函数名前加上命名空间名称来调用`someFunction()`：

```php
include (__DIR__ . DIRECTORY_SEPARATOR 
         . 'chap_03_developing_functions_namespace_alpha.php');
include (__DIR__ . DIRECTORY_SEPARATOR 
         . 'chap_03_developing_functions_namespace_beta.php');
      echo Alpha\someFunction();
      echo Beta\someFunction();
```

### 提示

**最佳实践**

最佳实践是将函数库（以及类！）放入单独的文件中：一个命名空间一个文件，一个类或函数库一个文件。

可以在单个命名空间中定义许多类或函数库。将开发到单独的命名空间的唯一原因是如果要促进功能的逻辑分离。

## 它是如何工作的...

最佳实践是将所有逻辑相关的函数放入一个单独的 PHP 文件中。创建一个名为`chap_03_developing_functions_library.php`的文件，并将这些函数（前面描述的）放入其中。

+   `someName()`

+   `someOtherName()`

+   `someInfinite()`

+   `someDirScan()`

+   `someTypeHint()`

然后将此文件包含在使用这些函数的代码中。

```php
include (__DIR__ . DIRECTORY_SEPARATOR . 'chap_03_developing_functions_library.php');
```

要调用`someName()`函数，请使用名称并提供参数。

```php
echo someName('TEST');   // returns "INIT and also TEST"
```

你可以像这样调用`someOtherName()`函数使用一个或两个参数：

```php
echo someOtherName(1);    // returns  1
echo someOtherName(1, 1);   //  returns 2
```

`someInfinite()`函数接受无限（或可变）数量的参数。以下是调用这个函数的一些例子：

```php
echo someInfinite(1, 2, 3);
echo PHP_EOL;
echo someInfinite(22.22, 'A', ['a' => 1, 'b' => 2]);
```

输出如下：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_03_01.jpg)

我们可以这样调用`someDirScan()`：

```php
echo someInfinite(1, 2, 3);
echo PHP_EOL;
echo someInfinite(22.22, 'A', ['a' => 1, 'b' => 2]);
```

输出如下：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_03_02.jpg)

# 数据类型提示

在开发函数时，许多情况下你可能会在其他项目中重用相同的函数库。此外，如果你与团队合作，你的代码可能会被其他开发人员使用。为了控制你的代码的使用，使用**类型提示**可能是合适的。这涉及到指定函数对于特定参数期望的数据类型。

## 如何做...

1.  函数中的参数可以加上类型提示。以下类型提示在 PHP 5 和 PHP 7 中都可用：

+   数组

+   类

+   可调用的

1.  如果调用函数，并传递了错误的参数类型，将抛出`TypeError`。以下示例需要一个数组、一个`DateTime`的实例和一个匿名函数：

```php
function someTypeHint(Array $a, DateTime $t, Callable $c)
{
  $message = '';
  $message .= 'Array Count: ' . count($a) . PHP_EOL;
  $message .= 'Date: ' . $t->format('Y-m-d') . PHP_EOL;
  $message .= 'Callable Return: ' . $c() . PHP_EOL;
  return $message;
}
```

### 提示

你不必为每个参数提供类型提示。只有在提供不同的数据类型会对函数处理产生负面影响时才使用这种技术。例如，如果你的函数使用`foreach()`循环，如果你没有提供一个数组，或者实现了`Traversable`的东西，就会产生一个错误。

1.  在 PHP 7 中，假设适当的`declare()`指令已经被声明，**标量**（即整数、浮点数、布尔值和字符串）类型提示是允许的。另一个函数演示了如何实现这一点。在包含你希望使用标量类型提示的函数的代码库文件的顶部，在开头的 PHP 标记之后添加这个`declare()`指令：

```php
declare(strict_types=1);
```

1.  现在你可以定义一个包含标量类型提示的函数：

```php
function someScalarHint(bool $b, int $i, float $f, string $s)
{
  return sprintf("\n%20s : %5s\n%20s : %5d\n%20s " . 
                 ": %5.2f\n%20s : %20s\n\n",
                 'Boolean', ($b ? 'TRUE' : 'FALSE'),
                 'Integer', $i,
                 'Float',   $f,
                 'String',  $s);
}
```

1.  在 PHP 7 中，假设已经声明了严格的类型提示，布尔类型提示与其他三种标量类型（即整数、浮点数和字符串）有些不同。你可以提供任何标量作为参数，不会抛出`TypeError`！然而，一旦传递到函数中，传入的值将自动转换为布尔数据类型。如果传递的数据类型不是标量（即数组或对象），将抛出`TypeError`。这是一个定义`boolean`数据类型的函数的例子。请注意，返回值将自动转换为`boolean`：

```php
function someBoolHint(bool $b)
{
  return $b;
}
```

## 它是如何工作的...

首先，你可以将`someTypeHint()`、`someScalarHint()`和`someBoolHint()`这三个函数放在一个单独的文件中以供包含。在这个例子中，我们将文件命名为`chap_03_developing_functions_type_hints_library.php`。不要忘记在顶部添加`declare(strict_types=1)`！

在我们的调用代码中，你需要包含这个文件：

```php
include (__DIR__ . DIRECTORY_SEPARATOR . 'chap_03_developing_functions_type_hints_library.php');
```

要测试`someTypeHint()`，调用函数两次，一次使用正确的数据类型，第二次使用不正确的类型。这将抛出一个`TypeError`，因此你需要将函数调用包装在`try { ... } catch () { ...}`块中：

```php
try {
    $callable = function () { return 'Callback Return'; };
    echo someTypeHint([1,2,3], new DateTime(), $callable);
    echo someTypeHint('A', 'B', 'C');
} catch (TypeError $e) {
    echo $e->getMessage();
    echo PHP_EOL;
}
```

从这个子部分末尾显示的输出中可以看出，当传递正确的数据类型时没有问题。当传递不正确的类型时，将抛出`TypeError`。

### 注意

在 PHP 7 中，某些错误已经转换为`Error`类，这与`Exception`的处理方式有些相似。这意味着你可以捕获`Error`。`TypeError`是`Error`的一个特定子类，当向函数传递不正确的数据类型时抛出。

所有 PHP 7 的`Error`类都实现了`Throwable`接口，`Exception`类也是如此。如果你不确定是否需要捕获`Error`还是`Exception`，你可以添加一个捕获`Throwable`的块。

接下来，您可以测试`someScalarHint()`，用正确和不正确的值调用它，将调用包装在`try { ... } catch () { ...}`块中：

```php
try {
    echo someScalarHint(TRUE, 11, 22.22, 'This is a string');
    echo someScalarHint('A', 'B', 'C', 'D');
} catch (TypeError $e) {
    echo $e->getMessage();
}
```

如预期的那样，对该函数的第一次调用有效，而第二次调用会抛出`TypeError`。

当对布尔值进行类型提示时，传递的任何标量值都*不会*导致抛出`TypeError`！相反，该值将被解释为其布尔等价值。如果随后返回此值，则数据类型将更改为布尔值。

要测试这一点，调用之前定义的`someBoolHint()`函数，并将任何标量值作为参数传入。`var_dump()`方法显示数据类型始终是布尔值：

```php
try {
    // positive results
    $b = someBooleanHint(TRUE);
    $i = someBooleanHint(11);
    $f = someBooleanHint(22.22);
    $s = someBooleanHint('X');
    var_dump($b, $i, $f, $s);
    // negative results
    $b = someBooleanHint(FALSE);
    $i = someBooleanHint(0);
    $f = someBooleanHint(0.0);
    $s = someBooleanHint('');
    var_dump($b, $i, $f, $s);
} catch (TypeError $e) {
    echo $e->getMessage();
}
```

如果您现在尝试相同的函数调用，但传入非标量数据类型，则会抛出`TypeError`：

```php
try {
    $a = someBoolHint([1,2,3]);
    var_dump($a);
} catch (TypeError $e) {
    echo $e->getMessage();
}
try {
    $o = someBoolHint(new stdClass());
    var_dump($o);
} catch (TypeError $e) {
    echo $e->getMessage();
}
```

这是整体输出：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_03_03.jpg)

## 另请参阅

PHP 7.1 引入了一个新的类型提示`iterable`，它允许数组、`Iterators`或`Generators`作为参数。有关更多信息，请参阅：

+   [`wiki.php.net/rfc/iterable`](https://wiki.php.net/rfc/iterable)

有关标量类型提示实现背后的原理的背景讨论，请参阅本文：

+   [`wiki.php.net/rfc/scalar_type_hints_v5`](https://wiki.php.net/rfc/scalar_type_hints_v5)

# 使用返回值数据类型

PHP 7 允许您为函数的返回值指定数据类型。然而，与标量类型提示不同，您不需要添加任何特殊声明。

## 如何做...

1.  这个例子向您展示了如何为函数返回值分配数据类型。要分配返回数据类型，首先像通常一样定义函数。在右括号后面，加一个空格，然后是数据类型和一个冒号：

```php
function returnsString(DateTime $date, $format) : string
{
  return $date->format($format);
}
```

### 注意

PHP 7.1 引入了一种称为**可空类型**的返回数据类型的变体。您需要做的就是将`string`更改为`?string`。这允许函数返回`string`或`NULL`。

1.  函数返回的任何东西，无论在函数内部的数据类型如何，都将被转换为声明的数据类型作为返回值。请注意，在这个例子中，将`$a`、`$b`和`$c`的值相加以产生一个单一的总和，然后返回。通常您会期望返回值是一个数字数据类型。然而，在这种情况下，返回数据类型被声明为`string`，这将覆盖 PHP 的类型转换过程：

```php
function convertsToString($a, $b, $c) : string

  return $a + $b + $c;
}
```

1.  您还可以将类分配为返回数据类型。在这个例子中，我们将返回类型分配为 PHP `DateTime`扩展的一部分的`DateTime`：

```php
function makesDateTime($year, $month, $day) : DateTime
{
  $date = new DateTime();
  $date->setDate($year, $month, $day);
  return $date;
}
```

### 注意

`makesDateTime()`函数将是标量类型提示的一个潜在候选。如果`$year`、`$month`或`$day`不是整数，在调用`setDate()`时会生成一个`Warning`。如果您使用标量类型提示，并且传递了错误的数据类型，将抛出`TypeError`。虽然生成警告或抛出`TypeError`并不重要，但至少`TypeError`会导致错误使用您的代码的开发人员警觉起来！

1.  如果一个函数有一个返回数据类型，并且您在函数代码中返回了错误的数据类型，那么在运行时会抛出`TypeError`。这个函数分配了一个`DateTime`的返回类型，但返回了一个字符串。会抛出`TypeError`，但直到运行时，当 PHP 引擎检测到不一致时才会抛出：

```php
function wrongDateTime($year, $month, $day) : DateTime
{
  return date($year . '-' . $month . '-' . $day);
}
```

### 注意

如果返回数据类型类不是内置的 PHP 类之一（即 SPL 的一部分），则需要确保已自动加载或包含该类。

## 它是如何工作的...

首先，将前面提到的函数放入名为`chap_03_developing_functions_return_types_library.php`的库文件中。这个文件需要包含在调用这些函数的`chap_03_developing_functions_return_types.php`脚本中：

```php
include (__DIR__ . '/chap_03_developing_functions_return_types_library.php');
```

现在，您可以调用`returnsString()`，提供一个`DateTime`实例和一个格式字符串：

```php
$date   = new DateTime();
$format = 'l, d M Y';
$now    = returnsString($date, $format);
echo $now . PHP_EOL;
var_dump($now);
```

如预期的那样，输出是一个字符串：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_03_07.jpg)

现在您可以调用`convertsToString()`并提供三个整数作为参数。注意返回类型是字符串：

```php
echo "\nconvertsToString()\n";
var_dump(convertsToString(2, 3, 4));
```

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_03_08.jpg)

为了证明这一点，您可以将一个类分配为返回值，使用三个整数参数调用`makesDateTime()`：

```php
echo "\nmakesDateTime()\n";
$d = makesDateTime(2015, 11, 21);
var_dump($d);
```

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_03_09.jpg)

最后，使用三个整数参数调用`wrongDateTime()`：

```php
try {
    $e = wrongDateTime(2015, 11, 21);
    var_dump($e);
} catch (TypeError $e) {
    echo $e->getMessage();
}
```

注意，在运行时抛出了`TypeError`：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_03_10.jpg)

## 还有更多...

PHP 7.1 添加了一个新的返回值类型，`void`。当您不希望从函数中返回任何值时使用。有关更多信息，请参阅[`wiki.php.net/rfc/void_return_type`](https://wiki.php.net/rfc/void_return_type)。

## 另请参阅

有关返回类型声明的更多信息，请参阅以下文章：

+   [`php.net/manual/en/functions.arguments.php#functions.arguments.type-declaration.strict`](http://php.net/manual/en/functions.arguments.php#functions.arguments.type-declaration.strict)

+   [`wiki.php.net/rfc/return_types`](https://wiki.php.net/rfc/return_types)

有关可空类型的信息，请参阅本文：

+   [`wiki.php.net/rfc/nullable_types`](https://wiki.php.net/rfc/nullable_types)

# 使用迭代器

**迭代器**是一种特殊类型的类，允许您**遍历**一个*容器*或列表。关键词在于*遍历*。这意味着迭代器提供了浏览列表的方法，但它本身不执行遍历。

SPL 提供了丰富的通用和专门设计用于不同上下文的迭代器。例如，`ArrayIterator`被设计用于允许面向对象遍历数组。`DirectoryIterator`被设计用于文件系统扫描。

某些 SPL 迭代器被设计用于与其他迭代器一起工作，并增加价值。示例包括`FilterIterator`和`LimitIterator`。前者使您能够从父迭代器中删除不需要的值。后者提供了分页功能，您可以指定要遍历多少项以及确定从何处开始的偏移量。

最后，还有一系列*递归*迭代器，允许您重复调用父迭代器。一个例子是`RecursiveDirectoryIterator`，它从起始点扫描整个目录树，直到最后一个可能的子目录。

## 如何做...

1.  我们首先检查`ArrayIterator`类。它非常容易使用。您只需要将数组作为参数提供给构造函数。之后，您可以使用所有基于 SPL 的迭代器标准的方法，例如`current()`，`next()`等。

```php
$iterator = new ArrayIterator($array);
```

### 注意

使用`ArrayIterator`将标准 PHP 数组转换为迭代器。在某种意义上，这提供了过程式编程和面向对象编程之间的桥梁。

1.  作为迭代器的实际用途的一个例子，请查看这个例子。它接受一个迭代器并生成一系列 HTML`<ul>`和`<li>`标签：

```php
function htmlList($iterator)
{
  $output = '<ul>';
  while ($value = $iterator->current()) {
    $output .= '<li>' . $value . '</li>';
    $iterator->next();
  }
  $output .= '</ul>';
  return $output;
}
```

1.  或者，您可以简单地将`ArrayIterator`实例包装到一个简单的`foreach()`循环中：

```php
function htmlList($iterator)
{
  $output = '<ul>';
  foreach($iterator as $value) {
    $output .= '<li>' . $value . '</li>';
  }
  $output .= '</ul>';
  return $output;
}
```

1.  `CallbackFilterIterator`是一种很好的方式，可以为您可能正在使用的任何现有迭代器增加价值。它允许您包装任何现有迭代器并筛选输出。在这个例子中，我们将定义`fetchCountryName()`，它遍历生成国家名称列表的数据库查询。首先，我们从使用第一章中定义的`Application\Database\Connection`类的查询中定义一个`ArrayIterator`实例，*建立基础*：

```php
function fetchCountryName($sql, $connection)
{
  $iterator = new ArrayIterator();
  $stmt = $connection->pdo->query($sql);
  while($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
    $iterator->append($row['name']);
  }
  return $iterator;
}
```

1.  接下来，我们定义一个过滤方法`nameFilterIterator()`，它接受部分国家名称作为参数，以及`ArrayIterator`实例：

```php
function nameFilterIterator($innerIterator, $name)
{
  if (!$name) return $innerIterator;
  $name = trim($name);
  $iterator = new CallbackFilterIterator($innerIterator, 
    function($current, $key, $iterator) use ($name) {
      $pattern = '/' . $name . '/i';
      return (bool) preg_match($pattern, $current);
    }
  );
  return $iterator;
}
```

1.  `LimitIterator` 为您的应用程序添加了基本的分页功能。要使用此迭代器，您只需要提供父迭代器、偏移量和限制。`LimitIterator` 将只产生从偏移量开始的整个数据集的子集。以步骤 2 中提到的相同示例为例，我们将对来自数据库查询的结果进行分页。我们可以通过简单地将`fetchCountryName()`方法生成的迭代器包装在`LimitIterator`实例中来实现这一点：

```php
$pagination = new LimitIterator(fetchCountryName(
$sql, $connection), $offset, $limit);
```

### 注意

在使用`LimitIterator`时要小心。为了实现限制，它需要将*整个*数据集保存在内存中。因此，在迭代大型数据集时，这不是一个好工具。

1.  迭代器可以*堆叠*。在这个简单的例子中，`ArrayIterator`由`FilterIterator`处理，然后由`LimitIterator`限制。首先，我们设置一个`ArrayIterator`实例：

```php
$i = new ArrayIterator($a);
```

1.  接下来，我们将`ArrayIterator`插入`FilterIterator`实例中。请注意，我们正在使用新的 PHP 7 匿名类特性。在这种情况下，匿名类扩展了`FilterIterator`并覆盖了`accept()`方法，只允许具有偶数 ASCII 代码的字母：

```php
$f = new class ($i) extends FilterIterator { 
  public function accept()
  {
    $current = $this->current();
    return !(ord($current) & 1);
  }
};
```

1.  最后，我们将`FilterIterator`实例作为参数提供给`LimitIterator`，并提供偏移量（在本例中为`2`）和限制（在本例中为`6`）：

```php
$l = new LimitIterator($f, 2, 6);
```

1.  然后，我们可以定义一个简单的函数来显示输出，并依次调用每个迭代器，以查看由`range('A', 'Z')`生成的简单数组的结果：

```php
function showElements($iterator)
{
  foreach($iterator as $item)  echo $item . ' ';
  echo PHP_EOL;
}

$a = range('A', 'Z');
$i = new ArrayIterator($a);
showElements($i);
```

1.  这是一个变体，通过在`ArrayIterator`上堆叠`FilterIterator`来产生每隔一个字母：

```php
$f = new class ($i) extends FilterIterator {
public function accept()
  {
    $current = $this->current();
    return !(ord($current) & 1);
  }
};
showElements($f);
```

1.  这里还有另一个变体，它只产生`F H J L N P`，这演示了一个消耗`FilterIterator`的`LimitIterator`，而`FilterIterator`又消耗`ArrayIterator`。这三个示例的输出如下：

```php
$l = new LimitIterator($f, 2, 6);
showElements($l);
```

![如何做...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_03_12.jpg)

1.  回到我们的例子，它产生了一个国家名称列表，假设我们希望迭代一个由国家名称和 ISO 代码组成的多维数组，而不仅仅是国家名称。到目前为止提到的简单迭代器是不够的。相反，我们将使用所谓的**递归**迭代器。

1.  首先，我们需要定义一个方法，该方法使用先前提到的数据库连接类从数据库中提取所有列。与以前一样，我们返回一个由查询数据填充的`ArrayIterator`实例：

```php
function fetchAllAssoc($sql, $connection)
{
  $iterator = new ArrayIterator();
  $stmt = $connection->pdo->query($sql);
  while($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
    $iterator->append($row);
  }
  return $iterator;
}
```

1.  乍一看，人们可能会简单地将标准的`ArrayIterator`实例包装在`RecursiveArrayIterator`中。不幸的是，这种方法只执行**浅**迭代，并且不能给我们想要的：对从数据库查询返回的多维数组的所有元素进行迭代：

```php
$iterator = fetchAllAssoc($sql, $connection);
$shallow  = new RecursiveArrayIterator($iterator);
```

1.  虽然这返回一个迭代，其中每个项表示数据库查询的一行，但在这种情况下，我们希望提供一个迭代，该迭代将遍历查询返回的所有行的所有列。为了实现这一点，我们需要通过`RecursiveIteratorIterator`来展开大规模的操作。

1.  蒙提·派森的粉丝将沉浸在这个类名的丰富讽刺之中，因为它让人回忆起*多余部门*。恰当地，这个类让我们的老朋友`RecursiveArrayIterator`类加班工作，并对数组的所有级别进行**深度**迭代：

```php
$deep     = new RecursiveIteratorIterator($shallow);
```

## 工作原理...

作为一个实际的例子，您可以开发一个测试脚本，使用迭代器实现过滤和分页。对于这个示例，您可以调用`chap_03_developing_functions_filtered_and_paginated.php`测试代码文件。

首先，按照最佳实践，将上述描述的函数放入名为`chap_03_developing_functions_iterators_library.php`的包含文件中。在测试脚本中，确保包含此文件。

数据源是一个名为`iso_country_codes`的表，其中包含 ISO2、ISO3 和国家名称。数据库连接可以在一个`config/db.config.php`文件中。您还可以包括在前一章中讨论的`Application\Database\Connection`类：

```php
define('DB_CONFIG_FILE', '/../config/db.config.php');
define('ITEMS_PER_PAGE', [5, 10, 15, 20]);
include (__DIR__ . '/chap_03_developing_functions_iterators_library.php');
include (__DIR__ . '/../Application/Database/Connection.php');
```

### 注意

在 PHP 7 中，您可以将常量定义为数组。在本例中，`ITEMS_PER_PAGE`被定义为一个数组，并用于生成 HTML`SELECT`元素。

接下来，您可以处理国家名称和每页项目数的输入参数。当前页码将从`0`开始，并且可以递增（下一页）或递减（上一页）：

```php
$name = strip_tags($_GET['name'] ?? '');
$limit  = (int) ($_GET['limit'] ?? 10);
$page   = (int) ($_GET['page']  ?? 0);
$offset = $page * $limit;
$prev   = ($page > 0) ? $page - 1 : 0;
$next   = $page + 1;
```

现在，您已经准备好启动数据库连接并运行一个简单的`SELECT`查询。这应该放在`try {} catch {}`块中。然后，您可以将要堆叠的迭代器放在`try {}`块内：

```php
try {
    $connection = new Application\Database\Connection(
      include __DIR__ . DB_CONFIG_FILE);
    $sql    = 'SELECT * FROM iso_country_codes';
    $arrayIterator    = fetchCountryName($sql, $connection);
    $filteredIterator = nameFilterIterator($arrayIterator, $name);
    $limitIterator    = pagination(
    $filteredIterator, $offset, $limit);
} catch (Throwable $e) {
    echo $e->getMessage();
}
```

现在我们准备好进行 HTML 编写。在这个简单的例子中，我们提供一个表单，让用户选择每页的项目数和国家名称：

```php
<form>
  Country Name:
  <input type="text" name="name" 
         value="<?= htmlspecialchars($name) ?>">
  Items Per Page: 
  <select name="limit">
    <?php foreach (ITEMS_PER_PAGE as $item) : ?>
      <option<?= ($item == $limit) ? ' selected' : '' ?>>
      <?= $item ?></option>
    <?php endforeach; ?>
  </select>
  <input type="submit" />
</form>
  <a href="?name=<?= $name ?>&limit=<?= $limit ?>
    &page=<?= $prev ?>">
  << PREV</a> 
  <a href="?name=<?= $name ?>&limit=<?= $limit ?>
    &page=<?= $next ?>">
  NEXT >></a>
<?= htmlList($limitIterator); ?>
```

输出将看起来像这样：

![工作原理...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_03_13.jpg)

最后，为了测试国家数据库查找的递归迭代，您需要包括迭代器的库文件，以及`Application\Database\Connection`类：

```php
define('DB_CONFIG_FILE', '/../config/db.config.php');
include (__DIR__ . '/chap_03_developing_functions_iterators_library.php');
include (__DIR__ . '/../Application/Database/Connection.php');
```

与以前一样，您应该将数据库查询放在`try {} catch {}`块中。然后，您可以将用于测试递归迭代的代码放在`try {}`块内：

```php
try {
    $connection = new Application\Database\Connection(
    include __DIR__ . DB_CONFIG_FILE);
    $sql    = 'SELECT * FROM iso_country_codes';
    $iterator = fetchAllAssoc($sql, $connection);
    $shallow  = new RecursiveArrayIterator($iterator);
    foreach ($shallow as $item) var_dump($item);
    $deep     = new RecursiveIteratorIterator($shallow);
    foreach ($deep as $item) var_dump($item);     
} catch (Throwable $e) {
    echo $e->getMessage();
}
```

以下是您可以期望从`RecursiveArrayIterator`输出的内容：

![工作原理...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_03_14.jpg)

使用`RecursiveIteratorIterator`后的输出如下：

![工作原理...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_03_15.jpg)

# 使用生成器编写自己的迭代器

在前面的一系列示例中，我们演示了 PHP 7 SPL 中提供的迭代器的使用。但是，如果这个集合不能满足给定项目的需求，该怎么办？一个解决方案是开发一个函数，该函数不是构建一个然后返回的数组，而是使用`yield`关键字通过迭代逐步返回值。这样的函数被称为**生成器**。实际上，在后台，PHP 引擎将自动将您的函数转换为一个称为`Generator`的特殊内置类。

这种方法有几个优点。主要好处在于当您有一个大容器要遍历时（即解析一个大文件），可以看到。传统的方法是构建一个数组，然后返回该数组。这样做的问题是您实际上需要的内存量翻倍！此外，性能受到影响，因为只有在最终数组被返回后才能实现结果。

## 如何做...

1.  在这个例子中，我们在基于迭代器的函数库上构建了一个我们自己设计的生成器。在这种情况下，我们将复制上面关于迭代器的部分中描述的功能，其中我们堆叠了`ArrayIterator`，`FilterIterator`和`LimitIterator`。

1.  因为我们需要访问源数组、所需的过滤器、页码和每页项目数，所以我们将适当的参数包含到一个单独的`filteredResultsGenerator()`函数中。然后，我们根据页码和限制（即每页项目数）计算偏移量。接下来，我们循环遍历数组，应用过滤器，并在偏移量尚未达到时继续循环，或者在达到限制时中断：

```php
function filteredResultsGenerator(array $array, $filter, $limit = 10, $page = 0)
  {
    $max    = count($array);
    $offset = $page * $limit;
    foreach ($array as $key => $value) {
      if (!stripos($value, $filter) !== FALSE) continue;
      if (--$offset >= 0) continue;
      if (--$limit <= 0) break; 
      yield $value;
    }
  }
```

1.  您会注意到这个函数和其他函数之间的主要区别是`yield`关键字。这个关键字的作用是向 PHP 引擎发出信号，产生一个`Generator`实例并封装代码。

## 工作原理...

为了演示`filteredResultsGenerator()`函数的使用，我们将让您实现一个 Web 应用程序，该应用程序扫描一个网页并生成一个经过过滤和分页的 URL 列表，这些 URL 列表是从`HREF`属性中获取的。

首先，您需要将`filteredResultsGenerator()`函数的代码添加到先前配方中使用的库文件中，然后将先前描述的函数放入一个包含文件`chap_03_developing_functions_iterators_library.php`中。

接下来，定义一个测试脚本`chap_03_developing_functions_using_generator.php`，其中包括函数库以及定义在第一章中描述的`Application\Web\Hoover`文件，*构建基础*：

```php
include (__DIR__ . DIRECTORY_SEPARATOR . 'chap_03_developing_functions_iterators_library.php');
include (__DIR__ . '/../Application/Web/Hoover.php');
```

然后，您需要从用户那里收集关于要扫描的 URL，要用作过滤器的字符串，每页多少项以及当前页码的输入。

### 注意

**null coalesce**运算符(`??`)非常适合从 Web 获取输入。如果未定义，它不会生成任何通知。如果未从用户输入接收参数，则可以提供默认值。

```php
$url    = trim(strip_tags($_GET['url'] ?? ''));
$filter = trim(strip_tags($_GET['filter'] ?? ''));
$limit  = (int) ($_GET['limit'] ?? 10);
$page   = (int) ($_GET['page']  ?? 0);
```

### 提示

**最佳实践**

Web 安全性应始终是优先考虑的。在此示例中，您可以使用`strip_tags()`，并将数据类型强制转换为整数`(int)`来消毒用户输入。

然后，您可以定义用于分页列表中上一页和下一页链接的变量。请注意，您还可以应用*健全性检查*，以确保下一页不会超出结果集的末尾。为简洁起见，本示例中未应用此类健全性检查：

```php
$next   = $page + 1;
$prev   = $page - 1;
$base   = '?url=' . htmlspecialchars($url) 
        . '&filter=' . htmlspecialchars($filter) 
        . '&limit=' . $limit 
        . '&page=';
```

然后，我们需要创建一个`Application\Web\Hoover`实例，并从目标 URL 中获取`HREF`属性：

```php
$vac    = new Application\Web\Hoover();
$list   = $vac->getAttribute($url, 'href');
```

最后，我们定义了 HTML 输出，通过先前描述的`htmlList()`函数渲染输入表单并运行我们的生成器：

```php
<form>
<table>
<tr>
<th>URL</th>
<td>
<input type="text" name="url" 
  value="<?= htmlspecialchars($url) ?>"/>
</td>
</tr>
<tr>
<th>Filter</th>
<td>
<input type="text" name="filter" 
  value="<?= htmlspecialchars($filter) ?>"/></td>
</tr>
<tr>
<th>Limit</th>
<td><input type="text" name="limit" value="<?= $limit ?>"/></td>
</tr>
<tr>
<th>&nbsp;</th><td><input type="submit" /></td>
</tr>
<tr>
<td>&nbsp;</td>
<td>
<a href="<?= $base . $prev ?>"><-- PREV | 
<a href="<?= $base . $next ?>">NEXT --></td>
</tr>
</table>
</form>
<hr>
<?= htmlList(filteredResultsGenerator(
$list, $filter, $limit, $page)); ?>
```

这是一个输出的例子：

![工作原理...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_03_16.jpg)
