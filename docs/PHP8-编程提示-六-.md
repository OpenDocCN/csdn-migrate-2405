# PHP8 编程提示（六）

> 原文：[`zh.annas-archive.org/md5/7838a031e7678d26b84966d54ffa29dd`](https://zh.annas-archive.org/md5/7838a031e7678d26b84966d54ffa29dd)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十二章：使用异步编程创建 PHP 8 应用程序

近年来，一项令人兴奋的新技术席卷了 PHP 社区：异步编程，也被称为 PHP async。异步编程模型解决了使用传统同步编程模式编写的应用程序代码中存在的问题：您的应用程序在提供结果之前被迫等待某些任务完成。服务器的中央处理单元（CPU）（或 CPU）在执行乏味的输入/输出（I/O）任务时处于空闲状态。PHP async 允许您的应用程序暂停阻塞的 I/O 任务直到以后。其净效果是性能大幅提升，以及处理更多用户请求的能力。

阅读本章并仔细研究示例后，您将能够开发 PHP 异步应用程序。此外，您将能够利用选定的 PHP 扩展和框架的异步能力。在完成本章的工作后，您将能够提高应用程序的性能，速度提高 5 倍甚至高达 40 倍！

本章涵盖的主题包括以下内容：

+   了解 PHP 异步编程模型

+   使用 Swoole 扩展

+   在异步模式下使用选定的 PHP 框架

+   学习 PHP 8.1 纤程

# 技术要求

本章提供的代码示例所需的最低硬件要求如下：

+   基于 x86_64 的台式电脑或笔记本电脑

+   1GB 的免费磁盘空间

+   4GB 的随机存取存储器（RAM）

+   500 千位每秒或更快的互联网连接

此外，您需要安装以下软件：

+   Docker

+   Docker Compose

有关 Docker 和 Docker Compose 安装的更多信息，请参阅《第一章》《引入新的 PHP 8 OOP 功能》中的《技术要求》部分，以及如何构建用于演示本书中所解释的代码的 Docker 容器。在本书中，我们将您为本书恢复样本代码的目录称为`/repo`。

本章的源代码位于此处：[`github.com/PacktPublishing/PHP-8-Programming-Tips-Tricks-and-Best-Practices`](https://github.com/PacktPublishing/PHP-8-Programming-Tips-Tricks-and-Best-Practices)。

我们现在可以开始讨论 PHP 异步。

# 了解 PHP 异步编程模型

在深入了解如何使用异步库开发 PHP 应用程序之前，重要的是退后一步，看看 PHP 异步编程模型。了解这一点与传统的同步编程模型之间的区别，将为您在开发 PHP 应用程序时利用高性能的新世界打开大门。让我们先看看同步编程模型，然后再深入了解异步。

## 开发同步编程代码

在传统的 PHP 编程中，代码是按线性方式执行的。一旦代码被编译成机器代码，CPU 就会按顺序逐行执行代码，直到代码结束。这对于 PHP 过程式编程来说是正确的。令一些人感到惊讶的是，这对于面向对象编程（OOP）也是正确的！无论您是否在代码中使用对象，OOP 代码都会被编译成第一字节代码，然后是机器代码，并以与过程式代码完全相同的同步方式进行处理。

使用 OPcache 和**即时**（**JIT**）编译器对代码是否以同步方式运行没有影响。OPcache 和 JIT 编译器带来的唯一好处是能够比以前更快地运行同步代码。

重要提示

请不要认为使用同步编程模型编写代码有什么问题！这种方法不仅经过验证，而且非常成功。此外，许多辅助工具（如 PHPUnit、Xdebug、许多框架等）都支持同步代码。 

然而，同步编程模型存在一个主要缺点。使用这种模型，CPU 必须不断等待某些任务完成，然后程序才能继续进行。在很大程度上，这些任务包括访问外部资源，例如进行数据库查询，写入日志文件或发送电子邮件。这些任务被称为**阻塞操作**（阻塞进度的操作）。

以下图表为您提供了一个应用程序流程的可视化表示，其中涉及写入日志文件和发送电子邮件通知的阻塞操作：

![图 12.1 - 同步编程模型](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php8-prog-tip/img/Figure_12.1_B16992_B16992.jpg)

图 12.1 - 同步编程模型

正如您从*图 12.1*中所看到的，当应用程序写入日志文件时，CPU 会暂停程序代码执行，直到**操作系统**（**OS**）发出信号表示日志文件的写入操作已经完成。稍后，代码可能会发送电子邮件通知。同样，CPU 会暂停代码执行，直到电子邮件发送操作结束。尽管每个等待间隔本身可能微不足道，但当您将所有这些阻塞操作的等待间隔相加时，特别是如果涉及较长的循环时，性能就会开始下降。

一个解决方案是大量实施缓存解决方案。另一个解决方案，你可能已经猜到了，是使用异步编程模型编写应用程序。让我们现在来看看。

## 理解异步编程模型

异步操作的理念已经存在了相当长的时间。一个非常著名的例子是 Apache Web 服务器，以其**多处理模块**（**MPMs**）而闻名。`MaxRequestWorkers`指令允许您指定 Web 服务器可以处理多少个同时请求（有关更多信息，请参见[`httpd.apache.org/docs/current/mod/mpm_common.html#maxrequestworkers`](https://httpd.apache.org/docs/current/mod/mpm_common.html#maxrequestworkers)）。

异步编程模型通常涉及设置管理节点，称为**工作节点**。这允许程序执行继续进行，而无需等待任何给定任务完成。性能的提升可能会相当显著，特别是在大量阻塞操作（例如，文件系统访问或数据库查询）发生的情况下。

以下图表可视化了使用异步编程模型完成写入日志文件和发送电子邮件的任务：

![图 12.2 - 异步编程模型](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php8-prog-tip/img/Figure_12.2_B16992_B16992.jpg)

图 12.2 - 异步编程模型

总等待时间减少了分配的工作节点数量的倍数。*图 12.2*中显示的程序流程将比*图 12.1*中显示的程序流程等待时间减少一半。随着分配给处理阻塞操作的工作节点数量的增加，整体性能会提高。

重要提示

异步编程模型*不应与**并行编程**混淆。在并行编程中，任务实际上是同时执行的，通常分配给不同的 CPU 或 CPU 核心。另一方面，异步编程是顺序操作，但允许顺序代码在等待阻塞操作的结果（例如文件系统请求或数据库查询）时继续执行。

现在您已经了解了 PHP 异步编程模型的工作原理，让我们来看看协程支持。

## 使用异步协程支持

*协程*类似于**线程**，但在用户空间中运行，而不是内核空间，因此不需要涉及操作系统。如果支持协程支持，协程支持组件会检测阻塞操作（例如读取或写入文件）并有效地暂停该操作，直到收到结果。这释放了 CPU 以继续执行其他任务，直到从阻塞过程中返回结果。这个过程在机器码级别运行，因此对我们来说是不可检测的，除了我们的代码运行得更快之外。

理论上，使用提供**协程支持**的扩展或框架可能会提高性能，即使您的代码是使用同步编程模型编写的。请注意，并非所有 PHP 异步框架或扩展都提供此支持，这可能会影响您选择未来开发中要使用的框架或扩展。

Swoole 扩展（[`www.swoole.co.uk/`](https://www.swoole.co.uk/)）提供协程支持。另一方面，ReactPHP（[`reactphp.org/`](https://reactphp.org/)）是最受欢迎的 PHP 异步框架之一，但如果不使用 Swoole 扩展（下文讨论）或 PHP fibers（在*学习 PHP 8.1 fibers*部分讨论），则不提供协程支持。然而，ReactPHP 如此受欢迎的原因之一是因为不需要 Swoole 扩展。如果您在无法控制 PHP 安装的托管环境中操作，您仍然可以使用 ReactPHP 并实现显著的性能提升，而无需触及 PHP 安装。

现在我们将注意力转向为异步模型编写代码。

## 创建 PHP 异步应用程序

现在是困难的部分！不幸的是，使用同步编程模型编写的应用程序无法充分利用异步模型所提供的优势。即使您使用提供协程支持的框架和/或扩展，除非重构代码以遵循异步编程模型，否则无法实现最大性能提升。

大多数 PHP 异步框架和扩展都提供多种方法来分离任务。以下是常用方法的简要总结。

### 事件循环

在某种意义上，**事件循环**是一段代码的重复块，它持续运行直到发生指定的事件。所有 PHP 异步扩展和框架都以某种形式提供此功能。以回调形式的监听器被添加到事件循环中。当事件触发时，将调用监听器的逻辑。

Swoole 事件循环利用 Linux `epoll_wait`（[`linux.die.net/man/2/epoll_wait`](https://linux.die.net/man/2/epoll_wait)）功能。由于基于硬件的事件通过伪文件句柄报告给 Linux，Swoole 事件循环允许开发人员基于实际文件的属性以及产生**文件描述符**（**FD**）的任何硬件过程来启动和停止事件循环。

ReactPHP 框架提供了相同的功能，但默认情况下使用 PHP 的`stream_select()`函数，而不是操作系统的`epoll_wait`功能。这使得 ReactPHP 事件循环**应用程序编程接口**（**API**）在服务器之间可移植，尽管反应时间会较慢。ReactPHP 还提供了基于`ext-event`，`ext-ev`，`ext-uv`或`ext-libevent` PHP 扩展定义事件循环的能力。利用这些扩展使 ReactPHP 能够访问硬件，就像 Swoole 一样。

### Promises

**Promise**是一种软件构造，允许您推迟任务的处理直到以后。这个概念最初是作为**CommonJS**项目的一部分提出的（[`wiki.commonjs.org/wiki/Promises/A`](http://wiki.commonjs.org/wiki/Promises/A)）。它被设计为同步和异步编程世界之间的桥梁。

在同步编程中，函数（或类方法）通常要么*成功*，要么*失败*。在 PHP 中，失败被处理为故意抛出的异常或致命错误。在异步模型中，*promise*被识别为三种状态：**fulfilled**，**failed**和**unfulfilled**。因此，当创建一个*promise*实例时，您需要提供三个处理程序，根据它们表示的状态采取行动。

在 ReactPHP 中，当您创建一个`React\Promise\Promise`实例时，您需要提供一个**解析器**作为第一个构造函数参数。解析器本身需要三个标记为`$resolve`，`$reject`和`$notify`的回调函数。这三个对应于 promise 的三种可能状态：fulfilled，failed 或 unfulfilled。

### 流

许多异步框架为 PHP **streams**提供了包装器。PHP 流最常用于处理涉及文件系统的操作。文件访问是一个阻塞操作，会导致程序执行暂停，直到操作系统返回结果。

为了避免文件访问阻塞异步应用程序的进度，使用了一个`streams`组件。例如，ReactPHP 提供了`React\Stream`命名空间下实现`ReadableStreamInterface`或`WritableStreamInterface`的类。这些类用作普通 PHP 流函数（如`fopen()`，`fread()`和`fwrite()`，以及`file_get_contents()`和`file_put_contents()`）的包装器。ReactPHP 类使用内存来避免阻塞，并推迟实际的读取或写入，从而允许异步活动继续进行。

### 定时器

**定时器**是可以在给定间隔后运行的单独任务。在这方面，定时器类似于 JavaScript 的`setTimeout()`函数。使用定时器安排的任务可以设置为仅运行一次，或者在指定间隔连续运行。

大多数 PHP 异步框架或扩展中的定时器实现通常避免使用 PHP 的`pcntl_alarm()`函数。后者允许开发人员在一定秒数后向进程发送`SIGALRM`信号。然而，`pcntl_alarm()`函数一次只允许设置一个，最低时间间隔以秒为单位。相比之下，PHP 异步框架和扩展允许您准确地设置多个定时器，精确到毫秒。PHP 异步定时器实现的另一个区别是它不依赖于`declare(ticks=1)`语句。

定时器有许多潜在的用途，例如，定时器可以检查包含**Completely Automated Public Turing test to tell Computers and Humans Apart**（**CAPTCHA**）图像的目录，并删除旧图像。另一个潜在用途是定期刷新缓存。

### 通道

**通道**是在并发进程之间进行通信的一种方式。当前的通道实现是基于查尔斯·安东尼·霍尔爵士在 1978 年提出的代数模型。他的提议经过多年的完善，并演变成了他在 1985 年出版的书中描述的模型*Communicating Sequential Processes*。通道和**通信顺序进程**（**CSP**）模型是许多当前流行语言的特性，如**Go**。

与其他更复杂的方法相比，使用通道时 CSP 进程是匿名的，而通道是明确命名的。通道方法的另一个方面是，发送方在接收方准备好接收之前被阻止发送。这个简单的原则减轻了实现过多共享锁逻辑的负担。例如，在 Swoole 扩展中，通道被用来实现连接池或作为调度并发任务的一种方式。

现在你已经对 PHP 异步理论有了基本的了解，是时候将理论付诸实践了。我们首先来看一下如何使用 Swoole 扩展。

# 使用 Swoole 扩展

PHP **Swoole 扩展**首次在 PHP 扩展 C 库网站（[`pecl.php.net/`](https://pecl.php.net/)）上于 2013 年 12 月发布。自那时起，它引起了相当大的关注。随着 PHP 8 中引入了 JIT 编译器，Swoole 扩展受到了相当多的关注，因为它快速、稳定，并且有望使 PHP 应用程序运行得更快。总下载量接近 600 万次，平均每月下载量约为 5 万次。

在这一部分，你将学习有关该扩展的信息，它是如何安装和使用的。让我们首先对该扩展进行概述。

## 检查 Swoole 扩展

因为该扩展是用 C 语言编写的，一旦编译、安装和启用，一组函数和类将被添加到你当前的 PHP 安装中。然而，该扩展利用了一些仅在 UNIX 衍生的操作系统中可用的低级特性。这意味着如果你运行的是 Windows 服务器，你唯一能够运行使用 Swoole 扩展的 PHP 异步应用的方法是安装**Windows Services for Linux**（**WSL**）或者在 Windows 服务器上设置你的应用程序在 Docker 容器中运行。

提示

如果你想在 Windows 服务器上尝试 PHP 异步，请考虑使用 ReactPHP（在*使用 ReactPHP*部分讨论），它不需要 Swoole 扩展所需的操作系统依赖项。

PHP 异步的一个重要优势是，初始的代码块会立即加载并保留在内存中，直到异步服务器实例停止。这是使用 Swoole 扩展时的情况。在你的代码中，你创建一个异步服务器实例，有效地将 PHP 转换为一个持续运行的守护程序，监听指定的端口。然而，这也是一个缺点，因为如果你对程序代码进行更改，这些更改在重新加载之前不会被异步服务器实例识别。

Swoole 扩展的一个伟大特性是它的**协程支持**。这意味着，我们不必对使用同步编程模型编写的应用程序进行重大改动。Swoole 将自动挑选出像文件系统访问和数据库查询这样的阻塞操作，并允许这些操作被暂停，而应用程序的其余部分继续进行。由于这种支持，你通常可以简单地使用 Swoole 运行同步应用程序，从而立即提高性能。

Swoole 扩展的另一个非常棒的功能是`Swoole\Table`。这个功能让您可以在内存中创建一个数据库表的等效内容，可以在多个进程之间共享。这样的构造有许多可能的用途，潜在的性能提升真是令人震惊。

Swoole 扩展具有监听**用户数据报协议**（**UDP**）传输而不是**传输控制协议**（**TCP**）的能力。这是一个非常有趣的可能性，因为 UDP 比 TCP 快得多。Swoole 还包括一个毫秒级准确的定时器实现，以及用于 MySQL、PostgreSQL、Redis 和 cURL 的异步客户端。Swoole 扩展还可以使用**Golang**风格的通道设置**进程间通信**（**IPC**）。现在让我们来看一下安装 Swoole。

## 安装 Swoole 扩展

Swoole 扩展可以使用与安装 C 语言编写的任何 PHP 扩展相同的技术来安装。一种方法是简单地使用您的操作系统包管理器。例如，对于 Debian 或 Ubuntu Linux，可以使用`apt`（或其不太友好的表亲`apt-get`），对于 Red Hat、CentOS 或 Fedora，可以使用`yum`或`dnf`。在使用操作系统包管理器时，Swoole 扩展以预编译的二进制形式提供。

然而，推荐的方法是使用`pecl`命令。如果您的安装中没有此命令，可以在 Ubuntu 或 Debian 操作系统上（以 root 用户身份登录）如下安装`pecl`命令：`apt install php-pear`。对于 Red Hat、CentOS 或 Fedora 安装，可以使用以下命令：`yum install php-pear`。

在使用`pecl`安装 Swoole 扩展时，可以指定一些选项。这些选项在这里总结如下：

![表 12.1 – Swoole 扩展 pecl 安装选项](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php8-prog-tip/img/Table_12.1_B16992.jpg)

表 12.1 – Swoole 扩展 pecl 安装选项

有关这些选项的更多信息以及安装过程的概述，请查看这里：

[`www.swoole.co.uk/docs/get-started/installation`](https://www.swoole.co.uk/docs/get-started/installation)

现在让我们来看一个包括对套接字、**JavaScript 对象表示法**（**JSON**）和 cURL 的 Swoole 支持的示例安装，如下所示：

1.  我们需要做的第一件事是更新`pecl`的**通道**。这是 PHP 扩展源代码仓库和函数的列表，就像`apt`或`yum`包管理器使用的`sources`列表一样。以下是执行此操作的代码：

```php
pecl channel-update pecl.php.net
```

1.  接下来，我们指定安装命令并使用`-D`标志添加选项，如下所示：

```php
pecl install -D \
    'enable-sockets="yes" \
     enable-openssl="no" \
     enable-http2="no" \
     enable-mysqlnd="no" \
     enable-swoole-json="yes" \
     enable-swoole-curl="yes"' \
     swoole
```

1.  这开始了扩展安装过程。然后，您会看到各种 C 语言代码文件和头文件被下载，之后会使用本地 C 编译器来编译扩展。以下是编译过程的部分视图：

```php
root@php8_tips_php8 [ / ]# pecl install swoole
downloading swoole-4.6.7.tgz ...
Starting to download swoole-4.6.7.tgz (1,649,407 bytes)
.....................................................................................................................................................................................................................................................................................................................................done: 1,649,407 bytes
364 source files, building
running: phpize
Configuring for:
PHP Api Version:         20200930
Zend Module Api No:      20200930
Zend Extension Api No:   420200930
building in /tmp/pear/temp/pear-build-defaultuserQakGt8/swoole-4.6.7
running: /tmp/pear/temp/swoole/configure --with-php-config=/usr/bin/php-config --enable-sockets=no --enable-openssl=no --enable-http2=no --enable-mysqlnd=yes --enable-swoole-json=yes --enable-swoole-curl=yes
...
Build process completed successfully
Installing '/usr/include/php/ext/swoole/config.h'
Installing '/usr/lib/php/extensions/no-debug-non-zts-20200930/swoole.so'
install ok: channel://pecl.php.net/swoole-4.6.7
configuration option "php_ini" is not set to php.ini location
You should add "extension=swoole.so" to php.ini
```

1.  如果找不到 C 编译器，将会收到警告。此外，您可能需要为您的操作系统安装 PHP 开发库。如果是这种情况，警告消息会给出进一步的指导。

1.  完成后，您需要启用扩展。这可以通过将`extension=swoole`添加到`php.ini`文件中来实现。如果您不确定其位置，可以使用`php -i`命令并查找`php.ini`文件的位置。以下是您可以从命令行发出的添加此指令的命令：

```php
echo "extension=swoole" >>/etc/php.ini
```

1.  然后，您可以使用以下命令来确认 Swoole 扩展的可用性：

```php
php --ri swoole
```

这就完成了 Swoole 扩展的安装。如果您正在自定义编译 PHP，还可以在运行`configure`之前添加`--enable-swoole`选项。这将导致 Swoole 扩展与核心 PHP 安装一起被编译和启用（并允许您跳过刚刚概述的安装步骤）。现在我们将看一下从文档中摘取的一个简短的*Hello World*示例，以测试安装。

## 测试安装

Swoole 文档提供了一个简单的示例，您可以用来快速测试安装是否成功。示例代码显示在主 Swoole 文档页面上([`www.swoole.co.uk/docs/`](https://www.swoole.co.uk/docs/))。由于版权原因，我们在这里不再重复。以下是运行*Hello World*测试的步骤：

1.  首先，我们将*Hello World*示例从[`www.swoole.co.uk/docs/`](https://www.swoole.co.uk/docs/)复制到`/path/to/repo/ch12/php8_swoole_hello_world.php`文件中。

接下来，我们修改了演示程序，并将`$server = new Swoole\HTTP\Server("127.0.0.1", 9501);`更改为`$server = new Swoole\HTTP\Server("0.0.0.0", 9501);`。

这个变化允许 Swoole 服务器监听端口`9501`，对任何**Internet Protocol** (**IP**) 地址。

1.  然后我们修改了`/repo/ch12/docker-compose.yml`文件，使端口`9501`在 Docker 容器外可用，如下所示：

```php
version: "3"
services:
  ...
  php8-tips-php8:
    ...
    ports:
     - 8888:80
     - 9501:9501
    ...
```

1.  为了使这个变化生效，我们不得不关闭并重新启动服务。从本地计算机的命令提示符/终端窗口上，使用以下两个命令：

```php
/path/to/repo/init.sh down
/path/to/repo/init.sh up
```

1.  请注意，如果您正在运行 Windows，请删除`.sh`。

1.  然后我们打开了 PHP 8 Docker 容器的 shell，并运行了*Hello World*程序，如下所示：

```php
$ docker exec -it php8_tips_php8 /bin/bash
# cd /repo/ch12
# php php8_swoole_hello_world.php
```

1.  最后，从 Docker 容器外部，我们打开了一个浏览器到这个 IP 地址和端口：`http://172.16.0.88:9501`。

以下屏幕截图显示了 Swoole *Hello World*程序的结果：

![图 12.3 - Swoole 演示 Hello World 程序输出](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php8-prog-tip/img/Figure_12.3_B16992_B16992.jpg)

图 12.3 - Swoole 演示 Hello World 程序输出

在深入了解 Swoole 扩展如何提高应用程序性能之前，我们需要检查一个适合 PHP 异步模型的样本应用程序。

## 检查一个 I/O 密集型应用程序

为了说明，我们创建了一个样本应用程序，编写为在 PHP 8 中运行的**REpresentational State Transfer** (**REST**) API。样本应用程序提供了以下简单功能的聊天或即时消息 API：

+   使用**HyperText Transfer Protocol** (**HTTP**) `POST`方法将消息发布到特定用户或所有用户。成功发布后，API 返回刚刚发布的消息。

+   一个带有`from=username`参数的 HTTP `GET`方法返回该用户名的所有消息以及发送给所有用户的消息。如果设置了`all=1`参数，它将返回所有用户名的列表。

+   一个 HTTP `DELETE`方法从`messages`表中删除所有消息。

本节仅显示了应用程序代码的部分内容。如果您对整个`Chat`应用程序感兴趣，源代码位于`/path/to/repo/src/Chat`下。主要的 API 端点在这里提供：`http://172.16.0.81/ch12/php8_chat_ajax.php`。

接下来的示例是在 PHP 8.1 Docker 容器中执行的。请确保从 Windows 计算机的命令提示符中按以下方式关闭现有容器：`C:\path\to\repo\init down`。对于 Linux 或 Mac，从终端窗口：`/path/to/repo/init.sh down`。要从 Windows 计算机上启动 PHP 8.1 容器：`C:\path\to\repo\ch12\init up`。从 Linux 或 Mac 终端窗口：`/path/to/repo/ch12/init.sh up`。

接下来的示例是在 PHP 8.1 Docker 容器中执行的。请确保从 Windows 计算机的命令提示符中按以下方式关闭现有容器：`C:\path\to\repo\init down`

对于 Linux 或 Mac，从终端窗口：

`/path/to/repo/init.sh down`

要从 Windows 计算机上启动 PHP 8.1 容器：

`C:\path\to\repo\ch12\init up`

从 Linux 或 Mac 终端窗口：

`/path/to/repo/ch12/init.sh up`

现在我们来看一下核心 API 程序的源代码，如下所示：

1.  首先，我们定义了一个`Chat\Message\Pipe`类，标识了我们需要使用的所有外部类，如下所示：

```php
// /repo/src/Chat/Messsage/Api.php;
namespace Chat\Message;
use Chat\Handler\ {GetHandler, PostHandler,
    NextHandler,GetAllNamesHandler,DeleteHandler};
use Chat\Middleware\ {Access,Validate,ValidatePost};
use Chat\Message\Render;
use Psr\Http\Message\ServerRequestInterface;
class Pipe {
```

1.  然后我们定义一个`exec()`静态方法，调用一组符合**PHP 标准建议 15**（**PSR-15**）的处理程序。我们还通过调用`Chat\Middleware\Access`中间件类的`process`方法来调用管道的第一阶段。`NextHandler`的返回值被忽略：

```php
public static function exec(
    ServerRequestInterface $request) {
    $params   = $request->getQueryParams();
    $method   = strtolower($request->getMethod());
    $dontcare = (new Access())
        ->process($request, new NextHandler());
```

1.  在同一个方法中，我们使用`match()`结构来检查 HTTP 的`GET`、`POST`和`DELETE`方法调用。如果方法是`POST`，我们使用`Chat\Middleware\ValidatePost`验证中间件类来验证`POST`参数。如果验证成功，经过清理的数据然后传递给`Chat\Handler\PostHandler`。如果 HTTP 方法是`DELETE`，我们直接调用`Chat\Handler\DeleteHandler`：

```php
    $response = match ($method) {
        'post' => (new ValidatePost())
            ->process($request, new PostHandler()),
        'delete' => (new DeleteHandler())
            ->handle($request),
```

1.  如果 HTTP 方法是`GET`，我们首先检查`all`参数是否已设置。如果是，我们调用`Chat\Handler\GetAllNamesHandler`。否则，*default*子句通过`Chat\MiddleWare\Validate`传递数据。如果验证成功，经过清理的数据将传递给`Chat\Handler\GetHandler`：

```php
        'get'    => (!empty($params['all'])
        ? (new GetAllNamesHandler())->handle($request)
        : (new Validate())->process($request, 
                new GetHandler())),
        default => (new Validate())
            ->process($request, new GetHandler())};
        return Render::output($request, $response);
    }
}
```

1.  然后可以使用一个简短的传统程序调用核心 API 类，如下所示。在这个调用程序中，我们使用`Laminas\Diactoros\ServerRequestFactory`构建一个符合 PSR-7 的`Psr\Http\Message\ServerRequestInterface`实例。然后将请求通过`Pipe`类，产生一个响应：

```php
// /repo/ch12/php8_chat_ajax.php
include __DIR__ . '/vendor/autoload.php';
use Laminas\Diactoros\ServerRequestFactory;
use Chat\Message\Pipe;
$request  = ServerRequestFactory::fromGlobals();
$response = Pipe::exec($request);
echo $response;
```

我们还创建了一个测试程序（`/repo/ch12/php8_chat_test.php`—未显示），该程序调用 API 端点一定次数（默认为 100 次）。在每次迭代中，测试程序会发布一个随机消息，包括随机的接收者用户名、随机日期和来自`/repo/sample_data/geonames.db`数据库的顺序条目。测试程序需要两个参数。第一个参数是代表 API 的 URL。第二个（可选）参数代表迭代次数。

这里是从命令行运行`/ch12/php8_chat_test.php`在 PHP 8.1 Docker 容器中的示例结果：

```php
root@php8_tips_php8_1 [ /repo/ch12 ]# php php8_chat_test.php \
     http://localhost/ch12/php8_chat_ajax.php 10000  bboyer :          Dubai:AE:2956587 : 2021-01-01 00:00:00
1 fcompton :       Sharjah:AE:1324473 : 2022-02-02 01:01:01
...
998 hrivas : Caloocan City:PH:1500000 : 2023-03-19 09:54:54
999  lpena :         Budta:PH:1273715 : 2021-04-20 10:55:55
From User: dwallace
Elapsed Time: 3.3177478313446
```

从输出中，注意经过的时间。在下一节中，使用 Swoole，我们能够将这个时间减少一半！然而，在使用 Swoole 之前，公平地加入 JIT 编译器是必要的。我们使用以下命令启用 JIT：

```php
# php /repo/ch10/php8_jit_reset.php on 
```

在 PHP 8.0.0 中，可能会遇到一些错误，可能会出现分段错误。然而，在 PHP 8.1 中，启用 JIT 编译器后，API 应该可以正常工作。然而，JIT 编译器是否会提高性能是非常可疑的，因为频繁的 API 调用会导致应用程序等待。任何频繁阻塞 I/O 操作的应用程序都是异步编程模型的绝佳候选。然而，在我们继续之前，我们需要关闭 JIT，使用与之前相同的实用程序，如下所示：

```php
# php /repo/ch10/php8_jit_reset.php off 
```

现在让我们看看 Swoole 扩展如何用于改进这个 I/O 密集型应用程序的性能。

## 使用 Swoole 扩展来提高应用程序性能

鉴于 Swoole 提供了协程支持，为了提高`Chat`应用程序的性能，我们实际上只需要重写`/repo/ch12/php8_chat_ajax.php`调用程序，将其转换为一个在端口`9501`上作为 Swoole 服务器实例监听的 API。以下是重写主 API 调用程序的步骤：

1.  首先，我们启用自动加载并识别所需的外部类：

```php
// /repo/ch12/php8_chat_swoole.php
include __DIR__ . '/vendor/autoload.php';
use Chat\Message\Pipe;
use Chat\Http\SwooleToPsr7;
use Swoole\Http\Server;
use Swoole\Http\Request;
use Swoole\Http\Response;
```

1.  接下来，我们启动一个 PHP 会话，并创建一个监听端口`9501`上任何 IP 地址的`Swoole\HTTP\Server`实例：

```php
session_start();
$server = new Swoole\HTTP\Server('0.0.0.0', 9501);
```

1.  然后我们调用`on()`方法并将其与`start`事件关联。在这种情况下，我们记录一个日志条目以标识 Swoole 服务器启动的时间。其他服务器事件在这里有文档记录：[`www.swoole.co.uk/docs/modules/swoole-http-server-doc`](https://www.swoole.co.uk/docs/modules/swoole-http-server-doc)：

```php
$server->on("start", function (Server $server) {
    error_log('Swoole http server is started at '
        . 'http://0.0.0.0:9501');
});
```

1.  最后，我们定义了一个主服务器事件，`$server->on('request', function () {})`，用于处理传入的请求。以下是实现这一点的代码：

```php
$server->on("request", function (
    Request $swoole_request, Response $swoole_response){
    $request  = SwooleToPsr7::
        swooleRequestToServerRequest($swoole_request);
    $swoole_response->header(
        "Content-Type", "text/plain");
    $response = Pipe::exec($request);
    $swoole_response->end($response);
}); 
$server->start();
```

不幸的是，传递给`on()`方法关联的回调的`Swoole\Http\Request`实例不符合 PSR-7！因此，我们需要定义一个`Chat\Http\SwooleToPsr7`类和一个`swooleRequestToServerRequest()`方法，使用静态调用执行转换。然后我们在`Swoole\Http|Response`实例上设置头，并从管道返回一个值以完成电路。

非常重要的一点是，标准的 PHP 超全局变量，如`$_GET`和`$_POST`，无法从运行的 Swoole 服务器实例中按预期工作。入口点是您用于从命令行启动 Swoole 服务器的初始程序。唯一的传入请求参数是实际的初始程序文件名。任何后续输入必须通过传递给`on()`函数的`Swoole\Http\Request`实例来捕获。

在[`php.net/swoole`](https://php.net/swoole)找到的文档并未显示`Swoole\HTTP\Request`和`Swoole\HTTP\Response`类中的所有可用方法。然而，在 Swoole 网站本身，您可以找到相关的文档，这里也列出了：

+   [`www.swoole.co.uk/docs/modules/swoole-http-request`](https://www.swoole.co.uk/docs/modules/swoole-http-request)

+   [`www.swoole.co.uk/docs/modules/swoole-http-response`](https://www.swoole.co.uk/docs/modules/swoole-http-response)

值得注意的是，`Swoole\HTTP\Request`对象属性大致对应于 PHP 超全局变量，如下所示：

![表 12.2 – Swoole 请求映射到 PHP 超全局变量](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php8-prog-tip/img/Table_12.2_B16992.jpg)

表 12.2 – Swoole 请求映射到 PHP 超全局变量

另一个考虑因素是，在 Swoole 协程中使用 Xdebug 可能会导致分段错误和其他问题，甚至包括**核心转储**。最佳实践是在首次使用`pecl`安装 Swoole 时使用`--enable-debug`标志启用 Swoole 调试。为了测试应用程序，我们进行如下操作：

1.  从命令行进入 PHP 8.1 Docker 容器，我们运行我们的`Chat` API 的 Swoole 版本，如下所示。立即显示的消息是由`$server->on("start", function() {})`产生的：

```php
# cd /repo/ch12
# php php8_chat_swoole.php 
Swoole http server is started at http://0.0.0.0:9501
```

1.  然后我们在主机计算机上打开另一个终端窗口，并在 PHP 8.1 Docker 容器中打开另一个 shell。从那里，我们可以运行`/repo/ch12/php8_chat_test.php`测试程序，如下所示：

```php
# cd /repo/ch12
# php php8_chat_test.php http://localhost:9501 1000
```

1.  注意两个额外的参数。第一个参数告诉测试程序使用 API 的 Swoole 版本，而不是使用 Apache Web 服务器的旧版本。最后的参数告诉测试程序运行 1,000 次迭代。

现在让我们来看一下输出，如下所示：

```php
root@php8_tips_php8_1 [ /repo/ch12 ]# php php8_chat_test.php \
     http://localhost:9501 1000
0    coconnel :      Dubai:AE:2956587 :  2021-01-01 00:00:00
1      htyler :    Sharjah:AE:1324473 :  2022-02-02 01:01:01
...
998  cvalenci : Caloocan City:PH:1500 :  2023-03-19 09:54:54
999  smccormi :      Budta:PH:1273715 :  2021-04-20 10:55:55
From User: ajenkins
Elapsed Time: 1.8595671653748
```

输出的最显着特征是经过的时间。如果您回顾前一节，您会注意到作为传统 PHP 应用程序在 Apache 上运行的 API 大约需要 3.35 秒才能完成 1,000 次迭代，而在 Swoole 下运行的相同 API 大约需要 1.86 秒：几乎是一半的时间！

请注意，这是没有任何额外优化的情况。Swoole 还有许多其他功能可供我们使用，包括定义内存表、在额外的工作线程中生成任务以及使用事件循环来促进缓存，还有其他可能性。正如您所看到的，Swoole 立即提供了性能提升，并且非常值得调查，作为获得现有应用程序更多性能的可能途径。

现在您已经对 Swoole 如何用于提高应用程序性能有了一个概念，让我们来看看其他潜在的 PHP 异步解决方案。

# 在异步模式下使用选定的 PHP 框架

还有许多其他 PHP 框架实现了异步编程模型。在本节中，我们将介绍 ReactPHP，这是最流行的 PHP 异步框架，以及 Amp，另一个流行的 PHP 异步框架。此外，我们还会向您展示如何在异步模式下使用选定的 PHP 框架。

需要注意的是，许多能够在异步模式下运行的 PHP 框架都依赖于 Swoole 扩展。没有这种依赖性的是接下来要介绍的 ReactPHP。

## 使用 ReactPHP

**ReactPHP** ([`reactphp.org/`](https://reactphp.org/)) 是**Reactor 软件设计模式**的一种实现，受到了非阻塞异步**Node.js**框架（[`nodejs.org/en/`](https://nodejs.org/en/)）等的启发。

尽管 ReactPHP 不会像 Swoole 扩展那样自动提高性能，但它的一个重要优势在于它不依赖于 UNIX 或 Linux 的特性，因此可以在 Windows 服务器上运行。ReactPHP 的另一个优势是，它除了标准扩展之外，没有对 PHP 扩展的特定依赖性。

任何 ReactPHP 应用程序的核心都是`React\EventLoop\Loop`类。顾名思义，`Loop`实例启动后实际上是一个**无限循环**。大多数 PHP 无限循环都会给您的应用程序带来灾难！然而，在这种情况下，循环与一个服务器实例一起使用，该服务器实例不断监听给定端口上的请求。

ReactPHP 的另一个关键组件是`React\Socket\Server`。这个类在给定端口上打开一个套接字，使得 ReactPHP 应用程序可以直接监听 HTTP 请求，而无需涉及 Web 服务器。

ReactPHP 的其他特性包括监听 UDP 请求的能力，非阻塞缓存以及异步承诺的实现。ReactPHP 还具有一个`Stream`组件，允许您推迟文件系统的读写操作，大大提高性能，因为您的应用程序不再需要等待这样的文件 I/O 请求完成。

使用 ReactPHP 的另一个优势是它完全符合 PSR-7（HTTP 消息）。我们现在将查看之前描述的`Chat` API 的示例程序，使用 ReactPHP 进行重写。以下是重写程序的步骤：

1.  从命令提示符进入 Docker PHP 8 容器，使用 Composer 安装必要的 ReactPHP 组件：

```php
cd /repo/ch12
composer require --ignore-platform-reqs react/event-loop
composer require --ignore-platform-reqs react/http
composer require --ignore-platform-reqs react/socket
```

1.  然后我们将`/repo/ch12/php8_chat_swoole.php`重写为`/repo/ch12/php8_chat_react.php`。我们需要更改的第一件事是`use`语句：

```php
// /repo/ch12/php8_chat_react.php
include __DIR__ . '/vendor/autoload.php';
use Chat\Message\Pipe;
use React\EventLoop\Factory;
use React\Http\Server;
use React\Http\Message\Response as ReactResponse;
use Psr\Http\Message\ServerRequestInterface;
```

1.  然后我们启动一个会话并创建一个`React\EventLoop\Loop`实例，如下所示：

```php
session_start();
$loop = Factory::create();
```

1.  我们现在定义一个处理程序，它接受一个 PSR-7 `ServerRequestInterface`实例作为参数，并返回一个`React\Http\Message\Response`实例：

```php
$server = new Server($loop, 
function (ServerRequestInterface $request) {
    return new ReactResponse(200,
        ['Content-Type' => 'text/plain'],
        <8 SPACES>Pipe::exec($request)
    );
});
```

1.  然后我们设置一个`React\Socker\Server`实例来监听端口`9501`并执行一个循环，就像这样：

```php
$socket = new React\Socket\Server(9501, $loop);
$server->listen($socket);
echo "Server running at http://locahost:9501\n";
$loop->run();
```

然后我们在 PHP 8.1 容器中打开一个单独的命令行，并启动 ReactPHP 服务器，如下所示：

`root@php8_tips_php8_1 [ /repo/ch12 ]# php php8_chat_react.php`

从另一个命令行进入 PHP 8.1 容器，然后可以运行测试程序如下：`root@php8_tips_php8_1 [ /repo/ch12 ]# php php8_chat_test.php \`

`http://localhost:9501`

输出（未显示）与使用 Swoole 扩展时所见的类似。

接下来，我们来看另一个流行的 PHP 异步框架：Amp。

## 使用 Amp 实现 PHP 异步

**Amp 框架**（https://amphp.org/），类似于 ReactPHP，提供了定时器、promise 和流的实现。Amp 还提供了协程支持，以及一个异步迭代器组件。后者非常有趣，因为迭代对大多数 PHP 应用程序至关重要。如果可以将迭代移入异步处理模式，虽然可能需要进行大量重构，但可能会极大地提高应用程序的性能。另一个有趣的变化是 Amp 可以直接使用任何 ReactPHP 组件！

要安装 Amp，请使用 Composer。各种 Amp 组件都在单独的存储库中可用，因此您不必安装整个框架，只需安装您需要的部分。PHP Amp 服务器的实际实现非常类似于 ReactPHP 中显示的示例。

现在让我们看看另一个可以在 PHP 异步模式下运行的框架：**Mezzio**，以前称为**Zend Expressive**。

## 使用 Mezzio 与 Swoole

**Mezzio**框架（[`docs.mezzio.dev/`](https://docs.mezzio.dev/)）是 Matthew Weier O'Phinney（[`mwop.net/`](https://mwop.net/)）的心血结晶，代表了一个较旧的框架**Zend Framework**和一个较新的框架**Zend Expressive**的延续。Mezzio 属于相对较新的**微框架**类别。微框架不依赖于老化的**模型-视图-控制器**（**MVC**）软件设计模式，主要面向**RESTful API 开发**。在实际应用中，微框架支持 PHP 中间件的原则，并且具有较少的开销和相应的更快速度。

要使用 Swoole 的 Mezzio 应用程序，只需要以下三件事：

1.  安装 Swoole 扩展（在本章前面描述）。

1.  安装`mezzio-swoole`组件，就像这样：

```php
composer require mezzio/mezzio-swoole
```

1.  然后需要使用 Swoole 服务器实例运行 Mezzio。可以使用以下命令完成此操作：

```php
/path/to/project/vendor/bin/laminas mezzio:swoole:start
```

1.  在 Mezzio 应用程序的配置文件中，您需要添加以下密钥：

```php
return [
    'mezzio-swoole' => [
        'swoole-http-server' => [
            'host' => '0.0.0.0',    // all IP addresses
            'port' => 9501,
        ]
    ],
];
```

为了进一步提高性能，当然还应该重写代码的适当部分，以利用 PHP 异步功能。接下来，我们来看一下超越异步的 PHP 扩展。

## 使用并行扩展

`parallel`扩展（[`www.php.net/parallel`](https://www.php.net/parallel)）是为了与 PHP 7.2 及以上版本一起使用而引入的。它的目的是在 PHP 异步之外进入全面并行处理的世界。`parallel`扩展提供了五个关键的低级类，可以构成并行处理应用程序的基础。使用此扩展允许 PHP 开发人员编写类似于**Go**语言的并行代码。让我们从`parallel\Runtime`开始。

### parallel\Runtime 类

每个`parallel\Runtime`实例都会生成一个新的 PHP 线程。然后可以使用`parallel\Runtime::run()`来安排任务。`run()`的第一个参数是`Closure`（匿名函数）。可选的第二个参数是`$argv`，表示在运行时传递给任务的输入参数。`parallel\Runtime::close()`用于优雅地关闭线程。当出现错误条件时，可以使用`parallel\Runtime::kill()`立即退出线程。

### parallel\Future 类

`parallel\Future`实例是从`parallel\Runtime::run()`的返回值创建的。它的作用很像 PHP 异步*promise*（在本章前面描述）。该类有三种方法，列在这里，执行以下操作：

+   `parallel\Future::value()`

返回任务的完成值

+   `parallel\Future::cancel()`

取消代表*失败*状态的任务

+   `parallel\Future::cancelled()|done()`

如果任务状态仍未实现，则返回任务状态

### parallel\Channel 类

`parallel\Channel`类允许开发人员在任务之间共享信息。使用`__construct()`方法或`make()`来创建一个通道。如果`__construct()`没有提供参数，或者`make()`的第二个参数没有提供，通道被认为是无缓冲的。如果向`__construct()`提供一个整数，或者向`make()`的第二个参数提供一个整数，该值表示通道的**容量**。然后，您可以使用`parallel\Channel::send()`和`parallel\Channel::recv()`方法通过通道发送和接收数据。

无缓冲通道会阻塞对`send()`的调用，直到有接收者，反之亦然。另一方面，缓冲通道在达到容量之前不会阻塞。

### 并行事件类

`parallel\Events`类类似于本章第一节中描述的*事件循环*。该类具有`addChannel()`和`addFuture()`方法，用于添加要监视的通道和/或未来实例。`setBlocking()`方法允许事件循环以阻塞或非阻塞模式监视事件。使用`setTimeout()`方法设置整体控制周期（以毫秒为单位），指定循环允许继续的时间。最后，`poll()`方法导致事件循环轮询下一个事件。

### 安装并行扩展

`parallel`扩展可以使用`pecl`命令或使用预编译的二进制文件进行安装，就像安装任何其他非标准的 PHP 扩展一样。然而，非常重要的是，这个扩展只能在**Zend 线程安全**（**ZTS**）的 PHP 安装上工作。因此，如果使用 Docker，您需要获取一个 PHP ZTS 镜像，或者如果自定义编译 PHP，您需要使用`--enable-zts`（Windows）或`--enable-maintainer-zts`（非 Windows）`configure`实用程序标志。

现在您已经了解了如何在异步模式下使用多个选择的 PHP 扩展和框架，我们将展望未来，并讨论 PHP 8.1 纤程。

# 了解 PHP 8.1 纤程

**请求评论**（**RFC**）于 2021 年 3 月由 PHP 核心团队开发人员 Aaron Piotrowski 和 Niklas Keller 发布，概述了在 PHP 语言核心中包含对**纤程**支持的情况。该 RFC 在月底得到批准，并已在即将推出的 PHP 8.1 版本中实施。

纤程实现是低级的，这意味着它主要设计用作 PHP 异步框架（如 ReactPHP 或 Amp）或扩展（如 Swoole 扩展）的一部分。因为从 PHP 8.1 开始，这将成为语言的核心部分，开发人员不必太担心加载哪些扩展。此外，这极大地增强了 PHP 异步框架，因为它们现在在语言核心中直接获得低级支持，大大提高了性能。现在让我们来看一下`Fiber`类本身。

## 发现 Fiber 类

PHP 8.1 的`Fiber`类提供了一个基本的实现，异步框架和扩展开发人员可以在此基础上构建定时器、事件循环、承诺和其他异步工件。

以下是正式的类定义：

```php
final class Fiber {
    public function __construct(callable $callback) {}
    public function start(mixed ...$args): mixed {}
    public function resume(mixed $value = null): mixed {}
    public function throw(Throwable $exception): mixed {}
    public function isStarted(): bool {}
    public function isSuspended(): bool {}
    public function isRunning(): bool {}
    public function isTerminated(): bool {}
    public function getReturn(): mixed {}
    public static function this(): ?self {}
    public static function suspend(
        mixed $value = null): mixed {}
}
```

以下是`Fiber`类方法的摘要：

![表 12.3 - Fiber 类方法摘要](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php8-prog-tip/img/Table_12.3_B16992.jpg)

表 12.3 - Fiber 类方法摘要

如您从*表 12.3*中所见，创建`Fiber`实例后，使用`start()`来运行与纤程关联的回调。之后，您可以自由地挂起、恢复或导致纤程失败，使用`throw()`。您也可以让回调在自己的纤程中运行，并使用`getReturn()`来检索返回的信息。您还可以注意到，`is*()`方法可以用来确定纤程在任何给定时刻的状态。

提示

有关 PHP 8.1 纤程实现的更多信息，请参阅以下 RFC：[`wiki.php.net/rfc/fibers`](https://wiki.php.net/rfc/fibers)。

现在让我们看一个示例，说明如何使用纤程。

## 使用纤程

PHP 8.1 fibers 构成了 PHP 异步应用程序的基础。尽管 fibers 的主要受众是框架和扩展开发人员，但任何 PHP 开发人员都可以从这个类中受益。为了说明 PHP fibers 可以解决的问题，让我们看一个简单的例子。

### 定义一个执行阻塞操作的示例程序

在这个示例中，使用同步编程模型，我们执行三个操作，如下：

+   执行 HTTP `GET` 请求。

+   执行数据库查询。

+   将信息写入访问日志。

已经具有一些异步编程知识的你意识到，所有三个任务都代表着 *阻塞* 操作。我们将采取以下步骤：

1.  首先，我们定义一个要包含的 PHP 文件，其中定义了回调：

```php
// /repo/ch12/php8_fibers_include.php
define('WAR_AND_PEACE',
    'https://www.gutenberg.org/files/2600/2600-0.txt');
define('DB_FILE', __DIR__ 
    . '/../sample_data/geonames.db');
define('ACCESS_LOG', __DIR__ . '/access.log');
$callbacks = [
    'read_url' => function (string $url) {
        return file_get_contents($url); },
    'db_query' => function (string $iso2) {
        $pdo = new PDO('sqlite:' . DB_FILE);
        $sql = 'SELECT * FROM geonames '
             . 'WHERE country_code = ?'
        $stmt = $pdo->prepare($sql);
        $stmt->execute([$iso2]);
        return var_export(
            $stmt->fetchAll(PDO::FETCH_ASSOC), TRUE);
        },
    'access_log' => function (string $info) {
        $info = date('Y-m-d H:i:s') . ": $info\n";
        return file_put_contents(
            ACCESS_LOG, $info, FILE_APPEND);
        },
];
return $callbacks;
```

1.  接下来，我们定义一个包含回调定义并按顺序执行它们的 PHP 程序。我们使用 PHP 8 的 `match {}` 结构来为适当的回调分配不同的参数。最后，我们通过简单返回一个字符串并运行 `strlen()` 来返回回调生成的字节数：

```php
// /repo/ch12/php8_fibers_blocked.php
$start = microtime(TRUE);
$callbacks = include __DIR__ . '/php8_fibers_include.php';
foreach ($callbacks as $key => $exec) {
    $info = match ($key) {
        'read_url' => WAR_AND_PEACE,
        'db_query' => 'IN',
        'access_log' => __FILE__,
        default => ''
    };
    $result = $exec($info);
    echo "Executing $key" . strlen($result) . "\n";
}
echo "Elapsed Time:" . (microtime(TRUE) - $start) . "\n";
```

如果我们按原样运行程序，结果可预见地糟糕，就像我们在这里看到的一样：

```php
root@php8_tips_php8_1 [ /repo/ch12 ]# 
php php8_fibers_blocked.php 
Executing read_url:     3359408
Executing db_query:     23194
Executing access_log:     2
Elapsed Time:6.0914640426636
```

**统一资源定位符**（**URL**）请求下载托尔斯泰的《战争与和平》花费了最长的时间，产生了超过 300 万字节的字节数。总共经过的时间略超过 6 秒。

现在让我们看看如何使用 fibers 重写调用程序。

### 使用 fibers 的示例程序

从 PHP 8.1 Docker 容器中，我们可以定义一个使用 fibers 的调用程序。以下是这样做的步骤：

1.  首先，我们像之前一样包含回调，像这样：

```php
// /repo/ch12/php8_fibers_unblocked.php
$start = microtime(TRUE);
$callbacks = include __DIR__ 
    . '/php8_fibers_include.php';
```

1.  接下来，我们创建一个 `Fiber` 实例来包装每个回调。然后使用 `start()` 启动回调，提供适当的信息：

```php
$fibers = [];
foreach ($callbacks as $key => $exec) {
    $info = match ($key) {
        'read_url' => WAR_AND_PEACE,
        'db_query' => 'IN',
        'access_log' => __FILE__,
        default => ''
    };
    $fibers[$key] = new Fiber($exec);
    $fibers[$key]->start($info);
}
```

1.  然后我们设置一个循环，并检查每个回调是否已经完成。如果是，我们从 `getReturn()` 中输出结果并取消 fiber：

```php
$count  = count($fibers);
$names  = array_keys($fibers);
while ($count) {
    $count = 0;
    foreach ($names as $name) {
        if ($fibers[$name]->isTerminated()) {
           $result = $fibers[$name]->getReturn();
            echo "Executing $name: \t" 
                . strlen($result) . "\n";
            unset($names[$name]);
        } else {
            $count++;
        }
    }
}
echo "Elapsed Time:" . (microtime(TRUE) - $start) . "\n";
```

请注意，此示例仅用于说明。更有可能的是，您会使用现有的框架，如 ReactPHP 或 Amp，它们都已重写以利用 PHP 8.1 fibers。还要注意，即使多个 fibers 同时运行，您可以实现的最短运行时间也与最长运行任务所花费的时间成正比。现在让我们看看 fibers 对 ReactPHP 和 Swoole 的影响。

## 检查 fibers 对 ReactPHP 和 Swoole 的影响

为了说明，您需要在 PHP 8.1 Docker 容器中打开两个单独的命令 shell。按照上一节中给出的说明操作，但打开两个命令 shell 而不是一个。然后我们将使用 `/repo/ch12/php8_chat_test.php` 程序来测试 fibers 的影响。让我们运行第一个测试，使用内置的 PHP web 服务器作为对照。

### 使用内置的 PHP web 服务器进行测试

在第一个测试中，我们使用内置的 PHP web 服务器和传统的 `/repo/ch12/php8_chat_ajax.php` 实现。我们将采取以下步骤：

1.  在两个命令 shell 中，切换到 `/repo/ch12` 目录，像这样：

```php
# cd /repo/ch12
```

1.  在第一个命令 shell 中，使用内置的 PHP web 服务器运行标准的 HTTP 服务器，使用以下命令：

```php
# php -S localhost:9501 php8_chat_ajax.php
```

1.  在第二个命令 shell 中，执行测试程序，如下所示：

```php
php php8_chat_test.php http://localhost:9501 1000 --no
```

结果输出应该是这样的：

```php
root@php8_tips_php8_1 [ /repo/ch12 ]# 
php php8_chat_test.php http://localhost:9501 1000 --no
From User: pduarte
Elapsed Time: 1.687940120697
```

如您所见，使用同步编程编写的传统代码，在 1000 次迭代中大约需要 1.7 秒。现在让我们看看使用 ReactPHP 运行相同测试的情况。

### 使用 ReactPHP 进行测试

在第二个测试中，我们使用我们的 `/repo/ch12/php8_chat_react.php` ReactPHP 实现。我们将采取以下步骤：

1.  在第一个命令 shell 中，按下 *Ctrl* + *C* 退出内置的 PHP web 服务器。

1.  使用 `exit` 退出第一个命令 shell，然后使用 `init shell`（Windows）或 `./init.sh shell`（Linux 或 Mac）重新进入。

1.  使用以下命令启动 ReactPHP 服务器：

```php
# php php8_chat_react.php
```

1.  在第二个命令行窗口中，执行测试程序，就像这样：

```php
php php8_chat_test.php http://localhost:9501 1000 --no
```

输出应如下所示：

```php
root@php8_tips_php8_1 [ /repo/ch12 ]# 
php php8_chat_test.php http://localhost:9501 1000 --no
From User: klang
Elapsed Time: 1.2330160140991
```

从输出中，您可以看到 ReactPHP 从 fibers 中受益匪浅。1000 次迭代的总耗时令人印象深刻，为 `1.2` 秒！

这结束了我们对 PHP 8.1 fibers 的讨论。您现在知道了 fibers 是什么，以及它们如何直接在您的程序代码中使用，以及它们如何使外部 PHP 异步框架受益。

# 总结

在本章中，您学会了传统同步编程和异步编程之间的区别。涵盖了事件循环、定时器、承诺和通道等关键术语。这些知识使您能够确定何时使用异步编程模型编写代码块，以及如何重写现有同步模型应用程序的部分以利用异步特性。

然后，您了解了 Swoole 扩展以及如何将其应用于现有应用程序代码以实现性能改进。您还了解了一些其他以异步方式运行的框架和扩展。您回顾了具体的代码示例，现在可以开始编写异步代码了。

在最后一节中，您了解了 PHP 8.1 fibers。然后，您回顾了一个代码示例，向您展示了如何使用 PHP 8.1 fibers 创建协作多任务函数和类方法。您还看到了选择的 PHP 异步框架如何能够从 PHP 8.1 fibers 支持中受益，提供了更多的性能改进。

这是本书的最后一章。我们希望您喜欢回顾 PHP 8 中提供的各种新功能和好处。您现在对面向对象和过程式代码中要避免的潜在陷阱有了更深入的了解，以及对 PHP 8 扩展的各种更改。有了这些知识，您不仅能够写出更好的代码，而且还有一个坚实的行动计划，最大程度地减少了 PHP 8 迁移后应用代码失败的可能性。
