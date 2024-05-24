# Solr PHP 集成（一）

> 原文：[`zh.annas-archive.org/md5/f84a22173de919e505ee0dcae2dc5dc5`](https://zh.annas-archive.org/md5/f84a22173de919e505ee0dcae2dc5dc5)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

搜索是今天构建的任何 Web 应用程序的一个重要部分。无论是内容网站、招聘网站、电子商务网站还是其他任何网站，搜索在帮助用户定位所需信息方面起着非常重要的作用。作为开发人员，必须为网站用户提供所有可能的搜索工具，并缩小到所需的信息。Apache Solr 是一个全文搜索引擎，提供了大量的搜索功能。PHP 是构建网站的首选编程语言。本书指导读者了解 PHP 和 Solr 之间的集成。

当用户在网站上进行搜索时，他希望结果基于某些标准是相关的。让我们以电子商务网站为例。搜索可以发生在产品名称、品牌名称、型号和产品类型上。一旦结果可见，重要的是在搜索结果中提供一组关于价格、尺寸和产品其他特性的外观，这些可以用来将结果缩小到确切所需的内容。随着用户输入搜索查询，自动完成搜索查询并提供拼写建议是一些高级搜索功能，在一些网站上是可见的。

这本书的想法是引起 PHP 开发人员社区对 Solr 提供的这些以及许多其他搜索功能的关注，并指导构建这些网站的 PHP 开发人员探索和使用这些搜索功能，以构建与其网站相关的搜索功能。这本书不仅提供了快速开发搜索功能的逐步 PHP 代码，还深入探讨了功能在 Solr 端的实际工作原理。还讨论了 Solr 和 PHP 中的配置和调整选项，以帮助高级用户根据其要求调整功能。

本书将从安装 Solr 开始，使用 PHP 向 Solr 添加、更新和删除文档，然后探索 Solr 搜索提供的功能。我们将探索 Solr 提供的功能，如分面、分组、提升和结果排序。我们将构建 Solr 提供的拼写检查和查询自动完成功能。我们还将研究用于扩展搜索的高级功能。本书将提供一个端到端的实用指南，以使用 PHP 和 Solr 构建一个功能齐全的搜索应用程序。

# 本书涵盖的内容

第一章，“安装和集成 Solr 和 PHP”，介绍了 Solr，并在 Windows 和 Linux 环境下安装和集成 Solr 与 PHP。

第二章，“向 Solr 插入、更新和删除文档”，提供了如何使用 PHP 添加、修改和删除 Solr 索引中的文档的实际示例。

第三章，“Solr 上的选择查询和查询模式（DisMax/eDisMax）”，解释了如何在 Solr 上运行基本搜索查询，并使用不同的查询模式来运行一些高级搜索查询。

第四章，“高级查询-过滤查询和分面”，深入探讨了搜索查询，并提供了使用 Solr 和 PHP 运行过滤查询和分面的实际示例。

第五章，“使用 PHP 和 Solr 突出显示结果”，解释了如何配置 Solr 以突出显示搜索结果，并提供了在 PHP 中突出显示的实际示例。

第六章，“调试和统计组件”，解释了 Solr 如何计算相关性，对搜索查询结果进行排名，并解释了如何获取索引统计信息。

第七章, *Solr 中的拼写检查*，配置 Solr 进行拼写检查，并提供了使用 PHP 和 Solr 构建自动完成功能的实际示例。

第八章, *高级 Solr-分组、MoreLikeThis 查询和分布式搜索*，深入讨论了 Solr 中的一些高级主题，并解释了 Solr 如何进行水平扩展。

# 本书所需内容

您需要一台配置了 Apache Web 服务器以运行 PHP 脚本的 Windows 或 Linux 机器。需要一个用于编写代码的文件编辑器和一个用于检查代码执行输出的网络浏览器。我们将根据需要下载、安装和配置 Solr。

# 本书适合谁

本书适用于需要在其应用程序中构建和集成搜索的 PHP 开发人员。不需要对 Solr 有先验知识。了解使用 PHP 进行面向对象编程将会有所帮助。读者应该熟悉 Web 应用程序的概念。

# 惯例

在本书中，您将找到一些区分不同类型信息的文本样式。以下是一些这些样式的示例，以及它们的含义解释。

文本中的代码单词显示如下：“调用`createPing()`函数来创建 ping 查询。”

代码块设置如下：

```php
$config = array(
  "endpoint" => array("localhost" => array("host"=>"127.0.0.1",
"port"=>"8080", "path"=>"/solr", "core"=>"collection1",)
) );
```

任何命令行输入或输出都以以下方式编写：

```php
**cd ~/solr-4.3.1/example**
**java –jar start.jar**

```

*新术语*和*重要单词*以斜体显示。例如，屏幕上看到的单词，例如菜单或对话框中的单词，会在文本中显示为：“从左侧面板的下拉菜单中选择**collection1**。单击**ping**，您将看到毫秒为单位的 ping 时间出现在**ping**链接旁边”。

### 注意

警告或重要说明会以这样的方式出现在一个框中。

### 提示

提示和技巧会以这种方式出现。


# 第一章：安装和集成 Solr 和 PHP

您是 PHP 程序员吗？您是否感到有必要在您的应用程序中整合搜索？您是否知道 Apache Solr？您是否觉得将 Solr 整合到您的 PHP 应用程序中是一项非常繁琐的工作？本书将为您简化整合过程。我们将全面整合 Apache Solr 与 PHP。我们将从 Solr 安装开始。我们将看看如何将 Solr 与 PHP 集成。然后，我们将通过 PHP 代码探索 Solr 提供的功能。阅读本书后，您应该能够将 Solr 提供的几乎所有功能整合到您的 PHP 应用程序中。

本章将帮助我们在两个主要环境中安装 Apache Solr：Windows 和 Linux。我们还将继续探索将 Solr 作为 Apache Tomcat 服务器的一部分进行安装。我们将讨论通过 PHP 与 Solr 通信的可用选项，并学习如何为 Solr PHP 集成设置 Solarium 库。

本章将涵盖以下主题：

+   什么是 Solr？

+   在 Windows 和 Linux 上下载和安装 Solr

+   配置 Tomcat 以运行 Solr。

+   使用 PHP 在 Solr 上执行 ping 查询

+   讨论 Solr PHP 集成的不同库

+   在 Windows 和 Linux 上安装 Solarium

+   使用 Solarium 将 PHP 连接到 Solr

+   使用 PHP 和 Solarium 运行 ping 查询

+   检查 Solr 日志

# Solr

您是 PHP 程序员，您构建网站，如招聘网站、电子商务网站、内容网站或其他网站。您需要为网站提供一个搜索框，用于搜索工作、产品或网站中的其他内容。您会如何处理？您是否在数据库中进行“like”搜索，或者可能使用 MySQL 中提供的全文搜索——如果您使用的是 MySQL。您是否愿意使用其他平台来为您进行搜索，并为您提供一系列功能，以根据您的要求调整搜索？

Solr 是一个开源的 Java 应用程序，提供了一个名为 Lucene 的全文搜索库的接口。Solr 和 Lucene 都是 Apache Lucene 项目的一部分。Apache Solr 使用 Apache Lucene 作为其搜索的核心。Apache Lucene 是一个用 Java 构建的开源搜索 API。除了全文搜索，Solr 还提供了一系列功能，如命中高亮和分面搜索。

# 安装 Solr

Solr 需要您的系统上安装有 Java。要检查系统上是否安装了 Java，请在 Linux 控制台或 Windows 命令提示符中运行`java –version`。如果 Java 的版本大于 1.6，则我们已经准备就绪。最好使用官方的 Java 运行环境，而不是 OpenJDK 提供的运行环境。

```php
**c:\>java -version**
**java version "1.6.0_18"**
**Java(TM) SE Runtime Environment (build 1.6.0_18-b07)**
**Java HotSpot(TM) Client VM (build 16.0-b13, mixed mode, sharing)**

```

让我们下载最新的 Solr。对于本书，我们使用的是 Solr 版本 4.3.1，可以从以下链接下载：

[`lucene.apache.org/solr/downloads.html`](http://lucene.apache.org/solr/downloads.html)

在 Windows 或 Linux 上安装 Solr 只需将`solr-4.3.1.zip`文件解压缩到一个文件夹中。Windows 和 Linux 的安装过程如下：

+   对于 Windows 的安装，只需右键单击 zip 文件并将其解压缩到`C:\solr-4.3.1`文件夹中。要启动 Solr，请转到 Windows 命令提示符**开始** | **运行**。在**运行**窗口中，键入`cmd`。在 Windows 命令提示符中键入以下内容：

```php
**cd C:\solr-4.3.1\example**
**java –jar start.jar**

```

+   对于 Linux 的安装，只需在您的主文件夹中解压缩 zip 文件。按照以下命令在控制台中提取和运行 Solr：

```php
**unzip solr-4.3.1.zip**
**cd ~/solr-4.3.1/example**
**java –jar start.jar**

```

当我们使用`java –jar start.jar`选项启动 Solr 时，Solr 运行在端口 8983 上。它使用一个名为 jetty 的内置 Web 服务器。要查看 Solr 的工作情况，只需将浏览器指向以下地址：

```php
http://localhost:8983/solr/
```

您将能够看到以下界面。这意味着 Solr 运行正常。以下屏幕截图显示了**Solr 管理**界面：

![安装 Solr](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/solr-php-intg/img/4920OS_01_01.jpg)

# 配置 Tomcat 以运行 Solr

默认情况下 Solr 使用的 web 服务器 jetty 仅用于开发目的。对于生产环境，我们希望 Solr 作为更方便的设置的一部分运行，涉及更可靠的 web 服务器。Solr 可以配置为在任何 J2EE 容器上运行，例如 IBM Websphere 或 JBoss 或任何其他服务器。Apache Tomcat 是最常用的服务器。让我们看看如何将 Solr 设置为 Apache Tomcat web 服务器的一部分。我们在 Windows 或 Linux 环境中安装了 Apache Tomcat。

要将 Solr 作为 Apache Tomcat web 服务器的一部分运行，您需要在配置中为`/solr`创建一个上下文。需要将以下`solr.xml`文件放在 Windows 和 Linux 中适当的位置，放在 Tomcat 配置文件夹`<tomcat_home>/conf/Catalina/localhost`中。

```php
<?xml version="1.0" encoding="UTF-8"?>
<Context docBase="/home/jayant/solr-4.3.1/example/webapps/solr.war" >
<Environment name="solr/home" type="java.lang.String" value="/home/jayant/solr-4.3.1/example/solr" override="true" />
</Context>
```

将`docBase`更改为`<solr_path>/example/webapps/solr.war`，并将`Environment`中的 value 属性更改为`<solr_path>/example/solr`。名为`solr/home`的环境告诉 Tomcat 可以找到 Solr 配置文件的位置。除此之外，让我们更改`<solr_path>/example/solr/solr.xml`文件中 Solr 的配置。搜索`hostPort`并将其更改为匹配 Tomcat 的端口`8080`。同样搜索`hostContext`并将其更更改为`solr`。

### 注意

Windows 用户在配置 XML 文件中的路径变量中使用`\`而不是`/`。不要更改`solr/home`中的`/`。

重新启动 Tomcat 服务器，您应该能够转到以下 URL 以查看 Solr 与 Tomcat 一起工作：

```php
http://localhost:8080/solr/
```

### 提示

如果在上述 URL 上看到错误“404 未找到”，可能是因为 Tomcat 无法找到 Solr 的某些库。您可以在`<tomcat_home>/logs/catalina.out`文件夹中的 Tomcat 错误日志中检查确切的错误。要解决缺少库的问题，请将所有 JAR 文件从`<solr_home>/example/lib/ext`复制到`<tomcat_home>/lib`文件夹。

您还可以通过将`<solr_home>/example/resources`文件夹中的`log4j.properties`文件复制到`<tomcat_home>/lib`文件夹中来在 Tomcat 日志中启用高级日志记录。

# 使用 PHP 在 Solr 上执行 ping 查询

在 Solr 中使用 ping 查询来监视 Solr 服务器的健康状况。让我们首先看看在**Solr Admin** web 界面上 ping 查询是如何工作的：

1.  打开浏览器并转到 Solr 的 URL。

1.  从左侧面板的下拉菜单中选择**collection1**。

1.  单击**Ping**，您将看到以毫秒为单位的 ping 时间出现在 ping 链接旁边。我们的 ping 正常工作。![使用 PHP 在 Solr 上执行 ping 查询](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/solr-php-intg/img/4920OS_01_02.jpg)

让我们检查已安装的 PHP 版本。我们需要版本 5.3.2 及以上。要检查版本，请在 Windows 或 Linux 命令行上运行`php -v`，如下所示：

```php
**c:\>php -v**
**PHP 5.4.16 (cli) (built: Jun  5 2013 21:01:46)**
**Copyright (c) 1997-2013 The PHP Group**
**Zend Engine v2.4.0, Copyright (c) 1998-2013 Zend Technologies**

```

要使我们的 PHP 代码中的 ping 正常工作，我们将需要一个名为 cURL 的实用程序。对于 Linux 环境，我们需要安装`curl`，`libcurl`和`php5-curl`软件包。在 Linux 的 Ubuntu 发行版上，可以使用以下命令进行安装：

```php
**sudo apt-get install curl php5-curl**

```

要在 Windows 上启用 cURL，我们需要编辑 PHP 安装中的`php.ini`文件。搜索扩展目录设置并将其更改为`php_curl.dll`所在的位置。还要取消注释加载`php_curl.dll`的行：

```php
**extension=php_curl.dll**
**extension_dir = "C:\php\ext"**

```

以下 URL 是用于执行 ping 查询的 URL。访问此 URL，我们可以看到包含响应头和状态（OK）的响应。

```php
http://localhost:8080/solr/collection1/admin/ping
```

我们可以看到响应是 XML 格式的。要将响应转换为 JSON，只需在先前的 URL 中添加`wt=json`：

```php
http://localhost:8080/solr/collection1/admin/ping/?wt=json
```

Linux 用户可以使用以下命令检查 curl 调用的响应：

```php
**curl http://localhost:8080/solr/collection1/admin/ping/?wt=json**
**{"responseHeader":{"status":0,"QTime":7,"params":{"df":"text","echoParams":"all","rows":"10","echoParams":"all","wt":"json","q":"solrpingquery","distrib":"false"}},"status":"OK"}**

```

通过 PHP 直接调用 Solr 需要我们通过 cURL 调用带有 JSON 响应的 ping，并解码 JSON 响应以显示结果。以下是执行相同操作的一段代码。可以使用 PHP 命令行执行此代码：

```php
$curl = curl_init("http://localhost:8080/solr/collection1/admin/ping/?wt=json");
curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);
$output = curl_exec($curl);
$data = json_decode($output, true);
echo "Ping Status : ".$data["status"]."\n";
```

通过命令行执行上述代码，我们将得到以下输出：

```php
**Ping Status : OK**

```

### 提示

**下载示例代码**

您可以从您在[`www.PacktPub.com`](http://www.PacktPub.com)账户中下载您购买的所有 Packt 图书的示例代码文件。如果您在其他地方购买了这本书，您可以访问[`www.PacktPub.com/support`](http://www.PacktPub.com/support)并注册以直接通过电子邮件接收文件。

# 可用于 PHP-Solr 集成的库

对 Solr 执行任何任务的每次调用最终都是一个 URL，具体参数取决于我们需要完成的任务。因此，向 Solr 添加文档，从 Solr 中删除文档以及搜索文档都可以通过构建具有其各自命令参数的 URL 来完成。我们可以使用 PHP 和 cURL 调用这些 URL 并以 JSON 格式解释响应。但是，我们可以使用库来创建 Solr URL 并解释响应，而不是记住要在 URL 中发送的每个命令。以下是一些可用的库：

+   Solr-PHP-client

+   Apache Solr-PHP 扩展

+   Solarium

Solr-PHP-client 可以从以下位置获得：

[`code.google.com/p/solr-php-client/`](https://code.google.com/p/solr-php-client/)

可以看到，该库的最新发布日期是 2009 年 11 月。自 2009 年以来，该库没有任何发展。这是一个非常基本的客户端，不支持 Solr 中现有的许多功能。

Apache SolrPhp 扩展可以从以下位置获得：

[`pecl.php.net/package/solr`](http://pecl.php.net/package/solr)

该库的最新发布日期是 2011 年 11 月。这是一个相对更好的库。并且也是与[www.php.net](http://www.php.net)集成 Solr 建议的库。它旨在比其他库更快速和轻量级。该库的完整 API 可以从以下位置获得：

[`php.net/manual/en/book.solr.php`](http://php.net/manual/en/book.solr.php)

Solarium 是 Solr PHP 集成的最新库。它是开源的，并且不断更新。它是完全面向对象的，并且几乎在 Solr 中提供功能。它是完全灵活的，您可以添加您认为缺少的功能。还可以使用自定义参数来实现几乎任何任务。不过，该库有许多文件，因此有些沉重。Solarium 在某种程度上复制了 Solr 的概念。并且正在积极开发中。我们将安装 Solarium 并使用 Solarium 库通过 PHP 代码探索 Solr 的全面功能列表。

# 安装 Solarium

Solarium 可以直接下载和使用，也可以使用名为 Composer 的 PHP 包管理器进行安装。如果我们直接下载 Solarium 库，我们将不得不获取其他安装所需的依赖项。另一方面，Composer 可以自行管理所有依赖项。让我们快速看一下在 Windows 和 Linux 环境中安装 Composer。

对于 Linux，以下命令将有助于安装 Composer：

```php
**curl https://getcomposer.org/installer | php**
**mv** **composer.phar composer**

```

这些命令下载 Composer 安装程序 PHP 脚本，并将输出传递给 PHP 程序进行解释和执行。在执行过程中，PHP 脚本将 Composer 代码下载到单个可执行的 PHP 程序`composer.phar`（PHP 存档）中。出于方便使用的目的，我们将`composer.phar`可执行文件重命名为 Composer。在 Linux 上，Composer 可以安装在用户级别或全局级别。要在用户级别安装 Composer，只需使用以下命令将其添加到您的环境路径中：

```php
**export PATH=<path to composer>:$PATH**

```

要在全局级别安装 Composer，只需将其移动到系统路径，例如`/usr/bin`或`/usr/local/bin`。要检查 Composer 是否已成功安装，只需在控制台上运行 Composer 并检查 Composer 提供的各种选项。

![安装 Solarium](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/solr-php-intg/img/4920OS_01_03.jpg)

Windows 用户可以从以下链接下载`composer-setup.exe`：

[`getcomposer.org/Composer-Setup.exe`](http://getcomposer.org/Composer-Setup.exe)

双击可执行文件，并按照说明安装 Composer。

### 注意

我们需要安装一个 Web 服务器——主要是 Apache，并配置它以在上面执行 PHP 脚本。

或者，我们可以使用 PHP 5.4 中内置的 Web 服务器。可以通过转到所有 HTML 和 PHP 文件所在的目录，并使用`php –S localhost:8000`命令在本地机器上的端口`8000`上启动 PHP 开发服务器来启动此服务器。

一旦 Composer 就位，安装 Solarium 就非常容易。让我们在 Linux 和 Windows 机器上都安装 Solarium。

对于 Linux 机器，打开控制台并导航到 Apache `documentRoot`文件夹。这是我们所有 PHP 代码和 Web 应用程序将驻留的文件夹。在大多数情况下，它是`/var/www`，或者可以通过更改 Web 服务器的配置来更改为任何文件夹。创建一个单独的文件夹，您希望您的应用程序驻留在其中，并在此文件夹内创建一个`composer.json`文件，指定要安装的 Solarium 版本。

```php
{
  "require": {
    "solarium/solarium": "3.1.0"
  }
}
```

现在通过运行`composer install`命令来安装 Solarium。Composer 会自动下载和安装 Solarium 及其相关依赖项，如 symfony 事件分发器。这可以在 Composer 的输出中看到。

![安装 Solarium](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/solr-php-intg/img/4920OS_01_04.jpg)

对于 Windows 的安装，打开命令提示符并导航到 Apache `documentRoot`文件夹。在`documentRoot`文件夹内创建一个新文件夹，并在文件夹内运行`composer install`。

我们可以看到在安装过程中，`symfony event dispatcher`和`solarium library`被下载到一个名为`vendor`的单独文件夹中。让我们检查`vendor`文件夹的内容。它包括一个名为`autoload.php`的文件和三个文件夹，分别是`composer`、`symfony`和`solarium`。`autoload.php`文件包含了在我们的 PHP 代码中加载 Solarium 库的代码。其他文件夹都是不言自明的。`solarium`文件夹是库，`symfony`文件夹包含一个名为事件分发器的依赖项，这是 Solarium 正在使用的。`composer`文件夹包含帮助在 PHP 中加载所有所需库的文件。

# 使用 PHP 和 Solarium 库在 Solr 上执行 ping 查询

要使用 Solarium 库，我们需要在我们的 PHP 代码中加载 Solarium 库。让我们看看如何使用 PHP 和 Solarium 执行与之前发出的相同的 ping 查询。

### 注意

我们已经在 Apache `documentroot`的`code`文件夹内安装了 Solarium。Apache `documentRoot`指向`~/htdocs`（在我们的主文件夹内）。

首先在我们的代码中包含 Solarium 库，使用以下代码行：

```php
include_once("vendor/autoload.php");
```

创建一个 Solarium 配置数组，定义如何连接到 Solr。

```php
$config = array(
  "endpoint" => array("localhost" => array("host"=>"127.0.0.1",
  "port"=>"8080", "path"=>"/solr", "core"=>"collection1",)
) );
```

Solarium 有端点的概念。**端点**基本上是一组设置，可用于连接到 Solr 服务器和核心。对于我们通过 Solarium 执行的每个查询，我们可以指定一个端点，使用该端点执行查询。如果未指定端点，则使用第一个端点执行查询，即默认端点。使用端点的好处是，我们需要创建一个 Solarium 客户端实例，而不管我们使用的服务器或核心数量如何。

使用我们之前创建的配置创建 Solarium 客户端。并调用`createPing()`函数创建 ping 查询。

```php
**$client = new Solarium\Client($config);**
**$ping = $client->createPing();**

```

最后执行 ping 查询并使用以下命令获取结果：

```php
**$result = $client->ping($ping);**
**$result->getStatus();**

```

可以看到结果是一个数组。但是我们也可以调用`getStatus()`函数来获取 ping 的状态。我们可以使用 PHP 命令行执行代码，或者调用以下 URL 来查看结果：

```php
http://localhost/code/pingSolarium.php
```

# 更多关于端点的信息

Solarium 为我们提供了在多个 Solr 服务器上添加多个端点并使用单个 Solarium 客户端在任何 Solr 服务器上执行查询的灵活性。要为运行在`localhost`上的另一个端口`8983`上的 Solr 添加另一个端点，并使用它来执行我们的查询，我们将使用以下代码：

```php
$config = array(
  "endpoint" => array(
    "localhost" => array("host"=>"127.0.0.1","port"=>"8080","path"=>"/solr", "core"=>"collection1",),
    "localhost2" => array("host"=>"127.0.0.1","port"=>"8983","path"=>"/solr", "core"=>"collection1",)
  ) );
$result = $client->ping($ping, "localhost2");
```

Solarium 客户端提供了使用`addEndpoint(array $endpointConfig)`和`removeEndpoint(string $endpointName)`函数添加和删除端点的功能。要在运行时修改端点，我们可以调用`getEndpoint(String $endPointName)`来获取端点，然后使用`setHost(String $host)`、`setPort(int $port)`、`setPath(String $path)`和`setCore(String $core)`等函数来更改端点设置。端点提供的其他设置有：

+   `setTimeout(int $timeout)`设置用于指定 Solr 连接的超时时间

+   `setAuthentication(string $username, string $password)`设置用于在 Solr 或 Tomcat 需要 HTTP 身份验证时提供身份验证

+   `setDefaultEndpoint(string $endpoint)`设置可用于为 Solarium 客户端设置默认端点

# 检查 Solr 查询日志

我们现在已经能够使用 Solarium 库在 Solr 上执行 ping 查询。要了解这是如何工作的，请打开 Tomcat 日志。它可以在`<tomcat_path>/logs/solr.log`或`<tomcat_path>/logs/catalina.out`中找到。在 Linux 上，我们可以对日志进行 tail 操作，以查看新条目的出现：

```php
**tail –f solr.log**

```

运行我们之前编写的基于 cURL 的 PHP 代码后，我们可以在日志中看到以下命中：

```php
**INFO  - 2013-06-25 19:51:16.389; org.apache.solr.core.SolrCore; [collection1] webapp=/solr path=/admin/ping/ params={wt=json} hits=0 status=0 QTime=2**
**INFO  - 2013-06-25 19:51:16.390; org.apache.solr.core.SolrCore; [collection1] webapp=/solr path=/admin/ping/ params={wt=json} status=0 QTime=3**

```

运行基于 Solarium 的代码后，我们得到了类似的输出，但是还有一个额外的参数`omitHeader=true`。这个参数会导致忽略输出中的响应头。

```php
**INFO  - 2013-06-25 19:53:03.534; org.apache.solr.core.SolrCore; [collection1] webapp=/solr path=/admin/ping params={omitHeader=true&wt=json} hits=0 status=0 QTime=1**
**INFO  - 2013-06-25 19:53:03.534; org.apache.solr.core.SolrCore; [collection1] webapp=/solr path=/admin/ping params={omitHeader=true&wt=json} status=0 QTime=1**

```

最终，Solarium 也会创建一个 Solr URL 并向 Solr 发出 cURL 调用以获取结果。Solarium 如何知道要访问哪个 Solr 服务器？这些信息是在`$config`参数中的端点设置中提供的。

# Solarium 适配器

那些没有安装 cURL 的系统怎么办？Solarium 具有**适配器**的概念。适配器定义了 PHP 与 Solr 服务器通信的方式。默认适配器是 cURL，我们之前使用过。但是在没有 cURL 的情况下，适配器可以切换到 HTTP。**CurlAdapter**依赖于 curl 实用程序，需要单独安装或启用。另一方面，**HttpAdapter**使用`file_get_contents()` PHP 函数来获取 Solr 响应。这会使用更多的内存，在 Solr 上的查询数量很大时不建议使用。让我们看看在 Solarium 中切换适配器的代码：

```php
$client->setAdapter('Solarium\Core\Client\Adapter\Http');
var_dump($client->getAdapter());
```

我们可以调用`getAdapter()`来检查当前的适配器。还有其他可用的适配器——**ZendHttp**适配器与 Zend Framework 一起使用。还有一个**PeclHttp**适配器，它使用`pecl_http`包来向 Solr 发出 HTTP 调用。HTTP、Curl 和 Pecl 适配器支持身份验证，可以通过之前讨论的`setAuthentication()`函数来使用。**CurlAdapter**还支持使用代理。如果需要，您还可以使用适配器接口创建自定义适配器。

# 摘要

我们已经成功地将 Solr 安装为 Apache Tomcat 服务器的一部分。我们看到了如何使用 PHP 和 cURL 与 Solr 通信，但没有使用库。我们讨论了一些库，并得出结论，Solarium 功能丰富，是一个积极开发和维护的库。我们能够安装 Solarium 并能够使用 PHP 和 Solarium 库与 Solr 通信。我们能够在 Solr 日志中看到实际的查询被执行。我们探索了 Solarium 客户端库的一些功能，如端点和适配器。

在下一章中，我们将看到如何使用 Solarium 库来使用我们的 PHP 代码向 Solr 插入、更新和删除文档。


# 第二章：向 Solr 插入、更新和删除文档

我们将从讨论 Solr 模式开始这一章。我们将探索 Solr 提供的默认模式。此外，我们将探讨：

+   将示例数据推送到 Solr

+   将示例文档添加到 Solr 索引

+   使用 PHP 向 Solr 索引添加文档

+   使用 PHP 在 Solr 中更新文档

+   使用 PHP 在 Solr 中删除文档

+   使用提交、回滚和索引优化

# Solr 模式

Solr 模式主要由字段和字段类型组成。它定义了要存储在 Solr 索引中的字段以及在对这些字段进行索引或搜索时应该发生的处理。在内部，模式用于为使用 Lucene API 创建要进行索引的文档分配属性。Solr 提供的默认模式可以在`<solr_home>/example/solr/collection1/conf/schema.xml`中找到。在这里，`collection1`是核心的名称。

### 注意

Solr 服务器可以有多个核心，每个核心可以有自己的模式。

让我们打开`schema.xml`文件并仔细阅读。在 XML 文件中，我们可以看到有一个字段的部分，在其中有多个字段。另外，还有一个类型的部分。类型部分包含不同的`fieldType`条目，定义了字段的类型，以及在索引和查询期间如何处理字段。让我们了解如何创建`fieldType`条目。

`fieldType`条目包括一个用于字段定义的名称属性。类属性定义了`fieldType`条目的行为。还有一些其他属性：

+   `sortMissingLast`：如果设置为 true，此属性将导致没有该字段的文档出现在具有该字段的文档之后。

+   `sortMissingFirst`：如果设置为 true，此属性将导致没有该字段的文档出现在具有该字段的文档之前。

+   `precisionStep`：`precisionstep`的较低值意味着更高的精度，索引中的更多术语，更大的索引和更快的范围查询。`0`禁用在不同精度级别进行索引。

+   `positionIncrementGap`：它定义了多值字段中一个条目的最后一个标记和下一个条目的第一个标记之间的位置。让我们举个例子。

假设文档中的多值字段中有两个值。第一个值是`aa bb`，第二个值是`xx yy`。理想情况下，在索引期间分配给这些标记的位置将分别为`0`、`1`、`2`和`3`，对应于标记`aa`、`bb`、`xx`和`yy`。

搜索`bb xx`将在其结果中给出此文档。为了防止这种情况发生，我们必须给出一个较大的`positionIncrementGap`，比如`100`。现在，分配给这些标记的位置将分别为`0`、`1`、`100`和`101`，对应于标记`aa`、`bb`、`xx`和`yy`。搜索`bb xx`将不会给出结果，因为`bb`和`xx`不相邻。

`FieldType`条目可以是原始的，如`String`、`Int`、`Boolean`、`Double`、`Float`，也可以是派生的字段类型。派生字段类型可以包含用于定义在索引或查询期间将发生的处理的分析器部分。每个分析器部分包含一个**分词器**和多个过滤器。它们定义了数据的处理方式。例如，有一个`fieldType text_ws`，其中**分析器**是`WhiteSpaceTokenizerFactory`。因此，在`text_ws`类型的字段中进行索引或搜索的任何数据都将在空格上被分割成多个标记。另一个`fieldType text_general`具有用于索引和查询的单独的分析器条目。在索引数据的分析过程中，数据通过一个称为`StandardTokenizerFactory`的分词器，然后通过多个过滤器。以下是我们使用的过滤器：

+   `StopFilterFactory`：这些过滤器用于删除在`stopwords.txt`中定义的停用词

+   `SynonymFilterFactory`：这些过滤器用于为在`index_synonyms.txt`中定义的单词分配同义词

+   `LowerCaseFilterFactory`：此过滤器用于将所有标记中的文本转换为小写

同样，在搜索期间，对该字段的查询进行了不同的分析。这由类型查询的分析器定义。

大多数所需的字段类型通常在默认模式中提供。但是，如果我们觉得有必要，我们可以继续创建新的字段类型。

每个字段都包括名称和类型，这是必需的，还有一些其他属性。让我们来看看这些属性：

+   `name`：此属性显示字段的名称。

+   `type`：此属性定义字段的类型。所有类型都定义为我们之前讨论的`fieldType`条目。

+   `indexed`：如果此字段中的数据需要被索引，则此属性为 true。已索引字段中的文本被分解为标记，并从这些标记创建索引，可以根据这些标记搜索文档。

+   `stored`：如果此字段中的数据也需要存储，则此属性为 true。已索引的数据不能用于构建原始文本。因此，字段中的文本是单独存储的，以检索文档的原始文本。

+   `multivalued`：如果字段在单个文档中包含多个值，则此属性为 true。**标签**就是文档关联的多个值的一个例子。一个文档可以有多个标签，对于任何标签的搜索，都必须返回相同的文档。

+   `required`：如果字段在索引创建期间对每个文档都是必需的，则此属性为 true。

除了普通字段外，模式还包括一些动态字段，这些字段增加了定义字段名称的灵活性。例如，名为`*_i`的动态字段将匹配以`_i`结尾的任何字段，例如`genre_i`或`xyz_i`。

模式中的其他部分有：

+   **uniqueKey**：此部分定义一个字段为唯一且必需的。此字段将用于在所有文档中强制执行唯一性。

+   **copyField**：此部分可用于将多个字段复制到单个字段中。因此，我们可以有多个具有不同字段类型的文本字段，以及一个超级字段，其中所有文本字段都被复制，以便在所有字段中进行通用搜索。

# 向 Solr 索引添加示例文档

让我们将一些示例数据推送到 Solr 中。转到`<solr_dir>/example/exampledocs`。执行以下命令将所有示例文档添加到我们的 Solr 索引中：

```php
**java -Durl=http://localhost:8080/solr/update -Dtype=application/csv -jar post.jar books.csv**
**java -Durl=http://localhost:8080/solr/update  -jar post.jar *.xml**
**java -Durl=http://localhost:8080/solr/update -Dtype=application/json -jar post.jar books.json**

```

要检查已索引多少文档，请转到以下网址：

```php
http://localhost:8080/solr/collection1/select/?q=*:*
```

这是一个向 Solr 查询，要求返回索引中的所有文档。XML 输出中的`numFound`字段指定了我们 Solr 索引中的文档数量。

![将示例文档添加到 Solr 索引](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/solr-php-intg/img/4920_02_01.jpg)

我们正在使用默认模式。要检查模式，请转到以下网址：

```php
http://localhost:8080/solr/#/collection1/schema
```

以下截图显示了示例模式文件`schema.xml`的内容：

![将示例文档添加到 Solr 索引](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/solr-php-intg/img/4920_02_02.jpg)

我们可以看到有多个字段：`id`、`title`、`subject`、`description`、`author`等。配置 Solr 就是为了设计模式以满足字段的要求。我们还可以看到`id`字段是唯一的。

我们可以通过`post.jar`程序向 Solr 插入文档，就像之前看到的那样。为此，我们需要创建一个指定文档中字段和值的 XML、CSV 或 JSON 文件。一旦文件准备好，我们可以简单地调用前面提到的命令之一，将文件中的文档插入 Solr。文件的 XML 格式如下：

```php
<add>
  <doc>
      <field name="id">0553573403</field>
      <field name="cat">book</field>
      <field name="name">A game of thrones</field>
      <!--add more fields -->
  </doc>
  <!-- add more docs here -->
</add>
```

`post.jar`文件是用于处理文件中的多个文档的程序。如果我们有大量文档要插入，而且文档是以 CSV、XML 或 JSON 格式存在的，我们可以使用它。用于向 Solr 插入文档的 PHP 代码反过来创建一个 Solr URL，并使用适当的数据进行`curl`调用。

```php
curl http://localhost:8080/solr/update?commit=true -H "Content-Type: text/xml" --data-binary '<add><doc><field name="id">...</field></doc>...</add>'
```

# 使用 PHP 向 Solr 索引添加文档

让我们看看使用 Solarium 库向 Solr 添加文档的代码。当我们执行以下查询时，我们可以看到在我们的 Solr 索引中有三本作者*George R R Martin*的书：

```php
http://localhost:8080/solr/collection1/select/?q=martin
```

让我们添加剩下的两本书，这些书也已经发布到我们的索引中：

1.  使用以下代码创建一个 solarium 客户端：

```php
$client = new Solarium\Client($config);
```

1.  使用以下代码创建更新查询的实例：

```php
$updateQuery = $client->createUpdate();
```

1.  创建要添加的文档并向文档添加字段。

```php
$doc1 = $updateQuery->createDocument();
$doc1->id = 112233445;
$doc1->cat = 'book';
$doc1->name = 'A Feast For Crows';
$doc1->price = 8.99;
$doc1->inStock = 'true';
$doc1->author = 'George R.R. Martin';
$doc1->series_t = '"A Song of Ice and Fire"';
$doc1->sequence_i = 4;
$doc1->genre_s = 'fantasy';
```

1.  同样，可以创建另一个文档`$doc2`。

### 注意

请注意，`id`字段是唯一的。因此，我们必须为添加到 Solr 的不同文档保留不同的`id`字段。

1.  将文档添加到更新查询中，然后使用`commit`命令：

```php
$updateQuery->addDocuments(array($doc1, $doc2));
$updateQuery->addCommit();
```

1.  最后，执行以下查询：

```php
$result = $client->update($updateQuery);
```

1.  让我们使用以下命令执行代码：

```php
php insertSolr.php
```

执行代码后，搜索马丁得到了五个结果

1.  要添加单个文档，我们可以使用以下代码行将`addDocument`函数调用更新查询实例：

```php
$updateQuery->addDocument($doc1);
```

# 使用 PHP 更新 Solr 中的文档

让我们看看如何使用 PHP 代码以及 Solarium 库来更新 Solr 中的文档。

1.  首先检查我们的索引中是否有任何包含`smith`这个词的文档。

```php
http://localhost:8080/solr/collection1/select/?q=smith
```

1.  我们可以看到`numFound=0`，这意味着没有这样的文档。让我们在我们的索引中添加一本作者姓氏为`smith`的书。

```php
$updateQuery = $client->createUpdate();
$testdoc = $updateQuery->createDocument();
$testdoc->id = 123456789;
$testdoc->cat = 'book';
$testdoc->name = 'Test book';
$testdoc->price = 5.99;
$testdoc->author = 'Hello Smith';
$updateQuery->addDocument($testdoc);
$updateQuery->addCommit();
$client->update($updateQuery);
```

1.  如果我们再次运行相同的选择查询，我们可以看到现在我们的索引中有一个作者名为`Smith`的文档。现在让我们将作者的名字更新为`Jack Smith`，价格标签更新为`7.59`：

```php
$testdoc = $updateQuery->createDocument();
$testdoc->id = 123456789;
$testdoc->cat = 'book';
$testdoc->name = 'Test book';
$testdoc->price = 7.59;
$testdoc->author = 'Jack Smith';
$updateQuery->addDocument($testdoc, true);
$updateQuery->addCommit();
$client->update($updateQuery);
```

1.  再次运行相同的查询，我们可以看到现在在 Solr 的索引中作者姓名和价格已经更新。

更新 Solr 中的文档的过程与向 Solr 中添加文档的过程类似，只是我们必须将`overwrite`标志设置为`true`。如果没有设置参数，Solarium 将不会向 Solr 传递任何标志。但在 Solr 端，`overwrite`标志默认设置为`true`。因此，向 Solr 添加任何文档都将替换具有相同唯一键的先前文档。

Solr 内部没有更新命令。为了更新文档，当我们提供唯一键和覆盖标志时，Solr 内部会删除并再次插入文档。

我们需要再次添加文档的所有字段，即使不需要更新的字段也要添加。因为 Solr 将删除完整的文档并插入新文档。

方法签名中的另一个有趣的参数是在时间内提交。

```php
$updateQuery->addDocument($doc1, $overwrite=true, $commitwithin=10000)
```

上述代码要求 Solr 覆盖文档并在 10 秒内提交。这将在本章后面进行解释。

我们还可以使用`addDocuments(array($doc1, $doc2))`命令一次更新多个文档。

# 使用 PHP 在 Solr 中删除文档

现在让我们继续从 Solr 中删除这个文档。

```php
$deleteQuery = $client->createUpdate();
$deleteQuery->addDeleteQuery('author:Smith');
$deleteQuery->addCommit();
$client->update($deleteQuery);
```

现在，如果我们在 Solr 上运行以下查询，将找不到文档：

```php
http://localhost:8080/solr/collection1/select/?q=smith
```

我们在这里做的是在 Solr 中创建一个查询，搜索作者字段包含`smith`单词的所有文档，然后将其作为删除查询传递。

我们可以通过`addDeleteQueries`方法添加多个删除查询。这可以用于一次删除多组文档。

```php
$deleteQuery->addDeleteQuery(array('author:Burst', 'author:Alexander'));
```

执行此查询时，所有作者字段为`Burst`或`Alexander`的文档都将从索引中删除。

除了通过查询删除，我们还可以通过 ID 删除。我们添加到索引的每本书都有一个`id`字段，我们将其标记为唯一。要按 ID 删除，只需调用`addDeleteById($id)`函数。

```php
$deleteQuery->addDeleteById('123456789');
```

我们还可以使用`addDeleteByIds(array $ids)`一次删除多个文档。

### 注意

除了使用 PHP 代码删除文档，我们还可以使用`curl`调用通过 ID 或查询删除文档。按 ID 删除的 curl 调用如下：

```php
curl http://localhost:8080/solr/collection1/update?commitWithin=1000 -H "Content-Type: text/xml" --data-binary '<delete><id>123456789</id></delete>'
```

通过查询删除的`curl`调用如下：

```php
curl http://localhost:8080/solr/collection1/update?commitWithin=1000 -H "Content-Type: text/xml" --data-binary '<delete><query>author:smith</query></delete>'
```

以下是从 Solr 索引中删除所有文档的简单方法：

```php
**curl http://localhost:8080/solr/collection1/update?commitWithin=1000 -H "Content-Type: text/xml" --data-binary '<delete><query>*:*</query></delete>'**

```

# 提交、回滚和索引优化

我们一直作为参数传递给`addDocument()`函数的`commitWithin`参数指定了此添加文档操作的提交时间。这将提交的控制权留给 Solr 本身。Solr 会在满足更新延迟要求的同时将提交次数优化到最低。

回滚选项通过`addRollback()`函数公开。回滚可以在上次提交之后和当前提交之前进行。一旦提交完成，就无法回滚更改。

```php
$rollbackQuery = $client->createUpdate();
$rollbackQuery->addRollback();
```

索引优化并不一定是必需的任务。但是优化后的索引比未优化的索引性能更好。要使用 PHP 代码优化索引，我们可以使用`addOptimize(boolean $softCommit, boolean $waitSearcher, int $maxSegments)`函数。它具有启用软提交、等待新搜索器打开和优化段数的参数。还要注意，索引优化会减慢 Solr 上所有其他查询的执行速度。

```php
$updateQuery = $client->createUpdate();
$updateQuery->addOptimize($softcommit=true, $waitSearcher=false, $maxSegments=10)
```

对于更高级的选项，我们还可以使用`addParam()`函数向查询字符串添加键值对。

```php
$updateQuery->addParam('name', 'value');
```

通常建议将多个命令组合在一个请求中。这些命令按照它们添加到请求中的顺序执行。但是我们也要注意不要构建超出请求限制的大型查询。在运行大量查询时，在异常情况下使用回滚来避免部分更新/删除，并单独执行提交。

```php
  try
  {
      $client->update($updateQuery);
  }catch(Solarium\Exception $e)
  {
      $rollbackQuery = $client->createUpdate();
      $rollbackQuery->addRollback();
      $client->update($rollbackQuery);
  }
  $commitQry = $client->createUpdate();
  $commitQry->addCommit();
  $client->update($commitQry);
```

在上述代码片段中，如果`update`查询抛出异常，那么它将被回滚。

# 总结

在本章中，我们首先讨论了 Solr 模式。我们对 Solr 模式的工作原理有了基本的了解。然后我们向 Solr 索引中添加了一些示例文档。然后我们看到了多个代码片段，用于向 Solr 索引添加、更新和删除文档。我们还看到了如何使用 cURL 删除文档。我们讨论了提交和回滚在 Solr 索引上的工作原理。我们还看到了如何在我们的代码中使用回滚的示例。我们讨论了使用 PHP 代码进行索引优化以及优化 Solr 索引的好处。

在下一章中，我们将看到如何使用 PHP 代码在 Solr 上执行搜索查询，并探索 Solr 提供的不同查询模式。


# 第三章：在 Solr 上执行选择查询和查询模式（DisMax/eDisMax）

本章将介绍如何使用 PHP 和 Solarium 库在 Solr 索引上执行基本的 select 查询。我们将指定不同的查询参数，如要获取的行数，获取特定字段，排序以及 Solarium 查询中的一些其他参数。我们将讨论 Solr 中的查询模式（查询解析器）是什么，并且还将介绍 Solr 中可用的不同查询模式及其用法。我们将查看不同的功能，以改进我们的查询结果或从我们的查询中获得更具体的结果。将涵盖的主题如下：

+   创建一个带有排序和返回字段的基本 select 查询

+   使用 select 配置运行查询

+   重复使用查询

+   DisMax 和 eDisMax 查询模式

+   Solarium 的基于组件的架构

+   使用 DisMax 和 eDisMax 执行查询

+   在 eDisMax 中对日期进行提升

+   高级调整参数

# 创建一个带有排序和返回字段的基本 select 查询

使用以下查询，让我们搜索索引中的所有书籍，并以 JSON 格式返回前五个结果：

```php
http://localhost:8080/solr/collection1/select/?q=cat:book&rows=5&wt=json
```

如前所述，我们可以形成一个查询 URL 并使用 cURL 通过 PHP 发出查询。解码 JSON 响应并将其用作结果。

让我们看一下 Solarium 代码，以在 Solr 上执行`select`查询。从 Solarium 客户端创建一个`select`查询，如下所示：

```php
$query = $client->createSelect();
```

创建一个搜索所有书籍的查询：

```php
$query->setQuery('cat:book');
```

假设我们每页显示三个结果。因此在第二页，我们将从第四个开始显示接下来的三个结果。

```php
$query->setStart(3)->setRows(3);
```

使用以下代码设置应返回哪些字段：

```php
$query->setFields(array('id','name','price','author'));
```

### 提示

PHP 5.4 用户可以使用方括号构造数组，而不是之前的`array(...)`构造。

```php
$query->setFields(['id','name','price','author']);
```

让我们使用以下查询按价格对结果进行排序：

```php
$query->addSort('price',$query::SORT_ASC);
```

最后，执行以下`select`查询并获取结果：

```php
$resultSet = $client->select($query);
```

结果集包含一个文档数组。每个文档都是一个包含字段和值的对象。对于 Solr 中的多值字段，所有值都将作为数组返回。我们需要相应地处理这些值。除了使用查询检索的四个字段之外，我们还会得到文档的分数。文档分数是由 Lucene 计算的一个数字，用于根据其与输入查询相关性对文档进行排名。我们将在后面的章节中深入讨论评分。让我们遍历结果集并显示字段。

```php
foreach($resultSet as $doc)
{
  echo PHP_EOL."-------".PHP_EOL;
  echo PHP_EOL."ID : ".$doc->id;
  echo PHP_EOL."Name : ".$doc->name;
  echo PHP_EOL."Author : ".$doc->author;
  echo PHP_EOL."Price : ".$doc->price;
  echo PHP_EOL."Score : ".$doc->score;
}
```

从结果集中，我们还可以使用`getNumFound()`函数获取找到的文档数量，如下所示：

```php
$found = $resultSet->getNumFound();
```

在内部，我们设置的参数用于形成一个 Solr 查询，并且相同的查询在 Solr 上执行。我们可以从 Solr 日志中检查正在执行的查询。

### 注意

Solr 日志位于`<tomcat_home>/logs`文件夹中的`catalina.out`文件中。

执行的查询如下所示：

```php
7643159 [http-bio-8080-exec-2] INFO  org.apache.solr.core.SolrCore  – [collection1] webapp=/solr path=/select params={omitHeader=true&sort=price+asc&fl=id,name,price,author&start=2&q=cat:book&wt=json&rows=5} hits=15 status=0 QTime=1
```

`setQuery()`函数的参数应该等于我们 Solr 查询中的`q`参数。如果我们想要在 Solr 索引中搜索多个字段，我们将不得不使用所需字段创建搜索查询。例如，如果我们想要搜索`Author`为`Martin`和`Category`为`book`，我们的`setQuery()`函数将如下所示：

```php
$query->setQuery('cat:book AND author:Martin');
```

# 使用 select 配置运行查询

除了通过函数构建`select`查询之外，还可以使用键值对数组构建`select`查询。以下是带有前述查询参数的`selectconfig`查询：

```php
$selectConfig = array(
  'query' => 'cat:book AND author:Martin',
  'start' => 3,
  'rows' => 3,
  'fields' => array('id','name','price','author'),
  'sort' => array('price' => 'asc')
);
```

我们还可以使用`addSorts(array $sorts)`函数将多个排序字段作为数组添加。要按价格排序，然后按分数排序，我们可以在`addSorts()`函数中使用以下参数：

```php
$query->addSorts(array('price'=>'asc','score'=>'desc'));
```

我们可以使用`getQuery()`函数获取查询参数。使用`getSorts()`函数从我们的 select 查询中获取排序参数。我们还可以使用`removeField($fieldStr)`和`removeSort($sortStr)`函数从查询的字段列表和排序列表中删除参数。

我们可以使用`setQueryDefaultField(String $field)`和`setQueryDefaultOperator(String $operator)`函数来更改 Solr 查询中的默认查询字段和默认运算符。如果没有提供这些函数，则默认的查询字段和默认的查询运算符将从 Solr 配置中获取。默认搜索字段从`solrconfig.xml`中的`df`参数中获取。如果没有提供，默认运算符为`OR`。可以通过在查询中传递`q.op`参数来覆盖它。

# 重用查询

在大多数情况下，作为应用程序的一部分构建的查询可以被重用。重用查询而不是再次创建它们会更有意义。Solarium 接口提供的函数有助于修改 Solarium 查询以便重用。让我们看一个重用查询的例子。

假设我们根据输入参数形成了一个复杂的查询。出于分页目的，我们希望使用相同的查询但更改`start`和`rows`参数以获取下一页或上一页。另一个可以重用查询的情况是排序。假设我们想按价格升序排序，然后再按降序排序。

首先，让我们定义并创建我们在代码中将要使用的 Solarium 命名空间的别名。

```php
use Solarium\Client;
use Solarium\QueryType\Select\Query\Query as Select;
```

接下来，创建一个扩展 Solarium 查询接口的类：

```php
Class myQuery extends Select
{
```

在类内部，我们将创建`init()`函数，它将覆盖`parent`类中的相同函数并在那里添加我们的默认查询参数，如下所示：

```php
protected function init()
{
  parent::init();
  $this->setQuery('*:*');
  $this->setFields(array('id','name','price','author','score'));
  $this->setStart($this->getPageStart(1));
  $this->setRows($this->RESULTSPERPAGE);
  $this->addSort('price', $this->getSortOrder('asc'));
}
```

`RESULTSPERPAGE`是一个私有变量，可以声明为`5`。创建一个单独的函数来设置查询。

```php
function setMyQuery($query)
{
  $this->setQuery($query);
}
```

创建一个函数来重置排序。重置意味着删除所有先前的排序参数。

```php
private function resetSort()
{
  $sorts = $this->getSorts();
  foreach($sorts as $sort)
  {
    $this->removeSort($sort);
  }
}
```

更改排序参数包括重置当前排序和添加新的排序参数。

```php
function changeSort($sortField, $sortOrder)
{
  $this->resetSort();
  $this->addSort($sortField, $this->getSortOrder($sortOrder));
}
```

添加额外排序参数的函数如下所示：

```php
function addMoreSort($sortField, $sortOrder)
{
  $this->addSort($sortField, $this->getSortOrder($sortOrder));
}
```

更改页面的函数如下所示：

```php
function goToPage($pgno)
{
  $this->setStart($this->getPageStart($pgno));
}
```

一旦类被定义，我们可以创建类的实例并设置我们的初始查询。这将给我们来自第一页的结果。

```php
$query = new myQuery();
$query->setMyQuery('cat:book');
echo "<b><br/>Searching for all books</b>".PHP_EOL;
$resultSet = $client->select($query);
displayResults($resultSet);
```

要前往任何其他页面，只需调用我们创建的`goToPage()`函数并传入我们想要前往的页面。它将改变 Solarium 查询，并将`Start`参数更改为与页面结果相符。

```php
$query->goToPage(3);
echo "<b><br/>Going to page 3</b>".PHP_EOL;
$resultSet = $client->select($query);
displayResults($resultSet);
```

完整的代码可以作为下载的一部分。我们在这里所做的是扩展查询接口并添加我们自己的函数来更改查询、重置和添加排序参数以及分页。一旦我们有了`myQuery`类的对象，我们所要做的就是根据需要不断改变参数并使用更改后的参数执行查询。

# DisMax 和 eDisMax 查询模式

**DisMax**（**Disjunction Max**）和**eDisMax**（**Extended Disjunction Max**）是 Solr 中的查询模式。它们定义了 Solr 如何解析用户输入以查询不同字段和不同相关权重。eDisMax 是对 DisMax 查询模式的改进。DisMax 和 eDisMax 默认启用在我们的 Solr 配置中。要切换查询类型，我们需要在我们的 Solr 查询中指定`defType=dismax`或`defType=edismax`。

让我们向我们的索引中添加一些更多的书籍。在我们的`<solr dir>/example/exampledocs`文件夹中执行以下命令（`books.csv`在代码下载中可用）：

```php
**java -Durl=http://localhost:8080/solr/update -Dtype=application/csv -jar post.jar books.csv**

```

DisMax 处理大多数查询。但仍有一些情况下 DisMax 无法提供结果。建议在这些情况下使用 eDisMax。DisMax 查询解析器不支持默认的 Lucene 查询语法。但该语法在 eDisMax 中得到支持。让我们来看看。

要在`cat`中搜索`books`，让我们执行以下查询：

```php
http://localhost:8080/solr/collection1/select?start=0&q=cat:book&rows=15&defType=dismax
```

我们将得到零结果，因为`q=cat:book`查询在 DisMax 中不受支持。要在 DisMax 中执行此查询，我们将不得不指定额外的查询参数`qf`（查询字段），如下所示：

```php
http://localhost:8080/solr/collection1/select?start=0&q=book&qf=cat&rows=15&defType=dismax
```

但`q=cat:book`将在 eDisMax 上起作用：

```php
http://localhost:8080/solr/collection1/select?start=0&q=cat:book&rows=15&defType=edismax
```

要了解 Solarium 库如何用于执行 DisMax 和 eDisMax 查询，我们需要介绍**组件**的概念。Solr 查询有很多选项。将所有选项放在单个查询模型中可能会导致性能下降。因此，额外的功能被分解为组件。Solarium 的查询模型处理基本查询，并且可以通过使用组件向查询添加附加功能。组件仅在使用时加载，从而提高性能。组件结构允许轻松添加更多组件。

# 使用 DisMax 和 eDisMax 执行查询

让我们探讨如何使用 Solarium 库执行 DisMax 和 eDisMax 查询。首先，使用以下代码从我们的选择查询中获取一个 DisMax 组件：

```php
$dismax = $query->getDisMax();
```

在 Solr 中使用 Boosting 来改变结果集中某些文档的得分，以便基于其内容对某些文档进行排名。增强查询是一个原始查询字符串，它与用户的查询一起插入以提高结果中的某些文档。我们可以在`author = martin`上设置一个增强。这个查询将通过`2`来增强包含`martin`的作者的结果。

```php
$dismax->setBoostQuery('author:martin²');
```

查询字段指定要使用某些增强进行查询的字段。传递给`setQuery`函数的查询字符串与这些字段中的文本进行匹配。当字段被增强时，对于该字段中的查询文本的匹配更加重要，因此该文档排名更高。在下面的函数中，作者字段中的匹配被增强了`3`，而名称中的匹配被增强了`2`，而`cat`字段没有增强。因此，在搜索期间，与作者中的输入查询文本匹配的文档将比在`name`或`cat`字段中找到文本的文档排名更高。

```php
$dismax->setQueryFields('cat name² author³');
```

默认情况下，默认 Solr 查询中的所有子句都被视为可选的，除非它们由`+`或`-`符号指定。可选子句被解释为查询中的任何一个子句应该与文档中指定字段中的文本匹配，以便将该文档视为搜索结果的一部分。在处理可选子句时，最小匹配参数表示必须匹配一些最小数量的子句。子句的最小数量可以是一个数字或一个百分比。在数字的情况下，不管查询中的子句数量如何，都必须匹配指定的最小数量。在百分比的情况下，从可用的子句数量和百分比计算出一个数字，然后将其向下舍入到最接近的整数，然后使用它。

```php
$dismax->setMinimumMatch('70%');
```

短语查询字段用于在查询参数中的术语在靠近的情况下提高文档的得分。短语查询字段中的查询术语越接近，文档的得分就越高。在下面的代码中，通过`5`来增强这个分数，从而提高了这些文档的相关性：

```php
$dismax->setPhraseFields('series_t⁵');
```

短语斜率是一个标记相对于另一个标记必须移动的位置数，以匹配查询中指定的短语。在索引期间，输入文本被分析并分解为更小的单词或短语，称为**标记**。同样，在搜索期间，输入查询被分解为与索引中的标记匹配的标记。这与`Phrase`字段一起使用，用于指定要应用于具有设置`Phrase`字段的查询的斜率。

```php
$dismax->setPhraseSlop('2');
```

查询斜率指定用户输入查询中短语中允许的斜率。

```php
$dismax->setQueryPhraseSlop('1');
```

eDisMax 具有 DisMax 解析器的所有功能并对其进行了扩展。

所有前述提到的功能也适用于 eDisMax 查询。我们所要做的就是获取 eDisMax 组件，并在 eDisMax 组件上调用这些功能。要获取 eDisMax 组件，请调用`getEDisMax()`函数如下：

```php
$edismax = $query->getEDisMax();
```

除此之外，eDisMax 还支持基本 Solr 查询解析器支持的基于字段的查询，并且在创建我们的搜索查询时给我们更好的灵活性。

eDisMax 为我们提供了应用具有乘法效应的增强函数的选项。我们可以使用`setBoostFunctionsMult()`函数来提供一个将与分数相乘的增强函数。另一方面，DisMax 解析器提供了`setBoostFunctions()`函数，它可以通过将函数的结果增强添加到查询的分数中来影响分数。

eDisMax 提供了一些其他函数，例如`setPhraseBigramFields()`，它将用户查询切成二元组，并查询指定的字段与相关的增强。例如，如果用户输入了`hello world solr`，它将被分解为`hello world`和`world solr`，并在这些函数中指定的字段上执行。类似地，另一个`setPhraseTrigramFields()`函数可以用于将用户输入分解为三元组，而不是二元组。三元组将包含三个词组，而不是我们之前在二元组中看到的两个词组。eDisMax 还提供了函数，如`setPhraseBigramSlop()`和`setPhraseTrigramSlop()`，用于在搜索期间指定与二元组和三元组字段相关的自定义 slop。

**Slop**是一个标记必须相对于另一个标记移动的位置数。标记`t1`和`t2`之间的`slop`为`5`意味着`t1`应该在`t2`的五个标记内出现。

让我们查看 DisMax 和 eDisMax 查询的 Solr 查询日志。

```php
43782622 [http-bio-8080-exec-5] INFO  org.apache.solr.core.SolrCore  – [collection1] webapp=/solr path=/select params={mm=70%25&tie=0.1&qf=cat+name²+author³&q.alt=*:*&wt=json&rows=25&defType=edismax&omitHeader=true&pf=series_t⁵&bq=author:martin²&fl=id,name,price,author,score&start=0&q=book+-harry+"dark+tower"&qs=1&ps=2} hits=24 status=0 QTime=55 

43795018 [http-bio-8080-exec-1] INFO  org.apache.solr.core.SolrCore  – [collection1] webapp=/solr path=/select params={mm=70%25&tie=0.1&qf=cat+name²+author³&q.alt=*:*&wt=json&rows=25&defType=dismax&omitHeader=true&pf=series_t⁵&bq=author:martin²&fl=id,name,price,author,score&start=0&q=book+-harry+"dark+tower"&qs=1&ps=2} hits=24 status=0 QTime=2
```

我们可以看到，除了 Solr 查询的常规参数之外，还有一个`defType`参数，用于指定查询的类型。在前面的情况下，我们可以看到`defType`是 DisMax 或 eDisMax，具体取决于我们执行的查询类型。

# 在 eDisMax 查询中的日期增强

让我们使用 eDisMax 根据日期增强搜索结果，以便最近的书籍出现在顶部。我们将使用`setBoostFunctionsMult()`函数来指定对`modified_date`的增强，在我们的情况下，它存储了记录最后添加或更新的日期。

```php
$query = $client->createSelect();
$query->setQuery('cat:book -author:martin');
$edismax = $query->getedismax();
$edismax->setBoostFunctionsMult('recip(ms(NOW,last_modified),1,1,1)');
$resultSet = $client->select($query);
```

在这里，我们正在搜索所有作者不是 Martin（`martin`）的书籍。`-`（负号）用于*非查询*。我们还对今天和上次修改日期之间的倒数进行了乘法增强。Solr 提供的`recip`函数定义如下：

```php
recip(x,m,a,b) = a/(m*x+b) which in our case becomes 1/(1*ms(NOW,last_modified)+1)
```

在这里，`m`，`a`和`b`是常数，`x`可以是任何数值或复杂函数。在我们的情况下，`x`是`NOW`和`last_modified`之间的毫秒数。我们在分母中添加`1`以避免在`last_modified`不存在的情况下出现错误。这表明随着`NOW`和`last_modified`之间的差异增加，该文档的增强减少。最近的文档具有更高的`last_modified`，因此与`NOW`相关的差异较小，因此增强更多。让我们检查查询的 Solr 日志。

```php
**2889948 [http-bio-8080-exec-4] INFO  org.apache.solr.core.SolrCore  – [collection1] webapp=/solr path=/select params={mm=70%25&tie=0.1&pf2=name²+author¹.8+series_t¹.3&q.alt=*:*&wt=json&rows=25&defType=edismax&omitHeader=true&pf=series_t⁵&fl=id,name,price,author,score,last_modified&start=0&q=cat:book+-author:martin&boost=recip(ms(NOW,last_modified),1,1,1)} hits=26 status=0 QTime=59**

```

复制并粘贴 Solr 日志中的查询参数，并附加到 Solr `select` URL。还将`wt=json`更改为`wt=csv`。这将给出结果的逗号分隔视图。

```php
**http://localhost:8080/solr/collection1/select?mm=70%25&tie=0.1&pf2=name²+author¹.8+series_t¹.3&q.alt=*:*&wt=csv&rows=25&defType=edismax&omitHeader=true&pf=series_t⁵&fl=id,name,price,author,score,last_modified&start=0&q=cat:book+-author:martin&boost=recip(ms(NOW,last_modified),1,1,1)**

```

![在 eDisMax 查询中的日期增强](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/solr-php-intg/img/4920_03_01.jpg)

可以进一步修改 URL 以根据我们的要求调整/修改查询。

# 高级查询参数

备用查询在查询参数为空或未指定时使用。Solarium 默认将查询参数设置为`*:*`。备用查询可用于从索引中获取所有文档以进行分面目的。

```php
$dismax->setQueryAlternative('*:*');
```

对于选择所有 DisMax/eDisMax 中的文档，正常的查询语法`*:*`不起作用。要选择所有文档，请将 Solarium 查询中的默认查询值设置为空字符串。这是因为 Solarium 中的默认查询是`*:*`。还将备用查询设置为`*:*`。DisMax/eDisMax 正常查询语法不支持`*:*`，但备用查询语法支持。

# 摘要

我们能够使用 Solarium 库在 Solr 上执行选择查询。我们探索了`select`查询的基本参数。我们看到如何使用配置数组来创建 Solarium 查询。我们能够在执行查询后遍历结果。我们扩展了查询类以重复使用查询。我们能够对现有查询进行分页，并能够在不重新创建完整查询的情况下更改排序参数。我们在 Solr 中看到了 DisMax 和 eDisMax 查询模式。我们还对 Solarium 库的基于组件的结构有了一些了解。我们探索了 DisMax 和 eDisMax 查询的查询参数。我们还看到了如何使用 eDisMax 查询在 Solr 上进行“最近优先”日期提升。最后，我们在 Solarium 中看到了一些高级查询参数，用于 DisMax 和 eDisMax。

在下一章中，我们将深入研究基于查询结果不同标准的高级查询。


# 第四章：高级查询-过滤器查询和分面

本章首先定义了过滤器查询及其与我们之前使用的普通搜索查询相比的优点。我们将看到如何在 Solr 中使用 PHP 和 Solarium 库使用过滤器查询。然后我们将探讨 Solr 中的分面。我们还将看到如何使用 PHP 在 Solr 中进行分面。我们将探索按字段进行分面、按查询进行分面和按范围进行分面。我们还将看看如何使用枢轴进行分面。将涵盖的主题如下：

+   过滤器查询及其优点

+   使用 PHP 和 Solarium 执行过滤器查询

+   创建过滤器查询配置

+   分面

+   按字段、查询和范围进行分面

+   分面枢轴

# 过滤器查询及其优点

过滤器查询用于在不影响评分的情况下对 Solr 查询的结果进行**过滤**。假设我们正在寻找所有有库存的书籍。相关查询将是`q=cat:book AND inStock:true`。

```php
http://localhost:8080/solr/collection1/select/?q=cat:book%20AND%20inStock:true&fl=id,name,price,author,score,inStock&rows=50&defType=edismax
```

处理相同查询的另一种方法是使用过滤器查询。查询将变为`q=cat:book&fq=inStock:true`。

```php
http://localhost:8080/solr/collection1/select/?q=cat:book&fl=id,name,price,author,score,inStock&rows=50&fq=inStock:true&defType=edismax
```

尽管结果相同，但使用过滤器查询有一定的好处。过滤器查询仅存储文档 ID。这使得在查询中应用过滤器以包括或排除文档非常快速。另一方面，普通查询具有复杂的评分函数，导致性能降低。过滤器查询不进行评分或相关性计算和排名。使用过滤器查询的另一个好处是它们在 Solr 级别被缓存，从而获得更好的性能。建议使用过滤器查询而不是普通查询。

# 执行过滤器查询

要向现有查询添加过滤器查询，首先需要从我们的 Solr 查询模块创建一个过滤器查询。

```php
$query = $client->createSelect();
$query->setQuery('cat:book');
$fquery = $query->createFilterQuery('Availability');
```

作为`createFilterQuery()`函数的参数提供的字符串被用作过滤器查询的*key*。此键可用于检索与此查询关联的过滤器查询。一旦过滤器查询模块可用，我们可以使用`setQuery()`函数为此 Solarium 查询设置过滤器查询。

在上面的代码片段中，我们创建了一个名为`Availability`的过滤器查询。我们将为键`Availability`设置过滤器查询为`instock:true`，然后执行完整的查询如下：

```php
$fquery->setQuery('inStock:true');
$resultSet = $client->select($query);
```

一旦结果集可用，就可以迭代它以获取和处理结果。

让我们检查 Solr 日志，看看发送到 Solr 的查询。

```php
70981712 [http-bio-8080-exec-8] INFO  org.apache.solr.core.SolrCore  – [collection1] webapp=/solr path=/select params={mm=70%25&tie=0.1&pf2=name²+author¹.8+series_t¹.3&q.alt=*:*&wt=json&rows=25&defType=edismax&omitHeader=true&pf=series_t⁵&fl=id,name,price,author,score,last_modified&start=0&q=cat:book+-author:martin&boost=recip(ms(NOW,last_modified),1,1,1)&**fq=inStock:true**} hits=19 status=0 QTime=4
```

我们可以看到`fq`参数`inStock:true`附加到我们 Solr 查询的参数列表中。

`getFilterQuery(string $key)`函数可用于检索与 Solarium 查询关联的过滤器查询。

```php
echo $fquery->getFilterQuery('Availability')->getQuery();
```

# 创建过滤器查询配置

我们还可以使用`addFilterQuery()`函数将过滤器查询作为配置参数传递给 Solarium 查询。为此，我们需要首先将过滤器查询定义为配置数组，然后将其添加到 Solarium 查询中。

```php
$fqconfig = array(
          "query"=>"inStock:true",
          "key"=>"Availability",
  );
$query = $client->createSelect();
$query->addFilterQuery($fqconfig);
```

上述配置创建的 Solr 查询与之前创建的查询类似。使用过滤器查询配置的好处是我们可以将多个标准过滤器查询定义为配置，并根据需要将它们添加到我们的 Solr 查询中。`addTag(String $tag)`和`addTags(array $tags)`函数用于在过滤器查询中定义标签。我们可以使用这些标签在分面中排除某些过滤器查询。稍后我们将通过一个示例进行说明。

# 分面

分面搜索将搜索结果分成多个类别，显示每个类别的计数。分面用于搜索以深入查询结果的子集。要了解分面有多么有用，让我们转到[www.amazon.com](http://www.amazon.com)搜索手机。我们将在左侧看到分面，如品牌、显示尺寸和运营商。一旦选择一个分面进行深入，我们将看到更多的分面，这将帮助我们缩小我们想购买的手机范围。

facet 通常用于预定义的人类可读文本，例如位置、价格和作者姓名。对这些字段进行标记化是没有意义的。因此，*facet 字段*在 Solr 模式中与搜索和排序字段分开。它们也不转换为小写，而是保留原样。facet 是在 Solr 上索引字段上完成的。因此，不需要存储 facet 字段。

Solarium 引入了**facetset**的概念，这是一个中央组件，可用于创建和管理 facet，并设置全局 facet 选项。让我们将本章的`books.csv`文件推送到 Solr 索引中。我们可以使用与第二章中使用的相同命令，*向 Solr 插入、更新和删除文档*，如下所示：

```php
**java -Durl=http://localhost:8080/solr/update -Dtype=application/csv -jar post.jar books.csv**

```

# 按字段 facet

按字段 facet 计算特定字段中术语的出现次数。让我们在**作者**和**流派**上创建 facet。在我们的 Solr 索引中，有专门的字符串字段用于索引与 facet 相关的字符串，而不进行任何标记。在这种情况下，字段是`author_s`和`genre_s`。

### 注意

以`_s`结尾的字段是在我们的 Solr `schema.xml`中定义的动态字段。定义为`*_s`的动态字段匹配以`_s`结尾的任何字段，并且字段定义中的所有属性都应用在这个字段上。

创建一个在我们的`author_s`字段上的 facet，我们需要从 Solarium 查询中获取`facetset`组件，创建一个`facet field`键，并使用将要创建的 facet 来设置实际字段。

```php
$query->setQuery('cat:book');
$facetset = $query->getFacetSet();
$facetset->createFacetField('author')->setField('author_s');
```

使用以下代码设置要获取的 facet 数量：

```php
$facetset->setLimit(5);
```

返回至少有一个术语的所有 facet。

```php
$facetset->setMinCount(1);
```

还返回没有 facet 字段值的文档。

```php
$facetset->setMissing(true);
```

执行查询后，我们将需要通过 facet 字段键获取 facet 和计数。

```php
$resultSet = $client->select($query);
$facetData = $resultSet->getFacetSet()->getFacet('author');
foreach($facetData as $item => $count)
{
  echo $item.": [".$count."] <br/>".PHP_EOL;
}
```

此外，我们可以使用`setOffset(int $offset)`函数从此偏移开始显示 facet。`setOffset(int $offset)`和`setLimit(int $limit)`函数可用于 facet 内的分页。

通过 Solr 日志，我们可以看到在 Solr 上执行的查询。

```php
928567 [http-bio-8080-exec-9] INFO  org.apache.solr.core.SolrCore  – [collection1] webapp=/solr path=/select params={omitHeader=true&**facet.missing=true&facet=true**&fl=id,name,price,author,score,last_modified&**facet.mincount=1**&start=0&q=cat:book&**facet.limit=5&facet.field={!key%3Dauthor}author_s&facet.field={!key%3Dgenre}genre_s**&wt=json&rows=25} hits=30 status=0 QTime=2 
```

传递参数`facet=true`以启用 facet。需要 facet 的字段作为多个`facet.field`值传递。我们在这里看到的其他参数是`facet.missing`，`facet.mincount`和`facet.limit`。要检查 Solr 对 facet 查询的响应，让我们从日志中复制查询，将其粘贴到我们的 Solr URL 中，并删除`omitHeaders`和`wt`参数。

```php
http://localhost:8080/solr/collection1/select/?facet.missing=true&facet=true&fl=id,name,price,author,score,last_modified&facet.mincount=1&start=0&q=cat:book&facet.limit=5&facet.field={!key%3Dauthor}author_s&facet.field={!key%3Dgenre}genre_s&rows=25
```

![按字段 facet](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/solr-php-intg/img/4920_04_01.jpg)

facet 是在字段上的-作者和流派。不同作者和流派的计数是可见的。

# 按查询 facet

我们可以使用 facet 查询来获取与 facet 查询相关的计数，而不受主查询的影响，并且可以排除过滤查询。让我们看看获取`genre`为`fantasy`的 facet 计数的代码，并且还看一个排除过滤查询的示例。

让我们首先创建一个查询，以选择我们索引中的所有书籍。

```php
$query->setQuery('cat:book');
```

为库存中的书籍创建一个过滤查询并对其进行标记。

```php
$fquery = $query->createFilterQuery('inStock');
$fquery->setQuery('inStock:true');
$fquery->addTag('inStockTag');
```

使用以下代码从我们的查询中获取`facetset`组件：

```php
$facetset = $query->getFacetSet();
```

创建一个 facet 查询，以计算特定流派的书籍数量。还要排除我们之前添加的过滤查询。

```php
$facetqry = $facetset->createFacetQuery('genreFantasy');
$facetqry->setQuery('genre_s: fantasy');
$facetqry->addExclude('inStockTag');
```

让我们添加另一个 facet 查询，其中不排除过滤查询：

```php
$facetqry = $facetset->createFacetQuery('genreFiction');
$facetqry->setQuery('genre_s: fiction');
```

执行查询后，我们可以从结果集中获取计数。

```php
$fantasyCnt = $resultSet->getFacetSet()->getFacet('genreFantasy')->getValue();
$fictionCnt = $resultSet->getFacetSet()->getFacet('genreFiction')->getValue();
```

在这里，`fantasy` facet 的计数包含了不在库存中的书籍，因为我们已经排除了获取库存中的书籍的过滤查询。而`fiction` facet 只包含库存中的书籍，因为在这个 facet 查询中没有排除过滤查询。

```php
1973307 [http-bio-8080-exec-9] INFO  org.apache.solr.core.SolrCore  – [collection1] webapp=/solr path=/select params={omitHeader=true&facet=true&fl=id,name,price,author,score,last_modified&**facet.query={!key%3DgenreFantasy+ex%3DinStockTag}genre_s:+fantasy&facet.query={!key%3DgenreFiction}genre_s:+fiction**&start=0&q=cat:book&wt=json&fq={!tag%3DinStockTag}inStock:true&rows=25} hits=24 status=0 QTime=2 
```

从 Solr 日志中，我们可以看到传递用于使用查询创建 facet 的参数是`facet.query`。

![按查询 facet](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/solr-php-intg/img/4920_04_03.jpg)

流派幻想和小说的查询计数

我们可以创建多个 facet 查询来获取不同查询 facet 的计数。但使用 Solarium 提供的**facet multiquery**功能更容易。让我们看看使用 facet multiquery 功能获取`genre`为`fantasy`和`fiction`的 facet 计数的代码：

```php
$facetmqry = $facetset->createFacetMultiQuery('genre');
$facetmqry->createQuery('genre_fantasy','genre_s: fantasy');
$facetmqry->createQuery('genre_fiction','genre_s: fiction');
```

以下是在执行主查询后获取所有 facet 查询的 facet 计数的代码。

```php
$facetCnts = $resultSet->getFacetSet()->getFacet('genre');
foreach($facetCnts as $fct => $cnt){
  echo $fct.': ['.$cnt.']'."<br/>".PHP_EOL;
}
```

使用`facetMultiQuery`和`facetQuery`创建的 Solr 查询是相同的。

# 按范围分面

分面也可以基于范围进行。例如，我们可以为每两美元的书籍创建 facet 计数。使用范围分面，我们可以给出价格在 0-2 美元之间的书籍的计数，以及 2-4 美元之间的书籍的计数，依此类推。

```php
$facetqry = $facetset->createFacetRange('pricerange');
$facetqry->setField('price');
$facetqry->setStart(0);
$facetqry->setGap(2);
$facetqry->setEnd(16);
```

在上述代码中，我们从价格`0`美元开始进行分面，直到`16`美元。在执行查询后，将使用以下代码显示范围 facet 及其计数：

```php
$facetCnts = $resultSet->getFacetSet()->getFacet('pricerange');
foreach($facetCnts as $range => $cnt){
  echo $range.' to '.($range+2).': ['.$cnt.']'."<br/>".PHP_EOL;
}
```

![按范围分面](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/solr-php-intg/img/4920_04_04.jpg)

按范围输出的分面

```php
5481523 [http-bio-8080-exec-4] INFO  org.apache.solr.core.SolrCore  – [collection1] webapp=/solr path=/select params={facet=true&f.price.facet.range.gap=2&**facet.range={!key%3Dpricerange+ex%3DinStockTag}price**&wt=json&rows=5&omitHeader=true&f.price.facet.range.other=all&fl=id,name,price,author,score,last_modified&start=0&q=cat:book&f.price.facet.range.end=16&fq={!tag%3DinStockTag}inStock:true&f.price.facet.range.start=0} hits=24 status=0 QTime=29
```

在这种情况下 Solr 查询中使用的参数是`facet.range`。可以同时提供多个 facet 参数。例如，我们可以在单个查询中进行按查询分面和按范围分面。

# 按枢轴分面

除了创建 facet 的不同方式之外，Solr 还提供了**按枢轴分面**的概念，并通过 Solarium 公开。枢轴分面允许我们在父 facet 的结果中创建 facet。枢轴分面的输入是一组要进行枢轴的字段。多个字段在响应中创建多个部分。

以下是在`genre`和`availability`（有库存）上创建 facet 枢轴的代码：

```php
$facetqry = $facetset->createFacetPivot('genre-instock');
$facetqry->addFields('genre_s,inStock');
```

要显示枢轴，我们必须从结果集中获取所有的 facet。

```php
$facetResult = $resultSet->getFacetSet()->getFacet('genre-instock');
```

对于每个 facet，获取 facet 的字段、值和计数，以及 facet 内的更多 facet 枢轴。

```php
  echo 'Field: '.$pivot->getField().PHP_EOL;
  echo 'Value: '.$pivot->getValue().PHP_EOL;
  echo 'Count: '.$pivot->getCount().PHP_EOL;
```

还要获取此 facet 内的所有枢轴，并在需要时以相同的方式进行递归调用处理。

```php
  $pivot->getPivot();
```

这个功能在创建数据的完整分类方面非常有帮助，可以在不同级别上进行 facet。从 Solr 查询日志中可以看到，这里使用的参数是`facet.pivot`。

```php
6893766 [http-bio-8080-exec-10] INFO  org.apache.solr.core.SolrCore  – [collection1] webapp=/solr path=/select params={omitHeader=true&facet=true&fl=id,name,price,author,score,last_modified&start=0&q=cat:book&facet.pivot.mincount=0&wt=json&**facet.pivot=genre_s,inStock**&rows=5} hits=30 status=0 QTime=9
```

在 Solr 界面上执行相同的查询时，我们得到以下输出。

```php
http://localhost:8080/solr/collection1/select/?facet=true&fl=id,name,price,author,score,last_modified&start=0&q=cat:book&facet.pivot.mincount=0&facet.pivot=genre_s,inStock&rows=5
```

![按枢轴分面](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/solr-php-intg/img/4920_04_02.jpg)

第一级分类发生在 genre 字段上。在 genre 内部，第二级分类发生在 inStock 字段上。

# 总结

在本章中，我们看到了 Solr 的高级查询功能。我们定义了过滤查询，并看到了使用过滤查询而不是普通查询的好处。我们看到了如何使用 PHP 和 Solarium 在 Solr 上进行分面处理。我们看到了不同的分面结果的方式，如按字段分面、按查询分面、按范围分面以及创建分面枢轴。我们还看到了在 Solr 上执行的实际查询，并在某些情况下执行了 Solr 上的查询并查看了结果。

在下一章中，我们将探讨使用 PHP 和 Solr 对搜索结果进行高亮显示。


# 第五章：使用 PHP 和 Solr 突出显示结果

Solr 提供的高级功能之一是在搜索返回的结果中突出显示匹配的关键字。除了突出显示的匹配项之外，还可以指定我们希望 Solr 每个字段返回的突出显示片段的数量。在本章中，我们将使用 PHP 和 Solarium 库探索 Solr 的所有突出显示功能。我们将涵盖的主题包括：

+   Solr 突出显示配置

+   使用 PHP 和 Solarium 在 Solr 中进行突出显示

+   为不同字段使用不同的突出显示标记

+   使用快速向量突出显示器进行突出显示

### 注意

需要在 Solr 中存储需要进行突出显示的字段。

# Solr 高亮配置

Solr 有两种类型的突出显示器——**常规突出显示器**和**快速向量突出显示器**。常规突出显示器适用于大多数查询类型，但不适用于大型文档。另一方面，快速向量突出显示器非常适用于大型文档，但支持的查询类型较少。尽管我个人还没有遇到快速向量突出显示器无法工作的情况。

### 注意

快速向量突出显示器需要设置`termVectors`，`termPositions`和`termOffsets`才能工作。

让我们看一下用于突出显示的 Solr 配置。打开`<solr_directory>/example/solr/collection1/conf/solrconfig.xml`中的 Solr 配置。搜索具有属性`class="solr.HighlightComponent"`和`name="highlight"`的 XML 元素`searchComponent`。我们可以看到文件中定义了多个**fragmenters**，一个 HTML **formatter**和一个 HTML **encoder**。我们还在文件中定义了多个`fragmentsBuilders`，多个`fragListBuilders`和多个`boundaryScanners`，如下列表所述：

+   **Fragmenter:** 它是用于突出显示文本的文本片段生成器。默认的片段生成器是由`default="true"`标记的间隙。

+   **格式化程序**：用于格式化输出，并指定要用于突出显示输出的 HTML 标记。标记是可定制的，并且可以在 URL 中传递。

+   **fragListBuilder:** 仅与`FastVectorHighlighter`一起使用。用于定义由`FastVectorHighlighter`创建的片段的大小（以字符为单位）。默认的`fragListBuilder`是`single`，可以用来指示应使用整个字段而不进行任何分段。

+   **fragmentsBuilder**：与`FastVectorHighlighter`一起使用，用于指定用于突出显示的标记。可以通过使用`hl.tag.pre`和`hl.tag.post`参数进行覆盖。

+   **boundaryScanner**：仅为`FastVectorHighlighter`定义边界如何确定。默认的`boundaryScanner`将边界字符定义为`.,!?\t\n`和空格。

### 注意

可以从以下 URL 获取有关突出显示参数的更多详细信息：[`cwiki.apache.org/confluence/display/solr/Standard+Highlighter`](https://cwiki.apache.org/confluence/display/solr/Standard+Highlighter)

# 使用 PHP 和 Solarium 在 Solr 中进行突出显示

让我们尝试使用 PHP 进行常规突出显示。在我们的索引中搜索`harry`，并突出显示两个字段——`name`和`series_t`，如以下代码所示：

```php
  $query->setQuery('harry');
  $query->setFields(array('id','name','author','series_t','score','last_modified'));
```

首先从以下查询中获取突出显示组件：

```php
  $hl = $query->getHighlighting();
```

使用以下查询设置我们想要突出显示的字段：

```php
  $hl->setFields('name,series_t');
```

使用以下查询将突出显示的 HTML 标记设置为粗体：

```php
  $hl->setSimplePrefix('<strong>');
  $hl->setSimplePostfix('</strong>');
```

设置要为每个字段生成的突出显示片段的最大数量。在这种情况下，可以生成从 0 到 2 个突出显示片段，如以下查询所示：

```php
  $hl->setSnippets(2);
```

设置要考虑进行突出显示的片段的字符大小。0 使用整个字段值而不进行任何分段，如以下查询所示：

```php
  $hl->setFragSize(0);
```

将`mergeContiguous`标志设置为将连续的片段合并为单个片段，如以下代码所示：

```php
  $hl->setMergeContiguous(true);
```

将`highlightMultiTerm`标志设置为启用范围、通配符、模糊和前缀查询的高亮显示，如下面的查询所示：

```php
  $hl->setHighlightMultiTerm(true);
```

一旦查询运行并接收到结果集，我们将需要从结果集中检索高亮显示的结果，使用以下查询：

```php
  $hlresults = $resultSet->getHighlighting();
```

对于结果集中的每个文档，我们将需要从高亮结果集中获取高亮文档。我们将需要在`getResult()`函数中传递唯一 ID 作为标识符，以获取高亮文档，如下面的代码所示：

```php
foreach($resultSet as $doc)
{
  $hldoc = $hlresults->getResult($doc->id);
  $hlname = implode(',',$hldoc->getField('name'));
  $hlseries = implode(',',$hldoc->getField('series_t'));
}
```

这里为每个文档的高亮字段，我们使用`getField()`方法获取，返回为一个数组。这就是为什么我们必须在显示之前将其 implode。我们可以看到在输出中，字段使用加粗的`<strong>`和`</strong>`标记进行高亮显示。

在 Solr 日志中，我们可以看到我们在 PHP 代码中指定的所有参数，如下所示：

```php
  336647163 [http-bio-8080-exec-1] INFO  org.apache.solr.core.SolrCore  – [collection1] webapp=/solr path=/select params={**hl.fragsize=0&hl.mergeContiguous=true&hl.simple.pre=**    **<strong>&hl.fl=name,series_t**&wt=json&**hl=true**    &rows=25&**hl.highlightMultiTerm=true**&omitHeader=true&fl=id,name,author,series_t,score,last_modified&**hl.snippets=2**&start=0&q=harry&**hl.simple.post=</strong>**} hits=7 status=0 QTime=203
```

传递给启用高亮的参数是`hl=true`，要高亮显示的字段指定为`hl.fl=name,series_t`。

# 为不同字段使用不同的高亮标记

我们可以为不同的字段使用不同的高亮标记。让我们使用`bold`标记为`name`添加高亮显示，使用`italics`标记为`series`添加高亮显示。在我们的代码中设置`per`字段标记，如下所示：

```php
  $hl->getField('name')->setSimplePrefix('<strong>')->setSimplePostfix('</strong>');
  $hl->getField('series_t')->setSimplePrefix('<em>')->setSimplePostfix('</em>');
```

输出显示，字段`name`被加粗标记，而字段`series`被斜体标记，如下面的截图所示：

![为不同字段使用不同的高亮标记](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/solr-php-intg/img/4920_05_01.jpg)

使用不同的标记高亮显示不同的字段。

我们还可以使用`setQuery()`函数为高亮结果设置单独的查询，而不是正常的查询。在之前的程序中，让我们将高亮显示更改为在搜索`harry`时发生在`harry potter`上，如下面的代码所示：

```php
  $hl->setQuery('harry potter');
```

在检查 Solr 日志时，可以看到用于高亮显示的查询作为`hl.q`参数传递给 Solr，如下面的代码所示：

```php
  344378867 [http-bio-8080-exec-9] INFO  org.apache.solr.core.SolrCore  – [collection1] webapp=/solr path=/select params={f.series_t.hl.simple.pre=<i>&f.name.hl.simple.post=</b>&f.name.hl.simple.pre=<b>&hl.fl=name,series_t&wt=json&hl=true&rows=25&omitHeader=true&hl.highlightMultiTerm=true&fl=id,name,author,series_t,score,last_modified&f.series_t.hl.simple.post=</i>&hl.snippets=2&start=0&q=harry&**hl.q=harry+potter**} hits=7 status=0 QTime=27
```

# 使用快速向量高亮显示

让我们更改`schema.xml`，并为两个字段`name`和`*_t`启用**termVectors**、**termPositions**和**termOffsets**（这将匹配所有以`_t`结尾的字段-`series_t`）。

```php
  <field name="name" type="text_general" indexed="true" stored="true" termVectors="true" termPositions="true" termOffsets="true"/>
  <dynamicField name="*_t"  type="text_general" indexed="true"  stored="true" termVectors="true" termPositions="true" termOffsets="true"/>
```

重新启动 Tomcat。根据您的系统（Windows 或 Linux）和安装类型，重新启动 Tomcat 的机制将有所不同。请查看 Tomcat 文档以了解如何重新启动 Tomcat。

由于模式现在已更改，我们需要重新索引我们在第二章中索引的所有文档，*从 Solr 插入、更新和删除文档*。还要索引本章的`books.csv`文件。在代码中，启用快速高亮显示，并设置用于高亮显示的`fragmentsBuilder`（HTML 标记），如下面的查询所示：

```php
  $hl->setUseFastVectorHighlighter(true);
  $hl->setFragmentsBuilder('colored');
```

在输出中，我们可以看到`harry`被高亮显示。要更改默认的高亮显示，我们需要在`solrconfig.xml`文件中添加一个新的**fragmentsBuilder**。浏览`solrconfig.xml`文件，并搜索带有名称 colored 的`fragmentsBuilder`标记。这有两个属性——`hl.tag.pre`和`hl.tag.post`。我们可以在这里为快速向量高亮显示指定前置和后置标记。在它之后创建一个名为`fasthl`的新`fragmentsbuilder`，如下面的代码所示：

```php
  <fragmentsBuilder name="fasthl" class="solr.highlight.ScoreOrderFragmentsBuilder">
  <lst name="defaults">
  <str name="hl.tag.pre"><![CDATA[<b style="background:cyan">]]></str>
  <str name="hl.tag.post"><![CDATA[</b>]]></str>
  </lst>
  </fragmentsBuilder>
```

重新启动 Tomcat，并更改 PHP 代码以使用这个新的`fragmentbuilder`进行高亮显示，如下面的查询所示：

```php
  $hl->setFragmentsBuilder('fasthl');
```

现在输出将包含以浅蓝色高亮显示的`harry`。

还可以使用`setTagPrefix()`和`setTagPostfix()`函数在运行时更改高亮显示标记。在下面的代码中，我们正在将快速向量高亮显示的标记更改为石灰色：

```php
  $hl->setTagPrefix('<b style="background:lime">')->setTagPostfix('</b>');
```

配置文件用于设置默认的高亮显示标记。标记可以通过 PHP 函数调用在运行时进行更改，以进行格式化。

以下是 Solarium 中的一些其他可用函数，可根据您的要求进行突出显示：

+   `setUsePhraseHighlighter(boolean $use)`: 设置为`true`，只有当短语项出现在文档的查询短语中时才进行突出显示。默认值为`true`。

+   `setRequireFieldMatch(boolean $require)`: 设置为`true`，只有在此特定字段中查询匹配时才突出显示字段。默认情况下，这是 false，因此无论哪个字段匹配查询，都会在所有请求的字段中突出显示项。需要`setUsePhraseHighlighter(true)`。

+   `setRegexPattern(string $pattern)`: 仅在常规突出显示器中使用。用于设置片段的正则表达式。

+   `setAlternateField(string $field)`: 如果没有匹配的项，也无法生成摘要，我们可以设置一个备用字段来生成摘要。

+   `setMaxAlternateFieldLength(int $length)`: 仅当设置了备用字段时使用。它指定要返回的备用字段的最大字符数。默认值为“无限制”。

# 摘要

我们看到了如何使用 PHP 代码向 Solr 请求突出显示的搜索结果。我们看到了常规和快速向量突出显示器。我们看到了用于更改常规和快速向量突出显示器的突出显示标记的函数和参数。我们还通过一些函数和 Solr 配置和模式更改来调整突出显示和生成的摘要。

在下一章中，我们将深入探讨评分机制。我们将探索调试和统计组件，这将使我们能够改进相关性排名并从索引中获取统计信息。


# 第六章：调试和统计组件

调试和统计是 Solarium 中用于获取有关索引统计信息以及查询执行和结果返回方式的两个组件。在本章中，我们将探讨这两个组件，并深入介绍如何使用 stats 组件检索索引统计信息。我们还将看看 Solr 如何计算相关性分数，以及如何使用 PHP 获取和显示 Solr 返回的查询解释。我们将探讨：

+   Solr 如何进行相关性排名

+   通过 PHP 代码执行调试

+   在 Solr 界面上运行调试

+   显示调试查询的输出

+   使用 stats 组件显示查询结果统计信息

你可能会问为什么我要深入研究这些组件的理论？这会帮助我实现什么？使用调试组件的好处在于理解和分析搜索结果的排名方式。为什么某个文档排在前面，另一个文档排在最后？此外，如果您想要修改排名以适应您希望结果显示的方式，您必须提升某些字段，并再次调试和分析应用提升后查询的执行情况。简而言之，调试组件帮助我们分析和修改排名以满足我们的需求。统计组件主要用于显示索引统计信息，这可以用来展示正在处理的索引的复杂性。

# Solr 相关性排名

当查询传递给 Solr 时，它会转换为适当的查询字符串，然后由 Solr 执行。对于结果中的每个文档，Solr 根据文档的相关性得分进行排序。默认情况下，得分较高的文档在结果中优先考虑。

Solr 相关性算法被称为**tf-idf 模型**，其中**tf**代表**术语频率**，**idf**代表**逆文档频率**。解释调试查询输出所使用的相关性计算参数的含义如下：

+   **tf**：术语频率是术语在文档中出现的频率。更高的术语频率会导致更高的文档得分。

+   **idf**：逆文档频率是术语出现在的文档数量的倒数。它表示索引中所有文档中术语的稀有程度。具有稀有术语的文档得分较高。

+   **coord**：这是协调因子，表示文档中找到了多少查询术语。具有更多查询术语的文档将得到更高的分数。

+   **queryNorm**：这是一个用于使跨查询的得分可比较的归一化因子。由于所有文档都乘以相同的 queryNorm，它不会影响文档排名。

+   **fieldNorm**：字段规范化惩罚具有大量术语的字段。如果一个字段包含的术语比其他字段多，那么它的得分就低于其他字段。

我们之前已经看到了查询时间提升。调试查询的目的是查看如何计算相关性，并利用我们对查询时间提升的了解来根据我们的需求调整输出。

# 通过 PHP 代码执行调试

要使用 PHP 启用对 Solr 查询的调试，我们需要从我们的查询中获取调试组件。

除了获取默认查询的调试信息外，我们还可以调用`explainOther()`函数来获取与主查询相关的指定查询的某些文档的分数，如下面的查询所示：

```php
  $query->setQuery('cat:book OR author:martin²');
  $debugq = $query->getDebug();
  $debugq->setExplainOther('author:king');
```

在上面的代码片段中，我们正在搜索所有的书籍，并通过`2`来提升作者`martin`的书籍。除此之外，我们还获取了作者`king`的书籍的调试信息。

运行查询后，我们需要从`ResultSet`中获取调试组件。然后我们使用它来获取查询字符串、解析的查询字符串、查询解析器以及调试其他查询的信息，如下面的代码所示：

```php
  echo 'Querystring: ' . $dResultSet->getQueryString() . '<br/>';
  echo 'Parsed query: ' . $dResultSet->getParsedQuery() . '<br/>';
  echo 'Query parser: ' . $dResultSet->getQueryParser() . '<br/>';
  echo 'Other query: ' . $dResultSet->getOtherQuery() . '<br/>';
```

我们需要遍历调试结果集，对于每个文档，我们需要获取总得分值，匹配和得分计算描述。我们还可以深入了解调试信息，并获取查询中每个术语相对于文档的值，匹配和计算描述，如下面的代码所示：

```php
  foreach ($dResultSet->getExplain() as $key => $explanation) {
  echo '<h3>Document key: ' . $key . '</h3>';
  echo 'Value: ' . $explanation->getValue() . '<br/>';
  echo 'Match: ' . (($explanation->getMatch() == true) ? 'true' : 'false')  . '<br/>';
  echo 'Description: ' . $explanation->getDescription() . '<br/>';
  echo '<h4>Details</h4>';
  foreach ($explanation as $detail) {
  echo 'Value: ' . $detail->getValue() . '<br/>';
  echo 'Match: ' . (($detail->getMatch() == true) ? 'true' : 'false')  . '<br/>';
  echo 'Description: ' . $detail->getDescription() . '<br/>';
  echo '<hr/>';
}
}
```

要获取其他查询的调试信息，我们需要调用`getExplainOther()`函数并按照上述相同的过程进行。除了得分信息之外，我们还可以获得每个查询执行阶段所花费的时间。可以使用以下`getTiming()`函数来获得。

```php
  echo 'Total time: ' . $dResultSet->getTiming()->getTime() . '<br/>';
```

要获取查询的每个阶段花费的时间，我们需要遍历`getPhases()`函数的输出并获取与阶段名称相关的数据。

```php
  foreach ($dResultSet->getTiming()->getPhases() as $phaseName => $phaseData) {
  echo '<h4>' . $phaseName . '</h4>';
  foreach ($phaseData as $subType => $time) {
  echo $subType . ': ' . $time . '<br/>';
}
}
```

# 在 Solr 界面上运行调试

我们示例中附加到 Solr 查询 URL 的参数是`debugQuery=true`，`explainOther=author:king`和`debug.explain.structured=true`。让我们通过访问 URL`http://localhost:8080/solr/collection1/select/?omitHeader=true&debugQuery=true&fl=id,name,author,series_t,score,price&start=0&q=cat:book+OR+author:martin²&rows=5`来检查调试查询的 Solr 输出

以下是上一个查询的输出截图：

![在 Solr 界面上运行调试](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/solr-php-intg/img/4920_06_01.jpg)

我们可以在 Solr 查询结果界面中的结果组件之后看到调试组件。它包含原始查询和解析查询。调试组件中的解释元素包含得分和为实现得分而进行的计算

由于调试 Solr 查询需要调整相关性，因此更有意义的是使用 Solr 界面查看调试输出。可以使用 PHP 接口来创建交互式用户界面，其中字段级别的增强来自用户并用于计算和显示相关性。这样的界面可以用于查看增强如何影响相关性得分并调整相同。

# 统计组件

统计组件可用于返回 Solr 查询返回的文档集中索引的数值字段的简单统计信息。让我们获取索引中所有书的价格的统计信息。我们还将在`price`和可用性(`inStock`)上进行 facet，并查看输出。

### 提示

建议使用模板引擎而不是在 PHP 中编写 HTML 代码。

创建查询以获取所有书籍，并将行数设置为`0`，因为我们对结果不感兴趣，只对统计信息感兴趣，这将作为单独的组件获取，如下面的查询所示：

```php
  $query->setQuery('cat:book');
  $query->setRows(0);
```

获取统计组件并为字段`price`创建统计信息，并在`price`和`inStock`字段上创建 facet。

```php
  $statsq = $query->getStats();
  $statsq->createField('price')->addFacet('price')->addFacet('inStock');
```

执行查询并从结果集中获取统计组件，如下面的查询所示：

```php
  $resultset = $client->select($query);
  $statsResult = $resultset->getStats();
```

循环遍历我们之前在统计组件中获取的字段。获取每个字段的所有统计信息，如下面的代码所示：

```php
  foreach($statsResult as $field) {
  echo '<b>Statistics for '.$field->getName().'</b><br/>';
  echo 'Min: ' . $field->getMin() . '<br/>';
  echo 'Max: ' . $field->getMax() . '<br/>';
  echo 'Sum: ' . $field->getSum() . '<br/>';
  echo 'Count: ' . $field->getCount() . '<br/>';
  echo 'Missing: ' . $field->getMissing() . '<br/>';
  echo 'SumOfSquares: ' . $field->getSumOfSquares() . '<br/>';
  echo 'Mean: ' . $field->getMean() . '<br/>';
  echo 'Stddev: ' . $field->getStddev() . '<br/>';
```

获取统计结果集中每个字段的 facet，并获取 facet 结果中每个元素的统计信息，如下面的代码所示：

```php
  foreach ($field->getFacets() as $fld => $fct) {
  echo '<hr/><b>Facet for '.$fld.'</b><br/>';
  foreach ($fct as $fctStats) {
  echo '<b>' . $fld . ' = ' . $fctStats->getValue() . '</b><br/>';
  echo 'Min: ' . $fctStats->getMin() . '<br/>';
  echo 'Max: ' . $fctStats->getMax() . '<br/>';
  echo 'Sum: ' . $fctStats->getSum() . '<br/>';
  echo 'Count: ' . $fctStats->getCount() . '<br/>';
  echo 'Missing: ' . $fctStats->getMissing() . '<br/>';
  echo 'SumOfSquares: ' . $fctStats->getSumOfSquares() . '<br/>';
  echo 'Mean: ' . $fctStats->getMean() . '<br/>';
  echo 'Stddev: ' . $fctStats->getStddev() . '<br/><br/>';
}
}
```

我们脚本的输出如下截图所示：

![统计组件](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/solr-php-intg/img/4920_06_02.jpg)

在检查 Solr 日志时，我们可以看到执行的查询如下：

```php
4105213 [http-bio-8080-exec-2] INFO  org.apache.solr.core.SolrCore  – [collection1] webapp=/solr path=/select params={omitHeader=true&fl=*,score&start=0&**stats.field=price&stats=true**&q=cat:book&**f.price.stats.facet=price&f.price.stats.**
**facet=inStock**&wt=json&rows=0} hits=30 status=0 QTime=7
```

启用统计信息，我们必须传递`stats=true`以及`stats.field`和 faceting 参数。我们可以在 Solr 上使用以下 URL`http://localhost:8080/solr/collection1/select/?omitHeader=true&rows=0&stats.field=price&stats=true&q=cat:book&f.price.stats.facet=price&f.price.stats.facet=inStock`看到相同的统计输出，如下面的截图所示：

![统计组件](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/solr-php-intg/img/4920_06_03.jpg)

在上一张截图中，我们可以看到**价格**的统计数据以及**价格**和**库存**的统计分面。在我们完整的图书库存中，最低价格为**3.06**，最高价格为**30.5**。所有价格的总和为**246.76**，平均值为**8.225**。我们可以看到我们的分面输出中每个元素的类似信息。

# 摘要

本章让我们对我们的索引有了一些了解，以及结果如何排名。我们看到了用于计算相关性得分的参数，以及如何使用 PHP 从 Solr 中提取计算。我们讨论了调试查询的用途。我们看到了如何从我们的索引中提取数值字段的查询统计信息，并如何使用 PHP 显示这些信息。从这些模块中检索到的信息用于分析和改进 Solr 搜索结果。统计数据也可以用于报告目的。

在下一章中，我们将探讨如何使用 Solr 和 PHP 构建拼写建议。我们还将构建自动完成功能，以在搜索过程中建议查询选项。


# 第七章：Solr 中的拼写检查

拼写检查组件可用于根据我们在索引中拥有的数据提供拼写更正的建议。在本章中，我们将看到如何在我们的索引中启用拼写检查，并使用 PHP 获取和显示拼写更正。本章将涵盖以下主题：

+   拼写检查的 Solr 配置

+   Solr 中可用的拼写检查器实现

+   使用 PHP 运行拼写检查查询

+   显示建议和整理

+   构建自动完成功能

### 注意

拼写检查适用于索引词。如果我们的索引中有拼写错误，建议也可能拼写错误。

拼写检查可用于向用户提供拼写更正的建议，提供*您是不是想要*的功能。这类似于 Google 提供的**显示结果**功能。它可用于为自动完成用户输入文本提供一系列建议。PHP 也有一个类似的功能，称为**pspell**，但这个拼写检查是建立在我们在 Solr 中创建的索引之上的。这意味着它更加定制化，适用于索引中存在的文档类型，并且可以调整以获得更符合我们喜好的结果。

# 拼写检查的 Solr 配置

Solr 安装中附带的演示模式和配置已经配置了拼写检查。让我们看看它的设置：

1.  打开`<solr_dir>/example/solr/collection1/conf`中的`solrconfig.xml`。

1.  通过名称为`spellcheck`的`searchComponent`进行搜索。

1.  在`spellcheck`组件内部有多个拼写检查器。这是 Solr 附带的`default`拼写检查器：

```php
<lst name="spellchecker">
<str name="name">default</str>
<str name="field">text</str>
<str name="classname">solr.DirectSolrSpellChecker</str>
<float name="accuracy">0.5</float>
<int name="maxEdits">2</int>
<int name="minPrefix">1</int>
<int name="maxInspections">5</int>
<int name="minQueryLength">4</int>
<float name="maxQueryFrequency">0.01</float>
<float name="thresholdTokenFrequency">.01</float>
</lst>
```

1.  上面的代码块显示了拼写检查中使用的各种变量。让我们来看看拼写检查配置中的重要变量，并了解它们的含义：

+   `name`：此变量指定 Solr 拼写检查器的拼写检查配置的名称。在我们的配置中，名称是`default`。

+   `field`：此变量指定用于拼写检查的字段。我们使用文本字段来加载拼写检查的标记。

+   `classname`：此变量指定正在使用的 Solr 拼写检查器的实现。我们使用`DirectSolrSpellChecker`，它直接使用 Solr 索引，不需要我们构建或重建拼写检查索引。我们还将查看其他实现。

+   `accuracy`：此变量的范围为`0.0`到`1.0`，`1.0`表示最准确。Solr 拼写检查实现使用此准确度值来决定是否可以使用结果。

+   `maxQueryFrequency`：此变量指定查询术语必须出现在文档中的最大阈值，才能被视为建议。这里设置为`0.01`。较小的阈值对于较小的索引更好。

+   `thresholdTokenFrequency`：此变量指定术语必须出现在百分之一的文档中，才能被考虑为拼写建议。这可以防止低频率的术语被提供为建议。但是，如果您的文档基数很小，您可能需要进一步减少这个值以获得拼写建议。

# Solr 中可用的拼写检查器实现

让我们来看看 Solr 提供的不同拼写检查器实现：

+   `DirectSolrSpellChecker`：此实现不需要为拼写检查构建单独的索引。它使用主 Solr 索引进行拼写建议。

+   `IndexBasedSpellChecker`：此实现用于创建和维护基于 Solr 索引的拼写词典。由于需要创建和维护一个单独的索引，我们需要在主索引发生变化时构建/重建索引。这可以通过在配置中启用`buildOnCommit`或`buildOnOptimize`来自动完成。此外，我们需要使用我们的 Solr 拼写检查组件配置中的`spellcheckIndexDir`变量来指定要创建的索引的位置。

### 注意

`buildOnCommit`组件非常昂贵。建议使用`buildOnOptimize`或在 Solr URL 中使用`spellcheck.build=true`进行显式构建。

+   基于文件的拼写检查器：此实现使用一个平面文件在 Solr 中构建拼写检查索引。由于没有可用的频率信息，使用此组件创建的索引不能用于提取基于频率的信息，例如阈值或最受欢迎的建议。文件的格式是每行一个单词，例如：

```php
Java
PHP
MySQL
Solr
```

索引需要使用`spellcheck.build=true`参数在我们的 Solr URL 中构建。除了`spellcheckIndexDir`位置来构建和存储索引外，`FileBasedSpellChecker`组件还需要`sourceLocation`变量来指定拼写文件的位置。

+   `WordBreakSolrSpellChecker`：此拼写检查组件通过组合相邻单词或将单词分解为多个部分来生成建议。它可以与前面的拼写检查器之一一起配置。在这种情况下，结果将被合并，整理可能包含来自两个拼写检查器的结果。

拼写检查器通常会提供通过字符串距离计算的分数排序的建议，然后按照索引中建议的频率进行排序。可以通过在配置文件中提供不同的距离计算实现使用`distanceMeasure`变量或通过提供不同的单词频率实现使用`comparatorClass`变量来调整这些参数。一些可用的`comparatorClass`实现是`score`（默认）和`freq`。类似地，`org.apache.lucene.search.spell.JaroWinklerDistance`是距离计算的实现，它在 Solr 中可用。

# 使用 PHP 运行拼写检查查询

让我们配置 Solr，使拼写检查发生在两个字段上，名称和作者：

1.  更改`schema.xml`文件的内容。创建一个新的字段，拼写检查将在该字段上进行，并使用以下代码将`name`和`author`字段复制到新字段中：

```php
<field name="spellfld" type="text_general" indexed="true" stored="false" multiValued="true"/>
<copyField source="name" dest="spellfld"/>
<copyField source="author" dest="spellfld"/>
```

1.  在`solrconfig.xml`中更改默认拼写检查器的拼写检查字段为我们刚刚创建的新字段。默认的拼写检查器使用 Solr 提供的拼写检查器`DirectSolrSpellChecker`实现。

```php
<lst name="spellchecker">
<str name="name">default</str>
<str name="field">spellfld</str>
```

1.  默认情况下，Solr 配置中的`/select`请求处理程序没有拼写检查设置和结果。因此，让我们在名为`/select`的`requestHandler`中添加这些变量。在这里，我们指定要使用的拼写检查词典为**default**，这是我们之前配置的，并将拼写检查组件添加为输出的一部分。

```php
<requestHandler name="/select" class="solr.SearchHandler">
<lst name="defaults">
.....  
<!-- spell check settings -->
<str name="spellcheck.dictionary">default</str>
<str name="spellcheck">on</str>
</lst>

<arr name="last-components">
<str>spellcheck</str>
</arr>
```

1.  现在重新启动 Solr，并在`exampledocs`文件夹中重新索引`books.csv`文件，以及在第五章中提供的`books.csv`文件，*使用 PHP 和 Solr 突出显示结果*。我们需要重新索引我们的书籍的原因是因为我们已经改变了我们的模式。每当模式更改并添加新字段时，需要重新索引文档以在新字段中填充数据。有关在 Solr 中索引这些 CSV 文件，请参阅第二章中的*向 Solr 索引添加示例文档*部分。

让我们使用 PHP 对作者*Stephen King*进行拼写检查，并查看 Solr 建议的更正：

1.  首先使用以下代码从选择查询中获取拼写检查组件：

```php
$spellChk = $query->getSpellcheck();
$spellChk->setCount(10);
$spellChk->setCollate(true);
$spellChk->setExtendedResults(true);
$spellChk->setCollateExtendedResults(true);
```

1.  我们已经通过`setCount()`函数设置了要返回的建议数量。通过将`setCollate()`设置为`true`，我们告诉 Solr 建议原始查询字符串，并用最佳建议替换原始拼写错误的单词。`setExtendedResults()`和`setCollateExtendedResults()`函数告诉 Solr 提供有关建议和返回的整理的附加信息。如果需要，可以用于分析。

1.  执行查询后，我们需要从查询结果集中获取拼写检查组件，并用它获取建议和整理。我们使用`getCorrectlySpelled()`函数来检查查询是否拼写正确。

```php
$resultset = $client->select($query);
$spellChkResult = $resultset->getSpellcheck();
if ($spellChkResult->getCorrectlySpelled()) {
echo 'yes';
}else{
echo 'no';
}
```

1.  接下来，我们循环遍历拼写检查结果，并针对查询中的每个术语获取建议和相关详细信息，例如建议的数量、原始术语的频率以及建议的单词及其出现频率。

```php
foreach($spellChkResult as $suggestion) {
echo 'NumFound: '.$suggestion->getNumFound().'<br/>';
echo 'OriginalFrequency: '.$suggestion->getOriginalFrequency().'<br/>';    
foreach ($suggestion->getWords() as $word) {
echo 'Frequency: '.$word['freq'].'<br/>';
echo 'Word: '.$word['word'].'<br/>';
}
}
```

1.  同样，我们获取整理并循环遍历它以获取更正后的查询和命中。我们还可以获取查询中每个术语的更正详细信息。

```php
$collations = $spellChkResult->getCollations();
echo '<h1>Collations</h1>';
foreach($collations as $collation) {
echo 'Query: '.$collation->getQuery().'<br/>';
echo 'Hits: '.$collation->getHits().'<br/>';
foreach($collation->getCorrections() as $input => $correction) {
echo $input . ' => ' . $correction .'<br/>';
}
}
```

# 使用 PHP 和 Solr 实现自动完成功能

可以通过在 Solr 中创建一个 Suggester 并使用 Solarium 中可用的 Suggester 来构建自动完成功能。自动完成的目的是根据不完整的用户输入建议查询术语。Suggester 的工作方式与拼写检查功能非常相似。它可以在主索引或任何其他字典上工作。

首先让我们更改`schema.xml`文件，添加一个名为`suggest`的拼写检查组件：

```php
<searchComponent name="suggest" class="solr.SpellCheckComponent">
<lst name="spellchecker">
<str name="name">suggest</str>
<str name="field">suggestfld</str>
<str name="classname">org.apache.solr.spelling.suggest.Suggester</str>
<str name="lookupImpl">org.apache.solr.spelling.suggest.tst.TSTLookup</str>
<str name="storeDir">suggest_idx</str>
<float name="threshold">0.005</float>
<str name="buildOnCommit">true</str>
</lst>
</searchComponent>
```

我们已经指定了用于建议的字段为`suggestfld`。用于构建 Suggester 的 Solr 组件在类名中被称为`org.apache.solr.spelling.suggest.Suggester`。阈值是一个介于 0 和 1 之间的值，指定了术语应出现在多少文档中才能添加到查找字典中的最小分数。我们将索引存储在`suggest_idx`文件夹中。`lookupImpl`组件提供了用于创建建议的`inmemory`查找实现。Solr 中可用的查找实现有：

+   `JaspellLookup`：这是基于 Jaspell 的基于树的表示。Jaspell 是一个创建拼写校正的复杂基于树的结构的 Java 拼写检查包。它使用一种称为`trie`的数据结构。

+   `TSTLookup`：这是一种简单而紧凑的三叉树表示，能够立即更新数据结构。它还使用`trie`数据结构。

+   `FSTLookup`：这是基于自动机的表示。它构建速度较慢，但在运行时消耗的内存要少得多。

+   `WFSTLookup`：这是加权自动机表示，是`FSTLookup`的另一种更精细的排名方法。

您可以更改查找实现并查看建议的变化。由于建议是基于索引的，因此索引越大，建议就越好。

让我们在 Solr 中为建议创建一个单独的请求处理程序，并将我们的建议拼写检查作为其中的一个组件添加进去。提供建议的默认配置选项已经合并在请求处理程序本身中。

```php
<requestHandler class="org.apache.solr.handler.component.SearchHandler" name="/suggest">
<lst name="defaults">
<str name="spellcheck">true</str>
<str name="spellcheck.dictionary">suggest</str>
<str name="spellcheck.onlyMorePopular">true</str>
<str name="spellcheck.count">5</str>
<str name="spellcheck.collate">true</str>
</lst>
<arr name="components">
<str>suggest</str>
</arr>
</requestHandler>
```

接下来，我们需要在我们的`schema.xml`中创建一个单独的字段，该字段被索引。我们将书名、作者和标题复制到该字段中，以便对它们进行建议。

```php
<field name="suggestfld" type="text_general" indexed="true" stored="false" multiValued="false"/>

<copyField source="name" dest="suggestfld"/>
<copyField source="author" dest="suggestfld"/>
<copyField source="title" dest="suggestfld"/>
```

完成后，重新启动 Apache Tomcat Web 服务器，并使用以下 URL 构建拼写检查索引：

```php
http://localhost:8080/solr/collection1/suggest/?spellcheck.build=true
```

### 注意

我们创建了一个名为 suggest 的单独请求处理程序，因此我们的 URL 为/`suggest`/而不是/`select`/。

现在让我们看看 Solarium 库提供的用于与 PHP 集成的 Suggester。首先，我们需要从 Solarium 客户端创建一个 Suggester 查询，而不是普通查询。

```php
$client = new Solarium\Client($config);
$suggestqry = $client->createSuggester();
```

接下来，我们必须设置要使用的请求处理程序。请记住，我们创建了一个名为**suggest**的单独请求处理程序来提供建议。还要设置我们要使用的字典。我们可以创建多个字典，并使用以下函数在运行时更改它们：

```php
$suggestqry->setHandler('suggest');
$suggestqry->setDictionary('suggest');
```

现在提供 Suggester 的查询。设置要返回的建议数量。打开`collation`标志和`onlyMorePopular`标志。

```php
$suggestqry->setQuery('ste');
$suggestqry->setCount(5);
$suggestqry->setCollate(true);
$suggestqry->setOnlyMorePopular(true);
```

使用`suggester()`函数执行查询，然后循环遍历结果集以获取所有术语及其建议。可以使用`getQuery()`函数显示原始查询。

```php
$resultset = $client->suggester($suggestqry);
echo "Query : ".$suggestqry->getQuery();
foreach ($resultset as $term => $termResult) {
    echo '<strong>' . $term . '</strong><br/>';
    echo 'Suggestions:<br/>';
    foreach($termResult as $result){
        echo '-> '.$result.'<br/>';
    }
}
```

最后，使用以下代码获取并显示整理：

```php
echo 'Collation: '.$resultset->getCollation();
```

这段代码可以用来创建一个 AJAX 调用，并提供 JSON 或 XML 字符串作为自动完成建议。

# 摘要

我们从理解 Solr 上的拼写检查是如何工作开始。我们通过配置 Solr 来创建拼写检查索引，并看到了 Solr 提供的不同拼写检查实现。我们了解了 Solr 中拼写检查的一些微调选项。接下来，我们在 Solr 中创建了一个用于对书名和作者进行拼写检查的字段，并配置 Solr 来使用这个字段提供拼写建议。我们看到了一种可以用于提供自动完成拼写建议的拼写检查变体。我们为自动完成建议创建了一个单独的 Solr 索引，并看到了一个 PHP 代码，它接受一个三个字符的单词，并从索引中提供建议。
