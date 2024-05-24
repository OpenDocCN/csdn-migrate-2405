# PHP 和 Netbeans 应用开发（一）

> 原文：[`zh.annas-archive.org/md5/3257ea46483c2860430cdda1bc8d9606`](https://zh.annas-archive.org/md5/3257ea46483c2860430cdda1bc8d9606)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

生产力是软件开发人员的重要因素。一个良好的开发环境或周围工具，携带着特定编程风格的精髓，可以提高我们的编码生产力，并产生质量和优化的软件产品。为了保持快节奏的开发，开发人员寻求一种让他们感到宾至如归的环境。这样的集成开发环境（IDE）确实可以加速代码实现，并成为项目开发的魔法棒。

一个好的 IDE 更像是一个精心设计的功能齐全的瑞士军刀。它包括：

+   源代码编辑器

+   编译器/解释器

+   调试器

+   数据库管理支持

+   版本控制系统

+   面向对象编程的工具，如类浏览器和对象检查器

IDE，如 NetBeans，具有更大的灵活性，开发人员可以在其中感到宾至如归。此外，NetBeans 是完全免费的，并由开源社区提供。简而言之，PHP 的 IDE 将在各个方面促进您从开发到生产的生产力。

在本书《使用 NetBeans 初学者指南进行 PHP 应用程序开发》中，您将学习如何通过 NetBeans IDE 完成一些真实的、时尚的 PHP 项目，从而成为一个自信的 PHP 开发人员，覆盖不同类别的基于 Web 的应用程序。

# 本书涵盖的内容

第一章，“设置您的开发环境”，指导您逐步完成 NetBeans 安装并设置 PHP 开发环境的过程。在本章结束时，您的开发环境将在您的操作系统上准备就绪。

第二章，“通过 PHP 编辑器提高编码效率”，展示了如何使用 NetBeans PHP 编辑器编写更快的代码。您将了解 IDE 的一些杀手功能，如代码完成、代码模板、重命名重构和代码生成。在本章结束时，您将对编辑器的智能功能和增加的编码生产力有全面的、实际的了解。

第三章，“使用 NetBeans 构建类似 Facebook 的状态发布器”，直接跳转到一个真实的 PHP 应用程序开发，用于显示类似 Facebook/Twitter 的发布状态流。在本章结束时，您将能够使用 NetBeans IDE 开发简单的 PHP 应用程序。

第四章，“使用 NetBeans 进行调试和测试”，将解释如何使用 IDE 调试和测试 PHP 应用程序。本章涵盖的主题包括配置 XDebug、调试 PHP 源代码、使用 PHPUnit 和 Selenium 进行测试，以及代码覆盖率。

第五章，“使用代码文档”，指导开发人员创建源代码和项目文档的过程。您将熟悉 PHPDoc 标准标签及其用法，以便在编辑器的帮助下对源代码进行文档化。此外，您将使用外部文档生成器生成项目 API。

第六章，“理解 Git，NetBeans 方式”，将向您展示如何使用 Git，这是一个免费的开源分布式版本控制系统。使用 IDE，您将进行 Git 操作，如初始化或克隆存储库，暂存文件，提交更改，恢复修改，以及远程存储库操作，如获取、拉取和推送，同时使用分支。在本章结束时，您将能够成为使用 NetBeans 协作开发功能的开发团队的一部分。

第七章*构建用户注册、登录和注销*，涉及专业的 PHP 应用程序。您将设计和开发一个 PHP 应用程序，用户可以在其中注册自己，注册后他们可以登录应用程序，查看和更新他们自己的个人资料等。

附录 A*在 NetBeans 7.2 中介绍 Symfony2 支持*，将发现 NetBeans 对 Symfony2 PHP 框架的支持。这介绍了 Symfony2 的项目创建，运行 Symfony2 命令，并介绍了从 NetBeans 创建 bundle。

附录 B*NetBeans 键盘快捷键*，是常见 NetBeans 键盘快捷键的便利参考。

# 您需要为本书做些什么

在第一章*设置您的开发环境*的*推荐系统要求*部分，解释了系统要求，以及以*设置您的开发环境*开头的部分解释了特定操作系统的 PHP 开发环境。总之，您应该有以下内容：

+   NetBeans IDE

+   最新的 Apache、MySQL 和 PHP 包

# 本书适合谁

本书面向希望在利用 NetBeans 功能简化软件开发工作并利用 IDE 的强大功能的同时开发 PHP 应用程序的初学者级别 PHP 开发人员。不假设熟悉 NetBeans。但是，预期对 PHP 开发有一些了解。

# 惯例

在本书中，您会经常看到几个标题。

为了清晰地说明如何完成一个过程或任务，我们使用：

# 行动时间 — 标题

1.  操作 1

1.  操作 2

1.  操作 3

指示通常需要一些额外的解释，以便理解，因此它们后面跟着：

## 刚刚发生了什么？

这个标题解释了您刚刚完成的任务或指示的工作原理。

您还会在本书中找到一些其他的学习辅助工具，包括：

## 弹出测验 — 标题

这些是旨在帮助您测试自己理解的简短的多项选择题。

## 尝试英雄 — 标题

这些设置实际挑战，并给您一些尝试所学内容的想法。

您还会发现一些区分不同类型信息的文本样式。以下是一些这些样式的示例，以及它们的含义解释。

文本中的代码词如下所示：“使用文件浏览器设置`安装`文件夹。”

代码块设置如下：

```php
<?php
echo "Hello World";
?>

```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体设置：

```php
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<title>Status updater</title> **<link href="<?=BASE_URL?>styles/styles.css" media="screen" rel="stylesheet" type="text/css" />
<script src="http://ajax.googleapis.com/ajax/ libs/jquery/1.7/jquery.min.js">**
</script>
<script src="<?=BASE_URL?>js/status.js"></script>
</head>

```

任何命令行输入或输出都以以下方式书写：

```php
**sudo apt-get install lamp-server^**

```

**新术语**和**重要单词**以粗体显示。您在屏幕上、菜单或对话框中看到的单词，例如，会在文本中以这样的方式出现：“点击**下一步**按钮，您将被要求接受许可协议。”

### 注意

警告或重要说明会以这样的方式出现在一个框中。

### 提示

提示和技巧会出现在这样的形式。


# 第一章：设置您的开发环境

> NetBeans 是一个免费开源的**集成开发环境**（**IDE**），符合多种编程语言。长期以来，它一直是主要开发者社区的首选编辑器。随着市场需求的增长，NetBeans 自 NetBeans 6.5（2008 年 11 月）以来已经集成了 PHP 开发功能，如今，它已成为 PHP 社区中最受欢迎的 IDE 之一。

在本章中，我们将讨论：

+   为什么选择 NetBeans 进行 PHP 应用程序开发？

+   下载 NetBeans IDE

+   逐步进行 NetBeans 安装

+   设置您的 PHP 开发环境

+   创建 NetBeans 项目

那么让我们开始吧…

# 为什么选择 NetBeans 进行 PHP 应用程序开发？

NetBeans IDE 通过以下方式促进我们日常的 PHP 应用程序开发活动：

+   **创建和管理项目：**PHP 的 IDE 使我们能够创建 PHP 项目，并帮助项目增长。它可以执行与项目相关的设置和操作；即创建项目文档，测试项目等。

+   **源代码的编辑功能：**代码编辑器在 PHP 项目范围内具有令人兴奋的源代码编辑功能集合。它通过以下功能加快了代码编写速度：

+   **语法高亮**使项目文件中的 PHP 语法突出显示。

+   **代码折叠**使当前文件中选择的类和方法代码可以折叠和展开。

+   **导航**帮助探索当前 PHP 文件中的类和方法。

+   **代码模板**帮助使用预定义的代码片段。

+   **代码完成**显示代码的自动完成列表。

+   **参数提示**提供有关方法的形式参数在方法被调用的地方的信息。

+   **智能缩进**在按代码时提供自动格式化。

+   **格式化**在当前文件中提供自动代码格式化。

+   **括号补全**在编写代码时添加/删除成对的引号、括号和大括号。

+   **标记出现**标记在打开的项目文件中代码字符串的所有出现。

+   **错误检测**在输入完成后立即显示 PHP 解析错误。

+   **配对匹配**突出显示匹配的引号、大括号、括号等。

+   **语义高亮**识别关键字、方法名、调用、未使用的变量等。

+   **转到声明**将光标发送到所选类型声明的位置。

+   **即时重命名**会重命名变量在其范围内的所有出现。

+   **拼写检查**显示拼写错误和更正。

+   **代码文档**帮助自动生成文档结构。

+   **部署项目：**在 PHP 项目内容内提供与远程服务器内容的同步。

+   **数据库和服务：**提供对数据库管理和 Web 服务的支持。

+   **SCM 工具：**提供源代码管理工具，如 Git、Subversion、CVS 和 Mercurial，内置用于源代码版本控制、跟踪更改等。

+   **运行 PHP 脚本：**使 PHP 脚本解析，并在不转到浏览器的情况下在 IDE 中产生输出。

+   **调试源代码：**您可以检查本地变量，设置监视，设置断点，并实时评估代码。您还可以执行命令行调试，并在不转到浏览器的情况下在 IDE 中检查 PHP 输出，这为远程调试提供了能力。

+   **支持 PHP 框架：**它还支持流行的 PHP 框架，如 Zend Framework 和 Symfony。

### 注意

可以在[`en.wikipedia.org/wiki/Comparison_of_integrated_development_environments#PHP`](http://en.wikipedia.org/wiki/Comparison_of_integrated_development_environments#PHP)找到用于 PHP 的集成开发环境的比较。

## 推荐的系统要求

在我们继续下载最新版本之前，让我们看一下各个平台安装和运行 NetBeans IDE 的推荐系统要求：

+   Microsoft Windows XP Professional SP3/Vista SP1/Windows 7 Professional：

+   处理器：2.6 GHz 英特尔奔腾 IV 或同等处理器

+   内存：2 GB

+   磁盘空间：1 GB 的可用磁盘空间

+   Ubuntu 12.04：

+   处理器：2.6 GHz 英特尔奔腾 IV 或同等处理器

+   内存：2 GB

+   磁盘空间：850 MB 的可用磁盘空间

+   Macintosh OS X 10.7 Intel：

+   处理器：双核英特尔（32 位或 64 位）

+   内存：2 GB

+   磁盘空间：850 MB 的可用磁盘空间

# 下载 NetBeans IDE

NetBeans 可以成为您日常开发的 IDE，有助于提高编码效率。它是一个免费的开源 IDE，可用于不同的技术，包括 Java、C/C++、PHP 等，以及 Windows、Linux、Mac OS X 或甚至独立于操作系统的捆绑包。此外，您可以仅为 PHP 技术下载 IDE，或者下载包含所有技术的安装程序包。

再次强调，如果您已经在使用 IDE 进行 Java、C/C++等开发，则可以跳过此下载和安装部分，直接转到名为“将 PHP 作为插件添加到已有的 NetBeans 安装”部分。

# 操作时间-下载 NetBeans IDE

按照以下步骤下载 NetBeans IDE：

1.  访问[`netbeans.org/downloads/`](http://netbeans.org/downloads/)以下载最新的 NetBeans 版本。下载页面将自动检测您的计算机操作系统，并允许您下载特定于操作系统的安装程序。

请注意，您可以稍后使用 IDE 的插件管理器添加或删除包或插件。此外，如果您想避免安装，您可以选择“OS-independent ZIP”。再次强调，NetBeans 是那些使用多种编程语言平台的程序员必备的 IDE。目前，NetBeans IDE 支持各种开发平台——J2SE、J2EE、J2ME、PHP、C/C++等等。

![操作时间-下载 NetBeans IDE](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_01_01.jpg)

接下来，我们将下载 PHP 捆绑，如上面的截图所示。

1.  点击“下载”按钮后，页面将被重定向到自动下载，同时显示直接下载链接，如下截图所示：![操作时间-下载 NetBeans IDE](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_01_02.jpg)

如您所见，您的下载将自动开始；Firefox 用户应该会看到一个保存文件的窗口，如下所示：

![操作时间-下载 NetBeans IDE](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_01_03.jpg)

1.  将文件保存到您的磁盘空间中。

## 刚刚发生了什么？

我们刚刚下载了 NetBeans PHP 捆绑安装文件。PHP 捆绑提供了用于 PHP 5.x 开发的工具，以及 Zend 和 Symfony 框架支持。如果您点击“全部”下载选项，您将获得所有提到的技术的安装文件，并且在安装过程中您将能够选择安装哪些工具和运行时。所以，现在我们准备启动安装向导。

# 安装 NetBeans

使用安装向导安装 NetBeans 非常简单，该向导将指导用户完成所需的步骤或配置。已经在使用 NetBeans 进行其他技术（如 Java 或 C/C++）开发的用户可以跳过此部分，直接转到名为“将 PHP 作为插件添加到已有的 NetBeans 安装”部分。

### 注意

PHP 和 C/C++的 NetBeans 捆绑只需要安装 Java Runtime Environment（JRE）6。但是，如果您计划使用任何 Java 功能，则需要安装 JDK 6 或 JDK 7。

# 操作时间-逐步安装 NetBeans

在本节中，我们将逐步安装 Windows 7 上的 NetBeans IDE。为了安装软件，您需要运行安装程序并按照以下步骤进行操作：

1.  运行或执行安装程序。第一步将类似于以下截图：![操作时间-逐步安装 NetBeans](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_01_04.jpg)

1.  点击**下一步**按钮，您将被要求接受许可协议：![操作时间-逐步安装 NetBeans](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_01_05.jpg)

1.  下一步将要求您为 NetBeans 和 JRE 选择安装位置，并提供一些默认的程序文件路径：![操作时间-逐步安装 NetBeans](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_01_06.jpg)

请注意，JRE 是您计算机的 Java 软件，或者 Java 运行环境，也被称为**Java 虚拟机（JVM）**。JRE 也将被安装。

1.  使用文件浏览器设置`安装`文件夹，并点击**下一步**按钮。下一个截图显示了总安装大小：![操作时间-逐步安装 NetBeans](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_01_07.jpg)

1.  如果一切都设置好了，点击**安装**按钮开始安装过程。![操作时间-逐步安装 NetBeans](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_01_08.jpg)

1.  安装正确后，您将看到完成向导，如下截图所示：![操作时间-逐步安装 NetBeans](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_01_09.jpg)

1.  您可以根据自己的意愿选择或取消**通过提供匿名使用数据为 NetBeans 项目做出贡献**复选框。请注意，它将向`netbeans.org`发送特定于项目的使用数据，因此在勾选之前请仔细阅读屏幕上的说明。点击**完成**按钮完成安装。现在，转到您的操作系统的**程序**菜单或安装 IDE 的目录以运行。IDE 将显示一个启动画面，如下所示：![操作时间-逐步安装 NetBeans](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_01_10.jpg)

1.  最后，运行的 IDE 看起来类似于以下截图：![操作时间-逐步安装 NetBeans](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_01_11.jpg)

## 刚刚发生了什么？

既然我们已经安装并运行了 IDE，我们可以继续探索在各种操作系统上设置开发环境。

在下一节中，我们将在各种操作系统上配置我们的 PHP 开发环境。我们将使用最新的 Apache-MySQL-PHP 软件包安装程序，即 LAMP、XAMPP 和 MAMP，对应于不同的操作系统。

### 将 PHP 作为插件添加到已有的 NetBeans 安装中

如果您想要为 NetBeans IDE 配置添加功能，请使用 NetBeans 插件管理器。例如，假设您已经在 NetBeans IDE 中运行了 Java 或 C/C++包。然后您决定尝试 PHP 功能。要做到这一点，从 IDE 中转到 NetBeans 插件管理器（选择**工具|插件**），并将 PHP 包添加到您已有的安装中。

### 多个安装支持

多个版本的 NetBeans IDE 5.x、6.x 和 7.x 可以与最新版本共存在同一系统上。您无需卸载早期版本即可安装或运行最新版本。

如果您之前安装过 NetBeans IDE，当您第一次运行最新的 IDE 时，您可以选择是否从现有用户目录导入用户设置。

## 尝试添加或删除 NetBeans 功能

因此，您的计算机上已经安装并运行了 NetBeans。现在，添加更多功能或删除不必要的功能，从已安装的 NetBeans 中检查新添加的功能。您可以尝试使用插件管理器来实现这一点。

# 在 Windows 中设置开发环境

我们将使用 XAMPP 软件包而不是单独安装和配置 Apache、MySQL 和 PHP，以便自动安装和配置所有这些。我们将下载并安装最新的 XAMPP 软件包（v. 1.7.7），其中包括以下内容：

+   Apache 2.2.21

+   MySQL 5.5.16

+   PHP 5.3.8

+   phpMyAdmin 3.4.5

+   FileZilla FTP 服务器 0.9.39

# 行动时间-在 Windows 安装 XAMPP

以下步骤将下载并安装 XAMPP 软件包：

1.  我们将从以下网址下载最新的 XAMPP 软件包安装程序：[`www.apachefriends.org/en/xampp-windows.html`](http://www.apachefriends.org/en/xampp-windows.html)。

1.  下载完成后，运行`.exe`文件以继续安装。更多安装细节可以在[`www.apachefriends.org/en/xampp-windows.html`](http://www.apachefriends.org/en/xampp-windows.html)找到。

1.  您将有选择安装 Apache 服务器和 MySQL 数据库服务器作为服务，因此您无需从 XAMPP 控制面板手动启动它们。同样，您将有选项稍后从 XAMPP 控制面板配置这些服务，如启动/停止、作为服务运行和卸载。

1.  成功完成安装过程后，您将能够继续进行后续步骤。从操作系统的**Start | Programs | XAMPP**中打开 XAMPP 控制面板。![行动时间-在 Windows 安装 XAMPP](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_01_12.jpg)

**Svc**复选框表示该模块已安装为 Windows 服务，因此将随 Windows 启动而启动，或者您可以将其选中以作为服务运行。如果您需要重新启动 Apache web 服务器，请使用 Apache **Status**旁边的**Stop/Start**按钮。

1.  现在，检查您的 XAMPP 安装。从您的 Web 浏览器访问 URL `http://localhost`；XAMPP 欢迎页面看起来类似于以下截图：![行动时间-在 Windows 安装 XAMPP](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_01_13.jpg)

1.  从左侧点击`phpinfo()`以检查您配置的 PHP 版本和已安装的组件：![行动时间-在 Windows 安装 XAMPP](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_01_14.jpg)

1.  单击**Welcome**菜单下的**Status**菜单，以检查已安装工具的状态；相应列旁边的激活绿色状态表示您已成功运行 Apache、MySQL 和 PHP：![行动时间-在 Windows 安装 XAMPP](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_01_15.jpg)

## 刚刚发生了什么？

我们已成功在系统上安装并运行了 XAMPP 软件包。我们有 XAMPP 控制面板来控制已安装的服务，我们还有一个 Web 界面来管理 MySQL 数据库。

## 尝试一下-保护您的 XAMPP 安装

XAMPP 不适用于生产环境，而仅适用于开发环境中的开发人员。XAMPP 被配置为尽可能开放，并允许 Web 开发人员获取他们想要的任何内容。对于开发环境来说，这很棒。但是，在生产环境中，这可能是致命的。因此，您需要在[`www.apachefriends.org/en/xampp-windows.html`](http://www.apachefriends.org/en/xampp-windows.html)的*A matter of security*部分的帮助下保护您的 XAMPP 安装。

### 注意

为了在开发环境中显示错误，更新加载的`php.ini`文件以设置`display_errors = On`，并为生产环境做相反的`display_errors = Off`。

# 在 Ubuntu 桌面上设置您的开发环境

**Linux，Apache，MySQL**和**PHP**（**LAMP**）是一些最常见的网络托管平台。因此，这是一个完美的环境，让您构建和测试您的网站代码。在本节中，我们将在我们的 Ubuntu 12.04 桌面上轻松设置、配置和运行我们自己的 LAMP。

# 行动时间-在 Ubuntu 桌面上安装 LAMP

按照这里列出的步骤安装 Ubuntu 中的 LAMP 软件包：

1.  与单独安装每个项目不同，我们将在 Ubuntu 中使用一个包安装 LAMP 服务器，这相当简单，只需一个终端命令：

```php
**sudo apt-get install lamp-server^** 

```

`apt-get`命令是一个强大的命令行工具，用于处理 Ubuntu 的**高级软件包工具（APT）**，执行诸如安装新软件包、升级现有软件包、更新软件包列表索引，甚至升级整个 Ubuntu 系统等功能。

### 注意

`sudo`用于调用当前用户以获得超级用户的权限，插入符号（^）放在包名后面，表示正在一起执行任务。

1.  这个命令将立即开始安装 LAMP 软件包，同时安装最新的 PHP5、Apache 2、MySQL 和 PHP5-MySQL 软件。默认情况下，Apache 2 和 MySQL 安装为服务，您的文档根目录将位于`/var/www/`，`index.html`文件将位于`/var/www/`。

1.  Apache 和 MySQL 都应该在运行。但是，如果需要，您可以使用`service start`命令启动 Apache，如下所示：

```php
**sudo service apache2 start** 

```

您可以使用以下命令停止 Apache：

```php
**sudo service apache2 stop** 

```

1.  现在，让我们检查 LAMP 安装。将浏览器指向`http://localhost/`，您将看到默认的 Apache 2 登录页面，如下图所示：![在 Ubuntu 桌面上安装 LAMP 的时间](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_01_16.jpg)

这意味着您的 Apache 2 Web 服务器正在运行。您仍然可以按以下方式检查这些服务状态：

```php
**sudo service apache2 status** 

```

上一个命令将给您以下输出：

```php
**Apache is running. Process #** 

```

1.  同样，要检查 MySQL 状态，只需运行以下命令：

```php
**sudo service mysql status** 

```

将显示以下输出：

```php
**mysql start/running. Process #** 

```

1.  要检查 PHP 安装，只需在`/var/www/`中创建一个名为`test.php`的文件，其中包含以下行：

```php
<?php phpinfo(); ?>

```

### 注意

您可以使用`touch test.php`命令从终端创建一个新文件，也可以使用 gedit 应用程序，然后编辑文件并保存。

1.  现在，将浏览器指向`http://localhost/test.php`，您将看到已安装的 PHP 和组件的配置详细信息：![在 Ubuntu 桌面上安装 LAMP 的时间](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_01_17.jpg)

*步骤 8*至*12*是可选的，因为我们在这些步骤中安装了`phpMyAdmin`。

1.  虽然我们可以使用 NetBeans 来维护我们的数据库，但我们仍然需要使用基于 Web 的界面来维护 MySQL 数据库功能。为此，我们可以使用`phpMyAdmin`。

```php
**sudo apt-get install phpmyadmin** 

```

使用此命令将安装`phpMyAdmin`，在安装过程中，您将收到一个蓝色窗口询问您要使用哪个服务器——`apache2`还是`lighttpd`。选择`apache2`，然后单击**OK**继续安装。请注意，在安装过程中，您可能会被要求配置`phpMyAdmin`以进行数据库配置、密码等。

1.  安装完成后，使用`http://localhost/phpmyadmin/`在浏览器中打开，您将能够查看一个`phpMyAdmin`登录页面，如下图所示：![在 Ubuntu 桌面上安装 LAMP 的时间](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_01_18.jpg)

1.  如果在`http://localhost/phpmyadmin/`收到`404`错误，则需要通过使用`gedit`（GNOME 桌面的官方文本编辑器）修改`/etc/apache2/apache2.conf`来手动设置`phpMyAdmin`在 Apache 下的配置：

```php
**sudo gedit /etc/apache2/apache2.conf** 

```

1.  `gedit`将以图形模式打开文件，并将以下行添加到`apache2.conf`的底部：

```php
**Include /etc/phpmyadmin/apache.conf** 

```

1.  现在，重新启动 Apache 服务器以使更改生效：

```php
**sudo service apache2 restart** 

```

刷新您的浏览器，您现在将看到与上一个屏幕截图中相同的`phpMyAdmin`登录界面。

## 刚刚发生了什么？

Ubuntu 桌面上的 PHP 开发环境已成功设置。使用单个终端命令安装 LAMP 服务器真的很简单。我们学会了如何停止或重新启动 Apache 和 MySQL 等服务，并检查它们的状态。

此外，我们还可选择安装`phpMyAdmin`以通过 Web 界面管理数据库。请注意，`phpMyAdmin`并不适用于生产环境，而只适用于开发环境中的开发人员。

## 尝试一下 — 显示错误

由于我们已经为开发环境进行了配置，PHP 错误消息对我们解决问题将非常有帮助。在您的 LAMP 安装中，默认情况下 PHP 错误消息是关闭的。您可以通过修改包含`display_errors`的行来启用从加载的`php.ini`文件（参见`phpinfo`）显示错误消息。请注意，对`php.ini`的任何更改都需要重新启动 Apache 2 服务器。

# 在 Mac OS X 中设置您的开发环境

由于我们对在一起设置 AMP 感兴趣，MAMP 包可能是 Mac OS X 的一个不错选择。

# 在 Mac OS X 中安装 MAMP 的时间

按照以下步骤在您的 Mac OS X 上下载和安装 MAMP：

1.  从[`www.mamp.info/en/`](http://www.mamp.info/en/)下载最新的 MAMP 版本；点击**MAMP 包下载器**下的**立即下载**按钮来下载 MAMP：![在 Mac OS X 中安装 MAMP 的时间](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_01_19.jpg)

1.  如前面的截图所示，在屏幕左侧选择 MAMP 下载。

1.  解压下载的文件，并运行`.dmg`文件。接受“使用条款”后，您将看到一个类似以下的屏幕：![在 Mac OS X 中安装 MAMP 的时间](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_01_20.jpg)

1.  将`MAMP`文件夹拖入`Applications`文件夹；MAMP 在您的 Mac OS X 上现在安装完成。

1.  现在，让我们检查我们的 MAMP 安装。将浏览器指向`http://localhost/MAMP/`，您将看到默认的 MAMP 登陆页面，如下图所示：![在 Mac OS X 中安装 MAMP 的时间](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_01_21.jpg)

您可以在 MAMP 的**开始**页面的顶部栏上检查**phpinfo, phpMyAdmin**等。

1.  从`/Applications/MAMP/`，双击`MAMP.app`来运行 Apache、MySQL、PHP 和 MAMP 控制面板。**MAMP**控制面板显示服务器状态，并允许您启动/停止服务器，如下图所示：![在 Mac OS X 中安装 MAMP 的时间](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_01_22.jpg)

1.  从 MAMP 控制面板中的**首选项... | PHP 选项卡**切换到 PHP 版本 5.3（需要重新启动服务器）。

## 刚刚发生了什么？

我们已经成功地为我们的 Mac OS X 开发环境下载并安装了 MAMP。此外，我们已经测试了安装，并发现它完美地运行起来。MAMP 登陆页面带有选项卡式界面，包括`phpinfo, phpMyAdmin, SQLiteManager`等。您的 MAMP 包中已安装了以下程序和库：

+   Apache 2.0.63

+   MySQL 5.1.44

+   PHP 5.2.13 和 5.3.2

+   APC 3.1.3

+   eAccelerator 0.9.6

+   XCache 1.2.2 和 1.3.0

+   phpMyAdmin 3.2.5

+   Zend Optimizer 3.3.9

+   SQLiteManager 1.2.4

+   Freetype 2.3.9

+   t1lib 5.1.2

+   curl 7.20.0

+   jpeg 8

+   libpng-1.2.42

+   gd 2.0.34

+   libxml 2.7.6

+   libxslt 1.1.26

+   gettext 0.17

+   libidn 1.15

+   iconv 1.13

+   mcrypt 2.6.8

+   YAZ 4.0.1 和 PHP/YAZ 1.0.14

到目前为止，我们已经安装了最新的 NetBeans IDE，并使用最新的 Apache、MySQL 和 PHP 设置了我们的平台特定的开发环境。现在，我们最近完成的开发环境已经足够精心地开始构建项目。我们将在 IDE 的帮助下进行 PHP 项目的创建和维护。开发人员和 IDE 之间的这种协同作用可以真正提高生产力。

## 尝试一下 — 保护您的 MAMP 安装

正如我们所了解的，MAMP 并不适用于生产环境，而只适用于开发环境中的开发人员。通过 MAMP 论坛[`forum.mamp.info/viewtopic.php?t=365`](http://forum.mamp.info/viewtopic.php?t=365)来保护您的 MAMP 安装。您可能需要设置 MySQL 密码、`phpMyAdmin`密码、保护 MAMP 登陆页面等。

# 创建一个 NetBeans PHP 项目

NetBeans 将用于开发应用程序的所有必要文件分组到一个项目中。项目文件包括您的原始代码以及您的项目可能依赖的任何导入的代码。NetBeans 项目管理使得在大型项目上工作变得更加容易，因为它可以立即显示程序的一个部分的变化将如何影响程序的其余部分。因此，IDE 提供了一些功能来促进项目的发展。

# 执行操作的时间-创建 NetBeans PHP 项目

最后，我们将创建一个 NetBeans PHP 项目，以便组织 PHP 内容，并对创建的项目有更多的控制。

要创建一个 NetBeans PHP 项目，请按照以下步骤进行：

1.  为了开始项目创建，从 IDE 菜单栏中转到**文件|新建项目**。

1.  从这个窗口中，选择**PHP**作为项目类别，并选择默认选择的**PHP 应用程序**，这意味着我们将从头开始创建一个 PHP 项目。如果您已经有源 PHP 代码，那么选择**具有现有源的 PHP 应用程序**，您将需要浏览到您的现有源以设置您的源目录。

1.  点击**下一步**按钮，它会带您到下面的屏幕，如下所示：![执行操作的时间-创建 NetBeans PHP 项目](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_01_24.jpg)

1.  定义项目名称和 IDE，它会自动为给定名称建议源文件夹。但是，我们可以通过浏览文件夹路径来明确定义源文件夹路径。还要选择适当的**PHP 版本**，根据这个版本，项目将在 IDE 中表现，并选择**默认编码**。我们将默认选择最新的 PHP 版本行为和`UTF-8`作为**默认编码**。

1.  请记住，项目元数据只在本地阶段使用；可选地，您可以将 NetBeans 创建的项目元数据放入一个单独的目录中。要做到这一点，勾选**将 NetBeans 元数据放入单独的目录中**。

1.  因此，我们将项目命名为`chapter1`，并点击**下一步**，如下图所示：![执行操作的时间-创建 NetBeans PHP 项目](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_01_25.jpg)

1.  定义项目将在哪里运行（远程服务器等），以及项目 URL。默认的项目 URL 是`http://localhost/`与尾部项目名称连接而成的形式。点击**下一步**，进入下一个截图：![执行操作的时间-创建 NetBeans PHP 项目](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_01_26.jpg)

如果需要，可以使用可选的复选框将 PHP 框架支持添加到您的项目中。IDE 支持两种流行的 PHP 框架——Symfony 和 Zend 框架。

1.  最后，点击**完成**以完成项目向导，并且 NetBeans 将打开 PHP 项目。它应该看起来类似于以下截图：![执行操作的时间-创建 NetBeans PHP 项目](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_01_27.jpg)

一个索引页面`index.php`会自动创建在项目源中。

1.  为了测试项目，我们将在 PHP 标签之间放置一些代码。因此，让我们放置一个简单的`echo`，如下所示：

```php
<?php
echo "Hello World";
?>

```

1.  保存文件，并将浏览器指向项目 URL，`http://localhost/chapter1/`。页面应该会输出类似于以下截图的内容：![执行操作的时间-创建 NetBeans PHP 项目](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_01_28.jpg)

因此，我们可以看到我们的 PHP 项目表现良好。

1.  将更多的文件和类添加到我们的项目中，您可以右键单击项目名称，这将显示**项目**菜单：![执行操作的时间-创建 NetBeans PHP 项目](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_01_29.jpg)

通过这个项目上下文菜单，我们可以根据需要从**新建**中添加更多的 PHP 文件、类等。正如我们在这个截图中所看到的，一个项目也可以被修改。例如，您可以重命名、复制或修改项目配置，如果您愿意的话。

## 刚刚发生了什么？

在 NetBeans 中创建一个新的 PHP 项目非常顺利。在创建过程中，我们发现可以通过逐步项目创建向导轻松设置项目的多个配置。此外，我们还看到在创建新项目后，IDE 支持从项目上下文菜单中添加新的 PHP 文件、类、接口等。请注意，您可以从项目上下文菜单中管理项目操作，如运行和版本控制任务。要更改现有项目的设置，请将光标放在项目节点上，并从弹出菜单中选择**属性**。

因此，从现在开始，这将是我们在 NetBeans 中创建新的 PHP 项目的步骤。

## 尝试英雄——从现有源代码创建项目

如果您已经有一些 PHP 项目的基础源代码，您可以将这些源文件引入 NetBeans，以便更好地控制项目。通过选择**文件|新建项目**从现有源代码创建新项目。

# 总结

我们已经练习了为特定操作系统设置开发环境。我们已经成功安装和运行了 IDE、Web 服务器、数据库服务器、脚本语言和数据库管理 Web 界面。

具体来说，我们涵盖了：

+   NetBeans IDE 安装

+   各种平台上的 PHP 开发环境设置

+   在 NetBeans IDE 中创建 PHP 项目

我们还讨论了使用这样的 IDE 的重要性，以及我们如何从中受益。现在我们已经准备好开始 PHP 开发所需的所有工具包，下一章我们将学习有关编辑器功能，以便进行快速和高效的 PHP 开发。


# 第二章：通过 PHP 编辑器提高编码生产力

> 在本章中，我们将讨论如何通过编辑器提高我们的编码生产力，以及如何充分利用 NetBeans 编辑器。

我们将重点关注以下内容：

+   基本 IDE 功能

+   PHP 编辑器

+   重命名重构和即时重命名

+   代码完成

+   代码生成器

那么让我们开始吧...

# 熟悉基本 IDE 功能

作为 IDE，NetBeans 支持各种功能，以提高您的日常 PHP 开发。它包括编辑器、调试器、分析器、版本控制和其他协作功能。基本 IDE 提供以下有趣的功能：

+   **快速搜索：**NetBeans 为您提供了 IDE 中的搜索功能，例如在文件、类型、符号、菜单操作、选项、帮助和打开项目中进行搜索，按*Ctrl+I*聚焦在搜索框上。在搜索结果列表中，您将找到输入的搜索词在结果项中的高亮显示：![熟悉基本 IDE 功能](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_02_01.jpg)

+   **插件管理器：**从**工具 | 插件**，您将有插件管理器，可以添加、删除或更新功能。此外，许多有趣的第三方插件都可以从插件门户网站获得。请注意，您可以从已安装的插件列表中停用或卸载插件（如 CVS、Mercurial 等），这些插件目前并不是您关心的问题，但您可以这样做以释放一些资源，并在需要时重新添加这些插件：![熟悉基本 IDE 功能](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_02_02.jpg)

+   **项目管理器：**从**窗口 | 项目**或按*Ctrl+1*，您可以固定 IDE 的**项目管理器**窗格，以对每个可用项目执行操作。项目操作，如运行、调试、测试、生成文档、检查本地历史记录、设置配置和设置项目属性都可以在项目管理器窗口中完成：![熟悉基本 IDE 功能](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_02_03.jpg)

+   **文件管理器：**从**窗口 | 文件**或按*Ctrl+2*，您可以固定 IDE 的**文件管理器**窗格，以浏览项目文件或对 IDE 可用的文件进行一般文件操作：![熟悉基本 IDE 功能](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_02_04.jpg)

+   **服务管理器：**从**窗口 | 服务**或按*Ctrl+5*，您可以固定 IDE 的**服务管理器**窗格，以使用预注册的**软件即服务**（**SaaS**）Web 服务组件。从**服务**选项卡中拖动项目，将项目放入资源类中，即可生成访问服务所需的代码。此外，**服务**窗格还可以让您访问所有连接的数据库：![熟悉基本 IDE 功能](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_02_05.jpg)

+   **任务管理器：**从**窗口 | 任务**或按*Ctrl+6*，您可以固定 IDE 的**任务管理器**或操作项窗格。NetBeans IDE 会自动扫描您的代码，并列出包含诸如`TODO`或`FIXME`等单词的注释行，以及包含编译错误、快速修复和样式警告的行。连接到 bug 数据库—**Bugzilla**，并在 IDE 中列出项目的问题报告。请注意，双击任务将直接带您到声明该任务的位置：![熟悉基本 IDE 功能](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_02_06.jpg)

+   **导航：**从**导航**菜单，IDE 提供了对文件、类型、符号、行、书签等的导航。这些功能用于快速跳转到项目中或项目外所需的位置：![熟悉基本 IDE 功能](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_02_07.jpg)

如前一截屏所示，一旦我们输入文件名，IDE 会显示**匹配文件**框中匹配的文件名的动态列表，这样您就可以快速打开该文件：

![熟悉基本 IDE 功能](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_02_08.jpg)

### 提示

按*Alt+Shift+O*打开**转到文件**，按*Ctrl+O*打开**转到类型**，按*Ctrl+B*打开**转到声明**，按*Ctrl+G*打开**转到行**，等等。

+   **模板和示例应用程序：**您可以在 IDE 中使用给定的示例应用程序开始类似的新项目。要做到这一点，按*Ctrl+Shift+N*开始一个新项目，并从**项目类别**中选择**Samples | PHP**。此外，您可以使用模板，如 PHP 文件的模板和**Tools | Templates**中的网页模板：![熟悉基本 IDE 功能](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_02_09.jpg)

+   **可定制的工作区和窗口：**整个 IDE 工作区是完全可定制的，因此您可以将工具栏和窗格拖动、滑动、调整大小并放置到所需的位置。此外，您可以在工作区内停靠或取消停靠窗格，使其完全适合访问和使用：![熟悉基本 IDE 功能](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_02_10.jpg)

### 提示

您可以轻松管理工作区中的窗口；双击编辑器选项卡以展开它。*Ctrl+Tab*显示已打开文件的列表，再次按下将导致在编辑器选项卡之间切换。*Ctrl+Pageup/Down*在已打开的文件之间切换。按*Ctrl+W*关闭当前文件窗口。

+   **多个监视器：**您可以取消停靠任何编辑器选项卡并将其拖出 IDE，使其可以像独立窗口一样运行，并且可以轻松地将其移动到第二个屏幕上。此外，您可以反向操作将其重新停靠在以前的屏幕上。请注意，第二个屏幕中的所有快捷键仍将保持不变；例如，拖出**Files**选项卡，然后单击 IDE 中的其他任何位置，然后按*CTRL+2*重新聚焦文件窗口。![熟悉基本 IDE 功能](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_02_11.jpg)

+   **本地历史记录：**本地历史记录类似于经典的版本控制系统，它存储文件的多个版本。但是，存储仅限于您的 NetBeans 安装。本地历史记录使您能够检查文件和文件夹中的内容，让您**diff**它们，最重要的是，让您将源代码回滚到以前的状态，或者恢复已删除的文件或文件夹。

+   **拼写检查器：**检查编辑器中的文本拼写。

### 注意

请参阅 NetBeans IDE 键盘快捷键附录。

## 小测验——熟悉基本 IDE 功能

1.  哪个不是 IDE 功能？

1.  源代码编辑器

1.  调试器

1.  插件管理器

1.  源代码优化器

1.  在哪个菜单下可以启用或聚焦所有 IDE 窗口？

1.  文件菜单

1.  工具菜单

1.  导航菜单

1.  窗口菜单

1.  哪个是打开**转到文件**窗口的正确命令？

1.  CTRL+F

1.  CTRL+SHIFT+O

1.  ALT+SHIFT+O

1.  CTRL+G

1.  为什么使用键盘快捷键*CTRL+SHIFT+N*？

1.  打开一个新的模板文件

1.  打开一个新的 PHP 文件

1.  打开一个新的 PHP 项目

1.  打开项目窗口

1.  修复**文件管理器**窗格的键盘快捷键是什么？

1.  CTRL+1

1.  CTRL+2

1.  CTRL+3

1.  CTRL+5

# 探索 PHP 编辑器

在本节中，我们将学习如何充分利用 NetBeans 中的 PHP 编辑器。编辑器提供非常方便的代码编写功能，我们将通过在编辑器中测试这些重要功能来学习它们。一旦我们熟悉了以下功能，我们就能掌握编辑器。您只需要练习以下功能的命令。我们开始吧：

+   **语法高亮：**此编辑器使语法元素（如 PHP 关键字、变量、常量、HTML 标记和输入表单属性）高亮显示。在编辑器中，当前行用浅蓝色背景标记，发生错误的行用红色下划线显示，如下图所示：![探索 PHP 编辑器](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_02_12.jpg)

### 提示

双击选择语法元素。按*Ctrl+F*进行语法搜索以突出显示语法元素的所有出现。

+   **转到声明：** **转到声明**功能可立即跳转到变量或方法的声明行，从其出现位置：![探索 PHP 编辑器](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_02_13.jpg)

### 提示

为了使用此功能，请将光标放在所需的变量或方法上，然后按*Ctrl+B*，或单击出现在屏幕右侧的上下文菜单，选择**导航|转到声明**，将光标放在声明的起始行。按*Ctrl+单击*也会将您引导到声明处，并突出显示所有出现的情况。

+   **代码导航器：** **代码导航器**窗格动态列出文件中的 PHP 结构，按层次顺序列出 HTML 标记；简单地列出文件中的命名空间、函数、方法、类、变量、类属性、HTML 标记等。双击列表中的任何项目以转到该声明：![探索 PHP 编辑器](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_02_14.jpg)

### 提示

从**窗口|导航|导航器**或按*Ctrl+7*，您可以专注于代码导航器窗格。列出的项目根据相关项目属性进行图标化。

+   **代码折叠：**编辑器为您提供了用于类、方法、注释块、HTML 标记、CSS 样式类等的代码块折叠/展开功能。您可以使用这些功能在编辑器左边缘旁边折叠/展开大型代码块，如下面的屏幕截图所示：![探索 PHP 编辑器](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_02_15.jpg)

### 提示

单击屏幕左侧的“”或“+”按钮，折叠和展开代码块。

+   **智能缩进：**编辑器在键入并按下新行时会在代码之前提供自动缩进：![探索 PHP 编辑器](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_02_16.jpg)

输入`if`或`for`语句行，然后按*Enter*键以查看下一行缩进。

+   **格式化：**为了使代码更易于理解，编辑器为您提供了格式化功能，该功能维护适当的语句层次结构，并在代码文件中应用换行、空格、缩进等：![探索 PHP 编辑器](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_02_17.jpg)

### 提示

选择要格式化的代码块。右键单击上下文菜单，选择**格式**，或按*Alt+Shift+F*。要格式化整个代码文件，请选择**源|格式**，或按*Ctrl+A*和*Alt+Shift+F*。

+   **括号补全：**成对字符项的连续第二个字符（例如单引号（''），双引号（""），括号（（）），方括号（[]））会自动添加第一个字符类型，并且成对的连续字符会随着第一个字符的删除而删除。当键入第一个字符并按*Enter*时，大括号{}的一对会被补全。当光标指向匹配对中的任何字符时，大括号、花括号和方括号会以黄色突出显示，如下所示：![探索 PHP 编辑器](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_02_18.jpg)

+   **参数提示：**编辑器在您开始键入函数名称时会提示您选择 PHP 默认或自定义函数的形式参数。带有函数名称和参数的自动建议列表将显示在光标底部，所选函数的描述将显示在光标顶部：![探索 PHP 编辑器](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_02_19.jpg)

在上一个自动建议列表中，您可以使用“上/下”箭头键进行遍历。您可以按*Enter*键插入带有占位符的所需函数名称，以在括号内插入参数：

![探索 PHP 编辑器](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_02_20.jpg)

+   **在注释中定义变量类型：**您可以在注释中定义变量及其类型，格式为`/* @var $variable type */`。如果注释编写正确，则`var`标签将以粗体字显示：![探索 PHP 编辑器](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_02_21.jpg)

在前面的截图中，您可以看到变量名称和类型的注释如何支配自动建议。在前面的示例中，您可以看到方法名称是从相应的类名称中提取的，该类名称在注释中作为变量类型提到。

键入`vdoc`，然后按`Tab`键使用变量文档的代码模板。将生成一个定义变量的注释。一旦选择了变量名称，更改它，然后再次按`Tab`键，以更改类型：

![探索 PHP 编辑器](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_02_22.jpg)

代码模板会自动生成变量名称和类型，以适应注释位置；也就是说，如果您在使用模板之前使用变量，则它将建议该变量名称和类型。

+   **错误消息：**编辑器在输入时解析您的 PHP 代码，用红色下划线标记语法错误，在左边缘放置红色错误标志，在右边缘放置红色错误滚动位置。![探索 PHP 编辑器](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_02_23.jpg)

### 提示

您可以通过将鼠标悬停在错误行上或单击屏幕左侧的红色错误标志来查看工具提示中的错误详细信息。按*Alt+Enter*显示错误提示。

请参阅 NetBeans IDE 键盘快捷键附录。

## 弹出测验-探索 PHP 编辑器

1.  哪个功能不是编辑器功能？

1.  源代码格式化

1.  代码自动完成

1.  语法高亮

1.  调试

1.  如何格式化代码块？

1.  通过右键单击上下文菜单选择代码块，然后选择**格式**

1.  选择代码块，然后按*ALT+SHIFT+F*

1.  选择代码块，然后选择**源代码|格式**

1.  以上所有

1.  什么是语法搜索键盘命令？

1.  *CTRL+W*

1.  *CTRL+F*

1.  *CTRL+ALT+F*

1.  *CTRL+SHIFT+S*

1.  如何转到方法的声明？

1.  将光标放在方法上，然后按*CTRL+B*

1.  右键单击方法名称，然后从上下文菜单中选择**导航|转到声明**

1.  在方法名称上按*CTRL+单击*

1.  以上所有

# 更多探索编辑器

我们已经了解了编辑器并练习了提示中给出的快捷方式。在接下来的两节中，我们将学习如何使用重命名重构、代码完成和编辑器的代码生成功能，这些功能对于提高编码非常有帮助。

在下一节中，我们将讨论和练习以下重要的编辑器功能：

+   重命名重构和即时重命名

+   代码完成

+   代码生成器

# 使用重命名重构和即时重命名

您可以在项目中的所有文件中重命名一个元素，例如类名。此功能使您可以预览所需重命名的每个位置的可能更改，并且您可以排除个别出现不被重命名。

即时重命名允许您在文件中重命名元素。对于即时重命名，将光标放在要重命名的名称上，然后按*Ctrl+R*；如果该变量适用于即时重命名，则该变量的所有实例将被突出显示如下：

![使用重命名重构和即时重命名](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_02_24.jpg)

即使只有一个实例的名称发生变化，也会同时重命名文件中的所有其他实例：

![使用重命名重构和即时重命名](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_02_25.jpg)

要使用重命名重构，选择要重命名的元素，然后右键单击，选择**重构|重命名**。将打开一个对话框，供您重命名元素，如下一张截图所示：

![使用重命名重构和即时重命名](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_02_26.jpg)

在此截图中，为元素提供一个新名称，然后单击**预览**。重构窗口将打开，并列出项目中元素的所有实例：

![使用重命名重构和即时重命名](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_02_27.jpg)

从这个截图中，您可以排除实例并对所选实例应用**进行重构**。

### 注意

请参阅 NetBeans IDE 键盘快捷键附录。

## 小测验——使用重命名重构和即时重命名

1.  如何在整个项目中重构变量名？

1.  选择变量，然后右键单击并选择**重构 | 重命名**

1.  将光标放在变量名上，然后按下*CTRL+SHIFT+R*

1.  选择变量，然后选择**源 | 重命名**

1.  以上都不是

1.  哪个是变量的即时重命名快捷键？

1.  *SHIFT+ALT+R*

1.  *CTRL+R*

1.  *CTRL+ALT+R*

1.  *CTRL+SPACE+R*

# 使用代码完成

代码完成功能使我们能够以最少的按键或仅使用键盘命令完成所需的语法、方法或代码。

### 提示

您可以从**工具 | 选项 | 编辑器 | 代码完成**启用/禁用自动代码完成。默认情况下，您将为所有语言都有复选框。从**语言**下拉列表中选择 PHP，以获得更多针对 PHP 的代码完成选项。

![使用代码完成](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_02_28.jpg)

以下是编辑器提供的代码完成功能：

+   **片段：**这会自动生成各种元素的代码片段。![使用代码完成](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_02_29.jpg)

选择**工具 | 调色板 | PHP**代码片段，然后**调色板管理器**将打开。从**调色板内容**中拖动相关项目图标，并将其放置到代码中的相关位置。将出现一个对话框，用于指定相应代码项的参数。填写参数，然后在该位置生成代码。

+   **上下文敏感的建议：**编辑器为任意数量的起始符号提供上下文敏感的建议：

+   一个 PHP 关键字，包括`if、else、elseif、while、switch、function`等。

+   一个 PHP 内置函数。

+   预定义或用户定义的变量。

输入关键字或函数名的起始字符，然后按下*Ctrl+Space*。下拉列表将显示该上下文的所有适用建议。每个建议都附有描述和参数提示：

![使用代码完成](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_02_30.jpg)

要生成适用于当前上下文的 PHP 关键字列表，请按下*Ctrl+Space*，而不输入任何内容：

![使用代码完成](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_02_31.jpg)

要获取有关变量的提示，请键入美元符号（`$`）。将显示当前可用的本地和全局变量列表：

![使用代码完成](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_02_32.jpg)

+   **代码模板和缩写：**通过使用定义的缩写来获取扩展的代码模板，例如`cls`表示类模板，这是最有趣的代码完成功能。要使用此功能，请键入缩写并按下*Tab:*![使用代码完成](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_02_33.jpg)

您可以看到缩写被替换为相应的 PHP 关键字，并且编辑器提供了该关键字的代码模板，如下截图所示：

![使用代码完成](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_02_34.jpg)

查看代码模板列表及其相关缩写，选择**工具 | 选项 | 编辑器 | 代码**模板。您可以根据以下截图中显示的方式添加/删除或编辑您的 PHP 代码模板：

![使用代码完成](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_02_35.jpg)

请注意，编码方法会随着时间而改变。因此，建议每隔几个月查看您的模板，并更新以符合任何新变化。

+   **构造函数中的代码完成：**在`new`关键字之后，将显示代码完成以及当前项目中所有类的构造函数和参数列表：![使用代码完成](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_02_36.jpg)

+   **SQL 代码完成：**当字符串以 SQL 关键字（如`select`和`insert`）开头时，按下该关键字后的*Ctrl+Space*将在编辑器内启用 SQL 代码完成功能。您可以在第一步中选择数据库连接，如下面的屏幕截图所示：![使用代码完成](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_02_37.jpg)

+   被选中的所有与 IDE 注册的数据库连接将显示如下：![使用代码完成](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_02_38.jpg)

+   选择数据库连接后，SQL 代码完成功能将提供与该连接关联的所有表：![使用代码完成](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_02_39.jpg)

此外，还将从该表中显示列（如果有）。SQL 代码完成还适用于表别名。

+   **PHP 5.3 命名空间：**代码完成支持 PHP 5.3 命名空间。

+   **重写和实现的方法：**类成员之间的代码完成提供了重写或实现方法的选项。

### 提示

在希望使用代码完成的地方按下*Ctrl+Space*。

有关 NetBeans IDE 键盘快捷键，请参见附录。

## 小测验——使用代码完成

1.  为什么要使用代码完成功能？

1.  重构变量

1.  编写新的 PHP 类

1.  完成所需的语法、方法或代码的快捷键

1.  完成 PHP 项目

1.  代码完成功能不支持哪种 PHP 语言特性？

1.  命名空间

1.  类声明

1.  重写方法

1.  以上都不是

1.  启用上下文敏感建议的快捷键是什么？

1.  Ctrl+Shift+Space

1.  Ctrl+Space

1.  Ctrl+S

1.  Ctrl+Alt+Space

# 使用代码生成器

编辑器提供了上下文敏感的代码生成器，以便生成数据库连接、构造函数、getter 或 setter 等。特定的代码生成器将出现在光标位置的上下文中。例如，在类内部，它将显示用于生成构造函数、getter、setter 等的选项。

例如，按*Alt+Insert*在类内部打开所有可能的代码生成器，如下面的屏幕截图所示：

![使用代码生成器](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_02_40.jpg)

我们将讨论以下代码生成器：

+   **构造函数：**在 PHP 类内（但不在任何方法体内），您可以按*Alt+Insert*打开构造函数生成器。选择**生成构造函数**，将出现类似于以下屏幕截图的对话框：![使用代码生成器](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_02_41.jpg)

该窗口列出了可以在构造函数中初始化的可用字段。字段名称用作构造函数的参数。您可以决定不选择任何字段；在这种情况下将生成一个空的构造函数。

+   **Getter 和 setter：**通过在 PHP 类内部按代码生成器命令，您可以选择**Getters...，Setters...**或**Getters and Setters**来查看可能的函数。如果您已经有 setter，那么您只会看到 getter 方法：![使用代码生成器](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_02_42.jpg)

选择**getter/setter**后，出现了上一个屏幕截图；您可以指定要为哪个属性生成**getter**或**setter**方法，并灵活选择方法的命名约定。

+   **重写和实现的方法：**当类内有多个方法时，您可以打开重写和实现方法的代码生成器。对话框将打开，显示您可以插入的方法，并指示它们是重写还是实现：![使用代码生成器](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_02_43.jpg)

### 注意

有关 NetBeans IDE 键盘快捷键，请参见*附录*。

## 小测验——使用代码生成器

1.  在 PHP 类内部打开代码生成器的快捷键是什么？

1.  Alt+Insert

1.  Shift+Alt+Insert

1.  Ctrl+ Alt+Insert

1.  Ctrl+Insert

1.  什么不能使用代码生成器生成？

1.  构造函数

1.  Getter 和 setter

1.  重写方法

1.  字符串

# 摘要

在本章中，我们发现了 PHP 编辑器的有用功能，并练习了在编写代码时应用的技巧。熟悉我们所看到的编辑器快捷键将帮助您更快、更准确地编写代码。

我们特别关注了：

+   PHP 编辑器的功能和快捷键

+   重命名重构和即时重命名

+   代码自动完成的使用

+   代码生成器的使用

因此，到目前为止，我们的 PHP 开发环境已经准备就绪。我们已经安装了 IDE，并学会了在需要时如何使用这些酷炫的编辑器功能。在下一章中，我们将直接深入到真实的 PHP 编码中，并将开发一个 PHP 项目，以掌握使用 NetBeans 进行 Web 应用程序开发。


# 第三章：使用 NetBeans 构建类似 Facebook 的状态发布者

> 在本章中，我们将使用 NetBeans IDE 构建一个很酷的 PHP 项目。我们的计划很简单明了。

我们将通过以下步骤创建一个类似 Facebook 的状态发布者：

+   规划项目

+   创建状态流显示列表

+   使用 PHP-AJAX 创建状态发布者

大多数社交网络平台，如 Facebook、Twitter 和 Google Plus，都为用户的朋友提供了状态发布功能，并允许用户查看他们朋友的状态发布。因此，我们将研究这是如何工作的，以及我们如何构建类似的功能。让我们选择实现一个类似最流行的社交网络平台 Facebook 的有趣功能。

此外，我们还将讨论 MySQL 数据库连接和 PHP 类创建以及我们的工作流程。所以，让我们开始吧...

# 规划项目

项目的适当规划对于智能开发和使用样机、图表和流程图至关重要，以便项目可以轻松地可视化需求。此外，它描述了你将要做什么，以及如何做。

我们将创建一个简单的类似 Facebook 的（[`www.facebook.com`](http://www.facebook.com)）状态发布者，并在其下方添加一个列表，以显示朋友的状态发布，以及您自己的状态。在这个单一的前端 PHP 应用程序中，我们将使用 JavaScript 库**jQuery**（[`jquery.com/`](http://jquery.com/)）通过**AJAX**（[`api.jquery.com/jQuery.ajax/`](http://api.jquery.com/jQuery.ajax/)）发布状态。发布的状态将在不重新加载页面的情况下显示在状态堆栈顶部。

在规划我们的项目时，我们将提前查看 Web 应用程序的最终外观，并尝试了解如何将特定功能放置到工作中。为了讨论工作流程的各个要点，我们还将拥有工作流程图。

让我们看看最终阶段我们将要构建的内容。

![规划项目](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_03_01.jpg)

这个**状态发布者**将以以下方式运行：

![规划项目](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_03_02.jpg)

根据这个图，用户在状态框中输入并点击“分享”按钮，触发`Status.js`中绑定的 JavaScript 方法，通过 AJAX 将状态发布到服务器。服务器端脚本`StatusPoster.php`接收状态以保存到数据库，并在完成任务后响应成功消息。前端代码接收成功通知，并在状态发布的显示堆栈顶部添加状态。

现在，我们将根据以下两部分拆分项目，并相应地开发它们：

+   状态流显示列表

+   使用 PHP-AJAX 创建状态发布者

我们已经收集了关于项目工作流程的概念。因此，根据我们的规划，我们可以立即开始实施项目。从这一点开始，我们将直接使用 NetBeans 开始 PHP 应用程序开发，创建一个新的 PHP 项目，并熟练使用 IDE。我们知道该做什么，几分钟内我们将学会如何做。

## 理解 JSON-JavaScript 对象表示法

**JavaScript 对象表示法（JSON）**是一种轻量级的数据交换格式，对人类来说易于阅读和编写。它是机器解析和生成的简单格式，基于 JavaScript 编程语言的一个子集。JSON 是一种完全与语言无关的文本格式。

JSON 建立在两种结构上：

+   一组名称/值对：在各种语言中，这被实现为对象、记录、结构、字典、哈希表、键控列表或关联数组。

+   一个有序的值列表：在大多数语言中，这被实现为数组、向量、列表或序列。

例如：

```php
{ "firstName":"John" , "lastName":"Doe" }

```

## 引入 jQuery-权威的 JavaScript 库

jQuery 是一个快速而简洁的 JavaScript 库，简化了 DOM（文档对象模型）遍历、事件处理、动画和快速网页开发的 AJAX 交互。jQuery 旨在改变您编写 JavaScript 的方式-[`jquery.com/`](http://jquery.com/)。

我们应该使用 jQuery 的一些原因如下：

+   免费和开源软件

+   轻量级足迹

+   符合 CSS3 标准

+   跨浏览器

+   最小代码

+   现成的插件

简而言之，jQuery 使您能够生成强大和动态的用户界面。

### 注意

借助各种 jQuery 插件，包括图像滑块、内容滑块、弹出框、选项卡内容等，开发人员的工作可能会减少，因为他们所要做的就是调整或定制 jQuery 插件的小部分，使其与他们的需求相匹配。

## 理解 AJAX-异步 JavaScript 和 XML

**异步 JavaScript 和 XML**（**AJAX**）是一种在客户端使用的编程技术或方法，用于在后台异步地从服务器检索数据，而不干扰现有页面的显示和行为。通常使用`XMLHttpRequest`对象检索数据。尽管有这个名字，实际上并不需要使用 XML，请求也不需要是异步的。

jQuery 库具有完整的 AJAX 功能。其中的函数和方法允许我们从服务器加载数据，而无需刷新浏览器页面。

## 介绍 jQuery.ajax()

让我们看一下示例`jQuery.ajax()` API。

```php
$.ajax({
url: "my_ajax_responder.php",
type: "POST",
data: {'name': 'Tonu'}, //key value paired or can be like "call=login&name=Tonu"
success: function(xh){
//success handler or callback
},
error: function(){
//error handler
}
});

```

在`$.ajax()`函数中，可以看到 AJAX 配置对象（使用 JavaScript 对象文字创建）被传递给它，这些配置可以描述如下：

+   `url`表示与之通信的服务器脚本的 URL

+   `type`表示 HTTP 请求类型；即`GET/POST`

+   `data`包含要发送到服务器的数据，可以是键值对或 URL 参数的形式

+   `success`保存 AJAX 成功回调或在获取数据时执行的方法

+   `error`保存 AJAX 错误回调

现在，让我们再举一个例子，`jQuery.ajax()`只是从服务器加载一个 JavaScript 文件：

```php
$.ajax({
type: "GET",
url: "test.js",
dataType: "script"
});

```

在这里，`dataType`定义了要从服务器检索的数据类型；这种类型可以是 XML、JSON、`script`、纯文本等。

## 介绍 PHP 数据对象（PDO）

**PHP 数据对象**（**PDO**）扩展定义了一个轻量级和一致的接口，用于在 PHP 中访问数据库。PDO 提供了一个数据访问抽象层，这意味着无论您使用哪个数据库，您都可以使用相同的函数来发出查询和获取数据。PDO 不提供数据库抽象；它不重写 SQL 或模拟缺失的功能。如果您需要该功能，应该使用完整的抽象层。

值得一提的是 PDO 支持预处理语句，即：

+   **更安全：**PDO 或底层数据库库将为您处理绑定变量的转义。如果始终使用预处理语句，您将永远不会受到 SQL 注入攻击的威胁。

+   **（有时）更快：**许多数据库将为预处理语句缓存查询计划，并使用符号引用预处理语句，而不是重新传输整个查询文本。如果您只准备一次语句，然后使用不同的变量重用预处理语句对象，这一点最为明显。

### 注意

PHP 5.3 内置了 PDO 和 PDO_MYSQL 驱动程序。更多信息请访问[`www.php.net/manual/en/book.pdo.php`](http://www.php.net/manual/en/book.pdo.php)。

## 创建 NetBeans PHP 项目

完成任务规划后，我们将处理其实际实施。

按下*Ctrl+Shift+N*开始新的 NetBeans PHP 项目，并按照第一章中已经讨论过的步骤创建新项目，*设置开发环境*。让我们将项目命名为`chapter3`，用于我们的教程。

当我们创建了 PHP 项目时，项目中将自动创建`index.php`文件。因此，可以通过将浏览器指向`http://localhost/chapter3/`来定位项目。

# 创建状态流显示列表

根据项目的第一部分，我们现在将创建状态流显示列表。为了做到这一点，我们需要一个 PHP 类和一个 MySQL 数据库，其中填充了一些代表状态帖子的虚拟数据。PHP 类`StatusPoster.php`将在其构造函数中包含使用 PDO 的 MySQL 数据库连接，并包含一个从数据库中提取状态条目的方法。

## 设置数据库服务器

为了从数据库中存储和检索状态帖子，我们连接到 MySQL 数据库服务器，创建数据库和表以插入状态条目，并获取这些条目以在状态流中显示。

# 执行操作-连接到 MySQL 数据库服务器

在本节中，我们将通过向 IDE 提供访问凭据来创建 MySQL 服务器连接，IDE 将在连接下显示可用数据库的列表：

1.  首先，我们将在 IDE 内创建 MySQL 数据库服务器连接；按下*Ctrl+5*将**服务**窗口置于焦点，展开**数据库**节点，在**MySQL 数据库服务器**上右键单击，并选择**属性**以打开**MySQL 服务器属性**窗口，如下面的屏幕截图所示：![执行操作-连接到 MySQL 数据库服务器](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_03_03.jpg)

在上一个屏幕截图中，IDE 已经填写了 MySQL 服务器详细信息的默认值，如主机名、端口号、用户名和您刚刚添加的密码。您可以随时更新这些详细信息。

1.  单击**管理属性**选项卡，允许您输入控制 MySQL 服务器的信息。单击**确定**按钮以保存设置。

1.  现在，您应该在**MySQL 服务器**节点下列出所有可用的数据库，如下面的屏幕截图所示：![执行操作-连接到 MySQL 数据库服务器](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_03_04.jpg)

## 刚刚发生了什么？

我们已成功连接到 MySQL 服务器，并列出了为提供的数据库用户提供的所有可用数据库。实际上，我们使得可以从 IDE 直接快速操作任何类型的数据库查询。现在，我们将在其中创建一个新的数据库和表。

### 注意

有关 NetBeans IDE 键盘快捷键，请参见*附录*。

## 创建数据库和表

为每个项目使用单独的数据库是一种常见做法。因此，我们将为我们的项目使用一个新的数据库，并创建一个表来存储条目。IDE 提供了出色的 GUI 工具，用于数据库管理，如 SQL 编辑器、查询输出查看器和带有列列表的表查看器。

# 执行操作-创建 MySQL 数据库和表

从**MySQL 服务器**节点，我们将创建一个新的数据库，并运行一个查询来创建表以及必要的列字段。

1.  从**服务**窗口，在**MySQL 服务器**节点上右键单击，并选择**创建数据库...**。将出现一个新的对话框，如下面的屏幕截图所示：![执行操作-创建 MySQL 数据库和表](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_03_05.jpg)

1.  在**新数据库名称**字段中输入名称`status_poster`。不要选中**授予**的复选框。您可以使用此复选框和下拉列表向特定用户授予权限。默认情况下，`admin`用户拥有所有权限。

1.  单击 **OK**，使新数据库列在服务器节点下列出，并且在 **Databases** 节点下创建新的数据库连接节点，如下图所示：![Time for action — creating MySQL database and table](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_03_06.jpg)

根据这个屏幕截图，在 status_poster 连接节点下有三个子文件夹——**Tables, Views,** 和 **Procedures**。

1.  现在，要在我们的数据库中创建一个新表，右键单击 **Tables** 文件夹，选择 **Execute Command...** 打开主窗口中的 **SQL Editor** 画布，如下所示：![Time for action — creating MySQL database and table](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_03_07.jpg)

1.  在 SQL 编辑器中，输入以下查询来创建新的 `Status` 表：

```php
CREATE TABLE `status` (
`id` bigint(20) NOT NULL AUTO_INCREMENT,
`name` varchar(50) NOT NULL,
`image` varchar(100) NOT NULL,
`status` varchar(500) NOT NULL,
`timestamp` int(11) unsigned NOT NULL,
PRIMARY KEY (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

```

正如你所看到的，在 `status` 表中，我们有 `id`（每个条目都会自动增加）作为主键。我们有 `name` 字段，可以存储长达 `50` 个字符的用户名称。`image` 字段将存储长达 `100` 个字符的用户缩略图像。状态字段将存储最多 500 个字符的用户状态帖子，而 `timestamp` 字段将跟踪状态发布的时间。数据库引擎选择了 `MyISAM` 以提供更快的表条目。

因此，你只需要在 NetBeans 查询编辑器中输入 MySQL 查询，并运行查询，就可以准备好你的数据库。

1.  要执行查询，可以单击顶部任务栏上的 **Run SQL** 按钮（*Ctrl+Shift+E*），或者在 SQL 编辑器中右键单击并选择 **Run Statement**。IDE 然后在数据库中生成状态表，并在 **Output** 窗口中收到类似以下消息：![Time for action — creating MySQL database and table](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_03_08.jpg)

1.  你还会在 `status_poster` 数据库连接下的 **Table** 子文件夹中看到你的表状态，如下图所示：![Time for action — creating MySQL database and table](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_03_09.jpg)

在这个屏幕截图中，扩展的状态表显示了创建的列，主键用红色标记。

## 刚才发生了什么？

IDE 显示了数据库管理功能；只需点击几下和按几下键就可以完成所有这些数据库和表的创建。可以在 IDE 中迅速运行查询，并且 SQL 命令的执行输出会显示在一个单独的窗口中。接下来，我们将向创建的表中插入一些示例条目，以在状态流列表中显示它们。我们还需要为本教程添加一些演示用户图像文件。

### 提示

你可以使用 **Database Explorer** 中的 **Create Table** 向导来创建表——右键单击 **Tables** 节点，选择 **Create Table**。**Create Table** 对话框会打开，你可以在其中为表添加具体属性的列。

### 注意

查看 *附录* 以获取 NetBeans IDE 键盘快捷键。

## 将示例行插入表中

右键单击 **Tables** 子文件夹下的 `status` 表，选择 **Execute Command...**，在 SQL 编辑器中输入以下查询，向 `status` 表中插入一些示例行：

```php
INSERT INTO `status` VALUES('', 'Rintu Raxan', 'rintu.jpg', 'On a day in the year of fox', 1318064723);
INSERT INTO `status` VALUES('', 'Aminur Rahman', 'ami.jpg', 'Watching inception first time', 1318064721);
INSERT INTO `status` VALUES('', 'Salim Uddin', 'salim.jpg', 'is very busy with my new pet project smugBox', 1318064722);
INSERT INTO `status` VALUES('', 'M A Hossain Tonu', 'tonu.jpg', 'Hello this is my AJAX posted status inserted by the StatusPoster PHP class', 1318067362);

```

你可以看到我们有一些 MySQL `INSERT` 查询来存储一些测试用户的数据，比如姓名、图片、状态帖子和 Unix 时间戳，用于状态流显示列表。每个这样的 `INSERT` 查询都会向 `status` 表中插入一行。

因此，我们的表中有一些示例行。为了验证记录是否已添加到 `status` 表中，右键单击 `status` 表，选择 **View Data...**。在主窗口中会打开一个新的 SQL 编辑器选项卡，其中包含 `select * from status` 查询。执行此语句将在主窗口的下部区域生成一个表格数据查看器，如下图所示：

![Inserting sample rows into the table](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_03_10.jpg)

这个 SQL 查询相当不言自明，其中使用`SELECT`关键字从表中选择数据，并使用 SQL 简写`-*`表示应从表中选择所有列。

## 添加示例用户图像文件

在本教程中，我们已经向`status`表中插入了一些示例行；在`image`列中，我们有一些用户图像文件名，实际上我们将它们存储在项目的`images`目录下的`user`文件夹中。这些示例用户图像可以在本章的项目源代码中找到。从 Packt Publishing 网站下载完整的项目源代码，并复制示例用户图像。

要在`project`文件夹内创建一个子文件夹，在`chapter3`项目节点上右键单击，然后选择**新建|文件夹...**；在**新建文件夹**对话框中输入文件夹名称`images`，然后单击**完成**以创建文件夹。现在以相同的方式在`images`目录下创建另一个名为"user"的文件夹，并将复制的示例用户图像文件放在那里。

## 创建 StatusPoster PHP 类

`StatusPoster` PHP 类的目的是查询数据库以获取和插入状态条目。该类的一个方法将用于将状态条目插入到数据库表中，另一个方法将用于执行从表中获取条目的操作。简而言之，该类将作为数据库代理，并可用于必要的数据库操作。

# 操作时间-创建类，添加构造函数和创建方法

我们将使用 NetBeans 代码模板创建`StatusPoster.php`文件和类骨架，并在类内创建方法时，我们也将使用`function`模板。我们将在类构造函数中使用 PDO 创建 MySQL 数据库连接，以便在实例化对象和`getStatusPosts()`方法时创建数据库连接以从表中获取状态帖子。

1.  从**项目**窗格中，右键单击项目名称`chapter3`，选择**新建|PHP 文件...**，并将文件命名为`StatusPoster`，如下截图所示：![操作时间-创建类，添加构造函数和创建方法](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_03_11.jpg)

1.  单击**完成**，将文件添加到我们的项目中，并自动在编辑器中打开。您将看到文件中放置了 PHP 起始和结束标记。

1.  为了创建 PHP 类的骨架，我们将使用 PHP 代码模板。我们输入`cls`并按下*Tab*键，以获得包含构造函数的类骨架，如下所示：![操作时间-创建类，添加构造函数和创建方法](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_03_12.jpg)

1.  在上述截图中，`classname`已经被选中。您只需输入`StatusPoster`作为`classname`的值，并按下*Tab 键*选择构造函数名称，如下截图所示：![操作时间-创建类，添加构造函数和创建方法](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_03_13.jpg)

构造函数名称保持不变，因为它是默认的 PHP 5 构造函数命名约定。

1.  现在，添加一些类常量和属性来保存数据库凭据，如下面的代码片段所示：

```php
class StatusPoster {
private $db = NULL;
const DB_SERVER = "localhost";
const DB_USER = "root";
const DB_PASSWORD = "root";
const DB_NAME = "status_poster";
public function __construct() {
}
}

```

您可以看到添加的类常量，其中包含数据库信息，如数据库服务器名称、用户名、密码和数据库名称。已添加了一个`private`类变量`$db`，用于在 PDO 对象中保存数据库连接。您可以根据自己的需求修改这些常量。

### 注意

**Private:** 此属性或方法只能被类或对象使用；它不能在其他地方访问。

1.  为了从`status`表中获取状态帖子，我们将在类中添加一个名为`getStatusPosts`的空方法。为此，输入`fnc`并按*Tab*以生成具有所选函数名称的空函数代码。这次输入所选的函数名称为`getStatusPosts`，并且不要放入参数`$param`变量。我们的类框架将类似于以下内容：

```php
class StatusPoster {
private $db = NULL;
const DB_SERVER = "localhost";
const DB_USER = "root";
const DB_PASSWORD = "root";
const DB_NAME = "status_poster";
public function __construct() {
}
public function getStatusPosts() {
}
}

```

我们已经准备好了类的框架，并且将在这些类方法中添加代码。现在，我们将在构造函数中创建数据库连接代码。

1.  要使用 PDO 连接 MySQL，将以下行输入类构造函数中，使其看起来类似于以下代码片段：

```php
public function __construct() {
$dsn = 'mysql:dbname='.self::DB_NAME.';host='.self::DB_SERVER;
try {
$this->db = new PDO($dsn, self::DB_USER, self::DB_PASSWORD);
} catch (PDOException $e) {
throw new Exception('Connection failed: ' . $e->getMessage());
}
return $this->db;
}

```

`public function __construct()`使用 PDO 连接到 MySQL 数据库-以 PDO 实例的形式存储在类的私有变量中。

`$dsn`变量包含**数据源名称（DSN）**，其中包含连接到数据库所需的信息。使用 PDO 的最大优势之一是，如果我们想要迁移到其他 SQL 解决方案，那么我们只需要调整 DSN 参数字符串。

以下行创建了一个 PDO 实例，表示与请求的数据库的连接，并在成功时返回一个 PDO 对象：

```php
$this->db = new PDO($dsn, self::DB_USER, self::DB_PASSWORD);

```

请注意，如果尝试连接到请求的数据库失败，它会抛出一个`PDOException`异常。

1.  为了从表中选择状态帖子，我们将在`getStatusPosts`方法中使用自动完成代码编写一个`select`查询。正如我们在上一章中讨论的那样，SQL 代码自动完成从 SQL 关键字`SELECT`开始，通过按下*Ctrl+空格*。因此，我们将按照这些步骤进行，并在这个方法中编写以下查询代码：

```php
public function getStatusPosts() {
$statement = $this->db->prepare("SELECT name, image, status, timestamp FROM status ORDER BY timestamp DESC,id");
$statement->execute();
if ($statement->rowCount() > 0) {
return $statement->fetchAll();
}
return false;
}

```

通过这段代码，我们从表 status 中选择了列（`name, image, status`和`timestamp`），按时间戳降序排列。我们还按默认情况选择了 id 按升序排列。`prepare()`方法准备要由`PDOStatement::execute()`方法执行的 SQL 语句。在`execute()`方法之后，如果找到行，则它会获取并返回所有表条目。

1.  现在，我们将在文件底部实例化这个类的对象，使用以下行：

```php
$status = new StatusPoster();

```

## 刚才发生了什么？

PDO 实例是在类构造函数中创建的，并存储在`$db`变量中，因此其他成员方法可以访问这个类变量作为`$this->db`，以使用 PDO 方法，如`prepare(), execute()`。

调用`PDO::prepare()`和`PDOStatement::execute()`来执行多次的语句可以通过缓存查询计划和元信息等优化性能。

到目前为止，我们在`StatusPoster.php`中准备好了我们的数据库操作代码。我们将创建一个 HTML 用户界面，以显示从数据库表 status 中获取的状态列表。

### 注意

查看*附录*以获取 NetBeans IDE 的键盘快捷键。

## 小测验-理解 PDO

1.  哪一个不是 PDO 的特性？

1.  准备语句

1.  绑定值

1.  绑定对象

1.  数据访问抽象

## 启动用户界面以显示状态列表

HTML 用户界面将显示由`StatusPoster`类的`getStatusPosts`方法检索的状态列表，并且用户将能够查看来自他的测试朋友以及他自己的帖子的状态列表。界面将使用 jQuery 和由 CSS 类样式化的状态列表。

# 行动时间-向文档添加 CSS 支持

我们将使用`index.php`作为应用程序的单页面界面，并将向文档添加 CSS 样式表支持。为了保持实践，我们将尝试将样式属性放入类中，以便它们变得可重用，并且可以在需要特定样式类的元素的类名中使用。因此，让我们首先创建 CSS 类：

1.  在我们的项目源目录中创建一个名为`styles`的文件夹，用于我们的 CSS 文件。

1.  为了创建一个**级联样式表**，其中包含 CSS 类，右键单击项目中的`styles`文件夹，从**新级联样式表**对话框中选择**新建|级联样式表**，将 CSS 文件命名为`styles.css`，然后点击**完成**。删除已打开的 CSS 文件中的所有注释和代码块。在 CSS 文件中键入以下样式类：

```php
body {
font-family:Arial,Helvetica,sans-serif;
font-size:12px;
}
h1,input {
color:#fff;
background-color:#1A3C6C;
}
h1,input,textarea,.inputbox,.postStatus {
padding:5px;
}
input,textarea,ul li img,.inputbox {
border:1px solid #ccc;
}
ul li {
width:100%;
display:block;
border-bottom:1px solid #ccc;
padding:10px 0;
}
ul li img {
padding:2px;
}
.container {
width:60%;
float:none;
margin:auto;
}
.content {
padding-left:15px;
}
.content a {
font-weight:700;
color:#3B5998;
text-decoration:none;
}
.clearer {
clear:both;
}
.hidden {
display:none;
}
.left {
float:left;
}
.right {
float:right;
}
.localtime {
color:#999;
}
.inputbox {
height:70px;
margin:15px 0;
}
.inputbox textarea {
width:450px;
height:50px;
overflow:hidden;
}
.inputbox input {
margin-right:30px;
width:50px;
}

```

我们将使用`container`类来在文档主体内的应用程序界面容器`<div>`上应用样式；`ul` li 将表示列出的项目，这些项目是具有父`ul`元素的状态`li`项目，以及其他 HTML 元素，如 h1、`img`和`textarea`，也使用 CSS 类进行样式设置。

1.  在`index.php`文件的顶部添加以下 PHP 代码片段：

```php
<?php
define('BASE_URL', 'http://localhost/chapter3/');
?>

```

我们已经为 Web 应用程序定义了一个 PHP 常量来定义基本 URL。基本 URL 可用于为项目资产文件（CSS 或 JS 文件）提供绝对路径。您可以在[第三章]（ch03.html“第三章。使用 NetBeans 构建类似 Facebook 的状态发布者”）的位置放置您的项目目录名称。

1.  现在，在`<title>`标签下的`index.php`文档标题中添加以下行，以包含 CSS 文件。

```php
<link href="<?=BASE_URL?>styles/styles.css" media="screen" rel="stylesheet" type="text/css" />

```

有了这行，我们已将 CSS 文件嵌入到我们的 HTML 文档中。在这里，`BASE_URL`告诉我们`styles/styles.css`文件在项目目录下可用。因此，我们的界面元素将继承`styles.css`文件的样式。

## 刚刚发生了什么？

为了在各种浏览器上保持一致的界面，使用 CSS 类对各种 HTML 元素进行了样式设置，并且一些类是从分配元素将继承样式的位置编写的。

为了将 CSS 代码保持在最小行数，逗号分隔的类或元素名称已用于共享公共属性，如下所示：

```php
h1, input, textarea, .inputbox, .postStatus{
padding:5px;
}

```

在这里，`padding:5px`样式将应用于所述元素或具有给定类的元素。因此，类之间的共同属性可以通过这种方式减少。

为了理解类的可重用性问题，让我们看一下以下内容：

```php
.left {
float:left;
}

```

我们可以使用`left`作为多个元素的类名，这些元素需要`float:left`样式，例如`<div class="left">，<img class="left" />`等。

# 行动时间-添加 jQuery 支持和自定义 JS 库

我们将为文档添加 jQuery（一个 JavaScript 库；更多信息请访问[`jquery.com/)`](http://jquery.com/)）支持，并创建基于 jQuery 的自定义 JS 库。

对于 JS 库，我们将创建一个单独的 JavaScript 文件`status.js`，其中将包含界面 JS 代码以执行界面任务，例如通过 AJAX 发布状态以及一些用于显示本地日期时间的实用方法。因此，让我们创建我们的自定义 JS 库：

1.  从谷歌内容交付网络（CDN）添加 jQuery 支持到我们的文档中，在`index.php`文档标题下的`<link>`标签之后添加以下行：

```php
<script src= "http://ajax.googleapis.com/ajax/libs/jquery/1.7/jquery.min.js">
</script>

```

有了这行，我们就可以从 CDN 获取最新的 jQuery 版本。请注意，版本 1.7 表示最新可用版本，即 1.7.X，除非您已指定确切的数字，即 1.7.2 或更高版本。现在，我们的文档已启用 jQuery，并准备使用 jQuery 功能。

1.  要创建基于 jQuery 的自定义 JS 库，请在`js`文件夹中添加一个新的 JavaScript 文件，并将其命名为`status.js`。将文件包含在文档头部，使得`<head>`标签看起来类似于以下代码片段：

```php
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<title>Status updater</title>
<link href="<?=BASE_URL?>styles/styles.css" media="screen" rel="stylesheet" type="text/css" />
<script src="http://ajax.googleapis.com/ajax/libs/jquery/1.7/jquery.min.js"></script>
<script src="<?=BASE_URL?>js/status.js"></script>
</head>

```

1.  现在，在`status.js`文件中创建`Status` JS 库骨架，如下所示：

```php
$(document).ready(function ($)
{
var Status = {
};
});

```

您可以看到变量`Status`包含一个使用 JavaScript 对象文字（在大括号内封闭的键值对）的对象。

```php
var obj = { a : function(){ }, b : function(){ } }

```

请注意，库代码被包装在 jQuery `$(document).ready()`函数中。

1.  让我们在`status`对象内编写一些实用的 JavaScript 方法，并键入以下`currentTime()`方法：

```php
currentTime: function (timestamp) {
if (typeof timestamp !== 'undefined' && timestamp !== '')
var currentTime = new Date(timestamp * 1000);
else
var currentTime = new Date();
var hours = currentTime.getHours();
var minutes = currentTime.getMinutes();
var timeStr = '';
if (minutes < 10) {
minutes = "0" + minutes
}
timeStr = ((hours > 12) ? (hours - 12) : hours) + ":" + minutes + ' ';
if (hours > 11) {
timeStr += "PM";
} else {
timeStr += "AM";
}
return timeStr;
},

```

`currentTime()`方法返回从 Unix 时间戳转换的本地时间。请记住，如果时间戳不存在，则返回当前本地时间。示例输出可能是上午 3:22 或下午 2:30。

您可以看到在`var currentTime = new Date(timestamp * 1000);`这一行中，Unix 时间戳已经转换为毫秒级的 JS 时间戳，并创建了一个新的 Date 对象。小时和分钟分别从`currentTime.getHours()`和`currentTime.getMinutes()`方法中获取。请注意，`currentTime()`方法用逗号（,）分隔。

1.  将`currentDate()`方法添加到`Status`对象中，如下所示：

```php
currentDate: function (timestamp) {
var m_names = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"];
if (typeof timestamp !== 'undefined' && timestamp !== '')
var d = new Date(timestamp * 1000);
else
var d = new Date();
var curr_date = d.getDate();
var curr_month = d.getMonth();
var curr_year = d.getFullYear();
var sup = "";
if (curr_date === 1 || curr_date === 21 || curr_date === 31)
{
sup = "st";
}
else if (curr_date === 2 || curr_date === 22)
{
sup = "nd";
}
else if (curr_date === 3 || curr_date === 23)
{
sup = "rd";
}
else
{
sup = "th";
}
return m_names[curr_month] + ' ' + curr_date + sup + ', ' + curr_year;
},

```

`currentDate()`方法返回转换后的本地日期。与`步骤 4`中的先前方法类似，它从 Date 对象中获取日期、月份和年份。

1.  现在，添加`getLocalTimeStr()`方法如下：

```php
getLocalTimeStr: function (gmtTimestampInSec) {
return 'at ' + this.currentTime(gmtTimestampInSec)
+ ' on ' + this.currentDate(gmtTimestampInSec);
}

```

上述方法返回连接的格式化时间和日期字符串。

## 刚刚发生了什么？

jQuery 为我们提供了一个称为`ready`的文档对象上的特殊实用程序，允许我们在 DOM 完全加载完成后执行代码。使用`$(document).ready()`，我们可以排队一系列事件，并在 DOM 初始化后执行它们。`$(document).ready()`方法接受一个函数（匿名）作为其参数，该函数在 DOM 加载完成后被调用，并执行函数内的代码。

如果您正在开发用于分发的代码，始终重要的是要补偿任何可能的名称冲突。因此，我们将`$`作为匿名函数的参数传递。这个`$`在内部指的是`jQuery`，因此在脚本之后导入的其他`$`函数不会发生冲突。

最后，为了从 UNIX 时间戳获取本地日期和时间，我们在自定义 JavaScript 库中添加了实用方法。至于用法示例，`currentDate()`实用方法可以从对象的内部和外部范围分别调用为`this.currentDate()`和`Status.currentDate()`。

# 操作时间-显示状态列表

我们将把接口元素放在`index.php`中，并以适当的方式嵌入 PHP 代码。因此，让我们按照以下步骤进行：

1.  修改`index.php`文件，在`<body>`标记内，删除 PHP 标记，并将状态条目放在`<div>`容器标记和元素中，如下所示：

```php
<body>
<div id="container" class="container">
<h1>Status Poster</h1>
<ul>
</ul>
</div>
</body>

```

从这段代码中，您可以看到我们的应用程序界面将位于 id 为 container 的`<div>`容器内，`<ul>`标记将保存内部`<li>`项的堆栈，其中包含用户的状态帖子，这些帖子将由一些 PHP 代码填充。

1.  在`index.php`文件的`<!DOCTYPE html>`标记上方的顶部 PHP 代码片段中，键入以下行，以集成`StatusPoster`类，使代码片段看起来类似于以下内容：

```php
<?php
require_once 'StatusPoster.php';
$result = $status->getStatusPosts();
define('BASE_URL', 'http://localhost/chapter3/');
?>

```

从代码中，一次需要 PHP 类文件来集成类，并在我们的应用程序中使用其实例。在这一行，我们调用了`$status`对象的`getStatusPosts()`方法，以从数据库中获取所有状态条目，并将返回的结果数组存储到`$result`中。

1.  为了显示状态流，我们将编写以下 PHP 代码，以在`<ul>`标记内循环遍历`$result`数组：

```php
<?php
if (is_array($result))
foreach ($result as $row) {
echo '
<li>
<a href="#">
<img class="left" src="images/user/' . $row['image'] . '" alt="picture">
</a>
<div class="content left">
<a href="#">' . $row['name'] . '</a>
<div class="status">' . $row['status'] . '</div>
<span class="localtime" data-timestamp="' . $row['timestamp'] . '"></span>
</div>
<div class="clearer"></div>
</li>
';
}
?>

```

首先，对`$result`数组进行了正确类型的验证。我们循环遍历数组，将每个条目放入`$row`变量中。前面的服务器脚本为每个状态条目生成一个`<li>`项，每个`<li>`项包含一个用户图像、一个超链接名称、一个用户状态文本和一个 UNIX 时间戳元素。请注意，时间戳已经转储到具有类名`localtime`的`span`元素的`data-timestamp`属性中。为了更好地理解，状态列表的项目骨架如下图所示：

![操作时间-显示状态列表](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_03_14.jpg)

1.  现在，我们需要在 DOM 准备就绪时使用 jQuery 代码转换`data-timestamp`属性中的 PHP 转储时间戳。在`status.js`库的`Status`对象中添加以下方法：

```php
showLocalTime: function () {
var spans = $('span.localtime[data-timestamp]');
spans.each( function () {
var localTimeStr = Status.getLocalTimeStr( $(this).attr('data-timestamp') );
$(this).html(localTimeStr);
});
},

```

使用 jQuery 选择器的方法选择所有具有`data-timestamp`属性的 span 元素为`$('span.localtime[data-timestamp]');`。对于每个元素，它使用`$(this).attr('data-timestamp')`解析时间戳，并传递给`Status.getLocalTimeStr()`以获取本地时间字符串。最后，它将每个`span`元素的内部 HTML 设置为该本地时间字符串。

1.  为了使`Status.showLocalTime()`立即与 DOM 一起工作，调用该方法，如下所示，在`ready()`方法的终止行之前：

```php
$(document).ready(function ($)
{
var Status = {
//whole library methods...
};
Status.showLocalTime();
});

```

因此，用户将在每个帖子下显示其本地日期和时间。

1.  最后，指向项目 URL 的浏览器，或者从工具栏中按下**运行项目（第三章）**按钮，或者从 IDE 中按下*F6*，以显示状态流显示列表，看起来类似于以下屏幕截图：![行动时间-显示状态列表](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_03_15.jpg)

## 刚刚发生了什么？

PHP 脚本将`<li>`项转储到`<ul>`标记中，界面 JS 代码`Status.showLocalTime()`；解析转储的时间戳，并在 DOM 准备就绪时以用户的本地时间显示它。如果我们显示 UNIX 时间戳的日期和时间而不进行时区转换，那么我们可能需要提供服务器的日期和时间，这可能不符合用户的时间。再次，用户的本地时区对服务器来说是未知的，对客户端界面来说是已知的。因此，我们以一种快速的方式使用客户端代码来解决本地时间显示问题。

因此，我们已经完成了项目的第一部分。我们已经创建了一个界面，状态流看起来像 Facebook。

到目前为止，我们已经能够使用 IDE 处理数据库操作，并使用 NetBeans 代码模板创建 PHP 类和方法，我们还能够为我们的 Web 应用程序创建必要的用户界面文件。

## 尝试一下-调整 CSS

对于较大的状态帖子，界面可能会在每个`<li>`内部找到破损，因此最好修复用户界面问题。您可以在相应的 CSS 文件中的`.content`类中添加固定宽度。

## 小测验-理解 CSS

1.  CSS 代表什么？

1.  级联样式表

1.  级联样式表

1.  多彩样式表

1.  计算机样式表

1.  引用外部样式表的正确 HTML 格式是什么？

1.  `<link rel="stylesheet" type="text/css" href="mystyle.css">`

1.  `<style src="mystyle.css">`

1.  `<stylesheet>mystyle.css</stylesheet>`

1.  需要添加到 CSS 类中的属性是什么，以在该元素周围留出一些空间？

1.  `填充`

1.  `边距`

1.  `padding-bottom 和 padding-top`

1.  `显示`

# 使用 PHP-AJAX 孵化状态发布者

用户的状态文本应该在不重新加载页面的情况下提交到服务器。为此，我们可以使用 AJAX 方法，其中用户的数据可以使用 HTTP 方法发送到服务器，并等待服务器的响应。一旦服务器响应，我们可以以编程方式解析响应数据，并可能做出我们的决定。在我们的情况下，如果服务器以成功结果响应，我们将根据此更新我们的界面 DOM。

简单地说，我们将使用 AJAX 将用户的状态文本提交到位于`index.php`的服务器端 PHP 代码，使用`HTTP POST`方法，并配置从服务器期望的数据类型为 JSON。因此，我们可以轻松解析 JSON 并确定状态是否成功保存。从成功的服务器响应中，我们可以更新状态流显示列表，并将新发布的状态放在该列表的顶部。但是，在任何失败或错误的情况下，我们也可以解析错误消息并将其显示在界面中。

# 行动时间-向界面添加状态输入框

在本节中，我们将简单地添加一个 HTML 表单，其中包含一个文本区域用于状态发布，以及一个用于表单提交的**提交**按钮。我们将在`index.php`的`<ul>`标签之前添加包含`div`元素的表单。

1.  为了添加状态发布框，我们将在`div#container`内添加以下 HTML 代码，位于`<ul>`标签之前：

```php
<div class="inputbox">
<form id="statusFrom" action="index.php" method="post" >
<textarea name="status" id="status_box">Write your status here</textarea>
<input class="right" type="submit" name="submit" id="submit" value="Share" />
<div id="postStatus" class="postStatus clearer hidden">loading</div>
</form>
</div>

```

因此，`div.inputbox`将包含带有`share`或`submit`按钮的状态输入框。`div#postStatus`将显示发布提交进度信息状态，以传达状态是否成功发布。在 AJAX 发布进行中，我们将使用一些花哨的加载`.gif`图像。`ajaxload.gif`图像也保存在项目的`images`目录中。

1.  现在，使用项目 URL 刷新您的浏览器，状态输入框应该看起来与以下截图类似：![行动时间-将状态输入框添加到界面](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_03_16.jpg)

## 刚刚发生了什么？

查看`form`标签打开的行，`<form id="statusFrom" action="index.php" method="post" >`。可以使用 jQuery 选择包含脚本名称为`index.php`的`action`属性的`id`属性选择表单，这意味着它将被发布到我们正在工作的同一文件。您可以看到`method`属性包含表单将被提交的 HTTP 方法类型。我们不需要 jQuery 代码的`action`和`method`属性。相反，在这种情况下，我们将保留它们。如果浏览器的 JavaScript 被禁用，那么我们仍然可以以`POST`方法提交表单到`index.php`。

请注意，`div#postStatus`默认使用 CSS 类`hidden`隐藏，并且只有在 AJAX 工作进行中时才会可见。

### 注意

有关 NetBeans IDE 键盘快捷键，请参阅*附录*。

## 将新的状态发布模板添加到 index.php

在编写代码时，我们需要保持行为的分离，即 HTML 标记应与 JavaScript 代码分开。此外，我们需要更新状态流显示列表，并在不刷新页面的情况下将新的状态发布放在列表顶部。

我们知道每个状态条目可以组织在`<li>`项内，在该项内，用户名、图片和带有本地日期时间的状态发布等条目值应该使用适当的标记元素进行构建。因此，我们需要为新的状态发布创建一个条目模板。使用模板，JavaScript 代码可以生成一个新的界面条目，放置在状态流的顶部。

在文档`<body>`标签内，`div#container`结束标签下方添加以下模板：

```php
<div id="statusTemplate" class="hidden">
<li>
<a href="#">
<img class="left" src="#SRC" alt="picture">
</a>
<div class="content left">
<a href="#">#NAME</a>
<div class="status">#STATUS</div>
<span class="localtime">#TIME</span>
</div>
<div class="clearer"></div>
</li>
</div>

```

我们可以看到有一些占位符，例如`#SRC`用于个人资料图片的图像 URL，`#NAME`用于条目的用户名，`#STATUS`用于状态文本，`#TIME`用于本地日期时间。通过复制此模板，这些占位符可以替换为适当的值，并在`<ul>`元素前添加。请注意，整个模板都放在一个隐藏的`div`元素中，以排除它不被用户看到。

## 创建 AJAX 状态发布器

AJAX 用于在浏览器和 Web 服务器之间频繁通信。这种著名的技术被广泛用于**Rich Internet Applications**（**RIA**），而 jQuery 提供了一个非常简单的 AJAX 框架。AJAX 发布器将在不刷新页面的情况下发布状态文本，并将最新的状态条目更新到顶部的状态堆栈中。

# 行动时间-使用 JQuery AJAX 创建状态发布器

我们将在`status.js`库中创建一个`post()`方法，并将该方法与**提交**按钮的单击事件绑定。我们将通过按照以下步骤逐行添加代码来创建该方法：

1.  在我们的`status.js`库中，输入以下`post()`方法，以逗号结尾，将其添加到`Status`库中：

```php
post: function () {
var myname = 'M A Hossain Tonu', myimage = 'images/user/tonu.jpg';
var loadingHtml = '<img src="images/ajaxload.gif" alt="loadin.." border="0" >';
var successMsg = 'Status Posted Successfully ...';
var statusTxt = $('#status_box').val(), postStatus = $('#postStatus');
},

```

在变量声明部分，`myname`和`myimage`变量包含了一个演示已登录用户的名称和个人资料图片 URL。`loadingHtml`包含用于显示加载 GIF 动画的 img 标签。此外，您可以看到`statusTxt`包含使用`$('#status_box').val()`获取的状态框值，`postStatus`缓存了`div#postStatus`元素。

1.  现在，在`post()`方法中的变量声明部分之后添加以下行：

```php
if ((statusTxt.trim() !== '' && statusTxt !== 'Write your status here'
&& statusTxt.length < 500) === false) return;

```

此代码验证了`statusTxt`是否为空，是否包含默认输入消息，以及是否在 500 个字符的最大输入限制内。如果任何此类验证失败，则在执行后返回该方法。

1.  为了在 AJAX 操作进行时显示动画加载，我们可以在上一行*(步骤 2)*之后添加以下行：

```php
postStatus.html(loadingHtml).fadeIn('slow');

```

它会在带有加载图像的 div 元素`#postStatus`中淡入。

1.  现在，是时候在方法中添加 AJAX 功能了。在上一行*(步骤 3)*之后添加以下 jQuery 代码：

```php
$.ajax({
data: $('form').serialize(),
url: 'index.php',
type: 'POST',
dataType: 'json',
success: function (response) {
//ajax success callback codes
},
error: function () {}
});

```

在这段代码中，您可以看到已添加了 AJAX 骨架，并且使用 jQuery `$.ajax()`方法传递了配置对象。配置对象是使用 JavaScript 对象字面量技术创建的。您可以看到这些键值对；例如，`data`包含使用`$('form').serialize()`序列化的表单值，`url`保存了数据要提交到的服务器 URL，`dataType`设置为 JSON，这样我们将在`success()`回调方法中传递一个 JSON 对象。查看默认的`success`和`error`回调方法；您可以看到一个变量`response`传递到`success`回调中，实际上是使用 AJAX 从服务器获取的 JSON 对象。

1.  在成功的 AJAX 提交中，让我们在`success`回调方法中输入以下代码：

```php
if (response.success === true) {
postStatus.html('<strong>'+successMsg+'</strong>');
$('#status_box').val('');
var statusHtml = $('#statusTemplate').html();
statusHtml = statusHtml
.replace('#SRC', myimage)
.replace('#NAME', myname)
.replace('#STATUS', statusTxt)
.replace('#TIME', Status.getLocalTimeStr());
$('#container ul').prepend(statusHtml);
} else {
postStatus.html('<strong>' + response.error + '</strong>').fadeIn("slow");
}

```

由于`response`传入的是一个 JSON 对象，我们检查`response`对象的`response.success`属性，其中包含布尔值 true 或 false。如果`response.success`属性未设置为`true`，则在元素`div#postStatus`中显示来自 response.error 的错误消息。

因此，对于来自服务器的成功响应，我们在`successMsg`中显示消息，并清除输入`text_area#status_box`的值以进行下一次输入。现在，在`var statusHtml = $('#statusTemplate').html();`行中，我们将条目模板缓存到`statusHtml`变量中。在连续的行中，我们用正确的条目值替换了占位符，并最终在`<ul>`元素中前置了新的条目项，使用了`$('#container ul').prepend(statusHtml)`行。

1.  为了使用事件触发`Status.post()`，我们将该方法与`Submit`（**分享**）按钮上的*click*事件绑定。在`status.js`库中的`$(document).ready()`方法终止之前（`Status.showLocalTime()`行之后）添加以下代码：

```php
$('#submit').click(function () {
Status.post();
return false;
});

```

## 刚刚发生了什么？

我们已经将表单值序列化以通过 AJAX 发送到服务器，并且服务器响应被 jQuery AJAX 功能解析为 JSON 对象，传递到`success`回调方法中。我们检查了`response`对象是否携带了`success`标志。如果找到了成功标志，我们使用它来解析状态条目模板，准备条目 HTML，并将条目置于状态列表顶部。

因此，我们将 AJAX 状态发布方法`post()`绑定到状态**提交**按钮，当单击按钮时触发。请注意，我们在`post()`方法执行时在用户界面上反映`success`或`error`消息，甚至显示加载动画。因此，我们使我们的应用程序具有响应性。

现在，让我们添加服务器代码来响应 AJAX 请求。

### 再次使用 StatusPoster.php 进行操作。

为了将条目插入数据库表的`status`字段，我们向我们的 PHP 类添加了一个`StatusPoster`方法，命名为`insertStatus`，如下所示：

```php
public function insertStatus(array $values){
$sql = "INSERT INTO status ";
$fields = array_keys($values);
$vals = array_values($values);
$sql .= '('.implode(',', $fields).') ';
$arr = array();
foreach ($fields as $f) {
$arr[] = '?';
}
$sql .= 'VALUES ('.implode(',', $arr).') ';
$statement = $this->db->prepare($sql);
foreach ($vals as $i=>$v) {
$statement->bindValue($i+1, $v);
}
return $statement->execute();
}

```

该方法接受传入的关联数组`$values`中的字段值，为`status`表准备 MySQL 插入查询，并执行查询。请注意，我们已将字段名称保留在`$fields`数组中，并且已从传递的数组的键和值中提取出`$vals`数组中的字段值。我们已经在准备的语句中使用`?`代替所有给定的值，每个值都将用`PDOStatement::bindValue()`方法绑定。`bindValue()`方法将一个值绑定到一个参数。

请注意，包含直接用户输入的变量应在发送到 MySQL 的查询之前进行转义，以使这些数据安全。PDO 准备的语句会为您处理转义的绑定值。

最后，无论`execute()`方法是否成功，该方法都会返回。

### 将 AJAX 响应器代码添加到 index.php

在位于`index.php`文件顶部的 PHP 代码中添加以下 AJAX 响应器代码，位于`require_once 'StatusPoster.php';`的下面：

```php
if (isset($_POST['status'])) {
$statusStr = trim($_POST['status']);
$length = mb_strlen($statusStr);
$success = false;
if ($length > 0 && $length < 500) {
$success = $status->insertStatus(array(
'name' => 'M A Hossain Tonu',
'image' => 'tonu.jpg',
'status' => $statusStr,
'timestamp' => time()
));
}
if (isset($_SERVER['HTTP_X_REQUESTED_WITH']) && $_SERVER['HTTP_X_REQUESTED_WITH'] === 'XMLHttpRequest') {
echo ($success) ? '{"success":true}' : '{"error":"Error posting status"}';
exit;
}
}

```

此代码检查是否存在由`$_POST['status']`包含的任何`POST`值；如果是，则修剪发布的状态值，并确定包含在`$statusStr`中的发布的状态字符串的长度。使用多字节字符串长度函数`mb_strlen()`来测量长度。如果字符串长度在提到的范围内，则使用关联数据库列名将状态条目值压缩到数组中，并将`StatusPoster`类的`insertStatus`方法传递以保存状态。

由于`insertStatus`方法对于成功的数据库插入返回`true`，我们将返回的值保留在`$success`变量中。此外，可以通过验证`$_SERVER['HTTP_X_REQUESTED_WITH']`的值是否为`XMLHttpRequest`来在服务器上识别 AJAX 请求。

因此，对于 AJAX 请求，我们将传递 JSON 字符串；如果`$success`包含布尔值`true`，则为`{"success":true}`，如果`$success`包含布尔值`false`，则为`{"error":"Error posting status"}`。

因此，检查值`XMLHttpRequest`确保仅对 AJAX 请求提供 JSON 字符串传递。最后，前面的 PHP 代码插入了带有或不带有 AJAX 请求的状态帖子。因此，在客户端浏览器中禁用 JavaScript 的情况下，状态发布者表单仍然可以被提交，并且提交的数据也可以被插入。

### 注意

本章的完整项目源代码可以从 Packt 网站 URL 下载。

## 测试状态发布者的可用性

我们已经准备好状态发布者项目。接口 JavaScript 代码将数据发送到服务器，服务器端代码执行指示的操作和响应，接口代码将 DOM 与响应一起更新。

您可以通过在框中输入状态文本并单击**分享**按钮来测试状态发布者。单击**分享**按钮后，您应该在输入框下方看到一个加载图像。几秒钟后，您将看到**状态发布成功**的消息，因为状态已在状态显示列表中预置。最后，在发布状态**"hello world"**后，屏幕看起来类似于以下内容：

![测试状态发布者的可用性](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_03_17.jpg)

完成的项目目录结构看起来类似于以下内容：

![测试状态发布者的可用性](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_03_18.jpg)

## 突击测验 - 复习 jQuery 知识

1.  jQuery 使用哪个符号作为 jQuery 的快捷方式？

1.  `?` 符号

1.  `％` 符号

1.  `$` 符号

1.  jQuery 符号

1.  以下哪个是正确的，使用`#element_id` ID 获取输入框的值？

1.  `$('#element_id').value()`

1.  `$('#element_id').text()`

1.  `$('#element_id').html()`

1.  `$('#element_id').val()`

1.  以下哪个返回 JavaScript 中存储在`stringVar`变量中的字符串的长度？

1.  `stringVar.size`

1.  `length(stringVar)`

1.  `stringVar.length`

1.  添加`DIV`元素的正确语句是什么？

1.  `$('#container').append('<div></div>')`;

1.  `$('#container').html('<div></div>')`;

1.  `$('#container').prepend('<div></div>')`;

1.  以下哪个将导致元素逐渐消失？

1.  `$('#element').hide()`;

1.  `$('#element').fadeOut('slow')`;

1.  `$('#element').blur('slow')`;

1.  以下哪个将是获取`element1`的内部 HTML 作为`element2`的内部 HTML 的正确代码？

1.  `$('#element2').html( ) = $('#element1').html( )`;

1.  `$('#element2').html( $('#element1').innerHTML )`;

1.  `$('#element1').html( $('#element2').html() )`;

1.  `$('#element2').html( $('#element1').html( ) )`;

## 尝试一下——清理状态输入

由于用户提供的状态输入未经过足够的清理，存在原始标记或 HTML 标记放置在输入中会破坏界面的可能性。因此，正确地清理状态输入，并且在 AJAX 成功时显示这个新的状态条目的 JavaScript 代码也要注意不刷新页面。如果您不希望允许标记，您可以在将其插入到`INSERT`查询之前使用`strip_tags()`方法剥离标记。再次，如果您希望保留标记，您可以使用 PHP 的`htmlspecialchars()`函数。您还需要重构您的 JS 代码；也就是说，您可以使用`$('#status_box').text()`而不是`$('#status_box').val()`。

# 总结

在本章中，我们完成了一个真实的 PHP 项目，现在能够使用 NetBeans IDE 创建和维护 PHP 项目。此外，我们现在熟悉了使用 IDE 进行更快速开发的方法。练习这些键盘快捷键、代码补全快捷码、代码生成器和其他 IDE 功能将加快您的步伐，使您的开发更加顺利。所有这些功能都旨在简化您的任务，使您的生活更轻松。

我们特别关注了：

+   设置数据库

+   创建 JavaScript 库

+   真实的 PHP AJAX 网络应用开发

+   使用 NetBeans 代码模板

到目前为止，我们已经使用 NetBeans 开发了一个 PHP 项目。在下一章中，我们将对一些演示 PHP 项目进行调试和测试，以便在处理项目中的关键时刻时具备更多的技能。
