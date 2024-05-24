# Linux 电子邮件教程（二）

> 原文：[`zh.annas-archive.org/md5/7BD6129F97DE898479F1548456826B76`](https://zh.annas-archive.org/md5/7BD6129F97DE898479F1548456826B76)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：提供 Webmail 访问

您在之前的章节中学习了如何设置和配置电子邮件服务器。现在您的电子邮件服务器已经准备好服务了，您的用户将如何访问它？在本章中，您将学习以下内容：

+   webmail 访问解决方案的好处和缺点

+   SquirrelMail webmail 软件包

+   设置和配置 SquirrelMail

+   什么是 SquirrelMail 插件以及它们能做什么

+   如何使 SquirrelMail 更安全

在下一节中，我们将介绍 SquirrelMail 软件包，并检查这个和其他 webmail 访问解决方案的优缺点。之后，我们将逐步跟进 SquirrelMail 的安装和配置。接下来，我们将检查插件的安装，并包括有用插件的参考。最后，我们将提供一些关于如何保护 SquirrelMail 的提示。

# webmail 解决方案

Webmail 解决方案是在服务器上运行的程序或一系列脚本，可以通过网络访问，并提供类似于传统邮件客户端的电子邮件功能。它被 Yahoo! Mail、Microsoft Hotmail、Microsoft Outlook Web Access 和 Gmail 用作其电子邮件解决方案的主要界面。您可能已经熟悉各种形式的 webmail。

尽管我们将专门研究 SquirrelMail webmail 解决方案，但 SquirrelMail 的好处和缺点适用于市场上大多数 webmail 系统。从这个角度来看，我们将从一个一般的角度来处理这个问题，然后详细介绍 SquirrelMail 软件包。

## 好处

本节将重点介绍安装和维护 webmail 解决方案所提供的优势。与任何列表一样，它并不完全全面。许多好处将特定于特定情况；重要的是仔细审查和考虑以下特质如何影响您的个人情况。

我们将在本节中探讨的主要优点如下：

+   简单快捷的访问，几乎不需要设置

+   简单的远程访问

+   无需维护客户端软件或配置

+   提供用户界面来配置邮件服务器选项

+   可能的安全好处

### 简单快捷的访问

尽管传统的邮件访问解决方案非常适合某些情况，但通常很难设置和维护。通常，这涉及在客户端的本地计算机上安装软件并进行配置。这可能很困难，特别是在用户需要自己设置软件的情况下。配置通常更加困难，因为一些用户可能不够有能力甚至无法遵循非常详细的一系列说明。这些说明还需要为许多不同的邮件客户端在许多不同的平台上提供和维护。

然而，webmail 解决方案并没有大多数这些问题。所有用户的设置都可以在服务器上配置，因为应用程序本身驻留在服务器上。这意味着用户几乎不需要设置时间。一旦他们收到登录凭据，他们就可以访问 webmail 站点，并立即访问所有的邮件。用户能够立即访问站点发送和接收电子邮件。

由于互联网现在如此普遍，许多用户将熟悉 Google Mail 和 Windows Live Hotmail 等提供免费电子邮件服务的 webmail 站点。然而，开源软件包提供的用户界面可能更为原始，缺乏一些视觉特性。Squirrelmail 提供了访问电子邮件的功能，包括发送和接收附件，并提供了良好的用户界面。

值得一提的是，webmail 解决方案可以提供某些传统邮件客户端所称的 groupware 功能。这些功能让群体以补充电子邮件通信的方式进行沟通和协调。groupware 组件的示例包括私人日历、共享日历、会议安排、待办事项列表和其他类似工具。

这些应用程序可以预先配置，以便用户可以立即开始使用它们，而无需自行配置。SquirrelMail 网站提供了实现这些功能的多个插件。

### 便捷的远程访问

传统邮件访问软件的另一个问题是它不具备可移植性，因为电子邮件客户端需要在计算机上安装和配置。一旦在特定计算机上下载、安装和配置，它只能在该计算机上访问。没有网络邮件，外出的用户将无法从朋友的计算机、移动设备或机场的互联网亭访问电子邮件。

然而，在网络邮件解决方案中，可以从任何具有互联网连接的位置访问电子邮件。员工可以从任何具有互联网连接和合适浏览器的计算机访问他们的工作电子邮件。

作为管理员，您可以选择允许或拒绝用户在不安全的情况下访问电子邮件。通过要求连接加密，您可以确保用户在远程位置与服务器的通信是安全的。

### 无需维护客户端

即使软件邮件客户端已安装并正确配置，也必须进行维护。当发布新版本时，所有客户端都必须更新。这并不一定是一项容易的任务。软件如果不能按预期工作，可能会导致大量的支持呼叫。

在每个客户端上更新软件可能是一个非常大的管理负担。事实上，许多昂贵的软件包都是专门用于自动更新单个机器上的软件。尽管如此，通常会出现特定于每台本地机器的问题，必须单独解决。向远程分支位置或远程工作者传达说明或通知可能也很困难。使用网络邮件解决方案，这是不必要的。

与此相反，网络邮件解决方案是集中维护和管理的。网络邮件应用程序驻留在服务器上。使用网络邮件，只需要升级网络服务器和网络邮件包。任何异常或问题都可以在升级之前或期间处理。软件升级本身可以在测试系统上运行，然后再部署到实际系统上。虽然 SquirrelMail 的设置更改很少，但可以更新用户的设置，使其与更新版本中引入的更改兼容。

此外，在升级或更改邮件服务器平台时，测试工作量可以大大减少，因为只需要测试受支持的浏览器版本。建议对企业计算机强制使用特定的浏览器版本。与电子邮件客户端不同，无需在所有可能的客户端和软件平台上进行测试。

### 通过用户界面配置邮件服务器接口

许多传统的桌面电子邮件客户端只提供电子邮件功能，没有其他支持任务的功能（例如更改访问密码），这些任务是代表邮件用户执行的。服务器上的某些配置选项可能需要额外的软件应用程序或外部解决方案来满足这些需求。可能需要配置的邮件服务器选项的示例包括每个用户的密码和垃圾邮件过滤设置。

在 SquirrelMail 网络邮件应用程序的情况下，已开发了许多插件提供这些功能。例如，用户可以直接从网络邮件界面更改密码。此外，还有插件和系统允许用户轻松注册，无需任何直接人工干预。如果您有兴趣提供一项服务，用户可以在不需要管理开销的情况下注册，这可能很有用。

### 可能的安全好处

这个问题可以从两个不同的角度来看——这也是标题列为“可能的”安全好处的原因。尽管如此，这仍然是一个有趣的观点需要审查。

在软件客户端访问模型中，电子邮件传统上被下载到本地用户的计算机上，存储在一个或多个个人文件夹中。从安全的角度来看，这可能是一件坏事。系统的用户可能没有受过专业计算机管理员那样的计算机安全意识或知识。未经授权访问最终用户的计算机通常比访问配置正确且安全的服务器容易得多。这意味着偷走公司的笔记本电脑的人可能能够访问该计算机上存储的所有电子邮件。

与客户端访问模型相关的另一个缺点是，即使员工被解雇，他/她仍然可能访问存储在他/她本地办公室计算机上的所有电子邮件。在重要信息得到保护之前可能需要一定的时间。一名不满的工人可能轻松地连接一个外部存储设备到他们的本地办公室计算机，并下载他们想要的任何数据。

值得注意的是，在网络邮件模型中，所有电子邮件都是集中存储的。如果攻击者能够访问中央电子邮件服务器，他/她可能会访问该服务器上存储的所有电子邮件。然而，即使不使用网络邮件系统，如果中央邮件服务器受到损害，攻击者也可能会访问所有电子邮件。

## 缺点

本节重点讨论提供和支持网络邮件解决方案所带来的缺点。前一节中提到的警告适用：这个列表并不完全全面。每种情况都是独特的，可能带来独特的缺点。

我们将讨论网络邮件解决方案的以下缺点：

+   性能问题

+   与大量电子邮件的兼容性

+   与电子邮件附件的兼容性

+   安全问题

### 性能

传统的电子邮件客户端是按照客户端-服务器模型设计的。一个邮件服务器接受并传递电子邮件到其他邮件服务器。然而，桌面邮件客户端可以提供许多额外的提高生产力的功能，如消息排序、搜索、联系人列表管理、附件处理，以及更近期的功能，如垃圾邮件过滤和消息加密。

这些功能中的每一个可能需要一定的处理能力。当在台式电脑上存储一个用户的电子邮件时，所需的处理能力可能微乎其微，但是如果将这些功能应用到单个服务器上的大规模操作，可能会出现问题。

在审查性能问题时，重要的是考虑将访问网络邮件应用程序的潜在用户数量，并相应地调整服务器的大小。一个单一的服务器可能很容易处理大约 300 个用户，但如果用户数量显著增加，服务器负载可能会成为一个问题。

例如，搜索几年的存档邮件可能需要客户端计算机几秒钟。当一个用户使用网络邮件执行此任务时，负载将是相似的。然而，如果许多客户端在短时间间隔或同时请求此操作，服务器可能难以及时处理所有请求。这可能导致页面以较慢的速度提供，或者在极端情况下，服务器无法响应。

如果担心服务器可能无法处理特定用户负载，最好在适当条件下进行负载测试。

### 与大量电子邮件的兼容性

网络邮件解决方案不太适合大量邮件。这个缺点与前一个问题有关，但更多地与发送的数据量有关。即使是在相对较少的用户数量下，大量的电子邮件在网络邮件应用程序中可能很难管理。主要有以下两个原因：

+   首先，每次查看电子邮件和列出文件夹都必须从服务器发送。在传统的邮件客户端中，客户端软件可以管理电子邮件消息，创建适合用户的列表和视图。然而，在网络邮件解决方案中，这是在服务器上执行的。因此，如果有很多用户，这种开销可能会占用服务器资源的相当大比例。

+   其次，与网络邮件应用程序的每次交互都需要一个**超文本传输协议**（**HTTP**）请求和响应。这些消息通常比电子邮件服务器和桌面邮件客户端之间的消息要大。当使用网络邮件客户端时，可能会出现较少的并行性，换句话说，较少的同时进行的事情。桌面邮件客户端可能能够同时检查几个文件夹中的新电子邮件，但网络邮件客户端通常会依次执行这些任务，如果它们自动发生的话。

### 与电子邮件附件的兼容性

网络邮件解决方案不太适合电子邮件附件。由于网络邮件应用程序位于远程服务器上，任何和所有的电子邮件附件都必须首先上传到该服务器上。由于一些原因，可能很难或不可能完成这个操作，特别是对于太多附件或者尺寸较大的附件来说。

由于网络邮件服务器上的存储空间有限，可能会出现上传大附件的困难。大附件可能需要很长时间通过 HTTP 协议上传，甚至在 HTTPS 上需要更长的时间。此外，上传文件可能会受到许多文件大小限制的限制。与 SquirrelMail 一起使用的编程语言 PHP 在其默认配置中对上传文件施加了 2MB 的限制。

上述问题的解决方案可能在于网络邮件访问解决方案的性质——电子邮件和邮件访问软件位于服务器上。在传统的邮件客户端中，用户通常在意识到特定电子邮件消息的内容或大小之前下载电子邮件。与此相反，在网络邮件的情况下，用户可以在不下载附件的情况下查看带有大附件的电子邮件——这对于没有高速互联网连接的用户来说是一个特别的好处。

最后，从服务器下载和上传大型电子邮件附件可能会导致用户界面的性能问题。许多用户对网络邮件应用程序中附件的上传时间感到沮丧，特别是因为在附件上传之前无法发送消息。在传统的邮件客户端中，附件会立即附加，而消息需要时间发送。

### 安全问题

我们将要检查的最后一个问题是安全缺陷的潜在可能性。网络邮件访问解决方案的一个重要特性也带来了潜在的问题。远程访问的好处让用户访问其邮件的本地计算机存在潜在的不安全性。

一个不受直接控制的计算机可能会被第三方控制，意图访问您的信息。通常，计算机不会记录用户的个别按键。网吧和信息亭，甚至员工的家用计算机都可能运行恶意软件。这种恶意软件可能会监视按键和访问的网站。用户必须输入他/她的密码或登录凭据才能访问系统。当这些凭据被恶意软件记录并存储在计算机上时，它们可以被第三方拦截并用于未经授权的访问。

即使我们排除恶意意图，仍然有一些情况可能会构成安全风险。例如，许多现代网络浏览器提供了在输入密码时保存密码的选项。这个密码存储在访问网站的本地计算机上。如果用户登录到网络邮件应用程序并意外地将密码保存在本地计算机上，那么任何可以访问该本地计算机的用户可能可以访问这个密码。

最后，用户可能会无意中保持登录到网络邮件应用程序。在未注销的情况下，任何可以访问该特定计算机的用户可能能够访问用户的邮件帐户。

# SquirrelMail 网络邮件包

以下屏幕截图显示了 SquirrelMail 的登录界面：

![SquirrelMail 网络邮件包](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-eml/img/8648_04_1.jpg)

选择 SquirrelMail 是基于它提供的以下功能的组合：

+   它是一个经过验证、稳定和成熟的网络邮件平台。

+   它已经被下载了两百多万次。

+   它是基于标准的，以纯 HTML 4.0 呈现页面，无需使用 JavaScript。

SquirrelMail 还包括以下功能（以及许多其他功能，通过灵活的插件系统）：

+   强大的 MIME 支持

+   地址簿功能

+   拼写检查器

+   支持发送和接收 HTML 电子邮件

+   模板和主题支持

+   虚拟主机支持

以下屏幕截图显示了收件箱，您可以看到其中一些功能：

![SquirrelMail 网络邮件包](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-eml/img/8648_04_2.jpg)

# SquirrelMail 安装和配置

如果您不熟悉安装网络应用程序，SquirrelMail 的安装和配置可能看起来令人生畏。但是通过接下来将要讨论的说明，可以轻松安装 SquirrelMail。

## 安装前提条件

在继续之前，SquirrelMail 需要安装 PHP 和支持 PHP 脚本的网络服务器。在我们的情况下，我们将使用 Apache2 网络服务器，尽管其他服务器也可以工作。

首先，我们将讨论基本要求，以及如果不符合要求该怎么办。然后，我们将讨论一些可能影响 SquirrelMail 内某些功能的更高级要求。

### 基本要求

在撰写本文时，SquirrelMail 的最新稳定版本是 1.4.19。以下说明适用于此版本。SquirrelMail 安装有两个基本要求。

#### 安装 Apache2

任何支持 PHP 的现代版本的 Apache，无论是 1.x 系列还是 2.x 系列，都可以胜任。这里我们提供了使用 Apache2 的说明。要查询基于 RPM 软件包管理的系统上是否安装了 Apache，请在提示符下发出以下命令：

```
$ rpm -q apache

apache-1.3.20-16

```

如果像刚才看到的示例一样返回了 Apache 的版本，则系统上已安装了 Apache 网络服务器。

要查询基于 Debian 软件包管理的系统上是否安装了 Apache，请在提示符下发出以下命令：

```
$ apt-cache search --installed apache2 | grep HTTP
libapache2-mod-evasive - evasive module to minimize HTTP DoS or brute force attacks
libpoe-component-server-http-perl - foundation of a POE HTTP Daemon
libserf-0-0 - high-performance asynchronous HTTP client library
libserf-0-0-dbg - high-performance asynchronous HTTP client library debugging symbols
libserf-0-0-dev - high-performance asynchronous HTTP client library headers
nanoweb - HTTP server written in PHP
php-auth-http - HTTP authentication
apache2 - Apache HTTP Server metapackage
apache2-doc - Apache HTTP Server documentation
apache2-mpm-event - Apache HTTP Server - event driven model
apache2-mpm-prefork - Apache HTTP Server - traditional non-threaded model
apache2-mpm-worker - Apache HTTP Server - high speed threaded model
apache2.2-common - Apache HTTP Server common files

```

其他使用其他软件包管理系统的发行版也有类似的命令。

如果您没有安装 Apache，最好首先查看您的发行版，寻找 Apache 的副本，比如在您的操作系统安装光盘上或使用在线软件包存储库。或者，您可以访问 Apache 基金会的主页[`www.apache.org`](http://www.apache.org)。

#### PHP

安装 SquirrelMail 需要 PHP 编程语言（版本 4.1.0 或更高版本，包括所有 PHP 5 版本）。要检查系统是否安装了 PHP，只需尝试使用以下命令运行它：

```
$ php -v

```

如果命令成功，您将看到一条描述已安装的 PHP 版本的消息。如果存在 PHP 版本 4.1.0 或更高版本，则您的系统具有所需的软件。否则，您需要安装或升级当前的安装。与 Apache 一样，最好查找您的发行版以安装副本。或者，您也可以访问[`www.php.net`](http://www.php.net)。

### Perl

SquirrelMail 不需要 Perl 编程环境，但有它可用会使 SquirrelMail 的配置更加简单。在本章中，我们假设您将有 Perl 可用以便轻松配置 SquirrelMail。

要在基于 RPM 的系统上查询 Perl 安装，只需尝试使用以下命令运行它：

```
$ perl -v

```

如果命令成功，您将看到一条描述已安装的 Perl 版本的消息。

如果存在任何版本的 Perl，则您的系统具有所需的软件。否则，您需要安装或升级当前的安装。与 Apache 一样，最好查看您的发行版以安装副本。或者，您也可以访问[`www.perl.com/get.html`](http://www.perl.com/get.html)。

### 审查配置

您需要查看 PHP 配置文件`php.ini`，以确保设置正确。在大多数 Linux 系统上，此文件可能位于`/etc/php.ini`。

`php.ini`是一个文本文件，可以使用 Emacs 或 vi 等文本编辑器进行编辑。首先，如果您希望用户能够上传附件，请确保选项`file_uploads`设置为`On`：

```
; Whether to allow HTTP file uploads.
file_uploads = On

```

`php.ini`文件中您可能想要更改的下一个选项是`upload_max_filesize`。此设置适用于上传的附件，并确定上传文件的最大文件大小。将其更改为合理的值可能会有所帮助，例如`10M`。

```
; Maximum allowed size for uploaded files.
upload_max_filesize = 10M

```

## 安装 SquirrelMail

SquirrelMail 可以通过软件包或直接从源代码安装。虽然在任一方法中都不会进行源代码编译，但使用软件包可以更轻松地进行升级。

许多不同的 Linux 和 Unix 发行版都包括 SquirrelMail 软件包。从您的发行版安装适当的软件包以使用二进制方法。在许多 Linux 发行版上，这可能是一个以`squirrelmail…`开头的 RPM 文件。

但是，更新的 SquirrelMail 版本可能不包括在您特定的发行版中或不可用。

以下是使用 Linux 发行版提供的 SquirrelMail 版本的优点：

+   安装 SquirrelMail 将非常简单。

+   它将需要更少的配置，因为它将被配置为使用 Linux 发行版选择的标准位置。

+   更新将非常容易应用，并且迁移问题可以由软件包管理系统处理。

以下是使用 Linux 发行版提供的 SquirrelMail 版本的缺点：

+   它可能不是最新版本。例如，可能已发布了一个修复安全漏洞的更新版本，但 Linux 发行商可能尚未创建新的软件包。

+   有时，Linux 发行版会通过应用补丁来更改软件包。这些补丁可能会影响软件包的操作，并可能使获取支持或帮助变得更加困难。

### 源安装

如果您没有通过发行版安装 SquirrelMail，您将需要获取适当的 tarball。要这样做，请访问 SquirrelMail 网站[`www.squirrelmail.org`](http://www.squirrelmail.org)，然后单击**在此下载**。在撰写本文时，此链接为[`www.squirrelmail.org/download.php`](http://www.squirrelmail.org/download.php)。

有两个可供下载的版本，一个是**稳定版本**，另一个是**开发版本**。除非您有特定原因选择其他版本，通常最好选择稳定版本。下载并将此文件保存到中间位置。

```
$ cd /tmp
$ wget http://squirrelmail.org/countdl.php?fileurl=http%3A%2F%2Fprdownloa
ds.sourceforge.net%2Fsquirrelmail%2Fsquirrelmail-1.4.19.tar.gz

```

接下来，解压缩 tarball（`.tar.gz`）文件。您可以使用以下命令：

```
$ tar xfz squirrelmail-1.4.19.tar.gz

```

将刚创建的文件夹移动到您的 Web 根文件夹。这是 Apache 提供页面的目录。在这种情况下，我们将假设`/var/www/html`是您的 Web 根。我们还将把笨拙的`squirrelmail-1.4.3a`文件夹重命名为更简单的`mail`文件夹。在大多数系统上，您需要超级用户`root`权限才能执行此操作。

```
# mv squirrelmail-1.4.19 /var/www/html/mail
# cd /var/www/html/mail

```

在这里，我们使用了名称`mail`，因此用户将使用的 URL 将是`http://www.sitename.com/mail`。您可以选择另一个名称，比如`webmail`，并在输入的命令中使用该目录名称，而不是`mail`。

为 SquirrelMail 创建一个`data`目录，这样这个文件夹将无法从 Web 访问，也是有用且安全的。

```
# mv /var/www/html/mail/data /var/www/sqmdata

```

重要的是要使这个新创建的文件夹对 Web 服务器可写。为了能够做到这一点，您必须知道您的 Web 服务器所在的用户和组。这可能是`nobody`和`nobody, apache`和`apache`，或者其他内容。您需要验证这一点；它将在您的`httpd.conf`文件中列出为`User`和`Group`条目。

```
# chown -R nobody:nobody /var/www/sqmdata

```

最后，我们将创建一个目录来存储附件。这个目录很特别，虽然 Web 服务器应该有写入附件的权限，但不应该有读取权限。我们使用以下命令创建这个目录并分配正确的权限：

```
# mkdir /var/www/sqmdata/attachments
# chgrp -R nobody /var/www/sqmdata/attachments
# chmod 730 /var/www/sqmdata/attachments

```

SquirrelMail 现在已经正确安装。所有文件夹都已设置正确的权限，以保护中间文件不受窥视。

### 注意

如果用户中止包含上传附件的消息，则 Web 服务器上的附件文件将不会被删除。在服务器上创建一个 cron 作业以从附件目录中删除多余的文件是一个好习惯。例如，创建一个名为`remove_orphaned_attachments`的文件，并将其放在`/etc/cron.daily`目录中。编辑文件，添加以下行：

```
 #!/bin/sh
#!/bin/sh
rm `find /var/www/sqmdata/attachments -atime +2 | grep -v "\."| grep -v _`

```

这将每天运行，并搜索 SquirrelMail 附件目录中的孤立文件，并将其删除。

## 配置 SquirrelMail

SquirrelMail 是通过`config.php`文件进行配置的。为了帮助配置，还提供了一个`conf.pl` Perl 脚本。这些文件位于基本安装目录中的`config/`目录中。

```
# cd /var/www/html/mail/config
# ./conf.pl

```

运行此命令后，您应该看到以下菜单：

![配置 SquirrelMail](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-eml/img/8648_04_3.jpg)

要从菜单中选择项目，请输入适当的字母或数字，然后按*Enter*键。随着 SquirrelMail 的开发，人们注意到 IMAP 服务器的行为并不总是一致的。为了充分利用您的设置，您应该告诉 SquirrelMail 您正在使用哪个 IMAP 服务器。要加载您的 IMAP 服务器的默认配置，请输入**D**选项，并输入您安装的 IMAP 服务器的名称。本书涵盖了 Courier IMAP 服务器，所以您应该选择它。再次按*Enter*，您将返回到主菜单。

我们将在菜单的各个子部分中移动并配置适当的选项。

输入 1，然后按*Enter*键选择**组织首选项**。您将得到一个可以更改的项目列表。您可能希望编辑**组织名称、组织标志**和**组织标题**字段。一旦您对这些进行了满意的修改，输入 R 返回到主菜单。

然后，输入 2 访问**服务器设置**。这允许您设置 IMAP 服务器设置。重要的是，您要将**域**字段更新为正确的值。

在我们的情况下，**更新 IMAP 设置**和**更新 SMTP 设置**的值应该是正确的。如果您想要使用位于不同机器上的 IMAP 或 SMTP 服务器，您可能希望更新这些值。

按下 R，然后按*Enter*键返回到主菜单。

接下来，输入 4 访问**常规选项**。您需要修改此部分中的两个选项。

+   数据目录为`/var/www/sqmdata`。

+   附件目录为`/var/www/sqmdata/attachments`。

+   输入 R，然后按*Enter*键返回主菜单。输入 S，然后按*Enter*键两次将设置保存到配置文件中。最后，输入 Q，然后按*Enter*键退出配置应用程序。

我们已经完成了配置 SquirrelMail 的基本操作所需的设置。您可以随时返回此脚本以更新您设置的任何设置。还有许多其他选项需要设置，包括主题和插件。

# SquirrelMail 插件

插件是扩展或添加功能到软件包的软件。SquirrelMail 是从头开始设计的，非常易于扩展，并包括强大的插件系统。目前，在 SquirrelMail 网站上有 200 多个不同的插件可用。它们可以在[`www.squirrelmail.org/plugins.php`](http://www.squirrelmail.org/plugins.php)获取。

它们提供的功能包括管理工具、视觉增强、用户界面调整、安全增强，甚至天气预报。在接下来的部分，我们将首先介绍如何安装和配置插件。之后，我们将介绍一些有用的插件，它们的功能，如何安装它们，等等。

## 安装插件

这些 SquirrelMail 的附加功能旨在简单设置和配置。事实上，它们中的大多数都遵循完全相同的安装过程。但是，有些需要自定义设置说明。对于所有插件，安装过程如下：

1.  下载并解压插件。

1.  如有需要，执行自定义安装。

1.  在`conf.pl`中启用插件。

## 示例插件安装

在本节中，我们将介绍**兼容性插件**的安装。为了安装为旧版本 SquirrelMail 创建的插件，需要此插件。无论您的安装有多简单，兼容性插件很可能是您设置的一部分。

### 下载和解压插件

SquirrelMail 的所有可用插件都列在 SquirrelMail 网站上，网址为[`www.squirrelmail.org/plugins.php`](http://www.squirrelmail.org/plugins.php)。

某些插件可能需要特定版本的 SquirrelMail。请验证您已安装此版本。一旦找到插件，请将其下载到 SquirrelMail 根文件夹中的`plugins/`目录。

您可以通过单击 SquirrelMail 插件网页上**杂项**类别中的插件页面上的**杂项**类别来找到兼容性插件。此页面列有**杂项**类别中的插件列表。找到兼容性，然后单击**详细信息和下载**，然后下载最新版本。

![下载和解压插件](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-eml/img/8648_04_4.jpg)

将 tarball 下载到 SquirrelMail 插件目录。

```
# cd /var/www/mail/plugins
# wget http://squirrelmail.org/countdl.php?fileurl=http%3A%2F%2Fwww.
squirrelmail.org%2Fplugins%2Fcompatibility-2.0.14-1.0.tar.gz

```

一旦您将插件下载到`plugins`目录中，使用以下命令解压缩它：

```
# tar zxvf compatibility-2.0.14-1.0.tar.gz

```

### 注意

如果已经安装了同名插件，则可能会覆盖其文件。请验证您是否没有同名插件，或在解压 tarball 之前保存文件。

### 执行自定义安装

当前版本的兼容性插件不需要任何额外的配置。但是，您应该始终检查插件的文档，因为某些其他插件可能需要自定义安装。一旦您解压了插件包，安装说明将列在新创建的`plugin`目录中的`INSTALL`文件中。在在配置管理器中启用插件之前，建议您先检查安装说明，因为某些插件可能需要自定义配置。

### 在 conf.pl 中启用插件

在配置编辑器的主菜单中，选项号码 8 用于配置和启用插件。启动`conf.pl`并选择选项**8**。

```
# cd /var/www/mail/plugins
# cd ../config
# ./conf.pl
SquirrelMail Configuration : Read: config_default.php (1.4.0) 
--------------------------------------------------------- 
Main Menu -- 
[...] 
7\. Message of the Day (MOTD) 
8\. Plugins 
9\. Database
[...] 
Command >>

```

当您第一次选择此选项时，应该会得到以下显示：

![在 conf.pl 中启用插件](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-eml/img/8648_04_5.jpg)

所有已安装和启用的插件都列在**已安装插件**列表下。所有已安装但未启用的插件都列在**可用插件**列表下。

一旦您在`plugins/`目录中解压缩了一个插件，它将显示在**可用插件**下。正如您在上一张图中所看到的，有许多已安装的插件，但没有一个是启用的。由于一个故障或配置错误的插件可能会导致 SquirrelMail 停止正常工作，建议逐个启用插件，并在每个插件启用后验证 SquirrelMail 是否正常工作。要启用兼容性插件，请在**可用插件**列表中找到它（在本例中，编号**4)** 并按*Enter*键。兼容性插件现在已安装。可以通过在**已安装插件**列表中找到它们并输入其编号并按*Enter*来禁用插件。

## 有用的插件

现在我们将看到一些有用的 SquirrelMail 插件，您可能考虑安装。

这些信息已经被编制成一个有用的参考，以便在决定是否安装插件时使用。每个插件包含四个特定的类别：

+   **类别：**插件在 SquirrelMail 网站上列出的类别

+   **作者：**按时间顺序编写插件的作者

+   **描述：**插件功能的简要描述

+   **要求：**插件成功安装的先决条件列表

| 插件名称 | 类别 | 作者 | 描述 | 要求 |
| --- | --- | --- | --- | --- |
| 兼容性插件 | 杂项 | Paul Lesneiwski | 此插件允许任何其他插件访问使其向后（和向前）兼容大多数广泛使用的 SM 版本所需的功能和特殊变量。这消除了在许多插件中重复某些功能的需要。它还提供了帮助检查插件是否已安装和设置正确的功能。 | 无 |
| 安全登录 | 登录 | Graham Norbury, Paul Lesneiwski | 如果 SquirrelMail 登录页面尚未被引用的超链接或书签请求，此插件将自动启用安全的 HTTPS/SSL 加密连接。可选地，在成功登录后可以再次关闭安全连接。 | SquirrelMail 版本 1.2.8 或更高版本，具有加密功能的 HTTPS/SSL 能力的 Web 服务器已在 SquirrelMail 安装中正常工作。 |
| HTTP 身份验证 | 登录 | Tyler Akins, Paul Lesniewski | 如果您将 SquirrelMail 放在 Web 服务器上受密码保护的目录后，并且如果 PHP 可以访问 Web 服务器使用的用户名和密码，此插件将绕过登录屏幕并使用该用户名/密码对。 | SquirrelMail >= 1.4.0 |
| 忘记密码 | 登录 | Tyler Akins, Paul Lesneiwski | 此插件提供了一个解决方案，用于避免浏览器潜在的漏洞，自动存储输入到网页中的用户名和密码。 | SquirrelMail >= 1.0.1 |
| HTML 邮件 | 撰写 | Paul Lesneiwski | 此插件允许使用 IE 5.5（及更高版本）和更新的 Mozilla（基于 Gecko 的浏览器，如 Firefox）的用户以 HTML 格式撰写和发送电子邮件。 | SquirrelMail >= 1.4.0 |
| 快速保存 | 撰写 | Ray Black III, Paul Lesneiwski | 此插件会自动保存正在撰写的消息，以防止由于从撰写屏幕浏览到更严重的问题（如浏览器或计算机崩溃）而导致消息内容意外丢失。 | SquirrelMail >= 1.2.9，兼容性插件，支持 JavaScript 的浏览器 |
| 检查配额使用情况（v） | 视觉添加 | Kerem Erkan | 此插件将检查并显示用户的邮件配额状态。 | SquirrelMail 1.4.0+；兼容性插件，版本 2.0.7+，UNIX，IMAP 或已安装和配置的 cPanel 配额 |
| 发送确认 | 杂项 | Paul Lesneiwski | 在成功发送消息后显示确认消息，以及其他功能。 | SquirrelMail >= 1.2.0，兼容性插件 |
| 超时用户 | 杂项 | Ray Black III，Paul Lesneiwski | 如果用户闲置一段时间，将自动注销用户。 | 兼容性插件 |
| 电子邮件页脚 | 杂项 | Ray Black III，Paul Lesneiwski | 此插件会自动在使用 SquirrelMail 发送的消息末尾附加自定义页脚。 | SquirrelMail >= 1.4.2 |
| 更改密码 | 更改密码 | Tyler Akins，Seth E. Randall | 允许用户使用 PAM 或 Courier 身份验证模块更改密码。 | SquirrelMail >= 1.4.0 |
| 通讯录导入导出 | 通讯录 | Lewis Bergman，Dustin Anders，Christian Sauer，Tomas Kuliavas | 允许从**CSV（逗号分隔值）**文件导入通讯录。 | SquirrelMail >= 1.4.4 |
| 插件更新（v0.7） | 管理员的解脱 | Jimmy Conner | 检查当前运行的插件是否有更新。 | SquirrelMail >= 1.4.2 |

还有许多其他插件可处理假期消息、日历、共享日历、笔记、待办事项列表、交换服务器集成、书签、天气信息等等。在 SquirrelMail 网站的**插件**部分查看所有可用的插件。

# 保护 SquirrelMail

SquirrelMail 软件包本身相当安全。它写得很好，不需要 JavaScript 来运行。但是，可以采取一些预防措施，以使 SquirrelMail 成为一个安全的邮件处理解决方案。

+   **使用 SSL 连接：**通过使用 SSL 连接，您可以确保所有通信都将被加密，因此用户名、密码和机密数据在传输过程中不会被拦截。这可以通过安装**Secure Login 插件**来实现。显然，还需要配置用于安全 SSL 访问的 Web 服务器；证书很可能需要生成或获取。

+   **超时未活动用户：**用户可能会保持登录状态并在完成后忽略注销。为了对抗这一点，应在一定时间后注销不活动的用户。**Timeout User 插件**可以实现这一点。

+   对抗“记住密码”：许多现代浏览器提供记住用户密码的功能。尽管这很方便，但这可能是一个很大的安全漏洞，特别是如果用户位于公共终端。为了对抗这一点，安装**Password Forget 插件**。该插件将更改用户名和密码输入字段中的名称，使浏览器更难建议给未来的用户。

+   **不要安装危害安全的插件：**像**Quick Save，HTML Mail**和**View As HTML**这样的插件可能会危害安全。

# 摘要

现在您已经完成了本章，您应该有一个可用的 SquirrelMail 安装，以及对 Web 邮件解决方案的优缺点有更深入的了解。您应该熟悉 Web 邮件解决方案的优缺点。优点包括远程访问、单一的中心维护点和更简单的测试；而缺点包括潜在的性能问题和允许来自潜在受损计算机的远程访问的安全风险。

现在您已经了解了 SquirrelMail 的主要特点，包括其灵活性和插件的可用性，以及安装 SquirrelMail 的先决条件，以及如何确定它们是否已安装。

您还学会了如何配置 SquirrelMail，包括定位、安装和配置插件。您已经了解了一个关键插件——兼容性插件的安装过程。还介绍了几个其他有用的插件。最后，您还学会了一些提高 SquirrelMail 安全性的方法，包括 Web 服务器配置和一些适当的插件。


# 第五章：保护您的安装

对于您的 SMTP 服务器可能发生的所有事情，最糟糕的可能就是它被滥用为开放中继-一个未经您许可就向第三方中继邮件的服务器。 这将消耗大量带宽（可能会很昂贵），耗尽服务器资源（可能会减慢或停止其他服务），并且在时间和金钱上都可能很昂贵。 更严重的后果是，您的电子邮件服务器很可能最终会出现在一个或多个黑名单上，任何引用这些列表的电子邮件服务器都将拒绝接受来自您的服务器的任何邮件，直到您证明它是中继安全的。 如果您需要使用电子邮件来开展业务，您将面临一个大问题。

本章将解释如何：

+   保护 Postfix 免受中继滥用

+   区分静态分配和动态分配的 IP 地址

+   使用 Postfix 为静态 IP 地址配置中继权限

+   使用 Cyrus SASL 进行来自不可预测和动态 IP 地址的身份验证

+   使用安全套接字层防止用户名和密码以明文形式发送

+   配置 Postfix 以打败或至少减缓字典攻击，其中电子邮件发送到域内的许多电子邮件地址，希望其中一些能够到达有效的收件人

# 配置 Postfix 网络映射

当互联网主要由学术界使用时，没有人需要保护他们的邮件服务器免受中继滥用。 实际上，没有多少人拥有邮件服务器，因此允许其他没有电子邮件服务器的人使用您的服务器中继电子邮件被视为对他们的服务。

随着很快就被称为垃圾邮件的人的出现，情况发生了变化。 他们会滥用开放中继向大量远程收件人发送广告，使邮件服务器的所有者为流量付费。

这就是邮件管理员开始限制处理中继权限的时候。 他们过去只允许受信任的 IP 地址进行中继，拒绝来自其他 IP 地址的消息。 在这种情况下，受信任的 IP 地址是指可以静态关联（参见*静态 IP 范围*部分）到属于已知用户的主机的 IP 地址，或者已知属于受信任网络的 IP 地址范围。 这在大多数计算机上运行良好，因为大多数计算机都会有静态 IP 地址（IP 地址不会随时间改变）。

然而，当用户变得移动并使用拨号提供商访问互联网并希望在未知位置使用邮件服务器时，必须找到一种新的方法。 接入提供商会给这些用户动态 IP 地址，也就是说，他们的 IP 地址每次拨号时都会更改。

突然之间，用来区分好用户和坏用户的标准消失了。 邮件管理员要么必须放宽中继权限，允许整个潜在不受信任的 IP 网络使用中继，要么必须找到另一种处理动态 IP 地址中继的方法。 随着时间的推移，出现了几种处理动态 IP 地址中继的方法，例如：

+   SMTP-after-POP

+   虚拟专用网络

+   SMTP 身份验证

这三种方法在其要求和工作方式上有所不同。 以下各节详细介绍了每种方法。

## SMTP-after-POP

从历史上看，许多互联网连接都是拨号连接； 如果一个人希望发送电子邮件，他/她必须离线撰写邮件，启动拨号连接，然后告诉电子邮件客户端“发送和接收”邮件。 在这种情况下，邮件客户端首先发送邮件（通过 SMTP），然后检查服务器（通过 POP）是否有新邮件- SMTP 部分发生在 POP 部分之前。

这使得 SMTP 服务器无法找出发件人是否应该被允许中继，因为动态 IP 与使发件人成为受信任主机的任何其他标准无关。ISP 将能够识别拨号连接的 IP 地址作为他们自己的 IP 地址，并允许中继。来自他们自己网络之外的任何连接通常都会被拒绝。对于一个有着企业网络之外用户的小组织来说，要跟踪所有潜在的有效源 IP 地址是不可能的。

然而，交易可以被颠倒过来，检查邮件可以在发送邮件之前进行。检查邮件需要密码，这意味着用户可以被认证。流行的电子邮件客户端现在可以在启动时检查电子邮件，并定期检查新的电子邮件。如果 SMTP 服务器可以被告知特定 IP 地址的用户已通过 POP 服务器进行了身份验证，它可以允许中继。这就是 SMTP-after-POP 的本质。SMTP 服务器需要知道特定 IP 地址是否有经过身份验证的 POP 用户连接到它。

在最后一次连接到 POP 服务器之后，用户连接的有效时间必须有一个时间限制，否则一个旅行推销员可能会留下一百个不同的 IP 地址作为一个星期的有效中继主机，其中一个以后可能被垃圾邮件发送者占用。如今，电子邮件通常是在用户在线时编写的，并在定期自动检查新邮件之间发送。因此，发送到 SMTP 服务器的任何已编写的电子邮件通常会在进行 POP3 请求后的几分钟内发送，因此时间段可以很短，通常是几十分钟。

SMTP-after-POP 的缺点是，即使您只想允许中继消息，您也需要一个 POP 服务器。如果您不需要它，POP 服务器将使服务器的设置变得复杂。它还可能将您的 SMTP 服务器的更新绑定到您的 POP 服务器以保持兼容性。而且 POP 不是一种安全的身份验证方法，因为它可以被欺骗。

## 虚拟专用网络

**虚拟专用网络**（**VPN**）在验证 VPN 成功后，为客户端分配另一个私有 IP 地址。VPN 服务器将在已知的区块中分配 IP 地址。SMTP 服务器可以配置为允许来自分配给 VPN 的 IP 地址的邮件客户端进行中继。

再次强调，仅仅为了中继邮件而运行 VPN 需要大量的工作。只有在通过 VPN 提供额外的资源和服务时才会有回报，例如访问共享存储、数据库、内部网站或应用程序。

## SMTP 身份验证

**SMTP 身份验证**，也称为**SMTP AUTH**，使用不同的方法来识别有效的中继用户。它要求邮件客户端在 SMTP 对话期间向 SMTP 服务器发送用户名和密码，如果认证成功，它们可以进行中继。

它比运行一个完整的 POP 服务器或 VPN 要简单，而且它解决了在 SMTP 服务器中出现的问题。学会如何为一系列受信任的静态 IP 地址配置服务器后，您将了解如何提供 SMTP AUTH 所需的条件。

## 静态 IP 范围

默认情况下，Postfix 只允许来自自己的网络的主机中继消息。可信任的网络是您为网络接口配置的网络。运行`ifconfig -a`以获取已在系统上配置的列表。

如果您想更改默认设置，您可以使用`mynetworks_style`参数使用一些通用值，或者在`main.cf`中的`mynetworks`参数的值中提供显式的 IP 地址范围。

### 通用中继规则

要配置通用中继规则，您需要将以下值之一添加到`main.cf`中的`mynetworks_style`参数中：

+   `host:` 如果你配置`mynetworks_style = host`，Postfix 将只允许它运行的主机的 IP 地址发送消息到远程目的地。如果你只提供一个 webmail 界面，这可能是可以接受的，但没有桌面客户端能够连接。

+   `class:` 如果你配置`mynetworks_style = class`，Postfix 将允许它服务的网络类（A/B/C 网络类）中的每个主机进行中继。网络类指定了一系列 IP 地址，大约 255 个（C 类），65000 个（B 类），或者 1600 万（A 类）地址。

### 显式中继规则

显式中继规则允许更精细的中继权限。要使用这个，你需要理解用于指定网络地址范围的符号。如果你的网络跨越了从 192.168.1.0 到 192.168.1.255 的范围，那么这可以被指定为 192.168.1.0/24。24 被用作 32 位网络地址的前 24 位对于每个客户端都是相同的。如果你使用 DHCP 服务器（例如，在你的 Linux 服务器或为 DSL 连接提供防火墙），你的网络地址范围可能会被该设备定义，并且你应该在你的 Postfix 设置中使用适当的值。如果你手动分配 IP 地址并硬编码它们，你可以将每个 IP 地址单独指定为/32 范围，或者你可以确保每个 IP 地址在你分配它们后落入一个易于识别的范围内。A 类网络 10.0.0.0/8，B 类网络范围在 172.16.0.0 到 172.31.255.255 之间的 16 个，以及 C 类网络范围在 192.168.0.0 到 192.168.255.255 之间的 256 个。这些都可以用于私人网络地址，并且可以用于内部网络地址。

你可以在`main.cf`的`mynetworks`参数中添加一个远程和本地主机和/或网络的列表。如果你想允许本地主机、LAN 中的所有主机（在下面的示例中 IP 地址为`10.0.0.0`到`10.0.0.254`），以及你家中的静态 IP（这里为`192.0.34.166`）作为一个列表以 CIDR 表示，如下例所示：

```
mynetworks = 127.0.0.0/8, 10.0.0.0/24, 192.0.34.166/32

```

一旦你重新加载 Postfix，新的设置就会生效。

## 动态 IP 范围

在前一节中，你看到了如何允许静态 IP 地址进行中继。本节将展示如何配置 Postfix 允许动态 IP 地址进行中继。

尽管如本章介绍中所述，有几种方法可以实现这一点，但我们只会描述 SMTP 认证的方法。它提供了一个简单而稳定的机制，但设置并不简单。原因是 SMTP AUTH 并不是由 Postfix 自己处理的。另一个软件模块 Cyrus SASL 需要提供和处理 SMTP AUTH 给邮件客户端。你需要配置 Cyrus SASL，Postfix 以及它们之间的相互操作。

# Cyrus SASL

Cyrus SASL（[`cyrusimap.web.cmu.edu/`](http://cyrusimap.web.cmu.edu/)）是卡内基梅隆大学对 SASL 的实现。**SASL**（**简单认证和安全层**），是在 RFC 2222（[`www.ietf.org/rfc/rfc2222.txt`](http://www.ietf.org/rfc/rfc2222.txt)）中描述的认证框架。

SASL 旨在为任何需要使用或提供认证服务的应用程序提供一个与应用程序无关的认证框架。

Cyrus SASL 并不是今天唯一可用的 SASL，但它是第一个出现并在各种应用程序中使用的。例如 Postfix，Sendmail，Mutt 和 OpenLDAP。为了使用 Cyrus SASL，你需要了解它的架构，各个层是如何协同工作的，以及如何配置层的功能。

## SASL 层

SASL 由三层组成——**认证接口，机制**和**方法**。每个层都在处理认证请求时负责不同的工作。

认证过程通常经历以下步骤：

1.  客户端连接到 SASL 服务器。

1.  服务器宣布其能力。

1.  客户端识别在列出的功能中进行身份验证的选项。它还识别可以选择以处理身份验证的机制列表。

1.  客户端选择一种机制并计算出一条编码消息。消息的确切内容取决于所使用的机制。

1.  客户端向服务器发送命令`AUTH <机制> <编码消息>`。

1.  服务器接收身份验证请求并将其交给 SASL。

1.  SASL 识别机制并解码编码的消息。解码取决于所选择的机制。

1.  SASL 联系身份验证后端以验证客户端提供的信息。它确切地寻找什么取决于所使用的机制。

1.  如果它可以验证信息，它将告诉服务器，服务器应允许客户端中继消息。如果无法验证信息，它将告诉服务器，服务器可能拒绝客户端中继消息。在这两种情况下，服务器都会告诉客户端身份验证是否成功或失败。

让我们在以下部分更仔细地看一下 SASL 的三个层。

### 身份验证接口

在我们刚刚讨论的 1 到 5 步和第 9 步中，您可以看到客户端和服务器交换数据以处理身份验证。这部分通信发生在身份验证接口中。

尽管 SASL 定义了必须交换的数据，但它并没有指定数据在客户端和服务器之间如何通信。它将这留给它们特定的通信协议，这就是为什么 SASL 可以被各种服务使用，如 SMTP、IMAP 或 LDAP。

### 注意

SASL 并不像 SMTP 协议那样古老（参见：RFC 821）。它是后来在 RFC 2554 中添加的（[`www.ietf.org/rfc/rfc2554.txt`](http://www.ietf.org/rfc/rfc2554.txt)），该文档描述了**SMTP 身份验证的服务扩展**。

服务器提供 SMTP 身份验证以及其他功能的 SMTP 对话如下：

```
$ telnet mail.example.com 25
220 mail.example.com ESMTP Postfix
EHLO client.example.com
250-mail.example.com
250-PIPELINING
250-SIZE 10240000
250-VRFY
250-ETRN
250-ENHANCEDSTATUSCODES
250-AUTH PLAIN LOGIN CRAM-MD5 DIGEST-MD5 1)
250-AUTH=PLAIN LOGIN CRAM-MD5 DIGEST-MD5 2)
250 8BITMIME
QUIT

```

+   `250-AUTH PLAIN LOGIN CRAM-MD5 DIGEST-MD5 1):` 这一行告诉客户端服务器提供`SMTP AUTH`。它由两个逻辑部分组成。第一部分`250-AUTH`宣布了`SMTP AUTH`的功能，行的其余部分是客户端可以选择其首选项的可用机制的列表。

+   `250-AUTH=PLAIN LOGIN CRAM-MD5 DIGEST-MD5 2):` 这一行重复了上面的行，但在宣布 SMTP 身份验证的方式上有所不同。在`250-AUTH`之后，它添加了一个等号，就像这样`250-AUTH=`。这是为了那些不遵循 SASL 最终规范的损坏客户端。

### 机制

机制（如步骤 4 到 7 中描述的）代表 SASL 的第二层。它们确定身份验证期间使用的验证策略。SASL 已知有几种机制。它们在传输数据的方式和传输过程中的安全级别上有所不同。最常用的机制可以分为**明文**和**共享密钥**机制。

您永远不应该让 Postfix 向客户端提供的一种机制是**匿名**机制。我们将首先看一下这个。

+   `anonymous:` 匿名机制要求客户端发送任何它想要的字符串。它旨在允许匿名访问全局 IMAP 文件夹，但不适用于 SMTP。在 AUTH 行中提供`ANONYMOUS`的 SMTP 服务器最终会被滥用。您不应该在 SMTP 服务器中提供这个选项！Postfix 在默认配置中不提供匿名访问。

+   `plaintext:` Cyrus SASL 知道**PLAIN**和**LOGIN**明文机制。`LOGIN`与`PLAIN`几乎相同，但用于不完全遵循最终 SASL RFC 的邮件客户端，如 Outlook 和 Outlook Express。这两种机制都要求客户端计算用户名和密码的 Base64 编码字符串，并将其传输到服务器进行认证。明文机制的好处是几乎每个现在使用的邮件客户端都支持它们。坏消息是，如果在没有**传输层安全性**（**TLS**）的情况下使用明文机制，它们是不安全的。这是因为 Base64 编码的字符串只是编码，而不是加密——它很容易被解码。但是，在传输层加密会话期间使用明文机制传输一个是安全的。然而，如果使用 TLS，它将保护 Base64 编码的字符串免受窃听者的侵害。

+   `shared secret:` Cyrus SASL 中可用的共享密钥机制有**CRAM-MD5**和**DIGEST-MD5**。基于共享密钥的身份验证具有完全不同的策略来验证客户端。它基于客户端和服务器都共享一个秘密的假设。选择共享密钥机制的客户端只会告诉服务器特定的共享密钥机制的名称。然后，服务器将生成一个基于他们的秘密的挑战，并将其发送给客户端。然后客户端生成一个响应，证明它知道这个秘密。在整个认证过程中，既不会发送用户名也不会发送密码。这就是为什么共享密钥机制比之前提到的机制更安全。然而，最受欢迎的邮件客户端 Outlook 和 Outlook Express 不支持共享密钥机制。

### 注意

在异构网络上，您可能最终会同时提供明文和共享密钥机制。

现在已经介绍了机制，只剩下一层——方法层。这是配置和处理保存凭据的数据存储的查找的地方。下一节将告诉您更多关于方法的信息。

### 方法

SASL 所指的最后一层是方法层。方法由 Cyrus SASL 安装目录中的库表示。它们用于访问数据存储，Cyrus SASL 不仅将其称为方法，还将其称为认证后端。在 SASL 拥有的许多方法中，最常用的是：

+   `rimap:` `rimap`方法代表**远程 IMAP**，使 SASL 能够登录到 IMAP 服务器。它使用客户端提供的用户名和密码。成功的 IMAP 登录是成功的 SASL 认证。

+   `ldap:` `ldap`方法查询 LDAP 服务器以验证用户名和密码。如果查询成功，则认证成功。

+   `kerberos:` `kerberos`方法使用流行的 Kerberos 方法，并检查 Kerberos 票证。

+   `Getpwent/shadow:` `getpwent`和`shadow`方法访问系统的本地用户密码数据库，以验证认证请求。

+   `pam:` `pam`方法访问您在 PAM 设置中配置的任何 PAM 模块，以验证认证请求。

+   `sasldb:` `sasldb`方法读取甚至写入 Cyrus SASL 的名为 sasldb2 的数据库。通常，此数据库与 Cyrus IMAP 一起使用，但也可以在没有 IMAP 服务器的情况下使用。

+   `sql:` 此方法使用 SQL 查询来访问各种 SQL 服务器。目前支持的有 MySQL、PostgreSQL 和 SQLite。

现在您已经了解了 SASL 架构的三个层，是时候来看看处理它们之间所有请求的 SASL 服务了。它被称为**密码验证服务**，将在接下来的部分中进行描述。

### 密码验证服务

密码验证服务处理来自服务器的认证请求，进行特定于机制的计算，调用方法查询认证后端，最终将结果返回给发送认证请求的服务器。

### 注意

在 Postfix 的情况下，处理认证请求的服务器是`smtpd`守护程序。在*Postfix SMTP AUTH 配置*部分，您将学习如何配置`smtpd`守护程序以选择正确的密码验证服务。

Cyrus SASL 2.1.23 版本，目前的最新版本，为我们提供了三种不同的密码验证服务：

+   `saslauthd`

+   `auxprop`

+   `authdaemond`

您的邮件客户端可能成功使用的机制以及 Cyrus SASL 在认证期间可以访问的方法取决于您告诉 Postfix 使用的密码验证服务。

+   `saslauthd：saslauthd`是一个独立的守护程序。它可以作为 root 运行，这样就具有访问仅限 root 访问的源所需的特权。但是，`saslauthd`在支持的机制范围上受到限制；它只能处理明文机制。

+   `auxprop：auxprop`是**辅助属性插件**的简称，这是 Project Cyrus 邮件服务器架构中使用的术语。`auxprop`代表一个库，被提供认证的服务器使用。它以使用它的服务器的特权访问源。与`saslauthd`不同，`auxprop`可以处理 Cyrus SASL 认证框架中提供的每种机制。

+   `authdaemond：authdaemond`是一个专门编写的密码验证服务，用于使用 Courier 的`authdaemond`作为密码验证器。这样，您就可以访问 Courier 可以处理的任何认证后端。这个`auxprop`插件只能处理明文机制。

以下表格为您提供了密码验证服务（方法）可以处理的机制的概述：

| 方法/机制 | PLAIN | LOGIN | CRAM-MD5 | DIGEST-MD5 |
| --- | --- | --- | --- | --- |
| `saslauthd` | 是 | 是 | 否 | 否 |
| `auxprop` | 是 | 是 | 是 | 是 |
| `authdaemond` | 是 | 是 | 否 | 否 |

只有`auxprop`密码验证服务能够处理更安全的机制；`saslauthd`和`authdaemond`只能处理明文机制。

现在我们已经介绍了一些 Cyrus SASL 理论，现在是时候安装它了。这正是我们在接下来的部分要做的事情。

## 安装 Cyrus SASL

您的系统上很可能已经安装了 Cyrus SASL。但是，各种 Linux 发行版已经开始将 Cyrus SASL 安装在与典型默认位置`/usr/lib/sasl2`不同的位置。要检查 Cyrus SASL 是否安装在您的服务器上，可以运行软件包管理器并查询`cyrus-sasl`，或者运行`find`。对于 Red Hat 软件包管理器（在 Fedora Core 11 上）的查询，如果安装了 SASL，将返回类似于以下内容：

```
$ rpm -qa | grep sasl
cyrus-sasl-2.1.18-2.2
cyrus-sasl-devel-2.1.18-2.2
cyrus-sasl-plain-2.1.18-2.2
cyrus-sasl-md5-2.1.18-2.2

```

对于 Ubuntu 上的`dpkg`查询，如果安装了 SASL，将返回类似于以下内容：

```
$ dpkg -l | grep sasl
ii libsasl2-2 2.1.22.dfsg1-23ubuntu3
Cyrus SASL - authentication abstraction libr
ii libsasl2-modules 2.1.22.dfsg1-23ubuntu3
Cyrus SASL - pluggable authentication module2

```

查找`libsasl*.*`的结果如下：

```
$ find /usr -name 'libsasl*.*'
/usr/lib/libsasl.so.7.1.11
/usr/lib/libsasl2.so
/usr/lib/libsasl.la
/usr/lib/libsasl2.so.2.0.18
/usr/lib/libsasl.a
/usr/lib/libsasl2.a
/usr/lib/libsasl2.la
/usr/lib/sasl2/libsasldb.so.2.0.18
/usr/lib/sasl2/libsasldb.so.2
/usr/lib/sasl2/libsasldb.so
/usr/lib/sasl2/libsasldb.la
/usr/lib/libsasl.so.7
/usr/lib/libsasl.so
/usr/lib/libsasl2.so.2

```

这证明您的系统上已安装了 SASL。要验证 SASL 库的位置，只需像这样运行`ls`：

![安装 Cyrus SASL](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-eml/img/8648_05_1.jpg)

如前所述，您的发行版可能会将它们放在其他位置。在这种情况下，`find`方法将找到正确的位置，或者您的发行版的文档应该提供这些信息。

如果您没有安装 Cyrus SASL，您将需要使用软件包管理器获取它，或者手动安装它。

Cyrus 的最新版本通常可以从[`cyrusimap.web.cmu.edu/downloads.html`](http://cyrusimap.web.cmu.edu/downloads.html)下载。要下载 2.1.23 版本（始终选择最新的稳定版本，而不是开发版本），请执行以下命令：

```
$ cd /tmp
$ wget ftp://ftp.andrew.cmu.edu/pub/cyrus-mail/cyrus-sasl-2.1.23.tar.gz
$ tar xfz cyrus-sasl-2.1.23.tar.gz
$ cd cyrus-sasl-2.1.23

```

下载并解压源文件后，进入源目录并运行`configure`。典型的源配置如下：

```
$ ./configure \
installingCyrus SASL--with-plugindir=/usr/lib/sasl2 \
--disable-java \
--disable-krb4 \
--with-dblib=berkeley \
--with-saslauthd=/var/state/saslauthd \
--without-pwcheck \
--with-devrandom=/dev/urandom \
--enable-cram \
--enable-digest \
--enable-plain \
--enable-login \
--disable-otp \
--enable-sql \
--with-ldap=/usr \
--with-mysql=/usr \
--with-pgsql=/usr/lib/pgsql

```

这将配置 Cyrus SASL 以为您提供明文和共享密钥机制，并将构建`saslauthd`并为您提供包括对 MySQL 和 PostgreSQL 的支持在内的 SQL 方法。

`configure`脚本完成后，运行`make`，成为`root`，然后运行`make install`。

```
$ make
$ su -c "make install"
Password:

```

Cyrus SASL 将安装到`/usr/local/lib/sasl2`，但它将期望在`/usr/lib/sasl2`中找到库。您需要创建这样的符号链接：

```
$ su -c "ln -s /usr/local/lib/sasl2 /usr/lib/sasl2" 
Password:

```

最后，您需要检查 SASL 日志消息是否会被`syslogd`捕获并写入日志文件。Cyrus SASL 记录到`syslog auth`设施。检查您的`syslogd`配置，通常是`/etc/syslog.conf`，看看它是否包含捕获 auth 消息的行。

```
$ grep auth /etc/syslog.conf
auth,authpriv.* /var/log/auth.log
*.*;auth,authpriv.none -/var/log/syslog
auth,authpriv.none;\
auth,authpriv.none;\

```

如果找不到条目，请添加以下内容，保存文件，然后重新启动`syslogd`：

```
auth.* /var/log/auth.log

```

完成所有这些后，您就可以配置 SASL 了。

## 配置 Cyrus SASL

在返回到 Postfix 并处理特定于 Postfix 的 SMTP AUTH 设置之前，始终配置和测试 Cyrus SASL 非常重要。

遵循此过程的原因非常简单。一个无法进行身份验证的认证框架对于使用它的任何其他应用程序都没有帮助。当问题与 Cyrus SASL 相关时，您很可能会花费数小时来调试 Postfix。

要了解必须在何处以及如何配置 SASL，需要记住它是一个认证框架，旨在为许多应用程序提供其服务。这些应用程序可能对要使用的密码验证服务以及要提供的机制以及用于访问认证后端的方法有完全不同的要求。

Cyrus 是使用特定于应用程序的文件进行配置的。每个客户端应用程序的配置都在单独的文件中。当应用程序连接到 SASL 服务器时，它会发送其应用程序名称。Cyrus 使用此名称来查找要使用的正确配置文件。

在我们的情景中，需要 SMTP AUTH 的应用程序是 Postfix 中的`smtpd`守护程序。当它联系 SASL 时，它不仅发送认证数据，还发送其应用程序名称`smtpd`。

### 注意

应用程序名称`smtpd`是从 Postfix 发送到 Cyrus SASL 的默认值。您可以使用`smtpd_sasl_application_name`进行更改，但通常不需要。只有在运行需要不同 Cyrus SASL 配置的不同 Postfix 守护程序时才需要。

当 Cyrus SASL 接收到应用程序名称时，它将附加一个`.conf`并开始查找包含配置设置的配置文件。

默认情况下，`smtpd.conf`的位置是`/usr/lib/sasl2/smtpd.conf`，但出于各种原因，一些 Linux 发行版已经开始将其放在其他位置。在 Debian Linux 上，您将不得不在`/etc/postfix/sasl/smtpd.conf`中创建配置。Mandrake Linux 希望文件位于`/var/lib/sasl2/smtpd.conf`。所有其他人都知道它应该位于`/usr/lib/sasl2/smtpd.conf`。

检查您的系统，找出是否已经创建了`smtpd.conf`。如果没有，一个简单的`touch`命令（作为 root）将创建它：

```
# touch /usr/lib/sasl2/smtpd.conf

```

现在接下来的所有配置都将集中在`smtpd.conf`上。以下是我们将在其中放置的内容的快速概述：

+   我们想要使用的密码验证服务的名称

+   SASL 应将日志消息发送到日志输出的日志级别

+   在向客户端提供 SMTP AUTH 时，Postfix 应该宣传的机制列表

+   特定于所选密码验证服务的配置设置

最后，我们将配置密码验证服务应如何访问认证后端。这需要根据我们选择的密码验证服务来完成，并将在到达时进行解释。

### 选择密码验证服务

第一步配置是选择 SASL 在身份验证期间应使用的密码验证服务。告诉 SASL 应该处理身份验证的密码验证服务的参数是`pwcheck_method`。您可以提供的值是：

+   `saslauthd`

+   `auxprop`

+   `authdaemond`

根据您选择的密码验证服务，您将不得不添加正确的值。名称应该说明情况，并告诉您将调用哪个密码验证服务。使用`saslauthd`的配置将在`smtpd.conf`中添加以下行：

```
pwcheck_method: saslauthd

```

### 选择日志级别

Cyrus SASL 的日志处理不一致。Cyrus SASL 将记录取决于密码验证服务和正在使用的方法。定义日志级别的参数是`log_level`。在设置期间合理的设置将是日志级别 3。

```
log_level: 3

```

此行应添加到`smtpd.conf`中。

以下是 Cyrus SASL 知道的所有日志级别的列表：

| log_level value | Description |
| --- | --- |
| `0` | 无日志 |
| `1` | 记录异常错误；这是默认设置 |
| `2` | 记录所有身份验证失败 |
| `3` | 记录非致命警告 |
| `4` | 比 3 更详细 |
| `5` | 比 4 更详细 |
| `6` | 记录内部协议的跟踪 |
| `7` | 记录内部协议的跟踪，包括密码 |

### 选择有效的机制

您的下一步将是选择 Postfix 在向客户端广告 SMTP 身份验证时可以提供的机制。在 Cyrus SASL 中配置有效机制列表的参数是`mech_list`。这些机制的名称与我们在*机制*部分中介绍它们时使用的名称完全相同。

重要的是设置`mech_list`参数，并且只列出您的密码验证服务可以处理的机制。如果不这样做，Postfix 将提供 SASL 提供的所有机制，如果您的邮件客户端选择 SASL 密码验证服务无法处理的机制，身份验证将失败。

### 注意

请记住，密码验证服务`saslauthd`和`authdaemond`只能处理两种明文机制——`PLAIN`和`LOGIN`。因此，这些密码验证服务的`mech_list`必须只包含`PLAIN`和`LOGIN`这两个值。任何能够处理更强机制的邮件客户端都会优先选择更强的机制。它会进行计算并将结果发送给服务器。服务器将无法进行身份验证，因为`Saslauthd`和`authdaemond`都无法处理非明文机制。

以下示例将在`smtpd.conf`中为`saslauthd`定义有效机制：

```
mech_list: PLAIN LOGIN

```

任何`auxprop`密码验证服务的有效机制列表可以进一步列出以下机制：

```
mech_list: PLAIN LOGIN CRAM-MD5 DIGEST-MD5

```

### 注意

此列表中机制的顺序不会影响客户端选择的机制。选择哪种机制取决于客户端；通常会选择提供最强加密的机制。

在接下来的部分中，我们将看看如何配置密码验证服务以选择认证后端，以及如何提供额外信息以选择相关数据。如前所述，这由三个密码验证服务以不同方式处理。我们将分别查看每个密码验证服务。

#### saslauthd

在使用`saslauthd`之前，您需要检查它是否能够在`saslauthd`称为`state dir`的目录中建立套接字。请仔细检查，因为与套接字相关的两个常见问题是：

+   **该目录不存在：**在这种情况下，`saslauthd`将停止运行，并且您将找到指示缺少目录的日志消息。

+   **该目录对于除`saslauthd`之外的应用程序是不可访问的：**在这种情况下，您将在邮件日志中找到指示`smtpd`无法连接到套接字的日志消息。

要解决这些问题，您首先需要找出`saslauthd`希望建立套接字的位置。只需像示例中那样以 root 身份启动它，并寻找包含`run_path`的行：

```
# saslauthd -a shadow -d

```

```
saslauthd[3610] :main : num_procs : 5
saslauthd[3610] :main : mech_option: NULL
saslauthd[3610] :main : run_path : /var/run/saslauthd
saslauthd[3610] :main : auth_mech : shadow
saslauthd[3610] :main : could not chdir to: /var/run/saslauthd
saslauthd[3610] :main : chdir: No such file or directory
saslauthd[3610] :main : Check to make sure the directory exists and is
saslauthd[3610] :main : writeable by the user, this process runs as—If you get no errors, the daemon will start, but the -d flag means that it will not start in the background; it will tie up your terminal session. In this case, press *Ctrl+C* to terminate the process.

```

如前面的示例所示，`saslauthd`希望访问`/var/run/saslauthd`作为`run_path`。由于它无法访问该目录，它立即退出。现在有两种方法可以解决这个问题。这取决于您是从软件包中获取`saslauthd`还是从源代码安装它。

在第一种情况下，软件包维护者很可能使用默认设置构建了`saslauthd`；选择不同的位置作为`state dir`并配置`init-script`以通过给出`-m /path/to/state_dir`选项来覆盖默认路径。

在 Debian 系统中，您通常会在`/etc/default/saslauthd`中找到命令行选项。在 Red Hat 系统中，您通常会在`/etc/sysconfig/saslauthd`中找到传递给`saslauthd`的命令行选项。以下清单为您提供了 Fedora Core 2 的设置概述：

```
# Directory in which to place saslauthd's listening socket, pid file, and so
# on. This directory must already exist.
SOCKETDIR=/var/run/saslauthd
# Mechanism to use when checking passwords. Run "saslauthd -v" to get a list
# of which mechanism your installation was compiled to use.
MECH=shadow
# Additional flags to pass to saslauthd on the command line. See saslauthd(8)
# for the list of accepted flags.
FLAGS=

```

就大多数 Linux 发行版而言，`state dir`的典型位置要么是`/var/state/saslauthd`，要么是`/var/run/saslauthd`。

现在考虑手动构建`saslauthd`的情况。然后，您应该创建一个与您在执行`configure`脚本时使用的`--with-saslauthd`参数相匹配的目录。

在 SASL 配置示例中，`--with-saslauthd`的值为`/var/state/saslauthd`。创建此目录并使其对 root 用户和 postfix 组可访问，如下所示：

```
# mkdir /var/state/saslauthd
# chmod 750 /var/state/saslauthd
# chgrp postfix /var/state/saslauthd

```

一旦您验证了`saslauthd`可以在您的`state dir`中创建套接字和`pid`文件，您可以开始配置`saslauthd`以访问您选择的身份验证后端。

### 注意

以下示例假定您不必为`saslauthd`提供额外的运行路径。如果需要，请将其添加到给出的示例中。

##### 使用 IMAP 服务器作为身份验证后端

指定`-a`选项以及值`rimap`，使 Cyrus SASL 使用邮件客户端提供的凭据登录到 IMAP 服务器。此外，您必须使用`-O`选项告诉`saslauthd`它应该转到哪个 IMAP 服务器，如下所示：

```
# saslauthd -a rimap -O mail.example.com

```

成功登录到 IMAP 服务器后，`saslauthd`将向 Postfix 报告身份验证成功，Postfix 可能允许邮件客户端将凭据交给中继。

##### 使用 LDAP 服务器作为身份验证后端

与 IMAP 服务器验证凭据比与 LDAP 服务器验证凭据稍微复杂一些。它需要更多的配置，这就是为什么您不会在命令行上给出所有选项给`saslauthd`，而是将它们放入配置文件中。默认情况下，`saslauthd`期望将 LDAP 配置位于`/usr/local/etc/saslauthd.conf`。如果选择不同的位置，您需要在命令行上声明它。

```
# saslauthd -a ldap -O /etc/cyrussasl/saslauthd.conf

```

在前面的示例中，值`ldap`告诉`saslauthd`转到 LDAP 服务器，`-O`选项提供了配置文件的路径。您的配置文件可能包含以下参数：

```
ldap_servers: ldap://127.0.0.1/ ldap://172.16.10.7/
ldap_bind_dn: cn=saslauthd,dc=example,dc=com
ldap_bind_pw: Oy6k0qyR
ldap_timeout: 10
ldap_time_limit: 10
ldap_scope: sub
ldap_search_base: dc=people,dc=example,dc=com
ldap_auth_method: bind
ldap_filter: (|(&(cn=%u)(&(uid=%u@%r)(smtpAuth=Y)))
ldap_debug: 0
ldap_verbose: off
ldap_ssl: no
ldap_start_tls: no
ldap_referrals: yes

```

正如您可能已经预料到的那样，您将不得不调整设置以适应您的 LDAP 树和其他特定于您的 LDAP 服务器的设置。要获取所有 LDAP 相关参数的完整列表（这里列出的远不止这些），请查看随 Cyrus SASL 源代码一起提供的`LDAP_SASLAUTHD readme`，它位于`saslauthd`子目录中。

##### 使用本地用户帐户

这是大多数人使用`saslauthd`的配置。您可以配置`saslauthd`从本地密码文件或支持影子密码的系统上的本地影子密码文件中读取。

要从`/etc/passwd`中读取，请使用`-a getpwent`选项，如下所示：

```
# saslauthd -a getpwent

```

大多数现代 Linux 发行版不会将密码存储在`/etc/passwd`中，而是存储在`/etc/shadow`中。如果要让`saslauthd`从`/etc/shadow`中读取，请像这样以 root 身份运行它：

```
# saslauthd -a shadow

```

##### 使用 PAM

还可以使用**PAM（可插入认证模块）**作为认证后端，后者又必须配置为访问其他认证后端。首先像这样运行`saslauthd`：

```
# saslauthd -a pam

```

然后创建一个`/etc/pam.d/smtp`文件或在`/etc/pam.conf`中添加一个部分，并向其中添加特定于 PAM 的设置。如果您从软件包中安装了 Cyrus SASL，那么您很有可能已经有了这样一个文件。例如，在 Red Hat 上，它看起来像这样：

```
#%PAM-1.0
auth required pam_stack.so service=system-auth
account required pam_stack.so service=system-auth

```

### 注意

配置文件的名称必须是`smtp`。这在`RFC 2554`中已经定义，其中指出 SASL 在 SMTP 上的服务名称是`smtp`。postfix `smtpd`守护程序将`smtp`的值作为服务名称传递给 Cyrus SASL。然后`saslauthd`将其传递给 PAM，后者将在`smtp`文件中查找认证指令。

#### auxprop

**辅助属性插件**（或**auxprop)**的配置与`saslauthd`不同。您只需在`smtpd.conf`中添加特定于 auxprop 的设置，而不是传递命令行选项。您在`smtpd.conf`中设置的任何 auxprop 配置都应以以下三行开头：

```
log_level: 3
pwcheck_method: auxprop
mech_list: PLAIN LOGIN CRAM-MD5 DIGEST-MD5

```

要告诉 Cyrus SASL 要使用哪个插件，您需要向配置中添加一个额外的参数。该参数称为`auxprop_plugin`，我们将在以下部分中研究其用法。

##### 配置 sasldb 插件

auxprop 插件`sasldb`是 Cyrus SASL 的默认插件，即使您没有设置`auxprop_plugin`参数，它也会使用`sasldb`。`sasldb`是 SASL 自己的数据库，可以使用`saslpasswd2`实用程序进行操作。

### 注意

这往往会激怒那些尝试设置不同插件并在其配置中出现错误的人。如果 Cyrus SASL 使用默认配置而不是所需的配置，它将失败。当您收到一个错误消息，说 Cyrus SASL 找不到`sasldb`时，这可能是您配置错误的错误（除非您选择故意配置`sasldb`），第一步应该是检查您的配置文件。

要使用`sasldb`，首先需要创建一个`sasldb`数据库。使用以下命令作为 root 创建一个`sasldb2`文件并添加一个用户。

```
# saslpasswd2 -c -u example.com username

```

此命令将创建一个`sasldb2`文件，并将一个用户名为`example.com`的用户添加到其中。您需要特别注意添加的领域，因为它将成为邮件客户端稍后必须发送的用户名的一部分。

### 注意

领域是 Kerberose 基础设施概念的一部分。Kerberose 是一种分布式的、加密的认证协议。通过添加领域，您可以定义用户可以在其中执行操作的上下文（例如，域或主机）。如果您不添加领域，`saslpasswd2`将默认添加服务器的主机名。

现在您已经创建了数据库并添加了一个用户，您需要更改对`sasldb`的访问权限，以便 Postfix 也可以访问数据库。只需像这样将`postfix`组对`sasldb2`的访问权限：

```
# chgrp postfix /etc/sasldb2

```

不要因为`sasldb`被称为`sasldb2`而感到困惑。当 Cyrus SASL 主要版本 2.x 推出时，`sasldb`的格式发生了变化。出于兼容性的原因，新的`sasldb`文件被称为`sasldb2`。创建完数据库后，您需要告诉 Cyrus SASL 使用它。像这样在`smtpd.conf`中添加`auxprop_plugin`参数：

```
auxprop_plugin: sasldb

```

这就是您需要做的一切，您应该准备好开始测试了（请参阅*测试 Cyrus SASL 认证*部分）。如果出于任何原因，您需要将`sasldb`放在与默认位置不同的位置，您可以使用以下附加参数：

```
sasldb_path: /path/to/sasldb2

```

##### 配置 sql 插件

**sql auxprop**插件是一个通用插件，可以让您访问 MySQL、PostgreSQL 和 SQLite。我们将以配置 sql 插件访问 MySQL 数据库为例进行说明。访问其他两个数据库的配置几乎相同，只有一个我们将注意到的例外。

首先，您需要创建一个数据库。当然，这取决于您使用的数据库。连接到 MySQL，如果还没有数据库，则创建一个数据库。

```
mysql> CREATE DATABASE `mail`;

```

然后添加一个包含所有 SASL 用户身份验证所需内容的表。它看起来类似于这样：

```
CREATE TABLE `users` (
`id` int(11) unsigned NOT NULL auto_increment,
`username` varchar(255) NOT NULL default '0',
`userrealm` varchar(255) NOT NULL default 'example.com',
`userpassword` varchar(255) NOT NULL default 't1GRateY',
`auth` tinyint(1) default '1',
PRIMARY KEY (`id`),
UNIQUE KEY `id` (`id`)
) TYPE=MyISAM COMMENT='Users';

```

该表具有用户名、用户领域、用户密码和一个额外的`auth`字段，我们稍后将使用它来确定用户是否可以中继。这样我们可以将该表用于其他身份验证目的，例如，与 Apache 的`mysql`模块一起，用于授予对`httpd`上特定文件夹的访问权限。

### 提示

不要忘记为`userpassword`设置默认值，如前面的示例所示，否则获取中继权限所需的只是发送一个有效的用户名。

创建表后，为测试目的添加一个用户，如下所示：

```
INSERT INTO `users` VALUES (1,'test','example.com','testpass',0);

```

然后为 Postfix 添加一个用户，以便访问 MySQL 的用户数据库，如下所示：

```
mysql> CONNECT mysql;
mysql> INSERT INTO user VALUES ('localhost','postfix','','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y');
mysql> UPDATE mysql.user SET password=PASSWORD("bu0tt^v") WHERE user='postfix' AND host='localhost';
mysql> GRANT SELECT, UPDATE ON mail.users TO 'postfix'@'localhost';
mysql> FLUSH PRIVILEGES;

```

设置 MySQL 完成后，您需要向`smtpd.conf`添加`sql auxprop-specific`参数。可用的参数如下：

+   `sql_engine:` 指定数据库类型。您可以选择`mysql, pgsql`或`sqlite`。在本示例中，我们使用`mysql`。如果选择不同的数据库，您需要相应地更改此值。

+   `sql_hostnames:` 指定数据库服务器名称。您可以指定一个或多个由逗号分隔的 FQDN 或 IP 地址。即使选择`localhost`，SQL 引擎也会尝试通过套接字进行通信。

+   `sql_database:` 告诉 Cyrus SASL 要连接的数据库的名称。

+   `sql_user:` 您在此处设置的值必须与连接到数据库的用户的名称匹配。

+   `sql_passwd:` 您在此处设置的值必须与连接到数据库的用户的密码匹配。它必须是明文密码。

+   `sql_select:` `sql_select`参数定义了用于验证用户的`SELECT`语句。

+   `sql_insert:` `sql_insert`参数定义了一个`INSERT`语句，允许 Cyrus SASL 在 SQL 数据库中创建用户。您将使用`saslpasswd2`程序来执行此操作。

+   `sql_update:` `sql_update`参数定义了`UPDATE`语句，允许 Cyrus SASL 修改数据库中的现有条目。如果您选择配置此参数，您将不得不与`sql_insert`参数结合使用。

+   `sql_usessl:` 您可以设置`yes, 1, on`或`true`来启用 SSL 以通过加密连接访问 MySQL。默认情况下，此选项为`off`。

将所有参数组合在一起的简单配置如下：

```
# Global parameters
log_level: 3
pwcheck_method: auxprop
mech_list: PLAIN LOGIN CRAM-MD5 DIGEST-MD5
# auxiliary Plugin parameters
auxprop_plugin: sql
sql_engine: mysql
sql_hostnames: localhost
sql_database: mail
sql_user: postfix
sql_passwd: bu0tt^v
sql_select: SELECT %p FROM users WHERE username = '%u' AND userrealm = '%r' AND auth = '1'
sql_usessl: no

```

如您所见，`sql_select`语句中使用了宏。它们的含义是：

+   `%u:` 此宏是要在身份验证期间查询的用户名的占位符。

+   `%p:` 此宏是密码的占位符。

+   `%r:` `r`代表领域，客户端提供的领域将插入到`%r`中。

+   `%v:` 此宏仅与`sql_update`或`sql_insert`语句结合使用。它表示应替换现有值的提交值。

### 提示

特别注意标记。必须使用单引号(')引用宏。

配置完成。如果您使用`auxprop`并按照到此为止的说明进行操作，您已准备好开始测试，并且可以跳过关于`authdaemond`的下一部分。

#### authdaemond

`authdaemond`是专门为与 Courier IMAP 配合使用而创建的。如果您配置 Cyrus SASL 使用`authdaemond`，它将连接到 Courier authlib 的`authdaemond`套接字，询问 Courier authlib 验证邮件客户端发送的凭据。一方面，Cyrus SASL 受益于 Courier authlib 可以用于用户验证的各种后端，但另一方面，Cyrus SASL 的`authdaemond`密码验证服务仅限于明文机制，这不如使用`auxprop`插件时所获得的好处多。

设置 authdaemond 密码验证服务非常简单。我们将在接下来的部分中看一下它。

##### 设置 authdaemond 密码验证服务

您的第一步是配置 Postfix 以使用`authdaemond`密码验证服务。与`saslauthd`或`auxprop`一样，您将`pwcheck_method`参数添加到您的`smtpd.conf`中，并选择它为`authdaemond`。

```
log_level: 3
pwcheck_method: authdaemond
mech_list: PLAIN LOGIN

```

由于`authdaemond`的限制，您还必须将机制列表限制为`PLAIN`和`LOGIN`——仅有的明文机制。

##### 配置 authdaemond 套接字路径

您需要告诉 Cyrus SASL 它可以在哪里找到由 Courier authlib 的`authdaemond`创建的套接字。

使用`authdaemond_path`参数提供包括套接字名称在内的完整路径。

```
authdaemond-path: /var/spool/authdaemon/socket

```

最后检查`authdaemond`目录的权限，并验证至少用户`postfix`可以访问该目录。完成后，您就可以开始测试了。

# 测试 Cyrus SASL 身份验证

没有测试工具，但您可以使用示例应用程序`sample-server`和`sample-client`来测试身份验证，而不会有其他应用程序（例如 Postfix）干扰测试。如果您从源代码构建了 Cyrus SASL，您可以在 Cyrus SASL 源代码的`sample`子目录中找到它们。基于 Fedora 的 Linux 发行版将示例包含在`cyrus-sasl-devel`软件包中，因此如果可用，您应该安装该软件包。基于 Debian 的 Linux 发行版没有类似的软件包，因此您现在必须自行构建它们。

要仅构建示例，请找到、下载并提取与您的软件包管理器安装相匹配的 Cyrus SASL 版本的发布版。要定位并安装源代码，请按照*Cyrus SASL 安装*部分中描述的说明进行操作。然后，不要发出`make install`命令，而是发出以下命令：

```
# cd sample
# make

```

我们将使用这些示例来测试我们在`smtpd.conf`中创建的 Cyrus SASL 配置。但是，这些程序不希望在`smtpd.conf`中找到它们的配置，而是在`sample.conf`中找到。我们将简单地创建一个从`sample.conf`到`smtpd.conf`的符号链接以满足要求：

```
# ln -s /usr/lib/sasl2/smtpd.conf /usr/lib/sasl2/sample.conf

```

接下来，我们需要启动服务器应用程序以便它监听传入的连接。像这样启动服务器：

```
$ ./server -s rcmd -p 8000
trying 2, 1, 6
trying 10, 1, 6
bind: Address already in use

```

不要担心`bind: Address already in use`的消息。服务器继续运行表明它已经成功监听指定的端口。这是因为应用程序启用了 IPv6，而底层系统不支持 IPv6。

如果您收到类似`./server: No such file or directory`的错误，请检查您是否已从您的发行版安装了`cyrus-sasl-devel`软件包，或者您从源代码构建的工作是否正确，并且您是否在正确的目录中。

服务器将在端口`8000`上监听传入的连接。接下来打开一个新的终端，并使用相同的端口和机制`PLAIN`启动客户端，并指向您的服务器实用程序应该在那里监听的`localhost`。在提示时，输入`test, test`和`testpass`，这些是测试服务器提供的有效值。成功的身份验证看起来像这样：

![测试 Cyrus SASL 身份验证](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-eml/img/8648_05_2.jpg)

您应该能够在`auth`日志中看到一些日志记录。如果您要使用`saslauthd`，请在调试模式下在单独的终端上启动它，您将能够像这样跟踪身份验证：

```
# saslauthd -m /var/run/saslauthd -a shadow -d

```

```
saslauthd[4547] :main : num_procs : 5
saslauthd[4547] :main : mech_option: NULL
saslauthd[4547] :main : run_path : /var/run/saslauthd
saslauthd[4547] :main : auth_mech : shadow
saslauthd[4547] :ipc_init : using accept lock file: /var/run/saslauthd/mux.accept
saslauthd[4547] :detach_tty : master pid is: 0
saslauthd[4547] :ipc_init : listening on socket: /var/run/saslauthd/mux
saslauthd[4547] :main : using process model
saslauthd[4548] :get_accept_lock : acquired accept lock
saslauthd[4547] :have_baby : forked child: 4548
saslauthd[4547] :have_baby : forked child: 4549
saslauthd[4547] :have_baby : forked child: 4550
saslauthd[4547] :have_baby : forked child: 4551
saslauthd[4548] :rel_accept_lock : released accept lock
saslauthd[4548] :do_auth : auth success: [user=test] [service=rcmd] [realm=] [mech=shadow]
saslauthd[4548] :do_request : response: OK

```

saslauthd[4548] :get_accept_lock : acquired accept lock

如果您能够成功进行身份验证，请继续配置 Postfix 中的`SMTP AUTH`。如果您的身份验证失败，请跟随日志并按照之前讨论的设置和配置 SASL 的说明进行迭代。

# 配置 Postfix SMTP AUTH

现在，在设置和配置 Cyrus SASL 后，配置 Postfix 中的 `SMTP AUTH` 就变得非常简单了。您需要做的第一件事是检查 Postfix 是否构建支持 SMTP 身份验证。使用 `ldd` 实用程序检查 Postfix `smtpd` 守护程序是否已链接到 `libsasl`：

```
# ldd /usr/libexec/postfix/smtpd | grep libsasl
libsasl2.so.2 => /usr/lib/libsasl2.so.2 (0x00002aaaabb6a000)

```

如果没有任何输出，您可能需要重新构建 Postfix。阅读 Postfix `README_FILES` 目录中的 `SASL_README`，以获取有关必须在 `CCARGS` 和 `AUXLIBS` 语句中包含的详细信息。

## 准备配置

一旦您验证了 Postfix 支持 `SMTP AUTH`，您需要验证在配置 `SMTP AUTH` 时 `smtpd` 守护程序是否未运行 `chrooted`。许多人在意识到原因是 `chroot` 监狱之前，花费数小时配置无法访问 `saslauthd` 套接字的 `chrooted` Postfix。不运行 `chrooted` 的 Postfix `smtpd` 守护程序在 `/etc/postfix/master.cf` 中的 `chroot` 列中有一个 `n`：

```
# ==================================================================
# service type private unpriv chroot wakeup maxproc command + args
# (yes) (yes) (yes) (never) (100)
# ==================================================================
smtp inet n - n - - smtpd

```

如果 Postfix 在更改了 `smtpd` 的 `chroot` 设置后正在运行 `chrooted`，请重新加载它并转到 `main.cf`。

## 启用 SMTP AUTH

您要做的第一件事是通过添加 `smtpd_sasl_auth_enable` 参数并将其设置为 `yes` 来启用 `SMTP AUTH`。

```
smtpd_sasl_auth_enable = yes

```

这将使 Postfix 向使用 `ESMTP` 的客户端提供 `SMTP AUTH`，但在开始测试之前，您仍然需要配置一些设置。

## 设置安全策略

您将不得不决定 Postfix 应该使用 `smtpd_sasl_security_options` 参数提供哪些机制。此参数接受以下一个或多个值的列表：

+   `noanonymous:` 您应该始终设置此值，否则 Postfix 将向邮件客户端提供匿名身份验证。允许匿名身份验证将使您成为开放中继，并且不应该用于 SMTP 服务器。

+   `noplaintext:` `noplaintext` 值将阻止 Postfix 提供明文机制 `PLAIN` 和 `LOGIN`。通常情况下，您不希望这样做，因为大多数广泛使用的客户端只支持 `LOGIN`。如果设置了此选项，我们将无法对一些客户端进行身份验证。

+   `noactive:` 此设置排除了容易受到主动（非字典）攻击的 SASL 机制。

+   `nodictionary:` 此关键字排除了所有可以通过字典攻击破解的机制。

+   `mutual_auth:` 这种形式的身份验证要求服务器向客户端进行身份验证，反之亦然。如果设置了它，只有能够执行此形式或身份验证的服务器和客户端才能进行身份验证。这个选项几乎从不使用。

`smtpd_sasl_security_options` 参数的常见设置将在 `main.cf` 中添加以下行：

```
smtpd_sasl_security_options = noanonymous

```

这将防止匿名身份验证，并允许所有其他身份验证。

## 包括破损的客户端

接下来，您需要决定 Postfix 是否应该向破损的客户端提供 `SMTP AUTH`。在 `SMTP AUTH` 的上下文中，破损的客户端是指如果身份验证已按照 RFC 2222 要求的方式提供，它们将不会识别服务器的 SMTP AUTH 能力。相反，它们遵循了 RFC 草案，在显示 SMTP 通信期间的 `SMTP AUTH` 能力行中具有额外的 `=`。在破损的客户端中，包括几个版本的 Microsoft Outlook Express 和 Microsoft Outlook。要解决此问题，只需像这样向 `main.cf` 添加 `broken_sasl_auth_clients` 参数：

```
broken_sasl_auth_clients = yes

```

当 Postfix 列出其功能给邮件客户端时，将打印一个额外的 `AUTH` 行。此行将在其中具有额外的 `=`，并且破损的客户端将注意到 `SMTP AUTH` 能力。

最后，如果要限制可以中继到具有相同领域的用户组，添加 `smtpd_sasl_local_domain` 参数，并提供该值作为领域，如下所示：

```
smtpd_sasl_local_domain = example.com

```

Postfix 将在成功通过邮件客户端发送的所有用户名后附加该值，成功限制中继到那些用户名中包含 `smtpd_sasl_local_domain` 值的用户。

完成所有配置步骤后，重新加载 Postfix 以使设置生效并开始测试。作为 root 用户，发出以下命令：

```
# postfix reload

```

# 测试 SMTP AUTH

在测试 SMTP 身份验证时，不要使用常规邮件客户端，因为邮件客户端可能会引入一些问题。而是使用 Telnet 客户端程序并在 SMTP 通信中连接到 Postfix。您将需要以 Base64 编码形式发送测试用户的用户名和密码，因此第一步将是创建这样的字符串。使用以下命令为用户`test`使用密码`testpass`创建 Base64 编码的字符串：

```
$ perl -MMIME::Base64 -e 'print encode_base64("test\0test\0testpass");'
dGVzdAB0ZXN0AHRlc3RwYXNz

```

### 注意

请注意，`\0`将用户名与密码分开，用户名将需要重复两次。这是因为 SASL 期望两个可能不同的用户名（`userid, authid`）来支持未用于 SMTP 身份验证的附加功能。

还要记住，如果您的用户名或密码包含`@`或`$`字符，您将需要使用前置的`\`进行转义，否则 Perl 将解释它们，这将导致一个无法正常工作的 Base64 编码的字符串。

一旦您手头有 Base64 编码的字符串，使用 Telnet 程序连接到服务器的端口`25`，如下所示：

```
$ telnet mail.example.com 25
220 mail.example.com ESMTP Postfix
EHLO client.example.com
250-mail.example.com
250-PIPELINING
250-SIZE 10240000
250-VRFY
250-ETRN
250-STARTTLS
250-AUTH LOGIN PLAIN DIGEST-MD5 CRAM-MD5
250-AUTH=LOGIN PLAIN DIGEST-MD5 CRAM-MD5
250-XVERP
250 8BITMIME
AUTH PLAIN dGVzdAB0ZXN0AHRlc3RwYXNz
235 Authentication successful
QUIT
221 Bye

```

您可以看到在前面的示例中，身份验证是成功的。首先，邮件客户端在介绍时发送了`EHLO`，而 Postfix 则以一系列功能的列表做出了回应。如果您像我们的示例中所做的那样将`broken_sasl_auth_clients`参数设置为`yes`，您还会注意到包含`=`的额外`AUTH`行。

认证发生在客户端发送`AUTH`字符串以及它想要使用的机制时，对于明文机制，还附加了 Base64 编码的字符串。如果您的身份验证没有成功，但您能够在 SASL 测试期间进行身份验证，请查看`main.cf`中的参数，并仔细检查`master.cf`中`smtpd`的`chroot`状态。

# 为经过身份验证的客户端启用中继

如果身份验证成功，我们只需告诉 Postfix 允许已经经过身份验证的用户中继消息。这是通过编辑`main.cf`并在`smtpd_recipient_restrictions`的限制列表中添加`permit_sasl_authenticated`选项来完成的，如下所示：

```
smtpd_recipient_restrictions =
...
permit_sasl_authenticated
permit_mynetworks
reject_unauth_destination
...

```

重新加载 Postfix 并开始使用真实的邮件客户端进行测试。如果可能，请确保其 IP 地址不是`mynetworks`的一部分，因为 Postfix 可能被允许中继的原因不是因为`SMTP AUTH`成功。您可能希望在测试期间将中继限制为仅限服务器。更改`mynetwork_classes = host`设置，以便来自其他计算机的客户端不会自动成为 Postfix 网络的一部分。

如果您仍然遇到`SMTP AUTH`问题，请查看`saslfinger`（[`postfix.state-of-mind.de/patrick.koetter/saslfinger/`](http://postfix.state-of-mind.de/patrick.koetter/saslfinger/)）。这是一个脚本，它收集有关`SMTP AUTH`配置的各种有用信息，并为您提供输出，您可以在向 Postfix 邮件列表询问时附加到您的邮件中。

# 保护明文机制

我们已经注意到，使用明文机制的`SMTP AUTH`实际上并不安全，因为在身份验证期间发送的字符串仅仅是编码而不是加密。这就是**传输层安全**（**TLS**）派上用场的地方，因为它可以保护编码字符串的传输免受好奇的眼睛。

## 启用传输层安全

要启用 TLS，您必须生成密钥对和证书，然后修改 postfix 配置以识别它们。

要生成 SSL 证书，并使用 SSL，您需要安装 OpenSSL 软件包。在许多情况下，这将被安装，否则请使用您的发行版软件包管理器进行安装。

要创建证书，请以 root 身份发出以下命令：

![启用传输层安全 SASL 层明文机制](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-eml/img/8648_05_3.jpg)

这将在`/etc/postfix/certs`中创建名为`smtpd.key`和`smtpd.crt`的证书。将`smtpd_use_tls`参数添加到`main.cf`并将其设置为`yes`：

```
smtpd_use_tls = yes

```

然后，您需要告诉`smtpd`在哪里可以找到密钥和证书，通过添加`smtpd_tls_key_file`和`smtpd_tls_cert_file`参数：

```
smtpd_tls_key_file = /etc/postfix/certs/smtpd.key
smtpd_tls_cert_file = /etc/postfix/certs/smtpd.crt

```

发送证书以证明其身份的邮件服务器还必须随时保留认证机构的公共证书的副本。假设您已经将其添加到服务器的本地 CA 根存储中的`/usr/share/ssl/certs`，使用以下参数：

```
smtpd_tls_CAfile = /usr/share/ssl/certs/ca-bundle.crt

```

如果 CA 证书不是在一个文件中，而是在同一个目录中的单独文件中，例如`/usr/share/ssl/certs`，则使用以下参数：

```
smtpd_tls_CApath = /usr/share/ssl/certs/

```

一旦您完成了所有这些配置，您就完成了基本的 TLS 配置，可以开始保护明文认证。

## 配置安全策略

有几种方法可以使用 TLS 保护明文认证。最激进的方法是使用`smtpd_tls_auth_only`参数，并将其设置为`yes`。如果使用它，只有在邮件客户端和邮件服务器建立了加密通信层后，才会宣布`SMTP AUTH`。通过这样做，所有用户名/密码组合都将被加密，不容易被窃听。

然而，这惩罚了所有其他能够使用其他更安全机制的邮件客户端，比如共享密钥机制。如果你想更有选择性地处理这个问题，你应该采取以下方法，禁用未加密传输中的明文认证，但一旦建立了加密通信，就允许它。

首先，您需要重新配置您的`smtpd_sasl_security_options`参数，以排除向邮件客户端提供明文机制：

```
smtpd_sasl_security_options = noanonymous, noplaintext

```

然后设置额外的`smtpd_sasl_tls_security_options`参数，该参数控制相同的设置，但仅适用于 TLS 会话：

```
smtpd_sasl_tls_security_options = noanonymous

```

正如您所看到的，`smtpd_sasl_tls_security_options`参数不会排除明文机制。这样一来，可以使用其他非明文机制的客户端无需使用 TLS，而只能使用明文机制的客户端一旦建立了加密会话就可以安全地使用它。

一旦您重新加载了 Postfix，您就可以开始测试了。

### 注意

不要忘记将签署您服务器证书请求的认证机构的证书添加到您的邮件客户端的 CA 根存储中，否则它至少会抱怨无法验证服务器的身份。

# 字典攻击

字典攻击是指客户端试图向无数潜在收件人发送邮件，这些收件人的电子邮件地址是从字典中的单词或名称派生的：

```
anton@example.com
bertha@example.com
...
zebediah@example.com

```

如果您的服务器没有有效收件人地址列表，它必须接受这些邮件，无论收件人是否真的存在。然后，这些邮件的攻击需要像往常一样进行处理（病毒检查、垃圾邮件检查、本地投递），直到系统在某个阶段意识到收件人甚至不存在！

然后将生成一个非投递报告并发送回发件人。

因此，对于每个不存在的收件人，都会接受和处理一封邮件，并且另外生成一封邮件（退信），并且会进行投递尝试。

正如您所看到的，这种做法浪费了服务器的宝贵资源。因为服务器正忙于尝试传递本来不应该接受的邮件，合法的邮件在垃圾邮件的洪流中落后。垃圾邮件发送者还可以使用退信消息来确定进一步攻击的合法电子邮件地址。退信消息还可以提示使用哪个 SMTP 服务器，从而使他们能够针对特定版本中已知的任何漏洞。

## 收件人映射

Postfix 能够在接受消息之前验证收件人地址。它可以对本地域（列在`mydestination`中）和中继域（列在`relay_domains`中）运行检查。

### 检查本地域收件人

`local_recipient_maps`参数控制 Postfix 将保留为有效本地收件人的收件人。默认情况如下：

```
local_recipient_maps = proxy:unix:passwd.byname, $alias_maps

```

通过这个设置，Postfix 将检查本地`/etc/passwd`文件的收件人名称，以及已分配给`main.cf`中的`alias_maps`参数的任何映射。添加虚拟用户超出了本书的范围，但如果您需要扩展此列表，您可以创建一个包含用户的数据库，并添加路径到保存额外本地收件人的映射。

### 检查中继域收件人

`relay_recipient_maps`参数控制中继域的有效收件人。默认情况下为空，为了让 Postfix 获得更多控制权，您需要构建一个 Postfix 可以查找有效收件人的映射。

假设您的服务器中继邮件到`example.com`，那么您将创建以下配置：

```
relay_domains = example.com
relay_recipient_maps = hash:/etc/postfix/relay_recipients

```

`relay_domain`参数告诉 Postfix 中继`example.com`域的收件人，`relay_recipient_maps`参数指向一个保存有效收件人的映射。在映射中，您可以创建以下列表：

```
adam@example.com OK
eve@example.com OK

```

然后运行`postmap`命令创建一个索引映射，如下所示：

```
# postmap /etc/postfix/relay_recipients

```

为了让 postfix 识别新的数据库，重新加载它：

```
# postfix reload
postfix/postfix-script: refreshing the Postfix mail system

```

这将只允许`adam@example.com`和`eve@example.com`作为`example.com`域的收件人。发送到`snake@example.com`的邮件将被拒绝，并显示**User unknown in relay recipient table**错误消息。

## 限制连接速率

拒绝发送到不存在收件人的邮件会有很大帮助，但是当您的服务器受到字典攻击时，它仍会接受所有客户端的连接并生成适当的错误消息（或者接受邮件，如果偶然命中了有效的收件人地址）。

Postfix 的 anvil 服务器维护短期统计数据，以防御您的系统受到在可配置的时间段内以以下任一情况轰炸您的服务器的客户端：

+   同时会话过多

+   过多的连续请求

硬件和软件的限制决定了您的服务器每个给定时间单位能够处理的邮件数量，因此不接受超出服务器处理能力的邮件是有意义的。

```
anvil_rate_time_unit = 60s

```

上一行指定了用于所有以下限制的时间间隔：

+   `smtpd_client_connection_rate_limit = 40:` 这指定了客户端可以在`anvil_rate_time_unit`指定的时间段内建立的连接数。在这种情况下，是每 60 秒 40 个连接。

+   `smtpd_client_connection_count_limit = 16:` 这是任何客户端允许在`anvil_rate_time_unit`内建立的最大并发连接数。

+   `smtpd_client_message_rate_limit = 100:` 这是一个重要的限制，因为客户端可以重复使用已建立的连接并仅使用这个单个连接发送许多邮件。

+   `smtpd_client_recipient_rate_limit = 32:` 这是任何客户端允许在`anvil_rate_time_unit`内发送到此服务的最大收件人地址数量，无论 Postfix 是否实际接受这些收件人。

+   `smtpd_client_event_limit_exceptions = $mynetworks:` 这可以用来豁免某些网络或机器免受速率限制。您可能希望豁免邮件列表服务器免受速率限制，因为它无疑会在短时间内向许多收件人发送大量邮件。

`anvil`将发出关于最大连接速率（这里是`5/60s`）以及哪个客户端达到了最大速率（`212.227.51.110`）以及何时（`Dec28 13:19:23`）的详细日志数据。

```
Dec 28 13:25:03 mail postfix/anvil[4176]: statistics: max connection rate 5/60s for (smtp:212.227.51.110) at Dec 28 13:19:23

```

这第二个日志条目显示了哪个客户端建立了最多的并发连接以及何时：

```
Dec 28 13:25:03 mail postfix/anvil[4176]: statistics: max connection count 5 for (smtp:62.219.130.25) at Dec 28 13:20:19

```

如果任何限制被超出，`anvil`也会记录这一点：

```
Dec 28 11:33:24 mail postfix/smtpd[19507]: warning: Connection rate limit exceeded: 54 from pD9E83AD0.dip.t-dialin.net[217.232.58.208] for service smtp
Dec 28 12:14:17 mail postfix/smtpd[24642]: warning: Connection concurrency limit exceeded: 17 from hqm-smrly01.meti.go.jp[219.101.211.110] for service smtp

```

任何超出这些限制的客户端都将收到临时错误代码，因此表示它在稍后重试。合法的客户端将遵守并重试。开放代理和特洛伊木马可能不会重试。

# 摘要

在本章中，我们讨论了如何保护您的安装。涵盖了几个不同的主题，首先是配置 Postfix 只接受来自特定 IP 地址的电子邮件，这在所有用户都是办公室用户时非常有用。接下来，本章介绍了使用 SASL 对可能来自任何 IP 地址的用户进行身份验证。然后，我们看了如何使用 TLS 加密客户端和服务器之间的身份验证。最后，我们看了如何限制表现不佳的客户端，使用`anvil`守护程序限制在一定时间内连接过于频繁的客户端，以及一次打开太多连接的客户端。

本章介绍的措施将使您作为邮件管理员的生活更轻松，并有助于限制用户遭受的垃圾邮件数量，如果您无意中配置了开放中继，还可以限制传递给其他互联网用户的垃圾邮件数量。有关限制垃圾邮件的更多细节，请移步到描述使用开源垃圾邮件过滤工具 SpamAssassin 的第八章。或者继续阅读第六章，介绍使用 Procmail 在电子邮件到达时对其进行操作。


# 第六章：开始使用 Procmail

Procmail 是一种多功能的电子邮件过滤器，通常用于在将消息传递到用户收件箱之前处理消息。

本章包括以下主题：

+   Procmail 的简要介绍

+   Procmail 可以执行的典型过滤任务

+   如何在服务器上安装和设置邮件过滤系统，以处理您每天不愿意花时间处理的重复分类和存储任务

+   Procmail 食谱中规则和操作的基本结构

+   如何在我们的食谱中创建和测试规则

+   最后，一些执行过滤的示例食谱

通过本章结束时，您将了解过滤过程的基础知识，如何设置系统执行过滤以及如何对自己的邮件执行许多非常简单但极其有用的过滤操作。所有这些都将帮助您掌握已经或即将收到的所有邮件。

# 介绍 Procmail

Procmail 是一个邮件过滤器，它在邮件到达邮件服务器后但在最终交付给收件人之前执行。Procmail 的行为由许多用户编写的食谱（或脚本）控制。每个食谱可以包含许多模式匹配规则，以至少基于收件人、主题和消息内容选择消息。如果规则中的匹配条件选择消息作为候选项，食谱可以执行许多操作，将消息移动到文件夹，回复发件人，甚至在交付之前丢弃消息。与规则一样，操作是用户在食谱中编写的，可以对消息执行几乎任何操作。

Procmail 的主页位于[`www.procmail.org.`](http://www.procmail.org.)

## 谁写的以及何时写的

1.0 版本于 20 世纪 90 年代末发布，并发展成为基于 UNIX 的邮件系统中最好和最常用的邮件过滤解决方案之一。Procmail 最初由 Stephen R. van den Berg（`<srb@cuci.nl>`）设计和开发。1998 年秋，他意识到自己没有时间独自维护 Procmail，于是创建了一个用于讨论未来发展的邮件列表，并委任 Philip Guenther（`<guenther@sendmail.com>`）为维护者。

自 2001 年 9 月发布的 3.22 版本以来，Procmail 一直很稳定，因此大多数最近的安装将安装此最新版本，这也是我们在整本书中将使用的版本。

# 过滤系统如何帮助我？

到目前为止，您应该已经建立并运行了一个电子邮件系统，并发送和接收电子邮件。您可能已经注册了一些有用的邮件列表，消息以不同的间隔到达。您还应该收到通知您系统状态的消息。所有这些额外的、低优先级的信息很容易分散注意力，妨碍您阅读其他重要的电子邮件。

如何组织您的邮件取决于您个人的口味；如果您非常有条理，您可能已经在电子邮件客户端中设置了一些文件夹，并在阅读后将消息移动到适当的位置。尽管如此，您可能已经意识到，能够让系统自动将一些消息存储在与您重要电子邮件不同的位置将非常有用。

在设置自动流程时，您需要考虑的是如何识别邮件项目的内容。最重要的指标是发送给谁，标题或主题行，以及发件人详细信息。如果您现在花几分钟时间记录一下您已经处理邮件的方式，到达的消息类型以及您对它们的处理方式，您将更清楚地了解您可能想要设置的自动流程。

一般来说，您可能会收到几种不同类别的消息。

+   **邮件列表成员资格：**来自邮件组或邮件列表的邮件通常很容易通过发件人信息或主题行进行识别。一些组每隔几分钟发送一封消息，而其他组可能每个月只发送几封消息。通常，不同的邮件组项目由不同的信息片段进行识别。例如，一些组发送的消息的“发件人”地址是真实发件人的地址，而其他组会添加一个虚假或系统生成的“发件人”地址。例如，一些组可能会自动向“主题”字段添加前缀。

+   **自动系统消息：**您的服务器每天会生成大量消息。尽管通常只发送给系统管理员或 root 用户，但首先要做的一件事是确保您收到邮件的副本，以便及时了解系统状态和事件。您可以通过编辑`/etc/mail/aliases`或`/etc/aliases`文件（取决于系统设置）来做到这一点。这些系统生成的消息几乎总是可以识别出来自少数特定系统用户 ID。这些通常是`root`和`cron`。

+   **未经请求的大量电子邮件：**被识别为垃圾邮件的消息通常被认为不重要。因此，您可以选择将这些项目移动到一个单独的文件夹以供稍后查看，甚至完全丢弃它们。不建议自动丢弃垃圾邮件，因为任何误识别的邮件将永远丢失。

+   **个人消息：**来自客户、同事或朋友的邮件通常被认为是重要的。因此，通常会将其投递到收件箱，让您有机会提供更及时的回复。个人消息更难以通过过滤器识别，尤其是来自新客户或同事的消息，因此不属于前述任何一类的消息应该正常投递。

完成本章的工作后，您应该具备工具和知识，可以开始更详细地检查邮件并设置一些基本的过滤操作。

## 邮件过滤的潜在用途

您已经设置的基本邮件系统具有其自己的内置能力，可以根据用户设置处理传入的邮件。默认操作是将消息发送到收件箱；其他选项是自动将所有邮件转发给另一个用户。假设您在不同系统上有多个邮件帐户，并且希望所有邮件最终都发送到一个特定的邮件帐户。然后，您可以将该邮件发送到特定文件，或者将其传递给程序或应用程序，以便让其自行处理。

这种设置的缺点是所有邮件必须遵循一个特定的路线，因此随着时间的推移，已经创建了许多智能过滤邮件的选项。其中最强大和最受欢迎的之一是 Procmail。

### 过滤和分类邮件

Procmail 旨在处理系统内用户接收的邮件的各种处理和过滤任务。过滤仅适用于在系统上拥有帐户的用户，而不适用于虚拟用户，并且可以应用于所有用户或个别用户可以添加自己的过滤器。

对于系统管理员，Procmail 提供了一系列设施，用于对系统用户接收的所有邮件应用规则和操作。这些操作可能包括为了历史目的而复制所有邮件，或者在邮件内容可能在某种法律或商业情况下使用的企业中使用。

在本书的其他地方，我们将讨论识别电子邮件病毒和垃圾邮件的方法。Procmail 可以利用这些过程提供的信息，并根据这些过程添加的信息执行操作，例如将包含病毒的所有邮件存储在系统管理员检查的安全邮件文件夹中。

对于系统用户来说，对收件箱中的邮件进行的最常见操作是将其分类整理，以便根据您感兴趣的主题区域轻松找到所需的项目。典型的组织布局可能是一个分层的布局，类似于以下内容：

```
/mailgroups/Procmail
/mailgroups/postfix
/mailgroups/linux
/system/cron
/system/warnings
/system/status
/inbox

```

如果您计划长时间保留邮件以供历史参考，可能值得增加一两层来将邮件分隔成年份和月份。这样将来存档或清除旧邮件会更容易，同时搜索和排序也会更快。

### 转发邮件

有时您可能会收到很多很容易识别需要发送到另一个用户的另一个电子邮件地址的电子邮件。在这种情况下，您可以设置一个规则，将电子邮件转发到一个或多个其他电子邮件地址，而不是将文件存储在系统上。当然，您需要小心确保转发不会最终回到您，从而创建一个永无止境的循环。

以这种方式转发邮件比在邮件客户端软件内手动转发邮件具有很大的优势，除了不需要任何手动干预之外。通过 Procmail 转发的邮件是透明的，对收件人来说，它看起来就像邮件直接从原始发件人那里到达一样。而如果使用邮件客户端转发，它看起来就好像是由进行转发的人或帐户发送的。

如果需要将单个地址的所有邮件转发到单个其他地址，更有效的方法是使用 Postfix 邮件系统的别名机制。只有在需要根据在接收消息时才能确定的因素进行智能过滤邮件时，才应该使用 Procmail。

### 在应用程序中处理邮件

有些邮件可能适合传递到一个应用程序，应用程序可以对电子邮件进行一些处理。也许它可以阅读内容，然后将信息存储在错误跟踪数据库中，或者更新客户活动的公司历史记录。这些是在下一章中简要介绍的更高级的主题。

### 确认和离职/度假回复

如果您想要对某些消息发送自动回复，可以设置一个过滤器或规则来发送这样的消息。当您长时间离开办公室度假、休假或者生病时，可以设置一个自动回复服务，通知发件人在您能够回复他们的邮件之前需要一些时间，并可能提供其他联系方式或要求他们联系其他人。

重要的是要仔细组织这样的功能。您不应该向邮件组发送这样的回复，也不应该向已经知道您离开但需要在您回来后发送信息的人重复发送回复。这需要保留发送消息的地址日志，以避免重复发送消息。我们将在下一章中探讨设置这样一个服务。

## 文件锁定和完整性

在您使用 Procmail 的所有工作中要牢记的一个重要概念是，总是可能有多封邮件同时到达，争相处理。因此，很可能会有两封或更多邮件同时存储在同一位置，这是灾难的开始。假设有两封邮件同时到达的简单例子。第一封邮件打开存储位置并开始写入邮件内容，然后第二个进程也这样做。从中可能产生各种可能的结果，从完全丢失一封邮件，到两封邮件交织存储且完全无法阅读。

为了确保这种情况不会发生，需要遵守严格的锁定协议，以确保只有一个进程可以同时写入，所有其他应用程序都需要耐心等待轮到它们。Procmail 本身具有强制执行适用于所应用的进程类型的锁定协议的能力，并且默认情况下会锁定存储邮件的物理文件。

在一些情况下，邮件正在被应用程序处理，可以通过规则中的标志指示 Procmail 使用适当的锁定机制。这将在第七章中更全面地介绍。

## Procmail 不适用于哪些情况

Procmail 可能被认为适用于一些非常特定的邮件过滤和处理需求。在大多数情况下，它足够灵活和能干，至少可以在基本水平上执行任务。这些任务可能包括过滤与垃圾邮件相关的电子邮件，过滤病毒或运行邮件列表操作。对于每一个任务，都有一些超出仅使用 Procmail 过滤器能力的解决方案可用。我们将在第八章后面讨论使用 SpamAssassin 进行垃圾邮件过滤以及病毒过滤解决方案。

我们已经提到 Procmail 只适用于在 Procmail 运行的系统上拥有账户的用户。尽管如此，值得强调的是，Procmail 无法处理发送到虚拟用户的邮件，这些邮件最终会被发送到另一个系统上。如果需要处理这样的用户的邮件，可以在系统上创建一个真实的用户账户，然后使用 Procmail 作为其过滤过程的一部分来执行最终的转发。这并不是一个理想的用法，因为如果允许 Postfix 系统执行这项工作，它会比使用 Procmail 更有效率。

# 下载和安装 Procmail

由于软件现在已经相当成熟，Procmail 通常可以在大多数 Linux 发行版上安装，并且可以通过软件包管理器安装。这是安装 Procmail 的推荐方法。如果您的 Linux 发行版的软件包管理器中没有 Procmail，也可以从源代码安装。

## 通过软件包管理器安装

对于 Fedora 用户，如果尚未安装 Procmail，可以使用以下`yum`命令简单安装：

```
yum install procmail

```

对于基于 Debian 的用户，可以使用以下命令：

```
apt-get install procmail

```

这将确保 Procmail 的二进制文件正确安装在您的系统上，然后您可以决定如何将其集成到您的 Postfix 系统中。

## 从源代码安装

Procmail 可以从多个来源获取，但官方发布的版本由[www.procmail.org](http://www.procmail.org)维护和提供。在那里，您会找到一些镜像服务的链接，可以从中下载源文件。本书中使用的版本可以从[`www.procmail.org/procmail-3.22.tar.gz`](http://www.procmail.org/procmail-3.22.tar.gz)下载。

可以使用`wget`命令下载如下：

```
wget http://www.procmail.org/procmail-3.22.tar.gz

```

下载并解压缩存档后，`cd`到目录，例如`procmail-3.22`。在开始构建和安装软件之前，值得阅读`INSTALL`和`README`文档。

对于大多数 Linux 系统，最简单的安装方法可以通过按照这里列出的步骤来简化：

1.  运行`configure`命令来创建正确的构建环境：

```
$ ./configure

```

1.  配置脚本完成后，您可以运行`make`命令来构建软件可执行文件：

```
$ make

```

1.  最后一步，作为`root`，是将可执行文件复制到系统上的正确位置以进行操作：

```
# make install

```

在最后一步，软件被安装到`/usr/local`目录中。

在所有阶段，您应该检查进程输出是否有任何重要的错误或警告。

## 安装选项/注意事项

对于本书中的大多数人，您将是您正在管理的机器或机器的系统管理员，并且可能会应用安装以处理系统上所有用户的所有邮件。如果您不是管理员，或者您希望系统上只有有限数量的人利用 Procmail 的功能，您可以为单个用户安装 Procmail。

### 个别安装

如果您为自己使用或仅为服务器上的少数人安装 Procmail，则最常见的方法是在服务器上的家目录中直接从`.forward`文件中调用 Procmail 程序（此文件需要是可全局读取的）。

在使用 Postfix 作为 MTA 时，`.forward`中的条目应该是这样的：

```
"|IFS=' ' && exec /usr/bin/procmail -f- || exit 75 *#username*"

```

引号是必需的，用户名应该替换为您的用户名。其他 MTA 的语法可能不同，因此请查阅 MTA 文档。

您还需要在主目录中安装一个`.procmailrc`文件—这个文件保存了 Procmail 将用来过滤和传递电子邮件的规则。

### 系统范围的安装

如果您是系统管理员，可以决定全局安装 Procmail。这样做的好处是用户不再需要拥有`.forward`文件。只需在每个用户的`HOME`目录中有一个`.procmailrc`文件就足够了。在这种情况下，操作是透明的—如果`HOME`目录中没有`.procmailrc`文件，邮件将像往常一样传递。

可以创建一个全局的`.procmailrc`文件，该文件在用户自己的文件之前生效。在这种情况下，您需要小心确保配置包含以下指令，以便消息以最终用户的权限而不是 root 用户的权限存储。

```
DROPPRIVS=yes

```

这也有助于保护系统安全性的弱点。该文件通常存储在`/etc`目录中，如`/etc/procmailrc`，旨在为添加到系统的所有用户提供一组默认的个人规则。值得配置一个`.procmailrc`文件在用于系统的`add user`功能的骨架帐户中。请查阅 Linux 文档，了解如何设置这一点。

## 与 Postfix 集成以进行系统范围的传递

将 Procmail 集成到 Postfix 系统中很简单，但是，与任何其他配置更改一样，必须小心。Postfix 以 nobody 用户 ID 运行所有外部命令，例如 Procmail。因此，它将无法将邮件传递给用户`root`。为了确保重要的系统消息仍然可以收到，您应该确保配置了别名，以便将所有发送给 root 用户的邮件转发到一个真实的用户，该用户将读取邮箱。

### 为系统帐户创建别名

要为 root 用户创建别名，您必须编辑适当的`alias`文件，通常位于`/etc/aliases`或`/etc/mail/aliases`中。

如果找不到文件，请使用以下命令：

```
postconf alias_maps

```

别名文件中的条目应该如下所示，冒号（：）和电子邮件地址的开头之间只有一个制表符，并且没有尾随空格：

```
root: user@domain.com

```

创建文本条目后，您应该运行`newaliases`命令，将文本文件转换为数据库文件，以便供 Postfix 读取。

值得为可能接收邮件的任何其他系统帐户添加额外的别名。例如，您可能最终会得到类似以下的`aliases`文件：

```
# /etc/aliases
postmaster: root
nobody: root
hostmaster: root
usenet: root
news: root
webmaster: root
www: root
ftp: root
abuse: root
noc: root
security: root
root: user@example.com
clamav: root

```

### 将 Procmail 添加到 Postfix 配置

对于由 Procmail 进行系统范围的邮件投递，需要修改 Postfix 的`main.cf`文件，以指定将负责实际投递的应用程序。

编辑`/etc/postfix/main.cf`文件并添加以下行：

```
mailbox_command = /path/to/procmail

```

进行更改后，您需要使用以下命令指示 Postfix 文件已更改：

```
postfix reload

```

### 由 Postfix 提供的环境变量

Postfix 通过使用多个环境变量导出有关邮件包的信息。这些变量被修改以避免任何 shell 扩展问题，方法是用下划线字符替换所有可能对 shell 具有特殊含义的字符，包括空格。以下是导出的变量及其含义的列表：

| 变量 | 含义 |
| --- | --- |
| `DOMAIN` | 收件人地址中`@`右侧的文本 |
| `EXTENSION` | 可选的地址扩展部分 |
| `HOME` | 收件人的主目录 |
| `LOCAL` | 收件人地址中`@`左侧的文本，例如，`$USER+$EXTENSION` |
| `LOGNAME` | 收件人用户名 |
| `RECIPIENT` | 整个收件人地址，`$LOCAL@$DOMAIN` |
| `SENDER` | 完整的发件人地址 |
| `SHELL` | 收件人的登录 shell |

# 基本操作

当邮件到达并传递给 Procmail 程序时，操作的顺序遵循一组固定的格式。它从加载各种配置文件开始，以获取为特定用户设置的规则。然后依次通过每个规则测试消息，当找到合适的匹配时，应用规则。一些规则在完成后终止，而其他规则返回控制，以便对消息进行潜在处理的剩余规则进行评估。

## 配置文件

通常在`/etc/procmailrc`中进行系统范围的配置，而个人配置文件通常存储在用户的主目录中，称为`.procmailrc`。个别规则可以存储在单独的文件中，或者分组存储在多个文件中，然后作为主`.procmailrc`文件的一部分包含在邮件过滤过程中。通常，这些文件将存储在主目录的`Procmail`子目录中。

### 文件格式

配置文件中的条目以简单的文本格式按照基本布局进行。允许注释，并且由`#`字符后的文本组成；空行将被简单地忽略。规则本身不必按任何特定格式布局，但为了便于维护和可读性，值得以一致和简单的格式编写规则。

### 配置文件解剖

Procmail 配置文件内容可以分为三个主要部分：

+   变量：Procmail 需要执行其工作所需的信息可以被分配到配置文件中的变量中，类似于它们在 shell 编程中的使用方式。一些变量是从 Procmail 正在运行的 shell 环境中获取的，另一些是由 Procmail 自己创建的，用于脚本内部使用，而其他变量可以在脚本内部分配。变量的另一个用途是设置 Procmail 本身的操作方式的标志。

大多数脚本中可以设置一些有用的变量：

```
PATH=/usr/bin: /usr/local/bin:.
MAILDIR=$HOME/Maildir # Make sure it exists
DEFAULT=$MAILDIR/ # Trailing / indicates maildir format mailbox
LOGFILE=$HOME/procmail.log
LOG="
"
VERBOSE=yes

```

+   `VERBOSE`变量用于影响执行的日志级别，而`LOG`变量中嵌入的`NEWLINE`是故意的，旨在使日志文件更易于阅读。

+   第七章还包括一个简短的脚本，显示了在 Procmail 中分配的所有变量。

+   **注释：** `#`字符和后续的所有字符直到`NEWLINE`都将被忽略。这不适用于无法被注释的条件行。空行将被忽略，并且可以与注释一起用于记录您的配置并提高可读性。您应该注释您的规则，因为今天写规则时显而易见的东西，也许在六个月后不查看手册就无法解释了。

+   **规则或配方：** 配方是我们创建的规则的常见名称。以冒号（：）开头的行标志着配方的开始。配方的格式如下：

```
:0 [flags] [ : [locallockfile] ]
<zero or more conditions (one per line)>
<exactly one action line>

```

`：0`是 Procmail 早期版本的遗留物。冒号后面的数字最初是用来指示规则中包含的动作数量，现在由 Procmail 解析器自动计算。然而，为了兼容性，仍然需要`：0`。

# 分析一个简单的规则

假设我们从一个特定的邮件组收到大量邮件，我们订阅了这个邮件组。这些邮件很有趣，但不重要，我们更愿意在闲暇时阅读它们。主题是“神话怪兽”，来自这个邮件列表的所有电子邮件都有一个“To”地址`<mythical@monsters.com>`。我们决定创建一个专门的文件夹来存放这些邮件，并将所有邮件复制到这个文件夹中。这是一个简单的规则，您将能够轻松复制和修改以处理将来的邮件。

## 规则结构

以下是一个非常简单的`.procmail`文件的示例副本，取自用户的主目录，并旨在解释 Procmail 配置的一些基本特性。规则本身旨在将发送到特定电子邮件地址`<mythical@monsters.com>`的所有邮件存储在一个名为`monsters`的特殊文件夹中。大多数邮件将发送给多个人，包括您自己，而“To”地址可以提供有用的邮件内容指示。例如，邮件可能发送到`info@yourcompany.com`的分发列表，您需要对这封邮件进行优先处理。

花点时间阅读文件的内容，然后我们将依次分解并分析每个部分的功能。

```
#
# Here we assign variables
#
PATH=/usr/bin: /usr/local/bin:.
MAILDIR=$HOME/Maildir # Make sure it exists
DEFAULT=$MAILDIR/ # Trailing / indicates maildir format mailbox
LOGFILE=$HOME/procmail.log
LOG="
"
VERBOSE=yes
#
# This is the only rule within the file
#
:0: # Anything to mythical@monsters.com
* ^TO_ mythical@monsters.com
monsters/ # will go to monsters folder. Note the trailing /

```

### 变量分析

要详细检查这个文件，我们可以从定义语句开始，其中变量被赋予特定值。这些值将覆盖 Procmail 已经分配的任何值。通过进行手动赋值，我们可以确保路径针对脚本操作进行了优化，并且我们确定使用的值而不是假设 Procmail 可能分配的值。

```
PATH=/usr/bin: /usr/local/bin:.
MAILDIR=$HOME/Maildir
DEFAULT=$MAILDIR/
LOGFILE=$HOME/procmail.log
LOG="
"
VERBOSE=yes

```

这些设置指令用于定义一些基本参数：

+   `PATH`指令指定了 Procmail 可以找到任何可能需要执行的程序的位置。

+   `MAILDIR`指定了所有邮件项目将存储的目录。这个目录应该存在。

+   `DEFAULT`定义了如果为单独的规则定义了特定位置，则邮件将存储在哪里。根据 Postfix 章节中关于选择邮箱格式的建议，尾部的/（斜杠）表示 Procmail 应以 Maildir 格式传递邮件。

+   `LOGFILE`是存储所有跟踪信息的文件，以便我们可以看到发生了什么。

### 规则分析

接下来是以`:0`开头的配方说明。第二个`:`指示 Procmail 创建一个锁定文件，以确保一次只写入一个邮件消息到文件中，以避免消息存储的损坏。单行规则可以分解如下：

+   `*：`所有规则行都以`*`开头。这是 Procmail 知道它们是规则的方式。每个配方可能有一个或多个规则。

+   `^TO_：`这是一个特殊的 Procmail 内置宏，用于搜索大多数可能携带您地址的标题，例如`To：，Apparently-To：，Cc：，Resent-To：`等等，如果找到地址`<mythical@monsters.com.>`，则会匹配。

最后一行是操作行，默认情况下指定了`MAILDIR`变量指定的目录中的邮件文件夹。

### 提示

对于 Maildir 格式邮箱，文件夹名称末尾的斜杠是必需的，否则邮件将以不受 Courier-IMAP 支持的 unix mbox 格式传递。如果您正在使用 IMAP，文件夹名称还应以`.`（句号）为前缀，因为句号字符被指定为层次分隔符。

# 创建和测试规则

Procmail 允许您将规则和配方组织成多个文件，然后依次处理每个文件。这样可以更容易地管理规则，并根据需要打开或关闭规则。对于这个第一个测试案例，我们将创建一个特殊的规则集进行测试，并将所有规则组织在我们的主目录的子目录中。通常，子目录称为`Procmail`，但您可以自由使用自己的名称。

我们将从查看一个简单的个人规则并为单个用户进行测试开始。在本章后面，当我们涵盖了所有基础知识并且您对创建和设置规则的过程感到满意时，我们将展示如何开始将规则应用于所有系统用户。

## 一个“hello world”示例

几乎所有关于编程的书都以非常简单的“hello world”示例开始，以展示编程语言的基础知识。在这种情况下，我们将创建一个简单的个人规则，处理用户收到的所有电子邮件，并检查主题是否包含“hello world”这几个词。如果邮件主题包含这些特定词，邮件消息将存储在一个特殊的文件夹中。如果不包含这些魔术词，邮件将存储在用户的正常收件箱中。

## 创建 rc.testing

在生产环境中工作时，重要的是要确保编写和测试的规则不会干扰您的日常邮件活动。控制这一点的一种方法是创建一个专门用于测试新规则的特殊文件，并且只在实际进行测试工作时将其包含在 Procmail 处理中。当您对规则操作满意时，可以将其移动到自己的特定文件中，或者将其添加到其他类似或相关的规则中。在这个例子中，我们将创建一个用于测试规则的新文件`rc.testing`。在`$HOME/Procmail`目录中，使用您喜欢的编辑器创建文件`rc.testing`并输入以下行：

```
# LOGFILE should be specified early in the file so
# everything after it is logged
LOGFILE=$PMDIR/pmlog
# To insert a blank line between each message's log entry,
# Use the following LOG entry
LOG="
"
# Set to yes when debugging; VERBOSE default is no
VERBOSE=yes
#
# Simple test recipes
#
:0:
* ^Subject:.*hello world
TEST-HelloWorld

```

到目前为止，您可能已经开始认识到规则的结构。这个规则可以分解如下。

前几行设置了适用于我们测试环境的变量。由于它们是在测试脚本中分配的，因此它们只适用于脚本被包含在处理中的时候。一旦我们排除了测试脚本，测试设置当然就不适用了。

匹配所有以`Subject：`开头并包含字符串`hello world`的行。我们故意没有使用诸如`test`之类的字符串，因为少数系统可能会剥离看起来是测试消息的消息。请记住，Procmail 的默认操作是不区分大小写的，因此我们不需要测试所有变体，例如`Hello World.`

最后一行指示 Procmail 将输出存储在`TEST-HelloWorld`文件中。

在`$HOME/Procmail`目录中创建`testmail.txt`，使用您喜欢的编辑器创建文件`testmail.txt`并输入以下行：

```
From: me@example.com
To: me@example.com (self test)
Subject: My Hello World Test
BODY OF TEST MESSAGE SEPARATED BY EMPTY LINE

```

主题行与`rc.testing`中的规则不一致，该规则包含了候选字符串，以演示不区分大小写的匹配。

## 对脚本进行静态测试

从`Procmail`目录运行以下命令将生成调试输出：

```
formail -s procmail -m PMDIR=. rc.testing < testmail.txt

```

### 注意

在静态测试期间，我们已经在上一个命令中定义了变量`PMDIR`为我们当前的目录。

运行命令后，您可以查看错误消息的日志文件。如果一切正常，您将看到文件`TEST-HelloWorld`的创建，其中包含`testmail.txt`的内容以及日志中的以下输出。

```
procmail: [9060] Mon Jun 8 17:52:31 2009
procmail: Match on "^Subject:.*hello world"
procmail: Locking "TEST-HelloWorld.lock"
procmail: Assigning "LASTFOLDER=TEST-HelloWorld"
procmail: Opening "TEST-HelloWorld"
procmail: Acquiring kernel-lock
procmail: Unlocking "TEST-HelloWorld.lock"
From me@example.com Mon Jun 8 17:52:31 2009
Subject: My Hello World Test
Folder: TEST-HelloWorld 194

```

如果`Subject`行没有包含相关的匹配短语，您可能会在日志中看到以下输出：

```
procmail: [9073] Mon Jun 8 17:53:47 2009
procmail: No match on "^Subject:.*hello world"
From me@example.com Mon Jun 8 17:53:47 2009
Subject: My Goodbye World Test
Folder: **Bounced** 0

```

## 配置 Procmail 以处理 rc.testing

您需要编辑`.procmailrc`配置文件。可能已经有一些条目在里面，所以在进行任何更改之前最好备份文件。确保文件中包含以下行：

```
# Directory for storing procmail configuration and log files
PMDIR=$HOME/Procmail
# Load specific rule sets
INCLUDERC=$PMDIR/rc.testing

```

有些行使用`#`进行了故意注释。如果以后需要进行更详细的调试，可能需要这些行。

## 测试设置

使用以下命令，给自己发送两条消息：

```
echo "test message" | mail -s "hello world" $USER

```

主题行应包含字符串`hello world`，而另一条消息则不应包含此特定字符串。

当您检查邮件时，您应该发现主题中包含关键字的消息已存储在`TEST-HelloWorld`邮件文件夹中，而另一条消息则留在了正常的邮件收件箱中。

# 配置调试

如果一切正常——恭喜！您已经在组织您的邮件的道路上取得了很大进展。

如果结果不如预期，我们可以做一些简单的事情来找出问题所在。

## 检查脚本中的拼写错误

与任何编程过程一样，如果一开始不起作用，请检查代码，确保在编辑阶段没有引入明显的拼写错误。

## 查看错误消息的日志文件

如果这没有显示任何问题，您可以查看 Procmail 创建的日志文件。在这种情况下，日志文件称为`~/Procmail`目录中的`pmlog`。要查看最后几行，请使用以下命令：

```
tail ~/Procmail/pmlog

```

在以下示例中，缺少`:0`，因此规则行被跳过：

```
* ^Subject:.*hello world
TEST-HelloWorld

```

这将导致以下错误：

```
procmail: [10311] Mon Jun 8 18:21:34 2009
procmail: Skipped "* ^Subject:.* hello world"
procmail: Skipped "TEST"
procmail: Skipped "-HelloWorld"

```

在这里没有存储指令来遵循规则`:0:`

```
:0:
* ^Subject:.*hello world

```

这将导致以下错误：

```
procmail: [10356] Mon Jun 8 18:23:36 2009
procmail: Match on "^Subject:.* hello world"
procmail: Incomplete recipe

```

## 检查文件和目录权限

使用`ls`命令检查`~/.procmailrc`和`~/Procmail/*`文件以及`~/ home`目录的权限。规则文件应该可以被除所有者以外的用户写入，并且应该具有类似以下的权限：

```
rw-r--r—

```

主目录应具有以下权限，其中`?`可以是`r`或：

```
drwx?-x?-x

```

## 打开完整日志记录

当您创建更复杂的规则，或者仍然遇到问题时，您需要启用 Procmail 的**完整日志记录**功能。为此，您需要从`~/.procmailrc`文件中删除`#`注释，以便启用它们，如下所示：

```
# Directory for storing procmail configuration and log files
PMDIR=$HOME/Procmail
# LOGFILE should be specified early in the file so
# everything after it is logged
LOGFILE=$PMDIR/pmlog
# To insert a blank line between each message's log entry,
# add a return between the quotes (this is helpful for debugging)
LOG="
"
# Set to yes when debugging; VERBOSE default is no
VERBOSE=yes
# Load specific rule sets
INCLUDERC=$PMDIR/rc.testing

```

现在重新发送两条示例消息，并检查输出信息的日志文件。日志文件应指示一些问题区域供您调查。

## 采取措施避免灾难

在`.procmailrc`文件的开头插入以下配方将确保最近接收的 32 条消息都存储在`backup`目录中，确保在配方包含错误或产生意外副作用的情况下不会丢失宝贵的邮件。

```
# Create a backup cache of 32 most recent messages in case of mistakes.
# For this to work, you must first create the directory
# ${MAILDIR}/backup.
:0 c
backup
:0 ic
| cd backup && rm -f dummy `ls -t msg.* | sed -e 1,32d`

```

现在我们将假设这个工作，并在下一章中详细分析这个规则，看看它是如何工作的以及它的作用。

# 了解电子邮件结构

为了充分利用 Procmail 的功能，值得花一些时间了解典型电子邮件消息的基本结构。 随着时间的推移，结构变得越来越复杂，但仍然可以分解为两个离散的块。

## 消息正文

消息正文与标题之间由一个空白行分隔（所有标题必须连续出现，因为在空白行之后的任何标题都将被假定为消息正文的一部分）。

消息正文本身可以是一个由简单 ASCII 字符组成的简单文本消息，也可以是使用称为**MIME**的东西编码的部分的复杂组合。 这使得电子邮件能够传输从简单文本，HTML 或其他格式化页面到包括附件或嵌入对象（如图像）在内的各种形式的数据。 MIME 编码的讨论超出了本书的范围，并且对于您可能在邮件过滤中遇到的大多数过程来说并不是必要的。

如果您决定尝试处理消息正文中保存的数据，重要的是要记住，您在邮件程序的输出中看到的内容可能与原始邮件消息中传输的实际数据非常不同。

## 电子邮件标题

标题是电子邮件包含的标签，允许各种邮件组件发送和处理消息。 电子邮件标题的典型格式是由一个关键字组成的简单两部分结构，由`:`终止，并跟随关键字分配的信息。 标题提供了有关电子邮件是如何创建的，什么形式的邮件程序创建了消息，消息来自谁，应该发送给谁，以及它如何到达您的邮箱的大量信息。

以下邮件头与从`freelancers.net`的多个邮件列表中收到的一封电子邮件相关。 电子邮件最有用的识别特征是主题行，因为大多数其他邮件组使用了讨论的其他邮件头的相同值。

![电子邮件标题](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-eml/img/8648_06_01.jpg)

## 标题结构

先前的示例包含了大量的标题，这些标题是由邮件在从发件人到收件人的过程中经历的一系列过程插入的。 但是，有一小部分关键标题非常有用，用于处理电子邮件，并且在大量的规则中使用。

## 标题的官方定义

所有不以`X-`开头的标题都由相关标准机构分配特定功能。 关于它们的更多信息可以在**RFC（请求评论）文档 822**中找到，网址为[`www.ietf.org/rfc/rfc0822.txt`](http://www.ietf.org/rfc/rfc0822.txt)。

以`X-`开头的标题是用户定义的，并且仅适用于特定应用程序。 但是，一些应用程序可能使用与其他应用程序相同的标题标记，但出于不同的原因，并且提供的信息格式也不同。

# 示例规则集

为了帮助您理解 Procmail 规则的工作方式，我们将介绍几个简单但非常有用的规则集的设计和设置。 这应该有助于让您开始设计自己的规则集，以满足更具体的需要来过滤您的传入邮件项目。

所有这些示例都是基于从 Freelancers 邮件列表收到的邮件消息，先前示例标题取自其中。 它们都实现了相同的结果，并再次证明编程问题没有一个正确的解决方案。

## 来自标题

此标头解释了电子邮件的发起者是谁。可以使用各种格式，并由各种人类可读和计算机可读的信息项的各种组合组成。当您查看了一些电子邮件后，您将开始看到不同邮件系统和软件可以使用的各种模式。实际的标头格式并不一定重要，因为您要生成规则以匹配特定的电子邮件。

```
From: Do Not Reply <do-not-reply@freelancers.net>

```

## Return-Path 标头

此字段由最终传输系统添加到将消息传递给其接收者的消息中。该字段旨在包含有关消息的发件人地址和路由的确切信息。

```
Return-Path: <do-not-reply@freelancers.net>

```

### 通过 Return-Path 进行过滤

大多数邮件列表使用`Return-Path`标头：

```
:0:
* ^Return-Path: <do-not-reply@freelancers.net>
freelancers//

```

这是一个方便地过滤邮件列表项的方法。在这里，`^`字符执行一个特殊功能，指示 Procmail 在新行的开头开始匹配过程。这意味着包含短语的行不会被匹配。Procmail 的默认操作是，如果在标头或邮件正文的任何位置找到字符串，就返回匹配，具体取决于脚本设置的搜索位置。

## To 和 Cc 标头

邮件通常发送给一个或多个列在电子邮件的 To:或 Cc:标头中的人。与 From:标头一样，这些地址可能以多种方式格式化。这些标头对所有邮件接收者可见，并允许您查看所有列出的公共接收者。

```
To:projects@adepteo.net

```

有一个第三个接收者标头，不像 To:和 Cc:那样常见，但在大量邮件中经常使用。这是 Bcc:（暗送）。不幸的是，正如名称所暗示的那样，这是一个盲标头，因此信息不包含在实际的标头信息中，因此无法用于处理。

### 通过 To 或 Cc 进行过滤

Procmail 有许多特殊的内置宏，可用于识别邮件项。特殊规则`^TO_`旨在搜索所有可用的目标标头。规则必须写成四个字符，没有空格，并且 T 和 O 都是大写。匹配的短语必须紧跟在`_`后面，再次没有空格。

```
:0:
rule setsCc header, filtering by* ^TO_do-not-reply@freelancers.net
freelancers/

```

## 主题头

主题行通常包含在电子邮件头中，除非发件人决定根本不包括主题行。

**主题：FN-PROJECTS 自由职业网页设计师**

在这个例子中，发送到这个特定列表的所有邮件都以短语“FN-PROJECTS”开头，因此有时适合过滤。

### 通过主题进行过滤

当邮件列表在主题行中添加前缀时，此前缀可能适用于过滤：

```
:0:
* ^Subject: FN-PROJECTS
freelancers//

```

# 系统范围的规则

现在我们已经涵盖了设置规则、分析电子邮件以及通常看到所有处理操作如何交互的所有基础知识，我们将浏览一些系统范围的过滤、测试和操作的示例。

## 删除可执行文件

在第九章中，我们将看到如何将完整的病毒检查系统集成到 Postfix 邮件架构中。这将执行准确的病毒签名识别，并向邮件头添加适当的标志以指示邮件中是否存在病毒。但是，如果不可能设置这样的系统，这条规则将提供一种替代但更残酷的方法来阻止所有带有可执行附件的电子邮件。

如果您将以下内容放入`/etc/procmailrc`，它将影响通过系统传输的所有包含特定类型文档附件的邮件。

```
# Note: The whitespace in the [ ] in the code comprises a space and a tab character
:0
* < 256000
* ! ^Content-Type: text/plain
{
:0B
* ^(Content-(Type|Disposition):.*|[ ]*(file)?)name=("[^"]*|[^ ]*)\.(bat|cmd|com|exe|js|pif|scr)
/dev/null
}

```

规则以惯例的`:0`指令开始。

条件适用如下：

首先，确保我们只过滤大小小于 256 KB 的邮件。这主要是为了效率，大多数垃圾邮件都比这个大小小。如果您收到的病毒更大，您可以显然增加它，但是您的系统可能会负载更高。

下一行表示我们也只查看那些是 MIME 类型的消息（即不是纯文本），因为附件根据定义不能包含在纯文本消息中。

我们在花括号之间有一个子过滤器。`:0B`表示我们正在处理消息的正文，而不是标题。我们必须这样做，因为附件出现在正文中，而不是标题中。然后我们寻找具有可执行文件 MIME 标题特征的行。如果需要，您可以修改文件扩展名；这些只是常用于传输病毒的扩展名。

在这种情况下的操作是，如果匹配，则将此消息发送到`/dev/null`。请注意，这意味着不会向发件人发送任何消息反弹或错误消息；消息只是被丢弃，永远不会再次被看到。当然，您可以将消息存储在安全位置，并指定某人监视不包含病毒的有效消息的帐户。对于这个问题的更优雅的解决方案，请记得查看第九章。

## 大邮件

随着高速、始终在线的互联网连接的日益增加，人们开始发送越来越大的电子邮件。曾经，一个签名文件超过四行被认为是粗鲁的，而如今人们愉快地包含图像和壁纸，并发送电子邮件的 HTML 和文本版本，而不意识到他们发送的邮件大小。

将这样大的消息存储在收件箱中会大大增加搜索邮件消息的处理开销。一个简单的解决方案是将所有超过一定大小的消息移动到一个超大文件夹中。通过使用以下规则，可以非常简单地实现这一点，该规则查找大小超过 100,000 字节的消息，并将它们存储在`largemail`文件夹中。

```
:0:
* >100000
largemail/

```

这条规则的缺点是你的用户需要记住定期检查他们的收件箱和`largemail`文件夹。更优雅的解决方案将允许你复制消息的前几行以及标题和主题行，并将其存储在收件箱中，并通知你需要检查完整版本。这样的解决方案可以在下一章末尾的示例中看到。

# 总结

在本章中，我们已经了解了 Procmail 的一些基础知识。到目前为止，你应该熟悉 Procmail 用于加载配方的各种文件，过滤的核心原则以及可用的选项。我们还分析了电子邮件，设置了个人和系统范围的过滤器，并查看了一些简单的测试、日志记录和调试选项，这些选项将帮助我们更有效地管理公司的邮件。

我们只是刚刚触及了可能性的表面，但希望这点小小的尝试已经给你提供了大量关于如何处理和过滤你每天过载的电子邮件的想法。这可能已经给你提供了更高级过滤器的想法，下一章将提供更多关于如何设置这些过滤器的建议和解释。
