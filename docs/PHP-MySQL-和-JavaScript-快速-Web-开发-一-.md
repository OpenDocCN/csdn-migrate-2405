# PHP、MySQL 和 JavaScript 快速 Web 开发（一）

> 原文：[`zh.annas-archive.org/md5/cfad008c082876a608d45b61650bee20`](https://zh.annas-archive.org/md5/cfad008c082876a608d45b61650bee20)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

更快 Web 可以定义为在所有 Web 技术领域中发展的一系列特质，以加快客户端和服务器之间的任何交易。它还包括可以影响用户对速度感知的 UI 设计原则。因此，理解更快 Web 涉及理解性能、效率和感知性能的概念，并发现构成今天互联网的大部分新基础 Web 技术。

# 本书适合对象

任何希望更好地理解更快 Web 的 Web 开发人员、系统管理员或 Web 爱好者。基本的*Docker*容器技术知识是一个加分项。

# 本书涵盖内容

第一章，*更快 Web-入门*，通过试图更好地理解其正式方面来定义更快 Web，并着手了解如何衡量性能，确定网站或 Web 应用是否属于更快 Web。

第二章，*持续性能分析和监控*，旨在帮助读者学习如何安装和配置性能分析和监控工具，以帮助他们在持续集成（CI）和持续部署（CD）环境中轻松优化 PHP 代码。

第三章，*利用 PHP 7 数据结构和函数的性能*，帮助读者学习如何通过大部分关键优化来利用 PHP 7 的性能提升。它还帮助他们探索更好地理解数据结构和数据类型，以及使用简化的函数如何帮助 PHP 应用程序在其关键执行路径上的全局性能。此外，它介绍了在我们的 PHP 代码中最好避免使用低效结构（如大多数动态结构），以及在优化 PHP 代码时一些功能技术如何立即帮助。

第四章，*异步 PHP 展望未来*，概述了如何通过学习生成器和异步非阻塞代码、使用*POSIX Threads*（`pthreads`）库进行多线程以及使用`ReactPHP`库进行多任务处理来应对输入和输出（I/O）的低延迟。

第五章，*测量和优化数据库性能*，展示了如何测量数据库性能，从简单的测量技术到高级的基准测试工具。

第六章，*高效查询现代 SQL 数据库*，解释了如何使用现代 SQL 技术来优化复杂的 SQL 查询。

[第七章](https://cdp.packtpub.com/mastering_the_faster_web_with_php__mysql__javascript/wp-admin/post.php?post=379&action=edit#post_292)，*JavaScript 和危险驱动开发*，涵盖了 JavaScript 的一些优点和缺点，特别是与代码效率和整体性能有关的部分，以及开发人员应该如何编写安全、可靠和高效的 JavaScript 代码，主要是通过避免“危险驱动开发”。

第八章，*函数式 JavaScript*，介绍了 JavaScript 如何越来越成为一种函数式语言，以及这种编程范式将成为未来性能的一个向量，通过快速查看将帮助改进 JavaScript 应用程序性能的即将推出的语言特性。

第九章，*提升 Web 服务器性能*，介绍了 HTTP/2 协议的相关内容，以及 SPDY 项目是如何实现的，PHP-FPM 和 OPcache 如何帮助提升 PHP 脚本的性能，如何通过设置 Varnish Cache 服务器来使用 ESI 技术，如何使用客户端缓存以及其他更快 Web 工具如何帮助提升 Web 服务器的整体性能。

第十章，*超越性能*，展示了当一切似乎已经完全优化时，通过更好地理解 UI 设计背后的原则，我们仍然可以超越性能。

# 为了充分利用本书

为了运行本书中包含的源代码，我们建议您首先在计算机上安装 Docker（[`docs.docker.com/engine/installation/`](https://docs.docker.com/engine/installation/)）。*Docker*是一个软件容器平台，允许您在隔离和复杂的 chroot-like 环境中轻松连接到计算机的设备。与虚拟机不同，容器不会捆绑完整的操作系统，而只会捆绑运行某些软件所需的二进制文件。您可以在 Windows、Mac 或 Linux 上安装*Docker*。但是需要注意的是，在 macOS 上运行*Docker*时，一些功能，如全功能网络，仍然不可用（[`docs.docker.com/docker-for-mac/networking/#known-limitations-use-cases-and-workarounds`](https://docs.docker.com/docker-for-mac/networking/#known-limitations-use-cases-and-workarounds)）。

本书中我们将使用的主要*Docker*镜像是*Linux for PHP* 8.1（[`linuxforphp.net/`](https://linuxforphp.net/)），其中包含 PHP 7.1.16 的非线程安全版本和*MariaDB*（*MySQL*）10.2.8（asclinux/linuxforphp-8.1:7.1.16-nts）。要启动主容器，请输入以下命令：

```php
# docker run --rm -it \
> -v ${PWD}/:/srv/fasterweb \
> -p 8181:80 \
> asclinux/linuxforphp-8.1:7.1.16-nts \
> /bin/bash
```

如果您喜欢在优化代码的同时使用多线程技术，可以运行*Linux for PHP*的线程安全版本（asclinux/linuxforphp-8.1:7.0.29-zts）。

此外，您应该`docker commit`任何对容器所做的更改，并创建容器的新镜像，以便以后可以`docker run`。如果您不熟悉 Docker 命令行及其`run`命令，请查看文档[`docs.docker.com/engine/reference/run/`](https://docs.docker.com/engine/reference/run/)。

最后，每当您启动原始的 Linux for PHP 镜像并希望开始使用本书中包含的大多数代码示例时，必须在 Linux for PHP 容器内运行以下三个命令：

```php
# /etc/init.d/mysql start
# /etc/init.d/php-fpm start
# /etc/init.d/httpd start
```

# 下载示例代码文件

您可以从[www.packtpub.com](http://www.packtpub.com)的账户中下载本书的示例代码文件。如果您在其他地方购买了本书，可以访问[www.packtpub.com/support](http://www.packtpub.com/support)注册并直接将文件发送到您的邮箱。

您可以按照以下步骤下载代码文件：

1.  请在[www.packtpub.com](http://www.packtpub.com/support)登录或注册

1.  选择“支持”选项卡

1.  点击“代码下载和勘误”

1.  在搜索框中输入书名并按照屏幕上的说明进行操作

文件下载后，请确保使用最新版本的解压缩或提取文件夹：

+   Windows 的 WinRAR/7-Zip

+   Mac 的 Zipeg/iZip/UnRarX

+   Linux 的 7-Zip/PeaZip

该书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Mastering-the-Faster-Web-with-PHP-MySQL-and-JavaScript`](https://github.com/PacktPublishing/Mastering-the-Faster-Web-with-PHP-MySQL-and-JavaScript)。如果代码有更新，将在现有的 GitHub 存储库中更新。

本书中提供的所有代码示例都可以在代码存储库中的以章节编号命名的文件夹中找到。因此，预计您在每章开始时更改工作目录，以便运行其中给出的代码示例。因此，对于第一章，您预计在容器的 CLI 上输入以下命令：

```php
# mv /srv/www /srv/www.OLD
# ln -s /srv/fasterweb/chapter_1 /srv/www
```

接下来的章节，您预计输入以下命令：

```php
# rm /srv/www
# ln -s /srv/fasterweb/chapter_2 /srv/www
```

接下来的章节也是如此。

我们还有其他代码包来自我们丰富的图书和视频目录，可在**[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)**上找到。去看看吧！

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。这是一个例子：“在可能的情况下，开发人员应始终优先使用 `const` 而不是 `let` 或 `var`。”

代码块设置如下：

```php
function myJS()
{
    function add(n1, n2)
    {
        let number1 = Number(n1);
        let number2 = Number(n2);

        return number1 + number2;
    }

}
```

任何命令行输入或输出都以以下方式编写：

```php
# php parallel-download.php 
```

**粗体**：表示新术语、重要单词或屏幕上看到的单词。例如，菜单或对话框中的单词会以这种方式出现在文本中。这是一个例子：“如果您向页面的末尾滚动，现在应该看到一个 xdebug 部分。”

警告或重要提示会以这种方式出现。技巧和窍门会以这种方式出现。


# 第一章：更快速的网络-入门

更快速的网络是一个已经存在几年的表达，用来指代网络性能的许多不同方面。在本书中，我们将更仔细地看看它是什么。为什么它重要？它和性能是一样的吗？我们如何测量它？在开发新项目时何时应该开始考虑它？底层技术是什么，我们如何利用这些技术的力量，使我们的网络项目成为更快速的网络的一部分？

在本章中，我们将首先定义更快速的网络是什么，并尝试更好地了解其正式方面。

此外，在整本书中，我们将提供许多代码示例，以帮助我们更好地理解更快速的网络背后的概念。我们将花时间回顾其起源，评估其当前发展，并展望未来，以了解其下一个重要的里程碑。

目前，我们将从在*Docker*容器中安装基准测试和分析工具开始，以便学会如何使用它们。此外，我们将花时间了解如何测量性能，并确定网站或 Web 应用程序是否属于更快速的网络。

因此，本章将涵盖以下几点：

+   了解更快速的网络是什么，以及为什么它很重要

+   学会区分更快速的网络和性能

+   知道如何测量更快速的网络

+   安装、配置和使用基准测试和分析工具

# 什么是更快速的网络？

2009 年，谷歌宣布其意图使网络更快[1]，并启动了相应的倡议，邀请网络社区想出使互联网更快的方法。宣布称“人们更喜欢更快速、更具响应性的应用程序”，这是谷歌倡议的主要原因。该公告还包括谷歌确定的许多挑战的清单，这些挑战被视为该倡议的首要任务。主要挑战包括：

+   更新老化的协议

+   解决 JavaScript 性能不足的问题

+   寻找新的测量、诊断和优化工具

+   为全球范围内提供更多宽带安装的机会

# 更快速的网络和性能

更快速的网络可以被定义为在所有网络技术领域中发展的一系列特质，以加快客户端和服务器之间的任何交易速度。

但速度有多重要？谷歌在 2010 年发现，任何减速都会直接影响公司的网站流量和广告收入。事实上，谷歌成功地建立了流量和广告收入与结果数量和获取结果所需时间之间的统计相关性。他们的研究结果表明，当在 0.9 秒内获得更多结果与在页面上仅在 0.4 秒内获得更少结果时，流量和广告收入可能会减少 20%。雅虎也证实，约 5%至 9%的用户会放弃加载时间超过 400 毫秒的网页。微软必应在搜索结果交付时额外延迟 2 秒时，收入减少了 4%。显然，速度不仅确保用户参与度，而且对公司的收入和整体表现都有重大影响。

乍一看，更快速的网络似乎与网络性能完全相同。但真的是这样吗？

性能被定义为机制的执行方式。根据*André B. Bondi[2]*的说法，"*计算机系统的性能通常以其以快速速率执行定义的一组活动的能力和快速响应时间来表征*。" 正如*J. D. Meier 等人*在他们关于性能测试的书中所述，"*性能测试是一种旨在确定系统在给定工作负载下的响应性*、*吞吐量*、*可靠性*和/或可扩展性的测试类型*。"

因此，很明显，网站性能是更快网络的核心概念。但是，我们总是期望这些特征是唯一的吗？如果一个应用程序承诺对硬盘进行彻底分析并在不到五秒的时间内完成任务，我们肯定会认为出了问题。根据*Denys Mishunov[4]*的说法，性能也与感知有关。正如*Stéphanie Walter[5]*在她关于感知性能的演讲中所述，"*时间的测量取决于测量的时刻，可以根据要执行的任务的复杂性、用户的心理状态（压力）以及用户根据他认为是执行某项任务时的参考软件所定义的期望而变化*。" 因此，应用程序执行任务的良好方式也意味着软件必须满足用户对计算机程序应该如何执行任务的期望。

尽管更快的网络倡议最初集中精力使不同的网络技术变得更快，但不同的研究使研究人员重新回到了主观时间或感知时间与客观时间或计时时间的概念，以便充分衡量网站性能如何影响用户在浏览网页时的习惯和一般行为。

因此，在本书中，我们将涵盖更快的网络，因为它适用于所有主要的网络技术，也就是说，在全球 70%至 80%的网络服务器上运行的技术以及所有主要的浏览器，即 Apache、PHP、MySQL 和 JavaScript。此外，我们不仅将从开发人员的角度讨论这些主要的网络技术，还将在最后几章中从系统管理员的角度讨论更快的网络，包括 HTTP/2 和反向代理缓存。尽管本书的大部分内容将只涉及网站性能的问题，但最后一章将涵盖更快网络的另一个方面，即通过良好的**用户界面**（**UI**）设计来满足用户的期望。

# 测量更快的网络

现在我们更好地理解了网站性能如何成为更快网络作为整体的一个非常重要部分，更快网络不仅关注效率和速度，还关注完全满足用户的期望，我们现在可以问自己如何客观地衡量更快的网络以及哪些工具最适合这样做。

# 在测量之前

在讨论速度测量时，始终重要的是要记住速度最终取决于硬件，如果在性能不佳的硬件基础设施上运行性能不佳的软件并不一定是问题。

当然，**输入和输出**（**I/O**）始终占据硬件基础设施总延迟的大部分。网络和文件系统是可能出现最糟糕性能的两个主要瓶颈，例如，访问磁盘上的数据可能比**随机存取内存**（**RAM**）慢上百倍，而繁忙的网络可能使网络服务几乎无法访问。

RAM 限制也迫使我们在速度、可伸缩性和准确性方面做出某些权衡。通过缓存应用程序数据的大部分并将所有内容加载到内存中，总是可以获得最高速度的性能。但在所有情况下，这是否是最佳解决方案？在重负载情况下，它是否仍然保持速度？在高度不稳定的数据情况下，数据是否得到了充分的刷新？对这些问题的明显答案可能是否定的。因此，最佳速度是纯速度、合理的内存消耗和可接受的数据陈旧之间的平衡。

为了确定计算机程序的最佳速度而进行性能测量，是通过实施适当的权衡并在之后进行微调来在特定业务规则和可用资源的情况下找到完美平衡的艺术。

因此，评估速度性能的第一步将是分析可用资源，并确定硬件速度性能的上限和下限。由于我们正在处理 Web 性能，这一步将通过对 Web 服务器本身进行基准测试来完成。

第二步将包括对 Web 应用程序进行分析，以分析其内部工作的每个部分的性能，并确定应用程序代码的哪些部分缺乏完美的平衡并应进行优化。

# 基准测试和分析

Web 服务器基准测试是评估 Web 服务器在特定工作负载下的性能的过程。软件分析是分析计算机程序在内存使用和执行时间方面的过程，以优化程序的内部结构。

在本章的这一部分，我们将设置和测试一些工具，这些工具将允许我们对我们的 Web 服务器进行基准测试和对我们将在本书的后续章节中分析的源代码进行分析。

# 实际先决条件

为了运行本书中包含的源代码，我们建议您首先在计算机上安装 Docker（[`docs.docker.com/engine/installation/`](https://docs.docker.com/engine/installation/)）。 Docker 是一个软件容器平台，允许您在隔离和复杂的 chroot-like 环境中轻松连接到计算机的设备。与虚拟机不同，容器不附带完整的操作系统，而是附带所需的二进制文件以运行某些软件。您可以在 Windows、Mac 或 Linux 上安装 Docker。然而，需要注意的是，在 macOS 上运行 Docker 时，一些功能，如全功能网络，仍然不可用（[`docs.docker.com/docker-for-mac/networking/#known-limitations-use-cases-and-workarounds`](https://docs.docker.com/docker-for-mac/networking/#known-limitations-use-cases-and-workarounds)）。

我们将在本书中使用的主要 Docker 镜像是*Linux for PHP* 8.1（[`linuxforphp.net/`](https://linuxforphp.net/)），其中包含 PHP 7.1.16 的非线程安全版本和*MariaDB*（*MySQL*）10.2.8（asclinux/linuxforphp-8.1:7.1.16-nts）。一旦在您的计算机上安装了 Docker，请在类似 bash 的终端中运行以下命令，以获取本书代码示例的副本并启动适当的 Docker 容器：

```php
# git clone https://github.com/andrewscaya/fasterweb 
# cd fasterweb  
# docker run --rm -it \ 
 -v ${PWD}/:/srv/fasterweb \ 
 -p 8181:80 \ 
 asclinux/linuxforphp-8.1:7.1.16-nts \ 
 /bin/bash 
```

运行这些命令后，您应该会得到以下命令提示符：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/fd5577ad-ff2d-4518-bceb-3d106e6fef15.png)Linux for PHP 容器的命令行界面（CLI）**Windows 用户请注意：**请确保在以前的 Docker 命令中的共享卷选项中用您的工作目录的完整路径（例如'/c/Users/fasterweb'）替换'${PWD}'部分，否则您将无法启动容器。此外，您应该确保在 Docker 设置中启用了卷共享。此外，如果您在 Windows 7 或 8 上运行 Docker，您只能在地址 http://192.168.99.100:8181 访问容器，而不能在'localhost:8181'上访问。

本书中提供的所有代码示例都可以在代码存储库中的一个名为根据章节编号命名的文件夹中找到。因此，预计您在每章开始时更改工作目录，以便运行其中给出的代码示例。因此，对于本章，您应该在容器的 CLI 上输入以下命令：

```php
# mv /srv/www /srv/www.OLD
# ln -s /srv/fasterweb/chapter_1 /srv/www
```

对于下一章，您应该输入以下命令：

```php
# rm /srv/www
# ln -s /srv/fasterweb/chapter_2 /srv/www
```

接下来的章节也是如此。

此外，如果您在优化代码时更喜欢使用多线程技术，可以通过运行*Linux for PHP*的线程安全版本（asclinux/linuxforphp-8.1:7.0.29-zts）来实现。

如果您希望以分离模式（`-d`开关）运行容器，请这样做。这将允许您在同一个容器上保持运行并且独立于您是否有运行的终端而运行`docker exec`多个命令 shell。

此外，您应该`docker commit`您对容器所做的任何更改，并创建其新图像，以便以后可以`docker run`它。如果您不熟悉 Docker 命令行及其`run`命令，请在以下地址找到文档：[`docs.docker.com/engine/reference/run/`](https://docs.docker.com/engine/reference/run/)。

最后，Packt Publishing 出版了许多关于 Docker 的优秀书籍和视频，我强烈建议您阅读它们以掌握这个优秀的工具。 

现在，输入以下命令以启动本书中将需要的所有服务，并创建一个测试脚本，以确保一切都按预期工作：

```php
# cd /srv/www
# /etc/init.d/mysql start 
# /etc/init.d/php-fpm start 
# /etc/init.d/httpd start 
# touch /srv/www/index.php 
# echo -e "<?php phpinfo();" > /srv/www/index.php 
```

当您完成这些命令后，您应该将您喜欢的浏览器指向`http://localhost:8181/`，并查看以下结果：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/b825527f-ca80-401b-93bd-836b9a0f1c7c.png)phpinfo 页面

如果您没有看到此页面，请尝试排除您的 Docker 安装问题。

此外，请注意，如果您不`docker commit`您的更改，并且希望在开始使用本书中包含的代码示例时使用原始的 Linux for PHP 基础镜像，那么以前的命令将需要每次都重复。

我们现在准备对我们的服务器进行基准测试。

# 了解 Apache Bench（AB）

有许多工具可用于对 Web 服务器进行基准测试。其中较为知名的是 Apache Bench（AB）、Siege、JMeter 和 Tsung。尽管 JMeter（[`jmeter.apache.org/`](https://jmeter.apache.org/)）和 Tsung（[`tsung.erlang-projects.org/`](http://tsung.erlang-projects.org/)）是非常有趣的负载测试工具，并且在进行更高级别的系统管理上的测试时应该进行探索，但我们将专注于 AB 和 Siege 以满足我们的开发需求。

AB 包含在 Apache Web 服务器的开发工具中，并且默认安装在包含 PHP 二进制文件的 Linux for PHP 镜像中。否则，AB 可以在大多数 Linux 发行版的单独 Apache 开发工具安装包中找到。重要的是要注意，Apache Bench 不支持多线程，这可能会在运行高并发测试时造成问题。

此外，在进行基准测试时有一些常见的陷阱需要避免。主要的是：

+   避免同时在正在进行基准测试的计算机上运行其他资源密集型应用程序

+   避免对远程服务器进行基准测试，因为网络，特别是在并发测试中，可能成为测得的延迟的主要原因

+   避免在通过 HTTP 加速器或代理缓存的网页上进行测试，因为结果将会被扭曲，并且不会显示实际的服务器速度性能

+   不要认为基准测试和负载测试会完美地代表用户与服务器的交互，因为结果只是指示性的

+   请注意，基准测试结果是针对正在测试的硬件架构的，并且会因计算机而异

对于我们的测试，我们将使用 *Apache Bench* 的 `-k`、`-l`、`-c` 和 `-n` 开关。以下是这些开关的定义：

+   -k 启用 KeepAlive 功能，以便在一个单一的 HTTP 会话中执行多个请求

+   -l 当内容长度从一个响应到另一个响应的大小不同时，禁用错误报告

+   -c 启用并发，以便同时执行多个请求

+   -n 确定当前基准测试会话中要执行的请求数

有关 AB 选项的更多信息，请参阅 *Apache* 文档中的相应条目 ([`httpd.apache.org/docs/2.4/programs/ab.html`](https://httpd.apache.org/docs/2.4/programs/ab.html))。

在启动基准测试之前，打开一个新的终端窗口，并通过 `docker exec` 运行一个新的 bash 终端到容器中。这样，您将能够通过 top 实用程序查看资源消耗。首先，获取容器的名称。它将出现在此命令返回的列表中：

```php
# docker ps 
```

然后，您将能够进入容器并开始使用以下命令观察资源消耗：

```php
# docker exec -it [name_of_your_container_here] /bin/bash 
```

并且在容器的新获得的命令行上，请运行 `top` 命令：

```php
# top 
```

现在，从第一个终端窗口启动一个基准测试：

```php
# ab -k -l -c 2 -n 2000 localhost/index.html 
```

然后，您将获得一个基准测试报告，其中包含服务器能够响应的平均请求数 (`每秒请求数`)、每个请求的平均响应时间 (`每个请求的时间`) 和响应时间的标准偏差 (`在特定时间内服务的请求的百分比 (ms)`) 的信息。

报告应该类似于以下内容：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/24bd9ed0-c77c-432b-b3c3-101096d5e152.png)基准测试报告显示，Apache 平均每秒提供约 817 个请求

现在，通过请求 `index.php` 文件来尝试新的基准测试：

```php
# ab -k -l -c 2 -n 2000 localhost/index.php 
```

您会注意到每秒平均请求数已经下降，平均响应时间和标准偏差更高。在我的情况下，平均值从大约 800 下降到我的计算机上的约 300，平均响应时间从 2 毫秒增加到 6 毫秒，响应时间的标准偏差现在从 100% 的请求在 8 毫秒内被服务，增加到 24 毫秒：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/069ab784-57fc-4e0d-b80d-8b8c5f4c2877.png)基准测试报告显示，Apache 平均每秒大约提供 313 个请求

这些结果使我们能够对硬件性能限制有一个大致的了解，并确定在扩展生成一些动态内容的 PHP 脚本性能时，我们将不得不处理的不同阈值。

现在，让我们通过 Siege 进一步深入了解我们的 Web 服务器性能，这是基准测试和负载测试时的首选工具。

# 了解 Siege

Siege 是一个负载测试和基准测试工具，它允许我们进一步分析我们的 Web 服务器性能。让我们开始在 Docker 容器中安装 Siege。

请从容器的命令行下载并解压 Siege 的 4.0.2 版本：

```php
# wget -O siege-4.0.2.tar.gz http://download.joedog.org/siege/siege-4.0.2.tar.gz 
# tar -xzvf siege-4.0.2.tar.gz 
```

然后，请进入 Siege 的源代码目录以编译和安装软件：

```php
# cd siege-4.0.2 
# ./configure 
# make 
# make install 
```

对于这些 Siege 测试，我们将使用`-b`，`-c`和`-r`开关。以下是这些开关的定义：

+   -b，启用基准测试模式，这意味着迭代之间没有延迟

+   `-c`，启用并发以同时执行多个请求

+   `-r`，确定每个并发用户执行的请求数

当然，您可以通过在容器的命令行中调用手册来获取有关 Siege 命令行选项的更多信息：

```php
# man siege  
```

现在启动 Siege 基准测试：

```php
# siege -b -c 3000 -r 100 localhost/index.html 
```

然后您将获得类似这样的基准测试报告：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/b408c27d-e91e-4a80-bb68-fe7659654d72.png)Siege 基准测试报告确认了从 AB 获得的结果

如您所见，结果与我们之前从 AB 获得的结果相匹配。我们的测试显示每秒近 800 次的事务率。

Siege 还配备了一个方便的工具，名为 Bombard，可以自动化测试并帮助验证可伸缩性。Bombard 允许您使用 Siege 和不断增加的并发用户数量。它可以带有一些可选参数。这些参数是：包含在执行测试时使用的 URL 的文件的名称，初始并发客户端的数量，每次调用 Siege 时要添加的并发客户端的数量，Bombard 应该调用 Siege 的次数以及每个请求之间的时间延迟（以秒为单位）。

因此，我们可以尝试通过在容器内部发出以下命令来确认我们之前测试的结果：

```php
# cd /srv/www
# touch urlfile.txt 
# for i in {1..4}; do echo "http://localhost/index.html" >> urlfile.txt ; done  
# bombardment urlfile.txt 10 100 4 0 
```

完成后，您应该获得类似以下的报告：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/7d44d2e3-1a94-4565-aa88-c724d235d090.png)结果显示，当有 210 个或更多并发用户时，最长的事务要高得多

再试一次，但请求 PHP 文件：

```php
# echo "http://localhost/index.php" > urlfile.txt 
# for i in {1..3}; do echo "http://localhost/index.php" >> urlfile.txt ;  done 
# bombardment urlfile.txt 10 100 4 0 
```

这个测试应该提供类似这样的结果：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/3ad97da7-ea6e-4379-8956-4a4b9ca1b77e.png)提供动态内容的效率类似于提供静态内容的效率，但事务率要低得多

现在运行`top`的第二个终端窗口显示了两个可用处理器的 50%使用率和我电脑上几乎 50%的 RAM 使用率：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/023bca16-862c-4227-a3ca-27f0993da7a6.png)容器在提交基准测试时使用的 CPU 和内存资源

我们现在知道，当并发请求不多时，这台硬件可以在小规模上表现良好，静态文件可以达到每秒 800 次的事务率，动态生成内容的页面大约为每秒 200 次的事务率。

现在，我们对基于硬件资源的基本速度性能有了更好的了解，现在我们可以开始真正测量通过性能分析来衡量 Web 服务器动态生成内容的速度和效率。我们现在将继续安装和配置工具，以便我们对 PHP 代码进行性能分析和优化。

# 安装和配置有用的工具

现在我们将安装和配置 MySQL 基准测试和 JavaScript 性能分析工具。但首先，让我们从安装和配置 xdebug 开始，这是一个 PHP 调试器和性能分析工具。

# 性能分析 PHP – xdebug 安装和配置

我们将安装和配置的第一个工具是 xdebug，这是一个用于 PHP 的调试和性能分析工具。这个扩展可以通过使用 PHP 附带的 PECL 实用程序（[`pecl.php.net/`](https://pecl.php.net/)）以非常简单的方式下载、解压缩、配置、编译和安装。要做到这一点，请在容器的终端窗口中输入以下命令：

```php
# pecl install xdebug 
# echo -e "zend_extension=$( php -i | grep extensions | awk '{print $3}' )/xdebug.so\n" >> /etc/php.ini
# echo -e "xdebug.remote_enable = 1\n" >> /etc/php.ini 
# echo -e "xdebug.remote_enable_trigger = 1\n" >> /etc/php.ini 
# echo -e "xdebug.remote_connect_back = 1\n" >> /etc/php.ini 
# echo -e "xdebug.idekey = PHPSTORM\n" >> /etc/php.ini 
# echo -e "xdebug.profiler_enable = 1\n" >> /etc/php.ini 
# echo -e "xdebug.profiler_enable_trigger = 1\n" >> /etc/php.ini 
# /etc/init.d/php-fpm restart
# tail -50 /etc/php.ini
```

您容器的`/etc/php.ini`文件的最后几行现在应该是这样的：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/a6cbcc31-351d-4ac1-9aa3-bf86c88b9cf2.png)在 php.ini 文件中新增的行

完成后，请在您喜爱的浏览器中重新加载`http://localhost:8181`页面。它现在应该显示如下：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/c868f3b7-e7de-4335-9ef7-232f1a36b3b6.png)确认 xdebug 扩展已加载

如果您向页面朝向滚动，现在应该会看到 xdebug 部分：

phpinfo 页面的 xdebug 部分

您还应该注意，在 xdebug 条目下现在启用了性能分析器选项：

确认 xdebug 代码分析已启用

我们现在将配置 PHPStorm 作为调试服务器。这将允许我们将 IDE 用作调试会话的控制中心。

在开始之前，我们将通过在容器内输入以下命令将整个`fasterweb`文件夹作为服务器的网站根目录可用：

```php
# rm /srv/www
# ln -s /srv/fasterweb /srv/www
# cd /srv/www
```

现在，启动*PHPStorm*，并将我们的`fasterweb`目录设置为此项目的主目录。为此，请选择**从现有文件创建新项目**，**源文件位于本地目录**，并在单击**完成**之前将我们的`fasterweb`目录指定为**项目根目录**。

创建后，从“文件”菜单中选择“设置”。在“语言和框架”部分下，展开 PHP 菜单条目，然后单击“服务器”条目。请根据您的设置的具体情况输入所有适当的信息。主机选项必须包含 Linux 的 PHP 容器的 IP 地址值。如果您不确定 Docker 容器的 IP 地址是什么，请在容器的命令行上输入以下命令以获取它：

```php
# ifconfig 
```

完成后，您可以通过单击“应用”和“确定”按钮进行确认：

配置 PHPStorm 以连接到 Web 服务器和 xdebug

然后，在“运行”菜单下，您将找到“编辑配置...”条目。它也可以在 IDE 屏幕的右侧找到：

“编辑配置...”设置

然后，通过单击窗口左上角的绿色加号添加 PHP 远程调试条目。请选择我们在上一步中创建的服务器，并确保将 Ide 密钥（会话 ID）设置为 PHPSTORM：

配置调试会话

现在，通过单击主 PHPStorm 屏幕右上角菜单中的“监听调试器连接”按钮来激活 PHPStorm 调试服务器，通过单击`index.php`文件的任何行号右侧的空白处设置断点，并启动我们在上一步中创建的`index.php`配置对应的调试工具。

如果您的屏幕上没有显示右上方的工具栏菜单，请单击“查看”菜单的“工具栏”条目，以使它们显示在您的屏幕上。这些按钮也可以作为“运行”菜单中的条目进行访问。

激活 PHPStorm 调试服务器，设置断点并启动调试工具

现在，打开您喜欢的浏览器，并通过输入 Docker 容器的 IP 地址请求相同的网页：`http://[IP_ADDRESS]/?XDEBUG_SESSION_START=PHPSTORM`。

然后您会注意到浏览器陷入了无限循环：

浏览器正在等待调试会话恢复或结束

您还会注意到调试信息现在显示在 IDE 中。我们还可以在 IDE 内控制会话，并确定何时会话将从中恢复。请在允许执行恢复之前检查变量的内容，方法是单击屏幕左侧的绿色播放按钮。您还可以通过单击同一图标菜单中的粉红色停止按钮来结束调试会话：

调试会话允许在运行时详细检查变量

调试会话结束后，我们现在可以检查容器的`/tmp`目录，并应该在名为`cachegrind.out`的文件中找到分析器输出。然后，您可以通过您喜欢的文本编辑器直接检查此文件，或者通过安装专门的软件，如您的 Linux 发行版的软件包管理器中的 Kcachegrind 来检查此文件。以下是使用 Kcachegrind 时的示例输出：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/5c519bc9-11da-44e6-a3c0-8d3bd72b9f4d.png)使用 Kcachegrind 查看 xdebug 分析报告

因此，如果您希望在我们将在接下来的章节中使用的工具之上使用 xdebug 的分析工具，它将对您可用。话虽如此，在下一章中，我们将研究更高级的分析工具，如`Blackfire.io`。

在测试 xdebug 完成后，您可以将`chapter_1`文件夹恢复为服务器的网站根目录：

```php
# rm /srv/www
# ln -s /srv/fasterweb/chapter_1 /srv/www
# cd /srv/www
```

现在，让我们继续看一下 SQL 速度测试工具。

# SQL – 速度测试

尽管 PostgreSQL 服务器通常被认为是继*Oracle Database*之后世界上最快的 RDBMS，但*MariaDB*（*MySQL*的分支）服务器仍然是最快和最受欢迎的 RDBMS 之一，特别是在处理简单的 SQL 查询时。因此，在本书中讨论 SQL 优化时，我们将主要使用*MariaDB*。

为了对我们的*MariaDB*服务器进行基准测试，我们将使用自*MySQL*服务器 5.1.4 版本以来包含的`mysqlslap`实用程序。为了运行测试，我们将首先加载`Sakila`测试数据库。在容器的命令行上，输入以下命令：

```php
# wget -O sakila-db.tar.gz \ 
> https://downloads.mysql.com/docs/sakila-db.tar.gz 
# tar -xzvf sakila-db.tar.gz 
# mysql -uroot < sakila-db/sakila-schema.sql 
# mysql -uroot < sakila-db/sakila-data.sql 
```

数据库加载完成后，您可以启动第一个基准测试：

```php
# mysqlslap --user=root --host=localhost --concurrency=20 --number-of-queries=1000 --create-schema=sakila --query="SELECT * FROM film;" --delimiter=";" --verbose --iterations=2 --debug-info  
```

然后，您应该获得类似于这样的结果：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/b3bee95e-44e5-4945-906b-809c4d1699bf.png)使用 mysqlslap 工具对 MariaDB 服务器进行基准测试

然后，您可以运行第二个基准测试，但使用不同的并发级别来比较结果：

```php
# mysqlslap --user=root --host=localhost --concurrency=50 --number-of-queries=1000 --create-schema=sakila --query="SELECT * FROM film;" --delimiter=";" --verbose --iterations=2 --debug-info 
```

以下是第二次测试的结果：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/7390a717-8331-49f9-92be-08f4ac4a5aed.png)使用更高的并发性对 MariaDB 服务器进行基准测试

我的测试结果表明，对于具有大约 1,000 条记录的表的全表扫描查询，在向服务器发送 50 个或更多并发查询时，性能会急剧下降。

我们将看到这些类型的测试以及许多其他更高级的测试在专门讨论此主题的章节中将特别有用。

# JavaScript – 开发者工具

为了衡量性能并分析本书中包含的 JavaScript 代码，我们将使用 Google Chrome 内置的开发者工具。具体来说，Chrome 包括时间线记录器和 JavaScript CPU 分析器，这将允许您识别 JavaScript 代码中的瓶颈。要激活这些工具，请单击浏览器右上角的三个点，然后单击“更多工具”子菜单中的“开发者工具”，如下所示：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/0e59a6b2-55ca-41f9-9346-a6f5c04dd331.png)在 Chrome 的主菜单的“更多工具”部分中找到“开发者工具”条目

使用分析工具就像点击记录按钮并刷新要分析的页面一样简单。然后，您可以分析结果以识别代码中的潜在问题：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/4069e3a6-8d3c-42ec-973e-e45418909c5a.png)Chrome 的时间线记录器和 JavaScript CPU 分析器

在第七章中，*JavaScript 和“危险驱动开发”*，以及第八章中，*函数式 JavaScript*，我们将更广泛地使用此工具，以便全面衡量和优化 JavaScript 代码的性能。

# 摘要

在本章中，我们定义了更快的 Web 是什么，为什么它很重要，它如何与纯速度性能区分开来，以及如何安装、配置和使用基准测试和分析工具来衡量它。

在下一章中，我们将了解使用`Blackfire.io`进行自动分析。此外，我们将通过在一个虚构的生产服务器上安装和配置 TICK 堆栈与 Grafana 来学习监控，该服务器将部署为另一个 Docker 容器。

# 参考文献

[1] [`googleblog.blogspot.ca/2009/06/lets-make-web-faster.html`](https://googleblog.blogspot.ca/2009/06/lets-make-web-faster.html)

[2] BONDI, André B. Foundations of Software and System Performance Engineering: Process, Performance Modeling, Requirements, Testing, Scalability, and Practice. Upper Saddle River, NJ: Addison-Wesley, 2015.

[3] MEIER, J. D. et al. Performance Testing Guidance for Web Applications. Redmond, WA: Microsoft Corporation, 2007.

[4] [`www.smashingmagazine.com/2015/11/why-performance-matters-part-2-perception-management/`](https://www.smashingmagazine.com/2015/11/why-performance-matters-part-2-perception-management/)

[5] [`speakerd.s3.amazonaws.com/presentations/2ece664392024e9da39ea82e3d9f1139/perception-performance-ux-confoo-3-4.pdf`](https://speakerd.s3.amazonaws.com/presentations/2ece664392024e9da39ea82e3d9f1139/perception-performance-ux-confoo-3-4.pdf)


# 第二章：持续分析和监控

在本章中，我们将学习如何安装和配置分析和监控工具，这将帮助您在**持续集成**（**CI**）和**持续部署**（**CD**）环境中轻松优化 PHP 代码。

我们将从安装和配置基本的`Blackfire.io`设置开始，以便在提交到存储库时轻松自动地对代码进行分析。我们还将学习如何安装 TICK Stack，以便在将代码部署到实时生产服务器后持续监视我们代码的性能。

因此，在本章中，我们将涵盖以下几点：

+   安装和配置`Blackfire.io`代理，客户端和 PHP 扩展

+   将`Blackfire.io`客户端与 Google Chrome 集成

+   将`Blackfire.io`客户端集成到像 Travis 这样的已知 CI 工具

+   安装和配置完整的 TICK Stack 与 Grafana

# 什么是 Blackfire.io？

正如官方 Blackfire 网站所述（[`blackfire.io`](https://blackfire.io)），*Blackfire 赋予所有开发人员和 IT/Ops 持续验证和改进其应用程序性能的能力，通过在适当的时刻获取正确的信息。因此，它是一种性能管理解决方案，允许您在整个应用程序生命周期中自动对代码进行分析，并通过断言设置性能标准，特别是在开发阶段*。`Blackfire.io`是一种工具，使 Fabien Potencier 所说的*性能作为特性*成为可能，通过使性能测试成为项目从一开始就开发周期的一部分。

# 安装和配置 Blackfire.io

安装和配置`Blackfire.io`意味着设置三个组件：代理，客户端和 PHP 探针。在本书的背景下，我们将在 Linux 的 PHP 容器中安装`Blackfire.io`。要获取有关在其他操作系统上安装`Blackfire.io`的更多信息，请参阅以下说明：[`blackfire.io/docs/up-and-running/installation`](https://blackfire.io/docs/up-and-running/installation)。

我们将从安装 Blackfire 代理开始。在容器的命令行界面上，输入以下命令：

```php
# rm /srv/www
# ln -s /srv/fasterweb/chapter_2 /srv/www
# cd /srv/www
# wget -O blackfire-agent https://packages.blackfire.io/binaries/blackfire-agent/1.17.0/blackfire-agent-linux_static_amd64
```

下载完成后，您应该看到以下结果：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/65c9d459-6f78-4931-b408-136785016f85.png)Blackfire 代理下载完成

如果是这样，请继续输入以下命令：

```php
# mv blackfire-agent /usr/local/bin/ 
# chmod +x /usr/local/bin/blackfire-agent 
```

现在，我们将把一个基本的代理配置文件复制到我们的`etc`目录：

```php
# mkdir -p /etc/blackfire 
# cp agent /etc/blackfire/ 
```

这是我们刚刚复制的文件的内容。这是一个基本的配置文件，正如 Blackfire 团队建议的那样：

```php
[blackfire] 
; 
; setting: ca-cert 
; desc   : Sets the PEM encoded certificates 
; default: 
ca-cert= 

; 
; setting: collector 
; desc   : Sets the URL of Blackfire's data collector 
; default: https://blackfire.io 
collector=https://blackfire.io/ 

; 
; setting: log-file 
; desc   : Sets the path of the log file. Use stderr to log to stderr 
; default: stderr 
log-file=stderr 

; 
; setting: log-level 
; desc   : log verbosity level (4: debug, 3: info, 2: warning, 1: error) 
; default: 1 
log-level=1 

; 
; setting: server-id 
; desc   : Sets the server id used to authenticate with Blackfire API 
; default: 
server-id= 

; 
; setting: server-token 
; desc   : Sets the server token used to authenticate with Blackfire 
API. It is unsafe to set this from the command line 
; default: 
server-token= 

; 
; setting: socket 
; desc   : Sets the socket the agent should read traces from. Possible 
value can be a unix socket or a TCP address 
; default: unix:///var/run/blackfire/agent.sock on Linux, 
unix:///usr/local/var/run/blackfire-agent.sock on MacOSX, and 
tcp://127.0.0.1:8307 on Windows. 
socket=unix:///var/run/blackfire/agent.sock 

; 
; setting: spec 
; desc   : Sets the path to the json specifications file 
; default: 
spec= 
```

然后，创建一个空文件，将用作代理的套接字：

```php
# mkdir -p /var/run/blackfire 
# touch /var/run/blackfire/agent.sock 
```

最后，我们将注册我们的代理到 Blackfire 服务：

```php
# blackfire-agent -register 
```

一旦您输入了最后一个命令，您将需要提供您的 Blackfire 服务器凭据。这些可以在您的 Blackfire 帐户中找到：[`blackfire.io/account#server`](https://blackfire.io/account#server)。输入凭据后，您可以通过输入以下命令启动代理：

```php
# blackfire-agent start & 
```

启动代理后，您应该看到代理的 PID 号。这告诉您代理正在监听我们之前创建的默认 UNIX 套接字。在本例中，代理的 PID 号为 8：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/e7dcf06d-e85a-4ffc-8f14-27769d0ba0dc.png)Blackfire 代理进程 ID 号显示

安装和配置代理后，您可以安装 Blackfire 客户端。我们将通过以下命令安装和配置客户端。让我们首先下载二进制文件：

```php
# wget -O blackfire https://packages.blackfire.io/binaries/blackfire-agent/1.17.0/blackfire-cli-linux_static_amd64 
```

下载完成后，您应该看到以下消息：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/81e2991b-5479-46af-8597-b0842fd7c96d.png)Blackfire 客户端下载完成

现在您可以继续配置客户端。输入以下命令：

```php
# mv blackfire /usr/local/bin/ 
# chmod +x /usr/local/bin/blackfire 
# blackfire config 
```

在输入最终命令后，您将需要提供 Blackfire 客户端凭据。这些也可以在以下 URL 的 Blackfire 帐户中找到：[`blackfire.io/account#client`](https://blackfire.io/account#client)。

为了在我们的服务器上运行`Blackfire.io`，最后一步是将 Blackfire 探针安装为 PHP 扩展。为了做到这一点，请首先下载库：

```php
# wget -O blackfire.so https://packages.blackfire.io/binaries/blackfire-php/1.20.0/blackfire-php-linux_amd64-php-71.so
```

下载完成后，您应该会收到以下确认消息：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/dbbc8f29-df0d-45ed-b35a-b66504dc1821.png)Blackfire 探针下载完成

然后，您可以将共享库文件复制到 PHP 扩展目录中。如果您不确定该目录的位置，可以在将库文件移动到该目录之前发出以下命令：

```php
# php -i | grep 'extension_dir' 
# mv blackfire.so $( php -i | grep extensions | awk '{print $3}' )
```

在本例中，扩展的目录是`/usr/lib/php/extensions/no-debug-non-zts-20160303`。

现在可以在`PHP.INI`文件中配置扩展。激活 Blackfire 探针时，建议停用其他调试和分析扩展，如 xdebug。请运行以下命令（或者，您可以复制并粘贴我们存储库中已包含这些修改的`PHP.INI`文件）：

```php
# sed -i 's/zend_extension=\/usr\/lib\/php\/extensions\/no-debug-non-zts-20160303\/xdebug.so/;zend_extension=\/usr\/lib\/php\/extensions\/no-debug-non-zts-20160303\/xdebug.so/' /etc/php.ini
# sed -i 's/^xdebug/;xdebug/' /etc/php.ini
# cat >>/etc/php.ini << 'EOF'

[blackfire]
extension=blackfire.so
; On Windows use the following configuration:
; extension=php_blackfire.dll

; Sets the socket where the agent is listening.
; Possible value can be a unix socket or a TCP address.
; Defaults to unix:///var/run/blackfire/agent.sock on Linux,
; unix:///usr/local/var/run/blackfire-agent.sock on MacOSX,
; and to tcp://127.0.0.1:8307 on Windows.
;blackfire.agent_socket = unix:///var/run/blackfire/agent.sock

blackfire.agent_timeout = 0.25

; Log verbosity level (4: debug, 3: info, 2: warning, 1: error)
;blackfire.log_level = 1

; Log file (STDERR by default)
;blackfire.log_file = /tmp/blackfire.log

;blackfire.server_id =

;blackfire.server_token =
EOF 
```

请通过重新启动 PHP-FPM 来完成扩展的安装和配置：

```php
# /etc/init.d/php-fpm restart 
```

让我们从命令行对我们的第一个脚本进行分析。您现在可以通过在容器的 CLI 上输入以下命令来运行客户端：

```php
# blackfire curl http://localhost/index.php 
```

分析完成后，您将获得一个 URL 和一些分析统计信息。如果浏览到该 URL，您将看到分析的调用图，并获得有关分析脚本的更详细信息：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/61a6dd68-99c9-46e6-8447-9012886ceadb.png)Blackfire 客户端返回一个初步的分析报告和一个 URL，以查看脚本的调用图

您还可以选择将客户端安装为浏览器插件。在本例中，我们将使用 Blackfire Companion，一个 Google Chrome 扩展程序。要安装该扩展，请使用 Chrome 访问以下 URL 并单击安装按钮：[`blackfire.io/docs/integrations/chrome`](https://blackfire.io/docs/integrations/chrome)。安装完成后，可以通过浏览到页面并单击工具栏中的 Blackfire Companion 图标，然后单击 Profile 按钮来对服务器上的资源进行分析：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/6f6c1807-4dee-4cea-bf6e-0f5525a9485c.png)Chrome 的 Blackfire Companion 允许您直接从浏览器对 PHP 脚本进行分析

# 使用 Blackfire.io 手动进行分析

我们将首先手动对两个 PHP 脚本进行分析，以更好地了解 Blackfire 工具的用途和功能。我们将使用以下脚本，可以在我们的存储库（`chap2pre.php`）中找到：

```php
<?php 

function getDiskUsage(string $directory) 
{ 
    $handle = popen("cd $directory && du -ch --exclude='./.*'", 'r'); 

    $du = stream_get_contents($handle); 

    pclose($handle); 

    return $du; 
} 

function getDirList(string $directory, string &$du) 
{ 
    $result = getDiskUsage($directory); 

    $du = empty($du) 
        ? '<br />' . preg_replace('/\n+/', '<br />', $result) 
        : $du; 

    $fileList = []; 

    $iterator = new RecursiveDirectoryIterator($directory, FilesystemIterator::SKIP_DOTS); 

    foreach($iterator as $entry) { 

        if (!$entry->isDir() && $entry->getFilename()[0] != '.') { 
            $fileList[$entry->getFilename()] = 'size is ' . $entry->getSize(); 
        } else { 
            if ($entry->isDir() && $entry->getFilename()[0] != '.') { 
                $fileList[$entry->getFilename()] = getDirList( 
                    $directory . DIRECTORY_SEPARATOR . $entry->getFilename(), 
                    $du 
                );
 }
        } 

    } 

    return $fileList; 
} 

$du = ''; 

$baseDirectory = dirname(__FILE__); 

$fileList = getDirList($baseDirectory, $du); 

echo '<html><head></head><body><p>'; 

echo 'Disk Usage : ' . $du . '<br /><br /><br />'; 

echo 'Directory Name : ' . $baseDirectory . '<br /><br />'; 

echo 'File listing :'; 

echo '</p><pre>'; 

print_r($fileList); 

echo '</pre></body></html>'; 

```

该脚本基本上列出了存储库中包含的所有文件（目录及其子目录），并计算了每个文件的大小。此外，它还给出了每个目录大小的汇总结果。请使用 Chrome 浏览到以下 URL 以查看脚本的输出并使用 Blackfire Companion 启动分析：`http://localhost:8181/chap2pre.php`：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/171e5bab-1f71-40f1-9f7b-125aa6bd05f3.png)单击右上方工具栏中的 Blackfire 图标将允许您启动分析会话

单击 Profile 按钮并等待几秒钟后，您应该可以单击 View Call Graph 按钮：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/f7030d4d-e30b-437b-820e-6c5d3e56b125.png)您可以单击“查看调用图”按钮查看脚本的调用图

结果应该如下：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/55a58fb4-3274-4c85-bd77-17660c01d532.png)该脚本执行完成所需的时间为 14.3 毫秒，并且使用'popen'函数创建了五个进程

结果显示，这个脚本的实际时间（墙时间[1]）为 14.3 毫秒，而唯一具有重要独占时间的函数是`stream_get_contents`和`popen`。这是合理的，因为脚本必须处理磁盘访问和可能大量的 I/O 延迟。不太合理的是，脚本似乎要创建五个子进程来获取一个简单的文件列表。

此外，如果我们向下滚动，我们会注意到`SplInfo::getFilename`被调用了六十七次，几乎是目录中文件数量的两倍：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/6be50866-01b2-444c-8ac4-7ff1716958e1.png)SplFileInfo::getFilename 函数被调用了 67 次

从分析器获得的信息使我们能够快速确定我们代码库的哪些部分应该成为代码审查的候选项，以及在审查它们时要寻找什么。快速查看我们的代码表明，我们在每个目录迭代中都调用了`popen`，而不是只在开始时调用一次。一个简单的修复方法是用以下两行代码替换：

```php
function getDirList(string $directory, string &$du) 
{ 
    $result = getDiskUsage($directory); 

    $du = empty($du) 
        ? '<br />' . preg_replace('/\n+/', '<br />', $result) 
        : $du;  
[...]  
```

然后，以下代码行可以插入到它们的位置：

```php
function getDirList(string $directory, string &$du) 
{ 
    $du = empty($du) 
        ? '<br />' . preg_replace('/\n+/', '<br />', getDiskUsage($directory)) 
        : $du;

[...]
```

最后的调整是用包含函数调用结果的变量替换所有对`SplInfo::getFilename()`的调用。修改后的脚本如下所示：

```php
<?php 

function getDiskUsage(string $directory) 
{ 
    $handle = popen("cd $directory && du -ch --exclude='./.*'", 'r'); 

    $du = stream_get_contents($handle); 

    pclose($handle); 

    return $du; 
} 

function getDirList(string $directory, string &$du) 
{ 
    $du = empty($du) 
        ? '<br />' . preg_replace('/\n+/', '<br />', getDiskUsage($directory)) 
        : $du; 

    $fileList = []; 

    $iterator = new RecursiveDirectoryIterator($directory, FilesystemIterator::SKIP_DOTS); 

    foreach($iterator as $entry) { 

        $fileName = $entry->getFilename(); 

        $dirFlag = $entry->isDir(); 

        if (!$dirFlag && $fileName[0] != '.') { 
            $fileList[$fileName] = 'size is ' . $entry->getSize(); 
        } else { 
            if ($dirFlag && $fileName[0] != '.') { 
                $fileList[$fileName] = getDirList( 
                    $directory . DIRECTORY_SEPARATOR . $fileName, 
                    $du 
                ); 
            } 
        } 

    } 

    return $fileList; 
} 

$du = ''; 

$baseDirectory = dirname(__FILE__); 

$fileList = getDirList($baseDirectory, $du); 

echo '<html><head></head><body><p>'; 

echo 'Disk Usage : ' . $du . '<br /><br /><br />'; 

echo 'Directory Name : ' . $baseDirectory . '<br /><br />'; 

echo 'File listing :'; 

echo '</p><pre>'; 

print_r($fileList); 

echo '</pre></body></html>'; 
```

让我们尝试对新脚本（`chap2post.php`）进行分析，以衡量我们的改进。同样，请使用 Chrome 浏览到以下网址查看脚本的输出，并使用 Blackfire Companion 启动分析：`http://localhost:8181/chap2post.php`。

结果应该如下：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/da3260d9-14de-48b4-b1ec-735d990cd3d2.png)现在，脚本只需要 4.26 毫秒来完成执行，并且只使用'popen'函数创建了一个进程

结果显示，这个脚本现在的墙时间为 4.26 毫秒，而`popen`函数只创建了一个子进程。此外，如果我们向下滚动，我们现在注意到`SplInfo::getFilename`只被调用了三十三次，比之前少了两倍：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/4bcc5dee-e4c1-47c0-b10e-3387d621b989.png)现在，SplFileInfo::getFilename 函数只被调用了 33 次

这些都是重大的改进，特别是如果这个脚本要在不同的目录结构上每分钟被调用数千次。确保这些改进不会在应用程序开发周期的未来迭代中丢失的一个好方法是通过性能测试自动化分析器。现在我们将快速介绍如何使用`Blackfire.io`自动化性能测试。

# 使用 Blackfire.io 进行性能测试

在开始之前，请注意，此功能仅适用于高级和企业用户，因此需要付费订阅。

为了自动化性能测试，我们将首先在我们的存储库中创建一个非常简单的`blackfire.yml`文件。这个文件将包含我们的测试。一个测试应该由一个名称、一个正则表达式和一组断言组成。最好避免创建易变的时间测试，因为这些测试很容易变得非常脆弱，可能会导致从一个分析会话到下一个分析会话产生非常不同的结果。强大的性能测试示例包括检查 CPU 或内存消耗、SQL 查询数量或通过配置比较测试结果。在我们的情况下，我们将创建一个非常基本和易变的时间测试，只是为了举一个简短和简单的例子。以下是我们`.blackfire.yml`文件的内容：

```php
tests: 
    "Pages should be fast enough": 
        path: "/.*" # run the assertions for all HTTP requests 
        assertions: 
            - "main.wall_time < 10ms" # wall clock time is less than 10ms 
```

最后一步是将这个性能测试与持续集成工具集成。要选择您喜欢的工具，请参阅以下网址的文档：[`blackfire.io/docs/integrations/index`](https://blackfire.io/docs/integrations/index)。

在我们的情况下，我们将与*Travis CI*集成。为此，我们必须创建两个文件。一个将包括我们的凭据，并且必须加密（`.blackfire.travis.ini.enc`）。另一个将包括我们的 Travis 指令（`.travis.yml`）。

这是我们的`.blackfire.travis.ini`文件在加密之前的内容（用您自己的凭据替换）：

```php
[blackfire] 

server-id=BLACKFIRE_SERVER_ID 
server-token=BLACKFIRE_SERVER_TOKEN 
client-id=BLACKFIRE_CLIENT_ID 
client-token=BLACKFIRE_CLIENT_TOKEN 
endpoint=https://blackfire.io/ 
collector=https://blackfire.io/ 
```

然后，必须在提交到存储库之前对该文件进行加密。为此，请在 Linux for PHP 容器内部发出以下命令：

```php
# gem install travis
# travis encrypt-file /srv/www/.blackfire.travis.ini -r [your_Github_repository_name_here] 
```

这是我们的`.travis.yml`文件的内容：

```php
language: php 

matrix: 
    include: 
        - php: 5.6 
        - php: 7.0 
          env: BLACKFIRE=on 

sudo: false 

cache: 
    - $HOME/.composer/cache/files 

before_install: 
    - if [[ "$BLACKFIRE" = "on" ]]; then 
        openssl aes-256-cbc -K [ENCRYPT_KEY_HERE] -iv [ENCRYPT_IV_HERE] -in .blackfire.travis.ini.enc -out ~/.blackfire.ini -d 
        curl -L https://blackfire.io/api/v1/releases/agent/linux/amd64 | tar zxpf - 
        chmod 755 agent && ./agent --config=~/.blackfire.ini --socket=unix:///tmp/blackfire.sock & 
      fi 

install: 
    - travis_retry composer install 

before_script: 
    - phpenv config-rm xdebug.ini || true 
    - if [[ "$BLACKFIRE" = "on" ]]; then 
        curl -L https://blackfire.io/api/v1/releases/probe/php/linux/amd64/$(php -r "echo PHP_MAJOR_VERSION . PHP_MINOR_VERSION;")-zts | tar zxpf - 
        echo "extension=$(pwd)/$(ls blackfire-*.so | tr -d '[[:space:]]')" > ~/.phpenv/versions/$(phpenv version-name)/etc/conf.d/blackfire.ini 
        echo "blackfire.agent_socket=unix:///tmp/blackfire.sock" >> ~/.phpenv/versions/$(phpenv version-name)/etc/conf.d/blackfire.ini 
      fi 

script: 
    - phpunit 
```

一旦提交，此配置将确保性能测试将在每次 git 推送到您的 Github 存储库时运行。因此，性能成为一个特性，并且像应用程序的其他任何特性一样持续测试。下一步是在生产服务器上部署代码后监视代码的性能。让我们了解一些可用的工具，以便这样做。

# 使用 TICK 堆栈监控性能

TICK 堆栈是由 InfluxData（*InfluxDB*）开发的，由一系列集成组件组成，允许您轻松处理通过时间生成的不同服务的时间序列数据。TICK 是一个首字母缩写词，由监控套件的每个主要产品的首字母组成。T 代表 Telegraf，它收集我们希望在生产服务器上获取的信息。I 代表 InfluxDB，这是一个包含 Telegraf 或任何其他配置为这样做的应用程序收集的信息的时间序列数据库。C 代表 Chronograf，这是一个图形工具，可以让我们轻松地理解收集的数据。最后，K 代表 Kapacitor，这是一个警报自动化工具。

监控基础设施性能不仅对于确定应用程序和脚本是否按预期运行很重要，而且还可以开发更高级的算法，如故障预测和意外行为模式识别，从而使得可以自动化性能监控的许多方面。

当然，还有许多其他出色的性能监控工具，比如 Prometheus 和 Graphite，但我们决定使用 TICK 堆栈，因为我们更感兴趣的是事件日志记录，而不是纯粹的指标。有关 TICK 堆栈是什么，内部工作原理以及用途的更多信息，请阅读 Gianluca Arbezzano 在 Codeship 网站上发表的这篇非常信息丰富的文章：[`blog.codeship.com/infrastructure-monitoring-with-tick-stack/`](https://blog.codeship.com/infrastructure-monitoring-with-tick-stack/)。

现在，为了查看我们的`Blackfire.io`支持的分析有多有用，以及我们的代码变得更加高效，我们将再次运行这两个脚本，但是这次使用官方 TICK Docker 镜像的副本，以便我们可以监视优化后的 PHP 脚本部署到 Web 服务器上后，Web 服务器的整体性能是否有所改善。我们还将用 Grafana 替换 Chronograf，这是一个高度可定制的图形工具，我们不会设置 Kapacitor，因为配置警报略微超出了我们当前目标的范围。

让我们开始激活 Apache 服务器上的`mod_status`。从我们的 Linux for PHP 的 CLI 中，输入以下命令：

```php
# sed -i 's/#Include \/etc\/httpd\/extra\/httpd-info.conf/Include \/etc\/httpd\/extra\/httpd-info.conf/' /etc/httpd/httpd.conf 
# sed -i 's/Require ip 127/Require ip 172/' /etc/httpd/extra/httpd-info.conf 
# /etc/init.d/httpd restart 
```

完成后，您应该能够通过 Chrome 浏览器浏览以下 URL 来查看服务器的状态报告：`http://localhost:8181/server-status?auto`。

下一步是启动 TICK 套件。请打开两个新的终端窗口以执行此操作。

在第一个终端窗口中，输入此命令：

```php
# docker run -d --name influxdb -p 8086:8086 andrewscaya/influxdb 
```

然后，在第二个新打开的终端窗口中，通过发出此命令获取我们两个容器的 IP 地址：

```php
# docker network inspect bridge 
```

这是我在我的计算机上运行此命令的结果：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/ce8758b7-ec84-4df8-88cd-455cec441844.png)两个容器的 IP 地址

请保留这两个地址，因为配置 Telegraf 和 Grafana 时将需要它们。

现在，我们将使用一个简单的命令生成 Telegraf 的示例配置文件（此步骤是可选的，因为示例文件已经包含在本书的存储库中）。

首先，将目录更改为我们项目的工作目录（Git 存储库），然后输入以下命令：

```php
# docker run --rm andrewscaya/telegraf -sample-config > telegraf.conf 
```

其次，用您喜欢的编辑器打开新文件，并取消注释`inputs.apache`部分中的以下行。不要忘记在`urls`行上输入我们 Linux *for PHP*容器的 IP 地址：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/e8c183a7-d96c-49b5-8d1b-1120d6acac48.png)配置 Telegraf 以监视在另一个容器中运行的 Apache 服务器

在终端窗口中，现在可以使用以下命令启动 Telegraf（请确保您在我们项目的工作目录中）：

```php
# docker run --net=container:influxdb -v ${PWD}/telegraf.conf:/etc/telegraf/telegraf.conf:ro andrewscaya/telegraf
```

在第二个新生成的终端窗口中，使用以下命令启动 Grafana：

```php
# docker run -d --name grafana -p 3000:3000 andrewscaya/grafana
```

使用 Chrome 浏览到`http://localhost:3000/login`。您将看到 Grafana 的登录页面。请使用用户名 admin 和密码 admin 进行身份验证：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/56f9895a-06a5-4188-8875-ac3e1220d599.png)显示 Grafana 登录页面

然后，添加新数据源：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/2a0326db-90f7-4ce5-b350-936ee3e6acfd.png)将 Grafana 连接到数据源

请选择 InfluxDB 数据源的名称。选择 InfluxDB 作为类型。输入 InfluxDB 容器实例的 URL，其中包括您在之前步骤中获得的 IP 地址，后跟 InfluxDB 的默认端口号 8086。您可以选择直接访问。数据库名称是 telegraf，数据库用户和密码是 root:

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/efe9ed1a-b23c-411e-bff9-69b844c5a244.png)配置 Grafana 的数据源

最后，单击添加按钮：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/01c2e253-e68f-4b92-9070-5da430a891c8.png)添加数据源

现在数据源已添加，让我们添加一些从 Grafana 网站导入的仪表板。首先点击仪表板菜单项下的导入：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/aaa308c4-dd9a-4ba5-9a9d-0891eac34f73.png)单击导入菜单项开始导入仪表板

我们将添加的两个仪表板如下：

+   Telegraf 主机指标（[`grafana.com/dashboards/1443`](https://grafana.com/dashboards/1443)）：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/f33d00fa-ffd4-457c-8190-0a263d1a5105.png)Telegraf 主机指标仪表板的主页

+   Apache 概览（[`grafana.com/dashboards/331`](https://grafana.com/dashboards/331)）：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/2356dfeb-5bca-458a-aba8-8bd40c185f83.png)Apache 概览仪表板的主页

在导入屏幕上，只需输入仪表板的编号，然后单击加载：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/5f6f1fe5-7540-4412-a155-4989ae0098a7.png)加载 Telegraf 主机指标仪表板

然后，确认新仪表板的名称并选择我们的本地 InfluxDB 连接：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/96777062-1a40-4a25-aba2-3e1101f5239d.png)将 Telegraf 主机指标仪表板连接到 InfluxDB 数据源

现在您应该看到新的仪表板：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/d04fec9b-f9c4-4ddb-9df5-8d6c708a9156.png)显示 Telegraf 主机指标仪表板

现在，我们将重复最后两个步骤，以导入 Apache 概览仪表板。单击仪表板菜单项下的导入按钮后，输入仪表板的标识符（`331`），然后单击加载按钮：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/e0c0faa6-3265-4e1d-ae5a-2afac962ffdc.png)加载 Apache 概览仪表板

然后，确认名称并选择我们的本地 InfluxDB 数据源：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/a207e4f0-7695-4895-856e-3a6d5a821eec.png)将 Apache 概览仪表板连接到 InfluxDB 数据源

现在您应该在浏览器中看到第二个仪表板：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/bf9d26a3-d85b-4964-a48c-3a462ffb0c93.png)显示 Apache 概览仪表板

所有 TICK 套件仪表板都允许更高级的图形配置和自定义。因此，通过执行自定义 cron 脚本，可以收集一组自定义的时间序列数据点，然后配置仪表板以按您的要求显示这些数据。

在我们当前的例子中，TICK 套件现在已安装和配置。因此，我们可以开始测试和监视使用`Blackfire.io`在本章第一部分中进行优化的 PHP 脚本，以测量其性能的变化。我们将首先部署、进行基准测试和监视旧版本。在 Linux 上的 PHP CLI 中，输入以下命令以对旧版本的脚本进行基准测试：

```php
# siege -b -c 3000 -r 100 localhost/chap2pre.php 
```

基准测试应该产生类似以下结果：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/845dd1b4-a034-4c57-bfe1-6dd3fda39694.png)显示了原始脚本的性能基准测试结果

然后，等待大约十分钟后，通过输入以下命令开始对新版本的脚本进行基准测试：

```php
# siege -b -c 3000 -r 100 localhost/chap2post.php 
```

这是我电脑上最新基准测试的结果：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/23505778-9583-41ba-be5d-b6a440b2c7f0.png)显示了优化脚本的性能基准测试结果

结果已经显示出性能上的显著改善。事实上，新脚本每秒允许的交易数量是原来的三倍多，失败交易的数量也减少了三分之一以上。

现在，让我们看看我们的 TICK Stack 收集了关于这两个版本的 PHP 脚本性能的哪些数据：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/148e9e94-8227-4989-8ddb-1de83c5f8a0b.png)监控图表中清楚地显示了性能的提升

我们 Grafana 仪表板中的图表清楚地显示了与基准测试结果本身相同数量级的性能提升。在 08:00 之后对新版本脚本进行的基准测试明显使服务器负载减少了一半，输入（I/O）减少了一半以上，并且总体上比之前在 7:40 左右进行基准测试的旧版本快了三倍以上。因此，毫无疑问，我们的`Blackfire.io`优化使得新版本的 PHP 脚本更加高效。

# 总结

在本章中，我们学习了如何安装和配置基本的`Blackfire.io`设置，以便在提交到存储库时轻松自动地对代码进行分析。我们还探讨了如何安装 TICK Stack，以便在将代码部署到实时生产服务器后持续监视其性能。因此，我们已经了解了如何安装和配置分析和监视工具，这些工具可以帮助我们在**持续集成**（**CI**）和**持续部署**（**CD**）环境中轻松优化 PHP 代码。

在下一章中，我们将探讨如何更好地理解 PHP 数据结构并使用简化的函数可以帮助应用程序在其关键执行路径上的全局性能。我们将首先分析项目的关键路径，然后微调其某些数据结构和函数。

# 参考资料

[1] 关于这些性能测试术语的进一步解释，请访问以下网址：[`blackfire.io/docs/reference-guide/time`](https://blackfire.io/docs/reference-guide/time)。


# 第三章：利用 PHP 7 数据结构和函数的强大功能

在本章中，我们将学习如何利用 PHP 7 的性能优化。

此外，我们将探讨更好地理解数据结构和数据类型，以及如何使用简化的函数可以帮助 PHP 应用程序在其关键执行路径上提高全局性能。

此外，我们将学习如何避免在 PHP 代码中使用效率低下的结构，比如大多数动态结构。

最后，尽管 PHP 不是一种函数式语言，但我们将看到一些函数式技术在优化 PHP 代码时可以立即提供帮助。

因此，在本章中，我们将涵盖以下几点：

+   PHP 7 的优化

+   识别可能的优化并避免动态结构

+   函数式编程和记忆化

# PHP 7 的优化

PHP 7 本身就是一个重大的优化。PHP 的大部分代码库都是为了这个版本而重写的，大多数官方基准测试显示，一般来说，几乎任何 PHP 代码在 PHP 7 上运行的速度都比以前的版本快两倍或更多。

PHP 是用 C 编程的，优化 Zend 的**Ahead-Of-Time**（**AOT**）编译器的性能最终取决于以优化的方式使用 C 编译器的内部逻辑。PHP 7 的最新版本是 Zend 多年研究和实验的结果。这些优化的大部分是通过消除由某些 PHP 内部结构构造和数据结构产生的性能开销来实现的。根据*Dmitry Stogov[1]*的说法，*典型的现实生活中的 PHP 应用程序大约有 20%的 CPU 时间用于内存管理器，10%用于哈希表操作，30%用于内部函数，只有 30%用于虚拟机。*为了优化 PHP 代码的执行，PHP 7 的 Zend 引擎的新版本必须首先将源代码表示为**抽象语法树**（**AST**），从而使引擎能够生成更高质量的**中间表示**（**IR**）源代码，并且自 PHP 7.1 以来，能够删除死代码并尽可能将许多表达式转换为它们的静态表示形式，通过**静态单赋值**（**SSA**）形式和类型推断。反过来，这使得引擎只需在运行时将必要的数据结构分配到堆栈而不是内存中的堆中。

这对于理解本章的其余部分非常重要，因为它让我们看到为什么数据类型转换和动态结构通常会通过在运行时膨胀内存分配来创建大部分开销，为什么必须重新实现某些数据结构以实现 C 级性能，以及为什么不可变性是开发人员在努力实现更好代码性能时的盟友。让我们更仔细地看看这些元素。

# 严格类型

当一种语言是动态类型的，也就是说，它具有松散类型的变量，它提供了更高级的抽象，提高了开发人员的生产力，但在尝试确定变量的数据类型时，编译器需要更多的工作，因此性能并不是最佳的。毫不奇怪，强类型语言在运行时的性能总是比松散类型的语言更好。这个结论得到了 Facebook 的 HipHop 项目的证实，该项目对不同语言进行了基准测试，并得出结论：静态编译的语言总是比动态语言执行更快，消耗的内存也更少。

尽管 PHP 7 仍然是一种松散类型的语言，但现在它提供了严格类型化变量和函数签名的可能性。可以通过执行以下代码示例来轻松测试。让我们运行以下代码来查看其当前性能：

```php
// chap3_strict_typing.php 

declare(strict_types = 0); 

$start = microtime(true); 

function test ($variable) 
{ 
    $variable++; 

    return "$variable is a test."; 
} 

ob_start(); 

for ($x = 0; $x < 1000000; $x++) { 

    $array[$x] = (string) $x; 

    echo test($array[$x]) . PHP_EOL; 

} 

$time = microtime(true) - $start; 

ob_clean(); 

ob_end_flush(); 

echo 'Time elapsed: ' . $time . PHP_EOL; 
```

以下是使用`Blackfire.io`运行此脚本的结果：

省略变量和函数签名的严格类型化时的分析报告

现在，让我们用以下代码替换原来的代码：

```php
// chap3_strict_typing_modified.php 

declare(strict_types = 1); 

$start = microtime(true); 

function test (int $variable) : string 
{ 
    $variable++; 

    return $variable . ' is a test.'; 
} 

ob_start(); 

for ($x = 0; $x < 1000000; $x++) { 

    $array[$x] = (int) $x; 

    echo test($array[$x]) . PHP_EOL; 

} 

$time = microtime(true) - $start; 

ob_clean(); 

ob_end_flush(); 

echo 'Time elapsed: ' . $time . PHP_EOL; 
```

如果我们执行它，我们会立即看到性能上的差异：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/694aceeb-df0c-4312-ac07-845f920538f7.png)在严格类型变量和函数签名的性能分析报告

使用`microtime()`函数也可以看到性能提升。让我们运行我们脚本的两个版本，看看结果：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/6eceebe1-668a-4c3c-8749-bb70f9ff3648.png)使用 microtime()函数比较脚本性能

为了充分利用 PHP 的新 AST 和 SSA 功能，开发人员应尽可能严格地对变量和函数签名进行类型限定。当 Zend 引擎在未来版本中获得**即时**（**JIT**）编译器时，这将变得尤为重要，因为这将允许基于类型推断进行进一步的优化。

严格类型的另一个附加优势是，它让编译器管理代码质量的一个方面，消除了需要进行单元测试来确保函数在接收到意外输入时表现如预期的必要性。

# 不可变和紧凑数组

正如我们将在本章后面看到的，不可变性不仅有助于开发人员在编程时减轻认知负担，提高代码质量和一般单元测试的质量，而且还将允许编译器进行更好的代码优化。从 PHP 7 开始，任何静态数组都会被 OPcache 缓存，并且指向数组的指针将与尝试访问它的代码的任何部分共享。此外，PHP 7 为紧凑数组提供了一个非常重要的优化，这些数组只使用升序整数进行索引。让我们拿以下代码来对比在启用 OPcache 的 PHP 5.6 和 PHP 7 上执行的结果：

```php
// chap3_immutable_arrays.php 

$start = microtime(true); 

for ($x = 0; $x < 10000; $x++) { 
    $array[] = [ 
        'key1' => 'This is the first key', 
        'key2' => 'This is the second key', 
        'key3' => 'This is the third key', 
    ]; 
} 

echo $array[8181]['key2'] . PHP_EOL; 

$time = microtime(true) - $start; 

echo 'Time elapsed: ' . $time . PHP_EOL; 

echo memory_get_usage() . ' bytes' . PHP_EOL; 
```

如果我们用 PHP 5.6 运行之前的代码，我们会消耗近 7.4MB 的内存，耗时为 0.005 秒：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/df382441-74a2-45f4-92f1-fc2e750ab0d2.png)在 PHP 5.6 上运行脚本时的结果

如果我们用 PHP 7 运行相同的代码，我们会得到以下结果：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/49b7fa67-c85d-412a-8889-450f65f22082.png)在 PHP 7.1 上运行相同脚本时的结果

结果令人印象深刻。相同的脚本快了 40 倍，内存消耗几乎减少了 10 倍。因此，不可变数组提供了更快的速度，开发人员应该避免修改大数组，并在处理大数组时尽可能使用紧凑数组，以优化内存分配并最大化运行时速度。

# 整数和浮点数的内存分配

PHP 7 引入的另一个优化是重用先前分配的变量容器。如果你需要创建大量的变量，你应该尝试重用它们，因为 PHP 7 的编译器将避免重新分配内存，并重用已经分配的内存槽。让我们看下面的例子：

```php
// chap3_variables.php 

$start = microtime(true); 

for ($x = 0; $x < 10000; $x++) { 
    $$x = 'test'; 
} 

for ($x = 0; $x < 10000; $x++) { 
    $$x = $x; 
} 

$time = microtime(true) - $start; 

echo 'Time elapsed: ' . $time . PHP_EOL; 

echo memory_get_usage() . ' bytes' . PHP_EOL; 
```

让我们运行这段代码，以便看到内存消耗的差异。让我们从 PHP 5.6 开始：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/2473ad97-fcf2-4790-bbbf-f365b20254a6.png)在 PHP 5.6 上运行脚本时的结果

现在，让我们用 PHP 7 运行相同的脚本：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/7b7954ca-cba2-44a4-b588-c7efb8e78b2d.png)在 PHP 7.1 上运行相同脚本时的结果

正如你所看到的，结果显示内存消耗减少了近三分之一。尽管这违背了变量不可变的原则，但当你必须在内存中分配大量变量时，这仍然是一个非常重要的优化。

# 字符串插值和连接

在 PHP 7 中，使用新的字符串分析算法对字符串插值进行了优化。这意味着字符串插值现在比连接快得多，过去关于连接和性能的说法不再成立。让我们拿以下代码示例来衡量新算法的性能：

```php
// chap3_string_interpolation.php

$a = str_repeat(chr(rand(48, 122)), rand(1024, 3000));

$b = str_repeat(chr(rand(48, 122)), rand(1024, 3000));

$start = microtime(true);

for ($x = 0; $x < 10000; $x++) {
    $$x = "$a is not $b";
}

$time = microtime(true) - $start;

echo 'Time elapsed: ' . $time . PHP_EOL;

echo memory_get_usage() . ' bytes' . PHP_EOL; 
```

在运行这段代码时，以下是对 PHP 5.6 的性能测量：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/aff9b54f-71a9-43e0-8a4c-ddd1dc2dda5b.png)针对 PHP 5.6 运行相同脚本的结果

以下是使用 PHP 7 的相同脚本：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/a82a65f3-b669-4d74-9811-9ff5d1bc9e49.png)针对 PHP 7.1 运行相同脚本的结果

PHP 7 大约快三到四倍，并且消耗的内存比少了三分之一。这里要学到的教训是，在处理字符串时，尽量使用 PHP 7 的字符串插值算法。

# 参数引用

尽管最好避免将变量通过引用传递给函数，以避免在函数外部改变应用程序的状态，但 PHP 7 使得以高度优化的方式传递变量给函数成为可能，即使引用不匹配。让我们看下面的代码示例，以更好地理解 PHP 7 在这方面比 PHP 5 更有效率：

```php
// chap3_references.php 

$start = microtime(true); 

function test (&$byRefVar) 
{ 
    $test = $byRefVar; 
} 

$variable = array_fill(0, 10000, 'banana'); 

for ($x = 0; $x < 10000; $x++) { 
    test($variable); 
} 

$time = microtime(true) - $start; 

echo 'Time elapsed: ' . $time . PHP_EOL; 

echo memory_get_usage() . ' bytes' . PHP_EOL; 
```

让我们用 PHP 5 二进制运行这段代码：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/68ecb6f7-c0d3-4e15-9be6-4de0b577dcb6.png)针对 PHP 5.6 运行脚本的结果

在执行相同的代码时，PHP 7 的结果如下：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/817ef153-f0e1-44f3-b593-8c1d37f9f150.png)针对 PHP 7.1 运行相同脚本的结果

PHP 7 的结果再次非常令人印象深刻，它几乎以三分之一的内存分配和 1000 倍的速度完成了相同的工作！在幕后发生的是，当引用不匹配时，PHP 7 不再在内存中复制变量。因此，新的编译器避免了为无用的内存分配膨胀，并加快了任何 PHP 脚本的执行，其中引用不匹配是一个问题。

# 识别更多可能的优化。

在优化应用程序时，您将首先确定最耗时的函数，特别是沿着应用程序的关键路径。正如前一章所述，大多数这些函数将是 I/O 函数，因为这些函数对计算机来说总是最昂贵的操作。大多数情况下，您会看到优化循环和减少系统调用的可能性，但很快您会意识到，无论您希望对其进行何种优化，I/O 操作始终是昂贵的。不过，有时您可能会遇到非常慢的 PHP 结构，可以简单地用更快的结构替换，或者您可能会意识到，设计不良的代码可以很容易地重构为更节约资源，比如用更简单的静态结构替换动态结构。

的确，除非绝对必要，应避免使用动态结构。现在我们来看一个非常简单的例子。我们将使用三种不同的方法编写相同的功能四次：函数和动态、函数和静态，最后是结构和静态。让我们从函数和动态方法开始：

```php
// chap3_dynamic_1.php 

$start = microtime(true); 

$x = 1; 

$data = []; 

$populateArray = function ($populateArray, $data, $x) { 

    $data[$x] = $x; 

    $x++; 

    return $x <= 1000 ? $populateArray($populateArray, $data, $x) : $data; 

}; 

$data = $populateArray($populateArray, $data, $x); 

$time = microtime(true) - $start; 

echo 'Time elapsed: ' . $time . PHP_EOL; 

echo memory_get_usage() . ' bytes' . PHP_EOL; 
```

这段代码通过递归调用相同的闭包来创建一个包含 1,000 个元素的数组。如果我们运行这段代码，我们会得到以下结果：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/310cd67e-f945-42ef-9ed8-f35f6e010b06.png)使用函数和动态方法编写的脚本运行时所消耗的时间和内存

让我们看看使用`Blackfire.io`运行此脚本的结果：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/865efdb5-9f6d-4340-acfc-691e6fd1940a.png)使用函数和动态方法编写的脚本运行时的性能报告

让我们以更静态的方式编写相同的功能，使用经典的命名函数：

```php
// chap3_dynamic_2.php 

$start = microtime(true); 

$x = 1; 

$data = []; 

function populateArray(Array $data, $x) 
{ 
    $data[$x] = $x; 

    $x++; 

    return $x <= 1000 ? populateArray($data, $x) : $data; 
} 

$data = populateArray($data, $x); 

$time = microtime(true) - $start; 

echo 'Time elapsed: ' . $time . PHP_EOL; 

echo memory_get_usage() . ' bytes' . PHP_EOL; 
```

如果我们执行这个版本的代码，我们会得到以下结果：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/1d09776a-1981-4715-a040-1409ede0791b.png)使用函数和静态方法编写的脚本运行时所消耗的时间和内存

使用`Blackfire.io`分析器运行脚本产生了以下结果：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/532b428d-1d99-4a5a-bf3d-814a59bb8755.png)使用函数和静态方法编写的脚本运行时的性能报告

最后，让我们再次以非常结构化和静态的方式编写这个功能，而不是通过尾递归调用函数：

```php
// chap3_dynamic_3.php 

$start = microtime(true); 

$data = []; 

function populateArray(Array $data) 
{ 
    static $x = 1; 

    $data[$x] = $x; 

    $x++; 

    return $data; 
} 

for ($x = 1; $x <= 1000; $x++) { 
    $data = populateArray($data); 
} 

$time = microtime(true) - $start; 

echo 'Time elapsed: ' . $time . PHP_EOL; 

echo memory_get_usage() . ' bytes' . PHP_EOL; 
```

在执行代码的最新版本后，以下是结果：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/38692ba5-dce2-4731-82d6-a4e9ac58f5fb.png)运行使用结构化和静态方法编程的脚本时所消耗的时间和内存

使用`Blackfire.io`对这个脚本版本进行分析的结果如下：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/8e1edd60-f97e-4acc-bce6-dc8d84e5a2a5.png)运行使用结构化和静态方法编程的脚本时的分析报告

结果清楚地显示了结构化方法是最快的。如果我们现在沿着结构化的路线再走一小步，只是稍微使用一点功能性编程，并尝试使用生成器来迭代创建数组，我们对将获得的高性能结果不应感到惊讶。以下是我们代码的最新版本：

```php
// chap3_dynamic_4.php

$start = microtime(true);

$data = [];

function populateArray()
{
    for ($i = 1; $i <= 1000; $i++) {

        yield $i => $i;

    }

    return;
}

foreach (populateArray() as $key => $value) {

    $data[$key] = $value;

}

$time = microtime(true) - $start;

echo 'Time elapsed: ' . $time . PHP_EOL;

echo memory_get_usage() . ' bytes' . PHP_EOL;
```

这是运行我们代码的最新版本的结果：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/c3201960-6ec7-4e70-92cb-98af3f9ca57a.png)运行使用非常结构化和静态方法编程的脚本时所消耗的时间和内存

使用`Blackfire.io`的结果如下：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/f6f60c39-b8b5-4b8a-91fa-6b5cb6076733.png)运行使用非常结构化和静态方法编程的脚本时的分析报告

结果清楚地显示了我们代码的这个最新版本确实优于其他版本。事实上，PHP 仍然是一种非常结构化的语言，因为它的编译器仍然没有完全优化尾递归调用，并且如果以结构化方式编写程序，则完成程序执行所需的时间更短。这是否意味着 PHP 永远不会成为一种功能性语言，最好避免在 PHP 中以功能性方式编程？简短的答案是否定的。这是否意味着使用 PHP 进行功能性编程只是未来的事情？同样，答案也是否定的。有一些功能性编程技术可以立即使用，并且将帮助我们的脚本更具性能。让我们特别看一下其中一种技术，即记忆化。

# 函数式编程和记忆化

PHP 是一种命令式而不是声明式语言，这意味着编程是通过改变程序状态的语句来完成的，就像 C 语言系列中的其他语言一样，它不是由无状态表达式或声明组成的，比如 SQL。尽管 PHP 主要是一种结构化（过程式）和面向对象的编程语言，但自 PHP 5.3 以来，我们已经看到越来越多的请求要求更多的功能性结构，比如生成器和 lambda 函数（匿名函数）。然而，就性能而言，PHP 目前仍然是一种结构化语言。

话虽如此，大多数功能性编程技术将在未来几年内产生成果，但仍然有一些功能性编程技术可以立即在 PHP 中使用，一旦在项目的代码库中实施，就会提高性能。其中一种技术就是记忆化。

记忆化是一种函数式编程技术，它将昂贵的函数计算的结果存储并在同一程序中每次调用时重复使用。其思想是在接收特定输入时返回函数的静态值。显然，为了避免值的失效，函数应该是引用透明的，这意味着当给定特定输入时，它应该始终返回相同的输出。当你意识到引用透明函数在应用程序的关键路径上被多次调用并且每次都被计算时，这就派上了用场。记忆化是一种简单的优化实现，因为它只是创建一个缓存来存储计算的结果。

让我们来看一个简单的例子，这将帮助我们轻松地理解其背后的思想。假设我们有以下代码沿着应用程序的关键路径：

```php
// chap3_memoization_before.php 

$start = microtime(true); 

$x = 1; 

$data = []; 

function populateArray(Array $data, $x) 
{ 
    $data[$x] = $x; 

    $x++; 

    return $x <= 1000 ? populateArray($data, $x) : $data; 
} 

$data = populateArray($data, $x); 

$data = populateArray($data, $x); 

$data = populateArray($data, $x); 

$data = populateArray($data, $x); 

$data = populateArray($data, $x); 

$time = microtime(true) - $start; 

echo 'Time elapsed: ' . $time . PHP_EOL; 

echo memory_get_usage() . ' bytes' . PHP_EOL; 
```

在这里，我们看到同一个函数被递归调用了很多次。而且，它是一个引用透明的函数。因此，它是记忆化的一个完美候选者。

让我们从检查其性能开始。如果我们执行代码，我们将得到以下结果：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/4111c620-6852-4dc9-8a5a-88e2e5370845.png)在实施记忆化之前的结果

现在，让我们实施一个缓存来记忆化结果：

```php
// chap3_memoization_after.php 

$start = microtime(true); 

$x = 1; 

$data = []; 

function populateArray(Array $data, $x) 
{ 
    static $cache = []; 

    static $key; 

    if (!isset($key)) { 
        $key = md5(serialize($x)); 
    } 

    if (!isset($cache[$key])) { 

        $data[$x] = $x; 

        $x++; 

        $cache[$key] = $x <= 1000 ? populateArray($data, $x) : $data; 

    } 

    return $cache[$key]; 

} 

$data = populateArray($data, $x); 

$data = populateArray($data, $x); 

$data = populateArray($data, $x); 

$data = populateArray($data, $x); 

$data = populateArray($data, $x); 

$time = microtime(true) - $start;
```

```php
echo 'Time elapsed: ' . $time . PHP_EOL; 

echo memory_get_usage() . ' bytes' . PHP_EOL; 
```

以下是执行相同代码的新版本时的结果：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/c8626594-4df0-4a81-9a97-cc503216f617.png)在实施记忆化后的结果

正如我们所看到的，PHP 脚本现在运行得更快了。当在应用程序的关键路径上调用引用透明函数的次数越多时，使用记忆化时速度就会增加得越多。让我们使用`Blackfire.io`来查看我们脚本的性能。

以下是在没有使用记忆化时执行脚本的结果：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/d9cbb171-7264-4da1-ab25-a6137c8c10a7.png)在不使用记忆化时的性能分析报告

以下是使用记忆化后的结果：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/30e818e4-d067-4b3c-ac71-7a3317063b81.png)使用记忆化时的性能分析报告

比较显示，脚本的记忆化版本运行大约快了八倍，并且消耗的内存少了三分之一。对于这样一个简单的实现来说，性能上的重要提升。

关于记忆化的最后一个问题可能是：我们可以在同一个脚本的多次运行之间缓存结果吗？当然可以。由你来确定最佳的缓存方式。你可以使用任何标准的缓存结果的方式。此外，至少有一个库可以用来在 PHP 中缓存记忆化的结果。你可以在以下地址找到它：[`github.com/koktut/php-memoize`](https://github.com/koktut/php-memoize)。请注意，这个库对于我们上一个脚本来说不是一个好的选择，因为它与递归尾调用不兼容。

# 摘要

在本章中，我们学习了 PHP 7 本身是一个优化，如何避免一般动态结构总是会提升 PHP 脚本的性能，以及某些函数式编程技术，比如记忆化，在优化代码性能时可以是强大的盟友。

在下一章中，我们将学习如何通过学习生成器和异步非阻塞代码、使用 POSIX 线程（`pthreads`）库进行多线程处理，以及使用`ReactPHP`库进行多任务处理来应对输入和输出（I/O）延迟较大的情况。

# 参考

[`news.php.net/php.internals/73888`](http://news.php.net/php.internals/73888)


# 第四章：使用异步 PHP 构想未来

在本章中，我们将学习如何确定在处理 I/O 调用时什么是最佳策略，以及如何实施这些策略。我们将看到多线程与多任务处理的区别，何时实施其中一个，以及如何实施。

此外，我们将学习如何使用`ReactPHP`库，并在处理异步 I/O 调用时如何从事件驱动编程中受益。

因此，在本章中，我们将涵盖以下几点：

+   使用异步非阻塞代码优化 I/O 调用

+   使用`POSIX Threads`库进行多线程

+   实施`ReactPHP`解决方案

# 异步非阻塞 I/O 调用

正如我们在本书的前几章中所看到的，由于建立、使用和关闭流和套接字的基础延迟，I/O 调用始终会提供最差的性能。由于 PHP 基本上是一种同步语言，它在恢复代码执行之前等待被调用的函数返回，因此如果被调用的函数必须等待流关闭才能返回到调用代码，I/O 调用尤其成问题。当一个 PHP 应用程序例如每隔几分钟需要进行数千次 I/O 调用时，情况会变得更糟。

自 PHP 5.3 以来，通过使用生成器中断 PHP 的正常执行流程成为可能，从而异步执行代码。正如我们之前所看到的，即使动态结构在一般情况下可能性能较差，它们仍然可以用于加速阻塞代码。这对于通常具有非常高延迟的 I/O 调用尤其如此。为了更好地掌握 I/O 延迟的数量级，我们可以查看谷歌发布的以下著名图表：

| 延迟比较数字--------------------------L1 缓存引用 0.5 ns 分支错误预测 5 nsL2 缓存引用 7 ns 14 倍 L1 缓存互斥锁定/解锁 25 ns 主存储器引用 100 ns 20 倍 L2 缓存，200 倍 L1 缓存使用 Zippy 压缩 1K 字节 3,000 ns 3 us 通过 1 Gbps 网络发送 1K 字节 10,000 ns 10 us 从 SSD*随机读取 4K150,000 ns 150 us 〜1GB/秒 SSD 从内存顺序读取 1 MB250,000 ns 250 us 在同一数据中心的往返 500,000 ns 500 us 从 SSD*顺序读取 1 MB1,000,000 ns 1,000 us 1 ms 〜1GB/秒 SSD，4 倍内存磁盘查找 10,000,000 ns 10,000 us 10 ms 20 倍数据中心往返从磁盘顺序读取 1 MB20,000,000 ns 20,000 us 20 ms 80 倍内存，20 倍 SSD 发送数据包 CA->荷兰->CA150,000,000 ns 150,000 us 150 ms 注释-----1 ns = 10^-9 秒 1 us = 10^-6 秒 = 1,000 ns1 ms = 10^-3 秒 = 1,000 us = 1,000,000 ns 来源------Jeff Dean：[`research.google.com/people/jeff/`](http://research.google.com/people/jeff/)Peter Norvig 原作：[`norvig.com/21-days.html#answers`](http://norvig.com/21-days.html#answers)贡献-------------来自：[`gist.github.com/2843375`](https://gist.github.com/2843375)"人性化"比较：[`gist.github.com/2843375`](https://gist.github.com/2843375)可视化比较图表：[`i.imgur.com/k0t1e.png`](http://i.imgur.com/k0t1e.png)动画演示：[`prezi.com/pdkvgys-r0y6/latency-numbers-for-programmers-web-development/latency.txt`](http://prezi.com/pdkvgys-r0y6/latency-numbers-for-programmers-web-development/latency.txt)[`gist.github.com/jboner/2841832`](https://gist.github.com/jboner/2841832)[`gist.github.com/andrewscaya/2f9e68d4b41f9d747b92fb26b1b60d9f`](https://gist.github.com/andrewscaya/2f9e68d4b41f9d747b92fb26b1b60d9f) |
| --- |

毫无疑问，从磁盘读取始终比从内存读取慢，网络 I/O 调用仍然是最慢的。

让我们深入一点，看一下一些进行一系列 I/O 调用的代码。我们的第一个例子将使用`cURL`。让我们看一下以下代码：

```php
// chap4_IO_blocking.php 

$start = microtime(true); 

$i = 0; 

$responses = []; 

while ($i < 10) { 

    $curl = curl_init(); 

    curl_setopt_array($curl, array( 
        CURLOPT_RETURNTRANSFER => 1, 
        CURLOPT_URL => 'http://www.google.ca', 
        CURLOPT_USERAGENT => 'Faster Web cURL Request' 
    )); 

    $responses[] = curl_exec($curl); 

    curl_close($curl); 

    $i++; 
} 

$time = microtime(true) - $start; 

echo 'Time elapsed: ' . $time . PHP_EOL; 

echo memory_get_usage() . ' bytes' . PHP_EOL; 
```

现在，让我们执行 PHP 脚本。我们现在应该看到以下结果：

运行阻塞代码脚本时经过的时间和消耗的内存

由于访问网络的高延迟，这段代码需要很长时间才能完成。

如果我们使用`Blackfire.io`对先前的代码进行性能分析，我们会看到 10 次`cURL`调用需要超过一秒才能完成：

对代码进行性能分析显示，10 次 cURL 调用占据了脚本总执行时间的大部分

让我们修改我们的 PHP 脚本，以使用异步代码同时运行我们的`cURL`请求。以下是先前 PHP 代码的新版本：

```php
// chap4_IO_non_blocking.php 

$start = microtime(true); 

$i = 0; 

$curlHandles = []; 

$responses = []; 

$multiHandle = curl_multi_init(); 

for ($i = 0; $i < 10; $i++) { 

    $curlHandles[$i] = curl_init(); 

    curl_setopt_array($curlHandles[$i], array( 
        CURLOPT_RETURNTRANSFER => 1, 
        CURLOPT_URL => 'http://www.google.ca', 
        CURLOPT_USERAGENT => 'Faster Web cURL Request' 
    )); 

    curl_multi_add_handle($multiHandle, $curlHandles[$i]); 
} 

$running = null; 

do { 
    curl_multi_exec($multiHandle, $running); 
} while ($running); 

for ($i = 0; $i < 10; $i++) { 
    curl_multi_remove_handle($multiHandle, $curlHandles[$i]); 

    $responses[] = curl_multi_getcontent($curlHandles[$i]); 
} 

curl_multi_close($multiHandle); 

$time = microtime(true) - $start; 

echo 'Time elapsed: ' . $time . PHP_EOL; 

echo memory_get_usage() . ' bytes' . PHP_EOL; 
```

执行代码后，我们现在得到了以下结果：

运行非阻塞代码脚本时经过的时间和消耗的内存

正如预期的那样，PHP 脚本更快，因为它不再需要等待 I/O 调用完成后才能继续执行其余的代码。实际上，在幕后发生的是在同一线程内的多任务处理。事实上，代码的执行流程实际上被中断，以允许许多 I/O 调用的并发执行。这是由于非阻塞代码会在等待某个任务完成时将控制权交还给调用者代码，并在完成时可能调用回调函数。如果我们使用`Blackfire.io`对先前的代码进行性能分析，我们将看到这种循环的执行——为了完成所有 10 个请求，yielding 函数实际上被调用了 45000 多次：

为了完成所有 10 个 cURL 请求，yielding 函数被调用了 45000 多次

在 PHP 5.5 中引入的生成器允许代码的不同部分似乎同时执行，从而更容易进行异步编程。生成器实际上是一个实现了迭代器接口的可调用对象。其基本原则是有一个循环，将重复调用一个生成器函数，然后将控制权交还给循环，直到没有东西可处理为止，此时生成器函数将返回。

现在，让我们通过一个简单的代码示例深入了解异步编程。为此，让我们使用以下代码编写一个基本的汽车比赛：

```php
// chap4_async_race.php

$laps[] = 0;
$laps[] = 0;
$laps[] = 0;

function car1(int &$lap) {
    while ($lap <= 10) {
        for ($x = 0; $x <= 200; $x++) {
            yield 0;
        }

        yield 1;
    }

    // If the car has finished its race, return null in order to remove the car from the race
    return;
}

function car2(int &$lap) {
    while ($lap <= 10) {
        for ($x = 0; $x <= 220; $x++) {
            yield 0;
        }

        yield 1;
    }

    // If the car has finished its race, return null in order to remove the car from the race
    return;
}

function car3(int &$lap) {
    while ($lap <= 10) {
        for ($x = 0; $x <= 230; $x++) {
            yield 0;
        }

        yield 1;
    }

    // If the car has finished its race, return null in order to remove the car from the race
    return;
}

function runner(array $cars, array &$laps) {
    $flag = FALSE;

    while (TRUE) {
        foreach ($cars as $key => $car) {
            $penalty = rand(0, 8);
            if($key == $penalty) {
                // We must advance the car pointer in order to truly apply the penalty 
                                                                to the "current" car
                $car->next();
            } else {
                // Check if the "current" car pointer points to an active race car
                if($car->current() !== NULL) {
                    // Check if the "current" car pointer points to a car that has  
                                                                    completed a lap
                    if($car->current() == 1) {
                        $lapNumber = $laps[$key]++;
                        $carNumber = $key + 1;
                        if ($lapNumber == 10 && $flag === FALSE) {
                            echo "*** Car $carNumber IS THE WINNER! ***\n";
                            $flag = TRUE;
                        } else {
                            echo "Car $carNumber has completed lap $lapNumber\n";
                        }
                    }
                    // Advance the car pointer
                    $car->next();
                    // If the next car is no longer active, remove the car from the 
                                                                              race
                    if (!$car->valid()) {
                        unset($cars[$key]);
                    }
                }
            }
        }

```

```php
        // No active cars left! The race is over!
        if (empty($cars)) return;
    }
}

runner(array(car1($laps[0]), car2($laps[1]), car3($laps[2])), $laps); 
```

正如你所看到的，主循环中的 runner 函数以随机顺序处理三个生成器函数，直到它们没有任何东西可处理为止。最终结果是，我们永远不知道哪辆车会赢得比赛，尽管其中一些车似乎比其他车快！让我们运行这段代码三次。以下是第一次运行的结果：

汽车 2 赢得了比赛！

以下是第二次运行的结果：

汽车 3 赢得了比赛！

以下是第三次也是最后一次运行的结果：

汽车 1 赢得了比赛！

最终结果是似乎在同一线程内同时执行三个不同函数。这正是异步编程的基本原则。事实上，很容易理解多任务处理是如何被用来帮助减轻单个 PHP 脚本的重负，通过中断脚本的执行来使用第三方软件（如 RabbitMQ 和 Redis）排队一些任务，从而延迟处理这些任务，直到适当的时候。

现在我们已经看过了多任务处理，让我们来看看多线程处理。

# 使用 pthreads 进行多线程

`POSIX Threads`，更为人所知的是`pthreads`，是一个允许计算机程序通过从其父进程分叉子进程来同时执行多个进程或线程的库。`pthreads`库可以在 PHP 中使用，因此可以在执行其他操作的同时在后台分叉进程。因此，多线程是另一种处理 I/O 调用延迟的方法。为了实现这一点，我们需要一个带有`pthreads`扩展启用的线程安全版本的 PHP。在我们的情况下，我们将使用运行**Zend 线程安全**（**ZTS**）版本的 PHP 7.0.29 的 Linux for PHP 容器。打开一个新的终端窗口，`cd`到项目的目录，并输入以下命令：

```php
# docker run -it --rm \
> -p 8282:80 \
> -v ${PWD}/:/srv/fasterweb \
> asclinux/linuxforphp-8.1:7.0.29-zts \
> /bin/bash
```

输入此命令后，如果在 CLI 中输入`php -v`命令，您应该会看到以下信息：

ZTS 容器的命令行界面（CLI）

这条消息确认我们正在使用线程安全（ZTS）版本的 PHP。然后，在容器的 CLI 中，输入这些命令：

```php
# mv /srv/www /srv/www.OLD
# ln -s /srv/fasterweb/chapter_4 /srv/www
# cd /srv/www
# pecl install pthreads
# echo "extension=pthreads.so" >> /etc/php.ini
```

您现在可以通过输入命令`php -i`来检查`pthreads`扩展是否已正确安装。最后一个命令应该让您看到扩展的版本号。如果是这样，那么扩展已正确安装：

pthread 扩展的 3.1.6 版本现已安装

现在`pthreads`库已安装并启用，让我们继续使用它，尝试在计算机的 CPU 上创建多个线程，这些线程将真正同时执行。为此，我们将使用以下源代码：

```php
// chap4_pthreads.php 

$start = microtime(true); 

class TestThreads extends Thread { 

    protected $arg; 

    public function __construct($arg) { 
        $this->arg = $arg; 
    } 

    public function run() { 
        if ($this->arg) { 
            $sleep = mt_rand(1, 10); 
            printf('%s: %s  -start -sleeps %d' . "\n", date("g:i:sa"), $this->arg, 
                                                                          $sleep); 
            sleep($sleep); 
            printf('%s: %s  -finish' . "\n", date("g:i:sa"), $this->arg); 
        } 
    } 
} 

$stack = array(); 

// Create Multiple Thread 
foreach ( range('1', '9') as $id ) { 
    $stack[] = new TestThreads($id); 
} 

// Execute threads 
foreach ( $stack as $thread ) { 
    $thread->start(); 
} 

sleep(1); 

$time = microtime(true) - $start; 

echo 'Time elapsed: ' . $time . PHP_EOL; 

echo memory_get_usage() . ' bytes' . PHP_EOL; 
```

执行后，我们获得以下输出：

线程同时执行

结果清楚地表明，线程是同时执行的，因为脚本的总经过时间为 10 秒，即使每个线程至少睡了几秒。如果没有使用多线程执行此同步阻塞代码，完成执行可能需要大约 40 秒。在这种情况下，多任务处理不是一个合适的解决方案，因为对`sleep()`函数的阻塞调用将阻止每个生成器将控制权让给主循环。

现在我们已经看到了通过异步编程进行多任务处理和通过`POSIX Threads`库进行多线程处理，我们将把注意力转向一个在编程异步时非常有用的 PHP 库，即`ReactPHP`库。

# 使用 ReactPHP 库

`ReactPHP`是一个事件驱动的、非阻塞 I/O 库。这个库基本上依赖于一个事件循环，它轮询文件描述符，使用定时器，并通过在每次循环迭代中注册和执行未完成的 tick 来推迟回调。

`ReactPHP`基于 Reactor 模式，根据 Douglas C. Schmidt 的说法，Reactor 模式是“*一种处理一个或多个客户端并发传递给应用程序的服务请求的设计模式。应用程序中的每个服务可能由多个方法组成，并由一个单独的事件处理程序表示，负责分派特定于服务的请求。事件处理程序的分派由一个初始化分派器执行，该分派器管理注册的事件处理程序。服务请求的多路复用由同步事件多路复用器执行*。”在 Schmidt 的原始论文*Reactor: An Object Behavioral Pattern for Demultiplexing and Dispatching Handles for Synchronous Events*中，我们可以找到这种模式的 UML 表示：

根据 Douglas C. Schmidt 的说法，Reactor 模式

让我们通过在我们的代码库中安装它来开始探索这个异步编程库。在容器的 CLI 中，输入以下命令：

```php
# cd /srv/www/react 
# php composer.phar self-update
# php composer.phar install 
# cd examples 
```

一旦库通过 Composer 安装，你可以尝试 examples 目录中找到的任何示例脚本。这些代码示例来自*ReactPHP*的主代码库。在我们的例子中，我们将首先看一下`parallel-download.php`脚本。以下是它的源代码：

```php
// parallel-download.php 

$start = microtime(true); 

// downloading the two best technologies ever in parallel 

require __DIR__ 
    . DIRECTORY_SEPARATOR 
    .'..' 
    . DIRECTORY_SEPARATOR 
    . 'vendor' 
    . DIRECTORY_SEPARATOR 
    .'autoload.php'; 

$loop = React\EventLoop\Factory::create(); 

$files = array( 
    'node-v0.6.18.tar.gz' => 'http://nodejs.org/dist/v0.6.18/node-v0.6.18.tar.gz', 
    'php-5.5.15.tar.gz' => 'http://it.php.net/get/php-5.5.15.tar.gz/from/this/mirror', 
); 

foreach ($files as $file => $url) {
    $readStream = fopen($url, 'r'); 
    $writeStream = fopen($file, 'w'); 

    stream_set_blocking($readStream, 0); 
    stream_set_blocking($writeStream, 0); 

    $read = new React\Stream\Stream($readStream, $loop); 
    $write = new React\Stream\Stream($writeStream, $loop); 

    $read->on('end', function () use ($file, &$files) { 
        unset($files[$file]); 
        echo "Finished downloading $file\n"; 
    }); 

    $read->pipe($write);

} 

$loop->addPeriodicTimer(5, function ($timer) use (&$files) { 
    if (0 === count($files)) { 
        $timer->cancel(); 
    } 

    foreach ($files as $file => $url) {

        $mbytes = filesize($file) / (1024 * 1024); 
        $formatted = number_format($mbytes, 3); 
        echo "$file: $formatted MiB\n"; 
    } 
}); 

echo "This script will show the download status every 5 seconds.\n"; 

$loop->run(); 

$time = microtime(true) - $start; 

echo 'Time elapsed: ' . $time . PHP_EOL; 

echo memory_get_usage() . ' bytes' . PHP_EOL; 
```

基本上，这个脚本创建了两个流，将它们设置为非阻塞模式，并将这些流注册到循环中。定时器被添加到循环中，以便每 5 秒回显一条消息。最后，它运行了循环。

让我们通过以下命令来看一下这个脚本的运行情况：

```php
 # php parallel-download.php 
```

以下是结果：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/ff636036-744b-4547-a6ee-a5cb40ad8c40.png)这两个包是异步下载的

正如你所看到的，下载是以并行、异步和反应式的方式执行的。

让我们继续通过在代码示例中包含的`tcp-chat.php`脚本来继续我们对 ReactPHP 世界的短暂旅程。以下是这个代码示例的源代码：

```php
// tcp-chat.php 

// socket based chat

require __DIR__ 
    . DIRECTORY_SEPARATOR 
    .'..' 
    . DIRECTORY_SEPARATOR 
    . 'vendor' 
    . DIRECTORY_SEPARATOR 
    .'autoload.php';

$loop = React\EventLoop\Factory::create();
$socket = new React\Socket\Server($loop);

$conns = new \SplObjectStorage();

$socket->on('connection', function ($conn) use ($conns) {
    $conns->attach($conn);

    $conn->on('data', function ($data) use ($conns, $conn) {
        foreach ($conns as $current) {

            if ($conn === $current) {
               continue;
            }

            $current->write($conn->getRemoteAddress().': ');
            $current->write($data);
        }

    });

    $conn->on('end', function () use ($conns, $conn) {
        $conns->detach($conn);
    });
});

echo "Socket server listening on port 4000.\n";
echo "You can connect to it by running: telnet localhost 4000\n";

$socket->listen(4000);
$loop->run();
```

该脚本创建了一个在 4000 端口监听的套接字服务器，并通过监听连接事件被循环通知有新连接。在收到事件通知后，套接字服务器将连接对象注入处理程序。连接对象然后开始监听数据事件，这将触发它对从套接字服务器客户端接收的数据进行处理。在这个聊天脚本的情况下，连接对象将触发`SplObjectStorage`对象中所有注册连接对象的写入方法，从而有效地将消息发送给当前连接的所有聊天客户端。

首先，通过运行脚本启动聊天服务器：

```php
 # php tcp-chat.php 
```

然后，打开三个新的终端窗口，并通过在每个窗口中输入以下命令来连接到我们的*Linux for PHP* *Docker*容器：

```php
 # **docker exec -it $( docker ps -q | awk '{ print $1 }' ) /bin/bash** 
```

在每个容器的 CLI 中，输入以下命令：

```php
# telnet localhost 4000
```

通过`telnet`连接后，只需在一个终端窗口和另一个终端窗口之间来回发送消息，玩得开心：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/5ef175eb-8d2b-4bf4-b304-06c76043129b.png)从一个终端窗口向其他终端窗口发送消息

显然，通过同一个容器内的终端窗口所做的工作也可以通过网络连接到不同计算机上的终端窗口来完成。这个例子向我们展示了异步编程有多么强大。

让我们通过查看`scalability.php`脚本来完成我们对*ReactPHP*代码示例的调查。以下是它的源代码：

```php
// scalability.php 

// a simple, single-process, horizontal scalable http server listening on 10 ports

require __DIR__ 
    . DIRECTORY_SEPARATOR 
    .'..' 
    . DIRECTORY_SEPARATOR 
    . 'vendor' 
    . DIRECTORY_SEPARATOR 
    .'autoload.php';

$loop = React\EventLoop\Factory::create();

for ($i = 0; $i < 10; ++$i) {

    $s = stream_socket_server('tcp://127.0.0.1:' . (8000 + $i));
    $loop->addReadStream($s, function ($s) use ($i) {
        $c = stream_socket_accept($s);
        $len = strlen($i) + 4;
        fwrite($c,"HTTP/1.1 200 OK\r\nContent-Length: $len\r\n\r\nHi:$i\n");
        echo "Served on port 800$i\n";
    });

}

echo "Access your brand new HTTP server on 127.0.0.1:800x. Replace x with any number from 0-9\n";

$loop->run();
```

该脚本创建了一个套接字服务器，然后将其附加到主事件循环中，以便在向服务器发送请求时调用一个 lambda 函数。然后，lambda 函数执行将答复发送回客户端的代码，通过将其写入接受的流套接字。

让我们通过以下命令运行这段代码：

```php
 # php scalability.php
```

然后，打开另一个终端窗口，并将其连接到我们的*Linux for PHP* *Docker*容器：

```php
 # **docker exec -it $( docker ps -q | awk '{ print $1 }' ) /bin/bash** 
```

然后，使用`wget`查询服务器：

```php
# wget -nv -O - http://localhost:8000
# wget -nv -O - http://localhost:8001
# wget -nv -O - http://localhost:8002
# wget -nv -O - http://localhost:8003
# wget -nv -O - http://localhost:8004
# wget -nv -O - http://localhost:8005
# wget -nv -O - http://localhost:8006
# wget -nv -O - http://localhost:8007
# wget -nv -O - http://localhost:8008
# wget -nv -O - http://localhost:8009
```

完成后，你应该得到每个请求的以下响应：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/9153e175-979f-4747-bf75-1a6799310991.png)连接到 Web 服务器的每个可用端口

这是你在服务器端应该看到的：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/ms-fst-web-php/img/1e99bfc2-3c61-4949-8724-c490a238df88.png)服务器确认已在所有这些端口上为所有这些请求提供服务

再次，你可以看到*ReactPHP*有多么强大，只需几行代码就足以创建一个可扩展的 Web 服务器。

此外，我们强烈建议探索并尝试我们存储库中包含的*ReactPHP*项目的所有文件，这样你就可以充分体会到这个库在异步编程方面为开发者能做些什么。

此外，还有其他出色的异步 PHP 库可以帮助您掌握这种新的开发方式，并加速高延迟 I/O 应用程序。其中一个这样的库是*Amp*（[`amphp.org/`](https://amphp.org/)）。在掌握异步编程艺术的过程中，探索这些非常有用的库是非常值得的。

最后，要了解有关 PHP 异步编程的更多信息，您可以听*Christopher Pitt*在*Nomad PHP*上关于这个主题的精彩演讲（[`nomadphp.com/asynchronous-php/`](https://nomadphp.com/asynchronous-php/)）。

# 总结

在本章中，我们学习了如何确定应对 I/O 调用的最佳策略以及如何实施这些策略。此外，我们还了解了如何使用`ReactPHP`库以及在处理异步 I/O 调用时如何从事件驱动编程中获益。

在下一章中，我们将学习如何测量数据库性能，从应用简单的测量技术到使用高级基准测试工具。
