# PHP7 高性能开发学习手册（一）

> 原文：[`zh.annas-archive.org/md5/57463751f7ad4ac2a29e3297fd76591c`](https://zh.annas-archive.org/md5/57463751f7ad4ac2a29e3297fd76591c)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

PHP 社区在几十年来面临着一个巨大的问题：性能。无论他们拥有多么强大的硬件，最终 PHP 本身都成为了瓶颈。随着 PHP 5.4.x、5.5.x 和 5.6.x 的推出，PHP 的性能开始改善，但在高负载应用中仍然是一个巨大的问题。社区开发了诸如**Alternative PHP Cache**（**APC**）和 Zend OpCache 之类的缓存工具，这些工具对性能产生了良好的影响。

为了解决 PHP 的性能问题，Facebook 构建了他们自己的开源工具**HHVM**（**HipHop 虚拟机**）。根据他们的官方网站，HHVM 使用即时（JIT）编译来实现卓越的性能，同时保持 PHP 提供的开发灵活性。与 PHP 相比，HHVM 的性能非常出色，并且广泛用于像 Magento 这样的重型应用的生产环境。

PHP 通过**PHP Next Generation**（**PHPNG**）与 HHVM 展开了竞争。PHPNG 的整个目的是提高性能，并专注于重写和优化 Zend 引擎内存分配和 PHP 数据类型。世界各地的人开始对 PHPNG 和 HHVM 进行基准测试，据他们称，PHPNG 的性能优于 HHVM。

最后，PHPNG 与 PHP 的主分支合并，经过大量优化和完全重写，PHP 7 发布，性能大幅提升。PHP 7 仍然不是 JIT，但其性能很好，与 HHVM 类似。这是与旧版本 PHP 相比的巨大性能提升。

# 本书涵盖的内容

第一章，*设置环境*，介绍了如何设置不同的开发环境，包括在 Windows、不同的 Linux 发行版上安装 NGINX、PHP 7 和 Percona Server，以及为开发目的设置 Vagrant 虚拟机。

第二章，*PHP 7 的新特性*，介绍了 PHP 7 引入的主要新特性，包括类型提示、组使用声明、匿名类和新操作符，如太空船操作符、空合并操作符和统一变量语法。

第三章，*改善 PHP 7 应用程序性能*，介绍了不同的技术来增加和扩展 PHP 7 应用程序的性能。在本章中，我们涵盖了 NGINX 和 Apache 的优化、CDN 和 CSS/JavaScript 的优化，如合并和最小化它们，全页面缓存以及安装和配置 Varnish。最后，我们讨论了应用开发的理想基础架构设置。

第四章，*改善数据库性能*，介绍了优化 MySQL 和 Percona Server 配置以实现高性能的技术。还介绍了不同的工具来监控数据库的性能。还介绍了用于缓存对象的 Memcached 和 Redis。

第五章，*调试和性能分析*，介绍了调试和性能分析技术，包括使用 Xdebug 进行调试和性能分析，使用 Sublime Text 3 和 Eclipse 进行调试，以及 PHP DebugBar。

第六章，*压力/负载测试 PHP 应用程序*，介绍了不同的工具来对应用程序进行压力和负载测试。涵盖了 Apache JMeter、ApacheBench 和 Siege 用于负载测试。还介绍了如何在 PHP 7 和 PHP 5.6 上对 Magento、Drupal 和 WordPress 等不同开源系统进行负载测试，并比较它们在 PHP 7 和 PHP 5.6 上的性能。

第七章，*PHP 编程的最佳实践*，介绍了一些生产高质量标准代码的最佳实践。涵盖了编码风格、设计模式、面向服务的架构、测试驱动开发、Git 和部署。

附录 A, *使生活更轻松的工具*，更详细地讨论了其中三种工具。我们将讨论的工具是 Composer、Git 和 Grunt watch。

附录 B, *MVC 和框架*，涵盖了 PHP 开发中使用的 MVC 设计模式和最流行的框架，包括 Laravel、Lumen 和 Apigility。

# 您需要为本书准备什么

任何符合运行以下软件的最新版本的硬件规格都应足以完成本书的学习：

+   操作系统：Debian 或 Ubuntu

+   软件：NGINX、PHP 7、MySQL、PerconaDB、Redis、Memcached、Xdebug、Apache JMeter、ApacheBench、Siege 和 Git

# 这本书适合谁

这本书适合那些具有 PHP 编程基础经验的人。如果您正在开发性能关键的应用程序，那么这本书适合您。

# 约定

在本书中，您会发现一些文本样式，用于区分不同类型的信息。以下是这些样式的一些示例及其含义的解释。

文本中的代码单词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 用户名显示如下：“我们可以通过使用`include`指令来包含其他上下文。”

代码块设置如下：

```php
location ~ \.php$ {
  fastcgi_pass    127.0.0.1:9000;
  fastcgi_param    SCRIPT_FILENAME complete_path_webroot_folder$fastcgi_script_name;
  include    fastcgi_params;
}
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项会以粗体显示：

```php
server {
  …
  …
 **root html;**
 **index index.php index.html index.htm;**
  …
```

任何命令行输入或输出都以以下方式编写：

```php
**php-cgi –b 127.0.0.1:9000**

```

**新术语**和**重要单词**以粗体显示。例如，在屏幕上看到的单词，比如菜单或对话框中的单词，会在文本中出现，就像这样：“点击**下一步**按钮会将您移动到下一个屏幕。”

### 注意

警告或重要说明会以这样的方式出现在一个框中。

### 提示

提示和技巧会以这种方式出现。


# 第一章：设置环境

PHP 7 终于发布了。很长一段时间以来，PHP 社区一直在谈论它，而且仍未停止。PHP 7 的主要改进是其性能。很长一段时间以来，PHP 社区在大规模应用程序中面临性能问题。甚至一些高流量的小型应用程序也面临性能问题。服务器资源增加了，但并没有太大帮助，因为最终瓶颈是 PHP 本身。使用了不同的缓存技术，如 APC，这有所帮助。然而，社区仍然需要一个能够在应用程序性能达到顶峰时提升性能的 PHP 版本。这就是 PHPNG 的用武之地。

**PHPNG**代表**PHP 下一代**。它是一个完全独立的分支，主要针对性能。有些人认为 PHPNG 是**JIT**（**即时编译**），但实际上，PHPNG 是基于经过高度优化的**Zend 引擎**重构而成的。PHPNG 被用作 PHP 7 开发的基础，根据官方 PHP 维基页面，PHPNG 分支现在已经合并到主分支中。

在开始构建应用程序之前，应该完成并配置好开发环境。在本章中，我们将讨论在不同系统上设置开发环境，如 Windows 和不同版本的 Linux。

我们将涵盖以下主题：

+   设置 Windows

+   设置 Ubuntu 或 Debian

+   设置 CentOS

+   设置 Vagrant

其他所有环境都可以跳过，我们可以设置我们将使用的环境。

# 设置 Windows

有许多可用的工具，它们在 Windows 上捆绑了 Apache、PHP 和 MySQL，提供了简单的安装，并且非常易于使用。这些工具中的大多数已经提供了对 PHP 7 与 Apache 的支持，例如 XAMPP、WAMPP 和 EasyPHP。EasyPHP 是唯一一个还提供对**NGINX**的支持，并提供了从 NGINX 切换到 Apache 或从 Apache 切换到 Nginx 的简单步骤。

### 注意

XAMPP 也适用于 Linux 和 Mac OS X。但是，WAMP 和 EasyPHP 仅适用于 Windows。这三种工具中的任何一种都可以用于本书，但我们建议使用 EasyPHP，因为它支持 NGINX，并且在本书中，我们主要使用 NGINX。

可以使用这三种工具中的任何一种，但我们需要更多地控制我们的 Web 服务器工具的每个元素，因此我们将单独安装 NGINX、PHP 7 和 MySQL，然后将它们连接在一起。

### 注意

可以从[`nginx.org/en/download.html`](http://nginx.org/en/download.html)下载 NGINX Windows 二进制文件。我们建议使用稳定版本，尽管使用主线版本也没有问题。可以从[`windows.php.net/download/`](http://windows.php.net/download/)下载 PHP Windows 二进制文件。根据您的系统下载 32 位或 64 位的*非线程安全*版本。

执行以下步骤：

1.  下载信息框中提到的 NGINX 和 PHP Windows 二进制文件。将 NGINX 复制到合适的目录。例如，我们有一个完全独立的 D 盘用于开发目的。将 NGINX 复制到这个开发驱动器或任何其他目录。现在，将 PHP 复制到 NGINX 目录或任何其他安全文件夹位置。

1.  在 PHP 目录中，将有两个`.ini`文件，`php.ini-development`和`php.ini-production`。将其中一个重命名为`php.ini`。PHP 将使用这个配置文件。

1.  按住*Shift*键并在 PHP 目录中右键单击以打开命令行窗口。命令行窗口将在相同的位置路径中打开。发出以下命令启动 PHP：

```php
php-cgi –b 127.0.0.1:9000
```

`-b`选项启动 PHP 并绑定到外部**FastCGI**服务器的路径。上述命令将 PHP 绑定到回环`127.0.0.1`IP 的端口`9000`。现在，PHP 可以在这个路径上访问。

1.  要配置 NGINX，打开`nginx_folder/conf/nginx.conf`文件。首先要做的是在服务器块中添加 root 和 index，如下所示：

```php
server {
 **root html;**
 **index index.php index.html index.htm;**

```

### 提示

**下载示例代码**

您可以从 http://www.packtpub.com 的帐户中下载本书的示例代码文件。如果您在其他地方购买了这本书，可以访问 http://www.packtpub.com/support 并注册，以便将文件直接发送到您的电子邮件。

您可以按照以下步骤下载代码文件：

+   使用您的电子邮件地址和密码登录或注册到我们的网站。

+   将鼠标指针悬停在顶部的 SUPPORT 选项卡上。

+   单击代码下载和勘误。

+   在搜索框中输入书名。

+   选择您要下载代码文件的书。

+   从下拉菜单中选择您购买本书的地方。

+   单击代码下载。

下载文件后，请确保使用最新版本的以下软件解压或提取文件夹：

+   Windows 的 WinRAR / 7-Zip

+   Mac 的 Zipeg / iZip / UnRarX

+   Linux 的 7-Zip / PeaZip

1.  现在，我们需要配置 NGINX 以在启动时使用 PHP 作为 FastCGI 的路径。在`nginx.conf`文件中，取消注释以下位置块以用于 PHP：

```php
location ~ \.php$ {
  fastcgi_pass    127.0.0.1:9000;
  fastcgi_param    SCRIPT_FILENAME **complete_path_webroot_folder$fastcgi_script_name;**
include    fastcgi_params;
}
```

注意`fastcgi_param`选项。突出显示的`complete_path_webroot_folder`路径应该是`nginx`文件夹内 HTML 目录的绝对路径。假设您的 NGINX 放置在`D:\nginx`路径，那么`HTML`文件夹的绝对路径将是`D:\nginx\html`。但是，对于前面的`fastcgi_param`选项，`\`应该替换为`/`。

1.  现在，在 NGINX 文件夹的根目录中发出以下命令重新启动 NGINX：

```php
**nginx –s restart**

```

1.  在重新启动 NGINX 后，打开浏览器，输入 Windows 服务器或机器的 IP 或主机名，我们将看到 NGINX 的欢迎消息。

1.  现在，要验证 PHP 安装并与 NGINX 一起工作，请在 webroot 中创建一个`info.php`文件，并输入以下代码：

```php
<?php
  phpinfo();
?>
```

1.  现在，在浏览器中访问[your_ip/info.php](http://your_ip/info.php)，我们将看到一个充满 PHP 和服务器信息的页面。恭喜！我们已经成功配置了 NGINX 和 PHP，使它们完美地配合工作。

### 注意

在 Windows 和 Mac OS X 上，我们建议您使用安装有 Linux 版本的所有工具的虚拟机，以获得服务器的最佳性能。在 Linux 中管理一切很容易。有现成的 vagrant boxes 可供使用。另外，可以在[`puphpet.com`](https://puphpet.com)上制作包括 NGINX、Apache、PHP 7、Ubuntu、Debian 或 CentOS 等工具的自定义虚拟机配置，这是一个易于使用的 GUI。另一个不错的工具是 Laravel Homestead，这是一个带有很棒工具的**Vagrant** box。

# 设置 Debian 或 Ubuntu

Ubuntu 是从 Debian 派生的，因此对于 Ubuntu 和 Debian，过程是相同的。我们将使用 Debian 8 Jessie 和 Ubuntu 14.04 Server LTS。相同的过程也适用于两者的桌面版本。

首先，为 Debian 和 Ubuntu 添加存储库。

## Debian

截至我们撰写本书的时间，Debian 没有为 PHP 7 提供官方存储库。因此，对于 Debian，我们将使用`dotdeb`存储库来安装 NGINX 和 PHP 7。执行以下步骤：

1.  打开`/etc/apt/sources.list`文件，并在文件末尾添加以下两行：

```php
deb http://packages.dotdeb.org jessie all
deb-src http://packages.dotdeb.org jessie all
```

1.  现在，在终端中执行以下命令：

```php
**wget https://www.dotdeb.org/dotdeb.gpg**
**sudo apt-key add dotdeb.gpg**
**sudo apt-get update**

```

前两个命令将向 Debian 添加`dotdeb`存储库，最后一个命令将刷新源的缓存。

## Ubuntu

截至撰写本书的时间，Ubuntu 也没有在官方存储库中提供 PHP 7，因此我们将使用第三方存储库进行 PHP 7 的安装。执行以下步骤：

1.  在终端中运行以下命令：

```php
**sudo add-apt-repository ppa:ondrej/php**
**sudo apt-get update**

```

1.  现在，存储库已添加。让我们安装 NGINX 和 PHP 7。

### 注意

其余的过程对于 Debian 和 Ubuntu 大部分是相同的，所以我们不会单独列出它们，就像我们为添加存储库部分所做的那样。

1.  要安装 NGINX，请在终端中运行以下命令（Debian 和 Ubuntu）：

```php
**sudo apt-get install nginx**

```

1.  安装成功后，可以通过输入 Debian 或 Ubuntu 服务器的主机名和 IP 来验证。如果看到类似下面的屏幕截图，那么我们的安装是成功的：![Ubuntu](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php7-hiperf/img/B05225_01_01.jpg)

以下是三个有用的 NGINX 命令列表：

+   `service nginx start`：这将启动 NGINX 服务器

+   `service nginx restart`：这将重新启动 NGINX 服务器

+   `service nginx stop`：这将停止 NGINX 服务器

1.  现在，是时候通过发出以下命令来安装 PHP 7 了：

```php
**sudo apt-get install php7.0 php7.0-fpm php7.0-mysql php7.0-mcrypt php7.0-cli**

```

这将安装 PHP 7 以及其他提到的模块。此外，我们还为命令行目的安装了 PHP Cli。要验证 PHP 7 是否已正确安装，请在终端中发出以下命令：

```php
**php –v**

```

1.  如果显示 PHP 版本以及其他一些细节，如下面的屏幕截图所示，那么 PHP 已经正确安装：![Ubuntu](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php7-hiperf/img/B05225_01_02.jpg)

1.  现在，我们需要配置 NGINX 以与 PHP 7 一起工作。首先，通过在终端中使用以下命令将 NGINX 默认配置文件`/etc/nginx/sites-available/default`复制到`/etc/nginx/sites-available/www.packt.com.conf`：

```php
**cd /etc/nginx/sites-available**
**sudo cp default www.packt.com.conf**
**sudo ln –s /etc/nginx /sites-available/www.packt.com.conf /etc/ nginx/sites-enabled/www.packt.com.conf**

```

首先，我们复制了默认配置文件，创建了另一个虚拟主机配置文件`www.packt.com.conf`，然后在 sites-enabled 文件夹中为这个虚拟主机文件创建了一个符号链接文件。

### 注意

为每个虚拟主机创建一个与域名相同的配置文件是一个很好的做法，这样可以很容易地被其他人识别。

1.  现在，打开`/etc/nginx/sites-available/www.packt.com.conf`文件，并添加或编辑高亮显示的代码，如下所示：

```php
server {
  server_**name your_ip:80**;
  root /var/www/html;
  index **index.php** index.html index.htm;
  **location ~ \.php$ {**
 **fastcgi_pass unix:/var/run/php/php7.0-fpm.sock;**
 **fastcgi_index index.php;**
 **include fastcgi_params;**
 **}**
}
```

上述配置不是一个完整的配置文件。我们只复制了那些重要的配置选项，我们可能想要更改的选项。

在上述代码中，我们的 webroot 路径是`/var/www/html`，我们的 PHP 文件和其他应用程序文件将放在这里。在索引配置选项中，添加`index.php`，这样如果 URL 中没有提供文件，NGINX 就可以查找并解析`index.php`。

我们添加了一个用于 PHP 的位置块，其中包括一个`fastcgi_pass`选项，该选项具有指向 PHP7 FPM 套接字的路径。在这里，我们的 PHP 运行在 Unix 套接字上，比 TCP/IP 更快。

1.  在进行这些更改后，重新启动 NGINX。现在，为了测试 PHP 和 NGINX 是否正确配置，创建一个`info.php`文件放在`webroot`文件夹的根目录，并在其中放入以下代码：

```php
<?php
  phpinfo();
 ?>
```

1.  现在，在浏览器中输入`server_ip/info.php`，如果看到一个 PHP 配置页面，那么恭喜！PHP 和 NGINX 都已正确配置。

### 注意

如果 PHP 和 NGINX 在同一系统上运行，那么 PHP 会监听端口`9000`的环回 IP。端口可以更改为任何其他端口。如果我们想要在 TCP/IP 端口上运行 PHP，那么在`fastcgi_pass`中，我们将输入`127.0.0.1:9000`。

现在，让我们安装**Percona Server**。Percona Server 是 MySQL 的一个分支，经过优化以获得更高的性能。我们将在第三章中更多地了解 Percona Server，*提高 PHP 7 应用程序性能*。现在，让我们通过以下步骤在 Debian/Ubuntu 上安装 Percona Server：

1.  首先，让我们通过在终端中运行以下命令将 Percona Server 仓库添加到我们的系统中：

```php
**sudo wget https://repo.percona.com/apt/percona-release_0.1-3.$(lsb_release -sc)_all.deb**
**sudo dpkg -i percona-release_0.1-3.$(lsb_release -sc)_all.deb**

```

第一个命令将从 Percona 仓库下载软件包。第二个命令将安装已下载的软件包，并在`/etc/apt/sources.list.d/percona-release.list`创建一个`percona-release.list`文件。

1.  现在，通过在终端中执行以下命令来安装 Percona Server：

```php
**sudo apt-get update**

```

1.  现在，通过发出以下命令来安装 Percona Server：

```php
**sudo apt-get install percona-server-5.5**

```

安装过程将开始。下载需要一段时间。

### 注意

为了本书的目的，我们将安装 Percona Server 5.5。也可以安装 Percona Server 5.6，而且不会出现任何问题。

在安装过程中，将要求输入`root`用户的密码，如下图所示：

![Ubuntu](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php7-hiperf/img/B05225_01_03.jpg)

输入密码是可选的但建议的。输入密码后，在下一个屏幕上重新输入密码。安装过程将继续。

1.  安装完成后，可以使用以下命令验证 Percona Server 的安装：

```php
**mysql –-version**

```

它将显示 Percona Server 的版本。如前所述，Percona Server 是 MySQL 的一个分支，因此可以使用相同的 MySQL 命令、查询和设置。

# 设置 CentOS

CentOS 是**Red Hat Enterprise Linux**（**RHEL**）的一个分支，代表**Community Enterprise Operating System**。它是服务器上广泛使用的操作系统，特别是由托管公司提供共享托管服务。

让我们首先为我们的开发环境配置 CentOS。执行以下步骤：

## 安装 NGINX

1.  首先，我们需要将 NGINX RPM 添加到我们的 CentOS 安装中，因为 CentOS 没有提供任何默认的 NGINX 仓库。在终端中输入以下命令：

```php
**sudo rpm -Uvh http://nginx.org/packages/centos/7/noarch/RPMS/nginx-release-centos-7-0.el7.ngx.noarch.rpm**

```

这将向 CentOS 添加 NGINX 仓库。

1.  现在，输入以下命令以查看可供安装的 NGINX 版本：

```php
**sudo yum --showduplicates list Nginx**

```

这将显示最新的稳定版本。在我们的情况下，它显示 NGINX 1.8.0 和 NGINX 1.8.1。

1.  现在，让我们使用以下命令安装 NGINX：

```php
**sudo yum install Nginx**

```

这将安装 NGINX。

1.  在 CentOS 上，NGINX 在安装或重新启动后不会自动启动。因此，首先，我们将使用以下命令使 NGINX 在系统重新启动后自动启动：

```php
**systemctl enable Nginx.service**

```

1.  现在，让我们通过输入以下命令来启动 NGINX：

```php
**systemctl start Nginx.service**

```

1.  然后，打开浏览器，输入 CentOS 服务器的 IP 或主机名。如果您看到与我们在 Debian 章节中看到的欢迎屏幕相同的屏幕，则 NGINX 已成功安装。

要检查安装了哪个版本的 NGINX，请在终端中输入以下命令：

```php
**Nginx –v**

```

在我们的服务器上，安装的 NGINX 版本是 1.8.1。

现在，我们的 Web 服务器已准备就绪。

## 安装 PHP 7

1.  下一步是安装 PHP 7 FPM 并配置 NGINX 和 PHP 7 一起工作。在撰写本书时，PHP 7 没有打包在官方的 CentOS 仓库中。因此，我们有两种选择来安装 PHP 7：要么从源代码构建，要么使用第三方仓库。从源代码构建有点困难，所以让我们选择简单的方式，使用第三方仓库。

### 注意

对于本书，我们将使用 webtatic 仓库来安装 PHP 7，因为它们为新版本提供快速更新。还有一些其他仓库，只要它能正常工作，读者可以自行选择使用任何仓库。

1.  现在，让我们通过输入以下命令向我们的 CentOS 仓库添加 webtatic 仓库：

```php
**rpm -Uvh https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm**
**rpm -Uvh https://mirror.webtatic.com/yum/el7/webtatic-release.rpm**

```

1.  成功添加仓库后，输入以下命令以查看可供安装的版本：

```php
**sudo yum –showduplicates list php70w**

```

在我们的情况下，可以安装 PHP 7.0.3。

1.  现在，输入以下命令以安装 PHP 7 以及可能需要的一些模块：

```php
**sudo yum install php70w php70w-common php70w-cli php70w-fpm php70w-mysql php70w-opcache php70w-mcrypt**

```

1.  这将安装核心 PHP 7 和一些可用于 PHP 7 的模块。如果需要其他模块，可以轻松安装；但是首先搜索以检查其是否可用。在终端中输入以下命令以查看所有可用的 PHP 7 模块：

```php
**sudo yum search php70w-**

```

将显示所有可用的 PHP 7 模块的长列表。

1.  现在，假设我们要安装 PHP 7 gd 模块；输入以下命令：

```php
**sudo yum install php70w-gd**

```

这将安装 gd 模块。可以使用相同的命令安装多个模块，并通过空格分隔每个模块，就像我们在最初安装 PHP 时所做的那样。

现在，要检查安装了哪个版本的 PHP，请输入以下命令：

```php
**php –v**

```

在我们的情况下，安装了 PHP 7.0.3。

1.  要启动、停止和重新启动 PHP，请在终端中输入以下命令：

```php
**sudo systemctl start php-fpm**
**sudo systemctl restart php-fpm**
**sudo systemctl stop php-fpm**

```

1.  现在，让我们配置 NGINX 以使用 PHP FPM。使用`vi`、`nano`或您选择的任何其他编辑器打开位于`/etc/Nginx/conf.d/default.conf`的默认 NGINX 虚拟主机文件。现在，请确保服务器块中设置了两个选项，如下所示：

```php
server {
    listen  80;
    server_name  localhost;
 **root   /usr/share/nginx/html;**
**index  index.php index.html index.htm;**

```

`root`选项表示我们的网站源代码文件将放置的 Web 文档根目录。Index 表示将与扩展名一起加载的默认文件。如果找到任何这些文件，默认情况下将执行它们，而不管 URL 中提到的任何文件。

1.  NGINX 中的下一个配置是用于 PHP 的位置块。以下是 PHP 的配置：

```php
location ~ \.php$ {
    try_files $uri =404;
    fastcgi_split_path_info ^(.+\.php)(/.+)$;
    fastcgi_pass 127.0.0.1:9000;
    fastcgi_index index.php;
    fastcgi_param SCRIPT_FILENAME$document_root$fastcgi_script_name;
      include fastcgi_params;
    }
```

上述块是最重要的配置，因为它使 NGINX 能够与 PHP 通信。行`fastcgi_pass 127.0.0.1:9000`告诉 NGINX，PHP FPM 可以在端口`9000`上的`127.0.0.1`环回 IP 上访问。其余细节与我们讨论 Debian 和 Ubuntu 的内容相同。

1.  现在，为了测试我们的安装，我们将创建一个名为`info.php`的文件，其中包含以下内容：

```php
<?php
  phpinfo();
?>
```

保存文件后，输入`http://server_ip/info.php`或`http://hostname/info.php`，我们将得到一个包含有关 PHP 的完整信息的页面。如果您看到此页面，恭喜！PHP 与 NGINX 一起运行。

## 安装 Percona Server

1.  现在，我们将在 CentOS 上安装 Percona Server。安装过程相同，只是它有一个单独的存储库。要将 Percona Server 存储库添加到 CentOS，请在终端中执行以下命令：

```php
**sudo yum install http://www.percona.com/downloads/percona-release/redhat/0.1-3/percona-release-0.1-3.noarch.rpm**

```

存储库安装完成后，将显示一条消息，指示安装完成。

1.  现在，为了测试存储库，发出以下命令，它将列出所有可用的 Percona 软件包：

```php
**sudo yum search percona**

```

1.  要安装 Percona Server 5.5，请在终端中发出以下命令：

```php
**sudo yum install Percona-Server-server-55**

```

安装过程将开始。其余的过程与 Debian/Ubuntu 相同。

1.  安装完成后，将看到完成消息。

# 设置 Vagrant

Vagrant 是开发人员用于开发环境的工具。Vagrant 提供了一个简单的命令行界面，用于设置带有所有所需工具的虚拟机。Vagrant 使用称为 Vagrant Boxes 的框，可以具有 Linux 操作系统和根据此框的其他工具。Vagrant 支持 Oracle VM VirtualBox 和 VMware。为了本书的目的，我们将使用 VirtualBox，我们假设它也安装在您的机器上。

Vagrant 有几个用于 PHP 7 的框，包括 Laravel Homestead 和 Rasmus PHP7dev。因此，让我们开始配置 Windows 和 Mac OS X 上的 Rasmus PHP7dev 框。

### 注意

我们假设我们的机器上都安装了 VirutalBox 和 Vagrant。可以从[`www.virtualbox.org/wiki/Downloads`](https://www.virtualbox.org/wiki/Downloads)下载 VirtualBox，可以从[`www.vagrantup.com/downloads.html`](https://www.vagrantup.com/downloads.html)下载 Vagrant，适用于不同的平台。有关 Rasmus PHP7dev VagrantBox 的详细信息，请访问[`github.com/rlerdorf/php7dev`](https://github.com/rlerdorf/php7dev)。

执行以下步骤：

1.  在其中一个驱动器中创建一个目录。例如，我们在`D`驱动器中创建了一个`php7`目录。然后，通过按住*Shift*键，右键单击，然后选择**在此处打开命令窗口**，直接在此特定文件夹中打开命令行。

1.  现在，在命令窗口中输入以下命令：

```php
**vagrant box add rasmus/php7dev**

```

它将开始下载 Vagrant 框，如下截图所示：

![设置 Vagrant](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php7-hiperf/img/B05225_01_04.jpg)

1.  现在，当下载完成时，我们需要初始化它，以便为我们配置并将该框添加到 VirtualBox 中。在命令窗口中输入以下命令：

```php
**vagrant init rasmus/php7dev**

```

这将开始将框添加到 VirtualBox 并对其进行配置。完成该过程后，将显示一条消息，如下截图所示：

![设置 Vagrant](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php7-hiperf/img/B05225_01_05.jpg)

1.  现在，输入以下命令，这将完全设置 Vagrant 框并启动它：

```php
**vagrant up**

```

这个过程会花一点时间。当完成后，你的框已经准备好并且可以使用了。

1.  现在，启动后的第一件事是更新所有内容。这个框使用 Ubuntu，所以在相同的`php7dev`目录中打开命令窗口，并输入以下命令：

```php
**vagrant ssh**

```

它将通过 SSH 将我们连接到虚拟机。

### 注意

在 Windows 中，如果 SSH 未安装或未在`PATH`变量中配置，可以使用 PuTTY。可以从[`www.chiark.greenend.org.uk/~sgtatham/putty/download.html`](http://www.chiark.greenend.org.uk/~sgtatham/putty/download.html)下载。对于 PuTTY，主机将是`127.0.0.1`，端口将是`2222`。`Vagrant`是 SSH 的用户名和密码。

1.  当我们登录到框的操作系统时，输入以下命令来更新系统：

```php
**sudo apt-get update**
**sudo apt-get upgrade**

```

这将更新核心系统、NGINX、MySQL、PHP 7 和其他安装的工具，如果有新版本的话。

1.  现在，框已经准备好用于开发目的。可以通过在浏览器窗口中输入其 IP 地址来访问框。要找到框的 IP 地址，在 SSH 连接的命令窗口中输入以下命令：

```php
**sudo ifconfig**

```

这将显示一些细节。在那里找到 IPv4 的细节并取得框的 IP。

# 总结

在本章中，我们为开发目的配置了不同的环境。我们在 Windows 机器上安装了 NGINX 和 PHP 7。我们还配置了 Debian/Ubuntu 并安装了 NGINX、PHP 和 Percona Server 5.5。然后，我们配置了 CentOS 并安装了 NGINX、PHP 和 Percona Server 5.5。最后，我们讨论了如何在 Windows 机器上配置 Vagrant Box。

在下一章中，我们将学习 PHP 7 的新功能，比如类型提示、命名空间分组和声明、太空船操作符等其他功能。


# 第二章：PHP 7 中的新功能

PHP 7 引入了一些新功能，可以帮助程序员编写高性能和有效的代码。此外，一些老式的功能已经完全移除，如果使用 PHP 7 将抛出错误。现在大多数致命错误都是异常，因此 PHP 不会再显示丑陋的致命错误消息；相反，它将通过可用的详细信息进行异常处理。

在本章中，我们将涵盖以下主题：

+   类型提示

+   命名空间和组使用声明

+   匿名类

+   旧式构造函数弃用

+   太空船运算符

+   空合并运算符

+   统一变量语法

+   其他更改

# 面向对象编程特性

PHP 7 引入了一些新的面向对象编程功能，使开发人员能够编写干净而有效的代码。在本节中，我们将讨论这些功能。

## 类型提示

在 PHP 7 之前，不需要声明传递给函数或类方法的参数的数据类型。此外，也不需要提及返回数据类型。任何数据类型都可以传递给函数或方法，并从函数或方法返回。这是 PHP 中的一个巨大问题，不清楚应该传递或接收哪些数据类型。为了解决这个问题，PHP 7 引入了类型提示。目前，引入了两种类型提示：标量和返回类型提示。这些将在以下部分讨论。

类型提示是面向对象编程和过程式 PHP 中的一个特性，因为它可以用于过程式函数和对象方法。

### 标量类型提示

PHP 7 使得可以为整数、浮点数、字符串和布尔值的函数和方法使用标量类型提示。让我们看下面的例子：

```php
class Person
{
  public function age(int $age)
  {
    return $age;
    }

  public function name(string $name)
  {
    return $name;
    }

  public function isAlive(bool $alive)
  {
    return $alive;
    }

}

$person = new Person();
echo $person->name('Altaf Hussain');
echo $person->age(30);
echo $person->isAlive(TRUE);
```

在上面的代码中，我们创建了一个`Person`类。我们有三种方法，每种方法接收不同的参数，其数据类型在上面的代码中进行了定义。如果运行上面的代码，它将正常工作，因为我们将为每种方法传递所需的数据类型。

年龄可以是浮点数，例如`30.5`岁；因此，如果我们将浮点数传递给`age`方法，它仍然可以工作，如下所示：

```php
echo $person->age(30.5);
```

为什么？这是因为默认情况下，*标量类型提示是非限制性的*。这意味着我们可以将浮点数传递给期望整数的方法。

为了使其更加严格，可以将以下单行代码放在文件的顶部：

```php
declare(strict_types = 1);
```

现在，如果我们将浮点数传递给`age`函数，我们将得到一个**未捕获的类型错误**，这是一个致命错误，告诉我们`Person::age`必须是给定浮点数的整数类型。如果我们将字符串传递给不是字符串类型的方法，将生成类似的错误。考虑以下例子：

```php
echo $person->isAlive('true');
```

由于传递了字符串，上面的代码将生成致命错误。

### 返回类型提示

PHP 7 的另一个重要特性是能够为函数或方法定义返回数据类型。它的行为与标量类型提示的行为相同。让我们稍微修改我们的`Person`类以理解返回类型提示，如下所示：

```php
class Person
{
  public function age(float $age) : string
  {
    return 'Age is '.$age;
  }

  public function name(string $name) : string
  {
    return $name;
    }

  public function isAlive(bool $alive) : string
  {
    return ($alive) ? 'Yes' : 'No';
  }

}
```

类中的更改已经突出显示。使用`:数据类型`语法定义了返回类型。返回类型是否与标量类型相同并不重要。只要它们与各自的数据类型匹配即可。

现在，让我们尝试一个带有对象返回类型的例子。考虑之前的`Person`类，并向其添加一个`getAddress`方法。此外，我们将在同一个文件中添加一个新的类`Address`，如下所示：

```php
**class Address** 
**{**
 **public function getAddress()**
 **{**
 **return ['street' => 'Street 1', 'country' => 'Pak'];**
 **}**
**}**

class Person
{
  public function age(float $age) **: string**
  {
    return 'Age is '.$age;
  }

  public function name(string $name) **: string**
  {
    return $name;
  }

  public function isAlive(bool $alive) : string
  {
    return ($alive) ? 'Yes' : 'No';
  }

 **public function getAddress() : Address**
 **{**
 **return new Address();**
 **}**
}
```

添加到`Person`类和新的`Address`类的附加代码已经突出显示。现在，如果我们调用`Person`类的`getAddress`方法，它将完美地工作，不会抛出错误。然而，假设我们改变返回语句，如下所示：

```php
public function getAddress() : Address
{
  return ['street' => 'Street 1', 'country' => 'Pak'];
}
```

在这种情况下，上面的方法将抛出类似于以下内容的*未捕获*异常：

```php
Fatal error: Uncaught TypeError: Return value of Person::getAddress() must be an instance of Address, array returned
```

这是因为我们返回的是一个数组，而不是一个`Address`对象。现在，问题是：为什么使用类型提示？使用类型提示的重要优势是它将始终避免意外地传递或返回错误和意外的数据到方法或函数。

如前面的例子所示，这使得代码清晰，通过查看方法的声明，可以准确知道应该传递哪些数据类型到每个方法，以及通过查看每个方法的代码或注释，返回什么类型的数据。

## 命名空间和组使用声明

在一个非常庞大的代码库中，类被划分到命名空间中，这使得它们易于管理和使用。但是，如果一个命名空间中有太多的类，而我们需要使用其中的 10 个类，那么我们必须为所有这些类输入完整的使用语句。

### 注意

在 PHP 中，不需要根据其命名空间将类分成子文件夹，这与其他编程语言不同。命名空间只是提供类的逻辑分离。但是，我们不限于根据我们的命名空间将我们的类放在子文件夹中。

例如，我们有一个`Publishers/Packt`命名空间和类`Book`、`Ebook`、`Video`和`Presentation`。此外，我们有一个`functions.php`文件，其中包含我们的常规函数，并且在相同的`Publishers/Packt`命名空间中。另一个文件`constants.php`包含应用程序所需的常量值，并且在相同的命名空间中。每个类和`functions.php`和`constants.php`文件的代码如下：

```php
//book.php
namespace Publishers\Packt;

class Book 
{
  public function get() : string
  {
    return get_class();
  }
}
```

现在，`Ebook`类的代码如下：

```php
//ebook.php
namespace Publishers\Packt;

class Ebook 
{
  public function get() : string
  {
    return get_class();
  }
}
```

`Video`类的代码如下：

```php
//presentation.php
namespace Publishers\Packt;

class Video 
{
  public function get() : string
  {
    return get_class();
  }
}
```

同样，`presentation`类的代码如下：

```php
//presentation.php
namespace Publishers\Packt;

class Presentation 
{
  public function get() : string
  {
    return get_class();
  }
}
```

所有四个类都有相同的方法，这些方法使用 PHP 内置的`get_class()`函数返回类的名称。

现在，将以下两个函数添加到`functions.php`文件中：

```php
//functions.php

namespace Publishers\Packt;

function getBook() : string
{
  return 'PHP 7';
}
function saveBook(string $book) : string
{
  return $book.' is saved';
}
```

现在，让我们将以下代码添加到`constants.php`文件中：

```php
//constants.php

namespace Publishers/Packt;

const COUNT = 10;
const KEY = '123DGHtiop09847';
const URL = 'https://www.Packtpub.com/';
```

`functions.php`和`constants.php`中的代码是不言自明的。请注意，每个文件顶部都有一行`namespace Publishers/Packt`，这使得这些类、函数和常量属于这个命名空间。

现在，有三种方法可以使用类、函数和常量。让我们逐一考虑每一种。

看一下下面的代码：

```php
//Instantiate objects for each class in namespace

$book = new Publishers\Packt\Book();
$ebook = new Publishers\Packt\Ebook();
$video = new Publishers\Packt\Video();
$presentation = new Publishers\Packt\Presentation();

//Use functions in namespace

echo Publishers/Packt/getBook();
echo Publishers/Packt/saveBook('PHP 7 High Performance');

//Use constants

echo Publishers\Packt\COUNT;
echo Publishers\Packt\KEY;
```

在前面的代码中，我们直接使用命名空间名称创建对象或使用函数和常量。代码看起来不错，但是有点混乱。命名空间到处都是，如果我们有很多命名空间，它看起来会很丑陋，可读性也会受到影响。

### 注意

我们在之前的代码中没有包含类文件。可以使用`include`语句或 PHP 的`__autoload`函数来包含所有文件。

现在，让我们重新编写前面的代码，使其更易读，如下所示：

```php
use Publishers\Packt\Book;
use Publishers\Packt\Ebook;
use Publishers\Packt\Video;
use Publishers\Packt\Presentation;
use function Publishers\Packt\getBook;
use function Publishers\Packt\saveBook;
use const Publishers\Packt\COUNT;
use const Publishers\Packt\KEY;

$book = new Book();
$ebook = new Ebook(();
$video = new Video();
$pres = new Presentation();

echo getBook();
echo saveBook('PHP 7 High Performance');

echo COUNT; 
echo KEY;
```

在前面的代码中，我们在顶部使用了 PHP 语句来指定命名空间中特定的类、函数和常量。但是，我们仍然为每个类、函数和/或常量编写了重复的代码行。这可能导致我们在文件顶部有大量的使用语句，并且整体冗长度不好。

为了解决这个问题，PHP 7 引入了组使用声明。有三种类型的组使用声明：

+   非混合使用声明

+   混合使用声明

+   复合使用声明

### 非混合组使用声明

假设我们在一个命名空间中有不同类型的特性，如类、函数和联系人。在非混合组使用声明中，我们使用`use`语句分别声明它们。为了更好地理解它，请看下面的代码：

```php
use Publishers\Packt\{ Book, Ebook, Video, Presentation };
use function Publishers\Packt\{ getBook, saveBook };
use const Publishers\Packt\{ COUNT, KEY };
```

在一个命名空间中，我们有三种特性：类、函数和常量。因此，我们使用单独的组`use`声明语句来使用它们。现在，代码看起来更清晰、有组织、可读性更好，而且不需要太多重复输入。

### 混合组使用声明

在这个声明中，我们将所有类型合并到一个`use`语句中。看看以下代码：

```php
use Publishers\Packt\{ 
  Book,
  Ebook,
  Video,
  Presentation,
  function getBook,
  function saveBook,
  const COUNT,
  const KEY
};
```

### 复合命名空间声明

为了理解复合命名空间声明，我们将考虑以下标准。

假设我们在`Publishers\Packt\Paper`命名空间中有一个`Book`类。此外，我们在`Publishers\Packt\Electronic`命名空间中有一个`Ebook`类。`Video`和`Presentation`类位于`Publishers\Packt\Media`命名空间中。因此，为了使用这些类，我们将使用以下代码：

```php
use Publishers\Packt\Paper\Book;
use Publishers\Packt\Electronic\Ebook;
use Publishers\Packt\Media\{Video,Presentation};
```

在复合命名空间声明中，我们可以使用前面的命名空间，如下所示：

```php
use Publishers\Packt\{
  Paper\Book,
  Electronic\Ebook,
  Media\Video,
  Media\Presentation
};
```

这更加优雅和清晰，如果命名空间名称很长，它不需要额外的输入。

## 匿名类

匿名类是在声明和实例化同时进行的类。它没有名称，并且可以具有普通类的全部特性。当需要执行一次性的小任务并且不需要为此编写完整的类时，这些类非常有用。

### 注意

在创建匿名类时，它没有名称，但在 PHP 内部使用基于内存块中的地址的唯一引用来命名。例如，匿名类的内部名称可能是`class@0x4f6a8d124`。

这个类的语法与命名类的语法相同，但类的名称缺失，如下所示：

```php
new class(argument) { definition };
```

让我们看一个匿名类的基本和非常简单的例子，如下所示：

```php
$name = new class() {
  public function __construct()
  {
    echo 'Altaf Hussain';
  }
};
```

前面的代码只会显示`Altaf Hussain`。

参数也可以传递给*匿名类构造函数*，如下所示的代码：

```php
$name = new class('Altaf Hussain') {
  public function __construct(string $name)
  {
    echo $name;
  }
};
```

这将给我们与第一个示例相同的输出。

匿名类可以扩展其他类，并且具有与普通命名类相同的父子类功能。让我们看另一个例子；看看以下内容：

```php
class Packt
{
  protected $number;

  public function __construct()
  {
    echo 'I am parent constructor';
  }

  public function getNumber() : float
  {
    return $this->number;
  }
}

$number = new class(5) extends packt
{
  public function __construct(float $number)
  {
    parent::__construct();
    $this->number = $number;
  }
};

echo $number->getNumber();
```

前面的代码将显示`I am parent constructor`和`5`。可以看到，我们扩展`Packt`类的方式与我们扩展命名类的方式相同。此外，我们可以在匿名类中访问`public`和`protected`属性和方法，并且可以使用匿名类对象访问公共属性和方法。

匿名类也可以实现接口，与命名类一样。让我们首先创建一个接口。运行以下代码：

```php
interface Publishers
{
  public function __construct(string $name, string $address);
  public function getName();
  public function getAddress();
}
```

现在，让我们修改我们的`Packt`类如下。我们添加了突出显示的代码：

```php
class Packt
{
  protected $number;
  protected $name;
  protected $address;
  public function …
}
```

代码的其余部分与第一个`Packt`类相同。现在，让我们创建我们的匿名类，它将实现前面代码中创建的`Publishers`接口，并扩展新的`Packt`类，如下所示：

```php
$info = new class('Altaf Hussain', 'Islamabad, Pakistan')extends packt implements Publishers
{
  public function __construct(string $name, string $address)
  {
    $this->name = $name;
    $this->address = $address;
  }

  public function getName() : string
  {
  return $this->name;
  }

  public function getAddress() : string
  {
  return $this->address;
  }
}

echo $info->getName(). ' '.$info->getAddress();
```

前面的代码是不言自明的，并将输出`Altaf Hussain`以及地址。

可以在另一个类中使用匿名类，如下所示：

```php
class Math
{
  public $first_number = 10;
  public $second_number = 20;

  public function add() : float
  {
    return $this->first_number + $this->second_number;
  }

  public function multiply_sum()
  {
    return new class() extends Math
    {
      public function multiply(float $third_number) : float
      {
        return $this->add() * $third_number;
      }
    };
  }
}

$math = new Math();
echo $math->multiply_sum()->multiply(2);
```

前面的代码将返回`60`。这是如何发生的？`Math`类有一个`multiply_sum`方法，返回匿名类的对象。这个匿名类是从`Math`类扩展出来的，并且有一个`multiply`方法。因此，我们的`echo`语句可以分为两部分：第一部分是`$math->multiply_sum()`，它返回匿名类的对象，第二部分是`->multiply(2)`，在这里我们链接了这个对象来调用匿名类的`multiply`方法，并传入值`2`。

在前面的情况下，`Math`类可以被称为外部类，匿名类可以被称为内部类。但是，请记住，内部类不需要扩展外部类。在前面的例子中，我们扩展它只是为了确保内部类可以通过扩展外部类来访问外部类的属性和方法。

## 旧式构造函数弃用

回到 PHP 4 时，类的构造函数与类的同名方法。它仍然被使用，并且在 PHP 的 5.6 版本之前是有效的。然而，现在在 PHP 7 中，它已被弃用。让我们看一个示例，如下所示：

```php
class Packt
{
  public function packt()
  {
    echo 'I am an old style constructor';
  }
}

$packt = new Packt();
```

前面的代码将显示输出`我是一个旧式构造函数`，并附带一个弃用消息，如下所示：

```php
Deprecated: Methods with the same name as their class will not be constructors in a future version of PHP; Packt has a deprecated constructor in…
```

然而，仍然调用旧式构造函数。现在，让我们向我们的类添加 PHP `__construct`方法，如下所示：

```php
class Packt
{
  public function __construct()
  {
    echo 'I am default constructor';
  }

  public function packt()
  {
    echo 'I am just a normal class method';
  }
}

$packt = new Packt();
$packt->packt();
```

在前面的代码中，当我们实例化类的对象时，会调用普通的`__construct`构造函数。`packt()`方法不被视为普通的类方法。

### 注意

旧式构造函数已经被弃用，这意味着它们在 PHP 7 中仍然可以工作，并且会显示一个弃用的消息，但它将在即将推出的版本中被移除。最好不要使用它们。

## 可抛出接口

PHP 7 引入了一个基本接口，可以作为可以使用`throw`语句的每个对象的基础。在 PHP 中，异常和错误可能会发生。以前，异常可以被处理，但无法处理错误，因此，任何致命错误都会导致整个应用程序或应用程序的一部分停止。为了使错误（最致命的错误）也可以被捕获，PHP 7 引入了*throwable*接口，它由异常和错误都实现。

### 注意

我们创建的 PHP 类无法实现可抛出接口。如果需要，这些类必须扩展异常。

我们都知道异常，因此在这个主题中，我们只讨论可以处理丑陋的致命错误的错误。

### 错误

现在几乎所有致命错误都可以抛出错误实例，类似于异常，错误实例可以使用`try/catch`块捕获。让我们来看一个简单的例子：

```php
function iHaveError($object)
{
  return $object->iDontExist();
  {

//Call the function
iHaveError(null);
echo "I am still running";
```

如果执行前面的代码，将显示致命错误，应用程序将停止，并且最终不会执行`echo`语句。

现在，让我们将函数调用放在`try/catch`块中，如下所示：

```php
try 
{
  iHaveError(null);
} catch(Error $e)
{
  //Either display the error message or log the error message
  echo $e->getMessage();
}

echo 'I am still running';
```

现在，如果执行前面的代码，`catch`体将被执行，之后，应用程序的其余部分将继续运行。在前面的情况下，`echo`语句将被执行。

在大多数情况下，错误实例将被抛出，用于最致命的错误，但对于一些错误，将抛出错误的子实例，例如`TypeError`、`DivisionByZeroError`、`ParseError`等。

现在，让我们看一个以下示例中的`DivisionByZeroError`异常：

```php
try
{
  $a = 20;
  $division = $a / 20;
} catch(DivisionByZeroError $e) 
{
  echo $e->getMessage();
}
```

在 PHP 7 之前，前面的代码会发出有关除以零的警告。然而，现在在 PHP 7 中，它将抛出一个`DivisionByZeroError`，可以处理。

# 新运算符

PHP 7 引入了两个有趣的运算符。这些运算符可以帮助编写更少、更清晰的代码，因此最终的代码将比使用传统运算符更易读。让我们来看看它们。

## 太空船运算符（<=>）

太空船或组合比较运算符对于比较值（字符串、整数、浮点数等）、数组和对象非常有用。这个运算符只是一个包装器，执行与三个比较运算符`==`、`<`和`>`相同的任务。这个运算符也可以用于为`usort`、`uasort`和`uksort`的回调函数编写干净和少量的代码。这个运算符的工作方式如下：

+   如果左右两侧的操作数相等，则返回 0

+   如果右操作数大于左操作数，则返回-1

+   如果左操作数大于右操作数，则返回 1

让我们通过比较整数、字符串、对象和数组来看几个例子，并注意结果：

```php
$int1 = 1;
$int2 = 2;
$int3 = 1;

echo $int1 <=> $int3; //Returns 0
echo '<br>';
echo $int1 <=> $int2; //Returns -1
echo '<br>';
echo $int2 <=> $int3; //Returns 1
```

运行前面的代码，你将得到类似以下的输出：

```php
0
-1
1
```

在第一个比较中，我们比较了`$int1`和`$int3`，两者都相等，所以它将返回`0`。在第二个比较中，比较了`$int1`和`$int2`，它将返回`-1`，因为右操作数（`$int2`）大于左操作数（`$int1`）。最后，第三个比较将返回`1`，因为左操作数（`$int2`）大于右操作数（`$int3`）。

上面是一个简单的例子，我们在其中比较了整数。我们可以以相同的方式检查字符串、对象和数组，并且它们是按照标准的 PHP 方式进行比较的。

### 注意

关于`<=>`运算符的一些例子可以在[`wiki.php.net/rfc/combined-comparison-operator`](https://wiki.php.net/rfc/combined-comparison-operator)找到。这是一个 RFC 出版物，其中有关于其用法的更多有用细节。

这个运算符在对数组进行排序时更有用。看看下面的代码：

```php
Function normal_sort($a, $b) : int 
{
  if( $a == $b )
    return 0;
  if( $a < $b )
    return -1;
  return 1;
}

function space_sort($a, $b) : int
{
  return $a <=> $b;
}

$normalArray = [1,34,56,67,98,45];

//Sort the array in asc
usort($normalArray, 'normal_sort');

foreach($normalArray as $k => $v)
{
  echo $k.' => '.$v.'<br>';
}

$spaceArray = [1,34,56,67,98,45];

//Sort it by spaceship operator
usort($spaceArray, 'space_sort');

foreach($spaceArray as $key => $value)
{
  echo $key.' => '.$value.'<br>';
}
```

在前面的代码中，我们使用了两个函数来对具有相同值的两个不同数组进行排序。`$normalArray`数组通过`normal_sort`函数进行排序，`normal_sort`函数使用`if`语句来比较值。第二个数组`$spaceArray`具有与`$normalArray`相同的值，但是这个数组通过`space_sort`函数进行排序，`space_sort`函数使用了太空船运算符。两个数组排序的最终结果是相同的，但回调函数中的代码是不同的。`normal_sort`函数有`if`语句和多行代码，而`space_sort`函数只有一行代码，就是这样！`space_sort`函数的代码更清晰，不需要多个 if 语句。

## 空合并运算符(??)

我们都知道三元运算符，并且大多数时候都会使用它们。三元运算符只是*if-else*语句的单行替代。例如，考虑以下代码：

```php
$post = ($_POST['title']) ? $_POST['title'] : NULL;
```

如果`$_POST['title']`存在，则`$post`变量将被赋予它的值；否则，将被赋予`NULL`。但是，如果`$_POST`或`$_POST['title']`不存在或为 null，则 PHP 将发出*未定义的索引*的通知。为了解决这个通知，我们需要使用`isset`函数，如下所示：

```php
$post = isset($_POST['title']) ? $_POST['title'] : NULL;
```

大多数情况下，看起来都很好，但当我们需要在多个地方检查值时，特别是在使用 PHP 作为模板语言时，情况就会变得非常棘手。

在 PHP 7 中，引入了合并运算符，它很简单，如果第一个操作数（左操作数）存在且不为 null，则返回其值。否则，返回第二个操作数（右操作数）。考虑以下例子：

```php
$post = $_POST['title'] ?? NULL;
```

这个例子与前面的代码完全相似。合并运算符检查`$_POST['title']`是否存在。如果存在，运算符返回它；否则，返回`NULL`。

这个运算符的另一个很棒的特性是它可以链接起来。以下是一个例子：

```php
$title = $_POST['title'] ?? $_GET['title'] ?? 'No POST or GET';
```

根据定义，它将首先检查第一个操作数是否存在并返回它；如果不存在，它将返回第二个操作数。现在，如果第二个操作数上使用了另一个合并运算符，同样的规则将被应用，如果左操作数存在，则返回它的值。否则，将返回右操作数的值。

因此，上面的代码与以下代码相同：

```php
If(isset($_POST['title']))
  $title = $_POST['title'];
elseif(isset($_GET['title']))
  $title = $_GET['title'];
else
  $title = 'No POST or GET';
```

正如前面的例子中所示，合并运算符可以帮助编写干净、简洁和更少的代码。

# 统一变量语法

大多数情况下，我们可能会遇到这样一种情况，即方法、变量或类名存储在其他变量中。看看下面的例子：

```php
$objects['class']->name;
```

在前面的代码中，首先会解释`$objects['class']`，然后会解释属性名。如前面的例子所示，变量通常是从左到右进行评估的。

现在，考虑以下情景：

```php
$first = ['name' => 'second'];
$second = 'Howdy';

echo $$first['name'];
```

在 PHP 5.x 中，这段代码将被执行，并且输出将是`Howdy`。然而，这与从左到右的表达式评估是不一致的。这是因为`$$first`应该首先被评估，然后是索引名称，但在前面的情况下，它被评估为`${$first['name']}`。很明显，变量语法不一致，可能会造成混淆。为了避免这种不一致，PHP 7 引入了一种称为统一变量语法的新语法。如果不使用这种语法，前面的例子将引起注意，并且不会产生期望的结果。为了使其在 PHP 7 中工作，应添加大括号，如下所示：

```php
echo ${$first['name']};
```

现在，让我们举一个例子，如下所示：

```php
class Packt
{
  public $title = 'PHP 7';
  public $publisher = 'Packt Publisher';

  public function getTitle() : string
  {
    return $this->title;
  }

  public function getPublisher() : string
  {
    return $this->publisher;
  }
}

$mthods = ['title' => 'getTitle', 'publisher' => 'getPublisher'];
$object = new Packt();
echo 'Book '.$object->$methods['title']().' is published by '.$object->$methods['publisher']();
```

如果在 PHP 5.x 中执行上述代码，它将正常工作并输出我们想要的结果。但是，如果我们在 PHP 7 中执行此代码，将会产生致命错误。错误将出现在代码的最后一行，这是突出显示的。PHP 7 将首先尝试评估`$object->$method`。之后，它将尝试评估`['title']`；依此类推；这是不正确的。

为了使其在 PHP 7 中工作，应添加大括号，如下所示：

```php
echo 'Book '.$object**->{$methods['title']}**().' is published by '.$object->**{$methods['publisher']}**();
```

在进行了前面提到的更改之后，我们将得到我们想要的输出。

# 其他功能和更改

PHP 7 还引入了一些其他新功能和小的更改，比如数组常量的新语法、`switch`语句中的多个默认情况、`session_start`中的选项数组等。让我们也看看这些。

## 常量数组

从 PHP 5.6 开始，可以使用`const`关键字初始化常量数组，如下所示：

```php
const STORES = ['en', 'fr', 'ar'];
```

现在，从 PHP 7 开始，可以使用`define`函数初始化常量数组，如下所示：

```php
define('STORES', ['en', 'fr', 'ar']);
```

## 在 switch 语句中的多个默认情况

在 PHP 7 之前，允许在 switch 语句中有多个默认情况。请看下面的例子：

```php
switch(true)
{
  default: 
    echo 'I am first one';
    break;
  default: 
    echo 'I am second one';
}
```

在 PHP 7 之前，允许上述代码，但在 PHP 7 中，这将导致类似以下的致命错误：

```php
Fatal error: Switch statements may only contain one default clause in…
```

## `session_start`函数的选项数组

在 PHP 7 之前，每当我们需要启动会话时，我们只是使用`session_start()`函数。这个函数不带任何参数，并且使用`php.ini`中定义的所有设置。现在，从 PHP 7 开始，可以传递一个可选的选项数组，它将覆盖`php.ini`文件中的会话设置。

一个简单的例子如下所示：

```php
session_start([
  'cookie_lifetime' => 3600,
  'read_and_close'  => true
]);
```

如前面的例子所示，很容易覆盖会话的`php.ini`设置。

## 过滤反序列化函数

序列化和反序列化对象是常见的做法。然而，PHP 的`unserialize()`函数并不安全，因为它没有任何过滤选项，并且可以反序列化任何类型的对象。PHP 7 在这个函数中引入了过滤。默认的过滤选项是反序列化所有类或类型的对象。其基本工作如下：

```php
$result = unserialize($object, ['allowed_classes' => ['Packt', 'Books', 'Ebooks']]);
```

# 总结

在本章中，我们讨论了新的面向对象编程功能，如类型提示、匿名类、可抛出接口、命名空间的组合使用声明以及两个重要的新运算符，太空船或组合比较运算符和 null 合并运算符。此外，我们还讨论了统一的变量语法和其他一些新功能，如联系数组定义的新语法、`session_start()`函数的选项数组以及在 switch 语句中删除多个默认情况。

在下一章中，我们将讨论如何提高应用程序的性能。我们将讨论 Apache 和 NGINX 以及它们的不同设置以提高性能。

我们将讨论不同的 PHP 设置，以提高其性能。还将讨论 Google 页面速度模块、CSS/JavaScript 合并和压缩、CDN 等。


# 第三章：提高 PHP 7 应用程序性能

PHP 7 已经完全重写，基于**PHP Next Generation**（**phpng**或**PHPNG**）进行性能优化。然而，总是有更多的方法来提高应用程序的性能，包括编写高性能代码、使用最佳实践、Web 服务器优化、缓存等。在本章中，我们将讨论以下列出的这些优化：

+   NGINX 和 Apache

+   HTTP 服务器优化

+   内容交付网络（CDN）

+   JavaScript/CSS 优化

+   完整页面缓存

+   Varnish

+   基础设施

# NGINX 和 Apache

有太多的 HTTP 服务器软件可用，每个都有其优缺点。最常用的两个 HTTP 服务器是 NGINX 和 Apache。让我们来看看它们两个，并注意哪一个更适合我们的需求。

## Apache

Apache 是最广泛使用的 HTTP 服务器，大多数管理员都喜爛它。管理员选择它是因为它的灵活性、广泛的支持、强大的功能以及对大多数解释性语言（如 PHP）的模块支持。由于 Apache 可以处理大量的解释性语言，它不需要与其他软件通信来满足请求。Apache 可以在 prefork（进程在线程之间生成）、worker（线程在进程之间生成）和事件驱动（与 worker 进程相同，但为*keep-alive*连接设置专用线程和为活动连接设置单独线程）中处理请求；因此，它提供了更大的灵活性。

正如前面讨论的，每个请求将由单个线程或进程处理，因此 Apache 消耗了太多资源。当涉及高流量应用程序时，Apache 可能会减慢应用程序的速度，因为它不提供良好的并发处理支持。

## NGINX

NGINX 是为解决高流量应用程序的并发问题而构建的。NGINX 提供了异步、事件驱动和非阻塞的请求处理。由于请求是异步处理的，NGINX 不会等待请求完成以阻塞资源。

NGINX 创建工作进程，每个工作进程可以处理成千上万的连接。因此，少量进程可以同时处理高流量。

NGINX 不提供任何解释性语言的内置支持。它依赖外部资源来实现这一点。这也是好的，因为处理是在 NGINX 之外进行的，NGINX 只处理连接和请求。大多数情况下，NGINX 被认为比 Apache 更快。在某些情况下，例如处理静态内容（提供图像、`.css`和`.js`文件等），这可能是真的，但在当前高性能服务器中，Apache 并不是问题；PHP 是瓶颈。

### 注意

Apache 和 NGINX 都适用于各种操作系统。在本书中，我们将使用 Debian 和 Ubuntu，因此所有文件路径都将根据这些操作系统进行提及。

如前所述，我们将在本书中使用 NGINX。

# HTTP 服务器优化

每个 HTTP 服务器都提供了一些功能，可以用来优化请求处理和提供内容。在本节中，我们将分享一些适用于 Apache 和 NGINX 的技术，用来优化 Web 服务器并提供最佳性能和可伸缩性。通常，应用这些优化后，需要重新启动 Apache 或 NGINX。

## 缓存静态文件

大多数静态文件，如图像、`.css`、`.js`和字体，不经常更改。因此，最佳做法是在最终用户的机器上缓存这些静态文件。为此，Web 服务器会在响应中添加特殊标头，告诉用户浏览器将静态内容缓存一段时间。以下是 Apache 和 NGINX 的配置代码。

### Apache

让我们来看看 Apache 配置如何缓存以下静态内容：

```php
<FilesMatch "\.(ico|jpg|jpeg|png|gif|css|js|woff)$">
  Header set Cache-Control "max-age=604800, public
</FileMatch>
```

在前面的代码中，我们使用了 Apache 的`FilesMatch`指令来匹配文件的扩展名。如果请求了所需的扩展名文件，Apache 会将头设置为缓存控制七天。然后浏览器会将这些静态文件缓存七天。

### NGINX

以下配置可以放置在`/etc/nginx/sites-available/your-virtual-host-conf-file`中：

```php
Location ~* .(ico|jpg|jpeg|png|gif|css|js|woff)$ {
  Expires 7d;
}
```

在前面的代码中，我们使用了 NGINX 的`Location`块和不区分大小写的修饰符(`~*`)来设置七天的`Expires`。此代码将为所有定义的文件类型设置七天的缓存控制头。

进行这些设置后，请求的响应头将如下所示：

![NGINX](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php7-hiperf/img/B05225_03_01.jpg)

在前面的图中，可以清楚地看到`.js`文件是从缓存中加载的。它的缓存控制头设置为七天或 604,800 秒。到期日期也可以清楚地在`expires`头中注意到。到期日期后，浏览器将从服务器加载此`.js`文件，并根据缓存控制头中定义的持续时间再次缓存它。

# HTTP 持久连接

在 HTTP 持久连接或 HTTP keep-alive 中，单个 TCP/IP 连接用于多个请求或响应。与正常连接相比，它具有巨大的性能改进，因为它只使用一个连接，而不是为每个单独的请求或响应打开和关闭连接。HTTP keep-alive 的一些好处如下：

+   由于一次只打开了较少的 TCP 连接，并且对于后续的请求和响应不会打开新的连接，因为这些 TCP 连接用于它们，所以 CPU 和内存的负载减少了。

+   在建立 TCP 连接后，减少了后续请求的延迟。当要建立 TCP 连接时，用户和 HTTP 服务器之间进行了三次握手通信。成功握手后，建立了 TCP 连接。在 keep-alive 的情况下，仅对初始请求进行一次握手以建立 TCP 连接，并且对于后续请求不进行握手或 TCP 连接的打开/关闭。这提高了请求/响应的性能。

+   网络拥塞减少了，因为一次只打开了少量 TCP 连接到服务器。

除了这些好处，keep-alive 还有一些副作用。每个服务器都有并发限制，当达到或消耗此并发限制时，应用程序的性能可能会大幅下降。为了解决这个问题，为每个连接定义了超时，超过超时后，HTTP keep-alive 连接将自动关闭。现在，让我们在 Apache 和 NGINX 上都启用 HTTP keep-alive。

## Apache

在 Apache 中，keep-alive 可以通过两种方式启用。您可以在`.htaccess`文件或 Apache 配置文件中启用它。

要在`.htaccess`文件中启用它，请在`.htaccess`文件中放置以下配置：

```php
<ifModule mod_headers.c>
  Header set Connection keep-alive
</ifModule>
```

在前面的配置中，我们在`.htaccess`文件中将连接头设置为 keep-alive。由于`.htaccess`配置会覆盖配置文件中的配置，这将覆盖 Apache 配置文件中对 keep-alive 所做的任何配置。

要在 Apache 配置文件中启用 keep-alive 连接，我们必须修改三个配置选项。搜索以下配置并将值设置为示例中的值：

```php
KeepAlive On
MaxKeepAliveRequests 100
KeepAliveTimeout 100
```

在前面的配置中，我们通过将`KeepAlive`的值设置为`On`来打开了 keep-alive 配置。

接下来是`MaxKeepAliveRequests`，它定义了同时向 Web 服务器保持活动连接的最大数量。在 Apache 中，默认值为 100，并且可以根据要求进行更改。为了获得高性能，应该保持这个值较高。如果设置为 0，将允许无限的 keep-alive 连接，这是不推荐的。

最后一个配置是`KeepAliveTimeout`，设置为 100 秒。这定义了在同一 TCP 连接上等待来自同一客户端的下一个请求的秒数。如果没有请求，则连接将关闭。

## NGINX

HTTP keep-alive 是`http_core`模块的一部分，默认情况下已启用。在 NGINX 配置文件中，我们可以编辑一些选项，如超时。打开`nginx`配置文件，编辑以下配置选项，并将其值设置为以下值：

```php
keepalive_requests 100
keepalive_timeout 100
```

`keepalive_requests`配置定义了单个客户端在单个 HTTP keep-alive 连接上可以发出的最大请求数。

`keepalive_timeout`配置是服务器需要等待下一个请求的秒数，直到关闭 keep-alive 连接。

## GZIP 压缩

内容压缩提供了一种减少 HTTP 服务器传送的内容大小的方法。Apache 和 NGINX 都支持 GZIP 压缩，同样，大多数现代浏览器都支持 GZIP。启用 GZIP 压缩后，HTTP 服务器会发送压缩的 HTML、CSS、JavaScript 和大小较小的图像。这样，内容加载速度很快。

当浏览器发送有关自身支持 GZIP 压缩的信息时，Web 服务器才会通过 GZIP 压缩内容。通常，浏览器在*Request*标头中发送此类信息。

以下是启用 GZIP 压缩的 Apache 和 NGINX 代码。

### Apache

以下代码可以放置在`.htaccess`文件中：

```php
<IfModule mod_deflate.c>
SetOutputFilter DEFLATE
 #Add filters to different content types
AddOutputFilterByType DEFLATE text/html text/plain text/xml    text/css text/javascript application/javascript
    #Don't compress images
    SetEnvIfNoCase Request_URI \.(?:gif|jpe?g|png)$ no-gzip dont-   
    vary
</IfModule>
```

在上述代码中，我们使用了 Apache 的`deflate`模块来启用压缩。我们按类型进行过滤，只压缩特定类型的文件，如`.html`，纯文本，`.xml`，`.css`和`.js`。此外，在结束模块之前，我们设置了一个条件，不压缩图像，因为压缩图像会导致图像质量下降。

### NGINX

如前所述，您必须将以下代码放置在 NGINX 的虚拟主机配置文件中：

```php
gzip on;
gzip_vary on;
gzip_types text/plain text/xml text/css text/javascript application/x-javascript;
gzip_com_level 4;
```

在上述代码中，通过`gzip on;`行激活了 GZIP 压缩。`gzip_vary on;`行用于启用不同的标头。`gzip_types`行用于定义要压缩的文件类型。根据要求可以添加任何文件类型。`gzip_com_level 4;`行用于设置压缩级别，但要小心这个值；不要设置得太高。它的范围是 1 到 9，所以保持在中间。

现在，让我们检查压缩是否真的有效。在下面的截图中，请求发送到一个未启用 GZIP 压缩的服务器。下载或传输的最终 HTML 页面的大小为 59 KB：

![NGINX](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php7-hiperf/img/B05225_03_02.jpg)

在启用 Web 服务器上的 GZIP 压缩后，传输的 HTML 页面的大小减小了 9.95 KB，如下截图所示：

![NGINX](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php7-hiperf/img/B05225_03_03.jpg)

此外，还可以注意到加载内容的时间也减少了。因此，您的内容越小，页面加载速度就越快。

## 将 PHP 用作独立服务

Apache 使用`mod_php`模块来处理 PHP。这样，PHP 解释器集成到 Apache 中，所有处理都由这个 Apache 模块完成，这会消耗更多的服务器硬件资源。可以使用 PHP-FPM 与 Apache 一起使用，它使用 FastCGI 协议并在单独的进程中运行。这使得 Apache 可以处理 HTTP 请求处理，而 PHP 处理由 PHP-FPM 完成。

另一方面，NGINX 不提供任何内置支持或模块支持 PHP 处理。因此，在 NGINX 中，PHP 始终用作独立服务。

现在，让我们看看当 PHP 作为独立服务运行时会发生什么：Web 服务器不知道如何处理动态内容请求，并将请求转发到另一个外部服务，从而减少了 Web 服务器的处理负载。

## 禁用未使用的模块

Apache 和 NGINX 都内置了许多模块。在大多数情况下，您不需要其中一些模块。最好的做法是禁用这些模块。

最好的做法是制作一个启用的模块列表，逐个禁用这些模块，并重新启动服务器。之后，检查您的应用程序是否工作。如果工作正常，继续；否则，在应用程序再次停止正常工作之后，启用模块。

这是因为您可能会发现某个模块可能不需要，但其他一些有用的模块依赖于这个模块。因此，最好的做法是制作一个列表，启用或禁用模块，如前所述。

### Apache

要列出为 Apache 加载的所有模块，请在终端中发出以下命令：

```php
**sudo apachectl –M**

```

这个命令将列出所有加载的模块，如下截图所示：

![Apache](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php7-hiperf/img/B05225_03_04.jpg)

现在，分析所有加载的模块，检查它们是否对应用程序有用，并禁用它们，如下所示。

打开 Apache 配置文件，找到加载所有模块的部分。这里包括一个示例：

```php
LoadModule access_compat_module modules/mod_access_compat.so
LoadModule actions_module modules/mod_actions.so
LoadModule alias_module modules/mod_alias.so
LoadModule allowmethods_module modules/mod_allowmethods.so
LoadModule asis_module modules/mod_asis.so
LoadModule auth_basic_module modules/mod_auth_basic.so
#LoadModule auth_digest_module modules/mod_auth_digest.so
#LoadModule auth_form_module modules/mod_auth_form.so
#LoadModule authn_anon_module modules/mod_authn_anon.so
```

在前面加上`#`符号的模块是未加载的。因此，要在完整列表中禁用模块，只需放置一个`#`符号。`#`符号将注释掉该行，模块将不再加载。

### NGINX

要检查 NGINX 编译时使用了哪些模块，请在终端中发出以下命令：

```php
**sudo Nginx –V**

```

这将列出 NGINX 安装的完整信息，包括版本和 NGINX 编译时使用的模块。请查看以下截图：

![NGINX](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php7-hiperf/img/B05225_03_05.jpg)

通常情况下，NGINX 只启用了 NGINX 工作所需的模块。要启用已安装的任何其他模块，我们可以在`nginx.conf`文件中为其添加一些配置，但是没有单一的方法来禁用任何 NGINX 模块。因此，最好搜索特定模块，并查看 NGINX 网站上的模块页面。在那里，我们可以找到有关特定模块的信息，如果可用，我们可以找到有关如何禁用和配置该模块的信息。

## Web 服务器资源

每个 Web 服务器都有自己的通用最佳设置。但是，这些设置可能不适用于您当前的服务器硬件。Web 服务器硬件上最大的问题是 RAM。服务器的 RAM 越多，Web 服务器就能处理的请求就越多。

### NGINX

NGINX 提供了两个变量来调整资源，即`worker_processes`和`worker_connections`。`worker_processes`设置决定了应该运行多少个 NGINX 进程。

现在，我们应该使用多少`worker_processes`资源？这取决于服务器。通常情况下，每个处理器核心使用一个工作进程。因此，如果您的服务器处理器有四个核心，这个值可以设置为 4。

`worker_connections`的值显示每秒每个`worker_processes`设置的连接数。简单地说，`worker_connections`告诉 NGINX 可以处理多少个同时请求。`worker_connections`的值取决于系统处理器核心。要找出 Linux 系统（Debian/Ubuntu）上核心的限制，请在终端中发出以下命令：

```php
**Ulimit –n**

```

这个命令将显示一个应该用于`worker_connections`的数字。

现在，假设我们的处理器有四个核心，每个核心的限制是 512。然后，我们可以在 NGINX 主配置文件中设置这两个变量的值。在 Debian/Ubuntu 上，它位于`/etc/nginx/nginx.conf`。

现在，找出这两个变量并设置如下：

```php
Worker_processes 4;
Worker_connections 512
```

前面的值可能会很高，特别是`worker_connections`，因为服务器处理器核心有很高的限制。

# 内容交付网络（CDN）

内容交付网络用于托管静态媒体文件，如图像、`.css`和`.js`文件，以及音频和视频文件。这些文件存储在地理网络上，其服务器位于不同的位置。然后，这些文件根据请求位置从特定服务器提供给请求。

CDN 提供以下功能：

+   由于内容是静态的，不经常更改，CDN 会将它们缓存在内存中。当对某个文件发出请求时，CDN 会直接从缓存中发送文件，这比从磁盘加载文件并发送到浏览器要快。

+   CDN 服务器位于不同的位置。所有文件都存储在每个位置，取决于您在 CDN 中的设置。当浏览器请求到达 CDN 时，CDN 会从最近可用的位置发送请求的内容到请求的位置。例如，如果 CDN 在伦敦、纽约和迪拜都有服务器，并且来自中东的请求到达时，CDN 将从迪拜服务器发送内容。这样，由于 CDN 从最近的位置提供内容，响应时间得到了缩短。

+   每个浏览器对向同一域发送并行请求有限制。通常是三个请求。当对请求的响应到达时，浏览器会向同一域发送更多的请求，这会导致完整页面加载的延迟。CDN 提供子域（可以是它们自己的子域或您主域的子域，使用您主域的 DNS 设置），这使得浏览器可以向从不同域加载的相同内容发送更多的并行请求。这使得浏览器可以快速加载页面内容。

+   通常，动态内容的请求量很小，静态内容的请求量更多。如果您的应用的静态内容托管在单独的 CDN 服务器上，这将极大地减轻服务器的负载。

## 使用 CDN

那么，您如何在应用中使用 CDN 呢？在最佳实践中，如果您的应用流量很大，为每种内容类型在 CDN 上创建不同的子域是最好的选择。例如，为 CSS 和 JavaScript 文件创建一个单独的域，为图像创建一个子域，为音频/视频文件创建另一个单独的子域。这样，浏览器将为每种内容类型发送并行请求。假设我们对每种内容类型有以下 URL：

+   **对于 CSS 和 JavaScript**：`http://css-js.yourcdn.com`

+   **对于图像**：`http://images.yourcdn.com`

+   **对于其他媒体**：`http://media.yourcdn.com`

现在，大多数开源应用程序在其管理控制面板中提供设置以设置 CDN URL，但如果您使用的是开源框架或自定义构建的应用程序，您可以通过将上述 URL 放在数据库中或全局加载的配置文件中来定义自己的 CDN 设置。

对于我们的示例，我们将把上述 URL 放在一个配置文件中，并为它们创建三个常量，如下所示：

```php
Constant('CSS_JS_URL', 'http://css-js.yourcdn.com/');
Constant('IMAGES_URL', 'http://images.yourcdn.com/');
Constant('MEDiA_URL', 'http://css-js.yourcdn.com/');
```

如果我们需要加载 CSS 文件，可以按以下方式加载：

```php
<script type="text/javascript" src="<?php echo CSS_JS_URL ?>js/file.js"></script>
```

对于 JavaScript 文件，可以按以下方式加载：

```php
<link rel="stylesheet" type="text/css" href="<?php echo CSS_JS_URL ?>css/file.css" />
```

如果我们加载图像，可以在`img`标签的`src`属性中使用上述方式，如下所示：

```php
<img src="<?php echo IMAGES_URL ?>images/image.png" />
```

在上述示例中，如果我们不需要使用 CDN 或想要更改 CDN URL，只需在一个地方进行更改即可。

大多数知名的 JavaScript 库和模板引擎都在其自己的个人 CDN 上托管其静态资源。谷歌在其自己的 CDN 上托管查询库、字体和其他 JavaScript 库，可以直接在应用程序中使用。

有时，我们可能不想使用 CDN 或负担不起它们。为此，我们可以使用一种称为域共享的技术。使用域分片，我们可以创建子域或将其他域指向我们在同一服务器和应用程序上的资源目录。这种技术与之前讨论的相同；唯一的区别是我们自己将其他域或子域指向我们的媒体、CSS、JavaScript 和图像目录。

这可能看起来不错，但它不会为我们提供 CDN 的最佳性能。这是因为 CDN 根据客户的位置决定内容的地理可用性，进行广泛的缓存，并在运行时对文件进行优化。

# CSS 和 JavaScript 优化

每个网络应用程序都有 CSS 和 JavaScript 文件。如今，大多数应用程序都有大量的 CSS 和 JavaScript 文件，以使应用程序具有吸引力和互动性。每个 CSS 和 JavaScript 文件都需要浏览器向服务器发送请求来获取文件。因此，你拥有的 CSS 和 JavaScript 文件越多，浏览器就需要发送的请求就越多，从而影响其性能。

每个文件都有一个内容大小，浏览器下载它需要时间。例如，如果我们有 10 个每个 10KB 的 CSS 文件和 10 个每个 50KB 的 JavaScript 文件，CSS 文件的总内容大小为 100KB，JavaScript 文件的总内容大小为 500KB，两种类型的文件总共为 600KB。这太多了，浏览器会花费时间来下载它们。

### 注意

性能在网络应用程序中扮演着至关重要的角色。即使是 Google 在其索引中也计算性能。不要认为一个文件只有几 KB 并且需要 1 毫秒下载，因为在性能方面，每一毫秒都是被计算的。最好的方法是优化、压缩和缓存一切。

在这一部分，我们将讨论两种优化我们的 CSS 和 JS 的方法，如下所示：

+   合并

+   压缩

## 合并

在合并过程中，我们可以将所有的 CSS 文件合并成一个文件，JavaScript 文件也是同样的过程，从而创建一个 CSS 和 JavaScript 的单一文件。如果我们有 10 个 CSS 文件，浏览器会发送 10 个请求来获取所有这些文件。然而，如果我们将它们合并成一个文件，浏览器只会发送一个请求，因此节省了九个请求所花费的时间。

## 压缩

在压缩过程中，CSS 和 JavaScript 文件中的所有空行、注释和额外的空格都被移除。这样，文件的大小就减小了，文件加载速度就快了。

例如，假设你在一个文件中有以下 CSS 代码：

```php
.header {
  width: 1000px;
  height: auto;
  padding: 10px
}

/* move container to left */
.float-left {
  float: left;
}

/* Move container to right */
.float-right {
  float: right;
}
```

压缩文件后，我们将得到类似以下的 CSS 代码：

```php
.header{width:100px;height:auto;padding:10px}.float-left{float:left}.float-right{float:right}
```

同样地，对于 JavaScript，假设我们在一个 JavaScript 文件中有以下代码：

```php
/* Alert on page load */
$(document).ready(function() {
  alert("Page is loaded");
});

/* add three numbers */
function addNumbers(a, b, c) {
  return a + b + c;
}
```

现在，如果前述文件被压缩，我们将得到以下代码：

```php
$(document).ready(function(){alert("Page is loaded")});function addNumbers(a,b,c){return a+b+c;}
```

可以注意到在前面的例子中，所有不必要的空格和换行都被移除了。它还将完整的文件代码放在一行中。所有的代码注释都被移除了。这样，文件大小就减小了，有助于文件快速加载。此外，这个文件将消耗更少的带宽，如果服务器资源有限的话，这是有用的。

大多数开源应用程序，如 Magento、Drupal 和 WordPress，提供内置支持或支持第三方插件/模块的应用程序。在这里，我们不会涵盖如何在这些应用程序中合并 CSS 或 JavaScript 文件，但我们将讨论一些可以合并 CSS 和 JavaScript 文件的工具。

### Minify

Minify 是一组完全用 PHP 编写的库。Minify 支持 CSS 和 JavaScript 文件的合并和压缩。它的代码完全是面向对象和命名空间的，因此可以嵌入到任何当前的或专有的框架中。

### 注意

Minify 主页位于[`minifier.org`](http://minifier.org)。它也托管在 GitHub 上，网址为[`github.com/matthiasmullie/minify`](https://github.com/matthiasmullie/minify)。值得注意的是，Minify 库使用了一个路径转换库，这个库是由同一作者编写的。路径转换库可以从[`github.com/matthiasmullie/path-converter`](https://github.com/matthiasmullie/path-converter)下载。下载这个库并将其放在与 minify 库相同的文件夹中。

现在，让我们创建一个小项目，用来缩小和合并 CSS 和 JavaScript 文件。项目的文件夹结构将如下截图所示：

![Minify](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php7-hiperf/img/B05225_03_06.jpg)

在上面的截图中，显示了完整的项目结构。项目名称是`minify`。`css`文件夹中包含了所有的 CSS 文件，包括缩小或合并的文件。同样，`js`文件夹中包含了所有的 JavaScript 文件，包括缩小或合并的文件。`libs`文件夹中包含了`Minify`库和`Converter`库。`Index.php`包含了我们用来缩小和合并 CSS 和 JavaScript 文件的主要代码。

### 注意

项目树中的`data`文件夹与 JavaScript 缩小有关。由于 JavaScript 有需要在其前后加上空格的关键字，这些`.txt`文件用于识别这些运算符。

因此，让我们从`index.php`中使用以下代码来缩小我们的 CSS 和 JavaScript 文件：

```php
include('libs/Converter.php');
include('libs/Minify.php');
include('libs/CSS.php');
include('libs/JS.php');
include('libs/Exception.php');

use MatthiasMullie\Minify;

/* Minify CSS */
$cssSourcePath = 'css/styles.css';
$cssOutputPath = 'css/styles.min.css';
$cssMinifier = new Minify\CSS($cssSourcePath);
$cssMinifier->minify($cssOutputPath);

/* Minify JS */
$jsSourcePath = 'js/app.js';
$jsOutputPath = 'js/app.min.js';
$jsMinifier = new Minify\JS($jsSourcePath);
$jsMinifier->minify($jsOutputPath);
```

前面的代码很简单。首先，我们包含了所有需要的库。然后，在`Minify CSS`块中，我们创建了两个路径变量：`$cssSourcePath`，它包含了我们需要缩小的 CSS 文件的路径，以及`$cssOutputPath`，它包含了将要生成的缩小 CSS 文件的路径。

之后，我们实例化了`CSS.php`类的一个对象，并传递了我们需要缩小的 CSS 文件。最后，我们调用了`CSS`类的缩小方法，并传递了输出路径以及文件名，这将为我们生成所需的文件。

JS 缩小过程也是同样的解释。

如果我们运行上述 PHP 代码，所有文件都就位，一切顺利，那么将会创建两个新的文件名：`styles.min.css`和`app.min.js`。这些是它们原始文件的新缩小版本。

现在，让我们使用 Minify 来合并多个 CSS 和 JavaScript 文件。首先，在项目中的相应文件夹中添加一些 CSS 和 JavaScript 文件。之后，我们只需要在当前代码中添加一点代码。在下面的代码中，我将跳过包含所有库，但是每当您需要使用 Minify 时，这些文件都必须被加载。

```php
/* Minify CSS */
$cssSourcePath = 'css/styles.css';
**$cssOutputPath = 'css/styles.min.merged.css';**
$cssMinifier = new Minify\CSS($cssSourcePath);
**$cssMinifier->add('css/style.css');**
**$cssMinifier->add('css/forms.js');**
$cssMinifier->minify($cssOutputPath);

/* Minify JS */
$jsSourcePath = 'js/app.js';
**$jsOutputPath = 'js/app.min.merged.js';**
$jsMinifier = new Minify\JS($jsSourcePath);
**$jsMinifier->add('js/checkout.js');**
$jsMinifier->minify($jsOutputPath);
```

现在，看一下高亮显示的代码。在 CSS 部分，我们将缩小和合并的文件保存为`style.min.merged.css`，但命名并不重要；这完全取决于我们自己的选择。

现在，我们只需使用`$cssMinifier`和`$jsMinifier`对象的`add`方法来添加新文件，然后调用`minify`。这将导致所有附加文件合并到初始文件中，然后进行缩小，从而生成单个合并和缩小的文件。

### Grunt

根据其官方网站，Grunt 是一个 JavaScript 任务运行器。它自动化了某些重复的任务，这样你就不必重复工作。这是一个很棒的工具，在 Web 程序员中被广泛使用。

安装 Grunt 非常容易。在这里，我们将在 MAC OS X 上安装它，大多数 Linux 系统，如 Debian 和 Ubuntu，使用相同的方法。

### 注意

Grunt 需要 Node.js 和 npm。安装和配置 Node.js 和 npm 超出了本书的范围，因此在本书中，我们将假设这些工具已经安装在您的计算机上，或者您可以搜索它们并弄清楚如何安装它们。

如果 Node.js 和 npm 已经安装在您的计算机上，只需在终端中输入以下命令：

```php
**sudo npm install –g grunt**

```

这将安装 Grunt CLI。如果一切顺利，那么以下命令将显示 Grunt CLI 的版本：

```php
**grunt –version**

```

上述命令的输出是`grunt-cli v0.1.13;`，在撰写本书时，这个版本是可用的。

Grunt 为您提供了一个命令行，可以让您运行 Grunt 命令。一个 Grunt 项目在您的项目文件树中需要两个文件。一个是`package.json`，它被`npm`使用，并列出了项目需要的 Grunt 和 Grunt 插件作为 DevDependencies。

第二个文件是`GruntFile`，它存储为`GruntFile.js`或`GruntFile.coffee`，用于配置和定义 Grunt 任务并加载 Grunt 插件。

现在，我们将使用相同的项目，但我们的文件夹结构将如下所示：

![Grunt](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php7-hiperf/img/B05225_03_07.jpg)

现在，在项目根目录中打开终端并发出以下命令：

```php
**sudo npm init**

```

这将通过询问一些问题生成`package.json`文件。现在，打开`package.json`文件并修改它，使最终的`package.json`文件的内容看起来类似于以下内容：

```php
{
  "name" : "grunt"  //Name of the project
  "version : "1.0.0" //Version of the project
  "description" : "Minify and Merge JS and CSS file",
  "main" : "index.js",
  "DevDependencies" : {
    "grunt" : "0.4.1", //Version of Grunt

    //Concat plugin version used to merge css and js files
    "grunt-contrib-concat" : "0.1.3"

    //CSS minifying plugin
    "grunt-contrib-cssmin" : "0.6.1",

    //Uglify plugin used to minify JS files.
    "grunt-contrib-uglify" : "0.2.0" 

   },
"author" : "Altaf Hussain",
"license" : ""
}
```

我在`package.json`文件的不同部分添加了注释，以便易于理解。请注意，对于最终文件，我们将从该文件中删除注释。

可以看到，在`DevDependencies`部分，我们添加了用于不同任务的三个 Grunt 插件。

下一步是添加`GruntFile`。让我们在项目根目录创建一个名为`GruntFile.js`的文件，内容类似于`package.json`文件。将以下内容放入`GruntFile`：

```php
module.exports = function(grunt) {
   /*Load the package.json file*/
   pkg: grunt.file.readJSON('package.json'),
  /*Define Tasks*/
  grunt.initConfig({
    concat: {
      css: {
        src: [
        'css/*' //Load all files in CSS folder
],
         dest: 'dest/combined.css' //Destination of the final combined file.

      }, //End of CSS
js: {
      src: [
     'js/*' //Load all files in js folder
],
      dest: 'dest/combined.js' //Destination of the final combined file.

    }, //End of js

}, //End of concat
cssmin:  {
  css: {
    src : 'dest/combined.css',
    dest : 'dest/combined.min.css' 
}
},//End of cssmin
uglify: {
  js: {
    files: {
      'dest/combined.min.js' : ['dest/combined.js'] // destination Path : [src path]
    }
  }
} //End of uglify

}); //End of initConfig

grunt.loadNpmTasks('grunt-contrib-concat');
grunt.loadNpmTasks('grunt-contrib-uglify');
grunt.loadNpmTasks('grunt-contrib-cssmin');
grunt.registerTask('default', ['concat:css', 'concat:js', 'cssmin:css', 'uglify:js']);

}; //End of module.exports
```

前面的代码简单易懂，需要时添加注释。在顶部，我们加载了我们的`package.json`文件，之后，我们定义了不同的任务以及它们的源文件和目标文件。请记住，每个任务的源文件和目标文件语法都不同，这取决于插件。在`initConfig`块之后，我们加载了不同的插件和 npm 任务，然后将它们注册到 GRUNT 上。

现在，让我们运行我们的任务。

首先，让我们合并 CSS 和 JavaScript 文件，并将它们存储在 GruntFile 中任务列表中定义的各自目标中，通过以下命令：

```php
**grunt concat**

```

在您的终端中运行上述命令后，如果看到`完成，无错误`的消息，则任务已成功完成。

同样，让我们使用以下命令来压缩我们的 css 文件：

```php
**grunt cssmin**

```

然后，我们将使用以下命令来压缩我们的 JavaScript 文件：

```php
**grunt uglify**

```

现在，使用 Grunt 可能看起来需要很多工作，但它提供了一些其他功能，可以让开发人员的生活变得更轻松。例如，如果您需要更改 JavaScript 和 CSS 文件怎么办？您应该再次运行所有前面的命令吗？不，Grunt 提供了一个 watch 插件，它会激活并执行任务中目标路径中的所有文件，如果发生任何更改，它会自动运行任务。

要了解更多详细信息，请查看 Grunt 的官方网站[`gruntjs.com/`](http://gruntjs.com/)。

# 完整页面缓存

在完整页面缓存中，网站的完整页面存储在缓存中，对于下一个请求，将提供此缓存页面。如果您的网站内容不经常更改，则完整页面缓存更有效；例如，在一个简单的博客上，每周添加新帖子。在这种情况下，可以在添加新帖子后清除缓存。

如果您有一个网站，其中页面具有动态部分，例如电子商务网站怎么办？在这种情况下，完整页面缓存会带来问题，因为每个请求的页面总是不同；用户登录后，他/她可能会向购物车中添加产品等。在这种情况下，使用完整页面缓存可能并不容易。

大多数流行的平台都提供对完整页面缓存的内置支持或通过插件和模块。在这种情况下，插件或模块会为每个请求处理页面的动态块。

# Varnish

如官方网站所述，Varnish 可以让您的网站飞起来；这是真的！Varnish 是一个开源的 Web 应用程序加速器，运行在您的 Web 服务器软件的前面。它必须配置在端口 80 上，以便每个请求都会经过它。

现在，Varnish 配置文件（称为带有`.vcl`扩展名的 VCL 文件）有一个后端的定义。后端是配置在另一个端口（比如说 8080）上的 Web 服务器（Apache 或 NGINX）。可以定义多个后端，并且 Varnish 也会负责负载均衡。

当请求到达 Varnish 时，它会检查该请求的数据是否在其缓存中可用。如果它在缓存中找到数据，则将缓存的数据返回给请求，不会发送请求到 Web 服务器或后端。如果 Varnish 在其缓存中找不到任何数据，则会向 Web 服务器发送请求并请求数据。当它从 Web 服务器接收数据时，首先会缓存这些数据，然后将其发送回请求。

正如前面的讨论所清楚的那样，如果 Varnish 在缓存中找到数据，就不需要向 Web 服务器发送请求，因此也不需要在那里进行处理，响应会非常快速地返回。

Varnish 还提供了负载平衡和健康检查等功能。此外，Varnish 不支持 SSL 和 cookies。如果 Varnish 从 Web 服务器或后端接收到 cookies，则不会缓存该页面。有不同的方法可以轻松解决这些问题。

我们已经讲了足够的理论；现在，让我们通过以下步骤在 Debian/Ubuntu 服务器上安装 Varnish：

1.  首先将 Varnish 存储库添加到`sources.list`文件中。在文件中加入以下行：

```php
    deb https://repo.varnish-cache.org/debian/ Jessie varnish-4.1
```

1.  之后，输入以下命令以更新存储库：

```php
**sudo apt-get update**

```

1.  现在，输入以下命令：

```php
**sudo apt-get install varnish**

```

1.  这将下载并安装 Varnish。现在，首先要做的是配置 Varnish 以侦听端口 80，并使您的 Web 服务器侦听另一个端口，例如 8080。我们将在这里使用 NGINX 进行配置。

1.  现在，打开 Varnish 配置文件位置`/etc/default/varnish`，并进行更改，使其看起来类似于以下代码：

```php
    DAEMON_OPS="-a :80 \
      -T localhost:6082 \ 
      -f /etc/varnish/default.vcl \
      -S /etc/varnish/secret \
      -s malloc,256m"
```

1.  保存文件并在终端中输入以下命令重新启动 Varnish：

```php
**sudo service varnish restart**

```

1.  现在我们的 Varnish 在端口`80`上运行。让 NGINX 在端口`8080`上运行。编辑应用程序的 NGINX `vhost`文件，并将侦听端口从`80`更改为`8080`，如下所示：

```php
    listen 8080;
```

1.  现在，在终端中输入以下命令重新启动 NGINX：

```php
**sudo service nginx restart**

```

1.  下一步是配置 Varnish VCL 文件并添加一个将与我们的后端通信的后端，端口为`8080`。编辑位于`/etc/varnish/default.vcl`的 Varnish VCL 文件，如下所示：

```php
    backend default {
      .host = "127.0.0.1";
      .port = "8080";
    }
```

在上述配置中，我们的后端主机位于 Varnish 运行的同一台服务器上，因此我们输入了本地 IP。在这种情况下，我们也可以输入 localhost。但是，如果我们的后端在远程主机或另一台服务器上运行，则应输入该服务器的 IP。

现在，我们已经完成了 Varnish 和 Web 服务器的配置。重新启动 Varnish 和 NGINX。打开浏览器，输入服务器的 IP 或主机名。初始响应可能会很慢，因为 Varnish 正在从后端获取数据，然后对其进行缓存，但其他后续响应将非常快，因为 Varnish 已经对其进行了缓存，并且现在正在发送缓存的数据而不与后端通信。

Varnish 提供了一个工具，我们可以轻松监视 Varnish 缓存状态。这是一个实时工具，会实时更新其内容。它被称为 varnishstat。要启动 varnishstat，只需在终端中输入以下命令：

```php
**varnishstat**

```

上述命令将显示类似于以下截图的会话：

![Varnish](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php7-hiperf/img/B05225_03_08.jpg)

如前面的截图所示，它显示非常有用的信息，例如运行时间和开始时的请求数，缓存命中，缓存未命中，所有后端，后端重用等。我们可以使用这些信息来调整 Varnish 以获得最佳性能。

### 注意

Varnish 的完整配置超出了本书的范围，但可以在 Varnish 官方网站[`www.varnish-cache.org`](https://www.varnish-cache.org)找到很好的文档。

# 基础设施

我们讨论了太多关于提高应用性能的话题。现在，让我们讨论一下我们应用的可扩展性和可用性。随着时间的推移，我们应用的流量可能会增加到同时使用数千名用户。如果我们的应用在单个服务器上运行，性能将受到严重影响。此外，将应用保持在单一点上并不是一个好主意，因为如果该服务器宕机，我们的整个应用将会宕机。

为了使我们的应用程序更具可扩展性和可用性，我们可以使用基础架构设置，在其中我们可以在多个服务器上托管我们的应用程序。此外，我们可以将应用程序的不同部分托管在不同的服务器上。为了更好地理解，看一下以下图表：

![基础设施](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php7-hiperf/img/B05225_03_09.jpg)

这是基础设施的一个非常基本的设计。让我们谈谈它的不同部分以及每个部分和服务器将执行的操作。

### 注意

可能只有负载均衡器（LB）连接到公共互联网，其余部分可以通过机架内的私有网络相互连接。如果有一个机架可用，这将非常好，因为所有服务器之间的通信都将在私有网络上进行，因此是安全的。

## Web 服务器

在上图中，我们有两个 Web 服务器。可以有任意数量的 Web 服务器，并且它们可以轻松连接到 LB。Web 服务器将托管我们的实际应用程序，并且应用程序将在 NGINX 或 Apache 和 PHP 7 上运行。我们将在本章讨论的所有性能调整都可以在这些 Web 服务器上使用。此外，并不一定要求这些服务器应该在端口 80 上监听。最好是我们的 Web 服务器应该在另一个端口上监听，以避免使用浏览器进行任何公共访问。

## 数据库服务器

数据库服务器主要用于安装 MySQL 或 Percona Server 的数据库。然而，基础架构设置中的一个问题是将会话数据存储在一个地方。为此，我们还可以在数据库服务器上安装 Redis 服务器，它将处理我们应用的会话数据。

上述基础设施设计并不是最终或完美的设计。它只是为了给出多服务器应用托管的想法。它有很多改进的空间，比如添加另一个本地负载均衡器、更多的 Web 服务器和数据库集群的服务器。

## 负载均衡器（LB）

第一部分是**负载均衡器**（**LB**）。负载均衡器的目的是根据每个 Web 服务器上的负载将流量分配给 Web 服务器。

对于负载均衡器，我们可以使用广泛用于此目的的 HAProxy。此外，HAProxy 会检查每个 Web 服务器的健康状况，如果一个 Web 服务器宕机，它会自动将该宕机的 Web 服务器的流量重定向到其他可用的 Web 服务器。为此，只有 LB 将在端口 80 上监听。

我们不希望在可用的 Web 服务器上（在我们的情况下，有两个 Web 服务器）上加重 SSL 通信的加密和解密负载，因此我们将使用 HAProxy 服务器在那里终止 SSL。当我们的负载均衡器接收到带有 SSL 的请求时，它将终止 SSL 并将普通请求发送到其中一个 Web 服务器。当它收到响应时，HAProxy 将加密响应并将其发送回客户端。这样，与使用两个服务器进行 SSL 加密/解密相比，只需使用一个单独的负载均衡器服务器来实现此目的。

### 注意

Varnish 也可以用作负载均衡器，但这并不是一个好主意，因为 Varnish 的整个目的是 HTTP 缓存。

## HAProxy 负载均衡

在上述基础设施中，我们在 Web 服务器前放置了一个负载均衡器，它会平衡每个服务器上的负载，检查每个服务器的健康状况，并终止 SSL。我们将安装 HAProxy 并配置它以实现之前提到的所有配置。

### HAProxy 安装

我们将在 Debian/Ubuntu 上安装 HAProxy。在撰写本书时，HAProxy 1.6 是最新的稳定版本。执行以下步骤安装 HAProxy：

1.  首先，在终端中发出以下命令更新系统缓存：

```php
**sudo apt-get update**

```

1.  接下来，在终端中输入以下命令安装 HAProxy：

```php
**sudo apt-get install haproxy**

```

这将在系统上安装 HAProxy。

1.  现在，在终端中发出以下命令确认 HAProxy 安装：

```php
**haproxy -v**

```

![HAProxy 安装](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php7-hiperf/img/B05225_03_10.jpg)

如果输出与上述截图相同，则恭喜！HAProxy 已成功安装。

### HAProxy 负载均衡

现在是使用 HAProxy 的时候了。为此，我们有以下三个服务器：

+   第一个是负载均衡器服务器，安装了 HAProxy。我们将其称为 LB。对于本书的目的，LB 服务器的 IP 是 10.211.55.1。此服务器将在端口 80 上进行监听，并且所有 HTTP 请求将发送到此服务器。此服务器还充当前端服务器，因为我们的应用的所有请求都将发送到此服务器。

+   第二个是 Web 服务器，我们将其称为 Web1。NGINX、PHP 7、MySQL 或 Percona Server 都安装在上面。此服务器的 IP 是 10.211.55.2。此服务器将在端口 80 或任何其他端口上进行监听。我们将其保持在端口 8080 上进行监听。

+   第三个是第二个 Web 服务器，我们将其称为 Web2，IP 为 10.211.55.3。这与 Web1 服务器的设置相同，并将在端口 8080 上进行监听。

Web1 和 Web2 服务器也称为后端服务器。首先，让我们配置 LB 或前端服务器在端口 80 上进行监听。

打开位于`/etc/haproxy/`的`haproxy.cfg`文件，并在文件末尾添加以下行：

```php
frontend http
  bind *:80
  mode http
  default_backend web-backends
```

在上述代码中，我们将 HAProxy 设置为在任何 IP 地址（本地回环 IP 127.0.0.1 或公共 IP）上监听 HTTP 端口 80。然后，我们设置默认的后端。

现在，我们将添加两个后端服务器。在同一文件中，在末尾放置以下代码：

```php
backend web-backend 
  mode http
  balance roundrobin
  option forwardfor
  server web1 10.211.55.2:8080 check
  server web2 10.211.55.3:8080 check
```

在上述配置中，我们将两个服务器添加到 Web 后端。后端的引用名称是`web-backend`，在前端配置中也使用了它。我们知道，我们的两个 Web 服务器都在端口 8080 上进行监听，因此我们提到这是每个 Web 服务器的定义。此外，我们在每个 Web 服务器的定义末尾使用了`check`，告诉 HAProxy 检查服务器的健康状况。

现在，在终端中发出以下命令重新启动 HAProxy：

```php
**sudo service haproxy restart**

```

### 注意

要启动 HAProxy，可以使用`sudo service haproxy start`命令。要停止 HAProxy，可以使用`sudo service haproxy stop`命令。

现在，在浏览器中输入 LB 服务器的 IP 或主机名，我们的 Web 应用页面将显示为来自 Web1 或 Web2。

现在，禁用任何一个 Web 服务器，然后再次重新加载页面。应用程序仍将正常工作，因为 HAProxy 自动检测到其中一个 Web 服务器已关闭，并将流量重定向到第二个 Web 服务器。

HAProxy 还提供了一个基于浏览器的统计页面。它提供有关 LB 和所有后端的完整监控信息。要启用统计信息，打开`haprox.cfg`，并在文件末尾放置以下代码：

```php
listen stats *:1434
  stats enable
  stats uri /haproxy-stats
  stats auth phpuser:packtPassword
```

统计信息在端口`1434`上启用，可以设置为任何端口。页面的 URL 是`stats uri`。它可以设置为任何 URL。`auth`部分用于基本的 HTTP 身份验证。保存文件并重新启动 HAProxy。现在，打开浏览器，输入 URL，例如`10.211.55.1:1434/haproxy-stats`。统计页面将显示如下：

![HAProxy 负载均衡](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php7-hiperf/img/B05225_03_11.jpg)

在上述截图中，可以看到每个后端 Web 服务器，包括前端信息。

此外，如果一个 Web 服务器宕机，HAProxy 统计信息将突出显示此 Web 服务器的行，如下截图所示：

![HAProxy 负载均衡](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php7-hiperf/img/B05225_03_12.jpg)

对于我们的测试，我们停止了 Web2 服务器上的 NGINX，并刷新了统计页面，然后在后端部分中，Web2 服务器行被突出显示。

要使用 HAProxy 终止 SSL，非常简单。我们只需在 SSL 端口 443 绑定上添加 SSL 证书文件位置。打开`haproxy.cfg`文件，编辑前端块，并在其中添加高亮显示的代码，如下所示的块：

```php
frontend http 
bind *:80
**bind *:443 ssl crt /etc/ssl/www.domain.crt**
  mode http
  default_backend web-backends
```

现在，HAProxy 也在 443 端口监听，当 SSL 请求发送到它时，它在那里处理并终止它，以便不会将 HTTPS 请求发送到后端服务器。这样，SSL 加密/解密的负载就从 Web 服务器中移除，并由 HAProxy 服务器单独管理。由于 SSL 在 HAProxy 服务器上终止，因此无需让 Web 服务器在 443 端口监听，因为来自 HAProxy 服务器的常规请求会发送到后端。

# 总结

在本章中，我们讨论了从 NGINX 和 Apache 到 Varnish 等多个主题。我们讨论了如何优化我们的 Web 服务器软件设置以获得最佳性能。此外，我们还讨论了 CDN 以及如何在客户应用程序中使用它们。我们讨论了优化 JavaScript 和 CSS 文件以获得最佳性能的两种方法。我们简要讨论了完整页面缓存和 Varnish 的安装和配置。最后，我们讨论了多服务器托管或基础架构设置，以使我们的应用程序具有可伸缩性和最佳可用性。

在下一章中，我们将探讨如何提高数据库性能的方法。我们将讨论包括 Percona Server、数据库的不同存储引擎、查询缓存、Redis 和 Memcached 在内的多个主题。
