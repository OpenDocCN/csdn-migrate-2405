# Magento PHP 开发指南（一）

> 原文：[`zh.annas-archive.org/md5/f2e271327b273df27fc8bf4ef750d5c2`](https://zh.annas-archive.org/md5/f2e271327b273df27fc8bf4ef750d5c2)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

《Magento PHP 开发者指南》将帮助新手和有经验的开发者理解并使用 Magento 的基本概念和开发和测试代码的标准实践。

这本书是我试图撰写的一本指南，回答了许多开发者（包括我自己）在开始为 Magento 开发时所遇到的问题：EAV 是什么？Magento 中的 ORM 是如何工作的？观察者和事件是什么？使用了哪些设计模式来创建 Magento？

最重要的是，本书还回答了许多开发者至今仍然存在的问题：开发模块和扩展前端和后端的标准是什么？我如何正确测试我的代码？部署和分发自定义模块的最佳方法是什么？

# 本书涵盖的内容

第一章，“理解和设置我们的开发环境”，将帮助您设置一个完整的 Magento 开发环境，包括 MySQL 和 Apache。此外，我们将介绍可用于简化开发的工具，几种集成开发环境和版本控制系统。

第二章，“Magento 开发者基础”，将介绍 Magento 的基本概念，如系统架构、MVC 实现以及与 Zend Framework 的关系。本章中的所有概念将为刚开始使用 Magento 的开发者奠定基础。

第三章，“ORM 和数据集合”，涵盖了 Magento 中的集合和模型，这是日常 Magento 开发的基础。在本章中，我们将向读者介绍 Magento ORM 系统，并学习如何正确地处理数据集合和 EAV 系统。

第四章，“前端开发”，将解释我们迄今为止所学到的技能和知识的实际用途，并逐步构建一个完全功能的 Magento 模块。自定义模块将允许读者应用各种重要概念，如处理集合、路由、会话和缓存。

第五章，“后端开发”，将扩展我们在上一章中构建的内容，并在 Magento 后端创建一个与我们的应用数据交互的界面。我们将学习如何扩展后端、管理 HTML 主题、设置数据源，并通过配置控制我们的扩展行为。

第六章，“Magento API”，将解释 Magento API 以及我们如何扩展它，以提供对我们使用扩展捕获的自定义数据的访问。

第七章，“测试和质量保证”，将帮助读者学习测试 Magento 模块和自定义的关键技能，这是开发的一个重要部分。我们将了解不同类型的测试和每种特定类型测试的可用工具。

第八章，“部署和分发”，将帮助读者了解多种工具，用于将我们的代码部署到生产环境，并如何通过 Magento Connect 等渠道正确打包我们的扩展以进行分发。

附录，“你好，Magento”，将为新开发者提供一个快速易懂的介绍，以创建我们的第一个 Magento 扩展。

# 你需要为本书做好准备

你需要安装 Magento 1.7，可以是在本地机器上或远程服务器上，你喜欢的代码编辑器，以及安装和修改文件的权限。

# 本书适合谁

如果您是一名刚开始使用 Magento 的 PHP 开发人员，或者已经对 Magento 有一些经验，并希望了解 Magento 的架构以及如何扩展 Magento 的前端和后端，那么这本书适合您！

您应该对 PHP5 有信心。不需要有 Magento 开发经验，但您应该熟悉基本的 Magento 操作和概念。

# 约定

在本书中，您会发现一些文本样式，用于区分不同类型的信息。以下是一些样式的示例及其含义的解释。

文本中的代码单词显示如下："GitHub 现在包括一个专门为 Magento 设计的`.gitignore`文件，它将忽略 Magento 核心中的所有文件，只跟踪我们自己的代码。"

一段代码设置如下：

```php
{
    "id": "default",
    "host": "magento.localhost.com",
    "repo": [
        "url": "svn.magentocommerce.com/source/branches/1.7",
```

任何命令行输入或输出都是这样写的：

```php
$ vagrant box add lucid32 http://files.vagrantup.com/lucid32.box
$ vagrant init lucid32
$ vagrant up
```

**新术语**和**重要单词**以粗体显示。屏幕上看到的单词，比如菜单或对话框中的单词，会以这样的方式出现在文本中："您现在应该看到 Apache 的默认网页，上面显示着**It Works!**的消息"。

### 注意

警告或重要说明会出现在这样的框中。

### 提示

提示和技巧会出现在这样。


# 第一章：了解和设置我们的开发环境

在本章中，我们将介绍运行 Magento 所涉及的技术堆栈以及如何为开发设置一个合适的环境。本章将涵盖以下主题：

+   LAMP 虚拟机

+   设置和使用 VirtualBox

+   设置和使用 Vagrant

+   IDE 和版本控制系统

我们还将学习如何从头开始设置一个 LAMP 虚拟机，以及如何使用 Vagrant 和 Chef 完全自动化这个过程。

# 从头开始的 LAMP

**LAMP**（**Linux，Apache，MySQL 和 PHP**）是一种开源技术解决方案堆栈，用于构建 Web 服务器，也是运行 Magento 的当前标准。

有关更详细的要求清单，请访问[www.magentocommerce.com/system-requirements](http://www.magentocommerce.com/system-requirements)。

### 注意

尽管在撰写本书时，Nginx 在 Magento 开发人员中得到了更广泛的采用，但 Apache2 仍然是社区公认的标准。我们将专注于与它一起工作。

作为开发人员，我们面临着多个挑战和细微差别，如设置和维护我们的开发环境：

+   匹配您的开发和生产环境

+   在不同平台和团队成员之间保持一致的环境

+   设置一个需要几个小时的新环境

+   并非所有开发人员都具有自己设置 LAMP 服务器的知识或经验

我们可以通过 Oracle 的 VirtualBox（[www.virtualbox.org](http://www.virtualbox.org)）来解决前两个问题。VirtualBox 是一个强大且广受欢迎的虚拟化引擎，它将允许我们创建虚拟机（VMs）。VMs 也可以在开发人员之间和所有主要操作系统之间共享。

## 获取 VirtualBox

VirtualBox 是开源的，并且在所有平台上都受支持。可以直接从[www.virtualbox.org/wiki/Downloads](http://www.virtualbox.org/wiki/Downloads)下载。

现在，我们将继续设置一个 Linux 虚拟机。我们选择了 Ubuntu Server 12.04.2 LTS，因为它易于使用并且有广泛的支持。首先，从[www.ubuntu.com/download/server](http://www.ubuntu.com/download/server)下载 ISO 文件；64 位和 32 位版本都可以使用。

要创建一个新的 Linux 虚拟机，请执行以下步骤：

1.  启动**VirtualBox Manager**，并单击左上角的**New**按钮，如下截图所示：![获取 VirtualBox](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mgt-php-dev-gd/img/3060OS_01_01_revised.jpg)

1.  一个向导对话框将弹出并引导我们完成创建一个裸虚拟机的步骤。向导将要求我们提供设置虚拟机的基本信息：

+   **VM 名称**：我们应该如何命名我们的虚拟机？让我们将其命名为`Magento_dev 01`。

+   **内存**：这是在我们的 VM 启动时将分配给客户操作系统的系统内存值；对于运行完整的 LAMP 服务器，建议使用 1GB 或更多。

+   **操作系统类型**：这是我们稍后将安装的操作系统类型；在我们的情况下，我们要选择**Linux/Ubuntu**，根据我们的选择，VirtualBox 将启用或禁用某些 VM 选项。

1.  接下来，我们需要指定一个虚拟硬盘。选择**现在创建虚拟硬盘**，如下截图所示：![获取 VirtualBox](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mgt-php-dev-gd/img/3060OS_01_02.jpg)

1.  有许多硬盘选项可用，但对于大多数情况，选择**VirtualBox 磁盘映像**（**VDI**）就足够了。这将在我们的主机操作系统上创建一个单个文件。

1.  现在我们需要选择物理驱动器上的存储类型。我们提供以下两个选项：

+   **动态分配**：磁盘映像将随着客户操作系统上的文件数量和使用量的增加而自动增长

+   **固定大小**：此选项将从一开始限制虚拟磁盘的大小

1.  接下来，我们需要指定虚拟硬盘的大小。我们希望根据我们计划使用的 Magento 安装数量来调整大小。

### 注意

一般来说，我们希望每个 Magento 安装至少保留 2GB 的空间，如果我们在同一安装上运行数据库服务器，还需要另外 3GB。这并不是说所有的空间会立即或甚至根本不会被使用，但是一旦考虑到产品图片和缓存文件，Magento 安装可能会使用大量的磁盘空间。

1.  最后，我们只需要点击**创建**按钮。

### 提示

主要区别在于固定大小的硬盘将从一开始就在物理硬盘上保留空间，而动态分配的硬盘将逐渐增长，直到获得指定的大小。

新创建的框将出现在左侧导航菜单中，但在启动我们最近创建的 VM 之前，我们需要进行一些更改，如下所示：

i. 选择我们新创建的 VM，然后点击顶部的**设置**按钮。

ii. 打开**网络**菜单，选择**适配器 2**。我们将把**连接到**设置为**桥接适配器**，因为我们希望将其设置为桥接适配器到我们的主网络接口。这将允许我们远程使用 SSH 连接。

![获取 VirtualBox](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mgt-php-dev-gd/img/3060OS_01_03.jpg)

iii. 转到**系统**菜单，更改启动顺序，使 CD/DVD-ROM 首先启动。

iv. 在**存储**菜单中，选择一个空的 IDE 控制器，并挂载我们之前下载的 Ubuntu ISO 镜像。

![获取 VirtualBox](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mgt-php-dev-gd/img/3060OS_01_04.jpg)

## 启动我们的虚拟机

此时，我们已经成功安装和配置了我们的 VirtualBox 实例，现在我们已经准备好首次启动我们的新虚拟机。要做到这一点，只需在左侧边栏中选择 VM，然后点击顶部的**启动**按钮。

一个新窗口将弹出，显示 VM 的界面。Ubuntu 将需要几分钟来启动。

一旦 Ubuntu 完成启动，我们将看到两个菜单。第一个菜单将允许我们选择语言，第二个菜单是主菜单，提供了几个选项。在我们的情况下，我们只想继续选择**安装 Ubuntu 服务器**选项。

![启动虚拟机](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mgt-php-dev-gd/img/3060OS_01_05.jpg)

现在我们应该看到 Ubuntu 安装向导，它将要求我们选择语言和键盘设置；在选择适合我们国家和语言的设置后，安装程序将继续将所有必要的软件包加载到内存中。这可能需要几分钟。

Ubuntu 将继续配置我们的主网络适配器，一旦自动配置完成，我们将被要求设置虚拟机的主机名。我们可以将主机名保留为默认设置。

![启动虚拟机](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mgt-php-dev-gd/img/3060OS_01_06.jpg)

下一个屏幕将要求我们输入用户的全名；在这个例子中，让我们使用`Magento Developer`：

![启动虚拟机](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mgt-php-dev-gd/img/3060OS_01_07.jpg)

接下来，我们将被要求创建用户名和密码。让我们使用`magedev`作为我们的用户名：

![启动虚拟机](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mgt-php-dev-gd/img/3060OS_01_08.jpg)

让我们使用`magento2013`作为我们的密码：

![启动虚拟机](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mgt-php-dev-gd/img/3060OS_01_09.jpg)

在接下来的屏幕上，我们将被要求确认我们的密码并设置正确的时区；输入正确的值后，安装向导将显示以下屏幕，询问我们的分区设置：

![启动虚拟机](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mgt-php-dev-gd/img/3060OS_01_10.jpg)

在我们的情况下，我们选择**引导-使用整个磁盘并设置 LVM**；现在让我们确认我们正在分区我们的虚拟磁盘：

![启动虚拟机](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mgt-php-dev-gd/img/3060OS_01_11.jpg)

我们将被要求最后一次确认我们的更改；选择**完成分区并将更改写入磁盘**，如下截图所示：

![启动虚拟机](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mgt-php-dev-gd/img/3060OS_01_12.jpg)

安装向导将要求我们选择预定义的软件包进行安装；可用选项之一是**LAMP 服务器**。

虽然这非常方便，但我们不想安装预先打包在我们的 Ubuntu CD 中的 LAMP 服务器；我们将手动安装所有 LAMP 组件，以确保它们根据特定需求进行设置，并且与最新的补丁保持最新。

接下来，我们需要一个 SSH 服务器；从列表中选择**OpenSSH 服务器**并点击**继续**：

![启动我们的虚拟机](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mgt-php-dev-gd/img/3060OS_01_13.jpg)

现在，Ubuntu 的安装已经完成，它将重新启动到我们新安装的虚拟盒中。

我们几乎准备好继续安装我们环境的其余部分了，但首先我们需要更新我们的软件包管理器存储库定义，登录控制台并运行以下命令：

```php
**$ sudo apt-get update**

```

**APT**代表**高级包装工具**，是大多数 Debian GNU/Linux 发行版中包含的核心库之一；`apt`大大简化了在我们的系统上安装和维护软件的过程。

一旦`apt-get`完成更新所有存储库源，我们可以继续安装我们的 LAMP 服务器的其他组件。

## 安装 Apache2

Apache 是一个 HTTP 服务器。目前，它用于托管超过 60％的网站，并且是运行 Magento 商店的公认标准。有许多在线指南和教程可供调整和优化 Apache2 以提高 Magento 性能。

安装 Apache 就像运行以下命令一样简单：

```php
**$ sudo apt-get install apache2 -y**

```

这将负责为我们安装 Apache2 和所有必需的依赖项。如果一切安装正确，我们现在可以通过打开浏览器并输入`http://192.168.36.1/`来进行测试。

Apache 默认作为服务运行，并且可以使用以下命令进行控制：

```php
**$ sudo apache2ctl stop** 
**$ sudo apache2ctl start** 
**$ sudo apache2ctl restart** 

```

现在，您应该看到 Apache 的默认网页，上面有**It Works!**的消息。

## 安装 PHP

**PHP**是一种服务器端脚本语言，代表**PHP 超文本处理器**。Magento 是基于 PHP5 和 Zend Framework 实现的，我们需要安装 PHP 和一些额外的库才能运行它。

让我们再次使用`apt-get`并运行以下命令来安装`php5`和所有必要的库：

```php
**$ sudo apt-get install php5 php5-curl php5-gd php5-imagick php5-imap php5-mcrypt php5-mysql -y**
**$ sudo apt-get install php-pear php5-memcache -y**
**$ sudo apt-get install libapache2-mod-php5 -y**

```

第一个命令安装了不仅`php5`，还安装了 Magento 连接到我们的数据库和操作图像所需的其他软件包。

第二个命令将安装 PEAR，一个 PHP 包管理器和一个 PHP memcached 适配器。

### 注意

Memcached 是一个高性能的分布式内存缓存系统；这是 Magento 的一个可选缓存系统。

第三个命令安装并设置了 Apache 的`php5`模块。

我们最终可以通过运行以下命令来测试我们的 PHP 安装是否正常工作：

```php
**$ php -v**

```

## 安装 MySQL

MySQL 是许多 Web 应用程序的流行数据库选择，Magento 也不例外。我们需要安装和设置 MySQL 作为开发堆栈的一部分，使用以下命令：

```php
**$ sudo apt-get install mysql-server mysql-client -y**

```

在安装过程中，我们将被要求输入根密码；使用`magento2013`。安装程序完成后，我们应该有一个在后台运行的`mysql`服务实例。我们可以通过尝试使用以下命令连接到`mysql`服务器来测试它：

```php
**$ sudo mysql -uroot -pmagento2013**

```

如果一切安装正确，我们应该看到以下`mysql`服务器提示：

```php
**mysql>**

```

此时，我们有一个完全功能的 LAMP 环境，不仅可以用于开发和处理 Magento 网站，还可以用于任何其他类型的 PHP 开发。

## 将所有内容放在一起

此时，我们已经有了一个基本的 LAMP 设置并正在运行。然而，为了使用 Magento，我们需要进行一些配置更改和额外的设置。

我们需要做的第一件事是创建一个位置来存储我们开发站点的文件，因此我们将运行以下命令：

```php
**$ sudo mkdir -p /srv/www/magento_dev/public_html/**
**$ sudo mkdir /srv/www/magento_dev/logs/**
**$ sudo mkdir /srv/www/magento_dev/ssl/**

```

这将为我们的第一个 Magento 站点创建必要的文件夹结构。现在我们需要通过使用 SVN 来快速获取文件的最新版本。

首先，我们需要在服务器上安装 SVN，使用以下命令：

```php
**$ sudo apt-get install subversion -y**

```

安装程序完成后，打开`magento_dev`目录并运行`svn`命令以获取最新版本的文件：

```php
**$ cd /srv/www/magento_dev** 
**$ sudo svn export --force http://svn.magentocommerce.com/source/branches/1.7 public_html/**

```

我们还需要修复新的 Magento 副本上的一些权限：

```php
**$ sudo chown -R www-data:www-data public_html/**
**$ sudo chmod -R 755 public_html/var/** 
**$ sudo chmod -R 755 public_html/media/** 
**$ sudo chmod -R 755 public_html/app/etc/**

```

接下来，我们需要为 Magento 安装创建一个新的数据库。让我们打开我们的`mysql` shell：

```php
**$ sudo mysql -uroot -pmagento2013**

```

进入`mysql` shell 后，我们可以使用`create`命令，后面应该跟着我们想要创建的实体类型（`database`，`table`）和要创建的数据库名称来创建一个新的数据库：

```php
**mysql> create database magento_dev;**

```

虽然我们可以使用 root 凭据访问我们的开发数据库，但这不是一个推荐的做法，因为这不仅可能危及单个站点，还可能危及整个数据库服务器。MySQL 帐户受权限限制。我们想要创建一组新的凭据，这些凭据只对我们的工作数据库有限的权限：

```php
**mysql> GRANT ALL PRIVILEGES ON magento_dev.* TO 'mage'@'localhost' IDENTIFIED BY 'dev2013$#';**

```

现在，我们需要正确设置 Apache2 并启用一些额外的模块；幸运的是，这个版本的 Apache 带有一组有用的命令：

+   `a2ensite`：这将在`sites-available`和`sites-enabled`文件夹之间创建符号链接，以允许 Apache 服务器读取这些文件。

+   `a2dissite`：这将删除`a2ensite`命令创建的符号链接。这将有效地禁用该站点。

+   `a2enmod`：这用于在`mods-enabled`目录和模块配置文件之间创建符号链接。

+   `a2dismod`：这将从`mods-enabled`目录中删除符号链接。此命令将阻止 Apache 加载该模块。

Magento 使用`mod_rewrite`模块来生成 URL。`mod_rewrite`使用基于规则的重写引擎来实时重写请求的 URL。

我们可以使用`a2enmod`命令启用`mod_rewrite`：

```php
**$ sudo a2enmod rewrite**

```

下一步需要我们在`sites-available`目录下创建一个新的虚拟主机文件：

```php
**$ sudo nano /etc/apache2/sites-available/magento.localhost.com**

```

`nano`命令将打开一个 shell 文本编辑器，我们可以在其中设置虚拟域的配置：

```php
<VirtualHost *:80>
  ServerAdmin magento@locahost.com
  ServerName magento.localhost.com
  DocumentRoot /srv/www/magento_dev/public_html

  <Directory /srv/www/magento_dev/public_html/>
    Options Indexes FollowSymlinks MultiViews
    AllowOverride All
    Order allow,deny
    allow from all
  </Directory>
  ErrorLog /srv/www/magento_dev/logs/error.log
  LogLevel warn
</VirtualHost>
```

要保存新的虚拟主机文件，请按*Ctrl* + *O*，然后按*Ctrl* + *X*。虚拟主机文件将告诉 Apache 在哪里找到站点文件以及给予它们什么权限。为了使新的配置更改生效，我们需要启用新站点并重新启动 Apache。我们可以使用以下命令来实现：

```php
**$ sudo a2ensite magento.localhost.com**
**$ sudo apache2ctl restart**

```

我们几乎准备好安装 Magento 了。我们只需要通过以下任一方式在主机系统的主机文件中设置本地映射：

+   Windows

i. 用记事本打开`C:\system32\drivers\etc\hosts`

ii. 在文件末尾添加以下行：

```php
192.168.36.1 magento.localhost.com
```

+   Unix/Linux/OSX

i. 使用`nano`打开`/etc/hosts`：

```php
**$ sudo nano /etc/hosts**

```

ii. 在文件末尾添加以下行：

```php
192.168.36.1 magento.localhost.com
```

### 提示

如果您在对主机文件进行必要更改时遇到问题，请访问`http://www.magedevguide.com/hostfile-help`。

现在，我们可以通过在浏览器中打开`http://magento.localhost.com`来安装 Magento。最后，我们应该看到安装向导。按照向导指示的步骤进行操作，您就可以开始使用了！

![把所有东西放在一起](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mgt-php-dev-gd/img/3060OS_01_14.jpg)

# 使用 Vagrant 快速上手

之前，我们使用 VM 创建了一个 Magento 安装。虽然使用 VM 为我们提供了一个可靠的环境，但为每个 Magento 分期安装设置我们的 LAMP 仍然可能非常复杂。这对于没有在 Unix/Linux 环境上工作经验的开发人员尤其如此。

如果我们能够获得运行 VM 的所有好处，但是具有完全自动化的设置过程呢？如果我们能够为我们的每个分期网站创建和配置新的 VM 实例？

这是通过使用 Vagrant 结合 Chef 实现的。我们可以创建自动化的虚拟机，而无需对 Linux 或不同的 LAMP 组件有广泛的了解。

### 注意

Vagrant 目前支持 VirtualBox 4.0.x、4.1.x 和 4.2.x。

## 安装 Vagrant

Vagrant 可以直接从[downloads.vagrantup.com](http://downloads.vagrantup.com)下载。此外，它的软件包和安装程序适用于多个平台。下载 Vagrant 后，运行安装。

一旦我们安装了 Vagrant 和 VirtualBox，启动基本 VM 就像在终端或命令提示符中输入以下行一样简单，具体取决于您使用的操作系统：

```php
**$ vagrant box add lucid32 http://files.vagrantup.com/lucid32.box**
**$ vagrant init lucid32**
**$ vagrant up**

```

这些命令将启动一个安装了 Ubuntu Linux 的新 Vagrant 盒子。从这一点开始，我们可以像平常一样开始安装我们的 LAMP。但是，为什么我们要花一个小时为每个项目配置和设置 LAMP 服务器，当我们可以使用 Chef 自动完成呢？Chef 是一个用 Ruby 编写的配置管理工具，可以集成到 Vagrant 中。

为了让刚开始使用 Magento 的开发人员更容易，我在 Github 上创建了一个名为`magento-vagrant`的 Vagrant 存储库，其中包括 Chef 所需的所有必要的食谱和配方。`magento-vagrant`存储库还包括一个新的食谱，将负责特定的 Magento 设置和配置。

为了开始使用`magento-vagrant`，您需要一个 Git 的工作副本。

如果您使用 Ubuntu，请运行以下命令：

```php
**$ sudo apt-get install git-core -y**

```

对于 Windows，我们可以使用本地工具在[`windows.github.com/`](http://windows.github.com/)下载和管理我们的存储库。

无论您使用的操作系统是什么，我们都需要在本地文件系统中检出此存储库的副本。我们将使用`C:/Users/magedev/Documents/magento-vagrant/`来下载和保存我们的存储库；在`magento-vagrant`中，我们将找到以下文件和目录：

+   食谱

+   `data_bags`

+   公共

+   `.vagrant`

+   `Vagrantfile`

`magento-vagrant`存储库包括我们开发环境的每个组件的食谱，一旦我们启动新的 Vagrant 盒子，它们将自动安装。

现在唯一剩下的事情就是设置我们的开发站点。通过使用 Vagrant 和 Chef，向我们的 Vagrant 安装添加新的 Magento 站点的过程已经变得简化。

在`data_bags`目录中，我们有一个文件用于 Vagrant 盒子中每个 Magento 安装；默认存储库中包含 Magento CE 1.7 的示例安装。

对于每个站点，我们需要创建一个包含 Chef 所需的所有设置的新 JSON 文件。让我们看一下`magento-vagrant`默认文件，可以在位置`C:/Users/magedev/Documents/magento-vagrant/data_bags/sites/default.json`找到：

```php
{
    "id": "default",
    "host": "magento.localhost.com",
    "repo": [
        "url": "svn.magentocommerce.com/source/branches/1.7",
        "revision": "HEAD"  
     ],
   "database": [
      "name": "magento_staging",
      "username": "magento",
      "password": "magento2013$"
   ]
}
```

这将自动使用 Magento 存储库中的最新文件设置 Magento 安装。

向我们的 Vagrant 盒子添加新站点只是添加一个相应站点的新 JSON 文件并重新启动 Vagrant 盒子的问题。

现在我们有一个运行中的 Magento 安装，让我们来选择一个合适的**集成开发环境**（**IDE**）。

# 选择一个 IDE

选择合适的 IDE 主要是个人开发者口味的问题。然而，选择合适的 IDE 对于 Magento 开发者来说可能是至关重要的。

IDE 的挑战主要来自 Magento 对工厂名称的广泛使用。这使得某些功能的实现，如代码完成（也称为智能感知），变得困难。目前，有两个 IDE 在其对 Magento 的本地支持方面表现出色-NetBeans 和 PhpStorm。

尽管 NetBeans 是开源的，并且已经存在很长时间，但 PhpStorm 一直占据上风，并得到了 Magento 社区的更多支持。

此外，最近发布的 Magicento 插件，专门用于扩展和集成 Magento 到 PhpStorm 中，已成为当前可用选项中最佳选择。

# 使用版本控制系统

Magento 代码库非常庞大，包括超过 7,000 个文件和近 150 万行代码。因此，使用版本控制系统不仅是一种良好的实践，也是一种必要性。

版本控制系统用于跟踪多个文件和多个开发人员之间的更改；通过使用版本控制系统，我们可以获得非常强大的工具。

在几种可用的版本控制系统中（Git、SVN、Mercurial），Git 由于其简单性和灵活性而值得特别关注。通过在 Git 托管服务 Github 上发布即将推出的 Magento 2 版本，Magento 核心开发团队已经认识到 Git 在 Magento 社区中的重要性。

### 注意

有关 Magento2 的更多信息，请访问[`github.com/magento/magento2`](https://github.com/magento/magento2)。

Github 现在包括一个特定于 Magento 的`.gitignore`文件，它将忽略 Magento 核心中的所有文件，只跟踪我们自己的代码。

也就是说，在处理 Magento 项目时，有几个版本控制概念需要牢记：

+   **分支**：这允许我们在不影响主干（稳定版本）的情况下工作新功能。

+   **合并**：这用于将代码从一个地方移动到另一个地方。通常，这是在开发分支准备好移动到生产环境时从开发分支到主干进行的。

+   **标记**：这用于创建发布的快照。

# 总结

在这第一章中，我们学习了如何设置和使用 LAMP 环境，在多个平台上设置开发环境，创建和配置 Vagrant 虚拟机，使用 Chef 配方以及使用 Magento 开发的版本控制系统。

拥有适当的环境是开始为 Magento 开发的第一步，也是我们 Magento 工具箱的一个组成部分。

现在我们已经设置好并准备好使用开发环境，是时候深入了解 Magento 的基本概念了；这些概念将为我们提供开发 Magento 所需的工具和知识。


# 第二章：开发人员的 Magento 基础知识

在本章中，我们将介绍与 Magento 一起工作的基本概念。我们将了解 Magento 的结构，并将介绍 Magento 灵活性的来源，即其模块化架构。

Magento 是一个灵活而强大的系统。不幸的是，这也增加了一定程度的复杂性。目前，Magento 的干净安装大约有 30,000 个文件和超过 120 万行代码。

拥有如此强大和复杂的功能，Magento 对于新开发人员可能会令人望而生畏；但不用担心。本章旨在教新开发人员所有他们需要使用和扩展 Magento 的基本概念和工具，在下一章中，我们将深入研究 Magento 的模型和数据集。

# Zend Framework – Magento 的基础

您可能知道，Magento 是市场上最强大的电子商务平台；您可能不知道的是，Magento 还是一个基于 Zend Framework 开发的**面向对象**（**OO**）PHP 框架。

Zend 的官方网站描述了该框架为：

> *Zend Framework 2 是一个使用 PHP 5.3+开发 Web 应用程序和服务的开源框架。Zend Framework 2 使用 100%面向对象的代码，并利用了 PHP 5.3 的大多数新特性，即命名空间、后期静态绑定、lambda 函数和闭包。*
> 
> *Zend Framework 2 的组件结构是独特的；每个组件都设计为对其他组件的依赖较少。ZF2 遵循 SOLID 面向对象设计原则。这种松散耦合的架构允许开发人员使用他们想要的任何组件。我们称之为“随意使用”设计。*

但是 Zend Framework 究竟是什么？Zend Framework 是一个基于 PHP 开发的面向对象框架，实现了**模型-视图-控制器**（**MVC**）范式。当 Varien，现在的 Magento 公司，开始开发 Magento 时，决定在 Zend 的基础上进行开发，因为以下组件：

+   `Zend_Cache`

+   `Zend_Acl`

+   `Zend_Locale`

+   `Zend_DB`

+   `Zend_Pdf`

+   `Zend_Currency`

+   `Zend_Date`

+   `Zend_Soap`

+   `Zend_Http`

总的来说，Magento 使用了大约 15 个不同的 Zend 组件。Varien 库直接扩展了先前提到的几个 Zend 组件，例如`Varien_Cache_Core`是从`Zend_Cache_Core`扩展而来的。

使用 Zend Framework，Magento 是根据以下原则构建的：

+   **可维护性**：通过使用代码池来将核心代码与本地定制和第三方模块分开

+   **可升级性**：Magento 的模块化允许扩展和第三方模块独立于系统的其他部分进行更新

+   **灵活性**：允许无缝定制并简化新功能的开发

虽然使用 Zend Framework 甚至理解它并不是开发 Magento 的要求，但至少对 Zend 组件、用法和交互有基本的了解，在我们开始深入挖掘 Magento 的核心时，可能会是非常宝贵的信息。

### 注意

您可以在[`framework.zend.com/`](http://framework.zend.com/)了解更多关于 Zend Framework 的信息。

# Magento 文件夹结构

Magento 的文件夹结构与其他 MVC 应用程序略有不同；让我们来看看目录树，以及每个目录及其功能：

+   `app`：这个文件夹是 Magento 的核心，分为三个导入目录：

+   `code`：这包含了我们的应用程序代码，分为`core`、`community`和`local`三个代码池

+   `design`：这包含了我们应用程序的所有模板和布局

+   `locale`：这包含了商店使用的所有翻译和电子邮件模板文件

+   `js`：这包含了 Magento 中使用的所有 JavaScript 库

+   `media`：这包含了我们产品和 CMS 页面的所有图片和媒体文件，以及产品图片缓存

+   `lib`：这包含 Magento 使用的所有第三方库，如 Zend 和 PEAR，以及 Magento 开发的自定义库，这些库位于 Varien 和 Mage 目录下

+   `皮肤`：这包含对应主题使用的所有 CSS 代码、图像和 JavaScript 文件

+   `var`：这包含我们的临时数据，如缓存文件、索引锁文件、会话、导入/导出文件，以及企业版中的完整页面缓存文件夹

Magento 是一个模块化系统。这意味着应用程序，包括核心，被划分为较小的模块。因此，文件夹结构在每个模块核心的组织中起着关键作用；典型的 Magento 模块文件夹结构看起来像下面的图：

![Magento 文件夹结构](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mgt-php-dev-gd/img/3060OS_02_01.jpg)

让我们更详细地审查每个文件夹：

+   `块`：这个文件夹包含 Magento 中形成控制器和视图之间的额外逻辑的块

+   `controllers`：`controllers`文件夹由处理 Web 服务器请求的操作组成

+   `控制器`：这个文件夹中的类是抽象类，由`controllers`文件夹下的`controller`类扩展

+   `etc`：在这里，我们可以找到以 XML 文件形式的模块特定配置，例如`config.xml`和`system.xml`

+   `助手`：这个文件夹包含封装常见模块功能并使其可用于同一模块的类和其他模块类的辅助类

+   `模型`：这个文件夹包含支持模块中控制器与数据交互的模型

+   `sql`：这个文件夹包含每个特定模块的安装和升级文件

正如我们将在本章后面看到的那样，Magento 大量使用工厂名称和工厂方法。这就是为什么文件夹结构如此重要的原因。

# 模块化架构

Magento 不是一个庞大的应用程序，而是由较小的模块构建，每个模块为 Magento 添加特定功能。

这种方法的优势之一是能够轻松启用和禁用特定模块功能，以及通过添加新模块来添加新功能。

## 自动加载程序

Magento 是一个庞大的框架，由近 30000 个文件组成。在应用程序启动时需要每个文件将使其变得非常缓慢和沉重。因此，Magento 使用自动加载程序类来在每次调用工厂方法时找到所需的文件。

那么，自动加载程序到底是什么？PHP5 包含一个名为`__autoload()`的函数。在实例化类时，`__autoload()`函数会自动调用；在这个函数内部，定义了自定义逻辑来解析类名和所需文件。

让我们仔细看看位于`app/Mage.php`的 Magento 引导代码：

```php
… 
Mage::register('original_include_path', get_include_path());
if (defined('COMPILER_INCLUDE_PATH')) {
    $appPath = COMPILER_INCLUDE_PATH;
    set_include_path($appPath . PS . Mage::registry('original_include_path'));
    include_once "Mage_Core_functions.php";
    include_once "Varien_Autoload.php";
} else {
    /**
     * Set include path
     */
    $paths[] = BP . DS . 'app' . DS . 'code' . DS . 'local';
    $paths[] = BP . DS . 'app' . DS . 'code' . DS . 'community';
    $paths[] = BP . DS . 'app' . DS . 'code' . DS . 'core';
    $paths[] = BP . DS . 'lib';

    $appPath = implode(PS, $paths);
    set_include_path($appPath . PS . Mage::registry('original_include_path'));
    include_once "Mage/Core/functions.php";
    include_once "Varien/Autoload.php";
}

Varien_Autoload::register();
```

引导文件负责定义`include`路径和初始化 Varien 自动加载程序，后者将定义自己的`autoload`函数作为默认调用函数。让我们来看看 Varien `autoload`函数的内部工作：

```php
    /**
     * Load class source code
     *
     * @param string $class
     */
    public function autoload($class)
    {
        if ($this->_collectClasses) {
            $this->_arrLoadedClasses[self::$_scope][] = $class;
        }
        if ($this->_isIncludePathDefined) {
            $classFile =  COMPILER_INCLUDE_PATH . DIRECTORY_SEPARATOR . $class;
        } else {
            $classFile = str_replace(' ', DIRECTORY_SEPARATOR, ucwords(str_replace('_', ' ', $class)));
        }
        $classFile.= '.php';
        //echo $classFile;die();
        return include $classFile;
    }
```

`autoload`类接受一个名为`$class`的参数，这是工厂方法提供的别名。这个别名被处理以生成一个匹配的类名，然后被包含。

正如我们之前提到的，Magento 的目录结构很重要，因为 Magento 从目录结构中派生其类名。这种约定是我们将在本章后面审查的工厂方法的核心原则。

## 代码池

正如我们之前提到的，在我们的`app/code`文件夹中，我们的应用程序代码分为三个不同的目录，称为代码池。它们如下：

+   `核心`：这是 Magento 核心模块提供基本功能的地方。Magento 开发人员之间的黄金法则是，绝对不要修改`core`代码池下的任何文件。

+   `community`：这是第三方模块放置的位置。它们要么由第三方提供，要么通过 Magento Connect 安装。

+   `本地`：这是专门为 Magento 实例开发的所有模块和代码所在的位置。

代码池确定模块来自何处以及它们应该被加载的顺序。如果我们再看一下`Mage.php`引导文件，我们可以看到代码池加载的顺序：

```php
    $paths[] = BP . DS . 'app' . DS . 'code' . DS . 'local';
    $paths[] = BP . DS . 'app' . DS . 'code' . DS . 'community';
    $paths[] = BP . DS . 'app' . DS . 'code' . DS . 'core';
    $paths[] = BP . DS . 'lib';
```

这意味着对于每个类请求，Magento 将首先查找`local`，然后是`community`，然后是`core`，最后是`lib`文件夹内的内容。

这也导致了一个有趣的行为，可以很容易地用于覆盖`core`和`community`类，只需复制目录结构并匹配类名。

### 提示

毋庸置疑，这是一个糟糕的做法，但了解这一点仍然是有用的，以防将来有一天你不得不处理利用这种行为的项目。

# 路由和请求流程

在更详细地了解构成 Magento 一部分的不同组件之前，重要的是我们了解这些组件如何相互交互以及 Magento 如何处理来自 Web 服务器的请求。

与任何其他 PHP 应用程序一样，我们有一个单一文件作为每个请求的入口点；在 Magento 的情况下，这个文件是`index.php`，负责加载`Mage.php`引导类并启动请求周期。然后它经历以下步骤：

1.  Web 服务器接收请求，并通过调用引导文件`Mage.php`来实例化 Magento。

1.  前端控制器被实例化和初始化；在控制器初始化期间，Magento 搜索 web 路由并实例化它们。

1.  然后 Magento 遍历每个路由器并调用匹配。`match`方法负责处理 URL 并生成相应的控制器和操作。

1.  Magento 然后实例化匹配的控制器并执行相应的操作。

路由器在这个过程中尤其重要。前端控制器使用`Router`对象将请求的 URL（路由）与模块控制器和操作进行匹配。默认情况下，Magento 带有以下路由器：

+   `Mage_Core_Controller_Varien_Router_Admin`

+   `Mage_Core_Controller_Varien_Router_Standard`

+   `Mage_Core_Controller_Varien_Router_Default`

然后动作控制器将加载和渲染布局，然后加载相应的块、模型和模板。

让我们分析一下 Magento 如何处理对类别页面的请求；我们将使用`http://localhost/catalog/category/view/id/10`作为示例。Magento 的 URI 由三部分组成 - */FrontName/ControllerName/ActionName*。

这意味着对于我们的示例 URL，拆分将如下所示：

+   **FrontName**：`catalog`

+   **ControllerName**：`category`

+   **ActionName**：`view`

如果我看一下 Magento 路由器类，我可以看到`Mage_Core_Controller_Varien_Router_Standard`匹配函数：

```php
public function match(Zend_Controller_Request_Http $request)
{
  …
   $path = trim($request->getPathInfo(), '/');
            if ($path) {
                $p = explode('/', $path);
            } else {
                $p = explode('/', $this->_getDefaultPath());
            }
  …
}
```

从前面的代码中，我们可以看到路由器尝试做的第一件事是将 URI 解析为数组。根据我们的示例 URL，相应的数组将类似于以下代码片段：

```php
$p = Array
(
    [0] => catalog
    [1] => category
    [2] => view
)
```

函数的下一部分将首先尝试检查请求是否指定了模块名称；如果没有，则尝试根据数组的第一个元素确定模块名称。如果无法提供模块名称，则函数将返回`false`。让我们看看代码的这一部分：

```php
      // get module name
        if ($request->getModuleName()) {
            $module = $request->getModuleName();
        } else {
            if (!empty($p[0])) {
                $module = $p[0];
            } else {
                $module = $this->getFront()->getDefault('module');
                $request->setAlias(Mage_Core_Model_Url_Rewrite::REWRITE_REQUEST_PATH_ALIAS, '');
            }
        }
        if (!$module) {
            if (Mage::app()->getStore()->isAdmin()) {
                $module = 'admin';
            } else {
                return false;
            }
        }
```

接下来，匹配函数将遍历每个可用模块，并尝试匹配控制器和操作，使用以下代码：

```php
…
        foreach ($modules as $realModule) {
            $request->setRouteName($this->getRouteByFrontName($module));

            // get controller name
            if ($request->getControllerName()) {
                $controller = $request->getControllerName();
            } else {
                if (!empty($p[1])) {
                    $controller = $p[1];
                } else {
                    $controller = $front->getDefault('controller');
                    $request->setAlias(
                        Mage_Core_Model_Url_Rewrite::REWRITE_REQUEST_PATH_ALIAS,
                        ltrim($request->getOriginalPathInfo(), '/')
                    );
                }
            }

            // get action name
            if (empty($action)) {
                if ($request->getActionName()) {
                    $action = $request->getActionName();
                } else {
                    $action = !empty($p[2]) ? $p[2] : $front->getDefault('action');
                }
            }

            //checking if this place should be secure
            $this->_checkShouldBeSecure($request, '/'.$module.'/'.$controller.'/'.$action);

            $controllerClassName = $this->_validateControllerClassName($realModule, $controller);
            if (!$controllerClassName) {
                continue;
            }

            // instantiate controller class
            $controllerInstance = Mage::getControllerInstance($controllerClassName, $request, $front->getResponse());

            if (!$controllerInstance->hasAction($action)) {
                continue;
            }

            $found = true;
            break;
        }
...
```

现在看起来代码量很大，所以让我们进一步分解。循环的第一部分将检查请求是否有一个控制器名称；如果没有设置，它将检查我们的参数数组（$p）的第二个值，并尝试确定控制器名称，然后它将尝试对操作名称做同样的事情。

如果我们在循环中走到了这一步，我们应该有一个模块名称，一个控制器名称和一个操作名称，Magento 现在将使用它们来尝试通过调用以下函数获取匹配的控制器类名：

```php
$controllerClassName = $this->_validateControllerClassName($realModule, $controller);
```

这个函数不仅会生成一个匹配的类名，还会验证它的存在；在我们的例子中，这个函数应该返回`Mage_Catalog_CategoryController`。

由于我们现在有了一个有效的类名，我们可以继续实例化我们的控制器对象；如果你一直关注到这一点，你可能已经注意到我们还没有对我们的操作做任何事情，这正是我们循环中的下一步。

我们新实例化的控制器带有一个非常方便的函数叫做`hasAction()`；实质上，这个函数的作用是调用一个名为`is_callable()`的 PHP 函数，它将检查我们当前的控制器是否有一个与操作名称匹配的公共函数；在我们的例子中，这将是`viewAction()`。

这种复杂的匹配过程和使用`foreach`循环的原因是，可能有几个模块使用相同的 FrontName。

![路由和请求流程](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mgt-php-dev-gd/img/3060OS_02_03.jpg)

现在，`http://localhost/catalog/category/view/id/10`不是一个非常用户友好的 URL；幸运的是，Magento 有自己的 URL 重写系统，允许我们使用`http://localhost/books.html`。

让我们深入了解一下 URL 重写系统，看看 Magento 如何从我们的 URL 别名中获取控制器和操作名称。在我们的`Varien/Front.php`控制器分发函数中，Magento 将调用：

```php
Mage::getModel('core/url_rewrite')->rewrite();
```

在实际查看`rewrite`函数的内部工作之前，让我们先看一下`core/url_rewrite`模型的结构：

```php
Array (
  ["url_rewrite_id"] => "10"
  ["store_id"]       => "1"
  ["category_id"]    => "10"
  ["product_id"]     => NULL
  ["id_path"]        => "category/10"
  ["request_path"]   => "books.html"
  ["target_path"]    => "catalog/category/view/id/10"
  ["is_system"]      => "1"
  ["options"]        => NULL
  ["description"]    => NULL
)
```

正如我们所看到的，重写模块由几个属性组成，但其中只有两个对我们特别感兴趣——`request_path`和`target_path`。简而言之，重写模块的工作是修改请求对象路径信息，使其与`target_path`的匹配值相匹配。

# Magento 的 MVC 版本

如果您熟悉传统的 MVC 实现，比如 CakePHP 或 Symfony，您可能知道最常见的实现被称为基于约定的 MVC。使用基于约定的 MVC，要添加一个新模型或者说一个控制器，你只需要创建文件/类（遵循框架约定），系统就会自动接收它。

Magento，另一方面，使用基于配置的 MVC 模式，这意味着创建我们的文件/类是不够的；我们必须明确告诉 Magento 我们添加了一个新类。

每个 Magento 模块都有一个`config.xml`文件，位于模块的`etc/`目录下，包含所有相关的模块配置。例如，如果我们想要添加一个包含新模型的新模块，我们需要在配置文件中定义一个节点，告诉 Magento 在哪里找到我们的模型，比如：

```php
<global>
…
<models>
     <group_classname>
          <class>Namespace_Modulename_Model</class>
     <group_classname>
</models>
...
</global>
```

虽然这可能看起来像是额外的工作，但它也给了我们巨大的灵活性和权力。例如，我们可以使用`rewrite`节点重写另一个类：

```php
<global>
…
<models>
     <group_classname>
      <rewrite>
               <modulename>Namespace_Modulename_Model</modulename>
      </rewrite>
     <group_classname>
</models>
...
</global>
```

Magento 然后会加载所有的`config.xml`文件，并在运行时合并它们，创建一个单一的配置树。

此外，模块还可以有一个`system.xml`文件，用于在 Magento 后台指定配置选项，这些选项又可以被最终用户用来配置模块功能。`system.xml`文件的片段如下所示：

```php
<config>
  <sections>
    <section_name translate="label">
      <label>Section Description</label>
      <tab>general</tab>
      <frontend_type>text</frontend_type>
      <sort_order>1000</sort_order>
      <show_in_default>1</show_in_default>
      <show_in_website>1</show_in_website>
      <show_in_store>1</show_in_store>
      <groups>
       <group_name translate="label">
         <label>Demo Of Config Fields</label>
         <frontend_type>text</frontend_type>
         <sort_order>1</sort_order>
         <show_in_default>1</show_in_default>
         <show_in_website>1</show_in_website>
         <show_in_store>1</show_in_store>  
   <fields>
          <field_name translate="label comment">
             <label>Enabled</label>
             <comment>
               <![CDATA[Comments can contain <strong>HTML</strong>]]>
             </comment>
             <frontend_type>select</frontend_type>
             <source_model>adminhtml/system_config_source_yesno</source_model>
             <sort_order>10</sort_order>
             <show_in_default>1</show_in_default>
             <show_in_website>1</show_in_website>
             <show_in_store>1</show_in_store>
          </field_name>
         </fields>
        </group_name>
       </groups>
    </section_name>
  </sections>
</config>
```

让我们分解每个节点的功能：

+   `section_name`：这只是一个我们用来标识配置部分的任意名称；在此节点内，我们将指定配置部分的所有字段和组。

+   `group`：组，顾名思义，用于对配置选项进行分组，并在手风琴部分内显示它们。

+   `label`：这定义了字段/部分/组上要使用的标题或标签。

+   `tab`：这定义了应在其中显示部分的选项卡。

+   `frontend_type`：此节点允许我们指定要为自定义选项字段使用的渲染器。一些可用的选项包括：

+   `button`

+   `checkboxes`

+   `checkbox`

+   `date`

+   `file`

+   `hidden`

+   `image`

+   `label`

+   `link`

+   `multiline`

+   `multiselect`

+   `password`

+   `radio`

+   `radios`

+   `select`

+   `submit`

+   `textarea`

+   `text`

+   `time`

+   `sort_order`：它指定字段、组或部分的位置。

+   `source_model`：某些类型的字段，如`select`字段，可以从源模型中获取选项。Magento 已经在`Mage/Adminhtml/Model/System/Config/Source`下提供了几个有用的类。我们可以找到一些类：

+   `YesNo`

+   `Country`

+   `Currency`

+   `AllRegions`

+   `Category`

+   `Language`

仅通过使用 XML，我们就可以在 Magento 后端为我们的模块构建复杂的配置选项，而无需担心设置模板来填充字段或验证数据。

Magento 还提供了大量的表单字段验证模型，我们可以在`<validate>`标签中使用。在以下字段验证器中，我们有：

+   `validate-email`

+   `validate-length`

+   `validate-url`

+   `validate-select`

+   `validate-password`

与 Magento 的任何其他部分一样，我们可以扩展`source_model`，`frontend_type`和`validator`函数，甚至创建新的函数。我们将在后面的章节中处理这个任务，在那里我们将创建每种新类型。但现在，我们将探讨模型、视图、文件布局和控制器的概念。

## 模型

Magento 使用 ORM 方法；虽然我们仍然可以使用`Zend_Db`直接访问数据库，但我们大多数时候将使用模型来访问我们的数据。对于这种类型的任务，Magento 提供了以下两种类型的模型：

+   **简单模型**：这种模型实现是一个简单的将一个对象映射到一个表，意味着我们的对象属性与每个字段匹配，表结构

+   **实体属性值（EAV）模型**：这种类型的模型用于描述具有动态属性数量的实体

Magento 将模型层分为两部分：处理业务逻辑的模型和处理数据库交互的资源。这种设计决策使 Magento 最终能够支持多个数据库平台，而无需更改模型内部的任何逻辑。

Magento ORM 使用 PHP 的一个魔术类方法来提供对对象属性的动态访问。在下一章中，我们将更详细地了解模型、Magento ORM 和数据集合。

### 注意

Magento 模型不一定与数据库中的任何类型的表或 EAV 实体相关。稍后我们将要审查的观察者就是这种类型的 Magento 模型的完美例子。

## 视图

视图层是 Magento 真正使自己与其他 MVC 应用程序区分开的领域之一。与传统的 MVC 系统不同，Magento 的视图层分为以下三个不同的组件：

+   **布局**：布局是定义块结构和属性（如名称和我们可以使用的模板文件）的 XML 文件。每个 Magento 模块都有自己的布局文件集。

+   **块**：块在 Magento 中用于通过将大部分逻辑移动到块中来减轻控制器的负担。

+   **模板**：模板是包含所需 HTML 代码和 PHP 标记的 PHTML 文件。

布局为 Magento 前端提供了令人惊讶的灵活性。每个模块都有自己的布局 XML 文件，告诉 Magento 在每个页面请求上包含和渲染什么。通过使用布局，我们可以在不担心改变除了我们的 XML 文件之外的任何其他内容的情况下，移动、添加或删除我们商店的块。

## 解剖布局文件

让我们来看看 Magento 的一个核心布局文件，比如`catalog.xml`：

```php
<layout version="0.1.0">
<default>
    <reference name="left">
        <block type="core/template" name="left.permanent.callout" template="callouts/left_col.phtml">
            <action method="setImgSrc"><src>images/media/col_left_callout.jpg</src></action>
            <action method="setImgAlt" translate="alt" module="catalog"><alt>Our customer service is available 24/7\. Call us at (555) 555-0123.</alt></action>
            <action method="setLinkUrl"><url>checkout/cart</url></action>
        </block>
    </reference>
    <reference name="right">
        <block type="catalog/product_compare_sidebar" before="cart_sidebar" name="catalog.compare.sidebar" template="catalog/product/compare/sidebar.phtml"/>
        <block type="core/template" name="right.permanent.callout" template="callouts/right_col.phtml">
            <action method="setImgSrc"><src>images/media/col_right_callout.jpg</src></action>
            <action method="setImgAlt" translate="alt" module="catalog"><alt>Visit our site and save A LOT!</alt></action>
        </block>
    </reference>
    <reference name="footer_links">
        <action method="addLink" translate="label title" module="catalog" ifconfig="catalog/seo/site_map"><label>Site Map</label><url helper="catalog/map/getCategoryUrl" /><title>Site Map</title></action>
    </reference>
    <block type="catalog/product_price_template" name="catalog_product_price_template" />
</default>
```

布局块由三个主要的 XML 节点组成，如下所示：

+   `handle`：每个页面请求将具有几个唯一的句柄；布局使用这些句柄告诉 Magento 在每个页面上加载和渲染哪些块。最常用的句柄是`default`和`[frontname]_[controller]_[action]`。

`default`句柄特别适用于设置全局块，例如在页眉块上添加 CSS 或 JavaScript。

+   `reference`：`<reference>`节点用于引用一个块。它用于指定嵌套块或修改已经存在的块。在我们的示例中，我们可以看到在`<reference name="left">`内指定了一个新的子块。

+   `block`：`<block>`节点用于加载我们的实际块。每个块节点可以具有以下属性：

+   `type`：这是实际块类的标识符。例如，`catalog`/`product_list`指的是`Mage_Catalog_Block_Product_List`。

+   `name`：其他块用这个名称来引用这个块。

+   `before`/`after`：这些属性可用于相对于其他块的位置定位块。这两个属性都可以使用连字符作为值，以指定模块是应该出现在最顶部还是最底部。

+   `template`：此属性确定将用于渲染块的`.phtml`模板文件。

+   `action`：每个块类型都有影响前端功能的特定操作。例如，`page`/`html_head`块具有用于添加 CSS 和 JavaScript（`addJs`和`addCss`）的操作。

+   `as`：用于指定我们将在模板中调用的块的唯一标识符，例如使用`getChildHtml('block_name')`调用子块。

块是 Magento 实现的一个新概念，以减少控制器的负载。它们基本上是直接与模型通信的数据资源，模型操作数据（如果需要），然后将其传递给视图。

最后，我们有我们的 PHTML 文件；模板包含`html`和`php`标记，并负责格式化和显示来自我们模型的数据。让我们来看一下产品视图模板的片段：

```php
<div class="product-view">
...
    <div class="product-name">
        <h1><?php echo $_helper->productAttribute($_product, $_product->getName(), 'name') ?></h1>
    </div>
...           
    <?php echo $this->getReviewsSummaryHtml($_product, false, true)?>
    <?php echo $this->getChildHtml('alert_urls') ?>
    <?php echo $this->getChildHtml('product_type_data') ?>
    <?php echo $this->getTierPriceHtml() ?>
    <?php echo $this->getChildHtml('extrahint') ?>
...

    <?php if ($_product->getShortDescription()):?>
        <div class="short-description">
            <h2><?php echo $this->__('Quick Overview') ?></h2>
            <div class="std"><?php echo $_helper->productAttribute($_product, nl2br($_product->getShortDescription()), 'short_description') ?></div>
        </div>
    <?php endif;?>
...
</div>
```

以下是 MVC 的块图：

![解剖布局文件](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mgt-php-dev-gd/img/3060OS_02_02.jpg)

## 控制器

在 Magento 中，MVC 控制器被设计为薄控制器；薄控制器几乎没有业务逻辑，主要用于驱动应用程序请求。基本的 Magento 控制器动作只是加载和渲染布局：

```php
    public function viewAction()
    {
        $this->loadLayout();
        $this->renderLayout();
    }
```

从这里开始，块的工作是处理显示逻辑，从我们的模型中获取数据，准备数据，并将其发送到视图。

# 网站和商店范围

Magento 的一个核心特性是能够使用单个 Magento 安装处理多个网站和商店；在内部，Magento 将这些实例称为范围。

![网站和商店范围](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mgt-php-dev-gd/img/3060OS_02_06.jpg)

某些元素的值，如产品、类别、属性和配置，是特定范围的，并且在不同的范围上可能不同；这使得 Magento 具有极大的灵活性，例如，一个产品可以在两个不同的网站上设置不同的价格，但仍然可以共享其余的属性配置。

作为开发人员，我们在使用范围最多的领域之一是在处理配置时。Magento 中可用的不同配置范围包括：

+   **全局**：顾名思义，这适用于所有范围。

+   **网站**：这些由域名定义，由一个或多个商店组成。网站可以设置共享客户数据或完全隔离。

+   **商店**：商店用于管理产品和类别，并分组商店视图。商店还有一个根类别，允许我们每个商店有单独的目录。

+   **商店视图**：通过使用商店视图，我们可以在商店前端设置多种语言。

Magento 中的配置选项可以在三个范围（全局、网站和商店视图）上存储值；默认情况下，所有值都设置在全局范围上。通过在我们的模块上使用`system.xml`，我们可以指定配置选项可以设置的范围；让我们重新审视一下我们之前的`system.xml`：

```php
…
<field_name translate="label comment">
    <label>Enabled</label>
    <comment>
         <![CDATA[Comments can contain <strong>HTML</strong>]]>
     </comment>
     <frontend_type>select</frontend_type>
     <source_model>adminhtml/system_config_source_yesno</source_model>
     <sort_order>10</sort_order>
     <show_in_default>1</show_in_default>
     <show_in_website>1</show_in_website>
     <show_in_store>1</show_in_store>
</field_name>
…
```

# 工厂名称和函数

Magento 使用工厂方法来实例化`Model`、`Helper`和`Block`类。工厂方法是一种设计模式，允许我们实例化一个对象而不使用确切的类名，而是使用类别名。

Magento 实现了几种工厂方法，如下所示：

+   `Mage::getModel()`

+   `Mage::getResourceModel()`

+   `Mage::helper()`

+   `Mage::getSingleton()`

+   `Mage::getResourceSingleton()`

+   `Mage::getResourceHelper()`

这些方法中的每一个都需要一个类别名，用于确定我们要实例化的对象的真实类名；例如，如果我们想要实例化一个`product`对象，可以通过调用`getModel()`方法来实现：

```php
$product = Mage::getModel('catalog/product'); 
```

请注意，我们正在传递一个由`group_classname/model_name`组成的工厂名称；Magento 将解析这个工厂名称为`Mage_Catalog_Model_Product`的实际类名。让我们更仔细地看看`getModel()`的内部工作：

```php
public static function getModel($modelClass = '', $arguments = array())
    {
        return self::getConfig()->getModelInstance($modelClass, $arguments);
    }

getModel calls the getModelInstance from the Mage_Core_Model_Config class.

public function getModelInstance($modelClass='', $constructArguments=array())
{
    $className = $this->getModelClassName($modelClass);
    if (class_exists($className)) {
        Varien_Profiler::start('CORE::create_object_of::'.$className);
        $obj = new $className($constructArguments);
        Varien_Profiler::stop('CORE::create_object_of::'.$className);
        return $obj;
    } else {
        return false;
    }
}
```

`getModelInstance()`又调用`getModelClassName()`方法，该方法以我们的类别名作为参数。然后它尝试验证返回的类是否存在，如果类存在，它将创建该类的一个新实例并返回给我们的`getModel()`方法：

```php
public function getModelClassName($modelClass)
{
    $modelClass = trim($modelClass);
    if (strpos($modelClass, '/')===false) {
        return $modelClass;
    }
    return $this->getGroupedClassName('model', $modelClass);
}
```

`getModelClassName()`调用`getGroupedClassName()`方法，实际上负责返回我们模型的真实类名。

`getGroupedClassName()`接受两个参数 - `$groupType`和`$classId`；`$groupType`指的是我们正在尝试实例化的对象类型（目前只支持模型、块和助手），`$classId`是我们正在尝试实例化的对象。

```php
public function getGroupedClassName($groupType, $classId, $groupRootNode=null)
{
    if (empty($groupRootNode)) {
        $groupRootNode = 'global/'.$groupType.'s';
    }
    $classArr = explode('/', trim($classId));
    $group = $classArr[0];
    $class = !empty($classArr[1]) ? $classArr[1] : null;

    if (isset($this->_classNameCache[$groupRootNode][$group][$class])) {
        return $this->_classNameCache[$groupRootNode][$group][$class];
    }
    $config = $this->_xml->global->{$groupType.'s'}->{$group};
    $className = null;
    if (isset($config->rewrite->$class)) {
        $className = (string)$config->rewrite->$class;
    } else {
        if ($config->deprecatedNode) {
            $deprecatedNode = $config->deprecatedNode;
            $configOld = $this->_xml->global->{$groupType.'s'}->$deprecatedNode;
            if (isset($configOld->rewrite->$class)) {
                $className = (string) $configOld->rewrite->$class;
            }
        }
    }
    if (empty($className)) {
        if (!empty($config)) {
            $className = $config->getClassName();
        }
        if (empty($className)) {
            $className = 'mage_'.$group.'_'.$groupType;
        }
        if (!empty($class)) {
            $className .= '_'.$class;
        }
        $className = uc_words($className);
    }
    $this->_classNameCache[$groupRootNode][$group][$class] = $className;
    return $className;
}
```

正如我们所看到的，`getGroupedClassName()`实际上正在做所有的工作；它抓取我们的类别名`catalog`/`product`，并通过在斜杠字符上分割字符串来创建一个数组。

然后，它加载一个`VarienSimplexml_Element`的实例，并传递我们数组中的第一个值（`group_classname`）。它还会检查类是否已被重写，如果是，我们将使用相应的组名。

Magento 还使用了`uc_words()`函数的自定义版本，如果需要，它将大写类别名的第一个字母并转换分隔符。

最后，该函数将返回真实的类名给`getModelInstance()`函数；在我们的例子中，它将返回`Mage_Catalog_Model_Product`。

![工厂名称和函数](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mgt-php-dev-gd/img/3060OS_02_04.jpg)

# 事件和观察者

事件和观察者模式可能是 Magento 更有趣的特性之一，因为它允许开发人员在应用程序流的关键部分扩展 Magento。

为了提供更多的灵活性并促进不同模块之间的交互，Magento 实现了事件/观察者模式；这种模式允许模块之间松散耦合。

这个系统有两个部分 - 一个是带有对象和事件信息的事件分发，另一个是监听特定事件的观察者。

![事件和观察者](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mgt-php-dev-gd/img/3060OS_02_05.jpg)

## 事件分发

使用`Mage::dispatchEvent()`函数创建或分派事件。核心团队已经在核心的关键部分创建了几个事件。例如，模型抽象类`Mage_Core_Model_Abstract`在每次保存模型时调用两个受保护的函数——`_beforeSave()`和`_afterSave()`；在这些方法中，每个方法都会触发两个事件：

```php
protected function _beforeSave()
{
    if (!$this->getId()) {
        $this->isObjectNew(true);
    }
    Mage::dispatchEvent('model_save_before', array('object'=>$this));
    Mage::dispatchEvent($this->_eventPrefix.'_save_before', $this->_getEventData());
    return $this;
}

protected function _afterSave()
{
    $this->cleanModelCache();
    Mage::dispatchEvent('model_save_after', array('object'=>$this));
    Mage::dispatchEvent($this->_eventPrefix.'_save_after', $this->_getEventData());
    return $this;
}
```

每个函数都会触发一个通用的`mode_save_after`事件，然后根据正在保存的对象类型生成一个动态版本。这为我们通过观察者操作对象提供了广泛的可能性。

`Mage::dispatchEvent()`方法接受两个参数：第一个是事件名称，第二个是观察者接收的数据数组。我们可以在这个数组中传递值或对象。如果我们想要操作对象，这将非常方便。

为了理解事件系统的细节，让我们来看一下`dispatchEvent()`方法：

```php
public static function dispatchEvent($name, array $data = array())
{
    $result = self::app()->dispatchEvent($name, $data);
    return $result;
}
```

这个函数实际上是位于`Mage_Core_Model_App`中的`app`核心类内部的`dispatchEvent()`函数的别名：

```php
public function dispatchEvent($eventName, $args)
{
    foreach ($this->_events as $area=>$events) {
        if (!isset($events[$eventName])) {
            $eventConfig = $this->getConfig()->getEventConfig($area, $eventName);
            if (!$eventConfig) {
                $this->_events[$area][$eventName] = false;
                continue;
            }
            $observers = array();
            foreach ($eventConfig->observers->children() as $obsName=>$obsConfig) {
                $observers[$obsName] = array(
                    'type'  => (string)$obsConfig->type,
                    'model' => $obsConfig->class ? (string)$obsConfig->class : $obsConfig->getClassName(),
                    'method'=> (string)$obsConfig->method,
                    'args'  => (array)$obsConfig->args,
                );
            }
            $events[$eventName]['observers'] = $observers;
            $this->_events[$area][$eventName]['observers'] = $observers;
        }
        if (false===$events[$eventName]) {
            continue;
        } else {
            $event = new Varien_Event($args);
            $event->setName($eventName);
            $observer = new Varien_Event_Observer();
        }

        foreach ($events[$eventName]['observers'] as $obsName=>$obs) {
            $observer->setData(array('event'=>$event));
            Varien_Profiler::start('OBSERVER: '.$obsName);
            switch ($obs['type']) {
                case 'disabled':
                    break;
                case 'object':
                case 'model':
                    $method = $obs['method'];
                    $observer->addData($args);
                    $object = Mage::getModel($obs['model']);
                    $this->_callObserverMethod($object, $method, $observer);
                    break;
                default:
                    $method = $obs['method'];
                    $observer->addData($args);
                    $object = Mage::getSingleton($obs['model']);
                    $this->_callObserverMethod($object, $method, $observer);
                    break;
            }
            Varien_Profiler::stop('OBSERVER: '.$obsName);
        }
    }
    return $this;
}
```

`dispatchEvent()`方法实际上是在事件/观察者模型上进行所有工作的：

1.  它获取 Magento 配置对象。

1.  它遍历观察者节点的子节点，检查定义的观察者是否正在监听当前事件。

1.  对于每个可用的观察者，分派事件将尝试实例化观察者对象。

1.  最后，Magento 将尝试调用与特定事件相映射的相应观察者函数。

## 观察者绑定

现在，分派事件是方程式的唯一部分。我们还需要告诉 Magento 哪个观察者正在监听每个事件。毫不奇怪，观察者是通过`config.xml`指定的。正如我们之前所看到的，`dispatchEvent()`函数会查询配置对象以获取可用的观察者。让我们来看一个示例`config.xml`文件：

```php
<events>
    <event_name>
        <observers>
            <observer_identifier>
                <class>module_name/observer</class>
                <method>function_name</method>
            </observer_identifier>
        </observers>
    </event_name>
</events>
```

`event`节点可以在每个配置部分（admin、global、frontend 等）中指定，并且我们可以指定多个`event_name`子节点；`event_name`必须与`dispatchEvent()`函数中使用的事件名称匹配。

在每个`event_name`节点内，我们有一个单一的观察者节点，可以包含多个观察者，每个观察者都有一个唯一的标识符。

观察者节点有两个属性，如`<class>`，指向我们的观察者模型类，和`<method>`，依次指向观察者类内部的实际方法。让我们分析一个示例观察者类定义：

```php
class Namespace_Modulename_Model_Observer
{
    public function methodName(Varien_Event_Observer $observer)
    {
        //some code
    }
}  
```

### 注意

关于观察者模型的一个有趣的事情是，它们不继承任何其他 Magento 类。

# 摘要

在本章中，我们涵盖了许多关于 Magento 的重要和基本主题，如其架构、文件夹结构、路由系统、MVC 模式、事件和观察者以及配置范围。

虽然乍一看可能会让人感到不知所措，但这只是冰山一角。关于每个主题和 Magento，还有很多值得学习的地方。本章的目的是让开发人员了解从配置对象到事件/对象模式的实现方式的所有重要组件。

Magento 是一个强大而灵活的系统，它远不止是一个电子商务平台。核心团队在使 Magento 成为一个强大的框架方面付出了很多努力。

在后面的章节中，我们不仅会更详细地回顾所有这些概念，还会通过构建我们自己的扩展来实际应用它们。


# 第三章：ORM 和数据集合

集合和模型是日常 Magento 开发的基础。在本章中，我们将向读者介绍 Magento ORM 系统，并学习如何正确地处理数据集合和 EAV 系统。与大多数现代系统一样，Magento 实现了一个**对象关系映射**（**ORM**）系统。

> *对象关系映射（ORM，O/RM 和 O/R 映射）是计算机软件中的一种编程技术，用于在面向对象的编程语言中在不兼容的类型系统之间转换数据。这实际上创建了一个可以从编程语言内部使用的“虚拟对象数据库”。

在本章中，我们将涵盖以下主题：

+   Magento 模型

+   Magento 数据模型的解剖学

+   EAV 和 EAV 模型

+   使用直接 SQL 查询

我们还将使用几个代码片段来提供一个方便的框架，以便在 Magento 中进行实验和玩耍。

### 注意

请注意，本章中的交互式示例假定您正在使用 VagrantBox 内的默认 Magento 安装或带有示例数据的 Magento 安装。

为此，我创建了**交互式 Magento 控制台**（**IMC**），这是一个专门为本书创建的 shell 脚本，受 Ruby 自己的**交互式 Ruby 控制台**（**IRB**）启发。请按照以下步骤：

1.  我们需要做的第一件事是安装 IMC。为此，请从[`github.com/amacgregor/mdg_imc`](https://github.com/amacgregor/mdg_imc)下载源文件，并将其提取到 Magento 测试安装下。IMC 是一个简单的 Magento shell 脚本，可以让我们实时测试我们的代码。

1.  提取脚本后，登录到您的虚拟机的 shell。

1.  接下来，我们需要导航到我们的 Magento 根文件夹。如果您正在使用默认的 vagrant box，安装已经提供；根文件夹位于`/srv/www/ce1720/public_html/`下，我们可以通过运行以下命令行来导航到它：

```php
**$ cd /srv/www/ce1720/public_html**

```

1.  最后，我们可以通过运行以下命令行来启动 IMC：

```php
**$ php shell/imc.php**

```

1.  如果一切安装成功，我们应该看到一行新的以`magento >`开头的内容。

# Magento 模型解剖学

正如我们在上一章中学到的，Magento 数据模型用于操作和访问数据。模型层分为两种基本类型，简单模型和 EAV，其中：

+   **简单模型**：这些模型实现是一个对象到一个表的简单映射，这意味着我们的对象属性与每个字段匹配，我们的表结构

+   **实体属性值模型（EAV）**：这种类型的模型用于描述具有动态属性数量的实体

### 注意

请注意，重要的是要澄清并非所有 Magento 模型都扩展或使用 ORM。观察者是一个明显的例子，它们是不与特定数据库表或实体映射的简单模型类。

除此之外，每种模型类型由以下层组成：

+   **模型类**：这是大部分业务逻辑所在的地方。模型用于操作数据，但不直接访问数据。

+   **资源模型类**：资源模型用于代表我们的模型与数据库交互。它们负责实际的 CRUD 操作。

+   **模型集合类**：每个数据模型都有一个集合类；集合是保存多个单独的 Magento 模型实例的对象。

### 注意

CRUD 代表数据库的四种基本操作：创建、读取、更新和删除。

Magento 模型不包含与数据库通信的任何逻辑；它们是与数据库无关的。相反，这些代码存在于资源模型层。

这使 Magento 有能力支持不同类型的数据库和平台。尽管目前只有 MySQL 得到官方支持，但完全可以编写一个新的资源类来支持新的数据库，而不用触及任何模型逻辑。

![Magento 模型解剖](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mgt-php-dev-gd/img/3060OS_03_01.jpg)

现在让我们通过实例化一个产品对象并按照以下步骤设置一些属性来进行实验：

1.  启动 Magento 交互式控制台，运行在 Magento 分期安装根目录下：

```php
**php shell/imc.php**

```

1.  我们的第一步是通过输入来创建一个新的产品对象实例：

```php
**magento> $product = Mage::getModel('catalog/product');**

```

1.  我们可以通过运行以下命令来确认这是否是产品类的空实例：

```php
**magento> echo get_class($product);**

```

1.  我们应该看到以下成功的输出：

```php
**magento> Magento_Catalog_Model_Product**

```

1.  如果我们想了解更多关于类方法的信息，可以运行以下命令行：

```php
**magento> print_r(get_class_methods($product));**

```

这将返回一个包含类内所有可用方法的数组。让我们尝试运行以下代码片段并修改产品的价格和名称：

```php
$product = Mage::getModel('catalog/product')->load(2);
$name    = $product->getName() . '-TEST';
$price   = $product->getPrice();
$product->setPrice($price + 15);
$product->setName($name);
$product->save();
```

在第一行代码中，我们实例化了一个特定的对象，然后我们继续从对象中检索名称属性。接下来，我们设置价格和名称，最后保存对象。

如果我们打开我们的 Magento 产品类`Mage_Catalog_Model_Product`，我们会注意到虽然`getName()`和`getPrice()`都在我们的类中定义了，但是`setPrice()`和`setName()`函数却没有在任何地方定义。

但是为什么，更重要的是，Magento 是如何神奇地定义每个产品对象的 setter 和 getter 方法的呢？虽然`getPrice()`和`getName()`确实被定义了，但是对于产品属性的任何 getter 和 setter 方法，比如颜色或制造商，都没有定义。

## 这是魔法-方法

事实上，Magento ORM 系统确实使用了魔术；或者更准确地说，使用了 PHP 更强大的特性来实现其 getter 和 setter，即`magic __call()`方法。Magento 中使用的方法用于设置、取消设置、检查或检索数据。

当我们尝试调用一个实际上在相应类中不存在的方法时，PHP 将查找每个父类中是否有该方法的声明。如果我们在任何父类中找不到该函数，它将使用最后的手段并尝试使用`__call()`方法，如果找到，Magento（或者 PHP）将调用魔术方法，从而传递请求的方法名和其参数。

现在，产品模型没有定义`__call()`方法，但是它从所有 Magento 模型继承的`Varien_Object`类中获得了一个。`Mage_Catalog_Model_Product`类的继承树如下流程图所示：

![这是魔法-方法](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mgt-php-dev-gd/img/3060OS_03_02.jpg)

### 提示

每个 Magento 模型都继承自`Varien_Object`类。

让我们更仔细地看一下`Varien_Object`类：

1.  打开位于`magento_root/lib/Varien/Object.php`中的文件。

1.  `Varien_Object`类不仅有一个`__call()`方法，还有两个已弃用的方法，`__set()`和`__get()`；这两个方法被`__call()`方法替代，因此不再使用。

```php
public function __call($method, $args)
{
   switch (substr($method, 0, 3)) {
       case 'get' :
           //Varien_Profiler::start('GETTER: '.get_class($this).'::'.$method);
           $key = $this->_underscore(substr($method,3));
           $data = $this->getData($key, isset($args[0]) ? $args[0] : null);
           //Varien_Profiler::stop('GETTER: '.get_class($this).'::'.$method);
           return $data;

       case 'set' :
           //Varien_Profiler::start('SETTER: '.get_class($this).'::'.$method);
           $key = $this->_underscore(substr($method,3));
           $result = $this->setData($key, isset($args[0]) ? $args[0] : null);
           //Varien_Profiler::stop('SETTER: '.get_class($this).'::'.$method);
           return $result;

       case 'uns' :
           //Varien_Profiler::start('UNS: '.get_class($this).'::'.$method);
           $key = $this->_underscore(substr($method,3));
           $result = $this->unsetData($key);
           //Varien_Profiler::stop('UNS: '.get_class($this).'::'.$method);
           return $result;
       case 'has' :
           //Varien_Profiler::start('HAS: '.get_class($this).'::'.$method);
           $key = $this->_underscore(substr($method,3));
           //Varien_Profiler::stop('HAS: '.get_class($this).'::'.$method);
           return isset($this->_data[$key]);
   }
   throw new Varien_Exception("Invalid method" . get_class($this)."::".$method."(".print_r($args,1).")");
}
```

在`__call()`方法内部，我们有一个 switch 语句，不仅处理 getter 和 setter，还处理`unset`和`has`函数。

如果我们启动调试器并跟踪我们的代码片段调用`__call()`方法，我们可以看到它接收两个参数：方法名，例如`setName()`，以及原始调用的参数。

有趣的是，Magento 尝试根据被调用方法的前三个字母来匹配相应的方法类型；这是在 switch case 参数调用 substring 函数时完成的：

```php
substr($method, 0, 3)
```

在每种情况下调用的第一件事是`_underscore()`函数，它以方法名的前三个字符之后的任何内容作为参数；按照我们的例子，传递的参数将是`Name`。

`__underscore()`函数返回一个数据键。然后每种情况下都使用这个键来操作数据。有四种基本的数据操作，每种操作对应一个 switch case：

+   `setData($parameters)`

+   `getData($parameters)`

+   `unsetData($parameters)`

+   `isset($parameters)`

这些函数中的每一个都将与`Varien_Object`数据数组交互，并相应地对其进行操作。在大多数情况下，将使用魔术 set/get 方法与我们的对象属性交互；只有在需要额外的业务逻辑时，才会定义 getter 和 setter。在我们的示例中，它们是`getName()`和`getPrice()`。

```php
public function getPrice()
{
   if ($this->_calculatePrice || !$this->getData('price')) {
       return $this->getPriceModel()->getPrice($this);
   } else {
       return $this->getData('price');
   }
}
```

我们不会详细介绍价格函数实际在做什么，但它清楚地说明了对模型的某些部分可能需要额外的逻辑。

```php
public function getName()
{
   return $this->_getData('name');
}
```

另一方面，`getName()`getter 并不是因为需要实现特殊逻辑而声明的，而是因为需要优化 Magento 的一个关键部分。`Mage_Catalog_Model_Product getName()`函数可能在每次页面加载时被调用数百次，是 Magento 中最常用的函数之一；毕竟，如果它不是围绕产品中心的电子商务平台，那它会是什么样子呢？

前端和后端都会在某个时候调用`getName()`函数。例如，如果我们加载一个包含 24 个产品的类别页面，也就是说，`getName()`函数会被调用 24 次，每次调用都会在父类中寻找`getName()`方法，然后当我们尝试使用`magic __call()`方法时，会导致丢失宝贵的毫秒。

资源模型包含所有特定于数据库的逻辑，并为其相应的数据源实例化特定的读取和写入适配器。让我们回到我们的产品示例，并查看位于`Mage_Catalog_Model_Resource_Product`的产品资源模型。

![这是魔术-方法](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mgt-php-dev-gd/img/3060OS_03_03.jpg)

资源模型有两种不同类型：实体和 MySQL4。后者是一个相当标准的单表/单模型关联，而前者则复杂得多。

# EAV 模型

EAV 代表实体、属性和值，这可能是新 Magento 开发人员难以理解的概念。虽然 EAV 概念并不是 Magento 独有的，但它在现代系统中很少实现，而且 Magento 的实现也并不简单。

![EAV 模型](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mgt-php-dev-gd/img/3060OS_03_04.jpg)

## 什么是 EAV？

为了理解 EAV 是什么以及它在 Magento 中的作用，我们需要将其分解为 EAV 模型的各个部分。

+   **实体**：实体代表 Magento 产品、客户、类别和订单中的数据项（对象）。每个实体都以唯一 ID 存储在数据库中。

+   **属性**：这些是我们的对象属性。与产品表上每个属性都有一列不同，属性存储在单独的表集上。

+   **值**：顾名思义，它只是与特定属性相关联的值链接。

这种设计模式是 Magento 灵活性和强大性的秘密，允许实体添加和删除新属性，而无需对代码或模板进行任何更改。

虽然模型可以被视为增加数据库的垂直方式（新属性增加更多行），传统模型将涉及水平增长模式（新属性增加更多列），这将导致每次添加新属性时都需要对模式进行重新设计。

EAV 模型不仅允许我们的数据库快速发展，而且更有效，因为它只处理非空属性，避免了为 null 值在数据库中保留额外空间的需要。

### 提示

如果您有兴趣探索和了解 Magento 数据库结构，我强烈建议您访问[www.magereverse.com](http://www.magereverse.com)。

添加新产品属性就像进入 Magento 后端并指定新属性类型一样简单，比如颜色、尺寸、品牌等。相反的也是真的，因为我们可以在我们的产品或客户模型上摆脱未使用的属性。

### 注意

有关管理属性的更多信息，请访问[`www.magentocommerce.com/knowledge-base/entry/how-do-attributes-work-in-magento`](http://www.magentocommerce.com/knowledge-base/entry/how-do-attributes-work-in-magento)。

Magento 社区版目前有八种不同类型的 EAV 对象：

+   客户

+   客户地址

+   产品

+   产品类别

+   订单

+   发票

+   信贷备忘录

+   发货

### 注意

Magento 企业版有一个额外的类型称为 RMA 项目，它是**退货授权**（RMA）系统的一部分。

所有这些灵活性和功能都是有代价的；实施 EAV 模型会导致我们的实体数据分布在大量的表中，例如，仅产品模型就分布在大约 40 个不同的表中。

以下图表仅显示了保存 Magento 产品信息所涉及的一些表：

![什么是 EAV？](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mgt-php-dev-gd/img/3060OS_03_05.jpg)

EAV 的另一个主要缺点是在检索大量 EAV 对象时性能下降，数据库查询复杂性增加。由于数据更分散（存储在更多的表中），选择单个记录涉及多个连接。

让我们继续以 Magento 产品作为示例，并手动构建检索单个产品的查询。

### 提示

如果您在开发环境中安装了 PHPMyAdmin 或 MySQL Workbench，可以尝试以下查询。可以从 PHPMyAdmin（[`www.phpmyadmin.net/`](http://www.phpmyadmin.net/)）和 MySQL Workbench（[`www.mysql.com/products/workbench/`](http://www.mysql.com/products/workbench/)）下载每个查询。

我们需要使用的第一个表是`catalog_product_entity`。我们可以将其视为我们的主要产品 EAV 表，因为它包含了我们产品的主要实体记录：

![什么是 EAV？](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mgt-php-dev-gd/img/3060OS_03_06_revised.jpg)

通过运行以下 SQL 查询来查询表：

```php
SELECT * FROM `catalog_product_entity`;
```

该表包含以下字段：

+   `entity_id`：这是我们产品的唯一标识符，由 Magento 在内部使用。

+   `entity_type_id`：Magento 有几种不同类型的 EAV 模型，产品、客户和订单，这些只是其中一些。通过类型标识，Magento 可以从适当的表中检索属性和值。

+   `attribute_set_id`：产品属性可以在本地分组到属性集中。属性集允许对产品结构进行更灵活的设置，因为产品不需要使用所有可用的属性。

+   `type_id`：Magento 中有几种不同类型的产品：简单、可配置、捆绑、可下载和分组产品，每种产品都具有独特的设置和功能。

+   `sku`：**库存保留单位**（SKU）是用于标识商店中每个唯一产品或商品的编号或代码。这是用户定义的值。

+   `has_options`：这用于标识产品是否具有自定义选项。

+   `required_options`：这用于标识是否需要任何自定义选项。

+   `created_at`：这是行创建日期。

+   `updated_at`：显示行上次修改的时间。

现在我们对产品实体表有了基本的了解，我们也知道每条记录代表着我们 Magento 商店中的一个产品，但是我们对该产品的信息并不多，除了 SKU 和产品类型之外。

那么，属性存储在哪里？Magento 如何区分产品属性和客户属性？

为此，我们需要通过运行以下 SQL 查询来查看`eav_attribute`表：

```php
SELECT * FROM `eav_attribute`;
```

因此，我们不仅会看到产品属性，还会看到与客户模型、订单模型等对应的属性。幸运的是，我们已经有一个用于从该表中过滤属性的关键。让我们运行以下查询：

```php
SELECT * FROM `eav_attribute`
WHERE entity_type_id = 4;
```

这个查询告诉数据库只检索`entity_type_id`列等于产品`entity_type_id(4)`的属性。在继续之前，让我们分析`eav_attribute`表中最重要的字段：

+   `attribute_id`: 这是每个属性的唯一标识符和表的主键。

+   `entity_type_id`: 这个字段将每个属性关联到特定的 EAV 模型类型。

+   `attribute_code`: 这个字段是我们属性的名称或键，用于生成我们的魔术方法的 getter 和 setter。

+   `backend_model`: 后端模型负责加载和存储数据到数据库中。

+   `backend_type`: 这个字段指定存储在后端（数据库）的值的类型。

+   `backend_table`: 这个字段用于指定属性是否应该存储在特殊表中，而不是默认的 EAV 表中。

+   `frontend_model`: 前端模型处理属性元素在 web 浏览器中的呈现。

+   `frontend_input`: 类似于前端模型，前端输入指定 web 浏览器应该呈现的输入字段类型。

+   `frontend_label`: 这个字段是属性的标签/名称，应该由浏览器呈现。

+   `source_model`: 源模型用于为属性填充可能的值。Magento 带有几个预定义的源模型，用于国家、是或否值、地区等。

## 检索数据

此时，我们已经成功检索了一个产品实体和适用于该实体的特定属性，现在是时候开始检索实际的值了。为了简单执行示例（和查询），我们将尝试只检索我们产品的名称属性。

但是，我们如何知道我们的属性值存储在哪个表中？幸运的是，Magento 遵循了一种命名约定来命名表。如果我们检查我们的数据库结构，我们会注意到有几个表使用`catalog_product_entity`前缀：

+   `catalog_product_entity`

+   `catalog_product_entity_datetime`

+   `catalog_product_entity_decimal`

+   `catalog_product_entity_int`

+   `catalog_product_entity_text`

+   `catalog_product_entity_varchar`

+   `catalog_product_entity_gallery`

+   `catalog_product_entity_media_gallery`

+   `catalog_product_entity_tier_price`

但是，等等，我们如何知道查询我们名称属性值的正确表？如果你在关注，我们已经看到了答案。你还记得`eav_attribute`表有一个叫做`backend_type`的列吗？

Magento EAV 根据属性的后端类型将每个属性存储在不同的表中。如果我们想确认我们的名称的后端类型，可以通过运行以下代码来实现：

```php
SELECT * FROM `eav_attribute`
WHERE `entity_type_id` =4 AND `attribute_code` = 'name';
```

并且我们应该看到，后端类型是`varchar`，这个属性的值存储在`catalog_product_entity_varchar`表中。让我们检查这个表：

![检索数据](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mgt-php-dev-gd/img/3060OS_03_07.jpg)

`catalog_product_entity_varchar`表只由六列组成：

+   `value_id`: 属性值是唯一标识符和主键

+   `entity_type_id`: 这个值属于实体类型 ID

+   `attribute_id`: 这是一个外键，将值与我们的`eav_entity`表关联起来

+   `store_id`: 这是一个外键，将属性值与 storeview 进行匹配

+   `entity_id`: 这是对应实体表的外键；在这种情况下，它是`catalog_product_entity`

+   `value`: 这是我们要检索的实际值

### 提示

根据属性配置，我们可以将其作为全局值，表示它适用于所有 storeview，或者作为每个 storeview 的值。

现在我们终于有了检索产品信息所需的所有表，我们可以构建我们的查询：

```php
SELECT p.entity_id AS product_id, var.value AS product_name, p.sku AS product_sku
FROM catalog_product_entity p, eav_attribute eav, catalog_product_entity_varchar var
WHERE p.entity_type_id = eav.entity_type_id 
   AND var.entity_id = p.entity_id
   AND eav.attribute_code = 'name'
   AND eav.attribute_id = var.attribute_id
```

![检索数据](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mgt-php-dev-gd/img/3060OS_03_08.jpg)

作为查询结果，我们应该看到一个包含三列的结果集：`product_id`，`product_name`和`product_sku`。因此，让我们退后一步，以便获取产品名称和 SKU。使用原始 SQL，我们将不得不编写一个五行的 SQL 查询，我们只能从我们的产品中检索两个值：如果我们想要检索数字字段，比如价格，或者从文本值，比如产品，我们只能从一个单一的 EAV 值表中检索。

如果我们没有 ORM，维护 Magento 几乎是不可能的。幸运的是，我们有一个 ORM，并且很可能你永远不需要处理 Magento 的原始 SQL。

说到这里，让我们看看如何使用 Magento ORM 来检索相同的产品信息：

1.  我们的第一步是实例化一个产品集合：

```php
**$collection = Mage::getModel('catalog/product')->getCollection();**

```

1.  然后，我们将明确告诉 Magento 选择名称属性：

```php
**$collection->addAttributeToSelect('name');**

```

1.  现在按名称对集合进行排序：

```php
**$collection->setOrder('name', 'asc');**

```

1.  最后，我们将告诉 Magento 加载集合：

```php
**$collection->load();**

```

1.  最终结果是商店中所有产品的集合按名称排序；我们可以通过运行以下命令来检查实际的 SQL 查询：

```php
**echo $collection->getSelect()->__toString();**

```

仅仅通过三行代码的帮助，我们就能告诉 Magento 抓取商店中的所有产品，具体选择名称，并最终按名称排序产品。

### 提示

最后一行`$collection->getSelect()->__toString()`，允许我们查看 Magento 代表我们执行的实际查询。

Magento 生成的实际查询是：

```php
SELECT `e`.*. IF( at_name.value_id >0, at_name.value, at_name_default.value ) AS `name`
FROM `catalog_product_entity` AS `e`
LEFT JOIN `catalog_product_entity_varchar` AS `at_name_default` ON (`at_name_default`.`entity_id` = `e`.`entity_id`)
AND (`at_name_default`.`attribute_id` = '65')
AND `at_name_default`.`store_id` =0
LEFT JOIN `catalog_product_entity_varchar` AS `at_name` ON ( `at_name`.`entity_id` = `e`.`entity_id` )
AND (`at_name`.`attribute_id` = '65')
AND (`at_name`.`store_id` =1)
ORDER BY `name` ASC
```

正如我们所看到的，ORM 和 EAV 模型是非常棒的工具，不仅为开发人员提供了很多功能和灵活性，而且还以一种全面易用的方式实现了这一点。

# 使用 Magento 集合

如果您回顾前面的代码示例，您可能会注意到我们不仅实例化了一个产品模型，还调用了`getCollection()`方法。`getCollection()`方法是`Mage_Core_Model_Abstract`类的一部分，这意味着 Magento 中的每个单个模型都可以调用此方法。

### 提示

所有集合都继承自`Varien_Data_Collection`。

Magento 集合基本上是包含其他模型的模型。因此，我们可以使用产品集合而不是使用数组来保存产品集合。集合不仅提供了一个方便的数据结构来对模型进行分组，还提供了特殊的方法，我们可以用来操作和处理实体的集合。

一些最有用的集合方法是：

+   `addAttributeToSelect`：要向集合中的实体添加属性，可以使用`*`作为通配符来添加所有可用的属性

+   `addFieldToFilter`：要向集合添加属性过滤器，需要在常规的非 EAV 模型上使用此函数

+   `addAttributeToFilter`：此方法用于过滤 EAV 实体的集合

+   `addAttributeToSort`：此方法用于添加属性以排序顺序

+   `addStoreFilter`：此方法用于存储可用性过滤器；它包括可用性产品

+   `addWebsiteFilter`：此方法用于向集合添加网站过滤器

+   `addCategoryFilter`：此方法用于为产品集合指定类别过滤器

+   `addUrlRewrite`：此方法用于向产品添加 URL 重写数据

+   `setOrder`：此方法用于设置集合的排序顺序

这些只是一些可用的集合方法；每个集合实现了不同的独特方法，具体取决于它们对应的实体类型。例如，客户集合`Mage_Customer_Model_Resource_Customer_Collection`有一个称为`groupByEmail()`的唯一方法，它的名称正确地暗示了通过电子邮件对集合中的实体进行分组。

与之前的示例一样，我们将继续使用产品模型，并在这种情况下是产品集合。

![使用 Magento 集合](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mgt-php-dev-gd/img/3060OS_03_09.jpg)

为了更好地说明我们如何使用集合，我们将处理以下常见的产品场景：

1.  仅从特定类别获取产品集合。

1.  获取自 X 日期以来的新产品。

1.  获取畅销产品。

1.  按可见性过滤产品集合。

1.  过滤没有图片的产品。

1.  添加多个排序顺序。

## 仅从特定类别获取产品集合

大多数开发人员在开始使用 Magento 时尝试做的第一件事是从特定类别加载产品集合，虽然我看到过许多使用`addCategoryFilter()`或`addAttributeToFilter()`的方法，但实际上，对于大多数情况来说，这种方法要简单得多，而且有点违反我们迄今为止学到的直觉。

最简单的方法不是首先获取产品集合，然后按类别进行过滤，而是实际上实例化我们的目标类别，并从那里获取产品集合。让我们在 IMC 上运行以下代码片段：

```php
$category = Mage::getModel('catalog/category')->load(5);
$productCollection = $category->getProductCollection();
```

我们可以在`Mage_Catalog_Model_Category`类中找到`getProductCollection()`方法的声明。让我们更仔细地看看这个方法：

```php
public function getProductCollection()
{
    $collection = Mage::getResourceModel('catalog/product_collection')
        ->setStoreId($this->getStoreId())
        ->addCategoryFilter($this);
    return $collection;
}
```

正如我们所看到的，该函数实际上只是实例化产品集合的资源模型，即将存储设置为当前存储 ID，并将当前类别传递给`addCategoryFilter()`方法。

这是为了优化 Magento 性能而做出的决定之一，而且坦率地说，也是为了简化与之合作的开发人员的生活，因为在大多数情况下，某种方式都会提供类别。

## 获取自 X 日期以来添加的新产品

现在，我们知道如何从特定类别获取产品集合，让我们看看是否能够对结果产品应用过滤器，并且只对符合我们条件的检索产品进行过滤；在这种特殊情况下，我们将请求所有在 2012 年 12 月之后添加的产品。根据我们之前的示例代码，我们可以通过在 IMC 上运行以下代码来按产品创建日期过滤我们的集合：

```php
// Product collection from our previous example
$productCollection->addFieldToFilter('created_at', array('from' => '2012-12-01));
```

很简单，不是吗？我们甚至可以添加一个额外的条件，并获取在两个日期之间添加的产品。假设我们只想检索在 12 月份创建的产品：

```php
$productCollection->addFieldToFilter('created_at', array('from' => '2012-12-01));
$productCollection->addFieldToFilter('created_at', array('to' => '2012-12-30));
```

Magento 的`addFieldToFilter`支持以下条件：

| 属性代码 | SQL 条件 |
| --- | --- |
| `eq` | `=` |
| `neq` | `!=` |
| `like` | `LIKE` |
| `nlike` | `NOT LIKE` |
| `in` | `IN ()` |
| `nin` | `NOT IN ()` |
| `is` | `IS` |
| `notnull` | `NOT NULL` |
| `null` | `NULL` |
| `moreq` | `>=` |
| `gt` | `>` |
| `lt` | `<` |
| `gteq` | `>=` |
| `lteq` | `<=` |

我们可以尝试其他类型的过滤器，例如，在添加了我们的创建日期过滤器后，在 IMC 上使用以下代码，这样我们就可以只检索可见产品：

```php
$productCollection->addAttributeToFilter('visibility', 4);
```

可见性属性是产品用来控制产品显示位置的特殊属性；它具有以下值：

+   **不单独可见**：它的值为 1

+   **目录**：它的值为 2

+   **搜索**：它的值为 3

+   **目录和搜索**：它的值为 4

## 获取畅销产品

要尝试获取特定类别的畅销产品，我们需要提升自己的水平，并与`sales_order`表进行连接。以后为了创建特殊类别或自定义报告，检索畅销产品将非常方便；我们可以在 IMC 上运行以下代码：

```php
$category = Mage::getModel('catalog/category')->load(5);
$productCollection = $category->getProductCollection();
$productCollection->getSelect()
            ->join(array('o'=> 'sales_flat_order_item'), 'main_table.entity_id = o.product_id', array('o.row_total','o.product_id'))->group(array('sku'));
```

让我们分析一下我们片段的第三行发生了什么。`getSelect()`是直接从`Varien_Data_Collection_Db`继承的方法，它返回存储`Select`语句的变量，除了提供指定连接和分组的方法之外，还无需编写任何 SQL。

这不是向集合添加连接的唯一方法。实际上，有一种更干净的方法可以使用`joinField()`函数来实现。让我们重写我们之前的代码以使用这个函数：

```php
$category = Mage::getModel('catalog/category')->load(5);
$productCollection = $category->getProductCollection();
$productCollection->joinField('o', 'sales_flat_order_item', array('o.row_total','o.product_id'), 'main_table.entity_id = o.product_id')
->group(array('sku'));
```

## 按可见性过滤产品集合

这在使用`addAttributeToFilter`的帮助下非常容易实现。Magento 产品有一个名为 visibility 的系统属性，它有四个可能的数字值，范围从 1 到 4。我们只对可见性为 4 的产品感兴趣；也就是说，它可以在搜索结果和目录中都能看到。让我们在 IMC 中运行以下代码：

```php
$category = Mage::getModel('catalog/category')->load(5);
$productCollection = $category->getProductCollection();
$productCollection->addAttributeToFilter('visibility', 4);
```

如果我们更改可见性代码，我们可以比较不同的集合结果。

## 过滤没有图像的产品

在处理第三方导入系统时，过滤没有图像的产品非常方便，因为这种系统有时可能不可靠。与我们迄今为止所做的一切一样，产品图像是我们产品的属性。

```php
$category = Mage::getModel('catalog/category')->load(5);
$productCollection = $category->getProductCollection();
$productCollection->addAttributeToFilter('small_image',array('notnull'=>'','neq'=>'no_selection'));
```

通过添加额外的过滤器，我们要求产品必须指定一个小图像；默认情况下，Magento 有三种产品：图像类型，缩略图和`small_image`和图像。这三种类型在应用程序的不同部分使用。如果我们愿意，甚至可以为产品设置更严格的规则。

```php
$productCollection->addAttributeToFilter('small_image', array('notnull'=>'','neq'=>'no_selection'));
->addAttributeToFilter('thumbnail, array('notnull'=>'','neq'=>'no_selection'))
->addAttributeToFilter('image', array('notnull'=>'','neq'=>'no_selection'));
```

只有具有三种类型图像的产品才会包含在我们的集合中。尝试通过不同的图像类型进行过滤。

## 添加多个排序顺序

最后，让我们先按库存状态排序，然后按价格从高到低排序我们的集合。为了检索库存状态信息，我们将使用一个特定于库存状态资源模型的方法`addStockStatusToSelect()`，它将负责为我们的集合查询生成相应的 SQL。

```php
$category = Mage::getModel('catalog/category')->load(5);
$productCollection = $category->getProductCollection();
$select = $productCollection->getSelect();
Mage::getResourceModel('cataloginventory/stock_status')->addStockStatusToSelect($select, Mage::app()->getWebsite());
$select->order('salable desc');
$select->order('price asc');
```

在这个查询中，Magento 将根据可销售状态（true 或 false）和价格对产品进行排序；最终结果是所有可用产品将显示从最昂贵到最便宜的产品，然后，缺货产品将显示从最昂贵到最便宜的产品。

尝试不同的排序顺序组合，看看 Magento 如何组织和排序产品集合。

# 使用直接 SQL

到目前为止，我们已经学习了 Magento 数据模型和 ORM 系统提供了一种清晰简单的方式来访问、存储和操作我们的数据。在我们直接进入本节之前，了解 Magento 数据库适配器以及如何运行原始 SQL 查询，我觉得重要的是我们要理解为什么尽可能避免使用你即将在本节中学到的内容。

Magento 是一个非常复杂的系统，正如我们在上一章中学到的，框架部分由事件驱动；仅仅保存一个产品就会触发不同的事件，每个事件执行不同的任务。如果你决定只创建一个查询并直接更新产品，这种情况就不会发生。因此，作为开发人员，我们必须非常小心，确保是否有正当理由去绕过 ORM。

也就是说，当然也有一些情况下，能够直接与数据库一起工作非常方便，实际上比使用 Magento 模型更简单。例如，当全局更新产品属性或更改产品集合状态时，我们可以加载产品集合并循环遍历每个单独的产品进行更新和保存。虽然这在较小的集合上可以正常工作，但一旦我们开始扩大规模并处理更大的数据集，性能就会开始下降，脚本执行需要几秒钟。

另一方面，直接的 SQL 查询将执行得更快，通常在 1 秒内，这取决于数据集的大小和正在执行的查询。

Magento 将负责处理与数据库建立连接的所有繁重工作，使用`Mage_Core_Model_Resource`模型；Magento 为我们提供了两种类型的连接，`core_read`和`core_write`。

让我们首先实例化一个资源模型和两个连接，一个用于读取，另一个用于写入：

```php
$resource = Mage::getModel('core/resource');
$read = $resource->getConnection('core_read');
$write = $resource->getConnection('core_write');
```

即使我们使用直接的 SQL 查询，由于 Magento 的存在，我们不必担心设置到数据库的连接，只需实例化一个资源模型和正确类型的连接。

## 阅读

让我们通过执行以下代码来测试我们的读取连接：

```php
$resource = Mage::getModel('core/resource');
$read = $resource->getConnection('core_read');
$query = 'SELECT * FROM catalog_product_entity';
$results = $read->fetchAll($query);
```

尽管此查询有效，但它将返回`catalog_product_entity`表中的所有产品。但是，如果我们尝试在使用表前缀的 Magento 安装上运行相同的代码会发生什么？或者如果 Magento 在下一个升级中突然更改了表名会发生什么？这段代码不具备可移植性或易维护性。幸运的是，资源模型提供了另一个方便的方法，称为`getTableName()`。

`getTableName()`方法将以工厂名称作为参数，并根据`config.xml`建立的配置，不仅会找到正确的表，还会验证该表是否存在于数据库中。让我们更新我们的代码以使用`getTableName()`：

```php
$resource = Mage::getModel('core/resource');
$read = $resource->getConnection('core_read');
$query = 'SELECT * FROM ' . $resource->getTableName('catalog/product');
$results = $read->fetchAll($query);
```

我们还在使用`fetchAll()`方法。这将以数组形式返回查询的所有行，但这并不是唯一的选项；我们还可以使用`fetchCol()`和`fetchOne()`。让我们看看以下函数：

+   `fetchAll`：此函数检索原始查询返回的所有行

+   `fetchOne`：此函数将仅返回查询返回的第一行数据库的值

+   `fetchCol`：此函数将返回查询返回的所有行，但只返回第一行；如果您只想检索具有唯一标识符的单个列，例如产品 ID 或 SKU，这将非常有用

## 写作

正如我们之前提到的，由于后端触发的观察者和事件数量，保存 Magento 中的模型（无论是产品、类别、客户等）可能相对较慢。

但是，如果我们只想更新简单的静态值，通过 Magento ORM 进行大型集合的更新可能是一个非常缓慢的过程。例如，假设我们想要使网站上的所有产品都缺货。我们可以简单地执行以下代码片段，而不是通过 Magento 后端进行操作或创建一个迭代所有产品集合的自定义脚本：

```php
$resource = Mage::getModel('core/resource');
$read = $resource->getConnection('core_write);
$tablename = $resource->getTableName('cataloginventory/stock_status');
$query = 'UPDATE {$tablename} SET `is_in_stock` = 1';
$write->query($query);
```

# 摘要

在本章中，我们学习了：

+   Magento 模型、它们的继承和目的

+   Magento 如何使用资源和集合模型

+   EAV 模型及其在 Magento 中的重要性

+   EAV 的工作原理和数据库内部使用的结构

+   Magento ORM 模型是什么以及它是如何实现的

+   如何使用直接 SQL 和 Magento 资源适配器

到目前为止，章节更多地是理论性的而不是实践性的；这是为了引导您了解 Magento 的复杂性，并为您提供本书其余部分所需的工具和知识。在本书的其余部分，我们将采取更加实践性的方法，逐步构建扩展，应用我们到目前为止学到的所有概念。

在下一章中，我们将开始涉足并开发我们的第一个 Magento 扩展。
