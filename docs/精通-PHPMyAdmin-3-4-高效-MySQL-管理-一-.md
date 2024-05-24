# 精通 PHPMyAdmin 3.4 高效 MySQL 管理（一）

> 原文：[`zh.annas-archive.org/md5/3B102B7D75B6F6D265E7C3CE6613ECC1`](https://zh.annas-archive.org/md5/3B102B7D75B6F6D265E7C3CE6613ECC1)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

phpMyAdmin 是一个处理 MySQL 管理的开源 Web 界面。它可以执行各种任务，如创建、修改或删除数据库、表、列或行。它还可以执行 SQL 语句或管理用户及其权限。即使是经验丰富的开发人员和系统管理员，在充分利用 phpMyAdmin 的潜力时，也会寻找教程来完成他们的任务。

《精通 phpMyAdmin 3.4 以实现有效的 MySQL 管理》是一本易于阅读的，逐步实用的指南，将带领您了解这个传奇工具 phpMyAdmin 的每个方面，并带您迈出一步，充分利用其潜力。本书充满了例证性的例子，将帮助您详细了解 phpMyAdmin 的每个功能。

本书首先介绍了安装和配置 phpMyAdmin，然后深入研究了 phpMyAdmin 的功能。接着是在 phpMyAdmin 中配置身份验证，并设置影响整体界面的参数，包括新的用户偏好功能。您将首先创建两个基本表，然后编辑、删除数据、表和数据库。由于备份对于项目至关重要，您将创建最新的备份，然后研究导入您已导出的数据。您还将探索各种搜索机制，并跨多个表进行查询。

现在您将学习一些高级功能，例如定义表间关系，包括关系视图和设计师面板。一些查询超出了界面的范围；您将输入 SQL 命令来完成这些任务。

您还将学习如何同步不同服务器上的数据库，并管理 MySQL 复制以提高性能和数据安全性。您还将将查询存储为书签以便快速检索。在本书的最后，您将学习如何记录数据库，跟踪对数据库的更改，并使用 phpMyAdmin 服务器管理功能管理用户帐户。

这本书是对之前版本的升级，之前版本涵盖了 phpMyAdmin 3.3 版。3.4.x 版本引入了一些新功能，例如用户偏好模块，关系模式导出到多种格式，ENUM/SET 列编辑器，简化的导出和导入界面，某些页面上的 AJAX 界面，图表生成以及可视化查询构建器。

# 本书内容

第一章，“使用 phpMyAdmin 入门”，介绍了我们应该使用 phpMyAdmin 来管理 MySQL 数据库的原因。然后涵盖了下载和安装 phpMyAdmin 的程序。还介绍了安装 phpMyAdmin 配置存储。

第二章，“配置身份验证和安全”，概述了 phpMyAdmin 中使用的各种身份验证类型。然后涵盖了与 phpMyAdmin 相关的安全问题。

第三章，“界面概述”，为我们提供了 phpMyAdmin 界面的概述。它包括登录面板，带有 Light 和 Full 模式的导航和主面板，以及查询窗口。新的用户偏好模块也在本章中进行了讨论。

第四章，“创建和浏览表”，主要讲述了数据库的创建。它教会我们如何创建表，如何手动插入数据，以及如何对数据进行排序。它还涵盖了如何从数据生成图表。

第五章，“更改数据和结构”，涵盖了 phpMyAdmin 中的数据编辑方面。它教会我们如何处理 NULL 值，多行编辑和数据删除。最后，它探讨了更改表结构的主题，重点是编辑列属性（包括新的 ENUM/SET 编辑器）和索引管理。

第六章，“导出结构和数据（备份）”，涉及备份和导出。它列出了触发导出的各种方式、可用的导出格式、与导出格式相关的选项，以及导出文件可能发送的各种位置。

第七章，“导入结构和数据”，告诉我们如何将为备份和传输目的创建的导出数据带回。它涵盖了 phpMyAdmin 中可用的各种导入数据的选项，以及导入 SQL 文件、CSV 文件和其他格式所涉及的不同机制。最后，它涵盖了导入文件可能面临的限制以及克服这些限制的方法。

第八章，“搜索数据”，介绍了对每个表或整个数据库进行有效搜索的机制。

第九章，“执行表和数据库操作”，涵盖了执行影响整个表或整个数据库的一些操作的方法。最后，它涉及表维护操作，如表修复和优化。

第十章，“从关系系统中受益”，是我们开始介绍 phpMyAdmin 高级功能的地方。本章解释了如何定义表间关系以及这些关系如何在浏览表、输入数据或搜索数据时帮助我们。

第十一章，“输入 SQL 语句”，帮助我们输入自己的 SQL 命令。本章还涵盖了查询窗口——用于编辑 SQL 查询的窗口。最后，它还帮助我们获取输入命令的历史记录。

第十二章，“生成多表查询”，涵盖了多表查询生成器，允许我们生成这些查询而不实际输入它们。还介绍了可视化查询构建器。

第十三章，“同步数据和支持复制”，教会我们如何在同一服务器上或从一个服务器到另一个服务器上同步数据库。然后涵盖了如何管理 MySQL 复制。

第十四章，“使用查询书签”，涵盖了 phpMyAdmin 配置存储的一个功能。它展示了如何记录书签以及如何操作它们。最后，它涵盖了向书签传递参数。

第十五章，“系统文档”，概述了如何使用 phpMyAdmin 提供的工具生成解释数据库结构的文档。

第十六章，“使用 MIME 转换数据”，解释了如何在查看时对数据应用转换以自定义其格式。

第十七章，“支持 MySQL 5 中添加的功能”，涵盖了 phpMyAdmin 对 MySQL 5.0 和 5.1 中的新功能的支持，如视图、存储过程和触发器。

第十八章，“跟踪更改”，教会我们如何记录从 phpMyAdmin 界面进行的结构和数据更改。

第十九章，“管理 MySQL 服务器”，讨论了 MySQL 服务器的管理，重点放在用户帐户和权限上。本章讨论了系统管理员如何使用 phpMyAdmin 的服务器管理功能进行日常用户帐户维护、服务器验证和服务器保护。

附录 A，*故障排除和支持*，解释了如何通过进行简单验证来排除 phpMyAdmin 的故障。它还解释了如何与开发团队互动，以获取支持、错误报告和贡献。

# 本书所需内容

您需要访问已安装以下内容的服务器或工作站：

+   具有 PHP 5.2 或更高版本的 Web 服务器

+   MySQL 5.0 或更高版本

# 本书的受众对象

如果您是开发人员、系统管理员或网页设计师，希望高效管理 MySQL 数据库和表，那么本书适合您。本书假定您已经熟悉 MySQL 基础知识。对于每个希望充分利用这一杰出应用程序的 phpMyAdmin 用户来说，本书都是必读之作。

# 约定

在本书中，您会发现一些文本样式，用于区分不同类型的信息。以下是一些样式的示例，以及它们的含义解释。

文本中的代码词显示如下："如果这些信息不可用，一个很好的替代选择是`localhost`。"

代码块设置如下：

```sql
$i++;
$cfg['Servers'][$i]['host'] = '';
$cfg['Servers'][$i]['port'] = '';
$cfg['Servers'][$i]['socket'] = '';

```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```sql
UPDATE `marc_book`.`book` SET `some_bits` = b '101' 
WHERE `book`.`isbn` = '1-234567-89-0' LIMIT 1;

```

任何命令行输入或输出都以以下形式书写：

```sql
 tar -xzvf phpMyAdmin-3.4.5-all-languages.tar.gz

```

**新术语**和**重要单词**以粗体显示。您在屏幕上看到的单词，例如菜单或对话框中的单词，会在文本中以这种方式出现："在**下载**部分有各种文件可用。"

### 注意

警告或重要提示会以这种形式出现在方框中。

### 提示

技巧和窍门会以这种形式出现。

# 读者反馈

我们始终欢迎读者的反馈。请告诉我们您对本书的看法——您喜欢或不喜欢的地方。读者的反馈对我们开发能让您真正受益的书籍至关重要。

要向我们发送一般反馈，只需发送电子邮件至`<feedback@packtpub.com>`，并在消息主题中提及书名。

如果您在某个专题上有专业知识，并且有兴趣撰写或为一本书做出贡献，请参阅我们的作者指南[www.packtpub.com/authors](http://www.packtpub.com/authors)。

# 客户支持

现在您是 Packt 书籍的自豪所有者，我们有一些事情可以帮助您充分利用您的购买。

## 勘误

尽管我们已经尽一切努力确保内容的准确性，但错误是难免的。如果您在我们的书中发现错误——可能是文本或代码中的错误——我们将不胜感激地希望您向我们报告。通过这样做，您可以帮助其他读者避免挫折，并帮助我们改进本书的后续版本。如果您发现任何勘误，请访问[`www.packtpub.com/support`](http://www.packtpub.com/support)报告，选择您的书，点击**勘误提交表**链接，并输入您的勘误详情。一旦您的勘误经过验证，您的提交将被接受，并且勘误将被上传到我们的网站上，或者添加到该标题的勘误部分的任何现有勘误列表中。

## 盗版

互联网上的版权盗版是所有媒体的持续问题。在 Packt，我们非常重视对我们的版权和许可的保护。如果您在互联网上发现我们作品的任何非法副本，请立即向我们提供位置地址或网站名称，以便我们采取补救措施。

请通过`<copyright@packtpub.com>`与我们联系，并附上涉嫌盗版材料的链接。

我们感谢您帮助我们保护我们的作者和我们提供有价值的内容的能力。

## 问题

如果您在阅读本书的过程中遇到任何问题，请联系我们`<questions@packtpub.com>`，我们将尽力解决。


# 第一章：开始使用 phpMyAdmin

我在这本书中对你表示热烈的欢迎！本章的目标是：

+   了解这个软件产品在 Web 领域中的位置

+   了解它的所有功能

+   熟练安装和配置它

# PHP 和 MySQL：领先的开源组合

当我们看当前主机提供商提供的 Web 应用平台时，我们会发现最普遍的是 PHP/MySQL 组合。

得到各自主页的大力支持—[`www.php.net`](http://www.php.net)和[`www.mysql.com`](http://www.mysql.com) —这对组合使开发人员能够构建许多现成的开源 Web 应用程序，最重要的是，使内部开发人员能够快速建立稳固的 Web 解决方案。

MySQL，大多符合 SQL:2003 标准，是一个以其速度、稳健性和小的连接开销而闻名的数据库系统。在 Web 环境中，页面必须尽快提供的情况下，这一点非常重要。

PHP 通常安装在 Web 服务器内部作为一个模块，是一种流行的脚本语言，用于编写与 MySQL（或其他数据库系统）后端和浏览器前端通信的应用程序。具有讽刺意味的是，这个首字母缩略词的意义随着 Web 的发展而演变，从**个人主页**到**专业主页**再到其当前的递归定义——**PHP：超文本预处理器**。有关连续名称更改的博客文章可在[`blog.roshambo.org/how-the-php-acronym-was-reborn`](http://blog.roshambo.org/how-the-php-acronym-was-reborn)上找到。PHP 可以在数百万个 Web 域上使用，并为 Facebook、Yahoo!、YouTube 和 Wikipedia 等知名网站提供动力。

# 什么是 phpMyAdmin？

phpMyAdmin（官方主页在[`www.phpmyadmin.net`](http://www.phpmyadmin.net)）是一个用 PHP 编写的 Web 应用程序；它包含（像大多数 Web 应用程序一样）XHTML、CSS 和 JavaScript 客户端代码。该应用程序为管理 MySQL 数据库提供了完整的 Web 界面，并被广泛认为是该领域的领先应用程序。

自诞生以来就是开源的，得到了全球众多开发人员和翻译人员的支持（在撰写本书时已被翻译成 65 种语言）。该项目目前托管在 SourceForge.net 上，并由 phpMyAdmin 团队利用他们的设施进行开发。

全球各地的主机提供商都通过在他们的服务器上安装 phpMyAdmin 来表现对其的信任。流行的 cPanel（一个网站控制应用程序）包含 phpMyAdmin。此外，只要我们的提供商服务器满足最低要求（请参阅本章后面的*系统要求*部分），我们就可以在我们自己的 Web 服务器上安装我们自己的 phpMyAdmin 副本。

phpMyAdmin 的目标是提供对 MySQL 服务器和数据的完整基于 Web 的管理，并跟上 MySQL 和 Web 标准的发展。虽然产品不断发展，但它支持所有标准操作以及额外的功能。

开发团队根据报告的错误和请求的功能不断调整产品，定期发布新版本。

phpMyAdmin 提供了涵盖基本 MySQL 数据库和表操作的功能。它还有一个内部系统，用于维护元数据以支持高级功能。最后，系统管理员可以从 phpMyAdmin 管理用户和权限。重要的是要注意，phpMyAdmin 选择的可用操作取决于用户在特定 MySQL 服务器上的权限。

## 项目文档

有关 phpMyAdmin 的更多信息，请参阅主页文档页面，位于[`www.phpmyadmin.net/home_page/docs.php`](http://www.phpmyadmin.net/home_page/docs.php)。此外，开发团队在社区的帮助下维护着一个维基，位于[`wiki.phpmyadmin.net`](http://wiki.phpmyadmin.net)。

# 安装 phpMyAdmin

是时候安装产品并进行最少的首次使用配置了。

我们安装 phpMyAdmin 的原因可能是以下之一：

+   我们的主机提供商没有安装中央副本

+   我们的提供商安装了它，但安装的版本不是最新的

+   我们直接在企业的 Web 服务器上工作

请注意，如果我们选择安装通常包括 phpMyAdmin 作为其产品的一部分的 AMP 产品之一，我们可以省去 phpMyAdmin 安装步骤。更多详细信息请参见[`en.wikipedia.org/wiki/List_of_AMP_packages`](http://en.wikipedia.org/wiki/List_of_AMP_packages)。

## 所需信息

一些主机提供商提供了集成的 Web 面板，我们可以在其中管理帐户，包括 MySQL 帐户，还有一个文件管理器，可以用来上传 Web 内容。根据这一点，我们用于将 phpMyAdmin 源文件传输到我们的 Web 空间的机制可能会有所不同。在开始安装之前，我们需要一些以下特定信息：

+   Web 服务器的名称或地址。在这里，我们假设它是[www.mydomain.com](http://www.mydomain.com)。

+   我们的网页服务器帐户信息（用户名，密码）。此信息将用于 FTP 或 SFTP 传输，SSH 登录或 Web 控制面板登录。

+   MySQL 服务器的名称或 IP 地址。如果没有这些信息，一个很好的备选选择是`localhost`，这意味着 MySQL 服务器位于与 Web 服务器相同的机器上。我们假设这是`localhost`。

+   我们的 MySQL 服务器帐户信息（用户名，密码）。

## 系统要求

特定 phpMyAdmin 版本的最新要求始终在附带的`Documentation.html`中说明。对于 phpMyAdmin 3.4，所需的最低 PHP 版本是带有**session**支持的 PHP 5.2，**标准 PHP 库（SPL）**和**JSON**支持。此外，Web 服务器必须能够访问 MySQL 服务器（5.0 版本或更高版本）-可以是本地的，也可以是远程的。强烈建议在 cookie 身份验证模式下提高性能时，Web 服务器必须具有**PHP mcrypt**扩展（有关此内容，请参见第二章）。实际上，在 64 位服务器上，这个扩展是必需的。

在浏览器端，无论我们使用哪种身份验证模式，都必须激活 cookie 支持。

## 下载文件

[`www.phpmyadmin.net`](http://www.phpmyadmin.net)的**下载**部分提供了各种文件。这里可能提供了多个版本，最好下载最新的稳定版本。我们只需要下载一个文件，无论平台（浏览器，Web 服务器，MySQL 或 PHP 版本）如何，都可以使用。对于 3.4 版本，有两组文件-**english**和**all-languages**。如果我们只需要英文界面，可以下载文件名包含**english**的文件，例如**phpMyAdmin-3.4.5-english.zip**。另一方面，如果我们需要至少另一种语言，选择**all-languages**是合适的。

如果我们使用的是仅支持 PHP 4 的服务器-自 2007 年 12 月 31 日 PHP 团队停止支持以来，最新的稳定版本的 phpMyAdmin 不是一个好选择。我们可以使用 2.11.x 版本，这是支持 PHP 4 的最新分支，尽管 phpMyAdmin 团队也停止支持这个版本。

提供的文件具有各种扩展名：`.zip，.tar.bz2，.tar.gz，.tar.xz 和.7z`。下载具有您具有相应提取器的扩展名的文件。在 Windows 世界中，`.zip`是最通用的文件格式，尽管它比`.gz`或`.bz2`（在 Linux/Unix 世界中常见）要大。`.7z`扩展名表示 7-Zip 文件，这是一种比其他提供的格式具有更高压缩比的格式；提取器可在[`www.7-zip.org`](http://www.7-zip.org)上找到。在以下示例中，我们将假定所选文件是**phpMyAdmin-3.4.5-all-languages.zip**。

单击适当的文件后，SourceForge.net 会选择最近的镜像站点。文件将开始下载，我们可以将其保存在我们的计算机上。

## 在不同平台上安装

下一步取决于您使用的平台。以下各节详细介绍了一些常见平台的程序。您可以直接转到相关部分。

### 在 Windows 客户端上安装到远程服务器

使用 Windows 资源管理器，在 Windows 客户端上双击刚刚下载的`phpMyAdmin-3.4.5-all-languages.zip`文件。文件提取器应该会启动，显示主目录`phpMyAdmin-3.4.5-all-languages`中的所有脚本和目录。

使用文件提取器提供的任何机制将所有文件（包括子目录）保存到工作站上的某个位置。在这里，我们选择了`C:\`。因此，提取器创建了一个`C:\phpMyAdmin-3.4.5-all-languages`目录。

现在，是时候将整个目录结构`C:\phpMyAdmin-3.4.5-all-languages`传输到我们网页空间中的 Web 服务器了。我们可以使用我们喜欢的 SFTP 或 FTP 软件，或者使用 Web 控制面板进行传输。

我们传输 phpMyAdmin 的确切目录可能会有所不同。它可以是我们的`public_html`目录或我们通常传输 Web 文档的其他目录。有关要使用的确切目录或传输目录结构的最佳方法的进一步说明，我们可以咨询我们的主机提供商的帮助台。

传输完成后，这些文件可以从我们的 Windows 机器上删除，因为它们不再需要了。

### 在本地 Linux 服务器上安装

假设我们选择了`phpMyAdmin-3.4.5-all-languages.tar.gz`并直接下载到 Linux 服务器上的某个目录。我们将其移动到我们的 Web 服务器文档根目录（例如`/var/www/html`）或其子目录之一（例如`/var/www/html/utilities`）。然后，我们使用以下 shell 命令或使用窗口管理器提供的任何图形文件提取器进行提取：

```sql
tar -xzvf phpMyAdmin-3.4.5-all-languages.tar.gz 

```

我们必须确保目录和文件的权限和所有权适合我们的 Web 服务器。Web 服务器用户或组必须能够读取它们。

### 在本地 Windows 服务器（Apache，IIS）上安装

这里的步骤与“在 Windows 客户端上安装到远程服务器”部分中描述的类似，只是目标目录将位于我们的`DocumentRoot`（对于 Apache）或我们的`wwwroot`（对于 IIS）下。当然，在对`config.inc.php`进行修改后，我们不需要传输任何内容（在下一节中描述），因为目录已经在 Web 空间中。

Apache 通常作为服务运行。因此，我们必须确保运行服务的用户具有正常的读取权限，以访问我们新创建的目录。相同的原则适用于使用`IUSR_machinename`用户的 IIS。该用户必须对目录具有读取权限。您可以在目录属性的`安全/权限`选项卡中调整权限。

# 配置 phpMyAdmin

在这里，我们学习如何准备和使用包含连接到 MySQL 的参数的配置文件，并且可以根据我们的要求进行自定义。

在配置之前，我们可以将目录`phpMyAdmin-3.4.5-all-languages`重命名为`phpMyAdmin`或其他更容易记住的名称。这样，我们和我们的用户可以访问一个容易记住的 URL 来启动 phpMyAdmin。在大多数服务器上，URL 的目录部分是区分大小写的，因此我们应该向用户传达确切的 URL。如果我们的服务器支持此功能，我们还可以使用符号链接。

在以下示例中，我们将假设该目录已重命名为`phpMyAdmin`。

## config.inc.php 文件

这个文件包含有效的 PHP 代码，定义了大部分参数（由 PHP 变量表示），我们可以更改以调整 phpMyAdmin 以满足我们自己的需求。文件中还有普通的 PHP 注释，我们可以注释我们的更改。

### 提示

注意不要在文件开头或结尾添加任何空行；这会妨碍 phpMyAdmin 的执行。

请注意，phpMyAdmin 在第一级目录中寻找此文件——与`index.php`位于同一目录。

包含一个`config.sample.inc.php`文件，可以复制并重命名为`config.inc.php`，作为起点。然而，建议您使用基于 Web 的安装脚本（在本章中解释）来代替，以获得更舒适的配置界面。

还有另一个文件——`layout.inc.php`——包含一些配置信息。由于 phpMyAdmin 提供主题管理，这个文件包含特定主题的颜色和设置。每个主题都有一个`layout.inc.php`文件，位于`themes/<themename>`，例如`themes/pmahomme`。我们将在第四章中介绍修改其中一些参数。

### 避免关于 config.inc.php 权限的虚假错误消息

在正常情况下，phpMyAdmin 会验证此文件的权限是否允许任何人修改。这意味着该文件不应该被世界写入。如果权限不正确，它还会显示警告。然而，在某些情况下（例如在非 Windows 服务器上挂载的 NTFS 文件系统），权限检测会失败。在这些情况下，您应该将以下配置参数设置为`false:`

```sql
$cfg['CheckConfigurationPermissions'] = false;

```

以下各节将解释在`config.inc.php`中添加或更改参数的各种方法。

## 配置原则

phpMyAdmin 不维护自己的用户帐户；相反，它使用 MySQL 的权限系统。

### 注意

现在可能是浏览[`dev.mysql.com/doc/refman/5.1/en/privilege-system.html`](http://dev.mysql.com/doc/refman/5.1/en/privilege-system.html)的时候了，了解 MySQL 权限系统的基础知识。

由于缺少配置文件，phpMyAdmin 默认显示基于 cookie 的登录面板（有关此内容的更多详细信息，请参阅第二章），其中解释了默认配置下，无法使用空密码登录：

![配置原则](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_01_01.jpg)

我们可以通过打开浏览器并访问`http://www.mydomain.com/phpMyAdmin`来验证这一事实，并替换域部分和目录部分的正确值。

如果我们能够登录，这意味着在与 Web 服务器相同的主机上有一个运行中的 MySQL 服务器（`localhost`），我们刚刚连接到它。然而，没有创建配置文件意味着我们将无法通过我们的 phpMyAdmin 安装管理其他主机。此外，许多高级的 phpMyAdmin 功能（例如查询书签、完整的关系支持、列转换等）将无法激活。

### 注意

基于 cookie 的身份验证方法使用 Blowfish 加密来存储浏览器 cookie 中的凭据。当没有配置文件存在时，会生成并存储一个 Blowfish 秘钥在会话数据中，这可能会导致安全问题。这就是为什么会显示以下警告消息的原因：

**配置文件现在需要一个秘密的密码（blowfish_secret）**

此时，我们有以下选择：

+   在没有配置文件的情况下使用 phpMyAdmin

+   使用基于 Web 的设置脚本生成`config.inc.php`文件

+   手动创建`config.inc.php`文件

这两个后续选项在以下部分中介绍。我们应该注意，即使使用基于 Web 的设置脚本，我们也应该熟悉`config.inc.php`文件的格式，因为设置脚本并没有涵盖所有可能的配置选项。

## 基于 Web 的设置脚本

强烈建议使用基于 Web 的设置机制，以避免手动创建配置文件可能导致的语法错误。此外，由于这个文件必须遵守 PHP 的语法，新用户在安装过程中可能会遇到问题。

### 注意

这里需要注意一点：当前版本的设置界面只有有限数量的翻译语言。

要访问设置脚本，我们必须访问[`www.mydomain.com/phpMyAdmin/setup`](http://www.mydomain.com/phpMyAdmin/setup)。在初始执行时，会出现以下截图：

![基于 Web 的设置脚本](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_01_02.jpg)

在大多数情况下，每个参数旁边的图标指向相应的 phpMyAdmin 官方维基和文档，为您提供有关此参数及其可能值的更多信息。

如果出现**显示隐藏消息**并点击此链接，之前可能显示的消息将被显示出来。

这里有三个警告。由于处理第一条消息需要更多操作，我们稍后再处理。第二个警告鼓励您使用`ForceSSL`选项，在使用 phpMyAdmin 时自动切换到 HTTPS（与设置阶段无关）。

让我们来看看第三条消息——**不安全的连接**。如果我们通过不安全的协议 HTTP 访问 Web 服务器，就会出现这个消息。由于我们可能会在设置阶段输入机密信息，比如用户名和密码，建议至少在这个阶段使用 HTTPS 进行通信。HTTPS 使用 SSL（安全套接字层）来加密通信，使窃听线路变得不可能。如果我们的 Web 服务器支持 HTTPS，我们可以简单地按照建议的链接进行操作。这将重新启动设置过程，这次是通过 HTTPS 进行的。

第一个警告告诉我们，phpMyAdmin 没有找到一个名为`config`的可写目录。这是正常的，因为在下载的套件中没有这个目录。此外，由于目录还不存在，我们注意到界面中的**保存、加载**和**删除**按钮是灰色的。在这个`config`目录中，我们可以：

+   在设置过程中保存工作版本的配置文件

+   加载之前准备好的`config.inc.php`文件

我们并不一定需要创建这个配置目录，因为我们可以将设置过程生成的`config.inc.php`文件下载到客户端机器上。然后，我们可以通过与上传 phpMyAdmin 相同的机制（比如 FTP）将其上传到 phpMyAdmin 的一级目录中。在这个练习中，我们将创建这个目录。

这里的原则是 Web 服务器必须能够写入这个目录。有多种方法可以实现这一点。以下是在 Linux 服务器上可以使用的一种方法——在这个目录上为每个人添加读、写和执行权限。

```sql
cd phpMyAdmin
mkdir config
chmod 777 config 

```

完成这些操作后，我们在浏览器中刷新页面，会看到一个类似以下截图的屏幕：

![基于 Web 的设置脚本](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_01_03.jpg)

在配置对话框中，下拉菜单允许用户选择适当的行尾格式。我们应该选择与我们将在后来使用文本编辑器打开`config.inc.php`文件的平台（UNIX/Linux 或 Windows）相对应的格式。

一个 phpMyAdmin 的副本可以用来管理许多 MySQL 服务器，但是现在我们将定义描述我们的第一个 MySQL 服务器的参数。我们单击**新服务器**，然后显示服务器配置面板。

这些参数的完整解释可以在本章的以下部分找到。现在，我们注意到设置过程已检测到 PHP 支持`mysqli`扩展。因此，默认选择此扩展。此扩展是 PHP 用于与 MySQL 通信的编程库。

我们假设我们的 MySQL 服务器位于`localhost`上。因此，我们保持此值和所有建议的值不变，除了以下内容：

+   **基本设置 | 该服务器的详细名称** —我们输入 **我的服务器**

+   **认证 | 用于配置认证的用户** —我们删除**root**并将其留空，因为默认的认证类型是`cookie`，它会忽略在此输入的用户名

您可以看到任何更改为其默认值的参数都以不同的颜色显示。此外，会出现一个小箭头，其目的是将字段恢复为其默认值。因此，您可以放心地尝试更改参数，知道您可以轻松恢复到建议的值。此时，**基本设置**面板应该类似于以下屏幕截图：

基于 Web 的设置脚本

然后我们单击**保存**，并返回到**概述**面板。此保存操作尚未将任何内容保存到磁盘；更改已保存在内存中。我们收到警告，生成了一个 Blowfish 秘钥。但是，我们不必记住它，因为在登录过程中不需要输入它，而是在内部使用。对于好奇的人，您可以切换到**功能**面板，然后单击**安全**选项卡，以查看生成的秘钥。让我们回到**概述**面板。现在，我们的设置过程已知道一个 MySQL 服务器，并且有一些链接，使我们能够像下面的屏幕截图中显示的那样**编辑**或**删除**这些服务器设置：

基于 Web 的设置脚本

我们可以使用**显示**按钮查看生成的配置行；然后，我们可以使用本章后面的*一些配置参数的描述*部分中给出的解释来分析这些参数。

此时，此配置仍仅存储在内存中，因此我们需要保存它。这是通过**概述**面板上的**保存**按钮完成的。它将`config.inc.php`保存在我们之前创建的特殊`config`目录中。这是一个严格用于配置目的的目录。如果由于任何原因无法创建此`config`目录，您只需通过单击**下载**按钮将文件下载并上传到安装了 phpMyAdmin 的 Web 服务器目录。

最后一步是将`config.inc.php`从`config`目录复制到顶级目录 —— 包含`index.php`的目录。通过复制此文件，它将由用户拥有，而不是由 Web 服务器拥有，从而确保可以进行进一步的修改。可以通过 FTP 或通过以下命令进行此复制：

```sql
cd config
cp config.inc.php .. 

```

作为安全措施，直到配置步骤完成之前，建议更改`config`目录的权限，例如使用以下命令：

```sql
chmod ugo-rwx config 

```

这是为了阻止在此目录中进行任何未经授权的读写操作。

其他配置参数可以使用这些基于 Web 的设置页面进行设置。要这样做，我们需要：

1.  启用对`config`目录的读写访问权限。

1.  将`config.inc.php`复制到那里。

1.  确保为 Web 服务器提供了对该文件的读写访问权限。

1.  启动基于 Web 的设置工具。

配置步骤完成后，建议完全删除`config`目录，因为这个目录只被基于 Web 的安装脚本使用。如果 phpMyAdmin 检测到这个目录仍然存在，它会在主页上显示以下警告（参见第三章)：

**目录 config，被安装脚本使用，仍然存在于您的 phpMyAdmin 目录中。一旦 phpMyAdmin 配置完成，您应该删除它**。

您可以浏览剩余的菜单，了解可用的配置可能性，无论是现在还是在我们涵盖相关主题时。

为了使本书的文本更轻，我们将在接下来的章节中只提到参数的文本值。

## 手动创建 config.inc.php

我们可以使用我们喜欢的文本编辑器从头开始创建这个文本文件，或者使用`config.sample.inc.php`作为起点。确切的步骤取决于我们使用的客户端操作系统。我们可以参考下一节获取更多信息。

所有可能的配置参数的默认值都在`libraries/config.default.php`中定义。我们可以查看此文件，了解使用的语法以及有关配置的进一步注释。请参见本章*升级 phpMyAdmin*部分中关于此文件的重要说明。

## 在 Windows 客户端上编辑 config.inc.php 的提示

这个文件包含特殊字符（Unix 风格的行尾）。因此，我们必须使用理解这种格式的文本编辑器打开它。如果我们使用错误的文本编辑器，这个文件将显示非常长的行。最好的选择是标准的 PHP 编辑器，如 NetBeans 或 Zend Studio for Eclipse。另一个选择是 WordPad，Metapad 或 UltraEdit。

每次修改`config.inc.php`文件，都必须再次将其传输到我们的网络空间。这种传输是通过 FTP 或 SFTP 客户端完成的。您可以选择使用独立的 FTP/SFTP 客户端，如 FileZilla，或者如果您的 PHP 编辑器支持此功能，也可以直接通过 FTP/SFTP 保存。

## 一些配置参数的描述

在本章和下一章中，我们将集中讨论与连接和身份验证相关的参数。其他参数将在解释相应功能的章节中讨论。

### PmaAbsoluteUri

我们将首先查看的参数是`$cfg['PmaAbsoluteUri'] = ''`;

有时，phpMyAdmin 需要发送 HTTP `Location`头，并且必须知道其安装点的绝对 URI。在这种情况下，使用绝对 URI 是 RFC 2616 第 14.30 节要求的。

在大多数情况下，我们可以将此项留空，因为 phpMyAdmin 会尝试自动检测正确的值。如果我们稍后浏览表，然后编辑一行，并单击**保存**，我们将收到来自浏览器的错误消息，例如**此文档不存在**。这意味着 phpMyAdmin 为了到达预期页面而构建的绝对 URI 是错误的，表明我们必须手动在此参数中放入正确的值。

例如，我们会将其更改为：

```sql
$cfg['PmaAbsoluteUri'] = 'http://www.mydomain.com/phpMyAdmin/';

```

### 特定于服务器的部分

文件的下一部分包含特定于服务器的配置，每个配置都以以下代码片段开头：

```sql
$i++;
$cfg['Servers'][$i]['host'] = '';

```

如果我们只检查正常的服务器参数（其他参数在本章的*安装 phpMyAdmin 配置存储*部分中有介绍），我们会看到每个服务器的以下代码块：

```sql
$i++;
$cfg['Servers'][$i]['host'] = '';
$cfg['Servers'][$i]['port'] = '';
$cfg['Servers'][$i]['socket'] = '';
$cfg['Servers'][$i]['connect_type'] = 'tcp';
$cfg['Servers'][$i]['extension'] = 'mysqli';
$cfg['Servers'][$i]['compress'] = FALSE;
$cfg['Servers'][$i]['controluser'] = '';
$cfg['Servers'][$i]['controlpass'] = '';
$cfg['Servers'][$i]['auth_type'] = 'cookie';
$cfg['Servers'][$i]['user'] = '';
$cfg['Servers'][$i]['password'] = '';
$cfg['Servers'][$i]['only_db'] = '';
$cfg['Servers'][$i]['hide_db'] = '';
$cfg['Servers'][$i]['verbose'] = '';

```

在这一部分，我们必须输入`$cfg['Servers'][$i]['host']`，MySQL 服务器的主机名或 IP 地址，例如，`mysql.mydomain.com`或`localhost`。如果此服务器在非标准端口或套接字上运行，我们在`$cfg['Servers'][$i]['port']`或`$cfg['Servers'][$i]['socket']`中填入正确的值。有关套接字的更多详细信息，请参见*connect_type, sockets, and port*部分。

在 phpMyAdmin 界面中显示的服务器名称将是`'host'`中输入的名称，除非我们在以下参数中输入非空值，例如：

```sql
$cfg['Servers'][$i]['verbose'] = 'Test server';

```

因此，这个功能可以用来在登录面板和主页面上显示用户所看到的不同服务器主机名，尽管真实的服务器名称可以作为用户定义的一部分（例如，在主页面上是`root@localhost`）。

#### 扩展

PHP 与 MySQL 服务器通信的传统机制，在 PHP 5 之前可用的是`mysql`扩展。这个扩展在 PHP 5 中仍然可用。然而，一个名为`mysqli`的新扩展已经开发出来，并且应该在 PHP 5 中优先使用，因为它具有改进的性能并支持 MySQL 4.1.x 系列的全部功能。这个扩展被设计用于与 MySQL 版本 4.1.3 及更高版本一起使用。由于 phpMyAdmin 支持这两个扩展，我们可以为特定服务器选择其中一个。我们在`$cfg['Servers'][$i]['extension']`中指定我们想要使用的扩展。默认使用的值是`mysqli`。

#### connect_type、socket 和 port

`mysql`和`mysqli`扩展在连接到`localhost`上的 MySQL 时会自动使用套接字。考虑以下配置：

```sql
$cfg['Servers'][$i]['host'] = 'localhost';
$cfg['Servers'][$i]['port'] = '';
$cfg['Servers'][$i]['socket'] = '';
$cfg['Servers'][$i]['connect_type'] = 'tcp';
$cfg['Servers'][$i]['extension'] = 'mysql';

```

`connect_type`的默认值是`tcp`。然而，扩展将使用套接字，因为它认为这样更有效率，因为`host`是`localhost`。所以在这种情况下，我们可以使用`tcp`或`socket`作为`connect_type`。要强制使用真正的 TCP 连接，可以在`host`参数中指定`127.0.0.1`而不是`localhost`。因为`socket`参数为空，扩展将尝试使用默认套接字。如果`php.ini`中定义的默认套接字与分配给 MySQL 服务器的真实套接字不对应，我们必须在`$cfg['Servers'][$i]['socket']`中放置套接字名称（例如`/tmp/mysql.sock`）。

如果主机名不是`localhost`，将发生 TCP 连接；在这种情况下，使用特殊端口`3307`。然而，将端口值留空将使用默认的`3306`端口：

```sql
$cfg['Servers'][$i]['host'] = 'mysql.mydomain.com';
$cfg['Servers'][$i]['port'] = '3307';
$cfg['Servers'][$i]['socket'] = '';
$cfg['Servers'][$i]['connect_type'] = 'tcp';
$cfg['Servers'][$i]['extension'] = 'mysql';

```

#### 压缩

PHP 与 MySQL 之间通信所使用的协议允许压缩模式。使用此模式可以提高效率。要利用此模式，只需指定：

```sql
$cfg['Servers'][$i]['compress'] = TRUE;

```

#### 持久连接

另一个重要的参数（不是特定于服务器的，但适用于所有服务器定义）是`$cfg['PersistentConnections']`。对于使用`mysql`扩展连接的每个服务器，当设置为`TRUE`时，此参数指示 PHP 保持与 MySQL 服务器的连接打开。这加快了 PHP 与 MySQL 之间的交互。然而，在`config.inc.php`中默认设置为`FALSE`，因为持久连接经常是服务器资源耗尽的原因（您会发现 MySQL 拒绝新连接）。因此，对于`mysqli`扩展，甚至不提供此选项。因此，如果您使用此扩展进行连接，则在这里将其设置为`TRUE`将不起作用。

#### 控制用户

定义控制用户有以下两个目的：

+   在运行`--skip-show-database`的 MySQL 服务器上，控制用户允许使用多用户身份验证，尽管使用此选项运行的服务器并不常见。这一方面在第二章中有描述。

+   在所有版本的 MySQL 服务器上，这个用户是必需的，才能使用 phpMyAdmin 的高级功能。

为了认证目的，`controluser`是一个特殊用户（我们选择的通常名称是`pma`），他有权读取`mysql`数据库中的一些字段（其中包含所有用户定义）。phpMyAdmin 仅为认证的特定需求发送带有这个特殊`controluser`的查询，而不是正常操作。创建控制用户的命令可以在 phpMyAdmin 的`Documentation.html`中找到，并且可能会因版本而异。这份文档包含了最新的命令。

当我们在 MySQL 服务器中创建`controluser`时，我们填写参数如下示例中的内容，将`xxx`替换为一个适当复杂的密码：

```sql
$cfg['Servers'][$i]['controluser'] = 'pma';
$cfg['Servers'][$i]['controlpass'] = 'xxx';

```

这里适用标准密码指南。请参考[`en.wikipedia.org/wiki/Password_strength`](http://en.wikipedia.org/wiki/Password_strength)获取建议。

# 安装 phpMyAdmin 配置存储

除了基本的 MySQL 数据库维护外，phpMyAdmin 还提供了高级功能，我们将在接下来的章节中发现。这些功能需要安装 phpMyAdmin 配置存储。

## 配置存储的目标

配置存储由 phpMyAdmin 在幕后使用的一组表组成。它们保存元数据，其中包含支持特殊功能的信息，例如查询书签和数据转换。此外，对于使用不支持外键的存储引擎的表，表之间的关系保存在这个配置存储中。元数据是根据我们在界面上的操作由 phpMyAdmin 生成和维护的。

## 配置存储的位置

有两个可能的地方来存储这些表：

+   用户的数据库-以方便每个网页开发人员拥有一个数据库以从这些功能中受益。

+   一个名为 pmadb（phpMyAdmin 数据库）的专用数据库。在多用户安装中，这个数据库可能对许多用户可见，同时保持元数据私有。

由于这个存储默认情况下不存在，并且 phpMyAdmin 团队希望推广它，界面在主页上显示以下通知消息：

![配置存储的位置](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_01_06.jpg)

这条消息可以通过以下参数禁用（默认情况下设置为`FALSE`）：

```sql
$cfg['PmaNoRelation_DisableWarning'] = TRUE;

```

## 执行安装

即使只有部分配置存储缺失，先前的错误消息也会显示。当然，在新安装中，所有部分都缺失-我们的数据库还没有听说过 phpMyAdmin，并且需要配备这个配置存储。在前一个截图中点击“here”链接会弹出一个面板，解释`pmadb`以及应该是其中一部分的表要么缺失要么未定义。

重要的是要意识到，只有满足以下两个条件，配置存储才能正常运行：

+   在`config.inc.php`中存在适当的定义

+   相应的表（也许是数据库）被创建

为了创建与我们当前版本的 phpMyAdmin 匹配的必要结构，phpMyAdmin 安装目录的`scripts`子目录中提供了一个名为`create_tables.sql`的命令文件。但是，在了解可能的选择-单用户安装或多用户安装之前，我们不应该盲目执行它。

### 注意

在后续章节中，我们将假设选择了多用户安装。

### 为单个用户安装

即使我们只有一个数据库的权限，我们仍然可以使用 phpMyAdmin 的所有高级功能。在这种设置中，我们将使用我们现有的数据库来存储元数据表。

我们需要修改`scripts/create_tables.sql`文件的本地副本，以便用所需的所有表填充我们的数据库。它们将具有前缀`pma_`以便于识别。我们需要删除以下行：

```sql
CREATE DATABASE IF NOT EXISTS `phpmyadmin`
DEFAULT CHARACTER SET utf8 COLLATE utf8_bin;
USE phpmyadmin;

```

这样做是因为我们不会使用`phpmyadmin`数据库，而是我们自己的。接下来，我们应该在 phpMyAdmin 中打开我们自己的数据库。现在我们准备执行脚本了。有两种方法可以做到这一点：

+   由于我们已经在编辑器中有脚本，我们可以只需复制这些行并粘贴到**SQL**页面的查询框中。更多细节请参阅第十一章。

+   另一种方法是使用第七章中展示的导入技术。我们选择刚刚修改的`create_tables.sql`脚本。

创建后，导航面板会显示特殊的`pma_`表和我们的普通表。

现在是时候调整`config.inc.php`中所有与配置存储相关的参数了。这可以通过本章中的设置脚本轻松完成，也可以通过从`config.sample.inc.php`文件中粘贴适当的行来完成。数据库是我们自己的，表名是刚刚创建的表名：

```sql
$cfg['Servers'][$i]['pmadb'] = 'mydatabase';
$cfg['Servers'][$i]['bookmarktable'] = 'pma_bookmark';
$cfg['Servers'][$i]['relation'] = 'pma_relation';
$cfg['Servers'][$i]['table_info'] = 'pma_table_info';
$cfg['Servers'][$i]['table_coords'] = 'pma_table_coords';
$cfg['Servers'][$i]['pdf_pages'] = 'pma_pdf_pages';
$cfg['Servers'][$i]['column_info'] = 'pma_column_info';
$cfg['Servers'][$i]['history'] = 'pma_history';
$cfg['Servers'][$i]['tracking'] = 'pma_tracking';
$cfg['Servers'][$i]['designer_coords'] = 'pma_designer_coords';
$cfg['Servers'][$i]['userconfig'] = 'pma_userconfig';

```

### 注意

由于表名区分大小写，我们必须使用与安装脚本创建的表相同的名称。我们可以自由更改表名（参见列出的配置指令的右侧部分），只要我们相应地在数据库中进行更改。

`pmadb`和每个表都有一个特定的功能，如下所列：

| 功能 | 描述 | 解释 |
| --- | --- | --- |
| `pmadb` | 定义所有表所在的数据库 | 本章 |
| `bookmarktable` | 包含查询书签 | 第十四章 |
| `relation` | 定义表间关系，用于 phpMyAdmin 的许多功能 | 第十章 |
| `table_info` | 包含显示字段 | 第十章 |
| `table_coords`和`pdf_pages` | 包含绘制 PDF 格式关系图所需的元数据 | 第十五章 |
| `column_info` | 用于列注释和基于 MIME 的转换 | 第十六章 |
| `history` | 包含 SQL 查询历史信息 | 第十一章 |
| `tracking` | 包含与被跟踪表相关的元数据和实际的 SQL 语句 | 第十八章 |
| `designer_coords` | 保存**Designer**功能使用的坐标 | 第十章 |
| `userconfig` | 保存用户的偏好设置 | 第三章 |

在每个 phpMyAdmin 版本之间，基础设施可能会得到增强——这些变化在`Documentation.html`中有解释。这就是为什么 phpMyAdmin 有各种检查来确定表的结构。如果我们知道我们使用的是最新结构，可以将`$cfg['Servers'][$i]['verbose_check']`设置为`FALSE`以避免检查，从而稍微提高 phpMyAdmin 的速度。

### 为多个用户安装

在这个设置中，我们将有一个独立的数据库`pmadb`来存储元数据表。我们的控制用户将有特定的权限访问这个数据库。每个用户将使用自己的登录名和密码来访问自己的数据库。然而，当 phpMyAdmin 本身访问`pmadb`以获取一些元数据时，它将使用控制用户的权限。

### 注意

设置多用户安装只有 MySQL 系统管理员才能做，他有权限给另一个用户（这里是`pma`用户）分配权限。

我们首先确保控制用户`pma`已经创建，并且在`config.inc.php`中的定义是合适的。然后我们将`scripts/create_tables.sql`复制到我们的本地工作站并进行编辑。我们替换以下行：

```sql
-- GRANT SELECT, INSERT, DELETE, UPDATE ON `phpmyadmin`.* TO
-- 'pma'@localhost;

```

使用这些，删除注释字符（双破折号）：

```sql
GRANT SELECT, INSERT, DELETE, UPDATE ON `phpmyadmin`.* TO
'pma'@localhost;

```

然后通过导入执行此脚本（参见[第七章)](ch07.html "第七章。导入结构和数据"）。其净效果是创建`phpmyadmin`数据库，为用户`pma`分配适当的权限，并用所有必要的表填充数据库。

最后一步是调整`config.inc.php`中与关系特性相关的所有参数。请参阅*为单个用户安装*部分，除了`pmadb`参数中的数据库名称，该名称将如下代码片段所示：

```sql
$cfg['Servers'][$i]['pmadb'] = 'phpmyadmin';

```

安装现在已经完成。我们将在接下来的章节中测试功能。我们可以通过退出 phpMyAdmin，然后登录并显示主页来进行快速检查；警告消息应该消失。

# 升级 phpMyAdmin

通常，升级只是将新版本安装到一个单独的目录，并将先前版本的`config.inc.php`复制到新目录。

### 注意

升级路径或首次安装路径，**不应**采用的方法是将`libraries/config.default.php`复制到`config.inc.php`。这是因为默认配置文件是特定版本的，并不能保证适用于将来的版本。

从版本到版本会出现新参数。它们在`Documentation.html`中有文档记录，并在`libraries/config.default.php`中定义。如果配置参数在`config.inc.php`中不存在，则将使用`libraries/config.default.php`中的值。因此，如果默认值适合我们，我们就不必在`config.inc.php`中包含它。

必须特别注意传播我们可能对`layout.inc.php`文件所做的更改，这取决于所使用的主题。如果我们向结构中添加了自定义主题，我们将不得不复制我们的自定义主题子目录。

# 总结

本章介绍了 PHP/MySQL 在 Web 应用程序中的流行程度。该章还概述了为什么 phpMyAdmin 被认为是从 Web 界面访问 MySQL 的领先应用程序。然后讨论了安装 phpMyAdmin 的常见原因，从主要网站下载它的步骤，基本配置，将 phpMyAdmin 上传到我们的 Web 服务器以及升级。

基本安装已完成，下一章将深入探讨配置主题，探索认证和安全方面。


# 第二章：配置身份验证和安全

在 phpMyAdmin 中配置身份验证有许多种方式 - 取决于我们的目标、其他应用程序的存在以及我们需要的安全级别。本章探讨了可用的可能性。

# 通过 phpMyAdmin 登录 MySQL

当我们输入用户名和密码时，尽管看起来我们是在登录 phpMyAdmin，但实际上我们并没有！我们只是使用 phpMyAdmin（运行在 web 服务器上）作为一个界面，将我们的用户名和密码信息发送到 MySQL 服务器。严格来说，我们并没有登录*到*phpMyAdmin，而是*通过*phpMyAdmin。

### 注意

这就是为什么在关于 phpMyAdmin 的用户支持论坛中，询问身份验证帮助的人经常被引荐回他们的 MySQL 服务器管理员，因为丢失的 MySQL 用户名或密码不是 phpMyAdmin 的问题。

本节解释了 phpMyAdmin 提供的各种身份验证模式。

## 在没有密码的情况下登录账户

MySQL 的默认安装会使服务器容易受到入侵，因为它创建了一个名为`root`的 MySQL 账户，而不设置密码 - 除非 MySQL 分发商已经设置了密码。对于这种安全性弱点的推荐解决方法是为`root`账户设置密码。如果我们无法设置密码或不想设置密码，我们将不得不对 phpMyAdmin 进行配置更改。事实上，存在一个特定于服务器的配置参数，`$cfg['Servers'][$i]['AllowNoPassword']`。它的默认值是`false`，这意味着不允许没有密码的账户登录。通常，这个指令应该保持为`false`，以避免通过 phpMyAdmin 进行这种访问，因为黑客正在积极地探测 web 上的不安全的 MySQL 服务器。查看*保护 phpMyAdmin*部分，了解有关保护服务器的其他想法。

### 注意

如果`AllowNoPassword`参数保持为`false`，并且尝试登录而没有密码，则会显示**拒绝访问**消息。

## 使用`config`身份验证对单个用户进行身份验证

我们可能需要通过固定的用户名和密码自动连接到 MySQL 服务器，而无需甚至被要求。这就是`config`身份验证类型的确切目标。

对于我们的第一个示例，我们将使用`config`身份验证。然而，在*身份验证多个用户*部分，我们将看到更强大和多功能的身份验证方式。

### 注意

使用`config`身份验证类型会使我们的 phpMyAdmin 容易受到入侵，除非我们像本章的*保护 phpMyAdmin*部分所解释的那样保护它。

在这里，我们要求`config`身份验证，并为这个 MySQL 服务器输入我们的用户名和密码：

```sql
$cfg['Servers'][$i]['auth_type'] = 'config';
$cfg['Servers'][$i]['user'] = 'marc';
$cfg['Servers'][$i]['password'] = 'xxx';

```

然后我们可以保存我们在`config.inc.php`中所做的更改。

### 测试 MySQL 连接

现在是时候启动 phpMyAdmin 并尝试使用我们配置的值连接到它。这将测试以下内容：

+   我们在`config`文件或基于 web 的设置中输入的值

+   PHP 组件在 web 服务器内的设置，如果我们进行了手动配置

+   web 和 MySQL 服务器之间的通信

我们启动浏览器，并将其指向我们安装 phpMyAdmin 的目录，如[`www.mydomain.com/phpMyAdmin/`](http://www.mydomain.com/phpMyAdmin/)。如果这不起作用，我们尝试[`www.mydomain.com/phpMyAdmin/index.php`](http://www.mydomain.com/phpMyAdmin/index.php)。（这意味着我们的 web 服务器没有配置为将`index.php`解释为默认的起始文档。）

如果仍然出现错误，请参考附录 A 进行故障排除和支持。现在我们应该看到 phpMyAdmin 的主页。第三章概述了现在看到的面板。

## 身份验证多个用户

我们可能希望允许一份 phpMyAdmin 副本被一组人使用，每个人都有自己的 MySQL 用户名和密码，并且只能看到他们有权限的数据库。或者我们可能更喜欢避免在`config.inc.php`中以明文形式存储我们的用户名和密码。

phpMyAdmin 不再依赖于`config.inc.php`中存储的用户名和密码，而是与浏览器通信，并从中获取认证数据。这使得所有在特定 MySQL 服务器中定义的用户都可以进行真正的登录，而无需在配置文件中定义它们。有三种模式可以允许通过 phpMyAdmin 对 MySQL 进行受控登录——`http，cookie`和`signon`。我们将不得不选择适合我们特定情况和环境的模式（稍后会详细介绍）。`http`和`cookie`模式可能需要我们首先定义一个控制用户，如第一章中所述。

### 使用 HTTP 进行身份验证

这种模式`—http—`是 HTTP 中提供的传统模式，其中浏览器请求用户名和密码，将它们发送到 phpMyAdmin，并一直发送直到所有浏览器窗口关闭。

要启用这种模式，我们只需使用以下行：

```sql
$cfg['Servers'][$i]['auth_type'] = 'http';

```

我们还可以通过`$cfg['Servers'][$i]['auth_http_realm']`定义 HTTP 的**基本认证领域**（[`en.wikipedia.org/wiki/Basic_access_authentication`](http://en.wikipedia.org/wiki/Basic_access_authentication)），这是在登录时向用户显示的消息，这可以帮助指示此服务器的目的。

这种模式有以下限制：

+   根据版本不同，PHP 可能不支持所有类型的 Web 服务器的 HTTP 身份验证。

+   如果我们想要用`.htaccess`文件保护 phpMyAdmin 的目录（参考本章的*Securing phpMyAdmin*部分），这将干扰 HTTP 身份验证类型；我们不能同时使用两者。

+   浏览器通常会存储认证信息以节省重新输入凭据的时间，但请记住这些凭据是以未加密的格式保存的。

+   HTTP 协议中没有适当的注销支持；因此我们必须关闭所有浏览器窗口才能再次使用相同的用户名登录。

### 使用 cookie 值进行身份验证

`cookie`身份验证模式在提供的功能方面优于`http`。这种模式允许真正的登录和注销，并且可以与任何类型的 Web 服务器上运行的 PHP 一起使用。它在 phpMyAdmin 内部呈现登录面板（如下面的截图所示）。这可以根据应用程序源代码进行自定义。然而，正如你可能已经猜到的，对于`cookie`身份验证，浏览器必须接受来自 Web 服务器的 cookie——但无论如何，这对所有身份验证模式都是如此。

这种模式将登录屏幕中输入的用户名存储为我们浏览器中的永久 cookie，而密码则存储为临时 cookie。在多服务器配置中，与每个服务器对应的用户名和密码是分开存储的。为了防止针对 cookie 内容的攻击方法泄露用户名和密码的机密性，它们使用 Blowfish 密码进行加密。因此，要使用这种模式，我们必须在`config.inc.php`中定义（一次）一个秘密字符串，该字符串将用于安全加密从此 phpMyAdmin 安装中存储为 cookie 的所有密码。

这个字符串是通过`blowfish_secret`指令设置的：

```sql
$cfg['blowfish_secret'] = 'jgjgRUD875G%/*';

```

在上面的例子中，使用了一串任意的字符；这个字符串可以非常复杂，因为没有人需要在登录面板上输入它。如果我们未能配置这个指令，phpMyAdmin 将生成一个随机的秘密字符串，但它只会持续当前的工作会话。因此，一些功能，比如在登录面板上回忆上一个用户名，将不可用。

然后，对于每个特定服务器的部分，使用以下内容：

```sql
$cfg['Servers'][$i]['auth_type'] = 'cookie';

```

下次启动 phpMyAdmin 时，我们将看到如下截图所示的登录面板：

![使用 cookie 值进行身份验证](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_02_01.jpg)

默认情况下，phpMyAdmin 在登录面板中显示上次成功登录到该特定服务器的用户名，从永久 cookie 中检索。如果这种行为不可接受（同一工作站上的其他用户不应该看到上一个用户名），我们可以将以下参数设置为`FALSE`：

```sql
$cfg['LoginCookieRecall'] = FALSE;

```

有一个安全功能，可以为密码的有效性添加特定的时间限制。这个功能有助于保护工作会话。成功登录后，我们的密码（加密）与计时器一起存储在 cookie 中。phpMyAdmin 中的每个操作都会重置计时器。如果我们在一定数量的秒内保持不活动，就会被断开连接，必须重新登录，这个数量在`$cfg['LoginCookieValidity']`中定义。增加这个参数并不总是有效，因为 PHP 自己的`session.gc_maxlifetime`指令可能会有阻碍。请参考[`php.net/manual/en/session.configuration.php`](http://php.net/manual/en/session.configuration.php)来了解这个指令。因此，如果 phpMyAdmin 检测到`session.gc_maxlifetime`的值小于配置的`$cfg['LoginCookieValidity']`，则会在主页上显示警告。默认值为 1440 秒；这与`php.ini`中`session.gc_maxlifetime`参数的默认值相匹配。

### 注意

用于保护用户名和密码的 Blowfish 算法需要进行许多计算。为了实现最佳速度，我们的 Web 服务器上必须安装 PHP 的`mcrypt`扩展及其相应的库。

为了帮助用户意识到这个扩展是非常重要的，当 phpMyAdmin 检测到其缺失时，会在主页上显示一条消息。`$cfg['McryptDisableWarning']`指令控制这条消息。默认情况下，`false`的值意味着显示这条消息。

### 使用登录模式进行身份验证

在工作会话期间，用户可能会遇到来自不同 Web 应用程序的多个身份验证请求。原因是这些应用程序之间不会相互通信，这种情况会给大多数用户带来不便。

`signon`模式使我们能够使用另一个应用程序的凭据来跳过 phpMyAdmin 的身份验证阶段。为了使其工作，这个其他应用程序必须将正确的凭据存储到 PHP 的会话数据中，以便稍后由 phpMyAdmin 检索。

### 注意

根据 PHP 手册，将凭据存储在 PHP 会话中并不一定安全：[`php.net/manual/en/session.security.php`](http://php.net/manual/en/session.security.php)。

要启用这种模式，我们从以下指令开始：

```sql
$cfg['Servers'][$i]['auth_type'] = 'signon';

```

假设认证应用程序已经使用名为`FirstApp`的会话来存储凭据。我们通过添加以下代码行告诉 phpMyAdmin：

```sql
$cfg['Servers'][$i]['SignonSession'] = 'FirstApp';

```

我们必须注意那些在其他应用程序之前尝试访问 phpMyAdmin 的用户；在这种情况下，phpMyAdmin 将用户重定向到认证应用程序。这是通过以下方式完成的：

```sql
$cfg['Servers'][$i]['SignonURL'] = 'http://www.mydomain.com/FirstApp';

```

认证应用程序如何以 phpMyAdmin 能够理解的格式存储凭据？一个示例包含在`scripts/signon.php`中。在这个脚本中，有一个简单的 HTML 表单来输入凭据和初始化会话的逻辑——我们将使用`FirstApp`作为会话名称，并将用户、密码、主机和端口信息创建到这个会话中，如下所示：

```sql
$_SESSION['PMA_single_signon_user'] = $_POST['user'];
$_SESSION['PMA_single_signon_password'] = $_POST['password'];
$_SESSION['PMA_single_signon_host'] = $_POST['host'];
$_SESSION['PMA_single_signon_port'] = $_POST['port'];

```

### 注意

请注意，认证的第一个应用程序不需要向用户询问 MySQL 的凭据。这些可以在应用程序内部硬编码，因为它们是机密的，或者这个应用程序的凭据与 MySQL 的凭据之间有已知的对应关系。

要将附加的配置参数传递给`signon`模块，`$_SESSION['PMA_single_signon_cfgupdate']`可以接收一个包含在`$cfg['Servers'][$i]`中允许的任何附加服务器参数的数组。

然后，认证应用程序使用自己选择的方式——链接或按钮——让其用户启动 phpMyAdmin。如果在登录过程中发生错误（例如，拒绝访问），`signon`模块将适当的错误消息保存到`$_SESSION['PMA_single_signon_error_message']`中。

在另一个示例中，`scripts/openid.php`展示了如何使用流行的 OpenID 机制进行登录。

## 配置多服务器支持

`config.inc.php`文件至少包含一个特定服务器部分；但是，我们可以添加更多部分，使单个 phpMyAdmin 副本能够管理多个 MySQL 服务器。让我们看看如何配置更多服务器。

### 在配置文件中定义服务器

在`config.inc.php`文件的特定服务器部分，我们看到了每个服务器的`$cfg['Servers'][$i]`的引用行。在这里，变量`$i`被使用，以便可以轻松地剪切和粘贴整个配置文件的部分来配置更多服务器。在复制这些部分时，我们应该注意复制`$i++`指令，这是在每个部分之前并且对于界定服务器部分至关重要的。

然后，在各个部分的末尾，以下行控制启动：

```sql
$cfg['ServerDefault'] = 1;

```

默认值`1`表示 phpMyAdmin 将默认使用第一个定义的服务器。我们可以指定任何数字，对应于特定服务器的部分。我们还可以输入值`0`，表示没有默认服务器；在这种情况下，登录时将呈现可用服务器的列表。

这个配置也可以通过基于 web 的设置来完成。这里给出了一个多服务器定义的示例，其中默认服务器设置为**让用户选择：**

![在配置文件中定义服务器](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_02_02.jpg)

如果没有定义默认服务器，phpMyAdmin 将呈现服务器选择：

![在配置文件中定义服务器](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_02_03.jpg)

### 通过任意服务器进行身份验证

如果我们想要能够连接到未定义的 MySQL 服务器，可以使用另一种机制。首先，我们必须设置以下参数：

```sql
$cfg['AllowArbitraryServer'] = TRUE;

```

我们还需要将`$cfg['ServerDefault']`的默认值设置回`1`。然后，我们需要使用`cookie`认证类型。我们将能够选择服务器并输入用户名和密码。

### 注意

允许任意服务器意味着可以通过 phpMyAdmin 连接到我们的网页服务器可访问的任何 MySQL 服务器。因此，这个功能应该与加强的安全机制一起使用（参考*Securing phpMyAdmin*部分）。

正如在这里所看到的，我们仍然可以在**服务器选择**中选择一个已定义的服务器。此外，我们还可以输入一个任意的服务器名称、用户名和密码。

![通过任意服务器进行身份验证](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_02_04.jpg)

## 登出

有一个机制可以告诉 phpMyAdmin 用户注销后应该到达哪个 URL。这个功能可以方便地与其他应用程序集成，并适用于所有允许注销的认证类型。这里是一个例子：

```sql
$cfg['Servers'][$i]['LogoutURL'] = 'http://www.mydomain.com';

```

这个指令必须包含一个绝对 URL，包括协议。

# 保护 phpMyAdmin

安全性可以在以下不同的级别进行检查：

+   如何保护 phpMyAdmin 安装目录

+   哪些工作站可以访问 phpMyAdmin

+   合法用户可以看到哪些数据库

## 在目录级别保护 phpMyAdmin

假设有人未经授权尝试使用我们的 phpMyAdmin 副本。如果我们使用简单的`config`认证类型，任何知道我们的 phpMyAdmin URL 的人都将具有与我们相同的数据访问权限。在这种情况下，我们应该使用网页服务器提供的目录保护机制（例如，`.htaccess`，以点开头的文件名）来增加一层保护。更多细节请参阅[`en.wikipedia.org/wiki/Basic_access_authentication`](http://en.wikipedia.org/wiki/Basic_access_authentication)。

如果我们决定使用`http`或`cookie`身份验证类型，我们的数据将足够安全。但是，我们应该对密码采取正常的预防措施（包括定期更改密码）。

phpMyAdmin 安装目录包含敏感数据。不仅配置文件，而且存储在那里的所有脚本都必须受到保护，以防止更改。我们应该确保除了我们之外，只有 Web 服务器有效用户可以读取该目录中包含的文件，并且只有我们可以对其进行写入。

### 注意

phpMyAdmin 的脚本永远不必修改此目录中的任何内容，除非我们使用**将导出文件保存到服务器**功能（在第六章中有解释）。

另一个建议是将默认的`phpMyAdmin`目录重命名为不太明显的名称；这可以阻止对我们服务器的探测。这被称为混淆安全，可以非常有效，但避免选择其他明显的名称，如`admin`。

另一个可能的攻击来自与我们在同一 Web 服务器上拥有帐户的其他开发人员。在这种攻击中，某人可以尝试打开我们的`config.inc.php`文件。由于 Web 服务器可以读取此文件，因此某人可以尝试从其 PHP 脚本中包含我们的文件。这就是为什么建议使用 PHP 的`open_basedir`功能，可能将其应用于可能发起此类攻击的所有目录。更多细节可以在[`php.net/manual/en/ini.core.php#ini.open-basedir`](http://php.net/manual/en/ini.core.php#ini.open-basedir)找到。

## 显示错误消息

phpMyAdmin 使用 PHP 的自定义错误处理机制。这个错误处理程序的好处之一是避免路径泄露，这被认为是一种安全弱点。与此相关的默认设置是：

```sql
$cfg['Error_Handler'] = array();
$cfg['Error_Handler']['display'] = false;

```

除非您正在开发新的 phpMyAdmin 功能并希望看到所有 PHP 错误和警告，否则应该让显示的默认值为`false`。

## 使用基于 IP 的访问控制进行保护

可以实施额外的保护级别，这次验证接收请求的机器的**Internet Protocol (IP)**地址。为了实现这种保护级别，我们构建允许或拒绝访问的规则，并指定这些规则将被应用的顺序。

### 定义规则

规则的格式是：

```sql
<'allow' | 'deny'> <username> [from] <source>

```

`from`关键字是可选的；以下是一些示例：

| 规则 | 描述 |
| --- | --- |
| `allow Bob from 1.2.3/24` | 用户`Bob`允许从匹配网络`1.2.3`的任何地址访问（这是 CIDR IP 匹配，更多细节请参见[`en.wikipedia.org/wiki/CIDR_notation)`](http://en.wikipedia.org/wiki/CIDR_notation)）。 |
| `deny Alice from 4.5/16` | 当用户`Alice`位于网络`4.5`时，无法访问。 |
| `allow Melanie from all` | 用户`Melanie`可以从任何地方登录。 |
| `deny % from all` | `all`可以等同于`0.0.0.0/0`，表示任何主机。在这里，`%`符号表示任何用户。 |

通常我们会有几个规则。假设我们希望有以下两个规则：

```sql
allow Marc from 45.34.23.12
allow Melanie from all

```

我们必须将它们放在`config.inc.php`（在相关的特定服务器部分）中，如下所示：

```sql
$cfg['Servers'][$i]['AllowDeny']['rules'] =
array('allow Marc from 45.34.23.12', 'allow Melanie from all');

```

在定义单个规则或多个规则时，使用 PHP 数组。我们必须遵循其语法，将每个完整规则括在单引号中，并用逗号分隔每个规则。因此，如果我们只有一个规则，仍然必须使用数组来指定它。下一个参数解释了规则解释的顺序。

### 规则解释的顺序

默认情况下，此参数为空：

```sql
$cfg['Servers'][$i]['AllowDeny']['order'] = '';

```

这意味着不进行基于 IP 的验证。

假设我们希望默认情况下允许访问，只拒绝对某些用户名/IP 对的访问，我们应该使用：

```sql
$cfg['Servers'][$i]['AllowDeny']['order'] = 'deny,allow';

```

在这种情况下，所有`deny`规则将首先应用，然后是`allow`规则。如果规则中没有提到的情况，将允许访问。为了更加严格，我们希望默认情况下拒绝。我们可以使用：

```sql
$cfg['Servers'][$i]['AllowDeny']['order'] = 'allow,deny';

```

这次，所有`allow`规则首先应用，然后是`deny`规则。如果规则中没有提到的情况，访问将被拒绝。指定规则顺序的第三种（也是最严格的）方式是：

```sql
$cfg['Servers'][$i]['AllowDeny']['order'] = 'explicit';

```

现在，`deny`规则会在`allow`规则之前应用。用户名/IP 地址对必须在`allow`规则中列出，并且不能在`deny`规则中列出，才能获得访问权限。

### 阻止 root 访问

由于`root`用户几乎存在于所有的 MySQL 安装中，因此经常成为攻击目标。一个参数允许我们轻松地阻止 MySQL 的`root`账户的所有 phpMyAdmin 登录，使用以下设置：

```sql
$cfg['Servers'][$i]['AllowRoot'] = FALSE;

```

一些系统管理员更喜欢在 MySQL 服务器级别禁用`root`账户，创建另一个不太明显的账户，拥有相同的权限。这样做的好处是阻止了来自所有来源的`root`访问，而不仅仅是来自 phpMyAdmin。

## 保护传输中的数据

HTTP 本身并不免疫网络嗅探（从传输中获取敏感数据）。因此，如果我们不仅想保护用户名和密码，而且想保护在 Web 服务器和浏览器之间传输的所有数据，那么我们必须使用 HTTPS。

为此，假设我们的 Web 服务器支持 HTTPS，我们只需在 URL 中使用`https`而不是`http`来启动 phpMyAdmin，如下所示：

```sql
https://www.mydomain.com/phpMyAdmin/

```

如果我们正在使用`PmaAbsoluteUri`自动检测，如下所示：

```sql
$cfg['PmaAbsoluteUri'] = '';

```

phpMyAdmin 将看到我们在 URL 中使用了 HTTPS，并做出相应的反应。

如果没有，我们必须按照以下方式在此参数中加入`https`部分：

```sql
$cfg['PmaAbsoluteUri'] = 'https://www.mydomain.com/phpMyAdmin';

```

我们可以通过以下设置自动将用户切换到 HTTPS 连接：

```sql
$cfg['ForceSSL'] = TRUE;

```

# 摘要

本章概述了如何使用单个副本的 phpMyAdmin 来管理多个服务器，以及使用认证类型来满足用户组的需求，同时保护认证凭据。本章还涵盖了保护我们的 phpMyAdmin 安装的方法。

在下一章中，我们将看一下 phpMyAdmin 用户界面中包括的所有面板和窗口。


# 第三章：概述界面

在进入以任务为导向的章节之前，例如搜索等，有必要先看一下 phpMyAdmin 界面的一般组织。我们还将看到影响整个界面的配置参数和设置。

# 概述面板和窗口

phpMyAdmin 界面由各种面板和窗口组成，每个面板都有特定的功能。我们将首先简要概述每个面板，然后在本章后面进行详细查看。

## 登录面板

出现的登录面板取决于所选择的身份验证类型。对于`http`类型，它将采用浏览器的 HTTP 身份验证弹出屏幕的形式。对于`cookie`类型，将显示 phpMyAdmin 特定的登录面板（在第二章中介绍）。对于外部身份验证（`signon`），登录面板由外部应用程序本身处理。默认情况下，此面板上有**服务器**选择对话框和**语言**选择器。

然而，如果我们使用`config`身份验证类型，则不会显示登录面板，第一个显示的界面包含导航和主面板。

## 导航和主面板

这些面板一起显示，并在我们使用 phpMyAdmin 的大部分工作会话期间显示。**导航面板**是我们在数据库和表之间的指南。**主面板**是数据管理和结果显示的工作区。其确切布局取决于从导航面板和执行的操作序列中所做的选择。对于大多数从左到右书写的语言，导航面板位于左侧，主面板位于右侧，但对于从右到左书写的语言，如希伯来语，这些面板是相反的。

![导航和主面板](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_03_01.jpg)

### 首页

主面板可以采用起始页的形式。起始页将包含与 MySQL 操作或 phpMyAdmin 信息相关的各种链接，一个**语言**选择器，可能还有**主题/样式**选择器。

### 视图

在主面板中，我们可以看到`数据库`视图——在这里我们可以对特定数据库执行各种操作，或者`表`视图——在这里我们可以访问许多管理表的功能。还有一个`服务器`视图，对系统管理员和非管理员用户都有用。所有这些视图都有一个顶部菜单，它以选项卡的形式呈现，导航到不同的页面，用于呈现按常见功能（表结构、权限等）重新组织的信息。

## 查询窗口

这是一个独立的窗口，通常从导航面板打开，有时也从主面板编辑 SQL 查询时打开。它的主要目的是方便查询工作，并在主面板上显示结果。

## 起始页

当我们启动 phpMyAdmin 时，我们将看到以下面板中的一个（取决于`config.inc.php`中指定的身份验证类型，以及其中是否定义了多个服务器）：

+   其中一个登录面板

+   导航和主面板显示在主面板中的起始页

# 自定义一般设置

本节描述了对许多面板产生影响的设置。这些设置修改了窗口标题的外观，信息图标的外观，以及表格列表的排序方式。所有页面的视觉风格都由主题系统控制，该系统也在本节中介绍。本节还涉及如何限制用户看到的数据库列表。

## 配置窗口标题

当导航和主面板显示时，窗口标题会更改以反映哪个 MySQL 服务器、数据库和表是活动的。这些指令控制要显示的信息量：`$cfg['TitleDefault'], $cfg['TitleServer'], $cfg['TitleDatabase']`和`$cfg['TitleTable']`。

如果没有选择服务器，则`$cfg['TitleDefault']`控制标题。当选择了服务器（但没有选择数据库）时，`$cfg['TitleServer']`控制标题栏中显示的内容。然后如果选择了数据库，则`$cfg['TitleDatabase']`起作用。最后，如果选择了表，则`$cfg['TitleTable']`生效。

这些指令包含控制显示哪些信息的格式字符串。例如，这是其中一个指令的默认值：

```sql
$cfg['TitleTable'] = '@HTTP_HOST@ / @VSERVER@ / @DATABASE@ / @TABLE@ | @PHPMYADMIN@';

```

可能的格式字符串及其含义在`Documentation.html`的 FAQ 6.27 中有描述。

## 数据库和表名的自然排序

通常，计算机按词法顺序对项目进行排序，这会导致对表列表的以下结果：

```sql
table1
table10
table2
table3

```

phpMyAdmin 默认实现**自然排序**，由`$cfg['NaturalOrder']`设置为`TRUE`来指定。因此导航和主面板中的数据库和表列表按以下方式排序：

```sql
table1
table2
table3
table10

```

## 创建特定网站的页眉和页脚

一些用户可能希望在`phpMyAdmin`界面上显示公司标志、公司帮助台的链接或其他信息。为此，在主`phpMyAdmin`目录中，我们可以创建两个脚本`—config.header.inc.php`和`config.footer.inc.php`。我们可以在这些脚本中放入我们自己的 PHP 或 XHTML 代码，它将出现在`cookie`登录和主面板页面的开头（页眉）或结尾（页脚）。

例如，创建一个包含以下内容的`config.footer.inc.php`：

```sql
<hr />
<em>All the information on this page is confidential.</em>

```

在页脚中使用这样的句子将在所有页面上产生预期的消息，如下截图所示：

![创建特定网站的页眉和页脚](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_03_02.jpg)

## 主题

phpMyAdmin 中提供了一个主题系统。颜色参数和各种图标位于`themes`子目录下的目录结构中。对于每个可用的主题，都有一个以主题命名的子目录。它包含：

+   主题参数的`layout.inc.php`

+   包含各种 CSS 脚本的`css`目录

+   包含任何图标或其他图像（例如标志）的`img`目录

+   `screen.png`，这个主题的屏幕截图

下载的套件包含两个主题，但在[`phpmyadmin.net/home_page/themes.php`](http://phpmyadmin.net/home_page/themes.php)上还有更多可用的主题。安装新主题只需下载相应的`.zip`文件并将其解压缩到`themes`子目录中。

### 注意

如果有人想要构建一个包含 JavaScript 代码的自定义主题，请注意所有 phpMyAdmin 3.4 页面都包含 jQuery 库。

### 配置主题

在`config.inc.php`中，`$cfg['ThemePath']`参数默认包含`'./themes'`，指示所需结构位于的子目录。这可以更改为指向另一个目录，其中包含您公司特定的 phpMyAdmin 主题。

默认选择的主题在`$cfg['ThemeDefault']`中指定，并设置为`'pmahomme'`。如果用户没有主题选择，将使用此主题。

### 选择主题

在主页上，我们可以向用户提供一个主题选择器。将`$cfg['ThemeManager']`设置为`TRUE`（默认值）会显示如下截图所示的选择器：

![选择主题](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_03_03.jpg)

为了帮助选择合适的主题，**主题/样式**链接显示一个面板，其中包含可用主题的屏幕截图和**获取更多主题**链接。然后我们可以在想要的主题下点击**take it**。所选主题的引用将存储在一个 cookie 中，并且默认情况下将应用于我们连接的所有服务器。

为了使 phpMyAdmin 记住每个 MySQL 服务器的一个主题，我们将`$cfg['ThemePerServer']`设置为`TRUE`。

## 选择语言

登录面板（如果有）和主页上会出现一个**语言**选择器。phpMyAdmin 的默认行为是使用浏览器偏好设置中定义的语言，如果有对应版本的语言文件的话。

如果程序无法检测到语言，则使用的默认语言在`config.inc.php`中的`$cfg['DefaultLang']`参数中定义为`'en'`（英语）。这个值是可以改变的。语言名称的可能值在`libraries/select_lang.lib.php`脚本中的`PMA_langDetails()`函数中定义。

即使默认语言已经定义，每个用户（特别是在多用户安装中）都可以从选择器中选择自己喜欢的语言。用户的选择将在可能的情况下保存在 cookie 中。

我们还可以通过设置`$cfg['Lang']`参数的值（比如`'fr'`表示法语）来强制使用单一语言。另一个参数`$cfg['FilterLanguages']`也是可用的。假设我们想要缩短可用语言列表，只显示**英语**和**法语**，因为这些是 phpMyAdmin 实例的用户专门使用的语言。这可以通过构建一个正则表达式来实现，指示我们想要显示的语言基于这些语言的 ISO 639 代码。继续我们的例子，我们会使用：

```sql
$cfg['FilterLanguages'] = '^(fr|en)';

```

在这个表达式中，插入符（^）表示“以…开头”，竖线（|）表示“或”。这个表达式表示我们将语言列表限制在对应的 ISO 代码以`fr`或`en`开头的语言。

默认情况下，这个参数是空的，意味着没有对可用语言列表应用任何过滤器。

## 滑块

在一些页面上，你会看到一个小加号，后面跟着一个控制标签——要么是**选项**，要么是**详情**。点击标签会打开一个滑块，显示界面的一个部分，这部分在日常工作中很少使用。由于很少有人愿意立即看到整个界面而牺牲屏幕空间，因此有一个配置参数来控制滑块的初始设置方式：

```sql
$cfg['InitialSlidersState'] = 'closed';

```

`closed`的默认值意味着滑块必须通过点击标签来打开；你可能已经猜到了相反的值是`open`。第三个值`disabled`可以被滑块过敏的用户使用。

## 限制数据库列表

有时候，避免在导航面板中显示用户可以访问的所有数据库是有用的。phpMyAdmin 提供了两种限制的方式——`only_db`和`hide_db`。

为了指定可以看到的内容列表，使用`only_db`参数。它可以包含一个数据库名称或一个数据库名称列表。只有这些数据库将在导航面板中显示：

```sql
$cfg['Servers'][$i]['only_db'] = 'payroll';
$cfg['Servers'][$i]['only_db'] = array('payroll', 'hr);

```

数据库名称可以包含 MySQL 通配符，比如`_`和`%`。这些通配符在[`dev.mysql.com/doc/refman/5.1/en/account-names.html`](http://dev.mysql.com/doc/refman/5.1/en/account-names.html)中有描述。如果使用数组来指定多个数据库，它们将按照数组中的顺序在界面上显示。

`only_db`的另一个特性是，你可以使用它来不限制列表，而是强调将显示在列表顶部的某些名称。在这里，`myspecial`数据库名称将首先显示，然后是所有其他名称：

```sql
$cfg['Servers'][$i]['only_db'] = array('myspecial', '*');

```

我们还可以使用`hide_db`参数指定哪些数据库名称必须被隐藏。它包含一个正则表达式（[`en.wikipedia.org/wiki/Regular_expression`](http://en.wikipedia.org/wiki/Regular_expression)），表示要排除的内容。如果我们不希望用户看到任何以`'secret'`开头的数据库，我们会使用：

```sql
$cfg['Servers'][$i]['hide_db'] = '^secret';

```

这些参数适用于此服务器特定配置的所有用户。

### 注意

这些机制不会取代 MySQL 权限系统。用户对其他数据库的权限仍然适用，但他们不能使用 phpMyAdmin 的导航面板来访问他们的其他数据库或表。

## 停用 Ajax

某些页面使用**异步**JavaScript 来改善用户体验。我们可以通过将`$cfg['AjaxEnable']`设置为`false`来停用此行为；在这种情况下，已经编程为非 Ajax 行为的页面将停止使用 Ajax，而是执行完全刷新。用户可能会感觉这样的体验不够流畅。

# 字符集和排序规则

**字符集**描述了特定语言或方言的符号是如何编码的。**排序规则**包含了比较和排序字符集中字符的规则。用于存储我们的数据的字符集可能与用于显示它的字符集不同，导致数据不一致。因此，需要进行数据转换。

自从 MySQL 4.1.x 以来，MySQL 服务器为我们进行字符重编码工作。此外，MySQL 使我们能够指示每个数据库、每个表甚至每个字段的字符集和排序规则。数据库的默认字符集适用于其每个表，除非在表级别被覆盖。相同的原则适用于每一列。

## 有效的字符集和排序规则

在主页上，我们可以看到**MySQL 字符集**信息和**MySQL 连接排序规则**选择器。这是**MySQL 字符集**信息：

![有效的字符集和排序规则](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_03_04.jpg)

字符集信息（在**MySQL 字符集**之后所见）用于生成 HTML 信息，告诉浏览器页面的字符集是什么。

我们还可以使用**MySQL 连接排序规则**对话框选择连接到 MySQL 服务器时要使用的字符集和排序规则。这将传递给 MySQL 服务器。MySQL 然后将要发送到我们的浏览器的字符转换为此字符集。MySQL 还根据字符集信息解释从浏览器接收到的内容。请记住，所有表和列都有描述其数据编码方式的字符集信息。

![有效的字符集和排序规则](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_03_05.jpg)

通常情况下，默认值应该有效。但是，如果我们使用不同的字符集输入一些字符，我们可以在此对话框中选择适当的字符集。

以下参数定义了默认连接排序规则和字符集：

```sql
$cfg['DefaultConnectionCollation'] = 'utf8_unicode_ci';

```

# 导航面板

导航面板包含以下元素：

+   标志

+   服务器列表（如果`$cfg['LeftDisplayServers']`设置为`TRUE`）

+   **主页**链接或图标（返回到 phpMyAdmin 主页）

+   **注销**链接或图标（如果可以注销）

+   指向**查询窗口**的链接或图标

+   显示 phpMyAdmin 和 MySQL 文档的图标

+   **重新加载**链接或图标（仅刷新此面板）

+   表名过滤器（在某些条件下，请参见*表名过滤器*部分）

+   数据库和表的名称

如果`$cfg['MainPageIconic']`设置为`TRUE`（默认值），我们会看到图标。但是，如果设置为`FALSE`，我们会看到链接。

导航面板可以通过点击并移动垂直分隔线来调整大小，以向首选方向显示更多数据，以防数据库或表名对于默认导航面板大小太长。

我们可以自定义此面板的外观。许多与外观相关的参数位于`themes/<themename>/layout.inc.php`中。`$cfg['NaviWidth']`参数包含导航面板的默认宽度（以像素为单位）。背景颜色在`$cfg['NaviBackground']`中定义。`$cfg['NaviPointerColor']`参数定义了指针颜色。要激活正在使用的任何主题的导航指针，`config.inc.php`中存在一个主设置`$cfg['LeftPointerEnable']`。其默认值为`TRUE`。

## 配置标志

标志显示行为由多个参数控制。首先，`$cfg['LeftDisplayLogo']`必须设置为`TRUE`，才能启用标志的任何显示。默认情况下是`true`。单击此标志将界面带到`$cfg['LeftLogoLink']`参数中列出的页面，通常是 phpMyAdmin 的主页面（默认值`main.php`），但可以更改为任何 URL。最后，`$cfg['LeftLogoLinkWindow']`参数指示单击标志后新页面出现在哪个窗口。默认情况下，它在主页面上（值为`main`）。但是，通过使用值`new`，它可以在全新的窗口上。

logo_left.png 文件本身来自于每个特定主题目录结构中的位置。

## 数据库和表列表

以下示例显示尚未选择任何数据库：

![数据库和表列表](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_03_06.jpg)

也可能看到**没有数据库**消息，而不是数据库列表。这意味着我们当前的 MySQL 权限不允许我们查看任何现有数据库。

### 注意

MySQL 服务器始终至少有一个数据库（名为**mysql**），但可能存在我们无权查看它的情况。此外，从 MySQL 5.0.2 开始，除非通过`$cfg['Servers'][$i]['only_db']`或`$cfg['Servers'][$i]['hide_db']`机制隐藏，否则数据库列表中始终会出现一个名为**information_schema**的特殊数据库。它包含一组描述已登录用户可见的元数据的视图。

我们可能有权创建一个，如第四章中所述。

### 轻模式

导航面板可以以两种方式显示——**轻模式**和**完整模式**。轻模式是默认使用的，由`$cfg['LeftFrameLight']`中的`TRUE`值定义。此模式显示可用数据库的下拉列表，并且仅显示当前选择数据库的表。它比完整模式更有效；原因在本章后面的*完整模式*部分中解释。在下面的屏幕截图中，我们选择了**mysql**数据库：

![轻模式](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_03_07.jpg)

单击数据库名称或选择它会在`Database`视图中打开主面板，单击表名会在`Table`视图中打开主面板以浏览此表。（有关详细信息，请参阅*主面板*部分。）

#### 数据库名称的树形显示

例如，用户可能被允许只在一个数据库上工作**marc**。一些系统管理员通过允许用户**marc**创建许多数据库，前提是所有数据库的名称都以**marc**开头，例如**marc_airline**和**marc_car**，提供了更灵活的方案。在这种情况下，导航面板可以设置为显示这些数据库名称的树，如下面的屏幕截图所示：

![数据库名称的树形显示](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_03_08.jpg)

此功能由以下参数控制：

```sql
$cfg['LeftFrameDBTree'] = TRUE;
$cfg['LeftFrameDBSeparator'] = '_';

```

`$cfg['LeftFrameDBTree']`中的`TRUE`的默认值确保了此功能的激活。分隔符的常用值是`'_'`。如果我们需要多个字符集作为分隔符，我们只需使用一个数组：

```sql
$cfg['LeftFrameDBSeparator'] = array('_', '+');

```

#### 表名过滤器

如果数据库中有太多表，我们可能只想显示其中的一部分，基于过滤文本字符串。仅在轻模式下，如果当前选择了数据库，则会显示一个表名过滤器，前提是表的数量超过了`$cfg['LeftDisplayTableFilterMinimum']`的值，默认值为`30`。当我们在此过滤器中输入表名的子集时，表的列表将减少以匹配此子集。要尝试此功能，我们将指令的值设置为`15`，并在过滤字段中输入**time**：

![表名过滤器](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_03_09.jpg)

### 完整模式

先前的示例是在 Light 模式下显示的，但是将`$cfg['LeftFrameLight']`参数设置为`FALSE`会使用可折叠菜单（如果浏览器支持）完整布局我们的数据库和表格，如下截图所示：

![全模式](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_03_10.jpg)

默认情况下，未选择全模式；如果我们当前的权限允许我们访问大量数据库和表格，它可能会增加网络流量和服务器负载。必须在导航面板中生成链接，以启用对表格的访问和快速访问每个表格。

### 表格简略统计

将光标移动到表格名称上会显示关于该表格的注释（如果有的话），以及当前其中的行数，如下截图所示：

![表格简略统计](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_03_11.jpg)

### 表格快速访问图标

已经确定，表格上最常见的操作必须是浏览。因此，单击表格名称本身会以浏览模式打开它。每个表格名称旁边的图标是在每个表格上执行另一个操作的快捷方式，默认情况下，它会将我们带到“结构”视图。

![表格快速访问图标](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_03_12.jpg)

`$cfg['LeftDefaultTabTable']`参数控制此操作。它的默认值是`'tbl_structure.php'`，这是显示表格结构的脚本。此参数的其他可能值在`Documentation.html`中列出。如果我们更喜欢设置，其中单击表格名称会在**结构**页面中打开它，而单击快速访问图标会导航到**浏览**页面，我们必须设置这些指令：

```sql
$cfg['LeftDefaultTabTable'] = 'sql.php';
$cfg['DefaultTabTable'] = 'tbl_structure.php';

```

### 数据库中表格的嵌套显示

MySQL 的数据结构基于两个级别——数据库和表格。这不允许对表格进行项目划分。要按项目工作，用户必须依靠拥有多个数据库，但这并不总是由他们的提供商允许。为了帮助他们解决这个问题，phpMyAdmin 支持基于表格命名的**嵌套级别**功能。

假设我们可以访问**db1**数据库，并且我们想要表示两个项目，**营销**和**工资单**。在项目名称和表格名称之间使用特殊分隔符（默认为双下划线），我们创建**marketing, payroll__employees**和**payroll__jobs**表格，实现如下截图所示的视觉效果：

![数据库中表格的嵌套显示](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_03_13.jpg)

此功能是通过`$cfg['LeftFrameTableSeparator']`（此处设置为`'__'`）进行参数化，以选择标记每个级别更改的字符，以及`$cfg['LeftFrameTableLevel']`（此处设置为`'1'）`用于子级的数量。

### 注意

嵌套级别功能仅用于改进导航面板的外观。在 MySQL 语句中引用表格的正确方法保持不变，例如，`db1.payroll__jobs`。

单击导航面板上的项目名称（这里是**payroll**）会在主面板中打开此项目，仅显示与该项目关联的表格。

### 计算表格数量

默认情况下，`$cfg['Servers'][$i]['CountTables']`设置为`false`，以加快显示速度，不统计每个数据库的表格数量。如果设置为`true`，则在导航面板中显示此计数，显示在每个数据库名称旁边。

## 从服务器列表中选择

如果我们必须从同一个 phpMyAdmin 窗口管理多个服务器，并且经常需要在服务器之间切换，始终在导航面板中具有服务器列表是有用的。

![从服务器列表中选择](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_03_14.jpg)

为此，必须将`$cfg['LeftDisplayServers']`参数设置为`TRUE`。服务器列表可以有两种形式——下拉列表或链接。显示哪种形式取决于`$cfg['DisplayServersList']`。默认情况下，此参数设置为`FALSE`，因此我们看到服务器的下拉列表。将`$cfg['DisplayServersList']`设置为`TRUE`会生成到所有定义的服务器的链接列表。

## 处理多个数据库或表格

本节描述了一些应对持有大量数据库和表的服务器的技术。

### 界面上的限制

如果我们可以访问数百甚至数千个数据库，或者在同一个数据库中有数百个表，那么要使用界面将会很困难。这里显示了两个参数及其默认值，它们通过添加页面选择器和导航链接来限制显示的数据库和表的数量：

```sql
$cfg['MaxDbList'] = 100;
$cfg['MaxTableList'] = 250;

```

将`$cfg['MaxTableList']`设置为`5`的效果可以在导航面板上看到，如下所示，对于具有超过五个表的数据库：

![界面上的限制](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_03_15.jpg)

页面选择器和导航链接也出现在主面板中。

### 提高获取速度

三个配置参数会影响数据库名称检索和表计数的速度。第一个是：

```sql
$cfg['Servers'][$i]['ShowDatabasesCommand'] = 'SHOW DATABASES';

```

每当 phpMyAdmin 需要从服务器获取数据库列表时，它都会使用此参数中列出的命令。默认命令`SHOW DATABASES`在普通情况下是可以的。但是，在具有许多数据库的服务器上，通过尝试其他命令，例如以下之一，可以观察到速度的提高：

```sql
SHOW DATABASES LIKE '#user#\_%'
SELECT DISTINCT TABLE_SCHEMA FROM information_schema.SCHEMA_PRIVILEGES'
SELECT SCHEMA_NAME FROM information_schema.SCHEMATA

```

在第一个示例中，`#user#`被当前用户名替换。

在极端情况下（成千上万个数据库），安装自己的 phpMyAdmin 副本的用户应该在此参数中放入`false`。这将阻止任何数据库名称的获取，并要求将`$cfg['Servers'][$i]['only_db']`参数填充为此用户的数据库列表。

最后，一些用户在从`INFORMATION_SCHEMA`中检索信息时（至少在 MySQL 5.1 下）遇到速度问题。因此，`$cfg['Servers'][$i]['DisableIS']`指令，默认值为`TRUE`，禁用了 phpMyAdmin 代码的大部分部分使用`INFORMATION_SCHEMA`。对于您的服务器，将其设置为`FALSE`可能值得一试，以查看响应时间是否有所改善。

# 主面板

**主面板**是主要的工作区域，所有可能的视图都在以下部分中解释。它的外观可以自定义。背景颜色在`$cfg['MainBackground']`中定义。

## 首页

主页的链接数量可能会根据登录模式和用户权限而有所不同。导航面板上的**首页**链接用于显示此页面。它显示了 phpMyAdmin 和 MySQL 的版本，MySQL 服务器名称以及登录用户。为了减少有关我们的 Web 服务器和 MySQL 服务器的信息，我们可以将`$cfg['ShowServerInfo']`设置为`FALSE`。另一个设置`$cfg['ShowPhpInfo']`，如果我们想在主页上看到**显示 PHP 信息**链接，可以将其设置为`TRUE`——默认情况下其值为`FALSE`。在某些情况下，这里可能会出现**无权限**消息；如何解决此问题以及如何修复此条件在第四章中有介绍。

在此示例中，普通用户可以通过使用**更改密码**链接从界面更改他/她的密码，从而带来以下对话框：

![首页](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_03_16.jpg)

我们可以通过两次输入新密码或使用**生成**按钮（仅在启用 JavaScript 的浏览器中可用）来选择新密码；在这种情况下，新密码将显示在一个清晰的字段中，供我们好好记下，并自动填入更改密码的对话框中。强烈建议以这种方式生成密码，因为它们很可能比人为选择的密码更安全。要禁止从主页上的**更改密码**链接，我们将`$cfg['ShowChgPassword']`设置为`FALSE`。特权用户在主页上有更多选项。他们有更多链接来管理整个服务器，例如**权限**链接（有关此内容，请参见第十九章）。

## 数据库视图

每次我们从导航面板点击数据库名称时，phpMyAdmin 都会进入“数据库”视图（如下截图所示）。

这里我们可以看到数据库的概述——现有的表，创建表的对话框，到“数据库”视图页面的选项卡，以及我们可能在此数据库上执行的一些特殊操作，以生成文档和统计信息。每个表旁边都有一个复选框，用于对该表执行全局操作（在第九章中介绍）。通过复选框或单击行背景的任何位置来选择表。如果`$cfg['ShowStats']`设置为`TRUE`，我们还可以看到每个表的大小。此参数还控制“表”视图中表特定统计信息的显示。

这里出现的初始屏幕是数据库的**结构**页面。我们注意到几乎每个列标题——如**表，记录**和**大小**——都是链接，可以用来对应的列进行排序（第第四章介绍了排序）。虽然按降序表名排序可能不太有用，但按降序大小排序绝对是我们应该偶尔做的事情。

![数据库视图](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_03_17.jpg)

当进入“数据库”视图时，我们可能希望出现不同的初始页面。这由`$cfg['DefaultTabDatabase']`参数控制，在配置文件中的注释中给出了可用选项。

行数是使用快速方法获取的，即`SHOW TABLE STATUS`语句，而不是使用`SELECT COUNT(*) FROM TABLENAME`。这种快速方法通常是准确的，但对于`InnoDB`表来说，它返回的是近似记录数。为了帮助获取正确的记录数，即使对于`InnoDB`，也可以使用`$cfg['MaxExactCount']`参数。如果近似记录数低于此参数的值——默认为 20000——将使用较慢的`SELECT COUNT(*)`方法。

不要为`MaxExactCount`参数设置过高的值。如果您的`InnoDB`表中有成千上万行数据，您将得到正确的结果，但需要等待几分钟。要查看显示的`InnoDB`行数，请参阅第十章，在那里我们实际上有一个`InnoDB`表可以使用。

当在“大小”和“开销”列中看到术语**KiB**时，用户可能会感到惊讶。phpMyAdmin 采用了**国际电工委员会（IEC）**的二进制前缀（参见[`en.wikipedia.org/wiki/Binary_prefix)`](http://en.wikipedia.org/wiki/Binary_prefix)）。显示的值在每个语言文件中定义。

## 表视图

这是一个常用的视图，可以访问所有特定于表的页面。默认情况下，初始屏幕是表的**浏览**屏幕，显示此表数据的第一页。请注意，此屏幕的标题始终显示当前数据库和表名称。我们还可以看到为表设置的注释，显示在表名旁边：

![表视图](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_03_18.jpg)

`$cfg['DefaultTabTable']`参数定义了“表”视图的初始页面。一些用户可能希望避免看到第一页的数据，因为在生产中他们通常运行保存的查询或进入**搜索**页面（在第八章中解释）。

## 服务器视图

每次返回主页时都会进入此视图。当然，特权用户在“服务器”视图中会看到更多选项。创建“服务器”视图面板是为了将相关的服务器管理页面分组，并在它们之间实现轻松导航。

![服务器视图](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_03_19.jpg)

默认的“服务器”页面由`$cfg['DefaultTabServer']`参数控制。此参数定义了初始起始页面。对于多用户安装，建议保持默认值`(main.php)`，显示传统的主页。我们可以选择通过将此参数更改为`server_status.php`来显示服务器统计信息，或者通过`server_privileges.php`来查看用户列表。其他可能的选择在配置文件中有解释，并且服务器管理页面在第十九章中有介绍。

## 主页和菜单选项卡的图标

一个配置参数`$cfg['MainPageIconic']`控制主面板各处图标的外观：

+   在主页上

+   在列出“服务器，数据库”和“表”信息时的页面顶部

+   在“数据库，表”和“服务器”视图的菜单选项卡上

当参数设置为`TRUE`时，默认情况下，您将看到以下截图：

![主页和菜单选项卡的图标](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_03_20.jpg)

## 打开新的 phpMyAdmin 窗口

有时我们希望同时比较两个表的数据或者有其他需要使用多个 phpMyAdmin 窗口的情况。几乎每个页面的底部都有一个小图标，可以打开另一个带有当前面板内容的 phpMyAdmin 窗口。此外，此图标还可以用于创建一个指向当前 phpMyAdmin 页面的浏览器书签（但我们应该登录以访问数据）。

![打开新的 phpMyAdmin 窗口](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_03_21.jpg)

# 用户偏好

一个 phpMyAdmin 实例可以安装为多个用户提供服务；但是，在 3.4.0 版本之前，这些用户必须接受由负责此实例的人选择的参数值。

确实，界面上的一些页面允许调整特定参数，并且其中一些参数被记住在 cookie 中，例如所选语言；但这个版本是第一个提供全局机制来调整和记住每个用户的偏好。

即使在实例只有一个用户的情况下，从界面微调偏好比操作配置文件更方便。

## 访问用户偏好

从主页，我们点击“更多设置”。从“服务器”视图中的任何页面，我们点击“设置”菜单选项卡。进入“设置”面板后，我们看到“管理您的设置”子页面：

![访问用户偏好](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_03_22.jpg)

这个子页面是我们全局处理偏好的地方。其他子页面，如“功能”和“主框架”，用于更改特定偏好-请参考“更改设置”部分。

“导入”和“导出”对话框将在“保存偏好的可能位置”部分中介绍。 “更多设置”对话框提醒我们，`config.inc.php`是配置所有可能性的地方，例如指定服务器和认证模式超出了用户偏好的范围。

“重置”对话框使我们可以一键返回所有用户偏好的默认值。

## 保存偏好的可能位置

有三个可能的位置可以保存用户偏好。每个位置都有优缺点；本节涵盖了这些模式。

### 在 phpMyAdmin 配置存储中保存

要启用此模式，必须使用包含这些偏好的表的名称对`$cfg['Servers'][$i]['userconfig']`进行配置，并且该表必须存在。这个保存位置非常有用，因为设置在登录后立即应用于运行的实例；此外，它会跟随用户在任何浏览器上使用。

如果未配置此存储，设置页面会显示以下消息：

“您的偏好将仅保存当前会话。要永久保存它们，需要进行 phpMyAdmin 配置存储”。

### 保存在文件中

我们始终有可能将我们的设置导出到文件中，然后再导入。该文件遵循 JSON 格式（参见[`json.org)`](http://json.org)）。在以下情况下，这种方法可能很方便：

+   我们计划在另一个 phpMyAdmin 实例上使用这些设置

+   我们希望保留我们的设置历史记录；因此，不时地将它们保存在几个文件中

### 保存在浏览器的本地存储中

最近的浏览器，例如 Firefox 6 和 Internet Explorer 9，提供了一种在会话之间持久存在的本地存储机制。第一次进入**管理您的设置**子页面时，我们会在**从浏览器的存储中导入**对话框中看到**您没有保存的设置！**消息。然而，将设置导出到浏览器的本地存储后，**导入**部分会告诉我们使用此机制上次保存设置的日期和时间。

此外，当在浏览器的存储中找到 phpMyAdmin 设置并且 phpMyAdmin 配置存储不可用时，每个 phpMyAdmin 页面顶部都有以下消息：

**您的浏览器为此域名配置了 phpMyAdmin。您想要为当前会话导入吗？是/否**

使用此方法的一个缺点是，我们的设置仅在使用此浏览器时才可用；此外，如果我们更改工作站时我们的浏览器设置不跟随我们，那么设置将绑定到此特定工作站（并适用于在其上运行 phpMyAdmin 的任何其他用户）。

## 更改设置

在进入特定偏好的子页面时，例如**主框架**子页面，我们会看到与此主题相关的第三级菜单：

![更改设置](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_03_23.jpg)

如果偏好已从其默认值更改，则复选框或数据字段具有不同的背景颜色，并且旁边显示了一个回收图标，以便快速将此偏好重置为其默认值。对每个指令都提供了快速解释，并且链接指向文档和官方维基。作为一般建议，我们需要在切换到不同的子页面之前保存我们在页面上所做的任何更改；然而，在这个例子中，我们可以在**启动**和其他第三级菜单之间切换，如**浏览模式**，而不会丢失我们的更改。

## 禁止特定偏好

负责`config.inc.php`的人对用户偏好中可以更改哪些设置有最终决定权。为了禁止某些设置，我们使用`$cfg['UserprefsDisallow']`指令。我们将一个包含代表要禁止的`$cfg`中的键的数组放入其中。例如，我们将此指令设置为：

```sql
$cfg['UserprefsDisallow'] = array('AjaxEnable', 'MaxDbList');

```

这会产生如下截图所示的警告：

![禁止特定偏好](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_03_24.jpg)

## 显示开发人员设置

某些设置是敏感的，仅供开发 phpMyAdmin 的人员使用。例如，显示所有错误的可能性，包括 PHP 通知，可能会导致公开 phpMyAdmin 实例的完整路径。因此，在**功能**子选项卡中，只有在`$cfg['UserprefsDeveloperTab']`设置为`true`时，才会显示**开发人员**菜单。

# 查询窗口

通常情况下，我们可以在一个独立的窗口中输入和调整查询，并且与主面板同步是非常方便的。这个窗口被称为**查询窗口**。我们可以通过使用小的**SQL**图标或导航面板的图标或链接区域中的**查询窗口**链接来打开此窗口。此功能仅适用于启用 JavaScript 的浏览器。

**查询窗口**本身有子页面，并且如下截图所示，它出现在主面板上方：

![查询窗口](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_03_25.jpg)

我们可以使用`$cfg['QueryWindowWidth']`和`$cfg['QueryWindowHeight']`选择此窗口的尺寸（以像素为单位）。第十一章更详细地解释了查询窗口，包括可用的 SQL 查询历史记录功能。

# 总结

本章涵盖了：

+   语言选择系统

+   导航和主面板的目的

+   导航面板的内容，包括轻模式和完整模式

+   主面板的内容，根据上下文的不同有不同的视图

+   用户偏好功能

+   查询窗口

下一章将指导您通过简单的步骤来完成一个新安装的 phpMyAdmin——初始表创建、数据插入和检索。


# 第四章：创建和浏览表

在看到了 phpMyAdmin 的整体布局之后，我们准备创建一个数据库，创建我们的第一个表，向其中插入一些数据，并浏览它。这些第一步是故意简单的，但它们将为您提供更复杂操作的基础。在本章结束时，我们将拥有两个基本表，这是后续练习的基础。

# 创建数据库

在创建表之前，我们必须确保我们有一个数据库，MySQL 服务器的管理员已经给了我们`CREATE`权限。存在以下可能性：

+   管理员已经为我们创建了一个数据库，并且我们在导航面板中看到了它的名称；我们没有权利创建额外的数据库。

+   我们有权从 phpMyAdmin 创建数据库。

+   我们在一个共享主机上，主机提供商已经安装了一个通用的网络界面（例如 cPanel）来创建 MySQL 数据库和账户；在这种情况下，我们现在应该访问这个网络界面，确保我们至少创建了一个数据库和一个 MySQL 账户。

`Server`视图中的**数据库**面板是查找数据库创建对话框的地方。请注意，配置参数`$cfg['ShowCreateDb']`控制**创建新数据库**对话框的显示。默认情况下，它设置为`true`，显示对话框。

## 无权限

如果您没有创建数据库的权限，面板在**创建新数据库**标签下显示**无权限**消息。这意味着您必须使用已为您创建的数据库，或者要求 MySQL 服务器的管理员给您必要的`CREATE`权限。

### 注意

如果您是 MySQL 服务器的管理员，请参阅第十九章。

## 第一个数据库创建已被授权

如果 phpMyAdmin 检测到我们有权创建数据库，则对话框将显示如下截图所示：

![第一个数据库创建已被授权](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_04_01.jpg)

在输入字段中，如果`$cfg['SuggestDBName']`参数设置为`TRUE`，则会出现建议的数据库名称，这是默认设置。建议的数据库名称是根据我们拥有的权限构建的。

如果我们受限于使用前缀，前缀可能会在输入字段中建议。在这种情况下，前缀后面可能会跟着一个省略号，由 phpMyAdmin 添加。我们应该删除这个省略号，并用适当的名称完成输入字段。

![第一个数据库创建已被授权](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_04_02.jpg)

**排序**选择现在可以保持不变。通过这个对话框，我们可以为这个数据库选择一个默认的字符集和排序规则。这个设置可以稍后更改（参考第九章了解更多信息）。

我们假设我们有权创建一个名为**marc_book**的数据库。我们在输入字段中输入**marc_book**并点击**创建**。一旦数据库创建完成，我们将看到以下屏幕：

![第一个数据库创建已被授权](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_04_03.jpg)

请注意以下内容：

+   主面板的标题已经更改，以反映我们现在位于这个数据库中

+   显示有关创建的确认消息

+   导航面板已更新；我们看到**marc_book**

+   默认情况下，phpMyAdmin 向服务器发送的用于创建数据库的 SQL 查询以彩色显示

### 注意

phpMyAdmin 显示它生成的查询，因为`$cfg['ShowSQL']`设置为`TRUE`。查看生成的查询可以是学习 SQL 的好方法。

由于生成的查询可能很大并且占用屏幕空间很多，`$cfg['MaxCharactersInDisplayedSQL']`充当一个限制。其默认值为`1000`应该是在查看查询时看到太少或太多查询之间的一个良好平衡，特别是在进行大量导入时。

检查 phpMyAdmin 的反馈以确定我们通过界面进行的操作的有效性是很重要的。这样，我们可以检测到错误，比如名称中的拼写错误，或者在错误的数据库中创建表。phpMyAdmin 从 MySQL 服务器检索错误消息并在界面上显示它们。

# 创建我们的第一个表

现在我们有了一个新的数据库，是时候在其中创建一个表了。我们将创建的示例表名为**book**。

## 选择列

在创建表之前，我们应该计划我们想要存储的信息。这通常是在数据库设计期间完成的。在我们的情况下，简单的分析导致我们想要保留以下与书籍相关的数据：

+   国际标准图书编号（ISBN）

+   标题

+   页数

+   作者识别

现在，对于我们的**book**表来说，拥有完整的列列表并不重要。我们将通过原型设计结构，然后稍后进行修改。在本章结束时，我们将添加第二个表`author`，其中包含有关每个作者的信息。

## 创建表

我们已经选择了我们的表名，并且知道了列的数量。我们在“创建表”对话框中输入这些信息，然后点击“Go”开始创建表。此时，列的数量是否完全知道并不重要，因为后续的面板将允许我们在创建表时添加列。

![创建表](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_04_04.jpg)

然后我们看到一个指定列信息的面板。因为我们要求四列，所以我们得到了四个输入行。每一行都指的是一个特定列的信息。下面的屏幕截图代表了这个面板的左侧：

![创建表](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_04_05.jpg)

接下来的内容代表右侧：

![创建表](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_04_06.jpg)

MySQL 文档解释了表和列名的有效字符（如果我们搜索“合法名称”）。这可能会根据 MySQL 版本而有所不同。通常，文件名中允许的任何字符（除了点和斜杠）在表名中都是可以接受的，名称的长度不能超过 64 个字符。列名也存在 64 个字符的限制，但我们可以使用任何字符。

我们在“列”列下输入我们的列名。每个列都有一个类型，最常用的类型位于下拉列表的开头。

当列的内容是字母数字时，**VARCHAR**（可变字符）类型被广泛使用，因为内容只会占用所需的空间。这种类型需要一个最大长度，我们需要指定。如果忘记这样做，当我们保存时会有一个小弹出消息提醒我们。对于页面计数和作者识别，我们选择了**INT**类型（整数），如下面的屏幕截图所示：

![创建表](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_04_07.jpg)

列还有其他属性，但在这个例子中我们将它们留空。您可能会注意到屏幕底部的“添加 1 列”对话框。我们可以使用它通过输入适当的值并点击“Go”来向这个创建表面板添加一些列。输入行的数量会根据新的列数而改变，但已经输入的关于前四列的信息不变。在保存页面之前，让我们定义一些键。

## 选择键

表通常应该有一个主键（具有唯一内容的列，代表每一行）。拥有主键对于行标识、更好的性能和可能的跨表关系是推荐的。在这里一个很好的值是 ISBN；因此，在**索引**对话框中，我们选择**PRIMARY**作为**isbn**列的索引类型。索引类型的其他可能性包括**INDEX, UNIQUE**和**FULLTEXT**（在第五章中有更多关于此的内容）。

### 注意

**索引管理**（也称为键管理）可以在初始表创建时进行，也可以在`Table`视图的**结构**页面中进行。

为了提高我们将通过**author_id**进行的查询的速度，我们应该在该列上添加一个索引。我们屏幕右侧现在的样子如下截图所示：

![选择键](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_04_08.jpg)

此时，我们可以从相应的下拉菜单中选择不同的**存储引擎**。但是，目前我们将接受默认的存储引擎。

现在，我们点击**保存**来创建表。如果一切顺利，下一个屏幕将确认表已创建；我们现在位于当前数据库的**结构**页面。

![选择键](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_04_09.jpg)

在**book**表的各种链接中，有些是不活跃的，因为如果其中没有行，则浏览或搜索表是没有意义的。

# 手动插入数据

既然我们有了一张表，让我们手动在其中插入一些数据。在这样做之前，这本书中有一些有用的关于数据操作的参考资料：

+   第五章介绍了如何更改数据和结构，包括如何使用**Function**选择器

+   第七章解释了如何从现有文件导入数据

+   第九章解释了如何从其他表复制数据

+   第十章介绍了关系系统（在我们的情况下，我们将要链接到`author`表）

现在，点击**插入**链接，这将带我们进入数据输入（或编辑）面板。该屏幕有空间可以输入两行信息，也就是说，在我们的示例中有两本书。这是因为`$cfg['InsertRows']`的默认值是`2`。在屏幕的下部，如果默认的行数不适合我们的需求，可以使用对话框**继续插入 2 行**。默认情况下，**忽略**复选框被选中，这意味着第二组输入字段将被忽略。一旦我们在该组的一个字段中输入一些信息并退出该字段，如果浏览器中启用了 JavaScript，则**忽略**框将自动取消选中。

我们可以为两本书输入以下示例信息：

+   ISBN：1-234567-89-0，标题：一百年的电影（第 1 卷），600 页，作者 ID：1

+   ISBN：1-234567-22-0，标题：未来的纪念品，200 页，作者 ID：2

**值**列的宽度遵循字符列的最大长度。在这个例子中，我们将较低的下拉选择器保持为**插入为新行**的默认值。然后，我们点击**Go**来插入数据。在每组代表一行的列后面都有一个**Go**按钮，屏幕的下部也有一个。所有这些都有相同的效果，即保存输入的数据，但为了方便起见提供了这些按钮。

![手动插入数据](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_04_10.jpg)

如果我们的意图是在这两本书之后输入更多书的数据，我们将在点击**Go**之前从第二个下拉菜单中选择**插入另一行**。然后这将插入我们提供的数据并重新加载屏幕以插入更多数据。

## CHAR 和 VARCHAR 的数据输入面板调整

默认情况下，phpMyAdmin 为`CHAR`和`VARCHAR`列类型显示单行输入字段。通过将`$cfg['CharEditing']`设置为`'input'`来控制。有时，我们可能希望在字段内插入换行符（新行）。这可以通过将`$cfg['CharEditing']`设置为`'textarea'`来实现。这是一个全局设置，将适用于此副本的所有用户的所有表的所有列。在此模式下，可以通过*Enter*键手动插入换行符，或者通过从屏幕上的其他源复制和粘贴文本行来完成。应用此设置将生成不同的**插入**屏幕，如下所示：

![CHAR 和 VARCHAR 的数据输入面板调整](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_04_11.jpg)

使用此输入模式，每个列的最大长度在视觉上不再适用。它将在插入时由 MySQL 强制执行。

# 浏览模式

有许多种方式可以进入这种模式。实际上，每次显示查询结果时都会使用这种模式。我们可以通过在导航面板上点击表名，或者在特定表的`表`视图中点击**浏览**来进入这种模式。

![浏览模式](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_04_12.jpg)

## SQL 查询链接

在**浏览**结果中，显示的第一部分是查询本身，以及一些链接。显示的链接可能会根据我们的操作和一些配置参数而有所不同。

![SQL 查询链接](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_04_13.jpg)

以下几点描述了每个链接的功能：

+   **分析**复选框在本章的*分析查询*部分中有详细介绍。

+   **内联**链接允许将查询放入文本区域，而无需重新加载页面；然后可以编辑查询并执行新的查询。

+   如果将`$cfg['SQLQuery']['Edit']`设置为`TRUE`，则会显示**编辑**链接。其目的是打开**查询窗口**，以便编辑此查询（有关详细信息，请参阅第十一章）。

+   如果将`$cfg['SQLQuery']['Explain']`设置为`TRUE`，则会显示**解释 SQL**。我们将在第五章中看到此链接可以用于什么。 

+   可以点击**创建 PHP 代码**链接，将查询重新格式化为 PHP 脚本中预期的语法。然后可以直接复制并粘贴到我们正在工作的 PHP 脚本中需要查询的地方。请注意，点击后，此链接会更改为**无 PHP 代码**（如下截图所示），这将恢复正常的查询显示。如果将`$cfg['SQLQuery']['ShowAsPHP']`设置为`TRUE`，则此链接可用。

![SQL 查询链接](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_04_14.jpg)

+   **刷新**用于再次执行相同的查询。结果可能会发生变化，因为 MySQL 服务器是多用户服务器，其他用户或进程可能正在修改相同的表。如果将`$cfg['SQLQuery']['Refresh']`设置为`TRUE`，则会显示此链接。

## 导航栏

导航栏显示在结果的顶部和底部。根据**重复标题后**字段中输入的值，列标题可以在结果中的某些间隔中重复显示。

![导航栏](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_04_15.jpg)

该栏使我们能够从一页导航到另一页，显示任意数量的行，从结果的某一点开始。通过点击**浏览**进入浏览模式，生成结果的基础查询包括整个表。但是，情况并非总是如此。

我们目前正在使用包含少量行的表。对于更大的表，我们可能会看到更完整的导航按钮集。为了模拟这种情况，让我们使用**显示**对话框将默认行数从**30**更改为**1**；然后点击**显示**。我们可以看到导航栏会自适应，如下截图所示：

![导航栏](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_04_16.jpg)

这一次，有标有**<<, <, >**和**>>**的按钮，用于方便地访问结果的第一页、上一页、下一页和最后一页。这些按钮仅在必要时显示；例如，如果我们已经在第一页上，则不会显示**第一页**按钮。这些符号以这种方式显示，因为`$cfg['NavigationBarIconic']`的默认设置为`TRUE`。在这里的`FALSE`会产生诸如**下一页**和**结束**的按钮，而`'both'`的值会显示**> 下一页**和**>> 结束**。

### 注意

请注意，`$cfg['NavigationBarIconic']`指令仅控制这些导航按钮的行为；其他按钮和链接（如**编辑**）由其他配置指令控制。

还有一个**页码**下拉菜单，可以直接转到靠近当前页的页面之一。由于可能有数百或数千页，因此该菜单保持较小，并包含常请求的页面：当前页面前后的几页，开头和结尾的几页，以及基于计算间隔的页面编号示例。

按设计，phpMyAdmin 始终尝试提供快速结果，实现此结果的一种方法是在`SELECT`中添加`LIMIT`子句。如果原始查询中已经有`LIMIT`子句，phpMyAdmin 将予以尊重。默认限制是 30 行，设置在`$cfg['MaxRows']`中。如果服务器上有许多用户，限制返回的行数有助于将服务器负载保持在最低水平。

导航栏上还有一个按钮，但必须通过将`$cfg['ShowAll']`设置为`TRUE`来激活。用户很容易会经常使用这个按钮。因此，在 phpMyAdmin 的多用户安装中，建议将按钮保持为其默认值禁用（FALSE）。启用时，导航栏将增加一个**显示全部**按钮。单击此按钮将检索当前结果集的所有行，这可能会达到 PHP 的执行时间限制或服务器的内存限制；当要求显示数千行时，大多数浏览器也会崩溃。可以安全显示的确切行数无法预测，因为它取决于列中实际存在的数据以及浏览器的功能。

### 注意

如果在**显示 __ 行**对话框中输入一个大数字，将会获得相同的结果（并且可能会面临相同的问题）。

## 查询结果操作

一个名为**查询结果操作**的部分位于结果下方。它包含打印结果的链接（带有或不带有`FULL TEXT`列），导出这些结果的链接（参考第六章中的*导出部分查询结果*部分），或者从此查询创建一个视图的链接（关于这一点在第十七章中有更多信息）。

### 显示数据为图表

另一个可用的操作是**显示图表**。为了练习这个，我们将使用一个选择只有两列的不同查询。为此，我们可以使用查询旁边显示的**内联**链接，并将查询更改为：

```sql
SELECT page_count, author_id from book

```

单击**Go**会生成一个只有这两列的结果集；接下来我们点击**显示图表**，会生成以下面板：

![显示数据为图表](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_04_17.jpg)

更多详细信息请参阅[`wiki.phpmyadmin.net/pma/Charts`](http://wiki.phpmyadmin.net/pma/Charts)。

## 排序结果

在 SQL 中，除非我们明确地对数据进行排序，否则我们无法确定数据检索的顺序。检索引擎的一些实现可能以与输入数据顺序相同的顺序显示结果，或者根据主键的顺序显示结果。然而，以明确排序的方式获取我们想要的结果是一种确定的方法。

当浏览结果显示时，可以单击任何列标题以对该列进行排序，即使它不是索引的一部分。让我们点击**author_id**列标题。

![排序结果](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_04_18.jpg)

我们可以确认排序已经发生，通过观察屏幕顶部的 SQL 查询；它包含一个**ORDER BY**子句。

现在我们在**author_id**标题旁边看到一个小三角形指向上方。这意味着当前的排序顺序是“升序”。将鼠标悬停在**author_id**标题上会使三角形改变方向，以指示如果再次点击标题会发生什么——按**author_id**值降序排序。

另一种排序的方法是按键排序。**排序**对话框显示了已经定义的所有键。在这里，我们看到一个名为**PRIMARY**的键——这是我们在创建时为**isbn**列检查**Primary**时给出的主键的名称：

![排序结果](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_04_19.jpg)

这可能是一次对多列进行排序的唯一方法（用于多列索引）。

初始排序顺序在`$cfg['Order']`中定义，使用`ASC`表示升序，`DESC`表示降序，或者`SMART`；后者是默认排序顺序，这意味着`DATE, TIME, DATETIME`和`TIMESTAMP`类型的列将按降序排序，而其他列类型将按升序排序。

### 头词

因为我们可以更改页面上显示的行数，很可能我们看不到所有数据。在这种情况下，看到**头词**会有所帮助——关于显示数据的第一行和最后一行的指示。这样，您可以点击**下一个**或**上一个**，而不必滚动到窗口底部。

然而，phpMyAdmin 应该基于哪一列生成头词？一个简单的假设已经被提出：如果您点击列标题表示您打算对该列进行排序，phpMyAdmin 将使用该列的数据作为头词。对于我们当前的**book**表，我们没有足够的数据来清楚地注意到这种技术的好处。然而，我们仍然可以看到排序后，屏幕顶部现在包含这条消息：

**显示行 0 - 1（共 2 行，查询耗时 0.0006 秒）[author_id: 1 - 2]**

在这里，方括号中的消息表示**author_id**编号**1**在第一行显示，编号**2**在最后一行显示。

## 颜色标记行或列

当鼠标在行之间移动（或在列标题之间移动）时，行（或列）的背景颜色可能会改变为`$cfg['BrowsePointerColor']`中定义的颜色。此参数可以在`themes/<themename>/layout.inc.php`中找到。要启用此功能，所有主题的浏览指针`$cfg['BrowsePointerEnable']`必须在`config.inc.php`中设置为`TRUE`（默认值）。

当我们在表中有许多列并且必须不断向左和向右滚动以读取数据时，可以有趣地标记一些行。另一个用途是突出一些行的重要性，以进行个人数据比较，或者向他人展示数据时。通过点击行来进行突出显示。再次点击会取消对行的标记。所选颜色由`$cfg['BrowseMarkerColor']`（参见`themes/<themename>/layout.inc.php`）定义。此功能必须通过在`config.inc.php`中将`$cfg['BrowseMarkerEnable']`设置为`TRUE`来启用。这将为所有主题设置该功能。我们可以标记多行。标记行还会激活该行的复选框。

![颜色标记行或列](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_04_20.jpg)

通过点击列标题（而不是列名本身）来标记列。

## 限制每列的长度

在前面的例子中，我们总是看到每列的完整内容，因为每列的字符数都在`$cfg['LimitChars']`定义的限制内。这是对所有非数字列强制执行的限制。如果这个限制很低（比如`10`），显示将如下所示：

![限制每列的长度](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_04_21.jpg)

这将帮助我们同时看到更多列（以减少每列的显示量）。

### 显示选项

为了看到完整的文本，我们现在将使用**选项**滑块，它会显示一些显示选项。所有这些选项将在涵盖相应概念的章节中进行解释。目前关注我们的选项是**部分文本/完整文本**对；我们可以选择**完整文本**来查看所有被截断的文本。即使我们选择不改变`$cfg['LimitChars']`参数，也会有一个时候要求完整文本会很有用（当我们使用`TEXT`列类型时——更多内容请参阅第五章）。

查看完整文本的更快方法是点击位于**编辑**和**删除**图标正上方的大**T**。再次点击此**T**会将显示从完整切换到部分。

## 浏览不同的值

有一种快速的方法可以显示所有不同的值以及每个列值的出现次数。这个功能在表的**结构**页面上可用。例如，我们想知道我们的书表中有多少不同的作者，以及每个作者写了多少本书。在描述我们想要浏览的列（这里是**author_id**）的行上，我们打开**更多**菜单，然后点击**浏览不同的值**链接。

![浏览不同的值](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_04_22.jpg)

我们有一个有限的测试集，但仍然可以看到结果。

![浏览不同的值](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_04_23.jpg)

# 性能分析查询

在 MySQL 版本 5.0.37 和 5.1.28 中添加了性能支持。我们之前已经看到**性能分析**复选框出现在查询结果中。

当选中此框时，phpMyAdmin 将分析每个查询（包括当前查询），并显示有关每个 MySQL 内部操作的执行时间的报告，如下面的屏幕截图所示：

![性能分析查询](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_04_24.jpg)

尽管性能分析系统可以报告有关操作的其他信息（如 CPU 时间，甚至是内部服务器的函数名称），但 phpMyAdmin 目前只显示操作的名称和持续时间。

# 创建一个额外的表

在我们（简单）的设计中，我们知道我们需要另一个表——**author**表。**author**表将包含：

+   作者识别

+   全名

+   电话号码

要创建此表，我们返回到**marc_book**的`数据库`视图，并请求创建另一个具有如下屏幕截图所示的三列的表：

![创建一个额外的表](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_04_25.jpg)

使用创建第一个表时使用的相同技术，我们输入以下内容：

![创建一个额外的表](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_04_26.jpg)

由于我们只有三列或更少，显示现在处于垂直模式（有关更多详细信息，请参阅第五章中的*垂直模式*部分）。

列名**id**，它是我们新表中的主键，与`book`表中的`author_id`列相关联。保存表结构后，我们为作者 1 和 2 输入一些数据。为此，请发挥您的想象！

# 总结

本章解释了如何创建数据库和表，以及如何在表中手动输入数据。它还涵盖了如何通过使用浏览模式来确认数据的存在，其中包括 SQL 查询链接、导航栏、排序选项和行标记。

下一章将解释如何编辑数据行，并涵盖删除行、表和数据库的各个方面。
