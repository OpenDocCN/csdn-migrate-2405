# FuelPHP 高效开发学习手册（一）

> 原文：[`zh.annas-archive.org/md5/8172c4d143a13bc077eabf0b73cc7f19`](https://zh.annas-archive.org/md5/8172c4d143a13bc077eabf0b73cc7f19)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

FuelPHP 是一个很棒的工具，专注于以简单快速的方式编写 Web 应用程序，需要更少的 PHP 代码。它允许您使用脚手架和命令行工具快速构建原型，从而让您专注于试验想法和概念的有趣部分。

《学习 FuelPHP 进行有效的 PHP 开发》包含了几个教程，将帮助您构建一个强大而引人入胜的应用程序，并在此过程中学习更多关于 FuelPHP 的知识。本书以逐步方式介绍了安装和构建 FuelPHP 项目的经验。

本书首先详细介绍了 FuelPHP 的特性，然后深入介绍了一个简单应用的创建。然后我们使用强大的 FuelPHP Oil 命令行工具来搭建我们的应用程序。最后，我们介绍了社区。

# 本书涵盖了什么

第一章，“什么是 FuelPHP?”，给出了对 FuelPHP 的快速介绍，以及 Fuel PHP 2.0 版本中预期的一些变化。

第二章，“安装”，涵盖了安装 FuelPHP 和设置开发环境。

第三章，“架构”，给出了 FuelPHP 架构的基本概述，并将介绍在哪里存储项目代码，然后总结本章内容。

第四章，“演示应用程序”，将介绍如何使用示例代码和逐步指南创建项目。还将涵盖创建管理系统、轻松创建表单以及使用 HTML5 Boilerplate 和模板。

第五章，“包”，将介绍包并突出显示在项目中重要的包。

第六章，“高级主题”，将介绍更高级的主题，包括模块、路由和单元测试。

第七章，“欢迎来到社区”，涵盖了如何从社区获得帮助。

# 您需要为本书做好准备

本书假定您已经安装了带有 Apache 和 PHP 的计算机。

# 这本书是为谁写的

这本书是为期待了解如何使用 FuelPHP 框架进行有效 PHP 开发的 PHP 开发人员而写的。假定读者对一般 PHP 开发有基本的了解。

# 约定

在本书中，您会发现一些文本样式，用于区分不同类型的信息。以下是一些样式的示例，以及它们的含义解释。

文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 用户名显示如下：“无需详细说明`id`、`created_at`或`updated_at`字段，因为这些将自动生成。”

代码块设置如下：

```php
<?php
return array(
    'default' => array(
        'connection' => array(
            'dsn' => 'mysql:host=localhost;dbname=journal_dev',
            'username' => 'journal_dev',
            'password' => 'journal_dev',
```

当我们希望引起您对代码块的特定部分的注意时，相关的行或项目会以粗体显示：

```php
[default]
exten => s,1,Dial(Zap/1|30)
exten => s,2,Voicemail(u100)
**exten => s,102,Voicemail(b100)**
exten => i,1,Voicemail(s0)
```

任何命令行输入或输出都以以下方式编写：

```php
**$ git checkout -b develop**
**$ git push origin develop**

```

**新术语**和**重要单词**以粗体显示。您在屏幕上看到的单词，例如菜单或对话框中的单词，会以这样的方式出现在文本中：“在 Initializr 网站上，选择**Classic H5BP**选项，然后选择**Responsive Bootstrap** 2.3.2 模板选项。最后，点击**Download it!**”。

### 注意

警告或重要说明会出现在这样的框中。

### 提示

提示和技巧会以这种方式出现。


# 第一章：什么是 FuelPHP？

FuelPHP 是一种更加社区驱动的框架的新方法。已经有一百多名开发人员在贡献和扩展源代码。还有更多人在为当前可用框架提供一些最好的文档。

由于它是社区驱动的，每个人都处于发现错误、提供修复或向框架添加新功能的平等地位。这导致了一些功能的创建，比如新的临时**ORM**（**对象关系映射器**），这是任何基于 PHP 的 ORM 的首次。这也意味着每个人都可以帮助构建使开发更容易、更直接、更快速的工具。

该框架轻巧，允许开发人员只加载他们需要的内容。这是一种配置优于约定的方法。它不是强制性的约定，而是作为建议和最佳实践。这使得新开发人员可以更快地加入项目并迅速跟上进度。当我们想要为项目找到额外的团队成员时，这也很有帮助。

本章涵盖的主题有：

+   FuelPHP 的简要历史

+   FuelPHP 的特点

+   在第 2 版中可以期待什么

# FuelPHP 的简要历史

FuelPHP 的目标是采纳其他框架的最佳实践，形成一个彻底现代的起点，充分利用 PHP 版本 5.3 的特性，如命名空间。它几乎没有遗留和兼容性问题，这可能会影响旧框架。

该框架始于 2010 年由*Dan Horrigan*创建。他得到了 Phil Sturgeon、Jelmer Schreuder、Harro Verton 和 Frank de Jonge 的加入。FuelPHP 是对其他框架（如 CodeIgniter）的突破，后者基本上仍然是一个 PHP 4 框架。这一突破允许创建一个更现代的 PHP 5.3 框架，并汇集了其他语言和框架（如 Ruby on Rails 和 Kohana）数十年的经验。经过一段时间的社区开发和测试，FuelPHP 框架的 1.0 版本于 2011 年 7 月发布。这标志着一个可以在生产站点上使用的版本，并标志着社区的增长开始。

社区定期发布版本（在撰写本文时，已经到了 1.7 版），并有一个清晰的路线图（[`fuelphp.com/roadmap`](http://fuelphp.com/roadmap)）来添加功能。这也包括迄今为止取得的进展的良好指南。

FuelPHP 的开发是一个开放的过程，所有的代码都托管在 GitHub 上，主要核心包可以在 Fuel GitHub 账户的其他存储库中找到——这些完整的列表可以在[`github.com/fuel/`](https://github.com/fuel/)找到。

# FuelPHP 的特点

使用定制的 PHP 或自定义开发的框架可以提供更好的性能。FuelPHP 提供了许多功能、文档和一个伟大的社区。以下部分描述了一些最有用的功能。

## (H)MVC

尽管 FuelPHP 是一个**Model-View-Controller**（**MVC**）框架，但它是建立在支持 HMVC 变体的 MVC 上的。第三章 *架构*详细介绍了 MVC 设计模式。**Hierarchical Model-View-Controller**（**HMVC**）是一种将逻辑分离然后在多个地方重用控制器逻辑的方法。这意味着当使用主题或模板部分生成网页时，它可以被分割成多个部分或小部件。使用这种方法，可以在项目中或多个项目中重用组件或功能。

除了通常的 MVC 结构外，FuelPHP 还允许使用表示模块（ViewModels）。这是一个强大的层，位于控制器和视图之间，允许更小的控制器，同时仍然将视图逻辑与控制器和视图分离。如果这还不够，FuelPHP 还支持基于路由器的方法，可以直接路由到闭包。然后处理输入 URI 的执行。

## 模块化和可扩展

FuelPHP 的核心已经设计得可以在不需要更改核心代码的情况下进行扩展。它引入了包的概念，这些包是自包含的功能，可以在项目和人员之间共享。与核心一样，在 FuelPHP 的新版本中，这些可以通过**Composer**工具安装。就像包一样，功能也可以分成模块。例如，可以创建一个完整的用户认证模块来处理用户操作，如注册。模块可以包括逻辑和视图，并且可以在项目之间共享。包和模块的主要区别在于，包可以是核心功能的扩展，它们不可路由，而模块是可路由的。包和模块都在第五章、*包*和第六章、*高级主题*中进行了介绍。

## 安全

每个人都希望他们的应用尽可能安全；为此，FuelPHP 为您处理了一些基本问题。FuelPHP 中的视图将对所有输出进行编码，以确保其安全，并且能够避免**跨站脚本**（**XSS**）攻击。这种行为可以被覆盖，也可以通过包含的 htmLawed 库进行清理。

该框架还支持使用令牌进行**跨站请求伪造**（**CSRF**）预防、输入过滤和查询构建器，试图帮助防止 SQL 注入攻击。**PHPSecLib**用于提供框架中的一些安全功能。

## 油-命令行的力量

如果您熟悉 CakePHP、Zend 框架或 Ruby on Rails，那么您将对 FuelPHP Oil 感到满意。它是 FuelPHP 核心的命令行实用程序，旨在加快开发和效率。它还有助于测试和调试。虽然不是必需的，但在开发过程中它被证明是不可或缺的。

Oil 提供了一种快速的方式来进行代码生成、脚手架、运行数据库迁移、调试和类似于 cron 的后台操作任务。它也可以用于自定义任务和后台进程。

Oil 是一个包，可以在[`github.com/fuel/oil`](https://github.com/fuel/oil)找到。

## ORM

FuelPHP 还配备了一个**对象关系映射器**（**ORM**）包，可以通过面向对象的方式与各种数据库进行交互。它相对轻量级，不打算取代像 Doctrine 或 Propel 这样更复杂的 ORM。

ORM 还支持数据关系，如：

+   属于

+   有一个

+   有许多

+   多对多关系

另一个不错的功能是级联删除；在这种情况下，ORM 将删除与单个条目关联的所有数据。

ORM 包可以单独从 FuelPHP 中获取，并托管在 GitHub 上，网址为[`github.com/fuel/orm`](https://github.com/fuel/orm)。

## 基控制器类和模型类

FuelPHP 包括几个类，可以为项目提供一个良好的开端。其中包括帮助模板的控制器，用于构建 RESTful API 的控制器，以及结合了模板和 RESTful API 的控制器。

在模型方面，基类包括**CRUD**（**创建**、**读取**、**更新**和**删除**）操作。有一个用于软删除记录的模型，一个用于嵌套集，最后是一个时间模型。这是一个保留数据修订的简单方法。

## 认证包

身份验证框架为用户身份验证和登录功能提供了良好的基础。可以使用驱动程序来扩展新的身份验证方法。一些基本功能，如组、基本的 ACL 功能和密码哈希，可以直接在身份验证框架中处理。

虽然在安装 FuelPHP 时包含了身份验证包，但它可以单独升级到应用程序的其余部分。代码可以从[`github.com/fuel/auth`](https://github.com/fuel/auth)获取。

## 模板解析器

解析器包使将逻辑与视图分离变得更加容易，而不是将基本的 PHP 嵌入视图中。FuelPHP 支持许多模板语言，如 Twig、Markdown、Smarty 和 HTML 抽象标记语言（Haml）。

## 文档

尽管这不是实际框架的特性，但 FuelPHP 的文档是最好的之一。它会随着每个版本的发布而保持最新，并且可以在[`fuelphp.com/docs/`](http://fuelphp.com/docs/)找到。

# 期待 2.0 版本的内容

尽管本书侧重于 FuelPHP 1.6 及更新版本，但值得期待框架的下一个重大版本。它带来了重大改进，但也对框架的功能方式进行了一些改变。

## 全局范围和转向依赖注入

FuelPHP 的一个很好的特性是全局范围，可以在需要时轻松使用静态语法和实例。版本 2 中最大的变化之一是摆脱静态语法和实例。该框架使用多例设计模式，而不是单例设计模式。现在，大多数多例将被依赖注入容器（DiC）设计模式取代，但这取决于所讨论的类。

更改的原因是允许对核心文件进行单元测试，并根据应用程序的需求动态交换和/或扩展其他类。转向依赖注入将允许对所有核心功能进行隔离测试。

在详细介绍下一个功能之前，让我们更详细地了解设计模式。

## 单例

确保一个类只有一个实例，并为其提供全局访问点。这种思路是一个类或对象的单一实例可能更有效，但它可能会给可能更适合使用不同设计模式的类增加不必要的限制。

## 多例模式

这类似于单例模式，但在此基础上扩展，包括一种以键值对形式管理命名实例映射的方法。因此，这种设计模式确保每个键值对都有一个单一的实例，而不是一个类或对象的单一实例。多例通常被称为单例的注册表。

## 依赖注入容器

这种设计模式旨在消除硬编码的依赖关系，并使其可以在运行时或编译时进行更改。

一个例子是确保变量具有默认值，但也允许它们被覆盖，还允许其他对象传递给类进行操作。

它允许在测试功能时使用模拟对象。

## 编码标准

一个深远的变化将是编码标准的不同。FuelPHP 2.0 现在将符合 PSR-0 和 PSR-1。这允许更标准的自动加载机制和使用 Composer 的能力。虽然 Composer 兼容性是在 1.5 版本中引入的，但这一移动是为了更好的一致性。这意味着方法名称将遵循“驼峰命名法”而不是当前的“蛇形命名法”。虽然这是一个简单的改变，但这可能会对现有项目和 API 产生很大的影响。

随着其他 PHP 框架向更标准化的编码标准迈出类似的步伐，将有更多机会重用其他框架的功能。

## 包管理和模块化

对于其他语言的包管理，比如 Ruby 和 Ruby on Rails，共享代码和功能很容易且很常见。PHP 世界更大，但功能的共享并不那么普遍。**PHP 扩展和应用程序仓库**（**PEAR**）是大多数包管理器的前身。它是一个可重用的 PHP 组件的框架和分发系统。虽然非常有用，但它并没有得到更流行的 PHP 框架的广泛支持。

从 FuelPHP 1.6 开始，一直到 FuelPHP 2.0，依赖管理将通过 Composer（[`getcomposer.org`](http://getcomposer.org)）实现。这不仅涉及单个包，还涉及它们的依赖关系。它允许项目使用每个项目所需的已知版本的库进行一致设置。这不仅有助于开发，还有助于项目的可测试性和可维护性。

它还抗议 API 的更改。FuelPHP 的核心和其他模块将通过 Composer 安装，并且一些 1.0 版本的包将逐渐迁移。

## 向后兼容性

FuelPHP 将发布一个遗留包，为了符合编码标准的变化，它将提供对已更改的函数名称的别名。它还将允许继续使用静态函数调用，同时提供更好的核心功能单元测试能力。

## 速度提升

尽管在最初的 alpha 阶段速度较慢，但 2.0 版本正在变得比 1.0 版本更快。目前（写作时）的 beta 版本比 1.0 版本快 7%，内存占用减少 8%。这听起来可能不多，但如果在多台服务器上运行一个大型网站，这可能会节省大量资源。在 2.0 版本的最终发布后，这些数字可能会更好，因为剩余的优化工作已经完成。

# 总结

我们现在对 FuelPHP 的历史和一些有用的功能有了更多了解，比如 ORM、身份验证、模块、（H）MVC 和 Oil（命令行界面）。

我们还列出了以下有用的链接，包括官方 API 文档（[`fuelphp.com/docs/`](http://fuelphp.com/docs/)）和 FuelPHP 主页（[`fuelphp.com`](http://fuelphp.com)）。

本章还涉及了 FuelPHP 2.0 版本中即将到来的一些新功能和变化。

在下一章中，我们将安装 FuelPHP，并介绍不同的环境和配置。


# 第二章：安装

在本章中，我们将介绍一些安装 FuelPHP 的基础知识。即使作为经验丰富的 PHP 开发人员，一些主题可能是新的。我们将介绍源代码控制的基础知识**Git**，并在后面的章节中介绍使用名为**Capistrano**的 Ruby 工具进行自动部署。不用担心，尽管它是用 Ruby 编写的，但即使您以前没有使用过 Ruby，它也很容易使用。

每个人都有自己设置开发环境的方式—有些人喜欢从源代码编译 Apache，而其他人则喜欢 MAMP 或 WAMP 的简单性。无论您选择的环境是什么，FuelPHP 都很可能相当快速和容易设置。

在本章中，我们将涵盖以下主题：

+   准备开发环境

+   使用 Git 进行源代码控制

+   安装 FuelPHP 并设置您的项目

+   与不同环境一起工作并迁移数据库更改

# 准备开发环境

FuelPHP 应该可以在任何 Web 服务器上运行，并且已经经过 Apache、IIS 和 Nginx 的测试。它还可以在 Windows 和*nix（Unix、Linux 和 Mac）操作系统上运行。

就这份指南而言，示例将基于*nix 和 Mac，但相同的步骤也适用于其他操作系统，如 Windows。

## Apache

还有其他的 Web 服务器可用，但在本书中，我们假设使用 Apache。

为了使用诸如`http://example.com/welcome/hello`这样的清晰 URL，Apache 将需要安装和启用`mod_rewrite`模块。

## PHP

您可能已经安装了 PHP，尤其是对 FuelPHP 感兴趣的人。

FuelPHP 需要 PHP 版本 5.3 或更高。它还使用了几个 PHP 扩展：

+   `fileinfo()`: 此扩展用于上传文件，可能需要在 Windows 上手动安装

+   `mbstring()`: 这在整个框架中都在使用

+   `mcrypt`: 这用于核心加密功能

+   `PHPSecLib`: 如果找不到`mcrypt`，则可以使用此作为替代

有许多设置 PHP 的方法，更多信息可以在`php.net`和[`www.phptherightway.com`](http://www.phptherightway.com)找到。

## 数据库交互

在 FuelPHP 中与数据库的交互由驱动程序处理；因此，它可以支持多种数据库。FuelPHP 默认支持 MySQL（通过 MySQL、MySQLi 驱动程序）、MongoDB、Redis 和任何具有**PHP 数据对象**（**PDO**）驱动程序的数据库。

在 FuelPHP 中编写的应用程序和站点可以在没有关系数据库或无 SQL 数据存储（如 Mongol DB）的情况下完美运行，但在本书中，我们将使用一个来演示 FuelPHP 一些令人惊叹的功能。

MySQL 在大多数平台上都得到很好的支持，并且是最广泛使用的数据库系统之一。您可以访问[`dev.mysql.com/downloads/mysql`](http://dev.mysql.com/downloads/mysql)，那里有很好的指导和安装程序。

## 源代码控制-介绍 Git

尽管并非所有项目都需要使用源代码控制，但回滚到旧版本的代码或与开发团队合作肯定会很方便。

Git 是一个非常强大的工具，相对容易上手。尽管并非所有项目都需要使用 Git 或**Subversion**等源代码控制系统，但它们都会受益于此。一个关键的好处是能够恢复到代码的先前版本，可以将其视为通用的“撤销”功能。这个“撤销”功能不仅适用于单个文档，还适用于整个项目。核心团队在开发和增强 FuelPHP 框架时也使用它们。如果您不熟悉源代码控制，可以手动安装框架，但本书将假定您正在使用 Git 和源代码控制。

如果您想了解更多关于使用 Git 的信息，可以在以下链接找到在线版本的手册：

[`git-scm.com/book/`](http://git-scm.com/book/)

Git 起源于 Linux 世界。因此，从源代码编译是安装它的传统方式，但现在也存在替代方法。Ubuntu 可以使用以下`apt-get`命令安装 Git：

```php
**$ sudo apt-get install git-core**

```

OS X 用户有多种安装 Git 的选项，包括**MacPorts** ([`www.macports.org`](http://www.macports.org)) 和**Homebrew** ([`github.com/mxcl/homebrew`](http://github.com/mxcl/homebrew))：

+   在通过 MacPorts 安装时，我们使用以下命令：

```php
$ sudo port install git-core +svn
```

+   在使用 Homebrew 时，我们使用：

```php
$ brew install git
```

Windows 用户可以在以下链接找到`msysGit`安装程序：

[`msysgit.github.io`](http://msysgit.github.io)

安装 Git 后，建议使用您的用户详细信息配置它，如以下命令所示：

```php
**$ git config --global user.name "Your name"**
**$ git config --global user.email "user@domain.com"**

```

为了使 Git 的输出更加直观，建议在命令行中启用颜色：

```php
**$ git config --global color.ui auto**

```

### 有关 Git 的更多信息

可以在[`git-scm.com`](http://git-scm.com)找到 Git 客户端和可用命令的一个很好的替代方案。GitHub 也有一个设置 Git 的良好指南，可在以下链接找到：

[`help.github.com/articles/set-up-git`](http:// https://help.github.com/articles/set-up-git)

### 提示

**额外阅读材料**

如果您熟悉源代码控制，Git 的核心概念将非常熟悉。可能需要一些时间来习惯语法。以下是一些有关学习更多关于 Git 的有用链接：

+   [`git-scm.com/book/en/`](http://git-scm.com/book/en/)：Git 的在线指南

+   [`git-scm.com`](http://git-scm.com)：一个很好的资源集合

+   [`nvie.com/posts/a-successful-git-branching-model/`](http://nvie.com/posts/a-successful-git-branching-model/)：使用名为**git-flow**的工具来与 Git 一起工作是一个很好的方法，它有助于保持分支结构化和受控

# 使用 curl 和 Oil 获取并安装 FuelPHP

通过使用`curl`（或`wget`）和 FuelPHP 命令行工具 Oil 的精简版本，安装 FuelPHP 的最简单方法。

要安装快速安装程序，可以从 shell 或终端窗口运行以下命令：

```php
**$ curl get.fuelphp.com/oil | sh***

```

这将要求您输入密码，以将新文件安装到`/usr/bin`目录中。

完成后，您只需要使用`oil`而不是`php oil`，但两者都可以用于命令行迭代。

### 注意

如果您之前使用的 FuelPHP 版本旧于 1.6，您需要重新安装 FuelPHP 以允许其使用**Composer**工具。

要创建一个新项目，只需运行以下命令：

```php
**$ oil create <project>**

```

在这里，`<project>`是您的项目名称。这将在当前目录中创建一个名为项目名称的文件夹。您的所有应用程序代码和软件包都将在项目文件夹中创建。

## 从 GitHub 克隆

如果您不想使用 curl，或者只想在命令行中克隆 FuelPHP 存储库，可以导航到您希望文件放置的文件夹。例如：

```php
**$ cd /Users/ross/Sites**
**$ git clone --recursive git://github.com/fuel/fuel.git <project name>**

```

这将在您的 Web 服务器根目录中创建一个名为`<project name>`的文件夹。它将包含所有必要的 FuelPHP 文件，包括所有核心软件包。

### 继续安装

除了单个命令或从 GitHub 克隆之外，还可以手动下载文件并以这种方式安装。有关此方法的更多信息，请访问[`fuelphp.com/docs/installation/instructions.html`](http://fuelphp.com/docs/installation/instructions.html)。

### 注意

如果您手动安装文件，出于安全原因，建议将 fuel 文件夹移出公共可访问的 Web 文件夹目录。FuelPHP 默认的`.htaccess`文件也阻止核心文件被 Web 访问。

在项目上工作时，某些应用程序文件夹的写入权限可能会发生更改。这些文件夹可能包括日志和缓存，导致应用程序停止运行。如果发生这种情况，可以使用 Oil 来进行更正。它还可以用于使它们可被 Web 服务器写入：

```php
**$ php oil refine install**
 **Made writable: APPPATH/cache**
 **Made writable: APPPATH/logs**
 **Made writable: APPPATH/tmp**
 **Made writable: APPPATH/config**

```

## 设置您的项目

现在您已经安装了 FuelPHP，设置新项目非常容易。首先，您需要导航到您想要从中工作的文件夹，例如 Mac OS X 上的`Sites`文件夹。之后，运行以下命令：

```php
**php oil create <project name>**

```

然后再次运行：

```php
**$ cd ~/Sites/**
**$ php oil create book**

```

这将安装运行 FuelPHP 所需的核心文件和软件包。它还将在项目中设置 Git 子模块。这有时可能会很棘手，但 FuelPHP 以非常灵活和强大的方式使用它们。使用子模块，您可以对项目中使用的软件包的版本进行精细控制。它还使升级或安装安全更新变得非常容易。

FuelPHP 创建的结构相当简单：

```php
**/**
 **fuel/**
 **app/**
 **core/**
 **packages/**
 **public/**
 **.htaccess**
 **assets/**
 **index.php**
 **oil**

```

像 CSS 和 JavaScript 这样的文件放在公共目录中的`assets`文件夹中。一旦安装了一些软件包，您对项目所做的大部分更改将发生在`fuel/app`文件夹中。我们将在接下来的几章中通过示例来介绍这些更改。

## 使用子模块轻松更新 FuelPHP 核心和软件包

子模块是以受控方式处理项目中的多个存储库的绝佳方式。例如，可以升级核心 FuelPHP 框架的版本，同时保留其他第三方软件包的旧版本。这使得更容易测试新功能，以确保它不会影响您的项目，或者突出显示您可能需要进行的更改。在本节中，我们将介绍使用子模块的一些基础知识，但如果您想要更多信息，我建议查看[`git-scm.com/book/en/Git-Tools-Submodules`](http://git-scm.com/book/en/Git-Tools-Submodules)中提供的 Git 手册的*子模块*部分。

如果您想查看当前为您的项目设置了哪些子模块，请导航到项目的根目录，然后运行`git submodule`命令，如下所示：

```php
**$ cd ~/Sites/book**
**$ git submodule**

```

![使用子模块轻松更新 FuelPHP 核心和软件包](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-fuelphp-eff-php-dev/img/0366OS_02_02.jpg)

如您所见，为每个 FuelPHP 项目设置了六个子模块并使用了它们。

如果您想要检查可用的其他子模块版本，请导航到子模块的文件夹，然后运行`git branch -r`命令，如下所示：

```php
**$ cd fuel/core**
**$ git branch -r**

```

![使用子模块轻松更新 FuelPHP 核心和软件包](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-fuelphp-eff-php-dev/img/0366OS_02_03.jpg)

然后，我们可以从其他分支中复制代码来测试新功能，或者回滚到以前的代码版本。例如，让我们看看当我们使用 FuelPHP 的开发版本时会发生什么：

```php
**$ git checkout origin/1.7/develop**

```

![使用子模块轻松更新 FuelPHP 核心和软件包](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-fuelphp-eff-php-dev/img/0366OS_02_04.jpg)

每个子模块都像自己的存储库一样，并且不考虑主项目存储库。如果您希望主项目考虑子模块的更改，只需提交所有更改到子模块，然后导航到主项目文件夹并提交项目存储库的更改，如下所示：

```php
**$ cd ~/Sites/book**
**$ git status**
**$ git add fuel/core**
**$ git commit -m 'Upgrading Fuel Core to 1.7/develop'**

```

### 注意

`fuel/core`与`fuel/core/`不同。

![使用子模块轻松更新 FuelPHP 核心和软件包](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-fuelphp-eff-php-dev/img/0366OS_02_05.jpg)

## 提交您的代码

设置项目后，Git 设置将希望将代码发送到 FuelPHP 存储库。因此，首先要做的是更改此设置，以便将其发送到您的项目。我们将使用 GitHub 进行演示，这与 FuelPHP 存储在同一位置。

首先，在 GitHub 上创建一个帐户（[`github.com/new`](https://github.com/new)），然后按照说明创建一个存储库。创建存储库后，复制存储库地址，例如`git@github.com:digitales/Chapter2.git`；您很快就会需要它。

### 注意

[Bitbucket.org](http://Bitbucket.org)是一个类似的服务，除了它将允许您拥有无限的私人存储库。

一旦您创建了存储库并复制了存储库地址，就该回到终端了。在终端中导航到项目目录，然后为存储库添加一个远程，例如：

```php
**$ cd ~/Sites/book**
**$ git remote rm origin** 
**$ git remote add origin git@github.com:digitales/Chapter2.git**
**$ git pull origin**
**$ git push origin master**

```

![提交您的代码](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-fuelphp-eff-php-dev/img/0366OS_02_01.jpg)

现在我们已经更新了 origin，是时候深入了解一下子模块，然后进行配置和一些基本的生产环境配置。

### 提示

**下载示例代码**

您可以从[`www.packtpub.com`](http://www.packtpub.com)的帐户中下载您购买的所有 Packt 图书的示例代码文件。如果您在其他地方购买了这本书，您可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册，以便文件直接通过电子邮件发送给您。

## Composer - 包管理器

在较新版本的 FuelPHP 中，Composer 包管理器用于动态地从**Packagist**、Github 或自定义位置拉取依赖项。它使用`composer.json`文件进行控制，您会在项目的 FuelPHP 安装的根文件夹中找到该文件。

通常，您需要手动安装 Composer，但 FuelPHP 包含了`composer.phar`库，因此您可以直接运行 Composer：

```php
**$ php composer.phar self-update**
**$ php composer.phar update**

```

![Composer - 包管理器](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-fuelphp-eff-php-dev/img/0366OS_02_06.jpg)

### 注意

如果您不执行此步骤，FuelPHP 将无法启动，因为现在正在使用 Composer 加载框架的重要组件。

## 配置

FuelPHP 采用配置优于约定的方法，遵循最佳实践和指南。所有应用程序或项目特定的代码都存储在`app/config`文件夹中，主配置文件包括`config.php`。值得一提的是，您可以选择覆盖哪些配置。任何未指定的键或值将从核心配置中加载。这意味着在升级 FuelPHP 版本时，对默认配置的任何更改都不会丢失。

## 在生产环境中运行

当您安装 FuelPHP 时，默认情况下它会认为自己处于开发环境中，但可以通过设置环境来快速更改。

这可以通过虚拟主机（或类似）为域完成，也可以通过应用程序的公共文件夹中的`.htaccess`文件完成，使用以下代码：

```php
**Set FUEL_ENV production**

```

默认情况下，环境将在应用程序和命令行任务中设置为开发环境。本书的后续章节将介绍在生产环境中运行命令行任务。

## 执行迁移

迁移是确保数据库在不同环境或团队成员之间保持一致的好方法。它提供了一种系统化的方式来更新数据存储结构。手动在数据库上运行 SQL 语句然后想知道是否已更新了正确的数据库结构的日子已经过去了。在开发网站的任何阶段，数据库都可以向前更改或回滚到旧版本的数据库结构。

迁移的示例将在本书的后续部分中成为项目的一部分。

# 总结

在本章中，我们已经设置了开发环境，并介绍了 Git 源代码控制及其一些好处。我们简要地研究了如何将项目调整到不同的环境，并配置源代码控制以考虑不同的分支。我们还安装了 FuelPHP。

在下一章中，我们将在构建演示应用程序之前检查 FuelPHP 架构。


# 第三章：架构

在我们开始使用新安装的 FuelPHP 版本构建任何内容之前，让我们首先看一下架构的一些主要方面。我们还将涵盖一些应该将代码放置在项目中的地方，然后在下一章中提供示例。

在本章中，我们将涵盖以下主题：

+   环境、常量和配置

+   Apache 配置

+   FuelPHP 引导

+   模型、视图和控制器

# 环境、常量和配置

任何开发人员都会告诉您，直接在实时生产环境中编辑文件绝不是一个好主意。为此，FuelPHP 将环境的概念内置到其核心中。环境允许在项目生命周期的每个阶段中进行不同的配置。FuelPHP 支持四种环境设置，如下所示：

+   `\Fuel::DEVELOPMENT`：这是默认的环境设置，也是您将开始的地方

+   `\Fuel::TEST`：这是您可以使用测试数据运行代码的地方

+   `\Fuel::STAGING`：这是您获得客户批准和接受的地方

+   `\Fuel::PRODUCTION`：这是实时环境

如果环境未设置，代码将以开发模式运行。可以通过多种方式设置环境。

## 服务器和 Apache 配置

本节将教您设置环境变量的可能是最简单的方法，但前提是您可以访问项目域的 Apache 配置或虚拟主机文件。在配置或虚拟主机文件中，只需包含以下代码：

```php
SetEnv FUEL_ENV production
```

### 注意

`FUEL_ENV`代码需要大写，因为它是一个 PHP 常量

## 引导 PHP 文件

如果您无法访问服务器配置并希望获得它，另一种方法是在应用程序引导中设置环境。这可以在`fuel/app/`中的`bootstrap.php`文件中使用以下代码完成：

```php
Fuel::$env = ( isset( $_SERVER['FUEL_ENV'] )? $_SERVER['FUEL_ENV'] : Fuel::PRODUCTION ;
```

## 配置

一旦配置了环境，就值得考虑项目的配置。FuelPHP 在自动加载配置时遵循一种层次结构。这对于数据库设置非常方便，这意味着您的生产连接可以更安全地用于生产和分段环境。事实上，团队甚至不需要访问数据库凭据就可以在项目上工作。配置目录结构可以类似于以下代码：

```php
app/
    config/
        db.php
        development/
            db.php
        staging/
            db.php
        test/
            bd.php
        production/
            db.php 
```

环境目录中的设置被视为比较高级目录中的设置更重要，从而实现了细粒度的配置控制和回退。这对于测试和确保每个环境可以以不同的方式配置非常有用，例如第三方 API 连接详细信息。

对于包配置，也遵循相同的层次结构。在这种情况下，应用程序配置文件夹中的包配置比包目录中的配置更重要。这允许在`app/config`文件夹中的配置文件中覆盖包中的默认选项。

## 常量

关于包，其文件夹路径的详细信息采用常量的形式。以下是在引导文件中设置的 PHP 常量：

+   `APPPATH`：应用程序目录的路径，您的应用程序代码和目录位于其中

+   `COREPATH`：FuelPHP 核心文件的路径

+   `DOCROOT`：用于资源和`index.php`文件的公共文件夹

+   `PKGPATH`：包目录路径

+   `VENDORPATH`：composer 根目录的路径

# 模型、视图和控制器

在没有提到**模型-视图-控制器**（**MVC**）设计模式的架构中是不完整的。如果您以前编写过 PHP，或者查看过其他众多框架，您可能已经听说过 MVC 模式。它允许代码的逻辑分离。控制器处理逻辑，而模型确保数据的一致性，并执行与数据存储的交互。视图向用户呈现控制器和模型的结果。到目前为止，一切都很好；为什么要提到 MVC 模式？嗯，FuelPHP 引入了 ViewModel 和一些基本类，为您的项目提供了一个快速入门。

## 视图和 ViewModels

视图存储在`app`文件夹中的`views`文件夹中，例如，`fuel/app/views`。

它们可以被分组放在子文件夹中，并且通常与控制器操作直接相关，例如，`login.php`位于`fuel/app/views/user/`中，将与`user`控制器中的`login`方法相关联。它还将具有`user/login`的类名。

值得注意的是，视图可以使用从控制器或 ViewModel 传递给它的变量。它们还可以使用任何核心 FuelPHP 类和本机 PHP 函数。为了帮助将逻辑与表示分离，建议仅使用基本的`if`语句和循环。

安全性始终很重要，因此传递给视图的所有变量都将使用配置的输出过滤器进行清理-通常是`Security::htmlentities()`。这种行为可以从每个控制器内部更改或禁用，配置文件中运行的默认函数也可以更改。

为了减少 FuelPHP 应用程序的内存占用，视图是“延迟加载”的。这意味着它们只在调用或回显时才会被渲染。

我们之前提到了 ViewModels；这些作为控制器和视图之间的粘合剂。当应用程序开始变得复杂时，很难决定一段代码是否应该放在控制器或视图中。代码可能与应用程序逻辑无关，而与表示逻辑有关。这就是 ViewModels 的用处所在。

ViewModel 在用户输入发生后发挥作用。然后检索视图所需的数据。它们不处理数据，但可以在视图之前与数据存储交互。

## 模型

FuelPHP 核心模型（`Model_Crud`）包括基本的 CRUD（创建、读取、更新和删除）函数，使其快速且易于开始使用数据存储。它只是用于处理表格的快捷方式，不是 ORM 包的一部分。`Model_Crud`和`ORM`包的命名约定相同；这使得更新到 ORM 包以进行更复杂的数据交互变得非常容易。ORM 包包括许多高级功能，从软删除到时间历史记录保留。

使用 ORM 包将需要您定义有关数据的更多详细信息，例如数据库表之间的关系。在下一章构建示例应用程序时，我们将涉及其中一些内容。

## 控制器

控制器是应用程序中更有趣的部分发生的地方。与项目的其他部分一样，代码在以下文件夹结构中具有逻辑位置。控制器放在`fuel/app/classes/controller`文件夹中。

路由器获取 URL，加载所需的控制器，然后将请求传递给控制器内对应的操作或方法。例如，导航到`http://project.dev/home/index` URL 将调用主页控制器中的`index`方法。控制器的结构看起来可能是这样的：

```php
class Controller_Home extends Controller
{
    public function action_index()
    {
        $data['css'] = Asset::css(array('reset.css','site.css'));
        return Response::forge( View::forge('home/index'));
    }
}
```

### 注意

控制器内的操作或方法以 action_ 为前缀，这是为了帮助您使用保留的 PHP 方法名称，例如`list`，并且仍然为控制器方法提供逻辑名称。其他方法可以被创建，但没有`action_`前缀，它们只能直接调用，而不是通过 URL 调用。

如果您正在构建 API 或设置 AJAX 系统，可以将方法分离出来。在下面的示例中，`action_example`将接受 GET 请求，而 POST 请求将转到`post_example`方法，如下所示：

```php
class Controller_Home extends Controller
{
     public action_example(){
       // Add your code here
     }
     public post_example(){
       // Add your code here
     }
}
```

当创建应用程序时，此功能将与基础控制器模板一起发挥作用。`action_`和`post_`方法的分离只适用于混合或 rest 基础控制器。有四个基本模板——base、template、rest 和 hybrid。

### 模板

模板控制器是基础控制器的扩展，之前提到过，它具有内置的模板支持，使用预定义的`before()`和`after()`方法。它可以用来在布局中包装您的视图，并带有页眉和页脚。您的布局模板应存储在`fuel/app/views/template.php`中。

### Rest

与模板控制器类似，rest 控制器是基础控制器的扩展。它不是内置模板支持操作，而是内置 RESTful 支持，使构建 API 更容易。

### 注意

如果在您的 rest 控制器中添加了`before()`或路由器方法，您将需要调用父方法`parent::before()`才能使所有这些方法都起作用。

### 混合

混合控制器将 rest 和模板控制器结合在一起。

# 摘要

在本章中，我们已经了解了 FuelPHP 架构的一些基本部分。我们已经看到 FuelPHP 提供了一个很好的起点，具有可扩展的控制器和模型。这些为大多数项目提供了一个很好的起点，并引入了一些功能，这是任何 PHP 框架的首次；例如，时间 ORM 模型。

在下一章中，我们将开始使用这些知识来创建演示应用程序。


# 第四章：演示应用程序

现在我们已经介绍了 FuelPHP 框架，是时候开始构建一些东西了。我们将通过 Oil 命令行工具迁移，将所有内容整合到示例应用程序中。在本章中，我们将创建一个类似 WordPress 的简单博客应用程序。

用他们自己的话来说，WordPress 正在成为网络的操作系统。根据创始人 Matt Mullenweg 的说法：

> *"WordPress 现在占据了网络的 18.9%，已经有超过 4600 万次下载"*

访问以下链接以获取有关文章的更多信息：

[`thenextweb.com/insider/2013/07/27/wordpress-now-powers-18-9-of-the-web-has-over-46m-downloads-according-to-founder-matt-mullenweg/`](http://thenextweb.com/insider/2013/07/27/wordpress-now-powers-18-9-of-the-web-has-over-46m-downloads-according-to-founder-matt-mullenweg/)

现在，WordPress 的焦点远远超出了博客或简单的期刊。尽管是一个简单的应用程序或网站，创建一个简单的博客将演示 FuelPHP 的许多功能，从数据库迁移、扭转思想和代码到存储期刊条目修订的完整时间模型。

在开始编码之前，让我们先考虑要构建什么，以及最小可行产品是什么。

在本章中，我们将涵盖以下主题：

+   创建和运行数据库迁移

+   使用 Oil 创建模型

+   使用 Oil 创建控制器

+   安装和使用 HTML5 Boilerplate

+   将所有内容整合在一起，创建一个带有脚手架的管理系统

+   使用 Oil 命令行控制台

# 入门

就像 WordPress 一样，我们将从小处开始，演示一些 FuelPHP 工具，这些工具在使用 FuelPHP 开发项目时可以让您的生活更轻松。

在创建项目之前，首先创建一个源代码控制存储库。在这个示例中，我们将使用 GitHub（[`github.com`](https://github.com)），但是其他选择，如**Bitbucket**（[`bitbucket.org`](https://bitbucket.org)）或**beanstalk**（[`beanstalkapp.com`](http://beanstalkapp.com)）可能更适合您。

1.  首先，登录您的帐户，然后创建一个新的项目/存储库。对于这个应用程序，我们可以选择公共选项，因为它在 GitHub 上是免费的。在这个示例中，我们将称我们的项目为`journal`。确保记录页面右侧的存储库 URL，您很快会需要它。

1.  现在，让我们在开发机器上创建项目，但首先您需要使用以下命令行导航到您的`home`文件夹：

```php
$ cd ~/
```

1.  然后，使用以下命令导航到`Sites`文件夹：

```php
$ cd ~/Sites
```

1.  如果您没有`Sites`文件夹，让我们创建一个：

```php
$ mkdir ~/Sites
```

1.  在您的 Sites 文件夹中，运行以下 Oil 命令：

```php
$ php oil create journal
```

### 注

请注意，在这些示例中，$表示终端中新行的开始。运行命令时，您只需要`$`后面的文本，例如`php oil create journal`。

如果您在本地开发机器上使用 Apache，下一步将是为新站点创建虚拟主机（**vhosts**），然后修改 hosts 文件。您需要有一个带有`sites-available`文件夹和`sites-enabled`文件夹的 Apache 配置。然后，来自朋友的一个小脚本将证明是非常宝贵的。可以使用以下命令安装它：

```php
**$ sudo cd /usr/local/bin && sudo git clone git://github.com/maartenJacobs/quickhost.git quickhost files && sudo mv quickhost files/* . && sudo rm -Rf quickhost_files**

```

### 注

这个脚本是一组 PHP 函数，用于在您的计算机上设置 Apache vhosts 和 hosts 文件。所有操作都很简单，但它们可以让您更快地设置它。代码可以在以下链接公开查看：

[`github.com/maartenJacobs/quickhost`](https://github.com/maartenJacobs/quickhost)

或者更多信息可以在[`github.com/digitales/quickhost`](https://github.com/digitales/quickhost)找到。

安装脚本后，我们将能够运行以下一组命令来设置 Apache，以便我们可以使用本地域`http://journal.dev`：

```php
**$ cd ~/Sites/journal/public**
**$ sudo quickhost journal.dev**

```

使用`sudo`的原因是允许 Apache 优雅地重新启动并修改主机文件。这将将域名映射到本地主机 IP 地址（`127.0.0.1`）。在此示例中，我们选择了`.dev`顶级域（TLD）来区分它与生产和暂存环境。我们也可以选择`.local`，但这可能会在某些操作系统上（尤其是在 Mac OS X 上）与 Active Directory（[`en.wikipedia.org/wiki/Active_Directory`](http://en.wikipedia.org/wiki/Active_Directory)）发生冲突。

### 注意

这已在 Mac OS X 上进行了测试，应该可以在*nix 上运行，但在 Windows 环境中可能需要更改脚本才能运行。

我们需要一个数据存储来存储日志条目，所以现在让我们进行配置。加载`fuel/app/config/development/db.php`中找到的`db.php`配置。

如前所述，FuelPHP 具有环境的概念，因此我们可以将开发数据库配置添加到源代码控制中，而不会影响其他环境。因此，您的`db.php`文件应该如下所示：

```php
<?php
return array(
    'default' => array(
        'connection' => array(
            'dsn' => 'mysql:host=localhost;dbname=fue_dev',
            'username' => 'root',
            'password' => 'root',
        ),
        'profiling' => true,
    ),
);
```

### 注意

我倾向于为每个项目设置单独的数据库用户。这确保了没有项目可以触及另一个项目的数据库。在我的 db.php 中，我正在使用 journal_dev 的 dbname、用户名和密码，所以您可以更改您的 db.php 文件版本。

虽然不建议在生产环境中使用，但启用`profiling`可以在开发项目时提供帮助。示例配置已启用它。

我们有代码和存储库，现在让我们将它们链接起来：

```php
**$ cd ~/Sites/journal**
**$ git remote rm origin**
**$ git remote add origin <repository url>**
**$ git pull origin**
**$ git add ./**
**$ git commit -m 'Initial commit'**
**$ git push origin master**

```

用您的存储库 URL 替换上面的`<repository URL>`。现在，也是设置几个不同环境的分支的好时机：`develop`、`staging`和`production`：

```php
**$ git checkout -b develop**
**$ git push origin develop**
**$ git checkout -b staging**
**$ git push origin staging**
**$ git checkout -b production**
**$ git push origin production**
**$ git checkout develop**

```

继续设置主题，让我们设置数据库表。

# 创建数据库表

在数据库中创建表之前，让我们首先详细说明将存储哪些数据以及表中将有哪些初始字段。

对于博客，我们将有博客文章或条目，这些文章将有发布日期。它们将被分类以便对类似主题进行分组。每篇文章将与作者（用户）相关联，并且将具有内容和摘录。我们可以稍后添加自由形式的标记。

## 条目

`Entries`表中存在以下字段：

+   `id`（整数）：这将是主要标识符

+   `name`（varchar）

+   `slug`（varchar）

+   `excerpt`（文本）

+   `content`（文本）

+   `published_at`（整数）

+   `created_at`（时间戳）：这将是记录创建时的时间戳

+   `updated_at`（时间戳）- 这将是记录上次更新的时间戳

## 类别

`Categories`表中存在以下字段：

+   `id`（整数）：这将是主要标识符

+   `name`（varchar）

+   `slug`（varchar）

+   `created_at`（时间戳）：这将是记录创建时的时间戳

+   `updated_at`（时间戳）：这将是记录上次更新的时间戳

## 用户

`Users`表中存在以下字段：

+   `id`（整数）：这将是主要标识符

+   `name`（varchar）

+   `username`（varchar）

+   `password`（varchar）

+   `email`（varchar）

+   `last_login`（时间戳）

+   `login_hash`（文本）

+   `profile_fields`（文本）

+   `created_at`（时间戳）：这将是记录创建时的时间戳

+   `updated_at`（时间戳）：这将是记录上次更新的时间戳

我们还需要一个链接表，以便多个条目可以分类到相同的类别中。

## categories_entries

`categories_entries`表中存在以下字段：

+   `id`（整数）：这将是主要标识符

+   `category_id`（整数）：这将是类别的主要标识符

+   `entry_id`（整数）：这将是条目的主要标识符

+   `created_at`（时间戳）：这将是记录创建时的时间戳

+   `updated_at`（时间戳）：这将是记录上次更新的时间戳

你可能已经注意到每个表都有一个`id`、一个`created_at`表和一个`updated_at`字段。这些都是由 FuelPHP Oil 工具自动添加的，当链接或形成数据对象之间的关系时，它们可能会很有用。它们确实会增加一些额外的开销，但在这个阶段这不应该成为问题，因为额外的存储需求是很小的。

让我们使用 FuelPHP Oil 工具创建一些迁移：

```php
**$ php oil generate migration create_entries name:string slug:string excerpt:text content:text published_at:timestamp**

```

这将创建迁移以组装 posts 数据库表。不需要详细说明`id`、`created_at`或`updated_at`字段，因为这些将自动生成。如果你不需要这些额外的基于时间的字段，你可以在`generate`命令的末尾添加`--no-timestamp`。

### 提示

我们在这里运行迁移示例，并且在本章后面生成模型时将使用正确的 entries 表。

# 迁移和石油

在快速创建项目并组织基本结构时，FuelPHP Oil 工具可以处理一些更加重复的任务，让你可以集中精力处理项目的其他方面。这包括设置数据库表（如之前演示的）以及创建模型和控制器。FuelPHP Oil 工具还可以用来搭建一个管理系统，该系统已经准备好用于管理内容，并带有完整的用户认证系统。它将提供起点；虽然结果不总是美观的，但它是功能性的。

这使你可以快速测试想法并迭代向完美的代码。我们将逐个介绍 Oil 的各个功能，以创建模型、控制器和数据库迁移。这将给我们更多时间来调整和创建一个更加完善的项目/日志。

Oil 最有用的功能之一是迁移数据库结构的能力。这些可以用于确保不同环境之间的一致性。在部署代码时，也可以在数据库上运行迁移。

迁移可以用于重命名表、添加和删除字段甚至表。Oil 有魔术迁移的概念。这些以关键字前缀开始，使得很容易看出它们将要做什么：

```php
$ php oil generate migration create_users name:text
$ php oil generate migration rename_table_users_to_people
$ php oil generate migration add_profile_to_people profile:text
$ php oil generate migration delete_profile_from_people profile:text
$ php oil generate migration drop_people
```

### 提示

在创建迁移时，你需要注意关键字。关键字包括`create_`、`rename_`、`add_`、`delete_`、`rename_`和`drop_`。

迁移存储在`fuel/app/migrations`中，已执行的迁移列表存储在`fuel/app/config/<environment>/migrations.php`中。

此外，迁移的数据库表记录了项目的当前状态。运行迁移就像输入以下命令一样简单：

```php
**$ oil refine migrate**

```

### 提示

你可以简单地输入`r`和`g`来运行 refine 和 generate Oil 操作。

如果你想要迁移上升或下降，请运行以下命令：

```php
**$ oil r migrate:up**
**$ oil r migrate:down**

```

这些命令可以被整合到部署脚本中，这样迁移就可以在将新代码添加到不同环境时自动运行。这对避免在生产环境中出现错误特别有用。

在继续生成模型及其数据库表之前，让我们删除之前创建的 posts 表：

```php
**$ php oil g migration drop_posts**
**$ php oil r migrate**

```

# 模型

现在我们对迁移和 Oil 有了简要的了解，让我们开始使用 Oil。我们将使用以下命令创建一个模型以及相应的数据库表细节：

```php
**$ php oil generate model entry name:string slug:string excerpt:text content:text published_at:timestamp**

```

这将创建模型和迁移。让我们打开新创建的`entry.php`模型，位于`fuel/app/classes/model/`：

```php
<?php
class Model_Entry extends \Orm\Model
{
    protected static $_properties = array(
        'id',
        'name',
        'slug',
        'excerpt',
        'content',
        'published_at',
        'created_at',
        'updated_at',
    );

    protected static $_observers = array(
        'Orm\Observer_CreatedAt' => array(
            'events' => array('before_insert'),
            'mysql_timestamp' => false,
        ),
        'Orm\Observer_UpdatedAt' => array(
            'events' => array('before_save'),
            'mysql_timestamp' => false,
        ),
    );

    protected static $_table_name = 'entries'
}
```

你会注意到新生成的模型正在扩展 ORM 模型。为了使其工作，我们需要在自动加载器中包含 ORM 包。这是一个很好的机会来介绍 FuelPHP 自动加载器配置。加载位于`fuel/app/config/config.php`的配置文件。查找`'always load'`部分，并取消注释`'always_load'`数组，如下所示：

```php
'always_load' => array(
    'packages' => array(
        'orm',
    )
),
```

当您安装新的包时，只需将它们添加到`always_load`数组中以自动加载它们。有时，一个包只在某个方法或类中需要。然而，在这种情况下，我们可以只在需要时加载包。关于这方面的更多信息可以在以下链接找到：

[`fuelphp.com/docs/classes/package.html#method_load`](http://fuelphp.com/docs/classes/package.html#method_load)

现在，让我们回到`entry`模型。您会注意到`$_properties`数组，这将使从模型层调用变量变得更容易。如果您添加了新的数据库字段，它将需要添加到`properties`数组中。ORM 包括观察者的概念，这些是可以在不同时间执行方法或函数的操作。模型中使用的是`before_insert`和`before_update`。目前正在使用它们来在添加或更新条目时创建时间戳。

其他观察者在文档中列出；其中一个对我们有用的是`Observer_Slug`。这个观察者将处理将条目标题转换为 URL 安全，并避免重写现有功能的需要。让我们通过将以下片段添加到`observers`数组中，将这个观察者添加到我们的 entry 模型中：

```php
'Orm\Observer_Slug' => array(
    'events' => array( 'before_insert', 'before_update'),
    'source' => 'name',
    'property' => 'slug',

),
```

现在，当我们保存一个条目时，slug 将自动更新。

我们还需要创建一些其他数据库表。让我们现在这样做，然后我们可以创建它们的模型之间的关系，以使我们的生活更轻松：

```php
**$ php oil generate model category name:varchar slug:varchar**
**$ php oil generate model categories_entries category_id:int entry_id:int**

```

对于`entry`模型，将`Observer_Slug`添加到新的类别模型中。

对于`user`表，我们将使用 Auth 包，因为它包括用户认证功能。为此，我们需要将默认的 Auth 包配置复制到我们的应用程序配置中。

```php
**$ cp ~/Sites/journal/fuel/packages/auth/config/auth.php ~/Sites/journal/fuel/app/config/auth.php**

```

在这个阶段，我们应该在`auth.php`配置文件中更改盐值。完成后，我们必须运行以下命令来创建必要的`auth`表：

```php
**$ php oil refine migrate --packages=auth**

```

让我们运行迁移工具，确保数据库已更新：

```php
**$ php oil r migrate**

```

现在我们已经建立了数据库结构，我们可以将模型之间的关系联系起来。这是由 ORM 模型实现的，它原生支持以下关系：

+   `belongs_to`：该模型具有关系的主键，它属于一个相关对象。

+   `has_one`：它的主键存储在属于该模型的另一个表中。它只有一个关系。

+   `has_many`：它的主键保存在另一个模型的多个结果中。每个其他模型都需要属于这个模型。它可以有许多关系。

+   `many_to_many`：这使用一个链接表跟踪多对多关系。这个表记录了被链接表的主键对。它可以有，并且属于，许多模型。例如，一个博客文章可以有许多类别，一个类别可以链接到许多博客文章。

对于日志，我们将使用`belongs_to`，`has_one`和`many_to_many`关系。充分利用关系只需要快速添加到已创建的模型中。在您喜欢的文本编辑器中加载 entry 模型。该模型可以在`fuel/app/classes/model/entry.php`中找到。

```php
<?php

class Model_Entry extends \Orm\Model
{
    protected static $_properties = array(
        'id',
        'name',
        'slug',
        'excerpt',
        'content',
        'published_at',
        'created_at',
        'updated_at',
    );

    protected static $_observers = array(
        'Orm\Observer_CreatedAt' => array(
            'events' => array('before_insert'),
            'mysql_timestamp' => false,
        ),
        'Orm\Observer_UpdatedAt' => array(
            'events' => array('before_update'),
            'mysql_timestamp' => false,
        ),
        'Orm\Observer_Slug' => array(
            'events' => array('before_insert'),
            'source' => 'name',
            'property' => 'slug',
        ),
    );
    protected static $_table_name = 'entries';
}
```

在关闭大括号之前，将以下代码添加到模型中：

```php
 protected static $_belongs_to = array(
            'category' => array(
                'key_from' => 'id',
                'model_to' => 'Model_Category_Entry',
                'key_to' => 'entry_id',
                'cascade_save' => false,
                'cascade_delete' => false,
            ),
        );

    protected static $_has_many = array(
        'categories' => array(
            'key_from' => 'id',
            'model_to' => 'Model_Category_Entry',
            'key_to' => 'entry_id',
            'cascade_save' => false,
            'cascade_delete' => false,
        )
    );
```

我们并不总是需要包含完整的`$_belongs_to`声明。在大多数情况下，我们可以简单地使用以下内容：

```php
protected static $_belongs_to = array('post');
```

通过这些添加，我们正在配置 ORM 模型，将条目和类别之间的关系视为多对多关系。我们不是直接将类别链接到条目，而是使用`category_entry`链接表。这个表的命名是使用要链接的表的单数版本按字母顺序排列；在这种情况下，`categories`和`entries`的连接给我们一个表名`category_entry`。我们想要使用链接表的原因是因为我们希望能够为每个条目分配多个类别，这样就可以重复使用类别而不需要重复。例如，如果我们检索一个条目，类别列表将以以下方式获取：

```php
**$entry = Model_Entry::find(1)**

**$categories =$entry->categories;**

```

在这个例子中，我们正在寻找 ID 设置为`1`的条目。如果找到，将返回完整的条目对象，否则将返回 false。

除了多对多的关系，让我们将用户链接到他们撰写的条目。

首先，我们需要将`user_id`添加到条目表中：

```php
**$ php oil g migration add_user_id_to_entry user_id:int**
**$ php oil r migrate**

```

我们需要将`user_id`添加到条目模型的`$_properties`中：

```php
protected static $_properties = array(
        'id',
        'name',
        'slug',
        'excerpt',
        'content',
        'published_at',
        'created_at',
        'updated_at',
    );
```

由于关系从`user_id`映射到`user`表中的主`id`键，我们可以将用户定义为`$_belongs_to`数组的一部分。一旦将互补关系添加到`Model_User`模型中，其他所有内容都会就位：

```php
$_belongs_to = array( 
    'user',
    'category' => ...
);
```

谈到`Model_User`，需要创建它：

```php
**$ php oil g model user username:string password:string group:string email:string last_login:int profile_fields:text --no-migration**

```

尽管大多数用户功能都是通过 Auth 包内完成的，但添加用户模型对于与用户数据的`Model_Entry`关系是必要的。因此，加载位于`fuel/app/classes/model/`的`user.php`用户模型，并添加以下数组：

```php
protected static $_has_many = array('entry');
```

`category`和`category_entry`模型也需要创建关系。要做到这一点，导航到位于`fuel/app/class/mode/`的`category.php`文件：

```php
<?php

class Model_Category extends \Orm\Model
{
    protected static $_properties = array(
        'id',
        'name',
        'slug',
        'created_at',
        'updated_at',
    );

    protected static $_observers = array(
        'Orm\Observer_CreatedAt' => array(
            'events' => array('before_insert'),
            'mysql_timestamp' => false,
        ),
        'Orm\Observer_UpdatedAt' => array(
            'events' => array('before_update'),
            'mysql_timestamp' => false,
        ),
    );
    protected static $_table_name = 'categories';

    protected static $_belongs_to = array(
            'entry' => array(
                'key_from' => 'id',
                'model_to' => 'Model_Category_Entry',
                'key_to' => 'category_id',
                'cascade_save' => false,
                'cascade_delete' => false,
            ),
        );

    protected static $_has_many = array(
        'entries' => array(
            'key_from' => 'id',
            'model_to' => 'Model_Category_Entry',
            'key_to' => 'category_id',
            'cascade_save' => false,
            'cascade_delete' => false,
        )
    );
}
```

以下是位于`fuel/app/classes/model/category/`的`entry.php`文件的列表：

```php
<?php

class Model_Category_Entry extends \Orm\Model
{
    protected static $_properties = array(
        'id',
        'category_id',
        'entry_id',
        'created_at',
        'updated_at',
    );

    protected static $_observers = array(
        'Orm\Observer_CreatedAt' => array(
            'events' => array('before_insert'),
            'mysql_timestamp' => false,
        ),
        'Orm\Observer_UpdatedAt' => array(
            'events' => array('before_update'),
            'mysql_timestamp' => false,
        ),
    );
    protected static $_table_name = 'category_entries';

    protected static $_belongs_to = array(
        'category',
        'entry',
    );
}
```

现在我们有了模型和迁移，将它们添加到源代码控制是个好主意。一旦完成，让我们开始创建控制器来使用模型，然后创建视图（包括表单）。

# 控制器

控制器和模型一样，可以使用 Oil 创建。主要的控制器将用于管理条目和类别。这将有两种类型，公开可见的站点控制器和条目和类别表的管理系统。

我们的控制器可能最初不需要处理 RESTful 请求。因此，我们应该扩展`Controller_Template`，幸运的是，这正是 Oil 工具设置运行的方式。当我们使用 Oil 创建控制器时，它将被创建为扩展模板控制器。我们只需要考虑我们需要做什么操作和方法。因为我们主要将显示博客的条目和类别信息，所以让我们从`index`和`view`操作开始：

```php
**$ php oil g controller entry index view**

```

这将创建控制器、模板文件和所需方法的视图——`index`和`view`。

让我们看一下位于`fuel/app/classes/controller/`的`entry.php`：

```php
<?php

class Controller_Entry extends Controller_Template { 
    public function action_index()
    {
        $data['entries'] = Model_Entry::find('all');
        $this->template->title = "Entries";
        $this->template->content = View::forge('entry/index', $data);

    }

    public function action_view($id = null)
    {
        is_null($id) and Response::redirect('entry');

        if ( ! $data['entry'] = Model_Entry::find($id))
        {
            Session::set_flash('error', 'Could not find entry #'.$id);
            Response::redirect('entry');
        }
        $this->template->title = "Entry";
        $this->template->content = View::forge('entry/view', $data);

    }
}
```

在生成的控制器中有一些有趣的事情需要注意。首先是每个直接与 URL 相关的方法都以`action_`为前缀。这样可以更容易地看出哪些方法直接与 URL 相关，哪些方法涵盖了控制器内的其他功能

您还会注意到活动视图被传递到`$data`数组中的视图中。这用于将变量传递给视图，允许在视图渲染之前进行逻辑处理。这样视图就纯粹用于呈现，就像它们应该的那样。`data`数组中的键将被转换为视图中的变量，例如，`$data['subnav']`将通过视图中的`$subnav`变量调用。

`Controller_Template`类还有另外两个方法——`before()`和`after()`——这两个方法非常有用。`before()`方法可用于管理系统的用户身份验证，这将在本章后面进行演示。我们将在管理系统中使用它，以确保只有经过身份验证的用户才能访问管理系统。在控制器中使用`before()`方法时，请确保调用`parent::before()`方法，例如：

```php
class Controller_Entry extends Controller_Template
{
    // Essential, don't forget this method.
    public function before()
    {
        parent::before();

        // Your code
    }    
    .....
}
```

# 视图

使用 Oil 工具创建控制器时，还会创建模板和视图。让我们来看看其中一个视图，加载`fuel/app/views/entry/index.php`。

在视图中，你会注意到缺少开头和结尾的 HTML body。`template.php`文件位于 views 文件夹的根目录中，负责处理演示元素的测试。在查看`template.php`之前，让我们讨论一下`index.php`文件的一些部分：

```php
Arr::get( $subnav, "index");
```

如前面的代码行所示，它使用了核心 FuelPHP `Arr`类，这是一组用于处理数组的辅助函数。在这种情况下，使用了`get`方法。这允许您检查数组中是否存在给定的键，如果找不到键，则返回 false。视图正在使用此功能来输出活动页面/视图的`'active'`样式类。

第二个正在使用的核心类是`Html::anchor()`。这个类提供了大量的 HTML 标签，并确保所有使用的标签都符合`Doctype`声明。我们使用`anchor`方法来输出到视图的链接。第一个值是链接，第二个是显示标题（在`a`标签之间的部分）。使用这个辅助方法的一个原因是确保链接在任何环境的 URL 下都能正常工作，无论应用程序是安装在子文件夹还是子域中。现在，让我们快速看一下`fuel/app/views/template.php`中的`template.php`文件。

默认情况下，模板使用 Twitter bootstrap 为项目提供快速起点。FuelPHP 期望项目的 public 文件夹中有 CSS 和 JS 文件夹。加载 CSS 和 JavaScript 文件就像在模板中使用以下代码一样简单：

```php
<?php echo Asset::css('bootstrap.css');?>
<?php echo Asset::js('bootstrap.js'); ?>
```

与 Ruby on Rails 等框架一样，FuelPHP 实现了 flash 会话，用于在页面加载之间传递变量和值。默认情况下，FuelPHP 有两个 flash 会话，默认命名为`success`和`error`。当然，您可以根据需要向 FuelPHP 添加任意数量的 flash 会话。以下是一个示例：

```php
**<?php Session::set_flash('warning', 'Warning Message') ?>**

```

以下示例是模板中输出 flash 会话的两种方式：

```php
<?php if (Session::get_flash('success')): ?>
    <div class="alert alert-success">
        <strong>Success</strong>
        <p>
            <?php echo implode('</p><p>', e((array) Session::get_flash('success'))); ?>
        </p>
    </div>
<?php endif; ?>
```

`template.php`的其余部分是相当简单的 HTML。创建能够响应访问者屏幕尺寸的网站，正在成为支持移动设备的一种非常流行的方式。因此，在为桌面添加布局之前，我们应该首先考虑移动尺寸的屏幕。为了帮助实现这一点，我们将使用 HTML5 Boilerplate ([`html5boilerplate.com`](http://html5boilerplate.com))。我们将自定义 Boilerplate 的版本，可以通过[`www.initializr.com/`](http://www.initializr.com/)伴侣网站完成。要做到这一点，请执行以下步骤：

1.  在 Initializr 网站上，应该有 3 个选项：Classic H5BP、Responsive 和 Bootstrap。选择**Classic H5BP**选项（灰色按钮），然后选择**Responsive Bootstrap** 2.3.2 模板选项。最后点击**Download it!**。

1.  将下载的文件复制到您的日志应用程序的 public 文件夹中。将`js`、`css`和`img`文件夹复制到您的 assets 文件夹中。

1.  现在，打开文本编辑器中的`index.html`文件并进行编辑。下一步是从`index.html`文件中提取元素并将其添加到`template.php`文件中。

以下是最终的示例：

```php
<!DOCTYPE html>
<!--[if lt IE 7]>      <html class="no-js lt-ie9 lt-ie8 lt-ie7"> <![endif]-->
<!--[if IE 7]>         <html class="no-js lt-ie9 lt-ie8"> <![endif]-->
<!--[if IE 8]>         <html class="no-js lt-ie9"> <![endif]-->
<!--[if gt IE 8]><!--> <html class="no-js"> <!--<![endif]-->
    <head>
        <meta charset="utf-8">
        <meta http-equiv="X-UA-Compatible" echo Asset::css('bootstrap.min.css'); ?>
content="IE=edge,chrome=1">
        <title><?php echo $title; ?></title>
        <meta name="description" content="">
        <meta name="viewport" content="width=device-width">
        <?php
        <style>
            body {
                padding-top: 60px;
                padding-bottom: 40px;
            }
        </style>
        <?php echo Asset::css('bootstrap-responsive.min.css'); ?>
        <?php echo Asset::css('main.css'); ?>
        <?php Asset::add_path('assets/js/vendor/', 'js'); ?>
        <?php echo Asset::js('modernizr-2.6.2.min.js'); ?>
    </head>
    <body>
        <!--[if lt IE 7]>
            <p class="chromeframe">You are using an <strong>outdated</strong> browser. Please <a href="http://browsehappy.com/">upgrade your browser</a> or <a href="http://www.google.com/chromeframe/?redirect=true">activate Google Chrome  Frame</a> to improve your experience.</p>
        <![endif]-->
        <div class="navbar navbar-inverse navbar-fixed-top">
            <div class="navbar-inner">
                <div class="container">
                    <a class="btn btn-navbar" data-toggle="collapse" data-target=".nav-collapse">
                        <span class="icon-bar"></span>
                        <span class="icon-bar"></span>
                        <span class="icon-bar"></span>
                    </a>
                    <a class="brand" href="/">Journal</a>
                    <div class="nav-collapse collapse">
                        <ul class="nav">
                          <li class="active"><a href="/">Home</a></li>
                          <li><a href="/entry">Entries</a></li>
                          <li><a href="/category">Categories</a></li>
                        </ul>
                    </div><!--/.nav-collapse -->
                </div>
            </div>
        </div>
        <div class="container">
            <h1><?php echo $title; ?></h1>
            <?php if (Session::get_flash('success')): ?>
                <div class="alert alert-success">
                    <strong>Success</strong>
                    <p>
                    <?php echo implode('</p><p>', e((array) Session::get_flash('success'))); ?>
                    </p>
                </div>
            <?php endif; ?>
            <?php if (Session::get_flash('error')): ?>
                <div class="alert alert-error">
                    <strong>Error</strong>
                    <p>
                    <?php echo implode('</p><p>', e((array) Session::get_flash('error'))); ?>
                    </p>
                </div>
            <?php endif; ?>
            <hr>
            <div class="span12">
                <?php echo $content; ?>
            </div>

            <footer>
                <p>&copy; Journal <?php echo date( 'Y' ); ?></p>
            </footer>

        </div> <!-- /container -->

        <script src="//ajax.googleapis.com/ajax/libs/jquery/1.10.1/jquery.min.js"></script>
        <script>window.jQuery || document.write('<script src="js/vendor/jquery-1.10.1.min.js"><\/script>')</script>
        <?php echo Asset::js('bootstrap.min.js'); ?>
        <?php echo Asset::js('plugins.js'); ?>
        <?php echo Asset::js('main.js'); ?>
    </body>
</html>
```

### 提示

完成`index.html`文件后，请确保从公共文件夹中删除它；否则，您可能会在加载日志网站时遇到问题。

`template.php`文件的大部分内容已经在前面提到过，除了`Asset::set_path()`。HTML5 Boilerplate 包括`modernizr` JavaScript 文件的`vendor`文件夹。默认情况下，Asset 加载器将查找位于`public/assets`的`css`和`js`文件夹，但不会查看这些目录中的文件夹。我们使用`set_path()`方法将`vendor`文件夹包含在 JavaScript 加载中。`set_path()`中的第二个变量让 Asset 加载器知道新路径是一个 JavaScript 文件夹。

现在，我们有机会在浏览器中检查网站，例如`http://journal.dev/entry`或`http://localhost/Site/journal/entry`或`http://127.0.0.1/Site/journal/entry`，具体取决于您的开发机器配置。

目前，访问者将看到的第一个网页是 FuelPHP 欢迎页面。我们应该更改这一点，使得访问者首先看到条目列表页面。这样做很快，可以很容易地通过 FuelPHP 中的路由来完成。加载位于`fuel/app/config/`的`routes.php`配置文件。

```php
<?php

return array(
    '_root_'  => 'welcome/index',  // The default route
    '_404_'   => 'welcome/404',    // The main 404 route
    'hello(/:name)?' => array('welcome/hello', 'name' => 'hello'),
);
```

您可以通过将`'welcome/index'`更改为`'entry/index'`来将欢迎页面更改为条目列表页面。

回到浏览器，在日志网站的顶层导航到，例如`http://journal.dev`或`http://localhost/Site/journal`或`http://127.0.0.1/Site/journal`。您会注意到您的条目索引页面正在显示。

到目前为止，我们已经涵盖了控制器和视图的基本部分，并安装了 HTML5 Boilerplate。现在，我们应该看一下条目和类别的管理。

在查看管理系统之前，公共网站上还有一件事要做——类别。让我们生成类别索引和查看控制器：

```php
**$ php oil g controller category index view**

```

您可能认为能够显示条目和类别很好，但我们实际上如何处理管理系统呢？下一节将教会我们如何做到这一点。

# 使用 Oil 生成管理系统

我们将使用 Oil 工具快速构建一个条目和类别的管理系统。

除了创建迁移和控制器之外，Oil 还可以用来为您搭建功能。这有两种风格：一种是用于前端，就像我们已经看到的那样，另一种是具有完全控制的管理系统。

在继续之前，我们需要重命名`category`和`entry`模型。这是因为它们将作为管理系统脚手架的一部分重新创建。我们将它们重命名，以便我们有之前在这些模型中设置的关系的副本：

```php
**$ mv ~/Sites/journal/fuel/app/classes/model/entry.php ~/Sites/journal/fuel/app/classes/model/entry.bak.php**
**$ mv ~/Sites/journal/fuel/app/classes/model/category.php ~/Sites/journal/fuel/app/classes/model/category.php**

```

现在，让我们运行管理脚手架 Oil 命令：

```php
**$ php oil g admin entry name:varchar slug:varchar excerpt:text content:text published_at:int user_id:int**
**$ php oil g admin category name:varchar slug:varchar -force**

```

`-force`元素是必需的，以便重新运行管理系统中的共享文件，以便创建类别文件。

Oil 已经为您创建了一些文件，但不幸的是，它不知道类别和条目的关系，也不知道`Observer_Slug`属性。因此，我们需要关联回`Entry 和 Category`模型，我们还需要添加回`Observer_Slug`。这个过程将与最近重命名的条目和类别模型一样简单。

在编辑模型时，我们需要删除或注释掉以下内容：

```php
**$val->add_field( 'slug', 'Slug', 'required|max_length[255]');**

```

我们还需要在管理条目和类别控制器中做同样的事情。在模型中定义的`Observer_Slug`将处理 slug。

因此，您需要检查位于`fuel/app/classes/controller/admin/`的`category.php`的第 32、66 和 86 行，并且还需要检查位于相同文件夹中的`entry.php`的第 32、69 和 92 行。

作为脚手架过程的一部分，已经创建了一些表单，并在条目和类别视图的创建和编辑之间共享。加载`fuel/app/views/admin/category/_form.php`和`fuel/app/views/admin/entry/_form.php`。在两个表单中，注释掉对 slug 的引用，因为它不需要。

在浏览器中，导航到`http://journal.dev/admin`或`http://localhost/Site/journal/admin`或`http://127.0.0.1/Site/journal/admin`，您将被重定向到登录表单。我们还没有设置用户帐户，但 Oil 可以帮助解决问题。

加载您的终端并运行：

```php
**$ php oil console**

```

这将启动一个交互式控制台，可以利用核心 FuelPHP 和包代码。在这种情况下，我们需要调用 Auth 包来创建一个新用户。

```php
>>> Auth::create_user('admin', 'password', 'email@domain.com', 100 );
1
>>> exit;
```

此命令将输出新创建帐户的`user_id`。`100`代表 Auth 包中的最高默认用户特权和角色。要退出控制台会话，只需输入`exit`并运行。

现在，您将能够登录到您新创建的管理系统。从那里，您将能够添加新的类别和条目。

# 总结

本章简要介绍了项目结构以及 FuelPHP Oil 命令行工具如何帮助您快速设置。

Oil 充当脚手架结构，但您仍然需要填补空白。例如，可以从博客中检索链接的条目和类别，但我们仍然需要构建必要的管理控件来设置关系。

在下一章中，我们将更详细地了解包，并创建我们自己的包，可以与社区共享。


# 第五章：包

在上一章中，我们使用包来使我们的生活更轻松。我们使用了 Oil 来快速启动和运行，以及帮助用户认证的 Auth 包。

在本章中，我们将涵盖以下主题：

+   什么是包？

+   推荐的包

+   使用 Auth 包进行用户认证

+   什么是 Composer 以及如何使用它？

+   构建自己的包的介绍

# 什么是包？

作为开发人员，我们经常有一些我们在多个项目中使用的代码。它可能只是简单的字符串操作，但如果没有我们熟悉的代码，我们会感到迷失。

这就是包派上用场的地方。它们提供了一个很好的组织、重用和共享代码的方式。包可以包含各种代码，比如模型、配置，甚至第三方库。

由于 FuelPHP 和其他包的类结构，可以扩展其他包和 FuelPHP 核心。这一切都可以在不更改核心文件的情况下实现，使升级更加容易和简单。

尽管包可以做很多事情，但也有一些包做不到的事情。例如，它们无法映射到 URL；这是应用程序或项目代码的作用。如果有一个功能在多个项目中需要重复使用，并且还需要 URL 访问，建议使用模块。这将在下一章中介绍。

运行一些推荐的包是展示使用包时可能发生的事情的好方法。

# 推荐的包

尽管您的需求可能不同，在本节中我们将介绍一些经常有用的包。

## OAuth

如今的互联网充满了像 Facebook 和 Twitter 这样的大玩家，每个玩家都有不同的结构和用途；但它们都支持用户认证的**OAuth**的一个版本。这意味着许多项目可能需要使用 OAuth 进行用户认证和单一登录。

一个高度推荐的包是从 Kohana PHP 框架（[`kohanaframework.org`](http://kohanaframework.org)）移植而来的。它可以在[`github.com/fuel-packages/fuel-oauth`](https://github.com/fuel-packages/fuel-oauth)找到。

这个包处理与第三方服务的认证，比如：

+   Dropbox

+   Flickr

+   领英

+   Tumblr

+   推特

+   Vimeo

在使用这个包时，您需要将配置文件复制到应用程序配置目录。这将允许您为第三方系统添加您的消费者密钥和密钥。

## OAuth2

您可能已经注意到，Facebook 在 OAuth 包的可用交互中缺失了。这主要是因为 Facebook 使用**OAuth2**标准（[`oauth.net/2`](http://oauth.net/2)）。尽管它与第一个包执行的工作类似，但您可能会发现 OAuth2 包有用。这个包可以在[`github.com/fuel-packages/fuel-oauth2`](https://github.com/fuel-packages/fuel-oauth2)找到，并支持以下第三方服务：

+   脸书

+   Foursquare

+   GitHub

+   谷歌

+   PayPal

+   Instagram

+   Soundcloud

+   Windows Live

+   YouTube

与之前的包一样，您需要创建控制器和应用程序代码，以利用来自 OAuth 的认证数据。

## Mandrill

有时，我们需要发送电子邮件。尽管使用默认的`mail()` PHP 函数肯定更容易，但这种方法并不总是可靠的。有时，`mail()`函数会悄悄失败。这就是第三方系统派上用场的地方。有几个大型的电子邮件服务，比如**Campaign Monitor**和**MailChimp**。这些通常是电子邮件活动和邮件列表。幸运的是，MailChimp 已经以**Mandrill**（[`mandrill.com`](http://mandrill.com)）的形式开放了他们的基础设施。

Fuel Mandrill 包是一个非官方包，可以从[`github.com/Izikd/fuel-mandrill`](https://github.com/Izikd/fuel-mandrill)获取。它是官方 Mandrill API 库的包装器，因此您可以放心它会正常工作。

## Sprockets

前端开发和 HTML 正开始变得更加结构化，使用诸如 LESS、Sass 和 Compass 之类的编译器。通常，我们需要使用外部库或工具编译 Web 上的资产。Sprockets 包受到 Ruby on Rails 资产管道的启发（[`guides.rubyonrails.org/asset_pipeline.html`](http://guides.rubyonrails.org/asset_pipeline.html)）。它处理了使用 Sass、LESS 和 CoffeeScript 编译器的端口进行编译。更多信息和安装说明可在[`github.com/vesselinv/fuel-sprockets`](https://github.com/vesselinv/fuel-sprockets)找到。

# 使用 Auth 包进行用户身份验证

尽管我们在第四章中提到了 Auth 包，*演示应用程序*，让我们详细地检查一下这个包。

`Auth`包不是 FuelPHP 核心的一部分，它为 FuelPHP 中的用户身份验证提供了一个标准化的接口。这使开发人员可以编写自己的驱动程序，并轻松地集成新的驱动程序以与旧代码一起工作，但仍然保持方法一致。

`Auth`包包括三个基本驱动程序：登录、组和**ACL**（**访问控制列表**）。值得注意的是，登录驱动程序可以同时处理多个登录驱动程序。例如，用户可以使用用户名和密码对进行登录，或者通过第三方系统（如 Twitter）进行身份验证。

包括的三个驱动程序是**SimpleAuth**、**ORMAuth**和**OPAuth**。

## SimpleAuth

这是一个简单的身份验证系统，它使用数据库表来存储用户信息。它在配置文件中存储有关组、角色和 ACL 的信息。它被用作管理系统的一部分。正如我们在第四章中所看到的，*演示应用程序*，SimpleAuth 包括创建存储用户信息的数据库表所需的迁移。只需配置应用程序以使用 SimpleAuth，然后运行以下命令即可创建表格：

```php
**oil r migrate --package=auth**

```

有关配置 SimpleAuth 的更多信息以及使用示例可以在以下链接找到：

[`fuelphp.com/docs/packages/auth/simpleauth/intro.html`](http://fuelphp.com/docs/packages/auth/simpleauth/intro.html)

## ORMAuth

在许多方面，这与 SimpleAuth 类似，只是它将所有配置存储在数据库中，而不是在配置文件中。

用户控件和角色可以更加精细化，并分配给个别用户。与 SimpleAuth 不同，用户属性存储在元数据表中，而不是在用户表中的序列化数组中。另一个不错的功能是保留用户登录时间的历史记录。

要启用 ORMAuth 包，您需要将`ORMAuth`添加到`app/config/config.php`文件中的`always load`代码部分。

更多信息可以在以下链接找到：

[`fuelphp.com/docs/packages/auth/ormauth/usage.html`](http://fuelphp.com/docs/packages/auth/ormauth/usage.html)

## OPAuth

这是提供的三个驱动程序中最复杂的一个。它支持对 OAuth 和 OpenID 提供程序进行身份验证。它还支持单一登录；因此，当用户登录到第三方网站（如 Twitter）时，OPAuth 将能够检测到会话并透明地登录用户。

有关 OPAuth 驱动程序的更多信息可以在以下链接找到：

[`fuelphp.com/docs/packages/auth/opauth/intro.html`](http://fuelphp.com/docs/packages/auth/opauth/intro.html)

正如您在日志管理系统的脚手架中所看到的，身份验证方法将需要在我们的应用程序中实现。Auth 方法有很好的文档，并且命名如下：

+   `Auth::check()`: 此方法检查用户是否已经认证，并返回一个布尔值 true 或 false

+   `Auth::remember_me()`: 此方法创建一个“记住我”cookie

+   `Auth::dont_remember_me()`: 此方法删除“记住我”cookie

+   `Auth::logout()`: 此方法注销用户

+   `Auth::create_user( array())`: 此方法注册一个用户

每个 Web 应用程序都是不同的，但至少 FuelPHP Auth 软件包为用户认证提供了一个很好的起点。对于大多数用途来说，这通常已经足够了。

# Composer

目前有很多种方法来管理代码和安装第三方功能。Ruby 世界有 Gem 打包系统。正如在第一章中提到的，FuelPHP 正在采用 PHP 编码和互操作标准。其中之一是能够在不重写为 FuelPHP 软件包的情况下使用其他框架的代码。

在项目的生命周期中，软件包可能会随着新功能和安全修复而发生变化。就像 Ruby on Rails 的 Bundler 一样，PHP 有一个名为 Composer 的依赖管理器。

Composer 允许您声明要在项目中安装哪些库的版本，并将为您安装它们。在开发和测试时非常有用，因为您知道确切安装了哪些代码。它还允许您对这些库的任何更改进行源代码控制。

尽管 FuelPHP 软件包和 Composer 仍处于早期阶段，但可以在以下链接找到一些软件包：

[`packagist.org/search/?q=fuel-`](https://packagist.org/search/?q=fuel-)

要向项目添加更多依赖项，只需更改`~/Sites/journal/composer.json`中找到的`composer.json`文件。

一旦找到要在 Composer 中使用的软件包，就需要在您的`composer.json`文件中添加类似以下代码：

```php
"require" : {
    "monolog/monolog": "1.2.*"
    }
```

这将确保您拥有 Monolog 1.2 软件包的最新点版本。

# 构建自己的软件包简介

到目前为止，您已经看到软件包非常有用，而且创建起来也很简单。在本节中，我们将通过创建一个文本操作软件包来介绍一些基础知识。

## 设置存储库

首先要做的是设置一个存储库。就像在上一章中一样，我们将使用 GitHub。

我们将创建一个名为**Journal String**的软件包；这将有一个名为`journal-string`的存储库名称。通常建议使用类似 Fuel String 的名称，但由于这只是一个简单的例子，因此不需要在软件包标题中包含 Fuel。

我们将使用新的存储库作为日志项目中的一个子模块，因此请确保记下存储库地址，类似于`git@github.com:digitales/journal-string.git`。

## 将软件包作为子模块使用

我们需要将这个新的子模块添加到我们的项目中，所以现在是加载控制台/终端窗口的时候了。在终端中，导航到日志项目的顶层，然后添加子模块。确保它被克隆到软件包目录中。在这个例子中，我们将子模块检出到一个名为 string 的目录中，而不是`journal-string`；这样做是为了节省输入并使自动加载更容易。

```php
**$ cd ~/Sites/journal**
**$ git submodule add git@github.com:digitales/journal-text.git fuel/packages/string**
**$ cd fuel/packages/string**

```

最后一个命令将我们带入`string`软件包目录。Git 子模块充当主项目存储库中封装的完全独立的存储库。这意味着对`journal-text`软件包所做的任何更改都需要提交到其自己的存储库，然后需要更新主存储库。

## 构建软件包

由于您将与您的团队或自己或社区共享软件包，因此将来目录和文件的结构非常重要。在使用软件包时，这将帮助您快速熟悉。建议的目录结构如下所示：

```php
**/packages**
 **/package**
 **/bootstrap.php**
 **/classes**
 **/class1.php**
 **/second-class.php**
 **/config**
 **/packageconfig.php**

```

每个包都应该在包的顶级目录中包含一个 `bootstrap.php` 文件。这个文件可以用来为包添加命名空间，并为了更好的性能和自动加载目的添加包类。如果您想要覆盖核心类，您需要将包命名空间添加到核心命名空间中，例如：

```php
Autoloader::add_core_namespace( 'String', true );
```

让我们创建我们的包结构，如下所示的层次结构：

```php
**packages/**
 **/journal/**
 **/classes/**
 **string.php**
 **/config/**
 **string.php**
 **bootstrap.php**
 **readme.md**

```

在这个例子中，我们将为一串文本创建一些基本的双向加密，并给它命名空间 `String`。我们将有一个配置文件，允许我们对加密后的字符串进行加盐。所以，让我们首先创建示例配置文件。加载位于 `/journal/config/` 的 `string.php` 文件，并添加以下代码片段：

```php
<?php
/**
 * NOTICE:
 *
 * If you need to make modifications to the default configuration, copy
 * this file to your app/config folder, and make them in there.
 *
 * This will allow you to upgrade without losing your custom config.
 */
return array(
    'active' => Fuel::$env,
    'development' => array(
        'salt' => 'put_your_salt_here',
    ),
    'production' => array(
        'salt' => 'put_your_salt_here',
    ),  
);
```

在 `string.php` 文件中，有一些示例环境。在配置文件中，我们还动态设置环境为 `Fuel::$env`。这将在主字符串类中用于加载正确环境的配置。然后，正确的值将被分配给一个名为 `$_config` 的静态类变量。

在 `encode` 和 `decode` 函数中，我们使用了 FuelPHP **Crypt** 功能。我们还包括了一些大写和小写字符串操作函数，以供后续演示目的使用。不再拖延，以下是字符串操作类的示例：

```php
<?php
/**
 * String manipulation Package
 *
 * This is a simple set of methods for string manipulation
 *
 * @license    MIT License
 */
namespace String;
```

这个类将包括一个 `StringExeption` 异常，它扩展了 FuelPHP 的 `Exception` 类，允许我们在需要时自定义异常：

```php
class StringException extends \Exception {}

class String {
    protected static $config;

    /**
     * @var  object  PHPSecLib hash object
     */
    protected static $hasher;
```

以下函数用于从应用程序配置目录中获取 `string.php` 文件：

```php
    protected static function get_config()
    {
        if ( !static::$config ):
            $config = \Config::load('string', true);
            static::$config = $config[ $config['active'] ];
        endif;
        return static::$config;    
    }

    /**
     * Encode a string using the core encode function
     *
     *  This will retrieve the salt and use that for the encoding.
     *
     *  @param string $string The string to be encoded
     *  @param null | string $salt If the salt is null, the config will be used instead.
     *  @return string
     */
    public static function encode( $string, $salt = null )
    {   
        if ( ! $salt) {
             $config = self::get_config();
    $salt = $config['salt']; 
        }
        return \Crypt::encode( $string, $salt );
    }
```

`encode()` 函数将对字符串进行编码并返回加密后的字符串。接下来，我们将在 `decode()` 函数中解码字符串：

```php

    /**
     * Decode a string using the core decode function
     *
     *  This will retrieve the salt and use that for the decoding
     *
     *  @param string $string The string to be decoded
     *  @param null | string $salt If the salt is null, the config will be used instead.
     *  @return string
     */
    public static function decode( $string, $salt = null )
    {
        if ( ! $salt) {
            $config = self::get_config();
            $salt = $config['salt'];   
        }    
        return \Crypt::decode ( $string, $salt );
    }
```

现在，让我们介绍一个快速的**密码哈希**方法。值得注意的是，在 PHP 5.5 中，我们可以使用新的密码哈希算法：

```php

    /**
     * Default password hash method
     *
     * @param   string
     * @return  string
     */
    public static function hash_password($password)
    {    
        $config = self::get_config();       
            $salt = $config['salt'];
        return base64_encode(self::hasher()->pbkdf2($password, $config['salt'], 10000, 32));
    }

    /**
     * Returns the hash object and creates it if necessary
     *
     * @return  PHPSecLib\Crypt_Hash
     */
    public static function hasher()
    {
        if ( !static::$hasher ):
            if ( ! class_exists('PHPSecLib\\Crypt_Hash', false))
            {
                import('phpseclib/Crypt/Hash', 'vendor');
            }
            $hasher = new \PHPSecLib\Crypt_Hash();
            return $hasher;
        endif;

        return static::$hasher;
    }
```

在接下来的几个函数中，我们将执行一些简单的文本字符串操作。首先，让我们将字符串改为全部小写：

```php

    /**
     * Convert the string to lowercase.
     *
     * @param   string  $str       required
     * @param   string  $encoding  default UTF-8
     * @return  string
     */
    public static function lower($str, $encoding = null)
    {
        $encoding = \Fuel::$encoding;

        if ( function_exists('mb_strtolower') ){
            return mb_strtolower($str, $encoding);
        } else {
            return strtolower($str);
        }

    }
```

现在，让我们将字符串转换为大写：

```php
    /**
     * Covert the string to uppercase.
     *
     * @param   string  $str       required
     * @param   string  $encoding  default UTF-8
     * @return  string
     */
    public static function upper($str, $encoding = null)
    {
        $encoding or $encoding = \Fuel::$encoding;

        if ( function_exists('mb_strtoupper') {
            return mb_strtoupper($str, $encoding);
        } else {
            return strtoupper($str);
        }

    }
```

现在，让我们将每个单词的第一个字符变为小写：

```php
    /**
     * lcfirst
     *
     * Does not strtoupper first
     *
     * @param   string  $str       required
     * @param   string  $encoding  default UTF-8
     * @return  string
     */
    public static function lcfirst($str, $encoding = null)
    {
        $encoding or $encoding = \Fuel::$encoding;

        if(function_exists('mb_strtolower')){
            return mb_strtolower(mb_substr($str, 0, 1, $encoding), $encoding).
                mb_substr($str, 1, mb_strlen($str, $encoding), $encoding);
        }else{
            return lcfirst($str);
        }

    }
```

现在，让我们将每个单词的第一个字符变为大写：

```php
    /**
     * ucfirst
     *
     * Does not strtolower first
     *
     * @param    string $str       required
     * @param    string $encoding  default UTF-8
     * @return   string
     */
    public static function ucfirst($str, $encoding = null)
    {
        $encoding or $encoding = \Fuel::$encoding;

        if(function_exists('mb_strtoupper')_{
            return mb_strtoupper(mb_substr($str, 0, 1, $encoding), $encoding).
                mb_substr($str, 1, mb_strlen($str, $encoding), $encoding);
        }else{
            return ucfirst($str);
        }

    }
```

现在，让我们将每个单词的第一个字符大写：

```php
    /**
     * ucwords
     *
     * First strtolower then ucwords
     *
     * ucwords normally doesn't strtolower first
     * but MB_CASE_TITLE does, so ucwords now too
     *
     * @param   string   $str       required
     * @param   string   $encoding  default UTF-8
     * @return  string
     */
    public static function ucwords($str, $encoding = null)
    {
        $encoding or $encoding = \Fuel::$encoding;

        if ( function_exists('mb_convert_case') ){
            return mb_convert_case($str, MB_CASE_TITLE, $encoding);
        } else {
            return ucwords(strtolower($str));
        }

    }
}
```

现在我们已经解决了基本功能，应用程序代码需要能够访问它。为此，我们可以使用日志包目录顶层的 `bootstrap.php` 文件。

加载位于 `packages/journal-string/` 的 `bootstrap.php` 文件：

```php
<?php
Autoloader::add_core_namespace('String');

Autoloader::add_classes(array(
    'String\\String' => __DIR__.'/classes/string.php',
    'String\\StringException' => __DIR__.'/classes/string.php'
));
```

然后，我们就可以使用类似以下的方式调用功能：

```php
String::decode( $the_string );
```

## 配置您的包

使用该包时的第一件事是创建一个特定于项目的包配置版本。要做到这一点，在您的终端中运行以下命令：

```php
**$ cp ~/Sites/journal/fuel/packages/journal-string/config/string.php  ~/Sites/journal/fuel/app/config/string.php**

```

我们需要添加一些自定义的 `salt` 文本字符串，这些将作为新复制的 `string.php` 配置中的键使用：

```php
return array(
    'active' => Fuel::$env,
    'development' => array(
        'salt' => '(my awesome salt)',
    ),
    'production' => array(
        'salt' => '(my awesome salt)',
    ),  
);
```

## 使用您的包

现在，您已经配置了包并创建了字符串函数，是时候演示如何使用新包了。首先，让我们将 `String` 包添加到我们的 `config.php` 应用程序文件中：

由于我们添加了一个核心命名空间 `String`，我们可以使用以下方法调用我们的字符串函数：

```php
**$encoded_string = String::encode( 'something to encode');**
**$decoded_string = String::decode();**
**echo $decoded_string;**

```

您可以在控制器中测试功能，然后在视图中显示结果。创建包是一个简单的过程，您应该熟悉它。一旦您创建了您的包，您可能希望与他人分享。

# 让人们了解您的包

所以，您已经创建了您的包，现在是时候发布它了。首先，检查所有函数是否都有注释，并且您已经在`Readme.md`文件（或`Readme.txt`文件）中记录了如何使用该包的方法是个好主意。如果您在 GitHub 上编写代码，他们提供了一个快速创建网页来宣传您的包或项目的方法。在 GitHub 上创建页面时，他们将使用 Readme 文件作为起点，然后让您自定义关于您的包的任何信息。更多信息可以在[`help.github.com/categories/20/articles`](https://help.github.com/categories/20/articles)中找到。

一旦您确定代码已经准备好分享，就发送一条推文到 FuelPHP 的 Twitter 账号（[`twitter.com/FuelPHP`](https://twitter.com/FuelPHP)）。他们经常会“转推”您的消息给他们的关注者。除此之外，您还可以在 FuelPHP 论坛上分享您的包链接，网址是[`fuelphp.com/forums/categories/codeshare`](http://fuelphp.com/forums/categories/codeshare)。

# 总结

在本章中，我们已经涵盖了一些包的基础知识，以及一些有用的包的示例，这些包可以让我们的开发工作更加轻松。有了一系列可靠的包，我们可以集中精力去创建应用程序，并交付客户想要的东西。我们已经创建了一个包，配置了它，并演示了它的使用。

在下一章中，我们将涵盖一些更高级的主题，包括功能可移植性、单元测试和在 FuelPHP 中进行性能分析。
