# Angular6 和 Laravel5  Web 全栈开发实用指南（一）

> 原文：[`zh.annas-archive.org/md5/b37ef01c0005efc4aa3cccbea6646556`](https://zh.annas-archive.org/md5/b37ef01c0005efc4aa3cccbea6646556)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

自其诞生以来，Web 开发已经走过了很长的路。今天，我们希望的是快速、强大和引人入胜的 Web 应用程序，而渐进式 Web 应用程序（PWA）是前进的道路。在这本书中，我们将利用 Angular 和 Laravel 这两个最流行的框架来构建强大的 Web 应用程序。

Angular 是用于创建现代快速 PWA 的最流行的前端 JavaScript 框架之一。除了非常多才多艺和完整之外，Angular 还包括用于生成模块、组件、服务和许多其他实用工具的 Angular CLI 工具。另一方面，我们有 Laravel 框架，这是用于开发 Web 应用程序的强大工具，探讨了约定优于配置的范式的使用。

这本书将为您提供从头开始使用 Angular 和 Laravel RESTful 后端构建现代全栈 Web 应用程序的实际知识。它将带您了解使用这两个框架开发的最重要的技术方面，并演示如何将这些技能付诸实践。

# 这本书是为谁准备的

这本书适用于初学 Angular 和 Laravel 的开发人员。需要了解 HTML、CSS 和 JavaScript 和 PHP 等脚本语言的知识。

本书的内容涵盖了软件工程生命周期的所有阶段，涵盖了现代工具和技术，包括但不限于 RESTful API、基于令牌的身份验证、数据库配置以及 Docker 容器和镜像。

# 本书涵盖了什么

第一章，*理解 Laravel 5 的核心概念*，介绍了 Laravel 框架作为开发 Web 应用程序的强大工具，并探讨了约定优于配置的范式的使用。我们将看到，Laravel 默认情况下具有构建现代 Web 应用程序所需的所有功能，包括基于令牌的身份验证、路由、资源等。此外，我们将了解为什么 Laravel 框架是当今最流行的 PHP 框架之一。我们将学习如何设置环境，了解 Laravel 应用程序的生命周期，并学习如何使用 Artisan CLI。

第二章，*TypeScript 的好处*，探讨了 TypeScript 如何使您能够编写一致的 JavaScript 代码。我们将研究它包括的功能，例如静态类型和其他在面向对象语言中非常常见的功能。此外，我们将研究如何使用最新版本的 ECMAScript 的新功能，并了解 TypeScript 如何帮助我们编写干净和组织良好的代码。在本章中，我们将看到 TypeScript 相对于传统 JavaScript 的好处，了解如何使用静态类型，并理解如何使用接口、类和泛型，以及导入和导出类。

第三章，*理解 Angular 6 的核心概念*，深入探讨了 Angular，这是用于开发前端 Web 应用程序的最流行的框架之一。除了非常多才多艺和完整之外，Angular 还包括用于生成模块、组件、服务和许多其他实用工具的 Angular CLI 工具。在本章中，我们将学习如何使用新版本的 Angular CLI，理解 Angular 的核心概念，并掌握组件的生命周期。

第四章，“构建基线后端应用程序”，是我们开始构建示例应用程序的地方。在本章中，我们将使用 RESTful 架构创建一个 Laravel 应用程序。我们将更仔细地研究一些在第一章中简要提到的要点，例如使用 Docker 容器来配置我们的环境，以及如何保持我们的数据库填充。我们甚至将查看如何使用 MySQL Docker 容器，如何使用迁移和数据库种子，以及如何使用 Swagger UI 创建一致的文档。

第五章，“使用 Laravel 创建 RESTful API - 第 1 部分”，将介绍 RESTful API。您将学习如何使用 Laravel 框架的核心元素构建 RESTful API - 控制器，路由和 eloquent 对象关系映射（ORM）。我们还展示了我们正在构建的应用程序的一些基本线框。此外，我们将更仔细地研究一些您需要熟悉的关系，例如一对一，一对多和多对多。

第六章，“使用 Laravel 创建 RESTful API - 第 2 部分”，继续我们构建示例 API 的项目，尽管在那时，我们在 Laravel 中仍有很长的路要走。我们将学习如何使用一些在 Web 应用程序中非常常见的功能，例如基于令牌的身份验证，请求验证和自定义错误消息；我们还将看到如何使用 Laravel 资源。此外，我们将看到如何使用 Swagger 文档来测试我们的 API。

第七章，“使用 Angular CLI 创建渐进式 Web 应用程序”，涵盖了自上一个 Angular 版本以来影响 angular-cli.json 的变化。angular-cli.json 文件现在改进了对多个应用程序的支持。我们将看到如何使用*ng add*命令创建 PWA，以及如何组织我们的项目结构，以留下一个可扩展项目的单一基础。此外，我们将看到如何使用 Angular CLI 创建 service-work 和清单文件。

第八章，“处理 Angular 路由器和组件”，是单页应用程序（SPA）中最重要的部分之一，即路由的使用。幸运的是，Angular 框架提供了一个强大的工具来处理应用程序路由：@angular/router 依赖项。在本章中，我们将学习如何使用其中一些功能，例如路由器出口和子视图，以及如何创建主细节页面。此外，我们将开始创建前端视图。

第九章，“创建服务和用户身份验证”，我们将创建许多新东西，并进行一些重构以记忆重要细节。这是以常规和渐进的方式学习新知识的好方法。此外，我们将深入研究 Angular 框架的 HTTP 模块的操作和使用，现在称为 httpClient。此外，我们将研究拦截器，处理错误，使用授权标头以及如何使用 r*oute guards*来保护应用程序路由。

第十章，“使用 Bootstrap 4 和 NgBootstrap 创建前端视图”，解释了如何使用 Angular CLI 的新*ng add*命令在运行中的 Angular 应用程序中包含 Bootstrap CSS 框架和 NgBootstrap 组件。此外，我们将看到如何将我们的 Angular 服务与组件连接起来，以及如何使用后端 API 将它们整合在一起。我们将学习在后端 API 上配置 CORS，以及如何在我们的 Angular 客户端应用程序中使用它。我们还将学习处理 Angular 管道，模板驱动表单，模型驱动表单和表单验证。

第十一章，*构建和部署 Angular 测试*，介绍了如何安装、自定义和扩展 Bootstrap CSS 框架，以及如何使用 NgBootstrap 组件以及如何将 Angular 服务与组件和 UI 界面连接。我们将学习编写 Angular 单元测试，配置应用程序的 linter（用于 SCSS 和 Tslint）以保持代码一致性，创建 NPM 脚本，以及创建 Docker 镜像并部署应用程序。

# 充分利用本书

一些命令行、Docker 和 MySQL 的知识将非常有帮助；但是，这并非完全必需，因为所有命令和示例都附有简要说明。

您需要在您的计算机上安装以下工具：

+   Node.js 和 NPM

+   Docker

+   代码编辑器——我们建议您使用 Visual Studio Code

+   推荐使用 Git 源代码控制，但不是必需的

# 下载示例代码文件

您可以从您在[www.packtpub.com](http://www.packtpub.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了这本书，您可以访问[www.packtpub.com/support](http://www.packtpub.com/support)并注册，以便文件直接通过电子邮件发送给您。

您可以按照以下步骤下载代码文件：

1.  在[www.packtpub.com](http://www.packtpub.com/support)上登录或注册。

1.  选择“支持”选项卡。

1.  点击“代码下载和勘误表”。

1.  在搜索框中输入书名，然后按照屏幕上的说明操作。

文件下载后，请确保使用最新版本的以下工具解压或提取文件夹：

+   Windows 上的 WinRAR/7-Zip

+   Mac 上的 Zipeg/iZip/UnRarX

+   Linux 上的 7-Zip/PeaZip

本书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Hands-On-Full-Stack-Web-Development-with-Angular-6-and-Laravel-5`](https://github.com/PacktPublishing/Hands-On-Full-Stack-Web-Development-with-Angular-6-and-Laravel-5)。如果代码有更新，将在现有的 GitHub 存储库中进行更新。

我们还有来自我们丰富书籍和视频目录的其他代码包，可在**[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)**上找到。去看看吧！

# 下载彩色图像

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图像。您可以在这里下载它[`www.packtpub.com/sites/default/files/downloads/HandsOnFullStackWebDevelopmentwithAngular6andLaravel5_ColorImages.pdf`](https://www.packtpub.com/sites/default/files/downloads/HandsOnFullStackWebDevelopmentwithAngular6andLaravel5_ColorImages.pdf)。

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。这里

这是一个例子：“所有使用 Composer 的 PHP 项目在根项目中都有一个名为`composer.json`的文件。”

代码块设置如下：

```php
{
 "require": {
     "laravel/framework": "5.*.*",
 }
}
```

任何命令行输入或输出都是这样写的：

```php
composer create-project --prefer-dist laravel/laravel chapter-01
```

**粗体**：表示新术语、重要单词或屏幕上看到的单词。例如，菜单或对话框中的单词会以这样的形式出现在文本中。这是一个例子：“

“搜索`chapter-01`文件夹，然后点击打开。”

警告或重要说明会出现在这样。提示和技巧会出现在这样。


# 第一章：理解 Laravel 5 的核心概念

正如本章的标题所暗示的，我们将提供 Laravel 框架的概述，涵盖与使用 Web 服务架构开发 Web 应用程序相关的主要概念。更确切地说，我们将在本书中使用 RESTful 架构。

我们假设您已经对 RESTful 架构以及 Web 服务（这里我们称之为**应用程序编程接口**（**API**）端点）的工作原理有基本了解。

但是，如果您对这个概念还很陌生，不用担心。我们将帮助您入门。

Laravel 框架将是一个有用的工具，因为使用它，我们控制器中的所有数据将默认转换为 JSON 格式。

Laravel 框架是开发 Web 应用程序的强大工具，使用“约定优于配置”的范式。 Laravel 开箱即用具有构建现代 Web 应用程序所需的所有功能，使用**模型视图控制器**（**MVC**）。此外，Laravel 框架是当今最受欢迎的 PHP 框架之一，用于开发 Web 应用程序。

从现在到本书结束，我们将简称 Laravel 框架为 Laravel。

Laravel 生态系统绝对令人难以置信。诸如 Homestead、Valet、Lumen 和 Spark 之类的工具进一步丰富了使用 PHP 进行 Web 软件开发的体验。

有许多方法可以使用 Laravel 开始开发 Web 应用程序，这意味着有许多方法可以配置您的本地环境或生产服务器。本章不偏向任何特定方式；我们理解每个开发人员随着时间的推移都有自己的偏好。

无论您对工具、服务器、虚拟机、数据库等有何偏好，我们将专注于主要概念，并不假设某种方式是对还是错。本章仅用于说明主要概念和需要执行的操作。

请记住，无论您选择哪种方法（使用 Homestead、WAMP、MAMP 或 Docker），Laravel 都有一些极其必要的依赖项（或服务器要求），这对于开发 Web 应用程序非常重要。

您可以在官方 Laravel 文档中找到更多有用的信息：[`laravel.com/docs/5.6`](https://laravel.com/docs/5.6)。

在本章中，我们将涵盖以下内容：

+   搭建环境

+   Laravel 应用程序的基本架构

+   Laravel 应用程序生命周期

+   Artisan CLI

+   MVC 和路由

+   与数据库连接

# 搭建环境

请记住，无论您如何配置环境来使用 PHP 和 Laravel 开发 Web 应用程序，牢记主要的服务器要求，您将能够跟随本章的示例。

需要注意的是，某些操作系统没有安装 PHP。例如 Windows 机器，这里有一些替代方案供您创建开发环境：

+   HOMESTEAD（Laravel 文档推荐）：[`laravel.com/docs/5.6/homestead`](https://laravel.com/docs/5.6/homestead)

+   MAMP: [`www.mamp.info/en/`](https://www.mamp.info/en/)

+   XAMPP：[`www.apachefriends.org/index.html`](https://www.apachefriends.org/index.html)

+   WAMP SERVER（仅适用于 Windows 操作系统）：[`www.wampserver.com/en/`](http://www.wampserver.com/en/)

+   PHPDOCKER: [`www.docker.com/what-docker`](https://www.docker.com/what-docker)

# 安装 Composer 包管理器

Laravel 使用**Composer**，这是 PHP 的依赖管理器，与 Node.js 项目的**Node Package Manager**（NPM）、Python 的 PIP 和 Ruby 的 Bundler 非常相似。让我们看看官方文档对此的说法：

“Composer 是 PHP 中的依赖管理工具。它允许您声明项目所依赖的库，并将为您管理（安装/更新）它们。”

因此，让我们按照以下步骤安装 Composer：

转到[`getcomposer.org/download/`](https://getcomposer.org/download/)并按照您的平台的说明进行操作。

您可以在[`getcomposer.org/doc/00-intro.md`](https://getcomposer.org/doc/00-intro.md)上获取更多信息。

请注意，您可以在本地或全局安装 Composer；现在不用担心。选择对您来说最容易的方式。

所有使用 Composer 的 PHP 项目在根项目中都有一个名为`composer.json`的文件，看起来类似于以下内容：

```php
{
 "require": {
     "laravel/framework": "5.*.*",
 }
}
```

这也与 Node.js 和 Angular 应用程序上的`package.json`文件非常相似，我们将在本书后面看到。

这是关于基本命令的有用链接：[`getcomposer.org/doc/01-basic-usage.md`](https://getcomposer.org/doc/01-basic-usage.md)

# 安装 Docker

我们将在本章中使用 Docker。尽管 Laravel 的官方文档建议使用带有虚拟机和 Vagrant 的 Homestead，但我们选择使用 Docker，因为它启动快速且易于使用，我们的主要重点是 Laravel 的核心概念。

您可以在[`www.docker.com/what-docker`](https://www.docker.com/what-docker)上找到有关 Docker 的更多信息。

根据 Docker 文档的说法：

Docker 是推动容器运动的公司，也是唯一一个能够应对混合云中的每个应用程序的容器平台提供商。今天的企业面临着数字转型的压力，但受到现有应用程序和基础设施的限制，同时需要合理化日益多样化的云、数据中心和应用程序架构组合。Docker 实现了应用程序和基础设施以及开发人员和 IT 运营之间的真正独立，释放了它们的潜力，并创造了更好的协作和创新模式。

让我们按照以下步骤安装 Docker：

1.  转到[`docs.docker.com/install/`](https://docs.docker.com/install/)。

1.  选择您的平台并按照安装步骤进行操作。

1.  如果你遇到任何问题，请查看[`docs.docker.com/get-started/`](https://docs.docker.com/get-started/)上的入门链接。

由于我们正在使用 Docker 容器和镜像来启动我们的应用程序，并且不会深入探讨 Docker 在幕后的工作原理，这里是一些 Docker 命令的简短列表：

| **命令**： | **描述**： |
| --- | --- |
| `docker ps` | 显示正在运行的容器 |
| `docker ps -a` | 显示所有容器 |
| `docker start` | 启动容器 |
| `docker stop` | 停止容器 |
| `docker-compose up -d` | 在后台启动容器 |
| `docker-compose stop` | 停止`docker-compose.yml`文件上的所有容器 |
| `docker-compose start` | 启动`docker-compose.yml`文件上的所有容器 |
| `docker-compose kill` | 杀死`docker-compose.yml`文件上的所有容器 |
| `docker-compose logs` | 记录`docker-compose.yml`文件上的所有容器 |

您可以在[`docs.docker.com/engine/reference/commandline/docker/`](https://docs.docker.com/engine/reference/commandline/docker/)上查看完整的 Docker 命令列表。以及在[`docs.docker.com/compose/reference/overview/#command-options-overview-and-help`](https://docs.docker.com/compose/reference/overview/#command-options-overview-and-help)上查看 Docker-compose 命令。

# 配置 PHPDocker.io

PHPDocker.io 是一个简单的工具，它帮助我们使用 Compose 构建 PHP 应用程序的 Docker/容器概念。它非常易于理解和使用；因此，让我们看看我们需要做什么：

1.  转到[`phpdocker.io/`](https://phpdocker.io/)。

1.  单击生成器链接。

1.  填写信息，如下截图所示。

1.  单击“生成项目存档”按钮并保存文件夹：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/hsn-flstk-web-dev-ng6-lrv5/img/0bfba06b-93cf-41eb-baa6-1162b0f4fe5d.png)PHPDocker 界面

数据库配置如下截图所示：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/hsn-flstk-web-dev-ng6-lrv5/img/3d363633-a23b-4ed5-a8cf-d49b15f3eea7.png)数据库配置请注意，我们在前面的配置中使用了 MYSQL 数据库的最新版本，但您可以选择任何您喜欢的版本。在接下来的示例中，数据库版本将不重要。

# 设置 PHPDocker 和 Laravel

既然我们已经填写了之前的信息并为我们的机器下载了文件，让我们开始设置我们的应用程序，以便更深入地了解 Laravel 应用程序的目录结构。

执行以下步骤：

1.  打开`bash/Terminal/cmd`。

1.  在 Mac 和 Linux 上转到`Users/yourname`，或者在 Windows 上转到`C:/`。

1.  在文件夹内打开您的终端并输入以下命令：

```php
composer create-project --prefer-dist laravel/laravel chapter-01
```

在您的终端窗口底部，您将看到以下结果：

```php
Writing lock file Generating autoload files > Illuminate\Foundation\ComposerScripts::postUpdate > php artisan optimize Generating optimized class loader
php artisan key:generate
```

1.  在终端窗口中，输入：

```php
cd chapter-01 && ls
```

结果将如下所示：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/hsn-flstk-web-dev-ng6-lrv5/img/460a8a5e-ccea-4297-8b42-84a7d4ce6066.png)终端窗口输出

恭喜！您有了您的第一个 Laravel 应用程序，使用了`Composer`包管理器构建。

现在，是时候将我们的应用程序与从 PHPDocker（我们的 PHP/MySQL Docker 截图）下载的文件连接起来了。要做到这一点，请按照以下步骤进行操作。

1.  获取下载的存档`hands-on-full-stack-web-development-with-angular-6-and-laravel-5.zip`，并解压缩它。

1.  复制所有文件夹内容（一个`phpdocker`文件夹和一个名为`docker-compose.yml`的文件）。

1.  打开`chapter-01`文件夹并粘贴内容。

现在，在`chapter-01`文件夹内，我们将看到以下文件：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/hsn-flstk-web-dev-ng6-lrv5/img/002f2cd2-0736-445b-a096-510ba7b07fba.png)chapter-01 文件夹结构

让我们检查一下，确保一切都会顺利进行我们的配置。

1.  打开您的终端窗口并输入以下命令：

```php
docker-compose up -d
```

重要的是要记住，在这一点上，您需要在您的机器上启动和运行 Docker。如果您完全不知道如何在您的机器上运行 Docker，您可以在[`github.com/docker/labs/tree/master/beginner/`](https://github.com/docker/labs/tree/master/beginner/)找到更多信息。

1.  请注意，此命令可能需要更多时间来创建和构建所有的容器。结果将如下所示：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/hsn-flstk-web-dev-ng6-lrv5/img/d7931a7a-4c40-47eb-9e03-b8d66cb23a7e.png)Docker 容器已启动

前面的截图表明我们已成功启动了所有容器：`memcached`，`webserver`（Nginx），`mysql`和`php-fpm`。

打开您的浏览器并输入`http://localhost:8081`；您应该看到 Laravel 的欢迎页面。

此时，是时候在文本编辑器中打开我们的示例项目，并检查所有的 Laravel 文件夹和文件。您可以选择您习惯使用的编辑器，或者，如果您愿意，您可以使用我们将在下一节中描述的编辑器。

# 安装 VS Code 文本编辑器

在本章和整本书中，我们将使用**Visual Studio Code**（**VS Code**），这是一个免费且高度可配置的多平台文本编辑器。它也非常适用于在 Angular 和 TypeScript 项目中使用。

按照以下步骤安装 VS Code：

1.  转到下载页面，并在[`code.visualstudio.com/Download`](https://code.visualstudio.com/Download)选择您的平台。

1.  按照您的平台的安装步骤进行操作。

VS Code 拥有一个充满活力的社区，有大量的扩展。您可以在[`marketplace.visualstudio.com/VSCode`](https://marketplace.visualstudio.com/VSCode)上研究并找到扩展。在接下来的章节中，我们将安装并使用其中一些扩展。

现在，只需从[`marketplace.visualstudio.com/items?itemName=robertohuertasm.vscode-icons`](https://marketplace.visualstudio.com/items?itemName=robertohuertasm.vscode-icons)安装 VS Code 图标。

# Laravel 应用程序的基本架构

正如之前提到的，Laravel 是用于开发现代 Web 应用程序的 MVC 框架。它是一种软件架构标准，将信息的表示与用户对其的交互分开。它采用的架构标准并不是很新；它自上世纪 70 年代中期以来就一直存在。它仍然很流行，许多框架今天仍在使用它。 

您可以在[`en.wikipedia.org/wiki/Model-view-controller`](https://en.wikipedia.org/wiki/Model-view-controller)中了解更多关于 MVC 模式的信息。

# Laravel 目录结构

现在，让我们看看如何在 Laravel 应用程序中实现这种模式：

1.  打开 VS Code 编辑器。

1.  如果这是您第一次打开 VS Code，请点击顶部菜单，然后导航到文件 | 打开。

1.  搜索`chapter-01`文件夹，并点击打开**。**

1.  在 VS Code 的左侧展开`app`文件夹。

应用程序文件如下：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/hsn-flstk-web-dev-ng6-lrv5/img/f0eff070-8dd1-4a97-8c20-710ab5b5afc5.png)Laravel 根文件夹`phpdocker`文件夹和`docker-compose.yml`文件不是 Laravel 框架的一部分；我们在本章的前面手动添加了这些文件。

# MVC 流程

在一个非常基本的 MVC 工作流中，当用户与我们的应用程序交互时，将执行以下截图中的步骤。想象一个简单的关于书籍的 Web 应用程序，有一个搜索输入框。当用户输入书名并按下*Enter*时，将发生以下流程循环：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/hsn-flstk-web-dev-ng6-lrv5/img/1bf73eab-92c2-4a84-978c-c5fae90f9155.png)MVC 流程

MVC 由以下文件夹和文件表示：

| **MVC 架构** | **应用程序路径** |  | **文件** |
| --- | --- | --- | --- |
| 模型 | `app/` |  | `User.php` |
| 视图 | `resources/views` |  | `welcome.blade.php` |
| 控制器 | `app/Http/Controllers` |  | `Auth/AuthController.php` `Auth/PasswordController.php` |

请注意，应用程序模型位于`app`文件夹的根目录，并且应用程序已经至少有一个文件用于 MVC 实现。

还要注意，`app`文件夹包含我们应用程序的所有核心文件。其他文件夹的名称非常直观，例如以下内容：

| 引导 | 缓存，自动加载和引导应用程序 |
| --- | --- |
| 配置 | 应用程序配置 |
| 数据库 | 工厂，迁移和种子 |
| 公共 | JavaScript，CSS，字体和图像 |
| 资源 | 视图，SASS/LESS 和本地化 |
| 存储 | 此文件夹包含分离的应用程序，框架和日志 |
| 测试 | 使用 PHPunit 进行单元测试 |
| 供应商 | Composer 依赖项 |

现在，让我们看看 Laravel 结构是如何工作的。

# Laravel 应用程序生命周期

在 Laravel 应用程序中，流程与前面的示例几乎相同，但稍微复杂一些。当用户在浏览器中触发事件时，请求到达 Web 服务器（Apache/Nginx），我们的 Web 应用程序在那里运行。因此，服务器将请求重定向到`public/index.php`，整个框架的起点。在`bootstrap`文件夹中，启动`autoloader.php`并加载由 composer 生成的所有文件，检索 Laravel 应用程序的实例。

让我们看一下以下的截图：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/hsn-flstk-web-dev-ng6-lrv5/img/cb7f983b-d19f-46a1-b284-0c317a4c3ee8.png)Laravel 应用程序生命周期

该图表对于我们的第一章来说已经足够复杂了，因此我们不会详细介绍用户请求执行的所有步骤。相反，我们将继续介绍 Laravel 中的另一个非常重要的特性，即 Artisan **命令行界面（CLI）**。

您可以在官方文档的[`laravel.com/docs/5.2/lifecycle`](https://laravel.com/docs/5.2/lifecycle)中了解更多关于 Laravel 请求生命周期的信息。

# Artisan 命令行界面

现在，通过使用命令行创建 Web 应用程序是一种常见的做法；随着 Web 开发工具和技术的发展，这变得非常流行。

我们将提到 NPM 是最受欢迎的之一。但是，对于使用 Laravel 开发应用程序，我们有一个优势。当我们创建 Laravel 项目时，Artisan CLI 会自动安装。

让我们看看 Laravel 官方文档对 Artisan CLI 的说法：

Artisan 是 Laravel 附带的命令行界面的名称。它为您在开发应用程序时使用的一些有用的命令提供了帮助。

在`chapter-01`文件夹中，我们找到了 Artisan bash 文件。它负责在 CLI 上运行所有可用的命令，其中有许多命令，用于创建类、控制器、种子等等。

在对 Artisan CLI 进行了简要介绍之后，最好的事情莫过于看一些实际的例子。所以，让我们动手操作，不要忘记启动 Docker：

1.  在`chapter-01`文件夹中打开您的终端窗口，并键入以下命令：

```php
docker-compose up -d
```

1.  让我们进入`php-fpm 容器`并键入以下内容：

```php
docker-compose exec php-fpm bash
```

现在我们在终端中有所有 Artisan CLI 命令可用。

这是与我们的 Docker 容器内的 Teminal 进行交互的最简单方式。如果您正在使用其他技术来运行 Laravel 应用程序，正如本章开头所提到的，您不需要使用以下命令：

```php
docker-compose exec php-fpm bash
```

您可以在终端中键入下一步的相同命令。

1.  仍然在终端中，键入以下命令：

```php
php artisan list
```

你将看到框架版本和所有可用命令的列表：

```php
Laravel Framework version 5.2.45
Usage:
 command [options] [arguments]
Options:
 -h, --help            Display this help message
 -q, --quiet           Do not output any message
 -V, --version         Display this application version
 --ansi            Force ANSI output
 --no-ansi         Disable ANSI output
 -n, --no-interaction  Do not ask any interactive question
 --env[=ENV]       The environment the command should run under.
 -v|vv|vvv, --verbose  Increase the verbosity of messages: 1 for normal output, 2 for more verbose output and 3 for debug
...
```

正如您所看到的，命令列表非常长。请注意，上面的代码片段中，我们没有列出`php artisan list`命令的所有选项，但我们将在下面看到一些组合。

1.  在您的终端中，键入以下组合：

```php
php artisan -h migrate
```

输出将详细解释`migrate`命令可以做什么以及我们有哪些选项，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/hsn-flstk-web-dev-ng6-lrv5/img/81c6afbf-151a-4ae5-80f1-f7871a674726.png)输出 php artisan -h migrate

也可以看到我们对`migrate`命令有哪些选项。

1.  仍然在终端中，键入以下命令：

```php
php artisan -h make:controller
```

您将看到以下输出：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/hsn-flstk-web-dev-ng6-lrv5/img/62d6573a-0b93-4cce-acd0-6e1fd7526b49.png)输出 php artisan -h make:controller

现在，让我们看看如何在 Laravel 应用程序中使用 Artisan CLI 创建 MVC。

# MVC 和路由

如前所述，我们现在将使用 Artisan CLI 分别创建模型、视图和控制器。但是，正如我们的标题所暗示的，我们将包括另一个重要项目：路由。我们已经在本章中提到过它们（在我们的 Laravel 请求生命周期图表中，以及在 MVC 本身的示例图表中）。

在本节中，我们将专注于创建文件，并在创建后检查它。

# 创建模型

让我们动手操作：

1.  在`chapter-01`文件夹中打开您的终端窗口，并键入以下命令：

```php
php artisan make:model Band
```

在命令之后，您应该看到一个绿色的成功消息，指出：模型成功创建。

1.  返回到您的代码编辑器；在`app`文件夹中，您将看到`Band.php`文件，其中包含以下代码：

```php
<?php
namespace App;
use Illuminate\Database\Eloquent\Model;
class Band extends Model
{
    //
}
```

# 创建控制器

现在是使用 artisan 生成我们的控制器的时候了，让我们看看我们可以如何做到：

1.  返回到终端窗口，并键入以下命令：

```php
php artisan make:controller BandController 
```

在命令之后，您应该看到一个绿色的消息，指出：控制器成功创建。

1.  现在，在`app/Http/Controllers`中，您将看到`BandController.php`，其中包含以下内容：

```php
<?php
namespace App\Http\Controllers;
use Illuminate\Http\Request;
use App\Http\Requests;
class BandController extends Controller
{
    //
}
```

作为一个良好的实践，始终使用后缀`<Somename>Controller`创建您的控制器。

# 创建视图

正如我们之前在使用`php artisan list`命令时所看到的，我们没有任何别名命令可以自动创建应用程序视图。因此，我们需要手动创建视图：

1.  返回到您的文本编辑器，并在`resources/views`文件夹中创建一个名为`band.blade.php`的新文件。

1.  将以下代码放入`band.blade.php`文件中：

```php
<div class="container">
    <div class="content">
        <div class="title">Hi i'm a view</div>
    </div>
</div>
```

# 创建路由

Laravel 中的路由负责指导来自用户请求的所有 HTTP 流量，因此路由负责 Laravel 应用程序中的整个流入，正如我们在前面的图表中看到的那样。

在本节中，我们将简要介绍 Laravel 中可用的路由类型，以及如何为我们的 MVC 组件创建一个简单的路由。

在这一点上，只需要看一下路由是如何工作的。在本书的后面，我们将深入研究应用程序路由。

因此，让我们看看在 Laravel 中可以用来处理路由的内容：

| 代码 | HTTP &#124; 方法 &#124;动词 |
| --- | --- |
| `Route::get($uri, $callback);` | 获取 |
| `Route::post($uri, $callback);` | 发布 |
| 路由::放置（$uri，$callback）; | 放置 |
| `Route::patch($uri, $callback);` | 补丁 |
| `Route::delete($uri, $callback);` | 删除 |
| `Route::options($uri, $callback);` | 选项 |

每个可用的路由都负责处理一种类型的 HTTP 请求方法。此外，我们可以在同一个路由中组合多种方法，就像下面的代码一样。现在不要太担心这个问题；我们将在本书的后面看到如何处理这种类型的路由：

```php
Route::match(['get', 'post'], '/', function () {
    //
});
```

现在，让我们创建我们的第一个路由：

1.  在文本编辑器中，打开`routes`文件夹中的`web.php`，并在`welcome view`之后添加以下代码：

```php
Route::get('/band', function () {
 return view('band');
 });
```

1.  在浏览器中打开`http://localhost:8081/band`，您将看到以下消息：

嗨，我是一个视图

不要忘记使用`docker-compose up -d`命令启动所有 Docker 容器。如果您遵循了前面的示例，您将已经拥有一切都在正常运行。

太棒了！我们已经创建了我们的第一个路由。这是一个简单的例子，但我们已经把所有东西都放在了正确的位置，并且一切都运行良好。在下一节中，我们将看看如何将模型与控制器集成并呈现视图。

# 连接到数据库

正如我们之前所看到的，控制器由路由激活，并在模型/数据库和视图之间传递信息。在前面的示例中，我们在视图中使用静态内容，但在更大的应用程序中，我们几乎总是会有来自数据库的内容，或者在控制器内生成并传递给视图的内容。

在下一个示例中，我们将看到如何做到这一点。

# 在 Docker 容器内设置数据库

现在是时候配置我们的数据库了。如果您使用 Homestead，您可能已经配置并且数据库连接正常工作。要检查，请打开终端并输入以下命令：

```php
php artisan tinker
DB::connection()->getPdo();
```

如果一切顺利，您将看到以下消息：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/hsn-flstk-web-dev-ng6-lrv5/img/993a52c8-b364-46ff-9cb1-aa0283760ff7.png)数据库连接消息

然而，对于这个例子，我们正在使用 Docker，我们需要做一些配置来完成这个任务：

1.  在根项目内，打开`.env`文件并查看第 8 行（数据库连接），如下所示：

```php
 DB_CONNECTION=mysql
 DB_HOST=127.0.0.1
 DB_PORT=3306
 DB_DATABASE=homestead
 DB_USERNAME=homestead
 DB_PASSWORD=secret
```

现在，用以下行替换前面的代码：

```php
 DB_CONNECTION=mysql
 DB_HOST=mysql
 DB_PORT=3306
 DB_DATABASE=laravel-angular-book
 DB_USERNAME=laravel-angular-book
 DB_PASSWORD=123456
```

请注意，我们需要稍微更改一下以获取 Docker MySQL 容器的指示；如果您不记得在`PHPDocker.io`生成器中选择了什么，可以从容器配置中复制它。

1.  在根目录打开`docker-compose.yml`。

1.  从 MySQL 容器设置中复制环境变量：

```php
mysql:
  image: mysql:8.0
  entrypoint: ['/entrypoint.sh', '--character-set-server=utf8', '--
  collation-server=utf8_general_ci']
  container_name: larahell-mysql
  working_dir: /application
  volumes:
    - .:/application
  environment:
    - MYSQL_ROOT_PASSWORD=larahell
    - MYSQL_DATABASE=larahell-angular-book
    - MYSQL_USER=larahell-user
    - MYSQL_PASSWORD=123456
  ports:
    - "8083:3306"
```

现在是时候测试我们的连接了。

1.  在您的终端窗口中，输入以下命令：

```php
docker-compose exec php-fpm bash
```

1.  最后，让我们检查一下我们的连接；输入以下命令：

```php
php artisan tinker DB::connection()->getPdo();
```

您应该看到与上一个截图相同的消息。然后，您将拥有继续进行示例所需的一切。

# 创建迁移文件和数据库种子

**迁移**文件在一些 MVC 框架中非常常见，例如 Rails，Django 和当然，Laravel。通过这种类型的文件，我们可以使我们的数据库与我们的应用程序保持一致，因为我们无法对数据库方案进行版本控制。迁移文件帮助我们存储数据库中的每个更改，以便我们可以对这些文件进行版本控制，并保持项目的一致性。

**数据库种子**用于在数据库的表中填充一批初始记录；当我们从头开始开发 Web 应用程序时，这非常有用。初始加载的数据可以是各种各样的，从用户表到管理对象，如密码和令牌，以及我们需要的其他所有内容。

让我们看看如何在 Laravel 中为`Bands`模型创建迁移文件：

1.  打开您的终端窗口并输入以下命令：

```php
php artisan make:migration create_bands_table
```

1.  打开`database/migrations`文件夹，您将看到一个名为`<timestamp>create_bands_table.php`的文件。

1.  打开此文件，并在`public function up()`中粘贴以下代码：

```php
Schema::create('bands', function (Blueprint $table) {
   $table->increments('id');
   $table->string('name');
   $table->string('description');
   $table->timestamps();
});
```

1.  将以下代码粘贴到`public function down()`中：

```php
Schema::dropIfExists('bands');
```

1.  最终结果将是以下代码：

```php
<?php
use Illuminate\Support\Facades\Schema;
 use Illuminate\Database\Schema\Blueprint;
 use Illuminate\Database\Migrations\Migration;
class CreateBandsTable extends Migration
 {
     /**
     * Run the migrations.
     *
     * @return void
    */
     public function up()
     {
         Schema::create('bands', function (Blueprint $table) {
         $table->increments('id');
         $table->string('name');
         $table->string('description');
         $table->timestamps();
         });
     }
    /**
     * Reverse the migrations.
     *
     * @return void
     */
     public function down()
     {
         Schema::dropIfExists('bands');
     }
 }
```

1.  在`database/factories`文件夹中，打开`ModalFactory.php`文件，并在`User Factory`之后添加以下代码。请注意，我们在`factory`函数中使用了一个名为`faker`的 PHP 库，以生成一些数据：

```php
$factory->define(App\Band::class, function (Faker\Generator $faker) {
return [
 'name' => $faker->word,
 'description' => $faker->sentence
 ];
 });
```

1.  返回到您的终端窗口并创建一个数据库种子。要做到这一点，请输入以下命令：

```php
php artisan make:seeder BandsTableSeeder
```

1.  在`database/seeds`文件夹中，打开`BandsTableSeeder.php`文件，并在`public function run()`中输入以下代码：

```php
factory(App\Band::class,5)->create()->each(function ($p) {
 $p->save();
 });
```

1.  现在，在`database/seeds`文件夹中，打开`DatabaseSeeder.php`文件，并在`public function run()`中添加以下代码：

```php
$this->call(BandsTableSeeder::class);
```

您可以在[`github.com/fzaninotto/Faker`](https://github.com/fzaninotto/Faker)上阅读更多关于 Faker PHP 的信息。

在我们继续之前，我们需要对`Band`模型进行一些小的重构。

1.  在应用程序根目录中，打开`Band.php`文件并在`Band`类中添加以下代码：

```php
protected $fillable = ['name','description'];
```

1.  返回到您的终端并输入以下命令：

```php
php artisan migrate
```

在命令之后，您将在终端窗口中看到以下消息：

```php
 Migration table created successfully.
```

前面的命令只是用来填充我们的种子数据库。

1.  返回到您的终端并输入以下命令：

```php
php artisan db:seed
```

我们现在有五个项目可以在我们的数据库中使用。

让我们看看一切是否会顺利进行。

1.  在您的终端中，要退出`php-fpm 容器`，请输入以下命令：

```php
exit
```

1.  现在，在应用程序根文件夹中，在终端中输入以下命令：

```php
docker-compose exec mysql mysql -ularavel-angular-book -p123456
```

前面的命令将使您可以在`mysql Docker 容器`中访问 MySQL 控制台，几乎与我们如何访问`php-fpm 容器`相同。

1.  在终端中，输入以下命令以查看所有数据库：

```php
show databases;
```

如您所见，我们有两个表：`information_schema`和`laravel-angular-book`。

1.  让我们访问`laravel-angular-book`表；输入以下命令：

```php
use laravel-angular-book;
```

1.  现在，让我们检查我们的表，如下所示：

```php
show tables;
```

1.  现在，让我们从`bands`表中`SELECT`所有记录：

```php
SELECT * from bands;
```

我们将看到类似以下截图的内容：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/hsn-flstk-web-dev-ng6-lrv5/img/6aa9f6e1-dbe6-4289-87db-c7c57e97568b.png)数据库 bands 表

1.  现在，使用以下命令退出 MySQL 控制台：

```php
exit
```

# 使用资源标志创建 CRUD 方法

让我们看看 Artisan CLI 的另一个功能，使用单个命令创建所有的**创建**、**读取**、**更新**和**删除**（CRUD）操作。

首先，在`app/Http/Controllers`文件夹中，删除`BandController.php`文件：

1.  打开您的终端窗口并输入以下命令：

```php
php artisan make:controller BandController --resource
```

这个动作将再次创建相同的文件，但现在它包括 CRUD 操作，如下面的代码所示：

```php
<?php
namespace App\Http\Controllers;
use Illuminate\Http\Request;
class BandController extends Controller
 {
     /**
     * Display a listing of the resource.
     *
     * @return \Illuminate\Http\Response
     */
     public function index()
     {
         //
     }
    /**
     * Show the form for creating a new resource.
     *
     * @return \Illuminate\Http\Response
     */
     public function create()
     {
         //
     }
    /**
     * Store a newly created resource in storage.
     *
     * @param \Illuminate\Http\Request $request
     * @return \Illuminate\Http\Response
     */
     public function store(Request $request)
     {
         //
     }
    /**
     * Display the specified resource.
     *
     * @param int $id
     * @return \Illuminate\Http\Response
     */
     public function show($id)
     {
         //
     }
    /**
     * Show the form for editing the specified resource.
     *
     * @param int $id
     * @return \Illuminate\Http\Response
     */
     public function edit($id)
     {
         //
     }
    /**
     * Update the specified resource in storage.
     *
     * @param \Illuminate\Http\Request $request
     * @param int $id
     * @return \Illuminate\Http\Response
     */
     public function update(Request $request, $id)
     {
         //
     }
    /**
     * Remove the specified resource from storage.
     *
     * @param int $id
     * @return \Illuminate\Http\Response
     */
     public function destroy($id)
     {
         //
     }
 }
```

在这个例子中，我们将只编写两种方法：一种用于列出所有记录，另一种用于获取特定记录。不要担心其他方法；我们将在接下来的章节中涵盖所有方法。

1.  编辑`public function index()`并添加以下代码：

```php
$bands = Band::all();
 return $bands;
```

1.  现在，编辑`public function show()`并添加以下代码：

```php
$band = Band::find($id);
 return view('bands.show', array('band' => $band));
```

1.  在`App\Http\Requests`之后添加以下行：

```php
use App\Band;
```

1.  更新`routes.php`文件，将其更改为以下代码：

```php
Route::get('/', function () {
 return view('welcome');
 });
Route::resource('bands', 'BandController');
```

1.  打开浏览器，转到`http://localhost:8081/bands`，您将看到以下内容：

```php
[{
  "id": 1,
  "name": "porro",
  "description": "Minus sapiente ut libero explicabo et voluptas harum.",
  "created_at": "2018-03-02 19:20:58",
  "updated_at": "2018-03-02 19:20:58"}
...]
```

如果你的数据与之前的代码不同，不要担心；这是由于 Faker 生成了随机数据。请注意，我们直接将 JSON 返回给浏览器，而不是将数据返回给视图。这是 Laravel 的一个非常重要的特性；它默认序列化和反序列化数据。

# 创建刀片模板引擎

现在，是时候创建另一个视图组件了。这一次，我们将使用刀片模板引擎来显示数据库中的一些记录。让我们看看官方文档对刀片的说法：

<q>刀片是 Laravel 提供的简单而强大的模板引擎。与其他流行的 PHP 模板引擎不同，刀片不限制您在视图中使用纯 PHP 代码。所有刀片视图都会被编译成纯 PHP 代码并缓存，直到被修改，这意味着刀片对您的应用基本上没有额外开销。</q>

现在，是时候看到这个行为的实际效果了：

1.  返回到代码编辑器，在`resources/views`内创建一个名为`bands`的文件夹。

1.  在`resources/views/bands`内创建一个名为`show.blade.php`的文件，并将以下代码放入其中：

```php
<h1>Band {{ $band->id }}</h1>
<ul>
<li>band: {{ $band->name }}</li>
<li>description: {{ $band->description }}</li>
</ul>
```

你可以在[`laravel.com/docs/5.2/blade`](https://laravel.com/docs/5.2/blade)了解更多关于刀片的信息。

1.  在浏览器中打开`http://localhost:8081/bands/1`。你会看到模板在运行中，结果类似以下：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/hsn-flstk-web-dev-ng6-lrv5/img/88d7abed-5777-4c77-9327-8a4d51b376b6.png)模板引擎的视图

请注意，这里我们使用刀片模板引擎来显示数据库中的记录。现在，让我们创建另一个视图来渲染所有的记录。

1.  在`resources/views/bands`内创建一个名为`index.blade.php`的文件，并将以下代码放入其中：

```php
@foreach ($bands as $band)
<h1>Band id: {{ $band->id }}</h1>
<h2>Band name: {{ $band->name }}</h2>
<p>Band Description: {{ $band->description }}</p>
@endforeach
```

1.  返回到你的浏览器，访问`http://localhost:8081/bands/`，你会看到类似以下的结果：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/hsn-flstk-web-dev-ng6-lrv5/img/0e5fd10e-9e6a-492e-8aee-6b1f25f78916.png)视图模板引擎

# 总结

我们终于完成了第一章，并涵盖了 Laravel 框架的许多核心概念。即使在本章讨论的简单示例中，我们也为 Laravel 的所有功能提供了相关的基础。只凭这些知识就可以创建令人难以置信的应用。但是，我们打算深入探讨一些值得单独章节的概念。在整本书中，我们将使用 RESTful API、Angular 和一些其他工具创建一个完整的应用，比如 TypeScript，我们将在下一章中讨论。


# 第二章：TypeScript 的好处

TypeScript 使您能够编写 JavaScript 代码。它包括静态类型和其他在面向对象语言中非常常见的特性。此外，使用 TypeScript，您可以使用 ECMAScript 6 的所有特性，因为编译器将它们转换为当前浏览器可读的代码。

TypeScript 的一个特性是用户可以创建类型化的变量，就像在 Java 或 C#中一样（例如，`const VARIABLE_NAME: Type = Value`），不仅如此，TypeScript 还帮助我们编写干净、组织良好的代码。这就是为什么 Angular 团队为当前版本的框架采用了 TypeScript 的原因之一。

在开始之前，让我们看一下官方 TypeScript 文档中的内容：

"TypeScript 是 JavaScript 的一种有类型的超集，可以编译为普通的 JavaScript。

任何浏览器。任何主机。

在本章中，我们将在我们的环境中全局安装 TypeScript，以了解 TypeScript 文件在转换为 JavaScript 时会发生什么。不用担心；Angular 应用程序已经为我们提供了内置的 TypeScript 编译器。

在本章中，我们将涵盖以下内容：

+   安装 TypeScript

+   使用 TypeScript 的好处

+   如何将 TypeScript 文件转译为 JavaScript 文件

+   使用静态类型编写 JavaScript 代码

+   理解 TypeScript 中的接口、类和泛型

# 安装 TypeScript

安装和开始使用 TypeScript 非常简单。您的机器上必须安装 Node.js 和 Node 包管理器（NPM）。

如果您还没有它们，请前往[`nodejs.org/en/download/`](https://nodejs.org/en/download/)，并按照您的平台的逐步安装说明进行操作。

让我们按照以下步骤安装 TypeScript：

1.  打开终端并输入以下命令以安装 TypeScript 编译器：

```php
npm install -g typescript
```

请注意，`-g`标志表示在您的机器上全局安装编译器。

1.  让我们检查一下可用的 TypeScript 命令。在终端中输入以下命令：

```php
tsc --help
```

上述命令将提供有关 TypeScript 编译器的大量信息；我们将看到一个简单的示例，演示如何将 TypeScript 文件转译为 JavaScript 文件。

示例：

` tsc hello.ts`

` tsc --outFile file.js file.ts`

前面几行的描述如下：

+   `tsc`命令编译`hello.ts`文件。

+   告诉编译器创建一个名为`hello.js`的输出文件。

# 创建一个 TypeScript 项目

一些文本编辑器，如 VS Code，让我们有能力将 TS 文件作为独立单元处理，称为文件范围。尽管这对于孤立的文件（如下面的示例）非常有用，但建议您始终创建一个 TypeScript 项目。然后，您可以模块化您的代码，并在将来的文件之间使用依赖注入。

使用名为`tsconfig.json`的文件在目录的根目录创建了一个 TypeScript 项目。您需要告诉编译器哪些文件是项目的一部分，编译选项以及许多其他设置。

一个基本的`tsconfig.json`文件包含以下代码：

```php
{ "compilerOptions":
  { "target": "es5",
   "module": "commonjs"
  }
}
```

尽管前面的代码非常简单和直观，我们只是指定了我们将在项目中使用的编译器，以及使用的模块类型。如果代码片段指示我们使用 ECMAScript 5，所有 TypeScript 代码将被转换为 JavaScript，使用 ES5 语法。

现在，让我们看看如何可以借助`tsc`编译器自动创建此文件：

1.  创建一个名为`chapter-02`的文件夹。

1.  在`chapter-02`文件夹中打开您的终端。

1.  输入以下命令：

```php
tsc --init
```

我们将看到由`tsc`编译器生成的以下内容：

```php
{
"compilerOptions": {
/* Basic Options */
/* Specify ECMAScript target version: 'ES3' (default), 'ES5', 'ES2015', 'ES2016', 'ES2017','ES2018' or 'ESNEXT'. */
"target": "es5",
/* Specify module code generation: 'none', 'commonjs', 'amd', 'system', 'umd', 'es2015', or 'ESNext'. */
"module": "commonjs",
...
/* Strict Type-Checking Options */
/* Enable all strict type-checking options. */
"strict": true,
...
/* Enables emit interoperability between CommonJS and ES Modules via creation of namespace objects for all imports. Implies 'allowSyntheticDefaultImports'. */
"esModuleInterop": true
/* Source Map Options */
...
/* Experimental Options */
...
}
}
```

请注意，我们省略了一些部分。您应该看到所有可用的选项；但是，大多数选项都是被注释掉的。现在不用担心这一点；稍后，我们将更详细地查看一些选项。

现在，让我们创建一个 TypeScript 文件，并检查一切是否顺利。

1.  在`chapter-02`文件夹中打开 VS Code，创建一个名为`sample-01.ts`的新文件。

1.  将以下代码添加到`sample-01.ts`中：

```php
console.log('First Sample With TypeScript');
```

1.  回到你的终端，输入以下命令：

```php
tsc sample-01.ts
```

在 VS Code 中，你可以使用集成终端；在顶部菜单栏上，点击 View | Integrate Terminal [ˆ`]。

请注意，另一个文件出现了，但扩展名是`.js`。

如果你比较这两个文件，它们完全相同，因为我们的例子非常简单，我们使用的是一个简单的`console.log()`函数。

由于 TypeScript 是 JavaScript 的超集，这里也提供了所有的 JS 功能。

# TypeScript 的好处

以下是使用 TypeScript 的好处的一个小列表：

+   TypeScript 是强大的、安全的，易于调试。

+   TypeScript 代码在转换为 JavaScript 之前被编译，因此我们可以在运行代码之前捕捉各种错误。

+   支持 TypeScript 的 IDE 具有改进代码完成和检查静态类型的能力。

+   TypeScript 支持面向对象编程（OOP），包括模块、命名空间、类等。

TypeScript 受欢迎的一个主要原因是它已经被 Angular 团队采用；而且，由于 Angular 是用于开发现代 Web 应用程序的最重要的前端框架之一，这激励了许多开发人员从 AngularJS 的 1.x 版本迁移到 2/4/5/6 版本学习它。

这是因为大多数 Angular 教程和示例都是用 TypeScript 编写的。

1.  打开`sample-01.ts`，在`console.log()`函数之后添加以下代码：

```php
class MyClass {
  public static sum(x:number, y: number) {
  console.log('Number is: ', x + y);
  return x + y;
 }
}
MyClass.sum(3, 5);
```

1.  回到你的终端，输入以下代码：

```php
tsc sample-01.ts
```

1.  现在，当你打开`sample-01.js`文件时，你会看到以下截图中显示的结果：

使用 TypeScript 与生成的 JavaScript 进行比较

请注意，sum 类参数`(x:number, y:number)`被赋予了类型 number。这是 TypeScript 的一个优点；然而，由于我们根据类型和在函数调用`MyClass.sum(3, 5)`中使用数字，我们无法看到它的强大之处。

让我们做一个小改变，看看区别。

1.  将`MyClass.sum()`函数调用更改为`MyClass.sum('a', 5)`。

1.  回到你的终端，输入以下命令：

```php
tsc sample-01.ts
```

请注意，我们收到了一个 TypeScript 错误：

```php
error TS2345: Argument of type '"a"' is not assignable to parameter of type 'number'.
```

如果你使用 VS Code，你会在执行编译文件之前看到以下截图中的消息：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/hsn-flstk-web-dev-ng6-lrv5/img/d90105da-eda8-4321-ad41-4a252b0c0842.png)编译错误消息

如前所述，VS Code 是 TypeScript 语言的强大编辑器；除了具有集成终端外，我们还能清楚地看到编译错误。

我们可以对 TS 文件进行一些修改，而不是每次都输入相同的命令。我们可以使用`--watch`标志，编译器将自动运行我们对文件所做的每一次更改。

1.  在你的终端中，输入以下命令：

```php
tsc sample-01.ts --watch
```

1.  现在，让我们修复它；回到 VS Code，用以下代码替换`MyClass.sum()`函数：

```php
MyClass.sum(5, 5);
```

要停止 TS 编译器，只需按下*Ctrl +* *C*。

# 使用静态类型编写 JavaScript 代码

在使用 TypeScript 时，你会注意到的第一件事是它的静态类型，以及下表中指示的所有 JavaScript 类型：

| **基本类型** | **对象** |
| --- | --- |
| 字符串 | 函数 |
| 数字 | 数组 |
| 空 | 原型 |
| 未定义 |  |
| 布尔 |  |
| 符号 |  |

这意味着你可以声明变量的类型；给变量分配类型非常简单。让我们看一些例子，只使用 JavaScript 类型：

```php

function Myband () {
  let band: string;
  let active: boolean;
  let numberOfAlbuns: number;
}
```

使用 TypeScript，我们有更多的类型，我们将在以下部分中看到。

# 创建一个元组

元组就像一个有组织的类型数组。让我们创建一个看看它是如何工作的：

1.  在`chapter-02`文件夹中，创建一个名为`tuple.ts`的文件，并添加以下代码：

```php
const organizedArray: [number, string, boolean] = [0, 'text',
      false];
let myArray: [number, string, boolean];
myArray = ['text', 0, false]
console.log(myArray);
```

前面的代码在 JavaScript 中看起来很好，但在 TypeScript 中，我们必须尊重变量类型；在这里，我们试图传递一个字符串，而我们必须传递一个数字。

1.  在你的终端中，输入以下命令：

```php
tsc tuple.ts
```

你将看到以下错误消息：

```php
tuple.ts(4,1): error TS2322: Type '[string, number, false]' is not assignable to type '[number, string, boolean]'.
 Type 'string' is not assignable to type 'number'.
```

在 VS Code 中，你会在编译文件之前看到错误消息。这是一个非常有用的功能。

当我们用正确的顺序修复它（`myArray = [0, 'text', false]`）时，错误消息消失了。

还可以创建一个元组类型，并将其用于分配一个变量，就像我们在下一个例子中看到的那样。

1.  返回到你的终端，并将以下代码添加到`tuple.ts`文件中：

```php
// using tuple as Type
type Tuple = [number, string, boolean];
let myTuple: Tuple;
myTuple = [0, 'text', false];
console.log(myTuple);
```

这时，你可能会想知道为什么前面的例子有`console.log`输出。

借助我们之前安装的 Node.js，我们可以运行示例并查看`console.log()`函数的输出。

1.  在终端中，输入以下命令：

```php
node tuple.js
```

请注意，你需要运行 JavaScript 版本，就像前面的例子一样。如果你尝试直接运行 TypeScript 文件，你可能会收到错误消息。

# 使用 void 类型

在 TypeScript 中，定义函数的返回类型是强制的。当我们有一个没有返回值的函数时，我们使用一个叫做`void`的类型。

让我们看看它是如何工作的：

在`chapter-02`文件夹内创建一个名为`void.ts`的新文件，并添加以下代码：

```php
function myVoidExample(firstName: string, lastName: string): string {
    return firstName + lastName;
}
console.log(myVoidExample('Jhonny ', 'Cash'));
```

在前面的代码中，一切都很好，因为我们的函数返回一个值。如果我们删除返回函数，我们将看到以下错误消息：

```php
void.ts(1,62): error TS2355: A function whose declared type is neither 'void' nor 'any' must return a value.
```

在 VS Code 中，你会看到以下内容：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/hsn-flstk-web-dev-ng6-lrv5/img/1c7652c8-7333-4dbd-a38e-9247c6f90b4a.png)VS Code 输出错误

要修复它，用`void`替换类型`string`：

```php
function myVoidExample(firstName: string, lastName: string): void {
const name = firstName + lastName;
}
```

这非常有用，因为我们的函数并不总是返回一个值。但请记住，我们不能在*返回*值的函数中声明`void`。

# 选择退出类型检查 - any

当我们不知道从函数中期望什么时（换句话说，当我们不知道我们将返回哪种类型时），`any`类型非常有用：

1.  在`chapter-02`文件夹中创建一个名为`any.ts`的新文件，并添加以下代码：

```php
let band: any;
band = {
    name: "Motorhead",
    description: "Heavy metal band",
    rate: 10
}
console.log(band);
band = "Motorhead";
console.log(band);
```

请注意，第一个`band`赋值是一个对象，而第二个是一个字符串。

1.  返回到你的终端，编译并运行这段代码；输入以下命令：

```php
tsc any.ts
```

1.  现在，让我们看一下输出。输入以下命令：

```php
node any.js
```

你将在终端看到以下消息：

```php
{ name: 'Motorhead', description: 'Heavy metal band', rate: 10 }
 Motorhead
```

在这里，我们可以将*任何东西*赋给我们的`band`变量。

# 使用枚举

`enum`允许我们使用更直观的名称对值进行分组。有些人更喜欢称枚举列表为其他名称。让我们看一个例子，以便更容易理解这在实践中是如何工作的：

1.  在`chapter-02`文件夹中创建一个名为`enum.js`的文件，并添加以下代码：

```php
enum bands {
    Motorhead,
    Metallica,
    Slayer
}
console.log(bands);
```

1.  在你的终端中，输入以下命令以转换文件：

```php
tsc enum.ts
```

1.  现在，让我们执行这个文件。输入以下命令：

```php
node enum.js
```

你将在终端看到以下结果：

```php
{ '0': 'Motorhead',
 '1': 'Metallica',
 '2': 'Slayer',
 Motorhead: 0,
 Metallica: 1,
 Slayer: 2 }
```

现在，我们可以通过名称而不是位置来获取值。

1.  在`console.log()`函数之后添加以下代码行：

```php
let myFavoriteBand = bands.Slayer;
console.log(myFavoriteBand);
```

现在，执行*步骤 2*和*步骤 3*中的命令以检查结果。你将在终端中看到以下输出：

```php
{ '0': 'Motorhead',
 '1': 'Metallica',
 '2': 'Slayer',
 Motorhead: 0,
 Metallica: 1,
 Slayer: 2 }
 My Favorite band is:  Slayer
```

请注意，`band`对象中声明的所有值（乐队名称）都被转换为字符串，放在一个索引对象中，就像你在前面的例子中看到的那样。

# 使用 never 类型

`never`类型是在 TypeScript 2.0 中引入的；它意味着永远不会发生的值。乍一看，它可能看起来很奇怪，但在某些情况下可以使用它。

让我们看看官方文档对此的解释：

`never`类型表示永远不会发生的值的类型。具体来说，`never`是永远不会返回的函数的返回类型，也是永远不会为`type`保护下的变量为真的类型。

假设在另一个函数内调用的消息传递函数指定了回调。

它看起来会像以下代码：

```php
const myMessage = (text: string): never => {
    throw new Error(text);
}
const myError = () => Error('Some text here');
```

另一个例子是检查同时是字符串和数字的值，例如以下代码：

```php
function neverHappen(someVariable: any) {
    if (typeof someVariable === "string" && typeof someVariable ===
     "number") {
    console.log(someVariable);
    }
}
neverHappen('text');
```

# 类型：未定义和空

在 TypeScript 中，`undefined`和`null`本身就是类型；这意味着 undefined 是一种类型(`undefined`)，null 是一种类型(`null`)。令人困惑？undefined 和 null 不能是类型变量；它们只能被分配为变量的值。

它们也是不同的：null 变量意味着变量被设置为 null，而 undefined 变量没有分配值。

```php
let A = null;
    console.log(A) // null
    console.log(B) // undefined
```

# 理解 TypeScript 中的接口、类和泛型

**面向对象编程**（**OOP**）是一个非常古老的编程概念，用于诸如 Java、C#和许多其他语言中。

使用 TypeScript 的优势之一是能够将其中一些概念带入您的 JavaScript Web 应用程序中。除了能够使用类、接口等，我们还可以轻松扩展导入类和导入模块，正如我们将在接下来的示例中看到的那样。

我们知道在纯 JavaScript 中使用类已经是一个选项，使用 ECMAScript 5。虽然它很相似，但也有一些区别；我们不会在本章中讨论它们，以免混淆我们的读者。我们只会专注于 TypeScript 中采用的实现。

# 创建一个类

理解 TypeScript 中的类的最佳方法是创建一个。一个简单的类看起来像以下代码：

```php
class Band {
    public name: string;
    constructor(text: string) {
    this.name = text;
    }
}
```

让我们创建我们的第一个类：

1.  打开您的文本编辑器，创建一个名为`my-first-class.ts`的新文件，并添加以下代码：

```php
class MyBand {
    // Properties without prefix are public
    // Available is; Private, Protected
    albums: Array<string>;
    members: number;
    constructor(albums_list: Array<string>, total_members: number) {
        this.albums = albums_list;
        this.members = total_members;
    }
    // Methods
    listAlbums(): void {
        console.log("My favorite albums: ");
        for(var i = 0; i < this.albums.length; i++) {
            console.log(this.albums[i]);
        }
    }
}
// My Favorite band and his best albums
let myFavoriteAlbums = new MyBand(["Ace of Spades", "Rock and Roll", "March or Die"], 3);
// Call the listAlbums method.
console.log(myFavoriteAlbums.listAlbums());
```

我们在以前的代码中添加了一些注释以便理解。

一个类可以有尽可能多的方法。在前一个类的情况下，我们只给出了一个方法，列出我们最喜欢的乐队专辑。您可以在终端上测试这段代码，将任何您想要的信息传递给新的`MyBand()`构造函数。

这很简单，如果您已经接触过 Java、C#甚至 PHP，您可能已经看到了这个类结构。

在这里，我们可以将继承（OOP）原则应用于我们的类。让我们看看如何做到这一点：

1.  打开`band-class.ts`文件，并在`console.log()`函数之后添加以下代码：

```php
/////////// using inheritance with TypeScript ////////////
class MySinger extends MyBand {
    // All Properties from MyBand Class are available inherited here
    // So we define a new constructor.
    constructor(albums_list: Array<string>, total_members: number) {
        // Call the parent's constructor using super keyword.
        super(albums_list, total_members);
    }
    listAlbums(): void{
        console.log("Singer best albums:");
        for(var i = 0; i < this.albums.length; i++) {
            console.log(this.albums[i]);
        }
    }
}
// Create a new instance of the YourBand class.
let singerFavoriteAlbum = new MySinger(["At Falson Prision", "Among out the Stars", "Heroes"], 1);
console.log(singerFavoriteAlbum.listAlbums());
```

在 Angular 中，类非常有用于定义组件，正如我们将在第三章中看到的那样，*理解 Angular 6 的核心概念*。

# 声明一个接口

在使用 TypeScript 时，接口是我们的盟友，因为它们在纯 JavaScript 中不存在。它们是一种有效的方式来对变量进行分组和类型化，确保它们始终在一起，保持一致的代码。

让我们看一个声明和使用接口的实际方法：

1.  在您的文本编辑器中，创建一个名为`band-interface.ts`的新文件，并添加以下代码：

```php
interface Band {
    name: string,
    total_members: number
}
```

要使用它，请将接口分配给函数类型，就像以下示例中那样。

1.  在`band-interface.ts`文件中的接口代码之后添加以下代码：

```php
interface Band {
    name: string,
    total_members: number
}
function unknowBand(band: Band): void {
    console.log("This band: " + band.name + ", has: " +                 band.total_members + " members");
}
```

请注意，在这里，我们使用`Band`接口来为我们的`function`参数命名。因此，当我们尝试使用它时，我们需要在新对象中保持相同的结构，就像以下示例中的那样：

```php
// create a band object with the same properties from Band interface:
let newband = {
    name: "Black Sabbath",
    total_members: 4
}
console.log(unknowBand(newband));
```

请注意，您可以通过键入以下命令来执行所有示例文件

在您的终端中键入`tsc band-interface.ts`和`band-interface.js`节点。

因此，如果您遵循前面的提示，您将在终端窗口中看到相同的结果：

```php
This band: Black Sabbath, has: 4 members
```

正如您所看到的，TypeScript 中的接口非常棒；我们可以用它们做很多事情。在本书的课程中，我们将看一些更多使用接口在实际 Web 应用程序中的例子。

# 创建泛型函数

**泛型**是创建灵活类和函数的非常有用的方式。它们与 C#中使用的方式非常相似。它非常有用，可以在多个地方使用。

我们可以通过在函数名称后添加尖括号并封装数据类型来创建泛型函数，就像以下示例中的示例一样：

```php
function genericFunction<T>( arg: T ): T [] {
    let myGenericArray: T[] = [];
    myGenericArray.push(arg);
    return myGenericArray;
}
```

请注意，尖括号内的`t`（`<t>`）表示`genericFunction()`是通用类型。

让我们看看实际操作：

1.  在您的代码编辑器中，创建一个名为`generics.ts`的新文件，并添加以下代码：

```php
function genericFunction<T>( arg: T ): T [] {
    let myGenericArray: T[] = [];
    myGenericArray.push(arg);
    return myGenericArray;
}
let stringFromGenericFunction = genericFunction<string>("Some string goes here");
console.log(stringFromGenericFunction[0]);
let numberFromGenericFunction = genericFunction(190);
console.log(numberFromGenericFunction[0]);
```

让我们看看我们的通用函数会发生什么。

1.  回到您的终端并输入以下命令：

```php
tsc generics.ts
```

1.  现在，让我们使用以下命令执行文件：

```php
node generics.js
```

我们将看到以下结果：

```php
Some string goes here
 190
```

请注意，编译器能够识别我们作为`function`参数传递的数据类型。在第一种情况下，我们明确将参数作为字符串传递，而在第二种情况下，我们不传递任何东西。

尽管编译器能够识别我们使用的参数类型，但始终确定我们要传递的数据类型是非常重要的。例如：

```php
let numberFromGenericFunction = genericFunction<number>(190);
console.log(numberFromGenericFunction[0]);
```

# 使用模块

在使用 TypeScript 开发大型应用程序时，模块非常重要。它们允许我们导入和导出代码、类、接口、变量和函数。这些函数在 Angular 应用程序中非常常见。

然而，它们只能通过使用库来实现，这可能是浏览器的 Require.js，或者是 Node.js 的 Common.js。

在接下来的章节中，我们将说明如何在实践中使用这些特性。

# 使用类导出功能

任何声明都可以被导出，正如我们之前提到的；要这样做，我们只需要添加`export`关键字。在下面的例子中，我们将导出`band`类。

在您的文本编辑器中，创建一个名为`export.ts`的文件，并添加以下代码：

```php
export class MyBand {
    // Properties without prefix are public
    // Available is; Private, Protected
    albums: Array<string>;
    members: number;
    constructor(albums_list: Array<string>, total_members: number) {
        this.albums = albums_list;
        this.members = total_members;
    }
    // Methods
    listAlbums(): void {
        console.log("My favorite albums: ");
        for(var i = 0; i < this.albums.length; i++) {
            console.log(this.albums[i]);
        }
    }
}
```

现在我们的`Myband`类可以被导入到另一个文件中了。

# 导入和使用外部类

使用关键字`import`可以实现导入，并且可以根据您使用的库的不同方式进行声明。使用 Require.js 的示例如下：

+   回到您的文本编辑器，创建一个名为`import.ts`的文件，并添加以下代码：

```php
import MyBand = require('./export');
console.log(Myband());
```

使用 Common.js 的示例如下：

```php
import { MyBand } from './export';
console.log(new Myband(['ZZ Top', 'Motorhead'], 3));
```

+   第二种方法已被 Angular 团队采用，因为 Angular 使用 Webpack，这是一个构建现代 Web 应用程序的模块捆绑器。

# 摘要

在本章中，您看到了 TypeScript 的基本原则。我们只是触及了表面，但是我们为您提供了一个处理使用 TypeScript 开发 Angular 应用程序的坚实基础。

在本书的过程中，随着我们创建 Web 应用程序的进展，我们将增强您的理解。


# 第三章：理解 Angular 6 的核心概念

Angular 框架已经成为全球最流行的前端应用程序开发工具之一。除了非常多功能（与其他库如`React.js`或`Vue.js`非常不同，这些库只用于一个目的），Angular 是一个完整的框架，并且随着 Angular 6 的新更新，我们现在有更多资源可用于创建令人惊叹和快速的 Web 应用程序。此外，Angular 团队每年提出两次重大更新。

Angular 的另一个优势是其包含用于创建 Web 应用程序的 Angular **命令行界面**（**CLI**）。这为我们提供了额外的能力；通过终端中的一个简单命令，我们可以非常快速和轻松地创建应用程序的样板代码。然而，一切并不像我们希望的那样甜蜜，因此我们需要了解 Angular 的基本概念，并知道如何避免一些问题。这可以通过采用基于组件和模块的开发思维模型来轻松解决。在接下来的示例中，我们将仔细创建可扩展和模块化项目的基本结构。

在本章中，我们将涵盖以下主题：

+   Angular 6 - 更小，更快，更容易

+   Angular 和组件方法用于开发现代 Web 应用程序

+   安装工具：Git，Angular CLI，HTTP 服务器和 VS Code 插件

+   创建一个简单的 Angular 应用程序

+   简单部署

# Angular 6 - 更小，更快，更容易

以下功能不仅适用于版本 6，而且从版本 5 开始就已包含；我们在这里提到它们是因为它们是构建现代 Web 应用程序的强大功能：

+   **Webpack**：您现在可以使用作用域托管技术生成更小的模块。

+   您可以通过使用 JavaScript 的 RxJS 6 库减少常见用例的捆绑大小。

+   Angular CLI 允许使用命令，如`ng` update，来更新所有依赖项。

+   您将有选择使用 Angular Material Design 启动应用程序。

+   `ng add`命令支持创建渐进式 Web 应用程序或将现有应用程序转换为**渐进式 Web 应用程序**（**PWA**）。

+   您将有机会使用 Bazel 构建应用程序的库，并与其他团队共享库。

+   Angular 使得可以打包自定义 HTML/JavaScript 元素以供第三方应用程序使用。

您可以在[`bazel.build/`](https://bazel.build/)了解有关 Bazel 的更多信息。

当然，Angular 6 版本中还有许多其他改进和功能；请注意，本书是在 Angular 6 beta 7 版本上编写的，接下来的章节将有关于当前 Angular 版本的更多新闻。

# Angular 和组件方法用于开发现代 Web 应用程序

Angular 组件类似于 Web 组件；它们用于组合网页，甚至其他组件。一个 Web 应用程序中可能有数十个组件。

组件定义视图和模板，并且它们属于应用程序中的一个模块；每个应用程序至少有一个根模块，由 Angular CLI 命名为`AppModule.ts`。

`app.module.ts`文件包含了 Angular 应用程序的所有引导代码和配置，如下面的代码块所示：

```php
import { NgModule } from '@angular/core';

@NgModule({
  declarations: [
    AppComponent
  ],
  imports: [],
  providers: [],
  bootstrap: [AppComponent]
})
export class AppModule { }
```

上述代码是 Angular 应用程序的最基本配置；我们从 Angular 核心库中导入`NgModule`并将其用作装饰器：`@NgModule`。

组件和服务都只是类，带有标记其类型并提供元数据的装饰器，告诉 Angular 如何使用它们。

您可以在[`www.webcomponents.org/introduction`](https://www.webcomponents.org/introduction)了解有关 Web 组件的更多信息。

# Angular 的主要构建模块

使用 Angular 框架创建的每个应用程序都有五个非常重要的连接到彼此的点，并建立了应用程序的基本架构：

+   **模块**：使用装饰器`@NgModule`

+   **服务**：使用装饰器`@Injectable`

+   **组件**：使用装饰器`@component`

+   **模板**：带有`data-bind`和指令的视图

+   **路由**：将 URL 路径设置为视图

让我们以一个简单的博客页面作为 Angular 应用程序来看待，使用组件构建：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/hsn-flstk-web-dev-ng6-lrv5/img/3c291f8a-fb7b-478f-a72b-9a6d2fa665d8.png)Angular 组件

前述图表说明了组件如何用于构建一个简单的应用程序。

前述图表与 Angular 应用程序的五个基本概念的比较如下：

+   一个模块：`blog.module.ts`

+   一个页面组件：`blog.component.ts`

+   博客页面的路由

+   加载博客文章的服务

还有一些其他组件，如**Header**，**Post**和**Pagination**。

请注意，Header 组件属于应用程序的主模块（在本例中为`AppModule`），而 Post 和 Pagination 组件属于`BlogModule`的一部分。

随着我们在本章中的深入，我们将更仔细地研究模块和组件之间的关系。现在，我们将看一下组件的生命周期。

# 组件生命周期

在 Angular 组件的生命周期中，在实例化后，组件从开始到结束都会运行一条明确的执行路径。最基本的理解方式是通过观察以下代码：

```php
export class HelloComponent implements OnInit, OnDestroy {
   constructor() { }

   ngOnInit() {
... Some code goes here
}
ngOnDestroy() {
... Some code goes here
}
}  
```

在上面的例子中，您可以看到名为`ngOnInit()`和`ngOnDestroy`的方法；这些名称非常直观，向我们展示了我们有一个开始和一个结束。`ngOnInit()`方法是通过其`OnInit`接口实现的，`ngOnDestroy()`方法也是如此。正如您在前一章中看到的，TypeScript 中的接口非常有用 - 这里也不例外。

在下图中，我们将看一下我们可以在组件上实现的主要接口。在图中，在`Constructor()`方法之后，有八个接口（也称为钩子）；每个接口在特定时刻负责一件事：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/hsn-flstk-web-dev-ng6-lrv5/img/5a04ccae-f092-429e-a923-74071100d1c7.png)Angular 组件生命周期您可以在官方的 Angular 文档中了解每个接口的更多信息[`angular.io/guide/lifecycle-hooks`](https://angular.io/guide/lifecycle-hooks)。

我们不会在本章逐一描述接口，以免给您带来过多负担，但在本书的过程中，我们将在我们构建的应用程序中使用它们。此外，上述链接包含了关于每个接口和钩子的详细信息。

# 安装工具 - Git，Angular CLI 和 VS Code 插件

从本章到本书的结束，我们将采用 VS Code 文本编辑器 - 它是免费的，轻量级的，非常适合创建 Web 应用程序。

此外，对于源代码使用版本控制系统非常重要；这将帮助我们跟踪代码库中的所有更改。

接下来，我们将介绍 Git 源代码控制。

# 安装 Git

作为对 Git 的简单快速介绍，我们可以描述如下。

Git 是一个文件版本控制系统。通过使用它，我们可以开发项目，让许多人可以同时贡献，编辑和创建新文件，使它们可以存在而不会被覆盖。

在使用 Git 时非常常见的情况是同时在云中使用服务（如 GitHub 或 Bitbucket）来存储代码，以便我们可以共享它。

此外，几乎所有的开源项目（框架和库）今天都在 GitHub 上。因此，您可以通过报告错误，甚至发送代码和建议来做出贡献。

如果您是开发人员，但尚未拥有 GitHub，那么您已经晚了 - 现在是开始使用它的时候。因此，让我们安装 Git。

转到 [`git-scm.com/downloads`](https://git-scm.com/downloads) 并下载并安装适用于您平台的 Git。

安装后，打开您的终端并输入以下命令：

```php
git --version
```

您必须看到已安装在您系统上的当前版本。

此外，`git help`命令非常有用，列出所有可用的命令。

您可以在 [`git-scm.com/book/en/v2/Getting-Started-Git-Basics`](https://git-scm.com/book/en/v2/Getting-Started-Git-Basics) 上阅读有关 Git 基础知识的更多信息。

# 安装 Angular CLI

在框架的世界中，无论使用哪种语言，我们经常会发现可以帮助我们进行日常软件开发的工具，特别是在有重复任务时。

Angular CLI 是一个命令行界面，可以以非常高效的方式创建、开发和维护 Angular 应用程序。它是由 Angular 团队自己开发的开源工具。

通过使用 Angular CLI，我们能够创建整个 Angular 应用程序的基本结构，以及模块、组件、指令、服务等。它有自己的开发服务器，并帮助我们构建应用程序。

现在，是时候安装它了：

1.  打开您的终端并输入以下命令：

```php
npm install -g @angular/cli@latest
```

安装后，您将在终端中看到以下输出：

```php
+ @angular/cli@1.7.3 added 314 packages, removed 203 packages, updated 170 packages and moved 7 packages in 123.346s
```

删除和更新的软件包数量以及 Angular CLI 版本可能会有所不同。不用担心。

1.  您可以使用以下命令删除旧版本的 Angular CLI 并安装最新版本：

```php
npm uninstall -g angular-cli
npm cache verify
npm install -g @angular/cli@latest
```

如果您在尝试在 Windows 机器上更新 Angular CLI 版本时遇到一些`npm`问题，您可以查看 [`docs.npmjs.com/troubleshooting/try-the-latest-stable-version-of-npm#upgrading-on-windows`](https://docs.npmjs.com/troubleshooting/try-the-latest-stable-version-of-npm#upgrading-on-windows) 获取信息。

请注意，上述命令将在您的环境/机器上全局安装 Angular CLI。通常，当我们使用 Angular 框架和 Angular CLI 进行开发时，我们会看到关于版本差异的警告消息。这意味着，即使您在您的环境中安装了最新版本的 Angular CLI，Angular CLI 也会检查当前项目中使用的版本，并将其与您的机器上安装的版本进行比较，并使用当前项目版本。

当您在第三方项目上工作并需要保持全局安装在您的机器上的 Angular CLI 与`node_modules`项目文件夹中安装的本地项目版本之间的依赖一致性时，这非常有用。

1.  在您当前的 Angular 项目中，输入以下命令：

```php
rm -rf node_modules
npm uninstall --save-dev angular-cli
npm install --save-dev @angular/cli@latest
npm install
```

与我们书中使用的其他命令一样，Angular CLI 有一个名为`ng help`的命令。通过它，我们可以访问大量的选项。

其中一个命令在我们使用 Angular 开发应用程序并需要在官方文档中查询内容时特别有用，而无需离开终端。

1.  返回您的终端并输入以下命令：

```php
ng doc HttpClient
```

上述命令将在您的默认浏览器中打开`HttpClient`文档 API，使用 [`angular.io/api?query=HttpClient`](https://angular.io/api?query=HttpClient)。因此，您可以将`ng doc`命令与您想要搜索的 API 中的任何内容结合使用。

现在我们已经拥有了开始使用 Angular CLI 开发 Web 应用程序所需的一切，但在深入构建示例应用程序之前，我们将使用一些非常有用的工具更新我们的工具包。

# 安装 VS Code Angular 插件

正如前几章所述，VS Code 文本编辑器是使用 JavaScript 和 TypeScript 开发 Web 应用程序的绝佳 IDE，Angular 也是如此。

在本节中，我们将看一些扩展（也称为插件），这些扩展可以帮助我们进行开发。

让我们来看看软件包名称和存储库 URL：

+   **Angular Language Service**：[`github.com/angular/vscode-ng-language-service`](https://github.com/angular/vscode-ng-language-service)。由官方 Angular 团队提供，此扩展可帮助我们在模板文件和模板字符串中进行补全，并为模板和 Angular 注释提供诊断。

+   **Angular v5 Snippets**：[`github.com/johnpapa/vscode-angular-snippets`](https://github.com/johnpapa/vscode-angular-snippets)。扩展名为 Angular v5；GitHub 项目存储库没有指定名称。因此，我们可以期望从插件作者那里获得未来版本的 Angular 的代码片段。这是一个强大的工具，可以帮助我们几乎在 Angular 应用程序中创建任何东西；您可以在 GitHub 存储库中看到完整的列表。

+   **Angular Support**：[`github.com/VismaLietuva/vscode-angular-support`](https://github.com/VismaLietuva/vscode-angular-support)。

转到并从中查看定义：

```php
interpolation {{ someVar }}
input [(...)]="someVar"
output (...)="someMethod"
templateUrl or styleUrls in @Component decorator
component <some-component></some-component>
```

最后但同样重要的是，我们建议您使用 GitLens 插件。这个扩展非常重要，因为它帮助我们在 Git 存储库中可视化我们的代码，同时还提供与 GitHub 或 Bitbucket 的集成。

+   **GitLens**：[`github.com/eamodio/vscode-gitlens`](https://github.com/eamodio/vscode-gitlens)。

增强内置于 Visual Studio Code 中的 Git 功能。

– Gitlens

+   您可以探索存储库和文件历史记录的导航

+   您还可以探索提交并可视化分支、标签和提交之间的比较

+   有一个作者代码镜头，显示文件顶部和/或代码块上最近的提交和作者数量

+   **GitLens 插件**：[`gitlens.amod.io/`](https://gitlens.amod.io/)。这个扩展非常重要，因为它帮助我们在 Git 存储库中可视化我们的代码，同时还提供与 GitHub 或 Bitbucket 的集成。

此外，还可以通过 IDE 本身安装任何扩展。要做到这一点，请按照以下步骤操作：

1.  打开 VS Code。

1.  单击左侧边栏上的最后一个图标；您可以在以下截图中看到它：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/hsn-flstk-web-dev-ng6-lrv5/img/f6a24014-3903-4bc6-a3e8-d1487d4bcfcb.png)VS Code 扩展安装

只需在搜索输入字段中键入要搜索的内容，然后单击安装。

现在，我们已经拥有了开始开发 Angular 应用程序所需的一切。在下一节中，我们将看看如何使用 Angular CLI 创建 Angular 应用程序。

# 创建一个简单的 Angular 应用程序

在本章中，我们将涵盖使用 Angular 框架和 Angular CLI 开发 Web 应用程序的所有要点。现在，是时候接触代码并从头到尾开发一个应用程序了。

在这个示例项目中，我们将开发一个简单的前端应用程序来消耗 API 的数据并在屏幕上显示它 - 类似于一个简单的博客。打开您的终端并键入以下命令：

```php
ng new chapter03 --routing
```

请注意，`--routing`标志是可选的，但由于我们的下一个示例将使用路由，因此最好在启动应用程序时使用该标志。安装了 Angular CLI 后，您应该在终端上看到以下消息：

```php
Testing binary
Binary is fine
added 1384 packages in 235.686s
You can `ng set --global packageManager=yarn`.
Project 'chapter03' successfully created.
```

# Angular 应用程序的结构

现在我们已经创建了我们的应用程序，让我们检查一些重要的文件。尽管这些文件已经设置好并准备好使用，但在现实世界的应用程序中，我们经常需要添加设置，甚至其他模块。

在 VS Code 中打开`chapter03`文件夹；您将在 VS Code 资源管理器选项卡中看到以下屏幕：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/hsn-flstk-web-dev-ng6-lrv5/img/7bce726d-6e59-4e39-8e65-cd7d4d60e0bc.png)Angular 项目结构

因此，在`/src/app`文件夹中，除了服务（我们很快将看到）外，我们还有 Angular 应用程序的五个主要块：

| `app.routing.module.ts` | 路由 |
| --- | --- |
| `app.component.css` | 样式表 |
| `app.component.html` | 模板 |
| `app.component.spec.ts` | 测试 |
| `app.component.ts` | @Component |
| `app.module.ts` | @NgModule |

# package.json 文件

`package.json`文件在使用 Node.js 模块的 Web 应用程序中非常常见。如今，它经常出现在前端应用程序中，除了使用 Node.js 的服务器端应用程序。对于 Angular 框架来说，它也不例外；这是新版本 Angular 的一个巨大优势，因为我们只能导入对应用程序非常必要的模块，从而减小了大小和构建时间。让我们看一下`package.json`文件的内容。我们在每个重要部分之前添加了一些注释：

```php
{
"name": "chapter03",
"version": "0.0.0",
"license": "MIT",
// Npm commands, based on Angular/Cli commands, including: test and     build.
"scripts": {
"ng": "ng",
"start": "ng serve",
"build": "ng build --prod",
"test": "ng test",
"lint": "ng lint",
"e2e": "ng e2e"
 },
"private": true,
// Dependencies to work in production, including:
@angular/core, @angular/common, @angular/route and many more. "dependencies":{
...
},
//  Dependencies only in development environment, including modules for test, TypeScript version, Angular/Cli installed locally and others.  "devDependencies": { ...
}
} 
```

当我们安装新模块时，此文件会自动更改。而且，我们经常在标签脚本内添加一些命令，正如您将在接下来的章节中看到的那样。您可以在官方 npm 文档的[`docs.npmjs.com/files/package.json`](https://docs.npmjs.com/files/package.json)中阅读更多关于`package.json`文件的信息。

# Dotfiles - .editorconfig，.gitignore 和.angular-cli.json

Dotfiles 是以点开头的配置文件；它们始终在项目的后台，但它们非常重要。它们用于自定义您的系统。名称 dotfiles 源自类 Unix 系统中的配置文件。在 Angular 项目中，我们将看到其中三个文件：

+   `.editorconfig`：此文件配置文本编辑器以使用特定的代码样式，以便项目保持一致，即使它由多人和多种文本编辑器编辑。

+   `.gitignore`：顾名思义，它会忽略确定的文件夹和文件，以便它们不被源代码控制跟踪。我们经常发现`node_modules`和`dist`文件夹不需要版本控制，因为它们在每次安装应用程序或运行构建命令时都会生成。

+   `.angular-cli.json`：存储项目设置，并在执行构建或服务器命令时经常使用。在单个项目中可能有几个 Angular 应用程序。让我们看一些细节并检查`.angular-cli.json`：

```php
{
    "$schema": "./node_modules/@angular/cli/lib/config/schema.json",
    "project": {
    "name": "chapter03"
    },
    // Here we determinate the projects, for this example we have     only one app.
    "apps": [
    {
    "root": "src",
    "outDir": "dist",
    "assets": [
    "assets",
    "favicon.ico"
    ],
    "index": "index.html",
    "main": "main.ts",
    "polyfills": "polyfills.ts",
    "test": "test.ts",
    "tsconfig": "tsconfig.app.json",
    "testTsconfig": "tsconfig.spec.json",
    "prefix": "app",
    "styles": [
    "styles.css"
    ],
    "scripts": [],
    "environmentSource": "environments/environment.ts",
    // Configuration for both environment, developing and production
    "environments": {
    "dev": "environments/environment.ts",
    "prod": "environments/environment.prod.ts"
    }
    }
    ],
    // Configuration for end to end tests and unit tests
    "e2e": {
    "protractor": {
    "config": "./protractor.conf.js"
    }
    },
    "lint": [
    {
    "project": "src/tsconfig.app.json",
    "exclude": "**/node_modules/**"
    },
    {
    "project": "src/tsconfig.spec.json",
    "exclude": "**/node_modules/**"
    },
    {
    "project": "e2e/tsconfig.e2e.json",
    "exclude": "**/node_modules/**"
    }
    ],
    "test": {
    "karma": {
    "config": "./karma.conf.js"
    }
    },
    // Stylesheet configiration, for this example we are using CSS
    "defaults": {
    "styleExt": "css",
    "component": {}
    }
}
```

# 环境

在`src/environments`文件夹中，我们找到两个配置文件。一个称为`environment.prod.ts`，另一个是`environment.ts`。Angular CLI 将根据我们使用的命令来决定使用哪一个；例如，考虑以下命令：

```php
 ng build --env = prod 
```

如果我们使用它，那么 Angular 将使用`environment.prod.ts`文件，对于其他命令，比如`ng serve`，它将使用`environment.ts`。这非常有用，特别是当我们有一个本地 API 和一个在`production`中时，使用不同的路径。

两个文件几乎具有相同的代码；请参阅`environment.prod.ts`，如下所示：

```php
export const environment = {
    production: true
};
```

`environment.ts`文件如下：

```php
export const environment = {
    production: false
};
```

请注意，在这个第一阶段，`true`（在生产中）和`false`（在开发中）是这两个文件之间唯一的区别。显然，除了我们提到的文件之外，Angular 应用程序中还有许多其他文件，它们都非常重要。但是，现在让我们专注于这些。别担心；在本书的过程中，我们将详细了解更多内容，在开发我们的示例应用程序时。现在，我们将专注于创建本章中使用的简单示例。

# 运行示例应用程序

现在我们已经启动了我们的项目，我们将运行内置的 Angular CLI 服务器，以查看我们的应用程序的外观：

1.  在项目根目录中打开 VS Code 到`chapter03`文件夹。

1.  在这个例子中，我们将使用集成终端进行编码；为此，请点击顶部菜单中的`view`，然后点击`Integrated Terminal`。

1.  在终端中键入以下命令：

```php
npm start
```

您将看到类似以下的消息：

```php
 ** NG Live Development Server is listening on localhost:4200, open  
 your  
 browser on http://localhost:4200/ **
 Date: xxxx 
 Hash: xxxx
 Time: 16943ms
 chunk {inline} inline.bundle.js (inline) 3.85 kB [entry] [rendered]
 chunk {main} main.bundle.js (main) 20.8 kB [initial] [rendered]
 chunk {polyfills} polyfills.bundle.js (polyfills) 549 kB [initial]  
 [rendered]
 chunk {styles} styles.bundle.js (styles) 41.5 kB [initial]  
 [rendered]
 chunk {vendor} vendor.bundle.js (vendor) 8.45 MB [initial] 
 [rendered]
```

1.  在幕后，Angular CLI 将使用 webpack 模块管理器。在本书的后面，您将看到如何导出和自定义 webpack 文件。

1.  现在，转到`http://localhost:4200`并检查结果；您将看到我们之前创建的样板应用程序的欢迎页面。您可以在`src/app/app.component.html`中找到这个页面的代码 - 这是我们的模板。

现在，是时候向我们的应用程序添加一个新模块了。

# 添加新模块

在这个例子中，我们将演示如何使用 Angular CLI 构建应用程序。即使在这个非常基本的例子中，我们也将涵盖以下几点：

+   如何组织一个 Angular 应用程序

+   创建模块

+   创建服务

+   模板数据绑定

+   在生产环境中运行应用程序

现在，让我们创建一个显示啤酒列表的模块：

1.  打开 VS Code，在集成终端内输入以下命令：

```php
ng g module beers
```

请注意，命令`ng g module`是`ng generate module <module-name>`的快捷方式，这个命令只是创建模块；我们需要添加路由、组件和模板，并且在`app`文件夹的根目录的`app.modules.ts`中导入`beers`模块。上述命令将在我们的项目中生成以下结构和文件内容：`src/app/beers/beers.module.ts`。`beers.module.ts`的内容如下：

```php
import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
    @NgModule({
    imports: [
    CommonModule
    ],
    declarations: []
    })
export class BeersModule { }
```

这是一个非常简单的样板代码，但非常有用。现在，我们将添加缺失的部分。

1.  将`beers`模块添加到您的`app`模块；打开`app.module.ts`并用以下行替换代码：

```php
import { BrowserModule } from '@angular/platform-browser';
import { NgModule } from '@angular/core';
import { HttpClientModule } from '@angular/common/http';
import { AppRoutingModule } from './app-routing.module';
import { AppComponent } from './app.component';
import { BeersModule } from './beers/beers.module';
    @NgModule({
    declarations: [
        AppComponent
    ],
    imports: [
    BrowserModule,
    AppRoutingModule,
    HttpClientModule,
    BeersModule
    ],
    providers: [],
    bootstrap: [AppComponent]
})
export class AppModule { }
```

请注意，我们导入了`BeersModule`并将其添加到`imports`数组中。

# 添加新组件

现在，我们需要一个组件来显示啤酒列表，因为我们刚刚创建了一个名为`Beers`的模块。稍后，您将看到如何使用 API 和 Angular 服务来加载啤酒列表；现在，我们将专注于创建我们的组件。

在根文件夹内，并在集成的 VS Code 终端中，输入以下命令：

```php
ng g component beers
```

前面的命令将生成以下结构：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/hsn-flstk-web-dev-ng6-lrv5/img/74c96c21-d187-4a2a-a86f-c67659f23185.png)

`BeersModule`和`Component`文件已经创建。现在我们有了我们的模块、模板和组件文件。让我们添加一个新的路由。

# 添加新路由

如您之前所见，路由是每个 Web 应用程序的一部分。现在，我们将添加一个新的路由，以便我们可以访问我们的`beers`模块的内容。打开`src/app/app-routing.module.ts`并用以下代码替换：

```php
import { NgModule } from '@angular/core';
import { Routes, RouterModule } from '@angular/router';
import { AppComponent } from './app.component';
import { BeersComponent } from './beers/beers.component';
const routes: Routes = [
    { path: '', redirectTo: 'beers', pathMatch: 'full' },
    { path: 'beers', component: BeersComponent }
];
@NgModule({
    imports: [RouterModule.forRoot(routes)],
    exports: [RouterModule]
})
export class AppRoutingModule { }
```

请注意，我们只是将新路由添加到现有的路由文件中（在这种情况下是`app.routing.module.ts`），因为这个例子非常简单。但是，在更大的应用程序中，建议为每个应用程序模块创建单独的路由文件。

# 创建一个 Angular 服务

Angular 服务用于处理数据；它可以是内部数据（从一个组件到另一个组件）或外部数据，比如与 API 端点通信。几乎所有使用 JavaScript 框架的前端应用程序都使用这种技术。在 Angular 中，我们称之为服务，并且我们使用一些内置在 Angular 框架中的模块来完成任务：`HttpClient`和`HttpClientModule`。

让我们看看 Angular CLI 如何帮助我们：

1.  打开 VS Code，在集成终端内输入以下命令：

```php
ng g service beers/beers
```

上述命令将在`beers`文件夹中生成两个新文件：

`beers.service.spec.ts`和`beers.service.ts`。

1.  将新创建的`Service`作为依赖提供者添加到`beers.module.ts`。打开`src/app/beers/beers.module.ts`并添加以下行：

```php
import { BeersService } from './beers.service'; @NgModule({
    providers: [BeersService] })
```

在 VS Code 中，我们有导入模块支持，所以当您开始输入模块的名称时，您将看到以下帮助屏幕：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/hsn-flstk-web-dev-ng6-lrv5/img/b24600db-4493-450f-bf85-c957e8e13a5d.png)

最终的`beers.module.ts`代码将如下所示：

```php
import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import { BeersComponent } from './beers.component';
import { BeersService } from './beers.service';
@NgModule({
    imports: [
        CommonModule
    ],
    declarations: [BeersComponent],
    providers: [BeersService
    ]
})
export class BeersModule { }
```

现在，是时候使用服务连接到 API 了。为了尽可能接近真实应用程序，我们将在这个例子中使用一个公共 API。在接下来的步骤中，我们将有效地创建我们的服务并将数据绑定到我们的模板上。

在这个例子中，我们将使用免费的[`punkapi.com/`](https://punkapi.com/) API：

1.  打开`beers.service.ts`，并用以下行替换代码：

```php
import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders, HttpErrorResponse } from '@angular/common/http';
import { Observable } from 'rxjs/Observable';
import 'rxjs/add/observable/throw';
import { catchError } from 'rxjs/operators';
@Injectable()
export class BeersService {
    private url = 'https://api.punkapi.com/v2/beers?';
    constructor(private http: HttpClient) { }
/**
* @param {page} {perpage} Are Page number and items per page
*
* @example
* service.get(1, 10) Return Page 1 with 10 Items
*
* @returns List of beers
*/
    get(page: number, per_page: number) {
        return this.http.get(this.url + 'page=' + page +
         '&per_page=' + per_page)
        .pipe(catchError(error => this.handleError(error)));
    }
```

```php

    private handleError(error: HttpErrorResponse) {
        return Observable.throw(error);
    }
}
```

现在，我们需要告诉组件我们需要使用这个服务来加载数据并将其传输到我们的模板中。

1.  打开`src/app/beers/beers.component.ts`，并用以下代码替换代码：

```php
import { Component, OnInit } from '@angular/core';
import { BeersService } from './beers.service';
@Component({
    selector: 'app-beers',
    templateUrl: './beers.component.html',
    styleUrls: ['./beers.component.css']
})
export class BeersComponent implements OnInit {
    public beersList: any [];
    public requestError: any;
    constructor(private beers: BeersService) { }
    ngOnInit() {
        this.getBeers();
    }
    /**
    * Get beers, page = 1, per_page= 10
    */
    public getBeers () {
        return this.beers.get(1, 20).subscribe(
            response => this.handleResponse(response),
            error => this.handleError(error)
        );
    }
    /**
    * Handling response
    */
    protected handleResponse (response: any) {
        this.requestError = null;
        return this.beersList = response;
    }
    /**
    * Handling error
    */
    protected handleError (error: any) {
        return this.requestError = error;
    }
}
```

# 模板数据绑定

现在我们有了一个连接到 API 端点并接收 JSON 文件的服务，让我们对我们的视图进行一些小的更改，即 Angular 世界中称为模板的视图。模板是`module`文件夹中的 HTML 文件：

1.  打开`src/app/app.component.html`，并删除`<router-outlet></route-outlet>`标签之前的所有代码。

1.  打开`src/app/beers/beers.component.html`，并在`beers`工作段落之后添加以下代码：

```php
<div class="row">
    <div class="col" href="" *ngFor="let item of beersList">
        <figure>
            <img [src]="item.image_url" [alt]="item.name" />
        <figcaption>
            <h1>{{item.name}}</h1>
                <p>{{item.tagline}}</p>
        </figcaption>
        </figure>
    </div> </div>
```

请注意，我们使用花括号模板标签(`{{}}`)和`*ngFor`指令来显示我们的数据。让我们看一些 Angular 数据绑定类型：

```php
{{ some.property }} One way Binding
[(ngModel)]="some.value" Two way Binding (click)="showFunction($event)" Event Binding
```

1.  现在，我们需要为`beers.component.html`添加一些样式；打开`src/app/beers/beers.component.css`，并添加以下代码：

```php
body {
    margin: 40px;
}
.row {
    display: grid;
    grid-template-columns: 300px 300px 300px;
    grid-gap: 10px;
    background-color: #fff;
    color: #444;
}
.col {
    background-color: #d1d1d1;
    border-radius: 5px;
    padding: 10px;
}
figure {
    text-align: center;
}
img {
    height:250px;
}
```

我们现在非常接近完成我们的示例应用程序。最后一步是构建我们的应用程序并查看最终结果。

# 简单部署

现在我们已经准备好了一切，让我们看看如何构建我们的应用程序。

首先，我们将在更改后查看应用程序：

1.  打开 VS Code，单击顶部菜单栏中的视图，然后单击集成终端。

1.  在您的终端中输入以下命令：

```php
npm start
```

1.  打开您的默认浏览器，转到`http://localhost.com:4200/beers`。

1.  恭喜；您应该看到以下截图：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/hsn-flstk-web-dev-ng6-lrv5/img/186751db-e369-4760-ba47-2be0b5666ce0.png)

请注意，我们正在使用`npm start`命令后面的`ng serve`命令进行开发。

现在，让我们使用命令构建应用程序，并检查结果：

1.  返回 VS Code，然后输入*Ctrl* *+* *C*停止服务器。

1.  输入以下命令：

```php
npm run build
```

上述命令将准备应用程序进行生产；Angular CLI 将为我们完成所有繁重的工作。现在，我们在`chapter03`根目录下有一个文件夹，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/hsn-flstk-web-dev-ng6-lrv5/img/65c85104-5ea9-44e6-981e-9ba6e4ebf8a7.png)dist 文件夹

如您所见，我们的整个应用程序都在这个文件夹中，尽可能地进行了优化；但是，要查看内容，我们需要一个 Web 服务器。在本例中，我们将使用`http-server`节点包，这是一个非常有用的 Node.js 模块，可以将特定目录放在简单的 Web 服务器上。您可以在[`www.npmjs.com/package/http-server`](https://www.npmjs.com/package/http-server)找到有关 http-server 的更多信息：

1.  返回 VS Code 和集成终端，输入以下命令：

```php
npm install http-server -g
```

1.  仍然在集成终端中，输入以下命令：

```php
cd dist && http-server -p 8080
```

1.  您将在终端中看到以下消息：

```php
 Starting up http-server, serving ./
 Available on:
 http://127.0.0.1:8080
 http://192.168.25.6:8080
 Hit CTRL-C to stop the server
```

这意味着一切进行顺利，您现在可以在浏览器中访问`dist`文件夹的内容了。

1.  打开您的默认浏览器，转到`http://localhost.com:8080/beers`。

我们完成了；现在，让我们使用一些 Git 命令将我们在本地存储库中`chapter03`文件夹中所做的一切保存起来。这一步对于接下来的章节并不是必需的，但强烈建议这样做。

1.  在`chapter03`文件夹中打开您的终端，并输入以下命令：

```php
git add .git commit -m "chapter03 initial commit"
```

1.  在上一个命令之后，您将在终端中看到以下输出：

```php
 [master c7d7c18] chapter03 initial commit
 10 files changed, 190 insertions(+), 24 deletions(-) rewrite  
 src/app/app.component.html (97%)
 create mode 100644 src/app/beers/beers.component.css
 create mode 100644 src/app/beers/beers.component.html
 create mode 100644 src/app/beers/beers.component.spec.ts
 create mode 100644 src/app/beers/beers.component.ts
 create mode 100644 src/app/beers/beers.module.ts
 create mode 100644 src/app/beers/beers.service.spec.ts
 create mode 100644 src/app/beers/beers.service.ts
```

# 总结

好了，我们已经到达了另一章的结尾，现在您应该了解如何使用 Angular 创建应用程序。在本章中，我们涵盖了使 Angular 成为强大框架的主要要点。您可以直接从 GitHub 下载我们在本章中使用的代码示例，网址为[`github.com/PacktPublishing`](https://github.com/PacktPublishing)。在下一章中，我们将深入了解后端 API。
