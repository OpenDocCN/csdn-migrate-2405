# Angular .NET 开发学习手册（一）

> 原文：[`zh.annas-archive.org/md5/1D7CD4769EDA3E96BB350F0A5265564A`](https://zh.annas-archive.org/md5/1D7CD4769EDA3E96BB350F0A5265564A)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

## 第一章：使用 Angular 入门

如果您正在阅读本书，那是因为您是.NET 开发人员，想了解如何将 Angular 与.NET Framework 技术一起使用，如 ASP.NET **Model View Controller**（MVC）和 Web API，以及诸如 Web Forms 和 Web Services 之类的传统技术。它使开发人员能够开发由 Angular 驱动的更丰富和动态的.NET Web 应用程序。Angular 是一个帮助创建动态 Web 应用程序的开源 JavaScript 框架。

在本章中，我们将涵盖以下主题：

+   介绍 Angular

+   Angular 架构

+   使用 Angular 构建一个 Hello World 应用程序

## 介绍 Angular

* * *

在向您介绍 Angular 之前，让我们讨论一下 AngularJS 的历史。一切都始于改进客户端 Web 开发过程。作为改进的一部分，微软引入了 XML HTTP 请求对象以从服务器检索数据。随着引入了像 jQuery 和 Prototype 这样先进的 JavaScript 库，开发人员开始使用 Ajax 从服务器异步请求数据。这些库被广泛用于操作 DOM 并绑定数据到 UI，直到 90 年代末。

Ajax 是异步 JavaScript 和 XML 的缩写。Ajax 可以使 Web 应用程序在不干扰页面显示和行为的情况下异步发送数据到服务器或从服务器检索数据。Ajax 允许 Web 应用程序动态更改内容，而无需重新加载整个页面，通过将数据交换层与表现层解耦来实现。 

2010 年底，引入了两个 JavaScript MVC 框架：Backbone 和 Knockout。Backbone 提供了完整的模型-视图-控制器（MVC）体验，而 Knockout 主要侧重于使用 MVVM 模式进行绑定。随着这些框架的发布，人们开始相信客户端 MVC 框架的威力。

### AngularJS 的诞生

来自 Google 的开发人员认为市场上存在的客户端 MVC 框架中有一个主要的缺失部分，即可测试性。他感觉有更好的方法来实现客户端 MVC，这让他开始了构建 Angular 的旅程。

Google 支持了 Angular 项目，看到了它的潜力，并且使其开源供世界免费使用。Angular 在市场中的所有 MVC 框架之间引起了很大的关注，因为它得到了 Google 的支持，并且具有诸如可测试性和指令等特性。如今，Angular 团队已经从单个开发人员发展到了大量开发人员，并且已经成为在小型、中型或大型 Web 应用程序中添加客户端 MVC 功能的首选。

### 为什么选择 AngularJS？

让我们讨论为什么使用 AngularJS 以及通过使用 AngularJS 我们的应用程序可以获得什么好处或增值：

+   **AngularJS 提供双向绑定**：许多客户端 MVC 框架只提供单向绑定。这意味着其他 MVC 框架只会使用来自服务器的模型来更新 HTML，当用户在页面上更改模型时，框架不会根据所做的更改更新模型。开发人员需要编写代码来根据用户操作更新模型。然而，AngularJS 方便了双向绑定，并通过根据用户在其上的操作更新模型使开发人员的生活更轻松。

+   **AngularJS 利用声明性视图**：这意味着功能将以 HTML 中的声明性指令的形式进行通信，以渲染模型并与 DOM 交互，根据模型的改变改变页面状态。这大大减少了用于此目的的代码量，将其减少了约 50%至 75%，并简化了开发人员的工作。

+   **AngularJS 支持指令概念**：这就像为 Web 应用程序编写一个特定领域的语言。指令将扩展 HTML 的功能，并根据应用程序的变化动态渲染它们，而不仅仅是显示 HTML 页面。

+   **AngularJS 非常易于测试**：如前所述，Angular 开发的主要目标之一是引入可测试的客户端 MVC 框架。AngularJS 非常易于测试，事实上，Angular 团队已经推出了两个框架：Karma 和 Protractor，用于编写端到端单元测试，以确保代码的稳定性，并确保自信地重构代码。

### Angular 2

AngularJS 是一个很好的框架。然而，它已经有六年的历史了，在这六年里，Web 世界发生了很多变化。为了适应 AngularJS 中所有这些现代发展，它将不得不在现有的实现中进行许多改变，这使得 Angular 团队从头开始编写 AngularJS。

在 2014 年 10 月举行的 ngEurope 大会上，宣布了 Angular 2 作为构建复杂 Web 应用的 Angular 1 的重大更新。ngCommunity 有点不满，因为他们在学习和实施 Angular 1 上投入了很多时间，而现在他们又不得不重新学习和实施 Angular。然而，谷歌在从 Angular 1 升级到 2 的迁移和升级过程中投入了大量精力，引入了 ngUpgrade 和 ngForward。一旦开发人员开始学习并使用 Angular 2 构建产品，他们就意识到了更清洁、更快速和更容易的 Angular 2 的威力。

Angular 2 是从零开始重写的。它帮助我们编写干净的、可测试的代码，可以在任何设备和平台上运行。Angular 2 消除了 Angular 1 中的许多概念。Angular 2 遵循了 ECMAScript 2015 的标准化。随着最近的 Web 标准化，影子 DOM 取代了传递和 ECMAScript 6 模块取代了 Angular 模块。Angular 2 比 Angular 1.x 快五倍。

### Angular 2 的优势

以下是 Angular 2 的特性和优势：

+   它支持跨平台应用程序开发，比如高性能应用程序，如使用 Ionic Framework、NativeScript、React Native 创建本机应用程序，并通过使用 Angular 方法访问本机操作系统 API 创建桌面安装应用程序。

+   Angular 2 继承了 Angular 1 的所有优点。它用组件取代了控制器和指令。

+   Angular 2 是用 TypeScript 编写的，也让开发人员能够使用 TypeScript 编写 Angular 2 应用程序。

+   Angular 2 比 Angular 1 明显快得多。新的组件路由器只会加载渲染所请求的视图所需的代码。模板语法使开发人员能够快速创建具有强大模板语法的视图。

+   Angular 2 使我们能够使用阴影 DOM（Document Object Model）。阴影 DOM 封装了 CSS、模板和组件。这样就可以与主文档的 DOM 分离。

+   这是更简单的认知模型。Angular 2 中删除了许多指令，这意味着 Angular 2 的部件更少，移动部件也更少，因此使用 Angular 2 比使用 Angular 1 更容易构建更大的应用程序。

### Angular 2 中的开发流程

Angular 2 有两个开发过程，即以下内容：

+   使用转译器

+   没有转译器

#### 什么是 ECMAScript 6？

ES6 是脚本语言规范的最新版本。它是世界范围内用于客户端脚本的 JavaScript 语言。ECMAScript 6 是 JavaScript 语言的一个伟大更新，这些特性正在 JavaScript 引擎中的实现过程中。

#### 什么是转译器？

转译器基本上将任何特定语言转换为 JavaScript。一个很好的例子就是 Typescript 转译器，它将 Typescript 代码转换为 JavaScript。

#### 什么是 TypeScript？

TypeScript 是由微软开发的开源编程语言。它是 JavaScript 的超集，它使程序员能够用 JavaScript 编写面向对象的程序。 TypeScript 还用于开发转译器，将 TypeScript 转换为 JavaScript。它旨在开发更大型的应用程序。 TypeScript 是根据 ECMAScript 标准的提案开发的。 TypeScript 具有类、模块和箭头函数语法等功能，这些功能是 ECMAScript 6 标准中提出的。

##### JavaScript 的开发流程

在讨论使用转译器的开发过程之前，让我们看看特定于 JavaScript 构建 Web 应用程序的开发过程。我们将在**ECMAScript 5**中编写我们的代码并**部署**到**服务器**上。 ECMAScript 5 是今天每个浏览器都理解的脚本。当**浏览器**发出**请求**时，服务器将提供脚本，浏览器将在客户端运行它。下面的图表显示了 JavaScript 的典型开发流程：:

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_01_001.png)

JavaScript 的开发流程

##### 带有构建时转译器的开发

我们不仅可以使用当前版本的 JavaScript（ECMAScript 5）编写脚本，还可以使用 Typecript 编写 **ECMAScript 6+** 的脚本并将其 **转译** 成 **ECMAScript 5**。然后，将转译后的脚本 **部署** 到 **服务器**，然后 **浏览器** 的 **请求** 将提供要在客户端执行的 **转译后的脚本** ，即 ECMAScript 5。这样做的好处是我们可以使用最新版本的 JavaScript 或 ECMAScript 的新功能。

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_01_002.png)

使用构建时转译器的开发过程

##### 使用运行时转译器进行开发

还有一种开发选项称为运行时转译器。在这种情况下，我们首先使用 Typecript 或 CoffeeScript 在 **ECMAScript 6+** 中编写脚本，然后 **部署** 到 **服务器**。当 **请求** 到达 **服务器** 时，它简单地提供在 **浏览器** 中不经转译的 **ECMAScript 6+** 代码。然后，浏览器使用运行时转译器将脚本转译为 **ECMAScript 5** 在客户端执行。这种类型的选项对于生产应用程序不好，因为它会给浏览器增加额外的负载。

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_01_003.png)

使用运行时转译器的开发过程

##### 转译器选项

在 Angular 2 中，我们有两种选项 - 使用转译器或不使用转译器。以下是一些可用的转译器类型：

+   **Traceur**：这是谷歌公司最受欢迎的转译器，可以在构建时模式和运行时模式下使用。

+   **Babel**：这个转译器适用于最新版本的 ECMAScript。

+   **TypeScript**：这是 Angular 中最受欢迎和首选的转译器之一。Angular 团队与 TypeScript 团队合作，他们一起合作构建了 Angular 2。

### Angular 3 发生了什么？

在发布 Angular 2 后，团队决定采用语义版本控制。语义版本控制遵循三数版本控制，表示主要、次要和补丁。补丁版本是版本中的最后一个数字，通常用于修复 bug。次要版本是版本中的中间数字，处理新功能或增强的发布。最后，主要版本是版本中的第一个数字，用于具有重大更改的发布。

Angular 团队从 Angular 2 使用的 TypeScript 1.8 切换到了 TypeScript 2.2。这带来了一些重大变化，很明显需要增加主要版本号。此外，当前路由模块的版本是 3.3.0，与其他仍在 2.3.0 版本的 Angular 模块不一致。因此，为了使所有模块版本保持同步并遵循语义版本控制，Angular 团队决定在下一个主要发布中使用 Angular 而不是 Angular 3。

### Angular 中的新功能是什么？

以下是 Angular 中的新功能：

+   Angular 需要的脚本语言是 TyepScript 2.1+。

+   预编译模式使得 Angular 在构建过程中编译模板并生成 JavaScript 代码。这有助于我们在构建时识别模板中的错误，而不是在运行时。

+   Angular 动画有着自己的包，这意味着你不需要为那些不需要动画的项目提供动画包。

+   模板标签现在已经被弃用，因为它会与 Web 组件中使用的模板 HTML 标签引起混淆。所以，ng-template 被引入作为 Angular 中的模板。

除此之外，还有新功能在代码级别上被引入。

### 为何对于.NET 开发者来说 Angular 是个好选择？

在.NET Web 应用程序中使用 JavaScript 编写客户端代码的复杂性不断增加，比如数据绑定、服务器调用和验证。.NET 开发人员在使用 JavaScript 编写客户端验证时遇到了困难。所以，他们发现并开始使用 jQuery 插件来进行验证，并大多仅仅用来根据用户动作改变视图。在后来阶段，.NET 开发人员得到了能确保代码结构并提供良好功能以简化客户端代码的 JavaScript 库的照顾。然后，他们最终使用了一些市场上的客户端 MVC 框架。然而，他们只是用 MVC 框架来与服务器通信并更新视图。

后来，**SPA**（**单页应用**）的趋势在 Web 开发场景中出现。这种类型的应用将会用一个初始页面提供服务，可能是在布局视图或主视图中。然后，其他视图将在请求时加载到主视图上。这种情景通过实现客户端路由来实现，这样客户端将从服务器请求视图的一小部分而不是整个视图。这些步骤的实现增加了客户端开发的复杂性。

AngularJS 为.NET 开发者带来了福音，使他们能够减少处理应用程序的客户端开发所需的工作，比如 SPA 等。数据绑定是 Angular 中最酷的功能，它使开发人员能够集中精力处理应用程序的其他部分，而不是编写大量代码来处理数据绑定、遍历、操作和监听 DOM。Angular 中的模板只是简单的纯 HTML 字符串，将被浏览器解析为 DOM；Angular 编译器遍历 DOM 以进行数据绑定和渲染指令。Angular 使我们能够创建自定义 HTML 标签并扩展 DOM 中现有元素的行为。通过内建的依赖注入支持，Angular 通过提供它们的实例来解析依赖参数。

## 用 Angular 构建一个 Hello World 应用

* * *

在我们开始构建我们的第一个 Angular 应用之前，让我们设置开发环境来开始使用 Angular 应用。

### 设置开发环境

在编写任何代码之前要做的第一件事是设置本地开发环境。我们需要一个编辑器来编写代码，一个本地服务器来运行应用程序，包管理工具来管理外部库，编译器来编译代码等等。

#### 安装 Visual Studio Code

Visual Studio Code 是用于编写 Angular 应用程序的最佳编辑器之一。因此，我们首先安装 Visual Studio Code。前往[`code.visualstudio.com/`](https://code.visualstudio.com/)，然后点击**`Download Code for Windows`**。Visual Studio Code 支持 Windows、Linux 和 OS X 等平台。因此，根据您的需求也可以在其他平台上下载它。

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_01_004.png)

Visual Studio Code 的首页

Visual Studio Code 是一款开源的跨平台编辑器，支持 Windows、Linux 和 OS X。它是一个功能强大的文本编辑器，包括诸如导航、可自定义绑定的键盘支持、语法高亮、括号匹配、自动缩进和片段等功能，支持许多编程语言。它具有内置的 IntelliSense 代码补全、更丰富的语义代码理解和导航、代码重构支持。它提供了简化的、集成的调试体验，支持 Node.js 调试。它是 Visual Studio 的一个轻量级版本。它不包含任何内置的开发服务器，如 IIS Express。但是，在开发过程中，测试 Web 应用程序在本地 Web 服务器中非常重要。市场上有几种可用的方法来设置本地 Web 服务器。

但是，我选择了 lite-server，因为它是一个轻量级的仅用于开发的 Node 服务器，用于提供静态内容，检测更改，刷新浏览器，并提供许多自定义选项。Lite-server 作为 Node.js 的 NPM 包可用。首先，我们将在下一节看如何安装 Node.js。

#### 安装 Node.js

Node.js 用于开发服务器端 Web 应用程序。它是一个开源的跨平台运行时环境。Node.js 中的内置库允许应用程序充当独立的 Web 服务器。Node.js 可用于需要轻量级实时响应的场景，例如通讯应用程序和基于 Web 的游戏。

Node.js 可用于多种平台，如 Windows、Linux、Mac OS X、Sun OS 和 ARM。您还可以下载 Node.js 的源代码，并根据您的需求进行定制。

要安装 Node.js，请前往[`nodejs.org/en/`](https://nodejs.org/en/)，并下载适用于 Windows 的成熟可靠的 LTS（长期支持）版本。

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_01_005.png)

Node.js 的首页

Node.js 带有 NPM，一个用于获取和管理 JavaScript 库的软件包管理器。要验证 Node.js 和 NPM 的安装是否成功，请按照以下步骤进行检查：

1.  打开 Windows 命令提示符，输入`node -v`命令并运行。您将得到我们安装的 Node.js 的版本。

1.  现在，检查 NPM 是否与 Node.js 一起安装。运行`NPM -v`命令，您将得到已安装的 NPM 的版本号。

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_01_006.png)

使用命令验证 Node.js 和 NPM 安装的命令提示符

现在，我们拥有了写我们的第一个 Angular 应用程序所需的一切。让我们开始吧。

### 创建一个 Angular 应用程序

我假设您已经安装了 Node.js、NPM 和 Visual Studio Code，并准备好用它们进行开发。现在，让我们按照以下步骤通过克隆 git 存储库创建一个 Angular 应用程序：

1.  打开 Node.Js 命令提示符并执行以下命令：

```ts
      git clone https://github.com/angular/quickstart my-
      angular
```

这个命令将克隆 Angular 快速起步存储库，并为你创建一个名为`my-angular`的 Angular 应用程序，其中包含所需的所有样板代码。

1.  使用 Visual Studio Code 打开克隆的`my-angular`应用程序：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_01_007-2.png)

my-angular 应用程序的文件夹结构

文件夹结构和样板代码按照[`angular.io/docs/ts/latest/guide/style-guide.html`](https://angular.io/docs/ts/latest/guide/style-guide.html)上的官方样式指南进行组织。`src`文件夹中包含与应用程序逻辑相关的代码文件，`e2e`文件夹中包含与端到端测试相关的文件。现在不要担心应用程序中的其他文件。现在让我们只关注`package.json`。

1.  点击`package.json`文件；它将包含有关元数据和项目依赖项配置的详细信息。以下是`package.json`文件的内容：

```ts
      {
      "name":"angular-quickstart",
      "version":"1.0.0",
      "description":"QuickStart package.json from the 
      documentation,             
      supplemented with testing support",
      "scripts":{
      "build":"tsc -p src/",
      "build:watch":"tsc -p src/ -w",
      "build:e2e":"tsc -p e2e/",
      "serve":"lite-server -c=bs-config.json",
      "serve:e2e":"lite-server -c=bs-config.e2e.json",
      "prestart":"npm run build",
      "start":"concurrently \"npm run build:watch\" \"npm 
      run serve\"",
      "pree2e":"npm run build:e2e",
      "e2e":"concurrently \"npm run serve:e2e\" \"npm run 
      protractor\"             
      --kill-others --success first",
      "preprotractor":"webdriver-manager update",
      "protractor":"protractor protractor.config.js",
      "pretest":"npm run build",
      "test":"concurrently \"npm run build:watch\" \"karma 
      start             
      karma.conf.js\"",
      "pretest:once":"npm run build",
      "test:once":"karma start karma.conf.js --single-
      run",
      "lint":"tslint ./src/**/*.ts -t verbose"
      },
      "keywords":[
      ],
      "author":"",
      "license":"MIT",
      "dependencies":{
      "@angular/common":"~4.0.0",
      "@angular/compiler":"~4.0.0",
      "@angular/core":"~4.0.0",
      "@angular/forms":"~4.0.0",
      "@angular/http":"~4.0.0",
      "@angular/platform-browser":"~4.0.0",
      "@angular/platform-browser-dynamic":"~4.0.0",
      "@angular/router":"~4.0.0",
      "angular-in-memory-web-api":"~0.3.0",
      "systemjs":"0.19.40",
      "core-js":"².4.1",
      "rxjs":"5.0.1",
      "zone.js":"⁰.8.4"
      },
      "devDependencies":{
      "concurrently":"³.2.0",
      "lite-server":"².2.2",
      "typescript":"~2.1.0",
      "canonical-path":"0.0.2",
      "tslint":"³.15.1",
      "lodash":"⁴.16.4",
      "jasmine-core":"~2.4.1",
      "karma":"¹.3.0",
      "karma-chrome-launcher":"².0.0",
      "karma-cli":"¹.0.1",
      "karma-jasmine":"¹.0.2",
      "karma-jasmine-html-reporter":"⁰.2.2",
      "protractor":"~4.0.14",
      "rimraf":"².5.4",
      "@types/node":"⁶.0.46",
      "@types/jasmine":"2.5.36"
      },
      "repository":{
      }
      }
```

1.  现在，我们需要在命令窗口中运行 NPM install 命令，通过导航到应用程序文件夹来安装`package.json`中指定的必需依赖项：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_01_008-2.png)

执行 NPM 命令来安装 package.json 中指定的依赖项

1.  现在，您将会在`node_modules`文件夹下添加所有的依赖项，如下图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_01_009-2.png)

`node_modules`文件夹下的依赖项

1.  现在，让我们运行这个应用程序。要运行它，在命令窗口中执行以下命令：

```ts
 npm start
```

1.  打开任何浏览器，并导航到`http://localhost:3000/`；您将会在应用程序中看到以下页面。运行这个命令会构建应用程序，启动 lite-server，并在上面托管应用程序。

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_01_010-2.png)

在 VS Code 中激活调试窗口

现在让我们详细看一下`index.html`的内容。以下是`index.html`的内容：

```ts
<!DOCTYPE html>
<html>
<head>
<title>Hello Angular </title>
<base href="/">
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="stylesheet" href="styles.css">
<!-- Polyfill(s) for older browsers -->
<script src="img/shim.min.js"></script>
<script src="img/zone.js"></script>
<script src="img/system.src.js"></script>
<script src="img/systemjs.config.js"></script>
<script>
System.import('main.js').catch(function(err){ console.error(err); });
</script>
</head>
<body>
<my-app>My first Angular app for Packt Publishing...</my-app>
</body>
</html>
```

到目前为止，我们已经看到了如何通过克隆 GitHub 上的官方 QuickStart 存储库来创建 Angular 应用程序。我们将在接下来的章节详细介绍创建 Angular 应用程序的步骤。请注意，脚本是使用 System.js 加载的。System.js 是在运行时加载模块的模块加载器。

## Angular 的架构

* * *

在我们跳转到 Angular 上的 Hello World 应用程序之前，请让我快速介绍一下 Angular 的架构。Angular 的架构由八个核心构建块组成：模块，组件，模板，元数据，数据绑定，服务，指令和依赖注入。

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_01_011.png)

Angular 的架构

一个 Angular 应用程序通常是从使用 Angular 标签或标记设计模板开始。然后，我们编写组件来处理模板。应用程序特定的逻辑将添加到服务中。最后，起始组件或根组件将传递给 Angular 启动器。

当我们运行应用程序时，Angular 负责向浏览器呈现模板，并根据组件和指令中提供的逻辑处理模板中元素的用户交互。

让我们看看 Angular 的每个模块的目标：

+   任何 Angular 应用程序都将由一组组件组成。

+   服务将被注入组件中。

+   模板负责以 HTML 形式呈现组件。

+   组件包含支持视图或模板的应用程序逻辑。

+   Angular 本身是一组模块。在 Angular 1 中，使用`ng-app`指令引导主模块或应用程序模块。我们可以包含我们的应用程序模块或主模块依赖的其他模块列表；它们将在`angular.module('myApp', [])`中定义为空数组。Angular 使用 ES6 模块，模块中定义的函数或变量应显式导出以供其他模块消费。通过使用 import 关键字，导出的函数或变量可在其他模块中使用，后跟函数名，然后跟随模块名。例如，`import {http}` from `@angular/http`。

+   每个 Angular 库实际上是许多相关的私有模块的外观。

+   指令提供指令以呈现模板。

我们将在接下来的章节中详细介绍 Angular 架构的每个构建块。

## 总结

* * *

很简单，不是吗？我们刚刚向您介绍了 Angular 框架。

我们从 AngularJS 的历史开始。然后，我们讨论了 AngularJS 的优点和 AngularJS 的诞生。我们讨论了 Angular 的新功能，并对 Angular 的架构进行了简要介绍。

我们还看到了编写 Angular 应用程序所需的开发环境设置。

最后，我们演示了如何使用 Visual Studio Code 和 Node.js 创建你的第一个 Angular 应用程序。

这一章节我们有了一个很好的开端，在学习了一些基础知识。然而，这只是开始。在下一章中，我们将讨论 Angular 架构的一些核心构建模块，比如模块、组件、模板和指令。让我们开始吧！


## 第二章：Angular 构建模块 - 第一部分

本章将详细介绍 Angular 架构的核心构建模块。

在本章中，我们将涵盖以下主题：

+   模块

+   组件

+   装饰器和元数据

+   模板

+   绑定

+   指令

+   依赖注入

## 模块（NgModules）

* * *

模块是实现不同功能的单个实现单元。通过多个模块的集合来实现复杂的应用程序。实现模块模式有助于避免变量和方法的全局冲突。JavaScript 通过实现模块模式将私有方法和公共方法封装在单个对象中。模块模式在 JavaScript 中使用闭包来实现封装。JavaScript 不支持访问修饰符；然而，使用函数作用域可以实现相同的效果。所有的 Angular 应用都是模块化的。我们通过创建许多模块来开发 Angular 应用。我们开发模块来封装独立且具有单一职责的功能。一个模块导出该模块中可用的类。Angular 模块称为`NgModules`。在任何 Angular 应用程序中都会至少存在一个 Angular 模块：根模块，它被表示为`AppModule`。`AppModule`是一个被`@NgModule`装饰的类。

```ts
AppModule class:
```

```ts
import { NgModule }      from '@angular/core'; 
import { BrowserModule } from '@angular/platform-browser'; 
@NgModule({ 
  imports:      [ BrowserModule ], 
  providers:    [ Logger ], 
  declarations: [ AppComponent ], 
  exports:      [ AppComponent ], 
  bootstrap:    [ AppComponent ] 
}) 
export class AppModule { } 
```

在上述代码中，从`@angular/core`导入的`NgModule`被装饰为`AppModule`类。请注意，`NgModule`具有一些重要属性，如 imports、exports、providers、declarations 和 bootstrap。

元数据声明应该分配给视图类，如组件、指令和管道，这些类属于该模块。元数据的 exports 将被分配给在组件模板中可用的组件、指令或管道。元数据的 imports 应该分配给组件模板中使用的导出类。元数据 provider 将分配给在整个应用程序中使用或访问的服务。它创建分配的服务的实例，并将其添加到服务的全局集合中，以便这些服务可以在整个 Angular 应用程序中被消耗。元数据 bootstrap 分配给负责渲染应用程序主视图的根组件。

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_02_001.png)

Angular 模块

一个示例`AppComponent`类如下所示。该`export`语句公开了组件，并且`AppComponent`类可被应用程序中的其他模块访问：

```ts
export class AppComponent { } 
```

类是包含对象方法和变量定义的模板。对象是类的一个实例，因此它可以保存变量的真实值，并且方法可以针对实际值执行操作。注意，当前版本的 JavaScript 不支持类。它是一种无类语言。在 JavaScript 中，一切都是对象，并且函数被用来模拟类。ECMAScript 6 通过在 JavaScript 中引入类来引入对 JavaScript 基于原型的继承的一种语法糖。

在这里，我们利用了 TypeScript 作为 JavaScript 的超集的能力。语句中的 export 关键字表示我们正在向应用程序的其他模块导出或公开一个`AppComponent`类。

假设我们已经把这个组件保存在一个名为`app.component.ts`的文件中。为了访问或引用被公开的`AppComponent`类，我们需要在我们将要访问的文件中导入它。下面的语句完成了这个操作：

```ts
import {AppComponent} from './app.component';
```

在这里，语句中的 import 关键字表示我们正在导入一个被公开的类：`AppComponent`。from 关键字表示或指向导入组件所在的文件或模块。例如，在我们的情况下，它是`app.component.ts`。一个模块名是组件的文件名去掉扩展名；所以，在这里，模块名是`app.component`。我们用相对文件路径(`./`)开头的模块文件名，并表示相同的文件夹。

模块也可以包含其他模块的集合，这样的模块被称为库模块。Angular 本身有许多库模块。一些库模块是核心，公用，路由等。我们从`@angular/core`库模块中导入`Component`，这是我们大多数情况下使用的主要模块：

```ts
import {Component} from '@angular/core'; 
```

所有的 Angular 库模块都将在 from 子句中以没有相对文件路径的方式提及。

## 组件

* * *

AngularJS 具有控制器，作用域和指令来处理视图，绑定数据，并通过更新数据来响应事件。在 Angular 中，组件取代了 AngularJS 的控制器，作用域和指令。

Angular 引入了支持面向对象组件模型的组件，以编写更干净的代码。一个组件是一个简单的类，它保持管理相关模板或视图的逻辑。一个简单的组件类如下所示：

```ts
Class FirstComponent { 
} 
```

在组件类中，我们将属性和方法暴露给模板或视图。组件属性可以为模板或视图提供数据，并允许用户修改属性值。根据用户在视图上的操作，可以调用组件方法。

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_02_002.png)

Angular 组件 FirstComponent

正如你所看到的，上述代码创建了一个名为`**`FirstComponent`**`的简单 JavaScript 类。也许你想知道一个 JavaScript 普通类如何被视为组件，模板如何与这个类被连接起来。为了实现这一点，Angular 利用了 TypeScript 语法来按照 2015 年的 ES6 规范对`**`FirstComponent`**`类进行注释，将其声明为组件并将模板与选择器的标识符进行连接。下面的代码展示了带有注释的组件类，声明类为组件并用模板将其与标记标识符连接起来：

```ts
import { Component } from '@angular/core';
@Component({
  selector: 'first-component',
  template: `<h1>{{getGreetingPhrase()}} {{name}}</h1>`,
})
export class FirstComponent {
  name: string;
  constructor() {
  this.name = 'Rajesh Gunasundaram';
}
getGreetingPhrase() {
  return 'Hello Author,';
}
}
getGreetingPhrase() function to fetch and display the phrase to greet, and it will also access the name property to display the name. The @Component()Â preceding the FirstComponent class is the annotation that denotes this class is a Component, and the markup identifier first component for this component is assigned to the metadata of @Component named selector.
```

也许你会惊讶地发现我们没有使用`$scope`来暴露`FirstComponent`的属性和方法。在这里，我们的组件实例化并可在模板或视图中使用。因此，我们可以访问该实例的任何属性；同时，我们可以根据用户在视图或模板中的操作或输入调用实例中的方法。组件实例提供了有关该实例的封装数据，类似于 AngularJS 中的隔离作用域。

当根组件的模板具有另一个组件选择器的特殊标记时，Angular 中的组件可以继承，并且这也使子组件能够访问其父级和同级组件。

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_02_003.png)

应用程序的组件层次结构

### 组件的生命周期

Angular 管理组件的生命周期。Angular 负责创建和渲染组件及其子组件，并在从 DOM 中删除之前销毁它们。Angular 跟踪组件属性值的变化。以下是 Angular 组件的生命周期事件按调用顺序给出：

+   **OnChanges**: 当绑定值发生变化时会触发此事件。此方法将有权访问旧值和新值。

+   **OnInit**: 这个事件在由于绑定值的更改而执行`OnChanges`事件之后触发。

+   **DoCheck**: 这个事件会在检测到每次变化时被触发，开发人员可以编写自定义逻辑来检查属性的变化。

+   **AfterContentInit**: 当指令的内容完全初始化后将触发此事件。

+   **AfterContentChecked**: 这个事件将在指令内容被检查后触发。

+   **AfterViewInit**: 当组件模板完全初始化后将触发此事件。

+   **AfterViewChecked**: 这个事件将在组件模板被检查后触发。

+   **OnDestroy**: 这个事件将在销毁指令或组件之前触发。

您可以实现所有这些事件，也可以只实现组件所需的特定事件。

## 装饰器和元数据

* * *

如您在上一节中所看到的，我们为组件定义了 JavaScript 普通类，并对其进行了一些信息注释，以通知 Angular 框架该类是一个组件。

我们利用了 Typescript 语法，并使用装饰符功能将类附加元数据。为了使一个类成为组件，我们添加`@Component`装饰符，如下所示：

```ts
@Component({...})
export class FirstComponent {...}
FirstComponent class has been decorated as a component.
```

现在，让我们使用装饰符语法为`FirstComponent`类附加元数据：

```ts
@Component({ 
   selector: 'first-component', 
   templateUrl: 'app/first.component.html' 
}) 
export class FirstComponent {...} 
```

在这里，我们已经添加了诸如选择器和`templateUrl`之类的元数据。组件中配置的选择器元数据告诉 Angular 在遇到`<first-controller>`标记时创建该组件的实例：

```ts
<first-controller></first-controller> 
```

`templateUrl`提供了组件渲染的模板文件的 URL。当您运行应用程序时，`<first-controller>`标记将被`templateUrl`中引用的模板内容替换。此元数据实际上是`@Component`装饰符的一个参数，而装饰符是一个函数。

通过装饰符添加元数据，我们实际上告诉 Angular 如何处理定义的类。组件、模板和元数据一起构成一个视图。

## 模板

* * *

当对组件进行注解时，您可能已经注意到我们为视图或模板添加了内联标记。我们还可以添加一个模板 URL，将视图或模板标记隔离在一个单独的 HTML 文件中，而不是将其作为内联视图或模板。

模板由 HTML 标记组成，向 Angular 提供有关呈现组件的信息。以下代码行中给出了一个简单的模板内容。它呈现了书名和出版商：

```ts
<div> 
  The Name of the book is {{bookName}} and is published by {{pubName}}. 
</div> 
```

### 内联模板

内联模板在需要呈现非常简单内容（例如一行）时使用。在这种情况下，内联视图或模板将直接在注释中定义：

```ts
@Component({ 
  selector: 'first-component', 
  template: "<div>{{getGreetingPhrase()}} {{name}}</div>" 
}) 
```

### 隔离模板

隔离模板主要用于模板包含更多内容的情况。在这种情况下，内容将被移到一个单独的文件中，并将 HTML 文件的 URL 分配给`templateUrl`，如下所示：

```ts
@Component({ 
  selector: 'first-component', 
  templateUrl: FirstPage.html' 
}) 
```

### 本地模板变量

Angular 允许创建模板作用域变量，在模板中移动数据：

```ts
<div *ngFor="let todo of todos"> 
  <todo-item [todo]="todo"></todo-item> 
</div> 
```

在前面的模板标记中，我们使用 let 关键字声明了一个本地变量 todo。然后，我们遍历 todos 集合变量；每个 todo 项目都被分配给 todo，并且可以在`<todo-item>`中使用。

也可以使用本地模板变量来保存 DOM 元素。以下代码显示了作者将保存输入元素本身，并且可以使用 author.value 访问元素的值：

```ts
<!-- author refers to input element and passes its `value`to the event handler --> 
<input #author placeholder="Author Name"> 
<button (click)="updateAuthor(author.value)">Update</button> 
```

## 绑定

* * *

绑定技术将使您能够将数据绑定到模板，并允许用户与绑定的数据进行交互。Angular 绑定框架负责将数据呈现到视图，并根据用户在视图上的操作进行更新。

以下截图让您快速了解了 Angular 中各种绑定技术。我们将逐个详细介绍每种绑定技术：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_02_004.png)

各种绑定语法

### 单向绑定

诸如`插值`、`属性`、`属性`、`类`和`样式`等绑定类型支持从数据源（从组件公开）到视图或模板的单向数据流。让数据从组件属性或方法流向模板的模板标记在下表中给出（单向绑定）：

| **模板代码** | **描述** |
| --- | --- |
| `{{表达式}}` | 这显示了从数据源构建的表达式 |
| `[目标]` = "表达式" | 这将数据源的表达式分配给目标属性 |
| `bind-target` = "表达式" | 这将数据源的表达式分配给绑定目标属性 |

让数据从模板流向组件属性或方法的模板标记在下表中给出（单向绑定）：

| **模板代码** | **描述** |
| --- | --- |
| `(目标)` = "语句" | 这将数据源的表达式分配给目标属性 |
| `on-target` = "语句" | 这将数据源的表达式分配给绑定目标属性 |

### 内插绑定

内插是Â Angular 的主要特性之一。您可以将任何属性值或表达式插值到任何 HTML 元素的内容中，例如`div`和`li`。您可以通过双大括号`{{和}}`来实现此目的，如下行代码所示：

```ts
<div>Hello, {{authorName}}!</div>
```

在这里，我们将`authorName`插值到`div`标签的内容中。这是一种单向绑定，其中数据从组件属性或方法流向模板。

### 属性绑定

属性绑定用于将组件属性绑定到 HTML 元素属性：

```ts
<div [hidden]="hidePubName>Packt Publishing</div> 
hidePubName component property to the div property hidden. This is also a one-way binding where the data flows from a component property to a template.
```

### 事件绑定

HTML 元素具有各种 DOM 事件，当事件触发时将触发。例如，单击按钮时将触发点击事件。我们挂钩事件监听器以便在事件触发时得到通知：

```ts
<button (click)="doSomething()">Do Something</button>
```

前面的 Angular 代码片段将事件名称放在括号中，需要挂接事件监听器，以便在触发单击事件时调用它。

### 双向绑定

Angular 已经从其框架中移除了一个核心功能，这是 AngularJS 诞生的一个主要原因，即双向绑定。因此，默认情况下不支持双向绑定。现在，让我们看看如何在 Angular 中实现双向绑定。

Angular 结合属性和事件绑定，使我们能够实现双向绑定，如下面的代码所示：

```ts
<input [(ngModel)]="authorName">
ngModel is wrapped with parentheses and then with square brackets. The parentheses indicate that the component property is tied up with the ngChange event, and the square brackets indicate that the component property is assigned to a value property of the input element. So, when the value of the input element changes, it fires up the change event that eventually updates authorName with the new value from the event object. ngModel in the markup is the built-in directive in Angular that unifies property and event binding.
```

可以帮助数据双向流动的模板标记，从模板到组件，从组件到模板，如下表所示（双向绑定）：

| **模板代码** | **描述** |
| --- | --- |
| `[(目标)]` = "表达式" | 这将数据源的表达式分配给目标属性 |
| `bindon-target` = "表达式" | 这将数据源的表达式分配给绑定目标属性 |

## 指令

* * *

我们详细介绍了 Angular 组件及其装饰方式。`@Component` 本身是一个带有在元数据中配置的模板的指令。因此，一个没有模板的指令是一个组件，而 `@directive` 在 Typescript 中用于附加元数据。

### 结构指令

结构指令处理通过添加新元素、删除现有元素和用新元素替换现有元素来修改 DOM 中的元素。下面的标记显示了两个结构指令：`*ngFor` 和 `*ngIf`：

```ts
<div *ngFor="#todo of todos"></div> 
<todo-item *ngIf="selectedTodo"></todo-item> 
```

`*ngFor` 遍历 todos 集合中的每个项目，并为每个项目添加一个 `div` 标签。而 `*ngIf` 仅在 selectedTodo 可用时呈现 `<todo-item>`。

### 属性指令

属性指令将像属性一样添加到现有的 HTML 元素中，并且可以修改或扩展 HTML 元素的行为。例如，如果将 ngModel 指令添加到输入元素中，它将通过更新其 value 属性和响应更改事件来扩展它：

```ts
<input [(ngModel)]="author.name">
```

除了使用现有的指令，我们还可以编写自己的指令，比如 `ngSwitch`、`ngStyles` 和 `ngClass`。

## 依赖注入

* * *

依赖注入是一种处理依赖关系并解决它们的设计模式。依赖项的实例将传递给依赖项，以便使用它。如果客户端模块或类依赖于一个服务，它需要在使用之前创建该服务的一个实例。我们可以使用依赖注入模式注入或传递服务的实例给客户端，而不是客户端模块构建服务。

应用依赖注入使我们能够创建一个不知道要构建的服务和实际消费的服务的客户端。客户端只会知道服务的接口，因为它需要知道如何使用服务。

### 为什么依赖注入？

假设我们正在创建一个 `Mobile` 类，并且它依赖于 `camera` 和 `internet` 连接。

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_02_005.png)

Mobile 类的代码片段

```ts
Camera and Internet areÂ created in the constructor of the MobileÂ class. These are the features of Mobile. Instead of requesting for the feature, the Mobile class created the feature by itself. This means that the Mobile class is bound to a certain version of features, such as a 2 MP camera and 2G Internet. Later, if we want to upgrade the camera to 20 MP and Internet to 3G or 4G, we need to rewrite the code of the Mobile class.
```

`Mobile` 类依赖于 `Camera` 和 `Internet`，这增加了测试的难度。我们只能用 2G 互联网和 2 MP 相机来测试 Mobile，因为我们无法控制依赖，因为 `Mobile` 类通过自身负责依赖的实例。

现在，让我们修改构造函数，接收 `Camera` 和 `Internet` 的实例作为参数，如下面的代码行所示：

```ts
constructor(public camera: Camera, public internet: Internet) { } 
```

现在，`Mobile` 类将不再创建 `Camera` 或 `Internet` 的实例。它只消耗从构造函数参数中收到的 `Camera` 或 `Internet` 的实例。这意味着我们将依赖项移到了构造函数中。客户端可以通过向构造函数传递 `Camera` 和 `Internet` 的实例来创建一个 `Mobile` 类，如下面的代码片段所示：

```ts
// Simple mobile with 2MP camera and 2G internet. 
var mobile = new Mobile(new Camera2MP(), new Internet2G()); 
```

您可以看到`Camera`和`Internet`的定义已经与`Mobile`类解耦。只要客户端传递的`Camera`和`Internet`类型符合`Camera`和`Internet`的接口，我们就可以传递任何类型的具有不同百万像素的摄像头和不同带宽的互联网，比如 2G，3G 和 4G。

```ts
// an advanced mobile with 20MP camera and 4G internet. 
var mobile = new Mobile(new Camera20MP(), new Internet4G()); 
```

在`Mobile`类中没有改变，以适应 20 MP 摄像头和 4G 互联网的依赖性。`Mobile`类更容易通过各种组合的`Camera`和`Internet`进行测试，因为我们对依赖性有完全的控制。我们还可以在测试中使用模拟技术，并将`Camera`和`Internet`的模拟传递给构造函数，以便所有必要的操作都将针对`Camera`和`Internet`的模拟进行。

### 注入器的作用

我们刚刚了解了什么是依赖注入，以及它如何从外部客户端接收依赖性而不是自己创建它们。然而，客户端需要更新其代码，以传递 20 MP 摄像头和 4G 互联网依赖的实例。任何想要使用`Mobile`类的客户端都必须创建`Camera`和`Internet`的实例，因为`Mobile`类依赖于它们。我们从`Mobile`类中消除了创建依赖实例的责任，并将其移动到将使用`Mobile`类的客户端。

现在，成为可怜的客户端的问题，要创建`Camera`和`Internet`的实例。因此，为了减少客户端创建依赖实例的额外工作，我们需要注入器来负责为客户端组装所需的`Camera`和`Internet`的实例。依赖注入框架有一个叫做注入器的东西，我们在其中注册我们的类，比如`Mobile`。然后我们可以请求注入器为我们创建`Mobile`的实例。注入器将负责解析依赖关系并创建`mobile`，如下面的代码行所示：

```ts
var mobile = injector.get(Mobile); 
```

### 在 Angular 中处理依赖注入

Angular 有自己的依赖注入框架，并且我们将通过一个示例看到它如何处理依赖注入。

首先，我们将在`app/todos/todo.ts`下创建一个`Todo`类，该类具有诸如`id`，`description`和`isCompleted`等属性，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_02_006.png)

Todo 类的代码片段

然后，创建一个`TodoListComponent`组件，并添加一个属性来保存从注入的`TodoService`检索到的待办事项集合。当依赖注入框架实例化`TodoListComponent`时，服务将被注入到构造函数中。您将在第三章*Angular 构建块-第二部分*中了解更多关于服务的内容。

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_02_007.png)

TodoListComponent 类的代码片段

代码是使用 Typescript 编写的，当它将代码编译为 JavaScript 时，会包含有关类元数据的信息，因为类被装饰为 `@component`。这个类元数据包含了关联`todoService`参数和`TodoService`类的信息。这使得 Angular 注入器在创建新的 `TodoListComponent` 时能够注入 `TodoService` 的实例。

在我们的代码中，我们不需要显式调用注入器来注入服务。相反，Angular 的自动依赖注入会处理它。当 Angular 遇到通过 HTML 标记或通过路由导航到组件时遇到`<todo-list>`选择器时，注入器会在实例化组件的同时被隐式调用。

现在，我们将创建 `TodosComponent`，在 `@Component` 指令的 providers 参数中注册 `TodoService`。`TodoService` 的实例在`TodosComponent`中和它的所有子项中都可以被注入使用。

```ts
import { Component } from '@angular/core';
import { TodoListComponent } from './todo-list.component';
@Component({
  selector: 'my-todos',
  template: '<h2>Todolist</h2><todo-list></todo-list>',
  providers: [TodoService],
  directives: [TodoListComponent]
})
export class TodosComponent { }
```

现在，让我们创建返回待办事项集合的 `TodoService` 服务。

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_02_008.png)

TodoService 的代码片段

在生产环境的 `TodoList` 应用程序中，`TodoService` 中的 `getTodos` 方法将进行一个 HTTP 请求来获取待办事项列表。在基本情况下，我们从`mock-todos`中返回待办事项的集合。

最后，我们需要创建 `mock-todos`，其中包含待办事项的集合，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_02_009.png)

`mock-todos` 的代码片段

该文件用作内存中的集合，以保存待办事项，并且可以在导入该文件的组件中使用。这种方法适用于开发阶段，但在生产阶段需要从远程服务器获取待办事项。

在 VS Code 中按下*F5*运行应用程序，您将得到 Angular TodoList 应用程序的输出，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/todoapp.png)

在浏览器中运行的 TodoList 应用程序

## 总结

* * *

哇！到现在为止，您一定已经学到了很多关于 Angular 架构的核心构建块。我们从 e 开始，讨论了它如何封装了独立且具有单一职责的功能。然后，您学习了组件的概念，以及它们如何取代了 AngularJS 中的控制器、作用域和指令。您还了解了装饰器和元数据，它们利用了 Typescript 语法将普通的 JavaScript 类转换为 Angular 组件。然后，我们讨论了模板以及内联模板和独立模板之间的区别。您还学习了如何在模板中实现各种绑定技术。稍后，我们通过指令讨论了指令以及指令与组件的区别。最后，您学习了一个最受欢迎的设计模式之一，依赖注入，以及它如何被 Angular 处理。

在下一章中，我们将讨论 Angular 架构中剩下的部分。


## 第三章：Angular 构建模块-第二部分

本章将详细介绍 Angular 架构中尚未涵盖的核心构建模块。 在本章中，我们将涵盖以下主题：

+   表单

+   管道

+   路由

+   服务

+   观察者

## 表单

* * *

每个应用程序都有一个数据输入点，它使最终用户能够输入数据。表单旨在向服务器和页面插入或更新输入数据。在提交以进行进一步操作之前，应验证输入数据。应用了两种类型的验证方法：客户端验证和服务器端验证：

+   **服务器端验证**：服务器端验证将由服务器处理。 收到的信息将由服务器处理和验证。 如果提交表单时存在任何错误，则需要使用适当的信息更新 UI。 如果信息无效或不足，则将适当的响应发送回客户端。 这种验证方法更加安全，因为即使浏览器中关闭了 JavaScript，它也可以工作，并且恶意用户无法绕过服务器端验证。 但是，这种方法的缺点是只有在将表单提交到服务器后才会验证表单。 因此，用户必须等到完全提交表单到服务器，才能知道所提供的所有数据是否有效。

+   **客户端验证**：虽然服务器端验证更加安全，但它不会提供更好的用户体验。 使用脚本语言，如 JavaScript，实现客户端验证，并在客户端上进行验证。 用户输入的数据可以在用户输入时验证。 这会通过在屏幕上提供验证错误的即时响应，提供更丰富的体验。 用户无需等待整个表单提交，即可知道输入的数据是否有效。

Angular 具有 FormBuilder、Control 和 Validators 等类来处理表单。 它使您能够使用 Control 和 Validators 轻松设置验证规则。

### 表单工具

Angular 有各种工具可实现应用程序中的表单。 以下是这些工具及其各自的目的：

+   **控件**：这些通过封装表单的输入提供对象

+   **验证器**：这些有助于验证表单中的输入数据

+   **观察者**：这些有助于跟踪表单中的更改并通知用户任何验证错误

### Angular 形式的类型

Angular 提供了两种处理表单的方法：模板驱动表单和模型驱动表单。

#### 模板驱动表单

AngularJS 使用`ng-model`指令处理表单，并利用了使开发人员生活更轻松的双向绑定功能。 Angular 使开发人员能够使用`ngModel`构建模板驱动表单，这类似于 AngularJS 中的`ng-model`。

以下是模板驱动表单的实现：

1.  让我们在 **Visual Studio Code**（**VS Code**）中创建一个名为 First Template Form 的应用程序。

1.  在 `package.json` 中添加所需的包和依赖详情，并使用 `npm` install 命令进行安装。

```ts
      {
      "name":"first-template-form",
      "version":"1.0.0",
      "private":true,
      "description":"First template form",
      "scripts":{
      "test:once":"karma start karma.conf.js --single-
       run",
      "build":"tsc -p src/",
      "serve":"lite-server -c=bs-config.json",
      "prestart":"npm run build",
      "start":"concurrently \"npm run build:watch\" \"npm  
       run serve\"",
      "pretest":"npm run build",
      "test":"concurrently \"npm run build:watch\" \"karma 
       start 
      karma.conf.js\"",
      "pretest:once":"npm run build",
      "build:watch":"tsc -p src/ -w",
      "build:upgrade":"tsc",
      "serve:upgrade":"http-server",
      "build:aot":"ngc -p tsconfig-aot.json && rollup -c  
       rollup-
      config.js",
      "serve:aot":"lite-server -c bs-config.aot.json",
      "build:babel":"babel src -d src --extensions 
      \".es6\" --source-
      maps",
      "copy-dist-files":"node ./copy-dist-files.js",
      "i18n":"ng-xi18n",
      "lint":"tslint ./src/**/*.ts -t verbose"
      },
      "keywords":[
      ],
      "author":"",
      "license":"MIT",
      "dependencies":{
      "@angular/common":"~4.0.0",
      "@angular/compiler":"~4.0.0",
      "@angular/compiler-cli":"~4.0.0",
      "@angular/core":"~4.0.0",
      "@angular/forms":"~4.0.0",
      "@angular/http":"~4.0.0",
      "@angular/platform-browser":"~4.0.0",
      "@angular/platform-browser-dynamic":"~4.0.0",
      "@angular/platform-server":"~4.0.0",
      "@angular/router":"~4.0.0",
      "@angular/tsc-wrapped":"~4.0.0",
      "@angular/upgrade":"~4.0.0",
      "angular-in-memory-web-api":"~0.3.1",
      "core-js":"².4.1",
      "rxjs":"5.0.1",
      "systemjs":"0.19.39",
      "zone.js":"⁰.8.4"
      },
      "devDependencies":{
      "@types/angular":"¹.5.16",
      "@types/angular-animate":"¹.5.5",
      "@types/angular-cookies":"¹.4.2",
      "@types/angular-mocks":"¹.5.5",
      "@types/angular-resource":"¹.5.6",
      "@types/angular-route":"¹.3.2",
      "@types/angular-sanitize":"¹.3.3",
      "@types/jasmine":"2.5.36",
      "@types/node":"⁶.0.45",
      "babel-cli":"⁶.16.0",
      "babel-preset-angular2":"⁰.0.2",
      "babel-preset-es2015":"⁶.16.0",
      "canonical-path":"0.0.2",
      "concurrently":"³.0.0",
      "http-server":"⁰.9.0",
      "jasmine":"~2.4.1",
      "jasmine-core":"~2.4.1",
      "karma":"¹.3.0",
      "karma-chrome-launcher":"².0.0",
      "karma-cli":"¹.0.1",
      "karma-jasmine":"¹.0.2",
      "karma-jasmine-html-reporter":"⁰.2.2",
      "karma-phantomjs-launcher":"¹.0.2",
      "lite-server":"².2.2",
      "lodash":"⁴.16.2",
      "phantomjs-prebuilt":"².1.7",
      "protractor":"~4.0.14",
      "rollup":"⁰.41.6",
      "rollup-plugin-commonjs":"⁸.0.2",
      "rollup-plugin-node-resolve":"2.0.0",
      "rollup-plugin-uglify":"¹.0.1",
      "source-map-explorer":"¹.3.2",
      "tslint":"³.15.1",
      "typescript":"~2.2.0"
      },
      "repository":{
      }
      }
```

1.  创建一个书籍类，并添加以下代码片段：

```ts
      export class Book {
      constructor(
      public id: number,
      public name: string,
      public author: string,
      public publication?: string
      ) { }
      }
```

1.  创建 `AppComponent`，并添加以下代码：

```ts
      import { Component } from '@angular/core';
      @Component({
      selector: 'first-template-form',
      template: '<book-form></book-form>'
      })
      export class AppComponent { }
```

这里展示的 `AppComponent` 是应用程序的根组件，将托管 `BookFormComponent`。`AppComponent` 被装饰为第一个模板表单选择器，模板中包含带有`<book-form/>`特殊标签的内联 HTML。这个标签在运行时将被更新为实际模板。

1.  现在，让我们使用以下代码片段向 `book-form.component.ts` 中添加代码：

```ts
      import { Component } from '@angular/core';
      import { Book } from './book';
      @Component({selector: 'book-form',
      templateUrl: './book-form.component.html'
      })
      export class BookFormComponent {
      model = new Book(1, 'book name','author 
      name','publication name 
      is optional');
      onSubmit() {
      // code to post the data
      }
      newBook() {
      this.model = new Book(0,'','','');
      }
      }
```

在这里，注意到我们从 `book.ts` 中导入了 Book。Book 是该表单的数据模型。`BookFormComponent` 被装饰为 `@Component` 指令，该指令从 `@angular/core` 中引入。选择器值设置为 `book-form`，templateUrl 被分配为模板 HTML 文件。在 `BookFormCompoent` 中，我们用虚拟数据初始化了 Book 模型。我们有两个方法--`onSubmit()` 和 `newBook()`--一个用于向 API 提交数据，另一个用于清空表单。

1.  现在，让我们向以下 HTML 内容中添加 `book-form.component.html` 模板文件：

```ts
      <div class="container">
      <h1>New Book Form</h1>
      <form (ngSubmit)="onSubmit()" #bookForm="ngForm">
      <div class="form-group">
      <label for="name">Name</label>
      <input type="text" class="form-control" id="name"
      required
      [(ngModel)]="model.name" name="name"
      #name="ngModel">
      <div [hidden]="name.valid || name.pristine"
      class="alert alert-danger">
      Name is required
      </div>
      </div>
      <div class="form-group">
      <label for="author">Author</label>
      <input type="text" class="form-control" id="author"
      required
      [(ngModel)]="model.author" name="author"
      #author="ngModel">
      <div [hidden]="author.valid || author.pristine"
      class="alert alert-danger">
      Author is required
      </div>
      </div>
      <div class="form-group">
      <label for="publication">Publication</label>
      <input type="text" class="form-control" 
      id="publication"
      [(ngModel)]="model.publication" name="publication"
      #publication="ngModel">
      </div>
      <button type="submit" class="btn btn-success"       
      [disabled]="!bookForm.form.valid">Submit</button>
      &nbsp;&nbsp;
      <button type="button" class="btn btn-default"        
      (click)="newBook()">Clear</button>
      </form>
      </div>
      <style>
      .no-style .ng-valid {
      border-left: 1px solid #CCC
      }
      .no-style .ng-invalid {
      border-left: 1px solid #CCC
      }
      </style>
```

这是一个简单的模板表单，包含三个输入控件用于输入书名、作者和出版商名称，一个提交按钮用于提交详情，以及一个清除按钮用于清空表单。Angular 隐式地将 `ngForm` 指令应用于模板中的表单。我们将 `ngForm` 指令分配给了 `#bookForm` 本地变量。

使用 `#bookForm` 本地变量，我们可以跟踪表单的错误，并检查它们是有效还是无效、被触碰还是未触碰以及原始还是脏。在这里，只有当 `ngForm` 的 valid 属性返回 true 时，提交按钮才会被启用，因为它被分配到按钮的 disabled 属性。

`BookFormComponent` 中的 `onSubmit` 函数被分配给了表单的 `ngSubmit` 事件。因此，当单击提交按钮时，它将调用 `BookFormComponent` 中的 `onSubmit` 函数。

请注意，所有输入控件都包含 `ngModel` 事件-属性属性，并且将其分配给它们各自的模型属性，比如 `model.name`、`model.author` 和 `model.publication`。通过这种方式，我们可以实现双向绑定，这样当在对应的输入控件中输入值时，`BookFormComponent` 中的模型属性将被更新为它们各自的值：

1.  我们已经放置了所需的模板和组件。现在，我们需要创建一个 `AppModule` 来引导我们应用程序的根组件 `AppComponent`。创建一个名为 `app.module.ts` 的文件，并添加以下代码片段：

```ts
      import { NgModule } from '@angular/core';
      import { BrowserModule } from '@angular/platform-
      browser';
      import { FormsModule } from '@angular/forms';
      import { AppComponent } from './app.component';
      import { BookFormComponent } from './book-
      form.component';
      @NgModule({
        imports: [
        BrowserModule,
        FormsModule
        ],
        declarations: [
        AppComponent,
        BookFormComponent
        ],
        bootstrap: [ AppComponent ]
      })
      export class AppModule { }
```

正如我们在第二章*Angular 构建块-第一部分*中讨论的，任何 Angular 应用程序都将有一个根模块，该模块将使用`NgModule`指令进行装饰，并包含导入、声明和引导等元数据详细信息。

在上述代码中，请注意我们将`AppComponent`类分配为引导元数据，以通知 Angular`AppComponent`是应用程序的根组件。

1.  现在我们已经准备好了所有所需的模板和类，我们需要引导模块。让我们创建一个名为`main.ts`的文件，其中包含以下代码片段，用于引导模块：

```ts
      import { platformBrowserDynamic } from 
      '@angular/platform-
      browser-dynamic';
      import { AppModule } from './app/app.module';
      platformBrowserDynamic().bootstrapModule(AppModule)
```

1.  最后，添加以下内容的 index.html 文件：

```ts
      <!DOCTYPE html>
      <html>
      <head>
      <title>Book Form</title>
      <base href="/">
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, 
      initial-
      scale=1">
      <link rel="stylesheet"
      href="https://unpkg.com/bootstrap@3.3.7/
      dist/css/bootstra p.min.cs
      s">
      <link rel="stylesheet" href="styles.css">
      <link rel="stylesheet" href="forms.css">
      <!-- Polyfills -->
      <script src="node_modules/core-
      js/client/shim.min.js"></script>
      <script src="img/zone.js">
      </script>
      <script 
      src="img/system.src.js">
      </script>
      <script src="img/systemjs.config.js"></script>
      <script>
      System.import('main.js').catch(function(err){   
      console.error(err); 
      });
      </script>
      </head>
      <body>
      <first-template-form>Loading...</first-template-
      form>
      </body>
      </html>
```

注意在正文中添加了`<first-template-form/>`特殊标记。该标记将在运行时使用实际模板进行更新。另外，请注意，在运行时使用`System.js`模块加载器加载必需的库。`systemjs.config.js`文件应包含有关映射 npm 包和我们应用程序起始点的指令。在这里，我们的应用程序在`main.ts`中引导，这将在构建应用程序后被转译为`main.js`。`systemjs.config.js`的内容如下所示：

```ts
/**
* System configuration for Angular samples
* Adjust as necessary for your application needs.
*/
(function (global) {
System.config({
paths: {
  // paths serve as alias
  'npm:': 'node_modules/'
},
// map tells the System loader where to look for things
map: {// our app is within the app folder
'app': 'app',
// angular bundles
'@angular/animations': 'npm:@angular/animations/bundles/animations.umd.js',
'@angular/animations/browser': 'npm:@angular/animations/bundles/animations-browser.umd.js',
'@angular/core': 'npm:@angular/core/bundles/core.umd.js',
'@angular/common': 'npm:@angular/common/bundles/common.umd.js',
'@angular/compiler': 'npm:@angular/compiler/bundles/compiler.umd.js',
'@angular/platform-browser': 'npm:@angular/platform-browser/bundles/platform-browser.umd.js',
'@angular/platform-browser/animations': 'npm:@angular/platform-browser/bundles/platform-browser-animations.umd.js',
'@angular/platform-browser-dynamic': 'npm:@angular/platform-browser-dynamic/bundles/platform-browser-dynamic.umd.js',
'@angular/http': 'npm:@angular/http/bundles/http.umd.js',
'@angular/router': 'npm:@angular/router/bundles/router.umd.js',
'@angular/router/upgrade': 'npm:@angular/router/bundles/router-upgrade.umd.js',
'@angular/forms': 'npm:@angular/forms/bundles/forms.umd.js',
'@angular/upgrade': 'npm:@angular/upgrade/bundles/upgrade.umd.js',
'@angular/upgrade/static': 'npm:@angular/upgrade/bundles/upgrade-static.umd.js',
// other libraries
'rxjs': 'npm:rxjs',
'angular-in-memory-web-api': 'npm:angular-in-memory-web-api/bundles/in-memory-web-api.umd.js'
},
// packages tells the System loader how to load when no filename and/or no extension
packages: {
app: {
  main: './main.js',
  defaultExtension: 'js',
meta: {
'./*.js': {
  loader: 'systemjs-angular-loader.js'
}
}
},
rxjs: {
  defaultExtension: 'js'
}
}
});
})(this);
```

1.  现在，我们已经准备好了所有所需的内容。通过按下*F5*来运行应用程序，索引页面将以由`BookFormComponent`提供模板的方式呈现，如下所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_03_001.png)

`FirstTemplateForm`应用程序的输出

1.  现在移除分配给输入控件的虚拟文本，并注意表单验证已触发，显示验证错误消息，保持**`Submit`**按钮处于禁用状态：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_03_002.png)

检查控制台日志以进行表单提交

在这个模板驱动表单中，您可能已经注意到我们已经将`required`属性应用于输入控件。类似于这样，我们还可以应用最小长度和最大长度验证。然而，这样应用验证会将验证逻辑紧密耦合到模板中，并且我们只能通过编写基于浏览器的端到端测试来测试这些验证。

#### 模型驱动表单

Angular 提供了`FormGroup`和`FormControl`属性来实现模型驱动表单。

##### 模型驱动表单的基本对象

`FormControl`和`FormGroup`是模型驱动表单中的两个基本对象。`FormControl`是 Angular 表单中的输入字段，它封装了输入字段的值，其状态（有效性），是否已更改（脏），或是否有任何错误。

当我们构建一个表单时，我们需要创建控件并附加元数据到这些控件。我们必须通过添加`formControlName`属性将 Control 类附加到 DOM 输入元素，如下所示：

```ts
<input type="text" formControlName="name" />
```

`FormGroup`可以由 FormBuilder 进行实例化。我们还可以用默认值在组件中手动构建`FormGroup`，如下所示：

```ts
this.bookForm = new FormGroup({
  name: new FormControl('book name', Validators.required),
  author: new FormControl('author name', Validators.required),
  publication: new FormControl('publication name is optional')
});
```

让我们在**Visual Studio Code**（**VS Code**）中创建一个名为`ModelDrivenForm`的应用程序。以下是模型驱动表单的实现：

1.  添加所需的包和依赖项详细信息，并使用`npm install`命令来安装它们：

```ts
      {
      "name":"model-driven-form",
      "version":"1.0.0",
      "private":true,
      "description":"Model driven form",
      "scripts":{
      "test:once":"karma start karma.conf.js --single-
       run",
      "build":"tsc -p src/",
      "serve":"lite-server -c=bs-config.json",
      "prestart":"npm run build",
      "start":"concurrently \"npm run build:watch\" \"npm 
      run serve\"",
      "pretest":"npm run build",
      "test":"concurrently \"npm run build:watch\" \"karma 
       start 
      karma.conf.js\"",
      "pretest:once":"npm run build",
      "build:watch":"tsc -p src/ -w",
      "build:upgrade":"tsc",
      "serve:upgrade":"http-server",
      "build:aot":"ngc -p tsconfig-aot.json && rollup -c 
       rollup-
      config.js",
      "serve:aot":"lite-server -c bs-config.aot.json",
      "build:babel":"babel src -d src --extensions 
      \".es6\" --source-
      maps",
      "copy-dist-files":"node ./copy-dist-files.js",
      "i18n":"ng-xi18n",
      "lint":"tslint ./src/**/*.ts -t verbose"
      },
      "keywords":[
      ],
      "author":"",
      "license":"MIT",
      "dependencies":{
      "@angular/common":"~4.0.0",
      "@angular/compiler":"~4.0.0",
      "@angular/compiler-cli":"~4.0.0",
      "@angular/core":"~4.0.0",
      "@angular/forms":"~4.0.0","@angular/http":"~4.0.0",
      "@angular/platform-browser":"~4.0.0",
      "@angular/platform-browser-dynamic":"~4.0.0",
      "@angular/platform-server":"~4.0.0",
      "@angular/router":"~4.0.0",
      "@angular/tsc-wrapped":"~4.0.0",
      "@angular/upgrade":"~4.0.0
      ",
      "angular-in-memory-web-api":"~0.3.1",
      "core-js":"².4.1",
      "rxjs":"5.0.1",
      "systemjs":"0.19.39",
      "zone.js":"⁰.8.4"
      },
      "devDependencies":{
      "@types/angular":"¹.5.16",
      "@types/angular-animate":"¹.5.5",
      "@types/angular-cookies":"¹.4.2",
      "@types/angular-mocks":"¹.5.5",
      "@types/angular-resource":"¹.5.6",
      "@types/angular-route":"¹.3.2",
      "@types/angular-sanitize":"¹.3.3",
      "@types/jasmine":"2.5.36",
      "@types/node":"⁶.0.45",
      "babel-cli":"⁶.16.0",
      "babel-preset-angular2":"⁰.0.2",
      "babel-preset-es2015":"⁶.16.0",
      "canonical-path":"0.0.2",
      "concurrently":"³.0.0",
      "http-server":"⁰.9.0",
      "jasmine":"~2.4.1",
      "jasmine-core":"~2.4.1",
      "karma":"¹.3.0",
      "karma-chrome-launcher":"².0.0",
      "karma-cli":"¹.0.1",
      "karma-jasmine":"¹.0.2",
      "karma-jasmine-html-reporter":"⁰.2.2",
      "karma-phantomjs-launcher":"¹.0.2",
      "lite-server":"².2.2",
      "lodash":"⁴.16.2",
      "phantomjs-prebuilt":"².1.7",
      "protractor":"~4.0.14",
      "rollup":"⁰.41.6",
      "rollup-plugin-commonjs":"⁸.0.2",
      "rollup-plugin-node-resolve":"2.0.0",
      "rollup-plugin-uglify":"¹.0.1",
      "source-map-explorer":"¹.3.2",
      "tslint":"³.15.1",
      "typescript":"~2.2.0"
      },
      "repository":{
      }
      }
```

1.  创建一个`Book`类，并添加以下代码片段：

```ts
      export class Book {
      constructor(
      public id: number,
      public name: string,
      public author: string,
      public publication?: string
      ) { }
      }
```

1.  创建`AppComponent`并添加以下代码：

```ts
      import { Component } from '@angular/core';
      @Component({
      selector: 'first-model-form',
      template: '<book-form></book-form>'
      })
      export class AppComponent { }
```

此前展示的`AppComponent`是应用程序的根组件，将托管`BookFormComponent`。`AppComponent`带有第一个模型表单选择器和模板，其中包含带有特殊标签`<book-form/>`的内联 HTML。这个标签将在运行时更新为实际模板。

1.  现在，让我们添加`book-form.component.ts`，使用以下代码片段：

```ts
      import { Component, OnInit } from '@angular/core';
      import { FormControl, FormGroup, Validators } from 
      '@angular/forms';
      import { Book } from './book';
      @Component({
      selector: 'book-form',
      templateUrl: './book-form.component.html'
      })
      export class BookFormComponent implements OnInit {
      bookForm: FormGroup;
      public submitted: boolean;
      constructor() { }
      ngOnInit() {
      this.bookForm = new FormGroup({
      name: new FormControl('book name', 
      Validators.required),
      author: new FormControl('author name', 
      Validators.required),
      publication: new FormControl('publication name is 
      optional')
      });
      }
      onSubmit(model: Book, isValid: boolean) {
      this.submitted = true;
      console.log(model, isValid);
      // code to post the data
      }
      }
```

在这里，注意我们从`@angular/forms`中导入了`FormControl`、`FormGroup`和`Validators`。这些是实现模型驱动表单的基本类。我们还从`@angular/core`中导入了`Component`和`OnInit`，用于组件类的实现，然后我们从`book.ts`中导入了 Book。Book 是该表单的数据模型。

`BookFormComponent`带有从`@angular/core`导入的`@Component`指令。选择器值设置为`book-form`，`templateUrl`分配了模板 HTML 文件。

在`BookFormCompoent`中，我们通过实例化`FormGroup`并将其分配给属性，如名称、作者和出版物，来初始化表单模型。我们有`onSubmit()`方法来将提交的数据提交到 API。

1.  现在，让我们添加`book-form.component.html`模板文件，并添加以下 HTML 内容：

```ts
      <div class="container">
      <h1>New Book Form</h1>
      <form [formGroup]="bookForm" novalidate       
      (ngSubmit)="onSubmit(bookForm.value, 
       bookForm.valid)">
      <div class="form-group">
      <label for="name">Name</label>
      <input type="text" class="form-control" 
       formControlName="name">
      <small [hidden]="bookForm.controls.name.valid ||       
      (bookForm.controls.name.pristine && !submitted)" 
      class="text-
      danger">
      Name is required.
      </small>
      </div>
      <div class="form-group">
      <label for="author">Author</label>
      <input type="text" class="form-control" 
      formControlName="author">
      <small [hidden]="bookForm.controls.author.valid ||       
      (bookForm.controls.author.pristine && !submitted)" 
      class="text-
      danger">
      Author is required.
      </small>
      </div>
      <div class="form-group">
      <label for="publication">Publication</label>
      <input type="text" class="form-control" 
      formControlName="publication">
      </div>
      <button type="submit" class="btn btn-
      success">Submit</button>
      </form>
      </div>
      <style>
      .no-style .ng-valid {
      border-left: 1px solid #CCC
      }
      .no-style .ng-invalid {
      border-left: 1px solid #CCC
      }
      </style>
```

与模板驱动表单类似，这是一个简单的模型驱动表单，其中包含三个输入控件用于输入图书、作者和出版商名称，以及一个提交按钮来提交详细信息。在表单标签中，我们添加了`formGroup`指令来分配给表单，并将其分配给了`bookForm`。每个输入控件都有一个特殊的属性`formControlName`，分别分配有各自的`formControl`，比如名称、作者和出版物。

`BookFormComponent`中的`onSubmit`函数分配给了表单的`ngSubmit`事件。因此，当单击提交按钮时，它将调用`BookFormComponent`中的`onSubmit`函数，传递`bookForm`的值和有效属性。

注意，所有的输入控件都没有任何事件兼属性属性，就像模板驱动表单中一样。在这里，我们可以通过将模型值从`bookForm.value`属性传递到`onSubmit`函数，并从组件中访问模型来实现双向绑定。

我们已经准备好所需的模板和组件。现在我们需要创建一个`AppModule`来引导我们应用程序的根组件`AppComponent`。创建一个名为`app.module.ts`的文件，并添加以下代码片段：

```ts
      import { NgModule } from '@angular/core';
      import { BrowserModule } from '@angular/platform-
      browser';
      import { FormsModule, ReactiveFormsModule } from 
      '@angular/forms';
      import { AppComponent } from './app.component';
      import { BookFormComponent } from './book-
      form.component';
      @NgModule({
      imports: [
      BrowserModule,
      ReactiveFormsModule
      ],
      declarations: [
      AppComponent,
      BookFormComponent
      ],
      bootstrap: [ AppComponent ]
      })
      export class AppModule { }
```

在上述代码中，请注意，我们已将 `AppComponent` 类分配为引导元数据，以通知 Angular `AppComponent` 是应用程序的根组件。还要注意，我们已从 `@angular/forms` 导入了 `FormsModule` 和 `ReactiveFormsModule`。

1.  现在，我们已经准备好所有所需的模板和类，我们需要引导模块。让我们创建一个名为 `main.ts` 的文件，其中包含如下代码段来引导模块：

```ts
      import { platformBrowserDynamic } from 
      '@angular/platform-
      browser-dynamic';
      import { AppModule } from './app/app.module';
      platformBrowserDynamic().bootstrapModule(AppModule)
```

1.  最后，使用以下内容添加 `index.html` 文件：

```ts
      <!DOCTYPE html>
      <html>
      <head>
      <title>Hero Form</title>
      <base href="/">
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, 
      initial-
      scale=1">
      <link rel="stylesheet"
      href="https://unpkg.com/bootstrap@3.3.7
      /dist/css/bootstra   p.min.css">
      <link rel="stylesheet" href="styles.css">
      <link rel="stylesheet" href="forms.css">
      <!-- Polyfills -->
      <script src="node_modules/core-   
      js/client/shim.min.js"></script>
      <script src="img/zone.js">
      </script>
      <script 
      src="img/system.src.js">
      </script>
      <script src="img/systemjs.config.js"></script>
      <script>
      System.import('main.js').catch(function(err){ 
      console.error(err); 
      });
      </script>
      </head>
      <body>
      <first-model-form>Loading...</first-model-form>
      </body>
      </html>
```

请注意，`<first-model-form/>` 特殊标记被添加到正文中。此标记将在运行时更新为实际模板。还要注意，使用 `System.js` 模块加载器在运行时加载所需的库。`systemjs.config.js` 文件应该包含有关如何映射 `npm` 包和我们应用程序的起始点的指令。在这里，我们的应用程序在 `main.ts` 中启动，在构建应用程序后，它将被转译为 `main.js`。`systemjs.config.js` 的内容如下：

```ts
/**
* System configuration for Angular samples
* Adjust as necessary for your application needs.
*/
(function (global) {
System.config({
paths: {
// paths serve as alias
'npm:': 'node_modules/'
},
// map tells the System loader where to look for things
map: {
// our app is within the app folder
'app': 'app',
// angular bundles
'@angular/animations': 'npm:@angular/animations/bundles/animations.umd.js',
'@angular/animations/browser': 'npm:@angular/animations/bundles/animations-browser.umd.js',
'@angular/core': 'npm:@angular/core/bundles/core.umd.js',
'@angular/common': 'npm:@angular/common/bundles/common.umd.js',
'@angular/compiler': 'npm:@angular/compiler/bundles/compiler.umd.js',
'@angular/platform-browser': 'npm:@angular/platform-browser/bundles/platform-browser.umd.js',
'@angular/platform-browser/animations': 'npm:@angular/platform-browser/bundles/platform-browser-animations.umd.js',
'@angular/platform-browser-dynamic': 'npm:@angular/platform-browser-dynamic/bundles/platform-browser-dynamic.umd.js',
'@angular/http': 'npm:@angular/http/bundles/http.umd.js',
'@angular/router': 'npm:@angular/router/bundles/router.umd.js',
'@angular/router/upgrade': 'npm:@angular/router/bundles/router-upgrade.umd.js',
'@angular/forms': 'npm:@angular/forms/bundles/forms.umd.js',
'@angular/upgrade': 'npm:@angular/upgrade/bundles/upgrade.umd.js',
'@angular/upgrade/static': 'npm:@angular/upgrade/bundles/upgrade-static.umd.js',
// other libraries
'rxjs': 'npm:rxjs',
'angular-in-memory-web-api': 'npm:angular-in-memory-web-api/bundles/in-memory-web-api.umd.js'
},
// packages tells the System loader how to load when no filename and/or no extension
packages: {
app: {
main: './main.js',
defaultExtension: 'js',
meta: {
'./*.js': {
loader: 'systemjs-angular-loader.js'
}
},
rxjs: {
defaultExtension: 'js'
}
}
});
})(this);
```

1.  现在，我们已经拥有了所需的一切。按下 *F5* 运行应用程序，索引页面将以`BookFormComponent`为模板进行渲染，如下所示:

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_03_003.png)

模型驱动表单的输出

在 Chrome 浏览器的开发者工具中保持控制台窗口打开的情况下，单击 **`提交`** 按钮。请注意，日志记录模型对象是表单有效值为 false，因为作者属性缺少值。

现在，让我们在作者属性中输入一些值，并在 Chrome 浏览器的开发者工具中保持控制台窗口打开的情况下，单击**`提交`** 按钮。请注意，模型对象与填充了值的所有必需属性的表单有效值都被记录如下：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_03_004.png)

检查模型驱动表单提交

当我们使用 `FormGroup` 在组件中配置验证时，我们将验证逻辑从模板松散耦合移动到了组件中。所以，我们可以使用任何测试框架编写测试方法来通过断言组件来验证验证逻辑。参考第八章，*测试 Angular 应用* 来了解如何测试 Angular 应用。

## 管道

* * *

在 Angular 中，管道是 AngularJS 1.x 中过滤器的替代品。管道是过滤器的改良版本，可以转换常见数据。大多数应用程序都会从服务器获取数据，并在在前端显示数据之前对其进行转换。在这种情况下，管道在渲染模板时非常有用。Angular 为此提供了这些强大的管道 API。管道将数据作为输入，并根据需要输出转换后的数据。

### 常用的管道

以下是 `@angular/core` 中提供的内置管道，并将看到一些带有示例的管道：

+   AsyncPipe

+   CurrencyPipe

+   DatePipe

+   DecimalPipe

+   I18nPluralPipe

+   I18nSelectPipe

+   JsonPipe

+   LowerCasePipe

+   PercentPipe

+   SlicePipe

+   TitleCasePipe

+   UpperCasePipe

#### 带参数的管道

我们可以通过冒号(:)符号向管道传递参数，如下所示：

```ts
<p>Price of the book is {{ price | currency:'USD' }} </p>
```

通过(:)分隔的方式可以将多个输入传递给管道，如下所示：

```ts
<li *ngFor="let book of books | slice:1:3">{{i}}</li>
```

### 管道链

在某些情况下，可能需要使用多个管道。例如，考虑一种情况，需要以大写形式和长日期格式显示数据。以下代码以大写形式和长日期格式显示书籍的出版日期：

```ts
Publishing Date: {{ pubDate | date | uppercase}}
```

### 货币管道

货币管道将数字格式化为所需的货币格式。这是货币管道的语法：

```ts
expression | currency[:currencyCode[:symbolDisplay[:digitInfo]]] 
```

`expression`是管道的输入数据；`currency`是管道的关键词，它接受三个参数，分别为`currencyCode`，取值为 USD、INR、GBP 和 EUR，`symbolDisplay`，接受 true 或 false 来显示/隐藏货币符号，以及`digitInfo`，用于货币的小数格式。以下模板演示了如何使用货币管道：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_03_005.png)

实现货币管道的模板

对于各种货币格式，模板的输出如下：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_03_006.png)

使用货币管道的输出

### 日期管道

日期管道将输入数据转换为日期管道支持的各种日期格式。日期管道的语法如下：

```ts
expression | date[:format] 
```

假设组件中的`dateData`被赋予了`Date.now()`。在模板中实现日期管道的方式如下截图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_03_007.png)

实现日期管道的模板

应用各种日期格式后的模板输出如下：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_03_008.png)

使用日期管道的输出

日期管道支持各种格式，如`medium`(`yMMMdjms`)、`short`(`yMdjm`)、`mediumDate`(`yMMMd`)、`shortDate`(`yMd`)、`fullDate`(`yMMMMEEEEd`)、`longDate`(`yMMMMd`)、`mediumTime`(`jms`)和`shortTime`(`jm`)。

### 大写和小写管道

大写和小写管道将输入数据分别转换为大写和小写。以下模板同时显示作者姓名的大写和小写形式：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_03_009.png)

实现大写和小写管道的模板

此模板的输出如下：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_03_010.png)

实现大写和小写管道的输出

### JSON 管道

JSON 管道类似于在 JavaScript 中应用 `JSON.Stringify` 对持有 JSON 值的对象进行操作。模板中使用 JSON 管道的用法如下截图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_03_011.png)

实现 JSON 管道的模板

在模板中使用 JSON 管道的输出如下所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_03_012.png)

使用 JSON 管道的输出

## AppComponent

* * *

`AppComponent`是一个应用程序的组件，其配置为根组件，并且处理`app.component.html`Â模板的渲染。在前面的章节中，我们看到了实现各种管道及其各自输出的模板代码。以下代码片段显示了模板的组件：

```ts
import { Component } from '@angular/core'; 

@Component({ 
  selector: 'pipe-page', 
  templateUrl: 'app/app.component.html' 
}) 
export class AppComponent { 
    numberData : number; 
    currencyData : number; 
    dateData : number; 
    authorName : string; 
    object: Object = {autherName: 'Rajesh Gunasundaram',   
    pubName: 'Packt Publishing'} 
    constructor() { 
        this.numberData = 123.456789; 
        this.currencyData = 50; 
        this.dateData = Date.now(); 
        this.authorName = 'rAjEsH gUnAsUnDaRaM'; 
    } 
} 
```

管道，这是 Angular 提供的非常强大且易于使用的 API，能够在显示在屏幕上之前格式化数据，这极大地简化了我们的流程。

## 路由器

* * *

AngularJS 使用`ngRoute`模块来运行具有基本功能的简单路由器。它通过将路径映射到使用`$routeProvider`服务配置的路由来使 URL 与组件和视图进行深度链接。AngularJS 1.x 需要安装`ngRoute`模块才能在应用中实现路由。

Angular 引入了一个组件路由器，用于深度链接 URL 请求并导航到模板或视图。如果有任何参数，它会将其传递给标注为该路线的相应组件。

### 组件路由的核心概念

Angular 使用一个组件路由器作为视图系统。它还适用于 AngularJS 1.x。它支持拦截路由并为加载的组件提供特定路由值，自动深度链接，嵌套和同级路由。让我们来看一下组件路由器的一些核心功能。

### 设置组件路由器

组件路由器不是核心 Angular 框架的一部分。它作为单独库`@angular/router`的一部分出现在 Angular NPM 包中。我们需要将`@angular/router`添加到`packages.json`中的依赖项部分。然后，在`app.routing.ts`中，我们需要从`@angular/router`中导入`Routes`和`RouterModule`。路由器包括诸如`RouterOutlet`，`RouterLink`和`RouterLinkActive`这样的指令，一个`RouterModule`服务和`Routes`的配置。

```ts
<base> tag with the href attribute that is to be added to the head tag in the index file, considering that the app folder is the root of the application. This is required when you run your application in HTML5 mode. It helps resolve all the relative URLs in the application:
```

```ts
<base href="/"> 
```

### 配置路由

```ts
app.module.ts:
```

```ts
import { RouterModule } from '@angular/router';
RouterModule.forRoot([
{
  path: 'about',
  component: AboutComponent
},
{
  path: 'contact',
  component: ContactComponent
}
])
```

在这里，我们配置了两个路由，帮助用户在单击时转到`about`和`contact`视图。路由基本上是路由定义的集合。所定义的路径值标识出匹配路径的 URL 时要实例化的组件。然后，实例化的组件将负责渲染视图。

现在，我们需要将配置的路由添加到`AppModule`中，从`@angular/router`中导入`RouterModule`，并将其添加到`@NgModule`的 imports 部分中，如下所示：

```ts
import { NgModule } from '@angular/core';
import { BrowserModule } from '@angular/platform-browser';
import { RouterModule } from '@angular/router';
import { AppComponent } from './app.component';
import { AboutComponent } from './heroes.component';
@NgModule({
  imports: [
  BrowserModule,
  FormsModule,
  RouterModule.forRoot([
{
  path: 'about',
  component: AboutComponent
}
])
],
declarations: [
AppComponent,
AboutComponent
],
bootstrap: [ AppComponent ]
})
export class AppModule { }
```

在这里，`forRoot()`方法提供了路由器服务提供程序和指令来执行导航。

### 路由出口和路由链接

当用户将`'/about'`添加到应用程序 URL 的末尾后，将其传递到浏览器地址栏中时，路由将使用`'about'`匹配该请求，并启动`AboutComponent`来处理`about`视图的渲染。我们需要以某种方式告知路由器在哪里显示此`about`视图。可以通过指定`<router-outlet/>`来实现这一点，这类似于 AngularJS 1.x 中的`<ng-view/>`标记，用于加载与路由相应路径相关的模板。

路由链接可通过单击锚标记中指定的链接来导航到路由 URL。以下是一个示例路由链接标记：

```ts
<a [routerLink]="['/about']">About</a>
```

## 服务

* * *

我们创建的应用程序处理大量的数据。大多数数据将从服务中检索，并且将在应用程序的各个部分重用。让我们创建一个可以使用`http`检索数据的服务。服务应该与组件松散耦合，因为组件的主要重点应该是支持视图。因此，可以使用依赖注入将服务注入到组件中。这种方法将使我们能够模拟服务以进行单元测试组件。

```ts
TodoService is shown here. TodoService has a property named todos of the type array that can hold a collection of Todo items and is hardcoded with the Todo items in the constructor:
```

```ts
import {Injectable} from '@angular/core'; 
import { Todo } from './todo'; 

@Injectable()  
export class TodoService { 
    todos: Array<Todo>; 
    constructor() { 
        this.todos = [ 
    {"title": "First Todo", "completed":  false}, 
    {"title": "Second Todo", "completed": false}, 
    {"title": "Third Todo", "completed": false} 
            ] 
    } 

    getTodos() { 
        return this.todos; 
    } 
} 
```

请注意，用`@Injectable`装饰的服务是为了让 Angular 知道这个服务是可注入的。

我们可以将可注入的`TodoService`注入到`AppComponent`的构造函数中，如下所示：

```ts
import { Component } from '@angular/core'; 
import { Todo } from './Todo'; 
import { TodoService } from './TodoService'; 
@Component({ 
  selector: 'my-service', 
  templateUrl: 'app/app.component.html' 
}) 
export class AppComponent { 
    todos: Array<Todo>; 
    constructor(todoService: TodoService) { 
        this.todos = todoService.getTodos(); 
    } 
} 
```

在引导过程中，我们还需要传递`TodoService`，这样 Angular 将创建服务的实例，并在其被注入的任何地方保持可用。因此，让我们在`main.ts`文件中如所示地向`bootstrap`函数传递`TodoService`： 

```ts
import { NgModule } from '@angular/core';
import { BrowserModule } from '@angular/platform-browser';
import { AppComponent } from './app.component';
import { TodoService } from './TodoService';
@NgModule({
imports: [
BrowserModule,
],
declarations: [
AppComponent,
],
providers: [ TodoService ],
bootstrap: [ AppComponent ]
})
export class AppModule { }
```

注意，可注入服务用方括号括起来。这是一种应用依赖注入的方法。有关 Angular 依赖注入更多信息，请参考第二章, *Angular Building Blocks - Part 1*。Angular 已经改进了依赖注入，可以创建`TodoService`的实例并将其注入到组件中。

在`app.component.html`模板中，我们遍历`AppComponent`中`todos`属性的每个项目并列出它们：

```ts
<h2>My Todo List</h2> 
<ul> 
    <li *ngFor="let todo of todos"> 
        {{ todo.title }} - {{ todo.completed }} 
    </li> 
</ul> 
```

此模板的内容将在`index.html`文件的`<my-service>`特殊标签下呈现：

```ts
 <body> 
        <my-service>Loading...</my-service> 
 </body> 
```

运行时，应用程序将呈现如下的`todo`项目清单：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_03_013.png)

我的待办事项应用程序的输出

## 可观察对象

* * *

在 AngularJS 中，我们使用服务以异步方式使用 `$http` 中的 promise 获取数据。在 Angular 中，我们有了 `Http` 服务取代了 `$http`，它返回一个可观察对象而不是 promise，因为它应用了类似模式。 Angular 利用了从 ReactiveX 库采用的 Observable 类。 ReactiveX 是一个用于应用观察者、迭代器模式和函数式编程完成异步编程的 API。你可以在 [`reactivex.io/`](http://reactivex.io/) 找到有关反应式编程的更多信息。

Observer 模式将在依赖对象更改时通知依赖者。迭代器模式将方便地访问集合，无需了解集合中元素的结构。在 ReactiveX 中结合这些模式使观察者能够订阅可观察的集合对象。观察者不需要等到可观察的集合对象可用时才能做出反应，而是在获得可观察对象更改通知时做出反应。

Angular 使用名为 RxJS 的 JavaScript 实现，它是一组库而不是一个特定的 API。它在 HTTP 服务和事件系统中使用 Observables。promise 总是返回一个值。

`http.get()` 方法将返回 Observables，并且客户端可以订阅以获取从服务返回的数据。 Observables 可以处理多个值。因此，我们还可以调用多个 `http.get()` 方法，并将它们包装在 Observables 提供的 `forkJoin` 方法下。

我们还可以控制服务调用并通过 Observable 延迟调用，通过应用一个规则，只有在上次对服务的调用是 500 毫秒前才调用服务。

Observables 是可取消的。所以，我们也可以通过取消订阅来取消之前的请求，并发起新的请求。我们随时可以取消任何之前未完成的调用。

让我们修改 `TodoService` 以使用 Observable，并将硬编码的 JSON 值替换为对 `todos.json` 文件的 `http.get()` 调用。更新后的 `TodoService` 如下所示：

```ts
import {Injectable} from '@angular/core';
import {Http} from '@angular/http';
import 'rxjs/add/operator/toPromise';
@Injectable()
export class TodoService {
constructor(private http: Http) {
this.http = http;
}
getTodos() {
  return this.http.get('/app/todos.json')
  .toPromise()
  .then(response => response.json().data)
  .catch(this.handleError);
}
}
```

请注意，我们从 `@angular/http` 中导入了 HTTP 模块、`rsjs/Rx` 中的响应，以及基于 ReactiveX 的 Observable 模块。`getTodos` 方法通过调用 `todos.json` 查询并返回一组待办事项来更新。

`AppComponent` 和 `TodoService` 在 `app.module.ts` 文件中进行了引导，如下所示：

```ts
import { NgModule } from '@angular/core';
import { BrowserModule } from '@angular/platform-browser';
import { HttpModule } from '@angular/http';
import { AppComponent } from './app.component';
import { TodoComponent } from './todo.component';
import { TodoService } from './hero.service';
@NgModule({
  imports: [
  BrowserModule,
  HttpModule,
  AppRoutingModule
  ],
  declarations: [
  AppComponent,
  TodoComponent
  ],
  providers: [ TodoService ],
  bootstrap: [ AppComponent ]
})
export class AppModule { }
```

从 `'@angular/platform-browser-dynamic'` 中导入 `{bootstrap}`；模板被更新以渲染待办事项列表，如下所示：

```ts
import {HTTP_PROVIDERS} from '@angular/http'; 
import 'rxjs/add/operator/map'; 
import {AppComponent} from './app.component'; 
import {TodoService} from './TodoService';
bootstrap(AppComponent, [HTTP_PROVIDERS, TodoService]); 
```

运行应用将呈现从 `TodoService` 中返回的从 Observables 订阅的数据：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_03_014.png)

从 Observables 订阅的渲染数据的 index.html 输出

## 总结

* * *

哇呜！你已经学习完了 Angular 架构的其余构建模块。我们从表单开始介绍本章，并讨论了 Angular 中可用的表单类型以及如何实现它们。然后，您了解了管道，这是 AngularJS 1.x 中筛选器的替代方案。接下来，我们讨论了路由器，并学习了如何在 Angular 中配置路由器到组件是多么容易。最后，您学会了如何在 Angular 中创建服务以及如何使用 HTTP 模块访问外部服务。您还了解了使用 Observables 的优势以及在服务调用中如何实现它。

在下一章中，我们将讨论 TypeScript 的基础知识。
