# SpringMVC：设计现实世界的 Web 应用（三）

> 原文：[`zh.annas-archive.org/md5/AB3510E97B9E20602840C849773D49C6`](https://zh.annas-archive.org/md5/AB3510E97B9E20602840C849773D49C6)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：构建单页 Spring 应用程序

在处理企业应用程序的所有主要技术问题时，掌握了 Spring Framework 的许多强大功能，现在是将我们在前几章中学到的所有技术结合起来构建现代 Web 应用程序的时候了。当前 Web 开发的趋势是构建提供类似本机用户体验和直观用户界面的**单页应用程序**（**SPAs**）。在本章中，让我们构建一个由 Spring 后端支持的响应式 SPA。

我们将使用 Ember.js 构建 SPA，并使用 Bootstrap 进行样式和响应行为。对于 Ember 开发，我们将使用一个名为**Ember CLI**的命令行工具，它在 Node.js 上运行，并结合了一系列支持工具，用于 JavaScript-based 现代前端开发的各种关键功能。

# SPAs 背后的动机

我们知道 Spring 主要关注服务器端，即集成、服务和数据层。Spring 依赖于其他 Web 技术来呈现表示层。虽然 Spring MVC 通过诸如 JSP 和 Thymeleaf 等 Web 技术来促进表示层，但它们都是基于服务器端渲染和全页面刷新来响应用户交互的。在这种传统方法中，Web 应用程序的表示层由一堆完全独立的 HTML 文件组成，由服务器按需提供，每个文件代表一个屏幕，每次只有一个屏幕呈现给客户端浏览器，每次用户交互都需要完整的往返到服务器。与优雅地在需要时重新呈现屏幕的本机桌面应用程序相比，这提供了非常糟糕的用户体验。

尽管可以使用一些使用 AJAX 的框架，如 jQuery，以从服务器获取数据，甚至用于 UI 的部分渲染（如 JSF 的情况），但这需要大量服务器资源用于表示层，当并发用户数量增加时，服务器处理很容易耗尽。在这种方法中，表示层关注点分布在服务器和客户端层之间。在这种情况下，UI 开发人员需要具备客户端和服务器端技能，这使得 Web 开发更加困难。

Web 开发人员一直在寻找一种更智能的方法来构建完全在客户端运行的数据驱动应用程序的用户界面，它运行在 Web 浏览器内部，提供类似本机的丰富用户体验，而无需对页面转换和导航进行完全刷新到服务器。他们希望通过纯粹在客户端上使用数据使其 UI 动态化，消除前端开发中对服务器的需求，并在客户端准备就绪后才将其插入服务器。对于所有这些问题和要求，SPA 范式是答案。

# 解释 SPA

SPA 是一个完全由静态 Web 资源组成的 Web 应用程序或网站，如 HTML、JavaScript 和 CSS，在单个页面加载中加载一次。一旦启动，随着用户开始与其交互，它会智能地更新自身。与传统 Web 应用程序为屏幕导航执行完整页面刷新不同，SPA 在不重新加载整个页面（或下一个页面）的情况下路由和重新绘制（重新呈现）屏幕。它使用 JavaScript 重建 DOM 结构，并响应用户操作和应用程序事件以在屏幕上表示它们。

初始启动后，SPA 与服务器通信的唯一时间是获取动态数据。SPA 通常依赖于 AJAX 或 WebSockets 从服务器获取数据访问。数据传输格式主要是 JSON，有时也是 XML。它们通过 AJAX 异步地在后台通过 HTTP 与服务器联系；这样可以提供流畅、流畅的用户体验，而不会阻塞屏幕或让用户等待服务器响应。此外，服务器可以使用 WebSocket API 与客户端同步其数据更改，以提供实时体验。

## SPA 的架构优势

除了前端开发人员的巨大生产力增益和显著性，SPA 还提供了许多架构优势。与传统的服务器渲染的 Web 应用程序相比，它的运行速度非常快，因为它完全在客户端本地工作。SPA 提供了更加流畅和流畅的用户体验，因为它能够立即响应，而无需在每次用户交互时重新提交整个页面到服务器。

### 注意

JavaScript 密集型 Web 应用程序在具有足够内存的现代 Web 浏览器上运行效果最佳。大多数框架利用许多 HTML5 功能和更新的 JavaScript 功能，如 AJAX。SPA 可以在较慢的 PC 上迅速淘汰旧版浏览器。

SPA 将整个应用程序状态的责任转移到浏览器，释放服务器资源以便专注于核心业务逻辑（服务）和状态无关的 Web 服务数据，通常设计为 REST API。使用 SPA，服务器只是一个 API 服务器；整个用户交互由客户端处理，这极大地提高了服务器的可扩展性。

另一个优势，也许是 SPA 最重要的优势之一，是客户端和服务器应用程序可以独立设计和演进。只要端点（API）合同保持完整，您可以替换其中一个而不影响另一个。此外，您可以让前端开发人员构建 UI，后端开发人员提供数据；两个团队都可以专注于自己的领域，同时围绕数据合同进行工作。

## SPA 框架

在纯 JavaScript 中开发 SPA 并不是一个明智的想法，考虑到 SPA 范式所处理的责任的重要性。如果我们打算从头开始编写所有路由、数据绑定、屏幕创作和渲染代码，那将会非常累人且容易出错。幸运的是，一系列令人印象深刻的框架从 SPA 概念中出现。它们每个都提供不同级别的抽象和架构风格；其中一些使用强大的模板技术。让我们来看看最流行的 SPA 框架：

+   **AngularJS**：由 Google 维护并得到开发人员和公司社区的支持，Angular 是最流行和广泛使用的 SPA 框架。它通过智能指令增强了原始 HTML，实现了双向数据绑定。Angular 支持本地化和可重用组件的构建。

+   **ReactJS**：由 Facebook、Instagram 和一群开发人员和公司支持，React 是撰写时增长最快的 SPA 框架。Facebook 和 Instagram 都是使用 React 开发的。它的工作基于虚拟 DOM 的概念，即显示的 DOM 的内存表示，可以在客户端或服务器（使用 Node）上呈现，并使用单向绑定进行操作。React 屏幕是使用 JSX 编写的，这是 JavaScript 的扩展，允许在 JavaScript 函数中轻松引用 HTML。

+   **Ember.js**：由 Yehuda Katz 创建并由一群活跃的开发人员社区贡献的非常强大的 JavaScript MVC 框架，Ember 被许多热门高流量的网站和应用程序使用，如 Groupon、Yahoo!（广告管理器 Plus）、Zendesk、Square、Discourse 和 LivingSocial。Ember 可用于构建移动和桌面应用程序：Apple Music 是一个使用 Ember 构建的著名桌面应用程序。Ember 以一种有主见的方式解决了客户端 Web 应用程序的端到端问题。作为 Web 和 JavaScript 标准的早期采用者，如 ES6、Web 组件和 Promises，Ember 配备了一套强大的生产工具和组件，使其成为一个完整的前端框架。

在本章中，我们将使用 Ember.js 来构建一个作为 Spring API 服务器前端的 SPA。我们将首先探索 Ember.js 及其核心组件和开发工具，然后使用 Ember 开发前端应用程序，连接到后端的基于 Spring 的 API 服务器。本章将使您成为现代技术栈上具有服务器端和客户端技能的全栈开发人员。

# 介绍 Ember.js

Ember 是一个全面的前端框架，用于创建雄心勃勃的 Web 应用程序。它是根据前端的**模型-视图-控制器**（**MVC**）架构模式建模的。其设计良好的组件具有明确定义的责任和丰富的功能，使开发人员能够使用大大减少的代码开发复杂的 Web 应用程序。在 Ember 应用程序中，屏幕是使用 Handlebars 模板组成的，当底层数据发生变化时，它们会自动更新自己。

Ember 在开箱即用时非常高效，具有全面的开发堆栈和友好的 API。Ember 开发堆栈包含以下工具：

+   **Ember CLI**：这是一个用于创建项目、脚手架和管理资源的命令行工具。它提供了一个带有实时重新加载的开发服务器、一个测试框架、模拟服务器和全面的资产管理支持。

+   **Ember Inspector**：这是一个用于 Ember 应用程序的调试器兼检查器工具，作为 Firefox 和 Chrome 浏览器的插件进行发布。它允许您在调试时评估和更改 Ember 对象、元素和变量，并提供运行中的 Ember 应用程序的可视化表示。

+   **Ember Data**：Ember 的这个子项目是一个数据持久化库，可以直接映射到远程数据源，比如 REST API。它通过诸如 API 端点之类的通道将 Ember 模型对象与服务器端的数据实体进行映射。Ember Data 为标准的 REST 和 JSON API 端点提供了适配器和序列化器，并允许您为任何数据源创建自己的适配器，例如浏览器的本地存储。

+   **Fastboot**：这是一个基于 Node.js 的服务器，用于 Ember 资源的服务器端渲染，消除了在加载静态资产后下载 JavaScript 有效负载的需求，从而提高了性能。

+   **Liquid Fire**：这为 Ember 视图提供了动画支持。

+   **测试框架**：Ember CLI 集成了 QUnit 来测试 Ember 资源。

Ember 是一个非常有主见的框架；这意味着你应该按照它自己的约定来构建应用程序，然后框架会处理剩下的事情。如果你遵循指南，你最终会写很少而且易读的代码。Ember CLI 通过简单的命令生成 Ember 项目结构和构件，符合框架的预期方式。

# Ember 应用程序的解剖结构

Ember 应用程序由一组具有明确定义的责任和属性的核心元素组成。它们在 Ember API 的 Ember 和 DS 命名空间下定义。

这张图描述了 Ember 应用程序的高级结构：

![Ember 应用程序的解剖结构](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00792.jpeg)

## 路由器

路由器管理应用程序状态。它将一组逻辑路由映射到路由器配置中映射的唯一 URL。

## 路由或路由处理程序

路由处理程序，也称为路由（在`Ember.Route`中定义），表示单个路由转换的处理程序。路由可以呈现显示屏的模板。路由提供一个可以被其模板和控制器使用的模型（数据）。它有一个相应的控制器，可以处理用户操作并维护状态。路由可以自行处理用户操作。

## 模板

模板是 HTML 片段，通常由路由和组件渲染。Ember 应用程序的用户界面由一系列模板组成。模板使用 Handlebars 语法，看起来像是带有一些 Handlebars 表达式的常规 HTML，这些表达式用双大括号（`{{ }}`）括起来。这些 Handlebars 表达式绑定 Ember 资源，如属性、对象、帮助器和组件。

## 组件

组件控制用户界面的行为。它们处理用户操作并管理模板使用的许多属性。组件由两部分组成：

+   一个扩展了`Ember.Component`的 JavaScript 对象，其中定义了操作和属性

+   一个渲染到父视图的模板，通常是路由的模板

## 模型

作为 Ember Data 项目的一部分，模型代表 Ember 应用程序中域数据的状态。一个 Ember 应用程序通常会有一组从`DS.Model`扩展的模型。路由通常会使用模板显示模型数据，并通过操作处理程序修改数据。模型通常从存储库（`DS.Store`）加载，而模型实例则从实际的持久存储中获取，通常是 Web 服务器上的 API 端点。模型可以持久保存到存储库；通常它们会被发送回适当的 API 端点。

## 控制器

控制器在现代 Ember 应用程序中的作用有限；它们将在未来版本中被弃用。目前，它们的用途仅限于维护路由的状态和处理用户操作。由于路由和组件可以处理操作，它们是添加操作处理程序的理想位置，而不是控制器。

除了这些核心元素，还有一些支持组件，可以帮助应用程序开发更加简单和优雅。

## 输入助手

这些是 Ember 捆绑的现成组件，用于从用户那里获取输入。它们大多是一般表单控件的 Ember 版本。例如`{{input}}`和`{{textarea}}`输入助手。自定义开发的组件可以类似于输入助手。

## 自定义助手

助手在模板内部不容易获得时，可以为应用程序添加自定义功能。它们大多用于某种格式化。例如`{{format-date}}`和`{{format-currency}}`。

## 初始化器

初始化器可以在应用程序启动时执行某些操作。有两种类型的初始化器：应用程序初始化器，在应用程序启动时执行；应用程序实例初始化器，在应用程序实例启动时加载。

## 服务

服务是可以保存数据和函数的对象，其范围是整个应用程序。它们通常用于封装跨多个路由的核心业务逻辑。服务可以被注入到控制器、路由、组件等中，从而可以调用它们的方法。

# 使用 Ember CLI

Ember CLI 是用于 Ember 应用程序的集成快速开发环境。基于 Broccoli，一个在 Node.js 上运行的快速可靠的资产管道，Ember CLI 是一个强大的命令行界面，集成了许多必要的 JavaScript 开发工具和优化实用程序。

Ember CLI 为 Ember 开发提供了以下功能和工具：

+   它为 Ember 应用程序创建了一个强大的基于约定的项目结构

+   它从命令行生成特定于 Ember 的应用程序资源，如路由、模板和组件

+   它支持在 Handlebars、HTMLBars 和 Emblem.js 格式中进行模板编写

+   它支持 ES2015（ES6）模块、CoffeeScript 和 EmberScript 语法的脚本编写

+   它支持在 CSS、Sass、Compass 和 Stylus 中进行 CSS 编写

+   它将 Node.js 风格的 ES2015 模块转换为 RequireJS 模型的 AMD 模块

+   它集成了 npm 和 Bower 包管理器来管理对 JS 库的依赖关系

+   它集成了一个带有 LiveReload 的开发服务器，可以自动重新构建和更新代码更改到所有连接的浏览器

+   它为应用程序资源执行资产管理功能（合并、最小化、混淆、版本控制等）

+   它通过使用插件和蓝图来共享代码和功能

在本章后面，我们将使用 Ember CLI 作为构建 Ember 应用程序及其各种构件的开发工具。

## 设置 Ember CLI

Ember CLI 依赖于 Node.js。因此，第一步是安装 Node.js。请按照网站[`nodejs.org`](http://nodejs.org)上的说明设置 Node.js。

一旦安装了 Node.js，就可以使用以下命令使用`npm`安装 Ember CLI：

```java
npm install -g ember-cli

```

现在，使用以下命令安装 Bower：

```java
npm install -g bower

```

您可以选择安装 Watchman 以更好地观察代码更改和 PhantomJS 测试运行环境。

## 使用 Ember CLI 命令开始

安装了 Ember CLI 后，您可以使用以下一组命令逐步创建 Ember 应用程序所需的构件：

| 命令 | 目的 |
| --- | --- |
| `ember` | 打印可用的命令。 |
| `ember new <appname>` | 生成一个名为`<appname>`的全新项目根目录，整个项目结构以及启动 Ember 应用程序所需的所有构件。 |
| `ember init` | 将当前目录转换为 Ember 应用程序，并生成所有必要的构件。 |
| `ember build` | 构建并生成可部署到`dist`目录的内容。使用环境标志指定环境，默认为`development`。 |
| `ember server (or serve)` | 在端口`4200`启动开发服务器。您可以使用`--port`标志指向另一个端口，例如`ember serve --port 8080`。 |
| `ember generate <generatortype> <name> <options>` | 生成特定的生成器，例如路由、模板和帮助程序，以及给定的名称和选项。输入`ember help generate`以获取可用生成器的完整列表。对于 POD 结构中的生成器，请使用`--pod`标志（稍后会解释）。 |
| `ember destroy <generatortype> <name> <options>` | 删除使用`ember generate`命令创建的构件。记得在生成构件时使用`--pod`标志。 |
| `ember test` | 使用 Testem 测试运行程序运行应用程序中编写的测试。 |
| `ember install <addon-name>` | 将给定的插件安装到应用程序中，并在`package.json`文件中注册它。 |

## Ember 项目结构

使用`ember new <project-name>`命令时，Ember CLI 根据约定生成和组织文件，并在构建和运行时编译它们并执行一系列任务。以下表格描述了 Ember CLI 生成的文件夹布局和重要文件：

| 文件/文件夹 | 描述 |
| --- | --- |
| `app/` | 这是 Ember 应用程序根目录。`index.html`文件和所有 JavaScript 文件和模板都放在这里的适当子目录下。除了`index.html`之外的所有内容都通过 ES6 模块转换器进行编译，然后被缩小和连接到`<app-name>.js`，然后在构建时由`index.html`文件加载。 |
| `app/index.html` | 这是从服务器加载的唯一 HTML 页面，它从`<app-name>.js`引导 Ember 应用程序，并使用嵌入其中的`<script/>`标签加载。Ember 在运行时从此基础 HTML 文档内部构建整个 DOM 结构。 |
| `app/app.js` | 这是 Ember 应用程序模块。这是应用程序的入口点，所有其他模块都在这里初始化并注入，以便根据解析器和特定环境的配置创建整个应用程序实例。 |
| `app/router.js` | 这是应用程序的路由配置模块。 |
| `app/adapters/` | Ember Data 模块的适配器放在这里。当第一次执行`ember generate adapter <model-name>`命令时，将生成此文件夹。 |
| `app/components/` | 所有组件都放在这里，除非使用了`--pod`选项。 |
| `app/controllers/` | 所有控制器都放在这里，除非使用了`--pod`选项。 |
| `app/helpers/` | 所有帮助程序都放在这里，除非使用了`--pod`选项。 |
| `app/models/` | 所有模型都放在这里，除非使用了`--pod`选项。 |
| `app/routes/` | 所有路由都放在这里，除非使用了`--pod`选项。 |
| `app/services` | 所有服务都放在这里，除非使用了`--pod`选项。 |
| `app/styles/` | 将应用程序的所有样式表放在这里，无论是 Sass、LESS、Stylus、Compass 还是纯 CSS。默认情况下只支持纯 CSS；您可以通过安装适当的`npm`模块来启用其他类型。对于 Sass，在命令行中输入`ember install ember-cli-sass`。对于 LESS，命令是`ember-cli-less`；对于 Compass，是`ember-cli-compass-compiler`，依此类推。对于默认的 CSS 选项，请将样式添加到`app.css`中。您还可以将样式组织在不同的 CSS 文件中，并将它们导入到您的`app.css`文件中。 |
| `app/templates/` | 所有模板都放在这里，除非使用了`--pod`选项。 |
| `bower.json` | 这是 Bower 配置文件。 |
| `bower_components/` | 由 Bower 管理的依赖项放在这里。 |
| `config/` | 应用程序配置文件放在这里。 |
| `config/environment.js` | 您的特定于环境的配置放在这个文件中。 |
| `dist/` | 构建过程生成的可部署文件放在这里。这是您需要发布的内容。 |
| `ember-cli-build.js` | 这是 Broccoli 构建文件。在这里包括所有由 Bower 和`npm`管理的资源。 |
| `node_modules` | 所有由 npm 管理的 node 依赖项放在这里。 |
| `package.json` | 这是 NPM 依赖项配置文件。 |
| `public/` | 这是一个用于未编译资产（如字体和图像）的目录。内容会按原样复制。 |
| `server/` | 这是您可以为模拟 API 和测试设置开发服务器的地方。 |
| `tests/` | 所有单元测试和集成测试都放在这里。 |
| `tmp/` | 这是一个用于构建执行的临时文件夹。 |
| `vendor/` | 将不由 npm 或 Bower 管理的外部依赖项放在这里。 |

在构建过程结束时，Ember CLI 会在`dist/directory`生成可部署文件。您需要分发该目录的内容，以便在发布时将可部署文件托管到 Web 服务器上。

## 使用 POD 结构进行工作

默认情况下，`ember generate <generator>`命令会在`app`根目录下直接生成特定资源目录内的工件。因此，所有路由都放在`app/routes`下，模板放在`app/templates`下，依此类推。然而，随着应用程序的增长，这变得有点难以维护。为了解决这个问题，Ember CLI 提供了使用`ember generate`命令生成工件时，使用`--pod`标志以特性驱动（POD）结构组织文件的选项。

为了使 POD 结构工作，您需要首先在`config/environment.js`中配置 POD 目录，如下面的代码所示：

```java
module.exports = function(environment) {
  var ENV = {
    ...
    podModulePrefix: 'my-ember-app/pod-modules',
    ...
    },
    ...
  return ENV;
};
```

前面的代码片段指定了使用`--pod`标志生成的所有工件将生成在`<app-root>/pod-modules`目录内。

一旦配置了 POD，您就可以开始使用`--pod`标志生成您的工件。

例如，如果您想在 POD 结构内生成一个路由，可以使用以下命令：

```java
ember generate route user --pod

```

这将在`/app/pod-modules/user/route.js`生成路由文件。

POD 模块将与特性相关的所有工件组合在一个地方，从而使其更易管理。

# 了解 Ember 对象模型

Ember 自带丰富的 API，扩展了原生 JavaScript 类，并引入了新的结构，提供了增强的功能，如双向数据绑定、属性观察等。它为大多数常见的 JavaScript 构造提供了更智能的替代方案，如对象和数组。

`Ember.Object`是所有 Ember 对象的主要基类。它提供了一个带有高级特性的类系统，如混入和构造方法。`Ember.Object`提供了许多特殊功能，如计算属性、数据绑定和属性值变化观察者。

## 声明类型（类）和实例

您可以以纯粹的面向对象的方式继承`Ember.Object`中的所有功能；如下面的代码所示，只需扩展它：

```java
var User = Ember.Object.extend({
   ...
});
```

前面的片段只是`User`类型的声明。现在，您需要实例化此类结构，以便在程序中使用它，如下所示：

```java
var User = Ember.Object.create();
```

您可以像前面的片段一样调用无参数构造函数，也可以将一组带有值的属性作为 JS 对象传递，以创建已声明类的实例，如下所示：

```java
var myUser = User.create({
    firstName: "John", 
    lastName: "Smith", 
    userName: "jsmith",
    password: "secretp@ss", 
    dateOfBirth: new Date(1980, 10, 24);
});
```

## 访问和变异属性

类型初始化后，您可以使用`get`方法访问其属性，如下所示：

```java
var name = myUser.get("name");
```

请记住始终使用`get`方法而不是`object.property`，因为 Ember 对象将托管属性存储在不同的哈希中，提供了一些特殊功能，而不像原始 JS 对象。

确保使用`set`方法以启用 Ember 对象的所有特殊功能，例如计算属性和属性观察：

```java
myUser.set('firstName', "Shameer");
```

## 计算属性

计算属性是从其他普通属性派生的虚拟属性，或者是由函数返回的值。`Ember.Object`也可以有计算属性，如下所示：

```java
var User = Ember.Object.extend({
   ...

   fullName: Ember.computed('firstName', 'lastName', function() {
      return `${this.get('firstName')} ${this.get('lastName')}`;
   }),
   ...
});
```

一旦实例化，您也可以以与普通属性相同的方式访问计算属性。它们在依赖属性更改时会自动更新自身。您也可以创建可变的可计算属性。以下是这种计算属性的合理实现示例：

```java
fullName: Ember.computed('firstName', 'lastName', {
    get(key) {
        return `${this.get('firstName')} ${this.get('lastName')}`;
    },
    set(key, value) {
        var [firstName, lastName] = value.split(/\s+/);
        this.set('firstName', firstName);
        this.set('lastName',  lastName);
        return value;
    }
})
```

由于计算属性就像任何其他函数一样，您可以向其添加任何业务逻辑。

## 属性观察者

您可以观察任何值的普通或计算属性的变化。为此目的，使用`Ember.Observer`注册属性。请参阅以下示例：

```java
var User = Ember.Object.extend({
   ...

   dateOfBirth: new Date(),
   dobChanged: Ember.observer('dateOfBirth', function() {
      // deal with the change
      console.log(`Date of birth updated. New value is: ${this.get('dateOfBirth')}`);
   })
});
```

在前面的片段中，`dobChanged`函数将在`dateOfBirth`属性更新时触发。您可以通过将所有属性作为参数传递到`Ember.observer`方法中来绑定多个属性到单个观察者方法中，然后再定义函数。

### 注意

计算属性也可以被观察。但是，直到访问计算属性之前，观察者方法才会被触发，即使依赖属性已经更新。

# 使用集合

Ember 使用一组核心集合类使数组操作更智能，如下表所示。这些类提供了许多方便的方法，抽象了复杂的数组操作：

| 集合类型 | 描述 |
| --- | --- |
| `Ember.Array` | 这是观察者友好的数组行为的抽象实现。预期具体实现已经实现了`length()`和`objectAt()`等方法。值得注意的方便方法有`any()`、`every()`、`filter()`、`filterBy()`、`find()`、`findBy()`、`forEach()`、`getEach()`、`map()`、`mapBy()`、`objectAt()`、`replace()`、`reverse()`、`sortBy`、`without()`等。 |
| `Ember.ArrayProxy` | `ArrayProxy`包装实现`Ember.Array`的对象，用于绑定用例和在迭代时交换内容。 |
| `Ember.MutableArray` | 这是`Array`的扩展，支持有序集合的数组。 |
| `Ember.Enumerable` | 这是用于枚举数组的 mixin。 |
| `Ember.NativeArray` | 这是上述所有内容中最具体的实现。在大多数情况下，您会使用它。 |

# 使用 Handlebars 构建 UI 模板

Ember.js 中的主要 UI 编写技术是 Handlebars。Handlebars 模板允许使用双大括号(`{{ }}`)内部放置的 Handlebars 表达式嵌入动态内容的 HTML 片段，动态脚本块。Handlebars 表达式使用路由、模型、控制器、组件、服务、工具甚至应用实例的属性执行数据绑定。以下是一个示例 Handlebars 表达式：

```java
<h3>Welcome <strong>{{loggedInUser.fullName}}.</strong></h3>
```

这段代码期望一个对象（最好是从`Ember.Object`派生的对象，尽管它也可以与普通 JS 对象绑定）具有名称为`loggedInUser`的属性，该对象在父上下文层次结构（模板、控制器、路由或应用程序）中的某个地方存在。然后，它与`loggedInUser`对象的`fullName`属性建立单向数据绑定；因此，它只显示绑定属性的值。

## Handlebars 帮助程序

Handlebars 依赖于帮助程序来处理动态脚本块内的业务逻辑。Handlebars 执行帮助程序内部实现的业务逻辑（如果有的话），放置在花括号内，或者它只是与绑定属性进行数据绑定。

Ember 提供了一组内置的帮助程序，并提供了一种很好的开发自定义帮助程序的方式。内置的帮助程序可以分为以下几类：

+   输入帮助程序

+   控制流帮助程序

+   事件帮助程序

+   开发帮助程序

帮助程序可以是内联的，也可以是块级的。内联帮助程序只是单行，类似于空的 HTML 和 XML 标记。看看`action`帮助程序，它是一个内联帮助程序，用于处理参数：

```java
{{action 'editUser' user}}
```

内联帮助程序可以嵌套，将更多动态值嵌入其中：

```java
{{action 'editUser' user (format-date today format='MMM DD, YYYY')}}
```

块帮助程序具有与 HTML 标记类似的开始和结束结构：

```java
{{#if isLoggedIn}}
    Welcome <strong>{{loggedInUser.fullName}}</strong>
{{/if}}
```

## 使用输入帮助程序进行数据绑定

模板可以使用输入帮助程序建立双向数据绑定。输入帮助程序主要是包装在 Ember 组件或视图中的 HTML 表单元素。Ember 提供了一些内置的输入帮助程序，例如`Ember.TextField`，`Ember.TextArea`和`Ember.Checkbox`。让我们来看一个例子：

```java
{{input placeholder="User Name" value=editingUser.userName}}
```

`{{input}}`是一个内置的输入帮助程序，它根据`type`属性的值（默认为`text`）包装 HTML 输入文本字段和复选框。它允许生成的`<input type="text"/>`标签与属性`editingUser.userName`之间进行双向绑定。每当其中一个值发生变化时，它会更新双向绑定的另一个参与者。`{{input}}`帮助程序支持许多有用的属性，例如`readonly`，`required`，`size`，`height`，`name`，`autofocus`，`placeholder`，`tabindex`和`maxlength`。

复选框是使用相同的`{{input}}`帮助程序创建的，但是通过将 type 属性设置为`checkbox`。`{{textarea}}`帮助程序表示 HTML`<textarea/>`组件。

您可以创建自己的输入帮助程序作为 Ember 组件，我们将在本章后面学习。

## 在 Handlebars 中使用控制流帮助程序

与大多数脚本语言一样，Handlebars 支持以下控制流帮助程序：

+   条件：

+   `{{if}}`

+   `{{#else}}`

+   `{{#else if}}`

+   `{{#unless}}`

+   循环：

+   `{{#each}}`

以下是`{{if}}`，`{{else}}`和`{{else if}}`帮助程序的示例：

```java
<div class="container">
{{#if isIdle}}
    You are idle for {{SessionService.idleMinutes}} minutes.
{{else if isLoggedIn}}
    Welcome <strong>{{loggedInUser.fullName}}</strong>
{{else}}
    <a {{action showLoginPopup}}>Please login</a>
{{/if}}
</div>
```

`{{#each}}`帮助程序用于循环（迭代）遍历集合，显示它，并在集合中的每个元素周围提供事件挂钩或操作。典型的`{{#each}}`帮助程序如下所示：

```java
{{#each model as |user|}}
<tr>
<td><a {{action 'showUser' user }}>{{user.id}}</a></td>
<td>{{user.userName}}</td>
    ...
</tr>
{{/each}}
```

## 使用事件帮助程序

事件帮助程序响应用户触发的操作。Ember 中的两个主要事件帮助程序是`{{action}}`和`{{link-to}}`帮助程序。

`{{link-to}}`帮助程序有助于导航到另一个路由。请参阅以下示例：

```java
{{link-to "Login here" "login" class="btn btn-primary"}}
```

`{{action}}`帮助程序通常添加到普通 HTML 元素中，以便将事件和事件处理程序附加到它：

```java
<a {{action "editTask" _task}} class="btn btn-success">Edit</a>
```

# 处理路由

Ember 应用程序在一组路由之间转换其状态；每个路由可以呈现一个显示当前状态的模板，并提供支持其基于状态的数据的控制器。路由在路由器配置内注册，通常在 Ember CLI 项目结构中的`router.js`内。路由在其自己的 JS 文件中定义。

路由可以通过命令行生成和自动配置，如下所示：

```java
ember generate route user --pod

```

该命令在`app/<pod-directory>/user/`目录下生成`route.js`和`template.hbs`。生成后，这两个文件都将具有基本结构，您需要根据特定要求完善它们。典型的路由将具有一个模型钩子，用于准备其数据。请参阅以下代码中给出的典型但最小的路由结构：

```java
import Ember from 'ember';

export default Ember.Route.extend({

  model: function(args) {
    return this.store.findAll('task');
  }
});
```

在上面的示例中，`model`钩子从`DS.Store`（Ember Data 存储库）获取数据。路由在 Ember CLI 项目的情况下呈现同一目录中的`template.hbs`文件，除非在`renderTemplate`方法中指定了另一个模板。路由的模型可供控制器和模板（通过控制器）进行操作和呈现。

# 使用组件处理 UI 行为

组件是 Ember 中动态 UI 片段或元素的构建块。它们呈现一个模板，可以选择由扩展`Ember.Component`的类支持。

创建组件的最简单方法是在`app/components/`目录中创建一个以破折号分隔的名称的模板文件。然后，您可以通过调用`{{<component-name>}}`并传递所需的参数将其嵌入到其他模板中。

组件是独立的，与客户端上下文完全隔离；所有必需的数据必须作为参数传递。但是，如果在模板中使用`{{yield}}`，它实质上变成了一个块（或容器）组件，您可以添加任何内容；此内容可以访问任何控制器属性和模型。

可以使用以下命令生成组件：

```java
ember generate component <component-name> --pod

```

该命令在`app/<pod-dir>/components/<component-name>/`目录下生成两个文件，`component.js`和`template.hbs`。如果不使用`--pod`标志，它将在`app/components/`目录下生成`<component-name>.js`和`<component-name>.hbs`文件。

组件将内容插入到 DOM 结构中，调用它，并控制插入内容的行为。默认情况下，组件呈现一个带有其模板生成的内容的`<div/>`元素。您可以通过在`component.js`文件中设置`tagName`属性来指定`<div/>`元素的不同 HTML 元素。同样，您可以使用另一个属性`assNameBindings`动态设置 CSS 类名。

组件为操纵组件的不同阶段提供了一些非常有用的生命周期钩子。可以在组件类中重写的一些生命周期方法是`didInsertElement()`、`willInsertElement()`和`willDestroyElement()`。

组件支持标准 HTML 元素事件，具体取决于使用的`tagName`。它们支持所有标准触摸事件，如`touchStart`和`touchMove`，键盘事件，如`keyDown`、`keyUp`和`keyPressed`，鼠标事件，如`mouseDown`、`mouseOver`、`click`和`doubleClick`，表单事件，如提交和更改，以及 HTML5 拖放事件，如`dragStart`和`dragEnd`。您只需在组件类内声明事件作为函数；组件将触发事件，并且相关函数将在用户与其交互时被调用。

除了事件之外，组件还可以响应动作处理程序，这些处理程序是在组件类的`actions`哈希内定义的命名函数。这些动作可以在组件的模板中的任何位置触发。动作处理程序可以接受来自客户端代码或模板的参数。

## 逐步构建 ToggleButton 组件

让我们逐步学习如何使用 Ember CLI 构建 Ember 组件。我们将构建一个切换按钮，当单击时切换开关。该组件仅根据其状态属性`isActive`更改其标签和样式。我们在此示例中使用 Bootstrap 样式。

首先，让我们使用 Ember CLI 逐步生成组件类和模板文件（`.hbs`）。在项目的根目录中，从命令行发出此命令：

```java
ember generate component toggle-button --pod

```

查看`app/<pod-dir>/components/toggle-button/`中生成的`component.js`和`template.hbs`文件。打开并查看`component.js`文件，它看起来如下所示：

```java
import Ember from 'ember';

export default Ember.Component.extend({
});
```

生成的`template.js`文件中只有`{{yield}}`。现在，您需要在这两个构件中添加必要的属性和业务逻辑，以使其成为一个合适的切换按钮组件。以下是修改后的`component.js`文件，具有适当的行为：

```java
import Ember from 'ember';

export default Ember.Component.extend({
  tagName: "button",
  attributeBindings: ['type'],
  type: "button",
  classNames: ["btn"],
  classNameBindings: ["isActive:btn-primary:btn-default"],
  activeLabel: "On",
  inactiveLabel: "Off",
  isActive: false,

  currentLabel: Ember.computed('isActive', 'activeLabel', 'inactiveLabel', function() {
    return this.get(this.get("isActive") ? "activeLabel" : "inactiveLabel");
  }),

  click: function() {
    var active = this.get("isActive")
    this.set("isActive", !active);
  }
});
```

在上述代码中，请注意您将`tagName`属性指定为`button`；否则，生成的 HTML 将是`<div/>`。另外，看看如何基于`isActive`属性动态绑定 CSS 类名。`currentLabel`属性是一个计算属性，它取决于其他几个属性。实际上，组件响应点击事件，并切换`isActive`变量。其他所有操作都将基于此事件进行。

现在，让我们看一下修改后的`template.js`文件，看看它如何利用`component.js`文件处理的属性和事件：

```java
{{currentLabel}}
```

惊喜！这就是模板中的所有内容。构建起来是如此简单。其余的繁重工作都是由`component.js`文件自己完成的。现在最有趣的部分是组件如何从客户端调用。让我们来看一下：

```java
{{toggle-button}}
```

这就是您在客户端代码中添加切换按钮组件的方式，它主要是路由的模板。您可以开始反复点击按钮，看到它的开启和关闭。

该组件可以通过覆盖其默认属性进行定制。让我们尝试从客户端更改其开启和关闭时的标签：

```java
{{toggle-button activeLabel="Turn me off now :)" inactiveLabel="Turn me On please.."}}
```

当您点击按钮时，您可以在屏幕上看到新的活动和非活动标签，切换它。切换按钮是 Ember 组件的最简单的示例，旨在让您对 Ember 组件有所了解。典型的 Ember 应用程序将拥有许多复杂的组件。将可重用的 UI 模块或部分转换为组件是使您的应用程序更加优雅和可维护的最佳方式。

# 使用 Ember Data 持久化数据

Ember Data 是 Ember 的数据访问机制。它提供了一个简单的 API 来处理数据，抽象了数据访问和各种数据源的复杂性和协议。使用 Ember Data，客户端可以像处理任何其他 Ember 对象一样处理数据模型。

Ember Data 定义了一组处理数据访问中各种角色和责任的基本组件。这些组件分组在命名空间`DS`下。以下表格描述了在`DS`下定义的最重要的 Ember Data 组件：

| 组件 | 目的 |
| --- | --- |
| `DS.Model` | 这是数据的基本单元，代表数据集合中的记录。您需要通过扩展此类来定义数据模型。它提供了保存、删除、重新加载和迭代属性、关系、相关类型等的方法。它提供了关于状态、属性、字段、关系、错误等的信息。此外，它提供了生命周期钩子事件。 |
| `DS.Store` | 这是 Ember Data 创建、获取和修改的所有数据的本地存储库。`Store`通过适配器获取数据，并将其转换为适当的`DS.Model`实例。使用序列化器，`Store`将模型实例序列化为适合服务器的形式。它提供了查询和创建新记录的方法。 |
| `DS.Adapter` | 这是一个抽象实现，接收来自`Store`的各种持久性命令，并将其转换为实际数据源（例如服务器 API 或浏览器本地存储）理解的形式。Ember 提供了两个具体的实现：`DS.RESTAdapter`和`DS.JSONAPIAdapter`。如果要更改默认行为或属性（例如远程 URL 和标头），请覆盖适配器。 |
| `DS.Serializer` | 这将`DS.Model`实例标准化为 API 的有效负载（或任何其他数据源），并将它们序列化回模型。两个默认的序列化器是`RestSerializer`和`JSONAPISerializer`。覆盖序列化器以自定义服务器的数据格式。 |

## Ember Data 架构

Ember Data 组件基于**promise**异步地相互通信进行数据访问操作。**Store**和**Adapter**的`query`和`find`方法是异步的，并且立即返回一个**promise**对象。一旦解析，模型实例就会被创建并返回给客户端。以下图表演示了 Ember Data 组件如何异步协调`find`方法操作：

![Ember Data architecture](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00793.jpeg)

Ember Data 组件的客户端（通常是路由、组件、控制器、服务等）不直接处理适配器和序列化器。它们与**Store**和模型进行正常的数据访问操作。由于`Route.model`方法（钩子）支持**promise**对象，转换将暂停，直到**promise**解析。我们不处理解析 promise，因此也不处理异步性；相反，Ember 会智能地处理它。

## 定义模型

模型代表了 Ember 应用程序的领域数据。它们需要以正确的结构定义并在存储中注册，然后才能用于数据访问。Ember CLI 项目期望模型位于`app/models/`目录下，或者在使用 POD 目录结构的情况下为`app/<pod-dir>/models/`。

让我们看一个示例模型定义。以下是用户模型的定义：

```java
import DS from 'ember-data';

export default DS.Model.extend({

  name: DS.attr('string'),
  userName: DS.attr('string'),
  password: DS.attr('string'),
  dateOfBirth: DS.attr('date'),
  profileImage: DS.belongsTo('file')
});
```

模型属性默认可以是字符串、数字、布尔和日期类型。对于自定义类型，您需要子类化`DS.Transform`。属性也可以有默认值。您可以像下面这行所示指定默认值：

```java
dateOfBirth: DS.attr('date', { defaultValue: new Date() }),
```

## 定义模型关系

模型可以在它们之间进行一对一、一对多和多对多的关系：

+   一个一对一关系在两个模型定义中使用`DS.belongsTo`来定义

+   一个一对多关系在一个模型中使用`DS.belongsTo`，在另一个模型中使用`DS.hasMany`来定义

+   当两个模型都为对方定义了`DS.hasMany`时，就声明了多对多关系

# 构建 Taskify 应用程序

嘿，是时候全面构建我们的 Taskify 应用程序了。首先，让我们回到使用 Spring 构建一个合适的 API 层，然后再回顾 Ember 构建前端 SPA。我们将使用 Spring Data 连接到 API 服务器并访问数据。

为简单起见，我们不会对服务器应用任何安全性措施；我们只会专注于对两个模型`User`和`Task`执行 CRUD 操作。`User`和`Task`彼此相关：`Task 属于 User`。我们将在服务器端和客户端构建模型。让我们看看这两种技术如何在没有直接依赖的情况下协同工作。

# 构建 API 服务器应用程序

我们在第二章中探讨了使用 Spring MVC 构建 Web 应用程序，*使用 Spring Web MVC 构建 Web 层*。在第三章中，*使用 Spring 访问数据*，我们还学习了如何使用 Spring Data JPA 持久化数据。我们将再次应用这两种技术来构建 Taskify 的 API 应用程序。

## 设置和配置项目

由于我们已经学习了使用 Spring Data JPA 创建 Spring MVC 应用程序的基础知识，因此在这一点上，我们只会详细介绍 API 端点的具体内容。有关 Spring MVC 配置，请参阅第二章，“使用 Spring Web MVC 构建 Web 层”，有关 Spring Data JPA 的详细信息，请参阅第三章，“使用 Spring 访问数据”。使用以下步骤设置和配置项目：

1.  创建一个 Spring MVC 应用程序，依赖于 Spring Data JPA 和您选择的数据库。

1.  启用 JPA 存储库，指定基本包。对于 JavaConfig，注释如下：

```java
@EnableJpaRepositories(basePackages = "com.taskify.dao")
```

1.  使用您选择的风格配置 Spring Data JPA 工件，如`DataSource`、`JdbcTemplate`、`TransactionManager`和`EntityManager`。

## 定义模型定义 - User 和 Task

该应用程序有以下两个模型作为域对象：

![定义模型定义 - User 和 Task](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00794.jpeg)

现在我们需要将这些作为 Java 类实现，并将其注释为 JPA 实体，以便我们可以将它们持久化到数据库中，如下所示：

`User.java`

```java
package com.taskify.domain;

import java.util.Date;
...
@Entity
@Table(name = "TBL_USER", uniqueConstraints = @UniqueConstraint(name = "UK_USER_USERNAME", columnNames = {"USER_NAME" }) )
public class User {

  @Id
  @GeneratedValue
  private Long id;

  @Column(name = "NAME", length = 200)
  private String name;

  @Column(name = "USER_NAME", length = 25)
  private String userName;

  @Column(name = "PASSWORD", length = 20)
  private String password;

  @Column(name = "DOB")
  @Temporal(TemporalType.TIMESTAMP)
  private Date dateOfBirth;
  ...
  //Getters and setters go here..

}
```

`Task.java`

```java
package com.taskify.domain;

import java.util.Date;
...
@Entity
@Table(name = "tbl_task")
public class Task {
  @Id
  @GeneratedValue
  private Long id;

  @Column(name = "NAME", length = 500)
  private String name;

  @Column(name = "PRIORITY")
  private int priority;

  @Column(name = "STATUS")
  private String status;

  @ManyToOne(optional = true)
  @JoinColumn(name = "CREATED_USER_ID", referencedColumnName = "ID")
  private User createdBy;

  @Column(name = "CREATED_DATE")
  @Temporal(TemporalType.TIMESTAMP)
  private Date createdDate;

  @ManyToOne(optional = true)
  @JoinColumn(name = "ASSIGNEE_USER_ID", referencedColumnName = "ID")
  private User assignee;

  @Column(name = "COMPLETED_DATE")
  @Temporal(TemporalType.TIMESTAMP)
  private Date completedDate;

  @Column(name = "COMMENTS")
  private String comments;
  ...
  //Getters and setters go here..
}
```

一旦 JPA 实体准备就绪，为`User`和`Task`创建 DAO——`UserDAO`和`TaskDAO`——并用`@Repository`注释。作为最佳方法并且为了正确的应用层分层，也创建相应的`@Service` bean。由于我们已经在前几章中介绍了 JPA `@Repository`和`@Service`类，这些 bean 的代码在此处不列出。您可以在本书提供的代码包中找到确切的代码。

## 为 Taskify 应用程序构建 API 端点

API 服务器的目的是公开 API 端点，以供客户端使用，包括 Taskify Ember 前端应用程序。让我们按照 REST 模型构建这些 Web 服务，并支持 JSON 数据格式。

在本节中，我们将列出两个使用`@RestController`注释的类：`UserController`和`TaskController`。处理程序方法支持异步、非阻塞 IO，因此它们更具可伸缩性和更快速。处理程序方法设计为 REST 模型。HTTP 方法`GET`、`POST`、`PUT`和`DELETE`与**创建**、**读取**、**更新**和**删除**（CRUD）操作相对应。

### UserController.java

`UserController`公开了对`User`实体的 CRUD 操作的端点。您可以在其代码中看到`UserController`接受和生成 JSON 数据的端点，如下所示：

```java
package com.taskify.web.controller;

import java.util.List;
...

/**
 * Handles requests for user related pages.
 */
@RestController
@RequestMapping("/api/v1/user")
@CrossOrigin
public class UserController {

  private static final Logger = LoggerFactory.getLogger(UserController.class);
  @Autowired
  private UserService;

  @RequestMapping(method = RequestMethod.GET)
  @ResponseBody
  public Callable<List<User>> listAllUsers() {
    return new Callable<List<User>>() {

      @Override
      public List<User> call() throws Exception {
        return userService.findAllUsers();
      }
    };
  }

  @RequestMapping(method = RequestMethod.POST, consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
  @ResponseBody
  public Callable<User> createNewUser( @RequestBody CreateUserRequest request) {
    logger.info(">>>>>>>> Creating User, request - " + request);
    return new Callable<User>() {
      @Override
      public User call() throws Exception {
        return userService.createNewUser(request.getUser());
      }
    };
  }

  @RequestMapping(path = "/{id}", method = RequestMethod.PUT, consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
  @ResponseBody
  public Callable<User> updateUser(@PathVariable("id") Long id, @RequestBody UpdateUserRequest request) {
    logger.info(">>>>>>>> updateUser, request - " + request);
    return new Callable<User>() {
      @Override
      public User call() throws Exception {
        User existingUser = userService.findById(id);
        existingUser.setName(request.getUser().getName());
        existingUser.setPassword(request.getUser().getPassword());
        existingUser.setUserName(request.getUser().getUserName());
        userService.updateUser(existingUser);
        return existingUser;
      }
    };
  }

  @RequestMapping(path = "/{id}", method = RequestMethod.GET)
  public Callable<User> getUser(@PathVariable("id") Long id) {
    return new Callable<User>() {
      @Override
      public User call() throws Exception {
        return userService.findById(id);
      }
    };
  }

  @RequestMapping(path = "/{id}", method = RequestMethod.DELETE)
  @ResponseStatus(value = HttpStatus.NO_CONTENT)
  public Callable<Void> deleteUser(@PathVariable("id") Long id) {
    return new Callable<Void>() {
      @Override
      public Void call() throws Exception {
        userService.deleteUser(userService.findById(id));
        return null;
      }
    };
  }
}
```

### TaskController.java

`TaskController`映射了围绕`Task`实体的 CRUD 操作的请求端点。其代码如下：

```java
package com.taskify.web.controller;

import java.util.List;
...

@RestController
@RequestMapping("/api/v1/task")
@CrossOrigin
public class TaskController {

  private static final Logger = LoggerFactory.getLogger(TaskController.class);

  @Autowired
  private UserService;

  @Autowired
  private TaskService;

  private static final int[] priorities = new int[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };

  @RequestMapping(method = RequestMethod.GET)
  @ResponseBody
  public Callable<List<Task>> listAllTask() {
    return new Callable<List<Task>>() {
      @Override
      public List<Task> call() throws Exception {
        return taskService.findAllTasks();
      }
    };
  }

  @RequestMapping(method = RequestMethod.POST, consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
  @ResponseBody
  public Callable<Task> createNewTask( @RequestBody CreateTaskRequest request) {
    logger.info(">>>>>>>> Creating Task, request - " + request);
    return new Callable<Task>() {
      @Override
      public Task call() throws Exception {
        return taskService.createTask(request.getTask());
      }
    };
  }

  @RequestMapping(path = "/{id}", method = RequestMethod.PUT, consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
  @ResponseBody
  public Callable<Task> updateTask(@PathVariable("id") Long id, @RequestBody UpdateTaskRequest request) {
    logger.info(">>>>>>>> updateTask, request - " + request);
    return new Callable<Task>() {
      @Override
      public Task call() throws Exception {
        Task existingTask = taskService.findTaskById(id);
        existingTask.setName(request.getTask().getName());
        existingTask.setPriority(request.getTask().getPriority());
        existingTask.setStatus(request.getTask().getStatus());
        existingTask.setCreatedBy(userService.findById( request.getTask().getCreatedBy().getId()));

        if(request.getTask().getAssignee() != null &&
           request.getTask().getAssignee().getId() != null) {
             existingTask.setAssignee(userService.findById(
             request.getTask().getAssignee().getId()));
        } else {
          existingTask.setAssignee(null);
        }
        taskService.updateTask(existingTask);
        return existingTask;
      }
    };
  }

  @RequestMapping(path = "/{id}", method = RequestMethod.GET)
  public Callable<Task> getTask(@PathVariable("id") Long id) {
    return new Callable<Task>() {
      @Override
      public Task call() throws Exception {
        return taskService.findTaskById(id);
      }
    };
  }

  @RequestMapping(path = "/{id}", method = RequestMethod.DELETE)
  @ResponseStatus(value = HttpStatus.NO_CONTENT)
  public Callable<Void> deleteTask(@PathVariable("id") Long id) {
    return new Callable<Void>() {
      @Override
      public Void call() throws Exception {
        taskService.deleteTask(id);
        return null;
      }
    };
  }
}
```

我们已经为 API 服务器构建了所有必要的工件。您可以打包应用程序并部署它。您应该能够在`http://<app-context-root>/api/v1/user`访问`UserController`处理程序，并在`http://<app-context-root>/api/v1/task/`访问`TaskController`处理程序。现在让我们构建前端。

# 构建 Taskify Ember 应用程序

让我们回到 Ember 开发，构建我们的 SPA。按照以下步骤进行。我们将偶尔参考本章的前几节，并在这里详细说明具体内容。

## 将 Taskify 设置为 Ember CLI 项目

让我们生成项目并设置所有工件。按照以下步骤进行：

1.  使用 Ember CLI 从命令行创建一个新的 Ember 项目：

```java

ember new taskify

```

1.  安装`broccoli-merge-trees`和`broccoli-static-compiler`以获得更丰富的 Broccoli 配置。从命令行发出以下命令：

```java

npm install --save-dev broccoli-merge-trees
npm install --save-dev broccoli-static-compiler

```

1.  从命令行使用 Bower 安装 Bootstrap：

```java

bower install bootstrap

```

1.  在`ember-cli-build.js`文件中配置 Broccoli 以包括 bootstrap.js、CSS 和字体：

```java
  var mergeTrees = require('broccoli-merge-trees');
  var pickFiles = require('broccoli-static-compiler');
  var extraAssets = pickFiles('bower_components/bootstrap/dist/fonts',{ srcDir: '/', files: ['**/*'], destDir: '/fonts' });

  app.import('bower_components/bootstrap/dist/css/bootstrap.css');
  app.import('bower_components/bootstrap/dist/js/bootstrap.js');

  return mergeTrees([app.toTree(), extraAssets]);
```

1.  在应用程序中，我们将使用一个名为`ember-bootstrap-datetimepicker`的第三方 Ember 插件。让我们将其安装到项目中：

```java

ember install ember-bootstrap-datetimepicker

```

1.  构建`npm`和`bower`依赖项：

```java

npm install
bower install

```

1.  使用`ember serve`命令启动 Ember 服务器，并确保您的应用程序可以在`http://localhost:4200/`访问。

1.  在`/config/environment.js`中设置 POD 目录：

```java
  var ENV = {
    modulePrefix: 'ember-webapp-forspring',
    podModulePrefix: 'ember-webapp-forspring/modules',
    ...
  }
```

现在我们可以开始在这个 POD 目录中生成所需的 Ember 构件。

## 设置 Ember Data

我们需要两个模型：`User`和`Task`。让我们首先使用以下代码生成它们。对于模型，我们不使用 POD：

```java

ember generate model user
ember generate model task

```

在`/app/models/`文件夹下找到生成的模型。打开它们并设置属性和关系：

`User.js`

```java
import DS from 'ember-data';

export default DS.Model.extend({
  name: DS.attr('string'),
  userName: DS.attr('string'),
  password: DS.attr('string'),
  dateOfBirth: DS.attr('date')
});
```

`Task.js`

```java
import DS from 'ember-data';

export default DS.Model.extend({
  name: DS.attr('string'),
  priority: DS.attr('number'),
  status: DS.attr('string'),
  createdBy: DS.belongsTo('user'),
  createdDate: DS.attr('date'),
  assignee: DS.belongsTo('user'),
  completedDate: DS.attr('date'),
  comments: DS.attr('string'),
});
```

让我们生成一个（Ember Data）应用程序适配器，它具有所有适配器共有的一些全局属性：

```java

ember generate adapter application

```

打开生成的`/app/adapters/application.js`文件，并添加两个属性`host`和`namespace`，并使用以下代码中显示的正确值。之后，除非单独覆盖，否则所有模型的适配器将使用这些属性：

```java
import Ember from 'ember';
import DS from 'ember-data';

export default DS.RESTAdapter.extend({
  host: 'http://<apiserver-context-root>',
  namespace: 'api/v1'
});
```

我们需要覆盖默认的序列化程序，因为 Ember Data 期望依赖对象的 ID 进行并行加载，其中 API 服务器发送嵌入的嵌套对象。因此，从命令行生成两个序列化程序，然后适当更新内容：

```java

ember generate serializer user
ember generate serializer task

```

使用以下内容更新生成的`/app/serializers/user.js`文件：

```java
import DS from 'ember-data';

export default DS.RESTSerializer.extend(DS.EmbeddedRecordsMixin, {
    attrs: {
        profileImage: {embedded: 'always'},
    },
});
```

使用以下内容更新生成的`/app/serializers/task.js`文件：

```java
import DS from 'ember-data';

export default DS.RESTSerializer.extend(DS.EmbeddedRecordsMixin, {
    attrs: {
        createdBy: {embedded: 'always'},
        assignee: {embedded: 'always'},
    },
});
```

## 配置应用程序路由

路由代表应用程序的状态。它们需要在应用程序的路由器中注册，以便启用导航。我们的应用程序有三个主要路由：`index`，`user`和`task`。让我们在`pod`目录中生成它们。从命令行执行：

```java

ember generate route index --pod
ember generate route user --pod
ember generate route task --pod

```

现在看一下`router.js`；您将在那里看到这些新路由已注册。此外，在 POD 目录下为每个生成的`route.js`和`template.hbs`文件将存在。

## 构建主屏幕

现在，让我们设置索引模板，以显示系统中任务总数和未完成任务的数量。打开`/app/modules/index/template.js`文件并更新内容：

```java
<div class="container">
  <h1>Welcome to Taskify!</h1>
  <hr />
  <P>There are <strong>{{model.openTasks.length}}</strong> open
    {{#link-to "task"}}tasks{{/link-to}} out of total
    <strong>{{model.tasks.length}}</strong> in the system</P>
</div>
```

上述模板使用 Handlebars 绑定模型属性，并期望模型加载正确的数据。让我们在`route.js`文件中构建模型：

```java
import Ember from 'ember';

export default Ember.Route.extend({
  model: function() {
    var _model = Ember.Object.extend({
      tasks: null,
      openTasks: Ember.computed("tasks", function() {
        var _tasks = this.get("tasks");
        return Ember.isEmpty(_tasks) ? Ember.A([]): _tasks.filterBy("status", "Open");
      }),
    }).create();

    this.store.findAll('task').then(function(_tasks) {
    _model.set("tasks", _tasks);
    return _model;
  });
    return _model;
});
```

在上述代码中，模型钩子首先使用`DS.Store`（Ember Data）从服务器加载数据，构造具有属性的模型对象，包括计算属性，然后返回。主屏幕将看起来像以下图片（暂时忽略标题）：

![构建主屏幕](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00795.jpeg)

## 构建用户界面

现在，让我们为系统中所有用户列出用户的用户界面。首先在路由的模型钩子内构建模型。在`/app/modules/user/route.js`中添加以下方法：

```java
model: function() {
  return this.store.findAll('user');
},
```

您可以看到 Ember 和 Ember Data 如何美妙地协同工作，以简化获取、转换和反序列化数据为模型实例，并最终使其异步可供模板和控制器消费，而不会阻塞屏幕。

现在让我们在屏幕上显示这些数据。使用以下内容更新`/app/modules/user/template.hbs`文件：

```java
<div class="container">
  <h1>List of users</h1><hr />
  <p class="text-right">
    <a {{action 'createNewUser'}} class="btn btn-primary" role="button">Create New User</a></p>

  <table class="table table-hover">
    <thead><tr>
      <th>ID</th>
      <th>User name</th>
      <th>Name</th>
      <th>Date Of Birth</th>
      <th>Edit</th>
      <th>Delete</th>
    </tr></thead>
  <tbody>
  {{#each model as |user|}}
  <tr>
    <td><a {{action 'showUser' user }}>{{user.id}}</a></td>
    <td>{{user.userName}}</td>
    <td>{{user.name}}</td>
    <td>{{format-date user.dateOfBirth format='MMM DD, YYYY'}}</td>
    <td><button type="button" class="btn btn-default" aria-label="Edit user" {{action 'editUser' user}}>
        <span class="glyphicon glyphicon-pencil" aria-hidden="true"></span></button></td>
    <td><button type="button" class="btn btn-default" aria-label="Delete user" {{action 'deleteUser' user}}>
        <span class="glyphicon glyphicon-trash" aria-hidden="true"></span></button></td>
  </tr>
  {{/each}}
  </tbody>
  </table>
</div>
```

现在您可以在`http://localhost:4200/user`看到`user`路由，它看起来像这样：

![构建用户界面](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00796.jpeg)

## 构建自定义帮助程序

在`template.hbs`文件中，您可能会注意到一个自定义帮助程序：

```java
{{format-date user.dateOfBirth format='MMM DD, YYYY'}}
```

让我们构建它；你应该已经收到一个错误，因为这个帮助程序还没有被定义。从命令行使用以下命令生成它：

```java

ember generate helper format-date

```

使用以下脚本更新生成的`/app/helpers/format-date.js`文件：

```java
import Ember from 'ember';

export function formatDate(params, hash) {
  if(!Ember.isEmpty(hash.format)) {
    return moment(new Date(params)).format(hash.format);
  }
  return params;
}

export default Ember.Helper.helper(formatDate);
```

现在看看您的浏览器；用户列表应该正确渲染。

## 添加操作处理程序

在`/app/modules/user/template.hbs`文件内，有四个动作调用：`createNewUser`、`showUser`、`editUser`和`deleteUser`。所有这些方法都接受一个`user`变量作为参数。让我们首先将这些动作添加到`/app/modules/user/route.js`中：

```java
actions: {
  createNewUser: function() {
    this.controller.set("_editingUser", null);
    this.controller.set("editingUser", Ember.Object.create({
      name: null,
      userName: null,
      password: null,
      dateOfBirth: new Date()
    }));

  Ember.$("#userEditModal").modal("show");
  },
  showUser: function(_user) {
    this.controller.set("_editingUser", _user);
    this.controller.set("editingUser", Ember.Object.create(
    _user.getProperties("id", "name", "userName", "password", "dateOfBirth", "profileImage")));
    Ember.$("#userViewModal").modal("show");
  },
  editUser: function(_user) {
    this.actions.closeViewModal.call(this);
    this.controller.set("_editingUser", _user);
    this.controller.set("editingUser", Ember.Object.create(
    _user.getProperties("id", "name", "userName", "password", "dateOfBirth", "profileImage")));
    Ember.$("#userEditModal").modal("show");
  },
  deleteUser: function(_user) {
    if(confirm("Delete User, " + _user.get("name") + " ?")) {
      var _this = this.controller;
      _user.destroyRecord().then(function() {
        _this.set("editingUser", null);
        _this.set("_editingUser", null);
        _this.set("model", _this.store.findAll('user'));
      });
    }
  }
}
```

## 构建自定义组件-模态窗口

在上述代码清单中，`createNewUser`和`editUser`方法都使用 jQuery 使用`userViewModal`。这是一个作为自定义 Ember 组件构建的 Bootstrap 模态窗口。实际上，有四个组件以嵌套方式一起工作：`{{modal-window}}`、`{{modal-header}}`、`{modal-body}}`和`{{modal-footer}}`。

首先让我们从命令行生成这些工件：

```java

ember generate component modal-window --pod
ember generate component modal-header --pod
ember generate component modal-body --pod
ember generate component modal-footer --pod

```

`component.js`和`template.hbs`文件应该生成在`/app/modules/components/<component-name>/`目录下。现在让我们更新`.js`和`.hbs`文件，使其成为一个真正的模态窗口：

`modal-window/template.hbs`

```java
<div class="modal-dialog" role="document">
<div class="modal-content">{{yield}}</div>
</div>
```

`modal-window/component.js`

```java
import Ember from 'ember';

export default Ember.Component.extend({
  classNames: ["modal", "fade"],
  attributeBindings: ['label:aria-label', 'tabindex', 'labelId:aria-labelledby'], ariaRole: "dialog", tabindex: -1, labelId: Ember.computed('id', function() {
    if(Ember.isEmpty(this.get("id"))) {
      this.set("id", this.get("parentView.elementId") + "_Modal");
    }
  return this.get('id') + "Label";
  })
});
```

`modal-header/template.hbs`

```java
{{yield}}
```

`modal-header/component.js`

```java
import Ember from 'ember';

export default Ember.Component.extend({
  classNames: ["modal-header"],
});
```

`modal-body/template.hbs`

```java
{{yield}}
```

`modal-body/component.js`

```java
import Ember from 'ember';

export default Ember.Component.extend({
  classNames: ["modal-body"],
});
```

`modal-footer/template.hbs`

```java
{{yield}}
```

`modal-footer/component.js`

```java
import Ember from 'ember';

export default Ember.Component.extend({
  classNames: ["modal-footer"],
});
```

### 使用{{modal-window}}构建 userEditModal

这四个与模态相关的组件已经构建完成；现在是将`userEditModal`添加到`user/template.js`文件的时候了。将以下代码或`userEditModal`添加到`user/template.js`文件中：

```java
{{#modal-window id="userEditModal"}}

  {{#modal-header}}
  <button type="button" class="close" {{action "closeEditModal"}} aria-label="Close"><span aria-hidden="true">&times;</span></button>
  <h4 class="modal-title" id=labelId>{{modalTitle}}</h4>
  {{/modal-header}}

  {{#modal-body}}
  <form> <div class="form-group">
  <label for="txtName">Full Name:</label>
  {{input class="form-control" id="txtName" placeholder="Full Name" value=editingUser.name}} </div>
  <div class="form-group"> <label for="txtUserName">Username:</label>
  {{input class="form-control" id="txtUserName" placeholder="User Name" value=editingUser.userName}}</div>
  <div class="form-group"> <label for="txtPassword">Password:</label>
  {{input type="password" class="form-control" id="txtPassword" placeholder="Your secret password" value=editingUser.password}}</div>
  <div class="form-group"><label for="calDob">Date of Birth:</label>
  {{bs-datetimepicker id="calDob" date=editingUser.dateOfBirth
       updateDate=(action (mut editingUser.dateOfBirth))
       forceDateOutput=true}} </div> </form>
  {{/modal-body}}

  {{#modal-footer}}
  <a {{action "saveUser"}} class="btn btn-success">Save</a>
  <a {{action "closeEditModal"}} class="btn btn-primary">Cancel</a>
  <a {{action 'deleteUser' _editingUser}} class="btn btn-danger"> Delete </a>
  {{/modal-footer}}
{{/modal-window}}
```

上述代码清单将用户编辑表单与`{{modal-body}}`整合在一起，表单标题在`{{modal-header}}`内，动作按钮在`{{modal-footer}}`内，所有这些都在 ID 为`userEditModal`的`{{modal-window}}`内。只需点击用户行的**编辑**按钮；您将看到这个漂亮的模态窗口在您面前弹出：

![使用{{modal-window}}构建 userEditModal](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00797.jpeg)

`userEditModal`的**保存**按钮调用`saveUser`动作方法，**取消**按钮调用`closeEditModal`动作，**删除**按钮调用`deleteUser`。让我们将它们添加到`user/route.js`的`actions`哈希中，紧挨着`deleteUser`：

```java
...
closeEditModal: function() {
  Ember.$("#userEditModal").modal("hide");
  this.controller.set("editingUser", null);
  this.controller.set("_editingUser", null);
},
closeViewModal: function() {
  Ember.$("#userViewModal").modal("hide");
  this.controller.set("editingUser", null);
  this.controller.set("_editingUser", null);
},

saveUser: function() {
  if(this.controller.get("_editingUser") === null) {
  this.controller.set("_editingUser",this.store.createRecord("user",
    this.controller.get("editingUser").getProperties("id", "name", "userName", "password", "dateOfBirth")));
  } else {
    this.controller.get("_editingUser").setProperties(
         this.controller.get("editingUser").getProperties("name", "userName", "password", "dateOfBirth"));
  }
  this.controller.get("_editingUser").save();
  this.actions.closeEditModal.call(this);
}
```

同样，`user/template.js`有`userViewModal`，它只以只读格式显示用户数据。现在，你可以很容易地从`userEditModal`中派生它；因此，我们在这里不列出它。

## 构建任务屏幕

任务屏幕遵循与用户屏幕相同的模式。本节仅描述与用户屏幕逻辑上不同的部分，并假定您将从用户屏幕开始开发任务屏幕，并整合此处描述的更改。此外，您可以从本书的附带项目文件中查看完整的代码。

任务屏幕除了模型数据（任务列表）之外，还有一些额外的特定状态数据。为了在任务屏幕处于活动状态时维护这些数据，我们将创建一个控制器：

```java

ember generate controller task --pod

```

`Task`和`User`之间的关系是，任务由一个用户创建并分配给另一个用户。因此，在编辑任务（或创建新任务）屏幕上，应该显示一个用户列表，以便可以从列表中选择一个用户。为此，我们需要将用户列表从`DS.store`加载到控制器内的一个变量中。以下是加载`user`列表的控制器方法：

```java
loadUsers: function() {
  this.set("allUsers", this.store.findAll('user'));
}.on("init"),
```

这个方法将在控制器初始化时触发，由`.on("init")`构造提供。渲染用户列表的模板代码摘录在这里：

```java
<div class="form-group">
  <label for="calDob">Created By:</label>
  <select onchange={{action "changeCreatedBy" value="target.value"}} class="form-control">
  {{#each allUsers as |user|}}
    <option value={{user.id}} selected={{eq editingTask.createdBy.id user.id}}>{{user.name}}</option>
  {{/each}}
  </select>
</div>
```

`changeCreatedBy`动作方法在此处列出：

```java
changeCreatedBy: function(_userId) {
  this.get("editingTask").set("createdBy", this.get("allUsers").findBy("id", _userId));
},
```

同样，任务优先级也是从 1 到 10 的整数列表。加载它们的代码在这里（这些代码放在控制器内）：

```java
taskPriorities: [],
  loadTaskPriorities: function() {
  for(var _idx=1; _idx<11; _idx++) {
    this.taskPriorities.pushObject(_idx);
  }
}.on("init"),
```

优先级选择框的代码如下：

```java
<div class="form-group">
  <label for="selectPriority">Priority:</label>
  <select onchange={{action (mut editingTask.priority) value="target.value"}} class="form-control">
  {{#each taskPriorities as |priority|}}
   <option value={{priority}} selected={{eq editingTask.priority priority}}>{{priority}}</option>
  {{/each}}
  </select>
</div>
```

作为进一步的步骤，您可以在应用程序的两端都添加安全性。您可以为已登录的用户个性化任务。Ember 还支持 WebSockets。任务可以在分配给其他地方的已登录用户时被推送到客户端。为简单起见，这些高级功能在本章中没有涵盖。然而，通过您在本章和前几章中获得的知识，您已经可以舒适地实现端到端的安全性和使用 WebSockets 进行实时更新，这些功能可以在 Taskify 中实现。

# 摘要

本章介绍了单页应用程序的概念，并将 Taskify 前端作为 SPA 实现，连接到后端基于 Spring 的 API 服务器。在构建前端时，我们对 Ember.js 及其工具有了相当的了解。Spring 和 Ember 共同简化了构建这种类型的复杂富 Web 应用程序。使用 Ember 只是说明了 Spring 如何为现代 SPA 的后端提供支持。Spring 支持构建在其他框架上的 SPA，例如由全球各地的团队创建的 Angular、React 和 Backbone。

到目前为止，我们已成功涵盖了 Spring 框架的最重要特性。这个基础使您能够进入 Spring 组合项目的更高级功能。Spring 集成、Spring AMQP、Spring Cloud 和 Spring Web Services 等项目解决了企业计算的更复杂的问题。通过本书所获得的知识，您现在可以使用 Spring 框架及其子项目设计强大的解决方案。



# 第七章：与其他 Web 框架集成

Spring 框架提供的灵活性可以选择第三方产品是 Spring 的核心价值主张之一，Spring 支持与第三方表示框架的集成。虽然 Spring 的表示层框架 Spring MVC 为 Web 应用程序的开发带来了最大程度的灵活性和效率，但 Spring 允许您集成最流行的表示框架。

Spring 可以与 Java 的太多 Web 框架集成，以至于无法在本章中包括所有，只有最流行的 JSF 和 Struts 将被解释。

# Spring 的 JSF 集成

JSF Web 应用程序可以通过在`web.xml`中加载 Spring 上下文文件（通过上下文加载器监听器）轻松集成 Spring。自 JSF 1.2 以来，Spring 的`SpringBeanFacesELResolver`对象将 Spring bean 读取为 JSF 托管 bean。JSF 只处理表示层，并且具有名为`FacesServlet`的控制器。我们只需要在应用程序部署描述符或`web.xml`中注册`FacesServlet`（在本节中，我们使用 JavaConfig 进行注册），并将任何请求与所需扩展名（这里是`.xhtml`）映射到`FacesServlet`。

首先，我们应该在项目依赖项中包含 JSF API 及其实现：

```java
<properties>
  <spring-framework-version>4.1.6.RELEASE</spring-framework-version>
  <mojarra-version>2.2.12</mojarra-version>
</properties>
  ...
<dependency>
  <groupId>com.sun.faces</groupId>
  <artifactId>jsf-api</artifactId>
  <version>${mojarra-version}</version>
</dependency>
<dependency>
  <groupId>com.sun.faces</groupId>
  <artifactId>jsf-impl</artifactId>
  <version>${mojarra-version}</version>
</dependency>
...
```

调度程序 Servlet 初始化程序是注册`FacesServlet`的位置。请注意，我们在此处将请求映射到`FacesServlet`。由于我们使用 JavaConfig 来注册设置，因此我们在`AnnotationConfigDispchServletInit`类中注册`FacesServlet`，如下所示：

```java
@Configuration
@Order(2)
public class AnnotationConfigDispchServletInit extends AbstractAnnotationConfigDispatcherServletInitializer {
  @Override
  protected Class<?>[] getRootConfigClasses() {
    return new Class<?>[] { AppConfig.class };
  }
  @Override
  protected Class<?>[] getServletConfigClasses() {
    return null;
  }
  @Override
  protected String[] getServletMappings() {
    return new String[] { "*.xhtml" };
  }
  @Override
  protected Filter[] getServletFilters() {
    return new Filter[] { new CharacterEncodingFilter() };
  }
  @Override
  public void onStartup(ServletContext servletContext) throws ServletException {
    // Use JSF view templates saved as *.xhtml, for use with // Facelets
    servletContext.setInitParameter("javax.faces.DEFAULT_SUFFIX", ".xhtml");
    // Enable special Facelets debug output during development
    servletContext.setInitParameter("javax.faces.PROJECT_STAGE", "Development");
    // Causes Facelets to refresh templates during development
    servletContext.setInitParameter("javax.faces.FACELETS_REFRESH_PERIOD", "1");
    servletContext.setInitParameter("facelets.DEVELOPMENT", "true");
    servletContext.setInitParameter("javax.faces.STATE_SAVING_METHOD", "server");
    servletContext.setInitParameter(
      "javax.faces.PARTIAL_STATE_SAVING_METHOD", "true");
      servletContext.addListener(com.sun.faces.config.ConfigureListener.class);
    ServletRegistration.Dynamic facesServlet = servletContext.addServlet("Faces Servlet", FacesServlet.class);
    facesServlet.setLoadOnStartup(1);
    facesServlet.addMapping("*.xhtml");
    // Let the DispatcherServlet be registered
    super.onStartup(servletContext);
  }
}
```

### 注意

我们必须在其他之前设置`FacesServlet`以在加载时启动（注意`facesServlet.setLoadOnStartup`）。

另一个重要的设置是配置监听器以读取`faces-config` XML 文件。默认情况下，它会在`WEB-INF`文件夹下查找`faces-config.xml`。通过将`org.springframework.web.jsf.el.SpringBeanFacesELResolver`设置为`ELResolver`，我们可以将 Spring POJO 作为 JSF bean 访问。通过注册`DelegatingPhaseListenerMulticaster`，任何实现`PhaseListener`接口的 Spring bean，JSF 的阶段事件将被广播到 Spring bean 中实现的相应方法。

这是`faces-config.xml`文件：

```java
<?xml version="1.0" encoding="UTF-8"?>
<faces-config 

xsi:schemaLocation="http://xmlns.jcp.org/xml/ns/javaee/web-facesconfig_2_2.xsd"
version="2.2">
  <application>
    <el-resolver>org.springframework.web.jsf.el.SpringBeanFacesELResolver</el-resolver>
  </application>
  <lifecycle>
    <phase-listener>org.springframework.web.jsf.DelegatingPhaseListenerMulticaster</phase-listener>
  </lifecycle>
</faces-config>
```

在 JSF 中，我们可以使用会话、请求或应用程序范围来定义 bean，并且 bean 的值在特定范围内保留。将`eager`标志设置为`false`意味着延迟初始化，这会在第一次请求到达时创建 bean，而`true`意味着在启动时创建 bean。`OrderBean`类的代码如下：

```java
@ManagedBean(name = "orderBean", eager = true)
@RequestScoped
@Component
public class OrderBean {
  private String orderName;
  private Integer orderId;

  @Autowired
  public OrderServiceorder Service;
  public String placeAnOrder(){
    orderName=orderService.placeAnOrder(orderId);
    return "confirmation";
  }

  public String getOrderName() {
    return orderName;
  }
  public void setOrderName(String orderName) {
    this.orderName = orderName;
  }
  public Integer getOrderId() {
    return orderId;
  }
  public void setOrderId(Integer orderId) {
    this.orderId = orderId;
  }

}
```

此外，这些 bean 在表示层中可用于与后端交互。在第一个屏幕（`order.xhtml`）上，我们调用 bean 的方法（`placeAnOrder`）：

```java
<html lang="en"

>
  <h:body>
  <h3>input: JSF 2 and Spring Integration</h3>
    <h:form id="orderForm">
      <h:outputLabel value="Enter order id:" />
      <h:inputText value="#{orderBean.orderId}" /> <br/>
      <h:commandButton value="Submit" action="#{orderBean.placeAnOrder}"/>
    </h:form>
  </h:body>
</html>
```

该方法返回一个字符串作为确认，并在`action`属性中指定导航，意味着下一页是`confirmation.xhtml`，如下所示：

```java
<html lang="en"

>
  <h:body>
  <h3>Confirmation of an order</h3>
  Product Name: #{orderBean.orderName}
  </h:body>
</html>
```

# Spring 的 Struts 集成

Spring MVC 依赖于`DispatcherServlet`，它将请求发送到可配置的映射处理程序和视图和主题解析的控制器。在 Struts 中，控制器的名称是`Action`。在 Struts 2 中，为了解决线程安全问题，将为每个请求实例化`Action`实例，而 Spring MVC 只创建一次控制器，每个控制器实例为所有请求提供服务。

要启用 Spring 与 Struts 2 的集成，Struts 提供了`struts2-spring-plugin`。在 Struts 2.1 中，Struts 引入了约定插件（`struts2-convention-plugin`），简化了通过注释创建`Action`类（无需任何配置文件`struts.xml`）。该插件期望一组命名约定，用于`Action`类、包和视图命名，将在本节中解释。

要将 Struts 2 与 Spring 集成，您需要添加这些依赖项：

```java
<dependency>
  <groupId>org.apache.struts</groupId>
  <artifactId>struts2-core</artifactId>
  <version>2.3.20</version>
</dependency>
<dependency>
  <groupId>org.apache.struts</groupId>
  <artifactId>struts2-spring-plugin</artifactId>
  <version>2.3.20</version>
</dependency>
<dependency>
  <groupId>org.apache.struts</groupId>
  <artifactId>struts2-convention-plugin</artifactId>
  <version>2.3.20</version>
</dependency>
```

`struts2-convention-plugin`插件搜索包含字符串“struts”、“struts2”、“action”或“actions”的包，并检测`Action`类，其名称以`Action`(`*Action`)结尾，或者实现`com.opensymphony.xwork2.Action`接口（或扩展其子类`com.opensymphony.xwork2.ActionSupport`）。`ViewOrderAction`类的代码如下：

```java
package com.springessentialsbook.chapter7.struts;
...
@Action("/order")
@ResultPath("/WEB-INF/pages")
@Result(name = "success", location = "orderEntryForm.jsp")
public class ViewOrderAction extends ActionSupport {
  @Override
  public String execute() throws Exception {
    return super.execute();
  }
}
```

`@Action`将`/order`（在请求 URL 中）映射到此操作类，`@ResultPath`指定视图（JSP 文件）的存在位置。`@Result`指定导航到`execute()`方法的字符串值的下一页。我们创建了`ViewOrderAction`，以便能够导航到新页面，并在视图（`orderEntryForm.jsp`）中提交表单时执行操作（业务逻辑）：

```java
package com.springessentialsbook.chapter7.struts;
…...
@Action("/doOrder")
@ResultPath("/WEB-INF/pages")
@Results({
  @Result(name = "success", location = "orderProceed.jsp"),
  @Result(name = "error", location = "failedOrder.jsp")
})
public class DoOrderAction extends ActionSupport {
  @Autowired
  private OrderService orderService;
  private OrderVO order;

  public void setOrder(OrderVO order) {
    this.order = order;
  }

  public OrderVO getOrder() {
    return order;
  }

  @Override
  public String execute( ) throws Exception {
    if ( orderService.isValidOrder(order.getOrderId())) {
      order.setOrderName(orderService.placeAnOrder(order.getOrderId()));
      return SUCCESS;
    }
    return ERROR;
  }
```

此外，这是调用`Action`类的 JSP 代码。请注意表单的`doOrder`操作，它调用`DoOrderAction`类（使用`@Action("doOrder")`）。

```java
<%@ page language="java" contentType="text/html; charset=UTF-8"
pageEncoding="UTF-8"%>
<%@ taglib prefix="s" uri="/struts-tags" %>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" 
"http://www.w3.org/TR/html4/loose.dtd">
<html>
  <head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
  </head>
  <body>
    <div align="center">
      <h1>Spring and Struts Integration</h1>
      <h2>Place an order</h2>
      <s:form action="doOrder" method="post">
        <s:textfield label="OrderId" name="order.orderId" />
        <s:submit value="Order" />
      </s:form>
    </div>
  </body>
</html>
```

正如您所看到的，我们在视图中使用了`OrderVO`，其代码如下，作为数据模型。对 JSP 代码或操作类中此对象的任何更改都将传递到下一页：

```java
public class OrderVO {
  private String orderName;
  private String orderId;

  public String getOrderName() {
    return orderName;
  }
  public void setOrderName(String orderName) {
    this.orderName = orderName;
  }
  public String getOrderId() {
    return orderId;
  }
  public void setOrderId(String orderId) {
    this.orderId = orderId;
  }
```

在`DoOrderAction`操作类中，在方法执行中，我们实现业务逻辑，并返回在表示层中导航逻辑中指定方法的字符串值。在这里，操作类要么转到`orderProceed.jsp`（如果是有效订单），要么转到`failedOrder.jsp`（如果失败）。这是`orderProceed.jsp`页面，将转发成功订单：

```java
<%@ taglib prefix="s" uri="/struts-tags" %>
<html>
  <head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
  </head>
  <body>
    <div align="center">
      <h1>Order confirmation</h1>
      <s:label label="OrderId" name="order.orderId" />, <s:label label="OrderName" name="order.orderName" /> <br/>
      has been successfully placed.
    </div>
  </body>
</html>
```

# 摘要

在本章中，我们解释了如何将 Spring 与两种著名的演示技术集成：JSF 和 Struts。

您可以在此处获取有关 Spring 与 Web 框架集成的更多信息：

[`docs.spring.io/spring/docs/current/spring-framework-reference/html/web-integration.html`](http://docs.spring.io/spring/docs/current/spring-framework-reference/html/web-integration.html)

要了解有关 Spring 的 Struts 插件的更多信息，请访问此链接：

[`struts.apache.org/docs/spring-plugin.html`](http://struts.apache.org/docs/spring-plugin.html)

您可以在此处获取有关 Struts 约定插件中命名约定的更多详细信息：

[`struts.apache.org/docs/convention-plugin.html`](https://struts.apache.org/docs/convention-plugin.html)

如今，大公司正在向单页面应用程序在表示层转变。要了解这个话题，请阅读第六章，“构建单页面 Spring 应用程序”。


# 第二部分：Spring MVC 秘籍

*超过 40 个用于使用 Spring MVC 创建云就绪 Java Web 应用程序的食谱*



# 第八章：企业 Spring 应用程序的设置例程

本章涵盖的主题对应于这个四步例程：

+   为 JEE 开发人员和 Java SE 8 安装 Eclipse

+   为 Java SE 8、Maven 3 和 Tomcat 8 配置 Eclipse

+   使用 Maven 定义项目结构

+   安装 Spring、Spring MVC 和 Web 结构

# 介绍

在我们深入介绍这个初始化开发的例程之前，我们将回答一些问题，这些问题应该帮助您更好地理解这个例程。

请记住，本章的结果也将构成所有后续章节的最小起点。

### 注意

让我们愉快地做吧！

在本书中，我们将代表 ZipCloud 公司行事。ZipCloud 旨在在社交和金融行业构建不同的产品。我们将建立公司的第一个产品：`cloudstreetmarket.com`，这将是一个具有社交功能的精彩股票交易平台。这个项目必须是这个小 ZipCloud 初创公司的一个最佳开端！

## 为什么要有这样一个例程？

无论您最初的目标是什么，都有必要确保设计不会因早期阶段的失败而受到影响。这个例程应该保护您免受这种风险。

例程本身的理念是分享一种引导方法，以启动您现在需要的项目基础，并支持您未来的需求。这个例程也是驱动您的产品思想走向可持续架构的关键，这种架构将易于重构和维护。

为企业级架构设置新项目不会扼杀兴奋和创造力！

## 为什么要使用 Eclipse IDE？

在这个领域存在竞争，但 Eclipse 在 Java 社区中很受欢迎，因为它是一种活跃的开源解决方案；因此，任何人都可以在网上无限制地访问它。它还提供了对 Web 实现的很好支持，特别是对 MVC Web 实现的支持。

## 为什么要使用 Maven？

**Maven**是一个*软件项目管理和理解工具*。它是一个由 Apache 社区和 Apache 软件基金会支持的开源项目。在近 10 年里，Maven 带来了巨大的好处。它还为 Java 项目塑造了一个标准结构。通过其**项目对象模型**（**POM**）方法，它为任何人，潜在地也为任何第三方软件，提供了一种统一和彻底的方式来理解和构建 Java 项目层次结构及其所有依赖关系。

在早期的架构中，考虑以下决定是至关重要的：

+   打开项目定义，可能适用于不同的开发环境和持续集成工具。

+   监控依赖关系，可能确保它们的访问

+   在项目层次结构内强制使用统一的目录结构

+   使用自测组件构建自测软件

选择 Maven 可以确保这些点，并满足我们项目使项目可重用、安全和可测试（自动化）的需求。

## Spring 框架带来了什么？

Spring 框架及其社区已经为 Java 平台做出了超过十年的贡献。详细介绍整个框架需要我们写的不止一本书。然而，基于**控制反转**（**IOC**）和**依赖注入**（**DI**）原则的核心功能，通过对 bean 存储库的高效访问，允许相当大的可重用性。保持轻量级，它确保了很好的扩展能力，可能适用于所有现代架构。

# 为 JEE 开发人员和 Java SE 8 安装 Eclipse

以下食谱是关于下载和安装 Eclipse IDE for JEE 开发人员以及下载和安装 JDK 8 Oracle Hotspot 的。

## 准备工作

这个第一个步骤可能看起来多余或不必要，与您的教育或经验相关。然而，在整本书中拥有统一的配置将为您带来许多好处。

例如，您肯定会避免未知的错误（集成或开发）。您还将体验到与所呈现的屏幕截图中相同的界面。此外，由于第三方产品是活的，您不会遇到意外的屏幕或窗口。

## 如何做…

总的来说，整个第一章需要逐步合作。从下一章开始，我们将使用 GIT，您的积极参与将会减轻。

1.  下载一个 Eclipse IDE for Java EE developers 的发行版：

+   在本书中，我们将使用 Eclipse Luna 发行版。我们建议您安装此版本，以便完全匹配我们的指南和屏幕截图。从[`www.eclipse.org/downloads/packages/eclipse-ide-java-ee-developers/lunasr1`](https://www.eclipse.org/downloads/packages/eclipse-ide-java-ee-developers/lunasr1)下载 Luna 发行版，选择适合您选择的操作系统和环境。

要下载的产品不是已编译的安装程序，而是一个 zip 存档。

+   如果您对使用另一个版本（更近期）的 Eclipse IDE for Java EE Developers 感到足够自信，所有这些版本都可以在[`www.eclipse.org/downloads`](https://www.eclipse.org/downloads)找到。

### 提示

对于即将进行的安装，在 Windows 上，建议将一些目标位置放在根目录（`C:\`）中。为了避免与权限相关的问题，最好将您的 Windows 用户配置为本地管理员。如果您无法成为此组的一部分，请随意选择您有写访问权限的安装目录。

1.  按照以下步骤将下载的存档解压缩到一个`eclipse`目录中：

+   `C:\Users\{system.username}\eclipse`：如果您使用 Windows，请在此处提取

+   `/home/usr/{system.username}/eclipse`：如果您使用 Linux，请在此处提取

+   `/Users/{system.username}/eclipse`：如果您使用 Mac OS X，请在此处提取

1.  选择并下载 JDK 8：

+   我们建议您下载 Oracle Hotspot JDK。Hotspot 是最初由 Sun Microsystems 开发的高性能 JVM 实现。现在由 Oracle 拥有，Hotspot JRE 和 JDK 可免费下载。

+   然后，通过 Oracle 网站的链接[`www.oracle.com/technetwork/java/javase/downloads/jdk8-downloads-2133151.html`](http://www.oracle.com/technetwork/java/javase/downloads/jdk8-downloads-2133151.html)选择与您的机器相对应的产品。

### 注意

为了避免后期的兼容性问题，请保持与您之前为 Eclipse 存档选择的架构选择（32 位或 64 位）一致。

1.  使用以下说明在您选择的操作系统上安装 JDK 8：

在 Windows 上，这是一个由可执行文件启动的受监控的安装：

1.  执行下载的文件，并等待直到您达到下一个安装步骤

1.  在安装步骤窗口上，注意目标目录并将其更改为`C:\java\jdk1.8.X_XX`（`X_XX`指的是最新的当前版本。在本书中，我们将使用 jdk1.8.0_25。此外，不需要安装外部 JRE，因此取消选中公共 JRE 功能。）

在 Linux/Mac 上，执行以下步骤：

1.  下载与您的环境相对应的`tar.gz`存档

1.  将当前目录更改为您想要安装 Java 的位置。为了更容易的指导，让我们同意使用`/usr/java`目录

1.  将下载的`tar.gz`存档移动到当前目录

1.  使用以下命令解压缩存档，目标是您的存档名称：`tar zxvf jdk-8u25-linux-i586.tar.gz`（此示例适用于与 Linux x86 机器相对应的二进制存档）

您必须最终得到包含`/bin`、`/db`、`/jre`、`/include`子目录的`/usr/java/jdk1.8.0_25`目录结构。

## 工作原理…

在本节中，我们将提供有关我们使用的 Eclipse 版本以及我们选择特定版本的 JVM 的更多见解。

### Java EE 开发人员的 Eclipse

我们已经成功地在这里安装了 Eclipse IDE for Java EE developers。与 Eclipse IDE for Java Developers 相比，这个版本还附带了一些额外的包，如*Java EE Developer Tools*、*Data Tools Platform*和*JavaScript Development Tools*。这个版本因其能够作为 IDE 本身的一部分管理开发服务器、自定义项目要素以及支持 JPA 的能力而受到赞赏。Luna 版本官方上兼容 Java SE 8；这在撰写时是一个决定性因素。

### 选择 JVM

JVM 实现的选择可以根据性能、内存管理、垃圾回收和优化能力进行讨论。

有许多不同的 JVM 实现，包括一些开源解决方案，如 OpenJDK 和 IcedTea（RedHat）。选择 JVM 实际上取决于应用程序的要求。我们根据经验和在生产中部署的参考实现选择了*Oracle Hotspot*；这个 JVM 实现可以信任用于各种通用目的。*Hotspot*在运行 Java UI 应用程序时也表现得非常好。Eclipse 就是其中之一。

### Java SE 8

如果您还没有尝试过 Scala 或 Clojure，现在是时候用 Java 搭上函数式编程的列车了！使用 Java SE 8，*Lambda 表达式*大大减少了代码量，提供了更好的*可读性和可维护性*。我们不会实现这个 Java 8 功能，但由于它可能是最受欢迎的，因此必须强调它对范式变化的巨大贡献。如今，熟悉这些模式是很重要的。

# 为 Java 8、Maven 3 和 Tomcat 8 配置 Eclipse

这个教程涉及配置技术，以便在 Eclipse 上有效地开发 Java、Maven 和 Tomcat。

## 准备工作

安装了不同的产品后，我们需要遵循一些步骤，主要是使 Eclipse 与 Java SE 8、Maven 3 和 Tomcat 8 正常工作。在这个教程中，我们还将看看如何自定义 Eclipse 配置文件（`Eclipse.ini`），以充分利用运行 Java 的平台，并确保它能应对应用程序的任何显著增长。

## 如何做…

让我们来看看在桌面上配置 Eclipse 的以下步骤：

1.  您可以通过在桌面上创建一个指向 Eclipse 可执行文件的快捷方式来开始：

+   在 Windows 上，可执行文件是`Eclipse.exe`，位于`eclipse`目录根目录下。

+   在 Linux/Mac 上，文件名为`Eclipse`，也位于`eclipse`目录根目录下

1.  然后，我们需要自定义`eclipse.ini`文件：

在您之前解压缩 Eclipse 存档的 Eclipse 目录中，您可以找到`eclipse.ini`文件。*这是一个文本文件，包含一些命令行选项，以控制 Eclipse 的启动*。

+   Eclipse 社区建议在这里指定我们的 JVM 的路径。因此，根据您的系统，在文件顶部添加以下两行：

对于 Windows，添加以下内容：

```java

-vm 
C:\java\jdk1.8.0_25\jre\bin\server\jvm.dll

```

对于 Linux/Mac，添加以下内容：

```java

-vm 
/usr/java/jdk1.8.0_25/jre/lib/{your.architecture}/server/libjvm.so

```

以下是一个可选的设置，您可以考虑：

+   如果您的开发机器至少有 2GB 的 RAM，您可以输入以下选项，使 Eclipse 比默认设置更快运行。*此部分是可选的，因为 Eclipse 的默认设置已经经过优化，适合大多数用户的环境*：

```java

-vmargs
-Xms128m
-Xmx512m
-Xverify:none
-Dosgi.requiredJavaVersion=1.6
-XX:MaxGCPauseMillis=10
-XX:MaxHeapFreeRatio=70
-XX:+UseConcMarkSweepGC
-XX:+CMSIncrementalMode
-XX:+CMSIncrementalPacing

```

如果您的机器 RAM 少于 2GB，您仍然可以输入这组选项，而不会覆盖默认的`-Xms`和`-Xmx`参数。

### 提示

在`-vmargs`下的所有选项都是在启动时传递给 JVM 的参数。重要的是不要混淆 Eclipse 选项（文件的顶部部分）和 VM 参数（文件的底部部分）。

1.  之后，我们将按照以下步骤启动 Eclipse 并设置工作区：

启动步骤*2*中描述的可执行文件。

+   对于我们的项目，指定路径：`<home-directory>/workspace`

这个路径对于每个操作系统都是不同的：

+   `C:\Users\{system.username}\workspace`：这是 Windows 上的路径

+   `/home/usr/{system.username}/workspace`：这是在 Linux 上

+   `/Users/{system.username}/workspace`：这是在 Mac OS 上

+   单击**确定**，让 Eclipse 程序启动

### 注意

工作区是您管理 Java 项目的地方。它可以特定于一个应用程序，但不一定是。

1.  然后，我们需要检查 JRE 定义：

在 Eclipse 中，需要验证一些设置：

1.  在**窗口**下打开**首选项**菜单（在 Mac OS X 上，**首选项**菜单在**Eclipse**菜单下）。

1.  在左侧的导航面板中，打开 Java 层次结构，然后单击**Java**下的**已安装的 JRE**。

1.  在中央屏幕上，删除您可能已经拥有的任何现有 JRE。

1.  单击**添加...**按钮添加标准 JVM。

1.  输入`C:\java\jdk1.8.0_25`（或`/usr/java/...`）作为**JRE 主目录**。

1.  并输入`jdk1.8.0_25`作为**JRE 名称**。

### 注意

我们告诉 Eclipse 使用 JDK 8 的 Java 运行时环境。

完成这些步骤后，您应该得到以下配置：

![如何操作...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00798.jpeg)

1.  现在，我们将检查编译器兼容性级别：

1.  在导航面板中，单击**Java**下的**编译器**。

1.  检查下拉列表中的**编译器兼容性级别**是否设置为**1.8**。

1.  之后，我们需要检查 Maven 配置：

1.  仍然在**首选项**菜单的导航面板中，打开 Maven 层次结构，然后导航到**Maven** | **安装**。

1.  我们将在这里指定我们计划使用的 Maven 安装。对于本书的目的，嵌入式 Maven 将是完美的。

1.  返回到导航面板，转到**Maven** | **用户设置**。

1.  将本地存储库设置为`<home-directory>/.m2/repository`。

### 注意

在本地存储库中，我们将保存所需工件的本地缓存版本。这将防止我们的环境在每次构建时都需要下载它们。

1.  对于**用户设置**字段，在`.m2`目录中创建一个`settings.xml`文件：`<home-directory>/.m2/settings.xml`。

1.  编辑`settings.xml`文件并添加以下块：

（您还可以从`chapter_1/source_code/.m2`目录中复制/粘贴）：

```java
<settings  
  xsi:schemaLocation="http://maven.apache.org/SETTINGS/1.1.0 http://maven.apache.org/xsd/settings-1.1.0.xsd">
  <profiles>
    <profile>
      <id>compiler</id>
        <properties>
          <JAVA_HOME>C:\java\jdk1.8.0_25</JAVA_HOME>
        </properties>
    </profile>
  </profiles>
  <activeProfiles>
  <activeProfile>compiler</activeProfile>
  </activeProfiles>
</settings>
```

### 提示

如果您不是 Windows 机器，请将此文件中的`JAVA_HOME`更改为您的 JDK 安装目录（`/usr/java/jdk1.8.0_25`）。

1.  返回到导航面板，单击**Maven**。按照此截图中给出的配置进行操作：![如何操作...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00799.jpeg)

1.  单击**确定**以保存这些配置更改。

1.  现在我们将在 Eclipse IDE 中安装 Tomcat 8。为此，请按照以下步骤进行：

1.  从 Tomcat 网站下载最新的 Tomcat8 核心版本的 ZIP 存档：[`tomcat.apache.org/download-80.cgi`](http://tomcat.apache.org/download-80.cgi)。

1.  将下载的存档解压缩到以下目录：

+   在 Windows 上，将存档解压缩到`C:\tomcat8`

+   在 Linux 上，将存档解压缩到`/home/usr/{system.username}/tomcat8`

+   在 Mac OS X 上，将存档解压缩到`/Users/{system.username}/tomcat8`

### 注意

根据您的系统，您必须能够从层次结构中访问 bin 目录：`C:\tomcat8\bin, /home/usr/{system.username}/tomcat8/bin 或 /Users/{system.username}/tomcat8/bin`。

1.  在 Eclipse 中，选择**窗口**下的**首选项**菜单，然后在左侧的导航面板中，打开**服务器**层次结构，然后选择**运行时环境**。

1.  在中央窗口中，单击**添加...**按钮。

1.  在下一步（**新服务器**环境窗口）中，导航到**Apache** | **Apache Tomcat v8.0**。

1.  还要检查此选项：**创建新的本地服务器**。

1.  单击**下一步**按钮。

1.  按照以下截图中显示的窗口中的详细信息填写：

![如何做...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00800.jpeg)

### 注意

如果您使用 Linux（或 Mac OS X），请用您的 Tomcat 安装目录替换`C:\tomcat8`。

## 工作原理...

在本节中，我们将回顾这个食谱带我们经历的不同元素和概念。

### eclipse.ini 文件

正如我们已经看到的，`eclipse.ini`文件控制 Eclipse 的启动。它是使 Eclipse 平台非常可配置的额外组件。您可以在他们的文档中找到可以在命令行中使用的命令行参数列表

[`help.eclipse.org/luna/topic/org.eclipse.platform.doc.isv/reference/misc/runtime-options.html`](http://help.eclipse.org/luna/topic/org.eclipse.platform.doc.isv/reference/misc/runtime-options.html)

重要的是要注意文档中提到的以下警告：

+   在`-vmargs`之后的所有行都作为参数传递给 JVM；所有 Eclipse 的参数和选项都必须在`-vmargs`之前指定（就像在命令行上使用参数时一样）

### 注意

这解释了为什么我们在文件顶部插入了`–vm`选项。

+   在命令行上使用`-vmargs`会替换`.ini`文件中所有`-vmargs`的设置，除非在`.ini`文件中或在命令行上指定了`--launcher.appendVmargs`

### 设置`-vm`选项

设置`-vm`选项可以确保 Eclipse 作为程序运行的 JVM 实现。您可能已经注意到，我们已经将 JVM 作为库(`*.dll / *.so`)。它在启动时具有更好的性能，并且还将程序进程标识为 Eclipse 可执行文件，而不仅仅是 Java 可执行文件。

如果您想知道当未设置`–vm`选项时 Eclipse 使用哪个 JVM，请注意 Eclipse *不会*查看`JAVA_HOME`环境变量。（Eclipse wiki）。

相反，Eclipse 执行解析您的路径环境变量的 Java 命令。

### 自定义 JVM 参数

建议的 JVM 参数列表来自 Piotr Gabryanczyk 关于 Java 内存管理模型的工作。最初，对于 JetBRAINS IntelliJ 设置，这个配置对 Eclipse 环境也很有用。它有助于以下任务：

+   防止垃圾收集器暂停应用程序超过 10 毫秒(`-XX:MaxGCPauseMillis=10`)

+   将垃圾收集器开始的级别降低到占用内存的 30%（`-XX:MaxHeapFreeRatio=70`）

+   强制垃圾收集器作为并行线程运行，降低其对应用程序的干扰（`-XX:+UseConcMarkSweepGC`）

+   选择垃圾收集器的增量调整模式，生成 GC 作业中断，以便应用程序可以停止冻结(`–XX:+CMSIncrementalPacing`)

程序生命周期中实例化的对象存储在堆内存中。建议的参数定义了 JVM 启动堆空间为 128 mb（`-Xms`），总体上限为 512 mb（`–Xmx`）。堆分为两个子空间，如下所示：

+   **年轻代**: 新对象存储在这个区域。对于领先的 Hotspot 或 OpenJDK JVM，年轻内存空间分为两部分：

+   `伊甸园`: 新对象存储在这个分区中。寿命短的对象将从这里被释放。

+   `幸存者`: 这是年轻代和老年代之间的缓冲区。幸存者空间比伊甸园小，也分为两部分（`FROM`和`TO`区域）。您可以使用`-XX:SurvivorRatio`调整`伊甸园`和`幸存者`对象之间的比例（这里，`-XX: SurvivorRatio=10`表示`YOUNG = 12`，`EDEN = 10`，`FROM = 1`和`TO =1`）。

### 提示

年轻区的最小大小可以使用`-XX:NewSize`进行调整。最大大小可以使用`-XX:MaxNewSize`进行调整。

+   老一代：当`Eden`或`Survivor`空间中的对象在足够多的垃圾收集后仍然被引用时，它们会被移动到这里。可以使用`-XX:NewRatio`设置`Young`区域大小作为`Old`区域大小的比例。（也就是说，`-XX:NewRatio=2`表示`HEAP = 3，YOUNG = 1`和`OLD =2`）。

### 提示

新一代空间的最大大小`-XX:MaxNewSize`必须始终小于堆空间的一半（`-Xmx/2`），因为垃圾收集器可能会将所有`Young`空间移动到`Old`空间。

使用 Hotspot 或 OpenJDK，永久代空间用于存储与类的定义相关的信息（结构、字段、方法等）。当加载的结构变得太大时，您可能已经遇到过`PermGen space OutOfMemoryError`异常。在这种情况下，解决方案是增加`-XX:MaxPermSize`参数。*在 JDK8 中不再需要*。

为此，**Permanent Generation**（**PermGen**）空间已被一个不属于堆而属于本机内存的元数据空间所取代。这个空间的默认最大大小是无限的。然而，我们仍然可以使用`-XX:MetaspaceSize`或`-XX:MaxMetaspaceSize`来限制它。

### 更改 JDK 兼容级别

降低兼容级别允许我们运行一个比 JDK 本身识别的更低版本的 Java 编译器。它会影响 Eclipse 的构建、错误和警告，以及 JavaDocs。显然，不能设置比编译器的本机版本更高的编译版本。

### 配置 Maven

在 Eclipse 中，大部分的 Maven 配置来自`m2eclipse`插件（也称为 Eclipse 的 Maven 集成）。这个插件默认包含在 Eclipse Luna 中，因此不需要手动下载。在我们经历的 Maven 配置之后，m2eclipse 也非常有助于从 IDE 上下文触发 Maven 操作，并提供帮助来创建 Java Maven 项目。您将在下一节中了解更多关于 m2eclipse 的内容。

然后我们安装了一个基本的`settings.xml`文件。这个文件用于配置 Maven，而不直接绑定到任何项目。`settings.xml`最常见的用途可能是配置文件和凭据存储以访问存储库管理器。

使用 Maven 配置文件，您可以为特定环境运行构建，并匹配特定配置（变量值、依赖项集等）。Maven 配置文件可以相互叠加。它们可以通过命令行、在 Maven 设置中声明，或者通过环境配置（例如文件在文件系统上存在或缺失、使用的 JDK 等）来激活。

### 提示

在我们的`settings.xml`文件中，我们已经定义了一个具有自己`JAVA_HOME`属性的编译器配置文件。编译器配置文件默认激活，以在`<activeProfiles>`部分中声明定义。Maven 在查找系统变量之前将查阅`settings.xml`文件。

### 存储库管理器

存储库管理器是一个第三方应用程序，管理开发应用程序可能需要的所有必需的二进制文件和依赖项。作为开发环境和公共存储库之间的缓冲代理，存储库管理器提供了对关键参数的控制，如构建时间、依赖项的可用性、可见性和访问限制等。

著名的解决方案包括*Apache Archiva*，*Artifactory*，*Sonatype Nexus*。在我们的应用程序环境中，我们不会使用存储库管理器。

### Eclipse 中的 Tomcat 8

Eclipse for JEE 开发人员允许在开发环境中集成 Tomcat 与其他应用服务器。这是通过提供的**Web 工具平台**（**WTP**）插件实现的，可以管理 Web 工件、它们的编译和部署到 Web 服务器。

在`服务器`选项卡（之前可见），双击创建的 Tomcat v8.0 服务器，打开一个配置窗口，并启用设置通常在`tomcat8\conf`目录中的`server.xml` Tomcat 文件中定义的参数的可能性。

默认情况下，WTP 会抽象出这个配置，不会影响真正的`server.xml`文件。这种行为可以通过在**服务器配置**窗口中激活**将模块上下文发布到单独的 XML 文件**选项来更改。

## 还有更多...

+   在[`wiki.eclipse.org/Eclipse/Installation`](http://wiki.eclipse.org/Eclipse/Installation)了解更多关于 Eclipse 安装的信息

+   在`Eclipse.ini`文件中了解更多信息，请访问[`wiki.eclipse.org/Eclipse.ini`](http://wiki.eclipse.org/Eclipse.ini)

+   了解有关 m2eclipse 插件的更多信息，请访问[`maven.apache.org/plugins/maven-eclipse-plugin/`](https://maven.apache.org/plugins/maven-eclipse-plugin/)

+   要了解如何使用存储库管理器，请参阅[`maven.apache.org/repository-management.html`](http://maven.apache.org/repository-management.html)

+   关于 IDE 的垃圾收集优化的 Piotr Gabryanczyk 文章可以在[`piotrga.wordpress.com/2006/12/12/intellij-and-garbage-collection`](http://piotrga.wordpress.com/2006/12/12/intellij-and-garbage-collection)找到

+   您可以在[`pubs.vmware.com/vfabric52/topic/com.vmware.vfabric.em4j.1.2/em4j/conf-heap-management.html`](http://pubs.vmware.com/vfabric52/topic/com.vmware.vfabric.em4j.1.2/em4j/conf-heap-management.html)和[`blog.codecentric.de/en/2012/08/useful-jvm-flags-part-5-young-generation-garbage-collection`](https://blog.codecentric.de/en/2012/08/useful-jvm-flags-part-5-young-generation-garbage-collection)了解更多关于内存优化的信息

# 使用 Maven 定义项目结构

在这个教程中，我们将专注于使用 Maven 定义我们应用程序所需的项目结构。

## 准备工作

我们将首先创建两个 Eclipse 项目：一个用于应用程序，一个用于 ZipCloud 作为公司以后可能与其他项目共享的组件。看一下下面的图片，它展示了我们将要构建的项目组件：

![准备就绪](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00801.jpeg)

应用程序项目**cloudstreetmarket-parent**将有三个模块。其中两个将被打包为 Web 存档（**war**）：主 Web 应用程序和 REST API。其中一个将被打包为**jar**依赖项（cloudstreetmarket-core）。

公司特定项目**zipcloud-parent**将只有一个子模块—**zipcloud-core**，它将被打包为**jar**。

## 如何做...

以下步骤将帮助我们创建一个 Maven 父项目：

1.  从 Eclipse 导航到**文件** | **新建** | **其他**。

1.  **新建**向导打开，您可以在其中选择层次结构内的项目类型。然后，打开**Maven**类别，选择**Maven 项目**，然后点击**下一步**。

新的 Maven 项目向导打开，如下截图所示：

![如何做...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00802.jpeg)

1.  确保选中**创建一个简单的项目**选项。点击**下一步**。

1.  按照以下向导填写下一个向导：

+   `edu.zipcloud.cloudstreetmarket`作为**Group Id**

+   `cloudstreetmarket-parent`作为**Artifact Id**

+   `0.0.1-SNAPSHOT`作为**版本**

+   `pom`作为**包装**

+   `CloudStreetMarket Parent`作为**名称**

+   然后，点击**完成**按钮

父项目必须出现在仪表板左侧的包资源管理器中。

![如何做...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00803.jpeg)

现在我们必须告诉 m2eclipse 你计划在这个项目中使用哪个 Java 编译器版本，以便它自动向我们即将创建的子模块添加正确的 JRE 系统库。这是通过`pom.xml`文件完成的。

1.  编辑`pom.xml`文件以指定 Java 编译器版本：

+   双击**pom.xml**文件。**m2eclipse** **概述**选项卡默认显示。您必须点击最后一个选项卡**pom.xml**才能访问完整的 XML 定义。

+   在此定义中，在**<project>**节点的末尾添加以下块。(*您也可以从* `chapter_1` *源代码的* `cloudstreetmarket-parent` *的* `pom.xml` *中复制/粘贴这段代码):*

```java
<build>
  <plugins>
    <plugin>
      <groupId>org.apache.maven.plugins</groupId>
      <artifactId>maven-compiler-plugin</artifactId>
      <version>3.1</version>
      <configuration>
          <source>1.8</source>
          <target>1.8</target>
          <verbose>true</verbose>
          <fork>true</fork>
          <executable>${JAVA_HOME}/bin/javac</executable>
          <compilerVersion>1.8</compilerVersion>
      </configuration>
    </plugin>
    <plugin>
      <groupId>org.apache.maven.plugins</groupId>
      <artifactId>maven-surefire-plugin</artifactId>
      <version>2.4.2</version>
      <configuration>
        <jvm>${JAVA_HOME}/bin/java</jvm>
        <forkMode>once</forkMode>
       </configuration>
    </plugin>
  </plugins>
</build>
```

### 注意

您可能已经注意到了**maven-surefire-plugin**的声明。我们很快将对其进行审查；它允许我们在构建过程中运行单元测试。

1.  现在，我们将创建子模块：

作为父项目的子模块，我们已经看到我们需要一个 Web 模块来处理和渲染网站的屏幕，一个用于 REST API 的 Web 模块，以及另一个模块，用于打包所有与第一个产品`cloudstreetmarket.com`相关的业务逻辑（服务，数据访问等）：

1.  从 Eclipse 的主 Webapp 模块中，导航到**文件** | **新建** | **其他**。一个**新建**向导会打开，您可以在其中选择层次结构中的项目类型。打开**Maven**类别，选择**Maven 模块**，然后点击**下一步**。

1.  在此之后，**新建 Maven 模块**向导打开，填写如下：

勾选创建一个简单的项目。

输入`cloudstreetmarket-webapp`作为**Module Name**。

输入`cloudstreetmarket-parent`作为**Parent project**。

![如何做...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00804.jpeg)

1.  点击**下一步**按钮后，下一步将显示。在新窗口中输入以下条目：

输入`edu.zipcloud.cloudstreetmarket`作为**Group Id**。

输入`0.0.1-SNAPSHOT`作为**Version**。

将**war**作为**Packaging**选择。

输入`CloudStreetMarket Webapp`作为**Name**。

然后点击**完成**按钮。

1.  现在我们将继续创建 REST API 模块：

我们将使用不同的参数重复上述操作。

1.  从 Eclipse 中导航到**文件** | **新建** | **其他**。当您这样做时，选择向导会弹出。在此之后，打开**Maven**类别，选择**Maven 模块**，然后点击**下一步**：

1.  在**新建 Maven 模块**向导中，输入以下条目：

勾选**创建一个简单的项目**选项。

输入`cloudstreetmarket-api`作为**Module Name**。

输入`cloudstreetmarket-parent`作为**Parent project**。

1.  点击**下一步**按钮进入下一步。在该窗口中输入以下条目：

输入`edu.zipcloud.cloudstreetmarket`作为**Group Id**。

输入`0.0.1-SNAPSHOT`作为**Version**。

将**war**作为**Packaging**选择。

输入`CloudStreetMarket API`作为**Name**。

然后点击完成按钮。

1.  现在，我们将创建核心模块：

为此，导航到**文件** | **新建** | **其他**。当您这样做时，选择向导会弹出。打开**Maven**类别，选择**Maven 模块**，然后点击**下一步**。

1.  在**新建 Maven 模块**向导中，输入以下条目：

勾选**创建一个简单的项目**选项。

输入`cloudstreetmarket-core`作为**Module Name**。

输入`cloudstreetmarket-parent`作为**Parent project**。

1.  点击**下一步**按钮进入下一步。填写以下字段：

输入`edu.zipcloud.cloudstreetmarket`作为**Group Id**。

输入`0.0.1-SNAPSHOT`作为**Version**。

这次，将**jar**作为**Packaging**选择。

输入`CloudStreetMarket Core`作为**Name**。

然后点击完成按钮。

如果您已激活了 Java 透视图（在右上角），您应该看到整体创建的结构与此处的屏幕截图匹配：

![如何做...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00805.jpeg)

1.  现在，我们将创建一个特定于公司的项目及其模块：

假设以后公司业务项目将包含许多不同类别的依赖项（核心，消息传递，报告等...）。

1.  我们需要一个父项目，因此从 Eclipse 中导航到**文件** | **新建** | **其他**。选择向导弹出。打开 Maven 类别，选择 Maven 项目，然后点击下一步。

1.  在新 Maven 项目向导的第一步中，对于我们之前创建的父项目，只需选中**创建简单项目**和**使用默认工作区位置**选项。

1.  单击**下一步**按钮，并填写下一个向导如下：

输入`edu.zipcloud`作为**Group Id**。

输入`zipcloud-parent`作为**Artifact Id**。

输入`0.0.1-SNAPSHOT`作为**版本**。

选择**pom**作为**打包**。

输入`ZipCloud Factory Business Parent`作为**名称**。

同样，在创建的`pom.xml`文件中，在`<project>`节点内添加以下块，以正确创建基础模块并启用自动测试执行。 (*您还可以从第一章源代码的 zipcloud-parent 的 pom.xml 文件中复制/粘贴此代码段*):

```java
<build>
  <plugins>
    <plugin>
    <groupId>org.apache.maven.plugins</groupId>
      <artifactId>maven-compiler-plugin</artifactId>
      <version>3.1</version>
      <configuration>
        <source>1.8</source>
        <target>1.8</target>
          <verbose>true</verbose>
          <fork>true</fork>
        <executable>${JAVA_HOME}/bin/javac</executable>
      <compilerVersion>1.8</compilerVersion>
      </configuration>
    </plugin>
    <plugin>
    <groupId>org.apache.maven.plugins</groupId>
      <artifactId>maven-surefire-plugin</artifactId>
        <version>2.4.2</version>
        <configuration>
        <jvm>${JAVA_HOME}/bin/java</jvm>
        <forkMode>once</forkMode>
      </configuration>
    </plugin>
  </plugins>
</build>
```

现在，我们将创建一个公司业务核心模块，它将是我们刚刚创建的父项目的子模块。

为此，请导航至**文件** | **新建** | **其他**。 选择向导弹出。 打开**Maven**类别，选择**Maven 模块**，然后单击**下一步**。

1.  在**新 Maven 模块**向导中，输入以下详细信息：

检查**创建简单项目**选项。

输入`zipcloud-core`作为**模块名称**。

输入`zipcloud-parent`作为**父项目**。

1.  单击**下一步**按钮，进入下一步。 在这里，输入以下详细信息：

输入`edu.zipcloud`作为**Group Id**。

输入`0.0.1-SNAPSHOT`作为**版本**。

选择**jar**作为**打包**。

选择`ZipCloud Factory Core Business`作为**名称**。

1.  现在，构建这两个项目：

如果结构正确，以下 Maven 命令可以成功运行：

```java

mvn clean install

```

### 提示

如果在开发机器上安装了 Maven，则可以在终端中启动此命令。

在我们的研究案例中，我们现在将使用 m2eclipse 修改后的**Run As**菜单进行启动：右键单击 zipcloud-parent 项目，然后单击**Run As** | **Maven Clean**。

### 注意

在 Maven 控制台中，您现在应该在底部看到这一行：

[INFO] BUILD SUCCESS

现在，重复安装构建阶段的操作。 您现在应该在控制台中看到以下输出：

```java

[INFO] ZipCloud Parent .......................SUCCESS [  0.313 s]
[INFO] ZipCloud Core .........................SUCCESS [  1.100 s]
[INFO] ----------------------------------------------------------
[INFO] BUILD SUCCESS
[INFO] ----------------------------------------------------------

```

好的，现在您应该能够构建`cloudstreetmarket-parent`。

为此，请右键单击**cloudstreetmarket-parent**项目，然后单击**Run As** | **Maven Clean**。 在此步骤之后，Maven 控制台应打印以下内容：

```java

[INFO] BUILD SUCCESS

```

再次右键单击**cloudstreetmarket-parent**项目，然后单击**Run As** | **Maven Install**。 Maven 控制台现在应该打印以下内容：

```java

[INFO] CloudStreetMarket Parent ..............SUCCESS [  0.313 s]
[INFO] CloudStreetMarket Webapp ..............SUCCESS [  6.129 s]
[INFO] CloudStreetMarket Core ................SUCCESS [  0.922 s]
[INFO] CloudStreetMarket API .................SUCCESS [  7.163 s]
[INFO] ----------------------------------------------------------
[INFO] BUILD SUCCESS
[INFO] ----------------------------------------------------------

```

向上滚动一点应该显示以下跟踪：

```java

-------------------------------------------------------
 T E S T S
-------------------------------------------------------
There are no tests to run.
Results :
Tests run: 0, Failures: 0, Errors: 0, Skipped: 0

```

### 注意

在这里，Maven 借助我们手动添加的 maven-surefire-plugin 解析`src/test/java`目录中遇到的所有类。 再次，此路径可以自定义。

在检测到的测试类中，Maven 还将运行使用 JUnit `@Test`注解标记的方法。 项目中需要 JUnit 依赖项。

## 它是如何工作的...

在本节中，我们将介绍有关 Maven 的许多概念，以便您更好地理解其标准。

### 新的 Maven 项目，新的 Maven 模块

我们刚刚经历的项目创建屏幕也来自 m2eclipse 插件。 这些屏幕用于使用预配置的`pom.xml`文件和标准目录结构初始化 Java 项目。

m2eclipse 插件还提供了一组快捷方式来运行 Maven 构建阶段以及一些方便的选项卡（已经看到）来管理项目依赖关系并可视化`pom.xml`配置。

### 标准项目层次结构

浏览创建的项目，您应该能够注意到以下目录的重复层次结构：`src/main/java`，`src/main/resource`，`src/test/java`和`src/test/resource`。 这种结构是 Maven 引导我们的默认结构。 *这种模型现在已经成为标准*。 但是，我们仍然可以覆盖它（在`pom.xml`文件中）并创建我们自己的层次结构。

如果您还记得在父项目的`pom.xml`文件中添加的**maven-compiler-plugin**定义，我们使用了以下四行代码：

```java
<verbose>true</verbose>
<fork>true</fork>
<executable>${JAVA_HOME}/bin/javac</executable>
<compilerVersion>1.8</compilerVersion>
```

这些行允许 Maven 使用外部 JDK 进行编译。最好能够控制 Maven 使用的编译器，特别是在管理不同环境时。

还有以下两行可能看起来过于配置：

```java
<source>1.8</source>
<target>1.8</target>
```

从严格的 Maven 观点来看，当使用指定的 compilerVersion 定义外部 JDK 时，这些行是可选的。最初，通过这两行，我们可以控制默认代码要在哪个 Java 版本中编译。在维护旧系统时，现有代码可能仍然在以前的 Java 版本中编译。

实际上，m2eclipse 特别希望这两行存在，以便将`JRE System Library [JavaSE-1.8]`添加到`jar`和`war`模块的构建路径中。现在，有了这些行，Eclipse 以与 Maven 相同的方式编译这些项目：在 Java SE 8 中。

### 提示

如果此依赖项仍显示为不同版本的 Java，您可能需要右键单击模块，然后导航到**Maven** | **Update Project**。

### IDE 中的项目结构

关于 Eclipse 项目层次结构中的父项目；您是否注意到创建的子模块似乎重复出现为独立项目和父项目的直接子项目？这是因为 Eclipse 目前在 Luna 中尚未处理项目层次结构。因此，模块显示为分开的项目。这可能会有点令人困惑，因为源代码似乎位于父项目旁边。*实际上并非如此，这只是它们呈现的方式，因此我们可以像通常绑定到项目级别一样拥有所有工具*。

### 注意

此时，JetBRAINS IntelliJ IDEA 已经支持项目的可视化层次结构。

最后，如果您打开父项目的`pom.xml`文件，您应该看到`<modules>`节点中填充了创建的子模块。这也是 m2eclipse 自动完成的。我们建议您密切关注此功能，因为根据您如何更改项目层次结构，m2eclipse 并不总是更新这些`<modules>`节点。

### Maven 的构建生命周期

Maven 中的构建生命周期是一组预定义操作（称为阶段）的特定顺序。Maven 中存在三个生命周期：默认、清理和站点。

让我们看看包括默认和清理生命周期的所有阶段（可能是开发人员最常用的生命周期）。

#### 清理生命周期

Maven 的**clean**阶段起着核心作用。它从 Maven 的角度重置项目构建。通常是删除 Maven 在构建过程中创建的目标目录。以下是**clean**生命周期中包含的一些阶段的详细信息。这些详细信息来自 Maven 文档：

| 阶段 | 描述 |
| --- | --- |
| `pre-clean` | 在实际项目清理之前执行必要的进程 |
| `clean` | 删除上一次构建生成的所有文件 |
| `post-clean` | 这执行需要完成项目清理的进程 |

#### 默认生命周期

在默认生命周期中，您可以找到处理源代码生成、编译、资源处理、测试、集成测试和构件部署的最有趣的构建阶段。以下是默认生命周期中包含的一些阶段的详细信息：

| 阶段 | 描述 |
| --- | --- |
| `validate` | 验证项目是否正确，是否有所有必要的信息可用。 |
| `initialize` | 这初始化构建状态，例如设置属性或创建目录。 |
| `generate-sources` | 生成要包含在编译中的源代码。 |
| `process-sources` | 处理源代码，例如过滤任何值。 |
| `generate-resources` | 这将生成要包含在包中的资源。 |
| `process-resources` | 这将资源复制并处理到目标目录，准备打包。 |
| `compile` | 这将编译项目的源代码。 |
| `process-classes` | 这将处理编译生成的文件，例如对 Java 类进行字节码增强。 |
| `generate-test-sources` | 这将生成任何要包含在编译中的测试源代码。 |
| `process-test-sources` | 这将处理测试源代码，例如过滤任何值。 |
| `generate-test-resources` | 这将创建用于测试的资源。 |
| `process-test-resources` | 这将资源复制并处理到测试目标目录中。 |
| `test-compile` | 这将测试源代码编译到测试目标目录中。 |
| `process-test-classes` | 这个过程处理来自测试编译的生成文件，例如对 Java 类进行字节码增强。适用于 Maven 2.0.5 及以上版本。 |
| `test` | 这将使用适当的单元测试框架运行测试。这些测试不应该需要代码打包或部署。 |
| `prepare-package` | 这将在实际打包之前执行必要的操作以准备包。这通常会导致包的未打包、处理版本。（Maven 2.1 及以上） |
| `package` | 这将编译后的代码打包成可分发的格式，比如 JAR。 |
| `pre-integration-test` | 这将在执行集成测试之前执行所需的操作。这可能涉及设置所需的环境。 |
| `integration-test` | 这将处理并部署包（如果需要）到可以运行集成测试的环境中。 |
| `post-integration-test` | 这在集成测试执行后执行所需的操作。这可能包括清理环境。 |
| `verify` | 这将运行检查以验证包是否有效并符合质量标准。 |
| `install` | 这将包安装到本地存储库中，以便在其他项目中作为依赖项使用。 |
| `deploy` | 这将把最终的包复制到远程存储库，与其他开发人员和项目共享（在集成或发布环境中完成）。 |

#### 插件目标

有了插件的概念，Maven 获得了更广泛的维度。Maven 本身提供了内置插件，但外部插件可以像其他依赖项一样引入（通过 groupIds 和 artefactIds 标识）。

每个构建阶段可以附加到零个、一个或多个插件目标。一个目标代表一个具体的任务，负责以某种方式构建或处理项目。一些阶段通过本机插件默认绑定了目标。

#### 内置生命周期绑定

现在我们已经看到了两个生命周期中每个阶段的目的，我们必须说，默认生命周期取决于我们选择的模块打包类型，只有一些阶段可能会潜在地被激活以执行目标。

让我们看看对于不同的打包类型，我们在默认生命周期中跳过了哪些阶段：

|   | 默认生命周期 |
| --- | --- |
| 打包类型 | jar/war/ejb/ejb3/rar | ear | maven-plugin | pom |
| --- | --- | --- | --- | --- |
| 激活的阶段 |   | generate-resources | generate-resources |   |
| process-resources | process-resources | process-resources |   |
| compile |   | compile |   |
| process-test-resources |   | process-test-resources |   |
| test-compile |   | test-compile |   |
| test |   | test |   |
| package | package | package | package |
| install | install | install | install |
| deploy | deploy | deploy | deploy |

### 提示

在第九章中，*测试和故障排除*，我们将实际将外部插件目标绑定到识别的构建阶段。

总之，在`jar`打包的模块上调用：mvn clean install 将导致执行以下阶段：clean，process-resources，compile，process-test-resources，test-compile，test，package 和 install。

#### 关于 Maven 命令

当告诉 Maven 执行一个或多个针对特定项目的`pom.xml`文件的阶段时，它将为每个模块执行请求的阶段。

然后，对于每个单独请求的阶段，Maven 将执行以下操作：

+   识别阶段所属的生命周期

+   查找当前模块的打包，并识别正确的生命周期绑定

+   执行在已识别的生命周期绑定的层次结构中位于请求阶段之前的所有阶段

### 注意

通过执行所有阶段，我们指的是执行所有检测到的和附加的插件目标（本地插件或非本地插件）。

总之，在`jar`打包的模块上调用`mvn clean install`将执行以下阶段：`clean`，`process-resources`，`compile`，`process-test-resources`，`test-compile`，`test`，`package`和`install`。

## 还有更多...

您可能想知道为什么我们要针对我们的应用程序创建这些项目和模块。

### 我们是如何选择 jar 模块的名称的？

关于 Maven 结构，非部署模块的最佳名称通常强调功能目的、业务创建的特定概念，或者由产品驱动（cloudstreetmarket-chat、cloudstreetmarket-reporting、cloudstreetmarket-user-management 等）。这种策略使得依赖管理更容易，因为我们可以推断一个新模块是否需要另一个模块。在宏观层面考虑控制器、服务和 DAO 层在这个阶段并不是很有意义，这可能会导致设计干扰或循环依赖。这些技术子组件（服务、DAO 等）将作为 Java 包存在或不存在，根据每个功能模块的需要，但不作为 JAR 包依赖。

### 我们是如何选择可部署模块的名称的？

选择可部署模块（`war`）的名称与选择 JAR 打包模块的名称有些不同。可部署的存档必须被视为可扩展和潜在负载平衡。可以合理地假设将针对应用程序检索 HTML 内容的请求可以与将返回 REST 内容的请求区分开来。

基于这一假设，在我们的情况下，我们希望将`war`拆分为两个。这样做可能会引发一个问题，即*web 会话*在两个 web 应用程序之间如何维护。我们将在稍后回答这一点。

### 我们为什么创建核心模块？

首先，我们创建了核心模块，因为可以肯定，在`cloudstreetmarket`应用程序和公司共享项目中，我们将拥有 POJOs、异常、常量、枚举和一些服务，这些服务将被几乎所有模块或应用程序水平使用。如果一个概念是特定于创建的功能模块，它就不应该是核心模块的一部分。

因此，*从大粒度开始*，*稍后再细化*可能更好，而不是考虑可能以不同方式实现甚至根本不实现的模块。在我们的情况下，我们是一家初创公司，可以说我们将要实现的 5 到 10 个功能可能构成这个应用程序的核心业务。

## 另请参阅...

+   我们还建议安装**代码样式格式化程序**。从**保存事件**触发，有了这些格式化程序，我们可以自动地使用统一的预定义重新排列我们的代码。在团队中拥有这样的格式化程序是非常受欢迎的，因为它可以保证在比较两个文件时具有相同的渲染。

# 安装 Spring、Spring MVC 和 Web 结构

在这个配方中，我们将使用继承为我们的`pom.xml`文件添加第三方依赖项。我们将加载`Spring 应用上下文`并创建我们应用的第一个控制器。最后，我们将在 Tomcat 中部署和启动 web 应用。

## 准备工作

现在我们已经准备好 Eclipse 并且正确配置了 Maven，接下来就可以开始了。我们需要在我们的`pom.xml`文件中指定所有必要的 Spring 依赖项，并且需要设置 Spring 以便为每个模块加载和检索其上下文。

我们还需要组织和可选地公开 web 资源，比如 JSP、JavaScript 文件、CSS 文件等。如果你完成了这个配置，我们应该得到一个由 Tomcat 服务器提供的静态欢迎页面，而且没有异常！

## 如何操作...

我们的第一组更改涉及到父项目：

1.  我们将为这些父项目定义依赖项和构建选项。让我们按照以下步骤进行：

1.  打开**chapter_1**源代码目录中的 cloudstreetmarket-parent 的`pom.xml`，然后选择主窗口下的**pom.xml**选项卡。

复制并粘贴`<properties>`、`<dependencyManagement>`和`<build>`块到你的 cloudstreetmarket-parent 的**pom.xml**文件中。

现在，对 zipcloud-parent 重复相同的操作。

1.  打开**chapter_1**源代码中的 zipcloud-parent 的`pom.xml`文件，然后点击**pom.xml**选项卡。

1.  复制并粘贴`<properties>`和`<dependencyManagement>`块到你的 zipcloud-parent 的**pom.xml**中。你应该已经复制了*第三个配方*中的`<build>`部分。

1.  现在，我们将为 web 模块定义依赖项和构建选项：

1.  打开**chapter_1**源代码中的 cloudstreetmarket-api 的`pom.xml`，然后选择**pom.xml**选项卡。

1.  复制并粘贴`<build>`和`<dependencies>`块到你的 cloudstreetmarket-api 的`pom.xml`中。

1.  现在，对 cloustreetmarket-webapp 重复相同的操作。

1.  打开**chapter_1**源代码目录中的 cloudstreetmarket-webapp 的`pom.xml`，然后点击**pom.xml**选项卡。

1.  复制并粘贴`<build>`和`<dependencies>`块到你的 cloudstreetmarket-webapp 的**pom.xml**文件中。

1.  之后，我们为 jar 模块定义依赖项：

1.  打开**chapter_1**源代码中的 cloudstreetmarket-core 的`pom.xml`，然后点击**pom.xml**选项卡。

1.  复制并粘贴整个`<dependencies>`块到你的 cloudstreetmarket-core 的**pom.xml**中。

1.  然后，我们放置 web 资源：

1.  从**chapter_1**源代码中，复制并粘贴整个**src/main/webapp/***目录到你的**cloudstreetmarket-webapp**项目中。你需要最终得到与**chapter_1**源代码相同的**webapp**目录结构：![如何操作...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00806.jpeg)

1.  现在，对**cloudstreetmarket-api**执行相同的操作。从**chapter_1**源代码中复制并粘贴整个**src/main/webapp/***分支到你的**cloudstreetmarket-api**项目中。你需要最终得到与**chapter_1**源代码相同的 webapp 节点和子节点：

![如何操作...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00807.jpeg)

1.  现在，我们为 web 模块定位一个运行时：

1.  在 Eclipse 中，右键单击**cloudmarket-api**项目。

1.  选择**Properties**菜单。

1.  在导航面板上，选择**Targeted Runtimes**。

1.  在中央窗口中，勾选**Server Apache Tomcat v8.0**选项。

1.  点击**OK**，然后在**cloudstreetmarket-webapp**上重复第五个操作。

### 注意

在这之后，**index.jsp**文件中的一些 Eclipse 警告应该已经消失了。

如果你的项目仍然有警告，你的 Eclipse Maven 配置可能与本地仓库不同步。

1.  这一步应该清除现有项目的警告（如果有的话）：

在这种情况下，执行以下步骤：

1.  选择项目层次结构中的所有项目，除了服务器，如下所示：![如何操作...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00808.jpeg)

1.  在选择的某个地方右键单击，然后在**Maven**下单击**更新项目**。此阶段的**警告**窗口应该消失！

1.  让我们部署`wars`并启动 Tomcat：

在 Eclipse 中添加**服务器**视图。为此，请执行以下操作：

1.  导航到**窗口** | **显示视图** | **其他**。

1.  打开**服务器**目录并选择服务器。您应该在仪表板上看到以下选项卡：

![如何做...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00809.jpeg)

1.  要部署 Web 存档，请执行以下操作：

1.  在我们刚刚创建的视图中，右键单击**本地主机上的 Tomcat v8.0 服务器**，然后选择**添加和移除...**。

1.  在下一步，也就是**添加和移除**窗口中，选择两个可用的存档，然后单击**添加**，然后单击**完成**。

1.  要在 Tomcat 中启动应用程序，我们需要完成以下步骤：

1.  在**服务器**视图中，右键单击**本地主机上的 Tomcat v8.0 服务器**，然后单击**启动**。

1.  在**控制台**视图中，最后应该看到以下内容：

```java

INFO: Starting ProtocolHandler ["http-nio-8080"]
Oct 20, 2014 11:43:44 AM org.apache.coyote.AbstractProtocol start
INFO: Starting ProtocolHandler ["ajp-nio-8009"]
Oct 20, 2014 11:43:44 AM org.apache.catalina.startup.Cata.. start
INFO: Server startup in 6898 ms

```

### 注意

如果您浏览这些日志，您不应该有任何异常！

最后，如果您尝试使用浏览器访问`http://localhost:8080/portal/index.html`，您应该收到以下 HTML 内容：

![如何做...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00810.jpeg)

### 注意

对于本章来说，对 HTML 页面的静态访问仍然是一个谦逊的视觉成就。在整本书中，您将发现我们并没有降低 Spring MVC 所处环境和上下文的重要性。

## 它是如何工作的...

通过这个配方，我们一直在处理与 Spring、Spring MVC 和 Web 环境相关的 Web 资源和 Maven 依赖关系。现在，我们将讨论 Maven 依赖关系和插件管理的方式。然后，我们将讨论 Spring Web 应用程序上下文，最后讨论 Web 资源的组织和打包。

### Maven 依赖的继承

关于父项目和子模块之间依赖关系的继承有两种策略。它们都是从父项目实施的。一方面，我们可以选择直接从`<dependencies>`节点中定义这些依赖关系，以这种方式塑造基本继承。另一方面，为了建立受控继承，我们可以将`<dependencies>`节点定义为`<dependencyManagement>`的子节点。让我们看看两者之间的区别。

#### 基本继承

通过基本继承，父`pom.xml`文件中指定的所有依赖关系都会自动继承到具有相同属性（范围、版本、打包类型等）的子模块中，除非您覆盖它们（使用相同的`groupId`/`artifactId`重新定义这些依赖关系）。

一方面，它提供了在我们想要的模块中使用我们想要的依赖关系版本的选项。另一方面，我们可能会得到一个非常复杂的依赖关系架构和子模块中的巨大`pom.xml`文件。此外，管理外部传递依赖关系的版本冲突可能会很痛苦。

### 提示

自 Maven 2.0 以来，传递依赖是一个需要的依赖关系。传递依赖关系已经自动导入。

在这种继承类型中，没有标准的外部依赖关系。

#### 受控继承

使用`<dependencyManagement>`机制，父`pom.xml`中定义的依赖关系不会自动继承到子模块中。但是，依赖属性（范围、版本、打包类型等）是从父依赖关系的定义中提取的，因此，重新定义这些属性是可选的。

这个过程将我们引向一个集中的依赖关系定义，所有子模块使用相同版本的依赖关系，除非特定的依赖关系需要自定义。

### 包括第三方依赖

在复制的依赖项中，你可能已经注意到了一些 Spring 模块，一些测试、Web、日志和实用程序依赖项。

这个想法是从一个基本的 Web 开发工具箱开始，然后使用所有的 Spring 模块进行增强。当我们面对特定情况时，我们将访问实际包含的大多数依赖项。

#### Spring 框架依赖模型

正如从[spring.io](http://spring.io)网站中提取的下图所示，如今，Spring 框架目前由 20 个模块组成，分组在不同的领域中：

![Spring 框架依赖模型](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00811.jpeg)

这些模块已经被包含在父 POM 中作为受控依赖项。这将使我们以后能够快速地挑选所需的依赖项，为我们的`wars`缩小选择范围。

#### Spring MVC 依赖

Spring MVC 模块是在`spring-webmvc` jar 中自包含的。在 Web 应用程序中，Spring MVC 是一个基本元素，它处理传入的客户端请求，并从控制器中平稳地监视业务操作。最终，它提供了一些工具和接口，能够以客户端期望的格式准备响应。

所有这些工作流程都伴随着 spring-webmvc jar 输出 HTML 内容或 Web 服务。

Spring MVC 完全集成在 Spring 框架中，其所有组件都符合 Spring 架构选择的标准。

#### 使用 Maven 属性

在每个父`pom.xml`文件中，我们已经在`<project>`部分定义了一个`<properties>`块。这些属性是绑定到项目的用户定义属性，但我们也可以在**Maven Profile**选项中定义这些属性。与变量一样，属性在 POM 中被引用时，其名称被**${…}**包围。

有一个标准，使用句点作为单词分隔符来定义属性名称。这不仅仅是一个标准，它还是一种统一的表示法，可以访问用户定义的变量和构成 Maven 模型的对象的属性。Maven 模型是 Maven 的公共接口，从项目级别开始。

POM **XML 模式定义**（**xsd**）是从这个 Maven 模型生成的。这可能听起来很抽象，但最终，Maven 模型只是一组带有 getter 和 setter 的 POJOs。请查看下面 URL 中 Maven 模型的 JavaDoc，以识别与 pom.xml 文件特定的概念（构建、依赖、插件等）：

[`maven.apache.org/ref/3.0.3/maven-model/apidocs/index.html`](http://maven.apache.org/ref/3.0.3/maven-model/apidocs/index.html)

总之，我们可以检索在 POM 中定义的节点值，并使用基于点的表达语言导航 Maven 模型层次结构，以定位 getter。

例如，`${project.name}`引用了当前的`project.getName()`，`${project.parent.groupId}`引用了当前的`project.getParent().getGroupId()`，依此类推。

定义与 Maven 模型的现有路径匹配的用户属性是覆盖其值的一种方式。这就是我们为`project.build.sourceEncoding`所做的事情。

Maven 还提供了访问`settings.xml`文件中定义的属性的可能性，比如`${settings.localRepository}`；还可以访问环境变量，比如`${env.JAVA_HOME}`；以及 Java 系统属性，比如`${java.class.path}`、`${java.version}`、`${user.home}`或`${user.name}`。

### Web 资源

如果你还记得，我们从`chapter_1`源代码中复制/粘贴了整个`src/main/webapp`目录。`webapp`目录名称是 Maven 的标准。在 Eclipse 中，`webapp`文件夹不需要被标记为构建路径的源文件夹，因为这会为静态文件创建一个复杂且无用的包层次结构。最好是它显示为一个普通的目录树。

`webapp`目录必须被视为应用程序的文档根，并位于 WAR 的根级别。`webapp`下的公共静态 web 资源，如 HTML 文件、Javascript、CSS 和图像文件，可以放在我们选择的子目录和结构中。然而，正如*Servlet 3.0 规范*中所描述的，`WEB-INF`目录是应用程序层次结构中的一个特殊目录。它的所有内容都无法从应用程序外部访问；它的内容只能从调用`ServletContext`的 servlet 代码中访问`getResource`或`getResourceAsStream`。规范还告诉我们，`WEB-INF`目录的内容由以下内容组成：

+   `/WEB-INF/web.xml`部署描述符。

+   `/WEB-INF/classes/`目录用于存放 servlet 和实用类。该目录中的类必须对应用程序类加载器可用。

+   `/WEB-INF/lib/*.jar`区域用于存放 Java ARchive 文件。这些文件包含了打包在 JAR 文件中的 servlet、bean、静态资源和 JSP，以及对 web 应用程序有用的其他实用类。web 应用程序类加载器必须能够从这些存档文件中加载类。

在`WEB-INF`文件夹内创建一个`jsp`目录是一个良好的做法，这样`jsp`文件就不能直接被定位，而必须通过显式定义的控制器传递。

JSP 应用程序确实存在，并且根据定义，它们不会遵循这种做法。这种类型的应用程序可能适合某些需求，但它们也不特别推广 MVC 模式的使用，也不具有很好的关注点分离。

要在 web 应用程序中使用 JSP，必须在`web.xml`中启用该功能，并定义一个类型为`org.apache.jasper.servlet.JspServlet`的 servlet，将其映射到 JSP 文件的位置。

#### 目标运行时环境

我们在`index.jsp`文件中遇到了警告。我们通过向项目添加目标运行时来解决了这些问题。我们还发现 Tomcat 自带了 Eclipse Compilator for Java 作为一个 JAR 库。为了执行 JSP 编译，`tomcat8\lib`目录必须包括以下 JAR 库：`jsp-api`，`servlet-api`和`el-api`等。在 Eclipse 中为项目指定目标运行时模拟并预测应用程序将从外部 Tomcat 容器（使用这些库设置）运行的情况。这也解释了为什么在父 POM 中使用*provided*范围定义了`jsp-api`和`el-api`依赖项。

#### Spring web 应用程序上下文

在`web.xml`文件中，我们定义了一种特殊类型的 Servlet，即 Spring MVC `DispatcherServlet`，并将其命名为`spring`。这个 servlet 覆盖了最广泛的`/*` URL 模式。我们将在下一章重新讨论`DispatcherServlet`。

`DispatcherServlet`有自己的发现算法，构建`WebApplicationContext`。提供了一个可选的`contextConfigLocation`初始化参数，指向一个`dispatcher-context.xml`文件。这个参数覆盖了`DispatcherServlet`发现逻辑中默认的预期文件名和路径（`/WEB-INF/{servletName}-servlet.xml`）。

将`load-on-startup`属性设置为`1`后，一旦 servlet 容器准备就绪，就会加载一个新的`WebApplicationContext`，并且仅对启动 servlet 进行范围限定。现在，*我们不再等待第一个客户端请求来加载 WebApplicationContext*。

Spring `WebApplicationContext`文件通常定义或覆盖了 Spring MVC 为 web 应用程序提供的配置和 bean。

在`web.xml`文件中，设置了`org.sfw.web.context.ContextLoaderListener`监听器。这个监听器的目的是启动和关闭另一个 Spring `ApplicationContext`，它将是根据容器生命周期的根`ApplicationContext`。

要轻松加载多个 spring 上下文文件，这里的诀窍是使用类路径表示法（相对路径）和资源路径中的星号（`*`）字符：

```java
<context-param>
  <param-name>contextConfigLocation</param-name>
  <param-value>classpath*:/META-INF/spring/*-config.xml</param-value>
</context-param>
```

这样做可以*加载在类路径中遇到的所有符合标准表示法和位置的上下文文件*。这种方法受到赞赏，因为它强加了一致性，但也因为它定位底层 jar 中的上下文文件的方式。

所有匹配的上下文文件的聚合创建了一个具有更广泛范围的`ApplicationContext`根，并且`WebApplicationContext`继承它。我们在根上下文中定义的 bean 对`WebApplicationContext`上下文可见。如果需要，我们可以覆盖它们。但是，`DispatcherServlet`上下文的 bean 对根上下文不可见。

#### 插件

Maven 首先是一个插件执行框架。Maven 运行的每个任务都对应一个插件。插件具有一个或多个与生命周期阶段分别关联的目标。与依赖关系一样，插件也由`groupId`、`artifactId`和版本标识。当 Maven 遇到不在本地存储库中的插件时，会下载它。此外，默认情况下，Maven 的特定版本会针对与生命周期阶段匹配的一些插件。这些插件被冻结在固定版本上，因此具有定义行为—您需要覆盖它们的定义以获得更近期的版本或更改它们的默认行为。

##### Maven 编译器插件

maven-compiler-plugin 是 Maven 核心插件。核心插件之所以被命名为核心插件，是因为它们的目标是在 Maven 核心阶段（清理、编译、测试等）上触发的。非核心插件涉及打包、报告、实用工具等。重新定义 maven-compiler-plugin 以控制要使用的编译器版本或触发一些外部工具的操作（实际上是 m2eclipse 项目管理工具）是一个很好的做法。

顾名思义，maven 编译器插件编译 Java 源代码。为此，它使用`javax.tools.JavaCompiler`类，并有两个目标：`compiler:compile`（作为编译阶段的一部分触发，编译`java/main`源类）和`compiler:testCompile`（作为测试编译阶段的一部分触发，编译`java/test`源类）。

##### Maven surefire 插件

maven-surefire-plugin 也是一个 Maven 核心插件，只有一个目标：`surefire:test`。这是作为默认生命周期（测试阶段）的一部分调用，用于运行应用程序中定义的单元测试。默认情况下，它会在`${basedir}/target/surefire-reports`位置生成报告（*.txt 或*.xml）。

##### Maven 强制执行插件

maven-enforcer-plugin 非常有用，可以定义项目的环境条件为*关键*。它有两个目标：`enforcer:enforce`（默认绑定到验证阶段，在该阶段执行每个模块的每个定义规则一次）和`enforcer:display-info`（它在执行规则时显示检测到的信息）。

最有趣的标准规则可能是`DependencyConvergence`：它为我们分析所有使用的依赖关系（直接和传递）。如果版本发生分歧，它会将其突出显示并停止构建。当我们面对这种冲突时，很容易在以下之间做出决定：

+   从类路径中排除最低版本

+   不升级依赖

我们还简要讨论了与 maven-enforcer-plugin 相关联的`<pluginManagement>`部分。在这种情况下，这是因为 m2eclipse 不支持这个插件。因此，为了避免在 Eclipse 中出现警告，有必要添加这个部分，以便 m2eclipse 跳过强制执行目标。

##### Maven war 插件

使用 maven-war-plugin，我们在我们的 web POMs 中重新定义。我们再次覆盖了这个用于打包 web 模块的插件的默认行为。如果您有非 Maven 标准项目结构，这绝对是必要的。

我们可能希望以与 IDE 中组织方式不同的方式打包我们的 Web 资源。出于某种原因，我们可能需要从 war 包中排除一些资源，或者甚至希望为构建的 war 包命名，以便它可以被与应用程序 URL 中的特定上下文路径匹配的 servlet 容器使用（/api，/app 等）。过滤、移动 Web 资源以及管理生成的 war 是这个插件的目的。

### 提示

默认情况下，Web 资源会被复制到 WAR 根目录。要覆盖默认目标目录，请指定目标路径`*`。

## 还有更多...

这是一个相当广泛的概述，涉及到自然需要更深入了解的概念：

+   关于 Maven 管理其依赖项的方式，我们建议您阅读有关此主题的 Maven 文档：

[`maven.apache.org/guides/introduction/introduction-to-dependency-mechanism.html`](http://maven.apache.org/guides/introduction/introduction-to-dependency-mechanism.html)

+   Sonatype 的电子书很好地介绍了 Maven 属性。您可以在以下网址找到这本电子书：[`books.sonatype.com/mvnref-book/reference/resource-filtering-sect-properties.html#resource-filtering-sect-settings-properties`](https://books.sonatype.com/mvnref-book/reference/resource-filtering-sect-properties.html#resource-filtering-sect-settings-properties)

+   Maven 模型 API 文档也可以在以下网址找到：

[`maven.apache.org/ref/3.0.3/maven-model/apidocs/index.html`](http://maven.apache.org/ref/3.0.3/maven-model/apidocs/index.html)

+   关于我们之前提到的 servlet 3.0 规范，可以在以下网址找到有关`web.xml`文件定义以及 WebArchive 结构的更多信息：[`download.oracle.com/otn-pub/jcp/servlet-3.0-fr-eval-oth-JSpec/servlet-3_0-final-spec.pdf`](http://download.oracle.com/otn-pub/jcp/servlet-3.0-fr-eval-oth-JSpec/servlet-3_0-final-spec.pdf)

+   最后，有关 Maven 插件的更多信息；我们强烈建议您访问 Maven 列表：[`maven.apache.org/plugins`](http://maven.apache.org/plugins)

## 另外

+   Pivotal 的[spring.io](http://spring.io)网站，特别是 Spring Framework 概述页面，也可以更新或介绍一些关键概念。请访问以下网址：[`docs.spring.io/spring-framework/docs/current/spring-framework-reference/html/overview.html`](http://docs.spring.io/spring-framework/docs/current/spring-framework-reference/html/overview.html)

### Maven checkstyle 插件

另一个有趣的插件是 maven-checkstyle-plugin。当团队在壮大时，我们有时需要保证某些开发实践的维护，或者我们可能需要维护特定的与安全相关的编码实践。像 maven-enforcer-plugin 一样，maven-checkstyle-plugin 使我们的构建对这种类型的违规行为进行断言。

在 Maven 文档中再了解有关此插件的更多信息：[`maven.apache.org/plugins/maven-checkstyle-plugin`](http://maven.apache.org/plugins/maven-checkstyle-plugin)。

