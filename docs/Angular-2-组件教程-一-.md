# Angular 2 组件教程（一）

> 原文：[`zh.annas-archive.org/md5/D90F9C2E423CFD3C0CE82E57CF69A28E`](https://zh.annas-archive.org/md5/D90F9C2E423CFD3C0CE82E57CF69A28E)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

Angular 2 是对之前的 Angular 1.x 框架的一大进步，后者成为了历史上最流行的前端 JavaScript 框架。

这是一个完全重写的、基于 Web 标准和现代 API 构建的最新平台。有了 Angular 2，你可以构建面向浏览器、服务器、移动设备和桌面的 JavaScript 应用，这要归功于 Angular 将视图层与平台核心和服务解耦的架构。

本书将专注于 Angular 的 UI 层：组件。我们将探索丰富的 API 和多种可用选项，用于构建和组合强大的用户界面和视图组件。

# 本书涵盖的内容

第一章，“Angular 2 组件架构”，概述了构建前端应用程序的现有流行架构模式，以及依赖于组合自包含自定义组件的新方法。

第二章，“使用 angular-cli 设置 Angular 2 开发环境”，涵盖了使用 angular-cli 设置开发环境。

第三章，“TypeScript 入门”，涵盖了 TypeScript 语言的基础知识以及你需要了解的内容。

第四章，“构建基本组件”，涵盖了构建基本组件的步骤。

第五章，“构建动态组件”，涵盖了将静态组件转换为动态组件的步骤，使用核心指令和数据绑定。

第六章，“组件通信”，涵盖了使组件彼此通信的不同方法。

第七章，“将所有内容放在一起”，涵盖了构建手风琴组件和组件生命周期。

第八章，“集成第三方组件”，涵盖了从流行的 Bootstrap 库集成工具提示小部件。

第九章 *Angular 2 指令*，介绍了在 Angular 2 中使用指令的用法。

# 本书所需内容

您需要知道如何阅读和编写 JavaScript。其他技术，如 C#或 Java，可能有助于您理解语法，但并非强制性。

需要具备一定的 Web 开发经验和相关技术，如 HTML 和 CSS，因此请确保您对此有所了解。

# 本书适合对象

如果您是具有一定 Angular 经验的前端开发人员，希望了解 Angular 2 组件并使用它们来创建强大的用户界面，那么本书适合您。

这本书也适合想要升级他们的知识和技能的 Angular 1.x 开发人员。

# 约定

在本书中，您将找到一些区分不同信息类型的文本样式。以下是一些示例以及它们的含义解释。

文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下：“我们可以通过使用`include`指令来包含其他上下文。”

代码块设置如下：

```ts
class Product {
  private id: number;
  private color: string;

  constructor(id:number, color:string) {
    this.id = id;
    this.color = color;
  }
}
```

任何命令行输入或输出都以以下方式编写：

```ts
**$ npm uninstall -g angular-cli**
**$ npm cache clean**

```

**新术语**和**重要单词**以粗体显示。您在屏幕上看到的单词，例如菜单或对话框中的单词，会以这种方式出现在文本中：“单击**下一步**按钮会将您移至下一个屏幕。”

### 注意

警告或重要说明以这样的方式出现在一个框中。

### 提示

提示和技巧看起来像这样。


# 第一章：Angular 2 组件架构

我们对 Web 应用程序的思考方式已经改变了。本章的目标是概述构建前端应用程序的现有流行架构模式，以及依赖于组合自包含自定义组件的新方法。

了解在 Angular 1 中实现的架构模式将有助于您将现有应用程序迁移到将来的 Angular 2。在本章中，我们将讨论这些主题：

+   模型视图控制器模式概述

+   Angular 1 中的模型、视图和 ViewModel 的实现

+   从 MVVM 迁移到组件

+   Angular 2 组件架构的示例

# 模型-视图-控制器模式

这是一种用于实现用户界面的架构设计模式，多年来一直用于桌面 GUI。

它将应用程序分为三个不同的部分：

+   模型：这负责存储实际数据

+   **视图**：这是将数据呈现给用户的表示层

+   **控制器**：模型和视图之间的粘合剂

以下图表描述了这些部分之间的关系：

![模型-视图-控制器模式](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng2-cpn/img/image00089.jpeg)

这种模式描述了这些部分之间的通信。**视图**反映模型中的数据，但不能直接改变模型中的数据。通常将模型和视图之间的关系描述为只读的（视图只能从模型中读取）。视图使用**控制器**通过调用方法和更改属性。**控制器**更新模型，导致视图更新并呈现新数据。

MVC 最初是为桌面应用程序开发的，但已被广泛采用作为构建单页面 Web 应用程序的架构，并且可以在所有流行的客户端框架中找到，包括 Angular。

# 在 Angular 1 中的 MVC

Angular 1 实现了经典 MVC 的变体，称为**Model View ViewModel**（**MVVM**）。这种模式描述了不同角色和部分之间的通信：

+   **模型**：这保存数据或充当数据访问层

+   **视图**：像 MVC 一样，这是表示层

+   **ViewModel**：这是绑定到视图的视图的抽象

以下图表描述了使用 Angular 1 术语的这些部分之间的关系：

![MVC in Angular 1](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng2-cpn/img/image00090.jpeg)

在 Angular 1 中，**ViewModel**是一个名为'`$scope`'的对象，由 Angular 控制器构造。我们并不总是直接与这个对象交互。它与视图的绑定是双向的（在 Angular 中，我们将视图称为'模板'）。ViewModel 可以读取和修改模型上的数据，并在必要时更新自身。视图将立即反映这些变化。Angular 不包括任何预定义的模型类型。相反，我们将我们的模型编码为纯 JavaScript，并将其注册为 Angular 服务。以下代码片段显示了自定义模型服务`Model.js`的结构：

```ts
class Product {
  constructor(){
    this.color = "red";
  }
}
```

以下代码片段显示了`ViewModel.js`的结构：

```ts
class ProductController {
  constructor(Product) {
    this.product = Product
  }
}
```

以下代码片段显示了`View.html`的结构：

```ts
<p>{{ product.color }}</p>
```

# 从视图转向组件

Angular 应用程序围绕视图的概念构建。在 Angular 中，视图指的是模板（HTML），大多数情况下由一个或多个控制器管理。这个视图也可以包含一些自定义指令，这些指令封装了一些其他的 HTML 和 JavaScript 块。多年来，Angular 开发人员倾向于创建更多的指令，并将它们用作替换原始 HTML 标记的自定义元素的构建块。

从小的自定义元素组合视图的概念变得流行，并且可以在其他流行的现代框架（如 react 和 polymer）中找到。Angular 2 很好地围绕这个概念构建，并将基于这些构建块构建 UI 架构。因此，从现在开始，我们将组件称为构建块，将模板称为布局。

# 定义组件

组件是将 UI 代码组织成自包含、可重用的块的一种清晰方式，其中包含它们自己的视图和逻辑。组件可以组合在一起创建复杂的用户界面。组件可以选择性地从外部接收属性，并可以通过回调或事件进行通信。业务逻辑、结构和样式可以封装在组件代码中。

在 Angular 2 中，组件只是带有视图的指令。实际上，Angular 2 中的组件是一种指令。在 Angular 2 中，我们也可以编写不包含模板（并且不会被称为组件）的指令。

这些指令与您在 Angular 1.x 中熟悉的指令非常相似。主要区别在于，在 Angular 2.0 中，我们考虑两种类型的指令：为元素添加行为的属性指令，以及我们称之为组件的结构指令。

# 将应用程序分解为组件

Angular 2 应用程序是一组组件。我们为每个 UI 元素、视图和路由定义一个组件。我们必须定义一个根组件，我们将用作所有其他组件的容器。换句话说，Angular 2 应用程序是一个组件树。

设计良好、面向组件的 Angular 2 应用程序的关键是成功地将 UI 分解为组件树。例如，让我们谈谈一个简单的移动待办事项列表应用程序，它看起来像这样：

![将应用程序分解为组件](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng2-cpn/img/image00091.jpeg)

构成此 UI 的组件树将如下所示：

![将应用程序分解为组件](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng2-cpn/img/image00092.jpeg)

该应用程序由九个组件组成。在根部是**Application**组件，其中包含所有其他组件。接下来，我们找到**Form**组件，它由**Input**组件和**Button**组件构成。

**TaskList**组件是**TaskRow**组件的容器。每个 TaskRow 包括三个组件——**CheckBox**，**Label**和**Trash**图标。

关于您应该创建多少组件并没有严格的规定，但最佳实践是将 UI 分解为尽可能多的组件。组件的数量将影响应用程序的其他方面，如可重用性、维护和测试。

# 摘要

从组件构建 UI 的想法并不新鲜。在 Angular 1 中，我们有能力开发行为像组件的指令，但这并不是强制性的。在 Angular 2 中，整个应用程序是一个组件树，因此将设计分解成小部分并学习如何构建组件的能力至关重要。


# 第二章：使用 angular-cli 设置 Angular 2 开发环境

Angular 2 利用现代 Web 技术和工具，这意味着开发环境变得更加复杂，需要一些工具和对它们的理解。

幸运的是，我们不需要花时间安装和配置所有必需的依赖项并将所有内容连接在一起。我们可以使用与 Angular 2 并行开发的 angular-cli（命令行工具）。

在本章中，我们将介绍如何使用 angular-cli 设置我们的开发环境：如何安装它以及如何使用它在几分钟内启动我们的 Angular 2 项目。

# Node 和 npm

在我们可以开始使用 angular-cli 之前，我们需要在我们的机器上安装 Node.js。Node 是建立在 Chrome 的 V8 JavaScript 引擎上的 JavaScript 运行时。它使 JavaScript 能够在没有浏览器的情况下运行，这导致了我们今天使用的许多开发工具的开发，如任务运行器、编译器、linter 和模块加载器。现代 Web 前端开发环境依赖于这些工具。

## 安装 Node

Node 是跨平台的，因此可以在任何流行的操作系统上运行。安装`node`的最简单方法是下载适用于您操作系统的官方安装程序。要做到这一点，转到[`nodejs.org/en/`](https://nodejs.org/en/)并找到 Windows、Macintosh 或 Linux 的官方安装程序。目前，Node 发布有两个主要路径——**长期支持**（**LTS**）和稳定版本。对于本书，我们将使用 Node 的 LTS 版本。确保下载 Node 4.24.53 LTS 版本的安装程序。

在成功下载并运行安装程序后，打开您的终端（或 Windows 中的命令行）并键入`node -v`。此命令应打印您刚刚安装的`node`的当前版本；在我们的情况下，应该是`4.24.53`或更高版本。

我们使用`node`作为我们的开发环境工具所依赖的 JavaScript 引擎。由于我们在本书中不会编写任何 Node.js 代码，因此此处提到的版本并没有任何特殊含义，但我们将使用的其他工具会有。

注意！angular-cli 工具将与大于 4.x 的任何 node 版本一起工作，因此您可以使用其他安装版本。

## 介绍 npm

Npm 是 node 的软件包管理器。它与 node 安装程序捆绑在一起。如果您在上一步成功安装了`node`，则应该准备好使用 npm。为了确保它已正确安装，请打开终端（Windows 上的命令行）并键入`npm -v`。此命令应打印出`npm`版本。它应该是 3 或更高版本。

我们使用`npm`来安装我们开发和运行时所需的依赖项。Npm 在`npm`注册表中搜索这些软件包，目前包含超过 19 万个软件包（并且还在增长）。您可以访问[`www.npmjs.com/`](https://www.npmjs.com/)并搜索软件包，或者使用`npm cli`来搜索、安装和管理软件包。Npm 还帮助我们管理项目生命周期，我们将在下面看到。

# 安装 angular-cli

我们将使用`npm`在我们的工作站上安装 angular-cli。要这样做，请按照以下简单步骤操作：

1.  启动`Terminal`（或 Windows 中的命令行）。

1.  键入：`npm install -g angular-cli@latest`并按*Enter*（在 Windows 上，您可能需要以管理员身份运行此命令）。

就是这样！`angular-cli`现在已安装在您的计算机上，并且因为我们在`npm install`命令中使用了`-g`标志，`angular-cli`暴露了一个`ng`别名，可以从任何地方使用。`（-g`代表`global`，这意味着该模块已安装在系统级目录上）。

# 生成一个 Angular 2 项目

我们将使用`angular-cli`的第一个命令是`new`。此命令将为我们的项目创建一个文件夹结构并安装所有必需的依赖项。除了基本的 Angular 2 文件和模块之外，`angular-cli`还将安装用于测试、linting 和文档化我们的代码的模块。本书主要讨论组件，因此我们不会涉及大部分这些内容。您可以在官方 angular-cli 页面上阅读更多关于可用命令的信息：[`cli.angular.io/`](https://cli.angular.io/)。

要生成一个新项目，请按照以下步骤操作：

1.  启动`Terminal`（或 Windows 中的命令行）。

1.  键入`ng new ng_components`并按*Enter*。

`angular-cli`软件将在当前目录下生成一个新项目。

![生成一个 Angular 2 项目](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng2-cpn/img/image00093.jpeg)

请注意，最后一行打印出：`通过 npm 安装工具包`。`angular-cli`工具将在后台使用标准的`npm`命令下载所有所需的模块。

就是这样！你刚刚生成了一个完整的 Angular 2 项目，其中已经配置和连接了一切所需的东西。

要在开发服务器上提供它，请按照以下步骤操作：

1.  使用`cd`命令导航到刚刚创建的目录，输入：`cd ng_components.`

1.  输入`ng serve`并坐下来。

等待`angular-cli`打印以下内容：

![生成 Angular 2 项目](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng2-cpn/img/image00094.jpeg)

### 注意

如果看到与 Brocolli 相关的内容，那是因为之前的`angular-cli`版本没有被正确卸载。在这种情况下，使用以下命令：

```ts
**$ npm uninstall -g angular-cli**
**$ npm cache clean**

```

然后，您可以按照本章中描述的方式重新安装该工具，使用以下命令：

```ts
**$ npm install -g angular-cli@latest**

```

在幕后，`angular-cli`构建项目，启动服务器并提供应用程序。现在我们只需要启动浏览器并将其指向`http://localhost:4200`：

![生成 Angular 2 项目](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng2-cpn/img/image00095.jpeg)

幕后发生了很多事情。angular-cli 工具使用各种其他工具，比如`webpack`来完成其魔术。这些工具超出了本书的范围，但你可以在 GitHub 上的 angular-cli 文档中阅读有关它的所有内容，网址是[`github.com/angular/angular-cli`](https://github.com/angular/angular-cli)。

# 选择一个 IDE

虽然可以使用纯文本编辑器开发 Angular 2 应用程序，但强烈建议使用集成开发环境（IDE）。我个人使用`webstorm`（[`www.jetbrains.com/webstorm/`](https://www.jetbrains.com/webstorm/)），它提供了对 Angular 的完整支持。如果你正在寻找免费的开源替代方案，我们有`VSCode`（[`code.visualstudio.com/`](https://code.visualstudio.com/)），它也自然地支持 Angular 2。它们两者都提供了 Angular 代码检查和高亮显示，以及重构和自动完成功能。WebStorm 与几乎所有 JavaScript 工具完全集成，被许多人认为是最好的 JavaScript IDE。

# 总结

在本章中，我们学习了如何使用 angular-cli 在几分钟内创建、配置和提供新的 Angular 2 项目。这个工具帮助我们作为开发人员专注于我们的应用程序代码，而不是配置。

在下一章中，我们将熟悉 TypeScript 语言，重点关注构建 Angular 2 组件（以及项目的其余部分）的重要特性。


# 第三章：TypeScript 入门

Angular 2 是用 TypeScript 编写的，但这并不意味着我们必须用 TypeScript 编写我们的应用程序。Angular 2 应用程序可以用 ES6（JavaScript 2015）甚至 ES5（JavaScript 1.5）编写。在本书中，我们将主要使用 TypeScript，主要是因为装饰器的实现可以使我们的 Angular 2 代码比 ES6 和 ES5 更清晰。

我假设你已经知道如何编写 JavaScript 2015（ES6）代码。在本章中，我们将只涵盖我们需要了解的 TypeScript 知识；大部分代码与 JavaScript 2015 兼容。如果你完全不熟悉 ES6，强烈建议你赶上新的语法和特性。

我们将涵盖以下主题：

+   TypeScript 语言简介

+   使用模块管理依赖关系

+   类的声明和使用

+   系统、内置和自定义类型

+   如何使用装饰器

# TypeScript 简介

你应该知道的最重要的一点是，TypeScript 并不是一个全新的语言。它是 ES6 的超集。这意味着 ES6 代码可以通过将文件扩展名从`.js`改为`.ts`来*转换*为 TypeScript。

例如，以下代码是有效的 ES6 或 TypeScript：

```ts
class User {
  constructor(id){
    this.id = id;
  }

  getUserInfo(){
    return this.userInfo;
  }
}
```

另一方面，TypeScript 编译器可以将代码目标定为各种 JavaScript 版本，包括 ES6。编译器将剥离所有*额外*的代码，并输出干净可读的 JavaScript 代码，几乎与源代码相同。

这是一个简单的 TypeScript 类：

```ts
class Product {
  private id: number;
  private color: string;

  constructor(id:number, color:string) {
    this.id = id;
    this.color = color;
  }
}
```

目标为 ES6 将输出这段代码：

```ts
class Product {
  constructor(id, color) {
    this.id = id;
    this.color = color;
  }
}
```

当目标为 ES5 时，这是完成的结果：

```ts
var Product = (function () {
  function Product(id, color) {
    this.id = id;
    this.color = color;
  }
  return Product;
})();
```

正如你所看到的，编译结果是干净可读的代码，几乎与源代码相同（在 ES6 的情况下）。

接下来，我们将探索语言特性。请注意，我们将要介绍的大部分特性都是 ES6 的一部分，而不是 TypeScript。我会提到哪些特性属于 TypeScript，哪些不属于。

# 使用模块管理依赖关系

JavaScript 引入的最重要的变化之一是模块。模块是以特殊方式加载的 JavaScript 文件。所有变量和声明都作用域限定在模块内。如果我们想要向外部公开一些代码，就需要显式地导出它。如果你尝试在模块的顶层记录`this`的值，你会得到 undefined。

## 导出和导入语句

`export` 和 `import` 关键字用于定义代码中应该暴露给其他模块的部分，以及我们想要从另一个模块导入的代码。以下模块暴露了一个函数、一个类和一个变量：

```ts
[user.ts]
export function getRandomNumber() {
  return Math.random();
}

export class User {
  constructor(name) {
    this.name = name;
  }
}

export const id = 12345;
```

要使用这个导出的代码，我们需要在另一个模块中导入它。我们可以以各种方式导入这段代码：

```ts
// import only the function from the module
import { getRandomNumber } from './user';

// import both the function and the class from the module
import { getRandomNumber, Person } from './user';

// import the function and bind it to a random variable
import { getRandomNumber as random } from './user';

// import everything from the module and
// bind it to a userModule variable
import * as UserModule from './user';
```

## 默认导出

我们可以从模块中导入我们需要的内容，导入多个代码和导入模块导出的所有内容。还有另一种从模块中导出代码的选项，称为 `default` 导出：

```ts
[user.ts]
export default class User {
  constructor(name) {
    this.name = name;
  }
}
```

当导入使用默认关键字导出的代码时，我们不必使用导出的函数、类或变量的确切名称：

```ts
import UserModule from './user.ts';
```

每个模块只能声明一个 `default` 导出。我们可以在同一个模块中混合使用默认导出和命名导出。请注意，当导入默认导出的代码时，我们不必使用大括号。

# 类

JavaScript 语言的面向对象能力是围绕原型的概念构建的。原型模型定义了对象之间的链接，而不是继承树。原型模型虽然强大，但对于普通的 JavaScript 程序员来说并不友好。TypeScript 让我们能够使用熟悉的语法创建类，它与 JavaScript 1.5 类完全相同（如果我们选择不使用 TypeScript 的独有功能）。要在 TypeScript 中定义一个类，我们使用 `class` 关键字：

```ts
class Product {}
```

在 TypeScript 中，类可能有构造函数和方法，就像 JavaScript 2015 一样。TypeScript 还添加了定义类属性的能力。以下示例展示了我们的 `Product` 类，其中包含构造函数、属性和方法：

```ts
class Product {

  color;
  price;

  constructor(color, price) {
    this.color = color;
    this.price = price;
  }

  getProductDetails() {
    return this.color + this.price;
  }
}
```

在 TypeScript 中，就像 JavaScript 2015 一样，通过 `extends` 关键字实现继承，当需要调用父类时使用 `super` 关键字。以下示例说明了如何使用它：

```ts
class Product {
  color;
  price;

  constructor(color, price) {
    this.color = color;
    this.price = price;
  }

  getProductDetails() {
    return `${this.color}, ${this.price}`;
  }
}

class Ebook extends Product {
  size;

  constructor(color, price, size) {
    super(color, price);
    this.size = size;
  }

  getProductDetails(){
    return `${this.color}, ${this.price}, ${this.size}`;
  }
}
```

重要的是要意识到，类只是原型的一种“糖”，这意味着 JavaScript 处理对象实例化和继承的方式在幕后并没有改变。它只是有一个友好的语法。

在 Angular 2 中，包含所有组件行为的组件被定义为一个类。其余部分只是元数据装饰器，我们将在未来的章节中学习。

# 类型系统

TypeScript 最著名的特性是类型系统，它使我们能够在编译时利用静态类型检查。我们已经在之前的代码示例中看到了类型的使用。重要的是要理解，在 TypeScript 中，类型的使用是可选的，但强烈建议使用。正如我们在本章开头看到的，TypeScript 编译器会将所有类型声明都分解，因此编译结果将是普通的 JavaScript。

## 基本类型

TypeScript 支持您期望的所有基本 JavaScript 类型：布尔值、数字、字符串和数组。以下示例显示了如何在代码中使用它：

```ts
// strings
let name: string = "bob";

// boolean
let isLoggedIn: boolean = true;

// number
let height: number = 24;
let width: number = 12;

// arrays
let colors: string[] = ['red', 'green', 'blue'];
let colors: Array<string> = ['red', 'green', 'blue'];
```

TypeScript 还将额外的三种类型添加到混合中，即`enum`、`any`和`void`。类型`any`顾名思义，用于处理动态数据，我们无法确定期望的数据类型。如果根本不指定类型，TypeScript 默认为`any`类型：

```ts
// value can be any type, init with a number
let value: any = 10;

// different types can assigned
value = false;
value = "this value is a string";
```

`void`类型就像`any`的相反。它表示*没有类型*。大多数情况下，它被用作不返回任何值的函数的返回类型：

```ts
// this function doesn't returns
function setId(id:string): void {
  this.id = id;
}
```

`enum`只是一种为一组数字值提供更友好名称的方式。没有其他。默认编号从`0`开始，可以手动设置为任何其他数字值：

```ts
// default behavior, value of color will be 2;
enum Color {Red, Green, Blue}
let color: Color = Color.Blue;

// manual initialize, value of color will be 6;
enum Color {Red = 2, Green = 4, Blue = 6}
let color: Color = Color.Blue;
```

## 自定义类型

除了内置的基本类型，您可以（而且可能会）为自己编写的代码使用自己的类型。在 TypeScript 中有三种定义类型的方式，即创建类、定义接口和使用声明现有库类型的特殊文件。

在 TypeScript 中，接口可以描述对象的*形状*，通常包括没有实现的类成员和方法。接口仅在设计时存在；例如，在定义提供程序时，您不能将其用作类型。

以下示例说明了如何将自己的类用作类型：

```ts
class Model {}
class Account extends Model {}
class Controller {
  model:Model;
  constructor(model:Model) {
    this.model = Model;
  }
}
new Controller(Account);
```

以下示例说明了如何创建用于定义类型的接口：

```ts
interface Model {
  get(query:string): any[];
}

class Account implements Model {
  get(query:string):any[] {
    return [];
  }
}

class Controller {
 model:Model;
 constructor(model:Model) {
  this.model = Model;
 }
}
```

第三种选择是创建一个带有`.d.ts`扩展名的文件，将现有代码（第三方）映射到类型。创建此文件的过程超出了本书的范围，您可以访问[`www.typescriptlang.org/Handbook#writing-dts-files`](http://www.typescriptlang.org/Handbook#writing-dts-files)了解更多信息。

好消息是，你几乎可以在任何库中找到定义映射（包括 Angular）。访问[`github.com/typings/typings`](https://github.com/typings/typings)，在那里你可以浏览定义映射的存储库，并了解更多关于 typings 的信息，它是一个用于管理这些映射的命令行工具。

## 关于泛型

还有另一个与类型相关的特性，应该提到的是*泛型*。这个特性使我们能够创建一个可以处理多种类型而不是单一类型的组件。

泛型 API 超出了本书的范围，我们不会在代码示例中使用这个特性。你可以通过访问[`www.typescriptlang.org/Handbook#generics`](http://www.typescriptlang.org/Handbook#generics)来了解更多关于泛型的信息。

# 使用装饰器

装饰器是修改类、属性、方法或方法参数的函数。下面的例子说明了如何定义和使用一个简单的装饰器，它给类添加了一个静态参数：

```ts
// decorator function
function AddMetadata (...args) {
  return function (target){
    target.metadata = [...args];
  }
}

// decorator applied
@AddMetadata({ metadata: 'some values'})
class Model {
}
```

三个点的语法（`...`）是*展开运算符*，这是 JavaScript 2015 的一个特性，它可以解构给定数组的项目。

## 装饰器与注解

你可能听说过注解这个术语；它们只是与 Angular 2 相关的元数据。在 Angular 团队决定使用 TypeScript 之前，他们向我们介绍了一种他们称为 AtScript 的新语言。这种语言包括一个叫做注解的特性，看起来与装饰器完全相同。那么有什么区别呢？装饰器是创建这些 Angular 注解的接口。装饰器被执行，在 Angular 2 中，它们负责使用 Reflect Metadata 库设置元数据。此外，装饰器是 ES7 的一个提案——JavaScript 的下一个版本。因此，我们可以专注于装饰器。

# 总结

TypeScript 是 JavaScript 的超集。这意味着你可以在`.ts`文件中编写纯粹的 JavaScript。TypeScript 编译器将去除所有额外的 TypeScript 代码，并生成纯净、可读的代码，几乎与源代码相同。Angular 2 团队使用 TypeScript 开发 Angular 平台（源代码是用 TypeScript 编写的，但也有编译后的 JavaScript 版本）。作为开发者，我们可以选择使用 TypeScript、JavaScript 2015（ES6）或 JavaScript 1.5。

如果您选择使用 TypeScript，强烈建议访问[`www.typescriptlang.org/`](http://www.typescriptlang.org/)，了解更多关于这种语言能力的信息，这超出了本书的范围。


# 第四章：构建基本组件

在其核心，Angular 2 组件是一个负责向视图公开数据并实现用户交互逻辑的类。Angular 2 组件可以与 Angular 1 的控制器、作用域和视图进行比较。

Angular 2 如何知道如何处理我们的类作为组件？我们需要向类附加元数据，告诉 Angular 如何处理它。

元数据一词描述了我们添加到代码中的附加信息。这些信息在运行时由 Angular 2 使用。

在本章中，我们将涵盖以下主题：

+   Angular 2 组件的解剖

+   组件选择器

+   组件模板

+   组件样式

+   视图封装（影子 DOM）

+   数据绑定

+   Angular 2 组件的解剖

在第二章, *使用 angular-cli 设置 Angular 2 开发环境*，设置开发环境时，我们使用`angular-cli`工具从头开始生成了一个 Angular 2 项目，并将其提供给浏览器。如果您还没有这样做，请参考第二章, *使用 angular-cli 设置 Angular 2 开发环境*，并按照步骤进行操作。

完成后，是时候在我们喜爱的 IDE 中打开项目（也在第二章, *使用 angular-cli 设置 Angular 2 开发环境*中描述），检查代码。它应该类似于以下截图：

![构建基本组件](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng2-cpn/img/image00096.jpeg)

当我们使用`angular-cli`生成项目时，会为我们创建一个带有我们应用程序名称的组件（我们提供给`ng new`命令）。我们可以在`src/app`目录下找到它，如下所示：

![构建基本组件](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng2-cpn/img/image00097.jpeg)

找到名为`app.component.ts`的文件，并在编辑视图中打开它（编辑视图可能因 IDE 而异）。

让我们逐行探索组件代码，这是`app.component.ts`的代码

```ts
[app.component.ts]
import { Component } from '@angular/core';

@Component({
  selector: 'app-root',
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.css']
})
export class AppComponent {
  title = 'app works!';
}
```

在第一行，我们从 Angular 核心模块导入`Component`装饰器

+   然后，我们通过在装饰器名称后面分配`@`符号来声明`Component`装饰器。因为装饰器只是一个函数（参考第三章，“TypeScript 入门”中的解释），我们需要像调用任何其他函数一样使用括号来调用它。

+   `Component`装饰器接受一个对象作为参数，该对象定义了组件的元数据。我们稍后会探讨它。

+   在装饰器之后，我们声明组件类，它应该包含我们的组件逻辑，并且当前声明了名为`title`的字符串。

+   类需要被导出，这样它才能在代码的其他地方使用。

正如我们所看到的，Angular 2 组件必须由两个不同的部分构建：一个简单的类和一个装饰器。

在我们深入研究这段代码之前，让我们打开浏览器，探索已经呈现到浏览器的元素。

为此，将浏览器指向`http://localhost:4200/`（我正在使用 Google Chrome），右键单击标题，然后从弹出菜单中选择**检查**：

![构建基本组件](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng2-cpn/img/image00098.jpeg)

这将打开 Chrome DevTool，我们将在其中探索 DOM：

![构建基本组件](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng2-cpn/img/image00099.jpeg)

我们在元数据中定义的`selector`成为了具有相同名称的元素，我们在组件类中定义的`title`作为`<h1>`标签呈现在其中。

`<app-root>`是如何找到 DOM 的？`<h1>`标签是从哪里来的？

# 引导应用程序

在处理组件和 DOM 之间的链接之前，让我们介绍模块的概念以及如何使用它来引导应用程序。

在项目根目录的`src`目录下，找到并打开`main.ts`文件：

![引导应用程序](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng2-cpn/img/image00100.jpeg)

这个文件是我们 Angular 应用程序的起点。它负责实例化应用程序的主模块和其中的根组件。为此，我们从`platform-browser-dynamic`模块中导入`platformBrowserDynamic`方法，该方法是 Angular 的一部分。这个方法返回一个对象来启动应用程序。这个对象的`bootstrapModule`方法负责通过渲染组件树的根组件来启动 Angular。它需要传递主模块作为参数，所以我们导入我们的模块类`AppModule`并将其传递给`bootstrap`：

以下代码来自`main.ts`文件：

```ts
import './polyfills.ts';
import { platformBrowserDynamic } from '@angular/platform-browser-dynamic';
import { enableProdMode } from '@angular/core';
import { environment } from './environments/environment';
import { AppModule } from './app/';

if (environment.production) {
  enableProdMode();
}

platformBrowserDynamic().bootstrapModule(AppModule);
```

其余的代码对使用根模块引导 Angular 没有任何影响。`enableProdMode`方法是 Angular 核心中的一个方法，它在生产模式下运行应用程序。环境只是一个常量，它保存一个布尔值，指示我们是否在生产环境中运行。

模块是将一组组件、指令、服务和管道聚合到一个单一实体中的便捷方式，可以进入其他模块。每个 Angular 应用程序都包含一个根模块，在我们的情况下是`AppModule`。它包含应用程序的根组件。

模块只是一个用`@NgModule`装饰的类，它接受一个对象作为参数，该对象定义了模块的元数据。

请注意，我们使用了动态引导的方法，利用了即时编译器。这会在内存中和浏览器中动态编译组件。另一种称为**预编译**（**AoT**）的替代方法在 Angular 2 中也是可能的。在这种情况下，无需将 Angular 编译器发送到浏览器，性能提升可能是显著的。

在这种情况下，在预编译应用程序之后，您需要在`main.ts`文件中使用`platform-browser-dynamic`模块的`platformBrowserDynamic`方法：

```ts
import './polyfills.ts';
import { platformBrowser } from '@angular/platform-browser';
import { enableProdMode } from '@angular/core';
import { environment } from './environments/environment';
import { AppModuleNgFactory } from './app/app.module.ng.factory';

if (environment.production) {
  enableProdMode();

}

platformBrowser().bootstrapModuleFactory(AppModuleNgFactory);
```

# 组件选择器

正如我们在本章的第一个示例中所看到的，我们在组件装饰器中定义的**选择器**成为一个呈现到 DOM 中的元素。在我们探索选择器选项之前，让我们了解一下 Angular 如何呈现这个组件。

正如我们在第一章中讨论的*Angular 2 组件架构*，Angular 2 应用程序可以被描述为一个组件树。就像任何其他树结构一样，只有一个根节点。目前在我们的项目中，我们只有一个组件，它被用作树节点。

有了这些信息，让我们看看 Angular 如何实例化我们的根组件并将其呈现出来：

在项目根目录的`src/app`目录下，找到并打开`app.module.ts`文件。这个文件包含了应用程序的根模块的定义：

```ts
[app.module.ts]
import { BrowserModule } from '@angular/platform-browser';
import { NgModule } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { HttpModule } from '@angular/http';
import { AppComponent } from './app.component';

@NgModule({
  declarations: [
    AppComponent
  ],

  imports: [
    BrowserModule,
    FormsModule,
    HttpModule
  ],

  providers: [],
  bootstrap: [AppComponent]
})
export class AppModule { }
```

`app.module.ts` 负责实例化组件类。当这发生时，Angular 会在`index.html`文件中搜索我们在组件装饰器中定义的选择器。我们需要放置在`index.html`中的唯一组件是在`app.module.ts`中的根模块的`bootstrap`属性中定义的根组件。

请注意，此组件需要在`declarations`属性中指定，列出模块中所有可用的组件。

打开`index.html`，它位于`main.ts`旁边，检查代码：

```ts
[index.html]
<html>
  <head>
    <!-- other code related to the page head -->
  </head>
  <body>
    <app-root>Loading...</app-root>
  </body>
</html>
```

我们看到的第一件事是，在我们的`html`文件中，我们将选择器用作元素。这是 Angular 的默认行为。

您在`index.html`中找到的其他代码与`angular-cli`使用的构建系统相关，这超出了本书的范围。

你需要知道的是，当这个 HTML 加载到服务器时，Angular 会加载所有必需的依赖项，你需要运行`main.ts`中的代码来启动框架。

## 选择器选项

当我们构建组件时，我们正在创建新的 HTML 元素。这就是为什么默认情况下我们的选择器名称在 HTML 中用作元素的原因。但是，我们还有其他选项可以用于构建组件。让我们来探索一下：

+   按 CSS 类名选择：

```ts
    @Component({
      selector: '.app-root'
    })
    ```

在标记中使用：

```ts
    <div class="app-root">Loading...</div>
    ```

+   按属性名选择：

```ts
    @Component({
      selector: '[app-root]'
    })
    ```

在标记中使用：

```ts
    <div app-root>Loading...</div>
    ```

+   按属性名和值选择：

```ts
    @Component({
      selector: 'div[app=components]'
    })
    ```

在标记中使用：

```ts
    <div app="components">Loading...</div>
    ```

+   仅在元素不匹配选择器时选择：

```ts
    @Component({
      selector: 'div:not(.widget)'
    })
    ```

在标记中使用：

```ts
    <div class="app">Loading...</div>
    ```

+   如果其中一个选择器匹配，则选择：

```ts
    @Component({
      selector: 'app-root, .app, [ng=app]'
    })
    ```

在标记中使用：

```ts
    <app-root>Loading...</app-root>
    <div class="app">Loading...</div>
    <div ng="app">Loading...</div>
    ```

大多数情况下，保留默认值——即组件选择器——正是我们在构建常见组件时想要的。在后面的章节中，我们还将看到其他用法。

现在，我们将保留选择器为默认值。

# 组件模板

模板是 Angular 2 中组件的核心。没有模板，就没有东西可以渲染到 DOM 中。有两种方法可以将模板附加到组件上：

+   提供外部`html`文件的 URL

+   内联定义模板

由`angular-cli`创建的`app-root`包含外部模板。它是用`templateUrl`属性定义的：

```ts
[app.component.ts]
@Component({
  selector: 'app-root',
  templateUrl: './app.component.html'
})
```

我们可以在`app.component.ts`旁边找到模板，它是一个与`app.component.html`同名的 HTML 文件。让我们打开它来检查代码：

```ts
[app.component.html]
<h1>
  {{title}}
</h1>
```

现在我们知道`<h1>`是从哪里来的。你可以猜到，双大括号会从组件类中渲染标题。

如果我们想要内联声明我们的模板，我们应该使用模板属性。幸运的是，在 ES6 中，我们有一种简单创建多行字符串的方法。这个功能称为**模板字符串**，并且用反引号（`` ` ``）字符。 在以下示例中，我们演示了如何声明内联模板：

```ts
[app.component.ts]
@Component({
  selector: 'app-root',
  template: `
    <h1>
      {{title}}
    </h1>
  `
})
```

将模板保持内联是方便的，因为我们可以在同一个文件中看到模板和组件类。

## 在组件模板中嵌入样式

我们可能会想要在组件的模板中使用一些 CSS。与模板一样，我们有两个选择——内联指定我们的 CSS 类或为外部样式表提供 URL。目前，我们的组件使用一个外部 CSS 文件，通过在`styleUrls`数组中声明路径。

如属性名称所示，我们可以提供多个 URL 以从中提取 CSS。这些 CSS 文件上定义的样式现在可以在我们的模板中使用。首先让我们看一下当前的组件声明：

```ts
[app.component.ts]
@Component({
  selector: 'app-root',
  template: `
    <h1>
      {{title}}
    </h1>
  `,
  styleUrls: ['./app.component.css']
})
```

或者，我们可以使用**styles**属性以内联方式定义样式，就像模板一样。**styles**是一个字符串数组，我们可以在其中编写我们的 CSS 规则。下面的示例演示了如何使用内联样式来为`<h1>`标签设定样式：

```ts
[app.component.ts]
@Component({
  selector: 'app-root',
  template: `
    <h1>
      {{title}}
    </h1>
  `,
  styles: [`
    h1 { color: darkblue }
  `]
})
```

让我们在 Chrome DevTool 中探索该元素。右键单击`title`并从弹出菜单中选择检查。Chrome DevTool 将启动：

![在组件模板中嵌入样式](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng2-cpn/img/image00101.jpeg)

通过 DevTool 查看元素，可以暴露一些关于组件样式的事实：

+   我们定义的样式被转换为一个内联样式标签，位于文档的`head`部分的顶部

+   样式定义已更改，现在包括其旁边的一个属性，这使其具体化并几乎不可能被覆盖

Angular 通过生成一个唯一的属性并将其附加到我们定义的原始 CSS 选择器来保护组件的样式不被覆盖。这种行为试图模仿阴影 DOM 的工作方式。因此，在继续之前，我们需要了解什么是阴影 DOM。

# 阴影 DOM

当我们在 Angular 2 中创建一个组件时，会创建一个阴影 DOM，并且我们的模板会被加载到其中（默认情况下）。什么是阴影 DOM？阴影 DOM 指的是 DOM 元素的子树，它作为文档的一部分呈现，但不在主文档 DOM 树中。

让我们看一个众所周知的阴影 DOM 的示例，一个 HTML `select` 它是如何运作的。在您喜欢的文本编辑器中创建一个普通的 HTML 文件，然后在其 body 中创建一个 `select` 元素：

```ts
<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8">
    <title>Document</title>
  </head>
  <body>
    <select>
      <option>ONE</option>
      <option>TWO</option>
      <option>THREE</option>
    </select>
  </body>
</html>
```

接下来，在 Chrome 中打开它，在元素上右键单击，然后从弹出菜单中选择**检查元素**：

![阴影 DOM](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng2-cpn/img/image00102.jpeg)

Chrome DevTool 将弹出，我们可以在**Elements**标签中检查`select`元素：

![阴影 DOM](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng2-cpn/img/image00103.jpeg)

如果您曾经尝试过使用 CSS 定制原生`html select`元素的外观，您就会知道需要进行破解和开发一种解决方案来使其工作。`select`元素有样式结构，甚至有内置的行为，但我们看不到它。它被封装在元素内部。

如果您对封装这个术语不熟悉，这里有一个从维基百科摘取的快速定义：

**封装**是一种面向对象编程的概念，它将数据和操纵数据的函数绑定在一起，并且保护它们免受外部干扰和误用。

那么，`select`元素的外观是从哪里来的？Chrome DevTool 有一个可以与该元素的影子 DOM 相媲美的功能。要启用此功能，请转到 Chrome DevTool 的设置菜单：

![影子 DOM](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng2-cpn/img/image00104.jpeg)

向下滚动并找到**Elements**部分。勾选复选框**显示用户代理影子 DOM**：

![影子 DOM](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng2-cpn/img/image00105.jpeg)

现在，让我们再次检查`select`元素：

![影子 DOM](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng2-cpn/img/image00106.jpeg)

现在我们清楚地看到，`select`元素隐藏了一个秘密的 DOM 树。在`select`元素下面，创建了一个新的根（`#shadow-root`），并且一个内容元素就在其下面渲染。隐藏的内容标签具有一个名为`select`的属性，它定义了一些内部行为。对于 option 标签也是一样的。如果你想探索另一个创建影子 DOM 的流行 HTML 元素，可以使用`<input type='file' />`重复这些步骤。

这种强大的能力来创建一个封装自身样式、行为甚至数据的本地元素，在 Angular 2 中也是可能的。

# 封装模式

默认情况下，正如我们所见，我们的组件不会封装其结构和样式。这意味着来自组件外部的 CSS 类可以覆盖并影响我们定义的嵌入式 CSS 样式，以及组件的 HTML 结构也是可访问的。

Angular 将为我们的`selector`生成一个独特的属性来保护我们的样式，但这可以通过 CSS 的`!important`语句来覆盖。

要更改这一点，我们需要定义一个封装模式。Angular 2 为我们提供了三个选择：

+   **模拟**（默认）：Angular 将向类`selector`添加一个特殊属性，以避免影响组件之外的其他样式。

+   **本地**：这是渲染器应用的本地封装机制。在我们的情况下，它是浏览器。Angular 将为该组件创建一个影子 DOM，这意味着外部 CSS 无法影响我们的组件。

+   **None**：不会应用任何封装。

要定义封装选项，我们需要从 Angular 核心中导入`ViewEncapsulation`并使用其中一个选项来定义组件的封装属性。以下示例演示了如何将组件封装模型设置为`None`：

```ts
[app.component.ts]
@Component({
  selector: 'app-root',
  encapsulation: ViewEncapsulation.None,
  template: `
    <h1>
      {{title}}
    </h1>
  `,
  styles: [`
    h1 { color: darkblue }
  `]
})
```

大多数情况下，保留默认的模拟模式就可以了。在未来的章节中，我们会遇到一些必须将模式设置为`None`的情况。

# 数据绑定

要完全了解由 angular-cli 为我们生成的组件代码，我们需要讨论数据绑定。换句话说，我们能够将在组件类中声明的**title**呈现到组件模板的方法。

首先，让我们看一下整个组件代码：

```ts
[app.component.ts]
import { Component, ViewEncapsulation } from '@angular/core';

@Component({
  selector: 'app-root',
  encapsulation: ViewEncapsulation.None,
  template: `
    <h1>
      {{title}}
    </h1>
  `,
  styles: [`
    h1 { color: darkblue }
  `]
})
export class AppComponent {
  title = 'app works!';
}
```

很容易在模板中发现双大括号。这是 Angular 模板语法的一部分，负责从组件类进行单向数据绑定。在这种情况下，我们将 title 属性（字符串）绑定到`<h1>`标签之间呈现。

在本书的后面，我们将探索更多的绑定选项。

# 总结

在 Angular 2 中，组件是一个带有装饰器的类，该装饰器为其添加重要的元数据。组件装饰器定义了我们如何使用它以及它可以做什么。当调用装饰器时，选择器和模板是最低要求的字段（如果其中一个缺少，Angular 将抛出错误）。

如果我们将视图封装定义为本地，Angular 将为我们的组件创建一个影子 DOM，这样可以保护嵌入样式不受页面上外部 CSS 的影响。

在下一章中，我们将继续开发我们的组件并使其动态化。


# 第五章：构建动态组件

组件本质上是数据驱动的。它们应该能够呈现动态数据，响应用户交互，并对事件做出反应。

在本章中，我们将继续在第四章中停下来，重点放在组件模板语法上，并学习如何绑定数据和事件。

将涵盖的主题如下：

+   数据插值

+   使用核心指令

+   属性绑定

+   事件绑定

+   双向绑定

# 数据插值

在第三章中，*TypeScript 入门*，我们将一个简单的字符串绑定到模板。如果您还没有这样做，请参考第四章，*构建基本组件*。让我们回顾一下我们的 app-component 代码：

```ts
[app.component.ts]
import { Component, ViewEncapsulation } from '@angular/core';

@Component({
  selector: 'app-root',
  encapsulation: ViewEncapsulation.None,
  template: `
    <h1>
      {{title}}
    </h1>
  `,
  styles: [`
    h1 { color: darkblue }
  `]
})
export class AppComponent {
  title = 'app works!';
}
```

现在，我们将专注于模板。从组件装饰器中删除`encapsulation`和`styles`属性，以使其更清晰和专注。在这样做的同时，让我们也给我们的类添加一个类型和一个构造函数：

```ts
[app.component.ts]
import { Component } from '@angular/core';

@Component({
  selector: 'app-root',
  template: `
    <h1>
      {{ title }}
    </h1>
  `
})
export class AppComponent {
  title: string;

  constructor() {
    this.title = 'app works!';
  }
}
```

这是从数据源（在我们的情况下是组件类）到视图（组件模板）的单向绑定。Angular 插值`title`并在双大括号之间输出结果。

双大括号只能插值字符串。如果我们尝试绑定一个对象，它将不起作用。在以下示例中，我创建了一个包含`title`的对象，并在浏览器中检查结果：

```ts
[app.component.ts]
import { Component } from '@angular/core';

@Component({
  selector: 'app-root',
  template: `
    <h1>
      {{ info }}
    </h1>
  `
})
export class AppComponent {
  info: {};

  constructor() {
    this.info = {title: 'app works!'};
  }
}
```

以下是输出：

![数据插值](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng2-cpn/img/image00107.jpeg)

### 注意

如果您在浏览器中看不到结果，请确保运行`ng serve`命令。如果您不确定如何操作，请参考第二章，*使用 angular-cli 设置 Angular 2 开发环境*。

我们可以绑定到对象属性，只需记住一切都将被插值为字符串。以下示例将正确呈现`title`：

```ts
[app.component.ts]
import { Component } from '@angular/core';

@Component({
  selector: 'app-root',
  template: `
    <h1>
      {{ info.title }}
    </h1>
  `
})
export class AppComponent {
  info: {};

  constructor() {
    this.info = {title: 'app works!'}
  }
}
```

我们在大括号之间写的是一个 angular 表达式。这意味着 angular 在将表达式转换为字符串之前对其进行评估。换句话说，我们可以在表达式中放入简单的逻辑，甚至绑定到一个方法。考虑以下示例：

```ts
[app.component.ts]
import { Component } from '@angular/core';

@Component({
  selector: 'app-root',
  template: `
    <h1>{{ info.title }}</h1>
    <h2>{{ info.subtitle || 'alternative text' }}</h2>
    <h3>My name is: {{ getFullName() }}</h3>        
  `
})
export class AppComponent {
  info: {};
  firstName: string;
  lastName: string;

  constructor() {
    this.info = {title: 'app works!'}
    this.firstName = 'Nir';
    this.lastName = 'Kaufman';
  }

  getFullName(){
    return `${this.firstName} ${this.lastName}`;
  }
}
```

在 angular 表达式中，我们不能使用`new`关键字和运算符，如：`++`，`--`和`+=`。

一般来说，表达式不应该太复杂。

组件模板的上下文是组件实例。这意味着你不能访问全局变量，比如`window`，`document`或`console.log`。

# 核心指令

如果你熟悉 Angular 1.x，你已经知道指令是什么。如果不熟悉，这里有一个简单的定义：指令是一个自定义属性，为元素添加功能。在 Angular 中，组件被认为是指令的一种特殊情况，其中包含一个模板。

Angular 2 核心包括几个指令—NgClass、NgFor、NgIf、NgStyle、NgSwitch、NgSwitchWhen 和 NgSwitchDefault。

如果你熟悉 Angular 1，你已经知道这些指令能做什么，尽管语法和底层实现已经改变。

这些指令旨在帮助我们实现常见的模板任务，比如 DOM 操作。

为了能够在组件中使用核心指令，我们需要将`BrowserModule`模块导入到组件所在的模块中。这是在生成应用程序时由 angular-cli 自动完成的，在`app.module.ts`文件中：

```ts
import { BrowserModule } from '@angular/platform-browser';
import { NgModule } from '@angular/core';
import { AppComponent } from './app.component';

@NgModule({
  declarations: [
    AppComponent
  ],

  imports: [
    BrowserModule
  ],

  bootstrap: [AppComponent]
})
export class AppModule { }
```

让我们探索如何在我们的代码中使用它们。

## NgIf

就像 Angular 1 一样，NgIf 指令会根据我们传递的表达式来删除或重新创建 DOM 的一部分。表达式应该评估为`true`或`false`。

这是我们如何使用`ngIf`：

```ts
[app.component.ts]
import { Component } from '@angular/core';

@Component({
  selector: 'app-root',
  template: `
    <h1>{{ info.title }}</h1>
    <h2>{{ info.subtitle || 'alternative text' }}</h2>  
    <h3 *ngIf="showFullName">My name is: {{ getFullName() }}</h3> 
  `
})
export class AppComponent {
  info: {};
  firstName: string;
  lastName: string;
  showFullName: boolean;

  constructor() {
    this.info = {title: 'app works!'};
    this.firstName = 'Nir';
    this.lastName = 'Kaufman';
    this.showFullName = false;
  }

  getFullName(){
    return `${this.firstName} ${this.lastName}`;
  }
}
```

不要担心`ngIf`属性前的星号，我们将在一会儿讨论它。我们分配了一个名为`showFullName`的表达式，它存在于组件类中。因此，在组件类中，我们声明了一个名为`showFullName`的类型为布尔型的类成员，并在构造函数中将其初始化为`false`。

因此，`<h3>`标签不会渲染到 DOM 中，我们也看不到完整的名字。

### 星号—*

指令名称前的星号（`*`）是 Angular 的一种语法糖，它隐藏了我们对`<template>`标签的使用。这个标签被用在*结构指令*中，这是一个描述影响 DOM 结构的指令的术语。

前面的例子可以这样写：

```ts
[app.component.ts]
import { Component } from '@angular/core';

@Component({
  selector: 'app-root',
  template: `
    <h1>{{ info.title }}</h1>
    <h2>{{ info.subtitle || 'alternative text' }}</h2>

     <template [ngIf]="showFullName">
      <h3>My name is: {{ getFullName() }}</h3>        
    </template>      
  `
})
export class AppComponent {
  info: {};
  firstName: string;
  lastName: string;
  showFullName: boolean;

  constructor() {
    this.info = {title: 'app works!'};
    this.firstName = 'Nir';
    this.lastName = 'Kaufman';
    this.showFullName = false;
  }

  getFullName(){
    return `${this.firstName} ${this.lastName}`;
  }
}
```

这就是 Angular 在幕后所做的，但是在使用语法的较短版本时，我们不需要担心。

## NgClass

NgClass 指令，就像在 Angular 1 中一样，有条件地添加和删除 CSS 类。我们传递一个可以以三种不同方式解释的表达式：

+   一个包含我们想要添加的所有 CSS 类的字符串，以空格分隔

+   要添加的 CSS 类的数组

+   将 CSS 类映射到布尔值（`true`或`false`）的对象

让我们演示使用`ngClass`的各种选项，从一个字符串开始：

```ts
[app.component.ts]
import { Component } from '@angular/core';

@Component({
  selector: 'app-root',
  styles: [`
    .italic { font-style: italic}
    .info { color: blue; } 
  `],
  template: `
    <h1>{{ info.title }}</h1>
    <h2 [ngClass]="getClass()">
      {{ info.subtitle || 'alternative text' }}</h2>

    <template [ngIf]="showFullName">
      <h3>My name is: {{ getFullName() }}</h3> 
    </template>  
  `
})
export class AppComponent {
  info: {};
  firstName: string;
  lastName: string;
  showFullName: boolean;

  constructor() {
    this.info = {title: 'app works!'};
    this.firstName = 'Nir';
    this.lastName = 'Kaufman';
    this.showFullName = false;
  }

  getFullName(){
    return `${this.firstName} ${this.lastName}`;
  }

  getClass(){
    return 'info italic';
  }
}
```

我们将`ngClass`应用到`<h2>`标签上，并传递一个我们在组件类中实现的方法。`getClass()`方法返回一个包含我们想要附加到`<h2>`元素的两个 CSS 类名的字符串。不要担心围绕`ngClass`指令的方括号。我们将在下一刻解释这个语法。

我们可以以另外两种方式实现该方法，以达到相同的结果：

+   第一种方法是通过返回一个数组：

```ts
getClass(){
  return ['info', 'italic'];
}
```

返回一个对象：

```ts
getClass(){
  return { italic: true, info: true };
}
```

+   第二种方法是使用方括号`（[ ]）`

### 提示

在 Angular 2 中，我们可以直接将数据绑定到 DOM 或指令属性。`ngClass`选择器被定义为一个属性，所以如果我们想使用它，我们需要使用方括号语法。当我们处理数据绑定时，我们将在本章后面看到更多例子。

## NgStyle

`ngStyle`指令将根据评估对象的表达式改变元素的内联样式。在下面的例子中，我们将使用`ngStyle`动态地为标题分配字体大小：

```ts
[app.component.ts]
import { Component } from '@angular/core';

@Component({
  selector: 'app-root',
  styles: [`
    .italic { font-style: italic}
    .info { color: blue; }        
  `],
  template: `
    <h1 [ngStyle]="{'font-size': titleSize }">{{ info.title }}</h1>
    <h2 [ngClass]="getClass()">
      {{ info.subtitle || 'alternative text' }}</h2>

    <template [ngIf]="showFullName">
      <h3>My name is: {{ getFullName() }}</h3>        
    </template>  
  `
})
export class AppComponent {
  info: {};
  firstName: string;
  lastName: string;
  showFullName: boolean;
  titleSize: string;

  constructor() {
    this.info = {title: 'app works!'};
    this.firstName = 'Nir';
    this.lastName = 'Kaufman';
    this.showFullName = false;
    this.titleSize = '96px';
  }

  getFullName(){
    return `${this.firstName} ${this.lastName}`;
  }

  getClass(){
    return { italic: true, info: true };
  }
}
```

在这个例子中，我们创建了一个类成员，初始化了一个名为`titleSize`的属性，然后使用它来确定`<h1>`标签上的字体大小样式，使用`ngStyle`。

## NgSwitch

NgSwitch 指令根据`switch`表达式的值添加或删除 DOM 子树。为了有效地使用这个指令，我们在`ngSwitch`指令块中使用了`ngSwitchCase`和`ngSwitchDefault`：

```ts
<div [ngSwitch]="cases">
  <div *ngSwitchCase="1">Case 1</div> 
  <div *ngSwitchCase="2">Case 2</div> 
  <div *ngSwitchDefault>Default Case</div> 
</div>
```

有几件事情需要注意——`ngSwitch`指令不是一个结构指令，这意味着它不使用`<template>`标签，也不操作 DOM 树。这是由`ngSwitchCase`和`ngSwitchDefault`指令完成的。因此，当使用`ngSwitch`指令时，我们使用方括号，其余的使用星号。

## NgFor

`ngFor`指令为集合中的每个项目创建一个新元素（实例化一个新模板）。如果你熟悉 Angular 1，`ngFor`指令在概念上类似于`ng-repeat`指令，但底层实现和语法是不同的：

在下面的例子中，我们通过重复字符串数组中的每个元素来创建一个颜色列表：

```ts
@Component({
  selector: 'app-root',
  template: `
    <ul>
      <li *ngFor="let color of colors">{{ color }}</li>
    </ul>   
  `
})
export class AppComponent {
  colors: string[] = ['red', 'green', 'blue'];
}
```

# 属性绑定

使用 Angular 2，我们可以轻松地绑定到每个 DOM 属性。例如，让我们将一个值绑定到按钮的`disabled`属性，并将其初始化为`true`：

```ts
@Component({
  selector: 'app-root',
  template: `
   <button [disabled]="isDisabled">You can't click me!</button>   
  `
})
export class AppComponent {
  private isDisabled: boolean;

  constructor() {
    this.isDisabled = true;
  }
}
```

这对任何属性都是适用的。让我们看另一个例子，这次是使用输入元素：

```ts
@Component({
  selector: 'app-root',
  template: `
    <input [type]="inputType" [placeholder]="placeHolderText">  
  `
})
export class AppComponent {
  private placeHolderText: string;
  private inputType: string;
  private inputClass: string;

  constructor() {
    this.placeHolderText = 'type your password...'
    this.inputType = 'password';
  }
}
```

# 事件绑定

到目前为止，我们学习了两种数据绑定：插值（使用花括号）和属性绑定。它们都被认为是从数据源到视图的单向数据绑定。在现实生活中，我们的组件应该能够响应用户事件。幸运的是，在 Angular 2 中，这就像属性绑定一样简单。

我们可以通过用括号括起来并将其分配给组件类上的方法来响应任何原生 DOM 事件。让我们看看如何响应按钮上的点击事件。我们需要用括号括起按钮的点击事件，并分配一个将被调用的方法：

```ts
@Component({
  selector: 'app-root',
  template: `
    <button (click)="clickHandler()">
      click me!</button> 
  `
})
export class AppComponent {
  clickHandler() {
    console.log('button clicked!');
  }
}
```

让我们使用数据绑定技术创建一个简单的切换组件：

```ts
@Component({
  selector: 'app-root',
  template: `    
    <h2 (click)="toggeld = !toggeld ">Click me to toggle some content1</h2>
    <p *ngIf="toggeld">Toggeld content</p>
  `
})
export class AppComponent {}
```

# 双向绑定

我们学会了如何使用属性和事件进行单向数据绑定。Angular 引入了第三个选项来与输入控件一起使用。这个指令叫做`ngModel`。语法可能有点奇怪，因为这个指令将属性和事件绑定在一起。

使用`ngModel`，我们可以轻松实现双向数据绑定。在下面的例子中，我们将用户名和密码输入绑定到一个用户对象：

```ts
@Component({
  selector: 'app-root',
  template: `          
    <input type="text" [(ngModel)]="user.username">
    <input type="password" [(ngModel)]="user.password">

    <button (click)="sendUser()">Send</button>
  `
})
export class AppComponent {
  private user = {
    username: '',
    password: ''
  }

  sendUser(){
    console.log(this.user);
  }
}
```

# 总结

在本章中，我们通过核心指令和数据绑定将我们的静态组件转换为动态组件。

Angular 2 保持了数据绑定的简单性，就像 Angular 1 一样。直接将数据绑定到原生 DOM 属性和事件是一个强大的功能。Angular 2 的核心指令只包括一些指令，为我们提供了一些额外的功能，否则很难实现。


# 第六章：组件通信

到目前为止，我们已经构建了一个单一的组件，但是 Angular 组件的真正力量在于构建它们之间的交互。在本章中，我们将学习组件如何以不同的方式进行通信：

+   从父组件通过属性向子组件传递数据

+   在子组件上定义自定义事件供父组件监听

+   通过本地变量进行通信

+   使用父组件查询子组件

# 通过属性传递数据

父组件可以通过属性将数据传递给子组件。有两种方式可以为组件定义输入属性：

+   通过在组件装饰器上创建一个输入数组

+   使用`@Input`装饰器装饰一个类属性

使用组件输入数组非常简单明了。只需声明一个输入数组，并用表示您期望的属性名称的字符串填充它：

```ts
[app.component.ts]
import { Component } from '@angular/core';

@Component({
  selector: 'child-component',
  inputs:   ['title'],
  template: `<h2>{{ title }}</h2>`
})

export class ChildComponent {}

@Component({
  selector: 'app-root',
  template: ` 
    <h1>Component Interactions</h1>
    <child-component [title]="title" ></child-component>
  `
})
export class AppComponent {
  private title: string = "Sub title for child";
}
```

在这个例子中，我们创建了一个子组件，它定义了一个名为`title`的单个字符串输入数组，表示父组件可以绑定并通过其传递数据的属性。

不要忘记将`ChildComponent`类添加到`AppModule`的 declarations 属性中。否则，该组件无法在`AppComponent`的模板中使用。每次需要在另一个组件和同一模块中使用组件或指令时，都需要进行此配置：

```ts
[app.module.ts]
import { BrowserModule } from '@angular/platform-browser';
import { NgModule } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { HttpModule } from '@angular/http';
import { AppComponent, ChildComponent } from './app.component';

@NgModule({
  declarations: [
    AppComponent,
    ChildComponent
  ],
  imports: [
    BrowserModule
  ],
  providers: [],
  bootstrap: [AppComponent]
})
export class AppModule { }
```

当我们不需要在`Component`类中访问输入，并且不关心输入的类型时，输入数组的方法是合适的。

或者，我们可以使用`@Input()`装饰器将输入绑定到类属性：

```ts
[app.component.ts]
import { Component, Input } from '@angular/core';

@Component({
  selector: 'child-component',
  template: `<h2>{{ title }}</h2>`
})
export class ChildComponent {
  @Input() private title: string;
}

@Component({
  selector: 'app-root',
  template: ` 
    <h1>Component Interactions</h1>
    <child-component [title]="title"></child-component>
  `
})
export class AppComponent {
  private title: string = 'Sub title for child';
}
```

绑定到类属性（第二个例子）被认为是处理输入时的最佳实践。

输入可以是原始类型或对象。

# 发出自定义事件

当子组件需要与其父组件通信时，它可以触发一个事件。这种技术使子组件与其父组件解耦（解耦：不需要知道其父组件）。

在 Angular 中，如果我们想要触发事件，我们需要使用一个名为`EventEmitter`的类。

您需要实例化`EventEmitter`类，将其分配给一个类属性，并调用`emit`方法。

在下面的例子中，当用户点击标题时，子组件将触发一个名为`TitleClicked`的自定义事件：

```ts
[app.component.ts]
import { Component, Input, EventEmitter, Output } from '@angular/core';

@Component({
  selector: 'child-component',
  template: `<h2 (click)="titleClicked.emit()">{{ title }}</h2>`
})
export class ChildComponent {
  @Input() private title: string;
  @Output() private titleClicked = new EventEmitter<any>();
}

@Component({
  selector: 'app-root',
  template: ` 
    <h1>Component Interactions</h1>
    <child-component [title]="title" 
    (titleClicked)="clickHandler()"></child-component>
  `
})
export class AppComponent {
  private title: string = 'Sub title for child';
  clickHandler() {
    console.log('Clicked!');
  }
}
```

首先，我们从 Angular 核心中导入了`EventEmitter`类和`Output`装饰器。然后，我们创建了一个名为`titleClicked`的类属性，并将其分配给`EventEmitter`类的一个新实例。

然后，我们绑定了`<h2>`元素的原生点击事件，并调用了`titleClicked`对象的`emit()`方法。

父组件现在可以绑定到这个事件。

## 使用本地变量引用

一个组件可以使用本地变量访问另一个组件的属性和方法。在下面的例子中，我们为子组件创建了一个本地变量，该变量在模板内部可访问：

```ts
[app.component.ts]
import { Component } from '@angular/core';

@Component({
  selector: 'child-component',
  template: `
    <h2>Content Header</h2>
    <p *ngIf="flag">Toggleable Content</p>
  `
})
export class ChildComponent {
  private flag: boolean = false;
  toggle() {
    this.flag = !this.flag;
  }
}

@Component({
  selector  : 'app-root',
  template  : ` 
    <h1>Component Interactions</h1>
    <button (click)="child.toggle()">Toggle Child</button>
    <child-component #child></child-component>
  `
})
export class AppComponent {}
```

我们使用`#`符号创建一个本地变量。

子组件中的方法必须是公共的，否则 Angular 会抛出异常。

这种技术在某些情况下非常有用，因为它不需要在组件类内部编写任何代码。另一方面，引用上下文仅在模板内部。

如果您需要在父组件内部访问子组件，您需要使用`@ViewChild`装饰器注入对子组件的引用。

考虑以下例子：

```ts
[app.component.ts]
import { Component, ViewChild } from '@angular/core';

@Component({
  selector: 'child-component',
  template: `
    <h2>Content Header</h2>
    <p *ngIf="flag">Toggleable Content</p>
  `
})
export class ChildComponent {
  private flag: boolean = false;
  toggle(){
    this.flag = !this.flag;
  }
}

@Component({
  selector: 'app-root',
  template: ` 
    <h1>Component Interactions</h1>
    <button (click)="toggle()">Toggle Child</button>
    <child-component></child-component>
  `
})
export class AppComponent {
  @ViewChild(ChildComponent)
  private childComponent: ChildComponent;
  toggle(){
    this.childComponent.toggle();
  }
}
```

父组件正在使用`@ViewChild`装饰器（从 angular 核心导入），传递组件的名称，并将其分配给一个名为`childComponent`的本地类成员。

如果我们有多个子组件的实例，我们可以使用`@ViewChildren`装饰器。

# 使用父组件查询子组件

`@ViewChildren`组件将提供对给定类型的所有子组件的引用，作为`QueryList`，其中包含子实例的数组。

考虑以下例子：

```ts
[app.component.ts]
import { Component, ViewChildren, QueryList } from '@angular/core';

@Component({
  selector: 'child-component',
  template: `
    <h2>Content Header</h2>
    <p *ngIf="flag">Toggleable Content</p>
  `
})
export class ChildComponent {
  private flag: boolean = false;

  toggle(){
    this.flag = !this.flag;
  }
}

@Component({
  selector: 'app-root',
  template: ` 
    <h1>Component Interactions</h1>
    <button (click)="toggle()">Toggle Child</button>
    <child-component></child-component>
    <child-component></child-component>
    <child-component></child-component>
  `
})
export class AppComponent {
  @ViewChildren(ChildComponent)
  private children: QueryList<ChildComponent>;
  toggle(){
    this.children.forEach(child => child.toggle())
  }
}
```

`ViewChildren`和`QueryList`都是从 Angular 核心中导入的。

# 总结

组件可以以多种方式进行交互和通信。每种技术都适用于特定情况。主要区别与通信范围有关：模板上下文或组件类上下文。

这种灵活性使我们能够创建复杂的组件组合，轻松共享数据和交互，其中包括 API。

在下一章中，我们将构建有用的组件，还将学习关于 Angular 2 变化检测和组件生命周期。


# 第七章：将一切放在一起

是时候把我们学到的关于组件的一切付诸实践了。在本章中，我们将构建有用的组件。我们还将学习关于 Angular 2 变化检测和组件生命周期的知识。

以下是我们将要涵盖的主题：

+   重置开发环境

+   构建一个简单的手风琴组件

+   扩展手风琴组件树

+   扩展钩子到组件生命周期事件

# 准备我们的开发环境

现在是时候使用`angular-cli`创建一个新项目了，就像第二章中描述的那样，*使用 angular-cli 设置 Angular 2 开发环境*。我们将创建一个名为`components`的新目录，用于包含本章中将要实现的所有组件。

在实现相应组件时，我们将在本章中创建另外两个子目录，`accordion`和`user-info`：

![准备我们的开发环境](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng2-cpn/img/image00108.jpeg)

在开始构建新组件之前的最后一件事是清理我们的根组件。打开`index.ts`并进行如下清理：

```ts
[app.component.ts]
import { Component } from '@angular/core';

@Component({
  selector: 'app-root',
  template: '<h1>Angular2 Components</h1>'
}) 
export class AppComponent {}
```

打开浏览器，确保组件已经渲染而没有任何错误：

![准备我们的开发环境](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng2-cpn/img/image00109.jpeg)

现在我们准备开始开发我们的新组件了。

# 手风琴组件

我们将要构建的第一个组件将是一个`accordion`组件。手风琴由两个组件组成：手风琴包装器和手风琴标签。让我们先开始实现`accordion`标签。

在 components 目录中，创建一个名为`accordion`的新目录。在其中，创建`accordion-tab.ts`文件，并粘贴以下代码：

```ts
[accordion-tab.ts]
import { Component } from '@angular/core';

@Component({
  selector: 'accordion-tab',
  styles: [`
    .accordion-tab {
      width: 500px;
      border: 1px solid black;
      border-collapse: collapse;
    }
    .accordion-heading {
      padding: 5px;
      background-color: lightblue;
      cursor: pointer;
    }
 `],
  template: `
    <div class="accordion-tab">
      <div class="accordion-heading">Accordion Title</div>
      <div>
        <ng-content></ng-content>
      </div>
    </div>
  `
})
export class AccordionTab {}
```

组件装饰器很简单。我们添加了一些 CSS 和一个包含`<ng-content>`标签的模板，用于手风琴标签内容的插入点。

为了测试它，让我们渲染`accordion-tab`文件。打开`app.component.ts`并更新代码：

```ts
[app.component.ts]
import { Component } from '@angular/core';
import { AccordionTab } from './components/accordion/accordion-tab';

@Component({
  selector: 'app-root',
  template:`
    <div>
      <accordion-tab>Accordion Content</accordion-tab>
      <accordion-tab></accordion-tab>
      <accordion-tab></accordion-tab>
    </div>
  `
})
export class AppComponent {}
```

不要忘记将`AccordionTab`类添加到根模块的 declarations 属性中。这个操作对于本章中实现的所有自定义组件都是必需的。打开`app.module.ts`文件并进行如下更新：

```ts
[app.module.ts]
import { BrowserModule } from '@angular/platform-browser';
import { NgModule } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { HttpModule } from '@angular/http';
import { AppComponent } from './app.component';
import { AccordionTab } from './components/accordion/accordion-tab';

@NgModule({
  declarations: [
    AppComponent,
    AccordionTab
  ],
  imports: [
    BrowserModule,
    FormsModule,
    HttpModule
  ],
  providers: [],
  bootstrap: [AppComponent]
})
export class AppModule { }
```

现在，让我们打开浏览器，确保组件按预期渲染：

![手风琴组件](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng2-cpn/img/image00110.jpeg)

接下来，让我们实现`accordion-tab`的切换动作。打开`accordion-tab.ts`并更新模板和`Component`类：

```ts
[accordion-tab.ts]
import { Component } from '@angular/core';

@Component({
  selector: 'accordion-tab',
  styles: [`
    .accordion-tab {
      width: 500px;
      border: 1px solid black;
      border-collapse: collapse;
    }
    .accordion-heading {
      padding: 5px;
      background-color: lightblue;
      cursor: pointer;
    }
  `],
  template: `
    <div class="accordion-tab">
      <div class="accordion-heading"
       (click)="toggleContent()">Accordion Title</div>
      <div class="accordion-body">
        <ng-content *ngIf="extended"></ng-content>
      </div>
    </div>
  `
})
export class AccordionTab {
  extended: boolean = false;
  toggleContent() {
    this.extended = !this.extended
  }
}
```

我们将一个方法绑定到标题的点击事件，这个方法切换一个布尔值，触发`ngIf`指令。我们在前两章中已经讨论过这个。为了测试我们的组件，让我们在其他标签中放一些虚拟内容。打开`app.component.ts`并按照以下方式更新模板：

```ts
[app.component.ts]
import { Component } from '@angular/core';
import { AccordionTab } from './accordion/accordion-tab.ts';

@Component({
  selector: 'app-root',
  template:`
    <div>
      <accordion-tab>Accordion Content</accordion-tab>
      <accordion-tab>Accordion Content</accordion-tab>
      <accordion-tab>Accordion Content</accordion-tab>
    </div>
  `
}) 
export class AppComponent {}
```

现在，我们可以打开浏览器测试我们的组件。当我们点击标签标题时，相应的内容会切换。但是标签应该一起工作。只有一个标签可以展开。为了实现这一点，我们可以用一个实现这个逻辑的组件包装`accordion-tab`组件。

在我们这样做之前，我们需要确保从服务器获取的`users`数组中的每个对象（在我们的情况下是`users.json`）都有一个唯一的`id`。打开`users.json`并确保它类似于以下内容：

```ts
[users.json]
[
  {
    "id": 1,
    "name": "Jhon Darn",
    "email": "jhon@email.com",
    "birthday": "5/6/1979",
    "gender": "male",
    "status": "active",
    "role": "employee",
    "phoneNumbers": [
      "+972-123-9873",
      "+972-352-8922",
      "+972-667-2973"
    ]
  },
  (...)
```

现在，在`accordion`文件夹内创建一个名为`accordion.ts`的新文件，让我们先制定基本实现：

```ts
[accordion.ts]
import { Component } from '@angular/core';
import { Http } from '@angular/http';
import 'rxjs/add/operator/map';
import { AccordionTab } from './accordion-tab';

@Component({
  selector: 'accordion',
  template: `
    <div>
      <accordion-tab *ngFor="let user of users"
                   (click)="toggle(user)"
                   [extended]="isActive(user)"
                   [title]="user.name">
                 <pre>{{ user | json }}</pre>
      </accordion-tab>
    </div>
  `
})
export class Accordion {  users;
  activeUserId = 0;

  constructor(http: Http) {
    http.get('/app/server/users.json')
        .map(result => result.json())
        .subscribe(result => this.users = result);
  }

  isActive(user) {
    return user.id === this.activeUserId;
  }

  toggle(user) {
    this.isActive(user) ?
        this.activeUserId = 0 : this.activeUserId = user.id;
  }
}
```

我们使用 HTTP 服务从静态 JSON 中获取用户数据，并遍历`users`数组——重复手风琴标签组件。在每个`accordion-tab`组件上，我们绑定一个方法到点击事件，并将动态数据绑定到属性上。我们还使用`json`管道在手风琴标签内填充一些内容。

选择活动标签的逻辑在`Component`类中非常容易实现。

接下来，我们需要重构`accordion-tab`并定义它的输入和输出接口：

```ts
[accordion-tab.ts]
import {
    Component, Input, Output
} from '@angular/core';

@Component({
  selector: 'accordion-tab',
  styles: [`
    .accordion-tab {
      width: 500px;
      border: 1px solid black;
      border-collapse: collapse;
    }
    .accordion-heading {
      padding: 5px;
      background-color: lightblue;
      cursor: pointer;
    }
  `],
  template:`
    <div class="accordion-tab">
      <div class="accordion-heading"
       (click)="toggleContent()">{{title}}</div>
      <div class="accordion-body">
        <content *ngIf="extended"></content>
      </div>
    </div>
  `
})
export class AccordionTab {
  @Input() extended;
  @Input() title;

  toggleContent() {
    this.extended = !this.extended
  }
}
```

简单的手风琴现在已经准备好了。我们几乎使用了我们学到的所有知识来制作这个小部件。请注意，我们不需要写很多代码。Angular 的内置指令和绑定系统为我们做了大部分的工作。要在浏览器中测试它，打开`app.component.ts`并渲染`<accordion>`组件：

```ts
[app.component.ts]
import { Component } from '@angular/core';
import { Accordion } from './components/accordion/accordion';

@Component({
  selector: 'app-root',
  template: `<accordion></accordion>`
}) 
export class AppComponent {}
```

打开浏览器并检查结果。每次点击手风琴标签时，只有一个标签会展开：

![手风琴组件](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng2-cpn/img/image00111.jpeg)

在我们继续之前，让手风琴只在点击它的`标题`和整个`标签`时展开。为此，我们将在点击标题时发出自定义事件，然后从父组件（即手风琴）绑定到这个事件：

```ts
[accordion-tab.ts]
import {
    Component, Input, Output, EventEmitter
} from '@angular/core';

@Component({
  selector: 'accordion-tab',
  styles: [`
    .accordion-tab {
      width: 500px;
      border: 1px solid black;
      border-collapse: collapse;
    }
    .accordion-heading {
      padding: 5px;
      background-color: lightblue;
      cursor: pointer;
    }
 `],
  template: `
    <div class="accordion-tab">
     <div class="accordion-heading" 
          (click)="toggleContent()">{{title}}</div>
     <div>
      <ng-content *ngIf="extended"></ng-content>
     </div>
    </div>
  `
}) 
export class AccordionTab {
  @Input() extended : boolean;
  @Input() title : string;
  @Output() toggle = new EventEmitter<any>();
  toggleContent() {
    this.toggle.emit(null)
  }
}
```

这就是`accordion-tab`组件。让我们转到`accordion`组件并绑定到这个事件：

```ts
[accordion.ts]
import { Component, Inject } from '@angular/core';
import { Http } from '@angular/http';
import 'rxjs/add/operator/map';
import { AccordionTab } from './accordion-tab';
@Component({
  selector: 'accordion',
  template: `
    <div>
      <accordion-tab *ngFor="let user of users"
                    (toggle)="toggle(user)"
                    [extended]="isActive(user)"
                    [title]="user.name">
        <pre>{{ user | json }}</pre>
      </accordion-tab>
    </div>
  `
})
export class Accordion {  
  users;
  activeUserId = 0;

  constructor(http: Http) {
    http.get('/app/server/users.json')
        .map(result => result.json())
        .subscribe(result => this.users = result);
  }
  isActive(user) {
    return user.id === this.activeUserId;
  }
  toggle(user) {
    this.isActive(user) ?
        this.activeUserId = 0 : this.activeUserId = user.id;
  }
}
```

现在我们可以渲染手风琴组件并查看结果。在`app.component.ts`中包括以下内容：

```ts
[app.component.ts]
import { Component } from '@angular/core';
import { Accordion } from './components/accordion/accordion';

@Component({
  selector: 'app-root',
  template:`<accordion></accordion>`
}) 
export class AppComponent {}
```

打开浏览器并检查结果。手风琴按预期工作。

## 扩展手风琴组件树

让我们向手风琴树中添加另一个组件。不要将原始 JSON 呈现为选项卡内容，而是重用我们在第四章和第五章中构建的用户信息组件。为此，只需在`components`目录中创建一个`user-info`子目录，并将相应的 TypeScript 文件复制到该目录中。我们需要重构的唯一文件是`accordion.ts`：

```ts
[accordion.ts] 
import { Component, Inject, ViewEncapsulation } from '@angular/core';
import { Http } from '@angular/http';
import 'rxjs/add/operator/map';
import { AccordionTab } from './accordion-tab';
import { UserInformation } from '../user-info/user-info';

@Component({
  selector: 'accordion',
  template: `
    <div>
      <accordion-tab *ngFor="let user of users"
                    (toggle)="toggle(user)"
                    [extended]="isActive(user)"
                    [title]="user.name">
        <user-info [user]="user"></user-info>
      </accordion-tab>
    </div>
  `
})
export class Accordion {  
  users;
  activeUserId = 0;
  constructor(http: Http) {
    http.get('app/server/users.json')
        .map(result => result.json())
        .subscribe(result => this.users = result);
  }
  isActive(user) {
    return user.id === this.activeUserId;
  }
  toggle(user) {
    this.isActive(user) ?
        this.activeUserId = 0 : this.activeUserId = user.id;
  }
}
```

我们所需要做的就是导入用户信息组件，在组件元数据中声明它，并在我们的模板中使用它，将`user`变量绑定到组件期望的`User`属性。

# 组件生命周期

组件实例有一个我们可以连接到的生命周期。目前，我们的迷你应用程序包含四个组件：`App`、`accordion`、`accordion-tab`和`user-info`，但一个典型的 Angular 应用程序将包含数十个组件树，Angular 将在应用程序的生命周期内创建、更新和销毁这些组件。

为了演示目的，我们将模拟一个返回其他数据的服务器调用。为此，在`server`目录中创建一个名为`other-users.json`的文件，并将以下代码粘贴到其中：

```ts
[other-users.json]
[
  {
    "id": 5,
    "name": "Michael jackson",
    "email": "jackson@email.com",
    "birthday": "22/3/1974",
    "gender": "male",
    "status": "onhold",
    "role": "manager",
    "phoneNumbers": [
      "+972-123-9873"
    ]
  },
  (...)
]
```

在手风琴组件模板上，我们将添加一个按钮，该按钮将获取新数据，并在`Component`类上实现`fetchData`方法：

```ts
[accordion.ts]
import { Component, Inject } from '@angular/core';
import { Http } from '@angular/http';
import 'rxjs/add/operator/map';
import { AccordionTab } from './accordion-tab';
import { UserInformation } from '../user-info/user-info';

@Component({
  selector: 'accordion',
  template: `
    <div>
     <button (click)="fetchData('other-users.json')">update data</button>
     <accordion-tab *ngFor="let user of users"
                    (toggle)="toggle(user)"
                    [extended]="isActive(user)"
                    [title]="user.name">
        <user-info [user]="user"></user-info>
      </accordion-tab>
    </div>
  `
})
export class Accordion {  
  users;
  activeUserId = 0;

  constructor(private http: Http) {
    this.fetchData('users.json');
  }
  isActive(user) {
    return user.id === this.activeUserId;
  }

  fetchData(subPath) {
    this.http.get(`/app/server/${subPath}`)
        .map(result => result.json())
        .subscribe(result => this.users = result);
  }

  toggle(user) {
    this.isActive(user) ?
        this.activeUserId = 0 : this.activeUserId = user.id;
  }
}
```

现在，每次点击按钮时，用户数据都会更新，手风琴会重新渲染。打开浏览器，点击按钮，观察手风琴数据的变化。

# 生命周期事件接口

为了在每个组件生命周期事件上运行我们自己的逻辑，我们需要实现与我们想要做出反应的事件相对应的所需方法。这些事件中的每一个都被发布为一个 TypeScript 接口，我们可以在我们的组件类中实现它。使用 TypeScript 接口是可选的，不会以任何方式影响我们的应用程序。您可以从 TypeScript 网站上的文档中了解有关 TypeScript 接口的信息[`www.typescriptlang.org/docs/handbook/interfaces.html`](http://www.typescriptlang.org/docs/handbook/interfaces.html)。我们不会在我们的代码示例中使用这个。

## OnInit and OnDestroy

最简单、最直接、最易于理解的生命周期事件钩子是`onInit`和`onDestroy`。

`ngOnInit`方法在组件数据绑定属性首次检查后被调用，`ngOnDestroy`将在组件实例被 Angular 销毁之前被调用。在我们的组件层次结构中，我们将在`user-info`类上实现这两种方法：

```ts
[user-info.ts]
import {
  Component, Input,
  OnInit, OnDestroy
} from '@angular/core';

@Component({

  selector: 'user-info',
  styleUrls: ['./user-info.css'],
  templateUrl: './user-info.html'
})
export class UserInformation implements OnInit, OnDestroy {  
  @Input() 
  user;

  fontSize = '20px';
  editMode = false;
  randomNumber;

  ngOnInit(){
    console.log('UserInformation initialized');
  }

  ngOnDestroy(){
    console.log('UserInformation Destroy');
  }

  toggleEditMode() {
    this.editMode = !this.editMode;
  }

  onSubmit(data) {
    Object.assign(this.user, data);
    this.editMode = false;
  }
}
```

现在，打开浏览器，确保控制台可见。您应该看到四个日志，指示每个用户组件已被初始化：

![OnInit and OnDestroy](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng2-cpn/img/image00112.jpeg)

现在，点击按钮从服务器拉取新数据。您应该看到每个已被销毁的用户信息组件的四个日志，并为新数据创建的新组件的三个日志：

![OnInit and OnDestroy](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng2-cpn/img/image00113.jpeg)

`OnInit`方法是在组件初始化后（数据绑定属性已解析）和一个子组件初始化之前运行代码的好地方。`OnDestroy`是在组件从 DOM 中移除之前进行清理或持久化代码的好地方。

## OnChanges

`OnChanges`有一个名为`ngOnChanges`的方法，它将在检查所有数据绑定属性后被调用。Angular 传递一个包含以更改的属性命名的键和一个`SimpleChange`对象实例的`change`对象。`SimpleChange`对象包含先前的值和当前的值。让我们在我们的`user-info`组件中实现这个方法：

```ts
[user-info.ts]
import {
  Component, Input,
  OnInit, OnDestroy, OnChanges
} from '@angular/core';

@Component({
  selector: 'user-info',
  styleUrls: ['./user-info.css'],
  templateUrl: './user-info.html'
})
export class UserInformation
      implements OnInit, OnDestroy, OnChanges {  
  @Input() user;
  fontSize = '20px';
  editMode = false;
  randomNumber;

  ngOnInit(){
    console.log('UserInformation initialized');
  }

  ngOnDestroy(){
    console.log('UserInformation Destroy');
  }

  ngOnChanges(changes){
    console.log('onChanges', changes);
  }

  toggleEditMode() {
    this.editMode = !this.editMode;
  }

  onSubmit(data) {
    Object.assign(this.user, data);
    this.editMode = false;
  }
}
```

在浏览器控制台中，我们将看到四个日志：

![OnChanges](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng2-cpn/img/image00114.jpeg)

如果您熟悉 Angular 1.x，您可以将`OnChange`方法视为`$scope.$watch`函数。它将在数据更改时被调用，并包含新值和旧值。

# 其他生命周期事件

除了`init`、`changes`和`destroy`事件之外，我们还可以挂接四个组件生命周期事件：

+   `AfterContentInit`：在组件的内容完全初始化后调用

+   `AfterContentChecked`：在每次组件被检查后调用

+   `AfterViewInit`：在组件的视图初始化后调用

+   `AfterViewChecked`：在组件的视图被检查后调用

它们每一个都可以像之前的例子一样实现。

# 总结

通过本章，我们将迄今为止学到的关于组件的一切都应用到了一个有用的手风琴小部件中，该小部件由四个组件组成。Angular 2 应用程序是一组动态组件，它们使用属性作为输入，使用事件作为输出来相互通信。我们可以挂接到组件的每个重要生命周期，例如，当组件被初始化或销毁时，并运行我们自己的逻辑。
