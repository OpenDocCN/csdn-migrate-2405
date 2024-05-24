# JavaScript 数据结构和算法实用手册（一）

> 原文：[`zh.annas-archive.org/md5/929680AA3DCF1ED8FDD0EBECC6F0F541`](https://zh.annas-archive.org/md5/929680AA3DCF1ED8FDD0EBECC6F0F541)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

本书的主要重点是使用 JavaScript 在真实的 Web 应用程序中应用数据结构和算法。

随着 JavaScript 进入服务器端，并且单页应用程序（SPA）框架接管客户端，很多，如果不是全部，业务逻辑都被移植到了客户端。这使得使用手工制作的数据结构和算法对于特定用例至关重要。

例如，在处理数据可视化（如图表、图形和 3D 或 4D 模型）时，可能会有数以万计甚至数十万个复杂对象从服务器提供，有时几乎是实时的。处理这些数据的方式有多种，这就是我们将要探讨的，配以真实世界的例子。

# 这本书适合谁

这本书适合对 HTML、CSS 和 JavaScript 有兴趣和基本知识的任何人。我们还将使用 Node.js、Express 和 Angular 来创建一些利用我们的数据结构的 Web 应用程序和 API。

# 本书涵盖了什么

第一章，“构建堆栈管理应用程序状态”，介绍了构建和使用堆栈，例如为应用程序创建自定义返回按钮以及在线 IDE 的语法解析器和评估器。

第二章，“为顺序执行创建队列”，演示了使用队列及其变体来创建一个能够处理消息失败的消息服务。然后，我们对不同类型的队列进行了快速比较。

第三章，“使用集合和映射加速应用程序”，使用集合和映射创建键盘快捷方式以在应用程序状态之间导航。然后，我们创建了一个自定义应用程序跟踪器，用于记录 Web 应用程序的分析信息。最后，我们对集合和映射与数组和对象进行了性能比较。

第四章，“使用树加速查找和修改”，利用树数据结构构建了一个自动完成组件。然后，我们创建了一个信用卡批准预测器，根据历史数据确定信用卡申请是否会被接受。

第五章，“使用图简化复杂应用程序”，讨论了图，并附有示例，例如为职业门户创建参考生成器以及在社交媒体网站上的朋友推荐系统。

第六章，“探索各种类型的算法”，探讨了一些最重要的算法，如 Dijkstra 算法、0/1 背包问题、贪婪算法等。

第七章，“排序及其应用”，探讨了归并排序、插入排序和快速排序，并附有示例。然后，我们对它们进行了性能比较。

第八章，“大 O 符号、空间和时间复杂度”，讨论了表示复杂性的符号，然后讨论了空间和时间复杂度以及它们如何影响我们的应用程序。

第九章，“微优化和内存管理”，探讨了 HTML、CSS、JavaScript 的最佳实践，然后讨论了 Google Chrome 的一些内部工作原理，以及我们如何利用它更好地和更快地渲染我们的应用程序。

# 充分利用本书

+   JavaScript、HTML 和 CSS 的基本知识

+   已安装 Node.js（[`nodejs.org/en/download/`](https://nodejs.org/en/download)）

+   安装 WebStorm IDE（[`www.jetbrains.com/webstorm/download`](https://www.jetbrains.com/webstorm/download)）或类似软件

+   下一代浏览器，如 Google Chrome ([`www.google.com/chrome/browser/desktop/`](https://www.google.com/chrome/browser/desktop/))

+   熟悉 Angular 2.0 或更高版本是一个优势，但不是必需的

+   本书中的屏幕截图是在 macOS 上拍摄的。对于任何其他操作系统的用户，可能会有一些差异（如果有的话）。但是，无论操作系统如何，代码示例都将运行而不会出现任何差异。在任何我们指定`CMD/cmd/command`的地方，请在 Windows 对应的地方使用`CTRL/ctrl/control`键。如果看到`return`，请使用*Enter*，如果看到术语`terminal/Terminal`，请在 Windows 上使用其等效的`command prompt`。

+   在本书中，代码库是随着主题的进展逐步构建的。因此，当您将代码示例的开头与 GitHub 中的代码库进行比较时，请注意 GitHub 中的代码是您所参考的主题或示例的最终形式。

# 下载示例代码文件

您可以从[www.packtpub.com](http://www.packtpub.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了本书，您可以访问[www.packtpub.com/support](http://www.packtpub.com/support)并注册，文件将直接发送到您的邮箱。

您可以按照以下步骤下载代码文件：

1.  登录或注册[www.packtpub.com](http://www.packtpub.com/support)。

1.  选择 SUPPORT 选项卡。

1.  点击 Code Downloads & Errata。

1.  在搜索框中输入书名，然后按照屏幕上的说明操作。

下载文件后，请确保使用最新版本的解压缩软件解压文件夹：

+   WinRAR/7-Zip 适用于 Windows

+   Zipeg/iZip/UnRarX 适用于 Mac

+   7-Zip/PeaZip 适用于 Linux

该书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Practical-JavaScript-Data-Structures-and-Algorithms`](https://github.com/PacktPublishing/Hands-On-Data-Structures-and-Algorithms-with-JavaScript)。我们还有来自丰富书籍和视频目录的其他代码包可供下载，网址为**[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)**。去看看吧！

# 下载彩色图像

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图像。您可以在这里下载它：

[`www.packtpub.com/sites/default/files/downloads/HandsOnDataStructuresandAlgorithmswithJavaScript_ColorImages.pdf`](https://www.packtpub.com/sites/default/files/downloads/HandsOnDataStructuresandAlgorithmswithJavaScript_ColorImages.pdf)。

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。这是一个例子：“本地数组操作的时间复杂度各不相同。让我们来看一下`Array.prototype.splice`和`Array.prototype.push`。”

代码块设置如下：

```js
class Stack {
    constructor() {

    }
}
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```js
var express = require('express');
var app = express();
var data = require('./books.json');
var Insertion = require('./sort/insertion');
```

任何命令行输入或输出都以以下形式书写：

```js
ng new back-button
```

**粗体**：表示新术语、重要单词或您在屏幕上看到的单词。例如，菜单或对话框中的单词会以这种形式出现在文本中。这是一个例子：“当用户点击`back`按钮时，我们将从堆栈中导航到应用程序的上一个状态。”

警告或重要提示会出现在这样的形式中。提示和技巧会出现在这样的形式中。


# 第一章：构建应用程序状态管理的堆栈

堆栈是我们可以想到的最常见的数据结构之一。它们在个人和专业设置中无处不在。堆栈是一种**后进先出**（**LIFO**）的数据结构，提供一些常见操作，如推送、弹出、查看、清除和大小。

在大多数**面向对象编程**（**OOP**）语言中，您会发现堆栈数据结构是内置的。另一方面，JavaScript 最初是为网络设计的；它没有内置堆栈。但是，不要让这阻止您。使用 JS 创建堆栈非常容易，而且使用最新版本的 JavaScript 可以进一步简化这一过程。

在本章中，我们的目标是了解堆栈在新时代网络中的重要性以及它们在简化不断发展的应用程序中的作用。让我们探索堆栈的以下方面：

+   对堆栈的理论理解

+   它的 API 和实现

+   在现实世界网络中的用例

在我们开始构建堆栈之前，让我们看一下我们希望堆栈具有的一些方法，以便行为符合我们的要求。必须自己创建 API 是一种幸事。你永远不必依赖别人的库*做得对*，甚至担心任何缺失的功能。您可以添加所需的内容，直到需要为止，不必担心性能和内存管理。

# 先决条件

以下是以下章节的要求：

+   对 JavaScript 的基本理解

+   安装了 Node.js 的计算机（可从[`nodejs.org/en/download/`](https://nodejs.org/en/download/)下载）

本章中所示代码示例的代码样本可以在[`github.com/NgSculptor/examples`](https://github.com/NgSculptor/examples)找到。

# 术语

在本章中，我们将使用以下与堆栈相关的术语，让我们更多地了解它：

+   **顶部**：指示堆栈的顶部

+   **基底**：指示堆栈的底部

# API

这是棘手的部分，因为很难预测应用程序将需要哪些方法。因此，通常最好的做法是从正常情况开始，然后根据应用程序的需求进行更改。按照这种方式，您最终会得到一个看起来像这样的 API：

+   **推送**：将项目推送到堆栈的顶部

+   **弹出**：从堆栈的顶部移除一个项目

+   **窥视**：显示推送到堆栈中的最后一个项目

+   **清除**：清空堆栈

+   **大小**：获取堆栈的当前大小

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-dsal-js/img/00895cb7-ce03-49c1-866a-6ebc7c158459.png)

# 我们难道没有数组吗？

到目前为止，您可能会想知道为什么首先需要堆栈。它与数组非常相似，我们可以在数组上执行所有这些操作。那么，拥有堆栈的真正目的是什么？

更喜欢堆栈而不是数组的原因有很多：

+   使用堆栈为您的应用程序提供更语义化的含义。考虑这样一个类比，您有一个背包（一个数组）和一个钱包（一个堆栈）。您可以在背包和钱包中都放钱吗？当然可以；但是，当您看着背包时，您不知道里面可能会找到什么，但是当您看着钱包时，您非常清楚它里面装着钱。它装着什么样的钱（即数据类型），比如美元、印度卢比和英镑，目前还不清楚（除非您从 TypeScript 获得支持）。

+   本机数组操作具有不同的时间复杂度。例如，让我们看一下`Array.prototype.splice`和`Array.prototype.push`。例如，`Splice`的最坏时间复杂度为 O(n)，因为它必须搜索所有索引并在从数组中剪切元素时进行调整。`Push`在内存缓冲区已满时具有最坏情况的复杂度为 O(n)，但是摊销为 O(1)。堆栈避免直接访问元素，并在内部依赖于`WeakMap()`，这在内存上是高效的，您很快就会看到。

# 创建一个堆栈

现在我们知道何时以及为什么要使用堆栈，让我们继续实现一个。正如前一节中讨论的，我们将使用`WeakMap()`进行实现。您可以使用任何本机数据类型进行实现，但是有一些原因使`WeakMap()`成为一个强有力的竞争者。`WeakMap()`对其持有的键保留了弱引用。这意味着一旦您不再引用特定的键，它将与值一起被垃圾回收。然而，`WeakMap()`也有其自身的缺点：键只能是非原始类型，并且不可枚举，也就是说，您无法获取所有键的列表，因为它们依赖于垃圾回收器。然而，在我们的情况下，我们更关心`WeakMap()`持有的值，而不是键和它们的内部内存管理。

# 实现堆栈方法

实现堆栈是一个相当简单的任务。我们将遵循一系列步骤，其中我们将使用 ES6 语法，如下所示：

1.  定义一个`constructor`：

```js
class Stack {
    constructor() {

    }
}
```

1.  创建一个`WeakMap()`来存储堆栈项：

```js
const sKey = {};
const items = new WeakMap();

class Stack {
 constructor() {
 items.set(sKey, [])
    }
}
```

1.  在`Stack`类中实现前面 API 中描述的方法：

```js
const sKey = {};
const items = new WeakMap();

class Stack {
 constructor() {
 items.set(sKey, []);
    }

 push(element) {
 let stack = items.get(sKey);
 stack.push(element);
    }

 pop() {
 let stack = items.get(sKey)
 return stack.pop()
    }

 peek() {
 let stack = items.get(sKey);
 return stack[stack.length - 1];
    }

 clear() {
 items.set(sKey, []);
    }

 size() {
 return items.get(sKey).length;
    }
}
```

1.  因此，`Stack`的最终实现将如下所示：

```js
var Stack = (() => {
 const sKey = {};
 const items = new WeakMap();

 class Stack {

 constructor() {
 items.set(sKey, []);
        }

 push(element) {
 let stack = items.get(sKey);
 stack.push(element);
        }

 pop() {
 let stack = items.get(sKey);
 return stack.pop();
        }

 peek() {
 let stack = items.get(sKey);
 return stack[stack.length - 1];
        }

 clear() {
 items.set(sKey, []);
        }

 size() {
 return items.get(sKey).length;
        }
    }

 return Stack;
})();
```

这是 JavaScript 堆栈的一个全面实现，这绝不是全面的，可以根据应用程序的要求进行更改。然而，让我们通过这个实现中采用的一些原则。

我们在这里使用了`WeakMap()`，正如前面的段萀中所解释的，它有助于根据对堆栈项的引用进行内部内存管理。

另一件重要的事情要注意的是，我们已经将`Stack`类包装在 IIFE 中，因此`items`和`sKey`常量在`Stack`类内部是可用的，但不会暴露给外部世界。这是当前 JSClas*s*实现的一个众所周知和有争议的特性，它不允许声明类级变量。TC39 基本上设计了 ES6 类，使其只定义和声明其成员，这些成员在 ES5 中是原型方法。此外，由于向原型添加变量不是常规做法，因此没有提供创建类级变量的能力。然而，人们仍然可以做到以下几点：

```js
 constructor() {
        this.sKey = {};
        this.items = new WeakMap();
 this.items.set(sKey, []);
    }
```

然而，这将使`items`也可以从我们的`Stack`方法外部访问，这是我们想要避免的。

# 测试堆栈

为了测试我们刚刚创建的`Stack`，让我们实例化一个新的堆栈，并调用每个方法，看看它们如何向我们呈现数据：

```js
var stack = new Stack();
stack.push(10);
stack.push(20);

console.log(stack.items); // prints undefined -> cannot be accessed directly   console.log(stack.size()); // prints 2

console.log(stack.peek()); // prints 20   console.log(stack.pop()); // prints 20   console.log(stack.size()); // prints 1   stack.clear();

console.log(stack.size()); // prints 0 
```

当我们运行上面的脚本时，我们会看到如上面的注释中指定的日志。正如预期的那样，堆栈在每个操作阶段提供了看似预期的输出。

# 使用堆栈

使用之前创建的`Stack`类，您需要进行一些微小的更改，以允许根据您计划使用的环境来使用堆栈。使这种更改通用相当简单；这样，您就不需要担心支持多个环境，并且可以避免在每个应用程序中重复编写代码：

```js
// AMD
if (typeof define === 'function' && define.amd) {

    define(function () { return Stack; });

// NodeJS/CommonJS

} else if (typeof exports === 'object') {

    if (typeof module === 'object' && typeof module.exports ===
    'object') {

        exports = module.exports = Stack;
    }

// Browser

} else {

    window.Stack = Stack;
}
```

一旦我们将这个逻辑添加到堆栈中，它就可以在多个环境中使用。为了简单和简洁起见，我们不会在看到堆栈的每个地方都添加它；然而，一般来说，在您的代码中拥有这个功能是件好事。

如果您的技术堆栈包括 ES5，则需要将先前的堆栈代码转译为 ES5。这不是问题，因为在线有大量选项可用于将代码从 ES6 转译为 ES5。

# 用例

现在我们已经实现了一个`Stack`类，让我们看看如何在一些 Web 开发挑战中使用它。

# 创建一个 Angular 应用程序

为了探索堆栈在 Web 开发中的一些实际应用，我们将首先创建一个 Angular 应用程序，并将其用作基础应用程序，我们将用于后续用例。

从最新版本的 Angular 开始非常简单。您只需要预先在系统中安装 Node.js。要测试您的计算机上是否安装了 Node.js，请转到 Mac 上的终端或 Windows 上的命令提示符，并键入以下命令：

```js
node -v
```

这应该会显示已安装的 Node.js 版本。如果您看到以下内容：

```js
node: command not found
```

这意味着您的计算机上没有安装 Node.js。

一旦您在计算机上安装了 Node.js，您就可以访问`npm`，也称为 node 包管理器命令行工具，它可以用于设置全局依赖项。使用`npm`命令，我们将安装 Angular CLI 工具，该工具为我们提供了许多 Angular 实用方法，包括但不限于创建新项目。

# 安装 Angular CLI

要在您的终端中安装 Angular CLI，请运行以下命令：

```js
npm install -g @angular/cli
```

这将全局安装 Angular CLI 并让您访问`ng`命令以创建新项目。

要测试它，您可以运行以下命令，这应该会显示可用于使用的功能列表：

```js
ng
```

# 使用 CLI 创建应用程序

现在，让我们创建 Angular 应用程序。为了清晰起见，我们将为每个示例创建一个新应用程序。如果您感到舒适，您可以将它们合并到同一个应用程序中。要使用 CLI 创建 Angular 应用程序，请在终端中运行以下命令：

```js
ng new <project-name>
```

将`project-name`替换为您的项目名称；如果一切顺利，您应该在终端上看到类似的东西：

```js
 installing ng
 create .editorconfig
 create README.md
 create src/app/app.component.css
 create src/app/app.component.html
 create src/app/app.component.spec.ts
 create src/app/app.component.ts
 create src/app/app.module.ts
 create src/assets/.gitkeep
 create src/environments/environment.prod.ts
 create src/environments/environment.ts
 create src/favicon.ico
 create src/index.html
 create src/main.ts
 create src/polyfills.ts
 create src/styles.css
 create src/test.ts
 create src/tsconfig.app.json
 create src/tsconfig.spec.json
 create src/typings.d.ts
 create .angular-cli.json
 create e2e/app.e2e-spec.ts
 create e2e/app.po.ts
 create e2e/tsconfig.e2e.json
 create .gitignore
 create karma.conf.js
 create package.json
 create protractor.conf.js
 create tsconfig.json
 create tslint.json
 Installing packages for tooling via npm.
 Installed packages for tooling via npm.
 Project 'project-name' successfully created.
```

如果遇到任何问题，请确保您已按前面所述安装了 angular-cli。

在为此应用程序编写任何代码之前，让我们将先前创建的堆栈导入项目中。由于这是一个辅助组件，我希望将其与其他辅助方法一起分组到应用程序根目录下的`utils`目录中。

# 创建一个堆栈

由于现在 Angular 应用程序的代码是 TypeScript，我们可以进一步优化我们创建的堆栈。使用 TypeScript 使代码更易读，因为可以在 TypeScript 类中创建`private`变量。

因此，我们优化后的 TypeScript 代码看起来像以下内容：

```js
export class Stack {
 private wmkey = {};
 private items = new WeakMap();

 constructor() {
 this.items.set(this.wmkey, []);
    }

 push(element) {
 let stack = this.items.get(this.wmkey);
 stack.push(element);
    }

 pop() {
 let stack = this.items.get(this.wmkey);
 return stack.pop();
    }

 peek() {
 let stack = this.items.get(this.wmkey);
 return stack[stack.length - 1];
    }

 clear() {
 this.items.set(this.wmkey, []);
    }

 size() {
 return this.items.get(this.wmkey).length;
    }
}
```

要使用先前创建的`Stack`，您只需将堆栈导入任何组件，然后使用它。您可以在以下截图中看到，由于我们将`WeakMap()`和`Stack`类的 keyprivate 成员，它们不再可以从类外部访问：

>！[](assets/ae8a74de-f5d0-4369-93d7-75702f697ae2.png)从 Stack 类中访问的公共方法

# 为 Web 应用程序创建自定义返回按钮

如今，Web 应用程序都关注用户体验，采用扁平设计和小负载。每个人都希望他们的应用程序快速而紧凑。使用笨重的浏览器返回按钮正在逐渐成为过去的事情。要为我们的应用程序创建自定义返回按钮，我们首先需要从先前安装的`ng`cli 客户端创建一个 Angular 应用程序，如下所示：

```js
ng new back-button
```

# 设置应用程序及其路由

现在我们已经设置了基本代码，让我们列出构建应用程序的步骤，以便我们能够在浏览器中创建自定义返回按钮：

1.  为应用程序创建状态。

1.  记录应用程序状态更改时的情况。

1.  检测我们自定义返回按钮的点击。

1.  更新正在跟踪的状态列表。

让我们快速向应用程序添加一些状态，这些状态也被称为 Angular 中的路由。所有 SPA 框架都有某种形式的路由模块，您可以使用它来为应用程序设置一些路由。

一旦我们设置了路由和路由设置，我们将得到以下目录结构：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-dsal-js/img/f819036a-8697-4aed-b7ab-8a045a320b86.png)添加路由后的目录结构

现在让我们设置导航，以便我们可以在各个路由之间切换。要在 Angular 应用程序中设置路由，您需要创建要路由到的组件以及该特定路由的声明。因此，例如，您的`home.component.ts`将如下所示：

```js
import { Component } from '@angular/core';

@Component({
    selector: 'home',
    template: 'home page' })
export class HomeComponent {

}
```

`home.routing.ts`文件将如下所示：

```js
import { HomeComponent } from './home.component';

export const HomeRoutes = [
    { path: 'home', component: HomeComponent },
];

export const HomeComponents = [
    HomeComponent
];
```

我们可以为所需的路由设置类似的配置，并一旦设置完成，我们将创建一个应用程序级文件用于应用程序路由，并在该文件中注入所有路由和`navigatableComponents`，以便我们不必一遍又一遍地触及我们的主模块。

因此，您的`app.routing.ts`文件将如下所示：

```js
import { Routes } from '@angular/router';
import {AboutComponents, AboutRoutes} from "./pages/about/about.routing";
import {DashboardComponents, DashboardRoutes} from "./pages/dashboard/dashboard.routing";
import {HomeComponents, HomeRoutes} from "./pages/home/home.routing";
import {ProfileComponents, ProfileRoutes} from "./pages/profile/profile.routing";

export const routes: Routes = [
    {
 path: '',
 redirectTo: '/home',
 pathMatch: 'full'
  },
    ...AboutRoutes,
    ...DashboardRoutes,
    ...HomeRoutes,
    ...ProfileRoutes ];

export const navigatableComponents = [
    ...AboutComponents,
    ...DashboardComponents,
    ...HomeComponents,
    ...ProfileComponents ];
```

在这里，您会注意到我们正在做一些特别有趣的事情：

```js
{
 path: '',
 redirectTo: '/home',
 pathMatch: 'full' }
```

这是 Angular 设置默认路由重定向的方式，因此当应用程序加载时，它会直接转到`/home`路径，我们不再需要手动设置重定向。

# 检测应用程序状态更改

幸运的是，我们可以使用 Angular 路由器的更改事件来检测状态更改，并根据此进行操作。因此，在您的`app.component.ts`中导入`Router`模块，然后使用它来检测任何状态更改：

```js
import { Router, NavigationEnd } from '@angular/router';
import { Stack } from './utils/stack';

...
...

constructor(private stack: Stack, private router: Router) {

    // subscribe to the routers event
 this.router.events.subscribe((val) => {

        // determine of router is telling us that it has ended
        transition
 if(val instanceof NavigationEnd) {

            // state change done, add to stack
 this.stack.push(val);
        }
    });
}
```

用户采取的任何导致状态更改的操作现在都被保存到我们的堆栈中，我们可以继续设计我们的布局和过渡状态的返回按钮。

# 布局 UI

我们将使用 angular-material 来为应用程序设置样式，因为它快速可靠。要安装`angular-material`，运行以下命令：

```js
npm install --save @angular/material @angular/animations @angular/cdk
```

一旦将 angular-material 保存到应用程序中，我们可以使用提供的`Button`组件来创建所需的 UI，这将非常简单。首先，导入我们想要在此视图中使用的`MatButtonModule`，然后将该模块注入到主`AppModule`中作为依赖项。

`app.module.ts`的最终形式将如下所示：

```js
import { BrowserModule } from '@angular/platform-browser';
import { NgModule } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { HttpModule } from '@angular/http';
import { BrowserAnimationsModule } from '@angular/platform-browser/animations';
import { MatButtonModule } from '@angular/material';

import { AppComponent } from './app.component';
import { RouterModule } from "@angular/router";
import { routes, navigatableComponents } from "./app.routing";
import { Stack } from "./utils/stack";

// main angular module
@NgModule({
 declarations: [
        AppComponent,

        // our components are imported here in the main module
        ...navigatableComponents
    ],
 imports: [
        BrowserModule,
        FormsModule,
        HttpModule,

        // our routes are used here
        RouterModule.forRoot(routes),
        BrowserAnimationsModule,

 // material module  MatButtonModule
    ],
 providers: [
        Stack
    ],
 bootstrap: [AppComponent]
})
export class AppModule { }
```

我们将在顶部放置四个按钮，用于在我们创建的四个状态之间切换，然后在`router-outlet`指令中显示这些状态，然后是返回按钮。完成所有这些后，我们将得到以下结果：

```js
<nav>
    <button mat-button 
        routerLink="/about" 
        routerLinkActive="active">
      About
    </button>
    <button mat-button 
        routerLink="/dashboard" 
        routerLinkActive="active">
      Dashboard
    </button>
    <button mat-button 
        routerLink="/home" 
        routerLinkActive="active">
      Home
    </button>
    <button mat-button 
        routerLink="/profile" routerLinkActive="active">
      Profile
    </button>
</nav>

<router-outlet></router-outlet>

<footer>
    <button mat-fab (click)="goBack()" >Back</button>
</footer>
```

# 在各个状态之间导航

从这里开始为返回按钮添加逻辑相对较简单。当用户点击返回按钮时，我们将从堆栈中导航到应用程序的上一个状态。如果堆栈在用户点击返回按钮时为空，这意味着用户处于起始状态，则我们将其放回堆栈，因为我们执行`pop()`操作来确定堆栈的当前状态。

```js
goBack() {
 let current = this.stack.pop();
 let prev = this.stack.peek();

 if (prev) {
 this.stack.pop();

        // angular provides nice little method to 
        // transition between the states using just the url if needed.
 this.router.navigateByUrl(prev.urlAfterRedirects);

    } else {
 this.stack.push(current);
    }
}
```

请注意，我们在这里使用`urlAfterRedirects`而不是普通的`url`。这是因为我们不关心特定 URL 在达到最终形式之前经历了多少跳转，因此我们可以跳过它之前遇到的所有重定向路径，并直接将用户发送到重定向后的最终 URL。我们只需要最终状态，以便将用户导航到他们之前所在的状态，因为那是他们导航到当前状态之前所在的位置。

# 最终应用程序逻辑

因此，现在我们的应用程序已经准备就绪。我们已经添加了堆栈正在导航到的状态的逻辑，并且我们还有用户点击返回按钮时的逻辑。当我们将所有这些逻辑放在我们的`app.component.ts`中时，我们将得到以下内容：

```js
import {Component, ViewEncapsulation} from '@angular/core';
import {Router, NavigationEnd} from '@angular/router';
import {Stack} from "./utils/stack";

@Component({
 selector: 'app-root',
 templateUrl: './app.component.html',
 styleUrls: ['./app.component.scss', './theme.scss'],
 encapsulation: ViewEncapsulation.None })
export class AppComponent {
 constructor(private stack: Stack, private router: Router) {
 this.router.events.subscribe((val) => {
 if(val instanceof NavigationEnd) {
 this.stack.push(val);
            }
        });
    }

 goBack() {
 let current = this.stack.pop();
 let prev = this.stack.peek();

 if (prev) {
 this.stack.pop();
 this.router.navigateByUrl(prev.urlAfterRedirects);
        } else {
 this.stack.push(current);
        }
    }
}
```

我们还有一些在应用程序中使用的辅助样式表。这些样式表基于您的应用程序和产品的整体品牌；在这种情况下，我们选择了一些非常简单的东西。

对于 AppComponent 的样式，我们可以在`app.component.scss`中添加组件特定的样式：

```js
.active {
  color: red !important;
}
```

对于应用程序的整体主题，我们将在`theme.scss`文件中添加样式：

```js
@import '~@angular/material/theming';
// Plus imports for other components in your app.   // Include the common styles for Angular Material. We include this here so that you only // have to load a single css file for Angular Material in your app. // Be sure that you only ever include this mixin once! @include mat-core();

// Define the palettes for your theme using the Material Design palettes available in palette.scss // (imported above). For each palette, you can optionally specify a default, lighter, and darker // hue. $candy-app-primary: mat-palette($mat-indigo);
$candy-app-accent:  mat-palette($mat-pink, A200, A100, A400);

// The warn palette is optional (defaults to red). $candy-app-warn:    mat-palette($mat-red);

// Create the theme object (a Sass map containing all of the palettes). $candy-app-theme: mat-light-theme($candy-app-primary, $candy-app-accent, $candy-app-warn);

// Include theme styles for core and each component used in your app. // Alternatively, you can import and @include the theme mixins for each component // that you are using. @include angular-material-theme($candy-app-theme);
```

这个前面的主题文件取自 Angular 材料设计文档，并可以根据您的应用程序的颜色方案进行更改。

一旦我们准备好所有的更改，我们可以通过从应用程序的根文件夹运行以下命令来运行我们的应用程序：

```js
ng serve
```

这将启动应用程序，可以通过`http://localhost:4200`访问。

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-dsal-js/img/1a715dff-96aa-4aaa-b8d8-9dd6e7c85b5a.png)

从上面的截图中，我们可以看到应用程序正在运行，并且我们可以使用我们刚刚创建的返回按钮在不同的状态之间导航。

# 构建基本 JavaScript 语法解析器和评估器的一部分

该应用程序的主要目的是在计算密集的环境中展示多个堆栈的并发使用。我们将解析和评估表达式，并生成它们的结果，而不必使用 eval。

例如，如果你想构建自己的`plnkr.co`或类似的东西，你需要在更深入了解复杂的解析器和词法分析器之前，采取类似的步骤，这些解析器和词法分析器用于全面的在线编辑器。

我们将使用与之前描述的类似的基本项目。要使用 angular-cli 创建新应用程序，我们将使用之前安装的 CLI 工具。在终端中运行以下命令来创建应用程序：

```js
ng new parser
```

# 构建基本的 Web Worker

一旦我们创建并实例化了应用程序，我们将首先使用以下命令从应用程序的根目录创建`worker.js`文件：

```js
cd src/app
mkdir utils
touch worker.js
```

这将在`utils`文件夹中生成`worker.js`文件。

请注意以下两点：

+   这是一个简单的 JS 文件，而不是一个 TypeScript 文件，尽管整个应用程序都是用 TypeScript 编写的。

+   它被称为`worker.js`，这意味着我们将为我们即将执行的解析和评估创建一个 Web Worker

Web Worker 用于模拟 JavaScript 中的**多线程**的概念，这通常不是情况。此外，由于此线程运行在隔离中，我们无法为其提供依赖项。这对我们来说非常有利，因为我们的主应用程序只会在每次按键时接受用户的输入并将其传递给 worker，而工作人员的责任是评估这个表达式并返回结果或必要时返回错误。

由于这是一个外部文件，而不是标准的 Angular 文件，我们将不得不将其作为外部脚本加载，以便我们的应用程序随后可以使用它。为此，打开您的`.angular-cli.json`文件，并更新`scripts`选项如下所示：

```js
...
"scripts": [
  "app/utils/worker.js" ],
...
```

现在，我们将能够使用注入的 worker，如下所示：

```js
this.worker = new Worker('scripts.bundle.js');
```

首先，我们将对`app.component.ts`文件进行必要的更改，以便它可以根据需要与`worker.js`进行交互。

# 布局 UI

我们将再次使用 angular-material，就像在前面的示例中描述的那样。因此，安装并使用组件，以便根据需要为应用程序的 UI 添加样式：

```js
npm install --save @angular/material @angular/animations @angular/cdk
```

我们将使用`MatGridListModule`来创建应用程序的 UI。在主模块中导入它后，我们可以创建以下模板：

```js
<mat-grid-list cols="2" rowHeight="2:1">
    <mat-grid-tile>
        <textarea (keyup)="codeChange()" [(ngModel)]="code"></textarea>
    </mat-grid-tile>
    <mat-grid-tile>
        <div>
            Result: {{result}}
        </div>
    </mat-grid-tile>
</mat-grid-list>
```

我们正在铺设两个瓷砖；第一个包含`textarea`用于编写代码，第二个显示生成的结果。

我们将输入区域与`ngModel`绑定，这将为我们的视图和组件之间提供双向绑定。此外，我们利用`keyup`事件来触发名为`codeChange()`的方法，该方法将负责将我们的表达式传递给 worker。

`codeChange()`方法的实现将相对容易。

# 基本 Web Worker 通信

组件加载时，我们将希望设置工作线程，以便不必多次重复。因此，想象一下，如果有一种方法可以有条件地设置并仅在需要时执行操作。在我们的情况下，您可以将其添加到构造函数或任何生命周期挂钩中，这些挂钩表示组件所处的阶段，例如`OnInit`、`OnContentInit`、`OnViewInit`等，这些由 Angular 提供如下：

```js
this.worker = new Worker('scripts.bundle.js');

this.worker.addEventListener('message', (e) => {
 this.result = e.data;
});
```

初始化后，我们使用`addEventListener()`方法来监听任何新消息，即来自工作线程的结果。

每当代码更改时，我们只需将数据传递给我们现在设置的工作线程。这样的实现如下所示：

```js
codeChange() {
 this.worker.postMessage(this.code);
}
```

正如您所注意到的，主应用程序组件是有意保持简洁的。我们利用工作线程的唯一原因是，CPU 密集型操作可以远离主线程。在这种情况下，我们可以将所有逻辑，包括验证，移动到工作线程中，这正是我们所做的。

# 启用 Web Worker 通信

现在，应用程序组件已经设置并准备好发送消息，工作线程需要启用以接收来自主线程的消息。为此，请将以下代码添加到您的`worker.js`文件中：

```js
init();

function init() {
   self.addEventListener('message', function(e) {
      var code = e.data;

      if(typeof code !== 'string' || code.match(/.*[a-zA-Z]+.*/g)) {
         respond('Error! Cannot evaluate complex expressions yet. Please try
         again later');
      } else {
         respond(evaluate(convert(code)));
      }
   });
}
```

如您所见，我们增加了监听可能发送到工作线程的任何消息的功能，然后工作线程只需获取该数据并在尝试评估并返回表达式的任何值之前对其进行基本验证。在我们的验证中，我们只拒绝了任何字母字符，因为我们希望用户只提供有效的数字和运算符。

现在，使用以下命令启动应用程序：

```js
npm start
```

您应该在`localhost:4200`上看到应用程序启动。现在，只需输入任何代码来测试您的应用程序；例如，输入以下内容：

```js
var a = 100;
```

您将看到以下错误弹出在屏幕上：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-dsal-js/img/56deb8ae-ddfd-4ae8-a322-1437289322ae.png)

现在，让我们详细了解正在进行的算法。算法将分为两部分：解析和评估。算法的逐步分解如下：

1.  将输入表达式转换为机器可理解的表达式。

1.  评估后缀表达式。

1.  将表达式的值返回给父组件。

# 将输入转换为机器可理解的表达式

输入（用户输入的任何内容）将是中缀表示法中的表达式，这是人类可读的。例如：

```js
(1 + 1) * 2
```

但是，这并不是我们可以直接评估的内容，因此我们将其转换为后缀表示法或逆波兰表示法。

将中缀表达式转换为后缀表达式是需要一点时间来适应的。我们在维基百科中有一个简化版本的算法，如下所示：

1.  获取输入表达式（也称为中缀表达式）并对其进行标记化，即拆分。

1.  迭代评估每个标记，如下所示：

1.  如果遇到数字，则将标记添加到输出字符串（也称为后缀表示法）中

1.  如果是`(`，即左括号，则将其添加到输出字符串中。

1.  如果是`)`，即右括号，则将所有运算符弹出，直到前一个左括号为止，然后将其添加到输出字符串中。

1.  如果字符是运算符，即`*`、`^`、`+`、`-`、`/`和`,`，则在将其从堆栈中弹出之前，首先检查运算符的优先级。

1.  弹出标记化列表中的所有剩余运算符。

1.  返回结果输出字符串或后缀表示法。

在将其转换为一些代码之前，让我们简要讨论一下运算符的优先级和结合性，这是我们需要预先定义的内容，以便在将中缀表达式转换为后缀表达式时使用。

优先级，顾名思义，确定了特定运算符的`优先级`，而结合性则决定了在没有括号的情况下表达式是从左到右还是从右到左进行评估。根据这一点，由于我们只支持简单的运算符，让我们创建一个运算符、它们的`优先级`和`结合性`的映射：

```js
var operators = {
 "^": {
 priority: 4,
 associativity: "rtl" // right to left
    },
 "*": {
 priority: 3,
 associativity: "ltr" // left to right
    },
 "/": {
 priority: 3,
 associativity: "ltr"
    },
 "+": {
 priority: 2,
 associativity: "ltr"
    },
 "-": {
 priority: 2,
 associativity: "ltr"
    }
};
```

现在，按照算法，第一步是对输入字符串进行标记化。考虑以下示例：

```js
(1 + 1) * 2
```

它将被转换如下：

```js
["(", "1", "+", "1", ")", "*", "2"]
```

为了实现这一点，我们基本上删除所有额外的空格，用空字符串替换所有空格，并在任何`*`，`^`，`+`，`-`，`/` *运算符上拆分剩下的字符串，并删除任何空字符串的出现。

由于没有简单的方法可以从数组中删除所有空字符串`""`，我们可以使用一个称为 clean 的小型实用方法，我们可以在同一个文件中创建它。

这可以翻译成如下代码：

```js
function clean(arr) {
 return arr.filter(function(a) {
 return a !== "";
    });
}
```

因此，最终表达式如下：

```js
expr = clean(expr.trim().replace(/\s+/g, "").split(/([\+\-\*\/\^\(\)])/));
```

现在我们已经将输入字符串拆分，我们准备分析每个标记，以确定它是什么类型，并相应地采取行动将其添加到`后缀`表示输出字符串中。这是前述算法的*第 2 步*，我们将使用一个堆栈使我们的代码更易读。让我们将堆栈包含到我们的工作中，因为它无法访问外部世界。我们只需将我们的堆栈转换为 ES5 代码，它将如下所示：

```js
var Stack = (function () {
   var wmkey = {};
   var items = new WeakMap();

   items.set(wmkey, []);

   function Stack() { }

   Stack.prototype.push = function (element) {
      var stack = items.get(wmkey);
      stack.push(element);
   };
   Stack.prototype.pop = function () {
      var stack = items.get(wmkey);
      return stack.pop();
   };
   Stack.prototype.peek = function () {
      var stack = items.get(wmkey);
      return stack[stack.length - 1];
   };
   Stack.prototype.clear = function () {
      items.set(wmkey, []);
   };
   Stack.prototype.size = function () {
      return items.get(wmkey).length;
   };
   return Stack;
}());
```

正如你所看到的，这些方法都附加在`prototype`上，我们的堆栈就准备好了。

现在，让我们在中缀转后缀转换中使用这个堆栈。在进行转换之前，我们将要检查用户输入是否有效，也就是说，我们要检查括号是否平衡。我们将使用下面代码中描述的简单的`isBalanced()`方法，如果不平衡，我们将返回错误：

```js
function isBalanced(postfix) {
   var count = 0;
   postfix.forEach(function(op) {
      if (op === ')') {
         count++
      } else if (op === '(') {
         count --
      }
   });

   return count === 0;
}
```

我们需要使用堆栈来保存我们遇到的运算符，以便我们可以根据它们的`优先级`和`结合性`在`后缀`字符串中重新排列它们。我们需要做的第一件事是检查遇到的标记是否是一个数字；如果是，那么我们将它附加到`后缀`结果中：

```js
expr.forEach(function(exp) {
 if(!isNaN(parseFloat(exp))) {
 postfix += exp + " ";
    }
});
```

然后，我们检查遇到的标记是否是一个开括号，如果是，那么我们将它推到运算符堆栈中，等待闭括号。一旦遇到闭括号，我们将在`后缀`输出中组合所有内容（运算符和数字），如下所示：

```js
expr.forEach(function(exp) {
 if(!isNaN(parseFloat(exp))) {
 postfix += exp + " ";
    }  else if(exp === "(") {
 ops.push(exp);
    } else if(exp === ")") {
 while(ops.peek() !== "(") {
 postfix += ops.pop() + " ";
        }
 ops.pop();
    }
});
```

最后（稍微复杂）的一步是确定标记是否是`*`，`^`，`+`，`-`，`/`中的一个，然后我们首先检查当前运算符的`结合性`。当它是从左到右时，我们检查当前运算符的优先级是否*小于或等于*上一个运算符的优先级。当它是从右到左时，我们检查当前运算符的优先级是否*严格小于*上一个运算符的优先级。如果满足任何这些条件，我们将弹出运算符直到条件失败，将它们附加到`后缀`输出字符串，然后将当前运算符添加到下一次迭代的运算符堆栈中。

我们对从右到左的严格检查而不是从左到右的`结合性`进行严格检查的原因是，我们有多个具有相同`优先级`的`结合性`的运算符。

在此之后，如果还有其他运算符剩下，我们将把它们添加到`后缀`输出字符串中。

# 将中缀转换为后缀表达式

将上面讨论的所有代码放在一起，将中缀表达式转换为`后缀`的最终代码如下：

```js
function convert(expr) {
 var postfix = "";
 var ops = new Stack();
 var operators = {
 "^": {
 priority: 4,
 associativity: "rtl"
        },
 "*": {
 priority: 3,
 associativity: "ltr"
        },
 "/": {
 priority: 3,
 associativity: "ltr"
        },
 "+": {
 priority: 2,
 associativity: "ltr"
        },
 "-": {
 priority: 2,
 associativity: "ltr"
        }
    };

    expr = clean(expr.trim().replace(/\s+/g, "").split(/([\+\-\*\/\^\(\)])/));

    if (!isBalanced(expr) {
        return 'error';
    }    

    expr.forEach(function(exp) {
 if(!isNaN(parseFloat(exp))) {
 postfix += exp + " ";
        }  else if(exp === "(") {
 ops.push(exp);
        } else if(exp === ")") {
 while(ops.peek() !== "(") {
 postfix += ops.pop() + " ";
            }
 ops.pop();
        } else if("*^+-/".indexOf(exp) !== -1) {
 var currOp = exp;
 var prevOp = ops.peek();
 while("*^+-/".indexOf(prevOp) !== -1 && ((operators[currOp].associativity === "ltr" && operators[currOp].priority <= operators[prevOp].priority) || (operators[currOp].associativity === "rtl" && operators[currOp].priority < operators[prevOp].priority)))
            {
 postfix += ops.pop() + " ";
 prevOp = ops.peek();
            }
 ops.push(currOp);
        }
    });

 while(ops.size() > 0) {
 postfix += ops.pop() + " ";
    }
 return postfix;
}
```

这将把提供的中缀运算符转换为`后缀`表示法。

# 评估后缀表达式

从这里开始，执行这种`后缀`表示法相当容易。算法相对简单；您将每个运算符弹出到最终结果堆栈上。*如果运算符是`*`、`,`、`^`、`+`、`-`、`/`中的一个，则相应地对其进行评估；否则，继续将其附加到输出字符串中：

```js
function evaluate(postfix) {
 var resultStack = new Stack();
    postfix = clean(postfix.trim().split(" "));
    postfix.forEach(function (op) {
 if(!isNaN(parseFloat(op))) {
 resultStack.push(op);
        } else {
 var val1 = resultStack.pop();
 var val2 = resultStack.pop();
 var parseMethodA = getParseMethod(val1);
 var parseMethodB = getParseMethod(val2);
 if(op === "+") {
 resultStack.push(parseMethodA(val1) + parseMethodB(val2));
            } else if(op === "-") {
 resultStack.push(parseMethodB(val2) - parseMethodA(val1));
            } else if(op === "*") {
 resultStack.push(parseMethodA(val1) * parseMethodB(val2));
            } else if(op === "/") {
 resultStack.push(parseMethodB(val2) / parseMethodA(val1));
            } else if(op === "^") {
 resultStack.push(Math.pow(parseMethodB(val2), 
 parseMethodA(val1)));
            }
       }
    });

 if (resultStack.size() > 1) {
 return "error";
    } else {
 return resultStack.pop();
    }
}
```

在这里，我们使用一些辅助方法，比如`getParseMethod()`来确定我们处理的是整数还是浮点数，以便我们不会不必要地四舍五入任何数字。

现在，我们需要做的就是指示我们的工作人员返回它刚刚计算的数据结果。这与我们返回的错误消息的方式相同，因此我们的`init()`方法如下更改：

```js
function init() {
 self.addEventListener('message', function(e) {
 var code = e.data;

 if(code.match(/.*[a-zA-Z]+.*/g)) {
 respond('Error! Cannot evaluate complex expressions yet. Please try
            again later');
        } else {
 respond(evaluate(convert(code)));
        }
    });
}
```

# 总结

在这里，我们有使用堆栈的真实网络示例。*在这两个示例中需要注意的重要事情是，大部分逻辑不像预期的那样围绕数据结构本身。它是一个辅助组件，极大地简化了访问并保护您的数据免受意外的代码问题和错误。

在本章中，我们介绍了为什么我们需要一个特定的堆栈数据结构而不是内置数组的基础知识，使用所述数据结构简化我们的代码，并注意数据结构的应用。这只是令人兴奋的开始，还有更多内容要来。

在下一章中，我们将沿着相同的线路探索**队列**数据结构，并分析一些额外的性能指标，以检查是否值得麻烦地构建和/或使用自定义数据结构。


# 第二章：为顺序执行创建队列

队列是一个编程构造，与现实世界的队列（例如电影院、ATM 或银行的队列）有很大的相似之处。与堆栈相反，队列是**先进先出**（**FIFO**），因此无论什么先进去，也会先出来。当您希望保持数据以流入的相同顺序时，这是特别有帮助的。

队列的更多计算机/科学定义如下：

<q>一个抽象数据集合，其中元素可以被添加到后端称为 enqueue，并从前端称为 dequeue 中移除，这使其成为 FIFO 数据结构。</q>

当然，只有*enqueue*和*dequeue*操作可能足够覆盖大多数情况，以涵盖我们可能遇到的更广泛的问题；然而，我们可以扩展 API 并使我们的队列具有未来的可扩展性。

在本章中，我们将讨论以下主题：

+   队列的类型

+   不同类型的队列实现

+   显示队列的有用性的用例

+   与其他本地数据结构相比的队列性能

# 队列的类型

在我们开始理解队列之前，让我们快速看一下我们可能想在应用程序中使用的队列类型：

+   **简单队列**：在简单的 FIFO 队列中，顺序被保留，数据以进入的顺序离开

+   **优先队列**：队列中的元素被赋予预定义的优先级

+   **循环队列**：类似于简单队列，只是队列的后端跟随队列的前端

+   **双端队列**（**Dequeue**）：类似于简单队列，但可以从队列的前端或后端添加或移除元素

# 实现 API

实现 API 从来不像看起来那么容易，正如之前讨论的那样。在创建通用类时，我们无法预测我们的队列将在何种情况下使用。考虑到这一点，让我们为我们的队列创建一个非常通用的 API，并根据需要在将来扩展它。我们可以添加到队列的一些最常见的操作如下：

+   `add()`: 将项目推送到队列的后端

+   `remove()`: 从队列的开头移除一个项目

+   `peek()`: 显示添加到队列的最后一个项目

+   `front()`: 返回队列前端的项目

+   `clear()`: 清空队列

+   `size()`: 获取队列的当前大小

# 创建队列

在我们之前讨论过的四种类型的队列中，首先，我们将实现一个简单的队列，然后继续修改每种类型的后续队列。

# 一个简单的队列

与堆栈类似，我们将使用以下步骤创建一个队列：

1.  定义一个`constructor()`：

```js
class Queue {
    constructor() {

    }
}
```

1.  我们将使用`WeakMap()`来进行内存数据存储，就像我们为堆栈所做的那样：

```js
 const qKey = {};
 const items = new WeakMap();

 class Queue {
 constructor() {

        }
    }
```

1.  实现先前在 API 中描述的方法：

```js
var Queue = (() => {
 const qKey = {};
 const items = new WeakMap();

 class Queue {

 constructor() {
 items.set(qKey, []);
        }

 add(element) {
 let queue = items.get(qKey);
 queue.push(element);
        }

 remove() {
 let queue = items.get(qKey);
 return queue.shift();
        }

 peek() {
 let queue = items.get(qKey);
 return queue[queue.length - 1];
        }

 front() {
 let queue = items.get(qKey);
 return queue[0];
        }

 clear() {
 items.set(qKey, []);
        }

 size() {
 return items.get(qKey).length;
        }
    }

 return Queue;
})();
```

我们再次将整个类包装在 IIFE 中，因为我们不希望从外部访问`Queue`项：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-dsal-js/img/602f7738-6cd0-40f4-8fe3-b9ba8a960396.png)

# 测试队列

要测试这个队列，您可以简单地实例化它并向队列中添加/移除一些项目：

```js
var simpleQueue = new Queue();
simpleQueue.add(10);
simpleQueue.add(20);

console.log(simpleQueue.items); // prints undefined   console.log(simpleQueue.size()); // prints 2   console.log(simpleQueue.remove()); // prints 10   console.log(simpleQueue.size()); // prints 1   simpleQueue.clear();

console.log(simpleQueue.size()); // prints 0
```

正如您可以从前面的代码中注意到的那样，所有元素都被同等对待。无论它们包含的数据是什么，元素始终以 FIFO 的方式对待。尽管这是一个很好的方法，但有时我们可能需要更多：即优先处理进入和离开队列的元素，正如我们可以在接下来的部分中注意到的那样。

# 优先队列

优先队列在操作上类似于简单队列，即它们支持相同的 API，但它们所持有的数据还有一个小小的附加项。除了元素（您的数据）之外，它们还可以保持一个优先级，这只是一个表示队列中元素优先级的数值。

从队列中添加或移除这些元素是基于优先级的。您可以拥有最小优先级队列或最大优先级队列，以帮助确定您是基于增加优先级还是减少优先级来添加元素。我们将看一下`add()`方法如何替代我们之前定义的简单队列的`add()`方法：

```js
add(newEl) {
 let queue = items.get(pqkey);
 let newElPosition = queue.length;

 if(!queue.length) {
 queue.push(newEl);
 return;
    }

 for (let [i,v] of queue.entries()) {
 if(newEl.priority > v.priority) {
 newElPosition = i;
 break;
        }
    }

 queue.splice(newElPosition, 0, newEl);
}
```

由于我们在插入堆栈时考虑了元素的优先级，所以我们在从队列中移除元素时不必关注优先级，因此`remove()`方法对于简单队列和优先队列是相同的。其他实用方法，如`front()`、`clear()`、`peek()`和`size()`，与保存在队列中的数据类型无关，因此它们也保持不变。

创建优先队列时的一个聪明举措是优化您的代码，并决定您是否想要在添加或移除时确定优先级。这样，您就不会在每一步都过度计算或分析数据集。

# 测试优先队列

让我们首先设置用于测试队列的数据：

```js
var priorityQueue = new PriorityQueue();

priorityQueue.add({ el : 1, priority: 1});

// state of Queue
// [1]
//  ^

priorityQueue.add({ el : 2, priority: 2});

// state of Queue
// [2, 1]
//  ^

priorityQueue.add({ el : 3, priority: 3});

// state of Queue
// [3, 2, 1]
//  ^

priorityQueue.add({ el : 4, priority: 3});

// state of Queue
// [3, 4, 2, 1]
//     ^

priorityQueue.add({ el : 5, priority: 2});

// state of Queue
// [3, 4, 2, 5, 1]
//           ^
```

从视觉上看，前面的步骤将生成一个如下所示的队列：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-dsal-js/img/8c841da0-1359-4cb8-bf55-731f3ac619a0.png)

从前面的图中，我们可以注意到当我们添加一个优先级为 2 的元素时，它会排在所有优先级为 1 的元素之前：

```js
priorityQueue.add({ el : 6, priority: 1});

// state of Queue
// [3, 4, 2, 5, 1, 6]
//                 ^  
```

当我们添加一个优先级为 1（最低）的元素时，它会被添加到队列的末尾：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-dsal-js/img/ff347fa9-6abe-441c-94d7-26e1e3f7571b.png)

我们在这里添加的最后一个元素恰好也是优先级最低的元素，这使它成为队列的最后一个元素，从而根据优先级保持所有元素的顺序。

现在，让我们从队列中移除元素：

```js
console.log(priorityQueue.remove());

// prints { el: 3, priority: 3}

// state of Queue
// [4, 2, 5, 1, 6]

console.log(priorityQueue.remove());

// prints { el: 4, priority: 3 }

// state of Queue
// [2, 5, 1, 6]

console.log(priorityQueue.remove());

// prints { el: 2, priority: 2 }

// state of Queue
// [5, 1, 6]

priorityQueue.print();

// prints { el: 5, priority: 2 } { el: 1, priority: 1 } { el: 6, priority: 1 }
```

这就是：使用`WeakMap()`在 JavaScript 中创建简单和优先队列。现在让我们来看一下这些队列的一些实际应用。

# 队列的用例

在开始使用案例之前，我们需要一个基本的起点，即一个 Node.js 应用程序。要创建一个，请确保您已安装了最新的 Node.js：

```js
node -v
```

这应该显示您当前安装的 Node.js 版本；如果没有，那么请从[`nodejs.org/en`](https://nodejs.org/en/)下载并安装最新版本的 Node.js。

# 创建一个 Node.js 应用程序

要开始一个示例 Node.js 项目，首先创建一个项目文件夹，然后从该文件夹运行以下命令：

```js
npm init
```

运行此命令时，Node 将提示您一系列问题，您可以选择填写或留空：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-dsal-js/img/aa9bf36c-0a1d-443a-9483-d94608efff14.png)

创建空应用程序后，您将看到一个名为`package.json`的文件。现在，您可以添加创建 Node.js 应用程序所需的依赖项：

```js
npm install body-parser express --save
```

`body-parser`模块有助于解析 POST 请求体，而`express`模块有助于创建 Node.js 服务器。

# 启动 Node.js 服务器

一旦我们创建了应用程序外壳，创建一个名为`index.js`的文件，这将是您的应用程序的主文件；您可以随意命名，但请确保您相应地更新`package.json`中的`main`属性。

现在，让我们在`index.js`文件中添加一些代码来启动一个 express 服务器：

```js
var express = require('express');
var app = express();

app.listen(3000, function () {
 console.log('Chat Application listening on port 3000!')
});
```

就是这样！服务器现在在`3000`端口上运行。要测试它，只需添加一个空路由来告诉您应用程序是否正常运行：

```js
app.get('/', function (req, res) {
    res.status(200).send('OK!')
});
```

您可以打开浏览器并导航到`localhost:3000`，这应该会显示服务器状态为`OK！`，或者如果服务器宕机，则会给出错误。

# 创建一个聊天端点

现在我们的服务器已经运行起来了，我们可以创建一个内存中的聊天端点，它将接受来自两个用户的消息，并使用队列将其转发给其预期的接收者，同时保留顺序。

在添加逻辑之前，我们需要进行一些基础工作，以模块化地设置应用程序。首先，让我们包含`body-parser`并在 express 中间件中使用它，以便我们可以轻松访问请求的`body`。因此，更新后的`index.js`文件如下所示：

```js
var express = require('express');
var app = express();
var bodyParser = require('body-parser');

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.get('/', function (req, res) {
    res.status(200).send('OK!')
});

app.listen(3000, function () {
 console.log('Chat Application listening on port 3000!')
});
```

现在，要为消息添加端点，我们可以在`routes`文件夹下创建一个名为`messages.js`的新文件，然后在其中添加基本的`post`请求：

```js
var express = require('express');
var router = express.Router();

router.route('/')
   .post(function(req, res) {

         res.send(`Message received from: ${req.body.from} to ${req.body.to} with message ${req.body.message}`);

});

module.exports = router;
```

然后，我们可以将其注入到我们的`index.js`中，并使其成为我们应用程序的一部分：

```js
var message = require('./routes/messages');

...
...
...

app.use('/message', message);
```

现在，为了测试这个，我们可以启动服务器并使用 Postman 向`localhost:3000/message`发送一条消息；然后我们可以看到以下响应：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-dsal-js/img/10ca44ce-3541-493d-a17d-6233240f53c8.png)图：示例发布消息

现在，我们可以继续开始添加逻辑，以便在两个用户之间发送消息。我们将抽象、模拟和简化应用程序的聊天部分，并更专注于在这种复杂应用程序中使用队列应用。

工作流本身相对简单：用户 A 向用户 B 发送消息，我们的服务器尝试将其转发给用户 B。如果没有任何问题，一切顺利，消息将被传递给用户 B；但如果失败，我们将调用我们的`FailureProtocol()`，它会重试发送上一次失败的对话消息。为简单起见，我们现在假设只有一个通道，即用户 A 和用户 B 之间的通道*。

生产环境中的对应部分将能够同时处理多个通道，当通道上的消息发送失败时，会为特定通道创建一个新的`FailureProtocol()`处理程序，并具有将作业推迟到多个线程的灵活性。

现在，让我们在一个名为`messaging-utils.js`的文件中模拟`sendMessage()`和`getUniqueFailureQueue()`方法，这将是我们的包装器，以便我们可以将它们移动到自己的模块中，因为它们在这种情况下对于理解队列并不重要：

```js
var PriorityQueue = require('./priority-queue');

var Utils = (()=> {
 class Utils {

 constructor() {

        }

 getUniqueFailureQueue(from, to) {
 // use from and to here to determine 
            // if a failure queue already 
            // exists or create a new one return new PriorityQueue();
        }

 sendMessage(message) {
 return new Promise(function(resolve, reject) {
 // randomize successes and failure of message being
                   sent  if(Math.random() < 0.1) {

                    resolve(message)

                } else {

                    reject(message);

                }

            });
        }

    }

 return Utils;
})();

module.exports = Utils;
```

现在，当我们收到新消息时，我们会尝试将其发送给预期的最终用户：

```js
var express = require('express');
var router = express.Router();
var Utils = require('../utils/messaging-utils');
const msgUtils = new Utils();

router.route('/')
    .post(function(req, res) {
 const message = req.body.message;
 let failedMessageQueue;

 // try to send the message msgUtils.sendMessage(req.body)
            .then(function() {

                res.send(`Message received from: ${req.body.from} to ${req.body.to} with message ${req.body.message}`);

            }, function() {

 failedMessageQueue = 
 msgUtils.getUniqueFailureQueue(req.body.from,
                   req.body.to);

 failedMessageQueue.add(message);

 // trigger failure protocol triggerFailureProtocol();

         });
```

如果消息发送成功，我们需要立即确认并发送成功消息；否则，我们将在两个用户之间得到一个唯一的`failedMessageQueue`，然后将消息添加到其中，随后触发失败协议。

失败协议对不同的应用程序可能意味着不同的事情。虽然一些应用程序选择只显示失败消息，像我们这样的应用程序会重试发送消息，直到成功发送为止：

```js
function triggerFailureProtocol() {

 var msg = failedMessageQueue.front();

 msgUtils.sendMessage(msg)
        .then(function() {

 failedMessageQueue.remove();

             res.send('OK!');

         }, function(msg) {

 //retry failure protocol triggerFailureProtocol();

         });
}
```

我们可以使用我们的`Queue`中可用的方法来选择顶部消息，然后尝试发送它。如果成功，然后删除它；否则，重试。正如你所看到的，使用队列极大地简化和抽象了实际失败消息排队的逻辑，更好的是，你可以随时升级和增强队列，而不必考虑其他组件会受到这种变化的影响。

现在我们已经准备好解析传入请求、发送给预期接收者并触发我们自定义的失败协议的 API 调用。当我们将所有这些逻辑结合在一起时，我们有以下内容：

```js
var express = require('express');
var router = express.Router();
var Utils = require('../utils/messaging-utils');
const msgUtils = new Utils();

router.route('/')
    .post(function(req, res) {
 const message = req.body.message;
 let failedMessageQueue;

 // try to send the message msgUtils.sendMessage(req.body)
            .then(function() {

 console.log("Sent Successfully : " + message);

 res.send(`Message received from: ${req.body.from} to ${req.body.to} with message ${req.body.message}`);

            }, function(msg) {

 console.log('Failed to send: ' + message);

 failedMessageQueue = 
 msgUtils.getUniqueFailureQueue(req.body.from,
                     req.body.to);

 failedMessageQueue.add(message);

 // trigger failure protocol triggerFailureProtocol();
            });

 function triggerFailureProtocol() {

 var msg = failedMessageQueue.front();

 msgUtils.sendMessage(msg)
                .then(function() {

 failedMessageQueue.remove();

 res.send('OK!');

                 }, function(msg) {

 //retry failure protocol triggerFailureProtocol();

                 });
        }
});

module.exports = router;
```

# 使用优先队列实现日志记录

端点失败是不可避免的。虽然我们可以尝试重新发送失败的消息，但我们需要意识到在某个时候我们的端出现了问题，并停止向服务器发送请求以转发消息。这就是优先队列可以派上用场的地方。

我们将替换现有逻辑，使用优先队列来检测何时停止尝试重新发送消息，并通知支持团队。

最大的变化在`triggerFailureProtocol()`方法中，我们检查消息是否失败的次数超过了预设的`retryThreshold`；如果是，那么我们将消息添加到具有关键优先级的队列中，稍后我们将使用它来防止服务器的后续轰炸，直到支持团队解决问题。这个解决方案虽然相当天真，但在保留服务器资源方面非常有效。

因此，带有优先队列的更新代码如下：

```js
function triggerFailureProtocol() {

 console.log('trigger failure protocol');

 // get front message from queue var frontMsgNode = failedMessageQueue.front();

 // low priority and hasnt hit retry threshold if (frontMsgNode.priority === 0 
        && failureTriggerCount <= failureTriggerCountThreshold) {

 // try to send message msgUtils.sendMessage(frontMsgNode.message)
            .then(function() {

 console.log('resend success');
 // success, so remove from queue failedMessageQueue.remove();

 // inform user                res.send('OK!');

             }, function() {

 console.log('resend failure');

 // increment counter failureTriggerCount++;

 //retry failure protocol triggerFailureProtocol();

             });

    } else {

 console.log('resend failed too many times');

 // replace top message with higher priority message let prevMsgNode = failedMessageQueue.remove();

 prevMsgNode.priority = 1;

 // gets added to front failedMessageQueue.add(prevMsgNode);

        res.status(500).send('Critical Server Error! Failed to send
        message');

    }
}
```

在上面的代码中，我们将相同的登录包装在`if-else`块中，以便能够重试发送消息或创建关键错误并停止我们的重试努力。

因此，下次该频道收到新消息时，您可以验证是否已经存在关键错误，并直接拒绝请求，而不必经历尝试发送消息并失败的麻烦，这会不断膨胀失败队列。

这当然是解决这个问题的一种方法，但更合适的方法是在用户尝试访问频道时通知用户任何关键错误，而不是在用户向其发布消息时这样做，这超出了本示例的范围。

以下是包括优先队列的完整代码：

```js
var express = require('express');
var router = express.Router();
var Utils = require('../utils/messaging-utils');
const msgUtils = new Utils();

router.route('/')
    .post(function(req, res) {
 const message = req.body.message;
 let failedMessageQueue;
 let failureTriggerCount = 0;
 let failureTriggerCountThreshold = 3;
 let newMsgNode = {
 message: message,
 priority: 0
        };

 // try to send the message msgUtils.sendMessage(req.body)
            .then(function() {

 console.log('send success');

 // success                res.send(`Message received from: ${req.body.from} to ${req.body.to} with message ${req.body.message}`);

         }, function() {

 console.log('send failed');

 // get unique queue failedMessageQueue = 
 msgUtils.getUniqueFailureQueue(req.body.from,
                    req.body.to);

 // get front message in queue var frontMsgNode = failedMessageQueue.front();
 // already has a critical failure if (frontMsgNode && frontMsgNode.priority === 1) {

 // notify support   // notify user                   res.status(500)
                      .send('Critical Server Error! Failed to send
                      message');

               } else {

 // add more failedMessageQueue.add(newMsgNode);

 // increment count failureTriggerCount++;

 // trigger failure protocol triggerFailureProtocol();

               }
        });

 function triggerFailureProtocol() {

 console.log('trigger failure protocol');

 // get front message from queue var frontMsgNode = failedMessageQueue.front();

 // low priority and hasnt hit retry threshold if (frontMsgNode.priority === 0 
               && failureTriggerCount <= failureTriggerCountThreshold) {

 // try to send message msgUtils.sendMessage(frontMsgNode.message)
                   .then(function() {

 console.log('resend success');
 // success, so remove from queue failedMessageQueue.remove();

 // inform user                       res.send('OK!');

                    }, function() {

 console.log('resend failure');

 // increment counter failureTriggerCount++;

 //retry failure protocol triggerFailureProtocol();

                     });

            } else {

 console.log('resend failed too many times');

 // replace top message with higher priority message let prevMsgNode = failedMessageQueue.remove();

 prevMsgNode.priority = 1;

 // gets added to front failedMessageQueue.add(prevMsgNode);

                res.status(500)
                   .send('Critical Server Error! Failed to send 
                   message');

           }
        }
});

module.exports = router;
```

# 性能比较

之前，我们看到了如何简单地将简单队列替换为优先队列，而不必担心它可能引起的功能性变化；同样，我们可以将优先队列替换为性能更高的变体：循环双端队列。

在我们开始进行比较之前，我们需要讨论循环队列以及为什么我们需要它们。

循环队列和简单队列之间的区别在于队列的尾部紧随队列的前部。也就是说，它们在功能上没有区别。它们仍然执行相同的操作，并产生相同的结果；您可能想知道它们究竟在哪里不同，如果最终结果是相同的，那有什么意义。

在 JavaScript 数组中，内存位置是连续的。因此，当创建队列并执行`remove()`等操作时，我们需要担心将剩余元素移动到更新的*front*而不是*null*，从而增加操作的数量；这也是一个内存开销，除非您的队列有无限/动态数量的插槽。

现在，想象一个循环队列——由于它的循环性质，这个队列有固定数量的内存位置，当元素被移除或添加时，您可以重用内存位置并减少执行的操作数量，这使得它比常规队列更快。

在我们对比这个队列与 JavaScript 中的原生数组的性能之前，让我们来看看 Chrome 的 JavaScript 引擎 V8 的内部工作，并检查它是否真的在我们的情况下很重要。我们考虑这个的原因是因为 JavaScript 中经常被忽视的稀疏数组和密集数组的概念，尽管这是一个底层实现，可能会不断变化。大多数情况下，JavaScript 数组是密集的，如果处理不当很容易变得稀疏。测试这一点的一个简单方法是创建一个数组，如下所示：

+   考虑示例 1：

```js
const a = [undefined, undefined, 10];
```

当你记录它时，你会看到相同的结果：

```js
[undefined, undefined, 10];
```

现在，创建一个这样的数组：

+   考虑示例 2：

```js
const b = [];
b[3] = 10; // hole as we missed out index 0,1,2
```

当你记录它时，你会得到相同的结果：

```js
[undefined x 3, 10];
```

这很有趣，因为它展示了 JavaScript 数组的密集（示例 1）和稀疏（示例 2）行为之间的差异。当您创建这些密集数组时，数组的元素被认为是特定值，并且这些值在初始化时是已知的，这使得 JavaScript 有可能将这些值保存在连续的内存中。

JavaScript 数组实现的 V8 代码有以下注释，这使得我们可以观察到另一个有趣的现象，与我们之前讨论的内容一致。

```js
// The JSArray describes JavaScript Arrays // Such an array can be in one of two modes: //           - fast, backing storage is a FixedArray and length <= elements.length(); //           Please note: push and pop can be used to grow and shrink the array. //         - slow, backing storage is a HashTable with numbers as keys. class JSArray: public JSObject {
```

因此，数组在内部根据正在保存在数组中的数据的类型和大小而有所不同。作为一个经验法则，总是使用数组文字创建一个空数组，并从 0 索引开始逐步为元素分配值，同时不在数组中留下空隙或空洞。这样可以使数组保持快速，并且除非数据的规模要求，否则不会进入字典模式。

双端循环队列，也称为循环双端队列，与简单队列类似，只是`add()`和`remove()`可以从队列的前面或后面进行。

这基本上是与您的数组相同的 API，我们可以构建一个提供此功能的类的示例，但让我们更进一步，看看如何使用循环队列实现我们之前讨论的一切，并使其尽可能高效：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-dsal-js/img/96b70c36-8796-4a30-9ebb-b82c590024e5.png)

首先，我们假设这个队列有一个有限的大小；它可以随后扩展为动态的性质，但现在不是一个问题。到目前为止，`WeakMap()`已被用作内存中的数据存储，我们在其中保存了队列所需的数据，但是在性能方面，它只是为我们的数据结构添加了另一层检索，因此在这种情况下，我们将转移到标准数组，因为这是我们将在基准测试中进行比较的。将这些转化为一些代码，我们可以得到我们的`CircularDequeue`，如下所示：

```js
var CircularDequeue = (()=> {
 class CircularDequeue {
 constructor() {
 // pseudo realistic 2^x value this._size = 1024;
 this._length = 0;
 this._front = 0;
 this._data = [];
        }

 push (item) {
 // get the length of the array var length = this._length;

 // calculate the end var i = (this._front + length) & (this._size - 1);

 // assign value to the current end of the data this._data[i] = item;

 // increment length for quick look up this._length = length + 1;

 // return new length return this._length;
        }

 pop () {
 // get the length of the array var length = this._length;

 // calculate the end var i = (this._front + length - 1) & (this._size - 1);

 // copy the value to return var ret = this._data[i];

 // remove the value from data this._data[i] = undefined;

 // reduce length for look up  this._length = length - 1;

 // return value  return ret;
       }

 shift () {
 // get the current front of queue var front = this._front;

 // capture return value var ret = this._data[front];

 // reset value in the data this._data[front] = undefined;

 // calculate the new front of the queue this._front = (front + 1) & (this._size - 1);

 // reduce the size this._length = this._length - 1;

 // return the value return ret;

        }

 unshift (item) {
 // get the size var size = this._size;

 // calculate the new front var i = (((( this._front - 1 ) & ( size - 1) ) ^ size ) -
            size );

 // add the item this._data[i] = item;

 // increment the length this._length = this._length + 1;

 // update the new front this._front = i;

 // return the acknowledgement of the addition of the new
            item return this._length;
        }
    }

 return CircularDequeue;
})();

module.exports = CircularDequeue;
```

当然，这只是实现循环双端队列的一种方式；您可以通过将属性添加到类的构造函数本身而不是将它们包装在 IIFE 中（即避免作用域链查找），并且如果您使用 TypeScript，还可以进一步简化代码，这允许私有类成员，就像我们在讨论堆栈时所讨论的那样。

# 运行基准测试

在运行基准测试之前，重要的是要理解我们比较队列与本机数组的意图。我们并不试图证明队列比数组更快，这就是为什么我们应该使用它们。同时，我们也不想使用一些非常慢的东西。这些测试的目标是帮助我们了解队列在本机数据结构方面的位置，以及我们是否可以依赖它们提供高性能的自定义数据结构（如果需要）。

现在，让我们运行一些基准测试来比较循环双端队列和数组。我们将使用`benchmark.js`来设置和运行我们的基准测试。

要开始测试，让我们首先在项目中包含基准测试节点模块。要安装它，请在项目根目录的终端上运行以下命令：

```js
npm install benchmark --save-dev
```

安装完成后，我们准备创建我们的测试套件。创建一个`tests`文件夹，并在其中添加一个名为`benchmark.js`的文件。为了创建一个测试套件，我们首先设置数据。如前所述，我们将比较我们的`CircularDequeue`和一个数组：

```js
var Benchmark = require("benchmark");
var suite = new Benchmark.Suite();
var CircularDequeue = require("../utils/circular-dequeue.js");

var cdQueue = new CircularDequeue();
var array = [];

for(var i=0; i < 10; i++) {
 cdQueue.push(i);
 array.push(i);
}
```

在这里，我们首先使用循环双端队列和数组中的小数据集。这将使数组变得密集，从而使 V8 引擎以快速模式运行并应用内部优化。

现在，我们可以继续并向我们的测试套件添加测试：

```js
suite
   .add("circular-queue push", function(){
 cdQueue.push(cdQueue.shift());
   })
   .add("regular array push", function(){
 array.push(array.shift());
   })
   .add("circular-queue pop", function(){
 cdQueue.pop();
   })
   .add("regular array pop", function(){
 array.pop();
   })
   .add("circular-queue unshift", function(){
 cdQueue.unshift(cdQueue.shift());
   })
   .add("regular array unshift", function(){
 array.unshift( array.shift());
   })
   .add("circular-queue shift", function(){
 cdQueue.shift();
   })
   .add("regular array shift", function(){
 array.shift();
   })
   .on("cycle", function(e) {
 console.log("" + e.target);
   })
   .run();
```

在先前的测试中需要注意的一点是，我们总是将两个操作耦合在一起，如下所示：

```js
.add("regular array push", function(){
 array.push(array.shift());
});
```

如果我们在执行`push()`方法之前不执行`shift()`方法并推送一个数字，例如`1`或`2`，那么我们将很快遇到`内存不足`错误，因为测试的迭代次数对于数组来说太大了；另一方面，循环队列将没有问题，因为它们的循环性质：它们只会覆盖先前的值。

现在，将测试添加到您的`package.json`脚本中以便更轻松地访问：

```js
"scripts": {
 "start": "node index.js",
 "test": "node tests/benchmark.js" },
```

要运行基准测试套件，请运行以下命令：

```js
npm run test
```

结果将如下：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-dsal-js/img/4ff62d71-59e1-4930-b5f4-a9cbf6bcebd6.png)

正如您可以从前面的截图中看到的，循环队列的 push 和 unshift 比本机的 push 和 unshift 操作快得多，而 pop 和 shift 操作几乎慢了 30%。

现在，让我们使数组稀疏，以便强制 V8 以字典模式运行数组方法（这对某些情况可能是真实用例，有时在处理混合数据类型的数组时也可能是可能的）：

```js
var i = 1000;

while(i--){
 cdQueue.push(i);
 array.push(i);
}
```

当我们使用稀疏数组运行类似的测试时，结果如下：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-dsal-js/img/8c009c93-8f99-491a-9b10-9c4123d53985.png)

您可以看到，性能与`push()`操作的快速模式大不相同，而其他操作基本保持不变。这是了解采用特定编码实践后果的好方法。您需要了解应用程序的要求，并相应地选择合适的工具来完成工作。

例如，当内存是优先考虑因素时，我们将使用简单队列，它可以与`WeakMap()`一起使用，而不是常规数组。我们可以创建两个新的测试，可以分开运行以跟踪它们各自的内存使用情况：

```js
suite
  .add("regular array push", function(){
 array.push(array.shift());
   })
   .on("cycle", function(e) {
 console.log("" + e.target);
 console.log(process.memoryUsage());
   })
   .run();
```

它产生了以下结果：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-dsal-js/img/6ac6574f-7e19-48e9-b6f6-3c4319db9981.png)

我们可以从前面的截图中看到，它记录了我们测试运行的结果，即 ops/sec，并记录了该周期的总内存使用情况。

类似地，我们可以对简单队列进行`remove`操作的基准测试，这与我们对 shift 操作所做的非常相似：

```js
suite
  .add("simple queue push", function(){
 simpleQueue.add(simpleQueue.remove());
   })
   .on("cycle", function(e) {
 console.log("" + e.target);
 console.log(process.memoryUsage());
   })
   .run();
```

这产生了以下结果：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-dsal-js/img/6dc01644-a555-4d2a-92ea-3cdb3c8776c0.png)

您可以看到，简单队列显然比数组慢了 4 倍，但这里重要的是要注意两种情况下的`heapUsed`。这是另一个让您决定何时以及如何选择特定类型数据结构的因素。

# 总结

至此，我们结束了关于队列的章节。我们学习了简单队列、优先级队列、循环队列以及双端队列的变体。我们还学习了何时根据使用情况应用它们，并且通过示例看到了如何利用基准测试任何算法或数据结构的能力。在下一章中，我们将对集合、映射和哈希进行深入研究，以了解它们的内部工作原理，并看看它们在哪些情况下可以发挥作用。
