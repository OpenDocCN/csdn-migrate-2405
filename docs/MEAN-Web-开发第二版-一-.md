# MEAN Web 开发第二版（一）

> 原文：[`zh.annas-archive.org/md5/F817AFC272941F1219C1F4494127A431`](https://zh.annas-archive.org/md5/F817AFC272941F1219C1F4494127A431)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

回到 1995 年春天，网络浏览器与现在的浏览器有很大不同。距离 WorldWideWeb（由 Tim Berners-Lee 编写的第一个互联网浏览器，后来更名为 Nexus）发布已经有 4 年了，距离 Mosaic 的初始发布已经有 2 年了，而 Internet Explorer 1.0 距离发布还有几个月的时间。万维网开始显示出受欢迎的迹象，尽管一些大公司对这个领域表现出了兴趣，但当时的主要颠覆者是一家名为 Netscape 的小公司。

Netscape 已经很受欢迎的浏览器 Netscape Navigator 正在制作其第二个版本，当时客户端工程团队和联合创始人 Marc Anderseen 决定 Navigator 2.0 应该嵌入一种编程语言。这项任务被分配给一位名叫 Branden Eich 的软件工程师，他在 1995 年 5 月 6 日至 5 月 15 日之间完成了这项任务，将这种语言命名为 Mocha，然后是 LiveScript，最终是 JavaScript。

Netscape Navigator 2.0 于 1995 年 9 月发布，改变了我们对网络浏览器的看法。到 1996 年 8 月，Internet Explorer 3.0 推出了自己的 JavaScript 实现，同年 11 月，Netscape 宣布他们已经向 ECMA 提交了 JavaScript 的标准化。1997 年 6 月，ECMA-262 规范发布，使 JavaScript 成为了 Web 的事实标准编程语言。

多年来，JavaScript 被许多人贬低为业余程序员的编程语言。JavaScript 的架构、分散的实现和原始的“业余”受众使专业程序员对其不屑一顾。但随后引入了 AJAX，当谷歌在 2000 年代中期发布了他们的 Gmail 和 Google Maps 应用程序时，突然间清楚地看到 AJAX 技术可以将网站转变为 Web 应用程序。这激发了新一代的 Web 开发人员将 JavaScript 开发推向新的高度。

从最初的实用库（如 jQuery 和 Prototype）开始，很快就得到了谷歌的下一个重大贡献，即 Chrome 浏览器及其于 2008 年底发布的 V8 JavaScript 引擎的推动。V8 引擎以其 JIT 编译能力大大提高了 JavaScript 的性能。这导致了 JavaScript 开发的新时代。2009 年是 JavaScript 的奇迹之年；突然间，诸如 Node.js 之类的平台使开发人员能够在服务器上运行 JavaScript，诸如 MongoDB 之类的数据库推广和简化了 JSON 存储的使用，诸如 Angular 和 React 之类的框架简化了复杂前端应用程序的创建。在其原始发布 20 多年后，JavaScript 现在无处不在。曾经是一种能够执行小脚本的“业余”编程语言，现在是世界上最流行的编程语言之一。开源协作工具的兴起，以及才华横溢的工程师的投入，创造了世界上最丰富的社区之一，许多贡献者播下的种子现在正在以纯粹的创造力迸发。

这个实际意义是巨大的。曾经是一个分散的开发团队，每个人都是自己领域的专家，现在可以成为一个能够使用单一语言跨所有层开发更精简、更敏捷软件的同质团队。

有许多全栈 JavaScript 框架，一些是由优秀团队构建的，一些解决了重要问题，但没有一个像 MEAN 堆栈那样开放和模块化。这个想法很简单，我们将 MongoDB 作为数据库，Express 作为 Web 框架，Angular 作为前端框架，Node.js 作为平台，以模块化的方式组合它们，以确保现代软件开发所需的灵活性。MEAN 的方法依赖于每个开源模块周围的社区保持其更新和稳定，确保如果其中一个模块变得无用，我们可以无缝地用更合适的模块替换它。

我想欢迎您加入 JavaScript 革命，并向您保证我会尽力帮助您成为全栈 JavaScript 开发人员。

在本书中，我们将帮助您设置您的环境，并解释如何使用最佳模块将不同的 MEAN 组件连接在一起。您将了解保持代码清晰简单的最佳实践，并学会如何避免常见陷阱。我们将逐步构建您的身份验证层并添加您的第一个实体。您将学会如何利用 JavaScript 非阻塞架构来构建服务器和客户端应用程序之间的实时通信。最后，我们将向您展示如何使用适当的测试覆盖您的代码，并向您展示自动化开发流程中使用的工具。

# 本书涵盖内容

第一章，“MEAN 简介”，向您介绍了 MEAN 堆栈，并向您展示了如何在每个操作系统上安装不同的先决条件。

第二章，“Node.js 入门”，解释了 Node.js 的基础知识以及它在 Web 应用程序开发中的使用。

第三章，“构建 Express Web 应用程序”，解释了如何通过实现 MVC 模式来创建和构建 Express 应用程序。

第四章，“MongoDB 简介”，解释了 MongoDB 的基础知识以及如何用它来存储应用程序的数据。

第五章，“Mongoose 简介”，展示了如何使用 Mongoose 将 Express 应用程序与 MongoDB 数据库连接起来。

第六章，“使用 Passport 管理用户身份验证”，解释了如何管理用户的身份验证并为他们提供不同的登录选项。

第七章，“Angular 简介”，解释了如何在 Express 应用程序中实现 Angular 应用程序。

第八章，“创建 MEAN CRUD 模块”，解释了如何编写和使用 MEAN 应用程序的实体。

第九章，“使用 Socket.io 添加实时功能”，向您展示了如何在客户端和服务器之间创建和使用实时通信。

第十章，“测试 MEAN 应用”，解释了如何自动测试 MEAN 应用的不同部分。

第十一章，“MEAN 应用的自动化和调试”，解释了如何更高效地开发 MEAN 应用程序。

# 您需要为本书做好准备

本书适合具有 HTML、CSS 和现代 JavaScript 开发基础知识的初学者和中级 Web 开发人员。

# 本书的受众

本书面向有兴趣学习如何使用 MongoDB、Express、Angular 和 Node.js 构建现代 Web 应用程序的 Web 开发人员。

# 约定

在本书中，您将找到一些文本样式，用于区分不同类型的信息。以下是这些样式的一些示例及其含义的解释。

文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下：“要测试您的静态中间件，请将名为`logo.png`的图像添加到`public/img`文件夹中。”

代码块设置如下：

```js
const message = 'Hello World';

exports.sayHello = function() {
  console.log(message);
}
```

当我们希望引起您对代码块的特定部分的注意时，相关的行或项目将以粗体显示：

```js
const express = require('express');
const app = express();

app.listen(3000);

console.log('Server running at http://localhost:3000/');
```

任何命令行输入或输出都以以下方式编写：

```js
$ npm start

```

**新术语**和**重要单词**以粗体显示。屏幕上显示的单词，例如菜单或对话框中的单词，会在文本中以这种方式出现：“一旦您点击**下一步**按钮，安装应该开始。”

### 注意

警告或重要提示会以这种方式出现在框中。

### 提示

提示和技巧会以这种方式出现。


# 第一章：MEAN 简介

MEAN 堆栈是一个强大的全栈 JavaScript 解决方案，由四个主要构建模块组成：MongoDB 作为数据库，Express 作为 Web 服务器框架，Angular 作为 Web 客户端框架，Node.js 作为服务器平台。这些构建模块由不同的团队开发，并涉及一个庞大的开发人员和倡导者社区，推动每个组件的开发和文档化。该堆栈的主要优势在于将 JavaScript 作为主要编程语言。然而，连接这些工具的问题可能为扩展和架构问题奠定基础，这可能会严重影响您的开发过程。

在本书中，我将尝试介绍构建 MEAN 应用程序的最佳实践和已知问题，但在您开始实际的 MEAN 开发之前，您首先需要设置您的环境。本章将涵盖一些编程概述，但主要介绍安装 MEAN 应用程序的基本先决条件的正确方法。通过本章的学习，您将了解如何在所有常见操作系统上安装和配置 MongoDB 和 Node.js 以及如何使用 NPM。在本章中，我们将涵盖以下主题：

+   MEAN 堆栈架构简介

+   在 Windows、Linux 和 Mac OS X 上安装和运行 MongoDB

+   在 Windows、Linux 和 Mac OS X 上安装和运行 Node.js

+   npm 简介及如何使用它安装 Node 模块

# 三层 Web 应用程序开发

大多数 Web 应用程序都是建立在三层架构上的，包括三个重要的层：数据、逻辑和呈现。在 Web 应用程序中，应用程序结构通常分解为数据库、服务器和客户端，而在现代 Web 开发中，它也可以分解为数据库、服务器逻辑、客户端逻辑和客户端 UI。

实现这种模型的一种流行范式是**模型-视图-控制器**（**MVC**）架构模式。在 MVC 范式中，逻辑、数据和可视化被分为三种类型的对象，每个对象处理自己的任务。**视图**处理视觉部分，负责用户交互。**控制器**响应系统和用户事件，命令模型和视图适当地进行更改。**模型**处理数据操作，响应对信息的请求或根据控制器的指示改变其状态。MVC 架构的简单可视化表示如下图所示：

![三层 Web 应用程序开发](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mean-webdev-2e/img/B05071_01_01.jpg)

常见的 MVC 架构通信

在 Web 开发的 25 年中，许多技术堆栈变得流行，用于构建三层 Web 应用程序。在那些现在无处不在的堆栈中，你可以找到 LAMP 堆栈、.NET 堆栈和丰富多样的其他框架和工具。这些堆栈的主要问题是，每个层都需要一个知识库，通常超出了单个开发人员的能力范围，使团队比他们应该的更大，生产力更低，面临意外风险。

# JavaScript 的演变

JavaScript 是一种为 Web 开发而构建的解释性计算机编程语言。最初由 Netscape Navigator 网络浏览器实现，它成为 Web 浏览器用于执行客户端逻辑的编程语言。在 2000 年代中期，从网站向 Web 应用程序的转变，以及更快的浏览器的发布，逐渐形成了一个编写更复杂应用程序的 JavaScript 开发人员社区。这些开发人员开始创建缩短开发周期的库和工具，催生了一代更先进的 Web 应用程序。他们反过来创造了对更好浏览器的持续需求。这个循环持续了几年，供应商不断改进他们的浏览器，JavaScript 开发人员不断推动边界。

真正的革命始于 2008 年，当谷歌发布了其 Chrome 浏览器，以及其快速的 JIT 编译 V8 JavaScript 引擎。谷歌的 V8 引擎使 JavaScript 运行速度大大加快，完全改变了 Web 应用程序开发。更重要的是，引擎源代码的发布使开发人员开始重新构想浏览器之外的 JavaScript。这场革命的第一个产物之一就是 Node.js。

在研究了一段时间其他选项之后，程序员 Ryan Dahl 发现 V8 引擎非常适合他的非阻塞 I/O 实验，称为 Node.js。这个想法很简单：帮助开发人员构建非阻塞的代码单元，以更好地利用系统资源并创建更具响应性的应用程序。结果是一个简洁而强大的平台，利用了 JavaScript 在浏览器之外的非阻塞特性。Node 的优雅模块系统使开发人员可以自由地使用第三方模块来扩展平台，实现几乎任何功能。在线社区的反应是创建了各种工具，从现代 Web 框架到机器人服务器平台。然而，服务器端 JavaScript 只是一个开始。

当 Dwight Merriman 和 Eliot Horowitz 在 2007 年开始构建可扩展的托管解决方案时，他们已经在构建 Web 应用程序方面有了很多经验。然而，他们构建的平台并没有按计划成功，因此在 2009 年，他们决定拆开它，并开源其组件，包括一个名为 MongoDB 的基于 V8 的数据库。MongoDB 源自“巨大”的单词，是一个可扩展的 NoSQL 数据库，使用动态模式的类 JSON 数据模型。MongoDB 立即获得了很多关注，因为它为开发人员提供了处理复杂数据时所需的灵活性，同时提供了高级查询和易于扩展的 RDBMS 功能，这些功能最终使 MongoDB 成为领先的 NoSQL 解决方案之一。JavaScript 打破了另一个界限。然而，JavaScript 革命者并没有忘记一切的起源。事实上，现代浏览器的普及创造了 JavaScript 前端框架的新浪潮。

回到 2009 年，当 Miško Hevery 和 Adam Abrons 在构建他们的 JSON 作为平台服务时，他们注意到常见的 JavaScript 库并不够用。他们丰富的 Web 应用程序的性质引发了对更有结构的框架的需求，这将减少繁重的工作并保持有组织的代码库。他们放弃了最初的想法，决定专注于开发他们的前端框架，并开源了该项目，命名为 AngularJS。这个想法是为了弥合 JavaScript 和 HTML 之间的差距，并帮助推广单页应用程序的开发。

结果是一个丰富的 Web 框架，为前端 Web 开发人员提供了诸如双向数据绑定、跨组件依赖注入和基于 MVC 的组件等概念。Angular，以及其他现代框架，通过将曾经难以维护的前端代码库转变为可以支持更高级开发范式的结构化代码库，彻底改变了 Web 开发。

开源协作工具的兴起，以及这些才华横溢的工程师的投入，创造了世界上最丰富的社区之一。更重要的是，这些重大进步使得三层 Web 应用程序的开发能够在 JavaScript 的统一编程语言下进行——这个想法通常被称为全栈 JavaScript。MEAN 堆栈就是这个想法的一个例子。

# ECMAScript 2015 介绍

经过多年的工作，ES6 规范于 2015 年 6 月发布。它提出了自 ES5 以来 JavaScript 最大的进步，并在语言中引入了几个功能，将彻底改变我们 JavaScript 开发人员编写代码的方式。描述 ES2015 所做的所有改进是雄心勃勃的。相反，让我们试着通过我们将在下一章中使用的基本功能来工作。

## 模块

模块现在是一种受支持的语言级特性。它允许开发人员将其组件包装在模块模式中，并在其代码中导出和导入模块。实现与前几章描述的 CommonJS 模块实现非常相似，尽管 ES2015 模块还支持异步加载。处理 ES2015 模块的基本关键字是`export`和`import`。让我们看一个简单的例子。假设您有一个名为`lib.js`的文件，其中包含以下代码：

```js
export function halfOf(x) {
    return x / 2;
}
```

因此，在您的`main.js`文件中，您可以使用以下代码：

```js
import halfOf from 'lib';
console.log(halfOf(84));
```

然而，模块可能更有趣。例如，假设我们的`lib.js`文件看起来像这样：

```js
export function halfOf(x) {
    return x / 2;
}
export function multiply(x, y) {
    return x * y;
}
```

在您的主文件中，使用以下代码：

```js
import {halfOf, multiply} from 'lib';
console.log(halfOf(84));
console.log(multiply(21, 2));
```

ES2015 模块还支持默认的`export`值。因此，例如，假设您有一个名为`doSomething.js`的文件，其中包含以下代码：

```js
export default function () { 
    console.log('I did something')
};
```

您可以在`main.js`文件中如下使用它：

```js
import doSomething from 'doSomething';
doSomething();
```

重要的是要记住，默认导入应该使用模块名称标识其实体。

另一件重要的事情要记住的是，模块导出绑定而不是值。因此，例如，假设您有一个名为`validator.js`的文件，看起来像这样：

```js
export let flag = false;
export function touch() {
    flag = true;
}
```

您还有一个名为`main.js`的文件，看起来像这样：

```js
import { flag, touch } from 'validator';
console.log(flag); 
touch();
console.log(flag); 
```

第一个输出将是`false`，第二个将是`true`。现在我们对模块有了基本的了解，让我们转到类。

## 类

关于类与原型的长期辩论得出结论，即 ES2015 中的类基本上只是基于原型的继承的一种语法糖。类是易于使用的模式，支持实例和静态成员、构造函数和 super 调用。这里有一个例子：

```js
class Vehicle {
    constructor(wheels) {
        this.wheels = wheels;
    }
    toString() {
        return '(' + this.wheels + ')';
    }
}

class Car extends Vehicle {
    constructor(color) {
        super(4);
        this.color = color;
    }
    toString() {
        return super.toString() + ' colored:  ' + this.color;
    }
}

let car = new Car('blue');
car.toString(); 

console.log(car instanceof Car); 
console.log(car instanceof Vehicle); 
```

在这个例子中，`Car`类扩展了`Vehicle`类。因此，输出如下：

```js
 (4) in blue
true
true
```

## 箭头函数

箭头函数是`=>`语法的函数简写。对于熟悉其他语言如 C#和 Java 8 的人来说，它们可能看起来很熟悉。然而，箭头函数也非常有帮助，因为它们与其作用域共享相同的词法`this`。它们主要以两种形式使用。一种是使用表达式体：

```js
const squares = numbers.map(n => n * n); 
```

另一种形式是使用语句体：

```js
numbers.forEach(n => {
  if (n % 2 === 0) evens.push(n);
});
```

使用共享词法的一个例子是：

```js
const author = {
  fullName: "Bob Alice",
  books: [],
  printBooks() {
     this.books.forEach(book => console.log(book + ' by ' + this.fullName));
  }
};
```

如果作为常规函数使用，`this`将是`book`对象，而不是`author`。

## Let 和 Const

`Let`和`Const`是用于符号声明的新关键字。`Let`几乎与`var`关键字相同，因此它的行为与全局和函数变量相同。但是，在块内部，`let`的行为不同。例如，看下面的代码：

```js
function iterateVar() {
  for(var i = 0; i < 10; i++) {
    console.log(i);
  }

  console.log(i)
}

function iterateLet() {
  for(let i = 0; i < 10; i++) {
    console.log(i);
  }

  console.log(i)
}
```

第一个函数将在循环后打印`i`，但第二个函数将抛出错误，因为`i`是由`let`定义的。

`const`关键字强制单一赋值。因此，这段代码也会抛出错误：

```js
const me = 1
me = 2
```

## 默认、Rest 和 Spread

默认、Rest 和 Spread 是与函数参数相关的三个新功能。默认功能允许您为函数参数设置默认值：

```js
function add(x, y = 0) {
    return x + y;
}
add(1) 
add(1,2)
```

在这个例子中，如果没有传递值或设置为`undefined`，`y`的值将设置为`0`。

Rest 功能允许您将数组作为尾随参数传递，如下所示：

```js
function userFriends(user, ...friends) {
  console.log(user + ' has ' + friends.length + ' friends');
}
userFriends('User', 'Bob', 'Alice');
```

Spread 功能将数组转换为调用参数：

```js
function userTopFriends(firstFriend, secondFriend, thirdFriends) {
  console.log(firstFriend);
  console.log(secondFriend);
  console.log(thirdFriends);
}

userTopFriends(...['Alice', 'Bob', 'Michelle']);
```

## 总结

进入现代 Web 开发，ES2015 将成为您日常编程会话的一个可行部分。这里显示的只是冰山一角，强烈建议您继续深入研究。但是，对于本书的目的，这就足够了。

# 介绍 MEAN

MEAN 是 MongoDB、Express、Angular 和 Node.js 的缩写。其背后的概念是只使用 JavaScript 驱动的解决方案来覆盖应用程序的不同部分。其优势很大，如下所示：

+   整个应用程序只使用一种语言

+   应用程序的所有部分都可以支持并经常强制使用 MVC 架构

+   不再需要数据结构的序列化和反序列化，因为数据编组是使用 JSON 对象完成的

然而，仍有一些重要的问题尚未解答：

+   如何将所有组件连接在一起？

+   Node.js 有一个庞大的模块生态系统，那么你应该使用哪些模块？

+   JavaScript 是范式不可知的，那么你如何维护 MVC 应用程序结构？

+   JSON 是一种无模式的数据结构，那么你应该如何以及何时对你的数据进行建模？

+   如何处理用户认证？

+   如何使用 Node.js 的非阻塞架构来支持实时交互？

+   如何测试你的 MEAN 应用程序代码库？

+   考虑到 DevOps 和 CI 的兴起，你可以使用哪些 JavaScript 开发工具来加快 MEAN 应用程序的开发过程？

在本书中，我将尝试回答这些问题和更多。但是，在我们继续之前，你首先需要安装基本的先决条件。

# 安装 MongoDB

对于 MongoDB 的稳定版本，官方 MongoDB 网站提供了链接的二进制文件，为 Linux、Mac OS X 和 Windows 提供了安装 MongoDB 的最简单方式。请注意，你需要根据你的操作系统下载正确的架构版本。如果你使用 Windows 或 Linux，请确保根据你的系统架构下载 32 位或 64 位版本。Mac 用户可以安全地下载 64 位版本。

### 注意

MongoDB 的版本方案是这样工作的，只有偶数版本号标记稳定版本。因此，版本 3.0.x 和 3.2x 是稳定的，而 2.9.x 和 3.1.x 是不稳定的版本，不应该在生产中使用。MongoDB 的最新稳定版本是 3.2.x。

当你访问[`mongodb.org/downloads`](http://mongodb.org/downloads)下载页面时，你将得到一个包含安装 MongoDB 所需二进制文件的存档文件的下载。下载并提取存档文件后，你需要找到`mongod`二进制文件，通常位于`bin`文件夹中。`mongod`进程运行主 MongoDB 服务器进程，可以用作独立服务器或 MongoDB 副本集的单个节点。在我们的情况下，我们将使用 MongoDB 作为独立服务器。`mongod`进程需要一个文件夹来存储数据库文件（默认文件夹是`/data/db`）和一个要监听的端口（默认端口是`27017`）。在接下来的小节中，我们将介绍每个操作系统的设置步骤。我们将从常见的 Windows 安装过程开始。

### 注意

建议你通过访问官方文档[`mongodb.org`](https://mongodb.org)来更多了解 MongoDB。

## 在 Windows 上安装 MongoDB

下载正确的版本后，运行`.msi`文件。MongoDB 应该安装在`C:\Program Files\MongoDB\`文件夹中。在运行时，MongoDB 使用默认文件夹来存储其数据文件。在 Windows 上，默认文件夹位置是`C:\data\db`。因此，在命令提示符中，转到`C:\`并输入以下命令：

```js
> md c:\data\db

```

### 提示

你可以告诉 mongod 服务使用`--dbpath`命令行标志来使用替代路径的数据文件。

创建完数据文件夹后，在运行主 MongoDB 服务时会得到两个选项。

### 手动运行 MongoDB

要手动运行 MongoDB，你需要运行`mongod`二进制文件。因此，打开命令提示符并导航到`C:\Program Files\MongoDB\Server\3.2\bin`文件夹。然后，输入以下命令：

```js
C:\Program Files\MongoDB\Server\3.2\bin> mongod

```

上述命令将运行主 MongoDB 服务，该服务将开始监听默认的`27017`端口。如果一切顺利，您应该看到类似以下截图的控制台输出：

![手动运行 MongoDB](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mean-webdev-2e/img/B05071_01_02.jpg)

在 Windows 上运行 MongoDB 服务器

根据 Windows 安全级别，可能会发出安全警报对话框，通知您有关某些服务功能的阻止。如果发生这种情况，请选择私人网络，然后单击**允许访问**。

### 注意

您应该知道，MongoDB 服务是自包含的，因此您也可以选择从任何文件夹运行它。

### 将 MongoDB 作为 Windows 服务运行

更流行的方法是在每次重启后自动运行 MongoDB。在将 MongoDB 设置为 Windows 服务之前，最好指定 MongoDB 日志和配置文件的路径。首先在命令提示符中运行以下命令创建这些文件的文件夹：

```js
> md C:\data\log

```

然后，您需要在`C:\Program Files\MongoDB\Server\3.2\mongod.cfg`创建一个包含以下内容的配置文件：

```js
systemLog:
    destination: file
    path: c:\data\log\mongod.log
storage:
    dbPath: c:\data\db
```

当您的配置文件就位时，请通过右键单击命令提示符图标并单击**以管理员身份运行**来打开具有管理员权限的新命令提示符窗口。请注意，如果已经运行较旧版本的 MongoDB 服务，您首先需要使用以下命令将其删除：

```js
> sc stop MongoDB
> sc delete MongoDB

```

然后，通过运行以下命令安装 MongoDB 服务：

```js
> "C:\Program Files\MongoDB\Server\3.2\bin\mongod.exe" --config "C:\Program Files\MongoDB\Server\3.2\mongod.cfg" --install

```

请注意，只有在正确设置配置文件时，安装过程才会成功。安装 MongoDB 服务后，您可以通过在管理命令提示符窗口中执行以下命令来运行它：

```js
> net start MongoDB

```

请注意，MongoDB 配置文件可以修改以适应您的需求。您可以通过访问[`docs.mongodb.org/manual/reference/configuration-options/`](http://docs.mongodb.org/manual/reference/configuration-options/)了解更多信息。

## 在 Mac OS X 和 Linux 上安装 MongoDB

在本节中，您将学习在基于 Unix 的操作系统上安装 MongoDB 的不同方法。让我们从最简单的安装 MongoDB 的方式开始，这涉及下载 MongoDB 的预编译二进制文件。

## 从二进制文件安装 MongoDB

您可以通过访问[`www.mongodb.org/downloads`](http://www.mongodb.org/downloads)的下载页面下载正确版本的 MongoDB。或者，您可以通过执行以下命令使用 CURL 来执行此操作：

```js
$ curl -O http://downloads.mongodb.org/osx/mongodb-osx-x86_64-3.2.10.tgz

```

请注意，我们已经下载了 Mac OS X 64 位版本，因此请确保修改命令以适合您的机器版本。下载过程结束后，请通过在命令行工具中发出以下命令解压文件：

```js
$ tar -zxvf mongodb-osx-x86_64-3.2.10.tgz

```

现在，通过运行以下命令将提取的文件夹更改为更简单的文件夹名称：

```js
$ mv mongodb-osx-x86_64-3.2.10 mongodb

```

MongoDB 使用默认文件夹来存储其文件。在 Linux 和 Mac OS X 上，默认位置是`/data/db`，所以在命令行工具中运行以下命令：

```js
$ mkdir -p /data/db

```

### 提示

您可能会在创建此文件夹时遇到一些问题。这通常是权限问题，因此在运行上述命令时，请使用`sudo`或超级用户。

上述命令将创建`data`和`db`文件夹，因为`-p`标志也会创建父文件夹。请注意，默认文件夹位于您的主文件夹外部，因此请确保通过运行以下命令设置文件夹权限：

```js
$ chown -R $USER /data/db

```

现在您已经准备好了，使用命令行工具并转到`bin`文件夹以运行`mongod`服务，如下所示：

```js
$ cd mongodb/bin
$ mongod

```

这将运行主 MongoDB 服务，它将开始监听默认的`27017`端口。如果一切顺利，您应该看到类似以下截图的控制台输出：

![从二进制文件安装 MongoDB](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mean-webdev-2e/img/B05071_01_03.jpg)

在 Mac OS X 上运行 MongoDB 服务器

### 使用软件包管理器安装 MongoDB

有时，安装 MongoDB 的最简单方法是使用软件包管理器。缺点是一些软件包管理器在支持最新版本方面落后。幸运的是，MongoDB 团队还维护了 RedHat、Debian 和 Ubuntu 的官方软件包，以及 Mac OS X 的 Homebrew 软件包。请注意，您需要配置软件包管理器存储库以包括 MongoDB 服务器以下载官方软件包。

要在 Red Hat Enterprise、CentOS 或 Fedora 上使用 Yum 安装 MongoDB，请按照[`docs.mongodb.org/manual/tutorial/install-mongodb-on-red-hat-centos-or-fedora-linux/`](http://docs.mongodb.org/manual/tutorial/install-mongodb-on-red-hat-centos-or-fedora-linux/)上的说明进行操作。

要在 Ubuntu 上使用 APT 安装 MongoDB，请按照[`docs.mongodb.org/manual/tutorial/install-mongodb-on-ubuntu/`](http://docs.mongodb.org/manual/tutorial/install-mongodb-on-ubuntu/)上的说明进行操作。

要在 Debian 上使用 APT 安装 MongoDB，请按照[`docs.mongodb.org/manual/tutorial/install-mongodb-on-debian/`](http://docs.mongodb.org/manual/tutorial/install-mongodb-on-debian/)上的说明进行操作。

在 Mac OS X 上使用 Homebrew 安装 MongoDB，请按照[`docs.mongodb.org/manual/tutorial/install-mongodb-on-os-x/`](http://docs.mongodb.org/manual/tutorial/install-mongodb-on-os-x/)上的说明进行操作。

## 使用 MongoDB shell

MongoDB 存档文件包括 MongoDB shell，它允许您使用命令行与服务器实例进行交互。要启动 shell，请转到 MongoDB `bin`文件夹，并运行以下`mongo`服务：

```js
$ cd mongodb/bin
$ mongo

```

如果成功安装了 MongoDB，shell 将自动连接到您的本地实例，使用测试数据库。您应该看到类似以下屏幕截图的控制台输出：

使用 MongoDB shell

在 Mac OS X 上运行 MongoDB shell

要测试您的数据库，请运行以下命令：

```js
> db.articles.insert({title: "Hello World"})

```

上述命令将创建一个新的文章集合，并插入一个包含`title`属性的 JSON 对象。要检索文章对象，请执行以下命令：

```js
> db.articles.find()

```

控制台将输出类似以下消息的文本：

```js
{ _id: ObjectId("52d02240e4b01d67d71ad577"), title: "Hello World" }

```

恭喜！这意味着您的 MongoDB 实例正常工作，并且您已成功使用 MongoDB shell 与其进行交互。在接下来的章节中，您将了解更多关于 MongoDB 以及如何使用 MongoDB shell 的知识。

# 安装 Node.js

对于稳定版本，官方 Node.js 网站提供了链接的二进制文件，为 Linux、Mac OS X 和 Windows 提供了安装 Node.js 的最简单方法。请注意，您需要为您的操作系统下载正确的架构版本。如果您使用 Windows 或 Linux，请确保根据您的系统架构下载 32 位或 64 位版本。Mac 用户可以安全地下载 64 位版本。

### 注意

在 Node.js 和 io.js 项目合并后，版本方案直接从 0.12.x 继续到 4.x。团队现在使用**长期支持**（**LTS**）政策。您可以在[`en.wikipedia.org/wiki/Long-term_support`](https://en.wikipedia.org/wiki/Long-term_support)上了解更多信息。Node.js 的最新稳定版本是 6.x。

## 在 Windows 上安装 Node.js

在 Windows 机器上安装 Node.js 是一项简单的任务，可以使用独立安装程序轻松完成。首先，转到[`nodejs.org/en/download/`](https://nodejs.org/en/download/)并下载正确的`.msi`文件。请注意有 32 位和 64 位版本，因此请确保为您的系统下载正确的版本。

下载安装程序后，运行它。如果出现任何安全对话框，只需单击**运行**按钮，安装向导应该会启动。您将看到类似以下屏幕截图的安装屏幕：

![在 Windows 上安装 Node.js](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mean-webdev-2e/img/B05071_01_05.jpg)

Node.js Windows 安装向导

一旦点击**下一步**按钮，安装将开始。几分钟后，您将看到一个类似以下截图的确认屏幕，告诉您 Node.js 已成功安装：

![在 Windows 上安装 Node.js](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mean-webdev-2e/img/B05071_01_06.jpg)

Node.js 在 Windows 上的安装确认

## 在 Mac OS X 上安装 Node.js

在 Mac OS X 上安装 Node.js 是一个简单的任务，可以使用独立安装程序轻松完成。首先转到[`nodejs.org/en/download/`](https://nodejs.org/en/download/)页面并下载`.pkg`文件。下载安装程序后，运行它，您将看到一个类似以下截图的安装屏幕：

![在 Mac OS X 上安装 Node.js](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mean-webdev-2e/img/B05071_01_07.jpg)

Node.js 在 Mac OS X 上的安装向导

点击**继续**，安装过程应该开始。安装程序将要求您确认许可协议，然后要求您选择文件夹目标。在再次点击**继续**按钮之前，选择最适合您的选项。然后安装程序将要求您确认安装信息，并要求您输入用户密码。几分钟后，您将看到一个类似于以下截图的确认屏幕，告诉您 Node.js 已成功安装：

![在 Mac OS X 上安装 Node.js](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mean-webdev-2e/img/B05071_01_08.jpg)

Node.js 在 Mac OS X 上的安装确认

## 在 Linux 上安装 Node.js

要在 Linux 机器上安装 Node.js，您需要使用官方网站上的 tarball 文件。最好的方法是下载最新版本，然后使用`make`命令构建和安装源代码。首先转到[`nodejs.org/en/download/`](http://nodejs.org/en/download/)页面，下载适合的`.tar.gz`文件。然后，通过以下命令扩展文件并安装 Node.js：

```js
$ tar -zxf node-v6.9.1.tar.gz
$ cd node-v6.9.1
$ ./configure && make && sudo make install

```

如果一切顺利，这些命令将在您的机器上安装 Node.js。请注意，这些命令适用于 Node.js 6.9.1 版本，所以请记得用您下载的版本替换版本号。

### 注意

建议您通过访问官方文档[`nodejs.org`](https://nodejs.org)来了解更多关于 Node.js 的信息。

## 运行 Node.js

安装成功后，您将能够使用提供的命令行界面（CLI）开始尝试使用 Node.js。转到命令行工具并执行以下命令：

```js
$ node

```

这将启动 Node.js CLI，它将等待 JavaScript 输入。要测试安装，请运行以下命令：

```js
> console.log('Node is up and running!');

```

输出应该类似于以下内容：

```js
Node is up and running!
undefined

```

这很好，但您还应该尝试执行一个 JavaScript 文件。首先创建一个名为`application.js`的文件，其中包含以下代码：

```js
console.log('Node is up and running!');

```

要运行它，您需要通过以下命令将文件名作为第一个参数传递给 Node CLI：

```js
$ node application.js
Node is up and running!

```

恭喜！您刚刚创建了您的第一个 Node.js 应用程序。要停止 CLI，请按*CTRL* + *D*或*CTRL* + *C*。

# 介绍 npm

Node.js 是一个平台，这意味着它的功能和 API 被保持在最低限度。为了实现更复杂的功能，它使用了一个模块系统，允许您扩展平台。安装、更新和删除 Node.js 模块的最佳方式是使用 npm。npm 主要用途包括：

+   用于浏览、下载和安装第三方模块的包注册表

+   用于管理本地和全局包的 CLI 工具

方便的是，npm 是在 Node.js 安装过程中安装的，所以让我们快速开始学习如何使用它。

## 使用 npm

为了了解 npm 的工作原理，我们将安装 Express web 框架模块，这将在接下来的章节中使用。npm 是一个强大的包管理器，它为公共模块保持了一个集中的注册表。要浏览可用的公共包，请访问官方网站[`www.npmjs.com/`](https://www.npmjs.com)。

注册表中的大多数包都是开源的，由 Node.js 社区开发者贡献。在开发开源模块时，包的作者可以决定将其发布到中央注册表，允许其他开发者下载并在他们的项目中使用它。在包配置文件中，作者将选择一个名称，以后将用作下载该包的唯一标识符。

### 注意

建议你通过访问官方文档[`docs.npmjs.com`](https://docs.npmjs.com)来学习更多关于 Node.js 的知识。

### npm 的安装过程

重要的是要记住，npm 有两种安装模式：本地和全局。默认的本地模式经常被使用，并且会将第三方包安装在本地的`node_modules`文件夹中，放在应用程序文件夹内。它不会对系统产生影响，并且用于安装应用程序需要的包，而不会用不必要的全局文件污染系统。

全局模式用于安装你想要 Node.js 全局使用的包。通常，这些是 CLI 工具，比如 Grunt，在接下来的章节中你会学到。大多数情况下，包的作者会明确指示你全局安装包。因此，当有疑问时，请使用本地模式。全局模式通常会将包安装在 Unix 系统的`/usr/local/lib/node_modules`文件夹中，以及 Windows 系统的`C:\Users\%USERNAME%\AppData\Roaming\npm\node_modules`文件夹中，使其对系统上运行的任何 Node.js 应用程序可用。

#### 使用 npm 安装一个包

一旦找到合适的包，你就可以使用`npm install`命令进行安装，如下所示：

```js
$ npm install <Package Unique Name>

```

全局安装模块与本地安装模块类似，但你需要添加`-g`标志，如下所示：

```js
$ npm install –g <Package Unique Name>

```

### 注意

你可能会发现你的用户没有权限全局安装包，所以你需要使用 root 用户或使用 sudo 进行安装。

例如，要在本地安装 Express，你需要导航到你的应用程序文件夹，并发出以下命令：

```js
$ npm install express

```

上述命令将在本地的`node_modules`文件夹中安装 Express 包的最新稳定版本。此外，npm 支持广泛的语义版本。因此，要安装一个特定版本的包，你可以使用`npm install`命令，如下所示：

```js
$ npm install <Package Unique Name>@<Package Version>

```

例如，要安装 Express 包的第二个主要版本，你需要发出以下命令：

```js
$ npm install express@2.x 

```

这将安装 Express 2 的最新稳定版本。请注意，这种语法使 npm 能够下载并安装 Express 2 的任何次要版本。要了解更多关于支持的语义版本语法，请访问[`github.com/npm/node-semver`](https://github.com/npm/node-semver)。

当一个包有依赖关系时，npm 会自动解析这些依赖关系，在`package`文件夹内的`node_modules`文件夹中安装所需的包。在前面的例子中，Express 的依赖关系将安装在`node_modules/express/node_modules`下。

#### 使用 npm 移除一个包

要移除一个已安装的包，你需要导航到你的应用程序文件夹，并运行以下命令：

```js
$ npm uninstall < Package Unique Name>

```

npm 然后会寻找这个包，并尝试从本地的`node_modules`文件夹中移除它。要移除一个全局包，你需要使用`-g`标志，如下所示：

```js
$ npm uninstall –g < Package Unique Name>

```

#### 使用 npm 更新一个包

要将一个包更新到最新版本，发出以下命令：

```js
$ npm update < Package Unique Name>

```

npm 会下载并安装这个包的最新版本，即使它还不存在。要更新一个全局包，使用以下命令：

```js
$ npm update –g < Package Unique Name>

```

### 使用 package.json 文件管理依赖关系

安装单个包很好，但很快，您的应用程序将需要使用多个包。因此，您需要一种更好的方法来管理这些依赖关系。为此，npm 允许您在应用程序的根文件夹中使用名为`package.json`的配置文件。在`package.json`文件中，您将能够定义应用程序的各种元数据属性，包括应用程序的名称、版本和作者等属性。这也是您定义应用程序依赖关系的地方。

`package.json`文件基本上是一个 JSON 文件，其中包含了描述应用程序属性所需的不同属性。使用最新的 Express 和 Grunt 包的应用程序将具有以下`package.json`文件：

```js
{
  "name" : "MEAN",
  "version" : "0.0.1",
  "dependencies" : {
    "express" : "latest",
    "grunt" : "latest"
  }
}
```

### 注意

您的应用程序名称和版本属性是必需的，因此删除这些属性将阻止 npm 正常工作。

#### 创建 package.json 文件

虽然您可以手动创建`package.json`文件，但更简单的方法是使用`npm init`命令。要这样做，使用命令行工具并发出以下命令：

```js
$ npm init

```

npm 会询问您关于您的应用程序的一些问题，并将自动为您创建一个新的`package.json`文件。示例过程应该类似于以下截图：

![创建 package.json 文件](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mean-webdev-2e/img/B05071_01_09.jpg)

在 Mac OS X 上使用`npm init`

创建`package.json`文件后，您需要修改它并添加一个`dependencies`属性。您的最终`package.json`文件应该如下代码片段所示：

```js
{
  "name": "mean",
  "version": "0.0.1",
  "description": "My First MEAN Application",
  "main": "server.js",
  "directories": {
    "test": "test"
  },
  "scripts": {
    "test": "echo \"Error: no test specified\" && exit 1"
  },
  "keywords": [
    "MongoDB",
    "Express",
    "Angular",
    "Node.js"
  ],
  "author": "Amos Haviv",
  "license": "MIT",
  "dependencies": {
    "express": "latest",
    "grunt": "latest"
  }
}
```

### 注意

在上述代码示例中，我们使用了`latest`关键字告诉 npm 安装这些包的最新版本。然而，强烈建议您使用特定的版本号或范围，以防止您的应用程序依赖关系在开发周期中发生变化。这是因为新的包版本可能与旧版本不兼容，这将导致应用程序出现重大问题。

#### 安装 package.json 的依赖项

创建`package.json`文件后，您可以通过转到应用程序的根文件夹并使用`npm install`命令来安装应用程序的依赖项，如下所示：

```js
$ npm install

```

npm 将自动检测您的`package.json`文件并安装所有应用程序的依赖项，将它们放在本地的`node_modules`文件夹下。安装依赖项的另一种方法，有时更好的方法是使用以下`npm update`命令：

```js
$ npm update

```

这将安装任何缺少的包，并将更新所有现有依赖项到它们指定的版本。

#### 更新 package.json 文件

`npm install`命令的另一个强大功能是能够安装新包并将包信息保存为`package.json`文件中的依赖项。在安装特定包时，可以使用`--save`可选标志来实现这一点。例如，要安装最新版本的 Express 并将其保存为依赖项，只需使用以下命令：

```js
$ npm install express --save

```

npm 将安装 Express 的最新版本，并将 Express 包添加为`package.json`文件的依赖项。为了清晰起见，在接下来的章节中，我们更喜欢手动编辑`package.json`文件。然而，这个有用的功能在您的日常开发周期中可能非常方便。

### 注意

建议您通过访问官方文档[`docs.npmjs.com/files/package.json`](https://docs.npmjs.com/files/package.json)了解更多关于 npm 庞大的配置选项。

# 摘要

在本章中，您学习了如何安装 MongoDB 以及如何使用 MongoDB shell 连接到本地数据库实例。您还学习了如何安装 Node.js 并使用 Node.js CLI。您了解了 npm 并发现了如何使用它来下载和安装 Node.js 包。您还学习了如何使用`package.json`文件轻松管理应用程序的依赖关系。

在下一章中，我们将讨论一些 Node.js 基础知识，您将构建您的第一个 Node.js Web 应用程序。


# 第二章：开始使用 Node.js

在上一章中，您设置了您的环境并发现了 Node.js 的基本开发原则。本章将介绍构建您的第一个 Node.js Web 应用程序的正确方法。您将学习 JavaScript 事件驱动的基础知识以及如何利用它来构建 Node.js 应用程序。您还将了解 Node.js 模块系统以及如何构建您的第一个 Node.js Web 应用程序。然后，您将继续学习 Connect 模块，并了解其强大的中间件方法。在本章结束时，您将知道如何使用 Connect 和 Node.js 构建简单而强大的 Web 应用程序。在本章中，我们将涵盖以下主题：

+   Node.js 介绍

+   JavaScript 闭包和事件驱动编程

+   Node.js 事件驱动的 Web 开发

+   CommonJS 模块和 Node.js 模块系统

+   Connect Web 框架介绍

+   Connect 的中间件模式

# Node.js 介绍

在 2009 年的 JSConf EU 上，一位名叫 Ryan Dahl 的开发人员上台介绍了他的项目 Node.js。从 2008 年开始，Dahl 研究了当前的 Web 趋势，并发现了 Web 应用程序工作方式的一些奇怪之处。几年前引入的**异步 JavaScript 和 XML**（**AJAX**）技术将静态网站转变为动态 Web 应用程序，但 Web 开发的基本构建块并没有遵循这一趋势。

问题在于 Web 技术不支持浏览器和服务器之间的双向通信。他使用的测试案例是 Flickr 上传文件功能，浏览器无法知道何时更新进度条，因为服务器无法告知它已上传文件的多少。

Dahl 的想法是构建一个 Web 平台，能够从服务器优雅地支持向浏览器推送数据，但这并不简单。当扩展到常见的 Web 使用时，该平台必须支持服务器和浏览器之间数百（有时甚至数千）个正在进行的连接。大多数 Web 平台使用昂贵的线程来处理请求，这意味着要保持相当数量的空闲线程以保持连接活动。因此，Dahl 采用了不同的方法。他意识到使用非阻塞套接字可以在系统资源方面节省很多，并且证明了这可以通过 C 来实现。鉴于这种技术可以在任何编程语言中实现，以及 Dahl 认为使用非阻塞 C 代码是一项繁琐的任务，他决定寻找一种更好的编程语言。

当谷歌在 2008 年底宣布推出 Chrome 及其新的 V8 JavaScript 引擎时，很明显 JavaScript 可以比以前运行得更快 - 快得多。 V8 引擎相对于其他 JavaScript 引擎的最大优势是在执行之前将 JavaScript 代码编译为本机机器代码。这和其他优化使 JavaScript 成为一种能够执行复杂任务的可行编程语言。 Dahl 注意到了这一点，并决定尝试一个新的想法：在 JavaScript 中使用非阻塞套接字。他拿了 V8 引擎，用已经稳固的 C 代码包装起来，创建了 Node.js 的第一个版本。

在社区的热烈反响之后，他继续扩展了 Node 核心。 V8 引擎并不是为了在服务器环境中运行而构建的，因此 Node.js 必须以一种在服务器上更有意义的方式来扩展它。例如，浏览器通常不需要访问文件系统，但在运行服务器代码时，这变得至关重要。结果是 Node.js 不仅仅是一个 JavaScript 执行引擎，而是一个能够运行简单编码、高效且易于扩展的复杂 JavaScript 应用程序的平台。

## io.js 和 Node.js 基金会

到 2014 年底，Joyent 公司，拥有 Node.js 资产的公司，与项目的一些核心贡献者之间产生了冲突。这些开发人员认为项目的治理不足，因此他们要求 Joyent 创建一个非营利基金会来管理该项目。2015 年 1 月，该团队决定分叉 Node.js 项目，并将其称为 io.js。新项目旨在实现更快和更可预测的发布周期，并开始获得一些关注。

几个月后，io.js 团队得到公司和社区开发者的支持，受邀到 Joyent 的办公室讨论项目的未来。他们一起决定创建一个由技术指导委员会领导的 Node 基金会，将项目合并为 Node.js 品牌，并基于 io.js 存储库。这导致了 Node 发布周期的大幅升级和项目治理的更加透明。

## Node.js ES6 支持

尽管 Node.js 在旧版本中已经实现了部分 ES6 支持，但最新版本在实现 ES6 功能方面取得了更好的进展。出于稳定性原因，Node V8 引擎将 ES6 功能分为三个分类：

+   **Shipping**：所有被认为是稳定的功能并且默认开启。这意味着它们*不*需要任何运行时标志来激活。

+   **Staged**：几乎稳定但不建议在生产中使用的所有功能。这些功能可以使用`--es_staging`运行时标志或其更为常见的同义词`--harmony`标志来激活。

+   **In progress**：所有仍在进行中且不稳定的功能。这些功能可以使用它们各自的`--harmony`标志来激活。

尽管这超出了本书的范围，但建议您访问官方文档[`nodejs.org/en/docs/es6/`](https://nodejs.org/en/docs/es6/)，了解更多关于 Node.js 中 ES6 实现的信息。

## Node.js LTS 支持

随着 Node.js 社区的不断壮大，越来越多的公司和大型组织加入进来，导致对稳定性和可预测版本发布的需求不断增加。为了满足这些新需求，Node.js 基金会决定了一个新的发布周期。基本上，团队每年 10 月发布一个新的稳定版本。这个版本总是有一个偶数版本号，比如 v4 或 v6。这些稳定版本受 LTS 计划支持。它包括安全和稳定更新，并且一旦它们在 10 月进入 LTS 计划，就可以在生产中使用。每年 4 月，一个稳定版本从 LTS 计划中发布。这意味着总是有两个重叠的稳定版本，最长为 6 个月，每个稳定版本都有 18 个月的支持。奇数版本被认为不稳定，主要用于向社区展示路线图的实现。这些版本在 10 月份被切割，以便及时合并到新的稳定版本中。

以下是未来几年发布周期的简单路线图：

![Node.js LTS support](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mean-webdev-2e/img/B05071_02_01.jpg)

## JavaScript 事件驱动编程

Node.js 利用 JavaScript 的事件驱动特性来支持平台中的非阻塞操作，这一特性使其具有出色的效率。JavaScript 是一种事件驱动的语言，这意味着您可以将代码注册到特定的事件上，一旦事件被触发，这些代码就会被执行。这个概念允许您无缝地执行异步代码，而不会阻止程序的其余部分运行。

为了更好地理解这一点，看一下以下的 Java 代码示例：

```js
System.out.print("What is your name?"); 
String name = System.console().readLine();
System.out.print("Your name is: " + name); 
```

在这个例子中，程序执行第一行和第二行，但在第二行之后的任何代码都不会被执行，直到用户输入他们的名字。这是同步编程，其中 I/O 操作阻止程序的其余部分运行。然而，这不是 JavaScript 的工作方式。

最初设计用于支持浏览器操作，JavaScript 围绕浏览器事件进行了设计。尽管它自早期以来已经大大发展，但其设计理念是允许浏览器接收 HTML 用户事件并将其委托给 JavaScript 代码。让我们看下面的 HTML 示例：

```js
<span>What is your name?</span>
<input type="text" id="nameInput">
<input type="button" id="showNameButton" value="Show Name">
<script type="text/javascript">
const showNameButton = document.getElementById('showNameButton');

showNameButton.addEventListener('click', (event) => {
    alert(document.getElementById('nameInput').value);
});

// Rest of your code...
</script>
```

在上面的例子中，我们有一个文本框和一个按钮。当按下按钮时，它将警报文本框内的值。这里要关注的主要函数是`addEventListener()`方法。如您所见，它接受两个参数：事件的名称和一个匿名函数，该函数在事件发生时运行一次。我们通常将后一种参数称为*回调*函数。请注意，`addEventListener()`方法之后的任何代码都将相应地执行，而不管我们在回调函数中写了什么。

尽管这个例子很简单，但很好地说明了 JavaScript 如何使用事件来执行一组命令。由于浏览器是单线程的，在这个例子中使用同步编程会冻结页面上的所有其他内容，这将使每个网页都变得极其不响应，并且会影响整体的网页体验。幸运的是，事实并非如此。浏览器使用内部循环（通常称为事件循环）来管理单个线程来运行整个 JavaScript 代码。事件循环是浏览器无限运行的单线程循环。每次发出事件时，浏览器都会将其添加到事件队列中。然后循环将从队列中获取下一个事件，以执行注册到该事件的事件处理程序。

所有事件处理程序执行完毕后，循环会获取下一个事件，执行其处理程序，再获取另一个事件，依此类推。事件循环周期如下图所示：

![JavaScript 事件驱动编程](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mean-webdev-2e/img/B05071_02_02.jpg)

事件循环周期

虽然浏览器通常处理用户生成的事件（例如按钮点击），但 Node.js 必须处理从不同来源生成的各种类型的事件。

## Node.js 事件驱动编程

在开发 Web 服务器逻辑时，您可能会注意到大量系统资源被阻塞代码浪费。例如，让我们观察以下 PHP 数据库交互：

```js
$output = mysql_query('SELECT * FROM Users');
echo($output);
```

我们的服务器将尝试查询数据库。数据库将执行`SELECT`语句，并将结果返回给 PHP 代码，最终将数据输出为响应。上述代码会阻塞其他操作，直到从数据库获取结果。这意味着该进程，或更常见的是线程，将保持空闲状态，消耗系统资源，同时等待其他进程。

为了解决这个问题，许多 Web 平台已经实现了一个线程池系统，通常为每个连接发出一个单个线程。这种多线程可能一开始看起来很直观，但有一些显著的缺点。它们如下：

+   管理线程变得复杂

+   系统资源被空闲线程浪费

+   这些应用程序的扩展性不容易实现

这在开发单向 Web 应用程序时是可以容忍的，其中浏览器发出快速请求，以服务器响应结束。但是，当您想要构建保持浏览器和服务器之间长期连接的实时应用程序时会发生什么？要了解这些设计选择的现实后果，请看以下图表。它们展示了 Apache（一个阻塞式 Web 服务器）和使用非阻塞事件循环的 NGINX 之间的著名性能比较。以下截图显示了 Apache 与 NGINX 中的并发请求处理（[`blog.webfaction.com/2008/12/a-little-holiday-present-10000-reqssec-with-nginx-2/`](http://blog.webfaction.com/2008/12/a-little-holiday-present-10000-reqssec-with-nginx-2/)）：

![Node.js 事件驱动编程](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mean-webdev-2e/img/B05071_02_03.jpg)

Apache 与 NGINX 中并发连接对请求处理的影响。

在上图中，您可以看到 Apache 的请求处理能力下降得比 NGINX 快得多。在下图中可以更清楚地看到 NGINX 的事件循环架构如何影响内存消耗：

![Node.js 事件驱动编程](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mean-webdev-2e/img/B05071_02_04.jpg)

Apache 与 NGINX 中并发连接对内存分配的影响。

从结果中可以看出，使用事件驱动架构将帮助您大大减少服务器的负载，同时利用 JavaScript 的异步行为来构建您的 Web 应用程序。这种方法更容易实现，这要归功于一个称为**闭包**的简单设计模式。

# JavaScript 闭包

闭包是指从其父环境引用变量的函数。为了更好地理解它们，让我们看一个例子：

```js
function parent() {
    const message = 'Hello World';

    function child() { 
        alert (message);
    }

    child(); 
}

parent();
```

在上面的例子中，您可以看到`child()`函数可以访问在`parent()`函数中定义的常量。然而，这只是一个简单的例子，让我们看一个更有趣的例子：

```js
function parent() {
   const message = 'Hello World'; 

    function child() { 
    alert (message); 
  }

   return child;
}

const childFN = parent();
childFN();
```

这一次，`parent()`函数返回了`child()`函数，并且`child()`函数是在`parent()`函数已经执行之后被调用的。这对一些开发人员来说是违反直觉的，因为通常`parent()`函数的局部成员应该只在函数执行时存在。这就是闭包的全部内容！闭包不仅仅是函数，还包括函数创建时存在的环境。在这种情况下，`childFN()`是一个闭包对象，包括`child()`函数和在创建闭包时存在的环境成员，包括`message`常量。

闭包在异步编程中非常重要，因为 JavaScript 函数是一级对象，可以作为参数传递给其他函数。这意味着您可以创建一个回调函数，并将其作为参数传递给事件处理程序。当事件被触发时，函数将被调用，并且它将能够操作在创建回调函数时存在的任何成员，即使其父函数已经执行。这意味着使用闭包模式将帮助您利用事件驱动编程，而无需将作用域状态传递给事件处理程序。

# Node 模块

JavaScript 已经成为一种功能强大的语言，具有一些独特的特性，可以实现高效而可维护的编程。它的闭包模式和事件驱动行为在现实场景中被证明非常有帮助，但像所有编程语言一样，它并不完美。其主要设计缺陷之一是共享单个全局命名空间。

要理解这个问题，我们需要回到 JavaScript 的浏览器起源。在浏览器中，当您将脚本加载到网页中时，引擎将其代码注入到所有其他脚本共享的地址空间中。这意味着当您在一个脚本中分配一个变量时，您可能会意外地覆盖先前脚本中已定义的另一个变量。虽然这可能适用于小型代码库，但在更大的应用程序中很容易引起冲突，因为错误将很难追踪。这可能是 Node.js 作为一个平台的主要威胁，但幸运的是，在 CommonJS 模块标准中找到了一个解决方案。

## CommonJS 模块

CommonJS 是一个于 2009 年开始的项目，旨在规范浏览器外部的 JavaScript 工作方式。从那时起，该项目已经发展，以支持各种 JavaScript 问题，包括全局命名空间问题，通过简单的规范来编写和包含隔离的 JavaScript 模块来解决。

CommonJS 标准在处理模块时指定了以下关键组件：

+   `require()`: 用于将模块加载到您的代码中的方法。

+   `exports`: 每个模块中包含的对象，允许在加载模块时公开代码片段。

+   `module`：最初用于提供有关模块的元数据信息的对象。它还包含`exports`对象的指针作为属性。然而，将`exports`对象作为独立对象的流行实现实际上改变了`module`对象的用例。

在 Node 的 CommonJS 模块实现中，每个模块都是在单个 JavaScript 文件中编写的，并具有一个持有自己成员的隔离作用域。模块的作者可以通过`exports`对象公开任何功能。为了更好地理解这一点，假设我们创建了一个名为`hello.js`的模块文件，其中包含以下代码段：

```js
const message = 'Hello';

exports.sayHello = function(){
  console.log(message);
}
```

我们还创建了一个名为`server.js`的应用程序文件，其中包含以下代码：

```js
const hello = require('./hello');
hello.sayHello();
```

在前面的例子中，你有一个名为`hello`的模块，其中包含一个名为`message`的常量。消息常量是在`hello`模块内部自包含的，它只通过将其定义为`exports`对象的属性来公开`sayHello()`方法。然后，应用程序文件使用`require()`方法加载`hello`模块，这允许它调用`hello`模块的`sayHello()`方法。

创建模块的另一种方法是使用`module.exports`指针公开单个函数。为了更好地理解这一点，让我们修改前面的例子。修改后的`hello.js`文件应该如下所示：

```js
module.exports = function() {
  const message = 'Hello';

  console.log(message);
}
```

然后，模块在`server.js`文件中加载如下：

```js
const hello = require('./hello');
hello();
```

在前面的例子中，应用程序文件直接将`hello`模块作为函数使用，而不是将`sayHello()`方法作为`hello`模块的属性使用。

CommonJS 模块标准允许对 Node.js 平台进行无限扩展，同时防止污染 Node 的核心。没有它，Node.js 平台将变成一团混乱。然而，并非所有模块都是相同的，在开发 Node 应用程序时，你将遇到多种类型的模块。

### 注意

当你需要模块时，可以省略`.js`扩展名。Node 会自动查找同名的文件夹，如果找不到，它会查找一个适用的`.js`文件。

## Node.js 核心模块

核心模块是编译到 Node 二进制文件中的模块。它们与 Node 一起预先捆绑，并在其文档中有详细解释。核心模块提供了 Node 的大部分基本功能，包括文件系统访问、HTTP 和 HTTPS 接口等。要加载核心模块，你只需要在你的 JavaScript 文件中使用`require`方法。

使用`fs`核心模块读取环境主机文件内容的示例代码如下所示：

```js
const fs = require('fs');

fs.readFile('/etc/hosts', 'utf8', (err, data) => { 
  if (err) { 
   return console.log(err); 
  } 

  console.log(data); 
});
```

当你需要`fs`模块时，Node 会在`core modules`文件夹中找到它。然后你就可以使用`fs.readFile()`方法来读取文件内容并将其打印在命令行输出中。

### 注意

要了解更多关于 Node 的核心模块的信息，建议你访问官方文档[`nodejs.org/api/`](http://nodejs.org/api/)。

## Node.js 第三方模块

在上一章中，你学会了如何使用 npm 安装第三方模块。你可能还记得，npm 会将这些模块安装在应用程序根文件夹下名为`node_modules`的文件夹中。要使用第三方模块，你可以像通常加载核心模块一样加载它们。Node 首先会在`core modules`文件夹中查找模块，然后尝试从`node_modules`文件夹中的`module`文件夹加载模块。例如，要使用`express`模块，你的代码应该如下所示：

```js
const express = require('express');
const app = express();
```

然后 Node 会在`node_modules`文件夹中查找`express`模块，并将其加载到你的应用程序文件中，你将能够将其用作生成`express`应用程序对象的方法。

## Node.js 文件模块

在前面的例子中，您看到了 Node 如何直接从文件加载模块。这些例子描述了文件位于同一文件夹中的情况。但是，您也可以将模块放在文件夹中，并通过提供文件夹路径来加载它们。假设您将 `hello` 模块移动到一个名为 `modules` 的文件夹中。应用程序文件将不得不更改，因此 Node 将在新的相对路径中寻找模块：

```js
const hello = require('./modules/hello');
```

请注意，路径也可以是绝对路径，如下所示：

```js
const hello = require('/home/projects/first-example/modules/hello');
```

然后 Node 将在该路径中查找 `hello` 模块。

## Node.js 文件夹模块

尽管这对于不编写第三方 Node 模块的开发人员来说并不常见，但 Node 也支持加载文件夹模块。加载文件夹模块的方式与加载文件模块相同，如下所示：

```js
const hello = require('./modules/hello');
```

现在，如果存在一个名为 `hello` 的文件夹，Node 将浏览该文件夹，寻找一个 `package.json` 文件。如果 Node 找到了 `package.json` 文件，它将尝试解析它，寻找 main 属性，一个看起来像以下代码片段的 `package.json` 文件：

```js
{
  "name": "hello",
  "version": "1.0.0",
  "main": "./hello-module.js"
}
```

Node 将尝试加载 `./hello/hello-module.js` 文件。如果 `package.json` 文件不存在或 main 属性未定义，Node 将自动尝试加载 `./hello/index.js` 文件。

Node.js 模块被发现是编写复杂 JavaScript 应用程序的一个很好的解决方案。它们帮助开发人员更好地组织他们的代码，而 npm 及其第三方模块注册表帮助他们找到并安装了社区创建的众多第三方模块之一。Ryan Dahl 建立更好的 Web 框架的梦想最终成为了一个支持各种解决方案的平台。然而，这个梦想并没有被放弃；它只是作为一个名为 `express` 的第三方模块实现了。

# 开发 Node.js Web 应用程序

Node.js 是一个支持各种类型应用程序的平台，但最流行的是 Web 应用程序的开发。Node 的编码风格取决于社区通过第三方模块扩展平台。然后，这些模块被用来创建新模块，以此类推。全球的公司和单个开发人员都参与到这个过程中，通过创建包装基本 Node API 的模块，为应用程序开发提供更好的起点。

有许多模块支持 Web 应用程序开发，但没有一个像 Connect 模块那样受欢迎。Connect 模块提供了一组包装器，围绕 Node.js 低级 API，以实现丰富的 Web 应用程序框架的开发。要了解 Connect 的全部内容，让我们从一个基本的 Node Web 服务器的基本示例开始。在您的工作文件夹中，创建一个名为 `server.js` 的文件，其中包含以下代码片段：

```js
const http = require('http');

http.createServer(function(req, res) => {
  res.writeHead(200, {
    'Content-Type': 'text/plain'
  });
  res.end('Hello World');
}).listen(3000);

console.log('Server running at http://localhost:3000/');
```

启动您的 Web 服务器，使用命令行工具并导航到您的工作文件夹。然后，运行 Node.js CLI 工具，并运行 `server.js` 文件如下：

```js
$ node server

```

现在，在浏览器中打开 `http://localhost:3000`，您将看到 **Hello World** 的响应。

那么，这是如何工作的呢？在这个例子中，`http` 模块用于创建一个监听 `3000` 端口的小型 Web 服务器。您首先需要引入 `http` 模块，然后使用 `createServer()` 方法返回一个新的服务器对象。然后使用 `listen()` 方法来监听 `3000` 端口。请注意，回调函数作为参数传递给 `createServer()` 方法。

每当 Web 服务器收到 HTTP 请求时，回调函数都会被调用。然后服务器对象将传递 `req` 和 `res` 参数，其中包含发送 HTTP 响应所需的信息和功能。然后回调函数将遵循以下两个步骤：

1.  首先，它将调用 `res` 对象的 `writeHead()` 方法。此方法用于设置响应的 HTTP 标头。在这个例子中，它将把 content-type 标头值设置为 `text/plain`。例如，当响应 HTML 时，只需用 `html/plain` 替换 `text/plain`。

1.  然后，它将调用`res`对象的`end()`方法。这个方法用于完成响应。`end()`方法接受一个单字符串参数，它将作为 HTTP 响应主体使用。另一种常见的写法是在`end()`方法之前添加一个`write()`方法，然后调用`end()`方法，如下所示：

```js
res.write('Hello World');
res.end();
```

这个简单的应用程序展示了 Node 的编码风格，其中使用低级 API 来简单实现某些功能。虽然这是一个很好的例子，但是使用低级 API 运行完整的 web 应用程序将需要您编写大量的辅助代码来支持常见的需求。幸运的是，一个名为 Sencha 的公司已经为您创建了这个脚手架代码，以 Node.js 模块的形式称为 Connect。

## 了解 Connect 模块

Connect 是一个模块，旨在以更模块化的方式支持请求的拦截。在第一个 web 服务器示例中，您学习了如何使用`http`模块构建一个简单的 web 服务器。如果您希望扩展此示例，您将需要编写代码来管理发送到服务器的不同 HTTP 请求，正确处理它们，并为每个请求提供正确的响应。

Connect 创建了一个专门用于此目的的 API。它使用了一个名为*middleware*的模块化组件，允许您简单地将应用逻辑注册到预定义的 HTTP 请求场景中。Connect 中间件基本上是回调函数，当发生 HTTP 请求时会被执行。然后中间件可以执行一些逻辑，返回一个响应，或者调用下一个注册的中间件。

虽然您大多数情况下会编写自定义中间件来支持应用程序的需求，但 Connect 还包括一些常见的中间件，以支持日志记录、静态文件服务等。

Connect 应用程序的工作方式是使用一个名为*dispatcher*的对象。调度程序对象处理服务器接收到的每个 HTTP 请求，然后以级联形式决定中间件执行的顺序。要更好地理解 Connect，请查看以下图示：

![了解 Connect 模块](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mean-webdev-2e/img/B05071_02_05.jpg)

使用中间件执行请求

上述图示了对 Connect 应用程序的两个调用：第一个由自定义中间件处理，第二个由静态文件中间件处理。Connect 的调度程序启动了这个过程，使用`next()`方法继续到下一个处理程序，直到它到达一个使用`res.end()`方法响应的中间件，这将结束请求处理。

在下一章中，您将创建您的第一个 Express 应用程序，但 Express 是基于 Connect 的方法。因此，为了理解 Express 的工作原理，我们将从创建一个 Connect 应用程序开始。

在您的工作文件夹中，创建一个名为`server.js`的文件，其中包含以下代码片段：

```js
const connect = require('connect');
const app = connect();
app.listen(3000); 

console.log('Server running at http://localhost:3000/');
```

如您所见，您的应用程序文件正在使用`connect`模块创建一个新的 web 服务器。但是，Connect 不是一个核心模块，因此您需要使用 npm 安装它。正如您已经知道的，有几种安装第三方模块的方法。最简单的方法是直接使用`npm install`命令进行安装。要这样做，使用命令行工具，导航到您的工作文件夹。然后，执行以下命令：

```js
$ npm install connect

```

npm 将在`node_modules`文件夹中安装`connect`模块，这将使您能够在应用程序文件中引用它。要运行 Connect web 服务器，只需使用 Node 的 CLI 并执行以下命令：

```js
$ node server

```

Node 将运行您的应用程序，并使用`console.log()`方法报告服务器状态。您可以尝试在浏览器中访问`http://localhost:3000`来访问您的应用程序。但是，您应该会得到类似以下截图所示的响应：

![了解 Connect 模块](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mean-webdev-2e/img/B05071_02_06.jpg)

这个响应的意思是没有任何中间件注册来处理 GET HTTP 请求。这意味着首先，您成功安装并使用了 Connect 模块，其次，现在是时候编写您的第一个 Connect 中间件了。

### Connect 中间件

Connect 中间件基本上是一个具有独特签名的 JavaScript 函数。每个中间件函数都使用以下三个参数定义：

+   `req`：这是一个保存 HTTP 请求信息的对象

+   `res`：这是一个保存 HTTP 响应信息并允许您设置响应属性的对象

+   `next`：这是在有序的 Connect 中间件集合中定义的下一个中间件函数

当您定义了一个中间件时，您只需使用`app.use()`方法将其注册到 Connect 应用程序中。让我们修改前面的例子，包括您的第一个中间件。将您的`server.js`文件更改为以下代码片段：

```js
const connect = require('connect');
const app = connect();

function helloWorld(req, res, next) {
 res.setHeader('Content-Type', 'text/plain');
 res.end('Hello World');
};
app.use(helloWorld);

app.listen(3000); 
console.log('Server running at http://localhost:3000/');
```

然后，通过在命令行工具中发出以下命令，再次启动您的 Connect 服务器：

```js
$ node server

```

再次访问`http://localhost:3000`。您现在将会得到与以下截图中类似的响应：

![Connect middleware](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mean-webdev-2e/img/B05071_02_07.jpg)

如果您看到 Connect 应用程序的响应与之前的截图相同，那么恭喜您！您刚刚创建了您的第一个 Connect 中间件！

让我们回顾一下。首先，您添加了一个名为`helloWorld()`的中间件函数，它有三个参数：`req`、`res`和`next`。在您的中间件函数内部，您使用了`res.setHeader()`方法来设置响应的`Content-Type`头部和`res.end()`方法来设置响应文本。最后，您使用了`app.use()`方法来将您的中间件注册到 Connect 应用程序中。

### 理解 Connect 中间件的顺序

Connect 最大的特点之一是能够注册尽可能多的中间件函数。使用`app.use()`方法，您可以设置一系列中间件函数，这些函数将按顺序执行，以实现编写应用程序时的最大灵活性。Connect 将使用`next`参数将下一个中间件函数传递给当前执行的中间件函数。在每个中间件函数中，您可以决定是调用下一个中间件函数还是停在当前中间件函数。请注意，每个中间件函数将使用下一个参数按照**先进先出**（**FIFO**）的顺序执行，直到没有更多的中间件函数要执行或者没有调用下一个中间件函数。

为了更好地理解这一点，我们将回到之前的例子，并添加一个记录器函数，它将在命令行中记录发送到服务器的所有请求。为此，返回到`server.js`文件，并更新如下：

```js
const connect = require('connect');
const app = connect();

function logger(req, res, next) {
 console.log(req.method, req.url);
 next();
};

function helloWorld(req, res, next) {
  res.setHeader('Content-Type', 'text/plain');
  res.end('Hello World');
};

app.use(logger);
app.use(helloWorld);
app.listen(3000);

console.log('Server running at http://localhost:3000/');
```

在前面的例子中，您添加了另一个名为`logger()`的中间件。`logger()`中间件使用`console.log()`方法简单地将请求信息记录到控制台。请注意，`logger()`中间件在`helloWorld()`中间件之前注册。这很重要，因为它决定了每个中间件执行的顺序。还要注意的一点是`logger()`中间件中的`next()`调用，它负责调用`helloWorld()`中间件。如果删除`next()`调用，将会停止在`logger()`中间件处执行中间件函数，这意味着请求将永远挂起，因为没有调用`res.end()`方法来结束响应。

要测试您的更改，请通过在命令行工具中发出以下命令，再次启动您的 Connect 服务器：

```js
$ node server

```

然后，在浏览器中访问`http://localhost:3000`，注意命令行工具中的控制台输出。

### 挂载 Connect 中间件

正如你可能已经注意到的，你注册的中间件会响应任何请求，而不管请求路径如何。这不符合现代 Web 应用程序开发的要求，因为响应不同路径是所有 Web 应用程序的一个重要部分。幸运的是，Connect 中间件支持一种称为挂载的功能，它使你能够确定中间件函数需要执行的请求路径。挂载是通过向`app.use()`方法添加路径参数来完成的。为了更好地理解这一点，让我们重新访问我们之前的例子。修改你的`server.js`文件，使其看起来像以下代码片段：

```js
const connect = require('connect');
const app = connect();

function logger(req, res, next) {
  console.log(req.method, req.url);

  next();
};

function helloWorld(req, res, next) {
  res.setHeader('Content-Type', 'text/plain');
  res.end('Hello World');
};

function goodbyeWorld(req, res, next) {
 res.setHeader('Content-Type', 'text/plain');
 res.end('Goodbye World');
};

app.use(logger);
app.use('/hello', helloWorld);
app.use('/goodbye', goodbyeWorld);
app.listen(3000);

console.log('Server running at http://localhost:3000/');
```

在之前的例子中有一些变化。首先，你将`helloWorld()`中间件挂载到仅响应对`/hello`路径发出的请求。然后，你添加了另一个（有点令人沮丧）中间件，名为`goodbyeWorld()`，它将响应对`/goodbye`路径发出的请求。请注意，正如`logger`应该做的那样，我们让`logger()`中间件响应服务器上的所有请求。另一件你应该注意的事情是，任何发往基本路径的请求都不会被任何中间件响应，因为我们将`helloWorld()`中间件挂载到了特定路径。

Connect 是一个很棒的模块，支持常见 Web 应用程序的各种功能。Connect 中间件非常简单，因为它是以 JavaScript 风格构建的。它允许无限扩展应用逻辑，而不会破坏 Node 平台的灵活哲学。虽然 Connect 在编写 Web 应用程序基础设施方面有很大改进，但它故意缺少一些你在其他 Web 框架中习惯拥有的基本功能。原因在于 Node 社区的一个基本原则：创建精简的模块，让其他开发人员在你创建的模块基础上构建自己的模块。社区应该用自己的模块扩展 Connect，并创建自己的 Web 基础设施。事实上，一个名叫 TJ Holowaychuk 的非常有活力的开发人员做得比大多数人都好，他发布了一个基于 Connect 的 Web 框架，名为 Express。

# 总结

在本章中，你学会了 Node.js 如何利用 JavaScript 的事件驱动行为来获益。你还了解了 Node.js 如何使用 CommonJS 模块系统来扩展其核心功能。此外，你还了解了 Node.js Web 应用程序的基本原则，并发现了 Connect Web 模块。最后，你创建了你的第一个 Connect 应用程序，并学会了如何使用中间件函数。

在下一章中，当我们讨论基于 Connect 的 Web 框架 Express 时，我们将解决 MEAN 拼图的第一部分。


# 第三章：构建一个 Express Web 应用程序

本章将介绍构建你的第一个 Express 应用程序的正确方法。你将首先安装和配置 Express 模块，然后学习 Express 的主要 API。我们将讨论 Express 请求、响应和应用程序对象，并学习如何使用它们。然后我们将介绍 Express 路由机制，并学习如何正确使用它。我们还将讨论应用程序文件夹的结构以及如何利用不同的结构来处理不同的项目类型。在本章结束时，你将学会如何构建一个完整的 Express 应用程序。在本章中，我们将涵盖以下主题：

+   安装 Express 并创建一个新的 Express 应用程序

+   组织你的项目结构

+   配置你的 Express 应用程序

+   使用 Express 路由机制

+   渲染 EJS 视图

+   提供静态文件

+   配置 Express 会话

# 介绍 Express

说 TJ Holowaychuk 是一个富有成效的开发者几乎是一个巨大的低估。TJ 在 Node.js 社区的参与几乎是任何其他开发者无法比拟的，他负责一些 JavaScript 生态系统中最受欢迎的框架，拥有 500 多个开源项目。

他最伟大的项目之一是 Express web 框架。Express 框架是一组常见的 Web 应用程序功能的最小集合，以保持 Node.js 风格。它建立在 Connect 之上，并利用其中间件架构。其功能扩展 Connect，允许各种常见的 Web 应用程序用例，例如包含模块化 HTML 模板引擎，扩展响应对象以支持各种数据格式输出，路由系统等等。

到目前为止，我们已经使用了一个`server.js`文件来创建我们的应用程序。然而，使用 Express 时，你将学习更多关于更好的项目结构，正确配置你的应用程序，并将应用程序逻辑分解为不同的模块。你还将学习如何使用 EJS 模板引擎，管理会话，并添加路由方案。在本节结束时，你将拥有一个可用的应用程序框架，你将在本书的其余部分中使用它。让我们开始创建你的第一个 Express 应用程序的旅程。

# 安装 Express

到目前为止，我们使用 npm 直接为我们的 Node 应用程序安装外部模块。当然，你可以使用这种方法，并通过输入以下命令来安装 Express：

```js
$ npm install express

```

然而，直接安装模块并不是真正可扩展的。想一想：你将在应用程序中使用许多 Node 模块，在工作环境之间传输它，并且可能与其他开发人员共享它。因此，以这种方式安装项目模块很快就会变成一项可怕的任务。相反，你应该开始使用`package.json`文件，它可以组织项目元数据并帮助你管理应用程序的依赖关系。首先，创建一个新的工作文件夹，并在其中创建一个新的`package.json`文件，其中包含以下代码片段：

```js
{
  "name" : "MEAN",
  "version" : "0.0.3",
  "dependencies" : {
    "express" : "4.14.0"
  }
}
```

在`package.json`文件中，注意到你包含了三个属性：应用程序的名称和版本，以及依赖属性，它定义了在应用程序运行之前应安装哪些模块。要安装应用程序的依赖项，请使用命令行工具并导航到应用程序文件夹，然后发出以下命令：

```js
$ npm install

```

npm 然后会安装 Express 模块，因为目前它是在你的`package.json`文件中定义的唯一依赖项。

# 创建你的第一个 Express 应用程序

创建你的第一个 Express 应用程序

```js
const express = require('express');
const app = express();

app.use('/', (req, res) => {
  res.status(200).send('Hello World');
});

app.listen(3000);
console.log('Server running at http://localhost:3000/');

module.exports = app;
```

你应该已经认识到大部分代码了。前两行需要 Express 模块并创建一个新的 Express 应用程序对象。然后，我们使用`app.use()`方法来挂载一个具有特定路径的中间件函数，以及`app.listen()`方法来告诉 Express 应用程序监听端口`3000`。注意`module.exports`对象是如何用于返回`app`对象的。这将帮助你加载和测试你的 Express 应用程序。

这段新代码对你来说也应该很熟悉，因为它类似于你在之前的 Connect 示例中使用的代码。这是因为 Express 以多种方式包装了 Connect 模块。`app.use()`方法用于挂载一个中间件函数，该函数将响应任何发送到根路径的 HTTP 请求。在中间件函数内部，`res.status()`方法用于设置 HTTP 响应代码，`res.send()`方法用于发送响应。`res.send()`方法基本上是一个 Express 包装器，根据响应对象类型设置 Content-Type 标头，然后使用 Connect 的`res.end()`方法发送响应。

### 注意

当将缓冲区传递给`res.send()`方法时，Content-Type 标头将设置为`application/octet-stream`；当传递字符串时，它将设置为`text/html`；当传递对象或数组时，它将设置为`application/json`。

要运行你的应用程序，只需在命令行工具中执行以下命令：

```js
$ node server

```

恭喜！你刚刚创建了你的第一个 Express 应用程序。你可以通过访问`http://localhost:3000`在浏览器中测试它。

# 应用程序、请求和响应对象

Express 提供了三个主要对象，你会经常使用它们。应用对象是你在第一个例子中创建的 Express 应用程序的实例，通常用于配置你的应用程序。请求对象是 Node 的 HTTP 请求对象的包装器，用于提取关于当前处理的 HTTP 请求的信息。响应对象是 Node 的 HTTP 响应对象的包装器，用于设置响应数据和标头。

## 应用对象

应用对象包含以下方法，帮助你配置你的应用程序：

+   `app.set(name, value)`: 这是一个用于设置 Express 将在其配置中使用的环境变量的方法。

+   `app.get(name)`: 这是一个用于获取 Express 在其配置中使用的环境变量的方法。

+   `app.engine(ext, callback)`: 这是一个用于定义给定模板引擎以渲染特定文件类型的方法；例如，你可以告诉 EJS 模板引擎使用 HTML 文件作为模板，就像这样：`app.engine('html', require('ejs').renderFile)`。

+   `app.locals`: 这是一个用于向所有渲染的模板发送应用级变量的属性。

+   `app.use([path], callback)`: 这是一个用于创建 Express 中间件来处理发送到服务器的 HTTP 请求的方法。可选地，你可以挂载中间件来响应特定路径。

+   `app.VERB(path, [callback...], callback)`: 这用于定义一个或多个中间件函数来响应与声明的 HTTP 动词一起使用的特定路径的 HTTP 请求。例如，当你想要响应使用 GET 动词的请求时，你可以使用`app.get()`方法来分配中间件。对于 POST 请求，你将使用`app.post()`，依此类推。

+   `app.route(path).VERB([callback...], callback)`: 这是一个用于定义一个或多个中间件函数来响应与多个 HTTP 动词一起使用的特定统一路径的 HTTP 请求的方法。例如，当你想要响应使用 GET 和 POST 动词的请求时，你可以使用`app.route(path).get(callback).post(callback)`来分配适当的中间件函数。

+   `app.param([name], callback)`: 这是一种方法，用于将特定功能附加到包含特定路由参数的路径上发出的任何请求。例如，您可以使用`app.param('userId', callback)`将逻辑映射到包含`userId`参数的任何请求。

您可以使用许多其他应用程序方法和属性，但使用这些常见的基本方法使开发人员能够以他们认为合理的方式扩展 Express。

## 请求对象

请求对象还提供了一些有助于包含有关当前 HTTP 请求的信息的方法。请求对象的关键属性和方法如下：

+   `req.query`: 这是一个包含解析后的查询字符串参数的属性。

+   `req.params`: 这是一个包含解析后的路由参数的属性。

+   `req.body`: 这是用于检索解析后的请求体的属性。它包含在`bodyParser()`中间件中。

+   `req.path` / `req.hostname` / `req.ip`: 这些用于检索当前请求的路径、主机名和远程 IP。

+   `req.cookies`: 这是与`cookieParser()`中间件一起使用的属性，用于检索用户代理发送的 cookie。

请求对象包含许多我们将在本书后面讨论的方法和属性，但这些方法通常是您在常见的 Web 应用程序中使用的。

## 响应对象

响应对象在开发 Express 应用程序时经常使用，因为发送到服务器的任何请求都将使用响应对象方法进行处理和响应。它有几个关键方法，如下所示：

+   `res.status(code)`: 这是用于设置响应 HTTP 状态代码的方法。

+   `res.set(field, [value])`: 这是用于设置响应 HTTP 标头的方法。

+   `res.cookie(name, value, [options])`: 这是用于设置响应 cookie 的方法。选项参数用于传递定义常见 cookie 配置的对象，例如`maxAge`属性。

+   `res.redirect([status], url)`: 这是用于将请求重定向到给定 URL 的方法。请注意，您可以向响应添加 HTTP 状态代码。当不传递状态代码时，它将默认为`302 Found`。

+   `res.status([status]).send( [body])`: 这是用于非流式响应的方法。它会做很多后台工作，例如设置 Content-Type 和 Content-Length 标头，并使用适当的缓存标头进行响应。

+   `res.status([status]).json( [body])`: 当发送对象或数组时，这与`res.send()`方法相同。大多数情况下，它被用作语法糖，但有时您可能需要使用它来强制将 JSON 响应发送到非对象，例如`null`或`undefined`。

+   `res.render(view, [locals], callback)`: 这是用于呈现视图并发送 HTML 响应的方法。

响应对象还包含许多其他方法和属性，用于处理不同的响应场景，您将在本书后面学习到。

# 外部中间件

Express 核心是最小的，但是背后的团队提供了各种预定义的中间件来处理常见的 Web 开发功能。这些类型的中间件在大小和功能上都有所不同，并扩展了 Express 以提供更好的框架支持。流行的 Express 中间件如下：

+   `morgan`: 这是一个 HTTP 请求记录器中间件。

+   `body-parser`: 这是一个用于解析请求体的中间件，它支持各种请求类型。

+   `method-override`: 这是一个提供 HTTP 动词支持的中间件，例如在客户端不支持的地方使用 PUT 或 DELETE。

+   `compression`: 这是一个压缩中间件，用于使用 GZIP/deflate 压缩响应数据。

+   `express.static`: 这是用于提供静态文件的中间件。

+   `cookie-parser`: 这是一个用于解析 cookie 的中间件，它填充了`req.cookies`对象。

+   `Session`: 这是用于支持持久会话的会话中间件。

有许多种类型的 Express 中间件，可以帮助您缩短开发时间，同时还有更多的第三方中间件。

### 注意

要了解更多关于 Connect 和 Express 中间件的信息，请访问 Connect 模块的官方存储库页面[`github.com/senchalabs/connect#middleware`](https://github.com/senchalabs/connect#middleware)。如果您想浏览第三方中间件集合，请访问 Connect 的 wiki 页面[`github.com/senchalabs/connect/wiki`](https://github.com/senchalabs/connect/wiki)。

# 实现 MVC 模式

Express 框架是模式不可知的，这意味着它不支持任何预定义的语法或结构，就像其他一些 Web 框架所做的那样。将 MVC 模式应用于您的 Express 应用程序意味着您可以创建特定的文件夹，将您的 JavaScript 文件按照一定的逻辑顺序放置在其中。所有这些文件基本上都是作为逻辑单元的 CommonJS 模块。例如，模型将是包含在`models`文件夹中的 Mongoose 模型定义的 CommonJS 模块，视图将是放置在`views`文件夹中的 HTML 或其他模板文件，控制器将是放置在`controllers`文件夹中的具有功能方法的 CommonJS 模块。为了更好地说明这一点，现在是讨论不同类型的应用程序结构的时候了。

## 应用程序文件夹结构

我们之前讨论了在开发真实应用时的最佳实践，我们推荐使用`package.json`文件而不是直接安装模块。然而，这只是一个开始；一旦您继续开发应用程序，您很快会想知道如何安排项目文件并将它们分解为逻辑代码单元。总的来说，JavaScript 和因此 Express 框架对于应用程序的结构是不可知的，因为你可以很容易地将整个应用程序放在一个 JavaScript 文件中。这是因为没有人预期 JavaScript 会成为一个全栈编程语言，但这并不意味着你不应该特别注意组织你的项目。由于 MEAN 堆栈可以用于构建各种大小和复杂度的应用程序，因此也可以以各种方式处理项目结构。决定往往直接与您的应用程序的预估复杂性有关。例如，简单的项目可能需要更简洁的文件夹结构，这样有利于更清晰和更容易管理，而复杂的项目通常需要更复杂的结构和更好的逻辑分解，因为它将包括许多功能和更大的团队在项目上工作。为了简化这个讨论，将其合理地分为两种主要方法：较小项目的水平结构和功能丰富应用程序的垂直结构。让我们从一个简单的水平结构开始。

### 水平文件夹结构

水平项目结构是基于按功能角色划分文件夹和文件，而不是按照它们实现的功能来划分，这意味着所有应用程序文件都放在一个主应用程序文件夹中，其中包含一个 MVC 文件夹结构。这也意味着有一个单独的`controllers`文件夹，其中包含所有应用程序控制器，一个单独的`models`文件夹，其中包含所有应用程序模型，依此类推。水平应用程序结构的一个示例如下：

![水平文件夹结构](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mean-webdev-2e/img/B05071_03_01.jpg)

让我们来回顾一下文件夹结构：

+   `app`文件夹是您保存 Express 应用程序逻辑的地方，它分为以下文件夹，代表了功能的分离，以符合 MVC 模式：

+   `controllers`文件夹是您保存 Express 应用程序控制器的地方

+   `models`文件夹是您保存 Express 应用程序模型的地方

+   `routes`文件夹是您保存 Express 应用程序路由中间件的地方

+   `views`文件夹是您保存 Express 应用程序视图的地方

+   `config`文件夹是您保存 Express 应用程序配置文件的地方。随着时间的推移，您将向应用程序添加更多模块，每个模块将在专用的 JavaScript 文件中进行配置，该文件放在此文件夹中。目前，它包含几个文件和文件夹，如下所示：

+   `env`文件夹是您保存 Express 应用程序环境配置文件的地方

+   `config.js`文件是您配置 Express 应用程序的地方

+   `express.js`文件是您初始化 Express 应用程序的地方

+   `public`文件夹是您保存静态客户端文件的地方，它分为以下文件夹，代表了功能的分离，以符合 MVC 模式：

+   `config`文件夹是您保存 Angular 应用程序配置文件的地方

+   `components`文件夹是您保存 Angular 应用程序组件的地方

+   `css`文件夹是您保存 CSS 文件的地方

+   `directives`文件夹是您保存 Angular 应用程序指令的地方

+   `pipes`文件夹是您保存 Angular 应用程序管道的地方

+   `img`文件夹是您保存图像文件的地方

+   `templates`文件夹是您保存 Angular 应用程序模板的地方

+   `bootstrap.ts`文件是您初始化 Angular 应用程序的地方

+   `package.json`文件是帮助您组织应用程序依赖关系的元数据文件。

+   `server.js`文件是您的 Node.js 应用程序的主文件，它将加载`express.js`文件作为模块，以启动您的 Express 应用程序。

如您所见，水平文件夹结构对于功能有限的小型项目非常有用，因此文件可以方便地放在代表其一般角色的文件夹中。然而，为了处理大型项目，在那里您将有许多处理特定功能的文件，这可能太简单了。在这种情况下，每个文件夹可能会被过多的文件所超载，您可能会在混乱中迷失。更好的方法是使用垂直文件夹结构。

### 垂直文件夹结构

垂直项目结构基于按功能实现的文件夹和文件的划分，这意味着每个功能都有自己独立的文件夹，其中包含一个 MVC 文件夹结构。垂直应用程序结构的示例如下：

![垂直文件夹结构](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mean-webdev-2e/img/B05071_03_02.jpg)

如您所见，每个功能都有自己类似应用程序的文件夹结构。在这个例子中，我们有包含主应用程序文件的`core feature`文件夹和包含功能文件的`feature`文件夹。一个示例功能将是包含身份验证和授权逻辑的用户管理功能。为了更好地理解这一点，让我们来看一个单个功能的文件夹结构：

+   `server`文件夹是您保存功能的服务器逻辑的地方，它分为以下文件夹，代表了功能的分离，以符合 MVC 模式：

+   `controllers`文件夹是您保存功能的 Express 控制器的地方

+   `models`文件夹是您保存功能的 Express 模型的地方

+   `routes`文件夹是您保存功能的 Express 路由中间件的地方

+   `views`文件夹是您保存功能的 Express 视图的地方

+   `config`文件夹是您保存功能服务器配置文件的地方

+   `env`文件夹是您保存功能环境服务器配置文件的地方

+   `feature.server.config.js`文件是您配置功能的地方

+   `client`文件夹是您保存功能的客户端文件的地方，它分为以下文件夹，代表了功能的分离，以符合 MVC 模式：

+   `config`文件夹是您保存特性的 Angular 配置文件的地方

+   `components`文件夹是您保存特性的 Angular `components`的地方

+   `css`文件夹是您保存特性的 CSS 文件的地方

+   `directives`文件夹是您保存特性的 Angular 指令的地方

+   `pipes`文件夹是您保存特性的 Angular 管道的地方

+   `img`文件夹是您保存特性的图像文件的地方

+   `templates`文件夹是您保存特性的 Angular 模板的地方

+   `feature.module.ts`文件是您初始化特性的 Angular 模块的地方

正如您所看到的，垂直文件夹结构对于特性数量无限且每个特性包含大量文件的大型项目非常有用。它将允许大型团队共同工作并分别维护每个特性，并且在不同应用程序之间共享特性时也很有用。

虽然这两种类型的应用程序结构是不同的，但事实上 MEAN 堆栈可以以许多不同的方式组装。甚至一个团队可能会以结合这两种方法的方式来构建他们的项目；因此，基本上由项目负责人决定使用哪种结构。在本书中，出于简单起见，我们将使用水平方法，但我们将以垂直方式整合我们应用程序的 Angular 部分，以展示 MEAN 堆栈结构的灵活性。请记住，本书中提出的所有内容都可以轻松重构以适应您项目的规格。

### 文件命名约定

在开发应用程序时，您很快会注意到您最终会得到许多具有相同名称的文件。原因是 MEAN 应用程序通常对 Express 和 Angular 组件都有并行的 MVC 结构。要理解这个问题，看一下常见的垂直特性文件夹结构：

![文件命名约定](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mean-webdev-2e/img/B05071_03_03.jpg)

正如您所看到的，强制文件夹结构有助于理解每个文件的功能，但也会导致多个文件具有相同的名称。这是因为一个应用程序的特性通常是使用多个 JavaScript 文件来实现的，每个文件都有不同的角色。这个问题可能会给开发团队带来一些困惑，因此为了解决这个问题，您需要使用某种命名约定。

最简单的解决方案是将每个文件的功能角色添加到文件名中。因此，特性控制器文件将被命名为`feature.controller.js`，特性模型文件将被命名为`feature.model.js`，依此类推。然而，当考虑到 MEAN 应用程序同时使用 JavaScript MVC 文件来处理 Express 和 Angular 应用程序时，情况变得更加复杂。这意味着您经常会有两个具有相同名称的文件。为了解决这个问题，还建议您扩展文件名以包含它们的执行目的地。这一开始可能看起来有些多余，但您很快会发现，快速识别应用程序文件的角色和执行目的地是非常有帮助的。

### 注意

重要的是要记住这是一种最佳实践约定。您可以轻松地用自己的关键字替换`controller`、`model`、`client`和`server`。

### 实施水平文件夹结构

要开始构建您的第一个 MEAN 项目的结构，请在其中创建一个新的项目文件夹，并在其中创建以下文件夹：

![实施水平文件夹结构](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mean-webdev-2e/img/B05071_03_04.jpg)

创建了所有前述文件夹后，返回到应用程序的根文件夹并创建一个包含以下代码片段的`package.json`文件：

```js
{
  "name" : "MEAN",
  "version" : "0.0.3",
  "dependencies" : {
    "express" : "4.14.0"
  }
}
```

现在，在`app/controllers`文件夹中，创建一个名为`index.server.controller.js`的文件，其中包含以下代码：

```js
exports.render = function(req, res) {
  res.status(200).send('Hello World');
};
```

恭喜！你刚刚创建了你的第一个 Express 控制器。这段代码可能看起来很熟悉；那是因为它是你在之前示例中创建的中间件的副本。你在这里所做的是使用 CommonJS 模块模式来定义一个名为`render()`的函数。稍后，你将能够获取这个模块并使用这个函数。一旦你创建了一个控制器，你就需要使用 Express 路由功能来利用这个控制器。

#### 处理请求路由

Express 支持使用`app.route(path).VERB(callback)`方法或`app.VERB(path, callback)`方法来路由请求，其中`VERB`应该替换为小写的 HTTP 动词。看一下以下例子：

```js
app.get('/', (req, res) => {
  res.status(200).send('This is a GET request');
});
```

这告诉 Express 执行中间件函数来处理任何使用`GET`动词并指向根路径的 HTTP 请求。如果你想处理`POST`请求，你的代码应该如下所示：

```js
app.post('/', (req, res) => {
  res.status(200).send('This is a POST request');
});
```

然而，Express 还允许你定义单个路由，然后链接多个中间件来处理不同的 HTTP 请求。这意味着前面的代码示例也可以写成如下形式：

```js
app.route('/').get((req, res) => {
  res.status(200).send('This is a GET request');
}).post((req, res) => {
  res.status(200).send('This is a POST request');
});
```

Express 的另一个很酷的功能是能够在单个路由定义中链接多个中间件。这意味着中间件函数将按顺序调用，将它们传递给下一个中间件，以便你可以确定如何继续执行中间件。这通常用于在执行响应逻辑之前验证请求。要更好地理解这一点，看一下以下代码：

```js
const express = require('express');

function hasName(req, res, next) {
 if (req.param('name')) {
 next();
 } else {
 res.status(200).send('What is your name?');
 }
};

function sayHello(req, res, next) {
 res.status(200).send('Hello ' + req.param('name'));
}

const app = express();
app.get('/', hasName, sayHello);

app.listen(3000);
console.log('Server running at http://localhost:3000/');
```

在上面的代码中，有两个名为`hasName()`和`sayHello()`的中间件函数。`hasName()`中间件正在寻找`name`参数；如果找到了定义的`name`参数，它将使用 next 参数调用下一个中间件函数。否则，`hasName()`中间件将自己处理响应。在这种情况下，下一个中间件函数将是`sayHello()`中间件函数。这是可能的，因为我们使用`app.get()`方法将中间件函数按顺序添加。还值得注意的是中间件函数的顺序，因为它决定了哪个中间件函数首先执行。

这个例子很好地演示了路由中间件如何在确定响应时执行不同的验证。当然，你可以利用这个功能来执行其他任务，比如验证用户身份验证和资源授权。不过，现在让我们继续我们的例子。

#### 添加路由文件

你接下来要创建的文件是你的第一个路由文件。在`app/routes`文件夹中，创建一个名为`index.server.routes.js`的文件，其中包含以下代码片段：

```js
module.exports = function(app) {
    const index = require('../controllers/index.server.controller');
 app.get('/', index.render);
};
```

在这里，你做了一些事情。首先，你再次使用了 CommonJS 模块模式。你可能还记得，CommonJS 模块模式支持导出多个函数，比如你在控制器中所做的，以及使用单个模块函数，就像你在这里所做的那样。接下来，你需要引入你的`index`控制器，并将其`render()`方法用作中间件来处理根路径的 GET 请求。

### 注意

路由模块函数接受一个名为`app`的参数，所以当你调用这个函数时，你需要传递 Express 应用程序的实例。

你所剩下的就是创建 Express 应用程序对象，并使用你刚刚创建的控制器和路由模块进行引导。为此，转到`config`文件夹，并创建一个名为`express.js`的文件，其中包含以下代码片段：

```js
const express = require('express');

module.exports = function() {
  const app = express();
 require('../app/routes/index.server.routes.js')(app);
  return app;
};
```

在上述代码片段中，您需要引入 Express 模块，然后使用 CommonJS 模块模式来定义一个`module`函数，该函数初始化 Express 应用程序。首先，它创建一个新的 Express 应用程序实例，然后需要您的路由文件并将其作为函数调用，将应用程序实例作为参数传递给它。路由文件将使用应用程序实例来创建新的路由配置，然后调用控制器的`render()`方法。`module`函数通过返回应用程序实例来结束。

### 注意

`express.js`文件是我们配置 Express 应用程序的地方。这是我们添加与 Express 配置相关的所有内容的地方。

要完成您的应用程序，您需要在根文件夹中创建一个名为`server.js`的文件，并复制以下代码：

```js
const configureExpress = require('./config/express');

const app = configureExpress();
app.listen(3000);
module.exports = app;

console.log('Server running at http://localhost:3000/');
```

就是这样！在主应用程序文件中，通过需要 Express 配置模块并使用它来检索您的应用程序对象实例，并侦听端口`3000`，您连接了所有松散的端点。

要启动您的应用程序，请使用`npm`在命令行工具中导航到您的应用程序的根文件夹，并安装您的应用程序依赖项，如下所示：

```js
$ npm install

```

安装过程结束后，您只需使用 Node 的命令行工具启动应用程序：

```js
$ node server 

```

您的 Express 应用程序现在应该可以运行了！要测试它，请导航到`http://localhost:3000`。

在这个例子中，您学会了如何正确构建您的 Express 应用程序。重要的是，您注意到了使用 CommonJS 模块模式创建文件并在整个应用程序中引用它们的不同方式。这种模式在本书中经常重复出现。

# 配置 Express 应用程序

Express 具有一个非常简单的配置系统，可以让您为 Express 应用程序添加某些功能。虽然有预定义的配置选项可以更改以操纵其工作方式，但您也可以为任何其他用途添加自己的键/值配置选项。Express 的另一个强大功能是根据其运行的环境配置应用程序。例如，您可能希望在开发环境中使用 Express 记录器，而在生产环境中不使用，同时在生产环境中压缩响应主体可能看起来是一个不错的主意。

为了实现这一点，您需要使用`process.env`属性。`process.env`是一个全局变量，允许您访问预定义的环境变量，最常见的是`NODE_ENV`环境变量。`NODE_ENV`环境变量通常用于特定环境的配置。为了更好地理解这一点，让我们回到之前的例子并添加一些外部中间件。要使用这些中间件，您首先需要将它们下载并安装为项目的依赖项。

要做到这一点，请编辑您的`package.json`文件，使其看起来像以下代码片段：

```js
{
  "name": "MEAN",
  "version": "0.0.3",
  "dependencies": {
 "body-parser": "1.15.2",
 "compression": "1.6.0",
    "express": "4.14.0",
 "method-override": "2.3.6",
 "morgan": "1.7.0"
  }
}
```

正如我们之前所述，`morgan`模块提供了一个简单的日志记录中间件，`compression`模块提供了响应压缩，`body-parser`模块提供了几个中间件来处理请求数据，`method-override`模块提供了`DELETE`和`PUT` HTTP 动词的旧版本支持。要使用这些模块，您需要修改您的`config/express.js`文件，使其看起来像以下代码片段：

```js
const express = require('express');
const morgan = require('morgan');
const compress = require('compression');
const bodyParser = require('body-parser');
const methodOverride = require('method-override');

module.exports = function() {
  const app = express();

 if (process.env.NODE_ENV === 'development') {
 app.use(morgan('dev'));
 } else if (process.env.NODE_ENV === 'production') {
 app.use(compress());
 }

 app.use(bodyParser.urlencoded({
 extended: true
 }));
 app.use(bodyParser.json());
 app.use(methodOverride());

  require('../app/routes/index.server.routes.js')(app);

  return app;
};
```

正如您所看到的，我们只是使用`process.env.NODE_ENV`变量来确定我们的环境，并相应地配置 Express 应用程序。我们只是使用`app.use()`方法在开发环境中加载`morgan()`中间件，在生产环境中加载`compress()`中间件。`bodyParser.urlencoded()`、`bodyParser.json()`和`methodOverride()`中间件将始终加载，无论环境如何。

要完成您的配置，您需要将您的`server.js`文件更改为以下代码片段：

```js
process.env.NODE_ENV = process.env.NODE_ENV || 'development';

const configureExpress = require('./config/express');

const app = configureExpress();
app.listen(3000);
module.exports = app;

console.log('Server running at http://localhost:3000/');
```

请注意，如果不存在，`process.env.NODE_ENV`变量将设置为默认的`development`值。这是因为通常`NODE_ENV`环境变量没有正确设置。

### 提示

建议在运行应用程序之前在操作系统中设置 NODE_ENV 环境变量。

在 Windows 环境中，您可以通过在命令提示符中执行以下命令来执行此操作：

```js
> set NODE_ENV=development
```

而在基于 Unix 的环境中，您应该简单地使用以下导出命令：

```js
$ export NODE_ENV=development
```

要测试您的更改，请使用`npm`导航到应用程序的根文件夹，并安装应用程序依赖项，如下所示：

```js
$ npm install

```

安装过程结束后，您只需使用 Node 的命令行工具启动应用程序：

```js
$ node server

```

您的 Express 应用程序现在应该运行！要测试它，请导航到`http://localhost:3000`，您将能够在命令行输出中看到记录器的操作。但是，当处理更复杂的配置选项时，`process.env.NODE_ENV`环境变量可以以更复杂的方式使用。

## 环境配置文件

在应用程序开发过程中，您经常需要配置第三方模块以在各种环境中以不同方式运行。例如，当连接到 MongoDB 服务器时，您可能会在开发和生产环境中使用不同的连接字符串。在当前设置中这样做可能会导致您的代码充斥着无尽的`if`语句，这通常会更难以维护。为了解决这个问题，您可以管理一组环境配置文件来保存这些属性。然后，您将能够使用`process.env.NODE_ENV`环境变量来确定要加载哪个配置文件，从而使您的代码更短，更易于维护。让我们首先为我们的默认开发环境创建一个配置文件。为此，请在`config/env`文件夹内创建一个新文件，并将其命名为`development.js`。在新文件中，粘贴以下代码：

```js
module.exports = {
  // Development configuration options
};
```

如您所见，您的配置文件目前只是一个空的 CommonJS 模块初始化。不用担心；我们很快将添加第一个配置选项，但首先，我们需要管理配置文件的加载。为此，请转到应用程序的`config`文件夹，并创建一个名为`config.js`的新文件。在新文件中，粘贴以下代码：

```js
module.exports = require('./env/' + process.env.NODE_ENV + '.js');
```

如您所见，此文件只是根据`process.env.NODE_ENV`环境变量加载正确的配置文件。在接下来的章节中，我们将使用此文件，它将为我们加载正确的环境配置文件。要管理其他环境配置，您只需要添加一个专门的环境配置文件，并正确设置`NODE_ENV`环境变量。

# 渲染视图

Web 框架的一个非常常见的特性是渲染视图的能力。基本概念是将数据传递给模板引擎，该引擎将渲染最终的视图，通常是 HTML。在 MVC 模式中，控制器使用模型来检索数据部分，并使用视图模板来渲染 HTML 输出，如下图所示。Express 可扩展的方法允许使用许多 Node.js 模板引擎来实现此功能。在本节中，我们将使用 EJS 模板引擎，但您可以随后将其替换为其他模板引擎。以下图表显示了渲染应用视图的 MVC 模式：

![渲染视图](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mean-webdev-2e/img/B05071_03_05.jpg)

Express 有两种方法来渲染视图：`app.render()`用于渲染视图然后将 HTML 传递给回调函数，更常见的是`res.render()`，它在本地渲染视图并将 HTML 作为响应发送。你将更频繁地使用`res.render()`，因为通常你希望将 HTML 输出为响应。不过，例如，如果你希望你的应用程序发送 HTML 电子邮件，你可能会使用`app.render()`。在我们开始探索`res.render()`方法之前，让我们先配置我们的视图系统。

## 配置视图系统

为了配置 Express 视图系统，你需要使用 EJS 模板引擎。让我们回到我们的示例并安装 EJS 模块。你应该首先更改你的`package.json`文件，使其看起来像以下代码片段：

```js
{
  "name": "MEAN",
  "version": "0.0.3",
  "dependencies": {
    "body-parser": "1.15.2",
    "compression": "1.6.0",
 "ejs": "2.5.2",
    "express": "4.14.0",
    "method-override": "2.3.6",
    "morgan": "1.7.0"  }
}
```

现在，通过在命令行中导航到项目的根文件夹并发出以下命令来安装 EJS 模块：

```js
$ npm update

```

在 npm 完成安装 EJS 模块后，你将能够配置 Express 将其用作默认模板引擎。要配置你的 Express 应用程序，回到`config/express.js`文件，并将其更改为以下代码行：

```js
const express = require('express');
const morgan = require('morgan');
const compress = require('compression');
const bodyParser = require('body-parser');
const methodOverride = require('method-override');

module.exports = function() {
  const app = express();
  if (process.env.NODE_ENV === 'development') {
    app.use(morgan('dev'));
  } else if (process.env.NODE_ENV === 'production') {
    app.use(compress());
  }

  app.use(bodyParser.urlencoded({
    extended: true
  }));
  app.use(bodyParser.json());
  app.use(methodOverride());

  app.set('views', './app/views');
  app.set('view engine', 'ejs');

  require('../app/routes/index.server.routes.js')(app);

  return app;
};
```

注意我们如何使用`app.set()`方法来配置 Express 应用程序的`view`文件夹和模板引擎。让我们创建你的第一个视图。

## 渲染 EJS 视图

EJS 视图基本上由 HTML 代码和`EJS`标签混合而成。EJS 模板将驻留在`app/views`文件夹中，并具有`.ejs`扩展名。当你使用`res.render()`方法时，EJS 引擎将在`views`文件夹中查找模板，如果找到符合的模板，它将渲染 HTML 输出。要创建你的第一个 EJS 视图，转到你的`app/views`文件夹，并创建一个名为`index.ejs`的新文件，其中包含以下 HTML 代码片段：

```js
<!DOCTYPE html>
<html>
  <head>
    <title><%= title %></title>
  </head>
  <body>
    <h1><%= title %></h1>
  </body>
</html>
```

这段代码对你来说应该大部分都很熟悉，除了`<%= %>`标签。这些标签是告诉 EJS 模板引擎在哪里渲染模板变量的方式——在这种情况下是`title`变量。你所要做的就是配置你的控制器来渲染这个模板，并自动将其输出为 HTML 响应。要做到这一点，回到你的`app/controllers/index.server.controller.js`文件，并将其更改为以下代码片段的样子：

```js
exports.render = function(req, res) {
  res.render('index', {
    title: 'Hello World'
  });
};
```

注意`res.render()`方法的使用方式。第一个参数是你的 EJS 模板的名称，不包括`.ejs`扩展名，第二个参数是一个包含你的模板变量的对象。`res.render()`方法将使用 EJS 模板引擎在我们在`config/express.js`文件中设置的`views`文件夹中查找文件，然后使用模板变量渲染视图。要测试你的更改，使用你的命令行工具并发出以下命令：

```js
$ node server

```

干得好，你刚刚创建了你的第一个 EJS 视图！通过访问`http://localhost:3000`来测试你的应用程序，在那里你将能够查看渲染的 HTML。

EJS 视图易于维护，并提供了一种简单的方式来创建你的应用程序视图。我们将在本书的后面详细介绍 EJS 模板，不过不会像你期望的那样多，因为在 MEAN 应用程序中，大部分的 HTML 渲染是在客户端使用 Angular 完成的。

# 提供静态文件

在任何 Web 应用程序中，总是需要提供静态文件。幸运的是，Express 的唯一内置中间件是`express.static()`中间件，它提供了这个功能。要将静态文件支持添加到前面的示例中，只需在你的`config/express.js`文件中进行以下更改：

```js
const express = require('express');
const morgan = require('morgan');
const compress = require('compression');
const bodyParser = require('body-parser');
const methodOverride = require('method-override');

module.exports = function() {
  const app = express();
  if (process.env.NODE_ENV === 'development') {
    app.use(morgan('dev'));
  } else if (process.env.NODE_ENV === 'production') {
    app.use(compress());
  }

  app.use(bodyParser.urlencoded({
    extended: true
  }));
  app.use(bodyParser.json());
  app.use(methodOverride());

  app.set('views', './app/views');
  app.set('view engine', 'ejs'); 

  require('../app/routes/index.server.routes.js')(app); 

  app.use(express.static('./public'));

  return app;
};
```

`express.static()`中间件接受一个参数来确定`static`文件夹的位置。注意`express.static()`中间件放置在路由文件调用下面。这个顺序很重要，因为如果它在上面，Express 首先会尝试在`static files`文件夹中查找 HTTP 请求路径。这会使响应变得更慢，因为它必须等待文件系统的 I/O 操作。

为了测试你的静态中间件，将一个名为`logo.png`的图片添加到`public/img`文件夹中，然后在你的`app/views/index.ejs`文件中做以下更改：

```js
<!DOCTYPE html>
<html>
  <head>
    <title><%= title %></title>
  </head>
  <body>
    <img src="img/logo.png" alt="Logo">
    <h1><%= title %></h1>
  </body>
</html>
```

现在，使用 Node 的命令行工具运行你的应用程序：

```js
$ node server

```

为了测试结果，访问`http://localhost:3000`，观察 Express 如何将你的图片作为静态文件提供。

# 配置会话

会话是一种常见的 Web 应用程序模式，允许你跟踪用户访问应用程序时的行为。要添加这个功能，你需要安装和配置`express-session`中间件。首先，修改你的`package.json`文件如下：

```js
{
  "name": "MEAN",
  "version": "0.0.3",
  "dependencies": {
    "body-parser": "1.15.2",
    "compression": "1.6.0",
    "ejs": "2.5.2",
    "express": "4.14.0",
 "express-session": "1.14.1",
    "method-override": "2.3.6",
    "morgan": "1.7.0"
  }
}
```

然后，通过在命令行中导航到项目的根文件夹并发出以下命令来安装`express-session`模块：

```js
$ npm update

```

安装过程完成后，你将能够配置你的 Express 应用程序使用`express-session`模块。`express-session`模块将使用一个存储在 cookie 中的签名标识符来识别当前用户。为了签署会话标识符，它将使用一个秘密字符串，这将有助于防止恶意会话篡改。出于安全原因，建议每个环境的 cookie 秘密都不同，这意味着这将是使用我们的环境配置文件的合适地方。为此，将`config/env/development.js`文件更改为以下代码片段的样子：

```js
module.exports = {
  sessionSecret: 'developmentSessionSecret'
};
```

由于这只是一个例子，可以随意更改秘密字符串。对于其他环境，只需在它们的环境配置文件中添加`sessionSecret`属性。要使用配置文件并配置你的 Express 应用程序，返回到你的`config/express.js`文件，并将其更改为以下代码片段的样子：

```js
const config = require('./config');
const express = require('express');
const morgan = require('morgan');
const compress = require('compression');
const bodyParser = require('body-parser');
const methodOverride = require('method-override');
const session = require('express-session');

module.exports = function() {
  const app = express();

  if (process.env.NODE_ENV === 'development') {
    app.use(morgan('dev'));
  } else if (process.env.NODE_ENV === 'production') {
    app.use(compress());
  }

  app.use(bodyParser.urlencoded({
    extended: true
  }));
  app.use(bodyParser.json());
  app.use(methodOverride());

  app.use(session({
    saveUninitialized: true,
    resave: true,
    secret: config.sessionSecret
  }));

  app.set('views', './app/views');
  app.set('view engine', 'ejs');

  app.use(express.static('./public'));

  require('../app/routes/index.server.routes.js')(app); 

  return app;
};
```

注意配置对象是如何传递给`express.session()`中间件的。在这个配置对象中，使用之前修改过的配置文件定义了`secret`属性。会话中间件将会话对象添加到应用程序中的所有请求对象中。使用这个会话对象，你可以设置或获取任何你希望在当前会话中使用的属性。为了测试会话，将`app/controller/index.server.controller.js`文件更改如下：

```js
exports.render = function(req, res) {
  if (req.session.lastVisit) {
    console.log(req.session.lastVisit);
  }

  req.session.lastVisit = new Date();

  res.render('index', {
    title: 'Hello World'
  });
};
```

你在这里做的基本上是记录最后一次用户请求的时间。控制器检查`session`对象中是否设置了`lastVisit`属性，如果设置了，就将最后访问日期输出到控制台。然后将`lastVisit`属性设置为当前时间。为了测试你的更改，使用 Node 的命令行工具运行你的应用程序，如下所示：

```js
$ node server

```

现在，通过在浏览器中访问`http://localhost:3000`并观察命令行输出来测试你的应用程序。

# 总结

在本章中，你创建了你的第一个 Express 应用程序，并学会了如何正确配置它。你将文件和文件夹组织成了一个有组织的结构，并发现了替代的文件夹结构。你还创建了你的第一个 Express 控制器，并学会了如何使用 Express 的路由机制调用它的方法。你渲染了你的第一个 EJS 视图，并学会了如何提供静态文件。你还学会了如何使用`express-session`来跟踪用户的行为。在下一章中，你将学会如何使用 MongoDB 保存你应用程序的持久数据。
