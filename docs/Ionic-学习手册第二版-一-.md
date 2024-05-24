# Ionic 学习手册第二版（一）

> 原文：[`zh.annas-archive.org/md5/2E3063722C921BA19E4DD3FA58AA6A60`](https://zh.annas-archive.org/md5/2E3063722C921BA19E4DD3FA58AA6A60)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

本书解释了如何使用 Ionic 轻松构建混合移动应用。无论是与 REST API 集成的简单应用，还是涉及原生功能的复杂应用，Ionic 都提供了简单的 API 来处理它们。

凭借对网页开发和 TypeScript 的基本知识，以及对 Angular 的良好了解，一个人可以轻松地将百万美元的创意转化为一款只需几行代码的应用。

在本书中，我们将探讨如何实现这一点。

# 本书涵盖的内容

第一章，*Angular - 入门*，向您介绍全新 Angular 的强大功能。我们将了解 TypeScript 的基础知识和理解 Angular 所需的概念。我们将学习 Angular 模块、组件和服务，并通过构建一个应用来结束本章。

第二章，*欢迎使用 Ionic*，介绍了名为 Cordova 的混合移动框架。它展示了 Ionic 如何融入混合移动应用开发的大局。本章还介绍了使用 Ionic 进行应用开发所需的软件。

第三章，*Ionic 组件和导航*，带您了解 Ionic 的各种组件，从页眉到导航栏。我们还将学习使用 Ionic Framework 在页面之间进行导航。

第四章，*Ionic 装饰器和服务*，探讨了我们用于初始化各种 ES6 类的装饰器。我们还将学习平台服务、配置服务以及其他一些内容，以更好地理解 Ionic。

第五章，*Ionic 和 SCSS*，讨论了如何利用内置的 SCSS 支持为 Ionic 应用设置主题。

第六章，*Ionic Native*，展示了 Ionic 应用如何使用 Ionic Native 与设备功能如相机和电池进行接口交互。

第七章，*构建 Riderr 应用*，展示了本书如何构建一个端到端的应用，该应用可以使用本书迄今为止所学的知识与设备 API 和 REST API 进行接口交互。我们将构建的应用将是 Uber API 的前端。使用这个应用，用户可以预订 Uber 车辆。

第八章，*Ionic 2 迁移指南*，展示了如何将使用 Ionic Framework v1 构建的 Ionic 应用迁移到 Ionic 2，并且相同的方法也适用于 Ionic 3。

第九章，*测试 Ionic 2 应用*，将带您了解测试 Ionic 应用的各种方法。我们将学习单元测试、端到端测试、monkey 测试以及使用 AWS Device Farm 进行设备测试。

第十章，*发布 Ionic 应用*，展示了如何使用 Ionic CLI 和 PhoneGap Build 生成 Cordova 和 Ionic 构建的应用的安装程序。

第十一章，*Ionic 3*，讨论了升级到 Angular 4 和 Ionic 3 的内容。我们还将了解 Ionic 3 的一些新功能。

附录，展示了如何有效地使用 Ionic CLI 和 Ionic 云服务来构建、部署和管理您的 Ionic 应用。

# 本书所需的内容

要开始构建 Ionic 应用，您需要对 Web 技术、TypeScript 和 Angular 有基本的了解。对移动应用开发、设备原生功能和 Cordova 的良好了解是可选的。

您需要安装 Node.js、Cordova CLI 和 Ionic CLI 才能使用 Ionic 框架。如果您想要使用设备功能，如相机或蓝牙，您需要在您的设备上设置移动操作系统。

本书旨在帮助那些想要学习如何使用 Ionic 构建移动混合应用程序的人。它也非常适合想要使用 Ionic 应用程序主题、集成 REST API，并了解更多关于设备功能（如相机、蓝牙）的人。

对 Angular 的先前了解对于成功完成本书至关重要。

# 约定

在本书中，您将找到许多文本样式，用于区分不同类型的信息。以下是一些这些样式的示例及其含义的解释。

文本中的代码单词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下：“TypeScript 文件保存为`.ts`扩展名。”

代码块设置如下：

```html
x = 20; 
// after a few meaningful minutes  
x = 'nah! It's not a number any more';

```

任何命令行输入或输出都以以下方式编写：

```html
npm install -g @angular/cli

```

**新术语**和**重要单词**以粗体显示。您在屏幕上看到的单词，例如菜单或对话框中的单词，会在文本中出现，就像这样：“我们将编写三种方法，一种用于获取随机 gif，一种用于获取最新趋势，一种用于使用关键字搜索 Gif API。”

警告或重要说明以以下方式显示。

提示和技巧会以这种方式出现。


# 第一章：Angular - 入门

当 Timothy Berners-Lee 爵士发明互联网时，他从未想到互联网会被用来发布自拍照、分享猫视频或用广告轰炸网页。他的主要意图（猜测）是创建一个文档网络，以便互联网上的用户可以从任何地方访问这些超文本并加以利用。

Sitepoint 的 Craig Buckler 发表的一篇有趣的文章，标题为《网络磁盘空间不足》（[`www.sitepoint.com/web-runs-disk-space/`](http://www.sitepoint.com/web-runs-disk-space/)），展示了互联网上的内容是如何分布的：

+   28.65％的猫图片

+   16.80％的自恋自拍

+   14.82％毫无意义的社交媒体闲聊

+   12.73％愚蠢的视频博主视频

+   9.76％的广告/点击诱导页面

+   8.70％的欺诈和骗局

+   4.79％的虚假统计文章

+   3.79％的新 JavaScript 工具/库

+   0.76％的文件，以改善人类知识

您可以看到，从互联网的发明到现在，我们是如何演变的。*更好的演变需要更好的框架*来构建和管理这样的应用程序，这些应用程序需要可扩展、可维护和可测试。这就是 2010 年 Angular 填补空白的地方，自那时以来它一直在不断发展。

我们将从理解 Angular 的新变化、TypeScript 的重要性开始我们的旅程，并看看 Ionic 2 如何与 Angular 一起适应，以帮助构建性能高效和现代的移动混合应用程序。

在本章中，我们将通过一个示例快速了解 Angular 的新主题。Angular（2）中发生的主要变化主要是性能和组件化，除了语言更新。在本章中，我们将介绍以下主题：

+   Angular 有什么新东西？

+   TypeScript 和 Angular

+   构建 Giphy 应用程序

# Angular 有什么新东西？

Angular 2 是我见过的软件最受期待和最戏剧性的版本升级之一。Angular 1 对于 Web/移动 Web/混合应用程序开发人员来说是一个福音，它使许多事情变得容易。Angular 1 不仅帮助重构客户端应用程序开发，而且提供了构建应用程序的平台；不是网站，而是应用程序。尽管第一个版本在处理大型数据集时存在性能问题，但 Angular 团队在随后的 Angular 1.4.x 及以上版本中取得了相当大的进展，并通过发布更稳定的版本（即 Angular 2）解决了这些性能问题。

一些伴随 Angular（2）的新变化是：

+   速度和性能改进。

+   基于组件（而不是典型的 MV*）。

+   Angular CLI。

+   简单而富有表现力的语法。

+   渐进式 Web 应用程序（PWA）。

+   跨平台应用程序开发，包括桌面、移动和 Web。

+   基于 Cordova 的混合应用程序开发。

+   用于快速初始视图的 Angular Universal 提供程序。

+   升级以获得更好的动画、国际化和可访问性。

+   Angular 可以用 ES5、ES6、TypeScript 和 Dart 编写，根据用户对 JavaScript 口味的喜好。

有了这些新的更新，无论是在桌面、移动还是移动混合环境上，开发应用程序都变得更加容易。

注意：最新版本的 Angular 将被称为 Angular，而不是 Angular 2，或 AngularJS 4，或 NG4。因此，在本书中，我将把 Angular 版本 2 称为 Angular。

目前最新版本的 Angular 是 4。请查看第十一章，*Ionic 3*，了解更多关于 Angular 4 及其如何改进 Ionic 的信息。

您可以在这里找到有关 Angular 的更多信息：[`angular.io`](https://angular.io)。

注意：如果您是 Angular 的新手，可以参考这些书籍：

[`www.packtpub.com/web-development/learning-angular-2`](https://www.packtpub.com/web-development/learning-angular-2)

[`www.packtpub.com/web-development/mastering-angular-2-components`](https://www.packtpub.com/web-development/mastering-angular-2-components)

[`www.packtpub.com/web-development/mastering-angular-2`](https://www.packtpub.com/web-development/mastering-angular-2)

[`www.packtpub.com/web-development/angular-2-example`](https://www.packtpub.com/web-development/angular-2-example)

或者这些视频：

[`www.packtpub.com/web-development/angular-2-projects-video`](https://www.packtpub.com/web-development/angular-2-projects-video)

[`www.packtpub.com/web-development/web-development-angular-2-and-bootstrap-video`](https://www.packtpub.com/web-development/web-development-angular-2-and-bootstrap-video)

[`www.packtpub.com/web-development/angular-2-web-development-TypeScript-video`](https://www.packtpub.com/web-development/angular-2-web-development-TypeScript-video)

# TypeScript 入门

Angular 在应用程序开发中广泛使用 TypeScript。因此，作为 Angular 入门的一部分，我们也将复习必要的 TypeScript 概念。

如果你是 TypeScript 的新手，TypeScript 是 JavaScript 的一种带类型的超集，可以编译成普通的 JavaScript。TypeScript 提供静态类型、类和接口，并支持几乎所有 ES6 和 ES7 的特性，这些特性在浏览器中还没有实现。

TypeScript 文件保存为`.ts`扩展名。

为无类型语言（JavaScript）添加类型的主要优势是让 IDE 理解我们尝试做的事情，并在编码时更好地帮助我们；换句话说，智能感知。

说到这一点，这就是我们可以用 TypeScript 做的事情。

# 变量类型

在纯 JavaScript 中，我们会做类似这样的事情：

```html
x = 20; 
// after a few meaningful minutes  
x = 'nah! It's not a number any more';

```

但是在 TypeScript 中，我们不能像前面的代码片段中所示那样做，TypeScript 编译器会抱怨，因为我们在运行时修改了变量类型。

# 定义类型

当我们声明变量时，可以选择声明变量的类型。例如：

```html
name: string = 'Arvind'; 
age: number  = 99; 
isAlive: boolean = true; 
hobbies: string[]; 
anyType: any; 
noType = 50; 
noType = 'Random String';

```

这增加了我们尝试做的事情的可预测性。

# 类

我是一个相信 JavaScript 是基于对象的编程语言而不是面向对象编程语言的人，我知道有很多人不同意我的观点。

在纯 JavaScript 中，我们有函数，它们就像类，并展示基于原型的继承。在 TypeScript/ES6 中，我们有类构造：

```html
class Person { 
  name: string; 

constructor(personName: string) {  
this.name = personName;  
} 

getName { 
    return "The Name: " + this.greeting; 
}   
} 
// somewhere else 
arvind:Person = new Person('Arvind');

```

在上面的例子中，我们定义了一个名为 Person 的类，并定义了类构造函数，在类初始化时接受名称。

要初始化类，我们将使用 new 关键字调用类，并将名称传递给构造函数。存储类实例的变量——在上面的例子中是对象`arvind`，也可以被赋予类的类型。这有助于更好地理解`arvind`对象的可能性。

注意：ES6 中的类仍然遵循基于原型的继承，而不是经典的继承模型。

# 接口

当我们开始构建复杂的应用程序时，通常会需要一种特定类型的结构在整个应用程序中重复出现，这遵循某些规则。这就是接口的作用。接口提供*结构子类型*或*鸭子类型*来检查实体的类型和*形状*。

例如，如果我们正在开发一个涉及汽车的应用程序，每辆汽车都有一定的共同结构，在应用程序中使用时需要遵守这个结构。因此，我们创建一个名为 ICar 的接口。任何与汽车相关的类都将按照以下方式实现这个接口：

```html
Interface ICar { 
  engine : String; 
  color: String; 
  price : Number; 
} 

class CarInfo implements ICar{ 
  engine : String; 
  color: String; 
  price : Number; 

  constructor(){ /* ... */} 
}

```

# 模块和导入

在纯 JavaScript 中，你可能会观察到这样的代码块：

```html
(function(){ 
  var x = 20; 
  var y = x * 30; 
})(); //IIFE 
// x & y are both undefined here.

```

在 ES6/TS 中，使用导入和导出语法实现模块：

```html
logic.ts
export function process(){ 
  x = 20; 
  y = x * 30; 
} 

exec.ts 
import { process } from './logic'; 
process();

```

这些是我们开始使用 TypeScript 所需的基本要素。我们将在需要时查看更多类似的概念。

通过这些概念，我们结束了开始使用 TypeScript 所需的关键概念。让我们开始学习 Angular。

有关 TypeScript 的更多信息，请查看：[`www.typescriptlang.org/docs/tutorial.html`](https://www.typescriptlang.org/docs/tutorial.html)。还可以查看 TypeScript 介绍视频：[`channel9.msdn.com/posts/Anders-Hejlsberg-Introducing-TypeScript`](https://channel9.msdn.com/posts/Anders-Hejlsberg-Introducing-TypeScript)。

# Angular

Angular（2）添加了许多新功能，并更新了现有功能，并删除了一些 Angular 1.x 中的功能。在本节中，我们将介绍一些 Angular 的基本功能。

# 组件

Angular 组件受到 Web 组件规范的启发。在非常高的层面上，Web 组件有四个部分：

+   **自定义元素**：用户可以创建自己的 HTML 元素。

+   **HTML 导入**：将一个 HTML 文档导入到另一个 HTML 文档中。

+   **模板**：自定义元素的 HTML 定义。

+   **Shadow DOM**：编写自定义元素封装逻辑的规范。

前面四个规范解释了前端开发人员如何开发自己的独立、隔离和可重用组件，类似于 HTML 选择框（`<select></select>`）、文本区域（`<textarea></textarea>`）或输入框（`<input />`）。

您可以在此处阅读有关 Web 组件规范的更多信息：[`www.w3.org/standards/techs/components#w3c_all`](https://www.w3.org/standards/techs/components#w3c_all)。

如果您想深入了解 Web 组件，请查看：[`webcomponents.org/`](http://webcomponents.org/)。

如前所述，Angular（宽松地）是构建在 Web 组件上的，前面四个规范是以 Angular 方式实现的。

简单来说，我们整个应用程序是一个组件树。例如，如果我们看世界上最受欢迎的页面[`www.google.com`](https://www.google.com)，它可能看起来像这样：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00005.jpeg)

如果我们必须在 Angular 中构建此页面，我们首先会将页面拆分为组件。

前面页面中的所有组件的可视表示如下：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00006.jpeg)

注意：每个黑色框都是（自定义）组件。

从前面的图中可以看出，整个页面是一棵自定义组件树。

（自定义）组件通常由三部分组成：

+   `component.ts`：表示组件逻辑

+   `component.html`：表示组件视图（模板）

+   `component.css`：表示组件特定的样式

要构建自定义组件，我们需要在类的顶部使用`Component`装饰器。简单来说，装饰器让我们可以在类上配置特定的元数据。然后 Angular 将使用这些元数据来理解该类的行为。装饰器以`@`开头，后面跟着装饰器的名称。

组件装饰器告诉 Angular 正在处理的类需要表现出 Angular 组件的行为。一个简单的装饰器如下所示：

```html
@Component({ 
  selector: 'app-root', 
  templateUrl: './app.component.html', 
  styleUrls: ['./app.component.css'] 
}) 
export class AppComponent { 
  // This is where we write the component logic! 
  title = 'Hello World!'; 
}

```

组件装饰器中包含的一些属性有：

+   `selector`：在模板中标识此组件的 CSS 选择器

+   `templateUrl`：包含视图模板的外部文件的 URL

+   `styleUrls`：要应用于此组件视图的样式表的 URL 列表

+   `providers`：此组件及其子组件可用的提供者列表

要了解有关 Component 装饰器的更多信息，请参阅以下链接：[`angular.io/docs/ts/latest/api/core/index/Component-decorator.html`](https://angular.io/docs/ts/latest/api/core/index/Component-decorator.html)

# 区域

区域是 Angular 中引入的新概念之一。区域的概念是从 Dart 迁移到 JavaScript 的。

许多开发人员最初被 Angular 吸引的主要原因是其*自动数据绑定*，以及其他一些原因。这是通过在 Angular 1.x 中使用作用域来实现的。在 Angular 2 中，我们使用 Zone.js（[`github.com/angular/zone.js`](https://github.com/angular/zone.js)）来实现相同的功能。

每当数据发生变化时，Angular 会使用新数据更新适当的*利益相关者*（变量、接口、提供程序等）。Angular 可以轻松跟踪所有同步活动。但是对于异步代码的变化检测，例如事件处理、AJAX 调用或计时器，Angular 2 使用 Zone.js。

要了解有关区域的更多信息，以及它们的工作方式和在 Angular 中的变化检测，请查看 Angular 中的区域：[`blog.thoughtram.io/angular/2016/02/01/zones-in-angular-2.html`](http://blog.thoughtram.io/angular/2016/02/01/zones-in-angular-2.html)和解释 Angular 变化检测：[`blog.thoughtram.io/angular/2016/02/22/angular-2-change-detection-explained.html`](http://blog.thoughtram.io/angular/2016/02/22/angular-2-change-detection-explained.html)。

# 模板

模板用于将组件逻辑绑定到 HTML。模板还用作用户交互和应用逻辑之间的接口。

与 Angular 1 版本相比，模板已经发生了相当大的变化。但是仍然有一些事情保持不变。例如，我们从组件中获取值并在用户界面中显示它的方式仍然相同，使用双大括号表示法（插值语法）。

以下是一个`app.component.ts`的示例：

```html
@Component({ 
  selector: 'app-root', 
  templateUrl: './app.component.html', 
  styleUrls: ['./app.component.css'] 
}) 
export class AppComponent { 
  // This is where we write the component logic! 
  title = 'Hello World!'; 
}

```

`app.component.html`可能如下所示：

```html
<h1>
{{title}} <!-- This value gets bound from app.component.ts -->
</h1>

```

模板也可以通过将模板元数据传递给装饰器而不是`templateUrl`来内联。这可能如下所示：

```html
 @Component({ 
  selector: 'app-root', 
  template: '<h1>{{title}}</h1>', 
  styleUrls: ['./app.component.css'] 
}) 
export class AppComponent { 
  // This is where we write the component logic! 
  title = 'Hello World!'; 
}

```

`template`元数据优先级高于`templateUrl`。例如，如果我们同时定义了`template`和`templateUrl`元数据，将选择并呈现`template`。

我们还可以使用反引号（`）而不是引号在 ES6 和 TypeScript 中编写多行模板。有关更多信息，请参阅模板文字：[`developer.mozilla.org/en/docs/Web/JavaScript/Reference/Template_literals`](https://developer.mozilla.org/en/docs/Web/JavaScript/Reference/Template_literals)

在 Angular 1.x 中，我们有核心/自定义指令。但是在 Angular（2）中，我们有各种表示法，使用这些表示法可以实现与 Angular 1 中指令相同的行为。

例如，如果我们想根据表达式的真值向元素添加自定义类，它会是这样的：

```html
<div [class.highlight]="shouldHighlight">Hair!</div>

```

上述是著名的`ng-class` Angular 1.x 指令的替代品。

为了处理事件，我们使用`( )`表示法，如下所示：

```html
<button (click)=pullHair($event)">Pull Hair</button>

```

而且`pullhair()`是在组件类内部定义的。

为了保持数据绑定最新，我们使用`[( )]`表示法，如下所示：

```html
<input type="text" [(ngModel)]="name">

```

这使得组件类中的名称属性与文本框同步。

这里显示了`*ngFor`的示例，它是`ng-repeat`的替代品：

```html
<ul> 
  <li *ngFor="let todo in todos">{{todo.title}}</li> 

</ul>

```

请注意，在`todo`前面的`let`表示它是该区域中的局部变量。

这些是我们需要开始实际示例的基本概念。当这些概念在我们的应用中出现时，我会谈论其他 Angular（2）的概念。

# Giphy 应用

利用我们迄今为止学到的概念，我们将使用 Angular 和一个名为 Giphy 的开放 JSON API 提供程序构建一个简单的应用。

Giphy（[`giphy.com`](http://giphy.com)）是一个简单的 Gif 搜索引擎。Giphy 的人们公开了一个我们可以使用和处理数据的开放 REST API。

我们要构建的应用将与 Giphy JSON API 通信并返回结果。使用 Angular，我们将为应用中的三个功能构建接口：

+   显示一个随机 Gif

+   显示趋势 Gifs

+   搜索 Gif

我们将使用 Angular CLI（[`cli.angular.io/`](https://cli.angular.io/)）和 Twitter Bootstrap（[`getbootstrap.com/`](http://getbootstrap.com/)）与 Cosmos 主题（[`bootswatch.com/cosmo/`](https://bootswatch.com/cosmo/)）。

在我们开始构建应用之前，让我们首先了解应用的结构。

# 架构

我们要看的第一件事是应用程序的架构。在客户端，我们将有一个路由器，所有事情都将从那里开始流动。路由器将有四个路由：

+   主页路由

+   浏览路由

+   搜索路由

+   页面未找到路由

我们将有一个服务，其中有三种方法将与 Giphy REST API 交互。

除了前面提到的项目，我们还将有以下组件：

+   **导航组件**：应用程序导航栏

+   **主页组件**：主页，显示随机 gif

+   **趋势组件**：显示趋势 gif

+   **搜索组件**：搜索 gif

+   **Giphy 组件**：gif 模板

+   **页面未找到组件**：显示告诉用户未找到任何内容的页面

此应用程序的组件树如下所示：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00007.jpeg)

# API

Giphy API 相当容易理解和使用。您可以在这里找到官方 API 文档：[`github.com/Giphy/GiphyAPI`](https://github.com/Giphy/GiphyAPI)。

我们将要使用的 API 是：

+   随机 Gif：[`api.giphy.com/v1/gifs/random?api_key=dc6zaTOxFJmzC`](http://api.giphy.com/v1/gifs/random?api_key=dc6zaTOxFJmzC)

+   趋势 Gifs：[`api.giphy.com/v1/gifs/trending?api_key=dc6zaTOxFJmzC`](http://api.giphy.com/v1/gifs/trending?api_key=dc6zaTOxFJmzC)

+   搜索 Gifs：[`api.giphy.com/v1/stickers/search?q=cat&api_key=dc6zaTOxFJmzC`](http://api.giphy.com/v1/stickers/search?q=cat&api_key=dc6zaTOxFJmzC)

您可以转到上述链接以查看示例数据。

在撰写本文时，Giphy 公开了`dc6zaTOxFJmzC`作为要使用的 API 密钥。

# Angular CLI

为了开发我们的 Giphy 应用程序，我们将使用 Angular CLI。如果您对 CLI 及其功能不熟悉，我建议您观看此视频：使用 Angular CLI 创建简单的 Angular 2 应用程序：[`www.youtube.com/watch?v=QMQbAoTLJX8`](https://www.youtube.com/watch?v=QMQbAoTLJX8)。

此示例是使用 Angular CLI 版本 1.0.0-beta.18 编写的。

# 安装软件

为了成功开发 Angular-Giphy 应用程序，我们需要安装 Node.js ([`nodejs.org/en`](https://nodejs.org/en))。我们将使用 NPM ([`www.npmjs.com`](https://www.npmjs.com)) 通过 Angular CLI 下载所需的模块。

安装 Node.js 后，打开新的命令提示符/终端，然后运行以下命令：

```html
npm install -g @angular/cli

```

这将继续安装 Angular CLI 生成器。这是我们开始开发应用程序所需的全部内容。

注意：我使用了 angular-cli 版本 1.0.0 构建此应用程序。

# 文本编辑器

关于文本编辑器，您可以使用任何编辑器来处理 Angular 和 Ionic。您还可以尝试 Sublime text ([`www.sublimetext.com/3`](http://www.sublimetext.com/3)) 或 Atom 编辑器 ([`atom.io/`](https://atom.io/)) 或 Visual Studio Code ([`code.visualstudio.com/`](https://code.visualstudio.com/)) 来处理代码。

如果您使用 Sublime text，可以查看：[`github.com/Microsoft/TypeScript-Sublime-Plugin`](https://github.com/Microsoft/TypeScript-Sublime-Plugin) 以在编辑器中添加 TypeScript 智能。对于 Atom，请参阅以下链接：[`atom.io/packages/atom-TypeScript`](https://atom.io/packages/atom-typescript)。

# 搭建一个 Angular 2 应用程序

首先，我们要做的是使用 Angular CLI 搭建一个 Angular 应用程序。创建一个名为`chapter1`的新文件夹，并在该文件夹中打开命令提示符/终端，然后运行以下命令：

```html
ng new giphy-app

```

现在，Angular CLI 生成器将继续创建所有必要的文件和文件夹，以便与我们的 Angular 应用程序一起使用。

如前所述，您可以查看使用 Angular CLI 创建简单的 Angular 2 应用程序：[`www.youtube.com/watch?v=QMQbAoTLJX8`](https://www.youtube.com/watch?v=QMQbAoTLJX8)，也可以查看 Angular CLI 文档：[`cli.angular.io/reference.pdf`](https://cli.angular.io/reference.pdf) 了解更多信息。

脚手架项目结构如下所示：

```html
. 
├── .angular-cli.json 
├── .editorconfig 
├── README.md 
├── e2e 
│   ├── app.e2e-spec.ts 
│   ├── app.po.ts 
│   ├── tsconfig.e2e.json 
├── karma.conf.js 
├── node_modules 
├── package.json 
├── protractor.conf.js 
├── src 
│   ├── app 
│   │   ├── app.component.css 
│   │   ├── app.component.html 
│   │   ├── app.component.spec.ts 
│   │   ├── app.component.ts 
│   │   ├── app.module.ts 
│   ├── assets 
│   │   ├── .gitkeep 
│   ├── environments 
│   │   ├── environment.prod.ts 
│   │   ├── environment.ts 
│   ├── favicon.ico 
│   ├── index.html 
│   ├── main.ts 
│   ├── polyfills.ts 
│   ├── styles.css 
│   ├── test.ts 
│   ├── tsconfig.app.json 
│   ├── tsconfig.spec.json 
│   ├── typings.d.ts 
├── tsconfig.json 
├── tslint.json

```

我们将大部分时间花在`src`文件夹内。一旦项目完全搭建好，进入`giphy-app`文件夹并运行以下命令：

```html
ng serve

```

这将启动内置服务器。构建完成后，我们可以导航到[`localhost:4200`](http://localhost:4200)查看页面。页面应该看起来像这样：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00008.jpeg)

# 构建 Giphy 应用程序

现在我们已经准备好开始了，我们将首先向应用程序添加 Twitter Bootstrap CSS。

在这个例子中，我们将使用来自[`bootswatch.com/`](https://bootswatch.com/)的 Bootstrap 主题 Cosmos。我们可以在主题页面上找到 Cosmos CSS 主题：[`bootswatch.com/cosmo/`](https://bootswatch.com/cosmo/)，点击 Cosmos 下拉菜单，选择`bootstrap.min.css`选项。或者，我们也可以在这里找到它：[`bootswatch.com/cosmo/bootstrap.min.css`](https://bootswatch.com/cosmo/bootstrap.min.css)。

如果你愿意，你也可以使用任何其他主题或原始的 Bootstrap CSS。

要添加主题文件，导航到`giphy-app/src/styles.css`并在其中添加以下行：

```html
@import "https://bootswatch.com/cosmo/bootstrap.min.css";

```

就是这样，现在我们的应用程序已经使用了 Twitter Bootstrap CSS。

接下来，我们将开始处理应用程序的主页面。为此，我们将利用 Twitter Bootstrap 的一个示例模板，名为 Starter Template。模板可以在这里找到：[`getbootstrap.com/examples/starter-template/`](http://getbootstrap.com/examples/starter-template/)。

起始模板包括一个导航栏和一个主体部分，其中显示内容。

对于导航栏部分，我们将生成一个名为`nav-bar`的新组件，并更新其中的相关代码。

要使用 Angular CLI 生成一个新的自定义组件，导航到`giphy-app`文件夹并运行以下命令：

```html
ng generate component nav-bar

```

注意：你可以终止当前运行的命令，或者生成一个新的命令提示符/终端来运行前面的命令。

你应该看到类似这样的东西：

```html
create src/app/nav-bar/nav-bar.component.css
create src/app/nav-bar/nav-bar.component.html
create src/app/nav-bar/nav-bar.component.spec.ts
create src/app/nav-bar/nav-bar.component.ts
update src/app/app.module.ts

```

现在打开`giphy-app/src/app/nav-bar/nav-bar.component.html`并更新如下：

```html
<nav class="navbar navbar-inverse navbar-fixed-top"> 
    <div class="container"> 
        <div class="navbar-header"> 
            <a class="navbar-brand" [routerLink]="['/']">Giphy App</a> 
        </div> 
        <div id="navbar" class="collapse navbar-collapse"> 
            <ul class="nav navbar-nav"> 
                <li [routerLinkActive]="['active']"><a [routerLink]="
                  ['/trending']">Trending</a></li> 
                <li [routerLinkActive]="['active']"><a [routerLink]="
                  ['/search']">Search</a></li> 
            </ul> 
        </div> 
    </div> 
</nav>

```

我们在这里所做的一切就是创建一个带有两个菜单项和应用程序名称的标题栏，它作为指向主页的链接。

接下来，我们将更新`giphy-app/src/app/app.component.html`以加载`nav-bar`组件。用以下内容替换该文件的内容：

```html
<nav-bar></nav-bar>

```

接下来，我们将开始向应用程序添加路由。如前所述，我们将有三个路由。

为了为当前应用程序添加路由支持，我们需要做三件事：

1.  创建所需的路由。

1.  配置`@NgModule`。

1.  告诉 Angular 在哪里加载这些路由的内容。

在撰写本文时，Angular CLI 已禁用了路由生成。因此，我们将手动创建相同的路由。否则，我们可以简单地运行`ng generate route home`来生成主页路由。

所以首先，让我们定义所有的路由。在 app 文件夹内创建一个名为`app.routes.ts`的新文件。更新文件如下：

```html
import { HomeComponent } from './home/home.component'; 
import { TrendingComponent } from './trending/trending.component'; 
import { SearchComponent } from './search/search.component'; 
import { PageNotFoundComponent } from './page-not-found/page-not-found.component'; 

export const ROUTES = [ 
  { path: '', component: HomeComponent }, 
  { path: 'trending', component: TrendingComponent }, 
  { path: 'search', component: SearchComponent }, 
  { path: '**', component: PageNotFoundComponent } 
];

```

我们所做的一切就是导出一个路由数组。请注意路径`'**'`。这是我们定义路由的另一部分。

现在我们将创建所需的组件。运行以下命令：

```html
ng generate component home
ng generate component trending
ng generate component search
ng generate component pageNotFound

```

接下来，我们将配置`@NgModule`。打开`giphy-app/src/app/app.module.ts`并在顶部添加以下导入：

```html
import { RouterModule }   from '@angular/router'; 
import { ROUTES } from './app.routes';

```

接下来，更新`@NgModule`装饰器的`imports`属性如下：

```html
//.. snipp 
imports: [ 
    BrowserModule, 
    FormsModule, 
    HttpModule, 
    RouterModule.forRoot(ROUTES) 
  ], 
//.. snipp 

```

完成的页面将如下所示：

```html
import { BrowserModule } from '@angular/platform-browser'; 
import { NgModule } from '@angular/core'; 
import { FormsModule } from '@angular/forms'; 
import { HttpModule } from '@angular/http'; 
import { RouterModule }   from '@angular/router'; 

import { AppComponent } from './app.component'; 
import { NavBarComponent } from './nav-bar/nav-bar.component'; 
import { HomeComponent } from './home/home.component'; 
import { TrendingComponent } from './trending/trending.component'; 
import { SearchComponent } from './search/search.component'; 
import { PageNotFoundComponent } from './page-not-found/page-not-found.component'; 

import { ROUTES } from './app.routes'; 

@NgModule({ 
  declarations: [ 
    AppComponent, 
    NavBarComponent, 
    HomeComponent, 
    TrendingComponent, 
    SearchComponent, 
    PageNotFoundComponent 
  ], 
  imports: [ 
    BrowserModule, 
    FormsModule, 
    HttpModule, 
    RouterModule.forRoot(ROUTES) 
  ], 
  providers: [], 
  bootstrap: [AppComponent] 
}) 
export class AppModule { }

```

现在我们将更新应用程序组件以显示导航栏以及当前路由内容。

更新`giphy-app/src/app/app.component.html`如下：

```html
<app-nav-bar></app-nav-bar> 
<router-outlet></router-outlet>

```

使用`router-outlet`，我们告诉路由器在该位置加载当前路由内容。

如果你想了解更多关于 Angular 中的路由，请查看：Brian Ford 的《Eleven Dimensions with Component Router》：[`www.youtube.com/watch?v=z1NB-HG0ZH4`](https://www.youtube.com/watch?v=z1NB-HG0ZH4)。

接下来，我们将更新主页组件的 HTML 并测试到目前为止的应用程序。

打开`giphy-app/src/app/home/home.component.html`并按以下方式更新它：

```html
<div class="container"> 
    <div class="starter-template"> 
        <h1>Giphy App</h1> 
        <p class="lead">This app uses the JSON API provided by Giphy to Browse and Search Gifs. 
            <br> To know more checkout : <a href="https://github.com/Giphy/GiphyAPI#trending-gifs-endpoint">Giphy API</a> </p> 
    </div> 
</div>

```

完成后，保存文件并运行以下命令：

```html
ng  serve

```

我们应该看到以下页面：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00009.jpeg)

如我们所见，页面看起来有问题。让我们通过添加一些样式来修复这个问题。打开`giphy-app/src/styles.css`并添加以下内容：

```html
body {
  padding-top: 50px; 
  padding-bottom: 20px; 
} 

.starter-template { 
  padding: 40px 15px; 
  text-align: center; 
}

```

现在我们的页面将如预期般显示：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00010.jpeg)

接下来，我们将开始编写服务以与 Giphy API 交互。我们将编写三种方法，一种用于获取随机 gif，一种用于获取最新趋势，一种用于使用关键字搜索 Gif API。

开始时，我们将生成一个服务。运行以下命令：

```html
ng generate service giphy

```

```html
WARNING Service is generated but not provided, it must be provided to be used

```

如警告所示，生成的服务尚未标记为提供者。因此，我们需要手动进行标记。

打开`giphy-app/src/app/app.module.ts`并导入`GiphyService`：

```html
import { GiphyService } from './giphy.service';

```

接下来，在`@NgModule`装饰器的`providers`属性中添加`GiphyService`作为提供者：

```html
//.. snipp 
providers: [ 
    GiphyService 
  ], 
//..snipp

```

完整的`giphy-app/src/app/app.module.ts`如下所示：

```html
import { BrowserModule } from '@angular/platform-browser'; 
import { NgModule } from '@angular/core'; 
import { FormsModule } from '@angular/forms'; 
import { HttpModule } from '@angular/http'; 
import { RouterModule }   from '@angular/router'; 

import { AppComponent } from './app.component'; 
import { NavBarComponent } from './nav-bar/nav-bar.component'; 
import { HomeComponent } from './home/home.component'; 
import { TrendingComponent } from './trending/trending.component'; 
import { SearchComponent } from './search/search.component'; 
import { PageNotFoundComponent } from './page-not-found/page-not-found.component'; 

import { ROUTES } from './app.routes'; 

import { GiphyService } from './giphy.service'; 

@NgModule({ 
  declarations: [ 
    AppComponent, 
    NavBarComponent, 
    HomeComponent, 
    TrendingComponent, 
    SearchComponent, 
    PageNotFoundComponent 
  ], 
  imports: [ 
    BrowserModule, 
    FormsModule, 
    HttpModule, 
    RouterModule.forRoot(ROUTES) 
  ], 
  providers: [ 
    GiphyService 
  ], 
  bootstrap: [AppComponent] 
}) 
export class AppModule { }

```

现在我们将更新`giphy-app/src/app/giphy.service.ts`以包含这三种方法。打开`giphy-app/src/app/giphy.service.ts`并按以下方式更新它：

```html
import { Injectable } from '@angular/core'; 
import { Http, Response, Jsonp } from '@angular/http'; 
import { Observable } from 'rxjs/Rx'; 
import 'rxjs/Rx'; 

@Injectable() 
export class GiphyService { 
  private giphyAPIBase = 'http://api.giphy.com/v1/gifs'; 
  private APIKEY = 'dc6zaTOxFJmzC'; 

  constructor(private http: Http) { } 

  getRandomGif(): Observable<Response> { 
    return this.http.get(this.giphyAPIBase + 
      '/random?api_key=' + this.APIKEY) 
      .map((res) => res.json()); 
  } 

  getTrendingGifs(offset, limit): Observable<Response> { 
    return this.http.get(this.giphyAPIBase + 
      '/trending?api_key=' + this.APIKEY + '&offset=' + offset + 
      '&limit=' + limit) 
      .map((res) => res.json()); 
  } 

  searchGifs(offset, limit, text): Observable<Response> { 
    return this.http.get(this.giphyAPIBase + '/search?api_key=' + 
      this.APIKEY + '&offset=' + offset + 
      '&limit=' + limit + '&q=' + text) 
      .map((res) => res.json()); 
  } 
}

```

我们所做的只是向相应的 Giphy API URL 发出 HTTP GET 请求并返回一个 Observable。

在 RxJS（[`reactivex.io/rxjs/`](http://reactivex.io/rxjs/)）中，Observable 是一个可以随时间变化的实体。这是 RxJS 的最基本构建块。观察者订阅 Observable 并对其变化做出反应。这种模式称为响应式模式。

引用自文档：

这种模式有助于并发操作，因为它不需要在等待 Observable 发出对象时阻塞，而是创建一个观察者作为哨兵，随时准备在 Observable 未来发出对象时做出适当的反应。

如果您对 Observables 还不熟悉，可以从这里开始：[`reactivex.io/documentation/observable.html`](http://reactivex.io/documentation/observable.html)，然后阅读：在 Angular 中利用 Observables：[`blog.thoughtram.io/angular/2016/01/06/taking-advantage-of-observables-in-angular2.html`](http://blog.thoughtram.io/angular/2016/01/06/taking-advantage-of-observables-in-angular2.html)和 Angular 2 中使用 Observables 进行 HTTP 请求：[`scotch.io/tutorials/angular-2-http-requests-with-observables`](https://scotch.io/tutorials/angular-2-http-requests-with-observables)。

现在服务已经完成，我们将更新`HomeComponent`以获取一个随机的 gif 并在主页上显示它。

打开`giphy-app/src/app/home/home.component.ts`并按以下方式更新它：

```html
import { Component, OnInit } from '@angular/core'; 
import { GiphyService } from '../giphy.service'; 

@Component({ 
  selector: 'app-home', 
  templateUrl: './home.component.html', 
  styleUrls: ['./home.component.css'] 
}) 
export class HomeComponent implements OnInit { 
  public gif: string; 
  public result: any; 
  public isLoading: boolean = true; 

  constructor(private giphyService: GiphyService) { 
    this.getRandomGif(); 
  } 

  ngOnInit() { 
  } 

  getRandomGif() { 
    this.giphyService.getRandomGif().subscribe( 
      (data) => { 
        this.result = data; 
        this.gif = this.result.data.image_url; 
        this.isLoading = false; 
      }, 
      (err) => console.log('Oops!', err), 
      () => console.log('Response', this.result) 
    ) 
  } 
}

```

在上述代码中，首先，我们导入了`GiphyService`并将其添加到构造函数中。接下来，我们编写了`getRandomGif()`并从构造函数中调用了`getRandomGif()`。在`getRandomGif()`中，我们在`giphyService`上调用了`getRandomGif()`来获取一个随机的 gif。然后，我们将 gif 赋值给一个名为`gif`的类变量。

为了确保一切正常运行，我们将通过执行`ng serve`并打开开发者工具来运行应用程序。如果一切顺利，我们应该能看到来自 Giphy API 的响应：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00011.jpeg)

现在我们已经得到了响应，我们希望构建一个组件来显示这个 gif。我们希望构建一个单独的组件，因为我们将在其他页面上使用相同的组件来显示需要的 gif。

让我们继续搭建组件。运行以下命令：

```html
ng generate component gif-viewr

```

接下来，打开`giphy-app/src/app/gif-viewr/gif-viewr.component.html`并按以下方式更新它：

```html
<div class="item"> 
  <div class="well"> 
    <img src="img/{{imgUrl}}"> 
  </div> 
</div>

```

完成后，我们需要告诉组件从父组件中期望数据，因为主页组件将把`imgUrl`传递给`gif-viewer`组件。

打开`giphy-app/src/app/gif-viewr/gif-viewr.component.ts`。首先，通过添加对 Input 装饰器的引用来更新导入语句：

```html
import { Component, OnInit, Input} from '@angular/core';

```

接下来，在`imgUrl`变量中添加一个 Input 装饰器：

```html
@Input() imgUrl: string;

```

更新后的`giphy-app/src/app/gif-viewr/gif-viewr.component.ts`如下所示：

```html
import { Component, OnInit, Input} from '@angular/core'; 

@Component({ 
  selector: 'app-gif-viewr', 
  templateUrl: './gif-viewr.component.html', 
  styleUrls: ['./gif-viewr.component.css'] 
}) 
export class GifViewrComponent implements OnInit { 
  @Input() imgUrl: string; 

  constructor() { } 

  ngOnInit() { 
  } 
}

```

注意：要为组件定义输入，我们使用`@Input`装饰器。要了解更多关于`@Input`装饰器的信息，请参考 Angular 文档中的属性指令部分：[`angular.io/docs/ts/latest/guide/attribute-directives.html`](https://angular.io/docs/ts/latest/guide/attribute-directives.html)。

保存文件并打开`giphy-app/src/app/home/home.component.html`。我们将在此页面内添加`app-gif-viewr`组件：

```html
<app-gif-viewr class="home" [imgUrl]="gif"></app-gif-viewr>

```

完整的文件如下所示：

```html
<div class="container"> 
    <div class="starter-template"> 
        <h1>Giphy App</h1> 
        <p class="lead">This app uses the JSON API provided by Giphy to 
          Browse and Search Gifs. 
            <br> To know more checkout : 
            <a href=
            "https://github.com/Giphy/GiphyAPI#trending-gifs-endpoint">
            Giphy API</a> </p> 
    </div> 

  <app-gif-viewr class="home" [imgUrl]="gif"></app-gif-viewr> 
</div>

```

接下来，我们将更新 CSS 以美化页面。打开`giphy-app/src/styles.css`并将以下 CSS 添加到现有样式中：

```html
.home .well{ 
   width: 70%; 
    margin: 0 auto; 
} 

img{ 
  width: 100%; 
}

```

如果我们回到浏览器并刷新，我们应该会看到以下内容：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00012.jpeg)

每次刷新页面，我们都会看到一个新的 gif 出现。

接下来，我们将在热门页面上进行工作。该页面将显示当前流行的 gif，使用 Pintrest 布局（或 Masonry 布局）。热门 REST API 支持分页。我们将利用这一点，每次加载 12 个 gif。然后提供一个“加载更多”按钮来获取接下来的 12 个 gif。

首先，让我们从 Giphy API 获取数据。打开`giphy-app/src/app/trending/trending.component.ts`。我们将首先导入`GiphyService`：

```html
import { GiphyService } from '../giphy.service';

```

现在，我们将添加相同的内容到构造函数中，并更新构造函数以调用`getTrendingGifs()`：

```html
constructor(private giphyService: GiphyService) { } 
In ngOnInit(), we will call the getTrendingGifs() API: 
  ngOnInit() { 
    this.getTrendingGifs(this.offset, this.perPage); 
  } 
Next, we will add the required class variables:  
private offset = 0; 
private perPage = 12; 
public results: any; 
public gifs: Array<any> = []; 
public isLoading: boolean = true;

```

`offset`和`perPage`将用于管理分页。

`results`将用于存储来自服务器的响应。

`gifs`是由一系列热门 gif 组成的数组，我们将其暴露给模板。

`isLoading`是一个`boolean`变量，用于跟踪请求是否正在进行中。使用`isLoading`，我们将显示/隐藏“加载更多”按钮。

接下来，我们将添加`getTrendingGifs()`：

```html
getTrendingGifs(offset, limit) { 
    this.giphyService.getTrendingGifs(offset, limit).subscribe( 
      (data) => { 
        this.results = data; 
        this.gifs = this.gifs.concat(this.results.data); 
        this.isLoading = false; 
      }, 
      (err) => console.log('Oops!', err), 
      () => console.log('Response', this.results) 
    ) 
  } 
And finally getMore(), which will be invoked by the Load More button: 
 getMore() { 
    this.isLoading = true; 
    this.offset = this.offset + this.perPage; 
    this.getTrendingGifs(this.offset, this.perPage); 
  }

```

为了显示检索到的 gif，我们将更新热门组件模板。打开`giphy-app/src/app/trending/trending.component.html`并进行如下更新：

```html
<div class="container"> 
    <h1 class="text-center">Trending Gifs</h1> 
    <div class="wrapper"> 
        <app-gif-viewr [imgUrl]="gif.images.original.url" *ngFor="let gif of gifs"></app-gif-viewr> 
    </div> 
    <input type="button" value="Load More" class="btn btn-primary btn-block" *ngIf="!isLoading" (click)="getMore()"> 
</div>

```

我们在这里所做的一切就是设置`app-gif-viewr`以通过对其应用`*ngFor`指令来获取 gif URL。底部还有一个“加载更多”按钮，用户可以加载更多 gif。

最后，为了实现 Pintrest/Masonry 布局，我们将添加一些 CSS 规则。打开`giphy-app/src/styles.css`并添加以下样式：

```html
*, *:before, *:after { 
  box-sizing: border-box !important; 
} 

.wrapper { 
  column-width: 18em; 
  column-gap: 1em; 
} 

.item { 
  display: inline-block; 
  padding: .25rem; 
  width: 100%; 
} 

.well { 
  position: relative; 
  display: block; 
}

```

保存所有文件并返回浏览器。如果我们点击导航栏中的热门菜单项，我们应该会看到以下内容：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00013.jpeg)

如果我们完全向下滚动，我们应该会看到一个“加载更多”按钮：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00014.jpeg)

点击“加载更多”按钮将加载下一组 gif：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00015.jpeg)

我浪费了大约 15 分钟点击“加载更多”并观看 gif。我认为这就是为什么 API 应该有速率限制的原因。

最后，我们将实现搜索 gif。打开`giphy-app/src/app/search/search.component.ts`并导入`GiphyService`：

```html
import { GiphyService } from '../giphy.service';

```

在构造函数中将`giphyService`添加为一个类变量：

```html
constructor(private giphyService: GiphyService) { }

```

接下来，我们将添加变量来管理分页以及响应：

```html
  private offset = 0; 
  private perPage = 12; 
  public results: any; 
  public query: string; 
  public gifs: Array<any> = []; 
  public isLoading: boolean = true;

```

现在我们将调用`searchGifs`，它通过传递查询字符串来进行 REST 调用以获取搜索到的 gif：

```html
searchGifs(offset, limit, query) { 
    this.giphyService.searchGifs(offset, limit, query).subscribe( 
      (data) => { 
        this.results = data; 
        this.gifs = this.gifs.concat(this.results.data); 
        this.isLoading = false; 
      }, 
      (err) => console.log('Oops!', err), 
      () => console.log('Response', this.results) 
    ) 
  }

```

以下是一个管理搜索表单提交按钮的方法：

```html
  search(query) { 
    this.query = query; 
    this.isLoading = true; 
    this.searchGifs(this.offset, this.perPage, this.query); 
  }

```

最后，`getMore()`来加载同一查询的更多页面：

```html
getMore() { 
    this.isLoading = true; 
    this.offset = this.offset + this.perPage; 
    this.searchGifs(this.offset, this.perPage, this.query); 
  }

```

更新后的`giphy-app/src/app/search/search.component.ts`如下所示：

```html
import { Component, OnInit } from '@angular/core'; 
import { GiphyService } from '../giphy.service'; 

@Component({ 
  selector: 'app-search', 
  templateUrl: './search.component.html', 
  styleUrls: ['./search.component.css'] 
}) 
export class SearchComponent implements OnInit { 
  private offset = 0; 
  private perPage = 12; 
  public results: any; 
  public query: string; 
  public gifs: Array<any> = []; 
  public isLoading: boolean = true; 

  constructor(private giphyService: GiphyService) { } 

  ngOnInit() { 
  } 

  searchGifs(offset, limit, query) { 
    this.giphyService.searchGifs(offset, limit, query).subscribe( 
      (data) => { 
        this.results = data; 
        this.gifs = this.gifs.concat(this.results.data); 
        this.isLoading = false; 
      }, 
      (err) => console.log('Oops!', err), 
      () => console.log('Response', this.results) 
    ) 
  } 

  search(query) { 
    this.query = query; 
    this.isLoading = true; 
    this.searchGifs(this.offset, this.perPage, this.query); 
  } 

  getMore() { 
    this.isLoading = true; 
    this.offset = this.offset + this.perPage; 
    this.searchGifs(this.offset, this.perPage, this.query); 
  } 
}

```

现在我们将更新`giphy-app/src/app/search/search.component.html`。打开`giphy-app/src/app/search/search.component.html`并进行如下更新：

```html
<div class="container"> 
    <h1 class="text-center">Search Giphy</h1> 
    <div class="row"> 
        <input class="form-control" type="text" placeholder="Search 
          something.. Like.. LOL or Space or Wow" #searchText 
          (keyup.enter)="search(searchText.value)"> 
    </div> 
    <br> 
    <div class="wrapper"> 
        <app-gif-viewr [imgUrl]="gif.images.original.url" *ngFor="let 
          gif of gifs"></app-gif-viewr> 
    </div> 
    <input type="button" value="Load More" class="btn btn-primary btn-block" *ngIf="!isLoading" (click)="getMore()"> 
</div>

```

这个视图与热门组件相同，只是有一个搜索文本框，允许用户通过输入字符串进行搜索。

如果我们保存所有文件，返回浏览器，并导航到搜索页面，我们应该会看到一个带有搜索文本框的空白页面。此时，“加载更多”按钮将不会显示。如果我们输入文本并按回车键，我们应该会看到结果，如下图所示：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00016.jpeg)

有了这个，我们已经完成了在 Angular 应用中使用 Giphy API 的实现。

为了结束这个例子，我们将更新`giphy-app/src/app/page-not-found/page-not-found.component.html`如下：

```html
<div class="container"> 
    <div class="starter-template"> 
        <h1>404 Not Found</h1> 
        <p class="lead">Looks Like We Were Not Able To Find What You Are Looking For. 
            <br>Back to : <a [routerLink]="['/']">Home</a>? </p> 
    </div> 
</div>

```

当我们导航到[`localhost:4200/nopage`](http://localhost:4200/nopage)时，我们应该看到以下页面：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00017.jpeg)

# 摘要

在本章中，我们已经对 TypeScript 进行了高层次的概述，以及为什么我们使用 TypeScript。接下来，我们熟悉了 Angular 的新语法和组件结构。利用这些知识，我们构建了一个名为 Giphy 的应用程序，它与 Giphy 的 REST API 进行交互以获取 gif。

您可以在这里阅读更多关于 Angular 的信息：[`angular.io`](https://angular.io)。

此外，查看第十一章，*Ionic 3*，了解有关 Angular 4 的更多变化。

在下一章--欢迎来到 Ionic，我们将开始使用 Cordova 进行移动混合开发，并了解 Ionic 如何融入更大的方案。


# 第二章：欢迎来到 Ionic

在上一章中，我们通过一个例子学习了 Angular 2。在本章中，我们将看一下移动混合应用的大局，设置所需的软件来开发 Ionic 应用，最后搭建一些应用并探索它们。

本章涵盖的主题如下：

+   移动混合架构

+   Apache Cordova 是什么？

+   Ionic 是什么？

+   设置开发和运行 Ionic 应用所需的工具

+   使用 Ionic 模板

# 移动混合架构

在我们开始使用 Ionic 之前，我们需要了解移动混合开发的大局。

这个概念非常简单。几乎每个移动操作系统（在使用 Cordova 时也称为平台）都有一个用于开发应用程序的 API。这个 API 包括一个名为 WebView 的组件。WebView 通常是一个在移动应用程序范围内运行的浏览器。这个浏览器运行 HTML、CSS 和 JS 代码。这意味着我们可以使用上述技术构建一个网页，然后在我们的应用程序内执行它。

我们可以使用相同的 Web 开发知识来构建本地混合移动应用程序（这里，本地是指在打包后与资产一起安装在设备上的特定于平台的格式文件），例如：

+   Android 使用 Android 应用程序包（`.apk`）

+   iOS 使用 iPhone 应用程序存档（`.ipa`）

+   Windows Phone 使用应用程序包（`.xap`）

包/安装程序由一段初始化网页和一堆显示网页内容所需的资产的本地代码组成。

在移动应用程序容器内显示网页的这种设置，其中包含我们的应用程序业务逻辑，被称为混合应用。

# Apache Cordova 是什么？

简单来说，Cordova 是将 Web 应用程序和本地应用程序拼接在一起的软件。Apache Cordova 的网站表示：

“Apache Cordova 是使用 HTML、CSS 和 JavaScript 构建本地移动应用程序的平台。”

Apache Cordova 不仅仅是将 Web 应用程序与本地应用程序拼接在一起，而且还提供了一组用 JavaScript 编写的 API，以与设备的本地功能进行交互。是的，我们可以使用 JavaScript 访问我们的相机，拍照并通过电子邮件发送。听起来很激动人心，对吧？

为了更好地理解发生了什么，让我们看一下以下的截图：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00018.jpeg)

正如我们所看到的，我们有一个 WebView，HTML/CSS/JS 代码在其中执行。这段代码可以是一个简单的独立用户界面；在最好的情况下，我们正在通过 AJAX 请求从远程服务器获取一些数据。或者，这段代码可以做更多的事情，比如与设备的蓝牙通信并获取附近设备的列表。

在后一种情况下，Cordova 有一堆 API，用 JavaScript 与 WebView 进行接口，然后以其本地语言（例如，Android 的 Java）与设备进行通信，从而在这种情况下为 Java 和 JavaScript 提供了桥梁。例如，如果我们想了解正在运行我们的应用程序的设备更多信息，我们只需要在 JS 文件中编写以下代码并启动应用程序：

```html
var platform = device.platform;

```

安装设备插件后，我们还可以使用 JavaScript 从 WebView 内部访问设备的 UUID、型号、操作系统版本和 Cordova 版本，如下所示：

```html
var uuid = device.uuid; 
var model = device.model; 
var version = device.version; 
var Cordova = device.Cordova;

```

我们将在第六章 *Ionic Native*中更多地处理 Cordova 插件。

前面的解释是为了让你了解移动混合应用的结构以及我们如何使用 JavaScript 从 WebView 中使用设备功能。

Cordova 不会将 HTML、CSS 和 JS 代码转换为特定于操作系统的二进制代码。它所做的只是包装 HTML、CSS 和 JS 代码，并在 WebView 内执行它。

所以你现在一定已经猜到了，Ionic 是我们用来构建在 WebView 中运行并与 Cordova 通信以访问设备特定 API 的 HTML/CSS/JS 代码的框架。

# Ionic 2 是什么？

Ionic 2 是一个用于开发混合移动应用程序的美观的开源前端 SDK，提供了移动优化的 HTML、CSS 和 JS 组件，以及用于构建高度交互式应用程序的手势和工具。

与其他框架相比，Ionic 2 通过最小化 DOM 操作和硬件加速的转换，具有高性能效率。Ionic 使用 Angular 2 作为其 JavaScript 框架。

在像 Ionic 2 这样的框架中使用 Angular 的强大功能，可能性是无限的（只要在移动应用程序中有意义，我们可以在 Ionic 中使用任何 Angular 组件）。 Ionic 2 与 Cordova 的设备 API 集成非常好。这意味着我们可以使用 Ionic Native 访问设备 API，并将其与 Ionic 的美观用户界面组件集成。

Ionic 有自己的命令行界面（CLI）来搭建、开发和部署 Ionic 应用程序。在开始使用 Ionic CLI 之前，我们需要设置一些软件。

# Ionic 3

在本书发布时，Ionic 的最新版本是 3。我已经准备了另一章名为 Ionic 3（第十一章），您可以参考了解更多关于 Ionic 3 及其变化的信息。

另外，请注意，本书中的示例在使用 Ionic 3 时仍然有效。可能会有一些语法和结构上的变化，但总体意思应该保持不变。

# 软件设置

现在我们将设置所有开发和运行 Ionic 应用程序所需的必要软件。

# 安装 Node.js

由于 Ionic 使用 Node.js 作为其 CLI 以及构建任务，我们将首先安装它如下：

1.  导航到[`nodejs.org/`](https://nodejs.org/)。

单击主页上的安装按钮，将自动下载适用于我们操作系统的安装程序。我们也可以导航到[`nodejs.org/download/`](https://nodejs.org/download/)并下载特定的副本。

1.  通过执行下载的安装程序安装 Node.js。

要验证 Node.js 是否已成功安装，请打开新的终端（*nix 系统）或命令提示符（Windows 系统）并运行以下命令：

```html
 node -v
 > v6.10.1

```

1.  现在执行以下命令：

```html
 npm -v
 > 3.10.10

```

`npm`是一个**Node Package Manager**，我们将使用它来下载我们 Ionic 项目的各种依赖项。

我们只需要在开发过程中使用 Node.js。指定的版本仅用于说明。您可能有相同版本或软件的最新版本。

# 安装 Git

Git 是一个免费的开源分布式版本控制系统，旨在处理从小型到非常大型的项目，并具有速度和效率。在我们的情况下，我们将使用一个名为 Bower 的包管理器，它使用 Git 来下载所需的库。此外，Ionic CLI 使用 Git 来下载项目模板。

要安装 Git，请导航到[`git-scm.com/downloads`](http://git-scm.com/downloads)并下载适用于您平台的安装程序。安装成功后，我们可以导航到命令提示符/终端并运行以下命令：

```html
git --version

```

我们应该看到以下输出：

```html
> git version 2.11.0 (Apple Git-81)

```

# 文本编辑器

这是一个完全可选的安装。每个人都有自己喜欢的文本编辑器。在尝试了许多文本编辑器之后，我纯粹因为其简单性和插拔包的数量而爱上了 Sublime Text。

如果您想尝试这个编辑器，可以导航到[`www.sublimetext.com/3`](http://www.sublimetext.com/3)下载 Sublime Text 3。

因为我们将用 TypeScript 编写 JavaScript 代码，Microsoft 的 Visual Studio Code 是另一个不错的选择。

如果您想尝试这个编辑器，可以导航到[`code.visualstudio.com/`](https://code.visualstudio.com/)。

您也可以尝试 Atom 作为另一种选择。

如果您想尝试这个编辑器，可以导航到[`atom.io/`](https://atom.io/)。

# 安装 TypeScript

接下来，我们将安装 TypeScript 编译器。如第一章“Angular - A Primer”中所述，我们将使用 TypeScript 编写 JavaScript 代码。要安装 TypeScript 编译器，请运行以下命令：

```html
npm install typescript -g

```

一旦 TypeScript 成功安装，我们可以通过运行此命令来验证：

```html
tsc -v
> message TS6029: Version 1.7.5

```

在 Ionic 3 发布时，TypeScript 的最新版本是 2.2.2。在使用 Ionic 3 时，您可能需要将 TSC 的版本更新为 2.2.2 或更高版本。

# 安装 Cordova 和 Ionic CLI

最后，为了完成 Ionic 2 的设置，我们将安装 Ionic 和 Cordova CLI。Ionic CLI 是 Cordova CLI 的包装器，具有一些附加功能。

本书中的所有代码示例使用 Cordova 版本 6.4.0，Ionic CLI 版本 2.1.14 和 Ionic 版本 2.1.17。但是最新版本的 Ionic 也应该可以使用相同的代码。

要安装 Ionic CLI，请运行以下命令：

```html
npm install -g ionic cordova

```

要验证安装，请运行以下命令：

```html
cordova -v
> 6.4.0

```

您也可以运行此命令：

```html
ionic -v
> 2.1.14

```

您可以运行以下命令获取有关 Ionic 设置的完整信息：

```html
ionic info

Your system information:
Cordova CLI: 6.4.0 
Ionic CLI Version: 2.1.14
Ionic App Lib Version: 2.1.7
ios-deploy version: 1.8.4 
ios-sim version: 5.0.6 
OS: macOS Sierra
Node Version: v6.10.1
Xcode version: Xcode 8.3 Build version 8E162

```

如果您看到的 Ionic CLI 版本大于或等于 2.2.2，则您有一个可以处理 Ionic 3 应用程序的 Ionic CLI。尽管如此，本书中的命令和示例将以相同的方式工作。

要了解 Ionic CLI 包含的功能，运行以下命令：

```html
 ionic

```

我们应该看到一系列任务，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00019.jpeg)

除了在上述截图中看到的任务之外，还有一些其他任务。

我们可以阅读任务和解释，了解它们的作用。还要注意，截至今天，其中一些任务仍处于测试阶段。

通过这样，我们已经完成了使用 Ionic 开发应用所需的所有软件的安装。

# 平台指南

在本书结束时，我们将构建可以部署到设备上的应用程序。由于 Cordova 接受 HTML、CSS 和 JS 代码作为输入并生成特定于平台的安装程序，我们需要在我们的机器上有构建环境。

Android 用户可以按照 Android 平台指南中的说明在本地机器上设置 SDK：[`cordova.apache.org/docs/en/edge/guide_platforms_android_index.md.html#Android%2520Platform%2520Guide`](http://cordova.apache.org/docs/en/edge/guide_platforms_android_index.md.html#Android%2520Platform%2520Guide)。

iOS 用户可以按照 iOS 平台指南中的说明在本地机器上设置 SDK：[`cordova.apache.org/docs/en/edge/guide_platforms_ios_index.md.html#iOS%20Platform%20Guide`](http://cordova.apache.org/docs/en/edge/guide_platforms_ios_index.md.html#iOS%2520Platform%2520Guide)。

您需要 macOS 环境来开发 iOS 应用程序。

截至今天，Ionic 仅支持 Android 4.0+（尽管在 2.3 上也可以工作）和 iOS 6+移动平台。但 Cordova 支持更多平台。

您可以在以下网址查看其他支持的平台：[`cordova.apache.org/docs/en/edge/guide_platforms_index.md.html#Platform%20Guides`](http://cordova.apache.org/docs/en/edge/guide_platforms_index.md.html#Platform%2520Guides)。

# 你好 Ionic

现在我们已经完成了软件设置，我们将创建一些 Ionic 应用程序的脚手架。

Ionic 有三个主要/常用模板，我们可以使用这些模板快速开始开发应用程序：

+   空白：这是一个空白的 Ionic 项目，有一个页面

+   选项卡：这是一个使用 Ionic 选项卡构建的示例应用程序

+   侧边菜单：这是一个使用侧边菜单驱动导航的示例应用程序

为了了解脚手架的基础知识，我们将从空白模板开始。

为了保持我们的学习过程清晰，我们将创建一个文件夹结构来处理 Ionic 项目。创建一个名为`chapter2`的文件夹。

接下来，打开一个新的命令提示符/终端，并将目录（`cd`）更改为`chapter2`文件夹。现在运行以下命令：

```html
ionic start -a "Example 1" -i app.example.one example1 blank --v2

```

上述命令具有以下功能：

+   `-a "Example 1"`：这是应用程序的可读名称。

+   `-i app.example.one`：这是应用程序 ID/反向域名。

+   `example1`：这是文件夹的名称。

+   `blank`：这是模板的名称。

+   `--v2`：此标志表示项目将使用最新版本的 Ionic 进行脚手架。这可能会在将来被移除。

参考附录，附加主题和提示，了解更多关于 Ionic start 任务的信息。

Ionic CLI 在执行任务时非常冗长。正如我们从命令提示符/终端中所看到的，项目正在创建时会打印出大量信息。

首先，从`ionic2-app-base` GitHub 存储库[`github.com/driftyco/ionic2-app-base`](https://github.com/driftyco/ionic2-app-base)下载`ionic2-app-base`。之后，从`ionic-starter-blank` GitHub 存储库[`github.com/driftyco/ionic2-starter-blank`](https://github.com/driftyco/ionic2-starter-blank)下载`ionic2-starter-blank`。然后安装所有必需的依赖项。

一旦项目成功创建，我们将看到一堆关于如何进一步进行的说明。我们的输出应该看起来类似以下内容：

！[](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00020.jpeg)

为了进一步进行，我们将使用`cd`命令导航到`example1`文件夹。我们不会按照命令提示符/终端中提供的说明进行，因为我们还没有理解项目设置。一旦我们对 Ionic 有一个大致的了解，我们可以在脚手架一个新的 Ionic 应用程序后，开始使用命令提示符/终端输出中提供的命令。

一旦我们已经切换到`example1`文件夹，我们将通过以下命令提供应用程序：

```html
ionic serve

```

这将在端口`8100`上启动一个新的`dev`服务器，然后在我们的默认浏览器中启动应用程序。我强烈建议在使用 Ionic 时将 Google Chrome 或 Mozilla Firefox 设置为默认浏览器。

当浏览器启动时，我们应该看到空模板的主页。

如果我们运行`ionic serve`并且端口`8100`已被占用，Ionic 将在`8101`上启动应用程序。

我们还可以使用以下命令在任何其他端口上提供 Ionic 应用程序：

```html
ionic serve -p 8200

```

一旦应用程序成功启动并且我们在浏览器中看到输出，我们将返回到命令提示符/终端，应该会看到类似以下截图的内容：

！[](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00021.jpeg)

# 浏览器开发者工具设置

在我们进一步进行之前，我建议按照以下格式在浏览器中设置开发者工具。

# Google Chrome

一旦 Ionic 应用程序启动，按下 Mac 上的*Command* + *Option* + *I*，或者在 Windows/Linux 上按下*Ctrl* + *Shift* + *I*，打开开发者工具。然后点击顶部行中倒数第二个图标，靠近关闭按钮，如下截图所示：

！[](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00022.jpeg)

这将把开发者工具停靠在当前页面的一侧。拖动浏览器和开发者工具之间的分界线，直到视图开始类似于移动设备。

如果您在开发者工具中点击“元素”选项卡，您可以轻松地检查页面并一次看到输出，如下截图所示：

！[](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00023.jpeg)

这个视图对于修复错误和调试问题非常有帮助。

# Mozilla Firefox

如果您是 Mozilla Firefox 的粉丝，我们也可以使用 Firefox 来实现前面的结果。一旦 Ionic 应用程序启动，按下 Mac 上的*Command* + *Option* + *I*，或者在 Windows/Linux 上按下*Ctrl* + *Shift* + *I*，打开开发者工具（不是 Firebug，Firefox 的本机开发工具）。然后点击浏览器窗口旁边的停靠图标，如下截图所示：

！[](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00024.jpeg)

现在我们可以拖动分界线，以实现与 Chrome 中看到的相同结果：

！[](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00025.jpeg)

# Ionic 项目结构

到目前为止，我们已经搭建了一个空白的 Ionic 应用程序并在浏览器中启动了它。现在，我们将浏览搭建好的项目结构。

如果我们在文本编辑器中打开`chapter2 example1`文件夹，我们应该在项目的根目录看到以下文件夹结构：

```html
. 
├── config.xml 
├── hooks 
├── ionic.config.json 
├── node_modules 
├── package.json 
├── platforms 
├── plugins 
├── resources 
├── src 
├── tsconfig.json 
├── tslint.json 
├── www

```

以下是每个项目的快速解释：

+   `src`：这是所有开发发生的文件夹。应用程序源代码将放在这里。如果您从 Ionic 1 转到 Ionic 2，这是您会注意到的第一个变化。对我来说，这是文件夹结构的一个很好的升级，因为它将开发代码与部署代码分开。

+   `hooks`：这个文件夹包含了在执行特定的 Cordova 任务时执行的脚本。Cordova 任务可以是以下任何一种：`after_platform_add`（添加新平台后）、`after_plugin_add`（添加新插件后）、`before_emulate`（模拟开始前）、`after_run`（应用程序运行前）等。每个任务都放在以 Cordova 任务命名的文件夹内。

+   `resources`：这个文件夹包含了基于移动操作系统的应用程序图标和启动画面的各种版本。

+   `www`：这个文件夹包含了在`src`文件夹中编写的构建 Ionic 代码。这个文件夹中的所有代码都打算放在 WebView 中。

+   `config.xml`：这个文件包含了 Cordova 在将我们的 Ionic 应用程序转换为特定于平台的安装程序时所需的所有元信息。如果您打开`config.xml`，您将看到一堆描述我们项目的 XML 标签。我们将再次详细查看这个文件。

+   `ionic.config.js`：这个文件包含了构建任务所需的配置。

+   `package.json`：这个文件包含了项目级别的 node 依赖项。

+   `tsconfig.json`：这个文件包含了 TypeScript 的配置。

+   `tslint.json`：这个文件包含了 TS lint 规则。要了解更多关于这些规则的信息，请参考：[`palantir.github.io/tslint/rules/`](https://palantir.github.io/tslint/rules/)。

# config.xml 文件

`config.xml`文件是一个与平台无关的配置文件。如前所述，这个文件包含了 Cordova 在将`www`文件夹中的代码转换为特定于平台的安装程序时所需的所有信息。

`config.xml`文件的设置基于 W3C 的打包 Web 应用程序（小部件）规范（[`www.w3.org/TR/widgets/`](http://www.w3.org/TR/widgets/)），并扩展为指定核心 Cordova API 功能、插件和特定于平台的设置。我们可以向该文件添加两种类型的配置。一种是全局的，即对所有设备通用，另一种是特定于平台的。

如果我们打开`config.xml`，我们会遇到的第一个标签是 XML 根标签。接下来，我们可以看到 widget 标签：

```html
<widget id="app.example.one" version="0.0.1"  >

```

之前指定的`id`是我们应用程序的反向域名，我们在脚手架时提供的。其他规范是在 widget 标签内定义的其子级。子级标签包括应用程序名称（在设备上安装时显示在应用程序图标下方）、应用程序描述和作者详细信息。

它还包含了在将`src`文件夹中的代码转换为本机安装程序时需要遵守的配置。

内容标签定义了应用程序的起始页面。

访问标签定义了应用程序中允许加载的 URL。默认情况下，它会加载所有的 URL。

preference 标签设置了各种选项的名称值对。例如，`DisallowOverscroll`描述了当用户滚动文档的开头或结尾时是否应该有任何视觉反馈。

您可以在以下链接中阅读有关特定于平台的配置的更多信息：

+   Android：[`docs.phonegap.com/en/edge/guide_platforms_android_config.md.html#Android%20Configuration`](http://docs.phonegap.com/en/4.0.0edge/guide_platforms_android_config.md.html#Android%2520Configuration)

+   iOS：[`docs.phonegap.com/en/edge/guide_platforms_ios_config.md.html#iOS%20Configuration`](http://docs.phonegap.com/en/4.0.0edge/guide_platforms_ios_config.md.html#iOS%2520Configuration)

平台特定配置和全局配置的重要性是一样的。您可以在[`docs.phonegap.com/en/edge/config_ref_index.md.html#The%20config.xml%20File`](http://docs.phonegap.com/en/4.0.0edge/config_ref_index.md.html#The%2520config.xml%2520File)了解更多关于全局配置的信息。

# src 文件夹

正如前面提到的，该文件夹包括我们的 Ionic 应用程序，HTML、CSS 和 JS 代码。如果我们打开`src`文件夹，我们将找到以下文件结构：

```html
. . 
├── app 
│   ├── app.component.ts 
│   ├── app.html 
│   ├── app.module.ts 
│   ├── app.scss 
│   ├── main.ts 
├── assets 
│   ├── icon 
├── declarations.d.ts 
├── index.html 
├── manifest.json 
├── pages 
│   ├── home 
├── service-worker.js 
├── theme 
    ├── variables.scss

```

让我们详细看看每一个：

+   `app 文件夹`：app 文件夹包括特定环境的初始化文件。该文件夹包括`app.module.ts`，其中定义了`@NgModule`模块。`app.component.ts`包括根组件。

+   `assets 文件夹`：该文件夹包括所有静态资产。

+   `pages 文件夹`：该文件夹包括我们将要创建的页面。在这个例子中，我们已经有一个名为`home`的示例页面。每个页面都是一个组件，其中包括业务逻辑-`home.ts`，标记-`home.html`和与组件相关的样式-`home.scss`。

+   `theme 文件夹`：该文件夹包括`variables.scss`，覆盖它将改变 Ionic 组件的外观和感觉。

+   `index.html`：这是一切的起点。

这完成了我们对空白模板的介绍。在我们搭建下一个模板之前，让我们快速查看一下`src/app/app.component.ts`文件。

正如您所看到的，我们正在创建一个新的应用/根组件。`@Component`装饰器需要一个`template`或`templateUrl`属性来正确加载 Ionic 2 应用程序。作为模板的一部分，我们添加了`ion-nav`组件。

在类定义内部，我们声明了一个`rootPage`并将其分配给主页，并在构造函数内部，我们有平台准备好的回调，当平台准备就绪时将调用它。

这是一个非常简单和基本的 Ionic 应用程序。到目前为止，您一定已经在与 Web 相关的 Angular 代码上工作过。但是当您处理 Ionic 时，您将与与设备功能相关的脚本一起工作。Ionic 为我们提供了服务，以更有条理地实现这些功能。

# 搭建选项卡模板

为了更好地了解 Ionic CLI 和项目结构，我们还将搭建其他两个起始模板。首先我们将搭建选项卡模板。

使用`cd`命令，返回到`chapter2`文件夹并运行以下命令：

```html
ionic start -a "Example 2" -i app.example.two example2 tabs --v2

```

选项卡项目被搭建在`example2`文件夹内。使用`cd`命令，进入`example2`文件夹并执行以下命令：

```html
    ionic serve

```

我们应该看到使用 Ionic 构建的选项卡界面应用程序，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00026.jpeg)

选项卡位于页面底部。我们将在第三章，*Ionic 组件和导航*，以及第四章，*Ionic 装饰器和服务*中更多地讨论自定义。

如果您回到`example2`文件夹并分析项目结构，除了`src`/`pages`文件夹的内容外，其他都是一样的。

这一次，在 pages 文件夹中您将看到四个文件夹。tabs 文件夹包括选项卡定义，about、contact 和 home 文件夹包括每个选项卡的定义。

现在您可以很好地了解 Ionic 是如何与 Angular 集成的，以及所有组件是如何相辅相成的。当我们处理更多 Ionic 的部分时，这种结构将更加有意义。

# 搭建侧边菜单模板

现在我们将搭建最终的模板。使用`cd`命令，返回到`chapter2`文件夹并运行以下命令：

```html
ionic start -a "Example 3" -i app.example.three example3 sidemenu --v2

```

执行脚手架项目，使用`cd`命令，进入`example3`文件夹并输入以下命令：

```html
ionic serve

```

输出应该类似于以下截图：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00027.jpeg)

您可以自行分析项目结构并查看区别。

您可以运行`ionic start -l`或`ionic templates`来查看可用模板的列表。您还可以使用`ionic start task`和列表中的模板名称来搭建应用程序。

# 摘要

在本章中，我们了解了移动混合架构的一些知识。我们还学习了混合应用程序的工作原理。我们看到了 Cordova 如何将 HTML、CSS 和 JS 代码拼接在一起，以在本地应用程序的 WebView 中执行。然后我们安装了开发 Ionic 应用程序所需的软件。我们使用 Ionic CLI 搭建了一个空白模板并分析了项目结构。随后，我们搭建了另外两个模板并观察了它们之间的区别。

您还可以参考 Ionic 幻灯片[`ionicframework.com/present-ionic/slides`](http://ionicframework.com/present-ionic/slides)获取更多信息。

在下一章节*Ionic 组件和导航*中，我们将学习 Ionic 组件以及如何构建一个简单的两页应用程序并在它们之间进行导航。这将帮助我们使用 Ionic API 构建有趣的用户界面和多页面应用程序。


# 第三章：Ionic 组件和导航

到目前为止，我们已经了解了 Ionic 是什么，以及它在移动混合应用开发的大局中扮演的角色。我们还看到了如何搭建一个 Ionic 应用程序。

在本章中，我们将使用 Ionic 组件、Ionic 网格系统和 Ionic 中的导航。我们将查看 Ionic 的各种组件，使用这些组件可以构建提供出色用户体验的应用程序。

本章将涵盖以下主题：

+   Ionic 网格系统

+   Ionic 组件

+   Ionic 导航

# 核心组件

Ionic 是一个强大的移动 CSS 框架和 Angular 的结合。使用 Ionic，将任何想法推向市场所需的时间非常短。Ionic CSS 框架包含了构建应用程序所需的大多数组件。

为了测试可用组件，我们将搭建一个空白的起始模板，然后添加 Ionic 的可视组件。

在开始搭建之前，我们将创建一个名为`chapter3`的新文件夹，并在该文件夹中搭建本章的所有示例。

要搭建一个空白应用程序，请运行以下代码：

```html
ionic start -a "Example 4" -i app.example.four example4 blank --v2 

```

# Ionic 网格系统

要对布局进行精细控制，以便在页面上定位组件或以一致的方式将元素排列在一起，您需要一个网格系统，Ionic 提供了这样一个系统。

Ionic 网格系统的美妙之处在于它是基于 FlexBox 的。FlexBox——或 CSS 柔性盒布局模块——为优化的用户界面设计提供了一个盒模型。

您可以在以下链接了解更多关于 FlexBox 的信息：

[`www.w3.org/TR/css3-flexBox/`](http://www.w3.org/TR/css3-flexBox/)

您可以在以下链接找到有关 FlexBox 的精彩教程：

[`css-tricks.com/snippets/css/a-guide-to-flexbox/`](https://css-tricks.com/snippets/css/a-guide-to-flexbox/)

基于 FlexBox 的网格系统的优势在于，您不需要固定列网格。您可以在一行内定义尽可能多的列，并且它们将自动分配相等的宽度。这样，与任何其他基于 CSS 的网格系统不同，您不需要担心类名的总和是否等于网格系统中的总列数。

要了解网格系统的工作原理，请打开`example4/src/pages/home`文件夹中的`home.html`文件。删除`ion-content`指令内的所有内容，并添加以下代码：

```html
<ion-row> 
        <ion-col>col-20%-auto</ion-col> 
        <ion-col>col-20%-auto</ion-col> 
        <ion-col>col-20%-auto</ion-col> 
        <ion-col>col-20%-auto</ion-col> 
        <ion-col>col-20%-auto</ion-col> 
</ion-row>

```

为了直观地看到区别，我们在`src/pages/home`文件夹中的`home.scss`中添加以下样式：

```html
ion-col { 
    border: 1px solid red; 
}

```

上述样式不是使用网格系统所必需的；它只是为了显示布局中每个列的视觉分隔。

保存`home.html`和`home.scss`文件，并使用`cd`命令进入`example4`文件夹，然后运行以下命令：

```html
ionic serve

```

然后您应该看到以下内容：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00028.jpeg)

为了检查宽度是否会自动变化，我们将子 div 的数量减少到三个，如下所示：

```html
<ion-row> 
        <ion-col>col-33%-auto</ion-col> 
        <ion-col>col-33%-auto</ion-col> 
        <ion-col>col-33%-auto</ion-col> 
</ion-row>

```

然后您应该看到以下内容：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00029.jpeg)

无需麻烦，无需计算；您只需要添加要使用的 ion-col，它们将自动分配相等的宽度。

但这并不意味着您不能应用自定义宽度。您可以使用 Ionic 提供的宽度属性轻松实现这一点。

例如，假设在前面的三列情况下，您希望第一列跨越 50%，剩下的两列占据剩余的宽度；您只需要在第一个`ion-col`中添加一个名为`width-50`的属性，如下所示：

```html
    <ion-row> 
        <ion-col width-50>col-50%-set</ion-col> 
        <ion-col>col-25%-auto</ion-col> 
        <ion-col>col-25%-auto</ion-col> 
   </ion-row>

```

然后您应该看到以下内容：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00030.jpeg)

您可以参考以下表格，了解预定义宽度属性及其隐含宽度的列表：

| **属性名称** | **百分比宽度** |
| --- | --- |
| `width-10` | 10% |
| `width-20` | 20% |
| `width-25` | 25% |
| `width-33` | 33.333% |
| `width-34` | 33.333% |
| `width-50` | 50% |
| `width-66` | 66.666% |
| `width-67` | 66.666% |
| `width-75` | 75% |
| `width-80` | 80% |
| `width-90` | 90% |

你还可以通过一定的百分比来偏移列。例如，将以下标记附加到我们当前的示例中：

```html
<ion-row> 
        <ion-col offset-33>col-33%-offset</ion-col> 
        <ion-col>col-33%-auto</ion-col> 
 </ion-row>

```

然后你应该会看到以下内容：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00031.jpeg)

第一个 div 偏移了 33%，剩下的 66%将在两个 div 之间分配。偏移属性所做的就是在 div 的左侧添加指定百分比的边距。

你可以参考以下表格，了解预定义类及其隐含的偏移宽度：

| **属性名称** | **百分比宽度** |
| --- | --- |
| `offset-10` | 10% |
| `offset -20` | 20% |
| `offset -25` | 25% |
| `offset -33` | 33.333% |
| `offset -34` | 33.333% |
| `offset -50` | 50% |
| `offset -66` | 66.666% |
| `offset -67` | 66.666% |
| `offset -75` | 75% |
| `offset -80` | 80% |
| `offset -90` | 90% |

你还可以垂直对齐网格中的列。这是使用 FlexBox 网格系统的另一个优势。

添加以下代码：

```html
<h4 text-center>Align Cols to <i>top</i></h4> 
    <ion-row top> 
        <ion-col> 
            <div>col</div> 
        </ion-col> 
        <ion-col> 
            <div>col</div> 
        </ion-col> 
        <ion-col> 
            <div>col</div> 
        </ion-col> 
        <ion-col> 
            <div> 
                This 
                <br>is a tall 
                <br> column 
            </div> 
        </ion-col> 
    </ion-row> 
    <h4 text-center>Align Cols to <i>center</i></h4> 
    <br> 
    <ion-row center> 
        <ion-col> 
            <div>col</div> 
        </ion-col> 
        <ion-col> 
            <div>col</div> 
        </ion-col> 
        <ion-col> 
            <div>col</div> 
        </ion-col> 
        <ion-col> 
            <div> 
                This 
                <br>is a tall 
                <br> column 
            </div> 
        </ion-col> 
    </ion-row> 
    <h4 text-center>Align Cols to <i>bottom</i></h4> 
    <ion-row bottom> 
        <ion-col> 
            <div>col</div> 
        </ion-col> 
        <ion-col> 
            <div>col</div> 
        </ion-col> 
        <ion-col> 
            <div>col</div> 
        </ion-col> 
        <ion-col> 
            <div> 
                This 
                <br>is a tall 
                <br> column 
            </div> 
        </ion-col> 
    </ion-row>

```

然后你应该会看到以下内容：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00032.jpeg)

如果其中一个列很高，你可以在`ion-row`标记上添加 top、center 或 bottom 属性，事情就会如前面的图所示的那样落实到位。

有了这样一个简单而强大的网格系统，布局可能是无限的。

要了解更多关于 Ionic 网格系统的信息，你可以参考以下链接：[`ionicframework.com/docs/components/#grid`](http://ionicframework.com/docs/components/#grid)

# Ionic 组件

在本节中，我们将介绍一些 Ionic 组件。这些组件包括按钮、列表、卡片和表单。Ionic 组件会根据运行设备自动适应 iOS 主题，或者根据 Android 或 Windows 主题的 Material Design。当我们使用 Ionic 组件时，我们将在所有三个平台上看到输出。

要进一步进行，我们为按钮创建一个新项目。你可以`cd`到`chapter3`文件夹，并运行以下命令：

```html
ionic start -a "Example 5" -i app.example.five example5 blank --v2 

```

接下来，我们在实验室模式下为应用提供服务。使用`cd`命令导航到`example5`文件夹，并运行以下命令：

```html
ionic serve --lab

```

这将在实验室模式下为 Ionic 应用提供服务，看起来会像这样：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00033.jpeg)

通过这个视图，我们可以在所有三个平台上看到所有组件的输出。

# 按钮

Ionic 提供了不同的按钮变化，包括大小和样式。

在`src/pages/home/home.html`中更新`ion-content`指令，使用以下代码，我们应该会看到不同的按钮变化：

```html
<ion-content class="home" padding> 
    <button ion-button>Button</button> 
    <button ion-button color="light" outline>Light Outline</button> 
    <button ion-button color="secondary" clear>Secondary Clear</button> 
    <button ion-button color="danger" round>Danger Round</button> 
    <button ion-button block>Block Button</button> 
    <button ion-button color="secondary" full>Full Button</button> 
    <button ion-button color="danger" large>Large Danger</button> 
    <button ion-button dark> 
        Home 
        <ion-icon name="home"></ion-icon> 
    </button> 
</ion-content>

```

你注意到了`ion-content`指令上的填充属性吗？这将为`ion-content`指令添加`16px`的填充。如果你保存文件，你应该会看到这个：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00034.jpeg)

前面的截图涵盖了基于默认 Ionic 颜色样本的所有按钮需求。

另外，你是否注意到按钮的外观在 iOS、Android 和 Windows 之间有所不同？我们将在第五章*Ionic 和 SCSS*中更多地讨论如何自定义这些组件。

有关按钮组件的更多信息，请参考：[`ionicframework.com/docs/api/components/button/Button`](http://ionicframework.com/docs/api/components/button/Button)

# 列表

```html
ion-content section:
```

```html
<ion-list> 
        <ion-item> 
            Light 
        </ion-item> 
        <ion-item> 
            Primary 
        </ion-item> 
        <ion-item> 
            Secondary 
        </ion-item> 
        <ion-item> 
            Danger 
        </ion-item> 
        <ion-item> 
            Dark 
        </ion-item> 
 </ion-list>

```

你应该会看到以下内容：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00035.jpeg)

通过向`ion-list`指令添加一个名为`no-lines`的属性，线条将消失。如果你将前面的代码片段更新为以下内容：

```html
<ion-list no-lines> 
        <ion-item> 
            Light 
        </ion-item> 
        <ion-item> 
            Primary 
        </ion-item> 
        <ion-item> 
            Secondary 
        </ion-item> 
        <ion-item> 
            Danger 
        </ion-item> 
        <ion-item> 
            Dark 
        </ion-item> 
    </ion-list>

```

你应该能够看到以下屏幕：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00036.jpeg)

你还可以使用`ion-item-group`将列表项分组在一起。其代码如下：

```html
<ion-list> 
    <ion-item-group> 
        <ion-item-divider light>A</ion-item-divider> 
        <ion-item>Apple</ion-item> 
        <ion-item>Apricots</ion-item> 
        <ion-item>Avocado</ion-item> 
        <ion-item-divider light>B</ion-item-divider> 
        <ion-item>Bananas</ion-item> 
        <ion-item>Blueberries</ion-item> 
        <ion-item>Blackberries</ion-item> 
    </ion-item-group>  
</ion-list>

```

为此，`ion-list`将被替换为`ion-item-group`，如前面的代码片段所示。你应该会看到以下屏幕：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00037.jpeg)

Ionic 列表的新添加是滑动列表。在这种类型的列表中，每个项目都可以向左滑动以显示新选项。

这段代码的片段如下所示：

```html
<ion-list> 
        <ion-item-sliding> 
            <ion-item> 
                <ion-avatar item-left> 
                    <img src="img/~text?
                     txtsize=23&txt=80%C3%9780&w=80&h=80"> 
                </ion-avatar> 
                <h2>Indiana Jones</h2> 
                <p>Played by Harrison Ford in Raiders of the Lost Ark
                </p> 
            </ion-item> 
            <ion-item-options> 
                <button ion-button color="light"> 
                    <ion-icon name="ios-more"></ion-icon> 
                    More 
                </button> 
                <button ion-button color="primary"> 
                    <ion-icon name="text"></ion-icon> 
                    Text 
                </button> 
                <button ion-button color="secondary"> 
                    <ion-icon name="call"></ion-icon> 
                    Call 
                </button> 
            </ion-item-options> 
        </ion-item-sliding> 
        <ion-item-sliding> 
            <ion-item> 
                <ion-avatar item-left> 
                    <img src="img/~text?
                     txtsize=23&txt=80%C3%9780&w=80&h=80"> 
                </ion-avatar> 
                <h2>James Bond</h2> 
                <p>Played by Sean Connery in Dr. No</p> 
            </ion-item> 
            <ion-item-options> 
                <button ion-button color="light"> 
                    <ion-icon name="ios-more"></ion-icon> 
                    More 
                </button> 
                <button ion-button color="primary"> 
                    <ion-icon name="text"></ion-icon> 
                    Text 
                </button> 
                <button ion-button color="secondary"> 
                    <ion-icon name="call"></ion-icon> 
                    Call 
                </button> 
            </ion-item-options> 
        </ion-item-sliding> 
</ion-list>

```

前面代码的输出如下所示：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00038.jpeg)

有关列表组件的更多信息，您可以参考以下链接：[`ionicframework.com/docs/components/#lists`](http://ionicframework.com/docs/components/#lists)

# 卡片

卡片是在移动设备上展示内容的最佳设计模式之一。对于显示用户个性化内容的任何页面或应用程序，卡片都是最佳选择。世界正在向卡片展示内容的方式发展，包括在某些情况下也在桌面上。例如 Twitter ([`dev.twitter.com/cards/overview`](https://dev.twitter.com/cards/overview))和 Google Now。

因此，您也可以将该设计模式简单地移植到您的应用程序中。您需要做的就是设计适合卡片的个性化内容，并将其放入`ion-card`组件中：

```html
<ion-card> 
 <ion-card-header> 
      Card Header 
 </ion-card-header> 
<ion-card-content> 
            Lorem ipsum dolor sit amet, consectetur adipisicing elit. Dignissimos magni itaque numquam distinctio pariatur voluptas sint, id inventore nulla vitae. Veritatis animi eos cupiditate. Labore, amet debitis maxime velit assumenda. 
</ion-card-content> 
</ion-card>

ion-card-header directive and the output would look as follows:
```

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00039.jpeg)

您可以通过向卡片添加图像来为卡片增添创意：

```html
<ion-card> 
        <img src="img/~text?
         txtsize=72&txt=600%C3%97390&w=600&h=390" /> 
        <ion-card-content> 
            <h2 class="card-title"> 
        quas quae sunt 
      </h2> 
            <p> 
                Lorem ipsum dolor sit amet, 
                consectetur adipisicing elit. Magni nihil 
                hic vel fugit dignissimos ad natus eaque! 
                Perspiciatis beatae quis doloremque soluta 
                enim ratione laboriosam. Dolore illum, 
                quas quae sunt. 
            </p> 
        </ion-card-content> 
        <ion-row no-padding> 
            <ion-col width-33> 
                <button ion-button clear small color="danger"> 
                    <ion-icon name='star'></ion-icon> 
                    Dolore 
                </button> 
            </ion-col> 
            <ion-col width-33> 
                <button ion-button clear small color="danger"> 
                    <ion-icon name='musical-notes'></ion-icon> 
                    Perspi 
                </button> 
            </ion-col> 
            <ion-col width-33> 
                <button ion-button clear small color="danger"> 
                    <ion-icon name='share-alt'></ion-icon> 
                    Magni 
                </button> 
            </ion-col> 
        </ion-row> 
</ion-card>

```

这将如下所示：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00040.jpeg)

您还可以使用卡片来显示地图：

```html
    <ion-card> 
        <div style="position: relative"> 
            <img src="img/staticmap?
             center=Malaysia&size=640x400&style=element:
             labels|visibility:off&style=
             element:geometry.stroke|visibility:off&style=
             feature:landscape|element:
             geometry|saturation:-100&style=feature:
             water|saturation:-100|invert_lig
             htness:true&key=
             AIzaSyA4rAT0fdTZLNkJ5o0uaAwZ89vVPQpr_Kc"> 
            <ion-fab bottom right edge> 
                <button ion-fab mini> 
                    <ion-icon name='pin'></ion-icon> 
                </button> 
            </ion-fab> 
        </div> 
        <ion-item> 
            <ion-icon subtle large item-left name='map'></ion-icon> 
            <h2>Malaysia</h2> 
            <p>Truely Asia!!</p> 
        </ion-item> 
    </ion-card>

```

你应该能够看到以下屏幕：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00041.jpeg)

有了`ion-card`的强大功能，您可以将应用程序提升到一个新水平！

# Ionic 图标

Ionic 拥有自己的 700 多个字体图标。添加图标的最简单方法如下：

```html
<ion-icon name="heart"></ion-icon>

```

您可以从这里找到图标的名称：[`ionicons.com`](http://ionicons.com)。

您可以使用`is-active`属性将图标标记为活动或非活动。活动图标通常是完整和粗的，而非活动图标是轮廓和细的：

```html
<ion-icon name="beer" isActive="true"></ion-icon> 
<ion-icon name="beer" isActive="false"></ion-icon>

```

图标也可以根据平台进行设置；以下片段显示了如何设置：

```html
<ion-icon ios="logo-apple" md="logo-android"></ion-icon>

```

您也可以通过首先创建一个分配给变量的属性，然后在构造函数中填充该变量，以编程方式设置图标名称。HTML 片段如下所示：

```html
<ion-icon [name]="myIcon"></ion-icon>

```

TypeScript 代码（在`home.ts`中）如下所示：

```html
import { Component } from '@angular/core';

@Component({
  selector: 'page-home',
  templateUrl: 'home.html'
})
export class HomePage {

  myIcon: String;
  iconNames: Array<String> = ['home', 'map', 'pin', 'heart', 'star'];

  constructor(public navCtrl: NavController) {
    this.myIcon = this.iconNames[Math.floor(Math.random() * 
    this.iconNames.length)];
  }
}

```

前面片段的整合输出如下：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00042.jpeg)

# 模态框

在本节中，我们将看一下 Ionic 中的模态框以及如何实现它们。要使用此示例，我们需要搭建一个新项目：

```html
ionic start -a "Example 6" -i app.example.six example6 blank --v2

```

`cd`进入`example6`文件夹并运行`ionic serve --lab`，您应该看到空白模板的主页。

要使用模态框，我们需要首先创建一个要显示为模态框的组件。

从`example6`文件夹内运行以下命令：

```html
ionic generate component helloModal

```

注意：我们将在本章的后面部分讨论子生成器。

注意：如果您使用的是最新的 Ionic CLI，您将看到一个名为`hello-modal.module.ts`的文件与`hello-modal.html`、`hello-modal.scss`和`hello-modal.ts`一起生成。要了解有关`hello-modal.module.ts`的更多信息，请参考第十一章，*Ionic 3*。

生成组件后，我们需要将其添加到`@NgModule`中。打开`src/app/app.module.ts`并添加`import`语句：

```html
import { HelloModalComponent } 
from '../components/hello-modal/hello-modal';

```

注意：生成的组件可能具有`HelloModal`而不是`HelloModalComponent`的类名。如果是这种情况，请相应更新。

接下来，将`HelloModalComponent`添加到`declarations`和`entryComponents`中，如下所示：

```html
@NgModule({ 
  declarations: [ 
    MyApp, 
    HomePage, 
    HelloModalComponent 
  ], 
  imports: [ 
    IonicModule.forRoot(MyApp) 
  ], 
  bootstrap: [IonicApp], 
  entryComponents: [ 
    MyApp, 
    HomePage, 
    HelloModalComponent 
  ], 
  providers: [ 
    StatusBar, 
    SplashScreen, 
    {provide: ErrorHandler, useClass: IonicErrorHandler} 
  ] 
})

```

现在已经完成，我们开始配置组件。打开`src/pages/home/home.ts`并更新如下：

```html
import { Component } from '@angular/core'; 
import { ModalController } from 'ionic-angular'; 
import { HelloModalComponent } from '../../components/hello-modal/hello-modal'; 

@Component({ 
   selector: 'page-home', 
   templateUrl: 'home.html' 
}) 
export class HomePage { 

   constructor(public modalCtrl: ModalController) { } 

   show() { 
      let modal = this.modalCtrl.create(HelloModalComponent); 
      modal.present(); 
      modal.onDidDismiss((data) => { 
         console.log(data); 
      }); 
   } 
}

```

如你所见，对于使用`modal`组件，我们有一个`ModalController`。使用`ModalController`实例的`create()`，我们可以注册一个模态框。然后，使用`present()`，我们显示模态框。

更新`src/pages/home/home.html`以显示一个按钮。点击该按钮将呈现模态框：

```html
<ion-header> 
  <ion-navbar> 
    <ion-title> 
      My Modal App 
    </ion-title> 
  </ion-navbar> 
</ion-header> 

<ion-content padding> 
  <button ion-button color="primary" (click)="show()">Show Modal</button> 
</ion-content>

```

接下来，我们更新`HelloModalComponent`。打开`src/components/hello-modal/hello-modal.ts`并更新如下：

```html
import { Component } from '@angular/core'; 
import { ViewController } from 'ionic-angular'; 

@Component({ 
  selector: 'hello-modal', 
  templateUrl: 'hello-modal.html' 
}) 
export class HelloModalComponent { 

  constructor(public viewCtrl: ViewController) { } 

  close() { 
    this.viewCtrl.dismiss({'random' : 'data'}); 
  } 
}

```

在这里，我们使用`ViewController`的实例来管理弹出窗口。最后，对于弹出窗口的内容，打开`src/components/hello-modal/hello-modal.html`并更新如下：

```html
<ion-content padding> 
    <h2>I'm a modal!</h2> 
    <button ion-button color="danger" (click)="close()">Close</button> 
</ion-content>

```

有了这个，我们已经添加了所有需要的代码。保存所有文件并运行`ionic serve -lab`以查看输出。

输出应如下所示：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00043.jpeg)

# 分段

Segment 是 Ionic 的另一个新功能。这个组件用于控制单选按钮的选择。我们将搭建另一个应用程序来使用这个示例。从`chapter3`文件夹内，运行以下命令：

```html
ionic start -a "Example 7" -i app.example.seven example7 blank --v2 

```

`cd`进入`example7`文件夹，运行`ionic serve --lab`，你应该会看到空模板的主页。

```html
ion-content directive in the src/pages/home/home.html file:
```

```html
    <ion-segment [(ngModel)]="food" color="primary"> 
        <ion-segment-button value="pizza"> 
            Pizza 
        </ion-segment-button> 
        <ion-segment-button value="burger"> 
            Burger 
        </ion-segment-button> 
    </ion-segment> 
    <div [ngSwitch]="food"> 
        <ion-list *ngSwitchCase="'pizza'"> 
            <ion-item> 
                <ion-thumbnail item-left> 
                    <img src="img/~text?
                     txtsize=23&txt=80%C3%9780&w=80&h=80"> 
                </ion-thumbnail> 
                <h2>Pizza 1</h2> 
            </ion-item> 
            <ion-item> 
                <ion-thumbnail item-left> 
                    <img src="img/~text?
                     txtsize=23&txt=80%C3%9780&w=80&h=80"> 
                </ion-thumbnail> 
                <h2>Pizza 2</h2> 
            </ion-item> 
        </ion-list> 
        <ion-list *ngSwitchCase="'burger'"> 
            <ion-item> 
                <ion-thumbnail item-left> 
                    <img src="img/~text?
                     txtsize=23&txt=80%C3%9780&w=80&h=80"> 
                </ion-thumbnail> 
                <h2>Burger 1</h2> 
            </ion-item> 
            <ion-item> 
                <ion-thumbnail item-left> 
                    <img src="img/~text?
                     txtsize=23&txt=80%C3%9780&w=80&h=80"> 
                </ion-thumbnail> 
                <h2>Burger 2</h2> 
            </ion-item> 
        </ion-list> 
    </div>

```

我们在`src/pages/home/home.ts`文件中将 food 属性初始化为`pizza`，如下所示：

```html

import { Component } from '@angular/core'; 
import { NavController } from 'ionic-angular'; 

@Component({ 
   selector: 'page-home', 
   templateUrl: 'home.html' 
}) 
export class HomePage { 
   food: string; 

   constructor(public navCtrl: NavController) { 
      this.food = 'pizza'; 
   } 
}

```

输出应该如下所示：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00044.jpeg)

# Ionic 导航

在本节中，我们将看看 Ionic 导航。我们将搭建一个空模板，然后添加更多页面，看看如何在它们之间导航。

Ionic 3 引入了`@IonicPage`装饰器，用于简化和改进导航，围绕原生移动体验。请查看第十一章，*Ionic 3*。

# 基本导航

要开始，我们需要搭建一个新项目。运行以下命令：

```html
ionic start -a "Example 8" -i app.example.eight example8 blank --v2

```

使用`ionic serve`命令运行 Ionic 应用，你应该会看到空模板的主页。

Ionic 中的导航不需要 URL；相反，页面是从导航控制器的页面堆栈中推送和弹出的。与基于浏览器的导航相比，这种方法非常符合在原生移动应用中实现导航的方式。但是，你可以使用 URL 进行页面深度链接，但这并不定义导航。

要了解基本导航，我们打开`src/app/app.html`文件，应该会找到以下模板：

```html
<ion-nav [root]="rootPage"></ion-nav>

```

`ion-nav`是`NavController`的子类，其目的是与导航页面堆栈一起工作。为了让`ion-nav`正常工作，我们必须将根页面设置为最初加载的页面，其中根页面是任何`@component`。

所以如果我们看`app.component.ts`，它指向一个名为 rootPage 的局部变量，并且设置为 HomePage。

现在，在`src/pages/home/home.html`中，我们会看到顶部有一个部分，如下所示：

```html
  <ion-navbar> 
    <ion-title> 
      Ionic Blank 
    </ion-title> 
  </ion-navbar>

```

这是动态导航栏。

在`src/pages/home/home.ts`内，我们可以按如下方式访问`NavController`：

```html
import { Component } from '@angular/core'; 
import { NavController } from 'ionic-angular'; 

@Component({ 
  selector: 'page-home', 
  templateUrl: 'home.html' 
}) 
export class HomePage { 
  constructor(public navCtrl: NavController) { 

  } 
}

```

现在我们可以访问导航属性。

# Ionic CLI 子生成器

全新的 Ionic CLI v2 现在充满了子生成器，可以帮助搭建页面、组件、提供者等。要查看可用子生成器的列表，可以运行以下命令：

```html
ionic generate --list 

```

你会看到以下内容：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00045.jpeg)

现在，我们将使用前面的子生成器，在`example8`项目内生成两个页面。运行以下命令：

```html
ionic generate page about

```

还要运行以下命令：

```html
ionic generate page contact

```

在`app/pages`文件夹内，你应该会看到两个新文件夹，about 和 contact 文件夹，它们有自己的`html`、`ts`和`scss`文件，以及`module.ts`文件。

类名为`About`而不是`AboutPage`。如果是这样，请相应地更新前面的内容。

在我们继续之前，我们需要按如下方式将`AboutPage`和`ContactPage`添加到`src/app/app.module.ts`中：

```html
import { NgModule, ErrorHandler } from '@angular/core'; 
import { IonicApp, IonicModule, IonicErrorHandler } from 'ionic-angular'; 
import { MyApp } from './app.component'; 
import { HomePage } from '../pages/home/home'; 
import { AboutPage } from '../pages/about/about'; 
import { ContactPage } from '../pages/contact/contact'; 

import { StatusBar } from '@ionic-native/status-bar'; 
import { SplashScreen } from '@ionic-native/splash-screen'; 

@NgModule({ 
  declarations: [ 
    MyApp, 
    HomePage, 
    AboutPage, 
    ContactPage 
  ], 
  imports: [ 
    IonicModule.forRoot(MyApp) 
  ], 
  bootstrap: [IonicApp], 
  entryComponents: [ 
    MyApp, 
    HomePage, 
    AboutPage, 
    ContactPage 
  ], 
  providers: [ 
    StatusBar, 
    SplashScreen, 
    { provide: ErrorHandler, useClass: IonicErrorHandler } 
  ] 
}) 
export class AppModule { }

```

# 多页面导航

现在我们有了三个页面，我们将看看如何在它们之间实现导航。从主页，用户应该能够转到关于和联系页面，从关于页面转到联系和主页，最后从联系页面转到主页和关于页面。

首先，我们按如下方式更新`home.html`：

```html
<ion-header> 
    <ion-navbar> 
        <ion-title> 
            Home Page 
        </ion-title> 
    </ion-navbar> 
</ion-header> 
<ion-content padding> 
    <ion-card> 
        <ion-card-header> 
            Home Page 
        </ion-card-header> 
        <ion-card-content> 
            <button ion-button (click)="goTo('about')">About</button> 
            <button ion-button color="danger"  
             (click)="goTo('contact')">Contact</button> 
            <button ion-button color="light" 
             (click)="back()">Back</button> 
        </ion-card-content> 
    </ion-card> 
</ion-content>

```

接下来，我们按如下方式更新`home.ts`：

```html

import { Component } from '@angular/core'; 
import { NavController } from 'ionic-angular'; 

import { AboutPage } from '../about/about'; 
import { ContactPage } from '../contact/contact'; 

@Component({ 
   selector: 'page-home', 
   templateUrl: 'home.html' 
}) 
export class HomePage { 
   constructor(private navCtrl: NavController) { } 

   goTo(page) { 
      if (page === 'about') { 
         this.navCtrl.push(AboutPage); 
      } else if (page === 'contact') { 
         this.navCtrl.push(ContactPage); 
      } 
   } 

   back() { 
      if (this.navCtrl.length() >= 2) { 
         this.navCtrl.pop(); 
      } 
   } 
}

```

你注意到`goTo`和`back`函数了吗？这就是我们从一个页面导航到另一个页面的方式。

接下来，我们将按如下方式更新`about.html`：

```html
<ion-header> 
    <ion-navbar> 
        <ion-title> 
            About Page 
        </ion-title> 
    </ion-navbar> 
</ion-header> 
<ion-content padding> 
    <ion-card> 
        <ion-card-header> 
            About Page 
        </ion-card-header> 
        <ion-card-content> 
            <button ion-button (click)="goTo('home')">Home</button> 
            <button ion-button color="danger" 
             (click)="goTo('contact')">Contact</button> 
            <button ion-button color="light" 
             (click)="back()">Back</button> 
        </ion-card-content> 
    </ion-card> 
</ion-content>

```

`about.ts`如下：

```html
import { Component } from '@angular/core'; 
import { NavController } from 'ionic-angular'; 

import { HomePage } from '../home/home'; 
import { ContactPage } from '../contact/contact'; 

@Component({ 
   selector: 'page-home', 
   templateUrl: 'home.html' 
}) 
export class AboutPage { 
   constructor(private navCtrl: NavController) { } 

   goTo(page) { 
      if (page === 'home') { 
         this.navCtrl.push(HomePage); 
      } else if (page === 'contact') { 
         this.navCtrl.push(ContactPage); 
      } 
   } 

   back() { 
      if (this.navCtrl.length() >= 2) { 
         this.navCtrl.pop(); 
      } 
   } 
}

```

最后，`contact.html`：

```html
<ion-header> 
    <ion-navbar> 
        <ion-title> 
            Contact Page 
        </ion-title> 
    </ion-navbar> 
</ion-header> 
<ion-content padding> 
    <ion-card> 
        <ion-card-header> 
            Contact Page 
        </ion-card-header> 
        <ion-card-content> 
            <button ion-button (click)="goTo('home')">Home</button> 
            <button ion-button color="danger" 
             (click)="goTo('about')">About</button> 
            <button ion-button color="light" 
             (click)="back()">Back</button> 
        </ion-card-content> 
    </ion-card> 
</ion-content>

```

以及`contact.ts`如下：

```html

import { Component } from '@angular/core'; 
import { NavController } from 'ionic-angular'; 

import { HomePage } from '../home/home'; 
import { AboutPage } from '../about/about'; 

@Component({ 
   selector: 'page-home', 
   templateUrl: 'home.html' 
}) 
export class ContactPage { 
   constructor(private navCtrl: NavController) { } 

   goTo(page) { 
      if (page === 'home') { 
         this.navCtrl.push(HomePage); 
      } else if (page === 'about') { 
         this.navCtrl.push(AboutPage); 
      } 
   } 

   back() { 
      if (this.navCtrl.length() >= 2) { 
         this.navCtrl.pop(); 
      } 
   } 
}

```

如果我们保存所有文件并返回浏览器，我们应该会看到以下内容：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00046.jpeg)

当我们点击 About 按钮时，我们应该会看到以下屏幕：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00047.jpeg)

正如我们所看到的，返回按钮会自动添加到导航栏中。现在，当我们点击返回按钮时，我们将返回到主页。如果你注意到了返回功能，我们添加了一个条件来检查堆栈中是否有多个视图以弹出视图。如果只有一个视图，它将被移除，用户将看到一个黑屏，如下所示：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00048.jpeg)

为了避免应用程序中的**黑屏死机**，我们添加了这个条件。

现在我们了解了 Ionic 应用程序中的导航，你可以回到标签模板和侧边菜单模板，并查看`src`文件夹以开始。

另外，请查看第十一章，*Ionic 3*，了解更多关于`@IonicPage`修饰符以及深度链接的信息。

# 摘要

在本章中，我们已经了解了 Ionic 网格系统和一些主要的 Ionic 组件，并且看到了如何使用它们。我们介绍了按钮、列表、卡片、图标和段落。接下来，我们将看到如何使用导航组件以及如何在页面之间导航。

在下一章中，我们将使用 Ionic 修饰符和服务，并且我们将看看 Ionic 提供的修饰符和服务。
