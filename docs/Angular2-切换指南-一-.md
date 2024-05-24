# Angular2 切换指南（一）

> 原文：[`zh.annas-archive.org/md5/AE0A0B893569467A0AAE20A9EA07809D`](https://zh.annas-archive.org/md5/AE0A0B893569467A0AAE20A9EA07809D)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

AngularJS 是一个使构建 Web 应用程序更容易的 JavaScript 开发框架。它如今被用于大规模、高流量的网站，这些网站在性能不佳、可移植性问题、SEO 不友好和规模复杂性方面存在困难。Angular 2 改变了这一切。

这是您构建高性能和健壮 Web 应用程序所需的现代框架。*转向 Angular 2* 是快速掌握 Angular 2 的最快途径，它将帮助您过渡到 Angular 2 的全新世界。

在本书结束时，您将准备好开始构建快速高效的 Angular 2 应用程序，充分利用提供的所有新功能。

# 本书涵盖了以下内容

第一章，“开始学习 Angular 2”，开启了我们进入 Angular 2 世界的旅程。它描述了框架设计决策背后的主要原因。我们将探讨框架形成的两个主要驱动因素——Web 的当前状态和前端开发的演变。

第二章，“Angular 2 应用程序的构建模块”，概述了 Angular 2 引入的核心概念。我们将探讨 AngularJS 1.x 提供的应用程序开发基础模块与框架最新主要版本中的区别。

第三章，“TypeScript Crash Course”，解释了虽然 Angular 2 是一种语言不可知的框架，但谷歌建议利用 TypeScript 的静态类型。在本章中，您将学习开发 Angular 2 应用程序所需的所有基本语法！

第四章《使用 Angular 2 组件和指令入门》描述了开发应用程序用户界面的核心构建模块——指令和组件。我们将深入探讨诸如视图封装、内容投影、输入和输出、变更检测策略等概念。我们还将讨论一些高级主题，如模板引用和使用不可变数据加速应用程序。

第五章《Angular 2 中的依赖注入》涵盖了框架中最强大的功能之一，这是由 AngularJS 1.x 最初引入的：其依赖注入机制。它使我们能够编写更易于维护、可测试和可理解的代码。在本章结束时，我们将了解如何在服务中定义业务逻辑，并通过 DI 机制将它们与 UI 粘合在一起。我们还将深入研究一些更高级的概念，如注入器层次结构、配置提供者等。

第六章《使用 Angular 2 路由器和表单》探讨了在开发实际应用程序过程中管理表单的新模块。我们还将实现一个显示通过表单输入的数据的页面。最后，我们将使用基于组件的路由器将各个页面粘合成一个应用程序。

第七章《管道解释和与 RESTful 服务通信》深入探讨了路由器和表单模块。在这里，我们将探索如何开发模型驱动的表单，定义参数化和子路由。我们还将解释 HTTP 模块，以及如何开发纯管道和不纯管道。

第八章, *SEO 和 Angular 2 在现实世界中*，探讨了 Angular 2 应用程序开发中的一些高级主题，例如在 Web Workers 和服务器端渲染中运行应用程序。在本章的第二部分，我们将探讨一些可以简化开发人员日常工作的工具，如`angular-cli`和`angular2-seed`，解释热重载的概念等。

# 本书需要什么

在本书中，您需要的是一个简单的文本编辑器或 IDE，安装了 Node.js、TypeScript，有互联网访问权限和浏览器。

每一章都介绍了运行提供的代码片段所需的软件要求。

# 这本书是为谁准备的

您想要深入了解 Angular 2 吗？或者您有兴趣在转换之前评估这些更改吗？如果是这样，那么*转换到 Angular 2*就是适合您的书。

要充分利用本书，您需要对 AngularJS 1.x 有基本的了解，并且对 JavaScript 有很好的理解。不需要了解 Angular 2 的更改就可以跟上。

# 约定

在本书中，您将找到一些区分不同信息类型的文本样式。以下是一些样式的示例及其含义的解释。

文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 用户名显示如下: "您应该看到相同的结果，但没有存储在磁盘上的`test.js`文件。"

代码块设置如下:

```ts
@Injectable()
class Socket {
  constructor(private buffer: Buffer) {}
}

let injector = Injector.resolveAndCreate([
  provide(BUFFER_SIZE, { useValue: 42 }),
  Buffer,
  Socket
]);

injector.get(Socket);
```

当我们希望引起您对代码块的特定部分的注意时，相关的行或项目会以粗体显示:

```ts
let injector = Injector.resolveAndCreate([
  provide(**BUFFER_SIZE**, { useValue: 42 }),
  Buffer,
  Socket
]);
```

与本书中的代码一起存储在存储库中的每个代码片段都以注释开头，注释中包含相应的文件位置，相对于`app`目录:

```ts
// ch5/ts/injector-basics/forward-ref.ts

@Injectable()
class Socket {
  constructor(private buffer: Buffer) {…}
}
```

**新术语**和**重要单词**以粗体显示。您在屏幕上看到的单词，例如菜单或对话框中的单词，会在文本中显示为: "当标记呈现到屏幕上时，用户将看到的只是标签:**加载中...**。"

### 注意

警告或重要提示以这样的框出现。

### 提示

技巧和窍门会以这种方式出现。


# 第一章：开始使用 Angular 2

2014 年 9 月 18 日，第一个公共提交被推送到 Angular 2 存储库。几周后，在 ng-europe 上，核心团队的 Igor 和 Tobias 简要概述了 Angular 2 的预期。当时的愿景远非最终；然而，有一件事是确定的——新版本的框架将与 AngularJS 1.x 完全不同。

这一公告引发了许多问题和争议。变化背后的原因非常明确——AngularJS 1.x 不再能充分利用发展中的 Web，并且无法完全满足大规模 JavaScript 应用程序的要求。一个新的框架将让 Angular 开发人员以更简单、更直接的方式利用 Web 技术的发展。然而，人们感到担忧。对于开发人员来说，与第三方软件的新版本进行迁移是最大的噩梦之一。在 Angular 的情况下，宣布后，迁移看起来令人生畏，甚至不可能。后来，在 ng-conf 2015 和 ng-vegas 上，引入了不同的迁移策略。Angular 社区汇聚在一起，分享额外的想法，预期 Angular 2 的好处，同时保留了从 AngularJS 1.x 中学到的东西。

这本书是该项目的一部分。升级到 Angular 2 并不容易，但是很值得。Angular 2 背后的主要驱动因素是 Web 的发展，以及从在野外使用 AngularJS 1.x 中所学到的经验。切换到 Angular 2 将帮助您通过了解我们是如何到达这里以及为什么 Angular 的新特性对于构建高性能、可扩展的单页应用程序在现代 Web 中具有直观意义来学习新框架。

# Web 的发展——是时候使用新框架了

在过去的几年里，网络发展迅速。在实施 ECMAScript 5 的同时，ECMAScript 6 标准开始了开发（现在被称为 ECMAScript 2015 或 ES2015）。ES2015 在语言中引入了许多变化，例如为模块添加内置语言支持，块作用域变量定义，以及许多语法糖，如类和解构。

与此同时，**Web Components**被发明了。Web Components 允许我们定义自定义 HTML 元素并为其附加行为。由于扩展现有 HTML 元素（如对话框、图表、网格等）很难，主要是因为需要时间来巩固和标准化它们的 API，更好的解决方案是允许开发人员按照他们的意愿扩展现有元素。Web Components 为我们提供了许多好处，包括更好的封装性，我们生成的标记的更好语义，更好的模块化，以及开发人员和设计人员之间更容易的沟通。

我们知道 JavaScript 是一种单线程语言。最初，它是为了简单的客户端脚本而开发的，但随着时间的推移，它的作用发生了很大变化。现在有了 HTML5，我们有了不同的 API，允许音频和视频处理，通过双向通信渠道与外部服务通信，传输和处理大块原始数据等。主线程中的所有这些繁重计算可能会导致用户体验不佳。当执行耗时计算时，可能会导致用户界面冻结。这导致了**WebWorkers**的开发，它允许在后台执行脚本，并通过消息传递与主线程通信。这样，多线程编程被引入到了浏览器中。

其中一些 API 是在 AngularJS 1.x 的开发之后引入的；这就是为什么框架并没有考虑大部分 API。然而，利用这些 API 给开发人员带来了许多好处，比如：

+   显著的性能改进。

+   开发具有更好质量特征的软件。

现在让我们简要讨论这些技术如何成为新的 Angular 核心的一部分，以及原因。

# ECMAScript 的发展

如今，浏览器供应商以短迭代的方式发布新功能，用户经常收到更新。这有助于推动 Web 前进，使开发人员能够利用尖端技术，旨在改进 Web。ES2015 已经标准化。最新版本的语言已经在主要浏览器中开始实现。学习新的语法并利用它不仅会提高我们作为开发人员的生产力，还会为我们在不久的将来当所有浏览器都完全支持它时做好准备。这使得现在开始使用最新的语法至关重要。

一些项目的要求可能要求我们支持不支持任何 ES2015 功能的旧浏览器。在这种情况下，我们可以直接编写 ECMAScript 5，它具有不同的语法，但与 ES2015 具有等效的语义。然而，我们可以利用**转译**的过程。在我们的构建过程中使用转译器可以让我们通过编写 ES2015 并将其转换为浏览器支持的目标语言来利用新的语法。

AngularJS 自 2009 年以来就存在。当时，大多数网站的前端都是由 ECMAScript 3 驱动的，这是 ECMAScript 5 之前的最后一个主要版本。这自动意味着框架实现所使用的语言是 ECMAScript 3。利用新版本的语言需要将整个 AngularJS 1.x 移植到 ES2015。

从一开始，Angular 2 就考虑到了 Web 的当前状态，引入了框架中的最新语法。虽然 Angular 2 是用 ES2016 的超集（TypeScript）编写的（我们马上会看一下），但它允许开发人员使用他们自己喜欢的语言。我们可以使用 ES2015，或者，如果我们不想对我们的代码进行任何中间预处理并简化构建过程，甚至可以使用 ECMAScript 5。

## Web 组件

Web Components 的第一个公开草案于 2012 年 5 月 22 日发布，大约在发布 AngularJS 1.x 三年后。正如前面提到的，Web Components 标准允许我们创建自定义元素并为其附加行为。听起来很熟悉；我们已经在 AngularJS 1.x 应用程序的用户界面开发中使用了类似的概念。Web Components 听起来像是 Angular 指令的替代品；然而，它们具有更直观的 API、更丰富的功能和内置的浏览器支持。它们引入了一些其他好处，比如更好的封装，这在处理 CSS 样式冲突方面非常重要。

在 AngularJS 1.x 中添加 Web Components 支持的一种可能策略是改变指令的实现，并在 DOM 编译器中引入新标准的原语。作为 Angular 开发人员，我们知道指令 API 是多么强大但也复杂。它包括许多属性，如`postLink`、`preLink`、`compile`、`restrict`、`scope`、`controller`等等，当然还有我们最喜欢的`transclude`。作为标准，Web Components 将在浏览器中以更低的级别实现，这带来了许多好处，比如更好的性能和本机 API。

在实现 Web Components 时，许多网络专家遇到了与 Angular 团队在开发指令 API 时遇到的相同问题，并提出了类似的想法。Web Components 背后的良好设计决策包括**content**元素，它解决了 AngularJS 1.x 中臭名昭著的 transclusion 问题。由于指令 API 和 Web Components 以不同的方式解决了类似的问题，将指令 API 保留在 Web Components 之上将是多余的，并增加了不必要的复杂性。这就是为什么 Angular 核心团队决定从头开始，构建在 Web Components 之上，并充分利用新标准的原因。Web Components 涉及新功能，其中一些尚未被所有浏览器实现。如果我们的应用程序在不支持这些功能的浏览器中运行，Angular 2 会模拟它们。一个例子是使用指令`ng-content`来模拟 content 元素。

## WebWorkers

JavaScript 以其事件循环而闻名。通常，JavaScript 程序在单个线程中执行，并且不同的事件被推送到队列中并按顺序依次处理，按照它们到达的顺序。然而，当计划的事件之一需要大量的计算时间时，这种计算策略就不够有效了。在这种情况下，事件的处理将阻塞主线程，并且直到耗时的计算完成并将执行传递给队列中的下一个事件之前，所有其他事件都不会被处理。一个简单的例子是鼠标点击触发一个事件，在回调中我们使用 HTML5 音频 API 进行一些音频处理。如果处理的音轨很大，算法运行的负担很重，这将影响用户体验，直到执行完成为止，界面会被冻结。

WebWorker API 的引入是为了防止这种陷阱。它允许在不同线程的上下文中执行重型计算，这样可以使主执行线程空闲，能够处理用户输入和渲染用户界面。

我们如何在 Angular 中利用这一点？为了回答这个问题，让我们想一想在 AngularJS 1.x 中的工作原理。假设我们有一个企业应用程序，需要处理大量数据，并且需要使用数据绑定在屏幕上呈现这些数据。对于每个绑定，都会添加一个新的观察者。一旦 digest 循环运行，它将遍历所有观察者，执行与它们相关的表达式，并将返回的结果与上一次迭代获得的结果进行比较。我们在这里有一些减速：

+   对大量观察者进行迭代。

+   在给定上下文中评估表达式。

+   返回结果的副本。

+   表达式评估的当前结果与先前结果之间的比较。

所有这些步骤可能会相当慢，具体取决于输入的大小。如果 digest 循环涉及重型计算，为什么不将其移动到 WebWorker 中呢？为什么不在 WebWorker 中运行 digest 循环，获取更改的绑定，并将其应用于 DOM？

社区进行了试验，旨在达到这一目标。然而，它们与框架的整合并不是简单的。令人不满意的结果背后的主要原因之一是框架与 DOM 的耦合。在监视器的回调函数中，Angular 经常直接操作 DOM，这使得将监视器移动到 WebWorkers 中变得不可能，因为 WebWorkers 在隔离的上下文中被调用，无法访问 DOM。在 AngularJS 1.x 中，我们可能存在不同监视器之间的隐式或显式依赖关系，这需要多次迭代 digest 循环才能获得稳定的结果。结合最后两点，很难在除执行主线程之外的线程中实现实际结果。

在 AngularJS 1.x 中修复这个问题会在内部实现中引入大量的复杂性。这个框架根本就没有考虑到这一点。由于 WebWorkers 是在 Angular 2 设计过程开始之前引入的，核心团队从一开始就考虑到了它们。

# 在野外学到的 AngularJS 1.x 的教训

尽管前一部分介绍了需要重新实现框架以响应最新趋势的许多论点，但重要的是要记住我们并不是完全从零开始。我们将从 AngularJS 1.x 中学到的东西带到了现在。自 2009 年以来，Web 不是唯一发展的东西。我们还开始构建越来越复杂的应用程序。如今，单页应用程序不再是什么奇特的东西，而更像是解决业务问题的所有 Web 应用程序的严格要求，它们旨在实现高性能和良好的用户体验。

AngularJS 1.x 帮助我们构建了高效和大规模的单页应用程序。然而，通过在各种用例中应用它，我们也发现了一些缺点。从社区的经验中学习，Angular 的核心团队致力于新的想法，旨在满足新的需求。当我们看着 Angular 2 的新特性时，让我们以 AngularJS 1.x 的当前实现为背景来考虑它们，并思考我们作为 Angular 开发人员在过去几年中所挣扎和修改的事情。

## 控制器

AngularJS 1.x 遵循**模型视图控制器**（**MVC**）微架构模式。有人可能会认为它看起来更像**模型视图视图模型**（**MVVM**），因为视图模型作为作用域或当前上下文附加到作用域或控制器的属性。如果我们使用**模型视图呈现器模式**（**MVP**），它可能会以不同的方式进行处理。由于我们可以在应用程序中构造逻辑的不同变体，核心团队将 AngularJS 1.x 称为**模型视图任何**（**MVW**）框架。

在任何 AngularJS 应用程序中，视图应该是指令的组合。指令共同协作，以提供完全功能的用户界面。服务负责封装应用程序的业务逻辑。这是我们应该与 RESTful 服务通过 HTTP 进行通信，与 WebSockets 进行实时通信甚至 WebRTC 的地方。服务是我们应该实现应用程序的领域模型和业务规则的构建模块。还有一个组件，主要负责处理用户输入并将执行委托给服务 - 控制器。

尽管服务和指令有明确定义的角色，但我们经常会看到**大型视图控制器**的反模式，这在 iOS 应用程序中很常见。偶尔，开发人员会尝试直接从他们的控制器访问甚至操作 DOM。最初，这是为了实现一些简单的事情，比如更改元素的大小，或者快速而肮脏地更改元素的样式。另一个明显的反模式是在控制器之间复制业务逻辑。开发人员经常倾向于复制和粘贴应该封装在服务中的逻辑。

构建 AngularJS 应用程序的最佳实践是，控制器不应该在任何情况下操作 DOM，而是所有 DOM 访问和操作应该在指令中进行隔离。如果在控制器之间有一些重复的逻辑，很可能我们希望将其封装到一个服务中，并使用 AngularJS 的依赖注入机制在所有需要该功能的控制器中注入该服务。

这是我们在 AngularJS 1.x 中的出发点。尽管如此，似乎控制器的功能可以移动到指令的控制器中。由于指令支持依赖注入 API，在接收用户输入后，我们可以直接将执行委托给特定的服务，已经注入。这是 Angular 2 使用不同方法的主要原因，通过使用`ng-controller`指令来阻止在任何地方放置控制器。我们将在第四章中看看如何从 Angular 2 组件和指令中取代 AngularJS 1.x 控制器的职责，*开始使用 Angular 2 组件和指令*。

## 作用域

在 AngularJS 中，数据绑定是通过`scope`对象实现的。我们可以将属性附加到它，并在模板中明确声明我们要绑定到这些属性（单向或双向）。尽管 scope 的概念似乎很清晰，但 scope 还有两个额外的责任，包括事件分发和与变更检测相关的行为。Angular 初学者很难理解 scope 到底是什么，以及应该如何使用它。AngularJS 1.2 引入了**controller as 语法**。它允许我们向给定控制器内的当前上下文（`this`）添加属性，而不是显式注入`scope`对象，然后再向其添加属性。这种简化的语法可以从以下片段中演示：

```ts
<div ng-controller="MainCtrl as main">
  <button ng-click="main.clicked()">Click</button>
</div>

function MainCtrl() {
  this.name = 'Foobar';
}
MainCtrl.prototype.clicked = function () {
  alert('You clicked me!');
};
```

Angular 2 更进一步，通过移除`scope`对象来实现。所有表达式都在给定 UI 组件的上下文中进行评估。移除整个 scope API 引入了更高的简单性；我们不再需要显式注入它，而是将属性添加到 UI 组件中，以便稍后绑定。这个 API 感觉更简单和更自然。

我们将在第四章中更详细地了解 Angular 2 组件和变更检测机制，*开始使用 Angular 2 组件和指令*。

## 依赖注入

也许在 JavaScript 世界中，市场上第一个包括**控制反转**（**IoC**）和**依赖注入**（**DI**）的框架是 AngularJS 1.x。DI 提供了许多好处，比如更容易进行测试，更好的代码组织和模块化，以及简单性。尽管 1.x 中的 DI 做得很出色，但 Angular 2 更进一步。由于 Angular 2 建立在最新的 web 标准之上，它使用 ECMAScript 2016 装饰器语法来注释代码以使用 DI。装饰器与 Python 中的装饰器或 Java 中的注解非常相似。它们允许我们通过反射来*装饰*给定对象的行为。由于装饰器尚未标准化并且得到主要浏览器的支持，它们的使用需要一个中间的转译步骤；但是，如果你不想这样做，你可以直接使用更加冗长的 ECMAScript 5 语法编写代码，并实现相同的语义。

新的 DI 更加灵活和功能丰富。它也修复了 AngularJS 1.x 的一些缺陷，比如不同的 API；在 1.x 中，一些对象是按位置注入的（比如在指令的链接函数中的作用域、元素、属性和控制器），而其他对象是按名称注入的（在控制器、指令、服务和过滤器中使用参数名称）。

我们将在第五章中进一步了解 Angular 2 的依赖注入 API，*Angular 2 中的依赖注入*。

## 服务器端渲染

Web 的需求越大，web 应用程序就变得越复杂。构建一个真实的单页面应用程序需要编写大量的 JavaScript，并且包括所有必需的外部库可能会增加页面上脚本的大小达到几兆字节。应用程序的初始化可能需要几秒甚至几十秒，直到所有资源从服务器获取，JavaScript 被解析和执行，页面被渲染，所有样式被应用。在使用移动互联网连接的低端移动设备上，这个过程可能会让用户放弃访问我们的应用程序。尽管有一些加速这个过程的做法，在复杂的应用程序中，并没有一种万能的解决方案。

在努力改善用户体验的过程中，开发人员发现了一种称为**服务器端渲染**的东西。它允许我们在服务器上渲染单页应用程序的请求视图，并直接向用户提供页面的 HTML。稍后，一旦所有资源都被处理，事件监听器和绑定可以由脚本文件添加。这听起来像是提高应用程序性能的好方法。在这方面的先驱之一是 ReactJS，它允许使用 Node.js DOM 实现在服务器端预渲染用户界面。不幸的是，AngularJS 1.x 的架构不允许这样做。阻碍因素是框架与浏览器 API 之间的强耦合，这与在 WebWorkers 中运行变更检测时遇到的问题相同。

服务器端渲染的另一个典型用例是构建**搜索引擎优化**（**SEO**）友好的应用程序。过去有一些技巧用于使 AngularJS 1.x 应用程序可以被搜索引擎索引。例如，一种做法是使用无头浏览器遍历应用程序，执行每个页面上的脚本并将渲染输出缓存到 HTML 文件中，使其可以被搜索引擎访问。

尽管构建 SEO 友好的应用程序的这种变通方法有效，但服务器端渲染解决了上述两个问题，改善了用户体验，并使我们能够更轻松、更优雅地构建 SEO 友好的应用程序。

Angular 2 与 DOM 的解耦使我们能够在浏览器之外运行我们的 Angular 2 应用程序。社区利用这一点构建了一个工具，允许我们在服务器端预渲染我们单页应用程序的视图并将其转发到浏览器。在撰写本文时，该工具仍处于早期开发阶段，不在框架的核心之内。我们将在第八章, *开发体验和服务器端渲染*中进一步了解它。

## 可以扩展的应用程序。

自 Backbone.js 出现以来，MVW 一直是构建单页应用程序的默认选择。它通过将业务逻辑与视图隔离，允许我们构建设计良好的应用程序。利用观察者模式，MVW 允许在视图中监听模型的变化，并在检测到变化时进行更新。然而，这些事件处理程序之间存在一些显式和隐式的依赖关系，这使得我们应用程序中的数据流不明显且难以推理。在 AngularJS 1.x 中，我们允许在不同的监视器之间存在依赖关系，这要求摘要循环多次迭代，直到表达式的结果稳定。Angular 2 使数据流单向化，这带来了许多好处，包括：

+   更明确的数据流。

+   绑定之间没有依赖关系，因此没有摘要的**生存时间**（**TTL**）。

+   更好的性能：

+   摘要循环仅运行一次。

+   我们可以创建友好于不可变/可观察模型的应用程序，这使我们能够进行进一步的优化。

数据流的变化在 AngularJS 1.x 架构中引入了一个更根本的变化。

当我们需要维护用 JavaScript 编写的大型代码库时，我们可能会从另一个角度看待这个问题。尽管 JavaScript 的鸭子类型使语言非常灵活，但它也使得 IDE 和文本编辑器对其分析和支持更加困难。在大型项目中进行重构变得非常困难和容易出错，因为在大多数情况下，静态分析和类型推断是不可能的。缺乏编译器使得拼写错误变得非常容易，直到我们运行测试套件或运行应用程序之前都很难注意到。

![可扩展的应用程序](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/swc-ng2/img/00002.jpeg)

Angular 核心团队决定使用 TypeScript，因为它具有更好的工具，并且具有编译时类型检查，这有助于我们更加高效和减少出错。正如前面的图所示，TypeScript 是 ECMAScript 的超集；它引入了显式类型注解和编译器。TypeScript 语言被编译为纯 JavaScript，受到今天浏览器的支持。自 1.6 版本以来，TypeScript 实现了 ECMAScript 2016 装饰器，这使其成为 Angular 2 的完美选择。

TypeScript 的使用允许更好的 IDE 和文本编辑器支持，具有静态代码分析和类型检查。所有这些都通过减少我们的错误和简化重构过程，显著提高了我们的生产力。TypeScript 的另一个重要好处是通过静态类型，我们隐含地获得了性能改进，这允许 JavaScript 虚拟机进行运行时优化。

我们将在第三章中详细讨论 TypeScript，*TypeScript Crash Course*。

## 模板

模板是 AngularJS 1.x 中的关键特性之一。它们是简单的 HTML，不需要任何中间处理和编译，不像大多数模板引擎（如 mustache）。AngularJS 中的模板通过创建内部的**领域特定语言**（**DSL**）来将简单性与强大性相结合，通过自定义元素和属性来扩展 HTML。

然而，这也是 Web 组件的主要目的之一。我们已经提到了 Angular 2 如何以及为什么利用了这项新技术。尽管 AngularJS 1.x 的模板很棒，但它们仍然可以变得更好！Angular 2 模板继承了框架先前版本中最好的部分，并通过修复其中一些令人困惑的部分来增强它们。

例如，假设我们构建了一个指令，并且我们希望允许用户通过使用属性将属性传递给它。在 AngularJS 1.x 中，我们可以以三种不同的方式来处理这个问题：

```ts
<user name="literal"></user>
<user name="expression"></user>
<user name="{{interpolate}}"></user>
```

如果我们有一个指令`user`，并且我们想传递`name`属性，我们可以以三种不同的方式来处理。我们可以传递一个字面量（在这种情况下是字符串`"literal"`），一个字符串，它将被评估为一个表达式（在我们的例子中是`"expression"`），或者一个在`{{ }}`中的表达式。应该使用哪种语法完全取决于指令的实现，这使得其 API 复杂且难以记忆。

每天处理大量具有不同设计决策的组件是一项令人沮丧的任务。通过引入一个共同的约定，我们可以解决这些问题。然而，为了取得良好的结果和一致的 API，整个社区都需要同意。

Angular 2 也解决了这个问题，提供了特殊的属性语法，其值需要在当前组件的上下文中进行评估，并为传递字面量提供了不同的语法。

我们还习惯于根据我们的 AngularJS 1.x 经验，在模板指令中使用微语法，比如`ng-if`、`ng-for`。例如，如果我们想在 AngularJS 1.x 中遍历用户列表并显示他们的名字，我们可以使用：

```ts
<div ng-for="user in users">{{user.name}}</div>
```

尽管这种语法对我们来说看起来很直观，但它允许有限的工具支持。然而，Angular 2 通过引入更加显式的语法和更丰富的语义来处理这个问题：

```ts
<template ngFor var-user [ngForOf]="users">
  {{user.name}}
</template>
```

前面的代码片段明确定义了必须在当前迭代的上下文中创建的属性（`user`），以及我们要迭代的对象（`users`）。

然而，这种语法对于输入来说太冗长了。开发人员可以使用以下语法，稍后会被转换为更冗长的语法：

```ts
<li *ngFor="#user of users">
  {{user.name}}
</li>
```

新模板的改进也将允许文本编辑器和 IDE 更好地支持高级工具。我们将在第四章中讨论 Angular 2 的模板，*开始使用 Angular 2 组件和指令*。

## 变更检测

在*WebWorkers*部分，我们已经提到了在不同线程的上下文中运行 digest 循环的机会，即作为 WebWorker 实例化。然而，AngularJS 1.x 中 digest 循环的实现并不是非常节省内存，并且阻止了 JavaScript 虚拟机进行进一步的代码优化，这可以实现显著的性能改进。其中一种优化是内联缓存（[`mrale.ph/blog/2012/06/03/explaining-js-vms-in-js-inline-caches.html`](http://mrale.ph/blog/2012/06/03/explaining-js-vms-in-js-inline-caches.html)）。Angular 团队进行了大量研究，发现了改进 digest 循环的性能和效率的不同方法。这导致了全新的变更检测机制的开发。

为了进一步提高灵活性，Angular 团队将变更检测抽象化，并将其实现与框架的核心解耦。这使得可以开发不同的变更检测策略，从而在不同的环境中赋予不同的功能更多的权力。

因此，Angular 2 具有两种内置的变更检测机制：

+   **动态变更检测**：这类似于 AngularJS 1.x 使用的变更检测机制。它用于不允许`eval()`的系统，如 CSP 和 Chrome 扩展程序。

+   **JIT 变更检测**：这会生成执行运行时变更检测的代码，允许 JavaScript 虚拟机执行进一步的代码优化。

我们将看看新的变更检测机制以及如何在第四章中配置它们，*开始使用 Angular 2 组件和指令*。

# 总结

在本章中，我们考虑了 Angular 核心团队做出决定背后的主要原因，以及框架的最后两个主要版本之间缺乏向后兼容性。我们看到这些决定是由两个因素推动的——Web 的发展和前端开发的进化，以及从开发 AngularJS 1.x 应用程序中学到的经验教训。

在第一部分中，我们了解了为什么需要使用最新版本的 JavaScript 语言，为什么要利用 Web 组件和 WebWorkers，以及为什么不值得在 1.x 版本中集成所有这些强大的工具。

我们观察了前端开发的当前方向以及过去几年所学到的经验教训。我们描述了为什么在 Angular 2 中移除了控制器和作用域，以及为什么改变了 AngularJS 1.x 的架构，以便允许服务器端渲染，以便创建 SEO 友好、高性能的单页面应用程序。我们还研究了构建大型应用程序的基本主题，以及这如何激发了框架中的单向数据流和静态类型语言 TypeScript 的选择。

在下一章中，我们将看看 Angular 2 应用程序的主要构建模块——它们如何被使用以及它们之间的关系。Angular 2 重新使用了一些由 AngularJS 1.x 引入的组件的命名，但通常完全改变了我们单页面应用程序的构建模块。我们将窥探新组件，并将它们与框架先前版本中的组件进行比较。我们将快速介绍指令、组件、路由器、管道和服务，并描述它们如何结合起来构建优雅的单页面应用程序。

### 提示

**下载示例代码**

您可以从[`www.packtpub.com`](http://www.packtpub.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了这本书，您可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册，以便文件直接通过电子邮件发送给您。

您可以按照以下步骤下载代码文件：

+   使用您的电子邮件地址和密码登录或注册到我们的网站。

+   将鼠标指针悬停在顶部的**SUPPORT**选项卡上。

+   单击**代码下载和勘误**。

+   在**搜索**框中输入书名。

+   选择您要下载代码文件的书籍。

+   从下拉菜单中选择您购买本书的地方。

+   单击**代码下载**。

下载文件后，请确保使用最新版本的以下工具解压或提取文件夹：

+   WinRAR / 7-Zip for Windows

+   Zipeg / iZip / UnRarX for Mac

+   7-Zip / PeaZip for Linux


# 第二章：Angular 2 应用程序的构建模块

在上一章中，我们看了 Angular 2 设计决策背后的驱动因素。我们描述了导致开发全新框架的主要原因；Angular 2 利用了 Web 标准，同时牢记过去的经验教训。尽管我们熟悉主要的驱动因素，但我们仍未描述核心 Angular 2 概念。框架的上一个主要版本与 AngularJS 1.x 走了不同的道路，并在用于开发单页面应用程序的基本构建模块中引入了许多变化。

在本章中，我们将研究框架的核心，并简要介绍 Angular 2 的主要组件。本章的另一个重要目的是概述这些概念如何组合在一起，以帮助我们为 Web 应用程序构建专业的用户界面。接下来的几节将概述我们将在本书后面更详细地研究的所有内容。

在本章中，我们将看到：

+   一个框架的概念概述，展示不同概念之间的关系。

+   我们如何将用户界面构建为组件的组合。

+   Angular 2 中指令的路径以及它们与框架先前主要版本相比的接口发生了怎样的变化。

+   导致指令分解为两个不同组件的关注点分离的原因。为了更好地理解这两个概念，我们将演示它们定义的基本语法。

+   改进的变化检测概述，以及它如何涉及指令提供的上下文。

+   什么是 zone，以及为什么它们可以使我们的日常开发过程更容易。

+   管道是什么，以及它们与 AngularJS 1.x 的过滤器有什么关系。

+   Angular 2 中全新的**依赖注入**（**DI**）机制以及它与服务组件的关系。

# Angular 2 的概念概述

在我们深入研究 Angular 2 的不同部分之前，让我们先概述一下它们如何相互配合。让我们看一下下面的图表：

![Angular 2 的概念概述](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/swc-ng2/img/00003.jpeg)

图 1

*图 1*至*图 4*显示了主要的 Angular 2 概念及它们之间的连接。这些图表的主要目的是说明使用 Angular 2 构建单页面应用程序的核心模块及其关系。

**组件**是我们将用来使用 Angular 2 创建应用程序用户界面的主要构建块。组件是指令的直接后继，指令是将行为附加到 DOM 的原始方法。组件通过提供进一步的功能（例如附加模板的视图）来扩展**指令**，该模板可用于呈现指令的组合。视图模板中可以包含不同的表达式。

![Angular 2 的概念概述](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/swc-ng2/img/00004.jpeg)

图 2

上述图表概念上说明了 Angular 2 的**变更检测**机制。它运行`digest`循环，评估特定 UI 组件上下文中注册的表达式。由于 Angular 2 中已经移除了作用域的概念，表达式的执行上下文是与其关联的组件的控制器。

**变更检测**机制可以通过**Differs**进行增强；这就是为什么在图表中这两个元素之间有直接关系的原因。

**管道**是 Angular 2 的另一个组件。我们可以将管道视为 AngularJS 1.x 中的过滤器。管道可以与组件一起使用。我们可以将它们包含在在任何组件上下文中定义的表达式中：

![Angular 2 的概念概述](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/swc-ng2/img/00005.jpeg)

图 3

现在让我们看一下上述图表。**指令**和**组件**将业务逻辑委托给**服务**。这强化了关注点的分离、可维护性和代码的可重用性。**指令**使用框架的**DI**机制接收特定服务实例的引用，并将与它们相关的业务逻辑执行委托给它们。**指令**和**组件**都可以使用**DI**机制，不仅可以注入服务，还可以注入 DOM 元素和/或其他**组件**或**指令**。

![Angular 2 的概念概述](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/swc-ng2/img/00006.jpeg)

图 4

最后，基于组件的路由器用于定义应用程序中的路由。由于**指令**没有自己的模板，因此只有**组件**可以由路由器呈现，代表应用程序中的不同视图。路由器还使用预定义的指令，允许我们在不同视图和应该呈现它们的容器之间定义超链接。

现在我们将更仔细地看看这些概念，看看它们如何共同工作以创建 Angular 2 应用程序，以及它们与其 AngularJS 1.x 前身有何不同。

# 更改指令

AngularJS 1.x 在单页应用程序开发中引入了指令的概念。指令的目的是封装与 DOM 相关的逻辑，并允许我们通过扩展 HTML 的语法和语义来构建用户界面的组合。最初，像大多数创新概念一样，指令被认为是有争议的，因为当使用自定义元素或属性而没有`data-`前缀时，它们会使我们倾向于编写无效的 HTML。然而，随着时间的推移，这个概念逐渐被接受，并证明它是值得留下的。

AngularJS 1.x 中指令实现的另一个缺点是我们可以使用它们的不同方式。这需要理解属性值，它可以是文字，表达式，回调或微语法。这使得工具基本上不可能。

Angular 2 保留了指令的概念，但从 AngularJS 1.x 中吸取了精华，并增加了一些新的想法和语法。Angular 2 指令的主要目的是通过在 ES2015 类中定义自定义逻辑来将行为附加到 DOM。我们可以将这些类视为与指令关联的控制器，并将它们的构造函数视为类似于 AngularJS 1.x 中指令的链接函数。然而，新的指令具有有限的可配置性。它们不允许定义模板，这使得大多数用于定义指令的已知属性变得不必要。指令 API 的简单性并不限制它们的行为，而只是强化了更强的关注点分离。为了补充这种更简单的指令 API，Angular 2 引入了一个更丰富的界面来定义 UI 元素，称为组件。组件通过`Component`元数据扩展了指令的功能，允许它们拥有模板。我们稍后会更深入地研究组件。

Angular 2 指令的语法涉及 ES2016 装饰器。然而，我们也可以使用 TypeScript、ES2015 甚至**ECMAScript** 5 (**ES5**)来实现相同的结果，只是需要多打一些字。以下代码定义了一个简单的指令，使用 TypeScript 编写：

```ts
@Directive({
  selector: '[tooltip]'
})
export class Tooltip {
  private overlay: Overlay;
  @Input()
  private tooltip: string;
  constructor(private el: ElementRef, manager: OverlayManager) {
    this.overlay = manager.get();
  }
  @HostListener('mouseenter')
  onMouseEnter() {
    this.overlay.open(this.el.nativeElement, this.tooltip);
  }
  @HostListener('mouseleave')
  onMouseLeave() {
    this.overlay.close();
  }
}
```

指令可以在我们的模板中使用以下标记：

```ts
<div tooltip="42">Tell me the answer!</div>
```

一旦用户指向标签“告诉我答案！”，Angular 将调用指令定义中的`@HostListener`装饰器下定义的方法。最终，将执行覆盖管理器的 open 方法。由于我们可以在单个元素上有多个指令，最佳实践规定我们应该使用属性作为选择器。

用于定义此指令的替代 ECMAScript 5 语法是：

```ts
var Tooltip = ng.core.Directive({
  selector: '[tooltip]',
  inputs: ['tooltip'],
  host: {
    '(mouseenter)': 'onMouseEnter()',
    '(mouseleave)': 'onMouseLeave()'
  }
})
.Class({
  constructor: [ng.core.ElementRef, Overlay, function (tooltip, el, manager) {
    this.el = el;
    this.overlay = manager.get();
  }],
  onMouseEnter() {
    this.overlay.open(this.el.nativeElement, this.tooltip);
  },
  onMouseLeave() {
    this.overlay.close();
  }
});
```

前面的 ES5 语法演示了 Angular 2 提供的内部 JavaScript**领域特定语言**（**DSL**），以便让我们编写代码而不需要语法，这些语法尚未得到现代浏览器的支持。

我们可以总结说，Angular 2 通过保持将行为附加到 DOM 的概念来保留了指令的概念。1.x 和 2 之间的核心区别是新的语法，以及通过引入组件引入的进一步关注点分离。在第四章中，*了解 Angular 2 组件和指令的基础*，我们将进一步查看指令的 API。我们还将比较使用 ES2016 和 ES5 定义语法的指令。现在让我们来看一下 Angular 2 组件的重大变化。

# 了解 Angular 2 组件

**模型视图控制器**（**MVC**）是最初用于实现用户界面的微架构模式。作为 AngularJS 开发人员，我们每天都在使用此模式的不同变体，最常见的是**模型视图视图模型**（**MVVM**）。在 MVC 中，我们有模型，它封装了我们应用程序的业务逻辑，以及视图，它负责呈现用户界面，接受用户输入，并将用户交互逻辑委托给控制器。视图被表示为组件的组合，这正式称为**组合设计模式**。

让我们看一下下面的结构图，它展示了组合设计模式：

![了解 Angular 2 组件](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/swc-ng2/img/00007.jpeg)

图 5

这里有三个类：

+   一个名为`Component`的抽象类。

+   两个具体的类称为`Leaf`和`Composite`。`Leaf`类是我们即将构建的组件树中的简单终端组件。

`Component`类定义了一个名为`operation`的抽象操作。`Leaf`和`Composite`都继承自`Component`类。然而，`Composite`类还拥有对它的引用。我们甚至可以进一步允许`Composite`拥有对`Component`实例的引用列表，就像图示中所示。`Composite`内部的组件列表可以持有对不同`Composite`或`Leaf`实例的引用，或者持有对扩展了`Component`类或其任何后继类的其他类的实例的引用。在`Composite`内部的`operation`方法的实现中，循环中不同实例的调用操作可能会有不同的行为。这是因为面向对象编程语言中多态性实现的后期绑定机制。

## 组件的作用

够了理论！让我们基于图示的类层次结构构建一个组件树。这样，我们将演示如何利用组合模式来使用简化的语法构建用户界面。我们将在第四章中看到一个类似的例子，*开始使用 Angular 2 组件和指令*：

```ts
Composite c1 = new Composite();
Composite c2 = new Composite();
Composite c3 = new Composite();

c1.components.push(c2);
c1.components.push(c3);

Leaf l1 = new Leaf();
Leaf l2 = new Leaf();
Leaf l3 = new Leaf();

c2.components.push(l1);
c2.components.push(l2);

c3.components.push(l3);
```

上面的伪代码创建了三个`Composite`类的实例和三个`Leaf`类的实例。实例`c1`在组件列表中持有对`c2`和`c3`的引用。实例`c2`持有对`l1`和`l2`的引用，`c3`持有对`l3`的引用：

![组件的作用](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/swc-ng2/img/00008.jpeg)

图 6

上面的图示是我们在片段中构建的组件树的图形表示。这是现代 JavaScript 框架中视图的一个相当简化的版本。然而，它说明了我们如何组合指令和组件的基本原理。例如，在 Angular 2 的上下文中，我们可以将指令视为上面`Leaf`类的实例（因为它们不拥有视图，因此不能组合其他指令和组件），将组件视为`Composite`类的实例。

如果我们更抽象地思考 AngularJS 1.x 中的用户界面，我们会注意到我们使用了相似的方法。我们的视图模板将不同的指令组合在一起，以便向我们应用程序的最终用户提供完全功能的用户界面。

## Angular 2 中的组件

Angular 2 采用了这种方法，引入了称为**组件**的新构建块。组件扩展了我们在上一节中描述的指令概念，并提供了更广泛的功能。这是一个基本的`hello-world`组件的定义：

```ts
@Component({
  selector: 'hello-world',
  template: '<h1>Hello, {{this.target}}!</h1>'
})
class HelloWorld {
  target: string;
  constructor() {
    this.target = 'world';
  }
}
```

我们可以通过在视图中插入以下标记来使用它：

```ts
<hello-world></hello-world>
```

根据最佳实践，我们应该使用一个元素作为组件的选择器，因为我们可能每个 DOM 元素只有一个组件。

使用 Angular 提供的 DSL 的替代 ES5 语法是：

```ts
var HelloWorld = ng.core.
  Component({
    selector: 'hello-world',
    template: '<h1>Hello, {{target}}!</h1>'
  })
  .Class({
    constructor: function () {
      this.target = 'world';
    }
  });
```

我们将在本书的后面更详细地看一下前面的语法。然而，让我们简要描述一下这个组件提供的功能。一旦 Angular 2 应用程序已经启动，它将查看我们 DOM 树中的所有元素并处理它们。一旦找到名为`hello-world`的元素，它将调用与其定义相关联的逻辑，这意味着组件的模板将被呈现，并且花括号之间的表达式将被评估。这将导致标记`<h1>Hello, world!</h1>`。

因此，Angular 核心团队将 AngularJS 1.x 中的指令分成了两个不同的部分——**组件**和**指令**。指令提供了一种简单的方法来将行为附加到 DOM 元素而不定义视图。Angular 2 中的组件提供了一个强大而简单易学的 API，使我们更容易定义应用程序的用户界面。Angular 2 组件允许我们做与 AngularJS 1.x 指令相同的惊人的事情，但输入更少，学习更少。组件通过向其添加视图来扩展 Angular 2 指令概念。我们可以将 Angular 2 组件和指令之间的关系看作是我们在*图 5*中看到的`Composite`和`Leaf`之间的关系。

如果我们开始阐述 Angular 2 提供的构建块的概念模型，我们可以将指令和组件之间的关系呈现为继承。第四章*开始使用 Angular 2 组件和指令*更详细地描述了这两个概念。

# 管道

在业务应用中，我们经常需要对相同的数据进行不同的可视化表示。例如，如果我们有数字 100,000，并且想要将其格式化为货币，很可能我们不想将其显示为普通数据；更可能的是，我们想要类似$100,000 这样的东西。

在 AngularJS 1.x 中，格式化数据的责任被分配给了过滤器。另一个数据格式化需求的例子是当我们使用项目集合时。例如，如果我们有一个项目列表，我们可能想要根据谓词（布尔函数）对其进行过滤；在数字列表中，我们可能只想显示素数。AngularJS 1.x 有一个名为`filter`的过滤器，允许我们这样做。然而，名称的重复经常导致混淆。这也是核心团队将过滤器组件重命名为**管道**的另一个原因。

新名称背后的动机是管道和过滤器所使用的语法：

```ts
{{expression | decimal | currency}}
```

在前面的例子中，我们将管道`decimal`和`currency`应用到`expression`返回的值上。花括号之间的整个表达式看起来像 Unix 管道语法。

## 定义管道

定义管道的语法类似于指令和组件的定义所使用的语法。为了创建一个新的管道，我们可以使用 ES2015 装饰器`@Pipe`。它允许我们向类添加元数据，声明它为管道。我们所需要做的就是为管道提供一个名称并定义数据格式化逻辑。还有一种替代的 ES5 语法，如果我们想跳过转译的过程，可以使用它。

在运行时，一旦 Angular 2 表达式解释器发现给定表达式包含对管道的调用，它将从组件内分配的管道集合中检索出它，并使用适当的参数调用它。

下面的例子说明了我们如何定义一个简单的管道叫做`lowercase1`，它将传递给它的字符串转换为小写表示：

```ts
@Pipe({ name: 'lowercase1' })
class LowerCasePipe1 implements PipeTransform {
  transform(value: string): string {
    if (!value) return value;
    if (typeof value !== 'string') {
      throw new Error('Invalid pipe value', value);
    }
    return value.toLowerCase();
  }
}
```

为了保持一致，让我们展示定义管道的 ECMAScript 5 语法：

```ts
var LowercasePipe1 = ng.core.
  Pipe({
    name: 'lowercase'
  })
  .Class({
    constructor: function () {},
    transform: function (value) {
      if (!value) return value;
      if (typeof value === 'string') {
        throw new Error('Invalid pipe value', value);
      }
      return value.toLowerCase();
    }
  });
```

在 TypeScript 语法中，我们实现了`PipeTransform`接口，并定义了其中声明的`transform`方法。然而，在 ECMAScript 5 中，我们不支持接口，但我们仍然需要实现`transform`方法以定义一个有效的 Angular 2 管道。我们将在下一章中解释 TypeScript 接口。

现在让我们演示如何在组件中使用`lowercase1`管道：

```ts
@Component({
  selector: 'app',
  pipes: [LowercasePipe1],
  template: '<h1>{{"SAMPLE" | lowercase1}}</h1>'
})
class App {}
```

而且，这个的 ECMAScript 5 的替代语法是：

```ts
var App = ng.core.Component({
  selector: 'app',
  pipes: [LowercasePipe1],
  template: '<h1>{{"SAMPLE" | lowercase1}}</h1>'
})
.Class({
  constructor: function () {}
});
```

我们可以使用以下标记来使用`App`组件：

```ts
   <app></app>
```

我们将在屏幕上看到的结果是`h1`元素中的文本示例。

通过将数据格式化逻辑保持为一个独立的组件，Angular 2 保持了强大的关注点分离。我们将在第七章中看看如何为我们的应用程序定义有状态和无状态管道，*在探索管道和 http 的同时构建一个真实的应用程序*。

# 更改检测

正如我们之前所看到的，MVC 中的视图会根据从模型接收到的更改事件进行更新。许多**Model View Whatever**（**MVW**）框架采用了这种方法，并将观察者模式嵌入到了它们的更改检测机制的核心中。

## 经典的更改检测

让我们看一个简单的例子，不使用任何框架。假设我们有一个名为`User`的模型，它有一个名为`name`的属性：

```ts
class User extends EventEmitter {
  private name: string;
  setName(name: string) {
    this.name = name;
    this.emit('change');
	}
  getName(): string {
    return this.name;}
}
```

前面的片段使用了 TypeScript。如果语法对你来说不太熟悉，不用担心，我们将在下一章中对这种语言进行介绍。

`user`类扩展了`EventEmitter`类。这提供了发出和订阅事件的基本功能。

现在让我们定义一个视图，显示作为其`constructor`参数传递的`User`类实例的名称：

```ts
class View {
  constructor(user: User, el: Element /* a DOM element */) {
    el.innerHTML = user.getName();
	}
}
```

我们可以通过以下方式初始化视图元素：

```ts
let user = new User();
user.setName('foo');
let view = new View(user, document.getElementById('label'));
```

最终结果是，用户将看到一个带有内容`foo`的标签。但是，用户的更改不会反映在视图中。为了在用户更改名称时更新视图，我们需要订阅更改事件，然后更新 DOM 元素的内容。我们需要以以下方式更新`View`定义：

```ts
class View {
  constructor(user:User, el:any /* a DOM element */) {
    el.innerHTML = user.getName();
    user.on('change', () => {
      el.innerHTML = user.getName();
	  });
  }
}
```

这是大多数框架在 AngularJS 1.x 时代实现它们的更改检测的方式。

## AngularJS 1.x 更改检测

大多数初学者都对 AngularJS 1.x 中的数据绑定机制着迷。基本的 Hello World 示例看起来类似于这样：

```ts
function MainCtrl($scope) {
  $scope.label = 'Hello world!';
}

<body ng-app ng-controller="MainCtrl">
  {{label}}
</body>
```

如果你运行这个，`Hello world!`神奇地出现在屏幕上。然而，这甚至不是最令人印象深刻的事情！如果我们添加一个文本输入，并将它绑定到作用域的`label`属性，每次更改都会反映出插值指令显示的内容：

```ts
<body ng-controller="MainCtrl">
  <input ng-model="label">
  {{label}}
</body>
```

这是 AngularJS 1.x 的主要卖点之一——极其容易实现数据绑定。我们在标记中添加了两个（如果计算`ng-controller`和`ng-app`则为四个）属性，将属性添加到一个名为`$scope`的神秘对象中，这个对象被神奇地传递给我们定义的自定义函数，一切都很简单！

然而，更有经验的 Angular 开发人员更好地理解了幕后实际发生的事情。在前面的例子中，在指令`ng-model`和`ng-bind`（在我们的例子中，插值指令`{{}}`）内部，Angular 添加了具有不同行为的观察者，关联到相同的表达式`label`。这些观察者与经典 MVC 模式中的观察者非常相似。在某些特定事件（在我们的例子中，文本输入内容的更改）上，AngularJS 将循环遍历所有这样的观察者，评估它们关联的表达式在给定作用域的上下文中的结果，并存储它们的结果。这个循环被称为`digest`循环。

在前面的例子中，表达式`label`在作用域的上下文中的评估将返回文本`Hello world!`。在每次迭代中，AngularJS 将当前评估结果与先前结果进行比较，并在值不同时调用关联的回调。例如，插值指令添加的回调将设置元素的内容为表达式评估的新结果。这是两个指令的观察者的回调之间的依赖关系的一个例子。`ng-model`添加的观察者的回调修改了插值指令添加的观察者关联的表达式的结果。

然而，这种方法也有其自身的缺点。我们说`digest`循环将在一些特定事件上被调用，但如果这些事件发生在框架之外呢？例如，如果我们使用`setTimeout`，并且在作为第一个参数传递的回调函数内部更改了我们正在监视的作用域附加的属性，那会怎么样？AngularJS 将不知道这个变化，并且不会调用`digest`循环，所以我们需要使用`$scope.$apply`来显式地做这件事。但是，如果框架知道浏览器中发生的所有异步事件，比如用户事件、`XMLHttpRequest`事件、`WebSockets`相关事件等，会怎样呢？在这种情况下，AngularJS 将能够拦截事件处理，并且可以在不强制我们这样做的情况下调用`digest`循环！

### 在 zone.js 中

在 Angular 2 中，情况确实如此。这种功能是通过使用`zone.js`来实现的。

在 2014 年的 ng-conf 上，Brian Ford 谈到了 zone。Brian 将 zone 呈现为浏览器 API 的元猴补丁。最近，Miško Hevery 向 TC39 提出了更成熟的 zone API 以供标准化。`Zone.js`是由 Angular 团队开发的一个库，它在 JavaScript 中实现了 zone。它们代表了一个执行上下文，允许我们拦截异步浏览器调用。基本上，通过使用 zone，我们能够在给定的`XMLHttpRequest`完成后或者当我们接收到新的`WebSocket`事件时立即调用一段逻辑。Angular 2 利用了`zone.js`，通过拦截异步浏览器事件，并在合适的时机调用`digest`循环。这完全消除了使用 Angular 的开发人员需要显式调用`digest`循环的需要。

### 简化的数据流

交叉观察者依赖关系可能在我们的应用程序中创建纠缠不清的数据流，难以跟踪。这可能导致不可预测的行为和难以发现的错误。尽管 Angular 2 保留了脏检查作为实现变更检测的一种方式，但它强制了单向数据流。这是通过不允许不同观察者之间的依赖关系，从而使`digest`循环只运行一次。这种策略极大地提高了我们应用程序的性能，并减少了数据流的复杂性。Angular 2 还改进了内存效率和`digest`循环的性能。有关 Angular 2 的变更检测和其实现所使用的不同策略的更多详细信息，可以在第四章中找到，《开始使用 Angular 2 组件和指令》。

## 增强 AngularJS 1.x 的变更检测

现在让我们退一步，再次思考一下框架的变更检测机制。

我们说在`digest`循环内，Angular 评估注册的表达式，并将评估的值与上一次循环中与相同表达式关联的值进行比较。

比较所使用的最优算法可能取决于表达式评估返回的值的类型。例如，如果我们得到一个可变的项目列表，我们需要循环遍历整个集合，并逐个比较集合中的项目，以验证是否有更改。然而，如果我们有一个不可变的列表，我们可以通过比较引用来执行具有恒定复杂度的检查。这是因为不可变数据结构的实例不能改变。我们不会应用意图修改这些实例的操作，而是会得到一个应用了修改的新引用。

在 AngularJS 1.x 中，我们可以使用几种方法添加监视器。其中两种是`$watch(exp, fn, deep)`或`$watchCollection(exp, fn)`。这些方法让我们在改变检测的执行上有一定程度的控制。例如，使用`$watch`添加一个监视器，并将`false`值作为第三个参数传递将使 AngularJS 执行引用检查（即使用`===`比较当前值与先前值）。然而，如果我们传递一个真值（任何`true`值），检查将是深层的（即使用`angular.equals`）。这样，根据表达式值的预期类型，我们可以以最合适的方式添加监听器，以便允许框架使用最优化的算法执行相等性检查。这个 API 有两个限制：

+   它不允许您在运行时选择最合适的相等性检查算法。

+   它不允许您将改变检测扩展到第三方以适应其特定的数据结构。

Angular 核心团队将这一责任分配给了差异，使它们能够扩展改变检测机制并根据我们在应用程序中使用的数据进行优化。Angular 2 定义了两个基类，我们可以扩展以定义自定义算法：

+   `KeyValueDiffer`：这允许我们在基于键值的数据结构上执行高级差异。

+   `IterableDiffer`：这允许我们在类似列表的数据结构上执行高级差异。

Angular 2 允许我们通过扩展自定义算法来完全控制改变检测机制，而在框架的先前版本中是不可能的。我们将进一步研究改变检测以及如何在第四章中配置它，*开始使用 Angular 2 组件和指令*。

# 理解服务

服务是 Angular 为定义应用程序的业务逻辑提供的构建块。在 AngularJS 1.x 中，我们有三种不同的方式来定义服务：

```ts
// The Factory method
module.factory('ServiceName', function (dep1, dep2, …) {
  return {
    // public API
  };
});

// The Service method
module.service('ServiceName', function (dep1, dep2, …) {
  // public API
  this.publicProp = val;
});

// The Provider method
module.provider('ServiceName', function () {
  return {
    $get: function (dep1, dep2, …) {
      return {
        // public API
      };
    }
  };
});
```

尽管前两种语法变体提供了类似的功能，但它们在注册指令实例化的方式上有所不同。第三种语法允许在配置时间进一步配置注册的提供者。

对于 AngularJS 1.x 的初学者来说，有三种不同的定义服务的方法是相当令人困惑的。让我们想一想是什么促使引入这些注册服务方法。为什么我们不能简单地使用 JavaScript 构造函数、对象文字或 ES2015 类，而 Angular 不会意识到呢？我们可以像这样在自定义 JavaScript 构造函数中封装我们的业务逻辑：

```ts
function UserTransactions(id) {
  this.userId = id;
}
UserTransactions.prototype.makeTransaction = function (amount) {
  // method logic
};

module.controller('MainCtrl', function () {
  this.submitClick = function () {
    new UserTransactions(this.userId).makeTransaction(this.amount);
  };
});
```

这段代码是完全有效的。然而，它没有利用 AngularJS 1.x 提供的一个关键特性——DI 机制。`MainCtrl`函数使用了构造函数`UserTransaction`，它在其主体中可见。上述代码有两个主要缺点：

+   我们与服务实例化的逻辑耦合在一起。

+   这段代码无法进行测试。为了模拟`UserTransactions`，我们需要对其进行 monkey patch。

AngularJS 如何处理这两个问题？当需要一个特定的服务时，通过框架的 DI 机制，AngularJS 解析所有的依赖关系，并通过将它们传递给`factory`函数来实例化它。`factory`函数作为`factory`和`service`方法的第二个参数传递。`provider`方法允许在更低级别定义服务；在那里，`factory`方法是提供者的`$get`属性下的方法。

就像 AngularJS 1.x 一样，Angular 2 也容忍这种关注点的分离，所以核心团队保留了服务。与 AngularJS 1.x 相比，这个框架的最新主要版本通过允许我们使用纯粹的 ES2015 类或 ES5 构造函数来定义服务，提供了一个更简单的接口。我们无法逃避这样一个事实，即我们需要明确声明哪些服务应该可用于注入，并以某种方式指定它们的实例化指令。然而，Angular 2 使用 ES2016 装饰器的语法来实现这一目的，而不是我们从 AngularJS 1.x 熟悉的方法。这使我们能够像 ES2015 类一样简单地在我们的应用程序中定义服务，并使用装饰器来配置 DI：

```ts
import {Inject, Injectable} from 'angular2/core';

@Injectable()
class HttpService {
  constructor() { /* … */ }
}

@Injectable()
class User {
  constructor(private service: HttpService) {}
  save() {
    return this.service.post('/users')
      .then(res => {
        this.id = res.id;
        return this;
      });
  }
}
```

ECMAScript 5 的替代语法是：

```ts
var HttpService = ng.core.Class({
  constructor: function () {}
});
var User = ng.core.Class({
  constructor: [HttpService, function (service) {
    this.service = service;
  }],
  save: function () {
    return this.service.post('/users')
      .then(function (res) {
        this.id = res.id;
        return this;
      });
  }
});
```

服务与前面章节中描述的组件和指令相关联。为了开发高度一致和可重用的 UI 组件，我们需要将所有与业务相关的逻辑移动到我们的服务中。为了开发可测试的组件，我们需要利用 DI 机制来解决它们的所有依赖关系。

Angular 2 和 AngularJS 1.x 中服务之间的一个核心区别是它们的依赖项是如何被解析和内部表示的。AngularJS 1.x 使用字符串来标识不同的服务和用于实例化它们的相关工厂。然而，Angular 2 使用键。通常，这些键是不同服务的类型。在实例化中的另一个核心区别是注入器的分层结构，它封装了具有不同可见性的不同依赖项提供者。

Angular 2 和框架的最后两个主要版本之间的另一个区别是简化的语法。虽然 Angular 2 使用 ES2015 类来定义业务逻辑，但您也可以使用 ECMAScript 5 的`constructor`函数，或者使用框架提供的 DSL。Angular 2 中的 DI 具有完全不同的语法，并通过提供一种一致的方式来注入依赖项来改进行为。前面示例中使用的语法使用了 ES2016 装饰器，在第五章中，我们将看一下使用 ECMAScript 5 的替代语法。您还可以在第五章中找到有关 Angular 2 服务和 DI 的更详细解释，*Angular 2 中的依赖注入*。

# 理解基于组件的新路由器

在传统的 Web 应用程序中，所有页面更改都与完整页面重新加载相关，这会获取所有引用的资源和数据，并将整个页面呈现到屏幕上。然而，随着时间的推移，Web 应用程序的要求已经发生了变化。

我们使用 Angular 构建的**单页应用程序**（**SPA**）模拟桌面用户体验。这经常涉及按需加载应用程序所需的资源和数据，并且在初始页面加载后不进行完整的页面重新加载。通常，SPA 中的不同页面或视图由不同的模板表示，这些模板是异步加载并在屏幕上的特定位置呈现。稍后，当加载了所有所需资源的模板并且路由已更改时，将调用附加到所选页面的逻辑，并使用数据填充模板。如果用户在加载了我们的 SPA 中的给定页面后按下刷新按钮，则在视图完成刷新后需要重新呈现相同的页面。这涉及类似的行为——查找请求的视图，获取所有引用资源的所需模板，并调用与该视图相关的逻辑。

需要获取哪个模板，以及在页面成功重新加载后应调用的逻辑，取决于用户在按下刷新按钮之前选择的视图。框架通过解析页面 URL 来确定这一点，该 URL 包含当前选定页面的标识符，以分层结构表示。

与导航、更改 URL、加载适当模板和在视图加载时调用特定逻辑相关的所有责任都分配给了路由器组件。这些都是相当具有挑战性的任务，为了跨浏览器兼容性而需要支持不同的导航 API，使得在现代 SPA 中实现路由成为一个非平凡的问题。

AngularJS 1.x 在其核心中引入了路由器，后来将其外部化为`ngRoute`组件。它允许以声明方式定义 SPA 中的不同视图，为每个页面提供模板和需要在选择页面时调用的逻辑。然而，路由器的功能有限。它不支持诸如嵌套视图路由之类的基本功能。这是大多数开发人员更喜欢使用由社区开发的`ui-router`的原因之一。AngularJS 1.x 的路由器和`ui-router`的路由定义都包括路由配置对象，该对象定义了与页面关联的模板和控制器。

如前几节所述，Angular 2 改变了它为开发单页应用程序提供的构建模块。Angular 2 移除了浮动控制器，而是将视图表示为组件的组合。这需要开发一个全新的路由器，以赋予这些新概念力量。

AngularJS 1.x 路由器和 Angular 2 路由器之间的核心区别是：

+   Angular 2 路由器是基于组件的，而`ngRoute`不是。

+   现在支持嵌套视图。

+   ES2016 装饰器赋予了不同的语法。

## Angular 2 路由定义语法

让我们简要地看一下 Angular 2 路由器在我们应用程序中定义路由时使用的新语法：

```ts
import {Component} from 'angular2/core';
import {bootstrap} from 'angular2/platform/browser';
import {RouteConfig, ROUTER_DIRECTIVES, ROUTER_BINDINGS} from 'angular2/router';

import {Home} from './components/home/home';
import {About} from './components/about/about';

@Component({
  selector: 'app',
  templateUrl: './app.html',
  directives: [ROUTER_DIRECTIVES]
})
@RouteConfig([
  { path: '/', component: Home, name: 'home' },
  { path: '/about', component: About, name: 'about' }
])
class App {}

bootstrap(App, [ROUTER_PROVIDERS]);
```

我们不会在这里详细介绍，因为第六章、*Angular 2 表单和基于组件的新路由器*和第七章、*在探索管道和 http 的同时构建一个真实的应用程序*专门讨论了新路由器，但让我们提到前面代码片段中的主要要点。

路由器位于模块`angular2/router`中。在那里，我们可以找到它定义的指令，用于配置路由的装饰器和`ROUTER_PROVIDERS`。

### 注意

我们将在第七章中进一步了解`ROUTER_PROVIDERS`，*在探索管道和 http 的同时构建一个真实的应用程序*。

`@RouteConfig`装饰器传递的参数显示了我们如何在应用程序中定义路由。我们使用一个包含对象的数组，它定义了路由和与其关联的组件之间的映射关系。在`Component`装饰器内部，我们明确说明我们要使用`ROUTER_DIRECTIVES`中包含的指令，这些指令与模板中的路由器使用相关。

# 总结

在本章中，我们快速概述了 Angular 2 提供的开发单页应用程序的主要构建模块。我们指出了 AngularJS 1.x 和 Angular 2 中这些组件之间的核心区别。

虽然我们可以使用 ES2015，甚至 ES5 来构建 Angular 2 应用程序，但 Google 的建议是利用用于开发框架的语言—TypeScript。

在下一章中，我们将看一下 TypeScript 以及如何在您的下一个应用程序中开始使用它。我们还将解释如何利用 JavaScript 库和框架中的静态类型，这些库和框架是用原生 JavaScript 编写的，带有环境类型注释。


# 第三章：TypeScript Crash Course

在本章中，我们将开始使用 TypeScript，这是 Angular 2 推荐的脚本语言。ECMAScript 2015 和 ECMAScript 2016 提供的所有功能，如函数、类、模块和装饰器，已经在 TypeScript 中实现或添加到路线图中。由于额外的类型注解，与 JavaScript 相比，有一些语法上的补充。

为了更顺畅地从我们已经了解的语言 ES5 过渡，我们将从 ES2016 和 TypeScript 之间的一些共同特性开始。在 ES 语法和 TypeScript 之间存在差异的地方，我们将明确提到。在本章的后半部分，我们将为我们到目前为止学到的所有内容添加类型注解。

在本章的后面，我们将解释 TypeScript 提供的额外功能，如静态类型和扩展语法。我们将讨论基于这些功能的不同后果，这将帮助我们更加高效和减少出错。让我们开始吧！

# TypeScript 简介

TypeScript 是一种由微软开发和维护的开源编程语言。它最初是在 2012 年 10 月公开发布的。TypeScript 是 ECMAScript 的超集，支持 JavaScript 的所有语法和语义，还有一些额外的功能，如静态类型和更丰富的语法。

图 1 显示了 ES5、ES2015、ES2016 和 TypeScript 之间的关系。

![TypeScript 简介](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/swc-ng2/img/00009.jpeg)

图 1

由于 TypeScript 是静态类型的，它可以为我们作为 JavaScript 开发人员提供许多好处。现在让我们快速看一下这些好处。

## 编译时类型检查

我们在编写 JavaScript 代码时常犯的一些常见错误是拼错属性或方法名。当我们遇到运行时错误时，我们会发现这个错误。这可能发生在开发过程中，也可能发生在生产环境中。希望在部署代码到生产环境之前我们能知道错误并不是一种舒适的感觉！然而，这不是 JavaScript 特有的问题；这是所有动态语言共有的问题。即使有很多单元测试，这些错误也可能会漏掉。

TypeScript 提供了一个编译器，通过静态代码分析来为我们处理这些错误。如果我们利用静态类型，TypeScript 将意识到给定对象具有的现有属性，如果我们拼错了其中任何一个，编译器将在编译时警告我们。

TypeScript 的另一个巨大好处是它允许大型团队合作，因为它提供了正式的、可验证的命名。这样，它允许我们编写易于理解的代码。

## 文本编辑器和集成开发环境提供更好的支持

有许多工具，如 Tern 或 Google Closure Compiler，它们试图为文本编辑器和集成开发环境提供更好的 JavaScript 自动补全支持。然而，由于 JavaScript 是一种动态语言，没有任何元数据，文本编辑器和集成开发环境无法提出复杂的建议。

用这些元数据注释代码是 TypeScript 的内置特性，称为类型注解。基于它们，文本编辑器和集成开发环境可以对我们的代码进行更好的静态分析。这提供了更好的重构工具和自动补全，这增加了我们的生产力，使我们在编写应用程序源代码时犯更少的错误。

## TypeScript 甚至更多

TypeScript 本身还有许多其他好处：

+   它是 JavaScript 的超集：所有 JavaScript（ES5 和 ES2015）程序已经是有效的 TypeScript 程序。实质上，您已经在编写 TypeScript 代码。由于它基于 ECMAScript 标准的最新版本，它允许我们利用语言提供的最新的前沿语法。

+   支持可选类型检查：如果出于任何原因，我们决定不想明确定义变量或方法的类型，我们可以跳过类型定义。然而，我们应该意识到这意味着我们不再利用静态类型，因此放弃了前面提到的所有好处。

+   由微软开发和维护：语言实现的质量非常高，不太可能会突然停止支持。TypeScript 基于世界上一些最优秀的编程语言开发专家的工作。

+   **它是开源的**：这允许社区自由地为语言做出贡献并提出功能，这些功能是以开放的方式讨论的。TypeScript 是开源的事实使得第三方扩展和工具更容易开发，从而进一步扩展了其使用范围。

由于现代浏览器不支持 TypeScript 本地，因此有一个编译器将我们编写的 TypeScript 代码转换为预定义版本的 ECMAScript 可读的 JavaScript。一旦代码编译完成，所有类型注释都将被移除。

# 使用 TypeScript

让我们开始编写一些 TypeScript！

在接下来的章节中，我们将看一些展示 TypeScript 功能的不同片段。为了能够运行这些片段并自己玩耍，您需要在计算机上安装 TypeScript 编译器。让我们看看如何做到这一点。

最好使用**Node Package Manager**（**npm**）安装 TypeScript。我建议您使用 npm 版本 3.0.0 或更新版本。如果您尚未安装 node.js 和 npm，可以访问[`nodejs.org`](https://nodejs.org)并按照那里的说明进行操作。

## 使用 npm 安装 TypeScript

一旦您安装并运行了 npm，请通过打开终端窗口并运行以下命令来验证您是否拥有最新版本：

```ts
**$ npm –v**

```

要安装 TypeScript 1.8，请使用：

```ts
**$ npm install -g typescript@1.8**

```

上述命令将安装 TypeScript 编译器，并将其可执行文件（`tsc`）添加为全局路径。

为了验证一切是否正常工作，您可以使用：

```ts
**$ tsc –v**
**Version 1.8.0**

```

输出应该类似于上面的输出，尽管可能使用不同的版本。

## 运行我们的第一个 TypeScript 程序

### 注意

您可以在以下 URL 找到本书的代码：[`github.com/mgechev/switching-to-angular2`](https://github.com/mgechev/switching-to-angular2)。在大多数代码片段中，您会找到一个相对于`app`目录的文件路径，您可以在那里找到它们。

现在，让我们编译我们的第一个 TypeScript 程序！创建一个名为`hello.ts`的文件，并输入以下内容：

```ts
// ch3/hello-world/hello-world.ts
console.log('Hello world!');
```

由于您已经安装了 TypeScript 编译器，您应该有一个名为`tsc`的全局可执行命令。您可以使用它来编译文件：

```ts
**$ tsc hello.ts**

```

现在，你应该在`hello.ts`所在的同一目录中看到文件`hello.js`。`hello.js`是 TypeScript 编译器的输出；它包含了你编写的 TypeScript 的 JavaScript 等价物。你可以使用以下命令运行这个文件：

```ts
**$ node hello.js**

```

现在，你会在屏幕上看到字符串`Hello world!`。为了结合编译和运行程序的过程，你可以使用`ts-node`包：

```ts
**$ npm install -t ts-node**

```

现在你可以运行：

```ts
**$ ts-node hello.ts**

```

你应该看到相同的结果，但是没有存储在磁盘上的`ts-node`文件。

# TypeScript 语法和特性是由 ES2015 和 ES2016 引入的。

由于 TypeScript 是 JavaScript 的超集，在我们开始学习它的语法之前，先介绍 ES2015 和 ES2016 中的一些重大变化会更容易一些；要理解 TypeScript，我们首先必须理解 ES2015 和 ES2016。在深入学习 TypeScript 之前，我们将快速浏览这些变化。

本书不涵盖 ES2015 和 ES2016 的详细解释。为了熟悉所有新特性和语法，我强烈建议你阅读*Exploring ES6: upgrade to the next version of JavaScript* by *Dr. Axel Rauschmayer*。

接下来的几页将介绍新的标准，并让你利用大部分你在开发 Angular 2 应用程序中需要的特性。

## ES2015 箭头函数

JavaScript 具有一级函数，这意味着它们可以像其他值一样传递：

```ts
// ch3/arrow-functions/simple-reduce.ts
var result = [1, 2, 3].reduce(function (total, current) {
  return total + current;
}, 0); // 6
```

这种语法很棒；但是有点太啰嗦了。ES2015 引入了一种新的语法来定义匿名函数，称为箭头函数语法。使用它，我们可以创建匿名函数，就像下面的例子中所示：

```ts
// ch3/arrow-functions/arrow-functions.ts

// example 1
var result = [1, 2, 3]
  .reduce((total, current) => total + current, 0);

console.log(result);

// example 2
var even = [3, 1, 56, 7].filter(el => !(el % 2));

console.log(even);

// example 3
var sorted = data.sort((a, b) => {
  var diff = a.price - b.price;
  if (diff !== 0) {
    return diff;
  }
  return a.total - b.total;
});
```

在第一个例子中，我们得到了数组`[1, 2, 3]`中元素的总和。在第二个例子中，我们得到了数组`[3, 1, 56, 7]`中所有的偶数。在第三个例子中，我们按照属性`price`和`total`的升序对数组进行了排序。

箭头函数还有一些我们需要看看的特性。其中最重要的一个是它们会保持周围代码的上下文(`this`)。

```ts
// ch3/arrow-functions/context-demo.ts
function MyComponent() {
  this.age = 42;
  setTimeout(() => {
    this.age += 1;
    console.log(this.age);
  }, 100);
}
new MyComponent(); // 43 in 100ms.
```

例如，当我们使用`new`操作符调用函数`MyComponent`时，`this`将指向调用实例化的新对象。箭头函数将保持上下文(`this`)，在`setTimeout`的回调中，屏幕上会打印**43**。

这在 Angular 2 中非常有用，因为给定组件的绑定上下文是其实例（即其`this`）。如果我们将`MyComponent`定义为 Angular 2 组件，并且我们有一个绑定到`age`属性，前面的代码将是有效的，并且所有绑定将起作用（请注意，我们没有作用域，也没有显式调用`$digest`循环，尽管我们直接调用了`setTimeout`）。

## 使用 ES2015 和 ES2016 类

当初次接触 JavaScript 的开发人员听说语言赋予了**面向对象**（**OO**）范式的能力时，当他们发现没有类的定义语法时，他们通常会感到困惑。这种看法是由于一些最流行的编程语言，如 Java、C#和 C++，具有用于构建对象的类的概念。然而，JavaScript 以不同的方式实现了面向对象范式。JavaScript 具有基于原型的面向对象编程模型，我们可以使用对象字面量语法或函数（也称为构造函数）来实例化对象，并且我们可以利用所谓的原型链来实现继承。

虽然这是一种实现面向对象范式的有效方式，语义与经典面向对象模型中的方式类似，但对于经验不足的 JavaScript 开发人员来说，他们不确定如何正确处理这一点，这是 TC39 决定提供一种替代语法来利用语言中的面向对象范式的原因之一。在幕后，新的语法与我们习惯的语法具有相同的语义，比如使用构造函数和基于原型的继承。然而，它提供了一种更方便的语法，以减少样板代码来增强面向对象范式的特性。

ES2016 为 ES2015 类添加了一些额外的语法，例如静态和实例属性声明。

以下是一个示例，演示了 ES2016 中用于定义类的语法：

```ts
// ch3/es6-classes/sample-classes.ts

class Human {
  static totalPeople = 0;
  _name; // ES2016 property declaration syntax
  constructor(name) {
    this._name = name;
    Human.totalPeople += 1;
  }
  get name() {
    return this._name;
  }
  set name(val) {
    this._name = val;
  }
  talk() {
    return `Hi, I'm ${this.name}!`;
  }
}

class Developer extends Human {
  _languages; // ES2016 property declaration syntax
  constructor(name, languages) {
    super(name);
    this._languages = languages;
  }
  get languages() {
    return this._languages;
  }
  talk() {
    return `${super.talk()} And I know
${this.languages.join(',')}.`;
  }
}
```

在 ES2015 中，不需要显式声明`_name`属性；然而，由于 TypeScript 编译器在编译时应该知道给定类的实例的现有属性，我们需要将属性的声明添加到类声明本身中。

前面的片段既是有效的 TypeScript 代码，也是 JavaScript 代码。 在其中，我们定义了一个名为`Human`的类，它向由它实例化的对象添加了一个属性。 它通过将其值设置为传递给其构造函数的参数名称来实现这一点。

现在，打开`ch3/es6-classes/sample-classes.ts`文件并进行操作！ 您可以以与使用构造函数创建对象相同的方式创建类的不同实例：

```ts
var human = new Human("foobar");
var dev = new Developer("bar", ["JavaScript"]);
console.log(dev.talk());
```

为了执行代码，请运行以下命令：

```ts
**$ ts-node sample-classes.ts**

```

类通常在 Angular 2 中使用。 您可以使用它们来定义组件，指令，服务和管道。 但是，您还可以使用替代的 ES5 语法，该语法利用构造函数。 在幕后，一旦 TypeScript 代码被编译，两种语法之间将没有太大的区别，因为 ES2015 类最终被转译为构造函数。

## 使用块作用域定义变量

JavaScript 对具有不同背景的开发人员来说另一个令人困惑的地方是语言中的变量作用域。 例如，在 Java 和 C ++中，我们习惯于块词法作用域。 这意味着在特定块内定义的给定变量只在该块内以及其中的所有嵌套块内可见。

然而，在 JavaScript 中，情况有些不同。 ECMAScript 定义了一个具有类似语义的函数词法作用域，但它使用函数而不是块。 这意味着我们有以下内容：

```ts
// ch3/let/var.ts

var fns = [];
for (var i = 0; i < 5; i += 1) {
  fns.push(function() {
    console.log(i);
  })
}
fns.forEach(fn => fn());
```

这有一些奇怪的含义。 一旦代码被执行，它将记录五次数字`5`。

ES2015 添加了一种新的语法来定义具有块作用域可见性的变量。 语法与当前的语法类似。 但是，它使用关键字`let`而不是`var`：

```ts
// ch3/let/let.ts

var fns = [];
for (let i = 0; i < 5; i += 1) {
  fns.push(function() {
    console.log(i);
  })
}
fns.forEach(fn => fn());
```

# 使用 ES2016 装饰器进行元编程

JavaScript 是一种动态语言，允许我们轻松修改和/或改变行为以适应我们编写的程序。 装饰器是 ES2016 的一个提案，根据设计文档[`github.com/wycats/javascript-decorators`](https://github.com/wycats/javascript-decorators)：

> *“…使注释和修改类和属性在设计时成为可能。”*

它们的语法与 Java 中的注解非常相似，甚至更接近 Python 中的装饰器。ES2016 装饰器在 Angular 2 中通常用于定义组件、指令和管道，并利用框架的依赖注入机制。基本上，装饰器的大多数用例涉及改变行为以预定义逻辑或向不同的结构添加一些元数据。

ES2016 装饰器允许我们通过改变程序的行为来做很多花哨的事情。典型的用例可能是将给定的方法或属性标注为已弃用或只读。一组预定义的装饰器可以提高我们所生成的代码的可读性，可以在*Jay Phelps*的名为*core-decorators.js*的项目中找到。另一个用例是利用基于代理的面向方面编程，使用声明性语法。提供此功能的库是`aspect.js`。

总的来说，ES2016 装饰器只是另一种语法糖，它转换成我们已经熟悉的来自 JavaScript 之前版本的代码。让我们看一个来自提案草案的简单示例：

```ts
// ch3/decorators/nonenumerable.ts

class Person {
  @nonenumerable
  get kidCount() {
    return 42;
  }
}

function nonenumerable(target, name, descriptor) {
  descriptor.enumerable = false;
  return descriptor;
}

var person = new Person();

for (let prop in person) {
  console.log(prop);
}
```

在这种情况下，我们有一个名为`Person`的 ES2015 类，其中有一个名为`kidCount`的单个 getter。在`kidCount` getter 上，我们应用了`nonenumerable`装饰器。装饰器是一个接受目标（`Person`类）、我们打算装饰的目标属性的名称（`kidCount`）和`target`属性的描述符的函数。在我们改变描述符之后，我们需要返回它以应用修改。基本上，装饰器的应用可以用以下方式转换成 ECMAScript 5：

```ts
descriptor = nonenumerable (Person.prototype, 'kidCount', descriptor) || descriptor;
Object.defineProperty(Person.prototype, 'kidCount', descriptor);
```

## 使用可配置的装饰器

以下是使用 Angular 2 定义的装饰器的示例：

```ts
@Component({
  selector: 'app',
  providers: [NamesList],
  templateUrl: './app.html',
  directives: [RouterOutlet, RouterLink]
})
@RouteConfig([
  { path: '/', component: Home, name: 'home' },
  { path: '/about', component: About, name: 'about' }
])
export class App {}
```

当装饰器接受参数（就像前面示例中的`Component`、`RouteConfig`和`View`一样），它们需要被定义为接受参数并返回实际装饰器的函数：

```ts
function Component(config) {
  // validate properties
  return (componentCtrl) => {
    // apply decorator
  };
}
```

在这个例子中，我们定义了一个可配置的装饰器，名为`Component`，它接受一个名为`config`的单个参数并返回一个装饰器。

# 使用 ES2015 编写模块化代码

JavaScript 专业人士多年来经历的另一个问题是语言中缺乏模块系统。最初，社区开发了不同的模式，旨在强制执行我们生产的软件的模块化和封装。这些模式包括模块模式，它利用了函数词法作用域和闭包。另一个例子是命名空间模式，它将不同的命名空间表示为嵌套对象。AngularJS 1.x 引入了自己的模块系统，不幸的是它不提供懒加载模块等功能。然而，这些模式更像是变通办法，而不是真正的解决方案。

**CommonJS**（在 node.js 中使用）和**AMD**（**异步模块定义**）后来被发明。它们仍然广泛使用，并提供功能，如处理循环依赖，异步模块加载（在 AMD 中），等等。

TC39 吸收了现有模块系统的优点，并在语言级别引入了这个概念。ES2015 提供了两个 API 来定义和消费模块。它们如下：

+   声明式 API。

+   使用模块加载器的命令式 API。

Angular 2 充分利用了 ES2015 模块系统，让我们深入研究一下！在本节中，我们将看一下用于声明性定义和消费模块的语法。我们还将窥探模块加载器的 API，以便了解如何以显式异步方式编程加载模块。

## 使用 ES2015 模块语法

让我们来看一个例子：

```ts
// ch3/modules/math.ts

export function square(x) {
  return Math.pow(x, 2);
};
export function log10(x) {
  return Math.log10(x);
};
export const PI = Math.PI;
```

在上面的片段中，我们在文件`math.ts`中定义了一个简单的 ES2015 模块。我们可以将其视为一个样本数学 Angular 2 实用模块。在其中，我们定义并导出了函数`square`和`log10`，以及常量`PI`。`const`关键字是 ES2015 带来的另一个关键字，用于定义常量。正如你所看到的，我们所做的不过是在函数定义前加上`export`关键字。如果我们最终想要导出整个功能并跳过重复显式使用`export`，我们可以：

```ts
// ch3/modules/math2.ts

function square(x) {
  return Math.pow(x, 2);
};
function log10(x) {
  return Math.log10(x);
};
const PI = Math.PI;
export { square, log10, PI };
```

最后一行的语法只不过是 ES2015 引入的增强对象文字语法。现在，让我们看看如何消费这个模块：

```ts
// ch3/modules/app.ts

import {square, log10} from './math';
console.log(square(2)); // 4
console.log(log10(10)); // 1
```

作为模块的标识符，我们使用了相对于当前文件的路径。通过解构，我们导入了所需的函数——在这种情况下是`square`和`log10`。

## 利用隐式的异步行为

重要的是要注意，ES2015 模块语法具有隐式的异步行为。

假设我们有模块`A`，`B`和`C`。模块`A`使用模块`B`和`C`，所以它依赖于它们。一旦用户需要模块`A`，JavaScript 模块加载器就需要在能够调用模块`A`中的任何逻辑之前加载模块`B`和`C`，因为我们有依赖关系。然而，模块`B`和`C`将被异步加载。一旦它们完全加载，JavaScript 虚拟机将能够执行模块`A`。

## 使用别名

另一种典型的情况是当我们想要为给定的导出使用别名。例如，如果我们使用第三方库，我们可能想要重命名其任何导出，以避免名称冲突或只是为了更方便的命名：

```ts
import {bootstrap as initialize} from 'angular2/platform/browser';
```

## 导入所有模块导出

我们可以使用以下方式导入整个`math`模块：

```ts
// ch3/modules/app2.ts

import * as math from './math';
console.log(math.square(2)); // 4
console.log(math.log10(10)); // 1
console.log(math.PI); // 3.141592653589793
```

这个语法背后的语义与 CommonJS 非常相似，尽管在浏览器中，我们有隐式的异步行为。

## 默认导出

如果给定模块定义了一个导出，这个导出很可能会被任何消费模块使用，我们可以利用默认导出语法：

```ts
// ch3/modules/math3.ts

export default function cube(x) {
  return Math.pow(x, 3);
};
export function square(x) {
  return Math.pow(x, 2);
};
```

为了使用这个模块，我们可以使用以下`app.ts`文件：

```ts
// ch3/modules/app3.ts

import cube from './math3';
console.log(cube(3)); // 27
```

或者，如果我们想要导入默认导出以及其他一些导出，我们可以使用：

```ts
// ch3/modules/app4.ts

import cube, { square } from './math3';
console.log(square(2)); // 4
console.log(cube(3)); // 27
```

一般来说，默认导出只是一个用保留字`default`命名的命名导出：

```ts
// ch3/modules/app5.ts

import { default as cube } from './math3';
console.log(cube(3)); // 27
```

# ES2015 模块加载器

标准的新版本定义了一个用于处理模块的编程 API。这就是所谓的模块加载器 API。它允许我们定义和导入模块，或配置模块加载。

假设我们在文件`app.js`中有以下模块定义：

```ts
import { square } from './math';
export function main() {
  console.log(square(2)); // 4
}
```

从文件`init.js`中，我们可以以编程方式加载`app`模块，并使用以下方式调用其`main`函数：

```ts
System.import('./app')
  .then(app => {
    app.main();
  })
  .catch(error => {
    console.log('Terrible error happened', error);
  });
```

全局对象`System`有一个名为`import`的方法，允许我们使用它们的标识符导入模块。在前面的片段中，我们导入了在`app.js`中定义的`app`模块。`System.import`返回一个 promise，该 promise 在成功时可以解析，或在发生错误时被拒绝。一旦 promise 作为传递给`then`的回调的第一个参数解析，我们将得到模块本身。在拒绝的情况下注册的回调的第一个参数是发生的错误。

最后一段代码不存在于 GitHub 存储库中，因为它需要一些额外的配置。我们将在本书的下一章中更明确地应用模块加载器在 Angular 2 示例中。

# ES2015 和 ES2016 回顾

恭喜！我们已经超过学习 TypeScript 的一半了。我们刚刚看到的所有功能都是 TypeScript 的一部分，因为它实现了 JavaScript 的超集，并且所有这些功能都是当前语法的升级，对于有经验的 JavaScript 开发人员来说很容易掌握。

在接下来的章节中，我们将描述 TypeScript 的所有令人惊奇的功能，这些功能超出了与 ECMAScript 的交集。

# 利用静态类型

静态类型是可以为我们的开发过程提供更好工具支持的。在编写 JavaScript 时，IDE 和文本编辑器所能做的最多就是语法高亮和基于我们代码的复杂静态分析提供一些基本的自动补全建议。这意味着我们只能通过运行代码来验证我们没有犯任何拼写错误。

在前面的章节中，我们只描述了 ECMAScript 提供的新功能，这些功能预计将在不久的将来由浏览器实现。在本节中，我们将看看 TypeScript 提供了什么来帮助我们减少错误，并提高生产力。在撰写本文时，尚无计划在浏览器中实现静态类型的内置支持。

TypeScript 代码经过中间预处理，进行类型检查并丢弃所有类型注释，以提供现代浏览器支持的有效 JavaScript。

## 使用显式类型定义

就像 Java 和 C++一样，TypeScript 允许我们明确声明给定变量的类型：

```ts
let foo: number = 42;
```

前一行使用`let`语法在当前块中定义变量`foo`。我们明确声明要将`foo`设置为`number`类型，并将`foo`的值设置为`42`。

现在让我们尝试更改`foo`的值：

```ts
let foo: number = 42;
foo = '42';
```

在这里，在声明`foo`之后，我们将其值设置为字符串`'42'`。这是完全有效的 JavaScript 代码；然而，如果我们使用 TypeScript 的编译器编译它，我们将得到：

```ts
$ tsc basic.ts
basic.ts(2,1): error TS2322: Type 'string' is not assignable to type 'number'.
```

一旦`foo`与给定类型关联，我们就不能为其分配属于不同类型的值。这是我们可以跳过显式类型定义的原因之一，如果我们为给定变量分配一个值：

```ts
let foo = 42;
foo = '42';
```

这段代码背后的语义将与显式类型定义的代码相同，因为 TypeScript 的类型推断。我们将在本章末进一步研究它。

### 任意类型

TypeScript 中的所有类型都是称为 `any` 的类型的子类型。我们可以使用 `any` 关键字声明属于 `any` 类型的变量。这样的变量可以保存 `any` 类型的值：

```ts
let foo: any;
foo = {};
foo = 'bar ';
foo += 42;
console.log(foo); // "bar 42"
```

上述代码是有效的 TypeScript 代码，在编译或运行时不会抛出任何错误。如果我们对所有变量使用类型 `any`，基本上就是使用动态类型编写代码，这会丧失 TypeScript 编译器的所有优势。这就是为什么我们必须小心使用 `any`，只有在必要时才使用它。

TypeScript 中的所有其他类型都属于以下类别之一：

+   **原始类型**：这包括 Number、String、Boolean、Void、Null、Undefined 和 Enum 类型。

+   **联合类型**：联合类型超出了本书的范围。您可以在 TypeScript 规范中查看它们。

+   **对象类型**：这包括函数类型、类和接口类型引用、数组类型、元组类型、函数类型和构造函数类型。

+   **类型参数**：这包括将在 *使用类型参数编写通用代码* 部分中描述的泛型。

## 理解原始类型

TypeScript 中大多数原始类型都是我们在 JavaScript 中已经熟悉的类型：Number、String、Boolean、Null 和 Undefined。因此，我们将跳过它们的正式解释。另一组在开发 Angular 2 应用程序时很方便的类型是用户定义的枚举类型。

### 枚举类型

枚举类型是原始用户定义类型，根据规范，它们是 Number 的子类。`enums` 的概念存在于 Java、C++ 和 C# 语言中，在 TypeScript 中具有相同的语义——由一组命名值元素组成的用户定义类型。在 TypeScript 中，我们可以使用以下语法定义 `enum`：

```ts
enum STATES {
  CONNECTING,
  CONNECTED,
  DISCONNECTING,
  WAITING,
  DISCONNECTED	
};
```

这将被翻译为以下 JavaScript：

```ts
var STATES;
(function (STATES) {
    STATES[STATES["CONNECTING"] = 0] = "CONNECTING";
    STATES[STATES["CONNECTED"] = 1] = "CONNECTED";
    STATES[STATES["DISCONNECTING"] = 2] = "DISCONNECTING";
    STATES[STATES["WAITING"] = 3] = "WAITING";
    STATES[STATES["DISCONNECTED"] = 4] = "DISCONNECTED";
})(STATES || (STATES = {}));
```

我们可以如下使用 `enum` 类型：

```ts
if (this.state === STATES.CONNECTING) {
  console.log('The system is connecting');
}
```

## 理解对象类型

在这一部分，我们将看一下数组类型和函数类型，它们属于更通用的对象类型类。我们还将探讨如何定义类和接口。元组类型是由 TypeScript 1.3 引入的，它们的主要目的是允许语言开始对 ES2015 引入的新功能进行类型化，比如解构。我们不会在本书中描述它们。想要进一步阅读可以查看语言规范[`www.typescriptlang.org`](http://www.typescriptlang.org)。

### 数组类型

在 TypeScript 中，数组是具有共同元素类型的 JavaScript 数组。这意味着我们不能在给定数组中有不同类型的元素。我们为 TypeScript 中的所有内置类型以及我们定义的所有自定义类型都有不同的数组类型。

我们可以定义一个数字数组如下：

```ts
let primes: number[] = [];
primes.push(2);
primes.push(3);
```

如果我们想要一个看起来杂种的数组，类似于 JavaScript 中的数组，我们可以使用类型引用`any`：

```ts
let randomItems: any[] = [];
randomItems.push(1);
randomItems.push("foo");
randomItems.push([]);
randomItems.push({});
```

这是可能的，因为我们推送到数组的所有值的类型都是`any`类型的子类型，我们声明的数组包含类型为`any`的值。

我们可以在 TypeScript 数组类型中使用我们熟悉的 JavaScript 数组方法：

```ts
let randomItems: any[] = [];
randomItems.push("foo");
randomItems.push("bar");
randomItems.join(''); // foobar
randomItems.splice(1, 0, "baz");
randomItems.join(''); // foobazbar
```

我们还有方括号运算符，它给我们提供对数组元素的随机访问：

```ts
let randomItems: any[] = [];
randomItems.push("foo");
randomItems.push("bar");
randomItems[0] === "foo"
randomItems[1] === "bar"
```

### 函数类型

函数类型是一组具有不同签名的所有函数，包括不同数量的参数、不同参数类型或不同返回结果类型。

我们已经熟悉如何在 JavaScript 中创建新函数。我们可以使用函数表达式或函数声明：

```ts
// function expression
var isPrime = function (n) {
  // body
};
// function declaration
function isPrime(n) {
  // body
};
```

或者，我们可以使用新的箭头函数语法：

```ts
var isPrime = n => {
  // body
};
```

TypeScript 唯一改变的是定义函数参数类型和返回结果类型的功能。语言编译器执行类型检查和转译后，所有类型注释都将被移除。如果我们使用函数表达式并将函数分配给变量，我们可以按照以下方式定义变量类型：

```ts
let variable: (arg1: type1, arg2: type2, …, argn: typen) => returnType
```

例如：

```ts
let isPrime: (n: number) => boolean = n => {
  // body
};
```

在`函数声明`的情况下，我们将有：

```ts
function isPrime(n: number): boolean {
  // body
}
```

如果我们想在对象字面量中定义一个方法，我们可以按照以下方式处理它：

```ts
let math = {
  squareRoot(n: number): number {
    // …
  },
};
```

在前面的例子中，我们使用了 ES2015 语法定义了一个对象字面量，其中定义了方法`squareRoot`。

如果我们想定义一个产生一些副作用而不是返回结果的函数，我们可以将其定义为`void`函数：

```ts
let person = {
  _name: null,
  setName(name: string): void {
    this._name = name;
  }
};
```

## 定义类

TypeScript 类与 ES2015 提供的类似。然而，它改变了类型声明并创建了更多的语法糖。例如，让我们把之前定义的`Human`类变成一个有效的 TypeScript 类：

```ts
class Human {
  static totalPeople = 0;
  _name: string;
  constructor(name) {
    this._name = name;
    Human.totalPeople += 1;
  }
  get name() {
    return this._name;
  }
  set name(val) {
    this._name = val;
  }
  talk() {
    return `Hi, I'm ${this.name}!`;
  }
}
```

当前的 TypeScript 定义与我们已经介绍的定义没有区别，然而，在这种情况下，`_name`属性的声明是必需的。以下是如何使用这个类的方法：

```ts
let human = new Human('foo');
console.log(human._name);
```

## 使用访问修饰符

类似于大多数支持类的传统面向对象语言，TypeScript 允许定义访问修饰符。为了拒绝在类外部直接访问`_name`属性，我们可以将其声明为私有：

```ts
class Human {
  static totalPeople = 0;
  private _name: string;
  // …
}
```

TypeScript 支持的访问修饰符有：

+   **公共**：所有声明为公共的属性和方法可以在任何地方访问。

+   **私有**：所有声明为私有的属性和方法只能从类的定义内部访问。

+   **受保护**：所有声明为受保护的属性和方法可以从类的定义内部或扩展拥有该属性或方法的任何其他类的定义中访问。

访问修饰符是实现具有良好封装和明确定义接口的 Angular 2 服务的好方法。为了更好地理解它，让我们看一个使用之前定义的类层次结构的示例，该类层次结构已转换为 TypeScript：

```ts
class Human {
  static totalPeople = 0;
  constructor(protected name: string, private age: number) {
    Human.totalPeople += 1;
  }
  talk() {
    return `Hi, I'm ${this.name}!`;
  }
}

class Developer extends Human {
  constructor(name: string, private languages: string[], age: number) {
    super(name, age);
  }
  talk() {
    return `${super.talk()} And I know ${this.languages.join(', ')}.`;
  }
}
```

就像 ES2015 一样，TypeScript 支持`extends`关键字，并将其解析为原型 JavaScript 继承。

在前面的示例中，我们直接在构造函数内部设置了`name`和`age`属性的访问修饰符。这种语法背后的语义与前面示例中使用的语法不同。它的含义是：定义一个受保护的名为`name`的属性，类型为`string`，并将传递给构造函数调用的第一个值赋给它。私有的`age`属性也是一样的。这样可以避免我们在构造函数中显式设置值。如果我们看一下`Developer`类的构造函数，我们可以看到我们可以在这些语法之间使用混合。我们可以在构造函数的签名中明确定义属性，或者只定义构造函数接受给定类型的参数。

现在，让我们创建`Developer`类的一个新实例：

```ts
let dev = new Developer("foo", ["JavaScript", "Go"], 42);
dev.languages = ["Java"];
```

在编译过程中，TypeScript 将抛出一个错误，告诉我们**属性 languages 是私有的，只能在类"Developer"内部访问**。现在，让我们看看如果创建一个新的`Human`类并尝试从其定义外部访问其属性会发生什么：

```ts
let human = new Human("foo", 42);
human.age = 42;
human.name = "bar";
```

在这种情况下，我们将得到以下两个错误：

**属性 age 是私有的，只能在类"Human"内部访问**和**属性 name 是受保护的，只能在类"Human"及其子类内部访问**。

然而，如果我们尝试在`Developer`的定义内部访问`_name`属性，编译器不会抛出任何错误。

为了更好地了解 TypeScript 编译器将从类型注释的类产生什么，让我们看一下以下定义产生的 JavaScript：

```ts
class Human {
  constructor(private name: string) {}
}
```

生成的 ECMAScript 5 将是：

```ts
var Human = (function () {
    function Human(name) {
        this.name = name;
    }
    return Human;
})();
```

通过使用`new`运算符调用构造函数实例化的对象直接添加了定义的属性。这意味着一旦代码编译完成，我们就可以直接访问创建的对象的私有成员。为了总结一下，访问修饰符被添加到语言中，以帮助我们强制实现更好的封装，并在我们违反封装时获得编译时错误。

## 定义接口

编程语言中的**子类型**允许我们根据它们是通用对象的专门化版本这一观察来以相同的方式对待对象。这并不意味着它们必须是相同类的实例，或者它们的接口之间有完全的交集。这些对象可能只有一些共同的属性，但在特定上下文中仍然可以以相同的方式对待。在 JavaScript 中，我们通常使用鸭子类型。我们可以根据这些方法的存在假设，在函数中为所有传递的对象调用特定的方法。然而，我们都曾经历过 JavaScript 解释器抛出的*undefined is not a function*错误。

面向对象编程和 TypeScript 提供了一个解决方案。它们允许我们确保如果它们实现了声明它们拥有属性子集的接口，那么我们的对象具有类似的行为。

例如，我们可以定义我们的接口`Accountable`：

```ts
interface Accountable {
  getIncome(): number;
}
```

现在，我们可以通过以下方式确保`Individual`和`Firm`都实现了这个接口：

```ts
class Firm implements Accountable {
  getIncome(): number {
    // …
  }
}
class Individual implements Accountable {
  getIncome(): number {
    // …
  }
}
```

如果我们实现了一个给定的接口，我们需要为其定义的所有方法提供实现，否则 TypeScript 编译器将抛出错误。我们实现的方法必须与接口定义中声明的方法具有相同的签名。

TypeScript 接口还支持属性。在`Accountable`接口中，我们可以包含一个名为`accountNumber`的字段，类型为字符串：

```ts
interface Accountable {
  accountNumber: string;
  getIncome(): number;
}
```

我们可以在我们的类中定义它作为一个字段或一个 getter。

### 接口继承

接口也可以相互扩展。例如，我们可以将我们的`Individual`类转换为一个具有社会安全号码的接口：

```ts
interface Accountable {
  accountNumber: string;
  getIncome(): number;
}
interface Individual extends Accountable {
  ssn: string;
}
```

由于接口支持多重继承，`Individual`也可以扩展具有`name`和`age`属性的`Human`接口：

```ts
interface Accountable {
  accountNumber: string;
  getIncome(): number;
}
interface Human {
  age: number;
  name: number;
}
interface Individual extends Accountable, Human {
  ssn: string;
}
```

### 实现多个接口

如果类的行为是在几个接口中定义的属性的并集，它可以实现它们所有：

```ts
class Person implements Human, Accountable {
  age: number;
  name: string;
  accountNumber: string;
  getIncome(): number {
    // ...
  }
}
```

在这种情况下，我们需要提供类实现的所有方法的实现，否则编译器将抛出编译时错误。

# 使用 TypeScript 装饰器进一步增强表达能力

在 ES2015 中，我们只能装饰类、属性、方法、getter 和 setter。TypeScript 通过允许我们装饰函数或方法参数来进一步扩展了这一点：

```ts
class Http {
  // …
}
class GitHubApi {
  constructor(@Inject(Http) http) {
    // …
  }
}
```

然而，参数装饰器不应该改变任何额外的行为。相反，它们用于生成元数据。这些装饰器最典型的用例是 Angular 2 的依赖注入机制。

# 使用类型参数编写通用代码

在使用静态类型的部分开头，我们提到了类型参数。为了更好地理解它们，让我们从一个例子开始。假设我们想要实现经典的数据结构`BinarySearchTree`。让我们使用一个类来定义它的接口，而不应用任何方法实现：

```ts
class Node {
  value: any;
  left: Node;
  right: Node;
}

class BinarySearchTree {
  private root: Node;
  insert(any: value): void { /* … */ }
  remove(any: value): void { /* … */ }
  exists(any: value): boolean { /* … */ }
  inorder(callback: {(value: any): void}): void { /* … */ }
}
```

在前面的片段中，我们定义了一个名为`Node`的类。这个类的实例代表了我们树中的个别节点。每个`node`都有一个左子节点和一个右子节点，以及一个`any`类型的值；我们使用`any`来能够在我们的节点和相应的`BinarySearchTree`中存储任意类型的数据。

尽管先前的实现看起来是合理的，但我们放弃了 TypeScript 提供的最重要的特性——静态类型。通过将`Node`类内的值字段的类型设置为`any`，我们无法充分利用编译时类型检查。这也限制了 IDE 和文本编辑器在访问`Node`类的实例的`value`属性时提供的功能。

TypeScript 提供了一个优雅的解决方案，这在静态类型世界中已经广泛流行——类型参数。使用泛型，我们可以使用类型参数对我们创建的类进行参数化。例如，我们可以将我们的`Node`类转换为以下形式：

```ts
class Node<T> {
  value: T;
  left: Node<T>;
  right: Node<T>;
}
```

`Node<T>`表示这个类有一个名为`T`的单一类型参数，在类的定义中的某个地方使用。我们可以通过以下方式使用`Node`：

```ts
let numberNode = new Node<number>();
let stringNode = new Node<string>();
numberNode.right = new Node<number>();
numberNode.value = 42;
numberNode.value = "42"; // Type "string" is not assignable to type "number"
numberNode.left = stringNode; // Type Node<string> is not assignable to type Node<number>
```

在前面的片段中，我们创建了三个节点：`numberNode`，`stringNode`和另一个类型为`Node<number>`的节点，将其值分配给`numberNode`的右子节点。请注意，由于`numberNode`的类型是`Node<number>`，我们可以将其值设置为`42`，但不能使用字符串`"42"`。对其左子节点也是适用的。在定义中，我们明确声明了希望左右子节点的类型为`Node<number>`。这意味着我们不能将类型为`Node<string>`的值分配给它们；这就是为什么我们会得到第二个编译时错误。

## 使用泛型函数

泛型的另一个典型用途是定义操作一组类型的函数。例如，我们可以定义一个接受类型为`T`的参数并返回它的`identity`函数：

```ts
function identity<T>(arg: T) {
  return arg;
}
```

然而，在某些情况下，我们可能只想使用具有特定属性的类型的实例。为了实现这一点，我们可以使用扩展语法，允许我们声明应该是类型参数的类型的子类型：

```ts
interface Comparable {
  compare(a: Comparable): number;
}
function sort<T extends Comparable>(arr: Comparable[]): Comparable[] {
  // …
}
```

例如，在这里，我们定义了一个名为`Comparable`的接口。它有一个名为`compare`的操作。实现接口`Comparable`的类需要实现操作`compare`。当使用给定参数调用`compare`时，如果目标对象大于传递的参数，则返回`1`，如果它们相等，则返回`0`，如果目标对象小于传递的参数，则返回`-1`。

## 具有多个类型参数

TypeScript 允许我们使用多个类型参数：

```ts
class Pair<K, V> {
  key: K;
  value: V;
}
```

在这种情况下，我们可以使用以下语法创建`Pair<K, V>`类的实例：

```ts
let pair = new Pair<string, number>();
pair.key = "foo";
pair.value = 42;
```

# 使用 TypeScript 的类型推断编写更简洁的代码

静态类型具有许多好处；然而，它使我们编写更冗长的代码，需要添加所有必需的类型注释。

在某些情况下，TypeScript 的编译器能够猜测我们代码中表达式的类型，例如：

```ts
let answer = 42;
answer = "42"; // Type "string" is not assignable to type "number"
```

在上面的例子中，我们定义了一个变量`answer`，并将值`42`赋给它。由于 TypeScript 是静态类型的，变量的类型一旦声明就不能改变，编译器足够聪明，能够猜测`answer`的类型是`number`。

如果我们在定义变量时不给变量赋值，编译器将把它的类型设置为`any`：

```ts
let answer;
answer = 42;
answer = "42";
```

上面的代码片段将在没有编译时错误的情况下编译。

## 最佳通用类型

有时，类型推断可能是多个表达式的结果。当我们将异构数组分配给一个变量时就是这种情况：

```ts
let x = ["42", 42];
```

在这种情况下，`x`的类型将是`any[]`。然而，假设我们有以下情况：

```ts
let x = [42, null, 32];
```

`x`的类型将是`number[]`，因为`Number`类型是`Null`的子类型。

## 上下文类型推断

当表达式的类型是从其位置暗示出来时，就发生了上下文类型推断，例如：

```ts
document.body.addEventListener("mousedown", e => {
  e.foo(); // Property "foo" does not exists on a type "MouseEvent"
}, false);
```

在这种情况下，回调函数`e`的参数类型是根据编译器根据其使用上下文“猜测”的。编译器根据`addEventListener`的调用和传递给该方法的参数理解`e`的类型。如果我们使用键盘事件（例如`keydown`），TypeScript 会意识到`e`的类型是`KeyboardEvent`。

类型推断是一种机制，使我们能够通过利用 TypeScript 执行的静态分析来编写更简洁的代码。根据上下文，TypeScript 的编译器能够猜测给定表达式的类型，而无需显式定义。

# 使用环境类型定义

尽管静态类型很棒，但我们使用的大多数前端库都是用 JavaScript 构建的，它是动态类型的。因此，我们希望在 Angular 2 中使用 TypeScript，但在使用外部库的代码中没有编译时类型检查是一个大问题；这会阻止我们利用编译时的类型检查。

TypeScript 是根据这些要点构建的。为了让 TypeScript 编译器处理它最擅长的事情，我们可以使用所谓的环境类型定义。它们允许我们提供现有 JavaScript 库的外部类型定义。这样，它们为编译器提供了提示。

## 使用预定义的环境类型定义

幸运的是，我们不必为我们使用的所有 JavaScript 库和框架创建环境类型定义。这些库的社区和/或作者已经在网上发布了这样的定义；最大的存储库位于：[`github.com/DefinitelyTyped/DefinitelyTyped`](https://github.com/DefinitelyTyped/DefinitelyTyped)。还有一个用于管理它们的工具叫做**typings**。我们可以使用以下命令通过`npm`安装它：

```ts
**npm install –g typings**

```

类型定义的配置在一个名为`typings.json`的文件中定义，默认情况下，所有已安装的环境类型定义将位于`./typings`目录中。

为了创建带有基本配置的`typings.json`文件，请使用：

```ts
**typings init**

```

我们可以使用以下命令安装新的类型定义：

```ts
**typings install angularjs --ambient**

```

上述命令将下载 AngularJS 1.x 的类型定义，并将它们保存在`typings`目录下的`browser/ambient/angular/angular.d.ts`和`main/ambient/angular/angular.d.ts`中。

### 注意

拥有`main/ambient`和`browser/ambient`目录是为了防止类型冲突。例如，如果我们在项目的`backend/build`和前端都使用 TypeScript，可能会引入类型定义的重复，这将导致编译时错误。通过为项目的各个部分的环境类型定义拥有两个目录，我们可以分别使用`main.d.ts`和`browser.d.ts`来包含其中一个。有关类型定义的更多信息，您可以访问 GitHub 上项目的官方存储库[`github.com/typings/typings`](https://github.com/typings/typings)。

为了下载类型定义并在`typings.json`中添加条目，您可以使用：

```ts
**typings install angular --ambient --save**

```

运行上述命令后，您的`typings.json`文件应该类似于：

```ts
{
  "dependencies": {},
  "devDependencies": {},
  "ambientDependencies": {
    "angular": "github:DefinitelyTyped/DefinitelyTyped/angularjs/angular.d.ts#1c4a34873c9e70cce86edd0e61c559e43dfa5f75"
  }
}
```

现在，为了在 TypeScript 中使用 AngularJS 1.x，创建`app.ts`并输入以下内容：

```ts
/// <reference path="./typings/browser.d.ts"/>

var module = angular.module("module", []);
module.controller("MainCtrl",
  function MainCtrl($scope: angular.IScope) {

  });
```

要编译`app.ts`，请使用：

```ts
**tsc app.ts**

```

TypeScript 编译将把编译后的内容输出到`app.js`中。为了添加额外的自动化并在项目中的任何文件更改时调用 TypeScript 编译器，您可以使用像 gulp 或 grunt 这样的任务运行器，或者将`-w`选项传递给`tsc`。

### 注意

由于使用引用元素来包含类型定义被认为是不良实践，我们可以使用`tsconfig.json`文件代替。在那里，我们可以配置哪些目录需要在编译过程中被`tsc`包含。更多信息请访问[`github.com/Microsoft/TypeScript/wiki/tsconfig.json`](https://github.com/Microsoft/TypeScript/wiki/tsconfig.json)。

## 自定义环境类型定义

为了理解一切是如何协同工作的，让我们来看一个例子。假设我们有一个 JavaScript 库的以下接口：

```ts
var DOM = {
  // Returns a set of elements which match the passed selector
  selectElements: function (selector) {
    // …
  },
  hide: function (element) {
    // …
  },
  show: function (element) {
    // …
  }
};
```

我们有一个分配给名为`DOM`的变量的对象文字。该对象具有以下方法：

+   `selectElements`：接受一个类型为字符串的单个参数并返回一组 DOM 元素。

+   `hide`：接受一个 DOM 节点作为参数并返回空。

+   `show`：接受一个`DOM`节点作为参数并返回空。

在 TypeScript 中，前面的定义将如下所示：

```ts
var DOM = {
  // Returns a set of elements which match the passed selector
  selectElements: function (selector: string): HTMLElement[] {
    return [];
  },
  hide: function (element: HTMLElement): void {
    element.hidden = true;
  },
  show: function (element: HTMLElement): void {
    element.hidden = false;
  }
};
```

这意味着我们可以如下定义我们的库接口：

```ts
interface LibraryInterface {
  selectElements(selector: string): HTMLElement[]
  hide(element: HTMLElement): void
  show(element: HTMLElement): void
}
```

## 定义 ts.d 文件

在我们有了库的接口之后，创建环境类型定义将变得很容易；我们只需要创建一个名为`dom`的扩展名为`ts.d`的文件，并输入以下内容：

```ts
// inside "dom.d.ts"

interface DOMLibraryInterface {
  selectElements(selector: string): HTMLElement[]
  hide(element: HTMLElement): void
  show(element: HTMLElement): void
}

declare var DOM: DOMLibraryInterface;
```

在前面的片段中，我们定义了名为`DOMLibraryInterface`的接口，并声明了类型为`DOMLibraryInterface`的变量`DOM`。

在能够利用静态类型的 JavaScript 库之前，唯一剩下的事情就是在我们想要使用我们的库的脚本文件中包含外部类型定义。我们可以这样做：

```ts
/// <reference path="dom.d.ts"/>
```

前面的片段提示编译器在哪里找到环境类型定义。

# 摘要

在本章中，我们窥探了用于实现 Angular 2 的 TypeScript 语言。虽然我们可以使用 ECMAScript 5 来开发我们的 Angular 2 应用程序，但谷歌建议使用 TypeScript 以利用其提供的静态类型。

在探索语言的过程中，我们看了一些 ES2015 和 ES2016 的核心特性。我们解释了 ES2015 和 ES2016 的类、箭头函数、块作用域变量定义、解构和模块。由于 Angular 2 利用了 ES2016 的装饰器，更准确地说是它们在 TypeScript 中的扩展，我们专门介绍了它们。

之后，我们看了一下如何通过使用显式类型定义来利用静态类型。我们描述了 TypeScript 中一些内置类型以及如何通过为类的成员指定访问修饰符来定义类。接下来我们介绍了接口。我们通过解释类型参数和环境类型定义来结束了我们在 TypeScript 中的冒险。

在下一章中，我们将开始深入探索 Angular 2，使用框架的组件和指令。
