# Angular 学习手册第二版（一）

> 原文：[`zh.annas-archive.org/md5/6C06861E49CB1AD699C8CFF7BAC7E048`](https://zh.annas-archive.org/md5/6C06861E49CB1AD699C8CFF7BAC7E048)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

自 2010 年以来，我们已经走了很长的路，当时 AngularJS 首次发布。互联网并不是真正用来作为一个应用平台，而是用来呈现静态页面的。当然，随着开发人员开始将其越来越多地视为他们的主要应用平台，这种情况已经发生了改变。能够触达数十亿人的承诺实在太诱人了。这意味着网络必须成熟起来。多年来已经尝试了不同的方法，比如 JSP、GWT、.NET 的 Web Forms 等等，这些方法或多或少地取得了成功。显而易见的是，当 AngularJS 出现时，它被视为救世主。它让每个人都能够快速地使用 JavaScript、CSS、HTML 甚至使用 AJAX 创建应用程序。它仍然是构建小到中型应用程序的有效选择。

某物使用起来越容易，人们就越有可能像番茄酱一样开始不断地添加更多内容并在各处使用它。AngularJS 从来都不是为大型企业应用程序而设计的。互联网不断发展，浏览器中提供了越来越多的功能。有一个想法，希望将所有这些新功能纳入其中，但同时确保 AngularJS 可以用于真正的大型应用程序。做出了一个决定，从头开始创建 Angular，作为 AngularJS 的继任者会更容易。因此，2016 年 9 月 14 日，Angular 的发布版本问世。从那时起，Angular 的主要版本以惊人的速度发布。

我们现在使用的是第 5 版。这并不意味着 Angular 的核心概念已经改变，它们已经被保留下来。在这一过程中引入了某些重大变化，但每个主要版本首先都是为了修复错误，引入新功能，并真正致力于使 Angular 应用程序尽可能快速，占用空间尽可能小。这是在当今以移动为先的世界中值得追求的目标。

本书旨在向读者介绍 Angular 的所有主要方面，并向您展示如何构建小型、中型甚至大型应用程序。您并不需要太多的知识来开始使用 Angular 应用程序，但它有许多层面。随着应用程序规模的增长，您将希望关心如何使其更美观、更快速、更易于维护等等。本书就是以此为出发点编写的。慢慢阅读本书。如果您想读几章并构建一些应用程序，那就去做吧。如果您想直接跳入更高级的功能，那也可以。

我们希望您会像我们写作时一样享受阅读本书。

# 本书内容包括

第一章*，在 Angular 中创建我们的第一个组件*，介绍了语义版本控制。这是一个重要的概念，因此您可以根据自己的需求决定是否采用新版本。本章还向读者介绍了 Angular CLI，并且读者将迈出编写 Angular 应用程序的第一步。

第二章*，IDE 和插件*，向您介绍了最流行的 IDE。还描述了最常见的 Angular 插件和代码片段，以进一步提高开发人员的生产力。

第三章*，介绍 TypeScript*，介绍了 TypeScript，这是编写 Angular 应用程序的选择语言。TypeScript 不仅仅是添加类型。您的代码可以变得更加优雅和安全，使用正确的功能将为您节省大量输入时间。

第四章*，在我们的组件中实现属性和事件*，介绍了如何向组件发送数据以及如何将方法绑定到它们，以便组件能够与上游进行通信。

第五章*，使用管道和指令增强我们的组件*，展示了如何使用管道和指令使您的组件更一致和可重用。

第六章*，使用 Angular 组件构建应用程序*，直接着手于构建真实应用程序的目标。我们讨论了如何思考以及如何使用最常见的结构指令来控制数据的显示方式，并在被 UI 元素操作时如何行为。

第七章，使用 Angular 进行异步数据服务，介绍了 RxJS 库，它不仅帮助我们处理 AJAX，还促进了反应式应用程序模式。在 RxJS 下，所有异步事物都成为一个概念，这引入的可能性是无限的。

第八章，Firebase，解释了 Firebase，这是谷歌的产品，允许您拥有后端作为服务。Firebase 让您专注于构建 Angular 应用程序，同时它会处理几乎所有其他事情。最好的部分是 Firebase 的反应性，这使得像聊天应用程序和协作应用程序一样轻松创建。

第九章，路由，解释了路由的概念，这样您就可以轻松扩展您的应用程序。

第十章，Angular 中的表单，涵盖了处理表单和用户输入的两种主要方式：基于模板的和反应式方法。

第十一章，Angular Material，带您了解 Angular Material，它不仅提供美观的界面，还配备了一堆组件，使得快速组装令人印象深刻的应用程序变得轻而易举。

第十二章，使用 Angular 对组件进行动画处理，介绍了 Angular 如何支持开发人员利用和控制相当高级的动画。

第十三章，Angular 中的单元测试，解释了 Angular 中的单元测试。Angular 团队确实为测试添加了一流的支持，因此您只需很少的代码，就能测试您的所有可能构造。从组件、服务和指令到端到端测试，应有尽有。

附录 A，SystemJS，介绍了 SystemJS，这是一个模块加载器，曾经是设置 Angular 应用程序的唯一方式。这仍然是设置项目的有效方式。本附录将涵盖 SystemJS 的核心部分，并特别关注 Angular 设置部分。

附录 B，使用 Angular 的 Webpack，旨在向开发人员展示如何使用 Webpack 设置您的 Angular 项目。肯定存在一定数量的用户群体，他们希望完全控制 Web 项目的每个方面。如果您是其中之一，那么这个附录就是为您准备的。

# 这本书需要什么

为了真正欣赏这本书，我们假设您对 HTML、CSS 和 JavaScript 有一定程度的了解，以及使用 AJAX 调用服务。我们还假设您对 REST 有一定的了解。现代 Web 应用程序开发已经变得非常艰巨，但我们希望在阅读完本书后，您会觉得对正在发生的事情有更多的了解，并且您也会觉得能够承担起使用 Angular 进行下一个 Web 开发项目的责任。

由于您将花费大部分时间编写 JavaScript、HTML 或 CSS 代码，我们只假设您可以访问一个体面的文本编辑器。您使用的编辑器越成熟，您将获得的帮助就越多，这就是为什么我们在本书中介绍了一些插件和最佳实践，以使您的日常工作变得不那么痛苦。

# 这本书适合谁

这本书适用于没有 Angular 先前知识但在 JavaScript、Node.js、HTML 和 CSS 方面有经验，并且对单页面应用的概念相当熟悉的 Web 开发人员。

# 惯例

在本书中，您将找到一些文本样式，用于区分不同类型的信息。以下是这些样式的一些示例及其含义的解释。文本中的代码单词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 用户名显示如下：“导入响应式`Forms`模块。”

代码块设置如下：

```ts
class AppComponent {
 title:string = 'hello app';
}
```

任何命令行输入或输出都将按照以下方式编写：

```ts
npm install -g @angular/cli
```

**新术语**和**重要单词**以粗体显示。屏幕上看到的单词，例如菜单或对话框中的单词，会在文本中以这种方式出现：“我们点击左侧的数据库菜单选项。”

警告或重要说明会以这种方式出现。提示和技巧会以这种方式出现。


# 第一章：在 Angular 中创建我们的第一个组件

在进行 Angular 开发时，有一些事情是好知道的，还有一些事情是我们需要知道的，以便开始我们伟大的旅程。其中一件好知道的事情是**语义化版本控制**。这是好知道的，因为这是 Angular 团队选择处理更改的方式。当您前往[`angular.io/`](https://angular.io/)或 Stack Overflow 等网站搜索解决方案时，这将有望使您更容易找到未来应用程序开发挑战的正确解决方案。

另一个重要但有时令人痛苦的话题是项目设置。这是一个必要的恶，需要在项目开始时完成，但在早期正确处理这个问题可以减少随着应用程序的增长而产生的许多摩擦。因此，本章的很大一部分致力于揭开谜团，并使您作为开发人员能够避免未来的挫折和偏头痛。

在本章结束时，我们还将能够创建我们的第一个应用程序，并了解 Angular 应用程序的结构。总之，以下是本章将探讨的主要主题。

在这一章中，我们将：

+   了解语义化版本控制的重要性，以及 Angular 对其的看法

+   了解我们如何使用 Angular CLI 设置项目

+   创建我们的第一个应用程序，并开始了解 Angular 中的核心概念

# 这只是 Angular-介绍语义化版本控制

使用语义化版本控制是关于管理期望。这是关于管理您的应用程序或库的用户在发生更改时会做出何种反应。更改会因各种原因而发生，无论是修复代码中的错误还是添加/更改/删除功能。框架或库的作者用来传达某个更改的影响的方式是通过增加软件的版本号。

一个可供生产使用的软件通常具有版本 1.0 或 1.0.0（如果您想更具体）。

在更新软件时可能会发生三种不同级别的更改。要么您对其进行修补并有效地纠正某些问题。要么您进行次要更改，这基本上意味着您添加功能。或者最后您进行主要更改，这可能会完全改变软件的工作方式。让我们在接下来的章节中更详细地描述这些变化。

# 版本更改

补丁变更意味着我们将最右边的数字增加一。将软件从 1.0.0 更改为 1.0.1 是一个小改变，通常是一个错误修复。作为软件的用户，你不需要担心；如果有什么变化，你应该高兴地发现某些东西突然工作得更好了。关键是，你可以放心地开始使用 1.0.1。

# 小改变

这意味着软件从 1.0.0 增加到 1.1.0。当我们增加中间数字时，我们正在处理更严重的变化。当软件功能被添加时，这个数字应该增加，而且它仍然应该向后兼容。在这种情况下，采用 1.1.0 版本的软件也是安全的。

# 主要变更

在这个阶段，版本号从 1.0.0 增加到 2.0.0。现在你需要留意了。在这个阶段，事情可能已经发生了很大的变化，构造可能已经被重命名或删除。它可能不兼容早期版本。我说“可能”是因为很多软件作者仍然确保有相当的向后兼容性，但这里的主要观点是没有保证，没有合同，保证它仍然可以工作。

# 那 Angular 呢？

Angular 的第一个版本大多数人都称为 Angular 1；后来它被称为 AngularJS。它没有使用语义化版本。大多数人实际上仍然将其称为 Angular 1。

然后 Angular 出现了，在 2016 年它达到了生产就绪状态。Angular 决定采用语义化版本，这在开发者社区引起了一些混乱，特别是当宣布将会有 Angular 4 和 5 等版本时。谷歌以及谷歌开发者专家开始向人们解释，他们希望人们称最新版本的框架为 Angular - 只是 Angular。你可以对这个决定的智慧进行争论，但事实仍然是，新的 Angular 正在使用语义化版本。这意味着 Angular 与 Angular 4 以及 Angular 11 等版本是相同的平台，如果有的话。采用语义化版本意味着作为 Angular 用户，你可以依赖事物一直以相同的方式工作，直到谷歌决定增加主要版本。即使在那时，你可以选择是保持在最新的主要版本上，还是想要升级你现有的应用程序。

# 一个全新的开始

如前所述，Angular 是 AngularJS 框架的全面重写，引入了全新的应用程序架构，完全使用 TypeScript 从头开始构建，TypeScript 是 JavaScript 的严格超集，它增加了可选的静态类型和对接口和装饰器的支持。

简而言之，Angular 应用程序基于一种架构设计，由 Web 组件树组成，它们通过各自特定的 I/O 接口相互连接。每个组件在底层利用了完全改进的依赖注入机制。

公平地说，这是对 Angular 真正含义的简单描述。然而，即使是 Angular 中最简单的项目也符合这些定义特征。在接下来的章节中，我们将专注于学习如何构建可互操作的组件和管理依赖注入，然后再转向路由、Web 表单和 HTTP 通信。这也解释了为什么我们在本书中不会明确提及 AngularJS。显然，浪费时间和页面提及对主题没有任何有用见解的东西是没有意义的，而且我们假设你可能不了解 Angular 1.x，因此这种知识在这里没有任何价值。

# Web 组件

Web 组件是一个概念，它包括四种技术，旨在一起使用以构建具有更高视觉表现力和可重用性的功能元素，从而实现更模块化、一致和可维护的 Web。这四种技术如下：

+   **模板**：这些是用于构造我们的内容的 HTML 片段

渲染

+   **自定义元素**：这些模板不仅包含传统的 HTML 元素，还包括提供更多呈现元素或 API 功能的自定义包装项

+   **影子 DOM**：这提供了一个沙盒，用于封装每个自定义元素的 CSS 布局规则和 JavaScript 行为

+   **HTML 导入**：HTML 不再仅限于承载 HTML 元素，还可以承载其他 HTML 文档

从理论上讲，Angular 组件确实是一个包含模板的自定义元素，用于承载其布局的 HTML 结构，后者由一个封装在影子 DOM 容器中的作用域 CSS 样式表控制。让我们用简单的英语来重新表达一下。想象一下 HTML5 中的 range 输入控件类型。这是一种方便的方式，可以为用户提供一个方便的输入控件，用于输入两个预定义边界之间的值。如果您以前没有使用过它，请在空白的 HTML 模板中插入以下标记，并在浏览器中加载它：

```ts
<input id="mySlider" type="range" min="0" max="100" step="10">
```

在浏览器中，您将看到一个漂亮的输入控件，其中包含一个水平滑块。使用浏览器开发者工具检查这样的控件将揭示一组隐藏的 HTML 标记，这些标记在您编辑 HTML 模板时并不存在。这就是影子 DOM 在起作用，具有由其自己封装的 CSS 控制的实际 HTML 模板，具有高级的拖动功能。您可能会同意，自己做这件事将是很酷的。好消息是，Angular 为您提供了交付这个功能所需的工具集，因此我们可以构建我们自己的自定义元素（输入控件、个性化标记和自包含小部件），其中包含我们选择的内部 HTML 标记和我们自己的样式表，不会受到页面托管我们组件的 CSS 的影响。

# 为什么选择 TypeScript 而不是其他语法？

Angular 应用程序可以使用多种语言和语法进行编码：ECMAScript 5、Dart、ECMAScript 6、TypeScript 或 ECMAScript 7。

TypeScript 是 ECMAScript 6（也称为 ECMAScript 2015）的类型超集，可以编译成普通的 JavaScript，并得到现代操作系统的广泛支持。它具有健全的面向对象设计，支持注解、装饰器和类型检查。

我们选择（并显然推荐）TypeScript 作为本书中指导如何开发 Angular 应用程序的首选语法的原因是 Angular 本身就是用这种语言编写的。精通 TypeScript 将使开发人员在理解框架的内部机制时具有巨大优势。

另一方面，值得注意的是，当涉及管理依赖注入和组件之间的类型绑定时，TypeScript 对注解和类型内省的支持变得至关重要，因为它可以以最小的代码占用量实现，我们将在本书的后面看到。

最终，如果这是您的偏好，您可以使用纯 ECMAScript 6 语法执行您的 Angular 项目。甚至本书提供的示例也可以通过删除类型注解和接口，或者用最冗长的 ES6 方式替换 TypeScript 中处理依赖注入的方式，轻松地转换为 ES6。

为了简洁起见，我们只会涵盖使用 TypeScript 编写的示例，并实际推荐其使用，因为由于类型注解，它具有更高的表达能力，并且通过基于类型内省的依赖注入的整洁方式。

# 使用 Angular CLI 设置我们的工作空间

有不同的方法可以开始，可以使用[`angular.io/`](https://angular.io/)网站上的 Angular 快速入门存储库，或安装脚手架工具 Angular CLI，或者最后，您可以使用 Webpack 来设置您的项目。值得指出的是，创建新的 Angular 项目的标准方式是使用*Angular CLI*并搭建您的项目。快速入门存储库使用的 Systemjs 曾经是构建 Angular 项目的默认方式。它现在正在迅速减少，但仍然是设置 Angular 项目的有效方式。因此，建议感兴趣的读者查看附录 A，*SystemJS*以获取更多信息。

如今，设置前端项目比以往任何时候都更加繁琐。我们过去只需在我们的 JavaScript 代码中包含必要的脚本，以及用于我们的 CSS 的`link`标签和用于我们的资产的`img`标签等。生活过去很简单。然后前端开发变得更加雄心勃勃，我们开始将我们的代码拆分成模块，我们开始使用预处理器来处理我们的代码和 CSS。总的来说，我们的项目变得更加复杂，我们开始依赖构建系统，如 Grunt、Gulp、Webpack 等。大多数开发人员并不是配置的铁杆粉丝，他们只想专注于构建应用程序。然而，现代浏览器更多地支持最新的 ECMAScript 标准，一些浏览器甚至开始支持在运行时解析的模块。尽管如此，这远非得到广泛支持。与此同时，我们仍然必须依赖工具进行捆绑和模块支持。

使用领先的框架（如 React 或 Angular）设置项目可能会非常困难。您需要知道要导入哪些库，并确保文件按正确的顺序处理，这将引入我们的脚手架工具主题。对于 AngularJS，使用 Yeoman 快速搭建新应用程序并预先配置许多好东西是非常流行的。React 有一个名为*create-react-app*的脚手架工具，您可能已经保存了它，它为 React 开发人员节省了无数小时。随着复杂性的增加，脚手架工具几乎成为必需品，但也是每个小时都用于产生业务价值而不是解决配置问题的地方。

创建 Angular CLI 工具的主要动机是帮助开发人员专注于应用程序构建，而不是太多地关注配置。基本上，通过一个简单的命令，您应该能够快速搭建一个应用程序，向其添加新构造，运行测试，或创建一个生产级捆绑包。Angular CLI 支持所有这些。

# 先决条件

您需要开始的是安装 Git 和 Node.js。Node.js 还将安装一个称为 NPM 的东西，这是一个您以后将用来安装项目所需文件的节点包管理器。完成后，您就可以设置您的 Angular 应用程序了。您可以在[`nodejs.org`](https://nodejs.org)找到 Node.js 的安装文件。

安装它的最简单方法是访问该网站：

```ts
https://nodejs.org/en/download/
```

安装 Node.js 也将安装一个称为 NPM 的东西，即 Node 包管理器，您将需要它来安装依赖项等。Angular CLI 需要 Node 6.9.0 和 NPM 3 或更高版本。目前在该网站上，您可以选择长期支持版本和当前版本。长期支持版本应该足够了。

# 安装

安装 Angular CLI 就像在您的终端中运行以下命令一样简单：

```ts
npm install -g @angular/cli
```

在某些系统上，您可能需要提升权限才能这样做；在这种情况下，以管理员身份运行您的终端窗口，在 Linux/macOS 上运行以下命令：

```ts
sudo npm install -g @angular/cli
```

# 第一个应用

一旦安装了 Angular CLI，就到了创建第一个项目的时候。为此，请进入您选择的目录并输入以下内容：

```ts
ng new <give it a name here>
```

输入以下内容：

```ts
ng new TodoApp
```

这将创建一个名为`TodoApp`的目录。在运行了上述命令之后，您需要做两件事才能在浏览器中看到您的应用程序：

+   导航到刚创建的目录

+   提供应用程序

这将通过以下命令完成：

```ts
cd TodoApp
npm start
```

此时，在`http://localhost:4200`上打开你的浏览器，你应该会看到以下内容：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-2e/img/cc3798ac-f306-4687-a4a5-4186198885c3.png)

# 测试

Angular CLI 不仅提供使您的应用程序工作的代码，还提供设置测试和包含测试的代码。运行所说的测试就像在终端中输入以下内容一样简单：

```ts
npm test
```

你应该会看到以下内容：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-2e/img/11371fd2-d676-4ca5-b1e1-78a4c89fd915.png)

为什么这样会起作用？让我们看一下刚刚创建的`package.json`文件和`scripts`标签。这里指定的所有内容都可以使用以下语法运行：

```ts
npm run <key>
```

在某些情况下，不需要输入`run`，只需输入以下内容即可：

```ts
npm <key>
```

这适用于`start`和`test`命令。

以下清单清楚地表明，可以运行的命令不仅仅是我们刚刚学到的`start`和`test`：

```ts
"scripts": {
 "ng": "ng",
 "start": "ng serve",
 "build": "ng build",
 "test": "ng test",
 "lint": "ng lint",
 "e2e": "ng e2e"
}
```

到目前为止，我们已经学会了如何安装 Angular CLI。使用 Angular CLI，我们已经学会了：

1.  搭建一个新项目。

1.  启动项目，看看它在浏览器中显示出来。

1.  运行测试。

这是相当了不起的成就。我们将在后面的章节中重新讨论 Angular CLI，因为它是一个非常有能力的工具，能够做更多的事情。

# 你好，Angular

我们即将迈出建立我们的第一个组件的第一步。Angular CLI 已经为我们搭建了项目，并且已经完成了大量的繁重工作。我们所需要做的就是创建一个新文件，并开始填充它的内容。百万美元的问题是要输入什么？

所以让我们开始构建我们的第一个组件。创建一个组件需要三个步骤。那就是：

1.  导入组件装饰器构造。

1.  用组件装饰器装饰一个类。

1.  将组件添加到它的模块中（这可能在两个不同的地方）。

# 创建组件

首先，让我们导入组件装饰器：

```ts
import { Component } from '@angular/core';
```

然后为你的组件创建类：

```ts
class AppComponent {
 title:string = 'hello app';
}
```

然后使用`Component`装饰器装饰你的类：

```ts
@Component({
 selector: 'app',
 template: `<h1>{{ title }}</h1>`
})
export class AppComponent { 
 title: string = 'hello app';
}
```

我们给`Component`装饰器，也就是函数，传入一个对象字面量作为输入参数。这个对象字面量目前包括`selector`和`template`键，所以让我们解释一下它们是什么。

# 选择器

`selector`是在模板中引用时应该使用的名称。我们称之为`app`，我们会这样引用它：

```ts
<app></app>
```

# 模板/templateUrl

`template`或`templateUrl`是您的视图。在这里，您可以编写 HTML 标记。在我们的对象字面量中使用`template`关键字意味着我们可以在与组件类相同的文件中定义 HTML 标记。如果我们使用`templateUrl`，那么我们将在一个单独的文件中放置我们的 HTML 标记。

上面的示例还列出了标记中的双大括号：

```ts
<h1>{{ title }}</h1>
```

这将被视为插值，表达式将被替换为`AppComponent`的`title`字段的值。因此，渲染时，组件将如下所示：

```ts
hello app
```

# 告诉模块

现在我们需要引入一个全新的概念，一个 Angular 模块。在 Angular 中创建的所有类型的构造都应该在模块中注册。Angular 模块充当对外界的门面，它只是一个由`@NgModule`装饰的类。就像`@Component`装饰器一样，`@NgModule`装饰器以对象字面量作为输入参数。为了将我们的组件注册到 Angular 模块中，我们需要给对象字面量添加`declarations`属性。`declarations`属性是一个数组类型，通过将我们的组件添加到该数组中，我们就将其注册到了 Angular 模块。

以下代码显示了创建一个 Angular 模块以及将组件注册到其中的过程，通过将其添加到`declarations`关键字数组中：

```ts
import { AppComponent } from './app.component';

@NgModule({ 
  declarations: [AppComponent] 
})
export class AppModule {}
```

此时，我们的 Angular 模块已经知道了这个组件。我们需要在我们的模块中添加一个属性`bootstrap`。`bootstrap`关键字表示这里放置的任何内容都作为整个应用程序的入口组件。因为目前我们只有一个组件，所以将我们的组件注册到这个`bootstrap`关键字是有意义的：

```ts
@NgModule({
 declarations: [AppComponent],
  bootstrap: [AppComponent]
})
export class AppModule {}
```

确实可以有多个入口组件，但通常情况下只有一个。

然而，对于任何未来的组件，我们只需要将它们添加到`declarations`属性中，以确保模块知道它们。

到目前为止，我们已经创建了一个组件和一个 Angular 模块，并将组件注册到了该模块。但我们还没有一个可工作的应用程序，因为我们还需要采取一步。我们需要设置引导。

# 设置一个引导文件

`main.ts`文件是您的引导文件，它应该具有以下内容：

```ts
import { platformBrowserDynamic } from '@angular/platform-browser-dynamic';
import { AppModule } from './app/app.module';

platformBrowserDynamic().bootstrapModule(AppModule);
```

在前面的代码片段中，我们所做的是将最近创建的模块作为输入参数传递给方法调用`bootstrapModule()`。这将有效地使该模块成为应用程序的入口模块。这就是我们创建一个工作应用程序所需的全部。让我们总结一下我们所采取的步骤：

1.  创建一个组件。

1.  创建一个模块，并在其声明属性中注册我们创建的组件。

1.  还要在模块的 bootstrap 属性中注册我们的组件，以使其成为应用程序的入口点。我们将来创建的其他组件只需要添加到`declarations`属性中即可。

1.  通过将所创建的模块作为输入参数传递给`bootstrapModule()`方法来引导我们创建的模块。

到目前为止，作为读者的你已经不得不吞下大量的信息，并相信我们的话。别担心，你将有机会在本章以及接下来的章节中更加熟悉组件和 Angular 模块。目前，重点只是让你快速上手，通过提供 Angular CLI 这个强大的工具，向你展示实际上只需要几个步骤就可以将应用程序渲染到屏幕上。

# 深入了解 Angular 组件

我们已经走了很长的路，从第一次接触 TypeScript 到学习如何编写 Angular 组件的基本脚本结构。然而，在跳入更抽象的主题之前，让我们尝试构建另一个组件，这样我们就真正掌握了创建组件的工作原理。

# 组件方法和数据更新

在相同的文件夹中创建一个新的`timer.component.ts`文件，并用以下非常简单的组件基本实现填充它。不要担心增加的复杂性，因为我们将在代码块之后审查每一次更改：

```ts
import { Component } from '@angular/core';

@Component({
 selector: 'timer',
 template: `<h1>{{ minutes }}:{{ seconds }} </h1>>`
})
export class TimerComponent {
 minutes: number;
 seconds: number;

 constructor(){
 this.minutes = 24;
 this.seconds = 59;
 }
}
```

到目前为止，我们通过创建`TimerComponent`类并用`@Component`装饰它，创建了一个全新的组件，就像我们在之前的部分学到的那样。我们在之前的部分学到，还有更多要做的，即告诉 Angular 模块这个新组件存在。Angular 模块已经创建好了，所以你只需要将我们的新组件添加到它的`declarations`属性中，就像这样：

```ts
@NgModule({
 declarations: [
 AppComponent, TimerComponent
 ],
 bootstrap: [AppComponent]
})
```

只要我们只有`AppComponent`，我们并没有真正看到拥有一个 Angular 模块的意义。有了两个组件在我们的模块中注册，这一点就改变了。当一个组件与 Angular 模块注册时，它就可以被模块中的其他构造使用。它可以被它们的`template/templateUrl`使用。这意味着我们可以在`AppComponent`中渲染`TimerComponent`。

因此，让我们回到我们的`AppComponent`文件，并更新其模板以显示这一点：

```ts
@Component({
 selector: 'app',
 template: `<h1>{{ title }}</h1> <timer></timer>`
})
export class AppComponent { 
 title: string = 'hello app';
}
```

在前面的代码中，我们用粗体突出显示了如何将`TimerComponent`添加到`AppComponents`模板中。或者我们通过其`selector`属性名称`timer`来引用`TimerComponent`。

让我们再次展示`TimerComponent`，并且突出显示`selector`属性，因为这是一个非常重要的事情要理解；也就是说，如何将一个组件放置在另一个组件中：

```ts
import { Component } from '@angular/core';

@Component({
  selector: 'timer',
 template: `<h1>{{ minutes }}:{{ seconds }} </h1>>`
})
export class TimerComponent {
 minutes: number;
 seconds: number;

 constructor(){
 this.minutes = 24;
 this.seconds = 59;
 }
}
```

我们想要做的不仅仅是显示一些数字，对吧？我们实际上希望它们代表一个倒计时，我们可以通过引入这些更改来实现这一点。让我们首先引入一个我们可以迭代的函数，以便更新倒计时。在构造函数之后添加这个函数：

```ts
tick() {
 if(--this.seconds < 0) {
 this.seconds = 59;
 if(--this.minutes < 0) {
 this.minutes = 24;
 this.seconds = 59;
 }
 }
}
```

Angular 中的选择器是区分大小写的。正如我们将在本书的后面看到的那样，组件是指令的一个子集，可以支持各种选择器。在创建组件时，我们应该通过强制使用破折号命名约定在`selector`属性中设置一个自定义标签名称。在视图中呈现该标记时，我们应该始终将标记关闭为非 void 元素。因此，`<custom-element></custom-element>`是正确的，而`<custom-element />`将触发异常。最后但同样重要的是，某些常见的驼峰命名可能会与 Angular 实现发生冲突，因此应避免使用它们。

# 从静态到实际数据

正如你在这里看到的，TypeScript 中的函数需要用它们返回的值的类型进行注释，或者如果没有值，则只需使用 void。我们的函数评估了分钟和秒钟的当前值，然后要么减少它们的值，要么将其重置为初始值。然后通过从类构造函数触发时间间隔来每秒调用此函数：

```ts
constructor() {
 this.minutes = 24;
 this.seconds = 59;
 setInterval(() => this.tick(), 1000);
}
```

在这里，我们在我们的代码中第一次发现了箭头函数（也称为 lambda 函数，fat arrow 等），这是 ECMAScript 6 带来的新的函数语法，我们将在第三章中更详细地介绍它，*介绍 TypeScript*。`tick`函数也被标记为私有，因此它不能在`PomodoroTimerComponent`对象实例之外被检查或执行。

到目前为止一切顺利！我们有一个工作中的番茄工作计时器，从 25 分钟倒数到 0，然后重新开始。问题是我们在这里和那里复制了代码。因此，让我们稍微重构一下，以防止代码重复：

```ts
constructor() {
 this.reset();
 setInterval(() => this.tick(), 1000);
}

reset() {
 this.minutes = 24;
 this.seconds = 59;
}

private tick() {
 if(--this.seconds < 0) {
 this.seconds = 59;
 if(--this.minutes < 0) {
 this.reset();
 }
 }
}
```

我们已经将分钟和秒的初始化（和重置）包装在我们的`resetPomodoro`函数中，该函数在实例化组件或倒计时结束时被调用。不过等一下！根据番茄工作法，番茄工作者可以在番茄工作时间之间休息，甚至在意外情况发生时暂停。我们需要提供某种交互性，以便用户可以启动、暂停和恢复当前的番茄工作计时器。

# 向组件添加交互性

Angular 通过声明式接口提供了一流的事件支持。这意味着很容易连接事件并将其指向方法。将数据绑定到不同的 HTML 属性也很容易，你即将学到。

首先修改我们的模板定义：

```ts
@Component({
 selector: 'timer',
 template: `
 <h1>{{ minutes }}: {{ seconds }} </h1>
 <p>
 <button (click)="togglePause()"> {{ buttonLabel }}</button>
 </p>
 `
})
```

我们使用了多行文本字符串！ECMAScript 6 引入了这个概念。

模板字符串，它是支持嵌入表达式、插入文本绑定和多行内容的字符串文字。我们将在第三章中更详细地了解它们，*介绍 TypeScript*。

与此同时，只需专注于我们引入了一个新的 HTML 块，其中包含一个带有事件处理程序的按钮，该处理程序监听点击事件并在点击时执行`togglePause()`方法。这个`(click)`属性可能是你以前没有见过的，尽管它完全符合 W3C 标准。再次强调，我们将在第四章中更详细地介绍这个内容，*在我们的组件中实现属性和事件*。让我们专注于`togglePause()`方法和新的`buttonLabel`绑定。首先，让我们修改我们的类属性，使其看起来像这样：

```ts
export class TimerComponent {
 minutes: number;
 seconds: number;
 isPaused: boolean;
 buttonLabel: string;
 // rest of the code will remain as it is below this point
}
```

我们引入了两个新字段。第一个是`buttonLabel`，其中包含稍后将显示在我们新创建的按钮上的文本。`isPaused`是一个新创建的变量，将根据计时器的状态而假设一个`true`/`false`值。因此，我们可能需要一个地方来切换这个字段的值。让我们创建我们之前提到的`togglePause()`方法：

```ts
togglePause() {
 this.isPaused = !this.isPaused;
 // if countdown has started
 if(this.minutes < 24 || this.seconds < 59) {
 this.buttonLabel = this.isPaused ? 'Resume' : 'Pause';
 }
}
```

简而言之，`togglePause()`方法只是将`isPaused`的值切换到相反的状态，然后根据这样一个新值以及计时器是否已启动（这将意味着任何时间变量的值低于初始化值）或者没有，我们为按钮分配不同的标签。

现在，我们需要初始化这些值，似乎没有比这更好的地方。因此，`reset()`函数是初始化影响我们类状态的变量的地方：

```ts
reset() {
 this.minutes = 24;
 this.seconds = 59;
 this.buttonLabel = 'Start';
 this.togglePause();
}
```

每次执行`togglePause()`时，我们都会重置它，以确保每当它达到需要重置的状态时，倒计时行为将切换到先前的相反状态。控制倒计时的控制器方法中只剩下一个调整：

```ts
private tick() {
 if(!this.isPaused) {
 this.buttonLabel = 'Pause';
 if(--this.seconds < 0) {
 this.seconds = 59;
 if(--this.minutes < 0) {
 this.reset();
 }
 }
 }
}
```

显然，当计时器应该暂停时，我们不希望倒计时继续，因此我们将整个脚本包装在一个条件中。除此之外，当倒计时没有暂停时，我们将希望在按钮上显示不同的文本，并且当倒计时达到结束时再次显示；停止然后重置 Pomodoro 到其初始值将是预期的行为。这加强了在`resetPomodoro`中调用`togglePause`函数的必要性。

# 改进数据输出

到目前为止，我们已经重新加载了浏览器，并尝试了新创建的切换功能。然而，显然还有一些需要一些润色的地方：当秒表显示的秒数小于 10 时，它显示的是一个单个数字，而不是我们在数字时钟和手表中习惯看到的两位数。幸运的是，Angular 实现了一组声明性辅助工具，可以格式化我们模板中的数据输出。我们称它们为管道，我们将在第四章中详细介绍它们，*在我们的组件中实现属性和事件*。目前，让我们在我们的组件模板中引入数字管道，并将其配置为始终显示两位数的秒数输出。更新我们的模板，使其看起来像这样：

```ts
@Component({
 selector: 'timer',
 template: `
 <h1>{{ minutes }}: {{ seconds | number: '2.0' }}</h1>
 <p>
 <button (click)="togglePause()">{{ buttonLabel }}</button>
 </p>
 `
})
```

基本上，我们在模板中的插值绑定后面加上了管道名称，用管道（`|`）符号分隔，因此得名。重新加载模板，您将看到秒数始终显示两位数，而不管它所代表的值如何。

我们已经创建了一个完全功能的番茄工作法定时器小部件，我们可以重复使用或嵌入到更复杂的应用程序中。第六章，*使用 Angular 组件构建应用程序*，将指导我们在更大的组件树的上下文中嵌入和嵌套我们的组件的过程。

与此同时，让我们添加一些 UI 美化，使我们的组件更具吸引力。我们已经在按钮标签中引入了一个 class 属性，以期待在项目中实现 Bootstrap CSS 框架。让我们导入通过 npm 安装项目依赖时下载的实际样式表。打开`timer.html`，并在`<head>`元素的末尾添加以下片段：

```ts
<link href="http://maxcdn.bootstrapcdn.com/bootstrap/3.3.6/CSS/bootstrap.min.CSS" rel="stylesheet" integrity="sha384-1q8mTJOASx8j1Au+a5WDVnPi2lkFfwwEAa8hDDdjZlpLegxhjVME1fgjWPGmkzs7" crossorigin="anonymous">
```

现在，让我们通过在我们的组件之前插入一个漂亮的页面标题来美化我们的 UI：

```ts
<body>
 <nav class="navbar navbar-default navbar-static-top">
 <div class="container">
 <div class="navbar-header">
 <strong class="navbar-brand">My Timer</strong>
 </div>
 </div>
 </nav>
</body>
```

调整组件按钮的 Bootstrap 按钮类将赋予它更多个性，将整个模板包裹在一个居中容器中将确实增强 UI。所以让我们更新我们的模板，使其看起来像这样：

```ts
<div class="text-center">
 <img src="assets/img/timer.png" alt="Timer">
 <h1> {{ minutes }}:{{ seconds | number:'2.0' }}</h1>
 <p>
 <button class="btn btn-danger" (click)="togglePause()">{{ buttonLabel }}</button>
 </p>
</div>
```

# 总结

根据现代网络标准，我们研究了 Web 组件以及 Angular 组件如何提供简单直接的 API 来构建我们自己的组件。我们介绍了 TypeScript 及其语法的一些基本特性，作为第三章《介绍 TypeScript》的准备工作。我们看到了如何设置我们的工作空间，以及在哪里找到我们需要的依赖项，将 TypeScript 引入项目并在项目中使用 Angular 库，了解了每个依赖项在我们应用程序中的作用。

我们的第一个组件教会了我们创建组件的基础知识，也让我们更加熟悉另一个重要概念，Angular 模块，以及如何引导应用程序。我们的第二个组件让我们有机会讨论控制器类的形式，其中包含属性字段、构造函数和实用函数，以及为什么元数据注解在 Angular 应用程序的上下文中如此重要，以定义我们的组件将如何在其所在的 HTML 环境中集成。我们的第一个 Web 组件具有自己的模板，这些模板以变量插值的形式声明性地托管属性绑定，通过管道方便地格式化。绑定事件监听器现在比以往任何时候都更容易，其语法符合标准。

下一章将详细介绍我们需要了解的所有 TypeScript 特性，以便迅速掌握 Angular。


# 第二章：IDE 和插件

在继续我们对 Angular 的旅程之前，是时候看看 IDE 了。当涉及到进行敏捷工作流程时，我们最喜欢的代码编辑器可以成为无与伦比的盟友，其中包括运行时的 TypeScript 编译、静态类型检查和内省，以及代码完成和可视化辅助调试和构建我们的应用程序。话虽如此，让我们重点介绍一些主要的代码编辑器，并概览它们在开发 Angular 应用程序时如何帮助我们。如果您只是满足于从命令行触发 TypeScript 文件的编译，并且不想获得可视化的代码辅助，请随意跳到下一节。否则，直接跳转到涵盖您选择的 IDE 的下一节。

在这一章中，您将学习以下内容：

+   最常见的编辑器

+   安装和配置插件以提高您的生产力

+   了解一些代码片段，这些代码片段将使您成为一个更快的编码人员，因为它们为您提供了最常见情况下的现成代码。

# IDE

**集成开发环境**（**IDE**）是我们用来指代比记事本或简单编辑器更强大的东西的术语。编写代码意味着我们有不同的要求，如果我们要写一篇文章的话。编辑器需要能够指示我们输入错误，为我们提供有关我们的代码的见解，或者最好是给我们所谓的自动完成，一旦我们开始输入其开头字母，它就会给我们一个方法列表。编码编辑器可以而且应该是您最好的朋友。对于前端开发，有很多很好的选择，没有哪个环境真的比其他环境更好；这取决于哪种对您最有效。让我们踏上发现之旅，让您来判断哪种环境最适合您。

# Atom

由 GitHub 开发，高度可定制的环境和安装新包的便利性已经使 Atom 成为许多人的首选 IDE。

为了在编写 Angular 应用程序时优化 TypeScript 的体验，您需要安装 Atom TypeScript 包。您可以通过 APM CLI 安装，也可以使用内置的包安装程序。包含的功能与在安装了 Microsoft 包后在 Sublime 中的功能基本相同：自动代码提示、静态类型检查、代码内省或保存时自动构建等。除此之外，该包还包括一个方便的内置`tsconfig.json`生成器。

# Sublime Text 3

这可能是当今最广泛使用的代码编辑器之一，尽管最近失去了一些动力，用户更青睐其他新兴竞争对手，如 GitHub 自己的 Atom。如果这是您的首选编辑器，我们将假设它已经安装在您的系统上，并且您还安装了 Node（这是显而易见的，否则，您首先无法通过 NPM 安装 TypeScript）。为了提供对 TypeScript 代码编辑的支持，您需要安装微软的 TypeScript 插件，可在[`github.com/Microsoft/TypeScript-Sublime-Plugin`](https://github.com/Microsoft/TypeScript-Sublime-Plugin)上找到。请参考此页面以了解如何安装插件以及所有快捷键和键映射。

安装成功后，只需按下*Ctrl* + Space Bar 即可根据类型内省显示代码提示。除此之外，我们还可以通过按下*F7*功能键触发构建过程，并将文件编译为我们正在工作的 JavaScript。实时代码错误报告是另一个可以从命令菜单中启用的花哨功能。

# Webstorm

这款由 IntelliJ 提供的优秀代码编辑器也是基于 TypeScript 编写 Angular 应用程序的不错选择。该 IDE 内置支持 TypeScript，因此我们可以从第一天开始开发 Angular 组件。WebStorm 还实现了一个内置的转译器，支持文件监视，因此我们可以将 TypeScript 代码编译为纯粹的 JavaScript，而无需依赖任何第三方插件。

# Visual Studio Code

由 Microsoft 支持的代码编辑器 Visual Studio Code 正在成为 Angular 中的一个严肃竞争者，主要是因为它对 TypeScript 的出色支持。TypeScript 在很大程度上是由 Microsoft 推动的项目，因此有意为其流行的编辑器之一内置对该语言的支持是有道理的。这意味着我们可能想要的所有不错的功能已经内置，包括语法和错误高亮显示以及自动构建。

使 Visual Studio 变得如此出色的真正原因不仅仅是其设计和易用性，还有许多插件可供选择，对于 Angular 开发来说有一些非常棒的插件，让我们来看看其中的一些领先者。

**Angular 语言服务**：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-2e/img/beaf36e8-c44d-498b-8ad7-b4aad4192b3e.png)

通过搜索`Angular 语言`，您可以获得与之匹配的插件列表。安装排在前面的插件。

完成后，您将通过以下方式丰富 Visual Studio Code：

+   代码完成

+   转到定义

+   快速信息

+   AOT 诊断消息

只是为了演示其能力，让我们像这样向我们的代码添加一个描述字段：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-2e/img/be374058-91ea-4410-9697-71da7b955bdd.png)

现在让我们编辑模板，并意识到我们在模板中有代码完成：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-2e/img/11f0c2af-6656-4b10-9e2c-401c1e3c6259.png)

当我们开始输入时，会显示一个视觉指示器，并为我们提供完成单词的选项，如果我们选择建议的文本。另一个强大的功能是支持悬停在字段名称上，单击它，然后转到它所属的组件类。这使得快速查找定义变得非常容易。这被称为*转到定义*功能。要使用该功能，您只需悬停在名称上，然后在 Mac 上按住命令按钮。正如前面所述，非常简单，非常强大。

**Typescript Hero**：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-2e/img/ac5874d4-f448-4ae9-a9d1-f214eb4f512d.png)

要使用此插件，只需像这样开始编码，并单击左侧的灯泡图标，以自动将导入添加到您的文件中：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-2e/img/091d180e-eca9-4722-98a6-5baa9654f2c8.png)

具有体面的代码完成和导入是必不可少的，除非您喜欢磨损手指。还有一些代码片段和代码片段，可以让您的编码速度更快。

**Angular 5 Typescript 代码片段（Dan Wahlin，John Papa）**：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-2e/img/b1e3ff62-892e-4db0-a780-b71714421b7d.png)

这是一个非常强大的插件。它带有三种不同类型的代码片段：

+   Angular 片段

+   RxJS 片段

+   HTML 片段

它的工作方式如下。输入一个片段快捷方式，当被要求时按*Enter*，代码将被添加：

```ts
a-component
```

按*Enter*将得到以下代码：

```ts
import { Component, OnInit } from '@Angular/core';

@Component({
 selector: 'selector-name',
 templateUrl: 'name.component.html'
})
export class NameComponent implements OnInit {
 constructor() {}

 ngOnInit(){}
}
```

正如你所看到的，你几乎不费吹灰之力就能得到大量的代码。总共有 42 个片段，它们都列在 Visual Studio 的插件描述中。

还有很多插件，但这些将在刚开始时产生真正的影响。这一切都是关于高效生产，而不是浪费时间输入不必要的字符。

# 总结

本章的重点是试图让你作为软件开发者更有能力。编辑器有很多选择，其中一些我们选择了更详细地介绍。还有许多插件和片段可以节省不少按键。归根结底，你的重点和精力应该花在解决问题和构建解决方案上，而不是让手指累坏。当然，你可以下载更多的插件、片段和快捷方式，但这些是一个很好的开始。我们鼓励你更多地了解你的编辑器及其可能性，因为这将使你更快速、更高效。

在下一章中，你将学习有关 Typescript 的所有内容，从基础到专业水平。本章将涵盖引入类型解决了什么问题，以及语言结构本身。Typescript 作为 JavaScript 的超集，包含了许多强大的概念，并且与 Angular 框架非常契合，你即将发现。


# 第三章：介绍 TypeScript

在上一章中，我们构建了我们的第一个组件，并使用 TypeScript 来塑造代码脚本，从而赋予其形式。本书中的所有示例都使用其语法。正如我们将在本书中看到的，使用 TypeScript 编写我们的脚本并利用其静态类型将使我们在其他脚本语言上具有显着优势。

本章不是对 TypeScript 语言的全面概述。我们将只关注语言的核心元素，并在我们学习 Angular 的过程中详细研究它们。好消息是，TypeScript 并不那么复杂，我们将设法涵盖它的大部分相关部分。

在本章中，我们将：

+   看看 TypeScript 背后的背景和原理

+   发现在线资源，练习学习

+   回顾类型化值的概念以及如何表示它们

+   构建我们自己的类型，基于类和接口

+   学会更好地组织我们的应用架构与模块

# 理解 TypeScript 的案例

早期 JavaScript 驱动的小型 Web 应用程序的自然演变

将厚重的单片客户端揭示了 ECMAScript 5 JavaScript 规范的缺陷。简而言之，一旦规模和复杂性增加，大规模 JavaScript 应用程序就会遭受严重的可维护性和可扩展性问题。

随着新的库和模块需要无缝集成到我们的应用程序中，这个问题变得更加重要。缺乏良好的互操作机制导致了一些非常繁琐的解决方案，似乎从未符合要求。

作为对这些问题的回应，ECMAScript 6（也称为 ES6 或 ES2015）承诺通过引入更好的模块加载功能、改进的语言架构以更好地处理作用域，并引入各种语法糖来更好地管理类型和对象，来解决这些可维护性和可扩展性问题。基于类的编程的引入成为了在构建大规模应用程序时采用更 OOP 方法的机会。

微软接受了这一挑战，花了近两年的时间构建了一种语言的超集，结合了 ES6 的约定，并借鉴了 ES7 的一些提案。其想法是推出一些有助于通过静态类型检查、更好的工具和代码分析来构建企业应用程序的东西，以际降低错误率。

在由 C#首席架构师 Anders Hejlsberg 领导的两年开发之后，TypeScript 0.8 终于在 2012 年推出，并在两年后达到了 1.0 版本。TypeScript 不仅领先于 ECMAScript 6，而且还实现了相同的功能，并通过类型注释引入了可选的静态类型，从而确保了编译时的类型检查。这有助于在开发过程的早期阶段捕获错误。声明文件的支持也为开发人员提供了描述其模块接口的机会，以便其他开发人员可以更好地将其集成到其代码工作流程和工具中。

# TypeScript 的好处

以下信息图提供了对不同功能的俯视。

区分 ECMAScript 6 和 ECMAScript 5，然后区分 TypeScript 与这两者。

作为 ECMAScript 6 的超集，采用 TypeScript 在下一个项目中的主要优势之一是低入门门槛。如果你了解 ECMAScript 6，那么你几乎已经具备了一切，因为 TypeScript 中的所有附加功能都是可选的。你可以选择并引入在实践中帮助你实现目标的功能。总的来说，有很多有力的论点支持在下一个项目中倡导使用 TypeScript，所有这些显然也适用于 Angular。以下是一些论点的简要概述，仅举几例：

+   用类型注释我们的代码可以确保不同代码单元的一致集成，并提高代码的可读性和理解性。

+   TypeScript 的内置类型检查器将在运行时分析您的代码，并帮助您在执行代码之前防止错误。

+   使用类型可以确保应用程序的一致性。与前两者结合使用，从长远来看，整体代码错误的印记得到最小化。

+   TypeScript 通过类字段、私有成员、枚举等长期需求的功能扩展了类。

+   使用装饰器为我们打开了以前无法企及的方式来扩展我们的类和实现。

+   创建接口和类型定义文件（本书不涉及）确保了我们的库在其他系统和代码库中的平稳无缝集成。

+   TypeScript 在商店中不同 IDE 的支持非常好，我们可以从代码高亮、实时类型检查和自动编译中受益，而且没有任何成本。

+   TypeScript 的语法肯定会让来自其他背景（如 Java、C＃、C ++等）的开发人员感到满意。

# 在野外介绍 TypeScript 资源

现在，我们将看看在哪里可以获得更多支持来学习和测试我们对 TypeScript 的新知识。

# TypeScript 官方网站

显然，我们首先要去官方网站了解这门语言：[`www.typescriptlang.org`](http://www.typescriptlang.org)。在那里，我们可以找到更详尽的语言介绍以及 IDE 和企业支持者的链接。然而，我们肯定会经常回顾的最重要部分是学习部分和 play 沙盒。

学习部分为我们提供了快速教程，让我们迅速掌握这门语言。这可能是对我们在上一章讨论的内容的一个回顾，但我们建议您跳过它，转而查看示例页面和语言规范，后者是指向 GitHub 上语言完整广泛文档的直接链接。这对新用户和有经验的用户都是无价的资源。

play 部分提供了一个方便的沙盒，包括一些现成的代码示例，涵盖了语言的一些最常见特性。我们鼓励您利用这个工具来测试我们在本章中将看到的代码示例。

# TypeScript 官方 wiki

在上一章中，当我们谈到使用 TypeScript 编译器 API 执行命令时，我们提到了 TypeScript 的 wiki 中最基本的参数。

TypeScript 的代码完全开源在 GitHub 上，微软团队在存储库网站上提供了对代码不同方面的良好文档。我们鼓励您随时查看，如果您有问题或想深入了解语言特性或语法方面的任何内容。

wiki 位于：[`github.com/Microsoft/TypeScript/wiki`](https://github.com/Microsoft/TypeScript/wiki)。

# TypeScript 中的类型

使用 TypeScript 或任何其他编程语言基本上意味着使用数据，这些数据可以表示不同类型的内容。这就是我们所知的类型，一个用来表示这样的数据可以是文本字符串、整数值或这些值类型的数组等的名词。这对 JavaScript 来说并不新鲜，因为我们一直在隐式地使用类型，但是以一种灵活的方式。这意味着任何给定的变量都可以假定（或返回，在函数的情况下）任何类型的值。有时，这会导致我们的代码出现错误和异常，因为我们的代码返回的类型与我们期望的类型发生了冲突。虽然这种灵活性仍然可以通过我们将在本章后面看到的任何类型来强制执行，但是静态地为我们的变量标注类型可以给我们和我们的 IDE 提供一个很好的图片，说明我们应该在每个代码实例中找到什么样的数据。这成为在编译时帮助我们调试应用程序的无价方式，而不至于为时已晚。要调查语言特性的工作原理，我建议您使用游乐场，有两个原因。第一个原因是学习该功能的工作原理。第二个原因是了解它产生的相应的 ES5 代码。我建议使用以下游乐场进行此操作：[`www.typescriptlang.org/play/.`](https://www.typescriptlang.org/play/)

# 字符串

我们代码中可能最广泛使用的原始类型之一将是字符串类型，我们用一段文本填充一个变量。

```ts
var brand: string = 'Chevrolet';
```

检查变量名称旁边的类型赋值，用冒号符号分隔。这就是我们在 TypeScript 中注释类型的方式，就像我们在上一章中看到的那样。

回到字符串类型，我们可以使用单引号或双引号，与 ECMAScript6 相同。我们可以使用相同类型定义支持文本插值的多行文本字符串，使用占位变量：

```ts
var brand: string = 'Chevrolet';
var message: string = `Today it's a happy day! I just bought a new ${brand} car`;
```

# 声明我们的变量 - ECMAScript 6 的方式

TypeScript 作为 ECMAScript 6 的超集，支持表达性声明名词，比如`let`，它告诉我们变量的作用域是最近的封闭块（函数`for`循环或任何封闭语句）。另一方面，`const`是一个指示，这种方式声明的值一旦被填充就应该始终具有相同的类型或值。在本章的其余部分，我们将强制使用传统的`var`符号来声明变量，但请记住在适当的地方使用`let`和`const`。

# let 关键字

在代码中的许多情况下，我一直在使用`var`来声明对象、变量和其他构造。但是在 ES6 或 TypeScript 中开始时，这是不被鼓励的。这是有原因的，因为 ES5 只有方法作用域。对于大多数从其他语言转到 JavaScript 的开发人员来说，这可能有点震惊。首先，我们所说的函数作用域是什么意思？我们的意思是变量在函数的上下文中是唯一的，就像这样：

```ts
function test() {
 var a;
}
```

在该函数中不能有其他变量`a`。如果你声明了更多的变量，那么你将有效地重新定义它。好的，但是什么时候作用域不起作用呢？例如，在`for`-循环中就没有作用域。在 Java 中，你会这样写：

```ts
for (int i = 0; i < arr.length; i++) {
}
```

在 Java 中，你会知道变量`i`永远不会泄漏到`for`-循环之外，你可以这样写：

```ts
int i = 3;
for (int i = 0; i < arr.length; i++) {
}
```

并且要知道`for`-循环之外的变量`i`不会影响`for`-循环内的变量`i`，它们会被分隔或作用域化，就像它被称为的那样。好的，所以 ES5 JavaScript 的用户已经有了这个语言缺陷很长时间了，最近 ES6 和 Typescript 分别添加了一个修复这个问题的方法，即`let`关键字。像这样使用它：

```ts
let i = 3;
for (let i = 0; i < arr.length; i++) {
}
```

这样运行的原因是 TypeScript 编译器将其转换为以下 ES5 代码：

```ts
var i = 3;
for (var i_1 = 0; i_1 < arr.length; i_1++) {
}
```

编译器基本上会在`for`-循环中重新命名变量，以防发生名称冲突。所以记住，不再使用`var`，当有疑问时只需使用`let`关键字。

# Const

`const`关键字是一种方式，让你传达这些数据永远不应该被改变。随着代码库的增长，很容易发生错误的更改；这样的错误可能是代价高昂的。为了在编译时支持这一点，`const`关键字可以帮助你。以以下方式使用它：

```ts
const PI = 3.14;
PI = 3 // not allowed
```

编译器甚至会指出不允许这样做，并显示以下消息：

```ts
Cannot assign to PI because it is a constant or a read-only property
```

这里需要注意一点：这仅适用于顶层。如果您将对象声明为`const`，则需要注意这一点：

```ts
const obj = {
 a : 3
}
obj.a = 4; // actually allowed
```

声明`obj`为`const`并不会冻结整个对象，而是`obj`指向的内容。因此，以下内容将不被允许：

```ts
obj = {}
```

在这里，我们积极改变了`obj`指向的内容，而不是它的一个子属性，因此这是不允许的，你会得到与之前相同的编译错误。

# 数字

数字可能是除了字符串和布尔值之外最常见的原始数据类型。与 JavaScript 一样，数字定义了浮点数。数字类型还定义了十六进制、十进制、二进制和八进制文字：

```ts
var age: number = 7;
var height: number = 5.6;
```

# 布尔值

布尔类型定义了可以是`True`或`False`的数据，表示条件的满足：

```ts
var isZeroGreaterThanOne: boolean = false;
```

# 数组

将错误的成员类型分配给数组，并处理由此引起的异常，现在可以通过`Array`类型轻松避免，我们在其中描述了仅包含某些类型的数组。语法只需要在类型注释中使用`后缀[]`，如下所示：

```ts
var brand: string[] = ['Chevrolet', 'Ford', 'General Motors'];
var childrenAges: number[] = [8, 5, 12, 3, 1];
```

如果我们尝试向`childrenAges`数组添加一个类型不是数字的新成员，运行时类型检查器将抱怨，确保我们的类型成员保持一致，我们的代码是无错误的。

# 使用 any 类型的动态类型

有时，很难根据我们在某一时刻拥有的信息推断数据类型，特别是当我们将遗留代码移植到 TypeScript 或集成松散类型的第三方库和模块时。不用担心，TypeScript 为我们提供了一个方便的类型来处理这些情况。`any`类型与所有其他现有类型兼容，因此我们可以使用它对任何数据值进行类型标注，并在以后分配任何值给它。然而，这种强大的功能也伴随着巨大的责任。如果我们绕过静态类型检查的便利，我们就会在通过我们的模块传递数据时打开类型错误的大门，我们将需要确保整个应用程序的类型安全：

```ts
var distance: any;
// Assigning different value types is perfectly fine
distance = '1000km':
distance = '1000'
// Allows us to seamlessly combine different types
var distance: any[] = ['1000km', '1000'];
```

空值和未定义的 JavaScript 文字需要特别提到。简而言之，它们在`any`类型下进行了类型化。这样以后就可以将这些文字分配给任何其他变量，而不管其原始类型如何。

# 自定义类型

在 Typescript 中，如果需要，您可以使用以下方式使用`type`关键字自定义类型：

```ts
type Animal = 'Cheetah' | 'Lion';
```

现在我们创建的是一个具有*x*个允许值的类型。让我们从这种类型创建一个变量：

```ts
var animal: Animal = 'Cheetah';
```

这是完全允许的，因为 `Cheetah` 是允许的值之一，并且按预期工作。有趣的部分发生在我们给变量赋予它不期望的值时：

```ts
var animal: Animal = 'Turtle';
```

这导致了以下编译器错误：

```ts
error TS2322: Type '"Turtle"' is not assignable to type 'Animal'.
```

# Enum

Enum 基本上是一组唯一的数值，我们可以通过为每个数值分配友好的名称来表示它们。枚举的用途不仅限于为数字分配别名。我们可以将它们用作以方便和可识别的方式列出特定类型可以假定的不同变化的方法。

枚举使用 `enum` 关键字声明，不使用 `var` 或任何其他变量声明名词，并且它们从 0 开始编号成员，除非为它们分配了显式的数值：

```ts
enum Brands { Chevrolet, Cadillac, Ford, Buick, Chrysler, Dodge };
var myCar: Brands = Brands.Cadillac;
```

检查 `myCar` 的值将返回 `1`（这是 `enum` 中 `Cadillac` 所持有的索引）。正如我们已经提到的，我们可以在 `enum` 中分配自定义数值：

```ts
enum BrandsReduced { Tesla = 1, GMC, Jeep };
var myTruck: BrandsReduced = BrandsReduced.GMC;
```

检查 `myTruck` 将产生 `2`，因为第一个枚举值已经设置为 `1`。只要这些值是整数，我们就可以将值分配给所有的 `enum` 成员：

```ts
enum StackingIndex {
 None = 0,
 Dropdown = 1000,
 Overlay = 2000,
 Modal = 3000
};
var mySelectBoxStacking: StackingIndex = LayerStackingIndex.Dropdown;
```

最后值得一提的一个技巧是查找与给定数值映射的枚举成员的可能性：

```ts
enum Brands { Chevrolet, Cadillac, Ford, Buick, Chrysler, Dodge };
var MyCarBrandName: string = Brands[1];
```

应该提到的是，从 TypeScript 2.4 开始，可以将字符串值分配给枚举。

# Void

`void` 类型确实表示任何类型的缺失，其使用受限于注释不返回实际值的函数。因此，也没有返回类型。我们已经有机会在上一章中通过一个实际例子看到这一点：

```ts
resetPomodoro(): void {
 this.minutes = 24;
 this.seconds = 59;
}
```

# 类型推断

对我们的数据进行类型标注是可选的，因为 TypeScript 足够聪明，可以在上下文中推断出变量和函数返回值的数据类型，并且具有一定的准确性。当无法进行类型推断时，TypeScript 将以动态的 any 类型分配给松散类型的数据，以减少类型检查的成本。

推断工作的一个例子可以在以下代码中看到：

```ts
var brand = 'Chevrolet';
```

这具有相同的效果，也就是说，如果您尝试将不兼容的数据类型分配给它，它将导致编译错误，就像这样：

```ts
var brand: string = 'Chevrolet';
var brand2 = 'Chevrolet';
brand = false; // compilation error
brand = 114; // compilation error
```

# 函数、lambda 和执行流

与 JavaScript 一样，函数是处理机器，我们在其中分析输入，消化信息，并对提供的数据应用必要的转换，以便转换我们应用程序的状态或返回一个输出，该输出将用于塑造我们应用程序的业务逻辑或用户交互。

TypeScript 中的函数与普通 JavaScript 并没有太大的区别，除了函数本身以及 TypeScript 中的其他所有内容一样，可以用静态类型进行注释，因此，它们更好地通知编译器它们在签名中期望的信息以及它们的返回数据类型（如果有的话）。

# 在我们的函数中注释类型

以下示例展示了在 TypeScript 中如何注释常规函数：

```ts
function sayHello(name: string): string {
 return 'Hello, ' + name;
}
```

我们可以清楚地看到与普通 JavaScript 中的常规函数语法有两个主要区别。首先，在函数签名中注释了参数的类型信息。这是有道理的，因为编译器将希望检查在执行函数时提供的数据是否具有正确的类型。除此之外，我们还通过在函数声明中添加后缀字符串来注释返回值的类型。在这些情况下，给定的函数不返回任何值，类型注释 void 将为编译器提供所需的信息，以进行适当的类型检查。

正如我们在前一节中提到的，TypeScript 编译器足够聪明，可以在没有提供注释时推断类型。在这种情况下，编译器将查看提供的参数和返回语句，以推断返回类型。

TypeScript 中的函数也可以表示为匿名函数的表达式，我们将函数声明绑定到一个变量上：

```ts
var sayHello = function(name: string): string {
 return 'Hello, ' + name;
}
```

然而，这种语法也有一个缺点。虽然允许以这种方式对函数表达式进行类型化，但由于类型推断，编译器在声明的变量中缺少类型定义。我们可能会假设指向类型为字符串的函数的变量的推断类型显然是字符串。但事实并非如此。指向匿名函数的变量应该用函数类型进行注释。基本上，函数类型通知了函数负载中期望的类型以及函数执行返回的类型（如果有的话）。这整个块，以`(arguments: type) =>`返回类型的形式，成为我们的编译器期望的类型注释：

```ts
var sayHello: (name: string) => string = function(name: string): string {
 return 'Hello, ' + name;
}
```

你可能会问为什么会有这样繁琐的语法？有时，我们会声明可能依赖于工厂或函数绑定的变量。然后，尽可能向编译器提供尽可能多的信息总是一个好习惯。这个简单的例子可能会帮助你更好地理解：

```ts
// Two functions with the same typing but different logic.
function sayHello(input: string): string {
 return 'Hello, ' + input;
}

function sayHi(input: string): string{
 return 'Hi, ' + input;
}

// Here we declare the variable with is own function type
var greetMe: (name: string) => string;
greetMe = sayHello; 
```

这样，我们也确保以后的函数赋值符合在声明变量时设置的类型注解。

# TypeScript 中的函数参数

由于编译器执行的类型检查，TypeScript 中的函数参数需要特别注意。

# 可选参数

参数是 TypeScript 编译器应用的类型检查的核心部分。TypeScript 通过在参数名称后面添加`?`符号来提供可选功能，这允许我们在函数调用中省略第二个参数。

```ts
function greetMe(name: string, greeting?: string): string {
 console.log(greeting);
 if(!greeting) { greeting = 'Hello'; }
 return greeting + ', ' + name;
}

console.log( greetMe('Chris') );
```

这段代码将尝试打印出问候变量，并产生一个合适的问候。像这样运行这段代码：

```ts
greetMe('Chris');
```

将给我们以下结果：

```ts
undefined
Hello Chris
```

因此，可选参数实际上不会被设置，除非你明确地这样做。这更多是一种构造，让你可以帮助决定哪些参数是必需的，哪些是可选的。让我们举个例子：

```ts
function add(mandatory: string, optional?: number) {}
```

你可以以以下方式调用这个函数：

```ts
add('some string');
add('some string', 3.14);
```

两个版本都是允许的。在函数签名中使用可选参数会强制你将它们放在最后，就像前面的例子一样。以下例子说明了什么不应该做：

```ts
function add(optional?: number, mandatory: string) {}
```

这将创建这样一种情况，其中两个参数都是必需的：

```ts
add(11); // error. mandatory parameter missing
```

即使编译器会抱怨并说以下内容：

```ts
A required parameter cannot follow an optional parameter
```

记住，可选参数很好，但要放在最后。

# 默认参数

TypeScript 给了我们另一个功能来应对前面描述的情况，即默认参数，我们可以在执行函数时设置参数的默认值，当没有明确赋值时参数将采用默认值。语法非常简单，我们可以在重构前面的例子时看到：

```ts
function greetMe(name: string, greeting: string = 'Hello'): string {
 return `${greeting}, ${name}`;
}
```

与可选参数一样，默认参数必须放在函数签名中非默认参数的后面。有一个非常重要的区别，就是默认参数总是安全的。为什么它们是安全的，可以从下面的 ES5 代码中看出。下面的 ES5 代码是将上面的 TypeScript 编译为 ES5 得到的结果代码。下面的代码表明编译器添加了一个 IF 子句，检查变量`greeting`是否为 undefined，如果是，则给它一个起始值：

```ts
function greetMe(name, greeting){
 if (greeting === void 0) { greeting = 'Hello'; }

 return greeting + ', ' + name;
}
```

正如你所看到的，编译器添加了一个 if 子句来检查你的值，如果没有设置，它会添加你之前提供的值。

当你处理默认参数时，类型会被推断出来，因为你给它们赋了一个值。在前面的代码片段中，greeting 被赋予字符串值'Hello'，因此被推断为字符串类型。

# 剩余参数

在定义函数时，JavaScript 的灵活性之一是接受以 arguments 对象形式的无限数量的未声明的参数。在 TypeScript 这样的静态类型上下文中，这可能是不可能的，但通过 REST 参数对象实际上是可能的。在这里，我们可以在参数列表的末尾定义一个额外的参数，前面加上省略号(`...`)并且类型为数组：

```ts
function greetPeople(greeting: string, ...names: string[]): string{
 return greeting + ', ' + names.join(' and ') + '!';
}

alert(greetPeople('Hello', 'John', 'Ann', 'Fred'));
```

需要注意的是，剩余参数必须放在参数列表的末尾，不需要时可以省略。让我们看一下生成的 ES5 代码，以了解 TypeScript 编译器生成了什么：

```ts
function greetPeople(greeting) {
 var names = [];
 for (var _i = 1; _i < arguments.length; _i++) {
 names[_i - 1] = arguments[_i];
 }
 return greeting + ', ' + names.join(' and ') + '!';
}

alert(greetPeople('Hello', 'John', 'Ann', 'Fred'));
```

我们可以看到这里使用了内置的 arguments 数组。而且，它的内容被复制到`names`数组中：

```ts
for (var _i = 1; _i < arguments.length; _i++) {
 names[_i -1] = arguments[_i];
}
```

当你想一想的时候，这真的是非常合理的。所以，当你不知道参数的数量时，剩余参数就是你的朋友。

# 函数签名的重载

方法和函数的重载在其他语言中是一种常见模式，比如 C#。然而，在 TypeScript 中实现这种功能与 JavaScript 相冲突，因为 JavaScript 并没有提供一种优雅的方式来直接集成这种功能。因此，唯一的解决方法可能是为每个重载编写函数声明，然后编写一个通用函数，它将包装实际的实现，并且其类型参数和返回类型与所有其他函数兼容：

```ts
function hello(name: string): string {}
function hello(name: string[]): string {}
function hello(name: any, greeting?: string): string {
 var namesArray: string[];
 if (Array.isArray(names)) {
 namesArray = names;
 } else {
 namesArray = [names];
 }
 if (!greeting) {
 greeting = 'Hello';
 }
 return greeting + ', ' + namesArray.join(' and ') + '!';
}
```

在上面的例子中，我们暴露了三种不同的函数签名，每个函数签名都具有不同的类型注释。如果有必要，我们甚至可以定义不同的返回类型。为此，我们只需使用任何返回类型注释包裹函数即可。

# 更好的函数语法和 lambda 的范围处理

ECMAScript 6 引入了箭头函数的概念（在其他语言中也称为 lambda 函数，如 Python、C＃、Java 或 C++），旨在简化一般函数语法，并提供一种处理函数范围的可靠方法，传统上由于处理`this`关键字的范围问题而处理。

第一印象是它的极简语法，大多数情况下，我们会看到箭头函数作为单行匿名表达式：

```ts
var double = x => x * 2;
```

该函数计算给定数字`x`的两倍，并返回结果，尽管我们在表达式中没有看到任何函数或返回语句。如果函数签名包含多个参数，我们只需要将它们都包裹在大括号中：

```ts
var add = (x, y) => x + y;
```

这使得这种语法在开发`map`、`reduce`等功能操作时非常方便：

```ts
var reducedArray = [23, 5, 62, 16].reduce((a, b) => a + b, 0);
```

箭头函数也可以包含语句。在这种情况下，我们希望将整个实现包裹在大括号中：

```ts
var addAndDouble = (x, y) => {
 var sum = x + y;
 return sum * 2;
}
```

但是，这与范围处理有什么关系呢？基本上，this 的值取决于我们执行函数的上下文。对于一种以出色的功能编程灵活性自豪的语言来说，这是一件大事，其中回调等模式至关重要。在回调函数中引用`this`时，我们失去了上下文的追踪，这通常迫使我们使用约定，例如将`this`的值分配给一个名为 self 或 that 的变量，稍后在回调中使用。包含间隔或超时函数的语句是这一点的完美例子：

```ts
function delayedGreeting(name): void {
 this.name = name;
 this.greet = function(){
 setTimeout(function() {
 alert('Hello ' + this.name);
 }, 0);
 }
}

var greeting = new delayedGreeting('Peter');
greeting.greet(); // alert 'Hello undefined'
```

在执行上述脚本时，我们不会得到预期的`Hello Peter`警报，而是一个不完整的字符串，突出显示对`Mr. Undefined!`的讨厌的问候。基本上，这种构造在评估超时调用内部的函数时会破坏 this 的词法作用域。将此脚本转换为箭头函数将解决问题：

```ts
function delayedGreeting(name): void {
 this.name = name;
 this.greet = function() {
 setTimeout(() => alert('Hello ' + this.name), 0);
 }
}
```

即使我们将箭头函数中的语句拆分为由花括号包裹的几行代码，this 的词法作用域仍将指向 setTimeout 调用外部的适当上下文，从而实现更加优雅和清晰的语法。

# 一般特性

在 TypeScript 中有一些一般特性，它们并不特别适用于类、函数或参数，而是使编码更加高效和有趣。这个想法是，你写的代码行数越少，就越好。这不仅仅是关于行数更少，还关乎让事情更清晰。在 ES6 中有许多这样的特性，TypeScript 也实现了这些特性，但在这里，我只会列出一些可能会出现在你的 Angular 项目中的特性。

# 展开参数

展开参数使用与 REST 参数相同的语法`...`省略号，但用法不同。它不是作为函数内部的参数使用，而是在函数体内使用。

让我们来说明一下这意味着什么：

```ts
var newItem = 3;
var oldArray = [ 1, 2 ];
var newArray = [
 ...oldArray,
 newItem
];
console.log( newArray )
```

这将输出：

```ts
1,2,3
```

我们在这里做的是向现有数组添加一个项目，而不改变旧数组。oldArray 变量仍然包含 1,2，但 newArray 包含 1,2,3。这个一般原则被称为*不可变性*，它基本上意味着不要改变，而是从旧状态创建一个新状态。这是函数式编程中使用的原则，既作为一种范式，也是出于性能原因。

你也可以在对象上使用 REST 参数；是的，真的。你可以这样写：

```ts
var oldPerson = { name : 'Chris' };
var newPerson = { ...oldPerson, age : 37 }; 
console.log( newPerson );
```

运行此代码的结果是：

```ts
{ name: 'Chris', age: 37 }
```

两个对象之间的合并。就像列表的例子一样，我们不会改变先前的变量 oldPerson。一个 newPerson 变量将从 oldPerson 获取信息，但同时将其新值添加到其中。看看 ES5 代码，你就会明白为什么：

```ts
var __assign = ( this && this.__assign ) || Object.assign || function(t) {
 for (var s, i = n, n = arguments.length; i < n; i++) {
 s = arguments[i];
 for (var p in s) if (Object.prototype.hasOwnProperty.call( s, p )) {
 t[ p ] = s[ p ];
 }
 return t;
 };
 var oldPerson = { name : 'Chris' };
 var newPerson = __assign({}, oldPerson, { age: 37 });
 console.log( newPerson );
}
```

这里发生的是定义了一个`assign`函数。该函数循环遍历`oldPerson`变量的键，并将其分配给一个新对象，最后添加`newPerson`变量的内容。如果你看一下前面的函数，它要么定义一个执行此操作的函数，要么使用 ES6 标准中的`Object.assign`（如果可用）。

# 模板字符串

模板字符串的目的是让你的代码更清晰。想象一下以下情景：

```ts
var url = 'http://path_to_domain' + 
'path_to_resource' + 
'?param=' + parameter + 
'=' + 'param2=' + 
parameter2;
```

那么，这有什么问题吗？答案是可读性。很难想象结果字符串会是什么样子，但你也很容易错误地编辑以前的代码，突然间，结果将不是你想要的。大多数语言都使用格式化函数来解决这个问题，这正是模板字符串的作用，一个格式化函数。它的使用方式如下：

```ts
var url = `${baseUrl}/${path_to_resource}?param=
 ${parameter}&param2={parameter2}`;
```

这是一个更简洁的表达方式，因此更容易阅读，所以一定要使用它。

# 泛型

泛型是一个表达式，表示我们有一个通用的代码行为，无论数据类型如何，我们都可以使用它。泛型经常用于操作集合，因为集合通常具有类似的行为，无论类型如何。但泛型也可以用于方法等结构。其想法也是，泛型应该指示你是否要以不允许的方式混合类型。

```ts
function method<T>(arg: T): T {
 return arg;
}
console.log(method<number>(1)); // works
console.log(method<string>(1)); // doesn't work
```

在前面的例子中，`T` 直到你实际使用该方法时才确定。正如你所看到的，`T` 的类型根据你调用它的方式从数字变化到 `String`。它还确保你输入了正确类型的数据。这可以在以下行中看到：

```ts
console.log(method<string>(1)); // doesn't work
```

在这里，我们明确指定 `T` 应该是一个字符串，但我们坚持要输入一个数字类型的值。编译器明确指出这是不允许的。

然而，你可以更具体地指定 `T` 应该是什么类型。通过输入以下内容，你确保 `T` 是 `Array` 类型，因此你输入的任何类型的值都必须遵循这一规定：

```ts
function method<T>(arg: T[]): T[] {
 console.log(arg.length); // Array has a .length, so no more error
 return arg;
}

class A extends Array {
}

class Person {
}

var p = new Array<Person>();
var person = new Person();
var a = new A();

method<Person>(p);
method<A>(a);
method<Person>(person);
```

在这种情况下，我们决定 `T` 应该是 `Person` 或 `A` 类型，并且我们还看到输入需要是数组类型：

```ts
function method<T>(arg: T[]) {}
```

因此，输入单个对象是不允许的。那么我们为什么要这样做呢？在这种情况下，我们希望确保某些方法是可用的，比如 `.length`，并且在某一时刻，我们不在乎我们是在操作 `A` 类型还是 `Person` 类型的东西。

你还可以决定你的类型 `T` 应该遵循这样一个接口：

```ts
interface Shape {
 area(): number;
}

class Square implements Shape {
 area() { return 1; }
}

class Circle implements Shape {
 area() { return 2; }
}

function allAreas<T extends Shape>(...args: T[]): number {
 let total = 0;
 args.forEach (x => {
 total += x.area();
 });
 return total;
}

allAreas(new Square(), new Circle());
```

以下行限制了 `T` 可以是什么：

```ts
T extends Shape
```

正如你所看到的，如果你有许多不同数据类型可以关联的共同行为，泛型是非常强大的。你可能最初不会编写自己的泛型代码，但了解正在发生的事情是很好的。

# 类、接口和类继承

现在我们已经概述了 TypeScript 最相关的部分，是时候看看如何将所有内容组合起来构建 TypeScript 类了。这些类是 TypeScript 和 Angular 应用程序的构建模块。

尽管名词类在 JavaScript 中是一个保留字，但语言本身从未对传统的面向对象的类有过实际的实现，就像 Java 或 C#等其他语言那样。JavaScript 开发人员过去常常模仿这种功能，利用函数对象作为构造函数类型，然后使用 new 运算符对其进行实例化。其他常见的做法，比如扩展我们的函数对象，是通过应用原型继承或使用组合来实现的。

现在，我们有了一个实际的类功能，足够灵活和强大，可以实现我们应用程序所需的功能。我们已经有机会在上一章中了解类。现在让我们更详细地看一下它们。

# 类的解剖-构造函数、属性、方法、getter 和 setter

以下代码片段说明了一个类的结构。请注意，类的属性成员首先出现，然后我们包括一个构造函数和几个方法和属性访问器。它们中没有一个使用保留字 function，并且所有成员和方法都正确地用类型进行了注释，除了构造函数：

```ts
class Car {
 private distanceRun: number = 0;
 color: string;

 constructor(public isHybrid: boolean, color: string = 'red') {
 this.color = color;
 }

 getCasConsumsption(): string {
 return this.ishybrid ? 'Very low' : 'Too high!';
 }

 drive(distance: number): void {
 this.distanceRun += distance;
 }

 static honk(): string {
 return 'HOOONK!';
 }

 get distance(): number {
 return this.distanceRun;
 }
}
```

这个类的布局可能会让我们想起我们在第一章中构建的组件类，*在 Angular 中创建我们的第一个组件*。基本上，类语句包含了我们可以分解为的几个元素。

+   **成员**：`Car`类的任何实例都将具有两个属性-color 类型为字符串，`distanceRun`类型为数字，它们只能从类内部访问。如果我们实例化这个类，`distanceRun`或任何其他标记为私有的成员或方法，它们将不会作为对象 API 的一部分公开。

+   **构造函数**：构造函数在创建类的实例时立即执行。通常，我们希望在这里使用构造函数签名中提供的数据初始化类成员。我们还可以利用构造函数签名本身来声明类成员，就像我们在`isHybrid`属性中所做的那样。为此，我们只需要使用 private 或 public 等访问修饰符作为构造函数参数的前缀。与我们在前面的部分中分析函数时看到的一样，我们可以定义剩余参数、可选参数或默认参数，就像在前面的示例中使用颜色参数时一样，当它没有明确定义时会回退到红色。

+   **方法**：方法是一种特殊类型的成员，表示一个函数，因此可以返回或不返回一个类型化的值。基本上，它是对象 API 的一部分的函数。方法也可以是私有的。在这种情况下，它们基本上用作类的内部范围内的辅助函数，以实现其他类成员所需的功能。

+   **静态成员**：标记为静态的成员与类相关联，而不是与该类的对象实例相关联。这意味着我们可以直接使用静态成员，而不必首先实例化对象。事实上，静态成员无法从对象实例中访问，因此它们无法使用 this 访问其他类成员。这些成员通常作为辅助或工厂方法包含在类定义中，以提供与任何特定对象实例无关的通用功能。

+   **属性访问器**：在 ES5 中，我们可以使用`Object.defineProperty`以非常冗长的方式定义自定义 setter/getter。现在，事情变得更简单了。为了创建属性访问器（通常指向内部私有字段，如所提供的示例），我们只需要使用以 set（使其可写）和 get（使其可读）命名的类型化方法前缀作为我们要公开的属性。

作为个人练习，为什么不将前面的代码片段复制到游乐场页面（[`www.typescriptlang.org/Playground`](http://www.typescriptlang.org/Playground)）并执行它呢？我们甚至可以在类定义之后直接附加此片段，运行代码并在浏览器的开发者工具控制台中检查输出，看`Car`类的实例对象如何运行。

```ts
var myCar = new Car(false);
console.log(myCar.color);  // 'red'
// Public accessor returns distanceRun:
console.log(myCar.distance)  // 0
myCar.drive(15);
console.log(myCar.distance);  // 15 (0 + 15)
myCar.drive(21);
console.log(myCar.distance);  // 36 (15 + 21)
// What's my carbon footprint according to my car type?
myCar.getGasConsumption();  // 'Too high!'
Car.honk();  // 'HOOONK!' no object instance required
```

我们甚至可以执行一个额外的测试，并在我们的代码中添加以下非法语句，尝试访问私有属性`distanceRun`，甚至通过 distance 成员应用一个值，而该成员没有 getter。

```ts
console.log(myCar.distanceRun);
myCar.distance = 100;
```

在将这些代码语句插入到代码编辑器中后，红色的下划线会提示我们正在尝试做一些不正确的事情。尽管如此，我们可以继续转译和运行代码，因为 ES5 将遵守这些做法。总的来说，如果我们尝试在这个文件上运行`tsc`编译器，运行时将退出并显示以下错误跟踪：

```ts
example_26.ts(21,7): error TS1056: Accessors are only available when targeting ECMAScript 5 and higher example_26.ts(29,13): error TS2341: Property 'distanceRun' is private and only accessible within class 'Car'
```

# 带有访问器的构造函数参数

通常，在创建一个类时，你需要给它命名，定义一个构造函数，并创建一个或多个后备字段，就像这样：

```ts
class Car {
 make: string;
 model: string;
 constructor(make: string, model: string) {
 this.make = make;
 this.model = model;
 }
}
```

对于每个你需要添加到类中的字段，通常需要做以下操作：

+   在构造函数中添加一个条目

+   在构造函数中添加一个赋值

+   创建后备字段

这真的很无聊，也不太高效。TypeScript 已经做到了，所以我们不需要通过在构造函数参数上使用访问器来输入后备字段。我们现在可以输入：

```ts
constuctor( public make: string, private model: string ) {}
```

给参数添加一个公共访问器意味着它将创建一个公共字段，给它一个私有访问器意味着它将为我们创建一个私有字段，就像这样：

```ts
class Car {
 public make: string;  // creating backing field
 private model: string;

 constructor(make: string, model: string) {
 this.make = make;  //doing assignment
 this.model = model;
 }
}
```

尝试访问这些字段会像这样：

```ts
var car = new Car('Ferrari', 'F40');
car.make  // Ferrari
car.model  // not accessible as it is private
```

在 ES5 中，我们没有字段的概念，所以它消失了，但是构造函数中的赋值仍然存在：

```ts
function Car(make) {
 this.make = make;
 this.model = model;
}
```

但是，在 TypeScript 中，你再也不需要做任何这些事情了。

```ts
class Car {
 constructor(public make: string, public model: string) {}
}
```

正如你所看到的，超过一半的代码消失了；这确实是 TypeScript 的一个卖点，因为它可以帮你省去输入大量乏味的代码。

# TypeScript 中的接口

随着应用程序规模的扩大，创建更多的类和结构，我们需要找到方法来确保代码的一致性和规则的遵从。解决一致性和类型验证问题的最佳方法之一就是创建接口。

简而言之，接口是一个定义特定字段模式和任何类型（无论是类、函数签名）的代码蓝图，实现这些接口的类型都应该符合这个模式。当我们想要强制对由工厂生成的类进行严格类型检查时，当我们定义函数签名以确保有效载荷中存在某个类型的属性，或者其他情况时，这就变得非常有用。

让我们开始吧！在这里，我们定义了`Vehicle`接口。`Vehicle`不是一个类，而是任何实现它的类必须遵守的合同模式：

```ts
interface Vehicle {
 make: string;
}
```

任何实现`Vehicle`接口的类必须具有名为`make`的成员，根据此示例，它必须被定义为字符串类型。否则，TypeScript 编译器会抱怨：

```ts
class Car implements Vehicle {
 // Compiler will raise a warning if 'make' is not defined
 make: string;
}
```

因此，接口非常有用，可以定义任何类型必须满足的最小成员集，成为确保代码库一致性的宝贵方法。

重要的是要注意，接口不仅用于定义最小的类模式，还用于定义任何类型。这样，我们可以利用接口的力量来强制存在于类中的某些字段和方法以及后来用作函数参数、函数类型、特定数组中包含的类型以及甚至变量的对象属性。接口也可以包含可选成员，甚至成员。

让我们创建一个例子。为此，我们将所有接口类型的前缀都加上`I`（大写）。这样，在引用它们时，使用我们的 IDE 代码自动完成功能会更容易找到它们的类型。

首先，我们定义了一个`Exception`接口，该接口模拟了一个具有强制消息属性成员和可选`id`成员的类型：

```ts
interface Exception {
 message: string;
 id?: number;
}
```

我们也可以为数组元素定义接口。为此，我们必须定义一个仅有一个成员的接口，定义索引为数字或字符串（用于字典集合），然后定义我们希望该数组包含的类型。在这种情况下，我们希望创建一个包含`Exception`类型的数组的接口。这是一个包含字符串消息属性和可选 ID 号成员的类型，就像我们在前面的例子中说的那样：

```ts
interface ExceptionArrayItem {
 [index: number]: IException;
}
```

现在，我们定义了未来类的蓝图，其中包括一个带有类型数组和一个返回类型定义的方法：

```ts
interface ErrorHandler {
 exception: ExceptionArrayItem[];
 logException(message: string; id?: number: void;)
}
```

我们还可以为独立的对象类型定义接口。当定义模板构造函数或方法签名时，这是非常有用的，我们稍后将在本例中看到：

```ts
interface ExceptionHandlerSettings {
 logAllExceptions: boolean;
}
```

最后但并非最不重要的是，在接下来的课程中，我们将实现所有这些接口类型：

```ts
class ErrorHandler implements ErrorHandler {
 exceptions: ExceptionArrayItem[];
 logAllExceptions: boolean;
 constructor(settings: ExceptionHandlerSettings) {
 this.logAllExceptions = settings.logAllExceptions;
 }

 logException(message: string, id?: number): void {
 this.exception.push({ message, id });
 }
}
```

基本上，我们在这里定义了一个错误处理程序类，它将管理一组异常并公开一个方法，通过将它们保存到前述数组中来记录新的异常。这两个元素由`ErrorHandler`接口定义，并且是强制性的。类构造函数期望由`ExceptionHandlerSettings`接口定义的参数，并使用它们来填充异常成员，其类型为`Exception`。在不带有有效载荷中的`logAllExceptions`参数的情况下实例化`ErrorHandler`类将触发错误。

到目前为止，我一直在解释接口，就像我们在其他高级语言中习惯看到的那样，但是 TypeScript 中的接口是经过增强的；让我通过以下代码来举例说明：

```ts
interface A {
 a
}

var instance = <A>{ a: 3 };
instance.a = 5;
```

在这里，我们声明了一个接口，但同时也在这里从接口创建了一个实例：

```ts
var instance = <A>{ a: 3 };
```

这很有趣，因为这里没有涉及到类。这意味着编写一个模拟库是小菜一碟。让我们稍微解释一下我们所说的模拟库。当你在开发代码时，你可能会先考虑接口，然后再考虑具体的类。这是因为你知道需要存在哪些方法，但可能还没有确定这些方法应该如何执行任务。想象一下，你正在构建一个订单模块。你的订单模块中有逻辑，你知道在某个时候需要与一个数据库服务进行通信，这将帮助你保存订单。你为所述数据库服务制定了一个合同，一个接口。你推迟了对该接口的实现。在这一点上，一个模拟库可以创建一个从接口生成的模拟实例。你的代码此时可能看起来像这样：

```ts
class OrderProcessor {
 constructor(private databaseService: DatabaseService) {}

 process(order) {
 this.databaseService.save(order);
 }
}

interface DatabaseService {
} 

let orderProcessor = new OrderProcessor(mockLibrary.mock<DatabaseService>());
orderProcessor.process(new Order());
```

因此，此时的模拟使我们能够推迟对`DatabaseService`的实现，直到我们完成了`OrderProcessor`的编写。它还使`OrderProcessor`的测试体验变得更好。在其他语言中，我们需要引入第三方依赖的模拟库，而现在我们可以利用 TypeScript 中的内置构造来实现以下类型：

```ts
var databaseServiceInstance = <DatabaseService>{};
```

这将给我们一个`DatabaseService`的实例。不过，需要警告一下，你需要为你的实例添加一个`process()`方法。你的实例最初是一个空对象。

这不会引起编译器的任何问题；这意味着这是一个强大的功能，但它留给你来验证你创建的东西是否正确。

让我们强调一下 TypeScript 功能的强大之处，通过查看一些更多的代码案例，这样能够模拟掉一些东西就会很值得。让我们重申，在代码中模拟任何东西的原因是为了更容易地进行测试。

假设您的代码看起来像这样：

```ts
class Stuff {
 srv:AuthService = new AuthService();
 execute() {
 if (srv.isAuthenticated())  // do x
 else  // do y
 }
}
```

测试这个的更好方法是确保`Stuff`类依赖于抽象，这意味着`AuthService`应该在其他地方创建，并且我们与`AuthService`的接口而不是具体实现进行交流。因此，我们将修改我们的代码看起来像这样：

```ts
interface AuthService {
 isAuthenticated(): boolean;
}

class Stuff {
 constructor(srv:AuthService) {}
 execute() {
 if (srv.isAuthenticated()) { /* do x */ }
 else { /* do y */ }
 }
}
```

要测试这个类，我们通常需要创建`AuthService`的具体实现，并将其作为`Stuff`实例的参数使用，就像这样：

```ts
class MockAuthService implements AuthService {
 isAuthenticated() { return true; }
}
var srv = new AuthService();
var stuff = new Stuff(srv);
```

然而，如果您想要模拟掉每个想要模拟掉的依赖项的话，这将变得相当乏味。因此，大多数语言中都存在模拟框架。其想法是给模拟框架一个接口，它将从中创建一个具体的对象。您永远不需要创建一个模拟类，就像我们之前所做的那样，但这将是模拟框架内部要做的事情。使用所述的模拟框架，它看起来会像这样：

```ts
var instance = mock<Type>();
```

到目前为止，我们已经说过从接口创建实例是多么容易，就像这样：

```ts
var instance = <A>{ a: 3 };
```

这意味着创建一个模拟框架就像输入以下内容一样容易：

```ts
function mock<T>(startData) {
 return <T>Object.assign({}, startData);
}
```

并且以以下方式使用它：

```ts
interface IPoint {
 x;
 y;
}

class Point implements IPoint {
 x;
 y;
}
var point = mock<IPoint>({ x: 3 });
console.log(point);
```

让我们通过强调类可以实现多个接口，但也可以让接口变得更加强大并且大大简化测试来总结一下关于接口的这一部分。

# 通过类继承扩展类

就像类可以由接口定义一样，它也可以扩展其他类的成员和功能，就好像它们是自己的一样。我们可以通过在类名后添加关键字`extends`，包括我们想要继承其成员的类的名称，使一个类继承自另一个类。

```ts
class Sedan extends Car {
 model: string;
 constructor(make: string, model: string) {
 super(maker);
 this.model = model;
 }
}
```

在这里，我们从一个父类`Car`扩展，该类已经公开了一个 make 成员。我们可以填充父类已定义的成员，甚至通过执行`super()`方法执行它们自己的构造函数，该方法指向父构造函数。我们还可以通过附加具有相同名称的方法来覆盖父类的方法。尽管如此，我们仍然能够执行原始父类的方法，因为它仍然可以从 super 对象中访问。回到接口，它们也可以从其他接口继承定义。简而言之，一个接口可以从另一个接口继承。

作为一种谨慎的提醒，ES6 和 TypeScript 不支持多重继承。因此，如果您想从不同的来源借用功能，您可能希望改用组合或中间类。

# TypeScript 中的装饰器

装饰器是一种非常酷的功能，最初由 Google 在 AtScript（TypeScript 的超集，最终于 2015 年初合并到 TypeScript 中）中提出，并且也是 ECMAScript 7 当前标准提案的一部分。简而言之，装饰器是一种向类声明添加元数据的方式，供依赖注入或编译指令使用（[`blogs.msdn.com/b/somasegar/archive/2015/03/05/typescript-lt-3-angular.aspx`](http://blogs.msdn.com/b/somasegar/archive/2015/03/05/typescript-lt-3-angular.aspx)）。通过创建装饰器，我们正在定义可能对我们的类、方法或函数的行为产生影响，或者仅仅改变我们在字段或参数中定义的数据的特殊注释。在这个意义上，装饰器是一种强大的方式，可以增强我们类型的本机功能，而不需要创建子类或从其他类型继承。

这是 TypeScript 最有趣的功能之一。事实上，在 Angular 中设计指令和组件或管理依赖注入时，它被广泛使用，我们将从第五章 *使用管道和指令增强我们的组件*开始看到。

装饰器可以很容易地通过其名称的`@`前缀来识别，它们通常位于它们装饰的元素的上方，包括方法负载或不包括方法负载。

我们可以定义最多四种不同类型的装饰器，具体取决于每种类型所要装饰的元素：

+   类装饰器

+   属性装饰器

+   方法装饰器

+   参数装饰器

让我们逐个看一下！

# 类装饰器

类装饰器允许我们增强一个类或对其任何成员执行操作，并且装饰器语句在类被实例化之前执行。

创建一个类装饰器只需要定义一个普通函数，其签名是指向我们想要装饰的类的构造函数的指针，类型为函数（或任何其他继承自函数的类型）。正式声明定义了一个`ClassDecorator`，如下所示：

```ts
declare type ClassDecorator = <TFunction extends Function>(Target: TFunction) => TFunction | void;
```

是的，很难理解这些胡言乱语的含义，对吧？让我们通过一个简单的例子来把一切放在上下文中，就像这样：

```ts
function Banana(target: Function): void {
 target.prototype.banana = function(): void {
 console.log('We have bananas!');
 }
}

@Banana
class FruitBasket {
 constructor() {
 // Implementation goes here...
 }
}
var basket = new FruitBasket();
basket.banana();  // console will output 'We have bananas!'
```

正如我们所看到的，我们通过正确地使用`Banana`装饰器，获得了一个在`FruitBasket`类中原本未定义的`banana()`方法。不过值得一提的是，这实际上不会编译通过。编译器会抱怨`FruitBasket`没有`banana()`方法，这是理所当然的。TypeScript 是有类型的。在 ES5 中，我们可以做任何我们想做的事情，任何错误都会在运行时被发现。所以在这一点上，我们需要告诉编译器这是可以的。那么，我们该如何做呢？一种方法是在创建篮子实例时，像这样给它赋予任意类型：

```ts
var basket: any = new FruitBasket();
basket.banana();
```

我们在这里所做的是将变量 basket 主动赋予`any`类型，从而抵制 TypeScript 编译器将类型推断为`FruitBasket`的冲动。通过使用 any 类型，TypeScript 无法知道我们对它所做的是否正确。另一种实现相同效果的方法是这样类型：

```ts
var basket = new FruitBasket();
(basket as any).banana();
```

在这里，我们使用`as`运算符进行了即时转换，从而告诉编译器这是可以的。

# 扩展类装饰器函数签名

有时，我们可能需要在实例化时自定义装饰器的操作方式。别担心！我们可以设计带有自定义签名的装饰器，然后让它们返回一个与我们在设计不带参数的类装饰器时定义的相同签名的函数。作为一个经验法则，带参数的装饰器只需要一个函数，其签名与我们想要配置的参数匹配。这样的函数必须返回另一个函数，其签名与我们想要定义的装饰器的签名匹配。

下面的代码片段展示了与前面例子相同的功能，但它允许开发人员自定义问候消息：

```ts
function Banana(message: string) {
 return function(target: Function) {
 target.prototype.banana = function(): void {
 console.log(message);
 }
 }
}

@Greeter('Bananas are yellow!')
class FruitBasket {
 constructor() {
 // Implementation goes here...
 }
}
var basket = new FruitBasket();
basket.banana();  // console will output 'Bananas are yellow'
```

# 属性装饰器

属性装饰器是用于应用于类字段的，并且可以通过创建一个`PropertyDecorator`函数来轻松定义，其签名接受两个参数：

+   **Target**：这是我们想要装饰的类的原型

+   **Key**：这是我们想要装饰的属性的名称

特定类型的装饰器的可能用例可能包括日志记录

在实例化此类的对象的类字段分配的值，甚至对这些字段的数据更改做出反应。让我们看一个实际的例子，涵盖了这两种行为：

```ts
function Jedi(target: Object, key: string) {
 var propertyValue: string = this[key];
 if (delete this[key]) {
 Object.defineProperty(target, key, {
 get: function() {
 return propertyValue;
 }, 
 set: function(newValue){
 propertyValue = newValue;
 console.log(`${propertyValue} is a Jedi`);
 }
 });
 }
}

class Character {
 @Jedi
 name: string;
}

var character = new Character();
character.name = 'Luke';  // console outputs 'Luke is a Jedi'
character.name = 'Yoda';  // console outputs 'Yoda is a Jedi'
```

这里适用于带参数的类装饰器的相同逻辑，尽管返回函数的签名略有不同，以匹配我们已经看到的无参数装饰器声明的签名。

以下示例描述了我们如何记录给定类属性的更改，并在发生这种情况时触发自定义函数：

```ts
function NameChanger(callbackObject: any): Function {
 return function(target: Object, key: string): void {
 var propertyValue: string = this[key];
 if (delete this[key]) {
 Object.defineProperty(target, key, {
 get: function() {
 return propertyValue;
 }, 
 set: function(newValue) {
 propertyValue = newValue;
 callbackObject.changeName.call(this, propertyValue);
 }
 });
 }
 }
}

class Fruit {
 @NameChanger ({
 changeName: function(string,newValue: string): void {
 console.log(`You are now known as ${newValue}`);
 }
 })
 name: string;
}

var character = new Character();
character.name 'Anakin';  // console: 'You are now known as Anakin'
character.name = 'Lord Vader';  //console: 'You are now known as Lord Vader'
```

# 方法装饰器

这些特殊的装饰器可以检测、记录并干预方法的执行方式。为此，我们只需要定义一个`MethodDecorator`函数，其有效负载接受以下参数：

+   **Target**：这被定义为一个对象，代表被装饰的方法。

+   **Key**：这是给定方法的实际名称的字符串。

+   **Value**：这是给定方法的属性描述符。实际上，它是一个哈希对象，其中包含了一个名为 value 的属性，其中包含对方法本身的引用。

让我们看看如何在实际示例中利用`MethodDecorator`函数。在后来的 TypeScript 版本中，这种语法已经改变。然而，想法是在方法执行之前和之后拦截。那么，为什么你想这样做呢？嗯，有一些有趣的情况：

+   您想了解有关方法如何被调用的更多信息，例如`args`，结果等

+   您想知道某个方法运行了多长时间

让我们为每种情况创建一个装饰器：

```ts
function Log(){
 return function(target, propertyKey: string, 
 descriptor: PropertyDescriptor) {
 var oldMethod = descriptor.value;
 descriptor.value = function newFunc( ...args:any[]){
 let result = oldMethod.apply(this, args);
 console.log(`${propertyKey} is called with ${args.join(',') and
 result ${result}`);
 return result;
 }
 }
}

class Hero {
 @Log()
 attack(...args:[]) { return args.join(); }
}

var hero = new Hero();
hero.attack();
```

在这里，我们正在讨论`descriptor.value`，其中包含我们实际的函数，正如你所看到的，我们：

+   保存对旧方法的引用

+   我们通过替换`descriptor.value`指向的内容来重新定义方法

+   在我们的新函数内部执行旧方法

+   我们记录使用了什么参数以及结果如何变化

到目前为止，我们已经解释了如何向方法添加日志信息，但还有另一种情况我们也想描述一下，即测量执行时间。我们可以使用与之前类似的方法，但有一些细微的差别：

```ts
function Timer(){
 return function(target, propertyKey: string, descriptor: PropertyDescriptor) {
 var oldMethod = descriptor.value;
 descriptor.value = function() {
 var start = new Date();
 let result = oldMethod.apply(this, args);
 var stop = new Date();
 console.log(`Method took ${stop.getMilliseconds() - 
 start.getMilliseconds()}ms to run`);
 return result;
 }
 }
}
```

我们仍然做了很多相同的事情，但让我们用几个要点来总结一下：

+   保存对旧方法的引用

+   重新定义`descriptor.value`

+   在方法执行前启动计时器

+   执行方法

+   在方法执行后停止计时器

请记住，装饰器函数的作用域限定在目标参数中表示的类中，因此我们可以利用这一点来为类增加我们自己的自定义成员。在这样做时要小心，因为这可能会覆盖已经存在的成员。在本例中，我们不会对此进行任何尽职调查，但在将来的代码中要小心处理。方法装饰器是非常强大的，但不要总是使用它们，而是在像前面那样它们发挥作用的情况下使用。

# 参数装饰器

我们最后一轮的装饰器将涵盖`ParameterDecorator`函数，该函数可以访问位于函数签名中的参数。这种装饰器并不意图改变参数信息或函数行为，而是查看参数值，然后在其他地方执行操作，例如，记录日志或复制数据。`ParameterDecorator`函数接受以下参数：

+   **Target**：这是包含被装饰参数的函数的对象原型，通常属于一个类

+   **Key**：这是包含装饰参数的函数签名的函数的名称

+   **参数索引**：这是装饰器应用的参数数组中的索引

以下示例显示了参数装饰器的工作示例：

```ts
function Log(target: Function, key: string, parameterIndex: number) {
 var functionLogged = key || target.prototype.constructor.name;
 console.log(`
 The parameter in position 
 ${parameterIndex} at ${functionLogged} has been decorated`
 );
}

class Greeter {
 greeting: string;
 constructor (@Log phrase: string) {
 this.greeting = phrase;
 }
}
// The console will output right after the class above is defined:
// 'The parameter in position 0 at Greeter has been decorated'
```

您可能已经注意到`functionLogged`变量的奇怪赋值。这是因为目标参数的值将根据被装饰参数的函数而变化。因此，如果我们装饰构造函数参数或方法参数，它是不同的。前者将返回对类原型的引用，后者将只返回构造函数。当装饰构造函数参数时，key 参数也将是未定义的。

正如我们在本节开头提到的，参数装饰器并不意味着修改装饰的参数的值或更改这些参数所在的方法或构造函数的行为。它们的目的通常是记录或准备容器对象，以通过更高级别的装饰器（如方法或类装饰器）实现额外的抽象层或功能。这种情况的典型案例包括记录组件行为或管理依赖注入，正如我们将在第五章中看到的，“通过管道和指令增强我们的组件”。

# 使用模块组织我们的应用程序

随着我们的应用规模和规模的增长，总会有一个时候，我们需要更好地组织我们的代码，使其可持续且更具重用性。模块是对这种需求的响应，所以让我们看看它们是如何工作的，以及我们如何在应用程序中实现它们。模块可以是内部的或外部的。在本书中，我们将主要关注外部模块，但现在概述这两种类型是一个好主意。

# 内部模块

简而言之，内部模块是包含一系列类、函数、对象或变量的单例包装器，其范围在内部，远离全局或外部范围。我们可以通过在我们希望从外部访问的元素前加上关键字`export`来公开模块的内容，就像这样：

```ts
module Greetings {
 export class Greeting {
 constructor(public name: string) {
 console.log(`Hello ${name}`);
 }
 }

 export class XmasGreeting {
 constructor(public name: string){
 console.log(`Merry Xmas ${name}`);
 }
 }
}
```

我们的“问候”模块包含两个类，可以通过导入模块并通过其名称访问要使用的类来从模块外部访问：

```ts
import XmasGreeting = Greeting.XmasGreeting;
var xmasGreeting = XmasGreeting('Joe');
// console outputs 'Merry Xmas Joe'
```

在查看前面的代码之后，我们可以得出结论，内部模块是将元素分组和封装在命名空间上下文中的一种好方法。我们甚至可以将我们的模块拆分成几个文件，只要模块声明在这些文件中保持相同的名称。为了做到这一点，我们将希望使用引用标签引用我们散布在这个模块中的不同文件中的对象：

```ts
/// <reference path="greetings/XmasGreeting.ts" />
```

然而，内部模块的主要缺点是，为了使它们在我们的 IDE 领域之外工作，我们需要将它们全部放在同一个文件或应用程序范围内。我们可以将所有生成的 JavaScript 文件作为脚本插入到我们的网页中，利用诸如 Grunt 或 Gulp 的任务运行器，或者甚至使用 TypeScript 编译器中的`--outFile`标志，将工作区中找到的所有`.ts`文件编译成一个单独的捆绑包，使用引用标签到所有其他模块作为我们编译的起点的引导文件：

```ts
tsc --outFile app.js module.ts
```

这将编译所有的 TypeScript 文件，遵循引用标签引用的依赖文件的路径。如果我们忘记以这种方式引用任何文件，它将不会包含在最终的构建文件中，所以另一个选项是在编译命令中列出包含独立模块的所有文件，或者只需添加一个包含模块综合列表的`.txt`文件来捆绑。或者，我们可以只使用外部模块。

# 外部模块

外部模块基本上是我们在构建旨在增长的应用程序时所需要的解决方案。基本上，每个外部模块都在文件级别上工作，其中每个文件都是模块本身，模块名称将与没有`.js`扩展名的文件名匹配。我们不再使用模块关键字，每个标有导出前缀的成员将成为外部模块 API 的一部分。在上一个示例中描述的内部模块一旦方便地保存在`Greetings.ts`文件中，将变成这样：

```ts
export class Greeting {
 constructor(public name: string) {
 console.log(`Hello ${name}`);
 }
}

export class XmasGreeting {
 constructor(public name: string) {
 console.log(`Merry Xmas ${name}`);
 }
}
```

导入此模块并使用其导出的类需要以下代码：

```ts
import greetings = require('Greetings');
var XmasGreetings = greeting.XmasGreetings();
var xmasGreetings = new XmasGreetings('Pete');
// console outputs 'Merry Xmas Pete'
```

显然，传统 JavaScript 不支持 require 函数，因此我们需要告诉编译器我们希望在目标 JavaScript 文件中实现该功能。幸运的是，TypeScript 编译器在其 API 中包含了`--module`参数，因此我们可以为我们的项目配置所选择的依赖加载器：`commonjs`用于基于 node 的导入，`amd`用于基于 RequireJS 的导入，`umd`用于实现通用模块定义规范的加载器，或者 system 用于基于 SystemJS 的导入。我们将在本书中重点介绍 SystemJS 模块加载器：

```ts
tsc --outFile app.js --module commonjs
```

生成的文件将被适当地填充，因此模块可以使用我们选择的模块加载器跨文件加载依赖项。

# TypeScript > 1.5 的 ES6 模块

在你的 Angular 项目中使用模块的方式是使用 ES6 语法的外部模块，所以让我们了解一下这意味着什么的基础知识。如本节前面提到的，每个模块一个文件，我们可以使用`export`关键字导出它。然而，你如何消费依赖在语法上有所不同；让我们通过创建一个 ES6 模块`service.ts`和另一个模块`consumer.ts`来说明这一点，后者旨在消费前者：

```ts
//service.ts
export class Service {
 getData() {} 
}

//consumer.ts import {} from './service';
```

这里有两件事要注意，在`consumer.ts`文件中：

+   使用大括号`{}`导入

+   使用 from 关键字来找到我们的文件

大括号`{}`给了我们选择想要导入的构造的机会。想象一下如果`service.ts`更复杂，像这样：

```ts
//service-v2.ts
export class Service {
 getData(){}
}

export const PI = 3.14
```

作为消费者，我们现在可以选择这样导入`Service`和/或`PI`：

```ts
//consumer-v2.ts
import { Service, PI } from './service-v2'
```

然而，也可以使用另一种语法来导出你的构造。到目前为止，我们一直在为每个想要导出的东西输入`export`；在我们的`service.ts`的第三部分`service-v3.ts`中，我们可以这样输入它：

```ts
//service-v3.ts
class Service {}

const PI = 3.14;

export { Service, PI }
```

进行导出的第三种方式是默认的`export`。有一个`default`关键字，这意味着我们在导入时不必使用大括号`{}`：

```ts
//service-v4.ts
export default function(a, b) {
 return a + b;
}

//consumer-v3.ts import service from './service-v4';

```

# 总结

这绝对是一篇长篇大论，但这篇关于 TypeScript 的介绍绝对是必要的，以便理解 Angular 许多最精彩部分背后的逻辑。它让我们有机会不仅介绍语言语法，还解释了它作为构建 Angular 框架的首选语法成功背后的原因。我们审查了它的类型架构，以及如何使用各种参数化签名的高级业务逻辑设计函数，甚至发现了如何通过使用强大的新箭头函数来绕过与作用域相关的问题。这一章最相关的部分可能是类、方法、属性和访问器的概述，以及我们如何通过接口处理继承和更好的应用程序设计。模块和装饰器是本章探讨的其他重要特性，正如我们很快将看到的那样，对这些机制的充分了解对于理解 Angular 中的依赖注入是至关重要的。

有了这些知识，我们现在可以恢复对 Angular 的调查，并自信地面对组件创建的相关部分，比如样式封装、输出格式化等等。第四章，*在我们的组件中实现属性和事件*，将使我们接触到高级模板创建技术、数据绑定技术、指令和管道。所有这些特性将使我们能够将新获得的 TypeScript 知识付诸实践。
