# 面向 .NET 开发者的 JavaScript 教程（一）

> 原文：[`zh.annas-archive.org/md5/9D370F6C530A09D4B2BBB62567683DDF`](https://zh.annas-archive.org/md5/9D370F6C530A09D4B2BBB62567683DDF)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 序言

这是一本关于 JavaScript 编程语言的书，面向希望使用流行的基于客户端的 JavaScript 框架开发响应式网络应用程序的.NET 开发者，以及希望创建丰富用户体验的程序员。它也适合具有 JavaScript 编程语言基础知识并希望了解一些核心和高级概念以及一些业界最佳实践和模式的程序员，以结构和设计网络应用程序。

这本书从 JavaScript 的基础知识开始，帮助读者了解核心概念，然后逐步深入到一些高级主题。其中一章主要关注 jQuery 库，这个库在整个网络应用开发中广泛使用，之后是一章关于 Ajax 技术，帮助开发者理解如何进行异步请求。接着是使用原生 JavaScript 的 XHR 对象或 jQuery 库进行请求的选项。还有一章通过使用 Angular 2 和 ASP.NET Core 开发完整的应用程序来介绍 TypeScript，这是一种支持 ECMAScript 2015 最新和 evolving 特性的 JavaScript 的超集。我们还将探索 Windows JavaScript (WinJS)库，使用 JavaScript 和 HTML 开发 Windows 应用程序，并使用这个库将 Windows 行为、外观和感觉带到 ASP.NET 网络应用程序中。有一个完整的章节介绍了 Node.js，帮助开发者了解 JavaScript 语言在服务器端的强大之处，之后的一章则讨论了在大型项目中使用 JavaScript 的方法。最后，这本书将以测试和调试章节结束，讨论哪些测试套件和调试技术可用于故障排除并使应用程序健壮。

这本书有一些非常密集的主题，需要全神贯注，因此非常适合有一些先前知识的人。所有章节都与 JavaScript 相关，围绕 JavaScript 框架和库构建丰富的网络应用程序。通过这本书，读者将获得关于 JavaScript 语言及其构建在其上的框架和库的端到端知识，以及测试和调试 JavaScript 代码的技术。

# 本书涵盖内容

第一章，*现代网络应用程序的 JavaScript*，关注 JavaScript 的基本概念，包括变量的声明、数据类型、实现数组、表达式、运算符和函数。我们将使用 Visual Studio 2015 编写简单的 JavaScript 程序，并了解这个 IDE 为编写 JavaScript 程序提供了什么。我们还将研究如何编写 JavaScript 代码，并比较.NET 运行时与 JavaScript 运行时的区别，以阐明代码编译过程的执行周期。

第二章，*高级 JavaScript 概念*，涵盖了 JavaScript 的高级概念，并向开发者展示了 JavaScript 语言的洞察。它将展示 JavaScript 语言在功能方面可以被使用的程度。我们将讨论变量提升及其作用域、属性描述符、面向对象编程、闭包、类型数组和异常处理。

第三章，*在 ASP.NET 中使用 jQuery*，讨论了 jQuery 及其在 ASP.NET Core 开发的网络应用程序中的使用。我们将讨论 jQuery 提供的选项及其与普通原生的 JavaScript 在操作 DOM 元素、附加事件和执行复杂操作方面的优势。

第四章，*Ajax 技术*，讨论了被称为 Ajax 请求的异步请求技术。我们将探讨使用 XMLHttpRequest（XHR）对象的核心概念，并研究 Ajax 请求的基本处理架构以及它提供的事件和方法。另一方面，我们还将探讨 jQuery 库与普通的 XHR 对象相比提供的内容。

第五章，*使用 Angular 2 和 Web API 开发 ASP.NET 应用程序*，介绍了 TypeScript 的基本概念并将其与 Angular 2 结合使用。我们将使用 Angular 2 作为前端的客户端框架、Web API 作为后端服务以及 Entity Framework Core 用于数据库持久化，在 ASP.NET Core 中开发一个简单的应用程序。在撰写本文时，Angular 2 处于测试版阶段，本章使用了测试版。随着 Angular 2 未来的发布，框架有可能发生一些变化，但基本概念几乎保持不变。对于未来的更新，您可以参考[`angular.io/`](http://angular.io/)。

第六章，*探索 WinJS 库*，探讨了由微软开发的 WinJS 库，这是一个不仅可以用 JavaScript 和 HTML 开发 Windows 应用程序，还可以与 ASP.NET 和其他网络框架一起使用的 JavaScript 库。我们将讨论定义类、命名空间、派生类、混合类（mixins）和承诺（promises）的核心概念。我们还将研究数据绑定技术以及如何使用 Windows 控件或 HTML 元素的特定属性来改变控件的行为、外观和感觉。此外，我们将使用 WinRT API 在我们的网络应用程序中访问设备的摄像头，并讨论通过宿主应用（Hosted app）的概念，任何网络应用程序都可以使用 Visual Studio 2015 中的通用窗口模板（Universal Window template）转换成 Windows 应用程序。

第七章，*JavaScript 设计模式*，表明设计模式为软件设计提供了高效的解决方案。我们将讨论一些业界广泛采用的最佳设计模式，这些模式分为创建型、结构型和行为型。每个类别将涵盖四种类型的设计模式，这些模式可以使用 JavaScript 来实现并解决特定的设计问题。

第八章，*Node.js 对 ASP.NET 开发者的应用*，专注于 Node.js 的基础知识以及如何使用它来使用 JavaScript 开发服务器端应用程序。在本章中，我们将讨论视图引擎，如 EJS 和 Jade，以及使用控制器和服务的 MVC 模式实现。此外，我们将在本章结束时通过一些示例来访问 Microsoft SQL Server 数据库，执行对数据库的读取、创建和检索操作。

第九章，*使用 JavaScript 进行大型项目开发*，提供了使用 JavaScript 进行大型应用开发的最佳实践。我们将讨论如何通过将项目拆分为模块来提高可扩展性和可维护性，从而结构化我们的基于 JavaScript 的项目。我们将了解如何有效地使用中介者模式（Mediator pattern）提供模块间的通信以及文档框架，以提高你的 JavaScript 代码的可维护性。最后，我们将讨论如何通过将 JavaScript 文件压缩和合并成压缩版本来优化应用程序，并提高性能。

第十章, *测试和调试 JavaScript*, 专注于 JavaScript 应用程序的测试和调试。我们将讨论最受欢迎的 JavaScript 代码测试套件 Jasmine，并使用 Karma 运行测试用例。至于调试，我们将讨论一些使用 Visual Studio 调试 JavaScript 的技巧和技术，以及 Microsoft Edge 为简化调试所提供的内容。最后，我们将研究 Microsoft Edge 如何使调试 TypeScript 文件变得简单的基本概念以及实现所需的配置。

# 您需要什么

全书我们将使用 Visual Studio 2015 来实践示例。对于服务器端技术，我们使用了 ASP.NET Core 进行网络应用开发，并在其上使用 JavaScript。在第八章, *Node.js 对 ASP.NET 开发者的使用*中，我们使用 Node.js 展示了 JavaScript 如何用于服务器端。对于 Node.js，我们需要在 Visual Studio 2015 中安装一些扩展，具体细节在章节中说明。

# 本书适合谁阅读

本书面向具有扎实 ASP.NET Core 编程经验的.NET 开发者。全书使用 ASP.NET Core 进行网络开发，并假定开发者有.NET Core 和 ASP.NET Core 的深入知识或实际经验。

# 约定

在本书中，你会看到多种文本样式，用以区分不同类型的信息。以下是这些样式的一些示例及其含义解释。

文本中的代码词汇、数据库表名、文件夹名、文件名、文件扩展名、路径名、假网址、用户输入和 Twitter 处理显示如下："JavaScript 可以放在 HTML 页面的`<head>`或`<body>`部分。"

代码块如下所示：

```js
<html>
  <head>
    <script>
      alert("This is a simple text");
    </script>
  </head>
</html>
```

任何命令行输入或输出如下所示：

```js
dotnet ef database update –verbose

```

**新术语**和**重要词汇**以粗体显示。例如，在菜单或对话框中出现的屏幕上的词汇，在文本中显示为："当页面加载时，它将显示弹出消息和文本**这是一个简单文本**。"

### 注意

警告或重要说明以框的形式出现，如下所示。

### 提示

技巧和小窍门如下所示。

# 读者反馈

我们的读者反馈始终受欢迎。让我们知道您对这本书的看法——您喜欢或不喜欢的地方。读者反馈对我们很重要，因为它有助于我们开发出您能真正从中获益的标题。

要发送一般性反馈，只需发送电子邮件至`<feedback@packtpub.com>`，并在消息主题中提到本书的标题。

如果你在某个主题上有专业知识，并且对撰写或贡献书籍感兴趣，请查看我们的作者指南，网址为[www.packtpub.com/authors](http://www.packtpub.com/authors)。

# 客户支持

既然你已经拥有了一本 Packt 书籍，我们有很多东西可以帮助你充分利用你的购买。

## 下载示例代码

你可以从你账户中的[`www.packtpub.com`](http://www.packtpub.com)下载本书的示例代码文件。如果你在其他地方购买了这本书，你可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册，以便将文件直接通过电子邮件发送给你。

你可以按照以下步骤下载代码文件：

1.  使用你的电子邮件地址和密码登录或注册我们的网站。

1.  将鼠标指针悬停在顶部的**支持**选项卡上。

1.  点击**代码下载与勘误**。

1.  在**搜索**框中输入书籍名称。

1.  选择你要下载代码文件的书籍。

1.  从下拉菜单中选择你购买这本书的地方。

1.  点击**代码下载**。

你还可以通过在 Packt 出版社网站上点击书籍网页上的**代码文件**按钮来下载代码文件。通过在**搜索**框中输入书籍名称可以访问此页面。请注意，你需要登录到你的 Packt 账户。

下载文件后，请确保使用最新版本解压或提取文件夹：

+   适用于 Windows 的 WinRAR / 7-Zip

+   适用于 Mac 的 Zipeg / iZip / UnRarX

+   适用于 Linux 的 7-Zip / PeaZip

本书的代码包也托管在 GitHub 上，地址为[`github.com/PacktPublishing/JavaScript-For-.NET-Developers`](https://github.com/PacktPublishing/JavaScript-For-.NET-Developers)。我们还有其他来自我们丰富书籍和视频目录的代码包，可在[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)找到。去看看吧！

## 下载本书的彩色图片

我们还为你提供了一个包含本书中使用的屏幕截图/图表彩色图片的 PDF 文件。彩色图片将帮助你更好地理解输出中的变化。你可以从[`www.packtpub.com/sites/default/files/downloads/JavaScriptForNETDevelopers_ColorImages.pdf`](https://www.packtpub.com/sites/default/files/downloads/JavaScriptForNETDevelopers_ColorImages.pdf)下载这个文件。

## 勘误表

虽然我们已经竭尽全力确保内容的准确性，但错误仍然可能发生。如果您在我们的某本书中发现错误——可能是文本或代码中的错误——如果您能向我们报告，我们将非常感激。这样做可以避免其他读者感到沮丧，并帮助我们改进本书的后续版本。如果您发现任何错误，请通过访问[`www.packtpub.com/submit-errata`](http://www.packtpub.com/submit-errata)报告，选择您的书籍，点击**错误提交表单**链接，并输入您的错误详情。一旦您的错误得到验证，您的提交将被接受，并且错误将被上传到我们的网站或添加到该标题下的错误部分现有的错误列表中。

要查看以前提交的错误，请前往[`www.packtpub.com/books/content/support`](https://www.packtpub.com/books/content/support)并在搜索框中输入书籍名称。所需信息将在**错误**部分出现。

## 盗版

互联网上侵犯版权材料的问题持续存在，所有媒体都受到影响。在 Packt，我们对保护我们的版权和许可证非常认真。如果您在互联网上以任何形式发现我们作品的非法副本，请立即提供给我们地址或网站名称，以便我们可以寻求补救措施。

如果您怀疑有被盗版的材料，请联系我们`<copyright@packtpub.com>`。

我们感激您在保护我们的作者和我们提供有价值内容的能力方面所提供的帮助。

## 问题

如果您对本书任何方面有问题，您可以联系`<questions@packtpub.com>`，我们将尽力解决问题。


# 第一章：为现代网络应用程序的 JavaScript

近年来，网络开发以惊人的速度发展。大多数在桌面平台上开发的企业应用程序现在都转移到了网络平台，原因是访问的便捷性和网络平台不断添加的丰富功能。通常，任何提供桌面应用程序特征的网络应用程序都被认为是富网络应用程序。因此，它涉及大量使用 JavaScript 及其框架和库。

JavaScript 在开发富应用程序中扮演着重要的角色，并允许开发人员减少服务器端的回调并通过 ajaxified 请求调用服务器端函数。不仅如此，现在许多公司和社区都在开发像 Angular、Knockout、ReactJS 这样的优秀框架，带来最先进和突破性的功能。微软还发布了**WinJS**库，使从移动浏览器上运行的网页应用程序能够访问移动原生设备功能，如相机、存储等。**myNFC** 也是一个很棒的 JavaScript 库，它允许开发人员为智能手机创建应用程序。

# JavaScript 的重要性

所有客户端框架都是基于 JavaScript 的。作为一名 ASP.NET 开发者，在使用或将其集成到我们的应用程序之前，我们应该对 JavaScript 有扎实的概念。JavaScript 是客户端脚本语言，是有史以来最受欢迎的编程语言之一，在浏览器上运行。当在 web 开发项目中工作时，这种语言以许多更好的方式为您服务，使**用户界面**（**UI**）具有响应性。通过 JavaScript，您可以操作 HTML 页面**文档对象模型**（**DOM**）元素，通过 ajaxified 请求调用服务器端代码，并向您的客户带来新的丰富体验。在 JavaScript 库的核心进行了许多创新，并且已经开发出了不同的框架和各种库。

## JavaScript 是什么？

JavaScript 是一种由 Brendden Eich 在 1995 年创造的编程语言。最初，它只被 Netscape Browser 支持，但后来他们决定发布一个被称为 ECMA 规范的标准，让其他浏览器实现并提供引擎来在其浏览器上执行 JavaScript。提供这个标准的原因是为了让遵循方拥有完整的规格细节并保持行为的一致性。

最初，它主要针对在浏览器上执行，并执行与 HTML 页面一起工作的客户端操作，如操作 DOM 元素、定义事件处理程序和其他功能。后来，在近年来，它已经成为一种强大的语言，并不仅限于客户端操作。通过 Node.js，我们可以在服务器端使用 JavaScript，并且 Node 提供了各种模块和插件来执行 I/O 操作、服务器端事件等。

## 比较运行时

由于本书针对.NET 开发者，让我们将 JavaScript 运行时与.NET 运行时进行比较。有一些共同之处，但基本的运行时不同。

在.NET 中，**公共语言运行时**（**CLR**）对正在运行的代码进行**即时编译**（**JIT**）并提供内存管理。JIT 编译是在你构建项目后生成的一次性编译的**中间语言**（**IL**）代码上进行的。

在 JavaScript 世界中，浏览器引擎是 JavaScript 语言的运行时。每个浏览器都以自己的方式解释 JavaScript，但都遵循 ECMA 脚本标准。不同的浏览器有不同的实现，例如，Microsoft Edge 使用 Chakra 引擎，Chrome 使用 V8，Firefox 有 Monkey 引擎。最初，JavaScript 被实现为一种解释型语言，但现在很少有现代浏览器进行 JIT 编译。每个引擎都提供一套服务，如内存管理、编译和处理。

以下图表展示了两种架构的比较：

![比较运行时](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00002.jpeg)

JavaScript 解析器解析和标记 JavaScript 代码，将其转化为语法树。所有浏览器（除了 Google V8）解析语法树并生成字节码，最终通过 JIT 编译转换成机器码。另一方面，Google V8 引擎解析语法树，而不是首先生成字节码，它直接生成机器码。

`.NET`源代码由其自己的语言编译器编译，例如 C#或 VB.NET 编译器，并经过编译器管道的几个阶段生成 IL 代码。然后 JIT 编译器读取这个 IL 代码并生成原生机器代码。

# 设置你的环境

在阅读本书之前，让我们设置一下你的环境。市场上有很多著名的编辑器可用于创建 JavaScript 项目，如 Sublime Text、Komodo IDE、NetBeans、Eclipse 等，但我们将继续使用 Visual Studio 2015，它带来了一些很好的改进，帮助开发者比以前更好地工作在 JavaScript 上。

接下来，让我们下载并安装 Visual Studio 2015。你可以从[`www.visualstudio.com/`](https://www.visualstudio.com/)下载 Visual Studio 2015 社区版，这是一个免费版本，并提供以下章节中描述的某些改进。

## Visual Studio 2015 IDE 中的 JavaScript 新编辑体验

新的 Visual Studio 2015 IDE 为开发网络应用程序提供了许多丰富的功能，并且有各种模板可用于根据不同框架和应用程序模型创建项目。早期版本已经支持 IntelliSense、着色和格式化，但新的 Visual Studio 2015 IDE 还有一些更多的改进，如下所示：

+   增加了对 ECMAScript 6 脚本语言的支持，正式名称为 ES2015。有了新的 ES2015，添加了许多功能，现在您可以定义类、lambda 表达式、展开操作符和代理对象。因此，借助 Visual Studio 2015，您可以在 JavaScript 代码中使用这些功能并获得所有 IntelliSense。

+   支持流行的 JavaScript 客户端框架，如 Angular、ReactJS 等。

+   文档注释可以帮助您为 JavaScript 方法添加注释，并在使用它们时显示描述：![Visual Studio 2015 IDE 中 JavaScript 的新编辑体验](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00003.jpeg)

+   对新的 JavaScript API（如触摸事件和 Web 音频 API）的支持。

+   您可以使用诸如`//TODO`、`//HACK`和`//UNDONE`之类的标记，它会在**任务列表**窗口中为您提供列表，帮助您追踪待办事项：![Visual Studio 2015 IDE 中 JavaScript 的新编辑体验](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00004.jpeg)

+   有了 JavaScript 文件，Visual Studio 2015 提供了我们在编写任何.NET 语言类时所熟悉的导航栏。使用此功能，选择并导航到不同的 JavaScript 方法要容易得多：![Visual Studio 2015 IDE 中 JavaScript 的新编辑体验](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00005.jpeg)

# 在 JavaScript 中编程

JavaScript 是最强大的语言之一，在任何网页开发项目中都发挥着至关重要的作用，提供客户端支持并实现丰富的功能。在本节中，我们将讨论在 JavaScript 中编写程序的核心概念，并将其应用于网页应用程序中。

## JavaScript 的核心基础知识

```js
<script></script> tags defined within the <head></head> section:
```

```js
<html>
  <head>
    <script>
      alert("This is a simple text");
    </script>
  </head>
</html>
```

页面加载时，会显示弹出消息和一段文字，如**这是一个简单的文本**。浏览器执行定义在`<script>`标签下的任何脚本，并运行此块内的语句。定义在脚本标签直接下方的任何语句在页面加载时都会执行。

同样，我们也可以在 HTML 页面的`<body>`部分定义 JavaScript：

```js
<html>
  <body>
    <script>
      alert("hello world");
    </script>
  </body>
</html>
```

### 提示

将脚本放在页面底部是一个好主意，因为编译可能会减慢页面加载速度。

通常，在每一个项目中，无论项目规模大小，将`<script>`部分与 HTML 分离可以使代码看起来更整洁，也更容易维护。JavaScript 文件扩展名称为`.js`，您还可以在一些脚本文件夹中单独创建这些文件，并在我们的 HTML 页面中引用它们。

在 Visual Studio 中，您可以使用**添加** | **JavaScript 文件**选项轻松创建 JavaScript 文件，如下所示：

![将 JavaScript 添加到 HTML 页面](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00006.jpeg)

文件创建完成后，我们就可以直接编写 JavaScript 语法，而无需使用`<script></script>`标签。JavaScript 文件可以通过在 HTML 页面中使用`<script></script>`标签的`src`属性来引用。在这里，我们在 HTML 页面中引用了`test.js`：

```js
<script src="img/test.js">
</script>
```

将`<script>`标签放在`<head>`或`<body>`部分取决于页面。如果您的页面引用一些大的 JavaScript 文件需要很长时间来加载，最好将它们定义在`<body>`部分的末尾。这是一个更好的方法，因此当浏览器开始解析您的页面时，它不会因为下载脚本而卡住，导致渲染延迟。另一方面，我们只有在它们不会影响性能或页面生命周期的情况下，才能在`<head>`部分定义 JavaScript 文件。在底部定义的脚本在整个页面加载后进行解析。我们还可以在`<script>`标签内使用一些属性，如`async`和`defer`，大多数浏览器支持这些属性。

以下是一个使用`async`在`<script>`标签中的示例：

```js
<script src="img/test1.js" async></script>
<script src="img/test2.js" async></script>
```

使用`async`定义的脚本异步执行，不会阻塞浏览器加载页面。然而，如果存在多个脚本，那么每个脚本都将异步执行且同时进行。这可能导致第二个脚本在第一个脚本完成之前就完成了，如果其中一个脚本依赖于另一个脚本，可能会抛出一些错误。例如，当使用某些客户端框架时，如 Angular 框架，使用 Angular 组件的 JavaScript 代码依赖于 AngularJS 库；在这种情况下，如果我们的自定义 JS 文件在它们依赖的 AngularJS 库之前被加载，它们将会抛出一个异常。

为了克服这种情况，我们可以使用`defer`按顺序执行脚本。我们可以这样使用`defer`：

```js
<script src="img/test1.js" defer></script>
<script src="img/test2.js" defer></script>
```

`async`和`defer`之间的基本区别是，`async`在 HTML 解析期间下载文件，并在完全下载后暂停 HTML 解析器执行它，而`defer`在 HTML 解析期间下载文件，并在 HTML 解析器完成后执行它。

### JavaScript 中的语句

语句是执行特定任务的单词、表达式和操作符的集合。与其他编程语言一样，JavaScript 中的语句也可以是给变量赋值、执行算术操作、实现条件逻辑、遍历集合等。

例如：

```js
var a; //variable declaration
a = 5; //value assignment
a = 5 * b; //value assignment
a++; // equivalent to a= a+1
a--; // equivalent to a= a-1
var method = function () { … } // declare function
alert("Hello World") // calling built-in function
if(…) {…} else {…}
for (…) {…}
while(…) {…}
```

然而，您可以在`do while`循环中使用分号：

```js
do {…} while (…);
function statement
function (arg) { //to do }
```

### 提示

如果同一行中定义了多个语句，它们应该用分号分隔，否则它们将被视为一个语句。在不同行中，分号不是必须的，但使用分号是一个好习惯。

### 字面量和变量

JavaScript 中有两种类型的值：字面量或固定值和变量。

字面量可以是数字、字符串或日期对象。

例如：

```js
Numbers
22.30
26
Strings
"John"
"10/Jan/2015"
```

变量用于存储值。在 JavaScript 中，我们可以使用`var`关键字定义变量。JavaScript 不是一种类型安全的语言，变量的类型在分配值时确定。

例如：

```js
var x=6;
var x="Sample value";
```

### 数据类型

每种编程语言都有特定的数据类型可用于存储特定数据。例如，在 C#中，我们可以使用`String`来存储字符串值，`int`来存储 32 位整数值，`DateTime`来存储日期和时间的值等等。JavaScript 没有提供像 C#和其他编程语言那样的强数据类型，它是一种松散类型的语言。根据最新的 ECMA 6 标准，JavaScript 提供了六个原始数据类型和一个对象。所有的原始数据类型都是不可变的，这意味着分配新值将会分配到单独的内存中。对象是可变的，其值可以被改变。

原始类型如下：

+   **Boolean**: 这持有逻辑值`true`或`false`。

+   **Null**: 这持有`null`值。

+   **Undefined**: 这是没有分配值并且值为 undefined 的变量。

+   **Number**: 这持有数值。`number`类型的尺寸是双精度 64 位，其中数值（分数）从 0 存储到 51 位，指数从 52 存储到 62 位，符号位是 63 位。

+   **String**: 这持有任何类型的文本值。

复杂类型被称为**对象**。在 JavaScript 中，对象是以 JSON 格式编写的。

#### JavaScript 中的数组

数组用于存储数据集合。你可以在 JavaScript 中简单地定义一个数组，如下所示：

```js
var browsers = ["Microsoft Edge", "Google Chrome", "Mozilla Firefox", "Safari"];
```

你可以通过数组索引来访问它们。索引从 0 开始，直到数组中的项目数。

我们可以如下访问数组项目：

```js
var a= browsers[0]; //returns Microsoft Edge
var b= browsers[1]; //returns Google Chrome
var c= browsers[3]; //returns Safari
```

为了获取数组中项目总数，你可以使用`length`属性：

```js
var totalItems = browsers.length;
```

以下是一些最常用方法的列表：

| 方法 | 描述 |
| --- | --- |
| `indexOf()` | 这会返回数组中等于特定值的元素的第一个索引，如果没有找到则返回`-1`。 |
| `lastIndexOf()` | 这会返回数组中等于指定值的元素的最后一个索引，如果没有找到则返回`-1`。 |
| `pop()` | 这会从数组中删除最后一个元素并返回那个元素。 |
| `push()` | 这会在数组中添加一个元素并返回数组长度。 |
| `reverse()` | 这会反转数组中元素的顺序。第一个元素变成最后一个，最后一个元素变成第一个。 |
| `shift()` | 这会删除第一个元素并返回那个元素。 |
| `splice()` | 这用于向数组中添加或删除元素。 |
| `toString()` | 这会返回所有元素的字符串表示。 |
| `unshift()` | 这会将元素添加到数组的前端并返回新长度。 |

### 提示

**下载示例代码**

下载代码包的详细步骤在本书的前言中提到。请查看。

本书的代码包也托管在 GitHub 上，地址为[`github.com/PacktPublishing/JavaScript-For-.NET-Developers`](https://github.com/PacktPublishing/JavaScript-For-.NET-Developers)。我们还有来自我们丰富书籍和视频目录的其他代码包，可在[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)找到。去看看吧！

### JSON 是什么？

**JavaScript 对象表示法**（**JSON**）是定义 JavaScript 中对象的轻量级、可交换格式。任何类型的对象都可以通过 JSON 定义，并用于构建通用数据结构。无论是简单对象、数组、嵌套数组还是复杂对象，都可以在 JSON 格式中处理。

#### JSON 中的简单对象

```js
person object that has three properties, namely name, email, and phone:
```

```js
var person = {
  "name" : "John Martin",
  "email": johnmartin@email.com,
  "phone": "201892882"
}
```

我们可以按以下方式访问这些对象属性：

```js
person.name;
person.email;
person.phone;
```

#### 在 JSON 中声明数组

以下代码片段显示了在 JSON 中声明数组的方式：

```js
var persons =
[{ 
  "name":"John",
  "email": "john@email.com",
  "phone":"201832882"
},
{
  "name":"Steve",
  "email": "steve@email.com",
  "phone":"201832882"
},
{
"name":"Smith",
"email": "smith@email.com",
"phone":"201832882"
}]
```

根据前面声明的数组，可以按以下方式访问：

```js
//returns name of the first item in the collection i.e. John
Persons[0].name
//returns email of the first item in the collection i.e. john@email.com
Persons[0].email
//returns name of the second item in the collection i.e. Steve
Persons[1].name
```

#### 在 JSON 中嵌套数据

JSON 格式可以轻松处理嵌套数组。让我们看看包含`employee`对象的复杂对象，该对象包含`Experiences`数组，该数组包含嵌套数组以持有项目，每个项目都有一个嵌套数组以持有每个项目中所使用的技术：

```js
var employee=
{
  "ID":"00333",
  "Name":"Scott",
  "DateOfJoining":"01/Jan/2010",
  "Experiences":[
    {
      "companyName":"ABC",
      "from":"Nov 2008",
      "to":"Oct 2009",
      "projects" :[
        {
        "title":"Sharepoint Migration",
        "noOfTeamMembers":5,
        "technologyUsed":[{"name":"SharePoint Server"}, {"name":"C#"}, {"name":"SQL Server"}]
        },
        {
        "title":"Messaging Gateway",
        "noOfTeamMembers":5,
        "technologyUsed":[{"name":"ASP.NET"}, {"name":"C#"}, {"name":"SQL Server"}]
        }
      ]
    },
    {
      "companyName":"XYZ",
      "from":"Nov 2009",
      "to":"Oct 2015",
      "projects" :[
        {
        "title":"ERP System",
        "noOfTeamMembers":5,
        "technologyUsed":[{"name":"ASP.NET"}, {"name":"C#"}, {"name":"SQL Server"}]
        },
        {
        "title":"Healthcare System",
        "noOfTeamMembers":4,
        "technologyUsed":[{"name":"ASP.NET"}, {"name":"C#"}, {"name":"SQL Server"}]
        }
      ]
    }
  ]
}
```

```js
First assign the string to the res variable:
```

```js
var res="Hello World";
```

然后将数字分配给同一个`res`变量：

```js
res= 2;
```

最后，将字符串`3`连接到持有以下数字的`res`变量中，但由于数值具有更高的优先级，结果值变成了`5`：

```js
var result = res + "3"
```

因此，无论最初分配给它的变量类型是什么，它都会根据赋值改变其类型，并动态处理转换。

## JavaScript 的元素

以下是我们在开始用 JavaScript 编程之前必须学习的 JavaScript 的一些重要元素。

### JavaScript 中的常量

JavaScript 中的常量可以用`const`关键字定义。常量是在编译时已知的不可变值，在整个程序的生命周期中值不会改变。

以下是显示常量变量赋值的 JavaScript 代码。当使用`const`时，不需要`var`，您只需使用`const`关键字即可声明常量值：

```js
const pi= 3.42
```

### 注释

注释可以用`//`和`/* */`添加。要注释单行，可以使用`//`，否则使用`/* */`来注释代码块。

以下是用 JavaScript 代码注释单行或代码块的方式：

```js
<script type="text/javascript">

function showInformation() {

  //var spObj = window.document.getElementById("spInfo");
  spObj.innerHTML =
    "Available Height: " + screen.availHeight + "<br>" +
    /*"Available Width: " + screen.availWidth + "<br>" +
    "Height: " + screen.height + "<br>" +*/
    "Width: " + screen.width + "<br>"
}

</script>
```

### 大小写敏感性

JavaScript 是一种大小写敏感的语言，它遵循 Pascal 命名约定来定义变量和方法。

例如，如果方法名是`doWork()`，只能通过以确切的大小写调用它，而调用`DoWork()`或`Dowork()`将不起作用并抛出异常。

### 字符集

JavaScript 基于 Unicode 字符集，并遵循 Unicode 标准。

### 注意

**什么是 Unicode 标准？**

它是一个全球编码标准，大多数语言都会使用。C# 和 VB.NET 遵循相同的 Unicode 标准。它为每一个字符提供了一个唯一的数字，例如，`A = 41`，`a = 61`，等等。

当前的 Unicode 标准版本是 Unicode 8.0.0，相关文档可访问 [`www.unicode.org/versions/Unicode8.0.0/`](http://www.unicode.org/versions/Unicode8.0.0/)。

## 表达式

表达式可以被认为是将某些值赋给变量的代码语句。表达式分为两种类型。

第一种表达式可以称为简单表达式，它将值赋给变量：

```js
var x = 2;
```

前一个示例表示将数值 `2` 赋给变量 `x` 的简单表达式。

第二种类型的表达式可以称为对右侧值进行任何算术或字符串操作，并将它们赋给任何变量。这类表达式在赋值给变量之前先执行操作：

```js
var x = 2+3
var x = "Hello" + "World";
```

这是第二种类型的表达式的示例，它将两个数字相加，并将结果值赋给 `x` 变量。第二个语句执行字符串连接操作，并将 `Hello World` 值赋给 `x` 变量。

### 这个关键字

就像 C# 和其他面向对象的语言一样，JavaScript 也有对象，并且有一些定义类、函数等等的方法，我们将在本章后面学习。就像在 C# 中一样，在 JavaScript 中，我们可以通过 `this` 关键字访问对象及其属性。让我们看看一些显示 JavaScript 中 `this` 关键字作用域的例子。

以下是一个包含几个属性和 `this` 关键字使用的 `customer` 对象：

```js
var customer =
  {
    name: "John Marting",
    email: "john@xyz.com",
    mobile: "109293988844",
    show: function () {
      alert("Name: "+this.name + " Email: " + this.email + " Mobile: " + this.mobile);
    }
  }
```

在前一个例子中，我们定义了一个包含三个属性和一个函数的 JavaScript 对象。要访问这些属性，我们可以像在 C# 中一样使用 `this` 关键字。然而，我们也可以使用 `customer` 变量来访问属性，如下所示：

```js
var customer =
  {
    name: "John Marting",
    email: "john@xyz.com",
    mobile: "109293988844",
    show: function () {
      alert("Name: "+ customer.name + " Email: " + customer.email + " Mobile: " + customer.mobile);
    }
  }
```

`this` 关键字的范围限制在对象的范围之内。然而，在前一个例子中的 `customer` 变量可能定义在页面的其他地方，可能导致不当的行为。尽可能使用 `this` 关键字并避免直接使用对象变量是一个更好的方法。

直接定义在 `<script>` 标签下的所有变量和函数称为全局变量和函数。我们也可以通过 `this` 关键字访问它们。在这种情况下，`this` 将被称为全局窗口对象，而不是前面例子中使用的子对象，即 `customer` 对象：

```js
<script type="text/javascript">
  var name = "";

  function ShowMessage() {
    alert(this.name);
  }
</script>
```

```js
alert(window.name);
```

让我们看看完整的示例，其中我们定义了全局变量，以及子对象，`this` 的作用域将根据其调用的上下文来确定：

```js
<script type="text/javascript">
  var name = "Scott Watson";

  var customer =
    {
      name: "John Marting",
      email: "john@xyz.com",
      mobile: "109293988844",
      show: function () {
        alert("Name: " + this.name + " Email: " + this.email + " Mobile: " + this.mobile);
      }
    }
  function ShowMessage() {
    alert("Global name is " + this.name);
    alert("Customer info is " + customer.show());
  }
</script>
```

在前面的示例中，我们将收到两个 JavaScript 警告消息。第一个警告将显示**Scott Watson**，它是全局定义的，第二个弹出窗口显示客户姓名、电子邮件地址和手机号码。因此，我们可以在两个地方使用`this`，但作用域是根据它从中调用的上下文确定的。

### 在 JavaScript 中的代码执行顺序

在 JavaScript 编程中，我们必须保持定义事物的顺序，然后再调用它们。考虑前面的示例，如果我们定义`customer`对象在`ShowMessage()`方法之后，它将不会被识别，什么也不会显示。

### 在调用方法上使用 this 关键字

让我们来看看一个名为`Multiply`的示例 HTML 页面，它有一个 JavaScript 函数，接受两个参数：`obj`和`val`。当用户在文本框中输入任何内容时，此方法将被调用，并将文本框控件的引用作为第一个参数传递。可以通过`this`关键字传递：

```js
<html>
<head>
  <script type="text/javascript">
    function Multiply(obj, val) {
      alert(obj.value * val);
    }
  </script>
</head>
<body>
  <input type="text" onchange ="Multiply(this, 2);" />
</body>
</html>
```

### 函数声明和表达式

函数声明是定义 JavaScript 中方法的一种方式。每个函数都有一个签名，包括名称和传入的参数。在 JavaScript 中，函数可以通过多种方式声明。例如，以下是`GetPerson(id)`函数的示例，该函数根据作为参数传递的 ID 返回`person`对象。这是在 JavaScript 中声明函数的正常方式：

```js
<script>

  function GetPerson(id) {
    return service.GetPerson(id);
  }

</script>
```

`function` 的返回类型是在运行时计算的，而不是函数签名的一部分。返回值不是强制的，你可以保持函数不返回任何值。

另一方面，匿名函数没有名称，它们可以作为其他函数的参数传递，或者没有函数名称定义。以下是无名函数的示例：

```js
var showMessage = function(message){
  console.log(message);
}
showMessage("Hello World");
```

定义匿名函数并将其作为参数传递的另一个示例如下：

```js
function messageLogger(message ,logMessage) {
  logMessage();
}

function consoleMessage() {
  alert("Hello World");
}
messageLogger(consoleMessage());
```

函数表达式与函数等价，唯一的区别是它不应该以函数名开始。

### 类声明和表达式

随着 ECMAScript 6，我们可以在 JavaScript 中创建类。与其他编程语言一样，我们可以使用`class`关键字创建类。借助于此，我们可以比在 ECMAScript 的早期版本中用函数表示类的方式写出更清晰的代码。

让我们来看看计算面积的`Rectangle`类：

```js
<script>
  class Rectangle {
    constructor(height, width) {
      this.height=height;
      this.width=width;
    }
    get Area() {
      return this.calcArea();
    }
    calcArea(){
      alert("Area is "+ this.height * this.width);
    }
  }
</script>
```

每个类应该有一个构造函数，如果指定了多个构造函数，则应该报错。类表达式是定义类的一种另一种方式。就像匿名函数一样，我们可以用类似的方式定义类。

让我们来看看前面定义的同一个类的示例：

```js
<script>
  var Rectangle = class{
    constructor(height, width) {
      this.height=height;
      this.width=width;
    }
    get Area() {
      return this.calcArea();
    }
    calcArea(){
      alert("Area is "+ this.height * this.width);
    }
  }
</script>
```

下一章将详细介绍类以及构建它们的属性和关键字。

### 分组运算符

对于任何算术表达式，JavaScript 使用**BODMAS**规则。优先级将首先给括号，然后是乘法、除法、加法和减法。分组运算符用于给表达式中任何成员的默认优先级更高的表达式更高的优先级。

例如：

```js
var a = 1;
var b = 2;
var c = 3;
var x = a + b * c;
```

结果`x`将是`7`，因为乘法有更高的优先级。然而，如果我们需要先进行加法呢？

我们可以像下面这样使用分组运算符，结果为`9`：

```js
var x = (a + b) * c;
```

### new

与 C#一样，`new`关键字用于在 JavaScript 中实例化任何对象。为了创建任何用户定义或预定义类型的实例，使用`new`关键字：

```js
var obj=new objectType();
```

### super

`super`关键字用于调用父对象的方法。在 C#中，我们使用`base`关键字来调用基类的方法或属性。在 JavaScript 中，我们可以这样使用：

```js
super.functionOnParent();
```

## 运算符

运算符是用来操作操作数值的对象。例如，`1 + 2`的结果是`3`，其中`1`和`2`是操作数，`+`是一个运算符。在 JavaScript 中，我们可以使用几乎所有的运算符来连接字符串，进行算术运算等。在本节中，让我们看看在 JavaScript 语言编程时我们可以使用哪些类型的运算符。

我们将在本节讨论以下运算符：

+   赋值运算符

+   算术运算符

+   一元运算符

+   比较运算符

+   逻辑运算符

+   位运算符

+   位移运算符

+   类型 of 运算符

+   空值运算符

+   删除运算符

+   杂项运算符

### 赋值运算符

赋值运算符表示为（`=`），并且赋值是从右到左进行的。

例如，`x=y`意味着`y`的值被赋给`x`。

### 算术运算符

以下是一系列你可以用来进行加法、减法、除法和乘法以及与赋值语句一起使用的算术运算符：

| 名称 | 运算符 | 意义 |
| --- | --- | --- |
| 加法 | `x + y` | `x`的值加上`y` |
| 减法 | `x – y` | `x`的值减去`y` |
| 除法 | `x / y` | `x`的值除以`y` |
| 乘法 | `x * y` | `x`的值乘以`y` |
| 取模运算符 | `x % y` | `x`的值除以`y`，返回余数 |
| 加法赋值运算符 | `x += y` | `x = x + y`，即`x`和`y`的值相加，结果赋值给`x` |
| 减法赋值运算符 | `x -= y` | `x = x - y`，即`x`和`y`的值相减，结果赋值给`x` |
| 乘法赋值运算符 | `x *= y` | `x = x * y`，即`x`和`y`的值相乘，结果赋值给`x` |
| 除法赋值运算符 | `x /= y` | `x = x / y`，即`x`的值除以`y`，结果赋值给`x` |
| 取模赋值运算符 | `x %= y` | `x = x % y`，即`x`的值除以`y`，余数赋值给`x` |
| 幂运算赋值 | `x **= y` | 即`x = x ** y`，`x`的值将 exponentially 乘以两次`y`并赋值给`x` |

### 一元运算符

一元运算符只与一个操作数一起使用。它可以用于递增、递减、取反等：

| 名称 | 运算符 | 意义 |
| --- | --- | --- |
| 递增运算符 | `x++` | `x`的值将增加`1` |
| 递减运算符 | `x--` | `x`的值将减少`1` |
| 逻辑补码运算符 | `!(x)` | 这将`x`的值取反 |

### 比较运算符

```js
number1 is equal to number2 and the summation of number1 and number2 is equal to number3 to return true:
```

```js
<script>
  function CheckNumbers(number1, number2, number3) {
    if ((number1 == number2) && ((number1 + number2) == number3)) {
      return true;
    }
  }
<script>
```

#### 逻辑或

```js
10, it will return true:
```

```js
<script>
  function AnyNumber10(number1, number2, number3) {
    if ((number1 ==10 || number2 == 10 || number3 ==10) {
      return true;
    }
  }
</script>
```

#### 逻辑非

```js
number1, number2, and number3 are equal to 10, the method will return false. If they are different, the return value will be true:
```

```js
<script>
  function AnyNumber10(number1, number2, number3) {
    return !(number1 ==10 && number2 == 10 && number3==10) {
    }
  }
</script>
```

### 按位运算符

按位运算符将每个数字或操作数视为二进制（`0`和`1`的组合）。每个数字都有特定的二进制对应。例如，数字`1`的二进制表示为`0001`，`5`表示为`0101`。

按位运算符对 32 位数字进行操作，任何数值操作数首先转换为 32 位数字，然后转换回 JavaScript 数字。

按位运算符在二进制中进行操作并返回数字结果。

例如，`x`是`1`，`y`是`9`。

`1`表示为`0001`。

`9`表示为`1001`。

#### 按位与

按位与表示为`&`，下面是操作数`1`和`9`的每位比较。如果每个位上的值都是`1`，结果将是`1`，否则为`0`：

| 数字 = 1 | 数字 = 9 | 结果 |
| --- | --- | --- |
| 0 | 1 | 0 |
| 0 | 0 | 0 |
| 0 | 0 | 0 |
| 1 | 1 | 1 |

在 JavaScript 代码中，我们可以如下使用它：

```js
<script>
  var a = "1";
  var b = "9";
  var c = a & b;
</script>
```

最后，结果值将是`0001`，等于`1`。

#### 按位或

按位或表示为`|`，下面是按位或的运算方式：

| 数字 = 1 | 数字 = 9 | 结果 |
| --- | --- | --- |
| 0 | 1 | 1 |
| 0 | 0 | 0 |
| 0 | 0 | 0 |
| 1 | 1 | 1 |

下面的代码片段展示了在 JavaScript 中的使用：

```js
<script>
  var a = "1";
  var b = "9";
  var c = a | b;
</script>
```

最后，结果值将是`1001`，等于`9`。

#### 按位非

按位非表示为`~`，它作用于单个操作数并反转每个二进制位。

例如，如果数字`9`表示为`1001`，它将转换为 32 位数字，然后按位非将其变为`11111111111111111111111111110110`，等于`-10`。

以下是一个代码片段：

```js
<script>
  var a = ~9;
</script>
```

#### 按位异或

按位异或表示为`^`，它与两个或更多操作数一起工作。

下面的表格展示了按位异或是如何进行的：

| 数字 = 1 | 数字 = 9 | 结果 |
| --- | --- | --- |
| 0 | 1 | 1 |
| 0 | 0 | 0 |
| 0 | 0 | 0 |
| 1 | 1 | 0 |

下面的代码片段展示了在 JavaScript 中的使用：

```js
<script>
  var a = "1";
  var b = "9";
  var c = a ^ b;
</script>
```

最后，结果值将是`1000`，等于`8`。

### 按位移位运算符

有三种按位移位运算符，如下：

+   按位左移运算符

+   按位右移运算符

#### 按位左移

它表示为`<<`，用于将位从右侧移到任何数字的二进制值。

例如，数字`9`表示为`01001`，如果我们使用位左移，结果值将是`10010`，从右边移动了一位。

以下代码片段展示了在 JavaScript 中的使用：

```js
<script>
  var a = 9;
  var result = a << 1;
</script>
```

最后，结果值将是`10010`，等于`18`。

#### 位右移

它表示为`>>`，用于将位从左侧移动到任何数字的二进制值。

例如，数字`9`表示为`1001`，使用位右移将结果值给出为`0100`。

以下代码片段展示了在 JavaScript 中的使用：

```js
<script>
  var a = "9";
  var result = a >> 1;
</script>
```

最后，结果值将是`0100`，等于`4`。

### 类型 of 操作符

这用于检查变量的类型是否为对象、未定义、数字等。在 JavaScript 中，我们可以这样使用：

```js
<script>
  if (typeof a=="number") {
    alert("this is a number");
  }
</script>
```

以下是 `typeof` 操作符可能返回的值列表：

| ```Value returned``` | 描述 |
| --- | --- |
| ```---``` | --- |
| ```"number"` | 如果操作数是一个数字 |
| ```"string"` | 如果操作数是一个字符串 |
| ```"boolean"` | 如果操作数是一个布尔值 |
| ```"object"` | 如果操作数是一个对象 |
| ```null``` | 如果操作数是 null |
| ```"undefined"` | 如果操作数未定义 |

### void 操作符

```js
void operator to display alert message when the link is clicked. Here, the alert expression is evaluated once the user clicks on the link:
```

```js
<html>
<head></head>
<body>
  <a href="javascript:void(alert('You have clicked!'));">
  </a>
</body>
</html>
```

当页面运行且用户点击链接时，将显示以下警告消息框：

![void 操作符](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00007.jpeg)

此外，在 `void` 方法内传递 `0` 作为表达式将不做任何事情：

```js
<html>
<head></head>
<body>
  <a href="javascript:void(0);">
  Do Nothing
  </a>
</body>
</html>
```

另一个例子是使用 `void` 添加两个数字，并返回给定操作数的 `undefined`：

```js
<script>
  var n1 = 6;
  var n2 = 7;
  var n3;
  var result = void (n3 = n1 + n2);
  alert ("result=" + result + "and n3 =" + n3);
</script>
```

### 删除操作符

`delete` 操作符用于删除对象及其属性，但不删除局部变量。以下示例展示了如何在 JavaScript 中使用 `delete` 操作符：

```js
var country = { id: 1, name: "USA" };

  delete country.id;

  alert(country.id);
```

调用 `country.id` 将返回 `undefined`，因为这在之前的语句中已经被删除。另一方面，如果我们删除 `country` 对象，它不会被删除并显示国家 ID 为 `1`：

```js
var country = { id: 1, name: "USA" };

  delete country;

  alert(country.id);
```

### 杂项操作符

```js
compareValues() function that takes two parameters, and an alert will be displayed stating whether both the parameters are equal or not equal:
```

```js
<script>
  function compareValues(n1, n2)
    (n1 == n2) ? alert("Both values are equal") : alert("Passed values are not equal");
</script>
```

#### 展开操作符

展开操作符表示为（`…`）。当期望在函数调用中传递多个参数时使用。

例如，如果你的函数需要五个参数，你可以一个接一个地传递这些值作为调用该方法时的参数值，或者将它们放在一个数组中，并通过展开操作符传递该数组。

以下代码片段展示了在 JavaScript 中的实际示例：

```js
function multipleArgs(a, b, c, d, e){
}
var args = [1,2,3,4,5]
multipleArgs(…args);
```

## 在 JavaScript 中的内置显示方法

以下是 JavaScript 中可用的显示方法，用于以不同形式向用户提供通知和消息。

### 显示消息

以下是三种弹出对话框类型：

+   警告消息框

+   确认消息框

+   提示消息框

#### 警告框

使用 `window.alert()`，我们可以弹出一个警告对话框：

```js
<!DOCTYPE html>
<html>
<body>

  <h1>My First Web Page</h1>
  <p>My first paragraph.</p>

<script>
  window.alert(5 + 6);
</script>

</body>
</html>
```

#### 确认框

使用`window.confirm()`，我们可以弹出一个确认对话框，返回用户所采取的事件结果。当确认对话框弹出时，它提供两个动作事件：**确定**和**取消**。如果用户点击**确定**，将返回`true`，否则返回`false`。以下代码展示了在您的 HTML 页面上使用确认对话框的方法。

```js
 saving a record:
```

```js
<!DOCTYPE html>
<html>
<body>

<script>
  var r = window.confirm("are you sure to save record");
  if(r==true){
    alert("Record saved successfully");
  }
  else {
    alert("Record couldn't be saved");
  }
</script>

</body>
</html>
```

#### 提示框

提示对话框在需要用户提供值的情况下使用。它可以在需要用户输入的条件下来使用。

下面的代码片段展示了在 JavaScript 程序中使用提示消息框的方法：

```js
<!DOCTYPE html>
<html>
<body>

<script>
  var name = window.prompt("Enter your name","N/A");
  if(name !=null){
    alert("hello "+ name "+, how are you today!");
  }
</script>

</body>
</html>
```

### 页面上的写入

我们可以使用`document.write()`方法在屏幕上写入任何内容。

下面的代码片段展示了在 JavaScript 中在网页上编写任何文本的方法：

```js
<!DOCTYPE html>
<html>
<body>
  <script>
  document.write("Hello World");
  </script>
</body>
</html>
```

### 向浏览器的控制台窗口写入

使用`console.log()`，我们可以将任何文本写入浏览器的控制台窗口。

下面的代码片段展示了在 JavaScript 中为了追踪或调试目的向浏览器控制台窗口写入文本的方法：

```js
<!DOCTYPE html>
<html>
<body>
  <h1>My First Web Page</h1>
  <p>My first paragraph.</p>
  <script>
  console.log("Entered into script execution context");
  </script>
</body>
</html>
```

## 浏览器对象模型在 JavaScript 中

JavaScript 提供了一些预定义的全局对象，您可以使用它们来操作 DOM、关闭浏览器等。以下是我们可以用来执行不同操作的浏览器对象：

+   窗口

+   导航器

+   屏幕

+   历史

+   位置

### 窗口

窗口对象指的是浏览器中打开的窗口。如果在 HTML 标记中定义了一些 iframes，将会创建一个单独的窗口对象。通过窗口对象，我们可以访问以下对象：

+   所有全局变量

+   所有全局函数

+   DOM

以下是一个从窗口对象访问 DOM 并访问文本框控制的示例。

### 文档

`window.document`返回文档对象，我们可以出于特定原因使用其属性和方法：

```js
<html>
<body>
  <input type="text" name="txtName" />
  <script>
  var textbox = Window.document.getElementById("txtName");
  textbox.value="Hello World";
  </script>
</body>
</html>
```

`window`对象本身包含许多方法，其中一些如下：

| 事件 | 描述 | 语法 |
| --- | --- | --- |
| 关闭 | 关闭当前窗口 | `window.close();` |
| 打开 | 打开新窗口 | `window.open();` |
| 移动 | 将窗口移动到指定的位置 | `window.moveTo();` |
| 调整大小 | 将窗口调整到指定的宽度和高度 | `window.resizeTo();` |

### 导航器

这个对象提供了关于浏览器的信息。当你需要根据浏览器版本运行特定的脚本或者对浏览器进行特定的操作时，它是有益的。我们来看看它暴露的方法。

#### 属性

属性如下描述：

+   `appCodeName`：这返回浏览器的代码名称

+   `appName`：这返回浏览器的名称

+   `appVersion`：这返回浏览器的版本

+   `cookieEnabled`：这确定浏览器是否启用了 cookies

+   `geoLocation`：这获取访问页面的用户的位置

+   `language`：这返回浏览器的语言

+   `online`：这确定浏览器是否在线

+   `platform`：这返回浏览器编译的平台

+   `product`: 这返回浏览器的引擎名称。

+   `userAgent`: 这返回浏览器发送到服务器的主机代理头。

以下是一个示例代码：

```js
<!DOCTYPE html>
<html>
<head>
  <script type="text/javascript">
    function showInformation() {
      var spObj = window.document.getElementById("spInfo");
      spObj.innerHTML =
      "Browser Code Name: " + navigator.appCodeName + "<br>" +
      "Application Name: " + navigator.appName + "<br>" +
      "Application Version: " + navigator.appVersion + "<br>" +
      "Cookie Enabled? " + navigator.cookieEnabled + "<br>" +
      "Language: " + navigator.language + "<br>" +
      "Online: " + navigator.onLine + "<br>" +
      "Platform: " + navigator.platform + "<br>" +
      "Product: " + navigator.product + "<br>" +
      "User Agent: " + navigator.userAgent;
      navigator.geolocation.getCurrentPosition(showPosition);
    }
    function showPosition(position) {
      var spObj = window.document.getElementById("spInfo");
      spObj.innerHTML =  spObj.innerHTML + "<br> Latitude: " + position.coords.latitude +
      "<br>Longitude: " + position.coords.longitude;
    }
  </script>
</head>
<body onload="showInformation();">
  <span id="spInfo"></span>
</body>
</html>
```

输出如下所示：

![属性](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00008.jpeg)

### 屏幕

通过屏幕对象，你可以获取有关用户屏幕的信息。这有助于了解用户从哪个屏幕查看内容。如果是移动浏览器或标准桌面屏幕，你可以获取尺寸和其他信息，并按需修改内容。

#### 属性

属性如下描述：

+   `availHeight` : 这返回屏幕的高度。

+   `availWidth`: 这返回屏幕的宽度。

+   `colorDepth`: 这返回显示图像的颜色调色板比特深度。

+   `height`: 这返回屏幕的总高度。

+   `pixelDepth`: 这返回屏幕的颜色分辨率（每像素比特数）。

+   `width`: 这返回屏幕的总宽度。

示例代码如下：

```js
<!DOCTYPE html>
<html>
<head>
  <script type="text/javascript">
    function showInformation() {
      var spObj = window.document.getElementById("spInfo");
      spObj.innerHTML =
      "Available Height: " + screen.availHeight + "<br>" +
      "Available Width: " + screen.availWidth + "<br>" +
      "Height: " + screen.height + "<br>" +
      "Width: " + screen.width + "<br>"
    }
  </script>
</head>
<body onload="showInformation();">
  <span id="spInfo"></span>
</body>
</html>
```

输出如下所示：

![属性](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00009.jpeg)

### 历史

这包含用户访问的 URL。你可以通过`window.history`对象访问它。

你可以使用这个对象导航到最近访问的链接。

#### 方法

方法如下描述：

+   `Window.history.back()`: 这加载历史列表中的上一个 URL。

+   `Window.history.forward()`: 这加载历史列表中的最近 URL。

+   `Window.history.go()`: 这加载历史列表中特定的 URL。

### 位置

位置对象提供了关于当前 URL 的信息。就像历史一样，它也可以通过`window.location`访问。有一些方法和属性，你可以用来执行特定操作。

#### 属性

属性如下描述：

+   `window.location.host`: 这返回 URL 的主机名和端口号。

+   `window.location.hostname`: 这只返回 URL 的主机名。

+   `window.location.href`: 这提供完整的 URL。

+   `window.location.origin`: 这返回 URL 的主机名、端口号和协议。

+   `window.location.pathname`: 这返回 URL 的路径名。

+   `window.location.port`: 这返回 URL 的端口号。

+   `window.location.protocol`: 这返回 URL 的协议，例如 HTTP 或 HTTPS。

+   `window.location.search`: 这返回 URL 的查询字符串。

#### 方法

方法如下描述：

+   `window.location.assign()`: 这加载新文档。

+   `window.location.reload()`: 这重新加载当前 URL。

+   `window.location.replace()`: 这可以用来用新 URL 替换当前 URL。替换不会刷新页面，它只能改变 URL。

# 摘要

在本章中，我们讨论了 JavaScript 的基本概念以及如何在我们的网络应用程序中使用它。我们讨论了声明变量和实现数组、函数和数据类型的核心基础，以开始用 JavaScript 编写程序。在下一章中，我们将讨论一些关于面向对象编程的高级概念，以及与闭包、作用域和原型函数的实际应用一起工作。


# 第二章：高级 JavaScript 概念

JavaScript 在最初设计时，并没有预料到会成为 Web 开发的核心编程语言。它通常被用来执行一些基本的客户端操作，这些操作需要对**文档对象模型**（**DOM**）元素进行一些操作。后来，随着 Web 开发的最近步伐，事情已经发生了很大的变化。现在，许多应用程序纯粹使用 JavaScript 和 HTML 来处理复杂的情况。有时，随着不同版本的出现，增加了不同的特性，根据 ECMAScript 6 的规范，你现在可以有类，可以进行继承，就像你用 C#或 Java 任何其他编程语言一样。闭包、原型函数、属性描述符等等，我们将在本章讨论的内容，使它更加强大和健壮。

在上一章中，我们学习了 JavaScript 编程的核心概念和一些基本的基本原理，以及它作为一门语言提供的特性。在本章中，我们将重点关注更高级的主题，这些主题有助于我们在大型和复杂的应用程序中使用这些概念。

我们还将重点关注作用域和提升变量、面向对象编程、原型函数、属性描述符、闭包、异常处理等。一些主题，如承诺、异步模式和**异步 JavaScript 和 XML**（**Ajax**）技术，是更广泛的主题，在其他章节中进行覆盖。

# 变量 - 作用域和提升

我们已经知道如何在 JavaScript 中使用`var`关键字声明变量。任何使用`var`关键字声明的变量都被称为提升变量，*提升*是 JavaScript 的默认行为，将声明移动到顶部。当 JavaScript 通过 JavaScript 引擎编译时，所有使用`var`关键字声明的变量都放在其作用域的顶部。这意味着如果变量在函数块内声明，它将被放在函数顶部；否则，如果它声明在任何函数之外并在脚本的根部，它将变得全局可用。让我们看看这个例子来澄清我们的理解。

假设以下代码是一个简单的程序，它返回传递给函数参数的国家名称的 GMT：

```js
function getCountryGMT(countryName) {
  if (countryName == "Pakistan") {
    var gmt = "+5.00";
  }
  else if (country == "Dubai") {
    var gmt = "+4.00";
  } else {
    return null;
  }
}
```

当 JavaScript 引擎编译脚本时，`var gmt`变量将被放在顶部：

```js
function getCountryGMT(countryName) {
  var gmt; 
  if (countryName == "Pakistan") {
    gmt = "+5.00";
  }
  else if (country == "Dubai") {
    gmt = "+4.00";
  } else {
    return null;
  }
}
```

这称为提升，其中`var`变量被放在其作用域的顶部。此外，如果您尝试在最后一个`else`条件中访问变量值，它将给出一个未定义的值，并且在每个条件块中都可能可用。

这段代码显示了另一个声明`gmt`变量全局和在代码底部声明的例子：

```js
function getCountryGMT(countryName) {
  if (countryName == "Pakistan") {
    gmt = "+5.00";
  }
  else if (country == "Dubai") {
    gmt = "+4.00";
  } else {
    return null;
  }
}

var gmt;
```

当脚本编译时，它将在代码顶部放置`gmt`的声明：

```js
var gmt;

function getCountryGMT(countryName) {
  if (countryName == "Pakistan") {
    gmt = "+5.00";
  }
  else if (country == "Dubai") {
    gmt = "+4.00";
  } else {
    return null;
  }
}
```

为了克服 ECMAScript 6 中的这种行为，引入了一个新的 `let` 关键字来声明变量，其作用域保留在定义的位置。这些变量在其作用域外不可访问。

### 提示

请注意，ECMAScript 6 不被老旧的浏览器版本支持，但 Microsoft Edge、Google Chrome 11 和 Mozilla Firefox 支持它。

## 声明 `let` 变量

与 `var` 一样，你可以用 `let` 以相同的方式声明变量。你可以在你的程序中使用这个关键字，但它将仅在其定义的作用域内可访问。所以，例如，如果某个变量在条件块内定义，它将无法在其作用域之外访问。

让我们来看以下示例，其中在条件块内部声明了一个变量，在编译后的最终输出保持不变。这在您想在一个特定逻辑或场景内声明变量的条件下非常有用。在 `else` 条件中，`gmt` 将不可访问，因为它是在 `if` 条件内定义的：

```js
function getCountryGMT(countryName) {
  if (countryName == "Pakistan") {
    let gmt = "+5.00";
  }
  else {
    return null;
  }
}
```

一旦在函数或脚本的作用域内声明了 `let` 变量，它就不能被重新声明。另外，如果使用 `var` 关键字声明变量，则不能使用 `let` 重新声明。

这段代码不会抛出异常，因为作用域不同。然而，在同一块中，它不能被重新声明：

```js
function getCountryGMT(countryName) {
  var gmt;
  if (countryName == "Pakistan") {
    let gmt = "+5.00";
  }
  else {
    return null;
  }
}
```

### 在使用 `let` 关键字时效率较高的条件

以下是使用 `let` 的条件。

#### 循环中的函数

如果在循环中的函数内部使用 `var` 变量，这些变量会产生问题。考虑以下示例，其中有一个值数组，并通过循环在每个数组的索引处插入一个函数。这将导致错误并将 `i` 变量作为引用传递。所以，如果你遍历每个索引并调用函数，将会打印出相同的值，即 `10`：

```js
var values = [];
for(var i=0;i<10;i++)
  {
    values.push(function () { console.log("value is " + i) });
  }
  values.forEach(function(valuesfunc) {
    valuesfunc();
  })
```

```js
let is as follows:
```

```js
var values = [];
  for(let i=0;i<10;i++)
  {
    values.push(function () { console.log("value is " + i) });
  }
  values.forEach(function(valuesfunc) {
    valuesfunc();
  })
```

# JavaScript 中的事件

事件在任何一个商业应用程序中扮演着重要的角色，你希望在按钮点击事件上保存记录，或者显示一些消息，或者改变某个元素的背景颜色。这些事件可以从控件级别本身定义，或者通过脚本直接注册。

让我们来看一个例子，当鼠标进入时，这个例子会改变 `div` 控件内部的 `html` 代码：

```js
<html>
  <body>
    <div id="contentPane" style="width:200px; height:200px;">
    </div>
    <script>
      var divPane = document.getElementById("contentPane");
      divPane.onmouseenter = function () {
        divPane.innerHTML = "You are inside the div";
      };
      divPane.onmouseleave = function () {
        divPane.innerHTML = "You are outside the div";
      };
    </script>
  </body>
</html>
```

前面的示例在 HTML `div` 控件的脚本侧注册了两个事件。如果鼠标进入了函数或离开了 `div` 的边界，它会改变文本。另外，我们也可以在控件本身上注册事件，这个示例展示了如何在按钮点击事件上显示一条消息。如果你注意到脚本块是在 `div` 面板之后定义的，原因是当页面加载时，它会尝试执行脚本并抛出一个错误，因为当时 `contentPane` 元素尚未创建：

```js
<html>
  <body>
    <script>
      function displayMessage() {
        alert("you have clicked button");
      }
    </script> 
    <input type="button" onclick="displayMessage();" />
  </body>
</html>
```

在这个例子中，脚本块定义在页面的顶部。在这种情况下，它可以定义在页面的任何位置，因为它只有在用户点击按钮时才会执行。

# 函数参数

我们已经知道 JavaScript 函数可以有参数。然而，在创建函数时无法指定参数的类型。JavaScript 在调用函数时既不会对参数值进行类型检查，也不会验证传递的参数数量。所以，例如，如果一个 JavaScript 函数接受两个参数，像这段代码所示，我们甚至可以不传递任何参数值，或者传递任何类型的值，或者传递比定义的预期参数数量更多的值：

```js
function execute(a, b) {
  //do something
}

//calling without parameter values
execute();

//passing numeric values
execute(1, 2);

//passing string values
execute("hello","world");

//passing more parameters
execute(1,2,3,4,5);
```

缺少的参数被设置为未定义，而如果传递了更多参数，这些参数可以通过 arguments 对象访问。arguments 对象是 JavaScript 中的一个内置对象，它包含了一个数组，该数组是在调用函数时使用的参数。我们可以像这段代码中这样使用它：

```js
function execute(a, b) {
  //do something
  alert(arguments[0]);
  alert(arguments[1]);
  alert(arguments[2]);
  alert(arguments[3]);
  alert(arguments[4]);
}

  //passing more parameters
  execute(1, 2, 3, 4, 5);
}
```

参数按值传递；这意味着如果在函数内部改变了参数的值，它将不会改变原始参数的值。

# 在 JavaScript 中的面向对象编程

所有的 JavaScript 对象都是从某个对象继承来的。JavaScript 提供了不同的模式，以便在构建应用程序时遵循**面向对象编程**（**OOP**）原则。这些模式包括构造器模式、原型模式和对象字面量表示法，以及 ECMAScript 6 中通过类和使用 `extends` 关键字继承基类来表示对象的一种完全新的方式。

在本节中，我们将了解如何使用不同的方法实现 OOP 原则。

## 创建对象

类表示对象的结构，每个类都有某些由对象使用的方法和属性，而对象是类的实例，被称为类实例。

JavaScript 是一种基于原型的语言，并且基于对象。在像 C# 和 Java 这样的类式语言中，我们必须首先定义一个包含一些方法和属性的类，然后使用其构造函数来创建对象。在 JavaScript 中，任何对象都可以作为模板来创建新对象，并使用其中定义的属性或方法。新对象也可以定义自己的属性或方法，并可以作为另一个对象的原型。然而，ECMAScript 6 在 JavaScript 中引入了类，这是对现有范式的语法糖，使开发者能够更容易地编写更简单、更干净的代码来创建对象。在下一节中，我们将看到在 JavaScript 中创建对象的不同方法。

### 使用对象字面量表示法定义对象

对象字面量是使用花括号括起来的由逗号分隔的名称值对列表。

对象字面量使用以下语法规则定义：

+   冒号将属性名与值分隔开来：

+   值可以是任何数据类型，包括数组字面量、函数和嵌套对象字面量：

+   每个名称值对之间用逗号与下一个名称值对分隔：

+   姓氏值对之后不应该包含任何逗号

以下是在对象字面量表示法中一个`person`对象的基本表示：

```js
var person = {id: "001", name: "Scott", isActive: true, 
  Age: 35 };
```

以下是用对象字面量表示法展示的`personModel`对象的另一种表示，其中包含`savePerson()`方法：

```js
var personModel = {id: "001", name: "Scott", isActive: true, 
  Age: 35, function: savePerson(){ //code to save person record } };
```

### 使用构造模式定义对象

在 JavaScript 中，可以使用函数来定义类。这段代码展示了用 JavaScript 定义客户类的一种简单方式：

```js
var person = new function(){};
```

前面的代码只是定义了一个空的类，有一个默认构造函数，没有属性和方法。可以使用 new 关键字来初始化对象，如下面的代码所示：

```js
var p1 = new person();
```

同一个函数可以用常规函数声明风格定义：

```js
function person(){};
```

使用常规函数声明，JavaScript 引擎知道在需要时获取函数。例如，如果您在脚本中在函数声明之前调用它，它会调用这个函数，而变量定义方法需要在调用它之前先声明变量。

#### 使用类关键字

ECMAScript 6 提供了一种新的定义类的方法，并引入了一个类关键字，可以像在其他编程语言中一样使用。这段代码是定义一个客户对象的表示。默认构造函数是`constructor()`，不带任何参数，可以根据需求用更多参数覆盖。每个类允许您定义只有一个构造函数，如果覆盖了构造函数，默认构造函数将不会用来实例化对象：

```js
class Person {
  constructor() { }
}
```

### 属性

属性用于存储和返回值。我们可以在初始化函数时定义属性，每次创建对象时这些属性都将可用。

#### 使用对象字面量表示法定义属性

属性可以在对象中定义为字面量字符串。例如，在这段代码中，有一个包含两个属性和一个方法的客户对象。这种方法的缺点是没有构造函数，我们无法限制用户在初始化对象时提供属性值。它可以设置为硬编码，如所示，或者在初始化对象后：

```js
var person = {
  id: "001",
  name:"Person 1",
  savePerson: function(){
  }

}
```

#### 使用构造模式定义属性

构造函数模式允许您定义参数，限制用户在实例化对象时传递属性值。考虑这个例子，它包含一个具有`id`和`name`两个属性的客户对象：

```js
var person = function(id, name){
  this._id = id;
  this._name = name;
}
```

`this`关键字指的是当前对象，在类内部调用时可以使用`this`来访问属性，或者通过实例变量，如下面的代码所示：

```js
var p1 = new person("001","Person 1");
console.log("Person ID: "+ p1.PersonID);
console.log("Person Name: "+ p1.name);
```

属性值也可以在初始化对象后设置，如下面的代码所示：

```js
var person = function(){
}
var p1 = new person();
p1.id="001";
p1.name="Person 1";
```

这段代码也代表了定义一个接受两个参数的人对象的相同方法。在下一节中，当我们处理原型时，我们将看到这种方法的局限性：

```js
function person(id, name){
  this.id = id;
  this.name = name;
  this.logToConsole: function(){
    console.log("Person ID is "+ this.id  +",Name: "+ this.name);
  };
}
```

#### 使用 setter/getter 在 ECMAScript 6 中定义属性

在 ECMAScript 6 中，有一种新的定义属性的方法，它遵循其他编程语言的标准方式：

```js
class Person {
  constructor(id, name) {
    this.id = id;
    this.name = name;
  }
}
var p1 = new person("001", "Person 1");
console.log ("Person ID: " + p1.id);
```

与这种方法不同，我们也可以使用`set`和`get`关键字定义 setter 和 getter。在 JavaScript 中定义类时，构造函数是可选的；如果没有定义构造函数，对象初始化时会调用默认构造函数`constructor()`。让我们看一个包含`personName`属性的例子，该属性用于 setter 和 getter：

```js
class Person {
  set Name(name) {
    this.personName = name;
  }
  get Name() {
    return this.personName;
  }
}
var p1 = new Person();
p1.Name = "Person 1";
console.log("personName " + p1.Name);
```

#### JavaScript 属性描述符

每个属性都有属性描述符，用于配置，其含义如下：

+   **Writable**：这个特性用于设置代码为只读或可写。`false`关键字使其只读，值不能被修改。

+   **Enumerable**：这个特性用于隐藏/显示属性，使其可访问或可序列化。将此属性设置为`false`，在遍历对象成员时不会显示属性，并且在使用`JSON.stringify`时也不会被序列化。

+   **Configurable**：这个特性用于`on`和`off`的配置更改。例如，将此属性设置为`false`将防止属性被修改或删除。

所有这些特性默认都是`true`，但可以被覆盖，如下例所示。这个例子有一个`car`对象，包含两个属性，分别是`name`和`color`：

```js
var car = {
  name: "BMW",
  color: "black"
};
```

##### 显示属性描述符

你可以使用以下语句显示现有属性：

```js
display(Object.getOwnPropertyDescriptor(car, 'name'));
```

##### 管理属性描述符

任何对象的属性都可以像以下代码那样进行管理：

```js
Object.defineProperty(car, 'color',{enumerable: false});
Object.defineProperty(car, 'color',{configurable: false});
Object.defineProperty(car, 'color',{writable: false});
```

##### 使用 getter 和 setter

通过`Object.defineProperty`，我们还可以为属性添加 setter 和 getter。这个例子通过连接`make`和`name`并分割`name`来添加汽车的完整名称，然后通过两个不同的属性获取模型和名称：

```js
var car = { name: { make: "honda",  brand: "accord"} };
Object.defineProperty(car, 'fullname', 
{
  get: function(){
    return this.name.make + ' ' + this.name.brand 
  },
  set: function (value) {
    var names= value.split(' ');
    this.name.make = names[0];
    this.name.brand = names[1];
  }
});
car.fullname = "Honda Accord";
display(car.fullname);
```

### 方法

方法是可以在对象上执行的动作。在 JavaScript 中，它可以表示为一个包含函数定义的属性。让我们看看定义 JavaScript 对象方法的不同方法。

#### 通过对象字面量表示法定义方法

以下是一个示例，展示了对象字面量表示法中定义的`logToConsole()`方法：

```js
var person = {
  id: "001",
  name:"Person 1",
  logToConsole: function()
  {
    console.log("Person ID is "+ this.id  +", Customer Name: "+ this.name);
  }
}
```

#### 使用构造函数函数定义对象

通过`constructor`函数定义方法的代码如下：

```js
var person = function (id, name) {
  this._id = id;
  this._name = name;
  this.LogToConsole= function(){
    console.log("Person Name is "+ this._name);
  }
}
var p1 = new person("001", "Person 1");
p1.LogToConsole();
```

另一种方法是声明`constructor`函数，如下所示：

```js
function person(id, name) {
  this._id = id;
  this._name = name;
  this.LogToConsole= function(){
    console.log("Name is "+ this._name);
  }
}
var p1 = new person("001","Person 1");
p1.LogToConsole();
```

在 ECMAScript 6 中，定义方法的语法更为优雅。以下是一个示例代码片段：

```js
class Person {

  constructor() {

  }

  set Name(name) {
    this._name = name;
  }

  get Name() {
    return this._name;
  }

  logToConsole() {
    console.log("Person Name is " + Name);
  }
}

var p1 = new Person();
p1.Name = "Person 1";
p1.logToConsole();
```

定义方法时不需要指定方法返回类型，它基于方法体实现。

### 扩展属性和方法

每个 JavaScript 对象都有一个称为原型的对象。原型是指向另一个对象的指针。这个原型可以用来扩展对象属性和方法。例如，如果你尝试访问一个对象的某个未定义属性，它会查看原型对象并通过原型链继续查找，直到找到或者返回 undefined。因此，无论使用字面量语法方法还是构造函数方法创建对象，它都会从称为`Object.prototype`的原型继承所有方法和属性。

例如，使用`new Date()`创建的对象从`Date.prototype`继承，依此类推。然而，基本对象本身没有原型。

我们可以很容易地向对象添加属性和函数，如下所示：

```js
var Person = function (name) {
  this.name = name;
}
var p1 = new Person("Person 1");
p1.phoneNo = "0021002010";
alert(p1.name);
```

不初始化对象而扩展现有函数是通过原型对象完成的。让我们来看这个例子，我们在`Person`函数上添加了一个方法`logToConsole()`和一个`phoneNo`属性：

```js
var Person = function (name) {
  this.name = name;
}
Person.prototype.phoneNo = "";
Person.prototype.logToConsole = function () {
  alert("Person Name is " + this.name +" and phone No is "+ this.phoneNo)
};
var p1 = new person("Person 1");
p1.phoneNo = "XXX"
p1.logToConsole();
```

### 私有和公共成员

在 JavaScript 中，没有像我们在 C#中那样的访问修饰符。所有定义为`this`或具有原型的一切成员都可以从实例中访问，而其他以某种其他方式定义的成员是不可访问的。

让我们来看这个例子，它只允许`y`和`y1()`方法在函数外部被访问：

```js
function a() {
  var x = 1;
  this.y = 2;
  x1 = function () {
    console.log("this is privately accessible");
  }
  this.y1 = function () {
    console.log("this is publicly accessible");
  }
}
```

### 继承

继承是面向对象编程的核心原则。在 JavaScript 中，如果你使用的是不遵守 ES6 标准的旧版本，它是通过基于原型的编程来实现的。

基于原型的编程是一种不使用类，而是通过原型链来扩展对象或继承的面向对象编程模型。这意味着每个对象都有一个内部的`prototype`属性，它指向一个特定的对象，如果没有使用则为 null。这个属性不能通过程序访问，并且对 JavaScript 引擎来说是`private`的。所以，例如，如果你调用某个属性，比如`customer.getName`，它会首先在对象本身上查找`getName`属性，否则通过原型属性链接对象来查找。如果没有定义属性，它会返回 undefined。

考虑以下**实体-关系模型**（**ERD**），它有一个具有某些通用属性的基本 person 对象和两个子对象，分别是**Vendor**和**Employee**，具有特定的属性：

![继承](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00010.jpeg)

为了用 JavaScript 构造函数方法表达相同的继承，我们可以像这段代码一样，将`Vendor`和`Employee`的`prototype`属性添加到 person 对象上：

```js
var Person = function (id, name) {
  this.id = id;
  this.name = name;
}

var Vendor = function (companyName, location) {
  this.companyName = companyName;
  this.location = location;
}

var Employee = function (employeeType, dateOfJoining) {
  this.employeeType = employeeType;
  this.dateOfJoining = dateOfJoining;
}

Vendor.prototype = new Person("001", "John");
Employee.prototype = new Person("002", "Steve");

var vendorObj = new Vendor("ABC", "US");
alert(vendorObj.id);
```

在前一个示例中，`vendorObj`是从`Vendor`构造函数创建的对象。`Vendor`构造函数既是对象又是函数，因为函数在 JavaScript 中是对象，而`vendorObj`对象可以有自己的属性和方法。它还可以从`Vendor`对象继承方法和属性。

通过构造函数将`Vendor`和`Employee`对象的`prototype`属性设置为`Person`实例，它继承了`Person`对象的属性和方法，并成为`Vendor`和`Employee`对象可访问的。

使用`prototype`对象定义的对象属性和方法被所有引用它的实例所继承。因此，在我们的例子中，我们通过`prototype`属性扩展了`Vendor`和`Employee`对象并将它们分配给`Person`实例。这样，无论何时创建`Vendor`或`Employee`对象的任何实例，它都可以访问`Person`对象的属性和方法。

还可以通过对象添加属性和方法；例如，我们可以向`Vendor`对象添加一个属性，如下面的代码所示，但这将变成静态属性，`Vendor`实例无法访问：

```js
Vendor.id="001";
```

另一方面，我们也可以向`Vendor`实例添加属性和方法，但这将仅对该特定实例可用：

```js
var vendorObj = new Vendor("ABC", "US");
vendorObj.id="001";
```

实现继承的另一种技术是通过将父对象的`prototype`分配给子对象的`prototype`对象，如下所示：

```js
Vendor.prototype = Person.prototype; 
```

使用这种技术，在`Person`原型中添加的任何方法或属性都将可通过`Vendor`对象访问：

```js
var Person = function (id, name) {
  this.id = id;
  this.name = name;
}

//Adding method to the Person's prototype to show message
Person.prototype.showMessage = function (message) {
  alert(message);
}

var Vendor = function (companyName, location) {
  this.companyName = companyName;
  this.location = location;
}

//Assigning the parent's prototype to child's prototype
Vendor.prototype = Person.prototype;
var vendorObj = new Vendor("XYZ", "Dubai");
vendorObj.showMessage(vendorObj instanceof Person);
```

运行此脚本后，它将在警告消息中显示`true`。这是因为`Vendor`对象成为`Person`对象的实例，并且在任何对象中添加的任何方法或属性都可以被两个对象访问。

如果我们修改前面的示例，在将`Person`原型分配给`Vendor`原型之后，通过`Vendor`原型属性添加另一个方法，它将可通过`Person`对象访问。这是因为，在 JavaScript 中，当子对象的原型被设置为父对象的原型时，在分配后添加到任一对象中的任何方法或属性都将可通过两个对象访问。

让我们在`Vendor`对象中通过`prototype`属性添加一个`showConsoleMessage()`方法，并通过`Person`实例访问它，如这段代码所示：

```js
var Person = function (id, name) {
  this.id = id;
  this.name = name;
}

//Adding method to the Person's prototype to show message
Person.prototype.showMessage = function (message) {
  alert(message);
}

var Vendor = function (companyName, location) {
  this.companyName = companyName;
  this.location = location;
}

//Assigning the parent's prototype to child's prototype
Vendor.prototype = Person.prototype;

//Adding method to the Vendor's prototype to show at console
Vendor.prototype.showConsoleMessage = function (message) {
  console.log(message);
}

var personObj = new Person("001", "John");
//Person object access the child's object method
personObj.showConsoleMessage("Console");
```

#### JavaScript 中的构造函数链

在前面的例子中，我们看到了如何继承对象。然而，如果某个基对象有一些重载构造函数，接受属性将需要一些额外的努力。JavaScript 中的每个函数都有一个`call`方法，用于将构造函数链接到对象。我们可以使用`call`方法来链接构造函数并调用基构造函数。因为`Person`对象接受两个参数，我们将修改`Vendor`函数和两个属性`id`和`number`，在创建`Vendor`对象时可以传递这些属性。所以，无论何时创建`Vendor`对象，都会创建`Person`对象并填充值：

```js
var Person = function (id, name) {
  this.id = id;
  this.name = name;
}

var Vendor = function (companyName, location, id, name) {
  this.companyName = companyName;
  this.location = location;
  Person.call(this, id, name);
}

var employee = function (employeeType, dateOfJoining, id, name) {
  this.employeeType = employeeType;
  this.dateOfJoining = dateOfJoining;
  Person.call(this, id, name);
}

Vendor.prototype = Person.prototype;
Employee.prototype = Person.prototype;

var vendorObj = new Vendor("ABC", "US", "V-01","Vendor 1");
alert(vendorObj.name);
```

#### 使用`Object.create()`继承

使用 ECMAScript 5，你可以通过`Object.create()`方法轻松地继承你的基对象。这个方法接受两个参数，一个作为原型的对象和一个包含新对象应具有的属性和方法的对象。`Object.create()`方法改进了基于构造函数的继承。它是一个创建对象而不必通过其构造函数的好方法。让我们看看使用`Object.create()`方法的`Vendor`和`Employee`继承`Person`对象的示例：

```js
var Person = function (id, name) {
  this.id = id;
  this.name = name;
}

var Vendor = function (companyName, location, id, name) {
  this.companyName = companyName;
  this.location = location;
  Person.call(this, id, name);
}

var Employee = function (employeeType, dateOfJoining, id, name) {
  this.employeeType = employeeType;
  this.dateOfJoining = dateOfJoining;
  Person.call(this, id, name);
}

Vendor.prototype = Object.create(Person.prototype);
Employee.prototype = Object.create(Person.prototype);

var vendorObj = new Vendor("ABC", "US", "V-01", "Vendor 1");
alert(vendorObj.name);
```

在前面的例子中，我们使用了`Object.create()`来继承`Person`对象到`Vendor`和`Employee`对象。无论何时创建`Vendor`或`Employee`实例，它们都可以访问`Person`对象的属性。`Object.create()`方法自动实例化其在`call`方法中定义的参数的对象实例。

#### `Object.create()`的预定义属性

`Object.create()`方法不会执行`Person`函数；相反，它只是将`Person`函数设置为客户函数的原型。下面代码中展示了客户对象的另一种表示形式，包含一个名为`CustomerCode`的属性：

```js
var customerObj = Object.create(Object.prototype, {
  customerCode: {
    value: "001",
    enumerable: true,
    writable: true,
    configurable: true
  }
});
alert("" + customerObj.customerCode);
```

在这里，value 代表实际的用户代码值，而`enumerable`、`writable`和`configurable`是预定义的属性。

#### 使用类定义继承

在前面的章节示例中，我们已经看到了如何使用 ECMAScript 6 定义类。就像 Java 一样，我们可以使用`extends`关键字来继承一个父类。

使用`extends`的一个示例在这里展示：

```js
class Person {

  constructor(id, name) {
    this._id = id;
    this._name = name;
  }

  get GetID() {return this._id;}
  get GetName() {return this._name;}
}

class Vendor extends Person {
  constructor(phoneNo, location, id, name){
    super(id, name);
    this._phoneNo = phoneNo;
    this._location = location;

  }
  logToConsole() {
    alert("Person ID is " + this.GetID);
  }
}

var vendorObj = new Vendor("XXX", "US", "V-01", "Vendor 1");
vendorObj.logToConsole();
```

有了 ECMAScript 6，你可以真正领略到在类中声明静态变量和方法的精髓。让我们看看下面的例子，其中包含一个静态方法`logToConsole()`，并且从继承`Person`类的客户类中调用它，而无需在继承后初始化其对象：

```js
class Person {
  static logToConsole() {
    console.log("Hello developers!");
  }
}

class Vendor extends Person {
}

Vendor.logToConsole();
```

### 封装

在上面的例子中，`Vendor`对象不需要知道`Person`类中`logToConsole()`方法的实现，并可以使用该方法。除非有特定的原因需要覆盖，否则`Vendor`类不需要定义这个方法。这称为封装，其中`Vendor`对象不需要知道`logToConsole()`方法的实际实现，每个`Vendor`对象都可以使用这个方法来记录到控制台。就是这样通过封装来完成的，每个类都被封装成一个单一的单元。

### 抽象

抽象用于隐藏与对象相关的所有信息，除了数据，以减少复杂性并提高效率。这是面向对象编程的核心原则之一。

在 JavaScript 中，没有内置的对抽象的支持，并且它不提供如接口或抽象类之类的类型来创建接口或抽象类以实现抽象。然而，通过某些模式，你可以实现抽象，但这种模式仍然不限制并确保所有抽象方法都被具体类或函数完全实现。

让我们来看一下下面的例子，其中我们有一个`person`控制器，它接受一个具体对象作为参数，然后调用其具体的实现：

```js
var person = function (id, name) {
  this._id = id;
  this._name = name;
  this.showMessage = function () { };
}
var vendor = function (companyName, location, id, name) {
  this._companyName = companyName;
  this._location = location;
  person.call(this, id, name);
  this.showMessage = function () {
    alert("this is Vendor");
  }
}
var employee = function (employeeType, dateOfJoining, id, name) {
  this._employeeType = employeeType;
  this._dateOfJoining = dateOfJoining;
  person.call(this, id, name);
  this.showMessage = function () {
    alert("this is Employee");
  }
}
vendor.prototype = Object.create(person.prototype);
employee.prototype = Object.create(person.prototype);
var personController = function (person) {
  this.personObj = person;
  this.showMessage = function () {
    this.personObj.showMessage();
  }
}

var v1 = new vendor("ABC", "USA", "V-01", "Vendor 1");
var p1 = new personController(v1);
p1.showMessage();
```

另外，借助 ECMAScript 6，我们可以实现同样的场景，如下面的代码所示：

```js
class person {
  constructor(id, name) {
    this._id = id;
    this._name = name;
  }
  showMessage() { };
}
class vendor extends person {
  constructor(companyName, location, id, name) {
    super(id, name);
    this._companyName = companyName;
    this._location = location;

  }
  showMessage() {
    alert("this is Vendor");
  }
}
class employee extends person {
  constructor(employeeType, dateOfJoining, id, name) {
    super(id, name);
    this._employeeType = employeeType;
    this._dateOfJoining = dateOfJoining;
  }
  showMessage() {
    alert("this is Employee");
  }
}
class personController {
  constructor(person) {
    this.personObj = person;
  }
  showMessage() {
    this.personObj.showMessage();
  }
}

var v1 = new vendor("ABC", "USA", "V-01", "Vendor 1");
var p1 = new personController(v1);
p1.showMessage();
```

### new.target

`new.target`属性用于检测函数或类是否使用`new`关键字调用。如果调用，它将返回对函数或类的引用，否则为`null`。考虑上面例子中的例子，我们可以通过使用`new.target`来限制创建`person`的`call`对象：

```js
class person {
  constructor(id, name) {
    if(new.target === person){
      throw new TypeError("Cannot create an instance of Person class as its abstract in nature");
    }
    this._id = id;
    this._name = name;
  }

  showMessage() { };
}
```

### 命名空间

ECMAScript 6 通过模块引入了命名空间，并使用`export`和`import`关键字，但它们仍然处于草案阶段，到目前为止没有实现。

然而，在早期版本中，可以通过局部对象来模拟命名空间。例如，下面是定义一个表示命名空间的局部对象的语法，我们可以在其中添加函数和对象：

```js
var BusinessLayer = BusinessLayer || {};
```

我们可以在上面显示的代码中添加函数：

```js
BusinessLayer.PersonManager = function(){
};
```

此外，还可以定义更多嵌套的命名空间层次，如下面的代码所示：

```js
var BusinessLayer = BusinessLayer || {};
var BusinessLayer.Managers = BusinessLayer.Managers || {};
```

## 异常处理

JavaScript 正在成为开发大型应用程序的强大平台，异常处理在处理程序中的异常和按需传播它们方面发挥着重要作用。就像 C#或其他任何编程语言一样，JavaScript 提供了`try`、`catch`和`finally`关键字来注解用于错误处理的代码。JavaScript 提供了使用嵌套的`try catch`语句和条件在`catch`块中处理不同条件的相同方式。

当一个异常发生时，会创建一个代表所抛出错误的对象。就像 C#一样，我们有不同类型的异常，如`InvalidOperationException`、`ArgumentException`、`NullException`和`Exception`。JavaScript 提供六种错误类型，如下所示：

+   `Error`

+   `RangeError`

+   `ReferenceError`

+   `SyntaxError`

+   `TypeError`

+   `URIError`

### `Error`

`Error`对象代表通用异常，主要用于返回用户定义的异常。一个`Error`对象包含两个属性，分别是 name 和 message。Name 返回错误类型，message 返回实际错误信息。我们可以抛出错误异常，如下所示：

```js
try{ }catch{throw new Error("Some error occurred");}
```

### `RangeError`

如果任何数字的范围被超出，将抛出`RangeError`异常。例如，创建一个负长度的数组将抛出`RangeError`：

```js
var arr= new Array(-1);
```

### `ReferenceError`

`ReferenceError`异常发生在访问一个不存在的对象或变量时；例如，以下代码将抛出一个`ReferenceError`异常：

```js
function doWork(){
  arr[0]=1;
}
```

### `SyntaxError`

正如名称所示，如果 JavaScript 代码中存在任何语法问题，就会抛出`SyntaxError`。所以，如果有些闭合括号缺失，循环结构不正确，等等，这都将归类为`SyntaxError`。

### 类型错误

当一个值不是期望的类型时，会发生`TypeError`异常。以下代码抛出一个`TypeError`异常，因为对象试图调用一个不存在的函数：

```js
var person ={};
person.saveRecord();
```

### URIError

当`encodeURI()`和`decodeURI()`中指定了一个无效的 URI 时，会发生`URIError`异常。以下代码抛出此错误：

```js
encodeURIComponent("-");
```

## 闭包

闭包是 JavaScript 最强大的特性之一。闭包提供了一种暴露位于其他函数体内内部函数的方式。当一个内部函数被暴露在包含它的函数外部，并且在外部函数执行后可以执行，并且可以使用外部函数调用时的相同局部变量、参数和函数声明时，一个函数可以被称为闭包。

让我们来看一下以下示例：

```js
function Incrementor() {
  var x = 0;
  return function () {
    x++;
    console.log(x);
  }
}

var inc= Incrementor();
inc();
inc();
inc();
```

这是一个简单的闭包示例，其中`inc()`成为引用内部函数的闭包，该内部函数增加外层函数中定义的`x`变量。`x`变量将在每次调用时增加，最后调用的值为`3`。

闭包是一种特殊类型的对象，它将函数和函数创建的环境结合起来。所以，多次调用它将使用相同的环境，以及在之前调用中更新的值。

让我们来看另一个示例，其中有一个表格生成函数，它接受一个表格号并返回一个函数，该函数可用于获取任何数字与提供的表格号相乘的结果：

```js
function tableGen(number) {
  var x = number;
  return function (multiplier) {
    var res = x * multiplier;
    console.log(x +" * "+ multiplier +" = "+ res);
  }
}

var twotable = tableGen(2);
var threetable = tableGen(3);

twotable(5);
threetable(6);
```

调用`twotable()`和`threetable()`方法后的结果值将是`10`和`18`。这是因为`twoTable()`函数对象是通过将`2`作为参数传递给`tableGen()`函数进行初始化的。当通过`twoTable()`和`threetable()`方法调用执行时，这个`tableGen()`函数将传递的参数值存储在`x`变量中，并将其与第二次调用传递的变量相乘。

因此，`twoTable(5)`函数调用的输出将是`10`，如下所示：

![闭包](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00011.jpeg)

第二条语句`threeTable(6)`的输出将是`18`，如下所示：

![闭包](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00012.jpeg)

### 实际使用

我们已经了解了闭包是什么以及我们如何实现它们。然而，让我们考虑它们的实际影响。闭包让你可以将某些环境与在那种环境或数据中操作的函数相关联。

在 JavaScript 中，函数大多在发生任何事件或用户执行任何操作时执行。让我们看看以下闭包在`console`和`dialog`窗口上实际使用示例，以记录消息：

```js
<body>
  <input type="text" id="txtMessage" />
  <button id="consoleLogger"> Log to Console </button>
  <button id="dialogLogger">Log to Dialog </button>
  <script>

    function getLogger(loggerType) {
      return function () {
        var message = document.getElementById("txtMessage").value;
        if (loggerType == "console")
        console.log(message);
        else if (loggerType == "dialog")
        alert(message);
      }
    }
    var consoleLogger = getLogger("console");
    var dialogLogger = getLogger("dialog");
    document.getElementById("consoleLogger").onclick = consoleLogger;
    document.getElementById("dialogLogger").onclick = dialogLogger;
  </script>
</body>
```

在前面的示例中，我们有两个日志闭包：一个记录到控制台，另一个记录到弹出对话窗口。我们可以初始化这些闭包，并在程序中使用它们来记录消息。

## JavaScript 类型数组

客户端开发在 JavaScript 已经成为一个强大的平台，并且有一些 API 和库可供使用，允许你与媒体文件、Web 套接字等进行交互，并在二进制中处理数据。当处理二进制数据时，需要将其保存在其特定的格式中。这时就轮到类型数组发挥作用了，它允许开发者在原始二进制格式中操纵数据。

### 类型数组架构

类型数组将数据分为两部分，即缓冲区和视图。缓冲区包含二进制中的实际数据，但没有视图无法访问。视图提供了有关缓冲区的实际元数据信息和上下文，例如数据类型、起始偏移量和元素数量。

#### 数组缓冲区

数组缓冲区是一种用于表示二进制数据的数据类型。在它被分配给一个视图之前，其内容无法被操纵。视图以特定格式表示缓冲区，并对数据执行操作。

有不同类型的类型数组视图，如下所示：

| 类型 | 字节大小 | 描述 |
| --- | --- | --- |
| `Int8Array` | 1 | 这是一个 8 位有符号整数数组。 |
| `UInt8Array` | 1 | 这是一个 8 位无符号整数数组。 |
| `Int16Array` | 2 | 这是一个 16 位有符号整数数组。 |
| `UInt16Array` | 2 | 这是一个 16 位无符号整数数组。 |
| `Int32Array` | 4 | 这是一个 32 位有符号整数数组。 |
| `UInt32Array` | 4 | 这是一个 32 位无符号整数数组。 |
| `Float32Array` | 4 | 这是一个 32 位 IEEE 浮点数数组。 |
| `Float64Array` | 8 | 此数组是 64 位的 IEEE 浮点数。 |
| `UInt8ClampedArray` | 1 | 此数组是 8 位无符号整数（夹紧）。 |

接下来，让我们通过一个示例来看看我们如何通过视图在缓冲区中存储数据并操作它。

#### 创建缓冲区

首先，我们需要创建一个缓冲区，如下面的代码所示：

```js
var buffer = new ArrayBuffer(32);
```

上述声明分配了 32 字节的内存。现在我们可以使用任意一种类型数组视图来操作它：

```js
var int32View= new Int32Array(buffer);
```

最后，我们可以像这样访问字段：

```js
for(var i=0;i< int32View.length; i++){
  int32View[i] = i;
}
```

这段代码将在视图中进行八个条目的操作，从`0`到`7`。输出将如下所示：

```js
0 1 2 3 4 5 6 7
```

同一个缓冲区也可以使用其他视图类型进行操作。例如，如果我们想要用一个 16 位数组视图读取已填充的缓冲区，结果将像这样：

```js
var Int16View =new Int16Array(buffer);
for(var i=0;i< int16View.length;i++){
  console.log(int16View[0]);
}
```

输出将如下所示：

```js
0 0 1 0 2 0 3 0 4 0 5 0 6 0 7 0
```

这就是我们如何可以轻松地使用多种不同类型的视图来操作单个缓冲区数据，并与包含多种数据类型的数据对象交互。

## 映射、集合、弱映射和弱集合

映射（Maps）、弱映射（weak maps）、集合（sets）和弱集合（weak sets）都是代表集合的对象。映射是键值对的键 ed 集合，而集合存储任何类型的唯一值。我们将在接下来的章节中讨论它们每一个。

### 映射和弱映射

`Map`对象提供了一个简单的键/值映射，并且根据插入的顺序进行迭代。首先插入的值将被首先检索。弱映射是不可枚举的，仅保存对象类型。在弱映射中不允许有原始类型，每个键代表一个对象。让我们看看以下使用映射作为货币的示例：

```js
var currencies = new Map();
currencies.set("US", "US Dollar");
currencies.set("UK", "British Pound");
currencies.set("CA", "Canadian Dollar");
currencies.set("PK", "Rupee");
currencies.set("UAE", "Dirham");
for (var currency of currencies) {
  console.log(currency[0] + " currency is " + currency[1]);
}
```

`Map`对象上可用的其他属性和方法如下所示：

```js
currencies.get("UAE"); // returns dirham
currencies.size; // returns 5 
currencies.has("PK") // returns true if found 
currencies.delete("CA") // delete Canada from the list
```

弱映射（weak maps）中保存的是对象，其键被表示为弱键（weak keys）。这是因为如果一个弱映射值中存储的对象没有被引用，并且在垃圾回收（garbage collection）时被回收，那么这个键就会变成弱键。它通常被用来存储对象的私有数据或者隐藏实现细节。

在上一节中，我们了解到实例级别和原型级别上暴露的都是公共的（public）。下面是一个实际例子，包含了一个用于验证来自 Twitter 账户用户的函数：对于**开放认证**（**OAuth**），Twitter 需要两个密钥：消费者 API 密钥和一个密钥秘密。我们不想暴露这些信息并让用户更改。因此，我们使用弱映射来保存这些信息，然后在`prototype`函数中检索它来验证用户：

```js
var authenticatorsecrets = new WeakMap();

function TwitterAuthenticator() {
  const loginSecret = {
    apikey: 'testtwitterapikey',
    secretkey: 'testtwittersecretkey'
  };
  authenticatorsecrets.set(this, loginSecret);
}

TwitterAuthenticator.prototype.Authenticate = function () {
  const loginSecretVal = authenticatorsecrets(this);
  //to do authenticate with twitter
};
```

### 集合和弱集合

集合是值的集合，每个值应该是唯一的。所以，例如，如果你在任何索引上已经有了一个值`1`，已经定义，你不能将它插入到同一个集合实例中。

集合是无类型的，你可以放入任何数据，不考虑任何数据类型：

```js
var set = new Set();
set.add(1);
set.add("Hello World");
set.add(3.4);
set.add(new Date());
```

另一方面，弱集合是独特对象的集合，而不是任意类型的任意值。就像弱映射一样，如果没有其他对存储的对象的引用，它将被处置并回收。与弱映射类似，它们是不可枚举的：

```js
var no = { id: 1 };
var abc = { alphabets: ['a', 'b', 'c'] };

var x = new WeakSet();
x.add(no);
x.add(abc);
```

### 严格模式

`strict`模式是 ECMAScript 5 中引入的字面表达式。它用于编写安全的 JavaScript，并在脚本中出现任何小错误时抛出错误，而不会忽视它们。其次，它的运行速度比普通 JavaScript 代码快，因为它有时会修复错误，这有助于 JavaScript 引擎进行优化，使您的代码运行得更快。

我们可以在全局脚本级别或函数级别调用`strict`模式：

```js
"use strict;"
```

例如，在以下代码中，它会抛出错误，因为`x`变量未定义：

```js
"use strict";
x=100;
function execute(){
  "use strict;"
  x=100;
}
```

对于较大的应用程序，使用`strict`模式是一个更好的选择，如果缺少或不定义某些内容，它会抛出错误。以下表格显示了使用`strict`模式会导致错误的一些场景：

| Code | Error 原因 |
| --- | --- |
| `x=100;` | 这段代码中变量未声明。 |
| `x= {id:1, name:'ABC'};` | 这段代码中对象变量未声明。 |
| `function(x,x){}` | 在此代码中参数名称重复导致了错误。 |
| `var x = 0001` | 这段代码中使用了八进制数字字面量。 |
| `var x=\0001` | 转义是不允许的，因此发生了错误。 |
| `var x = {get val() {return 'A'}};` `x.val = 'B'` | 在此代码中，向`get`值写入导致了错误。 |
| `delete obj.prototype;` | 删除对象原型是不允许的，因此发生了错误。 |
| `var x= 2;` `delete x;` | 删除变量是不允许的，因此发生了错误。 |

此外，还有一些保留关键字，如`arguments`、`eval`、`implements`、`interface`、`let`、`package`、`private`、`protected`、`public`、`static`和`yield`，也是不允许的。

# 总结

在本章中，我们学习了 JavaScript 的一些高级概念，如提升的变量及其作用域、属性描述符、面向对象编程、闭包、类型数组以存储数据类型，以及异常处理。在下一章中，我们将学习最广泛使用的库 jQuery，以非常简单和容易的方式进行 DOM 遍历和操作、事件处理等。
