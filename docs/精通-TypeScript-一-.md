# 精通 TypeScript（一）

> 原文：[`zh.annas-archive.org/md5/EF6D1933EE7A1583ABD80988FCB79F1E`](https://zh.annas-archive.org/md5/EF6D1933EE7A1583ABD80988FCB79F1E)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

自 2012 年底发布以来，TypeScript 语言和编译器已经取得了巨大的成功。它迅速在 JavaScript 开发社区中站稳了脚跟，并不断壮大。包括 Adobe、Mozilla 和 Asana 在内的许多大型 JavaScript 项目已经决定将它们的代码库从 JavaScript 切换到 TypeScript。最近，微软和谷歌团队宣布 Angular 2.0 将使用 TypeScript 开发，从而将 AtScript 和 TypeScript 语言合并为一种语言。

这种大规模的行业采用 TypeScript 显示了该语言的价值、编译器的灵活性以及使用其丰富的开发工具集可以实现的生产力增益。除了行业支持外，ECMAScript 6 标准也越来越接近发布，TypeScript 提供了一种在我们的应用程序中使用该标准特性的方法。

使用 TypeScript 社区构建的大量声明文件，使得使用 TypeScript 编写 JavaScript 单页面应用程序变得更加吸引人。这些声明文件无缝地将大量现有的 JavaScript 框架整合到 TypeScript 开发环境中，带来了增加的生产力、早期错误检测和高级的智能感知功能。

本书旨在成为有经验的 TypeScript 开发人员以及刚开始学习 TypeScript 的人的指南。通过专注于测试驱动开发、与许多流行的 JavaScript 库集成的详细信息，以及深入研究 TypeScript 的特性，本书将帮助您探索 JavaScript 开发的下一步。

# 本书内容

第一章，“TypeScript – 工具和框架选项”，为开始 TypeScript 开发铺平了道路，首先介绍了使用 TypeScript 的各种好处，然后讨论了如何设置开发环境。

第二章，“类型、变量和函数技术”，向读者介绍了 TypeScript 语言，从基本类型和类型推断开始，然后讨论了变量和函数。

第三章，“接口、类和泛型”，在前一章的基础上构建，并介绍了接口、类和继承的面向对象概念。然后介绍了 TypeScript 中泛型的语法和用法。

第四章，“编写和使用声明文件”，引导读者逐步构建现有 JavaScript 代码的声明文件，然后列出了编写声明文件时使用的一些最常见的语法。这些语法旨在成为声明文件语法的快速参考指南或备忘单。

第五章，“第三方库”，向读者展示了如何在开发环境中使用 DefinitelyTyped 存储库中的声明文件。然后，它继续向读者展示如何编写与三种流行的 JavaScript 框架—Backbone、Angular 和 ExtJs 兼容的 TypeScript。

第六章，“测试驱动开发”，从讨论什么是测试驱动开发开始，然后引导读者通过使用 Jasmine 库创建各种类型的单元测试，包括数据驱动和异步测试。本章最后讨论了集成测试、测试报告和使用持续集成构建服务器。

第七章，*模块化*，介绍了 TypeScript 编译器使用的两种模块生成类型：CommonJS 和 AMD。本章向读者展示了如何构建用于 Node 的 CommonJS 模块，然后讨论了使用 Require、Backbone、AMD 插件和 jQuery 插件构建 AMD 模块。

第八章, *TypeScript 面向对象编程*，讨论了高级面向对象设计模式，包括服务定位设计模式、依赖注入和领域事件设计模式。读者将了解每种模式的概念和思想，然后展示如何使用 TypeScript 实现这些模式。

第九章，*让我们动手吧*，从头开始使用 TypeScript 和 Marionette 构建单页面应用程序。本章首先讨论页面布局和转换，使用应用程序的仅 HTML 版本。然后，讨论、构建和测试将在应用程序中使用的基础数据模型和 Marionette 视图。最后，实现了状态和中介者设计模式来管理页面转换和图形元素。

# 您需要为本书做些什么

您将需要 TypeScript 编译器和某种编辑器。TypeScript 编译器可作为 Node.js 插件或 Windows 可执行文件使用；因此，它可以在任何操作系统上运行。第一章，*TypeScript - 工具和框架选项*描述了开发环境的设置。

# 这本书是为谁准备的

无论您是想学习 TypeScript 的 JavaScript 开发人员，还是想将自己的技能提升到更高水平的有经验的 TypeScript 开发人员，这本书都适合您。从基本到高级语言构造、测试驱动开发和面向对象技术，您将学会如何充分利用 TypeScript 语言和编译器。本书将向您展示如何将强类型、面向对象和设计最佳实践融入到您的 JavaScript 应用程序中。

# 约定

在本书中，您将找到许多文本样式，用于区分不同类型的信息。以下是一些样式的示例及其含义的解释。

文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下："这个`GruntFile.js`是设置所有 Grunt 任务所必需的。"

代码块设置如下：

```ts
class MyClass {
    add(x, y) {
        return x + y;
    }
}
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```ts
class MyClass {
    add(x, y) {
        return x + y;
    }
}
```

任何命令行输入或输出都以以下方式编写：

```ts
tsc app.ts

```

新术语和重要单词以粗体显示。您在屏幕上看到的单词，例如菜单或对话框中的单词，会在文本中显示为："选择**名称**并浏览目录后，单击**确定**将生成一个 TypeScript 项目。"

### 注意

警告或重要说明会出现在这样的框中。

### 提示

提示和技巧会出现在这样。


# 第一章：TypeScript - 工具和框架选项

JavaScript 是一种真正无处不在的语言。现代世界中您访问的几乎每个网站都会嵌入某种 JavaScript 组件，以使网站更具响应性、更易读，或者更具吸引力。想想您在过去几个月中访问过的最令人印象深刻的网站。它外观吸引人吗？它有某种巧妙的呈现方式吗？它是否通过为您提供全新的发现汽车保险、图片分享或新闻文章的方式来吸引您作为用户？

这就是 JavaScript 的力量。JavaScript 是互联网体验的点睛之笔，让全世界数百万人感到“哇，太酷了”。它也带来了收入。两个网站可能以相同的价格提供相同的产品，但是能够吸引客户并让他们享受网络体验的网站将吸引最多的追随者并获得最大的成功。如果这个网站还可以在台式机、手机或平板电脑上无缝重现，那么目标受众和目标收入可以成倍增加。

然而，JavaScript 也是互联网上讨厌的一面的原因。那些令人讨厌的广告，您必须等待 5 秒钟才能点击“跳过”按钮。或者在旧版浏览器上无法正常工作，或者在平板电脑和手机上无法正确渲染的网站。可以说，许多网站如果没有 JavaScript 会更好。

一个引人入胜的网络体验也可以在企业网络应用中产生巨大差异。笨重、难以使用和缓慢的网络应用会完全让企业用户对您的应用产生反感。请记住，您的典型企业用户正在将他们的工作体验与他们的日常网络体验进行比较 - 他们期望得到精心设计、响应迅速、直观的界面。毕竟，他们通常是最受欢迎的网站的用户，并期望在工作中得到同样的响应。

大部分这种增强的用户体验来自于 JavaScript 的有效使用。异步 JavaScript 请求允许您的网页在等待后端进程进行繁重、耗时的数据处理任务时更快地向用户呈现内容。

JavaScript 语言并不难学，但在编写大型、复杂程序时会带来挑战。作为一种解释性语言，JavaScript 没有编译步骤，因此是即时执行的。对于习惯于在更正式的环境中编写代码 - 使用编译器、强类型和成熟的编程模式的程序员来说，JavaScript 可能是一个完全陌生的环境。

TypeScript 弥合了这一差距。它是一种强类型、面向对象、编译语言，允许您作为程序员在 JavaScript 中重复使用成熟的面向对象语言的概念和思想。TypeScript 编译器生成的 JavaScript 遵循这些强类型、面向对象的原则 - 但同时又是纯粹的 JavaScript。因此，它将在 JavaScript 可以运行的任何地方成功运行 - 在浏览器、服务器或现代移动设备上。

本章分为两个主要部分。第一部分是对 TypeScript 为 JavaScript 开发体验带来的一些好处的快速概述。本章的第二部分涉及设置 TypeScript 开发环境。

如果您是一名有经验的 TypeScript 程序员，并且已经设置好了开发环境，那么您可能想跳过本章。如果您以前从未使用过 TypeScript，并且因为想了解 TypeScript 能为您做什么而拿起了这本书，那么请继续阅读。

本章将涵盖以下主题：

+   TypeScript 的好处

+   编译

+   强类型

+   与流行的 JavaScript 库集成

+   封装

+   私有和公共成员变量

+   设置开发环境

+   Visual Studio

+   WebStorm

+   括号和 Grunt

# 什么是 TypeScript？

TypeScript 既是一种语言，也是一套生成 JavaScript 的工具。它是由微软的 Anders Hejlsberg（C#的设计者）设计的，作为一个开源项目，帮助开发人员编写企业规模的 JavaScript。JavaScript 已经被世界各地的程序员广泛采用，因为它可以在任何操作系统上的任何浏览器上运行。随着 Node 的创建，JavaScript 现在也可以在服务器、桌面或移动设备上运行。

TypeScript 生成 JavaScript——就是这么简单。TypeScript 生成的 JavaScript 可以重用所有现有的 JavaScript 工具、框架和丰富的库，而不需要完全新的运行时环境。然而，TypeScript 语言和编译器将 JavaScript 的开发更接近于更传统的面向对象的体验。

## EcmaScript

JavaScript 作为一种语言已经存在很长时间，并且也受到语言特性标准的约束。在这个标准中定义的语言称为 ECMAScript，每个浏览器必须提供符合这个标准的功能和特性。这个标准的定义帮助了 JavaScript 和网络的增长，并允许网站在许多不同的操作系统上的许多不同的浏览器上正确呈现。ECMAScript 标准于 1999 年发布，被称为 ECMA-262 第三版。

随着语言的流行和互联网应用的爆炸性增长，ECMAScript 标准需要进行修订和更新。这个过程导致了 ECMAScript 的草案规范，称为第四版。不幸的是，这个草案提出了对语言的彻底改革，但并未受到良好的反响。最终，来自雅虎、谷歌和微软的领导人提出了一个另类提案，他们称之为 ECMAScript 3.1。这个提案被编号为 3.1，因为它是第三版的一个较小的功能集，并且位于标准的第 3 版和第 4 版之间。

这个提案最终被采纳为标准的第五版，并被称为 ECMAScript 5。ECMAScript 第四版从未出版，但决定将第四版和 3.1 功能集的最佳特性合并为第六版，命名为 ECMAScript Harmony。

TypeScript 编译器有一个参数，可以修改以针对不同版本的 ECMAScript 标准。TypeScript 目前支持 ECMAScript 3、ECMAScript 5 和 ECMAScript 6。当编译器运行在您的 TypeScript 上时，如果您尝试编译的代码不符合特定标准，它将生成编译错误。微软团队还承诺在 TypeScript 编译器的任何新版本中遵循 ECMAScript 标准，因此一旦采用新版本，TypeScript 语言和编译器也会跟进。

ECMAScript 标准的每个版本包含的细节超出了本书的范围，但重要的是要知道存在差异。一些浏览器版本不支持 ES5（IE8 就是一个例子），但大多数浏览器支持。在选择要为项目定位的 ECMAScript 版本时，您需要考虑要支持的浏览器版本。

## TypeScript 的好处

为了让您了解 TypeScript 的好处（这绝不是完整列表），让我们快速看一下 TypeScript 带来的一些东西：

+   编译步骤

+   强类型或静态类型

+   流行 JavaScript 库的类型定义

+   封装

+   私有和公共成员变量装饰器

### 编译

JavaScript 开发最令人沮丧的事情之一是缺乏编译步骤。JavaScript 是一种解释性语言，因此需要运行才能测试其有效性。每个 JavaScript 开发人员都会讲述关于花费数小时来查找代码中的错误的可怕故事，只是发现他们错过了一个多余的闭括号`{`，或者一个简单的逗号`,` - 或者甚至是一个双引号`"`，而应该是单引号`'`。更糟糕的是，当你拼错属性名称或者无意中重新分配全局变量时，真正的头痛就来了。

TypeScript 将编译你的代码，并在发现这种类型的语法错误时生成编译错误。这显然非常有用，并且可以帮助在 JavaScript 运行之前突出显示错误。在大型项目中，程序员通常需要进行大规模的代码合并 - 而今天的工具可以自动合并 - 令人惊讶的是编译器经常会发现这些类型的错误。

虽然像 JSLint 这样的语法检查工具已经存在多年，但将这些工具集成到你的 IDE 中显然是有益的。在持续集成环境中使用 TypeScript 也将在发现编译错误时完全失败构建 - 进一步保护程序员免受这些类型的错误。

### 强类型

JavaScript 不是强类型的。它是一种非常动态的语言，因为它允许对象在运行时改变其属性和行为。举个例子，考虑以下代码：

```ts
var test = "this is a string";
test = 1;
test = function(a, b) {
    return a + b;
}
```

在这段代码片段的第一行，变量`test`绑定到一个字符串。然后它被赋一个数字，最后被重新定义为一个期望两个参数的函数。然而，传统的面向对象语言不允许变量的类型改变 - 因此它们被称为强类型语言。

虽然前面的所有代码都是有效的 JavaScript - 并且可以被证明是合理的 - 但很容易看出这可能在执行过程中导致运行时错误。想象一下，你负责编写一个库函数来添加两个数字，然后另一个开发人员无意中重新将你的函数重新分配为减去这些数字。

这些类型的错误可能在几行代码中很容易发现，但随着你的代码库和开发团队的增长，找到并修复这些错误变得越来越困难。

强类型的另一个特性是，你正在使用的 IDE 可以理解你正在处理的变量类型，并且可以提供更好的自动完成或智能提示选项。

#### TypeScript 的“语法糖”

TypeScript 引入了一种非常简单的语法来在编译时检查对象的类型。这种语法被称为“语法糖”，或者更正式地说，类型注解。考虑以下 TypeScript 代码：

```ts
var test: string = "this is a string";
test = 1;
test = function(a, b) { return a + b; }
```

在这段代码片段的第一行上，我们介绍了一个冒号`:`和一个`string`关键字，将我们的变量和它的赋值之间。这种类型注解语法意味着我们正在设置变量的类型为`string`类型，并且任何不将其用作字符串的代码都将生成一个编译错误。通过 TypeScript 编译器运行前面的代码将生成两个错误：

```ts
error TS2011: Build: Cannot convert 'number' to 'string'.
error TS2011: Build: Cannot convert '(a: any, b: any) => any' to 'string'.

```

第一个错误非常明显。我们已经指定变量`test`是一个`string`，因此尝试将一个数字赋给它将生成一个编译错误。第二个错误与第一个类似，本质上是在说我们不能将一个函数赋给一个字符串。

通过 TypeScript 编译器，你的 JavaScript 代码引入了强大的静态类型，给你所有强类型语言的好处。因此，TypeScript 被描述为 JavaScript 的“超集”。我们将在下一章更详细地探讨类型。

### 流行 JavaScript 库的类型定义

正如我们所见，TypeScript 有能力“注释”JavaScript，并为 JavaScript 开发体验带来强类型。但是我们如何为现有的 JavaScript 库提供强类型？答案出奇的简单：通过创建一个定义文件。TypeScript 使用扩展名为`.d.ts`的文件作为一种“头”文件，类似于 C++等语言，以在现有的 JavaScript 库上叠加强类型。这些定义文件包含描述库中每个可用函数和变量以及它们相关类型注释的信息。

让我们快速看一下定义会是什么样子。举个例子，考虑一个来自流行的 Jasmine 单元测试框架的函数`describe`：

```ts
var describe = function(description, specDefinitions) {
  return jasmine.getEnv().describe(description, specDefinitions);
};
```

这个函数有两个参数，`description`和`specDefinitions`。然而，仅仅阅读这个 JavaScript 并不能告诉我们这些参数应该是什么类型。`specDefinitions`参数是一个字符串，还是一个字符串数组，一个函数或者其他什么？为了弄清楚这一点，我们需要查看 Jasmine 文档，可以在[`jasmine.github.io/2.0/introduction.html`](http://jasmine.github.io/2.0/introduction.html)找到。这个文档为我们提供了如何使用这个函数的有用示例：

```ts
describe("A suite", function () {
    it("contains spec with an expectation", function () {
        expect(true).toBe(true);
    });
});
```

从文档中，我们可以很容易地看出第一个参数是一个`string`，第二个参数是一个`function`。然而，在 JavaScript 语言中，并没有强制我们遵循这个 API。正如之前提到的，我们可以轻松地用两个数字调用这个函数，或者无意中交换参数，先发送一个函数，然后发送一个字符串。如果我们这样做，显然会开始出现运行时错误，但是 TypeScript 可以在我们尝试运行这段代码之前生成编译时错误，使用定义文件。 

让我们来看一下`jasmine.d.ts`定义文件的一部分：

```ts
declare function describe(
    description: string, specDefinitions: () => void
): void;
```

这是描述函数的 TypeScript 定义。首先，`declare function describe`告诉我们可以使用一个名为`describe`的函数，但是这个函数的实现将在运行时提供。

显然，`description`参数被强类型为`string`类型，`specDefinitions`参数被强类型为返回`void`的`function`。TypeScript 使用双括号`()`语法声明函数，并使用箭头语法显示函数的返回类型。所以`() => void`是一个不返回任何东西的函数。最后，`describe`函数本身将返回`void`。

如果我们的代码尝试将一个函数作为第一个参数传递，将一个字符串作为第二个参数传递（显然违反了这个函数的定义），如下例所示：

```ts
describe(() => { /* function body */}, "description");
```

TypeScript 编译器将立即生成以下错误：

```ts
error TS2082: Build: Supplied parameters do not match any signature of call target: Could not apply type "string" to argument 1 which is of type () => void

```

这个错误告诉我们，我们试图使用无效的参数调用`describe`函数。我们将在后面的章节中更详细地看定义文件，但是这个例子清楚地显示了如果我们尝试不正确地使用外部 JavaScript 库，TypeScript 将生成错误。

#### Definitely Typed

TypeScript 发布后不久，Boris Yankov 开始在 DefinitelyTyped（[`github.com/borisyankov/DefinitelyTyped`](https://github.com/borisyankov/DefinitelyTyped)）上创建了一个 GitHub 存储库，用于存放定义文件。这个存储库现在已经成为将外部库集成到 TypeScript 中的首选方法，并且目前保存了超过 500 个 JavaScript 库的定义。

### 封装

面向对象编程的一个基本原则是封装：将数据定义以及一组可以操作该数据的函数封装到一个单一的组件中。大多数编程语言都有类的概念，提供了一种定义数据和相关函数模板的方式。

让我们首先看一下一个简单的 TypeScript 类定义：

```ts
class MyClass {
    add(x, y) {
        return x + y;
    }
}

var classInstance = new MyClass();
console.log(classInstance.add(1, 2));
```

这段代码非常简单易懂。我们创建了一个名为`MyClass`的`class`，其中包含一个名为`add`的函数。要使用这个类，我们只需创建一个实例，并使用两个参数调用`add`函数。

不幸的是，JavaScript 没有`class`关键字，而是使用函数来复制类的功能。通过类实现封装可以通过使用原型模式或者使用闭包模式来完成。理解原型和闭包模式，并正确使用它们，被认为是编写企业级 JavaScript 时的基本技能。

闭包本质上是指引用独立变量的函数。这意味着在闭包函数内定义的变量会“记住”它们被创建的环境。这为 JavaScript 提供了一种定义局部变量和提供封装的方式。在前面的代码中使用 JavaScript 的闭包来编写`MyClass`定义会看起来像这样：

```ts
var MyClass = (function () {
    // the self-invoking function is the 
    // environment that will be remembered
    // by the closure
    function MyClass() {
        // MyClass is the inner function,
        // the closure
    MyClass.prototype.add = function (x, y) {
        return x + y;
    };
    return MyClass;
})();
var classInstance = new MyClass();
console.log("result : " + classInstance.add(1, 2));
```

我们从一个名为`MyClass`的变量开始，并将其分配给一个立即执行的函数——请注意代码片段底部附近的`})();`语法。这种语法是为了避免将变量泄漏到全局命名空间而常用的 JavaScript 编写方式。然后我们定义一个名为`MyClass`的新函数，并将这个新函数返回给外部调用函数。然后我们使用`prototype`关键字将一个新函数注入到`MyClass`定义中。这个函数名为`add`，接受两个参数，返回它们的和。

代码的最后两行展示了如何在 JavaScript 中使用这个闭包。创建一个闭包类型的实例，然后执行 add 函数。在浏览器中运行这个代码将会在控制台上记录**result: 3**，这是预期的结果。

### 提示

**下载示例代码**

您可以从您在[`www.packtpub.com`](http://www.packtpub.com)的帐户中下载示例代码文件，这适用于您购买的所有 Packt Publishing 图书。如果您在其他地方购买了这本书，您可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support )并注册以直接通过电子邮件接收文件。

通过比较 JavaScript 代码和 TypeScript 代码，我们可以很容易地看出 TypeScript 相对于等效的 JavaScript 来说是多么简单。还记得我们提到过 JavaScript 程序员很容易错放大括号`{`或者括号`(`吗？看一下闭包定义的最后一行：`})();`。弄错其中一个大括号或者括号可能需要花费数小时来调试。

#### TypeScript 类生成闭包

如前面的代码片段所示，TypeScript 类定义的实际输出是 JavaScript 闭包。因此 TypeScript 实际上为您生成了闭包。

### 注意

多年来，向 JavaScript 语言添加类的概念一直是人们讨论的话题，目前已经成为 ECMAScript 第六版（Harmony）标准的一部分，但这仍然是一个正在进行中的工作。微软已经承诺在 TypeScript 编译器中遵循 ECMAScript 标准，一旦这些标准发布，就会实现这些标准。

### 公共和私有访问器

封装中使用的另一个面向对象原则是数据隐藏的概念——即具有公共和私有变量的能力。私有变量应该对特定类的用户隐藏——因为这些变量只应该被类本身使用。意外地将这些变量暴露到类外部可能很容易导致运行时错误。

不幸的是，JavaScript 没有声明变量为私有的本地方法。虽然可以使用闭包来模拟这种功能，但很多 JavaScript 程序员简单地使用下划线字符`_`来表示私有变量。然而，在运行时，如果您知道私有变量的名称，您可以很容易地为它赋值。考虑以下 JavaScript 代码：

```ts
var MyClass = (function() {
    function MyClass() {
        this._count = 0;
    }
    MyClass.prototype.countUp = function() {
        this._count ++;
    }
    MyClass.prototype.getCountUp = function() {
        return this._count;
    }
    return MyClass;
}());

var test = new MyClass();
test._count = 17;
console.log("countUp : " + test.getCountUp());
```

`MyClass`变量实际上是一个闭包 - 具有构造函数、`countUp`函数和`getCountUp`函数。变量`_count`应该是一个私有成员变量，只在闭包范围内使用。使用下划线命名约定可以让这个类的用户知道这个变量是私有的，但是 JavaScript 仍然允许您操作变量`_count`。看一下代码片段的倒数第二行。我们明确地将假定的私有变量`_count`的值设置为 17 - 这是 JavaScript 允许的，但不是类的原始创建者所期望的。这段代码的输出将是**countUp: 17**。

然而，TypeScript 引入了`public`和`private`关键字，可以用于类成员变量。尝试访问被标记为`private`的类成员变量将生成一个编译时错误。例如，上面的 JavaScript 代码可以在 TypeScript 中写成如下形式：

```ts
class MyClass {
    private _count: number;
    constructor() {
        this._count = 0;
    }
    countUp() {
        this._count++;
    }
    getCount() {
        return this._count;
    }
}

var classInstance = new MyClass();
console.log(classInstance._count);
```

在我们的代码片段的第二行，我们声明了一个名为`_count`的`private`成员变量。同样，我们有一个构造函数、一个`countUp`和一个`getCount`函数。如果我们编译这个 TypeScript 代码，编译器将生成一个错误：

```ts
error TS2107: Build: 'MyClass._count' is inaccessible.

```

这个错误是因为我们试图在代码的最后一行访问私有变量`_count`。

因此，TypeScript 编译器帮助我们遵守公共和私有访问者 - 当我们无意中违反这个规则时，它会生成一个编译错误。

### 注意

不过，请记住，这些访问者只是编译时的特性，不会影响生成的 JavaScript。如果您正在编写将被第三方使用的 JavaScript 库，您需要牢记这一点。即使存在编译错误，TypeScript 编译器仍会生成 JavaScript 输出文件。

# TypeScript IDEs

本节的目的是让您快速上手使用 TypeScript 环境，以便您可以编辑、编译、运行和调试您的 TypeScript 代码。TypeScript 已经作为开源发布，并包括 Windows 版本和 Node 版本。这意味着编译器将在 Windows、Linux、OS X 和任何支持 Node 的其他操作系统上运行。

在 Windows 环境中，我们可以安装 Visual Studio - 这将在我们的`C:\Program Files`目录中注册`tsc.exe`（TypeScript 编译器），或者我们可以使用 Node。在 Linux 和 OS X 环境中，我们将需要使用 Node。无论哪种方式，启动命令提示符并输入`tsc –v`应该显示我们正在使用的编译器的当前版本。在撰写本文时，这个版本是 1.4.2.0。

在本节中，我们将看一下以下 IDE：

+   Visual Studio 2013

+   WebStorm

+   括号

## Visual Studio 2013

首先，让我们看一下微软的 Visual Studio 2013。这是微软的主要 IDE，有各种定价组合。最高端是 Ultimate，然后是 Premium，然后是 Professional，最后是 Express。Ultimate、Premium 和 Professional 都需要付费许可证，价格范围（撰写本文时）从 13000 美元到 1199 美元不等。好消息是，微软最近宣布了社区版，可以在非企业环境中免费使用。TypeScript 编译器包含在所有这些版本中。

Visual Studio 可以下载为 Web 安装程序或.ISO CD 映像。请注意，Web 安装程序在安装过程中需要互联网连接，因为它在安装步骤中下载所需的软件包。Visual Studio 还需要 Internet Explorer 10 或更高版本，但如果您尚未升级浏览器，它将在安装过程中提示您。如果您使用.ISO 安装程序，请记住，如果您已经有一段时间没有通过 Windows Update 更新系统，可能需要下载并安装额外的操作系统补丁。

### 创建 Visual Studio 项目

安装 Visual Studio 后，启动它并创建一个新项目（**File** | **New Project**）。在左侧的**Templates**部分下，您将看到一个 TypeScript 选项。选择此选项后，您将能够使用一个名为**Html Application with TypeScript**的项目模板。输入项目的名称和位置，然后单击**OK**生成一个 TypeScript 项目：

![创建 Visual Studio 项目](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-ts/img/9665OS_01_01.jpg)

Visual Studio - 选择 TypeScript 项目类型

### 注意

这不是唯一支持 TypeScript 的项目模板。任何 ASP.NET 项目类型都支持 TypeScript。如果您计划使用 Web API 提供 RESTful 数据控制器，那么您可能考虑从头开始创建一个 MVC Web 应用程序。然后，只需包含一个 TypeScript 文件，并在项目中指定`.ts`文件扩展名，Visual Studio 将自动开始编译您的 TypeScript 文件作为新项目的一部分。

### 默认项目设置

创建一个新的 TypeScript 项目后，注意项目模板会自动生成一些文件：

+   `app.css`

+   `app.ts`

+   `index.html`

+   `web.config`

如果我们现在编译然后运行这个项目，我们将立即拥有一个完整的、运行中的 TypeScript 应用程序：

![默认项目设置](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-ts/img/9665OS_01_02.jpg)

在 Internet Explorer 中运行的 Visual Studio index.html

让我们快速看一下生成的 index.html 文件及其内容：

```ts
<!DOCTYPE html>

<html lang="en">
<head>
    <meta charset="utf-8" />
    <title>TypeScript HTML App</title>
    <link rel="stylesheet" href="app.css" type="text/css" />
    <script src="img/app.js"></script>
</head>
<body>
    <h1>TypeScript HTML App</h1>

    <div id="content"></div>
</body>
</html>
```

这是一个非常简单的 HTML 文件，包括`app.css`样式表，以及一个名为`app.js`的 JavaScript 文件。这个`app.js`文件是从`app.ts` TypeScript 文件生成的 JavaScript 文件，当项目被编译时。

### 注意

`app.js`文件不包括在**Solution Explorer**中 - 只有`app.ts` TypeScript 文件包括在内。这是有意设计的。如果您希望看到生成的 JavaScript 文件，只需点击**Solution Explorer**工具栏中的**Show All Files**按钮。

### 在 Visual Studio 中调试

Visual Studio 最好的功能之一是它真正是一个集成环境。在 Visual Studio 中调试 TypeScript 与调试 C#或 Visual Studio 中的任何其他语言完全相同，并包括通常的**Immediate**、**Locals**、**Watch**和**Call stack**窗口。

要在 Visual Studio 中调试 TypeScript，只需在 TypeScript 文件中希望中断的行上设置断点（将鼠标移动到源代码行旁边的断点区域，然后单击）。在下面的图像中，我们在`window.onload`函数内设置了一个断点。

要开始调试，只需按下*F5*。

![在 Visual Studio 中调试](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-ts/img/9665OS_01_03.jpg)

在 Visual Studio 中设置断点的 TypeScript 编辑器

当源代码行被黄色高亮显示时，只需将鼠标悬停在源代码中的任何变量上，或使用**Immediate**、**Watch**、**Locals**或**Call stack**窗口。

### 注意

Visual Studio 只支持在 Internet Explorer 中调试。如果您的计算机上安装了多个浏览器，请确保在**Debug**工具栏中选择 Internet Explorer，如下面的截图所示：

![在 Visual Studio 中调试](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-ts/img/9665OS_01_04.jpg)

Visual Studio 调试工具栏显示浏览器选项

## WebStorm

WebStorm 是 JetBrains（[`www.jetbrains.com/webstorm/`](http://www.jetbrains.com/webstorm/)）的一款流行的 IDE，可在 Windows、Mac OS X 和 Linux 上运行。价格从单个开发者的 49 美元到商业许可证的 99 美元不等。JetBrains 还提供 30 天的试用版本。

WebStorm 有一些很棒的功能，包括实时编辑和代码建议，或者智能感知。实时编辑功能允许您保持浏览器窗口打开，WebStorm 将根据您的输入自动更新 CSS、HTML 和 JavaScript 的更改。代码建议 - 这也是另一款流行的 JetBrains 产品 Resharper 提供的 - 将突出显示您编写的代码，并建议更好的实现方式。WebStorm 还有大量的项目模板。这些模板将自动下载并包含模板所需的相关 JavaScript 或 CSS 文件，例如 Twitter Bootstrap 或 HTML5 样板。

设置 WebStorm 就像从网站下载软件包并运行安装程序一样简单。

### 创建 WebStorm 项目

要创建一个新的 WebStorm 项目，只需启动它，然后点击**文件** | **新建项目**。选择**名称**、**位置**和**项目类型**。对于这个项目，我们选择了`Twitter Bootstrap`作为项目类型，如下面的屏幕截图所示：

![创建 WebStorm 项目](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-ts/img/9665OS_01_05.jpg)

WebStorm 创建新项目对话框

WebStorm 随后会要求您选择要开发的 Twitter Boostrap 版本。在本例中，我们选择了版本`v3.2.0`。

![创建 WebStorm 项目](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-ts/img/9665OS_01_06.jpg)

WebStorm 选择 Twitter Boostrap 版本对话框

### 默认文件

WebStorm 方便地创建了一个`css`、`fonts`和`js`目录作为新项目的一部分 - 并为我们下载并包含了相关的 CSS、字体文件和 JavaScript 文件，以便开始构建基于 Bootstrap 的新网站。请注意，它没有为我们创建`index.html`文件，也没有创建任何 TypeScript 文件 - 就像 Visual Studio 一样。在使用 TypeScript 一段时间后，大多数开发人员都会删除这些通用文件。所以让我们创建一个`index.html`文件。

只需点击**文件** | **新建**，选择 HTML 文件，输入`index`作为名称，然后点击**确定**。

接下来，让我们以类似的方式创建一个 TypeScript 文件。我们将把这个文件命名为`app`（或`app.ts`），与 Visual Studio 默认项目示例中的相同。当我们点击新的`app.ts`文件时，WebStorm 会在编辑窗口顶部弹出一个绿色栏，建议读取**文件监视器'TypeScript'可用于此文件**，如下面的屏幕截图所示：

![默认文件](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-ts/img/9665OS_01_07.jpg)

WebStorm 首次编辑 TypeScript 文件，显示文件监视器栏

WebStorm 的“文件监视器”是一个后台进程，将在您保存文件后立即执行。这相当于 Visual Studio 的**保存时编译**TypeScript 选项。正如 WebStorm 建议的那样，现在是激活 TypeScript 文件监视器的好时机。点击绿色栏中的**添加监视器**链接，并在下一个屏幕上填写详细信息。

我们可以暂时保持下一个屏幕上的默认设置不变，除了**程序**设置：

如果您在 Windows 上运行，并且已经安装了 Visual Studio，则应将其设置为`tsc.exe`可执行文件的完整路径，即`C:\Program Files (x86)\Microsoft SDKs\TypeScript\1.0\tsc.exe`，如下面的屏幕截图所示：

如果您在非 Windows 系统上运行，或者通过 Node 安装了 TypeScript，那么这个设置将只是`tsc`，没有路径。

![默认文件](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-ts/img/9665OS_01_08.jpg)

WebStorm 新文件监视器选项屏幕

现在我们已经为我们的 TypeScript 文件创建了一个文件监视器，让我们创建一个简单的 TypeScript 类，它将修改 HTML 的`div`的`innerText`。当您输入时，您会注意到 WebStorm 的自动完成或 Intellisense 功能，帮助您使用可用的关键字、参数、命名约定和其他语言特定信息。这是 WebStorm 最强大的功能之一，类似于 JetBrain 的 Resharper 工具中看到的增强 Intellisense。继续输入以下 TypeScript 代码，您将体验到 WebStorm 提供的自动完成功能。

```ts
class MyClass {
    public render(divId: string, text: string) {
        var el: HTMLElement = document.getElementById(divId);
        el.innerText = text;
    }
}

window.onload = () => {
    var myClass = new MyClass();
    myClass.render("content", "Hello World");
}
```

我们首先定义了`MyClass`类，它简单地有一个名为`render`的函数。这个`render`函数接受一个 DOM 元素名称和一个文本字符串作为参数。然后它简单地找到 DOM 元素，并设置`innerText`属性。请注意变量`el`的强类型使用-我们明确将其类型为`HTMLElement`类型。

我们还将一个函数分配给`window.onload`事件，这个函数将在页面加载后执行，类似于 Visual Studio 示例。在这个函数中，我们只是创建了`MyClass`的一个实例，并调用`render`函数，传入两个字符串参数。

如果您的 TypeScript 文件中有任何错误，这些错误将自动显示在输出窗口中，让您在输入时立即得到反馈。创建了这个 TypeScript 文件后，我们现在可以将其包含在我们的`index.html`文件中，并尝试一些调试。

打开`index.html`文件，并添加一个`script`标签来包含`app.js` JavaScript 文件，以及一个`id`为`"content"`的`div`。就像我们在 TypeScript 编辑中看到的一样，您会发现 WebStorm 在编辑 HTML 时也具有强大的 Intellisense 功能。

```ts
<!DOCTYPE html>
<html>
<head lang="en">
    <meta charset="UTF-8">
    <title></title>
    <script src="img/app.js" type="application/javascript"></script>
</head>
<body>
    <h2>Index.html</h2>
    <div id="content"></div>
</body>
</html>
```

在上述代码中有几点要注意。我们正在包括一个`app.js` JavaScript 文件的脚本标签，因为这是 TypeScript 编译器将生成的输出文件。我们还创建了一个带有`content` id 的 HTML `<div>`，`MyClass`类的实例将使用它来渲染我们的文本。

### 在 Chrome 中运行网页

在 WebStorm 中查看或编辑 HTML 文件时，您会注意到编辑窗口右上角会弹出一组小的浏览器图标。单击其中任何一个图标将使用所选的浏览器启动当前的 HTML 页面。

![在 Chrome 中运行网页](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-ts/img/9665OS_01_09.jpg)

WebStorm 编辑 HTML 文件显示弹出式浏览器启动图标

### 在 Chrome 中调试

正如我们在 Visual Studio 中看到的那样，在 WebStorm 中进行调试只是标记断点，然后按下*Alt* + *F5*。WebStorm 使用 Chrome 插件来启用在 Chrome 中进行调试。如果您没有安装这个插件，WebStorm 将在您第一次开始调试时提示您下载并启用 JetBrains IDE Support Chrome 插件。启用了这个插件后，WebStorm 有一套非常强大的工具来检查 JavaScript 代码，添加监视器，查看控制台等，都可以在 IDE 内部完成。

![在 Chrome 中调试](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-ts/img/9665OS_01_10.jpg)

WebStorm 调试会话显示调试器面板

## Brackets

我们将在本章中看到的最后一个 IDE 实际上不是一个 TypeScript 的 IDE，它更像是一个具有 TypeScript 编辑功能的网页设计师 IDE。Brackets 是一个开源的代码编辑器，非常擅长帮助设计和样式网页。与 WebStorm 类似，它有一个实时编辑模式，您可以在输入时看到 HTML 或 CSS 在运行的网页上的更改。在我们的开发团队中，Brackets 已经成为快速原型设计 HTML 网页和 CSS 样式的非常受欢迎的编辑器。

在本章中包括 Brackets 有几个原因。首先，它是完全开源的，因此完全免费 - 并且可以在 Windows、Linux 和 Mac OS X 上运行。其次，使用 Brackets 环境可以展示一个多么简单的 TypeScript 环境会是什么样子，只需一个文本编辑器和命令行。最后，Brackets 显示了开源项目的语法高亮和代码补全能力可以和商业 IDE 一样好 - 如果不是更快。

### 安装括号

可以从[`brackets.io`](http://brackets.io)下载 Brackets 首选安装程序。安装完成后，我们需要安装一些扩展。Brackets 有一个非常简洁和简单的扩展管理器，易于使用，可以让我们轻松找到和安装可用的扩展。每当 Brackets 或已安装的扩展之一有更新时，Brackets 都会自动通知您。

要安装扩展，启动 Brackets，然后单击**文件** | **扩展管理器**，或单击右侧垂直侧边栏上的乐高图标。

首先，我们需要安装 TypeScript 扩展。在搜索栏中，键入`brackets typescript`，然后从**Francois de Campredon**那里安装**Brackets TypeScript**扩展。

如下截图所示，每个扩展都有一个**更多信息…**链接 - 这将带您到扩展主页。

![安装括号](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-ts/img/9665OS_01_11.jpg)

括号扩展管理器界面

除了**Brackets TypeScript**扩展之外，另一个有用的扩展是**Patrick Oladimeji**的**Code Folding**。这将允许您折叠或展开您正在编辑的任何文件中的代码部分。

另一个很棒的时间节省者是**Sergey Chikujonok**的**Emmet**。 Emmet（以前称为 Zen Coding）使用类似于 CSS 的简写，而不是传统的代码片段，来生成 HTML。在本节中，我们将快速展示 Emmet 如何用于生成 HTML，就像一个预告片一样。所以继续安装 Emmet 扩展。

### 创建一个括号项目

括号本身并没有项目的概念，而是直接在根文件夹上工作。在文件系统上创建一个目录，然后在 Brackets 中打开该文件夹：**文件** | **打开文件夹**。

现在让我们使用 Brackets 创建一个简单的 HTML 页面。选择**文件** | **新建**，或按*Ctrl* + *N*。在我们面前有一个空白文件时，我们将使用 Emmet 来生成我们的 HTML。输入以下 Emmet 字符串：

```ts
html>head+body>h3{index.html}+div#content
```

现在按下*Ctrl* + *Alt* + *Enter*，或从**文件菜单**中，选择**Emmet** | **展开缩写**。

哇！Emmet 在一毫秒内生成了以下 HTML 代码 - 对于一行源代码来说还不错。

```ts
<html>
<head></head>
<body>
    <h3>index.html</h3>
    <div id="content"></div>
</body>
</html>
```

按下*Ctrl* + *S*保存文件，并输入`index.html`。

### 注意

只有在我们保存了文件之后，括号才会根据文件扩展名进行语法高亮。这对于任何括号文件都是真实的，所以一旦你创建了一个文件 - TypeScript，CSS 或 HTML，尽快将其保存到磁盘上。

回到 Emmet。

Emmet 使用`>`字符来创建子元素，使用`+`字符来表示兄弟元素。如果在元素旁边指定花括号`{ }`，这将被用作文本内容。

我们之前输入的 Emmet 字符串基本上是这样说的：“创建一个带有子`head`标签的`html`标签。然后创建另一个名为`body`的`html`标签的子标签，创建一个带有文本`"index.html"`的子`h3`标签，然后创建一个兄弟`div`标签作为`body`的子标签，其`id`为`content`。”一定要前往[`emmet.io`](http://emmet.io)获取更多文档，并记得在学习 Emmet 字符串快捷方式时保持速查表方便（[`docs.emmet.io/cheat-sheet`](http://docs.emmet.io/cheat-sheet)）。

现在让我们用一个`app.js`脚本来完成我们的`index.html`，以加载我们生成的 TypeScript JavaScript 文件。将光标移动到`<head></head>`标签之间，然后输入另一个 Emmet 字符串：

```ts
script:src
```

现在按下*Ctrl* + *Alt* + *Enter*，让 Emmet 生成一个`<script src="img/code>`标签，并方便地将光标放在引号之间，准备让您简单地填写空白。现在键入 JavaScript 文件名`app.js`。

您完成的 index.html 文件现在应该如下所示：

```ts
<html>
<head>
    <script src="img/app.js"></script>
</head>
<body>
    <h3>index.html</h3>
    <div id="content"></div>
</body>
</html>
```

这就是我们样本 HTML 页面所需要的全部内容。

### 使用 Brackets 实时预览

在括号内，点击屏幕右侧的**实时预览**图标 - 它是电动的，就在乐高积木包图标的上方。这将启动 Chrome 并以实时预览模式渲染我们的`index.html`。为了展示 Brackets 可以用于实时预览，保持这个 Chrome 窗口可见，并导航回 Brackets。您应该能够同时看到两个窗口。

现在编辑`index.html`文件，在`<div id="content"></div>`元素下键入以下 Emmet 快捷方式：

```ts
ul>li.item$*5
```

再次按下*Ctrl* + *Alt* + *Enter*，注意生成的`<ul>`和`<li>`标签（共 5 个）如何自动显示在 Chrome 浏览器中。当您在源代码中上下移动光标时，注意 Chrome 中的蓝色轮廓如何显示网页中的元素。

![使用 Brackets 实时预览](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-ts/img/9665OS_01_12.jpg)

Brackets 在实时预览模式下运行 Chrome，显示突出显示的元素

我们不需要这些`<ul> <li>`标签用于我们的应用程序，所以简单地按下*Ctrl* + *Z*，*Ctrl* + *Z*来撤消我们的更改，或者删除这些标签。

### 创建一个 TypeScript 文件

要创建我们非常简单的 TypeScript 应用程序，按下*Ctrl* + *N*（新建文件），*Ctrl* + *S*（保存文件），并使用`app.ts`作为文件名。开始输入以下代码，并注意 Brackets 也会实时自动完成，或者类似于 Visual Studio 和 WebStorm 的智能感知功能：

```ts
class MyClass {
    render( elementId: string, text: string) {
        var el: HTMLElement = document.getElementById(elementId);
        el.innerHTML = text;
    }
}
window.onload = () => {
    var myClass = new MyClass();
    myClass.render("content", "Hello world!");
}
```

这是我们之前使用的相同代码，简单地创建了一个名为`MyClass`的 TypeScript 类，该类有一个`render`函数。这个`render`函数获取一个 DOM 元素，并修改它的`innerHTML`属性。`window.onload`函数创建了这个类的一个实例，然后使用适当的参数调用`render`函数。

如果您在任何阶段按下*Ctrl* + *S*保存文件，Brackets 将调用 TypeScript 语言引擎来验证我们的 TypeScript，并在底部窗格中呈现任何错误。在下面的截图中，我们可以清楚地看到我们缺少一个闭合大括号`}`。

![创建一个 TypeScript 文件](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-ts/img/9665OS_01_13.jpg)

Brackets 编辑一个 TypeScript 文件并显示编译错误

Brackets 不会调用 TypeScript 编译器来生成`app.js`文件 - 它只是在这个阶段解析 TypeScript 代码，并突出显示任何错误。在**TypeScript 问题**窗格中双击错误将跳转到相关行。

### 编译我们的 TypeScript

在我们能够运行应用程序之前，我们需要通过调用 TypeScript 编译器将`app.ts`文件编译成一个`app.js`文件。打开命令提示符，切换到您的源目录，然后简单地输入：

```ts
**tsc app.ts** 
```

这个命令将调用`tsc`命令行编译器，并从我们的`app.ts`文件创建一个`app.js`文件。

现在我们在这个目录中有一个`app.js`文件，我们可以再次调用**实时预览**按钮，现在可以看到我们的 TypeScript 应用程序确实将**Hello world!**文本呈现为内容`div`的`innerHTML`：

![编译我们的 TypeScript](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-ts/img/9665OS_01_14.jpg)

Brackets 实时预览运行我们的 TypeScript 应用程序

### 使用 Grunt

显然，每次我们进行更改时都必须切换到命令提示符并手动编译每个 TypeScript 文件将会非常乏味。Grunt 是一个自动化任务运行器（[`gruntjs.com`](http://gruntjs.com)），可以自动化许多乏味的编译、构建和测试任务。在本节中，我们将使用 Grunt 来监视 TypeScript 文件，并在保存文件时调用`tsc`编译器。这与我们之前使用的 WebStorm 文件监视功能非常相似。

Grunt 在 Node 环境中运行。Node 是一个开源的跨平台运行时环境，其程序是用 JavaScript 编写的。因此，要运行 Grunt，我们需要安装 Node。Windows、Linux 和 OS X 的安装程序可以在 Node 网站([`nodejs.org/`](http://nodejs.org/))上找到。安装 Node 后，我们可以使用**npm**（**Node 包管理器**）来安装 Grunt 和 Grunt 命令行界面。

Grunt 需要作为项目的 npm 依赖项安装。它不能像大多数 npm 包那样全局安装。为了做到这一点，我们需要在项目的根目录中创建一个`packages.json`文件。打开命令提示符，并导航到 Brackets 项目的根目录。然后简单地输入：

```ts
**npm init** 
```

然后按照提示操作。您几乎可以将所有选项保留为默认设置，并始终返回编辑从此步骤创建的`packages.json`文件，以便在需要调整任何更改时进行编辑。完成包初始化步骤后，我们现在可以按照以下方式安装 Grunt：

```ts
**npm install grunt –save-dev** 
```

-save-dev 选项将在项目目录中安装 Grunt 的本地版本。这样做是为了确保您的计算机上的多个项目可以使用不同版本的 Grunt。我们还需要安装`grunt-typescript`包，以及`grunt-contrib-watch`包。这些可以使用以下 npm 命令安装：

```ts
**Npm install grunt-typescript –save-dev**
**Npm install grunt-contrib-watch –save-dev.** 
```

最后，我们需要一个`GruntFile.js`作为 Grunt 的入口点。使用 Brackets，创建一个新文件，保存为`GruntFile.js`，并输入以下 JavaScript。请注意，这里我们创建的是 JavaScript 文件，而不是 TypeScript 文件。您可以在本章附带的示例源代码中找到此文件的副本。

```ts
module.exports = function (grunt) {
    grunt.loadNpmTasks('grunt-typescript');
    grunt.loadNpmTasks('grunt-contrib-watch');
    grunt.initConfig({
        pkg: grunt.file.readJSON('package.json'),
        typescript: {
            base: {
                src: ['**/*.ts'],
                options: {
                    module: 'commonjs',
                    target: 'es5',
                    sourceMap: true
                }
            }
        },
        watch: {
            files: '**/*.ts',
            tasks: ['typescript']
        }
    });

   //grunt.registerTask('default', ['typescript']);
    grunt.registerTask('default', ['watch']);
}
```

这个`GruntFile.js`是设置所有 Grunt 任务所必需的。它是一个简单的函数，Grunt 用它来初始化 Grunt 环境，并指定 Grunt 命令。函数的前两行加载了`grunt-typescript`和`grunt-contrib-watch`任务，然后运行了带有配置部分的`grunt.initConfig`函数。这个配置部分有一个`pkg`属性，一个`typescript`属性和一个`watch`属性。`pkg`属性是通过读取我们之前创建的`package.json`文件来设置的，这是 npm init 步骤的一部分。

`typescript`属性有一个`base`属性，在其中我们指定源代码应该是`'**/*.ts'` - 换句话说，任何子目录中的所有`.ts`文件。我们还指定了一些 TypeScript 选项 - 使用`'commonjs'`模块而不是`'amd'`模块，并生成 sourcemaps。

`watch`属性有两个子属性。`files`属性指定要监视源树中的任何`.ts`文件，`tasks`数组指定一旦文件发生更改，我们应该启动 TypeScript 命令。最后，我们调用`grunt.registerTask`，指定默认任务是监视文件更改。Grunt 将在后台运行，监视保存的文件，如果找到，将执行 TypeScript 任务。

现在我们可以从命令行运行 Grunt。确保您在 Brackets 项目的基本目录中，并启动 Grunt：

```ts
**Grunt** 
```

打开您的`app.ts`文件，进行一些小改动（添加一个空格或其他内容），然后按下*Ctrl* + *S*进行保存。现在检查 Grunt 命令行的输出。您应该会看到类似以下的内容：

```ts
**>> File "app.ts" changed.**
**Running "typescript:base" (typescript) task**
**2 files created. js: 1 file, map: 1 file, declaration: 0 files (861ms)**
**Done, without errors.**
**Completed in 1.665s at Fri Oct 10 2014 11:24:47 GMT+0800 (W. Australia Standard Time) - Waiting...** 
```

这个命令行输出证实了 Grunt watch 任务已经确认`app.ts`文件已经发生了变化，运行了 TypeScript 任务，创建了两个文件，现在正在等待下一个文件的变化。回到 Brackets，我们现在应该在 Brackets 文件窗格中看到 Grunt 创建的`app.js`文件。

### 在 Chrome 中调试

由于 Brackets 只是作为编辑器使用，我们需要使用标准的 Chrome 开发工具来调试我们的应用程序。我们在`GruntFile.js`中指定的一个选项是打开 sourcemap（`options { sourceMap : true }`）。有了这个选项，Chrome - 和其他浏览器 - 可以将运行的 JavaScript 映射回源 TypeScript 文件。这意味着您可以在 TypeScript 文件中设置调试器断点，并在调试时遍历 TypeScript 文件。

要调试我们的示例应用程序，首先在**实时预览**模式下运行`index.html`页面，然后按下*F12*以打开开发工具。Chrome 为开发人员提供了许多工具，包括 Network、Console 和 Elements 来检查 DOM。点击**Sources**选项卡，按下*Ctrl* + *P*打开文件。滚动到`app.ts`，然后按下*Enter*。在第 9 行（`var myClass = new MyClass()`）设置断点，然后重新加载页面。

Chrome 应该在调试器模式下暂停页面，方法如下：

![在 Chrome 中调试](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-ts/img/9665OS_01_15.jpg)

括号调试 TypeScript 使用 Chrome 开发工具。

现在您可以尽情使用所有 Chrome 调试工具。 

# 总结

在本章中，我们快速了解了 TypeScript 是什么，以及它可以为 JavaScript 开发体验带来什么好处。我们还看了如何使用两种流行的商业 IDE 和一个开源开发环境来设置开发环境。现在我们已经设置好了开发环境，可以开始更详细地了解 TypeScript 语言。我们将从类型开始，然后转向变量，然后在下一章讨论函数。

为 Bentham Chang 准备，Safari ID bentham@gmail.com 用户编号：2843974 © 2015 Safari Books Online，LLC。此下载文件仅供个人使用，并受到服务条款的约束。任何其他用途均需版权所有者事先书面同意。未经授权的使用、复制和/或分发严格禁止并违反适用法律。保留所有权利。


# 第二章：类型，变量和函数技术

TypeScript 通过一种简单的语法引入了强类型到 JavaScript，安德斯·海尔斯伯格称之为“语法糖”。

这一章是对 TypeScript 语言中用于将强类型应用于 JavaScript 的语法的介绍。它适用于以前没有使用过 TypeScript 的读者，并涵盖了从标准 JavaScript 过渡到 TypeScript 的过程。如果您已经有了 TypeScript 的经验，并且对下面列出的主题有很好的理解，那么请快速阅读一下，或者跳到下一章。

我们将在本章中涵盖以下主题：

+   基本类型和类型语法：字符串、数字和布尔值

+   推断类型和鸭子类型

+   数组和枚举

+   任意类型和显式转换

+   函数和匿名函数

+   可选和默认函数参数

+   参数数组

+   函数回调和函数签名

+   函数作用域规则和重载

# 基本类型

JavaScript 变量可以保存多种数据类型，包括数字、字符串、数组、对象、函数等。JavaScript 中对象的类型由其赋值确定——因此，如果一个变量被赋予了字符串值，那么它将是字符串类型。然而，这可能会在我们的代码中引入许多问题。

## JavaScript 没有强类型

正如我们在第一章中看到的，*TypeScript – 工具和框架选项*，JavaScript 对象和变量可以在运行时更改或重新分配。例如，考虑以下 JavaScript 代码：

```ts
var myString = "test";
var myNumber = 1;
var myBoolean = true;
```

我们首先定义三个变量，名为`myString`，`myNumber`和`myBoolean`。`myString`变量设置为字符串值`"test"`，因此将是`string`类型。同样，`myNumber`设置为值`1`，因此是`number`类型，`myBoolean`设置为`true`，因此是`boolean`类型。现在让我们开始将这些变量相互赋值，如下所示：

```ts
myString = myNumber;
myBoolean = myString;
myNumber = myBoolean;
```

我们首先将`myString`的值设置为`myNumber`的值（即数字值`1`）。然后将`myBoolean`的值设置为`myString`的值（现在将是数字值`1`）。最后，我们将`myNumber`的值设置为`myBoolean`的值。这里发生的是，即使我们最初有三种不同类型的变量——字符串、数字和布尔值——我们仍然能够将其中任何一个重新分配给另一种类型。我们可以将数字赋给字符串，字符串赋给布尔值，或者布尔值赋给数字。

虽然在 JavaScript 中这种赋值是合法的，但它表明 JavaScript 语言并不是强类型的。这可能导致我们的代码出现意外的行为。我们的代码的某些部分可能依赖于一个特定变量保存一个字符串的事实，如果我们无意中将一个数字赋给这个变量，我们的代码可能会以意想不到的方式开始出现问题。

## TypeScript 是强类型的

另一方面，TypeScript 是一种强类型语言。一旦你声明一个变量为`string`类型，你只能给它赋`string`值。所有进一步使用这个变量的代码必须将其视为`string`类型。这有助于确保我们编写的代码会按预期运行。虽然强类型在处理简单的字符串和数字时似乎没有任何用处，但当我们将相同的规则应用于对象、对象组、函数定义和类时，它确实变得重要。如果你编写了一个函数，期望第一个参数是`string`，第二个参数是`number`，如果有人用`boolean`作为第一个参数，另一个东西作为第二个参数调用你的函数，你是无法责怪的。

JavaScript 程序员一直严重依赖文档来理解如何调用函数，以及正确的函数参数的顺序和类型。但是，如果我们能够将所有这些文档包含在 IDE 中呢？然后，当我们编写代码时，我们的编译器可以自动指出我们错误地使用了对象和函数。这肯定会使我们更高效，更有生产力的程序员，使我们能够生成更少错误的代码。

TypeScript 确实做到了这一点。它引入了一种非常简单的语法来定义变量或函数参数的类型，以确保我们以正确的方式使用这些对象、变量和函数。如果我们违反了这些规则，TypeScript 编译器将自动生成错误，指出我们代码中的错误行。

这就是 TypeScript 得名的原因。它是带有强类型的 JavaScript - 因此是 TypeScript。让我们来看看这种非常简单的语言语法，它使 TypeScript 中的“类型”成为可能。

## 类型语法

声明变量类型的 TypeScript 语法是在变量名后面加上冒号（`:`），然后指定其类型。考虑以下 TypeScript 代码：

```ts
var myString : string = "test";
var myNumber: number = 1;
var myBoolean : boolean = true;
```

这段代码片段是我们前面的 JavaScript 代码的 TypeScript 等价物，并展示了为`myString`变量声明类型的 TypeScript 语法的示例。通过包括冒号和关键字`string`（`: string`），我们告诉编译器`myString`变量是`string`类型。同样，`myNumber`变量是`number`类型，`myBoolean`变量是`boolean`类型。TypeScript 为每种基本 JavaScript 类型引入了`string`、`number`和`boolean`关键字。

如果我们尝试将一个不同类型的值赋给一个变量，TypeScript 编译器将生成编译时错误。在前面代码中声明的变量的情况下，以下 TypeScript 代码将生成一些编译错误：

```ts
myString = myNumber;
myBoolean = myString;
myNumber = myBoolean;
```

![类型语法](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-ts/img/9665OS_02-01.jpg)

在分配不正确的类型时，TypeScript 生成构建错误

TypeScript 编译器正在生成编译错误，因为我们试图混合这些基本类型。第一个错误是由编译器生成的，因为我们不能将`number`值赋给`string`类型的变量。同样，第二个编译错误表示我们不能将`string`值赋给`boolean`类型的变量。同样，第三个错误是因为我们不能将`boolean`值赋给`number`类型的变量。

TypeScript 语言引入的强类型语法意味着我们需要确保赋值操作符（`=`）左侧的类型与赋值操作符右侧的类型相同。

要修复前面的 TypeScript 代码并消除编译错误，我们需要做类似以下的事情：

```ts
myString = myNumber.toString();
myBoolean = (myString === "test");
if (myBoolean) {
    myNumber = 1;
}
```

我们的第一行代码已更改为在`myNumber`变量（类型为`number`）上调用`.toString()`函数，以返回一个`string`类型的值。这行代码不会生成编译错误，因为等号两边的类型相同。

我们的第二行代码也已更改，以便赋值操作符的右侧返回比较的结果，`myString === "test"`，这将返回一个`boolean`类型的值。因此，编译器将允许这段代码，因为赋值的两侧都解析为`boolean`类型的值。

我们代码片段的最后一行已更改为仅在`myBoolean`变量的值为`true`时将值`1`（类型为`number`）赋给`myNumber`变量。

Anders Hejlsberg 将这一特性描述为“语法糖”。通过在可比较的 JavaScript 代码上添加一些糖，TypeScript 使我们的代码符合了强类型规则。每当你违反这些强类型规则时，编译器都会为你的有问题的代码生成错误。

## 推断类型

TypeScript 还使用了一种叫做推断类型的技术，在你没有明确指定变量类型的情况下。换句话说，TypeScript 会找到代码中变量的第一次使用，找出变量最初初始化的类型，然后假定在代码块的其余部分中该变量的类型相同。举个例子，考虑以下代码：

```ts
var myString = "this is a string";
var myNumber = 1;
myNumber = myString;
```

我们首先声明了一个名为`myString`的变量，并给它赋了一个字符串值。TypeScript 确定这个变量被赋予了`string`类型的值，因此会推断出这个变量的任何进一步使用都是`string`类型。我们的第二个变量，名为`myNumber`，被赋予了一个数字。同样，TypeScript 推断出这个变量的类型是`number`。如果我们尝试在代码的最后一行将`myString`变量（类型为`string`）赋给`myNumber`变量（类型为`number`），TypeScript 将生成一个熟悉的错误消息：

```ts
error TS2011: Build: Cannot convert 'string' to 'number'

```

这个错误是由于 TypeScript 的推断类型规则所生成的。

## 鸭子类型

TypeScript 还对更复杂的变量类型使用了一种叫做鸭子类型的方法。鸭子类型意味着如果它看起来像鸭子，叫起来像鸭子，那么它很可能就是鸭子。考虑以下 TypeScript 代码：

```ts
var complexType = { name: "myName", id: 1 };
complexType = { id: 2, name: "anotherName" };
```

我们从一个名为`complexType`的变量开始，它被赋予了一个包含`name`和`id`属性的简单 JavaScript 对象。在我们的第二行代码中，我们可以看到我们正在重新分配这个`complexType`变量的值给另一个也有`id`和`name`属性的对象。编译器将在这种情况下使用鸭子类型来判断这个赋值是否有效。换句话说，如果一个对象具有与另一个对象相同的属性集，那么它们被认为是相同类型的。

为了进一步说明这一点，让我们看看编译器在我们尝试将一个不符合鸭子类型的对象分配给我们的`complexType`变量时的反应：

```ts
var complexType = { name: "myName", id: 1 };
complexType = { id: 2 };
complexType = { name: "anotherName" };
complexType = { address: "address" };
```

这段代码片段的第一行定义了我们的`complexType`变量，并将一个包含`id`和`name`属性的对象赋给它。从这一点开始，TypeScript 将在我们尝试分配给`complexType`变量的任何值上使用这个推断类型。在我们的第二行代码中，我们尝试分配一个具有`id`属性但没有`name`属性的值。在第三行代码中，我们再次尝试分配一个具有`name`属性但没有`id`属性的值。在代码片段的最后一行，我们完全错了。编译这段代码将生成以下错误：

```ts
error TS2012: Build: Cannot convert '{ id: number; }' to '{ name: string; id: number; }':
error TS2012: Build: Cannot convert '{ name: string; }' to '{ name: string; id: number; }':
error TS2012: Build: Cannot convert '{ address: string; }' to '{ name: string; id: number; }':

```

从错误消息中我们可以看到，TypeScript 使用鸭子类型来确保类型安全。在每条消息中，编译器都给出了关于有问题的代码的线索 - 明确说明了它期望的内容。`complexType`变量既有`id`属性，也有`name`属性。因此，要给`complexType`变量赋值，这个值将需要同时具有`id`和`name`属性。通过处理每一个错误，TypeScript 都明确说明了每一行代码的问题所在。

请注意，以下代码不会生成任何错误消息：

```ts
var complexType = { name: "myName", id: 1 };
complexType = { name: "name", id: 2, address: "address" };
```

再次，我们的第一行代码定义了 `complexType` 变量，就像我们之前看到的那样，具有 `id` 和 `name` 属性。现在，看一下这个例子的第二行。我们正在使用的对象实际上有三个属性：`name`、`id` 和 `address`。即使我们添加了一个新的 `address` 属性，编译器只会检查我们的新对象是否同时具有 `id` 和 `name`。因为我们的新对象具有这些属性，因此将匹配变量的原始类型，TypeScript 将允许通过鸭子类型进行此赋值。

推断类型和鸭子类型是 TypeScript 语言的强大特性——为我们的代码带来了强类型，而无需使用显式类型，即冒号 `:` 然后是类型说明符语法。

## 数组

除了基本的 JavaScript 类型字符串、数字和布尔值之外，TypeScript 还有两种其他数据类型：数组和枚举。让我们看一下定义数组的语法。

数组只是用 `[]` 符号标记，类似于 JavaScript，并且每个数组可以被强类型化以保存特定类型，如下面的代码所示：

```ts
var arrayOfNumbers: number[] = [1, 2, 3];
arrayOfNumbers = [3, 4, 5];
arrayOfNumbers = ["one", "two", "three"];
```

在这个代码片段的第一行，我们定义了一个名为 `arrayOfNumbers` 的数组，并进一步指定该数组的每个元素必须是 `number` 类型。然后，第二行重新分配了这个数组以保存一些不同的数值。

然而，这个片段的最后一行将生成以下错误消息：

```ts
error TS2012: Build: Cannot convert 'string[]' to 'number[]':

```

这个错误消息警告我们，变量 `arrayOfNumbers` 的强类型只接受 `number` 类型的值。我们的代码试图将一个字符串数组赋给这个数字数组，因此会生成一个编译错误。

## 任意类型

所有这些类型检查都很好，但 JavaScript 足够灵活，允许变量混合使用。以下代码片段实际上是有效的 JavaScript 代码：

```ts
var item1 = { id: 1, name: "item 1" };
item1 = { id: 2 };
```

我们的第一行代码将一个具有 `id` 属性和 `name` 属性的对象分配给变量 `item1`。然后，第二行将这个变量重新分配给一个只有 `id` 属性而没有 `name` 属性的对象。不幸的是，正如我们之前所见，TypeScript 会为前面的代码生成一个编译时错误：

```ts
error TS2012: Build: Cannot convert '{ id: number; }' to '{ id: number; name: string; }'

```

TypeScript 为这种情况引入了 `any` 类型。在本质上，指定对象的类型为 `any` 会放宽编译器的严格类型检查。以下代码显示了如何使用 `any` 类型：

```ts
var item1 : any = { id: 1, name: "item 1" };
item1 = { id: 2 };
```

注意我们的第一行代码已经改变。我们指定变量 `item1` 的类型为 `: any`，这样我们的代码就可以编译而不会出错。没有类型说明符 `: any`，第二行代码通常会生成一个错误。

## 显式转换

与任何强类型语言一样，总有一个时刻需要明确指定对象的类型。这个概念将在下一章中更加详细地展开，但在这里快速记录显式转换是值得的。可以使用 `< >` 语法将一个对象转换为另一个对象的类型。

### 注意

这不是严格意义上的转换；它更像是 TypeScript 编译器在运行时使用的断言。您使用的任何显式转换都将在生成的 JavaScript 中被编译掉，并且不会影响运行时的代码。

让我们修改之前的代码片段来使用显式转换：

```ts
var item1 = <any>{ id: 1, name: "item 1" };
item1 = { id: 2 };
```

请注意，在这段代码片段的第一行，我们现在已经用右边的`<any>`显式转换替换了赋值左边的`: any`类型指定符。这段代码片段告诉编译器显式地转换，或者显式地将右边的`{ id: 1, name: "item 1" }`对象作为`any`类型处理。因此，`item1`变量也因此具有`any`类型（由于 TypeScript 的推断类型规则）。这样就允许我们在代码的第二行将只有`{ id: 2 }`属性的对象赋值给变量`item1`。在赋值的右边使用`< >`语法的这种技术称为显式转换。

虽然`any`类型是 TypeScript 语言的一个必要特性，但它的使用应尽可能受到限制。它是一种确保与 JavaScript 兼容性的语言快捷方式，但过度使用`any`类型会很快导致难以发现的编码错误。与其使用`any`类型，不如尝试找出你正在使用的对象的正确类型，然后使用这种类型。我们在编程团队内使用一个缩写：**S.F.I.A.T.**（读作 sviat 或 sveat）。**Simply Find an Interface for the Any Type**。虽然这听起来有些愚蠢，但它强调了`any`类型应该总是被接口替换，所以只需找到它。接口是在 TypeScript 中定义自定义类型的一种方式，我们将在下一章中介绍接口。只需记住，通过积极尝试定义对象的类型应该是什么，我们正在构建强类型代码，因此保护自己免受未来的编码错误和错误的影响。

## 枚举

枚举是从其他语言（如 C#）借鉴过来的一种特殊类型，它提供了解决特殊数字问题的解决方案。枚举将人类可读的名称与特定数字关联起来。考虑以下代码：

```ts
enum DoorState {
    Open,
    Closed,
    Ajar
}
```

在这段代码片段中，我们定义了一个名为`DoorState`的`enum`，用于表示门的状态。这个门状态的有效值是`Open`、`Closed`或`Ajar`。在底层（在生成的 JavaScript 中），TypeScript 将为这些人类可读的枚举值分配一个数值。在这个例子中，`DoorState.Open`的枚举值将等于数值`0`。同样，枚举值`DoorState.Closed`将等于数值`1`，而`DoorState.Ajar`的枚举值将等于`2`。让我们快速看一下我们将如何使用这些枚举值：

```ts
window.onload = () => {
    var myDoor = DoorState.Open;
    console.log("My door state is " + myDoor.toString());
};
```

`window.onload`函数中的第一行创建了一个名为`myDoor`的变量，并将其值设置为`DoorState.Open`。第二行只是将`myDoor`的值记录到控制台。这个`console.log`函数的输出将是：

```ts
My door state is 0

```

这清楚地显示了 TypeScript 编译器已经用数值`0`替换了`DoorState.Open`的枚举值。现在让我们以稍微不同的方式使用这个枚举：

```ts
window.onload = () => {
    var openDoor = DoorState["Closed"];
    console.log("My door state is " + openDoor.toString());
};
```

这段代码片段使用字符串值"Closed"来查找`enum`类型，并将结果的枚举值赋给`openDoor`变量。这段代码的输出将是：

```ts
My door state is 1

```

这个示例清楚地显示了`DoorState.Closed`的枚举值与`DoorState["Closed"]`的枚举值相同，因为两种变体都解析为`1`的数值。最后，让我们看看当我们使用数组类型语法引用枚举时会发生什么：

```ts
window.onload = () => {
    var ajarDoor = DoorState[2];
    console.log("My door state is " + ajarDoor.toString());
};
```

在这里，我们将变量`openDoor`赋值为基于`DoorState`枚举的第二个索引值的枚举值。然而，这段代码的输出令人惊讶：

```ts
My door state is Ajar

```

您可能期望输出只是`2`，但这里我们得到的是字符串`"Ajar"` - 这是我们原始枚举名称的字符串表示。这实际上是一个巧妙的小技巧 - 允许我们访问枚举值的字符串表示。这种可能性的原因在于 TypeScript 编译器生成的 JavaScript。让我们看一下 TypeScript 编译器生成的闭包：

```ts
var DoorState;
(function (DoorState) {
    DoorState[DoorState["Open"] = 0] = "Open";
    DoorState[DoorState["Closed"] = 1] = "Closed";
    DoorState[DoorState["Ajar"] = 2] = "Ajar";
})(DoorState || (DoorState = {}));
```

这种看起来很奇怪的语法正在构建一个具有特定内部结构的对象。正是这种内部结构使我们能够以刚刚探索的各种方式使用这个枚举。如果我们在调试 JavaScript 时查询这个结构，我们将看到`DoorState`对象的内部结构如下：

```ts
DoorState
{...}
    [prototype]: {...}
    [0]: "Open"
    [1]: "Closed"
    [2]: "Ajar"
    [prototype]: []
    Ajar: 2
    Closed: 1
    Open: 0
```

`DoorState`对象有一个名为`"0"`的属性，其字符串值为`"Open"`。不幸的是，在 JavaScript 中，数字`0`不是有效的属性名称，因此我们不能简单地使用`DoorState.0`来访问此属性。相反，我们必须使用`DoorState[0]`或`DoorState["0"]`来访问此属性。`DoorState`对象还有一个名为`Open`的属性，其值设置为数字`0`。在 JavaScript 中，`Open`是一个有效的属性名称，因此我们可以使用`DoorState["Open"]`或简单地`DoorState.Open`来访问此属性，这在 JavaScript 中等同于同一个属性。

尽管底层的 JavaScript 可能有点令人困惑，但我们需要记住的是，枚举是一种方便的方式，可以为特殊数字定义一个易于记忆和人类可读的名称。使用易于阅读的枚举，而不是在代码中散布各种特殊数字，也使代码的意图更加清晰。使用应用程序范围的值`DoorState.Open`或`DoorState.Closed`比记住为`Open`设置值为`0`，`Closed`设置值为`1`，`ajar`设置值为`3`要简单得多。除了使我们的代码更易读、更易维护外，使用枚举还可以在这些特殊数字值发生变化时保护我们的代码库，因为它们都在一个地方定义了。

关于枚举的最后一点说明 - 如果需要，我们可以手动设置数值：

```ts
enum DoorState {
    Open = 3,
    Closed = 7,
    Ajar = 10
}
```

在这里，我们已经覆盖了枚举的默认值，将`DoorState.Open`设置为`3`，`DoorState.Closed`设置为`7`，`DoorState.Ajar`设置为`10`。

### Const 枚举

随着 TypeScript 1.4 的发布，我们还可以定义`const`枚举如下：

```ts
const enum DoorStateConst {
    Open,
    Closed,
    Ajar
}

var myState = DoorStateConst.Open;
```

这些类型的枚举主要是出于性能原因引入的，由此产生的 JavaScript 将不包含我们之前看到的`DoorStateConst`枚举的完整闭包定义。让我们快速看一下从这个`DoorStateConst`枚举生成的 JavaScript：

```ts
var myState = 0 /* Open */;
```

请注意，我们根本没有完整的 JavaScript 闭包`DoorStateConstenum`。编译器只是将`DoorStateConst.Open`枚举解析为其内部值`0`，并完全删除了`const enum`定义。

因此，使用 const 枚举时，我们无法引用枚举的内部字符串值，就像我们在之前的代码示例中所做的那样。考虑以下示例：

```ts
// generates an error
console.log(DoorStateConst[0]);
// valid usage
console.log(DoorStateConst["Open"]);
```

第一个`console.log`语句现在将生成一个编译时错误 - 因为我们没有完整的闭包可用于我们的 const 枚举的`[0]`属性。然而，这个`const`枚举的第二个用法是有效的，并将生成以下 JavaScript：

```ts
console.log(0 /* "Open" */);
```

使用 const 枚举时，只需记住编译器将剥离所有枚举定义，并直接将枚举的数值替换到我们的 JavaScript 代码中。

# 函数

JavaScript 使用`function`关键字、一组大括号，然后是一组花括号来定义函数。典型的 JavaScript 函数将被编写如下：

```ts
function addNumbers(a, b) {
    return a + b;
}

var result = addNumbers(1, 2);
var result2 = addNumbers("1", "2");
```

这段代码很容易理解；我们定义了一个名为`addNumbers`的函数，它接受两个变量并返回它们的和。然后我们调用这个函数，传入`1`和`2`的值。变量`result`的值将是`1` + `2`，即`3`。现在看看代码的最后一行。在这里，我们调用`addNumbers`函数，传入两个字符串作为参数，而不是数字。变量`result2`的值将是一个字符串`"12"`。这个字符串值似乎可能不是期望的结果，因为函数的名称是`addNumbers`。

将前面的代码复制到一个 TypeScript 文件中不会生成任何错误，但让我们在前面的 JavaScript 中插入一些类型规则，使其更加健壮：

```ts
function addNumbers(a: number, b: number): number {
    return a + b;
};

var result = addNumbers(1, 2);
var result2 = addNumbers("1", "2");
```

在这个 TypeScript 代码中，我们为`addNumbers`函数的两个参数`a`和`b`添加了`:number`类型，并且在`( )`括号后面也添加了`:number`类型。在这里放置类型描述符意味着函数本身的返回类型被强制类型化为返回一个`number`类型的值。然而，在 TypeScript 中，代码的最后一行将导致编译错误：

```ts
error TS2082: Build: Supplied parameters do not match any signature of call target:

```

这个错误消息是由于我们明确声明了函数应该只接受`number`类型的两个参数`a`和`b`，但在我们的错误代码中，我们传递了两个字符串。因此，TypeScript 编译器无法匹配一个名为`addNumbers`的函数的签名，该函数接受两个`string`类型的参数。

## 匿名函数

JavaScript 语言也有匿名函数的概念。这些是在定义时即时定义的函数，不指定函数名称。考虑以下 JavaScript 代码：

```ts
var addVar = function(a, b) {
    return a + b;
};

var result = addVar(1, 2);
```

这段代码定义了一个没有名称的函数，它添加了两个值。因为这个函数没有名称，所以它被称为匿名函数。然后将这个匿名函数分配给一个名为`addVar`的变量。然后，`addVar`变量可以作为一个函数调用，带有两个参数，并且返回值将是执行匿名函数的结果。在这种情况下，变量`result`将具有值`3`。

现在让我们用 TypeScript 重写前面的 JavaScript 函数，并添加一些类型语法，以确保函数只接受两个`number`类型的参数，并返回一个`number`类型的值：

```ts
var addVar = function(a: number, b: number): number {
    return a + b;
}

var result = addVar(1, 2);
var result2 = addVar("1", "2");
```

在这段代码中，我们创建了一个匿名函数，它只接受类型为`number`的参数`a`和`b`，并且返回类型为`number`的值。现在`a`和`b`参数的类型，以及函数的返回类型，都使用了`:number`语法。这是 TypeScript 注入到语言中的另一个简单的“语法糖”的例子。如果我们编译这段代码，TypeScript 将拒绝最后一行的代码，在这里我们尝试用两个字符串参数调用我们的匿名函数：

```ts
error TS2082: Build: Supplied parameters do not match any signature of call target:

```

## 可选参数

当我们调用一个期望参数的 JavaScript 函数，并且我们没有提供这些参数时，函数内部的参数值将是`undefined`。作为这一点的例子，考虑以下 JavaScript 代码：

```ts
var concatStrings = function(a, b, c) {
    return a + b + c;
}

console.log(concatStrings("a", "b", "c"));
console.log(concatStrings("a", "b"));
```

在这里，我们定义了一个名为`concatStrings`的函数，它接受三个参数`a`、`b`和`c`，并简单地返回这些值的总和。如果我们使用所有三个参数调用这个函数，就像在这个片段的倒数第二行中看到的那样，我们将在控制台中得到字符串`"abc"`。然而，如果我们只提供两个参数，就像在这个片段的最后一行中看到的那样，将在控制台中得到字符串`"abundefined"`。再次，如果我们调用一个函数并且不提供参数，那么这个参数，在我们的例子中是`c`，将简单地是`undefined`。

TypeScript 引入了问号`?`语法来表示可选参数。考虑以下 TypeScript 函数定义：

```ts
var concatStrings = function(a: string, b: string, c?: string) {
    return a + b + c;
}

console.log(concatStrings("a", "b", "c"));
console.log(concatStrings("a", "b"));
console.log(concatStrings("a"));
```

这是原始`concatStrings` JavaScript 函数的强类型版本，我们之前使用过。请注意在第三个参数的语法中添加了`?`字符：`c?: string`。这表示第三个参数是可选的，因此，除了最后一行之外，所有前面的代码都将编译成功。最后一行将生成一个错误：

```ts
error TS2081: Build: Supplied parameters do not match any signature of call target.

```

这个错误是因为我们试图用只有一个参数调用`concatStrings`函数。然而，我们的函数定义要求至少有两个参数，只有第三个参数是可选的。

### 注意

可选参数必须是函数定义中的最后一个参数。只要非可选参数在可选参数之前，你可以有任意数量的可选参数。

## 默认参数

可选参数函数定义的微妙变体允许我们指定参数的默认值，如果它没有从调用代码中作为参数传递进来。让我们修改前面的函数定义来使用可选参数：

```ts
var concatStrings = function(a: string, b: string, c: string = "c") {
    return a + b + c;
}

console.log(concatStrings("a", "b", "c"));
console.log(concatStrings("a", "b"));
```

这个函数定义现在已经去掉了`?`可选参数的语法，而是给最后一个参数赋了一个值："c:string = "c"。通过使用默认参数，如果我们没有为最后一个参数命名为`c`提供一个值，`concatStrings`函数将会用默认值"c"来替代。因此参数`c`将不会是`undefined`。最后两行代码的输出都将是"abc"。

### 注意

注意，使用默认参数语法将自动使参数变为可选。

## 参数变量

JavaScript 语言允许一个函数被调用时带有可变数量的参数。每个 JavaScript 函数都可以访问一个特殊的变量，名为`arguments`，它可以用来检索传递给函数的所有参数。例如，考虑以下 JavaScript 代码：

```ts
function testParams() {
    if (arguments.length > 0) {
        for (var i = 0; i < arguments.length; i++) {
            console.log("Argument " + i + " = " + arguments[i]);
        }
    }
}

testParams(1, 2, 3, 4);
testParams("first argument");
```

在这段代码中，我们定义了一个名为`testParams`的函数，没有任何命名参数。但请注意，我们可以使用特殊变量`arguments`来测试函数是否被调用了任何参数。在我们的示例中，我们可以简单地遍历`arguments`数组，并通过使用数组索引器`arguments[i]`将每个参数的值记录到控制台中。console.log 调用的输出如下：

```ts
Argument 0 = 1
Argument 1 = 2
Argument 2 = 3
Argument 3 = 4
Argument 0 = first argument

```

那么，在 TypeScript 中如何表示可变数量的函数参数呢？答案是使用所谓的剩余参数，或者三个点(`…`)的语法。下面是用 TypeScript 表达的等价`testParams`函数：

```ts
function testParams(...argArray: number[]) {
    if (argArray.length > 0) {
        for (var i = 0; i < argArray.length; i++) {
            console.log("argArray " + i + " = " + argArray[i]);
            console.log("arguments " + i + " = " + arguments[i]);
        }
    }

}

testParams(1);
testParams(1, 2, 3, 4);
testParams("one", "two");
```

请注意我们的`testParams`函数使用了`…argArray: number[]`的语法。这个语法告诉 TypeScript 编译器函数可以接受任意数量的参数。这意味着我们对这个函数的使用，即用`testParams(1)`或`testParams(1,2,3,4)`调用函数，都将正确编译。在这个版本的`testParams`函数中，我们添加了两个`console.log`行，只是为了展示`arguments`数组可以通过命名的剩余参数`argArray[i]`或通过普通的 JavaScript 数组`arguments[i]`来访问。

在这个示例中，最后一行将会生成一个编译错误，因为我们已经定义了剩余参数只接受数字，而我们正试图用字符串调用这个函数。

### 注意

使用`argArray`和`arguments`的微妙差异在于参数的推断类型。由于我们明确指定了`argArray`的类型为`number`，TypeScript 将把`argArray`数组的任何项都视为数字。然而，内部的`arguments`数组没有推断类型，因此将被视为`any`类型。

我们还可以在函数定义中结合普通参数和剩余参数，只要剩余参数是参数列表中的最后一个定义，如下所示：

```ts
function testParamsTs2(arg1: string,
    arg2: number, ...ArgArray: number[]) {
}
```

在这里，我们有两个名为`arg1`和`arg2`的普通参数，然后是一个`argArray`剩余参数。错误地将剩余参数放在参数列表的开头将生成一个编译错误。

## 函数回调

JavaScript 最强大的特性之一，事实上也是 Node 技术构建的基础，就是回调函数的概念。回调函数是传递到另一个函数中的函数。请记住 JavaScript 不是强类型的，所以变量也可以是一个函数。通过查看一些 JavaScript 代码来最好地说明这一点：

```ts
function myCallBack(text) {
    console.log("inside myCallback " + text);
}

function callingFunction(initialText, callback) {
    console.log("inside CallingFunction");
    callback(initialText);
}

callingFunction("myText", myCallBack);
```

在这里，我们有一个名为`myCallBack`的函数，它接受一个参数并将其值记录到控制台。然后我们定义了一个名为`callingFunction`的函数，它接受两个参数：`initialText`和`callback`。这个函数的第一行只是将`"inside CallingFunction"`记录到控制台。`callingFunction`的第二行是有趣的部分。它假设`callback`参数实际上是一个函数，并调用它。它还将`initialText`变量传递给`callback`函数。如果我们运行这段代码，将会得到两条消息记录到控制台，如下所示：

```ts
inside CallingFunction
inside myCallback myText

```

但是，如果我们不将函数作为回调传递会发生什么？在前面的代码中没有任何信号告诉我们`callingFunction`的第二个参数必须是一个函数。如果我们无意中使用字符串而不是函数作为第二个参数调用`callingFunction`函数，如下所示：

```ts
callingFunction("myText", "this is not a function");
```

我们将得到一个 JavaScript 运行时错误：

```ts
0x800a138a - JavaScript runtime error: Function expected

```

然而，防御性的程序员首先会检查`callback`参数是否实际上是一个函数，然后再调用它，如下所示：

```ts
function callingFunction(initialText, callback) {
    console.log("inside CallingFunction");
    if (typeof callback === "function") {
        callback(initialText);
    } else {
        console.log(callback + " is not a function");
    }
}

callingFunction("myText", "this is not a function");
```

请注意此代码片段的第三行，我们在调用之前检查`callback`变量的类型。如果它不是一个函数，我们就会在控制台上记录一条消息。在此片段的最后一行，我们正在执行`callingFunction`，但这次将一个字符串作为第二个参数传递。

代码片段的输出将是：

```ts
inside CallingFunction
this is not a function is not a function

```

因此，当使用函数回调时，JavaScript 程序员需要做两件事；首先，了解哪些参数实际上是回调，其次，编写无效使用回调函数的代码。

## 函数签名

TypeScript 强制类型的“语法糖”不仅适用于变量和类型，还适用于函数签名。如果我们能够在代码中记录 JavaScript 回调函数，然后在用户传递错误类型的参数给我们的函数时警告他们，那该多好啊？

TypeScript 通过函数签名来实现这一点。函数签名引入了一个`() =>`的箭头语法，来定义函数的外观。让我们用 TypeScript 重新编写前面的 JavaScript 示例：

```ts
function myCallBack(text: string) {
    console.log("inside myCallback " + text);
}

function callingFunction(initialText: string,
    callback: (text: string) => void)
{
    callback(initialText);
}

callingFunction("myText", myCallBack);
callingFunction("myText", "this is not a function");
```

我们的第一个函数定义`myCallBack`现在将`text`参数强制类型为`string`类型。我们的`callingFunction`函数有两个参数；`initialText`是`string`类型，`callback`现在具有新的函数签名语法。让我们更仔细地看一下这个函数签名：

```ts
callback: (text: string) => void
```

这个函数定义的意思是，`callback`参数被类型化（通过`:`语法）为一个函数，使用箭头语法`() =>`。此外，这个函数接受一个名为`text`的参数，类型为`string`。在箭头语法的右边，我们可以看到一个新的 TypeScript 基本类型，称为`void`。Void 是一个关键字，用于表示函数不返回值。

因此，`callingFunction`函数只会接受一个函数作为其第二个参数，该函数接受一个字符串参数并且不返回任何值。编译前面的代码将正确地突出显示代码片段的最后一行中的错误，即我们将一个字符串作为第二个参数传递，而不是一个回调函数：

```ts
error TS2082: Build: Supplied parameters do not match any signature of call target:
Type '(text: string) => void' requires a call signature, but type 'String' lacks one

```

鉴于回调函数的前面函数签名，以下代码也会生成编译时错误：

```ts
function myCallBackNumber(arg1: number) {
    console.log("arg1 = " + arg1);
}

callingFunction("myText", myCallBackNumber);
```

在这里，我们定义了一个名为`myCallBackNumber`的函数，它以一个数字作为唯一参数。当我们尝试编译这段代码时，我们将收到一个错误消息，指示`callback`参数，也就是我们的`myCallBackNumber`函数，也没有正确的函数签名。

```ts
Call signatures of types 'typeof myCallBackNumber' and '(text: string) => void' are incompatible.

```

`myCallBackNumber`的函数签名实际上应该是`(arg1:number) => void`，而不是所需的`(text: string) => void`，因此会出现错误。

### 注意

在函数签名中，参数名（`arg1`或`text`）不需要相同。只需要函数的参数数量、它们的类型和函数的返回类型相同。

这是 TypeScript 的一个非常强大的特性——在代码中定义函数的签名，并在用户调用函数时警告他们是否使用了正确的参数。正如我们在 TypeScript 介绍中看到的，当我们使用第三方库时，这一点尤为重要。在我们能够在 TypeScript 中使用第三方函数、类或对象之前，我们需要定义它们的函数签名。这些函数定义被放入一种特殊类型的 TypeScript 文件中，称为声明文件，并以`.d.ts`扩展名保存。我们将在第四章中深入了解声明文件，*编写和使用声明文件*。

## 函数回调和作用域

JavaScript 使用词法作用域规则来定义变量的有效作用域。这意味着变量的值由它在源代码中的位置来定义。嵌套函数可以访问在其父作用域中定义的变量。作为这一点的例子，考虑以下 TypeScript 代码：

```ts
function testScope() {
    var testVariable = "myTestVariable";
    function print() {
        console.log(testVariable);
    }
}

console.log(testVariable);
```

这段代码片段定义了一个名为`testScope`的函数。变量`testVariable`在这个函数内部定义。`print`函数是`testScope`的子函数，因此它可以访问`testVariable`变量。然而，代码的最后一行将生成一个编译错误，因为它试图使用`testVariable`变量，而这个变量在`testScope`函数体内部是有效的。

```ts
error TS2095: Build: Could not find symbol 'testVariable'.

```

简单吧？嵌套函数可以访问源代码中的变量，取决于它在源代码中的位置。这一切都很好，但在大型 JavaScript 项目中，有许多不同的文件，代码的许多部分都设计为可重用。

让我们看看这些作用域规则如何成为一个问题。对于这个示例，我们将使用一个典型的回调场景——使用 jQuery 执行异步调用来获取一些数据。考虑以下 TypeScript 代码：

```ts
var testVariable = "testValue";

function getData() {
    var testVariable_2 = "testValue_2";
    $.ajax(
        {
            url: "/sample_json.json",
            success: (data, status, jqXhr) => {
                console.log("success : testVariable is "
                    + testVariable);
                console.log("success : testVariable_2 is" 
                    + testVariable_2);
            },
            error: (message, status, stack) => {
                alert("error " + message);
            }
        }
   );
}

getData();
```

在这段代码片段中，我们定义了一个名为`testVariable`的变量并设置了它的值。然后我们定义了一个名为`getData`的函数。`getData`函数设置了另一个名为`testVariable_2`的变量，然后调用了 jQuery 的`$.ajax`函数。`$.ajax`函数配置了三个属性：`url`、`success`和`error`。`url`属性是一个简单的字符串，指向项目目录中的`sample_json.json`文件。`success`属性是一个匿名函数回调，简单地将`testVariable`和`testVariable_2`的值记录到控制台中。最后，`error`属性也是一个匿名函数回调，简单地弹出一个警告。

这段代码按预期运行，成功函数将把以下结果记录到控制台中：

```ts
success : testVariable is :testValue
success : testVariable_2 is :testValue_2

```

到目前为止一切都很好。现在，假设我们正在尝试重构前面的代码，因为我们正在做一些类似的`$.ajax`调用，并希望在其他地方重用`success`回调函数。我们可以很容易地切换掉这个匿名函数，并为我们的`success`回调创建一个命名函数，如下所示：

```ts
var testVariable = "testValue";

function getData() {
    var testVariable_2 = "testValue_2";
    $.ajax(
        {
            url: "/sample_json.json",
            success: successCallback,
            error: (message, status, stack) => {
                alert("error " + message);
            }
        }
   );
}

function successCallback(data, status, jqXhr) {
    console.log("success : testVariable is :" + testVariable);
    console.log("success : testVariable_2 is :" + testVariable_2);
}

getData();
```

在这个示例中，我们创建了一个名为`successCallback`的新函数，参数与之前的匿名函数相同。我们还修改了`$.ajax`调用，只需将这个函数作为`success`属性的回调函数传递进去：`success: successCallback`。如果我们现在编译这段代码，TypeScript 会生成一个错误，如下所示：

```ts
error TS2095: Build: Could not find symbol ''testVariable_2''.

```

由于我们改变了代码的词法作用域，通过创建一个命名函数，新的`successCallback`函数不再可以访问变量`testVariable_2`。

### 注意

在一个简单的示例中很容易发现这种错误，但在更大的项目中，以及在使用第三方库时，这些错误变得更难追踪。因此，值得一提的是，在使用回调函数时，我们需要理解词法作用域。如果你的代码期望一个属性有一个值，在回调之后它没有一个值，那么记得查看调用代码的上下文。

## 函数重载

由于 JavaScript 是一种动态语言，我们经常可以用不同的参数类型调用同一个函数。考虑以下 JavaScript 代码：

```ts
function add(x, y) {
    return x + y;
}

console.log("add(1,1)=" + add(1,1));
console.log("add(''1'',''1'')=" + add("1", "1"));
console.log("add(true,false)=" + add(true, false));
```

在这里，我们定义了一个简单的`add`函数，返回其两个参数`x`和`y`的和。这段代码片段的最后三行只是记录了`add`函数的不同类型的结果：两个数字、两个字符串和两个布尔值。如果我们运行这段代码，将会看到以下输出：

```ts
add(1,1)=2
add('1','1')=11
add(true,false)=1

```

TypeScript 引入了一种特定的语法来表示同一个函数的多个函数签名。如果我们要在 TypeScript 中复制上述代码，我们需要使用函数重载语法：

```ts
function add(arg1: string, arg2: string): string;
function add(arg1: number, arg2: number): number;
function add(arg1: boolean, arg2: boolean): boolean;
function add(arg1: any, arg2: any): any {
    return arg1 + arg2;
}

console.log("add(1,1)=" + add(1, 1));
console.log("add(''1'',''1'')=" + add("1", "1"));
console.log("add(true,false)=" + add(true, false));
```

这段代码片段的第一行指定了一个`add`函数的函数重载签名，接受两个字符串并返回一个`string`。第二行指定了另一个使用数字的函数重载，第三行使用布尔值。第四行包含了函数的实际体，并使用了`any`类型说明符。片段的最后三行展示了我们如何使用这些函数签名，与我们之前使用的 JavaScript 代码类似。

在上述代码片段中有三个值得注意的地方。首先，片段的前三行中的函数签名实际上都没有函数体。其次，最终的函数定义使用了`any`类型说明符，并最终包括了函数体。函数重载的语法必须遵循这个结构，包括函数体的最终函数签名必须使用`any`类型说明符，因为其他任何类型都会生成编译时错误。

第三点需要注意的是，我们通过使用这些函数重载签名，限制了`add`函数只接受两个相同类型的参数。如果我们尝试混合类型；例如，如果我们用一个`boolean`和一个`string`调用函数，如下所示：

```ts
console.log("add(true,''1'')", add(true, "1"));
```

TypeScript 会生成编译错误：

```ts
error TS2082: Build: Supplied parameters do not match any signature of call target:
error TS2087: Build: Could not select overload for ''call'' expression.

```

这似乎与我们最终的函数定义相矛盾。在原始的 TypeScript 示例中，我们有一个接受`(arg1: any, arg2: any)`的函数签名；因此，理论上当我们尝试将一个`boolean`和一个`number`相加时，应该调用这个函数。然而，TypeScript 的函数重载语法不允许这样做。请记住，函数重载的语法必须包括对函数体的`any`类型的使用，因为所有的重载最终都会调用这个函数体。然而，在函数体之上包含函数重载的部分告诉编译器，这些是调用代码可用的唯一签名。

## 联合类型

随着 TypeScript 1.4 的发布，我们现在可以使用管道符(`|`)来表示联合类型，将一个或两个类型组合起来。因此，我们可以将前面代码片段中的`add`函数重写为以下形式：

```ts
function addWithUnion(
    arg1: string | number | boolean,
    arg2: string | number | boolean
     ): string | number | boolean
    {
    if (typeof arg1 === "string") {
        // arg1 is treated as a string here
        return arg1 + "is a string";
    }
    if (typeof arg1 === "number") {
        // arg1 is treated as a number here
        return arg1 + 10;
    }
    if (typeof arg1 === "boolean") {
        // arg1 is treated as a boolean here
        return arg1 && false;
    }
}
```

这个名为`addWithUnion`的函数有两个参数，`arg1`和`arg2`。这些参数现在使用联合类型语法来指定这些参数可以是`string`、`number`或`boolean`。还要注意，我们函数的返回类型再次使用联合类型，这意味着函数也将返回其中的一个类型。

### 类型保护

在前面代码片段的`addWithUnion`函数体内，我们检查`arg1`参数的类型是否为字符串，语句为`typeof arg1 === "string"`。这被称为类型保护，意味着`arg1`的类型将在`if`语句块内被视为`string`类型。在下一个`if`语句的函数体内，`arg1`的类型将被视为数字，允许我们将`10`添加到它的值，在最后一个 if 语句的函数体内，编译器将把类型视为`boolean`。

### 类型别名

我们还可以为类型、联合类型或函数定义定义别名。类型别名使用`type`关键字表示。因此，我们可以将前面的`add`函数写成如下形式：

```ts
type StringNumberOrBoolean = string | number | boolean;

function addWithAliases(
    arg1: StringNumberOrBoolean,
    arg2: StringNumberOrBoolean
     ): StringNumberOrBoolean {

}
```

在这里，我们定义了一个名为`StringNumberOrBoolean`的类型别名，它是`string`、`number`和`boolean`类型的联合类型。

类型别名也可以用于函数签名，如下所示：

```ts
type CallbackWithString = (string) => void;

function usingCallback(callback: CallbackWithString) {
    callback("this is a string");
}
```

在这里，我们定义了一个名为`CallbackWithString`的类型别名，它是一个接受单个`string`参数并返回`void`的函数。我们的`usingCallback`函数在函数签名中接受这个类型别名作为`callback`参数的类型。

# 总结

在本章中，我们讨论了 TypeScript 的基本类型、变量和函数技术。我们看到 TypeScript 如何在普通 JavaScript 代码的基础上引入了“语法糖”，以确保强类型的变量和函数签名。我们还看到 TypeScript 如何使用鸭子类型和显式转换，并以 TypeScript 函数、函数签名和重载结束。在下一章中，我们将在此基础上继续学习，看看 TypeScript 如何将这些强类型规则扩展到接口、类和泛型中。

为 Bentham Chang 准备，Safari ID bentham@gmail.com 用户编号：2843974 © 2015 Safari Books Online，LLC。此下载文件仅供个人使用，并受到服务条款的约束。任何其他用途均需版权所有者的事先书面同意。未经授权的使用、复制和/或分发严格禁止并违反适用法律。保留所有权利。


# 第三章：接口、类和泛型

我们已经看到 TypeScript 如何使用基本类型、推断类型和函数签名来为 JavaScript 带来强类型的开发体验。TypeScript 还引入了从其他面向对象语言借鉴的三个概念：接口、类和泛型。在本章中，我们将看看这些面向对象的概念在 TypeScript 中的使用，以及它们为 JavaScript 程序员带来的好处。

本章的第一部分适用于首次使用 TypeScript 的读者，并从基础开始介绍接口、类和继承。本章的第二部分建立在这些知识之上，展示如何创建和使用工厂设计模式。本章的第三部分涉及泛型。

如果您有 TypeScript 的经验，正在积极使用接口和类，了解继承，并且对应用于`this`参数的词法作用域规则感到满意，那么您可能对后面关于工厂设计模式或泛型的部分更感兴趣。

本章将涵盖以下主题：

+   接口

+   类

+   继承

+   闭包

+   工厂设计模式

+   类修饰符、静态函数和属性

+   泛型

+   运行时类型检查

# 接口

接口为我们提供了一种机制来定义对象必须实现的属性和方法。如果一个对象遵循一个接口，那么就说该对象实现了该接口。如果一个对象没有正确实现接口，TypeScript 会在我们的代码中更早地生成编译错误。接口也是定义自定义类型的另一种方式，除其他外，它在我们构造对象时提供了一个早期指示，即对象没有我们需要的属性和方法。

考虑以下 TypeScript 代码：

```ts
interface IComplexType {
    id: number;
    name: string;
}

var complexType : IComplexType = 
    { id: 1, name: "firstObject" };
var complexType_2: IComplexType = 
    { id: 2, description: "myDescription"};

if (complexType == complexType_2) {
    console.log("types are equal");
}
```

我们从一个名为`IComplexType`的接口开始，该接口具有`id`和`name`属性。`id`属性被强类型为`number`类型，`name`属性为`string`类型。然后我们创建一个名为`complexType`的变量，并使用`:`类型语法来指示该变量的类型为`IComplexType`。下一个变量名为`complexType_2`，也将该变量强类型为`IComplexType`类型。然后我们比较`complexType`和`complexType_2`变量，并在控制台中记录一条消息，如果这些对象相同。然而，这段代码将生成一个编译错误：

```ts
error TS2012: Build: Cannot convert 
'{ id: number; description: string; }' to 'IComplexType':

```

这个编译错误告诉我们`complexType_2`变量必须符合`IComplexType`接口。`complexType_2`变量有一个`id`属性，但它没有一个`name`属性。为了解决这个错误，并确保变量实现了`IComplexType`接口，我们只需要添加一个`name`属性，如下所示：

```ts
var complexType_2: IComplexType = {
    id: 2,
    name: "secondObject",
    description: "myDescription"
};
```

即使我们有额外的`description`属性，`IComplexType`接口只提到了`id`和`name`属性，所以只要我们有这些属性，对象就被认为是实现了`IComplexType`接口。

接口是 TypeScript 的一个编译时语言特性，编译器不会从您在 TypeScript 项目中包含的接口生成任何 JavaScript 代码。接口仅在编译步骤期间由编译器用于类型检查。

### 注意

在本书中，我们将坚持使用一个简单的接口命名约定，即在接口名称前加上字母`I`。使用这种命名方案有助于处理代码分布在多个文件的大型项目。在代码中看到任何以`I`为前缀的东西，可以立即将其识别为接口。但是，您可以随意命名您的接口。

# 类

类是对象的定义，它持有什么数据，以及可以执行什么操作。类和接口是面向对象编程原则的基石，并且通常在设计模式中一起工作。设计模式是一种简单的编程结构，已被证明是解决特定编程任务的最佳方式。稍后会详细介绍设计模式。

让我们使用类重新创建我们之前的代码示例：

```ts
interface IComplexType {
    id: number;
    name: string;
    print(): string;
}
class ComplexType implements IComplexType {
    id: number;
    name: string;
    print(): string {
        return "id:" + this.id + " name:" + this.name;
    }
}

var complexType: ComplexType = new ComplexType();
complexType.id = 1;
complexType.name = "complexType";
var complexType_2: ComplexType = new ComplexType();
complexType_2.id = 2;
complexType_2.name = "complexType_2";

window.onload = () => {
    console.log(complexType.print());
    console.log(complexType_2.print());
}
```

首先，我们有我们的接口定义（`IComplexType`），它有一个 `id` 和一个 `name` 属性，以及一个 `print` 函数。然后我们定义了一个名为 `ComplexType` 的类，该类实现了 `IComplexType` 接口。换句话说，`ComplexType` 的类定义必须与 `IComplexType` 接口定义相匹配。请注意，类定义不会创建一个变量——它只是定义了类的结构。然后我们创建了一个名为 `complexType` 的变量，然后将一个 `ComplexType` 类的新实例分配给这个变量。这行代码被称为创建类的实例。一旦我们有了类的实例，我们就可以设置类属性的值。代码的最后部分只是在 `window.onload` 函数中调用每个类的 `print` 函数。这段代码的输出如下：

```ts
id:1 name:complexType
id:2 name:complexType_2

```

## 类构造函数

类可以在初始构造时接受参数。如果我们看一下之前的代码示例，我们对 `ComplexType` 类的实例进行调用，然后设置其属性的调用可以简化为一行代码：

```ts
var complexType = new ComplexType(1, "complexType");
```

这个版本的代码将 `id` 和 `name` 属性作为类构造函数的一部分进行传递。然而，我们的类定义需要包括一个新的函数，名为 `constructor`，以接受这种语法。我们更新后的类定义将变成：

```ts
class ComplexType implements IComplexType {
    id: number;
    name: string;
    constructor(idArg: number, nameArg: string) {
        this.id = idArg;
        this.name = nameArg;
    }
    print(): string {
        return "id:" + this.id + " name:" + this.name;
    }
}
```

注意 `constructor` 函数。它是一个普通的函数定义，但使用了 `constructor` 关键字，并接受 `idArg` 和 `nameArg` 作为参数。这些参数被强类型为 `number` 和 `string` 类型。然后将 `ComplexType` 类的内部 `id` 属性赋值为 `idArg` 参数值。注意用于引用 `id` 属性的语法：`this.id`。类使用与对象相同的 `this` 语法来访问内部属性。如果我们尝试在不使用 `this` 关键字的情况下使用内部类属性，TypeScript 将生成编译错误。

## 类函数

类中的所有函数都遵循我们在上一章关于函数中涵盖的语法和规则。作为这些规则的复习，所有类函数都可以：

+   强类型

+   使用 `any` 关键字来放宽强类型

+   具有可选参数

+   具有默认参数

+   使用参数数组或剩余参数语法

+   允许函数回调并指定函数回调签名

+   允许函数重载

让我们修改我们的 `ComplexType` 类定义，并包括这些规则的示例：

```ts
class ComplexType implements IComplexType {
    id: number;
    name: string;
    constructor(idArg: number, nameArg: string);
    constructor(idArg: string, nameArg: string);
    constructor(idArg: any, nameArg: any) {
        this.id = idArg;
        this.name = nameArg;
    }
    print(): string {
        return "id:" + this.id + " name:" + this.name;
    }
    usingTheAnyKeyword(arg1: any): any {
        this.id = arg1;
    }
    usingOptionalParameters(optionalArg1?: number) {
        if (optionalArg1) {
            this.id = optionalArg1;
        }
    }
    usingDefaultParameters(defaultArg1: number = 0) {
        this.id = defaultArg1;
    }
    usingRestSyntax(...argArray: number []) {
        if (argArray.length > 0) {
            this.id = argArray[0];
        }
    }
    usingFunctionCallbacks( callback: (id: number) => string  ) {
        callback(this.id);
    }

}
```

要注意的第一件事是 `constructor` 函数。我们的类定义正在使用函数重载来定义 `constructor` 函数，允许使用一个 `number` 和一个 `string` 或两个字符串来构造类。以下代码展示了如何使用这些 `constructor` 定义：

```ts
var complexType: ComplexType = new ComplexType(1, "complexType");
var complexType_2: ComplexType = new ComplexType("1", "1");
var complexType_3: ComplexType = new ComplexType(true, true);
```

`complexType`变量使用构造函数的`number,` `string`变体，`complexType_2`变量使用`string,string`变体。`complexType_3`变量将生成编译错误，因为我们不允许构造函数使用`boolean,boolean`变体。然而，您可能会争辩说，最后一个构造函数指定了`any,any`变体，这应该允许我们使用`boolean,boolean`。只要记住，使用构造函数重载时，实际的构造函数实现必须使用与构造函数重载的任何变体兼容的类型。然后，我们的构造函数实现必须使用`any,any`变体。然而，由于我们使用构造函数重载，这个`any,any`变体被编译器隐藏，以支持我们的重载签名。

以下代码示例显示了我们如何使用我们为这个类定义的其余函数。让我们从`usingTheAnyKeyword`函数开始：

```ts
complexType.usingTheAnyKeyword(true);
complexType.usingTheAnyKeyword({id: 1, name: "test"});
```

此示例中的第一个调用使用布尔值调用`usingTheAnyKeyword`函数，第二个调用使用任意对象。这两个函数调用都是有效的，因为参数`arg1`定义为`any`类型。接下来是`usingOptionalParameters`函数：

```ts
complexType.usingOptionalParameters(1);
complexType.usingOptionalParameters();
```

在这里，我们首先使用单个参数调用`usingOptionalParameters`函数，然后再次调用时不使用任何参数。同样，这些调用都是有效的，因为`optionalArg1`参数被标记为可选。现在是`usingDefaultParameters`函数：

```ts
complexType.usingDefaultParameters(2);
complexType.usingDefaultParameters();
```

对`usingDefaultParameters`函数的这两个调用都是有效的。第一个调用将覆盖默认值 0，而第二个调用——没有参数——将使用默认值 0。接下来是`usingRestSyntax`函数：

```ts
complexType.usingRestSyntax(1, 2, 3);
complexType.usingRestSyntax(1, 2, 3, 4, 5);
```

我们的剩余函数`usingRestSyntax`可以使用任意数量的参数进行调用，因为我们使用剩余参数语法将这些参数保存在一个数组中。这两个调用都是有效的。最后，让我们看一下`usingFunctionCallbacks`函数：

```ts
function myCallbackFunction(id: number): string {
    return id.toString();
}
complexType.usingFunctionCallbacks(myCallbackFunction);
```

这段代码显示了一个名为`myCallbackFunction`的函数的定义。它匹配了`usingFunctionCallbacks`函数所需的回调签名，允许我们将`myCallbackFunction`作为参数传递给`usingFunctionCallbacks`函数。

请注意，如果您在理解这些不同的函数签名时遇到任何困难，请重新查看第二章中有关函数的相关部分，*类型、变量和函数技术*，其中详细解释了这些概念。

## 接口函数定义

接口与类一样，在处理函数时遵循相同的规则。要更新我们的`IComplexType`接口定义以匹配`ComplexType`类定义，我们需要为每个新函数编写一个函数定义，如下所示：

```ts
interface IComplexType {
    id: number;
    name: string;
    print(): string;
    usingTheAnyKeyword(arg1: any): any;
    usingOptionalParameters(optionalArg1?: number);
    usingDefaultParameters(defaultArg1?: number);
    usingRestSyntax(...argArray: number []);
    usingFunctionCallbacks(callback: (id: number) => string);
}
```

第 1 到 4 行构成了我们现有的接口定义，包括`id`和`name`属性以及我们一直在使用的`print`函数。第 5 行显示了如何为`usingTheAnyKeyword`函数定义一个函数签名。它看起来非常像我们实际的类函数，但没有函数体。第 6 行显示了如何为`usingOptionalParameters`函数使用可选参数。然而，第 7 行与我们的`usingDefaultParameters`函数的类定义略有不同。请记住，接口定义了我们的类或对象的形状，因此不能包含变量或值。因此，我们已将`defaultArg1`参数定义为可选的，并将默认值的赋值留给了类实现本身。第 8 行显示了包含剩余参数语法的`usingRestSyntax`函数的定义，第 9 行显示了带有回调函数签名的`usingFunctionCallbacks`函数的定义。它们与类函数签名几乎完全相同。

这个接口唯一缺少的是`constructor`函数的签名。如果我们在接口中包含`constructor`签名，TypeScript 会生成一个错误。假设我们在`IComplexType`接口中包含`constructor`函数的定义：

```ts
interface IComplexType {

    constructor(arg1: any, arg2: any);

}
```

TypeScript 编译器会生成一个错误：

```ts
Types of property 'constructor' of types 'ComplexType' and 'IComplexType' are incompatible

```

这个错误告诉我们，当我们使用`constructor`函数时，构造函数的返回类型会被 TypeScript 编译器隐式地确定。因此，`IComplexType`构造函数的返回类型将是`IComplexType`，而`ComplexType`构造函数的返回类型将是`ComplexType`。即使`ComplexType`函数实现了`IComplexType`接口，它们实际上是两种不同的类型，因此`constructor`签名将始终不兼容，因此会出现编译错误。

# 继承

继承是面向对象编程的基石之一。继承意味着一个对象使用另一个对象作为其基本类型，从而“继承”了基本对象的所有特征，包括属性和函数。接口和类都可以使用继承。被继承的接口或类称为基接口或基类，进行继承的接口或类称为派生接口或派生类。TypeScript 使用`extends`关键字实现继承。

## 接口继承

作为接口继承的例子，考虑以下 TypeScript 代码：

```ts
interface IBase {
    id: number;
}

interface IDerivedFromBase extends IBase {
    name: string;
}

class DerivedClass implements IDerivedFromBase {
    id: number;
    name: string;
}
```

我们从一个名为`IBase`的接口开始，该接口定义了一个类型为数字的`id`属性。我们的第二个接口定义`IDerivedFromBase`从`IBase`继承，并因此自动包含`id`属性。然后，`IDerivedFromBase`接口定义了一个类型为字符串的`name`属性。由于`IDerivedFromBase`接口继承自`IBase`，因此它实际上有两个属性：`id`和`name`。`DerivedClass`的类定义实现了`IDerivedFromBase`接口，因此必须包含`id`和`name`属性，以成功实现`IDerivedFromBase`接口的所有属性。虽然在这个例子中我们只展示了属性，但是函数也适用相同的规则。

## 类继承

类也可以像接口一样使用继承。使用我们对`IBase`和`IDerivedFromBase`接口的定义，以下代码展示了类继承的一个例子：

```ts
class BaseClass implements IBase {
    id : number;
}

class DerivedFromBaseClass 
    extends BaseClass 
    implements IDerivedFromBase 
{
    name: string;
}
```

第一个类名为`BaseClass`，实现了`IBase`接口，因此只需要定义一个类型为`number`的`id`属性。第二个类`DerivedFromBaseClass`继承自`BaseClass`类（使用`extends`关键字），同时实现了`IDerivedFromBase`接口。由于`BaseClass`已经定义了`IDerivedFromBase`接口中需要的`id`属性，`DerivedFromBaseClass`类需要实现的唯一其他属性是`name`属性。因此，我们只需要在`DerivedFromBaseClass`类中包含`name`属性的定义。

## 使用 super 进行函数和构造函数重载

在使用继承时，通常需要创建一个具有定义构造函数的基类。然后，在任何派生类的构造函数中，我们需要调用基类的构造函数并传递这些参数。这称为构造函数重载。换句话说，派生类的构造函数重载了基类的构造函数。TypeScript 包括`super`关键字，以便使用相同名称调用基类的函数。以下代码片段最好解释了这一点：

```ts
class BaseClassWithConstructor {
    private _id: number;
    constructor(id: number) {
        this._id = id;
    }
}

class DerivedClassWithConstructor extends BaseClassWithConstructor {
    private _name: string;
    constructor(id: number, name: string) {
        this._name = name;
        super(id);
    }
}
```

在这段代码片段中，我们定义了一个名为`BaseClassWithConstructor`的类，它拥有一个私有的`_id`属性。这个类有一个需要`id`参数的`constructor`函数。我们的第二个类，名为`DerivedClassWithConstructor`，继承自`BaseClassWithConstructor`类。`DerivedClassWithConstructor`的构造函数接受一个`id`参数和一个`name`参数，但它需要将`id`参数传递给基类。这就是`super`调用的作用。`super`关键字调用了基类中与派生类中函数同名的函数。`DerivedClassWithConstructor`的构造函数的最后一行显示了使用`super`关键字的调用，将接收到的`id`参数传递给基类构造函数。

这个技术被称为函数重载。换句话说，派生类有一个与基类函数同名的函数，并且"重载"了这个函数的定义。我们可以在类中的任何函数上使用这个技术，不仅仅是在构造函数上。考虑以下代码片段：

```ts
class BaseClassWithConstructor {
    private _id: number;
    constructor(id: number) {
        this._id = id;
    }
    getProperties(): string {
        return "_id:" + this._id;
    }
}

class DerivedClassWithConstructor extends BaseClassWithConstructor {
    private _name: string;
    constructor(id: number, name: string) {
        this._name = name;
        super(id);
    }
    getProperties(): string {
        return "_name:" + this._name + "," + super.getProperties();
    }
}
```

`BaseClassWithConstructor`类现在有一个名为`getProperties`的函数，它只是返回类的属性的字符串表示。然而，我们的`DerivedClassWithConstructor`类还包括一个名为`getProperties`的函数。这个函数是对`getProperties`基类函数的函数重写。为了调用基类函数，我们需要包括`super`关键字，就像在调用`super`.`getProperties()`中所示的那样。

以下是前面代码的一个示例用法：

```ts
window.onload = () => {
    var myDerivedClass = new DerivedClassWithConstructor(1, "name");
    console.log(
        myDerivedClass.getProperties()
    );
}
```

这段代码创建了一个名为`myDerivedClass`的变量，并传入了`id`和`name`的必需参数。然后我们简单地将对`getProperties`函数的调用结果记录到控制台上。这段代码片段将导致以下控制台输出：

```ts
_name:name,_id:1

```

结果显示，`myDerivedClass`变量的`getProperties`函数将按预期调用基类的`getProperties`函数。

## JavaScript 闭包

在我们继续本章之前，让我们快速看一下 TypeScript 是如何通过闭包技术在生成的 JavaScript 中实现类的。正如我们在第一章中提到的，闭包是指引用独立变量的函数。这些变量本质上记住了它们被创建时的环境。考虑以下 JavaScript 代码：

```ts
function TestClosure(value) {
    this._value = value;
    function printValue() {
        console.log(this._value);
    }
    return printValue;
}

var myClosure = TestClosure(12);
myClosure();
```

在这里，我们有一个名为`TestClosure`的函数，它接受一个名为`value`的参数。函数的主体首先将`value`参数赋给一个名为`this._value`的内部属性，然后定义了一个名为`printValue`的内部函数，它将`this._value`属性的值记录到控制台上。有趣的是`TestClosure`函数的最后一行 - 我们返回了`printValue`函数。

现在看一下代码片段的最后两行。我们创建了一个名为`myClosure`的变量，并将调用`TestClosure`函数的结果赋给它。请注意，因为我们从`TestClosure`函数内部返回了`printValue`函数，这实质上也使得`myClosure`变量成为了一个函数。当我们在片段的最后一行执行这个函数时，它将执行内部的`printValue`函数，但会记住创建`myClosure`变量时使用的初始值`12`。代码的最后一行的输出将会将值`12`记录到控制台上。

这就是闭包的本质。闭包是一种特殊类型的对象，它将函数与创建它的初始环境结合在一起。在我们之前的示例中，由于我们将通过`value`参数传入的任何内容存储到名为`this._value`的局部变量中，JavaScript 会记住创建闭包时的环境，换句话说，创建时分配给`this._value`属性的任何内容都将被记住，并且可以在以后重复使用。

有了这个想法，让我们来看一下 TypeScript 编译器为我们刚刚使用的`BaseClassWithConstructor`类生成的 JavaScript：

```ts
var BaseClassWithConstructor = (function () {
    function BaseClassWithConstructor(id) {
        this._id = id;
    }
    BaseClassWithConstructor.prototype.getProperties = function () {
        return "_id:" + this._id;
    };
    return BaseClassWithConstructor;
})();
```

我们的闭包从第一行开始是`function () {`，并以最后一行的`}`结束。这个闭包首先定义了一个用作构造函数的函数：`BaseClassWithConstructor(id)`。请记住，当构造一个 JavaScript 对象时，它会继承或复制原始对象的`prototype`属性到新实例中。在我们的示例中，使用`BaseClassWithConstructor`函数创建的任何对象也将继承`getProperties`函数，因为它是`prototype`属性的一部分。此外，因为在`prototype`属性上定义的函数也在闭包内，它们将记住原始的执行环境和变量值。

然后，这个闭包被包围在第一行的开括号`(`和最后一行的闭括号`)`中——定义了一个被称为 JavaScript 函数表达式的东西。然后，这个函数表达式立即被最后两个大括号`();`执行。这种立即执行函数的技术被称为**立即调用函数表达式**（**IIFE**）。我们上面的 IIFE 然后被赋值给一个名为`BaseClassWithConstructor`的变量，使它成为一个一流的 JavaScript 对象，并且可以使用`new`关键字创建它。这就是 TypeScript 在 JavaScript 中实现类的方式。

TypeScript 用于类定义的底层 JavaScript 代码实际上是一个众所周知的 JavaScript 模式——称为**模块**模式。它使用闭包来捕获执行环境，并提供了一种公开类的公共 API 的方式，正如使用`prototype`属性所见。

好消息是，TypeScript 编译器将处理闭包的深入知识，如何编写它们以及如何使用模块模式来定义类，从而使我们能够专注于面向对象的原则，而无需编写 JavaScript 闭包使用这种样板代码。

# 工厂设计模式

为了说明我们如何在一个大型的 TypeScript 项目中使用接口和类，我们将快速地看一下一个非常著名的面向对象设计模式——工厂设计模式。

## 业务需求

例如，假设我们的业务分析师给了我们以下要求：

根据出生日期，您需要对人进行分类，并用`true`或`false`标志表示他们是否具有签署合同的法定年龄。如果一个人不到 2 岁，则被视为婴儿。婴儿不能签署合同。如果一个人不到 18 岁，则被视为儿童。儿童也不能签署合同。如果一个人超过 18 岁，则被视为成年人，只有成年人才能签署合同。

## 工厂设计模式的作用

工厂设计模式使用一个工厂类来根据提供的信息返回多个可能类中的一个实例。

这种模式的本质是将决策逻辑放在一个单独的类——工厂类中，用于创建哪种类型的类。工厂类然后返回几个微妙变化的类中的一个，它们根据其专业领域会做稍微不同的事情。为了使我们的逻辑工作，任何使用这些类之一的代码必须有一个所有类的变化都实现的公共契约（或属性和方法列表）。这是接口的完美场景。

为了实现我们需要的业务功能，我们将创建一个`Infant`类、一个`Child`类和一个`Adult`类。`Infant`和`Child`类在被问及是否能签署合同时会返回`false`，而`Adult`类会返回`true`。

### IPerson 接口和 Person 基类

根据我们的要求，工厂返回的类实例必须能够做两件事：以所需格式打印人的类别，并告诉我们他们是否能签署合同。为了完整起见，我们将包括一个第三个函数，打印出生日期。让我们定义一个接口来满足这个要求：

```ts
interface IPerson {
    getPersonCategory(): string;
    canSignContracts(): boolean;
    getDateOfBirth(): string;
}
```

我们的`IPerson`接口有一个`getPersonCategory`方法，它将返回他们类别的字符串表示：`"Infant"`、`"Child"`或`"Adult"`。`canSignContracts`方法将返回`true`或`false`，`getDateOfBirth`方法将简单地返回他们的出生日期的可打印版本。为了简化我们的代码，我们将创建一个名为`Person`的基类，它实现了这个接口，并处理所有类型的`Person`的通用数据和函数：存储和返回出生日期。我们的基类定义如下：

```ts
class Person {
    _dateOfBirth: Date
    constructor(dateOfBirth: Date) {
        this._dateOfBirth = dateOfBirth;
    }
    getDateOfBirth(): string {
        return this._dateOfBirth.toDateString();
    }
}
```

这个`Person`类定义是我们专业人员类型的基类。由于我们的每一个专业类都需要一个`getDateOfBirth`函数，我们可以将这个通用代码提取到一个基类中。构造函数需要一个日期，它存储在内部变量`_dateOfBirth`中，`getDateOfBirth`函数返回这个`_dateOfBirth`转换为字符串的值。

### 专业类

现在让我们来看看三种专业类的类型：

```ts
class Infant extends Person implements IPerson {
    getPersonCategory(): string {
        return "Infant";
    }
    canSignContracts() { return false; }
}

class Child extends Person implements IPerson {
    getPersonCategory(): string {
        return "Child";
    }
    canSignContracts() { return false; }
}

class Adult extends Person implements IPerson
{
    getPersonCategory(): string {
        return "Adult";
    }
    canSignContracts() { return true; }
}
```

此代码片段中的所有类都使用继承来扩展`Person`类。我们的`Infant`、`Child`和`Adult`类没有指定`constructor`方法，而是从它们的基类`Person`继承了这个`constructor`。每个类都实现了`IPerson`接口，因此必须提供`IPerson`接口定义所需的所有三个函数的实现。`getDateOfBirth`函数在`Person`基类中定义，因此这些派生类只需要实现`getPersonCategory`和`canSignContracts`函数即可。我们可以看到我们的`Infant`和`Child`类在`canSignContracts`上返回`false`，而我们的`Adult`类返回`true`。

### 工厂类

现在，让我们转向工厂类本身。这个类负责保存所有需要做出决定的逻辑，并返回`Infant`、`Child`或`Adult`类的实例：

```ts
class PersonFactory {
    getPerson(dateOfBirth: Date): IPerson {
        var dateNow = new Date();
        var dateTwoYearsAgo = new Date(dateNow.getFullYear()-2,
            dateNow.getMonth(), dateNow.getDay());
        var dateEighteenYearsAgo = new Date(dateNow.getFullYear()-18,
            dateNow.getMonth(), dateNow.getDay());

        if (dateOfBirth >= dateTwoYearsAgo) {
            return new Infant(dateOfBirth);
        }
        if (dateOfBirth >= dateEighteenYearsAgo) {
            return new Child(dateOfBirth);
        }
        return new Adult(dateOfBirth);
    }
}
```

`PersonFactory`类只有一个函数`getPerson`，它返回一个`IPerson`类型的对象。这个函数创建一个名为`dateNow`的变量，它被设置为当前日期。然后使用这个`dateNow`变量来计算另外两个变量，`dateTwoYearsAgo`和`dateEighteenYearsAgo`。然后决策逻辑接管，比较传入的`dateOfBirth`变量与这些日期。这个逻辑满足了我们的要求，并根据他们的出生日期返回一个新的`Infant`、`Child`或`Adult`类的实例。

## 使用工厂类

为了说明如何使用这个`PersonFactory`类，我们将使用以下代码，包装在`window.onload`函数中，以便我们可以在浏览器中运行它：

```ts
window.onload = () => {
    var personFactory = new PersonFactory();

    var personArray: IPerson[] = new Array();
    personArray.push(personFactory.getPerson(
        new Date(2014, 09, 29))); // infant
    personArray.push(personFactory.getPerson(
       new Date(2000, 09, 29))); // child
    personArray.push(personFactory.getPerson(
       new Date(1950, 09, 29))); // adult

    for (var i = 0; i < personArray.length; i++) {
        console.log(" A person with a birth date of :"
            + personArray[i].getDateOfBirth()
            + " is categorised as : "
            + personArray[i].getPersonCategory()
            + " and can sign : "
            + personArray[i].canSignContracts());
    }
}
```

在第 2 行，我们开始创建一个变量`personFactory`，用于保存`PersonFactory`类的一个新实例。第 4 行创建一个名为`personArray`的新数组，它被强类型化为只能容纳实现`IPerson`接口的对象。然后第 5 到 7 行通过使用`PersonFactory`类的`getPerson`函数向这个数组添加值，传入出生日期。请注意，`PersonFactory`类将根据我们传入的出生日期做出所有关于返回哪种类型对象的决定。

第 8 行开始一个`for`循环来遍历`personArray`数组，第 9 到 14 行使用`IPerson`接口定义来调用相关的打印函数。这段代码的输出如下：

![使用 Factory 类](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-ts/img/9665OS_03_01.jpg)

我们满足了业务需求，并同时实现了一个非常常见的设计模式。如果你发现自己在许多地方重复相同的逻辑，试图弄清楚一个对象是否属于一个或多个类别，那么很有可能你可以重构你的代码来使用工厂设计模式——避免在整个代码中重复相同的决策逻辑。

# 类修饰符

正如我们在开头章节简要讨论的那样，TypeScript 引入了`public`和`private`访问修饰符，用于标记变量和函数是公共的还是私有的。传统上，JavaScript 程序员使用下划线(`_`)作为变量的前缀来表示它们是私有变量。然而，这种命名约定并不能阻止任何人无意中修改这些变量。

让我们看一个 TypeScript 代码示例来说明这一点：

```ts
class ClassWithModifiers {
    private _id: number;
    private _name: string;
    constructor(id: number, name: string) {
        this._id = id;
        this._name = name;
    }
    modifyId(id: number) {
        this._id = id;
        this.updateNameFromId();
    }
    private updateNameFromId() {
        this._name = this._id.toString() + "_name";
    }
}

var myClass = new ClassWithModifiers(1, "name");
myClass.modifyId(2);
myClass._id = 2;
myClass.updateNameFromId();
```

我们从一个名为`ClassWithModifiers`的类开始，它有两个属性，`_id`和`_name`。我们用`private`关键字标记了这些属性，以防止它们被错误修改。我们的`constructor`接受一个传入的`id`和`name`参数，并将这些值分配给内部的私有属性`_id`和`_name`。我们定义的下一个函数叫做`modifyId`，它允许我们用新值更新内部的`_id`变量。`modifyId`函数然后调用一个名为`updateNameFromId`的内部函数。这个函数被标记为`private`，因此只允许在类定义的内部调用它。`updateNameFromId`函数简单地使用新的`_id`值来设置私有的`_name`值。

代码的最后四行展示了我们如何使用这个类。第一行创建了一个名为`myClass`的变量，并将其赋值为`ClassWithModifiers`类的一个新实例。第二行是合法的，并调用了`modifyId`函数。然而，第三行和第四行将生成编译时错误：

```ts
error TS2107: Build: 'ClassWithModifiers._id' is inaccessible.
error TS2107: Build: 'ClassWithModifiers.updateNameFromId' is inaccessible.

```

TypeScript 编译器警告我们，`_id`属性和`updateNameFromId`函数都是不可访问的——换句话说，是`private`的，并且不打算在类定义之外使用。

### 注意

类函数默认是`public`的。如果不为属性或函数指定`private`的访问修饰符，它们的访问级别将默认为`public`。

## 构造函数访问修饰符

TypeScript 还引入了前一个构造函数的简写版本，允许你直接在构造函数中指定带有访问修饰符的参数。这最好用代码来描述：

```ts
class ClassWithAutomaticProperties {
    constructor(public id: number, private name: string) {
    }
    print(): void {
        console.log("id:" + this.id + " name:" + this.name);
    }
}

var myAutoClass = new ClassWithAutomaticProperties(1, "name");
myAutoClass.id = 2;
myAutoClass.name = "test";
```

这段代码片段定义了一个名为`ClassWithAutomaticProperties`的类。`constructor`函数使用两个参数——一个类型为`number`的`id`和一个类型为`string`的`name`。然而，请注意，`id`的访问修饰符是`public`，而`name`的访问修饰符是`private`。这个简写自动创建了`ClassWithAutomaticProperties`类的一个公共`id`属性和一个私有`name`属性。

第 4 行的`print`函数在`console.log`函数中使用了这些自动属性。我们在`console.log`函数中引用了`this.id`和`this.name`，就像我们之前的代码示例中一样。

### 注意

这种简写语法仅在`constructor`函数内部可用。

我们可以看到第 9 行我们创建了一个名为`myAutoClass`的变量，并将`ClassWithAutomaticProperties`类的一个新实例分配给它。一旦这个类被实例化，它就自动拥有两个属性：一个类型为数字的`public`的`id`属性；和一个类型为字符串的`private`的`name`属性。然而，编译前面的代码将产生一个 TypeScript 编译错误：

```ts
error TS2107: Build: 'ClassWithAutomaticProperties.name' is inaccessible.

```

这个错误告诉我们，自动属性`name`被声明为`private`，因此在类外部不可用。

### 注意

虽然这种简写创建自动成员变量的技术是可用的，但我认为它使代码更难阅读。就我个人而言，我更喜欢不使用这种简写技术的更冗长的类定义。在类的顶部列出属性列表，使得阅读代码的人立即看到这个类使用了哪些变量，以及它们是`public`还是`private`。使用构造函数的自动属性语法有时会隐藏这些参数，迫使开发人员有时需要重新阅读代码以理解它。无论你选择哪种语法，都要尽量将其作为编码标准，并在整个代码库中使用相同的语法。

## 类属性访问器

ECMAScript 5 引入了属性访问器的概念。这允许一对`get`和`set`函数（具有相同的函数名）被调用代码视为简单的属性。这个概念最好通过一些简单的代码示例来理解：

```ts
class SimpleClass {
    public id: number;
}

var mySimpleClass = new SimpleClass();
mySimpleClass.id = 1;
```

在这里，我们有一个名为`SimpleClass`的类，它有一个公共的`id`属性。当我们创建这个类的一个实例时，我们可以直接修改这个`id`属性。现在让我们使用 ECMAScript 5 的`get`和`set`函数来实现相同的结果：

```ts
class SimpleClassWithAccessors {
    private _id: number;
    get id() {
        return this._id;
    }
    set id(value: number) {
        this._id = value;
    }
}

var mySimpleAccClass = new SimpleClassWithAccessors();
mySimpleClass.id = 1;
console.log("id has the value of " + mySimpleClass.id);
```

这个类有一个私有的`_id`属性和两个函数，都叫做`id`。这些函数中的第一个是由`get`关键字前缀的，简单地返回内部`_id`属性的值。这些函数中的第二个是由`set`关键字前缀的，并接受一个`value`参数。然后将内部`_id`属性设置为这个`value`参数。

在类定义的底部，我们创建了一个名为`mySimpleAccClass`的变量，它是`SimpleClassWithAccessors`类的一个实例。使用这个类的实例的人不会看到两个名为`get`和`set`的单独函数。他们只会看到一个`id`属性。当我们给这个属性赋值时，ECMAScript 5 运行时将调用`set id(value)`函数，当我们检索这个属性时，运行时将调用`get id()`函数。

### 注意

一些浏览器不支持 ECMAScript 5（如 Internet Explorer 8），当运行这段代码时会导致 JavaScript 运行时错误。

## 静态函数

静态函数是可以在不必先创建类的实例的情况下调用的函数。这些函数在其性质上几乎是全局的，但必须通过在函数名前加上类名来调用。考虑以下 TypeScript 代码：

```ts
class ClassWithFunction {
    printOne() {
        console.log("1");
    }
}

var myClassWithFunction = new ClassWithFunction();
myClassWithFunction.printOne();
```

我们从一个简单的类开始，名为`ClassWithFunction`，它有一个名为`printOne`的函数。`printOne`函数实际上并没有做任何有用的事情，除了将字符串`"1"`记录到控制台。然而，为了使用这个函数，我们需要首先创建一个类的实例，将其赋给一个变量，然后调用这个函数。

然而，使用静态函数，我们可以直接调用函数或属性：

```ts
class StaticClass {
    static printTwo() {
        console.log("2");
    }
}

StaticClass.printTwo();
```

`StaticClass`的类定义包括一个名为`printTwo`的函数，标记为`static`。从代码的最后一行可以看出，我们可以在不创建`StaticClass`类的实例的情况下调用这个函数。只要我们在函数前面加上类名，就可以直接调用这个函数。

### 注意

类的函数和属性都可以标记为静态的。

## 静态属性

静态属性在处理代码库中的所谓“魔术字符串”时非常方便。如果你在代码的各个部分依赖于一个字符串包含特定的值，那么现在是时候用静态属性替换这个“魔术字符串”了。在我们之前讨论的工厂设计模式中，我们创建了返回字符串值"Infant"、"Child"或"Adult"的专门的`Person`对象。如果我们后来编写的代码检查返回的字符串是否等于"Infant"或"Child"，如果我们将"Infant"拼错成"Infent"，就可能无意中破坏我们的逻辑：

```ts
if (value === "Infant") {
    // do something with an infant.
}
```

以下是我们可以使用的静态属性的示例，而不是那些“魔术字符串”：

```ts
class PersonType {
    static INFANT: string = "Infant";
    static CHILD: string = "Child";
    static ADULT: string = "Adult";
}
```

然后，在我们的代码库中，我们不再检查值是否等于字符串"Infant"，而是将它们与静态属性进行比较：

```ts
if (value === PersonType.INFANT) {
    // do something with an infant.
}
```

这段代码不再依赖于“魔术字符串”。字符串"Infant"现在记录在一个地方。只要所有的代码都使用静态属性`PersonType.Infant`，它就会更加稳定，更加抗变化。

# 泛型

泛型是一种编写代码的方式，可以处理任何类型的对象，但仍然保持对象类型的完整性。到目前为止，我们已经在示例中使用了接口、类和 TypeScript 的基本类型来确保我们的代码是强类型的（并且更不容易出错）。但是如果一段代码需要处理任何类型的对象会发生什么呢？

举个例子，假设我们想要编写一些代码，可以迭代一个对象数组并返回它们值的连接。所以，给定一个数字列表，比如`[1,2,3]`，它应该返回字符串`"1,2,3"`。或者，给定一个字符串列表，比如`["first","second","third"]`，返回字符串`"first,second,third"`。我们可以编写一些接受`any`类型值的代码，但这可能会在我们的代码中引入错误 - 记得 S.F.I.A.T.吗？我们想要确保数组的所有元素都是相同类型。这就是泛型发挥作用的地方。

## 泛型语法

让我们编写一个名为`Concatenator`的类，它可以处理任何类型的对象，但仍然确保类型完整性得到保持。所有 JavaScript 对象都有一个`toString`函数，每当运行时需要一个字符串时，它就会被调用，所以让我们使用这个`toString`函数来创建一个泛型类，输出数组中包含的所有值。

`Concatenator`类的泛型实现如下：

```ts
class Concatenator< T > {
    concatenateArray(inputArray: Array< T >): string {
        var returnString = "";

        for (var i = 0; i < inputArray.length; i++) {
            if (i > 0)
                returnString += ",";
            returnString += inputArray[i].toString();
        }
        return returnString;
    }
}
```

我们注意到的第一件事是类声明的语法，`Concatenator < T >`。这个`< T >`语法是用来表示泛型类型的语法，而在我们代码的其余部分中用于这个泛型类型的名称是`T`。`concatenateArray`函数也使用了这个泛型类型的语法，`Array < T >`。这表示`inputArray`参数必须是最初用于构造此类实例的类型的数组。

## 实例化泛型类

要使用这个泛型类的实例，我们需要构造这个类，并通过`< >`语法告诉编译器`T`的实际类型是什么。我们可以在这个泛型语法中使用任何类型作为`T`的类型，包括基本的 JavaScript 类型、TypeScript 类，甚至 TypeScript 接口：

```ts
var stringConcatenator = new Concatenator<string>();
var numberConcatenator = new Concatenator<number>();
var personConcatenator = new Concatenator<IPerson>();
```

注意我们用来实例化 `Concatenator` 类的语法。在我们的第一个示例中，我们创建了 `Concatenator` 泛型类的一个实例，并指定它应该在代码中使用 `T` 的地方用类型 `string` 替代 `T`。类似地，第二个示例创建了 `Concatenator` 类的一个实例，并指定在代码遇到泛型类型 `T` 时应该使用类型 `number`。我们的最后一个示例展示了使用 `IPerson` 接口作为泛型类型 `T`。

如果我们使用这个简单的替换原则，那么对于使用字符串的 `stringConcatenator` 实例，`inputArray` 参数必须是 `Array<string>` 类型。同样，这个泛型类的 `numberConcatenator` 实例使用数字，所以 `inputArray` 参数必须是一个数字数组。为了测试这个理论，让我们生成一个字符串数组和一个数字数组，看看如果我们试图违反这个规则编译器会报什么错误：

```ts
var stringArray: string[] = ["first", "second", "third"];
var numberArray: number[] = [1, 2, 3];
var stringResult = stringConcatenator.concatenateArray(stringArray);
var numberResult = numberConcatenator.concatenateArray(numberArray);
var stringResult2 = stringConcatenator.concatenateArray(numberArray);
var numberResult2 = numberConcatenator.concatenateArray(stringArray);
```

我们的前两行定义了我们的 `stringArray` 和 `numberArray` 变量来保存相关的数组。然后我们将 `stringArray` 变量传递给 `stringConcatenator` 函数——没有问题。在下一行，我们将 `numberArray` 传递给 `numberConcatenator`——仍然可以。

然而，当我们试图将一个数字数组传递给只能使用字符串的 `stringConcatenator` 时，问题就开始了。同样，如果我们试图将一个只允许数字的 `numberConcatenator` 配置为使用的字符串数组，TypeScript 将生成以下错误：

```ts
Types of property 'pop' of types 'string[]' and 'number[]' are incompatible.
Types of property 'pop' of types 'number[]' and 'string[]' are incompatible.

```

`pop` 属性是 `string[]` 和 `number[]` 之间的第一个不匹配的属性，所以很明显，我们试图传递一个数字数组，而应该使用字符串，反之亦然。同样，编译器警告我们没有正确使用代码，并强制我们在继续之前解决这些问题。

### 注意

泛型的这些约束是 TypeScript 的编译时特性。如果我们查看生成的 JavaScript，我们将看不到任何大量的代码，通过各种方式确保这些规则被传递到生成的 JavaScript 中。所有这些类型约束和泛型语法都会被简单地编译掉。在泛型的情况下，生成的 JavaScript 实际上是我们代码的一个非常简化的版本，看不到任何类型约束。

## 使用类型 T

当我们使用泛型时，重要的是要注意泛型类或泛型函数定义中的所有代码都必须尊重 `T` 的属性，就好像它是任何类型的对象一样。让我们更仔细地看一下在这种情况下 `concatenateArray` 函数的实现：

```ts
class Concatenator< T > {
    concatenateArray(inputArray: Array< T >): string {
        var returnString = "";

        for (var i = 0; i < inputArray.length; i++) {
            if (i > 0)
                returnString += ",";
            returnString += inputArray[i].toString();
        }
        return returnString;
    }
}
```

`concatenateArray` 函数强类型化了 `inputArray` 参数，所以它应该是 `Array <T>` 类型。这意味着使用 `inputArray` 参数的任何代码都只能使用所有数组共有的函数和属性，无论数组保存的是什么类型的对象。在这个代码示例中，我们在两个地方使用了 `inputArray`。

首先，在我们的 for 循环中，注意我们使用了 `inputArray.length` 属性。所有数组都有一个 `length` 属性来表示数组有多少项，所以使用 `inputArray.length` 在任何数组上都可以工作，无论数组保存的是什么类型的对象。其次，当我们使用 `inputArray[i]` 语法引用数组中的对象时，我们实际上返回了一个类型为 `T` 的单个对象。记住，无论我们在代码中使用 `T`，我们只能使用所有类型为 `T` 的对象共有的函数和属性。幸运的是，我们只使用了 `toString` 函数，而所有 JavaScript 对象，无论它们是什么类型，都有一个有效的 `toString` 函数。所以这个泛型代码块将编译通过。

让我们通过创建一个自己的类来测试这个 `T` 类型理论，然后将其传递给 `Concatenator` 类：

```ts
class MyClass {
    private _name: string;
    constructor(arg1: number) {
        this._name = arg1 + "_MyClass";
    }
}
var myArray: MyClass[] = [new MyClass(1), new MyClass(2), new MyClass(3)];
var myArrayConcatentator = new Concatenator<MyClass>();
var myArrayResult = myArrayConcatentator.concatenateArray(myArray);
console.log(myArrayResult);
```

这个示例以一个名为`MyClass`的类开始，该类有一个接受数字的`constructor`。然后，它将一个名为`_name`的内部变量赋值为`arg1`的值，与`"_MyClass"`字符串连接在一起。接下来，我们创建了一个名为`myArray`的数组，并在这个数组中构造了一些`MyClass`的实例。然后，我们创建了一个`Concatenator`类的实例，指定这个泛型实例只能与`MyClass`类型的对象一起使用。然后，我们调用`concatenateArray`函数，并将结果存储在一个名为`myArrayResult`的变量中。最后，我们在控制台上打印结果。在浏览器中运行这段代码将产生以下输出：

```ts
[object Object],[object Object],[object Object]

```

嗯，不太符合我们的预期！这个奇怪的输出是因为对象的字符串表示形式 - 不是基本 JavaScript 类型之一 - 解析为`[object type]`。您编写的任何自定义对象可能需要重写`toString`函数以提供人类可读的输出。我们可以通过在我们的类中提供`toString`函数的重写来很容易地修复这段代码，如下所示：

```ts
class MyClass {
    private _name: string;
    constructor(arg1: number) {
        this._name = arg1 + "_MyClass";
    }
    toString(): string {
        return this._name;
    }
}
```

在上面的代码中，我们用自己的实现替换了所有 JavaScript 对象继承的默认`toString`函数。在这个函数中，我们只是返回了`_name`私有变量的值。现在运行这个示例会产生预期的结果：

```ts
1_MyClass,2_MyClass,3_MyClass

```

## 限制 T 的类型

在使用泛型时，有时希望限制`T`的类型只能是特定类型或类型的子集。在这些情况下，我们不希望我们的泛型代码对任何类型的对象都可用，我们只希望它对特定的对象子集可用。TypeScript 使用继承来实现这一点。例如，让我们重构我们之前的工厂设计模式代码，使用一个特定设计为与实现`IPerson`接口的类一起工作的泛型`PersonPrinter`类：

```ts
class PersonPrinter< T extends IPerson> {
    print(arg: T) {
        console.log("Person born on "
            + arg.getDateOfBirth()
            + " is a "
            + arg.getPersonCategory()
            + " and is " +
            this.getPermissionString(arg)
            + "allowed to sign."
        );
    }
    getPermissionString(arg: T) {
        if (arg.canSignContracts())
            return "";
        return "NOT ";
    }
}
```

在这段代码片段中，我们定义了一个名为`PersonPrinter`的类，它使用了泛型语法。请注意，`T`泛型类型是从`IPerson`接口派生的，如`< T extents IPerson >`中的`extends`关键字所示。这表示`T`类型的任何使用都将替代`IPerson`接口，并且因此，只允许在使用`T`的任何地方使用`IPerson`接口中定义的函数或属性。`print`函数接受一个名为`arg`的参数，其类型为`T`。根据我们的泛型规则，我们知道`arg`变量的任何使用只允许使用`IPerson`接口中可用的函数。

`print`函数构建一个字符串以记录到控制台，并且只使用`IPerson`接口中定义的函数。这些函数包括`getDateOfBirth`和`getPersonCategory`。为了生成一个语法正确的句子，我们引入了另一个名为`getPermissionString`的函数，它接受一个`T`类型或`IPerson`接口的参数。这个函数简单地使用`IPerson`接口的`canSignContracts()`函数来返回一个空字符串或字符串`"NOT"`。

为了说明这个类的用法，考虑以下代码：

```ts
window.onload = () => {
    var personFactory = new PersonFactory();
    var personPrinter = new PersonPrinter<IPerson>();

    var child = personFactory.getPerson(new Date(2010, 0, 21));
    var adult = personFactory.getPerson(new Date(1969, 0, 21));
    var infant = personFactory.getPerson(new Date(2014, 0, 21));

    console.log(personPrinter.print(adult));
    console.log(personPrinter.print(child));
    console.log(personPrinter.print(infant));
}
```

首先，我们创建了`PersonFactory`类的一个新实例。然后我们创建了泛型`PersonPrinter`类的一个实例，并将参数`T`的类型设置为`IPerson`类型。这意味着传递给`PersonPrinter`实例的任何类都必须实现`IPerson`接口。我们从之前的例子中知道，`PersonFactory`将返回`Infant`、`Child`或`Adult`类的一个实例，而这些类都实现了`IPerson`接口。因此，我们知道`PersonFactory`返回的任何类都将被`personPrinter`泛型类实例接受。

接下来，我们实例化了名为`child`、`adult`和`infant`的变量，并依靠`PersonFactory`根据他们的出生日期返回正确的类。这个示例的最后三行简单地将`personPrinter`泛型类实例生成的句子记录到控制台上。

这段代码的输出和我们预期的一样：

![限制 T 的类型](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-ts/img/9665OS_03_02.jpg)

泛型 PersonFactory 输出

## 泛型接口

我们也可以使用泛型类型语法与接口一起使用。对于我们的`PersonPrinter`类，匹配的接口定义将是：

```ts
interface IPersonPrinter<T extends IPerson> {
    print(arg: T) : void;
    getPermissionString(arg: T): string;
}
```

这个接口看起来和我们的类定义一样，唯一的区别是`print`和`getPermissionString`函数没有实现。我们保留了使用`< T >`的泛型类型语法，并进一步指定类型`T`必须实现`IPerson`接口。为了将这个接口用于`PersonPrinter`类，我们修改类定义如下：

```ts
class PersonPrinter<T extends IPerson> implements IPersonPrinter<T> {

}
```

这个语法看起来很简单。和之前一样，我们使用`implements`关键字跟在类定义后面，然后使用接口名。但是需要注意的是，我们将类型`T`传递到`IPersonPrinter`接口定义中作为泛型类型`IPersonPrinter<T>`。这满足了`IPersonPrinter`泛型接口定义的要求。

定义我们的泛型类的接口进一步保护了我们的代码，防止它被无意中修改。举个例子，假设我们试图重新定义`PersonPrinter`类的类定义，使得`T`不再被限制为`IPerson`类型：

```ts
class PersonPrinter<T> implements IPersonPrinter<T> {

}
```

在这里，我们已经移除了`PersonPrinter`类中对类型`T`的约束。TypeScript 会自动生成一个错误：

```ts
Type 'T' does not satisfy the constraint 'IPerson' for type parameter 'T extends IPerson'.

```

这个错误指向了我们错误的类定义；代码中使用的`T`类型（`PersonPrinter<T>`）必须使用一个从`IPerson`继承的类型`T`。

## 在泛型中创建新对象

有时，泛型类可能需要创建一个作为泛型类型`T`传入的类型的对象。考虑以下代码：

```ts
class FirstClass {
    id: number;
}

class SecondClass {
    name: string;
}

class GenericCreator< T > {
    create(): T {
        return new T();
    }
}

var creator1 = new GenericCreator<FirstClass>();
var firstClass: FirstClass = creator1.create();

var creator2 = new GenericCreator<SecondClass>();
var secondClass : SecondClass = creator2.create();
```

在这里，我们有两个类定义，`FirstClass`和`SecondClass`。`FirstClass`只有一个公共的`id`属性，`SecondClass`有一个公共的`name`属性。然后我们有一个接受类型`T`的泛型类，并有一个名为`create`的函数。这个`create`函数试图创建一个类型`T`的新实例。

示例的最后四行展示了我们如何使用这个泛型类。`creator1`变量使用正确的语法创建了`FirstClass`类型的新实例。`creator2`变量是`GenericCreator`类的一个新实例，但这次使用的是`SecondClass`。不幸的是，前面的代码会生成一个 TypeScript 编译错误：

```ts
error TS2095: Build: Could not find symbol 'T'.

```

根据 TypeScript 文档，为了使泛型类能够创建类型为`T`的对象，我们需要通过它的`constructor`函数引用类型`T`。我们还需要将类定义作为参数传递。`create`函数需要重写如下：

```ts
class GenericCreator< T > {
    create(arg1: { new(): T }) : T {
        return new arg1();
    }
}
```

让我们把这个`create`函数分解成它的组成部分。首先，我们传递一个名为`arg1`的参数。然后，定义这个参数的类型为`{ new(): T }`。这是一个小技巧，允许我们通过它的`constructor`函数来引用`T`。我们定义了一个新的匿名类型，重载了`new()`函数并返回了一个类型`T`。这意味着`arg1`参数是一个被强类型化的函数，它具有返回类型为`T`的单个`constructor`。这个函数的实现简单地返回`arg1`变量的一个新实例。使用这种语法消除了我们之前遇到的编译错误。

然而，这个改变意味着我们必须将类定义传递给`create`函数，如下所示：

```ts
var creator1 = new GenericCreator<FirstClass>();
var firstClass: FirstClass = creator1.create(FirstClass);

var creator2 = new GenericCreator<SecondClass>();
var secondClass : SecondClass = creator2.create(SecondClass);
```

注意在第 2 行和第 5 行上`create`函数的用法的变化。我们现在需要传入我们的`T`类型的类定义作为第一个参数：`create(FirstClass)`和`create(SecondClass)`。尝试在浏览器中运行这段代码，看看会发生什么。泛型类实际上会创建`FirstClass`和`SecondClass`类型的新对象，正如我们所期望的。

# 运行时类型检查

尽管 TypeScript 编译器对类型不正确的代码生成编译错误，但这种类型检查在生成的 JavaScript 中被编译掉了。这意味着 JavaScript 运行时引擎对 TypeScript 接口或泛型一无所知。那么我们如何在运行时告诉一个类是否实现了一个接口呢？

JavaScript 有一些函数，当处理对象时可以告诉我们对象的类型，或者一个对象是否是另一个对象的实例。对于类型信息，我们可以使用 JavaScript 的`typeof`关键字，对于实例信息，我们可以使用`instanceof`。让我们看看在给定一些简单的 TypeScript 类时，这些函数返回什么，并看看我们是否可以使用它们来判断一个类是否实现了一个接口。

首先，一个简单的基类：

```ts
class TcBaseClass {
    id: number;
    constructor(idArg: number) {
        this.id = idArg;
    }
}
```

这个`TcBaseClass`类有一个`id`属性和一个根据传递给它的参数设置这个属性的`constructor`。

然后，一个从`TcBaseClass`派生的类：

```ts
class TcDerivedClass extends TcBaseClass {
    name: string;
    constructor(idArg: number, nameArg: string) {
        super(idArg);
        this.name = name;
    }
    print() {
        console.log(this.id + " " + this.name);
    }
}
```

这个`TcDerivedClass`类派生（或扩展）自`TcBase`类，并添加了一个`name`属性和一个`print`函数。这个派生类的构造函数必须调用基类的构造函数，通过`super`函数传递`idArg`参数。

现在，让我们构造一个名为`base`的变量，它是`TcBaseClass`的一个新实例，然后构造一个名为`derived`的变量，它是`TcDerivedClass`的一个新实例，如下所示：

```ts
var base = new TcBaseClass(1);
var derived = new TcDerivedClass(2, "second");
```

现在进行一些测试；让我们看看对于这些类，`typeof`函数返回什么：

```ts
console.log("typeof base: " + typeof base);
console.log("typeof derived: " + typeof derived);
```

这段代码将返回：

```ts
typeof base: object
typeof derived: object

```

这告诉我们 JavaScript 运行时引擎将一个类的实例视为一个对象。

现在，让我们转到`instanceof`关键字，并使用它来检查一个对象是否是从另一个对象派生的：

```ts
console.log("base instance of TcBaseClass : " + (base instanceof TcBaseClass));
console.log("derived instance of TcBaseClass: " + (derived instanceof TcBaseClass));
```

这段代码将返回：

```ts
base instance of TcBaseClass : true
derived instance of TcBaseClass: true

```

到目前为止一切顺利。现在让我们看看当我们在一个类的属性上使用`typeof`关键字时它返回什么：

```ts
console.log("typeof base.id: " +  typeof base.id);
console.log("typeof derived.name: " +  typeof derived.name);
console.log("typeof derived.print: " + typeof derived.print);
```

这段代码将返回：

```ts
 typeof base.id: number
 typeof derived.name: string
 typeof derived.print: function

```

正如我们所看到的，JavaScript 运行时正确地将我们的基本类型的`id`属性识别为数字，`name`属性为字符串，`print`属性为函数。

那么我们如何在运行时告诉对象的类型是什么？简单的答案是我们不能轻易地告诉。我们只能告诉一个对象是否是另一个对象的实例，或者一个属性是否是基本的 JavaScript 类型之一。如果我们试图使用`instanceof`函数来实现类型检查算法，我们需要检查传入的对象是否与对象树中的每个已知类型匹配，这显然不是理想的。我们也不能使用`instanceof`来检查一个类是否实现了一个接口，因为 TypeScript 接口被编译掉了。

## 反射

其他静态类型的语言允许运行时引擎查询对象，确定对象的类型，并查询对象实现了哪些接口。这个过程称为反射。

正如我们所看到的，使用`typeof`或`instanceof` JavaScript 函数，我们可以从运行时获取一些关于对象的信息。除了这些能力之外，我们还可以使用`getPrototypeOf`函数来返回有关类构造函数的一些信息。`getPrototypeOf`函数返回一个字符串，所以我们可以解析这个字符串来确定类名。不幸的是，`getPrototypeOf`函数的实现返回的字符串略有不同，这取决于使用的浏览器。它也只在 ECMAScript 5.1 及以上版本中实现，这可能在旧版浏览器或移动浏览器上运行时引入问题。

我们可以使用`hasOwnProperty`函数来查找关于对象的运行时信息。这是自 ECMAScript 3 以来 JavaScript 的一部分，因此与几乎所有桌面和移动浏览器兼容。`hasOwnProperty`函数将返回`true`或`false`，指示对象是否具有您正在寻找的属性。

TypeScript 编译器帮助我们以面向对象的方式使用接口来编写 JavaScript，但这些接口被“编译掉”，并不会出现在生成的 JavaScript 中。例如，让我们看一下以下 TypeScript 代码：

```ts
interface IBasicObject {
    id: number;
    name: string;
    print(): void;
}

class BasicObject implements IBasicObject {
    id: number;
    name: string;
    constructor(idArg: number, nameArg: string) {
        this.id = idArg;
        this.name = nameArg;
    }
    print() {
        console.log("id:" + this.id + ", name" + this.name);
    }
}
```

这是一个简单的例子，定义一个接口并在一个类中实现它。`IBasicObject`接口具有一个类型为`number`的`id`，一个类型为`string`的`name`，以及一个`print`函数。类定义`BasicObject`实现了所有必需的属性和参数。现在让我们来看一下 TypeScript 生成的编译后的 JavaScript：

```ts
var BasicObject = (function () {
    function BasicObject(idArg, nameArg) {
        this.id = idArg;
        this.name = nameArg;
    }
    BasicObject.prototype.print = function () {
        console.log("id:" + this.id + ", name" + this.name);
    };
    return BasicObject;
})();
```

TypeScript 编译器没有包含`IBasicObject`接口的任何 JavaScript。这里我们只有一个`BasicObject`类定义的闭包模式。虽然 TypeScript 编译器使用了`IBasicObject`接口，但在生成的 JavaScript 中并不存在。因此，我们说它已经被“编译掉”了。

因此，在 JavaScript 中实现类似反射的能力时，这给我们带来了一些问题：

+   我们无法在运行时确定对象是否实现了 TypeScript 接口，因为 TypeScript 接口被编译掉了

+   在旧的 ECMAScript 3 浏览器上，我们不能使用`getOwnPropertyNames`函数来循环遍历对象的属性

+   我们不能在旧的 ECMAScript 3 浏览器上使用`getPrototypeOf`函数来确定类名

+   `getPrototypeOf`函数的实现在不同的浏览器中并不一致

+   我们不能使用`instanceof`关键字来确定类类型，而不是与已知类型进行比较

## 检查对象是否具有一个函数

那么我们如何在运行时确定对象是否实现了一个接口？

在他们的书*Pro JavaScript Design Patterns* ([`jsdesignpatterns.com/`](http://jsdesignpatterns.com/))中，Ross Harmes 和 Dustin Diaz 讨论了这个困境，并提出了一个相当简单的解决方案。我们可以使用包含函数名称的字符串在对象上调用一个函数，然后检查结果是否有效，或者是`undefined`。在他们的书中，他们使用这个原则构建了一个实用函数，用于在运行时检查对象是否具有一组定义的属性和方法。这些定义的属性和方法被保存在 JavaScript 代码中作为简单的字符串数组。因此，这些字符串数组充当了我们的代码的对象“元数据”，我们可以将其传递给一个函数检查工具。

他们的`FunctionChecker`实用类可以在 TypeScript 中编写如下：

```ts
class FunctionChecker {
    static implementsFunction(
    objectToCheck: any, functionName: string): boolean
    {
        return (objectToCheck[functionName] != undefined &&
            typeof objectToCheck[functionName] == 'function');
    }
}
```

这个`FunctionChecker`类有一个名为`implementsFunction`的静态函数，它将返回`true`或`false`。`implementsFunction`函数接受一个名为`objectToCheck`的参数和一个名为`functionName`的字符串。请注意，`objectToCheck`的类型被明确定义为`any`。这是`any`类型实际上是正确的 TypeScript 类型的罕见情况之一。

在`implementsFunction`函数中，我们使用一种特殊的 JavaScript 语法，使用`[]`语法从对象的实例中读取函数本身，并通过名称引用它：`objectToCheck[functionName]`。如果我们正在查询的对象具有这个属性，那么调用它将返回除`undefined`之外的东西。然后我们可以使用`typeof`关键字来检查属性的类型。如果`typeof`实例返回“function”，那么我们知道这个对象实现了这个函数。让我们来看一些快速的用法：

```ts
var myClass = new BasicObject(1, "name");
var isValidFunction = FunctionChecker.implementsFunction(
    myClass, "print");
console.log("myClass implements the print() function :" + isValidFunction);
isValidFunction = FunctionChecker.implementsFunction(
    myClass, "alert");
console.log("myClass implements the alert() function :" + isValidFunction);
```

第 1 行，简单地创建了`BasicObject`类的一个实例，并将其赋给`myClass`变量。然后第 2 行调用我们的`implementsFunction`函数，传入类的实例和字符串“print”。第 3 行将结果记录到控制台。第 4 行和第 5 行重复这个过程，但是检查`myClass`实例是否实现了函数“alert”。这段代码的结果将是以下内容：

```ts
myClass implements the print() function :true
myClass implements the alert() function :false

```

这个`implementsFunction`函数允许我们询问一个对象，并检查它是否具有特定名称的函数。稍微扩展这个概念，就可以简单地进行运行时类型检查。我们只需要一个 JavaScript 对象应该实现的函数（或属性）列表。这个函数（或属性）列表可以被描述为类的“元数据”。

## 使用泛型进行接口检查

罗斯和达斯汀描述的这种持有接口“元数据”信息的技术在 TypeScript 中很容易实现。如果我们定义了为每个接口持有这些“元数据”的类，我们就可以在运行时使用它们来检查对象。让我们组合一个接口，其中包含一个方法名称数组，用于检查对象，以及一个属性名称列表。

```ts
interface IInterfaceChecker {
    methodNames?: string[];
    propertyNames?: string[];
}
```

这个`IInterfaceChecker`接口非常简单——一个可选的`methodNames`数组，和一个可选的`propertyNames`数组。现在让我们实现这个接口，描述 TypeScript 的`IBasicObject`接口的必要属性和方法：

```ts
class IIBasicObject implements IInterfaceChecker {
    methodNames: string[] = ["print"];
    propertyNames: string[] = ["id", "name"];
}
```

我们首先从实现`IInterfaceChecker`接口的类定义开始。这个类被命名为`IIBasicObject`，类名前缀有两个`I`。这是一个简单的命名约定，表示`IIBasicObject`类持有我们之前定义的`IBasicObject`接口的“元数据”。`methodNames`数组指定了这个接口必须实现`print`方法，`propertyNames`数组指定了这个接口还包括`id`和`name`属性。

为对象定义元数据的这种方法是我们问题的一个非常简单的解决方案，而且既不依赖于浏览器，也不依赖于 ECMAScript 的版本。虽然这可能需要我们将“元数据”对象与 TypeScript 接口保持同步，但现在我们已经有了必要的东西来检查一个对象是否实现了一个定义好的接口。

我们还可以利用我们对泛型的了解来实现一个使用这些对象“元数据”类的`InterfaceChecker`类：

```ts
class InterfaceChecker<T extends IInterfaceChecker> {
    implementsInterface(
        classToCheck: any,
        t: { new (): T; }
    ): boolean
    {
        var targetInterface = new t();
        var i, len: number;
        for (i = 0, len = targetInterface.methodNames.length; i < len; i++) {
            var method: string = targetInterface.methodNames[i];
            if (!classToCheck[method] ||
                typeof classToCheck[method] !== 'function') {
                console.log("Function :" + method + " not found");
                return false;
            }
        }
        for (i = 0, len = targetInterface.propertyNames.length; i < len; i++) {
            var property: string = targetInterface.propertyNames[i];
            if (!classToCheck[property] ||
                typeof classToCheck[property] == 'function') {
                console.log("Property :" + property + " not found");
                return false;
            }
        }
        return true;
    }
}
var myClass = new BasicObject(1, "name");
var interfaceChecker = new InterfaceChecker();

var isValid = interfaceChecker.implementsInterface(myClass, IIBasicObject);

console.log("myClass implements the IIBasicObject interface :" + isValid);
```

我们首先从一个泛型类`InterfaceChecker`开始，它接受任何实现`IInterfaceChecker`类的对象`T`。同样，`IInterface`类的定义只是一个`methodNames`数组和一个`propertyNames`数组。这个类只有一个名为`implementsInterface`的函数，它返回一个布尔值——如果类实现了所有属性和方法，则返回 true，否则返回 false。第一个参数`classToCheck`是我们正在对接口“元数据”进行询问的类实例。我们的第二个参数使用了我们之前讨论过的泛型语法，可以创建类型`T`的一个新实例——在这种情况下，是任何实现了`IInterfaceChecker`接口的类型。

代码的主体是我们之前讨论过的`FunctionChecker`类的扩展。我们首先需要创建类型`T`的一个实例，赋给变量`targetInterface`。然后我们简单地循环遍历`methodNames`数组中的所有字符串，并检查我们的`classToCheck`对象是否实现了这些函数。

然后我们重复这个过程，检查`propertyNames`数组中给定的字符串。

这段代码示例的最后几行展示了我们如何使用这个`InterfaceChecker`类。首先，我们创建了`BasicObject`的一个实例，并将其赋给变量`myClass`。然后我们创建了`InterfaceChecker`类的一个实例，并将其赋给变量`interfaceChecker`。

此片段的倒数第二行调用`implementsInterface`函数，传入`myClass`实例和`IIBasicObject`。请注意，我们并没有传入`IIBasicObject`类的实例，而是只传入了类定义。我们的通用代码将创建`IIBasicObject`类的内部实例。

此代码的最后一行只是将一个`true`或`false`消息记录到控制台。这行的输出将是：

```ts
myClass implements the IIBasicObject interface :true

```

现在让我们用一个无效的对象运行代码：

```ts
var noPrintFunction = { id: 1, name: "name" };
isValid = interfaceChecker.implementsInterface(
    noPrintFunction, IIBasicObject);
console.log("noPrintFunction implements the IIBasicObject interface:" + isValid);
```

变量`noPrintFunction`既有`id`属性又有`name`属性，但它没有实现`print`函数。这段代码的输出将是：

```ts
Function :print not found
noPrintFunction implements the IIBasicObject interface :false

```

现在我们有了一种在运行时确定对象是否实现了定义的接口的方法。这种技术可以用于您无法控制的外部 JavaScript 库，甚至可以用于更大的团队，在这些团队中，特定库的 API 在库编写之前原则上已经达成一致。在这些情况下，一旦交付了库的新版本，消费者就可以迅速轻松地确保 API 符合设计规范。

接口在许多设计模式中使用，即使我们可以使用 TypeScript 实现这些模式，我们可能还想通过运行时检查对象的接口来进一步巩固我们的代码。这种技术还打开了在 TypeScript 中编写**控制反转**（**IOC**）容器或领域事件模式的实现的可能性。我们将在第八章中更详细地探讨这两种设计模式，*TypeScript 面向对象编程*。

# 摘要

在本章中，我们探讨了接口、类和泛型的面向对象概念。我们讨论了接口继承和类继承，并利用我们对接口、类和继承的知识在 TypeScript 中创建了工厂设计模式的实现。然后我们转向泛型及其语法，泛型接口和泛型构造函数。最后，我们在反射方面进行了讨论，并使用泛型实现了 TypeScript 版本的`InterfaceChecker`模式。在下一章中，我们将看一下 TypeScript 用于与现有 JavaScript 库集成的机制——定义文件。

为 Bentham Chang 准备，Safari ID bentham@gmail.com 用户编号：2843974 © 2015 Safari Books Online，LLC。此下载文件仅供个人使用，并受到服务条款的约束。任何其他用途均需版权所有者的事先书面同意。未经授权的使用、复制和/或分发严格禁止并违反适用法律。保留所有权利。
