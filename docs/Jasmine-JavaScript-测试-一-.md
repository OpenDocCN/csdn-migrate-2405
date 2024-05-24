# Jasmine JavaScript 测试（一）

> 原文：[`zh.annas-archive.org/md5/298440D531543CD7EE2CF1AAAB25EE4F`](https://zh.annas-archive.org/md5/298440D531543CD7EE2CF1AAAB25EE4F)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

这本书是关于成为更好的 JavaScript 开发人员。因此，在这些章节中，您不仅将了解如何在 Jasmine 的“习惯用法”中编写测试，还将了解在 JavaScript 语言中编写软件的最佳实践。这是关于承认 JavaScript 作为应用程序开发的真正平台，并利用其所有潜力。这也涉及到工具和自动化，以及如何使您的生活更轻松和更高效。

最重要的是，这本书不仅关于工作软件的工艺，还关于精心制作的软件。

《Jasmine JavaScript 测试，第二版》是一个实用指南，用于为 Web 应用程序编写和自动化 JavaScript 测试。它使用诸如 Jasmine、Node.js 和 webpack 等技术。

在这些章节中，通过开发一个简单的股票市场投资跟踪应用程序来解释了测试驱动开发的概念。它从测试的基础知识开始，通过开发基本的领域类（如股票和投资），经过可维护的浏览器代码的概念，并最终进行了完整的重构，构建了一个基于 ECMA Script 6 模块和自动构建的 React.js 应用程序。

# 本书涵盖的内容

第一章，“使用 Jasmine 入门”，介绍了测试 JavaScript 应用程序背后的动机。它介绍了 BDD 的概念以及它如何帮助您编写更好的测试。它还演示了下载 Jasmine 并开始编写您的第一个测试有多么容易。

第二章，“您的第一个规范”，帮助您了解以测试驱动开发思维方式的背后思维过程。您将编写您的第一个由测试驱动的 JavaScript 功能。您还将了解 Jasmine 的基本功能以及如何组织您的测试。还演示了 Jasmine 匹配器的工作原理，以及如何创建自己的匹配器来改进测试代码的可读性。

第三章，“测试前端代码”，涵盖了编写可维护的浏览器代码的一些模式。您将了解如何以组件的形式思考，以及如何使用模块模式更好地组织您的源文件。您还将了解 HTML fixtures 的概念，以及如何使用它来测试您的 JavaScript 代码，而无需让服务器呈现 HTML。您还将了解一个名为“jasmine-jquery”的 Jasmine 插件，以及它如何帮助您使用 jQuery 编写更好的测试。

第四章，“异步测试 - AJAX”，讨论了测试 AJAX 请求中的挑战，以及如何使用 Jasmine 测试任何异步代码。您将了解 Node.js 以及如何创建一个非常简单的 HTTP 服务器，以用作测试的 fixture。

第五章，“Jasmine 间谍”，介绍了测试替身的概念以及如何使用间谍进行行为检查。

第六章，“光速单元测试”，帮助您了解 AJAX 测试中的问题，以及如何使用存根或伪造使您的测试运行更快。

第七章，“测试 React 应用程序”，向您介绍了 React，这是一个构建用户界面的库，并介绍了如何使用它来改进第三章“测试前端代码”中介绍的概念，以创建更丰富和更易维护的应用程序，当然，这是由测试驱动的。

第八章，“构建自动化”，向您展示了自动化的力量。它向您介绍了 webpack，这是一个用于前端资产捆绑的工具。您将开始以模块及其依赖项的方式思考，并学习如何将测试编码为模块。您还将了解有关将代码打包和缩小到生产环境以及如何自动化此过程的内容。最后，您将学习如何从命令行运行测试以及如何在*Travis.ci*的持续集成环境中使用它。

# 本书所需材料

除了浏览器和文本编辑器外，运行一些示例的唯一要求是 Node.js 0.10.x。

# 这本书适合谁

这本书是新接触单元测试概念的网页开发人员必备材料。假设您具有 JavaScript 和 HTML 的基本知识。

# 约定

在本书中，您将找到许多文本样式，用于区分不同类型的信息。以下是这些样式的一些示例及其含义的解释。

文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下：“我们可以通过使用`include`指令来包含其他上下文。”

代码块设置如下：

```js
describe("Investment", function() {
  it("should be of a stock", function() {
    expect(investment.stock).toBe(stock);
  });
});
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项将以粗体显示：

```js
describe("Investment", function() {
  it("should be of a stock", function() {
    **expect(investment.stock).toBe(stock);**
  });
});
```

任何命令行输入或输出都以以下形式编写：

```js
**# npm install --save-dev webpack**

```

**新术语**和**重要单词**以粗体显示。您在屏幕上看到的单词，例如菜单或对话框中的单词，会以这种形式出现在文本中：“单击**下一步**按钮将您移至下一个屏幕。”

### 注意

警告或重要说明会以这样的方式出现在框中。

### 提示

提示和技巧会以这种方式出现。


# 第一章：使用 Jasmine 入门

成为 JavaScript 开发人员是一个令人兴奋的时刻；技术已经成熟，Web 浏览器更加标准化，每天都有新的东西可以玩。JavaScript 已经成为一种成熟的语言，而 Web 是当今真正开放的平台。我们已经看到单页 Web 应用的兴起，**模型视图控制器**（**MVC**）框架的大量使用，如 Backbone.js 和 AngularJS，使用 Node.js 在服务器上使用 JavaScript，甚至使用诸如 PhoneGap 等技术完全使用 HTML、JavaScript 和 CSS 创建的移动应用程序。

从处理 HTML 表单的谦虚开始，到今天的大型应用程序，JavaScript 语言已经走了很远的路，随之而来的是一系列成熟的工具，以确保你在使用它时能够达到与其他语言相同的质量水平。

这本书是关于让你控制 JavaScript 开发的工具。

# JavaScript - 不好的部分

处理客户端 JavaScript 代码时会遇到许多复杂问题；显而易见的是，你无法控制客户端的运行时。在服务器上，你可以运行特定版本的 Node.js 服务器，但你无法强迫客户端运行最新版本的 Chrome 或 Firefox。

JavaScript 语言由 ECMAScript 规范定义；因此，每个浏览器都可以有自己的运行时实现，这意味着它们之间可能存在一些小的差异或错误。

此外，你还会遇到语言本身的问题。Brendan Eich 在 Netscape 受到很大的管理压力下，仅用 10 天时间开发了 JavaScript。尽管它在简洁性、一流函数和对象原型方面做得很好，但它也在试图使语言具有可塑性并允许其发展的过程中引入了一些问题。

每个 JavaScript 对象都是可变的；这意味着你无法阻止一个模块覆盖其他模块的部分。以下代码说明了覆盖全局`console.log`函数有多么简单：

```js
**console.log('test');**
**>> 'test'**
**console.log = 'break';**
**console.log('test');**
**>> TypeError: Property 'log' of object #<Console> is not a function**

```

这是语言设计上的一个有意识的决定；它允许开发人员对语言进行调整并添加缺失的功能。但是在拥有这样的权力的同时，很容易犯错。

ECMA 规范的第 5 版引入了`Object.seal`函数，一旦调用就可以防止对任何对象的进一步更改。但它目前的支持并不广泛；例如，Internet Explorer 只在其第 9 版上实现了它。

另一个问题是 JavaScript 处理类型的方式。在其他语言中，像`'1' + 1`这样的表达式可能会引发错误；在 JavaScript 中，由于一些不直观的类型强制转换规则，上述代码的结果是`'11'`。但主要问题在于它的不一致性；在乘法运算中，字符串被转换为数字，所以`'3' * 4`实际上是`12`。

这可能导致在大型表达式上出现一些难以发现的问题。假设你有一些来自服务器的数据，虽然你期望是数字，但一个值却是字符串：

```js
var a = 1, b = '2', c = 3, d = 4;
var result = a + b + c * d;
```

前面示例的结果值是`'1212'`，一个字符串。

这些只是开发人员面临的两个常见问题。在整本书中，你将应用最佳实践并编写测试，以确保你不会陷入这些和其他陷阱。

# Jasmine 和行为驱动开发

Jasmine 是由 Pivotal Labs 的开发人员创建的一个小型**行为驱动开发**（BDD）测试框架，允许你编写自动化的 JavaScript 单元测试。

但在我们继续之前，首先我们需要搞清楚一些基本知识，从测试单元开始。

测试单元是测试应用程序代码功能单元的一段代码。但有时，理解功能单元是什么可能会有些棘手，因此，为此，Dan North 提出了一种解决方案，即 BDD，这是对**测试驱动开发**（**TDD**）的重新思考。

在传统的单元测试实践中，开发人员在如何开始测试过程、要测试什么、测试的规模有多大，甚至如何调用测试等方面都没有明确的指导。

为了解决这些问题，丹从标准的敏捷构造中引入了**用户故事**的概念，作为编写测试的模型。

例如，音乐播放器应用程序可能有一个验收标准，如下所示：

**假设**有一个播放器，**当**歌曲被暂停时，**然后**它应该指示歌曲当前是暂停状态。

如下列表所示，这个验收标准是按照一个基本模式编写的：

+   **假设**：这提供了一个初始上下文

+   **当**：这定义了发生的事件

+   **然后**：这确保了一个结果

在 Jasmine 中，这转化为一种非常富有表现力的语言，允许以反映实际业务价值的方式编写测试。前面的验收标准写成 Jasmine 测试单元将如下所示：

```js
describe("Player", function() {
  describe("when song has been paused", function() {
    it("should indicate that the song is paused", function() {

    });
  });
});
```

你可以看到标准很好地转化为了 Jasmine 语法。在下一章中，我们将详细介绍这些函数的工作原理。

使用 Jasmine，与其他 BDD 框架一样，每个验收标准直接转化为一个测试单元。因此，每个测试单元通常被称为**规范**。在本书的过程中，我们将使用这个术语。

# 下载 Jasmine

开始使用 Jasmine 实际上非常简单。

打开 Jasmine 网站[`jasmine.github.io/2.1/introduction.html#section-Downloads`](http://jasmine.github.io/2.1/introduction.html#section-Downloads)，并下载**独立版本**（本书将使用 2.1.3 版本）。

在 Jasmine 网站上，您可能会注意到它实际上是一个执行其中包含的规范的实时页面。这是由于 Jasmine 框架的简单性所实现的，使其能够在最不同的环境中执行。

下载了分发并解压缩后，您可以在浏览器中打开`SpecRunner.html`文件。它将显示一个示例测试套件的结果（包括我们之前向您展示的验收标准）：

![下载 Jasmine](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/jsm-js-test-2e/img/B04138_01_01.jpg)

这显示了在浏览器上打开的 SpecRunner.html 文件

这个`SpecRunner.html`文件是一个 Jasmine 浏览器规范运行器。这是一个简单的 HTML 文件，引用了 Jasmine 代码、源文件和测试文件。出于约定目的，我们将简称这个文件为**runner**。

你可以通过在文本编辑器中打开它来看到它有多简单。这是一个引用了 Jasmine 源代码的小型 HTML 文件：

```js
<script src="lib/jasmine-2.1.3/jasmine.js"></script>
<script src="lib/jasmine-2.1.3/jasmine-html.js"></script>
<script src="lib/jasmine-2.1.3/boot.js"></script>
```

runner 引用了源文件：

```js
<script type="text/javascript" src="src/Player.js"></script>
<script type="text/javascript" src="src/Song.js"></script>
```

runner 引用了一个特殊的`SpecHelper.js`文件，其中包含在规范之间共享的代码：

```js
<script type="text/javascript" src="spec/SpecHelper.js"></script>
```

runner 还引用了规范文件：

```js
<script type="text/javascript" src="spec/PlayerSpec.js"></script>
```

### 提示

**下载示例代码**

您可以从[`www.packtpub.com`](http://www.packtpub.com)的帐户中下载您购买的所有 Packt 图书的示例代码文件。如果您在其他地方购买了这本书，您可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册，以便直接通过电子邮件接收文件。

Jasmine 框架设置在`lib/jasmine-2.1.3/boot.js`文件中，虽然它是一个庞大的文件，但它的大部分内容都是关于设置实际发生的文档。建议您在文本编辑器中打开它并研究其内容。

尽管目前我们是在浏览器中运行规范，在第八章*构建自动化*中，我们将使相同的规范和代码在**无头浏览器**（如 PhantomJS）上运行，并将结果写入控制台。

无头浏览器是一个没有图形用户界面的浏览器环境。它可以是一个实际的浏览器环境，比如使用 WebKit 渲染引擎的 PhantomJS，也可以是一个模拟的浏览器环境，比如 Envjs。

虽然本书未涉及，但 Jasmine 也可以用于测试为诸如 Node.js 等环境编写的服务器端 JavaScript 代码。

这种 Jasmine 的灵活性令人惊叹，因为你可以使用同样的工具来测试各种类型的 JavaScript 代码。

# 总结

在本章中，你看到了测试 JavaScript 应用程序的动机之一。我向你展示了 JavaScript 语言的一些常见陷阱，以及 BDD 和 Jasmine 如何帮助你编写更好的测试。

你也看到了使用 Jasmine 进行下载和入门是多么简单。

在下一章中，你将学习如何以 BDD 的方式思考并编写你的第一个规范。


# 第二章：你的第一个规范

本章介绍了基础知识，我们将指导您如何编写您的第一个规范，以测试优先的术语进行开发，并向您展示所有可用的全局 Jasmine 函数。在本章结束时，您应该知道 Jasmine 的工作原理，并准备好自己进行第一次测试。

# 投资跟踪应用程序

为了让您开始，我们需要一个示例场景：考虑您正在开发一个用于跟踪股票市场投资的应用程序。

以下的表单截图说明了用户可能如何在这个应用程序上创建一个新的投资：

![投资跟踪应用程序](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/jsm-js-test-2e/img/B04138_02_01.jpg)

这是一个添加投资的表单

这个表单将允许输入定义投资的三个值：

+   首先，我们将输入**符号**，表示用户正在投资的公司（股票）

+   然后，我们将输入用户购买（或投资）了多少**股票**

+   最后，我们将输入用户为每股支付的金额（**股价**）

如果您不熟悉股票市场的运作方式，请想象您在购物杂货。要购买商品，您必须指定您要购买什么，您要购买多少件商品，以及您将支付多少。这些概念可以转化为投资：

+   股票由符号定义，例如`PETO`，可以理解为一种杂货类型

+   股票数量是您购买的商品数量

+   股价是每件商品的单价

一旦用户添加了一项投资，它必须与他们的其他投资一起列出，如下面的截图所示：

![投资跟踪应用程序](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/jsm-js-test-2e/img/B04138_02_02.jpg)

这是一个表单和投资列表

这个想法是展示他们的投资进展如何。由于股票价格随时间波动，用户支付的价格与当前价格之间的差异表明这是一个好（盈利）还是一个坏（亏损）的投资。

在前面的截图中，我们可以看到用户有两项投资：

+   其中一项是`AOUE`股票，获利`101.80%`

+   另一项是`PETO`股票，亏损`-42.34%`

这是一个非常简单的应用程序，随着我们对其开发的进行，我们将更深入地了解其功能。

# Jasmine 基础知识和 BDD 思维

根据之前介绍的应用程序，我们可以开始编写定义投资的验收标准：

+   给定一个投资，它应该是一种股票

+   给定一个投资，它应该有投资的股票数量

+   给定一个投资，它应该有支付的股价

+   给定一个投资，它应该有成本

使用上一章下载的独立分发版，我们需要做的第一件事是创建一个新的规范文件。这个文件可以在任何地方创建，但遵循一个约定是个好主意，而 Jasmine 已经有一个很好的约定：规范应该在`/spec`文件夹中。创建一个`InvestmentSpec.js`文件，并添加以下行：

```js
describe("Investment", function() {

});
```

`describe`函数是一个全局的 Jasmine 函数，用于定义测试上下文。当作为规范中的第一个调用时，它会创建一个新的测试套件（一组测试用例）。它接受两个参数，如下所示：

+   测试套件的名称——在本例中为“投资”

+   一个包含所有规范的`function`

然后，要将第一个验收标准（给定一个投资，它应该是一种股票）翻译成 Jasmine 规范（或测试用例），我们将使用另一个全局的 Jasmine 函数，称为`it`：

```js
describe("Investment", function() {
  **it("should be of a stock", function() {**

  **});**
});
```

它还接受两个参数，如下所示：

+   规范的标题——在本例中为`应该是股票`

+   一个包含规范代码的`function`

要运行此规范，请将其添加到运行器中，如下所示：

```js
<!-- include spec files here... -->
**<script type="text/javascript" src="spec/InvestmentSpec.js"></script>**

```

通过在浏览器上打开运行器来执行规范。可以看到以下输出：

![Jasmine 基础知识和 BDD 思维](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/jsm-js-test-2e/img/B04138_02_03.jpg)

这是浏览器上第一个规范的通过结果

一个空的规范通过可能听起来很奇怪，但在 Jasmine 中，与其他测试框架一样，需要失败的断言才能使规范失败。

**断言**（或期望）是两个值之间的比较，必须产生布尔值。只有在比较的结果为真时，断言才被认为是成功的。

在 Jasmine 中，使用全局 Jasmine 函数`expect`编写断言，以及指示要对值进行何种比较的**匹配器**。

关于当前的规范（预期投资是股票），在 Jasmine 中，这对应以下代码：

```js
describe("Investment", function() {
  it("should be of a stock", function() {
    **expect(investment.stock).toBe(stock);**
  });
});
```

将前面高亮的代码添加到`InvestmentSpec.js`文件中。`expect`函数只接受一个参数，它定义了**实际值**，或者换句话说，要进行测试的内容——`investment.stock`，并期望链接调用匹配器函数，这种情况下是`toBe`。这定义了**期望值**，`stock`，以及要执行的比较方法（要相同）。

在幕后，Jasmine 进行比较，检查实际值（`investment.stock`）和期望值（`stock`）是否相同，如果它们不同，测试就会失败。

有了写好的断言，先前通过的规范现在已经失败，如下截图所示：

![Jasmine 基础和 BDD 思维](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/jsm-js-test-2e/img/B04138_02_04.jpg)

这显示了第一个规范的失败结果

这个规范失败了，因为错误消息表明`investment 未定义`。

这里的想法是只做错误提示我们要做的事情，所以尽管您可能会有写其他内容的冲动，但现在让我们在`InvestmentSpec.js`文件中创建一个`investment`变量，并使用`Investment`实例，如下所示：

```js
describe("Investment", function() {
  it("should be of a stock", function() {
    **var investment = new Investment();**
    expect(investment.stock).toBe(stock);
  });
});
```

不要担心`Investment()`函数尚不存在；规范即将在下一次运行时要求它，如下所示：

![Jasmine 基础和 BDD 思维](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/jsm-js-test-2e/img/B04138_02_05.jpg)

这里的规范要求一个 Investment 类

您可以看到错误已经改为`Investment 未定义`。现在要求`Investment`函数。因此，在`src`文件夹中创建一个新的`Investment.js`文件，并将其添加到 runner 中，如下所示：

```js
<!-- include source files here... -->
<script type="text/javascript" src="src/Investment.js"></script>
```

要定义`Investment`，请在`src`文件夹中的`Investment.js`文件中编写以下构造函数：

```js
function Investment () {};
```

这会改变错误。现在它抱怨缺少`stock`变量，如下截图所示：

![Jasmine 基础和 BDD 思维](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/jsm-js-test-2e/img/B04138_02_06.jpg)

这显示了一个缺少 stock 的错误

再一次，我们将代码输入到`InvestmentSpec.js`文件中，如下所示：

```js
describe("Investment", function() {
  it("should be of a stock", function() {
    **var stock = new Stock();**
    var investment = new Investment();
    expect(investment.stock).toBe(stock);
  });
});
```

错误再次改变；这次是关于缺少`Stock`函数：

![Jasmine 基础和 BDD 思维](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/jsm-js-test-2e/img/B04138_02_07.jpg)

这里的规范要求一个 Stock 类

在`src`文件夹中创建一个新文件，命名为`Stock.js`，并将其添加到 runner 中。由于`Stock`函数将成为`Investment`的依赖项，所以我们应该在`Investment.js`之前添加它：

```js
<!-- include source files here... -->
**<script type="text/javascript" src="src/Stock.js"></script>**
<script type="text/javascript" src="src/Investment.js"></script>
```

将`Stock`构造函数写入`Stock.js`文件：

```js
function Stock () {};
```

最后，错误是关于期望值，如下截图所示：

![Jasmine 基础和 BDD 思维](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/jsm-js-test-2e/img/B04138_02_08.jpg)

期望是未定义的 Stock

要修复这个问题并完成这个练习，打开`src`文件夹中的`Investment.js`文件，并添加对`stock`参数的引用：

```js
function Investment (stock) {
  **this.stock = stock;**
};
```

在规范文件中，将`stock`作为参数传递给`Investment`函数：

```js
describe("Investment", function() {
  it("should be of a stock", function() {
    var stock = new Stock();
    var investment = new Investment(**stock**);
    expect(investment.stock).toBe(stock);
  });
});
```

最后，您将有一个通过的规范：

![Jasmine 基础和 BDD 思维](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/jsm-js-test-2e/img/B04138_02_09.jpg)

这显示了一个通过的 Investment 规范

这个练习是精心进行的，以展示开发人员在进行测试驱动开发时如何满足规范的要求。

### 提示

编写代码的动力必须来自一个失败的规范。除非其目的是修复失败的规范，否则不得编写代码。

# 设置和拆卸

还有三个要实现的验收标准。列表中的下一个是：

“给定一个投资，它应该有投资的股份数量。”

写它应该和之前的规范一样简单。在`spec`文件夹内的`InvestmentSpec.js`文件中，您可以将这个新标准翻译成一个名为`should have the invested shares' quantity`的新规范，如下所示：

```js
describe("Investment", function() {
  it("should be of a stock", function() {
    var stock = new Stock();
    var investment = new Investment(**{**
      **stock: stock,**
      **shares: 100**
    **}**);
    expect(investment.stock).toBe(stock);
  });

  **it("should have the invested shares' quantity", function() {**
 **var stock = new Stock();**
 **var investment = new Investment({**
 **stock: stock,**
 **shares: 100**
 **});**
 **expect(investment.shares).toEqual(100);**
 **});**
});
```

您可以看到，除了编写了新的规范之外，我们还改变了对`Investment`构造函数的调用，以支持新的`shares`参数。

为此，我们在构造函数中使用了一个对象作为单个参数，以模拟命名参数，这是 JavaScript 本身没有的功能。

在`Investment`函数中实现这一点非常简单 - 在函数声明中不再有多个参数，而只有一个参数，预期是一个对象。然后，函数从这个对象中探测每个预期的参数，进行适当的赋值，如下所示：

```js
function Investment (**params**) {
  **this.stock = params.stock;**
};
```

现在代码已经重构。我们可以运行测试来看只有新的规范失败，如下所示：

![设置和拆卸](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/jsm-js-test-2e/img/B04138_02_10.jpg)

这显示了股份规范的失败

为了解决这个问题，将`Investment`构造函数更改为对`shares`属性进行赋值，如下所示：

```js
function Investment (params) {
  this.stock = params.stock;
  **this.shares = params.shares;**
};
```

最后，您屏幕上的一切都是绿色的：

![设置和拆卸](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/jsm-js-test-2e/img/B04138_02_11.jpg)

这显示了通过的股份规范

但是，正如您所看到的，实例化`Stock`和`Investment`的以下代码在两个规范中都是重复的：

```js
var stock = new Stock();
var investment = new Investment({
  stock: stock,
  shares: 100
});
```

为了消除这种重复，Jasmine 提供了另一个全局函数叫做`beforeEach`，顾名思义，它在每个规范之前执行一次。因此，对于这两个规范，它将运行两次 - 每个规范之前运行一次。

通过使用`beforeEach`函数提取设置代码来重构先前的规范：

```js
describe("Investment", function() {
  **var stock, investment;**

  **beforeEach(function() {**
    **stock = new Stock();**
    **investment = new Investment({**
      **stock: stock,**
      **shares: 100**
    **});**
  **});**

  it("should be of a stock", function() {
    expect(investment.stock).toBe(stock);
  });

  it("should have the invested shares quantity", function() {
    expect(investment.shares).toEqual(100);
  });
});
```

这看起来干净多了；我们不仅消除了代码重复，还简化了规范。它们变得更容易阅读和维护，因为它们现在的唯一责任是满足期望。

还有一个**拆卸**函数（`afterEach`），它在每个规范之后设置要执行的代码。在每个规范之后需要清理时，它非常有用。我们将在第六章中看到其应用的示例，*光速单元测试*。

要完成`Investment`的规范，将剩下的两个规范添加到`spec`文件夹中的`InvestmentSpec.js`文件中：

```js
describe("Investment", function() {
  var stock;
  var investment;

  beforeEach(function() {
    stock = new Stock();
    investment = new Investment({
      stock: stock,
      shares: 100,
      **sharePrice: 20**
    });
  });

  //... other specs

  **it("should have the share paid price", function() {**
    **expect(investment.sharePrice).toEqual(20);**
  **});**

  **it("should have a cost", function() {**
    **expect(investment.cost).toEqual(2000);**
  **});**
});
```

运行规范，看它们失败，如下截图所示：

![设置和拆卸](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/jsm-js-test-2e/img/B04138_02_12.jpg)

这显示了成本和价格规范的失败

将以下代码添加到`src`文件夹中的`Investment.js`文件中以修复它们：

```js
function Investment (params) {
  this.stock = params.stock;
  this.shares = params.shares;
  **this.sharePrice = params.sharePrice;**
  **this.cost = this.shares * this.sharePrice;**
};
```

最后一次运行规范，看它们通过：

![设置和拆卸](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/jsm-js-test-2e/img/B04138_02_13.jpg)

这显示了所有四个投资规范都通过了

### 提示

在编写代码来修复之前，始终要看到规范失败；否则，您怎么知道您真的需要修复它呢？把这看作是测试测试的一种方式。

# 嵌套描述

**嵌套描述**在您想要描述规范之间相似行为时非常有用。假设我们想要以下两个新的验收标准：

+   给定一个投资，当其股票股价升值时，它应该有一个正的**投资回报率**（**ROI**）

+   给定一个投资，当其股票股价升值时，它应该是一个好的投资

当投资的股票股价升值时，这两个标准都具有相同的行为。

要将其翻译成 Jasmine，您可以在`InvestmentSpec.js`文件中现有的`describe`函数内嵌套一个调用（我为演示目的删除了其余代码；它仍然存在）：

```js
describe("Investment", function()
  **describe("when its stock share price valorizes", function() {**

  **});**
});
```

它应该像外部规范一样工作，因此您可以添加规范（`it`）并使用设置和拆卸函数（`beforeEach`，`afterEach`）。

## 设置和拆卸

在使用设置和拆卸函数时，Jasmine 也会尊重外部设置和拆卸函数，以便按预期运行。对于每个规范（`it`），执行以下操作：

+   Jasmine 按照从外到内的顺序运行所有设置函数（`beforeEach`）

+   Jasmine 运行规范代码（`it`）

+   Jasmine 按照从内到外的顺序运行所有拆卸函数（`afterEach`）

因此，我们可以向这个新的`describe`函数添加一个设置函数，以更改股票的股价，使其大于投资的股价：

```js
describe("Investment", function() {
  var stock;
  var investment;

  beforeEach(function() {
    stock = new Stock();
    investment = new Investment({
      stock: stock,
      shares: 100,
      sharePrice: 20
    });
  });

  describe("when its stock share price valorizes", function() {
    **beforeEach(function() {**
      **stock.sharePrice = 40;**
    **});**
  });
});
```

## 使用共享行为编写规范

现在我们已经实现了共享的行为，我们可以开始编写之前描述的验收标准。每个都是，就像以前一样，调用全局 Jasmine 函数`it`：

```js
describe("Investment", function() {
  describe("when its stock share price valorizes", function() {
    beforeEach(function() {
      stock.sharePrice = 40;
    });

    **it("should have a positive return of investment", function() {**
      **expect(investment.roi()).toEqual(1);**
    **});**

    **it("should be a good investment", function() {**
      **expect(investment.isGood()).toEqual(true);**
    **});**
  });
});
```

在`Investment.js`文件中添加缺失的函数之后：

```js
Investment.prototype.**roi** = function() {
  return (this.stock.sharePrice - this.sharePrice) / this.sharePrice;
};

Investment.prototype.**isGood** = function() {
  return this.roi() > 0;
};
```

您可以运行规范并查看它们是否通过：

![使用共享行为编写规范](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/jsm-js-test-2e/img/B04138_02_14.jpg)

这显示了嵌套的描述规范通过

## 理解匹配器

到目前为止，您已经看到了匹配器的许多用法示例，可能已经感受到它们的工作原理。

您已经看到了如何使用`toBe`和`toEqual`匹配器。这是 Jasmine 中提供的两个基本内置匹配器，但我们可以编写自己的匹配器来扩展 Jasmine。

因此，要真正理解 Jasmine 匹配器的工作原理，我们需要自己创建一个。

### 自定义匹配器

考虑一下前一节中的期望：

```js
expect(investment.isGood()).toEqual(true);
```

虽然它能够工作，但表达力不是很强。想象一下，如果我们可以改写成：

```js
expect(investment).toBeAGoodInvestment();
```

这与验收标准之间建立了更好的关系。

因此，在这里，“should be a good investment”变成了“expect investment to be a good investment”。

实现它非常简单。您可以通过调用`jasmine.addMatchers`函数来实现这一点，最好是在设置步骤（`beforeEach`）中。

尽管您可以将这个新的匹配器定义放在`InvestmentSpec.js`文件中，但 Jasmine 已经有一个默认的位置来添加自定义匹配器，即`SpecHelper.js`文件，位于`spec`文件夹内。如果您使用独立发行版，它已经带有一个示例自定义匹配器；删除它，让我们从头开始。

`addMatchers`函数接受一个参数，即一个对象，其中每个属性对应一个新的匹配器。因此，要添加以下新的匹配器，请更改`SpecHelper.js`文件的内容如下：

```js
beforeEach(function() {
  jasmine.addMatchers({
    **toBeAGoodInvestment: function() {}**
  });
});
```

在这里定义的函数不是匹配器本身，而是一个工厂函数，用于构建匹配器。它的目的是一旦调用就返回一个包含比较函数的对象，如下所示：

```js
jasmine.addMatchers({
  toBeAGoodInvestment: function () {
    **return** **{**
 **compare: function (actual, expected) {**
 **// matcher definition**
 **}**
    };
  }
});
```

`compare`函数将包含实际的匹配器实现，并且可以通过其签名观察到，它接收要比较的两个值（`actual`和`expected`值）。

对于给定的示例，`investment`对象将在`actual`参数中可用。

然后，Jasmine 期望`compare`函数的结果是一个带有`pass`属性的对象，该属性具有布尔值`true`，以指示期望通过，如果期望失败则为`false`。

让我们来看看`toBeAGoodInvestment`匹配器的以下有效实现：

```js
toBeAGoodInvestment: function () {
  return {
    compare: function (actual, expected) {
      **var result = {};**
 **result.pass = actual.isGood();**
 **return result;**
    }
  };
}
```

到目前为止，这个匹配器已经准备好被规范使用：

```js
it("should be a good investment", function() {
  **expect(investment).toBeAGoodInvestment();**
});
```

更改后，规范仍应通过。但是如果规范失败会发生什么？Jasmine 报告的错误消息是什么？

我们可以通过故意破坏`Investment.js`文件中`src`文件夹中的`investment.isGood`实现，使其始终返回`false`来看到它：

```js
Investment.prototype.isGood = function() {
  **return false;**
};
```

再次运行规范时，Jasmine 会生成一个错误消息，指出`Expected { stock: { sharePrice: 40 }, shares: 100, sharePrice: 20, cost: 2000 } to be a good investment`，如下面的截图所示：

![自定义匹配器](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/jsm-js-test-2e/img/B04138_02_15.jpg)

这是自定义匹配器的消息

Jasmine 在生成此错误消息方面做得很好，但它也允许通过匹配器结果对象的`result.message`属性进行自定义。Jasmine 期望此属性是一个带有以下错误消息的字符串：

```js
toBeAGoodInvestment: function () {
  return {
    compare: function (actual, expected) {
      var result = {};
      result.pass = actual.isGood();
      **result.message = 'Expected investment to be a good investment';**
      return result;
    }
  };
}
```

再次运行规范，错误消息应该改变：

![自定义匹配器](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/jsm-js-test-2e/img/B04138_02_16.jpg)

这是自定义匹配器的自定义消息

现在，让我们考虑另一个验收标准：

“给定一个投资，当它的股票价格贬值时，它应该是一个坏的投资。”

虽然可以创建一个新的自定义匹配器（`toBeABadInvestment`），Jasmine 允许在调用匹配器之前通过在匹配器调用之前链接`not`来否定任何匹配器。因此，我们可以说“一个坏的投资”是“不是一个好的投资”。

```js
expect(investment).**not**.toBeAGoodInvestment();
```

在`InvestmentSpec.js`文件的`spec`文件夹中添加新的和嵌套的`describe`和`spec`，以实现这个新的验收标准：

```js
describe("when its stock share price devalorizes", function() {
  beforeEach(function() {
    stock.sharePrice = 0;
  });

  it("should have a negative return of investment", function() {
    expect(investment.roi()).toEqual(-1);
  });

  it("should be a bad investment", function() {
    expect(investment).not.toBeAGoodInvestment();
  });
});
```

但是有一个问题！让我们来破解`Investment.js`文件中的`investment`实现，使其始终是一个好的投资，如下所示：

```js
Investment.prototype.isGood = function() {
  **return true;**
};
```

再次运行规范，您会发现这个新规范失败了，但错误消息`Expected investment to be a good investment`是错误的，如下面的截图所示：

![自定义匹配器](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/jsm-js-test-2e/img/B04138_02_17.jpg)

这是自定义匹配器的错误的自定义否定消息

这是硬编码在匹配器内部的消息。要修复这个问题，您需要使消息动态化。

Jasmine 只在匹配器失败时显示消息，因此使此消息动态化的正确方法是考虑在给定比较无效时应该显示什么消息：

```js
compare: function (actual, expected) {
  var result = {};
  result.pass = actual.isGood();

 **if (actual.isGood()) {**
 **result.message = 'Expected investment to be a bad investment';**
 **} else {**
 **result.message = 'Expected investment to be a good investment';**
 **}**

  return result;
}
```

这修复了消息，如下面的截图所示：

![自定义匹配器](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/jsm-js-test-2e/img/B04138_02_18.jpg)

这显示了自定义匹配器的自定义动态消息

现在这个匹配器可以在任何地方使用。

在继续本章之前，将`isGood`方法再次更改为正确的实现：

```js
Investment.prototype.isGood = function() {
  return this.roi() > 0;
};
```

这个例子缺少的是展示如何将预期值传递给这样的匹配器的方法：

```js
expect(investment.cost).toBe(2000)
```

事实证明，匹配器可以接收任意数量的预期值作为参数。因此，例如，前面的匹配器可以在`SpecHelper.js`文件中的`spec`文件夹中实现如下：

```js
beforeEach(function() {
  jasmine.addMatchers({
    toBe: function () {
      return {
        compare: function (actual, **expected**) {
          return actual === **expected**;
        }
      };
    }
  });
});
```

通过实现任何匹配器，首先检查是否已经有一个可用的匹配器可以实现你想要的功能。

有关更多信息，请查看 Jasmine 网站上的官方文档[`jasmine.github.io/2.1/custom_matcher.html`](http://jasmine.github.io/2.1/custom_matcher.html)。

### 内置匹配器

Jasmine 带有一堆默认匹配器，涵盖了 JavaScript 语言中值检查的基础知识。了解它们的工作原理以及在何处正确使用它们是了解 JavaScript 处理类型的过程。

#### toEqual 内置匹配器

`toEqual`匹配器可能是最常用的匹配器，每当您想要检查两个值之间的相等性时，都应该使用它。

它适用于所有原始值（数字、字符串和布尔值）以及任何对象（包括数组），如下面的代码所示：

```js
describe("toEqual", function() {
  it("should pass equal numbers", function() {
    expect(1).toEqual(1);
  });

  it("should pass equal strings", function() {
    expect("testing").toEqual("testing");
  });

  it("should pass equal booleans", function() {
    expect(true).toEqual(true);
  });

  it("should pass equal objects", function() {
    expect({a: "testing"}).toEqual({a: "testing"});
  });

  it("should pass equal arrays", function() {
    expect([1, 2, 3]).toEqual([1, 2, 3]);
  });
});
```

#### toBe 内置匹配器

`toBe`匹配器的行为与`toEqual`匹配器非常相似；实际上，在比较原始值时，它给出相同的结果，但相似之处止步于此。

虽然`toEqual`匹配器有一个复杂的实现（您应该查看 Jasmine 源代码），它检查对象的所有属性和数组的所有元素是否相同，但在这里它只是简单使用了**严格相等运算符**（`===`）。

如果您不熟悉严格相等运算符，它与**equals 运算符**（`==`）的主要区别在于，如果比较的值不是相同类型，后者会执行类型强制转换。

### 提示

严格相等运算符始终将不同类型的值之间的比较视为 false。

以下是此匹配器（以及严格相等运算符）的工作示例：

```js
describe("toBe", function() {
  it("should pass equal numbers", function() {
    expect(1).toBe(1);
  });

  it("should pass equal strings", function() {
    expect("testing").toBe("testing");
  });

  it("should pass equal booleans", function() {
    expect(true).toBe(true);
  });

  it("should pass same objects", function() {
    var object = {a: "testing"};
    expect(object).toBe(object);
  });

  it("should pass same arrays", function() {
    var array = [1, 2, 3];
    expect(array).toBe(array);
  });

  it("should not pass equal objects", function() {
    expect({a: "testing"}).not.toBe({a: "testing"});
  });

  it("should not pass equal arrays", function() {
    expect([1, 2, 3]).not.toBe([1, 2, 3]);
  });
});
```

建议在大多数情况下使用`toEqual`运算符，并且只有在要检查两个变量是否引用相同对象时才使用`toBe`匹配器。

#### toBeTruthy 和 toBeFalsy 匹配器

除了其原始布尔类型之外，JavaScript 语言中的所有其他内容也都具有固有的布尔值，通常被称为“truthy”或“falsy”。

幸运的是，在 JavaScript 中，只有少数值被识别为 falsy，如`toBeFalsy`匹配器的以下示例所示：

```js
describe("toBeFalsy", function () {
  it("should pass undefined", function() {
    expect(undefined).toBeFalsy();
  });

  it("should pass null", function() {
    expect(null).toBeFalsy();
  });

  it("should pass NaN", function() {
    expect(NaN).toBeFalsy();
  });

  it("should pass the false boolean value", function() {
    expect(false).toBeFalsy();
  });

  it("should pass the number 0", function() {
    expect(0).toBeFalsy();
  });

  it("should pass an empty string", function() {
    expect("").toBeFalsy();
  });
});
```

其他所有内容都被视为 truthy，如`toBeTruthy`匹配器的以下示例所示：

```js
describe("toBeTruthy", function() {
  it("should pass the true boolean value", function() {
    expect(true).toBeTruthy();
  });

  it("should pass any number different than 0", function() {
    expect(1).toBeTruthy();
  });
  it("should pass any non empty string", function() {
    expect("a").toBeTruthy();
  });

  it("should pass any object (including an array)", function() {
    expect([]).toBeTruthy();
    expect({}).toBeTruthy();
  });
});
```

但是，如果要检查某个东西是否等于实际的布尔值，可能更好的主意是使用`toEqual`匹配器。

#### toBeUndefined、toBeNull 和 toBeNaN 内置匹配器

这些匹配器非常直观，应该用于检查`undefined`、`null`和`NaN`的值：

```js
describe("toBeNull", function() {
  it("should pass null", function() {
    expect(null).toBeNull();
  });
});

describe("toBeUndefined", function() {
  it("should pass undefined", function() {
    expect(undefined).toBeUndefined();
  });
});

describe("toBeNaN", function() {
  it("should pass NaN", function() {
    expect(NaN).toBeNaN();
  });
});
```

`toBeNull`和`toBeUndefined`都可以分别写为`toBe(null)`和`toBe(undefined)`，但`toBeNaN`不是这种情况。

在 JavaScript 中，`NaN`值不等于任何值，甚至不等于`NaN`。因此，尝试将其与自身进行比较总是`false`，如下面的代码所示：

```js
NaN === NaN // false
```

作为良好的实践，尽量在可能的情况下使用这些匹配器，而不是它们的`toBe`对应物。

#### toBeDefined 内置匹配器

如果要检查变量是否已定义，而不关心其值，可以使用这个匹配器。

```js
describe("toBeDefined", function() {
  it("should pass any value other than undefined", function() {
    expect(null).toBeDefined();
  });
});
```

除了`undefined`之外的任何内容都会通过这个匹配器，甚至是`null`。

#### toContain 内置匹配器

有时，希望检查数组是否包含元素，或者一个字符串是否可以在另一个字符串中找到。对于这些用例，可以使用`toContain`匹配器，如下所示：

```js
describe("toContain", function() {
  it("should pass if a string contains another string", function()  {
    expect("My big string").toContain("big");
  });

  it("should pass if an array contains an element", function() {
    expect([1, 2, 3]).toContain(2);
  });
});
```

#### toMatch 内置匹配器

尽管`toContain`和`toEqual`匹配器可以在大多数字符串比较中使用，但有时唯一的断言字符串值是否正确的方法是通过正则表达式。对于这些情况，可以使用`toMatch`匹配器以及正则表达式，如下所示：

```js
describe("toMatch", function() {
  it("should pass a matching string", function() {
    expect("My big matched string").toMatch(/My(.+)string/);
  });
});
```

匹配器通过测试实际值（`"My big matched string"`）与预期正则表达式（`/My(.+)string/`）进行比较。

#### toBeLessThan 和 toBeGreaterThan 内置匹配器

`toBeLessThan`和`toBeGreaterThan`匹配器很简单，用于执行数字比较，最好通过以下示例进行描述：

```js
  describe("toBeLessThan", function() {
    it("should pass when the actual is less than expected", function() {
      expect(1).toBeLessThan(2);
    });
  });

  describe("toBeGreaterThan", function() {
    it("should pass when the actual is greater than expected", function() {
      expect(2).toBeGreaterThan(1);
    });
  });
```

#### toBeCloseTo 内置匹配器

这是一个特殊的匹配器，用于比较具有一组定义精度的浮点数，最好通过以下示例进行解释：

```js
describe("toBeCloseTo", function() {
    it("should pass when the actual is closer with a given precision", function() {
      expect(3.1415).toBeCloseTo(2.8, 0);
      expect(3.1415).not.toBeCloseTo(2.8, 1);
    });
  });
```

第一个参数是要比较的数字，第二个是小数位数的精度。

#### toThrow 内置匹配器

异常是语言在出现问题时展示的方式。

因此，例如，在编写 API 时，您可能决定在参数传递不正确时抛出异常。那么，如何测试这段代码呢？

Jasmine 有内置的`toThrow`匹配器，可用于验证是否抛出了异常。

它的工作方式与其他匹配器有些不同。由于匹配器必须运行一段代码并检查是否抛出异常，因此匹配器的**actual**值必须是一个函数。

以下是它的工作示例：

```js
describe("toThrow", function() {
  it("should pass when the exception is thrown", function() {
    expect(function () {
      throw "Some exception";
    }).toThrow("Some exception");
  });
});
```

当运行测试时，将执行匿名函数，如果抛出`Some exception`异常，则测试通过。

# 总结

在本章中，您学会了如何以 BDD 方式思考并从规范中驱动代码。您还熟悉了基本的 Jasmine 全局函数（`describe`、`it`、`beforeEach`和`afterEach`），并且对在 Jasmine 中创建规范有了很好的理解。

您已经熟悉了 Jasmine 匹配器，并知道它们在描述规范意图方面有多么强大。您甚至学会了创建自己的匹配器。

到目前为止，您应该已经熟悉了创建新规范并推动新应用程序的开发。

在下一章中，我们将看看如何利用本章学到的概念来开始测试 Web 应用程序，这些应用程序最常见的是 jQuery 和 HTML 表单。


# 第三章：测试前端代码

测试 JavaScript 浏览器代码一直被认为是困难的，尽管在处理跨浏览器测试时会遇到许多复杂问题，但最常见的问题不在于测试过程，而是应用程序代码本身不可测试。

由于浏览器文档中的每个元素都可以全局访问，因此很容易编写一个整体的 JavaScript 代码块，它处理整个页面。这会导致一些问题，其中最大的问题是很难进行测试。

在本章中，我们将学习如何编写可维护和可测试的浏览器代码的最佳实践。

为了实现用户界面，我们将使用 jQuery，这是一个众所周知的 JavaScript 库，它通过一个干净简单的 API 抽象了浏览器的 DOM，可以在不同的浏览器上运行。

为了使规范的编写更容易，我们将使用 Jasmine jQuery，这是一个 Jasmine 扩展，它添加了新的匹配器来对 jQuery 对象执行断言。要安装它及其 jQuery 依赖项，请下载以下文件：

+   [`raw.githubusercontent.com/velesin/jasmine-jquery/2.1.0/lib/jasmine-jquery.js`](https://raw.githubusercontent.com/velesin/jasmine-jquery/2.1.0/lib/jasmine-jquery.js)

+   [`raw.githubusercontent.com/velesin/jasmine-jquery/2.1.0/vendor/jquery/jquery.js`](https://raw.githubusercontent.com/velesin/jasmine-jquery/2.1.0/vendor/jquery/jquery.js)

将这些文件保存为`jasmine-jquery.js`和`jquery.js`，分别放在`lib`文件夹中，并将它们添加到`SpecRunner.html`中，如下所示：

```js
<script src="lib/jquery.js"></script>
<script src="lib/jasmine-jquery.js"></script>
```

到目前为止，我们已经创建了单独的抽象来处理投资及其相关的股票。现在，是时候开发这个应用程序的用户界面并取得良好的结果了，这完全取决于组织和良好的实践。

我们在服务器端代码上应用的软件工程原则在编写前端 JavaScript 代码时也不容忽视。考虑组件和关注点的适当分离仍然很重要。

# 以组件（视图）的方式思考

我们已经讨论了困扰大部分网络的单片 JavaScript 代码库，这些代码库是不可能进行测试的。不陷入这个陷阱的最好方法是通过编写应用程序驱动的测试。

考虑一下我们的投资跟踪应用程序的模拟界面：

![以组件（视图）的方式思考](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/jsm-js-test-2e/img/B04138_03_01.jpg)

这显示了投资跟踪应用程序的模拟界面

我们将如何实施它？很容易看出，这个应用程序有两个不同的责任：

+   一个责任是添加一个投资

+   另一个责任是列出添加的投资

因此，我们可以开始将此界面分解为两个不同的组件。为了更好地描述它们，我们将借鉴**MVC 框架**（如`Backbone.js`）的概念，并称它们为**视图**。

因此，在界面的顶层，有两个基本组件：

+   `NewInvestmentView`：这将负责创建新的投资

+   `InvestmentListView`：这将是所有添加的投资的列表

# 模块模式

因此，我们了解了如何分解代码，但是如何组织它呢？到目前为止，我们为每个新功能创建了一个文件。这是一个很好的做法，我们将看到如何改进它。

让我们从思考我们的`NewInvestmentView`组件开始。我们可以按照我们到目前为止使用的模式创建一个新文件`NewInvestmentView.js`，并将其放在`src`文件夹中，如下所示：

```js
(function ($, Investment, Stock) {
  function NewInvestmentView (params) {

  }

  this.NewInvestmentView = NewInvestmentView;
})(jQuery, Investment, Stock);
```

您可以看到，这个 JavaScript 文件比到目前为止显示的示例更健壮。我们已经将所有的`NewInvestmentView`代码包装在一个**立即调用的函数表达式**（**IIFE**）中。

它被称为 IIFE，因为它声明一个函数并立即调用它，有效地创建了新的作用域来声明局部变量。

一个好的做法是在 IIFE 中只使用局部变量。如果需要使用全局依赖项，将其作为参数传递。在这个例子中，它已经将三个依赖项传递给`NewInvestmentView`代码：`jQuery`，`Investment`和`Stock`。

您可以在函数声明中看到这一点：

```js
function (**$, Investment, Stock**)
```

并立即调用：

```js
})(**jQuery, Investment, Stock**);
```

这种做法的最大优点是，我们不再需要担心污染全局命名空间，因为我们在 IIFE 中声明的一切都将是局部的。这使得很难干扰全局范围。

如果我们需要使任何东西全局化，我们通过将其附加到全局对象来明确地执行，如下所示：

```js
**this**.NewInvestmentView = NewInvestmentView;
```

另一个优点是明确的依赖声明。通过查看文件的第一行，我们就知道了文件的外部依赖。

尽管这种做法现在并没有太大的优势（因为所有的组件都是全局暴露的），但我们将看到如何从中受益在第八章，*构建自动化*。

这种模式也被称为**模块模式**，我们将在本书的其余部分中使用它（即使有时为了简化目的而省略）。

# 使用 HTML fixtures

继续开发`NewInvestmentView`组件，我们可以编写一些基本的验收标准，如下所示：

+   `NewInvestmentView`应该允许输入股票符号

+   `NewInvestmentView`应该允许输入股票

+   `NewInvestmentView`应该允许输入股价

还有很多，但这是一个很好的开始。

在`spec`文件夹中创建一个名为`NewInvestmentViewSpec.js`的新组件的新规范文件，我们可以开始翻译这些规范，如下所示：

```js
describe("NewInvestmentView", function() {
  it("should allow the input of the stock symbol", function() {
  });

  it("should allow the input of shares", function() {
  });

  it("should allow the input of the share price", function() {
  });
});
```

然而，在我们开始实现这些之前，我们必须首先了解**HTML fixtures**的概念。

测试 fixtures 提供了测试运行的基本状态。它可以是类的实例化，对象的定义，或者一段 HTML。换句话说，为了测试处理表单提交的 JavaScript 代码，我们需要在运行测试时有表单可用。包含表单的 HTML 代码就是 HTML fixture。

处理这个要求的一种方法是在设置函数中手动附加所需的 DOM 元素，如下所示：

```js
beforeEach(function() {
  $('body').append('<form id="my-form"></form>');
});
```

然后，在拆卸期间将其删除，如下所示：

```js
afterEach(function() {
  $('#my-form').remove();
});
```

否则，规范将在文档中附加大量垃圾，并且可能会干扰其他规范的结果。

### 提示

重要的是要知道规范应该是独立的，并且可以以任何特定顺序运行。因此，作为一个规则，完全独立地处理规范。

更好的方法是在文档中有一个容器，我们总是把 HTML fixtures 放在那里，如下所示：

```js
<div id="html-fixtures">
</div>
```

将代码更改为以下内容：

```js
beforeEach(function() {
  **$('#html-fixtures').html('<form id="my-form"></form>');**
});
```

这样，下次规范运行时，它会自动用自己的 fixture 覆盖上一个 fixture。

但是，随着 fixtures 变得更加复杂，这很快就会升级为一个难以理解的混乱：

```js
beforeEach(function() {
  $('#html-fixtures').html('<form id="new-investment"><h1>New  investment</h1><label>Symbol:<input type="text" class="new-investment-stock-symbol" name="stockSymbol"  value=""></label><input type="submit" name="add"  value="Add"></form>');
});
```

如果这个装置可以从外部文件加载，那不是很好吗？这正是 Jasmine jQuery 扩展的**HTML fixture**模块所做的。

我们可以将 HTML 代码放在外部文件中，并通过简单调用`loadFixtures`来加载它到文档中，传递 fixture 文件路径，如下所示：

```js
beforeEach(function() {
  **loadFixtures('MyFixture.html');**
});
```

默认情况下，扩展程序会在`spec/javascripts/fixtures`文件夹中查找文件（对于上一个示例，它将是`spec/javascripts/fixtures/MyFixture.html`），并将其内容加载到容器中，如下所示：

```js
<div id="jasmine-fixtures">
  <form id="new-investment">
    <h1>New investment</h1>
    <label>
      Symbol:
      <input type="text" class="new-investment-stock-symbol" name="stockSymbol" value="">
    </label>
    <input type="submit" name="add" value="Add">
  </form>
</div>
```

我们还可以使用扩展的另一个全局函数来重新创建第一个示例。`setFixtures(html)`函数接受一个参数，其中包含要放置在容器中的内容：

```js
beforeEach(function() {
  **setFixtures('<form id="my-form"></form>');**
});
```

其他可用的函数如下：

+   `appendLoadFixtures(fixtureUrl[, fixtureUrl, …])`：而不是覆盖 fixture 容器的内容，这会将其附加上

+   `readFixtures(fixtureUrl[, fixtureUrl, …])`：这读取一个 fixture 容器的内容，但不是将其附加到文档中，而是返回一个包含其内容的字符串

+   `appendSetFixtures(html)`: 这与`appendLoadFixtures`相同，但使用 HTML 字符串而不是文件

Jasmine jQuery fixture 模块缓存每个文件，因此我们可以多次加载相同的 fixture 而不会对测试套件的速度造成任何惩罚。

它使用 AJAX 加载 fixtures，有时，测试可能希望修改 JavaScript 或 jQuery AJAX 的内部工作方式，就像我们将在第六章中看到的那样，*轻速单元测试*，这可能会破坏 fixture 的加载。解决这个问题的方法是使用`preloadFixtures()`函数将所需的 fixtures 预加载到缓存中。

`preloadFixtures(fixtureUrl[, fixtureUrl, …])`函数在不将其附加到文档中的情况下加载一个或多个文件到缓存中。

然而，使用 HTML 时存在一个问题。Jasmine jQuery 使用 AJAX 加载 HTML fixtures，但由于**同源策略**（**SOP**），现代浏览器在使用`file://`协议打开`SpecRunner.html`时将阻止所有 AJAX 请求。

解决这个问题的方法是通过 HTTP 服务器提供规范运行器，如第四章中所述，*异步测试 - AJAX*。

目前，在 Chrome 中有一个可用的解决方法，通过**命令行界面**（**CLI**）参数`--allow-file-access-from-files`。

例如，在 Mac OS X 中，需要在 bash 中使用以下命令以带有此标志的方式打开 Chrome：

```js
**$ open "Google Chrome.app" --args --allow-file-access-from-files**

```

有关此问题的更多细节，请参见 GitHub 票证[`github.com/velesin/jasmine-jquery/issues/4`](https://github.com/velesin/jasmine-jquery/issues/4)。

回到`NewInvestmentView`组件，我们可以借助这个 HTML fixture 插件开始编写规范的开发。

在`spec`文件夹内创建一个名为`fixtures`的文件夹。根据模拟界面，我们可以在`fixtures`文件夹内创建一个名为`NewInvestmentView.html`的新 HTML fixture，如下所示：

```js
<form id="new-investment">
  <h1>New investment</h1>
  <label>
    Symbol:
    <input type="text" class="new-investment-stock-symbol" name="stockSymbol" value="">
  </label>
  <label>
    Shares:
    <input type="number" class="new-investment-shares" name="shares" value="0">
  </label>
  <label>
    Share price:
    <input type="number" class="new-investment-share-price" name="sharePrice" value="0">
  </label>
  <input type="submit" name="add" value="Add">
</form>
```

这是一个 HTML fixture，因为它否则将由服务器呈现，而 JavaScript 代码只是附加到它并添加行为。

因为我们没有将这个 fixture 保存在插件的默认路径下，所以我们需要在`SpecHelper.js`文件的末尾添加一个新的配置，如下所示：

```js
jasmine.getFixtures().fixturesPath = 'spec/fixtures';
```

在`NewInvestmentSpec.js`文件中，添加一个调用来加载 fixture：

```js
describe("NewInvestmentView", function() {
  **beforeEach(function() {**
    **loadFixtures('NewInvestmentView.html');**
  **});**
});
```

最后，在添加`Stock.js`和`Investment.js`文件之后，将规范和源添加到 runner 中，如下所示：

```js
<script src="src/NewInvestmentView.js"></script>
<script src="spec/NewInvestmentViewSpec.js"></script>
```

# 基本的 View 编码规则

现在，是时候开始编写第一个 View 组件了。为了帮助我们完成这个过程，我们将为 View 编码幸福制定两条基本规则：

+   视图应该封装一个 DOM 元素

+   将 View 与观察者集成

所以，让我们看看它们如何单独工作。

## 视图应该封装一个 DOM 元素

如前所述，View 是与 DOM 元素相关联的行为，因此将此元素与 View 相关联是有意义的。一个很好的模式是在 View 实例化时传递一个 CSS `selector`，指示它应该引用的元素。以下是`NewInvestmentView`组件的规范：

```js
describe("NewInvestmentView", function() {
  **var view;**
  beforeEach(function() {
    loadFixtures('NewInvestmentView.html');
    **view = new NewInvestmentView({**
      **selector: '#new-investment'**
    **});**
  });
});
```

在 NewInvestmentView.js 文件的构造函数中，它使用 jQuery 来获取此选择器的元素并将其存储在一个实例变量`$element`中（源代码），如下所示：

```js
function NewInvestmentView (params) {
  **this.$element = $(params.selector);**
}
```

为了确保这段代码有效，我们应该在`NewInvestmentViewSpec.js`文件中为其编写以下测试：

```js
it("should expose a property with its DOM element", function() {
  expect(view.$element).toExist();
});
```

`toExist`匹配器是 Jasmine jQuery 扩展提供的自定义匹配器，用于检查文档中是否存在元素。它验证 JavaScript 对象上的属性的存在以及与 DOM 元素的成功关联。

将`selector`模式传递给 View 允许它在文档上的不同元素上实例化多次。

拥有明确关联的另一个优势是知道这个视图不会改变文档中的其他任何东西，我们将在下面看到。

视图是与 DOM 元素相关联的行为，因此不应该在页面的任何地方乱动。它应该只改变或访问与其关联的元素。

为了演示这个概念，让我们实现另一个关于视图默认状态的验收标准，如下所示：

```js
it("should have an empty stock symbol", function() {
  expect(view.getSymbolInput()).toHaveValue('');
});
```

`getSymbolInput`方法的一个天真的实现可能会使用全局 jQuery 查找来查找输入并返回其值：

```js
NewInvestmentView.prototype = {
  getSymbolInput: function () {
    return **$('.new-investment-stock-symbol')**
  }
};
```

然而，这可能会导致一个问题；如果文档中的其他地方有另一个具有相同类名的输入，它可能会得到错误的结果。

更好的方法是使用视图的关联元素来执行范围查找，如下所示：

```js
NewInvestmentView.prototype = {
  getSymbolInput: function () {
    return **this.$element.find('.new-investment-stock-symbol')**
  }
};
```

`find`函数只会查找`this.$element`的子元素。就好像`this.$element`代表了整个视图的文档。

由于我们将在视图代码的各个地方使用这种模式，因此我们可以创建一个函数并使用它，如下面的代码所示：

```js
NewInvestmentView.prototype = {
  **$: function () {**
    **return this.$element.find.apply(this.$element, arguments);**
  **}**,
  getSymbolInput: function () {
    return **this.$('.new-investment-stock-symbol')**
  }
};
```

现在假设从应用程序的其他地方，我们想要更改`NewInvestmentView`表单输入的值。我们知道它的类名，所以可能就像这样简单：

```js
$('.new-investment-stock-symbol').val('from outside the view');
```

然而，这种简单性隐藏了一个严重的封装问题。这一行代码正在与`NewInvestmentView`的实现细节产生耦合。

如果另一个开发人员更改了`NewInvestmentView`，将输入类名从`.new-investment-stock-symbol`更改为`.new-investment-symbol`，那么这一行代码将会出错。

为了解决这个问题，开发人员需要查看整个代码库中对该类名的引用。

一个更安全的方法是尊重视图并使用其 API，如下面的代码所示：

```js
newInvestmentView.setSymbol('from outside the view');
```

当实施时，会看起来像下面这样：

```js
NewInvestmentView.prototype.setSymbol = function(value) {
  this.$('.new-investment-stock-symbol').val(value);
};
```

这样，当代码被重构时，只需要在`NewInvestmentView`的实现内执行一次更改。

由于浏览器的文档中没有沙箱，这意味着从 JavaScript 代码的任何地方，我们都可以在文档的任何地方进行更改，除了良好的实践外，我们无法做太多事情来防止这些错误。

## 使用观察者集成视图

随着投资跟踪应用程序的开发，我们最终需要实现投资列表。但是，您将如何集成`NewInvestmentView`和`InvestmentListView`？

您可以为`NewInvestmentView`编写一个验收标准，如下所示：

给定新的投资视图，当点击其添加按钮时，它应该将投资添加到投资列表中。

这是非常直接的思维方式，通过写作可以看出我们在两个视图之间创建了直接关系。将这个转化为规范可以澄清这种感知，如下所示：

```js
describe("NewInvestmentView", function() {
  beforeEach(function() {
    loadFixtures('NewInvestmentView.html');
    **appendLoadFixtures('InvestmentListView.html');**

    **listView = new InvestmentListView({**
      **id: 'investment-list'**
    **});**

    view = new NewInvestmentView({
      id: 'new-investment',
      **listView: listView**
    });
  });

  describe("when its add button is clicked", function() {
    beforeEach(function() {
      // fill form inputs
      // simulate the clicking of the button
    });

    it("should add the investment to the list", function() {
      expect(**listView.count()**).toEqual(1);
    });
  });
});
```

这个解决方案在两个视图之间创建了一个依赖关系。`NewInvestmentView`构造函数现在接收`InvestmentListView`的实例作为其`listView`参数。

在其实现中，`NewInvestmentView`在其表单提交时调用`listView`对象的`addInvestment`方法：

```js
function NewInvestmentView (params) {
  **this.listView = params.listView;**

  this.$element.on('submit', function () {
    **this.listView.addInvestment(/* new investment */);**
  }.bind(this));
}
```

为了更好地澄清这段代码的工作原理，这里是集成是如何完成的图表：

![使用观察者集成视图](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/jsm-js-test-2e/img/B04138_03_02.jpg)

这显示了两个视图之间的直接关系

尽管非常简单，但这个解决方案引入了许多架构问题。首先，最明显的是`NewInvestmentView`规范的复杂性增加了。

其次，由于紧密耦合，使这些组件的演变变得更加困难。

为了更好地澄清这个问题，想象一下，将来我们也想在表格中列出投资。这将要求对`NewInvestmentView`进行更改，以支持列表和表视图，如下所示：

```js
function NewInvestmentView (params) {
  this.listView = params.listView;
  **this.tableView = params.tableView;**

  this.$element.on('submit', function () {
    this.listView.addInvestment(/* new investment */);
    **this.tableView.addInvestment(/* new investment */);**
  }.bind(this));
}
```

重新思考验收标准，我们可以得到一个更好的、未来可靠的解决方案。让我们重写它：

给定投资跟踪应用程序，当创建新的投资时，它应该将投资添加到投资列表中。

我们可以看到验收标准引入了一个新的被测试的主题：投资跟踪。这意味着一个新的源文件和规范文件。在创建这两个文件并将它们添加到运行器后，我们可以将这个验收标准写成一个规范，如下面的代码所示：

```js
describe("InvestmentTracker", function() {
  beforeEach(function() {
    loadFixtures('NewInvestmentView.html');
    appendLoadFixtures('InvestmentListView.html');

    listView = new InvestmentListView({
      id: 'investment-list'
    });

    newView = new NewInvestmentView({
      id: 'new-investment'
    });

    application = new InvestmentTracker({
      listView: listView,
      newView: newView
    });
  });

  describe("when a new investment is created", function() {
    beforeEach(function() {
      // fill form inputs
      newView.create();
    });

    it("should add the investment to the list", function() {
      expect(listView.count()).toEqual(1);
    });
  });
});
```

我们可以看到曾经在`NewInvestmentView`规范内部的相同设置代码。它加载了两个视图所需的固定装置，实例化了`InvestmentListView`和`NewInvestmentView`，并创建了一个`InvestmentTracker`的新实例，将两个视图作为参数传递。

稍后，在描述`创建新的投资`的行为时，我们可以看到对`newView.create`函数的调用来创建一个新的投资。

稍后，它检查`listView`对象是否添加了一个新项目，通过检查`listView.count()`是否等于`1`。

但是集成是如何发生的呢？我们可以通过查看`InvestmentTracker`的实现来看到：

```js
function InvestmentTracker (params) {
  this.listView = params.listView;
  this.newView = params.newView;

  this.newView.onCreate(function (investment) {
    this.listView.addInvestment(investment);
  }.bind(this));
}
```

它使用`onCreate`函数在`newView`上注册一个观察者函数作为回调。这个观察者函数将在以后创建新的投资时被调用。

`NewInvestmentView`内部的实现非常简单。`onCreate`方法将`callback`参数存储为对象的属性，如下所示：

```js
NewInvestmentView.prototype.onCreate = function(callback) {
  this._callback = callback;
};
```

`_callback`属性的命名约定可能听起来奇怪，但这是一个很好的约定，表明它是一个私有成员。

尽管前置下划线字符实际上不会改变属性的可见性，但它至少会通知对象的用户，`_callback`属性可能会在将来发生变化，甚至被移除。

稍后，当调用`create`方法时，它会调用`_callback`，并将新的投资作为参数传递，如下所示：

```js
NewInvestmentView.prototype.create = function() {
  this._callback(/* new investment */);
};
```

更完整的实现需要允许多次调用`onCreate`，存储每个传递的回调。

以下是更好理解的解决方案：

![使用观察者集成视图](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/jsm-js-test-2e/img/B04138_03_03.jpg)

使用回调函数集成两个视图

稍后，在第七章，“测试 React.js 应用程序”中，我们将看到`NewInvestmentView`规范的实现结果。

# 使用 jQuery 匹配器测试视图

除了其 HTML 装置模块外，Jasmine jQuery 扩展还带有一组自定义匹配器，这些匹配器有助于编写对 DOM 元素的期望。

使用这些自定义匹配器的最大优势，正如所示，是它们生成更好的错误消息。因此，尽管我们可以在不使用任何这些匹配器的情况下编写所有规范，但如果我们使用了这些匹配器，当发生错误时，它们会为我们提供更有用的信息。

为了更好地理解这个优势，我们可以回顾一下`应该公开具有其 DOM 元素的属性`规范的例子。在那里，它使用了`toExist`匹配器：

```js
it("should expose a property with its DOM element", function() {
  **expect(view.$element).toExist();**
});
```

如果这个规范失败，我们会得到一个很好的错误消息，如下面的截图所示：

![使用 jQuery 匹配器测试视图](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/jsm-js-test-2e/img/B04138_03_04.jpg)

这显示了一个很好的自定义匹配器错误消息

现在，我们重新编写这个规范，不使用自定义匹配器（仍然进行相同的验证）：

```js
it("should expose a property with its DOM element", function() {
  **expect($(document).find(view.$element).length).toBeGreaterThan(0);**
});
```

这次，错误消息变得不太具体：

![使用 jQuery 匹配器测试视图](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/jsm-js-test-2e/img/B04138_03_05.jpg)

阅读错误时，我们无法理解它真正在测试什么

因此，尽可能使用这些匹配器以获得更好的错误消息。让我们回顾一些可用的自定义匹配器，通过`NewInvestmentView`类的这些验收标准进行示例演示：

+   `NewInvestmentView`应该允许输入股票符号

+   `NewInvestmentView`应该允许输入股票份额

+   `NewInvestmentView` 应该允许输入股价

+   `NewInvestmentView` 应该有一个空的股票符号

+   `NewInvestmentView` 应该将其股票价值设为零

+   `NewInvestmentView` 应该将其股价值设为零

+   `NewInvestmentView` 应该将其股票符号输入设为焦点

+   `NewInvestmentView` 不应允许添加

重要的是您要理解，尽管下面的示例对于演示 Jasmine jQuery 匹配器的工作方式非常有用，但实际上并没有测试任何 JavaScript 代码，而只是测试了由 HTML fixture 模块加载的 HTML 元素。

## toBeMatchedBy jQuery 匹配器

此匹配器检查元素是否与传递的 CSS 选择器匹配，如下所示：

```js
it("should allow the input of the stock symbol", function() {
  expect(view.$element.find('.new-investment-stock-symbol')).**toBeMatchedBy**('input[type=text]');
});
```

## toContainHtml jQuery 匹配器

此匹配器检查元素的内容是否与传递的 HTML 匹配，如下所示：

```js
it("should allow the input of shares", function() {
  expect(view.$element).**toContainHtml**('<input type="number" class="new-investment-shares" name="shares" value="0">');
});
```

## toContainElement jQuery 匹配器

此匹配器检查元素是否包含与传递的 CSS 选择器匹配的任何子元素，如下所示

```js
it("should allow the input of the share price", function() {
  expect(view.$element).**toContainElement**('input[type=number].new-investment-share-price');
});
```

## toHaveValue jQuery 匹配器

仅适用于输入，此代码验证预期值与元素的值属性是否匹配：

```js
it("should have an empty stock symbol", function() {
  expect(view.$element.find('.new-investment-stock-symbol')).**toHaveValue**('');
});

it("should have its shares value to zero", function() {
  expect(view.$element.find('.new-investment-shares')).**toHaveValue**('0');
});
```

## toHaveAttr jQuery 匹配器

此匹配器测试元素是否具有指定名称和值的任何属性。以下示例显示了如何使用此匹配器测试输入的值属性，这是可以使用`toHaveValue`匹配器编写的预期：

```js
it("should have its share price value to zero", function() {
  expect(view.$element.find('.new-investment-share-price')).**toHaveAttr**('value', '0');
});
```

## toBeFocused jQuery 匹配器

以下代码说明了匹配器如何检查输入元素是否聚焦：

```js
it("should have its stock symbol input on focus", function() {
 expect(view.$element.find('.new-investment-stock-symbol')).**toBeFocused**();
});
```

## toBeDisabled jQuery 匹配器

此匹配器检查元素是否使用以下代码禁用：

```js
function itShouldNotAllowToAdd () {
 it("should not allow to add", function() {
  expect(view.$element.find('input[type=submit]')).**toBeDisabled**();
});
```

## 更多匹配器

该扩展有许多其他可用的匹配器；请确保查看项目文档 [`github.com/velesin/jasmine-jquery#jquery-matchers`](https://github.com/velesin/jasmine-jquery#jquery-matchers)。

# 摘要

在本章中，您学会了如何通过测试驱动应用程序开发可以变得更加容易。您看到了如何使用模块模式更好地组织项目代码，以及 View 模式如何帮助创建更易于维护的浏览器代码。

您学会了如何使用 HTML fixture，使您的规范更加易读和易懂。我还向您展示了如何通过自定义 jQuery 匹配器测试与浏览器 DOM 交互的代码。

在下一章中，我们将进一步开始测试服务器集成和异步代码。


# 第四章：异步测试 - AJAX

不可避免地，每个 JavaScript 应用程序都会有一个时刻，需要测试异步代码。

异步意味着您无法以线性方式处理它——一个函数可能在执行后立即返回，但结果通常会在稍后通过回调返回。

这在处理 AJAX 请求时是一种非常常见的模式，例如通过 jQuery：

```js
$.ajax('http://localhost/data.json', {
  success: function (data) {
    // handle the result
  }
});
```

在本章中，我们将学习 Jasmine 允许我们以不同方式编写异步代码的测试。

# 验收标准

为了演示 Jasmine 对异步测试的支持，我们将实现以下验收标准：

获取股票时，应更新其股价

使用我们到目前为止向您展示的技术，您可以在`spec`文件夹中的`StockSpec.js`文件中编写这个验收标准，如下所示：

```js
describe("Stock", function() {
  var stock;
  var originalSharePrice = 0;

  beforeEach(function() {
    stock = new Stock({
      symbol: 'AOUE',
      sharePrice: originalSharePrice
    });
  });

  it("should have a share price", function() {
    expect(stock.sharePrice).toEqual(originalSharePrice);
  });

  **describe("when fetched", function() {**
 **var fetched = false;**
 **beforeEach(function() {**
 **stock.fetch();**
 **});**

 **it("should update its share price", function() {**
 **expect(stock.sharePrice).toEqual(20.18);**
 **});**
 **});**
});
```

这将导致在`src`文件夹中的`Stock.js`文件中实现`fetch`函数，如下所示：

```js
Stock.prototype.**fetch** = function() {
  var that = this;
  var url = 'http://localhost:8000/stocks/'+that.symbol;

  **$.getJSON**(url, function (data) {
    that.sharePrice = data.sharePrice;
  });
};
```

在前面的代码中，重要的部分是`$.getJSON`调用，这是一个期望包含更新后的股价的 JSON 响应的 AJAX 请求，例如：

```js
{
  "sharePrice": 20.18
}
```

到目前为止，您可以看到我们被卡住了；为了运行这个规范，我们需要一个运行的服务器。

# 设置场景

由于本书都是关于 JavaScript 的，我们将创建一个非常简单的**Node.js**服务器供规范使用。Node.js 是一个允许使用 JavaScript 开发网络应用程序（如 Web 服务器）的平台。

在第六章*轻量级单元测试*中，我们将看到测试 AJAX 请求的替代解决方案，而无需服务器。在第八章*构建自动化*中，我们将看到如何使用 Node.js 作为高级构建系统的基础。

## 安装 Node.js

如果您已经安装了 Node.js，可以跳转到下一节。

Windows 和 Mac OS X 都有安装程序。执行以下步骤安装 Node.js：

1.  转到 Node.js 网站[`nodejs.org/`](http://nodejs.org/)。

1.  点击**安装**按钮。

1.  下载完成后，执行安装程序并按照步骤进行操作。

要检查其他安装方法以及如何在 Linux 发行版上安装 Node.js 的说明，请查看官方文档[`github.com/joyent/node/wiki/Installing-Node.js-via-package-manager`](https://github.com/joyent/node/wiki/Installing-Node.js-via-package-manager)。

完成后，您应该在命令行上有`node`和`npm`命令可用。

## 编写服务器

为了学习如何编写异步规范，我们将创建一个返回一些假数据的服务器。在项目的根文件夹中创建一个名为`server.js`的新文件，并将以下代码添加到其中：

```js
var express = require('express');
var app = express();

app.get('/stocks/:symbol', function (req, res) {
  res.setHeader('Content-Type', 'application/json');
  res.send({ sharePrice: 20.18 });
});

app.use(express.static(__dirname));

app.listen(8000);
```

为了处理 HTTP 请求，我们使用**Express**，一个 Node.js Web 应用程序框架。通过阅读代码，您可以看到它定义了一个到`/stocks/:symbol`的路由，因此它接受诸如`http://localhost:8000/stocks/AOUE`的请求，并用 JSON 数据做出响应。

我们还使用`express.static`模块在`http://localhost:8000/SpecRunner.html`上提供规范运行器。

有一个要求来规避 SOP。这是一个出于安全原因规定的政策，即不允许在与应用程序不同的域上执行 AJAX 请求。

在第三章*测试前端代码*中首次演示了使用 HTML 固定装置时出现的问题。

使用 Chrome 浏览器检查器，您可以看到在使用`file://`协议打开`SpecRunner.html`文件时控制台中的错误（基本上是您到目前为止一直在做的方式）：

![编写服务器](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/jsm-js-test-2e/img/B04138_04_01.jpg)

这显示了同源策略错误

通过为运行器提供相同的基本 URL 下的所有应用程序和测试代码，我们可以防止出现这个问题，并能够在任何浏览器上运行规范。

## 运行服务器

要运行服务器，首先需要使用 Node 的包管理器安装其依赖项（Express）。在应用程序根文件夹中，运行`npm`命令：

```js
**$ npm install express**

```

这个命令将下载 Express 并将其放在项目文件夹内的一个名为`node_modules`的新文件夹中。

现在，您应该能够通过调用以下`node`命令来运行服务器：

```js
**$ node server.js**

```

要检查它是否起作用，请在浏览器上访问`http://localhost:8000/stocks/AOUE`，您应该会收到 JSON 响应：

```js
{"sharePrice": "20.18"}
```

现在我们的服务器依赖项正在运行，我们可以继续编写规范。

# 编写规范

在服务器运行时，打开浏览器访问`http://localhost:8000/SpecRunner.html`，以查看我们规范的结果。

您可以看到，即使服务器正在运行，并且规范似乎是正确的，但它仍然失败了。这是因为`stock.fetch()`是异步的。对`stock.fetch()`的调用会立即返回，允许 Jasmine 在 AJAX 请求完成之前运行期望：

```js
it("should update its share price", function() {
  expect(stock.sharePrice).toEqual(20.18);
});
```

为了解决这个问题，我们需要接受`stock.fetch()`函数的异步性，并指示 Jasmine 在运行期望之前等待其执行。

## 异步设置和拆卸

在所示的示例中，我们在规范的设置（`beforeEach`函数）期间调用`fetch`函数。

我们唯一需要做的是在其函数定义中添加一个`done`参数，以识别这个设置步骤是异步的：

```js
describe("when fetched", function() {
  beforeEach(function(**done**) {

  });

  it("should update its share price", function() {
    expect(stock.sharePrice).toEqual(20.18);
  });
});
```

一旦 Jasmine 识别到这个`done`参数，它会将一个必须在异步操作完成后调用的函数作为其值传递。

因此，我们可以将这个`done`函数作为`fetch`函数的`success`回调传递：

```js
beforeEach(function(done) {
  stock.fetch(**{**
 **success: done**
 **}**);
});
```

在实现时，在 AJAX 操作完成后调用它：

```js
Stock.prototype.fetch = function(params) {
  params = params || {};
  var that = this;
  **var success = params.success || function () {};**
 **var url = 'http://localhost:8000/stocks/'+that.symbol;**

  $.getJSON(url, function (data) {
    that.sharePrice = data.sharePrice;
 **success(that);**
  });
};
```

就是这样；Jasmine 将等待 AJAX 操作完成，测试将通过。

在需要时，还可以使用相同的`done`参数定义异步的`afterEach`。

## 异步规范

另一种方法是使用异步规范而不是异步设置。为了演示这将如何工作，我们需要重新编写我们之前的验收标准：

```js
describe("Stock", function() {
  var stock;
  var originalSharePrice = 0;

  beforeEach(function() {
    stock = new Stock({
      symbol: 'AOUE',
      sharePrice: originalSharePrice
    });
  });

  it("should be able to update its share price", function(done) {
    stock.fetch();
    expect(stock.sharePrice).toEqual(20.18);
  });
});
```

再次，我们只需要在其函数定义中添加一个`done`参数，并在测试完成后调用`done`函数：

```js
it("should be able to update its share price", function(**done**) {
  stock.fetch({
    success: function () {
      expect(stock.sharePrice).toEqual(20.18);
      **done();**
    }
  });
});
```

这里的区别在于，我们必须将期望移到`success`回调中，在调用`done`函数之前。

## 超时

在编写异步规范时，默认情况下，Jasmine 将等待 5 秒钟，等待`done`回调被调用，如果在此超时之前未调用，则规范将失败。

在这个假设的例子中，服务器是一个返回静态数据的简单存根，超时不是问题，但有些情况下，默认时间不足以完成异步任务。

虽然不建议有长时间运行的规范，但知道可以通过更改 Jasmine 中称为`jasmine.DEFAULT_TIMEOUT_INTERVAL`的简单配置变量来避免这种默认行为是很好的。

要使其在整个套件中生效，可以在`SpecHelper.js`文件中设置它，如下所示：

```js
beforeEach(function() {
  **jasmine.DEFAULT_TIMEOUT_INTERVAL = 10000;**

  jasmine.addMatchers({
    // matchers code
  });
});

jasmine.getFixtures().fixturesPath = 'spec/fixtures';
```

要使其在单个规范中生效，请在`beforeEach`中更改其值，并在`afterEach`期间恢复：

```js
describe("Stock", function() {
 **var defaultTimeout;**

  beforeEach(function() {
 **defaultTimeout = jasmine.DEFAULT_TIMEOUT_INTERVAL;**
 **jasmine.DEFAULT_TIMEOUT_INTERVAL = 10000;**
  });

  afterEach(function() {
 **jasmine.DEFAULT_TIMEOUT_INTERVAL = defaultTimeout;**
  });

  it("should be able to update its share price", function(done) {

  });
});
```

# 总结

在本章中，您已经看到了如何测试异步代码，这在测试服务器交互（AJAX）时很常见。

我还向您介绍了 Node.js 平台，并使用它编写了一个简单的服务器，用作测试装置。

在第六章*轻量级单元测试*中，我们将看到不需要运行服务器的 AJAX 测试的不同解决方案。

在下一章中，我们将学习间谍以及如何利用它们来进行行为检查。
